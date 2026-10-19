// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hammer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// DefaultMaxOracleOccurrences bounds exact per-key occurrence retention (~80 MiB of uint64s)
// so multi-hour unconstrained soak runs remain memory-bounded.
const DefaultMaxOracleOccurrences uint64 = 10_000_000

// InputStateVerifier validates that a VIndex state commitment's (inputSize, inputRoot) matches
// or is Merkle-consistent with the hammer's own Input Log.
type InputStateVerifier func(ctx context.Context, inputSize uint64, inputRoot [sha256.Size]byte) error

// Oracle maintains pure-Go MapFn ground truth for sequenced Input Log entries and verifies
// target VIndex lookup responses for exactness (no omitted keys, phantom keys, or altered indices).
type Oracle struct {
	mapFn          MapFn
	maxOccurrences uint64
	contiguousSize atomic.Uint64

	mu            sync.RWMutex
	nextExpected  uint64
	pending       map[uint64][]string
	occurrences   map[string][]uint64
	sortedKeys    []string
	totalRecorded uint64
	capped        bool
	cappedAtSize  uint64
	waitCh        chan struct{}
	stateVerifier InputStateVerifier
}

// NewOracle initializes a ground-truth Oracle backed by the given pure-Go MapFn.
func NewOracle(mapFn MapFn, maxOccurrences uint64) *Oracle {
	if mapFn == nil {
		mapFn = MapRawLeaf
	}
	if maxOccurrences == 0 {
		maxOccurrences = DefaultMaxOracleOccurrences
	}
	return &Oracle{
		mapFn:          mapFn,
		maxOccurrences: maxOccurrences,
		pending:        make(map[uint64][]string),
		occurrences:    make(map[string][]uint64),
		waitCh:         make(chan struct{}),
	}
}

// SetInputStateVerifier registers the callback used to verify committed (inputSize, inputRoot) pairs.
func (o *Oracle) SetInputStateVerifier(fn InputStateVerifier) {
	o.mu.Lock()
	o.stateVerifier = fn
	o.mu.Unlock()
}

// VerifyInputState checks (inputSize, inputRoot) against the registered Input Log state verifier, if any.
func (o *Oracle) VerifyInputState(ctx context.Context, inputSize uint64, inputRoot [sha256.Size]byte) error {
	o.mu.RLock()
	fn := o.stateVerifier
	o.mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, inputSize, inputRoot)
}

// MapLeaf runs the pure-Go MapFn over raw leaf bytes.
func (o *Oracle) MapLeaf(leaf []byte) ([]string, error) {
	return o.mapFn(leaf)
}

// MapAndRecord maps leaf in pure Go and records its canonical keys at entry index idx.
func (o *Oracle) MapAndRecord(idx uint64, leaf []byte) error {
	keys, err := o.mapFn(leaf)
	if err != nil {
		return err
	}
	o.Record(idx, keys)
	return nil
}

// Record commits the deduplicated canonical keys emitted for Input Log entry idx.
// Out-of-order indices are buffered until all preceding indices [0, idx) are recorded,
// ensuring ContiguousSize advances strictly without gaps.
func (o *Oracle) Record(idx uint64, keys []string) {
	var dedup []string
	if len(keys) > 0 {
		dedup = make([]string, 0, len(keys))
		for _, k := range keys {
			if !slices.Contains(dedup, k) {
				dedup = append(dedup, k)
			}
		}
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if idx < o.nextExpected {
		return
	}
	if idx > o.nextExpected {
		o.pending[idx] = dedup
		return
	}

	advanced := false
	for {
		o.applyContiguousLocked(o.nextExpected, dedup)
		o.nextExpected++
		advanced = true

		nextKeys, ok := o.pending[o.nextExpected]
		if !ok {
			break
		}
		delete(o.pending, o.nextExpected)
		dedup = nextKeys
	}

	if advanced {
		o.contiguousSize.Store(o.nextExpected)
		close(o.waitCh)
		o.waitCh = make(chan struct{})
	}
}

func (o *Oracle) applyContiguousLocked(idx uint64, keys []string) {
	if o.capped {
		return
	}
	if o.totalRecorded+uint64(len(keys)) > o.maxOccurrences {
		o.capped = true
		o.cappedAtSize = idx
		return
	}
	for _, k := range keys {
		existing, exists := o.occurrences[k]
		if !exists {
			insIdx, _ := slices.BinarySearch(o.sortedKeys, k)
			o.sortedKeys = slices.Insert(o.sortedKeys, insIdx, k)
		}
		o.occurrences[k] = append(existing, idx)
		o.totalRecorded++
	}
}

// ContiguousSize returns the contiguous Input Log tree size [0, size) recorded in the Oracle.
func (o *Oracle) ContiguousSize() uint64 {
	return o.contiguousSize.Load()
}

func sliceIndicesInRange(sorted []uint64, from, before uint64) []uint64 {
	if len(sorted) == 0 || from >= before {
		return nil
	}
	lo, _ := slices.BinarySearch(sorted, from)
	hi, _ := slices.BinarySearch(sorted, before)
	if lo >= hi {
		return nil
	}
	return sorted[lo:hi]
}

// VerifyKeyLookup checks a verified LookupKey + /values result at [from, inputSize) against pure-Go ground truth.
func (o *Oracle) VerifyKeyLookup(key string, from, inputSize uint64, matched bool, gotIndices []uint64, isComplete bool) error {
	if from > inputSize {
		return fmt.Errorf("invalid range [%d, %d) for key %q", from, inputSize, key)
	}

	o.mu.RLock()
	contig := o.nextExpected
	capped := o.capped
	cappedAt := o.cappedAtSize
	all := o.occurrences[key]

	if inputSize > contig {
		o.mu.RUnlock()
		return fmt.Errorf("response input-size %d exceeds hammer oracle size %d for key %q", inputSize, contig, key)
	}

	if !capped || inputSize <= cappedAt {
		want := sliceIndicesInRange(all, from, inputSize)
		wantLen := len(want)
		if wantLen == 0 {
			o.mu.RUnlock()
			if matched || len(gotIndices) > 0 {
				return fmt.Errorf("phantom key %q present at [%d, %d) with %d indices (oracle expected 0)", key, from, inputSize, len(gotIndices))
			}
			return nil
		}
		if !matched {
			first, last := want[0], want[wantLen-1]
			o.mu.RUnlock()
			return fmt.Errorf("omitted key %q missing from MPT at [%d, %d): oracle expected %d occurrences (first=%d, last=%d)",
				key, from, inputSize, wantLen, first, last)
		}
		if isComplete {
			eq := slices.Equal(gotIndices, want)
			first, last := want[0], want[wantLen-1]
			o.mu.RUnlock()
			if !eq {
				return fmt.Errorf("index mismatch for key %q at [%d, %d): got %d indices, oracle expected %d (first=%d, last=%d)",
					key, from, inputSize, len(gotIndices), wantLen, first, last)
			}
			return nil
		}
		// Bounded newest-page scan: collectIndices stops upon reaching PageSize items, so wantLen >= len(gotIndices)
		// (equality holds when total occurrences equal PageSize), and returned indices must equal the newest suffix of want.
		validSuffix := len(gotIndices) > 0 && wantLen >= len(gotIndices) && slices.Equal(gotIndices, want[wantLen-len(gotIndices):])
		o.mu.RUnlock()
		if !validSuffix {
			return fmt.Errorf("partial-page suffix mismatch for key %q at [%d, %d): got %d newest indices, oracle total %d",
				key, from, inputSize, len(gotIndices), wantLen)
		}
		return nil
	}

	// Capped soak-run fallback: enforce exactness below cappedAt and prefix-superset consistency above cappedAt.
	minWant := sliceIndicesInRange(all, from, min(inputSize, cappedAt))
	minLen := len(minWant)
	prefixOK := !isComplete || (len(gotIndices) >= minLen &&
		slices.Equal(gotIndices[:minLen], minWant) &&
		(len(gotIndices) == minLen || gotIndices[minLen] >= cappedAt))
	o.mu.RUnlock()

	if minLen > 0 && !matched {
		return fmt.Errorf("omitted key %q missing from MPT at [%d, %d): oracle recorded >= %d occurrences", key, from, inputSize, minLen)
	}
	if !prefixOK {
		return fmt.Errorf("capped history prefix mismatch for key %q at [%d, %d): got %d indices, expected prefix of length >= %d",
			key, from, inputSize, len(gotIndices), minLen)
	}
	return nil
}

// VerifyPrefixLookup checks that matchedKeys (sorted) from GET /keys?prefix=<prefix> at [from, inputSize)
// matches the pure-Go ground-truth key set.
func (o *Oracle) VerifyPrefixLookup(prefix string, from, inputSize uint64, matchedKeys []string) error {
	if from > inputSize {
		return fmt.Errorf("invalid range [%d, %d) for prefix %q", from, inputSize, prefix)
	}

	o.mu.RLock()
	contig := o.nextExpected
	capped := o.capped
	cappedAt := o.cappedAtSize
	if inputSize > contig {
		o.mu.RUnlock()
		return fmt.Errorf("response input-size %d exceeds hammer oracle size %d for prefix %q", inputSize, contig, prefix)
	}

	upperBound := inputSize
	exact := !capped || inputSize <= cappedAt
	if !exact {
		upperBound = min(inputSize, cappedAt)
	}

	startIdx, _ := slices.BinarySearch(o.sortedKeys, prefix)
	var expected []string
	for i := startIdx; i < len(o.sortedKeys); i++ {
		k := o.sortedKeys[i]
		if !strings.HasPrefix(k, prefix) {
			break
		}
		if len(sliceIndicesInRange(o.occurrences[k], from, upperBound)) > 0 {
			expected = append(expected, k)
		}
	}
	o.mu.RUnlock()

	if exact {
		if !slices.Equal(matchedKeys, expected) {
			return fmt.Errorf("prefix %q key-set mismatch at [%d, %d): got %d keys %v, oracle expected %d keys %v",
				prefix, from, inputSize, len(matchedKeys), truncateSlice(matchedKeys, 5), len(expected), truncateSlice(expected, 5))
		}
		return nil
	}

	for _, k := range expected {
		if _, found := slices.BinarySearch(matchedKeys, k); !found {
			return fmt.Errorf("prefix %q omitted known key %q at [%d, %d)", prefix, k, from, inputSize)
		}
	}
	return nil
}

func truncateSlice(s []string, limit int) []string {
	if len(s) <= limit {
		return s
	}
	out := make([]string, limit+1)
	copy(out, s[:limit])
	out[limit] = "..."
	return out
}
