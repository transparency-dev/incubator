// Copyright 2025 Google LLC. All Rights Reserved.
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

// vindex contains a prototype of an in-memory verifiable index.
// It reads data from an InputLog interface, applies a MapFn to every leaf in the
// input log, and writes the mapped information out to a Write Ahead Log. Data is
// read from the WAL, and the in-memory map is built from this.
package vindex

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"sync"
	"time"

	"filippo.io/torchwood/mpt"
	"github.com/transparency-dev/formats/log"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

// MapFn takes the raw leaf data from a log entry and outputs the SHA256 hashes
// of the keys at which this leaf should be indexed under.
// A leaf can be recorded at any number of entries, including no entries (in which case an empty slice must be returned).
//
// MapFn is expected to consume any error states that it encounters in some way that
// makes sense to the particular ecosystem. This might mean outputting any invalid leaves
// at a known locations (e.g. all 0s), or not outputting any entry. Any panics will cause
// the mapping process to terminate.
type MapFn func([]byte) [][32]byte

// InputLog represents a connection to the input log from which map data will be built.
// This can be a local or remote data source.
type InputLog interface {
	// Checkpoint returns the latest checkpoint committing to the input log state.
	Checkpoint(ctx context.Context) (checkpoint []byte, err error)
	// Leaves returns all the leaves in the range [start, end), outputting them via
	// the returned iterator.
	Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error]
}

// OpenCheckpointFn is a function that parses a checkpoint, validating it, and returns a parsed
// checkpoint. This is expected to be a thin wrapper around log.ParseCheckpoint with the
// validators set up according to the index operator's policy on the number of witnesses
// required.
type OpenCheckpointFn func(cpRaw []byte) (*log.Checkpoint, error)

// NewVerifiableIndex returns an IndexBuilder that pulls entries from the given inputLog, determines
// indices for each one using the mapFn, and then writes the entries out to a Write Ahead Log at the given
// path.
// Note that only one IndexBuilder should exist for any given walPath at any time. The behaviour is unspecified,
// but likely broken, if multiple processes are writing to the same file at any given time.
func NewVerifiableIndex(ctx context.Context, inputLog InputLog, inputLogParseFn OpenCheckpointFn, mapFn MapFn, walPath string) (*VerifiableIndex, error) {
	wal := &walWriter{
		walPath: walPath,
	}
	ws, err := wal.init()
	if err != nil {
		return nil, err
	}
	reader, err := newWalReader(walPath)
	if err != nil {
		return nil, err
	}
	vtreeStorage := mpt.NewMemoryStorage()
	if err := mpt.InitStorage(sha256.Sum256, vtreeStorage); err != nil {
		return nil, fmt.Errorf("InitStorage: %s", err)
	}
	mapper := &inputLogMapper{
		inputLog:        inputLog,
		inputLogParseFn: inputLogParseFn,
		mapFn:           mapFn,
		walWriter:       wal,
		nextIndex:       ws,
	}
	b := &VerifiableIndex{
		mapper:    mapper,
		walReader: reader,
		vindex:    *mpt.NewTree(sha256.Sum256, vtreeStorage),
		data:      map[[32]byte][]uint64{},
	}
	if err := b.buildMap(ctx, ws); err != nil {
		return nil, fmt.Errorf("failed to build map: %v", err)
	}
	return b, nil
}

// inputLogMapper reads the Input Log, checking that the data matches the commitments,
// and updates the WAL and DB with the resulting information.
type inputLogMapper struct {
	inputLog        InputLog
	inputLogParseFn OpenCheckpointFn
	mapFn           MapFn
	walWriter       *walWriter

	nextIndex      uint64 // nextIndex is the next index in the log to consume
	inputLogCpSize uint64 // cpSize is the tree size of rawCp. Used to sync on WAL.
}

func (m *inputLogMapper) close() error {
	return m.walWriter.close()
}

// available returns whether this is work to do.
// TODO(mhutchinson): this can probably be deleted
func (m *inputLogMapper) available(ctx context.Context) bool {
	rawCp, err := m.inputLog.Checkpoint(ctx)
	if err != nil {
		klog.Warningf("Failed to get latest checkpoint from DB: %s", err)
		return false
	}
	cp, err := m.inputLogParseFn(rawCp)
	if err != nil {
		klog.Warningf("Failed to parse checkpoint: %s", err)
		return false
	}

	// TODO(mhutchinson): remove this and replace with disk persistence?
	defer func() {
		m.inputLogCpSize = cp.Size
	}()
	return cp.Size > m.inputLogCpSize
}

// syncFromInputLog reads the latest checkpoint from the input log, and ensures that the WAL
// contains a corresponding entry for every index committed to by that checkpoint.
//
// TODO(mhutchinson): this doesn't perform any validation on the input log to check the
// leaves correspond to the checkpoint root hash. This was reasonable while it was based on the
// cloneDB, which performed this validation. Implementing this will require the index to store some
// state alongside the WAL which contains a compact range of its current progress.
func (m *inputLogMapper) syncFromInputLog(ctx context.Context) error {
	if m.inputLogCpSize > m.nextIndex {
		ctx, done := context.WithCancel(ctx)
		defer done()
		for l, err := range m.inputLog.Leaves(ctx, m.nextIndex, m.inputLogCpSize) {
			idx := m.nextIndex
			if err != nil {
				return fmt.Errorf("failed to read leaf at index %d: %v", idx, err)
			}

			// Apply the MapFn in as safe a way as possible. This involves trapping any panics
			// and failing gracefully.
			var hashes [][32]byte
			var mapErr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						mapErr = fmt.Errorf("panic detected mapping index %d: %s", idx, r)
					}
				}()
				hashes = m.mapFn(l)
			}()
			if mapErr != nil {
				return mapErr
			}
			m.nextIndex++
			if len(hashes) == 0 && idx < m.inputLogCpSize-1 {
				// We can skip writing out values with no hashes, as long as we're
				// not at the end of the log.
				// If we are at the end of the log, we need to write out a value as a sentinel
				// even if there are no hashes.
				continue
			}
			if err := m.walWriter.append(idx, hashes); err != nil {
				return fmt.Errorf("failed to add index to entry for leaf %d: %v", idx, err)
			}
		}
	}
	return nil
}

// VerifiableIndex manages reading from the input log, mapping leaves, updating the WAL,
// reading the WAL, and keeping the state of the in-memory index updated from the WAL.
type VerifiableIndex struct {
	mapper    *inputLogMapper
	walReader *walReader

	indexMu sync.RWMutex // covers vindex and data
	vindex  mpt.Tree
	data    map[[32]byte][]uint64

	// servingSize is the size of the input log we are serving for.
	// This a temporary workaround not having an output log, which we will eventually read to get
	// the checkpoint size.
	servingSize uint64
}

// Close ensures that any open connections are closed before returning.
func (b *VerifiableIndex) Close() error {
	return b.mapper.close()
}

// Lookup returns the values stored for the given key.
// TODO(mhutchinson): This needs to return verifiable stuff
func (b *VerifiableIndex) Lookup(key [sha256.Size]byte) (indices []uint64, size uint64) {
	// Scope the lock to be as minimal as possible
	lookupLocked := func(key [sha256.Size]byte) []uint64 {
		b.indexMu.RLock()
		defer b.indexMu.RUnlock()
		return b.data[key]
	}

	// TODO(mhutchinson): this should come from the latest map root in the (witnessed) output log.
	// This map root, the witnessed output log checkpoint, and all proofs should also be served here.
	size = b.servingSize

	allIndices := lookupLocked(key)
	for i, idx := range allIndices {
		if idx >= size {
			// If we have indices past the current size we are serving, drop them.
			// Doing this allows us to update b.data with new indices while still serving from it.
			return allIndices[:i], size
		}
	}
	return allIndices, size
}

// Update checks the input log for a new Checkpoint, and ensures that the Verifiable Index
// is updated to the corresponding size.
func (b *VerifiableIndex) Update(ctx context.Context) error {
	if !b.mapper.available(ctx) {
		return nil
	}

	newSize := b.mapper.inputLogCpSize
	eg, cctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return b.mapper.syncFromInputLog(cctx) })
	eg.Go(func() error { return b.buildMap(cctx, newSize) })

	err := eg.Wait()

	return err
}

// buildMap reads from the WAL until the file has been consumed and the map has been
// built up the provided size.
func (b *VerifiableIndex) buildMap(ctx context.Context, toSize uint64) error {
	startWal := time.Now()
	updatedKeys := make(map[[32]byte]bool) // Allows us to efficiently update vindex after first init

	for i := b.servingSize; i < toSize; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		idx, hashes, err := b.walReader.next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			// Wait a small amount of time for more data to become available
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Locking strategy when updating the map containing actual data is to lock for each log entry
		// This more granular locking allows Lookup to still occur, and we can drop any indexes bigger than
		// the tree size.
		func() {
			b.indexMu.Lock()
			defer b.indexMu.Unlock()
			i = idx + 1
			for _, h := range hashes {
				klog.V(2).Infof("Read from WAL: index %d: %x", idx, h)
				// Add the data to the key/value map
				idxes := b.data[h]
				idxes = append(idxes, idx)
				b.data[h] = idxes
				updatedKeys[h] = true
			}
		}()
	}
	durationWal := time.Since(startWal)

	startVIndex := time.Now()
	// Build the verifiable index _afterwards_ for several reasons:
	//  1) doing this incrementally leads to a lot of duplicate work for keys with multiple values
	//  2) updating the vindex needs to block lookups for the whole update of the data structure

	// Locking strategy for the verifiable index is to prevent all reads while this is being updated.
	// TODO(mhutchinson): inside the same mutex we will need to update the output log with the calculated
	// map root, and eventually witness checkpoints.
	// If this is too slow (almost certain), then we need some strategy to allow us to serve a version of
	// the vindex while also updating it. One approach could be to have 2 trees whenever we are performing
	// an update.
	b.indexMu.Lock()
	defer b.indexMu.Unlock()
	for h := range updatedKeys {
		idxes := b.data[h]

		// Here we hash by simply appending all indices in the list and hashing that
		// TODO(mhutchinson): maybe use a log construction?
		sum := sha256.New()
		for _, idx := range idxes {
			if err := binary.Write(sum, binary.BigEndian, idx); err != nil {
				klog.Warning(err)
				return err
			}
		}

		// Finally, we update the vindex
		if err := b.vindex.Insert(h, [32]byte(sum.Sum(nil))); err != nil {
			return fmt.Errorf("Insert(): %s", err)
		}
	}
	durationVIndex := time.Since(startVIndex)
	durationTotal := time.Since(startWal)

	b.servingSize = toSize
	klog.Infof("buildMap: total=%s (wal=%s, vindex=%s)", durationTotal, durationWal, durationVIndex)
	return nil
}
