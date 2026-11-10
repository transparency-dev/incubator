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

package kvstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/sync/errgroup"
)

// activeChunkEntry caches the in-memory descriptor of the active (unsealed) chunk for a key.
type activeChunkEntry struct {
	chunkNum     uint64
	record       *chunkRecord
	runningRange *compactRange
}

// maxGenChunkCacheSize bounds the in-memory active chunk cache.
const maxGenChunkCacheSize = 131072

// KVIndexer indexes mapped batches into Pebble inverted chunks ('c') and maintains Merkle compact ranges.
type KVIndexer struct {
	db        *DB
	chunkSize uint64

	currentCache  map[[sha256.Size]byte]activeChunkEntry
	previousCache map[[sha256.Size]byte]activeChunkEntry
	marshalBuf    []byte
	writesBuf     []chunkMutation
	numWorkers    int
	hasUnsynced   bool
}

// NewKVIndexer creates a new KVIndexer using db's configured chunk size.
func NewKVIndexer(db *DB) *KVIndexer {
	chunkSize := ChunkSize
	if db != nil {
		chunkSize = db.ChunkSize()
	}
	return &KVIndexer{
		db:           db,
		chunkSize:    chunkSize,
		currentCache: make(map[[sha256.Size]byte]activeChunkEntry, 1024),
		numWorkers:   min(8, max(1, runtime.GOMAXPROCS(0)/2)),
	}
}

// SetNumWorkers sets the number of worker goroutines for parallel key indexing.
func (idx *KVIndexer) SetNumWorkers(n int) {
	idx.numWorkers = max(1, n)
}

// ClearCache evicts all cached active chunk descriptors.
func (idx *KVIndexer) ClearCache() {
	idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, 1024)
	idx.previousCache = nil
}

// IndexMappedBatch indexes a MappedBatch with optional raw target checkpoint bytes and target size.
func (idx *KVIndexer) IndexMappedBatch(ctx context.Context, batch *MappedBatch, rawTargetCP []byte, targetSize uint64) (res *IndexResult, retErr error) {
	persistedKVSize, err := idx.db.GetUint64(KeyMetaKVSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read persisted kv_size: %w", err)
	}
	if batch == nil {
		return &IndexResult{
			NewKVSize:             persistedKVSize,
			ModifiedKeyValueRoots: make(map[string][sha256.Size]byte),
		}, nil
	}

	b := idx.db.newBatch(false)
	if b.err != nil {
		return nil, b.err
	}
	defer func() {
		_ = b.Close()
		if retErr != nil {
			idx.ClearCache()
		}
	}()

	modifiedKeyValueRoots, newCachedEntries, newKVSize, err := idx.buildBatchMutations(ctx, b.b, nil, persistedKVSize, batch, targetSize)
	if err != nil {
		return nil, err
	}

	sync := targetSize == 0 || newKVSize >= targetSize
	if newKVSize > persistedKVSize {
		if err := b.SetUint64(KeyMetaKVSize, newKVSize); err != nil {
			return nil, fmt.Errorf("failed to set metadata kv_size: %w", err)
		}
		if sync && len(rawTargetCP) > 0 {
			if err := b.Set(KeyMetaKVCheckpoint, rawTargetCP); err != nil {
				return nil, fmt.Errorf("failed to set metadata kv_checkpoint: %w", err)
			}
		}

		applyStart := time.Now()
		if err := idx.db.Apply(b, sync); err != nil {
			return nil, fmt.Errorf("failed to commit indexing batch: %w", err)
		}
		metrics.PebbleApplyDurationSeconds.Observe(time.Since(applyStart).Seconds())
		// Release b's closeMu.RLock() before calling Sync()/SetMetadata() which acquire closeMu.RLock().
		_ = b.Close()

		if sync {
			if idx.hasUnsynced {
				if err := idx.db.Sync(); err != nil {
					return nil, fmt.Errorf("failed to flush prior unsynced writes: %w", err)
				}
				idx.hasUnsynced = false
			}
		} else {
			idx.hasUnsynced = true
		}

		idx.recordCachedEntries(newCachedEntries)
	} else {
		_ = b.Close()
		if sync {
			if len(rawTargetCP) > 0 {
				if err := idx.db.SetMetadata(KeyMetaKVCheckpoint, rawTargetCP); err != nil {
					return nil, fmt.Errorf("failed to set metadata kv_checkpoint: %w", err)
				}
			}
			if idx.hasUnsynced {
				if err := idx.db.Sync(); err != nil {
					return nil, fmt.Errorf("failed to flush prior unsynced writes: %w", err)
				}
				idx.hasUnsynced = false
			}
		}
	}

	return &IndexResult{
		NewKVSize:             max(newKVSize, persistedKVSize),
		ModifiedKeyValueRoots: modifiedKeyValueRoots,
	}, nil
}

// StageMappedBatch stages chunk mutations for batch into an indexed stagedBatch without applying them to DB.
// Cache entries are maintained in stagedBatch's overlay across multi-slab calls and promoted to KVIndexer only when db.Apply succeeds.
func (idx *KVIndexer) StageMappedBatch(ctx context.Context, stagedBatch *Batch, persistedKVSize uint64, batch *MappedBatch, targetSize uint64) (res *IndexResult, retErr error) {
	if stagedBatch == nil {
		return nil, errors.New("stagedBatch must not be nil")
	}
	if stagedBatch.err != nil {
		return nil, stagedBatch.err
	}
	if stagedBatch.db != idx.db || stagedBatch.b == nil || stagedBatch.applied || !stagedBatch.b.Indexed() {
		return nil, errors.New("stagedBatch must be an open indexed batch for this DB")
	}
	if batch == nil {
		return &IndexResult{
			NewKVSize:             persistedKVSize,
			ModifiedKeyValueRoots: make(map[string][sha256.Size]byte),
		}, nil
	}
	defer func() {
		if retErr != nil {
			idx.ClearCache()
		}
	}()

	modifiedKeyValueRoots, newCachedEntries, newKVSize, err := idx.buildBatchMutations(ctx, stagedBatch.b, stagedBatch.stagedCache, persistedKVSize, batch, targetSize)
	if err != nil {
		return nil, err
	}

	if newKVSize > persistedKVSize && len(newCachedEntries) > 0 {
		if stagedBatch.stagedCache == nil {
			stagedBatch.stagedCache = make(map[[sha256.Size]byte]activeChunkEntry, len(newCachedEntries))
			stagedBatch.onApply = append(stagedBatch.onApply, func() {
				idx.recordCachedEntries(stagedBatch.stagedCache)
			})
		}
		for k, v := range newCachedEntries {
			stagedBatch.stagedCache[k] = v
		}
	}

	return &IndexResult{
		NewKVSize:             max(newKVSize, persistedKVSize),
		ModifiedKeyValueRoots: modifiedKeyValueRoots,
	}, nil
}

func (idx *KVIndexer) recordCachedEntries(newCached map[[sha256.Size]byte]activeChunkEntry) {
	if len(idx.currentCache)+len(newCached) > maxGenChunkCacheSize {
		idx.previousCache = idx.currentCache
		idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, maxGenChunkCacheSize)
	}
	for k, v := range newCached {
		idx.currentCache[k] = v
	}
}

// newRawIterLocked opens a Pebble iterator while the caller's enclosing Batch already holds idx.db.closeMu.RLock().
func (idx *KVIndexer) newRawIterLocked(pBatch *pebble.Batch) (*pebble.Iterator, error) {
	if pBatch != nil && pBatch.Indexed() {
		return pBatch.NewIter(nil)
	}
	return idx.db.db.NewIter(nil)
}

type preparedKey struct {
	canon   string
	hash    [sha256.Size]byte
	indices []uint64
}

func (idx *KVIndexer) buildBatchMutations(
	ctx context.Context,
	pBatch *pebble.Batch,
	batchCache map[[sha256.Size]byte]activeChunkEntry,
	persistedKVSize uint64,
	batch *MappedBatch,
	targetSize uint64,
) (map[string][sha256.Size]byte, map[[sha256.Size]byte]activeChunkEntry, uint64, error) {
	canonKeys := make([]string, 0, len(batch.KeyIndices))
	for k, rawIndices := range batch.KeyIndices {
		if err := wire.ValidateCanonicalKey([]byte(k)); err != nil {
			return nil, nil, 0, err
		}
		if len(rawIndices) == 0 {
			continue
		}
		canonKeys = append(canonKeys, k)
	}
	slices.Sort(canonKeys)

	var maxLeafPlusOne uint64
	prepared := make([]preparedKey, len(canonKeys))
	for i, ck := range canonKeys {
		indices := slices.Clone(batch.KeyIndices[ck])
		if len(indices) > 1 {
			if !slices.IsSorted(indices) {
				slices.Sort(indices)
			}
			indices = slices.Compact(indices)
		}
		lastIdx := indices[len(indices)-1]
		if lastIdx == math.MaxUint64 {
			return nil, nil, 0, fmt.Errorf("leaf index %d overflows uint64 tree size", lastIdx)
		}
		if lastIdx+1 > maxLeafPlusOne {
			maxLeafPlusOne = lastIdx + 1
		}
		prepared[i] = preparedKey{
			canon:   ck,
			hash:    sha256.Sum256([]byte(ck)),
			indices: indices,
		}
	}

	newKVSize := batch.EndLeafIdx
	if newKVSize == 0 {
		newKVSize = max(targetSize, maxLeafPlusOne)
	}
	if maxLeafPlusOne > newKVSize {
		return nil, nil, 0, fmt.Errorf("leaf index %d out of bounds for batch end size %d", maxLeafPlusOne-1, newKVSize)
	}

	if len(prepared) == 0 {
		return make(map[string][sha256.Size]byte), nil, newKVSize, nil
	}

	const parallelThreshold = 32
	const minKeysPerWorker = 16
	workers := 1
	if idx.numWorkers > 1 && len(prepared) >= parallelThreshold && (pBatch == nil || !pBatch.Indexed()) {
		workers = max(1, min(idx.numWorkers, len(prepared)/minKeysPerWorker))
	}

	results := make([]keyProcessResult, len(prepared))
	runPartition := func(pCtx context.Context, start, end int, marshalBuf []byte, writes []chunkMutation) (_ []byte, _ []chunkMutation, retErr error) {
		var wIter *pebble.Iterator
		defer func() {
			if wIter != nil {
				if cErr := wIter.Close(); cErr != nil && retErr == nil {
					retErr = fmt.Errorf("close iterator: %w", cErr)
				}
			}
		}()
		getIter := func() (*pebble.Iterator, error) {
			if wIter == nil {
				var err error
				wIter, err = idx.newRawIterLocked(pBatch)
				if err != nil {
					return nil, fmt.Errorf("failed to create iterator: %w", err)
				}
			}
			return wIter, nil
		}

		for i := start; i < end; i++ {
			if err := pCtx.Err(); err != nil {
				return marshalBuf, writes, err
			}
			pk := &prepared[i]
			res, newBuf, err := idx.processKey(
				pk.hash, pk.indices, batchCache, persistedKVSize, newKVSize,
				marshalBuf, &writes, getIter,
			)
			if err != nil {
				return marshalBuf, writes, err
			}
			marshalBuf = newBuf
			results[i] = res
		}
		return marshalBuf, writes, nil
	}

	if workers == 1 {
		var err error
		idx.marshalBuf, idx.writesBuf, err = runPartition(ctx, 0, len(prepared), idx.marshalBuf[:0], idx.writesBuf[:0])
		if err != nil {
			return nil, nil, 0, err
		}
		if err := applyChunkMutations(pBatch, idx.writesBuf); err != nil {
			return nil, nil, 0, err
		}
	} else {
		partSize := (len(prepared) + workers - 1) / workers
		workerWrites := make([][]chunkMutation, workers)
		g, gCtx := errgroup.WithContext(ctx)

		for w := range workers {
			start := w * partSize
			if start >= len(prepared) {
				continue
			}
			end := min(start+partSize, len(prepared))
			g.Go(func() error {
				var err error
				_, workerWrites[w], err = runPartition(gCtx, start, end, make([]byte, 0, (end-start)*64), make([]chunkMutation, 0, end-start))
				return err
			})
		}
		if err := g.Wait(); err != nil {
			return nil, nil, 0, err
		}
		for _, wWrites := range workerWrites {
			if err := applyChunkMutations(pBatch, wWrites); err != nil {
				return nil, nil, 0, err
			}
		}
	}

	modifiedKeyValueRoots := make(map[string][sha256.Size]byte, len(prepared))
	newCachedEntries := make(map[[sha256.Size]byte]activeChunkEntry, len(prepared))
	for i := range results {
		r := &results[i]
		if r.hasValueRoot {
			modifiedKeyValueRoots[prepared[i].canon] = r.valueRoot
		}
		if r.hasCache {
			newCachedEntries[r.keyHash] = r.cached
		}
	}

	return modifiedKeyValueRoots, newCachedEntries, newKVSize, nil
}

func applyChunkMutations(pBatch *pebble.Batch, writes []chunkMutation) error {
	if pBatch == nil {
		return nil
	}
	for i := range writes {
		w := &writes[i]
		if err := pBatch.Set(w.key[:], w.val, nil); err != nil {
			return fmt.Errorf("failed to set chunk: %w", err)
		}
	}
	return nil
}

type chunkMutation struct {
	key [41]byte
	val []byte
}

type keyProcessResult struct {
	keyHash      [sha256.Size]byte
	valueRoot    [sha256.Size]byte
	hasValueRoot bool
	cached       activeChunkEntry
	hasCache     bool
}

func (idx *KVIndexer) processKey(
	keyHash [sha256.Size]byte,
	indices []uint64,
	batchCache map[[sha256.Size]byte]activeChunkEntry,
	persistedKVSize uint64,
	newKVSize uint64,
	marshalBuf []byte,
	writes *[]chunkMutation,
	getIter func() (*pebble.Iterator, error),
) (res keyProcessResult, outBuf []byte, err error) {
	res.keyHash = keyHash

	pos, _ := slices.BinarySearch(indices, persistedKVSize)
	unpersisted := indices[pos:]

	if len(unpersisted) == 0 {
		iter, err := getIter()
		if err != nil {
			return keyProcessResult{}, marshalBuf, err
		}
		vr, exists, err := idx.getValueRootWithIter(iter, keyHash, max(newKVSize, persistedKVSize))
		if err != nil {
			return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to get value root for key %x: %w", keyHash, err)
		}
		res.valueRoot = vr
		res.hasValueRoot = exists
		return res, marshalBuf, nil
	}

	var currChunkNum uint64
	var rec *chunkRecord
	var runningRange *compactRange

	var cached activeChunkEntry
	var inCache bool
	if batchCache != nil {
		cached, inCache = batchCache[keyHash]
	}
	if !inCache {
		cached, inCache = idx.currentCache[keyHash]
	}
	if !inCache {
		cached, inCache = idx.previousCache[keyHash]
	}
	if inCache {
		currChunkNum = cached.chunkNum
		rec = &chunkRecord{
			Preceding:       cached.record.Preceding,
			CompactRange:    slices.Clone(cached.record.CompactRange),
			RelativeIndices: slices.Clone(cached.record.RelativeIndices),
		}
		runningRange = cached.runningRange.clone()
	} else {
		prefix := encodeChunkPrefix(keyHash)
		iter, err := getIter()
		if err != nil {
			return keyProcessResult{}, marshalBuf, err
		}
		found := iter.SeekPrefixGE(prefix[:])
		if !found {
			if iErr := iter.Error(); iErr != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("seek chunk prefix: %w", iErr)
			}
		}
		if found && bytes.HasPrefix(iter.Key(), prefix[:]) {
			cNum, err := decodeChunkKey(iter.Key())
			if err != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to decode chunk key: %w", err)
			}
			currChunkNum = cNum
			rec, err = unmarshalChunkValue(iter.Value())
			if err != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to unmarshal chunk value: %w", err)
			}
			runningRange = &compactRange{
				Preceding: rec.Preceding,
				Hashes:    slices.Clone(rec.CompactRange),
			}
			chunkBase := currChunkNum * idx.chunkSize
			for _, rel := range rec.RelativeIndices {
				runningRange.appendIndex(chunkBase + uint64(rel))
			}
		} else {
			currChunkNum = unpersisted[0] / idx.chunkSize
			rec = &chunkRecord{}
			runningRange = newCompactRange()
		}
	}

	for _, leafIdx := range unpersisted {
		targetChunkNum := leafIdx / idx.chunkSize
		rel := uint16(leafIdx % idx.chunkSize)
		if targetChunkNum < currChunkNum || (targetChunkNum == currChunkNum && len(rec.RelativeIndices) > 0 && rel <= rec.RelativeIndices[len(rec.RelativeIndices)-1]) {
			continue
		}
		if targetChunkNum > currChunkNum {
			if len(rec.RelativeIndices) > 0 {
				start := len(marshalBuf)
				marshalBuf = appendChunkValue(marshalBuf, rec)
				*writes = append(*writes, chunkMutation{
					key: encodeChunkKey(keyHash, currChunkNum),
					val: marshalBuf[start:],
				})
			}

			currChunkNum = targetChunkNum
			rec = &chunkRecord{
				Preceding:    runningRange.Preceding,
				CompactRange: slices.Clone(runningRange.Hashes),
			}
		}
		rec.RelativeIndices = append(rec.RelativeIndices, rel)
		runningRange.appendIndex(leafIdx)
	}

	start := len(marshalBuf)
	marshalBuf = appendChunkValue(marshalBuf, rec)
	*writes = append(*writes, chunkMutation{
		key: encodeChunkKey(keyHash, currChunkNum),
		val: marshalBuf[start:],
	})

	res.valueRoot = runningRange.root()
	res.hasValueRoot = true
	res.cached = activeChunkEntry{
		chunkNum:     currChunkNum,
		record:       rec,
		runningRange: runningRange,
	}
	res.hasCache = true
	return res, marshalBuf, nil
}

func (idx *KVIndexer) getValueRootWithIter(iter *pebble.Iterator, keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, bool, error) {
	if maxInputLogSize == 0 {
		return [sha256.Size]byte{}, false, nil
	}

	maxChunkNum := (maxInputLogSize - 1) / idx.chunkSize
	seekKey := encodeChunkKey(keyHash, maxChunkNum)
	prefix := seekKey[:33]

	if !iter.SeekPrefixGE(seekKey[:]) {
		if iErr := iter.Error(); iErr != nil {
			return [sha256.Size]byte{}, false, fmt.Errorf("seek chunk prefix: %w", iErr)
		}
		return [sha256.Size]byte{}, false, nil
	}
	if !bytes.HasPrefix(iter.Key(), prefix) {
		return [sha256.Size]byte{}, false, nil
	}

	for ; iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		cNum, err := decodeChunkKey(iter.Key())
		if err != nil {
			return [sha256.Size]byte{}, false, err
		}
		if cNum > maxChunkNum {
			continue
		}

		rec, err := unmarshalChunkValue(iter.Value())
		if err != nil {
			return [sha256.Size]byte{}, false, err
		}

		cr := &compactRange{
			Preceding: rec.Preceding,
			Hashes:    slices.Clone(rec.CompactRange),
		}
		chunkBase := cNum * idx.chunkSize
		remBound := maxInputLogSize - chunkBase
		for _, rel := range rec.RelativeIndices {
			if uint64(rel) >= remBound {
				break
			}
			cr.appendIndex(chunkBase + uint64(rel))
		}

		if cr.Preceding == 0 {
			return [sha256.Size]byte{}, false, nil
		}
		return cr.root(), true, nil
	}
	if iErr := iter.Error(); iErr != nil {
		return [sha256.Size]byte{}, false, fmt.Errorf("iterate chunks: %w", iErr)
	}

	return [sha256.Size]byte{}, false, nil
}

// GetKeyValueRoots computes the value log roots for canonical keys with >= 1 occurrences below maxInputLogSize
// in parallel, reusing Pebble iterators across worker goroutines and performing zero storage writes.
// Keys with zero occurrences below maxInputLogSize are omitted from the returned map.
func (idx *KVIndexer) GetKeyValueRoots(ctx context.Context, keys []string, maxInputLogSize uint64) (map[string][sha256.Size]byte, error) {
	if len(keys) == 0 || maxInputLogSize == 0 {
		return make(map[string][sha256.Size]byte), nil
	}

	type rootEntry struct {
		root   [sha256.Size]byte
		exists bool
	}
	workers := max(1, min(idx.numWorkers, len(keys)))
	roots := make([]rootEntry, len(keys))
	partSize := (len(keys) + workers - 1) / workers
	g, gCtx := errgroup.WithContext(ctx)

	for w := range workers {
		start := w * partSize
		if start >= len(keys) {
			continue
		}
		end := min(start+partSize, len(keys))

		g.Go(func() (retErr error) {
			iter, err := idx.db.newIter()
			if err != nil {
				return fmt.Errorf("failed to create iterator: %w", err)
			}
			defer func() {
				if cErr := iter.Close(); cErr != nil && retErr == nil {
					retErr = fmt.Errorf("close iterator: %w", cErr)
				}
			}()

			for i := start; i < end; i++ {
				if err := gCtx.Err(); err != nil {
					return err
				}
				vr, exists, err := idx.getValueRootWithIter(iter.Iterator, sha256.Sum256([]byte(keys[i])), maxInputLogSize)
				if err != nil {
					return err
				}
				roots[i] = rootEntry{root: vr, exists: exists}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := make(map[string][sha256.Size]byte, len(keys))
	for i, k := range keys {
		if roots[i].exists {
			res[k] = roots[i].root
		}
	}
	return res, nil
}
