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
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"testing"
)

func openTestStore(t *testing.T, chunkSize uint64) (*DB, *KVIndexer) {
	t.Helper()
	db, err := Open("", &Options{ChunkSize: chunkSize})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, NewKVIndexer(db)
}

func TestKVIndexer_SingleChunkAndMetadata(t *testing.T) {
	ctx := context.Background()
	db, idx := openTestStore(t, 256)

	const (
		key1 = "com.example."
		key2 = "com.google."
	)
	batch := &MappedBatch{
		EndLeafIdx: 100,
		KeyIndices: map[string][]uint64{
			key1: {0, 5, 50},
			key2: {0, 10, 50},
		},
	}
	rawCP := []byte("checkpoint_data_v1")

	res, err := idx.IndexMappedBatch(ctx, batch, rawCP, 100)
	if err != nil || res.NewKVSize != 100 {
		t.Fatalf("IndexMappedBatch res=%+v err=%v", res, err)
	}

	if kvSize, err := db.GetUint64(KeyMetaKVSize); err != nil || kvSize != 100 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 100", kvSize, err)
	}
	if kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint); err != nil || !bytes.Equal(kvCP, rawCP) {
		t.Fatalf("KeyMetaKVCheckpoint = %q, want %q", string(kvCP), string(rawCP))
	}

	want1 := computeExpectedValueRoot([]uint64{0, 5, 50})
	want2 := computeExpectedValueRoot([]uint64{0, 10, 50})
	if res.ModifiedKeyValueRoots[key1] != want1 || res.ModifiedKeyValueRoots[key2] != want2 {
		t.Fatalf("value roots mismatch: got %x / %x", res.ModifiedKeyValueRoots[key1], res.ModifiedKeyValueRoots[key2])
	}
}

func TestKVIndexer_MultiChunkRolloverAndIncremental(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 16
	db, idx := openTestStore(t, chunkSize)

	const key = "incremental_test_key"
	var allIndices []uint64
	for batchNum := range 10 {
		var batchIndices []uint64
		for i := range 25 {
			leafIdx := uint64(batchNum*25 + i)
			allIndices = append(allIndices, leafIdx)
			batchIndices = append(batchIndices, leafIdx)
		}
		res, err := idx.IndexMappedBatch(ctx, &MappedBatch{
			StartLeafIdx: uint64(batchNum * 25),
			EndLeafIdx:   uint64((batchNum + 1) * 25),
			KeyIndices:   map[string][]uint64{key: batchIndices},
		}, nil, 0)
		if err != nil {
			t.Fatalf("batch %d failed: %v", batchNum, err)
		}
		if res.ModifiedKeyValueRoots[key] != computeExpectedValueRoot(allIndices) {
			t.Fatalf("batch %d value root mismatch", batchNum)
		}
	}

	prefix := encodeChunkPrefix(sha256.Sum256([]byte(key)))
	iter, err := db.newIter()
	if err != nil {
		t.Fatalf("newIter failed: %v", err)
	}
	defer func() { _ = iter.Close() }()
	if !iter.SeekPrefixGE(prefix[:]) {
		t.Fatal("SeekPrefixGE failed to find key prefix")
	}
	activeChunkNum, err := decodeChunkKey(iter.Key())
	if err != nil || activeChunkNum != uint64(249/chunkSize) {
		t.Fatalf("active chunk num = %d (err=%v), want %d", activeChunkNum, err, 249/chunkSize)
	}
}

func TestKVIndexer_SyncBarriersAndUnalignedOffsets(t *testing.T) {
	ctx := context.Background()
	db, idx := openTestStore(t, ChunkSize)

	rawCP := []byte("checkpoint_multi_batch")
	const key = "multi_batch_key"

	res1, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		KeyIndices:   map[string][]uint64{key: {10, 20}},
	}, rawCP, 100)
	if err != nil || res1.NewKVSize != 50 {
		t.Fatalf("batch1 res=%+v err=%v", res1, err)
	}
	if !idx.hasUnsynced {
		t.Fatal("expected hasUnsynced=true after NoSync intermediate batch")
	}
	if kvCP1, _ := db.GetMetadata(KeyMetaKVCheckpoint); len(kvCP1) != 0 {
		t.Fatalf("intermediate batch must not write KeyMetaKVCheckpoint, got %q", string(kvCP1))
	}

	res2, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		StartLeafIdx: 50,
		EndLeafIdx:   100,
	}, rawCP, 100)
	if err != nil || res2.NewKVSize != 100 {
		t.Fatalf("batch2 res=%+v err=%v", res2, err)
	}
	if idx.hasUnsynced {
		t.Fatal("expected hasUnsynced=false after final Sync barrier")
	}
	if kvCP2, _ := db.GetMetadata(KeyMetaKVCheckpoint); !bytes.Equal(kvCP2, rawCP) {
		t.Fatalf("final batch must write KeyMetaKVCheckpoint, got %q", string(kvCP2))
	}
}

func TestKVIndexer_GenerationalCacheAndUint16Boundary(t *testing.T) {
	ctx := context.Background()
	db, idx := openTestStore(t, ChunkSize)

	const hotKey = "hot_boundary_key"
	hotHash := sha256.Sum256([]byte(hotKey))
	if _, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		StartLeafIdx: 0,
		EndLeafIdx:   ChunkSize,
		KeyIndices:   map[string][]uint64{hotKey: {ChunkSize - 2, ChunkSize - 1}},
	}, nil, 0); err != nil {
		t.Fatalf("IndexMappedBatch 1 failed: %v", err)
	}

	for i := range maxGenChunkCacheSize + 5 {
		var k [32]byte
		binary.BigEndian.PutUint64(k[:], uint64(i+100))
		idx.currentCache[k] = activeChunkEntry{chunkNum: 0, record: &chunkRecord{}}
	}

	res2, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		StartLeafIdx: ChunkSize,
		EndLeafIdx:   ChunkSize + 100,
		KeyIndices:   map[string][]uint64{hotKey: {ChunkSize, ChunkSize + 1}},
	}, nil, 0)
	if err != nil {
		t.Fatalf("IndexMappedBatch 2 failed: %v", err)
	}

	all := []uint64{ChunkSize - 2, ChunkSize - 1, ChunkSize, ChunkSize + 1}
	if res2.ModifiedKeyValueRoots[hotKey] != computeExpectedValueRoot(all) {
		t.Fatal("valueRoot mismatch across uint16 chunk boundary")
	}
	if _, ok := idx.currentCache[hotHash]; !ok {
		t.Fatal("hotKey was not promoted to currentCache")
	}

	lookupRes, err := db.Lookup(hotHash, nil, 10, ChunkSize+100)
	if err != nil || !slices.Equal(lookupRes.MatchedIndices, all) {
		t.Fatalf("Lookup = %+v, err=%v, want %v", lookupRes, err, all)
	}
}

func TestKVIndexer_NoPhantomChunk0_And_CallerSliceImmutability(t *testing.T) {
	ctx := context.Background()
	db, idx := openTestStore(t, ChunkSize)

	const sparseKey = "sparse_first_seen_chunk_5"
	firstLeaf := 5*ChunkSize + 42
	callerSlice := []uint64{firstLeaf + 10, firstLeaf, firstLeaf + 10}
	origCopy := slices.Clone(callerSlice)

	res, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		StartLeafIdx: 5 * ChunkSize,
		EndLeafIdx:   6 * ChunkSize,
		KeyIndices:   map[string][]uint64{sparseKey: callerSlice},
	}, nil, 0)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}
	if !slices.Equal(callerSlice, origCopy) {
		t.Fatalf("caller slice mutated: got %v, want %v", callerSlice, origCopy)
	}
	if res.ModifiedKeyValueRoots[sparseKey] != computeExpectedValueRoot([]uint64{firstLeaf, firstLeaf + 10}) {
		t.Fatal("unexpected value root")
	}

	prefix := encodeChunkPrefix(sha256.Sum256([]byte(sparseKey)))
	iter, err := db.newIter()
	if err != nil {
		t.Fatalf("newIter failed: %v", err)
	}
	defer func() { _ = iter.Close() }()
	var chunksFound []uint64
	for ok := iter.SeekPrefixGE(prefix[:]); ok && bytes.HasPrefix(iter.Key(), prefix[:]); ok = iter.Next() {
		cNum, err := decodeChunkKey(iter.Key())
		if err != nil {
			t.Fatalf("decodeChunkKey failed: %v", err)
		}
		chunksFound = append(chunksFound, cNum)
	}
	if !slices.Equal(chunksFound, []uint64{5}) {
		t.Fatalf("stored chunks = %v, want [5]", chunksFound)
	}
}

func TestKVIndexer_GetKeyValueRoots_Watermarks_And_ZeroOccurrenceExclusion(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 32
	_, idx := openTestStore(t, chunkSize)
	idx.SetNumWorkers(4)

	const numKeys = 50
	keys := make([]string, numKeys)
	keyIndices := make(map[string][]uint64, numKeys)
	expectedRoots := make(map[string][sha256.Size]byte, numKeys)

	for i := range numKeys {
		k := fmt.Sprintf("parallel_key_%d", i)
		keys[i] = k
		var indices []uint64
		for j := range (i % 10) + 1 {
			indices = append(indices, uint64(i*5+j*20))
		}
		keyIndices[k] = indices
		expectedRoots[k] = computeExpectedValueRoot(indices)
	}

	res, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: 1000,
		KeyIndices: keyIndices,
	}, nil, 0)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	roots, err := idx.GetKeyValueRoots(ctx, append(slices.Clone(keys), "absent.key"), 1000)
	if err != nil || len(roots) != numKeys {
		t.Fatalf("GetKeyValueRoots len=%d err=%v, want %d (absent key must be omitted)", len(roots), err, numKeys)
	}
	for _, k := range keys {
		if roots[k] != expectedRoots[k] || roots[k] != res.ModifiedKeyValueRoots[k] {
			t.Fatalf("GetKeyValueRoots[%q] = %x, want %x", k, roots[k], expectedRoots[k])
		}
	}

	// Cutoff filtering: keys whose first occurrence is >= cutoff must be omitted, not EmptyRoot().
	cutoff := uint64(50)
	partialRoots, err := idx.GetKeyValueRoots(ctx, keys, cutoff)
	if err != nil {
		t.Fatalf("GetKeyValueRoots(cutoff=50) failed: %v", err)
	}
	for _, k := range keys {
		var below []uint64
		for _, off := range keyIndices[k] {
			if off < cutoff {
				below = append(below, off)
			}
		}
		got, ok := partialRoots[k]
		if len(below) == 0 {
			if ok {
				t.Fatalf("key %q has 0 occurrences < %d, but was emitted with %x", k, cutoff, got)
			}
		} else if !ok || got != computeExpectedValueRoot(below) {
			t.Fatalf("key %q at cutoff %d: ok=%v got=%x, want %x", k, cutoff, ok, got, computeExpectedValueRoot(below))
		}
	}

	if zeroRoots, err := idx.GetKeyValueRoots(ctx, keys, 0); err != nil || len(zeroRoots) != 0 {
		t.Fatalf("GetKeyValueRoots(maxInputLogSize=0) = %v, err=%v, want empty map", zeroRoots, err)
	}
}

func TestKVIndexer_CrashReplayOverlap_WarmAndColdCache(t *testing.T) {
	ctx := context.Background()
	for _, clearCache := range []bool{false, true} {
		t.Run(fmt.Sprintf("cold_cache_%v", clearCache), func(t *testing.T) {
			_, idx := openTestStore(t, 16)
			const kOverlap = "com.example.overlap"
			const kOnlyOld = "com.example.old"

			if _, err := idx.IndexMappedBatch(ctx, &MappedBatch{
				StartLeafIdx: 0,
				EndLeafIdx:   30,
				KeyIndices: map[string][]uint64{
					kOverlap: {2, 15, 16, 25},
					kOnlyOld: {4, 18},
				},
			}, nil, 0); err != nil {
				t.Fatalf("initial IndexMappedBatch failed: %v", err)
			}
			if clearCache {
				idx.ClearCache()
			}

			// Replay overlapping batch [10, 45): offsets < 30 must be skipped idempotently.
			res, err := idx.IndexMappedBatch(ctx, &MappedBatch{
				StartLeafIdx: 10,
				EndLeafIdx:   45,
				KeyIndices: map[string][]uint64{
					kOverlap: {15, 16, 25, 32, 40},
					kOnlyOld: {18},
				},
			}, nil, 45)
			if err != nil {
				t.Fatalf("overlapping IndexMappedBatch failed: %v", err)
			}
			if res.ModifiedKeyValueRoots[kOverlap] != computeExpectedValueRoot([]uint64{2, 15, 16, 25, 32, 40}) {
				t.Fatalf("kOverlap root mismatch after overlap replay")
			}
			if res.ModifiedKeyValueRoots[kOnlyOld] != computeExpectedValueRoot([]uint64{4, 18}) {
				t.Fatalf("kOnlyOld root mismatch after full-replay path")
			}
		})
	}
}

func TestKVIndexer_ValidationGuards(t *testing.T) {
	ctx := context.Background()
	_, idx := openTestStore(t, 64)

	for name, b := range map[string]*MappedBatch{
		"empty_key":        {EndLeafIdx: 10, KeyIndices: map[string][]uint64{"": {1}}},
		"whitespace_key":   {EndLeafIdx: 10, KeyIndices: map[string][]uint64{"bad key": {1}}},
		"index_ge_end":     {EndLeafIdx: 10, KeyIndices: map[string][]uint64{"com.example.a": {10}}},
		"max_uint64_index": {KeyIndices: map[string][]uint64{"com.example.a": {math.MaxUint64}}},
	} {
		if _, err := idx.IndexMappedBatch(ctx, b, nil, 0); err == nil {
			t.Errorf("%s: expected error from IndexMappedBatch, got nil", name)
		}
	}

	// Empty slice for valid key is omitted from ModifiedKeyValueRoots.
	res, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: 10,
		KeyIndices: map[string][]uint64{"com.example.empty": nil},
	}, nil, 10)
	if err != nil || len(res.ModifiedKeyValueRoots) != 0 {
		t.Fatalf("empty index slice: res=%+v err=%v", res, err)
	}
}

func TestKVIndexer_StagedBatch_MultiSlabAndRollback(t *testing.T) {
	ctx := context.Background()
	db, idx := openTestStore(t, 32)
	const key = "staged.multi.key"

	// 1. Aborted staged batch must NOT pollute KVIndexer cache or DB.
	aborted := db.NewIndexedBatch()
	if _, err := idx.StageMappedBatch(ctx, aborted, 0, &MappedBatch{
		EndLeafIdx: 20,
		KeyIndices: map[string][]uint64{key: {1, 2}},
	}, 20); err != nil {
		t.Fatalf("StageMappedBatch(aborted) failed: %v", err)
	}
	_ = aborted.Close()
	if len(idx.currentCache) != 0 {
		t.Fatalf("aborted StageMappedBatch polluted cache: len=%d", len(idx.currentCache))
	}

	// 2. Pre-populate committed batch so key is ALREADY in idx.currentCache ({1, 2}),
	// then stage 3 slabs into one stagedBatch (Slab 1 adds {10, 15}, Slab 2 adds {25, 30}, Slab 3 has unpersisted==0).
	if _, err := idx.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: 5,
		KeyIndices: map[string][]uint64{key: {1, 2}},
	}, nil, 5); err != nil {
		t.Fatalf("initial IndexMappedBatch failed: %v", err)
	}

	staged := db.NewIndexedBatch()
	defer func() { _ = staged.Close() }()

	if _, err := idx.StageMappedBatch(ctx, staged, 5, &MappedBatch{
		StartLeafIdx: 5,
		EndLeafIdx:   20,
		KeyIndices:   map[string][]uint64{key: {10, 15}},
	}, 50); err != nil {
		t.Fatalf("StageMappedBatch slab 1 failed: %v", err)
	}
	// Slab 2 must consult stagedBatch's overlay ({1, 2, 10, 15}), NOT stale idx.currentCache ({1, 2})!
	if _, err := idx.StageMappedBatch(ctx, staged, 20, &MappedBatch{
		StartLeafIdx: 20,
		EndLeafIdx:   35,
		KeyIndices:   map[string][]uint64{key: {25, 30}},
	}, 50); err != nil {
		t.Fatalf("StageMappedBatch slab 2 failed: %v", err)
	}
	// Slab 3 re-encounters key with indices < stagedKVSize (unpersisted==0): must read all {1, 2, 10, 15, 25, 30}.
	res3, err := idx.StageMappedBatch(ctx, staged, 35, &MappedBatch{
		StartLeafIdx: 35,
		EndLeafIdx:   50,
		KeyIndices:   map[string][]uint64{key: {30}},
	}, 50)
	if err != nil {
		t.Fatalf("StageMappedBatch slab 3 failed: %v", err)
	}
	wantRoot := computeExpectedValueRoot([]uint64{1, 2, 10, 15, 25, 30})
	if res3.ModifiedKeyValueRoots[key] != wantRoot {
		t.Fatalf("staged multi-slab root = %x, want %x", res3.ModifiedKeyValueRoots[key], wantRoot)
	}

	if err := staged.SetUint64(KeyMetaKVSize, res3.NewKVSize); err != nil {
		t.Fatalf("staged.SetUint64 failed: %v", err)
	}
	if err := db.Apply(staged, true); err != nil {
		t.Fatalf("db.Apply failed: %v", err)
	}
	roots, err := idx.GetKeyValueRoots(ctx, []string{key}, 50)
	if err != nil || roots[key] != wantRoot {
		t.Fatalf("committed staged key root = %x, want %x (err=%v)", roots[key], wantRoot, err)
	}
}

func BenchmarkKVIndexer_IndexBatch_1000Keys(b *testing.B) {
	for _, workers := range []int{1, 4, 8} {
		b.Run(fmt.Sprintf("workers_%d", workers), func(b *testing.B) {
			ctx := context.Background()
			db, err := Open(b.TempDir(), nil)
			if err != nil {
				b.Fatalf("Open failed: %v", err)
			}
			defer func() { _ = db.Close() }()

			idx := NewKVIndexer(db)
			idx.SetNumWorkers(workers)

			const numKeys = 1000
			keys := make([]string, numKeys)
			for i := range keys {
				keys[i] = fmt.Sprintf("bench-key-%d", i)
			}

			const targetSize = uint64(100000000)
			b.ReportAllocs()

			var leafOffset uint64
			for b.Loop() {
				keyIndices := make(map[string][]uint64, numKeys)
				for j := range numKeys {
					keyIndices[keys[j]] = []uint64{leafOffset + uint64(j)}
				}
				batch := &MappedBatch{
					StartLeafIdx: leafOffset,
					EndLeafIdx:   leafOffset + numKeys,
					KeyIndices:   keyIndices,
				}
				if _, err := idx.IndexMappedBatch(ctx, batch, nil, targetSize); err != nil {
					b.Fatalf("IndexMappedBatch failed: %v", err)
				}
				leafOffset += numKeys
			}
		})
	}
}
