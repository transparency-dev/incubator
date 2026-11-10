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
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"testing"
)

func TestLookup_BoundsAndWatermarks(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 64
	db, indexer := openTestStore(t, chunkSize)

	const key = "com.example.bounds"
	keyHash := sha256.Sum256([]byte(key))
	absentHash := sha256.Sum256([]byte("com.example.absent"))

	// Chunk 0: {10, 25, 63}, Chunk 1: {64, 90}, Chunk 3 (sparse): {195}
	if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: 256,
		KeyIndices: map[string][]uint64{key: {10, 25, 63, 64, 90, 195}},
	}, nil, 256); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	u64 := func(v uint64) *uint64 { return &v }
	for _, tc := range []struct {
		name          string
		hash          [32]byte
		before        *uint64
		limit         uint64
		maxLogSize    uint64
		wantIndices   []uint64
		wantPreceding uint64
	}{
		{name: "absent_key", hash: absentHash, limit: 100, maxLogSize: 256},
		{name: "zero_max_log_size", hash: keyHash, limit: 100, maxLogSize: 0},
		{name: "before_at_first_entry", hash: keyHash, before: u64(10), limit: 100, maxLogSize: 256},
		{name: "whole_chunk_tip_alignment", hash: keyHash, limit: 2, maxLogSize: 95, wantIndices: []uint64{64, 90}, wantPreceding: 3},
		{name: "exact_chunk_boundary_max_size", hash: keyHash, limit: 100, maxLogSize: 64, wantIndices: []uint64{10, 25, 63}},
		{name: "split_chunk_skip_empty_newest_window", hash: keyHash, before: u64(64), limit: 100, maxLogSize: 256, wantIndices: []uint64{10, 25, 63}},
		{name: "uncommitted_watermark_hides_newer_chunks", hash: keyHash, limit: 100, maxLogSize: 100, wantIndices: []uint64{10, 25, 63, 64, 90}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := db.Lookup(tc.hash, tc.before, tc.limit, tc.maxLogSize)
			if err != nil {
				t.Fatalf("Lookup failed: %v", err)
			}
			if !slices.Equal(res.MatchedIndices, tc.wantIndices) || res.Preceding != tc.wantPreceding {
				t.Fatalf("Lookup = %+v, want indices=%v preceding=%d", res, tc.wantIndices, tc.wantPreceding)
			}
		})
	}
}

func TestLookup_ChunkAlignedPaging_MultiChunk(t *testing.T) {
	ctx := context.Background()
	db, indexer := openTestStore(t, 100)
	const key = "chunk_aligned_key"
	keyHash := sha256.Sum256([]byte(key))

	indices := []uint64{10, 20, 30, 110, 120, 130, 140, 150}
	if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: 200,
		KeyIndices: map[string][]uint64{key: indices},
	}, nil, 200); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	page1, err := db.Lookup(keyHash, nil, 2, 200)
	if err != nil {
		t.Fatalf("Page 1 Lookup failed: %v", err)
	}
	wantPage1 := []uint64{110, 120, 130, 140, 150}
	if !slices.Equal(page1.MatchedIndices, wantPage1) || page1.Preceding != 3 {
		t.Fatalf("Page 1 = %+v, want %v preceding=3", page1, wantPage1)
	}
	cr := &compactRange{Preceding: page1.Preceding, Hashes: page1.CompactRange}
	if cr.root() != computeExpectedValueRoot([]uint64{10, 20, 30}) {
		t.Fatalf("Page 1 preceding root = %x, want %x", cr.root(), computeExpectedValueRoot([]uint64{10, 20, 30}))
	}

	nextCursor := page1.MatchedIndices[0]
	page2, err := db.Lookup(keyHash, &nextCursor, 2, 200)
	if err != nil {
		t.Fatalf("Page 2 Lookup failed: %v", err)
	}
	if !slices.Equal(page2.MatchedIndices, []uint64{10, 20, 30}) || page2.Preceding != 0 {
		t.Fatalf("Page 2 = %+v, want [10 20 30] preceding=0", page2)
	}
}

func TestLookup_MaxChunksPerRequest_BoundedSparseKeys(t *testing.T) {
	ctx := context.Background()
	const customChunkSize = 64
	db, indexer := openTestStore(t, customChunkSize)
	db.maxChunksPerReq.Store(4)

	const key = "sparse_bounded_key"
	keyHash := sha256.Sum256([]byte(key))

	var wantAll []uint64
	for c := range uint64(10) {
		wantAll = append(wantAll, c*customChunkSize+7)
	}
	maxLogSize := uint64(10 * customChunkSize)
	if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: maxLogSize,
		KeyIndices: map[string][]uint64{key: wantAll},
	}, nil, maxLogSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	var collected []uint64
	var before *uint64
	pages := 0
	for {
		pages++
		res, err := db.Lookup(keyHash, before, 100, maxLogSize)
		if err != nil {
			t.Fatalf("page %d Lookup failed: %v", pages, err)
		}
		if len(res.MatchedIndices) > 4 {
			t.Fatalf("page %d returned %d entries, exceeding maxChunksPerReq=4", pages, len(res.MatchedIndices))
		}
		collected = append(slices.Clone(res.MatchedIndices), collected...)
		if res.Preceding == 0 {
			break
		}
		cursor := res.MatchedIndices[0]
		before = &cursor
	}
	if pages != 3 || !slices.Equal(collected, wantAll) {
		t.Fatalf("pages=%d collected=%v, want 3 and %v", pages, collected, wantAll)
	}
}

func TestLookup_LimitBounds(t *testing.T) {
	ctx := context.Background()
	const customChunkSize = 4
	const totalChunks = 1200
	db, indexer := openTestStore(t, customChunkSize)
	db.maxChunksPerReq.Store(2000)

	const key = "com.example.limits"
	keyHash := sha256.Sum256([]byte(key))
	indices := make([]uint64, totalChunks)
	for c := range totalChunks {
		indices[c] = uint64(c*customChunkSize + 1)
	}
	maxLogSize := uint64(totalChunks * customChunkSize)
	if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: maxLogSize,
		KeyIndices: map[string][]uint64{key: indices},
	}, nil, maxLogSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	for _, tc := range []struct {
		limit uint64
		want  int
	}{
		{limit: 1, want: 1},
		{limit: 0, want: 100},
		{limit: 5000, want: 1000},
	} {
		res, err := db.Lookup(keyHash, nil, tc.limit, maxLogSize)
		if err != nil || len(res.MatchedIndices) != tc.want {
			t.Fatalf("Lookup(limit=%d) len=%d err=%v, want %d", tc.limit, len(res.MatchedIndices), err, tc.want)
		}
	}
}

func TestLookup_MaxUint64ChunkOverflowGuard(t *testing.T) {
	ctx := context.Background()
	db, indexer := openTestStore(t, 100)

	const key = "com.example.topchunk"
	keyHash := sha256.Sum256([]byte(key))
	topBase := uint64(math.MaxUint64/100) * 100 // 18446744073709551600; (topChunk+1)*100 overflows uint64!
	idxA := topBase + 2
	idxB := topBase + 10

	if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
		StartLeafIdx: topBase,
		EndLeafIdx:   topBase + 15,
		KeyIndices:   map[string][]uint64{key: {idxA, idxB}},
	}, nil, topBase+15); err != nil {
		t.Fatalf("IndexMappedBatch(topChunk) failed: %v", err)
	}

	cutoff := topBase + 5
	res, err := db.Lookup(keyHash, &cutoff, 100, topBase+15)
	if err != nil {
		t.Fatalf("Lookup(topChunk) failed: %v", err)
	}
	if !slices.Equal(res.MatchedIndices, []uint64{idxA}) {
		t.Fatalf("Lookup(topChunk, before=%d) = %v, want [%d] (must not leak %d)", cutoff, res.MatchedIndices, idxA, idxB)
	}

	roots, err := indexer.GetKeyValueRoots(ctx, []string{key}, cutoff)
	if err != nil || roots[key] != computeExpectedValueRoot([]uint64{idxA}) {
		t.Fatalf("GetKeyValueRoots(topChunk, cutoff=%d) = %x, err=%v", cutoff, roots[key], err)
	}
}

func BenchmarkLookup_MultiChunk(b *testing.B) {
	ctx := context.Background()
	db, err := Open(filepath.Join(b.TempDir(), "db_reader_bench"), &Options{ChunkSize: 1000})
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexer := NewKVIndexer(db)
	const key = "bench_multichunk_key"
	keyHash := sha256.Sum256([]byte(key))
	const totalEntries = 50000
	indices := make([]uint64, totalEntries)
	for i := range indices {
		indices[i] = uint64(i)
	}
	if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
		EndLeafIdx: totalEntries,
		KeyIndices: map[string][]uint64{key: indices},
	}, nil, totalEntries); err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		res, err := db.Lookup(keyHash, nil, 100, totalEntries)
		if err != nil || len(res.MatchedIndices) == 0 {
			b.Fatalf("Lookup failed: %v", err)
		}
	}
}

func BenchmarkLookup_AbsentKey_FlushedSSTables(b *testing.B) {
	ctx := context.Background()
	db, err := Open(filepath.Join(b.TempDir(), "db_bloom_bench"), nil)
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexer := NewKVIndexer(db)
	const numFlushes = 6
	const keysPerFlush = 2000

	for f := range numFlushes {
		keyIndices := make(map[string][]uint64, keysPerFlush)
		startLeaf := uint64(f * keysPerFlush)
		for i := range keysPerFlush {
			k := fmt.Sprintf("present_%d_%d", f, i)
			keyIndices[k] = []uint64{startLeaf + uint64(i)}
		}
		if _, err := indexer.IndexMappedBatch(ctx, &MappedBatch{
			StartLeafIdx: startLeaf,
			EndLeafIdx:   startLeaf + keysPerFlush,
			KeyIndices:   keyIndices,
		}, nil, startLeaf+keysPerFlush); err != nil {
			b.Fatalf("IndexMappedBatch failed: %v", err)
		}
		if err := db.Sync(); err != nil {
			b.Fatalf("Sync failed: %v", err)
		}
	}

	absentKeys := make([][32]byte, 1024)
	for i := range absentKeys {
		absentKeys[i] = sha256.Sum256([]byte(fmt.Sprintf("absent_%d", i)))
	}
	maxLogSize := uint64(numFlushes * keysPerFlush)

	b.ReportAllocs()
	var i int
	for b.Loop() {
		res, err := db.Lookup(absentKeys[i&1023], nil, 100, maxLogSize)
		if err != nil || len(res.MatchedIndices) != 0 {
			b.Fatalf("Lookup failed: %v", err)
		}
		i++
	}
}
