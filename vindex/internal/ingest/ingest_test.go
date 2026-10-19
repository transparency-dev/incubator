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

package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type mockTileFetcher struct {
	leaves     [][]byte
	origin     string
	bundleSize uint64
}

func (f *mockTileFetcher) Checkpoint(_ context.Context) (*Checkpoint, error) {
	root := sha256.Sum256([]byte(fmt.Sprintf("%d", len(f.leaves))))
	return &Checkpoint{
		Raw:    []byte(fmt.Sprintf("%s\n%d\n%x\n", f.origin, len(f.leaves), root)),
		Origin: f.origin,
		Size:   uint64(len(f.leaves)),
		Hash:   root,
	}, nil
}

func (f *mockTileFetcher) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	if idx >= uint64(len(f.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (len %d)", idx, len(f.leaves))
	}
	return f.leaves[idx], nil
}

func (f *mockTileFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	bsz := f.bundleSize
	if bsz == 0 {
		bsz = uint64(layout.EntryBundleWidth)
	}
	adapter := &LeafAdapter{
		LeafFn:     f.Leaf,
		BundleSize: bsz,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func TestIngestionPipeline_EndToEndResequencing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 4)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	var receivedCount uint64
	var expectedNextStart uint64 = 0

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)

		// Verify key mappings
		for k, idxs := range batch.KeyIndices {
			if len(idxs) == 0 {
				t.Fatalf("empty indices for key %q", k)
			}
		}
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	if receivedCount != totalLeaves {
		t.Fatalf("received %d leaves, want %d", receivedCount, totalLeaves)
	}
}

func TestNewTiledFetcher_DefaultHTTPClient(t *testing.T) {
	u, err := url.Parse("https://example.com/log")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}
	f, err := NewTiledFetcher(u, nil, "example-origin", nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}
	if f == nil || f.isStaticCT {
		t.Fatalf("expected non-StaticCT TiledFetcher, got %+v", f)
	}

	ctURL, _ := url.Parse("https://Sycamore.ct.transparency.dev/2026h1/")
	ctFetcher, err := NewTiledFetcher(ctURL, nil, "sycamore.ct.transparency.dev/2026h1", nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher(ct) failed: %v", err)
	}
	ctFetcher.SetStaticCT(true)
	if !ctFetcher.isStaticCT {
		t.Fatal("expected isStaticCT = true after SetStaticCT(true)")
	}
}

type mockTiledReader struct {
	readEntryBundleFn func(ctx context.Context, i uint64, p uint8) ([]byte, error)
	readTileFn        func(ctx context.Context, l, i uint64, p uint8) ([]byte, error)
}

func (m *mockTiledReader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (m *mockTiledReader) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	if m.readTileFn != nil {
		return m.readTileFn(ctx, l, i, p)
	}
	if m.readEntryBundleFn != nil {
		bundleBytes, err := m.readEntryBundleFn(ctx, i, p)
		if err != nil {
			return nil, err
		}
		var eb api.EntryBundle
		if err := eb.UnmarshalText(bundleBytes); err != nil {
			return nil, err
		}
		var tileData []byte
		for _, leaf := range eb.Entries {
			h := tlog.RecordHash(leaf)
			tileData = append(tileData, h[:]...)
		}
		return tileData, nil
	}
	return nil, nil
}

func (m *mockTiledReader) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	if m.readEntryBundleFn != nil {
		return m.readEntryBundleFn(ctx, i, p)
	}
	return nil, nil
}

func TestTiledFetcher_FetchTiles_ParallelOrdering(t *testing.T) {
	ctx := t.Context()

	var activeGoroutines atomic.Int32
	var maxConcurrent atomic.Int32

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, i uint64, _ uint8) ([]byte, error) {
			cur := activeGoroutines.Add(1)
			defer activeGoroutines.Add(-1)

			for {
				max := maxConcurrent.Load()
				if cur <= max || maxConcurrent.CompareAndSwap(max, cur) {
					break
				}
			}

			time.Sleep(10 * time.Millisecond)
			entry := []byte(fmt.Sprintf("entry_for_bundle_%d", i))
			var buf []byte
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(entry)))
			buf = append(buf, entry...)
			return buf, nil
		},
	}

	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 5 * uint64(layout.EntryBundleWidth),
	}

	bundles, err := fetcher.FetchTiles(ctx, 0, 5*uint64(layout.EntryBundleWidth))
	if err != nil {
		t.Fatalf("FetchTiles failed: %v", err)
	}

	if len(bundles) != 5 {
		t.Fatalf("got %d bundles, want 5", len(bundles))
	}

	for i, b := range bundles {
		if b.BundleIdx != uint64(i) {
			t.Fatalf("bundle[%d].BundleIdx = %d, want %d", i, b.BundleIdx, i)
		}
		if b.StartLeafIdx != uint64(i)*uint64(layout.EntryBundleWidth) {
			t.Fatalf("bundle[%d].StartLeafIdx = %d, want %d", i, b.StartLeafIdx, uint64(i)*uint64(layout.EntryBundleWidth))
		}
		if len(b.Leaves) == 0 {
			t.Fatalf("bundle[%d] has 0 leaves", i)
		}
	}

	if maxConcurrent.Load() < 2 {
		t.Fatalf("expected concurrent bundle downloads, maxConcurrent = %d", maxConcurrent.Load())
	}
}

func TestMappedBatch_Merge(t *testing.T) {
	b1 := &MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   256,
		Count:        256,
		KeyIndices: map[string][]uint64{
			"key1": {0, 10},
			"key2": {5},
		},
	}

	// Merging nil should be a no-op
	b1.Merge(nil)
	if b1.EndLeafIdx != 256 || b1.Count != 256 {
		t.Fatalf("unexpected state after nil merge: end=%d count=%d", b1.EndLeafIdx, b1.Count)
	}

	b2 := &MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 256,
		EndLeafIdx:   512,
		Count:        256,
		KeyIndices: map[string][]uint64{
			"key1": {260},
			"key3": {300, 301},
		},
	}

	b1.Merge(b2)

	if b1.StartLeafIdx != 0 {
		t.Errorf("StartLeafIdx = %d, want 0", b1.StartLeafIdx)
	}
	if b1.EndLeafIdx != 512 {
		t.Errorf("EndLeafIdx = %d, want 512", b1.EndLeafIdx)
	}
	if b1.Count != 512 {
		t.Errorf("Count = %d, want 512", b1.Count)
	}

	wantK1 := []uint64{0, 10, 260}
	if len(b1.KeyIndices["key1"]) != len(wantK1) {
		t.Fatalf("k1 len = %d, want %d", len(b1.KeyIndices["key1"]), len(wantK1))
	}
	for i, v := range wantK1 {
		if b1.KeyIndices["key1"][i] != v {
			t.Errorf("k1[%d] = %d, want %d", i, b1.KeyIndices["key1"][i], v)
		}
	}

	wantK2 := []uint64{5}
	if len(b1.KeyIndices["key2"]) != len(wantK2) || b1.KeyIndices["key2"][0] != 5 {
		t.Errorf("k2 mismatch: %v", b1.KeyIndices["key2"])
	}

	wantK3 := []uint64{300, 301}
	if len(b1.KeyIndices["key3"]) != len(wantK3) {
		t.Errorf("k3 mismatch: %v", b1.KeyIndices["key3"])
	}
}

func TestIngestionPipeline_UnalignedAndBoundaryRanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	leaves := make([][]byte, totalLeaves)
	for i := 0; i < totalLeaves; i++ {
		leaves[i] = []byte(fmt.Sprintf("entry_leaf_%d", i))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	wasmHost := wasmhosttest.Host()

	cases := []struct {
		name         string
		fromIdx      uint64
		targetSize   uint64
		fetchWorkers int
	}{
		{name: "unaligned_from", fromIdx: 100, targetSize: 600, fetchWorkers: 1},
		{name: "unaligned_target", fromIdx: 0, targetSize: 350, fetchWorkers: 1},
		{name: "unaligned_both_ends", fromIdx: 123, targetSize: 456, fetchWorkers: 4},
		{name: "single_bundle_subslice", fromIdx: 50, targetSize: 150, fetchWorkers: 2},
		{name: "empty_equal_range", fromIdx: 100, targetSize: 100, fetchWorkers: 1},
		{name: "inverted_range", fromIdx: 200, targetSize: 100, fetchWorkers: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline := NewPipeline(fetcher, nil, wasmHost, 4)
			pipeline.SetFetchWorkers(tc.fetchWorkers)

			batchChan, errChan := pipeline.StreamBatches(ctx, tc.fromIdx, tc.targetSize)
			var receivedCount uint64
			expectedNextStart := tc.fromIdx
			for batch := range batchChan {
				if batch.StartLeafIdx != expectedNextStart {
					t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
				}
				expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
				receivedCount += uint64(batch.Count)
			}
			if err := <-errChan; err != nil {
				t.Fatalf("pipeline returned error: %v", err)
			}

			var wantCount uint64
			if tc.targetSize > tc.fromIdx {
				wantCount = tc.targetSize - tc.fromIdx
			}
			if receivedCount != wantCount {
				t.Fatalf("received %d leaves, want %d", receivedCount, wantCount)
			}
		})
	}
}

func TestLeafAdapter_UnalignedStartAlignsToBundleBoundaries(t *testing.T) {
	ctx := context.Background()
	adapter := &LeafAdapter{
		BundleSize: 256,
		LeafFn: func(_ context.Context, idx uint64) ([]byte, error) {
			return []byte(fmt.Sprintf("entry_leaf_%d", idx)), nil
		},
	}

	// Request [100, 600): must return bundle-aligned bundles 0 [0..256), 1 [256..512), 2 [512..600).
	bundles, err := adapter.FetchTiles(ctx, 100, 500)
	if err != nil {
		t.Fatalf("FetchTiles failed: %v", err)
	}
	if len(bundles) != 3 {
		t.Fatalf("got %d bundles, want 3", len(bundles))
	}
	wantStarts := []uint64{0, 256, 512}
	wantLens := []int{256, 256, 88}
	for i, b := range bundles {
		if b.BundleIdx != uint64(i) || b.StartLeafIdx != wantStarts[i] || len(b.Leaves) != wantLens[i] {
			t.Fatalf("bundle[%d] = {Idx:%d, Start:%d, Len:%d}, want {Idx:%d, Start:%d, Len:%d}",
				i, b.BundleIdx, b.StartLeafIdx, len(b.Leaves), i, wantStarts[i], wantLens[i])
		}
	}

	// Caching bundles fetched from an unaligned start [100, 600) must subsequently satisfy [50, 100) from cache without panicking.
	cache, err := NewManagedTileCache(t.TempDir(), 256)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}
	pipeline := NewPipeline(adapter, cache, wasmhosttest.Host(), 2)
	b1, e1 := pipeline.StreamBatches(ctx, 100, 600)
	for range b1 {
	}
	if err := <-e1; err != nil {
		t.Fatalf("StreamBatches [100, 600) failed: %v", err)
	}

	cacheOnlyPipeline := NewPipeline(nil, cache, wasmhosttest.Host(), 2)
	b2, e2 := cacheOnlyPipeline.StreamBatches(ctx, 50, 100)
	var got uint64
	for batch := range b2 {
		got += uint64(batch.Count)
	}
	if err := <-e2; err != nil {
		t.Fatalf("StreamBatches [50, 100) from cache failed: %v", err)
	}
	if got != 50 {
		t.Fatalf("got %d leaves from cache, want 50", got)
	}

	// Cache miss with nil fetcher must return a clean error rather than panicking.
	b3, e3 := cacheOnlyPipeline.StreamBatches(ctx, 800, 900)
	for range b3 {
	}
	if err := <-e3; err == nil {
		t.Fatal("expected error on cache miss with nil fetcher, got nil")
	}
}

func TestIngestionPipeline_CachedUnaligned(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cache, err := NewManagedTileCache(t.TempDir(), 256)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// Pre-populate cache with 3 bundles (0..255, 256..511, 512..767)
	for bIdx := uint64(0); bIdx < 3; bIdx++ {
		leaves := make([][]byte, 256)
		for j := 0; j < 256; j++ {
			leaves[j] = []byte(fmt.Sprintf("entry_leaf_%d", bIdx*256+uint64(j)))
		}
		if err := cache.PutBundle(&LeafBundle{
			BundleIdx:    bIdx,
			StartLeafIdx: bIdx * 256,
			Leaves:       leaves,
		}); err != nil {
			t.Fatalf("PutBundle failed: %v", err)
		}
	}

	pipeline := NewPipeline(nil, cache, wasmhosttest.Host(), 4)

	// Stream unaligned from cache: [100, 600)
	const fromIdx = 100
	const targetSize = 600
	batchChan, errChan := pipeline.StreamBatches(ctx, fromIdx, targetSize)

	var receivedCount uint64
	var expectedNextStart uint64 = fromIdx

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	wantCount := uint64(targetSize - fromIdx)
	if receivedCount != wantCount {
		t.Fatalf("received %d leaves, want %d", receivedCount, wantCount)
	}
}

func TestIngestionPipeline_PartialCacheExpansion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cache, err := NewManagedTileCache(t.TempDir(), 256)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// 1. Initial state: 3 leaves in bundle 0
	leaves := [][]byte{[]byte("leaf0"), []byte("leaf1"), []byte("leaf2")}
	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	pipeline := NewPipeline(fetcher, cache, wasmhosttest.Host(), 2)

	// Stream [0, 3) -> bundle 0 cached with 3 leaves
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 3)
	for range batchChan {
	}
	if err := <-errChan; err != nil {
		t.Fatalf("StreamBatches [0, 3) failed: %v", err)
	}

	// 2. Log expands dynamically: leaf 3 is added (total 4 leaves)
	fetcher.leaves = append(fetcher.leaves, []byte("leaf3"))

	// Stream [3, 4) -> must fetch updated bundle rather than getting stuck on partial cache
	batchChan2, errChan2 := pipeline.StreamBatches(ctx, 3, 4)
	var count uint64
	for batch := range batchChan2 {
		if batch.StartLeafIdx != 3 || batch.EndLeafIdx != 4 {
			t.Fatalf("unexpected batch range: [%d, %d)", batch.StartLeafIdx, batch.EndLeafIdx)
		}
		count += uint64(batch.Count)
	}
	if err := <-errChan2; err != nil {
		t.Fatalf("StreamBatches [3, 4) failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("received %d leaves, want 1", count)
	}
}

func TestTiledFetcher_FetchTiles_TreeSizeClamping(t *testing.T) {
	ctx := context.Background()

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, i uint64, p uint8) ([]byte, error) {
			count := int(p)
			if count == 0 {
				count = int(layout.EntryBundleWidth)
			}
			var buf []byte
			for j := 0; j < count; j++ {
				entry := []byte(fmt.Sprintf("entry_for_bundle_%d_%d", i, j))
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(entry)))
				buf = append(buf, entry...)
			}
			return buf, nil
		},
	}

	// treeSize = 300 (covers bundle 0 and bundle 1)
	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 300,
	}

	// 1. Requesting beyond treeSize should return nil
	bundles, err := fetcher.FetchTiles(ctx, 300, 100)
	if err != nil {
		t.Fatalf("FetchTiles beyond treeSize failed: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("got %d bundles, want 0", len(bundles))
	}

	// 2. Requesting overlapping range [100, 600) should clamp to treeSize (300) -> bundles 0 and 1
	bundles, err = fetcher.FetchTiles(ctx, 100, 500)
	if err != nil {
		t.Fatalf("FetchTiles overlapping failed: %v", err)
	}
	if len(bundles) != 2 {
		t.Fatalf("got %d bundles, want 2 (clamped to treeSize)", len(bundles))
	}
	if bundles[0].BundleIdx != 0 || bundles[1].BundleIdx != 1 {
		t.Fatalf("unexpected bundles: %v", bundles)
	}
}

type gapTileFetcher struct {
	bundles []*LeafBundle
}

func (f *gapTileFetcher) Checkpoint(_ context.Context) (*Checkpoint, error) {
	return &Checkpoint{Size: 300}, nil
}
func (f *gapTileFetcher) FetchTiles(_ context.Context, _, _ uint64) ([]*LeafBundle, error) {
	return f.bundles, nil
}

func TestIngestionPipeline_ResequencerSilentDataDrop_GapError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Provide bundle 0 [0..100) and bundle 2 [200..300), skipping bundle 1 [100..200)
	b0 := &LeafBundle{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Leaves:       make([][]byte, 100),
	}
	for i := range b0.Leaves {
		b0.Leaves[i] = []byte(fmt.Sprintf("leaf_%d", i))
	}
	b2 := &LeafBundle{
		BundleIdx:    2,
		StartLeafIdx: 200,
		Leaves:       make([][]byte, 100),
	}
	for i := range b2.Leaves {
		b2.Leaves[i] = []byte(fmt.Sprintf("leaf_%d", 200+i))
	}

	fetcher := &gapTileFetcher{bundles: []*LeafBundle{b0, b2}}
	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 2)

	// Stream [0, 300)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 300)

	for range batchChan {
		// drain available batches
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error on gap/unpopped items in resequencer, got nil")
	}
}

func TestIngestionPipeline_ResequencerSilentDataDrop_MissingStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Only provide bundle 1 [100..200), missing [0..100)
	b1 := &LeafBundle{
		BundleIdx:    1,
		StartLeafIdx: 100,
		Leaves:       make([][]byte, 100),
	}
	for i := range b1.Leaves {
		b1.Leaves[i] = []byte(fmt.Sprintf("leaf_%d", 100+i))
	}

	fetcher := &gapTileFetcher{bundles: []*LeafBundle{b1}}
	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 2)

	// Stream [0, 200)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 200)

	for range batchChan {
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error on missing start batch in resequencer, got nil")
	}
}

func TestTiledFetcher_LeafHashAuthentication_CorruptedLeaf(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalLeaf := []byte("original_valid_leaf_data")
	corruptedLeaf := []byte("tampered_malicious_leaf_data")

	var bundleBuf []byte
	bundleBuf = binary.BigEndian.AppendUint16(bundleBuf, uint16(len(corruptedLeaf)))
	bundleBuf = append(bundleBuf, corruptedLeaf...)

	validHash := tlog.RecordHash(originalLeaf)
	tileBuf := validHash[:]

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, _ uint64, _ uint8) ([]byte, error) {
			return bundleBuf, nil
		},
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return tileBuf, nil
		},
	}

	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 1,
	}

	// FetchTiles must fail authentication directly and when invoked via IngestionPipeline.
	if _, err := fetcher.FetchTiles(ctx, 0, 1); err == nil {
		t.Fatal("FetchTiles expected hash mismatch error for corrupted leaf, got nil")
	}

	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 2)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 1)
	for range batchChan {
	}
	if err := <-errChan; err == nil {
		t.Fatal("pipeline expected error due to corrupted leaf hash mismatch, got nil")
	}
}

func TestIngestionPipeline_PropagateMapperErrorDirectly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const totalLeaves = 50
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}
	leaves[0] = []byte("\x01bad")

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 2)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error from pipeline, got nil")
	}
	if !errors.Is(err, wasmhost.ErrMalformedOutput) {
		t.Fatalf("expected error wrapping wasmhost.ErrMalformedOutput, got: %v", err)
	}
}

func TestIngestionPipeline_WorkerErrorUnblocksWithoutMasking(t *testing.T) {
	wasmHost := wasmhosttest.Host()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const totalLeaves = 200
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}
	leaves[0] = []byte("\x00trap")

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log", bundleSize: 1}
	pipeline := NewPipeline(fetcher, nil, wasmHost, 16)
	pipeline.bundleSize = 1

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error from pipeline, got nil")
	}
	if !errors.Is(err, wasmhost.ErrWasmHalt) {
		t.Fatalf("expected error matching wasmhost.ErrWasmHalt, got: %v", err)
	}
}

func TestIngestionPipeline_BundleTimeout_HaltsPipeline(t *testing.T) {
	ctx := context.Background()

	const totalLeaves = 10
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte("\x02loop"))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log", bundleSize: 5}
	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 2)
	pipeline.bundleSize = 5
	pipeline.bundleTimeout = 50 * time.Millisecond

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected timeout error from pipeline, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected error wrapping context.DeadlineExceeded, got: %v", err)
	}
}

func TestIngestionPipeline_ConcurrentWorkerFailures_NoPanic(t *testing.T) {
	const totalLeaves = 200
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte("\x00trap"))
	}

	for iter := 0; iter < 10; iter++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log", bundleSize: 1}
		pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 16)
		pipeline.bundleSize = 1

		batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)
		for range batchChan {
		}

		err := <-errChan
		cancel()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, wasmhost.ErrWasmHalt) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestIngestionPipeline_ChannelCapacityConfiguration(t *testing.T) {
	pipeline := NewPipeline(nil, nil, nil, 1)

	wantDefault := DefaultPipelineChannelCapacity()
	if pipeline.chanCap != wantDefault {
		t.Fatalf("NewPipeline chanCap = %d, want default %d", pipeline.chanCap, wantDefault)
	}

	pipeline.SetChannelCapacity(8)
	if pipeline.chanCap != 8 {
		t.Fatalf("chanCap after SetChannelCapacity(8) = %d, want 8", pipeline.chanCap)
	}

	pipeline.SetChannelCapacity(0)
	if pipeline.chanCap != 1 {
		t.Fatalf("chanCap after SetChannelCapacity(0) = %d, want minimum 1", pipeline.chanCap)
	}
}

func BenchmarkVerifyBundleWithTile(b *testing.B) {
	const numLeaves = 256
	bundle := api.EntryBundle{
		Entries: make([][]byte, numLeaves),
	}
	tileData := make([]byte, numLeaves*32)
	for i := range bundle.Entries {
		leaf := bytes.Repeat([]byte{byte(i)}, 1024)
		bundle.Entries[i] = leaf
		h := tlog.RecordHash(leaf)
		copy(tileData[i*32:(i+1)*32], h[:])
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := verifyBundleWithTile(&bundle, tileData, 0); err != nil {
			b.Fatal(err)
		}
	}
}

type checkpointMockReader struct {
	mockTiledReader
	rawCP []byte
}

func (r *checkpointMockReader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return r.rawCP, nil
}

func TestTiledFetcher_Checkpoint_RequiresVerifierByDefault(t *testing.T) {
	ctx := context.Background()
	rootHash := sha256.Sum256([]byte("tree_root"))
	rawCP := []byte(fmt.Sprintf("example.com/log\n10\n%s\n", base64.StdEncoding.EncodeToString(rootHash[:])))

	reader := &checkpointMockReader{rawCP: rawCP}
	fetcher := NewTiledFetcherWithReader(reader, nil, "example.com/log")

	if _, err := fetcher.Checkpoint(ctx); err == nil {
		t.Fatal("expected Checkpoint() with nil verifier to fail by default, got nil")
	}

	fetcher.SetAllowUnverifiedCheckpoints(true)
	cp, err := fetcher.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint() failed after SetAllowUnverifiedCheckpoints(true): %v", err)
	}
	if cp.Size != 10 || cp.Hash != rootHash {
		t.Fatalf("unexpected checkpoint: %+v", cp)
	}
}

func TestTiledFetcher_ForgedEntryAndLevel0TileRejectedAgainstCheckpointRoot(t *testing.T) {
	ctx := context.Background()

	// Attacker serves a forged leaf and a matching forged Level-0 hash tile,
	// so verifyBundleWithTile passes, but the Level-0 tile does not match the signed checkpoint root.
	forgedLeaf := []byte("forged_leaf_payload")
	var bundleBuf []byte
	bundleBuf = binary.BigEndian.AppendUint16(bundleBuf, uint16(len(forgedLeaf)))
	bundleBuf = append(bundleBuf, forgedLeaf...)

	forgedLeafHash := tlog.RecordHash(forgedLeaf)
	forgedTileBuf := forgedLeafHash[:]

	legitimateRoot := sha256.Sum256([]byte("legitimate_checkpoint_root"))

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, _ uint64, _ uint8) ([]byte, error) {
			return bundleBuf, nil
		},
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return forgedTileBuf, nil
		},
	}

	fetcher := NewTiledFetcherWithReader(reader, nil, "test-origin")
	fetcher.SetTreeState(1, legitimateRoot)

	if _, err := fetcher.FetchTiles(ctx, 0, 1); err == nil {
		t.Fatal("FetchTiles expected root verification failure for forged (entryBundle, level0Tile), got nil")
	}
}

func TestParseAndVerifyStaticCTBundle_TruncatedTreeTileRejected(t *testing.T) {
	// Construct a valid 1-entry Static-CT data tile (x509_entry with leaf_index=0 extension):
	// timestamp (8B) | entry_type=0 (2B) | cert_len=3 (3B) | cert (3B) | ext_len=8 (2B) | ext (8B) | fp_len=0 (2B)
	dataTile := []byte{
		0x00, 0x00, 0x01, 0x8b, 0xcf, 0xee, 0x58, 0x00, // timestamp
		0x00, 0x00, // entry_type = 0 (x509_entry)
		0x00, 0x00, 0x03, 0x30, 0x01, 0x00, // 3-byte dummy cert
		0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // leaf_index = 0 extension
		0x00, 0x00, // 0 chain fingerprints
	}
	parsedLeaf, rest, err := sunlight.ReadTileLeaf(dataTile)
	if err != nil || len(rest) != 0 {
		t.Fatalf("sunlight.ReadTileLeaf failed: %v (rest=%d)", err, len(rest))
	}
	mtl := parsedLeaf.MerkleTreeLeaf()
	validLeafHash := sha256.Sum256(append([]byte{0x00}, mtl...))

	// 1. Valid 32-byte treeTile succeeds
	lb, err := parseAndVerifyStaticCTBundle(dataTile, validLeafHash[:], 0, 0)
	if err != nil {
		t.Fatalf("expected valid static-ct bundle to succeed, got: %v", err)
	}
	if len(lb.Leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(lb.Leaves))
	}

	// 2. Empty treeTile must be rejected (was previously bypassing verification)
	if _, err := parseAndVerifyStaticCTBundle(dataTile, nil, 0, 0); err == nil {
		t.Fatal("expected error for empty static-ct treeTile, got nil")
	}

	// 3. Truncated 16-byte treeTile must be rejected
	if _, err := parseAndVerifyStaticCTBundle(dataTile, validLeafHash[:16], 0, 0); err == nil {
		t.Fatal("expected error for truncated static-ct treeTile, got nil")
	}

	// 4. Oversized 64-byte treeTile for 1-leaf bundle must be rejected
	oversized := append(validLeafHash[:], validLeafHash[:]...)
	if _, err := parseAndVerifyStaticCTBundle(dataTile, oversized, 0, 0); err == nil {
		t.Fatal("expected error for oversized static-ct treeTile, got nil")
	}

	// 5. Partial-tile fallback: 2-leaf dataTile with p=1 and 32-byte treeTile truncates to 1 verified leaf
	twoLeafDataTile := append(bytes.Clone(dataTile), dataTile...)
	lbFallback, err := parseAndVerifyStaticCTBundle(twoLeafDataTile, validLeafHash[:], 0, 1)
	if err != nil {
		t.Fatalf("expected static-ct partial fallback with p=1 to succeed, got: %v", err)
	}
	if len(lbFallback.Leaves) != 1 {
		t.Fatalf("expected 1 leaf after partial fallback truncation, got %d", len(lbFallback.Leaves))
	}
}

func TestManagedTileCache_PruneBefore_RetainsPartialBundleInMemory(t *testing.T) {
	cache, err := NewManagedTileCache("", 16)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// Bundle 0 has only 4 leaves [0..4), while bundleSize is 16 [0..16)
	partial := &LeafBundle{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Leaves:       [][]byte{[]byte("l0"), []byte("l1"), []byte("l2"), []byte("l3")},
	}
	if err := cache.PutBundle(partial); err != nil {
		t.Fatalf("PutBundle failed: %v", err)
	}

	// Pruning at watermark 4 must NOT evict partial bundle 0 because leaves [4..16) still belong to bundle 0
	pruned, err := cache.PruneBefore(4)
	if err != nil {
		t.Fatalf("PruneBefore(4) failed: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("PruneBefore(4) pruned %d bundles, want 0 (partial bundle must be retained until full)", pruned)
	}
	if _, err := cache.GetBundle(0); err != nil {
		t.Fatalf("expected partial bundle 0 to remain in cache at watermark 4, got: %v", err)
	}

	// Pruning at watermark 16 (full bundle boundary) evicts bundle 0
	pruned, err = cache.PruneBefore(16)
	if err != nil {
		t.Fatalf("PruneBefore(16) failed: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("PruneBefore(16) pruned %d bundles, want 1", pruned)
	}
}

func mustGenerateNoteKeyPair(t *testing.T, name string) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(nil, name)
	if err != nil {
		t.Fatalf("note.GenerateKey(%q) failed: %v", name, err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("note.NewSigner(%q) failed: %v", name, err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("note.NewVerifier(%q) failed: %v", name, err)
	}
	return signer, verifier
}

func writeTiledLogFixture(t *testing.T, rootDir, origin string, leaves [][]byte, signers ...note.Signer) (tlog.Hash, func(n int64) tlog.Hash) {
	t.Helper()
	if err := os.RemoveAll(rootDir); err != nil {
		t.Fatalf("RemoveAll(%s) failed: %v", rootDir, err)
	}

	var hashes []tlog.Hash
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			if idx < 0 || int(idx) >= len(hashes) {
				return nil, fmt.Errorf("hash index %d out of range (len=%d)", idx, len(hashes))
			}
			out[i] = hashes[idx]
		}
		return out, nil
	})
	for idx, leaf := range leaves {
		sh, err := tlog.StoredHashes(int64(idx), leaf, hr)
		if err != nil {
			t.Fatalf("tlog.StoredHashes(%d) failed: %v", idx, err)
		}
		hashes = append(hashes, sh...)
	}

	treeSize := int64(len(leaves))
	rootAt := func(n int64) tlog.Hash {
		h, err := tlog.TreeHash(n, hr)
		if err != nil {
			t.Fatalf("tlog.TreeHash(%d) failed: %v", n, err)
		}
		return h
	}
	rootHash := rootAt(treeSize)

	for _, tile := range tlog.NewTiles(layout.TileHeight, 0, treeSize) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			t.Fatalf("tlog.ReadTileData(%+v) failed: %v", tile, err)
		}
		p := uint8(0)
		if tile.W < (1 << layout.TileHeight) {
			p = uint8(tile.W)
		}
		dst := filepath.Join(rootDir, layout.TilePath(uint64(tile.L), uint64(tile.N), p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) failed: %v", dst, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile(%s) failed: %v", dst, err)
		}
	}

	const bundleW = int(layout.EntryBundleWidth)
	for start := 0; start < len(leaves); start += bundleW {
		end := min(start+bundleW, len(leaves))
		bIdx := uint64(start / bundleW)
		count := end - start
		p := uint8(0)
		if count < bundleW {
			p = uint8(count)
		}
		var buf []byte
		for _, leaf := range leaves[start:end] {
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(leaf)))
			buf = append(buf, leaf...)
		}
		dst := filepath.Join(rootDir, layout.EntriesPath(bIdx, p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) failed: %v", dst, err)
		}
		if err := os.WriteFile(dst, buf, 0o644); err != nil {
			t.Fatalf("WriteFile(%s) failed: %v", dst, err)
		}
	}

	cpBody := (&log.Checkpoint{
		Origin: origin,
		Size:   uint64(treeSize),
		Hash:   rootHash[:],
	}).Marshal()
	rawCP := cpBody
	if len(signers) > 0 {
		signed, err := note.Sign(&note.Note{Text: string(cpBody)}, signers...)
		if err != nil {
			t.Fatalf("note.Sign failed: %v", err)
		}
		rawCP = signed
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) failed: %v", rootDir, err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, layout.CheckpointPath), rawCP, 0o644); err != nil {
		t.Fatalf("WriteFile checkpoint failed: %v", err)
	}

	return rootHash, rootAt
}

func TestTiledFetcher_SetPolicy(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/inputlog"

	logSigner, logVerifier := mustGenerateNoteKeyPair(t, origin)
	wit1Signer, wit1Verifier := mustGenerateNoteKeyPair(t, "witness1.example.com")
	wit2Signer, wit2Verifier := mustGenerateNoteKeyPair(t, "witness2.example.com")
	_, wit3Verifier := mustGenerateNoteKeyPair(t, "witness3.example.com")
	untrustedSigner, _ := mustGenerateNoteKeyPair(t, "untrusted.example.com")

	rootHash := sha256.Sum256([]byte("witness_policy_tree_root"))
	cpBody := string((&log.Checkpoint{
		Origin: origin,
		Size:   42,
		Hash:   rootHash[:],
	}).Marshal())

	signNote := func(t *testing.T, signers ...note.Signer) []byte {
		t.Helper()
		raw, err := note.Sign(&note.Note{Text: cpBody}, signers...)
		if err != nil {
			t.Fatalf("note.Sign failed: %v", err)
		}
		return raw
	}

	mustSetPolicy := func(t *testing.T, f *TiledFetcher, witnesses []note.Verifier, threshold int) {
		t.Helper()
		pol, err := wire.BuildPolicy(origin, logVerifier, witnesses, threshold)
		if err != nil {
			t.Fatalf("wire.BuildPolicy failed: %v", err)
		}
		f.SetPolicy(pol)
	}

	t.Run("threshold_0_single_verifier_and_default_origin", func(t *testing.T) {
		raw := signNote(t, logSigner)
		reader := &checkpointMockReader{rawCP: raw}
		// Empty origin falls back to verifier.Name()
		fetcher := NewTiledFetcherWithReader(reader, logVerifier, "")
		cp, err := fetcher.Checkpoint(ctx)
		if err != nil {
			t.Fatalf("Checkpoint() failed with threshold 0: %v", err)
		}
		if cp.Size != 42 || cp.Hash != rootHash {
			t.Fatalf("unexpected checkpoint: %+v", cp)
		}

		// Explicitly setting threshold 0 with witnesses keeps single-verifier behavior
		mustSetPolicy(t, fetcher, []note.Verifier{wit1Verifier, wit2Verifier}, 0)
		if _, err := fetcher.Checkpoint(ctx); err != nil {
			t.Fatalf("Checkpoint() failed with SetPolicy(..., 0): %v", err)
		}
	})

	t.Run("valid_witness_quorum_passes", func(t *testing.T) {
		raw := signNote(t, logSigner, wit1Signer, wit2Signer)
		reader := &checkpointMockReader{rawCP: raw}
		fetcher := NewTiledFetcherWithReader(reader, nil, origin)
		mustSetPolicy(t, fetcher, []note.Verifier{wit1Verifier, wit2Verifier, wit3Verifier}, 2)

		cp, err := fetcher.Checkpoint(ctx)
		if err != nil {
			t.Fatalf("Checkpoint() failed with valid 2-of-3 witness quorum: %v", err)
		}
		if cp.Size != 42 || cp.Hash != rootHash {
			t.Fatalf("unexpected checkpoint: %+v", cp)
		}
	})

	t.Run("missing_and_insufficient_cosignatures_fail", func(t *testing.T) {
		// Only log signed, threshold = 1
		rawOnlyLog := signNote(t, logSigner)
		reader := &checkpointMockReader{rawCP: rawOnlyLog}
		fetcher := NewTiledFetcherWithReader(reader, logVerifier, origin)
		mustSetPolicy(t, fetcher, []note.Verifier{wit1Verifier, wit2Verifier}, 1)

		before := testutil.ToFloat64(metrics.InputFetchErrorsTotal)
		if _, err := fetcher.Checkpoint(ctx); err == nil {
			t.Fatal("expected error when witness cosignature is missing, got nil")
		}
		if after := testutil.ToFloat64(metrics.InputFetchErrorsTotal); after <= before {
			t.Fatalf("expected InputFetchErrorsTotal to increment: before=%v, after=%v", before, after)
		}

		// Log + 1 trusted witness + 1 untrusted witness signed, threshold = 2
		rawInsufficient := signNote(t, logSigner, wit1Signer, untrustedSigner)
		reader.rawCP = rawInsufficient
		mustSetPolicy(t, fetcher, []note.Verifier{wit1Verifier, wit2Verifier, wit3Verifier}, 2)

		before = testutil.ToFloat64(metrics.InputFetchErrorsTotal)
		if _, err := fetcher.Checkpoint(ctx); err == nil {
			t.Fatal("expected error when witness cosignatures are insufficient (1 < 2), got nil")
		}
		if after := testutil.ToFloat64(metrics.InputFetchErrorsTotal); after <= before {
			t.Fatalf("expected InputFetchErrorsTotal to increment: before=%v, after=%v", before, after)
		}
	})

	t.Run("primary_key_colliding_with_witness_rejected", func(t *testing.T) {
		// 1. Primary verifier configured as sole witness with threshold 1 fails at BuildPolicy
		if _, err := wire.BuildPolicy(origin, logVerifier, []note.Verifier{logVerifier}, 1); err == nil {
			t.Fatal("expected BuildPolicy error when primary verifier collides with sole witness, got nil")
		}

		// 2. Primary verifier + real witness configured with threshold 1 fails at BuildPolicy
		if _, err := wire.BuildPolicy(origin, logVerifier, []note.Verifier{logVerifier, wit1Verifier}, 1); err == nil {
			t.Fatal("expected BuildPolicy error when primary verifier collides with witness entry, got nil")
		}

		// 3. Primary verifier + real witness configured with threshold 2 fails at BuildPolicy
		if _, err := wire.BuildPolicy(origin, logVerifier, []note.Verifier{logVerifier, wit1Verifier}, 2); err == nil {
			t.Fatal("expected BuildPolicy error when colliding primary verifier leaves fewer than threshold distinct witnesses, got nil")
		}

		// 4. Duplicate witness configured with threshold 2 fails at BuildPolicy
		if _, err := wire.BuildPolicy(origin, logVerifier, []note.Verifier{wit1Verifier, wit1Verifier}, 2); err == nil {
			t.Fatal("expected BuildPolicy error when duplicate witness entries do not meet distinct threshold, got nil")
		}
	})
}

func TestTiledFetcher_ConsistencyProof(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/tiledlog"
	logSigner, logVerifier := mustGenerateNoteKeyPair(t, origin)

	const totalLeaves = 600 // Spans 3 Level-0 bundles (256, 256, 88) and Level-1 tile
	leaves := make([][]byte, totalLeaves)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("tiled_fixture_leaf_%d", i))
	}

	dir := t.TempDir()
	_, rootAt := writeTiledLogFixture(t, dir, origin, leaves, logSigner)

	tf, err := NewTiledFetcher(&url.URL{Scheme: "file", Path: dir}, logVerifier, origin, nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}

	// Edge cases: smaller == 0, smaller == larger, smaller > larger
	if p, err := tf.ConsistencyProof(ctx, 0, 0); err != nil || p != nil {
		t.Fatalf("ConsistencyProof(0, 0) = (%v, %v), want (nil, nil)", p, err)
	}
	if p, err := tf.ConsistencyProof(ctx, 0, 300); err != nil || p != nil {
		t.Fatalf("ConsistencyProof(0, 300) = (%v, %v), want (nil, nil)", p, err)
	}
	if p, err := tf.ConsistencyProof(ctx, 300, 300); err != nil || p != nil {
		t.Fatalf("ConsistencyProof(300, 300) = (%v, %v), want (nil, nil)", p, err)
	}
	if _, err := tf.ConsistencyProof(ctx, 400, 300); err == nil {
		t.Fatal("ConsistencyProof(400, 300) expected error for smaller > larger, got nil")
	}

	pairs := [][2]uint64{
		{1, 100},
		{100, 256},
		{100, 350},
		{256, 600},
		{350, 600},
	}
	for _, pair := range pairs {
		smaller, larger := pair[0], pair[1]
		cProof, err := tf.ConsistencyProof(ctx, smaller, larger)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d, %d) failed: %v", smaller, larger, err)
		}
		r1 := rootAt(int64(smaller))
		r2 := rootAt(int64(larger))
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, smaller, larger, cProof, r1[:], r2[:]); err != nil {
			t.Fatalf("VerifyConsistency(%d, %d) failed: %v", smaller, larger, err)
		}
		if len(cProof) > 0 && len(cProof[0]) > 0 {
			tampered := make([][]byte, len(cProof))
			for i := range cProof {
				tampered[i] = bytes.Clone(cProof[i])
			}
			tampered[0][0] ^= 0xff
			if err := proof.VerifyConsistency(rfc6962.DefaultHasher, smaller, larger, tampered, r1[:], r2[:]); err == nil {
				t.Fatalf("VerifyConsistency(%d, %d) unexpectedly succeeded with tampered proof", smaller, larger)
			}
		}
	}
}

func TestFetchVerifiedEntryByIndex(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{[]byte("entry-0"), []byte("entry-1"), []byte("entry-2")}
	var entriesTile []byte
	for _, entry := range leaves {
		entriesTile = binary.BigEndian.AppendUint16(entriesTile, uint16(len(entry)))
		entriesTile = append(entriesTile, entry...)
	}

	dir := t.TempDir()
	rootHash, _ := writeTiledLogFixture(t, dir, "example.com/c2sp", leaves)
	level0Tile, err := os.ReadFile(filepath.Join(dir, layout.TilePath(0, 0, 3)))
	if err != nil {
		t.Fatalf("ReadFile(level0Tile) failed: %v", err)
	}

	sumDBTile := []byte("golang.org/x/mod v0.1.0 h1:aaa=\ngolang.org/x/mod v0.1.0/go.mod h1:mmm=\n\ngolang.org/x/net v0.2.0 h1:bbb=\n")

	staticCTDataTile := []byte{
		0x00, 0x00, 0x01, 0x8b, 0xcf, 0xee, 0x58, 0x00, // timestamp (first two bytes are 0x00, 0x00)
		0x00, 0x00, // entry_type = 0 (x509_entry)
		0x00, 0x00, 0x03, 0x30, 0x01, 0x00, // 3-byte dummy cert
		0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // leaf_index = 0 extension
		0x00, 0x00, // 0 chain fingerprints
	}
	parsedStaticCTLeaf, _, err := sunlight.ReadTileLeaf(staticCTDataTile)
	if err != nil {
		t.Fatalf("sunlight.ReadTileLeaf failed: %v", err)
	}
	staticCTLeafHash := rfc6962.DefaultHasher.HashLeaf(parsedStaticCTLeaf.MerkleTreeLeaf())
	var staticCTRoot [32]byte
	copy(staticCTRoot[:], staticCTLeafHash)

	mux := http.NewServeMux()
	// Partial tail bundle at idx 0..2 (treeSize=3)
	mux.HandleFunc("/c2sp/tile/entries/000.p/3", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(entriesTile)
	})
	mux.HandleFunc("/c2sp/tile/0/000.p/3", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(level0Tile)
	})
	// Fallback to full bundle and full tile when .p/3 is 404 or returns a short partial tile
	mux.HandleFunc("/fallback-full/tile/entries/000", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(entriesTile)
	})
	mux.HandleFunc("/fallback-full/tile/0/000.p/3", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(level0Tile[:32]) // short partial tile (1 hash instead of 3) must fall through to /tile/0/000
	})
	mux.HandleFunc("/fallback-full/tile/0/000", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(level0Tile)
	})
	// Fallback to tile/data/000
	mux.HandleFunc("/fallback-data/tile/data/000", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(entriesTile)
	})
	mux.HandleFunc("/fallback-data/tile/0/000", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(level0Tile)
	})
	// Static-CT TileLeaf via tile/data/000.p/1 (must prioritize sunlight.ReadTileLeaf over api.EntryBundle)
	mux.HandleFunc("/static-ct/tile/data/000.p/1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(staticCTDataTile)
	})
	mux.HandleFunc("/static-ct/tile/0/000.p/1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(staticCTLeafHash)
	})
	// SumDB style (matched via query/path containing sum.golang.org or tile/8/data)
	mux.HandleFunc("/sum.golang.org/tile/8/data/000.p/2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sumDBTile)
	})
	// Truncated bundle (claims 3 entries via treeSize=3, only contains 1 entry)
	mux.HandleFunc("/truncated/tile/entries/000.p/3", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(entriesTile[:2+len("entry-0")])
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, base := range []string{srv.URL + "/c2sp", srv.URL + "/fallback-full", srv.URL + "/fallback-data"} {
		for idx := uint64(0); idx < 3; idx++ {
			got, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), base, idx, 3, [32]byte(rootHash))
			if err != nil {
				t.Fatalf("FetchVerifiedEntryByIndex(%s, %d) failed: %v", base, idx, err)
			}
			want := fmt.Sprintf("entry-%d", idx)
			if string(got) != want {
				t.Fatalf("FetchVerifiedEntryByIndex(%s, %d) = %q, want %q", base, idx, got, want)
			}
		}
	}

	gotStaticCT, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), srv.URL+"/static-ct", 0, 1, staticCTRoot)
	if err != nil {
		t.Fatalf("FetchVerifiedEntryByIndex(static-ct, 0) failed: %v", err)
	}
	if !bytes.Equal(gotStaticCT, staticCTDataTile) {
		t.Fatalf("FetchVerifiedEntryByIndex(static-ct, 0) = %x, want %x", gotStaticCT, staticCTDataTile)
	}

	// Wrong treeRoot must fail Merkle inclusion verification
	wrongRoot := sha256.Sum256([]byte("wrong_root"))
	if _, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), srv.URL+"/c2sp", 0, 3, wrongRoot); err == nil {
		t.Fatal("expected FetchVerifiedEntryByIndex to fail with wrong treeRoot")
	}

	gotSumDB0, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), srv.URL+"/sum.golang.org", 0, 2, [32]byte{})
	if err != nil {
		t.Fatalf("FetchVerifiedEntryByIndex(sumdb, 0) failed: %v", err)
	}
	wantSumDB0 := "golang.org/x/mod v0.1.0 h1:aaa=\ngolang.org/x/mod v0.1.0/go.mod h1:mmm=\n"
	if string(gotSumDB0) != wantSumDB0 {
		t.Fatalf("FetchVerifiedEntryByIndex(sumdb, 0) = %q, want %q", gotSumDB0, wantSumDB0)
	}

	gotSumDB1, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), srv.URL+"/sum.golang.org", 1, 2, [32]byte{})
	if err != nil {
		t.Fatalf("FetchVerifiedEntryByIndex(sumdb, 1) failed: %v", err)
	}
	if string(gotSumDB1) != "golang.org/x/net v0.2.0 h1:bbb=\n" {
		t.Fatalf("FetchVerifiedEntryByIndex(sumdb, 1) = %q", gotSumDB1)
	}

	if _, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), srv.URL+"/truncated", 2, 3, [32]byte{}); err == nil {
		t.Fatal("expected error when bundle has fewer entries than requested offset")
	}

	if _, err := FetchVerifiedEntryByIndex(ctx, srv.Client(), srv.URL+"/c2sp", 3, 3, [32]byte(rootHash)); err == nil {
		t.Fatal("expected error for idx >= treeSize")
	}
}

func TestTiledFetcher_PartialTileFallbackTruncatesToTreeSize(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/partial-fallback"
	logSigner, logVerifier := mustGenerateNoteKeyPair(t, origin)

	// Write a full 256-leaf bundle (so tile/entries/000 and tile/0/000 exist without .p/),
	// but authenticate against an earlier checkpoint of size 3.
	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf_%03d", i))
	}
	dir := t.TempDir()
	_, rootAt := writeTiledLogFixture(t, dir, origin, leaves, logSigner)
	root3 := [32]byte(rootAt(3))

	// 1. File-backed TiledFetcher (pooledFileFetcher) falling back from .p/3 to full 256-entry bundle & tile
	fileFetcher, err := NewTiledFetcher(&url.URL{Scheme: "file", Path: dir}, logVerifier, origin, nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher(file) failed: %v", err)
	}
	fileFetcher.SetTreeState(3, root3)
	bundles, err := fileFetcher.FetchTiles(ctx, 0, 3)
	if err != nil {
		t.Fatalf("fileFetcher.FetchTiles(0, 3) failed on full-tile fallback: %v", err)
	}
	if len(bundles) != 1 || len(bundles[0].Leaves) != 3 {
		t.Fatalf("expected 1 bundle truncated to 3 authenticated leaves, got len(bundles)=%d, leaves=%d", len(bundles), len(bundles[0].Leaves))
	}

	// 2. HTTP-backed TiledFetcher (tclient.HTTPFetcher) falling back from .p/3 to full 256-entry bundle & tile
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	httpFetcher, err := NewTiledFetcher(srvURL, logVerifier, origin, srv.Client())
	if err != nil {
		t.Fatalf("NewTiledFetcher(http) failed: %v", err)
	}
	httpFetcher.SetTreeState(3, root3)
	httpBundles, err := httpFetcher.FetchTiles(ctx, 0, 3)
	if err != nil {
		t.Fatalf("httpFetcher.FetchTiles(0, 3) failed on full-tile fallback: %v", err)
	}
	if len(httpBundles) != 1 || len(httpBundles[0].Leaves) != 3 {
		t.Fatalf("expected 1 HTTP bundle truncated to 3 authenticated leaves, got len(bundles)=%d, leaves=%d", len(httpBundles), len(httpBundles[0].Leaves))
	}
}

func TestTiledFetcher_UpperTileCache_SingleflightAndFullTileReuse(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/upper-tile-cache"
	logSigner, logVerifier := mustGenerateNoteKeyPair(t, origin)

	const totalLeaves = 600 // 3 Level-0 bundles (256, 256, 88) + 1 Level-1 tile (p=2)
	leaves := make([][]byte, totalLeaves)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("upper_cache_leaf_%d", i))
	}
	dir := t.TempDir()
	_, rootAt := writeTiledLogFixture(t, dir, origin, leaves, logSigner)

	baseReader := newPooledFileFetcher(dir, globalBufferPool)
	var level1Reads atomic.Int32
	countingReader := &mockTiledReader{
		readEntryBundleFn: baseReader.ReadEntryBundle,
		readTileFn: func(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
			if l == 1 {
				level1Reads.Add(1)
				time.Sleep(15 * time.Millisecond) // Hold in-flight to exercise singleflight deduplication across workers
			}
			return baseReader.ReadTile(ctx, l, i, p)
		},
	}

	tf := NewTiledFetcherWithReader(countingReader, logVerifier, origin)
	tf.SetTreeState(totalLeaves, [32]byte(rootAt(totalLeaves)))

	// Fetching all 3 bundles concurrently must deduplicate the in-flight Level-1 tile read to exactly 1 call.
	bundles, err := tf.FetchTiles(ctx, 0, totalLeaves)
	if err != nil {
		t.Fatalf("FetchTiles failed: %v", err)
	}
	if len(bundles) != 3 {
		t.Fatalf("got %d bundles, want 3", len(bundles))
	}
	if got := level1Reads.Load(); got != 1 {
		t.Fatalf("expected exactly 1 Level-1 tile read across concurrent workers, got %d", got)
	}

	// Seed a full upper tile (p=0) in upperTiles and verify advancing SetTreeState retains p=0 while evicting p>0.
	tf.upperTileMu.Lock()
	tf.upperTiles[upperTileKey{level: 1, index: 99, p: 0}] = []byte("sealed_full_upper_tile")
	tf.upperTileMu.Unlock()

	_, _ = tf.readCachedTile(ctx, totalLeaves+10, sha256.Sum256([]byte("next_root")), 1, 99, 0)
	tf.upperTileMu.Lock()
	_, fullRetained := tf.upperTiles[upperTileKey{level: 1, index: 99, p: 0}]
	_, partialRetained := tf.upperTiles[upperTileKey{level: 1, index: 0, p: 2}]
	tf.upperTileMu.Unlock()
	if !fullRetained {
		t.Fatal("expected sealed full upper tile (p=0) to be retained across checkpoint advances")
	}
	if partialRetained {
		t.Fatal("expected partial upper tile (p>0) to be evicted when checkpoint advances")
	}
}

type countingTileCache struct {
	TileCache
	getCalls map[uint64]int
	mu       sync.Mutex
}

func (c *countingTileCache) GetBundle(bundleIdx uint64) (*LeafBundle, error) {
	c.mu.Lock()
	c.getCalls[bundleIdx]++
	c.mu.Unlock()
	return c.TileCache.GetBundle(bundleIdx)
}

func TestIngestionPipeline_PartialCacheMissDoesNotRefetchCachedBundles(t *testing.T) {
	ctx := context.Background()
	baseCache, err := NewManagedTileCache("", 4)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}
	cache := &countingTileCache{
		TileCache: baseCache,
		getCalls:  make(map[uint64]int),
	}

	// Pre-populate bundle 1 (leaves 4..7) in cache, leaving bundle 0 (leaves 0..3) uncached.
	if err := cache.PutBundle(&LeafBundle{
		BundleIdx:    1,
		StartLeafIdx: 4,
		Leaves:       [][]byte{[]byte("l4"), []byte("l5"), []byte("l6"), []byte("l7")},
	}); err != nil {
		t.Fatalf("PutBundle failed: %v", err)
	}

	var fetchedBundle1 atomic.Bool
	fetcher := &LeafAdapter{
		BundleSize: 4,
		LeafFn: func(_ context.Context, idx uint64) ([]byte, error) {
			if idx >= 4 {
				fetchedBundle1.Store(true)
			}
			return []byte(fmt.Sprintf("l%d", idx)), nil
		},
	}

	pipeline := NewPipeline(fetcher, cache, wasmhosttest.Host(), 2)
	pipeline.bundleSize = 4
	pipeline.SetFetchWorkers(1)
	pipeline.SetFetchBatchBundles(2)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 8)
	var total uint64
	for b := range batchChan {
		total += uint64(b.Count)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("StreamBatches failed: %v", err)
	}
	if total != 8 {
		t.Fatalf("got %d leaves, want 8", total)
	}
	if fetchedBundle1.Load() {
		t.Fatal("expected cached bundle 1 not to be re-fetched on bundle 0 cache miss")
	}
	cache.mu.Lock()
	bundle1Gets := cache.getCalls[1]
	cache.mu.Unlock()
	if bundle1Gets != 1 {
		t.Fatalf("expected cached bundle 1 to be read from cache only once (during probe), got %d GetBundle(1) calls", bundle1Gets)
	}
}
