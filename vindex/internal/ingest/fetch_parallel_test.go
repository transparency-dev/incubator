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
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/tessera/api/layout"
)

// delayedTileFetcher simulates variable network/disk latency per bundle
// to force out-of-order bundle arrivals into the ingestion pipeline.
type delayedTileFetcher struct {
	leaves         [][]byte
	bundleSize     uint64
	bundleDelays   map[uint64]time.Duration
	defaultDelay   time.Duration
	fetchCallCount atomic.Uint64
}

func (f *delayedTileFetcher) Checkpoint(_ context.Context) (*Checkpoint, error) {
	root := sha256.Sum256([]byte(fmt.Sprintf("%d", len(f.leaves))))
	return &Checkpoint{
		Origin: "delayed-fetcher",
		Size:   uint64(len(f.leaves)),
		Hash:   root,
	}, nil
}

func (f *delayedTileFetcher) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	if idx >= uint64(len(f.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (total %d)", idx, len(f.leaves))
	}
	return f.leaves[idx], nil
}

func (f *delayedTileFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	f.fetchCallCount.Add(1)
	bsz := f.bundleSize
	if bsz == 0 {
		bsz = uint64(layout.EntryBundleWidth)
	}

	startB := startLeafIdx / bsz
	endB := (startLeafIdx + count + bsz - 1) / bsz

	var maxDelay time.Duration
	for b := startB; b < endB; b++ {
		d := f.defaultDelay
		if bd, ok := f.bundleDelays[b]; ok {
			d = bd
		}
		if d > maxDelay {
			maxDelay = d
		}
	}

	if maxDelay > 0 {
		select {
		case <-time.After(maxDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	adapter := &LeafAdapter{
		LeafFn:     f.Leaf,
		BundleSize: bsz,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

// TestIngestionPipeline_ParallelFetch_MonotonicResequencing verifies that when multiple
// fetch workers retrieve bundles out-of-order, the Resequencer restores strict monotonic order
// and guarantees zero duplicate and zero omitted leaves.
func TestIngestionPipeline_ParallelFetch_MonotonicResequencing(t *testing.T) {
	const totalLeaves = 2048
	const bsz = 256
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("test_leaf_%06d", i)))
	}

	// Reverse delays: bundle 0 has longest delay, so higher bundles finish first.
	delays := map[uint64]time.Duration{
		0: 40 * time.Millisecond,
		1: 30 * time.Millisecond,
		2: 20 * time.Millisecond,
		3: 10 * time.Millisecond,
		4: 5 * time.Millisecond,
		5: 2 * time.Millisecond,
		6: 1 * time.Millisecond,
		7: 0,
	}

	fetcher := &delayedTileFetcher{
		leaves:       leaves,
		bundleSize:   bsz,
		bundleDelays: delays,
	}

	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 4)
	pipeline.SetFetchWorkers(4)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	var receivedLeaves int
	var expectedStart uint64 = 0

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedStart {
			t.Fatalf("Out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedStart)
		}
		if batch.EndLeafIdx <= batch.StartLeafIdx {
			t.Fatalf("Invalid batch leaf range: [%d, %d)", batch.StartLeafIdx, batch.EndLeafIdx)
		}
		expectedStart = batch.EndLeafIdx
		receivedLeaves += int(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("StreamBatches failed: %v", err)
	}

	if receivedLeaves != totalLeaves {
		t.Fatalf("Total leaves mismatch: got %d, want %d", receivedLeaves, totalLeaves)
	}
	if expectedStart != totalLeaves {
		t.Fatalf("Final leaf index mismatch: got %d, want %d", expectedStart, totalLeaves)
	}
}

// TestIngestionPipeline_ParallelFetch_BatchBundles verifies that setting FetchBatchBundles
// reduces FetchTiles invocations by batching bundle retrieval while preserving monotonic ordering.
func TestIngestionPipeline_ParallelFetch_BatchBundles(t *testing.T) {
	const numBundles = 40
	const bsz = 256
	const totalLeaves = numBundles * bsz
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("batch_test_leaf_%06d", i)))
	}

	fetcher := &delayedTileFetcher{
		leaves:       leaves,
		bundleSize:   bsz,
		defaultDelay: 100 * time.Microsecond,
	}

	pipeline := NewPipeline(fetcher, nil, wasmhosttest.Host(), 4)
	pipeline.SetFetchWorkers(4)
	const batchBundles = 10
	pipeline.SetFetchBatchBundles(batchBundles)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	var receivedLeaves int
	var expectedStart uint64 = 0

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedStart {
			t.Fatalf("Out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedStart)
		}
		expectedStart = batch.EndLeafIdx
		receivedLeaves += int(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("StreamBatches failed: %v", err)
	}

	if receivedLeaves != totalLeaves {
		t.Fatalf("Total leaves mismatch: got %d, want %d", receivedLeaves, totalLeaves)
	}

	calls := fetcher.fetchCallCount.Load()
	// 40 bundles with batch size 10 across 4 workers should yield 4 calls (or at most 5 if boundary splits).
	if calls > 6 {
		t.Fatalf("Expected ~4-5 FetchTiles calls with batchBundles=%d, got %d calls", batchBundles, calls)
	}
}

// BenchmarkIngestionPipeline_FetchWorkers benchmarks end-to-end pipeline throughput
// comparing single-worker sequential batching (baseline) against parallel streaming fetchers (2, 4, 8 workers)
// under realistic simulated I/O latency and disk tile caching.
func BenchmarkIngestionPipeline_FetchWorkers(b *testing.B) {
	const numBundles = 50
	const bsz = 256
	const totalLeaves = numBundles * bsz

	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaf := bytes.Repeat([]byte{'a' + byte(i%26)}, 1024)
		leaves = append(leaves, leaf)
	}

	fetchWorkerCounts := []int{1, 2, 4, 8}

	for _, fw := range fetchWorkerCounts {
		name := fmt.Sprintf("FetchWorkers=%d", fw)
		if fw == 1 {
			name += "_SequentialBaseline"
		} else {
			name += "_ParallelStreaming"
		}

		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(totalLeaves * 1024))

			for b.Loop() {
				fetcher := &delayedTileFetcher{
					leaves:       leaves,
					bundleSize:   bsz,
					defaultDelay: 100 * time.Microsecond,
				}

				cacheDir := b.TempDir()
				cache, cErr := NewManagedTileCache(cacheDir, bsz)
				if cErr != nil {
					b.Fatalf("NewManagedTileCache failed: %v", cErr)
				}

				pipeline := NewPipeline(fetcher, cache, wasmhosttest.Host(), 16)
				pipeline.SetFetchWorkers(fw)

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

				var consumed int
				for batch := range batchChan {
					consumed += int(batch.Count)
				}
				cancel()

				if err := <-errChan; err != nil && !errors.Is(err, context.Canceled) {
					b.Fatalf("StreamBatches failed: %v", err)
				}
				if consumed != totalLeaves {
					b.Fatalf("Consumed leaves mismatch: got %d, want %d", consumed, totalLeaves)
				}
			}
		})
	}
}
