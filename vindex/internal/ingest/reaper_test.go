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
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockTileCache struct {
	mu           sync.Mutex
	tiles        map[uint64]string // tileEndIndex -> content
	lastPrunedTo uint64
}

func (m *mockTileCache) GetBundle(_ uint64) (*LeafBundle, error) {
	return nil, ErrBundleNotFound
}

func (m *mockTileCache) PutBundle(_ *LeafBundle) error {
	return nil
}

func (m *mockTileCache) PruneBefore(watermark uint64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastPrunedTo = watermark
	count := 0
	for endIdx := range m.tiles {
		if endIdx <= watermark {
			delete(m.tiles, endIdx)
			count++
		}
	}
	return count, nil
}

func TestTileReaper_SafeWatermarkAndPruning(t *testing.T) {
	ctx := context.Background()
	var currentWatermark atomic.Uint64
	var watermarkErr error
	cache := &mockTileCache{
		tiles: map[uint64]string{
			256:  "tile-0",
			512:  "tile-1",
			768:  "tile-2",
			1024: "tile-3",
		},
	}
	reaper := NewTileReaper(func(context.Context) (uint64, error) {
		return currentWatermark.Load(), watermarkErr
	}, cache)

	// 1. Initially watermark = 0 -> pruneOnce prunes 0
	watermark, pruned, err := reaper.pruneOnce(ctx)
	if err != nil {
		t.Fatalf("pruneOnce failed: %v", err)
	}
	if watermark != 0 || pruned != 0 {
		t.Fatalf("pruneOnce got watermark=%d, pruned=%d; want 0, 0", watermark, pruned)
	}

	// 2. Advance SafeWatermark to 512
	currentWatermark.Store(512)
	watermark, pruned, err = reaper.pruneOnce(ctx)
	if err != nil {
		t.Fatalf("pruneOnce failed: %v", err)
	}
	if watermark != 512 || pruned != 2 {
		t.Fatalf("pruneOnce got watermark=%d, pruned=%d; want 512, 2", watermark, pruned)
	}

	// Verify tiles 256 and 512 deleted, 768 and 1024 retained
	cache.mu.Lock()
	if _, ok := cache.tiles[256]; ok {
		t.Errorf("tile 256 should have been pruned")
	}
	if _, ok := cache.tiles[512]; ok {
		t.Errorf("tile 512 should have been pruned")
	}
	if _, ok := cache.tiles[768]; !ok {
		t.Errorf("tile 768 should be retained")
	}
	if _, ok := cache.tiles[1024]; !ok {
		t.Errorf("tile 1024 should be retained")
	}
	cache.mu.Unlock()

	// 3. Watermark error propagates without pruning
	watermarkErr = errors.New("watermark unavailable")
	if _, _, err := reaper.pruneOnce(ctx); err == nil {
		t.Fatal("expected pruneOnce to propagate watermark error")
	}
}

func TestTileReaper_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cache := &mockTileCache{
		tiles: map[uint64]string{
			256: "tile-0",
		},
	}
	reaper := NewTileReaper(func(context.Context) (uint64, error) {
		return 500, nil
	}, cache)

	errCh := make(chan error, 1)
	go func() {
		errCh <- reaper.Run(ctx, 10*time.Millisecond)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cache.mu.Lock()
		_, ok := cache.tiles[256]
		cache.mu.Unlock()
		if !ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	err := <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("reaper.Run returned unexpected error: %v", err)
	}

	cache.mu.Lock()
	if _, ok := cache.tiles[256]; ok {
		t.Error("expected tile 256 to be pruned by background reaper")
	}
	cache.mu.Unlock()
}
