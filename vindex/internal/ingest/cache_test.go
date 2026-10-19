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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkManagedTileCache_PutBundle(b *testing.B) {
	dir := b.TempDir()
	cache, err := NewManagedTileCache(dir, 256)
	if err != nil {
		b.Fatalf("NewManagedTileCache failed: %v", err)
	}

	const leavesPerBundle = 256
	const leafSize = 1024
	leaf := bytes.Repeat([]byte{0xcd}, leafSize)
	bundle := &LeafBundle{
		BundleIdx:    100,
		StartLeafIdx: 100 * leavesPerBundle,
		Leaves:       make([][]byte, leavesPerBundle),
	}
	for i := range bundle.Leaves {
		bundle.Leaves[i] = leaf
	}

	b.ReportAllocs()
	var i uint64
	for b.Loop() {
		bundle.BundleIdx = i
		bundle.StartLeafIdx = i * leavesPerBundle
		if err := cache.PutBundle(bundle); err != nil {
			b.Fatalf("PutBundle failed: %v", err)
		}
		i++
	}
}

func BenchmarkMarshalBundleInto(b *testing.B) {
	const leavesPerBundle = 256
	const leafSize = 1024
	leaf := bytes.Repeat([]byte{0xef}, leafSize)
	bundle := &LeafBundle{
		BundleIdx:    42,
		StartLeafIdx: 42 * leavesPerBundle,
		Leaves:       make([][]byte, leavesPerBundle),
	}
	for i := range bundle.Leaves {
		bundle.Leaves[i] = leaf
	}

	buf := make([]byte, 12+leavesPerBundle*(4+leafSize))
	b.ReportAllocs()
	for b.Loop() {
		_ = marshalBundleInto(buf, bundle)
	}
}

func TestManagedTileCache_Sharding(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewManagedTileCache(dir, 16)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// 1. Sharded write and read across multiple shards
	b0 := &LeafBundle{BundleIdx: 0, StartLeafIdx: 0, Leaves: [][]byte{[]byte("leaf0")}}
	b1000 := &LeafBundle{BundleIdx: 1000, StartLeafIdx: 16000, Leaves: [][]byte{[]byte("leaf1000")}}
	b2005 := &LeafBundle{BundleIdx: 2005, StartLeafIdx: 32080, Leaves: [][]byte{[]byte("leaf2005")}}

	if err := cache.PutBundle(b0); err != nil {
		t.Fatalf("PutBundle b0 failed: %v", err)
	}
	if err := cache.PutBundle(b1000); err != nil {
		t.Fatalf("PutBundle b1000 failed: %v", err)
	}
	if err := cache.PutBundle(b2005); err != nil {
		t.Fatalf("PutBundle b2005 failed: %v", err)
	}

	// Verify sharded file paths exist
	p0 := filepath.Join(dir, "000000", "bundle_0000000000000000.dat")
	p1000 := filepath.Join(dir, "000001", "bundle_0000000000001000.dat")
	p2005 := filepath.Join(dir, "000002", "bundle_0000000000002005.dat")

	for _, p := range []string{p0, p1000, p2005} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %q to exist, got err: %v", p, err)
		}
	}

	// Verify GetBundle reads them correctly
	gotB1000, err := cache.GetBundle(1000)
	if err != nil || string(gotB1000.Leaves[0]) != "leaf1000" {
		t.Fatalf("GetBundle(1000) = %v, %v", gotB1000, err)
	}

	// 2. DirSize calculates across shards
	sz, err := cache.DirSize()
	if err != nil || sz == 0 {
		t.Fatalf("DirSize() = %d, err = %v", sz, err)
	}

	// 3. PruneBefore cleans up across shards, removing empty shard directories
	// Watermark 16016 covers leaves up to bundle 1000 (0..16, 16000..16016)
	pruned, err := cache.PruneBefore(16016)
	if err != nil {
		t.Fatalf("PruneBefore failed: %v", err)
	}
	if pruned != 2 { // b0, b1000
		t.Fatalf("pruned = %d, want 2", pruned)
	}

	// Shard 000000 and 000001 should be deleted because they are now empty
	if _, err := os.Stat(filepath.Join(dir, "000000")); !os.IsNotExist(err) {
		t.Errorf("expected shard dir 000000 to be removed after prune")
	}
	if _, err := os.Stat(filepath.Join(dir, "000001")); !os.IsNotExist(err) {
		t.Errorf("expected shard dir 000001 to be removed after prune")
	}

	// Shard 000002 still contains bundle 2005
	gotB2005, err := cache.GetBundle(2005)
	if err != nil || string(gotB2005.Leaves[0]) != "leaf2005" {
		t.Fatalf("GetBundle(2005) failed: got %v, err: %v", gotB2005, err)
	}
}

func TestManagedTileCache_InMemoryBounded(t *testing.T) {
	cache, err := NewManagedTileCache("", 16)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// Insert 300 bundles (exceeding maxInMemoryBundles = 256)
	for i := uint64(0); i < 300; i++ {
		bundle := &LeafBundle{
			BundleIdx:    i,
			StartLeafIdx: i * 16,
			Leaves:       [][]byte{[]byte("data")},
		}
		if err := cache.PutBundle(bundle); err != nil {
			t.Fatalf("PutBundle(%d) failed: %v", i, err)
		}
	}

	cache.mu.RLock()
	inMemoryCount := len(cache.memory)
	orderCount := len(cache.memoryOrder)
	cache.mu.RUnlock()

	if inMemoryCount > maxInMemoryBundles {
		t.Fatalf("in-memory cache exceeded bound: got %d, want <= %d", inMemoryCount, maxInMemoryBundles)
	}
	if orderCount != inMemoryCount {
		t.Fatalf("memoryOrder length mismatch: got %d, want %d", orderCount, inMemoryCount)
	}

	// The first 44 bundles (0..43) should have been evicted in FIFO order
	for i := uint64(0); i < 44; i++ {
		if _, err := cache.GetBundle(i); !errors.Is(err, ErrBundleNotFound) {
			t.Errorf("expected bundle %d to be evicted, got err = %v", i, err)
		}
	}

	// The latest bundles (44..299) should still exist
	for i := uint64(44); i < 300; i++ {
		if _, err := cache.GetBundle(i); err != nil {
			t.Errorf("expected bundle %d to be present, got err = %v", i, err)
		}
	}
}

func TestManagedTileCache_CorruptFileTreatedAsCacheMiss(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewManagedTileCache(dir, 16)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	b0 := &LeafBundle{BundleIdx: 0, StartLeafIdx: 0, Leaves: [][]byte{[]byte("leaf0")}}
	p0 := filepath.Join(dir, "000000", "bundle_0000000000000000.dat")

	corruptPayloads := [][]byte{
		[]byte("short"),
		// 12-byte header with numLeaves = 0xFFFFFFFF (must not OOM)
		{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff},
		// Valid 0-leaf header followed by trailing garbage
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa},
	}

	for _, payload := range corruptPayloads {
		if err := cache.PutBundle(b0); err != nil {
			t.Fatalf("PutBundle failed: %v", err)
		}
		if err := os.WriteFile(p0, payload, 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
		if _, err := cache.GetBundle(0); !errors.Is(err, ErrBundleNotFound) {
			t.Fatalf("expected ErrBundleNotFound on corrupt bundle file (%x), got: %v", payload, err)
		}
		if _, err := os.Stat(p0); !os.IsNotExist(err) {
			t.Fatalf("expected corrupt bundle file to be removed, got stat err: %v", err)
		}
	}
}

func TestManagedTileCache_InMemoryDetachesFromPooledBuffer(t *testing.T) {
	cache, err := NewManagedTileCache("", 16)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	raw := globalBufferPool.pool8K.Get().(*[]byte)
	pBuf := &pooledBuffer{
		buf:  raw,
		pool: &globalBufferPool.pool8K,
	}
	pBuf.refs.Store(1)

	backing := (*raw)[:10]
	copy(backing, "leaf_zero_")
	b0 := &LeafBundle{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Leaves:       [][]byte{backing[:5], backing[5:10]},
		pooledBuf:    pBuf,
	}

	if err := cache.PutBundle(b0); err != nil {
		t.Fatalf("PutBundle failed: %v", err)
	}

	// Simulate Stage 2 releasing the bundle and overwriting the pooled backing array
	copy(backing, "XXXXXXXXXX")
	b0.Release()

	got, err := cache.GetBundle(0)
	if err != nil {
		t.Fatalf("GetBundle(0) failed: %v", err)
	}
	if got.pooledBuf != nil {
		t.Fatal("expected detached in-memory bundle to have nil pooledBuf")
	}
	if string(got.Leaves[0]) != "leaf_" || string(got.Leaves[1]) != "zero_" {
		t.Fatalf("in-memory cached leaves corrupted by pooled buffer reuse: got %q, %q", got.Leaves[0], got.Leaves[1])
	}
}
