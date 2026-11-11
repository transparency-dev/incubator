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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// maxInMemoryBundles bounds the in-memory fallback cache when cacheDir is empty.
// Prevents unbounded heap growth and swap thrashing on large log ingestion.
const maxInMemoryBundles = 256

// ManagedTileCache manages local filesystem and in-memory tile bundle caching.
type ManagedTileCache struct {
	mu          sync.RWMutex
	cacheDir    string
	memory      map[uint64]*LeafBundle
	memoryOrder []uint64 // FIFO tracking for in-memory mode
	bundleSz    uint64
}

// NewManagedTileCache creates a new ManagedTileCache.
func NewManagedTileCache(cacheDir string, bundleSz uint64) (*ManagedTileCache, error) {
	if bundleSz == 0 {
		bundleSz = DefaultBundleSize
	}
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create tile cache dir %q: %w", cacheDir, err)
		}
	}
	return &ManagedTileCache{
		cacheDir: cacheDir,
		memory:   make(map[uint64]*LeafBundle),
		bundleSz: bundleSz,
	}, nil
}

// bundlePath returns the sharded filepath for a bundle index.
func (c *ManagedTileCache) bundlePath(bundleIdx uint64) string {
	shard := fmt.Sprintf("%06d", bundleIdx/1000)
	filename := fmt.Sprintf("bundle_%016d.dat", bundleIdx)
	return filepath.Join(c.cacheDir, shard, filename)
}

// GetBundle retrieves a LeafBundle from memory or disk cache.
func (c *ManagedTileCache) GetBundle(bundleIdx uint64) (*LeafBundle, error) {
	if c == nil {
		return nil, ErrBundleNotFound
	}
	if c.cacheDir == "" {
		c.mu.RLock()
		b, ok := c.memory[bundleIdx]
		c.mu.RUnlock()
		if ok {
			return cloneLeafBundle(b), nil
		}
		return nil, ErrBundleNotFound
	}

	bundlePath := c.bundlePath(bundleIdx)
	data, pBuf, err := readPooledFile(bundlePath, globalBufferPool)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBundleNotFound
		}
		return nil, err
	}
	defer pBuf.Release()

	b, err := unmarshalBundle(data, bundleIdx)
	if err != nil {
		_ = os.Remove(bundlePath)
		return nil, ErrBundleNotFound
	}
	return b, nil
}

var bundleMarshalPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 65536)
		return &b
	},
}

// PutBundle stores a LeafBundle on disk (or in memory if cacheDir is not configured).
func (c *ManagedTileCache) PutBundle(bundle *LeafBundle) error {
	if c == nil || bundle == nil {
		return nil
	}

	if c.cacheDir == "" {
		cloned := cloneLeafBundle(bundle)
		c.mu.Lock()
		if _, exists := c.memory[bundle.BundleIdx]; !exists {
			if len(c.memory) >= maxInMemoryBundles {
				if len(c.memoryOrder) > 0 {
					oldest := c.memoryOrder[0]
					c.memoryOrder = c.memoryOrder[1:]
					delete(c.memory, oldest)
				}
			}
			c.memoryOrder = append(c.memoryOrder, bundle.BundleIdx)
		}
		c.memory[bundle.BundleIdx] = cloned
		c.mu.Unlock()
		return nil
	}

	bufPtr := bundleMarshalPool.Get().(*[]byte)
	buf := marshalBundleInto((*bufPtr)[:0], bundle)
	*bufPtr = buf
	defer bundleMarshalPool.Put(bufPtr)

	bundlePath := c.bundlePath(bundle.BundleIdx)
	shardDir := filepath.Dir(bundlePath)

	tmpFile, err := os.CreateTemp(shardDir, ".bundle_*.tmp")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(shardDir, 0o755); err != nil {
				return fmt.Errorf("failed to create shard dir %q: %w", shardDir, err)
			}
			tmpFile, err = os.CreateTemp(shardDir, ".bundle_*.tmp")
		}
		if err != nil {
			return err
		}
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(buf); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, bundlePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// DirSize calculates the total size in bytes of files stored in the cacheDir.
func (c *ManagedTileCache) DirSize() (int64, error) {
	if c == nil || c.cacheDir == "" {
		return 0, nil
	}
	var totalSize int64
	err := filepath.WalkDir(c.cacheDir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			if strings.HasSuffix(d.Name(), ".tmp") {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			totalSize += info.Size()
		}
		return nil
	})
	return totalSize, err
}

// PruneBefore prunes all cached bundles whose leaf range is strictly below the given watermark.
func (c *ManagedTileCache) PruneBefore(watermark uint64) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prunedCount := 0
	for bIdx := range c.memory {
		endIdx := (bIdx + 1) * c.bundleSz
		if endIdx <= watermark {
			delete(c.memory, bIdx)
			prunedCount++
		}
	}
	if len(c.memoryOrder) > 0 {
		newOrder := make([]uint64, 0, len(c.memory))
		for _, idx := range c.memoryOrder {
			if _, ok := c.memory[idx]; ok {
				newOrder = append(newOrder, idx)
			}
		}
		c.memoryOrder = newOrder
	}

	if c.cacheDir != "" {
		emptyDirs := make(map[string]struct{})
		err := filepath.WalkDir(c.cacheDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasPrefix(name, "bundle_") || !strings.HasSuffix(name, ".dat") {
				return nil
			}
			var bIdx uint64
			if _, err := fmt.Sscanf(name, "bundle_%016d.dat", &bIdx); err == nil {
				endIdx := (bIdx + 1) * c.bundleSz
				if endIdx <= watermark {
					if err := os.Remove(path); err == nil {
						prunedCount++
						parent := filepath.Dir(path)
						if parent != c.cacheDir {
							emptyDirs[parent] = struct{}{}
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			return prunedCount, err
		}
		for dir := range emptyDirs {
			_ = os.Remove(dir)
		}
	}

	return prunedCount, nil
}

func marshalBundleInto(buf []byte, b *LeafBundle) []byte {
	var totalLeavesLen int
	for _, l := range b.Leaves {
		totalLeavesLen += 4 + len(l)
	}
	totalLen := 12 + totalLeavesLen
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}
	binary.BigEndian.PutUint64(buf[0:8], b.StartLeafIdx)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(b.Leaves)))
	offset := 12
	for _, l := range b.Leaves {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(l)))
		offset += 4
		copy(buf[offset:offset+len(l)], l)
		offset += len(l)
	}
	return buf
}

func unmarshalBundle(data []byte, bundleIdx uint64) (*LeafBundle, error) {
	if len(data) < 12 {
		return nil, errors.New("bundle data too short")
	}
	startLeafIdx := binary.BigEndian.Uint64(data[0:8])
	numLeaves := binary.BigEndian.Uint32(data[8:12])
	if uint64(numLeaves) > uint64(len(data)-12)/4 {
		return nil, errors.New("bundle leaf count exceeds data length")
	}
	leaves := make([][]byte, 0, numLeaves)
	offset := 12
	for i := uint32(0); i < numLeaves; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("bundle truncated")
		}
		lLen := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if lLen > uint64(len(data)-offset) {
			return nil, errors.New("bundle leaf truncated")
		}
		leaf := make([]byte, lLen)
		copy(leaf, data[offset:offset+int(lLen)])
		leaves = append(leaves, leaf)
		offset += int(lLen)
	}
	if offset != len(data) {
		return nil, errors.New("bundle has trailing bytes")
	}
	return &LeafBundle{
		BundleIdx:    bundleIdx,
		StartLeafIdx: startLeafIdx,
		Leaves:       leaves,
	}, nil
}

func cloneLeafBundle(b *LeafBundle) *LeafBundle {
	if b == nil {
		return nil
	}
	var totalLen int
	for _, l := range b.Leaves {
		totalLen += len(l)
	}
	slab := make([]byte, totalLen)
	leaves := make([][]byte, len(b.Leaves))
	offset := 0
	for i, l := range b.Leaves {
		copy(slab[offset:offset+len(l)], l)
		leaves[i] = slab[offset : offset+len(l) : offset+len(l)]
		offset += len(l)
	}
	return &LeafBundle{
		BundleIdx:    b.BundleIdx,
		StartLeafIdx: b.StartLeafIdx,
		Leaves:       leaves,
	}
}
