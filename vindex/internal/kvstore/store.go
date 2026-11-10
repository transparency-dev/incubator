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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/cockroachdb/pebble/vfs"
)

// chunkComparer splits 'c' prefix keys at 33 bytes ('c' + 32-byte KeyHash)
// so 10-bit table Bloom filters prune absent keys via SeekPrefixGE.
var chunkComparer = &pebble.Comparer{
	Name:           "vindex.inverted_prefix_chunk_comparer",
	Compare:        bytes.Compare,
	Equal:          bytes.Equal,
	FormatKey:      pebble.DefaultComparer.FormatKey,
	FormatValue:    pebble.DefaultComparer.FormatValue,
	Separator:      pebble.DefaultComparer.Separator,
	Successor:      pebble.DefaultComparer.Successor,
	AbbreviatedKey: pebble.DefaultComparer.AbbreviatedKey,
	Split: func(key []byte) int {
		if len(key) >= 33 && key[0] == prefixChunkByte {
			return 33
		}
		return len(key)
	},
}

// DB wraps a Pebble database with VIndex conventions.
type DB struct {
	db              *pebble.DB
	cache           *pebble.Cache
	chunkSize       uint64
	maxChunksPerReq atomic.Int64
	closeMu         sync.RWMutex
	closed          bool
}

type dbIter struct {
	*pebble.Iterator
	unlock sync.Once
	db     *DB
}

func (it *dbIter) Close() error {
	if it == nil {
		return nil
	}
	var err error
	it.unlock.Do(func() {
		if it.Iterator != nil {
			err = it.Iterator.Close()
		}
		if it.db != nil {
			it.db.closeMu.RUnlock()
		}
	})
	return err
}

// Batch wraps an indexed or unindexed Pebble write batch so callers do not import pebble directly.
type Batch struct {
	b           *pebble.Batch
	db          *DB
	err         error
	applied     bool
	stagedCache map[[sha256.Size]byte]activeChunkEntry
	onApply     []func()
	unlock      sync.Once
}

// Set stages a key-value write in the batch.
func (b *Batch) Set(key, val []byte) error {
	if b.err != nil {
		return b.err
	}
	if b.b == nil || b.applied {
		return errors.New("kvstore: batch is closed or already applied")
	}
	return b.b.Set(key, val, nil)
}

// SetUint64 stages a big-endian uint64 metadata write in the batch.
func (b *Batch) SetUint64(key []byte, val uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	return b.Set(key, buf[:])
}

// Close releases resources associated with the batch.
func (b *Batch) Close() error {
	if b == nil {
		return nil
	}
	var err error
	b.unlock.Do(func() {
		if b.b != nil {
			err = b.b.Close()
			b.b = nil
		}
		b.stagedCache = nil
		b.onApply = nil
		if b.db != nil {
			b.db.closeMu.RUnlock()
		}
	})
	return err
}

// ChunkSize returns the configured chunk size for this DB.
func (d *DB) ChunkSize() uint64 {
	if d.chunkSize == 0 || d.chunkSize > ChunkSize {
		return ChunkSize
	}
	return d.chunkSize
}

func (d *DB) maxChunksPerRequest() int {
	if n := d.maxChunksPerReq.Load(); n > 0 {
		return int(n)
	}
	return defaultMaxChunksPerRequest
}

func buildPebbleOptions(dir string, opts *Options) (*pebble.Options, *pebble.Cache, string) {
	cacheBytes := int64(512 << 20)
	var maxOpenFiles int
	inMem := dir == "" || dir == ":memory:"
	if opts != nil {
		if opts.CacheSizeMB > 0 {
			cacheBytes = int64(opts.CacheSizeMB) << 20
		}
		maxOpenFiles = opts.MaxOpenFiles
	}
	if maxOpenFiles <= 0 {
		maxOpenFiles = autoTuneMaxOpenFiles()
	}

	bf := bloom.FilterPolicy(10)
	allocatedCache := pebble.NewCache(cacheBytes)
	pOpts := &pebble.Options{
		Comparer:                    chunkComparer,
		Filters:                     map[string]pebble.FilterPolicy{bf.Name(): bf},
		Cache:                       allocatedCache,
		MemTableSize:                128 << 20,
		MemTableStopWritesThreshold: 8,
		L0CompactionThreshold:       8,
		L0StopWritesThreshold:       32,
		MaxConcurrentCompactions:    func() int { return 8 },
		MaxOpenFiles:                maxOpenFiles,
		Levels:                      make([]pebble.LevelOptions, 7),
	}
	if inMem {
		pOpts.FS = vfs.NewMem()
		dir = ""
	}
	for i := range pOpts.Levels {
		pOpts.Levels[i].FilterPolicy = bf
		if i >= 2 {
			pOpts.Levels[i].TargetFileSize = int64((8 << 20) * (1 << min(i-2, 3)))
		}
	}
	return pOpts, allocatedCache, dir
}

// Open opens a Pebble DB configured for VIndex. If dir is empty or ":memory:",
// an ephemeral in-memory filesystem is used.
func Open(dir string, opts *Options) (*DB, error) {
	chunkSize := ChunkSize
	if opts != nil && opts.ChunkSize > 0 && opts.ChunkSize <= ChunkSize {
		chunkSize = opts.ChunkSize
	}
	pOpts, allocatedCache, openDir := buildPebbleOptions(dir, opts)
	pDb, err := pebble.Open(openDir, pOpts)
	if err != nil {
		allocatedCache.Unref()
		return nil, err
	}
	return &DB{db: pDb, cache: allocatedCache, chunkSize: chunkSize}, nil
}

func (d *DB) withReadLock(fn func(*pebble.DB) error) error {
	d.closeMu.RLock()
	defer d.closeMu.RUnlock()
	if d.closed {
		return ErrClosed
	}
	return fn(d.db)
}

// Close closes the underlying database after waiting for in-flight reads, iterators, and batches.
func (d *DB) Close() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.closed {
		return ErrClosed
	}
	d.closed = true

	err := d.db.Close()
	if d.cache != nil {
		d.cache.Unref()
		d.cache = nil
	}
	return err
}

// Sync flushes the memtable to stable storage, ensuring durability of all uncommitted writes.
func (d *DB) Sync() error {
	if d == nil {
		return nil
	}
	return d.withReadLock(func(p *pebble.DB) error {
		return p.Flush()
	})
}

func (d *DB) newBatch(indexed bool) *Batch {
	d.closeMu.RLock()
	if d.closed {
		d.closeMu.RUnlock()
		return &Batch{err: ErrClosed}
	}
	var pb *pebble.Batch
	if indexed {
		pb = d.db.NewIndexedBatch()
	} else {
		pb = d.db.NewBatch()
	}
	return &Batch{b: pb, db: d}
}

// NewIndexedBatch creates a new indexed write batch suitable for staging and reading uncommitted writes.
func (d *DB) NewIndexedBatch() *Batch {
	return d.newBatch(true)
}

// Apply commits a staged Batch to the database.
// An open Batch already holds d.closeMu.RLock(), so Apply commits directly without re-acquiring closeMu.RLock().
func (d *DB) Apply(b *Batch, sync bool) error {
	if d == nil {
		return ErrClosed
	}
	if b == nil {
		return nil
	}
	if b.err != nil {
		return b.err
	}
	if b.db != d || b.b == nil || b.applied {
		return errors.New("kvstore: invalid, closed, or already applied batch")
	}
	wo := pebble.NoSync
	if sync {
		wo = pebble.Sync
	}
	if err := d.db.Apply(b.b, wo); err != nil {
		return err
	}
	b.applied = true
	for _, fn := range b.onApply {
		fn()
	}
	b.onApply = nil
	b.stagedCache = nil
	return nil
}

func (d *DB) newIter() (*dbIter, error) {
	d.closeMu.RLock()
	if d.closed {
		d.closeMu.RUnlock()
		return nil, ErrClosed
	}
	iter, err := d.db.NewIter(nil)
	if err != nil {
		d.closeMu.RUnlock()
		return nil, err
	}
	return &dbIter{Iterator: iter, db: d}, nil
}

// GetMetadata retrieves a metadata key value. Returns nil, nil if key does not exist.
func (d *DB) GetMetadata(key []byte) ([]byte, error) {
	var res []byte
	err := d.withReadLock(func(p *pebble.DB) error {
		val, closer, err := p.Get(key)
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				return nil
			}
			return err
		}
		defer func() { _ = closer.Close() }()
		res = bytes.Clone(val)
		return nil
	})
	return res, err
}

// SetMetadata sets a metadata key-value pair synchronously.
func (d *DB) SetMetadata(key, value []byte) error {
	return d.withReadLock(func(p *pebble.DB) error {
		return p.Set(key, value, pebble.Sync)
	})
}

// GetUint64 reads a big-endian uint64 metadata value. Returns 0, nil if not found.
func (d *DB) GetUint64(key []byte) (uint64, error) {
	val, err := d.GetMetadata(key)
	if err != nil || val == nil {
		return 0, err
	}
	if len(val) != 8 {
		return 0, fmt.Errorf("%w: expected 8 bytes for uint64 at %q, got %d", errInvalidMetadata, string(key), len(val))
	}
	return binary.BigEndian.Uint64(val), nil
}

// SetUint64 writes a big-endian uint64 metadata value synchronously.
func (d *DB) SetUint64(key []byte, val uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	return d.SetMetadata(key, buf[:])
}
