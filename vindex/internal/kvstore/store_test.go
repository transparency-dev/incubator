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
	"path/filepath"
	"sync"
	"testing"
)

func TestChunkComparer_Split(t *testing.T) {
	var keyHash [32]byte
	copy(keyHash[:], []byte("01234567890123456789012345678901"))

	chunkKey := encodeChunkKey(keyHash, 0)
	if got := chunkComparer.Split(chunkKey[:]); got != 33 {
		t.Fatalf("chunkComparer.Split(chunkKey) = %d, want 33", got)
	}

	shortCKey := []byte("c_short")
	if got := chunkComparer.Split(shortCKey); got != len(shortCKey) {
		t.Fatalf("chunkComparer.Split(shortCKey) = %d, want %d", got, len(shortCKey))
	}

	if got := chunkComparer.Split(KeyMetaKVSize); got != len(KeyMetaKVSize) {
		t.Fatalf("chunkComparer.Split(KeyMetaKVSize) = %d, want %d", got, len(KeyMetaKVSize))
	}
}

func TestDB_MetadataAccessorsAndInMemory(t *testing.T) {
	db, err := Open(":memory:", nil)
	if err != nil {
		t.Fatalf("Open(:memory:) failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	val, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || val != nil {
		t.Fatalf("expected nil for missing key, got err=%v val=%v", err, val)
	}
	size, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || size != 0 {
		t.Fatalf("expected 0 for missing uint64, got err=%v size=%d", err, size)
	}

	if err := db.SetMetadata(KeyMetaKVCheckpoint, []byte("cp_raw_test_val")); err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
	if _, err := db.GetUint64(KeyMetaKVCheckpoint); !errors.Is(err, errInvalidMetadata) {
		t.Fatalf("GetUint64(non-8-byte) = %v, want errInvalidMetadata", err)
	}
	if err := db.SetUint64(KeyMetaKVSize, 123456789); err != nil {
		t.Fatalf("SetUint64 failed: %v", err)
	}

	gotCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(gotCP, []byte("cp_raw_test_val")) {
		t.Fatalf("GetMetadata mismatch: got %q, err=%v", string(gotCP), err)
	}
	gotSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || gotSize != 123456789 {
		t.Fatalf("GetUint64 mismatch: got %d, err=%v", gotSize, err)
	}
}

func TestDB_DoubleCloseAndConcurrentCloseRace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_clamp_closed")
	db, err := Open(dir, &Options{CacheSizeMB: 16, MaxOpenFiles: 2500, ChunkSize: ChunkSize + 1000})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if db.ChunkSize() != ChunkSize {
		t.Fatalf("db.ChunkSize() = %d, want clamped %d", db.ChunkSize(), ChunkSize)
	}

	idx := NewKVIndexer(db)
	if _, err := idx.IndexMappedBatch(context.Background(), &MappedBatch{
		EndLeafIdx: 10,
		KeyIndices: map[string][]uint64{"com.example.race": {1, 5}},
	}, nil, 10); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	keyHash := sha256.Sum256([]byte("com.example.race"))
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_, lErr := db.Lookup(keyHash, nil, 10, 10)
				if lErr != nil && !errors.Is(lErr, ErrClosed) {
					t.Errorf("unexpected Lookup error during Close: %v", lErr)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 20 {
			wIdx := NewKVIndexer(db)
			_, wErr := wIdx.IndexMappedBatch(context.Background(), &MappedBatch{
				StartLeafIdx: uint64(10 + i*5),
				EndLeafIdx:   uint64(15 + i*5),
				KeyIndices:   map[string][]uint64{fmt.Sprintf("com.example.w%d", i): {uint64(10 + i*5)}},
			}, nil, 0)
			if wErr != nil && !errors.Is(wErr, ErrClosed) {
				t.Errorf("unexpected IndexMappedBatch error during Close: %v", wErr)
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 20 {
			sIdx := NewKVIndexer(db)
			sb := db.NewIndexedBatch()
			_, sErr := sIdx.StageMappedBatch(context.Background(), sb, 0, &MappedBatch{
				EndLeafIdx: 5,
				KeyIndices: map[string][]uint64{fmt.Sprintf("com.example.s%d", i): {1}},
			}, 5)
			if sErr == nil {
				sErr = db.Apply(sb, false)
			}
			_ = sb.Close()
			if sErr != nil && !errors.Is(sErr, ErrClosed) {
				t.Errorf("unexpected StageMappedBatch/Apply error during Close: %v", sErr)
				return
			}
		}
	}()

	if err := db.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}
	wg.Wait()

	if err := db.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Second Close = %v, want ErrClosed", err)
	}
	if _, err := db.Lookup(keyHash, nil, 10, 10); !errors.Is(err, ErrClosed) {
		t.Fatalf("Lookup on closed DB = %v, want ErrClosed", err)
	}
	if _, err := idx.IndexMappedBatch(context.Background(), nil, nil, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("IndexMappedBatch(nil) on closed DB = %v, want ErrClosed", err)
	}
	closedBatch := db.NewIndexedBatch()
	defer func() { _ = closedBatch.Close() }()
	if err := db.Apply(closedBatch, false); !errors.Is(err, ErrClosed) {
		t.Fatalf("Apply(closedBatch) = %v, want ErrClosed", err)
	}
	if err := db.Sync(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Sync on closed DB = %v, want ErrClosed", err)
	}
}

func TestBuildPebbleOptions(t *testing.T) {
	pOpts, cache, _ := buildPebbleOptions(t.TempDir(), nil)
	defer cache.Unref()
	if pOpts.MaxOpenFiles < 500 {
		t.Errorf("expected auto-tuned MaxOpenFiles >= 500, got %d", pOpts.MaxOpenFiles)
	}
	if len(pOpts.Levels) != 7 {
		t.Fatalf("expected 7 levels, got %d", len(pOpts.Levels))
	}
	if pOpts.Levels[2].TargetFileSize != 8<<20 || pOpts.Levels[3].TargetFileSize != 16<<20 {
		t.Errorf("unexpected TargetFileSize: L2=%d L3=%d", pOpts.Levels[2].TargetFileSize, pOpts.Levels[3].TargetFileSize)
	}
}
