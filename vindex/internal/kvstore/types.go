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

// Package kvstore implements the persistent key-value and chunk storage layer for VIndex using Pebble DB.
package kvstore

import (
	"crypto/sha256"
	"errors"
)

const (
	// ChunkSize is the logical capacity of a single chunk (65536 entries).
	ChunkSize uint64 = 65536

	// DefaultTargetPageSize is the default page target for Lookup when targetPageSize is 0.
	DefaultTargetPageSize uint64 = 100

	// MaxTargetPageSize caps the requested page target for Lookup.
	MaxTargetPageSize uint64 = 1000

	// defaultMaxChunksPerRequest bounds the number of non-empty inverted chunks
	// visited in a single Lookup call to prevent P99 latency spikes on sparse keys.
	defaultMaxChunksPerRequest = 16

	// prefixChunkByte identifies KV Chunk records ('c').
	prefixChunkByte byte = 'c'
)

var (
	// Standard metadata keys.
	KeyMetaTargetCheckpoint = []byte("m_target_checkpoint")
	KeyMetaKVCheckpoint     = []byte("m_kv_checkpoint")
	KeyMetaKVSize           = []byte("m_kv_size")
)

var (
	// ErrClosed is returned when operating on a closed DB.
	ErrClosed = errors.New("kvstore is closed")

	errInvalidValue    = errors.New("invalid storage value")
	errInvalidChunkKey = errors.New("invalid chunk key")
	errInvalidMetadata = errors.New("invalid metadata value")
)

// Options configures a Pebble-backed kvstore.DB without exposing Pebble types outside kvstore.
type Options struct {
	CacheSizeMB  int
	MaxOpenFiles int
	ChunkSize    uint64
}

// chunkRecord represents the deserialized content of a KV chunk value.
type chunkRecord struct {
	Preceding       uint64
	CompactRange    [][sha256.Size]byte
	RelativeIndices []uint16
}

// LookupResult encapsulates range lookup matches and the preceding compact range.
type LookupResult struct {
	MatchedIndices []uint64
	Preceding      uint64
	CompactRange   [][sha256.Size]byte
}

// MappedBatch describes a contiguous range of mapped Input Log leaves and their deduplicated canonical keys.
type MappedBatch struct {
	StartLeafIdx uint64
	EndLeafIdx   uint64
	KeyIndices   map[string][]uint64
}

// IndexResult contains the result of an indexing batch.
type IndexResult struct {
	NewKVSize             uint64
	ModifiedKeyValueRoots map[string][sha256.Size]byte
}
