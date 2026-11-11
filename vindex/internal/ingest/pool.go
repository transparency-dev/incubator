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
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// tieredBufferPool manages reusable byte buffers across power-of-two slab thresholds:
//   - 8 KB: Level 0 Merkle hash tiles (256 * 32B = 8,192B) and checkpoints (<1 KB)
//   - 64 KB: SumDB entry bundles (~40-60 KB)
//   - 512 KB: Certificate Transparency / MTC entry bundles (~120-400 KB) and tile cache bundles (~270 KB)
type tieredBufferPool struct {
	pool8K   sync.Pool
	pool64K  sync.Pool
	pool512K sync.Pool
}

var globalBufferPool = &tieredBufferPool{
	pool8K: sync.Pool{
		New: func() any { b := make([]byte, 8192); return &b },
	},
	pool64K: sync.Pool{
		New: func() any { b := make([]byte, 65536); return &b },
	},
	pool512K: sync.Pool{
		New: func() any { b := make([]byte, 524288); return &b },
	},
}

// pooledBuffer wraps a pooled byte buffer with atomic reference counting.
type pooledBuffer struct {
	buf  *[]byte
	pool *sync.Pool
	refs atomic.Int32
}

// Release decrements the reference counter and returns the buffer to the pool when refs reaches 0.
func (p *pooledBuffer) Release() {
	if p != nil && p.refs.Add(-1) == 0 {
		if p.pool != nil && p.buf != nil {
			p.pool.Put(p.buf)
		}
	}
}

// readPooledFile reads the entire contents of a file into a buffer borrowed from pool.
func readPooledFile(path string, pool *tieredBufferPool) ([]byte, *pooledBuffer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	size := fi.Size()
	if size == 0 {
		return []byte{}, &pooledBuffer{}, nil
	}

	var rawBuf *[]byte
	var selectedPool *sync.Pool

	switch {
	case size <= 8192:
		selectedPool = &pool.pool8K
		rawBuf = selectedPool.Get().(*[]byte)
	case size <= 65536:
		selectedPool = &pool.pool64K
		rawBuf = selectedPool.Get().(*[]byte)
	case size <= 524288:
		selectedPool = &pool.pool512K
		rawBuf = selectedPool.Get().(*[]byte)
	default:
		// Oversized file fallback: allocate directly
		b := make([]byte, size)
		rawBuf = &b
	}

	pBuf := &pooledBuffer{
		buf:  rawBuf,
		pool: selectedPool,
	}
	pBuf.refs.Store(1)

	buf := (*rawBuf)[:size]
	if _, err := io.ReadFull(f, buf); err != nil {
		pBuf.Release()
		return nil, nil, err
	}

	return buf, pBuf, nil
}
