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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"testing"

	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

func testBatchRoot(leaves [][]byte) [sha256.Size]byte {
	if len(leaves) == 0 {
		return wire.EmptyRoot()
	}
	hashes := make([][sha256.Size]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = wire.LeafHash(l)
	}
	return testBatchRootHashes(hashes)
}

func testBatchRootHashes(hashes [][sha256.Size]byte) [sha256.Size]byte {
	n := len(hashes)
	if n == 1 {
		return hashes[0]
	}
	k := 1 << (bits.Len(uint(n-1)) - 1)
	return wire.InteriorHash(testBatchRootHashes(hashes[:k]), testBatchRootHashes(hashes[k:]))
}

func computeExpectedValueRoot(indices []uint64) [sha256.Size]byte {
	leaves := make([][]byte, len(indices))
	for i, idx := range indices {
		leaves[i] = binary.BigEndian.AppendUint64(nil, idx)
	}
	return testBatchRoot(leaves)
}

func TestCompactRange_IncrementalMatchesBatch(t *testing.T) {
	for size := range 258 {
		var leaves [][]byte
		cr := newCompactRange()
		for i := range size {
			leaf := []byte(fmt.Sprintf("entry_%d", i))
			leaves = append(leaves, leaf)
			cr.append(wire.LeafHash(leaf))
		}

		expectedRoot := testBatchRoot(leaves)
		if got := cr.root(); got != expectedRoot {
			t.Fatalf("size %d root mismatch: compact=%x, batch=%x", size, got, expectedRoot)
		}
		if cr.Preceding != uint64(size) {
			t.Fatalf("size %d preceding mismatch: got %d", size, cr.Preceding)
		}
	}
}

func BenchmarkCompactRange_Append1024(b *testing.B) {
	leafHashes := make([][sha256.Size]byte, 1024)
	for i := range leafHashes {
		leafHashes[i] = sha256.Sum256([]byte(fmt.Sprintf("entry_%d", i)))
	}
	b.ReportAllocs()
	for b.Loop() {
		cr := newCompactRange()
		for _, lh := range leafHashes {
			cr.append(lh)
		}
	}
}
