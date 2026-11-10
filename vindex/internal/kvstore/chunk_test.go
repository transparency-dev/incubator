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
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestChunkKey_InvertedOrderingAndRoundtrip(t *testing.T) {
	keyHash := sha256.Sum256([]byte("example_key_1"))

	chunk0Key := encodeChunkKey(keyHash, 0)
	chunk1Key := encodeChunkKey(keyHash, 1)
	chunk10Key := encodeChunkKey(keyHash, 10)
	chunkMaxKey := encodeChunkKey(keyHash, math.MaxUint64)

	if bytes.Compare(chunk1Key[:], chunk0Key[:]) >= 0 ||
		bytes.Compare(chunk10Key[:], chunk1Key[:]) >= 0 ||
		bytes.Compare(chunkMaxKey[:], chunk10Key[:]) >= 0 {
		t.Fatal("inverted chunk keys did not sort newest-first")
	}

	prefix := encodeChunkPrefix(keyHash)
	if !bytes.HasPrefix(chunk0Key[:], prefix[:]) {
		t.Fatal("encoded chunk key missing 33-byte prefix")
	}

	for _, chunkNum := range []uint64{0, 1, 2, 42, 65535, 65536, 1 << 30, math.MaxUint64} {
		enc := encodeChunkKey(keyHash, chunkNum)
		decChunkNum, err := decodeChunkKey(enc[:])
		if err != nil || decChunkNum != chunkNum {
			t.Fatalf("decodeChunkKey(%d) = %d, err=%v", chunkNum, decChunkNum, err)
		}
	}

	if _, err := decodeChunkKey([]byte("too_short")); err == nil {
		t.Fatal("expected error for short key")
	}
	badPrefix := chunk0Key
	badPrefix[0] = 'x'
	if _, err := decodeChunkKey(badPrefix[:]); err == nil {
		t.Fatal("expected error for non-'c' prefix key")
	}
}

func TestChunkValue_DelimitlessRoundtripAndValidation(t *testing.T) {
	testCases := []struct {
		name string
		rec  *chunkRecord
	}{
		{
			name: "empty_record",
			rec:  &chunkRecord{},
		},
		{
			name: "single_hash_and_indices",
			rec: &chunkRecord{
				Preceding:       1,
				CompactRange:    [][32]byte{sha256.Sum256([]byte("h0"))},
				RelativeIndices: []uint16{0, 5, 42, 65535},
			},
		},
		{
			name: "multi_hashes_and_indices",
			rec: &chunkRecord{
				Preceding: 7,
				CompactRange: [][32]byte{
					sha256.Sum256([]byte("h0_3")),
					sha256.Sum256([]byte("h4_5")),
					sha256.Sum256([]byte("h6")),
				},
				RelativeIndices: []uint16{1, 2, 3, 100, 200, 300, 65534},
			},
		},
		{
			name: "max_chunk_size",
			rec: &chunkRecord{
				Preceding:       65536,
				CompactRange:    [][32]byte{sha256.Sum256([]byte("full_chunk_0"))},
				RelativeIndices: []uint16{0, 1, 2, 3, 65535},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := appendChunkValue(nil, tc.rec)
			got, err := unmarshalChunkValue(b)
			if err != nil {
				t.Fatalf("unmarshalChunkValue failed: %v", err)
			}
			if diff := cmp.Diff(tc.rec, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("chunkRecord mismatch (-want +got):\n%s", diff)
			}
		})
	}

	truncHash := make([]byte, 20)
	truncHash[7] = 1
	dupIndices := make([]byte, 8+4) // Preceding=0, two identical uint16(5) offsets
	dupIndices[9] = 5
	dupIndices[11] = 5

	for i, bad := range [][]byte{
		{1, 2, 3},
		truncHash,
		make([]byte, 9),
		dupIndices,
	} {
		if _, err := unmarshalChunkValue(bad); err == nil {
			t.Fatalf("malformed case %d: expected error, got nil", i)
		}
	}
}

func BenchmarkAppendChunkValue(b *testing.B) {
	rec := &chunkRecord{
		Preceding: 7,
		CompactRange: [][32]byte{
			sha256.Sum256([]byte("h0")),
			sha256.Sum256([]byte("h1")),
			sha256.Sum256([]byte("h2")),
		},
		RelativeIndices: make([]uint16, 256),
	}
	for i := range rec.RelativeIndices {
		rec.RelativeIndices[i] = uint16(i)
	}
	buf := make([]byte, 0, 8+32*3+2*256)
	b.ReportAllocs()
	for b.Loop() {
		buf = appendChunkValue(buf[:0], rec)
	}
}
