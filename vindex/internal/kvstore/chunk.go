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
	"slices"
)

// encodeChunkPrefix formats the 33-byte prefix for a key hash ('c' + KeyHash).
func encodeChunkPrefix(keyHash [sha256.Size]byte) [33]byte {
	var buf [33]byte
	buf[0] = prefixChunkByte
	copy(buf[1:33], keyHash[:])
	return buf
}

// encodeChunkKey formats the 41-byte inverted chunk key ('c' + KeyHash + ^BigEndian(chunkNum)).
func encodeChunkKey(keyHash [sha256.Size]byte, chunkNum uint64) [41]byte {
	var buf [41]byte
	buf[0] = prefixChunkByte
	copy(buf[1:33], keyHash[:])
	binary.BigEndian.PutUint64(buf[33:41], ^chunkNum)
	return buf
}

// decodeChunkKey parses a 41-byte chunk key and returns its original chunkNum.
func decodeChunkKey(key []byte) (uint64, error) {
	if len(key) != 41 || key[0] != prefixChunkByte {
		return 0, fmt.Errorf("%w: expected 41 bytes starting with 'c', got %d bytes", errInvalidChunkKey, len(key))
	}
	return ^binary.BigEndian.Uint64(key[33:41]), nil
}

// appendChunkValue appends the serialized chunkRecord to dst and returns the extended slice.
func appendChunkValue(dst []byte, rec *chunkRecord) []byte {
	if rec == nil {
		return dst
	}
	if len(rec.CompactRange) != bits.OnesCount64(rec.Preceding) {
		panic(fmt.Sprintf("kvstore: chunkRecord CompactRange length %d != popcount(%d)", len(rec.CompactRange), rec.Preceding))
	}
	dst = slices.Grow(dst, 8+32*len(rec.CompactRange)+2*len(rec.RelativeIndices))
	dst = binary.BigEndian.AppendUint64(dst, rec.Preceding)
	for _, h := range rec.CompactRange {
		dst = append(dst, h[:]...)
	}
	for _, idx := range rec.RelativeIndices {
		dst = binary.BigEndian.AppendUint16(dst, idx)
	}
	return dst
}

// unmarshalChunkValue deserializes a chunkRecord from uniform delimitless binary format.
func unmarshalChunkValue(data []byte) (*chunkRecord, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: chunk value too short (%d bytes)", errInvalidValue, len(data))
	}
	preceding := binary.BigEndian.Uint64(data[0:8])
	numHashes := bits.OnesCount64(preceding)
	hashesEnd := 8 + 32*numHashes
	if len(data) < hashesEnd {
		return nil, fmt.Errorf("%w: chunk value truncated for compact range (expected at least %d bytes, got %d)", errInvalidValue, hashesEnd, len(data))
	}
	rem := len(data) - hashesEnd
	if rem%2 != 0 {
		return nil, fmt.Errorf("%w: chunk value invalid relative indices length (%d bytes)", errInvalidValue, rem)
	}
	numIndices := rem / 2

	var hashes [][sha256.Size]byte
	if numHashes > 0 {
		hashes = make([][sha256.Size]byte, numHashes)
		offset := 8
		for i := range numHashes {
			copy(hashes[i][:], data[offset:offset+32])
			offset += 32
		}
	}

	var indices []uint16
	if numIndices > 0 {
		indices = make([]uint16, numIndices)
		offset := hashesEnd
		for i := range numIndices {
			idx := binary.BigEndian.Uint16(data[offset : offset+2])
			if i > 0 && idx <= indices[i-1] {
				return nil, fmt.Errorf("%w: non-increasing relative index at %d (%d <= %d)", errInvalidValue, i, idx, indices[i-1])
			}
			indices[i] = idx
			offset += 2
		}
	}

	return &chunkRecord{
		Preceding:       preceding,
		CompactRange:    hashes,
		RelativeIndices: indices,
	}, nil
}
