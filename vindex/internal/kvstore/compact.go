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
	"math/bits"
	"slices"

	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// compactRange represents an incremental RFC 6962 compact Merkle tree range.
type compactRange struct {
	Preceding uint64
	Hashes    [][sha256.Size]byte
}

func newCompactRange() *compactRange {
	return &compactRange{}
}

func (cr *compactRange) clone() *compactRange {
	if cr == nil {
		return nil
	}
	return &compactRange{
		Preceding: cr.Preceding,
		Hashes:    slices.Clone(cr.Hashes),
	}
}

func (cr *compactRange) appendIndex(idx uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], idx)
	cr.append(wire.LeafHash(b[:]))
}

func (cr *compactRange) append(leafHash [sha256.Size]byte) {
	h := leafHash
	trailingOnes := bits.TrailingZeros64(^cr.Preceding)
	for range trailingOnes {
		idx := len(cr.Hashes) - 1
		left := cr.Hashes[idx]
		cr.Hashes = cr.Hashes[:idx]
		h = wire.InteriorHash(left, h)
	}
	cr.Hashes = append(cr.Hashes, h)
	cr.Preceding++
}

func (cr *compactRange) root() [sha256.Size]byte {
	if cr.Preceding == 0 || len(cr.Hashes) == 0 {
		return wire.EmptyRoot()
	}
	ln := len(cr.Hashes)
	root := cr.Hashes[ln-1]
	for i := ln - 2; i >= 0; i-- {
		root = wire.InteriorHash(cr.Hashes[i], root)
	}
	return root
}
