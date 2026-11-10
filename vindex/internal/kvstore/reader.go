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
	"fmt"
	"slices"
)

// Lookup retrieves matching leaf indices and preceding compact ranges for keyHash up to before.
//
// Optimization rationale:
//  1. Prefix Bloom Filters (SeekPrefixGE): Exploits Pebble's 33-byte prefix split ('c' + KeyHash)
//     and inverted chunk key ordering (^chunkNum) via SeekPrefixGE to prune absent keys without disk reads
//     and seek directly to the newest chunk <= upperBound.
//  2. Chunk-Aligned Paging: Uses 'targetPageSize' (default 100, max 1000) as a server-side page target
//     and aligns page boundaries to whole inverted chunks. Every stored chunk already contains precomputed
//     rec.CompactRange and rec.Preceding committing to all prior chunks, so preceding compact ranges are
//     copied directly with zero dynamic SHA-256 hashing on the read path.
//  3. Bounded Chunk Visitation: Halts once totalMatched >= targetPageSize OR chunksVisited >= maxChunksPerRequest
//     (defaultMaxChunksPerRequest = 16) to bound worst-case SSTable seeks on sparse keys.
func (d *DB) Lookup(keyHash [sha256.Size]byte, before *uint64, targetPageSize uint64, maxInputLogSize uint64) (res *LookupResult, retErr error) {
	if targetPageSize == 0 {
		targetPageSize = DefaultTargetPageSize
	} else if targetPageSize > MaxTargetPageSize {
		targetPageSize = MaxTargetPageSize
	}

	upperBound := maxInputLogSize
	if before != nil && *before < upperBound {
		upperBound = *before
	}
	if upperBound == 0 {
		return &LookupResult{}, nil
	}

	chunkSize := d.ChunkSize()
	maxChunkNum := (upperBound - 1) / chunkSize
	seekKey := encodeChunkKey(keyHash, maxChunkNum)
	prefix := seekKey[:33]

	iter, err := d.newIter()
	if err != nil {
		return nil, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func() {
		if cErr := iter.Close(); cErr != nil && retErr == nil {
			res = nil
			retErr = fmt.Errorf("close iterator: %w", cErr)
		}
	}()

	if !iter.SeekPrefixGE(seekKey[:]) {
		if iErr := iter.Error(); iErr != nil {
			return nil, fmt.Errorf("seek chunk prefix: %w", iErr)
		}
		return &LookupResult{}, nil
	}
	if !bytes.HasPrefix(iter.Key(), prefix) {
		return &LookupResult{}, nil
	}

	maxChunks := d.maxChunksPerRequest()
	var matchedSlices [][]uint64
	var totalMatched uint64
	var chunksVisited int
	var oldestRec *chunkRecord

	for ; iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		cNum, err := decodeChunkKey(iter.Key())
		if err != nil {
			return nil, fmt.Errorf("decode chunk key: %w", err)
		}
		if cNum > maxChunkNum {
			continue
		}

		rec, err := unmarshalChunkValue(iter.Value())
		if err != nil {
			return nil, fmt.Errorf("unmarshal chunk value: %w", err)
		}

		chunkBase := cNum * chunkSize
		remBound := upperBound - chunkBase
		var validCount int
		if remBound >= chunkSize {
			validCount = len(rec.RelativeIndices)
		} else {
			validCount, _ = slices.BinarySearch(rec.RelativeIndices, uint16(remBound))
		}
		if validCount == 0 {
			continue
		}

		chunkMatches := make([]uint64, validCount)
		for i, rel := range rec.RelativeIndices[:validCount] {
			chunkMatches[i] = chunkBase + uint64(rel)
		}
		matchedSlices = append(matchedSlices, chunkMatches)
		totalMatched += uint64(validCount)
		chunksVisited++
		oldestRec = rec

		if totalMatched >= targetPageSize || chunksVisited >= maxChunks {
			break
		}
	}
	if iErr := iter.Error(); iErr != nil {
		return nil, fmt.Errorf("iterate chunks: %w", iErr)
	}

	if totalMatched == 0 {
		return &LookupResult{}, nil
	}

	var allMatched []uint64
	if len(matchedSlices) == 1 {
		allMatched = matchedSlices[0]
	} else {
		// matchedSlices was collected newest-first, so assemble in reverse order.
		allMatched = make([]uint64, 0, totalMatched)
		for i := len(matchedSlices) - 1; i >= 0; i-- {
			allMatched = append(allMatched, matchedSlices[i]...)
		}
	}

	var preceding uint64
	var compactHashes [][sha256.Size]byte
	if oldestRec != nil && oldestRec.Preceding > 0 {
		preceding = oldestRec.Preceding
		compactHashes = slices.Clone(oldestRec.CompactRange)
	}

	return &LookupResult{
		MatchedIndices: allMatched,
		Preceding:      preceding,
		CompactRange:   compactHashes,
	}, nil
}
