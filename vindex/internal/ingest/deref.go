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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/sunlight"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/tlog"
)

type bundleCandidate struct {
	relPath string
	sumDB   bool
}

// FetchVerifiedEntryByIndex fetches the entry at idx from baseURL and, when treeSize > 0 and treeRoot is non-zero,
// cryptographically authenticates the entry against (treeSize, treeRoot) via an RFC 6962 inclusion proof.
func FetchVerifiedEntryByIndex(ctx context.Context, httpClient *http.Client, baseURL string, idx, treeSize uint64, treeRoot [32]byte) ([]byte, error) {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		return nil, errors.New("empty baseURL")
	}
	if treeSize > 0 && idx >= treeSize {
		return nil, fmt.Errorf("entry index %d out of bounds for tree size %d", idx, treeSize)
	}
	if treeRoot != ([32]byte{}) && treeSize == 0 {
		return nil, errors.New("cannot verify entry inclusion against tree size 0")
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL %q: %w", baseURL, err)
	}

	bIdx := idx / uint64(layout.EntryBundleWidth)
	offset := int(idx % uint64(layout.EntryBundleWidth))
	p := layout.PartialTileSize(0, bIdx, treeSize)
	isSumDB := strings.Contains(base, "sum.golang.org")

	var candidates []bundleCandidate
	addCandidate := func(rel string, sumDB bool) {
		for _, existing := range candidates {
			if existing.relPath == rel {
				return
			}
		}
		candidates = append(candidates, bundleCandidate{relPath: rel, sumDB: sumDB})
	}

	addSumDBCandidates := func() {
		if p != 0 {
			addCandidate(tlog.Tile{H: 8, L: -1, N: int64(bIdx), W: int(p)}.Path(), true)
		}
		addCandidate(tlog.Tile{H: 8, L: -1, N: int64(bIdx), W: 256}.Path(), true)
	}

	if isSumDB {
		addSumDBCandidates()
	}

	if p != 0 {
		entriesPartial := layout.EntriesPath(bIdx, p)
		addCandidate(entriesPartial, isSumDB)
	}
	entriesFull := layout.EntriesPath(bIdx, 0)
	addCandidate(entriesFull, isSumDB)

	if p != 0 {
		dataPartial := strings.Replace(layout.EntriesPath(bIdx, p), "tile/entries/", "tile/data/", 1)
		addCandidate(dataPartial, isSumDB)
	}
	dataFull := strings.Replace(entriesFull, "tile/entries/", "tile/data/", 1)
	addCandidate(dataFull, isSumDB)

	if !isSumDB {
		addSumDBCandidates()
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	var (
		entry      []byte
		leafHash   []byte
		usedSumDB  bool
		lastErr    error
		foundEntry bool
	)
	for _, cand := range candidates {
		raw, found, fetchErr := readBundleResource(ctx, httpClient, u, cand.relPath)
		if fetchErr != nil {
			lastErr = fetchErr
			continue
		}
		if !found {
			continue
		}
		parsedEntry, parsedHash, parseErr := extractEntryAndHashFromBundle(raw, offset, cand.sumDB, strings.HasPrefix(cand.relPath, "tile/data/"))
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		entry = parsedEntry
		leafHash = parsedHash
		usedSumDB = cand.sumDB
		foundEntry = true
		break
	}

	if !foundEntry {
		if lastErr != nil {
			return nil, fmt.Errorf("failed to fetch entry %d from %s: %w", idx, baseURL, lastErr)
		}
		return nil, fmt.Errorf("entry bundle for index %d not found at %s", idx, baseURL)
	}

	if treeSize > 0 && treeRoot != ([32]byte{}) {
		readTile := func(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
			var tileCandidates []string
			addSumDBTiles := func() {
				w := int(p)
				if w == 0 {
					w = 256
				}
				tileCandidates = append(tileCandidates, tlog.Tile{H: 8, L: int(level), N: int64(index), W: w}.Path())
				if p != 0 {
					tileCandidates = append(tileCandidates, tlog.Tile{H: 8, L: int(level), N: int64(index), W: 256}.Path())
				}
			}
			if usedSumDB {
				addSumDBTiles()
			}
			tileCandidates = append(tileCandidates, layout.TilePath(level, index, p))
			if p != 0 {
				tileCandidates = append(tileCandidates, layout.TilePath(level, index, 0))
			}
			if !usedSumDB {
				addSumDBTiles()
			}
			wantBytes := 256 * 32
			if p != 0 {
				wantBytes = int(p) * 32
			}
			var tileErr error
			for _, tc := range tileCandidates {
				data, ok, err := readBundleResource(ctx, httpClient, u, tc)
				if err != nil {
					tileErr = err
					continue
				}
				if !ok {
					continue
				}
				if len(data) < wantBytes {
					tileErr = fmt.Errorf("tile %s too short: got %d bytes, want at least %d", tc, len(data), wantBytes)
					continue
				}
				if len(data) > wantBytes {
					data = data[:wantBytes]
				}
				return data, nil
			}
			if tileErr != nil {
				return nil, tileErr
			}
			return nil, fmt.Errorf("hash tile level=%d index=%d p=%d not found at %s", level, index, p, baseURL)
		}
		pb, err := tclient.NewProofBuilder(ctx, treeSize, readTile)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize inclusion proof builder for entry %d: %w", idx, err)
		}
		incProof, err := pb.InclusionProof(ctx, idx)
		if err != nil {
			return nil, fmt.Errorf("failed to build inclusion proof for entry %d: %w", idx, err)
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, treeSize, leafHash, incProof, treeRoot[:]); err != nil {
			return nil, fmt.Errorf("entry %d failed Merkle inclusion verification against input root %x: %w", idx, treeRoot, err)
		}
	}

	return entry, nil
}

func readBundleResource(ctx context.Context, httpClient *http.Client, baseURL *url.URL, relPath string) ([]byte, bool, error) {
	if baseURL.Scheme == "" || baseURL.Scheme == "file" {
		root := baseURL.Path
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, false, nil
			}
			return nil, false, err
		}
		return data, true, nil
	}

	targetURL := baseURL.JoinPath(relPath).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "vindex/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP %s for %s", resp.Status, targetURL)
	}
	data, err := readBoundedBody(resp.Body, maxTileResponseBytes)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", targetURL, err)
	}
	return data, true, nil
}

func extractEntryAndHashFromBundle(bundle []byte, offset int, sumDB bool, allowStaticCT bool) ([]byte, []byte, error) {
	if sumDB {
		rest := bundle
		for cur := 0; cur <= offset; cur++ {
			if len(rest) == 0 {
				return nil, nil, fmt.Errorf("entry offset %d out of bounds in sumdb bundle (count %d)", offset, cur)
			}
			var entry, nextRest []byte
			if idx := bytes.Index(rest, []byte("\n\n")); idx >= 0 {
				entry, nextRest = rest[:idx+1], rest[idx+2:]
			} else {
				entry, nextRest = rest, nil
			}
			if cur == offset {
				cloned := bytes.Clone(entry)
				return cloned, rfc6962.DefaultHasher.HashLeaf(cloned), nil
			}
			rest = nextRest
		}
	}

	var staticCTErr error
	if allowStaticCT {
		rest := bundle
		for cur := 0; cur <= offset; cur++ {
			if len(rest) == 0 {
				staticCTErr = fmt.Errorf("entry offset %d out of bounds in static-ct bundle (count %d)", offset, cur)
				break
			}
			leaf, nextRest, err := sunlight.ReadTileLeaf(rest)
			if err != nil {
				staticCTErr = err
				break
			}
			rawLeaf := rest[:len(rest)-len(nextRest)]
			if cur == offset {
				cloned := bytes.Clone(rawLeaf)
				return cloned, rfc6962.DefaultHasher.HashLeaf(leaf.MerkleTreeLeaf()), nil
			}
			rest = nextRest
		}
	}

	var eb api.EntryBundle
	tileErr := eb.UnmarshalText(bundle)
	if tileErr == nil {
		if offset >= len(eb.Entries) {
			tileErr = fmt.Errorf("entry offset %d out of bounds in bundle (count %d)", offset, len(eb.Entries))
		} else {
			cloned := bytes.Clone(eb.Entries[offset])
			return cloned, rfc6962.DefaultHasher.HashLeaf(cloned), nil
		}
	}
	if staticCTErr != nil {
		return nil, nil, fmt.Errorf("failed to parse bundle as static-ct (%v) or tlog-tiles (%w)", staticCTErr, tileErr)
	}
	return nil, nil, tileErr
}
