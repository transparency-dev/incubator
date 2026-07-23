// Copyright 2025 Google LLC. All Rights Reserved.
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

// client contains a library for interacting with a Verifiable Index.
package client

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/api"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
	"filippo.io/torchwood/mpt"
)

func VerifyLookupResponse(keyHash [sha256.Size]byte, resp api.LookupResponse, inV, outV note.Verifier, inLogOrigin string) ([]uint64, []byte, error) {
	// Currently the response contains the RFC6962 style response type; leaf, proof, etc.
	// What if we flip this all around, and the OutputLog part of the response
	// only returns an index into the output log, and the client has to look up
	// that leaf, checkpoint, and generate inclusion proof?

	olcp, _, _, err := log.ParseCheckpoint(resp.OutputLogCP, outV.Name(), outV)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse output log checkpoint: %v", err)
	}
	outLeafHash := rfc6962.DefaultHasher.HashLeaf(resp.OutputLogLeaf)
	olp := make([][]byte, len(resp.OutputLogProof))
	for i := range olp {
		olp[i] = resp.OutputLogProof[i][:]
	}
	oli := olcp.Size - 1 // TODO(mhutchinson): include this in the response?
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, oli, olcp.Size, outLeafHash[:], olp, olcp.Hash); err != nil {
		return nil, nil, fmt.Errorf("failed to verify inclusion in output log: %v", err)
	}

	mapRoot, inCp, err := vindex.UnmarshalLeaf(resp.OutputLogLeaf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal output log leaf: %v", err)
	}

	idxLeafHash := sha256.New()
	for _, idx := range resp.IndexValue {
		if err := binary.Write(idxLeafHash, binary.BigEndian, idx); err != nil {
			return nil, nil, fmt.Errorf("failed to calculate leaf hash for indices: %v", err)
		}
	}
	vindexLeafHash := idxLeafHash.Sum(nil)

	origin := inLogOrigin
	if origin == "" {
		origin = inV.Name()
	}
	ilcp, _, _, err := log.ParseCheckpoint(inCp, origin, inV)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse input log checkpoint: %v", err)
	}

	expectFound := len(resp.IndexValue) > 0
	var val []byte
	if expectFound {
		val = vindexLeafHash
	}

	snap := mpt.Snapshot{
		Version: int64(ilcp.Size),
		Hash:    mapRoot,
	}
	if err := mpt.Verify(snap, keyHash[:], val, expectFound, resp.IndexProof); err != nil {
		return nil, nil, fmt.Errorf("mpt.Verify(): %v", err)
	}

	return resp.IndexValue, inCp, nil
}

// NewVIndexClient returns a client that can perform verified lookups into the index at the
// given base URL, using the supplied verifier to check checkpoint signatures on the output
// log.
func NewVIndexClient(vindexUrl string, inV, outV note.Verifier) (*VIndexClient, error) {
	return NewVIndexClientWithOrigin(vindexUrl, inV, outV, "")
}

// NewVIndexClientWithOrigin returns a client that can perform verified lookups into the index
// at the given base URL, using the supplied verifier to check checkpoint signatures on the
// output log, and the supplied origin to verify the input log checkpoint.
func NewVIndexClientWithOrigin(vindexUrl string, inV, outV note.Verifier, inLogOrigin string) (*VIndexClient, error) {
	viu, err := url.Parse(vindexUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	lookupURL := viu.JoinPath(api.PathLookup)

	return &VIndexClient{
		lookupURL:   lookupURL,
		inV:         inV,
		outV:        outV,
		inLogOrigin: inLogOrigin,
	}, nil
}

// VIndexClient allows verified lookups into a verifiable index.
type VIndexClient struct {
	lookupURL   *url.URL
	inV, outV   note.Verifier
	inLogOrigin string
}

// Lookup returns all indices, in ascending order, where the given key appears in the Input Log.
// This will be verified before being returned from this method, so a caller can be assured that
// any results (including the empty slice, i.e. non-presence) were found in the verifiable index,
// and committed to by the output log.
// On success, this also returns the Checkpoint for the Input Log that was relied upon by the
// verifiable index. This may be used by the caller when constructing inclusion proofs when
// dereferencing any pointers returned.
//
// Note that it is up to the caller to ensure that any leaves looked up in the Input Log are
// verified by an inclusion proof. The checkpoint returned by this method can be used.
// The easiest way to do this is to use the InputLogClient.
func (c VIndexClient) Lookup(ctx context.Context, key string) ([]uint64, []byte, error) {
	kh := sha256.Sum256([]byte(key))
	resp, err := c.lookupUnverified(ctx, kh)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup failed: %v", err)
	}

	return VerifyLookupResponse(kh, resp, c.inV, c.outV, c.inLogOrigin)
}

func (c VIndexClient) lookupUnverified(ctx context.Context, kh [sha256.Size]byte) (api.LookupResponse, error) {
	var lookupResp api.LookupResponse

	// For now, keys are stored under the hash of the key
	u := c.lookupURL.JoinPath(hex.EncodeToString(kh[:]))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to create request: %v", err)
	}

	klog.V(1).Infof("Making request to %q", u.String())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to get URL %q: %v", u, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return lookupResp, fmt.Errorf("got non-200 status code: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to read response body: %v", err)
	}

	if err := json.Unmarshal(body, &lookupResp); err != nil {
		return lookupResp, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return lookupResp, nil
}

// NewInputLogClient returns a client that allows pointers returned from the Verifiable Index
// to be dereferenced by looking up entries in the Input Log. All operations are verified by this
// client, which closes the loop.
func NewInputLogClient(inLogUrl string, origin string, inV note.Verifier, hc *http.Client) (*InputLogClient, error) {
	u, err := url.Parse(inLogUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	c, err := client.NewHTTPFetcher(u, hc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP fetcher for %q: %v", u, err)
	}
	return &InputLogClient{
		v:      inV,
		origin: origin,
		lc:     c,
	}, nil
}

// InputLogClient is a client intended to be used by users of the VIndexClient that want
// to look up the original leaves from the Input Log.
type InputLogClient struct {
	v      note.Verifier
	origin string
	lc     logClient
}

// Dereference takes pointers returned by the VIndexClient Lookup method, and fetches
// the original leaves from the Input Log. The inclusion of any leaves returned will be
// verified by constructing inclusion proofs to the checkpoint provided.
func (c *InputLogClient) Dereference(ctx context.Context, cpRaw []byte, pointers []uint64) iter.Seq2[InputLogLeaf, error] {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, c.origin, c.v)
	if err != nil {
		return func(yield func(InputLogLeaf, error) bool) {
			yield(InputLogLeaf{}, fmt.Errorf("failed to parse input log checkpoint: %v", err))
		}
	}
	pb, err := client.NewProofBuilder(ctx, cp.Size, c.lc.ReadTile)
	if err != nil {
		return func(yield func(InputLogLeaf, error) bool) {
			yield(InputLogLeaf{}, fmt.Errorf("failed to parse input log checkpoint: %v", err))
		}
	}
	return func(yield func(InputLogLeaf, error) bool) {
		var cache leafBundleCache
		for _, i := range pointers {
			if i >= cp.Size {
				yield(InputLogLeaf{}, fmt.Errorf("requested leaf %d >= log size %d", i, cp.Size))
				return
			}
			ip, err := pb.InclusionProof(ctx, i)
			if err != nil {
				yield(InputLogLeaf{}, fmt.Errorf("failed to get inclusion proof: %v", err))
				return
			}

			var entry []byte
			if entry = cache.get(i); entry == nil {
				bundle, err := client.GetEntryBundle(ctx, c.lc.ReadEntryBundle, i/layout.EntryBundleWidth, cp.Size)
				if err != nil {
					yield(InputLogLeaf{}, fmt.Errorf("failed to get entry bundle: %v", err))
					return
				}

				// Store the bundle in a cache in case the next index is in the same bundle.
				ti := i % layout.EntryBundleWidth
				cache = leafBundleCache{
					start:  i - ti,
					leaves: bundle.Entries,
				}
				entry = cache.leaves[ti]
			}

			lh := rfc6962.DefaultHasher.HashLeaf(entry)
			if err := proof.VerifyInclusion(rfc6962.DefaultHasher, i, cp.Size, lh, ip, cp.Hash); err != nil {
				yield(InputLogLeaf{}, fmt.Errorf("failed to verify inclusion proof: %v", err))
				return
			}

			if !yield(InputLogLeaf{i, entry}, nil) {
				return
			}
		}
	}
}

// InputLogLeaf is an entry in the Input Log.
type InputLogLeaf struct {
	Index uint64
	Data  []byte
}

// leafBundleCache stores the results of the last fetched tile. Assuming that the client
// accesses leaves in order, then this avoids fetching the same bundle multiple times if
// multiple leaves are in the same bundle.
type leafBundleCache struct {
	start  uint64
	leaves [][]byte
}

func (tc leafBundleCache) get(i uint64) []byte {
	end := tc.start + uint64(len(tc.leaves))
	if i >= tc.start && i < end {
		leaf := tc.leaves[i-tc.start]
		return leaf
	}
	return nil
}

// logClient describes what we need from a log client.
type logClient interface {
	ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error)
	ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error)
}
