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

// client defines a binary that looks up a key in a vindex, verifying all
// proofs. Optionally, it can derefence these indices and fetch verified
// leaf entries from the input log.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/api"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	vindexBaseURL = flag.String("vindex_base_url", "", "The base URL of the vindex server.")
	inLogBaseURL  = flag.String("in_log_base_url", "", "The base URL of the input log.")
	lookup        = flag.String("lookup", "", "The key to look up in the vindex.")
	outLogPubKey  = flag.String("out_log_pub_key", "", "The public key to use to verify the output log checkpoint.")
	inLogPubKey   = flag.String("in_log_pub_key", "", "The public key to use to verify the input log checkpoint.")
	minIdx        = flag.Uint64("min_idx", 0, "The minimum index to look up in the input log.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if err := run(context.Background()); err != nil {
		klog.Exitf("run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	c := newVIndexClientFromFlags()

	if *lookup == "" {
		return errors.New("lookup flag must be provided")
	}

	idxes, err := c.Lookup(ctx, *lookup)
	if err != nil {
		return fmt.Errorf("failed to look up key: %v", err)
	}

	if i := slices.IndexFunc(idxes, func(idx uint64) bool {
		return idx >= *minIdx
	}); i > 0 {
		klog.Infof("Dropping %d pointers to index less than min_idx %d", i, *minIdx)
		idxes = idxes[i:]
	} else if i < 0 {
		klog.Infof("Dropping %d pointers to index less than min_idx %d", len(idxes), *minIdx)
		idxes = []uint64{}
	}
	if len(idxes) == 0 {
		klog.Infof("No values found for key %q", *lookup)
		return nil
	}

	lr, err := NewLeafReaderFromFlags(ctx)
	if err != nil {
		return err
	}

	klog.Infof("Dereferencing %d pointers", len(idxes))
	for _, idx := range idxes {
		leaf, err := lr.getLeaf(ctx, idx)
		if err != nil {
			klog.Errorf("failed to get leaf at index %d: %v", idx, err)
			continue
		}
		fmt.Printf("%d)\n%s\n\n", idx, leaf)
	}

	return nil
}

func newVIndexClientFromFlags() VIndexClient {
	if *vindexBaseURL == "" {
		klog.Exit("vindex_base_url flag must be provided")
	}
	u, err := url.Parse(*vindexBaseURL)
	if err != nil {
		klog.Exitf("failed to parse URL: %v", err)
	}
	lookupURL := u.JoinPath(api.PathLookup)

	if *outLogPubKey == "" {
		klog.Exitf("out_log_pub_key must be provided")
	}
	outV, err := note.NewVerifier(*outLogPubKey)
	if err != nil {
		klog.Exitf("failed to construct output log verifier: %v", err)
	}
	return VIndexClient{
		lookupURL: lookupURL,
		outV:      outV,
	}
}

type VIndexClient struct {
	lookupURL *url.URL
	outV      note.Verifier
}

// Lookup returns all indices, in ascending order, where the given key appears in the Input Log.
// This will be verified before being returned from this method, so a caller can be assured that
// any results (including the empty slice, i.e. non-presence) were found in the verifiable index,
// and committed to by the output log.
//
// Note that it is up to the caller to ensure that any leaves looked up in the Input Log are
// verified by an inclusion proof.
// TODO(mhutchinson): maybe this should return the Input Log Checkpoint that was committed to in
// the Output Log leaf?
func (c VIndexClient) Lookup(ctx context.Context, key string) ([]uint64, error) {
	resp, err := c.lookupUnverified(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("lookup for %q failed: %v", *lookup, err)
	}

	// Currently the response contains the RFC6962 style response type; leaf, proof, etc.
	// What if we flip this all around, and the OutputLog part of the response
	// only returns an index into the output log, and the client has to look up
	// that leaf, checkpoint, and generate inclusion proof?

	cp, _, _, err := log.ParseCheckpoint(resp.OutputLogCP, c.outV.Name(), c.outV)
	if err != nil {
		return nil, fmt.Errorf("failed to parse output log checkpoint: %v", err)
	}
	outLeafHash := rfc6962.DefaultHasher.HashLeaf(resp.OutputLogLeaf)
	olp := make([][]byte, len(resp.OutputLogProof))
	for i := range olp {
		olp[i] = resp.OutputLogProof[i][:]
	}
	oli := cp.Size - 1 // TODO(mhutchinson): include this in the response?
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, oli, cp.Size, outLeafHash[:], olp, cp.Hash); err != nil {
		return nil, fmt.Errorf("failed to verify inclusion in output log: %v", err)
	}
	var mapRoot []byte
	if idx := bytes.Index(resp.OutputLogLeaf, []byte{'\n', '\n'}); idx < 0 {
		return nil, fmt.Errorf("failed to parse output log leaf: %q", resp.OutputLogLeaf)
	} else {
		mapRoot = resp.OutputLogLeaf[:idx]
		mapRoot, err = hex.AppendDecode(nil, mapRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to decode map root: %v", err)
		}
	}

	idxLeafHash := sha256.New()
	for _, idx := range resp.IndexValue {
		if err := binary.Write(idxLeafHash, binary.BigEndian, idx); err != nil {
			return nil, fmt.Errorf("failed to calculate leaf hash for indices: %v", err)
		}
	}
	vindexLeafHash := idxLeafHash.Sum(nil)
	vindexKeyHash := sha256.Sum256([]byte(key))
	// TODO(mhutchinson): verify inclusion in the vindex!
	klog.Warningf("TODO: confirm inclusion of leaf hash %x at key location %x with root hash %x", vindexLeafHash, vindexKeyHash, mapRoot)

	return resp.IndexValue, nil
}

func (c VIndexClient) lookupUnverified(ctx context.Context, key string) (api.LookupResponse, error) {
	var lookupResp api.LookupResponse

	// For now, keys are stored under the hash of the key
	kh := sha256.Sum256([]byte(key))
	u := c.lookupURL.JoinPath(hex.EncodeToString(kh[:]))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to create request: %v", err)
	}

	klog.Infof("Making request to %q", u.String())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to get URL %q: %v", u, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return lookupResp, fmt.Errorf("got non-200 status code: %d", resp.StatusCode)
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

func NewLeafReaderFromFlags(ctx context.Context) (*LeafReader, error) {
	inV, err := note.NewVerifier(*inLogPubKey)
	if err != nil {
		klog.Exitf("failed to construct input log verifier: %v", err)
	}

	if *inLogBaseURL == "" {
		klog.Exit("in_log_base_url flag must be provided")
	}
	u, err := url.Parse(*inLogBaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	c, err := client.NewHTTPFetcher(u, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP fetcher for %q: %v", u, err)
	}

	cpRaw, err := c.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint from input log: %v", err)
	}
	cp, _, _, err := log.ParseCheckpoint(cpRaw, inV.Name(), inV)
	if err != nil {
		klog.Warning(string(cpRaw))
		return nil, fmt.Errorf("failed to parse input log checkpoint: %v", err)
	}
	lr := &LeafReader{
		f:  c.ReadEntryBundle,
		cp: cp,
	}
	return lr, nil
}

// LeafReader reads leaves from the tree.
// This class is not thread safe.
type LeafReader struct {
	f  client.EntryBundleFetcherFunc
	cp *log.Checkpoint
	c  leafBundleCache
}

// getLeaf fetches the raw contents committed to at a given leaf index.
func (r *LeafReader) getLeaf(ctx context.Context, i uint64) ([]byte, error) {
	if i >= r.cp.Size {
		return nil, fmt.Errorf("requested leaf %d >= log size %d", i, r.cp.Size)
	}
	if cached := r.c.get(i); cached != nil {
		klog.V(2).Infof("Using cached result for index %d", i)
		return cached, nil
	}

	// TODO(mhutchinson): Check the inclusion proof of a fetched bundle
	bundle, err := client.GetEntryBundle(ctx, r.f, i/layout.EntryBundleWidth, r.cp.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry bundle: %v", err)
	}
	ti := i % layout.EntryBundleWidth
	r.c = leafBundleCache{
		start:  i - ti,
		leaves: bundle.Entries,
	}
	return r.c.leaves[ti], nil
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
