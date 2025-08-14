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

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/api"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	baseURL      = flag.String("base_url", "", "The base URL of the vindex server.")
	lookup       = flag.String("lookup", "", "The key to look up in the vindex.")
	outLogPubKey = flag.String("out_log_pub_key", "", "The public key to use to verify the output log checkpoint.")
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

	fmt.Printf("Indices: %v", idxes)

	return nil
}

func newVIndexClientFromFlags() VIndexClient {
	if *baseURL == "" {
		klog.Exit("base_url flag must be provided")
	}
	u, err := url.Parse(*baseURL)
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
	old := make([][]byte, len(resp.OutputLogProof))
	for i := range old {
		old[i] = resp.OutputLogProof[i][:]
	}
	oli := cp.Size - 1 // TODO(mhutchinson): include this in the response?
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, oli, cp.Size, outLeafHash[:], old, cp.Hash); err != nil {
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
