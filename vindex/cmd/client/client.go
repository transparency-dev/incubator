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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/transparency-dev/incubator/vindex/api"
	"k8s.io/klog/v2"
)

var (
	baseURL = flag.String("base_url", "", "The base URL of the vindex server.")
	lookup  = flag.String("lookup", "", "The key to look up in the vindex.")
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
		return errors.New("key flag must be provided")
	}

	resp, err := c.Lookup(ctx, *lookup)
	if err != nil {
		return fmt.Errorf("lookup for %q failed: %v", *lookup, err)
	}

	// For now, pretty print the JSON response
	jsonResp, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %v", err)
	}
	fmt.Println(string(jsonResp))

	// This needs to verify the proofs in the response.
	// We can't verify inclusion with the info we currently have.
	// We at least need the index of the leaf returned. We could add
	// that to the response object, but this is kinda rfc6962.
	// What would it look like if the output log is tiled? What should
	// the lookup response contain? Can it contain less, and thus put
	// more on the client as per tlog-tiles? If so, what stops clients
	// requesting old views of the index based on non-recent leaves from
	// the output log?
	// What if we flip this all around, and the OutputLog part of the response
	// only returns an index into the output log, and the client has to look up
	// that leaf, checkpoint, and generate inclusion proof?

	// proof.VerifyInclusion()

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
	return VIndexClient{
		lookupURL: lookupURL,
	}
}

type VIndexClient struct {
	lookupURL *url.URL
}

func (c VIndexClient) Lookup(ctx context.Context, key string) (api.LookupResponse, error) {
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
