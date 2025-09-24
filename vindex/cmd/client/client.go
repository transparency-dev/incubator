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
	"errors"
	"flag"
	"fmt"
	"net/http"
	"slices"

	"github.com/transparency-dev/incubator/vindex/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	vindexBaseURL = flag.String("vindex_base_url", "", "The base URL of the vindex server.")
	inLogBaseURL  = flag.String("in_log_base_url", "", "The base URL of the input log.")
	lookup        = flag.String("lookup", "", "The key to look up in the vindex.")
	outLogPubKey  = flag.String("out_log_pub_key", "", "The public key to use to verify the output log checkpoint.")
	inLogPubKey   = flag.String("in_log_pub_key", "", "The public key to use to verify the input log checkpoint.")
	inLogOrigin   = flag.String("in_log_origin", "", "Optional: allows the Input Log Origin string to be configured to something other than the public key name.")
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
	vic := newVIndexClientFromFlags()

	if *lookup == "" {
		return errors.New("lookup flag must be provided")
	}

	idxes, inCp, err := vic.Lookup(ctx, *lookup)
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

	if *inLogBaseURL == "" {
		// Support not providing input log in case a tlog-tiles isn't available (e.g. SumDB).
		klog.Info("in_log_base_url not provided, so cannot dereference pointers")
		for _, idx := range idxes {
			fmt.Printf("%d\n", idx)
		}
		return nil
	}

	lr := newInputLogClientFromFlags()

	klog.V(1).Infof("Dereferencing %d pointers", len(idxes))
	for leaf, err := range lr.Dereference(ctx, inCp, idxes) {
		if err != nil {
			klog.Errorf("failed to get leaf at index %d: %v", leaf.Index, err)
			continue
		}
		fmt.Printf("%d)\n%s\n\n", leaf.Index, leaf.Data)
	}

	return nil
}

func newVIndexClientFromFlags() *client.VIndexClient {
	if *vindexBaseURL == "" {
		klog.Exit("vindex_base_url flag must be provided")
	}
	if *outLogPubKey == "" {
		klog.Exitf("out_log_pub_key must be provided")
	}
	outV, err := note.NewVerifier(*outLogPubKey)
	if err != nil {
		klog.Exitf("failed to construct output log verifier: %v", err)
	}
	c, err := client.NewVIndexClient(*vindexBaseURL, outV)
	if err != nil {
		klog.Exitf("failed to construct VIndex Client: %v", err)
	}
	return c
}

func newInputLogClientFromFlags() *client.InputLogClient {
	if *inLogBaseURL == "" {
		klog.Exit("in_log_base_url flag must be provided")
	}
	if *inLogPubKey == "" {
		klog.Exitf("in_log_pub_key must be provided")
	}
	v, err := note.NewVerifier(*inLogPubKey)
	if err != nil {
		klog.Exitf("failed to construct output log verifier: %v", err)
	}
	origin := *inLogOrigin
	if len(origin) == 0 {
		origin = v.Name()
	}
	c, err := client.NewInputLogClient(*inLogBaseURL, origin, v, http.DefaultClient)
	if err != nil {
		klog.Exitf("failed to construct VIndex Client: %v", err)
	}
	return c
}
