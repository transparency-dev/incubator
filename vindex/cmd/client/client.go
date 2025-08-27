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
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"slices"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	vindexBaseURL  = flag.String("vindex_base_url", "", "The base URL of the vindex server.")
	inLogBaseURL   = flag.String("in_log_base_url", "", "The base URL of the input log.")
	lookup         = flag.String("lookup", "", "The key to look up in the vindex.")
	outLogPubKey   = flag.String("out_log_pub_key", "", "The public key to use to verify the output log checkpoint. Required.")
	inLogPubKey    = flag.String("in_log_pub_key", "", "The public key to use to verify the input log checkpoint. Required.")
	inLogPubKeyDER = flag.String("in_log_pub_key_der", "", "For CT logs. The public key to use to verify the input log checkpoint. Required, along with in_log_origin.")
	inLogOrigin    = flag.String("in_log_origin", "", "Required if in_log_pub_key_der is used. Otherwise, allows the Input Log Origin string to be configured to something other than the public key name.")
	minIdx         = flag.Uint64("min_idx", 0, "The minimum index to look up in the input log.")
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
	inV := inputLogVerifierFromFlags()
	outV, err := note.NewVerifier(*outLogPubKey)
	if err != nil {
		klog.Exitf("failed to construct output log verifier: %v", err)
	}
	c, err := client.NewVIndexClient(*vindexBaseURL, inV, outV)
	if err != nil {
		klog.Exitf("failed to construct VIndex Client: %v", err)
	}
	return c
}

func newInputLogClientFromFlags() *client.InputLogClient {
	if *inLogBaseURL == "" {
		klog.Exit("in_log_base_url flag must be provided")
	}
	v := inputLogVerifierFromFlags()
	origin := *inLogOrigin
	if len(origin) == 0 {
		origin = v.Name()
	}
	c, err := client.NewInputLogClient(*inLogBaseURL, origin, v, http.DefaultClient)
	if err != nil {
		klog.Exitf("failed to construct Input Log client: %v", err)
	}
	return c
}

func inputLogVerifierFromFlags() note.Verifier {
	if *inLogPubKey == "" && *inLogPubKeyDER == "" {
		klog.Exitf("Must provide exactly one --in_log_pub_key* flag")
	}
	if *inLogPubKey != "" {
		v, err := note.NewVerifier(*inLogPubKey)
		if err != nil {
			klog.Exitf("failed to construct input log verifier: %v", err)
		}
		return v
	}
	derBytes, err := base64.StdEncoding.DecodeString(*inLogPubKeyDER)
	if err != nil {
		klog.Exitf("Error decoding public key: %s", err)
	}
	pub, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		klog.Exitf("Error parsing public key: %v", err)
	}

	verifierKey, err := fnote.RFC6962VerifierString(*inLogOrigin, pub)
	if err != nil {
		klog.Exitf("Error creating RFC6962 verifier string: %v", err)
	}
	v, err := fnote.NewVerifier(verifierKey)
	if err != nil {
		klog.Exitf("Error creating verifier: %v", err)
	}
	return v
}
