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

// vindex-client is a CLI client for looking up keys in a Verifiable Index with full cryptographic verification.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err := run(ctx, os.Args[1:], os.Stdout)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func resolveTarget(keyFlag, domainFlag string, prefixFlag bool) (target string, isPrefix bool, err error) {
	if domainFlag != "" {
		if keyFlag != "" {
			return "", false, errors.New("cannot combine --domain with --key")
		}
		canon, dErr := client.DomainToCanonicalKey(domainFlag)
		if dErr != nil {
			return "", false, fmt.Errorf("invalid --domain: %w", dErr)
		}
		return canon, prefixFlag, nil
	}
	if keyFlag == "" {
		return "", false, errors.New("must specify --key or --domain")
	}
	return keyFlag, prefixFlag, nil
}

func parseInputLogURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid --input_log_url %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return nil, fmt.Errorf("invalid --input_log_url %q: missing host", raw)
		}
	case "file":
		if (u.Host != "" && u.Host != "localhost") || u.Path == "" {
			return nil, fmt.Errorf("invalid file --input_log_url %q: expected file:///abs/path", raw)
		}
	default:
		return nil, fmt.Errorf("unsupported --input_log_url scheme %q: expected http, https, or file", u.Scheme)
	}
	return u, nil
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vindex-client", flag.ContinueOnError)
	var (
		vindexURL       = fs.String("vindex_url", "http://localhost:8080", "Base URL of the VIndex server.")
		key             = fs.String("key", "", "Canonical key (or prefix when --prefix is set) to search.")
		domain          = fs.String("domain", "", "Domain name (e.g. example.com or *.example.com) converted to a reversed-DNS canonical key (com.example.).")
		prefix          = fs.Bool("prefix", false, "Perform a prefix query (?prefix=<prefix>) for --key or --domain.")
		outputLogPolicy = fs.String("output_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification.")
		outputLogOrigin = fs.String("output_log_origin", "", "Expected origin for Output Log (inferred from --output_log_policy or --output_log_pubkey when unset).")
		outputLogPubKey = fs.String("output_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
		inputLogOrigin  = fs.String("input_log_origin", "", "Expected origin for Input Log (inferred from --input_log_policy or --input_log_pubkey when unset).")
		inputLogPolicy  = fs.String("input_log_policy", "", "Optional C2SP tlog-policy file to verify Input Log checkpoint consistency against VIndex state commitment.")
		inputLogPubKey  = fs.String("input_log_pubkey", "", "Optional public key or key file to verify Input Log checkpoint consistency against VIndex state commitment.")
		inputLogURL     = fs.String("input_log_url", "", "Base URL of Input Log for dereferencing entries or verifying Input Log consistency.")
		maxFrom         = fs.Uint64("max_from", 0, "Maximum acceptable Input Log start index (from) in state commitments.")
		limit           = fs.Uint64("limit", 100, "Maximum newest occurrences to fetch per key unless --all is set.")
		fetchAll        = fs.Bool("all", false, "Fetch all matching indices across all pages.")
		dereference     = fs.Bool("dereference", false, "Dereference and print verified original leaves from Input Log (requires --input_log_url).")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments %v (use --key or --domain)", fs.Args())
	}

	target, isPrefix, err := resolveTarget(*key, *domain, *prefix)
	if err != nil {
		return err
	}
	inURLStr := strings.TrimSpace(*inputLogURL)
	if *dereference && inURLStr == "" {
		return errors.New("--dereference requires --input_log_url")
	}
	var parsedInURL *url.URL
	if inURLStr != "" {
		parsedInURL, err = parseInputLogURL(inURLStr)
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(*outputLogPolicy) == "" && strings.TrimSpace(*outputLogPubKey) == "" {
		return errors.New("must specify --output_log_policy or --output_log_pubkey")
	}
	if strings.TrimSpace(*outputLogPolicy) != "" && strings.TrimSpace(*outputLogPubKey) != "" {
		return errors.New("cannot specify both --output_log_policy and --output_log_pubkey")
	}
	if strings.TrimSpace(*inputLogPolicy) != "" && strings.TrimSpace(*inputLogPubKey) != "" {
		return errors.New("cannot specify both --input_log_policy and --input_log_pubkey")
	}

	var inPolicy wire.Policy
	inOrigin := strings.TrimSpace(*inputLogOrigin)
	if strings.TrimSpace(*inputLogPolicy) != "" || strings.TrimSpace(*inputLogPubKey) != "" {
		if parsedInURL == nil {
			return errors.New("--input_log_policy / --input_log_pubkey requires --input_log_url")
		}
		p, pErr := wire.ParsePolicyOrVerifier(*inputLogPolicy, *inputLogPubKey, inOrigin, nil, 0)
		if pErr != nil {
			return fmt.Errorf("failed to build input log policy: %w", pErr)
		}
		inPolicy = p
		if inOrigin == "" {
			inOrigin = wire.PolicyOrigin(inPolicy)
		}
	}
	if inOrigin == "" {
		return errors.New("--input_log_origin is required")
	}

	outOrigin := strings.TrimSpace(*outputLogOrigin)
	outPolicy, err := wire.ParsePolicyOrVerifier(*outputLogPolicy, *outputLogPubKey, outOrigin, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to build output log policy: %w", err)
	}
	if outOrigin == "" && wire.PolicyOrigin(outPolicy) == "" {
		return errors.New("--output_log_origin is required when --output_log_policy contains multiple logs")
	}

	var limitSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "limit" {
			limitSet = true
		}
	})
	if limitSet && *fetchAll {
		return errors.New("cannot combine --limit with --all")
	}
	if !*fetchAll && *limit == 0 {
		return errors.New("--limit must be >= 1 (or pass --all)")
	}
	maxItems := *limit
	if *fetchAll {
		maxItems = 0
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	cli, err := client.New(*vindexURL, client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  inOrigin,
	}, client.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	var keysResp *client.LookupResult
	if isPrefix {
		keysResp, err = cli.LookupPrefix(ctx, target)
		if err != nil {
			return fmt.Errorf("prefix keys verification failed: %w", err)
		}
	} else {
		keysResp, err = cli.LookupKey(ctx, target)
		if err != nil {
			return fmt.Errorf("key lookup verification failed: %w", err)
		}
	}
	if err := verifyHorizonAndInputConsistency(ctx, httpClient, keysResp, *maxFrom, parsedInURL, inOrigin, inPolicy); err != nil {
		return err
	}

	if isPrefix {
		_, _ = fmt.Fprintf(out, "Prefix:          %s\nMatching Keys:   %d\n", target, len(keysResp.Keys))
		printSnapshotHeader(out, keysResp)
		fetchValues := *fetchAll || *dereference || limitSet
		for _, kv := range keysResp.Keys {
			if !fetchValues {
				_, _ = fmt.Fprintf(out, "  Key: %s ValueRoot: %x\n", kv.Key, kv.ValueRoot)
				continue
			}
			indices, truncated, vErr := collectIndicesAscending(ctx, kv, maxItems)
			if vErr != nil {
				return fmt.Errorf("prefix values verification failed for key %q: %w", kv.Key, vErr)
			}
			_, _ = fmt.Fprintf(out, "  Key %s (%x): %d occurrences %v\n", kv.Key, kv.ValueRoot, len(indices), indices)
			if truncated {
				_, _ = fmt.Fprintf(out, "    (truncated to newest %d occurrences; pass --all to fetch remaining pages)\n", maxItems)
			}
			if *dereference {
				if err := dereferenceIndices(ctx, out, httpClient, inURLStr, indices, keysResp.InputSize, keysResp.InputRoot); err != nil {
					return err
				}
			}
		}
		return nil
	}

	exists := len(keysResp.Keys) > 0
	_, _ = fmt.Fprintf(out, "Key:             %s\nExists:          %v\n", target, exists)
	printSnapshotHeader(out, keysResp)
	if !exists {
		_, _ = fmt.Fprintf(out, "No occurrences found in Input Log range [%d, %d) (cryptographically verified non-inclusion).\n", keysResp.From, keysResp.InputSize)
		return nil
	}

	mk := keysResp.Keys[0]
	_, _ = fmt.Fprintf(out, "Value Root:      %x\n", mk.ValueRoot)
	indices, truncated, err := collectIndicesAscending(ctx, mk, maxItems)
	if err != nil {
		return fmt.Errorf("values lookup verification failed: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Found %d verified occurrences:\n", len(indices))
	for _, idx := range indices {
		_, _ = fmt.Fprintf(out, "  Index: %d\n", idx)
	}
	if truncated {
		_, _ = fmt.Fprintf(out, "  (showing newest %d occurrences; pass --all to fetch remaining pages)\n", maxItems)
	}
	if *dereference {
		return dereferenceIndices(ctx, out, httpClient, inURLStr, indices, keysResp.InputSize, keysResp.InputRoot)
	}
	return nil
}

func printSnapshotHeader(out io.Writer, r *client.LookupResult) {
	_, _ = fmt.Fprintf(out, "MPT Root:        %x\nOutput Log Size: %d\nInput Origin:    %s\nInput Log From:  %d\nInput Log Size:  %d\n",
		r.MPTRoot, r.OutputSize, r.InputOrigin, r.From, r.InputSize)
}

func collectIndicesAscending(ctx context.Context, mk client.MatchedKey, maxItems uint64) ([]uint64, bool, error) {
	var indices []uint64
	truncated := false
	for idx, vErr := range mk.Values(ctx) {
		if vErr != nil {
			return nil, false, vErr
		}
		if maxItems > 0 && uint64(len(indices)) >= maxItems {
			truncated = true
			break
		}
		indices = append(indices, idx)
	}
	slices.Reverse(indices)
	return indices, truncated, nil
}

func verifyHorizonAndInputConsistency(
	ctx context.Context,
	httpClient *http.Client,
	res *client.LookupResult,
	maxFrom uint64,
	inURL *url.URL,
	inOrigin string,
	inPolicy wire.Policy,
) error {
	if res.From > maxFrom {
		return fmt.Errorf("index starts at from=%d, exceeding --max_from=%d", res.From, maxFrom)
	}
	if inPolicy == nil {
		return nil
	}
	u := *inURL
	if u.Scheme != "file" && !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	tf, err := ingest.NewTiledFetcher(&u, nil, inOrigin, httpClient)
	if err != nil {
		return fmt.Errorf("failed to initialize Input Log fetcher: %w", err)
	}
	tf.SetPolicy(inPolicy)
	inCP, err := tf.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to verify signed Input Log checkpoint: %w", err)
	}
	if inCP.Origin != inOrigin {
		return fmt.Errorf("input log checkpoint origin %q != expected %q", inCP.Origin, inOrigin)
	}
	if inCP.Size == 0 && inCP.Hash != wire.EmptyRoot() {
		return fmt.Errorf("input log size-0 checkpoint has non-empty root %x", inCP.Hash)
	}
	if res.InputSize > inCP.Size {
		return fmt.Errorf("VIndex committed input-size %d exceeds signed Input Log checkpoint size %d", res.InputSize, inCP.Size)
	}
	switch res.InputSize {
	case 0:
		return nil
	case inCP.Size:
		if res.InputRoot != inCP.Hash {
			return fmt.Errorf("input log split-view at size %d: VIndex committed %x, Input Log signed %x", res.InputSize, res.InputRoot, inCP.Hash)
		}
	default:
		cProof, err := tf.ConsistencyProof(ctx, res.InputSize, inCP.Size)
		if err != nil {
			return fmt.Errorf("failed to fetch Input Log consistency proof (%d -> %d): %w", res.InputSize, inCP.Size, err)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, res.InputSize, inCP.Size, cProof, res.InputRoot[:], inCP.Hash[:]); err != nil {
			return fmt.Errorf("input log consistency proof (%d -> %d) failed: %w", res.InputSize, inCP.Size, err)
		}
	}
	return nil
}

func formatSafeLeaf(data []byte) string {
	trimmed := bytes.TrimRight(data, "\r\n")
	if !utf8.Valid(trimmed) {
		return fmt.Sprintf("<binary %d bytes: %s>", len(data), hex.EncodeToString(data[:min(len(data), 64)]))
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range string(trimmed) {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			fmt.Fprintf(&b, "\\x%02x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func dereferenceIndices(ctx context.Context, out io.Writer, httpClient *http.Client, baseURL string, indices []uint64, treeSize uint64, treeRoot [32]byte) error {
	_, _ = fmt.Fprintln(out, "\nDereferencing verified leaves from Input Log:")
	for _, idx := range indices {
		data, err := ingest.FetchVerifiedEntryByIndex(ctx, httpClient, baseURL, idx, treeSize, treeRoot)
		if err != nil {
			return fmt.Errorf("failed to dereference and verify leaf at index %d: %w", idx, err)
		}
		_, _ = fmt.Fprintf(out, "  [%d]: %s\n", idx, formatSafeLeaf(data))
	}
	return nil
}
