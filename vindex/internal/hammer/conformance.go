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

package hammer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
)

type httpProbeSpec struct {
	name       string
	path       string
	rawQuery   string
	wantStatus int
}

func newNoRedirectHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("HTTP redirects (3xx) are forbidden by tlog-vindex spec (redirected to %q)", req.URL.String())
		},
	}
}

func probeHTTPStatus(ctx context.Context, base *url.URL, hc *http.Client, routePath, rawQuery string) (int, error) {
	u := *base
	u.Path = strings.TrimSuffix(u.Path, "/") + routePath
	u.RawPath = ""
	u.RawQuery = rawQuery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// runHTTPConformanceProbes checks mandatory HTTP status-code behaviors specified in c2sp.org/tlog-vindex.
func runHTTPConformanceProbes(ctx context.Context, rawBaseURL string, hc *http.Client) []string {
	base, err := url.Parse(rawBaseURL)
	if err != nil {
		return []string{fmt.Sprintf("ConformanceError: invalid base URL %q: %v", rawBaseURL, err)}
	}
	overlongKey := strings.Repeat("a", 1025)
	probes := []httpProbeSpec{
		{name: "keys_missing_params", path: "/keys", rawQuery: "", wantStatus: http.StatusBadRequest},
		{name: "keys_both_key_and_prefix", path: "/keys", rawQuery: "key=alpha&prefix=alpha", wantStatus: http.StatusBadRequest},
		{name: "keys_empty_key", path: "/keys", rawQuery: "key=", wantStatus: http.StatusBadRequest},
		{name: "keys_space_in_key", path: "/keys", rawQuery: "key=bad%20space", wantStatus: http.StatusBadRequest},
		{name: "keys_nul_in_key", path: "/keys", rawQuery: "key=bad%00nul", wantStatus: http.StatusBadRequest},
		{name: "keys_overlong_key", path: "/keys", rawQuery: "key=" + overlongKey, wantStatus: http.StatusBadRequest},
		{name: "values_missing_key", path: "/values", rawQuery: "before=1", wantStatus: http.StatusBadRequest},
		{name: "values_missing_before", path: "/values", rawQuery: "key=alpha", wantStatus: http.StatusBadRequest},
		{name: "values_zero_before", path: "/values", rawQuery: "key=alpha&before=0", wantStatus: http.StatusBadRequest},
		{name: "values_leading_zero_before", path: "/values", rawQuery: "key=alpha&before=01", wantStatus: http.StatusBadRequest},
		{name: "values_future_before", path: "/values", rawQuery: "key=alpha&before=" + strconv.FormatUint(math.MaxUint64, 10), wantStatus: http.StatusServiceUnavailable},
	}

	var violations []string
	for _, pr := range probes {
		if ctx.Err() != nil {
			return violations
		}
		got, pErr := probeHTTPStatus(ctx, base, hc, pr.path, pr.rawQuery)
		if pErr != nil {
			violations = append(violations, fmt.Sprintf("HTTPConformanceViolation [%s]: request failed: %v", pr.name, pErr))
			continue
		}
		if got != pr.wantStatus {
			violations = append(violations, fmt.Sprintf("HTTPConformanceViolation [%s]: GET %s?%s returned HTTP %d, want %d",
				pr.name, pr.path, pr.rawQuery, got, pr.wantStatus))
		}
	}
	return violations
}

func probeValuesNotFound(ctx context.Context, rawBaseURL string, hc *http.Client, nonIncKey string, before uint64) string {
	base, err := url.Parse(rawBaseURL)
	if err != nil {
		return fmt.Sprintf("HTTPConformanceViolation [values_not_found]: invalid base URL %q: %v", rawBaseURL, err)
	}
	rawQuery := "key=" + wire.PercentEncodeCanonicalKey(nonIncKey) + "&before=" + strconv.FormatUint(before, 10)
	got, pErr := probeHTTPStatus(ctx, base, hc, "/values", rawQuery)
	if pErr != nil {
		if ctx.Err() != nil {
			return ""
		}
		return fmt.Sprintf("HTTPConformanceViolation [values_not_found]: request failed: %v", pErr)
	}
	if got != http.StatusNotFound {
		return fmt.Sprintf("HTTPConformanceViolation [values_not_found]: GET /values?%s returned HTTP %d, want 404", rawQuery, got)
	}
	return ""
}

// OutputLogVerifier polls <output-log-url>/checkpoint and /tile/entries/... to verify
// C2SP tlog-tiles and tlog-vindex Output Log conformance.
type OutputLogVerifier struct {
	fetcher       *tclient.HTTPFetcher
	outOrigin     string
	outPolicy     client.CheckpointPolicy
	inOrigin      string
	oracle        *Oracle
	onHorizon     func(uint64)
	onViolation   func(string, ...any)
	hasFrom       bool
	verifiedFrom  uint64
	prevOutSize   uint64
	verifiedSize  atomic.Uint64
	prevOutRoot   [sha256.Size]byte
	prevInputSize uint64
}

// NewOutputLogVerifier constructs a standalone OutputLogVerifier (usable with or without ReaderPool).
func NewOutputLogVerifier(
	rawURL, outOrigin string,
	outPolicy client.CheckpointPolicy,
	inOrigin string,
	oracle *Oracle,
	timeout time.Duration,
	analyzer *Analyzer,
) (*OutputLogVerifier, error) {
	if outPolicy == nil {
		return nil, fmt.Errorf("OutputLogPolicy is required")
	}
	resolvedOutOrigin := strings.TrimSpace(outOrigin)
	if resolvedOutOrigin == "" {
		if op, ok := outPolicy.(interface{ Origin() string }); ok {
			resolvedOutOrigin = op.Origin()
		}
	}
	if err := wire.ValidateInputOrigin(resolvedOutOrigin); err != nil {
		return nil, fmt.Errorf("invalid output_log_origin: %w", err)
	}
	if err := wire.ValidateInputOrigin(inOrigin); err != nil {
		return nil, fmt.Errorf("invalid input_log_origin: %w", err)
	}
	onViolation := func(format string, args ...any) {
		if analyzer != nil {
			analyzer.RecordInvariantViolation(fmt.Sprintf(format, args...))
		}
	}
	return newOutputLogVerifier(rawURL, resolvedOutOrigin, outPolicy, inOrigin, oracle, newNoRedirectHTTPClient(timeout), nil, onViolation)
}

// VerifiedSize returns the highest verified Output Log tree size observed so far.
func (v *OutputLogVerifier) VerifiedSize() uint64 {
	return v.verifiedSize.Load()
}

// Run polls the Output Log periodically until ctx is cancelled, performing one final check on shutdown.
func (v *OutputLogVerifier) Run(ctx context.Context, interval time.Duration) {
	v.run(ctx, interval)
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	v.checkOnce(checkCtx)
}

func newOutputLogVerifier(
	rawURL, outOrigin string,
	outPolicy client.CheckpointPolicy,
	inOrigin string,
	oracle *Oracle,
	hc *http.Client,
	onHorizon func(uint64),
	onViolation func(string, ...any),
) (*OutputLogVerifier, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid output_log_url %q: %w", rawURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("output_log_url %q must use http or https with a non-empty host", rawURL)
	}
	fetcher, err := tclient.NewHTTPFetcher(u, hc)
	if err != nil {
		return nil, fmt.Errorf("failed to create output log HTTP fetcher: %w", err)
	}
	return &OutputLogVerifier{
		fetcher:     fetcher,
		outOrigin:   outOrigin,
		outPolicy:   outPolicy,
		inOrigin:    inOrigin,
		oracle:      oracle,
		onHorizon:   onHorizon,
		onViolation: onViolation,
	}, nil
}

func (v *OutputLogVerifier) checkOnce(ctx context.Context) {
	rawCP, err := v.fetcher.ReadCheckpoint(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		// Transient 503/404 before first checkpoint is published is handled by readiness; after prevOutSize > 0 it is a violation.
		if v.prevOutSize > 0 {
			v.onViolation("OutputLogViolation: failed to fetch /checkpoint after size %d: %v", v.prevOutSize, err)
		}
		return
	}

	cp, err := v.outPolicy.Verify(rawCP)
	if err != nil {
		v.onViolation("OutputLogViolation: /checkpoint verification failed: %v", err)
		return
	}
	if cp.Origin != v.outOrigin {
		v.onViolation("OutputLogViolation: /checkpoint origin %q != expected %q", cp.Origin, v.outOrigin)
		return
	}
	if cp.Size < v.prevOutSize {
		v.onViolation("OutputLogViolation: output log tree size regressed from %d to %d", v.prevOutSize, cp.Size)
		return
	}
	if cp.Size == 0 {
		emptyRoot := wire.EmptyRoot()
		if !bytes.Equal(cp.Hash, emptyRoot[:]) {
			v.onViolation("OutputLogViolation: non-empty root hash at output log size 0")
		}
		return
	}
	if cp.Size == v.prevOutSize {
		if !bytes.Equal(cp.Hash, v.prevOutRoot[:]) {
			v.onViolation("OutputLogViolation: split-view root hash at output log size %d", cp.Size)
		}
		return
	}

	pb, err := tclient.NewProofBuilder(ctx, cp.Size, v.fetcher.ReadTile)
	if err != nil {
		if ctx.Err() == nil {
			v.onViolation("OutputLogViolation: failed to initialize tile proof builder at size %d: %v", cp.Size, err)
		}
		return
	}

	if v.prevOutSize > 0 {
		consProof, cErr := pb.ConsistencyProof(ctx, v.prevOutSize, cp.Size)
		if cErr != nil {
			if ctx.Err() == nil {
				v.onViolation("OutputLogViolation: failed to build consistency proof (%d -> %d): %v", v.prevOutSize, cp.Size, cErr)
			}
			return
		}
		if vErr := proof.VerifyConsistency(rfc6962.DefaultHasher, v.prevOutSize, cp.Size, consProof, v.prevOutRoot[:], cp.Hash); vErr != nil {
			v.onViolation("OutputLogViolation: consistency proof invalid (%d -> %d): %v", v.prevOutSize, cp.Size, vErr)
			return
		}
	}

	nextInputSize := v.prevInputSize
	nextHasFrom := v.hasFrom
	nextFrom := v.verifiedFrom
	startBundle := v.prevOutSize / layout.EntryBundleWidth
	endBundle := (cp.Size - 1) / layout.EntryBundleWidth
	for bIdx := startBundle; bIdx <= endBundle; bIdx++ {
		bundle, bErr := tclient.GetEntryBundle(ctx, v.fetcher.ReadEntryBundle, bIdx, cp.Size)
		if bErr != nil {
			if ctx.Err() == nil {
				v.onViolation("OutputLogViolation: failed to fetch entry bundle %d at size %d: %v", bIdx, cp.Size, bErr)
			}
			return
		}
		baseIdx := bIdx * layout.EntryBundleWidth
		for offset, rawEntry := range bundle.Entries {
			entryIdx := baseIdx + uint64(offset)
			if entryIdx < v.prevOutSize {
				continue
			}
			if entryIdx >= cp.Size {
				break
			}

			incProof, iErr := pb.InclusionProof(ctx, entryIdx)
			if iErr != nil {
				if ctx.Err() == nil {
					v.onViolation("OutputLogViolation: failed to build inclusion proof for entry %d: %v", entryIdx, iErr)
				}
				return
			}
			leafHash := rfc6962.DefaultHasher.HashLeaf(rawEntry)
			if vErr := proof.VerifyInclusion(rfc6962.DefaultHasher, entryIdx, cp.Size, leafHash, incProof, cp.Hash); vErr != nil {
				v.onViolation("OutputLogViolation: entry %d failed Merkle authentication against output checkpoint: %v", entryIdx, vErr)
				return
			}

			parsed, pErr := wire.ParseOutputLogLeafFull(rawEntry)
			if pErr != nil {
				v.onViolation("OutputLogViolation: entry %d malformed tlog-vindex-state@v1: %v", entryIdx, pErr)
				return
			}
			if parsed.InputOrigin != v.inOrigin {
				v.onViolation("OutputLogViolation: entry %d input-origin %q != expected %q", entryIdx, parsed.InputOrigin, v.inOrigin)
				return
			}
			if v.onHorizon != nil {
				v.onHorizon(parsed.From)
			} else if !nextHasFrom {
				nextHasFrom = true
				nextFrom = parsed.From
			} else if parsed.From != nextFrom {
				v.onViolation("OutputLogViolation: entry %d from changed (%d -> %d)", entryIdx, nextFrom, parsed.From)
				return
			}
			if parsed.InputSize == parsed.From && parsed.MPTRoot != wire.EmptyRoot() {
				v.onViolation("OutputLogViolation: entry %d non-empty mpt-root when input-size (%d) == from (%d)", entryIdx, parsed.InputSize, parsed.From)
				return
			}
			if parsed.InputSize < nextInputSize {
				v.onViolation("OutputLogViolation: entry %d input-size regressed (%d -> %d)", entryIdx, nextInputSize, parsed.InputSize)
				return
			}
			if v.oracle != nil {
				if sErr := v.oracle.VerifyInputState(ctx, parsed.InputSize, parsed.InputRoot); sErr != nil {
					if ctx.Err() == nil {
						v.onViolation("OutputLogViolation: entry %d invalid input state: %v", entryIdx, sErr)
					}
					return
				}
			}
			nextInputSize = parsed.InputSize
		}
	}

	v.hasFrom = nextHasFrom
	v.verifiedFrom = nextFrom
	v.prevInputSize = nextInputSize
	v.prevOutSize = cp.Size
	v.verifiedSize.Store(cp.Size)
	copy(v.prevOutRoot[:], cp.Hash)
}

func (v *OutputLogVerifier) run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	v.checkOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.checkOnce(ctx)
		}
	}
}
