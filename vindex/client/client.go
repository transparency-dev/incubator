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

// Package client provides a lightweight verification library and HTTP client for VIndex.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"iter"
	"math/bits"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/idna"
)

// CheckpointPolicy verifies a signed checkpoint (primary log signature plus optional witness quorum).
type CheckpointPolicy interface {
	Verify(checkpoint []byte) (*log.Checkpoint, error)
}

var (
	ErrVerificationFailed = errors.New("vindex: verification failed")
	ErrBadRequest         = errors.New("vindex: bad request")
	ErrTooManyKeys        = errors.New("vindex: prefix matched too many keys")
	ErrUnavailable        = errors.New("vindex: server unavailable")
)

const (
	maxResponseBodyBytes = 32 << 20 // 32 MiB
	maxErrorBodyBytes    = 4 << 10  // 4 KiB
	defaultHTTPTimeout   = 30 * time.Second
)

func isDNSLabelByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

// DomainToCanonicalKey converts a forward DNS name (such as "example.com", "*.example.com",
// or IDN "bücher.example.com") into its reversed-DNS canonical key with a trailing dot
// ("com.example.", "com.example.*.", or "com.example.xn--bcher-kva."), matching the ct and mtc MapFns.
func DomainToCanonicalKey(domain string) (string, error) {
	d := strings.Trim(domain, " \t\r\n")
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("%w: empty domain", ErrBadRequest)
	}

	hasWildcard := false
	if strings.HasPrefix(d, "*.") {
		hasWildcard = true
		d = d[2:]
	} else if strings.HasPrefix(d, "*") {
		return "", fmt.Errorf("%w: wildcard '*' is only valid as leftmost label in %q", ErrBadRequest, domain)
	}
	if d == "" {
		return "", fmt.Errorf("%w: empty base domain in %q", ErrBadRequest, domain)
	}

	hasNonASCII := false
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c <= 0x20 || c == ':' || c == '/' || c == '@' || c == '*' || c == 0x7f {
			return "", fmt.Errorf("%w: invalid DNS character in %q", ErrBadRequest, domain)
		}
		if c >= 0x80 {
			hasNonASCII = true
		}
	}
	if hasNonASCII {
		ascii, err := idna.Lookup.ToASCII(d)
		if err != nil || ascii == "" {
			return "", fmt.Errorf("%w: invalid internationalized domain %q: %v", ErrBadRequest, domain, err)
		}
		d = strings.TrimSuffix(ascii, ".")
		if d == "" {
			return "", fmt.Errorf("%w: empty domain %q", ErrBadRequest, domain)
		}
	}

	totalLen := len(d)
	if hasWildcard {
		totalLen += 2
	}
	if totalLen > 253 {
		return "", fmt.Errorf("%w: domain %q exceeds 253 bytes", ErrBadRequest, domain)
	}

	buf := make([]byte, len(d))
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= 0x80 {
			return "", fmt.Errorf("%w: non-ASCII byte in domain %q", ErrBadRequest, domain)
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}

	labels := strings.Split(string(buf), ".")
	for _, lbl := range labels {
		if lbl == "" || len(lbl) > 63 {
			return "", fmt.Errorf("%w: empty or overlong DNS label in %q", ErrBadRequest, domain)
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return "", fmt.Errorf("%w: leading or trailing hyphen in DNS label %q", ErrBadRequest, domain)
		}
		for j := 0; j < len(lbl); j++ {
			if !isDNSLabelByte(lbl[j]) {
				return "", fmt.Errorf("%w: invalid DNS label character %q in %q", ErrBadRequest, lbl[j], domain)
			}
		}
	}

	var b strings.Builder
	b.Grow(totalLen + 1)
	for i := len(labels) - 1; i >= 0; i-- {
		b.WriteString(labels[i])
		b.WriteByte('.')
	}
	if hasWildcard {
		b.WriteString("*.")
	}
	out := b.String()
	if err := mpt.ValidateCanonicalKey([]byte(out)); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBadRequest, err)
	}
	return out, nil
}

// Config holds the Output Log verification policy and expected log origins for a VIndex Client.
type Config struct {
	ExpectedOutputLogOrigin string
	OutputLogPolicy         CheckpointPolicy
	ExpectedInputLogOrigin  string
}

func resolveConfig(cfg Config) (Config, error) {
	if cfg.OutputLogPolicy == nil {
		return cfg, fmt.Errorf("%w: OutputLogPolicy is required", ErrBadRequest)
	}
	if cfg.ExpectedOutputLogOrigin == "" {
		if op, ok := cfg.OutputLogPolicy.(interface{ Origin() string }); ok {
			cfg.ExpectedOutputLogOrigin = op.Origin()
		}
	}
	if err := wire.ValidateInputOrigin(cfg.ExpectedOutputLogOrigin); err != nil {
		return cfg, fmt.Errorf("%w: invalid ExpectedOutputLogOrigin: %w", ErrBadRequest, err)
	}
	if err := wire.ValidateInputOrigin(cfg.ExpectedInputLogOrigin); err != nil {
		return cfg, fmt.Errorf("%w: invalid ExpectedInputLogOrigin: %w", ErrBadRequest, err)
	}
	return cfg, nil
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient configures the underlying *http.Client used by the Client.
// The supplied *http.Client is shallow-copied so its CheckRedirect hook can reject 3xx redirects without mutating the caller's client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// ParsePolicy parses a C2SP tlog-policy configuration into a CheckpointPolicy.
func ParsePolicy(b []byte) (CheckpointPolicy, error) {
	return wire.ParsePolicy(b)
}

// SingleKeyPolicy constructs an origin-bound single-key CheckpointPolicy.
func SingleKeyPolicy(origin string, v note.Verifier) (CheckpointPolicy, error) {
	return wire.BuildPolicy(origin, v, nil, 0)
}

// WitnessPolicy constructs an origin-bound CheckpointPolicy requiring the primary log signature
// plus at least threshold (>= 1) distinct witness cosignatures.
func WitnessPolicy(origin string, v note.Verifier, witnesses []note.Verifier, threshold int) (CheckpointPolicy, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("%w: witness threshold must be >= 1, got %d", ErrBadRequest, threshold)
	}
	return wire.BuildPolicy(origin, v, witnesses, threshold)
}

// LookupResult represents a cryptographically verified snapshot-scoped response from LookupKey or LookupPrefix.
type LookupResult struct {
	OutputOrigin string
	OutputSize   uint64
	OutputRoot   [sha256.Size]byte
	InputOrigin  string
	From         uint64
	InputSize    uint64
	InputRoot    [sha256.Size]byte
	MPTRoot      [sha256.Size]byte
	Keys         []MatchedKey // 0..1 for LookupKey; 0..N (lexicographically sorted) for LookupPrefix
}

// MatchedKey represents a single key and its authenticated Value Log Merkle root within a LookupResult snapshot.
type MatchedKey struct {
	Key       string
	ValueRoot [sha256.Size]byte

	client    *Client
	from      uint64
	inputSize uint64
}

// Values streams verified Input Log entry indices in [from, inputSize) for k in descending order (newest-first).
// Each /values page's RFC 6962 compact range root is verified against the expected ValueRoot before any entry index from that page is yielded.
func (k MatchedKey) Values(ctx context.Context) iter.Seq2[uint64, error] {
	return func(yield func(uint64, error) bool) {
		if k.client == nil {
			yield(0, fmt.Errorf("%w: MatchedKey %q is not bound to an HTTP Client", ErrBadRequest, k.Key))
			return
		}
		if err := mpt.ValidateCanonicalKey([]byte(k.Key)); err != nil {
			yield(0, fmt.Errorf("%w: invalid key %q: %w", ErrBadRequest, k.Key, err))
			return
		}
		if k.ValueRoot == ([sha256.Size]byte{}) || k.ValueRoot == wire.EmptyRoot() || k.inputSize <= k.from {
			yield(0, fmt.Errorf("%w: invalid MatchedKey snapshot state for %q", ErrVerificationFailed, k.Key))
			return
		}

		queryPrefix := "key=" + wire.PercentEncodeCanonicalKey(k.Key) + "&before="
		before := k.inputSize
		expectedValueRoot := k.ValueRoot

		for {
			page, err := k.client.fetchValuesPage(ctx, k.Key, queryPrefix, expectedValueRoot, k.from, before)
			if err != nil {
				yield(0, err)
				return
			}

			for i := len(page.Indices) - 1; i >= 0; i-- {
				if !yield(page.Indices[i], nil) {
					return
				}
			}

			if page.Preceding == 0 {
				return
			}
			nextBefore, nextRoot, ok := page.NextPage()
			if !ok {
				yield(0, fmt.Errorf("%w: invalid compact range continuation for key %q", ErrVerificationFailed, k.Key))
				return
			}
			before = nextBefore
			expectedValueRoot = nextRoot
		}
	}
}

// ValuesResponse represents a verified single page from GET <index-url>/values?key=<key>&before=<before>.
type ValuesResponse struct {
	Preceding    uint64
	CompactRange [][sha256.Size]byte
	Indices      []uint64
}

// NextPage folds CompactRange right-to-left when Preceding > 0, returning the next exclusive
// upper bound (Indices[0]) and expected value log root for backward pagination.
func (r *ValuesResponse) NextPage() (before uint64, expectedValueRoot [sha256.Size]byte, ok bool) {
	if r == nil || r.Preceding == 0 || len(r.Indices) == 0 || len(r.CompactRange) != bits.OnesCount64(r.Preceding) {
		return 0, [sha256.Size]byte{}, false
	}
	acc := r.CompactRange[len(r.CompactRange)-1]
	for i := len(r.CompactRange) - 2; i >= 0; i-- {
		acc = wire.InteriorHash(r.CompactRange[i], acc)
	}
	return r.Indices[0], acc, true
}

// VerifyKeysResponse verifies a raw response body from GET <index-url>/keys?key=<target> or ?prefix=<target>.
// It is a pure, stateless function that performs zero network I/O or state mutations.
func VerifyKeysResponse(rawBody []byte, target string, isPrefix bool, cfg Config) (*LookupResult, error) {
	if err := mpt.ValidateCanonicalKey([]byte(target)); err != nil {
		if isPrefix {
			return nil, fmt.Errorf("%w: invalid query prefix %q: %w", ErrBadRequest, target, err)
		}
		return nil, fmt.Errorf("%w: invalid query key %q: %w", ErrBadRequest, target, err)
	}
	resolvedCfg, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}
	return verifyKeysBody(rawBody, target, isPrefix, resolvedCfg, nil)
}

func verifyKeysBody(rawBody []byte, target string, isPrefix bool, cfg Config, cli *Client) (*LookupResult, error) {
	keysRaw, bindRaw, ok := bytes.Cut(rawBody, []byte("\n\n"))
	if !ok {
		return nil, fmt.Errorf("%w: keys response must contain keys block and proof block", ErrVerificationFailed)
	}

	keysSec, err := wire.ParseKeysSection(keysRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse keys section: %w", ErrVerificationFailed, err)
	}
	bindSec, err := wire.ParseBindingSection(bindRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse binding section: %w", ErrVerificationFailed, err)
	}

	outCP, err := cfg.OutputLogPolicy.Verify(bindSec.OutSignedCP)
	if err != nil {
		return nil, fmt.Errorf("%w: output log checkpoint verification failed: %w", ErrVerificationFailed, err)
	}
	if outCP == nil || len(outCP.Hash) != sha256.Size {
		return nil, fmt.Errorf("%w: output log policy returned invalid checkpoint", ErrVerificationFailed)
	}
	if outCP.Origin != cfg.ExpectedOutputLogOrigin {
		return nil, fmt.Errorf("%w: output log origin %q != expected %q", ErrVerificationFailed, outCP.Origin, cfg.ExpectedOutputLogOrigin)
	}
	if outCP.Size < 1 {
		return nil, fmt.Errorf("%w: output log checkpoint size is %d, want >= 1", ErrVerificationFailed, outCP.Size)
	}
	if bindSec.OutLeafIdx != outCP.Size-1 {
		return nil, fmt.Errorf("%w: output log leaf index %d != output_size - 1 (%d)", ErrVerificationFailed, bindSec.OutLeafIdx, outCP.Size-1)
	}

	leafHash := wire.LeafHash(bindSec.RawOutLeaf)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, bindSec.OutLeafIdx, outCP.Size, leafHash[:], bindSec.InclusionProof, outCP.Hash); err != nil {
		return nil, fmt.Errorf("%w: output log inclusion proof invalid: %w", ErrVerificationFailed, err)
	}

	if bindSec.InputOrigin != cfg.ExpectedInputLogOrigin {
		return nil, fmt.Errorf("%w: state commitment input-origin %q != expected %q", ErrVerificationFailed, bindSec.InputOrigin, cfg.ExpectedInputLogOrigin)
	}
	if bindSec.InputSize == 0 && bindSec.InputRoot != wire.EmptyRoot() {
		return nil, fmt.Errorf("%w: non-empty input-root at input_size 0", ErrVerificationFailed)
	}
	if bindSec.InputSize == bindSec.From && (bindSec.MPTRoot != wire.EmptyRoot() || len(keysSec.Matches) > 0) {
		return nil, fmt.Errorf("%w: non-empty MPT state when input_size (%d) == from (%d)", ErrVerificationFailed, bindSec.InputSize, bindSec.From)
	}

	keys := keysSec.Matches
	for _, kv := range keys {
		if kv.ValueRoot == ([sha256.Size]byte{}) || kv.ValueRoot == wire.EmptyRoot() {
			return nil, fmt.Errorf("%w: invalid empty value_root for key %q", ErrVerificationFailed, kv.Key)
		}
	}

	var outRoot [sha256.Size]byte
	copy(outRoot[:], outCP.Hash)
	res := &LookupResult{
		OutputOrigin: outCP.Origin,
		OutputSize:   outCP.Size,
		OutputRoot:   outRoot,
		InputOrigin:  bindSec.InputOrigin,
		From:         bindSec.From,
		InputSize:    bindSec.InputSize,
		InputRoot:    bindSec.InputRoot,
		MPTRoot:      bindSec.MPTRoot,
	}

	if !isPrefix {
		if len(keys) == 0 {
			if err := mpt.VerifyKey(bindSec.MPTRoot, []byte(target), [sha256.Size]byte{}, false, keysSec.MPTProof); err != nil {
				return nil, fmt.Errorf("%w: non-inclusion proof verification failed: %w", ErrVerificationFailed, err)
			}
			return res, nil
		}
		if len(keys) > 1 {
			return nil, fmt.Errorf("%w: point lookup returned %d keys", ErrVerificationFailed, len(keys))
		}
		if keys[0].Key != target {
			return nil, fmt.Errorf("%w: inclusion response must contain matching key %q, got %q", ErrVerificationFailed, target, keys[0].Key)
		}
		if err := mpt.VerifyKey(bindSec.MPTRoot, []byte(target), keys[0].ValueRoot, true, keysSec.MPTProof); err != nil {
			return nil, fmt.Errorf("%w: inclusion proof verification failed: %w", ErrVerificationFailed, err)
		}
		res.Keys = []MatchedKey{{
			Key:       keys[0].Key,
			ValueRoot: keys[0].ValueRoot,
			client:    cli,
			from:      bindSec.From,
			inputSize: bindSec.InputSize,
		}}
		return res, nil
	}

	if err := mpt.VerifyPrefix(bindSec.MPTRoot, []byte(target), keys, keysSec.MPTProof); err != nil {
		return nil, fmt.Errorf("%w: prefix proof verification failed: %w", ErrVerificationFailed, err)
	}
	if len(keys) > 0 {
		res.Keys = make([]MatchedKey, len(keys))
		for i, kv := range keys {
			res.Keys[i] = MatchedKey{
				Key:       kv.Key,
				ValueRoot: kv.ValueRoot,
				client:    cli,
				from:      bindSec.From,
				inputSize: bindSec.InputSize,
			}
		}
	}
	return res, nil
}

// VerifyValuesResponse verifies a raw response body from GET <index-url>/values?key=<key>&before=<before>
// against expectedValueRoot and the range [from, before).
func VerifyValuesResponse(rawBody []byte, expectedValueRoot [sha256.Size]byte, from, before uint64) (*ValuesResponse, error) {
	if expectedValueRoot == ([sha256.Size]byte{}) || expectedValueRoot == wire.EmptyRoot() {
		return nil, fmt.Errorf("%w: VerifyValuesResponse requires a non-empty expectedValueRoot", ErrVerificationFailed)
	}
	if before == 0 || from >= before {
		return nil, fmt.Errorf("%w: invalid or empty range [%d, %d)", ErrVerificationFailed, from, before)
	}

	valSec, err := wire.ParseValuesResponse(rawBody)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse values response: %w", ErrVerificationFailed, err)
	}

	if valSec.Indices[0] < from {
		return nil, fmt.Errorf("%w: first index %d < from %d", ErrVerificationFailed, valSec.Indices[0], from)
	}
	if valSec.Indices[len(valSec.Indices)-1] >= before {
		return nil, fmt.Errorf("%w: index %d >= before %d", ErrVerificationFailed, valSec.Indices[len(valSec.Indices)-1], before)
	}
	if valSec.Preceding > valSec.Indices[0]-from {
		return nil, fmt.Errorf("%w: preceding count (%d) exceeds available range before first index (%d - %d)", ErrVerificationFailed, valSec.Preceding, valSec.Indices[0], from)
	}

	computedRoot, err := wire.ComputeValueLogRoot(valSec.CompactRange, valSec.Preceding, valSec.Indices)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute value log root: %w", ErrVerificationFailed, err)
	}
	if computedRoot != expectedValueRoot {
		return nil, fmt.Errorf("%w: value log root mismatch: got %x, want %x", ErrVerificationFailed, computedRoot, expectedValueRoot)
	}

	return &ValuesResponse{
		Preceding:    valSec.Preceding,
		CompactRange: valSec.CompactRange,
		Indices:      valSec.Indices,
	}, nil
}

// Client performs cryptographically verified, stateless lookups against a VIndex HTTP endpoint.
type Client struct {
	baseURL    *url.URL
	cfg        Config
	httpClient *http.Client
}

// New creates a new VIndex Client targeting indexURL. HTTP redirects (3xx) are rejected per tlog-vindex.
func New(indexURL string, cfg Config, opts ...Option) (*Client, error) {
	u, err := url.Parse(indexURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid index URL %q: %w", ErrBadRequest, indexURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%w: index URL %q must use http or https with a non-empty host", ErrBadRequest, indexURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: index URL %q must not include userinfo, query parameters, or fragments", ErrBadRequest, indexURL)
	}
	resolvedCfg, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}

	c := &Client{
		baseURL:    u,
		cfg:        resolvedCfg,
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	clonedClient := *c.httpClient
	clonedClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("HTTP redirects (3xx) are forbidden by tlog-vindex spec (redirected to %q)", req.URL.String())
	}
	c.httpClient = &clonedClient
	return c, nil
}

func checkPlainUTF8ContentType(ct string) error {
	if ct == "text/plain; charset=utf-8" {
		return nil
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "text/plain" || !strings.EqualFold(params["charset"], "utf-8") {
		return fmt.Errorf("%w: unexpected Content-Type %q, want text/plain; charset=utf-8", ErrVerificationFailed, ct)
	}
	return nil
}

func sanitizeHeaderOrBody(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func (c *Client) doGet(ctx context.Context, routePath, rawQuery string) (int, string, []byte, error) {
	u := *c.baseURL
	u.Path = strings.TrimSuffix(u.Path, "/") + routePath
	u.RawPath = ""
	u.RawQuery = rawQuery
	reqURL := u.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, "", nil, fmt.Errorf("failed to construct request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("HTTP GET %s failed: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, "", nil, fmt.Errorf("HTTP redirects (3xx, status %d) are forbidden by tlog-vindex spec", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return resp.StatusCode, sanitizeHeaderOrBody(resp.Header.Get("Retry-After")), errBody, nil
	}
	if err := checkPlainUTF8ContentType(resp.Header.Get("Content-Type")); err != nil {
		return 0, "", nil, err
	}
	if resp.ContentLength > maxResponseBodyBytes {
		return 0, "", nil, fmt.Errorf("%w: response Content-Length %d exceeds %d bytes", ErrVerificationFailed, resp.ContentLength, maxResponseBodyBytes)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return 0, "", nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if len(body) > maxResponseBodyBytes {
		return 0, "", nil, fmt.Errorf("%w: response body exceeds %d bytes", ErrVerificationFailed, maxResponseBodyBytes)
	}
	return http.StatusOK, "", body, nil
}

func mapHTTPStatusError(statusCode int, retryAfter string, body []byte, allowTooManyKeys bool) error {
	msg := sanitizeHeaderOrBody(string(body))
	switch {
	case statusCode == http.StatusBadRequest:
		return fmt.Errorf("%w: server returned status 400: %s", ErrBadRequest, msg)
	case statusCode == http.StatusRequestEntityTooLarge && allowTooManyKeys:
		return fmt.Errorf("%w: server returned status 413: %s", ErrTooManyKeys, msg)
	case statusCode == http.StatusServiceUnavailable:
		if retryAfter != "" {
			return fmt.Errorf("%w (Retry-After: %s): server returned status 503: %s", ErrUnavailable, retryAfter, msg)
		}
		return fmt.Errorf("%w: server returned status 503: %s", ErrUnavailable, msg)
	default:
		return fmt.Errorf("server returned status %d: %s", statusCode, msg)
	}
}

func (c *Client) lookupKeys(ctx context.Context, target string, isPrefix bool) (*LookupResult, error) {
	if err := mpt.ValidateCanonicalKey([]byte(target)); err != nil {
		if isPrefix {
			return nil, fmt.Errorf("%w: invalid query prefix %q: %w", ErrBadRequest, target, err)
		}
		return nil, fmt.Errorf("%w: invalid query key %q: %w", ErrBadRequest, target, err)
	}
	paramName := "key"
	if isPrefix {
		paramName = "prefix"
	}
	status, retryAfter, body, err := c.doGet(ctx, "/keys", paramName+"="+wire.PercentEncodeCanonicalKey(target))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, mapHTTPStatusError(status, retryAfter, body, isPrefix)
	}
	return verifyKeysBody(body, target, isPrefix, c.cfg, c)
}

// LookupKey queries GET <index-url>/keys?key=<key> and verifies the state commitment and MPT proof.
func (c *Client) LookupKey(ctx context.Context, key string) (*LookupResult, error) {
	return c.lookupKeys(ctx, key, false)
}

// LookupPrefix queries GET <index-url>/keys?prefix=<prefix> and verifies the two-sided MPT prefix proof.
func (c *Client) LookupPrefix(ctx context.Context, prefix string) (*LookupResult, error) {
	return c.lookupKeys(ctx, prefix, true)
}

func (c *Client) fetchValuesPage(
	ctx context.Context,
	key, queryPrefix string,
	expectedValueRoot [sha256.Size]byte,
	from, before uint64,
) (*ValuesResponse, error) {
	status, retryAfter, body, err := c.doGet(ctx, "/values", queryPrefix+strconv.FormatUint(before, 10))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		if status == http.StatusNotFound {
			return nil, fmt.Errorf("%w: unexpected HTTP 404 on promised value log page for key %q (before=%d)", ErrVerificationFailed, key, before)
		}
		return nil, mapHTTPStatusError(status, retryAfter, body, false)
	}
	return VerifyValuesResponse(body, expectedValueRoot, from, before)
}
