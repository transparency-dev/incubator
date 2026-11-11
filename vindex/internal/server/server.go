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

// Package server provides HTTP read endpoints for the Verifiable Index wire protocol.
package server

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/net/publicsuffix"
	"k8s.io/klog/v2"
)

//go:embed index.html
var defaultIndexHTML []byte

var uiCSP string

func init() {
	const openTag, closeTag = "<script>", "</script>"
	start := strings.Index(string(defaultIndexHTML), openTag)
	end := strings.LastIndex(string(defaultIndexHTML), closeTag)
	if start < 0 || end <= start {
		panic("server: embedded index.html missing <script>...</script> block")
	}
	scriptBody := defaultIndexHTML[start+len(openTag) : end]
	sum := sha256.Sum256(scriptBody)
	uiCSP = "default-src 'self'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; style-src 'unsafe-inline'; connect-src *; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
}

const (
	defaultLookupLimit   uint64 = 100
	maxRawQueryBytes     int    = 4096
	DefaultMaxPrefixKeys int    = 10000
)

var mptInitDiagnosticsJSON = []byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n")

// LookupStore provides read-only inverted-index lookups for /values queries.
type LookupStore interface {
	Lookup(keyHash [sha256.Size]byte, before *uint64, limit uint64, maxInputLogSize uint64) (*kvstore.LookupResult, error)
}

// PrefixPolicy validates whether a prefix query (?prefix=<prefix>) is permitted.
// A nil PrefixPolicy permits all canonical key prefixes.
type PrefixPolicy func(prefix string) error

// ParsePrefixPolicy resolves a policy name ('allow', 'reversed-dns', 'none') into a PrefixPolicy.
func ParsePrefixPolicy(name string) (PrefixPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "allow":
		return nil, nil
	case "none", "disallow", "deny":
		return disallowPrefixPolicy, nil
	case "reversed-dns", "domain":
		return reversedDNSPrefixPolicy, nil
	default:
		return nil, fmt.Errorf("unknown prefix_policy %q: expected 'allow', 'reversed-dns', or 'none'", name)
	}
}

func disallowPrefixPolicy(prefix string) error {
	return fmt.Errorf("prefix queries are disabled on this server (prefix %q)", prefix)
}

func isReversedDNSLabelByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func reversedDNSPrefixPolicy(prefix string) error {
	if prefix == "" || !strings.HasSuffix(prefix, ".") {
		return fmt.Errorf("prefix %q must end with a trailing '.' on a label boundary", prefix)
	}
	trimmed := strings.TrimSuffix(prefix, ".")
	if trimmed == "" {
		return fmt.Errorf("prefix %q must contain at least an eTLD+1 domain", prefix)
	}

	revLabels := strings.Split(trimmed, ".")
	for i, lbl := range revLabels {
		if lbl == "" || len(lbl) > 63 {
			return fmt.Errorf("prefix %q contains an empty or overlong DNS label", prefix)
		}
		if lbl == "*" {
			if i != len(revLabels)-1 {
				return fmt.Errorf("prefix %q contains wildcard '*' outside final reversed label", prefix)
			}
			continue
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return fmt.Errorf("prefix %q contains leading or trailing hyphen in label %q", prefix, lbl)
		}
		for j := 0; j < len(lbl); j++ {
			if !isReversedDNSLabelByte(lbl[j]) {
				return fmt.Errorf("prefix %q contains invalid DNS label character in %q", prefix, lbl)
			}
		}
	}

	if revLabels[len(revLabels)-1] == "*" {
		revLabels = revLabels[:len(revLabels)-1]
		if len(revLabels) == 0 {
			return fmt.Errorf("prefix %q must contain at least an eTLD+1 domain", prefix)
		}
	}

	slices.Reverse(revLabels)
	forwardDomain := strings.Join(revLabels, ".")

	sfx, icann := publicsuffix.PublicSuffix(forwardDomain)
	if !icann && !strings.Contains(sfx, ".") {
		return fmt.Errorf("prefix %q (%s) uses unlisted TLD %q", prefix, forwardDomain, sfx)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(forwardDomain); err != nil {
		return fmt.Errorf("prefix %q (%s) must specify at least an eTLD+1 domain: %w", prefix, forwardDomain, err)
	}
	return nil
}

func cleanPathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return ""
	}
	cleaned := path.Clean("/" + prefix)
	if cleaned == "/" || cleaned == "/." {
		return ""
	}
	return cleaned
}

// Config configures a ReadServer.
type Config struct {
	Store         LookupStore
	MPT           *mpt.Manager
	Publisher     *tree.OutputPublisher
	ReadyCheck    func() error
	OutputLogDir  string
	PathPrefix    string
	DisableUI     bool
	PrefixPolicy  PrefixPolicy
	MaxPrefixKeys int
}

type backendRef struct {
	mptMgr  *mpt.Manager
	pub     *tree.OutputPublisher
	readyFn func() error
}

// ReadServer serves HTTP lookup, checkpoint, optional Output Log tile, and operational queries.
type ReadServer struct {
	store         LookupStore
	backend       atomic.Pointer[backendRef]
	outputLogDir  string
	pathPrefix    string
	disableUI     bool
	prefixPolicy  PrefixPolicy
	maxPrefixKeys int
	handler       http.Handler
	adminHandler  http.Handler
}

// New creates a configured ReadServer with prebuilt public and administrative HTTP handlers.
func New(cfg Config) *ReadServer {
	maxKeys := cfg.MaxPrefixKeys
	if maxKeys <= 0 {
		maxKeys = DefaultMaxPrefixKeys
	}
	s := &ReadServer{
		store:         cfg.Store,
		outputLogDir:  cfg.OutputLogDir,
		pathPrefix:    cleanPathPrefix(cfg.PathPrefix),
		disableUI:     cfg.DisableUI,
		prefixPolicy:  cfg.PrefixPolicy,
		maxPrefixKeys: maxKeys,
	}
	s.backend.Store(&backendRef{
		mptMgr:  cfg.MPT,
		pub:     cfg.Publisher,
		readyFn: cfg.ReadyCheck,
	})
	s.handler = s.buildPublicHandler()
	s.adminHandler = s.buildAdminHandler()
	return s
}

// NewHTTPServer constructs an http.Server with Slowloris and header-size protections.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// SetBackend atomically attaches or updates the MPT Manager, OutputPublisher, and readiness callback.
func (s *ReadServer) SetBackend(mptMgr *mpt.Manager, pub *tree.OutputPublisher, readyFn func() error) {
	s.backend.Store(&backendRef{
		mptMgr:  mptMgr,
		pub:     pub,
		readyFn: readyFn,
	})
}

// Handler returns the public C2SP tlog-vindex HTTP handler.
func (s *ReadServer) Handler() http.Handler {
	return s.handler
}

// AdminHandler returns the operational HTTP handler (/healthz, /readyz, /metrics, /debug/pprof/*).
func (s *ReadServer) AdminHandler() http.Handler {
	return s.adminHandler
}

func (s *ReadServer) buildAdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func (s *ReadServer) buildPublicHandler() http.Handler {
	subMux := http.NewServeMux()
	subMux.HandleFunc("/", s.handleUI)
	subMux.HandleFunc("/index.html", s.handleUI)
	subMux.HandleFunc("/checkpoint", s.handleCheckpoint)
	subMux.HandleFunc("/keys", s.handleKeys)
	subMux.HandleFunc("/values", s.handleValues)
	if s.outputLogDir != "" {
		// Register both /tile and /tile/ so ServeMux never emits a 301 redirect from /tile to /tile/.
		subMux.HandleFunc("/tile", http.NotFound)
		subMux.HandleFunc("/tile/", s.handleOutputTile)
	}

	var root http.Handler = subMux
	if s.pathPrefix != "" {
		outer := http.NewServeMux()
		outer.Handle(s.pathPrefix+"/", http.StripPrefix(s.pathPrefix, subMux))
		outer.HandleFunc(s.pathPrefix, s.serveUIBody)
		root = outer
	}

	// Reject uncleaned paths with 404 before ServeMux can emit 301 redirects (3xx is forbidden by tlog-vindex).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "" || p[0] != '/' ||
			strings.Contains(p, "//") ||
			strings.Contains(p, "/./") ||
			strings.Contains(p, "/../") ||
			strings.HasSuffix(p, "/.") ||
			strings.HasSuffix(p, "/..") {
			http.NotFound(w, r)
			return
		}
		root.ServeHTTP(w, r)
	})
}

func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func writeUnavailable(w http.ResponseWriter, msg string) {
	w.Header().Set("Retry-After", "30")
	http.Error(w, msg, http.StatusServiceUnavailable)
}

func writeUnavailableJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Retry-After", "30")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(body)
}

func (s *ReadServer) serveUIBody(w http.ResponseWriter, r *http.Request) {
	if s.disableUI {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeMethodNotAllowed(w, "GET, HEAD")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", uiCSP)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(defaultIndexHTML)
	}
}

func (s *ReadServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	s.serveUIBody(w, r)
}

func (s *ReadServer) handleOutputTile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	subPath := strings.TrimPrefix(r.URL.Path, "/tile/")
	if subPath == "" || strings.HasPrefix(subPath, "/") || strings.HasSuffix(subPath, "/") ||
		strings.Contains(subPath, "\\") || strings.Contains(subPath, "..") {
		http.NotFound(w, r)
		return
	}

	root, err := os.OpenRoot(filepath.Join(s.outputLogDir, "tile"))
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		klog.Errorf("open output tile root failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(subPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	if strings.Contains(subPath, ".p/") {
		h.Set("Cache-Control", "no-store")
	} else {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func (s *ReadServer) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	b := s.backend.Load()
	if b == nil || b.pub == nil {
		writeUnavailable(w, "checkpoint not ready")
		return
	}
	state := b.pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		writeUnavailable(w, "checkpoint not ready")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(state.RawCheckpoint)
}

func (s *ReadServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

type jsonDiagnosticsProvider interface {
	JSONDiagnostics() []byte
}

func (s *ReadServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	b := s.backend.Load()
	if b != nil && b.readyFn != nil {
		if err := b.readyFn(); err != nil {
			var diag jsonDiagnosticsProvider
			if errors.As(err, &diag) {
				writeUnavailableJSON(w, diag.JSONDiagnostics())
				return
			}
			writeUnavailable(w, fmt.Sprintf("unhealthy: %v", err))
			return
		}
	}
	if b == nil || b.mptMgr == nil || b.pub == nil {
		writeUnavailableJSON(w, mptInitDiagnosticsJSON)
		return
	}
	state := b.pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		writeUnavailable(w, "serving state not ready")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// walkRFC3986Query parses rawQuery using strict RFC 3986 percent-decoding without heap map/slice allocations.
// Unlike url.ParseQuery, it rejects malformed %-escapes, missing '=', and oversized query strings while preserving literal '+' (0x2B).
func walkRFC3986Query(rawQuery string, visit func(name, val string) error) error {
	if rawQuery == "" {
		return nil
	}
	if len(rawQuery) > maxRawQueryBytes {
		return errors.New("query string exceeds maximum length")
	}
	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			return errors.New("empty query parameter segment")
		}
		rawName, rawVal, hasEq := strings.Cut(part, "=")
		if !hasEq || rawName == "" {
			return errors.New("malformed query parameter")
		}
		name, err := url.PathUnescape(rawName)
		if err != nil {
			return fmt.Errorf("invalid percent-encoding in query parameter name: %w", err)
		}
		val, err := url.PathUnescape(rawVal)
		if err != nil {
			return fmt.Errorf("invalid percent-encoding in query parameter %q: %w", name, err)
		}
		if err := visit(name, val); err != nil {
			return err
		}
	}
	return nil
}

func parseKeysQuery(rawQuery string) (keyStr string, isPrefix bool, err error) {
	var seenKey, seenPrefix bool
	err = walkRFC3986Query(rawQuery, func(name, val string) error {
		switch name {
		case "key":
			if seenKey || seenPrefix {
				return errors.New("duplicate or mutually exclusive key/prefix parameters")
			}
			seenKey = true
			keyStr = val
		case "prefix":
			if seenKey || seenPrefix {
				return errors.New("duplicate or mutually exclusive key/prefix parameters")
			}
			seenPrefix = true
			isPrefix = true
			keyStr = val
		default:
			return fmt.Errorf("unknown query parameter %q", name)
		}
		return nil
	})
	if err != nil {
		return "", false, err
	}
	if !seenKey && !seenPrefix {
		return "", false, errors.New("missing key or prefix parameter")
	}
	if err := mpt.ValidateCanonicalKey([]byte(keyStr)); err != nil {
		return "", false, err
	}
	return keyStr, isPrefix, nil
}

func parseValuesQuery(rawQuery string) (keyStr string, before uint64, err error) {
	var seenKey, seenBefore bool
	var beforeStr string
	err = walkRFC3986Query(rawQuery, func(name, val string) error {
		switch name {
		case "key":
			if seenKey {
				return errors.New("duplicate key parameter not allowed")
			}
			seenKey = true
			keyStr = val
		case "before":
			if seenBefore {
				return errors.New("duplicate before parameter not allowed")
			}
			seenBefore = true
			beforeStr = val
		default:
			return fmt.Errorf("unknown query parameter %q", name)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if !seenKey {
		return "", 0, errors.New("missing key parameter")
	}
	if err := mpt.ValidateCanonicalKey([]byte(keyStr)); err != nil {
		return "", 0, err
	}
	if !seenBefore || beforeStr == "" {
		return "", 0, errors.New("missing required before parameter")
	}
	before, err = parseStrictPositiveUint64(beforeStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid before parameter %q: %w", beforeStr, err)
	}
	return keyStr, before, nil
}

func parseStrictPositiveUint64(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("must be canonical positive integer without leading zeros")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("non-digit character")
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("must be a positive 64-bit integer")
	}
	return v, nil
}

func (s *ReadServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	keyStr, isPrefix, err := parseKeysQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
		return
	}
	if isPrefix && s.prefixPolicy != nil {
		if err := s.prefixPolicy(keyStr); err != nil {
			http.Error(w, fmt.Sprintf("prefix rejected by policy: %v", err), http.StatusBadRequest)
			return
		}
	}

	b := s.backend.Load()
	if b == nil || b.mptMgr == nil || b.pub == nil {
		writeUnavailableJSON(w, mptInitDiagnosticsJSON)
		return
	}
	if s0 := b.pub.GetServingState(); s0 == nil || len(s0.RawCheckpoint) == 0 {
		writeUnavailable(w, "serving state not initialized")
		return
	}

	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	var (
		state   *tree.ServingState
		proof   []byte
		matches []mpt.PrefixKeyVal
		mode    string
	)

	b.mptMgr.RLock()
	state = b.pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		b.mptMgr.RUnlock()
		writeUnavailable(w, "serving state not initialized")
		return
	}
	if isPrefix {
		mode = "prefix"
		proof, matches, err = b.mptMgr.ProvePrefixLocked([]byte(keyStr), s.maxPrefixKeys)
	} else {
		var val [sha256.Size]byte
		var exists bool
		proof, val, exists, err = b.mptMgr.ProveKeyLocked([]byte(keyStr))
		if exists {
			mode = "inclusion"
			matches = []mpt.PrefixKeyVal{{Key: keyStr, ValueRoot: val}}
		} else {
			mode = "non-inclusion"
		}
	}
	b.mptMgr.RUnlock()

	if errors.Is(err, mpt.ErrPrefixTooManyKeys) {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		klog.Errorf("MPT proof generation failed for %q (prefix=%v): %v", keyStr, isPrefix, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	respBytes := wire.FormatKeysResponseFull(state.RawCheckpoint, state.OutputLogIndex, state.MPTRoot, state.From, state.InputLogCP, state.OutputLogProof, mode, proof, matches)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (s *ReadServer) handleValues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	keyStr, parsedBefore, err := parseValuesQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid query: %v", err), http.StatusBadRequest)
		return
	}

	if s.store == nil {
		writeUnavailable(w, "storage not initialized")
		return
	}
	b := s.backend.Load()
	if b == nil || b.pub == nil {
		writeUnavailableJSON(w, mptInitDiagnosticsJSON)
		return
	}
	state := b.pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		writeUnavailable(w, "serving state not initialized")
		return
	}

	if parsedBefore > state.InputLogSize {
		writeUnavailable(w, fmt.Sprintf("before (%d) exceeds indexed input log size (%d)", parsedBefore, state.InputLogSize))
		return
	}
	if parsedBefore <= state.From {
		http.Error(w, "no entries found before requested index", http.StatusNotFound)
		return
	}

	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	keyHash := sha256.Sum256([]byte(keyStr))
	lookupRes, err := s.store.Lookup(keyHash, &parsedBefore, defaultLookupLimit, state.InputLogSize)
	if err != nil {
		klog.Errorf("KV Lookup failed for key %q: %v", keyStr, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if lookupRes == nil || len(lookupRes.MatchedIndices) == 0 {
		http.Error(w, "no entries found before requested index", http.StatusNotFound)
		return
	}
	if lookupRes.MatchedIndices[0] < state.From {
		klog.Errorf("KV Lookup returned index %d below configured From %d for key %q", lookupRes.MatchedIndices[0], state.From, keyStr)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	metrics.LookupResultsReturned.Observe(float64(len(lookupRes.MatchedIndices)))

	respBytes := wire.FormatValuesResponse(lookupRes.Preceding, lookupRes.CompactRange, lookupRes.MatchedIndices)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}
