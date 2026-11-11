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

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

type mockOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
	signer note.Signer
}

func newMockOutputLog(tb testing.TB, origin string) *mockOutputLog {
	tb.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		tb.Fatalf("GenerateKey failed: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		tb.Fatalf("NewSigner failed: %v", err)
	}
	return &mockOutputLog{origin: origin, signer: signer}
}

func (m *mockOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, bytes.Clone(leafData))
	size := uint64(len(m.leaves))

	// Single-leaf RFC 6962 hash (0x00 || leaf) for size == 1, deterministic root otherwise.
	root := rfc6962.DefaultHasher.HashLeaf(leafData)
	if size > 1 {
		sib := sha256.Sum256([]byte("sibling"))
		root = rfc6962.DefaultHasher.HashChildren(sib[:], root)
	}
	body := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root))
	rawCP, err := note.Sign(&note.Note{Text: body}, m.signer)
	if err != nil {
		return 0, nil, err
	}
	return idx, rawCP, nil
}

func (m *mockOutputLog) InclusionProof(_ context.Context, _, treeSize uint64) ([][sha256.Size]byte, error) {
	if treeSize > 1 {
		return [][sha256.Size]byte{sha256.Sum256([]byte("sibling"))}, nil
	}
	return nil, nil
}

func openMemDB(tb testing.TB, chunkSize uint64) *kvstore.DB {
	tb.Helper()
	db, err := kvstore.Open("", &kvstore.Options{ChunkSize: chunkSize})
	if err != nil {
		tb.Fatalf("kvstore.Open(in-memory) failed: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return db
}

func setupEnv(tb testing.TB, chunkSize uint64, cfg Config) (*ReadServer, *kvstore.DB, *mpt.Manager, *tree.OutputPublisher) {
	tb.Helper()
	db := openMemDB(tb, chunkSize)
	mptMgr := mpt.NewMem()
	outLog := newMockOutputLog(tb, "example.com/output")
	pub := tree.NewOutputPublisher(mptMgr, outLog)
	cfg.Store = db
	cfg.MPT = mptMgr
	cfg.Publisher = pub
	return New(cfg), db, mptMgr, pub
}

func seedIndex(tb testing.TB, db *kvstore.DB, pub *tree.OutputPublisher, size uint64, keyIndices map[string][]uint64) map[string][sha256.Size]byte {
	tb.Helper()
	var roots map[string][sha256.Size]byte
	if len(keyIndices) > 0 {
		indexer := kvstore.NewKVIndexer(db)
		res, err := indexer.IndexMappedBatch(context.Background(), &kvstore.MappedBatch{KeyIndices: keyIndices}, nil, size)
		if err != nil {
			tb.Fatalf("IndexMappedBatch failed: %v", err)
		}
		roots = res.ModifiedKeyValueRoots
	}
	var inRoot [sha256.Size]byte
	if size == 0 {
		inRoot = wire.EmptyRoot()
	} else {
		inRoot = sha256.Sum256([]byte(fmt.Sprintf("in-%d", size)))
	}
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: size, Hash: inRoot[:]}
	if _, err := pub.PublishKeyBatch(context.Background(), roots, inCP); err != nil {
		tb.Fatalf("PublishKeyBatch failed: %v", err)
	}
	return roots
}

func doReq(tb testing.TB, h http.Handler, method, target string, wantCode int) *httptest.ResponseRecorder {
	tb.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
	if w.Code != wantCode {
		tb.Fatalf("%s %s status = %d, want %d (body: %q)", method, target, w.Code, wantCode, w.Body.String())
	}
	return w
}

func splitAndVerifyKeysWire(t *testing.T, body []byte) (*wire.KeysSection, *wire.BindingSection) {
	t.Helper()
	const sep = "\nc2sp.org/tlog-proof@v1\n"
	idx := bytes.Index(body, []byte(sep))
	if idx < 0 {
		t.Fatalf("response missing tlog-proof@v1 separator:\n%s", string(body))
	}
	keysSec, err := wire.ParseKeysSection(body[:idx])
	if err != nil {
		t.Fatalf("ParseKeysSection failed: %v\nbody:\n%s", err, string(body))
	}
	bindSec, err := wire.ParseBindingSection(body[idx+1:])
	if err != nil {
		t.Fatalf("ParseBindingSection failed: %v\nbody:\n%s", err, string(body))
	}
	return keysSec, bindSec
}

type testDiagErr struct {
	payload string
}

func (e testDiagErr) Error() string           { return "backfilling" }
func (e testDiagErr) JSONDiagnostics() []byte { return []byte(e.payload) }

func TestReadServer_CheckpointsMethodsAndNoRedirects(t *testing.T) {
	tileRoot := t.TempDir()
	srv, _, _, pub := setupEnv(t, 256, Config{OutputLogDir: tileRoot})
	h := srv.Handler()

	// Uninitialized checkpoint returns 503 with Retry-After: 30
	w503 := doReq(t, h, http.MethodGet, "/checkpoint", http.StatusServiceUnavailable)
	if w503.Header().Get("Retry-After") != "30" {
		t.Fatalf("Retry-After = %q, want 30", w503.Header().Get("Retry-After"))
	}

	seedIndex(t, srv.store.(*kvstore.DB), pub, 500, nil)

	wCP := doReq(t, h, http.MethodGet, "/checkpoint", http.StatusOK)
	if wCP.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /checkpoint Cache-Control = %q, want no-store", wCP.Header().Get("Cache-Control"))
	}
	if !strings.Contains(wCP.Body.String(), "example.com/output\n1\n") {
		t.Fatalf("unexpected checkpoint body: %s", wCP.Body.String())
	}

	// RFC 9110 Allow header on 405 Method Not Allowed across endpoints
	for _, tc := range []struct {
		handler http.Handler
		path    string
		allow   string
	}{
		{h, "/", "GET, HEAD"},
		{h, "/index.html", "GET, HEAD"},
		{h, "/checkpoint", "GET"},
		{h, "/keys?key=a", "GET"},
		{h, "/values?key=a&before=1", "GET"},
		{h, "/tile/0/000", "GET"},
		{srv.AdminHandler(), "/healthz", "GET"},
		{srv.AdminHandler(), "/readyz", "GET"},
	} {
		w405 := doReq(t, tc.handler, http.MethodPost, tc.path, http.StatusMethodNotAllowed)
		if got := w405.Header().Get("Allow"); got != tc.allow {
			t.Errorf("POST %s Allow = %q, want %q", tc.path, got, tc.allow)
		}
	}

	// Removed routes and uncleaned paths must return 404 (never 301 redirect)
	for _, badPath := range []string{
		"/vindex/v1/checkpoint",
		"/vindex/v1/inputlog_checkpoint",
		"/inputlog_checkpoint",
		"/vindex/v1/keys?key=test",
		"/vindex/v1/values?key=test&before=1",
		"/entries?key=test&before=1",
		"/keys/test",
		"/unknown-route",
		"//keys?key=test",
		"/./checkpoint",
		"/keys/..",
		"/tile",
		"/tile/",
	} {
		doReq(t, h, http.MethodGet, badPath, http.StatusNotFound)
	}
}

func TestReadServer_AsyncBackendReadinessAndJSONDiagnostics(t *testing.T) {
	db := openMemDB(t, 256)
	srv := New(Config{Store: db})

	// Liveness (/healthz) is 200 OK while backend is still opening
	doReq(t, srv.AdminHandler(), http.MethodGet, "/healthz", http.StatusOK)

	// /readyz, /keys, and /values all return 503 application/json with mpt_initializing before SetBackend
	for _, tc := range []struct {
		h    http.Handler
		path string
	}{
		{srv.AdminHandler(), "/readyz"},
		{srv.Handler(), "/keys?key=testkey"},
		{srv.Handler(), "/values?key=testkey&before=1"},
	} {
		w := doReq(t, tc.h, http.MethodGet, tc.path, http.StatusServiceUnavailable)
		if w.Header().Get("Retry-After") != "30" {
			t.Fatalf("%s Retry-After = %q, want 30", tc.path, w.Header().Get("Retry-After"))
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("%s Content-Type = %q, want application/json", tc.path, ct)
		}
		if !strings.Contains(w.Body.String(), `"status":"mpt_initializing"`) {
			t.Fatalf("%s body = %q, want mpt_initializing", tc.path, w.Body.String())
		}
	}

	// Wrapped jsonDiagnosticsProvider error via errors.As preserves application/json Content-Type
	mptMgr := mpt.NewMem()
	pub := tree.NewOutputPublisher(mptMgr, newMockOutputLog(t, "example.com/output"))
	diagJSON := `{"status":"genesis_backfill","genesis_backfill":true,"leaves_indexed":500,"target_leaves":10000}` + "\n"
	srv.SetBackend(mptMgr, pub, func() error {
		return fmt.Errorf("coordinator busy: %w", testDiagErr{payload: diagJSON})
	})

	wDiag := doReq(t, srv.AdminHandler(), http.MethodGet, "/readyz", http.StatusServiceUnavailable)
	if ct := wDiag.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("/readyz wrapped diag Content-Type = %q, want application/json", ct)
	}
	if wDiag.Body.String() != diagJSON {
		t.Fatalf("/readyz body = %q, want %q", wDiag.Body.String(), diagJSON)
	}

	// Plain error falls back to text/plain 503; nil readyFn + published state transitions /readyz to 200 OK
	srv.SetBackend(mptMgr, pub, func() error { return errors.New("recovering") })
	wPlain := doReq(t, srv.AdminHandler(), http.MethodGet, "/readyz", http.StatusServiceUnavailable)
	if !strings.Contains(wPlain.Body.String(), "recovering") {
		t.Fatalf("/readyz body = %q, want recovering", wPlain.Body.String())
	}

	srv.SetBackend(mptMgr, pub, nil)
	doReq(t, srv.AdminHandler(), http.MethodGet, "/readyz", http.StatusServiceUnavailable) // ServingState still nil
	seedIndex(t, db, pub, 100, map[string][]uint64{"com.example.k": {1}})
	doReq(t, srv.AdminHandler(), http.MethodGet, "/readyz", http.StatusOK)

	// Public mux never exposes operational endpoints
	for _, adminPath := range []string{"/healthz", "/readyz", "/syncz", "/metrics", "/debug/pprof/"} {
		doReq(t, srv.Handler(), http.MethodGet, adminPath, http.StatusNotFound)
	}
	wMetrics := doReq(t, srv.AdminHandler(), http.MethodGet, "/metrics", http.StatusOK)
	if !strings.Contains(wMetrics.Body.String(), "vindex_lookup_latency_seconds") {
		t.Fatalf("/metrics missing lookup latency metric")
	}
}

func TestReadServer_UISecurityAndCSP(t *testing.T) {
	srv, _, _, _ := setupEnv(t, 256, Config{})
	h := srv.Handler()

	w := doReq(t, h, http.MethodGet, "/", http.StatusOK)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET / Content-Type = %q, want text/html", ct)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, wantDirective := range []string{"script-src 'sha256-", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, wantDirective) {
			t.Errorf("CSP %q missing %q", csp, wantDirective)
		}
	}
	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("CSP must pin script SHA-256 instead of unsafe-inline: %q", csp)
	}

	htmlBody := w.Body.String()
	if !strings.Contains(htmlBody, "VIndex Web") {
		t.Fatal("GET / body missing 'VIndex Web'")
	}
	for _, banned := range []string{
		"cdn.tailwindcss.com",
		"fonts.googleapis.com",
		"config-limit",
		"Cryptographically Verified",
		"Inclusion Proof Valid",
		".innerHTML",
	} {
		if strings.Contains(htmlBody, banned) {
			t.Errorf("index.html contains banned substring %q", banned)
		}
	}

	doReq(t, h, http.MethodGet, "/index.html", http.StatusOK)
	wHead := doReq(t, h, http.MethodHead, "/", http.StatusOK)
	if wHead.Body.Len() != 0 {
		t.Fatalf("HEAD / body len = %d, want 0", wHead.Body.Len())
	}

	srvDisabled, _, _, _ := setupEnv(t, 256, Config{DisableUI: true})
	doReq(t, srvDisabled.Handler(), http.MethodGet, "/", http.StatusNotFound)
	doReq(t, srvDisabled.Handler(), http.MethodGet, "/index.html", http.StatusNotFound)
}

func TestCleanPathPrefix(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", ""},
		{"///", ""},
		{"  ", ""},
		{"indices/sumdb", "/indices/sumdb"},
		{"/indices/sumdb", "/indices/sumdb"},
		{"/indices/sumdb/", "/indices/sumdb"},
		{"///indices//sumdb///", "/indices/sumdb"},
	} {
		if got := cleanPathPrefix(tc.input); got != tc.want {
			t.Errorf("cleanPathPrefix(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadServer_PathPrefixAndHardenedTileServing(t *testing.T) {
	tmpDir := t.TempDir()
	fullTile := filepath.Join(tmpDir, "tile", "0", "000")
	partTile := filepath.Join(tmpDir, "tile", "0", "000.p", "5")
	if err := os.MkdirAll(filepath.Dir(partTile), 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	// Leading "<a " tests that nosniff + application/octet-stream prevents HTML MIME-sniffing
	fullBytes := []byte("<a binary tile payload>")
	if err := os.WriteFile(fullTile, fullBytes, 0o644); err != nil {
		t.Fatalf("WriteFile fullTile failed: %v", err)
	}
	if err := os.WriteFile(partTile, []byte("partial"), 0o644); err != nil {
		t.Fatalf("WriteFile partTile failed: %v", err)
	}

	// External secret file outside tmpDir/tile linked via symlink must be blocked by os.OpenRoot
	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(outsideFile, []byte("top-secret"), 0o600)
	_ = os.Symlink(outsideFile, filepath.Join(tmpDir, "tile", "escape"))

	srv, db, _, pub := setupEnv(t, 256, Config{
		PathPrefix:   "/indices/sumdb",
		OutputLogDir: tmpDir,
	})
	seedIndex(t, db, pub, 500, nil)
	h := srv.Handler()

	// Both /indices/sumdb (no trailing slash -> 200 without 3xx!) and /indices/sumdb/ serve UI
	doReq(t, h, http.MethodGet, "/indices/sumdb", http.StatusOK)
	doReq(t, h, http.MethodGet, "/indices/sumdb/", http.StatusOK)
	doReq(t, h, http.MethodGet, "/indices/sumdb/checkpoint", http.StatusOK)

	// Full tile: application/octet-stream + nosniff + immutable Cache-Control
	wFull := doReq(t, h, http.MethodGet, "/indices/sumdb/tile/0/000", http.StatusOK)
	if wFull.Header().Get("Content-Type") != "application/octet-stream" ||
		wFull.Header().Get("X-Content-Type-Options") != "nosniff" ||
		wFull.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" ||
		!bytes.Equal(wFull.Body.Bytes(), fullBytes) {
		t.Fatalf("unexpected full tile headers/body: %+v", wFull.Header())
	}

	// Partial tile: no-store Cache-Control
	wPart := doReq(t, h, http.MethodGet, "/indices/sumdb/tile/0/000.p/5", http.StatusOK)
	if wPart.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("partial tile Cache-Control = %q, want no-store", wPart.Header().Get("Cache-Control"))
	}

	// Directory enumeration, missing trailing slashes, traversal, symlink escape, and unprefixed paths -> 404 (never 301/200)
	for _, blocked := range []string{
		"/checkpoint",
		"/indices/sumdb/tile",
		"/indices/sumdb/tile/",
		"/indices/sumdb/tile/0",
		"/indices/sumdb/tile/0/",
		"/indices/sumdb/tile/escape",
		"/indices/sumdb//checkpoint",
		"/indices/sumdb/healthz",
		"/indices/sumdb/metrics",
	} {
		doReq(t, h, http.MethodGet, blocked, http.StatusNotFound)
	}

	for _, adminPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		doReq(t, srv.AdminHandler(), http.MethodGet, adminPath, http.StatusOK)
	}
}

func TestReadServer_ZeroByteMPTProofWireCases(t *testing.T) {
	// 1. Empty MPT: point non-inclusion and prefix both emit "proof\n" (no trailing space)
	srvEmpty, dbEmpty, _, pubEmpty := setupEnv(t, 64, Config{})
	seedIndex(t, dbEmpty, pubEmpty, 0, nil)
	for _, target := range []string{"/keys?key=com.example.absent.", "/keys?prefix=com.example."} {
		w := doReq(t, srvEmpty.Handler(), http.MethodGet, target, http.StatusOK)
		if !strings.HasPrefix(w.Body.String(), "c2sp.org/tlog-vindex-keys@v1\nproof\n\nc2sp.org/tlog-proof@v1\n") {
			t.Fatalf("%s on empty MPT did not emit bare 'proof\\n':\n%s", target, w.Body.String())
		}
		keysSec, bindSec := splitAndVerifyKeysWire(t, w.Body.Bytes())
		if len(keysSec.MPTProof) != 0 || len(keysSec.Matches) != 0 {
			t.Fatalf("unexpected keysSec on empty MPT: %+v", keysSec)
		}
		if err := mpt.VerifyKey(bindSec.MPTRoot, []byte("com.example.absent."), [32]byte{}, false, keysSec.MPTProof); err != nil {
			t.Fatalf("VerifyKey(empty MPT) failed: %v", err)
		}
	}

	// 2. Single-leaf MPT inclusion emits bare "proof\n"
	srvSingle, dbSingle, _, pubSingle := setupEnv(t, 64, Config{})
	rootsSingle := seedIndex(t, dbSingle, pubSingle, 10, map[string][]uint64{"com.example.only.": {3}})
	wSingle := doReq(t, srvSingle.Handler(), http.MethodGet, "/keys?key=com.example.only.", http.StatusOK)
	if !strings.HasPrefix(wSingle.Body.String(), "c2sp.org/tlog-vindex-keys@v1\nproof\ncom.example.only. ") {
		t.Fatalf("single-leaf inclusion did not emit bare 'proof\\n':\n%s", wSingle.Body.String())
	}
	keysSec1, bindSec1 := splitAndVerifyKeysWire(t, wSingle.Body.Bytes())
	if err := mpt.VerifyKey(bindSec1.MPTRoot, []byte("com.example.only."), rootsSingle["com.example.only."], true, keysSec1.MPTProof); err != nil {
		t.Fatalf("VerifyKey(single-leaf MPT) failed: %v", err)
	}

	// 3. Multi-leaf full-tree prefix match emits bare "proof\n"
	srvFullPref, dbFullPref, _, pubFullPref := setupEnv(t, 64, Config{})
	seedIndex(t, dbFullPref, pubFullPref, 20, map[string][]uint64{
		"com.example.a.": {1},
		"com.example.b.": {2},
	})
	wFullPref := doReq(t, srvFullPref.Handler(), http.MethodGet, "/keys?prefix=com.example.", http.StatusOK)
	if !strings.HasPrefix(wFullPref.Body.String(), "c2sp.org/tlog-vindex-keys@v1\nproof\ncom.example.a. ") {
		t.Fatalf("full-tree prefix match did not emit bare 'proof\\n':\n%s", wFullPref.Body.String())
	}
	keysSec2, bindSec2 := splitAndVerifyKeysWire(t, wFullPref.Body.Bytes())
	if err := mpt.VerifyPrefix(bindSec2.MPTRoot, []byte("com.example."), keysSec2.Matches, keysSec2.MPTProof); err != nil {
		t.Fatalf("VerifyPrefix(full-tree MPT) failed: %v", err)
	}
}

func TestReadServer_HandleKeys_ProofVerificationAndReversedDNSPolicy(t *testing.T) {
	pol, err := ParsePrefixPolicy("reversed-dns")
	if err != nil {
		t.Fatalf("ParsePrefixPolicy(reversed-dns) failed: %v", err)
	}
	if _, err := ParsePrefixPolicy("bogus"); err == nil {
		t.Fatal("expected error from ParsePrefixPolicy(bogus)")
	}

	srv, db, _, pub := setupEnv(t, 100, Config{PrefixPolicy: pol})
	ki := map[string][]uint64{
		"com.google.":      {0, 5},
		"com.google.*.":    {10, 15},
		"com.google.docs.": {20, 25},
		"com.google.mail.": {30, 35},
		"com.googleapis.":  {40, 45},
	}
	roots := seedIndex(t, db, pub, 500, ki)
	h := srv.Handler()

	t.Run("point_inclusion_and_non_inclusion_cryptographic_verification", func(t *testing.T) {
		wInc := doReq(t, h, http.MethodGet, "/keys?key=com.google.mail.", http.StatusOK)
		if wInc.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", wInc.Header().Get("Cache-Control"))
		}
		kSec, bSec := splitAndVerifyKeysWire(t, wInc.Body.Bytes())
		if len(kSec.Matches) != 1 || kSec.Matches[0].ValueRoot != roots["com.google.mail."] {
			t.Fatalf("unexpected point match: %+v", kSec.Matches)
		}
		if err := mpt.VerifyKey(bSec.MPTRoot, []byte("com.google.mail."), kSec.Matches[0].ValueRoot, true, kSec.MPTProof); err != nil {
			t.Fatalf("VerifyKey(inclusion) failed: %v", err)
		}

		wAbs := doReq(t, h, http.MethodGet, "/keys?key=com.google.absent.", http.StatusOK)
		kAbs, bAbs := splitAndVerifyKeysWire(t, wAbs.Body.Bytes())
		if len(kAbs.Matches) != 0 {
			t.Fatalf("expected 0 matches for absent key, got %d", len(kAbs.Matches))
		}
		if err := mpt.VerifyKey(bAbs.MPTRoot, []byte("com.google.absent."), [32]byte{}, false, kAbs.MPTProof); err != nil {
			t.Fatalf("VerifyKey(non-inclusion) failed: %v", err)
		}
	})

	t.Run("prefix_discovery_cryptographic_verification", func(t *testing.T) {
		wPref := doReq(t, h, http.MethodGet, "/keys?prefix=com.google.", http.StatusOK)
		kSec, bSec := splitAndVerifyKeysWire(t, wPref.Body.Bytes())
		gotKeys := make([]string, len(kSec.Matches))
		for i, m := range kSec.Matches {
			gotKeys[i] = m.Key
		}
		wantKeys := []string{"com.google.", "com.google.*.", "com.google.docs.", "com.google.mail."}
		if !slices.Equal(gotKeys, wantKeys) {
			t.Fatalf("prefix matches = %v, want %v", gotKeys, wantKeys)
		}
		if err := mpt.VerifyPrefix(bSec.MPTRoot, []byte("com.google."), kSec.Matches, kSec.MPTProof); err != nil {
			t.Fatalf("VerifyPrefix(matches) failed: %v", err)
		}

		wEmpty := doReq(t, h, http.MethodGet, "/keys?prefix=com.nonexistent.", http.StatusOK)
		kEmp, bEmp := splitAndVerifyKeysWire(t, wEmpty.Body.Bytes())
		if len(kEmp.Matches) != 0 {
			t.Fatalf("expected 0 matches, got %d", len(kEmp.Matches))
		}
		if err := mpt.VerifyPrefix(bEmp.MPTRoot, []byte("com.nonexistent."), kEmp.Matches, kEmp.MPTProof); err != nil {
			t.Fatalf("VerifyPrefix(empty) failed: %v", err)
		}
	})

	t.Run("reversed_dns_policy_and_psl_validation", func(t *testing.T) {
		for _, badPrefix := range []string{
			"com.",
			"uk.co.",
			"io.github.",
			"notatld.foo.",
			"notatld.sub.foo.",
			"com.a/b.",
			"com.-bad.",
			"com.bad-.",
			"com.*.",
			"com.g*o.",
			"com.*google.",
			"com.*.sub.",
			"com.Google.",
			"com..google.",
			"com.google",
		} {
			doReq(t, h, http.MethodGet, "/keys?prefix="+badPrefix, http.StatusBadRequest)
		}
		for _, goodPrefix := range []string{
			"uk.co.bbc.news.",
			"io.github.myorg.",
			"com.google.*.",
			"com.google._dmarc.",
		} {
			doReq(t, h, http.MethodGet, "/keys?prefix="+goodPrefix, http.StatusOK)
		}

		for _, denyAlias := range []string{"none", "disallow", "deny"} {
			denyPol, err := ParsePrefixPolicy(denyAlias)
			if err != nil {
				t.Fatalf("ParsePrefixPolicy(%q) failed: %v", denyAlias, err)
			}
			srvDeny := New(Config{Store: db, MPT: srv.backend.Load().mptMgr, Publisher: pub, PrefixPolicy: denyPol})
			doReq(t, srvDeny.Handler(), http.MethodGet, "/keys?prefix=com.google.", http.StatusBadRequest)
		}
	})

	t.Run("exact_max_prefix_keys_boundary_4_ok_vs_3_413", func(t *testing.T) {
		b := srv.backend.Load()
		srvAtCap := New(Config{Store: db, MPT: b.mptMgr, Publisher: pub, MaxPrefixKeys: 4})
		doReq(t, srvAtCap.Handler(), http.MethodGet, "/keys?prefix=com.google.", http.StatusOK)

		srvOverCap := New(Config{Store: db, MPT: b.mptMgr, Publisher: pub, MaxPrefixKeys: 3})
		doReq(t, srvOverCap.Handler(), http.MethodGet, "/keys?prefix=com.google.", http.StatusRequestEntityTooLarge)
	})
}

type failingLookupStore struct {
	err error
	res *kvstore.LookupResult
}

func (f failingLookupStore) Lookup([sha256.Size]byte, *uint64, uint64, uint64) (*kvstore.LookupResult, error) {
	return f.res, f.err
}

func TestReadServer_HandleValues_LockFreePaginationAndGuards(t *testing.T) {
	srv, db, mptMgr, pub := setupEnv(t, 100, Config{})

	keyStr := "github.com/google/uuid"
	indices := make([]uint64, 150)
	for i := range indices {
		indices[i] = uint64(i * 2)
	}
	roots := seedIndex(t, db, pub, 500, map[string][]uint64{keyStr: indices})
	h := srv.Handler()

	for _, badTarget := range []string{
		"/values?key=" + keyStr,
		"/values?key=" + keyStr + "&before=",
		"/values?key=" + keyStr + "&before=0",
		"/values?key=" + keyStr + "&before=0500",
		"/values?key=" + keyStr + "&before=+500",
		"/values?key=" + keyStr + "&before=-1",
		"/values?key=" + keyStr + "&before=18446744073709551616",
		"/values?key=" + keyStr + "&before=500&limit=50",
		"/values?key=" + keyStr + "&before=500&extra=1",
	} {
		doReq(t, h, http.MethodGet, badTarget, http.StatusBadRequest)
	}

	// before > InputLogSize -> 503 with Retry-After: 30
	wFuture := doReq(t, h, http.MethodGet, "/values?key="+keyStr+"&before=501", http.StatusServiceUnavailable)
	if wFuture.Header().Get("Retry-After") != "30" {
		t.Fatalf("Retry-After = %q, want 30", wFuture.Header().Get("Retry-After"))
	}

	// Absent key and 64-hex SHA-256 digest of keyStr both return 404 Not Found
	hexDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(keyStr)))
	for _, missing := range []string{"nonexistent", hexDigest} {
		doReq(t, h, http.MethodGet, "/values?key="+missing+"&before=500", http.StatusNotFound)
	}

	// Hold exclusive MPT write lock during /values to prove zero MPT lock contention
	mptMgr.Lock()
	wPage1 := doReq(t, h, http.MethodGet, "/values?key="+keyStr+"&before=500", http.StatusOK)
	mptMgr.Unlock()

	if cc := wPage1.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	valSec1, err := wire.ParseValuesResponse(wPage1.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseValuesResponse(page 1) failed: %v", err)
	}
	if valSec1.Preceding != 50 || valSec1.Indices[0] != 100 || len(valSec1.Indices) != 100 {
		t.Fatalf("unexpected page 1 parsed values: preceding=%d first=%d len=%d", valSec1.Preceding, valSec1.Indices[0], len(valSec1.Indices))
	}
	gotRoot, err := wire.ComputeValueLogRoot(valSec1.CompactRange, valSec1.Preceding, valSec1.Indices)
	if err != nil || gotRoot != roots[keyStr] {
		t.Fatalf("page 1 ComputeValueLogRoot = %x (err=%v), want %x", gotRoot, err, roots[keyStr])
	}

	wPage2 := doReq(t, h, http.MethodGet, fmt.Sprintf("/values?key=%s&before=%d", keyStr, valSec1.Indices[0]), http.StatusOK)
	valSec2, err := wire.ParseValuesResponse(wPage2.Body.Bytes())
	if err != nil || valSec2.Preceding != 0 || valSec2.Indices[0] != 0 || len(valSec2.Indices) != 50 {
		t.Fatalf("unexpected page 2: %+v err=%v", valSec2, err)
	}

	// Nil store -> 503; storage error -> 500 without leaking internal disk paths; pre-From index -> fail-closed 500
	srvNilStore := New(Config{MPT: mptMgr, Publisher: pub})
	doReq(t, srvNilStore.Handler(), http.MethodGet, "/values?key="+keyStr+"&before=500", http.StatusServiceUnavailable)

	srvErrStore := New(Config{Store: failingLookupStore{err: errors.New("/secret/pebble/MANIFEST-0001: I/O error")}, MPT: mptMgr, Publisher: pub})
	w500 := doReq(t, srvErrStore.Handler(), http.MethodGet, "/values?key="+keyStr+"&before=500", http.StatusInternalServerError)
	if strings.Contains(w500.Body.String(), "/secret/pebble") {
		t.Fatalf("500 response leaked internal storage path: %q", w500.Body.String())
	}

	pubFrom := tree.NewOutputPublisher(mpt.NewMem(), newMockOutputLog(t, "example.com/output"))
	pubFrom.SetFrom(50)
	pubFrom.SetServingState(&tree.ServingState{
		From:          50,
		InputLogSize:  100,
		RawCheckpoint: []byte("example.com/output\n1\nAAAA\n\n— sig\n"),
	})
	srvPreFrom := New(Config{
		Store:     failingLookupStore{res: &kvstore.LookupResult{MatchedIndices: []uint64{49, 60}}},
		MPT:       mptMgr,
		Publisher: pubFrom,
	})
	doReq(t, srvPreFrom.Handler(), http.MethodGet, "/values?key=test&before=50", http.StatusNotFound)
	doReq(t, srvPreFrom.Handler(), http.MethodGet, "/values?key=test&before=100", http.StatusInternalServerError)
}

func TestReadServer_RFC3986QueryAndCanonicalBounds(t *testing.T) {
	srv, db, _, pub := setupEnv(t, 100, Config{})
	plusKey := "golang.org/x/mod+v1"
	maxKey1024 := strings.Repeat("k", mpt.MaxKeyLen)
	roots := seedIndex(t, db, pub, 100, map[string][]uint64{
		"!":        {1},
		plusKey:    {7, 42},
		maxKey1024: {99},
	})
	h := srv.Handler()

	plusRoot := roots[plusKey]
	wantPlusRoot := base64.StdEncoding.EncodeToString(plusRoot[:])
	for _, target := range []string{
		"/keys?key=golang.org%2Fx%2Fmod%2Bv1",
		"/keys?key=golang.org/x/mod+v1",
		"/keys?prefix=golang.org%2Fx%2Fmod%2B",
		"/keys?prefix=golang.org/x/mod+",
	} {
		w := doReq(t, h, http.MethodGet, target, http.StatusOK)
		if !strings.Contains(w.Body.String(), "\n"+plusKey+" "+wantPlusRoot+"\n") {
			t.Fatalf("GET %s body missing %s: %s", target, plusKey, w.Body.String())
		}
	}
	doReq(t, h, http.MethodGet, "/keys?key=!", http.StatusOK)
	doReq(t, h, http.MethodGet, "/keys?key="+maxKey1024, http.StatusOK)

	for _, target := range []string{
		"/values?key=golang.org%2Fx%2Fmod%2Bv1&before=100",
		"/values?key=golang.org/x/mod+v1&before=100",
	} {
		w := doReq(t, h, http.MethodGet, target, http.StatusOK)
		if !strings.Contains(w.Body.String(), "\n\n7\n42\n") {
			t.Fatalf("GET %s unexpected body: %s", target, w.Body.String())
		}
	}

	for _, bad := range []string{
		"/keys",
		"/keys?foo",
		"/keys?key",
		"/keys?key=",
		"/keys?prefix=",
		"/keys?key=" + strings.Repeat("k", mpt.MaxKeyLen+1),
		"/keys?key=bad%00key",
		"/keys?key=bad%20key",
		"/keys?key=bad%7Fkey",
		"/keys?key=bad%80key",
		"/keys?key=bad%ZZ",
		"/keys?key=bad%2",
		"/keys?key=bad%",
		"/keys?prefix=com.example.%GG",
		"/keys?key=valid&other=1",
		"/keys?%ZZ=1&key=valid",
		"/keys?key=a&key=b",
		"/keys?prefix=a.&prefix=b.",
		"/keys?key=a&prefix=a",
		"/keys?key=valid&",
		"/keys?" + strings.Repeat("a=1&", 1100),
		"/values?key=bad%ZZ&before=1",
		"/values?key=valid&before=1%ZZ",
		"/values?key=valid&before=1&other=1",
		"/values?key=valid&before=1&before=2",
		"/values?key=valid&key=other&before=2",
		"/values?key=valid&noval",
	} {
		doReq(t, h, http.MethodGet, bad, http.StatusBadRequest)
	}
}

func TestReadServer_EmptyRawCheckpointAndConcurrentSetBackend(t *testing.T) {
	srv, _, mptMgr, pub := setupEnv(t, 64, Config{PathPrefix: "/v1"})
	h := srv.Handler()

	pub.SetServingState(&tree.ServingState{InputLogSize: 100})
	for _, target := range []string{"/v1/keys?key=test", "/v1/keys?prefix=test", "/v1/values?key=test&before=50", "/v1/checkpoint"} {
		doReq(t, h, http.MethodGet, target, http.StatusServiceUnavailable)
	}

	seedIndex(t, srv.store.(*kvstore.DB), pub, 100, map[string][]uint64{"com.example.k": {5}})

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 25 {
				if j%2 == 0 {
					srv.SetBackend(nil, nil, nil)
				} else {
					srv.SetBackend(mptMgr, pub, nil)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/keys?key=com.example.k", nil))
				if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
					t.Errorf("unexpected status %d during concurrent SetBackend", w.Code)
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkReadServer_Endpoints(b *testing.B) {
	srv, db, _, pub := setupEnv(b, 1024, Config{})
	ki := make(map[string][]uint64, 500)
	for i := range 500 {
		k := fmt.Sprintf("org.other%03d.svc.", i)
		if i < 25 {
			k = fmt.Sprintf("com.google.sub%03d.", i)
		}
		indices := make([]uint64, 64)
		for j := range indices {
			indices[j] = uint64(i*64 + j)
		}
		ki[k] = indices
	}
	seedIndex(b, db, pub, 50000, ki)
	h := srv.Handler()

	b.Run("Keys_PointLookup", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/keys?key=com.google.sub010.", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("Keys_PrefixLookup_25Matches", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("Values_Page1", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/values?key=com.google.sub010.&before=50000", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})
}
