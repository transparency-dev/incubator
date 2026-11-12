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

package client

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
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

type testKeys struct {
	outSigner   note.Signer
	outVerifier note.Verifier
	outVKey     string
}

func newTestKeys(t testing.TB) testKeys {
	t.Helper()
	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/output")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outSigner, _ := note.NewSigner(outSKey)
	outVerifier, _ := note.NewVerifier(outVKey)
	return testKeys{
		outSigner:   outSigner,
		outVerifier: outVerifier,
		outVKey:     outVKey,
	}
}

func (k testKeys) clientConfig(t testing.TB) Config {
	t.Helper()
	outPol, err := SingleKeyPolicy("example.com/output", k.outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	return Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}
}

func makeInputCP(size uint64) *log.Checkpoint {
	var hash [sha256.Size]byte
	if size == 0 {
		hash = wire.EmptyRoot()
	} else {
		hash = sha256.Sum256(fmt.Appendf(nil, "input-root-%d", size))
	}
	return &log.Checkpoint{
		Origin: "example.com/input",
		Size:   size,
		Hash:   hash[:],
	}
}

type testEnv struct {
	srv    *server.ReadServer
	db     *kvstore.DB
	mptMgr *mpt.Manager
	pub    *tree.OutputPublisher
	idxer  *kvstore.KVIndexer
	keys   testKeys
}

func newTestEnv(t testing.TB, chunkSize uint64) *testEnv {
	t.Helper()
	db, err := kvstore.Open("", &kvstore.Options{ChunkSize: chunkSize})
	if err != nil {
		t.Fatalf("kvstore.Open(in-memory) failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys := newTestKeys(t)
	mptMgr := mpt.NewMem()
	outLog, err := tree.NewPOSIXOutputLog(context.Background(), t.TempDir(), keys.outSigner, tree.WithOrigin("example.com/output"))
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog failed: %v", err)
	}
	t.Cleanup(func() { _ = outLog.Close() })
	pub := tree.NewOutputPublisher(mptMgr, outLog)
	pub.SetInputOrigin("example.com/input")
	idxer := kvstore.NewKVIndexer(db)
	srv := server.New(server.Config{Store: db, MPT: mptMgr, Publisher: pub})

	return &testEnv{srv: srv, db: db, mptMgr: mptMgr, pub: pub, idxer: idxer, keys: keys}
}

func (e *testEnv) seed(t testing.TB, startLeaf, endLeaf uint64, keyIndices map[string][]uint64) {
	t.Helper()
	ctx := context.Background()
	res, err := e.idxer.IndexMappedBatch(ctx, &kvstore.MappedBatch{
		StartLeafIdx: startLeaf,
		EndLeafIdx:   endLeaf,
		KeyIndices:   keyIndices,
	}, nil, 0)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}
	if _, err := e.pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, makeInputCP(endLeaf)); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}
}

func (e *testEnv) newClient(t testing.TB) *Client {
	t.Helper()
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cli, err := New(ts.URL, e.keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}
	return cli
}

func (e *testEnv) getRaw(path string) []byte {
	w := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Body.Bytes()
}

func collectValuesNewestFirst(ctx context.Context, mk MatchedKey) ([]uint64, error) {
	var res []uint64
	for idx, err := range mk.Values(ctx) {
		if err != nil {
			return nil, err
		}
		res = append(res, idx)
	}
	return res, nil
}

func TestDomainToCanonicalKey(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"example.com", "com.example."},
		{"Example.COM.", "com.example."},
		{"*.example.com", "com.example.*."},
		{"bücher.example.com", "com.example.xn--bcher-kva."},
		{"*.bücher.example.com", "com.example.xn--bcher-kva.*."},
		{"_dmarc.sub-1.mail.google.co.uk", "uk.co.google.mail.sub-1._dmarc."},
	} {
		got, err := DomainToCanonicalKey(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("DomainToCanonicalKey(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
		}
	}

	overlongLabel := strings.Repeat("a", 64) + ".com"
	overlongDomain := strings.Repeat("a.", 127) + "com"
	for _, bad := range []string{
		"",
		".",
		"*",
		"*.",
		"foo.*.bar.com",
		"a*b.example.com",
		"example..com",
		"bad space.com",
		"https://example.com",
		"example.com:443",
		"user@example.com",
		"-leading.example.com",
		"trailing-.example.com",
		"\u00a0example.com", // Non-ASCII NBSP must be rejected by IDNA2008, not stripped as whitespace
		overlongLabel,
		overlongDomain,
	} {
		if _, err := DomainToCanonicalKey(bad); !errors.Is(err, ErrBadRequest) {
			t.Errorf("DomainToCanonicalKey(%q) err = %v, want ErrBadRequest", bad, err)
		}
	}
}

type noOriginTestPolicy struct{ CheckpointPolicy }

type fixedOriginTestPolicy struct {
	CheckpointPolicy
	origin string
}

func (p fixedOriginTestPolicy) Origin() string { return p.origin }

func TestNewAndConfigValidation(t *testing.T) {
	keys := newTestKeys(t)
	validCfg := keys.clientConfig(t)

	for _, badURL := range []string{
		"",
		"ftp://example.com",
		"http://",
		"https://user:pass@example.com",
		"https://example.com/vindex?foo=bar",
		"https://example.com/vindex#frag",
	} {
		if _, err := New(badURL, validCfg); !errors.Is(err, ErrBadRequest) {
			t.Errorf("New(%q) err = %v, want ErrBadRequest", badURL, err)
		}
	}

	for _, badCfg := range []Config{
		{OutputLogPolicy: noOriginTestPolicy{validCfg.OutputLogPolicy}, ExpectedInputLogOrigin: "example.com/input"},
		{ExpectedOutputLogOrigin: "bad\norigin", OutputLogPolicy: validCfg.OutputLogPolicy, ExpectedInputLogOrigin: "example.com/input"},
		{ExpectedOutputLogOrigin: "example.com/output", ExpectedInputLogOrigin: "example.com/input"},
		{ExpectedOutputLogOrigin: "example.com/output", OutputLogPolicy: validCfg.OutputLogPolicy},
	} {
		if _, err := New("https://example.com", badCfg); !errors.Is(err, ErrBadRequest) {
			t.Errorf("New(badCfg %+v) err = %v, want ErrBadRequest", badCfg, err)
		}
		if _, err := VerifyKeysResponse([]byte("x"), "com.example.", false, badCfg); !errors.Is(err, ErrBadRequest) {
			t.Errorf("VerifyKeysResponse(badCfg %+v) err = %v, want ErrBadRequest", badCfg, err)
		}
	}

	// Policy implementing Origin() string auto-populates ExpectedOutputLogOrigin when omitted.
	inferredCfg := Config{
		OutputLogPolicy:        fixedOriginTestPolicy{CheckpointPolicy: validCfg.OutputLogPolicy, origin: "example.com/output"},
		ExpectedInputLogOrigin: "example.com/input",
	}
	if _, err := New("https://example.com", inferredCfg); err != nil {
		t.Fatalf("New with inferred ExpectedOutputLogOrigin failed: %v", err)
	}

	if _, err := WitnessPolicy("example.com/output", keys.outVerifier, nil, 0); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("WitnessPolicy(threshold=0) err = %v, want ErrBadRequest", err)
	}

	// Verify WithHTTPClient does not mutate caller's http.Client CheckRedirect hook.
	customHC := &http.Client{}
	if _, err := New("https://example.com", validCfg, WithHTTPClient(customHC)); err != nil {
		t.Fatalf("New with customHC failed: %v", err)
	}
	if customHC.CheckRedirect != nil {
		t.Fatal("WithHTTPClient mutated caller's CheckRedirect")
	}
}

func TestClient_PositiveInclusionAndNonInclusion(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, kvstore.ChunkSize)
	env.seed(t, 0, 100, map[string][]uint64{
		"target_key_1": {5, 20, 35},
		"target_key_2": {10},
	})
	cli := env.newClient(t)

	kr1, err := cli.LookupKey(ctx, "target_key_1")
	if err != nil {
		t.Fatalf("LookupKey(k1) failed: %v", err)
	}
	if len(kr1.Keys) != 1 || kr1.Keys[0].Key != "target_key_1" {
		t.Fatalf("unexpected LookupResult for k1: %+v", kr1)
	}
	if kr1.InputSize != 100 || kr1.OutputSize != 1 || kr1.InputOrigin != "example.com/input" || kr1.OutputOrigin != "example.com/output" {
		t.Fatalf("unexpected metadata: %+v", kr1)
	}
	indices1, err := collectValuesNewestFirst(ctx, kr1.Keys[0])
	if err != nil || !slices.Equal(indices1, []uint64{35, 20, 5}) {
		t.Fatalf("Values(k1) = %v, err=%v, want [35 20 5]", indices1, err)
	}

	kr2, err := cli.LookupKey(ctx, "target_key_2")
	if err != nil {
		t.Fatalf("LookupKey(k2) failed: %v", err)
	}
	indices2, err := collectValuesNewestFirst(ctx, kr2.Keys[0])
	if err != nil || !slices.Equal(indices2, []uint64{10}) {
		t.Fatalf("Values(k2) = %v, err=%v, want [10]", indices2, err)
	}

	krNon, err := cli.LookupKey(ctx, "unmapped_key")
	if err != nil || len(krNon.Keys) != 0 {
		t.Fatalf("LookupKey(unmapped) = %+v, err=%v", krNon, err)
	}
}

func TestClient_PaginationContinuation(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, 10)

	indices := make([]uint64, 250)
	for i := range indices {
		indices[i] = uint64(i)
	}
	env.seed(t, 0, 250, map[string][]uint64{"paginated_key": indices})

	var valuesReqs atomic.Int32
	h := env.srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/values") {
			valuesReqs.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, env.keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	kr, err := cli.LookupKey(ctx, "paginated_key")
	if err != nil || len(kr.Keys) != 1 {
		t.Fatalf("LookupKey = %+v, err=%v", kr, err)
	}

	var top5 []uint64
	for idx, err := range kr.Keys[0].Values(ctx) {
		if err != nil {
			t.Fatalf("Values early break failed: %v", err)
		}
		top5 = append(top5, idx)
		if len(top5) == 5 {
			break
		}
	}
	if !slices.Equal(top5, []uint64{249, 248, 247, 246, 245}) || valuesReqs.Load() != 1 {
		t.Fatalf("top5 = %v (reqs=%d), want [249..245] and 1 req", top5, valuesReqs.Load())
	}

	valuesReqs.Store(0)
	allDesc, err := collectValuesNewestFirst(ctx, kr.Keys[0])
	if err != nil || valuesReqs.Load() != 3 {
		t.Fatalf("full Values err=%v reqs=%d, want 3 reqs", err, valuesReqs.Load())
	}
	wantDesc := slices.Clone(indices)
	slices.Reverse(wantDesc)
	if !slices.Equal(allDesc, wantDesc) {
		t.Fatalf("allDesc len=%d, want 250 newest-first", len(allDesc))
	}
}

func TestClient_NegativeTamperCases(t *testing.T) {
	env := newTestEnv(t, kvstore.ChunkSize)
	keyStr := "tamper_key"
	env.seed(t, 0, 100, map[string][]uint64{keyStr: {10, 20, 30}})

	validKeysBody := string(env.getRaw("/keys?key=" + keyStr))
	validValuesBody := string(env.getRaw("/values?key=" + keyStr + "&before=100"))
	cfg := env.keys.clientConfig(t)

	keysResp, err := VerifyKeysResponse([]byte(validKeysBody), keyStr, false, cfg)
	if err != nil {
		t.Fatalf("Baseline valid keys body failed: %v", err)
	}
	// Standalone VerifyKeysResponse returns unbound MatchedKey -> Values() must yield ErrBadRequest.
	for _, vErr := range keysResp.Keys[0].Values(context.Background()) {
		if !errors.Is(vErr, ErrBadRequest) {
			t.Fatalf("unbound MatchedKey.Values err = %v, want ErrBadRequest", vErr)
		}
	}

	expectedValueRoot := keysResp.Keys[0].ValueRoot
	if _, err := VerifyValuesResponse([]byte(validValuesBody), expectedValueRoot, 0, 100); err != nil {
		t.Fatalf("Baseline valid values body failed: %v", err)
	}

	// 1. Corrupted Output Log checkpoint size / proof / extra leaf / MPT proof / missing stanza
	for _, bad := range []string{
		strings.Replace(validKeysBody, "example.com/output\n1\n", "example.com/output\n2\n", 1),
		strings.Replace(validKeysBody, "index 0\n", "index 0\nbm9uc2Vuc2VoYXNoCg==\n", 1),
		strings.Replace(validKeysBody, "c2sp.org/tlog-vindex-keys@v1\nproof\n", "c2sp.org/tlog-vindex-keys@v1\nproof AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n", 1),
		strings.SplitN(validKeysBody, "\n\n", 2)[0],
	} {
		if _, err := VerifyKeysResponse([]byte(bad), keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
			t.Errorf("expected ErrVerificationFailed, got %v", err)
		}
	}

	// Validly signed proof for keyStr presented as answer for a different target key -> must fail key match check.
	if _, err := VerifyKeysResponse([]byte(validKeysBody), "different_target", false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("expected ErrVerificationFailed when keys[0].Key != target, got %v", err)
	}

	// Mismatched expected origins with validly signed response.
	wrongInCfg := cfg
	wrongInCfg.ExpectedInputLogOrigin = "other.example/input"
	if _, err := VerifyKeysResponse([]byte(validKeysBody), keyStr, false, wrongInCfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("expected ErrVerificationFailed on InputOrigin mismatch, got %v", err)
	}

	// Corrupted Output Log extra leaf wraps wire.ErrOutputLogCorrupted and ErrVerificationFailed.
	for _, l := range strings.Split(validKeysBody, "\n") {
		if strings.HasPrefix(l, "extra ") {
			corruptExtra := "extra " + base64.StdEncoding.EncodeToString([]byte("corrupt_v1_leaf_without_header"))
			tamperedExtra := strings.Replace(validKeysBody, l, corruptExtra, 1)
			_, err := VerifyKeysResponse([]byte(tamperedExtra), keyStr, false, cfg)
			if !errors.Is(err, ErrVerificationFailed) || !errors.Is(err, wire.ErrOutputLogCorrupted) {
				t.Errorf("corrupted extra leaf err = %v, want ErrVerificationFailed + ErrOutputLogCorrupted", err)
			}
			break
		}
	}

	// Validly signed non-tip Output Log proof (index 0 in output_size 2) and output_size 0 checkpoint.
	mptRoot := keysResp.MPTRoot
	inCP := makeInputCP(100)
	outLeaf0 := wire.FormatOutputLogLeafFull(mptRoot, 0, inCP)
	outLeaf1 := wire.FormatOutputLogLeafFull(mptRoot, 0, makeInputCP(200))
	h0, h1 := wire.LeafHash(outLeaf0), wire.LeafHash(outLeaf1)
	root2 := wire.InteriorHash(h0, h1)
	signedOut2, _ := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/output\n2\n%s\n", base64.StdEncoding.EncodeToString(root2[:])),
	}, env.keys.outSigner)
	nonTipBody := wire.FormatKeysResponseFull(signedOut2, 0, mptRoot, 0, inCP, [][sha256.Size]byte{h1}, "", nil, []wire.KeyValueRoot{{Key: keyStr, ValueRoot: expectedValueRoot}})
	if _, err := VerifyKeysResponse(nonTipBody, keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("expected ErrVerificationFailed for non-tip index 0 at output_size 2, got %v", err)
	}

	emptyOutHash := wire.EmptyRoot()
	signedOut0, _ := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/output\n0\n%s\n", base64.StdEncoding.EncodeToString(emptyOutHash[:])),
	}, env.keys.outSigner)
	size0OutBody := wire.FormatKeysResponseFull(signedOut0, 0, wire.EmptyRoot(), 0, makeInputCP(0), nil, "", nil, nil)
	if _, err := VerifyKeysResponse(size0OutBody, keyStr, false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("expected ErrVerificationFailed for output_size 0, got %v", err)
	}

	// Empty indexed range (input_size == from) must reject non-empty MPTRoot even on 0-match non-inclusion/prefix responses.
	envEmpty := newTestEnv(t, kvstore.ChunkSize)
	forgedMPTRoot, _ := envEmpty.mptMgr.CommitKeysWithVersion(map[string][32]byte{keyStr: sha256.Sum256([]byte("forged-vr"))}, 100)
	nonIncProof, _, _, _ := envEmpty.mptMgr.ProveKey([]byte("absent_key"))
	inCP100 := makeInputCP(100)
	forgedOutLeaf := wire.FormatOutputLogLeafFull(forgedMPTRoot, 100, inCP100)
	forgedOutRoot := wire.LeafHash(forgedOutLeaf)
	forgedOutSigned, _ := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(forgedOutRoot[:])),
	}, envEmpty.keys.outSigner)
	forgedNonIncBody := wire.FormatKeysResponseFull(forgedOutSigned, 0, forgedMPTRoot, 100, inCP100, nil, "", nonIncProof, nil)
	if _, err := VerifyKeysResponse(forgedNonIncBody, "absent_key", false, envEmpty.keys.clientConfig(t)); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when input_size == from has non-empty MPTRoot on non-inclusion, got: %v", err)
	}

	// input_size == 0 with non-empty input-root must be rejected.
	badZeroHash := sha256.Sum256([]byte("non-empty-at-size-0"))
	badZeroInCP := &log.Checkpoint{Origin: "example.com/input", Size: 0, Hash: badZeroHash[:]}
	badZeroLeaf := wire.FormatOutputLogLeafFull(wire.EmptyRoot(), 0, badZeroInCP)
	badZeroOutRoot := wire.LeafHash(badZeroLeaf)
	badZeroSigned, _ := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(badZeroOutRoot[:])),
	}, envEmpty.keys.outSigner)
	badZeroBody := wire.FormatKeysResponseFull(badZeroSigned, 0, wire.EmptyRoot(), 0, badZeroInCP, nil, "", nil, nil)
	if _, err := VerifyKeysResponse(badZeroBody, "absent_key", false, envEmpty.keys.clientConfig(t)); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when input_size == 0 has non-empty input_root, got: %v", err)
	}

	// EmptyRoot as a key's ValueRoot must be rejected.
	mptEmptyVR := mpt.NewMem()
	rootEmptyVR, _ := mptEmptyVR.CommitKeysWithVersion(map[string][32]byte{keyStr: wire.EmptyRoot()}, 10)
	proofEmptyVR, _, _, _ := mptEmptyVR.ProveKey([]byte(keyStr))
	leafEmptyVR := wire.FormatOutputLogLeafFull(rootEmptyVR, 0, makeInputCP(10))
	outRootEmptyVR := wire.LeafHash(leafEmptyVR)
	signedEmptyVR, _ := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(outRootEmptyVR[:])),
	}, envEmpty.keys.outSigner)
	bodyEmptyVR := wire.FormatKeysResponseFull(signedEmptyVR, 0, rootEmptyVR, 0, makeInputCP(10), nil, "", proofEmptyVR, []wire.KeyValueRoot{{Key: keyStr, ValueRoot: wire.EmptyRoot()}})
	if _, err := VerifyKeysResponse(bodyEmptyVR, keyStr, false, envEmpty.keys.clientConfig(t)); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed for EmptyRoot ValueRoot, got: %v", err)
	}

	// Tampered / unordered / out-of-bounds indices in values response.
	for _, badVals := range []string{
		strings.Replace(validValuesBody, "20\n", "21\n", 1),
		strings.Replace(validValuesBody, "20\n30\n", "30\n20\n", 1),
		strings.Replace(validValuesBody, "30\n", "150\n", 1),
	} {
		if _, err := VerifyValuesResponse([]byte(badVals), expectedValueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
			t.Errorf("Tampered values should fail with ErrVerificationFailed, got %v", err)
		}
	}
}

func TestClient_Values_ContinuationFaults(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, 100)

	keyStr := "mismatch_key"
	indices := make([]uint64, 250)
	for i := range indices {
		indices[i] = uint64(i * 10)
	}
	env.seed(t, 0, 2500, map[string][]uint64{keyStr: indices})

	h := env.srv.Handler()
	var mode atomic.Int32 // 0 = tamper page 2, 1 = 404 on page 2
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("before") == "1500" && mode.Load() == 1 {
			http.Error(w, "missing continuation page", http.StatusNotFound)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		body := rec.Body.String()
		if r.URL.Query().Get("before") == "1500" && mode.Load() == 0 {
			body = strings.Replace(body, "\n1000\n", "\n1001\n", 1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	cli, err := New(ts.URL, env.keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}
	kr, err := cli.LookupKey(ctx, keyStr)
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}

	if _, err = collectValuesNewestFirst(ctx, kr.Keys[0]); !errors.Is(err, ErrVerificationFailed) || !strings.Contains(err.Error(), "value log root mismatch") {
		t.Fatalf("expected ErrVerificationFailed value log root mismatch, got: %v", err)
	}

	mode.Store(1)
	if _, err = collectValuesNewestFirst(ctx, kr.Keys[0]); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed on HTTP 404 continuation page, got: %v", err)
	}
}

func TestClient_PrefixLookupAndTwoSidedSoundness(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, kvstore.ChunkSize)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."
	env.seed(t, 0, 100, map[string][]uint64{
		kApex:                {1, 10},
		kMail:                {2, 20, 30},
		kDocs:                {3},
		kWild:                {4, 40},
		"com.googleapis.www.": {99},
	})

	cfg := env.keys.clientConfig(t)
	cli := env.newClient(t)

	prefixResp, err := cli.LookupPrefix(ctx, "com.google.")
	if err != nil || len(prefixResp.Keys) != 4 {
		t.Fatalf("LookupPrefix = %+v, err=%v", prefixResp, err)
	}
	for i, wantKey := range []string{kApex, kWild, kDocs, kMail} {
		if prefixResp.Keys[i].Key != wantKey {
			t.Errorf("Keys[%d].Key = %q, want %q", i, prefixResp.Keys[i].Key, wantKey)
		}
	}
	mailIndices, err := collectValuesNewestFirst(ctx, prefixResp.Keys[3])
	if err != nil || !slices.Equal(mailIndices, []uint64{30, 20, 2}) {
		t.Fatalf("Values(kMail) = %v, err=%v, want [30 20 2]", mailIndices, err)
	}

	emptyPrefixResp, err := cli.LookupPrefix(ctx, "com.nonexistent.")
	if err != nil || len(emptyPrefixResp.Keys) != 0 {
		t.Fatalf("LookupPrefix(com.nonexistent.) = %+v, err=%v", emptyPrefixResp, err)
	}

	broaderBody := env.getRaw("/keys?prefix=com.")
	if _, err := VerifyKeysResponse(broaderBody, "com.google.", true, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("VerifyKeysResponse must reject broader subtree, got %v", err)
	}
	if _, err := VerifyKeysResponse(broaderBody, "com.google.", false, cfg); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("VerifyKeysResponse point lookup must reject multiple keys, got %v", err)
	}

	// HTTP 413 on LookupPrefix -> ErrTooManyKeys; HTTP 400 prefix policy rejection -> ErrBadRequest.
	tsCap := httptest.NewServer(server.New(server.Config{Store: env.db, MPT: env.mptMgr, Publisher: env.pub, MaxPrefixKeys: 2}).Handler())
	defer tsCap.Close()
	cliCap, _ := New(tsCap.URL, cfg, WithHTTPClient(tsCap.Client()))
	if _, err := cliCap.LookupPrefix(ctx, "com.google."); !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("expected ErrTooManyKeys on HTTP 413, got: %v", err)
	}

	disallowPol, _ := server.ParsePrefixPolicy("none")
	tsNone := httptest.NewServer(server.New(server.Config{Store: env.db, MPT: env.mptMgr, Publisher: env.pub, PrefixPolicy: disallowPol}).Handler())
	defer tsNone.Close()
	cliNone, _ := New(tsNone.URL, cfg, WithHTTPClient(tsNone.Client()))
	if _, err := cliNone.LookupPrefix(ctx, "com.google."); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on HTTP 400 prefix policy rejection, got: %v", err)
	}
}

func TestClient_ValuesTruncationAndCompactRangeValidation(t *testing.T) {
	valueRoot, err := wire.ComputeValueLogRoot(nil, 0, []uint64{10, 20})
	if err != nil {
		t.Fatalf("ComputeValueLogRoot failed: %v", err)
	}

	validBody := "c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n10\n20\n"
	if _, err := VerifyValuesResponse([]byte(validBody), valueRoot, 0, 100); err != nil {
		t.Fatalf("expected valid values response to pass, got: %v", err)
	}
	for _, badRoot := range [][32]byte{{}, wire.EmptyRoot()} {
		if _, err := VerifyValuesResponse([]byte(validBody), badRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("expected VerifyValuesResponse to reject invalid expectedValueRoot %x, got %v", badRoot, err)
		}
	}

	dummyHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, bad := range []string{
		fmt.Sprintf("c2sp.org/tlog-vindex-values@v1\npreceding 0\n%s\n\n10\n20\n", dummyHash),
		"c2sp.org/tlog-vindex-values@v1\npreceding 5\n\n10\n20\n",
		"c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n",
		fmt.Sprintf("c2sp.org/tlog-vindex-values@v1\npreceding 64\n%s\n\n10\n20\n", dummyHash),
	} {
		if _, err := VerifyValuesResponse([]byte(bad), valueRoot, 0, 100); !errors.Is(err, ErrVerificationFailed) {
			t.Errorf("expected ErrVerificationFailed for %q, got %v", bad, err)
		}
	}
}

func TestStateless_VerifyKeysAndValuesResponse(t *testing.T) {
	env := newTestEnv(t, 64)
	env.pub.SetFrom(50)

	kTest := "com.example.stateless"
	env.seed(t, 50, 100, map[string][]uint64{kTest: {55, 60, 75}})
	body1 := env.getRaw("/keys?key=" + kTest)

	env.seed(t, 100, 150, map[string][]uint64{kTest: {110}})
	body2 := env.getRaw("/keys?key=" + kTest)

	cfg := env.keys.clientConfig(t)
	kr2, err := VerifyKeysResponse(body2, kTest, false, cfg)
	if err != nil || len(kr2.Keys) != 1 || kr2.From != 50 || kr2.InputSize != 150 || kr2.OutputSize != 2 {
		t.Fatalf("VerifyKeysResponse(body2) = %+v, err=%v", kr2, err)
	}
	kr1, err := VerifyKeysResponse(body1, kTest, false, cfg)
	if err != nil || len(kr1.Keys) != 1 || kr1.From != 50 || kr1.InputSize != 100 || kr1.OutputSize != 1 {
		t.Fatalf("VerifyKeysResponse(body1) = %+v, err=%v", kr1, err)
	}

	comp0 := sha256.Sum256([]byte("compact-prefix-4"))
	comp1 := sha256.Sum256([]byte("compact-prefix-1"))
	pageIndices := []uint64{55, 58, 59}
	valRoot, _ := wire.ComputeValueLogRoot([][32]byte{comp0, comp1}, 5, pageIndices)
	rawVals := wire.FormatValuesResponse(5, [][32]byte{comp0, comp1}, pageIndices)
	vr, err := VerifyValuesResponse(rawVals, valRoot, 50, 60)
	if err != nil {
		t.Fatalf("VerifyValuesResponse valid from=50 failed: %v", err)
	}
	wantPrevRoot, _ := wire.ComputeValueLogRoot([][32]byte{comp0, comp1}, 5, nil)
	if nextBefore, nextRoot, ok := vr.NextPage(); !ok || nextBefore != 55 || nextRoot != wantPrevRoot {
		t.Fatalf("unexpected NextPage: before=%d root=%x wantRoot=%x ok=%v", nextBefore, nextRoot, wantPrevRoot, ok)
	}

	for _, rng := range [][2]uint64{{50, 50}, {60, 50}, {0, 0}, {56, 60}, {52, 60}} {
		if _, err := VerifyValuesResponse(rawVals, valRoot, rng[0], rng[1]); !errors.Is(err, ErrVerificationFailed) {
			t.Errorf("range [%d, %d) expected ErrVerificationFailed, got %v", rng[0], rng[1], err)
		}
	}
}

func TestPercentEncodeCanonicalKeyInQueries(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, 64)
	specialKey := "pkg+v1.2_3-rc~final/mod"
	env.seed(t, 0, 50, map[string][]uint64{specialKey: {7, 42}})

	var capturedRawQueries []string
	h := env.srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawQueries = append(capturedRawQueries, r.URL.RawQuery)
		h.ServeHTTP(w, r)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, env.keys.clientConfig(t), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	kr, err := cli.LookupKey(ctx, specialKey)
	if err != nil {
		t.Fatalf("LookupKey(%q) failed: %v", specialKey, err)
	}
	indices, err := collectValuesNewestFirst(ctx, kr.Keys[0])
	if err != nil || !slices.Equal(indices, []uint64{42, 7}) || len(capturedRawQueries) != 2 {
		t.Fatalf("Values(%q) = %v, err=%v, queries=%d", specialKey, indices, err, len(capturedRawQueries))
	}
	for _, rq := range capturedRawQueries {
		if !strings.Contains(rq, "pkg%2Bv1.2_3-rc~final%2Fmod") {
			t.Errorf("expected RFC 3986 unreserved encoding in RawQuery, got %q", rq)
		}
	}
}

func TestClient_PolicyQuorumAndHTTPTransportEdgeCases(t *testing.T) {
	ctx := context.Background()
	keys := newTestKeys(t)

	genWitness := func(name string) (note.Signer, note.Verifier, string) {
		sKey, rawVKey, err := note.GenerateKey(rand.Reader, name)
		if err != nil {
			t.Fatalf("note.GenerateKey(%s) failed: %v", name, err)
		}
		cs, _ := f_note.NewSignerForCosignatureV1(sKey)
		cosigVKey, _ := f_note.VKeyToCosignatureV1(rawVKey)
		cv, _ := f_note.NewVerifier(cosigVKey)
		return cs, cv, cosigVKey
	}

	w1Signer, w1Verifier, w1VKey := genWitness("witness1.example.com")
	w2Signer, w2Verifier, w2VKey := genWitness("witness2.example.com")
	_, w3Verifier, w3VKey := genWitness("witness3.example.com")

	outWitnessPol, err := WitnessPolicy("example.com/output", keys.outVerifier, []note.Verifier{w1Verifier, w2Verifier, w3Verifier}, 2)
	if err != nil {
		t.Fatalf("WitnessPolicy failed: %v", err)
	}
	policyText := fmt.Sprintf("log %s\nwitness w1 %s\nwitness w2 %s\nwitness w3 %s\ngroup g 2 w1 w2 w3\nquorum g\n",
		keys.outVKey, w1VKey, w2VKey, w3VKey)
	parsedPol, err := ParsePolicy([]byte(policyText))
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}

	mptMgr := mpt.NewMem()
	kTest := "com.google."
	vr := sha256.Sum256([]byte("vr-1"))
	mptRoot, _ := mptMgr.CommitKeysWithVersion(map[string][32]byte{kTest: vr}, 50)
	mptProof, _, _, _ := mptMgr.ProveKey([]byte(kTest))

	inCP := makeInputCP(50)
	outRoot := wire.LeafHash(wire.FormatOutputLogLeafFull(mptRoot, 0, inCP))
	outText := fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))

	buildKeysBody := func(signers ...note.Signer) []byte {
		outSigned, sErr := note.Sign(&note.Note{Text: outText}, signers...)
		if sErr != nil {
			t.Fatalf("note.Sign(output) failed: %v", sErr)
		}
		return wire.FormatKeysResponseFull(outSigned, 0, mptRoot, 0, inCP, nil, "", mptProof, []wire.KeyValueRoot{{Key: kTest, ValueRoot: vr}})
	}

	if _, err := VerifyKeysResponse(buildKeysBody(keys.outSigner, w1Signer), kTest, false, Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outWitnessPol,
		ExpectedInputLogOrigin:  "example.com/input",
	}); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when 1-of-3 witnesses signed, got: %v", err)
	}

	body2Witnesses := buildKeysBody(keys.outSigner, w1Signer, w2Signer)
	for _, pol := range []CheckpointPolicy{outWitnessPol, parsedPol} {
		if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, Config{
			ExpectedOutputLogOrigin: "example.com/output",
			OutputLogPolicy:         pol,
			ExpectedInputLogOrigin:  "example.com/input",
		}); err != nil {
			t.Fatalf("expected 2-of-3 policy to pass, got: %v", err)
		}
	}

	// Transport edge cases: 302 with Location, 304 without Location, 503 with Retry-After, bad Content-Type, >32 MiB body.
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/keys?key=com.google.", http.StatusFound)
	})
	mux.HandleFunc("/notmod/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	mux.HandleFunc("/unavail/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "45")
		http.Error(w, "recovering", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/html/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body2Witnesses)
	})
	mux.HandleFunc("/huge/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxResponseBodyBytes+16))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	makeSubCli := func(sub string) *Client {
		c, cErr := New(ts.URL+sub, Config{
			ExpectedOutputLogOrigin: "example.com/output",
			OutputLogPolicy:         outWitnessPol,
			ExpectedInputLogOrigin:  "example.com/input",
		}, WithHTTPClient(ts.Client()))
		if cErr != nil {
			t.Fatalf("New(%s) failed: %v", sub, cErr)
		}
		return c
	}

	if _, err := makeSubCli("/redirect").LookupKey(ctx, kTest); err == nil || !strings.Contains(err.Error(), "redirects (3xx) are forbidden") {
		t.Fatalf("expected LookupKey to reject 302 redirect, got: %v", err)
	}
	if _, err := makeSubCli("/notmod").LookupKey(ctx, kTest); err == nil || !strings.Contains(err.Error(), "3xx") {
		t.Fatalf("expected LookupKey to reject 304 without Location, got: %v", err)
	}
	if _, err := makeSubCli("/unavail").LookupKey(ctx, kTest); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "Retry-After: 45") {
		t.Fatalf("expected ErrUnavailable with Retry-After: 45, got: %v", err)
	}
	if _, err := makeSubCli("/html").LookupKey(ctx, kTest); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed on text/html Content-Type, got: %v", err)
	}
	if _, err := makeSubCli("/huge").LookupKey(ctx, kTest); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed on >32 MiB response body, got: %v", err)
	}
}

func TestClient_DependencyBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{range .Imports}}{{.}}\n{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, string(out))
	}
	allowedExternal := map[string]bool{
		"golang.org/x/mod/sumdb/note":                                true,
		"golang.org/x/net/idna":                                      true,
		"github.com/transparency-dev/formats/log":                    true,
		"github.com/transparency-dev/merkle/proof":                   true,
		"github.com/transparency-dev/merkle/rfc6962":                 true,
		"github.com/transparency-dev/incubator/vindex/internal/mpt":  true,
		"github.com/transparency-dev/incubator/vindex/internal/wire": true,
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if imp == "" || !strings.Contains(imp, ".") {
			continue
		}
		if !allowedExternal[imp] {
			t.Errorf("forbidden direct import in vindex/client: %q", imp)
		}
	}
}

func BenchmarkClient_VerifyKeysAndValues(b *testing.B) {
	env := newTestEnv(b, 64)
	kApex := "com.google."
	kMail := "com.google.mail."

	mailIndices := make([]uint64, 128)
	for i := range mailIndices {
		mailIndices[i] = uint64(i*10 + 1)
	}
	env.seed(b, 0, 2000, map[string][]uint64{
		kApex:              {1, 10},
		kMail:              mailIndices,
		"com.google.docs.": {3},
		"com.google.*.":    {4, 40},
	})

	pointBytes := env.getRaw("/keys?key=com.google.mail.")
	prefixBytes := env.getRaw("/keys?prefix=com.google.")
	valuesBytes := env.getRaw("/values?key=com.google.mail.&before=2000")

	cfg := env.keys.clientConfig(b)
	keysResp, err := VerifyKeysResponse(pointBytes, kMail, false, cfg)
	if err != nil {
		b.Fatalf("VerifyKeysResponse failed: %v", err)
	}
	mailValueRoot := keysResp.Keys[0].ValueRoot

	b.Run("VerifyKeysResponse_Point", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyKeysResponse(pointBytes, kMail, false, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("VerifyKeysResponse_Prefix4Keys", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyKeysResponse(prefixBytes, kApex, true, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("VerifyValuesResponse_ZeroMPTContinuation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyValuesResponse(valuesBytes, mailValueRoot, keysResp.From, 2000); err != nil {
				b.Fatal(err)
			}
		}
	})
}
