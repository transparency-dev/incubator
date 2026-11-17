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

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

type verifierTestCluster struct {
	*testCluster
	inLogServer       *httptest.Server
	outLogServer      *httptest.Server
	inCheckpointCalls atomic.Int64
}

func newVerifierTestCluster(t *testing.T, ctx context.Context, chunkSize uint64) *verifierTestCluster {
	t.Helper()
	baseCluster := newTestCluster(t, ctx, chunkSize)
	vtc := &verifierTestCluster{testCluster: baseCluster}

	inFs := http.FileServer(http.Dir(baseCluster.inLogDir))
	inMux := http.NewServeMux()
	inMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checkpoint" || strings.HasSuffix(r.URL.Path, "/checkpoint") {
			vtc.inCheckpointCalls.Add(1)
		}
		inFs.ServeHTTP(w, r)
	})
	vtc.inLogServer = httptest.NewServer(inMux)
	t.Cleanup(vtc.inLogServer.Close)

	vtc.outLogServer = httptest.NewServer(http.FileServer(http.Dir(baseCluster.storage.OutputLogDir)))
	t.Cleanup(vtc.outLogServer.Close)

	return vtc
}

func (c *verifierTestCluster) newVerifierConfig(t *testing.T, wasmHost *vindex.WASMHost) auditor.Config {
	t.Helper()
	tmpDir := t.TempDir()
	inPolicy, err := wire.BuildPolicy(c.inOrigin, c.inVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(input) failed: %v", err)
	}
	outPolicy, err := wire.BuildPolicy(c.outOrigin, c.outVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(output) failed: %v", err)
	}
	return auditor.Config{
		InputLogURL:     c.inLogServer.URL,
		InputLogOrigin:  c.inOrigin,
		InputLogPolicy:  inPolicy,
		OutputLogURL:    c.outLogServer.URL,
		OutputLogOrigin: c.outOrigin,
		OutputLogPolicy: outPolicy,
		WASMHost:        wasmHost,
		DBPath:          filepath.Join(tmpDir, "verifier_db"),
		MPTDir:          testMPTDir(tmpDir, "verifier_mpt"),
		PollInterval:    50 * time.Millisecond,
	}
}

func probeAdminEndpoint(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	h.ServeHTTP(rec, req)
	return rec
}

func TestE2E_HonestSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64)
	baseMismatches := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

	var batch1 [][]byte
	for i := range 10 {
		batch1 = append(batch1, fmt.Appendf(nil, "entry_%02d", i))
	}
	vtc.appendLeaves(batch1...)

	mapper := newTestWASMHost(t)
	engine, err := vtc.newEngine(mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}

	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}
	if vtc.inCheckpointCalls.Load() == 0 {
		t.Fatal("expected InputLog /checkpoint to be fetched and verified during auditor sync, got 0 requests")
	}

	st := v.Status()
	if st.IsHalted || st.HaltError != nil {
		t.Fatalf("verifier unexpectedly halted: %+v", st)
	}
	if st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 10 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 0", m)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal) - baseMismatches; c != 0 {
		t.Errorf("vindex_auditor_root_mismatches_total delta = %v, want 0", c)
	}

	adminH := v.AdminHandler()
	for _, opPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/"} {
		if rec := probeAdminEndpoint(t, adminH, opPath); rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", opPath, rec.Code)
		}
	}

	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	v2, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New restart failed: %v", err)
	}
	t.Cleanup(func() { _ = v2.Close() })

	if v2.Status().VerifiedOutputSize != 1 || v2.Status().VerifiedInputSize != 10 {
		t.Fatalf("reopened verifier recovered status mismatch: %+v", v2.Status())
	}

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	daemonCtx, daemonCancel := context.WithCancel(ctx)
	defer daemonCancel()
	runDone := make(chan error, 1)
	go func() { runDone <- v2.Run(daemonCtx) }()
	defer func() {
		daemonCancel()
		if rErr := <-runDone; rErr != nil && !errors.Is(rErr, context.Canceled) {
			t.Errorf("v2.Run error: %v", rErr)
		}
	}()

	var batch2 [][]byte
	for i := 10; i < 20; i++ {
		batch2 = append(batch2, fmt.Appendf(nil, "entry_%02d", i))
	}
	vtc.appendLeaves(batch2...)

	catchupDeadline := time.Now().Add(10 * time.Second)
	caughtUp := false
	for time.Now().Before(catchupDeadline) {
		s := v2.Status()
		if s.VerifiedOutputSize >= 2 && s.VerifiedInputSize >= 20 {
			caughtUp = true
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !caughtUp {
		t.Fatalf("verifier daemon failed to catch up to leaf 1; status: %+v", v2.Status())
	}
	if v2.Status().IsHalted {
		t.Fatalf("verifier halted during daemon mode: %v", v2.Status().HaltError)
	}
}

func TestE2E_TamperedRootDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	t.Cleanup(func() {
		metrics.ResetAuditorRootMismatch()
		metrics.ResetAuditorHalted()
	})

	vtc := newVerifierTestCluster(t, ctx, 64)
	baseMismatches := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

	var batch1 [][]byte
	for i := range 5 {
		batch1 = append(batch1, fmt.Appendf(nil, "record_%d", i))
	}
	vtc.appendLeaves(batch1...)

	mapper := newTestWASMHost(t)
	engine, err := vtc.newEngine(mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.SyncOnce(ctx); err != nil {
		_ = engine.Close()
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close failed: %v", err)
	}

	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}
	authenticRoot0 := v.Status().LastVerifiedRoot
	rawInCP5, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("failed to read initial input checkpoint: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	var batch2 [][]byte
	for i := 5; i < 10; i++ {
		batch2 = append(batch2, fmt.Appendf(nil, "record_%d", i))
	}
	vtc.appendLeaves(batch2...)
	rawInCP10, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("failed to read input checkpoint at size 10: %v", err)
	}

	advOutDir := t.TempDir()
	advLog, err := tree.NewPOSIXOutputLog(ctx, advOutDir, vtc.outSigner, tree.WithOrigin(vtc.outOrigin))
	if err != nil {
		t.Fatalf("failed to create adversarial OutputLog: %v", err)
	}
	defer func() { _ = advLog.Close() }()

	inCP5, _, _, err := log.ParseCheckpoint(rawInCP5, vtc.inOrigin, vtc.inVerifier)
	if err != nil {
		t.Fatalf("failed to parse rawInCP5: %v", err)
	}
	if _, _, err := advLog.Append(ctx, wire.FormatOutputLogLeafFull(authenticRoot0, 0, inCP5)); err != nil {
		t.Fatalf("failed to append honest leaf 0: %v", err)
	}

	inCP10, _, _, err := log.ParseCheckpoint(rawInCP10, vtc.inOrigin, vtc.inVerifier)
	if err != nil {
		t.Fatalf("failed to parse rawInCP10: %v", err)
	}
	tamperedRoot := sha256.Sum256([]byte("forged_mpt_root_hash"))
	if _, _, err := advLog.Append(ctx, wire.FormatOutputLogLeafFull(tamperedRoot, 0, inCP10)); err != nil {
		t.Fatalf("failed to append tampered leaf 1: %v", err)
	}

	advServer := httptest.NewServer(http.FileServer(http.Dir(advOutDir)))
	defer advServer.Close()

	vCfg.OutputLogURL = advServer.URL
	advVerifier, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("failed to create advVerifier: %v", err)
	}
	t.Cleanup(func() { _ = advVerifier.Close() })

	err = advVerifier.VerifyOnce(ctx)
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got: %v", err)
	}

	var mismatchErr *auditor.RootMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("expected *auditor.RootMismatchError, got %T", err)
	}
	if mismatchErr.CommittedMPTRoot != tamperedRoot || mismatchErr.OutputIndex != 1 || mismatchErr.InputSize != 10 {
		t.Errorf("unexpected mismatch details: %+v", mismatchErr)
	}

	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 1.0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 1.0", m)
	}
	if h := testutil.ToFloat64(metrics.AuditorHalted); h != 1.0 {
		t.Errorf("vindex_auditor_halted = %v, want 1.0", h)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal) - baseMismatches; c < 1.0 {
		t.Errorf("vindex_auditor_root_mismatches_total delta = %v, want >= 1.0", c)
	}

	adminH := advVerifier.AdminHandler()
	if rec := probeAdminEndpoint(t, adminH, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("halted /healthz status = %d, want 200", rec.Code)
	}
	if rec := probeAdminEndpoint(t, adminH, "/readyz"); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"degraded"`) {
		t.Errorf("halted /readyz status=%d body=%q, want 503 degraded", rec.Code, rec.Body.String())
	}

	status := advVerifier.Status()
	if !status.IsHalted || status.VerifiedOutputSize != 1 || status.VerifiedInputSize != 5 {
		t.Errorf("unexpected halted status: %+v", status)
	}
	if err := advVerifier.VerifyOnce(ctx); !errors.Is(err, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", err)
	}
}

func TestE2E_MTCPersonality_GoldenLeavesAndAuditor(t *testing.T) {
	mtcMapper := mustExampleWASMHost(t, "mtc")

	goldenJSON, err := os.ReadFile(filepath.Join("..", "..", "mapfn", "examples", "mtc", "testdata", "golden_leaves.json"))
	if err != nil {
		t.Fatalf("failed to read mtc golden_leaves.json: %v", err)
	}
	var golden []struct {
		LeafHex         string   `json:"leaf_hex"`
		ExpectedDomains []string `json:"expected_domains"`
	}
	if err := json.Unmarshal(goldenJSON, &golden); err != nil || len(golden) == 0 {
		t.Fatalf("failed to parse mtc golden_leaves.json: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64)
	var firstExpectedKey string
	leaves := make([][]byte, 0, len(golden))
	for _, g := range golden {
		leafBytes, decErr := hex.DecodeString(g.LeafHex)
		if decErr != nil {
			t.Fatalf("hex.DecodeString failed: %v", decErr)
		}
		leaves = append(leaves, leafBytes)
		if firstExpectedKey == "" && len(g.ExpectedDomains) > 0 {
			firstExpectedKey = g.ExpectedDomains[0]
		}
	}
	vtc.appendLeaves(leaves...)

	engine, err := vtc.newEngine(mtcMapper)
	if err != nil {
		t.Fatalf("vindex.New(mtc) failed: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce(mtc) failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := vtc.newClient(ts.URL)
	if firstExpectedKey != "" {
		idxs, lErr := getAllAscending(ctx, cli, firstExpectedKey)
		if lErr != nil || !slices.Contains(idxs, 0) {
			t.Fatalf("expected MTC golden domain %q at leaf 0, got %v (err=%v)", firstExpectedKey, idxs, lErr)
		}
	}
	ts.Close()
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close(mtc) failed: %v", err)
	}

	// Verify independent auditor running identical mtc.wasm agrees on MPT root.
	v, err := auditor.New(vtc.newVerifierConfig(t, mtcMapper))
	if err != nil {
		t.Fatalf("auditor.New(mtc) failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("auditor.VerifyOnce(mtc) failed: %v", err)
	}
}
