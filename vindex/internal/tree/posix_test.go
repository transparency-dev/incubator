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

package tree_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
)

const (
	rawWit1VKey  = "Wit1+55ee4561+AVhZSmQj9+SoL+p/nN0Hh76xXmF7QcHfytUrI1XfSClk"
	testWit1SKey = "PRIVATE+KEY+Wit1+55ee4561+AeadRiG7XM4XiieCHzD8lxysXMwcViy5nYsoXURWGrlE"
	rawWit2VKey  = "Wit2+85ecc407+AWVbwFJte9wMQIPSnEnj4KibeO6vSIOEDUTDp3o63c2x"
	testWit2SKey = "PRIVATE+KEY+Wit2+85ecc407+AfPTvxw5eUcqSgivo2vaiC7JPOMUZ/9baHPSDrWqgdGm"
)

var (
	testWit1VKey, _ = f_note.VKeyToCosignatureV1(rawWit1VKey)
	testWit2VKey, _ = f_note.VKeyToCosignatureV1(rawWit2VKey)
)

func newTestSignerAndVerifier(t *testing.T) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, "outputlog.test")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	return s, v
}

func verifyLeafAndInclusionProof(t *testing.T, ctx context.Context, outLog *tree.POSIXOutputLog, idx uint64, wantLeaf []byte, cp *log.Checkpoint) {
	t.Helper()
	gotLeaf, err := outLog.GetLeaf(ctx, idx)
	if err != nil {
		t.Fatalf("GetLeaf(%d) failed: %v", idx, err)
	}
	if !bytes.Equal(gotLeaf, wantLeaf) {
		t.Fatalf("GetLeaf(%d) = %q, want %q", idx, gotLeaf, wantLeaf)
	}
	proofHashes, err := outLog.InclusionProof(ctx, idx, cp.Size)
	if err != nil {
		t.Fatalf("InclusionProof(%d, %d) failed: %v", idx, cp.Size, err)
	}
	rawProof := make([][]byte, len(proofHashes))
	for i := range proofHashes {
		rawProof[i] = proofHashes[i][:]
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(wantLeaf)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, cp.Size, leafHash, rawProof, cp.Hash); err != nil {
		t.Fatalf("VerifyInclusion failed for leaf %d: %v", idx, err)
	}
}

func TestNewPOSIXOutputLog_Validation(t *testing.T) {
	ctx := context.Background()
	signer, _ := newTestSignerAndVerifier(t)
	tmpDir := t.TempDir()

	for _, tc := range []struct {
		name string
		dir  string
		sig  note.Signer
		opts []tree.POSIXOption
	}{
		{name: "nil_signer", dir: tmpDir, sig: nil},
		{name: "empty_dir", dir: "", sig: signer},
		{name: "origin_mismatch", dir: tmpDir, sig: signer, opts: []tree.POSIXOption{tree.WithOrigin("mismatched.origin")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := tree.NewPOSIXOutputLog(ctx, tc.dir, tc.sig, tc.opts...)
			if err == nil {
				_ = l.Close()
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
		})
	}

	// BuildWitnessGroup: 2-witness folding + validation guards
	if _, err := tree.BuildWitnessGroup(
		[]string{"https://w1.example.com/", "https://w2.example.com/"},
		[]string{testWit1VKey, testWit2VKey},
	); err != nil {
		t.Fatalf("BuildWitnessGroup(2 witnesses) failed: %v", err)
	}
	for name, args := range map[string][2][]string{
		"length_mismatch": {{"https://w1.example.com/"}, nil},
		"empty_entry":     {{""}, {testWit1VKey}},
		"bad_scheme":      {{"ftp://w1.example.com/"}, {testWit1VKey}},
		"missing_host":    {{"https://"}, {testWit1VKey}},
		"duplicate_url":   {{"https://w1.example.com/", "https://W1.example.com"}, {testWit1VKey, testWit2VKey}},
		"duplicate_vkey":  {{"https://w1.example.com/", "https://w2.example.com/"}, {testWit1VKey, testWit1VKey}},
	} {
		if _, err := tree.BuildWitnessGroup(args[0], args[1]); err == nil {
			t.Errorf("BuildWitnessGroup(%s): expected error, got nil", name)
		}
	}

	policyDoc := fmt.Sprintf("witness w1 %s https://w1.example.com/\nquorum w1\n", testWit1VKey)
	if _, err := tree.BuildWitnessGroupFromPolicy([]byte(policyDoc)); err != nil {
		t.Fatalf("BuildWitnessGroupFromPolicy failed: %v", err)
	}
}

func TestPOSIXOutputLog_LifecycleAndPersistenceReopen(t *testing.T) {
	ctx := context.Background()
	signer, _ := newTestSignerAndVerifier(t)
	tmpDir := filepath.Join(t.TempDir(), "persistent_log")

	leaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
		[]byte("leaf-4"),
	}

	// Phase 1: Open with WithBatchMaxSize(0) clamp, check initial Size=0, append 3 leaves, close
	log1, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer, tree.WithOrigin("outputlog.test"), tree.WithBatchMaxSize(0))
	if err != nil {
		t.Fatalf("Phase 1 NewPOSIXOutputLog failed: %v", err)
	}
	if sz, err := log1.Size(ctx); err != nil || sz != 0 {
		t.Fatalf("initial Size() = %d, err=%v, want 0", sz, err)
	}
	for i := range 3 {
		idx, cpBytes, err := log1.Append(ctx, leaves[i])
		if err != nil || idx != uint64(i) || len(cpBytes) == 0 {
			t.Fatalf("Phase 1 Append(%d): idx=%d len(cp)=%d err=%v", i, idx, len(cpBytes), err)
		}
	}
	if err := log1.Close(); err != nil {
		t.Fatalf("Phase 1 Close failed: %v", err)
	}

	// Phase 2: Reopen, verify Size=3, append 2 more leaves, verify all 5 proofs + bounds + double-Close
	log2, err := tree.NewPOSIXOutputLog(ctx, tmpDir, signer)
	if err != nil {
		t.Fatalf("Phase 2 NewPOSIXOutputLog failed: %v", err)
	}
	defer func() { _ = log2.Close() }()

	if sz, err := log2.Size(ctx); err != nil || sz != 3 {
		t.Fatalf("Phase 2 reopened Size() = %d, err=%v, want 3", sz, err)
	}
	for i := 3; i < 5; i++ {
		idx, _, err := log2.Append(ctx, leaves[i])
		if err != nil || idx != uint64(i) {
			t.Fatalf("Phase 2 Append(%d): idx=%d err=%v", i, idx, err)
		}
	}

	rawCP, err := log2.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint() failed: %v", err)
	}
	parsedCP, err := wire.ParseCheckpointHeader(rawCP)
	if err != nil || parsedCP.Size != 5 {
		t.Fatalf("ParseCheckpointHeader size=%d err=%v, want 5", parsedCP.Size, err)
	}
	for i, wantLeaf := range leaves {
		verifyLeafAndInclusionProof(t, ctx, log2, uint64(i), wantLeaf, parsedCP)
	}

	if _, err := log2.GetLeaf(ctx, 5); err == nil {
		t.Fatal("GetLeaf(out_of_bounds) expected error, got nil")
	}
	if _, err := log2.InclusionProof(ctx, 5, parsedCP.Size); err == nil {
		t.Fatal("InclusionProof(out_of_bounds) expected error, got nil")
	}
	if err := log2.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := log2.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestPOSIXOutputLog_SpanningEntryBundles(t *testing.T) {
	ctx := context.Background()
	signer, _ := newTestSignerAndVerifier(t)

	outLog, err := tree.NewPOSIXOutputLog(ctx, t.TempDir(), signer, tree.WithBatchMaxSize(256))
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog failed: %v", err)
	}
	defer func() { _ = outLog.Close() }()

	const numEntries = 270
	leaves := make([][]byte, numEntries)
	for i := range numEntries {
		leaves[i] = []byte(fmt.Sprintf("bundle-entry-%04d", i))
	}
	indices := make([]uint64, numEntries)

	var g errgroup.Group
	for i := range numEntries {
		g.Go(func() error {
			leafIdx, _, err := outLog.Append(ctx, leaves[i])
			if err != nil {
				return fmt.Errorf("Append(%d) failed: %w", i, err)
			}
			indices[i] = leafIdx
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("concurrent appends failed: %v", err)
	}

	rawCP, err := outLog.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint() failed: %v", err)
	}
	parsedCP, err := wire.ParseCheckpointHeader(rawCP)
	if err != nil || parsedCP.Size != numEntries {
		t.Fatalf("ParseCheckpointHeader size=%d err=%v, want %d", parsedCP.Size, err, numEntries)
	}

	idxToLeaf := make(map[uint64][]byte, numEntries)
	for i := range numEntries {
		idxToLeaf[indices[i]] = leaves[i]
	}
	for _, idx := range []uint64{0, 1, 127, 255, 256, 257, numEntries - 1} {
		verifyLeafAndInclusionProof(t, ctx, outLog, idx, idxToLeaf[idx], parsedCP)
	}
}

func startMockWitness(t *testing.T, skey string, reject *atomic.Bool) *httptest.Server {
	t.Helper()
	signer, err := f_note.NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatalf("NewSignerForCosignatureV1 failed: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject != nil && reject.Load() {
			http.Error(w, "witness unavailable", http.StatusServiceUnavailable)
			return
		}
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, cpNote, ok := bytes.Cut(reqBody, []byte("\n\n"))
		if !ok {
			http.Error(w, "missing blank line", http.StatusBadRequest)
			return
		}
		cpBody, _, ok := bytes.Cut(cpNote, []byte("\n\n"))
		if !ok {
			http.Error(w, "malformed note", http.StatusBadRequest)
			return
		}
		signed, err := note.Sign(&note.Note{Text: string(cpBody) + "\n"}, signer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, sigBlock, _ := bytes.Cut(signed, []byte("\n\n"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sigBlock)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPOSIXOutputLog_WitnessCosigning_FailClosedAndIdempotentRetry(t *testing.T) {
	ctx := context.Background()
	signer, logVerifier := newTestSignerAndVerifier(t)

	var rejectWit2 atomic.Bool
	w1Srv := startMockWitness(t, testWit1SKey, nil)
	w2Srv := startMockWitness(t, testWit2SKey, &rejectWit2)

	wg, err := tree.BuildWitnessGroup([]string{w1Srv.URL, w2Srv.URL}, []string{testWit1VKey, testWit2VKey})
	if err != nil {
		t.Fatalf("BuildWitnessGroup failed: %v", err)
	}
	wit1V, _ := wire.ParseWitnessVerifier(testWit1VKey)
	wit2V, _ := wire.ParseWitnessVerifier(testWit2VKey)
	pol, err := wire.BuildPolicy(signer.Name(), logVerifier, []note.Verifier{wit1V, wit2V}, 2)
	if err != nil {
		t.Fatalf("BuildPolicy failed: %v", err)
	}

	outLog, err := tree.NewPOSIXOutputLog(ctx, t.TempDir(), signer, tree.WithWitnessGroup(wg))
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog failed: %v", err)
	}
	defer func() { _ = outLog.Close() }()

	// 1. Witness 2 down -> fail-closed Append times out without advancing published Size()
	rejectWit2.Store(true)
	shortCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	_, _, err = outLog.Append(shortCtx, []byte("witnessed-leaf-0"))
	cancel()
	if err == nil {
		t.Fatal("expected Append to fail closed when witness 2 returns 503")
	}
	if sz, err := outLog.Size(ctx); err != nil || sz != 0 {
		t.Fatalf("published Size() during witness outage = %d, err=%v, want 0", sz, err)
	}

	// 2. Witness 2 recovers -> retrying Append with identical leaf awaits idx 0 idempotently (no duplicate leaf 1!)
	rejectWit2.Store(false)
	idx, rawCP, err := outLog.Append(ctx, []byte("witnessed-leaf-0"))
	if err != nil {
		t.Fatalf("Append retry after witness recovery failed: %v", err)
	}
	if idx != 0 {
		t.Fatalf("idempotent retry Append idx = %d, want 0 (no duplicate leaf)", idx)
	}
	outCP, err := pol.Verify(rawCP)
	if err != nil || outCP.Size != 1 {
		t.Fatalf("pol.Verify(rawCP) size=%v err=%v, want size=1 with 2-of-2 witness cosigs", outCP, err)
	}
	if err := outLog.AwaitQuiescent(ctx); err != nil {
		t.Fatalf("AwaitQuiescent failed: %v", err)
	}
}
