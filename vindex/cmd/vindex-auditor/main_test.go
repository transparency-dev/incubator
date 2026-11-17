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

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmtest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

func TestVindexAuditor_FlagValidation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tmpDir := t.TempDir()

	if err := run(ctx, []string{"--help"}, nil); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run(--help) = %v, want flag.ErrHelp", err)
	}

	_, vkey1, err := note.GenerateKey(rand.Reader, "custom.log/one")
	if err != nil {
		t.Fatal(err)
	}
	_, vkey2, err := note.GenerateKey(rand.Reader, "custom.log/two")
	if err != nil {
		t.Fatal(err)
	}
	polFile := filepath.Join(tmpDir, "single.policy")
	if err := os.WriteFile(polFile, fmt.Appendf(nil, "log %s\nquorum none\n", vkey1), 0o644); err != nil {
		t.Fatal(err)
	}
	multiFile := filepath.Join(tmpDir, "multi.policy")
	if err := os.WriteFile(multiFile, fmt.Appendf(nil, "log %s\nlog %s\nquorum none\n", vkey1, vkey2), 0o644); err != nil {
		t.Fatal(err)
	}

	baseArgs := func(extra ...string) []string {
		return append([]string{
			"--output_log_url=http://127.0.0.1:1/out",
			"--input_log_url=http://127.0.0.1:1/in",
			"--db_path=" + filepath.Join(tmpDir, "db"),
			"--mpt_dir=:memory:",
			"--wasm_path=" + filepath.Join(tmpDir, "dummy.wasm"),
		}, extra...)
	}

	tests := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{
			name:    "forbidden signer flag rejected",
			args:    []string{"--output_log_signer_key=x"},
			wantSub: "flag provided but not defined: -output_log_signer_key",
		},
		{
			name:    "forbidden mode flag rejected",
			args:    []string{"--mode=auditor"},
			wantSub: "flag provided but not defined: -mode",
		},
		{
			name:    "unexpected positional arg rejected",
			args:    append(baseArgs("--input_log_pubkey="+vkey1, "--output_log_pubkey="+vkey2), "extra"),
			wantSub: "unexpected positional arguments",
		},
		{
			name:    "missing output_log_url",
			args:    []string{"--input_log_url=http://x", "--db_path=a", "--mpt_dir=b", "--wasm_path=c"},
			wantSub: "--output_log_url flag is required",
		},
		{
			name:    "bare path output_log_url rejected",
			args:    []string{"--output_log_url=/var/log/out", "--input_log_url=http://x", "--db_path=a", "--mpt_dir=b", "--wasm_path=c"},
			wantSub: "scheme must be http, https, or file",
		},
		{
			name:    "missing input_log_url",
			args:    []string{"--output_log_url=http://x", "--db_path=a", "--mpt_dir=b", "--wasm_path=c"},
			wantSub: "--input_log_url flag is required",
		},
		{
			name:    "missing db_path",
			args:    []string{"--output_log_url=http://x", "--input_log_url=http://y", "--mpt_dir=b", "--wasm_path=c"},
			wantSub: "--db_path flag is required",
		},
		{
			name:    "missing mpt_dir",
			args:    []string{"--output_log_url=http://x", "--input_log_url=http://y", "--db_path=a", "--wasm_path=c"},
			wantSub: "--mpt_dir flag is required",
		},
		{
			name:    "missing wasm_path",
			args:    []string{"--output_log_url=http://x", "--input_log_url=http://y", "--db_path=a", "--mpt_dir=b"},
			wantSub: "--wasm_path flag is required",
		},
		{
			name:    "unknown input_log_type",
			args:    baseArgs("--input_log_type=bogus", "--input_log_pubkey="+vkey1, "--output_log_pubkey="+vkey2),
			wantSub: "unknown --input_log_type",
		},
		{
			name:    "missing input log verification",
			args:    baseArgs(),
			wantSub: "--input_log_policy or --input_log_pubkey is required",
		},
		{
			name:    "conflicting input_log_policy and input_log_pubkey",
			args:    baseArgs("--input_log_policy="+polFile, "--input_log_pubkey="+vkey1),
			wantSub: "cannot specify both --input_log_policy and --input_log_pubkey",
		},
		{
			name:    "conflicting output_log_policy and output_log_pubkey",
			args:    baseArgs("--input_log_pubkey="+vkey1, "--output_log_policy="+polFile, "--output_log_pubkey="+vkey2),
			wantSub: "cannot specify both --output_log_policy and --output_log_pubkey",
		},
		{
			name:    "multi-log policy without explicit origin fails closed",
			args:    baseArgs("--input_log_policy="+multiFile, "--output_log_pubkey="+vkey2),
			wantSub: "--input_log_origin is required",
		},
		{
			name:    "invalid metrics_addr rejected",
			args:    baseArgs("--input_log_pubkey="+vkey1, "--output_log_pubkey="+vkey2, "--metrics_addr=not-a-hostport"),
			wantSub: "invalid --metrics_addr",
		},
		{
			name:    "invalid mtc pubkey rejected",
			args:    baseArgs("--input_log_pubkey=mtc+bad", "--output_log_pubkey="+vkey2),
			wantSub: "failed to build input_log policy",
		},
	}

	for _, tc := range tests {
		err := run(ctx, tc.args, nil)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("%s: run(%v) err = %v, want substring %q", tc.name, tc.args, err, tc.wantSub)
		}
	}
}

func TestVindexAuditor_OneshotRestartCancelTamperAndDaemon(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	t.Cleanup(func() {
		metrics.ResetAuditorRootMismatch()
		metrics.ResetAuditorHalted()
	})

	const inOrigin = "test.auditor.input"
	const outOrigin = "test.auditor.output"

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, inOrigin)
	if err != nil {
		t.Fatal(err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatal(err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatal(err)
	}

	inLogDir := filepath.Join(tmpDir, "inlog")
	inLog, err := tree.NewPOSIXOutputLog(ctx, inLogDir, inSigner, tree.WithOrigin(inOrigin))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inLog.Close() }()
	if _, _, err := inLog.Append(ctx, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	outLogDir := filepath.Join(tmpDir, "outlog")
	inPol, err := client.SingleKeyPolicy(inOrigin, inVerifier)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := vindex.New(
		vindex.StorageConfig{
			DBPath:       filepath.Join(tmpDir, "eng_db"),
			MPTDir:       ":memory:",
			OutputLogDir: outLogDir,
		},
		outSigner,
		vindex.WithInputLog("file://"+inLogDir, inPol, wasmhosttest.Host()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SyncOnce(ctx); err != nil {
		_ = eng.Close()
		t.Fatal(err)
	}
	_ = eng.Close()

	inSrv := httptest.NewServer(http.FileServer(http.Dir(inLogDir)))
	defer inSrv.Close()
	outSrv := httptest.NewServer(http.FileServer(http.Dir(outLogDir)))
	defer outSrv.Close()

	wasmFile := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmFile, wasmtest.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	audDB := filepath.Join(tmpDir, "aud_db")
	baseArgs := []string{
		"--output_log_url=" + outSrv.URL,
		"--output_log_pubkey=" + outVKey,
		"--input_log_url=" + inSrv.URL,
		"--input_log_pubkey=" + inVKey,
		"--db_path=" + audDB,
		"--mpt_dir=:memory:",
		"--wasm_path=" + wasmFile,
	}

	// 1. Oneshot honest verification infers origins and suppresses metrics listener by default.
	var oneshotAddr string
	if err := run(ctx, append(baseArgs, "--oneshot"), func(v *auditor.Verifier) {
		oneshotAddr = v.MetricsAddr()
	}); err != nil {
		t.Fatalf("first oneshot run failed: %v", err)
	}
	if oneshotAddr != "" {
		t.Fatalf("expected --oneshot not to bind metrics listener by default, got %q", oneshotAddr)
	}

	// 2. Second oneshot run exercises warm restart recovery on persisted DB.
	var warmOutSize uint64
	if err := run(ctx, append(baseArgs, "--oneshot"), func(v *auditor.Verifier) {
		warmOutSize = v.Status().VerifiedOutputSize
	}); err != nil {
		t.Fatalf("second oneshot run (warm restart) failed: %v", err)
	}
	if warmOutSize != 1 {
		t.Fatalf("warm restart VerifiedOutputSize = %d, want 1", warmOutSize)
	}

	// 3. Interrupted oneshot must return a non-Canceled error so main() exits non-zero.
	canceledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if err := run(canceledCtx, append(baseArgs, "--oneshot"), nil); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("expected interrupted --oneshot to return non-Canceled error, got: %v", err)
	}

	// 4. Oneshot against tampered Output Log root fails with auditor.ErrRootMismatch.
	advDir := filepath.Join(tmpDir, "adv_outlog")
	advLog, err := tree.NewPOSIXOutputLog(ctx, advDir, outSigner, tree.WithOrigin(outOrigin))
	if err != nil {
		t.Fatal(err)
	}
	rawInCP, err := os.ReadFile(filepath.Join(inLogDir, "checkpoint"))
	if err != nil {
		_ = advLog.Close()
		t.Fatal(err)
	}
	inCP, _, _, err := log.ParseCheckpoint(rawInCP, inOrigin, inVerifier)
	if err != nil {
		_ = advLog.Close()
		t.Fatal(err)
	}
	if _, _, err := advLog.Append(ctx, wire.FormatOutputLogLeafFull(sha256.Sum256([]byte("forged")), 0, inCP)); err != nil {
		_ = advLog.Close()
		t.Fatal(err)
	}
	_ = advLog.Close()

	advSrv := httptest.NewServer(http.FileServer(http.Dir(advDir)))
	defer advSrv.Close()

	err = run(ctx, []string{
		"--output_log_url=" + advSrv.URL,
		"--output_log_pubkey=" + outVKey,
		"--input_log_url=" + inSrv.URL,
		"--input_log_pubkey=" + inVKey,
		"--db_path=" + filepath.Join(tmpDir, "adv_db"),
		"--mpt_dir=:memory:",
		"--wasm_path=" + wasmFile,
		"--oneshot",
	}, nil)
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("oneshot against tampered root err = %v, want ErrRootMismatch", err)
	}

	// 5. Daemon mode serves /readyz, /healthz, and /metrics on --metrics_addr.
	dCtx, dCancel := context.WithCancel(ctx)
	defer dCancel()
	var verifierPtr atomic.Pointer[auditor.Verifier]
	runDone := make(chan error, 1)
	go func() {
		runDone <- run(dCtx, []string{
			"--output_log_url=" + outSrv.URL,
			"--output_log_pubkey=" + outVKey,
			"--input_log_url=" + inSrv.URL,
			"--input_log_pubkey=" + inVKey,
			"--db_path=" + filepath.Join(tmpDir, "daemon_db"),
			"--mpt_dir=:memory:",
			"--wasm_path=" + wasmFile,
			"--metrics_addr=127.0.0.1:0",
			"--poll_interval=50ms",
		}, func(v *auditor.Verifier) {
			verifierPtr.Store(v)
		})
	}()

	var stopOnce sync.Once
	var stopErr error
	stopDaemon := func() error {
		stopOnce.Do(func() {
			dCancel()
			stopErr = <-runDone
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stopDaemon() })

	httpCli := &http.Client{Timeout: 2 * time.Second}
	var adminAddr string
	readyOK := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		v := verifierPtr.Load()
		if v != nil {
			adminAddr = v.MetricsAddr()
		}
		if adminAddr != "" && v != nil && v.Status().VerifiedOutputSize >= 1 {
			if res, reqErr := httpCli.Get("http://" + adminAddr + "/readyz"); reqErr == nil {
				_ = res.Body.Close()
				if res.StatusCode == http.StatusOK {
					readyOK = true
					break
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !readyOK {
		t.Fatalf("timed out waiting for auditor /readyz on %q", adminAddr)
	}

	for _, opPath := range []string{"/healthz", "/metrics"} {
		res, reqErr := httpCli.Get("http://" + adminAddr + opPath)
		if reqErr != nil {
			t.Fatalf("GET %s failed: %v", opPath, reqErr)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", opPath, res.StatusCode)
		}
	}

	if dErr := stopDaemon(); dErr != nil && !errors.Is(dErr, context.Canceled) {
		t.Fatalf("daemon exited with unexpected error: %v", dErr)
	}
}
