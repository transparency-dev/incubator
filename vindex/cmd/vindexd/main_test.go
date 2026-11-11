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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmtest"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

var isRaceDarwin = sync.OnceValue(func() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" && s.Value == "true" {
			return true
		}
	}
	return false
})

func testMPTDir(rootDir, sub string) string {
	if isRaceDarwin() {
		return ":memory:"
	}
	return filepath.Join(rootDir, sub)
}

func newTestSignerKey(t *testing.T, origin string) (string, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("failed to generate note key: %v", err)
	}
	return skey, vkey
}

func getTestWasm(t *testing.T) string {
	t.Helper()
	wasmPath := filepath.Join(t.TempDir(), "test.wasm")
	if err := os.WriteFile(wasmPath, wasmtest.Bytes(), 0o644); err != nil {
		t.Fatalf("failed to write test wasm: %v", err)
	}
	return wasmPath
}

func TestParseSigner_MLDSA44(t *testing.T) {
	skey, vkey, err := fnote.GenerateMLDSAKey("test.mldsa.out")
	if err != nil {
		t.Fatalf("GenerateMLDSAKey failed: %v", err)
	}
	verifier, err := fnote.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("fnote.NewVerifier failed: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "out.key")
	if err := os.WriteFile(keyFile, []byte(skey+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	for _, in := range []string{skey, keyFile} {
		signer, err := parseSigner(in)
		if err != nil {
			t.Fatalf("parseSigner failed: %v", err)
		}
		if signer.Name() != verifier.Name() || signer.KeyHash() != verifier.KeyHash() {
			t.Fatalf("signer (%s, %08x) does not match verifier (%s, %08x)", signer.Name(), signer.KeyHash(), verifier.Name(), verifier.KeyHash())
		}
	}
}

func TestVindexd_FlagValidation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tmpDir := t.TempDir()
	const wasm = "unused.wasm"
	skey, _ := newTestSignerKey(t, "test.out")

	for _, tc := range []struct {
		name    string
		args    []string
		wantSub string
	}{
		{
			name:    "missing_db_path",
			args:    []string{"--mpt_dir", filepath.Join(tmpDir, "m"), "--wasm_path", wasm, "--output_log_dir", filepath.Join(tmpDir, "o"), "--output_log_signer_key", skey},
			wantSub: "--db_path flag is required",
		},
		{
			name:    "missing_mpt_dir",
			args:    []string{"--db_path", filepath.Join(tmpDir, "d"), "--wasm_path", wasm, "--output_log_dir", filepath.Join(tmpDir, "o"), "--output_log_signer_key", skey},
			wantSub: "--mpt_dir flag is required",
		},
		{
			name:    "missing_wasm_path",
			args:    []string{"--db_path", filepath.Join(tmpDir, "d"), "--mpt_dir", filepath.Join(tmpDir, "m"), "--output_log_dir", filepath.Join(tmpDir, "o"), "--output_log_signer_key", skey},
			wantSub: "--wasm_path flag is required",
		},
		{
			name:    "missing_output_log_dir",
			args:    []string{"--db_path", filepath.Join(tmpDir, "d"), "--mpt_dir", filepath.Join(tmpDir, "m"), "--wasm_path", wasm, "--output_log_signer_key", skey},
			wantSub: "--output_log_dir flag is required",
		},
		{
			name:    "missing_output_log_signer_key",
			args:    []string{"--db_path", filepath.Join(tmpDir, "d"), "--mpt_dir", filepath.Join(tmpDir, "m"), "--wasm_path", wasm, "--output_log_dir", filepath.Join(tmpDir, "o")},
			wantSub: "--output_log_signer_key flag is required",
		},
		{
			name:    "missing_input_log_url",
			args:    []string{"--db_path", filepath.Join(tmpDir, "d"), "--mpt_dir", filepath.Join(tmpDir, "m"), "--wasm_path", wasm, "--output_log_dir", filepath.Join(tmpDir, "o"), "--output_log_signer_key", skey},
			wantSub: "--input_log_url flag is required",
		},
		{
			name: "conflicting_input_policy_and_pubkey",
			args: []string{
				"--db_path", filepath.Join(tmpDir, "d"),
				"--mpt_dir", filepath.Join(tmpDir, "m"),
				"--wasm_path", wasm,
				"--output_log_dir", filepath.Join(tmpDir, "o"),
				"--output_log_signer_key", skey,
				"--input_log_policy", "p.policy",
				"--input_log_pubkey", "k.vkey",
			},
			wantSub: "cannot specify both --input_log_policy and --input_log_pubkey",
		},
	} {
		err := run(ctx, tc.args, nil)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.wantSub)
		}
	}
}

func TestVindexd_OneshotNoListeners_SyncRestartAndDaemonServing(t *testing.T) {
	t.Parallel()
	wasm := getTestWasm(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	inLogDir := filepath.Join(tmpDir, "inlog")
	inOrigin := "test.inlog"
	inSKey, inVKey := newTestSignerKey(t, inOrigin)
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	appCtx, appCancel := context.WithCancel(context.Background())
	driver, err := posix.New(appCtx, posix.Config{Path: inLogDir})
	if err != nil {
		appCancel()
		t.Fatalf("posix.New failed: %v", err)
	}
	appender, shutdown, reader, err := tessera.NewAppender(appCtx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(2, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		appCancel()
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() {
		_ = shutdown(context.Background())
		appCancel()
	})

	awaiter := tessera.NewPublicationAwaiter(appCtx, reader.ReadCheckpoint, 5*time.Millisecond)
	_ = appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-0")))
	f1 := appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-1")))
	if _, _, err := awaiter.Await(ctx, f1); err != nil {
		t.Fatalf("Await(f1) failed: %v", err)
	}

	outOrigin := "test.outlog"
	outSKey, _ := newTestSignerKey(t, outOrigin)
	outD := filepath.Join(tmpDir, "outputlog")

	baseArgs := []string{
		"--db_path", filepath.Join(tmpDir, "db"),
		"--mpt_dir", testMPTDir(tmpDir, "mpt"),
		"--output_log_dir", outD,
		"--output_log_signer_key", outSKey,
		"--tile_cache_dir", filepath.Join(tmpDir, "tilecache"),
		"--input_log_url", "file://" + inLogDir,
		"--input_log_origin", inOrigin,
		"--input_log_pubkey", inVKey,
		"--wasm_path", wasm,
		"--wasm_workers", "1",
	}

	// 1. Oneshot mode must NOT bind :8080 or :9090 when listener flags are omitted.
	var oneshotListen, oneshotMetrics string
	if err := run(ctx, append(baseArgs, "--oneshot"), func(l, m string) {
		oneshotListen, oneshotMetrics = l, m
	}); err != nil {
		t.Fatalf("first run (oneshot) failed: %v", err)
	}
	if oneshotListen != "" || oneshotMetrics != "" {
		t.Fatalf("expected --oneshot not to bind listeners by default, got listen=%q metrics=%q", oneshotListen, oneshotMetrics)
	}

	cpBytes, err := os.ReadFile(filepath.Join(outD, "checkpoint"))
	if err != nil || !strings.Contains(string(cpBytes), outOrigin) {
		t.Fatalf("output checkpoint err=%v body=%q", err, string(cpBytes))
	}

	// 2. Second oneshot run exercises warm startup recovery, and canceled oneshot returns a non-Canceled error.
	if err := run(ctx, append(baseArgs, "--oneshot"), nil); err != nil {
		t.Fatalf("second run (recovery restart) failed: %v", err)
	}
	canceledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if err := run(canceledCtx, append(baseArgs, "--oneshot"), nil); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("expected interrupted --oneshot to return non-Canceled error, got: %v", err)
	}

	// 3. Daemon mode binds public and admin listeners on separate addresses.
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()
	type addrs struct{ pub, adm string }
	startedCh := make(chan addrs, 1)
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- run(srvCtx, append(baseArgs,
			"--listen_addr", "127.0.0.1:0",
			"--metrics_addr", "127.0.0.1:0",
			"--poll_interval", "100ms",
		), func(l, m string) {
			startedCh <- addrs{pub: l, adm: m}
		})
	}()

	var stopOnce sync.Once
	var stopErr error
	stopDaemon := func() error {
		stopOnce.Do(func() {
			srvCancel()
			stopErr = <-srvErrCh
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stopDaemon() })

	var bound addrs
	select {
	case bound = <-startedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for daemon listeners")
	}

	httpCli := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		r, gErr := httpCli.Get(fmt.Sprintf("http://%s/readyz", bound.adm))
		if gErr == nil {
			_ = r.Body.Close()
			if r.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("daemon /readyz did not reach 200 OK")
	}

	cpResp, err := httpCli.Get(fmt.Sprintf("http://%s/checkpoint", bound.pub))
	if err != nil || cpResp.StatusCode != http.StatusOK {
		t.Fatalf("GET public /checkpoint failed: err=%v resp=%v", err, cpResp)
	}
	body, _ := io.ReadAll(cpResp.Body)
	_ = cpResp.Body.Close()
	if !strings.Contains(string(body), outOrigin) {
		t.Errorf("public /checkpoint body %q missing %q", string(body), outOrigin)
	}

	pubReady, err := httpCli.Get(fmt.Sprintf("http://%s/readyz", bound.pub))
	if err != nil || pubReady.StatusCode != http.StatusNotFound {
		t.Fatalf("GET public /readyz = %v/%v, want 404", pubReady, err)
	}
	_ = pubReady.Body.Close()

	if err := stopDaemon(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server run error: %v", err)
	}
}

func TestVindexd_MTCVerifier_FlagAndInit(t *testing.T) {
	t.Parallel()
	wasm := getTestWasm(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	mtcKey := "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	outOrigin := "vindex.test.output"
	skey, _ := newTestSignerKey(t, outOrigin)

	mkArgs := func(pubKey string) []string {
		return []string{
			"--db_path", filepath.Join(tmpDir, "db"),
			"--mpt_dir", testMPTDir(tmpDir, "mpt"),
			"--output_log_dir", filepath.Join(tmpDir, "outputlog"),
			"--output_log_signer_key", skey,
			"--wasm_path", wasm,
			"--wasm_workers", "1",
			"--listen_addr", "127.0.0.1:0",
			"--metrics_addr", "",
			"--input_log_url", "https://127.0.0.1:1",
			"--input_log_origin", "bootstrap-mtca.example/logs/shard3",
			"--input_log_pubkey", pubKey,
		}
	}

	if err := run(ctx, mkArgs("mtc+invalid+key"), nil); err == nil || !strings.Contains(err.Error(), "invalid MTC verifier") {
		t.Fatalf("expected invalid MTC verifier error, got: %v", err)
	}

	cancel()
	if err := run(ctx, mkArgs(mtcKey), nil); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected clean exit on canceled context, got: %v", err)
	}
}
