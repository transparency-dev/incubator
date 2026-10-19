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
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/merkle/rfc6962"
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

func TestFormatSafeLeaf(t *testing.T) {
	t.Parallel()
	if got := formatSafeLeaf([]byte("line1\n\tline2\r\n")); got != "line1\n\tline2" {
		t.Fatalf("formatSafeLeaf(newlines/tabs) = %q", got)
	}
	if got := formatSafeLeaf([]byte("esc\x1bdel\x7fc1\u009bend")); got != "esc\\x1bdel\\x7fc1\\x9bend" {
		t.Fatalf("formatSafeLeaf(control runes) = %q", got)
	}
	binPayload := bytes.Repeat([]byte{0xff, 0x00}, 40) // 80 invalid UTF-8 bytes (truncated to 64 bytes = 128 hex chars)
	gotBin := formatSafeLeaf(binPayload)
	if !strings.HasPrefix(gotBin, "<binary 80 bytes: ") || len(gotBin) != len("<binary 80 bytes: >")+128 {
		t.Fatalf("formatSafeLeaf(binary) = %q (len=%d)", gotBin, len(gotBin))
	}
}

func TestRunFlagValidation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	_, vkey, err := note.GenerateKey(rand.Reader, "example.com/output")
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(t.TempDir(), "out.policy")
	if err := os.WriteFile(polPath, fmt.Appendf(nil, "log %s\nquorum none\n", vkey), 0o644); err != nil {
		t.Fatal(err)
	}

	if target, isPrefix, rErr := resolveTarget("", "*.sub.Example.COM", true); rErr != nil || !isPrefix || target != "com.example.sub.*." {
		t.Fatalf("resolveTarget(*.sub.Example.COM) = (%q, %v, %v)", target, isPrefix, rErr)
	}

	for _, tc := range []struct {
		name    string
		args    []string
		wantSub string
	}{
		{
			name:    "missing_key_or_domain",
			args:    []string{},
			wantSub: "must specify --key or --domain",
		},
		{
			name:    "conflicting_key_and_domain",
			args:    []string{"--key", "manual.key", "--domain", "example.com"},
			wantSub: "cannot combine --domain with --key",
		},
		{
			name:    "invalid_whitespace_domain",
			args:    []string{"--domain", "   "},
			wantSub: "invalid --domain",
		},
		{
			name:    "dereference_without_input_log_url",
			args:    []string{"--key", "apple", "--dereference"},
			wantSub: "--dereference requires --input_log_url",
		},
		{
			name:    "invalid_input_log_url_scheme",
			args:    []string{"--key", "apple", "--dereference", "--input_log_url", "/bare/local/path"},
			wantSub: "unsupported --input_log_url scheme",
		},
		{
			name:    "invalid_relative_file_input_log_url",
			args:    []string{"--key", "apple", "--dereference", "--input_log_url", "file://relative/dir"},
			wantSub: "invalid file --input_log_url",
		},
		{
			name:    "missing_output_policy_or_pubkey",
			args:    []string{"--key", "apple", "--input_log_origin", "example.com/in"},
			wantSub: "--output_log_policy or --output_log_pubkey",
		},
		{
			name:    "conflicting_output_policy_and_pubkey",
			args:    []string{"--key", "apple", "--input_log_origin", "example.com/in", "--output_log_policy", polPath, "--output_log_pubkey", vkey},
			wantSub: "cannot specify both --output_log_policy and --output_log_pubkey",
		},
		{
			name:    "missing_input_origin",
			args:    []string{"--key", "apple", "--output_log_policy", polPath},
			wantSub: "--input_log_origin is required",
		},
		{
			name:    "positional_arg_rejected_when_prefix_bool_used",
			args:    []string{"--prefix", "com.example.", "--all", "--output_log_policy", polPath, "--input_log_origin", "example.com/in"},
			wantSub: "unexpected positional arguments",
		},
		{
			name:    "limit_zero_without_all_rejected",
			args:    []string{"--key", "apple", "--limit", "0", "--output_log_policy", polPath, "--input_log_origin", "example.com/in"},
			wantSub: "--limit must be >= 1",
		},
		{
			name:    "conflicting_limit_and_all",
			args:    []string{"--key", "apple", "--limit", "5", "--all", "--output_log_policy", polPath, "--input_log_origin", "example.com/in"},
			wantSub: "cannot combine --limit with --all",
		},
	} {
		var buf bytes.Buffer
		err := run(ctx, tc.args, &buf)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: run(%v) err = %v, want substring %q", tc.name, tc.args, err, tc.wantSub)
		}
	}

	// Verify --output_log_policy infers single-log origin when --output_log_origin is omitted.
	var buf bytes.Buffer
	err = run(ctx, []string{
		"--vindex_url", "http://127.0.0.1:1",
		"--output_log_policy", polPath,
		"--input_log_origin", "example.com/input",
		"--key", "apple",
	}, &buf)
	if err == nil || strings.Contains(err.Error(), "failed to create client") {
		t.Fatalf("expected client.New to succeed with inferred origin from --output_log_policy, got: %v", err)
	}
}

func TestVindexClient_EndToEndDereferenceAndMaxFrom(t *testing.T) {
	t.Parallel()
	wasm := wasmhosttest.Host()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	inOrigin := "example.com/inlog"
	inSKey, inVKey, _ := note.GenerateKey(rand.Reader, inOrigin)
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	appCtx, appCancel := context.WithCancel(context.Background())
	drv, err := posix.New(appCtx, posix.Config{Path: inLogDir})
	if err != nil {
		appCancel()
		t.Fatal(err)
	}
	appender, shutdown, reader, err := tessera.NewAppender(appCtx, drv, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(4, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		appCancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = shutdown(context.Background())
		appCancel()
	})
	awaiter := tessera.NewPublicationAwaiter(appCtx, reader.ReadCheckpoint, 5*time.Millisecond)
	_ = appender.Add(ctx, tessera.NewEntry([]byte("ignored_before_from")))
	f1 := appender.Add(ctx, tessera.NewEntry([]byte("apple payload_1")))
	if _, _, err := awaiter.Await(ctx, f1); err != nil {
		t.Fatal(err)
	}

	outOrigin := "example.com/outlog"
	outSKey, outVKey, _ := note.GenerateKey(rand.Reader, outOrigin)
	outSigner, _ := note.NewSigner(outSKey)
	inPol, err := client.SingleKeyPolicy(inOrigin, inVerifier)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := vindex.New(
		vindex.StorageConfig{
			DBPath:       filepath.Join(rootDir, "db"),
			MPTDir:       testMPTDir(rootDir, "mpt"),
			TileCacheDir: filepath.Join(rootDir, "cache"),
			OutputLogDir: filepath.Join(rootDir, "outlog"),
		},
		outSigner,
		vindex.WithInputLog("file://"+inLogDir, inPol, wasm),
		vindex.WithFrom(1),
		vindex.WithTuning(vindex.TuningOptions{Workers: 1, DisableReaper: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eng.Close() }()
	if err := eng.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vindexTS := httptest.NewServer(eng.Handler())
	defer vindexTS.Close()

	var corruptBundles atomic.Bool
	var overrideInCP atomic.Pointer[[]byte]
	inFS := http.FileServer(http.Dir(inLogDir))
	inTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cpPtr := overrideInCP.Load(); cpPtr != nil && len(*cpPtr) > 0 && strings.HasSuffix(r.URL.Path, "/checkpoint") {
			_, _ = w.Write(*cpPtr)
			return
		}
		if corruptBundles.Load() && strings.Contains(r.URL.Path, "/entries/") {
			_, _ = w.Write([]byte{0x00, 0x05, 'f', 'o', 'r', 'g', 'e'})
			return
		}
		inFS.ServeHTTP(w, r)
	}))
	defer inTS.Close()

	// 1. Default --max_from=0 must reject suffix index (From == 1).
	var outBuf bytes.Buffer
	err = run(ctx, []string{
		"--vindex_url", vindexTS.URL,
		"--output_log_pubkey", outVKey,
		"--input_log_origin", inOrigin,
		"--key", "apple",
	}, &outBuf)
	if err == nil || !strings.Contains(err.Error(), "exceeding --max_from=0") {
		t.Fatalf("expected --max_from=0 failure on From=1 index, got: %v", err)
	}

	// 2. With --max_from=1, --dereference, and --input_log_pubkey, both Input Log consistency and entry inclusion pass.
	outBuf.Reset()
	if err := run(ctx, []string{
		"--vindex_url", vindexTS.URL,
		"--output_log_pubkey", outVKey,
		"--input_log_url", inTS.URL,
		"--input_log_pubkey", inVKey,
		"--max_from", "1",
		"--dereference",
		"--key", "apple",
	}, &outBuf); err != nil {
		t.Fatalf("verified --dereference failed: %v", err)
	}
	if !strings.Contains(outBuf.String(), "[1]: apple payload_1") {
		t.Fatalf("missing dereferenced leaf in output:\n%s", outBuf.String())
	}

	// 2b. Prefix query with explicit --limit=1 fetches occurrences without requiring --all.
	outBuf.Reset()
	if err := run(ctx, []string{
		"--vindex_url", vindexTS.URL,
		"--output_log_pubkey", outVKey,
		"--input_log_origin", inOrigin,
		"--max_from", "1",
		"--prefix",
		"--limit", "1",
		"--key", "app",
	}, &outBuf); err != nil {
		t.Fatalf("prefix --limit=1 failed: %v", err)
	}
	if !strings.Contains(outBuf.String(), "1 occurrences [1]") {
		t.Fatalf("expected prefix --limit=1 to fetch occurrences, got:\n%s", outBuf.String())
	}

	// 3. Tampered Input Log entry bundle must cause --dereference to return a non-nil error.
	corruptBundles.Store(true)
	outBuf.Reset()
	err = run(ctx, []string{
		"--vindex_url", vindexTS.URL,
		"--output_log_pubkey", outVKey,
		"--input_log_url", inTS.URL,
		"--input_log_pubkey", inVKey,
		"--max_from", "1",
		"--dereference",
		"--key", "apple",
	}, &outBuf)
	if err == nil {
		t.Fatal("expected non-nil error when Input Log serves tampered entry bundle during --dereference")
	}
	corruptBundles.Store(false)

	// 4. Input Log consistency rejects VIndex InputSize > signed Input Log checkpoint size,
	// and rejects split-view at equal size.
	signCP := func(size uint64, hash []byte) []byte {
		cp := log.Checkpoint{Origin: inOrigin, Size: size, Hash: hash}
		b, sErr := note.Sign(&note.Note{Text: string(cp.Marshal())}, inSigner)
		if sErr != nil {
			t.Fatal(sErr)
		}
		return b
	}
	for _, cpCase := range []struct {
		name    string
		rawCP   []byte
		wantSub string
	}{
		{
			name:    "size_0_behind_vindex_size_2",
			rawCP:   signCP(0, rfc6962.DefaultHasher.EmptyRoot()),
			wantSub: "exceeds signed Input Log checkpoint size 0",
		},
		{
			name:    "size_1_behind_vindex_size_2",
			rawCP:   signCP(1, bytes.Repeat([]byte{0x11}, 32)),
			wantSub: "exceeds signed Input Log checkpoint size 1",
		},
		{
			name:    "split_view_at_size_2",
			rawCP:   signCP(2, bytes.Repeat([]byte{0x22}, 32)),
			wantSub: "input log split-view at size 2",
		},
	} {
		cloned := slices.Clone(cpCase.rawCP)
		overrideInCP.Store(&cloned)
		outBuf.Reset()
		cErr := run(ctx, []string{
			"--vindex_url", vindexTS.URL,
			"--output_log_pubkey", outVKey,
			"--input_log_url", inTS.URL,
			"--input_log_pubkey", inVKey,
			"--max_from", "1",
			"--key", "apple",
		}, &outBuf)
		if cErr == nil || !strings.Contains(cErr.Error(), cpCase.wantSub) {
			t.Fatalf("%s: err = %v, want substring %q", cpCase.name, cErr, cpCase.wantSub)
		}
	}
}
