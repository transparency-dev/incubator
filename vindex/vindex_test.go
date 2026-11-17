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

package vindex_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
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

// testMPTDir returns ":memory:" under the race detector on macOS because each disk-backed
// torchwood/mpt open reserves a 16 TiB virtual address span via mmap, which collides with
// ThreadSanitizer's fixed Go heap arena on darwin/arm64 ("too many address space collisions
// for -race mode"). Disk-backed MPT runs on macOS without -race and on Linux with -race.
func testMPTDir(rootDir, sub string) string {
	if isRaceDarwin() {
		return ":memory:"
	}
	return filepath.Join(rootDir, sub)
}

func newBaseEngineSetup(t *testing.T) (vindex.StorageConfig, note.Signer) {
	t.Helper()
	rootDir := t.TempDir()
	outSKey, _, err := note.GenerateKey(rand.Reader, "test.outputlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}
	return vindex.StorageConfig{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       testMPTDir(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
		OutputLogDir: filepath.Join(rootDir, "outlog"),
	}, outSigner
}

func newPOSIXInputLog(t *testing.T, ctx context.Context, dir string, signer note.Signer) func(payloads ...[]byte) []uint64 {
	t.Helper()
	appCtx, appCancel := context.WithCancel(context.Background())
	drv, err := posix.New(appCtx, posix.Config{Path: dir})
	if err != nil {
		appCancel()
		t.Fatalf("posix.New(%q) failed: %v", dir, err)
	}
	appender, shutdown, reader, err := tessera.NewAppender(appCtx, drv, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(64, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		appCancel()
		t.Fatalf("tessera.NewAppender failed: %v", err)
	}
	t.Cleanup(func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sCancel()
		_ = shutdown(sCtx)
		appCancel()
	})

	awaiter := tessera.NewPublicationAwaiter(appCtx, reader.ReadCheckpoint, 5*time.Millisecond)
	return func(payloads ...[]byte) []uint64 {
		t.Helper()
		futs := make([]tessera.IndexFuture, len(payloads))
		for i, p := range payloads {
			futs[i] = appender.Add(ctx, tessera.NewEntry(p))
		}
		indices := make([]uint64, len(payloads))
		for i, f := range futs {
			idx, rawCP, aErr := awaiter.Await(ctx, f)
			if aErr != nil || len(rawCP) == 0 {
				t.Fatalf("await leaf %d failed: %v", i, aErr)
			}
			indices[i] = idx.Index
		}
		return indices
	}
}

func TestVIndex_PublicAPIAndSharedWASMHostSurvivesClose(t *testing.T) {
	for _, name := range []string{"allow", "none", "reversed-dns"} {
		if _, err := vindex.ParsePrefixPolicy(name); err != nil {
			t.Fatalf("ParsePrefixPolicy(%q) failed: %v", name, err)
		}
	}
	if _, err := vindex.ParsePrefixPolicy("invalid_policy"); err == nil {
		t.Fatal("expected ParsePrefixPolicy(invalid_policy) to fail")
	}

	sharedHost, err := vindex.NewWASMHost(context.Background(), wasmtest.Bytes(), 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	t.Cleanup(func() { _ = sharedHost.Close(context.Background()) })

	storage, outSigner := newBaseEngineSetup(t)
	eng, err := vindex.New(storage, outSigner,
		vindex.WithTuning(vindex.TuningOptions{PollInterval: 10 * time.Millisecond}),
	)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("eng.Close failed: %v", err)
	}

	batch, err := sharedHost.MapBundle(context.Background(), [][]byte{[]byte("hello")})
	if err != nil {
		t.Fatalf("sharedHost.MapBundle after Engine.Close() failed: %v", err)
	}
	if len(batch) != 1 || len(batch[0]) != 1 || batch[0][0].Key != "hello" || batch[0][0].KeyHash != sha256.Sum256([]byte("hello")) {
		t.Fatalf("unexpected canonical entries: %+v", batch)
	}
}

func TestEngine_Lifecycle_EndToEndIngestionAndLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.inputlog")
	if err != nil {
		t.Fatalf("failed to generate input log key: %v", err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)
	inPolicy, err := client.SingleKeyPolicy("test.inputlog", inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(in) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.outputlog")
	if err != nil {
		t.Fatalf("failed to generate output log key: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}
	outVerifier, _ := note.NewVerifier(outVKey)

	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	appendLeaves := newPOSIXInputLog(t, ctx, inLogDir, inSigner)

	if idxs := appendLeaves([]byte("apple alpha"), []byte("banana beta"), []byte("apple gamma")); !slices.Equal(idxs, []uint64{0, 1, 2}) {
		t.Fatalf("unexpected indices: %v", idxs)
	}

	storage := vindex.StorageConfig{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       testMPTDir(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
		OutputLogDir: filepath.Join(rootDir, "outlog"),
	}
	opts := []vindex.Option{
		vindex.WithInputLog("file://"+inLogDir, inPolicy, wasmhosttest.Host()),
		vindex.WithServing(vindex.ServeOptions{ServeOutputTiles: true}),
		vindex.WithTuning(vindex.TuningOptions{
			ChunkSize:    64,
			PollInterval: 50 * time.Millisecond,
		}),
	}

	engine, err := vindex.New(storage, outSigner, opts...)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	adminTS := httptest.NewServer(engine.AdminHandler())
	defer adminTS.Close()

	for _, liveURL := range []string{
		ts.URL + "/checkpoint",
		ts.URL + "/tile/entries/000.p/1",
		adminTS.URL + "/healthz",
		adminTS.URL + "/readyz",
		adminTS.URL + "/metrics",
	} {
		resp, gErr := ts.Client().Get(liveURL)
		if gErr != nil {
			t.Fatalf("GET %s failed: %v", liveURL, gErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", liveURL, resp.StatusCode)
		}
	}

	outPolicy, err := client.SingleKeyPolicy("test.outputlog", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(out) failed: %v", err)
	}
	verifierCfg := client.Config{
		ExpectedOutputLogOrigin: "test.outputlog",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "test.inputlog",
	}
	cli, err := client.New(ts.URL, verifierCfg, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	collectAscending := func(c *client.Client, key string) ([]uint64, error) {
		res, lErr := c.LookupKey(ctx, key)
		if lErr != nil {
			return nil, lErr
		}
		if len(res.Keys) == 0 {
			return nil, nil
		}
		var out []uint64
		for idx, vErr := range res.Keys[0].Values(ctx) {
			if vErr != nil {
				return nil, vErr
			}
			out = append(out, idx)
		}
		slices.Reverse(out)
		return out, nil
	}

	if indicesApple, err := collectAscending(cli, "apple"); err != nil || !slices.Equal(indicesApple, []uint64{0, 2}) {
		t.Fatalf("LookupKey/Values(apple) = %v, err=%v, want [0 2]", indicesApple, err)
	}
	if prefResp, err := cli.LookupPrefix(ctx, "a"); err != nil || len(prefResp.Keys) != 1 || prefResp.Keys[0].Key != "apple" {
		t.Fatalf("LookupPrefix(a) = %+v, err=%v", prefResp, err)
	}
	if indicesBanana, err := collectAscending(cli, "banana"); err != nil || !slices.Equal(indicesBanana, []uint64{1}) {
		t.Fatalf("LookupKey/Values(banana) = %v, err=%v, want [1]", indicesBanana, err)
	}
	if krCherry, err := cli.LookupKey(ctx, "cherry"); err != nil || len(krCherry.Keys) != 0 {
		t.Fatalf("LookupKey(cherry) = %+v, err=%v", krCherry, err)
	}

	if idxs := appendLeaves([]byte("apple delta")); !slices.Equal(idxs, []uint64{3}) {
		t.Fatalf("unexpected idxs = %v, want [3]", idxs)
	}

	deadline := time.Now().Add(5 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		if indices, err := collectAscending(cli, "apple"); err == nil && slices.Equal(indices, []uint64{0, 2, 3}) {
			updated = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of dynamic leaf 3")
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close failed: %v", err)
	}

	// Warm restart recovery via SyncOnce.
	engine2, err := vindex.New(storage, outSigner, opts...)
	if err != nil {
		t.Fatalf("vindex.New (restart) failed: %v", err)
	}
	if err := engine2.SyncOnce(ctx); err != nil {
		t.Fatalf("engine2.SyncOnce failed: %v", err)
	}
	defer func() { _ = engine2.Close() }()

	ts2 := httptest.NewServer(engine2.Handler())
	defer ts2.Close()

	cli2, err := client.New(ts2.URL, verifierCfg, client.WithHTTPClient(ts2.Client()))
	if err != nil {
		t.Fatalf("client.New (restart) failed: %v", err)
	}
	if indicesRestart, err := collectAscending(cli2, "apple"); err != nil || !slices.Equal(indicesRestart, []uint64{0, 2, 3}) {
		t.Fatalf("after restart: indices=%v, err=%v, want [0 2 3]", indicesRestart, err)
	}
}

func TestEngine_HandlersLifecycleAndValidation(t *testing.T) {
	httpCli := &http.Client{Timeout: 5 * time.Second}

	t.Run("handlers_and_lifecycle_guards", func(t *testing.T) {
		storage, outSigner := newBaseEngineSetup(t)
		engine, err := vindex.New(storage, outSigner,
			vindex.WithServing(vindex.ServeOptions{ServeOutputTiles: true}),
			vindex.WithTuning(vindex.TuningOptions{PollInterval: 10 * time.Millisecond}),
		)
		if err != nil {
			t.Fatalf("vindex.New failed: %v", err)
		}

		adminTS := httptest.NewServer(engine.AdminHandler())
		defer adminTS.Close()

		resp, err := httpCli.Get(adminTS.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
		}

		ctx := context.Background()
		if err := engine.Start(ctx); err != nil {
			t.Fatalf("engine.Start failed: %v", err)
		}
		if err := engine.Start(ctx); err == nil {
			t.Error("expected error calling Start() when already running")
		}
		if err := engine.Run(ctx); err == nil {
			t.Error("expected error calling Run() when already running")
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("engine.Close failed: %v", err)
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}
		if err := engine.Start(ctx); err == nil {
			t.Error("expected error calling Start() after Close")
		}
		if err := engine.Run(ctx); err == nil {
			t.Error("expected error calling Run() after Close")
		}
		if err := engine.SyncOnce(ctx); err == nil {
			t.Error("expected error calling SyncOnce() after Close")
		}
	})

	t.Run("concurrent_run_synconce_and_close_never_deadlocks", func(t *testing.T) {
		for range 8 {
			storage, outSigner := newBaseEngineSetup(t)
			engine, err := vindex.New(storage, outSigner,
				vindex.WithTuning(vindex.TuningOptions{PollInterval: 10 * time.Millisecond}),
			)
			if err != nil {
				t.Fatalf("vindex.New failed: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			wg.Add(4)
			go func() {
				defer wg.Done()
				_ = engine.Start(ctx)
			}()
			go func() {
				defer wg.Done()
				_ = engine.Run(ctx)
			}()
			go func() {
				defer wg.Done()
				_ = engine.SyncOnce(ctx)
			}()
			go func() {
				defer wg.Done()
				_ = engine.Close()
			}()
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("deadlock detected between concurrent Start, Run, SyncOnce, and Close")
			}
			cancel()
		}
	})

	t.Run("disable_ui_and_multilog_input_policy", func(t *testing.T) {
		storage, outSigner := newBaseEngineSetup(t)
		engine, err := vindex.New(storage, outSigner,
			vindex.WithServing(vindex.ServeOptions{DisableUI: true}),
		)
		if err != nil {
			t.Fatalf("vindex.New(DisableUI) failed: %v", err)
		}
		defer func() { _ = engine.Close() }()

		ts := httptest.NewServer(engine.Handler())
		defer ts.Close()
		for _, p := range []string{"/", "/index.html"} {
			r, gErr := httpCli.Get(ts.URL + p)
			if gErr != nil {
				t.Fatalf("GET %s failed: %v", p, gErr)
			}
			_ = r.Body.Close()
			if r.StatusCode != http.StatusNotFound {
				t.Errorf("DisableUI GET %s status = %d, want 404", p, r.StatusCode)
			}
		}

		// Multi-log InputLogPolicy requires explicit WithInputOrigin and rejects checkpoints signed by another log in the policy.
		skeyA, vkeyA, _ := note.GenerateKey(rand.Reader, "multi.log.a")
		_, vkeyB, _ := note.GenerateKey(rand.Reader, "multi.log.b")
		multiPol, err := client.ParsePolicy([]byte("log " + vkeyA + "\nlog " + vkeyB + "\nquorum none\n"))
		if err != nil {
			t.Fatalf("ParsePolicy(multi) failed: %v", err)
		}
		stNoOrigin, signerNoOrigin := newBaseEngineSetup(t)
		if _, err := vindex.New(stNoOrigin, signerNoOrigin,
			vindex.WithInputLog("file:///tmp/unused", multiPol, wasmhosttest.Host()),
		); err == nil {
			t.Fatal("expected multi-log CheckpointPolicy without WithInputOrigin to fail closed")
		}

		inDir := t.TempDir()
		signerA, _ := note.NewSigner(skeyA)
		appCtx, appCancel := context.WithCancel(context.Background())
		defer appCancel()
		drv, err := posix.New(appCtx, posix.Config{Path: inDir})
		if err != nil {
			t.Fatal(err)
		}
		app, shutdown, reader, err := tessera.NewAppender(appCtx, drv, tessera.NewAppendOptions().
			WithCheckpointSigner(signerA).
			WithBatching(4, time.Millisecond).
			WithCheckpointInterval(100*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = shutdown(context.Background()) }()
		awaiter := tessera.NewPublicationAwaiter(appCtx, reader.ReadCheckpoint, 5*time.Millisecond)
		if _, _, err := awaiter.Await(t.Context(), app.Add(t.Context(), tessera.NewEntry([]byte("leaf")))); err != nil {
			t.Fatal(err)
		}

		stWrong, signerWrong := newBaseEngineSetup(t)
		engWrong, err := vindex.New(stWrong, signerWrong,
			vindex.WithInputLog("file://"+inDir, multiPol, wasmhosttest.Host()),
			vindex.WithInputOrigin("multi.log.b"),
		)
		if err != nil {
			t.Fatalf("vindex.New(multi.log.b) failed: %v", err)
		}
		defer func() { _ = engWrong.Close() }()
		if err := engWrong.SyncOnce(t.Context()); err == nil {
			t.Fatal("expected SyncOnce to reject checkpoint signed by multi.log.a when WithInputOrigin=multi.log.b")
		}
	})

	t.Run("run_and_context_cancel", func(t *testing.T) {
		storage, outSigner := newBaseEngineSetup(t)
		engine, err := vindex.New(storage, outSigner,
			vindex.WithTuning(vindex.TuningOptions{PollInterval: 10 * time.Millisecond}),
		)
		if err != nil {
			t.Fatalf("vindex.New failed: %v", err)
		}
		defer func() { _ = engine.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		runErrCh := make(chan error, 1)
		go func() {
			runErrCh <- engine.Run(ctx)
		}()
		time.Sleep(25 * time.Millisecond)
		cancel()

		select {
		case err := <-runErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run returned unexpected error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for engine.Run to exit after cancel()")
		}
	})

	t.Run("config_validation_errors", func(t *testing.T) {
		rootDir := t.TempDir()
		outSKey, outVKey, _ := note.GenerateKey(rand.Reader, "test.out")
		outSigner, _ := note.NewSigner(outSKey)
		_, otherVKey, _ := note.GenerateKey(rand.Reader, "other.origin")
		otherVerifier, _ := note.NewVerifier(otherVKey)
		singleInPol, _ := client.SingleKeyPolicy("test.in", otherVerifier)

		mkStorage := func(sub string) vindex.StorageConfig {
			return vindex.StorageConfig{
				DBPath:       filepath.Join(rootDir, "db_"+sub),
				MPTDir:       filepath.Join(rootDir, "mpt_"+sub),
				OutputLogDir: filepath.Join(rootDir, "out_"+sub),
			}
		}

		for _, tc := range []struct {
			name    string
			storage vindex.StorageConfig
			signer  note.Signer
			opts    []vindex.Option
		}{
			{
				name: "missing_db_path",
				storage: vindex.StorageConfig{
					MPTDir:       filepath.Join(rootDir, "mpt_nodb"),
					OutputLogDir: filepath.Join(rootDir, "out_nodb"),
				},
				signer: outSigner,
			},
			{
				name: "missing_mpt_dir",
				storage: vindex.StorageConfig{
					DBPath:       filepath.Join(rootDir, "db_nompt"),
					OutputLogDir: filepath.Join(rootDir, "out_nompt"),
				},
				signer: outSigner,
			},
			{
				name: "missing_output_log_dir",
				storage: vindex.StorageConfig{
					DBPath: filepath.Join(rootDir, "db_noout"),
					MPTDir: filepath.Join(rootDir, "mpt_noout"),
				},
				signer: outSigner,
			},
			{
				name:    "nil_output_signer",
				storage: mkStorage("nilsigner"),
				signer:  nil,
			},
			{
				name:    "chunk_size_exceeds_max",
				storage: mkStorage("cs"),
				signer:  outSigner,
				opts:    []vindex.Option{vindex.WithTuning(vindex.TuningOptions{ChunkSize: 100_000})},
			},
			{
				name:    "from_overflows_int64",
				storage: mkStorage("from_ovf"),
				signer:  outSigner,
				opts:    []vindex.Option{vindex.WithFrom(uint64(math.MaxInt64) + 1)},
			},
			{
				name:    "input_log_nil_policy",
				storage: mkStorage("nilpol"),
				signer:  outSigner,
				opts:    []vindex.Option{vindex.WithInputLog("file:///tmp/some-log", nil, wasmhosttest.Host())},
			},
			{
				name:    "input_log_nil_wasm",
				storage: mkStorage("nilwasm"),
				signer:  outSigner,
				opts:    []vindex.Option{vindex.WithInputLog("file:///tmp/some-log", singleInPol, nil)},
			},
			{
				name:    "input_log_invalid_scheme",
				storage: mkStorage("badscheme"),
				signer:  outSigner,
				opts:    []vindex.Option{vindex.WithInputLog("ftp://example.com/log", singleInPol, wasmhosttest.Host())},
			},
			{
				name:    "input_log_mismatched_origin",
				storage: mkStorage("inorigin_mismatch"),
				signer:  outSigner,
				opts: []vindex.Option{
					vindex.WithInputLog("file:///tmp/some-log", singleInPol, wasmhosttest.Host()),
					vindex.WithInputOrigin("different.in"),
				},
			},
			{
				name:    "duplicate_input_log_options",
				storage: mkStorage("dupin"),
				signer:  outSigner,
				opts: []vindex.Option{
					vindex.WithInputLog("file:///tmp/some-log", singleInPol, wasmhosttest.Host()),
					vindex.WithUnverifiedInputLog("file:///tmp/some-log", "test.in", wasmhosttest.Host()),
				},
			},
			{
				name:    "mismatched_output_witness_policy_origin",
				storage: mkStorage("outpol_mismatch"),
				signer:  outSigner,
				opts: []vindex.Option{
					vindex.WithOutputWitnessPolicy([]byte("log " + otherVKey + "\nquorum none\n")),
				},
			},
			{
				name:    "conflicting_output_witness_options",
				storage: mkStorage("outwit_conflict"),
				signer:  outSigner,
				opts: []vindex.Option{
					vindex.WithOutputWitnessPolicy([]byte("log " + outVKey + "\nquorum none\n")),
					vindex.WithOutputWitnesses(nil, []string{"https://w.example"}, []string{otherVKey}),
				},
			},
		} {
			if _, err := vindex.New(tc.storage, tc.signer, tc.opts...); err == nil {
				t.Errorf("%s: expected error from vindex.New, got nil", tc.name)
			}
			// Validation failures must not create Pebble/MPT directories on disk.
			if tc.storage.DBPath != "" {
				if _, statErr := os.Stat(tc.storage.DBPath); statErr == nil {
					t.Errorf("%s: unexpected directory created at %s on validation failure", tc.name, tc.storage.DBPath)
				}
			}
		}
	})

	t.Run("fatal_background_halt_flips_readyz_to_503", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.halt.in")
		if err != nil {
			t.Fatal(err)
		}
		inSigner, _ := note.NewSigner(inSKey)
		inVerifier, _ := note.NewVerifier(inVKey)
		inPol, err := client.SingleKeyPolicy("test.halt.in", inVerifier)
		if err != nil {
			t.Fatal(err)
		}

		rootDir := t.TempDir()
		inLogDir1 := filepath.Join(rootDir, "in1")
		inLogDir2 := filepath.Join(rootDir, "in2")

		newPOSIXInputLog(t, ctx, inLogDir1, inSigner)([]byte("honest"))
		newPOSIXInputLog(t, ctx, inLogDir2, inSigner)([]byte("split_view_forged"))

		var serveSplit atomic.Bool
		fs1 := http.FileServer(http.Dir(inLogDir1))
		fs2 := http.FileServer(http.Dir(inLogDir2))
		inTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if serveSplit.Load() {
				fs2.ServeHTTP(w, r)
				return
			}
			fs1.ServeHTTP(w, r)
		}))
		defer inTS.Close()

		storage, outSigner := newBaseEngineSetup(t)
		engine, err := vindex.New(storage, outSigner,
			vindex.WithInputLog(inTS.URL, inPol, wasmhosttest.Host()),
			vindex.WithTuning(vindex.TuningOptions{PollInterval: 25 * time.Millisecond}),
		)
		if err != nil {
			t.Fatalf("vindex.New failed: %v", err)
		}
		defer func() { _ = engine.Close() }()

		if err := engine.Start(ctx); err != nil {
			t.Fatalf("engine.Start failed: %v", err)
		}
		adminTS := httptest.NewServer(engine.AdminHandler())
		defer adminTS.Close()

		readyURL := adminTS.URL + "/readyz"
		resp, err := httpCli.Get(readyURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("initial /readyz status=%v err=%v, want 200", resp, err)
		}
		_ = resp.Body.Close()

		serveSplit.Store(true)
		deadline := time.Now().Add(3 * time.Second)
		halted := false
		for time.Now().Before(deadline) {
			r503, rErr := httpCli.Get(readyURL)
			if rErr == nil {
				_ = r503.Body.Close()
				if r503.StatusCode == http.StatusServiceUnavailable {
					halted = true
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !halted {
			t.Fatal("expected /readyz to transition to 503 after fatal background sync error")
		}
	})
}
