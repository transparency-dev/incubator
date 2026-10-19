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

// Package e2e_test implements opaque-box, requirement-driven end-to-end tests
// for VIndex v1 covering Tiers 1-4.
package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
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

func newTestWASMHost(t *testing.T) *vindex.WASMHost {
	t.Helper()
	return wasmhosttest.Host()
}

var exampleWASMBuilders = struct {
	mu       sync.Mutex
	builders map[string]func() (*vindex.WASMHost, error)
}{builders: make(map[string]func() (*vindex.WASMHost, error))}

// mustExampleWASMHost compiles a vindex/mapfn/examples/<pkg> WASM binary once per
// test binary (concurrently across distinct <pkg> names) and shares the compiled *vindex.WASMHost.
func mustExampleWASMHost(t *testing.T, pkg string) *vindex.WASMHost {
	t.Helper()
	exampleWASMBuilders.mu.Lock()
	fn, ok := exampleWASMBuilders.builders[pkg]
	if !ok {
		fn = sync.OnceValues(func() (*vindex.WASMHost, error) {
			tmpDir, err := os.MkdirTemp("", "vindex-e2e-wasm-*")
			if err != nil {
				return nil, fmt.Errorf("MkdirTemp failed: %w", err)
			}
			defer func() { _ = os.RemoveAll(tmpDir) }()

			wasmPath := filepath.Join(tmpDir, pkg+".wasm")
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-buildmode=c-shared", "-o", wasmPath,
				"github.com/transparency-dev/incubator/vindex/mapfn/examples/"+pkg)
			cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("failed to build %s.wasm: %w\n%s", pkg, err, string(out))
			}
			wasmBytes, err := os.ReadFile(wasmPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read %s.wasm: %w", pkg, err)
			}
			return vindex.NewWASMHost(context.Background(), wasmBytes, 2)
		})
		exampleWASMBuilders.builders[pkg] = fn
	}
	exampleWASMBuilders.mu.Unlock()

	h, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// testCluster bundles an isolated Tessera Input Log and VIndex configuration.
type testCluster struct {
	t           *testing.T
	ctx         context.Context
	inLogDir    string
	inOrigin    string
	outOrigin   string
	inPolicy    client.CheckpointPolicy
	outSigner   note.Signer
	outVerifier note.Verifier
	inAppender  *tessera.Appender
	inAwaiter   *tessera.PublicationAwaiter
	storage     vindex.StorageConfig
	chunkSize   uint64
}

// newTestCluster initializes isolated cryptographic keys, directories, and Tessera log appender.
func newTestCluster(t *testing.T, ctx context.Context, chunkSize uint64) *testCluster {
	t.Helper()
	rootDir := t.TempDir()

	const inOrigin = "test.e2e.inputlog"
	const outOrigin = "test.e2e.outputlog"

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, inOrigin)
	if err != nil {
		t.Fatalf("GenerateKey inputlog failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner inputlog failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier inputlog failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatalf("GenerateKey outputlog failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("NewSigner outputlog failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier outputlog failed: %v", err)
	}

	inLogDir := filepath.Join(rootDir, "inlog")
	outLogDir := filepath.Join(rootDir, "outlog")

	appCtx, appCancel := context.WithCancel(context.Background())
	inDriver, err := posix.New(appCtx, posix.Config{Path: inLogDir})
	if err != nil {
		appCancel()
		t.Fatalf("posix.New inputlog failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(appCtx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(256, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		appCancel()
		t.Fatalf("NewAppender inputlog failed: %v", err)
	}
	t.Cleanup(func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sCancel()
		_ = inShutdown(sCtx)
		appCancel()
	})

	inAwaiter := tessera.NewPublicationAwaiter(appCtx, inReader.ReadCheckpoint, 5*time.Millisecond)
	if chunkSize == 0 {
		chunkSize = 64
	}
	inPolicy, err := client.SingleKeyPolicy(inOrigin, inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy inputlog failed: %v", err)
	}

	return &testCluster{
		t:           t,
		ctx:         ctx,
		inLogDir:    inLogDir,
		inOrigin:    inOrigin,
		outOrigin:   outOrigin,
		inPolicy:    inPolicy,
		outSigner:   outSigner,
		outVerifier: outVerifier,
		inAppender:  inAppender,
		inAwaiter:   inAwaiter,
		storage: vindex.StorageConfig{
			DBPath:       filepath.Join(rootDir, "db"),
			MPTDir:       testMPTDir(rootDir, "mpt"),
			TileCacheDir: filepath.Join(rootDir, "cache"),
			OutputLogDir: outLogDir,
		},
		chunkSize: chunkSize,
	}
}

func (c *testCluster) newEngine(wasm *vindex.WASMHost, extraOpts ...vindex.Option) (*vindex.Engine, error) {
	opts := []vindex.Option{
		vindex.WithInputLog("file://"+c.inLogDir, c.inPolicy, wasm),
		vindex.WithTuning(vindex.TuningOptions{
			ChunkSize:    c.chunkSize,
			PollInterval: 40 * time.Millisecond,
			Workers:      2,
		}),
	}
	opts = append(opts, extraOpts...)
	return vindex.New(c.storage, c.outSigner, opts...)
}

func (c *testCluster) appendLeaves(payloads ...[]byte) {
	c.t.Helper()
	if len(payloads) == 0 {
		return
	}
	futs := make([]tessera.IndexFuture, len(payloads))
	for i, p := range payloads {
		futs[i] = c.inAppender.Add(c.ctx, tessera.NewEntry(p))
	}
	for i, fut := range futs {
		if _, _, err := c.inAwaiter.Await(c.ctx, fut); err != nil {
			c.t.Fatalf("failed to append leaf %d: %v", i, err)
		}
	}
}

func (c *testCluster) newClient(serverURL string) *client.Client {
	c.t.Helper()
	outPolicy, err := client.SingleKeyPolicy(c.outOrigin, c.outVerifier)
	if err != nil {
		c.t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	cli, err := client.New(serverURL, client.Config{
		OutputLogPolicy:        outPolicy,
		ExpectedInputLogOrigin: c.inOrigin,
	})
	if err != nil {
		c.t.Fatalf("client.New failed: %v", err)
	}
	return cli
}

func getAllAscending(ctx context.Context, cli *client.Client, key string) ([]uint64, error) {
	kr, err := cli.LookupKey(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(kr.Keys) == 0 {
		return nil, nil
	}
	var out []uint64
	for idx, err := range kr.Keys[0].Values(ctx) {
		if err != nil {
			return nil, err
		}
		out = append(out, idx)
	}
	slices.Reverse(out)
	return out, nil
}

// -----------------------------------------------------------------------------
// TIER 1 & 2: Core Lifecycle, Chunking, Multi-Page Pagination & Boundary Cases
// -----------------------------------------------------------------------------

// TestTier1_HappyPath_CatchupTransitionAndClientLookup verifies the complete VIndex lifecycle:
// offline SyncOnce catchup -> Start serving transition, operational endpoint isolation,
// verified client lookups, absent key non-inclusion proofs, standalone /checkpoint consistency,
// and live background sync as new leaves arrive.
func TestTier1_HappyPath_CatchupTransitionAndClientLookup(t *testing.T) {
	wasm := newTestWASMHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64)
	cluster.appendLeaves(
		[]byte("alice entry_1"),
		[]byte("bob entry_1"),
		[]byte("carol entry_1"),
		[]byte("alice entry_2"),
	)

	engine, err := cluster.newEngine(wasm)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	adminTS := httptest.NewServer(engine.AdminHandler())
	defer adminTS.Close()

	cli := cluster.newClient(ts.URL)

	// 1. Operational endpoints must be isolated to adminMux and 404 on public mux.
	for _, opPath := range []string{"/healthz", "/readyz", "/syncz", "/metrics"} {
		resPub, err := http.Get(ts.URL + opPath)
		if err != nil {
			t.Fatalf("GET public %s err %v", opPath, err)
		}
		_ = resPub.Body.Close()
		if resPub.StatusCode != http.StatusNotFound {
			t.Fatalf("GET public %s status = %d, want 404", opPath, resPub.StatusCode)
		}
	}
	for _, opPath := range []string{"/healthz", "/readyz", "/metrics"} {
		resAdm, err := http.Get(adminTS.URL + opPath)
		if err != nil {
			t.Fatalf("GET admin %s err %v", opPath, err)
		}
		_ = resAdm.Body.Close()
		if resAdm.StatusCode != http.StatusOK {
			t.Fatalf("GET admin %s status = %d, want 200", opPath, resAdm.StatusCode)
		}
	}

	// 2. Query existing keys and standalone /checkpoint consistency.
	keysAlice, err := cli.LookupKey(ctx, "alice")
	if err != nil {
		t.Fatalf("LookupKey(alice) failed: %v", err)
	}
	if len(keysAlice.Keys) != 1 || keysAlice.InputSize < 4 || keysAlice.MPTRoot == [32]byte{} {
		t.Fatalf("unexpected LookupKey(alice) result: %+v", keysAlice)
	}

	cpRes, err := http.Get(ts.URL + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint failed: %v", err)
	}
	cpBytes, err := io.ReadAll(cpRes.Body)
	_ = cpRes.Body.Close()
	if err != nil || cpRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /checkpoint status = %d, err = %v", cpRes.StatusCode, err)
	}
	outCP, _, _, err := log.ParseCheckpoint(cpBytes, cluster.outOrigin, cluster.outVerifier)
	if err != nil {
		t.Fatalf("ParseCheckpoint failed: %v", err)
	}
	if keysAlice.OutputSize != outCP.Size {
		t.Fatalf("OutputSize mismatch: lookup got %d, /checkpoint got %d", keysAlice.OutputSize, outCP.Size)
	}

	for key, want := range map[string][]uint64{
		"alice": {0, 3},
		"bob":   {1},
		"carol": {2},
		"eve":   nil,
	} {
		got, lErr := getAllAscending(ctx, cli, key)
		if lErr != nil || !slices.Equal(got, want) {
			t.Fatalf("getAllAscending(%q) = %v, err=%v, want %v", key, got, lErr, want)
		}
	}

	// 3. Dynamically append leaf 4 ("alice entry_3") while engine runs in background mode.
	cluster.appendLeaves([]byte("alice entry_3"))

	deadline := time.Now().Add(10 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		indices, err := getAllAscending(ctx, cli, "alice")
		if err == nil && slices.Equal(indices, []uint64{0, 3, 4}) {
			updated = true
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of leaf 4")
	}
}

// TestTier1_MultiKeyDeduplication_MultiPageChunksAndUnalignedClamping exercises per-leaf
// multi-key mapping and duplicate suppression, >100-entry multi-page backward /values pagination
// across 4-entry micro-chunks, and unaligned 259-leaf (1 full bundle + .p/3 partial bundle) clamping.
func TestTier1_MultiKeyDeduplication_MultiPageChunksAndUnalignedClamping(t *testing.T) {
	wasm := newTestWASMHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 4)

	const totalLeaves = 259 // 256-entry full bundle + .p/3 partial bundle
	payloads := make([][]byte, totalLeaves)
	wantHot := make([]uint64, totalLeaves)
	for i := range totalLeaves {
		wantHot[i] = uint64(i)
		switch i {
		case 0:
			payloads[i] = []byte("news\ntech\nnews\nhot_topic")
		case 1:
			payloads[i] = []byte("tech\nscience\nhot_topic")
		case 2:
			payloads[i] = []byte("news\nhot_topic")
		default:
			payloads[i] = fmt.Appendf(nil, "hot_topic leaf_%03d", i)
		}
	}
	cluster.appendLeaves(payloads...)

	engine, err := cluster.newEngine(wasm)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := cluster.newClient(ts.URL)

	hotResp, err := cli.LookupKey(ctx, "hot_topic")
	if err != nil || hotResp.InputSize != totalLeaves {
		t.Fatalf("LookupKey(hot_topic) InputSize=%v err=%v, want %d", hotResp, err, totalLeaves)
	}

	for key, want := range map[string][]uint64{
		"news":      {0, 2},
		"tech":      {0, 1},
		"science":   {1},
		"hot_topic": wantHot,
	} {
		got, lErr := getAllAscending(ctx, cli, key)
		if lErr != nil || !slices.Equal(got, want) {
			t.Fatalf("getAllAscending(%q) len=%d err=%v, want len=%d", key, len(got), lErr, len(want))
		}
	}
}

// TestTier2_EmptyInputLog_ReadinessAndLookup verifies engine and client behavior
// when operating against a signed size-0 Input Log checkpoint (0 leaves).
func TestTier2_EmptyInputLog_ReadinessAndLookup(t *testing.T) {
	wasm := newTestWASMHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	rootDir := t.TempDir()
	const inOrigin = "test.e2e.inputlog"
	const outOrigin = "test.e2e.outputlog"

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, inOrigin)
	if err != nil {
		t.Fatal(err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)
	inPol, err := client.SingleKeyPolicy(inOrigin, inVerifier)
	if err != nil {
		t.Fatal(err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatal(err)
	}
	outSigner, _ := note.NewSigner(outSKey)
	outVerifier, _ := note.NewVerifier(outVKey)
	outPol, err := client.SingleKeyPolicy(outOrigin, outVerifier)
	if err != nil {
		t.Fatal(err)
	}

	emptyInDir := filepath.Join(rootDir, "empty-inlog")
	if err := os.MkdirAll(emptyInDir, 0o755); err != nil {
		t.Fatal(err)
	}
	emptyCP := log.Checkpoint{
		Origin: inOrigin,
		Size:   0,
		Hash:   rfc6962.DefaultHasher.EmptyRoot(),
	}
	signedCP, err := note.Sign(&note.Note{Text: string(emptyCP.Marshal())}, inSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emptyInDir, "checkpoint"), signedCP, 0o644); err != nil {
		t.Fatal(err)
	}

	engine, err := vindex.New(
		vindex.StorageConfig{
			DBPath:       filepath.Join(rootDir, "db"),
			MPTDir:       testMPTDir(rootDir, "mpt"),
			TileCacheDir: filepath.Join(rootDir, "cache"),
			OutputLogDir: filepath.Join(rootDir, "outlog"),
		},
		outSigner,
		vindex.WithInputLog("file://"+emptyInDir, inPol, wasm),
		vindex.WithTuning(vindex.TuningOptions{PollInterval: 40 * time.Millisecond, Workers: 1}),
	)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	adminTS := httptest.NewServer(engine.AdminHandler())
	defer adminTS.Close()

	resReady, err := http.Get(adminTS.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET admin /readyz err: %v", err)
	}
	_ = resReady.Body.Close()
	if resReady.StatusCode != http.StatusOK {
		t.Fatalf("GET admin /readyz status = %d, want 200", resReady.StatusCode)
	}

	cli, err := client.New(ts.URL, client.Config{
		OutputLogPolicy:        outPol,
		ExpectedInputLogOrigin: inOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.LookupKey(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("LookupKey(nonexistent) on empty log failed: %v", err)
	}
	if resp.InputSize != 0 || len(resp.Keys) != 0 {
		t.Fatalf("LookupKey on empty log got InputSize=%d, Keys=%+v; want InputSize=0, Keys=[]", resp.InputSize, resp.Keys)
	}
}

// -----------------------------------------------------------------------------
// TIER 3: Cross-Feature Combinations & Invariants
// -----------------------------------------------------------------------------

// TestTier3_ConcurrentReadsDuringContinuousIngestion simulates concurrent reader traffic
// while a writer appends batches of leaves into the Input Log, verifying zero races,
// full value-log pagination verification, and monotonic convergence to the tip.
func TestTier3_ConcurrentReadsDuringContinuousIngestion(t *testing.T) {
	wasm := newTestWASMHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64)

	initial := make([][]byte, 10)
	for i := range initial {
		initial[i] = fmt.Appendf(nil, "concurrent_key_%d leaf_%d", i%5, i)
	}
	cluster.appendLeaves(initial...)

	keyNames := make([]string, 5)
	for i := range keyNames {
		keyNames[i] = fmt.Sprintf("concurrent_key_%d", i)
	}

	engine, err := cluster.newEngine(wasm)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	var readSuccesses atomic.Uint64
	var readFailures atomic.Uint64
	var stopFlag atomic.Bool
	var wg sync.WaitGroup
	defer func() {
		stopFlag.Store(true)
		wg.Wait()
	}()

	const numReaders = 6
	for r := range numReaders {
		workerCli := cluster.newClient(ts.URL)
		wg.Add(1)
		go func(workerID int, rCli *client.Client) {
			defer wg.Done()
			i := workerID
			for !stopFlag.Load() {
				targetKeyName := keyNames[i%5]
				kResp, err := rCli.LookupKey(ctx, targetKeyName)
				if err != nil {
					if ctx.Err() == nil {
						readFailures.Add(1)
					}
				} else if len(kResp.Keys) > 0 {
					failed := false
					for _, vErr := range kResp.Keys[0].Values(ctx) {
						if vErr != nil {
							failed = true
							break
						}
					}
					if failed {
						if ctx.Err() == nil {
							readFailures.Add(1)
						}
					} else {
						readSuccesses.Add(1)
					}
				}
				i++
				time.Sleep(2 * time.Millisecond)
			}
		}(r, workerCli)
	}

	// Append 30 more leaves in 5 waves of 6 leaves.
	for wave := range 5 {
		batch := make([][]byte, 6)
		for j := range batch {
			idx := 10 + wave*6 + j
			batch[j] = fmt.Appendf(nil, "concurrent_key_%d leaf_%d", idx%5, idx)
		}
		cluster.appendLeaves(batch...)
	}

	probeCli := cluster.newClient(ts.URL)
	deadline := time.Now().Add(15 * time.Second)
	caughtUp := false
	for time.Now().Before(deadline) {
		res, err := probeCli.LookupKey(ctx, keyNames[0])
		if err == nil && res.InputSize == 40 && readSuccesses.Load() >= 50 {
			caughtUp = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	stopFlag.Store(true)
	wg.Wait()

	if readFailures.Load() > 0 {
		t.Fatalf("encountered %d read failures during concurrent ingestion", readFailures.Load())
	}
	if !caughtUp {
		t.Fatalf("did not converge to InputSize=40 with >=50 reads (readSuccesses=%d)", readSuccesses.Load())
	}
}

// TestTier3_CrashRecoveryAndIdempotency verifies 3-Phase Zero-WAL crash recovery:
// ingests 20 leaves, closes the engine, writes 15 more leaves while offline, and restarts
// on the same directories without duplicate entries.
func TestTier3_CrashRecoveryAndIdempotency(t *testing.T) {
	wasm := newTestWASMHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64)

	batch1 := make([][]byte, 20)
	for i := range batch1 {
		if i%2 == 0 {
			batch1[i] = fmt.Appendf(nil, "k1 %d", i)
		} else {
			batch1[i] = fmt.Appendf(nil, "k2 %d", i)
		}
	}
	cluster.appendLeaves(batch1...)

	engine1, err := cluster.newEngine(wasm)
	if err != nil {
		t.Fatalf("vindex.New (initial) failed: %v", err)
	}
	defer func() { _ = engine1.Close() }()
	if err := engine1.Start(ctx); err != nil {
		t.Fatalf("engine1.Start failed: %v", err)
	}

	ts1 := httptest.NewServer(engine1.Handler())
	defer ts1.Close()
	cli1 := cluster.newClient(ts1.URL)
	idxInit, err := getAllAscending(ctx, cli1, "k1")
	if err != nil || len(idxInit) != 10 {
		t.Fatalf("initial lookup k1 failed: indices=%v, err=%v", idxInit, err)
	}
	ts1.Close()

	if err := engine1.Close(); err != nil {
		t.Fatalf("engine1.Close failed: %v", err)
	}

	batch2 := make([][]byte, 15)
	for j := range batch2 {
		i := 20 + j
		if i%2 == 0 {
			batch2[j] = fmt.Appendf(nil, "k1 %d", i)
		} else {
			batch2[j] = fmt.Appendf(nil, "k2 %d", i)
		}
	}
	cluster.appendLeaves(batch2...)

	engine2, err := cluster.newEngine(wasm)
	if err != nil {
		t.Fatalf("vindex.New (restart) failed: %v", err)
	}
	defer func() { _ = engine2.Close() }()
	if err := engine2.Start(ctx); err != nil {
		t.Fatalf("engine2.Start (crash recovery) failed: %v", err)
	}

	ts2 := httptest.NewServer(engine2.Handler())
	defer ts2.Close()
	cli2 := cluster.newClient(ts2.URL)

	deadline := time.Now().Add(15 * time.Second)
	recovered := false
	for time.Now().Before(deadline) {
		idxK1, err1 := getAllAscending(ctx, cli2, "k1")
		idxK2, err2 := getAllAscending(ctx, cli2, "k2")
		if err1 == nil && err2 == nil && len(idxK1) == 18 && len(idxK2) == 17 {
			dupFound := false
			for i := 1; i < len(idxK1); i++ {
				if idxK1[i] <= idxK1[i-1] {
					dupFound = true
					break
				}
			}
			if !dupFound {
				recovered = true
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("timed out waiting for crash recovery catchup across offline leaves")
	}
}

// TestTier3_SuffixFromHorizonAndReversedDNSPrefixPolicy exercises suffix indexing (From > 0),
// reversed-DNS prefix policy enforcement (rejecting broad single-label TLD scans), and MaxPrefixKeys(413).
func TestTier3_SuffixFromHorizonAndReversedDNSPrefixPolicy(t *testing.T) {
	wasm := newTestWASMHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64)
	cluster.appendLeaves(
		[]byte("com.example.early."), // leaf 0 (< From, skipped)
		[]byte("com.example.alpha."), // leaf 1 (< From, skipped)
		[]byte("com.other.early."),   // leaf 2 (< From, skipped)
		[]byte("com.example.alpha."), // leaf 3 (>= From, indexed)
		[]byte("com.example.beta."),  // leaf 4 (>= From, indexed)
		[]byte("com.example.gamma."), // leaf 5 (>= From, indexed)
	)

	revPol, err := vindex.ParsePrefixPolicy("reversed-dns")
	if err != nil {
		t.Fatalf("ParsePrefixPolicy failed: %v", err)
	}
	engine, err := cluster.newEngine(
		wasm,
		vindex.WithFrom(3),
		vindex.WithServing(vindex.ServeOptions{
			PrefixPolicyFunc: revPol,
			MaxPrefixKeys:    2,
		}),
	)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := cluster.newClient(ts.URL)

	earlyRes, err := cli.LookupKey(ctx, "com.example.early.")
	if err != nil {
		t.Fatalf("LookupKey(com.example.early.) failed: %v", err)
	}
	if earlyRes.From != 3 || len(earlyRes.Keys) != 0 {
		t.Fatalf("LookupKey(com.example.early.) From=%d, Keys=%+v; want From=3, Keys=[]", earlyRes.From, earlyRes.Keys)
	}

	alphaIdx, err := getAllAscending(ctx, cli, "com.example.alpha.")
	if err != nil || !slices.Equal(alphaIdx, []uint64{3}) {
		t.Fatalf("getAllAscending(com.example.alpha.) = %v, err=%v, want [3]", alphaIdx, err)
	}

	if _, err := cli.LookupPrefix(ctx, "com."); !errors.Is(err, client.ErrBadRequest) {
		t.Fatalf("LookupPrefix(com.) err = %v, want ErrBadRequest", err)
	}
	if _, err := cli.LookupPrefix(ctx, "com.example."); !errors.Is(err, client.ErrTooManyKeys) {
		t.Fatalf("LookupPrefix(com.example.) err = %v, want ErrTooManyKeys", err)
	}
	if _, err := cli.LookupPrefix(ctx, "com.example.a"); !errors.Is(err, client.ErrBadRequest) {
		t.Fatalf("LookupPrefix(com.example.a) err = %v, want ErrBadRequest", err)
	}

	subRes, err := cli.LookupPrefix(ctx, "com.example.alpha.")
	if err != nil || len(subRes.Keys) != 1 || subRes.Keys[0].Key != "com.example.alpha." {
		t.Fatalf("LookupPrefix(com.example.alpha.) = %+v, err=%v; want [com.example.alpha.]", subRes, err)
	}
}

// -----------------------------------------------------------------------------
// TIER 4: Real-World Scenarios (Personalities)
// -----------------------------------------------------------------------------

// TestTier4_SumDBPersonality_RealWorld tests authentic Go SumDB log indexing:
// parsing module path and version lines, filtering out pseudo-versions, indexing
// release versions, and performing verified lookups for module releases.
func TestTier4_SumDBPersonality_RealWorld(t *testing.T) {
	sumdbMapper := mustExampleWASMHost(t, "sumdb")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64)
	cluster.appendLeaves(
		[]byte("golang.org/x/text v0.3.7 h1:abcdef12345=\n"),
		[]byte("golang.org/x/text v0.3.7/go.mod h1:67890abcde=\n"),
		[]byte("golang.org/x/crypto v0.14.0 h1:crypto12345=\n"),
		[]byte("golang.org/x/text v0.0.0-20190502123456-abcdef123456 h1:pseudo12345=\n"),
		[]byte("golang.org/x/text v0.4.0 h1:text40000000=\n"),
		[]byte("example.com/pseudoonly v0.0.0-20200101000000-111111111111 h1:hash=\n"),
	)

	engine, err := cluster.newEngine(sumdbMapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := cluster.newClient(ts.URL)

	idxText, err := getAllAscending(ctx, cli, "golang.org/x/text")
	if err != nil || !slices.Equal(idxText, []uint64{0, 1, 4}) {
		t.Fatalf("getAllAscending(golang.org/x/text) = %v, err=%v, want [0, 1, 4]", idxText, err)
	}
	idxCrypto, err := getAllAscending(ctx, cli, "golang.org/x/crypto")
	if err != nil || !slices.Equal(idxCrypto, []uint64{2}) {
		t.Fatalf("getAllAscending(golang.org/x/crypto) = %v, err=%v, want [2]", idxCrypto, err)
	}
	prefixResp, err := cli.LookupPrefix(ctx, "golang.org/x/")
	if err != nil || len(prefixResp.Keys) != 2 {
		t.Fatalf("LookupPrefix(golang.org/x/) len = %d, err=%v, want 2", len(prefixResp.Keys), err)
	}
	respPseudo, err := cli.LookupKey(ctx, "example.com/pseudoonly")
	if err != nil || len(respPseudo.Keys) != 0 {
		t.Fatalf("LookupKey(example.com/pseudoonly) keys=%+v, err=%v, want empty", respPseudo, err)
	}
}

// TestTier4_CTPersonality_RealWorld builds the ct.wasm MapFn and indexes real DER X.509
// certificates into reversed-DNS canonical keys, verifying query-time hierarchical subdomain
// prefix discovery and non-inclusion proofs for unissued domains.
func TestTier4_CTPersonality_RealWorld(t *testing.T) {
	ctMapper := mustExampleWASMHost(t, "ct")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cluster := newTestCluster(t, ctx, 64)

	certPub, certPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	makeCertDER := func(serial int64, sans ...string) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: sans[0]},
			DNSNames:     sans,
			NotBefore:    time.Unix(1_700_000_000, 0).UTC(),
			NotAfter:     time.Unix(1_800_000_000, 0).UTC(),
		}
		der, cErr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certPub, certPriv)
		if cErr != nil {
			t.Fatalf("x509.CreateCertificate failed: %v", cErr)
		}
		return der
	}

	cluster.appendLeaves(
		makeCertDER(1, "api.v1.transparency.dev"),
		makeCertDER(2, "auth.transparency.dev", "xn--bcher-kva.transparency.dev"),
		makeCertDER(3, "www.google.com"),
	)

	engine, err := cluster.newEngine(ctMapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := cluster.newClient(ts.URL)

	respTransPrefix, err := cli.LookupPrefix(ctx, "dev.transparency.")
	if err != nil || len(respTransPrefix.Keys) != 3 {
		t.Fatalf("LookupPrefix(dev.transparency.) keys = %d, err=%v, want 3", len(respTransPrefix.Keys), err)
	}

	idnKey, err := client.DomainToCanonicalKey("bücher.transparency.dev")
	if err != nil {
		t.Fatalf("DomainToCanonicalKey(bücher.transparency.dev) failed: %v", err)
	}
	idxIDN, err := getAllAscending(ctx, cli, idnKey)
	if err != nil || !slices.Equal(idxIDN, []uint64{1}) {
		t.Fatalf("getAllAscending(%s) = %v, err=%v, want [1]", idnKey, idxIDN, err)
	}

	idxAuth, err := getAllAscending(ctx, cli, "dev.transparency.auth.")
	if err != nil || !slices.Equal(idxAuth, []uint64{1}) {
		t.Fatalf("getAllAscending(dev.transparency.auth.) = %v, err=%v, want [1]", idxAuth, err)
	}

	respFake, err := cli.LookupKey(ctx, "com.fake.malicious.")
	if err != nil || len(respFake.Keys) != 0 {
		t.Fatalf("LookupKey(com.fake.malicious.) keys=%+v, err=%v, want empty", respFake, err)
	}
}
