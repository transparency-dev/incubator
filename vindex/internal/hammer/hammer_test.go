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

package hammer_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	"github.com/transparency-dev/incubator/vindex/internal/hammer"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
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

var buildHammerWASMOnce = struct {
	mu       sync.Mutex
	builders map[string]func() (*vindex.WASMHost, error)
}{builders: make(map[string]func() (*vindex.WASMHost, error))}

func mustHammerExampleWASM(t *testing.T, pkg string) *vindex.WASMHost {
	t.Helper()
	buildHammerWASMOnce.mu.Lock()
	fn, ok := buildHammerWASMOnce.builders[pkg]
	if !ok {
		fn = sync.OnceValues(func() (*vindex.WASMHost, error) {
			tmpDir, err := os.MkdirTemp("", "hammer-wasm-*")
			if err != nil {
				return nil, err
			}
			defer func() { _ = os.RemoveAll(tmpDir) }()
			wasmPath := filepath.Join(tmpDir, "plugin.wasm")
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-buildmode=c-shared", "-o", wasmPath, pkg)
			cmd.Env = append(cmd.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("WASM build(%s) failed: %w\n%s", pkg, err, string(out))
			}
			wasmBytes, err := os.ReadFile(wasmPath)
			if err != nil {
				return nil, err
			}
			return vindex.NewWASMHost(context.Background(), wasmBytes, 1)
		})
		buildHammerWASMOnce.builders[pkg] = fn
	}
	buildHammerWASMOnce.mu.Unlock()

	h, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func wasmKeysForBundle(t *testing.T, host *vindex.WASMHost, leaves [][]byte) [][]string {
	t.Helper()
	mapped, err := host.MapBundle(t.Context(), leaves)
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}
	out := make([][]string, len(mapped))
	for i, m := range mapped {
		keys := make([]string, 0, len(m))
		for _, kv := range m {
			keys = append(keys, kv.Key)
		}
		slices.Sort(keys)
		out[i] = slices.Compact(keys)
	}
	return out
}

func TestGenerator_DistributionsAndPureGoVsWASMEquivalence(t *testing.T) {
	t.Parallel()

	t.Run("Zipfian_And_Uniform", func(t *testing.T) {
		t.Parallel()
		zipfGen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistZipf,
			NumKeys:      100,
			ZipfS:        1.5,
			ZipfV:        1.0,
			Seed:         12345,
			LeafFormat:   hammer.FormatRaw,
		})
		counts := make(map[string]int)
		uniformHits := make(map[string]int)
		var rawLeaves [][]byte
		for range 1000 {
			e := zipfGen.NextLeaf()
			counts[e.Key]++
			uniformHits[zipfGen.SampleUniformKey()]++
			if len(rawLeaves) < 32 {
				rawLeaves = append(rawLeaves, e.LeafData)
			}
		}
		if counts[hammer.KeyForID(0)] < 50 {
			t.Fatalf("expected hot key count >= 50, got %d", counts[hammer.KeyForID(0)])
		}
		if len(uniformHits) < 80 {
			t.Fatalf("expected SampleUniformKey to cover >= 80/100 keys even under Zipf generator, got %d", len(uniformHits))
		}
		// Key ID 7 embeds RFC 3986 delimiters ('+', '=', '&') and '~'.
		if !strings.Contains(hammer.KeyForID(7), "+") || !strings.Contains(hammer.KeyForID(7), "&") {
			t.Fatalf("expected KeyForID(7) to contain RFC 3986 delimiters, got %q", hammer.KeyForID(7))
		}

		wasmOut := wasmKeysForBundle(t, wasmhosttest.Host(), rawLeaves)
		for i, leaf := range rawLeaves {
			pureOut, err := hammer.MapRawLeaf(leaf)
			if err != nil {
				t.Fatalf("MapRawLeaf(%d) failed: %v", i, err)
			}
			if !slices.Equal(pureOut, wasmOut[i]) {
				t.Fatalf("raw leaf %d pure-Go keys %v != WASM keys %v", i, pureOut, wasmOut[i])
			}
		}

		uniGen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      20,
			Seed:         54321,
		})
		uniCounts := make(map[string]int)
		for range 1000 {
			uniCounts[uniGen.NextLeaf().Key]++
		}
		if len(uniCounts) != 20 {
			t.Fatalf("expected all 20 keys under uniform, got %d", len(uniCounts))
		}
		for range 20 {
			nonKey := uniGen.SampleNonInclusionKey()
			for id := range uint64(20) {
				if nonKey == hammer.KeyForID(id) {
					t.Fatalf("non-inclusion key %s collided with ID %d", nonKey, id)
				}
			}
		}
	})

	t.Run("SumDB_PureGo_Matches_SumDB_WASM", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      16,
			Seed:         101,
			LeafFormat:   hammer.FormatSumDB,
		})
		var leaves [][]byte
		var sawEscapedBang bool
		for range 32 {
			e := gen.NextLeaf()
			if strings.Contains(e.Key, "!") {
				sawEscapedBang = true
			}
			leaves = append(leaves, e.LeafData)
		}
		if !sawEscapedBang {
			t.Fatalf("expected synthetic SumDB leaves to include mixed-case '!'-escaped module paths")
		}

		host := mustHammerExampleWASM(t, "github.com/transparency-dev/incubator/vindex/mapfn/examples/sumdb")
		wasmOut := wasmKeysForBundle(t, host, leaves)
		for i, leaf := range leaves {
			pureOut, err := hammer.MapSumDBLeaf(leaf)
			if err != nil {
				t.Fatalf("MapSumDBLeaf(%d) failed: %v", i, err)
			}
			if !slices.Equal(pureOut, wasmOut[i]) || len(pureOut) != 1 {
				t.Fatalf("sumdb leaf %d pure-Go keys %v != sumdb.wasm keys %v", i, pureOut, wasmOut[i])
			}
		}
	})

	t.Run("CT_PureGo_Matches_CT_WASM", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      16,
			Seed:         202,
			LeafFormat:   hammer.FormatCT,
			CTMinDomains: 2,
			CTMaxDomains: 4,
		})
		var leaves [][]byte
		var sawWildcard bool
		for range 24 {
			entry := gen.NextLeaf()
			certLen := int(entry.LeafData[12])<<16 | int(entry.LeafData[13])<<8 | int(entry.LeafData[14])
			if _, err := x509.ParseCertificate(entry.LeafData[15 : 15+certLen]); err != nil {
				t.Fatalf("x509.ParseCertificate failed on synthetic CT leaf: %v", err)
			}
			leaves = append(leaves, entry.LeafData)
		}

		host := mustHammerExampleWASM(t, "github.com/transparency-dev/incubator/vindex/mapfn/examples/ct")
		wasmOut := wasmKeysForBundle(t, host, leaves)
		for i, leaf := range leaves {
			pureOut, err := hammer.MapCTLeaf(leaf)
			if err != nil {
				t.Fatalf("MapCTLeaf(%d) failed: %v", i, err)
			}
			for _, k := range pureOut {
				if strings.HasSuffix(k, "*.") {
					sawWildcard = true
				}
			}
			if !slices.Equal(pureOut, wasmOut[i]) {
				t.Fatalf("CT leaf %d pure-Go keys %v != ct.wasm keys %v", i, pureOut, wasmOut[i])
			}
		}
		if !sawWildcard {
			t.Fatalf("expected synthetic CT leaves to exercise wildcard canonicalization")
		}
	})
}

func TestOracle_OutOfOrderCappingAndExactVerification(t *testing.T) {
	t.Parallel()
	oracle := hammer.NewOracle(hammer.MapRawLeaf, 4)

	// Record out-of-order: index 1 arrives before index 0.
	oracle.Record(1, []string{"k-beta", "k-alpha", "k-beta"})
	if oracle.ContiguousSize() != 0 {
		t.Fatalf("ContiguousSize() = %d before index 0, want 0", oracle.ContiguousSize())
	}
	oracle.Record(0, []string{"k-alpha"})
	if oracle.ContiguousSize() != 2 {
		t.Fatalf("ContiguousSize() = %d after index 0, want 2", oracle.ContiguousSize())
	}
	oracle.Record(2, []string{"k-alpha"})
	// Total recorded so far = 4 (exact cap); index 3 triggers capped soak mode at cappedAtSize=3.
	oracle.Record(3, []string{"k-gamma"})
	if oracle.ContiguousSize() != 4 {
		t.Fatalf("ContiguousSize() = %d, want 4", oracle.ContiguousSize())
	}

	// Exact mode within [0, 3):
	if err := oracle.VerifyKeyLookup("k-alpha", 0, 3, true, []uint64{0, 1, 2}, true); err != nil {
		t.Fatalf("expected valid full match, got %v", err)
	}
	// Partial newest-page match within [0, 3) (both strict subset and exact PageSize==wantLen boundary):
	if err := oracle.VerifyKeyLookup("k-alpha", 0, 3, true, []uint64{1, 2}, false); err != nil {
		t.Fatalf("expected valid partial suffix match, got %v", err)
	}
	if err := oracle.VerifyKeyLookup("k-alpha", 0, 3, true, []uint64{0, 1, 2}, false); err != nil {
		t.Fatalf("expected valid exact-PageSize suffix match, got %v", err)
	}
	// Omitted key must fail:
	if err := oracle.VerifyKeyLookup("k-alpha", 0, 3, false, nil, true); err == nil {
		t.Fatalf("expected omitted key failure")
	}
	// Phantom key must fail:
	if err := oracle.VerifyKeyLookup("k-missing", 0, 3, true, []uint64{1}, true); err == nil {
		t.Fatalf("expected phantom key failure")
	}
	// Prefix exactness at [0, 3):
	if err := oracle.VerifyPrefixLookup("k-", 0, 3, []string{"k-alpha", "k-beta"}); err != nil {
		t.Fatalf("expected valid prefix match, got %v", err)
	}
	if err := oracle.VerifyPrefixLookup("k-", 0, 3, []string{"k-alpha"}); err == nil {
		t.Fatalf("expected prefix omission failure")
	}

	// Capped soak mode at [0, 4) (past cappedAtSize=3): enforces [0, 3) prefix without failing on index 3.
	if err := oracle.VerifyKeyLookup("k-alpha", 0, 4, true, []uint64{0, 1, 2, 3}, true); err != nil {
		t.Fatalf("expected capped superset match to pass, got %v", err)
	}
	if err := oracle.VerifyKeyLookup("k-alpha", 0, 4, false, nil, true); err == nil {
		t.Fatalf("expected capped omitted key to still fail")
	}
}

func TestSequencer_WriteGoalReplayVerifyInputStateAndClose(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tempDir := t.TempDir()

	origin := "example.com/hammer/explicit"
	skey, wantVKey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	gen1 := hammer.NewGenerator(hammer.GeneratorConfig{NumKeys: 8, Seed: 77})
	seq1, err := hammer.NewSequencer(ctx, hammer.SequencerConfig{
		StorageDir: tempDir,
		SignerKey:  skey,
		BatchSize:  8,
		WriteRate:  0,
		WriteGoal:  25,
	}, gen1)
	if err != nil {
		t.Fatalf("NewSequencer(1) failed: %v", err)
	}
	if seq1.Origin() != origin || seq1.VerifierKey() != wantVKey {
		t.Fatalf("Origin=%q VerifierKey=%q, want %q / %q", seq1.Origin(), seq1.VerifierKey(), origin, wantVKey)
	}
	if err := seq1.RunLoop(ctx); err != nil {
		t.Fatalf("seq1.RunLoop failed: %v", err)
	}
	cp25Raw, err := seq1.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("seq1.ReadCheckpoint failed: %v", err)
	}
	cp25, _, _, err := log.ParseCheckpoint(cp25Raw, origin, seq1.Verifier())
	if err != nil || cp25.Size != 25 {
		t.Fatalf("ParseCheckpoint(25) = %v, %v", cp25, err)
	}
	var root25 [sha256.Size]byte
	copy(root25[:], cp25.Hash)
	if err := seq1.Close(ctx); err != nil {
		t.Fatalf("seq1.Close failed: %v", err)
	}

	// Reopen against the same POSIX directory: must replay [0, 25) into the pure-Go Oracle
	// and verify historical root25 via Merkle consistency after growing to size 45.
	gen2 := hammer.NewGenerator(hammer.GeneratorConfig{NumKeys: 8, Seed: 88})
	seq2, err := hammer.NewSequencer(ctx, hammer.SequencerConfig{
		StorageDir: tempDir,
		SignerKey:  skey,
		BatchSize:  8,
		WriteRate:  0,
		WriteGoal:  20,
	}, gen2)
	if err != nil {
		t.Fatalf("NewSequencer(2) failed: %v", err)
	}
	if seq2.Oracle().ContiguousSize() != 25 {
		t.Fatalf("replayed ContiguousSize() = %d, want 25", seq2.Oracle().ContiguousSize())
	}
	if err := seq2.RunLoop(ctx); err != nil {
		t.Fatalf("seq2.RunLoop failed: %v", err)
	}
	cp45Raw, err := seq2.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("seq2.ReadCheckpoint failed: %v", err)
	}
	cp45, _, _, err := log.ParseCheckpoint(cp45Raw, origin, seq2.Verifier())
	if err != nil || cp45.Size != 45 {
		t.Fatalf("ParseCheckpoint(45) = %v, %v", cp45, err)
	}
	var root45 [sha256.Size]byte
	copy(root45[:], cp45.Hash)

	if err := seq2.VerifyInputState(ctx, 0, wire.EmptyRoot()); err != nil {
		t.Fatalf("VerifyInputState(0) failed: %v", err)
	}
	if err := seq2.VerifyInputState(ctx, 25, root25); err != nil {
		t.Fatalf("VerifyInputState(25 consistency) failed: %v", err)
	}
	if err := seq2.VerifyInputState(ctx, 45, root45); err != nil {
		t.Fatalf("VerifyInputState(45 latest) failed: %v", err)
	}
	badRoot := sha256.Sum256([]byte("forged"))
	if err := seq2.VerifyInputState(ctx, 25, badRoot); err == nil {
		t.Fatalf("expected VerifyInputState to reject forged root at size 25")
	}
	if err := seq2.VerifyInputState(ctx, 46, root45); err == nil {
		t.Fatalf("expected VerifyInputState to reject size 46 > 45")
	}

	canceledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	closeStart := time.Now()
	if err := seq2.Close(canceledCtx); err != nil {
		t.Fatalf("seq2.Close failed: %v", err)
	}
	if elapsed := time.Since(closeStart); elapsed > 3*time.Second {
		t.Fatalf("seq2.Close took %v, expected fast shutdown", elapsed)
	}
}

func TestDripServer_PublishesLatestCheckpointWithoutFIFOLag(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tempDir := t.TempDir()

	var currentCP atomic.Value
	currentCP.Store([]byte("example.com/hammer\n10\nhash1\n"))

	srv := hammer.NewDripServer(hammer.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		StorageDir:   tempDir,
		DripRate:     50.0,
		InitialPause: 200 * time.Millisecond,
	}, func(context.Context) ([]byte, error) {
		return currentCP.Load().([]byte), nil
	})
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("DripServer.Start failed: %v", err)
	}
	defer func() { _ = srv.Close(ctx) }()

	httpCli := &http.Client{Timeout: 2 * time.Second}
	resp503, err := httpCli.Get(srv.URL() + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint failed: %v", err)
	}
	_ = resp503.Body.Close()
	if resp503.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 during InitialPause, got %d", resp503.StatusCode)
	}

	currentCP.Store([]byte("example.com/hammer\n20\nhash2\n"))
	currentCP.Store([]byte("example.com/hammer\n30\nhash3\n"))

	deadline := time.Now().Add(3 * time.Second)
	var gotBody string
	for time.Now().Before(deadline) {
		resp, gErr := httpCli.Get(srv.URL() + "/checkpoint")
		if gErr == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(b) == "example.com/hammer\n30\nhash3\n" {
				gotBody = string(b)
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	if gotBody != "example.com/hammer\n30\nhash3\n" {
		t.Fatalf("timed out waiting for latest size-30 checkpoint, last=%q", gotBody)
	}
}

func TestAnalyzer_ExportStats(t *testing.T) {
	t.Parallel()
	analyzer := hammer.NewAnalyzer(nil)

	analyzer.RecordReadSuccess(100*time.Microsecond, 50)
	analyzer.RecordReadSuccess(200*time.Microsecond, 60)
	analyzer.RecordReadSuccess(500*time.Microsecond, 60)
	analyzer.RecordReadError(fmt.Errorf("simulated timeout"), 2*time.Millisecond)
	analyzer.RecordInvariantViolation("test violation 1")

	stats := analyzer.ExportStats()
	if stats.TotalReads != 4 || stats.ReadSuccesses != 3 || stats.ReadFailures != 1 {
		t.Fatalf("unexpected read counts: %+v", stats)
	}
	if stats.ServingTreeSize != 60 {
		t.Fatalf("stats.ServingTreeSize = %d, want 60", stats.ServingTreeSize)
	}
	if stats.InvariantViolations != 1 || len(stats.ViolationSamples) != 1 {
		t.Fatalf("unexpected violations: %+v", stats)
	}
	if stats.LatencyMax != 2*time.Millisecond {
		t.Fatalf("stats.LatencyMax = %v, want 2ms", stats.LatencyMax)
	}
}

func buildMockEmptyKeysResponse(outOrigin string, outSigner note.Signer, inOrigin string, from, inSize uint64, inHash [32]byte, reqKey string) []byte {
	mptMgr := mpt.NewMem()
	mptRoot := wire.EmptyRoot()
	if inSize > from {
		_, _ = mptMgr.Snap(int64(inSize))
	}
	mptProof, _, _, _ := mptMgr.ProveKey([]byte(reqKey))
	if inSize == 0 {
		inHash = wire.EmptyRoot()
	}
	inCP := &log.Checkpoint{Origin: inOrigin, Size: inSize, Hash: inHash[:]}
	outLeaf := wire.FormatOutputLogLeafFull(mptRoot, from, inCP)
	outRoot := wire.LeafHash(outLeaf)
	outText := fmt.Sprintf("%s\n1\n%s\n", outOrigin, base64.StdEncoding.EncodeToString(outRoot[:]))
	signed, err := note.Sign(&note.Note{Text: outText}, outSigner)
	if err != nil {
		panic(err)
	}
	return wire.FormatKeysResponseFull(signed, 0, mptRoot, from, inCP, nil, "", mptProof, nil)
}

func TestReaderPool_DetectsTimeoutHorizonOracleAndConformanceViolations(t *testing.T) {
	t.Parallel()
	outOrigin := "example.com/out"
	inOrigin := "example.com/in"
	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatal(err)
	}
	outSigner, _ := note.NewSigner(outSKey)
	outVerifier, _ := note.NewVerifier(outVKey)

	t.Run("Timeout_And_HorizonViolation", func(t *testing.T) {
		t.Parallel()
		var reqCount atomic.Uint64
		var stallRequests atomic.Bool
		fakeInHash := sha256.Sum256([]byte("in-root"))

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := reqCount.Add(1)
			if stallRequests.Load() {
				select {
				case <-r.Context().Done():
				case <-time.After(time.Second):
				}
				return
			}
			key := r.URL.Query().Get("key")
			if key == "" {
				key = "probe"
			}
			from := uint64(0)
			if n == 3 {
				from = 5
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(buildMockEmptyKeysResponse(outOrigin, outSigner, inOrigin, from, 10, fakeInHash, key))
		}))
		defer ts.Close()

		gen := hammer.NewGenerator(hammer.GeneratorConfig{NumKeys: 5})
		an := hammer.NewAnalyzer(nil)
		pool, err := hammer.NewReaderPool(hammer.ReaderConfig{
			VIndexURL:         ts.URL,
			NumWorkers:        1,
			MaxReadQPS:        200,
			OutputLogOrigin:   outOrigin,
			OutputLogVerifier: outVerifier,
			InputLogOrigin:    inOrigin,
			RequestTimeout:    200 * time.Millisecond,
		}, gen, an)
		if err != nil {
			t.Fatalf("NewReaderPool failed: %v", err)
		}

		runCtx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- pool.Start(runCtx)
		}()

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st := an.ExportStats()
			if st.TotalReads >= 3 && st.InvariantViolations >= 1 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		stallRequests.Store(true)
		for time.Now().Before(deadline) {
			st := an.ExportStats()
			if st.ReadFailures >= 1 && st.InvariantViolations >= 2 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		if startErr := <-done; startErr != nil && !errors.Is(startErr, context.Canceled) {
			t.Fatalf("pool.Start failed: %v", startErr)
		}

		st := an.ExportStats()
		if st.ReadFailures == 0 {
			t.Fatalf("expected HTTP client request timeout to record ReadFailures > 0, got %+v", st)
		}
		joinedSamples := fmt.Sprint(st.ViolationSamples)
		if !strings.Contains(joinedSamples, "HorizonViolation") || !strings.Contains(joinedSamples, "UnexpectedQueryError") {
			t.Fatalf("expected both HorizonViolation and UnexpectedQueryError in ViolationSamples, got %+v", st)
		}
	})

	t.Run("OmittedKeys_ForgedInputRoot_And_HTTPConformance", func(t *testing.T) {
		t.Parallel()
		// Non-conformant target: serves cryptographically valid empty-MPT proofs while claiming input-size=10
		// with a forged input-root, and returns 200 instead of 400/404/503 on malformed/missing queries.
		forgedHash := sha256.Sum256([]byte("forged-input-root"))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.URL.Query().Get("key")
			if key == "" {
				key = "fallback-key"
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(buildMockEmptyKeysResponse(outOrigin, outSigner, inOrigin, 0, 10, forgedHash, key))
		}))
		defer ts.Close()

		gen := hammer.NewGenerator(hammer.GeneratorConfig{NumKeys: 1, Distribution: hammer.DistUniform})
		oracle := hammer.NewOracle(hammer.MapRawLeaf, 0)
		for i := range uint64(10) {
			oracle.Record(i, []string{hammer.KeyForID(0)})
		}
		oracle.SetInputStateVerifier(func(_ context.Context, _ uint64, gotRoot [32]byte) error {
			wantRoot := sha256.Sum256([]byte("genuine-input-root"))
			if gotRoot != wantRoot {
				return fmt.Errorf("root mismatch")
			}
			return nil
		})

		an := hammer.NewAnalyzer(nil)
		pool, err := hammer.NewReaderPool(hammer.ReaderConfig{
			VIndexURL:         ts.URL,
			NumWorkers:        1,
			MaxReadQPS:        200,
			OutputLogOrigin:   outOrigin,
			OutputLogVerifier: outVerifier,
			InputLogOrigin:    inOrigin,
			Oracle:            oracle,
			CheckConformance:  true,
			PrefixRatio:       0,
			RequestTimeout:    time.Second,
		}, gen, an)
		if err != nil {
			t.Fatalf("NewReaderPool failed: %v", err)
		}

		runCtx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- pool.Start(runCtx)
		}()

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			joined := fmt.Sprint(an.ExportStats().ViolationSamples)
			if strings.Contains(joined, "InputStateViolation") &&
				strings.Contains(joined, "HTTPConformanceViolation") &&
				strings.Contains(joined, "OracleKeyViolation") {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		if startErr := <-done; startErr != nil && !errors.Is(startErr, context.Canceled) {
			t.Fatalf("pool.Start failed: %v", startErr)
		}

		joined := fmt.Sprint(an.ExportStats().ViolationSamples)
		for _, wantSub := range []string{"InputStateViolation", "HTTPConformanceViolation", "OracleKeyViolation"} {
			if !strings.Contains(joined, wantSub) {
				t.Fatalf("expected %q in ViolationSamples, got %v", wantSub, an.ExportStats().ViolationSamples)
			}
		}
	})
}

func TestEndToEnd_HammerConformanceAcrossFormats(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		format       hammer.LeafFormat
		wasmHostFn   func(*testing.T) *vindex.WASMHost
		prefixPolicy string
		writeGoal    uint64
	}{
		{
			name:         "Raw_WithDelimitersAndPrefixes",
			format:       hammer.FormatRaw,
			wasmHostFn:   func(*testing.T) *vindex.WASMHost { return wasmhosttest.Host() },
			prefixPolicy: "allow",
			writeGoal:    48,
		},
		{
			name:   "SumDB_PureGoVsWASM",
			format: hammer.FormatSumDB,
			wasmHostFn: func(t *testing.T) *vindex.WASMHost {
				return mustHammerExampleWASM(t, "github.com/transparency-dev/incubator/vindex/mapfn/examples/sumdb")
			},
			prefixPolicy: "allow",
			writeGoal:    32,
		},
		{
			name:   "CT_ReversedDNSPolicy_PureGoVsWASM",
			format: hammer.FormatCT,
			wasmHostFn: func(t *testing.T) *vindex.WASMHost {
				return mustHammerExampleWASM(t, "github.com/transparency-dev/incubator/vindex/mapfn/examples/ct")
			},
			prefixPolicy: "reversed-dns",
			writeGoal:    24,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			rootDir := t.TempDir()
			posixDir := filepath.Join(rootDir, "posix_inlog")

			generator := hammer.NewGenerator(hammer.GeneratorConfig{
				Distribution: hammer.DistZipf,
				NumKeys:      16,
				ZipfS:        1.3,
				ZipfV:        1.0,
				Seed:         42,
				LeafFormat:   tc.format,
				CTMinDomains: 1,
				CTMaxDomains: 3,
			})

			sequencer, err := hammer.NewSequencer(ctx, hammer.SequencerConfig{
				StorageDir: posixDir,
				BatchSize:  16,
				WriteRate:  0,
				WriteGoal:  tc.writeGoal,
			}, generator)
			if err != nil {
				t.Fatalf("NewSequencer failed: %v", err)
			}
			defer func() { _ = sequencer.Close(ctx) }()

			if err := sequencer.RunLoop(ctx); err != nil {
				t.Fatalf("sequencer.RunLoop failed: %v", err)
			}

			dripServer := hammer.NewDripServer(hammer.ServerConfig{
				ListenAddr: "127.0.0.1:0",
				StorageDir: posixDir,
				DripRate:   100.0,
			}, sequencer.ReadCheckpoint)
			if err := dripServer.Start(ctx); err != nil {
				t.Fatalf("dripServer.Start failed: %v", err)
			}
			defer func() { _ = dripServer.Close(ctx) }()

			outOrigin := "example.com/vindex/output"
			outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			outSigner, err := note.NewSigner(outSKey)
			if err != nil {
				t.Fatalf("NewSigner failed: %v", err)
			}
			outVerifier, err := note.NewVerifier(outVKey)
			if err != nil {
				t.Fatalf("NewVerifier failed: %v", err)
			}
			inPolicy, err := wire.BuildPolicy(sequencer.Origin(), sequencer.Verifier(), nil, 0)
			if err != nil {
				t.Fatalf("BuildPolicy(in) failed: %v", err)
			}
			prefixPol, err := vindex.ParsePrefixPolicy(tc.prefixPolicy)
			if err != nil {
				t.Fatalf("ParsePrefixPolicy(%q) failed: %v", tc.prefixPolicy, err)
			}

			engine, err := vindex.New(
				vindex.StorageConfig{
					DBPath:       filepath.Join(rootDir, "pebble_db"),
					MPTDir:       testMPTDir(rootDir, "mpt_tree"),
					TileCacheDir: filepath.Join(rootDir, "tilecache"),
					OutputLogDir: filepath.Join(rootDir, "posix_outlog"),
				},
				outSigner,
				vindex.WithInputLog(dripServer.URL(), inPolicy, tc.wasmHostFn(t)),
				vindex.WithServing(vindex.ServeOptions{
					ServeOutputTiles: true,
					PrefixPolicyFunc: prefixPol,
				}),
				vindex.WithTuning(vindex.TuningOptions{
					ChunkSize:     8,
					DisableReaper: true,
				}),
			)
			if err != nil {
				t.Fatalf("vindex.New failed: %v", err)
			}
			defer func() { _ = engine.Close() }()

			if err := engine.SyncOnce(ctx); err != nil {
				t.Fatalf("engine.SyncOnce failed: %v", err)
			}

			vindexHTTP := httptest.NewServer(engine.Handler())
			defer vindexHTTP.Close()

			analyzer := hammer.NewAnalyzer(sequencer)
			readers, err := hammer.NewReaderPool(hammer.ReaderConfig{
				VIndexURL:         vindexHTTP.URL,
				OutputLogURL:      vindexHTTP.URL,
				NumWorkers:        4,
				MaxReadQPS:        0,
				OutputLogOrigin:   outOrigin,
				OutputLogVerifier: outVerifier,
				InputLogOrigin:    sequencer.Origin(),
				Oracle:            sequencer.Oracle(),
				CheckConformance:  true,
				PrefixRatio:       0.25,
				PageSize:          4,
			}, generator, analyzer)
			if err != nil {
				t.Fatalf("NewReaderPool failed: %v", err)
			}

			testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			go func() {
				for testCtx.Err() == nil {
					if analyzer.ExportStats().ReadSuccesses >= 40 {
						cancel()
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
			if err := readers.Start(testCtx); err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("readers.Start failed: %v", err)
			}

			snap := analyzer.ExportStats()
			if snap.ReadSuccesses < 40 {
				t.Fatalf("expected >= 40 successful reads, got %+v", snap)
			}
			if snap.InvariantViolations != 0 {
				t.Fatalf("expected 0 invariant violations, got %d (samples: %v)", snap.InvariantViolations, snap.ViolationSamples)
			}
		})
	}
}

func BenchmarkPureGoMapFn(b *testing.B) {
	rawLeaf := hammer.NewGenerator(hammer.GeneratorConfig{LeafFormat: hammer.FormatRaw, NumKeys: 16}).NextLeaf().LeafData
	sumdbLeaf := hammer.NewGenerator(hammer.GeneratorConfig{LeafFormat: hammer.FormatSumDB, NumKeys: 16}).NextLeaf().LeafData
	ctLeaf := hammer.NewGenerator(hammer.GeneratorConfig{LeafFormat: hammer.FormatCT, NumKeys: 16, CTMinDomains: 4, CTMaxDomains: 4}).NextLeaf().LeafData

	b.Run("Raw", func(b *testing.B) {
		for b.Loop() {
			_, _ = hammer.MapRawLeaf(rawLeaf)
		}
	})
	b.Run("SumDB", func(b *testing.B) {
		for b.Loop() {
			_, _ = hammer.MapSumDBLeaf(sumdbLeaf)
		}
	})
	b.Run("CT", func(b *testing.B) {
		for b.Loop() {
			_, _ = hammer.MapCTLeaf(ctLeaf)
		}
	})
}

func BenchmarkOracleVerifyKeyLookup(b *testing.B) {
	oracle := hammer.NewOracle(hammer.MapRawLeaf, 0)
	var want []uint64
	for i := range uint64(1024) {
		k := fmt.Sprintf("example.com/module-%d", i%16)
		oracle.Record(i, []string{k})
		if i%16 == 0 {
			want = append(want, i)
		}
	}
	tail := want[len(want)-16:]

	b.Run("FullMatch", func(b *testing.B) {
		for b.Loop() {
			if err := oracle.VerifyKeyLookup("example.com/module-0", 0, 1024, true, want, true); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("PartialPageSuffix", func(b *testing.B) {
		for b.Loop() {
			if err := oracle.VerifyKeyLookup("example.com/module-0", 0, 1024, true, tail, false); err != nil {
				b.Fatal(err)
			}
		}
	})
}
