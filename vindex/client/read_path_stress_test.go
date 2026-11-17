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

package client_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
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

type stressEnv struct {
	inOrigin  string
	outOrigin string
	outVerify note.Verifier
	inLogDir  string
	newEngine func(t *testing.T) *vindex.Engine
	append    func(ctx context.Context, payloads ...[]byte) []uint64
}

func newStressEnv(t *testing.T, chunkSize uint64, name string, disableReaper bool) *stressEnv {
	t.Helper()
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	inOrigin := "test.stress." + name + ".inlog"
	outOrigin := "test.stress." + name + ".outlog"

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, inOrigin)
	if err != nil {
		t.Fatalf("GenerateKey(in) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner(in) failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier(in) failed: %v", err)
	}
	inPolicy, err := client.SingleKeyPolicy(inOrigin, inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(in) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatalf("GenerateKey(out) failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(out) failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier(out) failed: %v", err)
	}

	appCtx, appCancel := context.WithCancel(context.Background())
	inDriver, err := posix.New(appCtx, posix.Config{Path: inLogDir})
	if err != nil {
		appCancel()
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(appCtx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(128, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		appCancel()
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sCancel()
		_ = inShutdown(sCtx)
		appCancel()
	})
	inAwaiter := tessera.NewPublicationAwaiter(appCtx, inReader.ReadCheckpoint, 5*time.Millisecond)

	storage := vindex.StorageConfig{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       testMPTDir(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
		OutputLogDir: filepath.Join(rootDir, "outlog"),
	}

	return &stressEnv{
		inOrigin:  inOrigin,
		outOrigin: outOrigin,
		outVerify: outVerifier,
		inLogDir:  inLogDir,
		newEngine: func(t *testing.T) *vindex.Engine {
			t.Helper()
			eng, nErr := vindex.New(storage, outSigner,
				vindex.WithInputLog("file://"+inLogDir, inPolicy, wasmhosttest.Host()),
				vindex.WithTuning(vindex.TuningOptions{
					ChunkSize:     chunkSize,
					PollInterval:  20 * time.Millisecond,
					DisableReaper: disableReaper,
				}),
			)
			if nErr != nil {
				t.Fatalf("vindex.New failed: %v", nErr)
			}
			return eng
		},
		append: func(ctx context.Context, payloads ...[]byte) []uint64 {
			t.Helper()
			futs := make([]tessera.IndexFuture, len(payloads))
			for i, p := range payloads {
				futs[i] = inAppender.Add(ctx, tessera.NewEntry(p))
			}
			indices := make([]uint64, len(payloads))
			for i, f := range futs {
				idx, rawCP, aErr := inAwaiter.Await(ctx, f)
				if aErr != nil || len(rawCP) == 0 {
					t.Fatalf("append leaf %d failed: %v", i, aErr)
				}
				indices[i] = idx.Index
			}
			return indices
		},
	}
}

func (e *stressEnv) newClient(t *testing.T, ts *httptest.Server) *client.Client {
	t.Helper()
	outPol, err := client.SingleKeyPolicy(e.outOrigin, e.outVerify)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(out) failed: %v", err)
	}
	cli, err := client.New(ts.URL, client.Config{
		ExpectedOutputLogOrigin: e.outOrigin,
		OutputLogPolicy:         outPol,
		ExpectedInputLogOrigin:  e.inOrigin,
	}, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}
	return cli
}

func collectValuesAscending(ctx context.Context, mk client.MatchedKey) ([]uint64, error) {
	var desc []uint64
	for idx, err := range mk.Values(ctx) {
		if err != nil {
			return nil, err
		}
		if len(desc) > 0 && idx >= desc[len(desc)-1] {
			return nil, fmt.Errorf("indices not strictly descending: %v then %d", desc, idx)
		}
		desc = append(desc, idx)
	}
	slices.Reverse(desc)
	return desc, nil
}

// TestStress_DifferentialLookupAndPagination tests client LookupKey and MatchedKey.Values
// against an independent oracle across multi-chunk datasets.
func TestStress_DifferentialLookupAndPagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	env := newStressEnv(t, 4, "diff", true)

	const (
		key1      = "key_1"
		key2      = "key_2"
		keyExact  = "key_chunk_exact"
		keyPlus1  = "key_chunk_plus_1"
		keyDouble = "key_chunk_double"
		keyHeavy  = "key_heavy"
		keySparse = "key_sparse"
		keyAbsent = "key_absent_never_indexed"
	)

	var sequence []string
	sequence = append(sequence, key1)
	for range 2 {
		sequence = append(sequence, key2)
	}
	for range 4 {
		sequence = append(sequence, keyExact)
	}
	for range 5 {
		sequence = append(sequence, keyPlus1)
	}
	for range 8 {
		sequence = append(sequence, keyDouble)
	}
	// 130 occurrences of keyHeavy (> 100 defaultLookupLimit) and 26 chunks of keySparse (> 16 defaultMaxChunksPerRequest)
	// exercise multi-page /values backward continuation under both server pagination caps.
	for i := range 130 {
		sequence = append(sequence, keyHeavy)
		if i%5 == 0 {
			sequence = append(sequence, keySparse)
		}
	}

	payloads := make([][]byte, len(sequence))
	for i, keyName := range sequence {
		payloads[i] = fmt.Appendf(nil, "%s leaf_%d", keyName, i)
	}
	assigned := env.append(ctx, payloads...)

	oracle := make(map[string][]uint64)
	for i, keyName := range sequence {
		oracle[keyName] = append(oracle[keyName], assigned[i])
	}

	engine := env.newEngine(t)
	defer func() { _ = engine.Close() }()
	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := env.newClient(t, ts)

	t.Run("NonInclusion_AbsentKey", func(t *testing.T) {
		kr, err := cli.LookupKey(ctx, keyAbsent)
		if err != nil {
			t.Fatalf("LookupKey non-inclusion failed: %v", err)
		}
		if len(kr.Keys) != 0 {
			t.Fatalf("expected non-inclusion with 0 keys, got %+v", kr)
		}
	})

	for _, kName := range []string{key1, key2, keyExact, keyPlus1, keyDouble, keyHeavy, keySparse} {
		t.Run("LookupValues_"+kName, func(t *testing.T) {
			expected := oracle[kName]
			kr, err := cli.LookupKey(ctx, kName)
			if err != nil {
				t.Fatalf("LookupKey(%s) failed: %v", kName, err)
			}
			if len(kr.Keys) != 1 {
				t.Fatalf("expected 1 matched key for %s, got %d", kName, len(kr.Keys))
			}
			indices, err := collectValuesAscending(ctx, kr.Keys[0])
			if err != nil {
				t.Fatalf("Values(%s) failed: %v", kName, err)
			}
			if !slices.Equal(indices, expected) {
				t.Fatalf("Values(%s) mismatch:\n got:  %v\n want: %v", kName, indices, expected)
			}
		})
	}
}

// TestStress_HighConcurrencyReadPath subjects the engine and client to parallel reader goroutines
// performing simultaneous lookups and backward pagination while asserting 0 data races and exact index sets.
func TestStress_HighConcurrencyReadPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	env := newStressEnv(t, 16, "concurr", true)

	const numKeys = 10
	keyNames := make([]string, numKeys)
	wantByKey := make([][]uint64, numKeys)
	for i := range numKeys {
		keyNames[i] = fmt.Sprintf("concurr_key_%d", i)
	}

	payloads := make([][]byte, 100)
	for i := range 100 {
		kID := i % numKeys
		payloads[i] = fmt.Appendf(nil, "%s %d", keyNames[kID], i)
		wantByKey[kID] = append(wantByKey[kID], uint64(i))
	}
	env.append(ctx, payloads...)

	engine := env.newEngine(t)
	defer func() { _ = engine.Close() }()
	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := env.newClient(t, ts)

	const numWorkers = 20
	const iterationsPerWorker = 30
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	for w := range numWorkers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startBarrier

			for it := range iterationsPerWorker {
				kID := (workerID + it) % numKeys
				key := keyNames[kID]

				switch it % 3 {
				case 0:
					kr, err := cli.LookupKey(ctx, key)
					if err != nil || len(kr.Keys) != 1 {
						t.Errorf("worker %d LookupKey(%s): len=%d err=%v", workerID, key, len(kr.Keys), err)
						return
					}
					var gotFirst uint64
					var ok bool
					for idx, vErr := range kr.Keys[0].Values(ctx) {
						if vErr != nil {
							t.Errorf("worker %d first value(%s) err=%v", workerID, key, vErr)
							return
						}
						gotFirst = idx
						ok = true
						break
					}
					if !ok || gotFirst != wantByKey[kID][len(wantByKey[kID])-1] {
						t.Errorf("worker %d newest(%s) = %d, want %d", workerID, key, gotFirst, wantByKey[kID][len(wantByKey[kID])-1])
						return
					}
				case 1:
					kr, err := cli.LookupKey(ctx, key)
					if err != nil || len(kr.Keys) != 1 {
						t.Errorf("worker %d LookupKey(%s): len=%d err=%v", workerID, key, len(kr.Keys), err)
						return
					}
					indices, err := collectValuesAscending(ctx, kr.Keys[0])
					if err != nil || !slices.Equal(indices, wantByKey[kID]) {
						t.Errorf("worker %d Values(%s) = %v (err=%v), want %v", workerID, key, indices, err, wantByKey[kID])
						return
					}
				case 2:
					fakeKey := fmt.Sprintf("non_existent_%d_%d", workerID, it)
					kr, err := cli.LookupKey(ctx, fakeKey)
					if err != nil || len(kr.Keys) != 0 {
						t.Errorf("worker %d non-inclusion(%s): len=%d err=%v", workerID, fakeKey, len(kr.Keys), err)
						return
					}
				}
			}
		}(w)
	}

	close(startBarrier)
	wg.Wait()
}

// TestStress_ConcurrentWriterAndBackwardPaginator stresses backward pagination while
// the engine is actively ingesting and publishing new batches in the background.
func TestStress_ConcurrentWriterAndBackwardPaginator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	env := newStressEnv(t, 4, "writer", false)
	const dynamicKey = "dynamic_hot_key"

	// 80 initial leaves across 20 chunks (> 16 chunk scan cap) plus 60 dynamic leaves (reaching 140 > 100 match cap)
	// ensure every reader iteration performs multi-page /values pagination concurrently with checkpoint promotion.
	seedPayloads := make([][]byte, 80)
	for i := range 80 {
		seedPayloads[i] = fmt.Appendf(nil, "%s initial_%d", dynamicKey, i)
	}
	env.append(ctx, seedPayloads...)

	engine := env.newEngine(t)
	defer func() { _ = engine.Close() }()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	var stopFlag atomic.Bool
	var totalReads atomic.Uint64
	var wg sync.WaitGroup
	defer func() {
		stopFlag.Store(true)
		wg.Wait()
	}()

	cli := env.newClient(t, ts)
	for r := range 4 {
		wg.Add(1)
		go func(rID int) {
			defer wg.Done()
			for !stopFlag.Load() {
				kr, err := cli.LookupKey(ctx, dynamicKey)
				if err != nil {
					if !stopFlag.Load() && ctx.Err() == nil {
						t.Errorf("reader %d LookupKey failed: %v", rID, err)
					}
					return
				}
				if len(kr.Keys) != 1 {
					t.Errorf("reader %d expected 1 matched key at size %d, got %d", rID, kr.InputSize, len(kr.Keys))
					return
				}
				indices, err := collectValuesAscending(ctx, kr.Keys[0])
				if err != nil {
					if !stopFlag.Load() && ctx.Err() == nil {
						t.Errorf("reader %d Values failed: %v", rID, err)
					}
					return
				}
				if uint64(len(indices)) != kr.InputSize {
					t.Errorf("reader %d len(indices)=%d != InputSize=%d", rID, len(indices), kr.InputSize)
					return
				}
				for j, idx := range indices {
					if idx != uint64(j) {
						t.Errorf("reader %d indices[%d]=%d, want %d", rID, j, idx, j)
						return
					}
				}
				totalReads.Add(1)
			}
		}(r)
	}

	// Append leaves 80..139 in 6 batches of 10 across 6 checkpoints while readers continuously paginate.
	for wave := range 6 {
		batch := make([][]byte, 10)
		for j := range 10 {
			batch[j] = fmt.Appendf(nil, "%s dyn_%d", dynamicKey, 80+wave*10+j)
		}
		env.append(ctx, batch...)
	}

	// Poll until the engine serves all 140 leaves.
	deadline := time.Now().Add(8 * time.Second)
	reached140 := false
	for time.Now().Before(deadline) {
		kr, err := cli.LookupKey(ctx, dynamicKey)
		if err == nil && kr.InputSize == 140 && len(kr.Keys) == 1 {
			indices, vErr := collectValuesAscending(ctx, kr.Keys[0])
			if vErr == nil && len(indices) == 140 {
				reached140 = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopFlag.Store(true)
	wg.Wait()

	if !reached140 {
		t.Fatal("timed out waiting for engine to serve InputSize == 140")
	}
	if totalReads.Load() < 10 {
		t.Fatalf("expected >= 10 concurrent reads, got %d", totalReads.Load())
	}
}
