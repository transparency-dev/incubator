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

package coordinator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestCoordinator_SafeWatermark_ClampedToFrom(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.pub.SetFrom(500)
	coord := env.newCoord()

	sw, err := coord.SafeWatermark(ctx)
	if err != nil || sw != 500 {
		t.Fatalf("empty state SafeWatermark = %d (err: %v), want 500", sw, err)
	}

	if err := env.db.SetUint64(kvstore.KeyMetaKVSize, 800); err != nil {
		t.Fatalf("SetUint64 failed: %v", err)
	}
	_, _ = env.mpt.Snap(300)
	_ = env.mpt.Persist()
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 500 {
		t.Fatalf("below-from MPT SafeWatermark = %d (err: %v), want 500", sw, err)
	}

	_, _ = env.mpt.Snap(700)
	_ = env.mpt.Persist()
	sw, err = coord.SafeWatermark(ctx)
	if err != nil || sw != 700 {
		t.Fatalf("above-from SafeWatermark = %d (err: %v), want 700", sw, err)
	}
}

func TestCoordinator_SyncOnce_RejectsTargetBelowFromAndBootstrapAtFrom(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.pub.SetFrom(250)
	coord := env.newCoord(func(c *Config) { c.ExplicitFrom = true })

	err := coord.SyncOnce(ctx)
	if err == nil || !strings.Contains(err.Error(), "below configured start index from") {
		t.Fatalf("expected error for targetCP.Size < from, got: %v", err)
	}
	if raw, mErr := env.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint); mErr == nil && len(raw) > 0 {
		t.Fatalf("expected KeyMetaTargetCheckpoint not to be persisted when targetCP.Size < from, got %q", raw)
	}

	// Bootstrap at targetCP.Size == from (250) publishes empty MPT root and recovers cleanly without m_kv_size violation.
	env.fetcher.mu.Lock()
	env.fetcher.leaves = makeTestLeaves("leaf_from_", 250)
	env.fetcher.mu.Unlock()
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce at targetCP.Size == from (250) failed: %v", err)
	}
	state := env.pub.GetServingState()
	if state == nil || state.InputLogSize != 250 || state.From != 250 || state.MPTRoot != wire.EmptyRoot() {
		t.Fatalf("unexpected ServingState at size==from: %+v", state)
	}
	restarted := env.newCoord(func(c *Config) { c.ExplicitFrom = true })
	if err := restarted.Recover(ctx); err != nil {
		t.Fatalf("Recover after bootstrap at targetCP.Size == from failed: %v", err)
	}

	// ExplicitFrom=true with From=0 must reject tipLeaf.From=250.
	env.pub.SetFrom(0)
	badZeroFrom := env.newCoord(func(c *Config) { c.ExplicitFrom = true })
	if err := badZeroFrom.Recover(ctx); !errors.Is(err, errInvariantViolation) {
		t.Fatalf("expected errInvariantViolation when ExplicitFrom=0 mismatches tip From=250, got: %v", err)
	}
}

func TestCoordinator_SyncOnce_RejectsRegressionAndSplitView(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/inputlog"

	t.Run("serving_state_regression_and_split_view", func(t *testing.T) {
		env := newTestEnv(t)
		leaves := makeTestLeaves("leaf_", 100)
		cp100 := makeRawCP(origin, 100, testBatchRoot(leaves))
		env.fetcher = &memoryTileFetcher{origin: origin, leaves: leaves, overrideCP: cp100}
		coord := env.newCoord()

		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("initial SyncOnce(100) failed: %v", err)
		}
		savedRaw, err := env.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
		if err != nil || !bytes.Equal(savedRaw, cp100.Raw) {
			t.Fatalf("expected KeyMetaTargetCheckpoint to match cp100.Raw, got %q (err: %v)", savedRaw, err)
		}
		retainedRaw, err := env.db.GetMetadata(inputCheckpointMetaKey(0))
		if err != nil || !bytes.Equal(retainedRaw, cp100.Raw) {
			t.Fatalf("expected retained Input Log checkpoint at m_in_cp:0, got %q (err: %v)", retainedRaw, err)
		}

		// 1. Regression (e.g. CDN POP skew): targetCP.Size = 80 < prevCP.Size = 100 -> non-fatal skip
		env.fetcher.overrideCP = makeRawCP(origin, 80, testBatchRoot(leaves[:80]))
		err = coord.SyncOnce(ctx)
		if !errors.Is(err, errCheckpointRegressed) || IsFatalSyncError(err) {
			t.Fatalf("expected non-fatal errCheckpointRegressed on CDN size skew 100 -> 80, got: %v", err)
		}
		if afterRegress, _ := env.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint); !bytes.Equal(afterRegress, cp100.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten despite checkpoint regression")
		}

		// 2. Equal-size split-view: targetCP.Size = 100 == prevCP.Size = 100, different hash
		env.fetcher.overrideCP = makeRawCP(origin, 100, sha256.Sum256([]byte("split_view_root_at_100")))
		err = coord.SyncOnce(ctx)
		if !errors.Is(err, errInvariantViolation) || !IsFatalSyncError(err) {
			t.Fatalf("expected fatal errInvariantViolation on equal-size split-view, got: %v", err)
		}
		if afterSplit, _ := env.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint); !bytes.Equal(afterSplit, cp100.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten despite equal-size split-view")
		}
	})

	t.Run("db_metadata_fallback_when_serving_state_nil", func(t *testing.T) {
		env := newTestEnv(t)
		origCP := makeRawCP(origin, 100, sha256.Sum256([]byte("frozen_target_100")))
		if err := env.db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, origCP.Raw); err != nil {
			t.Fatalf("SetMetadata failed: %v", err)
		}

		env.fetcher.overrideCP = makeRawCP(origin, 90, sha256.Sum256([]byte("regressed_90")))
		coord := env.newCoord()
		err := coord.SyncOnce(ctx)
		if !errors.Is(err, errCheckpointRegressed) || IsFatalSyncError(err) {
			t.Fatalf("expected non-fatal errCheckpointRegressed against persisted KeyMetaTargetCheckpoint regression, got: %v", err)
		}
		if gotRaw, _ := env.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint); !bytes.Equal(gotRaw, origCP.Raw) {
			t.Fatal("KeyMetaTargetCheckpoint was overwritten on regression")
		}

		env.fetcher.overrideCP = makeRawCP(origin, 100, sha256.Sum256([]byte("different_hash_at_100")))
		if err := coord.SyncOnce(ctx); !errors.Is(err, errInvariantViolation) {
			t.Fatalf("expected errInvariantViolation against persisted KeyMetaTargetCheckpoint split-view, got: %v", err)
		}
	})

	t.Run("output_log_wipe_regression_and_witness_policy", func(t *testing.T) {
		env := newTestEnv(t)
		outSKey, outVKey, _ := note.GenerateKey(rand.Reader, "example.com/outputlog")
		outSigner, _ := note.NewSigner(outSKey)
		outVerifier, _ := note.NewVerifier(outVKey)
		wSKey, wRawVKey, _ := note.GenerateKey(rand.Reader, "witness.example.com")
		wSigner, _ := f_note.NewSignerForCosignatureV1(wSKey)
		wCosigVKey, _ := f_note.VKeyToCosignatureV1(wRawVKey)
		wVerifier, _ := f_note.NewVerifier(wCosigVKey)
		outPolicy, err := wire.BuildPolicy("example.com/outputlog", outVerifier, []note.Verifier{wVerifier}, 1)
		if err != nil {
			t.Fatalf("BuildPolicy failed: %v", err)
		}
		env.outLog.signers = []note.Signer{outSigner}
		env.pub.SetOutputLogPolicy(outPolicy)

		coord := env.newCoord()
		// SyncOnce fails witness quorum (missing wSigner), then Recover also rejects unwitnessed checkpoint if present.
		if err := coord.SyncOnce(ctx); err == nil {
			t.Fatal("expected SyncOnce to fail when witness cosignature is missing")
		}
		if err := coord.Recover(ctx); err == nil {
			t.Fatal("expected Recover to reject unwitnessed Output Log checkpoint")
		}

		// Reset Output Log with both primary + witness signers and complete sync.
		env.outLog.mu.Lock()
		env.outLog.leaves = nil
		env.outLog.signers = []note.Signer{outSigner, wSigner}
		env.outLog.mu.Unlock()
		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("SyncOnce with witness cosignature failed: %v", err)
		}

		// Output Log wipe while serving must trigger errInvariantViolation instead of re-entering Genesis Backfill.
		env.outLog.mu.Lock()
		env.outLog.leaves = nil
		env.outLog.mu.Unlock()
		if err := coord.SyncOnce(ctx); !errors.Is(err, errInvariantViolation) {
			t.Fatalf("expected errInvariantViolation when Output Log wiped while serving, got: %v", err)
		}
	})
}

func writeCoordinatorTiledFixture(t *testing.T, rootDir, origin string, leaves [][]byte, signer note.Signer) []byte {
	t.Helper()
	if err := os.RemoveAll(rootDir); err != nil {
		t.Fatalf("RemoveAll(%s) failed: %v", rootDir, err)
	}

	var hashes []tlog.Hash
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = hashes[idx]
		}
		return out, nil
	})
	for idx, leaf := range leaves {
		sh, err := tlog.StoredHashes(int64(idx), leaf, hr)
		if err != nil {
			t.Fatalf("tlog.StoredHashes(%d) failed: %v", idx, err)
		}
		hashes = append(hashes, sh...)
	}

	treeSize := int64(len(leaves))
	rootHash, err := tlog.TreeHash(treeSize, hr)
	if err != nil {
		t.Fatalf("tlog.TreeHash(%d) failed: %v", treeSize, err)
	}

	for _, tile := range tlog.NewTiles(layout.TileHeight, 0, treeSize) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			t.Fatalf("tlog.ReadTileData(%+v) failed: %v", tile, err)
		}
		p := uint8(0)
		if tile.W < (1 << layout.TileHeight) {
			p = uint8(tile.W)
		}
		dst := filepath.Join(rootDir, layout.TilePath(uint64(tile.L), uint64(tile.N), p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	const bundleW = int(layout.EntryBundleWidth)
	for start := 0; start < len(leaves); start += bundleW {
		end := min(start+bundleW, len(leaves))
		bIdx := uint64(start / bundleW)
		count := end - start
		p := uint8(0)
		if count < bundleW {
			p = uint8(count)
		}
		var buf []byte
		for _, leaf := range leaves[start:end] {
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(leaf)))
			buf = append(buf, leaf...)
		}
		dst := filepath.Join(rootDir, layout.EntriesPath(bIdx, p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(dst, buf, 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	cpBody := (&log.Checkpoint{
		Origin: origin,
		Size:   uint64(treeSize),
		Hash:   rootHash[:],
	}).Marshal()
	rawCP, err := note.Sign(&note.Note{Text: string(cpBody)}, signer)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, layout.CheckpointPath), rawCP, 0o644); err != nil {
		t.Fatalf("WriteFile checkpoint failed: %v", err)
	}
	return rawCP
}

func TestCoordinator_SyncOnce_MerkleConsistencyVerification(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/tiledinput"

	skey, vkey, err := note.GenerateKey(nil, origin)
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, _ := note.NewSigner(skey)
	verifier, _ := note.NewVerifier(vkey)

	logDir := t.TempDir()
	env := newTestEnv(t)
	leaves := makeTestLeaves("consistent_leaf_", 300)

	writeCoordinatorTiledFixture(t, logDir, origin, leaves[:100], signer)
	tf, err := ingest.NewTiledFetcher(&url.URL{Scheme: "file", Path: logDir}, verifier, origin, nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}
	coord := env.newCoord(func(c *Config) { c.Fetcher = tf })

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(100) failed: %v", err)
	}

	rawCP300 := writeCoordinatorTiledFixture(t, logDir, origin, leaves[:300], signer)
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(300) consistent progression failed: %v", err)
	}
	if state := env.pub.GetServingState(); state == nil || state.InputLogSize != 300 {
		t.Fatalf("ServingState after 300 sync = %+v, want InputLogSize=300", state)
	}

	// Mutated history at size 400 must fail Merkle consistency with fatal errInvariantViolation BEFORE overwriting KeyMetaTargetCheckpoint.
	forkedLeaves := makeTestLeaves("consistent_leaf_", 400)
	forkedLeaves[0] = []byte("mutated_historical_leaf_0")
	writeCoordinatorTiledFixture(t, logDir, origin, forkedLeaves, signer)

	beforeErrs := testutil.ToFloat64(metrics.InputFetchErrorsTotal)
	err = coord.SyncOnce(ctx)
	if !errors.Is(err, errInvariantViolation) || !IsFatalSyncError(err) {
		t.Fatalf("expected fatal errInvariantViolation on mutated history, got: %v", err)
	}
	if afterErrs := testutil.ToFloat64(metrics.InputFetchErrorsTotal); afterErrs <= beforeErrs {
		t.Fatalf("expected InputFetchErrorsTotal to increment: before=%v, after=%v", beforeErrs, afterErrs)
	}
	if persistedTarget, _ := env.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint); !bytes.Equal(persistedTarget, rawCP300) {
		t.Fatal("KeyMetaTargetCheckpoint was overwritten despite failed Merkle consistency verification")
	}
}

func TestCoordinator_MonotonicBaselineAndOriginFromInvariants(t *testing.T) {
	ctx := context.Background()
	const origin = "example.com/inputlog"
	skey, vkey, err := note.GenerateKey(nil, origin)
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, _ := note.NewSigner(skey)
	verifier, _ := note.NewVerifier(vkey)

	logDir := filepath.Join(t.TempDir(), "input_log")
	env := newTestEnv(t)
	env.pub.SetInputOrigin(origin)
	env.pub.SetFrom(10)

	leaves := makeTestLeaves("leaf_", 100)
	writeCoordinatorTiledFixture(t, logDir, origin, leaves[:50], signer)
	tf, err := ingest.NewTiledFetcher(&url.URL{Scheme: "file", Path: logDir}, verifier, origin, nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}

	coord := env.newCoord(func(c *Config) {
		c.Fetcher = tf
		c.Workers = 2
		c.FetchWorkers = 2
		c.FetchBatchBundles = 4
	})
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce(50) failed: %v", err)
	}

	writeCoordinatorTiledFixture(t, logDir, origin, leaves[:30], signer)
	if err := coord.SyncOnce(ctx); !errors.Is(err, errCheckpointRegressed) {
		t.Fatalf("expected errCheckpointRegressed on size regression, got: %v", err)
	}

	env.pub.SetInputOrigin("other.example.com/inputlog")
	writeCoordinatorTiledFixture(t, logDir, origin, leaves[:50], signer)
	if err := coord.SyncOnce(ctx); !errors.Is(err, errInvariantViolation) {
		t.Fatalf("expected errInvariantViolation on input-origin mismatch in SyncOnce, got: %v", err)
	}
	if err := coord.Recover(ctx); !errors.Is(err, errInvariantViolation) {
		t.Fatalf("expected errInvariantViolation on input-origin mismatch in Recover, got: %v", err)
	}
	env.pub.SetInputOrigin(origin)

	env.pub.SetFrom(20)
	if err := coord.Recover(ctx); !errors.Is(err, errInvariantViolation) {
		t.Fatalf("expected errInvariantViolation on from mismatch in Recover, got: %v", err)
	}
}

func TestCoordinator_RunReadinessAndConcurrency(t *testing.T) {
	env := newTestEnv(t)
	coord := env.newCoord()

	// Before sync: ReadinessCheck reports genesis_backfill JSON diagnostics.
	if err := coord.ReadinessCheck(); err == nil || !strings.Contains(err.Error(), "genesis_backfill") {
		t.Fatalf("ReadinessCheck before sync = %v, want genesis_backfill", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			_ = coord.ReadinessCheck()
			_, _ = coord.SafeWatermark(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		_ = coord.SyncOnce(ctx)
	}()

	if err := coord.Run(ctx, 10*time.Millisecond); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	wg.Wait()

	state := env.pub.GetServingState()
	if state == nil || state.InputLogSize != 200 {
		t.Fatalf("expected state with size 200, got %v", state)
	}
	if err := coord.ReadinessCheck(); err != nil {
		t.Fatalf("ReadinessCheck after Run = %v, want nil", err)
	}
}
