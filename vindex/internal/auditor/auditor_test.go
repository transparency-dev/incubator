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

package auditor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func diskMPTDir(t *testing.T) string {
	t.Helper()
	if raceEnabled && runtime.GOOS == "darwin" {
		t.Skip("skipping disk-backed torchwood/mpt test under darwin -race: 16 TiB pmem mmap collides with Go race shadow arena")
	}
	return t.TempDir()
}

func testBatchRoot(leaves [][]byte) [sha256.Size]byte {
	if len(leaves) == 0 {
		return wire.EmptyRoot()
	}
	hashes := make([][sha256.Size]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = wire.LeafHash(l)
	}
	return testBatchRootHashes(hashes)
}

func testBatchRootHashes(hashes [][sha256.Size]byte) [sha256.Size]byte {
	n := len(hashes)
	if n == 1 {
		return hashes[0]
	}
	k := 1 << (bits.Len(uint(n-1)) - 1)
	return wire.InteriorHash(testBatchRootHashes(hashes[:k]), testBatchRootHashes(hashes[k:]))
}

// memoryLog implements logSource (ingest.TileFetcher + ConsistencyProof) for both Input Log and Output Log in unit tests.
type memoryLog struct {
	mu           sync.Mutex
	origin       string
	signer       note.Signer
	leaves       [][]byte
	fetched      []uint64
	overrideCP   []byte
	corruptTiles bool
}

func (l *memoryLog) Append(leaves ...[]byte) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaves = append(l.leaves, leaves...)
	return uint64(len(l.leaves))
}

func (l *memoryLog) AppendFormat(prefix string, n int) {
	for i := range n {
		l.Append(fmt.Appendf(nil, "%s%d", prefix, i))
	}
}

func (l *memoryLog) SignCheckpoint(size uint64) (*log.Checkpoint, []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	root := testBatchRoot(l.leaves[:size])
	cp := &log.Checkpoint{Origin: l.origin, Size: size, Hash: root[:]}
	signed, err := note.Sign(&note.Note{Text: string(cp.Marshal())}, l.signer)
	if err != nil {
		panic(err)
	}
	return cp, signed
}

func (l *memoryLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	l.mu.Lock()
	raw := l.overrideCP
	size := uint64(len(l.leaves))
	var root [sha256.Size]byte
	if raw == nil {
		root = testBatchRoot(l.leaves)
		cp := &log.Checkpoint{Origin: l.origin, Size: size, Hash: root[:]}
		var err error
		raw, err = note.Sign(&note.Note{Text: string(cp.Marshal())}, l.signer)
		if err != nil {
			l.mu.Unlock()
			return nil, err
		}
	}
	l.mu.Unlock()
	parsed, _ := wire.ParseCheckpointHeader(raw)
	out := &ingest.Checkpoint{Raw: raw, Origin: l.origin, Size: size, Hash: root}
	if parsed != nil {
		out.Origin = parsed.Origin
		out.Size = parsed.Size
		copy(out.Hash[:], parsed.Hash)
	}
	return out, nil
}

func (l *memoryLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (len %d)", idx, len(l.leaves))
	}
	l.fetched = append(l.fetched, idx)
	return l.leaves[idx], nil
}

func (l *memoryLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	l.mu.Lock()
	corrupt := l.corruptTiles
	l.mu.Unlock()
	if corrupt {
		return nil, fmt.Errorf("%w: simulated output log bundle authentication failure", errInclusionFailed)
	}
	adapter := &ingest.LeafAdapter{LeafFn: l.Leaf, BundleSize: 1}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (l *memoryLog) ConsistencyProof(_ context.Context, smaller, larger uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if smaller == 0 || smaller == larger {
		return nil, nil
	}
	if larger > uint64(len(l.leaves)) {
		return nil, fmt.Errorf("larger %d exceeds len %d", larger, len(l.leaves))
	}
	var hashes []tlog.Hash
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = hashes[idx]
		}
		return out, nil
	})
	for i, leaf := range l.leaves[:larger] {
		sh, err := tlog.StoredHashes(int64(i), leaf, hr)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, sh...)
	}
	tp, err := tlog.ProveTree(int64(larger), int64(smaller), hr)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(tp))
	for i := range tp {
		h := tp[i]
		out[i] = slices.Clone(h[:])
	}
	return out, nil
}

func (l *memoryLog) ResetFetched() {
	l.mu.Lock()
	l.fetched = nil
	l.mu.Unlock()
}

func (l *memoryLog) FetchedLeaves() []uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.fetched)
}

func computeExpectedMPTRoot(t *testing.T, leaves [][]byte, from uint64, host *wasmhost.WASMHost) [sha256.Size]byte {
	t.Helper()
	ctx := context.Background()
	if uint64(len(leaves)) <= from {
		return wire.EmptyRoot()
	}
	db, err := kvstore.Open("", &kvstore.Options{CacheSizeMB: 8})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	ki := make(map[string][]uint64)
	for start := int(from); start < len(leaves); start += int(wasmhost.DefaultBundleSize) {
		end := min(start+int(wasmhost.DefaultBundleSize), len(leaves))
		bundleRes, err := host.MapBundle(ctx, leaves[start:end])
		if err != nil {
			t.Fatalf("MapBundle failed: %v", err)
		}
		for offset, leafEntries := range bundleRes {
			leafIdx := uint64(start + offset)
			for _, e := range leafEntries {
				ki[e.Key] = append(ki[e.Key], leafIdx)
			}
		}
	}
	idx := kvstore.NewKVIndexer(db)
	res, err := idx.IndexMappedBatch(ctx, &kvstore.MappedBatch{
		StartLeafIdx: from,
		EndLeafIdx:   uint64(len(leaves)),
		KeyIndices:   ki,
	}, nil, 0)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}
	mptMgr := mpt.NewMem()
	root, err := mptMgr.CommitKeysWithVersion(res.ModifiedKeyValueRoots, int64(len(leaves)))
	if err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	return root
}

type testHarness struct {
	inSigner    note.Signer
	inVerifier  note.Verifier
	inVKey      string
	inPolicy    wire.Policy
	outSigner   note.Signer
	outVerifier note.Verifier
	outVKey     string
	outPolicy   wire.Policy
	inLog       *memoryLog
	outLog      *memoryLog
	wasmHost    *wasmhost.WASMHost
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	const (
		inOrigin  = "example.com/inputlog"
		outOrigin = "example.com/outputlog"
	)
	inSKey, inVKey, err := note.GenerateKey(rand.Reader, inOrigin)
	if err != nil {
		t.Fatalf("GenerateKey(in) failed: %v", err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)
	inPolicy, _ := wire.BuildPolicy(inOrigin, inVerifier, nil, 0)

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatalf("GenerateKey(out) failed: %v", err)
	}
	outSigner, _ := note.NewSigner(outSKey)
	outVerifier, _ := note.NewVerifier(outVKey)
	outPolicy, _ := wire.BuildPolicy(outOrigin, outVerifier, nil, 0)

	return &testHarness{
		inSigner:    inSigner,
		inVerifier:  inVerifier,
		inVKey:      inVKey,
		inPolicy:    inPolicy,
		outSigner:   outSigner,
		outVerifier: outVerifier,
		outVKey:     outVKey,
		outPolicy:   outPolicy,
		inLog:       &memoryLog{origin: inOrigin, signer: inSigner},
		outLog:      &memoryLog{origin: outOrigin, signer: outSigner},
		wasmHost:    wasmhosttest.Host(),
	}
}

func (h *testHarness) baseConfig() Config {
	return Config{
		InputLogOrigin:  h.inLog.origin,
		InputLogPolicy:  h.inPolicy,
		OutputLogOrigin: h.outLog.origin,
		OutputLogPolicy: h.outPolicy,
		outputFetcher:   h.outLog,
		inputFetcher:    h.inLog,
		WASMHost:        h.wasmHost,
		DBPath:          ":memory:",
		DBCacheSizeMB:   8,
		MPTDir:          ":memory:",
	}
}

func (h *testHarness) commitHonestState(t *testing.T, size, from uint64) [sha256.Size]byte {
	t.Helper()
	root := computeExpectedMPTRoot(t, h.inLog.leaves[:size], from, h.wasmHost)
	cp, _ := h.inLog.SignCheckpoint(size)
	h.outLog.Append(wire.FormatOutputLogLeafFull(root, from, cp))
	return root
}

func (h *testHarness) newVerifier(t *testing.T, mutators ...func(*Config)) *Verifier {
	t.Helper()
	cfg := h.baseConfig()
	for _, fn := range mutators {
		fn(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func TestAuditor_ConfigValidationRequiresPolicies(t *testing.T) {
	h := newTestHarness(t)
	noOutPol := h.baseConfig()
	noOutPol.OutputLogPolicy = nil
	if _, err := New(noOutPol); err == nil {
		t.Fatal("expected New to reject nil OutputLogPolicy")
	}
	noInPol := h.baseConfig()
	noInPol.InputLogPolicy = nil
	if _, err := New(noInPol); err == nil {
		t.Fatal("expected New to reject nil InputLogPolicy")
	}
}

func TestAuditor_HonestSyncPersistenceAndNoDuplicateIndexing(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	dbDir := t.TempDir()
	mptDir := diskMPTDir(t)

	h.inLog.AppendFormat("persist-leaf-", 15)
	root0 := h.commitHonestState(t, 5, 0)

	cfg := h.baseConfig()
	cfg.DBPath = dbDir
	cfg.MPTDir = mptDir

	v1, err := New(cfg)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	h.inLog.ResetFetched()
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	if st := v1.Status(); st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 5 || st.LastVerifiedRoot != root0 {
		t.Fatalf("v1 status = %+v", st)
	}
	if got := len(h.inLog.FetchedLeaves()); got != 5 {
		t.Fatalf("v1 fetched %d leaves, want 5", got)
	}
	_ = v1.Close()

	// Phase 2: append OutputLog leaf 1 ([5..10)), restart, verify zero duplicate fetches of [0..5)
	root1 := h.commitHonestState(t, 10, 0)
	h.inLog.ResetFetched()

	v2, err := New(cfg)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	if st := v2.Status(); st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 5 || st.LastVerifiedRoot != root0 {
		t.Fatalf("v2 recovered status = %+v", st)
	}
	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}
	if st := v2.Status(); st.VerifiedOutputSize != 2 || st.VerifiedInputSize != 10 || st.LastVerifiedRoot != root1 {
		t.Fatalf("v2 updated status = %+v", st)
	}
	if fetched2 := h.inLog.FetchedLeaves(); !slices.Equal(fetched2, []uint64{5, 6, 7, 8, 9}) {
		t.Fatalf("v2 fetched leaves = %v, want [5 6 7 8 9]", fetched2)
	}
	_ = v2.Close()

	// Phase 3: zero-delta restart performs zero InputLog fetches
	h.inLog.ResetFetched()
	v3, err := New(cfg)
	if err != nil {
		t.Fatalf("v3 New failed: %v", err)
	}
	defer func() { _ = v3.Close() }()
	if err := v3.VerifyOnce(ctx); err != nil {
		t.Fatalf("v3 zero-delta VerifyOnce failed: %v", err)
	}
	if got := len(h.inLog.FetchedLeaves()); got != 0 {
		t.Fatalf("zero-delta VerifyOnce fetched %d leaves, want 0", got)
	}
}

func TestAuditor_GenesisCoarseCheckpointAndChunkRollover(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	h.inLog.AppendFormat("genesis-bulk-", 600)
	wantRoot := h.commitHonestState(t, 600, 0)

	dbDir := t.TempDir()
	mptDir := diskMPTDir(t)

	// Simulate an interrupted genesis backfill run that completed a coarse MPT checkpoint at 128
	// and indexed KV slabs up to 200 before crashing with output_watermark == 0.
	{
		db, err := kvstore.Open(dbDir, &kvstore.Options{CacheSizeMB: 8, ChunkSize: 64})
		if err != nil {
			t.Fatalf("kvstore.Open failed: %v", err)
		}
		mptMgr, err := mpt.Open(mptDir)
		if err != nil {
			t.Fatalf("mpt.Open failed: %v", err)
		}
		idx := kvstore.NewKVIndexer(db)
		ki1 := make(map[string][]uint64, 128)
		for i := range 128 {
			ki1[string(h.inLog.leaves[i])] = []uint64{uint64(i)}
		}
		res1, err := idx.IndexMappedBatch(ctx, &kvstore.MappedBatch{StartLeafIdx: 0, EndLeafIdx: 128, KeyIndices: ki1}, nil, 600)
		if err != nil {
			t.Fatalf("IndexMappedBatch 1 failed: %v", err)
		}
		_ = db.Sync()
		_ = mptMgr.SetKeyBatch(res1.ModifiedKeyValueRoots)
		_, _ = mptMgr.Snap(128)
		_ = mptMgr.Persist()

		ki2 := make(map[string][]uint64, 72)
		for i := 128; i < 200; i++ {
			ki2[string(h.inLog.leaves[i])] = []uint64{uint64(i)}
		}
		if _, err := idx.IndexMappedBatch(ctx, &kvstore.MappedBatch{StartLeafIdx: 128, EndLeafIdx: 200, KeyIndices: ki2}, nil, 600); err != nil {
			t.Fatalf("IndexMappedBatch 2 failed: %v", err)
		}
		_ = db.Sync()
		_ = mptMgr.Close()
		_ = db.Close()
	}

	v := h.newVerifier(t, func(c *Config) {
		c.DBPath = dbDir
		c.MPTDir = mptDir
		c.ChunkSize = 64
		c.CommitBatchSize = 64
		c.CoarseCheckpointInterval = 128
	})
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce resume across interrupted genesis backfill failed: %v", err)
	}
	if st := v.Status(); st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 600 || st.LastVerifiedRoot != wantRoot {
		t.Fatalf("unexpected status after resumed genesis backfill: %+v", st)
	}
	_ = v.Close()

	// Reopening with mismatched ExpectedFrom or InputLogOrigin must fail immediately in New().
	wrongFrom := uint64(5)
	badCfg := h.baseConfig()
	badCfg.DBPath = dbDir
	badCfg.MPTDir = mptDir
	badCfg.ExpectedFrom = &wrongFrom
	if _, err := New(badCfg); err == nil {
		t.Fatal("expected New() to reject mismatched ExpectedFrom against persisted DB")
	}
	badOriginCfg := h.baseConfig()
	badOriginCfg.DBPath = dbDir
	badOriginCfg.MPTDir = mptDir
	badOriginCfg.InputLogOrigin = "other.example.com/inputlog"
	if _, err := New(badOriginCfg); err == nil {
		t.Fatal("expected New() to reject mismatched InputLogOrigin against persisted DB")
	}
}

func TestAuditor_AdversarialTamperAndForensicStateFreeze(t *testing.T) {
	ctx := context.Background()

	t.Run("forged_output_root_halts_and_freezes_pebble_state", func(t *testing.T) {
		h := newTestHarness(t)
		metrics.ResetAuditorRootMismatch()
		beforeCounter := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

		dbDir := t.TempDir()
		h.inLog.AppendFormat("forensic-leaf-", 10)
		h.commitHonestState(t, 5, 0)

		forgedRoot := sha256.Sum256([]byte("forged_mpt_root"))
		cp10, _ := h.inLog.SignCheckpoint(10)
		h.outLog.Append(wire.FormatOutputLogLeafFull(forgedRoot, 0, cp10))

		v, err := New(Config{
			InputLogOrigin:  h.inLog.origin,
			InputLogPolicy:  h.inPolicy,
			OutputLogOrigin: h.outLog.origin,
			OutputLogPolicy: h.outPolicy,
			outputFetcher:   h.outLog,
			inputFetcher:    h.inLog,
			WASMHost:        h.wasmHost,
			DBPath:          dbDir,
			DBCacheSizeMB:   8,
			MPTDir:          ":memory:",
		})
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}

		err = v.VerifyOnce(ctx)
		var rmErr *RootMismatchError
		if !errors.Is(err, ErrRootMismatch) || !errors.As(err, &rmErr) {
			t.Fatalf("expected *RootMismatchError wrapping ErrRootMismatch, got %v", err)
		}
		if rmErr.OutputIndex != 1 || rmErr.InputSize != 10 || rmErr.CommittedMPTRoot != forgedRoot {
			t.Fatalf("unexpected RootMismatchError: %+v", rmErr)
		}
		if st := v.Status(); !st.IsHalted || st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 5 {
			t.Fatalf("status = %+v, want halted at out=1 in=5", st)
		}
		if g := testutil.ToFloat64(metrics.AuditorRootMismatch); g != 1.0 {
			t.Fatalf("AuditorRootMismatch gauge = %v, want 1.0", g)
		}
		if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal); c != beforeCounter+1 {
			t.Fatalf("AuditorRootMismatchesTotal = %v, want %v", c, beforeCounter+1)
		}
		if err2 := v.VerifyOnce(ctx); !errors.Is(err2, ErrRootMismatch) {
			t.Fatalf("subsequent VerifyOnce = %v, want ErrRootMismatch", err2)
		}
		_ = v.Close()

		// Forensic freeze: KeyMetaKVSize remains 5 and leaves [5..10) were never committed to Pebble.
		db, err := kvstore.Open(dbDir, &kvstore.Options{CacheSizeMB: 8})
		if err != nil {
			t.Fatalf("kvstore.Open failed: %v", err)
		}
		defer func() { _ = db.Close() }()
		if kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize); err != nil || kvSize != 5 {
			t.Fatalf("KeyMetaKVSize = %d (err=%v), want 5", kvSize, err)
		}
		for i := 5; i < 10; i++ {
			kh := sha256.Sum256(fmt.Appendf(nil, "forensic-leaf-%d", i))
			res, err := db.Lookup(kh, nil, 10, 10)
			if err != nil || (res != nil && len(res.MatchedIndices) > 0) {
				t.Fatalf("unverified leaf %d leaked into Pebble: %+v (err=%v)", i, res, err)
			}
		}
	})

	for _, tc := range []struct {
		name    string
		setup   func(*testing.T, *testHarness, *Verifier)
		wantErr error
	}{
		{
			name: "corrupted_input_leaf_content_diverges_from_committed_root",
			setup: func(t *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.AppendFormat("genuine-", 5)
				genuineRoot := computeExpectedMPTRoot(t, h.inLog.leaves, 0, h.wasmHost)
				h.inLog.leaves[2] = []byte("corrupted-2")
				cp5, _ := h.inLog.SignCheckpoint(5)
				h.outLog.Append(wire.FormatOutputLogLeafFull(genuineRoot, 0, cp5))
			},
			wantErr: ErrRootMismatch,
		},
		{
			name: "corrupted_output_log_bundle_authentication",
			setup: func(t *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.AppendFormat("inc-", 5)
				h.commitHonestState(t, 5, 0)
				h.outLog.corruptTiles = true
			},
			wantErr: errInclusionFailed,
		},
		{
			name: "corrupted_output_log_leaf_payload",
			setup: func(_ *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.Append([]byte("x"))
				h.outLog.Append([]byte("not-a-valid-vindex-leaf"))
			},
			wantErr: wire.ErrOutputLogCorrupted,
		},
		{
			name: "non_monotonic_input_size",
			setup: func(t *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.AppendFormat("mono-", 10)
				h.commitHonestState(t, 10, 0)
				h.commitHonestState(t, 5, 0)
			},
			wantErr: errMonotonicityBroken,
		},
		{
			name: "output_log_size_regression",
			setup: func(t *testing.T, h *testHarness, v *Verifier) {
				h.inLog.AppendFormat("reg-", 5)
				h.commitHonestState(t, 5, 0)
				if err := v.VerifyOnce(ctx); err != nil {
					t.Fatalf("VerifyOnce failed: %v", err)
				}
				h.outLog.mu.Lock()
				h.outLog.leaves = nil
				h.outLog.mu.Unlock()
			},
			wantErr: errOutputLogRegressed,
		},
		{
			name: "input_log_checkpoint_regression_across_polls",
			setup: func(t *testing.T, h *testHarness, v *Verifier) {
				h.inLog.AppendFormat("inreg-", 20)
				h.commitHonestState(t, 5, 0)
				if err := v.VerifyOnce(ctx); err != nil {
					t.Fatalf("VerifyOnce failed: %v", err)
				}
				h.inLog.mu.Lock()
				h.inLog.leaves = h.inLog.leaves[:10]
				h.inLog.mu.Unlock()
				h.commitHonestState(t, 10, 0)
			},
			wantErr: errMonotonicityBroken,
		},
		{
			name: "size_0_non_empty_input_root",
			setup: func(_ *testing.T, h *testHarness, _ *Verifier) {
				forgedHash := sha256.Sum256([]byte("non-empty-root-for-size-0"))
				badCP0 := &log.Checkpoint{Origin: h.inLog.origin, Size: 0, Hash: forgedHash[:]}
				h.outLog.Append(wire.FormatOutputLogLeafFull(wire.EmptyRoot(), 0, badCP0))
			},
			wantErr: errConsistencyFailed,
		},
		{
			name: "empty_range_from_equals_input_size_with_non_empty_mpt_root",
			setup: func(_ *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.AppendFormat("skip-", 5)
				cp5, _ := h.inLog.SignCheckpoint(5)
				h.outLog.Append(wire.FormatOutputLogLeafFull(sha256.Sum256([]byte("forged-non-empty")), 5, cp5))
			},
			wantErr: errConsistencyFailed,
		},
		{
			name: "forged_input_root_at_target_smaller_than_latest_input_cp",
			setup: func(t *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.AppendFormat("lag-", 20)
				root5 := computeExpectedMPTRoot(t, h.inLog.leaves[:5], 0, h.wasmHost)
				badHash := sha256.Sum256([]byte("forged-intermediate-input-root-5"))
				forgedInCP5 := &log.Checkpoint{Origin: h.inLog.origin, Size: 5, Hash: badHash[:]}
				h.outLog.Append(wire.FormatOutputLogLeafFull(root5, 0, forgedInCP5))
			},
			wantErr: errConsistencyFailed,
		},
		{
			name: "split_view_input_log",
			setup: func(t *testing.T, h *testHarness, v *Verifier) {
				h.inLog.AppendFormat("entry-", 10)
				h.commitHonestState(t, 5, 0)
				if err := v.VerifyOnce(ctx); err != nil {
					t.Fatalf("VerifyOnce leaf 0 failed: %v", err)
				}
				h.inLog.mu.Lock()
				h.inLog.leaves[0] = []byte("mutated-historical-0")
				h.inLog.mu.Unlock()
				h.commitHonestState(t, 10, 0)
			},
			wantErr: errConsistencyFailed,
		},
		{
			name: "split_view_output_log",
			setup: func(t *testing.T, h *testHarness, v *Verifier) {
				h.inLog.AppendFormat("entry-", 10)
				root5 := h.commitHonestState(t, 5, 0)
				if err := v.VerifyOnce(ctx); err != nil {
					t.Fatalf("VerifyOnce leaf 0 failed: %v", err)
				}
				cp5, _ := h.inLog.SignCheckpoint(5)
				h.outLog.mu.Lock()
				h.outLog.leaves[0] = wire.FormatOutputLogLeafFull(root5, 1, cp5)
				h.outLog.mu.Unlock()
				h.commitHonestState(t, 10, 0)
			},
			wantErr: errConsistencyFailed,
		},
		{
			name: "cross_entry_input_origin_mismatch",
			setup: func(t *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.AppendFormat("orig-", 5)
				root5 := computeExpectedMPTRoot(t, h.inLog.leaves[:5], 0, h.wasmHost)
				cp5, _ := h.inLog.SignCheckpoint(5)
				cp5.Origin = "evil.example.com/otherlog"
				h.outLog.Append(wire.FormatOutputLogLeafFull(root5, 0, cp5))
			},
			wantErr: errCheckpointFailed,
		},
		{
			name: "deterministic_wasm_trap_halts_auditor",
			setup: func(_ *testing.T, h *testHarness, _ *Verifier) {
				h.inLog.Append([]byte("\x00trap_leaf"))
				cp1, _ := h.inLog.SignCheckpoint(1)
				h.outLog.Append(wire.FormatOutputLogLeafFull(wire.EmptyRoot(), 0, cp1))
			},
			wantErr: wasmhost.ErrWasmHalt,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t)
			v := h.newVerifier(t)
			tc.setup(t, h, v)
			if err := v.VerifyOnce(ctx); !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyOnce() err = %v, want %v", err, tc.wantErr)
			}
			if !v.Status().IsHalted {
				t.Fatal("expected Verifier to be halted")
			}
		})
	}
}

func TestAuditor_CrossEntryFromDrift(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	h.inLog.AppendFormat("drift-", 10)
	h.commitHonestState(t, 5, 0)
	h.commitHonestState(t, 10, 2) // from drifts 0 -> 2 when ExpectedFrom is nil

	v := h.newVerifier(t)
	if err := v.VerifyOnce(ctx); err == nil || !v.Status().IsHalted {
		t.Fatalf("expected halt on cross-entry from drift, got err=%v status=%+v", err, v.Status())
	}
}

func writeTiledLogDir(t *testing.T, dir, origin string, signer note.Signer, leaves [][]byte) {
	t.Helper()
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
			t.Fatalf("StoredHashes(%d) failed: %v", idx, err)
		}
		hashes = append(hashes, sh...)
	}
	treeSize := int64(len(leaves))
	rootHash, err := tlog.TreeHash(treeSize, hr)
	if err != nil {
		t.Fatalf("TreeHash failed: %v", err)
	}
	for _, tile := range tlog.NewTiles(layout.TileHeight, 0, treeSize) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			t.Fatalf("ReadTileData failed: %v", err)
		}
		p := uint8(0)
		if tile.W < (1 << layout.TileHeight) {
			p = uint8(tile.W)
		}
		dst := filepath.Join(dir, layout.TilePath(uint64(tile.L), uint64(tile.N), p))
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		_ = os.WriteFile(dst, data, 0o644)
	}
	const bundleW = int(layout.EntryBundleWidth)
	for start := 0; start < len(leaves); start += bundleW {
		end := min(start+bundleW, len(leaves))
		p := uint8(0)
		if end-start < bundleW {
			p = uint8(end - start)
		}
		var buf []byte
		for _, leaf := range leaves[start:end] {
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(leaf)))
			buf = append(buf, leaf...)
		}
		dst := filepath.Join(dir, layout.EntriesPath(uint64(start/bundleW), p))
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		_ = os.WriteFile(dst, buf, 0o644)
	}
	cp := (&log.Checkpoint{Origin: origin, Size: uint64(treeSize), Hash: rootHash[:]}).Marshal()
	rawCP, _ := note.Sign(&note.Note{Text: string(cp)}, signer)
	_ = os.WriteFile(filepath.Join(dir, layout.CheckpointPath), rawCP, 0o644)
}

func TestAuditor_HTTPTiledOutputAndInputLogsEndToEnd(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	h.inLog.AppendFormat("http-tiled-", 300) // Input Log is at 300 (.p/44 only), while Output Log Entry 0 commits 276!
	fromVal := uint64(10)
	root276 := h.commitHonestState(t, 276, fromVal)

	inDir := t.TempDir()
	outDir := t.TempDir()
	writeTiledLogDir(t, inDir, h.inLog.origin, h.inSigner, h.inLog.leaves) // writes only .p/44 for bundle 1 (size 300), NOT .p/20!
	writeTiledLogDir(t, outDir, h.outLog.origin, h.outSigner, h.outLog.leaves)

	inSrv := httptest.NewServer(http.FileServer(http.Dir(inDir)))
	defer inSrv.Close()
	outSrv := httptest.NewServer(http.FileServer(http.Dir(outDir)))
	defer outSrv.Close()

	v, err := New(Config{
		InputLogURL:     inSrv.URL,
		InputLogOrigin:  h.inLog.origin,
		InputLogPolicy:  h.inPolicy,
		OutputLogURL:    outSrv.URL,
		OutputLogOrigin: h.outLog.origin,
		OutputLogPolicy: h.outPolicy,
		WASMHost:        h.wasmHost,
		ExpectedFrom:    &fromVal,
		DBPath:          ":memory:",
		DBCacheSizeMB:   8,
		MPTDir:          ":memory:",
	})
	if err != nil {
		t.Fatalf("New(HTTP tiled logs) failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce over lagging HTTP partial-tile InputLog (276 < 300) failed: %v", err)
	}
	if st := v.Status(); st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 276 || st.LastVerifiedRoot != root276 {
		t.Fatalf("unexpected status over HTTP tiled logs: %+v", st)
	}

	// Corrupt Output Log entry bundle on disk while keeping signed Output Log checkpoint unchanged -> must halt with errInclusionFailed.
	corruptEntryPath := filepath.Join(outDir, layout.EntriesPath(0, 1))
	_ = os.WriteFile(corruptEntryPath, []byte{0x00, 0x04, 'e', 'v', 'i', 'l'}, 0o644)
	vTamper, err := New(Config{
		InputLogURL:     inSrv.URL,
		InputLogOrigin:  h.inLog.origin,
		InputLogPolicy:  h.inPolicy,
		OutputLogURL:    outSrv.URL,
		OutputLogOrigin: h.outLog.origin,
		OutputLogPolicy: h.outPolicy,
		WASMHost:        h.wasmHost,
		ExpectedFrom:    &fromVal,
		DBPath:          ":memory:",
		DBCacheSizeMB:   8,
		MPTDir:          ":memory:",
	})
	if err != nil {
		t.Fatalf("New(vTamper) failed: %v", err)
	}
	defer func() { _ = vTamper.Close() }()
	if err := vTamper.VerifyOnce(ctx); !errors.Is(err, errInclusionFailed) || !vTamper.Status().IsHalted {
		t.Fatalf("expected errInclusionFailed halt on tampered Output Log entry bundle, got err=%v status=%+v", err, vTamper.Status())
	}
}

func TestAuditor_WitnessPolicyExpectedFromAndStartupMPTCatchUp(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	genWitness := func(name string) (note.Signer, string) {
		sKey, rawVKey, _ := note.GenerateKey(rand.Reader, name)
		cs, _ := f_note.NewSignerForCosignatureV1(sKey)
		cosigVKey, _ := f_note.VKeyToCosignatureV1(rawVKey)
		return cs, cosigVKey
	}
	w1Signer, w1VKey := genWitness("witness1.example.com")
	w2Signer, w2VKey := genWitness("witness2.example.com")
	_, w3VKey := genWitness("witness3.example.com")

	outPolicyText := fmt.Sprintf("log %s\nwitness w1 %s\nwitness w2 %s\nwitness w3 %s\ngroup g 2 w1 w2 w3\nquorum g\n",
		h.outVKey, w1VKey, w2VKey, w3VKey)
	outPolicy, err := wire.ParsePolicy([]byte(outPolicyText))
	if err != nil {
		t.Fatalf("wire.ParsePolicy failed: %v", err)
	}

	h.inLog.AppendFormat("policy-entry-", 10)
	fromVal := uint64(2)
	h.commitHonestState(t, 5, fromVal)
	_, unwitnessedOutCP := h.outLog.SignCheckpoint(1)
	h.outLog.overrideCP = unwitnessedOutCP

	// 1. Unwitnessed OutputLog checkpoint fails 2-of-3 quorum
	vFail := h.newVerifier(t, func(c *Config) {
		c.InputLogOrigin = "" // also verifies InputLogOrigin auto-binding via latestInCP.Origin
		c.OutputLogPolicy = outPolicy
		c.ExpectedFrom = &fromVal
	})
	if err := vFail.VerifyOnce(ctx); !errors.Is(err, errCheckpointFailed) {
		t.Fatalf("expected errCheckpointFailed without witness quorum, got %v", err)
	}

	// 2. Cosign with 2-of-3 witnesses; wrong ExpectedFrom fails, matching ExpectedFrom=2 succeeds
	parsedOutNote, _ := note.Open(unwitnessedOutCP, note.VerifierList(h.outVerifier))
	witnessedOutCP, _ := note.Sign(parsedOutNote, w1Signer, w2Signer)
	h.outLog.overrideCP = witnessedOutCP

	wrongFrom := uint64(0)
	vWrongFrom := h.newVerifier(t, func(c *Config) {
		c.OutputLogPolicy = outPolicy
		c.ExpectedFrom = &wrongFrom
	})
	if err := vWrongFrom.VerifyOnce(ctx); err == nil || !vWrongFrom.Status().IsHalted {
		t.Fatal("expected ExpectedFrom mismatch halt")
	}

	dbDir := t.TempDir()
	v1 := h.newVerifier(t, func(c *Config) {
		c.OutputLogPolicy = outPolicy
		c.ExpectedFrom = &fromVal
		c.DBPath = dbDir
		c.MPTDir = ":memory:"
	})
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	_ = v1.Close()

	// 3. Simulate crash between Pebble commit and MPT fsync by reopening dbDir with an empty in-memory MPT
	root10From2 := h.commitHonestState(t, 10, fromVal)
	_, unwitnessedOutCP2 := h.outLog.SignCheckpoint(2)
	parsedOutNote2, _ := note.Open(unwitnessedOutCP2, note.VerifierList(h.outVerifier))
	witnessedOutCP2, _ := note.Sign(parsedOutNote2, w1Signer, w2Signer)
	h.outLog.overrideCP = witnessedOutCP2

	v2 := h.newVerifier(t, func(c *Config) {
		c.OutputLogPolicy = outPolicy
		c.ExpectedFrom = &fromVal
		c.DBPath = dbDir
		c.MPTDir = ":memory:"
	})
	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce after simulated MPT lag failed: %v", err)
	}
	if st2 := v2.Status(); st2.VerifiedOutputSize != 2 || st2.VerifiedInputSize != 10 || st2.LastVerifiedRoot != root10From2 {
		t.Fatalf("unexpected v2 status after startup MPT catch-up: %+v", st2)
	}
}

func TestAuditor_AdminHandlerAndRunLoop(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetAuditorRootMismatch()

	h.inLog.AppendFormat("admin-leaf-", 5)
	h.commitHonestState(t, 5, 0)

	v := h.newVerifier(t, func(c *Config) {
		c.MetricsAddr = "127.0.0.1:0"
		c.PollInterval = 15 * time.Millisecond
	})

	// Concurrent VerifyOnce + Status race check
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); _ = v.VerifyOnce(ctx) }()
		go func() { defer wg.Done(); _ = v.Status() }()
	}
	wg.Wait()

	adminHandler := v.AdminHandler()
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		adminHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
			t.Fatalf("healthy GET %s = %d %q", path, rec.Code, rec.Body.String())
		}
		headRec := httptest.NewRecorder()
		adminHandler.ServeHTTP(headRec, httptest.NewRequest(http.MethodHead, path, nil))
		if headRec.Code != http.StatusOK || headRec.Body.Len() != 0 {
			t.Fatalf("healthy HEAD %s = %d len=%d", path, headRec.Code, headRec.Body.Len())
		}
		postRec := httptest.NewRecorder()
		adminHandler.ServeHTTP(postRec, httptest.NewRequest(http.MethodPost, path, nil))
		if postRec.Code != http.StatusMethodNotAllowed || postRec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("POST %s = %d Allow=%q, want 405 GET, HEAD", path, postRec.Code, postRec.Header().Get("Allow"))
		}
	}
	for _, path := range []string{"/metrics", "/debug/pprof/"} {
		rec := httptest.NewRecorder()
		adminHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
	}

	// Run loop + context cancel
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Millisecond)
	defer cancel()
	if err := v.Run(runCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	// Trigger forensic halt via forged MPTRoot
	h.inLog.AppendFormat("admin-more-", 5)
	forgedRoot := sha256.Sum256([]byte("forged-admin-mpt-root"))
	cp10, _ := h.inLog.SignCheckpoint(10)
	h.outLog.Append(wire.FormatOutputLogLeafFull(forgedRoot, 0, cp10))
	if err := v.VerifyOnce(ctx); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("VerifyOnce = %v, want ErrRootMismatch", err)
	}

	haltedHealth := httptest.NewRecorder()
	adminHandler.ServeHTTP(haltedHealth, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if haltedHealth.Code != http.StatusOK {
		t.Fatalf("halted GET /healthz = %d, want 200", haltedHealth.Code)
	}

	rec := httptest.NewRecorder()
	adminHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "30" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("halted GET /readyz = %d Retry-After=%q Cache-Control=%q", rec.Code, rec.Header().Get("Retry-After"), rec.Header().Get("Cache-Control"))
	}
	var diag map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &diag); err != nil || diag["status"] != "degraded" || diag["committed_root"] != fmt.Sprintf("%x", forgedRoot) {
		t.Fatalf("unexpected /readyz JSON %q (err=%v)", rec.Body.String(), err)
	}
}
