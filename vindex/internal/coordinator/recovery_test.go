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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/tessera/api"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func skipIfRaceDarwin(t *testing.T) {
	t.Helper()
	if raceEnabled && runtime.GOOS == "darwin" {
		t.Skip("skipping disk-backed torchwood/mpt test under darwin -race: 16 TiB pmem mmap collides with Go race shadow arena")
	}
}

func makeTestLeaves(prefix string, n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = fmt.Appendf(nil, "%s%d", prefix, i)
	}
	return leaves
}

func makeRawCP(origin string, size uint64, hash [sha256.Size]byte) *ingest.Checkpoint {
	raw := (&log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hash[:],
	}).Marshal()
	return &ingest.Checkpoint{
		Raw:    raw,
		Origin: origin,
		Size:   size,
		Hash:   hash,
	}
}

type memoryOutputLog struct {
	mu           sync.Mutex
	leaves       [][]byte
	origin       string
	signers      []note.Signer
	corruptProof bool
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

func newMemoryOutputLog(origin string) *memoryOutputLog {
	return &memoryOutputLog{origin: origin}
}

func (m *memoryOutputLog) formatSignedCP(size uint64, root [sha256.Size]byte) ([]byte, error) {
	body := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	if len(m.signers) > 0 {
		return note.Sign(&note.Note{Text: body}, m.signers...)
	}
	return []byte(body + "\n— test_sig\n"), nil
}

func (m *memoryOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	rawCP, err := m.formatSignedCP(uint64(len(m.leaves)), testBatchRoot(m.leaves))
	return idx, rawCP, err
}

func (m *memoryOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= uint64(len(m.leaves)) {
		return nil, fmt.Errorf("index out of range %d >= %d", idx, len(m.leaves))
	}
	return m.leaves[idx], nil
}

func (m *memoryOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.formatSignedCP(uint64(len(m.leaves)), testBatchRoot(m.leaves))
}

func (m *memoryOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corruptProof {
		return [][sha256.Size]byte{sha256.Sum256([]byte("corrupt"))}, nil
	}

	leafHashes := make([][sha256.Size]byte, treeSize)
	for i, l := range m.leaves[:treeSize] {
		leafHashes[i] = wire.LeafHash(l)
	}

	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		k := uint64(1) << (bits.Len(uint(n-1)) - 1)
		if idx < k {
			rightSubRoot := testBatchRootHashes(leaves[k:])
			buildProof(leaves[:k], idx)
			proof = append(proof, rightSubRoot)
		} else {
			leftSubRoot := testBatchRootHashes(leaves[:k])
			buildProof(leaves[k:], idx-k)
			proof = append(proof, leftSubRoot)
		}
	}

	buildProof(leafHashes, leafIdx)
	return proof, nil
}

type memoryTileFetcher struct {
	mu           sync.Mutex
	leaves       [][]byte
	origin       string
	overrideCP   *ingest.Checkpoint
	minLeafRead  *uint64
	fetchedCount int
}

func (f *memoryTileFetcher) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overrideCP != nil {
		return f.overrideCP, nil
	}
	return makeRawCP(f.origin, uint64(len(f.leaves)), testBatchRoot(f.leaves)), nil
}

func (f *memoryTileFetcher) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx >= uint64(len(f.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (len %d)", idx, len(f.leaves))
	}
	if f.minLeafRead == nil || idx < *f.minLeafRead {
		v := idx
		f.minLeafRead = &v
	}
	f.fetchedCount++
	return f.leaves[idx], nil
}

func (f *memoryTileFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     f.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (f *memoryTileFetcher) ConsistencyProof(_ context.Context, smaller, larger uint64) ([][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if smaller == 0 || smaller == larger {
		return nil, nil
	}
	if larger > uint64(len(f.leaves)) {
		return nil, fmt.Errorf("larger %d exceeds len %d", larger, len(f.leaves))
	}
	var hashes []tlog.Hash
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = hashes[idx]
		}
		return out, nil
	})
	for i, leaf := range f.leaves[:larger] {
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

func openMemDB(t *testing.T) *kvstore.DB {
	t.Helper()
	db, err := kvstore.Open("", &kvstore.Options{CacheSizeMB: 8, ChunkSize: 64})
	if err != nil {
		t.Fatalf("kvstore.Open(in-memory) failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func makeMappedBatch(leaves [][]byte, start, end int) *kvstore.MappedBatch {
	ki := make(map[string][]uint64, end-start)
	for i := start; i < end; i++ {
		k := string(leaves[i])
		ki[k] = append(ki[k], uint64(i))
	}
	return &kvstore.MappedBatch{
		StartLeafIdx: uint64(start),
		EndLeafIdx:   uint64(end),
		KeyIndices:   ki,
	}
}

type testEnv struct {
	db      *kvstore.DB
	mpt     *mpt.Manager
	outLog  *memoryOutputLog
	pub     *tree.OutputPublisher
	indexer *kvstore.KVIndexer
	fetcher *memoryTileFetcher
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	db := openMemDB(t)
	mptMgr := mpt.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(mptMgr, outLog)
	indexer := kvstore.NewKVIndexer(db)
	fetcher := &memoryTileFetcher{
		leaves: makeTestLeaves("leaf_recovery_", 200),
		origin: "example.com/inputlog",
	}
	return &testEnv{
		db:      db,
		mpt:     mptMgr,
		outLog:  outLog,
		pub:     pub,
		indexer: indexer,
		fetcher: fetcher,
	}
}

func (e *testEnv) newCoord(mutators ...func(*Config)) *Coordinator {
	cfg := Config{
		DB:        e.db,
		MPT:       e.mpt,
		OutputLog: e.outLog,
		Publisher: e.pub,
		Indexer:   e.indexer,
		Fetcher:   e.fetcher,
		WASMHost:  wasmhosttest.Host(),
	}
	for _, fn := range mutators {
		fn(&cfg)
	}
	return New(cfg)
}

func TestRecovery_CleanWarmStartAndKVLeadForwardSync(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	coord := env.newCoord()

	// 1. Clean empty startup
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover on clean empty state failed: %v", err)
	}
	if env.pub.GetServingState() != nil {
		t.Fatal("expected nil serving state for empty output log")
	}

	// 2. Ingest & publish batch of 50 leaves
	res1, err := env.indexer.IndexMappedBatch(ctx, makeMappedBatch(env.fetcher.leaves, 0, 50), nil, 0)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	root50 := testBatchRoot(env.fetcher.leaves[:50])
	inputCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: root50[:]}
	state1, err := env.pub.PublishKeyBatch(ctx, res1.ModifiedKeyValueRoots, inputCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	// 3. Simulate crash where Pebble indexed [50, 100) ahead of Output Log tip (50):
	// Recover promotes 50 immediately with nil Fetcher/WASMHost, then SyncOnce publishes 200 without duplicate offsets.
	if _, err := env.indexer.IndexMappedBatch(ctx, makeMappedBatch(env.fetcher.leaves, 50, 100), nil, 0); err != nil {
		t.Fatalf("IndexBatch [50,100) failed: %v", err)
	}

	newPub := tree.NewOutputPublisher(env.mpt, env.outLog)
	warmCoord := env.newCoord(func(c *Config) {
		c.Publisher = newPub
		c.Fetcher = nil
		c.WASMHost = nil
	})
	if err := warmCoord.Recover(ctx); err != nil {
		t.Fatalf("warm-start Recover failed: %v", err)
	}
	restored := newPub.GetServingState()
	if restored == nil || restored.InputLogSize != 50 || restored.MPTRoot != state1.MPTRoot {
		t.Fatalf("restored ServingState = %+v, want size 50 root %x", restored, state1.MPTRoot)
	}

	fullCoord := env.newCoord(func(c *Config) { c.Publisher = newPub })
	if err := fullCoord.SyncOnce(ctx); err != nil {
		t.Fatalf("forward SyncOnce after KV-ahead crash failed: %v", err)
	}
	if s := newPub.GetServingState(); s == nil || s.InputLogSize != 200 {
		t.Fatalf("ServingState after forward SyncOnce = %+v, want size 200", s)
	}
	keyHash := sha256.Sum256([]byte("leaf_recovery_75"))
	before := uint64(200)
	lr, err := env.db.Lookup(keyHash, &before, 10, 200)
	if err != nil || !slices.Equal(lr.MatchedIndices, []uint64{75}) {
		t.Fatalf("Lookup(leaf_recovery_75) = %+v, err=%v, want [75]", lr, err)
	}

	// 4. Regression guard: if m_kv_size lags OutputLog tip (e.g. wiped DB), warm-start MUST reject.
	_ = env.db.SetUint64(kvstore.KeyMetaKVSize, 10)
	badCoord := env.newCoord(func(c *Config) {
		c.Publisher = tree.NewOutputPublisher(env.mpt, env.outLog)
	})
	if err := badCoord.Recover(ctx); !errors.Is(err, errInvariantViolation) {
		t.Fatalf("expected errInvariantViolation when kvSize < tip InputLogSize, got: %v", err)
	}
}

func TestRecovery_LaggingDirtyAndSuffixMPTReplay(t *testing.T) {
	ctx := context.Background()

	t.Run("lagging_mpt_with_from_skips_pre_from_tiles", func(t *testing.T) {
		env := newTestEnv(t)
		env.pub.SetFrom(32)

		res1, err := env.indexer.IndexMappedBatch(ctx, makeMappedBatch(env.fetcher.leaves, 32, 64), nil, 0)
		if err != nil {
			t.Fatalf("IndexBatch 1 failed: %v", err)
		}
		r64 := testBatchRoot(env.fetcher.leaves[:64])
		if _, err := env.pub.PublishKeyBatch(ctx, res1.ModifiedKeyValueRoots, &log.Checkpoint{Origin: "example.com/inputlog", Size: 64, Hash: r64[:]}); err != nil {
			t.Fatalf("PublishKeyBatch 1 failed: %v", err)
		}

		// Reset MPT to empty (lagging at 0) while Output Log is at 64 with from=32.
		env.mpt = mpt.NewMem()
		env.pub = tree.NewOutputPublisher(env.mpt, env.outLog)
		env.fetcher.minLeafRead = nil
		coord := env.newCoord()
		if err := coord.Recover(ctx); err != nil {
			t.Fatalf("Recover failed during suffix replay: %v", err)
		}
		if env.fetcher.minLeafRead == nil || *env.fetcher.minLeafRead < 32 {
			t.Fatalf("expected zero pre-from tile reads (< 32), got minLeafRead=%v", env.fetcher.minLeafRead)
		}
	})

	t.Run("dirty_mpt_at_equal_size_replays_cleanly", func(t *testing.T) {
		skipIfRaceDarwin(t)
		env := newTestEnv(t)
		mptDir := t.TempDir()
		mptMgr, err := mpt.Open(mptDir)
		if err != nil {
			t.Fatalf("mpt.Open failed: %v", err)
		}

		res, err := env.indexer.IndexMappedBatch(ctx, makeMappedBatch(env.fetcher.leaves, 0, 50), nil, 0)
		if err != nil {
			t.Fatalf("IndexBatch failed: %v", err)
		}
		pub := tree.NewOutputPublisher(mptMgr, env.outLog)
		inRoot := testBatchRoot(env.fetcher.leaves[:50])
		inputCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: inRoot[:]}
		expectedState, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inputCP)
		if err != nil {
			t.Fatalf("PublishKeyBatch failed: %v", err)
		}

		if err := mptMgr.SetKeyBatch(map[string][32]byte{"leaf_recovery_0": sha256.Sum256([]byte("dirty"))}); err != nil {
			t.Fatalf("SetKeyBatch failed: %v", err)
		}
		_ = mptMgr.Close()

		reopenedMPT, err := mpt.Open(mptDir)
		if err != nil {
			t.Fatalf("Reopen failed: %v", err)
		}
		defer func() { _ = reopenedMPT.Close() }()
		if reopenedMPT.IsExact() {
			t.Fatal("expected reopenedMPT.IsExact() == false")
		}

		env.mpt = reopenedMPT
		env.pub = tree.NewOutputPublisher(reopenedMPT, env.outLog)
		if err := env.newCoord().Recover(ctx); err != nil {
			t.Fatalf("Recover failed on dirty MPT at equal size: %v", err)
		}
		if !reopenedMPT.IsExact() || reopenedMPT.Root() != expectedState.MPTRoot {
			t.Fatalf("reopenedMPT exact=%v root=%x, want true and %x", reopenedMPT.IsExact(), reopenedMPT.Root(), expectedState.MPTRoot)
		}
	})
}

func TestRecovery_InvariantViolationsAndCorruptedLeaves(t *testing.T) {
	ctx := context.Background()
	inCP50 := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: make([]byte, 32)}

	for _, tc := range []struct {
		name    string
		setup   func(*testEnv)
		wantErr error
	}{
		{
			name: "mpt_persisted_greater_than_kv_size",
			setup: func(e *testEnv) {
				_ = e.db.SetUint64(kvstore.KeyMetaKVSize, 100)
				_, _ = e.mpt.Snap(150)
				_ = e.mpt.Persist()
			},
			wantErr: errInvariantViolation,
		},
		{
			name: "mpt_persisted_greater_than_output_log_tip",
			setup: func(e *testEnv) {
				_, _, _ = e.outLog.Append(ctx, wire.FormatOutputLogLeafFull(sha256.Sum256([]byte("r")), 0, inCP50))
				_ = e.db.SetUint64(kvstore.KeyMetaKVSize, 100)
				_, _ = e.mpt.Snap(75)
				_ = e.mpt.Persist()
			},
			wantErr: errInvariantViolation,
		},
		{
			name: "mpt_root_mismatch_at_equal_size",
			setup: func(e *testEnv) {
				_, _, _ = e.outLog.Append(ctx, wire.FormatOutputLogLeafFull(sha256.Sum256([]byte("expected_tip_root")), 0, inCP50))
				_ = e.db.SetUint64(kvstore.KeyMetaKVSize, 50)
				_, _ = e.mpt.CommitKeysWithVersion(map[string][32]byte{"com.example.k1": sha256.Sum256([]byte("v1"))}, 50)
				_ = e.mpt.Persist()
			},
			wantErr: errRootMismatch,
		},
		{
			name: "replayed_root_mismatch_against_tip",
			setup: func(e *testEnv) {
				_, _, _ = e.outLog.Append(ctx, wire.FormatOutputLogLeafFull(sha256.Sum256([]byte("fraudulent_root")), 0, inCP50))
				_, _ = e.indexer.IndexMappedBatch(ctx, makeMappedBatch(e.fetcher.leaves, 0, 50), nil, 0)
			},
			wantErr: errRootMismatch,
		},
		{
			name: "corrupted_output_log_inclusion_proof",
			setup: func(e *testEnv) {
				res, _ := e.indexer.IndexMappedBatch(ctx, makeMappedBatch(e.fetcher.leaves, 0, 50), nil, 0)
				root, _ := e.mpt.CommitKeysWithVersion(res.ModifiedKeyValueRoots, 50)
				_ = e.mpt.Persist()
				_, _, _ = e.outLog.Append(ctx, wire.FormatOutputLogLeafFull(root, 0, inCP50))
				e.outLog.corruptProof = true
			},
			wantErr: errInvariantViolation,
		},
		{
			name: "corrupted_output_log_leaf_one_line",
			setup: func(e *testEnv) {
				_, _, _ = e.outLog.Append(ctx, []byte("only_one_line_here"))
			},
			wantErr: wire.ErrOutputLogCorrupted,
		},
		{
			name: "corrupted_output_log_leaf_bad_header",
			setup: func(e *testEnv) {
				_, _, _ = e.outLog.Append(ctx, []byte("c2sp.org/tlog-vindex-state@v1\nmpt-root zzzz\n"))
			},
			wantErr: wire.ErrOutputLogCorrupted,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			tc.setup(env)
			if err := env.newCoord().Recover(ctx); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Recover() err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

type partialRejectingReader struct {
	bundleBytes []byte
	tileBytes   []byte
}

func (r *partialRejectingReader) ReadCheckpoint(_ context.Context) ([]byte, error) { return nil, nil }
func (r *partialRejectingReader) ReadTile(_ context.Context, _, _ uint64, p uint8) ([]byte, error) {
	if p != 50 {
		return nil, fmt.Errorf("unexpected tile p=%d, want 50", p)
	}
	return r.tileBytes, nil
}
func (r *partialRejectingReader) ReadEntryBundle(_ context.Context, _ uint64, p uint8) ([]byte, error) {
	if p != 50 {
		return nil, fmt.Errorf("unexpected bundle p=%d, want 50", p)
	}
	return r.bundleBytes, nil
}

func TestRecover_PartialTileFetch(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)

	var bundle api.EntryBundle
	leaves := makeTestLeaves("leaf_partial_", 50)
	bundle.Entries = append(bundle.Entries, leaves...)
	res, err := env.indexer.IndexMappedBatch(ctx, makeMappedBatch(leaves, 0, 50), nil, 0)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	var bundleBytes, tileBytes []byte
	for _, leaf := range bundle.Entries {
		bundleBytes = binary.BigEndian.AppendUint16(bundleBytes, uint16(len(leaf)))
		bundleBytes = append(bundleBytes, leaf...)
		h := tlog.RecordHash(leaf)
		tileBytes = append(tileBytes, h[:]...)
	}

	predictedRoot, err := env.mpt.PredictKeys(res.ModifiedKeyValueRoots)
	if err != nil {
		t.Fatalf("PredictKeys failed: %v", err)
	}
	inRoot := testBatchRoot(bundle.Entries)
	inCP := &log.Checkpoint{Origin: "example.com/inputlog", Size: 50, Hash: inRoot[:]}
	_, _, _ = env.outLog.Append(ctx, wire.FormatOutputLogLeafFull(predictedRoot, 0, inCP))

	fetcher := ingest.NewTiledFetcherWithReader(&partialRejectingReader{bundleBytes: bundleBytes, tileBytes: tileBytes}, nil, "example.com/inputlog")
	coord := env.newCoord(func(c *Config) { c.Fetcher = fetcher })
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover failed during partial tile fetch: %v", err)
	}
	if state := env.pub.GetServingState(); state == nil || state.MPTRoot != predictedRoot {
		t.Fatalf("ServingState = %+v, want root %x", state, predictedRoot)
	}
}

func snapshotDirFiles(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s) failed: %v", dir, err)
	}
	out := make(map[string]int64, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info(%s) failed: %v", e.Name(), err)
		}
		out[e.Name()] = info.Size()
	}
	return out
}

func TestGenesisBackfill_BootstrapCoarseCheckpointAndDirtyCrashReplay(t *testing.T) {
	skipIfRaceDarwin(t)
	ctx := context.Background()
	const (
		totalLeaves      = 3000
		coarseCheckpoint = 1024
		crashLeaf        = 2000
	)

	leaves := makeTestLeaves("genesis_leaf_", totalLeaves)
	host := wasmhosttest.Host()

	// Reference clean run -> Leaf 0 -> Normal Serving Mode Leaf 1
	envRef := newTestEnv(t)
	envRef.fetcher = &memoryTileFetcher{leaves: slices.Clone(leaves), origin: "example.com/inputlog"}
	coordRef := envRef.newCoord(func(c *Config) {
		c.CommitBatchSize = 512
		c.CoarseCheckpointInterval = coarseCheckpoint
	})
	if err := coordRef.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce (Genesis Backfill) failed: %v", err)
	}
	refState := envRef.pub.GetServingState()
	if refState == nil || refState.OutputLogIndex != 0 || refState.InputLogSize != totalLeaves {
		t.Fatalf("refState = %+v, want OutputLogIndex=0 InputLogSize=%d", refState, totalLeaves)
	}

	// Append 200 more leaves and verify transition to Normal Serving Mode (Leaf 1)
	envRef.fetcher.mu.Lock()
	for i := totalLeaves; i < totalLeaves+200; i++ {
		envRef.fetcher.leaves = append(envRef.fetcher.leaves, fmt.Appendf(nil, "genesis_leaf_%d", i))
	}
	envRef.fetcher.mu.Unlock()
	if err := coordRef.SyncOnce(ctx); err != nil {
		t.Fatalf("second SyncOnce (Normal Serving Mode) failed: %v", err)
	}
	if len(envRef.outLog.leaves) != 2 {
		t.Fatalf("outLogRef size = %d, want 2", len(envRef.outLog.leaves))
	}

	// Dirty Crash Run: coarse checkpoint at 1024, crash at 2000 before MPT Snap, reopen, verify zero Pebble writes on Recover(), finish to 3000
	crashDir := t.TempDir()
	dbDir := filepath.Join(crashDir, "db")
	mptDir := filepath.Join(crashDir, "mpt")
	fetcherCrash := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	targetCP, _ := fetcherCrash.Checkpoint(ctx)

	{
		db, err := kvstore.Open(dbDir, &kvstore.Options{CacheSizeMB: 8, ChunkSize: 64})
		if err != nil {
			t.Fatalf("Open db failed: %v", err)
		}
		_ = db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw)
		_ = db.SetUint64(keyMetaCoordinatorFrom, 0)
		mptMgr, err := mpt.Open(mptDir)
		if err != nil {
			t.Fatalf("Open mpt failed: %v", err)
		}
		idx := kvstore.NewKVIndexer(db)

		res1, err := idx.IndexMappedBatch(ctx, makeMappedBatch(leaves, 0, coarseCheckpoint), targetCP.Raw, targetCP.Size)
		if err != nil {
			t.Fatalf("IndexBatch 1 failed: %v", err)
		}
		_ = mptMgr.SetKeyBatch(res1.ModifiedKeyValueRoots)
		_ = db.Sync()
		_, _ = mptMgr.Snap(coarseCheckpoint)
		_ = mptMgr.Persist()

		res2, err := idx.IndexMappedBatch(ctx, makeMappedBatch(leaves, coarseCheckpoint, crashLeaf), targetCP.Raw, targetCP.Size)
		if err != nil {
			t.Fatalf("IndexBatch 2 failed: %v", err)
		}
		_ = mptMgr.SetKeyBatch(res2.ModifiedKeyValueRoots)
		_ = db.Sync()
		_ = mptMgr.Close()
		_ = db.Close()
	}

	dbB, err := kvstore.Open(dbDir, &kvstore.Options{CacheSizeMB: 8, ChunkSize: 64})
	if err != nil {
		t.Fatalf("Reopen dbB failed: %v", err)
	}
	t.Cleanup(func() { _ = dbB.Close() })
	mptB, err := mpt.Open(mptDir)
	if err != nil {
		t.Fatalf("Reopen mptB failed: %v", err)
	}
	t.Cleanup(func() { _ = mptB.Close() })

	// Verify mid-backfill --from drift is caught by Recover().
	driftPub := tree.NewOutputPublisher(mptB, newMemoryOutputLog("example.com/outputlog"))
	driftPub.SetFrom(50)
	driftCoord := New(Config{
		DB:           dbB,
		MPT:          mptB,
		OutputLog:    newMemoryOutputLog("example.com/outputlog"),
		Publisher:    driftPub,
		Indexer:      kvstore.NewKVIndexer(dbB),
		ExplicitFrom: true,
	})
	if err := driftCoord.Recover(ctx); !errors.Is(err, errInvariantViolation) {
		t.Fatalf("expected errInvariantViolation on mid-backfill from change, got: %v", err)
	}

	filesBefore := snapshotDirFiles(t, dbDir)

	outLogB := newMemoryOutputLog("example.com/outputlog")
	pubB := tree.NewOutputPublisher(mptB, outLogB)
	idxB := kvstore.NewKVIndexer(dbB)
	coordB := New(Config{
		DB:                       dbB,
		MPT:                      mptB,
		OutputLog:                outLogB,
		Publisher:                pubB,
		Indexer:                  idxB,
		Fetcher:                  fetcherCrash,
		WASMHost:                 host,
		CommitBatchSize:          512,
		CoarseCheckpointInterval: coarseCheckpoint,
	})

	if sw, _ := coordB.SafeWatermark(ctx); sw != coarseCheckpoint {
		t.Fatalf("SafeWatermark before recovery = %d, want %d", sw, coarseCheckpoint)
	}
	if err := coordB.Recover(ctx); err != nil {
		t.Fatalf("Recover() failed: %v", err)
	}
	if mptB.PersistedSize() != crashLeaf {
		t.Fatalf("mptB.PersistedSize() after recovery = %d, want %d", mptB.PersistedSize(), crashLeaf)
	}

	filesAfter := snapshotDirFiles(t, dbDir)
	for name, szAfter := range filesAfter {
		szBefore, existed := filesBefore[name]
		if !existed {
			t.Fatalf("new Pebble file %s (%d bytes) created during Recover()", name, szAfter)
		}
		if szAfter > szBefore {
			t.Fatalf("Pebble file %s grew during Recover(): before=%d, after=%d", name, szBefore, szAfter)
		}
	}

	// Resume Genesis Backfill to 3000 leaves and verify byte-for-byte identical MPTRoot to clean Run Ref
	if err := coordB.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce resume failed: %v", err)
	}
	stateB := pubB.GetServingState()
	if stateB == nil || stateB.MPTRoot != refState.MPTRoot {
		t.Fatalf("recovered final MPTRoot %x != clean reference MPTRoot %x", stateB.MPTRoot, refState.MPTRoot)
	}
}
