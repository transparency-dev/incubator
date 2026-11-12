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

// Package coordinator implements crash recovery, startup coordination, and ingestion pipeline orchestration.
package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var (
	errInvariantViolation  = errors.New("state progression invariant violation")
	errCheckpointRegressed = errors.New("input log checkpoint regressed")
	errRootMismatch        = fmt.Errorf("%w: MPT root does not match Output Log commitment", errInvariantViolation)

	keyMetaCoordinatorFrom = []byte("m_coord_from")
	metaCheckpointKeys     = [2][]byte{kvstore.KeyMetaKVCheckpoint, kvstore.KeyMetaTargetCheckpoint}
)

func inputCheckpointMetaKey(outLeafIdx uint64) []byte {
	var key [len("m_in_cp:") + 8]byte
	copy(key[:], "m_in_cp:")
	binary.BigEndian.PutUint64(key[len("m_in_cp:"):], outLeafIdx)
	return key[:]
}

type outputLogReader interface {
	tree.OutputLogClient
	GetLeaf(ctx context.Context, idx uint64) ([]byte, error)
	Checkpoint(ctx context.Context) ([]byte, error)
}

type consistencyProver interface {
	ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error)
}

const (
	defaultCommitBatchSize          uint64 = 4096
	defaultCoarseCheckpointInterval uint64 = 50_000_000
	defaultBackfillMaxPendingKeys   uint64 = 50_000_000
)

// Config configures a Coordinator instance.
type Config struct {
	DB                       *kvstore.DB
	MPT                      *mpt.Manager
	OutputLog                outputLogReader
	Publisher                *tree.OutputPublisher
	Indexer                  *kvstore.KVIndexer
	Fetcher                  ingest.TileFetcher
	Cache                    ingest.TileCache
	WASMHost                 *wasmhost.WASMHost
	CommitBatchSize          uint64
	CoarseCheckpointInterval uint64
	BackfillMaxPendingKeys   uint64
	Workers                  int
	FetchWorkers             int
	FetchBatchBundles        int
	ExplicitFrom             bool
}

// Coordinator manages startup crash recovery and incremental synchronization.
type Coordinator struct {
	db                       *kvstore.DB
	mptMgr                   *mpt.Manager
	outputLog                outputLogReader
	pub                      *tree.OutputPublisher
	indexer                  *kvstore.KVIndexer
	fetcher                  ingest.TileFetcher
	pipeline                 *ingest.IngestionPipeline
	commitBatchSize          uint64
	coarseCheckpointInterval uint64
	backfillMaxPendingKeys   uint64
	explicitFrom             bool

	syncMu         sync.Mutex
	fatalErr       atomic.Pointer[error]
	knownOutServed atomic.Bool
	replayActive   atomic.Bool
	replayCurrent  atomic.Uint64
}

// New creates a new Coordinator from cfg.
func New(cfg Config) *Coordinator {
	if cfg.CommitBatchSize == 0 {
		cfg.CommitBatchSize = defaultCommitBatchSize
	}
	if cfg.CoarseCheckpointInterval == 0 {
		cfg.CoarseCheckpointInterval = defaultCoarseCheckpointInterval
	}
	if cfg.BackfillMaxPendingKeys == 0 {
		cfg.BackfillMaxPendingKeys = defaultBackfillMaxPendingKeys
	}
	var pipeline *ingest.IngestionPipeline
	if cfg.Fetcher != nil && cfg.WASMHost != nil {
		pipeline = ingest.NewPipeline(cfg.Fetcher, cfg.Cache, cfg.WASMHost, cfg.Workers)
		if cfg.FetchWorkers > 0 {
			pipeline.SetFetchWorkers(cfg.FetchWorkers)
		}
		if cfg.FetchBatchBundles > 0 {
			pipeline.SetFetchBatchBundles(cfg.FetchBatchBundles)
		}
	}
	return &Coordinator{
		db:                       cfg.DB,
		mptMgr:                   cfg.MPT,
		outputLog:                cfg.OutputLog,
		pub:                      cfg.Publisher,
		indexer:                  cfg.Indexer,
		fetcher:                  cfg.Fetcher,
		pipeline:                 pipeline,
		commitBatchSize:          cfg.CommitBatchSize,
		coarseCheckpointInterval: cfg.CoarseCheckpointInterval,
		backfillMaxPendingKeys:   cfg.BackfillMaxPendingKeys,
		explicitFrom:             cfg.ExplicitFrom,
	}
}

func (c *Coordinator) readMetaCheckpoint(key []byte) (*log.Checkpoint, []byte, error) {
	rawCP, err := c.db.GetMetadata(key)
	if err != nil || len(rawCP) == 0 {
		return nil, nil, err
	}
	cp, pErr := wire.ParseCheckpointHeader(rawCP)
	if pErr != nil {
		return nil, rawCP, pErr
	}
	return cp, rawCP, nil
}

// SafeWatermark returns max(min(m_kv_size, MPT.PersistedSize()), from).
func (c *Coordinator) SafeWatermark(_ context.Context) (uint64, error) {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	return max(min(kvSize, c.mptMgr.PersistedSize()), c.pub.From()), nil
}

type readinessStatusError struct {
	Status          string
	GenesisBackfill bool
	LeavesIndexed   uint64
	TargetLeaves    uint64
}

func (e *readinessStatusError) Error() string {
	return fmt.Sprintf("status=%s genesis_backfill=%v leaves_indexed=%d target_leaves=%d",
		e.Status, e.GenesisBackfill, e.LeavesIndexed, e.TargetLeaves)
}

func (e *readinessStatusError) JSONDiagnostics() []byte {
	return fmt.Appendf(nil, "{\"status\":%q,\"genesis_backfill\":%t,\"leaves_indexed\":%d,\"target_leaves\":%d}\n",
		e.Status, e.GenesisBackfill, e.LeavesIndexed, e.TargetLeaves)
}

type readinessHaltedError struct {
	Err string
}

func (e *readinessHaltedError) Error() string {
	return "halted: " + e.Err
}

func (e *readinessHaltedError) JSONDiagnostics() []byte {
	b, _ := json.Marshal(struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}{Status: "halted", Error: e.Err})
	return append(b, '\n')
}

// ReadinessCheck evaluates whether the coordinator has promoted a valid ServingState and has not fatally halted.
func (c *Coordinator) ReadinessCheck() error {
	if fErr := c.fatalErr.Load(); fErr != nil && *fErr != nil {
		return &readinessHaltedError{Err: (*fErr).Error()}
	}
	if state := c.pub.GetServingState(); state != nil && len(state.RawCheckpoint) > 0 {
		return nil
	}

	kvSize, _ := c.db.GetUint64(kvstore.KeyMetaKVSize)
	var targetLeaves uint64
	for _, metaKey := range [2][]byte{kvstore.KeyMetaTargetCheckpoint, kvstore.KeyMetaKVCheckpoint} {
		if cp, _, err := c.readMetaCheckpoint(metaKey); err == nil && cp != nil && cp.Size > 0 {
			targetLeaves = cp.Size
			break
		}
	}
	leavesIndexed := kvSize
	if c.replayActive.Load() {
		leavesIndexed = c.replayCurrent.Load()
	}
	if targetLeaves == 0 {
		targetLeaves = kvSize
	}

	isServed := c.knownOutServed.Load()
	if !isServed {
		if rawCP, err := c.outputLog.Checkpoint(context.Background()); err != nil {
			// Output Log read error during probe: report "recovering" rather than falsely claiming genesis_backfill.
			isServed = true
		} else if len(rawCP) > 0 {
			if cp, pErr := wire.ParseCheckpointHeader(rawCP); pErr != nil || cp.Size > 0 {
				isServed = true
			}
		}
	}
	status := "genesis_backfill"
	if isServed {
		status = "recovering"
	}
	return &readinessStatusError{
		Status:          status,
		GenesisBackfill: !isServed,
		LeavesIndexed:   leavesIndexed,
		TargetLeaves:    targetLeaves,
	}
}

func (c *Coordinator) setFetcherTreeState(size uint64, hash [sha256.Size]byte) {
	if stater, ok := c.fetcher.(interface{ SetTreeState(uint64, [32]byte) }); ok {
		stater.SetTreeState(size, hash)
	}
}

func (c *Coordinator) readVerifiedOutputCheckpoint(ctx context.Context) ([]byte, *log.Checkpoint, error) {
	if quiescer, ok := c.outputLog.(interface{ AwaitQuiescent(context.Context) error }); ok {
		if err := quiescer.AwaitQuiescent(ctx); err != nil {
			return nil, nil, err
		}
	}
	rawOutCP, err := c.outputLog.Checkpoint(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch output log checkpoint: %w", err)
	}
	if len(rawOutCP) == 0 {
		return nil, nil, nil
	}
	outCP, err := c.pub.VerifyCheckpoint(rawOutCP)
	if err != nil {
		return nil, nil, err
	}
	emptyRoot := wire.EmptyRoot()
	if outCP.Size == 0 && !bytes.Equal(outCP.Hash, emptyRoot[:]) {
		return nil, nil, fmt.Errorf("%w: output log checkpoint size 0 has non-empty root %x", errInvariantViolation, outCP.Hash)
	}
	if outCP.Size > 0 {
		c.knownOutServed.Store(true)
	}
	return rawOutCP, outCP, nil
}

func (c *Coordinator) verifyPersistedFrom() error {
	raw, err := c.db.GetMetadata(keyMetaCoordinatorFrom)
	if err != nil {
		return fmt.Errorf("failed to read persisted from metadata: %w", err)
	}
	if len(raw) == 0 {
		return nil
	}
	persistedFrom, uErr := c.db.GetUint64(keyMetaCoordinatorFrom)
	if uErr != nil {
		return fmt.Errorf("failed to decode persisted from metadata: %w", uErr)
	}
	from := c.pub.From()
	if (c.explicitFrom || from != 0) && from != persistedFrom {
		return fmt.Errorf("%w: configured from (%d) != persisted from (%d)", errInvariantViolation, from, persistedFrom)
	}
	if from == 0 && !c.explicitFrom && persistedFrom != 0 {
		c.pub.SetFrom(persistedFrom)
	}
	return nil
}

func (c *Coordinator) persistFromIfAbsent(from uint64) error {
	raw, err := c.db.GetMetadata(keyMetaCoordinatorFrom)
	if err != nil {
		return fmt.Errorf("failed to read persisted from metadata: %w", err)
	}
	if len(raw) > 0 {
		return nil
	}
	return c.db.SetUint64(keyMetaCoordinatorFrom, from)
}

func (c *Coordinator) reconcileInputOrigin(origin, label string) error {
	if origin == "" {
		return nil
	}
	if cur := c.pub.InputOrigin(); cur != "" && cur != origin {
		return fmt.Errorf("%w: configured input-origin %q != %s %q", errInvariantViolation, cur, label, origin)
	}
	if c.pub.InputOrigin() == "" {
		c.pub.SetInputOrigin(origin)
	}
	return nil
}

func (c *Coordinator) recoverGenesisMPT(ctx context.Context, treeSize uint64, treeHash [sha256.Size]byte) (uint64, error) {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	metrics.KVCommittedSize.Set(float64(kvSize))
	mptPersistedSize := c.mptMgr.PersistedSize()
	if mptPersistedSize > kvSize {
		return 0, fmt.Errorf("%w: MPT durable size (%d) > m_kv_size (%d)", errInvariantViolation, mptPersistedSize, kvSize)
	}
	if mptPersistedSize < kvSize || !c.mptMgr.IsExact() {
		if treeSize == 0 {
			treeSize, treeHash = c.resolveReplayTreeState(ctx, kvSize)
		}
		if err := c.replayMPTToSize(ctx, mptPersistedSize, kvSize, treeSize, treeHash, c.pub.From(), nil, nil); err != nil {
			return 0, err
		}
	}
	return kvSize, nil
}

// Recover restores the MPT and ServingState after startup or an unclean shutdown.
func (c *Coordinator) Recover(ctx context.Context) error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	rawOutCP, outCP, err := c.readVerifiedOutputCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to read verified output log checkpoint: %w", err)
	}
	return c.recoverLocked(ctx, rawOutCP, outCP)
}

func (c *Coordinator) recoverLocked(ctx context.Context, rawOutCP []byte, outCP *log.Checkpoint) error {
	if outCP == nil || outCP.Size == 0 {
		if state := c.pub.GetServingState(); state != nil {
			return fmt.Errorf("%w: output log wiped (size 0) while serving index %d", errInvariantViolation, state.OutputLogIndex)
		}
		if err := c.verifyPersistedFrom(); err != nil {
			return err
		}
		_, err := c.recoverGenesisMPT(ctx, 0, [sha256.Size]byte{})
		return err
	}

	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	metrics.KVCommittedSize.Set(float64(kvSize))
	mptPersistedSize := c.mptMgr.PersistedSize()
	if mptPersistedSize > kvSize {
		return fmt.Errorf("%w: MPT durable size (%d) > m_kv_size (%d)", errInvariantViolation, mptPersistedSize, kvSize)
	}

	tipIdx := outCP.Size - 1
	tipLeafData, err := c.outputLog.GetLeaf(ctx, tipIdx)
	if err != nil {
		return fmt.Errorf("failed to get tip leaf %d: %w", tipIdx, err)
	}
	proofHashes, err := c.outputLog.InclusionProof(ctx, tipIdx, outCP.Size)
	if err != nil {
		return fmt.Errorf("failed to generate inclusion proof for tip leaf %d: %w", tipIdx, err)
	}
	proofBytes := make([][]byte, len(proofHashes))
	for i := range proofHashes {
		proofBytes[i] = proofHashes[i][:]
	}
	leafHash := wire.LeafHash(tipLeafData)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, tipIdx, outCP.Size, leafHash[:], proofBytes, outCP.Hash); err != nil {
		return fmt.Errorf("%w: output log tip leaf %d failed inclusion verification against checkpoint root: %v", errInvariantViolation, tipIdx, err)
	}

	tipLeaf, err := wire.ParseOutputLogLeafFull(tipLeafData)
	if err != nil {
		return fmt.Errorf("failed to parse tip leaf %d: %w", tipIdx, err)
	}
	if err := c.reconcilePublisherMetadata(tipLeaf); err != nil {
		return err
	}

	targetInputSize := tipLeaf.InCP.Size
	if kvSize < targetInputSize {
		return fmt.Errorf("%w: m_kv_size (%d) < OutputLog tip size (%d)", errInvariantViolation, kvSize, targetInputSize)
	}
	if mptPersistedSize > targetInputSize {
		return fmt.Errorf("%w: MPT durable size (%d) > OutputLog tip size (%d)", errInvariantViolation, mptPersistedSize, targetInputSize)
	}

	promoteServing := func() {
		c.pub.SetServingState(&tree.ServingState{
			OutputLogIndex: tipIdx,
			RawCheckpoint:  bytes.Clone(rawOutCP),
			OutputLogProof: proofHashes,
			InputLogCP:     tipLeaf.InCP,
			InputLogSize:   tipLeaf.InCP.Size,
			MPTRoot:        tipLeaf.MPTRoot,
			From:           tipLeaf.From,
		})
		if kvSize >= tipLeaf.InCP.Size {
			metrics.IndexingLag.Set(float64(kvSize - tipLeaf.InCP.Size))
		}
	}

	if mptPersistedSize == targetInputSize && c.mptMgr.IsExact() {
		if c.mptMgr.Root() != tipLeaf.MPTRoot {
			return fmt.Errorf("%w: MPT root mismatch at size %d: MPT %x, want tip %x", errRootMismatch, targetInputSize, c.mptMgr.Root(), tipLeaf.MPTRoot)
		}
		promoteServing()
		return nil
	}

	var tipHash [sha256.Size]byte
	if len(tipLeaf.InCP.Hash) == sha256.Size {
		tipHash = [sha256.Size]byte(tipLeaf.InCP.Hash)
	}
	minStart := max(c.pub.From(), tipLeaf.From)
	return c.replayMPTToSize(ctx, mptPersistedSize, targetInputSize, targetInputSize, tipHash, minStart, &tipLeaf.MPTRoot, promoteServing)
}

func (c *Coordinator) resolveReplayTreeState(ctx context.Context, minSize uint64) (uint64, [sha256.Size]byte) {
	for _, metaKey := range metaCheckpointKeys {
		if cp, _, err := c.readMetaCheckpoint(metaKey); err == nil && cp != nil && cp.Size >= minSize && len(cp.Hash) == sha256.Size {
			return cp.Size, [sha256.Size]byte(cp.Hash)
		}
	}
	if c.fetcher != nil {
		if cp, err := c.fetcher.Checkpoint(ctx); err == nil && cp != nil && cp.Size >= minSize {
			return cp.Size, cp.Hash
		}
	}
	return minSize, [sha256.Size]byte{}
}

func (c *Coordinator) replayMPTToSize(
	ctx context.Context,
	mptPersistedSize, targetSize, treeSize uint64,
	treeHash [sha256.Size]byte,
	minStart uint64,
	wantRoot *[sha256.Size]byte,
	onPromoted func(),
) error {
	replayStart := mptPersistedSize
	if replayStart == targetSize && !c.mptMgr.IsExact() {
		replayStart = 0
	}
	if replayStart < minStart {
		replayStart = minStart
	}
	klog.Infof("Replaying MPT leaves [%d..%d) from WASM with zero Pebble writes (MPT durable=%d, exact=%v)...",
		replayStart, targetSize, mptPersistedSize, c.mptMgr.IsExact())

	var mutations map[string][sha256.Size]byte
	if replayStart < targetSize {
		if c.pipeline == nil {
			return errors.New("cannot replay MPT: pipeline not initialized")
		}
		c.setFetcherTreeState(treeSize, treeHash)
		c.replayCurrent.Store(replayStart)
		c.replayActive.Store(true)
		defer c.replayActive.Store(false)

		batchChan, errChan := c.pipeline.StreamBatches(ctx, replayStart, targetSize)
		modifiedSet := make(map[string]struct{})
		replayedLeaves := replayStart
		for batch := range batchChan {
			for k := range batch.KeyIndices {
				modifiedSet[k] = struct{}{}
			}
			replayedLeaves += uint64(batch.Count)
			c.replayCurrent.Store(replayedLeaves)
		}
		if err := <-errChan; err != nil {
			return fmt.Errorf("stream batches failed during recovery replay: %w", err)
		}

		modifiedKeys := slices.AppendSeq(make([]string, 0, len(modifiedSet)), maps.Keys(modifiedSet))
		clear(modifiedSet)
		var err error
		mutations, err = c.indexer.GetKeyValueRoots(ctx, modifiedKeys, targetSize)
		if err != nil {
			return fmt.Errorf("failed to extract value roots during replay: %w", err)
		}
	}

	batch, err := mpt.PrepareBatch(mutations)
	if err != nil {
		return err
	}
	if wantRoot != nil && c.mptMgr.IsExact() {
		predRoot, pErr := c.mptMgr.PredictBatch(batch)
		if pErr != nil {
			return fmt.Errorf("mptMgr.PredictBatch failed during replay: %w", pErr)
		}
		if predRoot != *wantRoot {
			return fmt.Errorf("%w: replay predicted root %x, want tip leaf root %x", errRootMismatch, predRoot, *wantRoot)
		}
	}

	if targetSize > math.MaxInt64 {
		return fmt.Errorf("%w: target size %d overflows int64 MPT version", errInvariantViolation, targetSize)
	}
	actualRoot, err := c.mptMgr.CommitBatchAndPersist(batch, int64(targetSize), func(committedRoot [sha256.Size]byte) {
		if onPromoted != nil && (wantRoot == nil || committedRoot == *wantRoot) {
			onPromoted()
		}
	})
	if err != nil {
		return fmt.Errorf("mptMgr.CommitBatchAndPersist failed during replay: %w", err)
	}
	if wantRoot != nil && actualRoot != *wantRoot {
		return fmt.Errorf("%w: replay reached root %x, want tip leaf root %x", errRootMismatch, actualRoot, *wantRoot)
	}
	klog.Infof("MPT replay completed at size %d (root: %x, %d modified keys)", targetSize, actualRoot, len(mutations))
	return nil
}

func (c *Coordinator) reconcilePublisherMetadata(tipLeaf *wire.OutputLogLeaf) error {
	if err := c.reconcileInputOrigin(tipLeaf.InputOrigin, "output log tip input-origin"); err != nil {
		return err
	}
	if err := c.verifyPersistedFrom(); err != nil {
		return err
	}
	if (c.explicitFrom || c.pub.From() != 0) && c.pub.From() != tipLeaf.From {
		return fmt.Errorf("%w: configured from (%d) != output log tip from (%d)", errInvariantViolation, c.pub.From(), tipLeaf.From)
	}
	if c.pub.From() == 0 && !c.explicitFrom && tipLeaf.From != 0 {
		c.pub.SetFrom(tipLeaf.From)
	}
	return nil
}

// SyncOnce fetches the latest checkpoint from the Input Log, verifies append-only consistency,
// indexes missing leaf batches, and publishes the resulting MPT state commitment to the Output Log.
func (c *Coordinator) SyncOnce(ctx context.Context) error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	if c.fetcher == nil {
		return nil
	}

	targetCP, err := c.fetcher.Checkpoint(ctx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return fmt.Errorf("ingestion fetch checkpoint error: %w", err)
	}
	if targetCP == nil {
		return nil
	}
	if targetCP.Size > math.MaxInt64 {
		return fmt.Errorf("%w: input log checkpoint size %d overflows int64 MPT version", errInvariantViolation, targetCP.Size)
	}
	if targetCP.Size == 0 && targetCP.Hash != wire.EmptyRoot() {
		return fmt.Errorf("%w: input log checkpoint size 0 has non-empty root %x", errInvariantViolation, targetCP.Hash)
	}
	if err := c.verifyPersistedFrom(); err != nil {
		return err
	}
	if targetCP.Size < c.pub.From() {
		return fmt.Errorf("input log checkpoint size (%d) is below configured start index from (%d)", targetCP.Size, c.pub.From())
	}
	if err := c.reconcileInputOrigin(targetCP.Origin, "checkpoint origin"); err != nil {
		return err
	}

	persistedTargetRaw, err := c.verifyInputCheckpointProgression(ctx, targetCP)
	if err != nil {
		return err
	}

	metrics.InputTreeSize.Set(float64(targetCP.Size))
	if kvSz, kErr := c.db.GetUint64(kvstore.KeyMetaKVSize); kErr == nil {
		metrics.KVCommittedSize.Set(float64(kvSz))
		if targetCP.Size >= kvSz {
			metrics.IngestionLag.Set(float64(targetCP.Size - kvSz))
		}
		if st := c.pub.GetServingState(); st != nil && kvSz >= st.InputLogSize {
			metrics.IndexingLag.Set(float64(kvSz - st.InputLogSize))
		}
	}
	if !bytes.Equal(persistedTargetRaw, targetCP.Raw) {
		if err := c.db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw); err != nil {
			return fmt.Errorf("failed to persist target checkpoint: %w", err)
		}
	}

	rawOutCP, outCP, err := c.readVerifiedOutputCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log checkpoint: %w", err)
	}

	state := c.pub.GetServingState()
	if outCP == nil || outCP.Size == 0 {
		if state != nil {
			return fmt.Errorf("%w: output log wiped (size 0) while serving index %d", errInvariantViolation, state.OutputLogIndex)
		}
		if err := c.persistFromIfAbsent(c.pub.From()); err != nil {
			return err
		}
		kvSize, err := c.recoverGenesisMPT(ctx, targetCP.Size, targetCP.Hash)
		if err != nil {
			return fmt.Errorf("genesis dirty crash recovery failed: %w", err)
		}
		startLogSize := max(min(kvSize, c.mptMgr.PersistedSize()), c.pub.From())
		return c.indexToTarget(ctx, startLogSize, targetCP, true)
	}

	if state != nil {
		if outCP.Size < state.OutputLogIndex+1 {
			return fmt.Errorf("%w: output log regressed from %d to %d", errInvariantViolation, state.OutputLogIndex+1, outCP.Size)
		}
		if prevOutCP, pErr := wire.ParseCheckpointHeader(state.RawCheckpoint); pErr == nil && outCP.Size == prevOutCP.Size && !bytes.Equal(outCP.Hash, prevOutCP.Hash) {
			return fmt.Errorf("%w: output log split-view at size %d", errInvariantViolation, outCP.Size)
		}
	}
	if state == nil || outCP.Size != state.OutputLogIndex+1 {
		if err := c.recoverLocked(ctx, rawOutCP, outCP); err != nil {
			return err
		}
		state = c.pub.GetServingState()
	}
	if err := c.persistFromIfAbsent(c.pub.From()); err != nil {
		return err
	}

	startLogSize := c.pub.From()
	if state != nil {
		startLogSize = max(state.InputLogSize, startLogSize)
	}
	if startLogSize >= targetCP.Size {
		return nil
	}
	return c.indexToTarget(ctx, startLogSize, targetCP, false)
}

func (c *Coordinator) verifyInputCheckpointProgression(ctx context.Context, targetCP *ingest.Checkpoint) ([]byte, error) {
	var candidates []*log.Checkpoint
	if state := c.pub.GetServingState(); state != nil && state.InputLogCP != nil {
		candidates = append(candidates, state.InputLogCP)
	}
	var persistedTargetRaw []byte
	for _, metaKey := range metaCheckpointKeys {
		cp, rawCP, err := c.readMetaCheckpoint(metaKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q checkpoint metadata: %w", metaKey, err)
		}
		if bytes.Equal(metaKey, kvstore.KeyMetaTargetCheckpoint) {
			persistedTargetRaw = rawCP
		}
		if cp != nil {
			candidates = append(candidates, cp)
		}
	}

	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	if targetCP.Size < kvSize {
		return nil, fmt.Errorf("%w: input log checkpoint size (%d) < m_kv_size (%d)", errCheckpointRegressed, targetCP.Size, kvSize)
	}

	var prevCP *log.Checkpoint
	for i, cp := range candidates {
		if cp.Origin != "" && targetCP.Origin != "" && cp.Origin != targetCP.Origin {
			return nil, fmt.Errorf("%w: persisted input log origin %q != checkpoint origin %q", errInvariantViolation, cp.Origin, targetCP.Origin)
		}
		for j := 0; j < i; j++ {
			other := candidates[j]
			if cp.Size == other.Size && len(cp.Hash) == sha256.Size && len(other.Hash) == sha256.Size && !bytes.Equal(cp.Hash, other.Hash) {
				return nil, fmt.Errorf("%w: persisted input log checkpoint split-view at size %d: %x != %x", errInvariantViolation, cp.Size, cp.Hash, other.Hash)
			}
		}
		if prevCP == nil || cp.Size > prevCP.Size || (cp.Size == prevCP.Size && len(prevCP.Hash) != sha256.Size && len(cp.Hash) == sha256.Size) {
			prevCP = cp
		}
	}

	if prevCP == nil {
		return persistedTargetRaw, nil
	}
	if targetCP.Size < prevCP.Size {
		return nil, fmt.Errorf("%w: input log checkpoint regressed from %d to %d", errCheckpointRegressed, prevCP.Size, targetCP.Size)
	}
	if targetCP.Size == prevCP.Size {
		if len(prevCP.Hash) == sha256.Size && !bytes.Equal(targetCP.Hash[:], prevCP.Hash) {
			return nil, fmt.Errorf("%w: input log split-view at size %d: got %x, want %x", errInvariantViolation, targetCP.Size, targetCP.Hash, prevCP.Hash)
		}
		return persistedTargetRaw, nil
	}
	if prevCP.Size > 0 && len(prevCP.Hash) == sha256.Size {
		prover, ok := c.fetcher.(consistencyProver)
		if !ok {
			return nil, fmt.Errorf("%w: input log fetcher does not support Merkle consistency proofs (%d -> %d)", errInvariantViolation, prevCP.Size, targetCP.Size)
		}
		cProof, err := prover.ConsistencyProof(ctx, prevCP.Size, targetCP.Size)
		if err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to fetch input log consistency proof (%d -> %d): %w", prevCP.Size, targetCP.Size, err)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, prevCP.Size, targetCP.Size, cProof, prevCP.Hash, targetCP.Hash[:]); err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("%w: input log consistency verification failed (%d -> %d): %v", errInvariantViolation, prevCP.Size, targetCP.Size, err)
		}
	}
	return persistedTargetRaw, nil
}

func (c *Coordinator) indexToTarget(ctx context.Context, startLogSize uint64, targetCP *ingest.Checkpoint, genesisBackfill bool) error {
	if startLogSize >= targetCP.Size {
		// Bootstrap at targetCP.Size == from (empty indexed range [from, from)): advance m_kv_size to targetCP.Size
		// before publishing Output Log Entry 0 so m_kv_size >= Output_CP.InputSize >= MPT_Durable_Size holds.
		if targetCP.Size > 0 {
			if kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize); err != nil {
				return err
			} else if kvSize < targetCP.Size {
				if err := c.db.SetUint64(kvstore.KeyMetaKVSize, targetCP.Size); err != nil {
					return fmt.Errorf("failed to advance m_kv_size at empty range: %w", err)
				}
				if len(targetCP.Raw) > 0 {
					if err := c.db.SetMetadata(kvstore.KeyMetaKVCheckpoint, targetCP.Raw); err != nil {
						return fmt.Errorf("failed to persist m_kv_cp at empty range: %w", err)
					}
				}
			}
		}
		if err := c.db.Sync(); err != nil {
			return fmt.Errorf("db.Sync error: %w", err)
		}
		return c.publishTargetState(ctx, targetCP, nil)
	}

	c.setFetcherTreeState(targetCP.Size, targetCP.Hash)

	lastCheckpointLeaf := c.mptMgr.PersistedSize()
	lastIndexedSize := startLogSize
	leavesSinceCheckpoint := uint64(0)
	flushFailed := false
	startTime := time.Now()
	lastLogSize := startLogSize
	const logInterval = uint64(100_000)

	modifiedValueRoots := make(map[string][sha256.Size]byte)

	flushCoarseCheckpoint := func(checkpointSize uint64) error {
		if len(modifiedValueRoots) == 0 && checkpointSize <= lastCheckpointLeaf {
			return nil
		}
		if err := c.db.Sync(); err != nil {
			return fmt.Errorf("genesis flush db.Sync error: %w", err)
		}
		if len(modifiedValueRoots) > 0 {
			if err := c.mptMgr.SetKeyBatch(modifiedValueRoots); err != nil {
				return fmt.Errorf("genesis mpt.SetKeyBatch error: %w", err)
			}
		}
		if checkpointSize > math.MaxInt64 {
			return fmt.Errorf("%w: checkpoint size %d overflows int64 MPT version", errInvariantViolation, checkpointSize)
		}
		if _, err := c.mptMgr.Snap(int64(checkpointSize)); err != nil {
			return fmt.Errorf("genesis mpt.Snap error: %w", err)
		}
		if err := c.mptMgr.Persist(); err != nil {
			return fmt.Errorf("genesis mpt.Persist error: %w", err)
		}
		clear(modifiedValueRoots)
		leavesSinceCheckpoint = 0
		lastCheckpointLeaf = checkpointSize
		return nil
	}

	streamErr := c.streamAndIndex(ctx, startLogSize, targetCP.Size, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
		res, err := c.indexer.IndexMappedBatch(drainCtx, &kvstore.MappedBatch{
			StartLeafIdx: batch.StartLeafIdx,
			EndLeafIdx:   batch.EndLeafIdx,
			KeyIndices:   batch.KeyIndices,
		}, targetCP.Raw, targetCP.Size)
		if err != nil {
			return fmt.Errorf("indexing error: %w", err)
		}
		lastIndexedSize = res.NewKVSize
		leavesSinceCheckpoint += uint64(batch.Count)
		metrics.KVCommittedSize.Set(float64(res.NewKVSize))
		metrics.LeavesIndexedTotal.Add(float64(batch.Count))
		metrics.IngestionLag.Set(float64(targetCP.Size - res.NewKVSize))
		var servedSize uint64
		if st := c.pub.GetServingState(); st != nil {
			servedSize = st.InputLogSize
		}
		if res.NewKVSize >= servedSize {
			metrics.IndexingLag.Set(float64(res.NewKVSize - servedSize))
		}
		maps.Copy(modifiedValueRoots, res.ModifiedKeyValueRoots)

		if genesisBackfill && res.NewKVSize < targetCP.Size {
			flushNeeded := (c.backfillMaxPendingKeys > 0 && uint64(len(modifiedValueRoots)) >= c.backfillMaxPendingKeys) ||
				(c.coarseCheckpointInterval > 0 && leavesSinceCheckpoint >= c.coarseCheckpointInterval)
			if flushNeeded {
				if err := flushCoarseCheckpoint(res.NewKVSize); err != nil {
					flushFailed = true
					return err
				}
			}
		}

		if res.NewKVSize-lastLogSize >= logInterval || res.NewKVSize == targetCP.Size {
			elapsed := time.Since(startTime).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(res.NewKVSize-startLogSize) / elapsed
			}
			if genesisBackfill {
				klog.Infof("Genesis backfill progress: %d / %d leaves (%.1f leaves/sec, %d pending keys)", res.NewKVSize, targetCP.Size, rate, len(modifiedValueRoots))
			} else {
				klog.Infof("Indexing progress: %d / %d leaves (%.1f leaves/sec)", res.NewKVSize, targetCP.Size, rate)
			}
			lastLogSize = res.NewKVSize
		}
		return nil
	})
	if streamErr != nil {
		if genesisBackfill && !flushFailed && lastIndexedSize > lastCheckpointLeaf {
			if err := flushCoarseCheckpoint(lastIndexedSize); err == nil {
				klog.Infof("Genesis backfill shutdown checkpoint saved at leaf %d", lastIndexedSize)
			}
		}
		return streamErr
	}

	if genesisBackfill {
		if err := c.db.Sync(); err != nil {
			return fmt.Errorf("genesis final db.Sync error: %w", err)
		}
	}
	if err := c.publishTargetState(ctx, targetCP, modifiedValueRoots); err != nil {
		if genesisBackfill && len(modifiedValueRoots) > 0 && c.pub.GetServingState() == nil {
			// If Output Log Entry 0 was not yet published (e.g., transient witness failure before append/quiescence),
			// check whether Output Log is still at size 0 before snapshotting MPT so MPT_Durable_Size <= Output_CP.InputSize holds.
			if _, outCP, oErr := c.readVerifiedOutputCheckpoint(ctx); oErr == nil && (outCP == nil || outCP.Size == 0) {
				_ = flushCoarseCheckpoint(targetCP.Size)
			}
		}
		return err
	}
	return nil
}

func (c *Coordinator) publishTargetState(ctx context.Context, targetCP *ingest.Checkpoint, modifiedValueRoots map[string][sha256.Size]byte) error {
	logCP := &log.Checkpoint{
		Origin: targetCP.Origin,
		Size:   targetCP.Size,
		Hash:   targetCP.Hash[:],
	}
	state, err := c.pub.PublishKeyBatch(ctx, modifiedValueRoots, logCP)
	if err != nil {
		return fmt.Errorf("publish error: %w", err)
	}
	if state != nil && len(targetCP.Raw) > 0 {
		if err := c.db.SetMetadata(inputCheckpointMetaKey(state.OutputLogIndex), targetCP.Raw); err != nil {
			klog.Warningf("Failed to retain signed Input Log checkpoint for Output Log index %d: %v", state.OutputLogIndex, err)
		}
	}
	c.knownOutServed.Store(true)
	metrics.IngestionLag.Set(0)
	metrics.IndexingLag.Set(0)
	return nil
}

func (c *Coordinator) streamAndIndex(
	ctx context.Context,
	fromLeaf, toLeaf uint64,
	indexFn func(ctx context.Context, batch *ingest.MappedBatch) error,
) error {
	if fromLeaf >= toLeaf {
		return nil
	}
	if c.pipeline == nil {
		return errors.New("cannot stream and index: pipeline not initialized")
	}

	g, gCtx := errgroup.WithContext(ctx)
	slabChan := make(chan *ingest.MappedBatch, 32)

	g.Go(func() error {
		for slab := range slabChan {
			if err := gCtx.Err(); err != nil {
				return err
			}
			if err := indexFn(gCtx, slab); err != nil {
				return err
			}
		}
		return nil
	})

	g.Go(func() error {
		defer close(slabChan)
		batchChan, errChan := c.pipeline.StreamBatches(gCtx, fromLeaf, toLeaf)
		var pendingBatch *ingest.MappedBatch

		for batch := range batchChan {
			if err := gCtx.Err(); err != nil {
				return err
			}
			if pendingBatch == nil {
				pendingBatch = batch
			} else {
				pendingBatch.Merge(batch)
			}
			if pendingBatch.EndLeafIdx-pendingBatch.StartLeafIdx >= c.commitBatchSize {
				select {
				case slabChan <- pendingBatch:
					pendingBatch = nil
				case <-gCtx.Done():
					return gCtx.Err()
				}
			}
		}

		if err, ok := <-errChan; ok && err != nil {
			return fmt.Errorf("stream batches failed: %w", err)
		}

		if pendingBatch != nil && pendingBatch.EndLeafIdx > pendingBatch.StartLeafIdx {
			select {
			case slabChan <- pendingBatch:
			case <-gCtx.Done():
				return gCtx.Err()
			}
		}
		return nil
	})

	return g.Wait()
}

// IsFatalSyncError reports whether err is an unrecoverable WASM or cryptographic invariant error.
func IsFatalSyncError(err error) bool {
	return errors.Is(err, wasmhost.ErrWasmHalt) ||
		errors.Is(err, wasmhost.ErrInvalidMemory) ||
		errors.Is(err, wasmhost.ErrMalformedOutput) ||
		errors.Is(err, errInvariantViolation) ||
		errors.Is(err, wire.ErrOutputLogCorrupted)
}

// RecordFatalError marks the coordinator as permanently halted so ReadinessCheck returns an error (503 on /readyz).
func (c *Coordinator) RecordFatalError(err error) {
	if err != nil {
		c.fatalErr.Store(&err)
	}
}

// RunPollLoop enters the periodic ingestion polling loop until ctx is canceled or a fatal error occurs.
func (c *Coordinator) RunPollLoop(ctx context.Context, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.SyncOnce(ctx); err != nil {
				if IsFatalSyncError(err) {
					fErr := fmt.Errorf("fatal sync error: %w", err)
					c.RecordFatalError(fErr)
					return fErr
				}
				if ctx.Err() == nil {
					klog.Warningf("Sync error: %v", err)
				}
			}
		}
	}
}

// Run executes startup recovery and enters the periodic ingestion polling loop until ctx is canceled.
func (c *Coordinator) Run(ctx context.Context, pollInterval time.Duration) error {
	if err := c.Recover(ctx); err != nil {
		fErr := fmt.Errorf("startup recovery failed: %w", err)
		c.RecordFatalError(fErr)
		return fErr
	}
	if err := c.SyncOnce(ctx); err != nil {
		if IsFatalSyncError(err) {
			fErr := fmt.Errorf("fatal initial sync error: %w", err)
			c.RecordFatalError(fErr)
			return fErr
		}
		if ctx.Err() == nil {
			klog.Warningf("Initial sync error: %v", err)
		}
	}
	return c.RunPollLoop(ctx, pollInterval)
}
