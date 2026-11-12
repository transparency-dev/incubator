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

// Package auditor implements the VIndex Independent Auditor engine.
// It verifies published OutputLogs against InputLogs using a provided MapFn,
// checks cryptographic root hashes before advancing verified watermarks, and halts on divergence.
package auditor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

// ErrRootMismatch is returned when the calculated local MPT root hash diverges from the root hash committed in the OutputLog leaf.
var ErrRootMismatch = errors.New("auditor root hash mismatch")

var (
	errInclusionFailed    = errors.New("output log inclusion proof invalid")
	errConsistencyFailed  = errors.New("log consistency proof invalid")
	errCheckpointFailed   = errors.New("checkpoint verification failed")
	errMonotonicityBroken = errors.New("input log size non-monotonic")
	errOutputLogRegressed = errors.New("output log tree size regressed")

	keyVerifierOutputWatermark = []byte("meta:verifier:output_watermark")
	keyVerifierInputWatermark  = []byte("meta:verifier:input_watermark")
	keyVerifierInputHash       = []byte("meta:verifier:input_hash")
	keyVerifierLastRoot        = []byte("meta:verifier:last_root")
	keyVerifierLastOutCP       = []byte("meta:verifier:last_out_cp")
	keyVerifierLastInCP        = []byte("meta:verifier:last_in_cp")
	keyVerifierFrom            = []byte("meta:verifier:from")
	keyVerifierInputOrigin     = []byte("meta:verifier:input_origin")
)

const (
	defaultCommitBatchSize          uint64 = 4096
	defaultCoarseCheckpointInterval uint64 = 1_000_000
)

// RootMismatchError provides structured diagnostic details when a local MPT root calculation
// diverges from the state commitment in an OutputLog leaf.
type RootMismatchError struct {
	OutputIndex      uint64
	InputSize        uint64
	LocalMPTRoot     [sha256.Size]byte
	CommittedMPTRoot [sha256.Size]byte
}

func (e *RootMismatchError) Error() string {
	return fmt.Sprintf("%v: output leaf %d (input size %d): calculated local MPT root %x != committed MPT root %x",
		ErrRootMismatch, e.OutputIndex, e.InputSize, e.LocalMPTRoot, e.CommittedMPTRoot)
}

func (e *RootMismatchError) Unwrap() error { return ErrRootMismatch }

// JSONDiagnostics formats the root mismatch details as JSON for structured diagnostic reporting.
func (e *RootMismatchError) JSONDiagnostics() []byte {
	return fmt.Appendf(nil,
		"{\"status\":\"degraded\",\"error\":\"auditor root hash mismatch\",\"output_index\":%d,\"input_size\":%d,\"local_root\":\"%x\",\"committed_root\":\"%x\"}\n",
		e.OutputIndex, e.InputSize, e.LocalMPTRoot, e.CommittedMPTRoot,
	)
}

type logSource interface {
	ingest.TileFetcher
	ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error)
}

// Config defines the runtime configuration for the VIndex Auditor.
type Config struct {
	InputLogURL     string
	InputLogOrigin  string
	InputLogPolicy  wire.Policy
	InputLogType    string
	OutputLogURL    string
	OutputLogOrigin string
	OutputLogPolicy wire.Policy

	WASMHost     *wasmhost.WASMHost
	ExpectedFrom *uint64

	DBPath       string
	MPTDir       string
	TileCacheDir string

	MetricsAddr              string
	PollInterval             time.Duration
	ChunkSize                uint64
	CommitBatchSize          uint64
	CoarseCheckpointInterval uint64
	WASMWorkers              int
	FetchWorkers             int
	DBCacheSizeMB            int
	DBMaxOpenFiles           int

	outputFetcher logSource
	inputFetcher  logSource
}

// Status represents an instantaneous snapshot of the auditor's operational state.
type Status struct {
	IsHalted           bool
	HaltError          error
	VerifiedOutputSize uint64
	VerifiedInputSize  uint64
	LastVerifiedRoot   [sha256.Size]byte
}

// Verifier implements the independent audit engine for VIndex.
type Verifier struct {
	cfg           Config
	outputFetcher logSource
	inputFetcher  logSource

	db        *kvstore.DB
	mptMgr    *mpt.Manager
	indexer   *kvstore.KVIndexer
	tileCache ingest.TileCache
	pipeline  *ingest.IngestionPipeline

	syncMu               sync.Mutex
	closed               bool
	verifiedOutputCPSize uint64
	verifiedOutputCPHash [sha256.Size]byte
	verifiedInputCPSize  uint64
	verifiedInputCPHash  [sha256.Size]byte
	verifiedInputHash    [sha256.Size]byte
	hasFrom              bool
	verifiedFrom         uint64
	hasOrigin            bool
	verifiedInputOrigin  string

	stateMu            sync.RWMutex
	isHalted           bool
	haltErr            error
	verifiedOutputSize uint64
	verifiedInputSize  uint64
	lastVerifiedRoot   [sha256.Size]byte
}

func newTiledLogSource(rawURL, origin, logType string, forceTessera bool) (logSource, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid log URL %q: %w", rawURL, err)
	}
	tf, err := ingest.NewTiledFetcher(u, nil, origin, nil)
	if err != nil {
		return nil, err
	}
	// Policy verification is executed explicitly by Verifier so cryptographic checkpoint failures
	// deterministically trigger forensic halt while network errors remain retryable.
	tf.SetAllowUnverifiedCheckpoints(true)
	if forceTessera {
		tf.SetStaticCT(false)
		return tf, nil
	}
	switch strings.ToLower(strings.TrimSpace(logType)) {
	case "static-ct", "ct":
		tf.SetStaticCT(true)
	case "tessera":
		tf.SetStaticCT(false)
	}
	return tf, nil
}

// New initializes and returns a new Auditor (Verifier) instance.
func New(cfg Config) (*Verifier, error) {
	if cfg.WASMHost == nil {
		return nil, errors.New("auditor requires non-nil WASMHost")
	}
	if cfg.OutputLogPolicy == nil {
		return nil, errors.New("auditor requires non-nil OutputLogPolicy")
	}
	if cfg.InputLogPolicy == nil {
		return nil, errors.New("auditor requires non-nil InputLogPolicy")
	}
	if cfg.OutputLogOrigin == "" {
		if op, ok := any(cfg.OutputLogPolicy).(interface{ Origin() string }); ok {
			cfg.OutputLogOrigin = op.Origin()
		}
	}
	if cfg.InputLogOrigin == "" {
		if op, ok := any(cfg.InputLogPolicy).(interface{ Origin() string }); ok {
			cfg.InputLogOrigin = op.Origin()
		}
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	if cfg.CommitBatchSize == 0 {
		cfg.CommitBatchSize = defaultCommitBatchSize
	}
	if cfg.CoarseCheckpointInterval == 0 {
		cfg.CoarseCheckpointInterval = defaultCoarseCheckpointInterval
	}
	switch strings.ToLower(strings.TrimSpace(cfg.InputLogType)) {
	case "", "auto", "tessera", "static-ct", "ct":
	default:
		return nil, fmt.Errorf("unknown InputLogType %q: expected 'auto', 'tessera', or 'static-ct'", cfg.InputLogType)
	}

	dir := cfg.DBPath
	if dir == ":memory:" {
		dir = ""
	}
	db, err := kvstore.Open(dir, &kvstore.Options{
		CacheSizeMB:  cfg.DBCacheSizeMB,
		MaxOpenFiles: cfg.DBMaxOpenFiles,
		ChunkSize:    cfg.ChunkSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open KV store: %w", err)
	}

	mptMgr, err := mpt.Open(cfg.MPTDir)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to open MPT at %q: %w", cfg.MPTDir, err)
	}

	v := &Verifier{
		cfg:     cfg,
		db:      db,
		mptMgr:  mptMgr,
		indexer: kvstore.NewKVIndexer(db),
	}
	failInit := func(err error) (*Verifier, error) {
		_ = v.Close()
		return nil, err
	}

	// Recover persisted watermarks (fail closed on any metadata corruption or I/O error).
	outSz, err := v.db.GetUint64(keyVerifierOutputWatermark)
	if err != nil {
		return failInit(fmt.Errorf("failed to read output watermark: %w", err))
	}
	v.verifiedOutputSize = outSz

	inSz, err := v.db.GetUint64(keyVerifierInputWatermark)
	if err != nil {
		return failInit(fmt.Errorf("failed to read input watermark: %w", err))
	}
	v.verifiedInputSize = inSz

	kvSz, err := v.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return failInit(fmt.Errorf("failed to read KV size metadata: %w", err))
	}
	if v.verifiedOutputSize == 0 {
		if v.verifiedInputSize != 0 {
			return failInit(fmt.Errorf("corrupt state: output watermark is 0 while input watermark is %d", v.verifiedInputSize))
		}
		if mptMgr.PersistedSize() > kvSz {
			return failInit(fmt.Errorf("MPT durable size (%d) exceeds persisted KV size (%d) during genesis backfill", mptMgr.PersistedSize(), kvSz))
		}
	} else if mptMgr.PersistedSize() > v.verifiedInputSize {
		return failInit(fmt.Errorf("MPT durable size (%d) exceeds persisted input watermark (%d)", mptMgr.PersistedSize(), v.verifiedInputSize))
	}

	if inHash, err := v.db.GetMetadata(keyVerifierInputHash); err != nil {
		return failInit(fmt.Errorf("failed to read input hash metadata: %w", err))
	} else if len(inHash) > 0 {
		if len(inHash) != sha256.Size {
			return failInit(fmt.Errorf("corrupt input hash metadata length %d, want 32", len(inHash)))
		}
		copy(v.verifiedInputHash[:], inHash)
	}

	if lastRoot, err := v.db.GetMetadata(keyVerifierLastRoot); err != nil {
		return failInit(fmt.Errorf("failed to read last verified root metadata: %w", err))
	} else if len(lastRoot) > 0 {
		if len(lastRoot) != sha256.Size {
			return failInit(fmt.Errorf("corrupt last verified root length %d, want 32", len(lastRoot)))
		}
		copy(v.lastVerifiedRoot[:], lastRoot)
	}

	if rawOutCP, err := v.db.GetMetadata(keyVerifierLastOutCP); err != nil {
		return failInit(fmt.Errorf("failed to read last output checkpoint metadata: %w", err))
	} else if len(rawOutCP) > 0 {
		cp, pErr := wire.ParseCheckpointHeader(rawOutCP)
		if pErr != nil || len(cp.Hash) != sha256.Size {
			return failInit(fmt.Errorf("corrupt last output checkpoint metadata: %w", pErr))
		}
		if cfg.OutputLogOrigin != "" && cp.Origin != cfg.OutputLogOrigin {
			return failInit(fmt.Errorf("persisted output log origin %q != configured %q", cp.Origin, cfg.OutputLogOrigin))
		}
		v.verifiedOutputCPSize = cp.Size
		copy(v.verifiedOutputCPHash[:], cp.Hash)
	}

	if rawInCP, err := v.db.GetMetadata(keyVerifierLastInCP); err != nil {
		return failInit(fmt.Errorf("failed to read last input checkpoint metadata: %w", err))
	} else if len(rawInCP) > 0 {
		cp, pErr := wire.ParseCheckpointHeader(rawInCP)
		if pErr != nil || len(cp.Hash) != sha256.Size {
			return failInit(fmt.Errorf("corrupt last input checkpoint metadata: %w", pErr))
		}
		if cfg.InputLogOrigin != "" && cp.Origin != cfg.InputLogOrigin {
			return failInit(fmt.Errorf("persisted input log origin %q != configured %q", cp.Origin, cfg.InputLogOrigin))
		}
		v.verifiedInputCPSize = cp.Size
		copy(v.verifiedInputCPHash[:], cp.Hash)
	}

	if fromRaw, err := v.db.GetMetadata(keyVerifierFrom); err != nil {
		return failInit(fmt.Errorf("failed to read persisted from metadata: %w", err))
	} else if len(fromRaw) > 0 {
		fromVal, uErr := v.db.GetUint64(keyVerifierFrom)
		if uErr != nil {
			return failInit(fmt.Errorf("corrupt persisted from metadata: %w", uErr))
		}
		if cfg.ExpectedFrom != nil && fromVal != *cfg.ExpectedFrom {
			return failInit(fmt.Errorf("persisted from (%d) != configured ExpectedFrom (%d)", fromVal, *cfg.ExpectedFrom))
		}
		v.verifiedFrom = fromVal
		v.hasFrom = true
	}

	if originRaw, err := v.db.GetMetadata(keyVerifierInputOrigin); err != nil {
		return failInit(fmt.Errorf("failed to read persisted input-origin metadata: %w", err))
	} else if len(originRaw) > 0 {
		v.verifiedInputOrigin = string(originRaw)
		if cfg.InputLogOrigin != "" && v.verifiedInputOrigin != cfg.InputLogOrigin {
			return failInit(fmt.Errorf("persisted input-origin %q != configured %q", v.verifiedInputOrigin, cfg.InputLogOrigin))
		}
		v.hasOrigin = true
	}

	if cfg.outputFetcher != nil {
		v.outputFetcher = cfg.outputFetcher
	} else if cfg.OutputLogURL != "" {
		src, err := newTiledLogSource(cfg.OutputLogURL, cfg.OutputLogOrigin, "", true)
		if err != nil {
			return failInit(fmt.Errorf("failed to create output log fetcher: %w", err))
		}
		v.outputFetcher = src
	} else {
		return failInit(errors.New("auditor requires OutputLogURL"))
	}

	if cfg.inputFetcher != nil {
		v.inputFetcher = cfg.inputFetcher
	} else if cfg.InputLogURL != "" {
		src, err := newTiledLogSource(cfg.InputLogURL, cfg.InputLogOrigin, cfg.InputLogType, false)
		if err != nil {
			return failInit(fmt.Errorf("failed to create input log fetcher: %w", err))
		}
		v.inputFetcher = src
	} else {
		return failInit(errors.New("auditor requires InputLogURL"))
	}

	if cfg.TileCacheDir != "" {
		tc, err := ingest.NewManagedTileCache(cfg.TileCacheDir, 0)
		if err != nil {
			return failInit(fmt.Errorf("failed to initialize tile cache at %q: %w", cfg.TileCacheDir, err))
		}
		v.tileCache = tc
	}
	v.pipeline = ingest.NewPipeline(v.inputFetcher, v.tileCache, cfg.WASMHost, cfg.WASMWorkers)
	if cfg.FetchWorkers > 0 {
		v.pipeline.SetFetchWorkers(cfg.FetchWorkers)
	}

	metrics.ResetAuditorRootMismatch()
	return v, nil
}

func (v *Verifier) halt(err error) error {
	v.stateMu.Lock()
	v.isHalted = true
	v.haltErr = err
	v.stateMu.Unlock()
	return err
}

func (v *Verifier) haltError() error {
	v.stateMu.RLock()
	defer v.stateMu.RUnlock()
	if v.isHalted {
		return v.haltErr
	}
	return nil
}

func (v *Verifier) handleRootMismatch(leafIdx, targetInputSize uint64, localRoot, committedRoot [sha256.Size]byte) error {
	metrics.RecordAuditorRootMismatch()
	klog.Errorf(
		"CRITICAL ROOT MISMATCH DETECTED: output_leaf_index=%d target_input_size=%d local_mpt_root=%x committed_mpt_root=%x output_log_url=%q input_log_url=%q. Halting auditor sync engine immediately.",
		leafIdx, targetInputSize, localRoot, committedRoot, v.cfg.OutputLogURL, v.cfg.InputLogURL,
	)
	return v.halt(&RootMismatchError{
		OutputIndex:      leafIdx,
		InputSize:        targetInputSize,
		LocalMPTRoot:     localRoot,
		CommittedMPTRoot: committedRoot,
	})
}

func setFetcherTreeState(f ingest.TileFetcher, size uint64, hash [sha256.Size]byte) {
	if stater, ok := f.(interface{ SetTreeState(uint64, [32]byte) }); ok {
		stater.SetTreeState(size, hash)
	}
}

func isFatalWASMError(err error) bool {
	return errors.Is(err, wasmhost.ErrWasmHalt) ||
		errors.Is(err, wasmhost.ErrInvalidMemory) ||
		errors.Is(err, wasmhost.ErrMalformedOutput)
}

func isBundleAuthError(err error) bool {
	var rmErr proof.RootMismatchError
	return errors.Is(err, errInclusionFailed) ||
		errors.As(err, &rmErr) ||
		strings.Contains(err.Error(), "failed to authenticate")
}

func (v *Verifier) verifyCheckpointWithPolicy(rawCP []byte, pol wire.Policy, expectedOrigin, logName string) (*log.Checkpoint, [sha256.Size]byte, error) {
	if len(rawCP) == 0 {
		return nil, [sha256.Size]byte{}, v.halt(fmt.Errorf("%w: %s checkpoint missing raw signed note bytes", errCheckpointFailed, logName))
	}
	cp, err := pol.Verify(rawCP)
	if err != nil || cp == nil || len(cp.Hash) != sha256.Size {
		return nil, [sha256.Size]byte{}, v.halt(fmt.Errorf("%w: %s checkpoint policy verification failed: %v", errCheckpointFailed, logName, err))
	}
	if expectedOrigin != "" && cp.Origin != expectedOrigin {
		return nil, [sha256.Size]byte{}, v.halt(fmt.Errorf("%w: %s checkpoint origin mismatch: got %q, expected %q", errCheckpointFailed, logName, cp.Origin, expectedOrigin))
	}
	var root [sha256.Size]byte
	copy(root[:], cp.Hash)
	if cp.Size == 0 && root != wire.EmptyRoot() {
		return nil, [sha256.Size]byte{}, v.halt(fmt.Errorf("%w: %s checkpoint size 0 has non-empty root %x", errCheckpointFailed, logName, root))
	}
	return cp, root, nil
}

func (v *Verifier) verifyLogConsistency(
	ctx context.Context,
	src logSource,
	smallerSize uint64,
	smallerHash [sha256.Size]byte,
	largerSize uint64,
	largerHash [sha256.Size]byte,
	desc string,
) error {
	if smallerSize == 0 {
		return nil
	}
	if smallerSize == largerSize {
		if smallerHash != largerHash {
			return v.halt(fmt.Errorf("%w: %s hash mismatch at size %d: got %x, expected %x", errConsistencyFailed, desc, smallerSize, largerHash, smallerHash))
		}
		return nil
	}
	setFetcherTreeState(src, largerSize, largerHash)
	consProof, err := src.ConsistencyProof(ctx, smallerSize, largerSize)
	if err != nil {
		return fmt.Errorf("failed to fetch %s consistency proof (%d -> %d): %w", desc, smallerSize, largerSize, err)
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, smallerSize, largerSize, consProof, smallerHash[:], largerHash[:]); err != nil {
		return v.halt(fmt.Errorf("%w: %s consistency proof (%d -> %d) invalid: %v", errConsistencyFailed, desc, smallerSize, largerSize, err))
	}
	return nil
}

func (v *Verifier) fetchLatestInputCheckpoint(ctx context.Context) (*log.Checkpoint, [sha256.Size]byte, error) {
	inCP, err := v.inputFetcher.Checkpoint(ctx)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("failed to fetch input log checkpoint: %w", err)
	}
	if inCP == nil {
		return nil, [sha256.Size]byte{}, errors.New("input log returned nil checkpoint")
	}
	verifiedCP, root, err := v.verifyCheckpointWithPolicy(inCP.Raw, v.cfg.InputLogPolicy, v.cfg.InputLogOrigin, "input log")
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	minExpected := max(v.verifiedInputSize, v.verifiedInputCPSize)
	if verifiedCP.Size < minExpected {
		return nil, [sha256.Size]byte{}, v.halt(fmt.Errorf("%w: input log checkpoint regressed from %d to %d", errMonotonicityBroken, minExpected, verifiedCP.Size))
	}
	if err := v.verifyLogConsistency(ctx, v.inputFetcher, v.verifiedInputCPSize, v.verifiedInputCPHash, verifiedCP.Size, root, "input log checkpoint"); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	if verifiedCP.Size != v.verifiedInputCPSize || root != v.verifiedInputCPHash {
		if err := v.db.SetMetadata(keyVerifierLastInCP, inCP.Raw); err != nil {
			return nil, [sha256.Size]byte{}, fmt.Errorf("failed to persist latest input checkpoint: %w", err)
		}
		v.verifiedInputCPSize = verifiedCP.Size
		v.verifiedInputCPHash = root
	}
	return verifiedCP, root, nil
}

func (v *Verifier) verifyLeafMetadata(leafIdx uint64, outLeaf *wire.OutputLogLeaf, latestInOrigin string) error {
	if v.cfg.InputLogOrigin != "" && outLeaf.InputOrigin != v.cfg.InputLogOrigin {
		return v.halt(fmt.Errorf("%w: leaf %d input-origin mismatch: got %q, expected %q", errCheckpointFailed, leafIdx, outLeaf.InputOrigin, v.cfg.InputLogOrigin))
	}
	if latestInOrigin != "" && outLeaf.InputOrigin != latestInOrigin {
		return v.halt(fmt.Errorf("%w: leaf %d input-origin %q != input log checkpoint origin %q", errCheckpointFailed, leafIdx, outLeaf.InputOrigin, latestInOrigin))
	}
	if v.hasOrigin && outLeaf.InputOrigin != v.verifiedInputOrigin {
		return v.halt(fmt.Errorf("%w: leaf %d input-origin drifted from %q to %q", errCheckpointFailed, leafIdx, v.verifiedInputOrigin, outLeaf.InputOrigin))
	}
	if outLeaf.From > outLeaf.InCP.Size {
		return v.halt(fmt.Errorf("leaf %d invalid from %d > input log size %d", leafIdx, outLeaf.From, outLeaf.InCP.Size))
	}
	if v.cfg.ExpectedFrom != nil && outLeaf.From != *v.cfg.ExpectedFrom {
		return v.halt(fmt.Errorf("leaf %d from mismatch: got %d, expected %d", leafIdx, outLeaf.From, *v.cfg.ExpectedFrom))
	}
	if v.hasFrom && v.verifiedFrom != outLeaf.From {
		return v.halt(fmt.Errorf("leaf %d from drifted from %d to %d", leafIdx, v.verifiedFrom, outLeaf.From))
	}
	return nil
}

func (v *Verifier) catchUpMPT(ctx context.Context, targetSize, latestInSize uint64, latestInHash [sha256.Size]byte) error {
	replayStart := v.mptMgr.PersistedSize()
	if !v.mptMgr.IsExact() && replayStart == targetSize {
		replayStart = 0
	}
	if v.hasFrom && replayStart < v.verifiedFrom {
		replayStart = v.verifiedFrom
	}
	if v.cfg.ExpectedFrom != nil && replayStart < *v.cfg.ExpectedFrom {
		replayStart = *v.cfg.ExpectedFrom
	}

	var mutations map[string][sha256.Size]byte
	if replayStart < targetSize {
		setFetcherTreeState(v.inputFetcher, latestInSize, latestInHash)
		batchChan, errChan := v.pipeline.StreamBatches(ctx, replayStart, targetSize)
		modifiedSet := make(map[string]struct{})
		for batch := range batchChan {
			for k := range batch.KeyIndices {
				modifiedSet[k] = struct{}{}
			}
		}
		if err := <-errChan; err != nil {
			if isFatalWASMError(err) {
				return v.halt(fmt.Errorf("deterministic WASM fault during startup catch-up: %w", err))
			}
			return fmt.Errorf("startup MPT catch-up streaming failed [%d, %d): %w", replayStart, targetSize, err)
		}
		modifiedKeys := slices.AppendSeq(make([]string, 0, len(modifiedSet)), maps.Keys(modifiedSet))
		clear(modifiedSet)
		var err error
		mutations, err = v.indexer.GetKeyValueRoots(ctx, modifiedKeys, targetSize)
		if err != nil {
			return fmt.Errorf("startup MPT catch-up GetKeyValueRoots failed: %w", err)
		}
	}

	mptBatch, err := mpt.PrepareBatch(mutations)
	if err != nil {
		return err
	}
	if targetSize > math.MaxInt64 {
		return v.halt(fmt.Errorf("target size %d overflows int64 MPT version", targetSize))
	}
	actualRoot, err := v.mptMgr.CommitBatchAndPersist(mptBatch, int64(targetSize), nil)
	if err != nil {
		return fmt.Errorf("startup MPT catch-up commit/persist failed: %w", err)
	}
	if v.verifiedOutputSize > 0 && v.lastVerifiedRoot != ([sha256.Size]byte{}) && actualRoot != v.lastVerifiedRoot {
		return v.halt(fmt.Errorf("%w: startup MPT catch-up root %x != persisted verified root %x at input size %d", ErrRootMismatch, actualRoot, v.lastVerifiedRoot, targetSize))
	}
	if v.tileCache != nil && targetSize >= ingest.DefaultBundleSize {
		_, _ = v.tileCache.PruneBefore(targetSize)
	}
	return nil
}

// VerifyOnce executes a single audit pass over newly published OutputLog leaves.
func (v *Verifier) VerifyOnce(ctx context.Context) error {
	if err := v.haltError(); err != nil {
		return fmt.Errorf("auditor halted: %w", err)
	}

	v.syncMu.Lock()
	defer v.syncMu.Unlock()

	if v.closed {
		return errors.New("auditor is closed")
	}
	if err := v.haltError(); err != nil {
		return fmt.Errorf("auditor halted: %w", err)
	}

	outFetchCP, err := v.outputFetcher.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch output log checkpoint: %w", err)
	}
	if outFetchCP == nil || len(outFetchCP.Raw) == 0 {
		if v.verifiedOutputSize > 0 || v.verifiedOutputCPSize > 0 {
			return v.halt(fmt.Errorf("%w: output log checkpoint empty after reaching size %d", errOutputLogRegressed, max(v.verifiedOutputSize, v.verifiedOutputCPSize)))
		}
		return errors.New("output log checkpoint is empty")
	}

	outCP, outHash, err := v.verifyCheckpointWithPolicy(outFetchCP.Raw, v.cfg.OutputLogPolicy, v.cfg.OutputLogOrigin, "output log")
	if err != nil {
		return err
	}

	if outCP.Size < v.verifiedOutputSize || outCP.Size < v.verifiedOutputCPSize {
		return v.halt(fmt.Errorf("%w: published size %d < verified size %d", errOutputLogRegressed, outCP.Size, max(v.verifiedOutputSize, v.verifiedOutputCPSize)))
	}

	if err := v.verifyLogConsistency(ctx, v.outputFetcher, v.verifiedOutputCPSize, v.verifiedOutputCPHash, outCP.Size, outHash, "output log"); err != nil {
		return err
	}
	if outCP.Size != v.verifiedOutputCPSize || outHash != v.verifiedOutputCPHash {
		if err := v.db.SetMetadata(keyVerifierLastOutCP, outFetchCP.Raw); err != nil {
			return fmt.Errorf("failed to persist latest output checkpoint: %w", err)
		}
		v.verifiedOutputCPSize = outCP.Size
		v.verifiedOutputCPHash = outHash
	}

	recoveryTarget := v.verifiedInputSize
	if v.verifiedOutputSize == 0 {
		kvSz, kErr := v.db.GetUint64(kvstore.KeyMetaKVSize)
		if kErr != nil {
			return fmt.Errorf("failed to read m_kv_size: %w", kErr)
		}
		recoveryTarget = kvSz
	}
	needCatchUp := v.mptMgr.PersistedSize() < recoveryTarget || !v.mptMgr.IsExact()

	if outCP.Size == v.verifiedOutputSize && !needCatchUp {
		if v.verifiedOutputSize > 0 && v.lastVerifiedRoot != ([sha256.Size]byte{}) && v.mptMgr.Root() != v.lastVerifiedRoot {
			return v.halt(fmt.Errorf("%w: recovered MPT root %x != persisted verified root %x at input size %d", ErrRootMismatch, v.mptMgr.Root(), v.lastVerifiedRoot, v.verifiedInputSize))
		}
		return nil
	}

	latestInCP, latestInHash, err := v.fetchLatestInputCheckpoint(ctx)
	if err != nil {
		return err
	}
	if v.verifiedInputSize > 0 {
		if err := v.verifyLogConsistency(ctx, v.inputFetcher, v.verifiedInputSize, v.verifiedInputHash, latestInCP.Size, latestInHash, "verified -> latest input log"); err != nil {
			return err
		}
	}

	if needCatchUp {
		if recoveryTarget > latestInCP.Size {
			return v.halt(fmt.Errorf("%w: persisted recovery target %d exceeds latest input log checkpoint size %d", errMonotonicityBroken, recoveryTarget, latestInCP.Size))
		}
		if err := v.catchUpMPT(ctx, recoveryTarget, latestInCP.Size, latestInHash); err != nil {
			return err
		}
	}
	if v.verifiedOutputSize > 0 && v.lastVerifiedRoot != ([sha256.Size]byte{}) && v.mptMgr.Root() != v.lastVerifiedRoot {
		return v.halt(fmt.Errorf("%w: recovered MPT root %x != persisted verified root %x at input size %d", ErrRootMismatch, v.mptMgr.Root(), v.lastVerifiedRoot, v.verifiedInputSize))
	}
	if outCP.Size == v.verifiedOutputSize {
		return nil
	}

	setFetcherTreeState(v.outputFetcher, outCP.Size, outHash)
	outBundles, err := v.outputFetcher.FetchTiles(ctx, v.verifiedOutputSize, outCP.Size-v.verifiedOutputSize)
	if err != nil {
		if isBundleAuthError(err) {
			return v.halt(fmt.Errorf("%w: %v", errInclusionFailed, err))
		}
		return fmt.Errorf("failed to fetch output log entry bundles [%d, %d): %w", v.verifiedOutputSize, outCP.Size, err)
	}
	defer func() {
		for _, b := range outBundles {
			if b != nil {
				b.Release()
			}
		}
	}()

	nextIdx := v.verifiedOutputSize
	for _, b := range outBundles {
		if b == nil {
			continue
		}
		for offset, leafData := range b.Leaves {
			idx := b.StartLeafIdx + uint64(offset)
			if idx < nextIdx {
				continue
			}
			if idx >= outCP.Size {
				break
			}
			if idx != nextIdx {
				return fmt.Errorf("unexpected gap in output log bundles: got index %d, want %d", idx, nextIdx)
			}
			if err := v.verifyLeaf(ctx, idx, leafData, &latestInCP, &latestInHash); err != nil {
				return err
			}
			nextIdx++
		}
	}
	if nextIdx != outCP.Size {
		return fmt.Errorf("incomplete output log bundle stream: reached %d, want %d", nextIdx, outCP.Size)
	}
	return nil
}

func (v *Verifier) verifyLeaf(
	ctx context.Context,
	leafIdx uint64,
	leafData []byte,
	latestInCP **log.Checkpoint,
	latestInHash *[sha256.Size]byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	outLeaf, err := wire.ParseOutputLogLeafFull(leafData)
	if err != nil {
		return v.halt(fmt.Errorf("leaf %d format corrupted: %w", leafIdx, err))
	}
	targetInputSize := outLeaf.InCP.Size
	if targetInputSize > math.MaxInt64 {
		return v.halt(fmt.Errorf("leaf %d target input size %d overflows int64 MPT version", leafIdx, targetInputSize))
	}
	if targetInputSize < v.verifiedInputSize {
		return v.halt(fmt.Errorf("%w: leaf %d target size %d < verified size %d", errMonotonicityBroken, leafIdx, targetInputSize, v.verifiedInputSize))
	}

	if *latestInCP == nil || targetInputSize > (*latestInCP).Size {
		newInCP, newInHash, err := v.fetchLatestInputCheckpoint(ctx)
		if err != nil {
			return err
		}
		*latestInCP = newInCP
		*latestInHash = newInHash
		if targetInputSize > (*latestInCP).Size {
			return v.halt(fmt.Errorf("%w: leaf %d target input size %d exceeds latest signed input log checkpoint size %d", errConsistencyFailed, leafIdx, targetInputSize, (*latestInCP).Size))
		}
	}

	if err := v.verifyLeafMetadata(leafIdx, outLeaf, (*latestInCP).Origin); err != nil {
		return err
	}
	if targetInputSize == 0 && outLeaf.InputRoot != wire.EmptyRoot() {
		return v.halt(fmt.Errorf("%w: leaf %d input-size 0 has non-empty input-root %x", errConsistencyFailed, leafIdx, outLeaf.InputRoot))
	}
	if targetInputSize == outLeaf.From && outLeaf.MPTRoot != wire.EmptyRoot() {
		return v.halt(fmt.Errorf("%w: leaf %d empty range [from=%d, input-size=%d) has non-empty mpt-root %x", errConsistencyFailed, leafIdx, outLeaf.From, targetInputSize, outLeaf.MPTRoot))
	}

	// Both (v.verifiedInputSize, v.verifiedInputHash) and (targetInputSize, outLeaf.InputRoot) are verified
	// consistent with ((*latestInCP).Size, *latestInHash) using the live latestInCP partial tile.
	if err := v.verifyLogConsistency(ctx, v.inputFetcher, targetInputSize, outLeaf.InputRoot, (*latestInCP).Size, *latestInHash, fmt.Sprintf("leaf %d -> latest input log", leafIdx)); err != nil {
		return err
	}
	if v.verifiedInputSize > 0 && targetInputSize == v.verifiedInputSize && outLeaf.InputRoot != v.verifiedInputHash {
		return v.halt(fmt.Errorf("%w: leaf %d input-root %x != verified input-root %x at size %d", errConsistencyFailed, leafIdx, outLeaf.InputRoot, v.verifiedInputHash, targetInputSize))
	}

	startInputSize := max(v.verifiedInputSize, outLeaf.From)
	if v.verifiedOutputSize == 0 && targetInputSize-startInputSize > v.cfg.CoarseCheckpointInterval {
		return v.verifyGenesisBackfillLeaf(ctx, leafIdx, outLeaf, targetInputSize, *latestInCP, *latestInHash)
	}

	stagedBatch := v.db.NewIndexedBatch()
	defer func() { _ = stagedBatch.Close() }()

	var allModifiedValueRoots map[string][sha256.Size]byte
	if targetInputSize > startInputSize {
		setFetcherTreeState(v.inputFetcher, (*latestInCP).Size, *latestInHash)
		batchChan, errChan := v.pipeline.StreamBatches(ctx, startInputSize, targetInputSize)
		var merged *ingest.MappedBatch
		for batch := range batchChan {
			if merged == nil {
				merged = batch
			} else {
				merged.Merge(batch)
			}
		}
		if err := <-errChan; err != nil {
			if isFatalWASMError(err) {
				return v.halt(fmt.Errorf("deterministic WASM fault for leaf %d: %w", leafIdx, err))
			}
			return fmt.Errorf("input streaming failed for leaf %d [%d, %d): %w", leafIdx, startInputSize, targetInputSize, err)
		}
		if merged != nil && merged.EndLeafIdx > merged.StartLeafIdx {
			res, err := v.indexer.StageMappedBatch(ctx, stagedBatch, startInputSize, &kvstore.MappedBatch{
				StartLeafIdx: merged.StartLeafIdx,
				EndLeafIdx:   merged.EndLeafIdx,
				KeyIndices:   merged.KeyIndices,
			}, targetInputSize)
			if err != nil {
				return fmt.Errorf("indexing error [%d, %d): %w", merged.StartLeafIdx, merged.EndLeafIdx, err)
			}
			allModifiedValueRoots = res.ModifiedKeyValueRoots
		}
	}

	mptBatch, err := mpt.PrepareBatch(allModifiedValueRoots)
	if err != nil {
		return err
	}
	localMPTRoot, err := v.mptMgr.PredictBatch(mptBatch)
	if err != nil {
		return fmt.Errorf("MPT predict failed at leaf %d: %w", leafIdx, err)
	}
	if localMPTRoot != outLeaf.MPTRoot {
		return v.handleRootMismatch(leafIdx, targetInputSize, localMPTRoot, outLeaf.MPTRoot)
	}

	nextOutputSize := leafIdx + 1
	if err := v.stageWatermarkMetadata(stagedBatch, nextOutputSize, targetInputSize, outLeaf, localMPTRoot); err != nil {
		return err
	}
	if err := v.db.Apply(stagedBatch, true); err != nil {
		return fmt.Errorf("failed to commit verified chunks and watermarks: %w", err)
	}

	// Update in-memory watermarks immediately after durable Pebble commit so any transient MPT error
	// below triggers catchUpMPT on the next pass rather than a false-positive root mismatch.
	v.commitInMemoryWatermarks(nextOutputSize, targetInputSize, outLeaf, localMPTRoot)

	if targetInputSize > startInputSize || (targetInputSize > 0 && (v.mptMgr.PersistedSize() < targetInputSize || !v.mptMgr.IsExact())) {
		if targetInputSize > math.MaxInt64 {
			return v.halt(fmt.Errorf("leaf %d target input size %d overflows int64 MPT version", leafIdx, targetInputSize))
		}
		if _, err := v.mptMgr.CommitBatchAndPersist(mptBatch, int64(targetInputSize), nil); err != nil {
			return fmt.Errorf("MPT commit/persist failed at leaf %d: %w", leafIdx, err)
		}
		if v.tileCache != nil && targetInputSize >= ingest.DefaultBundleSize {
			_, _ = v.tileCache.PruneBefore(targetInputSize)
		}
	}

	v.updateMetrics(nextOutputSize, targetInputSize, *latestInCP)
	return nil
}

func (v *Verifier) verifyGenesisBackfillLeaf(
	ctx context.Context,
	leafIdx uint64,
	outLeaf *wire.OutputLogLeaf,
	targetInputSize uint64,
	latestInCP *log.Checkpoint,
	latestInHash [sha256.Size]byte,
) error {
	if !v.hasFrom {
		if err := v.db.SetUint64(keyVerifierFrom, outLeaf.From); err != nil {
			return err
		}
		v.hasFrom = true
		v.verifiedFrom = outLeaf.From
	}
	kvSize, err := v.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return err
	}
	if v.mptMgr.PersistedSize() < kvSize || !v.mptMgr.IsExact() {
		if err := v.catchUpMPT(ctx, kvSize, latestInCP.Size, latestInHash); err != nil {
			return err
		}
	}
	startInputSize := max(min(kvSize, v.mptMgr.PersistedSize()), outLeaf.From)

	var activeBuffer map[string][sha256.Size]byte
	if targetInputSize > startInputSize {
		setFetcherTreeState(v.inputFetcher, latestInCP.Size, latestInHash)
		batchChan, errChan := v.pipeline.StreamBatches(ctx, startInputSize, targetInputSize)

		activeBuffer = make(map[string][sha256.Size]byte)
		var pending *ingest.MappedBatch
		leavesSinceFlush := uint64(0)

		flushSlab := func() error {
			if pending == nil || pending.EndLeafIdx <= pending.StartLeafIdx {
				return nil
			}
			res, err := v.indexer.IndexMappedBatch(ctx, &kvstore.MappedBatch{
				StartLeafIdx: pending.StartLeafIdx,
				EndLeafIdx:   pending.EndLeafIdx,
				KeyIndices:   pending.KeyIndices,
			}, nil, targetInputSize)
			if err != nil {
				return err
			}
			leavesSinceFlush += uint64(pending.Count)
			maps.Copy(activeBuffer, res.ModifiedKeyValueRoots)
			pending = nil
			if res.NewKVSize < targetInputSize && leavesSinceFlush >= v.cfg.CoarseCheckpointInterval {
				if err := v.db.Sync(); err != nil {
					return err
				}
				if err := v.mptMgr.SetKeyBatch(activeBuffer); err != nil {
					return err
				}
				if res.NewKVSize > math.MaxInt64 {
					return v.halt(fmt.Errorf("KV size %d overflows int64 MPT version", res.NewKVSize))
				}
				if _, err := v.mptMgr.Snap(int64(res.NewKVSize)); err != nil {
					return err
				}
				if err := v.mptMgr.Persist(); err != nil {
					return err
				}
				clear(activeBuffer)
				leavesSinceFlush = 0
			}
			return nil
		}

		for batch := range batchChan {
			if pending == nil {
				pending = batch
			} else {
				pending.Merge(batch)
			}
			if pending.EndLeafIdx-pending.StartLeafIdx >= v.cfg.CommitBatchSize {
				if err := flushSlab(); err != nil {
					return err
				}
			}
		}
		if err := <-errChan; err != nil {
			if isFatalWASMError(err) {
				return v.halt(fmt.Errorf("deterministic WASM fault for genesis leaf %d: %w", leafIdx, err))
			}
			return fmt.Errorf("genesis input streaming failed for leaf %d [%d, %d): %w", leafIdx, startInputSize, targetInputSize, err)
		}
		if err := flushSlab(); err != nil {
			return err
		}
	}
	if err := v.db.Sync(); err != nil {
		return err
	}

	mptBatch, err := mpt.PrepareBatch(activeBuffer)
	if err != nil {
		return err
	}
	localMPTRoot, err := v.mptMgr.PredictBatch(mptBatch)
	if err != nil {
		return fmt.Errorf("genesis MPT predict failed at leaf %d: %w", leafIdx, err)
	}
	if localMPTRoot != outLeaf.MPTRoot {
		return v.handleRootMismatch(leafIdx, targetInputSize, localMPTRoot, outLeaf.MPTRoot)
	}

	nextOutputSize := leafIdx + 1
	metaBatch := v.db.NewIndexedBatch()
	defer func() { _ = metaBatch.Close() }()
	if err := v.stageWatermarkMetadata(metaBatch, nextOutputSize, targetInputSize, outLeaf, localMPTRoot); err != nil {
		return err
	}
	if err := v.db.Apply(metaBatch, true); err != nil {
		return fmt.Errorf("failed to commit genesis watermarks: %w", err)
	}
	v.commitInMemoryWatermarks(nextOutputSize, targetInputSize, outLeaf, localMPTRoot)

	if targetInputSize > math.MaxInt64 {
		return v.halt(fmt.Errorf("genesis target input size %d overflows int64 MPT version", targetInputSize))
	}
	if _, err := v.mptMgr.CommitBatchAndPersist(mptBatch, int64(targetInputSize), nil); err != nil {
		return fmt.Errorf("genesis MPT commit/persist failed: %w", err)
	}
	if v.tileCache != nil && targetInputSize >= ingest.DefaultBundleSize {
		_, _ = v.tileCache.PruneBefore(targetInputSize)
	}
	v.updateMetrics(nextOutputSize, targetInputSize, latestInCP)
	return nil
}

func (v *Verifier) stageWatermarkMetadata(
	b *kvstore.Batch,
	nextOutputSize, targetInputSize uint64,
	outLeaf *wire.OutputLogLeaf,
	localMPTRoot [sha256.Size]byte,
) error {
	if targetInputSize > v.verifiedInputSize {
		if err := b.SetUint64(kvstore.KeyMetaKVSize, targetInputSize); err != nil {
			return err
		}
	}
	if err := b.SetUint64(keyVerifierOutputWatermark, nextOutputSize); err != nil {
		return err
	}
	if err := b.SetUint64(keyVerifierInputWatermark, targetInputSize); err != nil {
		return err
	}
	if err := b.Set(keyVerifierInputHash, outLeaf.InputRoot[:]); err != nil {
		return err
	}
	if err := b.Set(keyVerifierLastRoot, localMPTRoot[:]); err != nil {
		return err
	}
	if err := b.SetUint64(keyVerifierFrom, outLeaf.From); err != nil {
		return err
	}
	return b.Set(keyVerifierInputOrigin, []byte(outLeaf.InputOrigin))
}

func (v *Verifier) commitInMemoryWatermarks(
	nextOutputSize, targetInputSize uint64,
	outLeaf *wire.OutputLogLeaf,
	localMPTRoot [sha256.Size]byte,
) {
	v.verifiedInputHash = outLeaf.InputRoot
	v.hasFrom = true
	v.verifiedFrom = outLeaf.From
	v.hasOrigin = true
	v.verifiedInputOrigin = outLeaf.InputOrigin

	v.stateMu.Lock()
	v.verifiedInputSize = targetInputSize
	v.verifiedOutputSize = nextOutputSize
	v.lastVerifiedRoot = localMPTRoot
	v.stateMu.Unlock()
}

func (v *Verifier) updateMetrics(nextOutputSize, targetInputSize uint64, latestInCP *log.Checkpoint) {
	metrics.ResetAuditorRootMismatch()
	metrics.OutputTreeSize.Set(float64(nextOutputSize))
	metrics.ServingTreeSize.Set(float64(targetInputSize))
	metrics.KVCommittedSize.Set(float64(targetInputSize))
	if latestInCP != nil && latestInCP.Size >= targetInputSize {
		metrics.IndexingLag.Set(float64(latestInCP.Size - targetInputSize))
	} else {
		metrics.IndexingLag.Set(0)
	}
}

// Run executes the periodic polling loop and optionally serves operational endpoints on MetricsAddr.
func (v *Verifier) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	if v.cfg.MetricsAddr != "" {
		ln, err := net.Listen("tcp", v.cfg.MetricsAddr)
		if err != nil {
			return fmt.Errorf("auditor admin listener failed on %s: %w", v.cfg.MetricsAddr, err)
		}
		actualAddr := ln.Addr().String()
		mServer := server.NewHTTPServer(actualAddr, v.AdminHandler())
		g.Go(func() error {
			klog.Infof("Serving auditor metrics at http://%s/metrics", actualAddr)
			errCh := make(chan error, 1)
			go func() {
				if sErr := mServer.Serve(ln); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
					errCh <- sErr
				}
				close(errCh)
			}()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return mServer.Shutdown(shutdownCtx)
			case sErr := <-errCh:
				return sErr
			}
		})
	}

	g.Go(func() error {
		runPass := func() error {
			if err := v.VerifyOnce(ctx); err != nil {
				if v.haltError() != nil || errors.Is(err, ErrRootMismatch) {
					klog.Errorf("Auditor sync engine permanently halted: %v", err)
					<-ctx.Done()
					return err
				}
				if ctx.Err() == nil {
					klog.Warningf("Auditor transient poll warning: %v", err)
				}
			}
			return nil
		}
		if err := runPass(); err != nil {
			return err
		}

		ticker := time.NewTicker(v.cfg.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				if err := runPass(); err != nil {
					return err
				}
			}
		}
	})

	return g.Wait()
}

func (v *Verifier) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte("ok\n"))
	}
}

func (v *Verifier) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	st := v.Status()
	if st.IsHalted {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method == http.MethodGet {
			var rmErr *RootMismatchError
			if errors.As(st.HaltError, &rmErr) {
				_, _ = w.Write(rmErr.JSONDiagnostics())
			} else {
				errMsg := "auditor halted"
				if st.HaltError != nil {
					errMsg = st.HaltError.Error()
				}
				b, _ := json.Marshal(struct {
					Status string `json:"status"`
					Error  string `json:"error"`
				}{Status: "halted", Error: errMsg})
				_, _ = w.Write(append(b, '\n'))
			}
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// AdminHandler returns an http.Handler serving /metrics, /healthz, /readyz, and /debug/pprof/*.
func (v *Verifier) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", v.handleHealthz)
	mux.HandleFunc("/readyz", v.handleReadyz)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// Status returns a thread-safe snapshot of the auditor's operational status.
func (v *Verifier) Status() Status {
	v.stateMu.RLock()
	defer v.stateMu.RUnlock()
	return Status{
		IsHalted:           v.isHalted,
		HaltError:          v.haltErr,
		VerifiedOutputSize: v.verifiedOutputSize,
		VerifiedInputSize:  v.verifiedInputSize,
		LastVerifiedRoot:   v.lastVerifiedRoot,
	}
}

// Close closes owned storage resources (Pebble database and MPT manager).
func (v *Verifier) Close() error {
	v.syncMu.Lock()
	defer v.syncMu.Unlock()

	if v.closed {
		return nil
	}
	v.closed = true

	var errs []error
	if v.db != nil {
		if err := v.db.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if v.mptMgr != nil {
		if err := v.mptMgr.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
