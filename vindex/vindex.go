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

// Package vindex provides the public embedder API for the Verifiable Index.
package vindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// WASMHost manages compiled WebAssembly modules and a bounded pool of reusable instances for bundle mapping.
type WASMHost = wasmhost.WASMHost

// NewWASMHost compiles a WASM binary and initializes a pool of instances.
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	return wasmhost.NewWASMHost(ctx, wasmBytes, poolSize)
}

// CheckpointPolicy verifies signed checkpoints (primary log signature plus optional witness quorum).
type CheckpointPolicy interface {
	Verify(checkpoint []byte) (*log.Checkpoint, error)
}

// ParsePrefixPolicy parses a named prefix query policy ("allow", "none", or "reversed-dns")
// into a validation function suitable for ServeOptions.PrefixPolicyFunc.
func ParsePrefixPolicy(name string) (func(prefix string) error, error) {
	return server.ParsePrefixPolicy(name)
}

// StorageConfig specifies the required local persistence paths and optional tile cache path for an Engine.
type StorageConfig struct {
	// DBPath is the required directory path for the Pebble KV store.
	DBPath string
	// MPTDir is the required directory path for MPT persistence files (use ":memory:" only in ephemeral tests).
	MPTDir string
	// OutputLogDir is the required directory path for POSIX Output Log tiles and checkpoints.
	OutputLogDir string
	// TileCacheDir is an optional directory path for persistent Input Log leaf bundle caching.
	TileCacheDir string
}

// ServeOptions configures the HTTP read server behavior exposed by Engine.Handler().
// Zero values select standard defaults (root path, UI enabled, allow-all prefix policy, default max prefix keys).
type ServeOptions struct {
	PathPrefix       string
	DisableUI        bool
	ServeOutputTiles bool
	PrefixPolicyFunc func(prefix string) error
	MaxPrefixKeys    int
}

// TuningOptions configures optional indexing, batching, caching, and concurrency parameters.
// Zero values select automatic defaults.
type TuningOptions struct {
	PollInterval             time.Duration
	ChunkSize                uint64
	CommitBatchSize          uint64
	CoarseCheckpointInterval uint64
	BackfillMaxPendingKeys   uint64
	Workers                  int
	KVIndexerWorkers         int
	FetchWorkers             int
	FetchBatchBundles        int
	DBCacheSizeMB            int
	DBMaxOpenFiles           int
	DisableReaper            bool
}

type engineOptions struct {
	hasInputLog         bool
	unverifiedInput     bool
	inputURL            string
	inputPolicy         CheckpointPolicy
	unverifiedOrigin    string
	explicitInputOrigin string
	wasmHost            *WASMHost
	staticCT            *bool

	hasFrom bool
	from    uint64

	hasOutWitnessPolicy bool
	outWitnessPolicy    []byte
	hasOutWitnesses     bool
	outVerifier         note.Verifier
	witnessURLs         []string
	witnessPubKeys      []string

	serve  ServeOptions
	tuning TuningOptions
	errs   []error
}

// Option configures optional Engine behavior.
type Option func(*engineOptions)

// WithInputLog configures verified ingestion from an upstream C2SP tlog-tiles or Static-CT Input Log.
func WithInputLog(rawURL string, policy CheckpointPolicy, wasm *WASMHost) Option {
	return func(o *engineOptions) {
		if o.hasInputLog {
			o.errs = append(o.errs, errors.New("cannot specify multiple Input Log options (WithInputLog / WithUnverifiedInputLog)"))
			return
		}
		o.hasInputLog = true
		o.inputURL = rawURL
		o.inputPolicy = policy
		o.wasmHost = wasm
	}
}

// WithUnverifiedInputLog configures ingestion from an upstream Input Log without verifying checkpoint signatures.
// Intended strictly for local development and testing.
func WithUnverifiedInputLog(rawURL, origin string, wasm *WASMHost) Option {
	return func(o *engineOptions) {
		if o.hasInputLog {
			o.errs = append(o.errs, errors.New("cannot specify multiple Input Log options (WithInputLog / WithUnverifiedInputLog)"))
			return
		}
		o.hasInputLog = true
		o.unverifiedInput = true
		o.inputURL = rawURL
		o.unverifiedOrigin = origin
		o.wasmHost = wasm
	}
}

// WithInputOrigin explicitly sets the expected Input Log origin string.
// Required when WithInputLog uses a multi-log CheckpointPolicy; optional when the policy binds a single log origin.
func WithInputOrigin(origin string) Option {
	return func(o *engineOptions) {
		o.explicitInputOrigin = origin
	}
}

// WithStaticCT overrides automatic Input Log tile layout detection (true forces Static-CT tile/data layout;
// false forces standard C2SP tlog-tiles tile/entries layout).
func WithStaticCT(enabled bool) Option {
	return func(o *engineOptions) {
		v := enabled
		o.staticCT = &v
	}
}

// WithFrom sets the inclusive starting Input Log leaf index (from) committed in Output Log entries.
func WithFrom(from uint64) Option {
	return func(o *engineOptions) {
		o.hasFrom = true
		o.from = from
	}
}

// WithOutputWitnessPolicy configures Output Log witness quorum cosigning and checkpoint verification
// from a C2SP tlog-policy document.
func WithOutputWitnessPolicy(policy []byte) Option {
	return func(o *engineOptions) {
		if o.hasOutWitnessPolicy || o.hasOutWitnesses {
			o.errs = append(o.errs, errors.New("cannot combine multiple Output Log witness options"))
			return
		}
		o.hasOutWitnessPolicy = true
		o.outWitnessPolicy = bytes.Clone(policy)
	}
}

// WithOutputWitnesses configures N-of-N Output Log witness cosigning and verification from explicit
// witness HTTP URLs and verifier public keys.
func WithOutputWitnesses(outVerifier note.Verifier, urls, pubKeys []string) Option {
	return func(o *engineOptions) {
		if o.hasOutWitnessPolicy || o.hasOutWitnesses {
			o.errs = append(o.errs, errors.New("cannot combine multiple Output Log witness options"))
			return
		}
		o.hasOutWitnesses = true
		o.outVerifier = outVerifier
		o.witnessURLs = slices.Clone(urls)
		o.witnessPubKeys = slices.Clone(pubKeys)
	}
}

// WithServing configures HTTP read handler behavior exposed by Engine.Handler().
func WithServing(opts ServeOptions) Option {
	return func(o *engineOptions) {
		o.serve = opts
	}
}

// WithTuning configures optional indexing, caching, and concurrency parameters.
func WithTuning(opts TuningOptions) Option {
	return func(o *engineOptions) {
		o.tuning = opts
	}
}

type originBoundPolicy struct {
	inner  wire.Policy
	origin string
}

func (p originBoundPolicy) Verify(raw []byte) (*log.Checkpoint, error) {
	cp, err := p.inner.Verify(raw)
	if err != nil {
		return nil, err
	}
	if cp == nil || len(cp.Hash) != sha256.Size {
		return nil, errors.New("checkpoint policy returned invalid checkpoint")
	}
	if p.origin != "" && cp.Origin != p.origin {
		return nil, fmt.Errorf("checkpoint origin %q != expected %q", cp.Origin, p.origin)
	}
	return cp, nil
}

func (p originBoundPolicy) Origin() string { return p.origin }

// Engine encapsulates the Verifiable Index storage, MPT, coordinator, and HTTP handler subsystems.
type Engine struct {
	pollInterval time.Duration
	db           *kvstore.DB
	mptMgr       *mpt.Manager
	outLog       *tree.POSIXOutputLog
	hasFetcher   bool
	coord        *coordinator.Coordinator
	server       *server.ReadServer
	reaper       *ingest.TileReaper

	closeCtx    context.Context
	closeCancel context.CancelFunc
	closeOnce   sync.Once
	closeErr    error

	opMu      sync.Mutex
	mu        sync.Mutex
	wg        sync.WaitGroup
	recovered bool
	running   bool
	closed    bool
}

// New initializes and wires all Engine subsystems.
// The caller retains ownership of any *WASMHost supplied via WithInputLog or WithUnverifiedInputLog.
func New(storage StorageConfig, outSigner note.Signer, opts ...Option) (_ *Engine, retErr error) {
	dbPath := strings.TrimSpace(storage.DBPath)
	if dbPath == "" {
		return nil, errors.New("StorageConfig.DBPath is required")
	}
	mptDir := strings.TrimSpace(storage.MPTDir)
	if mptDir == "" {
		return nil, errors.New("StorageConfig.MPTDir is required")
	}
	outLogDir := strings.TrimSpace(storage.OutputLogDir)
	if outLogDir == "" {
		return nil, errors.New("StorageConfig.OutputLogDir is required")
	}
	tileCacheDir := strings.TrimSpace(storage.TileCacheDir)

	if outSigner == nil {
		return nil, errors.New("outSigner is required")
	}
	outOrigin := outSigner.Name()
	if err := wire.ValidateInputOrigin(outOrigin); err != nil {
		return nil, fmt.Errorf("invalid Output Log signer origin %q: %w", outOrigin, err)
	}

	var o engineOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if len(o.errs) > 0 {
		return nil, errors.Join(o.errs...)
	}

	if o.tuning.ChunkSize == 0 {
		o.tuning.ChunkSize = kvstore.ChunkSize
	} else if o.tuning.ChunkSize > kvstore.ChunkSize {
		return nil, fmt.Errorf("TuningOptions.ChunkSize (%d) exceeds maximum %d", o.tuning.ChunkSize, kvstore.ChunkSize)
	}
	if o.from > math.MaxInt64 {
		return nil, fmt.Errorf("from (%d) overflows int64", o.from)
	}
	if o.tuning.Workers <= 0 {
		o.tuning.Workers = max(runtime.GOMAXPROCS(0)-1, 1)
	}
	if o.tuning.PollInterval <= 0 {
		o.tuning.PollInterval = 10 * time.Second
	}

	prefixPol := o.serve.PrefixPolicyFunc

	// Validate Output Log witness policy / group before touching disk.
	posixOpts := []tree.POSIXOption{tree.WithOrigin(outOrigin)}
	var outPolicy wire.Policy
	switch {
	case o.hasOutWitnessPolicy:
		if len(bytes.TrimSpace(o.outWitnessPolicy)) == 0 {
			return nil, errors.New("output witness policy must not be empty")
		}
		wg, wErr := tree.BuildWitnessGroupFromPolicy(o.outWitnessPolicy)
		if wErr != nil {
			return nil, fmt.Errorf("failed to build witness group from output log policy: %w", wErr)
		}
		posixOpts = append(posixOpts, tree.WithWitnessGroup(wg))
		parsedOutPol, pErr := wire.ParsePolicy(o.outWitnessPolicy)
		if pErr != nil {
			return nil, fmt.Errorf("failed to parse output log policy: %w", pErr)
		}
		if polOrigin := wire.PolicyOrigin(parsedOutPol); polOrigin != "" && polOrigin != outOrigin {
			return nil, fmt.Errorf("output log policy origin %q does not match signer origin %q", polOrigin, outOrigin)
		}
		outPolicy = originBoundPolicy{inner: parsedOutPol, origin: outOrigin}

	case o.hasOutWitnesses:
		if len(o.witnessURLs) == 0 && len(o.witnessPubKeys) == 0 {
			return nil, errors.New("WithOutputWitnesses requires at least one witness URL and public key")
		}
		if o.outVerifier == nil {
			return nil, errors.New("WithOutputWitnesses requires non-nil outVerifier")
		}
		if o.outVerifier.Name() != outOrigin {
			return nil, fmt.Errorf("outVerifier origin %q does not match signer origin %q", o.outVerifier.Name(), outOrigin)
		}
		wg, wErr := tree.BuildWitnessGroup(o.witnessURLs, o.witnessPubKeys)
		if wErr != nil {
			return nil, fmt.Errorf("failed to build witness group: %w", wErr)
		}
		posixOpts = append(posixOpts, tree.WithWitnessGroup(wg))
		witnessVerifiers := make([]note.Verifier, 0, len(o.witnessPubKeys))
		for _, wpk := range o.witnessPubKeys {
			wv, wvErr := wire.ParseWitnessVerifier(wpk)
			if wvErr != nil {
				return nil, fmt.Errorf("failed to parse witness public key %q: %w", wpk, wvErr)
			}
			witnessVerifiers = append(witnessVerifiers, wv)
		}
		builtOutPol, bErr := wire.BuildPolicy(outOrigin, o.outVerifier, witnessVerifiers, len(witnessVerifiers))
		if bErr != nil {
			return nil, fmt.Errorf("failed to build output log policy: %w", bErr)
		}
		outPolicy = builtOutPol
	}

	// Validate Input Log URL, auth policy, WASM host, and origin before creating storage directories.
	explicitInOrigin := strings.TrimSpace(o.explicitInputOrigin)
	if explicitInOrigin != "" {
		if err := wire.ValidateInputOrigin(explicitInOrigin); err != nil {
			return nil, fmt.Errorf("invalid InputOrigin: %w", err)
		}
	}
	inOrigin := explicitInOrigin
	var fetcher ingest.TileFetcher
	if o.hasInputLog {
		rawURL := strings.TrimSpace(o.inputURL)
		if rawURL == "" {
			return nil, errors.New("input log URL is required")
		}
		u, uErr := url.Parse(rawURL)
		if uErr != nil {
			return nil, fmt.Errorf("invalid input log URL %q: %w", o.inputURL, uErr)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
			if u.Host == "" {
				return nil, fmt.Errorf("invalid input log URL %q: missing host", o.inputURL)
			}
		case "file":
			if (u.Host != "" && u.Host != "localhost") || u.Path == "" {
				return nil, fmt.Errorf("invalid file input log URL %q: expected file:///abs/path", o.inputURL)
			}
		default:
			return nil, fmt.Errorf("unsupported input log URL scheme %q: expected http, https, or file", u.Scheme)
		}
		if o.wasmHost == nil {
			return nil, errors.New("wasmHost is required when Input Log is configured")
		}

		var inPolicy wire.Policy
		if o.unverifiedInput {
			unvOrigin := strings.TrimSpace(o.unverifiedOrigin)
			if unvOrigin != "" {
				if err := wire.ValidateInputOrigin(unvOrigin); err != nil {
					return nil, fmt.Errorf("invalid unverified InputOrigin: %w", err)
				}
			}
			if inOrigin != "" && unvOrigin != "" && inOrigin != unvOrigin {
				return nil, fmt.Errorf("conflicting InputOrigin %q vs %q", unvOrigin, inOrigin)
			}
			if inOrigin == "" {
				inOrigin = unvOrigin
			}
		} else {
			if o.inputPolicy == nil {
				return nil, errors.New("input log CheckpointPolicy is required (or use WithUnverifiedInputLog)")
			}
			polOrigin := wire.PolicyOrigin(o.inputPolicy)
			if inOrigin == "" {
				inOrigin = polOrigin
			} else if polOrigin != "" && polOrigin != inOrigin {
				return nil, fmt.Errorf("input log policy origin %q != configured InputOrigin %q", polOrigin, inOrigin)
			}
			if inOrigin == "" {
				return nil, errors.New("WithInputOrigin is required when InputLog CheckpointPolicy contains multiple logs")
			}
			if err := wire.ValidateInputOrigin(inOrigin); err != nil {
				return nil, fmt.Errorf("invalid InputOrigin: %w", err)
			}
			inPolicy = originBoundPolicy{inner: o.inputPolicy, origin: inOrigin}
		}

		tFetcher, fErr := ingest.NewTiledFetcher(u, nil, inOrigin, nil)
		if fErr != nil {
			return nil, fmt.Errorf("failed to create tile fetcher for %q: %w", o.inputURL, fErr)
		}
		if inPolicy != nil {
			tFetcher.SetPolicy(inPolicy)
		} else {
			tFetcher.SetAllowUnverifiedCheckpoints(true)
		}
		if o.staticCT != nil {
			tFetcher.SetStaticCT(*o.staticCT)
		}
		fetcher = tFetcher
	}

	closeCtx, closeCancel := context.WithCancel(context.Background())
	e := &Engine{
		pollInterval: o.tuning.PollInterval,
		hasFetcher:   fetcher != nil,
		closeCtx:     closeCtx,
		closeCancel:  closeCancel,
	}
	defer func() {
		if retErr != nil {
			_ = e.Close()
		}
	}()

	db, err := kvstore.Open(dbPath, &kvstore.Options{
		CacheSizeMB:  o.tuning.DBCacheSizeMB,
		MaxOpenFiles: o.tuning.DBMaxOpenFiles,
		ChunkSize:    o.tuning.ChunkSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open KV store at %q: %w", dbPath, err)
	}
	e.db = db

	tileDir := ""
	if o.serve.ServeOutputTiles {
		tileDir = outLogDir
	}
	e.server = server.New(server.Config{
		Store:         db,
		OutputLogDir:  tileDir,
		PathPrefix:    o.serve.PathPrefix,
		DisableUI:     o.serve.DisableUI,
		PrefixPolicy:  prefixPol,
		MaxPrefixKeys: o.serve.MaxPrefixKeys,
	})

	mptMgr, err := mpt.Open(mptDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open MPT at %q: %w", mptDir, err)
	}
	e.mptMgr = mptMgr

	cache, err := ingest.NewManagedTileCache(tileCacheDir, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tile cache at %q: %w", tileCacheDir, err)
	}

	indexer := kvstore.NewKVIndexer(db)
	if o.tuning.KVIndexerWorkers > 0 {
		indexer.SetNumWorkers(o.tuning.KVIndexerWorkers)
	} else if o.tuning.Workers == 1 {
		indexer.SetNumWorkers(1)
	}

	posixLog, err := tree.NewPOSIXOutputLog(context.Background(), outLogDir, outSigner, posixOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to open POSIX output log at %q: %w", outLogDir, err)
	}
	e.outLog = posixLog

	pub := tree.NewOutputPublisher(mptMgr, posixLog)
	if inOrigin != "" {
		pub.SetInputOrigin(inOrigin)
	}
	if o.from > 0 {
		pub.SetFrom(o.from)
	}
	if outPolicy != nil {
		pub.SetOutputLogPolicy(outPolicy)
	}

	e.coord = coordinator.New(coordinator.Config{
		DB:                       db,
		MPT:                      mptMgr,
		OutputLog:                posixLog,
		Publisher:                pub,
		Indexer:                  indexer,
		Fetcher:                  fetcher,
		Cache:                    cache,
		WASMHost:                 o.wasmHost,
		CommitBatchSize:          o.tuning.CommitBatchSize,
		CoarseCheckpointInterval: o.tuning.CoarseCheckpointInterval,
		BackfillMaxPendingKeys:   o.tuning.BackfillMaxPendingKeys,
		Workers:                  o.tuning.Workers,
		FetchWorkers:             o.tuning.FetchWorkers,
		FetchBatchBundles:        o.tuning.FetchBatchBundles,
		ExplicitFrom:             o.hasFrom,
	})
	e.server.SetBackend(mptMgr, pub, e.coord.ReadinessCheck)

	if !o.tuning.DisableReaper {
		e.reaper = ingest.NewTileReaper(e.coord.SafeWatermark, cache)
	}
	return e, nil
}

func (e *Engine) withOp(ctx context.Context, fn func(context.Context) error) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("engine is closed")
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()

	opCtx, opCancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.closeCtx, opCancel)
	defer func() {
		stop()
		opCancel()
	}()
	return fn(opCtx)
}

// caller must hold e.opMu.
func (e *Engine) recoverIfNeededLocked(ctx context.Context) error {
	e.mu.Lock()
	alreadyRecovered := e.recovered
	e.mu.Unlock()
	if alreadyRecovered {
		return nil
	}
	if err := e.coord.Recover(ctx); err != nil {
		fErr := fmt.Errorf("startup recovery failed: %w", err)
		if ctx.Err() == nil || coordinator.IsFatalSyncError(err) {
			e.coord.RecordFatalError(fErr)
		}
		return fErr
	}
	e.mu.Lock()
	e.recovered = true
	e.mu.Unlock()
	return nil
}

// caller must hold e.opMu.
func (e *Engine) bootstrapSyncLocked(ctx context.Context) error {
	if err := e.recoverIfNeededLocked(ctx); err != nil {
		return err
	}
	if !e.hasFetcher {
		return nil
	}
	if err := e.coord.SyncOnce(ctx); err != nil {
		if coordinator.IsFatalSyncError(err) {
			fErr := fmt.Errorf("fatal initial sync error: %w", err)
			e.coord.RecordFatalError(fErr)
			return fErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		klog.Warningf("Initial sync error: %v", err)
	}
	return ctx.Err()
}

// SyncOnce executes startup recovery (if not yet run) followed by a single synchronization pass.
func (e *Engine) SyncOnce(ctx context.Context) error {
	return e.withOp(ctx, func(opCtx context.Context) error {
		e.opMu.Lock()
		defer e.opMu.Unlock()

		if err := e.recoverIfNeededLocked(opCtx); err != nil {
			return err
		}
		err := e.coord.SyncOnce(opCtx)
		if err != nil && coordinator.IsFatalSyncError(err) {
			e.coord.RecordFatalError(err)
		}
		return err
	})
}

// Start executes startup crash recovery, runs an initial sync pass, and starts background loops
// scoped to ctx (and halted on Close).
func (e *Engine) Start(ctx context.Context) error {
	return e.withOp(ctx, func(opCtx context.Context) error {
		e.opMu.Lock()
		defer e.opMu.Unlock()

		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return errors.New("engine is closed")
		}
		if e.running {
			e.mu.Unlock()
			return errors.New("engine is already running")
		}
		e.running = true
		e.mu.Unlock()

		if err := e.bootstrapSyncLocked(opCtx); err != nil {
			e.mu.Lock()
			e.running = false
			e.mu.Unlock()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		e.mu.Lock()
		if e.closed {
			e.running = false
			e.mu.Unlock()
			return errors.New("engine is closed")
		}
		bgCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(e.closeCtx, cancel)

		if e.hasFetcher {
			e.wg.Add(1)
			go func() {
				defer func() {
					stop()
					cancel()
					e.wg.Done()
				}()
				if err := e.coord.RunPollLoop(bgCtx, e.pollInterval); err != nil {
					klog.Errorf("Fatal background sync error, halting engine: %v", err)
				}
			}()
		} else {
			e.wg.Add(1)
			go func() {
				defer func() {
					stop()
					cancel()
					e.wg.Done()
				}()
				<-bgCtx.Done()
			}()
		}

		if e.reaper != nil {
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				_ = e.reaper.Run(bgCtx, 60*time.Second)
			}()
		}
		e.mu.Unlock()
		return nil
	})
}

// Run executes startup recovery and runs the coordinator synchronization loop synchronously until ctx is canceled.
func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("engine is closed")
	}
	if e.running {
		e.mu.Unlock()
		return errors.New("engine is already running")
	}
	e.running = true
	e.wg.Add(1)
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		e.wg.Done()
	}()

	runCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.closeCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	if e.reaper != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			_ = e.reaper.Run(runCtx, 60*time.Second)
		}()
	}

	e.opMu.Lock()
	err := e.bootstrapSyncLocked(runCtx)
	e.opMu.Unlock()
	if err != nil {
		if ctx.Err() != nil && !coordinator.IsFatalSyncError(err) {
			return nil
		}
		return err
	}

	return e.coord.RunPollLoop(runCtx, e.pollInterval)
}

// Close gracefully closes the engine, halting background loops and releasing owned storage resources.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()

		if e.closeCancel != nil {
			e.closeCancel()
		}
		e.wg.Wait()

		e.mu.Lock()
		e.running = false
		e.mu.Unlock()

		if e.server != nil {
			e.server.SetBackend(nil, nil, func() error { return errors.New("engine is closed") })
		}

		var errs []error
		if e.outLog != nil {
			if err := e.outLog.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close output log: %w", err))
			}
		}
		if e.mptMgr != nil {
			if err := e.mptMgr.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close MPT: %w", err))
			}
		}
		if e.db != nil {
			if err := e.db.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close KV store: %w", err))
			}
		}
		e.closeErr = errors.Join(errs...)
	})
	return e.closeErr
}

// Handler returns an http.Handler exposing the public read server endpoints (/keys, /values, /checkpoint, etc.).
func (e *Engine) Handler() http.Handler {
	if e.server == nil {
		return http.NewServeMux()
	}
	return e.server.Handler()
}

// AdminHandler returns an http.Handler exposing the internal operational endpoints (/healthz, /readyz, /metrics, /debug/pprof/*).
func (e *Engine) AdminHandler() http.Handler {
	if e.server == nil {
		return http.NewServeMux()
	}
	return e.server.AdminHandler()
}
