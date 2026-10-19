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

package hammer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

const (
	defaultSequencerOrigin     = "example.com/hammer/inputlog"
	sequencerBatchTimeout      = 10 * time.Millisecond
	sequencerCheckpointPeriod  = 100 * time.Millisecond
	sequencerAwaitPollInterval = 10 * time.Millisecond
	maxCachedKnownRoots        = 65536
)

// SequencerConfig configures the Tessera input log sequencer.
type SequencerConfig struct {
	StorageDir           string
	Origin               string
	SignerKey            string
	WriteRate            float64 // Leaves per second (0 = unconstrained)
	WriteGoal            uint64  // Total leaves to write before stopping (0 = continuous)
	BatchSize            uint
	MaxOracleOccurrences uint64
}

// SequencerStats holds telemetry counters.
type SequencerStats struct {
	LeavesWritten      uint64
	CheckpointsCreated uint64
	LatestTreeSize     uint64
}

type pendingSequencedEntry struct {
	fut  tessera.IndexFuture
	keys []string
}

// Sequencer writes generated leaves to a local Tessera POSIX log and feeds a pure-Go MapFn Oracle.
type Sequencer struct {
	cfg         SequencerConfig
	generator   *Generator
	oracle      *Oracle
	appCtx      context.Context
	appCancel   context.CancelFunc
	appender    *tessera.Appender
	shutdownFn  func(context.Context) error
	reader      tessera.LogReader
	awaiter     *tessera.PublicationAwaiter
	verifier    note.Verifier
	verifierKey string

	leavesWritten      atomic.Uint64
	checkpointsCreated atomic.Uint64
	latestTreeSize     atomic.Uint64
	activeCollectors   atomic.Int32

	mu              sync.Mutex
	latestRoot      [sha256.Size]byte
	knownRoots      map[uint64][sha256.Size]byte
	collectorDoneCh chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

// NewSequencer initializes a new Tessera POSIX sequencer and pure-Go ground-truth Oracle.
func NewSequencer(ctx context.Context, cfg SequencerConfig, gen *Generator) (*Sequencer, error) {
	cfg.Origin = strings.TrimSpace(cfg.Origin)
	cfg.SignerKey = strings.TrimSpace(cfg.SignerKey)
	if cfg.Origin == "" && cfg.SignerKey == "" {
		cfg.Origin = defaultSequencerOrigin
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 4096
	}

	signer, verifier, vkey, err := parseOrGenerateKey(cfg.SignerKey, cfg.Origin)
	if err != nil {
		return nil, err
	}
	if cfg.Origin == "" {
		cfg.Origin = signer.Name()
	} else if cfg.Origin != signer.Name() {
		return nil, fmt.Errorf("input log origin %q does not match signer key name %q", cfg.Origin, signer.Name())
	}
	if err := wire.ValidateInputOrigin(cfg.Origin); err != nil {
		return nil, fmt.Errorf("invalid input log origin %q: %w", cfg.Origin, err)
	}

	appCtx, appCancel := context.WithCancel(context.Background())
	stopInit := context.AfterFunc(ctx, appCancel)

	driver, err := posix.New(appCtx, posix.Config{Path: cfg.StorageDir})
	if err != nil {
		stopInit()
		appCancel()
		return nil, fmt.Errorf("failed to initialize POSIX log at %q: %w", cfg.StorageDir, err)
	}

	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCheckpointInterval(sequencerCheckpointPeriod).
		WithBatching(cfg.BatchSize, sequencerBatchTimeout)

	appender, shutdownFn, reader, err := tessera.NewAppender(appCtx, driver, appendOpts)
	stopInit()
	if err != nil {
		appCancel()
		return nil, fmt.Errorf("failed to initialize Tessera appender: %w", err)
	}

	var leafFmt LeafFormat
	if gen != nil {
		leafFmt = gen.LeafFormat()
	}
	oracle := NewOracle(MapFnForFormat(leafFmt), cfg.MaxOracleOccurrences)

	knownRoots := make(map[uint64][sha256.Size]byte, 64)
	knownRoots[0] = wire.EmptyRoot()
	doneCh := make(chan struct{})
	close(doneCh)

	s := &Sequencer{
		cfg:             cfg,
		generator:       gen,
		oracle:          oracle,
		appCtx:          appCtx,
		appCancel:       appCancel,
		appender:        appender,
		shutdownFn:      shutdownFn,
		reader:          reader,
		awaiter:         tessera.NewPublicationAwaiter(appCtx, reader.ReadCheckpoint, sequencerAwaitPollInterval),
		verifier:        verifier,
		verifierKey:     vkey,
		latestRoot:      wire.EmptyRoot(),
		knownRoots:      knownRoots,
		collectorDoneCh: doneCh,
	}
	oracle.SetInputStateVerifier(s.VerifyInputState)

	if _, parsed, cpErr := s.readAndObserveCheckpoint(ctx); cpErr == nil && parsed != nil && parsed.Size > 0 {
		if rErr := s.replayExistingEntries(ctx, parsed.Size); rErr != nil {
			_ = s.Close(ctx)
			return nil, fmt.Errorf("failed to replay existing input log entries [0, %d): %w", parsed.Size, rErr)
		}
	}
	return s, nil
}

func (s *Sequencer) replayExistingEntries(ctx context.Context, treeSize uint64) error {
	numBundles := (treeSize + layout.EntryBundleWidth - 1) / layout.EntryBundleWidth
	for bIdx := range numBundles {
		bundle, err := tclient.GetEntryBundle(ctx, s.reader.ReadEntryBundle, bIdx, treeSize)
		if err != nil {
			return fmt.Errorf("read entry bundle %d: %w", bIdx, err)
		}
		baseIdx := bIdx * layout.EntryBundleWidth
		for offset, rawEntry := range bundle.Entries {
			entryIdx := baseIdx + uint64(offset)
			if entryIdx >= treeSize {
				break
			}
			if err := s.oracle.MapAndRecord(entryIdx, rawEntry); err != nil {
				return fmt.Errorf("map entry %d: %w", entryIdx, err)
			}
		}
	}
	return nil
}

func parseOrGenerateKey(rawOrPath, origin string) (note.Signer, note.Verifier, string, error) {
	skey := strings.TrimSpace(rawOrPath)
	var vkey string
	if skey == "" {
		var err error
		skey, vkey, err = note.GenerateKey(rand.Reader, origin)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to generate note key: %w", err)
		}
	} else {
		isFilePath := strings.Count(skey, "+") < 2
		if !isFilePath {
			if info, err := os.Stat(skey); err == nil && !info.IsDir() {
				isFilePath = true
			}
		}
		if isFilePath {
			data, err := os.ReadFile(skey)
			if err != nil {
				return nil, nil, "", fmt.Errorf("failed to read signer key file %q: %w", skey, err)
			}
			skey = string(bytes.TrimSpace(data))
		}
	}

	signer, verifier, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse signer key: %w", err)
	}
	if vkey == "" {
		parts := strings.SplitN(skey, "+", 5)
		if len(parts) == 5 && parts[0] == "PRIVATE" && parts[1] == "KEY" {
			if raw, decErr := base64.StdEncoding.DecodeString(parts[4]); decErr == nil && len(raw) == 1+ed25519.SeedSize && raw[0] == 0x01 {
				pub := ed25519.NewKeyFromSeed(raw[1:]).Public().(ed25519.PublicKey)
				vkey, _ = note.NewEd25519VerifierKey(signer.Name(), pub)
			}
		}
	}
	return signer, verifier, vkey, nil
}

// Oracle returns the pure-Go ground-truth Oracle populated by this Sequencer.
func (s *Sequencer) Oracle() *Oracle { return s.oracle }

// Verifier returns the note verifier for Input Log checkpoints.
func (s *Sequencer) Verifier() note.Verifier { return s.verifier }

// VerifierKey returns the public note verifier key string.
func (s *Sequencer) VerifierKey() string { return s.verifierKey }

// Origin returns the origin string for the Input Log.
func (s *Sequencer) Origin() string { return s.cfg.Origin }

// Stats returns a snapshot of current sequencer stats.
func (s *Sequencer) Stats() SequencerStats {
	return SequencerStats{
		LeavesWritten:      s.leavesWritten.Load(),
		CheckpointsCreated: s.checkpointsCreated.Load(),
		LatestTreeSize:     s.latestTreeSize.Load(),
	}
}

func (s *Sequencer) readAndObserveCheckpoint(ctx context.Context) ([]byte, *log.Checkpoint, error) {
	rawCP, err := s.reader.ReadCheckpoint(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(rawCP) == 0 {
		return nil, nil, nil
	}
	parsed := s.observeCheckpoint(rawCP)
	return rawCP, parsed, nil
}

// ReadCheckpoint reads the latest signed checkpoint from the underlying Tessera POSIX log,
// ensuring the pure-Go Oracle has recorded all entries in [0, cp.Size) before exposing the checkpoint.
func (s *Sequencer) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	rawCP, parsed, err := s.readAndObserveCheckpoint(ctx)
	if err != nil || len(rawCP) == 0 || parsed == nil {
		return rawCP, err
	}
	if err := s.waitForOracleSize(ctx, parsed.Size); err != nil {
		return nil, err
	}
	return rawCP, nil
}

func (s *Sequencer) waitForOracleSize(ctx context.Context, targetSize uint64) error {
	for s.oracle.ContiguousSize() < targetSize {
		s.mu.Lock()
		doneCh := s.collectorDoneCh
		s.mu.Unlock()
		if s.oracle.ContiguousSize() >= targetSize {
			return nil
		}
		if s.activeCollectors.Load() == 0 {
			if s.oracle.ContiguousSize() >= targetSize {
				return nil
			}
			return fmt.Errorf("oracle contiguous size %d lags checkpoint size %d with no active collector", s.oracle.ContiguousSize(), targetSize)
		}

		s.oracle.mu.RLock()
		waitCh := s.oracle.waitCh
		cur := s.oracle.nextExpected
		s.oracle.mu.RUnlock()
		if cur >= targetSize {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneCh:
		case <-waitCh:
		}
	}
	return nil
}

// VerifyInputState verifies that (inputSize, inputRoot) committed in a VIndex state commitment
// matches or is Merkle-consistent with the hammer's own Input Log.
func (s *Sequencer) VerifyInputState(ctx context.Context, inputSize uint64, inputRoot [sha256.Size]byte) error {
	if inputSize == 0 {
		if inputRoot != wire.EmptyRoot() {
			return fmt.Errorf("non-empty input-root %x at input-size 0", inputRoot)
		}
		return nil
	}

	s.mu.Lock()
	if want, ok := s.knownRoots[inputSize]; ok {
		s.mu.Unlock()
		if inputRoot != want {
			return fmt.Errorf("input-root %x at size %d != hammer input log root %x", inputRoot, inputSize, want)
		}
		return nil
	}
	latestSize := s.latestTreeSize.Load()
	latestRoot := s.latestRoot
	s.mu.Unlock()

	if inputSize > latestSize {
		if _, _, err := s.readAndObserveCheckpoint(ctx); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to refresh hammer input log checkpoint: %w", err)
		}
		s.mu.Lock()
		if want, ok := s.knownRoots[inputSize]; ok {
			s.mu.Unlock()
			if inputRoot != want {
				return fmt.Errorf("input-root %x at size %d != hammer input log root %x", inputRoot, inputSize, want)
			}
			return nil
		}
		latestSize = s.latestTreeSize.Load()
		latestRoot = s.latestRoot
		s.mu.Unlock()
	}

	if inputSize > latestSize {
		return fmt.Errorf("committed input-size %d exceeds hammer input log size %d", inputSize, latestSize)
	}
	if inputSize == latestSize {
		if inputRoot != latestRoot {
			return fmt.Errorf("input-root %x at size %d != hammer input log root %x", inputRoot, inputSize, latestRoot)
		}
		return nil
	}

	pb, err := tclient.NewProofBuilder(ctx, latestSize, s.reader.ReadTile)
	if err != nil {
		return fmt.Errorf("failed to create input log proof builder at size %d: %w", latestSize, err)
	}
	consProof, err := pb.ConsistencyProof(ctx, inputSize, latestSize)
	if err != nil {
		return fmt.Errorf("failed to build input log consistency proof (%d -> %d): %w", inputSize, latestSize, err)
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, inputSize, latestSize, consProof, inputRoot[:], latestRoot[:]); err != nil {
		return fmt.Errorf("input-root %x at size %d is not Merkle-consistent with hammer input log size %d (%x): %w",
			inputRoot, inputSize, latestSize, latestRoot, err)
	}

	s.mu.Lock()
	if len(s.knownRoots) >= maxCachedKnownRoots {
		clear(s.knownRoots)
		s.knownRoots[0] = wire.EmptyRoot()
	}
	s.knownRoots[inputSize] = inputRoot
	s.mu.Unlock()
	return nil
}

// RunLoop continuously writes generated leaves at cfg.WriteRate until ctx is cancelled or WriteGoal is reached.
func (s *Sequencer) RunLoop(ctx context.Context) error {
	var writeTicker *time.Ticker
	if s.cfg.WriteRate > 0 {
		writeTicker = time.NewTicker(rateToInterval(s.cfg.WriteRate, time.Microsecond))
		defer writeTicker.Stop()
	}

	cpTicker := time.NewTicker(sequencerCheckpointPeriod)
	defer cpTicker.Stop()

	queueCap := int(min(max(s.cfg.BatchSize*2, 128), 16384))
	workCh := make(chan pendingSequencedEntry, queueCap)
	doneCh := make(chan struct{})

	s.mu.Lock()
	s.collectorDoneCh = doneCh
	s.mu.Unlock()
	s.activeCollectors.Add(1)

	var collectorErr atomic.Pointer[error]
	go func() {
		defer func() {
			s.activeCollectors.Add(-1)
			close(doneCh)
		}()
		for item := range workCh {
			if collectorErr.Load() != nil {
				continue
			}
			idx, err := item.fut()
			if err != nil {
				wrapped := fmt.Errorf("tessera entry sequencing failed: %w", err)
				collectorErr.CompareAndSwap(nil, &wrapped)
				continue
			}
			s.oracle.Record(idx.Index, item.keys)
		}
	}()

	finishCollector := func() error {
		close(workCh)
		<-doneCh
		if ep := collectorErr.Load(); ep != nil {
			return *ep
		}
		return nil
	}

	var lastFut tessera.IndexFuture
	var submitted uint64

	for {
		if ep := collectorErr.Load(); ep != nil {
			_ = finishCollector()
			return *ep
		}

		if s.cfg.WriteGoal > 0 && submitted >= s.cfg.WriteGoal {
			if err := finishCollector(); err != nil {
				return err
			}
			if lastFut != nil {
				_, cpBytes, err := s.awaiter.Await(ctx, lastFut)
				if err != nil {
					return fmt.Errorf("failed to await checkpoint for write goal %d: %w", s.cfg.WriteGoal, err)
				}
				if len(cpBytes) > 0 {
					s.observeCheckpoint(cpBytes)
				}
			}
			return nil
		}

		if writeTicker != nil {
			select {
			case <-ctx.Done():
				if err := finishCollector(); err != nil {
					return err
				}
				return ctx.Err()
			case <-cpTicker.C:
				_, _, _ = s.readAndObserveCheckpoint(ctx)
				continue
			case <-writeTicker.C:
			}
		} else {
			select {
			case <-ctx.Done():
				if err := finishCollector(); err != nil {
					return err
				}
				return ctx.Err()
			case <-cpTicker.C:
				_, _, _ = s.readAndObserveCheckpoint(ctx)
			default:
			}
		}

		if err := ctx.Err(); err != nil {
			if cErr := finishCollector(); cErr != nil {
				return cErr
			}
			return err
		}

		leaf := s.generator.NextLeaf()
		keys, err := s.oracle.MapLeaf(leaf.LeafData)
		if err != nil {
			_ = finishCollector()
			return fmt.Errorf("pure-Go MapFn failed on generated leaf: %w", err)
		}
		fut := s.appender.Add(s.appCtx, tessera.NewEntry(leaf.LeafData))
		lastFut = fut
		submitted++
		s.leavesWritten.Add(1)

		// Once submitted to Tessera, the entry MUST reach the collector so the Oracle never misses an assigned index.
		workCh <- pendingSequencedEntry{fut: fut, keys: keys}
	}
}

func (s *Sequencer) observeCheckpoint(rawCP []byte) *log.Checkpoint {
	parsed, _, _, err := log.ParseCheckpoint(rawCP, s.cfg.Origin, s.verifier)
	if err != nil || len(parsed.Hash) != sha256.Size {
		return nil
	}

	var root [sha256.Size]byte
	copy(root[:], parsed.Hash)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.knownRoots) >= maxCachedKnownRoots {
		clear(s.knownRoots)
		s.knownRoots[0] = wire.EmptyRoot()
	}
	s.knownRoots[parsed.Size] = root
	if parsed.Size > s.latestTreeSize.Load() {
		s.latestTreeSize.Store(parsed.Size)
		s.latestRoot = root
		s.checkpointsCreated.Add(1)
		klog.V(2).Infof("Sequencer observed checkpoint size %d", parsed.Size)
	}
	return parsed
}

// Close shuts down the Tessera appender gracefully before cancelling its storage context.
func (s *Sequencer) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		if s.shutdownFn != nil {
			sCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			s.closeErr = s.shutdownFn(sCtx)
			cancel()
		}
		if s.appCancel != nil {
			s.appCancel()
		}
	})
	return s.closeErr
}
