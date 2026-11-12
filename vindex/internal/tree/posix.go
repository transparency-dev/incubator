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

package tree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

type posixConfig struct {
	origin       string
	batchMaxSize uint16
	witnessGroup *tessera.WitnessGroup
}

// POSIXOption configures a POSIXOutputLog instance.
type POSIXOption func(*posixConfig)

// WithOrigin sets the origin string for the log.
func WithOrigin(origin string) POSIXOption {
	return func(c *posixConfig) {
		c.origin = origin
	}
}

// WithBatchMaxSize sets the maximum batch size for entry integration.
func WithBatchMaxSize(size uint16) POSIXOption {
	return func(c *posixConfig) {
		c.batchMaxSize = size
	}
}

// WithWitnessGroup configures mandatory (fail-closed) witness cosigning for published checkpoints.
func WithWitnessGroup(wg tessera.WitnessGroup) POSIXOption {
	return func(c *posixConfig) {
		c.witnessGroup = &wg
	}
}

// BuildWitnessGroupFromPolicy constructs a tessera.WitnessGroup from a C2SP tlog-policy / Sigsum policy document.
func BuildWitnessGroupFromPolicy(policy []byte) (tessera.WitnessGroup, error) {
	return tessera.NewWitnessGroupFromPolicy(policy)
}

// BuildWitnessGroup constructs a tessera.WitnessGroup requiring cosignatures from all configured witnesses.
func BuildWitnessGroup(urls, pubKeys []string) (tessera.WitnessGroup, error) {
	if len(urls) != len(pubKeys) {
		return tessera.WitnessGroup{}, fmt.Errorf("witness URLs count (%d) does not match witness pubkeys count (%d)", len(urls), len(pubKeys))
	}
	if len(urls) == 0 {
		return tessera.WitnessGroup{}, nil
	}

	seenEndpoints := make(map[string]struct{}, len(urls))
	seenKeys := make(map[uint32]struct{}, len(pubKeys))
	var wg tessera.WitnessGroup
	for i := range urls {
		rawURL := strings.TrimSpace(urls[i])
		pubKey := strings.TrimSpace(pubKeys[i])
		if rawURL == "" || pubKey == "" {
			return tessera.WitnessGroup{}, fmt.Errorf("witness URL and pubkey at index %d must not be empty", i)
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			return tessera.WitnessGroup{}, fmt.Errorf("invalid witness URL %q at index %d: %w", rawURL, i, err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return tessera.WitnessGroup{}, fmt.Errorf("invalid witness URL %q at index %d: must be http or https with non-empty host", rawURL, i)
		}
		normEndpoint := strings.ToLower(u.Scheme+"://"+u.Host) + strings.TrimRight(u.Path, "/")
		if _, dup := seenEndpoints[normEndpoint]; dup {
			return tessera.WitnessGroup{}, fmt.Errorf("duplicate witness URL %q at index %d", rawURL, i)
		}
		seenEndpoints[normEndpoint] = struct{}{}

		w, err := tessera.NewWitness(pubKey, u)
		if err != nil {
			return tessera.WitnessGroup{}, fmt.Errorf("invalid witness at index %d: %w", i, err)
		}
		if _, dup := seenKeys[w.Key.KeyHash()]; dup {
			return tessera.WitnessGroup{}, fmt.Errorf("duplicate witness pubkey %q at index %d", w.Key.Name(), i)
		}
		seenKeys[w.Key.KeyHash()] = struct{}{}
		// tessera.NewWitnessGroup's variadic parameter uses an unexported policyComponent
		// interface, so dynamic witness slices cannot be unpacked with "..."; fold 2-of-2 instead.
		if i == 0 {
			wg = tessera.NewWitnessGroup(1, w)
		} else {
			wg = tessera.NewWitnessGroup(2, wg, w)
		}
	}
	return wg, nil
}

// POSIXOutputLog wraps a Tessera POSIX-backed tile log for appending and serving output log commitments.
type POSIXOutputLog struct {
	appender     *tessera.Appender
	awaiter      *tessera.PublicationAwaiter
	logReader    tessera.LogReader
	hasWitnesses bool
	shutdown     func(context.Context) error
	cancel       context.CancelFunc
	closeOnce    sync.Once
	closeErr     error
}

var _ OutputLogClient = (*POSIXOutputLog)(nil)

// NewPOSIXOutputLog initializes and returns a new POSIXOutputLog.
func NewPOSIXOutputLog(ctx context.Context, storageDir string, signer note.Signer, opts ...POSIXOption) (*POSIXOutputLog, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}
	if storageDir == "" {
		return nil, errors.New("storageDir must not be empty")
	}

	cfg := posixConfig{
		batchMaxSize: 1,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.batchMaxSize == 0 {
		cfg.batchMaxSize = 1
	}

	if cfg.origin == "" {
		cfg.origin = signer.Name()
	} else if cfg.origin != signer.Name() {
		return nil, fmt.Errorf("configured origin %q does not match signer name %q", cfg.origin, signer.Name())
	}
	if err := wire.ValidateInputOrigin(cfg.origin); err != nil {
		return nil, fmt.Errorf("invalid output log origin %q: %w", cfg.origin, err)
	}

	driver, err := posix.New(ctx, posix.Config{Path: storageDir})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize posix storage: %w", err)
	}

	batchMaxAge := time.Millisecond
	if cfg.batchMaxSize > 1 {
		batchMaxAge = 10 * time.Millisecond
	}
	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(uint(cfg.batchMaxSize), batchMaxAge).
		WithCheckpointInterval(100 * time.Millisecond)

	if cfg.witnessGroup != nil {
		appendOpts.WithWitnesses(*cfg.witnessGroup, &tessera.WitnessOptions{FailOpen: false})
	}

	appCtx, cancel := context.WithCancel(context.Background())
	stopCancelOnInit := context.AfterFunc(ctx, cancel)
	appender, shutdown, logReader, err := tessera.NewAppender(appCtx, driver, appendOpts)
	stopCancelOnInit()
	if err != nil {
		cancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("failed to create appender: %w", err)
	}

	emptyRoot := wire.EmptyRoot()
	syntheticZeroCP := fmt.Appendf(nil, "%s\n0\n%s\n", cfg.origin, base64.StdEncoding.EncodeToString(emptyRoot[:]))
	awaiter := tessera.NewPublicationAwaiter(appCtx, func(rCtx context.Context) ([]byte, error) {
		cp, rErr := logReader.ReadCheckpoint(rCtx)
		if errors.Is(rErr, os.ErrNotExist) {
			return syntheticZeroCP, nil
		}
		return cp, rErr
	}, 5*time.Millisecond)

	return &POSIXOutputLog{
		appender:     appender,
		awaiter:      awaiter,
		logReader:    logReader,
		hasWitnesses: cfg.witnessGroup != nil,
		shutdown:     shutdown,
		cancel:       cancel,
	}, nil
}

func (l *POSIXOutputLog) awaitPublication(ctx context.Context, fut tessera.IndexFuture) (tessera.Index, []byte, error) {
	waitStart := time.Now()
	idx, rawCP, err := l.awaiter.Await(ctx, fut)
	if l.hasWitnesses {
		metrics.WitnessWaitSeconds.Observe(time.Since(waitStart).Seconds())
	}
	return idx, rawCP, err
}

// AwaitQuiescent blocks until any sequenced or integrated entries ahead of the published checkpoint
// have been witnessed and published into a checkpoint.
func (l *POSIXOutputLog) AwaitQuiescent(ctx context.Context) error {
	nextIdx, err := l.logReader.NextIndex(ctx)
	if err != nil || nextIdx == 0 {
		return err
	}
	pubSize, err := l.Size(ctx)
	if err != nil || pubSize >= nextIdx {
		return err
	}
	target := nextIdx - 1
	_, _, err = l.awaitPublication(ctx, func() (tessera.Index, error) {
		return tessera.Index{Index: target}, nil
	})
	return err
}

// Append appends a leaf to the log and awaits publication in a signed checkpoint.
// If the current log tip already stores the identical leafData (e.g. from a prior Append that timed out
// waiting on witnesses before or after background checkpoint publication), Append awaits that tip index
// instead of appending a duplicate entry.
func (l *POSIXOutputLog) Append(ctx context.Context, leafData []byte) (leafIdx uint64, cp []byte, err error) {
	if intSize, sErr := l.logReader.IntegratedSize(ctx); sErr == nil && intSize > 0 {
		tipIdx := intSize - 1
		if existing, gErr := l.readLeafAtTreeSize(ctx, tipIdx, intSize); gErr == nil && bytes.Equal(existing, leafData) {
			index, rawCP, aErr := l.awaitPublication(ctx, func() (tessera.Index, error) {
				return tessera.Index{Index: tipIdx}, nil
			})
			if aErr != nil {
				return 0, nil, fmt.Errorf("failed to await tip leaf %d: %w", tipIdx, aErr)
			}
			return index.Index, rawCP, nil
		}
	}

	index, rawCP, err := l.awaitPublication(ctx, l.appender.Add(ctx, tessera.NewEntry(leafData)))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to append leaf: %w", err)
	}
	return index.Index, rawCP, nil
}

// InclusionProof builds an inclusion proof for the leaf at leafIdx in a tree of size treeSize.
func (l *POSIXOutputLog) InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	pb, err := client.NewProofBuilder(ctx, treeSize, l.logReader.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder: %w", err)
	}
	proof, err := pb.InclusionProof(ctx, leafIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate inclusion proof: %w", err)
	}
	proofRes := make([][sha256.Size]byte, len(proof))
	for i, p := range proof {
		if len(p) != sha256.Size {
			return nil, fmt.Errorf("invalid proof element size %d at %d, want %d", len(p), i, sha256.Size)
		}
		copy(proofRes[i][:], p)
	}
	return proofRes, nil
}

// Size returns the size of the latest published checkpoint, or 0 if no entries have been published yet.
func (l *POSIXOutputLog) Size(ctx context.Context) (uint64, error) {
	rawCP, err := l.Checkpoint(ctx)
	if err != nil || len(rawCP) == 0 {
		return 0, err
	}
	cp, err := wire.ParseCheckpointHeader(rawCP)
	if err != nil {
		return 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	return cp.Size, nil
}

// Checkpoint returns the raw bytes of the latest published checkpoint (which may be a size-0 initial
// checkpoint written at startup), or nil if no checkpoint file exists on disk yet.
func (l *POSIXOutputLog) Checkpoint(ctx context.Context) ([]byte, error) {
	rawCP, err := l.logReader.ReadCheckpoint(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	return rawCP, nil
}

func (l *POSIXOutputLog) readLeafAtTreeSize(ctx context.Context, idx, size uint64) ([]byte, error) {
	if idx >= size {
		return nil, fmt.Errorf("leaf index %d out of range for tree size %d", idx, size)
	}
	bundleIndex := idx / layout.EntryBundleWidth
	offset := idx % layout.EntryBundleWidth

	bundle, err := client.GetEntryBundle(ctx, l.logReader.ReadEntryBundle, bundleIndex, size)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry bundle: %w", err)
	}
	if int(offset) >= len(bundle.Entries) {
		return nil, fmt.Errorf("leaf index %d offset %d out of range in bundle (len %d)", idx, offset, len(bundle.Entries))
	}
	return bundle.Entries[offset], nil
}

// GetLeaf retrieves the leaf payload at idx from the appropriate published entry bundle.
func (l *POSIXOutputLog) GetLeaf(ctx context.Context, idx uint64) ([]byte, error) {
	size, err := l.Size(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree size: %w", err)
	}
	return l.readLeafAtTreeSize(ctx, idx, size)
}

// Close gracefully terminates the log appender and publication awaiter within a bounded timeout.
func (l *POSIXOutputLog) Close() error {
	l.closeOnce.Do(func() {
		if l.shutdown != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			l.closeErr = l.shutdown(shutdownCtx)
			cancel()
		}
		if l.cancel != nil {
			l.cancel()
		}
	})
	return l.closeErr
}
