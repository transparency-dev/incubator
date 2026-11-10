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

// Package tree provides Output Log storage and state commitment publishing.
package tree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"k8s.io/klog/v2"
)

// OutputLogClient describes the client interface to append state commitments to the Output Log and fetch inclusion proofs.
type OutputLogClient interface {
	Append(ctx context.Context, leafData []byte) (leafIdx uint64, checkpoint []byte, err error)
	InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error)
}

// ServingState contains the immutable snapshot of the active serving state.
type ServingState struct {
	OutputLogIndex uint64
	RawCheckpoint  []byte // Raw signed checkpoint note bytes preserving witness cosignatures
	OutputLogProof [][sha256.Size]byte
	InputLogCP     *log.Checkpoint
	InputLogSize   uint64
	MPTRoot        [sha256.Size]byte
	From           uint64
}

// OutputPublisher orchestrates root prediction, Output Log append, checkpoint policy verification, and atomic state ratcheting.
type OutputPublisher struct {
	publishMu       sync.Mutex
	mu              sync.RWMutex
	mptMgr          *mpt.Manager
	outputLog       OutputLogClient
	outputLogPolicy wire.Policy
	inputOrigin     string
	from            uint64
	servingState    atomic.Pointer[ServingState]
}

// NewOutputPublisher creates a new OutputPublisher.
func NewOutputPublisher(mptMgr *mpt.Manager, outputLog OutputLogClient) *OutputPublisher {
	return &OutputPublisher{
		mptMgr:    mptMgr,
		outputLog: outputLog,
	}
}

// SetOutputLogPolicy configures an optional wire.Policy used to verify Output Log checkpoints
// (including witness cosignatures) prior to promoting ServingState.
func (p *OutputPublisher) SetOutputLogPolicy(policy wire.Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outputLogPolicy = policy
}

// VerifyCheckpoint verifies a raw Output Log checkpoint against the configured OutputLogPolicy
// (or parses its header when no policy is configured).
func (p *OutputPublisher) VerifyCheckpoint(rawCP []byte) (*log.Checkpoint, error) {
	p.mu.RLock()
	outPolicy := p.outputLogPolicy
	p.mu.RUnlock()

	if outPolicy != nil {
		outCP, err := outPolicy.Verify(rawCP)
		if err != nil {
			metrics.WitnessErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to verify output log checkpoint against policy: %w", err)
		}
		return outCP, nil
	}
	outCP, err := wire.ParseCheckpointHeader(rawCP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse output log checkpoint: %w", err)
	}
	return outCP, nil
}

// SetInputOrigin sets the Input Log origin string committed in Output Log leaves.
func (p *OutputPublisher) SetInputOrigin(origin string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inputOrigin = origin
}

// InputOrigin returns the Input Log origin string committed in Output Log leaves.
func (p *OutputPublisher) InputOrigin() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.inputOrigin
}

// SetFrom sets the inclusive starting Input Log index committed in Output Log leaves.
func (p *OutputPublisher) SetFrom(from uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.from = from
}

// From returns the inclusive starting Input Log index committed in Output Log leaves.
func (p *OutputPublisher) From() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.from
}

// GetServingState returns the currently active ServingState.
func (p *OutputPublisher) GetServingState() *ServingState {
	return p.servingState.Load()
}

// SetServingState explicitly sets the active serving state (e.g. during recovery/startup).
func (p *OutputPublisher) SetServingState(state *ServingState) {
	p.servingState.Store(state)
	if state != nil {
		metrics.ServingTreeSize.Set(float64(state.InputLogSize))
		metrics.OutputTreeSize.Set(float64(state.OutputLogIndex + 1))
		metrics.WitnessSignaturesCount.Set(float64(countWitnessSignatures(state.RawCheckpoint)))
	}
}

// PublishKeyBatch publishes a batch of variable-length canonical key value root modifications
// to the Output Log and promotes the serving state.
func (p *OutputPublisher) PublishKeyBatch(ctx context.Context, modifiedValueRoots map[string][sha256.Size]byte, inputLogCP *log.Checkpoint) (*ServingState, error) {
	if inputLogCP == nil {
		return nil, errors.New("inputLogCP must not be nil")
	}
	if p.mptMgr == nil {
		return nil, errors.New("mptMgr must not be nil")
	}
	if p.outputLog == nil {
		return nil, errors.New("outputLog must not be nil")
	}

	p.publishMu.Lock()
	defer p.publishMu.Unlock()

	p.mu.RLock()
	inputOrigin := p.inputOrigin
	from := p.from
	p.mu.RUnlock()

	origin := inputLogCP.Origin
	if origin == "" {
		origin = inputOrigin
	} else if inputOrigin != "" && origin != inputOrigin {
		return nil, fmt.Errorf("input log checkpoint origin %q does not match configured origin %q", origin, inputOrigin)
	}
	if err := wire.ValidateInputOrigin(origin); err != nil {
		return nil, fmt.Errorf("invalid input log origin: %w", err)
	}
	if from > inputLogCP.Size {
		return nil, fmt.Errorf("from (%d) exceeds input log size (%d)", from, inputLogCP.Size)
	}
	if len(inputLogCP.Hash) != sha256.Size {
		return nil, fmt.Errorf("invalid input log root hash length %d, want %d", len(inputLogCP.Hash), sha256.Size)
	}
	if inputLogCP.Size == 0 && [sha256.Size]byte(inputLogCP.Hash) != wire.EmptyRoot() {
		return nil, fmt.Errorf("input log size 0 must have empty root hash %x, got %x", wire.EmptyRoot(), inputLogCP.Hash)
	}

	if prev := p.GetServingState(); prev != nil {
		if prev.InputLogCP != nil && origin != prev.InputLogCP.Origin {
			return nil, fmt.Errorf("input log origin changed from %q to %q", prev.InputLogCP.Origin, origin)
		}
		if from != prev.From {
			return nil, fmt.Errorf("from changed from %d to %d", prev.From, from)
		}
		if inputLogCP.Size < prev.InputLogSize {
			return nil, fmt.Errorf("input log size regressed from %d to %d", prev.InputLogSize, inputLogCP.Size)
		}
		if inputLogCP.Size == prev.InputLogSize && prev.InputLogCP != nil && !bytes.Equal(inputLogCP.Hash, prev.InputLogCP.Hash) {
			return nil, fmt.Errorf("input log root hash mismatch at unchanged size %d", inputLogCP.Size)
		}
	}

	clonedInCP := &log.Checkpoint{
		Origin: origin,
		Size:   inputLogCP.Size,
		Hash:   bytes.Clone(inputLogCP.Hash),
	}

	batch, err := mpt.PrepareBatch(modifiedValueRoots)
	if err != nil {
		return nil, err
	}

	// Step 1: Non-blocking root prediction under shared read lock, followed by Output Log append & witnessing
	predictStart := time.Now()
	predictedMPTRoot, err := p.mptMgr.PredictBatch(batch)
	metrics.MPTPredictDurationSeconds.Observe(time.Since(predictStart).Seconds())
	if err != nil {
		return nil, fmt.Errorf("mptMgr.PredictBatch failed: %w", err)
	}
	if clonedInCP.Size == from && (len(modifiedValueRoots) > 0 || predictedMPTRoot != wire.EmptyRoot()) {
		return nil, fmt.Errorf("empty indexed range [from=%d, size=%d) must commit to empty MPT root", from, clonedInCP.Size)
	}

	leafData := wire.FormatOutputLogLeafFull(predictedMPTRoot, from, clonedInCP)
	appendStart := time.Now()
	leafIdx, rawCP, err := p.outputLog.Append(ctx, leafData)
	if err != nil {
		return nil, fmt.Errorf("outputLog.Append failed: %w", err)
	}

	outCP, err := p.VerifyCheckpoint(rawCP)
	if err != nil {
		return nil, err
	}
	if outCP.Size == 0 || leafIdx != outCP.Size-1 {
		return nil, fmt.Errorf("output log index %d is not tip of checkpoint size %d", leafIdx, outCP.Size)
	}

	proof, err := p.outputLog.InclusionProof(ctx, leafIdx, outCP.Size)
	if err != nil {
		return nil, fmt.Errorf("outputLog.InclusionProof failed: %w", err)
	}
	metrics.OutputLogAppendDurationSeconds.Observe(time.Since(appendStart).Seconds())

	// Steps 2 & 3: Commit to MPT, assert predicted root, atomically ratchet ServingState under treeMu, then fsync outside treeMu
	var newState *ServingState
	writeStart := time.Now()
	actualRoot, err := p.mptMgr.CommitBatchAndPersist(batch, int64(clonedInCP.Size), func(committedRoot [sha256.Size]byte) {
		metrics.MPTWriteDurationSeconds.Observe(time.Since(writeStart).Seconds())
		if committedRoot != predictedMPTRoot {
			panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual root %x != predicted root %x", committedRoot, predictedMPTRoot))
		}
		newState = &ServingState{
			OutputLogIndex: leafIdx,
			RawCheckpoint:  bytes.Clone(rawCP),
			OutputLogProof: slices.Clone(proof),
			InputLogCP:     clonedInCP,
			InputLogSize:   clonedInCP.Size,
			MPTRoot:        committedRoot,
			From:           from,
		}
		p.SetServingState(newState)
	})
	if err != nil {
		return nil, fmt.Errorf("mptMgr.CommitBatchAndPersist failed: %w", err)
	}
	klog.Infof("Committed MPTRoot %x for InputLog size %d in %v", actualRoot, clonedInCP.Size, time.Since(writeStart))
	return newState, nil
}

// countWitnessSignatures counts witness cosignature lines on a signed checkpoint note,
// excluding the Output Log's own primary signature line.
func countWitnessSignatures(rawCP []byte) int {
	_, sigBlock, ok := bytes.Cut(rawCP, []byte("\n\n"))
	if !ok {
		return 0
	}
	sigLines := 0
	for line := range bytes.SplitSeq(sigBlock, []byte("\n")) {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("\xe2\x80\x94 ")) {
			sigLines++
		}
	}
	return max(sigLines-1, 0)
}
