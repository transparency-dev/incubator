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
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/incubator/vindex/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

const (
	hotKeyRatio           = 0.60
	uniformKeyRatio       = 0.25
	nonInclusionRatio     = 0.10
	maxTrackedHistoryKeys = 4096
)

// ReaderConfig configures the concurrent verifying reader and conformance pool.
type ReaderConfig struct {
	VIndexURL         string
	OutputLogURL      string
	NumWorkers        int
	MaxReadQPS        float64
	OutputLogOrigin   string
	OutputLogVerifier note.Verifier
	OutputLogPolicy   client.CheckpointPolicy
	InputLogOrigin    string
	Oracle            *Oracle
	CheckConformance  bool
	PrefixRatio       float64
	PageSize          uint64
	ReadinessTimeout  time.Duration
	RequestTimeout    time.Duration
}

type keyHistory struct {
	treeSize uint64
	indices  []uint64
}

// ReaderPool manages concurrent reader workers querying a target tlog-vindex endpoint
// with cryptographic proof, ground-truth oracle, and HTTP/tile conformance verification.
type ReaderPool struct {
	cfg             ReaderConfig
	generator       *Generator
	client          *client.Client
	probeHC         *http.Client
	outLogVerifier  *OutputLogVerifier
	analyzer        *Analyzer
	values404Once   sync.Once
	mu              sync.Mutex
	hasFrom         bool
	verifiedFrom    uint64
	history         map[string]keyHistory
}

// NewReaderPool creates a new ReaderPool instance.
func NewReaderPool(cfg ReaderConfig, gen *Generator, an *Analyzer) (*ReaderPool, error) {
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = 8
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}
	if cfg.ReadinessTimeout <= 0 {
		cfg.ReadinessTimeout = 15 * time.Second
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 5 * time.Second
	}

	outPolicy := cfg.OutputLogPolicy
	if outPolicy == nil && cfg.OutputLogVerifier != nil {
		var err error
		outPolicy, err = client.SingleKeyPolicy(cfg.OutputLogOrigin, cfg.OutputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("failed to construct output log policy: %w", err)
		}
	}

	httpClient := &http.Client{
		Timeout: cfg.RequestTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.NumWorkers * 4,
			MaxIdleConnsPerHost: cfg.NumWorkers * 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	cli, err := client.New(cfg.VIndexURL, client.Config{
		ExpectedOutputLogOrigin: cfg.OutputLogOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  cfg.InputLogOrigin,
	}, client.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	probeHC := newNoRedirectHTTPClient(cfg.RequestTimeout)
	p := &ReaderPool{
		cfg:       cfg,
		generator: gen,
		client:    cli,
		probeHC:   probeHC,
		analyzer:  an,
		history:   make(map[string]keyHistory),
	}

	if strings.TrimSpace(cfg.OutputLogURL) != "" {
		resolvedOutOrigin := cfg.OutputLogOrigin
		if resolvedOutOrigin == "" {
			if op, ok := outPolicy.(interface{ Origin() string }); ok {
				resolvedOutOrigin = op.Origin()
			}
		}
		ov, oErr := newOutputLogVerifier(
			cfg.OutputLogURL,
			resolvedOutOrigin,
			outPolicy,
			cfg.InputLogOrigin,
			cfg.Oracle,
			probeHC,
			p.verifyHorizon,
			p.recordViolation,
		)
		if oErr != nil {
			return nil, oErr
		}
		p.outLogVerifier = ov
	}

	return p, nil
}

func isTransientReadinessError(err error) bool {
	if errors.Is(err, client.ErrUnavailable) || errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, client.ErrVerificationFailed) || errors.Is(err, client.ErrBadRequest) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// Start launches worker goroutines and runs until ctx is cancelled.
func (p *ReaderPool) Start(ctx context.Context) error {
	probeKey := p.generator.SampleNonInclusionKey()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	readyCtx, readyCancel := context.WithTimeout(ctx, p.cfg.ReadinessTimeout)
	defer readyCancel()

	var readyFrom, readySize uint64
	for {
		probeStart := time.Now()
		kr, err := p.client.LookupKey(readyCtx, probeKey)
		if err == nil {
			p.verifyHorizon(kr.From)
			p.verifyInputState(ctx, kr.InputSize, kr.InputRoot)
			if len(kr.Keys) > 0 {
				p.recordViolation("NonInclusionViolation: readiness probe key %s matched %d keys", probeKey, len(kr.Keys))
			} else if p.cfg.Oracle != nil {
				if oErr := p.cfg.Oracle.VerifyKeyLookup(probeKey, kr.From, kr.InputSize, false, nil, true); oErr != nil {
					p.recordViolation("OracleKeyViolation: %v", oErr)
				}
			}
			if p.analyzer != nil {
				p.analyzer.RecordReadSuccess(time.Since(probeStart), kr.InputSize)
			}
			readyFrom = kr.From
			readySize = kr.InputSize
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if readyCtx.Err() != nil {
			p.recordViolation("ReadinessTimeout: target VIndex did not become ready within %v", p.cfg.ReadinessTimeout)
			return fmt.Errorf("timed out waiting %v for target VIndex readiness", p.cfg.ReadinessTimeout)
		}
		if !isTransientReadinessError(err) {
			p.recordViolation("ReadinessProbeError: %v", err)
			return fmt.Errorf("readiness probe failed: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-readyCtx.Done():
			p.recordViolation("ReadinessTimeout: target VIndex did not become ready within %v", p.cfg.ReadinessTimeout)
			return fmt.Errorf("timed out waiting %v for target VIndex readiness", p.cfg.ReadinessTimeout)
		case <-ticker.C:
		}
	}

	if p.cfg.CheckConformance {
		for _, v := range runHTTPConformanceProbes(ctx, p.cfg.VIndexURL, p.probeHC) {
			p.recordViolation("%s", v)
		}
		p.maybeProbeValues404(ctx, readyFrom, readySize)
	}

	var rateLimiter <-chan time.Time
	if p.cfg.MaxReadQPS > 0 {
		qpsTicker := time.NewTicker(rateToInterval(p.cfg.MaxReadQPS, time.Microsecond))
		defer qpsTicker.Stop()
		rateLimiter = qpsTicker.C
	}

	var wg sync.WaitGroup
	if p.outLogVerifier != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.outLogVerifier.Run(ctx, 250*time.Millisecond)
		}()
	}
	for range p.cfg.NumWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runWorker(ctx, rateLimiter)
		}()
	}

	<-ctx.Done()
	wg.Wait()
	return nil
}

func (p *ReaderPool) maybeProbeValues404(ctx context.Context, from, inputSize uint64) {
	if !p.cfg.CheckConformance || inputSize <= from {
		return
	}
	p.values404Once.Do(func() {
		if msg := probeValuesNotFound(ctx, p.cfg.VIndexURL, p.probeHC, p.generator.SampleNonInclusionKey(), inputSize); msg != "" {
			p.recordViolation("%s", msg)
		}
	})
}

func (p *ReaderPool) verifyInputState(ctx context.Context, inputSize uint64, inputRoot [32]byte) {
	if p.cfg.Oracle == nil {
		return
	}
	if err := p.cfg.Oracle.VerifyInputState(ctx, inputSize, inputRoot); err != nil && ctx.Err() == nil {
		p.recordViolation("InputStateViolation: %v", err)
	}
}

func (p *ReaderPool) runWorker(ctx context.Context, rateLimiter <-chan time.Time) {
	for {
		if rateLimiter != nil {
			select {
			case <-ctx.Done():
				return
			case <-rateLimiter:
			}
		} else if ctx.Err() != nil {
			return
		}
		p.executeOneQuery(ctx)
	}
}

func (p *ReaderPool) recordViolation(format string, args ...any) {
	if p.analyzer != nil {
		p.analyzer.RecordInvariantViolation(fmt.Sprintf(format, args...))
	}
}

func (p *ReaderPool) verifyHorizon(from uint64) {
	p.mu.Lock()
	var prev uint64
	mismatch := false
	if !p.hasFrom {
		p.hasFrom = true
		p.verifiedFrom = from
	} else if from != p.verifiedFrom {
		prev = p.verifiedFrom
		mismatch = true
	}
	p.mu.Unlock()

	if mismatch {
		p.recordViolation("HorizonViolation: index start horizon changed from %d to %d", prev, from)
	}
}

func (p *ReaderPool) executeOneQuery(ctx context.Context) {
	dice := rand.Float64()
	if p.cfg.PrefixRatio > 0 && dice < p.cfg.PrefixRatio {
		p.executePrefixQuery(ctx)
		return
	}
	if p.cfg.PrefixRatio > 0 && p.cfg.PrefixRatio < 1.0 {
		dice = (dice - p.cfg.PrefixRatio) / (1.0 - p.cfg.PrefixRatio)
	}

	var queryType, keyStr string
	var isNonInclusion, isPagination bool

	switch {
	case dice < hotKeyRatio:
		queryType = "hot"
		keyStr = p.generator.SampleHotKey()
	case dice < hotKeyRatio+uniformKeyRatio:
		queryType = "uniform"
		keyStr = p.generator.SampleUniformKey()
	case dice < hotKeyRatio+uniformKeyRatio+nonInclusionRatio:
		queryType = "non_inclusion"
		keyStr = p.generator.SampleNonInclusionKey()
		isNonInclusion = true
	default:
		queryType = "pagination"
		keyStr = p.generator.SampleHotKey()
		isPagination = true
	}

	start := time.Now()
	kr, err := p.client.LookupKey(ctx, keyStr)
	var indices []uint64
	isComplete := true
	if err == nil {
		p.verifyHorizon(kr.From)
		p.verifyInputState(ctx, kr.InputSize, kr.InputRoot)
		p.maybeProbeValues404(ctx, kr.From, kr.InputSize)
		if len(kr.Keys) > 0 {
			pageLimit := p.cfg.PageSize
			if isPagination {
				pageLimit = 0
			}
			indices, isComplete, err = collectIndices(ctx, kr.Keys[0], pageLimit)
		}
	}
	latency := time.Since(start)

	if err != nil {
		p.handleQueryError(ctx, queryType, keyStr, err, latency)
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, kr.InputSize)
	}

	if isNonInclusion {
		if len(kr.Keys) > 0 || len(indices) > 0 {
			p.recordViolation("NonInclusionViolation: key %s exists in response with %d indices", keyStr, len(indices))
		}
		return
	}

	p.verifyKeyIndices(keyStr, kr.From, kr.InputSize, len(kr.Keys) > 0, indices, isComplete)
}

func (p *ReaderPool) executePrefixQuery(ctx context.Context) {
	isNonInc := rand.IntN(4) == 0
	var prefix string
	if isNonInc {
		prefix = p.generator.SampleNonInclusionPrefix()
	} else {
		prefix = p.generator.SamplePrefix()
	}

	start := time.Now()
	kr, err := p.client.LookupPrefix(ctx, prefix)
	if err == nil {
		p.verifyHorizon(kr.From)
		p.verifyInputState(ctx, kr.InputSize, kr.InputRoot)
		p.maybeProbeValues404(ctx, kr.From, kr.InputSize)
		if isNonInc && len(kr.Keys) > 0 {
			p.recordViolation("PrefixNonInclusionViolation: prefix %s matched %d keys", prefix, len(kr.Keys))
		}
		if !isNonInc && p.cfg.Oracle != nil {
			matchedNames := make([]string, len(kr.Keys))
			for i, m := range kr.Keys {
				matchedNames[i] = m.Key
			}
			if oErr := p.cfg.Oracle.VerifyPrefixLookup(prefix, kr.From, kr.InputSize, matchedNames); oErr != nil {
				p.recordViolation("OraclePrefixViolation: %v", oErr)
			}
		}

		fetchValues := rand.IntN(2) == 1
		const maxPrefixValueScans = 5
		scanned := 0
		for _, m := range kr.Keys {
			if fetchValues && scanned < maxPrefixValueScans {
				scanned++
				indices, isComplete, vErr := collectIndices(ctx, m, p.cfg.PageSize)
				if vErr != nil {
					err = vErr
					break
				}
				p.verifyKeyIndices(m.Key, kr.From, kr.InputSize, true, indices, isComplete)
			}
		}
		if err == nil && !isNonInc {
			p.verifyPrefixCompleteness(prefix, kr.InputSize, kr.Keys)
		}
	}
	latency := time.Since(start)

	if err != nil {
		p.handleQueryError(ctx, "prefix", prefix, err, latency)
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, kr.InputSize)
	}
}

func collectIndices(ctx context.Context, m client.MatchedKey, maxCount uint64) ([]uint64, bool, error) {
	var revIndices []uint64
	complete := true
	for idx, err := range m.Values(ctx) {
		if err != nil {
			return nil, false, err
		}
		revIndices = append(revIndices, idx)
		if maxCount > 0 && uint64(len(revIndices)) >= maxCount {
			complete = false
			break
		}
	}
	slices.Reverse(revIndices)
	return revIndices, complete, nil
}

func (p *ReaderPool) handleQueryError(ctx context.Context, queryType, target string, err error, latency time.Duration) {
	if ctx.Err() != nil {
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadError(err, latency)
		switch {
		case errors.Is(err, client.ErrVerificationFailed):
			p.recordViolation("CryptographicViolation [%s] %s: %v", queryType, target, err)
		case errors.Is(err, client.ErrUnavailable):
			// Transient HTTP 503 during cold startup is tracked in read failure telemetry without failing invariants.
		case queryType == "prefix" && errors.Is(err, client.ErrTooManyKeys):
			// Expected HTTP 413 when a broad synthetic prefix exceeds MaxPrefixKeys.
		default:
			p.recordViolation("UnexpectedQueryError [%s] %s: %v", queryType, target, err)
		}
	}
	klog.V(2).Infof("Read error [%s] %s: %v", queryType, target, err)
}

func (p *ReaderPool) verifyKeyIndices(keyStr string, from, inputSize uint64, matched bool, indices []uint64, isComplete bool) {
	for i, idx := range indices {
		if i > 0 && idx <= indices[i-1] {
			p.recordViolation("SortViolation: indices not strictly ascending for key %s: %v", keyStr, indices)
			return
		}
		if idx < from || idx >= inputSize {
			p.recordViolation("BoundsViolation: index %d out of range [%d, %d) for key %s", idx, from, inputSize, keyStr)
			return
		}
	}
	if p.cfg.Oracle != nil {
		if err := p.cfg.Oracle.VerifyKeyLookup(keyStr, from, inputSize, matched, indices, isComplete); err != nil {
			p.recordViolation("OracleKeyViolation: %v", err)
			return
		}
	}
	p.verifyMonotonicity(keyStr, inputSize, indices, isComplete)
}

func (p *ReaderPool) verifyMonotonicity(keyStr string, inputLogSize uint64, indices []uint64, isComplete bool) {
	if !isComplete {
		return
	}

	p.mu.Lock()
	hist, exists := p.history[keyStr]
	if !exists {
		if len(p.history) < maxTrackedHistoryKeys {
			p.history[keyStr] = keyHistory{treeSize: inputLogSize, indices: indices}
		}
		p.mu.Unlock()
		return
	}

	older, newer := hist, keyHistory{treeSize: inputLogSize, indices: indices}
	if newer.treeSize < older.treeSize {
		older, newer = newer, older
	}
	violation := len(newer.indices) < len(older.indices) ||
		!slices.Equal(newer.indices[:len(older.indices)], older.indices) ||
		(len(newer.indices) > len(older.indices) && newer.indices[len(older.indices)] < older.treeSize) ||
		(older.treeSize == newer.treeSize && len(newer.indices) != len(older.indices))

	if !violation && inputLogSize > hist.treeSize {
		p.history[keyStr] = keyHistory{treeSize: inputLogSize, indices: indices}
	}
	p.mu.Unlock()

	if violation {
		p.recordViolation("MonotonicityViolation: key %s incompatible histories at sizes (%d -> %d counts %d vs %d)",
			keyStr, older.treeSize, newer.treeSize, len(older.indices), len(newer.indices))
	}
}

func (p *ReaderPool) verifyPrefixCompleteness(prefix string, inputLogSize uint64, matched []client.MatchedKey) {
	var missing []string
	p.mu.Lock()
	for k, hist := range p.history {
		if len(hist.indices) == 0 || hist.treeSize > inputLogSize || !strings.HasPrefix(k, prefix) {
			continue
		}
		if _, found := slices.BinarySearchFunc(matched, k, func(m client.MatchedKey, target string) int {
			return strings.Compare(m.Key, target)
		}); !found {
			missing = append(missing, k)
		}
	}
	p.mu.Unlock()

	for _, k := range missing {
		p.recordViolation("MonotonicityViolation: key %s with prefix %s omitted at tree size %d", k, prefix, inputLogSize)
	}
}
