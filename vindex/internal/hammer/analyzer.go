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
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxLatencySamples = 16384

// Stats summarizes point-in-time or full-run hammer execution metrics.
type Stats struct {
	Duration            time.Duration
	LeavesWritten       uint64
	InputLogSize        uint64
	WriteQPS            float64
	CheckpointsCreated  uint64
	ServingTreeSize     uint64
	IngestionLag        uint64
	TotalReads          uint64
	ReadSuccesses       uint64
	ReadFailures        uint64
	ReadQPS             float64
	LatencyP50          time.Duration
	LatencyP90          time.Duration
	LatencyP99          time.Duration
	LatencyMax          time.Duration
	InvariantViolations uint64
	ViolationSamples    []string
}

// Analyzer aggregates telemetry and renders terminal dashboards.
type Analyzer struct {
	mu                  sync.Mutex
	sequencer           *Sequencer
	readSuccesses       uint64
	readFailures        uint64
	servingTreeSize     uint64
	invariantViolations uint64
	violations          []string
	latencies           []time.Duration
	latencyWriteIdx     int
	maxLatency          time.Duration
	windowLatencies     []time.Duration
	lastLeavesWritten   uint64
	lastTotalReads      uint64
	lastTickTime        time.Time
	startTime           time.Time
}

// NewAnalyzer creates a new Analyzer instance.
func NewAnalyzer(seq *Sequencer) *Analyzer {
	now := time.Now()
	return &Analyzer{
		sequencer:    seq,
		startTime:    now,
		lastTickTime: now,
	}
}

func (a *Analyzer) recordLatencyLocked(latency time.Duration) {
	if latency > a.maxLatency {
		a.maxLatency = latency
	}
	if len(a.windowLatencies) < maxLatencySamples {
		a.windowLatencies = append(a.windowLatencies, latency)
	}
	if len(a.latencies) < maxLatencySamples {
		a.latencies = append(a.latencies, latency)
	} else {
		a.latencies[a.latencyWriteIdx] = latency
		a.latencyWriteIdx = (a.latencyWriteIdx + 1) % maxLatencySamples
	}
}

// RecordReadSuccess records a successful verifiable read.
func (a *Analyzer) RecordReadSuccess(latency time.Duration, servingTreeSize uint64) {
	a.mu.Lock()
	a.readSuccesses++
	if servingTreeSize > a.servingTreeSize {
		a.servingTreeSize = servingTreeSize
	}
	a.recordLatencyLocked(latency)
	a.mu.Unlock()
}

// RecordReadError records a failed read attempt without polluting InvariantViolations samples.
func (a *Analyzer) RecordReadError(_ error, latency time.Duration) {
	a.mu.Lock()
	a.readFailures++
	a.recordLatencyLocked(latency)
	a.mu.Unlock()
}

// RecordInvariantViolation records a critical invariant assertion failure.
func (a *Analyzer) RecordInvariantViolation(msg string) {
	a.mu.Lock()
	a.invariantViolations++
	if len(a.violations) < 20 {
		a.violations = append(a.violations, msg)
	}
	a.mu.Unlock()
}

func (a *Analyzer) snapshot() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	tickDelta := now.Sub(a.lastTickTime).Seconds()
	if tickDelta <= 0 {
		tickDelta = 1.0
	}

	var seqStats SequencerStats
	if a.sequencer != nil {
		seqStats = a.sequencer.Stats()
	}

	writeQPS := float64(seqStats.LeavesWritten-a.lastLeavesWritten) / tickDelta
	a.lastLeavesWritten = seqStats.LeavesWritten

	totalReads := a.readSuccesses + a.readFailures
	readQPS := float64(totalReads-a.lastTotalReads) / tickDelta
	a.lastTotalReads = totalReads
	a.lastTickTime = now

	p50, p90, p99, winMax := calculatePercentiles(a.windowLatencies)
	a.windowLatencies = a.windowLatencies[:0]

	return a.assembleStatsLocked(now.Sub(a.startTime), seqStats, totalReads, writeQPS, readQPS, p50, p90, p99, winMax)
}

// ExportStats returns cumulative full-run metrics and overall latency percentiles without mutating window state.
func (a *Analyzer) ExportStats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	dur := time.Since(a.startTime)
	secs := dur.Seconds()

	var seqStats SequencerStats
	if a.sequencer != nil {
		seqStats = a.sequencer.Stats()
	}

	totalReads := a.readSuccesses + a.readFailures
	var writeQPS, readQPS float64
	if secs > 0 {
		writeQPS = float64(seqStats.LeavesWritten) / secs
		readQPS = float64(totalReads) / secs
	}

	p50, p90, p99, bufMax := calculatePercentiles(a.latencies)
	return a.assembleStatsLocked(dur, seqStats, totalReads, writeQPS, readQPS, p50, p90, p99, max(bufMax, a.maxLatency))
}

func (a *Analyzer) assembleStatsLocked(dur time.Duration, seqStats SequencerStats, totalReads uint64, writeQPS, readQPS float64, p50, p90, p99, maxLat time.Duration) Stats {
	var lag uint64
	if seqStats.LatestTreeSize > a.servingTreeSize {
		lag = seqStats.LatestTreeSize - a.servingTreeSize
	}
	return Stats{
		Duration:            dur,
		LeavesWritten:       seqStats.LeavesWritten,
		InputLogSize:        seqStats.LatestTreeSize,
		WriteQPS:            writeQPS,
		CheckpointsCreated:  seqStats.CheckpointsCreated,
		ServingTreeSize:     a.servingTreeSize,
		IngestionLag:        lag,
		TotalReads:          totalReads,
		ReadSuccesses:       a.readSuccesses,
		ReadFailures:        a.readFailures,
		ReadQPS:             readQPS,
		LatencyP50:          p50,
		LatencyP90:          p90,
		LatencyP99:          p99,
		LatencyMax:          maxLat,
		InvariantViolations: a.invariantViolations,
		ViolationSamples:    slices.Clone(a.violations),
	}
}

func calculatePercentiles(lats []time.Duration) (p50, p90, p99, maxLat time.Duration) {
	if len(lats) == 0 {
		return 0, 0, 0, 0
	}
	sorted := slices.Clone(lats)
	slices.Sort(sorted)
	n := len(sorted)
	return sorted[n*50/100], sorted[n*90/100], sorted[n*99/100], sorted[n-1]
}

// RunDashboard periodically prints live terminal status updates until ctx is cancelled.
func (a *Analyzer) RunDashboard(ctx context.Context, refreshInterval time.Duration) {
	if refreshInterval <= 0 {
		refreshInterval = 1 * time.Second
	}
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.renderLine(a.snapshot())
		}
	}
}

func (a *Analyzer) renderLine(s Stats) {
	status := "HEALTHY"
	if s.InvariantViolations > 0 {
		status = fmt.Sprintf("FAIL (%d Invariant Violations)", s.InvariantViolations)
	} else if s.ReadFailures > 0 {
		status = fmt.Sprintf("WARN (%d Errors)", s.ReadFailures)
	}

	fmt.Printf("[%04.0fs] Status: %-10s | Writes: %6.1f/s (Tot: %d, Tree: %d) | Reads: %6.1f/s (Tot: %d, Ok: %d, Err: %d) | Lag: %d | Lat: P50=%v P90=%v P99=%v\n",
		s.Duration.Seconds(),
		status,
		s.WriteQPS, s.LeavesWritten, s.InputLogSize,
		s.ReadQPS, s.TotalReads, s.ReadSuccesses, s.ReadFailures,
		s.IngestionLag,
		s.LatencyP50.Round(time.Microsecond),
		s.LatencyP90.Round(time.Microsecond),
		s.LatencyP99.Round(time.Microsecond),
	)
}

// PrintSummary prints a comprehensive end-of-run summary report and returns the final Stats.
func (a *Analyzer) PrintSummary() Stats {
	stats := a.ExportStats()

	fmt.Println("\n========================== HAMMER RUN SUMMARY ==========================")
	fmt.Printf("Duration:               %v\n", stats.Duration.Round(time.Millisecond))
	fmt.Printf("Leaves Written:         %d (%.1f writes/sec)\n", stats.LeavesWritten, stats.WriteQPS)
	fmt.Printf("Checkpoints Produced:   %d\n", stats.CheckpointsCreated)
	fmt.Printf("Input Log Tree Size:    %d\n", stats.InputLogSize)
	fmt.Printf("Serving Tree Size:      %d\n", stats.ServingTreeSize)
	fmt.Printf("Total Read Lookups:     %d (%.1f reads/sec)\n", stats.TotalReads, stats.ReadQPS)
	fmt.Printf("Successful Reads:       %d\n", stats.ReadSuccesses)
	fmt.Printf("Failed Reads:           %d\n", stats.ReadFailures)
	fmt.Printf("Latency Overall:        P50=%v  P90=%v  P99=%v  Max=%v\n",
		stats.LatencyP50.Round(time.Microsecond),
		stats.LatencyP90.Round(time.Microsecond),
		stats.LatencyP99.Round(time.Microsecond),
		stats.LatencyMax.Round(time.Microsecond),
	)
	fmt.Printf("Invariant Violations:   %d\n", stats.InvariantViolations)

	if len(stats.ViolationSamples) > 0 {
		fmt.Println("\nViolation / Error Samples:")
		for i, v := range stats.ViolationSamples {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(stats.ViolationSamples)-10)
				break
			}
			fmt.Printf("  - %s\n", strings.TrimSpace(v))
		}
	}
	fmt.Println("========================================================================")
	return stats
}
