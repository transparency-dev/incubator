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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

func runBenchCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "Path to compiled WASM plugin file (required).")
	inputStr := fs.String("input", "github.com/example/benchmodule v1.2.3 h1:benchHash123456789=\n", "Benchmark input leaf payload.")
	inputFile := fs.String("input_file", "", "Path to file containing input leaf payload.")
	bundleSize := fs.Int("bundle_size", 256, "Number of leaves per bundle (defaults to 256).")
	iterations := fs.Int("iterations", 1000, "Total number of bundle executions.")
	workers := fs.Int("workers", 4, "Number of concurrent worker goroutines and pool size.")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *wasmPath == "" {
		return errors.New("--wasm flag is required")
	}
	if *iterations <= 0 {
		return errors.New("--iterations must be greater than 0")
	}
	if *bundleSize <= 0 {
		*bundleSize = 256
	}
	if *workers <= 0 {
		*workers = 1
	}

	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM file %q: %w", *wasmPath, err)
	}

	var inputBytes []byte
	if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file %q: %w", *inputFile, err)
		}
		inputBytes = b
	} else {
		inputBytes = []byte(*inputStr)
	}

	bundle := make([][]byte, *bundleSize)
	for i := range bundle {
		bundle[i] = inputBytes
	}

	wasmHost, err := wasmhost.NewWASMHost(ctx, wasmBytes, *workers)
	if err != nil {
		return fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	defer func() { _ = wasmHost.Close(ctx) }()

	// Warmup
	for i := 0; i < 10; i++ {
		if _, err := wasmHost.MapBundle(ctx, bundle); err != nil {
			return fmt.Errorf("warmup MapBundle failed: %w", err)
		}
	}

	latencies := make([]time.Duration, *iterations)
	taskChan := make(chan int, *iterations)
	for i := 0; i < *iterations; i++ {
		taskChan <- i
	}
	close(taskChan)

	start := time.Now()
	var wg sync.WaitGroup
	var execErr error
	var errMu sync.Mutex

	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner, err := wasmHost.NewRunner(ctx)
			if err != nil {
				errMu.Lock()
				if execErr == nil {
					execErr = err
				}
				errMu.Unlock()
				return
			}
			defer func() { _ = runner.Close(ctx) }()

			for idx := range taskChan {
				t0 := time.Now()
				_, err := runner.MapBundle(ctx, bundle)
				d := time.Since(t0)
				if err != nil {
					errMu.Lock()
					if execErr == nil {
						execErr = err
					}
					errMu.Unlock()
					return
				}
				latencies[idx] = d
			}
		}()
	}

	wg.Wait()
	totalElapsed := time.Since(start)

	if execErr != nil {
		return fmt.Errorf("benchmark execution failed: %w", execErr)
	}

	// Calculate stats
	slices.Sort(latencies)
	n := len(latencies)
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}

	minLat := latencies[0]
	p50Lat := latencies[n*50/100]
	p90Lat := latencies[n*90/100]
	p99Lat := latencies[n*99/100]
	maxLat := latencies[n-1]
	meanLat := sum / time.Duration(n)

	totalLeaves := (*iterations) * (*bundleSize)
	bundlesPerSec := float64(*iterations) / totalElapsed.Seconds()
	leavesPerSec := float64(totalLeaves) / totalElapsed.Seconds()
	mbPerSec := (float64(len(inputBytes)*totalLeaves) / (1024 * 1024)) / totalElapsed.Seconds()

	fmt.Printf("--- WASM MapFn Benchmark Results ---\n")
	fmt.Printf("Bundle Iterations:%d (%d leaves/bundle, %d total leaves)\n", *iterations, *bundleSize, totalLeaves)
	fmt.Printf("Workers (pool):   %d\n", *workers)
	fmt.Printf("Input payload:    %d bytes/leaf\n", len(inputBytes))
	fmt.Printf("Total Elapsed:    %v\n", totalElapsed)
	fmt.Printf("Throughput:       %.2f leaves/sec (%.2f bundles/sec, %.2f MB/s)\n", leavesPerSec, bundlesPerSec, mbPerSec)
	fmt.Printf("Latencies:\n")
	fmt.Printf("  Min:  %v\n", minLat)
	fmt.Printf("  Mean: %v\n", meanLat)
	fmt.Printf("  p50:  %v\n", p50Lat)
	fmt.Printf("  p90:  %v\n", p90Lat)
	fmt.Printf("  p99:  %v\n", p99Lat)
	fmt.Printf("  Max:  %v\n", maxLat)

	return nil
}
