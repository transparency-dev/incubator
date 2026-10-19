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

// vindex-wasm is a developer tool and test harness for VIndex WASM MapFn plugins.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:]); err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("subcommand required")
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "test":
		return runTestCmd(ctx, subArgs)
	case "inspect":
		return runInspectCmd(ctx, subArgs)
	case "bench":
		return runBenchCmd(ctx, subArgs)
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown subcommand %q", subcmd)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `vindex-wasm is a utility tool for testing and benchmarking VIndex WASM MapFn plugins.

Usage:
  vindex-wasm <command> [options]

Commands:
  inspect              Inspect a WASM binary and verify VIndex MapFn ABI exports and imports.
  test                 Execute a WASM MapFn against an input leaf and inspect mapped entries.
  bench                Benchmark execution throughput and latency percentiles of a WASM MapFn.
  help                 Display this help message.

Use "vindex-wasm <command> -h" for more information about a command.
`)
}
