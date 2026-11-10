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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

type testJSONEntry struct {
	Index   int    `json:"index"`
	Key     string `json:"key,omitempty"`
	KeyHash string `json:"key_hash"`
}

type testJSONOutput struct {
	Total   int             `json:"total"`
	Entries []testJSONEntry `json:"entries"`
}

func runTestCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "Path to compiled WASM plugin file (required).")
	inputStr := fs.String("input", "", "Literal string input payload.")
	inputFile := fs.String("input_file", "", "Path to file containing input leaf payload.")
	inputHex := fs.String("hex", "", "Hex-encoded input leaf payload.")
	bundleSize := fs.Int("bundle_size", int(wasmhost.DefaultBundleSize), "Number of leaves per bundle execution (defaults to 256).")
	format := fs.String("format", "plain", "Output format: plain or json.")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundleSize <= 0 {
		*bundleSize = int(wasmhost.DefaultBundleSize)
	}

	if *wasmPath == "" {
		return errors.New("--wasm flag is required")
	}

	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM file %q: %w", *wasmPath, err)
	}

	var inputBytes []byte
	if *inputHex != "" {
		b, err := hex.DecodeString(*inputHex)
		if err != nil {
			return fmt.Errorf("invalid hex input %q: %w", *inputHex, err)
		}
		inputBytes = b
	} else if *inputFile == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read input from stdin: %w", err)
		}
		inputBytes = b
	} else if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file %q: %w", *inputFile, err)
		}
		inputBytes = b
	} else if *inputStr != "" {
		inputBytes = []byte(*inputStr)
	}

	wasmHost, err := wasmhost.NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		return fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	defer func() { _ = wasmHost.Close(ctx) }()

	bundle := make([][]byte, *bundleSize)
	for i := range bundle {
		bundle[i] = inputBytes
	}

	bundleResults, err := wasmHost.MapBundle(ctx, bundle)
	if err != nil {
		return fmt.Errorf("MapBundle execution failed: %w", err)
	}
	if len(bundleResults) != *bundleSize {
		return fmt.Errorf("MapBundle returned %d leaf results, want %d", len(bundleResults), *bundleSize)
	}
	entries := bundleResults[0]
	for i := 1; i < len(bundleResults); i++ {
		if !slices.Equal(bundleResults[i], entries) {
			return fmt.Errorf("non-deterministic bundle output at leaf %d: got %v, want %v", i, bundleResults[i], entries)
		}
	}

	if *format == "json" {
		out := testJSONOutput{
			Total:   len(entries),
			Entries: make([]testJSONEntry, len(entries)),
		}
		for i, e := range entries {
			out.Entries[i] = testJSONEntry{
				Index:   i,
				Key:     e.Key,
				KeyHash: hex.EncodeToString(e.KeyHash[:]),
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Printf("Mapped %d entries from input (%d bytes):\n", len(entries), len(inputBytes))
	for i, e := range entries {
		fmt.Printf("  [%d] Key: %s | KeyHash: %x\n", i, e.Key, e.KeyHash)
	}

	return nil
}
