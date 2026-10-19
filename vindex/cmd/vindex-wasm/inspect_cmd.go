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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

func runInspectCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "Path to compiled WASM plugin file (required).")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *wasmPath == "" {
		if fs.NArg() > 0 {
			*wasmPath = fs.Arg(0)
		} else {
			return errors.New("--wasm flag is required")
		}
	}

	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM file %q: %w", *wasmPath, err)
	}

	compiled, err := wasmhost.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("failed to compile WASM module: %w", err)
	}

	exports := compiled.ExportedFunctions()
	imports := compiled.ImportedFunctions()
	memories := compiled.ExportedMemories()

	hasMemory := memories["memory"] != nil
	hasInputBuf := exports["input_buffer"] != nil
	hasMapBundle := exports["map_bundle"] != nil

	digest := sha256.Sum256(wasmBytes)
	fmt.Printf("=== VIndex WASM MapFn Inspection: %s ===\n", *wasmPath)
	fmt.Printf("Module Size: %d bytes (%.2f KB)\n", len(wasmBytes), float64(len(wasmBytes))/1024.0)
	fmt.Printf("MapFn (base64): %s\n", base64.StdEncoding.EncodeToString(digest[:]))
	fmt.Printf("SHA-256 (hex): %x\n\n", digest)

	fmt.Println("Required ABI Exports:")
	if hasMemory {
		fmt.Println("  [✓] memory")
	} else {
		fmt.Println("  [✗] memory: MISSING")
	}
	if hasInputBuf {
		fmt.Println("  [✓] input_buffer () -> i32 (static 4 MB input slab)")
	} else {
		fmt.Println("  [✗] input_buffer () -> i32: MISSING")
	}
	if hasMapBundle {
		fmt.Println("  [✓] map_bundle (i32, i32) -> i64 (batch tile ABI)")
	} else {
		fmt.Println("  [✗] map_bundle (i32, i32) -> i64: MISSING")
	}

	fmt.Printf("\nImports (%d):\n", len(imports))
	for _, imp := range imports {
		mod, name, _ := imp.Import()
		fmt.Printf("  - %s.%s\n", mod, name)
	}

	fmt.Println("\nABI Compatibility Status:")
	if hasMemory && hasInputBuf && hasMapBundle {
		host, err := wasmhost.NewWASMHost(ctx, wasmBytes, 1)
		if err != nil {
			return fmt.Errorf("module failed VIndex host instantiation: %w", err)
		}
		_ = host.Close(ctx)
		fmt.Println("  >>> PASSED: Compatible with VIndex host runtime (vindexd).")
		return nil
	}

	return errors.New("module failed VIndex MapFn ABI requirements")
}
