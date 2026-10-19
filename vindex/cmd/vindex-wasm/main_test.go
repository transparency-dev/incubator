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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

func TestCLI_TestCmd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, wasmhost.TestWASMBytes(), 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}

	// 1. Plain output
	err := run(ctx, []string{"test", "--wasm=" + wasmPath, "--input=hello"})
	if err != nil {
		t.Fatalf("test command failed: %v", err)
	}

	// 2. JSON output
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "--input=hello", "--format=json"})
	if err != nil {
		t.Fatalf("test json command failed: %v", err)
	}

	// 3. Hex input
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "--hex=68656c6c6f"})
	if err != nil {
		t.Fatalf("test hex command failed: %v", err)
	}

	// 4. Input file
	inFile := filepath.Join(tmpDir, "input.txt")
	if err := os.WriteFile(inFile, []byte("file_input"), 0o644); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "--input_file=" + inFile})
	if err != nil {
		t.Fatalf("test input_file command failed: %v", err)
	}

	// 5. Positional input
	err = run(ctx, []string{"test", "--wasm=" + wasmPath, "positional_arg_leaf"})
	if err != nil {
		t.Fatalf("test positional command failed: %v", err)
	}
}

func TestCLI_InspectCmd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmBytes := wasmhost.TestWASMBytes()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = w
	runErr := run(ctx, []string{"inspect", "--wasm=" + wasmPath})
	_ = w.Close()
	os.Stdout = origStdout
	outBytes, _ := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatalf("inspect command failed: %v", runErr)
	}

	digest := sha256.Sum256(wasmBytes)
	wantB64 := fmt.Sprintf("MapFn (base64): %s", base64.StdEncoding.EncodeToString(digest[:]))
	wantHex := fmt.Sprintf("SHA-256 (hex): %x", digest)
	outStr := string(outBytes)
	if !strings.Contains(outStr, wantB64) {
		t.Errorf("inspect output missing %q:\n%s", wantB64, outStr)
	}
	if !strings.Contains(outStr, wantHex) {
		t.Errorf("inspect output missing %q:\n%s", wantHex, outStr)
	}

	// Positional syntax
	err = run(ctx, []string{"inspect", wasmPath})
	if err != nil {
		t.Fatalf("inspect positional failed: %v", err)
	}
}

func TestCLI_BenchCmd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, wasmhost.TestWASMBytes(), 0o644); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}

	err := run(ctx, []string{"bench", "--wasm=" + wasmPath, "--iterations=50", "--workers=2"})
	if err != nil {
		t.Fatalf("bench command failed: %v", err)
	}
}

func TestCLI_ErrorsAndHelp(t *testing.T) {
	ctx := context.Background()

	// Empty args
	if err := run(ctx, []string{}); err == nil {
		t.Fatal("expected error on empty args, got nil")
	}

	// Help flag
	if err := run(ctx, []string{"--help"}); err != nil {
		t.Fatalf("expected nil for help, got %v", err)
	}

	// Unknown subcommand
	if err := run(ctx, []string{"unknown-cmd"}); err == nil {
		t.Fatal("expected error on unknown subcommand, got nil")
	}

	// Missing wasm flag
	if err := run(ctx, []string{"test"}); err == nil {
		t.Fatal("expected error on missing --wasm, got nil")
	}
}

func TestCLI_WithCompiledPlugins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow wasm compilation test in short mode")
	}
	ctx := context.Background()
	tmpDir := t.TempDir()

	sumdbWasm := filepath.Join(tmpDir, "sumdb.wasm")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", sumdbWasm, "github.com/transparency-dev/incubator/vindex/mapfn/examples/sumdb")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build sumdb wasm: %v\nOutput: %s", err, string(out))
	}

	ctWasm := filepath.Join(tmpDir, "ct.wasm")
	cmd = exec.Command("go", "build", "-buildmode=c-shared", "-o", ctWasm, "github.com/transparency-dev/incubator/vindex/mapfn/examples/ct")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build ct wasm: %v\nOutput: %s", err, string(out))
	}

	// 1. Test sumdb plugin via CLI
	err := run(ctx, []string{"test", "--wasm=" + sumdbWasm, "--input=golang.org/x/mod v0.40.0 h1:abc="})
	if err != nil {
		t.Fatalf("sumdb test failed: %v", err)
	}

	// 2. Test CT plugin via CLI with a real DER X.509 certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "foo.bar.example.com"},
		DNSNames:     []string{"foo.bar.example.com", "sub.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDer, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certHex := hex.EncodeToString(certDer)

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	ctErr := run(ctx, []string{"test", "--wasm=" + ctWasm, "--hex=" + certHex, "--format=json"})
	_ = w.Close()
	os.Stdout = origStdout
	ctOut, _ := io.ReadAll(r)
	_ = r.Close()
	if ctErr != nil {
		t.Fatalf("ct test failed: %v", ctErr)
	}
	if !strings.Contains(string(ctOut), "com.example.bar.foo.") || !strings.Contains(string(ctOut), "org.example.sub.") {
		t.Fatalf("ct test output missing expected canonical keys:\n%s", string(ctOut))
	}

	// 3. Bench CT plugin
	certFile := filepath.Join(tmpDir, "cert.der")
	if err := os.WriteFile(certFile, certDer, 0o644); err != nil {
		t.Fatalf("WriteFile(cert.der): %v", err)
	}
	err = run(ctx, []string{"bench", "--wasm=" + ctWasm, "--input_file=" + certFile, "--iterations=50", "--workers=2"})
	if err != nil {
		t.Fatalf("ct bench failed: %v", err)
	}
}
