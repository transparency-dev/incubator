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

// Package wasmtest provides compiled WASM guest fixtures for VIndex tests.
package wasmtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

var compileTestGuestOnce = sync.OnceValues(func() ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "vindex-testguest-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	wasmPath := filepath.Join(tmpDir, "testguest.wasm")
	_, thisFile, _, _ := runtime.Caller(0)
	guestDir := filepath.Join(filepath.Dir(thisFile), "testdata", "testguest")

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-buildmode=c-shared", "-o", wasmPath, ".")
	cmd.Dir = guestDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to build testdata/testguest: %w\n%s", err, string(out))
	}
	return os.ReadFile(wasmPath)
})

// Bytes compiles and returns the WebAssembly guest module in testdata/testguest
// built with the VIndex MapFn SDK (sdk.RegisterEmit).
func Bytes() []byte {
	b, err := compileTestGuestOnce()
	if err != nil {
		panic(err)
	}
	return b
}
