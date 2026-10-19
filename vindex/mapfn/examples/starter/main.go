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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o starter.wasm ."

// Package main demonstrates a minimal starter template for authoring a VIndex WASM MapFn.
package main

import (
	"bytes"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
)

func main() {}

func init() {
	// Register the leaf mapping function using the zero-allocation streaming callback.
	sdk.RegisterEmit(MapLeaf)
}

// MapLeaf inspects a single log leaf and extracts one or more canonical search key preimages.
// Canonical keys must be 1..1024 printable ASCII bytes in 0x21..0x7E (no NUL or whitespace).
func MapLeaf(leaf []byte, emit func(key []byte)) {
	leaf = bytes.TrimSpace(leaf)
	if len(leaf) == 0 {
		return
	}

	var buf [1024]byte
	n := 0
	for _, b := range leaf {
		if n >= len(buf) {
			break
		}
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			if n > 0 && buf[n-1] != '_' {
				buf[n] = '_'
				n++
			}
			continue
		}
		if b >= 0x21 && b <= 0x7E {
			buf[n] = b
			n++
		}
	}
	for n > 0 && buf[n-1] == '_' {
		n--
	}
	if n == 0 {
		return
	}

	// Example: emit the normalized leaf payload as the search key preimage.
	// Replace this logic with your custom leaf parsing / key extraction.
	emit(buf[:n])
}
