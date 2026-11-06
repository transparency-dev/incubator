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

// Package main implements the default test WASM guest using the VIndex MapFn SDK.
// For each newline-delimited line in a leaf, it emits the first whitespace-delimited
// token as a search key. To support fault-injection tests:
//   - If a leaf contains 0x00 (NUL), it panics (triggering a WASM trap).
//   - If a leaf contains 0x02 (STX), it spins indefinitely until cancelled by context timeout.
//   - If a leaf contains 0x03 (ETX), it overflows the 4 MB output slab so map_bundle returns (0, 0).
package main

import (
	"bytes"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapLeaf)
}

func MapLeaf(leaf []byte, emit func(key []byte)) {
	if bytes.IndexByte(leaf, 0x00) >= 0 {
		panic("injected trap: NUL byte in leaf")
	}
	if bytes.IndexByte(leaf, 0x02) >= 0 {
		for {
		}
	}
	if bytes.IndexByte(leaf, 0x03) >= 0 {
		bigKey := bytes.Repeat([]byte{'a'}, 1000)
		for range 4500 {
			emit(bigKey)
		}
		return
	}
	for line := range bytes.SplitSeq(leaf, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) > 0 {
			emit(fields[0])
		}
	}
}
