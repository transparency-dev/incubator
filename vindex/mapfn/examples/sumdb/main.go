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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o sumdb.wasm ."

// Package main implements the SumDB WASM MapFn plugin.
package main

import (
	"bytes"
	"unsafe"

	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapSumDBLeaf)
}

var goModSuffix = []byte("/go.mod")

// MapSumDBLeaf parses a Go SumDB log leaf, filtering pseudo-versions and streaming canonical module path preimages.
func MapSumDBLeaf(data []byte, emit func(key []byte)) {
	var emitted [8][]byte
	n := 0
	var overflow [][]byte

	for len(data) > 0 {
		var line []byte
		idx := bytes.IndexByte(data, '\n')
		if idx >= 0 {
			line = data[:idx]
			data = data[idx+1:]
		} else {
			line = data
			data = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		modEnd := bytes.IndexByte(line, ' ')
		if modEnd <= 0 {
			continue
		}
		rawModPath := line[:modEnd]

		verStart := modEnd + 1
		if verStart >= len(line) {
			continue
		}
		verLen := bytes.IndexByte(line[verStart:], ' ')
		if verLen <= 0 || verStart+verLen+1 >= len(line) {
			continue
		}
		verBytes := bytes.TrimSuffix(line[verStart:verStart+verLen], goModSuffix)
		verStr := unsafe.String(unsafe.SliceData(verBytes), len(verBytes))
		if !semver.IsValid(verStr) || module.IsPseudoVersion(verStr) {
			continue
		}

		escaped, err := module.EscapePath(unsafe.String(unsafe.SliceData(rawModPath), len(rawModPath)))
		if err != nil || len(escaped) == 0 || len(escaped) > 1024 {
			continue
		}
		modPath := unsafe.Slice(unsafe.StringData(escaped), len(escaped))

		duplicate := false
		for i := 0; i < n; i++ {
			if bytes.Equal(emitted[i], modPath) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			for _, ov := range overflow {
				if bytes.Equal(ov, modPath) {
					duplicate = true
					break
				}
			}
		}
		if !duplicate {
			if n < len(emitted) {
				emitted[n] = modPath
				n++
			} else {
				overflow = append(overflow, modPath)
			}
			emit(modPath)
		}
	}
}
