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

// Package sdk provides the guest SDK for authoring VIndex WASM MapFn plugins.
package sdk

import (
	"encoding/binary"
	"unsafe"
)

const (
	// maxBufferSize is the static arena buffer size (4MB to accommodate 256-leaf bundles).
	maxBufferSize   = 4 * 1024 * 1024
	maxBundleLeaves = 256
)

// EmitMapFunc maps a raw input log leaf to search key preimages via an emitter callback.
type EmitMapFunc func(leaf []byte, emit func(key []byte))

var (
	registeredEmitMapFunc EmitMapFunc
	inputBuf              [maxBufferSize]byte
	outputBuf             [maxBufferSize]byte
	emitOutOffset         int
	emitKeyCount          int
	emitOverflow          bool
)

// RegisterEmit registers a streaming plugin using an emitter callback.
func RegisterEmit(fn EmitMapFunc) {
	registeredEmitMapFunc = fn
}

//go:wasmexport map_bundle
func mapBundle(inPtr, inLen uint32) uint64 {
	outPtr, outLen := executeBundle(inPtr, inLen)
	return (uint64(outPtr) << 32) | uint64(outLen)
}

//go:wasmexport input_buffer
func inputBuffer() uint32 {
	return uint32(uintptr(unsafe.Pointer(&inputBuf[0])))
}

// Suppress unused warnings when compiled on non-WASM architectures.
var (
	_ = mapBundle
	_ = inputBuffer
)

func emitKey(k []byte) {
	kLen := len(k)
	if emitOverflow || emitOutOffset+4+kLen > maxBufferSize {
		emitOverflow = true
		return
	}
	binary.LittleEndian.PutUint32(outputBuf[emitOutOffset:emitOutOffset+4], uint32(kLen))
	copy(outputBuf[emitOutOffset+4:emitOutOffset+4+kLen], k)
	emitOutOffset += 4 + kLen
	emitKeyCount++
}

func getInputSlice(ptr, length uint32) []byte {
	if length == 0 || length > maxBufferSize {
		return nil
	}
	base := inputBuffer()
	if ptr < base || ptr-base > maxBufferSize-length {
		return nil
	}
	offset := ptr - base
	return inputBuf[offset : offset+length]
}

func executeBundle(inPtr, inLen uint32) (uint32, uint32) {
	emitOverflow = false
	if inLen < 8 {
		return 0, 0
	}

	inSlice := getInputSlice(inPtr, inLen)
	if len(inSlice) < 8 {
		return 0, 0
	}

	leafCount := binary.LittleEndian.Uint32(inSlice[0:4])
	if leafCount == 0 || leafCount > maxBundleLeaves {
		return 0, 0
	}

	headerLen := 4 + (leafCount+1)*4
	if uint32(len(inSlice)) < headerLen {
		return 0, 0
	}

	offsetTable := inSlice[4:headerLen]
	payload := inSlice[headerLen:]

	if binary.LittleEndian.Uint32(offsetTable[0:4]) != 0 {
		return 0, 0
	}
	if binary.LittleEndian.Uint32(offsetTable[leafCount*4:(leafCount+1)*4]) != uint32(len(payload)) {
		return 0, 0
	}

	outBase := uint32(uintptr(unsafe.Pointer(&outputBuf[0])))
	binary.LittleEndian.PutUint32(outputBuf[0:4], leafCount)

	keyCountsOffset := 4
	outOffset := 4 + int(leafCount)*4

	for i := uint32(0); i < leafCount; i++ {
		start := binary.LittleEndian.Uint32(offsetTable[i*4 : (i+1)*4])
		end := binary.LittleEndian.Uint32(offsetTable[(i+1)*4 : (i+2)*4])

		if end < start || end > uint32(len(payload)) {
			return 0, 0
		}
		leafBytes := payload[start:end]

		if registeredEmitMapFunc != nil {
			emitOutOffset = outOffset
			emitKeyCount = 0
			registeredEmitMapFunc(leafBytes, emitKey)
			if emitOverflow {
				return 0, 0
			}
			binary.LittleEndian.PutUint32(outputBuf[keyCountsOffset+int(i)*4:], uint32(emitKeyCount))
			outOffset = emitOutOffset
		} else {
			binary.LittleEndian.PutUint32(outputBuf[keyCountsOffset+int(i)*4:], 0)
		}
	}

	return outBase, uint32(outOffset)
}
