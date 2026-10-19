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

// EmitMapFunc maps a raw input log leaf to search key preimages via an emitter callback.
type EmitMapFunc func(leaf []byte, emit func(key []byte))

var registeredEmitMapFunc EmitMapFunc

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
	return inputBufferPtr()
}

// Suppress unused warnings when compiled on non-WASM architectures.
var (
	_ = mapBundle
	_ = inputBuffer
)
