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

package sdk

import (
	"encoding/binary"
	"testing"
)

func packBundleInput(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 || n > 256 {
		return nil
	}

	headerLen := 4 + (n+1)*4
	var payloadLen int
	for _, l := range leaves {
		payloadLen += len(l)
	}

	buf := make([]byte, headerLen+payloadLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(n))

	var currentOffset uint32
	binary.LittleEndian.PutUint32(buf[4:8], 0)
	payloadDst := buf[headerLen:]
	var writePos int

	for i, l := range leaves {
		copy(payloadDst[writePos:], l)
		writePos += len(l)
		currentOffset += uint32(len(l))
		binary.LittleEndian.PutUint32(buf[4+(i+1)*4:4+(i+2)*4], currentOffset)
	}

	return buf
}

func TestArena_InputBufferAndSliceBounds(t *testing.T) {
	base := inputBufferPtr()
	if base == 0 {
		t.Fatal("expected non-zero inputBufferPtr pointer")
	}
	if got := inputBuffer(); got != base {
		t.Fatalf("inputBuffer() = %d, want %d", got, base)
	}

	// Test writing and reading via getInputSlice
	slice := getInputSlice(base, 100)
	if len(slice) != 100 {
		t.Fatalf("expected slice len 100, got %d", len(slice))
	}
	for i := range slice {
		slice[i] = byte(i)
	}
	readSlice := getInputSlice(base, 100)
	for i := range readSlice {
		if readSlice[i] != byte(i) {
			t.Fatalf("mismatch at byte %d: got %d, want %d", i, readSlice[i], byte(i))
		}
	}

	// Bounds and uint32 wrap-around guards in getInputSlice
	if s := getInputSlice(base, 0); s != nil {
		t.Fatalf("expected nil for zero length, got len %d", len(s))
	}
	if s := getInputSlice(base, maxBufferSize+1); s != nil {
		t.Fatalf("expected nil for oversized length, got len %d", len(s))
	}
	if s := getInputSlice(base+50, ^uint32(0)-10); s != nil {
		t.Fatalf("expected nil for uint32 wrap-around length in getInputSlice, got len %d", len(s))
	}
	if s := getInputSlice(base-1, 10); s != nil {
		t.Fatalf("expected nil for ptr < base in getInputSlice, got len %d", len(s))
	}
}

func TestPackBundleInput_And_ExecuteBundle_Emit(t *testing.T) {
	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		if string(leaf) == "skip" {
			return
		}
		emit([]byte("key_" + string(leaf)))
		emit([]byte("extra_" + string(leaf)))
	})

	leaves := [][]byte{
		[]byte("leaf0"),
		[]byte("leaf1"),
		[]byte("skip"),
		[]byte("leaf3"),
	}

	packedInput := packBundleInput(leaves)
	if len(packedInput) == 0 {
		t.Fatal("packBundleInput returned empty buffer")
	}

	ptr := inputBufferPtr()
	copy(getInputSlice(ptr, uint32(len(packedInput))), packedInput)

	outPtr, outLen := executeBundle(ptr, uint32(len(packedInput)))
	if outPtr == 0 || outLen == 0 {
		t.Fatalf("executeBundle failed: outPtr=%d outLen=%d", outPtr, outLen)
	}

	outBuf := outputBuf[:outLen]
	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if leafCount != 4 {
		t.Fatalf("leafCount = %d, want 4", leafCount)
	}

	k0 := binary.LittleEndian.Uint32(outBuf[4:8])
	k1 := binary.LittleEndian.Uint32(outBuf[8:12])
	k2 := binary.LittleEndian.Uint32(outBuf[12:16])
	k3 := binary.LittleEndian.Uint32(outBuf[16:20])

	if k0 != 2 || k1 != 2 || k2 != 0 || k3 != 2 {
		t.Fatalf("key counts mismatch: [%d, %d, %d, %d], want [2, 2, 0, 2]", k0, k1, k2, k3)
	}

	// Verify mapBundle wasm export
	ret := mapBundle(ptr, uint32(len(packedInput)))
	if ret == 0 {
		t.Fatal("mapBundle returned 0")
	}
}

func TestExecuteBundle_EmitSingle(t *testing.T) {
	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		emit([]byte("domain_" + string(leaf)))
	})

	leaves := [][]byte{[]byte("example.com")}
	packedInput := packBundleInput(leaves)

	ptr := inputBufferPtr()
	copy(getInputSlice(ptr, uint32(len(packedInput))), packedInput)

	outPtr, outLen := executeBundle(ptr, uint32(len(packedInput)))
	if outPtr == 0 || outLen == 0 {
		t.Fatalf("executeBundle failed: outPtr=%d outLen=%d", outPtr, outLen)
	}

	outBuf := outputBuf[:outLen]
	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if leafCount != 1 {
		t.Fatalf("leafCount = %d, want 1", leafCount)
	}
	kCount := binary.LittleEndian.Uint32(outBuf[4:8])
	if kCount != 1 {
		t.Fatalf("kCount = %d, want 1", kCount)
	}

	keyLen := binary.LittleEndian.Uint32(outBuf[8:12])
	keyBytes := string(outBuf[12 : 12+keyLen])
	if keyBytes != "domain_example.com" {
		t.Fatalf("key = %q, want %q", keyBytes, "domain_example.com")
	}
}

func TestExecuteBundle_OffsetTableValidation(t *testing.T) {
	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		emit(leaf)
	})

	leaves := [][]byte{[]byte("example.com")}
	packedInput := packBundleInput(leaves)
	ptr := inputBufferPtr()

	// 1. OffsetTable[0] != 0 must fail
	badStart := append([]byte(nil), packedInput...)
	binary.LittleEndian.PutUint32(badStart[4:8], 1)
	copy(getInputSlice(ptr, uint32(len(badStart))), badStart)
	if outPtr, outLen := executeBundle(ptr, uint32(len(badStart))); outPtr != 0 || outLen != 0 {
		t.Fatalf("expected (0, 0) for non-zero OffsetTable[0], got (%d, %d)", outPtr, outLen)
	}

	// 2. OffsetTable[leafCount] != len(payload) must fail
	badEnd := append([]byte(nil), packedInput...)
	binary.LittleEndian.PutUint32(badEnd[8:12], uint32(len(leaves[0])-1))
	copy(getInputSlice(ptr, uint32(len(badEnd))), badEnd)
	if outPtr, outLen := executeBundle(ptr, uint32(len(badEnd))); outPtr != 0 || outLen != 0 {
		t.Fatalf("expected (0, 0) for OffsetTable[leafCount] != len(payload), got (%d, %d)", outPtr, outLen)
	}
}

func TestExecuteBundle_EmitOverflow(t *testing.T) {
	RegisterEmit(func(leaf []byte, emit func(key []byte)) {
		bigKey := make([]byte, maxBufferSize)
		emit(bigKey)
	})

	leaves := [][]byte{[]byte("leaf")}
	packedInput := packBundleInput(leaves)

	ptr := inputBufferPtr()
	copy(getInputSlice(ptr, uint32(len(packedInput))), packedInput)

	outPtr, outLen := executeBundle(ptr, uint32(len(packedInput)))
	if outPtr != 0 || outLen != 0 {
		t.Fatalf("expected (0, 0) on overflow, got (%d, %d)", outPtr, outLen)
	}
}
