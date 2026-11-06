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

// Package wasmhost provides a pure Wazero WebAssembly host runtime and ABI decoder
// for VIndex MapFn guest modules without HTTP or log-fetching dependencies.
package wasmhost

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

const (
	// DefaultBundleSize is the default number of leaves per bundle execution.
	DefaultBundleSize uint64 = 256
)

var (
	ErrWasmHalt        = errors.New("wasm execution halted due to violation or trap")
	ErrInvalidMemory   = errors.New("wasm returned memory pointer out of bounds")
	ErrMalformedOutput = errors.New("wasm output format is malformed")
	ErrHostClosed      = errors.New("wasm host is closed")
)

// MappedEntry represents a single canonical search key and its SHA-256 digest produced by a WASM MapFn.
type MappedEntry struct {
	Key     string
	KeyHash [sha256.Size]byte
}

// ValidatePreimageKey validates that a WASM-emitted preimage key satisfies the canonical
// key invariants: 1 <= len <= 1024 and printable ASCII (0x21..0x7E, no NUL or whitespace).
func ValidatePreimageKey(keyBytes []byte) error {
	if len(keyBytes) == 0 || len(keyBytes) > 1024 {
		return fmt.Errorf("%w: canonical key length %d out of range [1, 1024]", ErrMalformedOutput, len(keyBytes))
	}
	for i, b := range keyBytes {
		if b < 0x21 || b > 0x7E {
			return fmt.Errorf("%w: canonical key contains invalid byte 0x%02x at offset %d", ErrMalformedOutput, b, i)
		}
	}
	return nil
}

// WASMHost manages the lifecycle and execution of a compiled Wazero WebAssembly module.
type WASMHost struct {
	compiled wazero.CompiledModule
	pool     chan *wasmInstance
	mu       sync.Mutex
	closed   bool
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type wasmInstance struct {
	// Required for correctness: module instance and exported guest bindings.
	mod         api.Module
	mapBundleFn api.Function
	mem         api.Memory
	staticInPtr uint32

	// Performance optimizations (NOT functional requirements):
	// Reusable per-instance buffers to eliminate heap allocation churn during bundle processing.
	resultsBuf [][]MappedEntry // Reusable outer slice buffer for decoded leaf entries.
	entriesBuf []MappedEntry   // Reusable contiguous backing array for all mapped entries in a bundle.
}

var (
	sharedRuntimeOnce sync.Once
	sharedRuntime     wazero.Runtime
	compileMu         sync.Mutex
	compiledModules   = make(map[[sha256.Size]byte]wazero.CompiledModule)
)

func getSharedRuntime() wazero.Runtime {
	sharedRuntimeOnce.Do(func() {
		bgCtx := context.Background()
		sharedRuntime = wazero.NewRuntimeWithConfig(bgCtx, wazero.NewRuntimeConfig().
			WithDebugInfoEnabled(false).
			WithMemoryLimitPages(1024).
			WithCloseOnContextDone(true))
		wasi_snapshot_preview1.MustInstantiate(bgCtx, sharedRuntime)
	})
	return sharedRuntime
}

// CompileModule compiles wasmBytes on the shared Wazero runtime, returning a cached CompiledModule when available.
func CompileModule(ctx context.Context, wasmBytes []byte) (wazero.CompiledModule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := getSharedRuntime()
	hash := sha256.Sum256(wasmBytes)

	compileMu.Lock()
	defer compileMu.Unlock()
	if compiled, ok := compiledModules[hash]; ok {
		return compiled, nil
	}
	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}
	compiledModules[hash] = compiled
	return compiled, nil
}

// NewWASMHost compiles the guest bytecode and initializes a pool of instantiated WASM modules.
// If poolSize <= 0, it defaults to runtime.GOMAXPROCS(0) - 1 (minimum 1).
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	if poolSize <= 0 {
		poolSize = runtime.GOMAXPROCS(0) - 1
		if poolSize < 1 {
			poolSize = 1
		}
	}

	compiled, err := CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, err
	}

	h := &WASMHost{
		compiled: compiled,
		pool:     make(chan *wasmInstance, poolSize),
	}

	inst, err := h.instantiateInstance(ctx)
	if err != nil {
		_ = h.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate initial wasm module 0: %w", err)
	}
	h.pool <- inst

	return h, nil
}

func (h *WASMHost) instantiateInstance(ctx context.Context) (*wasmInstance, error) {
	wasiConfig := wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions("_initialize").
		WithStdout(io.Discard).
		WithStderr(io.Discard).
		WithStdin(bytes.NewReader(nil)).
		WithArgs().
		WithWalltime(func() (sec int64, nsec int32) { return 1, 0 }, sys.ClockResolution(1)).
		WithNanotime(func() int64 { return 1_000_000 }, sys.ClockResolution(1)).
		WithNanosleep(func(int64) {}).
		WithRandSource(zeroReader{})

	mod, err := getSharedRuntime().InstantiateModule(ctx, h.compiled, wasiConfig)
	if err != nil {
		return nil, err
	}

	mapBundleFn := mod.ExportedFunction("map_bundle")
	if mapBundleFn == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: 'map_bundle' not exported", ErrWasmHalt)
	}

	mem := mod.Memory()
	if mem == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: module memory not found", ErrWasmHalt)
	}

	inBufFn := mod.ExportedFunction("input_buffer")
	if inBufFn == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: 'input_buffer' not exported", ErrWasmHalt)
	}
	res, err := inBufFn.Call(ctx)
	if err != nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: input_buffer call failed: %v", ErrWasmHalt, err)
	}
	if len(res) == 0 {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: input_buffer returned no result", ErrWasmHalt)
	}
	staticInPtr := uint32(res[0])
	if staticInPtr == 0 {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: input_buffer returned null pointer (0)", ErrInvalidMemory)
	}
	if _, ok := mem.Read(staticInPtr, 4*1024*1024); !ok {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: input_buffer (ptr=%d, len=4MB) exceeds guest memory %d", ErrInvalidMemory, staticInPtr, mem.Size())
	}

	return &wasmInstance{
		mod:         mod,
		mapBundleFn: mapBundleFn,
		mem:         mem,
		staticInPtr: staticInPtr,
	}, nil
}

func (inst *wasmInstance) executeBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	n := len(leaves)
	if n == 0 {
		return nil, nil
	}
	if uint64(n) > DefaultBundleSize {
		return nil, fmt.Errorf("%w: bundle size %d exceeds %d", ErrMalformedOutput, n, DefaultBundleSize)
	}

	headerLen := 4 + (n+1)*4
	var payloadLen int
	for _, l := range leaves {
		payloadLen += len(l)
	}
	totalLen := headerLen + payloadLen
	if totalLen > 4*1024*1024 {
		return nil, fmt.Errorf("%w: bundle input size %d exceeds 4 MB static slab capacity", ErrWasmHalt, totalLen)
	}
	inPtr := inst.staticInPtr
	inputLen := uint32(totalLen)
	destSlice, ok := inst.mem.Read(inPtr, inputLen)
	if !ok {
		return nil, fmt.Errorf("%w: failed to read guest buffer at ptr %d len %d", ErrInvalidMemory, inPtr, totalLen)
	}
	binary.LittleEndian.PutUint32(destSlice[0:4], uint32(n))
	var currentOffset uint32
	binary.LittleEndian.PutUint32(destSlice[4:8], 0)
	payloadDst := destSlice[headerLen:]
	var writePos int
	for i, l := range leaves {
		copy(payloadDst[writePos:], l)
		writePos += len(l)
		currentOffset += uint32(len(l))
		binary.LittleEndian.PutUint32(destSlice[4+(i+1)*4:4+(i+2)*4], currentOffset)
	}

	callRes, err := inst.mapBundleFn.Call(ctx, uint64(inPtr), uint64(inputLen))
	if err != nil {
		return nil, fmt.Errorf("%w: map_bundle execution failed: %v", ErrWasmHalt, err)
	}
	if len(callRes) == 0 {
		return nil, fmt.Errorf("%w: map_bundle returned no result", ErrMalformedOutput)
	}

	packed := callRes[0]
	outPtr := uint32(packed >> 32)
	outLen := uint32(packed & 0xFFFFFFFF)
	if outPtr == 0 || outLen == 0 {
		return nil, fmt.Errorf("%w: map_bundle returned (ptr=%d, len=%d): output slab overflow or invalid input", ErrWasmHalt, outPtr, outLen)
	}

	outBuf, ok := inst.mem.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("%w: out_ptr=%d out_len=%d exceeds guest memory %d",
			ErrInvalidMemory, outPtr, outLen, inst.mem.Size())
	}

	return inst.decodeBundleOutput(outBuf, n)
}

func decodeBundleOutputInto(resultsBuf [][]MappedEntry, entriesBuf []MappedEntry, outBuf []byte, expectedCount int) ([][]MappedEntry, []MappedEntry, error) {
	if len(outBuf) < 4+expectedCount*4 {
		return nil, nil, fmt.Errorf("%w: bundle output length %d is too short for %d leaves", ErrMalformedOutput, len(outBuf), expectedCount)
	}

	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if int(leafCount) != expectedCount {
		return nil, nil, fmt.Errorf("%w: bundle output leaf_count %d != expected %d", ErrMalformedOutput, leafCount, expectedCount)
	}

	keyCountsOffset := 4
	preimagesOffset := 4 + expectedCount*4

	var totalKeysU64 uint64
	for i := 0; i < expectedCount; i++ {
		totalKeysU64 += uint64(binary.LittleEndian.Uint32(outBuf[keyCountsOffset+i*4 : keyCountsOffset+(i+1)*4]))
	}

	maxPossibleKeys := uint64(len(outBuf)-preimagesOffset) / 4
	if totalKeysU64 > maxPossibleKeys {
		return nil, nil, fmt.Errorf("%w: total keys %d exceeds maximum possible %d for buffer length %d", ErrMalformedOutput, totalKeysU64, maxPossibleKeys, len(outBuf))
	}
	totalKeys := int(totalKeysU64)

	if cap(resultsBuf) < expectedCount {
		resultsBuf = make([][]MappedEntry, expectedCount)
	} else {
		resultsBuf = resultsBuf[:expectedCount]
		clear(resultsBuf)
	}
	if totalKeys == 0 {
		if preimagesOffset != len(outBuf) {
			return nil, nil, fmt.Errorf("%w: trailing unconsumed bytes in bundle output (%d != %d)", ErrMalformedOutput, preimagesOffset, len(outBuf))
		}
		return resultsBuf, entriesBuf[:0], nil
	}

	if cap(entriesBuf) < totalKeys {
		entriesBuf = make([]MappedEntry, totalKeys)
	} else {
		entriesBuf = entriesBuf[:totalKeys]
	}
	allEntries := entriesBuf
	var curEntryIdx int

	for i := 0; i < expectedCount; i++ {
		kCount := int(binary.LittleEndian.Uint32(outBuf[keyCountsOffset+i*4 : keyCountsOffset+(i+1)*4]))
		if kCount == 0 {
			continue
		}

		startEntryIdx := curEntryIdx
		for j := 0; j < kCount; j++ {
			if preimagesOffset+4 > len(outBuf) {
				return nil, nil, fmt.Errorf("%w: truncated key length header", ErrMalformedOutput)
			}
			keyLen := binary.LittleEndian.Uint32(outBuf[preimagesOffset : preimagesOffset+4])
			preimagesOffset += 4

			if uint64(preimagesOffset)+uint64(keyLen) > uint64(len(outBuf)) {
				return nil, nil, fmt.Errorf("%w: truncated key bytes", ErrMalformedOutput)
			}
			keyBytes := outBuf[preimagesOffset : preimagesOffset+int(keyLen)]
			preimagesOffset += int(keyLen)
			if err := ValidatePreimageKey(keyBytes); err != nil {
				return nil, nil, err
			}

			allEntries[curEntryIdx] = MappedEntry{
				Key: string(keyBytes),
			}
			curEntryIdx++
		}

		entries := allEntries[startEntryIdx:curEntryIdx]
		if len(entries) > 1 {
			slices.SortFunc(entries, func(a, b MappedEntry) int {
				return cmp.Compare(a.Key, b.Key)
			})
			entries = slices.CompactFunc(entries, func(a, b MappedEntry) bool {
				return a.Key == b.Key
			})
		}
		for k := range entries {
			entries[k].KeyHash = sha256.Sum256([]byte(entries[k].Key))
		}
		curEntryIdx = startEntryIdx + len(entries)
		resultsBuf[i] = entries[:len(entries):len(entries)]
	}

	if preimagesOffset != len(outBuf) {
		return nil, nil, fmt.Errorf("%w: trailing unconsumed bytes in bundle output (%d != %d)", ErrMalformedOutput, preimagesOffset, len(outBuf))
	}

	return resultsBuf, allEntries[:curEntryIdx], nil
}

func (inst *wasmInstance) decodeBundleOutput(outBuf []byte, expectedCount int) ([][]MappedEntry, error) {
	results, entries, err := decodeBundleOutputInto(inst.resultsBuf, inst.entriesBuf, outBuf, expectedCount)
	if err != nil {
		return nil, err
	}
	inst.resultsBuf = results
	inst.entriesBuf = entries
	return results, nil
}

// MapBundle executes WASM mapping across a contiguous bundle of leaves using a checked-out runner.
func (h *WASMHost) MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	runner, err := h.NewRunner(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = runner.Close(ctx) }()

	results, err := runner.MapBundle(ctx, leaves)
	if err != nil {
		return nil, err
	}
	return cloneBundleResults(results), nil
}

func cloneBundleResults(results [][]MappedEntry) [][]MappedEntry {
	if results == nil {
		return nil
	}
	cloned := make([][]MappedEntry, len(results))
	for i, r := range results {
		if len(r) > 0 {
			cloned[i] = append([]MappedEntry(nil), r...)
		}
	}
	return cloned
}

// Close closes all pooled module instances.
func (h *WASMHost) Close(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true

	close(h.pool)
	for inst := range h.pool {
		if inst != nil && inst.mod != nil {
			_ = inst.mod.Close(ctx)
		}
	}
	return nil
}

// WASMRunner is a dedicated, unshared WASM execution environment bound to a single worker.
// It executes mapping calls lock-free without instance pool or mutex contention.
type WASMRunner struct {
	host   *WASMHost
	inst   *wasmInstance
	closed bool
	hadErr bool
}

// NewRunner creates a dedicated WASMRunner from the host.
// The runner has exclusive access to its WASM module instance, eliminating pool and mutex overhead.
func (h *WASMHost) NewRunner(ctx context.Context) (*WASMRunner, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrHostClosed
	}
	h.mu.Unlock()

	var inst *wasmInstance
	select {
	case inst = <-h.pool:
	default:
	}
	if inst == nil {
		var err error
		inst, err = h.instantiateInstance(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate wasm runner: %w", err)
		}
	}

	return &WASMRunner{
		host: h,
		inst: inst,
	}, nil
}

// MapBundle executes WASM mapping across a contiguous bundle of leaves on this dedicated runner.
// The returned slice and sub-slices reference internal runner buffers and remain valid until
// the next invocation of MapBundle on this runner.
func (r *WASMRunner) MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	if r.closed {
		return nil, ErrHostClosed
	}
	if r.hadErr {
		return nil, fmt.Errorf("%w: wasm runner already failed", ErrWasmHalt)
	}

	results, err := r.inst.executeBundle(ctx, leaves)
	if err != nil {
		r.hadErr = true
		return nil, err
	}

	return results, nil
}

// Close releases this runner's WASM module instance, returning it to the host pool if healthy.
func (r *WASMRunner) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	r.closed = true

	if r.inst == nil {
		return nil
	}

	if r.hadErr {
		if r.inst.mod != nil {
			err := r.inst.mod.Close(ctx)
			r.inst.mod = nil
			return err
		}
		return nil
	}

	r.host.mu.Lock()
	defer r.host.mu.Unlock()

	if r.host.closed {
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}

	select {
	case r.host.pool <- r.inst:
		return nil
	default:
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}
}
