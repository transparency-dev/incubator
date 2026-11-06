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

package wasmhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmtest"
)

func TestWASMHost_PreimageKeysAndDeduplication(t *testing.T) {
	ctx := context.Background()

	hBeta := sha256.Sum256([]byte("key_beta"))
	hAlpha := sha256.Sum256([]byte("key_alpha"))

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapBundle(ctx, [][]byte{[]byte("key_beta\nkey_alpha\nkey_alpha")})
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}

	expected := [][]MappedEntry{{
		{Key: "key_alpha", KeyHash: hAlpha},
		{Key: "key_beta", KeyHash: hBeta},
	}}

	if !slices.EqualFunc(results, expected, slices.Equal) {
		t.Fatalf("MapBundle = %+v, want %+v", results, expected)
	}
}

func TestWASMHost_EmptyOutput(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapBundle(ctx, [][]byte{[]byte("   \n\t  ")})
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}
	if len(results) != 1 || len(results[0]) != 0 {
		t.Fatalf("expected 1 empty leaf result, got %v", results)
	}
}

func TestWASMHost_UnreachableTrap(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapBundle(ctx, [][]byte{[]byte("\x00trap_leaf")})
	if err == nil {
		t.Fatal("expected error on unreachable trap, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMHost_MalformedOutput(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapBundle(ctx, [][]byte{[]byte("\x01malformed")})
	if err == nil {
		t.Fatal("expected malformed output error, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestWASMHost_ConcurrentExecution(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("concurrent_key"))
	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 4)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				res, err := host.MapBundle(ctx, [][]byte{[]byte("concurrent_key")})
				if err != nil {
					t.Errorf("concurrent MapBundle failed: %v", err)
					return
				}
				if len(res) != 1 || len(res[0]) != 1 || res[0][0].Key != "concurrent_key" || res[0][0].KeyHash != h1 {
					t.Errorf("unexpected MapBundle result: %v", res)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestWASMHost_ClosedHost(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}

	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err = host.MapBundle(ctx, [][]byte{[]byte("leaf")})
	if !errors.Is(err, ErrHostClosed) {
		t.Fatalf("expected ErrHostClosed after Close(), got: %v", err)
	}
}

func TestWASMHost_MissingInputBufferExport(t *testing.T) {
	ctx := context.Background()

	// Rename the 12-byte export "input_buffer" to "other_buffer" so the binary
	// remains valid WASM but lacks the required "input_buffer" export.
	wasmBytes := bytes.ReplaceAll(slices.Clone(wasmtest.Bytes()), []byte("input_buffer"), []byte("other_buffer"))

	_, err := NewWASMHost(ctx, wasmBytes, 1)
	if err == nil {
		t.Fatal("expected error on missing input_buffer export, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMHost_MissingMapBundleExport(t *testing.T) {
	ctx := context.Background()

	// Rename the 10-byte export "map_bundle" to "other_func" so the binary
	// remains valid WASM but lacks the required "map_bundle" export.
	wasmBytes := bytes.ReplaceAll(slices.Clone(wasmtest.Bytes()), []byte("map_bundle"), []byte("other_func"))

	_, err := NewWASMHost(ctx, wasmBytes, 1)
	if err == nil {
		t.Fatal("expected error on missing map_bundle export, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMHost_Timeout(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leafCtx, leafCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer leafCancel()

	start := time.Now()
	_, err = host.MapBundle(leafCtx, [][]byte{[]byte("\x02infinite_loop")})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error for infinite loop, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
	if elapsed < 80*time.Millisecond || elapsed > 2000*time.Millisecond {
		t.Logf("execution elapsed: %v (expected ~100ms timeout)", elapsed)
	}
}

func TestWASMHost_MapBundle_PreimagesAndHardwareHashing(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	k0 := []byte("golang.org/x/mod")
	k1 := []byte("example.com")
	k2 := []byte("my-package")

	leaves := [][]byte{
		[]byte("golang.org/x/mod\nexample.com"),
		[]byte("   "),
		[]byte("my-package"),
	}

	results, err := host.MapBundle(ctx, leaves)
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	h0 := sha256.Sum256(k0)
	h1 := sha256.Sum256(k1)
	if len(results[0]) != 2 {
		t.Fatalf("leaf 0 expected 2 entries, got %d", len(results[0]))
	}
	// Lexicographical sort by canonical Key: "example.com" (k1) < "golang.org/x/mod" (k0).
	if results[0][0].KeyHash != h1 || results[0][1].KeyHash != h0 {
		t.Fatalf("leaf 0 key hashes mismatch: got %+v", results[0])
	}

	if len(results[1]) != 0 {
		t.Fatalf("leaf 1 expected 0 entries, got %d", len(results[1]))
	}

	h2 := sha256.Sum256(k2)
	if len(results[2]) != 1 {
		t.Fatalf("leaf 2 expected 1 entry, got %d", len(results[2]))
	}
	if results[2][0].KeyHash != h2 {
		t.Fatalf("leaf 2 hash mismatch: got %x, want %x", results[2][0].KeyHash, h2)
	}
}

func BenchmarkWASMHost_MapBundle(b *testing.B) {
	ctx := context.Background()
	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte("benchmark_leaf_payload")
	}

	b.ReportAllocs()

	for b.Loop() {
		_, err := host.MapBundle(ctx, leaves)
		if err != nil {
			b.Fatalf("MapBundle failed: %v", err)
		}
	}
}

func BenchmarkWASMRunner_MapBundle(b *testing.B) {
	ctx := context.Background()
	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		b.Fatalf("NewRunner failed: %v", err)
	}
	defer func() { _ = runner.Close(ctx) }()

	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte("benchmark_leaf_payload")
	}

	b.ReportAllocs()

	for b.Loop() {
		_, err := runner.MapBundle(ctx, leaves)
		if err != nil {
			b.Fatalf("runner.MapBundle failed: %v", err)
		}
	}
}

func BenchmarkDecodeBundleOutputInto(b *testing.B) {
	const leavesCount = 256
	const keysPerLeaf = 2
	var outBuf bytes.Buffer
	var countBuf [4]byte
	binary.LittleEndian.PutUint32(countBuf[:], leavesCount)
	outBuf.Write(countBuf[:])

	for i := 0; i < leavesCount; i++ {
		var kc [4]byte
		binary.LittleEndian.PutUint32(kc[:], keysPerLeaf)
		outBuf.Write(kc[:])
	}

	domain1 := []byte("example.com")
	domain2 := []byte("sub.example.org")
	for i := 0; i < leavesCount; i++ {
		var k1Len, k2Len [4]byte
		binary.LittleEndian.PutUint32(k1Len[:], uint32(len(domain1)))
		outBuf.Write(k1Len[:])
		outBuf.Write(domain1)

		binary.LittleEndian.PutUint32(k2Len[:], uint32(len(domain2)))
		outBuf.Write(k2Len[:])
		outBuf.Write(domain2)
	}

	rawOutput := outBuf.Bytes()
	var resultsBuf [][]MappedEntry
	var entriesBuf []MappedEntry

	b.ReportAllocs()

	for b.Loop() {
		var err error
		resultsBuf, entriesBuf, err = decodeBundleOutputInto(resultsBuf, entriesBuf, rawOutput, leavesCount)
		if err != nil || len(resultsBuf) != leavesCount {
			b.Fatalf("decodeBundleOutputInto failed: %v", err)
		}
	}
}

func TestWASMRunner_DedicatedExecution(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer func() { _ = runner.Close(ctx) }()

	leaves := [][]byte{[]byte("bundle_leaf_0")}
	bundleRes, err := runner.MapBundle(ctx, leaves)
	if err != nil {
		t.Fatalf("runner.MapBundle failed: %v", err)
	}
	if len(bundleRes) != 1 || len(bundleRes[0]) == 0 {
		t.Fatalf("expected 1 non-empty bundle result, got %v", bundleRes)
	}
}

func TestWASMRunner_ConcurrentDedicatedRunners(t *testing.T) {
	ctx := context.Background()

	concurrency := 8
	host, err := NewWASMHost(ctx, wasmtest.Bytes(), concurrency)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runner, err := host.NewRunner(ctx)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: NewRunner failed: %w", workerID, err)
				return
			}
			defer func() { _ = runner.Close(ctx) }()

			for j := 0; j < 50; j++ {
				leaves := [][]byte{
					[]byte(fmt.Sprintf("worker_%d_bundle_%d_leaf_0", workerID, j)),
					[]byte(fmt.Sprintf("worker_%d_bundle_%d_leaf_1", workerID, j)),
				}
				res, err := runner.MapBundle(ctx, leaves)
				if err != nil {
					errCh <- fmt.Errorf("worker %d: MapBundle failed on iter %d: %w", workerID, j, err)
					return
				}
				if len(res) != 2 {
					errCh <- fmt.Errorf("worker %d: expected 2 results, got %d", workerID, len(res))
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func TestDecodeBundleOutput_BoundsCheck(t *testing.T) {
	outBuf := make([]byte, 20)
	binary.LittleEndian.PutUint32(outBuf[0:4], 1)
	binary.LittleEndian.PutUint32(outBuf[4:8], 1_000_000)

	_, _, err := decodeBundleOutputInto(nil, nil, outBuf, 1)
	if err == nil {
		t.Fatal("expected error for totalKeys exceeding buffer capacity, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestDecodeBundleOutputInto_CapacityProtection(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_a")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_a")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_b")

	results, entries, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 2)
	if err != nil {
		t.Fatalf("decodeBundleOutputInto failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 leaf results, got %d", len(results))
	}
	if len(results[0]) != 1 {
		t.Fatalf("expected 1 compacted key in leaf 0, got %d", len(results[0]))
	}
	if cap(results[0]) != len(results[0]) {
		t.Errorf("expected cap(results[0]) == len(results[0]) (%d), got cap %d", len(results[0]), cap(results[0]))
	}
	if len(results[1]) != 1 {
		t.Fatalf("expected 1 key in leaf 1, got %d", len(results[1]))
	}
	if cap(results[1]) != len(results[1]) {
		t.Errorf("expected cap(results[1]) == len(results[1]) (%d), got cap %d", len(results[1]), cap(results[1]))
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 total compacted entries, got %d", len(entries))
	}
	expectedHashA := sha256.Sum256([]byte("key_a"))
	expectedHashB := sha256.Sum256([]byte("key_b"))
	if results[0][0].KeyHash != expectedHashA {
		t.Errorf("leaf 0 hash mismatch: got %x, want %x", results[0][0].KeyHash, expectedHashA)
	}
	if results[1][0].KeyHash != expectedHashB {
		t.Errorf("leaf 1 hash mismatch: got %x, want %x", results[1][0].KeyHash, expectedHashB)
	}
}

func TestDecodeBundleOutputInto_KeyLenOverflow(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	buf.WriteString("short_data")

	_, _, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 1)
	if err == nil {
		t.Fatal("expected ErrMalformedOutput for overflowing keyLen, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestWASMHost_MapBundle_ZeroLenSlabOverflowFailsFast(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	// 0x03 causes testguest to overflow the 4 MB output slab so map_bundle returns (0, 0).
	_, err = host.MapBundle(ctx, [][]byte{[]byte("\x03overflow")})
	if err == nil {
		t.Fatal("expected ErrWasmHalt when map_bundle returns (0, 0), got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMRunner_TrapDiscardsBrokenInstanceAndRecovers(t *testing.T) {
	ctx := context.Background()

	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	if _, err := runner.MapBundle(ctx, [][]byte{[]byte("\x00trap")}); !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt on trap, got: %v", err)
	}
	if err := runner.Close(ctx); err != nil {
		t.Fatalf("runner.Close failed: %v", err)
	}
	if got := len(host.pool); got != 0 {
		t.Fatalf("expected broken runner not to be returned to pool, got pool len %d", got)
	}

	// Next MapBundle lazily instantiates a fresh healthy instance.
	res, err := host.MapBundle(ctx, [][]byte{[]byte("healthy_key")})
	if err != nil {
		t.Fatalf("MapBundle after runner trap failed: %v", err)
	}
	if len(res) != 1 || len(res[0]) != 1 || res[0][0].Key != "healthy_key" {
		t.Fatalf("unexpected result after recovery: %+v", res)
	}
}

func TestDecodeBundleOutputInto_NonCanonicalKeys(t *testing.T) {
	badKeys := [][]byte{
		{},
		bytes.Repeat([]byte("a"), 1025),
		[]byte("has space"),
		[]byte("has\x00nul"),
		[]byte("has\x7fdel"),
		[]byte{0x20},
		[]byte{0xff},
	}
	for i, badKey := range badKeys {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(badKey)))
		buf.Write(badKey)

		_, _, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 1)
		if !errors.Is(err, ErrMalformedOutput) {
			t.Fatalf("case %d (%q): expected ErrMalformedOutput, got %v", i, badKey, err)
		}
	}
}

func TestDecodeBundleOutputInto_TrailingUnconsumedBytes(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(5))
	buf.WriteString("key_a")
	buf.WriteByte(0x99) // trailing unconsumed byte

	_, _, err := decodeBundleOutputInto(nil, nil, buf.Bytes(), 1)
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput for trailing bytes, got %v", err)
	}
}

func TestWASMRunner_FailsSubsequentCallsAfterError(t *testing.T) {
	ctx := context.Background()
	host, err := NewWASMHost(ctx, wasmtest.Bytes(), 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	runner, err := host.NewRunner(ctx)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	defer func() { _ = runner.Close(ctx) }()

	if _, err := runner.MapBundle(ctx, [][]byte{[]byte("\x00trap")}); !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt on first call, got %v", err)
	}
	if _, err := runner.MapBundle(ctx, [][]byte{[]byte("second")}); !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt on subsequent MapBundle after failure, got %v", err)
	}
}

func TestZeroReader_Infinite(t *testing.T) {
	var zr zeroReader
	buf := bytes.Repeat([]byte{0xaa}, 4096)
	n, err := zr.Read(buf)
	if err != nil || n != 4096 {
		t.Fatalf("zeroReader.Read = (%d, %v), want (4096, nil)", n, err)
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("buf[%d] = 0x%02x, want 0", i, b)
		}
	}
}
