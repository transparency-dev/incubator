# WASM Guest SDK & Plugin Interface

This document defines the WebAssembly guest ABI, developer contract, memory management protocols, load-bearing invariants, and verified performance optimizations across VIndex's mapping packages:
- **`vindex/mapfn/sdk`** *(public Go package)*: External zero-allocation Go guest SDK imported by WASM plugin authors.
- **`vindex/internal/wasmhost`** *(internal Go package)*: Internal WASI-free Wazero sandbox host used by `vindexd`, `vindex-auditor`, and `vindex-wasm`.

---

## 1. Context & Objectives

### 1.1 Architectural Separation: User Callback vs. Guest SDK vs. Host Runtime
Mapping in VIndex operates across three decoupled layers:
1. **User Logic (`MapFn`)**: The pure mapping logic (`func(entry []byte, emit func(key []byte))` in Go, or any language targeting the slab ABI) written by ecosystem developers. In Go, user logic has no knowledge of WebAssembly, linear memory pointers, or host runtimes.
2. **Public Guest SDK (`vindex/mapfn/sdk`, Go) / Language-Agnostic Slab ABI**: `vindex/mapfn/sdk` is the public Go guest harness compiled into `.wasm` alongside Go `MapFn` callbacks. Because the underlying `input_buffer` / `map_bundle` slab ABI (§2.2) uses flat little-endian linear memory, guest plugins can equally be written in Rust (`wasm32-unknown-unknown` / `wasm32-wasip1`), C/C++, Zig, or TinyGo without `mapfn/sdk`.
3. **Internal Host Sandbox Runtime (`vindex/internal/wasmhost` & `vindex/internal/ingest`)**: `internal/wasmhost` provides the internal, WASI-free Wazero sandbox pool (`InstantiateModule`) that loads the compiled `.wasm` plugin, executes `map_bundle` over 256-entry bundles, strictly validates every emitted canonical key (`1..1024` bytes in `0x21..0x7E`, returning a fatal error that immediately `HALT`s the daemon on violation), and preserves un-hashed canonical keys for the MPT, while `internal/ingest` computes `KeyHash = SHA-256(key)` strictly as an internal Pebble storage digest using native CPU SIMD instructions.

### 1.2 Problem Statement & Real-World Friction
Every transparency ecosystem indexes different payloads (e.g. DER X.509 certificates in Certificate Transparency, newline-delimited strings in Go SumDB, or JSON provenance records in Sigstore). VIndex must allow ecosystem authors to define custom extraction logic without compromising node security, crashing the host process, or causing state divergence across independent auditors.

Relying on in-process native Go plugins or shared libraries introduces three severe failure modes:
1. **Toolchain Version Drift & Non-Determinism**: If an Index Operator and an Auditor compile their code with different Go versions (e.g. Go 1.23 vs. Go 1.25) or execute on different operating systems, standard library behavior can diverge. A subtle parsing change in ASN.1 DER certificate decoding or Unicode normalization across compiler versions on even **one entry out of 100 million** causes the computed `mpt_root` to diverge permanently, triggering false split-view alarms and breaking consensus.
2. **Host Process Fragility**: Untrusted or malformed entries in public logs could cause out-of-bounds memory accesses, nil pointer panics, or unbounded recursion. Running native code directly in the host engine risks corrupting host memory.
3. **Foreign Function Interface (FFI) Overhead**: Naively executing foreign functions across language boundaries on a per-entry basis introduces excessive context-switching and memory-copying overhead, consuming ~23% of total host CPU time purely in FFI crossings.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Provide a high-level, idiomatic public Go developer contract (`func(entry []byte, emit func(key []byte))`) allowing ecosystem authors to write pure functions without managing raw WebAssembly linear memory pointers.
  - Provide a zero-allocation public guest runtime SDK (`vindex/mapfn/sdk`) that binds the developer's function to the high-performance `map_bundle` ABI.
  - Freeze compiler and standard library bytecode inside a hermetic `.wasm` binary, guaranteeing bit-for-bit identical execution across all host architectures, operating systems, and toolchain versions.
  - Amortize boundary-crossing overhead by processing full 256-entry bundles in a single FFI call using contiguous shared-memory slabs.
  - Provide an offline CLI (`vindex-wasm`) to inspect ABI exports and `map-fn` commitment digests, test canonical key extraction, and benchmark throughput prior to deployment.
- **Non-Goals**:
  - **No Ingestion Concurrency or Storage Hashing in `mapfn/sdk`**: `vindex/mapfn/sdk` contains strictly in-guest ABI harnesses, while `vindex/internal/wasmhost` provides the internal zero-I/O Wazero module runner; multi-worker pool orchestration and internal Pebble `KeyHash = SHA-256(key)` SIMD hashing live in the Ingest subsystem (`internal/ingest`).
  - **No In-Place Dynamic Upgrades**: Once a compiled plugin binary is published for an Output Log, its `map-fn` commitment digest is immutable across all Output Log entries. Fixing a parsing bug requires deploying a new index instance from its configured `from` start index (`0` or a suffix start index).
  - **No In-Guest Cryptographic Hashing**: Guest modules do not compute Pebble storage `KeyHash = SHA-256(key)` digests; they emit un-hashed canonical keys (`1..1024` bytes in `0x21..0x7E`) stored directly in the MPT and delegate internal Pebble storage key hashing to the Go host.
  - **No Host I/O or State**: Guest modules are strictly pure functions; they have zero access to disk, network, environment variables, or host clocks.

### 1.4 Requirements, Constraints & Known Pain Points
- **Host Runtime**: Pure Go WebAssembly runtime via `github.com/tetratelabs/wazero` (`GOOS=wasip1 GOARCH=wasm` guest binaries instantiated in `internal/wasmhost` with stubbed, zero-I/O WASI imports and zero CGO dependencies).
- **WASM Memory Constraints**: Guest modules execute within a bounded linear memory space (tens of megabytes by default, scalable via configuration), with pre-allocated multi-megabyte static input and output slabs.
- **Known Pain Points ("Warts and All")**:
  - **Standard Go WASM Binary Size**: Standard Go (`GOOS=wasip1 GOARCH=wasm`) bundles the complete Go runtime and garbage collector into the binary, resulting in ~1.9 MB to ~2.5 MB binaries. While TinyGo produces ~200 KB binaries, it lacks support for certain standard library packages (such as full `crypto/x509`).
  - **Immutable Logic Cost**: Because `map-fn` bytecode is frozen across an Output Log to prevent split-view attacks, any bug in key extraction cannot be hot-patched in place; it requires bringing up a new index instance (and Output Log) from the desired `from` start index.
  - **Memory Slab Ceiling**: An entry bundle containing abnormally large entries (e.g. 50 KB certificates with hundreds of SANs) can exceed the initial guest memory allocation, requiring the host to configure larger linear memory bounds.

---

## 2. Detailed Design

### 2.1 The High-Level Developer Experience
Ecosystem developers write standard, idiomatic Go against `vindex/mapfn/sdk`. They do not write assembly, manage WebAssembly linear pointers, or handle memory layout serialization.

The developer implements a pure mapping function using a streaming `emit` callback and registers it in `init()` (Go guest plugins compile as WASI reactors with `GOOS=wasip1 GOARCH=wasm -buildmode=c-shared`, isolating `//go:wasmexport` bindings in `mapfn/sdk` behind `//go:build wasm` so native `go test` runs cleanly on host OSes; `internal/wasmhost` instantiates modules with `wazero.NewModuleConfig().WithStartFunctions()` and invokes `_initialize` if exported so both WASI reactors and `wasm32-unknown-unknown` guests initialize deterministically without invoking `_start` / `main()`):

```go
type EmitMapFunc func(entry []byte, emit func(key []byte))

func RegisterEmit(fn EmitMapFunc)
```

Every emitted `key` MUST be a valid canonical key (`1..1024` printable ASCII bytes in `0x21..0x7E`, containing no `NUL` or whitespace bytes; see [`../docs/tlog-vindex.md`](../docs/tlog-vindex.md#canonical-keys) and [`../docs/APPLICATIONS.md`](../docs/APPLICATIONS.md) for ecosystem-specific canonicalization rules). Guest mappers MUST skip malformed or unindexable fields before calling `emit`: emitting an invalid canonical key (`len == 0`, `len > 1024`, or any byte outside `0x21..0x7E`) causes the host (`internal/wasmhost`) to return a fatal validation error that immediately **`HALT`s** the Index Operator (`vindexd`) or Auditor (`vindex-auditor`).

The `sdk.RegisterEmit` harness automatically binds the user's pure function to the low-level `map_bundle` FFI export. Each call to `emit(key)` writes the length-prefixed canonical key directly into the pre-allocated output memory slab in-place. This eliminates intermediate slice allocations (`[]string` or `[][]byte`), dynamic array resizing, and garbage collector overhead inside the WebAssembly guest.

#### WASM Guest ABI Contract:
To exchange data across the FFI boundary while eliminating per-entry allocation overhead:
- **Memory Lifecycle**: The guest exports `input_buffer() uint32` returning the base pointer of a pre-allocated multi-megabyte input slab in linear memory. The host serializes the 256-entry bundle directly into this buffer, invokes `map_bundle`, and reads and validates the resulting canonical keys from the returned output slab pointer.
- **Statelessness Invariant**: Guest code must maintain zero mutable state across invocations. All mapping logic must be deterministic and pure; execution depends strictly on the bytes of each individual Input Log entry.

---

### 2.2 Language-Agnostic Low-Level WASM ABI & The Pack-and-Wipe Memory Slab
To eliminate the 23% CPU overhead of per-entry FFI boundary crossings—and allow guest plugins to be authored in any WASM-capable systems language (Go via `mapfn/sdk`, Rust, C/C++, Zig, or TinyGo)—the host (`internal/wasmhost`) and guest communicate through contiguous pre-allocated linear memory slabs using the `input_buffer` and `map_bundle` exports:

```text
//go:wasmexport input_buffer
func input_buffer() uint32

//go:wasmexport map_bundle
func map_bundle(inputPtr uint32, inputLen uint32) uint64
```

#### Memory Slab Lifecycle:
1. **Pack (Host)**: The Go host (`internal/wasmhost`) queries `input_buffer()` once on instance initialization and serializes all entries of a 256-entry bundle into the contiguous input slab in the guest's linear memory.
2. **Execute (FFI Call)**: The host invokes `map_bundle(inputPtr, inputLen)`.
3. **Stream (Guest SDK)**: Inside WASM, the SDK harness reads the `[Count+1]uint32` offset table (`entry := payload[offsets[i]:offsets[i+1]]`), iterates over all entries in a tight in-guest loop, and invokes `userMapFn(entry, emit)`. Each call to `emit` copies the length-prefixed canonical key directly into the pre-allocated output slab at the current write cursor, avoiding intermediate collection allocations.
4. **Return, Validate & Unpack (Host)**: The guest returns a packed 64-bit integer `uint64(outputPtr)<<32 | uint64(outputLen)`. The host (`internal/wasmhost`) reads all extracted canonical keys directly from guest linear memory and validates every key (`1 <= len(key) <= 1024`, all bytes in `0x21..0x7E`); any invalid key returns a fatal validation error that immediately **`HALT`s** the indexer or auditor.
5. **Wipe (Guest/Host)**: Output slab write cursors are reset (`offset = 0`) at the start of the next `map_bundle` call, completely eliminating guest heap allocations and GC pauses.

#### Binary Slab Layouts (All `uint32` fields encoded in Little-Endian):

| Memory Buffer | Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Input Slab** | `0` | `EntryCount` | `uint32` (4B, LE) | Number of entries in the 256-entry bundle (`Count`, 1 to 256). |
| | `4` | `OffsetTable` | `[Count+1]uint32` (LE) | `Count + 1` byte offsets relative to `PayloadBlock`: `OffsetTable[0] = 0`, followed by the end offset of each entry (`entry[i] = PayloadBlock[OffsetTable[i]:OffsetTable[i+1]]`). |
| | `8 + 4*Count` | `PayloadBlock` | `[]byte` | Raw, contiguous Input Log entry bytes concatenated end-to-end. |
| **Output Slab** | `0` | `EntryCount` | `uint32` (4B, LE) | Number of entries processed (`Count`). |
| | `4` | `KeyCountTable` | `[Count]uint32` (LE) | Number of canonical keys emitted by each respective entry. |
| | `4 + 4*Count` | `KeyBlock` | `[]byte` | Concatenated length-prefixed canonical keys (`uint32 length` (LE) + raw canonical key bytes). |

---

### 2.3 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Pinned Artifact Determinism & `map-fn` Commitment**:
  - *Rule*: Within `vindex`, the `MapFn` `.wasm` module is compiled once (e.g. reproducibly via `go build -trimpath -buildvcs=false -buildmode=c-shared` or an equivalent Rust/Zig/C toolchain) and executed identically by `vindexd` and WASM-based `vindex-auditor` instances. `vindex` currently computes the 32-byte `map-fn` state commitment as `SHA-256(wasm_bytes)` pending resolution of [`docs/tlog-vindex.md`](../docs/tlog-vindex.md#output-log-entries)'s pre-1.0 `TODO` on committing a canonical provenance/build manifest (`{source repo @ commit, build toolchain/args, wasm_sha256}`). At the `tlog-vindex` protocol layer, independent auditors may either verify and execute the pinned `.wasm` artifact or audit via a native clean-room implementation matching the committed mapping specification.
  - *Rationale*: Running pinned `.wasm` bytecode across `vindex` nodes eliminates subtle compiler, standard library, or operating system drift (e.g. updates to ASN.1 parsers or Unicode tables), while keeping `tlog-vindex` open to multi-language guests and native non-WASM auditors.
  - *Consequence ("Or Else")*: If Index Operators and WASM-based Auditors ran unpinned native builds compiled with drifting toolchains, edge-case parsing discrepancies on a single entry would produce conflicting `mpt_root` commitments and false split-view alarms.

- **[Correctness Invariant] Hermetic Isolation, Canonical Key Validation & Fatal HALT Policy**:
  - *Rule*: Guest WASM execution runs inside a hermetically sealed WASI-free sandbox (`internal/wasmhost`) with zero host filesystem access, zero network sockets, and deterministic frozen clocks. If the guest encounters an unhandled panic, memory fault, execution trap, or emits an invalid canonical key (`len == 0`, `len > 1024`, or any byte outside `0x21..0x7E`), `internal/wasmhost` returns a fatal validation error that immediately **`HALT`s** the indexer or auditor.
  - *Rationale*: Ensures that execution is 100% deterministic, spec-compliant, and reproducible across all Index Operators and Auditors.
  - *Consequence ("Or Else")*: Silently swallowing guest traps or dropping malformed canonical keys produces divergent key mappings, resulting in false non-inclusion proofs or `mpt-root` audit mismatches.

- **[Performance Optimization] Bundled FFI Invocation (`map_bundle`)**:
  - *Mechanism*: Packs an entire 256-entry bundle into the input slab and executes a single FFI call per bundle, rather than crossing the boundary once per entry.
  - *Impact*: Reduces FFI transitions from 768 to 2–3 per 256-entry bundle, slashing FFI CPU overhead from ~23% of host CPU time to < 1%.

- **[Performance Optimization] Pack-and-Wipe Slab Allocation**:
  - *Mechanism*: Slabs are allocated once in guest linear memory and reused across sequential bundle invocations with simple pointer resets.
  - *Impact*: Eliminates in-guest heap allocations and garbage collector pauses, keeping memory usage bounded and CPU dedicated to parsing.

- **[Performance Optimization] Raw Canonical Key Emission & Host SIMD Storage Hashing**:
  - *Mechanism*: Guest sandboxes emit un-hashed canonical keys (`1..1024` bytes in `0x21..0x7E`), which the Go host preserves directly for MPT indexing and hashes via `KeyHash = SHA-256(key)` strictly as an internal Pebble storage digest using native hardware vector instructions (Single Instruction, Multiple Data / SIMD, such as x86 SHA-NI or ARMv8 Crypto extensions).
  - *Impact*: Preserves variable-length canonical keys for MPT prefix lookups while eliminating the ~55% software crypto bottleneck inside WebAssembly bytecode.

---

### 2.4 Offline Developer Verification Tooling (`vindex-wasm`)
The mapping subsystem provides a standalone CLI tool (`vindex/cmd/vindex-wasm`) so plugin authors can inspect, test, and benchmark their `.wasm` binaries before production deployment:

- **`vindex-wasm inspect`**: Instantiates the module via `internal/wasmhost`, validates the required `input_buffer` and `map_bundle` ABI exports and linear memory bounds, and prints the 32-byte `map-fn` SHA-256 commitment digest in both canonical base64 (for `c2sp.org/tlog-vindex-state@v1` and policy pinning) and hex.
- **`vindex-wasm test`**: Executes the module against literal entry strings or binary entry files, validates every emitted canonical key against `1..1024` printable ASCII bounds (`0x21..0x7E`), and prints extracted canonical keys in plain text or JSON.
- **`vindex-wasm bench`**: Measures single-worker and multi-bundle mapping throughput (`entries/sec`) and per-bundle latency over repeated 256-entry bundles.

```bash
# Validate ABI exports, linear memory bounds, and print map-fn SHA-256 digest (base64 & hex)
vindex-wasm inspect --wasm=map.wasm

# Test canonical key extraction against a literal entry string or binary entry file
vindex-wasm test --wasm=map.wasm --input="golang.org/x/crypto v0.1.0 h1:..."
vindex-wasm test --wasm=map.wasm --input_file=entry.bin --format=json

# Run performance and throughput benchmarks (entries/sec)
vindex-wasm bench --wasm=map.wasm --input="golang.org/x/crypto v0.1.0 h1:..." --iterations=1000
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 Per-Entry Mapping (`map_leaf`) vs. Bundled Mapping (`map_bundle`)
- **Proposed**: Invoking an exported `map_leaf(ptr, len)` guest function individually for every Input Log entry.
- **Empirical Rejection**: Generated 768 FFI calls per 256-entry bundle (memory allocation, entry mapping, and arena reset transitions x 256). Profiling revealed that ~23% of total host CPU time was spent purely on boundary-crossing overhead.
- **Chosen Design**: Bundled mapping (`map_bundle`) processes all 256 entries in a single invocation via shared memory slabs, reducing FFI overhead to < 1%.

### 3.2 In-Guest Software Cryptography vs. Host SIMD Storage Hashing
- **Proposed**: Compiling SHA-256 hashing libraries directly into the guest WASM bytecode so that the guest outputs 32-byte key hashes directly.
- **Empirical Rejection**: Because WebAssembly runtimes lack direct access to native CPU hardware crypto instructions, software bitwise hashing consumed ~55% of all CPU cycles during mapping, and emitting pre-hashed digests destroys variable-length canonical keys needed for MPT prefix lookups.
- **Chosen Design**: Guest modules emit un-hashed canonical keys (`0x21..0x7E`) stored directly in the MPT; the Go host computes hardware-accelerated `KeyHash = SHA-256(key)` digests strictly as an internal Pebble chunk storage digest using CPU SIMD vector instructions.

### 3.3 Exporting Host Hardware Hashing into WASM vs. Pure Canonical Key Return
- **Proposed**: Exposing an imported host function (`host.sha256(ptr, len)`) into the WebAssembly sandbox so guest modules could invoke host hardware crypto while still returning pre-computed hashes.
- **Theoretical Rejection (Ergonomics, Prefix Loss & Architectural Purity)**:
  - Ruled out without benchmarking due to excessive SDK complexity, loss of un-hashed canonical keys for the MPT, and loss of pure-function abstraction.
  - Requiring a host import forces guest SDK authors across different languages (Go, Rust, TinyGo, Zig) to bind against proprietary host runtime hooks rather than writing a clean, portable function (`entry []byte -> canonical keys`).
  - Incurring bidirectional FFI hops for every individual hash would introduce its own boundary overhead.
- **Chosen Design**: Keep the guest contract completely pure and self-contained: the guest emits raw canonical keys, and the Go host preserves them for the MPT while performing bulk SIMD hashing natively for internal Pebble storage.

### 3.4 In-Process Go Plugins / CGO vs. WebAssembly Sandboxing
- **Proposed**: Dynamically loading Go plugins (`plugin.Open`) or shared C libraries (`cgo`).
- **Theoretical Rejection**:
  - In-process native plugins do not guarantee determinism across toolchain versions (Go compiler upgrades can alter standard library parsing behavior).
  - Memory corruptions or panics inside the plugin crash the main daemon.
  - Go plugins have poor cross-platform support and require identical dependency version trees between the host and plugin.
- **Chosen Design**: Standardized on Wazero WebAssembly sandboxing (`internal/wasmhost`).

### 3.5 Slice-Returning MapFn (`func(entry) []string`) vs. Streaming Callback (`func(entry, emit)`)
- **Proposed & Historical Design**: An earlier design specified a 1:1 slice-returning contract (`type MapFn func(entry []byte) []string` or `[][]byte`), where user logic parsed an entry and returned an allocated collection of canonical keys to the SDK harness.
- **Why It Was Changed**:
  - *In-Guest Allocation Churn*: Returning dynamic slices forced the guest runtime to allocate slice headers and backing arrays for every single entry. On high-fanout workloads like Certificate Transparency (up to 50 SANs per certificate), dynamic `append` growth triggered repeated slice reallocations and GC sweeps inside the WASM sandbox.
  - *Cross-Language WASM Portability*: Systems languages that compile to WebAssembly (C, C++, Rust, Zig) lack native Go-style dynamic slices. Returning a variable-length list requires importing or linking a dynamic heap allocator (`malloc`/`dlmalloc`) and managing complex array descriptors.
  - *Direct Arena Streaming*: In contrast, a streaming callback (`func(entry []byte, emit func(key []byte))`) allows user parsing code to write canonical keys directly into the SDK's pre-allocated linear memory output buffer at the current cursor.
  - *Measurable Throughput Gain*: Eliminating intermediate slice allocations and GC overhead inside the guest delivers a 15% to 25% throughput improvement in guest mapping execution (and up to 35% on high-fanout certificate parsing).
- **Chosen Design**: Streaming callback (`EmitMapFunc` / `RegisterEmit`) as the canonical zero-allocation contract.

---

## Appendix: Guest Parsing Optimization Case Study (Certificate Transparency)

### A.1 The In-Guest Parsing Bottleneck
While WebAssembly provides sandboxed memory safety and cross-platform determinism, guest execution overhead is non-uniform across Go packages. Compiling standard library decoders (`crypto/x509`, `encoding/asn1`, `encoding/json`, `regexp`) into `wasip1/wasm` introduces severe performance degradation:

1. **Reflection & Heap Churn**: Standard decoders build dynamic Abstract Syntax Trees (ASTs) on the Go heap, triggering garbage collection cycles inside bounded guest linear memory.
2. **Extraneous Cryptographic Decoding**: Standard `crypto/x509` decodes public key structures, executes `big.Int` modular arithmetic, and validates elliptic curve points—operations irrelevant to canonical key extraction.
3. **Concurrency Saturation**: Under naive parsing, guest execution drops to ~1,200 entries/sec per core. Even scaling across 16 to 24 parallel Wazero workers caps aggregate throughput at ~14,000 entries/sec. Because the downstream storage engine and trie can commit >200,000 entries/sec, the pipeline becomes completely CPU-starved on guest mapping.

- **[Performance Optimization] Zero-Allocation In-Guest Parsing**:
  - *Mechanism*: Ecosystem plugins should avoid reflection-heavy standard library decoders in favor of targeted, in-place byte scanners over raw entry payloads.
  - *Impact*: Eliminates in-guest AST heap allocations and extraneous cryptographic validation, preventing guest WASM execution from starving the downstream storage and trie pipeline.

### A.2 Structural Architecture: Naive vs. Targeted Parsing
- **Naive Architecture (Standard Library Decoders)**:
  Deserializes the full certificate structure via `crypto/x509` and `encoding/asn1`. Incurs full ASN.1 reflection overhead, parses public keys, and validates signatures.
- **Optimized Architecture (Targeted In-Place Scanner)**:
  Bypasses `crypto/x509` and reflection entirely. A zero-allocation cursor scans the raw ASN.1 TLV stream in-place, extracting only the Subject Common Name (OID `2.5.4.3`) and SAN `dNSName` entries (OID `2.5.29.17`):
  - *Extension Filtering*: Unrecognized extension OIDs are skipped without decoding or allocating values.
  - *CT Poison & SCTs*: Ignored; search indexing requires canonical domain keys rather than certificate chain validation.
  - *Framing Differences*: Precertificate entries (`precert_entry`) and standard certificates (`x509_entry`) differ only by initial byte offset (skipping the outer certificate sequence or the 32-byte issuer hash) before entering the identical scanning loop.

### A.3 Empirical Telemetry (Sycamore 2026h2 Dataset, 10,240 Real Certificates)

| Metric | Naive (`crypto/x509`) | Targeted In-Place Scanner | Delta / Speedup |
| :--- | :--- | :--- | :--- |
| **WASM Single-Thread** | 1,269 entries/sec (788 μs/entry) | **9,391 entries/sec** (106.5 μs/entry) | **7.4x** |
| **WASM 16 Workers** | 14,684 entries/sec (1,065 μs/entry) | **109,828 entries/sec** (142 μs/entry) | **7.5x** |
| **256-Entry Bundle Latency (P50)** | 272.6 ms | **36.3 ms** | **7.5x lower** |
| **256-Entry Bundle Latency (P99)** | 379.8 ms | **56.6 ms** | **6.7x lower** |
| **Projected Wall Time (1B Entries)** | 18.9 hours | **2.53 hours** | **-16.37 hours (-86.6%)** |

Across all 10,240 real Static-CT certificates in the evaluation dataset, the targeted scanner produced output 100% bitwise identical to `crypto/x509` (0 mismatches).

---

## 4. Verification Gate

All public guest SDK (`mapfn/sdk`), internal sandbox host (`internal/wasmhost`), example mapper (`ct`, `mtc`, `sumdb`), and `vindex-wasm` CLI tests are verified via:

```bash
go test -race ./vindex/mapfn/... ./vindex/internal/wasmhost/... ./vindex/cmd/vindex-wasm/...
```
