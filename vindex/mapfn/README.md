# WASM Guest SDK & Plugin Interface

Every transparency ecosystem indexes different log entry formats (such as DER X.509 certificates in Certificate Transparency, module lines in Go SumDB, or JSON provenance records in Sigstore). VIndex isolates entry parsing and canonical key extraction inside a hermetic, zero-I/O WebAssembly sandbox so ecosystem authors can write custom mapping logic without risking host memory safety or causing state divergence across independent auditors compiled with different toolchains or operating systems.

This document covers the public Go guest SDK (`vindex/mapfn/sdk`), the language-agnostic shared-memory bundle ABI (`input_buffer` / `map_bundle`), the internal Wazero sandbox host (`vindex/internal/wasmhost`), and the offline verification CLI (`vindex-wasm`).

### Non-Goals
- **No Worker Pool Orchestration in the Guest SDK**: The guest SDK provides only in-guest ABI bindings, while `internal/wasmhost` compiles the `.wasm` module once and provisions isolated per-worker module instances; multi-worker pipeline concurrency is managed by [`internal/ingest`](../internal/ingest/README.md).
- **No In-Place Mapping Upgrades**: A deployed mapping function is fixed for the lifetime of an Output Log. Changing extraction logic requires deploying a new index instance from its configured `from` start index.
- **No Host I/O or Cross-Call State**: Guest modules are pure, stateless functions with zero access to the filesystem, network, environment variables, or host clocks.

---

## 1. Design

### 1.1 Three-Layer Mapping Architecture

Mapping is decoupled across three layers so plugin authors can write idiomatic Go (or Rust, C/C++, Zig, or TinyGo) while the host enforces strict sandboxing and canonical key validation:

| Layer | Package / Component | Responsibility |
| :--- | :--- | :--- |
| **User Mapping Callback** | Ecosystem plugin (`MapFn`) | Pure function extracting zero or more canonical keys from a single raw Input Log entry. |
| **Guest SDK & Slab ABI** | `vindex/mapfn/sdk` (or non-Go slab target) | Binds user callbacks to the low-level `input_buffer` / `map_bundle` shared-memory ABI in flat little-endian WASM linear memory. |
| **Host Sandbox Runtime** | `vindex/internal/wasmhost` ([`wazero`](https://github.com/tetratelabs/wazero), zero CGO) | Instantiates `.wasm` modules with stubbed zero-I/O WASI imports, executes 256-entry bundles, validates canonical key bounds (`1..1024` bytes in `0x21..0x7E`), and sorts and deduplicates emitted keys per entry. |

Within `vindex`, the `.wasm` module is compiled once (for example with `go build -trimpath -buildvcs=false -buildmode=c-shared`) and pinned out-of-band by its `SHA-256(wasm_bytes)` digest (`vindex-wasm inspect`). At the `tlog-vindex` protocol layer, `c2sp.org/tlog-vindex-state@v1` omits an in-band `map-fn` commitment pre-1.0 (see [`../docs/tlog-vindex.md`](../docs/tlog-vindex.md#design-log)); independent auditors may either execute the pinned `.wasm` artifact or run a clean-room native implementation of the same mapping specification.

### 1.2 Go Guest Developer Contract (`vindex/mapfn/sdk`)

Go plugin authors implement a streaming `emit` callback and register it in `init()`:

```go
type EmitMapFunc func(entry []byte, emit func(key []byte))

func RegisterEmit(fn EmitMapFunc)
```

- **Build & Reactor Initialization**: Go guest plugins compile as WASI reactors (`GOOS=wasip1 GOARCH=wasm -buildmode=c-shared`, ~1.9 to 2.5 MB with the standard Go runtime or ~200 KB with TinyGo). Go 1.24+ ignores `//go:wasmexport` directives on non-WASM targets so native `go test` runs cleanly on host OSes without build tags. On startup, `internal/wasmhost` instantiates the module without running `_start` / `main()` and invokes `_initialize` if exported so both WASI reactors and `wasm32-unknown-unknown` guests initialize deterministically.
- **Canonical Key Validation & Fatal `HALT`**: Every emitted `key` MUST be a valid canonical key (`1..1024` printable ASCII bytes in `0x21..0x7E`, containing no `NUL` or whitespace bytes; see [`../docs/tlog-vindex.md`](../docs/tlog-vindex.md#canonical-keys) and [`../docs/APPLICATIONS.md`](../docs/APPLICATIONS.md)). Guest mappers must skip malformed or unindexable fields before calling `emit`: if the guest traps, overflows its linear memory slabs, or emits an invalid canonical key (`len == 0`, `len > 1024`, or any byte outside `0x21..0x7E`), `internal/wasmhost` returns a fatal validation error that immediately **`HALT`s** the indexer or auditor rather than silently dropping the key.
- **Zero-Allocation Streaming**: Each `emit(key)` call writes the length-prefixed canonical key directly into the pre-allocated output slab in-place, avoiding intermediate `[]string` or `[][]byte` slice allocations inside the guest.

### 1.3 Language-Agnostic Slab ABI (`input_buffer` & `map_bundle`)

Crossing the Go-to-WASM Foreign Function Interface (FFI) once per entry requires 768 transitions per 256-entry bundle and consumes ~23% of total host CPU time. To reduce FFI transitions to 2–3 per bundle (< 1% CPU overhead) and support guests written in any WASM-capable language, the host and guest exchange entire 256-entry bundles through pre-allocated contiguous linear memory slabs:

```text
//go:wasmexport input_buffer
func input_buffer() uint32

//go:wasmexport map_bundle
func map_bundle(inputPtr uint32, inputLen uint32) uint64
```

1. **Pack (Host)**: `internal/wasmhost` queries `input_buffer()` once on instance initialization and serializes the 256-entry bundle into the guest's static input slab. If the framed bundle exceeds the input slab capacity, the host returns a fatal error (`HALT`).
2. **Execute & Stream (Guest)**: The host invokes `map_bundle(inputPtr, inputLen)`. The guest reads the `[Count+1]uint32` offset table (`entry := payload[offsets[i]:offsets[i+1]]`), invokes the mapping callback per entry, and appends length-prefixed keys into the static output slab. If input decoding fails or `emit` overflows the output slab capacity, `map_bundle` aborts and returns `0`.
3. **Validate, Deduplicate & Wipe (Host)**: The guest returns `uint64(outputPtr)<<32 | uint64(outputLen)`. If the return value is `0` or out of bounds, the host returns a fatal error (`HALT`). Otherwise, the host reads all emitted keys from guest memory, validates canonical key bounds (`1..1024` bytes in `0x21..0x7E`), and **sorts and deduplicates canonical keys per entry** before passing the batch downstream. Output slab cursors reset to `0` on the next `map_bundle` call with zero guest heap allocations.

#### Binary Slab Layouts (All `uint32` fields encoded in Little-Endian)

| Memory Buffer | Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Input Slab** | `0` | `EntryCount` | `uint32` (4B, LE) | Number of entries in the bundle (`Count`, 1 to 256). |
| | `4` | `OffsetTable` | `[Count+1]uint32` (LE) | `Count + 1` byte offsets relative to `PayloadBlock`: `OffsetTable[0] = 0`, followed by each entry's end offset (`entry[i] = PayloadBlock[OffsetTable[i]:OffsetTable[i+1]]`). |
| | `8 + 4*Count` | `PayloadBlock` | `[]byte` | Raw, contiguous Input Log entry bytes concatenated end-to-end. |
| **Output Slab** | `0` | `EntryCount` | `uint32` (4B, LE) | Number of entries processed (`Count`). |
| | `4` | `KeyCountTable` | `[Count]uint32` (LE) | Number of canonical keys emitted by each respective entry. |
| | `4 + 4*Count` | `KeyBlock` | `[]byte` | Concatenated length-prefixed canonical keys (`uint32 length` (LE) + raw canonical key bytes). |

### 1.4 Offline Verification CLI (`vindex-wasm`)

`vindex/cmd/vindex-wasm` allows plugin authors to inspect, test, and benchmark `.wasm` modules before deployment:
- **`vindex-wasm inspect`**: Instantiates the module via `internal/wasmhost`, validates `input_buffer` / `map_bundle` exports and memory bounds, and prints the 32-byte `.wasm` SHA-256 digest in base64 and hex for operator and auditor pinning.
- **`vindex-wasm test`**: Runs the module against literal entry strings or binary entry files, validates canonical key bounds (`1..1024` bytes in `0x21..0x7E`), and prints extracted keys in plain text or JSON.
- **`vindex-wasm bench`**: Benchmarks single-worker and multi-bundle mapping throughput (`entries/sec`) and per-bundle latency over repeated 256-entry bundles.

```bash
vindex-wasm inspect --wasm=map.wasm
vindex-wasm test --wasm=map.wasm --input="golang.org/x/crypto v0.1.0 h1:..."
vindex-wasm test --wasm=map.wasm --input_file=entry.bin --format=json
vindex-wasm bench --wasm=map.wasm --input="golang.org/x/crypto v0.1.0 h1:..." --iterations=1000
```

---

## 2. Alternatives Considered

### 2.1 Per-Entry Mapping (`map_leaf`) vs. Bundled Mapping (`map_bundle`)
- **Proposed**: Invoking an exported `map_leaf(ptr, len)` guest function individually for every Input Log entry.
- **Rejection**: Generated 768 FFI calls per 256-entry bundle (allocation, mapping, and reset x 256), spending ~23% of total host CPU time on boundary-crossing overhead.
- **Chosen Design**: Bundled mapping (`map_bundle`) processes up to 256 entries per FFI call via shared memory slabs, reducing FFI overhead to < 1%.

### 2.2 In-Process Go Plugins / CGO vs. WebAssembly Sandboxing
- **Proposed**: Dynamically loading native Go plugins (`plugin.Open`) or shared C libraries (`cgo`).
- **Rejection**: Native plugins do not guarantee bit-for-bit determinism across Go compiler/stdlib upgrades or host OSes, crash the entire daemon on a plugin panic or memory fault, and require identical host/plugin dependency trees.
- **Chosen Design**: Zero-CGO Wazero WebAssembly sandboxing (`internal/wasmhost`).

---

## Appendix: Guest Parsing Optimization Notes (Certificate Transparency)

Compiling reflection-heavy standard library decoders (`crypto/x509`, `encoding/asn1`, `encoding/json`, `regexp`) into `wasip1/wasm` incurs high heap allocation churn and unnecessary cryptographic validation (such as public-key and signature decoding) irrelevant to canonical key extraction. Ecosystem plugins should prefer targeted, in-place byte scanners (for example, scanning raw ASN.1 TLV streams for Subject Common Name OID `2.5.4.3` and SAN `dNSName` OID `2.5.29.17` before applying canonical DNS label normalization per [`../docs/APPLICATIONS.md`](../docs/APPLICATIONS.md)), which achieves a ~7.5x throughput improvement over `crypto/x509` in `wasip1/wasm`.

---

## 3. Verification Gate

```bash
go test -race ./vindex/mapfn/... ./vindex/internal/wasmhost/... ./vindex/cmd/vindex-wasm/...
```
