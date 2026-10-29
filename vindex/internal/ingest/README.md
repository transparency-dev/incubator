# Ingestion Pipeline & Local Tile Cache

This document defines the architecture, data structures, concurrency model, load-bearing invariants, and verified performance optimizations for the **Ingestion Subsystem** (`vindex/internal/ingest`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Real-World Friction
The ingestion engine sits at the front of the VIndex pipeline. It must continuously poll remote append-only transparency logs over HTTP, verify checkpoint policies and Merkle consistency, download 256-entry bundles, execute untrusted mapping logic inside WebAssembly sandboxes (`internal/wasmhost`), and feed sorted batches to downstream storage.

If ingestion is naive, four severe operational failure modes emerge:
1. **Host-Sandbox Boundary Overhead**: Invoking WebAssembly guest functions per entry incurs severe boundary-crossing penalties. Every transition across the Foreign Function Interface (FFI)—switching execution contexts and copying memory between the Go host process and the WebAssembly sandbox—costs CPU cycles. When executed entry-by-entry, FFI boundary overhead alone consumes ~23% of total host CPU time.
2. **Out-of-Order Corruption**: Executing mapping across parallel worker threads causes batches to finish at different times. If out-of-order batches reach the storage engine, the database commits non-contiguous entry index sequences, permanently corrupting the RFC 6962 compact range hashes of affected keys' value logs.
3. **Upstream Rate Limiting vs. Catch-Up Bandwidth**: Ingesting high-velocity logs from genesis (tens of millions of entries) requires saturating network bandwidth, but upstream CDNs and log endpoints enforce strict rate limits (HTTP 429 Too Many Requests). Ingestion must maximize parallel download concurrency while gracefully backing off to avoid upstream bans.
4. **Network-Free Restart Guarantee (Cache Durability)**: Network egress is expensive and external logs can be transiently unreachable. Ingestion stages consumed tiles locally in a bounded staging buffer until downstream storage and trie persistence confirm they are no longer needed, ensuring daemon restarts and crash recoveries complete with zero network roundtrips.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Ingest upstream Input Logs in native 256-entry bundles matching the underlying tile structure.
  - Maximize upstream download throughput with adaptive concurrency while respecting HTTP 429 rate limits.
  - Parallelize CPU-heavy parsing across worker pools while emitting strictly contiguous Input Log entry sequences.
  - Maintain a bounded local staging buffer and crash-recovery cache, enabling restarts and Zero-WAL recovery with zero network egress (not an immutable log of record).
  - Bound local disk growth by having the background tile reaper actively prune cached tiles older than `SafeWatermark`.
- **Non-Goals**:
  - **No Upstream Checkpoint Creation**: The ingestion engine does not publish checkpoints or modify upstream log state; it is strictly a read-only consumer.
  - **No In-Guest Storage Writes**: The WASM sandbox is forbidden from performing disk or network I/O; guest modules solely transform entry bytes into canonical keys.
  - **No Cross-Subsystem Watermark Calculation**: The ingestion cache does not inspect the internal state of Pebble DB or the MPT; watermark authority resides strictly with the Coordinator.

### 1.3 Requirements, Dependencies & Constraints
- **Upstream Log Contract**: Supports standard tile-based logs ([C2SP tlog-tiles](https://c2sp.org/tlog-tiles) `/tile/entries/...` and [C2SP static-ct-api](https://c2sp.org/static-ct-api) `/tile/data/...`) as well as custom leaf-by-leaf log adapters that group entries into 256-entry bundles, with checkpoints verified against configured checkpoint verification policies (such as C2SP [tlog-policy](https://c2sp.org/tlog-policy)).
- **WASM Host Runtime**: Pure Go WebAssembly sandbox execution via `internal/wasmhost` backed by `github.com/tetratelabs/wazero` (zero CGO dependencies).
- **Resequencer Straggler Buffering**: If a single WASM worker stalls on an anomalous entry bundle, subsequent workers buffer finished batches in the in-memory min-heap until the straggler bundle completes.

---

## 2. Detailed Design

### 2.1 The Assembly Line Sorter Architecture
Checkpoint polling and `Target_CP` persistence are driven by the Coordinator using the upstream log fetcher; once a verified `Target_CP` is established, the Coordinator streams `[max(persisted_watermark, from), Target_CP.Size)` through the three-stage ingestion pipeline:

1. **Tile Fetcher**: Queries the upstream Input Log's `/checkpoint` endpoint and verifies checkpoints against `<input-log-origin>` and the configured Input Log checkpoint policy. Downloads 256-entry bundles (`/tile/entries/<N>[.p/<W>]` for `tlog-tiles`, `/tile/data/<N>[.p/<W>]` for `static-ct-api` using partial tile width `.p/<W>` on unsealed tail tiles, or synthesized 256-entry bundles via a leaf-by-leaf adapter) and authenticates each bundle against its Level-0 tree tile and upper-level tree tiles up to `Target_CP.Root` across `[max(persisted_watermark, from), Target_CP.Size)`.
2. **Local Tile Cache**: Writes downloaded, Merkle-authenticated 256-entry bundles to the local filesystem via atomic temp-file rename. When `Target_CP.Size` advances within an unsealed 256-entry tail tile across consecutive sync cycles, any cached partial bundle narrower than required (`bundleEnd < Target_CP.Size` and `len < 256`) is treated as a cache miss, re-fetched at the wider width, and atomically overwritten on disk.
3. **WASM Worker Pool**: A configurable pool of parallel Wazero sandboxes (`internal/wasmhost`, scaling across available host CPU capacity) running the compiled `.wasm` plugin. Each worker slices boundary bundles to `[max(bundleStart, start), min(bundleEnd, Target_CP.Size))`—excluding entries `< from`, entries already persisted in a partially indexed tail bundle, and entries `>= Target_CP.Size`—and maps the slice in a single `map_bundle` invocation via the in-guest SDK (`mapfn/sdk`).
4. **Canonical Key Validation & Per-Entry Deduplication**: Upon unpacking the WASM output slab, the host validates every emitted key against the canonical key bounds in [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) (`1..1024` printable ASCII bytes in `0x21..0x7E`, containing no `NUL` or whitespace bytes) and sorts and deduplicates canonical keys per entry (`entryIdx`). If the WASM module traps, overflows its linear memory slabs, or emits any key violating canonical key bounds (`1..1024` bytes in `0x21..0x7E`), the host returns a fatal validation error that immediately **`HALT`s** ingestion—never silently dropping invalid keys—preserving bit-for-bit `mpt_root` equivalence with [`internal/auditor`](../auditor/README.md) and [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md). Valid deduplicated un-hashed canonical keys are passed downstream to storage and the MPT.
5. **Resequencer (Min-Heap)**: Receives completed batches out of order from workers and buffers them in a priority queue. Emits strictly ascending entry batches across `[max(persisted_watermark, from), input_size)` to the downstream storage channel.
6. **Tile Reaper**: Periodically receives the authorized `SafeWatermark` from the Coordinator (`max(min(KV_CP.Size, MPT_Durable_Size), from)`) and actively prunes cached tiles fully covered by that watermark (`(tileIndex + 1) * 256 <= SafeWatermark`) to bound local disk usage.

### 2.2 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Target Checkpoint Policy & Consistency Verification**:
  - *Rule*: Upstream Input Log checkpoints must be cryptographically validated against `<input-log-origin>` and the configured Input Log checkpoint policy (enforcing primary log signature and witness cosignature quorum), must satisfy `Target_CP.Size >= max(prev_Target_CP.Size, from)`, and (after the first verified checkpoint) must verify Merkle consistency against `prev_Target_CP` before the size advancement is accepted.
  - *Rationale*: Guarantees that the indexer only ingests authentic, append-only entries committed by the legitimate log authority and witnesses at or above `from`.
  - *Consequence ("Or Else")*: If an unauthenticated, regressed, or split-view checkpoint were accepted, an adversary could feed forged or rolled-back entries, causing the indexer to commit bogus state and permanently diverge from independent auditors.

- **[Correctness Invariant] Fatal `HALT` on WASM Trap or Invalid Canonical Key**:
  - *Rule*: Every key emitted by the WASM guest must satisfy canonical key bounds (`1..1024` bytes in `0x21..0x7E`). If the WASM module traps or emits an invalid canonical key, the host must return a fatal validation error that immediately **`HALT`s** ingestion rather than dropping or sanitizing the offending key.
  - *Rationale*: Preserves bit-for-bit root equivalence with [`internal/auditor`](../auditor/README.md) and the auditing rules in [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md).
  - *Consequence ("Or Else")*: Silently dropping invalid keys would allow a defective mapping module to publish Output Log state commitments that spec-compliant auditors reject.

- **[Correctness Invariant] Strictly Monotonic Resequencing**:
  - *Rule*: Batches pushed to downstream storage must strictly follow ascending Input Log entry index (`entryIdx`) order without gaps, where each emitted batch's starting entry index equals the preceding batch's ending entry index.
  - *Rationale*: Inverted chunks maintain cumulative RFC 6962 compact range hashes over value log leaves, which require strictly increasing Input Log entry indices.
  - *Consequence ("Or Else")*: Committing out-of-order batches breaks the Merkle compact range tree structure, computing invalid `value_root` digests that fail client inclusion proofs.

- **[Correctness Invariant] Tile Reaper Authority & Pruning Bounds**:
  - *Rule*: The background tile reaper must strictly prune only those tile files whose highest entry index is covered by `SafeWatermark` (`(tileIndex + 1) * 256 <= SafeWatermark`), where `SafeWatermark` is authoritative input dictated by the Coordinator.
  - *Rationale*: Preserves un-synced historical 256-entry bundles on disk so that Zero-WAL crash recovery can fast-forward lagging MPT state without network requests.
  - *Consequence ("Or Else")*: Pruning ahead of the durable MPT watermark causes dirty crash recovery to fail, forcing the daemon to re-download historical tiles over the network and violating the sub-500ms time-to-first-serve SLO.

- **[Performance Optimization] Native 256-Entry Tile Bundling**:
  - *Mechanism*: Fetches and caches data in native 256-entry bundles rather than issuing individual HTTP requests per entry.
  - *Impact*: Reduces upstream network requests by 256x compared to per-entry REST APIs.

- **[Performance Optimization] Bundled WebAssembly Invocation (`map_bundle`)**:
  - *Mechanism*: Transfers an entire 256-entry bundle across the WASM boundary in a single FFI call.
  - *Impact*: Reduces FFI boundary crossings from 768 to 2–3 per tile, dropping FFI CPU overhead from ~23% of host CPU time to < 1%.

### 2.3 Ingestion Pipeline Contract

The ingestion subsystem manages upstream data retrieval, sandboxed mapping, and local tile caching:

- **Inputs**:
  - Upstream Input Log HTTP endpoint, expected `<input-log-origin>`, and Input Log checkpoint policy.
  - Local tile cache directory.
  - Sandboxed WASM mapping runner (`internal/wasmhost`).
  - Worker concurrency.
- **Outputs**:
  - Stream of mapped `(canonicalKey, entryIdx)` batches ordered monotonically by Input Log entry index.
- **Pruning Contract**:
  - Local tile cache retains 256-entry bundles strictly within the active lag window; tiles covered by `SafeWatermark` are deleted by the background reaper.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Ephemeral In-Memory Fetching vs. Persistent Local Tile Cache
- **Proposed**: Streaming 256-entry bundles directly from HTTP responses into the WASM worker pool in memory without persisting verified bundles on local disk.
- **Theoretical & Operational Rejection**:
  - Tightly couples upstream HTTP jitter to downstream mapping and storage throughput.
  - Any daemon restart or dirty crash where `MPT_Durable_Size` lags behind `KV_CP.Size` or `Output_CP.InputSize` would force the node to re-download historical 256-entry bundles over the network—risking upstream HTTP 429 rate limits, stalling startup completely during upstream outages, and violating the sub-500ms Zero-WAL recovery SLO.
- **Chosen Design**: Persist Merkle-authenticated 256-entry bundles on local disk up to `SafeWatermark` (`max(min(KV_CP.Size, MPT_Durable_Size), from)`), enabling offline Zero-WAL crash replay while bounding disk usage via the background tile reaper.

---

## 4. Verification Gate

All tile fetching, cryptographic tile verification, cache durability, reaper, and WASM pipeline tests are verified via:

```bash
go test -race ./vindex/internal/ingest/...
```
