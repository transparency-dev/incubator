# Verifiable Index (VIndex v1) Architecture

This document defines the core architecture, load-bearing invariants, verified performance optimizations, operational considerations, and retired design branches for **VIndex v1**.

---

## 0. High Level Overview

### 0.0 Architectural Context
VIndex operates as a **Map Sandwich** bounded between an **Input Log** (the immutable source of truth) and a **Witnessed Output Log** (the cryptographic state anchor). For the foundational problem statement, non-negotiable system scope (single-machine deployment, canonical key & bounded prefix lookups, append-only, hermetic WASM), and formal wire specification, see the top-level [VIndex README](../README.md) and [C2SP tlog-vindex Specification](./tlog-vindex.md).

This document specifies the technical system architecture: the 5-stage pipeline, checkpoint promotion and ratcheting invariants, crash consistency guarantees, operational sizing, and retired design branches.

### 0.1 Primary Pipeline Flow & Subsystem Map
Data progresses sequentially through 5 modular stages, coordinated by the coordinator:

| # | Pipeline Stage | Subsystem Directory | Physical Responsibility & Transition |
| :- | :--- | :--- | :--- |
| **1** | **Ingest & Tile Cache** | [`internal/ingest/`](../internal/ingest/README.md) | Polls upstream Input Log checkpoints, downloads and authenticates 256-entry bundles and hash tiles into local disk cache, and reaps tiles below the safe pruning watermark. |
| **2** | **Sandboxed Mapping** | [`mapfn/`](../mapfn/README.md), `internal/wasmhost`, & [`internal/ingest/`](../internal/ingest/README.md) | WASI-free Wazero sandbox pool (`internal/wasmhost`) executes guest WASM plugins built with the public Guest SDK (`mapfn/sdk`), validates canonical keys (`1..1024` bytes in `0x21..0x7E`, halting fatally on violation) via `map_bundle`, and computes host SIMD `KeyHash = SHA-256(key)` digests strictly for Pebble storage. |
| **3** | **Inverted Storage** | [`internal/kvstore/`](../internal/kvstore/README.md) | Computes `value_root` digests across key partitions in memory, batches updates into Pebble LSM inverted chunks (`'c'`), and executes a blocking disk sync at the target checkpoint barrier. |
| **4** | **State Commitment** | `internal/mpt` & [`internal/tree/`](../internal/tree/README.md) | Predicts candidate `mpt_root` over un-hashed variable-length canonical keys in the MPT (`internal/mpt`) under a shared read lock, appends the index state commitment entry to the Tessera Output Log (`internal/tree`), collects witness cosignatures, and ratchets the in-memory trie pointer. |
| **5** | **Read Serving** | [`internal/server/`](../internal/server/README.md) & `internal/wire` | Serves spec-defined HTTP lookups (`GET <index-url>/keys?key=<key>` or `GET <index-url>/keys?prefix=<key-prefix>` and lock-free `GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]`), RFC 6962 compact range hashes, and inductive backward pagination (`before=<before>`), strictly isolated to witnessed checkpoints. |
| *(Orch)* | **Coordinator** | [`internal/coordinator/`](../internal/coordinator/README.md) | Drives the batch loop across stages 1–4, freezes target Input Log checkpoints, tracks watermarks, and executes Zero-WAL startup recovery. |
| *(Client)* | **Client SDK** | [`client/`](../client/README.md) | Lightweight public Go client (`client/`, with pure stateless `Verify*` primitives, `torchwood.Policy` (`tlog-policy`) verification, and optional O(1) `StateTracker`) for querying indices and cryptographically verifying point, non-inclusion, and two-sided prefix proofs against witnessed checkpoints. |
| *(Audit)* | **Auditor** | [`internal/auditor/`](../internal/auditor/README.md) | Audits published Output Log entries from the configured start index (`from`, default `0`), alerts on root mismatches, and triggers state-preserving forensic halts. |
| *(Test)* | **Hammer Load & Verification** | [`internal/hammer/`](../internal/hammer/README.md) | Synthetic Zipfian load generator, drip-feed proxy scheduler, and concurrent verifying lookup client harness. |
| *(CLIs & Adapters)* | **Daemon, Tooling & Personalities** | `cmd/vindexd`, `cmd/vindex-auditor`, `cmd/vindex-wasm`, `cmd/vindex-client`, `cmd/hammer`, & `internal/mtc` | Entrypoint binaries for the Index Operator (`vindexd`), Auditor (`vindex-auditor`), offline WASM inspector/tester (`vindex-wasm`), lookup CLI (`vindex-client`), load harness (`hammer`), and experimental MTC checkpoint adapter (`internal/mtc` / `cmd/clonelog`). Requires Go 1.27+ (`filippo.io/torchwood` `>= v0.10.1` and `github.com/tetratelabs/wazero`). |

### 0.2 Checkpoint Promotion & Monotonic Ratcheting
VIndex operates as an asynchronous pipeline: earlier stages ingest and process new entries from the Input Log while the serving plane continues serving the previously committed state. This pipelining is essential for high throughput, but introduces crash and consistency risks if transitions are ambiguous.

Progress is governed by two complementary rules: **promoting checkpoints forward** through durability boundaries, and **ratcheting them in place**:
1. **Checkpoint Promotion**: Checkpoints progress strictly down the pipeline stage by stage. An authenticated Input Log checkpoint is targeted, mapped, and committed to KV storage (`KV_CP`), unlocking non-blocking root prediction and subsequent publication to the Output Log (`Output_CP`), which is finally ratcheted into memory as the active serving state (`Serving_CP`).
2. **Monotonic Ratcheting**: Once a checkpoint or watermark advances at a given stage, it is locked and can never slip backward.

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` (`input_size`) | Durable (synced in Pebble metadata) | Upstream poll, Input Log `tlog-policy` verification, & consistency proof | Upper goalpost (`>= from`) for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` (`input_size`) | Durable (synced in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | Output Log tree size (`Output_CP.Size`, `output_size`) committing Input Log size (`Output_CP.InputSize`, `input_size` in entry) | Durable (Tessera Output Log storage) | Append index state commitment entry & witness cosigning | Cryptographically commits to index root (`mpt-root` + embedded Input Log checkpoint). **Size Distinction**: `Output_CP.Size` represents the tree size (`output_size`, number of index state commitment entries) of the Output Log itself, whereas the committed Input Log size (`input_size`) is carried by the embedded Input Log checkpoint inside the Output Log entry (`Output_CP.InputSize`). |
| **`Serving_CP`** | Output Log Entry | `Serving_CP.InputSize` (`input_size`) | Volatile (In-memory atomic pointer) | Pointer swap under exclusive writer lock (< 5ms) | Active state exposed to lookup clients. |

**The Checkpoint Monotonic Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```
Every relation in the chain is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batches accumulate and commit in discrete chunks toward the target goalpost.
- `KV_CP.Size >= Output_CP.InputSize`: Inverted chunk storage writes must complete a durable disk sync before Output Log append begins.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Appending to the Output Log and collecting witness signatures occur outside reader locking; `Output_CP` is naturally ahead until the writer acquires the exclusive writer lock to swap the serving pointer.
Because storage persistence strictly precedes Output Log publication (`KV_CP.Size >= Output_CP.InputSize`), startup recovery is mathematically guaranteed never to encounter an Output Log commitment referencing uncommitted or missing KV chunks.

### 0.3 Concurrency Architecture: Competing Pressures & Dynamic Backpressure

VIndex pipelines multiple concurrent stages that contend for shared host resources. Efficient throughput requires balancing three competing architectural pressures:

1. **Compute Contention (Mapping vs. Indexing)**:
   - *Pressure*: Stage 2 (WASM guest mapping) and Stage 3 (Merkle value log hashing) are both CPU-bound. If both stages scale independently to host concurrency, runnable threads double, causing OS thread preemption, L1/L2 cache invalidation, and starvation of Pebble compactions and read serving.
   - *Consideration*: Compute allocation must be asymmetric. WASM mapping scales across available cores because entry bundle mapping is embarrassingly parallel. Key indexing is capped at modest concurrency because value log hashing exhibits diminishing returns due to the serial costs of database batching and memtable commits (Amdahl's Law).

2. **Decoupling vs. Garbage Collection Pressure**:
   - *Pressure*: Inter-stage channel buffers decouple throughput jitter between parallel mapping, sequential indexing, and disk syncs. However, deep buffers allow hundreds of uncommitted entry batches to accumulate in memory, creating multi-gigabyte heap graphs that trigger expensive Go runtime GC mark-assist pauses and inflate queueing delay.
   - *Consideration*: Keep channel buffers strictly bounded. The buffer must be large enough to absorb transient disk flush latency, but tight enough that memory stays flat and backpressure engages before heap growth impacts the Go collector.

3. **Dynamic Backpressure via Runtime Scheduling**:
   - *Pressure*: Statically partitioning CPU cores between stages leaves host capacity idle whenever the workload bottleneck shifts (e.g. lightweight vs. expensive WASM mappers, or fast NVMe vs. slow disk syncs).
   - *Consideration*: Use bounded channels as self-regulating scheduler governors. When downstream indexing or disk sync slows, channels fill rapidly, causing the Go runtime to park upstream mapping goroutines. Parked workers yield their OS threads and CPU cores entirely to the storage engine. When storage catches up, channels drain and mapping workers immediately resume.

*Note: Specific worker pool sizes and channel capacities are implementation defaults calibrated by empirical benchmarks, and exposed as runtime configuration flags for operator tuning.*

---

## 1. End-to-End Pipeline & Subsystem Mechanics

### 1.1 Stage 1: Ingest & Tile Cache ([`internal/ingest/`](../internal/ingest/README.md))
The ingestion engine polls the upstream Input Log for signed checkpoints, verifies them, and streams authenticated entry data into a local filesystem tile cache.

1. **Protocol Support & Pluggable Ingestion**: Out of the box, the fetcher supports standard tile-based log specifications—primarily [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP static-ct-api](https://c2sp.org/static-ct-api). Pluggable log adapters can also supply entries in 256-entry bundles.
2. **Cryptographic Authentication**: Regardless of upstream transport, all downloaded entries are cryptographically authenticated against the target checkpoint's Merkle tree head before being admitted into the mapping pipeline.
3. **Local Tile Cache & Retention**: Verified tiles and entry bundles are written directly to a local filesystem cache. This cache acts as a durable staging buffer that decouples network download throughput from downstream indexing. Cached files remain on disk until downstream systems (KV storage and the MPT) have durably committed their changes. Once data is durably persisted beyond the safe pruning watermark, superseded cache files are reaped by an asynchronous background pruner to bound disk usage.

- **[Correctness Invariant] Target Checkpoint Policy & Consistency Verification**:
  - *Rule*: Polled Input Log checkpoints must satisfy the configured Input Log `tlog-policy` (origin, primary signature, and any required witness cosignatures), satisfy `Target_CP.Size >= max(prev_Target_CP.Size, from)`, and pass Merkle consistency verification against the previously committed Input Log checkpoint before the coordinator freezes `Target_CP`.
  - *Rationale*: Protects the Index Operator against forged, unwitnessed, or split-view upstream checkpoints and ensures every `<input-log-checkpoint>` embedded in the append-only Output Log passes downstream lookup client and auditor `tlog-policy` and consistency checks.
  - *Consequence ("Or Else")*: Accepting an unwitnessed or inconsistent Input Log checkpoint would ingest phantom entries or permanently poison the append-only Output Log with an entry that spec-compliant lookup clients and auditors reject.

- **[Correctness Invariant] Crash Recovery Tile Retention**:
  - *Rule*: The tile cache pruner must only delete cached files where no Input Log entry contained in the bundle will ever be required for crash recovery. The authoritative pruning boundary is calculated and governed by the Coordinator ([`internal/coordinator/`](../internal/coordinator/README.md)).
  - *Rationale*: Guarantees that startup recovery can fast-forward lagging state directly from local disk with zero external network requests.
  - *Consequence ("Or Else")*: If uncommitted entry bundles were prematurely pruned, a crash would force the node into expensive network egress to re-download historical bundles, violating the sub-500ms startup recovery SLO.

- **[Performance Optimization] Native 256-Entry Bundling**:
  - *Mechanism*: Ingests entries exclusively in native 256-entry bundles matching the upstream log's tile structure, dispatching each bundle directly as a discrete unit of work to the WASM worker pool.
  - *Impact*: Reduces upstream network requests by 256x compared to per-entry REST endpoints, and eliminates memory slicing/repackaging overhead by aligning the network ingest unit directly with the `map_bundle` FFI execution boundary.

### 1.2 Stage 2: Sandboxed Mapping ([`mapfn/`](../mapfn/README.md), `internal/wasmhost`, & [`internal/ingest/`](../internal/ingest/README.md))
The mapping pipeline extracts canonical keys from raw verified Input Log entries while preserving absolute node isolation and cross-toolchain determinism. Ecosystem developers write a pure mapping function using a streaming `emit` callback (`type EmitMapFunc func(entry []byte, emit func(key []byte))`) via the public WASM Guest SDK (`mapfn/sdk`). The compiled `.wasm` plugin is executed by the Ingestion subsystem's host Wazero worker pool (`internal/wasmhost`):

1. **Sandboxed Worker Pool**: A pool of WASI-free Wazero sandboxes (`internal/wasmhost`) managed by `internal/ingest` executes the guest plugin's exported `map_bundle` function concurrently across 256-entry bundles. The in-guest SDK unpacks the entry bundle, loops over entries, and invokes the user's `MapFn`. Extracted canonical keys are streamed via `emit` directly into the pre-allocated output memory slab, eliminating intermediate collection allocations.
2. **Strict Canonical Key Validation & Host SIMD Storage Hashing**: The guest SDK returns raw, un-hashed canonical keys. The host (`internal/wasmhost`) strictly validates every emitted key against `tlog-vindex` canonical key bounds (`1..1024` printable ASCII bytes in `0x21..0x7E`): if the WASM module emits any key violating these bounds (`len == 0`, `len > 1024`, or any byte outside `0x21..0x7E`), the host triggers an immediate, fatal **`HALT`** (matching `vindex-auditor` and [`docs/tlog-vindex.md`](./tlog-vindex.md#canonical-keys)—never silently dropping invalid keys). Valid un-hashed canonical keys are preserved directly for MPT indexing and HTTP wire responses, while `internal/ingest` computes 32-byte `KeyHash = SHA-256(key)` digests using native CPU hardware vector instructions strictly as an internal Pebble storage digest for inverted chunk keys (`'c'`).
3. **Chronological Resequencer**: Because parallel workers complete batches at variable rates, finished batches enter an in-memory resequencer that emits them in strictly ascending Input Log entry index (`entry_idx`) order before downstream storage handoff.

- **[Correctness Invariant] Deterministic Halt on Execution Trap or Invalid Canonical Key**:
  - *Rule*: Sandboxes execute with zero host I/O, zero network access, and deterministic clocks. If a guest module encounters an unhandled panic, memory violation, runtime trap, or emits any key outside canonical key bounds (`1..1024` bytes in `0x21..0x7E`), the host executes an immediate, fatal `HALT`.
  - *Rationale*: Guarantees 100% deterministic reproducibility across Index Operators and Auditors.
  - *Consequence ("Or Else")*: Silently swallowing guest errors or dropping invalid keys would create divergent index state, resulting in false non-inclusion proofs or `mpt-root` audit mismatches.

- **[Correctness Invariant] Monotonic Chronological Resequencing**:
  - *Rule*: Batches delivered to downstream storage and tree stages must be strictly ordered by Input Log entry index (`entry_idx`) in monotonic ascending sequence with zero gaps.
  - *Rationale*: Canonical key value logs rely on strictly sequential `entry_idx` order to construct valid RFC 6962 compact range hashes.
  - *Consequence ("Or Else")*: Out-of-order writes would corrupt the compact range Merkle structure, producing invalid `value_root` digests that fail lookup client verification.

- **[Performance Optimization] Bundled WebAssembly Execution**:
  - *Mechanism*: Transfers an entire 256-entry bundle into shared memory and executes a single boundary call per bundle, rather than invoking the guest once per entry.
  - *Impact*: Slashes foreign-function interface (FFI) boundary crossings by >99%, dropping FFI CPU overhead from ~23% of total CPU time to < 1%.

- **[Performance Optimization] Host Hardware SIMD Cryptography**:
  - *Mechanism*: Delegates internal Pebble storage `KeyHash = SHA-256(key)` hashing to host CPU vector instructions (such as x86 SHA-NI or ARMv8 Crypto extensions) rather than compiling cryptographic routines into WebAssembly bytecode.
  - *Impact*: Eliminates the ~55% CPU software crypto bottleneck inside WebAssembly while keeping un-hashed canonical keys intact for the MPT.

### 1.3 Stage 3: Inverted Storage Commit ([`internal/kvstore/`](../internal/kvstore/README.md))
The KV storage engine persists canonical keys and their entry index occurrence lists efficiently in an embedded Pebble LSM database, keying `'c'` chunk records by `KeyHash = SHA-256(key)` strictly as an internal Pebble storage digest while the MPT stores un-hashed canonical keys.

1. **Inverted Chunk Value Logs**: Each canonical key's occurrences in the Input Log are stored as an append-only value log partitioned by fixed 64K global Input Log `entry_idx` windows. Chunks are indexed in reverse chronological order so that the latest chunk for any key can be located in a single prefix seek without scanning historical records.
2. **Compact Binary Encoding**: Chunk values store cumulative compact range hashes covering all occurrences of that key in prior chunks, plus a dense sequence of 16-bit relative entry index offsets within the current 64K entry window.
3. **Synchronous Commit Barrier**: Storage updates across a target sync cycle are durably flushed to disk before the coordinator publishes the new index state commitment to the Output Log.

- **[Correctness Invariant] Synchronous Persistence Barrier**:
  - *Rule*: Storage writes must durably flush all modified chunk records and the updated `KV_CP` to disk before the Output Log publication phase is permitted to begin (`KV_CP.Size >= Output_CP.InputSize`).
  - *Rationale*: Guarantees that the physical database never lags behind publicly published commitments across crashes or power loss.
  - *Consequence ("Or Else")*: If the node published an index state commitment to the Output Log but crashed before storage was synced, the published root would reference missing KV chunks, permanently breaking proof generation for witnessed checkpoints.

- **[Correctness Invariant] Point-in-Time Value Log Root Isolation**:
  - *Rule*: When calculating or reconstructing `value_root` digests for a target Input Log size (`input_size`), the storage engine strictly evaluates records committed up to that size, ignoring any newer entries written ahead of it.
  - *Rationale*: Enables startup recovery and lookup queries to safely inspect the database even if storage contains batches ahead of the active serving state.
  - *Consequence ("Or Else")*: Query responses would leak unwitnessed or in-flight entries, violating reader snapshot isolation.

- **[Performance Optimization] Inverted Key Indexing & Prefix Bloom Filters**:
  - *Mechanism*: Orders chunk keys such that the newest chunk is positioned first under the `KeyHash` prefix, and evaluates full-table prefix Bloom filters on seeks.
  - *Impact*: Seeks directly to the active chunk without iterating through historical records, while bypassing disk I/O for non-existent keys.

- **[Performance Optimization] Window-Relative Offset Encoding**:
  - *Mechanism*: Partitions occurrences by 64K Input Log entry windows so each occurrence inside a chunk is stored as a compact 16-bit relative offset rather than a full 8-byte absolute `entry_idx`.
  - *Impact*: Reduces per-occurrence storage footprint by 75% within each chunk.

- **[Performance Optimization] Active Chunk Caching & Parallel In-Memory Value Log Hashing**:
  - *Mechanism*: Retains hot chunk state across consecutive batches in a bounded in-memory cache and evaluates RFC 6962 compact range hashes across distinct keys concurrently in memory before sequentially applying chunk writes to Pebble.
  - *Impact*: Eliminates repeated block cache reads on hot keys and prevents single-thread CPU bottlenecks on Merkle hashing during high-fanout ingestion.

### 1.4 Stage 4: State Commitment (`internal/mpt` & [`internal/tree/`](../internal/tree/README.md))
The commitment plane anchors the updated search index in an append-only Output Log. Each canonical key's value log commits to the strictly increasing sequence of Input Log entry indices (`entry_idx`) matching that key in `[from, input_size)`, where each value log leaf is `value_log_leaf_hash(entry_idx) = SHA-256(0x00 || uint64_be(entry_idx))`, producing a 32-byte `value_root` stored at `key` in the MPT.

Following data preparation, the commitment plane executes a 3-step atomic commitment sequence (Prediction -> Immutable Output Log Append -> Atomic State Ratchet):

1. **Prediction (Non-Blocking Prediction)**: The commitment engine (`internal/tree`) pre-computes the candidate `mpt_root` in memory across modified `(key, value_root)` mappings under a shared read lock without blocking concurrent HTTP lookups.
2. **Immutable Output Log Append & Witnessing**: The `c2sp.org/tlog-vindex-state@v1` index state commitment—binding the predicted `mpt_root` (`mpt-root`), `map-fn`, `from`, and the embedded Input Log checkpoint—is appended as an entry to the append-only Output Log (advancing the Output Log's own tree size `Output_CP.Size` / `output_size`, while committing the Input Log size `Output_CP.InputSize` / `input_size` inside the embedded Input Log checkpoint) and submitted to external witnesses to collect cryptographic cosignatures.
3. **Atomic State Ratchet**: The commitment engine briefly acquires the exclusive tree lock, confirms that the actual computed root matches the prediction, swaps the active serving state pointer, and releases the lock (< 5ms critical section).

- **[Correctness Invariant] Fatal Halt on Root Prediction Divergence**:
  - *Rule*: When the writer lock is acquired to commit in-memory mutations, the actual computed tree root must strictly match the predicted root previously committed to the Output Log. If any divergence is detected, the daemon halts immediately.
  - *Rationale*: Output Log entries are immutable. Once an index state commitment is published and witnessed, the node must never serve an internal state that diverges from it.
  - *Consequence ("Or Else")*: Continuing execution would publish an equivocal commitment to the Output Log that cannot be proven by the node's internal state.

- **[Correctness Invariant] Single-Timeline Equivocation Resistance**:
  - *Rule*: Every published Output Log entry (`c2sp.org/tlog-vindex-state@v1`) binds the exact `mpt_root` (`mpt-root`), `map-fn`, and `from` to the embedded signed Input Log checkpoint.
  - *Rationale*: Independent witnesses cosign the Output Log checkpoint note, preventing the Index Operator from presenting conflicting views of index state to different lookup clients without producing split-view evidence detectable by public monitors and auditors.
  - *Consequence ("Or Else")*: An Index Operator attempting to selectively hide records would be mathematically detected by any monitor or auditor cross-checking witness cosignatures.

- **[Performance Optimization] Non-Blocking Prediction & Split-Locking**:
  - *Mechanism*: Separates slow disk persistence (mmap page `fsync`s) from in-memory lookup reads. Disk operations run in the background outside the exclusive tree lock; the exclusive lock is held solely for the in-memory commit and pointer swap (< 5ms).
  - *Impact*: HTTP lookup throughput sustains over 670,000 reads/second during active disk commits, compared to severe stalls under coarse global locking.

### 1.5 Stage 5: Read Serving ([`internal/server/`](../internal/server/README.md) & `internal/wire`)
The public HTTP listener (`--listen_addr`) exposes ONLY the spec-defined endpoints—`<index-url>/keys`, `<index-url>/values`, and (when co-hosted) `<output-log-url>/checkpoint` and `<output-log-url>/tile/...`—adhering to Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions (see [`docs/tlog-vindex.md`](./tlog-vindex.md) for the full wire specification):

1. **Two-Endpoint Read Protocol**:
   - **Key Discovery & State Commitment (`GET <index-url>/keys?key=<key>` or `GET <index-url>/keys?prefix=<key-prefix>`)**: Acquires a brief shared read lock on the MPT (`internal/mpt`), evaluates point inclusion/non-inclusion (`ProveKey`) or prefix subtree scans (`ProvePrefix`), and returns the `c2sp.org/tlog-vindex-keys@v1` block (`proof [<base64-mpt-proof>]`, `<canonical-key> <base64-value-root>`) followed by the `c2sp.org/tlog-proof@v1` block (`extra <base64-encoded-tlog-vindex-state>`, `index`, audit path hashes, and `<output-log-checkpoint>`).
   - **Lock-Free Value Log Pagination (`GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]`)**: Computes `KeyHash = SHA-256(key)` internally to query Pebble inverted chunks (`'c'`) with **zero MPT lock acquisition**, returning the `c2sp.org/tlog-vindex-values@v1` response (`preceding <preceding-count>`, base64 compact range hashes, and matching decimal `entry_idx` lines).
2. **Prefix Policy Guardrails**: Prefix queries (`?prefix=<key-prefix>`) are validated against an optional personality-configured prefix policy (such as `--prefix_policy=reversed-dns` for CT/MTC deployments rejecting bare TLD/public-suffix scans beneath `eTLD+1` with `HTTP 400 Bad Request`) and bounded by `--max_prefix_keys` (returning `HTTP 413 Content Too Large` if exceeded).

- **[Correctness Invariant] Serving Isolation Invariant**:
  - *Rule*: Lookup client queries are strictly isolated to data committed by the active serving checkpoint (`Serving_CP.InputSize <= Output_CP.InputSize`). Any in-flight storage writes ahead of `Serving_CP` must be invisible to readers.
  - *Rationale*: Ensures that every response returned by the server can be mathematically proven against the currently witnessed checkpoint.
  - *Consequence ("Or Else")*: Lookup clients would observe unwitnessed or uncommitted future entries, causing client-side Merkle proof verification to fail.

- **[Correctness Invariant] Inductive Backward Verification Protocol**:
  - *Rule*: Multi-page query pagination progresses backward (`before=<before>`). Page 1 verifies `value_root` directly against `mpt_root`; continuation pages inductively fold the compact range hashes from the preceding page to obtain the expected `value_root` for the older slice.
  - *Rationale*: Proves completeness across high-cardinality keys without requiring the server to construct consistency proofs or return millions of historical entry indices in a single response.
  - *Consequence ("Or Else")*: Forward pagination would require either returning unverified future state or forcing lookup clients to scan from `from`, degrading lookup latency.

- **[Performance Optimization] Direct Plaintext Streaming**:
  - *Mechanism*: Streams standardized multi-section plaintext responses (`internal/wire`) directly to network sockets without intermediate JSON marshalling or reflection.
  - *Impact*: Maintains sub-millisecond median read latency (< 1ms P50, < 15ms P99) during heavy concurrent ingestion.

---

## 2. System-Wide Invariants & Crash Consistency

### 2.1 The Universal Crash Invariant
Because storage persistence strictly precedes Output Log publication:
```text
KV_CP.Size >= Output_CP.InputSize   (persisted KV storage watermark >= Output_CP.InputSize)
```
This invariant holds under all crash, kill, and power loss scenarios. Note the distinction between the Output Log's own Merkle tree size (`Output_CP.Size`, `output_size`) and the committed Input Log size (`Output_CP.InputSize`, `input_size`) carried in the embedded Input Log checkpoint inside each Output Log entry. Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted or missing KV store chunks. If a crash occurs after storage sync but before Output Log publishing, `KV_CP.Size > Output_CP.InputSize`; startup recovery safely ignores chunks beyond `Output_CP.InputSize` using point-in-time `value_root` reconstruction bounded at `Output_CP.InputSize`.

### 2.2 Zero-WAL Startup Recovery Sequence
On daemon launch, `vindexd` binds the internal operational listener (`--metrics_addr`, serving `/healthz`, `/readyz`, `/metrics`, and `/debug/pprof/*`) and public HTTP listener (`--listen_addr`, serving `<index-url>/keys`, `<index-url>/values`, and when co-hosted `<output-log-url>/checkpoint` and `<output-log-url>/tile/...`) immediately so `/healthz` on `--metrics_addr` returns `200 OK`, `/readyz` on `--metrics_addr` returns `503 Service Unavailable` (`Retry-After: 30`, `"status": "mpt_initializing"`), and public lookup endpoints return `503 Service Unavailable` while `mpt.Open()` replays any uncompacted journal frames on disk. Once `mpt.Open()` completes, the coordinator defines `recoveryTarget = Output_CP.InputSize` when `Output_CP.Size > 0` (or `KV_CP.Size` when `Output_CP.Size == 0` during an interrupted Genesis Backfill) and executes a 3-phase Zero-WAL recovery sequence (`coord.Recover()`):

1. **Phase 1: Instant Warm Start (< 5ms after `mpt.Open`)**:
   - Entered if and only if `Output_CP.Size > 0`, the MPT's persisted snapshot `Version()` equals `(Output_CP.InputSize, true)` (`exact == true` and `MPT_Durable_Size == Output_CP.InputSize`), and the trie root matches `mpt-root` in the latest Output Log entry.
   - Clean shutdown is verified: activates the latest published checkpoint as `Serving_CP` and **opens the HTTP Read Server + `/readyz` (`200 OK`) immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Entry Replay (< 500ms after `mpt.Open`)**:
   - Entered whenever the persisted MPT lags `recoveryTarget` or is inexact (`version < recoveryTarget || !exact`):
     - Streams missing historical Input Log entries across `[max(MPT_Durable_Size, from) .. recoveryTarget)` directly from the local disk cache.
     - Maps replayed entries to identify modified canonical keys.
     - Reconstructs `value_root` digests for modified keys across `[from, recoveryTarget)` (where each value log leaf is `value_log_leaf_hash(entry_idx) = SHA-256(0x00 || uint64_be(entry_idx))`) with **zero database writes**.
     - Updates in-memory trie nodes and flushes trie persistence to disk. If `Output_CP.Size > 0`, asserts that the resulting root strictly matches the Output Log entry commitment, activates `Serving_CP`, and **opens the Read Server + `/readyz` (`200 OK`, < 500ms)**; if `Output_CP.Size == 0` (Genesis Backfill not yet finalized), public endpoints and `/readyz` remain `503 Service Unavailable`.
3. **Phase 3: Background Catchup**:
   - Resumes forward ingestion from `max(Serving_CP.InputSize, from)` when `Output_CP.Size > 0` (or from `max(KV_CP.Size, from)` in Genesis Backfill when `Output_CP.Size == 0`) toward `Target_CP`.

### 2.3 Moving-Goalpost Prevention & Value Log Determinism
When indexing high-velocity logs, the upstream log head advances continuously. Polling unverified checkpoints on every batch risks synchronization starvation. The coordinator freezes verified target sync checkpoints into durable database metadata prior to batch processing, ensuring that the ingestion pipeline processes fixed ranges to completion before advancing to a new target.

Value log roots (`value_root`) within the target boundary are computed deterministically from `value_log_leaf_hash(entry_idx) = SHA-256(0x00 || uint64_be(entry_idx))` across matching Input Log entry indices in `[from, input_size)`. This deterministic hashing guarantees that independent Index Operators, Lookup Clients, and Auditors compute identical `value_root` digests for any given Input Log size.

### 2.4 Genesis Backfill Lifecycle (Unserved Bootstrap)

When bootstrapping an unserved index from its configured start index `from` (`0` or a suffix start index) on large, high-cardinality logs, accumulating every modified key's `value_root` across `[from, Target_CP.Size)` in memory before committing to the MPT would consume excessive heap memory, while publishing and witnessing an Output Log entry on every batch prior to initial catch-up would incur unnecessary intermediate Output Log appends and witness roundtrips.

To resolve this simply without background channels or double-buffered maps, VIndex executes a synchronous **Genesis Backfill** lifecycle while `Output_CP.Size == 0`:

| State / Phase | Entry Condition | Operations | Exit Transition |
| :--- | :--- | :--- | :--- |
| **Mode Selection** | Daemon startup / sync cycle start | Inspects Output Log tree size (`Output_CP.Size`). | `Output_CP.Size == 0` -> **Genesis Backfill**<br>`Output_CP.Size > 0` -> **Normal Serving** |
| **Batch Ingest & Coalesce** | `Output_CP.Size == 0` and `KV_CP.Size < Target_CP.Size` | Streams 256-entry bundles, stages Pebble `'c'` chunk updates, and tracks modified `(key, value_root)` mappings in a bounded map while suppressing Output Log appends. | Coarse checkpoint threshold reached -> **Synchronous Coarse Checkpoint**<br>Reaches `Target_CP.Size` -> **Genesis Finalization** |
| **Synchronous Coarse Checkpoint** | Modified-key or entry-count threshold reached | Executes synchronous `Pebble Sync` (`KV_CP.Size`) followed immediately by synchronous `MPT Commit & Persist` (`MPT_Durable_Size`) on the batch loop, then clears the modified-key map. | Returns to **Batch Ingest & Coalesce** |
| **Genesis Finalization** | Reached `Target_CP.Size` | Executes final synchronous `Pebble Sync -> MPT Commit & Persist`, appends Output Log **`Entry 0`** (`c2sp.org/tlog-vindex-state@v1`), collects witness cosignatures, and promotes `Serving_CP`. | Permanent one-way transition to **Normal Serving** (`Output_CP.Size > 0`) |

1. **Activation & Serving Plane Isolation**:
   - Activated automatically if and only if the Output Log has zero entries (`Output_CP.Size == 0`).
   - Because no Output Log checkpoint has been published yet, public `<index-url>/keys` and `<index-url>/values` endpoints return `503 Service Unavailable`, while on the internal `--metrics_addr` listener `/healthz` returns `200 OK` and `/readyz` returns `503 Service Unavailable` with structured bootstrap progress diagnostics.
2. **Synchronous Periodic Checkpointing & Crash Recovery**:
   - Intermediate root predictions, Output Log appends, and external witness roundtrips are suppressed until `Target_CP.Size` is reached.
   - At periodic coarse intervals, the coordinator executes a synchronous `Pebble Sync -> MPT Commit & Persist` sequence directly in-line on the batch loop, strictly maintaining `KV_CP.Size >= MPT_Durable_Size`.
   - If interrupted mid-backfill, crash recovery reuses the standard Phase 2 fast-forward replay path against `KV_CP.Size` (replaying cached entry bundles across `[max(MPT_Durable_Size, from) .. KV_CP.Size)` before resuming from `KV_CP.Size`).
3. **Permanent One-Way Transition**:
   - Upon reaching `Target_CP.Size`, the final MPT root is committed and persisted, published as Output Log `Entry 0`, witnessed, and promoted to `Serving_CP`. From that point forward (`Output_CP.Size > 0`), the node runs permanently in Normal Serving Mode. See [`internal/coordinator/README.md`](../internal/coordinator/README.md) for detailed mechanics.

---

## 3. Independent Auditor Architecture ([`internal/auditor/`](../internal/auditor/README.md))

The auditor subsystem audits the Index Operator's published Output Log entries from the configured start index (`from`), detects equivocation or forged commitments, and halts with forensic state preserved on divergence. For the full continuous audit loop, threat vector matrix, forensic state-freeze mechanics, and operational mismatch runbook, see [`internal/auditor/README.md`](../internal/auditor/README.md).

### 3.1 Verification Boundaries
1. **Lookup Client Verification (`client/`)**: Evaluates individual query responses (`c2sp.org/tlog-vindex-keys@v1` + `c2sp.org/tlog-proof@v1` and `c2sp.org/tlog-vindex-values@v1`) against Output Log and Input Log `torchwood.Policy` (`tlog-policy`) rules via the lightweight public Go client SDK ([`client/`](../client/README.md), using stateless `Verify*` primitives and optional O(1) `StateTracker` checkpoint ratcheting).
2. **Full-Log Independent Auditor (`internal/auditor/`)**: A standalone daemon (`vindex-auditor`) that continuously tails the Output Log, verifies checkpoint `tlog-policy` quorums and Merkle consistency, validates `map-fn` and `from` parameters in each Output Log entry, downloads and authenticates Input Log entries across `[from, input_size)`, executes mapping independently, reconstructs its own local MPT, and asserts that its locally computed `mpt_root` strictly matches the published `mpt-root` in each Output Log entry.

### 3.2 State-Preserving Forensic Halt
- **Atomic Staging & Forensic State Freeze**: Each Output Log entry is staged via `KVIndexer.StageMappedBatch` before predicting the candidate `mpt_root`. If the candidate `mpt_root` diverges from the published Output Log commitment, the auditor closes the unapplied Pebble batch without committing, clears the in-memory chunk cache, halts forward sync (`vindex_auditor_root_mismatch = 1`), and freezes database/MPT files on disk in-place to preserve uncorrupted forensic evidence.
- **Liveness vs. Readiness Decoupling**: On upstream divergence, `/healthz` on `--metrics_addr` remains `HTTP 200 OK` (preventing orchestrator liveness restarts from disturbing frozen forensic state), while `/readyz` on `--metrics_addr` returns `HTTP 503` with structured JSON diagnostics. See [`internal/auditor/README.md`](../internal/auditor/README.md) for the complete threat matrix and incident response runbook.

---

## 4. Operational Considerations & Hardware Sizing

### 4.1 Dual-Disk Physical NVMe Isolation
Deploying MPT working files and Pebble DB on separate physical NVMe SSDs is recommended for high-velocity installations:
- **Disk A (NVMe SSD)**: Pebble DB (`'c'` chunks, `'m'` metadata) and local managed tile cache.
- **Disk B (NVMe SSD)**: Memory-mapped MPT working files.

Physical separation isolates sequential MPT compaction writes from Pebble LSM memtable flushes, preventing write stalls during sustained bulk ingestion.

### 4.2 Workload & Memory Sizing Guidance
Resource allocation in `vindexd` and `vindex-auditor` is governed directly by plain CLI flag defaults (Pebble block cache size, WASM worker concurrency, batch/channel bounds, and `--max_prefix_keys`). Because `internal/mpt` memory-maps the trie directly from disk, operators should leave the majority of host RAM available to the OS page cache so active MPT pages stay resident in memory:

| Scale (Unique Canonical Keys) | MPT Working Set (OS Page Cache) | Pebble Disk (`'c'` chunks) | Recommended Host RAM |
| :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1.0 – 1.5 GB | ~1 GB | 8 GB |
| **Medium (100M)** | ~10 – 15 GB | ~10 GB | 64 GB |
| **Large (1B)** | ~100 – 150 GB | ~100 GB | 256 GB |
| **Very Large (2B)** | ~200 – 300 GB | ~200 GB | 512+ GB |

### 4.3 Variable-Length Canonical Keys & Two-Sided Prefix Proofs (`internal/mpt`)

VIndex v1 indexes variable-length canonical keys (`1..1024` printable ASCII bytes `0x21..0x7E`, validated via `mpt.ValidateCanonicalKey`) directly in a single unified MPT (`filippo.io/torchwood/mpt`):
- **Hybrid Keying**: The MPT stores raw, un-hashed variable-length canonical keys (`mpt.Key`) so common string prefixes share a dedicated subtrie, while Pebble DB (`internal/kvstore`) keys inverted chunks by `KeyHash = SHA-256(key)` strictly as an internal Pebble storage digest to preserve fixed 41-byte LSM keys and 33-byte prefix Bloom filters.
- **Two-Sided Prefix Proofs**: `GET <index-url>/keys?prefix=<key-prefix>` scans the MPT subtree via `Tree.Scan(prefix)`, proves the subtree boundary via `mpt.ProvePrefix`, and allows lookup clients (`mpt.VerifyPrefix`) to verify both **soundness** (every returned key has `prefix` and maps to its authenticated `value_root`) and **completeness** (zero matching keys in the global trie were omitted). See [`docs/tlog-vindex.md`](./tlog-vindex.md#verifying-a-keys-response) for the formal verification procedure.

### 4.4 Prometheus Metrics & SLO Thresholds
The daemon exports Prometheus metrics on `--metrics_addr` (`/metrics`, alongside `/healthz`, `/readyz`, and `/debug/pprof/*`) covering the entire lifecycle:
- Ingestion Lag: `vindex_ingestion_lag` (Target: < 60s)
- Mapping Latency: `vindex_map_bundle_duration_seconds` (Target: < 50ms/bundle)
- MPT Write Lock Duration: `vindex_mpt_write_duration_seconds` (Target: < 5ms)
- HTTP Lookup Latency: `vindex_lookup_latency_seconds` (Target: P99 < 50ms, P50 < 1ms)
- Read Availability: Target >= 99.9% uptime.

### 4.5 Single-Host Disaster Recovery Procedures
- **MPT Disk Corruption**: Rebuilt entirely from Pebble inverted chunks (`'c'`) and cached entry bundles via point-in-time `value_root` reconstruction without network egress.
- **Pebble Storage Corruption**: Replayed from local tile cache or streamed from the upstream Input Log.
- **Runtime Trap / Invariant Divergence**: Deterministic `HALT` policy freezes state and preserves disk data for post-mortem forensics.

---

## 5. Retired Ideas & Alternatives Considered

### 5.1 Arbitrary Runtime Backfill Mode Switching (Retired)
- **Proposed**: Allowing running daemons to switch dynamically between a bulk ingestion mode ("Backfill Mode") and Normal Serving Mode during live catch-up operations.
- **Empirical Rejection Findings**:
  1. **Read Starvation on Live Nodes**: Shutting down the HTTP read server during live catch-up breaks availability for active lookup clients.
  2. **State Machine Complexity**: Dynamic mode switching introduced edge cases around checkpoint continuity, witness synchronization, and reader lock handoffs.
- **Resolution**: Arbitrary runtime switching was permanently retired. Live serving nodes always operate in Normal Serving Mode. For unserved indices bootstrapping from `from` (`Output_CP.Size == 0`), the synchronous **Genesis Backfill** lifecycle (§2.4) suppresses intermediate Output Log appends until caught up, then transitions permanently to Normal Serving Mode.

### 5.2 Intermediate Write-Ahead Log in Storage ('w' Prefix)
- **Proposed**: Staging mapped records under a transient `'w'` prefix in Pebble DB before an asynchronous background worker converted them into inverted chunks (`'c'`).
- **Empirical Rejection**: Caused double-write disk amplification, massive LSM compaction churn, and severe P99 read latency spikes (up to 1,214 ms).
- **Resolution**: Retired in favor of the Zero-WAL direct inverted chunk commit architecture.

### 5.3 Sparse Merkle Trees (SMT) & Verkle Trees
- **SMT**: Rejected due to prohibitive memory and disk I/O across 256-level tree depths.
- **Verkle Trees**: Rejected due to high CPU polynomial commitment generation costs during high-throughput ingestion.
- **Resolution**: Standardized on path-compressed binary MPT in `mmap` (`filippo.io/torchwood/mpt`).

### 5.4 Distributed Key-Value Engines (Cloud Bigtable, Spanner, Cassandra)
- **Proposed**: Backing the inverted chunk store with a distributed NoSQL database.
- **Theoretical Rejection**: The authenticated MPT already requires single-host physical RAM/mmap locality; remote RPC hops degrade bulk ingestion throughput by orders of magnitude without solving tree state replication.
- **Resolution**: Embedded Pebble LSM storage engine.

### 5.5 Subsystem-Level Alternatives
- **Per-entry WebAssembly invocation (`map_leaf`) & in-guest software SHA-256 hashing**: Retired in favor of 256-entry `map_bundle` slabs and host SIMD Pebble storage hashing; see [`mapfn/README.md`](../mapfn/README.md#3-alternatives-considered-or-tried).
- **Forward value log pagination (`start=X&limit=M`)**: Retired in favor of backward pagination (`before=<before>[&limit=<limit>]`) over RFC 6962 compact range hashes; see [`internal/server/README.md`](../internal/server/README.md).

---

## 6. Verification Gate

All architectural invariants, package dependency boundaries, and end-to-end pipeline flows are verified via:

```bash
go test -race ./vindex/...
```
