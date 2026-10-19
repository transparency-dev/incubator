# Coordinator & Lifecycle Engine

This document defines the batch orchestration engine, watermark governance, Zero-WAL startup recovery protocols, load-bearing invariants, and verified performance optimizations for the **Coordinator Subsystem** (`vindex/internal/coordinator`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Orchestration Dilemma
The VIndex architecture decomposes indexing into five specialized, asynchronous subsystems:
1. **`internal/ingest`**: Network fetching and local 256-entry bundle tile caching.
2. **`mapfn` & `internal/wasmhost`**: Isolated WebAssembly guest SDK (`mapfn`) and Wazero sandbox host execution (`internal/wasmhost`).
3. **`internal/kvstore`**: Pebble LSM inverted chunk storage.
4. **`internal/mpt` & `internal/tree`**: Authenticated MPT state trie (`internal/mpt`) and Output Log state commitment publication (`internal/tree`).
5. **`internal/server`**: C2SP HTTP read serving.

Without a central orchestrator managing these components behind strict black-box interfaces, three critical failure modes emerge:
1. **Watermark Drift & Ambiguity**: If individual subsystems track state independently, cross-subsystem boundaries drift out of alignment. A crash between storage sync and Output Log publication leaves the node unable to determine where recovery begins.
2. **Moving-Goalpost Starvation**: In high-velocity logs appending thousands of entries per second, continuously polling the log head prevents the pipeline from ever finalizing a batch, causing synchronization starvation.
3. **Network-Dependent Crash Recovery**: If startup recovery relies on downloading historical tiles over the network, node restart times become unpredictable and fail completely during upstream network outages.

### 1.2 Centralized Watermark Authority & Separation of Concerns
The Coordinator serves as the **single source of truth** for system lifecycle and watermark governance:
- Worker subsystems expose clean, black-box functional interfaces and do not inspect each other's internal metadata or storage engines.
- The Coordinator alone tracks the global progression chain, evaluates persistence boundaries, and calculates the authoritative `SafeWatermark` (`max(min(KV_CP.Size, MPT_Durable_Size), from)`) communicated to the tile cache reaper.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Drive the steady-state batch processing loop across all pipeline stages in strictly monotonic sequence.
  - Prevent moving-goalpost starvation by freezing target sync checkpoints prior to batch ingestion.
  - Enforce the synchronous handoff: persist the KV checkpoint to disk, ratchet forward, predict the MPT change, and promote the state commitment entry to the Output Log.
  - Guarantee deterministic, network-free Zero-WAL crash recovery (< 5ms clean start, < 500ms dirty crash recovery after `torchwood/mpt` journal replay completes on open).
- **Non-Goals**:
  - **No Distributed Consensus**: Operates strictly within a single process; does not run Raft, Paxos, or distributed leader election.
  - **No Direct In-Memory Mutation**: The Coordinator does not touch trie nodes or LSM chunk bytes directly; it coordinates subsystem boundaries.
  - **No Arbitrary Runtime Mode Switching**: Operates Normal Serving Mode for all serving logs; Genesis Backfill is used strictly during unserved initial bootstrap when the Output Log is empty (`Output_CP.Size == 0`).

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Orchestrates the ingestion fetcher and local tile cache, WASM mapping pipeline (`internal/wasmhost`), KV chunk store, MPT manager (`internal/mpt`), `OutputPublisher` (`internal/tree`), and C2SP `tlog-policy` checkpoint verification via `filippo.io/torchwood` (`torchwood.Policy`, `torchwood.VerifyCheckpoint`).
- **Known Pain Points ("Warts and All")**:
  - **Dirty Crash Recovery Replay Duration**: While clean restarts open read serving in under 5 milliseconds, recovering from a dirty kill where MPT disk `fsync` lagged behind the committed recovery target requires replaying historical 256-entry bundles from the local disk cache, taking up to 500ms before HTTP queries can be served.
  - **End-of-Cycle Partial Batch Flushing**: Each sync cycle streams a bounded Input Log entry range up to the frozen target checkpoint and flushes any trailing partial commit batch at the end of the range so low-velocity logs do not stall waiting to fill a multi-tile slab.

---

## 2. Detailed Design

### 2.1 The Master Batch Loop
The coordinator executes batch synchronization through a structured, 6-step sequential lifecycle:

| Step | Phase | Action & Subsystem Transition | Durability Transition |
| :- | :--- | :--- | :--- |
| **1** | **Poll & Freeze** | Polls upstream Input Log `/checkpoint`, verifies Input Log C2SP `tlog-policy` via `filippo.io/torchwood` (`torchwood.Policy`, `torchwood.VerifyCheckpoint`), checks `Target_CP.Size >= max(prev_Target_CP.Size, from)` and Input Log Merkle consistency against `prev_Target_CP`, and writes `Target_CP` to Pebble metadata. | Freezes target sync boundary. |
| **2** | **Tile Ingestion** | Downloads missing 256-entry bundles across `[max(KV_CP.Size, from), Target_CP.Size)` into the local tile cache. | Durably stages verified entry bundles on disk. |
| **3** | **Parallel Mapping** | Streams 256-entry bundles to WASM workers (`internal/wasmhost`), preserves validated un-hashed canonical keys (`1..1024` bytes in `0x21..0x7E`) alongside host SIMD `KeyHash = SHA-256(key)` Pebble prefixes, and resequences batches into multi-tile commit slabs. | In-memory key-index aggregation. |
| **4** | **Storage Commit** | Streams commit slabs into the KV store (committing intermediate slabs without disk sync while accumulating modified `(key, value_root)` mappings across the target window, and executing a blocking disk `fsync` barrier on the final slab reaching `Target_CP.Size`). | **Ratchets persisted KV storage watermark durably to disk and persists `KV_CP` at `Target_CP.Size`.** |
| **5** | **Commitment & Promotion** | Once `Target_CP.Size` is reached and synced in Pebble, predicts candidate `mpt_root` over accumulated modified `(key, value_root)` mappings, appends one state commitment entry (`c2sp.org/tlog-vindex-state@v1`: `mpt-root`, `map-fn`, `from`, and the embedded `<input-log-checkpoint>`) for `Target_CP` to the Output Log, collects witness cosignatures per Output Log `tlog-policy`, and ratchets `Serving_CP` (`ServingState`) under the exclusive tree lock (< 5ms). | **Promotes state to Output Log (`Output_CP`) & Serving (`Serving_CP`).** |
| **6** | **Pruning Notification** | Computes `SafeWatermark` (`max(min(KV_CP.Size, MPT_Durable_Size), from)`) and notifies the tile cache reaper. | Bounded disk cache garbage collection. |

### 2.2 Checkpoint Governance & Progression Chain

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` (`input_size`) | Durable (synced in Pebble metadata) | Upstream poll, Input Log `tlog-policy` (`torchwood.VerifyCheckpoint`) & Merkle consistency check (`>= max(prev_Target_CP.Size, from)`) | Upper goalpost for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (synced in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | `Output_CP.Size` (`output_size`), committing `Output_CP.InputSize` (`input_size` in state commitment entry) | Durable (Tessera Output Log storage) | Append state commitment entry & witness cosigning | Cryptographically commits to index root (`mpt-root` + embedded Input Log checkpoint). |
| **`Serving_CP`** | Output Log Entry | `Serving_CP.InputSize` (`input_size`) | Volatile (In-memory atomic `ServingState` pointer) | Pointer swap via atomic state promotion under tree lock (< 5ms) | Active state exposed to client HTTP readers. |

**Monotonic Checkpoint Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```
Every relation is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batch aggregation advances toward the target checkpoint in discrete commit slices.
- `KV_CP.Size >= Output_CP.InputSize`: KV storage persistence strictly precedes Output Log publication.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Output Log publication and witness collection execute outside reader locking; `Output_CP` advances before the in-memory `ServingState` pointer is swapped via atomic state promotion under the tree lock.

#### Intermediate Buffers & Trailing Durability
- `Target_CP -> KV_CP`: Ingest stages 256-entry bundles on disk and through worker mapping queues; the persisted KV storage watermark accumulates across write batches until synced at `KV_CP.Size`.
- `KV_CP -> Output_CP`: Non-blocking MPT prediction calculates candidate `mpt_root`.
- `Output_CP -> Serving_CP`: In-memory atomic swap ratchets `Serving_CP` (< 5ms critical section).
- `Trailing Serving_CP`: `MPT_Durable_Size` `fsync`s to disk in the background, satisfying `Serving_CP.InputSize >= MPT_Durable_Size`.

### 2.3 Authoritative Safe Pruning Watermark for Tile Cache Reclamation
To guarantee that the ingestion cache never deletes 256-entry bundles needed for crash recovery, the Coordinator calculates the authoritative safe pruning boundary `SafeWatermark = max(min(KV_CP.Size, MPT_Durable_Size), from)`. Because storage persistence strictly precedes Output Log publication and MPT persistence (`KV_CP.Size >= Output_CP.InputSize >= MPT_Durable_Size`), clamping the lower bound to `from` ensures that suffix indices (`from > 0`) never retain or replay pre-`from` tiles before their first durable MPT sync, while keeping all 256-entry bundles in `[max(MPT_Durable_Size, from), KV_CP.Size)` cached on disk until the MPT confirms a durable `fsync`.

### 2.4 Moving-Goalpost Prevention
On high-traffic transparency logs, the log head advances continuously. If the coordinator polled unverified checkpoints on every iteration, the sync target would constantly move, starving downstream commitment.

The Coordinator prevents this by writing the verified target checkpoint into Pebble DB metadata (`Target_CP`) prior to batch processing. The entire pipeline processes that fixed entry range to completion before the coordinator advances to a new target.

### 2.5 Zero-WAL Startup Recovery Sequence & Uncommitted KV Writes
On daemon launch, `vindexd` binds `--metrics_addr` and `--listen_addr` immediately (returning `200 OK` on `/healthz` and `503 Service Unavailable` with `"status": "mpt_initializing"` on `/readyz` on `--metrics_addr`, and `503 Service Unavailable` on public lookup endpoints) while opening the MPT replays any uncompacted `torchwood/mpt` journal frames on disk. Once journal replay finishes, the Coordinator computes `recoveryTarget = Output_CP.InputSize` when `Output_CP.Size > 0` (or `KV_CP.Size` when `Output_CP.Size == 0`) and executes a deterministic 3-phase recovery sequence:

1. **Phase 1: Instant Warm Start (< 5ms after MPT open)**:
   - Entered if and only if `Output_CP.Size > 0`, the MPT's persisted `Version()` equals `(Output_CP.InputSize, true)` (`exact == true` and `MPT_Durable_Size == Output_CP.InputSize`), and the trie root matches `mpt-root` in the latest Output Log state commitment entry.
   - Clean shutdown is verified: activates `Serving_CP`, initializes watermarks, and **opens the HTTP Read Server + `/readyz` (`200 OK`) immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms after MPT open)**:
   - Entered whenever the persisted MPT lags `recoveryTarget` or is inexact (`version < recoveryTarget || !exact`):
     - Streams missing historical 256-entry bundles across `[max(MPT_Durable_Size, from), recoveryTarget)` directly from the local disk tile cache.
     - Maps replayed entries via `map_bundle` to collect distinct modified un-hashed canonical keys.
     - Reconstructs value log roots (`value_root`) for modified keys at `recoveryTarget` from Pebble (via `KeyHash = SHA-256(key)`) with **zero writes to the database**.
     - Updates in-memory MPT nodes with sorted `(key, value_root)` pairs and flushes MPT persistence to disk. When `Output_CP.Size > 0`, asserts that the resulting `mpt_root` strictly matches the latest Output Log state commitment entry, activates `Serving_CP`, and **opens the Read Server + `/readyz` (`200 OK`, < 500ms)**; when `Output_CP.Size == 0`, public endpoints and `/readyz` remain `503 Service Unavailable`.
3. **Phase 3: Background Catch-Up & Uncommitted KV Writes**:
   - Resumes forward ingestion from `max(Serving_CP.InputSize, from)` when `Output_CP.Size > 0` (or from `max(KV_CP.Size, from)` in Genesis Backfill when `Output_CP.Size == 0`—including clean restarts mid-backfill where `version == KV_CP.Size && exact == true`) toward `Target_CP.Size`.
   - **Handling Uncommitted KV Writes**: If a crash occurred in Normal Serving Mode after Pebble durably synced a batch to disk but before Output Log commitment (`KV_CP.Size > max(Serving_CP.InputSize, from)`), the next sync cycle streams starting from `max(Serving_CP.InputSize, from)`. When re-processing Input Log entries that were already written to disk, the KV store filters out already-persisted entry indices and reconstructs their `value_root` digests directly from Pebble without re-writing storage. This allows uncommitted batches to be safely published to the Output Log upon initial sync without duplicate entries or storage churn.

### 2.6 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Synchronous Stage Promotion**:
  - *Rule*: Inverted chunk storage writes must complete a durable disk sync and commit `KV_CP` before Output Log publication is permitted to execute (`KV_CP.Size >= Output_CP.InputSize`).
  - *Rationale*: Guarantees `KV_CP.Size >= Output_CP.InputSize` across all crash scenarios.
  - *Consequence ("Or Else")*: A crash between Output Log publishing and storage sync would publish a state commitment entry referencing missing or rolled-back KV chunks, permanently breaking inclusion proofs for witnessed checkpoints.

- **[Correctness Invariant] Zero-WAL Startup Durability Guarantee**:
  - *Rule*: Because `KV_CP.Size >= Output_CP.InputSize` (and cached tiles cover `[max(MPT_Durable_Size, from), KV_CP.Size)`), crash recovery must resolve all lagging MPT state using the local tile cache and local Pebble DB records without issuing external network requests.
  - *Rationale*: Protects node availability against upstream log outages and guarantees predictable cold-boot timing.
  - *Consequence ("Or Else")*: A node recovering from a crash during an upstream network partition would fail to boot, causing extended service downtime.

- **[Performance Optimization] Multi-Tile Slab Aggregation & Target-Level Witnessing**:
  - *Mechanism*: Buffers mapped Input Log entries into multi-tile commit slabs without per-slab disk syncs on intermediate slabs, executing a single durable KV sync and Output Log witness cycle at `Target_CP.Size`.
  - *Impact*: Amortizes disk write latency and external witness network RPCs across the sync window, sustaining high indexing throughput (>90,000 entries/sec).

### 2.7 Coordination Contract & State Guarantees

The coordinator acts as the single source of truth for pipeline progression and lifecycle management:

- **Inputs**:
  - Input Log fetcher and configured Input Log `torchwood.Policy`.
  - Configured start index `from` (default `0`) and constant 32-byte `map-fn` commitment digest.
  - Local tile cache.
  - Mapping pipeline (`internal/wasmhost`).
  - KV store (`internal/kvstore`).
  - MPT manager (`internal/mpt`).
  - `OutputPublisher` (`internal/tree`) and configured Output Log `torchwood.Policy`.
- **Recovery Contract**:
  - Enforces 3-phase startup recovery:
    1. Verifies whether persisted trie state matches the committed Output Log watermark (`Output_CP.InputSize`).
    2. Replays uncommitted 256-entry bundles across `[max(MPT_Durable_Size, from), recoveryTarget)` from the local disk cache to align the MPT with zero database writes.
    3. Resumes ingestion without duplicating persisted writes.
- **Durability Invariant**:
  - Storage durability strictly precedes public Output Log commitment (`KV_CP.Size >= Output_CP.InputSize`).
- **Concurrency**:
  - The background polling loop runs synchronously per iteration; catch-up and steady-state ingestion are strictly single-threaded.

### 2.8 Genesis Backfill Lifecycle (Unserved Bootstrap)

When bootstrapping an unserved index from its configured start index `from` (`Output_CP.Size == 0`) against a large Input Log, accumulating every modified `(key, value_root)` pair across `[from, Target_CP.Size)` in memory before a single final commit would exhaust host RAM, while publishing and witnessing an Output Log state commitment entry on every intermediate batch would incur thousands of unnecessary external witness roundtrips before the index is ready to serve.

When `Output_CP.Size == 0`, the Coordinator executes a synchronous **Genesis Backfill** flow:

1. **Gating & Serving Plane Isolation (`Output_CP.Size == 0`)**:
   - Activated automatically if and only if the Output Log has zero state commitment entries (`Output_CP.Size == 0`).
   - Throughout Genesis Backfill, `/readyz` on `--metrics_addr` reports `503 Service Unavailable` (while `/healthz` reports `200 OK`), and public `/keys` and `/values` endpoints remain `503 Service Unavailable` per [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md).

2. **Bounded Coalescing & Synchronous Coarse Checkpointing (Suppressing Intermediate Output Log Appends)**:
   - Multi-tile batches commit inverted `'c'` chunk updates to Pebble without per-batch `fsync` while coalescing modified `(key, value_root)` mappings in a bounded in-memory map and **suppressing intermediate Output Log appends and witness roundtrips**.
   - Whenever the modified-key count or entry threshold is reached, the Coordinator executes a synchronous `Pebble Sync` (advancing `KV_CP.Size`) followed immediately by a synchronous `MPT Commit & Persist` (`Set` + `Snap` + `Sync`, advancing `MPT_Durable_Size` strictly after Pebble `fsync` so `KV_CP.Size >= MPT_Durable_Size` always holds even across power loss), clears the modified-key map, and updates `SafeWatermark` (`max(min(KV_CP.Size, MPT_Durable_Size), from)`) so the tile cache reaper prunes superseded tiles.

3. **Genesis Finalization & Output Log `Entry 0` Publication**:
   - Upon reaching `Target_CP.Size`, the Coordinator executes a final synchronous `Pebble Sync -> MPT Commit & Persist` and publishes Output Log `Entry 0` (`c2sp.org/tlog-vindex-state@v1` binding `mpt-root`, `map-fn`, `from`, and the embedded `<input-log-checkpoint>`), collects witness cosignatures, promotes `Serving_CP`, and permanently transitions to Normal Serving Mode (`Output_CP.Size > 0`).

4. **Standard Phase 2 Crash Recovery**:
   - If the process crashes during Genesis Backfill (`Output_CP.Size == 0` and `version < KV_CP.Size || !exact`), startup reuses standard Phase 2 recovery across `[max(MPT_Durable_Size, from), KV_CP.Size)`—replaying cached 256-entry bundles and reconstructing `value_root` digests from Pebble—with zero special-case backfill recovery machinery before resuming synchronous backfill from `KV_CP.Size` toward `Target_CP.Size`.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Arbitrary Runtime Backfill Mode Switching (Retired)
- **Proposed**: Allowing running daemons to switch dynamically between a bulk ingestion mode ("Backfill Mode") and Normal Serving Mode during live catch-up operations.
- **Empirical Rejection Findings**:
  1. **Read Starvation on Live Nodes**: Shutting down the HTTP read server during live catch-up breaks availability for active readers.
  2. **State Machine Complexity**: Dynamic mode switching introduced edge cases around checkpoint continuity, witness synchronization, and reader lock handoffs.
- **Resolution**: Arbitrary runtime switching was permanently retired. Live serving nodes (`Output_CP.Size > 0`) always operate in Normal Serving Mode. Initial unserved bootstrap (`Output_CP.Size == 0`) uses synchronous **Genesis Backfill** (§2.8), coalescing batches in memory and executing periodic synchronous `Pebble Sync -> MPT Commit & Persist` checkpoints while suppressing intermediate Output Log appends until `Entry 0` is published at `Target_CP.Size`.

### 3.2 Decentralized Subsystem Watermarking vs. Centralized Coordinator Governance
- **Proposed**: Allowing each subsystem to independently determine when to advance watermarks and prune historical state.
- **Theoretical Rejection**: Decentralized state tracking creates race conditions during dirty crashes. Subsystems cannot establish whether sibling components successfully persisted data, leading to either unrecoverable data loss or redundant disk storage.
- **Chosen Design**: Centralized Coordinator governance with a single authoritative progression chain.

### 3.3 Distributed Consensus Orchestration (Raft/Paxos) vs. Single-Host Coordinator
- **Proposed**: Coordinating indexing across a distributed cluster using Raft consensus.
- **Theoretical & Architectural Rejection**:
  - The MPT already requires single-host RAM/mmap locality; clustering the coordinator adds immense operational complexity without solving tree state synchronization.
  - High availability is achieved externally: independent operators run standalone VIndex instances against the shared Input Log.
- **Chosen Design**: Single-process, single-host embedded coordinator.

---

## 4. Verification Gate

All coordinator recovery, genesis backfill, and batch loop invariants are verified via:

```bash
go test -race ./vindex/internal/coordinator/...
```
