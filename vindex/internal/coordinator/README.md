# Coordinator & Lifecycle Engine

`vindex/internal/coordinator` is the single-threaded lifecycle orchestrator and watermark authority for `vindexd`. Worker subsystems (tile ingestion, WASM mapping, KV chunk storage, MPT state commitment, and HTTP serving) expose narrow interfaces and never inspect each other's internal state. The Coordinator drives the end-to-end indexing loop in monotonic order, freezes target checkpoints so high-velocity logs cannot starve batch completion, computes the safe pruning watermark for the local tile cache, and orchestrates network-free Zero-WAL startup recovery and unserved Genesis Backfill.

### Non-Goals
- **No Distributed Consensus**: Operates strictly within a single process on a single host; high availability is achieved externally by running independent VIndex instances against the shared Input Log.
- **No Direct Storage or Trie Mutation**: Coordinates subsystem boundaries and checkpoints without manipulating LSM chunk records or MPT nodes directly.
- **No Arbitrary Runtime Mode Switching**: Runs Normal Serving Mode once the Output Log has at least one state commitment entry (`Output_CP.Size > 0`); Genesis Backfill is used strictly during initial bootstrap when the Output Log is empty (`Output_CP.Size == 0`).

---

## 1. Design

### 1.1 The Master Batch Loop

Each steady-state sync cycle executes six sequential steps across a frozen target range (`>90,000 entries/sec` sustained throughput):

| Step | Phase | Action & Subsystem Transition | Durability Transition |
| :- | :--- | :--- | :--- |
| **1** | **Poll & Freeze** | Polls upstream Input Log `/checkpoint`, verifies the checkpoint against `<input-log-origin>` and the configured Input Log checkpoint policy (such as [C2SP `tlog-policy`](https://c2sp.org/tlog-policy)), checks `Target_CP.Size >= max(prev_Target_CP.Size, from)` and Merkle consistency against `prev_Target_CP`, and persists `Target_CP` to Pebble metadata. | Freezes target sync boundary to prevent moving-goalpost starvation on high-velocity logs. |
| **2** | **Tile Ingestion** | Downloads missing 256-entry bundles across `[max(KV_CP.Size, from), Target_CP.Size)` into the local tile cache ([`internal/ingest`](../ingest/README.md)). | Durably stages verified entry bundles on disk. |
| **3** | **Parallel Mapping** | Streams 256-entry bundles to WASM workers (`internal/wasmhost`), validates un-hashed canonical keys (`1..1024` bytes in `0x21..0x7E`), and resequences batches into multi-tile commit slabs. | In-memory key-index aggregation. |
| **4** | **Storage Commit** | Streams commit slabs into [`internal/kvstore`](../kvstore/README.md) (writing intermediate slabs without disk `fsync` while accumulating modified `(key, value_root)` mappings across the target window, and executing a blocking disk `fsync` barrier on the final slab reaching `Target_CP.Size`). | **Syncs persisted KV watermark (`KV_CP.Size == Target_CP.Size`) and latest verified Input Log checkpoint prior to Output Log publication.** |
| **5** | **Commitment & Promotion** | Predicts candidate `mpt_root` over accumulated modified `(key, value_root)` mappings, appends one 6-line `c2sp.org/tlog-vindex-state@v1` entry (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`) for `Target_CP` to the Output Log, collects witness cosignatures per Output Log `tlog-policy`, verifies Output Log inclusion, retains the signed Input Log checkpoint in Pebble (`m_in_cp:<out_idx>`), and ratchets `Serving_CP` under the exclusive tree lock (< 5ms; see [`internal/tree`](../tree/README.md)). | **Promotes state to Output Log (`Output_CP`) and Serving (`Serving_CP`).** |
| **6** | **Pruning Watermark** | Exposes `SafeWatermark = max(min(KV_CP.Size, MPT_Durable_Size), from)` polled by the background tile cache reaper. | Bounded disk cache garbage collection. |

### 1.2 Checkpoint Progression Chain & Safe Pruning Watermark

| Checkpoint | Log Type | Committed Size | Persistence | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` (`input_size`) | Durable (Pebble metadata) | Frozen upper goalpost for the active sync cycle. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (Pebble LSM) | Tracks indexed `'c'` chunk records, synced (`fsync`) before `Output_CP` appends. |
| **`Output_CP`** | Output Log | `Output_CP.Size` (`output_size`), committing `Output_CP.InputSize` | Durable (Tessera Output Log) | Witnessed state commitment (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`). |
| **`Serving_CP`** | Output Log Entry | `Serving_CP.InputSize` (`input_size`) | Volatile (atomic pointer) | Active snapshot exposed to HTTP lookup readers. |

The checkpoints obey a strict monotonic progression invariant across all execution and crash states:

```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize >= MPT_Durable_Size
```

- **Storage Precedes Commitment (`KV_CP.Size >= Output_CP.InputSize`)**: Pebble must complete a durable `fsync` before the Output Log entry is published, ensuring a crash never leaves a witnessed Output Log entry referencing missing KV chunks.
- **Authoritative Safe Pruning Watermark**: The Coordinator instructs the tile cache reaper to prune only bundles below `SafeWatermark = max(min(KV_CP.Size, MPT_Durable_Size), from)`. Clamping to `from` ensures suffix indices (`from > 0`) never retain or replay pre-`from` tiles, while keeping all 256-entry bundles in `[max(MPT_Durable_Size, from), KV_CP.Size)` cached on local disk until the MPT confirms a durable `fsync`.

### 1.3 Zero-WAL Startup Recovery Sequence

On daemon launch, the HTTP read server gates public lookup endpoints with `503 Service Unavailable` while opening the MPT replays any uncompacted `torchwood/mpt` journal frames on disk. Once journal replay finishes, the Coordinator computes `recoveryTarget = Output_CP.InputSize` when `Output_CP.Size > 0` (or `KV_CP.Size` when `Output_CP.Size == 0`) and executes a network-free 3-phase recovery sequence:

1. **Phase 1: Instant Warm Start (< 5ms after MPT open)**: Entered if and only if `Output_CP.Size > 0`, the MPT's persisted version equals `(Output_CP.InputSize, true)` (`exact == true` and `MPT_Durable_Size == Output_CP.InputSize`), and the trie root matches `mpt-root` in the latest Output Log state commitment entry. Activates `Serving_CP`, initializes watermarks, and **opens the HTTP Read Server immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms after MPT open)**: Entered whenever the persisted MPT lags `recoveryTarget` or is inexact (`version < recoveryTarget || !exact`). Streams missing 256-entry bundles across `[max(MPT_Durable_Size, from), recoveryTarget)` from the local disk tile cache, maps them via `map_bundle` to collect distinct modified canonical keys, reconstructs point-in-time `value_root` digests at `recoveryTarget` from Pebble with **zero database writes**, commits sorted `(key, value_root)` updates to the MPT, and syncs the MPT to disk. When `Output_CP.Size > 0`, asserts that the resulting `mpt_root` matches the latest Output Log entry, activates `Serving_CP`, and **opens the Read Server (< 500ms)**; when `Output_CP.Size == 0`, public endpoints remain `503 Service Unavailable`.
3. **Phase 3: Background Catch-Up & Uncommitted KV Writes**: Resumes forward ingestion from `max(Serving_CP.InputSize, from)` when `Output_CP.Size > 0` (or from `max(KV_CP.Size, from)` in Genesis Backfill when `Output_CP.Size == 0`, including clean restarts mid-backfill where `version == KV_CP.Size && exact == true`) toward `Target_CP.Size`. If a crash occurred in Normal Serving Mode after Pebble synced a batch to disk but before Output Log publication (`KV_CP.Size > max(Serving_CP.InputSize, from)`), re-streaming from `max(Serving_CP.InputSize, from)` skips already-persisted entry indices in Pebble while reconstructing their `value_root` digests so uncommitted batches are published cleanly without duplicate offsets.

### 1.4 Genesis Backfill Lifecycle (`Output_CP.Size == 0`)

When bootstrapping an unserved index from `from` (`Output_CP.Size == 0`) against a large Input Log, accumulating every modified `(key, value_root)` pair across `[from, Target_CP.Size)` in memory before a single final commit would exhaust host RAM, while publishing and witnessing an Output Log entry on every intermediate batch would incur thousands of unnecessary external witness roundtrips before the index is ready to serve. When `Output_CP.Size == 0`, the Coordinator executes synchronous **Genesis Backfill**:

1. **Serving Plane Gating**: Activated automatically if and only if `Output_CP.Size == 0`. Public `/keys` and `/values` endpoints and `/readyz` remain `503 Service Unavailable` throughout backfill.
2. **Bounded Coalescing & Coarse Local Checkpoints**: Multi-tile batches write inverted `'c'` chunk updates to Pebble without per-batch `fsync` while coalescing modified `(key, value_root)` mappings in a bounded in-memory map and **suppressing intermediate Output Log appends and witness roundtrips**. Whenever the modified-key count or entry threshold is reached (or on graceful shutdown), the Coordinator executes a synchronous Pebble disk sync (advancing `KV_CP.Size`) followed immediately by a synchronous MPT commit and disk sync (advancing `MPT_Durable_Size` strictly after Pebble `fsync` so `KV_CP.Size >= MPT_Durable_Size`), clears the modified-key map, and updates `SafeWatermark` so the tile cache reaper prunes superseded tiles.
3. **Genesis Finalization (`Entry 0`)**: Upon reaching `Target_CP.Size`, the Coordinator executes a final synchronous Pebble sync and MPT commit/sync, publishes Output Log `Entry 0` (`c2sp.org/tlog-vindex-state@v1`), collects witness cosignatures, promotes `Serving_CP`, and permanently transitions to Normal Serving Mode (`Output_CP.Size > 0`).
4. **Crash Recovery During Backfill**: If the process crashes during Genesis Backfill (`Output_CP.Size == 0` and `version < KV_CP.Size || !exact`), startup reuses standard Phase 2 recovery across `[max(MPT_Durable_Size, from), KV_CP.Size)` before resuming backfill from `KV_CP.Size` toward `Target_CP.Size`.

---

## 2. Alternatives Considered

### 2.1 Decentralized Subsystem Watermarking vs. Centralized Coordinator Governance
- **Proposed**: Allowing each subsystem to advance watermarks and prune historical state independently.
- **Rejection**: Decentralized tracking creates recovery races on dirty crashes because individual subsystems cannot determine whether downstream components persisted a batch.
- **Chosen Design**: Centralized Coordinator governance with a single monotonic progression chain.

### 2.2 Distributed Consensus Orchestration (Raft/Paxos) vs. Single-Host Coordinator
- **Proposed**: Coordinating indexing across a multi-node cluster via Raft.
- **Rejection**: The MPT requires single-host RAM/mmap locality, and high availability is achieved externally by running independent VIndex operator instances against the shared Input Log.
- **Chosen Design**: Single-process, single-host embedded coordinator.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/coordinator/...
```
