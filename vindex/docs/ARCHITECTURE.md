# Verifiable Index (VIndex) Architecture

This document defines the high-level system architecture, checkpoint promotion invariants, crash consistency model, auditing boundaries, and architectural trade-offs for **VIndex**.

For the problem statement and ecosystem use cases, see the [VIndex Overview](../README.md) and [Verifiable Index Applications](./APPLICATIONS.md). For the normative wire formats and cryptographic verification rules, see the [C2SP `tlog-vindex` Specification](./tlog-vindex.md).

---

## 1. Architectural Overview

### 1.1 The Map Sandwich

VIndex operates as a **Map Sandwich** bounded between two append-only transparency logs:

- **Input Log** (_source of truth_): The existing append-only transparency log whose entries are being indexed.
- **Indexer & Serving Node**: A single-host process that ingests verified Input Log entries, extracts canonical keys via a deterministic mapping function, maintains per-key value logs and an authenticated Merkle Patricia Trie (MPT), and serves HTTP lookup proofs.
- **Witnessed Output Log** (_state anchor_): A [tiled transparency log](https://c2sp.org/tlog-tiles) recording `c2sp.org/tlog-vindex-state@v1` index state commitments (`input-origin`, `from`, `input-size`, `input-root`, and `mpt-root`), cosigned by independent witnesses.

### 1.2 Pipeline Stages & System Roles

Data flows sequentially through five stages governed by a central coordinator, verified externally by lookup clients and independent auditors:

| Stage / Role                                                 | Responsibility                                                                                                                                                                                                                          |
| :----------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**1. Ingest & Bundle Cache**](../internal/ingest/README.md) | Polls Input Log checkpoints, verifies checkpoint policies and Merkle consistency, downloads and authenticates entry bundles into a local disk cache, and prunes cached bundles once downstream storage and MPT state are durable.       |
| [**2. Sandboxed Mapping**](../mapfn/README.md)               | Executes the index's deterministic mapping function inside a zero-I/O WebAssembly sandbox pool, validating emitted [canonical keys](./tlog-vindex.md#canonical-keys) and resequencing mapped batches into strict Input Log entry order. |
| [**3. Value-Log Storage**](../internal/kvstore/README.md)    | Partitions each key's matching Input Log entry indices into append-only chunks in an embedded LSM key-value store, precomputing RFC 6962 compact range hashes and syncing updates to disk at target checkpoint barriers.                |
| [**4. State Commitment**](../internal/tree/README.md)        | Predicts the candidate `mpt_root` over un-hashed canonical keys under a shared read lock, appends the state commitment entry to the Output Log, collects witness cosignatures, and atomically swaps the active serving snapshot.        |
| [**5. Read Serving**](../internal/server/README.md)          | Serves `<index-url>/keys` (exact key and bounded prefix proofs from the in-memory MPT) and `<index-url>/values` (lock-free backward value-log pagination from the KV store), strictly isolated to witnessed snapshots.                  |
| [**Coordinator**](../internal/coordinator/README.md)         | Freezes target Input Log checkpoints, drives stages 1–4 in monotonic order, governs safe cache-pruning watermarks, and runs Zero-WAL startup recovery.                                                                                  |
| [**Lookup Client**](../client/README.md)                     | Queries `/keys` and `/values` and verifies Output Log inclusion proofs, MPT inclusion/non-inclusion/prefix proofs, and value-log compact range roots offline against an Output Log checkpoint verification policy.                      |
| [**Independent Auditor**](../internal/auditor/README.md)     | Tails the Output Log from entry `0`, verifies Input Log and Output Log checkpoints, independently replays Input Log entries from `from` through the mapping function, and halts and alerts if any published `mpt-root` diverges.        |

---

## 2. Checkpoint Promotion & Concurrency

### 2.1 Checkpoint Promotion & Monotonic Ratcheting

Earlier pipeline stages ingest and index new Input Log entries asynchronously while the HTTP serving path continues serving lookups against the most recently witnessed state. Progress across stages is governed by four checkpoints:

| Checkpoint       | Log Scope                                                               | Role                                                                                                                                    | Advancement                                                                                                                                      | Persistence                         |
| :--------------- | :---------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------- |
| **`Target_CP`**  | Input Log (`Target_CP.Size`)                                            | Frozen upper bound (`>= from`) for the current sync cycle; prevents moving-goalpost starvation.                                         | Upstream poll, Input Log checkpoint policy check, & Merkle consistency proof                                                                     | Durable (KV metadata)               |
| **`KV_CP`**      | Input Log (`KV_CP.Size`)                                                | Marks that all value-log chunks covering `[from, KV_CP.Size)` are durably persisted on disk.                                            | Atomic watermark write and `fsync` once _all_ value-log entries for `Target_CP` are written (or at coarse periodic barriers in Genesis Backfill) | Durable (KV store `fsync`)          |
| **`Output_CP`**  | Output Log (`Output_CP.Size` entries, committing `Output_CP.InputSize`) | Publicly commits `(input-origin, from, input-size, input-root, mpt-root)`, while retaining the signed Input Log checkpoint out-of-band. | Append `c2sp.org/tlog-vindex-state@v1` entry & collect witness cosignatures                                                                      | Durable (Output Log storage)        |
| **`Serving_CP`** | Output Log Entry (`Serving_CP.InputSize`)                               | Snapshot exposed to HTTP lookup clients.                                                                                                | MPT commit & pointer swap under brief writer lock                                                                                                | Volatile (in-memory atomic pointer) |

Note the two tree sizes on `Output_CP`: `Output_CP.Size` (`output_size`) is the number of state commitment entries in the Output Log itself, whereas `Output_CP.InputSize` (`input_size`) is the Input Log tree size committed inside the latest Output Log entry.

All four checkpoints obey a strict monotonic invariant:

```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```

- `Target_CP.Size >= KV_CP.Size`: Intermediate batches write value-log chunk updates into the KV store without advancing `KV_CP` or forcing an `fsync`; in normal serving, `KV_CP` holds at the prior checkpoint until _all_ entries up to `Target_CP.Size` have been written, then ratchets atomically to `Target_CP.Size` (during Genesis Backfill, [§4.3](#43-genesis-backfill-unserved-bootstrap), `KV_CP` also advances at coarse intermediate barriers).
- `KV_CP.Size >= Output_CP.InputSize`: Value-log storage is synced to disk _before_ an Output Log commitment is published.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Output Log publication and external witness cosigning complete before the serving pointer advances.

### 2.2 Pipeline Concurrency & Backpressure

VIndex balances three competing pressures on a single host:

1. **Asymmetric Compute Allocation**: Entry-bundle mapping is embarrassingly parallel across worker sandboxes, whereas downstream KV batching and LSM memtable commits have a serial tail. Scaling both stages equally across all cores causes thread preemption and starves read serving and background compactions, so mapping scales wide while value-log indexing uses bounded concurrency.
2. **Bounded Inter-Stage Buffers**: Bounded channels absorb transient flush jitter between parallel mapping and sequential storage commits without letting queued batches accumulate into multi-gigabyte Go heap graphs.
3. **Self-Regulating Backpressure**: When disk flushes or compactions slow downstream commits, bounded channels fill and park upstream mapping workers, yielding CPU cores to storage and read serving until the commit queue drains.

---

## 3. Pipeline Mechanics & Invariants

### 3.1 Stage 1: Ingest & Bundle Cache

The ingestion layer polls the Input Log for signed checkpoints, verifies them against the configured Input Log checkpoint policy and prior checkpoints, and downloads authenticated entry bundles into a local disk cache (supporting [C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles), [C2SP `static-ct-api`](https://c2sp.org/static-ct-api), and user-defined log adapters).

- **Target Checkpoint Verification**: Every polled Input Log checkpoint must satisfy the Input Log checkpoint verification policy, advance monotonically (`>= max(prev_Target_CP.Size, from)`), and pass Merkle consistency verification before `Target_CP` advances. Operators retain the signed Input Log checkpoint corresponding to each published Output Log entry out-of-band so Input Log equivocation can be proven if a conflict ever arises.
- **Recovery-Safe Cache Retention**: Verified entry bundles remain in the local disk cache until _both_ the KV store (`KV_CP.Size`) and the on-disk MPT (`MPT_Durable_Size`) have durably synced past them. An asynchronous reaper can be configured to prune bundles strictly below that safe watermark, bounding disk usage while guaranteeing local crash recovery without network fetches.

### 3.2 Stage 2: Sandboxed Mapping

Ecosystem authors express mapping logic as a deterministic function from raw Input Log entry bytes to canonical keys, compiled to WebAssembly and executed by a pool of zero-I/O sandboxes:

- **Bundled Execution**: Rather than crossing the host-guest boundary once per entry, workers pass entire entry bundles in shared linear memory per invocation, amortizing boundary overhead while streaming emitted keys directly into pre-allocated slabs.
- **Deterministic Halt on Fault or Invalid Key**: Sandboxes run with no filesystem, network, or clock nondeterminism. Any guest trap, panic, or emitted key outside [`tlog-vindex` canonical key bounds](./tlog-vindex.md#canonical-keys) halts indexing immediately rather than silently dropping keys and diverging from auditors.
- **Chronological Resequencing**: Parallel workers finish bundles out of order; an in-memory resequencer restores strict ascending `entry_idx` order before batches reach storage.

### 3.3 Stage 3: Value-Log Storage & Hybrid Keying

VIndex separates trie structure from per-key occurrence lists using a **hybrid keying model**:

- The **MPT** indexes **un-hashed variable-length canonical keys** directly so keys sharing a string prefix form a contiguous subtrie for [two-sided prefix proofs](./tlog-vindex.md#verifying-a-keys-response).
- The **KV store** indexes per-key value-log chunks by fixed-size **`SHA-256(key)` digests** computed on the host, keeping LSM keys uniform and decoupled from variable canonical key lengths.

Within the KV store, each key's matching `entry_idx` sequence is partitioned into fixed-window chunks ordered newest-first under `SHA-256(key)`. Each chunk stores the RFC 6962 compact range hashes of all older occurrences preceding that chunk alongside compact relative offsets within the window:

- **Synchronous Persistence Barrier**: Intermediate batches write chunk updates without advancing `KV_CP`; once all entries up to `Target_CP.Size` have been written, all modified chunks and `KV_CP = Target_CP` are synced to disk (`fsync`) together before Stage 4 publishes a new Output Log commitment (`KV_CP.Size >= Output_CP.InputSize`).
- **Snapshot-Bounded Reads**: Point-in-time `value_root` reconstruction and `/values` queries ignore any entries at or above the requested `before` / `Serving_CP.InputSize` bound, isolating readers and crash recovery from uncommitted batches ahead of the serving snapshot.

### 3.4 Stage 4: State Commitment

Once `KV_CP` is durable at `Target_CP.Size`, the commitment layer anchors the new `mpt_root` in the Output Log through a three-step handoff:

1. **Non-Blocking Root Prediction**: Under a shared read lock on the MPT, the commitment layer predicts the candidate `mpt_root` from the sorted `(key, value_root)` changes without mutating the live trie or blocking concurrent `/keys` queries.
2. **Output Log Append & Witnessing**: The 6-line `c2sp.org/tlog-vindex-state@v1` entry (`input-origin`, `from`, `input-size`, `input-root`, and predicted `mpt-root`) is appended to the Output Log and cosigned by witnesses according to the Output Log checkpoint policy.
3. **Atomic State Ratchet & Background Persistence**: Under a brief exclusive tree lock, the commitment layer applies the `(key, value_root)` mutations to the in-memory MPT, asserts that the resulting root equals the predicted `mpt-root` (halting fatally on any mismatch), and swaps `Serving_CP`. Flushing updated MPT patch frames to disk (`fsync`) runs outside the exclusive tree lock so read serving never blocks on disk I/O.

### 3.5 Stage 5: Read Serving

The HTTP server exposes `<index-url>/keys` and `<index-url>/values` (and, when co-hosted, Output Log `/checkpoint` and `/tile/...` paths; non-protocol paths such as an optional human-facing browser UI remain outside the protocol):

- **Key Discovery (`GET <index-url>/keys`)**: Acquires a short shared read lock on the in-memory MPT, generates an exact key proof or bounded prefix subtree proof against `Serving_CP`, and pairs it with the `c2sp.org/tlog-proof@v1` inclusion proof to the witnessed Output Log checkpoint. Prefix queries are guarded by optional application-specific prefix policies (e.g., rejecting bare public suffixes) and matched-key limits.
- **Lock-Free Value Pagination (`GET <index-url>/values`)**: Hashes `key` with `SHA-256` and reads newest-first chunks from the KV store with **zero MPT lock acquisition**, bounded by `before <= Serving_CP.InputSize`. Clients verify the newest page against `value_root` from `/keys` and inductively fold the returned compact range hashes to verify older pages backward without consistency proofs.

---

## 4. Crash Consistency & Lifecycle

### 4.1 Universal Crash Invariant

Because KV storage syncs to disk before Output Log publication (`KV_CP.Size >= Output_CP.InputSize`), recovery never encounters a witnessed Output Log commitment whose value-log chunks are missing from local storage. If a crash occurs after `KV_CP` syncs but before Output Log publication (`KV_CP.Size > Output_CP.InputSize`), snapshot-bounded reads reconstruct `value_root` digests strictly at `Output_CP.InputSize` while the next sync cycle replays the cached window `[Output_CP.InputSize, KV_CP.Size)` to publish its state commitment without duplicating persisted KV entries.

### 4.2 Zero-WAL Startup Recovery

While the MPT opens and replays any uncompacted on-disk patch frames, lookup endpoints return `503 Service Unavailable`. Once open, the coordinator sets `recoveryTarget` to `Output_CP.InputSize` (or `KV_CP.Size` if crashing during initial bootstrap when `Output_CP.Size == 0`) and runs three phases:

1. **Instant Warm Start**: If `Output_CP.Size > 0` and the persisted MPT snapshot is exact at `Output_CP.InputSize` with matching `mpt-root`, `Serving_CP` activates immediately.
2. **Local Bundle Replay**: If the on-disk MPT lags `recoveryTarget` or is inexact after an unclean crash, the coordinator streams `[max(MPT_Durable_Size, from), recoveryTarget)` from the **local bundle cache** (retained above the safe pruning watermark, requiring zero network egress), runs mapping to identify modified canonical keys, reconstructs their `value_root` digests at `recoveryTarget` from the KV store with zero KV writes, updates and syncs the MPT, verifies `mpt-root` against `Output_CP`, and opens read serving.
3. **Forward Catch-Up**: Resumes normal batch ingestion from `max(Serving_CP.InputSize, from)` toward `Target_CP.Size`.

### 4.3 Genesis Backfill (Unserved Bootstrap)

When bootstrapping a new index from `from` (`Output_CP.Size == 0`) against a large existing Input Log, accumulating all modified keys in RAM for a single commit would exhaust memory, while publishing and witnessing an Output Log entry on every intermediate batch would incur thousands of unnecessary witness round-trips before the index is ready to serve.

While `Output_CP.Size == 0`, lookup endpoints remain `503 Service Unavailable` and the coordinator suppresses intermediate Output Log appends. Batches write chunks to the KV store and coalesce modified `(key, value_root)` pairs in bounded memory, periodically executing a synchronous `KV Sync -> MPT Commit & Sync` coarse checkpoint (maintaining `KV_CP.Size >= MPT_Durable_Size` and advancing the cache-pruning watermark). Once `Target_CP.Size` is reached, the coordinator publishes and witnesses Output Log `Entry 0`, activates `Serving_CP`, and permanently transitions to normal serving (`Output_CP.Size > 0`).

---

## 5. Verification & Auditing Boundaries

VIndex separates lightweight client query checks from full-log construction verification:

1. **Lookup Client Verification**: Authenticates individual `/keys` and `/values` responses offline against `<output-log-origin>`, the client's Output Log checkpoint verification policy, `<input-log-origin>`, and the caller's required `from` coverage horizon, proving soundness and completeness relative to the witnessed `mpt-root` without trusting the HTTP server.
2. **Full-Log Independent Auditor**: Continuously tails the Output Log from entry `0`, verifies Output Log and Input Log checkpoint policies and Merkle consistency, downloads and authenticates Input Log entries starting from `from` (`[from, input_size)`), independently executes the mapping function, and verifies every published `mpt-root`. On any `mpt-root` mismatch or protocol violation, the auditor halts and alerts without advancing past its last verified commitment.

---

## 6. Operational Characteristics

- **Memory Residency & Storage Layout**: The MPT (`filippo.io/torchwood/mpt`) holds compact inner trie nodes in off-heap anonymous virtual memory (avoiding Go garbage-collector scan overhead) backed by alternating checksummed snapshot/patch-frame files and an on-disk leaf file, while per-key occurrence history lives on disk in the LSM KV store. Host RAM scales primarily with the number of distinct canonical keys in the MPT rather than total Input Log entries.
- **Disk I/O Isolation**: On high-throughput deployments, placing MPT snapshot/patch files and the LSM KV store (plus bundle cache) on separate NVMe volumes isolates sequential trie compaction writes from LSM memtable flushes and compactions.
- **Authoritative Output Log vs. Derived Index State**: The Output Log (and its signing key) is authoritative for witness continuity: because historical Output Log entries record runtime sync boundaries (`input-size`), losing the Output Log breaks Merkle consistency with previously witnessed checkpoints and requires standing up a new Output Log origin from scratch (so production deployments back the Output Log with durable storage). By contrast, the local KV store, MPT files, and bundle cache are purely derived state. Provided the Output Log survives, lost local index state can be rebuilt by re-indexing Input Log entries from `from` up to `Output_CP.InputSize`, verifying that the reconstructed `mpt_root` matches `Output_CP`, and resuming append-only operation.

---

## 7. Architectural Alternatives Considered

### 7.1 Dynamic Runtime Backfill Mode Switching

- **Proposed**: Switching live serving nodes dynamically into an unserved bulk "backfill mode" whenever ingestion lag spiked.
- **Why Rejected**: Dropping HTTP read availability during catch-up starved lookup clients and complicated checkpoint and witness handoffs. Initial bootstrap uses Genesis Backfill strictly while `Output_CP.Size == 0`; once serving begins, nodes stay permanently in normal serving mode.

### 7.2 Storage Write-Ahead Log Staging

- **Proposed**: Writing mapped `(key, entry_idx)` pairs into a staging log inside the KV store before a background compactor folded them into value-log chunks.
- **Why Rejected**: Doubled disk write amplification, triggered heavy LSM compaction churn, and caused severe tail read-latency spikes compared to computing compact range updates in memory and writing inverted chunks directly.

### 7.3 Sparse Merkle Trees & Verkle Trees

- **Proposed**: Storing key-to-`value_root` state in a 256-level Sparse Merkle Tree (SMT) or polynomial-commitment Verkle tree.
- **Why Rejected**: Full-depth 256-bit SMTs incur high node fanout and hashing overhead (and hash keys, losing native byte-prefix subtrees), while Verkle polynomial commitments are CPU-prohibitive at high ingestion rates. Path-compressed binary MPTs keep expected proof depth proportional to actual key branching while preserving un-hashed prefix subtrees.

### 7.4 Distributed Key-Value Databases

- **Proposed**: Storing value-log chunks in an external distributed database (such as Spanner, Bigtable, or Cassandra).
- **Why Rejected**: The in-memory MPT already anchors each indexer to a single host; adding network RPC hops to storage degrades bulk ingestion throughput without providing multi-node MPT consensus. High availability is achieved by running independent VIndex instances over the shared Input Log.
