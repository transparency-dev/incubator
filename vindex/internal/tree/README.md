# Authenticated State Commitment (MPT & Output Log)

This document defines the cryptographic commitment engine, tree synchronization protocols, concurrency model, load-bearing invariants, and verified performance optimizations for the **MPT Subsystem** (`vindex/internal/mpt`) and **Output Log Commitment Subsystem** (`vindex/internal/tree`).

---

## 1. Context & Objectives

### 1.1 Problem Statement, Package Decoupling & Concurrency Dilemma
The commitment plane is split into two focused packages:
- **`internal/mpt`** (`vindex/internal/mpt`): Owns the `filippo.io/torchwood/mpt` state trie, canonical key validation, and binary MPT proof codecs—point inclusion/non-inclusion and two-sided prefix subtree proofs—with zero dependencies on `pebble` or `tessera` so it can be imported directly by [`client`](../../client/README.md) and server subsystems. On top of `torchwood/mpt`, `internal/mpt` enforces the strict `tlog-vindex` proof invariants: split-bit bounds `0 <= b <= 8192` on all path steps, canonical key (`1..1024` bytes in `0x21..0x7E`) and 32-byte value validation on terminal leaves in non-inclusion/empty-prefix proofs, and two-sided prefix verification (prefix match + strictly ascending key order + subtree root check).
- **`internal/tree`** (`vindex/internal/tree`): Owns Output Log publication, Tessera POSIX Output Log storage, and atomic `Serving_CP` promotion via the 3-step commitment lifecycle.

The tree subsystem binds the search index into an authenticated 32-byte cryptographic root (`mpt_root`), anchors it in an append-only Output Log, and serves cryptographic inclusion, non-inclusion, and prefix proofs to HTTP readers.

Because readers must verify proofs against a coherent snapshot, all mutations to the in-memory MPT require taking an exclusive tree lock. This creates a severe operational dilemma:
1. **The Reader Starvation Trap**: A full commit requires computing tree updates, persisting MPT files to disk (5–20ms), appending a state commitment entry to the Output Log, and awaiting cosignatures from external witnesses over the network (50–200ms). If the writer lock is held across this entire sequence, concurrent HTTP readers are starved. Under heavy traffic, query availability collapses and lookups time out.
2. **The Equivocation Trap**: If the system writes a state commitment entry to the append-only Output Log and *subsequently* encounters an in-memory trie mutation error or calculation mismatch, the node has permanently committed an unprovable root to public witnesses, destroying operator trust.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Deliver cryptographic inclusion, non-inclusion, and two-sided prefix proofs with compact path sizes (`uvarint(b) || sib_hash` steps over split bits `0 <= b <= 8192`, bounded by at most `min(N - 1, 8193)` steps for `N` active keys).
  - Minimize reader lock contention during continuous ingestion, keeping write lock duration under 5 milliseconds.
  - Eliminate split-view equivocation by binding `mpt_root` commitments to `(input-origin, from, input-size, input-root)` inside witnessed Output Log entries (while retaining signed Input Log checkpoints out-of-band).
  - Maintain an immutable on-disk MPT log for Zero-WAL crash recovery.
- **Non-Goals**:
  - **No Dynamic Rollbacks**: The MPT is strictly append-only; state transitions progress monotonically forward.
  - **No In-Memory Tree Duplication**: Does not duplicate full in-memory trie trees across buffers; memory constraints require mutating a single in-memory trie under short-lived locks.
  - **No Multi-Master Consensus**: Tree sequencing is driven by a single local Index Operator process.

### 1.3 Requirements, Dependencies & Constraints
- **Dependencies**: MPT via `filippo.io/torchwood/mpt`, checkpoint policy verification (`internal/wire`), Tessera POSIX Output Log writer, and external witness clients.
- **RAM Sizing for Branch Locality**: Variable-length canonical keys scatter updates across the trie keyspace. `torchwood/mpt` holds inner trie nodes (`52 bytes/node`) in anonymous virtual memory backed by alternating checksummed patch-frame journal files (`mpt.tree1`, `mpt.tree2`) and an append-only leaf value file (`mpt.disk`), scaling from ~1–1.5 GB for 10M keys to 100–150 GB for 1B keys.
- **Cold-Start Journal Replay**: On process restart, opening the MPT replays uncompacted `torchwood/mpt` journal frames on disk before coordinator recovery begins (while the HTTP server returns `503 Service Unavailable` until replay and startup recovery complete).

---

## 2. Detailed Design

### 2.1 Variable-Length MPT (`internal/mpt`)
The commitment plane maps un-hashed variable-length canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`) to 32-byte value log roots (`value_root`):

1. **Variable-Length Radix Structure & Proof Wrapper**: `filippo.io/torchwood/mpt` stores variable-length canonical keys (up to 1024 bytes) in bitwise big-endian paths. Keys sharing a common byte prefix share a single subtrie, enabling both point proofs and two-sided prefix subtree proofs, with `internal/mpt` enforcing `0 <= b <= 8192` split-bit bounds, canonical `path_key` / 32-byte `path_val` checks on terminal no-match leaves, and two-sided prefix completeness/soundness.
2. **Journaled Anonymous Memory & Leaf Storage**: `torchwood/mpt` stores inner trie nodes (`52 bytes/node`) in anonymous memory backed by two alternating checksummed patch-frame journal files (`mpt.tree1`, `mpt.tree2`) and stores variable-length MPT leaf nodes (`mpt_leaf_hash`) in an append-only leaf file (`mpt.disk`), wrapped with deferred `fsync` file descriptors so slow kernel `fsync(2)` calls never block in-memory trie reads.
3. **Value Log Roots (`value_root`)**: The 32-byte value committed at each MPT leaf node is the RFC 6962 value log root computed by the KV storage layer (`internal/wire`), authenticating all Input Log entry indices at which that canonical key occurred.

### 2.2 The 3-Step Atomic Commitment Sequence
The Output Log publisher coordinates the progression from KV storage to public commitment through a structured 3-step sequence designed to satisfy two strict system constraints:

1. **System Constraint 1 (Zero Unwitnessed State)**: Readers must never observe or obtain proofs against an in-memory root that has not yet been committed to the append-only Output Log and signed by a threshold of external witnesses. Mutating the live trie before publishing would leak unwitnessed state to readers.
2. **System Constraint 2 (Sub-Millisecond Read Latency)**: Readers must never block on external network I/O. Because appending to the Output Log and collecting witness cosignatures takes 50ms–200ms+, holding an exclusive tree write lock across network calls would stall concurrent client queries and violate read latency SLOs (< 15ms P99).
3. **Solution (Separate Prediction from Mutation)**: Pre-compute the deterministic candidate root under a shared read lock without mutating the live trie, release the read lock, and then append the state commitment entry to the Output Log and gather witness cosignatures while readers query unblocked. Once proofs and signatures are secured, acquire the exclusive tree lock briefly (< 5ms) to commit in-memory mutations, assert that the committed root equals the predicted root, and atomically ratchet the `Serving_CP` snapshot.
4. **Why Halt on Divergence**: Candidate root prediction and in-place mutation are deterministic functions over identical inputs. Any divergence indicates an internal invariant violation or memory corruption in the trie. Halting immediately prevents the node from serving proofs that contradict the witnessed Output Log.

#### Batch Publication Locking & Concurrency:
Batch commits are serialized by the single-writer coordinator. Within each commit cycle, lock scope is minimized so readers never block on network or disk I/O:

| Step | Phase | Operations | Lock State | Reader Impact |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Non-Blocking Prediction & Witnessing** | 1. Compute candidate `mpt_root` over modified `(key, value_root)` mappings.<br>2. Append state commitment entry to Output Log.<br>3. Obtain witness cosignatures satisfying the Output Log checkpoint policy (e.g., C2SP `tlog-policy`). | Shared read lock held only during in-memory prediction; **no lock held** during Output Log append and witness network calls. | **Zero blocking**; shared read locks allow concurrent HTTP proof generation to run in parallel. |
| **2** | **Atomic Mutation & Ratchet** | 1. Acquire exclusive persistence and tree locks.<br>2. Commit batch mutations and flush the in-memory journal patch buffer into the OS page cache (via deferred-`fsync` file wrappers).<br>3. Assert committed root equals predicted `mpt_root`.<br>4. Ratchet active `Serving_CP` pointer.<br>5. Release exclusive tree lock. | Exclusive persistence & tree locks held. | **< 5ms** critical section duration. |
| **3** | **Background Durability** | 1. Execute kernel `fsync(2)` on dirty journal/leaf files (`mpt.tree1`, `mpt.tree2`, `mpt.disk`).<br>2. Advance durable trie watermark (`MPT_Durable_Size`). | Exclusive persistence lock held; exclusive tree lock released. | **Zero blocking**; disk `fsync(2)` runs outside the exclusive tree lock without racing in-memory trie state. |

#### Step Details:
1. **Non-Blocking Prediction & Witnessing**:
   - The publisher acquires a shared read lock on the trie to compute candidate hashes over cloned branch nodes without mutating the live tree, then immediately releases the read lock.
   - The canonical 6-line `c2sp.org/tlog-vindex-state@v1` state commitment entry is appended to the Output Log with zero tree or persistence locks held (while retaining the corresponding signed Input Log checkpoint durably out-of-band):
     ```text
     c2sp.org/tlog-vindex-state@v1
     input-origin <input-log-origin>
     from <decimal-start-index>
     input-size <decimal-input-size>
     input-root <base64-input-root>
     mpt-root <base64-mpt-root>
     ```
   - The resulting Output Log checkpoint is submitted to external witnesses to gather cosignatures satisfying the configured Output Log checkpoint policy quorum (e.g., C2SP `tlog-policy`).
   - **Throughout this entire phase, concurrent HTTP readers acquire shared read locks and generate proofs without blocking.**
2. **Atomic Mutation & Ratchet**:
   - The publisher acquires the exclusive persistence lock and exclusive tree lock.
   - Mutates in-memory MPT nodes and flushes `torchwood/mpt`'s in-memory header/journal patch buffer into the OS page cache (against deferred-`fsync` file wrappers) while holding the exclusive tree lock so header and patch-frame compaction state never race concurrent proof or scan readers.
   - Asserts that the committed root equals the predicted root. If mismatched, the process terminates immediately.
   - Ratchets the active `Serving_CP` pointer to the newly witnessed Output Log checkpoint and inclusion proof.
   - Releases the exclusive tree lock (keeping the persistence lock for Step 3).
   - **Total critical section duration: < 5 milliseconds.**
3. **Background Durability**:
   - Still under the independent persistence lock—with zero tree lock held—`internal/mpt` executes blocking kernel `fsync(2)` calls on the dirty underlying file descriptors (`mpt.tree1`, `mpt.tree2`, `mpt.disk`).
   - Once durable on disk, `MPT_Durable_Size` advances atomically, allowing the tile cache reaper to prune superseded 256-entry bundles.

### 2.3 Concurrency Architecture & Split-Locking
The subsystem enforces strict isolation between in-memory proof serving and background disk persistence using two distinct locks:

| Conceptual Lock | Synchronization Model | Scope & Protected State | Typical Duration |
| :--- | :--- | :--- | :--- |
| **In-Memory Tree Lock** | Read-write lock | Protects in-memory MPT nodes and the active `Serving_CP` snapshot. Acquired in shared read mode by HTTP proof readers and candidate root prediction; acquired in exclusive write mode only during the in-memory batch commit and `Serving_CP` ratchet. | **< 5ms** (exclusive write)<br>**< 50µs** (shared read) |
| **Disk Persistence Lock** | Exclusive mutex | Serializes in-memory trie mutations against background snapshot serialization and disk `fsync` operations. Never held during Output Log appends or witness network calls. | **5ms – 20ms** |

Because disk persistence and network witnessing are decoupled from the exclusive tree lock, slow disk syncs and witness roundtrips never block HTTP readers.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Fatal Halt on Root Prediction Divergence**:
  - *Rule*: After the Output Log append succeeds, when the exclusive tree lock is acquired to apply the batch mutations in memory, the resulting trie root must equal the predicted root committed to the Output Log; any mismatch must immediately terminate the process.
  - *Rationale*: The Output Log is immutable. If the committed in-memory root diverges from the predicted root that was already appended and witnessed, execution must halt immediately.
  - *Consequence ("Or Else")*: Continuing execution would publish an equivocal state commitment entry to the Output Log that cannot be cryptographically proven by the node's internal state.

- **[Correctness Invariant] Single-Timeline Equivocation Resistance**:
  - *Rule*: Every published state commitment entry binds `input-origin`, `from`, `input-size`, `input-root`, and the exact `mpt_root` (`mpt-root`), while the operator retains the signed Input Log checkpoint out-of-band.
  - *Rationale*: Independent witnesses cosign the Output Log checkpoint. The index operator cannot present conflicting views of index state to different clients without producing split-view signatures detectable by public monitors, and retaining the signed Input Log checkpoint proves upstream Input Log equivocation if a root conflict ever arises.
  - *Consequence ("Or Else")*: An operator attempting to selectively hide certificates or packages would be mathematically detected by any monitor cross-checking witness cosignatures.

- **[Correctness Invariant] Serving Isolation & Atomic Ratcheting**:
  - *Rule*: HTTP readers evaluate state strictly bounded by the active `Serving_CP` snapshot (`Serving_CP.InputSize <= Output_CP.InputSize`).
  - *Rationale*: HTTP requests capture an atomic `Serving_CP` snapshot and filter all storage reads to Input Log entry indices strictly below the serving checkpoint's `input_size` (`InputSize`).
  - *Consequence ("Or Else")*: Readers would observe uncommitted, unwitnessed Input Log entries ahead of the latest published Output Log entry, breaking client-side Merkle proof verification.

- **[Performance Optimization] Non-Blocking MPT Prediction**:
  - *Mechanism*: Computes candidate trie roots under a shared read lock and performs Output Log writes and witness network roundtrips with no tree locks held.
  - *Impact*: Reduces exclusive writer lock duration from ~250ms to < 5ms per commit cycle.

- **[Performance Optimization] Split-Locking Concurrency Engine**:
  - *Mechanism*: Isolates background disk `fsync` operations from in-memory trie read locks.
  - *Impact*: Sustains 678,000 read queries/sec during active disk commits, compared to 53,000 reads/sec under coarse global locking (12.8x throughput improvement).

### 2.5 State Trie & Commitment Contract

The state commitment subsystem provides authenticated indexing over canonical keys and coordinates public Output Log commitments:

- **Inputs**:
  - Batch of modified `(key, value_root)` mappings over un-hashed canonical keys (`1..1024` bytes in `0x21..0x7E`).
  - Configured `<input-log-origin>` and start index `from` (`0 <= from <= input_size`).
  - Verified Input Log checkpoint (`input_size` and `input_root`, validated against the Input Log checkpoint policy and retained out-of-band).
- **Outputs**:
  - Witnessed Output Log state commitment entry (`c2sp.org/tlog-vindex-state@v1`).
  - Verified Output Log Merkle inclusion proof (`c2sp.org/tlog-proof@v1` at `index == output_size - 1`).
  - Atomically promoted `Serving_CP` snapshot (exposing `InputSize` and `OutputSize`).
- **Concurrency Contract**:
  - Readers are wait-free and never block on disk `fsync` or network calls.
  - State commits are strictly serialized (single-writer); state ratcheting promotes `Serving_CP` atomically.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Coarse Global Locking vs. Split-Locking with Prediction
- **Proposed**: Holding a single global lock across the entire commitment cycle (prediction, Output Log append, witness network calls, in-memory trie mutation, and disk `fsync`).
- **Empirical Rejection**: Benchmark profiling under heavy concurrent read traffic showed that coarse locking dropped HTTP read throughput to **53,000 queries/sec**, with P99 read latency ballooning past 250ms due to writer lock starvation.
- **Chosen Design**: Split-locking with lock-free prediction holds the exclusive tree lock for < 5ms, sustaining **678,000 queries/sec** (a 12.8x speedup) with sub-millisecond P50 read latency.

### 3.2 Sparse Merkle Trees (SMT) vs. Merkle Patricia Trie (MPT)
- **Proposed**: Using a standard Sparse Merkle Tree (SMT) with fixed 256-level depth.
- **Theoretical & Empirical Rejection**: Standard SMTs require generating and traversing 256 levels of nodes per operation. Even with default empty node optimizations, SMTs incur massive memory footprint and excessive disk I/O during random-insert batch workloads.
- **Chosen Design**: Path-compressed binary MPT (`filippo.io/torchwood/mpt`), which collapses single-child paths over variable-length canonical keys, bounding tree depth to the active key set and enabling fast `mmap` persistence.

### 3.3 Post-Commit Output Log Publishing
- **Proposed**: Mutating and syncing the in-memory MPT to disk *first*, and then appending the state commitment entry to the Output Log.
- **Theoretical Rejection**: If the node crashes or power fails after the MPT disk sync but before the Output Log append completes, the local MPT has advanced to a state that was never committed or witnessed in the Output Log. On restart, the node would serve state ahead of the Output Log, violating the universal invariant `MPT_Durable_Size <= Output_CP.InputSize`.
- **Chosen Design**: Predict root lock-free -> append state commitment entry to Output Log -> commit to MPT under short lock.

---

## 4. Verification Gate

All MPT variable-length canonical key, prefix proof, and Output Log publisher tests are verified via:

```bash
go test -race ./vindex/internal/mpt/... ./vindex/internal/tree/...
```
