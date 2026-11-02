# Authenticated State Commitment (MPT & Output Log)

The state commitment subsystem binds every present canonical key's Value Log root (`value_root`) into a path-compressed binary Merkle Patricia Trie (`mpt_root`), publishes state commitments to an append-only Output Log cosigned by external witnesses, and generates point inclusion, non-inclusion, and prefix proofs for HTTP lookup clients. By predicting candidate roots under a shared read lock before publishing and witnessing, and isolating background disk `fsync` calls from in-memory trie reads, concurrent HTTP queries never block on network witnessing or disk persistence.

### Non-Goals
- **No Dynamic Rollbacks**: The trie and Output Log are strictly append-only; state transitions progress monotonically forward.
- **No Full In-Memory Trie Duplication**: Memory constraints require mutating a single in-memory trie under short-lived locks (< 5ms) rather than maintaining duplicate multi-gigabyte trie copies.
- **No Multi-Master Sequencing**: State commitment sequencing is driven by a single local Index Operator process.

---

## 1. Design

### 1.1 Package Decoupling & Variable-Length MPT (`internal/mpt` & `internal/tree`)

The commitment plane is split into two internal packages:
- **`vindex/internal/mpt`**: Wraps [`filippo.io/torchwood/mpt`](https://pkg.go.dev/filippo.io/torchwood/mpt) with canonical key validation and binary MPT proof codecs (`uvarint(b) || sib_hash` path steps over split bits `0 <= b <= 8192`, bounded by at most `min(N - 1, 8193)` steps for `N` active keys) with zero dependencies on `pebble` or `tessera` so it can be imported directly by [`client`](../../client/README.md) and [`internal/server`](../server/README.md). On top of `torchwood/mpt`, `internal/mpt` enforces split-bit bounds `0 <= b <= 8192`, canonical key (`1..1024` bytes in `0x21..0x7E`) and 32-byte value validation on terminal no-match leaves, and [two-sided prefix verification](../../docs/tlog-vindex.md#two-sided-prefix-verification): checking `HasPrefix(key, prefix)` on every returned key ensures the server did not substitute a wider ancestor subtree containing keys outside `prefix`, while checking `b_1 < 8 * len(prefix)` on the first ancestor step, reconstructing the subtree root over the strictly ascending `(key, value_root)` pairs, and folding the ancestor path to `mpt_root` ensures no matching keys inside `prefix` were omitted.
- **`vindex/internal/tree`**: Coordinates candidate root prediction, Tessera POSIX Output Log publication, witness quorum collection, and atomic `Serving_CP` snapshot promotion.

`torchwood/mpt` stores variable-length canonical keys in bitwise big-endian paths so keys sharing a byte prefix share a single subtrie. Inner trie nodes (`52 bytes/node`) live in anonymous virtual memory (~1–1.5 GB RAM for 10M keys, 100–150 GB for 1B keys) backed by alternating checksummed patch-frame journal files (`mpt.tree1`, `mpt.tree2`), while variable-length leaf nodes (`mpt_leaf_hash`) append to `mpt.disk`. Underlying file descriptors are wrapped with deferred-`fsync` handles so kernel `fsync(2)` calls never block in-memory reads; on process restart, opening the MPT replays uncompacted journal frames on disk before coordinator recovery begins (while the HTTP server returns `503 Service Unavailable`).

### 1.2 The 3-Step Atomic Commitment Sequence & Split-Locking

A commit cycle must satisfy two simultaneous invariants:
1. **Zero Unwitnessed State**: HTTP readers must never observe or obtain proofs against an `mpt_root` that has not yet been committed to the Output Log and cosigned by witnesses (`Serving_CP.InputSize <= Output_CP.InputSize`).
2. **Sub-Millisecond Read Latency**: Appending to the Output Log and collecting witness cosignatures takes 50–200ms+, and syncing journal/leaf files to disk takes 5–20ms. Holding an exclusive tree lock across network and disk I/O would starve HTTP readers.

To satisfy both, the subsystem separates in-memory trie access from disk persistence using two independent locks and executes each commit in three steps:

| Conceptual Lock | Synchronization Model | Scope & Protected State | Typical Duration |
| :--- | :--- | :--- | :--- |
| **In-Memory Tree Lock** | Read-write lock | Protects in-memory MPT nodes and the active `Serving_CP` snapshot. Shared read mode for HTTP proof generation and Step 1 root prediction; exclusive write mode only during Step 2 in-memory mutation and `Serving_CP` ratchet. | **< 5ms** (exclusive write)<br>**< 50µs** (shared read) |
| **Disk Persistence Lock** | Exclusive mutex | Serializes Step 2 in-memory journal buffer flushes against Step 3 background disk `fsync(2)` calls. Never held during Output Log appends or witness network calls. | **5ms – 20ms** |

| Step | Phase | Operations | Lock State & Reader Impact |
| :--- | :--- | :--- | :--- |
| **1** | **Non-Blocking Prediction & Witnessing** | Pre-sorts the batch's modified `(key, value_root)` mappings outside the lock (reused in Step 2), acquires a shared read lock on the trie to compute the candidate `mpt_root` over cloned branch nodes, and immediately releases the read lock. Appends the 6-line `c2sp.org/tlog-vindex-state@v1` entry (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`) to the Output Log (retaining the signed Input Log checkpoint durably out-of-band) and collects witness cosignatures satisfying the Output Log checkpoint policy (such as [C2SP `tlog-policy`](https://c2sp.org/tlog-policy)) with **no tree or persistence locks held**. | **Zero reader blocking**; concurrent HTTP `/keys` proof generation runs in parallel under shared read locks. |
| **2** | **Atomic Mutation & Ratchet** | Acquires the exclusive persistence lock and exclusive tree lock. Mutates in-memory MPT nodes and flushes `torchwood/mpt`'s in-memory header/journal patch buffer into the OS page cache (against deferred-`fsync` file wrappers) so header and patch-frame compaction state never race concurrent readers. **Asserts that the committed root equals the predicted `mpt_root`** (terminating the process immediately on any mismatch rather than serving proofs that contradict the witnessed Output Log), ratchets the active `Serving_CP` pointer to the newly witnessed Output Log checkpoint and inclusion proof (`index == output_size - 1`), and releases the exclusive tree lock. | **< 5ms** exclusive write critical section. |
| **3** | **Background Durability** | Still holding only the persistence lock (with the exclusive tree lock released), executes blocking kernel `fsync(2)` calls on the dirty underlying file descriptors (`mpt.tree1`, `mpt.tree2`, `mpt.disk`) and atomically advances `MPT_Durable_Size` so the tile cache reaper can prune superseded 256-entry bundles. | **Zero reader blocking**; disk `fsync(2)` runs outside the tree lock. |

---

## 2. Alternatives Considered

### 2.1 Coarse Global Locking vs. Split-Locking with Prediction
- **Proposed**: Holding a single global lock across prediction, Output Log append, witness network calls, in-memory trie mutation, and disk `fsync`.
- **Rejection**: Under concurrent read load, coarse locking dropped HTTP read throughput to **53,000 queries/sec** with P99 read latency exceeding 250ms due to writer lock starvation.
- **Chosen Design**: Split-locking with lock-free prediction holds the exclusive tree lock for < 5ms, sustaining **678,000 queries/sec** (a 12.8x speedup) with sub-millisecond P50 read latency.

### 2.2 Sparse Merkle Trees (SMT) vs. Merkle Patricia Trie (MPT)
- **Proposed**: Using a fixed 256-level Sparse Merkle Tree (SMT).
- **Rejection**: Traversing 256 levels per key incurs large memory and disk I/O amplification during random-insert batch workloads.
- **Chosen Design**: Path-compressed binary MPT (`filippo.io/torchwood/mpt`) over variable-length canonical keys, collapsing single-child paths to bound depth to the active key set.

### 2.3 Post-Commit Output Log Publishing
- **Proposed**: Mutating and syncing the in-memory MPT to disk *first*, and then appending the state commitment entry to the Output Log.
- **Rejection**: A crash after MPT disk sync but before Output Log publication advances persisted trie state ahead of the Output Log (`MPT_Durable_Size > Output_CP.InputSize`), causing a restarted node to serve unwitnessed state.
- **Chosen Design**: Predict root under shared read lock -> publish and witness in the Output Log -> commit to MPT under short exclusive lock.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/mpt/... ./vindex/internal/tree/...
```
