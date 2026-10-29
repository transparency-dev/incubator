# Inverted Chunk Storage Engine

This document defines the storage architecture, LSM-tree key-value layout, binary serialization schemas, load-bearing invariants, verified performance optimizations, and empirical benchmarks for the **Storage Subsystem** (`vindex/internal/kvstore`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Skewed Cardinality Dilemma
The storage engine persists the per-key value logs mapping canonical keys (`1..1024` bytes in `0x21..0x7E`) to chronologically ordered sequences of Input Log entry indices (`entryIdx`), indexing physical Pebble chunks internally by 32-byte `KeyHash = SHA-256(key)` digests and returning modified `(canonicalKey, value_root)` pairs for MPT state commitment.

Transparency logs exhibit extreme key cardinality skew:
- **Long-tail keys**: The vast majority of domains or packages appear only once or twice in the entire log.
- **Hot keys**: Popular keys (e.g. major cloud provider domains, popular open-source packages) accumulate hundreds of thousands of entries over years.

In an LSM-tree database (such as Pebble), storing this mapping naively leads to two severe failure modes:
1. **O(N^2) Write Amplification**: Appending to flat lists per key requires rewriting the entire historical list on every new entry.
2. **Scan Latency on Deep Keys**: If chunks are stored in chronological forward order (`chunk_0, chunk_1, ...`), locating the active chunk to append a new entry requires seeking past years of historical SSTables, introducing a 7.5x latency penalty.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Provide single-seek active chunk location for batch appends regardless of key depth or historical occurrence count.
  - Eliminate disk I/O on missing keys via full-table 33-byte prefix Bloom filters.
  - Maximize storage density by encoding occurrence entry indices as 16-bit relative offsets within 65,536-entry chunks.
  - Guarantee zero-overhead point-in-time `value_root` calculation to support non-blocking MPT prediction and Zero-WAL crash recovery.
  - Enforce synchronous durability before state commitment handoff to guarantee `KV_CP.Size >= Output_CP.InputSize`.
- **Non-Goals**:
  - **No Distributed Storage**: Operates strictly as a single-host embedded database; distributed clustering and remote RPC storage backends are explicitly out of scope.
  - **No Cross-Key Range Scans**: Supports point queries by exact 32-byte `KeyHash`; lexical prefix scanning across distinct canonical keys inside Pebble is out of scope (all prefix discovery is served by un-hashed canonical keys in the MPT).
  - **No Deletions or Tombstones**: Data is strictly append-only; records are never deleted or overwritten once sealed.

### 1.3 Requirements & Dependencies
- **Storage Engine**: Embedded [Pebble](https://github.com/cockroachdb/pebble) LSM-tree with a custom 33-byte prefix splitter and 10-bit Bloom filter policy.
- **Merkle Tree Utilities**: RFC 6962 value log hashing and compact range hashes via `internal/wire` (`vindex/internal/wire`) and `github.com/transparency-dev/merkle`.

---

## 2. Detailed Design

### 2.1 Logical Model & Inverted Chunk Key Layout
To eliminate write amplification and support direct window-based seeks, the Input Log entry index space is partitioned into fixed global windows of 65,536 entries. Each occurrence at Input Log entry index `entryIdx` maps deterministically to:
- **Chunk Number**: `chunkNum = entryIdx / 65536`
- **Relative Offset**: `relOffset = uint16(entryIdx % 65536)`

While the MPT stores un-hashed variable-length canonical keys (`1..1024` bytes in `0x21..0x7E`), Pebble allocates chunks only for windows in which a canonical key actually occurs, keyed by fixed-width 41-byte records: `'c'` (1 byte) + `KeyHash` (32 bytes, `SHA-256(key)`) + `^BigEndian(chunkNum)` (8 bytes, bitwise inverted so newer chunks sort first):

```text
Key (41 bytes) = [Prefix 'c' (1B)] + [KeyHash (32B)] + [^BigEndian(chunkNum) (8B)]
```
where `^BigEndian(chunkNum) = 0xFFFFFFFFFFFFFFFF - chunkNum`.

#### The Inverted Ordering Mechanism:
Because chunk numbers are bitwise-inverted, the **highest (newest) chunk has the lexicographically smallest key** among all chunks for that key prefix.
- Pebble's custom key comparer splits keys at byte 33 (`'c' + KeyHash`).
- Full-table 10-bit Bloom filters are indexed on this 33-byte prefix across all SSTable levels.
- Performing a prefix-bounded seek on `'c' + KeyHash` achieves two simultaneous benefits:
  1. If the key does not exist, the Bloom filter prunes all SSTables, returning empty with **zero disk I/O**.
  2. If the key exists, the iterator lands **directly on the latest active chunk**, completely skipping all older historical chunks.

### 2.2 Delimitless Binary Chunk Serialization & Compact Ranges

Values store a cumulative RFC 6962 compact range covering all occurrences of that canonical key across prior chunks (`chunk < chunkNum`), plus a dense array of 16-bit relative offsets for occurrences within the current 65,536-entry window (`chunkNum`):

```text
Preceding uint64 (8 bytes, BigEndian) || CompactRange (32 bytes * popcount(Preceding)) || RelativeIndices (uint16, 2 bytes BigEndian * N)
```

| Byte Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `0` | `Preceding` | `uint64` (8 bytes, BigEndian) | Cumulative number of occurrences (value log leaves) for this key across all prior chunks. |
| `8` | `CompactRange` | `[K][32]byte` | Compact range hashes committing to the `Preceding` older value log leaves of this key, where `K = popcount(Preceding)` (32 bytes * K). |
| `8 + 32*K` | `RelativeIndices` | `[]uint16` (2 bytes BigEndian * N) | Dense 2-byte offsets: `uint16(entryIdx % 65536)` for each occurrence of this key within global 65,536-entry window `chunkNum` (`entryIdx = chunkNum*65536 + uint64(relOffset)`). |

#### Per-Entry Key Deduplication, Crash-Replay Idempotency & Value Log Leaf Hashing:
Each leaf in a key's RFC 6962 value log commits to a distinct Input Log entry index (`entryIdx`) where the canonical key occurred:
- **Per-Entry Deduplication**: While the WASM host already sorts and deduplicates canonical keys per entry on output slab unpacking, batch indexing also defensively sorts and deduplicates `(canonicalKey, entryIdx)` pairs (hashing `canonicalKey` internally to `KeyHash = SHA-256(key)` for Pebble storage). Each `entryIdx` is appended at most once to a key's value log, ensuring strictly increasing entry indices within every chunk (`relOffset_0 < relOffset_1 < ...`).
- **Crash-Replay Idempotency (`entryIdx < KV_CP.Size`)**: Every batch write atomically records the batch's ending entry watermark alongside the modified `'c'` chunk records in Pebble (with the full `KV_CP` checkpoint note and durable `fsync` committed on the final slab reaching `Target_CP.Size`). During startup crash recovery or batch replay across `[Output_CP.InputSize, KV_CP.Size)`, any `entryIdx` below the persisted KV watermark—or whose `(chunkNum, relOffset)` is `<=` the active chunk's highest persisted offset—is skipped. When all occurrences of a key in a replayed batch are already persisted in Pebble, the storage engine skips chunk mutation and reconstructs the key's point-in-time `value_root` as of the target size so the MPT receives the exact modified `(canonicalKey, value_root)` mapping without duplicating chunk offsets.
- **Value Log Leaf Hashing**: Each absolute Input Log entry index (`entryIdx = chunkNum*65536 + uint64(relOffset)`) is encoded as an 8-byte big-endian integer and hashed with RFC 6962 leaf domain separator `0x00` (`value_log_leaf_hash(entryIdx) = SHA-256(0x00 || uint64_be(entryIdx))`).
- **Interior Nodes & Chunk Rollover**: Value log interior nodes are hashed with RFC 6962 node domain separator `0x01` (`value_log_node_hash(left, right) = SHA-256(0x01 || left || right)`). When a new occurrence for a key falls into a higher global 65,536-entry window, the previous chunk is sealed and a new chunk is initialized with `Preceding` and `CompactRange` snapshotted from the key's running compact range hashes across all prior chunks.

#### Delimitless Deserialization:
Because the number of compact range hashes is mathematically determined by the population count (number of set bits) of `Preceding` (`K = popcount(Preceding)`), the byte offset where `RelativeIndices` begins is always `8 + 32*K`. This layout eliminates field delimiters, length prefixes, and serialization padding, achieving optimal binary packing density.

### 2.3 Two-Generational Active Chunk Cache & Running Compact Range
To avoid repeatedly reading active chunk descriptors from Pebble or re-hashing historical offsets within the active 65,536-entry window during sequential batching, the store maintains a bounded in-memory two-generational chunk cache:
- **Cached Descriptor & Running Compact Range**: Each cache entry holds both the active chunk record (`Preceding`, `CompactRange`, `RelativeIndices`) and its cumulative in-memory running compact range across all occurrences up to the latest batch. Incremental batch appends update the running compact range directly in O(1) amortized leaf hashes per new occurrence instead of re-hashing prior `RelativeIndices` from index 0; on cache eviction or node restart, the running compact range is lazily reconstructed once when the active chunk is loaded from Pebble.
- **Current & Previous Generations**: The current generation stores chunk descriptors accessed or modified during the active batch, while the previous generation retains descriptors from the immediately preceding batch.
- **Eviction**: When the current generation reaches capacity (scaling to hundreds of thousands of hot keys), the previous generation is replaced by the current generation, and a fresh current generation map is allocated. This absorbs repeated writes to hot keys without LRU lock contention, eliminating >90% of Pebble block cache read I/O during high-throughput ingestion.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Synchronous Persistence Barrier**:
  - *Rule*: Within a target sync cycle, intermediate commit slabs may write to Pebble without an immediate `fsync`, but the final slab reaching `Target_CP.Size` (or an explicit flush barrier) must execute a durable disk sync to flush all modified `'c'` records and metadata (`KV_CP`) to disk before returning to the Coordinator for Output Log publication.
  - *Rationale*: Enforces `KV_CP.Size >= Output_CP.InputSize` across all crash and power-loss scenarios while amortizing disk `fsync` overhead across multi-slab sync cycles.
  - *Consequence ("Or Else")*: If the node crashed after appending a state commitment entry to the Output Log but before Pebble synced to disk, the published root would reference missing KV chunks. The node would be permanently unable to produce inclusion proofs for its own witnessed checkpoints.

- **[Correctness Invariant] Per-Entry Key Deduplication**:
  - *Rule*: The KV store must deduplicate identical `(canonicalKey, entryIdx)` emissions before appending relative offsets or updating the key's running compact range.
  - *Rationale*: Guarantees that a key's value log contains each matching Input Log entry index at most once in strictly ascending order.
  - *Consequence ("Or Else")*: Duplicate relative offsets for the same Input Log entry would be appended to chunk records, corrupting the value log compact range hashes and violating pagination cursor monotonicity (`before=<entry_idx>`).

- **[Correctness Invariant] Point-in-Time Value Log Root Isolation**:
  - *Rule*: When computing or reconstructing `value_root` digests for target Input Log size `input_size`, the storage engine strictly evaluates records with `entryIdx < input_size`, ignoring any chunks or entry indices written ahead of `input_size`.
  - *Rationale*: Allows startup recovery and reader lookups to safely inspect the database even if the KV store has synced batches ahead of the active serving state.
  - *Consequence ("Or Else")*: Query responses would leak unwitnessed or in-flight entry indices, violating reader snapshot isolation.

- **[Performance Optimization] Bitwise Key Inversion (`^chunkNum`) & 33-Byte Bloom Filters**:
  - *Mechanism*: Bitwise inversion places the active chunk first under the prefix; the 33-byte prefix Bloom filter prunes non-existent keys.
  - *Impact*: Delivers single-seek active chunk lookups, eliminating the 7.5x append latency penalty observed on deep keys in forward-ordered layouts.

- **[Performance Optimization] 16-Bit Relative Offset Encoding**:
  - *Mechanism*: Stores entry index offsets as `uint16(entryIdx % 65536)` within each global 65,536-entry window instead of 8-byte integers.
  - *Impact*: Saves 75% disk storage on entry index occurrence lists within each 65,536-entry chunk.

- **[Performance Optimization] Two-Generational Active Chunk Cache**:
  - *Mechanism*: Caches active chunk descriptors across sequential batches.
  - *Impact*: Cuts Pebble block read I/O by >90% during sustained high-concurrency ingestion.

- **[Performance Optimization] Chunk-Aligned Backward Lookup & Zero-Hashing Compact Range Reuse**:
  - *Mechanism*: Seeks directly to the highest valid chunk (`(before - 1) / 65536`), aligns page boundaries to whole 65,536-entry chunks until `totalMatched >= targetPageSize` (default `100`) or `chunksVisited >= maxChunksPerRequest` (default `16`), and copies the `c2sp.org/tlog-vindex-values@v1` `preceding` count and compact range hashes directly from the oldest visited chunk's stored `Preceding` and `CompactRange` with zero dynamic SHA-256 hashing on the read path.
  - *Impact*: Bounds SSTable chunk reads (`maxChunksPerRequest`) per request while eliminating intra-chunk splitting and dynamic Merkle re-hashing across deep keys.

- **[Performance Optimization] Key-Partitioned In-Memory Value Log Hashing**:
  - *Mechanism*: Partitions distinct keys within each incoming mapped batch across a worker pool. Workers independently compute value log compact range updates, `value_root` digests (`internal/wire`), and serialized chunk records in parallel in memory, while the committer sequentially applies the precomputed writes into an atomic Pebble batch.
  - *Impact*: Eliminates single-thread CPU bottlenecks on RFC 6962 value log Merkle hashing during high-throughput ingestion, preventing upstream pipeline backpressure on mapping workers while keeping database writes strictly sequential.

### 2.5 Storage Engine Contract

The storage subsystem manages physical chunk persistence, value log compact range hashes, and point lookups:

- **Physical Format & Key Layout**:
  - Chunks are partitioned by global 65,536-entry Input Log windows (`chunkNum = entryIdx / 65536`) and keyed by 41 bytes: `'c'` (1 byte) + `KeyHash` (32 bytes, `SHA-256(key)`) + `^BigEndian(chunkNum)` (8 bytes bitwise inverted).
  - Bitwise inversion places the newest active chunk first under the key prefix, enabling single-seek active chunk lookups with 33-byte prefix Bloom filtering.
  - Chunk values use a delimitless binary serialization format: an 8-byte big-endian `Preceding` count (total occurrences for that key across prior chunks), followed by RFC 6962 `CompactRange` hashes committing to those `Preceding` prior value log leaves, followed by dense 2-byte relative entry index offsets (`uint16(entryIdx % 65536)`).
- **Write Contract & Rollover**:
  - Monotonic batch writes accept `(canonicalKey, entryIdx)` pairs, compute `KeyHash = SHA-256(key)` internally, deduplicate per Input Log entry, accumulate occurrences across multi-tile commit slabs, return the modified `(canonicalKey, value_root)` mappings for MPT commitment, and execute a durable disk sync at the target checkpoint boundary before Output Log commitment.
  - When an occurrence for a key crosses into a new global 65,536-entry window, the prior chunk is sealed as immutable historical state and a new active chunk is allocated with the cumulative `Preceding` and `CompactRange` of all prior occurrences.
- **Point-in-Time `value_root` Reconstruction**:
  - To reconstruct a modified key's 32-byte `value_root` as of any target `input_size` (used during crash recovery and uncommitted batch staging for keys with `>= 1` occurrences in `[from, input_size)`), the store seeks to `'c' + KeyHash + ^BigEndian((input_size - 1) / 65536)`, skips any chunk where `chunkNum * 65536 >= input_size`, clones that chunk's `Preceding` and `CompactRange`, appends `SHA-256(0x00 || uint64_be(entryIdx))` into the running compact range for each relative offset where `chunkNum * 65536 + relOffset < input_size`, and folds the compact range right-to-left into the 32-byte `value_root` (keys with zero total occurrences in `[from, input_size)`—where `Preceding` plus matching offsets in the chunk equals `0`—are never inserted into the MPT per [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md)).
- **Lookup Contract & Chunk-Aligned Backward Traversal**:
  - The HTTP serving layer rejects `before > Serving_CP.InputSize` with `503 Service Unavailable` prior to storage lookup; once `before <= Serving_CP.InputSize` is established, point lookups accept `canonicalKey` (hashed internally to `KeyHash = SHA-256(key)`) and retrieve Input Log entry indices in `[from, before)` (ignoring any uncommitted chunks written ahead of `Serving_CP.InputSize`) using server-governed chunk-aligned page boundaries per [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) (`targetPageSize` default `100`, `maxChunksPerRequest` default `16`).
  - **Direct Seek**: Computes the target window (`(before - 1) / 65536`) and seeks directly to that inverted chunk key under `'c' + KeyHash`, landing on the newest candidate chunk without scanning future or non-matching SSTables.
  - **Whole-Chunk Reverse Traversal**: Iterates forward through inverted keys (`^chunkNum`), moving backward chronologically. Any chunk where `chunkNum * 65536 >= before` or where zero offsets fall in `[from, before)` is skipped without incrementing `chunksVisited` or copying `Preceding`/`CompactRange`. Each visited chunk with `>= 1` occurrences in `[from, before)` emits **all** matching offsets in that 65,536-entry window without intra-chunk splitting, halting once `totalMatched >= targetPageSize` or `chunksVisited >= maxChunksPerRequest` (default `16`). Consequently, a single dense chunk may return up to `65,536` entry indices while sparse chunks return fewer than `targetPageSize`, returning empty (`404 Not Found` at the HTTP layer) if zero matching occurrences exist in `[from, before)`. When `preceding > 0` on the returned page, clients paginate backward using the first (smallest) returned entry index (`entry_idx_0`) as the next `before` cursor.
  - **Zero-Hashing Compact Range Reuse**: Because page boundaries always align to whole chunks, when `Preceding > 0` on the oldest visited matching chunk, `preceding` and the compact range hashes are copied directly from that chunk's precomputed `Preceding` and `CompactRange` with zero dynamic SHA-256 hashing on the read path.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Evaluated Storage Layouts & Chunk Sizing
1. **Flat Lists per Key**: Storing an unbounded flat list of 8-byte integers under `KeyHash` caused `O(N^2)` write amplification on hot keys as full lists were rewritten on every batch.
2. **One Record per Occurrence**: Appending a discrete key-value pair per occurrence (`KeyHash + BigEndian(entryIdx)`) inflated SSTable metadata and slowed range scans.
3. **Chunk Size (`65,536` vs. `256` / `1,024`)**: Small windows (`256` or `1,024`) caused frequent chunk rollovers and inflated Pebble's block index; `65,536` caps uncompressed chunk values at ~130 KB and enables 16-bit relative offset encoding.
4. **Inverted vs. Forward Chunk Ordering**: Forward ordering (`chunk_0, chunk_1, ...`) required scanning past historical chunks to locate the active tail, whereas bitwise inversion (`^chunkNum`) places the newest chunk first under `'c' + KeyHash` for single-seek access.

### 3.2 Distributed NoSQL (Cloud Bigtable, Spanner, Cassandra) vs. Embedded Pebble LSM
- **Proposed**: Backing the inverted chunk store with a distributed NoSQL engine.
- **Theoretical & Architectural Rejection**:
  - Remote RPC roundtrips introduce 5–20ms network latency per batch seek, destroying ingestion throughput.
  - The authenticated MPT already requires single-host RAM/mmap locality; placing the storage engine on a distributed cluster introduces operational complexity without solving tree state replication.
- **Chosen Design**: Single-host embedded Pebble LSM engine.

### 3.3 Concurrent Database Iterators vs. Key-Partitioned In-Memory Hashing
- **Proposed (Concurrent Database Iterators)**: Partition keys across worker goroutines where each worker manages an independent database iterator to read, mutate, and write chunks concurrently to disk.
- **Empirical Rejection**: Concurrent Pebble iterators introduced lock contention, allocator overhead, and cache thrashing, yielding only an isolated ~14% speedup on 4 workers while degrading performance beyond 8 workers. Furthermore, concurrent disk I/O competed directly with background LSM compactions.
- **Adopted Design (Key-Partitioned In-Memory Hashing)**: Decouples CPU-bound Merkle calculations from I/O-bound database mutations:
  1. *Parallel In-Memory Hashing*: Distinct keys in each batch are distributed across worker goroutines. Each worker computes compact range appends and serializes chunk entries independently in pure memory with zero shared state.
  2. *Sequential Database Commit*: The precomputed key-value writes are merged into a single atomic Pebble batch and committed sequentially.
- **Impact**: Delivers linear multi-core scaling for CPU-intensive value log hashing on high-throughput workloads, eliminating pipeline stalls while preserving zero-contention, deterministic single-threaded database durability.

---

## 4. Verification Gate

All inverted chunk storage, chunk-aligned paging, point-in-time root reconstruction, and batch staging tests are verified via:

```bash
go test -race ./vindex/internal/kvstore/...
```
