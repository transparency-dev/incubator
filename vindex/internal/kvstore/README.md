# Inverted Chunk Storage Engine

`vindex/internal/kvstore` is the embedded [Pebble](https://github.com/cockroachdb/pebble) storage engine that persists per-key Value Logs: the chronologically ordered sequences of Input Log entry indices at which each canonical key appeared, together with their RFC 6962 Merkle compact ranges. Transparency logs have extreme key cardinality skew (most keys appear once or twice, while hot keys accumulate hundreds of thousands of entries). By partitioning occurrences into global 65,536-entry windows and ordering chunks newest-first in the LSM keyspace, the store supports single-seek appends, lock-free backward pagination with zero read-path SHA-256 hashing, and point-in-time `value_root` reconstruction for crash recovery.

### Non-Goals
- **No Distributed Storage**: Operates strictly as a single-host embedded database; remote RPC storage backends are out of scope.
- **No Lexical Prefix Scans in Pebble**: Indexes chunks internally by fixed-width 32-byte key hashes for exact key lookup; lexical prefix discovery across canonical keys is served by the in-memory MPT ([`internal/tree`](../tree/README.md)).
- **No Deletions or Tombstones**: Strictly append-only; sealed historical chunks are immutable.

---

## 1. Design

### 1.1 Inverted 65,536-Entry Chunk Key Layout

The Input Log entry index space is partitioned into fixed global windows of 65,536 entries (`chunkNum = entryIdx / 65536`, `relOffset = uint16(entryIdx % 65536)`). While the MPT stores un-hashed canonical keys (`1..1024` bytes in `0x21..0x7E`), Pebble allocates chunks only for windows in which a key occurs, keyed by fixed 41-byte records using internal `KeyHash = SHA-256(key)` digests and bitwise-inverted chunk numbers (`^BigEndian(chunkNum) = 0xFFFFFFFFFFFFFFFF - chunkNum`):

```text
Key (41 bytes) = [Prefix 'c' (1B)] + [KeyHash (32B)] + [^BigEndian(chunkNum) (8B)]
```

- **Inverted Ordering & 33-Byte Prefix Bloom Filter**: Pebble's custom comparer splits keys at byte 33 (`'c' + KeyHash`) and builds full-table 10-bit Bloom filters on that 33-byte prefix across all SSTable levels. A prefix-bounded seek on `'c' + KeyHash` prunes non-existent keys with **zero disk I/O**, and for existing keys lands **directly on the newest active chunk** (eliminating the 7.5x scan latency penalty of forward-ordered chunks on deep keys).

### 1.2 Delimitless Binary Chunk Values & Compact Ranges

Each chunk value stores a cumulative RFC 6962 compact range covering all occurrences of that key across prior chunks (`chunk < chunkNum`), followed by dense 16-bit relative offsets for occurrences within `chunkNum` (saving 75% storage compared to 64-bit indices):

```text
Preceding uint64 (8 bytes, BigEndian) || CompactRange (32 bytes * popcount(Preceding)) || RelativeIndices (uint16, 2 bytes BigEndian * N)
```

| Byte Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `0` | `Preceding` | `uint64` (8 bytes, BigEndian) | Cumulative number of occurrences (Value Log leaves) for this key across all prior chunks. |
| `8` | `CompactRange` | `[K][32]byte` | Compact range hashes committing to the `Preceding` older Value Log leaves, where `K = popcount(Preceding)` (`32 * K` bytes). |
| `8 + 32*K` | `RelativeIndices` | `[]uint16` (`2 * N` bytes, BigEndian) | Strictly increasing 2-byte offsets `uint16(entryIdx % 65536)` within window `chunkNum` (`entryIdx = chunkNum*65536 + uint64(relOffset)`). |

Because `K = popcount(Preceding)` determines the exact length of `CompactRange`, `RelativeIndices` always starts at byte offset `8 + 32*K` without delimiters or length prefixes.

### 1.3 Write Pipeline, Two-Generational Cache & Point-in-Time Reconstruction

- **Per-Entry Deduplication & Parallel Value Log Hashing**: Batch writes defensively sort and deduplicate `(canonicalKey, entryIdx)` pairs so each `entryIdx` is appended at most once per key (`relOffset_0 < relOffset_1 < ...`). Distinct modified keys in a batch are partitioned across worker goroutines that compute RFC 6962 leaf hashes (`SHA-256(0x00 || uint64_be(entryIdx))`), interior node merges (`SHA-256(0x01 || left || right)`), `value_root` digests (`internal/wire`), and serialized chunk values in parallel in memory before committing sequentially in a single atomic Pebble batch, returning modified `(canonicalKey, value_root)` mappings for MPT commitment. When an occurrence crosses into a higher 65,536-entry window, the prior chunk is sealed and a new active chunk is initialized with the snapshotted `Preceding` and `CompactRange`.
- **Two-Generational Active Chunk Cache**: Each cache entry holds the active chunk descriptor (`Preceding`, `CompactRange`, `RelativeIndices`) alongside its in-memory running compact range, updating incrementally in O(1) amortized leaf hashes per new occurrence instead of re-hashing prior `RelativeIndices` from index `0` (reconstructed lazily once on cache miss or restart). Maintaining current and previous batch generations absorbs repeated writes to hot keys without LRU lock contention and cuts Pebble block cache read I/O by >90%.
- **Synchronous Persistence Barrier & Crash-Replay Idempotency**: Intermediate commit slabs within a sync cycle may write to Pebble without an immediate `fsync`, but the final slab reaching `Target_CP.Size` (or an explicit flush barrier) executes a durable disk sync committing `KV_CP` before Output Log publication (`KV_CP.Size >= Output_CP.InputSize`). Every batch write atomically records the batch's ending entry watermark alongside modified `'c'` records; during startup recovery or batch replay across `[Output_CP.InputSize, KV_CP.Size)`, any `entryIdx` below the persisted KV watermark (or `<=` the active chunk's highest persisted offset) is skipped.
- **Point-in-Time `value_root` Reconstruction**: To reconstruct a key's 32-byte `value_root` as of any target `input_size` (used during crash recovery and batch replay for keys with `>= 1` occurrences in `[from, input_size)`), the store seeks to `'c' + KeyHash + ^BigEndian((input_size - 1) / 65536)`, skips any chunk with `chunkNum * 65536 >= input_size`, clones that chunk's `Preceding` and `CompactRange`, appends `SHA-256(0x00 || uint64_be(entryIdx))` for each relative offset with `chunkNum * 65536 + relOffset < input_size`, and folds the compact range right-to-left into `value_root`. Keys with zero total occurrences in `[from, input_size)` (`Preceding` plus matching offsets equals `0`) are omitted from the MPT per [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md).

### 1.4 Chunk-Aligned Backward Lookup & Zero-Hashing Compact Range Reuse

Once the HTTP layer establishes `before <= Serving_CP.InputSize`, point lookups hash `canonicalKey` to `KeyHash = SHA-256(key)` and retrieve entry indices in `[from, before)` (ignoring any uncommitted chunks written ahead of `Serving_CP.InputSize`) using chunk-aligned page boundaries (`targetPageSize` default `100`, `maxChunksPerRequest` default `16`):
1. **Direct Seek**: Seeks directly to `'c' + KeyHash + ^BigEndian((before - 1) / 65536)`, landing on the newest candidate chunk without scanning newer or unrelated SSTables.
2. **Whole-Chunk Reverse Traversal**: Iterates forward through inverted keys (`^chunkNum`), moving backward chronologically. Any chunk where `chunkNum * 65536 >= before` or where zero offsets fall in `[from, before)` is skipped without incrementing `chunksVisited`. Each visited chunk with `>= 1` occurrences in `[from, before)` emits **all** matching offsets in that 65,536-entry window without intra-chunk splitting, halting once `totalMatched >= targetPageSize` or `chunksVisited >= maxChunksPerRequest` (returning up to `65,536` indices for a dense chunk, fewer than `targetPageSize` for sparse chunks, or empty / `HTTP 404` if zero occurrences exist in `[from, before)`).
3. **Zero-Hashing Compact Range Reuse**: Because page boundaries always align to whole chunks, when `Preceding > 0` on the oldest visited matching chunk, the `/values` response copies `preceding` and the compact range hashes directly from that chunk's stored `Preceding` and `CompactRange` with zero dynamic SHA-256 hashing on the read path.

---

## 2. Alternatives Considered

### 2.1 Storage Layouts & Chunk Sizing
- **Flat Lists per Key**: Rewriting a single flat list of 8-byte indices per key caused O(N^2) write amplification on hot keys.
- **One Record per Occurrence**: Storing one KV record per occurrence (`KeyHash + BigEndian(entryIdx)`) inflated SSTable metadata and slowed pagination scans.
- **Window Size (`65,536` vs. `256` / `1,024`)**: Small windows caused frequent chunk rollovers and bloated Pebble's block index; `65,536` caps uncompressed chunk values at ~130 KB and enables exact 16-bit relative offset encoding.
- **Inverted vs. Forward Chunk Ordering**: Forward ordering (`chunk_0, chunk_1, ...`) required scanning past historical SSTables to reach the active tail (7.5x slower appends), whereas bitwise inversion (`^chunkNum`) places the newest chunk first under `'c' + KeyHash`.

### 2.2 Distributed NoSQL vs. Embedded Pebble LSM
- **Proposed**: Backing the chunk store with a distributed NoSQL database (Bigtable, Spanner, or Cassandra).
- **Rejection**: Remote RPCs add 5–20ms network latency per batch seek, and the MPT already requires single-host RAM/mmap locality.
- **Chosen Design**: Single-host embedded Pebble LSM engine.

### 2.3 Concurrent Database Iterators vs. Key-Partitioned In-Memory Hashing
- **Proposed**: Partitioning keys across worker goroutines that each hold an independent Pebble iterator to read, mutate, and write chunks concurrently.
- **Rejection**: Concurrent Pebble iterators suffered lock contention and cache thrashing (~14% speedup on 4 workers, degrading beyond 8 workers) while competing with background LSM compactions.
- **Chosen Design**: Parallel key-partitioned Value Log hashing in pure memory followed by a single sequential atomic Pebble batch commit.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/kvstore/...
```
