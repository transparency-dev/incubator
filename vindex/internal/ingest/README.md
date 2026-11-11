# Ingestion Pipeline & Local Tile Cache

`vindex/internal/ingest` is the front-end pipeline that turns a remote append-only Input Log into a verified, strictly ordered stream of `(canonicalKey, entryIdx)` batches for downstream storage. It verifies upstream checkpoints and Merkle consistency against the configured Input Log policy, downloads and authenticates 256-entry bundles across parallel fetchers, caches verified bundles on local disk so crash recovery completes without network egress, maps bundles in parallel across sandboxed WebAssembly workers, and resequences out-of-order worker completions back into contiguous entry index order.

### Non-Goals
- **No Upstream Log Mutation**: Strictly a read-only consumer of the upstream Input Log.
- **No In-Guest Storage Writes**: Sandboxed mapping workers transform raw entry bytes into canonical keys in memory and perform zero disk or network I/O.
- **No Independent Pruning Authority**: The local tile cache never inspects downstream database or trie state directly; it prunes cached bundles strictly up to the `SafeWatermark` dictated by [`internal/coordinator`](../coordinator/README.md).

---

## 1. Design

### 1.1 The Assembly Line Sorter Pipeline

Once the Coordinator establishes a verified `Target_CP` (`Target_CP.Size >= max(prev_Target_CP.Size, from)` and Merkle-consistent with `prev_Target_CP`), it streams `[max(persisted_watermark, from), Target_CP.Size)` through six stages:

1. **Tile Fetcher & Merkle Authentication**: Supports standard tiled logs ([C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles) `/tile/entries/<N>[.p/<W>]` and [C2SP `static-ct-api`](https://c2sp.org/static-ct-api) `/tile/data/<N>[.p/<W>]` using partial tile width `.p/<W>` on unsealed tail tiles, truncating full-bundle fallbacks to `W` authenticated leaves) as well as leaf-by-leaf log adapters that group entries into bundle-aligned 256-entry bundles. Checkpoint verification follows the configured Input Log policy (such as [C2SP `tlog-policy`](https://c2sp.org/tlog-policy)). Fetching in 256-entry bundles cuts upstream HTTP requests by 256x, and each bundle is authenticated against its Level-0 tree tile and in-memory cached upper-level tree tiles (deduplicating concurrent in-flight parent tile reads across workers and retaining sealed full upper tiles across checkpoints) up to `Target_CP.Root` before use. For on-demand single-entry dereferencing (`FetchVerifiedEntryByIndex`), an entry at `idx` is fetched from its containing bundle and authenticated via an RFC 6962 inclusion proof against `(treeSize, treeRoot)`.
2. **Local Tile Cache**: Writes Merkle-authenticated 256-entry bundles to sharded subdirectories (`1,000` bundles per shard, preventing flat-directory inode contention) on local disk via atomic temp-file rename (or a bounded 256-bundle FIFO in-memory cache when `cacheDir == ""`). When `Target_CP.Size` advances within an unsealed 256-entry tail tile across consecutive sync cycles, any cached partial bundle narrower than required (`bundleEnd < Target_CP.Size` and `len < 256`) is treated as a cache miss, re-fetched at the wider width, and atomically overwritten on disk.
3. **WASM Worker Pool**: A pool of parallel Wazero sandboxes (`internal/wasmhost`) running the compiled `.wasm` plugin. Each worker slices boundary bundles to `[max(bundleStart, start), min(bundleEnd, Target_CP.Size))` (excluding entries `< from`, entries already persisted in a partially indexed tail bundle, and entries `>= Target_CP.Size`), maps the slice in a single `map_bundle` FFI call via [`mapfn/sdk`](../../mapfn/README.md) (reducing FFI crossings from 768 to 2–3 per bundle and FFI CPU overhead from ~23% to < 1%), and aggregates emitted entries into a `MappedBatch` (`KeyMap` of `keyHash -> []entryIdx` plus `CanonicalKeys`).
4. **Canonical Key Validation & Per-Entry Deduplication**: Upon unpacking the WASM output slab, the host validates every emitted key against the canonical key bounds in [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) (`1..1024` printable ASCII bytes in `0x21..0x7E`, containing no `NUL` or whitespace bytes) and sorts and deduplicates canonical keys per entry (`entryIdx`). If the WASM module traps, overflows its linear memory slabs, or emits any invalid canonical key, the host returns a fatal validation error that immediately **`HALT`s** ingestion rather than silently dropping the key, preserving bit-for-bit `mpt_root` equivalence with [`internal/auditor`](../auditor/README.md).
5. **Resequencer (Min-Heap)**: Parallel workers finish bundles out of chronological order, and committing out-of-order entry indices would corrupt downstream RFC 6962 Value Log compact ranges. An in-memory min-heap buffers completed worker batches (holding subsequent completions if a straggler worker stalls on a large bundle) and emits strictly contiguous, ascending `(canonicalKey, entryIdx)` batches across `[max(persisted_watermark, from), Target_CP.Size)`.
6. **Tile Reaper**: Periodically receives the Coordinator's `SafeWatermark` (`max(min(KV_CP.Size, MPT_Durable_Size), from)`) and deletes only cached tile files fully covered by that watermark (`(tileIndex + 1) * 256 <= SafeWatermark`), preserving un-synced bundles on disk for Zero-WAL crash recovery while bounding local disk usage.

---

## 2. Alternatives Considered

### 2.1 Ephemeral In-Memory Fetching vs. Persistent Local Tile Cache
- **Proposed**: Streaming 256-entry bundles directly from HTTP responses into the WASM worker pool in memory without caching verified bundles on local disk.
- **Rejection**: Tightly couples upstream HTTP jitter to downstream mapping throughput, and forces any restart or dirty crash where `MPT_Durable_Size` lags `KV_CP.Size` or `Output_CP.InputSize` to re-download historical bundles over the network (risking `HTTP 429` rate limits, failing during upstream outages, and violating the sub-500ms Zero-WAL recovery SLO).
- **Chosen Design**: Persist Merkle-authenticated 256-entry bundles on local disk up to `SafeWatermark` (`max(min(KV_CP.Size, MPT_Durable_Size), from)`), enabling offline Zero-WAL crash replay while bounding disk usage via the tile reaper.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/ingest/...
```
