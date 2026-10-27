# Read Serving & C2SP Query Protocol

This document defines the HTTP serving architecture, endpoint admission rules, reader snapshot isolation, load-bearing invariants, and verified performance optimizations for the **Serving Subsystem** (`vindex/internal/server`). For the full `tlog-vindex` wire format specifications (`c2sp.org/tlog-vindex-keys@v1`, `c2sp.org/tlog-vindex-values@v1`, `c2sp.org/tlog-vindex-state@v1`) and client-side cryptographic verification rules, see [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) and [`client/README.md`](../../client/README.md).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Verifiable Pagination Dilemma
The read serving engine exposes HTTP endpoints for point and prefix lookups over variable-length canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`). In a verifiable index, serving search results is fundamentally different from a traditional database:
1. **Omission Resistance**: Lookup clients cannot trust the index operator. Every query response must deliver cryptographic inclusion, non-inclusion, or two-sided prefix proofs, proving that no matching Input Log entries were omitted.
2. **Cardinality Skew & Pagination**: When a canonical key accumulates tens of thousands of occurrences (e.g. popular domains in Certificate Transparency), returning all Input Log entry indices in a single HTTP response causes memory exhaustion, serialization stalls, and denial-of-service amplification.
3. **Backward Pagination over Compact Ranges**: If the server paginated forward in time (`start=X`), proving that an intermediate page did not omit records would require computing Merkle consistency proofs across arbitrary Value Log prefixes or scanning from entry `0`. By serving Value Log pages backward from `input_size` (`before=<entry_idx>`) aligned to whole 65,536-entry Pebble chunks, each page embeds the oldest visited chunk's precomputed `preceding` count and compact range hashes (`c2sp.org/tlog-vindex-values@v1`) with zero dynamic SHA-256 hashing on the read path.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Implement the two-endpoint C2SP `tlog-vindex` HTTP read protocol separating key/prefix proof generation (`GET <index-url>/keys?key=<key>` or `GET <index-url>/keys?prefix=<key-prefix>`) from lock-free Pebble Value Log pagination (`GET <index-url>/values?key=<key>&before=<before>`).
  - Return verifiable point inclusion proofs, non-inclusion proofs, and two-sided prefix proofs (`c2sp.org/tlog-vindex-keys@v1`) paired with the latest Output Log inclusion proof (`c2sp.org/tlog-proof@v1`).
  - Remain completely application-agnostic while enforcing an optional caller-supplied prefix policy callback (`400 Bad Request`, e.g. CT/MTC eTLD+1 policies configured by the binary) alongside a configurable maximum prefix match limit (`413 Content Too Large`, default `10,000`).
  - Enforce strict reader snapshot isolation: lookup clients observe state strictly bounded by witnessed Output Log checkpoints (`Serving_CP.InputSize`).
  - Stream responses using direct plaintext formatting (`internal/wire`) without JSON reflection or intermediate heap allocations.
- **Non-Goals**:
  - **No Unbounded Full-Tree Scans**: Prefix scans are guarded by the optional prefix policy callback and maximum prefix match limit.
  - **No Uncommitted / Read-Uncommitted Mode**: Lookups never observe unwitnessed or in-flight Input Log entries ahead of `Serving_CP.InputSize`.
  - **No In-Server Client Verification**: The server generates proofs; cryptographic verification is executed exclusively by the lookup client ([`client/`](../../client/README.md)).

### 1.3 Requirements, Dependencies & Constraints
- **Protocol Standards**: Implements [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) and [C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles@v1.0.0).
- **Dependencies**: Reads from the Pebble inverted chunk store ([`internal/kvstore`](../kvstore/README.md)), the in-memory MPT ([`internal/tree`](../tree/README.md)), and the active serving snapshot (`Serving_CP`).
- **Sequential Roundtrips for Deep Keys**: Because each `/values` continuation cursor (`before = Indices[0]`) is derived from the oldest entry index returned on the preceding page, callers fetching the full history of a key spanning multiple 65,536-entry chunks must issue `/values` requests sequentially rather than in parallel.

---

## 2. Detailed Design

### 2.1 HTTP Endpoints
The public read server exposes the spec-defined C2SP `tlog-vindex` lookup endpoints under `<index-url>` (optionally mounted under a configured URL path prefix without `3xx` redirects) alongside `tlog-tiles` Output Log endpoints when the Output Log directory is co-hosted on the same mux, while operational probes and telemetry are isolated onto an internal administrative/metrics listener:

#### A. Public C2SP `tlog-vindex` & Co-Hosted `tlog-tiles` Endpoints

| Endpoint | Method | Purpose, Status Codes & Caching |
| :--- | :--- | :--- |
| `<index-url>/keys` | `GET` | Exact key or key prefix lookup over canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`).<br>Query params: either `key=<key>` (exact lookup) or `prefix=<key-prefix>` (prefix lookup), mutually exclusive with duplicate or unknown params rejected, parsed via strict RFC 3986 percent-decoding (never converting literal `+` to space `0x20`).<br>On `prefix=<key-prefix>`, validates `<key-prefix>` against the optional prefix policy callback and scans up to `maxPrefixKeys + 1` matching `(key, value_root)` pairs **before** writing `200 OK` headers (returning `413 Content Too Large` if a `(maxPrefixKeys + 1)`-th match exists), then writes `200 OK` (`text/plain; charset=utf-8`, `Cache-Control: no-store`) with `c2sp.org/tlog-vindex-keys@v1` followed by `c2sp.org/tlog-proof@v1` (see [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md)).<br>Returns `400 Bad Request` if neither/both/duplicate/unknown params are present, if percent-decoding fails or the unescaped key/prefix is not a valid canonical key, or if the configured prefix policy rejects `<key-prefix>`; `413 Content Too Large` if matched keys exceed the configured prefix limit; or `503 Service Unavailable` (with `Retry-After: 30`) if the server has not yet published its first Output Log checkpoint. |
| `<index-url>/values` | `GET` | Lock-free Value Log pagination for `key`.<br>Query params: `key` (**required**, parsed via strict RFC 3986 percent-decoding without `+`-to-space conversion) and `before` (**required** canonical positive ASCII decimal integer `1 <= before < 2^64` with no leading zeros or `+`). Page boundaries are server-governed via whole 65,536-entry chunk alignment (`targetPageSize` default `100`, `maxChunksPerRequest` default `16`), returning at least `1` entry index whenever occurrences in `[from, before)` exist.<br>Acquires **zero MPT locks**; returns `200 OK` (`text/plain; charset=utf-8`, `Cache-Control: public, max-age=31536000, immutable`) with `c2sp.org/tlog-vindex-values@v1` (see [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md)).<br>Returns `400 Bad Request` on missing/unknown/duplicate/invalid params, non-canonical or non-positive `before`, or malformed `%`-escapes; `503 Service Unavailable` (with `Retry-After: 30`) if uninitialized or `before > Serving_CP.InputSize`; or `404 Not Found` once `before <= Serving_CP.InputSize` and zero occurrences exist in `[from, before)`. |
| `<output-log-url>/checkpoint` | `GET` | Co-hosted `tlog-tiles` endpoint returning the latest signed, witnessed Output Log checkpoint note from `Serving_CP` (`503 Service Unavailable` with `Retry-After: 30` if uninitialized). |
| `<output-log-url>/tile/...` | `GET` | Co-hosted `tlog-tiles` internal hash tiles and `/tile/entries/...` Output Log entry bundles served from the local Tessera Output Log directory for auditors. |

The server implements only the spec-defined protocol paths above; other paths under `<index-url>` (such as `/` and `/index.html` for an optional embedded single-page HTML explorer UI) are left open and are not part of the protocol. All C2SP `tlog-vindex` endpoints never serve `3xx` redirect responses.

#### B. Non-Public Operational Endpoints (Admin / Metrics Listener Only)

Operational liveness, readiness, Prometheus telemetry, and Go runtime profiling handlers are registered on a separate administrative mux and are never exposed on the public listener:

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/healthz` | `GET` | Liveness probe. Returns **HTTP 200 OK** (`ok\n`) as long as the process and optional health callback report healthy. |
| `/readyz` | `GET` | Readiness probe. Returns **HTTP 200 OK** (`ok\n`) when `Serving_CP` is initialized and ready to serve, or **HTTP 503** (with `Retry-After: 30` and JSON status diagnostics) during MPT initialization, startup recovery, or Genesis Backfill. |
| `/metrics` | `GET` | Exposes Prometheus telemetry metrics. |
| `/debug/pprof/*` | `GET` | Go runtime profiling endpoints. |

### 2.2 Reader Snapshot Isolation & Concurrency
To ensure lookup clients never observe uncommitted or unwitnessed records, the serving engine enforces strict watermark filtering (`Serving_CP.InputSize <= Output_CP.InputSize`):

1. **Brief Shared Read Lock on `/keys`**: Every `/keys` query acquires a shared read lock on the in-memory MPT, reads the atomic `Serving_CP` snapshot under that lock, generates the binary MPT point or prefix proof (`0` bytes when `mpt_root == empty_mpt_hash`, single-leaf inclusion, or full-tree prefix match), and releases the read lock before formatting and writing the response.
2. **Zero-Lock Pebble Reads on `/values`**: Every `/values` query loads the atomic `Serving_CP` pointer without acquiring any MPT lock, rejects `before > Serving_CP.InputSize` with `503 Service Unavailable` (`Retry-After: 30`), hashes `<key>` to `SHA-256(key)`, and performs a chunk-aligned backward lookup in Pebble restricted to `[from, before)`.
3. **Decoupled from Background Ingestion**: Because Output Log appends, witness network roundtrips, and MPT disk `fsync` calls execute outside the in-memory MPT lock (see [`internal/tree`](../tree/README.md)), concurrent `/keys` and `/values` requests never block on ingestion I/O.

### 2.3 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Serving Snapshot Isolation**:
  - *Rule*: Query responses evaluate state strictly bounded by the latest witnessed Output Log commitment (`Serving_CP.InputSize <= Output_CP.InputSize`).
  - *Rationale*: Guarantees that lookup clients only observe state committed in the Output Log and cosigned by witnesses.
  - *Consequence ("Or Else")*: Lookup clients would observe uncommitted or unwitnessed entries, causing client-side `/keys` or `/values` proof verification to fail against witnessed checkpoints.

- **[Correctness Invariant] Pre-Header Prefix Admission**:
  - *Rule*: On `GET <index-url>/keys?prefix=<key-prefix>`, the server validates `<key-prefix>` against the configured prefix policy and collects at most `maxPrefixKeys + 1` matching keys from the MPT **before** writing HTTP response headers, returning `400 Bad Request` or `413 Content Too Large` cleanly if rejected.
  - *Rationale*: Prevents the server from committing a `200 OK` status header and then truncating a response stream mid-body if a broad prefix exceeds `maxPrefixKeys`.
  - *Consequence ("Or Else")*: Mid-stream truncation after `200 OK` would deliver an incomplete key set that fails two-sided prefix proof verification on the client.

- **[Performance Optimization] Zero-Reflection Plaintext Formatting**:
  - *Mechanism*: Formats C2SP plaintext responses (`c2sp.org/tlog-vindex-keys@v1`, `c2sp.org/tlog-proof@v1`, and `c2sp.org/tlog-vindex-values@v1`) directly into contiguous byte buffers without JSON reflection.
  - *Impact*: Delivers sub-millisecond P50 read latency (< 1 ms) and sustains high lookup throughput under concurrent ingestion.

### 2.4 Serving Contract

- **Non-Blocking Read Path**: `/keys` acquires only a brief shared read lock on the in-memory MPT (`Cache-Control: no-store`), while `/values` acquires zero MPT locks and reads immutable/append-only Pebble inverted chunks directly (`Cache-Control: public, max-age=31536000, immutable`).
- **Application-Agnostic Prefix Guardrails**: Contains no hardcoded domain or ecosystem rules; callers may supply an optional prefix policy callback (`400 Bad Request` on policy rejection) alongside a configurable maximum prefix key limit (`413 Content Too Large` when exceeded, default `10,000`).
- **Strict RFC 3986 Query Validation & Chunk-Aligned Paging**: Rejects malformed `%`-escapes, unknown parameters, or duplicate query parameters with `400 Bad Request`, never decodes literal `+` into space `0x20`, validates canonical key syntax (`1..1024` bytes in `0x21..0x7E`), and validates `before` as a canonical positive ASCII decimal integer (`1 <= before < 2^64`) without leading zeros or `+`. On `/values`, page boundaries align to whole 65,536-entry Pebble chunks (`targetPageSize` default `100`, `maxChunksPerRequest` default `16`).

---

## 3. Verification Gate

All server endpoint, prefix policy, chunk-aligned paging, and C2SP wire response tests are verified via:

```bash
go test -race ./vindex/internal/server/...
```
