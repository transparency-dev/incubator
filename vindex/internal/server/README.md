# Read Serving & C2SP Query Protocol

`vindex/internal/server` is the HTTP serving layer that exposes a Verifiable Index over the public [C2SP `tlog-vindex`](../../docs/tlog-vindex.md) lookup protocol. Unlike a traditional database query server, every response must carry cryptographic proofs showing that no matching entries were omitted, while bounding memory and I/O when hot keys match hundreds of thousands of entries. The server splits lookups into two endpoints: key/prefix proof generation against the latest witnessed Output Log commitment, and lock-free backward Value Log pagination aligned to 65,536-entry storage chunks.

### Non-Goals
- **No Unbounded Tree Scans**: Prefix lookups are bounded by an optional application prefix policy callback and a configurable maximum prefix match limit.
- **No Read-Uncommitted Serving**: Lookup responses never expose unwitnessed or in-flight Input Log entries ahead of the active witnessed serving snapshot.
- **No Server-Side Client Verification**: The server generates and formats proofs; cryptographic verification is performed by the lookup client ([`client/`](../../client/README.md)).

---

## 1. Design

### 1.1 Public & Operational HTTP Endpoints

The public read server exposes the C2SP `tlog-vindex` lookup endpoints under `<index-url>` (optionally mounted under a configured URL path prefix without `3xx` redirects) alongside `tlog-tiles` Output Log endpoints when co-hosted on the same mux. All responses are formatted directly into contiguous plaintext buffers (`internal/wire`) without JSON reflection (< 1 ms P50 read latency):

| Endpoint | Method | Purpose, Status Codes & Caching |
| :--- | :--- | :--- |
| `<index-url>/keys` | `GET` | Exact key (`key=<key>`) or prefix (`prefix=<key-prefix>`) lookup over canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`), mutually exclusive with duplicate or unknown query params rejected, parsed via strict RFC 3986 percent-decoding (never converting literal `+` to space `0x20`).<br>On `prefix=<key-prefix>`, validates `<key-prefix>` against the optional prefix policy callback and collects at most `maxPrefixKeys + 1` matching `(key, value_root)` pairs **before** writing `200 OK` headers (returning `413 Content Too Large` cleanly if a `(maxPrefixKeys + 1)`-th match exists, default limit `10,000`, so a `200 OK` response is never truncated mid-stream), then writes `200 OK` (`text/plain; charset=utf-8`, `Cache-Control: no-store`) with `c2sp.org/tlog-vindex-keys@v1` followed by `c2sp.org/tlog-proof@v1`.<br>Returns `400 Bad Request` on invalid/missing/duplicate/unknown params, malformed `%`-escapes, non-canonical key syntax, or prefix policy rejection; `413 Content Too Large` when prefix matches exceed `maxPrefixKeys`; or `503 Service Unavailable` (`Retry-After: 30`) if the first Output Log checkpoint has not yet been published. |
| `<index-url>/values` | `GET` | Lock-free backward Value Log pagination for `key` (**required**, strict RFC 3986 percent-decoding) and `before` (**required** canonical positive ASCII decimal integer `1 <= before < 2^64` with no leading zeros or `+`). Page boundaries align to whole 65,536-entry Pebble chunks (`targetPageSize` default `100`, `maxChunksPerRequest` default `16`), returning at least `1` entry index whenever occurrences in `[from, before)` exist and embedding the oldest visited chunk's precomputed `preceding` count and compact range hashes (`c2sp.org/tlog-vindex-values@v1`) with zero read-path SHA-256 hashing. Callers walking deep histories paginate sequentially using `before = Indices[0]` from the preceding page.<br>Acquires **zero MPT locks**; returns `200 OK` (`text/plain; charset=utf-8`, `Cache-Control: public, max-age=31536000, immutable`).<br>Returns `400 Bad Request` on missing/unknown/duplicate/invalid params, non-canonical or non-positive `before`, or malformed `%`-escapes; `503 Service Unavailable` (`Retry-After: 30`) if uninitialized or `before > Serving_CP.InputSize`; or `404 Not Found` once `before <= Serving_CP.InputSize` and zero occurrences exist in `[from, before)`. |
| `<output-log-url>/checkpoint` | `GET` | Co-hosted [C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles@v1.0.0) endpoint returning the latest signed, witnessed Output Log checkpoint note from `Serving_CP` (`503 Service Unavailable` with `Retry-After: 30` if uninitialized). |
| `<output-log-url>/tile/...` | `GET` | Co-hosted `tlog-tiles` internal hash tiles and `/tile/entries/...` Output Log entry bundles served from the local Tessera Output Log directory for auditors. |

Other paths under `<index-url>` (such as `/` and `/index.html` for an optional embedded single-page HTML explorer UI) are left open and are not part of the protocol. Operational endpoints are isolated onto a separate internal administrative/metrics listener and are never exposed on the public listener:

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/healthz` | `GET` | Liveness probe (`200 OK` `ok\n` while the process and optional health callback report healthy). |
| `/readyz` | `GET` | Readiness probe (`200 OK` `ok\n` when `Serving_CP` is active, or `503` with `Retry-After: 30` and JSON diagnostics during MPT open, startup recovery, or Genesis Backfill). |
| `/metrics` | `GET` | Prometheus telemetry metrics. |
| `/debug/pprof/*` | `GET` | Go runtime profiling endpoints. |

### 1.2 Reader Snapshot Isolation & Concurrency

Lookup clients only ever observe state bounded by the latest witnessed Output Log commitment (`Serving_CP.InputSize <= Output_CP.InputSize`):
1. **Brief Shared Read Lock on `/keys`**: Acquires a shared read lock on the in-memory MPT, reads the atomic `Serving_CP` snapshot under that lock, generates the binary MPT point or prefix proof (`0` bytes when `mpt_root == empty_mpt_hash`, single-leaf inclusion, or full-tree prefix match), and releases the read lock before formatting and writing the response.
2. **Zero-Lock Pebble Reads on `/values`**: Loads the atomic `Serving_CP` pointer without acquiring any MPT lock, rejects `before > Serving_CP.InputSize` with `503 Service Unavailable` (`Retry-After: 30`), hashes `<key>` to `SHA-256(key)`, and performs a chunk-aligned backward lookup in [`internal/kvstore`](../kvstore/README.md) restricted to `[from, before)`.
3. **Decoupled from Ingestion I/O**: Because Output Log appends, witness network roundtrips, and MPT disk `fsync` calls execute outside the in-memory MPT lock (see [`internal/tree`](../tree/README.md)), concurrent `/keys` and `/values` requests never block on background ingestion.

---

## 2. Verification Gate

```bash
go test -race ./vindex/internal/server/...
```
