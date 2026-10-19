# Read Serving & C2SP Query Protocol

This document defines the HTTP serving architecture, wire protocol specifications, inductive backward verification mechanics, load-bearing invariants, and verified performance optimizations for the **Serving Subsystem** (`vindex/internal/server`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Verifiable Pagination Dilemma
The read serving engine exposes HTTP endpoints for point and prefix lookups over variable-length canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`, with `KeyHash = SHA-256(key)` used for Pebble inverted chunk storage). In a verifiable index, serving search results is fundamentally different from a traditional database:
1. **Omission Resistance**: Lookup clients cannot trust the index operator. Every query response must deliver cryptographic inclusion, non-inclusion, or two-sided prefix proofs, proving that no matching Input Log entries were omitted.
2. **Cardinality Skew & Pagination**: When a canonical key accumulates tens of thousands of occurrences (e.g. popular domains in Certificate Transparency), returning all Input Log entry indices in a single HTTP response causes memory exhaustion, serialization stalls, and denial-of-service amplification.
3. **The Forward Pagination Trap**: If the server paginates forward in time (`start=X`), proving that an intermediate page did not omit records requires computing expensive Merkle consistency proofs across arbitrary Value Log prefixes or scanning from entry `0`.

### 1.2 The Inverted Filing Drawer Analogy (Read Path)
The serving engine mirrors the inverted storage structure established in [`internal/kvstore`](../kvstore/README.md):
- **Opening the Front Drawer**: The lookup client approaches the inverted filing cabinet and pulls the folder at the front of the drawer (`^chunkNum`), representing the latest active 65,536-entry chunk.
- **The Witnessed Seal**: That front folder is anchored to the witnessed `mpt_root` committed in the latest Output Log entry (`c2sp.org/tlog-vindex-state@v1`).
- **Flipping Backwards**: If the lookup client requires deeper history for a high-cardinality key, it requests the folders stacked immediately behind the current page (`before=<Indices[0]>`).
- **The Cryptographic Wax Seal**: Each folder carries an embedded compact range (`preceding <preceding-count>` plus Base64 compact range hashes in `c2sp.org/tlog-vindex-values@v1`) summarizing all older Value Log leaves behind it. By reading backward, the lookup client verifies each page inductively against the compact range hashes of the page ahead of it, proving unbroken completeness with zero consistency proofs.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Implement the two-endpoint C2SP `tlog-vindex` HTTP read protocol separating key/prefix proof generation (`GET <index-url>/keys?key=<key>` or `GET <index-url>/keys?prefix=<key-prefix>`) from lock-free Pebble Value Log pagination (`GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]`).
  - Return verifiable point inclusion proofs, non-inclusion proofs, and two-sided prefix proofs (`c2sp.org/tlog-vindex-keys@v1`) paired with the latest Output Log inclusion proof (`c2sp.org/tlog-proof@v1`).
  - Remain completely application-agnostic while enforcing an optional caller-supplied prefix policy callback (`type PrefixPolicy func(prefix string) error` -> `400 Bad Request`, e.g. CT/MTC eTLD+1 policies configured by the binary) alongside `--max_prefix_keys` (`413 Content Too Large`).
  - Enforce strict reader snapshot isolation: lookup clients observe state strictly bounded by witnessed Output Log checkpoints (`Serving_CP.InputSize`).
  - Stream responses using direct plaintext formatting (`internal/wire`) without JSON reflection or intermediate heap allocations.
- **Non-Goals**:
  - **No Unbounded Full-Tree Scans**: Prefix scans are guarded by the optional `PrefixPolicy` callback and `--max_prefix_keys`.
  - **No Uncommitted / Read-Uncommitted Mode**: Lookups never observe unwitnessed or in-flight Input Log entries ahead of `Serving_CP.InputSize`.
  - **No In-Server Client Verification**: The server generates proofs; cryptographic verification is executed exclusively by the lookup client ([`client/`](../../client/README.md)).

### 1.4 Requirements, Dependencies & Known Pain Points
- **Protocol Standards**: Implements [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) and [C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles@v1.0.0).
- **Dependencies**: Reads from the Pebble inverted chunk store ([`internal/kvstore`](../kvstore/README.md)), the in-memory MPT (`internal/mpt`), and the active serving snapshot published by [`internal/tree`](../tree/README.md).
- **Known Pain Points ("Warts and All")**:
  - **Backward Cursor Friction**: Callers accustomed to forward REST pagination (`start=X`) must pass descending `before` cursors (`before = input_size`, then `before = Indices[0]`), which `vindex/client` pagination helpers abstract automatically.
  - **Sequential Roundtrips for Deep Keys**: Hot keys spanning multiple 65,536-entry chunks require sequential backward `/values` requests to retrieve full historical entry lists.
  - **Checkpoint Boundary Latency**: HTTP lookups evaluate the latest witnessed state commitment (`Serving_CP`); Input Log entries in an uncommitted ingestion batch remain invisible until the next Output Log checkpoint is witnessed and promoted.

---

## 2. Detailed Design

### 2.1 HTTP Endpoints
The public read server (`--listen_addr`) exposes the spec-defined C2SP `tlog-vindex` lookup endpoints under `<index-url>` alongside `tlog-tiles` Output Log endpoints under `<output-log-url>` when the Output Log is co-hosted (see [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md)), while operational probes and telemetry are isolated onto the non-public `--metrics_addr` listener:

#### A. Public C2SP `tlog-vindex` & `tlog-tiles` Endpoints (`--listen_addr`)

| Endpoint | Method | Purpose, Status Codes & Caching |
| :--- | :--- | :--- |
| `<index-url>/keys` | `GET` | Exact key or key prefix lookup over canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`).<br>Query params: either `key=<key>` (exact lookup) or `prefix=<key-prefix>` (prefix lookup), mutually exclusive with duplicate params rejected, parsed from `r.URL.RawQuery` via `url.PathUnescape` (never converting literal `+` to space `0x20`).<br>On `prefix=<key-prefix>`, iterates `Tree.Scan(prefix)` cloning up to `maxPrefixKeys + 1` `(key, value_root)` pairs **before** writing `200 OK` headers (returning `413 Content Too Large` if a `(maxPrefixKeys + 1)`-th match exists), then streams `200 OK` (`text/plain; charset=utf-8`, `Cache-Control: no-store`) with `c2sp.org/tlog-vindex-keys@v1` followed by `c2sp.org/tlog-proof@v1`.<br>Returns `400 Bad Request` if neither/both/duplicate params are present, if percent-decoding fails or the unescaped key/prefix is not a valid canonical key, or if the configured `PrefixPolicy` rejects `<key-prefix>`; `413 Content Too Large` if matched keys exceed `--max_prefix_keys`; or `503 Service Unavailable` if the server has not yet published its first Output Log checkpoint. |
| `<index-url>/values` | `GET` | Lock-free Value Log pagination for `key` (`KeyHash = SHA-256(key)`).<br>Query params: `key` (**required**, parsed from `r.URL.RawQuery` via `url.PathUnescape` without `+`-to-space conversion), `before` (**required** canonical positive ASCII decimal integer `1 <= before < 2^64` with no leading zeros or `+`), `limit` (optional advisory canonical positive ASCII decimal integer `1 <= limit < 2^64` with no leading zeros or `+`; omitted `limit` defaults to `100`, while an explicit `limit` is clamped to `[1, 1000]`—never clamping `limit=1` upward to `100`—subject to whole 65,536-entry chunk alignment and `maxChunksPerRequest`, so a response may return up to `65,536` entry indices in a dense chunk or fewer than `limit` across sparse chunks while always returning at least `1` entry index whenever occurrences `< before` exist).<br>Acquires **zero MPT locks**; returns `200 OK` (`text/plain; charset=utf-8`, long-lived immutable `Cache-Control`) with `c2sp.org/tlog-vindex-values@v1`.<br>Returns `400 Bad Request` on missing/duplicate/invalid params, non-canonical or non-positive `before`/`limit`, or malformed `%`-escapes; `503 Service Unavailable` (with `Retry-After`) if uninitialized or `before > Serving_CP.InputSize`; or `404 Not Found` once `before <= Serving_CP.InputSize` and zero occurrences exist strictly below `before`. |
| `<output-log-url>/checkpoint` | `GET` | Co-hosted `tlog-tiles` endpoint returning the latest signed, witnessed Output Log checkpoint note from `Serving_CP` (`503 Service Unavailable` if uninitialized). |
| `<output-log-url>/tile/...` | `GET` | Co-hosted `tlog-tiles` internal hash tiles and `/tile/entries/...` Output Log entry bundles for auditors. |

The server implements only the spec-defined protocol paths above; other paths under `<index-url>` (such as `/` for an optional human-facing VIndex browser) are left open and are not part of the protocol.

All C2SP `tlog-vindex` endpoints MUST NOT serve `3xx` redirect responses. Because `<index-url>/keys` returns the mutable latest state commitment, responses set `Cache-Control: no-store` (or short TTLs); once the server has indexed Input Log entries at least up to `before`, `<index-url>/values` is deterministic for a fixed server page-boundary policy and sets long-lived immutable caching headers.

#### B. Non-Public Operational Endpoints (`--metrics_addr` Only)

Operational liveness, readiness, Prometheus telemetry, and Go runtime profiling handlers are bound exclusively to the internal `--metrics_addr` listener and are never exposed on the public `--listen_addr` mux:

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/healthz` | `GET` | Liveness probe. Returns **HTTP 200 OK** (`ok\n`) as long as the process is alive. |
| `/readyz` | `GET` | Readiness probe. Returns **HTTP 200 OK** (`ok\n`) when serving state is initialized and healthy, or **HTTP 503** with JSON diagnostics during startup recovery or Genesis Backfill. |
| `/metrics` | `GET` | Exposes standard Prometheus telemetry metrics. |
| `/debug/pprof/*` | `GET` | Go `net/http/pprof` runtime profiling endpoints. |

### 2.2 Plaintext Response Wire Formats

Responses use the canonical C2SP line-oriented plaintext formats defined in [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) (`internal/wire`).

#### A. `GET <index-url>/keys?prefix=com.google.` Response:
```text
c2sp.org/tlog-vindex-keys@v1
proof <base64-mpt-proof>
<canonical-key-1> <base64-value-root-1>
<canonical-key-2> <base64-value-root-2>

c2sp.org/tlog-proof@v1
extra <base64-encoded-tlog-vindex-state>
index <output-entry-index>
<base64-audit-path-hash-1>

<output-log-checkpoint>
```
Where:
- Line 2 is `proof <base64-mpt-proof>` when the binary MPT proof is non-empty, or the bare string `proof` when the binary MPT proof is `0` bytes (when `mpt_root == empty_mpt_hash`, when proving an included key in a single-leaf MPT, or when proving a prefix whose matched keys form the entire MPT).
- `<base64-value-root>` is the 44-character standard Base64 encoding of the 32-byte `value_root`.
- `index` equals `output_size - 1` (proving `extra` is the latest entry in `<output-log-checkpoint>`).
- `extra` in `c2sp.org/tlog-proof@v1` is the Base64 encoding of the `c2sp.org/tlog-vindex-state@v1` Output Log entry (`state_entry`):
  ```text
  c2sp.org/tlog-vindex-state@v1
  mpt-root <base64-mpt-root>
  map-fn <base64-map-fn-sha256>
  from <decimal-start-index>

  <input-log-checkpoint>
  ```

For non-inclusion responses (or `0`-match prefix lookups), there are zero matched key lines:
```text
c2sp.org/tlog-vindex-keys@v1
proof <base64-mpt-proof>

c2sp.org/tlog-proof@v1
extra <base64-encoded-tlog-vindex-state>
index <output-entry-index>
<base64-audit-path-hash-1>

<output-log-checkpoint>
```

#### B. `GET <index-url>/values?key=com.google.&before=98765&limit=100` Response:
```text
c2sp.org/tlog-vindex-values@v1
preceding <preceding-count>
<base64-compact-range-hash-1>

<decimal-entry-index-1>
<decimal-entry-index-2>
```
Where:
- `preceding <preceding-count>` gives the number of older occurrences of `<key>` in the Value Log preceding `<decimal-entry-index-1>`, followed by `popcount(preceding)` Base64-encoded 32-byte compact range hashes (zero hash lines when `preceding == 0`).
- After the empty line, one or more matching decimal Input Log entry indices in `[from, before)` are listed in strictly increasing numerical order.
- Pagination terminates when `preceding == 0`. When `preceding > 0`, the lookup client requests the next backward page with `before = Indices[0]`.

### 2.3 The Inductive Backward Verification Protocol
To prove completeness across paginated responses without consistency proofs, pagination proceeds backward from `input_size`:

#### Step 1: Key Discovery & Initial Value Page (Tip / Page 1)
1. The lookup client queries `GET <index-url>/keys?key=<key>` to obtain the authenticated `value_root`, `from`, and `input_size` (from the `c2sp.org/tlog-vindex-state@v1` commitment inside `extra` of `c2sp.org/tlog-proof@v1`), then queries `GET <index-url>/values?key=<key>&before=<input_size>&limit=100` (when `input_size >= 1` and the key is present).
2. On `/keys`, the server captures an atomic snapshot of `Serving_CP` and generates the MPT inclusion, non-inclusion, or prefix proof under a shared read lock (returning `503 Service Unavailable` if no Output Log checkpoint has been published yet). On `/values`, the server reads matching Input Log entry indices from Pebble DB strictly below `before` without acquiring any MPT lock (returning `503 Service Unavailable` with `Retry-After` if uninitialized or `before > Serving_CP.InputSize`, or `404 Not Found` if zero matching occurrences exist strictly below `before`).
3. The lookup client verifies:
   - Verifies the `c2sp.org/tlog-proof@v1` block (`extra`, `output_size >= 1`, `index == output_size - 1`, audit path, and `<output-log-checkpoint>`) against its Output Log `tlog-policy`.
   - Parses `extra` as `c2sp.org/tlog-vindex-state@v1` (`mpt-root`, `map-fn`, `from`, `<input-log-checkpoint>`), validates `map-fn`, verifies `<input-log-checkpoint>` against its Input Log `tlog-policy` to obtain `input_size`, and checks `0 <= from <= input_size`.
   - Verifies the `c2sp.org/tlog-vindex-keys@v1` MPT proof against `mpt_root` to authenticate `value_root`.
   - Checks that returned `Indices` are strictly increasing inside `[from, before)` with `preceding <= Indices[0] - from`, appends `value_log_leaf_hash(entry_idx)` (`SHA-256(0x00 || uint64_be(entry_idx))`) for each returned `entry_idx` onto the `popcount(preceding)` compact range hashes, and asserts that the folded root equals `value_root`.
   - **Page 1 is now cryptographically authenticated.**

#### Step 2: Continuation Queries (Page 2..N)
1. When `preceding > 0` (indicating older occurrences exist strictly below `Indices[0]`):
2. The lookup client computes the next expected `value_root` by folding the current page's `popcount(preceding)` compact range hashes from right to left using `value_log_node_hash(left, right)`, sets `before = Indices[0]`, and queries `GET <index-url>/values?key=<key>&before=<Indices[0]>&limit=100`.
3. The server reads older Input Log entry indices from Pebble DB strictly below `before` and streams the next `c2sp.org/tlog-vindex-values@v1` response.
4. The lookup client verifies that the returned `Indices` lie in `[from, before)` in strictly increasing order with `preceding <= Indices[0] - from`, and asserts that the reconstructed Value Log root equals the expected `value_root` folded from the prior page.
5. This process repeats inductively until `preceding == 0`, proving that every matching Input Log entry index in `[from, input_size)` has been retrieved without gaps or omissions.

### 2.4 Reader Snapshot Isolation
To ensure lookup clients never observe uncommitted or unwitnessed records, the serving engine enforces strict watermark filtering (`Serving_CP.InputSize <= Output_CP.InputSize`):

1. Every `/keys` lookup captures an atomic snapshot of `Serving_CP` alongside the MPT proof under a shared read lock.
2. When serving `/values?key=<key>&before=<before>`, requests with `before > Serving_CP.InputSize` are rejected with `503 Service Unavailable`, and Pebble chunk reads filter out any Input Log entry index `>= before`, ensuring uncommitted entries from in-flight ingestion batches are never exposed.
3. Lookups remain decoupled from concurrent background ingestion and witnessing.

### 2.5 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Serving Snapshot Isolation**:
  - *Rule*: Query responses evaluate state strictly bounded by the latest witnessed Output Log commitment (`Serving_CP.InputSize <= Output_CP.InputSize`).
  - *Rationale*: Guarantees that lookup clients only observe state committed in the Output Log and cosigned by witnesses.
  - *Consequence ("Or Else")*: Lookup clients would observe uncommitted or unwitnessed entries, causing `VerifyValuesResponse` or `VerifyKeysResponse` to fail against witnessed checkpoints.

- **[Correctness Invariant] Inductive Backward Verification Completeness**:
  - *Rule*: For every `/values` response, the server returns `preceding <preceding-count>` and `popcount(preceding)` compact range hashes in `c2sp.org/tlog-vindex-values@v1` committing to all Value Log leaves strictly preceding `Indices[0]`.
  - *Rationale*: Enables lookup clients to inductively link older continuation pages directly to the witnessed `value_root`.
  - *Consequence ("Or Else")*: A malicious or buggy index operator could omit historical occurrences during backward pagination without detection.

- **[Performance Optimization] Zero-Reflection Plaintext Streaming**:
  - *Mechanism*: Once status admission succeeds (including pre-header bounded collection of at most `maxPrefixKeys` cloned `(key, value_root)` pairs on `/keys?prefix=`), serializes C2SP plaintext responses (`internal/wire`) directly to the HTTP response writer using buffered I/O, avoiding JSON reflection.
  - *Impact*: Delivers sub-millisecond P50 read latency (< 1 ms) and sustains high lookup throughput under concurrent ingestion.

### 2.6 Serving Contract

`internal/server` is an application-agnostic HTTP serving package implementing `tlog-vindex`:

- **Non-Blocking Read Path**: `/keys` acquires only a brief shared read lock on the in-memory MPT, while `/values` acquires zero MPT locks and reads immutable/append-only Pebble inverted chunks directly.
- **Application-Agnostic Prefix Guardrails**: `internal/server` contains no hardcoded domain or ecosystem rules. Callers may supply an optional `type PrefixPolicy func(prefix string) error` callback in server configuration (returning `400 Bad Request` when `PrefixPolicy` returns an error, such as CT/MTC registrable-domain eTLD+1 policies configured by the daemon binary) alongside `--max_prefix_keys` (collecting at most `maxPrefixKeys + 1` cloned items from `Tree.Scan` prior to writing headers and aborting with `413 Content Too Large` if exceeded).
- **Request Validation & `limit` Clamping**: Requests parse `r.URL.RawQuery` directly via `url.PathUnescape` (rejecting malformed `%`-escapes or duplicate query parameters with `400 Bad Request` and never decoding literal `+` into space `0x20`), validate canonical key syntax (`1..1024` bytes in `0x21..0x7E`), and validate `before`/`limit` as canonical positive ASCII decimal integers without leading zeros or `+`. On `/values`, omitted `limit` defaults to `100`, while an explicit `limit` (`1 <= limit < 2^64`) is clamped to `[1, 1000]` (never clamping `limit=1` upward to `100`), subject to whole 65,536-entry chunk alignment and `maxChunksPerRequest`.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Single-RTT Combined Lookup Endpoint vs. Two-Endpoint `/keys` + Lock-Free `/values` Split
- **Proposed**: Serving exact key and prefix lookups from a single combined endpoint that returns the Output Log state commitment, MPT proof, Value Log compact range hashes, and initial Input Log entry indices in one HTTP round-trip.
- **Architectural Trade-Off**:
  - Combining `/keys` and `/values` saves 1 RTT on cold single-key lookups, at the cost of coupling MPT proof generation with Pebble chunk I/O, re-sending redundant Output Log and MPT proofs on every `/values` continuation page, and complicating multi-key prefix responses where dozens of matched keys each have distinct Value Logs.
- **Chosen Design**: Split lookups into `GET <index-url>/keys` (state commitment + MPT proof) and `GET <index-url>/values` (lock-free Value Log pagination). Accepting 2 RTTs on a cold point lookup eliminates MPT lock contention during `/values` pagination, enables long-lived immutable HTTP caching on `/values?key=<key>&before=<before>`, and cleanly composes multi-key prefix discovery with selective per-key Value Log retrieval.

### 3.2 Forward Paging (`start=X`) vs. Backward Paging (`before=X`)
- **Proposed**: Returning Input Log entry indices in ascending chronological order starting from a forward offset cursor (`start=X`).
- **Theoretical Rejection**:
  - RFC 6962 Merkle trees naturally summarize prefixes (`[0, preceding)`) via compact range hashes, not suffixes.
  - Forward pagination requires either returning unverified state, computing custom Merkle consistency proofs on every page, or forcing lookup clients to page through millions of historical entries starting from entry `0` to reach recent occurrences.
- **Chosen Design**: Standardized on backward pagination (`before=<before>`), leveraging compact range hashes over `preceding` older Value Log leaves for zero-consistency-proof inductive verification.

### 3.3 JSON / Protobuf API vs. C2SP Plaintext Wire Format
- **Proposed**: Serving responses formatted as JSON (`{"checkpoint": "...", "indices": [...]}`) or binary Protobufs.
- **Architectural Rejection**:
  - C2SP transparency specifications (`tlog-checkpoint`, `tlog-proof`, `tlog-tiles`, `tlog-witness`) use deterministic line-oriented ASCII/Base64 formats so signed notes and inclusion proofs can be embedded verbatim without canonicalization ambiguity.
  - JSON reflection adds unnecessary allocation and CPU overhead on high-QPS lookups.
- **Chosen Design**: Line-oriented C2SP plaintext wire formats (`c2sp.org/tlog-vindex-keys@v1` and `c2sp.org/tlog-vindex-values@v1`) with direct streaming.

---

## 4. Verification Gate

All server endpoint, `PrefixPolicy`, `limit` clamping, and C2SP wire response tests are verified via:

```bash
go test -race ./vindex/internal/server/...
```
