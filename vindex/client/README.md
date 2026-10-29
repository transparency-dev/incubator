# Client SDK & Query Proof Verification

This document defines the lightweight public Go client SDK (`vindex/client`) for querying VIndex servers over HTTP and cryptographically verifying point, non-inclusion, prefix, and paginated value responses through snapshot-scoped lookup handles.

---

## 1. Context & Objectives

### 1.1 Problem Statement: Zero-Trust Lookup Clients
In verifiable transparency systems, a lookup client querying an index cannot trust the index operator's response. A compromised, coerced, or malfunctioning server could return falsified Input Log entry indices, omit matching records, or present stale state commitments.

To achieve cryptographic security without requiring lookup clients to download entire databases or execute WebAssembly indexing pipelines, VIndex provides a **lightweight, goroutine-safe HTTP verification client** (`vindex/client`). External Go callers import only `vindex/client`, issue exact or prefix lookups that return an immutable `*LookupResult` snapshot, and lazily stream verified Input Log entry indices per matched key via `MatchedKey.Values(ctx)` against configured Output Log checkpoint verification policies (such as [C2SP `tlog-policy`](https://c2sp.org/tlog-policy)).

### 1.2 Goals & Non-Goals
- **Goals**:
  - Provide a clean, minimal public Go package (`vindex/client`) as the sole import required by external Go lookup clients, CLIs, and monitors.
  - Expose a stateless, concurrency-safe HTTP `Client` targeting `<index-url>` (`New(indexURL, cfg, opts ...Option)` with `WithHTTPClient(*http.Client)` for custom proxies, TLS, auth, timeouts, and test transports while enforcing protocol `3xx` redirect rejection and HTTP status semantics).
  - Configure Output Log verification via `Config` (`ExpectedOutputLogOrigin`, `OutputLogPolicy`, and `ExpectedInputLogOrigin`), supporting both [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) witness quorum policies and programmatic log/witness verifier policies without coupling `/keys` lookups to Input Log signature schemes.
  - Authenticate state commitments on `LookupKey` and `LookupPrefix` by verifying the `c2sp.org/tlog-proof@v1` bundle against `ExpectedOutputLogOrigin` and `OutputLogPolicy` (enforcing canonical decimal `index == output_size - 1`) and parsing the strict 6-line `c2sp.org/tlog-vindex-state@v1` record (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`) into an immutable `*LookupResult`.
  - Verify binary MPT inclusion, non-inclusion, and two-sided prefix proofs (`internal/mpt`, enforcing `b <= 8192`, terminal `path_key` canonicality, and 32-byte `path_val` bounds on top of `filippo.io/torchwood/mpt`) over canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`).
  - Scope value enumeration to immutable `MatchedKey` values inside `LookupResult.Keys` via a single lazy iterator method, `MatchedKey.Values(ctx context.Context) iter.Seq2[uint64, error]`, which paginates `<index-url>/values` backward from `before = InputSize`, verifies each page's RFC 6962 Value Log compact range against the expected `value_root`, and yields verified Input Log entry indices **newest-first** so callers can `break` early at a watermark without unbounded slice allocation.
  - Maintain a minimal dependency graph with zero dependencies on storage engines (`pebble`), WebAssembly runtimes (`wazero`), or internal ingestion packages (`internal/ingest`, `internal/kvstore`).
- **Non-Goals**:
  - **No Unbounded `AllValues` Slice Helper**: Hot keys can match millions of Input Log entries; `vindex/client` intentionally omits an `AllValues` slice-drain helper so callers stream newest-first via `MatchedKey.Values(ctx)` and apply explicit bounds when collecting into memory.
  - **No Cross-Lookup Mutable State**: `Client` caches zero state across `LookupKey` / `LookupPrefix` calls; monitors that track progress across polling intervals persist their own `InputSize` watermark externally.
  - **No Full-Log Auditing**: The lookup client does not replay raw Input Log entries or reconstruct global MPT state; continuous full-log auditing is performed by [`internal/auditor`](../internal/auditor/README.md).
  - **No Output Log Tile Polling**: Lookup clients query only `<index-url>/keys` and `<index-url>/values`; they do not configure `<output-log-url>` or fetch `/checkpoint` and `/tile/...` endpoints directly.

### 1.3 Security Boundary
- **Witness Policy Trust Floor**: Lookup client security on `/keys` and `/values` is bounded by the configured `OutputLogPolicy` (and, when a caller fetches matched raw entries from the Input Log, by Merkle authentication against `(InputSize, InputRoot)` and optional Merkle consistency verification against a signed Input Log checkpoint). If Output Log witnesses equivocate or cosign a fraudulent Output Log checkpoint, lookup clients will accept proofs anchored to that checkpoint until an independent auditor ([`internal/auditor`](../internal/auditor/README.md)) detects the invalid state transition.

---

## 2. Detailed Design

### 2.1 Public Architecture & Package Decoupling

External Go callers import `vindex/client` exclusively. Shared wire and MPT proof primitives live in internal packages decoupled from the indexing and storage subsystems:

| Responsibility | Package | Purpose |
| :--- | :--- | :--- |
| **HTTP Transport & Verification Client API** | `vindex/client` | Public snapshot-scoped lookup client (`Client`, `LookupResult`, `MatchedKey`) with zero dependencies on `pebble`, `wazero`, or `tessera`. |
| **C2SP Plaintext Wire & Value Log Codecs** | `vindex/internal/wire` | C2SP `tlog-vindex` plaintext parsers/formatters, checkpoint policy verification, and RFC 6962 Value Log compact range folding. |
| **MPT Point & Prefix Proof Verification** | `vindex/internal/mpt` | Binary MPT point inclusion/non-inclusion and two-sided prefix proof verification (`b <= 8192` split-bit bounds and canonical terminal leaf validation). |

### 2.2 Snapshot-Scoped Client API (`Client`, `LookupResult`, `MatchedKey`)

`Client` is immutable after construction and safe for concurrent use by multiple goroutines. Each `LookupKey` or `LookupPrefix` call returns an isolated `*LookupResult` capturing the verified state commitment and any `MatchedKey` handles bound to that snapshot:

```go
type Config struct {
    ExpectedOutputLogOrigin string
    OutputLogPolicy         CheckpointPolicy
    ExpectedInputLogOrigin  string
}

func New(indexURL string, cfg Config, opts ...Option) (*Client, error)
func WithHTTPClient(hc *http.Client) Option

func (c *Client) LookupKey(ctx context.Context, key string) (*LookupResult, error)
func (c *Client) LookupPrefix(ctx context.Context, prefix string) (*LookupResult, error)

type LookupResult struct {
    OutputSize  uint64
    OutputRoot  [32]byte
    InputOrigin string
    From        uint64
    InputSize   uint64
    InputRoot   [32]byte
    MPTRoot     [32]byte
    Keys        []MatchedKey // 0..1 for LookupKey; 0..N (lexicographically sorted) for LookupPrefix
}

type MatchedKey struct {
    Key       string
    ValueRoot [32]byte
    // unexported snapshot context: client, from, inputSize
}

func (k MatchedKey) Values(ctx context.Context) iter.Seq2[uint64, error]

var (
    ErrVerificationFailed = errors.New("vindex: verification failed")
    ErrBadRequest         = errors.New("vindex: bad request")
    ErrTooManyKeys        = errors.New("vindex: prefix matched too many keys")
    ErrUnavailable        = errors.New("vindex: server unavailable")
)
```

`OutputLogPolicy` may be parsed from a standard [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) text file (supporting arbitrary `quorum` threshold expressions across witnesses) or constructed programmatically from a primary log verifier and witness threshold, pinned to `ExpectedOutputLogOrigin`. `WithHTTPClient` clones the caller-supplied `*http.Client` (preserving custom `Transport`, proxies, TLS settings, and timeouts) while overriding `CheckRedirect` to reject all `3xx` redirects per [`docs/tlog-vindex.md`](../docs/tlog-vindex.md).

Because snapshot context (`ValueRoot`, `From`, `InputSize`, and `*Client`) is encapsulated on each immutable `MatchedKey`, callers can selectively enumerate a subset of keys from a prefix lookup, stop early at a watermark, and reuse the same `*Client` across unrelated lookups without mutating shared client state:

```go
res, err := cli.LookupPrefix(ctx, "com.google.")
if err != nil {
    return err
}
if res.From > requiredHorizon {
    return fmt.Errorf("index starts at %d, need <= %d", res.From, requiredHorizon)
}
for _, mk := range res.Keys {
    if mk.Key != "com.google.mail." && mk.Key != "com.google.maps." {
        continue // skip uninterested keys with zero /values requests
    }
    for entryIdx, err := range mk.Values(ctx) {
        if err != nil {
            return err
        }
        if entryIdx < lastProcessedSize {
            break // newest-first stream: stops without fetching older /values pages
        }
        // Authenticate raw entry at entryIdx against (res.InputSize, res.InputRoot)
    }
}
```

### 2.3 End-to-End HTTP & Cryptographic Verification Sequence

Verification executes across 4 protocol steps matching [`docs/tlog-vindex.md`](../docs/tlog-vindex.md)—Steps 1–3 eagerly inside `LookupKey` / `LookupPrefix`, and Step 4 lazily per page inside `MatchedKey.Values`:

| Step | Phase | Operations | Cryptographic & Protocol Assertion |
| :--- | :--- | :--- | :--- |
| **1** | **Output Log Proof (`c2sp.org/tlog-proof@v1`)** | Percent-encodes `<key>` or `<key-prefix>` per RFC 3986 (`unreserved` only, escaping `+` as `%2B`), fetches `GET <index-url>/keys?...` (rejecting `3xx`, mapping `400`/`413`/`503`, bounding response body size), splits on `\n\n` into `c2sp.org/tlog-vindex-keys@v1`, `c2sp.org/tlog-proof@v1` (base64 `extra` `state_entry` and canonical decimal `index`), and `<output-log-checkpoint>`, and computes `SHA-256(0x00 \|\| state_entry)`. | Verifies `<output-log-checkpoint>` against `cfg.ExpectedOutputLogOrigin` and `cfg.OutputLogPolicy` to extract `output_size` and `output_root`, asserts `output_size >= 1` and `index == output_size - 1`, and verifies the Merkle inclusion proof for `SHA-256(0x00 \|\| state_entry)` at `index`. |
| **2** | **State Commitment (`c2sp.org/tlog-vindex-state@v1`)** | Parses `state_entry` as a strict 6-line `c2sp.org/tlog-vindex-state@v1` record (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`) with no extension lines or trailing data. | Asserts `input_origin == cfg.ExpectedInputLogOrigin` and `0 <= from <= input_size`. Because a lookup response only attests to Input Log entries in `[from, input_size)`, callers requiring coverage back to a specific entry index check `LookupResult.From` against that bound. |
| **3** | **MPT Key / Prefix Proof (`LookupKey` / `LookupPrefix`)** | Validates canonical key syntax (`1..1024` bytes in `0x21..0x7E`), and verifies the binary MPT proof (`internal/mpt`) against `mpt_root` (enforcing `b <= 8192` split-bit bounds and canonical `path_key` / 32-byte `path_val` checks on terminal leaves). | **Inclusion**: Single matched `(key, value_root)` with `key == target` hashes to `mpt_root`.<br>**Non-Inclusion**: `mpt_root == empty_mpt_hash` (`0`-byte proof) or terminal MPT leaf `mpt_leaf_hash(path_key, path_val)` with `path_key != target` hashes to `mpt_root` (`len(res.Keys) == 0`).<br>**Prefix**: On `0` matches, `mpt_root == empty_mpt_hash` (`0`-byte proof) or terminal MPT leaf with `!HasPrefix(path_key, target)` hashes to `mpt_root`; on `n >= 1` matches, `HasPrefix` + strictly ascending key order + `b_1 < 8*len(target)` + subtree root + path to `mpt_root`. |
| **4** | **Lazy Backward Value Pagination (`MatchedKey.Values`)** | Initializes local iterator state `(before = inputSize, expectedValueRoot = k.ValueRoot)`. Fetches `GET <index-url>/values?key=<key>&before=<before>` and parses `c2sp.org/tlog-vindex-values@v1` (`preceding`, `popcount(preceding)` compact range hashes, and strictly increasing `Indices`). | Treats `HTTP 404` on an MPT-included key or promised continuation page (`preceding > 0`) as `ErrVerificationFailed`. Asserts `len(Indices) >= 1`, strictly increasing order in `[from, before)`, and `preceding <= Indices[0] - from`; appends `value_log_leaf_hash(entry_idx)` into the running compact range (merging interior nodes via `value_log_node_hash(left, right)` on trailing `1` bits of the running leaf count) and folds the resulting compact range right-to-left to assert equality with `expectedValueRoot` **before** yielding `Indices` in reverse (`len-1` down to `0`, newest-first). If the caller continues and `preceding > 0`, folds the page's initial `popcount(preceding)` compact range hashes right-to-left into `expectedValueRoot`, sets `before = Indices[0]`, and fetches the next backward page. |

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Pre-Yield Cryptographic & Protocol Assertion**:
  - *Rule*: `LookupKey` and `LookupPrefix` never return a `*LookupResult` until Output Log policy verification, `index == output_size - 1`, `c2sp.org/tlog-vindex-state@v1` bounds, and binary MPT proof verification all succeed; `MatchedKey.Values` verifies the entire `/values` page's compact range root before yielding a single `entry_idx` from that page, and rejects `3xx` redirects or unexpected `404` responses on `/values`.
  - *Rationale*: HTTP responses and status codes from `<index-url>` are untrusted input; yielding unverified indices or silently treating an unexpected `404` as empty history would let a faulty or malicious server truncate results.
  - *Consequence ("Or Else")*: A compromised index operator could forge entry indices or omit matching records without detection.

- **[Correctness Invariant] Snapshot-Scoped Lookup Isolation**:
  - *Rule*: `*Client` holds zero mutable per-lookup or cross-lookup state. Each `*LookupResult` and its `MatchedKey` values capture an immutable `(ValueRoot, from, inputSize)` snapshot, and pagination cursors `(before, expectedValueRoot)` exist strictly as local stack variables inside each `MatchedKey.Values(ctx)` invocation.
  - *Rationale*: Allows a single `*Client` (and even a single `MatchedKey`) to be used concurrently across goroutines, across unrelated key/prefix lookups, and against load-balanced or short-TTL-cached server replicas where consecutive `/keys` responses may arrive slightly out of order without invalidating any proof.
  - *Consequence ("Or Else")*: Mutating shared state on `*Client` across lookups causes data races or false regression errors under concurrent goroutines and load-balanced replicas, and tangles cursor state when interleaving multiple prefix enumerations.

- **[Performance Optimization] Lazy Newest-First Streaming & Zero-Allocation Proof Evaluation**:
  - *Mechanism*: `MatchedKey.Values(ctx)` streams verified entry indices newest-first via `iter.Seq2[uint64, error]` one server-bounded page at a time (omitting any `AllValues` full-slice helper), while `internal/mpt` and `internal/wire` evaluate binary MPT path steps and RFC 6962 compact range folds linearly over byte slices without allocating intermediate tree node graphs.
  - *Impact*: Callers inspecting recent occurrences or polling down to a watermark execute a single `/values` round-trip with constant per-page memory even on hot keys with millions of historical occurrences, completing proof verification in roughly 1 ms per query on commodity CPUs.

### 2.5 Failure Taxonomy & Client Handling

| Failure Category | Root Cause | Client Action |
| :--- | :--- | :--- |
| **Untrusted Checkpoint / Quorum Failure** | Output Log proof or checkpoint fails verification against `ExpectedOutputLogOrigin` and `OutputLogPolicy`, or `input-origin` in `state_entry` does not match `ExpectedInputLogOrigin`. | Return `ErrVerificationFailed`; abort lookup without `*LookupResult`. |
| **Latest-Entry Proof Violation** | `c2sp.org/tlog-proof@v1` proves an entry at `index != output_size - 1` or `output_size == 0`. | Return `ErrVerificationFailed`; abort lookup (server attempted to serve a non-tip Output Log entry). |
| **MPT Proof Mismatch** | Binary MPT path steps or prefix subtree reconstruction do not evaluate to `mpt_root`, or returned keys violate canonical key / prefix bounds. | Return `ErrVerificationFailed`; abort lookup. |
| **Value Log Root or Range Mismatch** | Reconstructed RFC 6962 root from `preceding` compact range hashes and `Indices` does not equal `expectedValueRoot`, or `Indices` fall outside `[from, before)` or are not strictly increasing. | Yield `(0, ErrVerificationFailed)` and terminate iterator without yielding unverified page indices. |
| **Unexpected `/values` `HTTP 404` on Present Key** | `/values` returns `404 Not Found` for a key proven present in the MPT at `before = InputSize` (or when `preceding > 0` promised older entries). | Yield `(0, ErrVerificationFailed)` and terminate iteration (server state violates the witnessed MPT or Value Log commitment). |
| **Prefix Cardinality or Policy Rejection (`HTTP 413` / `HTTP 400`)** | `/keys?prefix=` matched more keys than the server's configured prefix limit (`413`), or violated the server's prefix policy (`400`). | Surface typed HTTP status error (`ErrTooManyKeys` / `ErrBadRequest`) so the caller can narrow the queried prefix. |
| **Upstream Server Unavailable (`HTTP 503`)** | Server has not yet published its first Output Log checkpoint or lags `before`. | Surface `ErrUnavailable` (preserving `Retry-After` metadata when present) so the caller can retry with backoff or fail over. |

### 2.6 Client Contract & API Requirements

- **Inputs**:
  - Index base URL (`<index-url>`, serving `/keys` and `/values`).
  - `Config` containing non-empty `ExpectedOutputLogOrigin` (`string`), non-nil `OutputLogPolicy` (`CheckpointPolicy`), and non-empty `ExpectedInputLogOrigin` (`string`), plus optional `WithHTTPClient(*http.Client)`.
  - Canonical key (`key`) or canonical key prefix (`prefix`) of `1..1024` printable ASCII bytes (`0x21..0x7E`), validated locally before sending and percent-encoded per RFC 3986 (`unreserved`) on the wire.
- **Outputs**:
  - `*LookupResult` exposing verified state commitment metadata (`OutputSize`, `OutputRoot`, `InputOrigin`, `From`, `InputSize`, `InputRoot`, `MPTRoot`) and lexicographically ordered `Keys []MatchedKey` (`0..1` for `LookupKey`, `0..N` for `LookupPrefix`).
  - Lazy `MatchedKey.Values(ctx) iter.Seq2[uint64, error]` yielding verified `uint64` Input Log entry indices in `[From, InputSize)` in **strictly decreasing (newest-first)** order across backward pages (callers requiring historical coverage back to a specific entry index check `LookupResult.From`, and callers fetching raw entries from the Input Log authenticate them against `(LookupResult.InputSize, LookupResult.InputRoot)`).
- **Guarantees**:
  - All HTTP redirects (`3xx`) on `/keys` and `/values` are rejected per `tlog-vindex`.
  - `*Client`, `*LookupResult`, and `MatchedKey` contain no mutable cross-lookup state and are safe for concurrent use across goroutines.
  - Any Output Log policy verification failure, `input-origin` or `from` violation, non-tip Output Log proof, MPT path/prefix defect, unexpected `404` on `/values`, entry index bound violation, or compact range mismatch returns an immediate error and withholds unverified data.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Stateless Snapshot Handles vs. Mutable Cross-Lookup Client State
- **Proposed**: Caching observed `(output_size, input_size)` watermarks inside `Client` across lookups or exposing unbounded slice-draining helpers for value pagination.
- **Rejection**:
  - **Cross-Lookup Watermark Races**: Caching observed `(output_size, input_size)` watermarks inside `Client` verifies no Merkle consistency proof (witnesses and auditors provide that guarantee), causes false regression errors when concurrent goroutines or load-balanced/short-TTL-cached server replicas return checkpoints out of arrival order, and tangles state across unrelated key lookups.
  - **Unbounded Slice Allocations on Hot Keys**: Keys appearing hundreds of thousands or millions of times would trigger unbounded sequential HTTP pagination and large slice allocations, whereas callers needing a slice can collect from `iter.Seq2` explicitly with their own bounds.
- **Chosen Design**: `Client` is stateless across lookups and returns snapshot-scoped `*LookupResult` handles whose `MatchedKey.Values(ctx)` `iter.Seq2[uint64, error]` iterator streams verified entry indices newest-first with early `break` support.

---

## 4. Verification Gate

All client proof verification, HTTP transport/redirect/status handling, checkpoint policy quorum enforcement, backward pagination streaming, and package dependency boundary tests are verified via:

```bash
go test -race ./vindex/client/...
```
