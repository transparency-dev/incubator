# Client SDK & Query Proof Verification

This document defines the lightweight public Go client SDK (`vindex/client`) for querying VIndex servers and cryptographically verifying lookup responses via pure, stateless `Verify*` functions and an optional, composable `StateTracker` for monotonic state commitment ratcheting.

---

## 1. Context & Objectives

### 1.1 Problem Statement: Zero-Trust Lookup Clients
In verifiable transparency systems, a lookup client querying an index cannot trust the index operator's response. A compromised, coerced, or malfunctioning server could return falsified Input Log entry indices, omit matching records, or present stale state commitments.

To achieve cryptographic security without requiring lookup clients to download entire databases or execute WebAssembly indexing pipelines, VIndex provides a **lightweight verification client library** (`vindex/client`) combining pure, stateless per-response proof verification functions with an optional O(1) `StateTracker`. External Go callers import only `vindex/client` and verify point and prefix lookup responses locally against [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) trust policies via `filippo.io/torchwood`.

### 1.2 The Independent Receipt Analogy
The lookup client functions like a bank customer verifying an itemized transaction receipt:
- The receipt carries the operator's signature and independent witness cosignatures (the Output Log checkpoint verified against the client's `torchwood.Policy`).
- The receipt contains a tamper-evident chain linking the active index state commitment (`c2sp.org/tlog-vindex-state@v1`) to the latest entry of the Output Log (`c2sp.org/tlog-proof@v1`).
- The receipt proves whether the canonical key or prefix exists in the MPT and binds each matched key to its 32-byte Value Log root (`value_root`).
- Subsequent value pages prove completeness via RFC 6962 compact range hashes over preceding Value Log leaves without requiring Merkle consistency proofs.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Provide a clean, minimal public Go package (`vindex/client`) as the sole import required by external Go lookup clients, CLIs, and monitors.
  - Expose pure, stateless cryptographic verification functions matching [`docs/tlog-vindex.md`](../docs/tlog-vindex.md):
    - `VerifyKeysResponse(rawBody []byte, target string, isPrefix bool, cfg VerifierConfig) (*KeysResponse, error)`
    - `VerifyValuesResponse(rawBody []byte, expectedValueRoot [32]byte, from, before uint64) (*ValuesResponse, error)`
  - Use `filippo.io/torchwood` (`torchwood.Policy`) directly in `VerifierConfig` (`OutputLogPolicy torchwood.Policy`, `InputLogPolicy torchwood.Policy`, and optional `ExpectedMapFn *[32]byte`), supporting full C2SP `tlog-policy` witness quorum expressions (`torchwood.ParsePolicy`) as well as programmatic origin-bound single-key policies (`torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(origin), torchwood.SingleVerifierPolicy(v))`).
  - Authenticate state commitments using `torchwood.VerifyProof` + `torchwood.VerifyCheckpoint` (`c2sp.org/tlog-proof@v1`) against `OutputLogPolicy` (explicitly enforcing canonical decimal `index == output_size - 1`) and `torchwood.VerifyCheckpoint` against `InputLogPolicy`.
  - Verify binary MPT inclusion, non-inclusion, and two-sided prefix proofs (`internal/mpt`, enforcing `b <= 8192`, terminal `path_key` canonicality, and 32-byte `path_val` bounds on top of `filippo.io/torchwood/mpt`) over canonical keys (`1..1024` printable ASCII bytes in `0x21..0x7E`).
  - Reconstruct and assert RFC 6962 Value Log roots (`value_root`) from `preceding` compact range hashes and returned Input Log entry indices (`internal/wire`) across initial (`before = InputSize`) and backward continuation pages (`ValuesResponse.NextPage()`).
  - Provide an optional, composable `StateTracker` (`NewStateTracker`, `Observe`, `ObserveKeysResponse`) enforcing monotonicity and non-equivocation across `output_size` and `input_size` and constancy of `map-fn` and `from` (`ErrCheckpointRegressed`, `ErrConsistencyFault`).
  - Expose an HTTP `Client` targeting `<index-url>` with 5 methods: `LookupKey`, `LookupPrefix`, `LookupValues`, and convenience pagination helpers `LookupAllValues` and `LookupPrefixAll`.
  - Maintain a minimal dependency graph with zero dependencies on storage engines (`pebble`), WebAssembly runtimes (`wazero`), or internal ingestion packages (`internal/ingest`, `internal/kvstore`).
- **Non-Goals**:
  - **No Full-Log Auditing**: The lookup client does not replay raw Input Log entries or reconstruct global MPT state; continuous full-log auditing is performed by [`internal/auditor`](../internal/auditor/README.md).
  - **No Output Log Tile Polling**: Lookup clients query only `<index-url>/keys` and `<index-url>/values`; they do not configure `<output-log-url>` or fetch `/checkpoint` and `/tile/...` endpoints directly.
  - **No Storage Mutations**: All client verification executes strictly in memory.

### 1.4 Known Constraints & Trade-Offs
- **Witness Policy Trust Floor**: Lookup client security is bounded by the configured `OutputLogPolicy` and `InputLogPolicy`. If witnesses equivocate or cosign a fraudulent Output Log checkpoint, lookup clients will accept proofs anchored to that checkpoint until an independent auditor ([`internal/auditor`](../internal/auditor/README.md)) detects the invalid state transition.
- **CPU Overhead of Local Verification**: Verifying checkpoint and witness signatures, Output Log inclusion proofs, MPT bitwise paths, and Value Log compact ranges adds roughly 0.5 to 1.5 milliseconds of CPU time per lookup on the client machine.

---

## 2. Detailed Design

### 2.1 Public Architecture & Package Decoupling

External Go callers import `vindex/client` exclusively. Shared wire and MPT proof primitives live in internal packages decoupled from the indexing and storage subsystems:

| Responsibility | Package | External Dependencies |
| :--- | :--- | :--- |
| **HTTP Transport, `StateTracker` & Verification API** | `vindex/client` | `net/http`, `filippo.io/torchwood`, `vindex/internal/wire`, `vindex/internal/mpt`. |
| **C2SP Plaintext Wire & Value Log Codecs** | `vindex/internal/wire` | `crypto/sha256`, `github.com/transparency-dev/formats/log`, `github.com/transparency-dev/merkle`. |
| **MPT Point & Prefix Proof Verification** | `vindex/internal/mpt` | `filippo.io/torchwood/mpt`, `vindex/internal/wire`. |

### 2.2 Stateless Verification Primitives & `StateTracker`

`VerifierConfig` parameterizes stateless proof verification directly with `filippo.io/torchwood` policies:

```go
type VerifierConfig struct {
    OutputLogPolicy torchwood.Policy
    InputLogPolicy  torchwood.Policy
    ExpectedMapFn   *[32]byte // optional; when nil, map-fn syntax is validated and its value ignored
}
```

Policies may be parsed from standard [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) text files via `torchwood.ParsePolicy` (supporting arbitrary `quorum` threshold expressions across witnesses) or constructed programmatically with explicit origin binding via `torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(origin), torchwood.SingleVerifierPolicy(v))` (note that `torchwood.VerifyCheckpoint` rejects bare `SingleVerifierPolicy` instances that do not bind a checkpoint origin).

For every lookup, verification proceeds across the following sequence (specified in [`docs/tlog-vindex.md`](../docs/tlog-vindex.md)):

| Step | Phase | Operations | Cryptographic Assertion |
| :--- | :--- | :--- | :--- |
| **1** | **Output Log Proof (`torchwood.VerifyProof` + `VerifyCheckpoint`)** | Splits `/keys` body on `\n\n` into `c2sp.org/tlog-vindex-keys@v1`, `c2sp.org/tlog-proof@v1` (extracting base64 `extra` `state_entry` and canonical ASCII decimal `index` with no leading zeros), and `<output-log-checkpoint>`, computing the RFC 6962 leaf hash `SHA-256(0x00 \|\| state_entry)`. | Verifies `<output-log-checkpoint>` against `cfg.OutputLogPolicy` via `torchwood.VerifyCheckpoint` to extract `output_size` and `output_root`, asserts `output_size >= 1` and `index == output_size - 1`, and verifies the Merkle inclusion proof via `torchwood.VerifyProof`. |
| **2** | **State Commitment & Input Log Checkpoint (`torchwood.VerifyCheckpoint`)** | Parses `state_entry` as `c2sp.org/tlog-vindex-state@v1` (`mpt-root`, `map-fn`, `from`, `<input-log-checkpoint>`). | Validates `map-fn` (matching `*cfg.ExpectedMapFn` if non-nil), verifies `<input-log-checkpoint>` against `cfg.InputLogPolicy` via `torchwood.VerifyCheckpoint` to obtain `input_size` and `input_root`, and asserts `0 <= from <= input_size`. |
| **3** | **MPT Key / Prefix Proof (`VerifyKeysResponse`)** | Validates canonical key syntax (`1..1024` bytes in `0x21..0x7E`), asserts zero matched keys when `input_size == from`, and verifies the binary MPT proof (`internal/mpt`) against `mpt_root` (enforcing `b <= 8192` split-bit bounds and canonical `path_key` / 32-byte `path_val` checks on terminal leaves). | **Inclusion**: Single matched `(key, value_root)` with `key == target` hashes to `mpt_root`.<br>**Non-Inclusion**: `mpt_root == empty_mpt_hash` (empty proof) or terminal MPT leaf `mpt_leaf_hash(path_key, path_val)` with `path_key != target` hashes to `mpt_root`.<br>**Prefix**: Two-sided proof (`!HasPrefix(path_key, target)` on `0` matches, or `HasPrefix` + strictly ascending key order + `b_1 < 8*len(target)` + subtree root + path to `mpt_root` on `n >= 1` matches). |
| **4** | **Value Log Compact Range (`VerifyValuesResponse`)** | Parses `c2sp.org/tlog-vindex-values@v1` (`preceding`, `popcount(preceding)` compact range hashes, and canonical decimal Input Log entry indices `Indices`). | Asserts `len(Indices) >= 1`, strictly increasing order in `[from, before)`, and `Preceding <= Indices[0] - from`; appends `value_log_leaf_hash(entry_idx)` onto the compact range hashes and folds right-to-left (`value_log_node_hash`) to assert equality with `expectedValueRoot`. |
| **5** | **Monotonic State Ratchet (`StateTracker`, Optional)** | Stateful callers pass verified commitments to `StateTracker.Observe` or `StateTracker.ObserveKeysResponse`. | Enforces monotonicity across `output_size` and `input_size` (`ErrCheckpointRegressed`), non-equivocation of Output Log and Input Log root hashes at equal sizes (`ErrConsistencyFault`), and constancy of `map-fn` and `from` (`ErrConsistencyFault`). |

#### Core Function Signatures:
- **`VerifyKeysResponse(rawBody []byte, target string, isPrefix bool, cfg VerifierConfig) (*KeysResponse, error)`**: Executes Steps 1–3 purely from memory without network I/O or mutable state, returning the verified `KeysResponse` (`OutputSize`, `OutputRoot`, `InputSize`, `InputRoot`, `MPTRoot`, `MapFn`, `From`, `InputCheckpoint`, `Keys`).
- **`VerifyValuesResponse(rawBody []byte, expectedValueRoot [32]byte, from, before uint64) (*ValuesResponse, error)`**: Executes Step 4 purely from its explicit inputs (`expectedValueRoot`, `from`, `before`), returning the verified `ValuesResponse` (`Preceding`, `CompactRange`, `Indices`). `ValuesResponse.NextPage() (before uint64, expectedValueRoot [32]byte, ok bool)` folds `CompactRange` right-to-left via `internal/wire` when `Preceding > 0`, returning `(Indices[0], foldedRoot, true)` for callers paginating backward page-by-page (or `(0, [32]byte{}, false)` when `Preceding == 0`).
- **`NewStateTracker() *StateTracker`**: Provides `Observe(outputSize uint64, outputRoot [32]byte, inputSize uint64, inputRoot [32]byte, mapFn [32]byte, from uint64) error` and `ObserveKeysResponse(resp *KeysResponse) error` for stateful rollback, split-view, and parameter-drift detection across repeated queries.

### 2.3 HTTP Client & Backward Pagination (`Client`)

`Client` wraps `<index-url>`, a `VerifierConfig`, an `*http.Client`, and an optional `*StateTracker`, exposing 5 methods against `<index-url>/keys` and `<index-url>/values`:

1. **`LookupKey`**: Percent-encodes `<key>` per RFC 3986 (escaping any byte outside `unreserved`: `ALPHA`, `DIGIT`, `-`, `.`, `_`, `~`, including `+` as `%2B`), fetches `GET <index-url>/keys?key=<key>`, verifies the body with `VerifyKeysResponse(rawBody, key, false, cfg)`, and (if configured) records the commitment in `StateTracker.ObserveKeysResponse`.
2. **`LookupPrefix`**: Percent-encodes `<key-prefix>` per RFC 3986, fetches `GET <index-url>/keys?prefix=<key-prefix>`, verifies the body with `VerifyKeysResponse(rawBody, prefix, true, cfg)`, and updates the optional `StateTracker`.
3. **`LookupValues`**: Fetches a single value log page via `GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]` and verifies the body with `VerifyValuesResponse(rawBody, expectedValueRoot, from, before)`.
4. **`LookupAllValues`**: Convenience pagination helper for an exact canonical key. Calls `LookupKey` to obtain `From`, `InputSize`, and any matched `ValueRoot` (returning an empty slice when non-included; note `VerifyKeysResponse` already rejects any matched key if `InputSize == From`). Initializes `expectedValueRoot = ValueRoot` and `before = InputSize`, then repeatedly calls `LookupValues` and advances `(before, expectedValueRoot, ok) = page.NextPage()` until `!ok` (`Preceding == 0`), returning all matching Input Log entry indices in strictly ascending order.
5. **`LookupPrefixAll`**: Convenience pagination helper for a key prefix. Calls `LookupPrefix` to obtain `From`, `InputSize`, and all matched `(Key, ValueRoot)` pairs under `<key-prefix>`, then walks backward `/values` pages from `before = InputSize` via `page.NextPage()` down to `Preceding == 0` for each matched key.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Client-Side Cryptographic Assertion**:
  - *Rule*: `Client` and `Verify*` functions never expose lookup results to callers until every signature, inclusion proof, MPT path, canonical key check, and Value Log compact range check has succeeded.
  - *Rationale*: HTTP responses from `<index-url>` are untrusted input; returning unverified results re-introduces trust in the index operator.
  - *Consequence ("Or Else")*: A compromised index operator could forge entry indices or omit matching records without detection.

- **[Correctness Invariant] Monotonic State Commitment Ratchet (`StateTracker`, Optional)**:
  - *Rule*: Stateful lookup clients configured with a `StateTracker` retain O(1) commitment watermarks (`OutputSize`/`OutputRoot`, `InputSize`/`InputRoot`, `MapFn`, and `From`) and reject size regressions (`ErrCheckpointRegressed`), conflicting root hashes at equal tree sizes (`ErrConsistencyFault`), or mutations to `map-fn` or `from` (`ErrConsistencyFault`), without caching per-key entry lists.
  - *Rationale*: Enforces [`docs/tlog-vindex.md`](../docs/tlog-vindex.md) stateful verification in constant memory across arbitrary query volume, while Output Log witness quorums and independent auditors ([`internal/auditor`](../internal/auditor/README.md)) guarantee that every witnessed `mpt-root` faithfully reflects the append-only Input Log.
  - *Consequence ("Or Else")*: Without state commitment ratcheting, a long-lived client polling over time could accept a rolled-back checkpoint or split-view commitment from a compromised mirror.

- **[Performance Optimization] Stateless Zero-Allocation Proof Evaluation**:
  - *Mechanism*: `VerifyKeysResponse` and `VerifyValuesResponse` evaluate binary MPT path steps and RFC 6962 compact range folds linearly over byte slices without allocating intermediate tree node graphs.
  - *Impact*: Client verification completes in roughly 1 ms per query on commodity CPUs.

### 2.5 Failure Taxonomy & Client Handling

| Failure Category | Root Cause | Client Action |
| :--- | :--- | :--- |
| **Untrusted Checkpoint / Quorum Failure** | Output Log proof or embedded Input Log checkpoint fails `torchwood.VerifyProof` or `torchwood.VerifyCheckpoint` under the configured `torchwood.Policy`. | Reject response immediately; abort lookup. |
| **Latest-Entry Proof Violation** | `c2sp.org/tlog-proof@v1` proves an entry at `index != output_size - 1` or `output_size == 0`. | Reject response; server attempted to serve a non-tip Output Log entry. |
| **MPT Proof Mismatch** | Binary MPT path steps or prefix subtree reconstruction do not evaluate to `mpt_root`, or returned keys violate canonical key / prefix bounds. | Security alert; abort lookup (forged or malformed trie proof). |
| **Value Log Root Mismatch** | Reconstructed RFC 6962 root from `preceding` compact range hashes and `Indices` does not equal `expectedValueRoot`, or `Indices` fall outside `[from, before)`. | Security alert; abort lookup (altered, reordered, or truncated entry indices). |
| **State Regression or Consistency Fault** | `StateTracker` detects smaller `output_size`/`input_size` (`ErrCheckpointRegressed`), conflicting root hash at equal size (`ErrConsistencyFault`), or mutated `map-fn`/`from` (`ErrConsistencyFault`). | Security alert; abort lookup (checkpoint rollback, equivocation, or parameter drift). |
| **Prefix Cardinality Exceeded (`HTTP 413`)** | `/keys?prefix=` matched more keys than the server's configured `--max_prefix_keys` guardrail, or `/keys` violated server `PrefixPolicy` (`HTTP 400`). | Surface typed error to caller so the application can narrow the queried prefix. |
| **Unexpected `/values` `HTTP 404` on Present Key** | `/values` returns `404 Not Found` for a key proven present in the MPT at `before = InputSize` (or when `Preceding > 0` promised older entries). | Treat as an unverified server fault (`ErrCryptographicFault`); abort lookup without returning partial results. |
| **Upstream Server Unavailable (`HTTP 503`)** | Server has not yet published its first Output Log checkpoint or lags `before`. | Retry with backoff (honoring `Retry-After`) or fail over to another VIndex instance. |

### 2.6 Client Contract & API Requirements

- **Inputs**:
  - Index base URL (`<index-url>`, serving `/keys` and `/values`).
  - `VerifierConfig` containing non-nil `OutputLogPolicy` (`torchwood.Policy`), non-nil `InputLogPolicy` (`torchwood.Policy`), and optional `ExpectedMapFn` (`*[32]byte`).
  - Canonical key (`key`) or canonical key prefix (`prefix`) of `1..1024` printable ASCII bytes (`0x21..0x7E`), percent-encoded per RFC 3986 on the wire.
  - Explicit `expectedValueRoot` (`[32]byte`), start index `from` (`0 <= from <= before`), exclusive cursor `before` (`1 <= before < 2^64`), and optional advisory `limit` (`1 <= limit < 2^64`) when calling `LookupValues` or `VerifyValuesResponse` directly.
  - Optional `*StateTracker` for stateful commitment ratcheting across lookups.
- **Outputs**:
  - Verified `(Key, ValueRoot)` matches (`KeysResponse`) and strictly ascending `uint64` Input Log entry indices in `[from, InputSize)` (`ValuesResponse` and composite pagination helpers).
  - Verified state commitment metadata (`OutputSize`, `OutputRoot`, `InputSize`, `InputRoot`, `MPTRoot`, `MapFn`, `From`, and raw `InputCheckpoint`).
- **Guarantees**:
  - All HTTP redirects (`3xx`) on `/keys` and `/values` are rejected per `tlog-vindex`.
  - Any policy verification failure, `map-fn` or `from` mismatch, non-tip Output Log proof, MPT path/prefix defect, entry index bound violation, compact range mismatch, or `StateTracker` regression/equivocation returns an immediate error and withholds unverified data.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Server-Side Proof Verification vs. Client-Side Verification
- **Proposed**: Having the VIndex server verify Merkle proofs internally and return a boolean `"verified": true` in a JSON response.
- **Security Rejection**: Defeats the foundational premise of verifiable computing. A compromised, coerced, or buggy index operator can claim its own output is verified. Trust must terminate on the lookup client through local cryptographic verification against `torchwood.Policy` witness quorums.
- **Chosen Design**: The server returns raw C2SP proofs; `vindex/client` executes all cryptographic assertions locally.

### 3.2 Coupling Verification Inside `internal/auditor` vs. Decoupled Public Client SDK
- **Proposed**: Housing query proof verification inside `internal/auditor` alongside the full-log auditor.
- **Architectural Rejection**:
  - `internal/` packages cannot be imported by external Go applications.
  - The full-log auditor depends on embedded storage engines (`pebble`), WebAssembly runtimes (`wazero`), and disk-backed MPT state. Forcing lookup clients to pull in server storage and WASM dependencies violates lightweight client design.
- **Chosen Design**: External Go callers import only `vindex/client` (backed by lightweight `internal/wire` and `internal/mpt` proof codecs), while full-log replay auditing is isolated in [`internal/auditor`](../internal/auditor/README.md).

---

## 4. Verification Gate

All client proof verification, `torchwood.Policy` quorum enforcement, `StateTracker` ratcheting, and package dependency boundary tests are verified via:

```bash
go test -race ./vindex/client/...
```
