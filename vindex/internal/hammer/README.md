# Hammer Conformance & Load-Testing Harness

Unit tests and single-codebase integration suites only verify an implementation against its own assumptions, leaving subtle wire-format divergences, URL percent-decoding bugs, shared WebAssembly guest/compiler quirks, and tail-latency stalls under concurrent read/write load undetected. The hammer ([`cmd/hammer`](../../cmd/hammer)) is an implementation-agnostic [C2SP `tlog-vindex`](../../docs/tlog-vindex.md) conformance checker and performance benchmark harness designed to test both this repository and independent third-party `tlog-vindex` implementations built in any language or storage stack.

The harness operates strictly across standard protocol boundaries: it hosts an upstream [C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles) Input Log over HTTP (with programmable entry distributions and checkpoint release schedules), evaluates the active mapping function natively in pure Go to maintain an independent ground-truth oracle, and drives concurrent HTTP lookup and protocol conformance probes against the target index's `<index-url>` and optional `<output-log-url>`.

### Non-Goals
- **No Target Implementation Coupling**: Never inspects target-specific admin listeners, metrics endpoints, on-disk database files, or in-process state; every assertion is derived solely from standard `tlog-tiles` and `tlog-vindex` HTTP traffic.
- **No WebAssembly Execution in the Oracle**: Evaluates mapping functions (`raw`, `sumdb`, `ct`) in pure Go using standard library parsers rather than executing shared `.wasm` guest modules, ruling out WebAssembly compiler, ABI, or sandbox bugs that could mask mapping discrepancies across implementations.
- **Not a Production Log Sequencer**: Generates deterministic synthetic workloads and controlled checkpoint schedules for conformance and benchmark testing rather than operating a public durable log.

---

## 1. Design

### 1.1 Architecture & Protocol Boundary

| Component | Protocol Surface & Responsibility |
| :--- | :--- |
| **Synthetic Entry Generator** | Produces deterministic synthetic Input Log entries across Zipfian (`s > 1`) and uniform key distributions in `raw`, `sumdb`, or `ct` formats, alongside disjoint non-inclusion probe keys guaranteed never to appear in the Input Log. |
| **Input Log Sequencer & Drip Server** | Appends generated entries to a local POSIX `tlog-tiles` log, signs checkpoints with an Ed25519 note key (printing the verifier key and Input Log URL at startup for any target indexer), and serves `/checkpoint` and `/tile/...` over HTTP on steady-drip, burst, or initial-pause schedules. |
| **Pure-Go Mapping Oracle** | Applies a pure-Go reference implementation of the active mapping function to every sequenced Input Log entry bytes, recording exact ground-truth `(key -> entry_indices)` mappings and valid Input Log `(input-size, input-root)` states before checkpoints covering those entries are exposed to the target indexer. |
| **Lookup & Conformance Workers** | Drives concurrent HTTP queries against `<index-url>/keys` and `<index-url>/values` via [`client/`](../../client/README.md), runs negative HTTP edge-case conformance probes, and optionally tails `<output-log-url>` (`/checkpoint` and `/tile/entries/...`) to verify Output Log tile conformance. |
| **Telemetry & Invariant Analyzer** | Tracks write/read throughput, P50/P90/P99/Max read latency, catch-up time, and live ingestion lag (`input_log_size - indexed_size`), failing with non-zero exit status on any cryptographic, ground-truth, or protocol conformance violation. |

### 1.2 Synthetic Workloads, Pure-Go Mapping & Checkpoint Synchronization

- **Leaf Formats & Pure-Go Mapping Profiles**:
  - **`raw`**: Single-key printable ASCII entries (`1..1024` bytes in `0x21..0x7E`), periodically embedding RFC 3986 reserved query delimiters (`+`, `&`, `=`) alongside unreserved `~` to catch servers that misparse raw query strings or treat `+` as space (`0x20`) instead of requiring `%2B`. Mapped in pure Go by extracting the first whitespace-delimited token per non-empty line.
  - **`sumdb`**: Two-line Go Checksum Database records (`<module> <version> h1:<hash>` and `<module> <version>/go.mod h1:<hash>`), including mixed-case module paths (such as `example.com/Mod-3` escaping to `example.com/!mod-3`). Mapped in pure Go via standard semantic-version validation and Go module path case-escaping, exercising both `!` (`%21`) percent-encoding and per-entry duplicate key suppression (`tlog-vindex` requires recording an `entry_idx` at most once per canonical key).
  - **`ct`**: RFC 6962 `MerkleTreeLeaf` X.509 certificate entries containing multiple SAN `dNSName` values, subdomains, and leftmost wildcards (`*.domain-<id>.com`). Mapped in pure Go using standard library X.509 certificate parsing (Subject Common Name and SAN `dNSName` entries) and reversed-label domain canonicalization (`com.domain-<id>.`, `com.domain-<id>.*.`), providing true implementation diversity against custom ASN.1 or WebAssembly parsers.
- **Key Skew & Checkpoint Release Schedules**:
  - **Zipfian Skew vs. Uniform Fanout**: Zipfian skew concentrates >80% of occurrences onto the hottest 1% of keys, driving hot value logs across multi-page backward `/values` boundaries while uniform keys exercise wide MPT branching and single-entry value logs.
  - **Steady Drip, Burst & Pause/Catch-Up**: Modulates `/checkpoint` publication independently of background entry sequencing so operators can measure steady-state read/write tail latency, batch burst absorption, and cold backlog catch-up throughput.
- **Checkpoint-Oracle Ordering**: Every sequenced entry (including entries replayed from an existing Input Log directory on startup) is mapped in pure Go and committed into the in-memory oracle before `/checkpoint` exposes a tree size covering that entry; or else a fast target indexer could serve a newly published `input-size` before the oracle recorded its entries, causing false-positive accuracy failures.

### 1.3 Ground-Truth Accuracy & Protocol Conformance Checks

1. **Cryptographic Lookup Verification**: Every `/keys` and `/values` lookup is verified offline via [`client/`](../../client/README.md): checking `Content-Type: text/plain; charset=utf-8`, rejecting HTTP `3xx` redirects, verifying the `c2sp.org/tlog-proof@v1` Output Log checkpoint policy and inclusion proof at `output_size - 1`, validating the 6-line `c2sp.org/tlog-vindex-state@v1` payload, verifying binary MPT inclusion/non-inclusion/two-sided prefix proofs against `mpt-root`, and verifying RFC 6962 compact range roots across `/values` pages.
2. **Input Log State Binding**: On every verified state commitment `(input-origin, from, input-size, input-root, mpt-root)`, the harness asserts that `input-origin` matches the hammer's Input Log origin, `from` remains constant across the run, `input-size` does not exceed the hammer's sequenced Input Log size, and `(input-size, input-root)` matches (or is Merkle-consistent with) the hammer's Input Log; or else an implementation committing to a bogus or forked `input-root` while serving internally consistent MPT proofs would evade detection.
3. **Pure-Go Oracle Exactness**: At every verified snapshot `[from, input-size)`, the harness checks lookup results against the pure-Go mapping oracle (retaining exact full-log occurrence slices up to tens of millions of occurrences, and enforcing monotonic prefix-superset bounds beyond that cap during multi-day soak runs):
   - **Exact Key Lookups (`GET /keys?key=<key>`)**: Must return a match if and only if the oracle recorded at least one occurrence of `<key>` in `[from, input-size)`; or else a broken target mapping function that drops keys and serves valid MPT non-inclusion proofs over an incomplete trie would silently pass proof verification. Full backward `/values` walks (`preceding == 0`) must match the oracle's exact ascending index slice in `[from, input-size)`, and bounded newest-page reads must match the exact newest suffix of that slice.
   - **Prefix Lookups (`GET /keys?prefix=<prefix>`)**: Must return the exact lexicographically sorted set of oracle keys starting with `<prefix>` that have occurrences in `[from, input-size)` (unless rejected with `413 Content Too Large` under the server's matched-key cap).
   - **Non-Inclusion Probes**: Queries for disjoint keys and prefixes outside the generated keyspace must prove zero matches.
4. **HTTP Status-Code & Parameter Conformance**: Dedicated conformance probes exercise normative `tlog-vindex` error handling once the target server is ready:
   - **`400 Bad Request`**: `/keys` with neither or both of `key` and `prefix`, empty keys, non-canonical bytes (`NUL`, space `0x20`, or length `> 1024`), and `/values` with missing `key`, missing `before`, `before=0`, or leading-zero integers (`before=01`).
   - **`404 Not Found`**: `/values` for a valid canonical key with zero occurrences in `[from, before)` when `1 <= before <= indexed_size`.
   - **`503 Service Unavailable`**: `/values` when `before` exceeds the target's currently indexed Input Log size (and transient `503` responses prior to initial checkpoint publication).
5. **Optional Output Log `tlog-tiles` Conformance**: When `<output-log-url>` is supplied (`--output_log_url`), a background verifier polls `<output-log-url>/checkpoint` and `/tile/entries/...` directly, verifying Output Log checkpoint signatures/witnesses, cross-checkpoint Merkle consistency (detecting rollbacks or split views), entry bundle Merkle authentication, 6-line `c2sp.org/tlog-vindex-state@v1` formatting, monotonic `input-size` advancement, and `input-root` consistency against the hammer's Input Log.

---

## 2. Alternatives Considered

### 2.1 Executing `.wasm` Guest Modules in the Hammer vs. Pure-Go Reference Mapping
- **Proposed**: Running the same compiled `.wasm` guest binary inside the hammer to predict expected keys for generated Input Log entries.
- **Rejection**: Executing shared `.wasm` bytecode creates a common-mode blind spot (any bug in the guest code, compiler toolchain, or host ABI agrees with itself) and couples a black-box conformance tool to WebAssembly even when testing third-party `tlog-vindex` implementations that do not use WASM.
- **Chosen Design**: Evaluate `raw`, `sumdb`, and `ct` mapping functions natively in pure Go using standard library parsers, cross-checked against the repository's `.wasm` examples in unit tests.

### 2.2 Proof-Only Self-Consistency Checks vs. Ground-Truth Oracle Verification
- **Proposed**: Verifying only cryptographic proofs and cross-query monotonicity without tracking ground-truth key occurrences from the Input Log.
- **Rejection**: A defective or misconfigured target indexer that omits keys during mapping (or indexes an empty trie) serves cryptographically valid MPT non-inclusion proofs and monotonic empty histories, passing proof-only checks with 0% recall.
- **Chosen Design**: Pair full `tlog-vindex` proof verification with an exact ground-truth `(key -> entry_indices)` and `(input-size -> input-root)` oracle fed directly by the hammer's Input Log sequencer.

### 2.3 In-Process Storage Hooks vs. Strictly External HTTP Harness
- **Proposed**: Inspecting internal Prometheus metrics or Pebble/MPT state directly to measure indexing lag and readiness.
- **Rejection**: Breaks compatibility with external partner implementations written in other languages or using different storage backends.
- **Chosen Design**: Derive ingestion lag (`input_log_size - indexed_size`), readiness, throughput, latency, and conformance strictly from standard `tlog-tiles` and `tlog-vindex` HTTP endpoints.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/hammer/... ./vindex/cmd/hammer/...
```
