# Independent Log Auditor

Lookup clients ([`client/`](../../client/README.md)) verify that individual query responses match a witnessed Output Log commitment, but they cannot verify that the committed `mpt_root` itself was honestly constructed from the Input Log without omitting or fabricating unqueried keys. `vindex/internal/auditor` (`vindex-auditor`) closes that security loop: it independently replays the Input Log from `from` through the mapping function, recomputes every key's Value Log and the global MPT, and asserts that every state commitment published in the Output Log matches the reconstructed root.

This reference auditor reuses the indexer's Pebble chunk store ([`internal/kvstore`](../kvstore/README.md)) and disk-backed MPT (`internal/mpt`) to share the high-throughput ingestion pipeline (90,000 to 240,000+ entries/sec, requiring equivalent RAM and NVMe sizing) and preserve inspectable on-disk forensic state immediately prior to any divergence. However, reusing the indexer's storage and trie code is not required by the protocol, and relying solely on a single codebase would only verify that the operator ran the same code rather than catching shared implementation bugs. Independent clean-room auditors (written in other languages or using different storage and mapping implementations conforming to [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md#auditing-the-index)) should also audit the Output Log to provide true implementation diversity.

### Non-Goals & Future Work
- **No Automatic Retry / Self-Healing on Root Mismatch**: On any root mismatch or consistency violation, the auditor halts immediately and freezes local disk state to preserve forensic evidence.
- **No Checkpoint Signing or Publication**: Strictly an independent consumer and verifier of the Output Log and Input Log.
- **No HTTP Lookup Serving (Future Work)**: Although an auditor maintains a verified MPT and Pebble chunk store locally, `c2sp.org/tlog-vindex` does not yet specify read-mirror semantics (such as which Output Log checkpoint a lagging or halted auditor serves to satisfy the `index == output_size - 1` latest-entry proof check). Verified mirror serving is deferred to future work.

---

## 1. Design

### 1.1 The Continuous Audit Loop

The auditor is configured with `<output-log-url>`, the Input Log retrieval endpoint (requiring historical entry bundles across `[from, input_size)` to remain retrievable), expected `<output-log-origin>` and `<input-log-origin>`, checkpoint verification policies (such as [C2SP `tlog-policy`](https://c2sp.org/tlog-policy)) for both logs, the compiled WASM `MapFn` module, and the start index `from` (default `0`).

Initialized with an empty local MPT and `prev_size = from` (or, on restart, after replaying local Phase 2 MPT catch-up across `[max(MPT_Durable_Size, from), audited_input_size)` if the MPT's persisted `(version, exact)` lags `audited_input_size`), the auditor executes the 4-step loop defined in [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md):

| Step | Phase | Operations | Verification & Persistence Rules |
| :--- | :--- | :--- | :--- |
| **1** | **Poll Output & Input Checkpoints** | Fetches `<output-log-url>/checkpoint` and a signed Input Log `/checkpoint` (`latest_input_size`, `latest_input_root`, re-fetched whenever a newer Output Log entry commits `input_size > latest_input_size`). | Verifies both checkpoints against their expected origins and checkpoint policies, and verifies Output Log Merkle consistency against the previously audited Output Log checkpoint before reading any entries. |
| **2** | **Stream Output Entries** | Fetches new Output Log entry bundles from `<output-log-url>/tile/entries/...` from the last audited `output_size` up to the new `output_size`. | Authenticates bundles against the verified Output Log checkpoint root per `tlog-tiles`, parses each 6-line `c2sp.org/tlog-vindex-state@v1` entry (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`) in order, asserts `input_origin` and `from` match configured parameters and `prev_size <= input_size <= latest_input_size`, and verifies that `(input_size, input_root)` is Merkle-consistent with `(latest_input_size, latest_input_root)` (checking `input_root == latest_input_root` when `input_size == latest_input_size`). |
| **3** | **Fetch, Map & Calculate Local MPT Root** | Downloads Input Log entry bundles covering `[prev_size, input_size)` (slicing boundary 256-entry bundles to exclude entries `< from` on non-256-aligned initial bundles and entries `>= input_size` on partial tail bundles), maps entries via `MapFn`, updates modified Value Logs and `(canonicalKey, value_root)` mappings in the local MPT, and calculates the resulting local `mpt_root`. | Authenticates Input Log bundles against `input_root` (or `latest_input_root`), validates canonical key bounds (`1..1024` bytes in `0x21..0x7E`), deduplicates keys per `entry_idx`, appends `value_log_leaf_hash(entry_idx)` to each key's Value Log, and updates the local MPT to compute the root at `input_size`. On crash replay, any `entry_idx` already persisted in Pebble is skipped while reconstructing its point-in-time `(canonicalKey, value_root)` at `input_size`. |
| **4** | **Assert Root Equality** | Compares the calculated local `mpt_root` against `mpt_root` in the Output Log entry. | **Match**: Persists the updated chunk state, MPT snapshot, and `audited_output_size` / `audited_input_size` watermarks (`KV_CP >= MPT_Durable_Size`), and sets `prev_size = input_size`.<br>**Mismatch**: Executes the state-preserving halt protocol without advancing verified watermarks, freezing disk state and emitting alerts. |

### 1.2 Root Mismatch Alerting, State-Preserving Halt & Runbook

On any root mismatch or upstream consistency/policy violation, the auditor halts and freezes local database state on disk for forensic triage:

1. **State Freeze & Telemetry**: Terminates the background audit loop without advancing verified watermarks, leaves local Pebble and MPT files intact on disk for inspection, sets the root mismatch gauge metric to `1`, and logs the divergent `output_index`, `input_size`, `local_root`, and `committed_root`.
2. **Operational Probes (Internal Admin Listener)**:
   - `/healthz`: Remains **`200 OK`** while the process is alive so container orchestrators do not restart the halted auditor and disturb frozen disk state.
   - `/readyz`: Returns **`503 Service Unavailable`** with structured JSON diagnostics:
     ```json
     {
       "status": "degraded",
       "error": "auditor root hash mismatch",
       "output_index": 12480,
       "input_size": 3194880,
       "local_root": "a4f1...",
       "committed_root": "b7c2..."
     }
     ```
3. **Operator Runbook**:
   - Do not wipe storage; inspect `/readyz` and structured logs for the divergent `(output_index, input_size, local_root, committed_root)`.
   - Compare local Pebble `'c'` chunks against raw Input Log entries in `[prev_size, input_size)` and re-run the auditor in one-shot mode with an isolated scratch directory to confirm deterministic reproduction.
   - If `MapFn` and Input Log entries are valid, publish the misbehavior proof bundle (witnessed Output Log checkpoint, inclusion proof, raw `c2sp.org/tlog-vindex-state@v1` entry, and signed Input Log checkpoint + consistency proof) to witnesses and monitoring channels.

### 1.3 Adversarial Threat Matrix

| Threat Vector | Adversary Action | Detection Mechanism | Auditor Action |
| :--- | :--- | :--- | :--- |
| **Operator Equivocation** | Serves conflicting Output Log checkpoints to different auditors or witnesses. | Output Log checkpoint policy verification and Merkle consistency proofs between Output Log checkpoints. | Halts audit loop; logs alert; freezes database. |
| **Tree Size Rollback** | Serves an Output Log checkpoint (or `input-size` commitment) smaller than previously audited watermarks. | Monotonic `output_size` and `prev_size <= input_size <= latest_input_size` assertions. | Halts audit loop; freezes watermarks; `/readyz` reports `503`. |
| **Forged MPT Root (Omission)** | Commits an invalid `mpt_root` in an Output Log entry to hide or fabricate records. | Local MPT root calculation from authenticated Input Log entries compared against `mpt_root`. | Freezes disk state; sets mismatch metric; `/readyz` reports `503`. |
| **Corrupted Input Entries** | Alters raw Input Log entry bundles in transit or on CDN. | Entry bundle Merkle authentication fails against verified `input_root` / `latest_input_root`. | Rejects bundle; retries transient fetch errors without advancing state. |
| **Unauthenticated Output Entries** | Serves Output Log entry bundles that do not match the Output Log checkpoint root. | `tlog-tiles` entry bundle Merkle authentication fails against Output Log checkpoint root. | Rejects bundle; terminates audit loop with authentication error. |
| **Parameter Drift (`input-origin` / `from`)** | Publishes an Output Log state commitment altering `input-origin` or `from`. | Checks `input-origin` and `from` against configured parameters on every Output Log entry. | Halts audit loop immediately; freezes state; emits alerts. |

---

## 2. Alternatives Considered

### 2.1 Lookup Client Verification Alone vs. Full-Log Independent Auditing
- **Proposed**: Relying solely on lookup clients ([`client/`](../../client/README.md)) to verify individual query responses without running a full-log auditor.
- **Rejection**: Lookup clients verify proofs against `mpt_root` only for queried keys and cannot detect whether `mpt_root` omitted or fabricated entries across unqueried keys.
- **Chosen Design**: Complementary verification: per-query proof verification in [`client/`](../../client/README.md) paired with continuous full-log replay auditing in `vindex/internal/auditor` (and independent clean-room auditors).

### 2.2 Ephemeral In-Memory Auditing vs. State-Preserving Forensic Freeze
- **Proposed**: Storing auditor state purely in RAM or wiping local database files upon detecting a divergence.
- **Rejection**: Destroys the local state needed to isolate which Input Log entries were omitted or corrupted in `[prev_size, input_size)`.
- **Chosen Design**: State-preserving halt that freezes local Pebble and MPT files in-place without advancing verified watermarks.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/auditor/...
```
