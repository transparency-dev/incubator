# Independent Log Auditor

This document defines the architecture, continuous audit loop, root mismatch alerting, state-preserving halt protocols, and adversarial threat model for the **Auditor Subsystem** (`vindex/internal/auditor`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & The Operator Trust Dilemma
The index operator publishes an Output Log asserting that its verifiable index accurately, completely, and deterministically represents the underlying Input Log over `[from, input_size)`.

However, in a verifiable transparency architecture, lookup clients and ecosystem monitors cannot simply trust the index operator's claims. A compromised, coerced, or buggy index operator could:
1. **Targeted Omission Attacks**: Commit an invalid `mpt_root` that silently conceals specific certificates, packages, or identities, while returning valid-looking non-inclusion proofs against that forged `mpt_root`.
2. **Equivocation & Split-Views**: Present conflicting Output Log checkpoints to different monitors or lookup clients.
3. **Historical Rollbacks & Parameter Drift**: Regress tree sizes or mutate `map-fn` or `from` across Output Log entries.

To enforce cryptographic integrity, independent third parties must be able to audit the index operator's Output Log state commitments from `from` to the Output Log head without trusting the `/keys` or `/values` HTTP endpoints. If the index operator cheats or state divergence is detected, the auditor halts forward sync, freezes on-disk state to preserve forensic evidence, and alerts operators.

### 1.2 The Independent Auditor & Forensic Freeze Analogy
The auditor operates as an independent external auditor paired with a forensic freeze:
- **The Audit**: Like a forensic accountant re-running a company's general ledger from raw bank statements (Input Log entries) and checking whether every published balance sheet (`mpt_root` in each Output Log entry) matches down to the exact bit.
- **The Forensic Freeze**: If the locally reconstructed `mpt_root` diverges by even a single bit, the auditor raises an immediate alert (`vindex_auditor_root_mismatch = 1`), freezes the physical database files on disk to preserve uncorrupted forensic evidence, and halts forward sync until human operators triage the divergence.

### 1.3 Goals, Non-Goals & Future Work
- **Goals**:
  - Continuously audit published Output Log index state commitments (`c2sp.org/tlog-vindex-state@v1`) against authenticated Input Log entries starting from the configured `from` index (default `0`).
  - Verify Output Log and Input Log checkpoints against [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) trust policies using `filippo.io/torchwood` (`torchwood.Policy` and `torchwood.VerifyCheckpoint`).
  - Assert cryptographic equality between the independently reconstructed local `mpt_root` and the index operator's committed `mpt_root` at every Output Log entry.
  - Signal divergence immediately via Prometheus metrics (`vindex_auditor_root_mismatch = 1`, `vindex_auditor_root_mismatches_total`), structured logs, and readiness probe degradation (`/readyz` on `--metrics_addr`).
  - Freeze physical database state on root mismatch to preserve forensic post-mortem evidence.
- **Non-Goals**:
  - **No Automatic Retry / Self-Healing on Root Mismatch**: If a root mismatch occurs, the auditor does not guess or retry; it halts immediately to preserve evidence of operator fraud or software bugs.
  - **No Operator Checkpoint Generation**: The auditor does not sign or publish Output Log checkpoints; it is strictly an independent consumer and auditor.
  - **No HTTP Lookup Serving**: The auditor does not serve `/keys` or `/values` lookup queries; verified read-mirror serving is out of scope.
- **Future Work (Verified Mirror Serving)**:
  - Because an auditor already maintains a locally verified MPT and Pebble chunk store, it could in principle also serve C2SP lookup queries (`/keys` and `/values`) as a read mirror. Mirror serving is intentionally omitted for now: `c2sp.org/tlog-vindex` does not specify mirror semantics, and serving lookups from an auditor introduces protocol design questions around which Output Log checkpoint is served and how to satisfy the `index == output_size - 1` latest-entry proof requirement when an auditor lags or halts behind the index operator's Output Log head. This capability can be revisited in future work once specified.

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Integrates `filippo.io/torchwood` (`torchwood.Policy`, `torchwood.VerifyCheckpoint`), the tile fetcher and local tile cache ([`internal/ingest`](../ingest/README.md)), the KV chunk store ([`internal/kvstore`](../kvstore/README.md)), and the MPT (`internal/mpt`).
- **Known Pain Points ("Warts and All")**:
  - **Hardware Sizing Parity**: Running a full-log auditor requires the same RAM and NVMe disk capacity as the index operator to maintain the local MPT and Pebble chunk store.
  - **Audit Catch-Up vs. Issuance Velocity**: When catching up from `from`, a newly provisioned auditor experiences initial sync lag. However, because VIndex's indexing pipeline processes 90,000 to 240,000+ entries/sec—orders of magnitude faster than steady-state transparency log issuance rates (50 to 500 entries/sec)—catch-up over tens of millions of Input Log entries completes in hours rather than months, provided historical Input Log entry bundles in `[from, input_size)` remain retrievable.

---

## 2. Detailed Design

### 2.1 Ecosystem Verification Architecture & Policy Configuration

VIndex verification operates across two complementary boundaries:

| Role & Component | Execution Scope | Target Consumer | Threat Coverage |
| :--- | :--- | :--- | :--- |
| **Lookup Client Verification** ([`client/`](../../client/README.md)) | Verifies individual `/keys` and `/values` responses against witnessed Output Log checkpoints. | Lookup clients, end-user apps, CLIs. | Verifies inclusion/non-inclusion/prefix proofs for queried keys; verifies `torchwood.Policy` witness quorums; verifies backward Value Log pagination chains. |
| **Full-Log Independent Auditor** (`vindex/internal/auditor`) | Independently replays all Input Log entries in `[from, input_size)` and reconstructs the full MPT across every Output Log entry. | Standalone monitoring daemon (`vindex-auditor`). | Detects operator equivocation, forged `mpt_root` commitments, `map-fn`/`from` drift, targeted omission of unqueried keys, and tree rollbacks; enforces `torchwood.Policy` witness quorums and Merkle consistency. |

#### Auditor Configuration & `torchwood.Policy` Enforcement
The auditor daemon is configured with `<output-log-url>`, the Input Log entry retrieval endpoint, the expected 32-byte `map-fn` commitment digest, the configured start index `from` (`0` by default, or `> 0` for suffix indices), and C2SP `tlog-policy` policies (`torchwood.Policy` from `filippo.io/torchwood`, parsed via `torchwood.ParsePolicy`) for both the Output Log and the Input Log. Every Output Log checkpoint and embedded Input Log checkpoint is verified via `torchwood.VerifyCheckpoint` before any entries are processed.

### 2.2 The Continuous Audit Loop
Initialized with an empty local MPT and `prev_size = from` (or, on process restart, after running local Phase 2 MPT catch-up across `[max(MPT_Durable_Size, from), audited_input_size)` if the MPT's persisted `(version, exact)` lags `audited_input_size`), the auditor polls `<output-log-url>/checkpoint` and extracts each target Input Log checkpoint directly from the Output Log's `c2sp.org/tlog-vindex-state@v1` entries (never polling the Input Log's `/checkpoint` endpoint directly), executing the 5-step audit loop defined in [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md):

| Step | Phase | Action & Operations | Verification Check |
| :--- | :--- | :--- | :--- |
| **1** | **Poll Output Checkpoint** | Fetches `<output-log-url>/checkpoint`. | Verifies origin and witness cosignatures via `torchwood.VerifyCheckpoint` against the Output Log `torchwood.Policy`, and verifies Merkle consistency against the previously audited Output Log checkpoint. |
| **2** | **Stream Output Entries** | Fetches new Output Log entry bundles from `<output-log-url>/tile/entries/...` from the last audited `output_size` up to the new `output_size`. | Authenticates entry bundles against the verified Output Log checkpoint root hash per `tlog-tiles`, parses each `c2sp.org/tlog-vindex-state@v1` entry, asserts `map-fn` and `from` match configured parameters, verifies the embedded Input Log checkpoint via `torchwood.VerifyCheckpoint` against the Input Log `torchwood.Policy` to obtain `input_size`, checks `prev_size <= input_size`, and (after the first Output Log entry) verifies Merkle consistency with the previous entry's Input Log checkpoint. |
| **3** | **Fetch & Map Input Entries** | Downloads Input Log entries in `[prev_size, input_size)` (slicing non-256-aligned initial `from` or partial tail bundles), filters already-persisted entries, and stages chunk updates into Pebble. | Authenticates Input Log entry bundles against the embedded Input Log checkpoint root hash, executes sandboxed `MapFn`, checks that every emitted key is a valid canonical key (`1..1024` bytes in `0x21..0x7E`), deduplicates keys per `entry_idx`, appends `value_log_leaf_hash(entry_idx)` to each key's Value Log, and enforces replay deduplication. |
| **4** | **Predict Candidate MPT Root** | Evaluates modified `(key, value_root)` pairs against the local MPT without mutating verified tree state. | Computes the candidate local `mpt_root` in memory under a shared read lock. |
| **5** | **Assert Root Equality & Commit** | Asserts that the candidate local `mpt_root` equals the committed `mpt_root` in the Output Log entry. | **Match**: Commits staged Pebble chunks and MPT mutations, sets `prev_size = input_size`, and persists verified watermarks.<br>**Mismatch**: Triggers state-preserving halt, discards uncommitted staging batch, freezes database files, and emits alerts. |

#### Step Details:
1. **Discover & Authenticate Output Checkpoint**: Polls `<output-log-url>/checkpoint`, verifies origin and witness cosignatures via `torchwood.VerifyCheckpoint` against the Output Log `torchwood.Policy`, and verifies a Merkle consistency proof from the previously audited Output Log checkpoint. If policy or consistency verification fails, the checkpoint is rejected before reading any entries.
2. **Stream State Commitments & Validate Embedded Input Checkpoints**: Fetches new Output Log entry bundles from `<output-log-url>/tile/entries/...` and authenticates them against the Output Log checkpoint root hash according to `tlog-tiles`. For each `c2sp.org/tlog-vindex-state@v1` Output Log entry in sequential order, checks that `map-fn` and `from` match the auditor's configured parameters, verifies the embedded `<input-log-checkpoint>` via `torchwood.VerifyCheckpoint` against the Input Log `torchwood.Policy`, lets `input_size` be its tree size, checks `prev_size <= input_size`, and (after the first Output Log entry) verifies Merkle consistency with the previous Output Log entry's embedded Input Log checkpoint.
3. **Fetch & Map Input Entries**: For the Input Log entry range `[prev_size, input_size)`:
   - Fetches Input Log entry bundles and authenticates them against the embedded Input Log checkpoint root hash (`tlog-tiles` or `static-ct-api`), slicing boundary 256-entry bundles to `[prev_size, input_size)` so entries `< from` on non-256-aligned initial bundles and entries `>= input_size` on partial tail bundles are excluded.
   - Executes the WASM `MapFn` on each Input Log entry at `entry_idx` in sequential order, validates that every emitted key is a canonical key (`1..1024` printable ASCII bytes in `0x21..0x7E`), and discards duplicate keys emitted for the same `entry_idx`.
   - **Replay Deduplication Invariant**: On restart or crash replay, any Input Log entry indices `< from` or already persisted in Pebble are filtered out prior to appending `value_log_leaf_hash(entry_idx)` to active chunks while still reconstructing their `(key, GetValueRoot(keyHash, input_size))` pairs from Pebble for Step 4, ensuring idempotent crash recovery without false root mismatches.
4. **Predict Candidate MPT Root**: Evaluates modified `(key, value_root)` mappings at `input_size` against the local MPT using non-mutating prediction to compute the candidate local `mpt_root`.
5. **Root Equality Assertion & Commit**: Checks that the candidate local `mpt_root` equals the Output Log entry's `mpt_root`:
   - If equal: atomically commits staged Pebble `'c'` chunks together with `audited_output_size` and `audited_input_size` (`prev_size = input_size`) in a single Pebble write batch before committing and syncing MPT mutations (`KV_CP >= MPT_Durable_Size`). If the process crashes between the Pebble commit and MPT `fsync`, startup MPT catch-up replays `[max(MPT_Durable_Size, from), audited_input_size)` from local storage before auditing the next Output Log entry.
   - If divergent: enters the state-preserving halt protocol without advancing watermarks or mutating the verified MPT and Pebble state.

### 2.3 Root Mismatch Alerting & State-Preserving Halt
If the candidate local `mpt_root` differs from the committed `mpt_root`, or an upstream consistency/policy fault is detected, the auditor immediately executes a coordinated containment response:

1. **Sync Engine Halt**:
   - The background audit loop terminates immediately.
   - Verified watermarks are **not** advanced on disk.
2. **Forensic State Freeze**:
   - Discards the uncommitted Pebble staging batch while leaving verified Pebble DB and MPT files intact on disk, freezing the exact pre-divergence state for forensic triage and public misbehavior reporting.
3. **Metrics & Structured Logging**:
   - Increments `vindex_auditor_root_mismatches_total`.
   - Sets gauge `vindex_auditor_root_mismatch = 1`.
   - Emits structured error logs recording the divergent output entry index, target `input_size`, candidate local root, and committed root.
4. **Health and Readiness Probes (`--metrics_addr`, Non-Public)**:
   - `/healthz`: Remains **HTTP 200 OK** as long as the auditor process is alive, preventing container orchestrators from restarting the halted process and disturbing frozen forensic state or diagnostic endpoints.
   - `/readyz`: Returns **HTTP 503 Service Unavailable** on `--metrics_addr` with structured JSON diagnostics:
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

### 2.4 Adversarial Threat Vector Matrix

| Threat Vector | Adversary Action | Detection Mechanism | Auditor Action |
| :--- | :--- | :--- | :--- |
| **Operator Equivocation** | Index operator serves conflicting Output Log checkpoints to different auditors or witnesses. | `torchwood.VerifyCheckpoint` policy verification; Merkle consistency proofs between Output Log checkpoints. | Audit loop halts immediately; alert logged; database frozen. |
| **Tree Size Rollback** | Index operator serves an Output Log checkpoint (or embedded Input Log checkpoint) smaller than previously audited watermarks. | Monotonic `output_size` and `prev_size <= input_size` assertions during audit poll. | Audit loop halts; watermarks frozen; `/healthz` remains HTTP 200; `/readyz` reports `503` degraded status. |
| **Forged MPT Root (Omission)** | Index operator commits an invalid `mpt_root` in an Output Log entry to hide or fabricate records. | Local MPT reconstruction from authenticated Input Log entries; root equality check against the Output Log entry. | Increments `vindex_auditor_root_mismatches_total`; sets `vindex_auditor_root_mismatch = 1`; freezes disk state; `/readyz` reports `503` degraded status. |
| **Corrupted Input Entries** | Network attacker or corrupted CDN alters raw Input Log entry bundles. | Entry bundle Merkle authentication fails against the signed Input Log checkpoint root hash. | Pipeline rejects entry bundle; retries transient fetch errors without advancing state. |
| **Unauthenticated Output Entries** | Index operator serves Output Log entry bundles that do not match the Output Log checkpoint root. | `tlog-tiles` entry bundle Merkle authentication fails against the Output Log checkpoint root hash. | Entry bundle rejected; audit loop terminates with an authentication error. |
| **Parameter Drift (`map-fn` / `from`)** | Index operator publishes an Output Log state commitment altering `map-fn` or `from`. | State commitment parser checks `map-fn` and `from` against the auditor's configured parameters on every Output Log entry. | Audit loop halts immediately; state frozen; alerts emitted. |

### 2.5 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Strict Root Equality Assertion**:
  - *Rule*: For every processed Output Log entry, the candidate `mpt_root` computed from authenticated Input Log entries in `[from, input_size)` must equal the `mpt_root` committed in the `c2sp.org/tlog-vindex-state@v1` payload.
  - *Rationale*: Guarantees that the index operator's published index state is 100% faithful to the Input Log.
  - *Consequence ("Or Else")*: Accepting mismatched roots would allow a malicious or buggy index operator to conceal or fabricate key occurrences without detection.

- **[Correctness Invariant] Monotonic Progression & Log Consistency**:
  - *Rule*: Each successive Output Log entry must satisfy `from <= prev_size <= input_size` and Merkle consistency across both consecutive Output Log checkpoints and consecutive embedded Input Log checkpoints.
  - *Rationale*: Transparency logs are append-only; historical tree prefixes and sizes cannot shrink or rewrite prior entries.
  - *Consequence ("Or Else")*: An index operator or upstream log could roll back or rewrite historical entries undetected.

- **[Performance Optimization] High-Throughput Catch-Up Architecture**:
  - *Mechanism*: Reuses the core batching pipeline (256-entry bundle fetching, Wazero worker pool, host SIMD SHA-256 hashing, and Pebble batch staging).
  - *Impact*: Sustains 90,000 to 240,000+ entries/sec, allowing a newly provisioned auditor to catch up over tens of millions of historical Input Log entries in hours.

### 2.6 Operational Runbook: Responding to Mismatches
When a root mismatch alert fires (`vindex_auditor_root_mismatch == 1` or `/readyz` returning `HTTP 503` with `"auditor root hash mismatch"`):
1. **Triage & Containment**: The auditor has automatically halted forward sync and frozen database state on disk. Do not restart the auditor with cleared storage, as the disk preserves forensic state immediately prior to the divergent Output Log entry.
2. **Inspect Structured Logs**: Examine auditor logs and `/readyz` diagnostics to record the divergent output entry index, target `input_size`, `local_root`, and `committed_root`.
3. **Forensic State Extraction**: Inspect local Pebble DB inverted chunks (`'c'`) and compare against raw Input Log entries in `[prev_size, input_size)` to determine whether the index operator omitted entries, altered canonical keys, or suffered a non-deterministic `MapFn` bug.
4. **Reproduce via Standalone CLI**: Run `vindex-auditor --oneshot` with an isolated scratch directory against the target Output Log checkpoint to confirm deterministic reproducibility.
5. **Publish Misbehavior Bundle**: If `MapFn` and the Input Log entries are valid, publish the cryptographic proof bundle (witnessed Output Log checkpoint, Output Log inclusion proof, raw `c2sp.org/tlog-vindex-state@v1` entry, and signed Input Log checkpoint) to transparency witnesses and public monitoring channels.

### 2.7 Auditor Contract

The auditor subsystem provides continuous full-log state verification:

- **Inputs**:
  - Output Log URL (`<output-log-url>`) and Output Log `torchwood.Policy` (`filippo.io/torchwood`).
  - Input Log entry retrieval endpoint and Input Log `torchwood.Policy` (`filippo.io/torchwood`, used strictly to verify embedded Input Log checkpoints, consistency proofs, and entry bundles; never polled for `/checkpoint`).
  - Compiled WASM `MapFn` module, expected 32-byte `map-fn` SHA-256 commitment digest (pending [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md)'s pre-1.0 provenance-manifest `TODO`), and configured start index `from` (default `0`).
  - Local Pebble DB and MPT storage directories.
  - Non-public operational listener (`--metrics_addr`), serving `/healthz`, `/readyz`, `/metrics`, and `/debug/pprof/*`.
- **Outputs**:
  - Continuous audit telemetry (`vindex_auditor_root_mismatch`, `vindex_auditor_root_mismatches_total`) and `/readyz` JSON diagnostics on `--metrics_addr`.
- **Safety Guarantees**:
  - Never signs or publishes Output Log checkpoints.
  - Never commits unverified state to disk: candidate MPT roots are predicted and checked against the Output Log entry commitment before committing staged Pebble chunks, mutating the verified MPT, or advancing watermarks.
  - Immediately halts forward sync and preserves forensic state on any `torchwood.VerifyCheckpoint` failure, Merkle consistency failure, tree size regression, `map-fn` or `from` mismatch, entry bundle authentication failure, invalid canonical key emission, or `mpt_root` mismatch.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Lookup Client Verification Alone vs. Full-Log Independent Auditing
- **Proposed**: Relying exclusively on lookup clients (`vindex/client`) to verify individual query responses, omitting a full-log auditor.
- **Theoretical Rejection**: Lookup client verification proves inclusion or non-inclusion against `mpt_root` only when a key is queried, and cannot verify that `mpt_root` itself was faithfully constructed from the Input Log without omissions across unqueried keys.
- **Chosen Design**: Complementary verification: lightweight lookup client SDK ([`client/`](../../client/README.md)) for per-query proof verification against witnessed checkpoints, paired with `vindex/internal/auditor` for continuous full-log replay auditing.

### 3.2 Ephemeral In-Memory Auditing vs. State-Preserving Forensic Freezing
- **Proposed**: Storing auditor state ephemerally in RAM or wiping local database files upon detecting an upstream error.
- **Operational Rejection**: Wiping or discarding state upon detecting a forged `mpt_root` destroys the exact pre-divergence state needed to pinpoint omitted Input Log entries and produce a reproducible misbehavior report against the index operator.
- **Chosen Design**: State-preserving halt: the auditor freezes verified Pebble DB and MPT files in-place, exposes structured JSON diagnostics on `/readyz`, keeps `/healthz` at `HTTP 200 OK` so orchestrators do not restart the halted process, and stops forward sync.

---

## 4. Verification Gate

All auditor replay, `torchwood.Policy` verification, and root mismatch forensic freeze tests are verified via:

```bash
go test -race ./vindex/internal/auditor/...
```
