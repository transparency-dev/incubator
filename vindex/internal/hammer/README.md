# Hammer Load Testing & Verification Framework

This document defines the architecture, workload generation models, drip-feed scheduling protocols, cryptographic invariant verification rules, and operational telemetry for the internal **Hammer Integration Load-Testing & Verification Package** (`vindex/internal/hammer`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Integration Testing Dilemma
Unit tests verify isolated package logic, but critical failure modes in a verifiable index only emerge under **sustained, concurrent read-write load**:
1. **LSM Compaction Stalls**: Heavy write ingestion triggers background Pebble LSM compactions that can spike read latency or stall batch commits.
2. **Lock Contention & Race Conditions**: High-frequency updates to hot keys stress in-memory MPT path compression and exclusive writer lock transitions, risking deadlocks or tail-latency regressions against concurrent HTTP lookups.
3. **Chunk Boundary Rollovers**: Inverted Value Log chunks roll over every 65,536 Input Log entries; verifying that multi-chunk backward pagination reconstructs complete, unbroken Value Logs requires driving individual hot keys across multiple 65,536-entry boundaries.

Validating that `vindexd` preserves cryptographic integrity, zero data loss, and sub-millisecond read serving requires an internal integration load-testing and verification package (`vindex/internal/hammer`) that simultaneously acts as the upstream Input Log producer and a pool of concurrent lookup clients.

### 1.2 The "Crash Test Rig" Harness
The **VIndex Hammer** (`vindex/internal/hammer`, executed via `cmd/hammer`) operates like an automotive crash test rig:
- **Upstream Input Log Producer (Top Bread)**: Drives a real local append-only Tessera transparency log, synthesizing Input Log entries across Zipfian and uniform key distributions and controlling checkpoint release schedules (drip-feeding) to simulate upstream network dynamics.
- **System Under Test (The Meat)**: Exercises `vindexd` (`internal/coordinator`, `internal/ingest`, `internal/kvstore`, `internal/tree`, and [`internal/server`](../server/README.md)) over real loopback HTTP and POSIX storage.
- **Downstream Lookup Clients (Bottom Bread)**: Runs a pool of concurrent reader workers querying `<index-url>/keys` and `<index-url>/values` via [`client/`](../../client/README.md), cryptographically verifying every response and asserting that observed history never regresses.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Provide an internal integration load-testing and verification harness (`vindex/internal/hammer`) for stressing `vindexd` under multi-million-entry workloads with heavy Zipfian key skew.
  - Simulate upstream Input Log CDN behaviors via steady, burst, and pause/catch-up checkpoint drip schedules.
  - Assert [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) cryptographic invariants (`torchwood.Policy` checkpoint and inclusion proof verification, MPT proofs, Value Log compact range roots, and monotonic history) on 100% of lookup queries.
  - Render real-time terminal telemetry tracking ingestion throughput (entries/sec), read QPS, latency percentiles, and invariant checks.
- **Non-Goals**:
  - **Not a Public SDK Package**: `vindex/internal/hammer` is strictly an internal test and benchmark harness, not an external library API.
  - **Not a Production Log Sequencer**: Designed exclusively for integration testing, benchmarking, and chaos verification.
  - **Not an In-Memory Mock**: Executes real HTTP requests (`http://127.0.0.1:8085` -> `:8088`) against real POSIX files.

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Integrates `tessera` (POSIX storage, appender, publication awaiter) and [`client/`](../../client/README.md) (`vindex/client`).
- **Known Pain Points ("Warts and All")**:
  - **Host Core Contention**: Running both `cmd/hammer` and `vindexd` on a single workstation causes CPU-heavy entry generation and WASM worker pools to compete for physical cores.
  - **File Descriptor Saturation**: Running hundreds of concurrent lookup clients across high-rate HTTP connections can exhaust OS file descriptors unless `ulimit -n` is raised.

---

## 2. Detailed Design

### 2.1 Component Architecture & Pipeline Map

| Subsystem Component | Source File | Core Responsibility |
| :--- | :--- | :--- |
| **Synthetic Entry Generator** | `generator.go` | Emits structured synthetic Input Log entries across Zipfian, Pareto, Uniform, and Non-Inclusion distributions (`raw`, `sumdb`, or `ct` formats). |
| **Tessera Sequencer** | `sequencer.go` | Writes Input Log entries into a local POSIX append-only log, computes Merkle roots, and signs Input Log checkpoints. |
| **Drip-Feed HTTP Server** | `server.go` | Serves standard C2SP `tlog-tiles` endpoints (`:8085`, `/checkpoint` and `/tile/...`) and schedules checkpoint releases (steady, burst, pause). |
| **Verifying Concurrent Readers** | `reader.go` | Queries `vindexd` (`GET <index-url>/keys` and `GET <index-url>/values`) via [`client/`](../../client/README.md) and cryptographically verifies 100% of lookup responses. |
| **Metrics Analyzer & Dashboard** | `analyzer.go` | Aggregates latency percentiles, read QPS, ingestion lag, and invariant assertions into periodic stdout summaries. |

---

### 2.2 Synthetic Workload Distributions (`generator.go`)
The entry generator synthesizes Input Log entries across raw key/value, Go SumDB (`<module> <version> h1:<hash>`), and Certificate Transparency (`ct`) formats:

1. **Zipfian / Pareto Skew (`alpha > 1`, `--zipf_s=1.2`)**:
   - Models realistic registries where the hottest 1% of canonical keys account for over 80% of all Input Log entries.
   - **Targeted Stress**: Drives individual hot keys across multiple 65,536-entry chunk boundaries, verifying that chunk rollovers (`^0 -> ^1`), Pebble SSTable compactions, and multi-page backward `/values` scans preserve unbroken Value Log continuity.
2. **Uniform Distribution**:
   - Spreads Input Log entries evenly across a wide canonical keyspace (`[0, K)`) to stress MPT branch fanout and 33-byte Pebble prefix Bloom filter performance.
3. **Non-Inclusion Keys**:
   - Issues `/keys?key=nonexistent/<id>` and `/keys?prefix=nonexistent/` probes for keys never appended to the Input Log, exercising cryptographic MPT non-inclusion proofs (`0` matched key lines in `c2sp.org/tlog-vindex-keys@v1`).

---

### 2.3 Tessera Sequencer & Drip-Feed HTTP Server (`sequencer.go`, `server.go`)
To evaluate `vindexd` under varied upstream conditions, the hammer controls Input Log checkpoint visibility:

- **POSIX Storage & Signer**: Appends generated Input Log entries to a local directory using `tessera.NewAppender`, signing Input Log checkpoints with an ephemeral test Ed25519 key.
- **Drip-Feed Schedules**:
  - **Steady Drip**: Releases queued Input Log checkpoints at a fixed rate (`--drip_rate` checkpoints/sec), simulating steady upstream log integration.
  - **Burst Mode**: Buffers generated checkpoints and releases them in sudden bursts (`--burst_size` every `--burst_interval`), simulating upstream batch publications.
  - **Pause & Catch-Up Mode**: Holds checkpoint publication for a configurable window so `vindexd` idles, then exposes a deep backlog of 256-entry bundles to benchmark catch-up throughput.

---

### 2.4 Verifying Concurrent Readers (`reader.go`)
A pool of worker goroutines (`--num_readers`, rate-limited by `--max_read_qps`) issues continuous point and prefix lookups against `vindexd` (`GET <index-url>/keys?key=<key>`, `GET <index-url>/keys?prefix=<key-prefix>`, and `GET <index-url>/values?key=<key>&before=<before>`), validating every response through [`client/`](../../client/README.md):

#### Query Verification Sequence:
1. **Output Log Proof & State Commitment**: Verifies `<output-log-checkpoint>` and `c2sp.org/tlog-proof@v1` against `OutputLogPolicy` (`torchwood.VerifyCheckpoint` + `torchwood.VerifyProof`, asserting `output_size >= 1` and canonical decimal `index == output_size - 1`) and verifies the embedded `<input-log-checkpoint>` in `c2sp.org/tlog-vindex-state@v1` against `InputLogPolicy` (`torchwood.VerifyCheckpoint`).
2. **MPT Proof Verification**: Verifies the `c2sp.org/tlog-vindex-keys@v1` binary MPT inclusion, non-inclusion, or two-sided prefix proof against `mpt_root` (`VerifyKeysResponse`).
3. **Value Log Compact Range Verification**: Paginates `/values` backward from `before = InputSize` via `ValuesResponse.NextPage()` while `Preceding > 0`, reconstructing the RFC 6962 Value Log root from `preceding` compact range hashes and returned Input Log entry indices (`VerifyValuesResponse`).
4. **Monotonic State & History Assertions**: Shared `client.StateTracker` enforces monotonicity and non-equivocation across `output_size` and `input_size` and constancy of `map-fn` and `from` (`ErrCheckpointRegressed`, `ErrConsistencyFault`). In addition, per-key history tracking asserts that for any two queries on key `K` at `input_size_new >= input_size_old`, the returned entry index slice `I_new` is a prefix-preserving superset of `I_old` (`len(I_new) >= len(I_old)` and `I_new[:len(I_old)] == I_old`).

---

### 2.5 In-Situ Invariants & Performance Assertions

- **[Correctness Invariant] Zero-Tolerance Cryptographic Failure**:
  - *Rule*: Any verification error from `vindex/client` (failed `torchwood.Policy` verification, invalid MPT proof, or mismatched Value Log compact range root) immediately records an invariant violation and fails the hammer run.
  - *Rationale*: A verifiable index must never serve forged, torn, or unverifiable responses under any read/write concurrency stress.
  - *Consequence ("Or Else")*: Tolerating transient proof errors would mask race conditions between MPT snapshots, Output Log witnessing, and Pebble chunk flushes.

- **[Correctness Invariant] Monotonic History Superset**:
  - *Rule*: For repeated queries on canonical key `K` where `input_size_new >= input_size_old`, `I_new` must be a superset of `I_old` with an identical prefix (`I_new[:len(I_old)] == I_old`), alongside `client.StateTracker` state commitment ratcheting.
  - *Rationale*: Input Logs and per-key Value Logs are strictly append-only; committed Input Log entry indices can never vanish, shrink, or reorder.
  - *Consequence ("Or Else")*: Any violation proves chunk rollover corruption, out-of-order batch commits, or broken snapshot isolation.

---

### 2.6 CLI Usage & Configuration Parameters (`cmd/hammer`)

```bash
# Run 100,000-entry Zipfian stress test with 50 concurrent lookup clients
go run ./vindex/cmd/hammer \
  --storage_dir=/tmp/hammer-inputlog \
  --listen_addr=:8085 \
  --vindex_url=http://127.0.0.1:8088 \
  --write_goal=100000 \
  --key_distribution=zipf \
  --num_keys=10000 \
  --zipf_s=1.2 \
  --write_rate=5000 \
  --drip_rate=10 \
  --max_read_qps=500 \
  --num_readers=50
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 In-Process Go Unit Test Mocks vs. Out-of-Process "Map Sandwich"
- **Proposed**: Stress-testing `vindexd` purely in-memory using mocked storage and channel harnesses.
- **Practical Rejection**: In-memory mocks miss real concurrency and I/O dynamics—loopback HTTP connection pooling, OS scheduler preemption, `mmap` page flushing, and Pebble LSM compaction stalls.
- **Chosen Design**: Real HTTP client/server execution backed by POSIX Tessera tiles, Pebble SSTables, and `mmap` MPT files.

### 3.2 Static Pre-Recorded Log Dumps vs. Dynamic Drip-Feed Sequencer
- **Proposed**: Replaying a fixed snapshot of an existing public transparency log.
- **Practical Rejection**: Static dumps cannot modulate write rates on demand, dial exact Zipfian skew to force 65,536-entry chunk rollovers, inject targeted non-inclusion probes, or orchestrate pause/burst checkpoint schedules.
- **Chosen Design**: Deterministic synthetic entry generator paired with a programmable drip-feed `tlog-tiles` sequencer.

---

## 4. Verification Gate

All internal hammer generator, sequencer, and concurrent client verification tests are verified via:

```bash
go test -race ./vindex/internal/hammer/...
```
