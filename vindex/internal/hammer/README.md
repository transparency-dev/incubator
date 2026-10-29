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

### 1.2 Goals & Non-Goals
- **Goals**:
  - Provide an internal integration load-testing and verification harness (`vindex/internal/hammer`) for stressing `vindexd` under multi-million-entry workloads with heavy Zipfian key skew.
  - Act simultaneously as the upstream Input Log producer (serving signed Input Log checkpoints and `tlog-tiles` entry bundles under steady, burst, and pause/catch-up drip schedules) and a pool of concurrent lookup clients.
  - Assert [`docs/tlog-vindex.md`](../../docs/tlog-vindex.md) cryptographic invariants (Output Log checkpoint policy and inclusion proof verification, MPT point/prefix proofs, Value Log compact range roots, and monotonic history) on 100% of lookup queries.
  - Render real-time terminal telemetry tracking ingestion throughput (entries/sec), read QPS, latency percentiles, and invariant checks.
- **Non-Goals**:
  - **Not a Public SDK Package**: `vindex/internal/hammer` is strictly an internal test and benchmark harness, not an external library API.
  - **Not a Production Log Sequencer**: Designed exclusively for integration testing, benchmarking, and chaos verification.
  - **Not an In-Memory Mock**: Executes real HTTP requests over loopback sockets against real POSIX files.

### 1.3 Requirements & Dependencies
- **Dependencies**: Integrates `tessera` (POSIX storage, appender, publication awaiter) and [`client/`](../../client/README.md) (`vindex/client`).

---

## 2. Detailed Design

### 2.1 Component Architecture & Pipeline Map

| Subsystem Component | Core Responsibility |
| :--- | :--- |
| **Synthetic Entry Generator** | Emits structured synthetic Input Log entries across Zipfian/Pareto and uniform key distributions in configurable leaf formats (`raw`, `sumdb`, or `ct`), and provides disjoint non-inclusion probe keys for reader workers. |
| **Tessera Input Log Sequencer** | Writes generated Input Log entries into a local POSIX append-only log, computes Merkle roots, and signs Input Log checkpoints with a configurable or generated Ed25519 signer (printing the verifier key on startup for `vindexd`). |
| **Drip-Feed HTTP Server** | Serves standard C2SP `tlog-tiles` endpoints (`/checkpoint` and `/tile/...`) for the synthetic Input Log and schedules checkpoint visibility across steady, burst, and pause/catch-up modes. |
| **Verifying Concurrent Readers** | Queries `vindexd` (`GET <index-url>/keys` and `GET <index-url>/values`) via [`client/`](../../client/README.md) across hot, uniform, non-inclusion, and full-pagination query mixes, cryptographically verifying 100% of lookup responses. |
| **Metrics Analyzer & Dashboard** | Aggregates latency percentiles, read QPS, ingestion lag, and invariant assertions into periodic terminal summaries. |

---

### 2.2 Synthetic Entry Generation & Leaf Formats
The entry generator synthesizes Input Log entries in raw key/value (`raw`), Go SumDB (`sumdb`, `<module> <version> h1:<hash>`), or Certificate Transparency (`ct`, X.509/precertificate) formats across two write distributions:

1. **Zipfian / Pareto Skew (`alpha > 1`)**:
   - Models realistic registries where the hottest 1% of canonical keys account for over 80% of all Input Log entries.
   - **Targeted Stress**: Drives individual hot keys across multiple 65,536-entry chunk boundaries, verifying that chunk rollovers (`^0 -> ^1`), Pebble SSTable compactions, and multi-page backward `/values` scans preserve unbroken Value Log continuity.
2. **Uniform Distribution**:
   - Spreads Input Log entries evenly across a wide canonical keyspace (`[0, K)`) to stress MPT branch fanout and single-occurrence chunk creation.

---

### 2.3 Tessera Input Log Sequencer & Drip-Feed HTTP Server
To evaluate `vindexd` under varied upstream conditions, the hammer controls Input Log checkpoint visibility:

- **POSIX Storage & Signer**: Appends generated Input Log entries to a local directory using Tessera POSIX storage, signing Input Log checkpoints with a configurable or freshly generated Ed25519 key (and printing the corresponding verifier key at startup so `vindexd` can configure its Input Log checkpoint policy).
- **Drip-Feed Schedules**:
  - **Steady Drip**: Releases queued Input Log checkpoints at a fixed rate, simulating steady upstream log integration.
  - **Burst Mode**: Buffers generated checkpoints and releases them in sudden bursts, simulating upstream batch publications.
  - **Pause & Catch-Up Mode**: Holds checkpoint publication for a configurable window so `vindexd` idles, then exposes a deep backlog of 256-entry bundles to benchmark catch-up throughput.

---

### 2.4 Verifying Concurrent Readers
A pool of concurrent reader workers issues continuous point and prefix lookups against `vindexd` (`GET <index-url>/keys?key=<key>`, `GET <index-url>/keys?prefix=<key-prefix>`, and `GET <index-url>/values?key=<key>&before=<before>`), validating every response through [`client/`](../../client/README.md) configured with the expected `<input-log-origin>`, `<output-log-origin>`, and Output Log checkpoint policy.

#### Reader Query Mix:
Each reader query selects a target key according to a weighted workload mix:
- **Hot Keys (~60%)**: Samples heavily skewed Zipfian keys and verifies the newest `/values` page (single-page break).
- **Uniform Keys (~25%)**: Samples uniformly across the active keyspace and verifies the newest `/values` page.
- **Non-Inclusion Probes (~10%)**: Samples synthetic keys (`nonexistent/<id>`) never appended to the Input Log, exercising cryptographic MPT non-inclusion and empty-prefix proofs (`0` matched key lines in `c2sp.org/tlog-vindex-keys@v1`).
- **Full Backward Pagination (~5%)**: Samples a hot key and walks `MatchedKey.Values(ctx)` all the way back to `preceding == 0` across multiple 65,536-entry chunks.

#### Query Verification Sequence:
1. **Output Log Proof & State Commitment**: `Client.LookupKey` / `Client.LookupPrefix` verifies `<output-log-checkpoint>` and `c2sp.org/tlog-proof@v1` against `ExpectedOutputLogOrigin` and `OutputLogPolicy` (asserting `output_size >= 1` and canonical decimal `index == output_size - 1`) and parses the 6-line `c2sp.org/tlog-vindex-state@v1` record (`input-origin == ExpectedInputLogOrigin` and `0 <= from <= input_size`).
2. **MPT Proof Verification**: Verifies the `c2sp.org/tlog-vindex-keys@v1` binary MPT inclusion, non-inclusion, or two-sided prefix proof against `mpt_root`, returning an immutable `*client.LookupResult` snapshot.
3. **Value Log Compact Range Verification**: Iterates `MatchedKey.Values(ctx)` (either stopping after the newest page on normal hot/uniform probes or walking to `preceding == 0` on full-pagination probes), reconstructing and verifying the RFC 6962 Value Log root from `preceding` compact range hashes and returned Input Log entry indices on every fetched page.
4. **Monotonic History & Parameter Assertions**: Asserts that `LookupResult.From` never regresses across queries. Whenever a query observes the **complete** Value Log history for canonical key `K` (either a single-page result with `preceding == 0` or a full backward pagination walk to `preceding == 0`), the reader records the chronologically ordered entry index slice `I_new` at `input_size_new` and asserts that for any prior complete observation `I_old` at `input_size_old <= input_size_new`, `I_new` is a prefix-preserving superset of `I_old` (`len(I_new) >= len(I_old)` and `I_new[:len(I_old)] == I_old`).

---

### 2.5 In-Situ Invariants & Performance Assertions

- **[Correctness Invariant] Verification & Consistency Fault Discrimination**:
  - *Rule*: Any verification error from `vindex/client` (`ErrVerificationFailed`) or reader-side consistency failure (`From` regression or monotonic history superset violation) immediately records a fatal invariant violation and fails the hammer run, whereas transient operational status codes (`503 Service Unavailable` during startup/backfill or `413 Content Too Large` on broad prefix limits) are tracked in telemetry without failing the run.
  - *Rationale*: A verifiable index must never serve forged, torn, or unverifiable responses under any read/write concurrency stress, while legitimately returning `503` before its first Output Log checkpoint is published.
  - *Consequence ("Or Else")*: Tolerating cryptographic proof errors would mask race conditions between MPT snapshots, Output Log witnessing, and Pebble chunk flushes, while treating initial `503` responses as cryptographic faults would cause false failures during cold startup.

- **[Correctness Invariant] Monotonic History Superset on Complete Scans**:
  - *Rule*: For repeated complete Value Log observations (`preceding == 0` reached) on canonical key `K` where `input_size_new >= input_size_old`, `I_new` must be a superset of `I_old` with an identical prefix (`I_new[:len(I_old)] == I_old`).
  - *Rationale*: Input Logs and per-key Value Logs are strictly append-only; committed Input Log entry indices can never vanish, shrink, or reorder.
  - *Consequence ("Or Else")*: Any violation proves chunk rollover corruption, out-of-order batch commits, or broken snapshot isolation.

---

## 3. Alternatives Considered (or Tried)

### 3.1 In-Process Go Unit Test Mocks vs. Out-of-Process End-to-End Harness
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
