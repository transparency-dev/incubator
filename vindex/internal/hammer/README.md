# Hammer Load Testing & Verification Framework

Unit tests validate isolated package logic, but race conditions, LSM compaction stalls, writer lock contention, and 65,536-entry chunk boundary bugs only surface under sustained concurrent read-write load. `vindex/internal/hammer` is the end-to-end load-testing and verification harness for `vindexd`: it acts simultaneously as a synthetic upstream Input Log producer (serving signed checkpoints and tiled entry bundles across programmable release schedules) and a pool of concurrent lookup clients that cryptographically verify 100% of responses via [`vindex/client`](../../client/README.md).

### Non-Goals
- **Not a Public SDK Package**: Strictly an internal load-testing and verification harness.
- **Not a Production Log Sequencer**: Generates synthetic workloads for stress testing, benchmarking, and chaos verification.
- **Not an In-Memory Mock**: Executes real HTTP requests over loopback sockets against real POSIX tiles, Pebble SSTables, and `mmap` MPT files.

---

## 1. Design

### 1.1 Component Architecture

| Component | Responsibility |
| :--- | :--- |
| **Synthetic Entry Generator** | Emits synthetic Input Log entries across Zipfian/Pareto (`alpha > 1`) and uniform key distributions in configurable leaf formats (`raw`, `sumdb`, or `ct`), plus disjoint non-inclusion probe keys (`nonexistent/<id>`). |
| **Tessera Input Log Sequencer** | Appends generated entries into a local POSIX log, computes Merkle roots, and signs Input Log checkpoints with a configurable or freshly generated Ed25519 key (printing the verifier key at startup for `vindexd`). |
| **Drip-Feed HTTP Server** | Serves standard [C2SP `tlog-tiles`](https://c2sp.org/tlog-tiles) endpoints (`/checkpoint` and `/tile/...`) and schedules checkpoint visibility across steady, burst, and pause/catch-up modes. |
| **Verifying Concurrent Readers** | Queries `vindexd` concurrently via [`vindex/client`](../../client/README.md) across hot, uniform, non-inclusion, and full-pagination query mixes, asserting cryptographic proof validity and monotonic history invariants. |
| **Metrics Analyzer & Dashboard** | Aggregates latency percentiles, read QPS, ingestion lag, operational status counts (`503`/`413`), and invariant checks into periodic terminal summaries. |

### 1.2 Workload Distributions & Drip-Feed Schedules

- **Synthetic Entry Distributions & Formats**: Generates entries in raw key/value (`raw`), Go SumDB (`sumdb`, `<module> <version> h1:<hash>`), or Certificate Transparency (`ct`, X.509/precertificate) formats:
  - **Zipfian / Pareto Skew (`alpha > 1`)**: Concentrates >80% of entries onto the hottest 1% of keys, driving individual hot keys across multiple 65,536-entry chunk boundaries (`^0 -> ^1`) to stress chunk rollovers, Pebble compactions, and multi-page backward `/values` scans.
  - **Uniform Distribution**: Spreads entries evenly across `[0, K)` to stress MPT branch fanout and single-occurrence chunk creation.
- **Drip-Feed Checkpoint Schedules**:
  - **Steady Drip**: Releases Input Log checkpoints at a fixed rate to test steady-state ingestion and read concurrency.
  - **Burst Mode**: Buffers checkpoints and releases them in sudden bursts to simulate batch upstream publications.
  - **Pause & Catch-Up Mode**: Holds checkpoint publication so `vindexd` idles, then exposes a deep backlog of 256-entry bundles to benchmark catch-up throughput.

### 1.3 Verifying Concurrent Readers & Fault Discrimination

Concurrent reader workers query `vindexd` (`LookupKey`, `LookupPrefix`, and `MatchedKey.Values(ctx)`) using [`vindex/client`](../../client/README.md) configured with the expected `<input-log-origin>`, `<output-log-origin>`, and Output Log checkpoint policy across a weighted query mix:
- **Hot Keys (~60%)**: Samples skewed Zipfian keys and verifies the newest `/values` page (single-page `break`).
- **Uniform Keys (~25%)**: Samples uniformly across the active keyspace and verifies the newest `/values` page.
- **Non-Inclusion Probes (~10%)**: Queries synthetic `nonexistent/<id>` keys never appended to the Input Log, exercising MPT non-inclusion and empty-prefix proofs.
- **Full Backward Pagination (~5%)**: Walks a hot key's `MatchedKey.Values(ctx)` iterator all the way back to `preceding == 0` across multiple 65,536-entry chunks.

#### Verification & Monotonic History Assertions
1. **Cryptographic Proof Verification (`vindex/client`)**: Every query verifies the Output Log checkpoint policy and inclusion proof at `index == output_size - 1`, the 6-line `c2sp.org/tlog-vindex-state@v1` commitment, the binary MPT inclusion/non-inclusion/prefix proof against `mpt_root`, and the RFC 6962 Value Log compact range root on every fetched `/values` page.
2. **Monotonic History Superset & `From` Non-Regression**: Readers assert that `LookupResult.From` never regresses across queries. Whenever a query observes the **complete** Value Log history for canonical key `K` (either a single-page result with `preceding == 0` or a full backward walk to `preceding == 0`), the reader records the chronologically ordered entry index slice `I_new` at `input_size_new` and asserts that for any prior complete observation `I_old` at `input_size_old <= input_size_new`, `I_new` is a prefix-preserving superset of `I_old` (`len(I_new) >= len(I_old)` and `I_new[:len(I_old)] == I_old`).
3. **Fault Discrimination**: Any verification error (`client.ErrVerificationFailed`) or reader-side consistency failure (`From` regression or monotonic history superset violation) immediately records a fatal invariant violation and fails the hammer run, whereas transient operational status codes (`client.ErrUnavailable` / `HTTP 503` during cold startup or `client.ErrTooManyKeys` / `HTTP 413` on broad prefix limits) are tracked in telemetry without failing the run.

---

## 2. Alternatives Considered

### 2.1 In-Process Unit Test Mocks vs. End-to-End Loopback Harness
- **Proposed**: Stress-testing `vindexd` purely in memory using mocked storage and channel harnesses.
- **Rejection**: In-memory mocks miss real concurrency and I/O dynamics: loopback HTTP connection pooling, OS scheduler preemption, `mmap` page flushing, and Pebble LSM compaction stalls.
- **Chosen Design**: Real HTTP client/server execution backed by POSIX Tessera tiles, Pebble SSTables, and `mmap` MPT files.

### 2.2 Static Pre-Recorded Log Dumps vs. Dynamic Drip-Feed Sequencer
- **Proposed**: Replaying a fixed snapshot of an existing public transparency log.
- **Rejection**: Static dumps cannot modulate write rates on demand, dial exact Zipfian skew to force 65,536-entry chunk rollovers, inject targeted non-inclusion probes, or orchestrate pause/burst checkpoint schedules.
- **Chosen Design**: Deterministic synthetic entry generator paired with a programmable drip-feed `tlog-tiles` sequencer.

---

## 3. Verification Gate

```bash
go test -race ./vindex/internal/hammer/...
```
