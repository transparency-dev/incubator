# Verifiable Index (VIndex)

A **Verifiable Index (VIndex)** provides efficient, trustless, and cryptographically verifiable querying over append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB).

> **Looking for the original WAL-based MVP?** The initial prototype that preceded this architecture has been retired on `main`; you can browse its source and docs at commit [`d76a0d4`](https://github.com/transparency-dev/incubator/tree/d76a0d4/vindex).

---

## 1. Context & Problem Statement

Append-only transparency logs provide tamper-evident discoverability: anyone can mathematically verify that an entry exists at a specific sequence number in the log. However, discovering records by content (e.g., domain name, module path, or public key hash) historically forced an impossible trade-off:

1. **Massive Client Inefficiency**: Finding a subject required clients to download, deserialize, and scan gigabytes or terabytes of irrelevant log entries locally.
2. **Loss of Verifiability**: To avoid local downloads, users relied on centralized, third-party search APIs (such as `crt.sh`). However, these services lack cryptographic commitments; an untrusted or compromised operator can omit, reorder, or forge search results without detection.

A **Verifiable Index (VIndex)** eliminates this trade-off by acting as an authenticated "back-of-the-book index" that delivers direct key and prefix lookups with compact Merkle proofs, guaranteeing completeness against witnessed checkpoints without scanning the log.

---

## 2. Background & Lineage

VIndex v1 represents the distillation of years of research, experimentation, and production experience with verifiable key-value mappings over transparency logs:

- [**Google Key Transparency**](https://github.com/google/key-transparency): Early pioneer in verifiable identity-to-key mapping, exploring sparse Merkle tree lookups and continuous auditability.
- [**Trillian Batch Map**](https://github.com/google/trillian/tree/master/experimental/batchmap): Experimental map engine investigating batch-oriented Sparse Merkle Tree mutations and log integration.
- [**VIndex Prototype (v0 MVP)**](https://github.com/transparency-dev/incubator/tree/d76a0d4/vindex): The initial WAL-based prototype (preserved at commit [`d76a0d4`](https://github.com/transparency-dev/incubator/tree/d76a0d4/vindex)), which validated the core "Map Sandwich" concept, in-process Pebble storage, and demonstrated full-scale indexing on the Go Checksum Database (SumDB).

### The Key Evolution: Pure Indexing vs. State Summarization
Earlier systems attempted to act as verifiable state machines that copied, aggregated, or summarized application data directly inside the map nodes. VIndex v1 makes a fundamental architectural departure: it focuses **purely on indexing** an existing log rather than summarizing its state:
- **Pointers, Not Copies**: The index stores lightweight Input Log entry indices referencing the authoritative Input Log, rather than replicating or transforming entry payloads.
- **High Throughput & Bounded Footprint**: Storing compact relative entry index offsets eliminates data amplification, enabling sustained indexing speeds exceeding 240,000 entries per second on commodity hardware.
- **Clear Security Boundaries**: The Input Log remains the sole source of truth. VIndex acts as an untrusted search overlay; if the indexer halts, corrupts, or falls behind, the underlying log's consensus and integrity are completely unaffected, and lookup clients independently verify retrieved entry data against the Input Log's signed checkpoints.

---

## 3. The Map Sandwich Architecture

The VIndex topology bounds search indexing between two append-only logs—a structure known as the **"Map Sandwich"**:

| Component | Physical Role | Cryptographic Contract |
| :--- | :--- | :--- |
| **Input Log** | Authoritative source of truth (e.g. CT, MTC, Go SumDB, Sigstore). | Strictly append-only log of raw entries and signed tree checkpoints. |
| **vindexd Daemon** | Single-host indexing and serving engine. | Ingests authenticated entry bundles, executes sandboxed WASM mapping, stores inverted chunks in Pebble DB, commits state in an in-memory MPT, and serves C2SP HTTP lookups. |
| **Output Log** | Cryptographic anchor committing to index state (`mpt-root` + embedded Input Log checkpoint). | Append-only log of index state commitments signed and monitored by an independent witness network. |

### Core System Guarantees
- **Point & Bounded Prefix Lookups**: Exact key lookups (`?key=<key>`) and policy-bounded prefix scans (`?prefix=<key-prefix>`) over variable-length canonical keys (`1..1024` bytes), returning verified value log roots and paginated lists of matching Input Log entry indices.
- **Two-Endpoint Read Protocol**: Separates state commitment & MPT proof generation (`GET <index-url>/keys?key=<key>` or `GET <index-url>/keys?prefix=<key-prefix>`) from lock-free Pebble value log pagination (`GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]`).
- **Omission Resistance**: Every query response delivers cryptographic inclusion proofs, non-inclusion proofs, or two-sided prefix proofs against witnessed checkpoints.
- **Decoupled Security**: VIndex operates as a secondary search overlay. If an Index Operator halts, corrupts, or falls behind, the underlying Input Log's consensus and security remain completely unaffected.

---

## 4. Non-Negotiable System Scope

1. **Strictly Single-Machine Deployment**: VIndex operates strictly within a single process on a single host. It avoids internal clustering, distributed consensus (Raft/Paxos), or multi-node replication. High availability is achieved externally: independent Index Operators run standalone VIndex instances against the shared Input Log.
2. **Canonical Key & Bounded Prefix Lookups**: The production serving plane provides point queries (`?key=<key>`) and policy-guarded prefix queries (`?prefix=<key-prefix>`) over canonical printable ASCII keys (`1..1024` bytes, `0x21..0x7E`). Unbounded full-tree scans, arbitrary substring matches, and regex searches are out of scope.
3. **Strictly Append-Only (Zero Tombstones)**: The index state progresses strictly forward. The system supports no deletions, key un-mappings, rollbacks, or tombstones.
4. **Hermetic, Deterministic Mapping**: The WebAssembly guest plugin operates in a restricted WASI-free sandbox (`internal/wasmhost`) with zero host I/O, zero network access, and deterministic execution. Any runtime trap, memory fault, unhandled exception, or invalid canonical key emission triggers an immediate `HALT` to prevent unverified state divergence across nodes.

---

## 5. Core Terminology Glossary

- **Input Log**: The authoritative, append-only source transparency log containing the raw entries to be indexed.
- **Canonical Key**: A normalized printable ASCII byte string (`1..1024` bytes in `0x21..0x7E`) identifying a subject in an Input Log entry (e.g. reversed-label domain `com.google.mail.` in CT/MTC or case-escaped module path `golang.org/x/!text` in Go SumDB). Corresponds to the normalized *Claim Subject* in [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md) terminology.
- **MapFn**: A pure, deterministic mapping function (`map_fn(entry: bytes) -> list[CanonicalKey]`) that extracts zero or more Canonical Keys from a raw Input Log entry, identified in `c2sp.org/tlog-vindex-state@v1` commitments by a constant 32-byte SHA-256 digest (`map-fn`; `tlog-vindex` itself is runtime-agnostic and has an open pre-1.0 `TODO` on hashing a canonical provenance/build manifest vs. raw artifact bytes, while `vindex` currently uses `SHA-256(wasm_bytes)`).
- **WASM** (*WebAssembly*): The hermetic, language-agnostic bytecode sandbox (`input_buffer`/`map_bundle` slab ABI, targetable from Go, Rust, C/C++, Zig, or TinyGo) used by `vindexd` and `vindex-auditor` to package and execute `MapFn` plugins with zero host I/O or network access.
- **Value Log**: A per-key, append-only RFC 6962 Merkle tree committing to the strictly ascending sequence of Input Log entry indices at which that Canonical Key appeared, summarized by a 32-byte `value_root`.
- **MPT** (*Merkle Patricia Trie*): A path-compressed binary Merkle Patricia Trie mapping each present Canonical Key to its 32-byte Value Log root (`value_root`), supporting exact inclusion, non-inclusion, and two-sided prefix subtree proofs.
- **Witnessed Output Log**: A secondary append-only tiled transparency log (`tlog-tiles`) that records index state commitments (`mpt-root`, `map-fn`, `from`, and Input Log checkpoint) cosigned by independent witnesses.
- **Verifier of Correct Construction** (*Auditor*): An independent verifier that replays the Input Log through `MapFn` and recomputes Value Logs and the MPT to verify that every `mpt-root` published in the Output Log was faithfully constructed without omissions or fabrications.

---

## 6. Role-Based Reading Pathways

### System Architect
- Start with [Architecture & Subsystem Mechanics](./docs/ARCHITECTURE.md) for the 5-stage pipeline flow, system-wide invariants, crash recovery guarantees, and retired alternatives.
- Read [Coordinator & Lifecycle Engine](./internal/coordinator/README.md) for watermark governance, moving-goalpost prevention, and Zero-WAL recovery sequences.
- Read [Inverted Chunk Storage Engine](./internal/kvstore/README.md) for Pebble LSM key layout, bitwise chunk inversion (`^chunkNum`), and Bloom filter mechanics.

### WASM Plugin Author
- Read [WASM Guest SDK & Plugin Interface](./mapfn/README.md) for the pure Go developer contract (`type EmitMapFunc func(entry []byte, emit func(key []byte))`), low-level `map_bundle` memory slabs, and the `vindex-wasm` CLI.
- Review [Applications & Ecosystem Specifications](./docs/APPLICATIONS.md) for real-world canonicalization profiles across Certificate Transparency, MTC, Go SumDB, Sigstore, and Sigsum.

### Client Application Engineer
- Read [Client SDK & Query Proof Verification](./client/README.md) for the public Go client API, multi-section response parsing, and the 5-step cryptographic verification sequence.
- Read [Read Serving & C2SP Query Protocol](./internal/server/README.md) for HTTP endpoints, multi-section response formats, and the inductive backward verification protocol.

### Auditor Operator
- Read [Independent Log Auditor](./internal/auditor/README.md) for the continuous audit loop, root mismatch alerting, and state-preserving forensic halts.
- Review operational commands in `cmd/vindex-auditor/`.

### Test & Performance Engineer
- Read [Hammer Load Testing & Verification Framework](./internal/hammer/README.md) for synthetic Zipfian load generation, drip-feed proxy scheduling, and continuous invariant verification.

---

## 7. Complete Documentation Index

### Core Architecture & Ecosystems
- [**C2SP tlog-vindex Specification**](./docs/tlog-vindex.md): Formal wire protocol, cryptographic tree definitions, and client/auditor verification specification.
- [**System Architecture**](./docs/ARCHITECTURE.md): Primary pipeline flow, subsystem map, system-wide invariants, Zero-WAL crash consistency, operational sizing, and retired alternatives.
- [**Applications & Ecosystem Specifications**](./docs/APPLICATIONS.md): Universal Claim Subject Map model, canonicalization profiles, host hardware SIMD hashing, and ecosystem specifications (CT, MTC, Go SumDB, Sigstore, Sigsum).

### Client & Subsystem Specifications
- [**Client SDK & Query Proof Verification**](./client/README.md): Lightweight public Go client library with pure, stateless `Verify*` primitives, optional O(1) `StateTracker` checkpoint ratcheting, two-endpoint C2SP verification, two-sided prefix proofs, `torchwood.Policy` (`tlog-policy`) verification, and backward pagination chains.
- **C2SP Wire Format & Merkle Codecs** (`internal/wire`): Internal zero-I/O C2SP multi-section parser/formatter, Output Log index state commitment codecs, and RFC 6962 value log compact range hash root computation.
- [**Ingestion Pipeline & Tile Cache**](./internal/ingest/README.md): Upstream tile and entry bundle fetching, local tile cache durability, WASM worker pool, host SIMD hashing, monotonic resequencing, and safe cache pruning.
- [**WASM Guest SDK & Plugin Interface**](./mapfn/README.md): Public Go guest SDK runtime harness (`mapfn/sdk`), internal WASI-free Wazero sandbox host (`internal/wasmhost`), pack-and-wipe linear memory slabs, and `vindex-wasm` verification tooling.
- [**Inverted Chunk Storage Engine**](./internal/kvstore/README.md): Embedded Pebble LSM engine, inverted chunk keys (`'c' + KeyHash + ^chunkNum`, where `KeyHash = SHA-256(key)` is strictly an internal Pebble storage digest while the MPT stores un-hashed canonical keys), 33-byte prefix Bloom filters, delimitless 16-bit offset serialization, and the `pebble-tests` empirical suite.
- [**Authenticated State Commitment (MPT & Output Log)**](./internal/tree/README.md): Variable-length MPT (`internal/mpt`), non-blocking root prediction, 3-step atomic commitment dance (`internal/tree`), and split-locking concurrency (< 5ms critical section).
- [**Read Serving & C2SP Query Protocol**](./internal/server/README.md): Two-endpoint C2SP HTTP REST protocol (`<index-url>/keys` and lock-free `<index-url>/values`), prefix policy guardrails, inductive backward verification, and reader snapshot isolation.
- [**Coordinator & Lifecycle Engine**](./internal/coordinator/README.md): Batch loop orchestration, checkpoint progression chain, moving-goalpost prevention (freezing target sync checkpoints), and 3-phase Zero-WAL crash recovery.
- [**Independent Log Auditor**](./internal/auditor/README.md): Full-log audit verification from the configured start index (`from`, default `0`), root mismatch alerting, and state-preserving forensic halts.

### Tooling & Verification
- [**Hammer Load Testing Framework**](./internal/hammer/README.md): Integration load generator, Zipfian workload synthesizer, and concurrent verifying lookup client harness.

