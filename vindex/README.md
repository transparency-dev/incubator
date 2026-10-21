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
- **Pointers, Not Copies**: The index stores lightweight leaf pointers (indices) referencing the authoritative Input Log, rather than replicating or transforming leaf payloads.
- **High Throughput & Bounded Footprint**: Storing compact relative index offsets eliminates data amplification, enabling sustained indexing speeds exceeding 240,000 leaves per second on commodity hardware.
- **Clear Security Boundaries**: The Input Log remains the sole source of truth. VIndex acts as an untrusted search overlay; if the indexer halts, corrupts, or falls behind, the underlying log's consensus and integrity are completely unaffected, and clients independently verify retrieved leaf data against the Input Log's signed checkpoints.

---

## 3. The Map Sandwich Architecture

The VIndex topology bounds search indexing between two append-only logs—a structure known as the **"Map Sandwich"**:

| Component | Physical Role | Cryptographic Contract |
| :--- | :--- | :--- |
| **Input Log** | Authoritative source of truth (e.g. CT, MTC, Go SumDB, Sigstore). | Strictly append-only log of raw leaves and signed tree checkpoints. |
| **vindexd Daemon** | Single-host indexing and serving engine. | Ingests tiles, executes sandboxed WASM mapping, stores inverted chunks in Pebble DB, commits state in an in-memory MPT, and serves C2SP HTTP lookups. |
| **Output Log** | Cryptographic anchor committing to index state (`mpt-root` + Input Log checkpoint). | Append-only log of state commitments signed and monitored by an independent witness network. |

### Core System Guarantees
- **Point & Bounded Prefix Lookups**: Exact key lookups (`?key=<key>`) and policy-bounded prefix scans (`?prefix=<key-prefix>`) over variable-length canonical keys (`1..1024` bytes), returning verified value log roots and paginated lists of matching entry indices.
- **Two-Endpoint Read Protocol**: Separates state commitment & MPT proof generation (`GET /keys?key=<key>` or `GET /keys?prefix=<key-prefix>`) from lock-free Pebble value log pagination (`GET /values?key=<key>&before=<B>[&limit=<L>]`).
- **Omission Resistance**: Every query response delivers cryptographic inclusion proofs, non-inclusion proofs, or two-sided prefix proofs against witnessed checkpoints.
- **Decoupled Security**: VIndex operates as a secondary search overlay. If an indexer halts, corrupts, or falls behind, the underlying Input Log's consensus and security remain completely unaffected.

---

## 4. Non-Negotiable System Scope

1. **Strictly Single-Machine Deployment**: VIndex operates strictly within a single process on a single host. It avoids internal clustering, distributed consensus (Raft/Paxos), or multi-node replication. High availability is achieved externally: independent monitors and mirrors run standalone VIndex instances against the shared Input Log.
2. **Canonical Key & Bounded Prefix Lookups**: The production serving plane provides point queries (`?key=<key>`) and policy-guarded prefix queries (`?prefix=<key-prefix>`) over canonical printable ASCII keys (`1..1024` bytes, `0x21..0x7E`). Unbounded full-tree scans, arbitrary substring matches, and regex searches are out of scope.
3. **Strictly Append-Only (Zero Tombstones)**: The index state progresses strictly forward. The system supports no deletions, key un-mappings, rollbacks, or tombstones.
4. **Hermetic, Deterministic Mapping**: The WebAssembly guest plugin operates in a restricted WASI-free sandbox (`mapfn/host`) with zero host I/O, zero network access, and deterministic execution. Any runtime trap, memory fault, or unhandled exception triggers an immediate `HALT` to prevent unverified state divergence across nodes.

---

## 5. Core Terminology Glossary

- **Input Log**: The authoritative, append-only source transparency log containing the raw entries to be indexed.
- **Canonical Key**: A normalized printable ASCII byte string (`1..1024` bytes in `0x21..0x7E`) identifying a subject in an Input Log entry (e.g. reversed-label domain `com.google.mail.` in CT/MTC or case-escaped module path `golang.org/x/!text` in Go SumDB). Corresponds to the normalized *Claim Subject* in [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md) terminology.
- **MapFn**: A pure, deterministic mapping function (`map_fn(entry: bytes) -> list[CanonicalKey]`) that extracts zero or more Canonical Keys from a raw Input Log entry, identified in state commitments by a 32-byte SHA-256 digest (`map-fn`).
- **WASM** (*WebAssembly*): The hermetic, deterministic bytecode sandbox used to package and execute `MapFn` plugins with zero host I/O or network access, ensuring identical key extraction across operators and verifiers.
- **Value Log**: A per-key, append-only RFC 6962 Merkle tree committing to the strictly ascending sequence of Input Log entry indices at which that Canonical Key appeared, summarized by a 32-byte `value_root`.
- **MPT** (*Merkle Patricia Trie*): A path-compressed binary Merkle Patricia Trie mapping each present Canonical Key to its 32-byte Value Log root (`value_root`), supporting exact inclusion, non-inclusion, and two-sided prefix subtree proofs.
- **Witnessed Output Log**: A secondary append-only tiled transparency log (`tlog-tiles`) that records index state commitments (`mpt-root`, `map-fn`, `from`, and Input Log checkpoint) cosigned by independent witnesses.
- **Verifier of Correct Construction** (*Auditor*): An independent verifier that replays the Input Log through `MapFn` and recomputes Value Logs and the MPT to verify that every `mpt-root` published in the Output Log was faithfully constructed without omissions or fabrications.

---

## 6. Specification

- [**C2SP tlog-vindex Specification**](./docs/tlog-vindex.md): Formal wire protocol, cryptographic tree definitions, and client/auditor verification specification.
