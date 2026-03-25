# Verifiable Index

## The Problem

Logs, such as those used in Certificate Transparency or Software Supply Chains, provide a strong foundation for discoverability: you can definitively prove that an entry exists in a log. However, they lack a critical feature: the ability to *verifiably* query for entries based on their content.

This forces users—like a domain owner looking for their certificates, or a developer checking their software packages—into a painful choice:
1. **Massive Inefficiency**: Download and process the *entire* log (which can be terabytes of mostly irrelevant data) just to find a few relevant entries.
2. **Losing Verifiability**: Rely on an unverifiable third-party index. This breaks the chain of trust, as the index operator could inadvertently or maliciously omit results.

Users shouldn't have to sacrifice efficiency for security, or vice versa.

## The Solution

A Verifiable Index resolves this conflict by acting like a verifiable "back-of-the-book" index. It maps search terms (like a domain or package name) to exact locations (pointers) in the main log, providing an efficient and cryptographically verifiable way to query log data.

It provides two key guarantees:
1. **Efficiency**: Look up data by a meaningful key and receive a small, targeted list of pointers, bypassing the need to download the full log.
2. **Verifiability**: Every lookup response includes a cryptographic proof guaranteeing that the results are complete and the index operator has not omitted any entries.

## Deployment Examples

This verifiable map can be applied to any existing log where users need to enumerate all values matching a specific query. Examples include:

- **Certificate Transparency**: Domain owners can efficiently and verifiably query for all certificates matching a domain they own.
- **Go Software Supply Chain (SumDB)**: Package owners can quickly discover all releases for a package they maintain.
- **Sigstore**: Users can efficiently retrieve all signatures or provenance records associated with a specific software artifact or developer identity.

While traditional indices exist for these ecosystems today, they rely on centralized trust and are not verifiable.

## High-Level Implementation Details

The Verifiable Index (informally called a "Map Sandwich") operates by sitting between two logs. It utilizes three core components:

1. **Input Log**: The pre-existing append-only log that is being indexed (e.g., a CT Log).
2. **Verifiable Index**: The index data structure mapping search keys to their locations in the Input Log.
3. **Output Log**: A new log containing a sequential timeline of the Verifiable Index's cryptographic state commitments. 

> [!NOTE]  
> A Verifiable Index is constructed for a single Input Log. If an ecosystem has multiple logs (like Certificate Transparency), there will be as many Verifiable Indices as there are Input Logs.

### 1. Construction Strategy

Log data is read sequentially, leaf by leaf.

- **Leaf Verification**: Before parsing, the indexing pipeline *must* cryptographically verify that every downloaded leaf is genuinely committed to by the current Input Log checkpoint (e.g., by rolling up the tree and matching the root hash). This prevents a compromised network connection or malicious cache from feeding fake log data into the index.
- **MapFn**: A universally specified function determines which search keys belong to each verified log entry. It is compiled to WebAssembly (WASM) to guarantee completely deterministic, hermetic execution, ensuring the mapping logic cannot silently change behavior due to external factors like Go version updates. For example, in CT, it parses a log leaf as a certificate and outputs covered domains.
- **State Commitments**: In practice, this happens in batches (e.g., polling every 10 seconds). The system fetches the latest Input Log checkpoint, consumes all new entries by running them through the `MapFn` in memory, and calculates a new cryptographic root hash for the index (the Map Root). This root is appended as a new leaf into the **Output Log**. Crucially, the Output Log leaf contains both the `Map Root Hash` and the `Input Log Checkpoint` (which includes the Input Log tree size). This explicitly preserves the chain of custody, cryptographically binding the state of the map to the exact state of the Input Log that produced it. If the indexing process crashes mid-batch, it simply restarts from the last valid Output Log checkpoint and re-processes the delta of Input Log entries, requiring no intermediate durable storage for the inflight batch itself.

### 2. The Index Data Structure

The parsed outputs from the `MapFn` are physically separated into two purpose-built data structures maintained in lockstep:

- **Verifiable Prefix Trie**: Based on [AKD](https://github.com/facebook/akd) and powered by [rsc/tmp/mpt](https://github.com/rsc/tmp/tree/master/mpt), this maintains exclusively the cryptographic proofs. To keep the tree blindingly fast and efficiently memory-bound, a leaf's value is restricted to exactly 32 bytes. Therefore, the MPT does not store the actual list of matching indices; it solely stores the 32-byte *root hash* of the key's index log (the mini Merkle tree root stored in the KV store). 
- **Key-Value (KV) Data Store**: A persistent KV store acts as the bulk storage layer, holding the actual lookup data required to satisfy client queries. Crucially, it maps each key to an *append-only log* of relevant Input Log indices. By structuring a key's values as its own mini Merkle tree (where the root hash is what gets committed to the MPT above), clients can request highly compact **incremental updates**. If a client already knows the state of a key's list at size N, they simply ask for the delta up to the new size M, avoiding the need to download the entire history of a highly active key. Clients locally verify these updates using a [compact range](https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md).

> [!TIP]  
> Rather than storing raw search keys (e.g., `maps.google.com`), keys in the map are cryptographically hashed. For privacy-sensitive logs, a VRF (Verifiable Random Function) can be used.

### 3. Read & Verify Flows

- **Reading**: The VIndex is exclusively queried at its *latest* version; there are no historic queries. The system returns the latest list of matching indices in the Input Log, alongside inclusion proofs tying those results to the map's current root hash. Because the list of indices is structured as an append-only Merkle tree, a client who previously fetched the index at size N can simply request the delta up to size M and use a [compact range](https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md) to locally reconstruct and verify their historical state. No consistency proof is computed or returned by the server.
- **Verifying**: The brand new append-only **Output Log** exists entirely for auditing. Anyone with compute resources can act as a verifier by running the universally specified MapFn against the Input Log to construct an identical local index. By comparing their computed root hash against the sequence of roots permanently published in the Output Log, they can verify every past state commitment. This guarantees that all past map revisions clients relied upon were constructed correctly, proving the operator never served an invalid map root.

## Design Rationale for Transparency Experts

For those familiar with Key Transparency (KT), Merkle Tree Certs (MTC), or other verifiable maps, the "Map Sandwich" architecture makes an intentional departure from standard map designs:

1. **Decoupling Data from the Index**: Unlike typical Key Transparency systems where the Verifiable Map serves as the primary database (or a Sparse Merkle Tree tightly integrates the log and map), the VIndex acts entirely as a secondary *overlay*. The pre-existing Input Log remains the absolute source of truth. If the VIndex is corrupted or goes offline, the underlying transparency log's security model remains completely unaffected.
2. **The Output Log Format**: The Output Log is not a heavyweight, database-backed transparency log (like Trillian). In v1, it is implemented using [Tessera](https://github.com/transparency-dev/tessera)'s POSIX log ([`tlog-tiles`](https://c2sp.org/tlog-tiles)). This writes static, cacheable Merkle tree tiles directly to a dumb filesystem or blob storage (like S3). This lightweight approach strictly protects against split-view (equivocation) attacks, mathematically forcing the Map Operator to commit to one verifiable timeline. Crucially, because the Output Log uses the exact same `tlog-tiles` format as many Input Logs, clients and verifiers can leverage their existing transparency verification libraries for both layers.

## Limitations & Out of Scope (v1)

While the VIndex architecture cleanly solves the read-efficiency problem for transparency logs, there are several database-like features that are explicitly out of scope for v1:

- **MapFn Upgradability**: The `MapFn` (e.g., the WASM parser) is strongly immutable for the life of the index. If the mapping logic needs to change (e.g., to index a new metadata field), the operator cannot dynamically "upgrade" the function. Instead, they must deploy an entirely new VIndex (processing the Input Log from index 0) and coordinate rolling clients over to the new version.
- **No Custom ReduceFn**: The VIndex creates an append-only log of all matching Input Log indices for a given search key. It does not support a user-defined `ReduceFn` to pre-aggregate or filter these results (e.g. to only return the single latest version of a module). Any reduction or filtering logic must be implemented by the client that consumes entries from the VIndex.
- **Record Deletion & Value Overwriting**: The VIndex is an append-only map of logs. It does not support overwriting or deleting mapped pointers. If an entry in the Input Log is revoked or superseded, the VIndex will still point to it. It is up to the client validating the records to recognize revocation events within the data payload.
- **Admission Validation**: The VIndex is designed to be a "dumb" indexer that strictly inherits the admission criteria of the Input Log (e.g., a CT log requiring trusted root signatures). It will not run heavyweight cryptographic validation to filter out spam. Therefore, the onus is entirely on the **author** of the `MapFn` to design their parser defensively—only outputting keys for rigidly expected data structures—to minimize spam and hot-key vectors, especially when indexing open-admission logs.

## Relationship to Incubator MVP

This project is a continuation and refinement of the original Verifiable Index MVP located in the [transparency-dev/incubator](https://github.com/transparency-dev/incubator/tree/main/vindex) repository.

The main deltas from the incubator MVP include:
- **WASM Requirement**: Added WASM as a requirement for the MapFn.
- **Removed WAL**: Removed the Write-Ahead Log (WAL) unless demonstrated needed.
- **Pebble DB**: Pebble is used to store K/Vs.
- **Pebble Ranges**: Indexes are stored using Pebble ranges to allow for larger values.
- **Merkle Tree Construction**: Added Merkle Tree construction for leaf hashing.
