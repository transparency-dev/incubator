# Verifiable Index Applications

This document outlines the various ecosystems and use cases where a [Verifiable Index](./README.md) can be applied to provide efficient, trustless querying over large append-only transparency logs.

## Certificate Transparency (CT)

In the context of Certificate Transparency, the Verifiable Index (VIndex) addresses the challenge of **efficient, trustless domain monitoring**.

### The Problem
A domain owner wants to know every certificate issued for their domain to detect unauthorized issuance. Today, they must either:
1. Download, and process all massive CT logs themselves; OR
2. Trust a centralized third-party search tool (like `crt.sh`), which could theoretically omit results due to error or malice.

### The Solution
A VIndex can be deployed over a CT log to provide verifiable lookups:
* **Input Log**: A Certificate Transparency Log.
* **MapFn**: Designed to parse CT log leaves (X.509 certificates/precertificates) and output the Subject and Subject Alternative Name (SAN) entries as search keys (which are then cryptographically hashed for the index).

### Guarantees & Flow
1. **Query**: A domain owner queries the index for a specific key (e.g., `example.com`).
2. **Result**: The VIndex returns a compact, append-only list of pointers (leaf indices in the CT log) where certificates for `example.com` are located, along with a cryptographic inclusion proof. If the monitor has queried before, they only need to request the incremental delta of new entries.
3. **Verification**: The domain owner can cryptographically verify that the returned list is complete and correct against the publicly audited Output Log checkpoints.
4. **Revocation Monitoring**: Because the VIndex provides an append-only history of all certificates issued for the domain, monitors are responsible for parsing the returned certificates/precertificates to determine their expiration or revocation status.

### Post-Quantum & Merkle Tree Certificates (MTCs)

#### 1. MTC vs. Traditional CT Logs
[Merkle Tree Certificates (MTCs)](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) are designed to minimize certificate sizes by omitting public keys and signatures from log entries, storing only hashes of the public keys and using a single signature over the tree head. This makes MTC logs significantly smaller than traditional CT logs (like RFC6962 or `static-ct`), even when accounting for larger Post-Quantum keys.

Importantly, **Subject Alternative Names (SANs) remain fully present** in the MTC leaf structure. This is the essential ingredient that allows VIndex to parse the log and map domain names to their corresponding leaf indices. Combined with log pruning and the fact that MTCs are logged exclusively in their issuer's log, independent monitoring of MTC logs is inherently more efficient than traditional CT. However, downloading and processing all active certificates across multiple logs remains a high barrier for individual domain owners, making VIndex a crucial complementary layer.

#### 2. Deployment Models & Pruning Realities

A VIndex can be integrated into the MTC ecosystem across different operational models. However, unlike traditional CT where logs grow infinitely, MTC ecosystems heavily utilize pruning to maintain sustainability. This pruning can apply to the primary log, mirrors, and even the VIndex itself.

##### 2a. Integrated CA-Operated Index
* **Model**: The Certificate Authority (CA) runs both the primary MTC log and the VIndex as a unified offering.
* **Trade-offs**: Because MTC logs actively prune expired certificates, older VIndex pointers will eventually reference leaves that have been dropped from the primary log. If the VIndex itself is also managed via pruning or temporal epochs, these historical records may disappear entirely.

##### 2b. Mirror-Operated Index
* **Model**: Independent mirrors operate the VIndex alongside a copy of the MTC log. These mirrors may choose to maintain a full, unpruned history, or they may adopt the same pruning policy as the source log to reduce operational costs.
* **Trade-offs**: While an unpruned mirror is ideal for long-term historical forensics, funding and maintaining such storage is a significant barrier. If a mirror adopts standard pruning, older data becomes unavailable just as it does in the primary log.

##### The Value of Active Monitoring

Regardless of whether the underlying data is eventually pruned from all logs, mirrors, and the index, the VIndex retains its core value: **efficient real-time threat detection**. 

The primary mission of a domain monitor is to detect unauthorized certificates *while they are active* so that mitigation (revocation) can occur. The VIndex reduces the cost of discovering these active certificates to a simple targeted query, removing the need for domain owners to download massive datasets. While a full, unpruned mirror provides the best capability for retrospective auditing, the VIndex remains a crucial operational layer even in a fully pruned ecosystem.

#### 3. Open Questions
* **Deployment Path**: Which deployment model (CA-integrated vs. Mirror-operated) will be widely adopted by the ecosystem?
* **VIndex Lifecycle & Size Management**: If primary logs grow infinitely but prune older certificates, how should an unbounded VIndex be managed?
  * Should the VIndex be periodically rolled over (creating temporal epochs)?
  * Can individual sub-logs within the VIndex be safely pruned over time to reclaim storage? (See [VIndex Pruning & Storage Reclamation](./README.md#vindex-pruning--storage-reclamation))

---

## Go Software Supply Chain (SumDB)

*To be documented.*

---

## Sigstore

*To be documented.*

---

## Sigsum

*To be documented.*
