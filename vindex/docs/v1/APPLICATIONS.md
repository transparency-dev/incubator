# Verifiable Index Applications

This document outlines the various ecosystems and use cases where a [Verifiable Index](./README.md) can be applied to provide efficient, trustless querying over large append-only transparency logs.

## Certificate Transparency (CT)

In the context of Certificate Transparency, the Verifiable Index (VIndex) addresses the challenge of **efficient, trustless domain monitoring**.

### The Problem
A domain owner wants to know every certificate issued for their domain to detect unauthorized issuance. Today, they must either:
1. Process the entire massive CT log themselves.
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

#### 2. Deployment Models
A VIndex can be integrated into the MTC ecosystem using one of two primary deployment models:

##### 2a. Integrated CA-Operated Index
* **Model**: The Certificate Authority (CA) runs both the primary MTC log and the VIndex as a unified offering.
* **Trade-offs**: Because MTC logs actively prune expired certificates, older VIndex pointers may reference leaves that have been dropped from the primary log. In practice, this is rarely an issue: regular monitors tail the VIndex frequently enough to fetch new entries before they expire, and new monitors typically focus on currently active certificates. In the rare event that a full historical audit is required, unpruned data can still be retrieved from an external mirror using the same leaf indices.

##### 2b. Mirror-Operated Index
* **Model**: Independent mirrors maintain a full, unpruned history of the MTC log and operate the VIndex alongside it.
* **Trade-offs**: This guarantees that all VIndex pointers resolve to valid, downloadable certificate data. However, funding and maintaining this infrastructure remains an open question.

##### Incentives & Game Theory
Choosing between these models involves shifting the ecosystem's operational incentives. Traditional CT relies heavily on third-party log operators providing a public good. MTC intentionally shifts the primary log operational burden to the CAs themselves.

Integrating the VIndex directly into the CA's log infrastructure (Model 2a) presents a unique opportunity to bundle the costs of verifiable logging and targeted monitoring into a single package, dramatically improving usability for independent monitors without relying on third parties. While the CT community will ultimately determine the preferred path, VIndex is fully compatible with either approach and requires no modifications to the underlying MTC log format, serving as a natural and purely complementary addition.

---

## Go Software Supply Chain (SumDB)

*To be documented.*

---

## Sigstore

*To be documented.*

---

## Sigsum

*To be documented.*
