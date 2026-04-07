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
While [Merkle Tree Certificates (MTCs)](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) elegantly solve the problem of bloated signature chains during TLS handshakes, the transition to Post-Quantum (PQ) cryptography shifts that data burden entirely onto the transparency logs. VIndex serves as the crucial missing layer to keep the MTC ecosystem viable for independent monitors:

* **Sustaining Decentralized Monitoring**: Post-Quantum algorithms (like ML-DSA) produce larger keys and signatures. Combined with shorter certificate lifespans, transparency logs will grow at an unprecedented rate. Without a verifiable index, downloading full logs will become computationally and financially prohibitive, effectively killing independent domain monitoring.
* **Targeted, Trustless Verification**: VIndex decouples the lookup layer from the primary log, reducing a monitor's bandwidth requirement from the entire global certificate volume down to the specific delta of their own domain. This democratization ensures any domain owner can independently and verifiably monitor their assets on low-resource hardware.
* **Zero-Risk Integration**: Designed as an independent overlay, VIndex does not interfere with the critical path of MTC log admission or issuance. Furthermore, because the Output Log leverages the exact same static `tlog-tiles` format as modern log layers, verifiers can reuse their existing fetching and verification tooling.

---

## Go Software Supply Chain (SumDB)

*To be documented.*

---

## Sigstore

*To be documented.*

---

## Sigsum

*To be documented.*
