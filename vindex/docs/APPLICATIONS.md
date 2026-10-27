# Verifiable Index Applications

Append-only transparency logs make records tamper-evident once logged, but they only deliver accountability when the people affected by those records can actually find them. This document shows how real-world transparency ecosystems map onto the [C2SP `tlog-vindex`](./tlog-vindex.md) model: who monitors each log, what question a verifiable index answers for them, how log leaves map to canonical keys, and how prefix lookups and log rotation work in practice.

---

## 1. Claim Subject Maps & Who Verifies the Log

In the [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md), an append-only transparency log records signed claims, while a verifiable index acts as a **Claim Subject Map (CSM)** (or **Map of Logs (MoL)**) over that _input log_:

- **Claim Subjects (Canonical Keys)**: A deterministic _mapping function_ extracts zero or more printable ASCII _canonical keys_ from each input log entry in `[from, input_size)`, for example, a domain name, a Go module path, an OIDC signing identity, or a public key hash.
- **Value Logs**: Rather than copying or summarizing entry payloads inside the map, each present key in the Merkle Patricia Trie (MPT) points to the 32-byte [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html) Merkle root (`value_root`) of an append-only _value log_ recording the ascending input log entry indices (`entry_idx`) where that key appeared.

The security property a Claim Subject Map provides is **Efficient Discovery**. An artifact consumer who already holds a certificate, Go module, or signature bundle can verify a single inclusion proof directly against the input log. The harder problem belongs to **subject owners** (e.g. domain owners, module maintainers, and key holders) who need to verify that _no unexpected entries_ concerning their identity or namespace exist anywhere in the log, without downloading terabytes of unrelated entries or trusting an unauthenticated search service. Lookup clients query `<index-url>/keys` and `<index-url>/values` and verify completeness offline against witnessed _output log_ commitments.

---

## 2. Mapping Principles & Ecosystem Overview

Every ecosystem profile turns raw input log entries into canonical keys ([`tlog-vindex`](./tlog-vindex.md#index-structure), 1 to 1024 printable ASCII bytes without whitespace) under three shared rules:

1. **Consistent Key Normalization**: Index operators, independent auditors, and lookup clients apply the exact same normalization from a real-world identifier to canonical key bytes. Because the MPT and `<index-url>/keys` match raw canonical key bytes directly, querying `example.com` or `com.example` against an index keyed by `com.example.` walks a different trie path and returns a valid non-inclusion proof even when certificates exist for that domain.
2. **Skipping Unindexable Fields**: Real-world log entries contain fields that do not represent indexable subjects, such as human-readable X.509 Organization/Common Name strings containing spaces, output artifact hashes, or untagged commit pseudo-versions in Go SumDB. Mapping functions deterministically skip those fields so only valid canonical keys enter the trie.
3. **One Occurrence per Entry**: When a single log entry names the same subject multiple times (such as repeating a domain across Subject Common Name and Subject Alternative Name, or repeating a Go module path on both archive and `/go.mod` lines), duplicates within that entry are collapsed so `entry_idx` appears at most once in the key's value log.

| Ecosystem                    | Who Monitors          | Claim Subject                | Illustrative Canonical Key                                                                    | Keys per Entry |
| :--------------------------- | :-------------------- | :--------------------------- | :-------------------------------------------------------------------------------------------- | :------------- |
| **Certificate Transparency** | Domain owners         | DNS name (CN / SAN)          | `com.google.mail.`, `com.google.*.`                                                           | `0..N`         |
| **Merkle Tree Certificates** | Domain owners         | DNS name (subject assertion) | `com.google.mail.`, `com.google.*.`                                                           | `0..N`         |
| **Go Checksum Database**     | Module authors & orgs | Go module path               | `github.com/!azure/azure-sdk-for-go`                                                          | `0..1`         |
| **Sigstore (Rekor)**         | Signers & CI owners   | OIDC email or workload URI   | `user@example.com`, `https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main` | `0..N`         |
| **Sigsum**                   | Key holders           | Ed25519 public key hash      | 64-character lowercase hex digest                                                             | `1`            |

---

## 3. Ecosystem Deployments

### 3.1 Certificate Transparency (RFC 6962 & Static CT)

- **References**:
  - [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962.html)
  - [C2SP Static CT API Specification](https://c2sp.org/static-ct-api)
  - [Known Certificate Transparency Logs](https://certificate.transparency.dev/logs/)

**Who verifies, and why**: Browsers check at TLS handshake time that a presented certificate was logged, which only forces an attacker or compromised CA to log a mis-issued certificate. **Domain owners** must monitor CT logs to verify that no unauthorized certificates cover their domains or subdomains. Without a verifiable index, monitors must either download and parse terabytes of certificate entries across dozens of logs or rely on centralized aggregators (such as `crt.sh`) that carry no cryptographic proof of completeness.

**From leaf to canonical key**: CT log leaves (`x509_entry` certificates and `precert_entry` precertificates) contain ASN.1 DER X.509 `Certificate` / `TBSCertificate` structures carrying DNS identifiers in the Subject Common Name (CN) and Subject Alternative Name (SAN) `dNSName` extension. The mapping function extracts valid DNS names, converts internationalized labels to lowercase ASCII Punycode (IDNA2008), reverses the label order, and appends a trailing dot, turning `mail.google.com` into `com.google.mail.` and `*.google.com` into `com.google.*.`. Non-DNS Common Names (such as organization strings with spaces) and IP literals are skipped, and parent domain suffixes are not expanded at map time.

**Querying the index**: A domain owner monitoring `google.com` queries `GET <index-url>/keys?prefix=com.google.` (or `GET <index-url>/keys?key=com.google.mail.` for a single host). The trailing dot aligns prefix matching on complete DNS label boundaries so `com.google.` never matches sibling domains like `com.googleapis.`, while server prefix policies reject bare public-suffix queries such as `com.` or `uk.co.`. The `/keys` response returns a verified list of every matching apex, subdomain, and wildcard key (`com.google.`, `com.google.*.`, `com.google.mail.`, ...) with its `value_root`. For each key of interest, the monitor queries `GET <index-url>/values?key=<key>&before=<input-size>` to verify the matching log entry indices and fetches those certificates from the CT log.

---

### 3.2 Merkle Tree Certificates (MTC)

- **Reference**:
  - [IETF PLANTS Working Group: Merkle Tree Certificates (`draft-ietf-plants-merkle-tree-certs`)](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)

**Who verifies, and why**: Under `draft-ietf-plants-merkle-tree-certs`, Merkle Tree Certificates embed public logging directly into issuance to avoid bulky per-certificate post-quantum signatures in TLS handshakes: CAs log subject assertions (binding DNS names, public keys, and short validity windows) into Merkle trees whose active landmark subtrees are pre-distributed to relying parties. Short certificate lifetimes (days to two weeks) and high issuance volume cause rapid log growth and rely on periodic pruning of expired entries, facing **domain owners** with the same discovery problem as CT at much higher entry velocity.

**Key mapping & prefix lookups**: Identical to Certificate Transparency (§3.1). DNS identifiers in MTC subject assertions map to lowercase Punycode reversed-label keys with a trailing dot (`com.google.mail.`, `com.google.*.`), queried via `<index-url>/keys` under the same trailing-dot and registrable-domain prefix guardrails.

Two external `tlog-vindex` properties matter specifically for MTC deployments:

- **Checkpoint Signature Decoupling**: Output log commitments (`c2sp.org/tlog-vindex-state@v1`) bind unsigned input log state (`input-origin`, `from`, `input-size`, `input-root`, and `mpt-root`). Domain monitors verifying `/keys` and `/values` responses only need the output log's checkpoint verification policy and are decoupled from MTC's upstream checkpoint and cosigned-subtree signature formats; only index operators, independent auditors, and clients verifying MTC checkpoints directly need an MTC checkpoint policy.
- **Log Pruning & Epoch Rotation (`from > 0`)**: Within a single VIndex instance, `from` is fixed and `[from, input_size)` is strictly append-only. When an MTC log prunes expired historical entries below a minimum retained index `P` (or when an operator sheds expired index history), the operator stands up a new VIndex instance and output log, starting at `from = P`. Once `[P, input_size)` covers the full lifetime of all unexpired certificates, monitors confirm `from` meets their coverage horizon and cut over cleanly before the older instance is retired.

---

### 3.3 Go Checksum Database (SumDB)

- **References**:
  - [Go Modules Reference: Checksum Database](https://go.dev/ref/mod#checksum-database)
  - [Proposal: Secure the Public Go Package Ecosystem](https://go.dev/design/25530-sumdb)
  - Public log: [`sum.golang.org`](https://sum.golang.org)

**Who verifies, and why**: When `go get` downloads a dependency, it checks `sum.golang.org` via `/lookup/module@version` to confirm the hash for a _known_ version string. What `sum.golang.org` cannot answer is enumeration: **module authors and security teams** have no verifiable way to ask _"what versions have ever been logged for my module?"_ (to spot an unauthorized release tag) or _"what modules exist under our organization's namespace?"_ without trusting external package registries or proxies.

**From leaf to canonical key**: Each `sum.golang.org` leaf contains newline-delimited `go.sum` lines pairing a module archive and its `/go.mod` file with their hashes:

```text
github.com/google/uuid v1.3.0 h1:tIOElFI0...
github.com/google/uuid v1.3.0/go.mod h1:Usq...
```

To keep the index focused on published releases rather than every ephemeral commit, the mapping function skips untagged Go pseudo-versions and converts tagged module paths into Go's case-encoded canonical form, encoding uppercase letters as `!` followed by lowercase (for example, `github.com/Azure/azure-sdk-for-go` becomes `github.com/!azure/azure-sdk-for-go`). Because both lines of a tagged entry name the same module, each standard release entry produces a single key (`0..1` keys per entry overall).

**Querying the index**: Maintainers query an exact module (`GET <index-url>/keys?key=github.com%2Fgoogle%2Fuuid`, percent-encoding `/` as `%2F` and `!` as `%21`) or an organizational namespace prefix (`GET <index-url>/keys?prefix=github.com%2Fgoogle%2F`), page `<index-url>/values` to obtain the verified log indices, and fetch those entries from `sum.golang.org` to inspect every recorded release tag.

---

### 3.4 Sigstore (Rekor)

- **References**:
  - [Sigstore Documentation](https://docs.sigstore.dev/)
  - [Rekor Transparency Log](https://github.com/sigstore/rekor) (`rekor.sigstore.dev`)

**Who verifies, and why**: Artifact consumers verify a Rekor inclusion proof when installing a signed package or container, which only proves that _that_ signature was logged. Who verifies that an attacker did not briefly hijack a developer's OIDC session or a repository's GitHub Actions workflow to sign something else? **The signers themselves**; developers, release engineers, and CI identity owners must monitor Rekor for every signing event bound to their identity. Rekor's built-in search API is unauthenticated, so it cannot prove that a compromised signing event was not omitted from search results.

**From leaf to canonical key**: Rekor entries (such as `hashedrekord`, `intoto`, and `dsse` records) embed short-lived Fulcio X.509 signing certificates that bind the signer's OpenID Connect (OIDC) identity in the Subject Alternative Name extension. Rather than indexing one-off artifact digests (which would create a new single-entry key for every build), the mapping function extracts the signer identity from the Fulcio SAN; either a lowercase email address (`user@example.com`) or a workload identity URI (`https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main`).

**Querying the index**: Credential owners query their exact email (`GET <index-url>/keys?key=user%40example.com`) or their repository/organization URI prefix (`GET <index-url>/keys?prefix=https%3A%2F%2Fgithub.com%2Forg%2Frepo%2F`), then page `<index-url>/values` to audit every signature or attestation ever issued under their credentials.

---

### 3.5 Sigsum

- **References**:
  - [Sigsum](https://www.sigsum.org/)
  - [Sigsum Documentation & Specifications](https://www.sigsum.org/docs/)

**Who verifies, and why**: Like Sigstore, Sigsum logs signed artifact checksums so downstream users only accept logged signatures, leaving **key holders** responsible for checking the log to verify that no unexpected signatures were ever produced with their Ed25519 signing key.

**From leaf to canonical key & lookup**: Every Sigsum tree leaf is a fixed 128-byte binary record containing a 32-byte `checksum`, a 64-byte Ed25519 `signature`, and a 32-byte `key_hash` (`SHA-256` of the signer's Ed25519 public key). The mapping function hex-encodes `key_hash` into a 64-character lowercase hexadecimal string so it forms a printable ASCII canonical key (`1` key per leaf). Key holders query `GET <index-url>/keys?key=<64-hex-key-hash>` and `<index-url>/values` to verify the complete set of log entries attributed to their key.

---

## 4. Prefix Lookups & Why Keys Remain Un-Hashed

Storing un-hashed canonical keys directly in the MPT (where `0x00`-terminated bit ordering matches unsigned lexicographical byte order) means every byte prefix `<key-prefix>` forms a contiguous subtree verifiable with a single two-sided prefix proof (`GET <index-url>/keys?prefix=<key-prefix>`; see [`tlog-vindex`](./tlog-vindex.md#verifying-a-keys-response)):

1. **One Primitive Across Ecosystems**: The same subtree proof supports domain hierarchy monitoring (`prefix=com.example.`), Go module namespace discovery (`prefix=github.com%2Forg%2F`), and CI workload URI prefix auditing (`prefix=https%3A%2F%2Fgithub.com%2Forg%2F`).
2. **Why Query-Time Prefix Proofs Beat Map-Time Parent Expansion**: An alternative design for DNS hierarchies hashes MPT keys (`SHA-256(key)`) and expands every certificate domain into all registrable parent suffixes at map time (emitting `mail.sub.example.com`, `sub.example.com`, and `example.com` separately). Keeping un-hashed reversed-label keys and resolving prefixes at query time avoids three structural problems:
   - _Key & Value Log Amplification_: Deep subdomains multiply the number of keys and value log leaves committed per certificate across every ancestor label.
   - _Freezing the Mutable Public Suffix List (PSL) into Cryptographic State_: Preventing map-time expansion into bare public suffixes (`com`, `co.uk`) requires baking the ICANN Public Suffix List into the deterministic mapping function. Because the mapping function is fixed for the lifetime of an output log, every PSL amendment makes historical commitments stale unless the operator rebuilds a new index from `from`. With un-hashed reversed-label keys, registrable-domain (eTLD+1) checks live purely in a stateless HTTP prefix policy outside `mpt-root`.
   - _Preserving Subdomain & Wildcard Granularity_: Collapsing child certificates into a single hashed parent key (`SHA-256("example.com")`) hides which subdomains or wildcards (`*.example.com`) exist unless monitors download every certificate ever issued under the parent domain, while hashing MPT keys eliminates prefix queries for module paths and workload URIs.
3. **Bounding Prefix Queries**: Because a prefix lookup returns all matched `(key, value_root)` pairs in one response so the client can reconstruct the prefix subtree hash, servers guard against overly broad scans using application-specific prefix policies (such as rejecting bare public-suffix prefixes like `com.` or `uk.co.`) and matched-key limits that prompt clients to query narrower prefixes.

---

## 5. Operational Considerations

- **Multi-Subject Fanout**: Unlike single-key logs (Go SumDB, Sigsum), a single CT or MTC certificate can carry dozens or hundreds of unique SAN `dNSName` identifiers, updating `N` distinct keys and value logs per input log entry.
- **Mapping Immutability & Re-Indexing**: Because `mpt-root` at any `input-size` is defined by replaying `[from, input_size)` through a fixed mapping function, changing how an ecosystem normalizes keys or selects indexable fields requires standing up a new VIndex instance (with a new output log) from `from = 0` or a chosen suffix start index `from`.
- **Hot Keys & Backward Pagination**: Open-admission logs can accumulate millions of entries under popular keys (such as shared apex domains or busy automated CI identities). Representing each key's occurrences as an append-only RFC 6962 value log and paginating backward (`GET <index-url>/values?key=<key>&before=<before>`) lets monitors verify the newest page directly against `value_root` (via `preceding` compact range hashes) and stop as soon as they reach their previously inspected `entry_idx` watermark.
