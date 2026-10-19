# Verifiable Index Applications & Ecosystem Specifications

This document defines the application architecture, canonicalization profiles, verified performance optimizations, real-world ecosystem specifications, operational considerations, and retired design branches for **VIndex v1**.

---

## 0. High Level Overview

### 0.0 The Claimant Model & Claim Subject Maps (CSM)
In terms of the [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md), VIndex operates as a **Claim Subject Map (CSM)** or **Map of Logs (MoL)** over an append-only log:
- **Claim Subjects**: The specific entities an index record or log entry concerns (e.g. domain name, Go module path, OIDC signing identity, or Ed25519 public key).
- **Value Logs**: The value committed at each key is an append-only value log of matching Input Log entry indices (`entry_idx`).

The core security property of a Claim Subject Map is **Discoverability**: a lookup client must be able to discover all claims regarding a Claim Subject without scanning the entire underlying log.

### 0.1 Mental Models: The Phonebook and the Fanout Multiplier
- **The "Universal Phonebook"**: VIndex is agnostic to the internal structure of the underlying Input Log entry payload. It does not parse or interpret payloads during serving; it only requires an unambiguous canonical key (the "name" in the phonebook) and Input Log entry indices (`entry_idx`) to construct authenticated inclusion proofs.
- **The "Fanout Multiplier"**: Different ecosystems exhibit radically different mapping cardinality:
  - In **Go SumDB**, each entry maps to **at most one** module path (`0..1` keys per entry; pseudo-versions are filtered out and emit zero keys, while tagged release entries emit one deduplicated case-escaped module path).
  - In **Certificate Transparency (CT)** and **Merkle Tree Certificates (MTC)**, a single certificate contains a Subject Common Name (CN) and multiple Subject Alternative Names (SANs). Each unique DNS name is emitted once in reversed-label trailing-dot notation (`"com.google.mail."`, `"com.google.*."`) without parent-domain expansion at map time; hierarchical subdomain discovery is performed at query time via MPT prefix lookups (`?prefix=<key-prefix>`).

---

## 1. Universal Mapping & Canonicalization Invariants

To guarantee that lookup clients can independently discover records, the Index Operator (`MapFn`) and lookup clients must agree on the exact byte-level representation of every canonical key (`1..1024` printable ASCII bytes in `0x21..0x7E`).

- **[Correctness Invariant] Deterministic Canonical Agreement**:
  - *Rule*: The normalization from a real-world identifier (e.g. domain name, module path, OIDC identity) to its canonical key bytes MUST be unambiguous and deterministically agreed upon by both the Index Operator (`MapFn`) and lookup clients. The MPT and HTTP query endpoints (`<index-url>/keys` and `<index-url>/values`) operate directly on un-hashed canonical keys, while `KeyHash = SHA-256(key)` is computed strictly as an internal Pebble storage digest for inverted chunk keys (`'c'`).
  - *Rationale*: MPT radix paths and byte-prefix matching operate directly on exact canonical key bytes. If the Index Operator formats reversed domain labels with a trailing dot (`com.example.`) while a lookup client queries `example.com` or omits the trailing dot, the client's lookup targets a different trie path.
  - *Consequence ("Or Else")*: The lookup client will query an unpopulated canonical key or prefix and receive a valid cryptographic non-inclusion proof, falsely concluding that no records exist for their identity.

- **[Correctness Invariant] Per-Entry Canonical Key Deduplication**:
  - *Rule*: When a single Input Log entry maps to multiple canonical keys (1-to-N fanout), duplicate canonical keys emitted for the same entry must be discarded so each `entry_idx` is recorded at most once per canonical key (`(key, entry_idx)`).
  - *Rationale*: Certificates frequently repeat the same domain across Subject Common Name and Subject Alternative Name fields, while SumDB entries repeat the module path across version and `/go.mod` lines.
  - *Consequence ("Or Else")*: Duplicate relative offsets would be appended to value log chunks, producing invalid RFC 6962 compact range hashes and wasting storage.

- **[Performance Optimization] Raw Canonical Key Emission & Host SIMD Storage Hashing**:
  - *Mechanism*: The sandboxed WASM `MapFn` parses raw Input Log entry bytes and emits raw canonical keys (`0x21..0x7E`) across the FFI boundary. The Go host preserves those un-hashed canonical keys directly for MPT point and prefix indexing, while computing `KeyHash = SHA-256(key)` strictly for internal Pebble inverted chunk keys using native CPU hardware instructions (Single Instruction, Multiple Data / SIMD, such as **x86 SHA-NI** or **ARMv8 Crypto**).
  - *Impact*: Preserves lexicographical prefix locality in the MPT while eliminating the ~55% software cryptographic hashing bottleneck inside WebAssembly bytecode for fixed-width KV chunk keys.

### 1.1 Universal Canonicalization Reference Profiles

| Application | Claim Subject Type | Canonical Key Extraction Profile (Guest WASM -> Un-Hashed MPT Key) | Internal Pebble Storage KeyHash | Cardinality Profile |
| :--- | :--- | :--- | :--- | :--- |
| **Certificate Transparency** | Reversed-Label Domain Name | Extract Subject CN + SAN `dNSName`; IDNA2008 Punycode (`xn--...`); ASCII lowercase; reverse labels with mandatory trailing dot (`*.mail.google.com` -> `com.google.mail.*.`). No map-time parent expansion. | `SHA-256(key)` | 1-to-N (1 per unique SAN/CN) |
| **Merkle Tree Certificates** | Reversed-Label Domain Name | Same as CT: extract Subject CN + SAN `dNSName`, IDNA2008 Punycode, lowercase, reverse labels with mandatory trailing dot (`com.google.mail.`). No map-time parent expansion. | `SHA-256(key)` | 1-to-N (1 per unique SAN/CN) |
| **Go Software Supply Chain** | Escaped Module Path | Filter out untagged pseudo-versions (`vX.Y.Z-yyyymmddhhmmss-abcdefabcdef`); apply canonical Go module path case-escaping via `module.EscapePath` (`!` + lowercase for uppercase letters). | `SHA-256(key)` | At most 1-to-1 (`0..1` keys/entry) |
| **Sigstore** | Signer Identity | Lowercase, whitespace-trimmed OIDC email or workload identity URI string. | `SHA-256(key)` | 1-to-1 (or 1-to-N per SAN identity) |
| **Sigsum** | Ed25519 Key | Lowercase 64-character hex string of 32-byte public key hash. | `SHA-256(key)` | 1-to-1 (exactly 1 key/entry) |

---

## 2. Known Applications

### 2.1 Certificate Transparency (RFC 6962 / Static-CT)

- **Real-World Context & References**:
  - [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
  - [C2SP Static CT API Specification](https://c2sp.org/static-ct-api)
  - Primary production logs: Google Argon, Let's Encrypt Oak, Cloudflare Nimbus.

#### The Problem
In Certificate Transparency, domain owners must monitor all certificates issued for their domains (and any subdomains beneath their registered domain) to detect unauthorized issuance or compromised Certificate Authorities (CAs). Today, monitors face an untenable dilemma: either download and parse terabytes of massive CT logs, or trust centralized third-party search engines (like `crt.sh`), which can omit records inadvertently or maliciously without cryptographic detection.

#### Input Log Format & Payloads
CT logs store RFC 6962 / `static-ct` entries consisting of serialized X.509 certificates and precertificates (`x509_entry` / `precert_entry`). Entry payloads contain ASN.1 DER-encoded `TBSCertificate` structures with Subject Common Names (CN) and Subject Alternative Name (SAN) extensions (`dNSName`).

#### MapFn Key Extraction & Normalization
The WASM `MapFn` parses the DER certificate or precertificate entry, extracts the Subject CN and all SAN `dNSName` entries, and normalizes each valid DNS name into a reversed-label canonical key with a mandatory trailing dot (`ToReversedDomainKey`):
1. Trim ASCII whitespace and any trailing dot (`example.com.` -> `example.com`).
2. Preserve leading wildcard labels (`*.example.com`) as a terminal wildcard label (`*`), while silently skipping bare `*` or partial-label wildcards (`*foo.example.com`).
3. Convert Internationalized Domain Names (IDN) to Punycode via IDNA2008 (`idna.Lookup.ToASCII`), lowercase ASCII characters (`Bücher.Example.com` -> `xn--bcher-kva.example.com`), and enforce strict DNS label syntax and canonical key bounds (`1..1024` bytes in `0x21..0x7E`). Non-DNS Subject Common Names (such as human-readable CA/organization strings containing spaces), IP literals, malformed labels, or oversized names MUST be silently skipped in-guest without emitting an invalid key (since emitting an invalid canonical key triggers a fatal host `HALT`).
4. **Reverse Labels with Trailing Dot (Zero Map-Time Parent Expansion)**: Reverse the domain labels and append a mandatory trailing `.` (`mail.google.com` -> `com.google.mail.`, `*.google.com` -> `com.google.*.`). Parent suffixes are **not** expanded at map time; instead, subdomain hierarchy discovery is served natively via MPT prefix queries (`?prefix=<key-prefix>`).

#### Lookup Client Query & Verification Flow
1. **Prefix / Point Discovery (`GET <index-url>/keys?prefix=com.google.`)**: A domain owner queries the reversed registrable domain prefix `com.google.` via `prefix=com.google.`. When configured on `vindexd` (`--prefix_policy=reversed-dns`, wired into `server.PrefixPolicy`), the policy verifies that `<key-prefix>` ends with a mandatory trailing `.` (preventing cross-label prefix scans like `com.google` matching `com.googleapis.`), reverses the DNS labels, and checks `golang.org/x/net/publicsuffix.EffectiveTLDPlusOne` so bare TLD or public-suffix scans like `com.` or `uk.co.` are rejected with `HTTP 400 Bad Request`. VIndex returns the `c2sp.org/tlog-vindex-keys@v1` response (`proof [<base64-mpt-proof>]` and `<canonical-key> <base64-value-root>` lines listing every matching subdomain and wildcard key such as `com.google.`, `com.google.*.`, `com.google.mail.`, etc.) followed by the `c2sp.org/tlog-proof@v1` Output Log inclusion proof.
2. **Value Retrieval (`GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]`)**: For each matched key in `c2sp.org/tlog-vindex-keys@v1` (with initial cursor `before = input_size`), the lookup client fetches the matching Input Log entry indices (`entry_idx`) from the lock-free `<index-url>/values` endpoint (`c2sp.org/tlog-vindex-values@v1`) and verifies that the RFC 6962 Merkle root reconstructed from the compact range hashes and returned `entry_idx` values equals the key's authenticated `value_root`.
3. **Certificate Retrieval**: The lookup client fetches the raw certificate entries from the CT log using the verified `entry_idx` positions to inspect validity dates, public keys, and revocation status.

---

### 2.2 Merkle Tree Certificates (MTC & Post-Quantum)

- **Real-World Context & References**:
  - [IETF TLS Merkle Tree Certificates Draft](https://datatracker.ietf.org/doc/draft-ietf-tls-merkle-tree-certs/)

#### The Problem
Merkle Tree Certificates replace traditional WebPKI X.509 signatures with Merkle inclusion proofs in an append-only log. Because MTC certificates have very short lifespans (e.g. 14 days) and high issuance volumes (hundreds of millions of certs), log sizes expand rapidly, making full log scanning impractical for standard domain owners.

#### Input Log Format, Payloads & Checkpoint Boundary
Under `draft-ietf-tls-merkle-tree-certs`, MTC logs carry DNS and X.509 certificate subject assertions—including `CertificateEntry` / `TBSCertificate` (`TBSCertificateLogEntry`) payloads binding Subject Alternative Name (`dNSName`) and Subject Common Name (`CN`) identifiers alongside public keys and validity windows, issued at 10x–50x the frequency of classic CT.

**`tlog-vindex` Checkpoint Boundary**: Each `c2sp.org/tlog-vindex-state@v1` Output Log entry embeds a signed C2SP `tlog-checkpoint` verified against an Input Log `tlog-policy`. Because native MTC logs authenticate state using cosigned subtree signatures rather than standard C2SP `tlog-checkpoint` notes, indexing an MTC log either pairs an experimental origin-bound `torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(origin), torchwood.SingleVerifierPolicy(v))` MTC `note.Verifier` adapter (`internal/mtc`) or clones MTC entries into a standard C2SP tiled log (`cmd/clonelog`).

#### MapFn Key Extraction & Personality Configuration
The WASM `MapFn` parses the MTC `CertificateEntry` / `TBSCertificate` DER payload, extracts Subject Common Name (CN) and SAN `dNSName` identifiers, and applies the identical reversed-label trailing-dot canonicalization as CT (`ToReversedDomainKey`: lowercase, IDNA2008 Punycode, strict DNS label and `1..1024` byte `0x21..0x7E` validation skipping non-DNS CNs/malformed labels without emitting invalid keys or trapping, reversed labels + trailing `.`, preserving `*.` as terminal `*.`, with zero map-time parent suffix expansion). Like CT, MTC personality deployments optionally configure `--prefix_policy=reversed-dns` on `vindexd` to require a trailing `.` and reject bare TLD/public-suffix prefix scans (`com.`, `uk.co.`).

#### Interaction with Log Pruning
MTC logs rely on aggressive log pruning to discard expired certificates. Within a running VIndex instance, `from` is immutable and `[from, input_size)` is strictly append-only—in-place index pruning or deleting historical KV entry indices is not supported. Instead, VIndex handles pruned logs via **epoch rotation (`from > 0`)**:
- When bootstrapping against an MTC log whose prefix `< P` has already been pruned (or when shedding historical index state), the Index Operator stands up a new VIndex instance with start index `from = P` (`c2sp.org/tlog-vindex-state@v1`), scoping all value logs, `<index-url>/values` responses, and independent auditing strictly to `[P, input_size)`.
- Lookup clients and auditors roll over cleanly from the older VIndex instance to the new `from = P` instance once its coverage overlaps active certificate lifetimes, after which the older VIndex instance can be retired.

---

### 2.3 Go Software Supply Chain (Go Checksum Database / SumDB)

- **Real-World Context & References**:
  - [Go Module Mirror and Checksum Database Specification](https://golang.org/cmd/go/#hdr-Module_authentication_failures)
  - [Go Checksum Database Architecture](https://go.dev/design/25530-sumdb)
  - Primary production log: `sum.golang.org` (>61.7 million entries)

#### The Problem
The Go Checksum Database (`sum.golang.org`) ensures that module versions downloaded by `go get` match the versions downloaded by everyone else. However, SumDB provides point lookups only by exact version (`/lookup/{module}@{version}`). It provides no native mechanism to query all known versions of a module. Developers cannot discover whether new versions or unauthorized patch releases have been published without querying external package registries.

#### Input Log Format & Payloads
Each SumDB entry contains plain-text, newline-delimited lines (a module archive hash line and a `/go.mod` hash line):
```text
github.com/google/uuid v1.3.0 h1:tIOElFI0...
github.com/google/uuid v1.3.0/go.mod h1:Usq...
```

#### MapFn Key Extraction & Normalization
The WASM `MapFn` scans the lines of the SumDB record, extracts the module path and version token, filters out ephemeral pseudo-versions (`vX.Y.Z-yyyymmddhhmmss-abcdefabcdef`), and emits the canonical module path for tagged releases:
- Module paths are normalized using standard Go module path case-escaping, replacing uppercase characters with `!` followed by lowercase.
- **At-Most 1-to-1 Cardinality (`0..1` keys per entry)**: Many SumDB entries represent untagged commit pseudo-versions and output **zero** keys. For tagged versions, the two lines in the record (`v1.3.0` and `v1.3.0/go.mod`) share the identical module path and are deduplicated per entry into a single `entry_idx` occurrence.

- **[Performance Optimization] Zero-Allocation Byte Scanner**:
  - *Mechanism*: Guest WASM module replaces standard Go regex engines with a zero-allocation byte scanner to filter pseudo-versions without heap allocations.
  - *Impact*: Eliminated `reflect`, `regexp`, and Unicode tables inside `sumdb.wasm`, reducing guest binary size by 24% (from 2.5 MB to 1.9 MB) and accelerating mapping throughput.

#### Lookup Client Query & Verification Flow
1. **Point or Prefix Query**: A developer queries `GET <index-url>/keys?key=github.com%2Fgoogle%2Fuuid` for an exact module or `GET <index-url>/keys?prefix=github.com%2Fgoogle%2F` to discover all modules under `github.com/google/`.
2. **Value Retrieval**: Using the authenticated `value_root` from `c2sp.org/tlog-vindex-keys@v1`, the lookup client queries `GET <index-url>/values?key=github.com%2Fgoogle%2Fuuid&before=<input_size>&limit=100` to retrieve and verify the list of all Input Log entry indices where tagged versions of `github.com/google/uuid` appeared.
3. **Audit**: The developer fetches the corresponding entries from `sum.golang.org` to enumerate every release tag ever committed for that module.

---

### 2.4 Sigstore (Cosign & Rekor)

- **Real-World Context & References**:
  - [Sigstore Architecture Specification](https://docs.sigstore.dev/architecture/)
  - [Rekor Transparency Log](https://github.com/sigstore/rekor)
  - Primary production log: `rekor.sigstore.dev`

#### The Problem
Sigstore logs cryptographic software provenance, signatures, and attestations in an append-only transparency log (Rekor). Identity owners and security teams monitoring signatures and attestations issued under a specific OpenID Connect (OIDC) email or CI workload identity must otherwise scan Rekor or rely on Rekor's non-verifiable search index.

#### Input Log Format & Payloads
Rekor stores pluggable entry types (e.g. `hashedrekord`, `intoto`) containing JSON payloads with signatures, Fulcio X.509 signing certificates (binding OIDC identities in Subject Alternative Names), and transparency timestamps.

#### MapFn Key Extraction & Normalization
The WASM `MapFn` extracts **Signer Identity** canonical keys from the Fulcio X.509 signing certificate's Subject Alternative Name (SAN) extension, silently skipping any malformed or oversized identity outside `1..1024` printable ASCII bytes (`0x21..0x7E`) without emitting an invalid key (keying by per-build artifact digests is intentionally avoided to prevent unbounded single-occurrence MPT key explosion):
- **OIDC Email**: Lowercase, whitespace-trimmed email address (e.g. `user@example.com`).
- **Workload Identity URI**: Normalized URI string (e.g. `https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main`), which also supports organizational or repository prefix queries (`?prefix=https%3A%2F%2Fgithub.com%2Forg%2F`).

#### Lookup Client Query & Verification Flow
Identity monitors query VIndex by OIDC email (`?key=user%40example.com`) or workload URI prefix (`?prefix=https%3A%2F%2Fgithub.com%2Forg%2Frepo%2F`) to retrieve and verify all signatures and attestations issued under their credentials against witnessed Output Log checkpoints, detecting compromised tokens or unauthorized CI runs.

---

### 2.5 Sigsum (Public Key Logging)

- **Real-World Context & References**:
  - [Sigsum: Free and Open Source Public Key Logging](https://www.sigsum.org/)
  - [Sigsum System Design](https://git.sigsum.org/sigsum/tree/doc/design.md)

#### The Problem
Sigsum is a minimalist transparency log that stores cryptographic signatures tied to Ed25519 public keys. Lookup clients need to discover all signatures issued by a specific public key to detect unauthorized key use or account compromise.

#### Input Log Format & Payloads
Sigsum entries are strictly formatted, fixed-size binary records (128 bytes) consisting of a 32-byte checksum (`SHA-256` over the artifact hash), a 64-byte Ed25519 signature, and a 32-byte Ed25519 public key hash (`SHA-256` of the signer's public key).

#### MapFn Key Extraction & Normalization
The WASM `MapFn` extracts the 32-byte public key hash directly from its fixed binary offset and encodes it as a **64-character lowercase hexadecimal ASCII string** (`[0-9a-f]{64}`) so that the emitted canonical key satisfies the printable ASCII constraint (`0x21..0x7E`). The MPT stores that un-hashed 64-character hex canonical key directly, while the host computes `KeyHash = SHA-256(key)` strictly as an internal Pebble storage digest. Mapping is strictly 1-to-1.

---

## 3. Native Prefix-Trie & Subtree Indexing

Because `MapFn` plugins emit un-hashed variable-length canonical keys (`1..1024` printable ASCII bytes `0x21..0x7E`) directly into the MPT (`filippo.io/torchwood/mpt`), VIndex v1 natively supports cryptographic prefix and subtree queries without map-time suffix expansion:

1. **Hierarchy Discovery Without Map-Time Fanout**: Reversed-label trailing-dot domain keys (`com.google.mail.`, `com.google.*.`) allow querying `GET <index-url>/keys?prefix=com.google.` to discover the apex domain and every subdomain/wildcard in a single two-sided MPT prefix proof (`mpt.ProvePrefix` / `mpt.VerifyPrefix`), avoiding map-time write amplification across parent labels.
2. **Namespace / Organization Discovery (`github.com/org/`)**: In Go SumDB, developers can query `GET <index-url>/keys?prefix=github.com%2Forg%2F` to cryptographically enumerate all indexed modules published under an organizational namespace.
3. **Personality Prefix Policy Guardrails**: CT and MTC personality deployments can enable `--prefix_policy=reversed-dns` on `vindexd` (requiring a trailing `.` on `<key-prefix>` and validating eTLD+1 depth via `publicsuffix.EffectiveTLDPlusOne`) to reject overly broad bare TLD or public-suffix scans (`com.`, `uk.co.`) with `HTTP 400 Bad Request`, alongside `--max_prefix_keys` (`HTTP 413 Content Too Large`). See [`docs/tlog-vindex.md`](./tlog-vindex.md#keys) for the formal prefix lookup specification.

---

## 4. Operational Realities & Known Pain Points

- **High-Fanout Storage Amplification in CT**: Unlike 1-to-1 logs (SumDB, Sigsum), Certificate Transparency generates high key cardinality. A single certificate entry covering 100 SANs writes to 100 distinct inverted chunk keys in Pebble. This causes LSM-tree write amplification and requires provisioning larger SSD capacity.
- **Canonicalization Immutability**: If an ecosystem changes its canonicalization standard (e.g. transitioning from IDNA2003 to IDNA2008 domain Punycode normalization), the index cannot be patched in-place. The Index Operator must deploy a new VIndex instance and re-index from its configured start index `from` (`0` or a suffix start index).
- **Hot-Key Flooding in Open-Admission Logs**: Open-admission logs can be intentionally spammed with popular keys (e.g. thousands of certs issued for `example.com`), creating deeply stacked 64K chunks. Lookup clients querying these hot keys execute backward pagination queries (`before=<before>`) to retrieve older pages beyond the most recent occurrences.

---

## 5. Retired Alternatives Considered

### 5.1 Hashed MPT Keys & Map-Time Parent Domain Expansion
- **Proposed**: Storing fixed 32-byte `SHA-256(key)` digests as MPT keys while having the CT/MTC WASM `MapFn` expand every certificate domain into all registrable parent suffixes at map time (e.g. emitting `mail.sub.example.com`, `sub.example.com`, and `example.com` separately).
- **Rejection Findings**:
  1. **3x–5x Write Amplification**: Deep subdomains multiplied MPT leaf updates and Pebble `'c'` chunk writes by 3x–5x across high-fanout CT/MTC logs, inflating both memory-mapped trie size and SSD compaction churn.
  2. **Mutable Public Suffix List (PSL) Inside the Deterministic WASM TCB**: Preventing parent expansion into bare TLDs (`com`, `co.uk`) required compiling the ICANN Public Suffix List directly into the immutable `.wasm` module; because `map-fn` is frozen across an Output Log, every PSL update forced deploying a new VIndex instance and re-indexing the entire Input Log from `from`.
  3. **Loss of Subdomain & Wildcard Granularity**: Collapsing child certificates into a single hashed parent key (`SHA-256("example.com")`) hid which distinct subdomains or wildcards (`*.example.com`) existed unless lookup clients downloaded every certificate entry ever issued under the parent domain, while hashing MPT keys destroyed prefix queries for all other ecosystems (such as Go module namespaces and OIDC workload URIs).
- **Resolution**: Store un-hashed, variable-length reversed-label canonical keys (`com.example.mail.`, `com.example.*.`) directly in the MPT and serve hierarchical discovery at query time via two-sided MPT prefix proofs (`GET <index-url>/keys?prefix=com.example.`), keeping the mutable eTLD+1 guardrail (`--prefix_policy=reversed-dns`) strictly as a stateless HTTP query-admission policy outside the cryptographic state commitment.

### 5.2 In-Guest Regex Engines for Version Parsing
- **Proposed**: Importing `golang.org/x/mod/module` inside the guest WASM binary to parse and filter pseudo-versions using standard Go regex expressions.
- **Empirical Rejection**: Embedded `reflect`, `regexp`, and Unicode tables into the WASM bytecode, bloating `sumdb.wasm` to 2.5 MB and consuming significant heap allocation cycles.
- **Resolution**: Replaced with a zero-allocation byte scanner, shrinking WASM binary size by 24% (down to 1.9 MB) and improving parsing throughput.

### 5.3 Subsystem-Level Alternatives
- **In-Guest Software Cryptographic Hashing**: Retired in favor of emitting un-hashed canonical keys from WASM and computing internal Pebble storage digests (`KeyHash = SHA-256(key)`) on the host via hardware SIMD instructions; see [`mapfn/README.md`](../mapfn/README.md#3-alternatives-considered-or-tried).

---

## 6. Verification Gate

All application mapping profiles (`ct`, `mtc`, `sumdb`) and canonicalization tests are verified via:

```bash
go test -race ./vindex/mapfn/... ./vindex/cmd/...
```
