# CT MapFn Example (`ct.wasm`)

This example implements a VIndex WASM MapFn for **Certificate Transparency (CT)** logs.

## Supported Leaf Formats

- **RFC 6962 CT Logs**: Parses TLS `MerkleTreeLeaf` structures containing both `x509_entry` (full X.509 certificate) and `precert_entry` (PreCertificate TBS DER).
- **Static CT Logs (C2SP / Sunlight / TesseraCT)**: Parses individual leaf entries unpacked from static data tiles (standard X.509 DER or RFC 6962 `MerkleTreeLeaf`).

> [!NOTE]
> **Merkle Tree Certificates (MTC) are not supported** by this MapFn. MTC issuance logs use a distinct ASN.1 `TBSCertificateLogEntry` schema with `SubjectPublicKeyInfoHash` rather than standard X.509 `SubjectPublicKeyInfo`.

## Indexing & Reversed-Label Canonical Keys

For each certificate or precertificate leaf, the mapper:
1. Extracts all DNS names from the **Subject Common Name (CN)** and **Subject Alternative Name (SAN)** extension using a zero-allocation ASN.1 TLV scanner.
2. Normalizes domains via IDNA2008 Punycode (`idna.Lookup.ToASCII`) and ASCII lowercasing, preserving leading wildcard labels (`*.`) as a terminal wildcard label (`*`).
3. Reverses domain labels and appends a mandatory trailing dot (`ToReversedDomainKey`), e.g.:
   - `auth.service.example.com` -> `com.example.service.auth.`
   - `*.example.com` -> `com.example.*.`
4. Emits each unique reversed-label canonical key via `sdk.RegisterEmit` without map-time parent domain expansion (hierarchical subdomain discovery is served natively at query time via MPT prefix queries `GET /keys?prefix=com.example.`).

## Building & Testing

Compile the WASM binary:
```bash
go generate ./...
```

Inspect and test against sample inputs:
```bash
# Verify ABI compliance
vindex-wasm inspect --wasm=ct.wasm

# Test against a leaf payload
vindex-wasm test --wasm=ct.wasm --input_file=leaf.bin
```
