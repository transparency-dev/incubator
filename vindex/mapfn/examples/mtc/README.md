# MTC MapFn Example (`mtc.wasm`)

This example implements a VIndex WASM MapFn for **Merkle Tree Certificates (MTC)** logs.

## Supported Leaf Formats

- **MTC Entry Type 1 (`TBSCertificateLogEntry`)**: Parses 2-byte big-endian entry type (`0x0001`) prefix followed by ASN.1 DER `TBSCertificateLogEntry`. Other entry types are ignored.

## Indexing & Reversed-Label Canonical Keys

For each certificate leaf, the mapper:
1. Extracts all DNS names from the **Subject Common Name (CN)** and **Subject Alternative Name (SAN)** extension.
2. Normalizes domains via IDNA2008 Punycode (`idna.Lookup.ToASCII`) and ASCII lowercasing, preserving leading wildcard labels (`*.`) as a terminal wildcard label (`*`).
3. Reverses domain labels and appends a mandatory trailing dot (symmetric with `client.DomainToCanonicalKey`), e.g.:
   - `deep.maps.google.co.uk` -> `uk.co.google.maps.deep.`
   - `*.google.co.uk` -> `uk.co.google.*.`
4. Emits each unique reversed-label canonical key to the host runtime via `sdk.RegisterEmit` without map-time parent domain expansion (hierarchical subdomain discovery is served natively at query time via MPT prefix queries `GET /keys?prefix=uk.co.google.`).

## Building & Testing

Compile the WASM binary:
```bash
go generate ./...
```

Inspect and test against sample inputs:
```bash
vindex-wasm inspect --wasm=mtc.wasm
vindex-wasm test --wasm=mtc.wasm --input_file=leaf.bin
```

## Running with `vindexd`

### Input Log Verification Policies & Public Keys

Use `--input_log_policy` to provide a C2SP `tlog-policy` file, or `--input_log_pubkey` (accepting either a raw key string or a path to a file) for single-key verification under two schemes (`internal/wire`):

1. **Standard RFC 6962 / SumDB Note format**: `<name>+<hash>+<base64Key>`
2. **MTC Cosigned Subtree format**: `mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>`
   - `<name>`: Log name / key name matching the checkpoint signature line (e.g., `oid/1.3.6.1.4.1.44363.47.1.44363.48.8`).
   - `<cosignerID>`: Dotted relative OID for the cosigner (e.g., `44363.48.9`).
   - `<logID>`: Dotted relative OID for the log (e.g., `44363.48.8`).
   - `<ed25519_base64_pubkey>`: Base64-encoded 32-byte Ed25519 public key.

### Example Invocation

To index the Cloudflare MTC Shard 3 log (or pass `--input_log_url="file:///tmp/log-clones/mtc"` after mirroring locally with `clonelog --input_log_url=... --input_log_origin=... --input_log_pubkey=... --out_dir=/tmp/log-clones/mtc`):

```bash
vindexd \
  --input_log_url="https://bootstrap-mtca-shard3.cloudflareresearch.com/" \
  --input_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
  --input_log_pubkey="mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=" \
  --wasm_path="vindex/mapfn/examples/mtc/mtc.wasm" \
  --prefix_policy="reversed-dns" \
  --output_log_dir="/data/vindex/outputlog" \
  --output_log_signer_key="/path/to/output_log_signer.sec" \
  --db_path="/data/vindex/pebble" \
  --mpt_dir="/data/vindex/mpt" \
  --listen_addr=":8080"
```

## Querying with `vindex-client`

Use `--domain` on `vindex-client` to convert a forward DNS domain (e.g. `example.com`, `*.example.com`, or IDN `bücher.example.com`) into its reversed-DNS canonical key (`com.example.` / `com.example.*.`), or combine `--prefix --domain` to discover all indexed subdomains:

```bash
# Exact domain lookup (queries key=com.example.)
vindex-client \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="/path/to/output_log_verifier.pub" \
  --input_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
  --domain="example.com"

# Subdomain prefix lookup (queries prefix=com.example.)
vindex-client \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="/path/to/output_log_verifier.pub" \
  --input_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
  --prefix \
  --all \
  --domain="example.com"
```
