# MTC Verifiable Indexer (`mtcindex`)

`mtcindex` is a verifiable indexer for Merkle Tree Certificates (MTC) logs. It processes leaf entries from an MTC log, parses the certificates, and indexes them by domain name in a verifiable map. This allows users to query for all certificates associated with a domain verifiably and efficiently, without downloading the entire log.

For details on the Merkle Tree Certificates specification, see the [MTC Draft](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/).
For details on the Verifiable Index architecture (the "Map Sandwich"), see the [root VIndex README](../../README.md).

## How it works

1. **Input Log**: It monitors an MTC log (e.g., Cloudflare's bootstrap MTC log).
1. **MTC Verification**: It uses a custom checkpoint verifier that handles MTC-specific binary checkpoint signatures (`MTCSubtreeSignatureInput`) instead of standard text-based note signatures.
1. **Parsing (`mapFn`)**: It parses leaf entries of type `tbs_cert_entry` (type 1) using ASN.1, extracts the DNS names from the Subject Alternative Name (SAN) extension, and hashes them. Other entry types (like `null_entry`) are ignored.
1. **Verifiable Map**: It maintains a verifiable map (using Pebble DB for persistence) mapping domain hashes to log indices.
1. **Output Log**: It writes the map roots to an output log, which is signed by the operator.

## Usage

> [!WARNING]
> This demo uses hardcoded cryptographic keys. Do not use these keys in production or public deployments. Ensure you generate and use your own secure keys when deploying this service.

### 1. Run the Indexer

Run the indexer by pointing it to a storage directory and providing the output log private key.

By default, it is configured to index the Cloudflare Shard 3 MTC log. We use a demo private key here:

```bash
OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+example.com/outputlog+07392c46+ATPJ4crkyUbPeaRffN/4NUof3KV0pQznVIPGOQm3SDEJ \
go run ./vindex/cmd/mtcindex/ \
  --storage_dir=/path/to/storage \
  --listen=:8088
```

### 2. Query the Index

Once running, the indexer hosts a web server (default `:8088`) serving the verifiable index.
A domain indexed by the verifiable map can be looked up using the client command.

For example, to look up `minefun.io`:

```shell
go run ./vindex/cmd/client \
  --vindex_base_url http://localhost:8088/vindex/ \
  --out_log_pub_key="example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8" \
  --in_log_pub_key="teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=" \
  --in_log_mtc \
  --in_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
  --in_log_cosigner_id="44363.48.9" \
  --in_log_id="44363.48.8" \
  --in_log_key_name="oid/1.3.6.1.4.1.44363.47.1.44363.48.8" \
  --lookup=minefun.io
```
## Flags

- `--log_url`: Base URL of the MTC log to index (default: `https://bootstrap-mtca-shard3.cloudflareresearch.com/`).
- `--key_name`: The key name used in the checkpoint signature (default: `oid/1.3.6.1.4.1.44363.47.1.44363.48.8`).
- `--log_public_key`: The log's public key, base64 encoded raw 32-byte Ed25519 key (default: `teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=`).
- `--cosigner_id`: The relative OID of the cosigner (default: `44363.48.9`).
- `--log_id`: The relative OID of the log (default: `44363.48.8`).
- `--origin`: The expected origin string in the checkpoint text (default: `bootstrap-mtca.cloudflareresearch.com/logs/shard3`).
- `--storage_dir`: Root directory in which to store the output log data and verifiable map persistence (required).
- `--listen`: Address to set up the HTTP server on (default: `:8088`).
- `--persist_index`: Set to false to use a memory-based implementation of the verifiable index (default: `true`).
- `--oneshot`: Set to true to build the map once up to the current log size and then exit (default: `false`).
- `--output_log_private_key_path`: Location of the output log private key file.
