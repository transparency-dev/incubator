# tlog-verify

`tlog-verify` is a command-line tool that performs offline verification of transparency log proofs formatted according to the [c2sp.org/tlog-proof](https://c2sp.org/tlog-proof) specification.

## Motivation

Transparency logs allow verifiers to ensure that data has been publicly logged. A `tlog-proof` file bundles all the information needed to verify that a specific leaf exists in the log at a specific checkpoint:
1. The log checkpoint (signed by the log).
2. The index of the entry.
3. The Merkle inclusion proof.

This tool allows verifying these proofs offline, given the log's public verifier key and the expected leaf data (or its hash).

## Usage

```shell
go run ./cmd/tlog-verify --log-key <key> [flags] [proof-file]
```

If `proof-file` is omitted, the proof is read from standard input.

### Flags

*   `--log-key`: (Required) Log verifier key (format: `name+hash+key`).
*   `--origin`: (Optional) Expected log origin in checkpoint. Defaults to the name in the log key.
*   `--leaf-hash`: Pre-computed leaf hash (hex or base64 encoded).
*   `--leaf`: Raw leaf data string.
*   `--leaf-file`: Path to file containing raw leaf data.

Exactly one of `--leaf-hash`, `--leaf`, or `--leaf-file` must be specified.
If raw leaf data is provided (`--leaf` or `--leaf-file`), it is hashed using the RFC6962 leaf hashing strategy: `SHA256(0x00 || data)`.

### Example: Go Checksum DB (SumDB)

The Go Checksum DB (`sum.golang.org`) is a transparency log. You can use the [Woodpecker Web](../../woodpecker-web) viewer to browse the log and export proof and leaf files.

For example, for entry `#43930254` (which contains `github.com/transparency-dev/tessera@v1.0.0`), you can export:
1.  The proof bundle: `go.sum-database-tree-43930254.tlog-proof`
2.  The raw leaf file: `go.sum-database-tree-43930254.raw`

For convenience, these files are checked into the repository in the `testdata` directory.

The public key for `sum.golang.org` is:
`sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8`

Since Go SumDB uses `go.sum database tree` as the origin name in its checkpoints (which differs from the key name `sum.golang.org`), we must pass the `--origin` flag.

#### Verification using raw leaf file (Recommended)

This verifies that the actual content of the leaf matches what is in the log:

```shell
go run ./cmd/tlog-verify \
  --log-key "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --origin "go.sum database tree" \
  --leaf-file cmd/tlog-verify/testdata/go.sum-database-tree-43930254.raw \
  cmd/tlog-verify/testdata/go.sum-database-tree-43930254.tlog-proof
```

#### Verification using pre-computed leaf hash

This only verifies that the hash is present in the log (it does not verify the leaf content):

The RFC6962 leaf hash for this Tessera entry is `D6V8URw7L/zAoFrWMXJWjSZar5hE6bY2oJeHlTlvKrE=` (base64).

```shell
go run ./cmd/tlog-verify \
  --log-key "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --origin "go.sum database tree" \
  --leaf-hash "D6V8URw7L/zAoFrWMXJWjSZar5hE6bY2oJeHlTlvKrE=" \
  cmd/tlog-verify/testdata/go.sum-database-tree-43930254.tlog-proof
```

