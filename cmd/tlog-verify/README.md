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

The Go Checksum DB (`sum.golang.org`) is a transparency log. We can verify that `github.com/transparency-dev/tessera@v1.0.0` is included in it using the saved proof in `testdata/tessera-v1.0.0.tlog-proof`.

The public key for `sum.golang.org` is:
`sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8`

Since Go SumDB uses `go.sum database tree` as the origin name in its checkpoints (which differs from the key name `sum.golang.org`), we must pass the `--origin` flag.

#### Verification using pre-computed leaf hash

The RFC6962 leaf hash for the Tessera entry is:
*   Hex: `0fa57c511c3b2ffcc0a05ad63172568d265aaf9844e9b636a0978795396f2ab1`
*   Base64: `D6V8URw7L/zAoFrWMXJWjSZar5hE6bY2oJeHlTlvKrE=`

```shell
go run ./cmd/tlog-verify \
  --log-key "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --origin "go.sum database tree" \
  --leaf-hash "D6V8URw7L/zAoFrWMXJWjSZar5hE6bY2oJeHlTlvKrE=" \
  cmd/tlog-verify/testdata/tessera-v1.0.0.tlog-proof
```

#### Verification using raw leaf data

The raw leaf data in SumDB for this entry is:
```
github.com/transparency-dev/tessera v1.0.0 h1:4OT1V9xJLa5NnYlFWWlCdZkCm18/o12rdd+bCTje7XE=
github.com/transparency-dev/tessera v1.0.0/go.mod h1:TLvfjlkbmsmKVEJUtzO2eb9Q2IBnK3EJ0dI4G0oxEOU=
```
Note: The data must include the trailing newline.

Using `--leaf` with literal newlines in quotes (to prevent shell from stripping the trailing newline):
```shell
go run ./cmd/tlog-verify \
  --log-key "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --origin "go.sum database tree" \
  --leaf "github.com/transparency-dev/tessera v1.0.0 h1:4OT1V9xJLa5NnYlFWWlCdZkCm18/o12rdd+bCTje7XE=
github.com/transparency-dev/tessera v1.0.0/go.mod h1:TLvfjlkbmsmKVEJUtzO2eb9Q2IBnK3EJ0dI4G0oxEOU=
" \
  cmd/tlog-verify/testdata/tessera-v1.0.0.tlog-proof
```

Or using `--leaf-file`:
```shell
# Create a file containing the raw leaf data (including the trailing newline)
printf "github.com/transparency-dev/tessera v1.0.0 h1:4OT1V9xJLa5NnYlFWWlCdZkCm18/o12rdd+bCTje7XE=\ngithub.com/transparency-dev/tessera v1.0.0/go.mod h1:TLvfjlkbmsmKVEJUtzO2eb9Q2IBnK3EJ0dI4G0oxEOU=\n" > /tmp/leaf.txt

go run ./cmd/tlog-verify \
  --log-key "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --origin "go.sum database tree" \
  --leaf-file /tmp/leaf.txt \
  cmd/tlog-verify/testdata/tessera-v1.0.0.tlog-proof
```

