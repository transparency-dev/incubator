# VIndex WASM MapFn Examples

This directory contains standalone example implementations of VIndex WASM MapFn binaries.

These examples demonstrate how external developers can implement and compile custom indexing logic using the [VIndex Guest SDK](../sdk) without needing to upstream code into the core VIndex repository.

---

## Examples Overview

1. **`sumdb`** (`mapfn/examples/sumdb`):
   - Parses Go Checksum Database (`go.sum`) leaves.
   - Validates module path and semver formats.
   - Filters out ephemeral pseudo-versions.
   - Emits canonical case-escaped Go module paths (`module.EscapePath`) via `sdk.RegisterEmit`.

2. **`ct`** (`mapfn/examples/ct`):
   - Parses Certificate Transparency (RFC 6962) `MerkleTreeLeaf`, C2SP Static-CT `TileLeaf`, raw X.509 DER certificates, and PreCertificates.
   - Extracts Subject Common Name (CN) and Subject Alternative Names (SANs).
   - Normalizes domains (IDNA2008 Punycode, lowercase) into reversed-label canonical keys with a mandatory trailing dot (`com.google.mail.`, `com.google.*.`), without map-time parent expansion.
   - Emits canonical domain keys via `sdk.RegisterEmit` for direct MPT prefix/point indexing.

3. **`starter`** (`mapfn/examples/starter`):
   - Minimal boilerplate demonstrating zero-allocation leaf ingestion and key emission.
   - Ideal starting point for writing a custom MapFn from scratch.

---

## Building the Examples

### 1. Using `go generate`
Build all example WASM binaries from the repository root:

```bash
go generate ./vindex/mapfn/examples/...
```

### 2. Manual Invocation
Or compile individually using standard Go flags:

```bash
# Build starter template
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-buildid=" \
  -buildmode=c-shared \
  -o vindex/mapfn/examples/starter/starter.wasm \
  github.com/transparency-dev/incubator/vindex/mapfn/examples/starter

# Build SumDB example
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-buildid=" \
  -buildmode=c-shared \
  -o vindex/mapfn/examples/sumdb/sumdb.wasm \
  github.com/transparency-dev/incubator/vindex/mapfn/examples/sumdb

# Build CT example
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-buildid=" \
  -buildmode=c-shared \
  -o vindex/mapfn/examples/ct/ct.wasm \
  github.com/transparency-dev/incubator/vindex/mapfn/examples/ct
```

---

## Testing with `vindex-wasm`

You can test and benchmark the precompiled binaries using `vindex-wasm`:

```bash
# 1. Test single leaf
go run ./vindex/cmd/vindex-wasm test \
  --wasm=./vindex/mapfn/examples/sumdb/sumdb.wasm \
  --input="golang.org/x/mod v0.14.0 h1:abc=" \
  --format=json

# 2. Inspect ABI compliance and map-fn commitment digest
go run ./vindex/cmd/vindex-wasm inspect \
  --wasm=./vindex/mapfn/examples/ct/ct.wasm

# 3. Benchmark throughput and latency percentiles
go run ./vindex/cmd/vindex-wasm bench \
  --wasm=./vindex/mapfn/examples/sumdb/sumdb.wasm \
  --iterations=1000 \
  --workers=4
```
