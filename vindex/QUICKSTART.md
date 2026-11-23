# VIndex v1 Quickstart & Developer Guide

This guide walks you through running a Verifiable Index, querying it with full cryptographic proofs, authoring a custom WebAssembly mapping function, and indexing your own transparency log.

---

## Tooling & Prerequisites

Before starting, ensure you have the following installed:

* **[Go](https://go.dev/dl/)** (>= 1.27 required for `wasip1` builds and workspace toolchain)
* **[just](https://github.com/casey/just#installation)** (Command runner for repository automation)
* **[Docker](https://docs.docker.com/get-docker/)** (Optional; required for multi-container SumDB stack)

Verify your environment:
```bash
go version
just --version
docker --version # optional
```

---

## 1. 30-Second Local Demo

To see VIndex in action with zero manual configuration:

```bash
just demo-local
```

What this does automatically:
1. Compiles the [`starter`](./mapfn/examples/starter) WASM mapping function targeting `wasip1/wasm`.
2. Creates an ephemeral local [Tessera](https://github.com/transparency-dev/tessera) input log with sample leaves (`apple`, `banana`, `cherry`, `apple`).
3. Generates cryptographic Ed25519 Note keys.
4. Starts `vindexd` on ephemeral localhost ports to ingest, extract keys in WASM, update the Sparse Merkle Patricia Trie, and commit checkpoints.
5. Runs `vindex-client` queries verifying multi-index occurrences (`apple` -> indices `[0, 3]`), Input Log checkpoint consistency, raw leaf dereferencing, and non-inclusion (`nonexistent`).
6. Shuts down cleanly with zero orphaned processes or leftover temp files.

---

## 2. Building Core Binaries

To build all VIndex command-line tools into `bin/`:

```bash
just build
```

Or manually with standard `go build`:
```bash
mkdir -p bin
go build -o bin/ ./vindex/cmd/...
```

| Binary | Purpose |
| :--- | :--- |
| `bin/vindexd` | VIndex indexing and HTTP serving daemon (supports `--oneshot` catch-up) |
| `bin/vindex-client` | End-user CLI for cryptographically verified key and prefix lookups |
| `bin/vindex-wasm` | Tooling for inspecting, testing, and benchmarking WASM mapping plugins |
| `bin/vindex-auditor` | Independent full-log auditor |
| `bin/hammer` | Conformance and load-testing harness |
| `bin/sumdbverify` | Reproducible Go module git-tag vs. SumDB VIndex verifier |
| `bin/clonelog` | High-speed local log cloning utility |

---

## 3. Authoring a Custom WASM MapFn

VIndex parses log leaves inside an isolated, sandboxed WebAssembly runtime. Mapping functions are written using [`vindex/mapfn/sdk`](./mapfn/sdk).

### The MapFn Contract

A minimal mapping plugin needs only one file (`main.go`). Emitted canonical keys must be `1..1024` printable ASCII bytes (`0x21..0x7E`, containing no whitespace or control characters):

```go
package main

import (
	"bytes"
	"github.com/transparency-dev/incubator/vindex/mapfn/sdk"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapLeaf)
}

func isCanonicalKey(b []byte) bool {
	if len(b) == 0 || len(b) > 1024 {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// MapLeaf inspects each raw log leaf and emits zero or more canonical search keys.
func MapLeaf(leaf []byte, emit func(key []byte)) {
	for token := range bytes.FieldsSeq(leaf) {
		if isCanonicalKey(token) {
			emit(token)
		}
	}
}
```

### Compiling & Validating Your Plugin

Compile to `wasip1` WebAssembly and run qualification checks (`inspect`, `test`, `bench`) via `vindex-wasm`:

```bash
just build-wasm vindex/mapfn/examples/starter bin/starter.wasm
just verify-wasm bin/starter.wasm "my-sample-payload"
```

---

## 4. Pointing VIndex to Your Own Log

### Requirements for the Input Log
VIndex connects to any log conforming to the [tlog-tiles (C2SP)](https://c2sp.org/tlog-tiles) specification (or local filesystem layout via `file://`). It requires:
1. A readable `checkpoint` file signed with an RFC 6962 / Note key (unless `--insecure_skip_verify` is explicitly passed for local testing).
2. Standard 256-entry bundles (`tile/entries/...`) and hash tiles (`tile/0/...`).

> **Tip:** Generate a local mock log for testing with `just mock-log /tmp/inlog demo.mock.log`.

### Step A: Generate Note Keypair for the Output Log
VIndex signs its state trie commitments to an append-only Output Log. Generate an Ed25519 Note keypair:

```bash
just keygen my.vindex.org
```

### Step B: Run `vindexd`
Start the indexing and serving daemon pointing to your Input Log:

```bash
go run ./vindex/cmd/vindexd \
  --input_log_url="https://your-log-endpoint.org" \
  --input_log_origin="your-log.org" \
  --input_log_pubkey="your-log.org+a1b2c3d4+..." \
  --output_log_dir="/data/vindex/outlog" \
  --output_log_signer_key="PRIVATE+KEY+my.vindex.org+..." \
  --wasm_path="/path/to/compiled_plugin.wasm" \
  --db_path="/data/vindex/pebble" \
  --mpt_dir="/data/vindex/mpt" \
  --tile_cache_dir="/data/vindex/tiles" \
  --listen_addr=":8080" \
  --metrics_addr=":9090"
```

For initial historical catch-ups without serving HTTP traffic, pass `--oneshot` to index up to the log tip and exit cleanly.

#### Log Verification Flags Across CLIs
- **Input Log verification** (`vindexd`, `vindex-auditor`, `clonelog`, `vindex-client`, `sumdbverify`): supply either a [C2SP `tlog-policy` file](https://c2sp.org/tlog-policy) via `--input_log_policy` or a single-key verifier string/file via `--input_log_pubkey` (`<name>+<hash>+<base64Key>` or `mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>`).
- **Output Log signing & witness quorum** (`vindexd`): sign checkpoints with `--output_log_signer_key`, and optionally require witness cosignatures via `--output_log_policy`.
- **Output Log verification** (`vindex-client`, `vindex-auditor`, `hammer`, `sumdbverify`): verify checkpoints via `--output_log_policy` or `--output_log_pubkey` (`--output_log_origin` is inferred automatically when the policy/verifier names a single log).

---

## 5. Querying the VIndex

### Using the CLI Client (`vindex-client`)
`vindex-client` verifies the Sparse Merkle Trie proof, Output Log inclusion proof, Output Log checkpoint policy, suffix horizon (`--max_from`, default `0`), and optional Input Log checkpoint consistency (`--input_log_pubkey` / `--input_log_policy`) before displaying results:

```bash
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="my.vindex.org+904c615e+..." \
  --input_log_origin="your-log.org" \
  --input_log_url="https://your-log-endpoint.org" \
  --input_log_pubkey="your-log.org+a1b2c3d4+..." \
  --dereference \
  --key="my-search-key"
```

- `--dereference`: Fetches and authenticates each matched leaf bundle against the committed `InputRoot` via RFC 6962 inclusion proof.
- `--prefix`: Queries `/keys?prefix=<key-prefix>`; add `--all` to paginate occurrence indices across all matched keys.
- `--limit` / `--all`: Bounds occurrence output to the newest `--limit` (default `100`) indices unless `--all` is passed.
- `--max_from`: Rejects suffix-indexed responses whose `from` horizon exceeds `--max_from` (default `0`).

### HTTP Endpoints
VIndex isolates public `tlog-vindex` query endpoints from internal operational endpoints:

**Public Read API (`--listen_addr`, default `:8080`):**
- `GET /keys?key=<key>` and `GET /keys?prefix=<key-prefix>`: Authenticated key/prefix value root lookup with MPT and Output Log proofs.
- `GET /values?key=<key>&before=<B>`: Paginated value log occurrence indices and compact range prefixes.
- `GET /checkpoint` and `GET /tile/*`: Latest signed Output Log checkpoint and `tlog-tiles` bundles.
- `GET /` (unless `--enable_ui=false`): Unverified raw wire inspector UI for browsing wire payloads.

**Internal Operational Listener (`--metrics_addr`, default `:9090`, non-public):**
- `GET /healthz`: Process liveness probe.
- `GET /readyz`: Sync readiness probe (`200 OK` when ready, `503 Service Unavailable` while catching up or halted).
- `GET /metrics` and `GET /debug/pprof/*`: Prometheus metrics and Go runtime profiling handlers.

---

## 6. Real-World Personality: Go Checksum Database (SumDB)

The repository includes an end-to-end deployment for indexing the [Go Checksum Database](https://sum.golang.org):

```bash
# 1. Launch Caddy, sumdbproxy, vindexd (sumdb.wasm), Prometheus, and Grafana
just run-sumdb

# 2. Query any Go module path with full Output + Input Log verification and leaf dereferencing
just query-sumdb golang.org/x/mod

# 3. Verify all SumDB entries for a local git checkout (tags, go.mod h1, and zip h1)
go run ./vindex/cmd/sumdbverify \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --input_log_pubkey="sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --mod_root="$HOME/git/tessera"
```

See [`deploy/sumdb/README.md`](../deploy/sumdb/README.md) for container architecture, demo-key notes, and Grafana dashboards, and [`cmd/sumdbverify/README.md`](./cmd/sumdbverify/README.md) for local module verification details.
