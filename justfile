# Verifiable Index (VIndex) Task Runner
# https://github.com/casey/just

set shell := ["bash", "-euo", "pipefail", "-c"]

# List available recipes
default:
    @just --list

# Build all VIndex CLI binaries into bin/
build:
    @mkdir -p bin
    go build -o bin/ ./vindex/cmd/...
    @echo "Built binaries in bin/"

# Run full repository test suite
test:
    go test ./...

# Generate an Ed25519 Note signing and verification keypair
keygen origin="vindex.local":
    @go run ./scripts/keygen {{quote(origin)}}

# Generate a local mock Input Log with signed checkpoint and test entries
mock-log dir="/tmp/mock-inlog" origin="demo.mock.log":
    @go run ./scripts/mock_log {{quote(dir)}} {{quote(origin)}}

# Compile a WASM MapFn plugin for wasip1
build-wasm dir="vindex/mapfn/examples/starter" out="bin/starter.wasm":
    @mkdir -p "$(dirname -- {{quote(out)}})"
    pkg={{quote(dir)}}; [[ "$pkg" != /* && "$pkg" != ./* ]] && pkg="./$pkg"; \
    GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -buildmode=c-shared -o {{quote(out)}} "$pkg"
    @printf 'Compiled: %s\n' {{quote(out)}}

# Run full qualification on a WASM plugin (inspect, test, benchmark)
verify-wasm wasm="bin/starter.wasm" input="package:github.com/foo/bar@v1.0.0":
    @printf '=== Inspect ABI Exports ===\n'
    @go run ./vindex/cmd/vindex-wasm inspect --wasm={{quote(wasm)}}
    @printf '\n=== Test Mapping Function ===\n'
    @go run ./vindex/cmd/vindex-wasm test --wasm={{quote(wasm)}} --input={{quote(input)}}
    @printf '\n=== Benchmark Throughput ===\n'
    @go run ./vindex/cmd/vindex-wasm bench --wasm={{quote(wasm)}} --input={{quote(input)}} --iterations=500

# Run local zero-configuration end-to-end demo (mock log + starter.wasm + vindexd + query)
demo-local:
    @./scripts/demo-local.sh

# Launch the full Go SumDB VIndex Docker Compose stack
run-sumdb:
    docker compose -f deploy/sumdb/docker-compose.yml up -d --build
    @echo "SumDB VIndex stack running at http://localhost:8080 (Grafana: http://localhost:8080/grafana/)"

# Query the local Go SumDB VIndex stack with full cryptographic verification
query-sumdb key="golang.org/x/mod":
    @go run ./vindex/cmd/vindex-client \
        --vindex_url=http://localhost:8080 \
        --output_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
        --input_log_origin="go.sum database tree" \
        --input_log_pubkey="sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
        --input_log_url=http://localhost:8080/sumdb/ \
        --dereference \
        --key={{quote(key)}}

# Remove build artifacts
clean:
    rm -rf bin/
