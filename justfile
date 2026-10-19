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

# Remove build artifacts
clean:
    rm -rf bin/
