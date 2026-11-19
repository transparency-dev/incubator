#!/usr/bin/env bash
# Copyright 2026 The Transparency Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DEMO_DIR=$(mktemp -d -t vindex-demo-XXXXXX)
VINDEXD_PID=""

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$VINDEXD_PID" ]]; then
    kill -TERM "$VINDEXD_PID" 2>/dev/null || true
    for _ in {1..20}; do
      if ! kill -0 "$VINDEXD_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    kill -KILL "$VINDEXD_PID" 2>/dev/null || true
  fi
  if [[ $exit_code -ne 0 && -f "$DEMO_DIR/vindexd.log" ]]; then
    printf '\n=== vindexd.log (Last 25 Lines) ===\n'
    tail -n 25 "$DEMO_DIR/vindexd.log" || true
  fi
  rm -rf "$DEMO_DIR"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Localhost ports (default 0 binds ephemeral free ports; override with DEMO_PORT / DEMO_METRICS_PORT)
REQ_PORT=${DEMO_PORT:-0}
REQ_METRICS_PORT=${DEMO_METRICS_PORT:-0}

printf '=== 1. Compiling Binaries & Starter WASM ===\n'
mkdir -p "$DEMO_DIR/bin"
go build -o "$DEMO_DIR/bin/" ./vindex/cmd/vindexd ./vindex/cmd/vindex-client
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -buildmode=c-shared \
  -o "$DEMO_DIR/starter.wasm" ./vindex/mapfn/examples/starter
printf 'Compiled: vindexd, vindex-client, starter.wasm\n'

printf '\n=== 2. Creating Local Input Log ===\n'
INPUT_LOG_DIR="$DEMO_DIR/inlog"
INPUT_LOG_ORIGIN="demo.mock.log"
go run ./scripts/mock_log "$INPUT_LOG_DIR" "$INPUT_LOG_ORIGIN"
INPUT_LOG_PUBKEY="$(<"$INPUT_LOG_DIR/verifier.vkey")"
printf "Created mock input log with 4 entries ('apple', 'banana', 'cherry', 'apple')\n"

printf '\n=== 3. Generating VIndex Output Log Keypair ===\n'
KEYGEN_OUT=$(go run ./scripts/keygen "demo.vindex.log")
OUT_SKEY=$(printf '%s\n' "$KEYGEN_OUT" | awk '/^Signer Key:/ {print $3}')
OUT_VKEY=$(printf '%s\n' "$KEYGEN_OUT" | awk '/^Verifier Key:/ {print $3}')
printf 'Origin: demo.vindex.log\n'
printf 'Public Verifier: %s\n' "$OUT_VKEY"

printf '\n=== 4. Launching vindexd Server ===\n'
: >"$DEMO_DIR/vindexd.log"
"$DEMO_DIR/bin/vindexd" \
  --input_log_url="file://$INPUT_LOG_DIR" \
  --input_log_origin="$INPUT_LOG_ORIGIN" \
  --input_log_pubkey="$INPUT_LOG_PUBKEY" \
  --output_log_dir="$DEMO_DIR/outlog" \
  --output_log_signer_key="$OUT_SKEY" \
  --wasm_path="$DEMO_DIR/starter.wasm" \
  --db_path="$DEMO_DIR/db" \
  --mpt_dir="$DEMO_DIR/mpt" \
  --tile_cache_dir="$DEMO_DIR/tiles" \
  --listen_addr="127.0.0.1:$REQ_PORT" \
  --metrics_addr="127.0.0.1:$REQ_METRICS_PORT" \
  --poll_interval=100ms >>"$DEMO_DIR/vindexd.log" 2>&1 &
VINDEXD_PID=$!

LISTEN_ADDR=""
METRICS_ADDR=""
READY=false
for _ in {1..100}; do
  if ! kill -0 "$VINDEXD_PID" 2>/dev/null; then
    printf 'vindexd exited prematurely\n' >&2
    exit 1
  fi
  if [[ -z "$LISTEN_ADDR" ]]; then
    LISTEN_ADDR=$(awk -F'http://' '/Serving VIndex Read API at http:\/\// {print $2; exit}' "$DEMO_DIR/vindexd.log")
  fi
  if [[ -z "$METRICS_ADDR" ]]; then
    METRICS_ADDR=$(awk -F'http://' '/Serving operational endpoints .* at http:\/\// {print $2; exit}' "$DEMO_DIR/vindexd.log")
  fi
  if [[ -n "$LISTEN_ADDR" && -n "$METRICS_ADDR" ]] && curl -sf "http://$METRICS_ADDR/readyz" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 0.1
done
if [[ "$READY" != "true" ]]; then
  printf 'Timed out waiting for vindexd /readyz\n' >&2
  exit 1
fi
printf 'vindexd ready (Read API: http://%s, Admin: http://%s)\n' "$LISTEN_ADDR" "$METRICS_ADDR"

query_key() {
  local key=$1
  shift
  "$DEMO_DIR/bin/vindex-client" \
    --vindex_url="http://$LISTEN_ADDR" \
    --output_log_pubkey="$OUT_VKEY" \
    --input_log_origin="$INPUT_LOG_ORIGIN" \
    --key="$key" \
    "$@"
}

printf '\n=== 5. Running Verified Client Queries ===\n'

printf "\n[Query 1/3] Key 'apple' (with verified entry dereferencing) -> Expecting occurrences at leaf 0 and leaf 3:\n"
query_key "apple" \
  --dereference \
  --input_log_url="file://$INPUT_LOG_DIR" \
  --input_log_pubkey="$INPUT_LOG_PUBKEY"

printf "\n[Query 2/3] Key 'cherry' -> Expecting occurrence at leaf 2:\n"
query_key "cherry"

printf "\n[Query 3/3] Key 'nonexistent' -> Expecting verified non-inclusion:\n"
query_key "nonexistent"

printf '\nDemo completed successfully. Shutting down cleanly.\n'
