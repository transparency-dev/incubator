# VIndex SumDB Personality Docker Compose Bundle

This deployment bundle runs a self-contained **Verifiable Index (VIndex) personality for the Go Checksum Database (SumDB)**, complete with upstream proxying, WASM MapFn execution, Caddy gateway routing, Prometheus metrics, and a pre-provisioned Grafana dashboard.

> [!WARNING]
> **Local Demo Signing Key**: The `sumdb.vindex.local` private key bundled in `deploy/sumdb/Dockerfile` is a public keypair intended solely for local evaluation. For shared or production deployments, generate a fresh keypair with `just keygen <origin>` and mount or pass `--output_log_signer_key` (and optionally a witness quorum via `--output_log_policy`).

## Architecture

```
                                      +---------------------------------------------+
                                      |                Caddy Gateway                |
                                      |           (http://127.0.0.1:8080)           |
                                      +---------------------------------------------+
                                            /                  |               \
                       /checkpoint, /tile/* |                  | /sumdb/*       \ /grafana/*
                       /keys, /values, /    |                  |                 \
                                            v                  v                  v
                             +-------------------+    +-----------------+    +-----------------+
                             |      vindexd      |    |    sumdbproxy   |    |     Grafana     |
                             |   (WASM: sumdb)   |    |    (:8089)      |    |     (:3000)     |
                             +-------------------+    +-----------------+    +-----------------+
                                      |    ^                   |                      ^
                         fetches tiles|    |                   | fetches upstream     | queries
                                      +----+                   v                      v
                                                        sum.golang.org       +-----------------+
                                                                             |    Prometheus   |
                                                                             |     (:9090)     |
                                                                             +-----------------+
```

## Quickstart

### 1. Launch the Stack (from the repository root)
```bash
docker compose -f deploy/sumdb/docker-compose.yml up -d --build
```

> [!NOTE]
> **Initial Backfill Duration**: By default (`--from=0`), `vindexd` performs a full Genesis Backfill across all ~45M entries of `sum.golang.org`, during which `/readyz` returns `503` and queries wait until the initial Output Log commitment is published. To start serving immediately from a recent suffix horizon during local testing, override `command:` on `vindexd` with `--from=<recent-leaf-index>` (and pass `--max_from=<recent-leaf-index>` to `vindex-client` / `sumdbverify`).

### 2. Service Endpoints (via Loopback Gateway `127.0.0.1:8080`)

| Service / Path | URL | Description |
| :--- | :--- | :--- |
| **VIndex Wire Inspector** | `http://localhost:8080/` | Unverified raw wire inspector UI for browsing `/keys`, `/values`, and `/checkpoint` payloads (use `vindex-client` or `sumdbverify` for cryptographic verification). |
| **Output Log Checkpoint** | `http://localhost:8080/checkpoint` | Current signed tree head for `sumdb.vindex.local`. |
| **Output Log Tiles** | `http://localhost:8080/tile/*` | `tlog-tiles` hash and entry bundles for `sumdb.vindex.local`. |
| **Index Key & Prefix Lookup** | `http://localhost:8080/keys?key=<key>` or `?prefix=<key-prefix>` | Verifiable inclusion / non-inclusion / prefix proofs for module search keys. |
| **Index Value Pagination** | `http://localhost:8080/values?key=<key>&before=<B>` | Verifiable value log entry indices and compact range prefixes. |
| **SumDB Proxy** | `http://localhost:8080/sumdb/` | Proxied `sum.golang.org` tiles and checkpoints. |
| **Grafana Dashboards** | `http://localhost:8080/grafana/` | Pre-provisioned read-only (`Viewer`) dashboard; sign in at `/grafana/login` (`admin` / `admin`) to edit. |

---

## Verifying & Querying the Deployed Index

Use [`vindex-client`](../../vindex/cmd/vindex-client) to cryptographically verify queries against both the Output Log and the upstream `sum.golang.org` Input Log:

```bash
go run ./vindex/cmd/vindex-client \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --input_log_origin="go.sum database tree" \
  --input_log_pubkey="sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --input_log_url="http://localhost:8080/sumdb/" \
  --dereference \
  --key="golang.org/x/mod"
```

Or verify a local git checkout of a Go module against the SumDB VIndex using [`sumdbverify`](../../vindex/cmd/sumdbverify):

```bash
go run ./vindex/cmd/sumdbverify \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --input_log_pubkey="sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --mod_root="$HOME/git/tessera"
```

---

## Teardown

To stop all containers and remove persistent volumes:
```bash
docker compose -f deploy/sumdb/docker-compose.yml down -v
```
