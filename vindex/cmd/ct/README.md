## Verifiable Index: CT

This is a demo of pulling the contents of a tile-based CT log into a [Verifiable Index](../../README.md).

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

The CT Input Log is processed, with each entry being indexed on all common names defined in the cert. 
This allows the owner of a domain to look up all certs for their domain, in a way that is fully verified.

## Running

The static CT Input Log is expected to be available for reading at a URL provided by the `--monitoring_url` flag.
This is the base directory that should contain the checkpoint file.
The Verifiable Index and Output Log are constructed locally, persisted to local disk (in the `--storage_dir` directory), and hosted via a web server.

```shell
OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+example.com/outputlog+07392c46+ATPJ4crkyUbPeaRffN/4NUof3KV0pQznVIPGOQm3SDEJ \
go run ./vindex/cmd/ct \
  --storage_dir ~/vindex-ct/ \
  --origin="coachandhorses2026h1.staging.certificate.transparency.goog"  \
  --public_key="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECHOhXfvYgTcu+Fnl7M7niFj3FgqWlQpXUSWUDw2KAaJXvhGxdJTtmyciN5rWTiDtpeNENVmsUTHFS4XQgeRE0g==" \
  --monitoring_url="https://storage.googleapis.com/coachandhorses2026h1.staging.certificate.transparency.goog"
```

### Resource Requirements

Running this demo has the following estimated system requirements (based on indexing ~180M certs from a staging log):
*   **Architecture:** **64-bit OS** (Linux/Unix). The MPT library reserves a large virtual address space (16 TB) and cannot run on 32-bit systems.
*   **RAM:** **32 GB+** (observed ~31 GB physical RAM usage). The current prototype stores the key-value index in a raw Go map in memory.
*   **CPU:** **8+ cores** (actively utilizes ~6 cores during ingestion).
*   **Disk:** **100 GB+ SSD** (uses ~45 GB for WAL and MPT files, fast I/O is required).

> [!NOTE]
> The high memory usage is a limitation of the current prototype's in-memory key-value store. The planned [v1 architecture](../../docs/v1/IMPLEMENTATION.md) will move this store to a disk-backed Pebble database, which is expected to drastically reduce RAM requirements to approximately 6-8 GB.

Running the above will run a web server hosting the following URLs:
 - `/vindex/lookup` - the provisional [vindex lookup API](./api/api.go)
 - `/outputlog/` - the [tlog-tiles][] base URL for the output log

To inspect the log, you can use the woodpecker tool (using the corresponding public key to the private key used above):

```shell
# To inspect the Output Log
go run github.com/mhutchinson/woodpecker@main --custom_log_type=tiles --custom_log_url=http://localhost:8088/outputlog/ --custom_log_vkey=example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8
```

Use left/right cursor to browse, and `q` to quit.

A domain indexed by the verifiable map can be looked up using the following command:

```shell
go run ./vindex/cmd/client \
  --vindex_base_url http://localhost:8088/vindex/ \
  --out_log_pub_key=example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8 \
  --in_log_pub_key_der=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECHOhXfvYgTcu+Fnl7M7niFj3FgqWlQpXUSWUDw2KAaJXvhGxdJTtmyciN5rWTiDtpeNENVmsUTHFS4XQgeRE0g== \
  --in_log_origin=coachandhorses2026h1.staging.certificate.transparency.goog \
  --lookup=google.com

I0610 15:02:17.112527   87150 client.go:83] in_log_base_url not provided, so cannot dereference pointers
148000245
151898263
152014951
152015244
152015262
152015307
...
154306826
154307178
154307232
154307321
154368790
154368845
```

To view the certs at the index, [woodpecker](https://github.com/mhutchinson/woodpecker) can be used.

