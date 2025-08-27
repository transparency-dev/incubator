## Verifiable Index: CT

This is a demo of pulling the contents of a tile-based CT log into a [Verifiable Index](../../README.md).

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

The CT Input Log is processed, with each entry being indexed on all common names defined in the cert. 
This allows the owner of a domain to look up all certs for their domain, in a way that is fully verified.

> [!NOTE]
> This demo doesn't map all certificates!
> In order to generate a manageable number of key/values, this only indexes
> final certs, and only domain names ending with `.co.uk`.
> https://github.com/transparency-dev/incubator/issues/64

## Running

The Input Log is expected to be available at a URL provided by the `--static_ct_log_url` flag.
The Verifiable Index and Output Log are constructed locally, persisted to local disk (in the `--storage_dir` directory), and hosted via a web server.

```shell
OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+example.com/outputlog+07392c46+ATPJ4crkyUbPeaRffN/4NUof3KV0pQznVIPGOQm3SDEJ \
MY_EMAIL=me@example.com \
go run ./vindex/cmd/ct \
  --storage_dir ~/vindex-ct/ \
  --origin="arche2026h1.staging.ct.transparency.dev"  \
  --public_key="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ+3YKoZTMruov4cmlImbk4MckBNzEdCyMuHlwGgJ8BUrzFLlR5U0619xDDXIXespkpBgCNVQAkhMTTXakM6KMg==" \
  --monitoring_url="https://storage.googleapis.com/static-ct-staging-arche2026h1-bucket/" \
  --user_agent_info=${MY_EMAIL}
```

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
  --lookup=google.co.uk
```
