## Verifiable Index: SumDB

This is a demo of building a [Verifiable Index](../../README.md) for Go's SumDB.

The index allows package maintainers to verifiably look up all [non-pseudo](https://pkg.go.dev/golang.org/x/mod@v0.28.0/module#IsPseudoVersion) versions of their module served by the Module Proxy.

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

## Running

The Verifiable Index and Output Log are managed by a single binary, which can be run using:

```shell
OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+SumDBIndex+a5ed0e81+AYT6tfHpqGaSoH0gYpM7fhj1tEkM3wwYR/IhtiYh1pnj \
go run ./vindex/cmd/sumdb \
  --storage_dir ~/vindex-sumdb/
```

Running the above will run a web server hosting the following URLs:
 - `/inputlog/` - the [tlog-tiles][] base URL for a proxy of the SumDB API
 - `/vindex/lookup` - the provisional [vindex lookup API](./api/api.go)
 - `/outputlog/` - the [tlog-tiles][] base URL for the output log

To inspect the log, you can use the woodpecker tool (using the corresponding public key to the private key used above):

```shell
# To inspect the Output Log
go run github.com/mhutchinson/woodpecker@main \
  --custom_log_type=tiles \
  --custom_log_url=http://localhost:8088/outputlog/ \
  --custom_log_vkey=SumDBIndex+a5ed0e81+AXEnbaKj+9gCH3f69vcQokgkcFocCl+GlaMXrAg8mRzd
```

Use left/right cursor to browse, and `q` to quit.

This log is processed into a verifiable map which can be looked up using the following command:

```shell
go run ./vindex/cmd/client \
  --vindex_base_url http://localhost:8088/vindex/ \
  --in_log_base_url http://localhost:8088/inputlog/ \
  --out_log_pub_key=SumDBIndex+a5ed0e81+AXEnbaKj+9gCH3f69vcQokgkcFocCl+GlaMXrAg8mRzd \
  --in_log_pub_key=sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8 \
  --in_log_origin="go.sum database tree" \
  --lookup=github.com/transparency-dev/tessera
```

