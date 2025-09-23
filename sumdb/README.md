## SumDB to tlog-tiles proxy

This is a proxy that serves the [Go SumDB](https://sum.golang.org/) with a [tlog-tiles](https://c2sp.org/tlog-tiles) API.
This allows tooling written for the tlog-tiles API to be used with the SumDB, even though its API is slightly different.

### Running

```shell
go run ./sumdb/proxy.go --listen=":8089"
```

### Using

Any valid tlog-tiles API paths sent to the listen address will be routed to the SumDB proxy.
Paths will be changed as necessary, and leaf data returned will be rewritten to comply with the tlog-tiles spec.

For example, to run Tessera's tlog-tiles `fsck` tool against the log to confirm integrity:

```shell
# Put the SumDB public key in a file so that fsck can read it.
echo sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8 > ~/.go.sum.vkey

# Run the fsck tool against the proxy.
go run github.com/transparency-dev/tessera/cmd/fsck@main \
  --storage_url=http://localhost:8089/ \
  --public_key ~/.go.sum.vkey \
  --origin "go.sum database tree"
```
