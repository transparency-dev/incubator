## Verifiable Index: Log & Map

This is a demo of using a [Tessera][] Verifiable Log as the Input Log, with all entries indexed by a [Verifiable Index](../../README.md).

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

The entries in the Input Log loosely represent Binary/Artifact Registry entries, committing to a triple of `{module name, module version, artifact hash}`:

```
{
  "module": "bar",
  "version": "2025-08-07T10:41:56.527888424Z",
  "hash": "vsOru/9zZqrLjamAgzvQCaSvpMmF9jy+r75HpMvncZc="
}
```

This pattern is very common: committing that a module at a given version has a particular hash.
This hash could represent the git commit fingerprint the release was tagged from, the hash of a compiled binary, etc.
See [Transparency.dev: Add tamper checking to a package manager](https://transparency.dev/application/add-tamper-checking-to-a-package-manager/) for more background on this pattern.

This Input Log is processed, with each entry being indexed solely on the `module`,
i.e. the key that is put into the map has the following value:

```go
		sha256.Sum256([]byte(entry.Module))
```

This allows the owner of a given module to look up the modules they are responsible for, and verifiably
find the index of all entries in the Input Log for their modules.

## Running

The Input Log, Verifiable Index, and Output Log are all managed by a single binary:

```shell
INPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+example.com/inputlog+bd6268fb+ATPZW5UsUYHJo24lwgK1ykm9VafhyUtUxX5evV4ZIokY OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+example.com/outputlog+07392c46+ATPJ4crkyUbPeaRffN/4NUof3KV0pQznVIPGOQm3SDEJ go run ./vindex/cmd/logandmap --storage_dir ~/logandmap/
```

Running the above will run a web server hosting the following URLs:
 - `/inputlog/` - the [tlog-tiles][] base URL for the input log
 - `/vindex/lookup` - the provisional [vindex lookup API](./api/api.go)
 - `/outputlog/` - TODO(mhutchinson): this is where the output log will be hosted

The input log has entries for packages in the set {`foo`, `bar`, `baz`, `splat`}.
To inspect the log, you can use the woodpecker tool (using the corresponding public key to the private key used above):

```shell
# To inspect the Input Log
go run github.com/mhutchinson/woodpecker@main --custom_log_type=tiles --custom_log_url=http://localhost:8088/inputlog/ --custom_log_vkey=example.com/inputlog+bd6268fb+AWdGkrHKBm+pOubTrcBTV8JMDLFlF1Y8WUH1nrtLNXDr

# To inspect the Output Log
go run github.com/mhutchinson/woodpecker@main --custom_log_type=tiles --custom_log_url=http://localhost:8088/outputlog/ --custom_log_vkey=example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8
```

Use left/right cursor to browse, and `q` to quit.

This log is processed into a verifiable map which can be looked up using the following command:

```shell
go run ./vindex/cmd/client --vindex_base_url http://localhost:8088/vindex/ --in_log_base_url http://localhost:8088/inputlog/ --out_log_pub_key=example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8 --in_log_pub_key=example.com/inputlog+bd6268fb+AWdGkrHKBm+pOubTrcBTV8JMDLFlF1Y8WUH1nrtLNXDr --lookup=foo
```
