## SumDB Verify

> [!IMPORTANT]
> Verifiable use of this tool queries a running [SumDB VIndex deployment](../../../deploy/sumdb/).
> See [Running non-verifiably](#running-non-verifiably) for offline/proxy comparison without a local VIndex.

`sumdbverify` checks that every version of a Go module recorded in Go's Checksum Database (`sum.golang.org`) matches the tags and source trees in a local git checkout (supporting root `v0`/`v1` modules, `/v2+` major branches and subdirectories, `+incompatible` releases, and monorepo subdirectories):

```shell
go run ./vindex/cmd/sumdbverify \
  --vindex_url="http://localhost:8080" \
  --output_log_pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  --input_log_pubkey="sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
  --mod_root="$HOME/git/tessera"

github.com/transparency-dev/tessera (./go.mod)
VERSION     INDEX     FOUND  go.mod  zip
v0.1.0      37258761  ✅      ✅       ✅
v0.1.1      37258762  ✅      ✅       ✅
v0.1.2      37258746  ✅      ✅       ✅
v0.2.0      38108519  ✅      ✅       ✅
v1.0.0-rc1  41510961  ✅      ✅       ✅
v1.0.0-rc2  42710781  ✅      ✅       ✅
v1.0.0-rc3  43267373  ✅      ✅       ✅
v1.0.0      43930254  ✅      ✅       ✅
```

For each version present in SumDB:
 - `INDEX` is the verified leaf index of `module@version` in SumDB.
 - `FOUND` shows whether a matching git tag was found in `--mod_root`.
 - `go.mod` shows whether the `go.mod` `h1:` hash matches git (`⚠️` if the tagged commit predates Go modules or is `+incompatible`; `❌` on hash mismatch).
 - `zip` shows whether the module zip `h1:` hash reproduced from git matches SumDB (`❌` on hash mismatch).
 - Local semver git tags absent from SumDB print `--` under `INDEX` and cause a non-zero exit status.

By default `--max_from=0` requires a full-history VIndex (`from == 0`) so historical module releases cannot be omitted silently; pass `--max_from=<N>` when querying a suffix-indexed VIndex intentionally.

### Running non-verifiably

Omitting `--vindex_url` queries `proxy.golang.org` and `sum.golang.org/lookup` directly without VIndex completeness proofs:

```shell
go run ./vindex/cmd/sumdbverify --mod_root="$HOME/git/tessera"
```
