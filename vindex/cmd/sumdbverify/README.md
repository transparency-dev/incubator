## SumDB Verify

> [!IMPORTANT]
> Proper use of this tool requires a [SumDB VIndex](../sumdb/) to be running.
> See [Running non-verifiably](#running-non-verifiably) for the quick and dirty way.

This tool checks that the contents for a module in SumDB match the state as represented in a local git repository.
The command below shows the output for this command querying a local checkout of `github.com/transparency-dev/tessera`:

```shell
go run ./vindex/cmd/sumdbverify \
  --base_url http://localhost:8088/ \
  --out_log_pub_key=SumDBIndex+a5ed0e81+AXEnbaKj+9gCH3f69vcQokgkcFocCl+GlaMXrAg8mRzd \
  --mod_root ~/git/tessera

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

The output shows all versions present in SumDB, and for each:
 - INDEX is the leaf index of this `module@version` in SumDB
 - FOUND shows that a tag with the same version string was found in the git repository
 - go.mod shows that the hashes for the `go.mod` file match. In addition to the green tick, there are two other states:
   - ⚠️: no `go.mod` file was found in the git repo at the tagged version; this _could_ be a release from before modules were adopted
   - ❌: a `go.mod` file was found in the git repo, but the hash doesn't match that in SumDB. Either the tag was changed, or SumDB is hosting bad content.
 - zip shows that the hashes for the zip containing the source code match. In addition to the green tick, there are two other states:
   - ⚠️: no `go.mod` file was found in the git repo at the tagged version; this _could_ be a release from before modules were adopted
   - ❌: the zip file hash did not match that in SumDB. Either the tag was changed, or SumDB is hosting bad content.

### Running non-verifiably

By omitting the `--base_url` and `--out_log_pub_key` flags, the SumDB information will be fetched from non-verifiable endpoints.
This is useful for casual testing before a public-good instance of the SumDB verifiable index is available.

```shell
go run ./vindex/cmd/sumdbverify --mod_root ~/git/tessera

W1002 13:31:48.254094 2883468 client.go:84] --base_url is not provided. Using NON-VERIFIABLE lookup to source SumDB data.
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
