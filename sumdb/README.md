## SumDB to tlog-tiles proxy

This is a proxy that serves the [Go SumDB](https://sum.golang.org/) with a  [tlog-tiles](https://c2sp.org/tlog-tiles) API.
This allows tooling written for the tlog-tiles API to be used with the SumDB, even though its API is slightly different.

### Running

```shell
go run ./sumdb/proxy.go
```
