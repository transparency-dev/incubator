## Verifiable Index: Go Checksum Database (SumDB)

[tlog-tiles]: https://c2sp.org/tlog-tiles

This is a demo of building a [Verifiable Index](../../README.md) for [Go's Checksum Database](https://go.dev/ref/mod#checksum-database).
The index allows module maintainers to verifiably look up all [non-pseudo](https://pkg.go.dev/golang.org/x/mod@v0.28.0/module#IsPseudoVersion) versions of their module served by the Module Proxy.

### Background

The sum.golang.org service, often referred to as Go Checksum DB or SumDB, serves as an auditable checksum database for Go modules. Its primary purpose is to enhance the security and integrity of the Go module ecosystem by providing a public, tamper-proof record of module checksums. This ensures that when developers fetch a module, they receive the exact version of the code that others are using and that hasn't been maliciously altered.

SumDB functions as a transparency log. This means that every module version and its corresponding checksum added to the database is appended in an immutable, append-only fashion. Each new entry is cryptographically committed to, which makes it impossible to modify or remove an entry without detection. This transparency allows anyone to independently verify the integrity of the database and confirm that no module has been altered or replaced. The auditable nature of the database is crucial for trust in the Go module supply chain.

In addition to sum.golang.org, there is also an index at index.golang.org. This index provides a convenient way to discover available Go modules and their versions. However, it's important to note that index.golang.org is not verifiable in the same way as sum.golang.org. While it helps with discovery, it does not offer the same cryptographic guarantees of integrity and immutability as the checksum database. The security and verification of module content rely solely on the auditable records within sum.golang.org.

The entries in the SumDB log match what is written in a `go.sum` file.
For example, any project depending on the v1.0 release of Tessera will have the following in its `go.sum` file:

```
github.com/transparency-dev/tessera v1.0.0 h1:4OT1V9xJLa5NnYlFWWlCdZkCm18/o12rdd+bCTje7XE=
github.com/transparency-dev/tessera v1.0.0/go.mod h1:TLvfjlkbmsmKVEJUtzO2eb9Q2IBnK3EJ0dI4G0oxEOU=
```

This is the same content written to the SumDB at index 43930254 ([query link](https://sum.golang.org/lookup/github.com/transparency-dev/tessera@v1.0.0)).

The index is built from this log of modules by parsing the module name from every leaf. A pointer to the leaf is added to the index if it represents a [non-pseudo](https://pkg.go.dev/golang.org/x/mod@v0.28.0/module#IsPseudoVersion) version.
The index can be [queried](#querying) using the client.

### Status

The goal is to find an operator that will run this service to allow verifiable lookups.
For now, users may run this themselves using the instructions below.

### Running

The Verifiable Index and Output Log are managed by a single binary, which can be run using:

```shell
OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+SumDBIndex+a5ed0e81+AYT6tfHpqGaSoH0gYpM7fhj1tEkM3wwYR/IhtiYh1pnj \
go run ./vindex/cmd/sumdb \
  --storage_dir ~/vindex-sumdb/
```

This will take some time on the first run as it needs to download every entry from the SumDB log in order to build the index.

The command above starts a web server that hosts the following URLs:
 - `/inputlog/` - the [tlog-tiles][] base URL for a proxy of the SumDB API
 - `/vindex/lookup` - the provisional [vindex lookup API](./api/api.go)
 - `/outputlog/` - the [tlog-tiles][] base URL for the output log

> [!NOTE]
> This brings up a proxy server that makes SumDB available via the local server at `/inputlog/`.
> This allows the index and the client to use standard [tlog-tiles][] APIs to query the data, instead of requiring a custom client for SumDB.

### Querying 

This log is processed into a verifiable map which can be looked up using the client in `./vindex/cmd/client`.
Below is an example of querying the index to list all releases of `github.com/transparency-dev/tessera`.
The output lists all of the indices where the module is logged, and the entry from the log at this index. 

```shell
go run ./vindex/cmd/client \
  --vindex_base_url http://localhost:8088/vindex/ \
  --in_log_base_url http://localhost:8088/inputlog/ \
  --out_log_pub_key=SumDBIndex+a5ed0e81+AXEnbaKj+9gCH3f69vcQokgkcFocCl+GlaMXrAg8mRzd \
  --in_log_pub_key=sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8 \
  --in_log_origin="go.sum database tree" \
  --lookup=github.com/transparency-dev/tessera \
  --min_idx=40000000

37258746)
github.com/transparency-dev/tessera v0.1.2 h1:s8h0HQ5knhvCmQ2TdATw7FMTvdZY+RMcAcgsaPrKm1k=
github.com/transparency-dev/tessera v0.1.2/go.mod h1:jARcxCIWevuPy8XsxN7Q8waDV+M4rY9fNKIXJXBbzXo=


37258761)
github.com/transparency-dev/tessera v0.1.0 h1:TZuf5eLhDf9EWw5MaT9KLasKOgyzlW8mTu6gndTpK98=
github.com/transparency-dev/tessera v0.1.0/go.mod h1:cpk4hVzA5aXcaP6r5UD3EJBQWauI0hprgn27xF5a3ls=


37258762)
github.com/transparency-dev/tessera v0.1.1 h1:vk0XI98cEHZYXDZxa14RlzLh+hwmkVQ0mWrdiTRQHTU=
github.com/transparency-dev/tessera v0.1.1/go.mod h1:uvyZ7WGpaRDPY+4Lme+s1vEUOluYevTYzrDg9j05cYU=


38108519)
github.com/transparency-dev/tessera v0.2.0 h1:KZu0vt1nL6gSRJziDqnNlKMuzjeM+ZXANW2B4Oo/r9o=
github.com/transparency-dev/tessera v0.2.0/go.mod h1:lJCDw1om4T8H73MWQaZ2XBg5Ca0mKozvZZrtd6j5UZw=


41510961)
github.com/transparency-dev/tessera v1.0.0-rc1 h1:topftrvPcD6detUWoR/cdoPgkyI88wQuHasd6pMBjmM=
github.com/transparency-dev/tessera v1.0.0-rc1/go.mod h1:ilpKqGrwDD/6uop5nDj/X60o0qt33GK1uInjIcfZTP0=


42710781)
github.com/transparency-dev/tessera v1.0.0-rc2 h1:BKtDWr0nhL9dG66cS4DyKU9lpZFbUZrpHGh+BpqakcU=
github.com/transparency-dev/tessera v1.0.0-rc2/go.mod h1:aaLlvG/sEPMzT96iIF4hua6Z9pLzkfDtkbaUAR4IL8I=


43267373)
github.com/transparency-dev/tessera v1.0.0-rc3 h1:v385KqMekDUKI3ZVJHCHE5MAz8LBrWsEKa6OzYLrz0k=
github.com/transparency-dev/tessera v1.0.0-rc3/go.mod h1:aaLlvG/sEPMzT96iIF4hua6Z9pLzkfDtkbaUAR4IL8I=


43930254)
github.com/transparency-dev/tessera v1.0.0 h1:4OT1V9xJLa5NnYlFWWlCdZkCm18/o12rdd+bCTje7XE=
github.com/transparency-dev/tessera v1.0.0/go.mod h1:TLvfjlkbmsmKVEJUtzO2eb9Q2IBnK3EJ0dI4G0oxEOU=
```

Note that this matches the list of entries on the unverifiable proxy endpoint: https://proxy.golang.org/github.com/transparency-dev/tessera/@v/list.

When running this command on a regular basis, you can avoid seeing entries you have already processed by providing the `--min_idx` flag.

```shell
❯ go run ./vindex/cmd/client \
  --vindex_base_url http://localhost:8088/vindex/ \
  --in_log_base_url http://localhost:8088/inputlog/ \
  --out_log_pub_key=SumDBIndex+a5ed0e81+AXEnbaKj+9gCH3f69vcQokgkcFocCl+GlaMXrAg8mRzd \
  --in_log_pub_key=sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8 \
  --in_log_origin="go.sum database tree" \
  --lookup=github.com/transparency-dev/tessera \
  --min_idx=40000000

I0924 16:14:28.105308 2932871 client.go:66] Dropping 4 pointers to index less than min_idx 40000000
41510961)
github.com/transparency-dev/tessera v1.0.0-rc1 h1:topftrvPcD6detUWoR/cdoPgkyI88wQuHasd6pMBjmM=
github.com/transparency-dev/tessera v1.0.0-rc1/go.mod h1:ilpKqGrwDD/6uop5nDj/X60o0qt33GK1uInjIcfZTP0=


42710781)
github.com/transparency-dev/tessera v1.0.0-rc2 h1:BKtDWr0nhL9dG66cS4DyKU9lpZFbUZrpHGh+BpqakcU=
github.com/transparency-dev/tessera v1.0.0-rc2/go.mod h1:aaLlvG/sEPMzT96iIF4hua6Z9pLzkfDtkbaUAR4IL8I=


43267373)
github.com/transparency-dev/tessera v1.0.0-rc3 h1:v385KqMekDUKI3ZVJHCHE5MAz8LBrWsEKa6OzYLrz0k=
github.com/transparency-dev/tessera v1.0.0-rc3/go.mod h1:aaLlvG/sEPMzT96iIF4hua6Z9pLzkfDtkbaUAR4IL8I=


43930254)
github.com/transparency-dev/tessera v1.0.0 h1:4OT1V9xJLa5NnYlFWWlCdZkCm18/o12rdd+bCTje7XE=
github.com/transparency-dev/tessera v1.0.0/go.mod h1:TLvfjlkbmsmKVEJUtzO2eb9Q2IBnK3EJ0dI4G0oxEOU=
```

To inspect either the input or output log, you can use the woodpecker tool (using the corresponding public key to the private key used above):

```shell
# To inspect the Output Log
go run github.com/mhutchinson/woodpecker@main \
  --custom_log_type=tiles \
  --custom_log_url=http://localhost:8088/outputlog/ \
  --custom_log_vkey=SumDBIndex+a5ed0e81+AXEnbaKj+9gCH3f69vcQokgkcFocCl+GlaMXrAg8mRzd

# To inspect the Input Log
go run github.com/mhutchinson/woodpecker@main \
  --custom_log_type=tiles \
  --custom_log_url=http://localhost:8088/inputlog/ \
  --custom_log_origin="go.sum database tree" \
  --custom_log_vkey=sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8 
```

Use the left and right arrow keys to browse, `g` to jump to a specific index, and `q` to quit.

