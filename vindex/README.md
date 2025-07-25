## Verifiable Index

Status: Experimental.

This idea has been distilled from years of experiments with maps, and a pressing need to have an efficient and verifiable way for an end-user to find _their_ data in logs without needing to download the whole log.

This experiment should be considered a 20% project for the time being and isn't on the near-term official roadmap for transparency.dev.
Discussions are welcome, please join us on [Transparency-Dev Slack](https://transparency.dev/slack/).

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

## Overview

### The Problem: Verifiability vs. Efficiency

Logs, such as those used in Certificate Transparency or Software Supply Chains, provide a strong foundation for discoverability. You can prove that an entry exists in a log. However, they lack a critical feature: the ability to _verifiably_ query for entries based on their content.

This forces users who need to find specific data, like a domain owner finding their certificates, or a developer finding their software packages, into a painful choice:

1.  **Massive Inefficiency**: Download and process the _entire_ log, which can be terabytes of mostly irrelevant data, just to find the few entries that matter to you.
2.  **Losing Verifiability**: Rely on a third-party service to index the data. This breaks the chain of verifiability, as the index operator could, by accident or design, fail to show you all the results. You are forced to trust them.

Neither option is acceptable. Users should not have to sacrifice efficiency for security, or security for efficiency.

### The Solution: A Verifiable "Back-of-the-Book" Index

A Verifiable Index resolves this conflict by providing a third option: an efficient, cryptographically verifiable way to query log data.

At its core it works like a familiar index, much like one would find in the back of a book. It maps search terms (like a domain or package name) to the exact locations (pointers) in the main log where that data can be found.

This provides two key guarantees:

-   **Efficiency**: Users can look up data by a meaningful key and receive a small, targeted list of pointers back, avoiding the need to download the entire log.
-   **Verifiability**: Every lookup response comes with a cryptographic proof. This proof guarantees that the list of results is complete and that the index operator has not omitted any entries for your query.

The result is a system that extends the verifiability of the underlying log to its queries, preserving the end-to-end chain of trust while providing the efficiency modern systems require.

## Applications

This verifiable map can be applied to any log where users have a need to enumerate all values matching a specific query. For example:

* CT: domain owners wish to query for all certs matching a particular domain  
* SumDB: package owners want to find all releases for a given package

Indices exist for both ecosystems at the moment, but they aren’t verifiable.

## Core Idea; TL;DR

The Verifiable Index has 3 data structures involved (and is informally called a Map Sandwich, as the Map sits between two Logs):

1. The _Input Log_ that is to be indexed
2. The _Verifiable Index_ containing pointers back into the _Input Log_
3. The _Output Log_ that contains a list of all revisions of the map

The Input Log likely aready exists before the Verifiable Index is added, but the Output Log is new, and required in order to make the Verifiable Index historically verifiable.
For example, in Certificate Transparency, the Input Log could be any one of the CT Logs.
In order to make certificates in a log be efficiently looked up by domain, an operator can spin up Verifiable Index and a corresponding Output Log.
The Index would map domain names to indices in the Input Log where the cert is for this domain.

> [!TIP]
> Note that the map doesn't have a "signed map root", i.e. it has no direct analog for a Log Checkpoint.
> Instead, the state of a Verifiable Index is committed to by including its state as a leaf in the Output Log.

> [!NOTE]
> A Verifiable Index is constructed for a single Input Log.
> For ecosystems of multiple logs (e.g. CT), there will be as many Verifiable Indices as there are Input Logs.

### Constructing

1. Log data is consumed leaf by leaf  
2. Each log leaf is parsed using a [MapFn](#mapfn-specified-in-universal-language) that specifies all of the keys in the map to which this relates  
   1. e.g. for CT, this would be all of the domains that relate to a cert.  
   2. The raw domains are not output, but are hashed. If privacy is important, a VRF could be used here.  
3. The output from the MapFn stage represents a sequence of update operations to the map  
   1. This output stream can be serialized for data recovery (see [Write Ahead Map Transaction Log](#write-ahead-map-transaction-log))
4. The map is computed for these update operations and a root is calculated
5. The root hash is written as a new leaf into the Output Log, along with the checkpoint from the Input Log that was consumed to create this revision
6. The Output Log is witnessed, and an Output Log Checkpoint is made available with witness signatures

### Reading

Users looking up values in the map need to know about the MapFn in order to know what the correct key hash is for, e.g. `maps.google.com`.
The values returned for a verifiable point lookup under this key would be a list of `uint64` values that represent indices into the log.
To find the certs for these values, the original log is queried at these indices.

Given a key to read, a read operation needs to return:
 - A witnessed Output Log Checkpoint
 - The latest value in this log, with an inclusion proof to the Output Log Checkpoint
   - The value in this log commits to the Input Log state, and also contains a Verifiable Index root hash
 - The value at the given key in the Verifiable Index, and an inclusion proof

Verifying this involves verifying the following chain:
 - The Output Log Checkpoint is signed by the Map Operator, and sufficient witnesses
 - The inclusion proof in the Output Log: this ties the Map Root Hash to the Output Log Checkpoint
 - The inclusion proof in the Verifiable Index: this ties the indices returned to the key and the Map Root Hash

### Verifying

The correct construction of the map can be verified by any other party.
The only requirement is compute resources to be able to build the map, and a clear understanding of the MapFn (hence the importance for this to be universally specified).
The verifier builds a map at the same size as the verifiable index and if the map checkpoint has the same root hash then both maps are equivalent and the map has been verified for correct construction.

## Sub-Problems

### MapFn Specified in Universal Language

Being able to specify which keys are relevant to any particular entry in the log is critical to allow a verifier to check for correct construction of the map. Ideally this MapFn would be specified in a universal way, to allow the verifier to be running a different technology stack than the core map operator. i.e. having the Go implementation be the specification is undesirable, as it puts a lot of tax on the verifier to reproduce this behaviour identically in another environment.

Some options:

* WASM ([go docs](https://go.dev/wiki/WebAssembly))  
* Formal spec  
* Functional language that can be transpiled

In any case, the MapFn functionally needs to be of the form:

```
type MapFn func([]byte) [][]byte
```

This would be used similarly to:

```
var i uint64 // the index currently being processed. Needs to be set to non-zero if log started mid-way through.
var log chan []byte // channel on which leaves from the log will be written
var mapFn MapFn // initialized somehow (maybe loading wasm)
var output func(i uint64, mapKeys ...[][]byte) // probably just writes the the write ahead log

for leaf := <- log {
  mapKeys := mapFn(leaf)
  output(i, mapKeys...)
  i++
}
```

i.e. consume each entry in the log, apply the map function in order to determine the keys to update, and then output this operation to the next stage of the pipeline.

> [!IMPORTANT]
> This describes the MapFn as returning key hashes.
> We _may_ want to have the map return the raw key (e.g. `maps.google.com`) so that a prefix trie can be constructed.

> [!IMPORTANT]
> The `MapFn` is fixed for the life of the Verifiable Index.
> There are strategies that could be employed to allow updates, but these are out of scope for any early drafts.

### Write Ahead Map Transaction Log

Having a compact append-only transaction log allows the map process to restart and pick up from where it last crashed efficiently. It also neatly divides the problem space: before this stage you have downloading logs and applying the MapFn, and after this stage you have the challenges of maintaining an efficient map data structure for updates and reads.

The core idea is to output at most a single record (row) for each entry in the log.
A valid row has:
 1. the first token being the log index (string representation of uint64)
 1. the following (optional) space-separated values being the key hashes under which this index should appear
 1. a newline terminator

Some use cases may have lots of entries in the log that do not map to any value, and so this supports omitting a log index if it has no updates required in the map.
However, an empty value can be output as a form of sentinel to provide a milepost on restarts that prevents going back over large numbers of empty entries from the log.

```
0 HEX_HASH_1 HEX_HASH_2
2 HEX_HASH_52
3 HEX_HASH_99
4
6 HEX_HASH_2
```

In the above example, there is no map value for the entries at index 1, 4, or 5 in the log.
It is undetermined whether index 7+ is present, and thus anyone replaying this log would need to assume that this needs to be recomputed starting from index 7.

### Turning Log into Efficient Map

The [WAL](#write-ahead-map-transaction-log) can be transformed directly into the data structures needed for serving lookups.
This is implemented using two data structures that are maintained in lockstep:
 - A Verifiable Prefix Trie based on [AKD](https://github.com/facebook/akd): https://github.com/FiloSottile/torchwood/tree/main/mpt; this maintains only the Merkle tree
 - A standard Go map; this stores the actual data, i.e. it maps each key to the list of all relevant indices

Keys in the map are hashes, according to whatever strategy [MapFn](#mapfn-specified-in-universal-language) returns.
Values are an ordered list of indices.

> [!NOTE]
> The current mechanism for hashing the list of indices writes all values out as a single block, and hashes this with a single SHA256.
> An alternative would be to build a Merkle tree of these values.
> This would be slightly more complex conceptually, but could allow for incremental updating of values, and more proofs.

## Status

There is a basic end-to-end application written that supports SumDB in [trillian-examples](https://github.com/google/trillian-examples/tree/master/experimental/vindex/cmd).

In this repository, there is a demo of running a [tlog-tiles][] log using [Tessera][], and keeping the contents of that log synced to a map.
Below are instructions for running this demo with sample key material:

```shell
LOG_PRIVATE_KEY=PRIVATE+KEY+logandmap+38581672+AXJ0FKWOcO2ch6WC8kP705Ed3Gxu7pVtZLhfHAQwp+FE; go run ./vindex/cmd/logandmap --input_log_dir ~/logandmap/inputlog/ --walPath ~/logandmap/map.wal
```

Running the above will run a web server hosting the following URLs:
 - `/inputlog/` - the [tlog-tiles][]
 - `/vindex/lookup` - the provisional [vindex lookup API](./api/api.go)
 - `/outputlog/` - TODO(mhutchinson): this is where the output log will be hosted

The input log has entries for packages in the set {`foo`, `bar`, `baz`, `splat`}.
To inspect the log, you can use the woodpecker tool (using the corresponding public key to the private key used above):

```shell
go run github.com/mhutchinson/woodpecker@main --custom_log_type=tiles --custom_log_url=http://localhost:8088/inputlog --custom_log_vkey=logandmap+38581672+Ab/PCr1eCclRPRMBqw/r5An1xO71MCnImLiospEq6b4l
```

Use left/right cursor to browse, and `q` to quit.

This log is processed into a verifiable map which can be looked up using the following command:

```shell
go run ./vindex/cmd/client --base_url http://localhost:8088/vindex/ --lookup=foo
```

## Milestones

|  #  | Step                                                      | Status |
| :-: | --------------------------------------------------------- | :----: |
|  1  | Public code base and documentation for prototype          |   ✅   |
|  2  | Implementation of in-memory Merkle Radix Tree             |   ✅   |
|  3  | Incremental update                                        |   ✅   |
|  4  | Example written for mapping SumDB                         |   ✅   |
|  5  | Proofs served on Lookup                                   |   ❌   |
|  6  | Output log                                                |   ❌   |
|  7  | Storage backed verifiable-map                             |   ❌   |
|  8  | Example written for mapping CT                            |   ⚠️   |
|  9  | MapFn defined in WASM                                     |   ❌   |
|  10 | Proper repository for this code to live long-term         |   ❌   |
|  11 | Support reading directly from Input Log instead of Clone  |   ❌   |
|  N  | Production ready                                          |   ❌   |


Note that a storage-backed map needs to be implemented before this can be applied to larger logs, e.g. CT.
