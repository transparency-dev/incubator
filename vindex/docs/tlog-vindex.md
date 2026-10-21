---
description: Verifiable key and prefix index for transparency logs
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/tlog-vindex](https://c2sp.org/tlog-vindex).

# Transparency Log Verifiable Index

This document specifies a verifiable key and prefix lookup index over a transparency log, exposing an HTTP query API alongside a [tiled transparency log][tlog-tiles] of index state commitments.

## Conventions used in this document

The hashing algorithm used throughout is SHA-256, as defined in [FIPS 180-4][], producing a 32-byte digest.

The base64 encoding used throughout is the standard Base 64 encoding specified in [RFC 4648][], Section 4, with `=` padding. Encoders MUST generate canonical base64 according to RFC 4648, Section 3.5, and decoders MUST reject non-canonical encodings.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte value in the 0-255 range. `||` denotes concatenation. All text formats in this document consist of lines terminated by a newline character (U+000A) and MUST NOT contain carriage return characters (U+000D).

Unless stated otherwise, integer indices, counts, and tree sizes in this document are unsigned 64-bit integers (`0 <= x < 2^64`). `[start, end)`, where `start <= end`, denotes the half-open interval containing integers `x` such that `start <= x < end`.

A non-negative integer encoded as an ASCII decimal is a string containing the base-10 representation of the integer with no extra leading zeros. Zero is encoded as `0`, not the empty string.

`uint64_be(x)` denotes the 8-byte big-endian encoding of an unsigned 64-bit integer `x`. `uvarint(x)` denotes the unsigned 64-bit Little-Endian Base 128 (LEB128) variable-length integer encoding of `x`: a value in `0..127` encodes as a single byte, and multi-byte encodings MUST use the minimal number of bytes (with no trailing zero continuation bytes) and MUST NOT exceed 10 bytes.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[FIPS 180-4]: https://csrc.nist.gov/pubs/fips/180-4/final
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Introduction

A verifiable index allows clients to look up which entries in an existing append-only transparency log (the _input log_) match a given search key or key prefix, without downloading the entire input log or trusting the index operator.

The index operator applies a deterministic _mapping function_ to each entry in the input log to extract zero or more _canonical keys_. For each key, the index maintains an [RFC 6962][] Merkle tree (the key's _value log_) over the ascending sequence of input log _entry indices_ at which that key appeared. The 32-byte roots of all non-empty value logs (each a _value log root_, `value_root`) are stored in a path-compressed binary Merkle Patricia Trie (_MPT_).

Rather than signing standalone map checkpoints, the index operator publishes each _index state commitment_ (`c2sp.org/tlog-vindex-state@v1`)—binding the MPT's 32-byte root hash (`mpt-root`), a commitment to the mapping function (`map-fn`), the indexed _start index_ (`from`), and a signed input log [checkpoint][]—as an entry in a [tiled transparency log][tlog-tiles] (the _output log_) witnessed according to [tlog-witness][]. Lookup clients verify query responses offline against witnessed output log checkpoints, while monitors and auditors can deterministically replay the input log to verify every state commitment in the output log.

## Parameters

A verifiable index is defined by:

- an _input log_, parameterized by its [checkpoint][] origin and [tlog-policy][], along with an entry retrieval mechanism that defines how clients and auditors fetch and authenticate input log entries against the input log checkpoint root hash (such as [tlog-tiles][] or [static-ct-api][]);

- a _start index_ (`from`), the first input log entry index covered by the verifiable index (`0` when indexing from the start of the input log, or a positive integer when indexing a suffix of an existing input log);

- an _output log_, which is a [tiled transparency log][tlog-tiles] parameterized by its URL prefix (`<output-log-url>`) and its [tlog-policy][];

- an _index URL_ (`<index-url>`), the base URL serving the `/keys` and `/values` HTTP lookup endpoints defined in this document; and

- a deterministic _mapping function_ that maps a raw input log entry to a set of canonical keys, identified by a 32-byte SHA-256 commitment digest (`map-fn`) distributed out-of-band alongside the input and output log policies.

An operator MAY use the same base URL for both `<output-log-url>` and `<index-url>`.

## Index Structure

This section specifies the deterministic transformation from the indexed input log entry range `[from, input_size)` and a mapping function to the 32-byte MPT root hash (`mpt_root`) committed in an output log entry. Any independent verifier given the input log entries in `[from, input_size)` and the mapping function MUST arrive at the identical `mpt_root`.

### Canonical keys

A _canonical key_ is a byte string representing a normalized search subject (for example, a reversed-label domain name `com.example.mail.` or an escaped Go module path `golang.org/x/crypto`).

A canonical key MUST be between `1` and `1024` bytes in length, inclusive (`1 <= len(key) <= 1024`). Every byte in a canonical key MUST be a printable ASCII character in the range `0x21` to `0x7E` (`!` through `~`), inclusive. Canonical keys MUST NOT contain `NUL` (`0x00`), space (`0x20`), or ASCII control or whitespace characters.

If the mapping function emits the same canonical key `key` multiple times for a single input log entry at entry index `entry_idx`, duplicates MUST be discarded so that `entry_idx` is recorded at most once for `key`.

### Value logs

When indexing an input log of tree size `input_size` from start index `from` (`0 <= from <= input_size`), each canonical key `key` is associated with the input log entry indices in `[from, input_size)` for which the mapping function emitted `key`.

If `key` has zero occurrences in `[from, input_size)`, it MUST NOT be present in the MPT.

If `key` has one or more occurrences in `[from, input_size)`, the matching input log entry indices `entry_idx` (`from <= entry_idx < input_size`) in strictly increasing order form an append-only [RFC 6962, Section 2.1][] Merkle tree (the key's _value log_), where each leaf commits to the 8-byte big-endian encoding of `entry_idx`:

```
value_log_leaf_hash(entry_idx)   = SHA-256(0x00 || uint64_be(entry_idx))
value_log_node_hash(left, right) = SHA-256(0x01 || left || right)
```

The 32-byte Merkle Tree Hash of this value log is the key's _value log root_, denoted `value_root`, and serves as the 32-byte value stored at `key` in the MPT.

### Merkle Patricia Trie

The _MPT_ is a path-compressed binary Merkle Patricia Trie mapping every canonical key `key` with one or more occurrences in `[from, input_size)` to its 32-byte value log root `value_root`.

#### Key padding and bit ordering

To ensure that no distinct key is a bit-prefix of another key, a key `key` of length `L` bytes (`1 <= L <= 1024`) is treated for bit extraction and comparison as an infinite byte stream consisting of `key`, a `0x00` terminator byte, and an infinite sequence of `0xFF` padding bytes:

```
padded(key) = key[0] || key[1] || ... || key[L-1] || 0x00 || 0xFF || 0xFF || ...
```

The bit at _bit position_ `b` of `key` (`b >= 0`, numbered from `0` at the most significant bit of `key[0]`) is:

```
bit(key, b) = (padded(key)[floor(b / 8)] >> (7 - (b mod 8))) & 1
```

Because canonical keys contain no `0x00` bytes (`0x21..0x7E`, see [Canonical keys](#canonical-keys)), the padded bitstream order `padded(x) < padded(y)` is identical to unsigned lexicographical byte order, and a canonical key `key` falls in the MPT subtree of a canonical key prefix `prefix` if and only if `prefix` is a byte prefix of `key`.

For any two distinct canonical keys `x` and `y` (`x != y`), their _split bit_ `split_bit(x, y)` is the smallest bit position `b` (`0 <= b <= 8192`) at which `bit(x, b) != bit(y, b)`. (Because canonical keys are at most 1024 bytes long, two distinct keys always differ at or before bit position `8192`, the first bit of the `0x00` terminator at byte offset `1024`.)

#### Tree topology

The MPT over a set of `(key, value_root)` pairs is the unique path-compressed binary radix trie such that:

- If the set of keys is empty, the trie is the empty trie.
- If the set contains a single pair `(key, value_root)`, the trie is a single MPT leaf node.
- If the set contains two or more keys, let `b` be the minimum `split_bit(x, y)` across all pairs of distinct keys in the set. The root of the subtree is an inner node with split bit `b`, whose left child is the MPT over all keys in the set with `bit(key, b) = 0` and whose right child is the MPT over all keys in the set with `bit(key, b) = 1`.

Because the topology is uniquely determined by the set of present keys and their value log roots, the root hash of the MPT (`mpt_root`) is independent of the order in which keys are inserted or updated. Moreover, when keys are sorted in lexicographical order, the minimum `split_bit(x, y)` in any key range is the minimum `split_bit` between adjacent keys, allowing the root hash of the MPT (or of any prefix subtree) to be computed in `O(n)` time in a single pass.

#### Node hashing

Every node in the MPT has a 32-byte hash.

The hash of the empty trie is the SHA-256 hash of the empty byte string:

```
empty_mpt_hash = SHA-256("")
```

The hash of an MPT leaf node for canonical key `key` and 32-byte value `value_root` is:

```
mpt_leaf_hash(key, value_root) = SHA-256(0x00 || uvarint(len(key)) || key || uvarint(len(value_root)) || value_root)
```

Since `value_root` is 32 bytes, `uvarint(len(value_root))` is the single byte `0x20`.

The hash of an MPT inner node with split bit `b >= 0`, 32-byte left child hash `left`, and 32-byte right child hash `right` is:

```
mpt_inner_hash(b, left, right) = SHA-256(0x01 || uvarint(b) || left || right)
```

### Output log entries

Each entry in the output log is an _index state commitment_ over an input log entry range `[from, input_size)`:

```
c2sp.org/tlog-vindex-state@v1
mpt-root <base64-mpt-root>
map-fn <base64-map-fn-sha256>
from <decimal-start-index>

<input-log-checkpoint>
```

The first line MUST be the string `c2sp.org/tlog-vindex-state@v1`.

The second line MUST start with the string `mpt-root` followed by a space (U+0020) and the base64 encoding of the 32-byte MPT root hash (`mpt_root`).

The third line MUST start with the string `map-fn` followed by a space (U+0020) and the base64 encoding of the 32-byte SHA-256 commitment to the mapping function that produced `mpt_root`. The mapping function commitment MUST remain constant across all entries in a given output log. Lookup clients that do not pin a specific mapping function digest MUST validate the syntactic format of this line and MAY ignore its value.

> [!NOTE]
> **TODO (pre-1.0)**: Decide whether the `map-fn` preimage is the raw compiled `.wasm` module bytecode directly, or a canonical provenance/build manifest (`{source repo @ tag, build toolchain, output wasm hash}`) committing to both the source definition and compiled artifact.

The fourth line MUST start with the string `from` followed by a space (U+0020) and the starting input log entry index (inclusive), encoded as an ASCII decimal. The start index MUST be less than or equal to the tree size (`input_size`) of the embedded input log checkpoint and MUST remain constant across all entries in a given output log (typically `0` when indexing from the start of the input log).

After the `from` line and an empty line, the signed input log [checkpoint][] is included verbatim, ending with a single trailing newline (U+000A).

The output log entry (`state_entry`) is hashed into the output log's Merkle tree according to [RFC 6962, Section 2.1][] (`SHA-256(0x00 || state_entry)`).

Example output log entry:

```
c2sp.org/tlog-vindex-state@v1
mpt-root UFxpN2pP0tW3wQ5xlaluI6r0iIjoc08s2nFK+nnL1uE=
map-fn kElQ2l5Fh62m98WyOGdrXVXnWRtByCf97CCrlK4XCQk=
from 0

example.com/inputlog
98765
lxDZaupAJAxWNRnEK4esZKdB8d/Lq+JZGw+GBWCUK58=

— example.com/inputlog Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
```

## HTTP Interface

A verifiable index exposes two HTTP GET lookup endpoints under `<index-url>`, alongside the output log's [tiled transparency log][tlog-tiles] endpoints under `<output-log-url>`. All successful (`200 OK`) lookup responses MUST have `Content-Type: text/plain; charset=utf-8`.

The endpoints defined in this section MUST NOT serve redirect (`3xx`) responses. If a server has not yet published its first output log checkpoint, or receives a `values` request with `before` greater than its currently indexed input log tree size, it MUST respond with a "503 Service Unavailable" HTTP status code.

`<index-url>/keys` is mutable (returning the latest output log state commitment), so its HTTP headers SHOULD prevent caching beyond a few seconds. Once a server has indexed input log entries at least up to `before`, `<index-url>/values?key=<key>&before=<before>[&limit=<limit>]` is deterministic for a fixed server page-boundary policy, so its caching headers MAY be long-lived.

### keys

Exact key lookups and key prefix lookups in the MPT are served at

    GET <index-url>/keys?key=<key>
    GET <index-url>/keys?prefix=<key-prefix>

A request MUST specify either the `key` query parameter or the `prefix` query parameter, and MUST NOT specify both:

- `key` specifies an exact key lookup: the server proves whether `<key>` exists in the MPT and, if present, returns its `<key> <base64-value-root>` pair.
- `prefix` specifies a key prefix lookup: the server proves and returns all `(key, value_root)` pairs in the MPT whose key has `<key-prefix>` as a byte prefix.

The `<key>` or `<key-prefix>` parameter value MUST be percent-encoded per [RFC 3986][]. Clients MUST percent-encode any byte outside the RFC 3986 `unreserved` set (`ALPHA`, `DIGIT`, `-`, `.`, `_`, `~`—in particular query delimiters and `+` as `%2B`). The unescaped value MUST be a valid canonical key (`1` to `1024` bytes in `0x21..0x7E`, see [Canonical keys](#canonical-keys)). If neither or both of `key` and `prefix` are present, or if the unescaped value is not a valid canonical key, the server MUST respond with a "400 Bad Request" HTTP status code.

On a `prefix` query, a server MAY enforce an application-specific prefix policy (for example, rejecting bare TLD queries such as `com.` or `uk.co.` that do not contain a registrable domain). If `<key-prefix>` violates the server's prefix policy, the server MUST respond with a "400 Bad Request" HTTP status code. A server SHOULD enforce a maximum matched key count on `prefix` queries; if the number of keys in the MPT starting with `<key-prefix>` exceeds the server's limit, the server MUST abort the scan and respond with a "413 Content Too Large" HTTP status code.

```
c2sp.org/tlog-vindex-keys@v1
proof <base64-mpt-proof>
<canonical-key-1> <base64-value-root-1>
<canonical-key-2> <base64-value-root-2>

<output-log-tlog-proof>
```

The first line MUST be the string `c2sp.org/tlog-vindex-keys@v1`.

The second line MUST start with the string `proof`. If the binary MPT proof (see [Binary MPT proofs](#binary-mpt-proofs)) is non-empty, `proof` is followed by a single space (U+0020) and the base64 encoding of the proof. If the binary MPT proof is empty (`0` bytes), the second line MUST be the bare string `proof` with no trailing space. An empty proof occurs when the MPT is empty, when proving an included key in a single-leaf MPT, or when proving a prefix whose non-empty matched keys form the entire MPT.

The next zero or more non-empty lines are the matched keys and their value log roots, each formatted as `<canonical-key>`, a space (U+0020), and the base64 encoding of the 32-byte `value_root`:

- For a `key=<key>` query, there MUST be either zero matched key lines (when `<key>` is not in the MPT) or one matched key line whose `<canonical-key>` equals `<key>` (when `<key>` is in the MPT).
- For a `prefix=<key-prefix>` query, there are zero or more matched key lines sorted in strictly increasing lexicographical key order, each having `<key-prefix>` as a byte prefix.

After the matched key lines and an empty line, an output log inclusion proof (`<output-log-tlog-proof>`) is included verbatim according to [tlog-proof][] (`c2sp.org/tlog-proof@v1`), authenticating the index state commitment that the MPT lookup was evaluated against:

- `extra` MUST be the base64-encoded `c2sp.org/tlog-vindex-state@v1` entry (`state_entry`, see [Output log entries](#output-log-entries)).
- `index` MUST be `output_size - 1` (one less than the tree size of the proof's output log checkpoint), proving that `state_entry` is the latest entry in that checkpoint.

Example response body:

```
c2sp.org/tlog-vindex-keys@v1
proof FQUrvVQc2/IXY3yZ4vmGm5Wdxo9B17djMlHbR6i5fTjP
golang.org/x/crypto obw28IrVp+Sx1FhKBsu5p2Lv2JwyXAFseatVCHqtUsE=

c2sp.org/tlog-proof@v1
extra YzJzcC5vcmcvdGxvZy12aW5kZXgtc3RhdGVAdjEKbXB0LXJvb3QgVUZ4cE4ycFAwdFczd1E1eGxhbHVJNnIwaUlqb2MwOHMybkZLK25uTDF1RT0KbWFwLWZuIGtFbFEybDVGaDYybTk4V3lPR2RyWFZYbldSdEJ5Q2Y5N0NDcmxLNFhDUWs9CmZyb20gMAoKZXhhbXBsZS5jb20vaW5wdXRsb2cKOTg3NjUKbHhEWmF1cEFKQXhXTlJuRUs0ZXNaS2RCOGQvTHErSlpHdytHQldDVUs1OD0KCuKAlCBleGFtcGxlLmNvbS9pbnB1dGxvZyBBejNncmxndHpQSUNhNU9TOG5wVm1mMU15cS81SVpuaU1wK1pKdXJtUkRlT29SRGU0VVJZTjd1NS9aaGN5djJxMWdHekdrdTluVG8renlXRSt4ZU1jVE9BWVE4PQo=
index 12
RZP8gEWXTBy4gCcH9XPPkVhodGgAsHm+Z5ob/4sbqfM=
JiuhJcYDxEsAsEN7LCirEe1u+Gwt0JHruBBQo0BqdNs=

example.com/outputlog
13
pdC++7DEwrjyf+ZbXonKydZY09m6c7UCd0UVVmA2o0s=

— example.com/outputlog opLqBQsREYCgu6xQkYQwJr9fo45a62DN9EdmHXnZdXNqlcVGlCum2Wks+49/V6267UEjw6QUXTS5Rovnzv++qbSzm9Q=
— witness.example/w1 CMp+6LWBU0anHGH5aNDTJkH/gj79sG+T6+iP2ThYN5krrDJbR1HDnucjL39QsZTSvVjyQLrdk3DXDqI5G2HgLatVs0pWh6Up69HVOw==
```

#### Binary MPT proofs

In a non-empty MPT, looking up any target `<key>` or `<key-prefix>` walks from the root down the split bits `b` of the target until it ends at an MPT leaf `(path_key, path_val)`. A binary MPT proof authenticates that terminal leaf (or, for a non-empty prefix match, the root of the prefix subtree) against `mpt_root`.

A _path step_ in a binary MPT proof is encoded as:

```
step = uvarint(b) || sib_hash
```

where `b` (`0 <= b <= 8192`) is the inner node's split bit position and `sib_hash` is the 32-byte sibling node hash at that split. Across any sequence of `k >= 0` path steps `step_1 || step_2 || ... || step_k` walking from a leaf or prefix subtree up to the MPT root (empty when `k = 0`), the split bit positions MUST be strictly decreasing (`b_1 > b_2 > ... > b_k >= 0`). Decoders MUST reject a binary MPT proof if any `uvarint` is malformed or exceeds 10 bytes, if a length-prefixed byte slice or 32-byte `sib_hash` extends past the end of the proof, or if any unconsumed trailing bytes remain after parsing all path steps.

- **Single-key match (`key=<key>` with 1 matched key line)**: The lookup ended at `path_key = <key>` and `path_val = value_root`. Because `<key>` and `value_root` are already present on the matched key line, the binary proof omits them and encodes only the `k >= 0` path steps from that leaf to the MPT root:

  ```
  step_1 || step_2 || ... || step_k
  ```

- **Prefix match (`prefix=<key-prefix>` with `n >= 1` matched key lines)**: The matched key lines reconstruct the prefix subtree root hash, and the binary proof encodes only the `k >= 0` path steps strictly above the prefix subtree root:

  ```
  step_1 || step_2 || ... || step_k   (where b_1 < 8 * len(prefix))
  ```

- **No match (`0` matched key lines for either `key=<key>` or `prefix=<key-prefix>`)**: If `mpt_root` equals `empty_mpt_hash`, the proof is `0` bytes (`proof` with no argument). Otherwise, because no matched key lines are present in the response, the binary proof encodes the terminal leaf `(path_key, path_val)` (a canonical key `path_key` and 32-byte `path_val`) reached when walking the MPT for the target `<key>` or `<key-prefix>` (padded as a key), followed by its `k >= 0` path steps to the MPT root:

  ```
  uvarint(len(path_key)) || path_key || uvarint(len(path_val)) || path_val || step_1 || ... || step_k
  ```

### values

Value log entries (input log entry indices) for a key are served at

    GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]

`<key>` is a required query parameter containing the canonical key (see [Canonical keys](#canonical-keys)), percent-encoded per [RFC 3986][]. Clients MUST percent-encode any byte outside the RFC 3986 `unreserved` set (`ALPHA`, `DIGIT`, `-`, `.`, `_`, `~`—in particular query delimiters and `+` as `%2B`).

`before` is a required query parameter giving the exclusive upper bound on input log entry indices, encoded as a positive ASCII decimal integer (`1 <= before < 2^64`). On the initial page for a key discovered via `keys`, the client MUST set `before` to the input log checkpoint tree size (`input_size`) from the `c2sp.org/tlog-vindex-state@v1` payload of the `keys` response, pinning the query to the exact snapshot committed by `value_root`. On continuation pages, the client MUST set `before` to the first (smallest) input log entry index returned on the preceding page.

`limit` is an optional query parameter giving an advisory maximum number of entry indices to return, encoded as a positive ASCII decimal integer (`1 <= limit < 2^64`). The server MAY return fewer or more entry indices (for example, to align page boundaries with precomputed storage chunks) provided at least one entry index is returned whenever matching occurrences strictly less than `before` exist.

If `<key>` is missing or is not a valid canonical key, `before` is missing, or `before` or `limit` is not a positive ASCII decimal integer (`1 <= x < 2^64`), the server MUST respond with a "400 Bad Request" HTTP status code. Once the server has indexed input log entries at least up to `before`, if `<key>` has zero occurrences strictly less than `before`, the server MUST respond with a "404 Not Found" HTTP status code.

```
c2sp.org/tlog-vindex-values@v1
preceding <preceding-count>
<base64-compact-range-hash-1>
<base64-compact-range-hash-2>

<decimal-entry-index-1>
<decimal-entry-index-2>
```

The first line MUST be the string `c2sp.org/tlog-vindex-values@v1`.

The second line MUST start with the string `preceding` followed by a space (U+0020) and the count of older occurrences of `<key>` in the value log that precede `<decimal-entry-index-1>`, encoded as an ASCII decimal (`preceding >= 0`).

The next zero or more non-empty lines are the base64-encoded 32-byte _compact range hashes_ of the `preceding` older leaves of the value log: one hash for each `1` bit in the binary representation of `preceding` (zero lines when `preceding = 0`), giving the [RFC 6962][] Merkle Tree Hashes of the complete binary subtrees of size `2^i` that partition the first `preceding` leaves of the value log, ordered from largest subtree (most significant `1` bit) to smallest subtree (least significant `1` bit).

After the compact range lines and an empty line, one or more non-empty lines give the matching input log entry indices in `[from, before)` in strictly increasing numerical order, each encoded as an ASCII decimal. When `preceding > 0`, the first (smallest) returned entry index serves as the `before` cursor for the next backward page.

Example response body:

```
c2sp.org/tlog-vindex-values@v1
preceding 3
7BDsxsNsNzaI3Yk8ckaiz6mxWIUS7449VfEKMo3bwSE=
PXEufxzVxESpCkzsKp7fkkM138tI1fUC1cSzEnEJ+uo=

5120
94102
```

## Verifying a Lookup

A client MUST NOT trust any lookup response until all verification steps below succeed.

### Verifying the state commitment

To authenticate the state commitment in a `keys` response:

1. Split the response body on the first empty line (`\n\n`) into the `c2sp.org/tlog-vindex-keys@v1` block and the trailing `c2sp.org/tlog-proof@v1` block.

2. Extract the base64-encoded `extra` field from the `c2sp.org/tlog-proof@v1` block, decode `state_entry`, and compute the output log leaf hash `SHA-256(0x00 || state_entry)`.

3. Verify the `c2sp.org/tlog-proof@v1` block against that leaf hash and the client's configured output log [tlog-policy][] according to [tlog-proof][]. Let `output_size` be the verified output log checkpoint tree size. Check that `output_size >= 1` and that the proven entry `index` equals `output_size - 1`.

4. Parse `state_entry` as a `c2sp.org/tlog-vindex-state@v1` record (see [Output log entries](#output-log-entries)) to obtain `mpt_root`, the `map-fn` digest, `from`, and the embedded `<input-log-checkpoint>`. If the client is configured with an expected `map-fn` commitment, check that the entry's `map-fn` matches; otherwise, validate its syntactic encoding and ignore its value.

5. Verify the embedded `<input-log-checkpoint>` against the client's configured input log [tlog-policy][]. Let `input_size` be the verified input log checkpoint tree size, and check that `0 <= from <= input_size`.

6. A stateful client that caches previously observed checkpoints MUST reject the response if `output_size` or `input_size` is smaller than previously verified sizes, if a checkpoint at an equal tree size has a different root hash, or if `map-fn` or `from` differs from previously verified output log entries.

### Verifying an MPT path

Given a starting node or subtree hash `node_hash`, a lookup target `target` (`<key>` or `<key-prefix>`), a path key `path_key`, and proof path steps `steps`:

1. Read each path step `uvarint(b) || sib_hash` from `steps` in order (rejecting the proof if any `uvarint` is malformed or exceeds 10 bytes, or if fewer than 32 bytes remain for `sib_hash`). Check that `0 <= b <= 8192`, that the split bit positions `b` are strictly decreasing across steps (`b_1 > b_2 > ... > b_k >= 0`), and that `bit(target, b) = bit(path_key, b)`.
2. At each step, update `node_hash = mpt_inner_hash(b, node_hash, sib_hash)` if `bit(target, b) = 0` or `mpt_inner_hash(b, sib_hash, node_hash)` if `bit(target, b) = 1`.
3. Check that `node_hash` equals `mpt_root`.

### Verifying a keys response

To verify an exact key lookup (`GET <index-url>/keys?key=<key>`, with `target = <key>`) or a prefix lookup (`GET <index-url>/keys?prefix=<key-prefix>`, with `target = <key-prefix>`):

1. Check that `target` is a valid canonical key (see [Canonical keys](#canonical-keys)), verify the state commitment (see [Verifying the state commitment](#verifying-the-state-commitment)) to obtain the authenticated `mpt_root`, `from`, and `input_size`, and parse the `c2sp.org/tlog-vindex-keys@v1` header, the `proof` line, and the matched key lines.

2. If there are zero matched key lines (no match in the MPT):
   - If `mpt_root` equals `empty_mpt_hash`, check that the proof is empty (`0` bytes).
   - Otherwise, read `path_key` and `path_val` from the start of the proof (`uvarint(len(path_key)) || path_key || uvarint(len(path_val)) || path_val`). For an exact key lookup, check that `path_key != target`; for a prefix lookup, check that `target` is not a byte prefix of `path_key`. Verify the remaining proof bytes `steps` using [Verifying an MPT path](#verifying-an-mpt-path) with `node_hash = mpt_leaf_hash(path_key, path_val)`, `target`, and `path_key`.

3. If there are one or more matched key lines:
   - For an exact key lookup, check that there is exactly one matched key line `(key, value_root)` with `key = target`, and verify the proof using [Verifying an MPT path](#verifying-an-mpt-path) with `node_hash = mpt_leaf_hash(key, value_root)` and `path_key = target`.
   - For a prefix lookup, check that every matched key is a valid canonical key with `target` as a byte prefix, and that the matched keys are in strictly increasing lexicographical byte order. Check that the first path step in the proof (if non-empty) has split bit `b_1 < 8 * len(target)`. Compute the MPT root hash `node_hash` over the matched `(key, value_root)` pairs (see [Merkle Patricia Trie](#merkle-patricia-trie)), and verify the proof using [Verifying an MPT path](#verifying-an-mpt-path) with `node_hash` and `path_key = target`.

4. For each verified `(key, value_root)` of interest, proceed to [Verifying value log entries](#verifying-value-log-entries) with start index `from` and initial cursor `before = input_size`.

### Verifying value log entries

Given a canonical key `key`, an expected 32-byte value log root `value_root`, the start index `from`, and cursor `before` (initialized to `input_size` from the `keys` response):

1. Fetch `GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>]`.

2. Check that the first line is `c2sp.org/tlog-vindex-values@v1`, parse `preceding` from the second line, and decode the remaining lines before the empty line as 32-byte compact range hashes (checking that the number of hashes equals the number of `1` bits in the binary representation of `preceding`).

3. Parse the one or more decimal input log entry indices after the empty line. Check that they are in strictly increasing order inside `[from, before)`, and that `preceding <= first_entry_idx - from` (where `first_entry_idx` is the first returned entry index).

4. Compute the Merkle Tree Hash of the value log from the compact range hashes (covering the `preceding` older leaves) followed by `value_log_leaf_hash(entry_idx)` for each returned `entry_idx` in order, according to [RFC 6962, Section 2.1][], and check that the resulting 32-byte root hash equals `value_root`.

   To compute this root directly from the compact range list (initially of leaf count `count = preceding`): for each returned `entry_idx` in order, start with `h = value_log_leaf_hash(entry_idx)`, pop the rightmost hash `left` from the list and set `h = value_log_node_hash(left, h)` for each trailing `1` bit of `count`, append `h` to the list, and increment `count` by `1`. Once all returned entry indices have been appended, fold the remaining hashes in the list from right to left using `value_log_node_hash(left, right)`.

5. If `preceding = 0`, the client has retrieved and verified all occurrences of `key` in `[from, input_size)`. If `preceding > 0` and the client wishes to fetch older pages, fold the compact range hashes from right to left using `value_log_node_hash(left, right)` to obtain the expected `value_root` for the `preceding` older leaves, set `before = first_entry_idx`, and repeat from step 1.

## Auditing the Index

Because every state transition of a verifiable index is committed to the output log ([tlog-tiles][]), any third party can audit the index operator without trusting the `keys` or `values` HTTP endpoints:

1. Fetch and verify the output log checkpoint at `<output-log-url>/checkpoint` against the output log [tlog-policy][], verifying Merkle consistency with previously audited output log checkpoints. Fetch new output log entry bundles from `<output-log-url>/tile/entries/...` and authenticate them against the output log checkpoint root hash according to [tlog-tiles][].

2. Initialize the auditor's local MPT to the empty trie and set `prev_size` to the index's configured `from` parameter.

3. For each output log entry in sequential order:
   - Parse the `c2sp.org/tlog-vindex-state@v1` payload to obtain `mpt_root`, the `map-fn` digest, `from`, and the embedded input log checkpoint. Check that `map-fn` and `from` match the index's configured parameters.
   - Verify the input log checkpoint against the input log [tlog-policy][], let `input_size` be its tree size, check that `prev_size <= input_size`, and (after the first output log entry) verify that the input log checkpoint is Merkle-consistent with the previous entry's input log checkpoint.
   - Fetch the input log entries in `[prev_size, input_size)` and authenticate them against the input log checkpoint root hash according to the input log's specification. For each input log entry at `entry_idx` in sequential order, execute the mapping function to obtain the deduplicated set of canonical keys, check that each emitted key is a valid canonical key (see [Canonical keys](#canonical-keys)), append `value_log_leaf_hash(entry_idx)` to the key's value log, and update `(key, value_root)` in the local MPT.
   - Check that the local MPT root hash equals `mpt_root`, and set `prev_size = input_size`. Any mismatch proves that the index operator published an invalid state commitment to the output log.

## Design Rationale

### Unpaginated prefix proofs

Verifying a non-empty prefix proof requires reconstructing the Merkle hash of the matched MPT subtree from all `(key, value_root)` pairs under `<key-prefix>`. Because the subtree hash cannot be verified from a partial subset of keys without introducing interior subtree proofs, `keys?prefix=<key-prefix>` returns the complete matched key set in a single response. Servers bound response sizes by enforcing domain or prefix policies (`400 Bad Request`) and maximum matched-key limits (`413 Content Too Large`).

### Two-sided prefix verification

When verifying a non-empty prefix proof, the MPT path verification step only checks that every ancestor split bit strictly above `8 * len(prefix)` follows the bits of `prefix`. On its own, that check would not prevent a server from omitting an ancestor step and returning the keys of a larger ancestor subtree that contains `prefix` alongside keys outside `prefix`. Checking that every returned key has `prefix` as a byte prefix ensures that all returned keys lie within the `prefix` subtree, while the MPT path check ensures that no keys within the `prefix` subtree were omitted.

### Backward pagination of value log entries

A single canonical key may appear millions of times in the input log, whereas most lookup clients only need the most recent occurrences. Representing each key's occurrences as an append-only [RFC 6962][] value log and paginating backward from `before` allows the server to summarize all `preceding` older occurrences using the compact range hashes of the `preceding` older leaves. The client verifies the newest page directly against `value_root` and, if it wishes to inspect older pages, folds those same compact range hashes to obtain the exact expected `value_root` for the next backward page—requiring no Merkle consistency proofs and no additional round-trips.

## Acknowledgements

The MPT structure and binary proof encoding are based on the Merkle Patricia Trie design in `filippo.io/torchwood/mpt`.

[RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 6962, Section 2.1]: https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1
[checkpoint]: https://c2sp.org/tlog-checkpoint@v1.1.0
[static-ct-api]: https://c2sp.org/static-ct-api@v1.1.0
[tlog-policy]: https://c2sp.org/tlog-policy
[tlog-proof]: https://c2sp.org/tlog-proof
[tlog-tiles]: https://c2sp.org/tlog-tiles@v1.0.0
[tlog-witness]: https://c2sp.org/tlog-witness@v1.1.0
