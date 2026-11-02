# Client SDK & Query Proof Verification

`vindex/client` is a lightweight, concurrency-safe Go SDK for querying VIndex servers via their public API. It is safe by default: every lookup and paginated value response is cryptographically verified before data is returned to the caller. This allows Go applications to query a Verifiable Index without trusting the server operator, and serves as a reference model for client implementations in other languages.

Clients must configure an appropriate [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) (or programmatic verifier policy) for trusting the Output Log: lookup verification guarantees that results match a witnessed Output Log commitment, while end-to-end security relies on third-party auditors (such as [`internal/auditor`](../internal/auditor/README.md)) verifying that those commitments were honestly constructed from the Input Log (and, when a caller fetches matched raw entries from the Input Log, authenticating them against the committed `(InputSize, InputRoot)`).

### Non-Goals
- **No Unbounded In-Memory Value Collection**: Hot keys can match millions of Input Log entries; the SDK streams verified entry indices lazily page-by-page rather than providing helpers that drain all historical matches into memory.
- **No Cross-Lookup State**: The client caches zero state across lookups; monitors tracking progress across polling intervals persist their own watermarks externally.
- **No Full-Log Auditing**: The client verifies individual query proofs against witnessed commitments; replaying the Input Log to verify index construction is performed by an auditor ([`internal/auditor`](../internal/auditor/README.md)).
- **No Direct Output Log Polling**: Lookup clients query only the VIndex server's lookup endpoints; they do not fetch Output Log `/checkpoint` or `/tile/...` endpoints directly.

---

## 1. Design

### 1.1 Public Architecture & Package Decoupling

External Go callers import `vindex/client` exclusively. Shared wire and MPT proof primitives live in internal packages that evaluate binary MPT path steps and RFC 6962 compact range folds linearly over byte slices without allocating intermediate tree node graphs (~1 ms per query on commodity CPUs):

| Responsibility | Package | Purpose |
| :--- | :--- | :--- |
| **HTTP Transport & Verification Client API** | `vindex/client` | Public snapshot-scoped lookup client (`Client`, `LookupResult`, `MatchedKey`) with zero dependencies on `pebble`, `wazero`, `tessera`, `internal/ingest`, or `internal/kvstore`. |
| **C2SP Plaintext Wire & Value Log Codecs** | `vindex/internal/wire` | C2SP `tlog-vindex` plaintext parsers/formatters, checkpoint policy verification, and RFC 6962 Value Log compact range folding. |
| **MPT Point & Prefix Proof Verification** | `vindex/internal/mpt` | Binary MPT point inclusion/non-inclusion and two-sided prefix proof verification (`b <= 8192` split-bit bounds and canonical terminal leaf validation on top of `filippo.io/torchwood/mpt`). |

### 1.2 Snapshot-Scoped Client API (`Client`, `LookupResult`, `MatchedKey`)

```go
type Config struct {
    ExpectedOutputLogOrigin string
    OutputLogPolicy         CheckpointPolicy
    ExpectedInputLogOrigin  string
}

func New(indexURL string, cfg Config, opts ...Option) (*Client, error)
func WithHTTPClient(hc *http.Client) Option

func (c *Client) LookupKey(ctx context.Context, key string) (*LookupResult, error)
func (c *Client) LookupPrefix(ctx context.Context, prefix string) (*LookupResult, error)

type LookupResult struct {
    OutputSize  uint64
    OutputRoot  [32]byte
    InputOrigin string
    From        uint64
    InputSize   uint64
    InputRoot   [32]byte
    MPTRoot     [32]byte
    Keys        []MatchedKey // 0..1 for LookupKey; 0..N (lexicographically sorted) for LookupPrefix
}

type MatchedKey struct {
    Key       string
    ValueRoot [32]byte
    // unexported snapshot context: client, from, inputSize
}

func (k MatchedKey) Values(ctx context.Context) iter.Seq2[uint64, error]

var (
    ErrVerificationFailed = errors.New("vindex: verification failed")
    ErrBadRequest         = errors.New("vindex: bad request")
    ErrTooManyKeys        = errors.New("vindex: prefix matched too many keys")
    ErrUnavailable        = errors.New("vindex: server unavailable")
)
```

- **Configuration & Transport**: `New` requires non-empty `ExpectedOutputLogOrigin`, non-nil `OutputLogPolicy` (parsed from a [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) witness quorum text file or constructed programmatically from a primary log verifier and witness threshold), and non-empty `ExpectedInputLogOrigin`. `WithHTTPClient` clones the caller-supplied `*http.Client` (preserving custom `Transport`, proxies, TLS settings, and timeouts) while overriding `CheckRedirect` to reject all `3xx` redirects per [`docs/tlog-vindex.md`](../docs/tlog-vindex.md).
- **Snapshot-Scoped Isolation**: `*Client`, `*LookupResult`, and `MatchedKey` hold zero mutable cross-lookup state. Pagination cursors `(before, expectedValueRoot)` exist strictly as stack-local variables inside each `MatchedKey.Values(ctx)` invocation, allowing a single `*Client` or `MatchedKey` to be used concurrently across goroutines and against load-balanced or short-TTL-cached server replicas where consecutive `/keys` responses may arrive slightly out of order.

```go
res, err := cli.LookupPrefix(ctx, "com.google.")
if err != nil {
    return err
}
if res.From > requiredHorizon {
    return fmt.Errorf("index starts at %d, need <= %d", res.From, requiredHorizon)
}
for _, mk := range res.Keys {
    if mk.Key != "com.google.mail." && mk.Key != "com.google.maps." {
        continue // skip uninterested keys with zero /values requests
    }
    for entryIdx, err := range mk.Values(ctx) {
        if err != nil {
            return err
        }
        if entryIdx < lastProcessedSize {
            break // newest-first stream: stops without fetching older /values pages
        }
        // Authenticate raw entry at entryIdx against (res.InputSize, res.InputRoot)
    }
}
```

### 1.3 End-to-End HTTP & Cryptographic Verification Sequence

`LookupKey` and `LookupPrefix` never return a `*LookupResult` until Steps 1–3 succeed, and `MatchedKey.Values` verifies each `/values` page's compact range root before yielding any `entry_idx` from that page:

| Step | Phase | Operations | Cryptographic & Protocol Assertion |
| :--- | :--- | :--- | :--- |
| **1** | **Output Log Proof (`c2sp.org/tlog-proof@v1`)** | Validates local canonical key/prefix syntax (`1..1024` bytes in `0x21..0x7E`), percent-encodes per RFC 3986 (`unreserved` only, escaping `+` as `%2B`), fetches `GET <index-url>/keys?...` (rejecting `3xx`, mapping `400`/`413`/`503`, bounding response body size), splits on `\n\n` into `c2sp.org/tlog-vindex-keys@v1`, `c2sp.org/tlog-proof@v1` (base64 `extra` `state_entry` and canonical decimal `index`), and `<output-log-checkpoint>`, and computes `SHA-256(0x00 \|\| state_entry)`. | Verifies `<output-log-checkpoint>` against `cfg.ExpectedOutputLogOrigin` and `cfg.OutputLogPolicy` to extract `output_size` and `output_root`, asserts `output_size >= 1` and `index == output_size - 1`, and verifies the Merkle inclusion proof for `SHA-256(0x00 \|\| state_entry)` at `index`. |
| **2** | **State Commitment (`c2sp.org/tlog-vindex-state@v1`)** | Parses `state_entry` as a strict 6-line `c2sp.org/tlog-vindex-state@v1` record (`input-origin`, `from`, `input-size`, `input-root`, `mpt-root`) with no extension lines or trailing data. | Asserts `input_origin == cfg.ExpectedInputLogOrigin` and `0 <= from <= input_size`. Because a lookup response only attests to Input Log entries in `[from, input_size)`, callers requiring coverage back to a specific entry index check `LookupResult.From` against that bound. |
| **3** | **MPT Key / Prefix Proof (`LookupKey` / `LookupPrefix`)** | Validates canonical key syntax (`1..1024` bytes in `0x21..0x7E`) on returned keys, and verifies the binary MPT proof (`internal/mpt`) against `mpt_root` (enforcing `b <= 8192` split-bit bounds and canonical `path_key` / 32-byte `path_val` checks on terminal leaves). | **Inclusion**: Single matched `(key, value_root)` with `key == target` hashes to `mpt_root`.<br>**Non-Inclusion**: `mpt_root == empty_mpt_hash` (`0`-byte proof) or terminal MPT leaf `mpt_leaf_hash(path_key, path_val)` with `path_key != target` hashes to `mpt_root` (`len(res.Keys) == 0`).<br>**Prefix ([two-sided](../docs/tlog-vindex.md#two-sided-prefix-verification))**: On `0` matches, `mpt_root == empty_mpt_hash` (`0`-byte proof) or terminal MPT leaf with `!HasPrefix(path_key, target)` hashes to `mpt_root`; on `n >= 1` matches, `HasPrefix(key, target)` on every returned key proves no keys outside `target` were included from a wider ancestor subtree, while strictly ascending key order + first ancestor split bit `b_1 < 8*len(target)` + reconstructed subtree root + ancestor path to `mpt_root` proves no keys inside `target` were omitted. |
| **4** | **Lazy Backward Value Pagination (`MatchedKey.Values`)** | Initializes local iterator state `(before = inputSize, expectedValueRoot = k.ValueRoot)`. Fetches `GET <index-url>/values?key=<key>&before=<before>` and parses `c2sp.org/tlog-vindex-values@v1` (`preceding`, `popcount(preceding)` compact range hashes, and strictly increasing `Indices`). | Treats `HTTP 404` on an MPT-included key or promised continuation page (`preceding > 0`) as `ErrVerificationFailed`. Asserts `len(Indices) >= 1`, strictly increasing order in `[from, before)`, and `preceding <= Indices[0] - from`; appends `value_log_leaf_hash(entry_idx)` into the running compact range (merging interior nodes via `value_log_node_hash(left, right)` on trailing `1` bits of the running leaf count) and folds the resulting compact range right-to-left to assert equality with `expectedValueRoot` **before** yielding `Indices` in reverse (`len-1` down to `0`, newest-first). If the caller continues and `preceding > 0`, folds the page's initial `popcount(preceding)` compact range hashes right-to-left into `expectedValueRoot`, sets `before = Indices[0]`, and fetches the next backward page. |

### 1.4 Failure Taxonomy & Client Handling

| Failure Category | Root Cause | Client Action |
| :--- | :--- | :--- |
| **Untrusted Checkpoint / Quorum Failure** | Output Log proof or checkpoint fails verification against `ExpectedOutputLogOrigin` and `OutputLogPolicy`, or `input-origin` in `state_entry` does not match `ExpectedInputLogOrigin`. | Return `ErrVerificationFailed`; abort lookup without `*LookupResult`. |
| **Latest-Entry Proof Violation** | `c2sp.org/tlog-proof@v1` proves an entry at `index != output_size - 1` or `output_size == 0`. | Return `ErrVerificationFailed`; abort lookup (server attempted to serve a non-tip Output Log entry). |
| **MPT Proof Mismatch** | Binary MPT path steps or prefix subtree reconstruction do not evaluate to `mpt_root`, or returned keys violate canonical key / prefix bounds. | Return `ErrVerificationFailed`; abort lookup. |
| **Value Log Root or Range Mismatch** | Reconstructed RFC 6962 root from `preceding` compact range hashes and `Indices` does not equal `expectedValueRoot`, or `Indices` fall outside `[from, before)` or are not strictly increasing. | Yield `(0, ErrVerificationFailed)` and terminate iterator without yielding unverified page indices. |
| **Unexpected `/values` `HTTP 404` on Present Key** | `/values` returns `404 Not Found` for a key proven present in the MPT at `before = InputSize` (or when `preceding > 0` promised older entries). | Yield `(0, ErrVerificationFailed)` and terminate iteration (server state violates the witnessed MPT or Value Log commitment). |
| **Prefix Cardinality or Policy Rejection (`HTTP 413` / `HTTP 400`)** | `/keys?prefix=` matched more keys than the server's configured prefix limit (`413`), or violated the server's prefix policy (`400`). | Surface typed HTTP status error (`ErrTooManyKeys` / `ErrBadRequest`) so the caller can narrow the queried prefix. |
| **Upstream Server Unavailable (`HTTP 503`)** | Server has not yet published its first Output Log checkpoint or lags `before`. | Surface `ErrUnavailable` (preserving `Retry-After` metadata when present) so the caller can retry with backoff or fail over. |

---

## 2. Alternatives Considered

### 2.1 Stateless Snapshot Handles vs. Mutable Cross-Lookup Client State
- **Proposed**: Caching observed `(output_size, input_size)` watermarks inside `Client` across lookups or exposing an `AllValues` full-slice helper for value pagination.
- **Rejection**:
  - **Cross-Lookup Watermark Races**: Caching watermarks inside `Client` verifies no Merkle consistency proof (witnesses and auditors provide that guarantee), causes false regression errors when concurrent goroutines or load-balanced/short-TTL-cached server replicas return checkpoints out of arrival order, and tangles state across unrelated key lookups.
  - **Unbounded Slice Allocations on Hot Keys**: Hot keys can match millions of entries, triggering unbounded sequential HTTP pagination and large slice allocations, whereas callers needing a slice can collect from `iter.Seq2` explicitly with their own bounds.
- **Chosen Design**: `Client` is stateless across lookups and returns snapshot-scoped `*LookupResult` handles whose `MatchedKey.Values(ctx)` iterator streams verified entry indices newest-first with early `break` support.

---

## 3. Verification Gate

```bash
go test -race ./vindex/client/...
```
