# aqua-template-registry

A lightweight service and library where template publishers register Aqua templates under their publisher DID, and consumers subscribe to or fetch templates by publisher DID. Licensed Apache-2.0.

## Relationship to aqua-rs-sdk-core

`aqua-rs-sdk-core` is the WASM-free protocol core: revision hashing, Merkle proofs, tree linking, signature verification (Ed25519, EIP-191, P-256, WebAuthn), and template primitives. It deliberately defers template distribution. It knows how to verify a template, and says nothing about how you find one. This project is that missing piece, kept as a separate repository so it can move at community speed without touching the protocol core. It depends on `aqua-rs-sdk-core` for tree parsing, signature verification, and template hashing, and never re-implements any of it.

Core also does not ship the three registration templates (`vendor-registration`, `template-registration`, `alias-registration`) as built-ins, unlike the full `aqua-rs-sdk`. That is why this project vendors byte-identical copies of them; see "Vendored registration templates" below.

## How registration works

Registration is not an API write. A publisher builds a signed Aqua tree, elsewhere, using their own key, and POSTs the whole tree. The registry runs it through a fixed acceptance pipeline (`src/verify.rs`):

1. Parse the submitted body as an Aqua tree.
2. Verify it with `aqua-rs-sdk-core`, handing over the three vendored registration templates as linked trees so the object's type can resolve. Verification runs under a strict policy: a tree whose template cannot be resolved is rejected, never tolerated.
3. Require exactly one typed object in the tree, and require its template hash to be one of the three registration templates. A tree that verifies but carries some other type is not a registration.
4. Require at least one signature over that object, and require every signature on it to come from the same DID. That DID becomes the publisher.
5. Decode the payload into the matching Rust struct and canonicalize its vendor and template names per spec-type-registry.md section 3.3.

The publisher DID is read off the tree's signature revision recovered in step 4. It is never taken from a header, a query parameter, or a field inside the payload that the caller could set freely. A `vendor-registration` payload does carry a `vendor_did` field, but that field is only ever compared against the recovered signer DID (see "Publisher-DID trust model"); it cannot substitute for it.

## Quickstart

Prerequisite: `aqua-rs-sdk-core` is currently a path dependency, so a checkout of it must sit next to this one (`../aqua-rs-sdk-core`). Running the `#[ignore]`d cross-SDK tests additionally needs `../aqua-rs-sdk`. Both become plain version requirements once those crates are published.

Build and run the server:

```bash
cargo run --bin registryd
```

It prints (default data dir `./data`, default bind `127.0.0.1:8088`):

```text
aqua-template-registry v0.1.0
  data dir : ./data
  replayed : seq=0 vendors=0 templates=0 aliases=0 publishers=0
  listening: http://127.0.0.1:8088
```

In another shell, build the three signed registration trees:

```bash
cargo run --example publish -- ./out demo-vendor --seed 5
```

It writes `./out/vendor.json`, `./out/template.json`, and `./out/alias.json`, and prints the publisher DID. With `--seed 5` the key is deterministic, so the DID is always:

```text
did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2
```

Submit them and read the results back.

```bash
curl -sS -X POST http://127.0.0.1:8088/vendors \
     -H 'content-type: application/json' -d @out/vendor.json
```

```json
{"seq":1,"kind":"vendor","publisher_did":"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2","tree_tip":"0x1620fe2c172d0919cafd3b4264972870c98b478542ef3f15b805bb9b37dc82397af9","qualified_name":"demo-vendor"}
```

```bash
curl -sS -X POST http://127.0.0.1:8088/templates \
     -H 'content-type: application/json' -d @out/template.json
```

Receipt with `seq: 2` and `qualified_name: "demo-vendor/invoice"`.

```bash
curl -sS -X POST http://127.0.0.1:8088/aliases \
     -H 'content-type: application/json' -d @out/alias.json
```

Receipt with `seq: 3` and `qualified_name: "demo-vendor/inv"`.

```bash
curl -sS http://127.0.0.1:8088/resolve/demo-vendor/invoice
```

```json
{"qualified_name":"demo-vendor/invoice","template_hash":"0xabababababababababababababababababababababababababababababababab","via":"template","publisher_did":"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2","lineage":["0xabababababababababababababababababababababababababababababababab"]}
```

```bash
curl -sS http://127.0.0.1:8088/stats
```

```json
{"head_seq":3,"vendors":1,"templates":1,"aliases":1,"publishers":1}
```

Submitting `template.json` a second time is rejected with HTTP 409:

```json
{"error":{"code":"DUPLICATE_TEMPLATE","message":"template hash 0xabab... is already registered"}}
```

## Subscribing (the feed)

Every accepted registration gets a registry-global, monotonically increasing sequence number. That number is persisted before the registry acknowledges the write, so it survives a restart and never rewinds.

A consumer subscribes by polling `GET /publishers/{did}/feed?since=<seq>`, which returns entries with `seq > since` for that publisher, oldest first, plus a `next` cursor and a `has_more` flag. The consumer stores `next` and passes it as `since` on the following poll. When the consumer is caught up, `entries` is empty and `next` equals `since`. There is no push and no websocket and no long poll: polling is restart-safe and the server keeps no per-consumer state, which is the entire point.

Default page size is 100 entries, maximum 1000, controlled by the `limit` query parameter.

A truncated response for a publisher with one registration on the feed:

```json
{
  "publisher_did": "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2",
  "since": 0,
  "next": 1,
  "has_more": false,
  "entries": [
    {
      "seq": 1,
      "kind": "vendor",
      "publisher_did": "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2",
      "tree_tip": "0x1620fe2c...",
      "received_at": 1786054403,
      "qualified_name": "demo-vendor",
      "payload": { "kind": "vendor", "vendor_name": "demo-vendor", "vendor_did": "did:key:z6Mkmt..." }
    }
  ]
}
```

A minimal polling loop, in shell. Persist `since` somewhere durable in a real consumer, since that cursor is the only state the subscription has:

```bash
did=did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2
since=0
while true; do
  page=$(curl -sS "http://127.0.0.1:8088/publishers/$did/feed?since=$since")
  echo "$page" | jq -c '.entries[]'          # process new registrations here
  since=$(echo "$page" | jq -r .next)
  sleep 30
done
```

## API reference

Everything is `application/json`, with the single exception of `GET /health`, which returns the plain string `ok`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service metadata: name, version, spec links, subscription hint |
| GET | `/health` | Liveness check, returns `ok` |
| GET | `/stats` | Registry counters (`head_seq`, `vendors`, `templates`, `aliases`, `publishers`) |
| GET | `/registration-templates` | The three vendored registration template definitions and their hashes |
| POST | `/vendors` | Submit a signed `vendor-registration` tree |
| GET | `/vendors` | List every claimed vendor namespace, alphabetically |
| GET | `/vendors/{vendor}` | Record for one vendor namespace |
| GET | `/vendors/{vendor}/tree` | The full signed vendor-registration tree, verbatim |
| POST | `/templates` | Submit a signed `template-registration` tree |
| GET | `/templates/{hash}` | The full signed registration tree for a registered template hash, verbatim |
| GET | `/templates/{hash}/metadata` | Decoded metadata for a registered template hash |
| POST | `/aliases` | Submit a signed `alias-registration` tree |
| GET | `/publishers/{did}/vendors` | Every vendor namespace owned by a publisher DID |
| GET | `/publishers/{did}/templates` | Every template registered by a publisher DID, newest first |
| GET | `/publishers/{did}/aliases` | Every alias registered by a publisher DID |
| GET | `/publishers/{did}/feed` | The subscription feed for a publisher DID; see above |
| GET | `/resolve/{vendor}/{name}` | Resolve `<vendor>/<name>` to a template hash |

The three POST bodies are the full signed Aqua tree JSON, taken verbatim: the body is extracted as a raw string, not parsed and re-serialized through a JSON extractor, because storing a re-serialized copy could reorder object keys and the stored bytes would no longer be what the publisher signed.

`GET /templates/{hash}` returns the stored signed tree byte-identical to what was submitted, so a consumer can re-verify it with `aqua-rs-sdk-core` and never has to trust the registry. The `{hash}` in that path is the hash of the registered template, the thing being published, not the hash of the registration tree that published it.

Error codes, from `RegistryError::code()` and `RegistryError::status()` in `src/error.rs`:

| Code | HTTP status | Meaning |
|---|---|---|
| `MALFORMED_TREE` | 400 | Body is not valid Aqua tree JSON |
| `EMPTY_TREE` | 400 | Tree has no revisions or no resolvable tip |
| `NOT_A_REGISTRATION` | 400 | Tree verified but its typed object is not one of the three registration templates |
| `AMBIGUOUS_REGISTRATION` | 400 | Tree contains more than one typed object |
| `WRONG_REGISTRATION_KIND` | 400 | A vendor tree posted to `/templates`, or similar endpoint mismatch |
| `MALFORMED_PAYLOAD` | 400 | Payload does not match the expected Rust shape |
| `INVALID_NAME` | 400 | A name failed the section 3.3 character or script rules |
| `INVALID_HASH` | 400 | A hash field is not 0x-prefixed hex |
| `TREE_NOT_VERIFIED` | 422 | Cryptographic verification failed |
| `UNSIGNED` | 422 | The registration object carries no signature |
| `MULTIPLE_SIGNERS` | 422 | Signatures over the object come from more than one DID |
| `NOT_SELF_CERTIFYING` | 403 | A vendor registration's signer differs from its own `vendor_did` |
| `NOT_NAMESPACE_OWNER` | 403 | Signer does not own the vendor namespace being written to |
| `VENDOR_NAME_TAKEN` | 403 | A different DID already owns this vendor name |
| `VENDOR_NOT_REGISTERED` | 404 | Referenced vendor namespace has no prior vendor registration |
| `NOT_FOUND` | 404 | No record for the requested key |
| `DUPLICATE_TEMPLATE` | 409 | This template hash is already registered |
| `DUPLICATE_ALIAS` | 409 | This qualified alias name is already registered |
| `NAME_COLLISION` | 409 | A qualified name is claimed by both an alias and a template |
| `UNKNOWN_SUPERSEDES` | 409 | `supersedes` target is not a registered version of the same qualified name |
| `ALREADY_SUPERSEDED` | 409 | `supersedes` target has already been superseded by something else |
| `STORAGE_ERROR` | 500 | On-disk store could not be read or written |
| `CORRUPT_STORE` | 500 | A persisted entry could not be decoded |
| `CORE_ERROR` | 500 | Something went wrong inside `aqua-rs-sdk-core` |

## Publisher-DID trust model

There is exactly one authority in this registry: the publisher's signing key. The registry reads the signer DID off the tree and enforces three rules (`src/registry.rs`, matching spec-type-registry.md section 3.7):

1. Vendor registrations are self-certifying. A `vendor-registration` for namespace `V` is accepted only if the tree's signer DID equals the `vendor_did` in its own payload. A key can only claim a namespace for itself.
2. Vendor names are first come, first served. Once `V` is claimed by DID `D`, no other DID can claim `V`, including by a case variation, since Latin names are case-folded to their canonical lowercase form before comparison. `D` may re-register `V` to update its display name.
3. Only the namespace owner may register templates or aliases into that namespace. A `template-registration` or `alias-registration` naming vendor `V` is accepted only if its signer DID equals the `vendor_did` recorded by `V`'s prior vendor registration.

What this registry deliberately does not do: decide whether a DID is trustworthy. That is a consumer-side policy question, out of scope here by design; a domain-scoped trust store on top of a resolved DID is described in the spec's section 4, and this project does not implement it. Consumers subscribe to the publisher DIDs they already trust, using the feed described above.

Cross-vendor aliases are allowed: a vendor can register an alias in their own namespace pointing at a template hash owned by a completely different vendor. Rule 3 only requires the signer to own the namespace the alias *name* lives in; it says nothing about who owns the hash the alias points at.

## Names and versions

Qualified names have the form `<vendor>/<name>`. Both halves go through the same character rules (`src/name.rs`, a faithful port of the SDK's `NameValidator`):

- Names are NFC-normalized on the way in.
- Each name component must use characters from a single Unicode script, plus the Common and Inherited scripts (digits, hyphens, and the like mix freely with any script).
- Allowed characters are Unicode letters, Unicode digits, and the three separators hyphen, underscore, and dot, none of which may start or end a name.
- Vendor names are capped at 64 Unicode scalar values, template names at 128, both measured after NFC normalization.
- Latin-script names are case-folded to lowercase for canonical storage; scripts without case distinction are stored as-is.

`inblock` is fine (pure Latin). `инблок` is fine (pure Cyrillic). `阿里巴巴` is fine (pure Han). `inblоck`, with the fourth letter swapped for the Cyrillic lookalike `о` (U+043E), is rejected: it mixes Latin and Cyrillic in one component.

Divergence between this validator and the SDK's would silently break resolution compatibility between the two, so the rules are ported faithfully rather than reimplemented from the spec text directly.

Template hashes are immutable: any change to a template produces a new hash. A new version is registered as a new hash, linked to its predecessor by an optional `supersedes` field naming the old hash. `GET /resolve/{vendor}/{name}` returns the newest version that nothing else supersedes, along with the full `lineage`, oldest first, so a consumer pinning an older version by hash can see where it sits in the chain.

The chain is kept linear: a `supersedes` target must already be a known version of the same qualified name (otherwise `409 UNKNOWN_SUPERSEDES`), and a hash that some other version has already superseded cannot be superseded again (`409 ALREADY_SUPERSEDED`).

## Vendored registration templates

A template's hash is its type identity: one changed byte, even reordered whitespace, produces a different hash and therefore a different type. The three JSON files under `src/templates/` are byte-identical copies of the corresponding files in `aqua-rs-sdk`, vendored here because `aqua-rs-sdk-core` ships no registration templates of its own.

The three frozen hashes (bare SHA3-256 digests; on the wire, core wraps each as a multihash with a `0x1620` prefix):

```text
vendor-registration:    0xfe0db62677dad4b648e6ef2f4a96c64c98212765341be8e815388915f2c15b21
template-registration:  0xa02b06af0daa6ecf19ca9495118a46af255a898445f71dd167900350a2f39197
alias-registration:     0xd82b8cb8caef2658cd6f529663dbf9e915f25c04a0b56807329562d39260f294
```

`tests/cross_sdk.rs` asserts these equal the full SDK's `TEMPLATE_LINK` constants, and that trees built with these copies verify under the full SDK with no linked trees needed at all. Those tests are `#[ignore]`d because the full `aqua-rs-sdk` is a heavy dev-dependency (it pulls in `wasmi`, `jsonschema`, blockchain and web hosts, and a trust store), and running it on every `cargo test` would tax everyone for a check that only matters when `src/templates/*.json` is touched.

```bash
cargo test --test cross_sdk -- --ignored
```

## Storage

```text
<data dir>/
  entries/000000000001.json    one FeedEntry per file, zero padded to 12 digits
  trees/<tree_tip>.json        the full signed Aqua tree, verbatim
```

The append-only feed under `entries/` is the only durable state. Every index the registry serves (vendor ownership, template lineage, alias resolution, the reverse per-publisher indexes) is derived and rebuilt by replaying that feed at startup. Writes are atomic: each file is written to a `.tmp` sibling in the same directory, `fsync`ed, and then renamed into place, so a crash mid-write never leaves a corrupt or partial file behind. The tree blob is written before its entry file, so any entry that exists on disk is guaranteed to have its tree blob already there too; the only possible crash artifact is a harmless orphaned tree blob with no entry pointing at it yet. Tree blobs are stored verbatim rather than re-serialized, because re-serializing through `serde_json` could reorder object keys, and the bytes on disk would no longer be exactly what the publisher signed.

Plain files were chosen over an embedded database such as sled or a SQL engine because the durable state here is a small append-only log: no query planner is needed, no concurrent-writer story is needed, no schema migration story is needed. A directory of readable JSON is operator-inspectable (`cat`, `grep`, `ls`), trivially backed up (`cp -r`, `rsync`, `tar`), and adds zero extra dependencies.

## Testing

```bash
cargo test                                  # unit plus end-to-end
cargo test --test cross_sdk -- --ignored    # cross-SDK compatibility
```

The end-to-end test (`tests/e2e.rs`) generates a real Ed25519 key through `aqua-rs-sdk-core`, builds and signs real vendor and template registration trees with core's `Aquafier`, submits them through both the library API and the axum router, resolves them by publisher DID, fetches the full tree back, and re-verifies it with core. Nothing is stubbed.

## Dependencies

| Crate | Why |
|---|---|
| `aqua-rs-sdk-core` | Tree parsing, signature verification, template hashing |
| `serde`, `serde_json` | Wire format |
| `thiserror` | The error enum |
| `hex` | Hash field validation |
| `unicode-normalization`, `unicode-script` | The section 3.3 name rules need real Unicode NFC and script tables; hand-rolling either would silently diverge from the SDK |
| `axum`, `tokio`, `tower` (feature `server`, default on) | HTTP surface, async runtime, service plumbing |

The library alone can be used with `default-features = false`, which drops `axum`, `tokio`, and `tower` entirely.

`aqua-rs-sdk` (the full SDK, not `-core`) is a dev-dependency, used only by the `#[ignore]`d cross-SDK tests in `tests/cross_sdk.rs`; it is never linked into the library or the `registryd` binary.

## Non-goals

- No on-chain registry. Registration state lives on disk in one service, not in a contract.
- No SWARM or other content-addressed transport. Storage is local, retrieval is HTTP.
- No trust store integration. See the trust model section above: trust is the consumer's decision, not this registry's.
- No plugin or WASM module distribution. The spec's `plugin-registration` template is not implemented, and `aqua-rs-sdk-core` has no WASM runtime to run a plugin against anyway.
- No federation or replication between registries. A consumer polls whichever registries it chooses to.
- No authentication or API keys on the write path. There is nothing to authenticate: every write is a signed tree that authenticates itself, and an unauthorized write is rejected by the trust rules above, not by a missing credential.

## License

Apache-2.0. See `LICENSE`. `NOTICE` credits `aqua-rs-sdk` for the ported name rules in `src/name.rs` and the vendored registration template definitions in `src/templates/`.
