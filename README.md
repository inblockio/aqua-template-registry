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
| POST | `/definitions` | Upload a template definition body (unsigned, content addressed) |
| GET | `/definitions` | List every template hash that has a body on hand |
| GET | `/definitions/{hash}` | The stored definition body, verbatim, rehashed on read |
| POST | `/heads` | Submit a publisher's signed feed head |
| GET | `/publishers/{did}/head` | The publisher's highest signed feed head, verbatim |
| GET | `/publishers/{did}/heads` | Every height at which this publisher has a stored head |
| GET | `/publishers/{did}/heads/{seq}` | A publisher's head at a specific height, verbatim |
| GET | `/publishers/{did}/vendors` | Every vendor namespace owned by a publisher DID |
| GET | `/publishers/{did}/templates` | Every template registered by a publisher DID, newest first |
| GET | `/publishers/{did}/aliases` | Every alias registered by a publisher DID |
| GET | `/publishers/{did}/feed` | The subscription feed for a publisher DID; see above |
| GET | `/resolve/{vendor}/{name}` | Resolve `<vendor>/<name>` to a template hash |

The three POST bodies are the full signed Aqua tree JSON, taken verbatim: the body is extracted as a raw string, not parsed and re-serialized through a JSON extractor, because storing a re-serialized copy could reorder object keys and the stored bytes would no longer be what the publisher signed.

`POST /definitions` takes no signature. A definition body is content addressed, and its address is already covered by a signed `template-registration`, so the registry rehashes the body and accepts it only when it lands on a hash some publisher already registered. A wrong body cannot be stored no matter who uploads it, which means a mirror or a CI job can supply one. Bodies carrying a `verification` (WASM) section are refused, and so are bodies over 262144 bytes. `GET /definitions/{hash}` rehashes on the way out and refuses to serve anything that no longer matches its own key.

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
| `DEFINITION_TOO_LARGE` | 400 | Definition body over the 262144 byte cap |
| `DEFINITION_CARRIES_WASM` | 400 | Definition body declares a `verification` section |
| `DEFINITION_NOT_REGISTERED` | 404 | Body hashes to something no registration claims |
| `HEAD_REJECTED` | 422 | A submitted feed head failed verification (see `src/feedhead.rs::HeadRejection`) |
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

Cross-vendor aliases are allowed: a vendor can register an alias in their own namespace pointing at a template hash owned by a completely different vendor. Rule 3 only requires the signer to own the namespace the alias *name* lives in; it says nothing about who owns the hash the alias points at.

### What those three rules do not prove

They prove a namespace is internally consistent. They do not prove identity. Nothing in section 3.7 stops anyone from generating a key, claiming a free namespace, and publishing whatever they like, entirely self-consistently and with every signature checking out. "This registration is coherent" and "this publisher is someone you should trust" are different claims, and only the first is in scope for a registry.

So the registry deliberately does not decide who is trustworthy. That decision belongs to the consumer, and it is made explicitly: see "Importing: the consumer side" below, where a committed trust policy names the publisher DIDs a given consumer will accept and pins each template to a specific hash. Every default there is deny.

### Detecting a registry that lies by omission

A consumer re-derives everything it acts on from signed trees and content-addressed bodies, so a hostile registry cannot forge a publisher, invent a name, or substitute a template body. Those were always caught.

What it could also do, until now, was withhold, delay, or reorder feed entries, because nothing in a feed page is publisher-signed. For a template registry the practical harm is pinning a consumer to a superseded template long after a fix was published.

Publishers now sign a feed head: a commitment to their own feed (how many of their entries exist, and a Merkle root over them). A subscriber verifies it on every sync and fails closed.

What is now detected:

- **Withholding.** The registry serves fewer entries than a verified head covers.
- **Reordering or substitution.** The recomputed root does not match the signed one.
- **Rollback.** A head at a lower height than one already verified.
- **Equivocation.** Two different roots signed at the same height.
- **Disappearance.** A head was verified before and the registry now serves none.

On any of those, nothing is imported and the persisted cursor does not advance (`src/subscribe.rs`, `Subscriber::sync`).

What remains, honestly:

- **Bootstrapping.** A publisher who has never signed a head is followed anyway, tolerated and reported on every sync, because refusing would make the feature impossible to adopt. Until the first head exists, withholding is undetectable. A subscriber that has seen a head once will never silently go back to this state (that is the disappearance check above).
- **First contact.** A fresh subscriber has no history, so it cannot tell a current head from a slightly stale one that a registry replayed. It can only detect a head going backwards relative to what it has already seen. Comparing against a mirror, or obtaining the head out of band, closes that.
- **Collusion between a registry and the publisher's own signing key** is out of scope by definition. The key is the authority for that namespace, so a publisher can always sign a head that omits their own entries. A subscriber trusting that DID has already accepted this.
- **Freshness in general.** A head says "at least N entries existed when I signed this", not "nothing has been published since". There is no liveness guarantee and no expiry; `covered_at` is informational.

### The feed head construction

A head covers the publisher's OWN feed entries, numbered from 1 in registry sequence order. The construction uses this publisher-local ordinal rather than the registry-global `seq`: the global number depends on what other publishers did, so a head built from it would only verify against the one registry that assigned it. Ordinals make a head portable, so the same signed head verifies against a mirror.

For the n-th covered entry, with `tip_n` that entry's registration tree tip hash, the lowercase `0x`-prefixed multihash string the registry stores:

```text
preimage_n = ascii(decimal(n)) || 0x1F || ascii(lowercase(tip_n))
leaf_n     = SHA3-256(0x00 || preimage_n)
root       = merkle_root([leaf_1 .. leaf_N], SHA3-256)
```

`0x1F` is ASCII Unit Separator. It cannot occur in either field (one side is decimal digits, the other is `0x` plus lowercase hex), so the concatenation is unambiguous and no length prefix is needed. Without a separator, `(1, "0x12...")` and `(11, "0x2...")` could collide.

`0x00` is the RFC 6962 leaf prefix, applied by core's `batch_leaf_hash`; internal nodes get `0x01` via core's `merkle_root`, and odd nodes are promoted rather than duplicated. This matches the conventions `audit_round_anchor` already uses.

The ordinal is inside the leaf, so the tree commits to each entry's position as well as its content. A pure reorder changes the root, which a construction over tips alone would miss.

`leaf_version` exists so a verifier that does not implement a construction refuses the head rather than guessing at it.

### The feed head template

The `feed_head` template is defined by this project, data only, no `verification` section, no `derives_from`. No SDK defines a feed head.

Its frozen hash (bare SHA3-256 digest; on the wire core wraps it as a multihash with a `0x1620` prefix):

```text
feed-head: 0x77c13274ab93b2707017db0ba8e5b872fce94e86ba54064235bcb528d1879cb9
```

Payload fields: `signer_did`, `head_seq`, `merkle_root`, `leaf_version`, `covered_at`.

The nonce and `local_timestamp` in `src/templates/feed_head.json` are pinned rather than generated, because both feed into the hash: leaving either to chance would mint a new type on every build.

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

## The audit template set v1

The first template set published through this registry. It is the Aqua audit family that `aqua-rs-sdk-core` ships: eleven data-only templates for recording what an agent did during a session, so the record can be verified afterwards by someone who was not there.

The family is flat and re-rooted. `audit_artifact` is the abstract root, carrying the `signer_did` and `created_at` fields common to everything else. The other ten derive from it directly, at depth one:

| Name | Role |
|---|---|
| `audit_artifact` | Abstract root, never instantiated directly |
| `audit_user_turn_marker` | T1, opens a turn |
| `audit_user_prompt` | T2, the user's prompt |
| `audit_agent_thinking` | T3, a reasoning step |
| `audit_agent_tool_call` | T4, a requested tool invocation |
| `audit_api_response` | T5, an attested external API response |
| `audit_tool_result` | T6, the outcome of a tool invocation |
| `audit_hitl_approval` | T7, a human-in-the-loop decision |
| `audit_agent_response` | T8, a response returned to the user |
| `audit_round_anchor` | Closes a turn, commits to its Merkle root |
| `audit_session_close` | Closes a session |

All eleven are data-only: JSON Schema, no WASM, no compute stage. They validate structurally and by signature, and nothing executes.

Namespace and publisher:

```text
vendor        inblockio
publisher DID did:key:z6MkqDxSY5Z3gMNR2qKzV9ZwZDLwUYi5DqevZWhR7vaDWLCN
source        aqua-rs-sdk-core tip 14aa77d, tests/audit_template_hashes.txt
```

That DID is the only authority over the `inblockio` namespace. A consumer who trusts it can subscribe to it and take everything it publishes; a consumer who does not can ignore the namespace entirely, which is the whole of the trust model.

### Publishing the set

`publish-audit-set` reads the template definitions and the hash ledger out of a core checkout, recomputes every hash from the definition through core's own `calculate_link`, and aborts if any of them disagrees with the ledger. Only then does it sign anything: registering a hash that does not match the definition being distributed would publish a name pointing at a type nobody can resolve.

```bash
cargo run --bin publish-audit-set -- \
    --core ../aqua-rs-sdk-core \
    --data-dir ./data \
    --seed-out seed/audit-set-v1
```

The publisher key lives outside the working tree, at `~/.aqua-registry-publisher/inblockio.key` by default (`--key` to override). It is created with mode 0600 inside a 0700 directory if it does not exist, and the derived DID is printed. It is never written into the seed set and must never be committed: whoever holds it owns the namespace.

### Replaying the seed set

`seed/audit-set-v1/` holds the published set as committed data:

```text
seed/audit-set-v1/
  01-vendor-inblockio.json           the signed vendor registration
  02-template-audit_artifact.json    eleven signed template registrations,
  ...                                numbered in registration order
  12-template-audit_session_close.json
  13-feed-head.json                  the signed feed head covering all 12 registrations
  definitions/*.json                 the eleven template bodies, byte-identical to core
  manifest.json                      name, hash, DID, tip, and file names
```

The signed trees are committed rather than regenerated because each one carries a nonce and a timestamp: re-running the publisher produces different bytes with the same meaning. Committing them means the tests and any consumer exercise the exact bytes that were published.

The shipped set includes a signed feed head, `13-feed-head.json`, covering all 12 registrations (`head_seq: 12`), with Merkle root `0x6c143d6dbe550f6b0a08c41804341fec99f93091948131173aa930ca199e711e` (`manifest.json`'s `feed_head` block).

To load the set into a running `registryd`, POST each tree in manifest order (the vendor registration must land first, since the other eleven write into the namespace it claims):

```bash
cd seed/audit-set-v1
curl -sS -X POST http://127.0.0.1:8088/vendors \
     -H 'content-type: application/json' -d @01-vendor-inblockio.json
for f in [01][0-9]-template-*.json; do
  curl -sS -X POST http://127.0.0.1:8088/templates \
       -H 'content-type: application/json' -d @"$f"
  echo
done
```

### Consuming the set

Resolve a name, or list everything the publisher offers:

```bash
did=did:key:z6MkqDxSY5Z3gMNR2qKzV9ZwZDLwUYi5DqevZWhR7vaDWLCN
curl -sS http://127.0.0.1:8088/resolve/inblockio/audit_user_turn_marker
curl -sS "http://127.0.0.1:8088/publishers/$did/templates"
curl -sS "http://127.0.0.1:8088/publishers/$did/feed?since=0"
```

To verify rather than trust, fetch the full signed registration tree for a hash and check it with `aqua-rs-sdk-core`. It comes back byte-identical to what was published, signature intact:

```bash
curl -sS http://127.0.0.1:8088/templates/0x9bf38992cb2cc1230edb6539a98e6d3c889c69aa09b1764a4b91b30cb6a36990
```

Two things are worth checking independently, and `tests/audit_set.rs` checks both. First, the registration tree verifies and is signed by the DID you expected. Second, the `template_hash` it registers is the hash you get by running the distributed template definition back through `calculate_link`. The second check is the one that matters: a registration is only a signed claim that a name points at a hash, and it says nothing about whether the definition you were handed is the one that hashes to it.

```bash
cargo test --test audit_set                # replay and verify the committed seed
cargo test --test audit_set -- --ignored   # also check the seed against ../aqua-rs-sdk-core
```

The ignored test is the staleness check. Core legitimately moves ahead of a published set, so a failure there means it is time to publish a v2, not that the build is broken.

## Importing: the consumer side

Subscribing is the easy half. Deciding what to accept is the half that matters. A consumer runs `subscribe`, which polls a publisher's feed, fetches and verifies the publisher's signed feed head before importing anything, downloads each registration and its definition body, puts both through a verification chain, and files what passes into a local store. A head failure (withholding, rollback, equivocation, disappearance, or a root mismatch) means nothing is imported and the cursor does not move; see "Detecting a registry that lies by omission" above.

### The trust policy

A committed JSON file, because it gets machine-appended and comments would not survive a rewrite. `trust/inblockio-audit-set-v1.json` is the shipped example, pinning the audit set:

```json
{
  "version": 1,
  "allowed_publishers": [
    "did:key:z6MkqDxSY5Z3gMNR2qKzV9ZwZDLwUYi5DqevZWhR7vaDWLCN"
  ],
  "pins": {
    "inblockio/audit_agent_response": "0xe36f3af11b2c6d5c94e2862e4a66db016ff8e8f5486fe72594daa7df480c5413",
    "inblockio/audit_agent_thinking": "0xfe1d5fd50335d5d21f3f1976baadc9eab68a0506241ed5303bb8ad0a25a407f1",
    "inblockio/audit_artifact":       "0x431668e53b2181311ec43db30ff4d4cf738059051829a5a4f3398c22440a16f3"
  }
}
```

(abridged: the shipped file lists all eleven pins.)

`allowed_publishers` is the identity gate and it is required. An absent file is an error, an empty list imports nothing, and there is no trust on first use: a publisher DID that is not written down is refused no matter how well formed its registrations are. Both halves are validated on load, and one bad entry rejects the whole file rather than being skipped, so a typo cannot silently widen what you accept. An unknown top-level key is an error too, so a misspelled setting fails loudly instead of being ignored.

`pins` is a lockfile: qualified name to bare-digest hash. Two modes govern it:

| Mode | Behaviour |
|---|---|
| `PinnedOnly` (default) | Only templates whose name AND hash match an existing pin are imported. |
| `ApproveNew` (`--approve-new`) | Additionally imports templates from allowed publishers that are not yet pinned, and appends each one to the pin file. |

`ApproveNew` is a CLI flag rather than a config setting on purpose. Turning off pinning should be a deliberate act at the moment of doing it, not a line someone set months ago that nobody rereads. The append is the other half of that: every accepted template ends up durably recorded and reviewable in a diff.

Crucially, `ApproveNew` still refuses a name that is pinned to a different hash. Approving new names is not the same as approving substitutions of old ones, and that substitution is the exact attack pinning exists to catch.

### The verification chain

All of these must pass before a template enters the local store. No warn-and-continue, no partial credit:

1. The vendor registration tree verifies through `aqua-rs-sdk-core` under the strict policy, and is self-certifying.
2. Its signer DID is in `allowed_publishers`.
3. The template registration tree verifies through core under the strict policy.
4. Its signer DID equals the vendor DID from step 1.
5. The definition body is within the size cap (262144 bytes) and carries no `verification` (WASM) section.
6. The definition body, rehashed through core's `calculate_link`, equals the `template_hash` the registration claims.
7. The pin check passes for the mode in force.

Step 6 is the one that is easy to omit and fatal to omit. A registration is a signed claim that a name means a hash. It says nothing whatsoever about whether the bytes someone handed you are the bytes that hash to it.

Step 5 is unconditional and not configurable. Core has no WASM runtime, so a WASM-carrying template could not run here anyway, but the local store must not become a distribution channel for one toward a full-SDK consumer downstream. The same refusal is applied on the registry's own `POST /definitions`.

Note what the chain never consults: the registry's derived JSON. The vendor's owning DID is recovered from the signature on the vendor registration tree, fetched from `GET /vendors/{name}/tree`, not read out of the registry's vendor record. That is what makes a hostile registry unable to inject a publisher.

### The local store

```text
<store>/
  templates/<hash>.json       the definition body, verbatim
  records/<hash>.json         who published it, under what name, when
  registrations/<hash>.json   the signed registration, kept so the import can be re-proved
  cursor.json                 the persisted feed position
```

Keyed by hash throughout, never by name. Names are display data chosen by a publisher; a hash is the thing that identifies a type. Nothing activates on import: an application asks for a specific hash and gets a template tree back, so using a template is always an explicit per-hash act in application code.

Reads are guarded. `ImportStore::definition` rehashes the stored body and refuses to return it if it no longer matches the key it was filed under, so local corruption or tampering after import surfaces as an error rather than as a trusted template.

### Running it

```bash
cargo run --bin subscribe -- \
    --registry http://127.0.0.1:8088 \
    --publisher did:key:z6MkqDxSY5Z3gMNR2qKzV9ZwZDLwUYi5DqevZWhR7vaDWLCN \
    --trust trust/inblockio-audit-set-v1.json \
    --store ./imported \
    --once
```

Add `--approve-new` to accept and pin templates that are not yet in the file. Drop `--once` to poll on an interval (`--interval`, default 30 seconds). `--list` prints the local store and talks to nothing.

The cursor advances only over entries that were accepted or already present. A rejected entry does not move it, so the next poll offers that entry again and it imports once the pin exists. A permanently rejected entry is therefore retried on every poll, which is the right trade: silently stepping over something that failed verification would turn a security decision into a one-time event nobody ever sees again.

### Using an imported template

The payoff is the portable-template pattern. A consumer that has never had a template compiled in can create objects of that type and hand any verifier what it needs to check them:

```rust
use aqua_rs_sdk_core::{Aquafier, schema::AquaTreeWrapper};

let store = ImportStore::open("./imported")?;
let aquafier = Aquafier::new();

// Create an object of the imported type.
let tree = aquafier.create_object(link_of(&hash), None, payload, None)?;

// Ship the imported definition alongside so the type resolves for the verifier.
let result = aquafier.verify_aqua_tree_with_linked_trees(
    AquaTreeWrapper::new(tree, None, None),
    vec![store.linked_tree(&hash)?],
    vec![],
).await?;
assert!(result.is_verified());
```

`tests/full_loop.rs` runs exactly this against a live daemon, and asserts the same object does NOT verify without the linked tree, so the import is provably doing the work.

## Vendored registration templates

A template's hash is its type identity: one changed byte, even reordered whitespace, produces a different hash and therefore a different type. The three JSON files under `src/templates/` are byte-identical copies of the corresponding files in `aqua-rs-sdk`, vendored here because `aqua-rs-sdk-core` ships no registration templates of its own.

These three are the registry's own machinery, and are unrelated to the audit set above: the audit templates are content that gets registered, these three are the forms you fill in to register anything at all.

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
cargo test                                  # everything below except the ignored suites
cargo test --test cross_sdk -- --ignored    # cross-SDK compatibility
cargo test --test audit_set -- --ignored    # seed staleness against ../aqua-rs-sdk-core
```

| Suite | What it covers |
|---|---|
| `tests/e2e.rs` | Library-level publish, resolve, trust rules, version chains, aliases |
| `tests/audit_set.rs` | Replays the committed seed set, drift guard against its own definitions |
| `tests/http_stack.rs` | Full stack over real HTTP against a spawned `registryd`, including restart |
| `tests/import_security.rs` | The negative suite: every import control asserted to deny |
| `tests/feed_head_security.rs` | The feed head negative suite: withholding, reordering, rollback, equivocation, and forged heads |
| `tests/feed_head_loop.rs` | Feed heads end to end: a staged registry withholding, rolling back, and dropping a head |
| `tests/full_loop.rs` | Publish, subscribe, import, use an imported template, pick up a delta |
| `tests/cross_sdk.rs` | Ignored: hash equality against the full `aqua-rs-sdk` |

The end-to-end test (`tests/e2e.rs`) generates a real Ed25519 key through `aqua-rs-sdk-core`, builds and signs real vendor and template registration trees with core's `Aquafier`, submits them through both the library API and the axum router, resolves them by publisher DID, fetches the full tree back, and re-verifies it with core. Nothing is stubbed.

The seed replay test (`tests/audit_set.rs`) loads the committed `seed/audit-set-v1` into a fresh store and asserts all twelve registrations still verify, that every registered hash matches the hash recomputed from its own distributed definition, that the eleven names resolve, that the publisher-DID reverse index is complete, and that the feed replays twelve entries in order.

## Dependencies

| Crate | Why |
|---|---|
| `aqua-rs-sdk-core` | Tree parsing, signature verification, template hashing |
| `serde`, `serde_json` | Wire format |
| `thiserror` | The error enum |
| `hex` | Hash field validation |
| `unicode-normalization`, `unicode-script` | The section 3.3 name rules need real Unicode NFC and script tables; hand-rolling either would silently diverge from the SDK |
| `axum`, `tokio`, `tower` (feature `server`, default on) | HTTP surface, async runtime, service plumbing |
| `hyper`, `hyper-util`, `http-body-util`, `bytes` (feature `client`, default on) | The subscriber's HTTP client. All four already arrive under `axum`, so the `client` feature adds no new dependency subtree. hyper's low-level http1 client is used rather than a batteries-included one because a subscriber polls a handful of endpoints on one origin, and every feature not present is one that cannot go wrong in a security-relevant path |

The two networking features are separate: `--no-default-features --features client` builds the subscriber without `axum`, and `--features server` builds the registry without the client. `default-features = false` drops both and leaves the library, which still publishes, verifies, and imports.

`aqua-rs-sdk` (the full SDK, not `-core`) is a dev-dependency, used only by the `#[ignore]`d cross-SDK tests in `tests/cross_sdk.rs`; it is never linked into the library or the `registryd` binary.

## Non-goals

- No on-chain registry. Registration state lives on disk in one service, not in a contract.
- No SWARM or other content-addressed transport. Storage is local, retrieval is HTTP.
- No trust store in the registry. Trust is the consumer's decision, expressed in a local policy file (see "Importing: the consumer side"). The spec's section 4 domain-scoped trust store, with ENS or DNS resolution of a vendor name to a DID, is not implemented: a publisher DID is written down by hand, not resolved.
- No freshness or liveness guarantee. A signed feed head says at least N entries existed when it was signed, not that nothing newer exists; see "Detecting a registry that lies by omission" above.
- No cross-registry gossip or mirror comparison. A subscriber talks only to the registries it chooses; nothing here reconciles two registries' views of the same publisher automatically.
- No transport security in the client. `registryd` binds loopback and expects a reverse proxy; everything a subscriber acts on is checked after it arrives, so TLS is confidentiality and availability, not integrity.
- No plugin or WASM module distribution. The spec's `plugin-registration` template is not implemented, and `aqua-rs-sdk-core` has no WASM runtime to run a plugin against anyway.
- No federation or replication between registries. A consumer polls whichever registries it chooses to.
- No authentication or API keys on the write path. There is nothing to authenticate: every write is a signed tree that authenticates itself, and an unauthorized write is rejected by the trust rules above, not by a missing credential.

## License

Apache-2.0. See `LICENSE`. `NOTICE` credits `aqua-rs-sdk` for the ported name rules in `src/name.rs` and the vendored registration template definitions in `src/templates/`.
