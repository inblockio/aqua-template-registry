# Publisher Key Rotation

Status: design note, not implemented.
Date: 2026-08-07.
Backlog item: R12 (see `BACKLOG.md`, "Trust and integrity").

Scoped to design only. Nothing here changes `src/registry.rs`, `src/import.rs`,
`src/trust.rs`, or `src/feedhead.rs` this round. The goal is a document precise
enough that a later round can build from it without redoing the thinking.

## 1. Why this is protocol shaped, not a feature

A vendor namespace `V` is bound to exactly one DID for life today. Two of the
three rules in `src/registry.rs`'s module doc (spec-type-registry.md section
3.7) enforce that binding: rule 1, self-certification, a `vendor-registration`
for `V` is accepted only if the signer equals the `vendor_did` it claims; rule
3, namespace ownership, a `template-registration` or `alias-registration`
naming `V` is accepted only if its signer equals the `vendor_did` `V`'s prior
vendor registration recorded, checked in `owner_check` in `src/registry.rs`.

Rotation is not a feature bolted on top of this. It changes who may write to
`V`, the one fact the whole trust model in the README's "Publisher-DID trust
model" section rests on. Every downstream decision,
`ImportPolicy::allows_publisher` in `src/trust.rs`, `verify_vendor`'s identity
gate in `src/import.rs`, the reverse indexes `vendors_by_did` and
`feed_by_did` in `src/registry.rs`, assumes "the DID that owns `V`" is a fixed
fact learned once. A mechanism that lets it change must satisfy the same
constraint everything else here does: a consumer absent at rotation time must
be able to verify it later from signed bytes alone, offline, the way
`tests/full_loop.rs` verifies an imported template without trusting the
registry that served it.

Concretely: no rotation record the registry alone attests to, and none whose
validity depends on state a later verifier cannot reconstruct from the tree.
A hostile registry must not be able to forge, suppress, or backdate a
rotation any more than it can forge a vendor registration today. This is the
posture R10 already took on feed heads (withholding, reordering, rollback,
closed by a publisher-signed commitment); rotation needs the same treatment
for "who the publisher is."

## 2. The continuity proof

### Payload shape

Propose a fourth registration-shaped payload, `vendor_rotation`, vendored like
`vendor_registration.json` and `template_registration.json` (data only,
`additionalProperties: false`, a `bounds` block). Named `vendor_rotation`
rather than `key-rotation` because what is rotated is which key speaks for a
vendor namespace, not an abstract key; the payload is scoped to `V`.

Minimum fields:

```json
{
  "vendor": "acme-corp",
  "old_did": "did:key:z6Mk...",
  "new_did": "did:key:z6Mk...",
  "effective_ordinal": 7,
  "reason": "rotation"
}
```

- `vendor`: canonical vendor name, validated like `TemplateRegistration.vendor`
  via `NameValidator::validate_vendor_name`.
- `old_did`, `new_did`: full DID strings, same constraint as
  `VendorRegistration.vendor_did` (`^did:(pkh|key):`).
- `effective_ordinal`: `old_did`'s own feed-local ordinal (section 5) at or
  after which rotation takes effect, mirroring `FeedHead.head_seq`'s
  publisher-local counting rather than the registry-global `seq`; left partly
  open, see open question 5.
- `reason`: an enum, at minimum `rotation` (routine), `compromise` (old key
  compromised or suspected), `succession` (namespace handed to a different
  controlling party, not just a new key for the same one). Changes nothing
  cryptographically; changes what a human reviewing `allowed_publishers`
  months later understands, the same motivation as R11.

### The critical property: signed by both keys

A record signed only by `new_did` proves nothing: anyone can generate a key
and claim to be the successor to any namespace. One signed only by `old_did`
is closer but still does not show the new party agreed to receive the
namespace. Both must sign either the same object or an object naming the
other specifically. Linking to something `old_did` signed for an unrelated
reason (their original vendor registration, say) is not consent: that
signature never mentions `new_did`.

This runs into a hard constraint of the current codebase: `src/verify.rs` step
4 requires "at least one signature over that object, and requires every
signature to come from the same DID," rejecting the tree with
`RegistryError::MultipleSigners` otherwise; `verify_vendor` and
`verify_template` in `src/import.rs` inherit the same assumption through
`verify::accept`. Getting a dual-signed claim past this needs a deliberate
change. Two shapes were considered.

**(a) One tree, two signature revisions over the same object.** The
`vendor_rotation` object is created once and both DIDs attach independent
`Signature` revisions to it. Not new capability for `aqua-rs-sdk-core`: its
`Tree` model is already a DAG, and `get_signatures_for` already returns every
signature revision whose `previous_revision` points at a given object, not
just one. Both vendored templates already declare room for it,
`vendor_registration.json` and `template_registration.json` set
`bounds.max_signature_branches: 2`, but enforcement is missing:
`max_signature_branches` is declared schema metadata nothing in
`aqua-rs-sdk-core`'s verification path currently checks, so "exactly two
signers, exactly `{old_did, new_did}`" is a registry-side rule to add, the
same way "exactly one signer" is today, not something core imposes.

**(b) Two linked trees, the new key's tree linking to the old key's tree.**
`new_did` builds a tree with the `vendor_rotation` object, signed once by
`new_did`, with an `Anchor` branch whose `structural_links` point at a
revision inside a tree signed by `old_did`. This reuses
`verify_aqua_tree_with_linked_trees` exactly as `verify::accept` and
`feedhead::verify_head` already do, to resolve both `revision_type`
references and `Anchor.structural_links` against supplied linked trees. The
catch: the anchor target must be an object `old_did` signed for this
rotation, naming `new_did`; linking to `old_did`'s pre-existing
vendor-registration tip proves nothing, since that tip says nothing about
`new_did`. Shape (b) still needs `old_did` to sign a fresh object, just as a
second tree instead of a second signature branch.

### Recommendation

Recommend (a). Both parties end up signing the literal same bytes, so there is
no way for the two sides to disagree, even subtly, about what was agreed.
Shape (b) requires a second object shape for `old_did`'s consent and then
requires, by convention rather than structure, that its fields match the new
tree's claims, an extra place to drift. Shape (a) also matches the
registration-templates convention already in place: one object, one canonical
set of fields, signed.

What this requires changing:

- `src/verify.rs` step 4 stays as is for `Vendor`, `Template`, and `Alias`.
  Give `vendor_rotation` its own acceptance path instead, the way
  `feedhead.rs` already has `verify_head` as a sibling to `verify::accept`
  rather than a branch inside it. A `rotation.rs` module would run
  `verify_aqua_tree_with_linked_trees`, require exactly one typed object of
  the `vendor_rotation` template, and require the signer set on it to be
  exactly `{old_did, new_did}`, each once.
- `src/import.rs` gains an analogous consumer-side function, roughly
  `verify_rotation(aquafier, trusted_vendor: &TrustedVendor, rotation_tree, policy) -> Result<TrustedVendor, ImportRejection>`,
  checking the recovered signer pair against `trusted_vendor.vendor_did`
  (must equal `old_did`) and producing a new `TrustedVendor` with
  `vendor_did = new_did`. Does not reuse `verify_vendor`, which assumes one
  signer.
- `src/registry.rs`'s `check_trust` gains a fourth match arm; see section 6.

## 3. The compromise case, which is the hard one

If an attacker holds `old_did`'s private key, dual signing buys nothing. The
attacker mints a fresh `new_did`, signs the `vendor_rotation` object with both
keys (they control both), and the result verifies exactly as well as a
legitimate rotation. No cryptographic test distinguishes "the real publisher
rotated to a key they control" from "an attacker who stole the old key
rotated to a key they control," because those are the same statement, signed
the same way. Be honest: a purely cryptographic continuity proof cannot solve
key compromise. Claiming otherwise solves a different, easier problem
(rotation without compromise) and calls it the whole thing.

What actually helps is out of band, not in band:

- **Out-of-band confirmation.** A rotation announced only inside the registry
  is exactly as trustworthy as the registry's willingness to carry it. One
  also announced elsewhere (the publisher's own site, a mailing list, a DNS
  record) gives a silent attacker rotation something to contradict.
- **A delay or challenge window.** If a rotation only takes effect some
  interval after first appearing on the feed, the legitimate publisher has
  time to notice and object with the still-valid old key before any consumer
  acts on it. Bounds damage; does not prevent it.
- **Consumer-side manual approval.** `ImportPolicy` in `src/trust.rs` is
  already where a human signs off on what gets trusted, `allowed_publishers`
  populated "by the consumer out of band, never by the act of importing
  something." Rotation acceptance belongs there too; section 4 works this out.
- **Pre-registered recovery keys.** If, at namespace creation, the vendor
  registers recovery DIDs authorized to co-sign a rotation instead of the
  current key, a recovery key can force a rotation the attacker cannot
  countersign. The only item here addressing "old key is compromised and
  unavailable to object"; the rest assume the legitimate publisher can act.

Recommend for v1: out-of-band confirmation and consumer-side manual approval,
both cheap and already having a home in this trust model with no protocol
change. A delay window needs a decision about who enforces it (registry
refusing to serve a rotation until aged, or subscriber refusing to act on
one) and should not block v1. Recovery keys are the real answer to
compromise but are a second protocol mechanism in their own right (their own
`vendor_recovery_keys` declaration, signature, and revocation story); deferred
in staging, not solved.

## 4. Consumer pin migration

`pins` (qualified name to hash) survives rotation untouched. A template's hash
is a function of its definition body through `calculate_link`, unrelated to
who signed the registration that published it. Rotation changes who may
publish new templates into `V`, not the hash of anything already registered.
Every existing pin stays correct with zero action required.

`allowed_publishers` (a `BTreeSet<String>` of DIDs) is what has to change, and
only by growing: a template signed by `new_did` after rotation fails
`verify_vendor`'s identity gate (`policy.allows_publisher(&accepted.publisher_did)`)
and, even bypassing that, fails `verify_template`'s step 4
(`accepted.publisher_did != vendor.vendor_did`) against the old
`TrustedVendor`. Both exist specifically to fail this closed.

Should a subscriber ever auto-add `new_did`? No, by default, for the same
reason the README gives for `PinMode::ApproveNew`: "Turning off pinning
should be a deliberate act at the moment of doing it, not a line someone set
months ago that nobody rereads." Rotation acceptance is the same shape of
decision, arguably larger. `ApproveNew` only widens which *names* are
accepted from a key already trusted; `check_pin` never even consults
`allowed_publishers`. Auto-accepting a rotation would widen *which key* is
trusted, exactly the boundary `import.rs`'s module doc calls the whole reason
a policy file exists ("whose templates am I willing to run"). A self-declared
successor deserves at least as much friction as a new name from an
already-trusted party, not less.

Propose `--accept-rotation` on the `subscribe` binary, mirroring
`--approve-new`. On a verified `vendor_rotation` whose `old_did` is in
`allowed_publishers`:

1. Without the flag: log it, do nothing. Templates from `new_did` keep
   failing exactly as today, and nothing is recorded, matching
   `PinnedOnly`'s posture of never widening on its own.
2. With the flag: call a new `ImportPolicy::accept_rotation(old_did, new_did, vendor, reason)`,
   which *adds* `new_did` to `allowed_publishers` (`allow_publisher` already
   supports this) and does **not** remove `old_did`. Removal is a separate,
   more drastic act (`old_did` may need to stay valid indefinitely to
   re-verify what it signed before rotation, section 5) and should be its own
   explicit operation, not a side effect of accepting a successor.

`old_did` staying in `allowed_publishers` is not a bug, it is required: an
already-imported template signed by `old_did` still needs it in the allow
list to re-verify under the exact chain `import.rs` runs today, since nothing
there distinguishes "currently active for `V`" from "was ever valid for `V`".

Durable recording: `ImportPolicy` is `#[serde(deny_unknown_fields)]` and
already gates on a `version` field, so a `rotations` section is a breaking
file-format bump under the discipline `ImportPolicy::load` already applies to
`version`. This is also R11's problem: R11 proposes recording where an
`allowed_publishers` DID came from, and this note adds a requirement its
eventual design must support, that a DID arriving via `--accept-rotation`
records that it arrived by rotation and names its predecessor (`old_did`, the
rotation tree's tip, when accepted).

## 5. Interaction with feed heads

The subtlest part, where "just make it work" quietly does not.

A feed head is per-DID today. `FeedHead.signer_did` names one publisher, and
`feed_by_did`, `publisher_entry_tips`, and the `feed_head.json` construction
all count ordinals within one publisher's own history ("Entries are the
publisher's OWN entries... numbered from 1", `src/feedhead.rs` module doc).
`subscribe` follows one `--publisher <did>` at a time, and its cursor
bookkeeping (`cursor.json`, `check_against_previous`'s `previous_seq` and
`previous_root`) is scoped to that DID.

Does the old head remain valid after rotation? Yes, unconditionally. A head
`old_did` signed before rotating is a true statement about `old_did`'s own
feed at the time: "at least N of my entries existed when I signed this, and
here is the root." A later rotation does not make that false, and nothing in
`verify_head`, `check_against_entries`, or `check_against_previous` references
anything outside the head and the entries it covers.

What does not carry across is continuity of ordinals. `new_did`'s first head
starts counting from 1 again: `feed_by_did` is keyed by DID, and nothing
expresses "`new_did`'s ordinal 1 continues where `old_did`'s ordinal N left
off." A subscriber "following a vendor" across a rotation is, mechanically,
following two separate DID-keyed feeds with two independently-bootstrapped
head-verification histories that nothing splices together.

The feed is per-DID, not per-namespace: `feed_by_did: BTreeMap<String, Vec<u64>>`
in `src/registry.rs`'s `Index`. Name resolution (`resolve`, `by_qualified`,
`templates`) is keyed by qualified name and hash, not DID, so `<vendor>/<name>`
still resolves correctly across a rotation. But subscription and feed-head
machinery is DID-keyed throughout, so a rotated namespace's feed is genuinely
split across two DIDs at the indexing level, one continuous history to a
human but not to the registry, and the entry that matters most for
continuity, the rotation itself, is not covered by any head unless arranged
to be (enforcement item 6, below).

What real continuity requires: the head construction becoming
namespace-scoped rather than DID-scoped, a head committing to every entry in
`V`'s lineage across however many DIDs have legitimately held it, in rotation
order. This is exactly what `leaf_version` exists to gate ("a verifier that
does not implement a construction refuses the head rather than guessing",
README; `feedhead.rs`'s `LEAF_VERSION`, currently `1`). A namespace-scoped
head is a `leaf_version` 2 proposal, not a compatible extension, because the
ordinal's meaning changes from "my n-th entry" to "the namespace's n-th
entry, whichever DID produced it." It also needs a namespace-keyed sibling to
`feed_by_did` and `publisher_entry_tips` server-side, which depends on the
registry already enforcing rotations correctly, so section 6 is a
prerequisite for this, not the reverse.

Recommend for v1: no namespace-scoped heads. Instead, land the rotation record
itself on the feed where a head can cover it: index the `vendor_rotation`
entry under `old_did`'s feed (naturally the last thing `old_did` is entitled
to publish for `V`), so a further head `old_did` signs commits to it, and a
registry cannot silently withhold the rotation from a subscriber already
head-verifying `old_did`. Because the record is dual-signed, also index it
under `new_did`'s feed, so `new_did`'s first head can cover it too. Modest but
real: it protects visibility of the rotation event using machinery R10
already built, without solving cross-DID ordinal continuity. Needs one small
change to `apply()` in `src/registry.rs`: the trailing
`index.feed_by_did.entry(entry.publisher_did.clone())...` line assumes one
`FeedEntry` has one publisher DID, true for `Vendor`, `Template`, and `Alias`
but not a dual-signed `Rotation` entry, which needs a named exception rather
than a schema change to `FeedEntry` for everyone.

## 6. What the registry would have to enforce

In the style of the three existing rules in `src/registry.rs`'s module doc:

1. **Rotations are dual-signed and self-naming.** A `vendor_rotation` for `V`
   is accepted only if the signer set is exactly two DIDs, exactly the
   `old_did` and `new_did` the payload names. Neither one signer nor a third,
   unrelated signer is acceptable.
2. **`old_did` must be the currently active owner, not merely a past one.**
   A rotation whose `old_did` does not equal `V`'s presently recorded
   `vendor_did` is rejected, so a superseded key cannot re-rotate; only the
   live key authorizes the next move.
3. **`new_did` must differ from `old_did`.** A no-op rotation naming the same
   key twice proves nothing and only pollutes the feed.
4. **Rotation is prospective, never retroactive.** Accepting a rotation
   updates `V`'s recorded `vendor_did` for future ownership checks (rule 3 of
   the existing three) but does not invalidate, re-attribute, or require
   re-signing anything registered under `old_did` before it. History is
   immutable; only the forward-looking pointer moves.
5. **The effective ordinal must not point into the past.** `effective_ordinal`
   must be at least the number of entries `old_did` has already published at
   acceptance time, so a rotation cannot brand some of `old_did`'s
   already-accepted registrations forgeries by claiming to predate them.
6. **A rotation entry is indexed onto both DIDs' feeds.** As in section 5, it
   is appended to `feed_by_did[old_did]` and `feed_by_did[new_did]`, so a
   signed head from either party can cover it, and a registry cannot make the
   rotation disappear from one feed without the absence being conspicuous.

## 7. Staging

A useful, small v1: the `vendor_rotation` template and `RegistrationKind`
addition, an acceptance path in a `rotation.rs` sibling to `feedhead.rs`,
enforcement rules 1 through 5 above (rule 6 is cheap enough to include too),
`verify_rotation` in `import.rs`, and the `--accept-rotation` flag plus
provenance stub in `ImportPolicy` from section 4. This turns "no path" into
"a deliberate, human-gated path" for the common case, routine rotation with
no compromise, which is most rotations. It does not solve compromise and
should not claim to.

Needs spec agreement first: spec-type-registry.md section 10's open question
2, "Vendor name transfer... If yes, this requires a transfer protocol... If
no, vendor name is permanently bound to its inception key," is exactly this
problem, unresolved at the spec level. Implementing `vendor_rotation` without
an answer means this registry silently invents one the spec explicitly leaves
open, risking a format `aqua-rs-sdk` and other registries do not recognize,
undermining the "verifiable by anyone, not just this registry" property this
system is built on. Whether `vendor_rotation` becomes a genesis template,
like the three it sits beside, or stays a community template some registries
choose not to honor, is also a spec-level choice, since genesis status is
what lets a template verify with no linked trees at all (`tests/cross_sdk.rs`).

Should stay out of any near-term round, opinionated: namespace-scoped
(`leaf_version` 2) feed heads, pre-registered recovery keys, any delay or
challenge window (needs its own enforcement-location decision first),
cross-registry corroboration of a rotation (R14's problem, generalized), and
`old_did` being forcibly removed from a trust file as a side effect of
accepting a rotation (removal is a distinct, deliberate act; folding it into
acceptance would make one flag do two differently risky things).

## 8. Open questions

1. Does `vendor_rotation` belong inside the existing `RegistrationPayload`
   tagged union `verify.rs` decodes (a fourth `RegistrationKind`), or should
   it sit outside that enum the way `feed_head` already does? What follows
   for `verify::accept`'s single-signer assumption either way?
2. When `old_did` is compromised with no recovery key pre-registered, is
   there any acceptable v1 answer besides "the namespace is stuck, claim a
   new one"? Is "stuck" the right outcome, given first-come-first-served
   naming means a squatter could claim the old name once abandoned?
3. Should a rotation ever be authorized by a party other than `old_did` and
   `new_did` themselves (a pre-registered recovery key, an organizational
   authority), and if so, whose signature substitutes for `old_did`'s in
   enforcement rule 1?
4. Must `new_did` be a DID never seen before in this registry, or may it
   already be the `vendor_did` of some other namespace, merging two vendors'
   identities under one key? Does the trust model care either way?
5. Should `effective_ordinal` be `old_did`'s own feed-local ordinal, as
   proposed, or the registry-global `seq`? Feed heads use publisher-local
   ordinals specifically so a head stays portable across mirrors that assign
   different global sequence numbers; does the same argument apply here, or
   does "who owns `V` right now" need every mirror to agree on an ordering
   only a registry-global sequence guarantees?
6. How long, if ever, should `old_did` remain in `allowed_publishers` after
   `--accept-rotation`? Is there a meaningful difference between "`old_did`
   may sign nothing new" and "`old_did` remains valid indefinitely for
   re-verifying what it already signed," and should the policy file be able
   to express that difference rather than only present or absent?
