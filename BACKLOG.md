# Backlog

Living backlog for aqua-template-registry. Core-SDK and upstream items live
in the companion repo's
[aqua-rs-sdk-core BACKLOG.md](https://github.com/inblockio/aqua-rs-sdk-core/blob/main/BACKLOG.md).

Status legend: [ ] open, [~] in progress, [x] done (keep with a date until
the section clears).

## End-to-end and subscription (requested by Tim, 2026-08-07)

- [x] R1. (2026-08-07, `tests/http_stack.rs`) Complete full-stack end-to-end test over HTTP, running in the
      default suite (no `--ignored`): spawn `registryd` on an ephemeral port
      with a fresh data dir, publish the whole audit set through the HTTP API
      (not the library shortcut), then over HTTP: list vendors, resolve
      `inblockio/<name>` for all 11 templates, fetch each registration tree
      verbatim and re-verify it with aqua-rs-sdk-core, walk
      `GET /publishers/{did}/feed` with `since` paging and assert 12 entries
      in publication order, restart the daemon and assert the feed cursor
      and indexes survive, then shut down cleanly. This supersedes the
      current split between library-level e2e and the curl smoke test.
- [x] R2. (2026-08-07, `src/trust.rs`, `src/import.rs`, `src/subscribe.rs`,
      `src/httpclient.rs`, `src/bin/subscribe.rs`) Consumer subscription and import flow (the missing half of
      "register and subscribe"): a client API plus a small CLI that
      1. subscribes to a publisher DID (feed polling with a persisted
         cursor, restart-safe),
      2. downloads each new template registration and its definition body,
      3. verifies before trusting: registration tree verifies via
         aqua-rs-sdk-core, signer DID equals the vendor's registered
         `vendor_did`, and the definition's recomputed hash
         (`calculate_link`) equals the registered `template_hash`,
      4. imports accepted templates into a local template store that
         applications can use directly: `create_object` with the imported
         hash and verification via the linked-template-tree pattern.
      Delivered with a consumer-side trust layer that the original item did
      not describe, added after a gap analysis: an `ImportPolicy` file
      (explicit publisher allow list, required, with no trust on first use;
      lockfile-style hash pins with `PinnedOnly` and `ApproveNew` modes),
      unconditional rejection of definitions carrying a `verification` (WASM)
      section, a 262144 byte body cap, and a hash-keyed local store with a
      verify-on-read guard. Negative suite in `tests/import_security.rs`.
- [x] R3. (2026-08-07, `tests/full_loop.rs`) End-to-end proof of the full loop in one test: publish a template
      set, subscribe from a second process/store, import, create an object
      of an imported type, verify it green with aqua-rs-sdk-core, and then
      publish one more template and assert the subscriber picks up exactly
      the delta.
- [x] R4. (2026-08-07, `POST /definitions`, `GET /definitions/{hash}`,
      `GET /definitions`) Template-body serving over HTTP: the definition JSONs currently
      ship inside the repo's `seed/audit-set-v1/definitions/`. Add
      `GET /definitions/{hash}` (or equivalent) serving the stored body with
      a recompute-hash-on-read guard, so R2 needs no out-of-band files.
- [ ] R5. Alias registrations for the audit set (short names such as
      `inblockio/prompt`) as audit-set follow-up; additive, no v2 of the set
      required.
- [ ] R6. Push-style subscription upgrade path (SSE or webhooks) as a design
      note first; polling stays the compatibility baseline.

## Trust and integrity

- [x] R10. (2026-08-07, `src/feedhead.rs`, `src/templates/feed_head.json`,
      `tests/feed_head_security.rs`, `tests/feed_head_loop.rs`) Signed feed
      head. Publishers now sign a commitment to their own feed (a count of
      their entries plus a Merkle root over them) as a `feed_head` Aqua tree,
      and subscribers verify it on every sync and fail closed.

      Detected: withholding (registry serves fewer entries than a verified
      head covers), reordering and substitution (recomputed root differs),
      rollback (a head below one already verified), equivocation (two roots at
      one height), and disappearance (a head was verified before, none is
      served now). On any of these nothing is imported and the persisted
      cursor does not advance.

      Leaf construction v1, documented byte for byte in the README:
      `leaf_n = SHA3-256(0x00 || ascii(decimal(n)) || 0x1F || ascii(tip_n))`
      over publisher-local ordinals, rooted with core's `merkle_root`. Ordinals
      rather than registry-global `seq` so a head is portable to a mirror.

      Remaining, and now documented rather than implied: bootstrapping (a
      publisher with no head yet is followed and reported), a fresh subscriber
      cannot tell a current head from a replayed slightly-stale one, there is
      no freshness or liveness guarantee, and collusion with the publisher's
      own key is out of scope by definition.
- [ ] R13. Head freshness. A feed head says "at least N entries existed when
      I signed this", never "nothing newer exists", and it carries no expiry.
      A registry can serve a genuine but months-old head indefinitely and a
      fresh subscriber cannot tell. Options: a publisher-declared maximum head
      age that subscribers enforce, or comparing heads across mirrors.
- [ ] R14. Cross-registry corroboration. A subscriber talks to the registries
      it is configured with and never compares them. Fetching the same
      publisher's head from two independent registries would catch a single
      registry replaying a stale head, which is the main gap R10 leaves.
- [ ] R11. Trust-policy provenance. `allowed_publishers` entries are written
      by hand today. Consider recording where a DID came from (out-of-band
      exchange, a signed introduction, a directory) so an operator reviewing
      the file months later can tell which entries were verified and how.
- [ ] R12. Key rotation for publishers. A namespace is bound to one DID for
      life; there is no way for a publisher to hand a namespace to a new key
      without consumers re-pinning by hand.

## Hardening and operations

- [ ] R7. Concurrency test on the write path (two simultaneous submissions
      for the same vendor/name; assert one 409 and a consistent store).
- [ ] R8. Data-dir migration/versioning note for the file store (what
      happens when the record shape evolves).
- [ ] R9. CI: run the cross-SDK `--ignored` tests in an environment that has
      both SDK checkouts; keep them ignored in the public default suite.
