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
- [x] R5. (2026-08-07, `seed/audit-aliases-v1/`, `tests/alias_set.rs`) Alias registrations for the audit set (short names such as
      `inblockio/prompt`) as audit-set follow-up; additive, no v2 of the set
      required.
      Published as a SEPARATE additive seed set rather than as extra files in
      audit-set-v1. That set's twelve signed trees and its feed head are
      published bytes, and its head commits to exactly twelve entries; adding
      eleven aliases to that directory would have left the shipped head
      describing a prefix of a longer feed. The original head still verifies
      over the extended feed (a head covers a prefix), which is asserted.
- [x] R6. (2026-08-07, `docs/design/push-subscriptions.md`) Push-style subscription upgrade path (SSE or webhooks) as a design
      note first; polling stays the compatibility baseline.

## Trust and integrity

      Recommendation: SSE if a trigger is ever met, never webhooks, polling
      stays the baseline. Push can only ever be a notification hint that
      triggers a normal verified sync, never a delivery path.
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
- [x] R13. (2026-08-07, `src/feedhead.rs` (`check_freshness`), `tests/head_freshness.rs`) Head freshness. A feed head says "at least N entries existed when
      I signed this", never "nothing newer exists", and it carries no expiry.
      A registry can serve a genuine but months-old head indefinitely and a
      fresh subscriber cannot tell. Options: a publisher-declared maximum head
      age that subscribers enforce, or comparing heads across mirrors.
      No template version bump was needed: `covered_at` already exists in the
      feed_head payload and is covered by the signature. The first design draft
      claimed the signature revision's own local_timestamp was malleable; the
      test rewrote it, rekeyed the revision, and core still refused the tree,
      so that reasoning was wrong and the doc was corrected. `covered_at` is
      still the right field, for meaning rather than integrity.
- [x] R14. (2026-08-07, `src/corroborate.rs`, `tests/head_freshness.rs`) Cross-registry corroboration. A subscriber talks to the registries
      it is configured with and never compares them. Fetching the same
      publisher's head from two independent registries would catch a single
      registry replaying a stale head, which is the main gap R10 leaves.
      Corroboration, not consensus: it reports equivocation and stops rather
      than voting or picking a majority, since a majority of mirrors run by one
      party is not evidence. Lag and unreachability are reported but are not
      failures.
- [x] R11. (2026-08-07, `src/trust.rs` (`PublisherEntry`), `trust/inblockio-audit-set-v1.json`) Trust-policy provenance. `allowed_publishers` entries are written
      by hand today. Consider recording where a DID came from (out-of-band
      exchange, a signed introduction, a directory) so an operator reviewing
      the file months later can tell which entries were verified and how.
      Entries accept either a bare DID string or an object with source,
      verified_by, verified_on and note. Both forms parse, `save` emits
      whichever an entry uses, and files written before this still load
      unchanged, so the format version stays 1. Annotations are advisory:
      nothing in the import chain reads them.
- [ ] R12. Key rotation for publishers. DESIGN COMPLETE, implementation open.
      See `docs/design/publisher-key-rotation.md` (2026-08-07) for the
      continuity-proof shape, the consumer pin-migration flow, and the
      interaction with feed heads. The blocking finding recorded there: a
      purely cryptographic continuity proof cannot distinguish a legitimate
      rotation from an attacker-run one when the old key is compromised, since
      the attacker holds the old key and can generate the new one, so any v1
      needs consumer-side manual approval rather than automatic acceptance.
      Also blocked on a spec question: feed head ordinals are publisher-local
      and a rotated namespace has a feed split across two DIDs, so
      namespace-scoped heads would be a versioned leaf-definition change.
      Original description: A namespace is bound to one DID for
      life; there is no way for a publisher to hand a namespace to a new key
      without consumers re-pinning by hand.

- [ ] R15. Corroboration inside the library sync path. `--corroborate` is a
      CLI-level pre-flight today; `Subscriber::sync` itself does not consult
      other mirrors. A library consumer gets no corroboration unless it calls
      `corroborate` itself.
- [ ] R16. Mirror independence is unmeasurable. Corroboration is worth exactly
      what the independence of the configured mirrors is worth, and nothing
      records or checks whether two URLs are actually run by different parties.
      At minimum the trust config could carry an operator annotation per mirror
      the way R11 does for publishers.
- [ ] R17. Alias version lineage. Aliases have no `supersedes` equivalent, so
      repointing an alias at a new hash is not expressible; today it would need
      a second alias name. Decide whether aliases should be mutable by their
      owner and, if so, how a consumer pins one.

## Hardening and operations

- [x] R7. (2026-08-07, `tests/concurrency.rs`) Concurrency test on the write path (two simultaneous submissions
      for the same vendor/name; assert one 409 and a consistent store).
      Finding: there is no observable index-level race. `submit` holds the
      write lock across the trust check, seq assignment, durable append, and
      index update, so that whole span is one critical section; only the
      cryptographic verification runs concurrently. Roughly 1600 racing
      submissions produced exactly one winner every time.
- [x] R8. (2026-08-07, `src/model.rs` (`record_version`), README "Format and versioning") Data-dir migration/versioning note for the file store (what
      happens when the record shape evolves).
- [x] R9. (2026-08-07, `.github/workflows/ci.yml`) CI: run the cross-SDK `--ignored` tests in an environment that has
      both SDK checkouts; keep them ignored in the public default suite.

      Two jobs: the default one clones aqua-rs-sdk-core as a sibling (the path
      dependency makes that a build prerequisite, not a nicety); the cross-SDK
      job additionally clones the full SDK and is gated on a secret so it is a
      no-op when unavailable and fully blocking when configured. Note
      `cargo fmt --all` reaches into local path dependencies, so the workflow
      uses plain `cargo fmt --check`; and RUSTFLAGS=-D warnings cannot be set
      because the sibling core emits its own warnings.
- [ ] R18. The `test` job cannot pass as written: cargo refuses to resolve a
      manifest whose path dependency is missing on disk, even for builds that
      never compile it, and the job checks out only aqua-rs-sdk-core while
      `Cargo.toml` lists the private `../aqua-rs-sdk` as a path
      dev-dependency. Empirically proven 2026-08-08 during the Docker image
      work: `cargo build --bin registryd` inside a container with only the
      core sibling fails with "failed to load source for dependency
      aqua-rs-sdk" (the ci.yml comment claiming the job was verified with
      only the public sibling is wrong). `docker/build.sh` works around it
      by stripping `[dev-dependencies]` from the staged manifest, the same
      trimming `cargo publish` performs. Fix options: have the test job
      apply the same stripping before building (mirrors the published-crate
      view), or vendor a stub `../aqua-rs-sdk` manifest for the job, or move
      the dev-dependency behind the secret-gated job entirely. Until fixed,
      assume the default CI job is red and do not read its state as a
      verdict on the code.
- [ ] R19. Aqua-service identity conformance for the deployed registry.
      `registryd` has no service key and no `/.well-known/aqua-identity`
      (agent-customer-portal is the reference: JSON document with
      `server_did` plus a signed `service_claim_server` Aqua tree, 90-day
      validity, renewed on restart). The service_claim family is
      identity-module territory that aqua-rs-sdk-core deliberately does not
      ship (unsupported lookup), so the registry cannot mint or verify such
      claims natively. Scoped approach: mint the claim out of band with the
      full SDK under a dedicated service key (distinct from the publisher
      key), mount the resulting document, serve it verbatim from a new
      route (e.g. `REGISTRY_IDENTITY_FILE`). Keeps registryd data-only.
- [ ] R20. Publish the Docker image to GHCR once the org PAT is rotated
      (`docker/build.sh` builds and tags; the 2026-08-08 deployment to
      aqua-registry.inblock.io shipped the image over SSH as a local image,
      which also means watchtower does not auto-update it).