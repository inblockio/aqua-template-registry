# Backlog

Living backlog for aqua-template-registry. Core-SDK and upstream items live
in the companion repo's
[aqua-rs-sdk-core BACKLOG.md](https://github.com/inblockio/aqua-rs-sdk-core/blob/main/BACKLOG.md).

Status legend: [ ] open, [~] in progress, [x] done (keep with a date until
the section clears).

## End-to-end and subscription (requested by Tim, 2026-08-07)

- [ ] R1. Complete full-stack end-to-end test over HTTP, running in the
      default suite (no `--ignored`): spawn `registryd` on an ephemeral port
      with a fresh data dir, publish the whole audit set through the HTTP API
      (not the library shortcut), then over HTTP: list vendors, resolve
      `inblockio/<name>` for all 11 templates, fetch each registration tree
      verbatim and re-verify it with aqua-rs-sdk-core, walk
      `GET /publishers/{did}/feed` with `since` paging and assert 12 entries
      in publication order, restart the daemon and assert the feed cursor
      and indexes survive, then shut down cleanly. This supersedes the
      current split between library-level e2e and the curl smoke test.
- [ ] R2. Consumer subscription and import flow (the missing half of
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
- [ ] R3. End-to-end proof of the full loop in one test: publish a template
      set, subscribe from a second process/store, import, create an object
      of an imported type, verify it green with aqua-rs-sdk-core, and then
      publish one more template and assert the subscriber picks up exactly
      the delta.
- [ ] R4. Template-body serving over HTTP: the definition JSONs currently
      ship inside the repo's `seed/audit-set-v1/definitions/`. Add
      `GET /definitions/{hash}` (or equivalent) serving the stored body with
      a recompute-hash-on-read guard, so R2 needs no out-of-band files.
- [ ] R5. Alias registrations for the audit set (short names such as
      `inblockio/prompt`) as audit-set follow-up; additive, no v2 of the set
      required.
- [ ] R6. Push-style subscription upgrade path (SSE or webhooks) as a design
      note first; polling stays the compatibility baseline.

## Hardening and operations

- [ ] R7. Concurrency test on the write path (two simultaneous submissions
      for the same vendor/name; assert one 409 and a consistent store).
- [ ] R8. Data-dir migration/versioning note for the file store (what
      happens when the record shape evolves).
- [ ] R9. CI: run the cross-SDK `--ignored` tests in an environment that has
      both SDK checkouts; keep them ignored in the public default suite.
