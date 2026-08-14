# Release discipline

Same physics as [`aqua-rs-sdk-core/RELEASE.md`](https://github.com/inblockio/aqua-rs-sdk-core/blob/main/RELEASE.md):
`Cargo.toml` = git tag `vX.Y.Z` = crates.io. No fourth number.

This crate is **not** version-locked to core. They are different products.
The coupling is the `aqua-rs-sdk-core = { version = "…" }` pin, and that
pin must name a version **already on crates.io**.

## When a release happens

1. Core you depend on is already published (if you moved the pin).
2. This repo's `main` is green.
3. Then `scripts/release.sh X.Y.Z`.

Do not `cargo publish` by hand. Do not bump the version inside a feature
PR.

## Version numbers (0.1 series)

Default bump is **`0.1.z+1`**, same experimental window as core. Open
`0.2.0` only on purpose.

A future WASM-accepting registry is a **new series or a feature flag on
this crate**, not a change to core. Core stays WASM-free and fail-closed
on `verification` sections. This crate today rejects WASM definitions on
import; that stays until a deliberate `0.2` (or a named feature) says
otherwise.

## Compatibility

- Registration and import verify through `aqua-rs-sdk-core`. If core
  rejects a tree, so do we.
- Seed `audit-set-v1` hashes must stay equal to core's fixture ledger
  and to the full SDK's audit family.
- `tests/cross_sdk.rs` (ignored, needs the full SDK sibling) is the
  proof that our registration templates match the full SDK. Run it
  before a release that touches those templates.

## Command

```
# After core is on crates.io, if this release needs that core:
#   edit Cargo.toml pin  aqua-rs-sdk-core = { ..., version = "0.1.2", ... }

./scripts/release.sh 0.1.1
./scripts/release.sh --dry-run 0.1.1
```
