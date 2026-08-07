#!/usr/bin/env bash
# Build the registryd container image hermetically.
#
# Stages the COMMITTED content (git archive HEAD) of this repo and its public
# path-dependency sibling into a throwaway context directory, then builds
# docker/Dockerfile against it. Uncommitted changes are deliberately not
# included: the image must be reproducible from what is pushed, not from
# whatever happens to sit in a working tree (same discipline as CI).
#
# Usage:  docker/build.sh
# Env:    AQUA_CORE_DIR   sibling checkout of aqua-rs-sdk-core
#                         (default: ../aqua-rs-sdk-core relative to this repo)
#         DOCKER          container tool (default: docker; podman works)
#
# Result: aqua-template-registry:<crate version> and :latest

set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
core="${AQUA_CORE_DIR:-"$(cd "$here/.." && pwd)/aqua-rs-sdk-core"}"
docker="${DOCKER:-docker}"

[ -f "$core/Cargo.toml" ] || {
    echo "error: aqua-rs-sdk-core not found at $core (set AQUA_CORE_DIR)" >&2
    exit 1
}

version="$(grep -m1 '^version' "$here/Cargo.toml" | cut -d'"' -f2)"

# Disk-backed staging (never a tmpfs: build contexts are real artifacts).
stage="${XDG_CACHE_HOME:-$HOME/.cache}/aqua-template-registry/docker-stage"
rm -rf "$stage"
mkdir -p "$stage/aqua-template-registry" "$stage/aqua-rs-sdk-core"

git -C "$here" archive HEAD | tar -x -C "$stage/aqua-template-registry"
git -C "$core" archive HEAD | tar -x -C "$stage/aqua-rs-sdk-core"

# Strip [dev-dependencies] from the staged manifest — the same trimming
# `cargo publish` applies to path dev-dependencies. The section carries the
# path dev-dependency on the PRIVATE ../aqua-rs-sdk (cross-SDK test suites
# only), and cargo refuses to resolve a manifest whose path dependency is
# absent, even for a --bin build that never compiles it. Dev-dependencies
# are irrelevant to the shipped binary, so the image build uses the
# published-source view of the crate. The section is last in Cargo.toml;
# the guard below fails the build if that ever stops being true.
sed -i '/^\[dev-dependencies\]/,$d' "$stage/aqua-template-registry/Cargo.toml"
if grep -q 'aqua-rs-sdk = { path' "$stage/aqua-template-registry/Cargo.toml"; then
    echo "error: dev-dependency stripping failed (section moved?); fix build.sh" >&2
    exit 1
fi

"$docker" build \
    -f "$here/docker/Dockerfile" \
    -t "aqua-template-registry:$version" \
    -t "aqua-template-registry:latest" \
    "$stage"

rm -rf "$stage"
echo "built aqua-template-registry:$version"
