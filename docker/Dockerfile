# Minimal image for `registryd`, the aqua-template-registry HTTP server.
#
# Build via docker/build.sh, which stages the build context: this Dockerfile
# expects a context directory holding the two sibling checkouts the crate's
# path dependency requires (the same layout the CI test job creates):
#
#   <context>/
#     aqua-template-registry/   this repo (committed content only)
#     aqua-rs-sdk-core/         the public sibling (path dependency)
#
# The full aqua-rs-sdk is NOT needed: it is a path DEV-dependency used only
# by the #[ignore]d cross-SDK suites. Cargo nevertheless refuses to resolve a
# manifest whose path dependency is missing on disk, so build.sh strips the
# [dev-dependencies] section from the staged manifest (the same trimming
# `cargo publish` performs). That edit prunes entries from the committed
# Cargo.lock, which is why the build below runs without --locked: every
# crates.io version still comes from the committed lock, cargo only removes
# the dev-only entries.
#
# The runtime stage is `scratch`: one statically linked musl binary, a /data
# mount point, nothing else. No shell, no libc, no package manager. Health
# checks live in the orchestrator (GET /health), not in the image.

FROM docker.io/library/rust:1.95-alpine AS build

# build-base: cc + binutils for the C parts of the hash stack (blake3) and
# for `strip`. `file` backs the static-link assertion below.
RUN apk add --no-cache build-base file

COPY aqua-rs-sdk-core /build/aqua-rs-sdk-core
COPY aqua-template-registry /build/aqua-template-registry

WORKDIR /build/aqua-template-registry

# Server binary only: --no-default-features + server skips the whole client
# dependency subtree (hyper et al.). No --locked: see the header comment —
# versions still resolve from the committed Cargo.lock.
#
# The rust:alpine image ships RUSTFLAGS=-C target-feature=-crt_static
# (dynamic musl linking); override it and name the musl target explicitly so
# the flag applies to the final binary while proc-macros and build scripts
# still build for the host — the scratch stage needs a fully static binary.
ENV RUSTFLAGS="-C target-feature=+crt_static"
RUN target="$(uname -m)-unknown-linux-musl" \
 && cargo build --release --bin registryd \
      --no-default-features --features server --target "$target" \
 && strip "target/$target/release/registryd" \
 && file "target/$target/release/registryd" | tee /tmp/link-check \
 && grep -Eq 'statically linked|static-pie linked' /tmp/link-check \
 && cp "target/$target/release/registryd" /registryd \
 && mkdir -p /data

FROM scratch

COPY --from=build /registryd /registryd
# The store creates its own subdirectories, but on scratch the mount point
# itself must exist and be writable by the runtime UID.
COPY --from=build --chown=65532:65532 /data /data

ENV REGISTRY_DATA_DIR=/data \
    REGISTRY_BIND=0.0.0.0:8088
EXPOSE 8088
VOLUME /data
USER 65532:65532

ENTRYPOINT ["/registryd"]
