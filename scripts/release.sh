#!/usr/bin/env bash
# The only publish path for aqua-template-registry. See RELEASE.md.
set -euo pipefail

usage() {
  echo "usage: $0 [--dry-run] [--yes] X.Y.Z" >&2
  exit 2
}

dry_run=0
assume_yes=0
version=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes) assume_yes=1 ;;
    -h|--help) usage ;;
    *)
      if [ -n "$version" ]; then usage; fi
      version="$arg"
      ;;
  esac
done
[ -n "$version" ] || usage
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "error: version must be X.Y.Z, got '$version'" >&2
  exit 2
}

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
crate="aqua-template-registry"
tag="v$version"

current="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
# The crates.io pin on aqua-rs-sdk-core (not the path).
core_pin="$(python3 - <<'PY'
import re, pathlib
text = pathlib.Path("Cargo.toml").read_text()
m = re.search(r'aqua-rs-sdk-core\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', text)
if not m:
    raise SystemExit("could not parse aqua-rs-sdk-core version pin")
print(m.group(1))
PY
)"

echo "crate:     $crate"
echo "current:   $current"
echo "release:   $version"
echo "tag:       $tag"
echo "core pin:  aqua-rs-sdk-core $core_pin"

if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
  echo "error: must be on main (not $(git rev-parse --abbrev-ref HEAD))" >&2
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is dirty" >&2
  git status -sb >&2
  exit 1
fi
git fetch origin
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  echo "error: HEAD is not origin/main" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "error: tag $tag already exists locally" >&2
  exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "error: tag $tag already exists on origin" >&2
  exit 1
fi
if [ "$version" = "$current" ]; then
  echo "error: $version is already Cargo.toml; bump to a new number" >&2
  exit 1
fi

echo "checking crates.io for $crate $version..."
code="$(curl -sS -o /tmp/reg-ver.json -w '%{http_code}' \
  "https://crates.io/api/v1/crates/$crate/$version")"
if [ "$code" = "200" ]; then
  echo "error: $crate $version is already on crates.io" >&2
  exit 1
fi
if [ "$code" != "404" ]; then
  echo "error: crates.io returned HTTP $code looking up $crate $version" >&2
  exit 1
fi

echo "checking crates.io for aqua-rs-sdk-core $core_pin (pin must already exist)..."
core_code="$(curl -sS -o /tmp/core-pin.json -w '%{http_code}' \
  "https://crates.io/api/v1/crates/aqua-rs-sdk-core/$core_pin")"
if [ "$core_code" != "200" ]; then
  echo "error: aqua-rs-sdk-core $core_pin is not on crates.io (HTTP $core_code)." >&2
  echo "       publish core first, then this crate. See RELEASE.md." >&2
  exit 1
fi

if ! grep -qE "^## $version( |$)" CHANGELOG.md; then
  echo "error: CHANGELOG.md has no '## $version' heading" >&2
  exit 1
fi

echo "==> cargo test"
cargo test
echo "==> publish dry-run"
cargo publish --dry-run --allow-dirty

if [ "$dry_run" -eq 1 ]; then
  echo "dry-run complete. would bump $current -> $version, tag $tag, publish."
  exit 0
fi

if [ "$assume_yes" -eq 0 ]; then
  echo
  echo "About to: bump $current -> $version, commit, tag $tag, push, cargo publish."
  echo "This is the timed gate. Ctrl-C to abort."
  read -r -p "Press enter to publish $crate $version: "
fi

python3 - "$version" <<'PY'
import pathlib, sys
version = sys.argv[1]
toml = pathlib.Path("Cargo.toml")
text = toml.read_text()
seen = False
out = []
for line in text.splitlines(keepends=True):
    if not seen and line.startswith("version = "):
        line = f'version = "{version}"\n'
        seen = True
    out.append(line)
if not seen:
    raise SystemExit("Cargo.toml has no package version line")
toml.write_text("".join(out))
lock = pathlib.Path("Cargo.lock")
lt = lock.read_text()
needle = 'name = "aqua-template-registry"\nversion = "'
i = lt.find(needle)
if i < 0:
    raise SystemExit("Cargo.lock missing aqua-template-registry stanza")
j = lt.find('"', i + len(needle))
old_ver = lt[i + len(needle) : j]
lock.write_text(lt[: i + len(needle)] + version + lt[j:])
print(f"Cargo.toml/Cargo.lock: {old_ver} -> {version}")
PY

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "$(cat <<EOF
release: $crate $version

Tested against aqua-rs-sdk-core $core_pin (crates.io pin).
scripts/release.sh ran cargo test + publish dry-run before this commit.
EOF
)"

cargo publish --dry-run
git tag -a "$tag" -m "$crate $version"
git push origin main
git push origin "$tag"
cargo publish

echo "published $crate $version  tag $tag"
echo "crates.io: https://crates.io/crates/$crate/$version"
