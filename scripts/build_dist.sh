#!/usr/bin/env bash
# Build the files for PyPI exactly as the release does, from a throw-away copy of the committed tree
# (git archive HEAD), so the checkout is never changed:
#
# 1. every package has the same version (scripts/check_versions.py), and with --tag the tag is v<version>;
# 2. the package READMEs' relative links point at GitHub at the tag (or at the commit without --tag)
#    (scripts/pypi_readmes.py);
# 3. `uv build --no-sources` of every package (sdist, then the wheel from that sdist) into OUT_DIR;
# 4. `twine check --strict` of every built file.
#
# Usage: scripts/build_dist.sh OUT_DIR [--tag vX.Y.Z]     needs uv, git, network for the build tools
# Exit 0 when every step passed.
set -euo pipefail

TWINE="twine@7.0.0"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ $# -ge 1 ] || { echo "usage: $0 OUT_DIR [--tag vX.Y.Z]" >&2; exit 2; }
OUT="$1"; shift
TAG=""
if [ $# -gt 0 ]; then
    [ "$1" = "--tag" ] && [ $# -eq 2 ] || { echo "usage: $0 OUT_DIR [--tag vX.Y.Z]" >&2; exit 2; }
    TAG="$2"
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
[ -z "$(ls -A "$OUT")" ] || { echo "$OUT is not empty" >&2; exit 2; }

COPY="$(mktemp -d "${TMPDIR:-/tmp}/aqt-dist-XXXXXX")"
trap 'rm -rf "$COPY"' EXIT
git -C "$REPO" archive HEAD | tar -x -C "$COPY"
REF="${TAG:-$(git -C "$REPO" rev-parse HEAD)}"
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
    echo "note: uncommitted changes are not part of the build (it uses the committed tree)" >&2
fi

echo "== versions"
VERSION="$(python3 "$COPY/scripts/check_versions.py" ${TAG:+--tag "$TAG"})"
echo "   $VERSION"
echo "== README links at $REF"
python3 "$COPY/scripts/pypi_readmes.py" --ref "$REF" | sed 's/^/   /'
echo "== build"
for project in "$COPY"/*/pyproject.toml; do
    (cd "$COPY" && uv build -q --no-sources --out-dir "$OUT" "$(dirname "$project")")
done
echo "   $(ls "$OUT"/*.whl | wc -l) wheels, $(ls "$OUT"/*.tar.gz | wc -l) sdists in $OUT"
echo "== twine check"
if out="$(NO_COLOR=1 uvx -q "$TWINE" check --strict "$OUT"/* 2>&1)"; then
    echo "   $(ls "$OUT" | wc -l) files PASSED"
else
    echo "$out"; exit 1
fi
