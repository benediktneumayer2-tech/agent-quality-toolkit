#!/usr/bin/env bash
# Clean-install check: prove that the packages work installed, without the repository.
#
# 1. Build every aqt-* package that has a pyproject.toml (sdist, then the wheel from that sdist).
# 2. Install only the built wheels into a fresh venv outside the repository (third-party
#    dependencies such as cryptography come from PyPI; no editable installs).
# 3. From a directory outside the checkout, with throw-away HOME and XDG directories (as in
#    scripts/test_all.sh): every console script's --help, `aqt-evidence vectors`,
#    `aqt status --json` (when the umbrella command is installed) and the integration demo test,
#    run from a copy of examples/demo.
#
# Usage: scripts/clean_install_check.sh            needs uv, git and network for package downloads
#        scripts/clean_install_check.sh --docker   the same in a fresh python:3.12-slim container
#                                                  (repository mounted read-only, removed afterwards)
# Exit 0 when every check passed.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "${1:-}" = "--docker" ]; then
    command -v docker >/dev/null || { echo "docker is required for --docker" >&2; exit 2; }
    exec docker run --rm -v "$REPO:/src:ro" -w /tmp python:3.12-slim bash -c '
        set -e
        export DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore
        apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null
        pip install -q uv
        useradd -m checker
        exec su checker -c "/src/scripts/clean_install_check.sh"'
fi
[ $# -eq 0 ] || { echo "usage: $0 [--docker]" >&2; exit 2; }

for tool in uv git; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aqt-clean-XXXXXX")"
RUNTIME="$(mktemp -d /tmp/aqtr-XXXXXX)"           # short path: AF_UNIX socket paths are limited
chmod 700 "$RUNTIME"
trap 'rm -rf "$WORK" "$RUNTIME"' EXIT
case "$WORK/" in "$REPO"/*) echo "the temporary directory must be outside the repository" >&2; exit 2 ;; esac
DIST="$WORK/dist" VENV="$WORK/venv" OUTSIDE="$WORK/outside"
SANDBOX="$WORK/sandbox"
mkdir -p "$DIST" "$OUTSIDE" "$SANDBOX/home" "$SANDBOX/state" "$SANDBOX/config" "$SANDBOX/cache" "$SANDBOX/tmp"
PY="$VENV/bin/python"

STATUS=0
fail() { echo "FAIL: $*"; STATUS=1; }

run_isolated() {  # throw-away HOME/XDG dirs, no AQT_* overrides, no PYTHONPATH, the venv first on PATH
    local name unset_args=(-u PYTHONPATH -u PYTHONHOME)
    for name in $(env | sed -n 's/^\(AQT_[A-Za-z0-9_]*\)=.*/\1/p'); do unset_args+=(-u "$name"); done
    (cd "$OUTSIDE" && env "${unset_args[@]}" HOME="$SANDBOX/home" XDG_STATE_HOME="$SANDBOX/state" \
        XDG_CONFIG_HOME="$SANDBOX/config" XDG_CACHE_HOME="$SANDBOX/cache" XDG_RUNTIME_DIR="$RUNTIME" \
        TMPDIR="$SANDBOX/tmp" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$SANDBOX/gitconfig" \
        PYTHONDONTWRITEBYTECODE=1 VIRTUAL_ENV="$VENV" PATH="$VENV/bin:$PATH" "$@")
}

# ---- 1. build ---------------------------------------------------------------------------------------
PACKAGES=()
for project in "$REPO"/aqt-*/pyproject.toml; do PACKAGES+=("$(basename "$(dirname "$project")")"); done
[ ${#PACKAGES[@]} -gt 0 ] || { echo "no aqt-* packages found in $REPO" >&2; exit 2; }
echo "== build: ${PACKAGES[*]}"
for pkg in "${PACKAGES[@]}"; do
    (cd "$WORK" && uv build -q --no-sources --out-dir "$DIST" "$REPO/$pkg") || fail "build $pkg"
done
WHEELS=("$DIST"/*.whl)
SDISTS=("$DIST"/*.tar.gz)
echo "   ${#WHEELS[@]} wheels, ${#SDISTS[@]} sdists"
[ ${#WHEELS[@]} -eq ${#PACKAGES[@]} ] && [ ${#SDISTS[@]} -eq ${#PACKAGES[@]} ] \
    || fail "expected ${#PACKAGES[@]} wheels and sdists"

# ---- 2. install the wheels only ----------------------------------------------------------------------
echo "== install into a fresh venv outside the repository"
(cd "$WORK" && uv venv -q "$VENV" && uv pip install -q --python "$PY" "${WHEELS[@]}" "jsonschema>=4.18" "pytest>=8") \
    || { fail "install"; exit 1; }
# Every built package is installed (not editable), its modules load from the venv, and no repository
# path is on sys.path (an editable install or a .pth file would put one there).
SCRIPTS="$(run_isolated "$PY" - "$REPO" "$VENV" "${#PACKAGES[@]}" <<'EOF'
import importlib, importlib.metadata as md, json, os, sys
repo, venv, expected = os.path.realpath(sys.argv[1]), os.path.realpath(sys.argv[2]), int(sys.argv[3])
bad = [p for p in sys.path if p and (os.path.realpath(p) + os.sep).startswith(repo + os.sep)]
assert not bad, f"repository paths on sys.path: {bad}"
dists = {d.metadata["Name"]: d for d in md.distributions() if d.metadata["Name"].startswith("aqt-")}
assert len(dists) == expected, f"{len(dists)} aqt-* distributions installed, {expected} built: {sorted(dists)}"
for name, dist in sorted(dists.items()):
    origin = json.loads(dist.read_text("direct_url.json") or "{}")
    assert not origin.get("dir_info", {}).get("editable"), f"{name} is an editable install"
    for ep in dist.entry_points:
        if ep.group == "console_scripts":
            module = importlib.import_module(ep.module.split(".")[0])
            where = os.path.realpath(module.__file__)
            assert where.startswith(venv + os.sep), f"{module.__name__} imported from {where}"
            print(ep.name)
EOF
)" || { fail "installed packages"; exit 1; }
echo "   $(echo "$SCRIPTS" | wc -l) console scripts, all modules load from the venv"

# ---- 3. run the installed tools from outside the checkout ---------------------------------------------
echo "== console scripts --help"
for script in $SCRIPTS; do
    if out="$(run_isolated "$VENV/bin/$script" --help 2>&1)"; then echo "   ok  $script"
    else fail "$script --help"; echo "$out" | tail -10; fi
done

echo "== aqt-evidence vectors"
if out="$(run_isolated "$VENV/bin/aqt-evidence" vectors 2>&1)"; then echo "   ok  $out"
else fail "aqt-evidence vectors"; echo "$out" | tail -10; fi

echo "== aqt status --json"
if [ -x "$VENV/bin/aqt" ]; then
    # Exit 0 (ready) or 1 (problems found, which a fresh environment may have); JSON either way.
    out="$(run_isolated "$VENV/bin/aqt" status --json 2>"$WORK/status.err")"; code=$?
    if [ "$code" -le 1 ] && printf '%s' "$out" | "$PY" -c 'import json, sys; json.load(sys.stdin)' 2>/dev/null; then
        echo "   ok  exit $code, valid JSON"
    else fail "aqt status --json (exit $code)"; echo "$out" | tail -10; tail -10 "$WORK/status.err"; fi
else
    echo "   skipped: no aqt command (the aqt-cli package is not in this checkout yet)"
fi

echo "== integration demo from a copy of examples/demo"
mkdir -p "$WORK/demo"
cp "$REPO/examples/demo/run_demo.py" "$REPO/examples/demo/test_demo.py" "$WORK/demo/"
if out="$(cd "$WORK/demo" && run_isolated "$PY" -m pytest -q -p no:cacheprovider --rootdir "$WORK/demo" \
        "$WORK/demo/test_demo.py" 2>&1)"; then echo "   ok  $(echo "$out" | tail -1)"
else fail "integration demo"; echo "$out" | tail -40; fi

echo
[ "$STATUS" -eq 0 ] && echo "clean install: all checks passed" || echo "clean install: FAILED"
exit $STATUS
