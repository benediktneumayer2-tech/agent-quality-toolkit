#!/usr/bin/env bash
# Run every package's offline test suite (each in its own .venv), then the integration demo test,
# and print a summary table. Missing virtual environments are created with uv
# (SUITE_ARCHITECTURE §1.3). All runs see throw-away HOME and XDG directories, so nothing is
# written to the real ~/.local/state/aqt or ~/.config/aqt.
#
# Usage: scripts/test_all.sh [PACKAGE...]      e.g. scripts/test_all.sh aqt-trail aqt-signoff
# Exit 0 when every suite passed.
set -uo pipefail

SUITE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGES=(aqt-spec aqt-trail aqt-signoff aqt-change aqt-sensei aqt-quarantine aqt-validate aqt-capa)
[ $# -gt 0 ] && PACKAGES=("$@")
REAL_HOME="$HOME"
REAL_DIRS=("$REAL_HOME/.local/state/aqt" "$REAL_HOME/.config/aqt")
declare -A EXISTED
for dir in "${REAL_DIRS[@]}"; do [ -e "$dir" ] && EXISTED[$dir]=1 || EXISTED[$dir]=0; done

command -v uv >/dev/null || { echo "uv is required (https://docs.astral.sh/uv/)" >&2; exit 2; }

ensure_venv() {   # $1 = package directory name
    local pkg="$1" dir="$SUITE/$1"
    [ -x "$dir/.venv/bin/python" ] && return 0
    echo "creating $pkg/.venv with uv"
    local extra=()
    case "$pkg" in
        aqt-spec) ;;
        aqt-validate) extra=(-e ../aqt-spec -e ../aqt-quarantine) ;;   # detector plug-in tests
        *) extra=(-e ../aqt-spec) ;;
    esac
    (cd "$dir" && uv venv -q .venv && uv pip install -q --python .venv/bin/python "${extra[@]}" -e ".[test]")
}

ensure_demo_venv() {
    local py="$SUITE/examples/demo/.venv/bin/python"
    [ -x "$py" ] && return 0
    echo "creating examples/demo/.venv with uv"
    (cd "$SUITE" && uv venv -q examples/demo/.venv && uv pip install -q --python "$py" -e "aqt-spec[schema]" \
        -e aqt-trail -e aqt-signoff -e aqt-change -e aqt-sensei -e aqt-quarantine -e aqt-validate -e aqt-capa pytest)
}

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/aqt-test-all-XXXXXX")"
RUNTIME="$(mktemp -d /tmp/aqtr-XXXXXX)"           # short path: AF_UNIX socket paths are limited
chmod 700 "$RUNTIME"
trap 'rm -rf "$SANDBOX" "$RUNTIME"' EXIT

run_isolated() {  # run a command with throw-away HOME/XDG dirs and without AQT_* overrides
    local name
    local unset_args=()
    for name in $(env | sed -n 's/^\(AQT_[A-Za-z0-9_]*\)=.*/\1/p'); do unset_args+=(-u "$name"); done
    env "${unset_args[@]}" HOME="$SANDBOX/home" XDG_STATE_HOME="$SANDBOX/state" XDG_CONFIG_HOME="$SANDBOX/config" \
        XDG_CACHE_HOME="$SANDBOX/cache" XDG_RUNTIME_DIR="$RUNTIME" TMPDIR="$SANDBOX/tmp" GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL="$SANDBOX/gitconfig" PYTHONDONTWRITEBYTECODE=1 "$@"
}

count() {  # $1 = word, $2 = pytest summary line
    echo "$2" | grep -oE "[0-9]+ $1" | head -1 | grep -oE "^[0-9]+" || echo 0
}

ROWS=()
STATUS=0
run_suite() {  # $1 = label, $2 = directory, $3 = python, $4... = pytest args
    local label="$1" dir="$2" py="$3"; shift 3
    mkdir -p "$SANDBOX/home" "$SANDBOX/state" "$SANDBOX/config" "$SANDBOX/tmp"
    local log="$SANDBOX/$label.log" start end
    start=$(date +%s)
    (cd "$dir" && run_isolated "$py" -m pytest -q -p no:cacheprovider "$@") >"$log" 2>&1
    local code=$?
    end=$(date +%s)
    local line
    line=$(grep -E "(passed|failed|error|no tests ran)" "$log" | tail -1)
    local passed failed errors skipped
    passed=$(count passed "$line"); failed=$(count failed "$line")
    errors=$(count error "$line"); skipped=$(count skipped "$line")
    local result="ok"
    if [ "$code" -ne 0 ]; then
        result="FAIL"; STATUS=1
        echo "---- $label (exit $code), last lines:"; tail -25 "$log"
    fi
    ROWS+=("$(printf '%-16s %7s %7s %7s %7s %6ss  %s' "$label" "$passed" "$failed" "$errors" "$skipped" \
        "$((end - start))" "$result")")
    echo "$label: $result ($line)"
}

for pkg in "${PACKAGES[@]}"; do
    [ -d "$SUITE/$pkg" ] || { echo "no package $pkg" >&2; STATUS=1; continue; }
    ensure_venv "$pkg" || { ROWS+=("$(printf '%-16s %s' "$pkg" "venv setup FAILED")"); STATUS=1; continue; }
    run_suite "$pkg" "$SUITE/$pkg" "$SUITE/$pkg/.venv/bin/python"
done
if [ $# -eq 0 ]; then
    ensure_demo_venv && run_suite "demo" "$SUITE" "$SUITE/examples/demo/.venv/bin/python" examples/demo/test_demo.py
fi

echo
printf '%-16s %7s %7s %7s %7s %7s  %s\n' "suite" "passed" "failed" "errors" "skipped" "time" "result"
printf '%s\n' "${ROWS[@]}"

for dir in "${REAL_DIRS[@]}"; do
    if [ -e "$dir" ] && [ "${EXISTED[$dir]}" = 0 ]; then
        echo "ERROR: $dir was created during the test run" >&2
        STATUS=1
    fi
done
exit $STATUS
