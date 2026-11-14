#!/usr/bin/env bash
# Freeze the AQT runtime with PyInstaller (onedir): Python 3.12 and all eleven packages from this repository
# (aqt-cli with the [egress] extra), installed as wheels. Output: aqt-desktop/core/dist/aqt/aqt (aqt.exe and the
# console-less aqtw.exe on Windows, where it runs in Git Bash).
# Needs uv and network access for the third-party packages. Then: a few smoke commands against a temp HOME.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VENV="$HERE/build/venv"
BIN=bin EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) BIN=Scripts EXE=.exe ;; esac
export UV_PYTHON_PREFERENCE=only-managed      # uv's Python 3.12, the same on every machine

rm -rf "$VENV" "$HERE/dist"
uv venv -q --python 3.12 "$VENV"
# --no-sources: the packages' [tool.uv.sources] would install the siblings editable (without packaged data)
uv pip install -q --python "$VENV/$BIN/python$EXE" --no-sources "pyinstaller==6.22.3" \
    "$REPO/aqt-spec[schema]" "$REPO/aqt-trail" "$REPO/aqt-signoff" "$REPO/aqt-change" "$REPO/aqt-sensei" \
    "$REPO/aqt-quarantine" "$REPO/aqt-validate" "$REPO/aqt-capa" "$REPO/aqt-ui" "$REPO/aqt-egress" \
    "$REPO/aqt-cli[egress]"
(cd "$HERE" && "$VENV/$BIN/pyinstaller$EXE" --noconfirm --clean --log-level WARN \
    --distpath "$HERE/dist" --workpath "$HERE/build/work" aqt.spec)

# smoke: the program starts, every tool answers --help, the status reads a fresh (temp) HOME
AQT="$HERE/dist/aqt/aqt$EXE"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
WINDOWS_HOME=()     # Windows takes the home and the AQT folders from these
[ -n "$EXE" ] && WINDOWS_HOME=(USERPROFILE="$(cygpath -w "$SANDBOX/home")" APPDATA="$(cygpath -w "$SANDBOX/appdata")"
                               LOCALAPPDATA="$(cygpath -w "$SANDBOX/localappdata")")
isolated() { env -u PYTHONPATH -u PYTHONHOME HOME="$SANDBOX/home" XDG_CONFIG_HOME="$SANDBOX/config" \
    XDG_STATE_HOME="$SANDBOX/state" XDG_DATA_HOME="$SANDBOX/data" XDG_CACHE_HOME="$SANDBOX/cache" \
    ${WINDOWS_HOME[@]+"${WINDOWS_HOME[@]}"} "$@"; }
mkdir -p "$SANDBOX/home"
if [ -n "$EXE" ]; then
    for program in aqtw.exe aqt-toolkit.exe; do   # without a console window (the logon task); the second name
        [ -f "$HERE/dist/aqt/$program" ] || { echo "$program is missing from the runtime" >&2; exit 1; }
    done
    isolated "$HERE/dist/aqt/aqt-toolkit.exe" --version
fi
isolated "$AQT" --version
for tool in trail signoff change sensei quarantine validate capa ui egress evidence; do
    isolated "$AQT" "$tool" --help >/dev/null || { echo "aqt $tool --help failed" >&2; exit 1; }
done
isolated "$AQT" evidence vectors >/dev/null
isolated "$AQT" -m aqt_trail.cli --help >/dev/null
# exit 0 (ready) or 1 (problems, as a fresh HOME has them), valid JSON either way
code=0; isolated "$AQT" status --json >"$SANDBOX/status.json" || code=$?
[ "$code" -le 1 ] && "$VENV/$BIN/python$EXE" -c 'import json, sys; json.load(open(sys.argv[1]))' "$SANDBOX/status.json" \
    || { echo "aqt status --json failed (exit $code)" >&2; exit 1; }
echo "frozen runtime ok: $(du -sh "$HERE/dist/aqt" | cut -f1) in $HERE/dist/aqt"
