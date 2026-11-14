#!/usr/bin/env bash
# Smoke test of the app, on Linux always under xvfb-run (never on a real display), with throw-away HOME and XDG
# folders and its own D-Bus session (dbus-run-session), so it can reach neither a running AQT app nor the
# desktop's tray and notifications. That bus starts no services on demand: no desktop portal or accessibility bus
# to wait for (on a desktop machine the portal alone held the window up for 25 s). On macOS (--dmg) it runs in the
# login session (the CI runner's: never on a Mac someone is using), from a copy of the app taken out of the .dmg as
# a person would install it. The app waits for the core's ready event, makes one request (GET /api/overview), waits
# until the page itself got an answer from the core, prints one JSON line with timings and exits 0 (ok) or 1. For a
# bundle, the bundle's aqt command then runs --version and status --json (the .deb's usr/bin/aqt and
# usr/bin/aqt-toolkit, the AppImage's CLI mode, the runtime inside the .app).
#
# Usage: scripts/smoke.sh BINARY               e.g. src-tauri/target/debug/aqt-desktop (core: AQT_CORE or PATH)
#        scripts/smoke.sh --appimage FILE      extracts the AppImage, then runs its AppRun
#        scripts/smoke.sh --deb FILE           extracts the package (dpkg-deb -x), then runs usr/bin/aqt-desktop
#        scripts/smoke.sh --dmg FILE           macOS: copies the .app out of the disk image, then runs it
# SMOKE_RUNS=n runs it n times in the same HOME: the first run is cold (fresh files and HOME), the rest warm.
set -euo pipefail
# the real path: Tauri finds no bundled resources for an app started through a symbolic link, such as macOS's
# /var (-> /private/var), where $TMPDIR lies
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/aqt-smoke-XXXXXX")" && pwd -P)"
# WebKit's helper processes may still write their caches for a moment after the app exits: retry the cleanup.
trap 'for _ in 1 2 3 4 5; do rm -rf "$WORK" 2>/dev/null && break; sleep 1; done' EXIT
AQT=(); AQT2=(); DISPLAY_RUN=(xvfb-run -a -s "-screen 0 1440x900x24")
case "${1:-}" in
    --dmg) hdiutil attach -nobrowse -readonly -mountpoint "$WORK/mnt" "$2" >/dev/null
           app="$(find "$WORK/mnt" -maxdepth 1 -name '*.app' | head -1)"
           ditto "$app" "$WORK/$(basename "$app")"; hdiutil detach "$WORK/mnt" >/dev/null
           app="$WORK/$(basename "$app")"
           APP=("$app/Contents/MacOS/aqt-desktop"); AQT=("$app/Contents/Resources/runtime/aqt/aqt"); DISPLAY_RUN=() ;;
    --appimage) file="$(realpath "$2")"; (cd "$WORK" && "$file" --appimage-extract >/dev/null)
                APP=("$WORK/squashfs-root/AppRun"); AQT=("$WORK/squashfs-root/AppRun" --cli) ;;
    --deb) dpkg-deb -x "$2" "$WORK/deb"; APP=("$WORK/deb/usr/bin/aqt-desktop"); AQT=("$WORK/deb/usr/bin/aqt")
           AQT2=("$WORK/deb/usr/bin/aqt-toolkit") ;;
    "") echo "usage: $0 BINARY | --appimage FILE | --deb FILE | --dmg FILE" >&2; exit 2 ;;
    *) APP=("$(realpath "$1")") ;;
esac
mkdir -p "$WORK"/{home,config,state,data,cache,runtime}
chmod 700 "$WORK/runtime"
isolated() {
    env -u WAYLAND_DISPLAY -u DISPLAY -u DBUS_SESSION_BUS_ADDRESS -u PYTHONPATH -u PYTHONHOME GDK_BACKEND=x11 \
        HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/config" XDG_STATE_HOME="$WORK/state" \
        XDG_DATA_HOME="$WORK/data" XDG_CACHE_HOME="$WORK/cache" XDG_RUNTIME_DIR="$WORK/runtime" "$@"
}
SESSION=()
cat > "$WORK/bus.conf" <<'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>
EOF
command -v dbus-run-session >/dev/null && SESSION=(dbus-run-session --config-file="$WORK/bus.conf" --)
status=0
for _ in $(seq "${SMOKE_RUNS:-1}"); do
    isolated ${SESSION[@]+"${SESSION[@]}"} ${DISPLAY_RUN[@]+"${DISPLAY_RUN[@]}"} "${APP[@]}" --smoke >"$WORK/log" 2>&1 \
        || status=1
    # xvfb-run merges the app's stderr into stdout: the JSON line goes to stdout, the log only on failure
    grep '^{"' "$WORK/log" || true
    [ "$status" -eq 0 ] || { tail -20 "$WORK/log" >&2; break; }
done
if [ "$status" -eq 0 ] && [ "${#AQT[@]}" -gt 0 ]; then
    isolated "${AQT[@]}" --version || status=1
    [ "${#AQT2[@]}" -eq 0 ] || isolated "${AQT2[@]}" --version || status=1       # the second name
    code=0; isolated "${AQT[@]}" status --json >"$WORK/status.json" || code=$?
    # exit 0 (ready) or 1 (problems, as a fresh HOME has them), valid JSON either way
    if [ "$code" -le 1 ] && python3 -c 'import json, sys; print("aqt status --json:", json.load(open(sys.argv[1]))["verdict"])' \
            "$WORK/status.json"; then :; else echo "aqt status --json failed (exit $code)" >&2; status=1; fi
    # it works in the caller's folder (an AppImage's AppRun changes into its own)
    (cd "$WORK/home" && isolated "${AQT[@]}" project status --json >"$WORK/project.json") || true
    python3 -c 'import json, sys; assert json.load(open(sys.argv[1]))["project"] == sys.argv[2]' "$WORK/project.json" \
        "$(realpath "$WORK/home")" || { echo "aqt project status did not run in the caller's folder" >&2; status=1; }
fi
exit "$status"
