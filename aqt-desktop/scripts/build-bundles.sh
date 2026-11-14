#!/usr/bin/env bash
# Build the app on Ubuntu 24.04 with the Tauri build dependencies installed (the container of
# build-linux.sh, or the CI runner): the frozen runtime (core/build.sh), then the AppImage and .deb,
# copied to dist/ as aqt-desktop_<version>_<arch>.{AppImage,deb}.
# On Windows (Git Bash, as on the CI runner): the NSIS installer instead (tauri.windows.conf.json),
# copied to dist/ as aqt-desktop_<version>_x64-setup.exe.
# --debug: only the debug binary, without the runtime and bundles.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
npm ci --no-audit --no-fund --loglevel=error
if [ "${1:-}" = "--debug" ]; then
    npx tauri build --debug --no-bundle
    exit 0
fi
bash core/build.sh
npx tauri build --config src-tauri/tauri.bundle.conf.json
VERSION="$(node -p 'require("./src-tauri/tauri.conf.json").version')"
PRODUCT="$(node -p 'require("./src-tauri/tauri.conf.json").productName')"
mkdir -p dist
rm -f dist/aqt-desktop_*
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        # the installer puts the runtime's folder (aqt.exe, aqt-toolkit.exe) on the user's PATH itself
        cp src-tauri/target/release/bundle/nsis/*-setup.exe "dist/aqt-desktop_${VERSION}_x64-setup.exe" ;;
    *)
        cp src-tauri/target/release/bundle/appimage/*.AppImage "dist/aqt-desktop_${VERSION}_amd64.AppImage"
        # the .deb gets /usr/bin/aqt and /usr/bin/aqt-toolkit (its second name, where another aqt comes first on PATH):
        # relative links to the bundled runtime, so agents and terminals find the command (Tauri's deb "files" would
        # copy the program, which then misses its _internal folder)
        PKG="$(mktemp -d)"
        trap 'rm -rf "$PKG"' EXIT
        dpkg-deb -R src-tauri/target/release/bundle/deb/*.deb "$PKG/root"
        ln -s "../lib/$PRODUCT/runtime/aqt/aqt" "$PKG/root/usr/bin/aqt"
        ln -s "../lib/$PRODUCT/runtime/aqt/aqt" "$PKG/root/usr/bin/aqt-toolkit"
        dpkg-deb --root-owner-group -b "$PKG/root" "dist/aqt-desktop_${VERSION}_amd64.deb" >/dev/null
        ;;
esac
ls -l dist/
