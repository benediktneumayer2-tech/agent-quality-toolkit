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
mkdir -p dist
rm -f dist/aqt-desktop_*
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        cp src-tauri/target/release/bundle/nsis/*-setup.exe "dist/aqt-desktop_${VERSION}_x64-setup.exe" ;;
    *)
        cp src-tauri/target/release/bundle/appimage/*.AppImage "dist/aqt-desktop_${VERSION}_amd64.AppImage"
        cp src-tauri/target/release/bundle/deb/*.deb "dist/aqt-desktop_${VERSION}_amd64.deb" ;;
esac
ls -l dist/
