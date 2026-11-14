#!/usr/bin/env bash
# Build the app on macOS (the CI runner, or a Mac with Xcode's command line tools, Rust, Node and uv): the frozen
# runtime (core/build.sh), then the .app and the .dmg for this machine's architecture, copied to dist/ as
# aqt-desktop_<version>_<arch>.dmg, and the .app as aqt-desktop_<version>_<arch>.app.tar.gz, the archive the app
# updates itself from (the release signs it and lists it in latest.json). Unsigned for now: the app is ad-hoc
# signed (Apple silicon runs no unsigned code); src-tauri/tauri.macos.conf.json sets that. --app: only the .app
# (no .dmg, whose layout step talks to the Finder).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
npm ci --no-audit --no-fund --loglevel=error
bash core/build.sh
rm -rf src-tauri/target/release/bundle   # a cached target keeps the last version's bundles, which the globs below would match
BUNDLES=app,dmg
[ "${1:-}" = "--app" ] && BUNDLES=app
npx tauri build --config src-tauri/tauri.bundle.conf.json --bundles "$BUNDLES"
VERSION="$(node -p 'require("./src-tauri/tauri.conf.json").version')"
PRODUCT="$(node -p 'require("./src-tauri/tauri.conf.json").productName')"
ARCH="$(uname -m)"                                  # arm64 or x86_64
APP="src-tauri/target/release/bundle/macos/$PRODUCT.app"
# the signature covers the app and the runtime inside it (PyInstaller signs each of its binaries ad hoc)
codesign --verify --deep --strict "$APP"
codesign -dv "$APP" 2>&1 | grep -q "Signature=adhoc" || { echo "the app is not ad-hoc signed" >&2; exit 1; }
mkdir -p dist
rm -rf dist/aqt-desktop_*
if [ "$BUNDLES" = app ]; then
    ditto "$APP" "dist/aqt-desktop_${VERSION}_${ARCH}.app"
else
    cp src-tauri/target/release/bundle/dmg/*.dmg "dist/aqt-desktop_${VERSION}_${ARCH}.dmg"
    # the update: the .app in a tar.gz, as tauri-plugin-updater unpacks it (no AppleDouble ._ files)
    COPYFILE_DISABLE=1 tar -czf "dist/aqt-desktop_${VERSION}_${ARCH}.app.tar.gz" -C "$(dirname "$APP")" "$PRODUCT.app"
fi
ls -l dist/
