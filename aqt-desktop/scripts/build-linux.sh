#!/usr/bin/env bash
# Build the Linux app in a throw-away Ubuntu 24.04 container (no sudo or -dev packages on the host):
# the frozen AQT runtime, then the Tauri bundles. Output: aqt-desktop/dist/ (AppImage and .deb).
#
# Usage: aqt-desktop/scripts/build-linux.sh           the bundles
#        aqt-desktop/scripts/build-linux.sh --debug   only a debug binary (src-tauri/target/debug/aqt-desktop),
#                                                     which takes the core from AQT_CORE or PATH
# Caches (cargo, uv, npm, the AppImage tools) stay in the docker volume aqt-desktop-cache.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
IMAGE=aqt-desktop-build:ubuntu24.04
docker build -q -t "$IMAGE" -f "$HERE/linux-build.Dockerfile" "$HERE" >/dev/null
exec docker run --rm --user "$(id -u):$(id -g)" \
    -v "$REPO:/src" -w /src/aqt-desktop -v aqt-desktop-cache:/cache \
    -e HOME=/cache/home -e CARGO_HOME=/cache/cargo -e XDG_CACHE_HOME=/cache/xdg \
    -e UV_CACHE_DIR=/cache/uv -e UV_PYTHON_INSTALL_DIR=/cache/python -e npm_config_cache=/cache/npm \
    -e APPIMAGE_EXTRACT_AND_RUN=1 \
    "$IMAGE" bash scripts/build-bundles.sh "$@"
