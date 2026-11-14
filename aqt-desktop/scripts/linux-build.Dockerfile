# Build image for the Linux app (scripts/build-linux.sh): Ubuntu 24.04 with the Tauri 2 build dependencies,
# Rust, Node (for the Tauri CLI) and uv (for the frozen Python runtime). Caches live in a named volume (/cache).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev libxdo-dev \
      build-essential curl wget file patchelf ca-certificates xdg-utils nodejs npm \
 && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | CARGO_HOME=/opt/cargo sh -s -- -y --no-modify-path --profile minimal --component clippy --default-toolchain 1.98.1 \
 && chmod -R a+rX /opt/rustup /opt/cargo
COPY --from=ghcr.io/astral-sh/uv:0.12.10 /uv /uvx /usr/local/bin/
# A new named volume takes this folder's mode, so the build user (the caller's uid) can write to it.
RUN mkdir -m 1777 /cache
