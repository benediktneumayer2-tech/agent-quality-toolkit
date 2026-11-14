# aqt-desktop

The Agent Quality Toolkit as a desktop app: one window with the aqt-ui pages, and no web server.

- **Window:** a [Tauri 2](https://tauri.app) shell (Rust, the system's webview) shows the pages from
  `aqt-ui/src/aqt_ui/static/`. They are the same files `aqt ui` serves to a browser, without a fork.
- **Core:** the window starts the AQT core (`aqt core --stdio`) as its child process. The core answers the
  page's API requests as JSON lines over stdin and stdout; nothing listens on a port. The protocol is described
  in `aqt-ui/src/aqt_ui/core.py`.
- **Runtime:** a bundle ships a frozen Python 3.12 with all eleven packages (PyInstaller, one folder). It is
  also the full `aqt` command, at `runtime/aqt/aqt` inside the installed app.

Builds are unsigned for now: Linux (AppImage and .deb) and Windows (a per-user NSIS installer).

## How it fits together

- **The page** (`app.js`) checks for the app's IPC. In the app it sends each request through the one command
  `core_request`, and takes the session information from the core's ready event (`core_session`). In a browser
  it uses `fetch` as before. Downloads are saved with the system's save dialog (`save_file`).
- **Routing:** the page keeps its pathname routes (`/case/...`, `/change/...`). In the app, Tauri answers
  unknown paths with `index.html`, so a reload stays on the page.
- **Security:**
  - the window may call only those three commands (`src-tauri/capabilities/main.json`);
  - a strict Content-Security-Policy allows no inline code and no remote content
    (`scripts/sync-frontend.mjs` refuses inline code in the HTML);
  - the window cannot navigate to another origin; http(s) links open in the system browser.
- **The core** stays the guard: started from an agent session, it comes up read-only.
- **The core command** is, in this order:
  1. the runtime shipped with the app;
  2. `AQT_CORE`, a command line split on spaces, e.g. `AQT_CORE="/path/to/aqt core --stdio"`;
  3. `aqt core --stdio` from `PATH`.

  If the core stops, it is restarted once. If it stops again, the page shows the error. The app's own
  `--read-only` is passed on to the core.

## Build (Linux)

You need Docker. No sudo, and no `-dev` packages on the host.

```bash
aqt-desktop/scripts/build-linux.sh           # AppImage and .deb in aqt-desktop/dist/
aqt-desktop/scripts/build-linux.sh --debug   # only src-tauri/target/debug/aqt-desktop
```

The build runs in a throw-away Ubuntu 24.04 container (`scripts/linux-build.Dockerfile`) as your user. The
cargo, uv, npm and AppImage-tool caches stay in the Docker volume `aqt-desktop-cache`.

On an Ubuntu 24.04 machine with the Tauri build dependencies installed, as in CI, `scripts/build-bundles.sh`
does the same without Docker. The frozen runtime alone is `core/build.sh`. It needs only uv, and it checks
the result: `aqt --version`, every tool's `--help`, and `aqt status --json` against a temp HOME.

## Build and install (Windows)

CI builds the installer on a Windows runner (`.github/workflows/desktop.yml`, job `windows`): in Git Bash,
`scripts/build-bundles.sh` freezes the runtime and runs the NSIS bundler (`src-tauri/tauri.windows.conf.json`).
The result is `dist/aqt-desktop_<version>_x64-setup.exe`, the artifact `aqt-desktop-windows`.

- **Per user, no administrator rights:** the installer goes to the user's own programs folder and has its own
  uninstaller (Settings > Apps). It is unsigned, so SmartScreen warns on the first start ("More info", "Run anyway").
- **The `aqt` command:** the installer puts the folder of the bundled `aqt.exe` (`<install folder>\runtime\aqt`) on
  the user's `PATH` and the uninstaller takes it off (`src-tauri/windows/installer-hooks.nsh`). New terminals find
  `aqt`, PowerShell, cmd and Git Bash alike; the folder holds only `aqt.exe`, `aqtw.exe` (the same program without
  a console window, for the writer's logon task) and `_internal\`.
- **Not available on Windows** (owner decision D2): the sensei sandbox and the egress box, which need Linux
  (bubblewrap); `aqt status`, `aqt-sensei` and `aqt-egress` say so. Everything else runs natively.

`scripts/smoke-windows.ps1` (CI only: it installs and uninstalls the app and opens its window) installs the
installer silently, checks `aqt` from the `PATH` entry and Claude Code hook commands through Git Bash, runs
`--smoke`, and checks that the uninstaller removes the app and the `PATH` entry.

## Smoke test

`--smoke` (or `AQT_DESKTOP_SMOKE=1`) makes the app:

1. wait for the core's ready event;
2. make one request (`GET /api/overview`);
3. wait until the page itself got an answer from the core;
4. print one JSON line and exit 0 (ok) or 1.

The JSON line holds the timings in ms since start (`core_ready_ms`, `first_response_ms`, `window_ms` for the
page load, `page_ms` for the page's first answer) and the core's `mode`.

`scripts/smoke.sh` runs it under `xvfb-run`, never on your display, with throw-away HOME and XDG folders:

```bash
aqt-desktop/scripts/smoke.sh --appimage aqt-desktop/dist/aqt-desktop_*.AppImage
aqt-desktop/scripts/smoke.sh --deb aqt-desktop/dist/aqt-desktop_*.deb
AQT_CORE="$PWD/aqt-desktop/core/dist/aqt/aqt core --stdio" \
  aqt-desktop/scripts/smoke.sh aqt-desktop/src-tauri/target/debug/aqt-desktop
```

`SMOKE_RUNS=3` repeats it in the same HOME: the first run is cold, the others are warm.

CI (`.github/workflows/desktop.yml`) builds both Linux bundles, smoke-tests each of them, and uploads them as the
artifact `aqt-desktop-linux`; the Windows job does the same for the installer (`aqt-desktop-windows`).
