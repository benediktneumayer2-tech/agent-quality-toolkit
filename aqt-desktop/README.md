# aqt-desktop

The Agent Quality Toolkit as a desktop app: one window with the aqt-ui pages, and no web server.

- **Window:** a [Tauri 2](https://tauri.app) shell (Rust, the system's webview) shows the pages from
  `aqt-ui/src/aqt_ui/static/`. They are the same files `aqt ui` serves to a browser, without a fork.
- **Core:** the window starts the AQT core (`aqt core --stdio`) as its child process. The core answers the
  page's API requests as JSON lines over stdin and stdout; nothing listens on a port. The protocol is described
  in `aqt-ui/src/aqt_ui/core.py`.
- **Runtime:** a bundle ships a frozen Python 3.12 with all eleven packages (PyInstaller, one folder). It is
  also the full `aqt` command, at `runtime/aqt/aqt` inside the installed app.

Builds are unsigned for now. Only Linux (AppImage and .deb) is built so far.

## How it fits together

- **The page** (`app.js`) checks for the app's IPC. In the app it sends each request through the one command
  `core_request`, and takes the session information from the core's ready event (`core_session`). In a browser
  it uses `fetch` as before. Downloads are saved with the system's save dialog (`save_file`); connecting a
  project opens the system's folder dialog (`pick_folder`), and a browser shows a path field instead.
- **Routing:** the page keeps its pathname routes (`/case/...`, `/change/...`). In the app, Tauri answers
  unknown paths with `index.html`, so a reload stays on the page.
- **Security:**
  - the window may call only these five commands: the three above, `desktop_settings` and `pick_folder`
    (`src-tauri/capabilities/main.json`);
  - a strict Content-Security-Policy allows no inline code and no remote content
    (`scripts/sync-frontend.mjs` refuses inline code in the HTML);
  - the window cannot navigate to another origin; http(s) links open in the system browser.
- **The core** stays the guard: started from an agent session, it comes up read-only.
- **The core command** is, in this order:
  1. the runtime shipped with the app;
  2. `AQT_CORE`, a command line split on spaces, e.g. `AQT_CORE="/path/to/aqt core --stdio"`;
  3. `aqt core --stdio` from `PATH`.

  If the core stops, it is restarted once. If it stops again, the page shows the error. The app's own
  `--read-only` is passed on to the core. The tray, the count and the notifications go on after a restart: the
  new core's first `queue` event sets the count again and announces nothing.

## In the operating system

- **The queue.** While it runs, the core looks at the "Needs you" queue every 5 s (`AQT_CORE_QUEUE_SECONDS`;
  0 turns it off). It uses the overview's own data and does not verify the trail again. When the queue changes it
  sends `{"event":"queue","body":{"count":n,"new":[{"id","title","kind"}],"removed":["<id>"]}}`; the first such
  event after a start only carries the count.
- **Tray or menu-bar icon** with the number of open cases (the label beside the icon on Linux, the text in the
  macOS menu bar, the tooltip on Windows). Its menu: *Open*, *Needs you (n)*, *Quit*. Closing the window keeps
  the app running there; the setting `close_to_tray: false` makes closing quit instead.
- **Notifications:** one per new case ("Quarantine holds content from example.com"), or one for all of them
  when four or more arrive at once. A click opens that case (or *Needs you*). The page words them in its
  language: the app hands it the queue event (`window.aqtQueue`) and it answers with `show_notifications`.
  Before the page has loaded, or if it does not answer within 3 s, the core's English words are used.
- **Links** `aqt://case/<id>` (e.g. `aqt://case/quarantine:Q7SEGGW`) and `aqt://change/<project>/<plan>` open
  that view. They only navigate; every decision still needs the signing sheet and the passphrase. Other links
  are ignored. A second start of the app brings the running window to the front and hands it its link.
  `aqt open <case-or-link>` opens one through the system (`xdg-open`, `open`, `start`), and the quarantine's
  hold notice names the link of its case.
- **Start at login** with `--hidden`: only the tray icon, no window. When no tray icon can show within 10 s,
  the window opens instead.
- **The `aqt` command** is the bundled runtime, the same program as the core:
  - the .deb installs `/usr/bin/aqt` and `/usr/bin/aqt-toolkit`, links to
    `/usr/lib/Agent Quality Toolkit/runtime/aqt/aqt`;
  - the AppImage runs it as `AppImage --cli ARGS`, or when it is called through a link named `aqt` or
    `aqt-toolkit` (Settings: install the aqt command makes both in `~/.local/bin`; a name already taken there,
    e.g. by an `aqt` from pip or uv, is never replaced).

  `aqt project init` writes hooks that call `aqt <tool> ...` from `PATH`, never a path inside the app. When the
  first `aqt` on `PATH` is another program (aqtinstall's), they call `aqt-toolkit <tool> ...` instead.
  `aqt status` reports which AQT command agents run (the `command` check).

**The page's commands** besides the three of the core: `show_notifications(seq, words)` (above; it can only
word the cases the core reported) and `desktop_settings`, which answers
`{close_to_tray, tray, autostart, appimage, aqt_command, links}`. Called with `{"change": {...}}` it first applies
`close_to_tray` and `autostart` (true or false), and `aqt_command: true` or `links: true` (AppImage only: make
`~/.local/bin/aqt`, register `aqt://`). `tray` says whether a tray icon shows now; `aqt_command` is null outside
an AppImage, where there is nothing to install. The settings are kept in `desktop.json` in the app's config folder
(`~/.config/io.github.benediktneumayer2tech.aqt/` on Linux). Onboarding's last step turns `autostart` on.

**Platform limits** (Linux checked under Xvfb on a private D-Bus session with stand-in notification and tray
services; macOS and Windows not run yet):

- **Linux tray:** the icon is an AppIndicator (libayatana-appindicator, which the .deb depends on and the
  AppImage carries). It shows only where the desktop runs a StatusNotifierWatcher: KDE, Xfce, Cinnamon, GNOME
  with the AppIndicator extension (Ubuntu's default session has it). GNOME without the extension shows no tray:
  the app then has none, and closing the window quits it, so it never runs invisibly. AppIndicators report no
  clicks on the icon itself; the menu opens the window.
- **Notification clicks:** on Linux the click is the notification's default action, which notification
  servers report (GNOME, KDE, dunst, ...). On Windows the toast's activation is handled the same way, not
  tested yet. On macOS a click only brings the app to the front; the case is in *Needs you* and the count.
- **AppImage links:** the AppImage registers nothing by itself. Settings: register `aqt://` links writes a
  handler entry to `~/.local/share/applications` and makes it the default with `xdg-mime`; if the AppImage
  moves, register again. Desktops open the link through `gio`/`kde-open`; plain `xdg-open` without a known
  desktop cannot run that entry's quoted command line.
- **AppImage start at login:** the autostart entry names the AppImage file without quotes, so it fails for a
  path with spaces; keep the AppImage in a folder without spaces.
- **AppImage `aqt` speed:** each call mounts the AppImage and runs its start script first (here 0.16 s for
  `aqt --version`, against 0.07 s through the .deb's `/usr/bin/aqt`); agent hooks run on every tool call, so
  the .deb is the better choice for heavy use.

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

## Smoke test

`--smoke` (or `AQT_DESKTOP_SMOKE=1`) makes the app:

1. wait for the core's ready event;
2. make one request (`GET /api/overview`);
3. wait until the page itself got an answer from the core;
4. print one JSON line and exit 0 (ok) or 1.

The JSON line holds the timings in ms since start (`core_ready_ms`, `first_response_ms`, `window_ms` for the
page load, `page_ms` for the page's first answer) and the core's `mode`.

`scripts/smoke.sh` runs it under `xvfb-run`, never on your display, with throw-away HOME and XDG folders and
its own D-Bus session (`dbus-run-session`), so it reaches neither a running AQT app nor your desktop's tray and
notifications. For a bundle it then runs the bundle's `aqt --version` and `aqt status --json` (the .deb's
`usr/bin/aqt`, the AppImage's `--cli`):

```bash
aqt-desktop/scripts/smoke.sh --appimage aqt-desktop/dist/aqt-desktop_*.AppImage
aqt-desktop/scripts/smoke.sh --deb aqt-desktop/dist/aqt-desktop_*.deb
AQT_CORE="$PWD/aqt-desktop/core/dist/aqt/aqt core --stdio" \
  aqt-desktop/scripts/smoke.sh aqt-desktop/src-tauri/target/debug/aqt-desktop
```

`SMOKE_RUNS=3` repeats it in the same HOME: the first run is cold, the others are warm.

CI (`.github/workflows/desktop.yml`) builds both bundles, smoke-tests each of them, and uploads them as the
artifact `aqt-desktop-linux`.
