# aqt-desktop

The Agent Quality Toolkit as a desktop app: one window with the aqt-ui pages, and no web server.

- **Window:** a [Tauri 2](https://tauri.app) shell (Rust, the system's webview) shows the pages from
  `aqt-ui/src/aqt_ui/static/`. They are the same files `aqt ui` serves to a browser, without a fork.
- **Core:** the window starts the AQT core (`aqt core --stdio`) as its child process. The core answers the
  page's API requests as JSON lines over stdin and stdout; nothing listens on a port. The protocol is described
  in `aqt-ui/src/aqt_ui/core.py`.
- **Runtime:** a bundle ships a frozen Python 3.12 with all eleven packages (PyInstaller, one folder). It is
  also the full `aqt` command, at `runtime/aqt/aqt` inside the installed app.

Builds are unsigned for now: Linux (AppImage and .deb) and macOS (.dmg for Apple silicon and Intel, ad-hoc
signed; see [Install on macOS](#install-on-macos) for the first start).

## How it fits together

- **The page** (`app.js`) checks for the app's IPC. In the app it sends each request through the one command
  `core_request`, and takes the session information from the core's ready event (`core_session`). In a browser
  it uses `fetch` as before. Downloads are saved with the system's save dialog (`save_file`); connecting a
  project opens the system's folder dialog (`pick_folder`), and a browser shows a path field instead.
- **Routing:** the page keeps its pathname routes (`/case/...`, `/change/...`). In the app, Tauri answers
  unknown paths with `index.html`, so a reload stays on the page.
- **Security:**
  - the window may call only these commands: the three above, `desktop_settings`, `show_notifications`,
    `pick_folder`, `machines` and `updates` (`src-tauri/capabilities/main.json`);
  - a strict Content-Security-Policy allows no inline code and no remote content
    (`scripts/sync-frontend.mjs` refuses inline code in the HTML);
  - the window cannot navigate to another origin; http(s) links open in the system browser.
- **The core** stays the guard: started from an agent session, it comes up read-only.
- **The core command** is, in this order:
  1. the runtime shipped with the app;
  2. `AQT_CORE`, a command line split on spaces, e.g. `AQT_CORE="/path/to/aqt core --stdio"`;
  3. `aqt core --stdio` from `PATH`.

  On another machine the core is started over SSH (below). If the core stops, it is restarted once. If it
  stops again, the page shows why, with a button to start it again. The app's own
  `--read-only` is passed on to the core. The tray, the count and the notifications go on after a restart: the
  new core's first `queue` event sets the count again and announces nothing.

## In the operating system

- **The queue.** While it runs, the core looks at the "Needs you" queue every 5 s (`AQT_CORE_QUEUE_SECONDS`;
  0 turns it off). It uses the overview's own data and does not verify the trail again. When the queue changes it
  sends `{"event":"queue","body":{"count":n,"new":[{"id","title","kind"}],"removed":["<id>"]}}`; the first such
  event after a start only carries the count.
- **Tray or menu-bar icon** with the number of open cases (the label beside the icon on Linux, the text in the
  macOS menu bar, the tooltip on Windows). Its menu: *Open window*, *Needs you (n)*, *Quit*, in the page's
  language once the page has loaded (it sends the words with `desktop_settings`, `menu`), English before.
  Closing the window keeps the app running there; the setting `close_to_tray: false` makes closing quit instead.
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

  - on macOS it is `Contents/Resources/runtime/aqt/aqt` inside the app. Settings: *Install 'aqt' command* links
    `/usr/local/bin/aqt` and `/usr/local/bin/aqt-toolkit` to it (on the `PATH` of every macOS shell, so agents'
    hooks find it), through macOS's administrator prompt, as editors install their command. A name taken by
    another program is never replaced; a link to an AQT app that moved is renewed.

  `aqt project init` writes hooks that call `aqt <tool> ...` from `PATH`, never a path inside the app. When the
  first `aqt` on `PATH` is another program (aqtinstall's), they call `aqt-toolkit <tool> ...` instead. The texts
  agents read name the commands the same way (the agent-instruction block, the hook messages, aqt-change's
  refusals): never `aqt-<tool>`, which the app's runtime does not have.
  `aqt status` reports which AQT command agents run (the `command` check).

**The page's commands** besides the three of the core: `machines` (below), `show_notifications(seq, words)` (above; it can only
word the cases the core reported) and `desktop_settings`, which answers
`{close_to_tray, tray, autostart, appimage, aqt_command, links}`. Called with `{"change": {...}}` it first applies
`close_to_tray` and `autostart` (true or false), `aqt_command: true` or `links: true` (AppImage only: make
`~/.local/bin/aqt`, register `aqt://`), and `menu` (`{"open", "needs", "quit"}`, `needs` with `{n}`: the tray
menu's words). `tray` says whether a tray icon shows now; `aqt_command` is null outside
an AppImage, where there is nothing to install. The settings are kept in `desktop.json` in the app's config folder
(`~/.config/io.github.benediktneumayer2tech.aqt/` on Linux). Onboarding's last step turns `autostart` on.

## Another machine over SSH

The window can show the AQT of another machine, e.g. the server where the agents run: the app starts the core
there with `ssh <destination> aqt core --stdio`. There is no tunnel, no port and no web page; the protocol is
the same.

- **Machines** are kept under Settings, *This app*, *Machines*: *This computer* and entries with a name and an
  SSH destination (`user@host`, or a `Host` from `~/.ssh/config`). *Test connection* shows the AQT version
  there, the command found and whether decisions are on. The list holds no secrets: `machines` and `machine` in
  `desktop.json`. The page's command `machines` lists them and can `add`, `remove`, `select`, `reconnect` and
  `test`.
- **The window always shows the machine it is on:** the top bar has a choice of machine once there is one
  besides this computer, and so does the first-run setup's header. The rail and the window title name a remote
  machine. Choosing another machine stops the core and starts it there; the page then loads its data again.
- **ssh** is the system's OpenSSH (built into Windows 10 and 11), with the user's config, keys and agent. The app
  adds `-T -a -x`, `BatchMode=yes` (never a password or passphrase prompt: a key with a passphrase works
  through the ssh-agent), `ConnectTimeout=15`, `ServerAliveInterval=15` with `ServerAliveCountMax=3`,
  `ClearAllForwardings=yes` and, outside Windows, `ControlPath=none`. Host keys are checked as the user's ssh
  checks them: an unknown host is refused, with the command to run once in a terminal (`ssh <destination>`).
  The destination follows `--` and can never be an option. Nothing passes through a local shell, and the line
  run on the other machine is fixed. `AQT_SSH` sets the ssh command line, split on spaces like `AQT_CORE`.
- **The command there** is found with one probe in one connection: `aqt` when it is AQT's, else `aqt-toolkit`
  (where aqtinstall's `aqt` comes first), else `~/.local/bin/aqt-toolkit`. That last one is the link the
  install makes, and an SSH command often lacks it on its `PATH`: on Ubuntu only a login shell adds
  `~/.local/bin`. The app's `--read-only` is passed on.
- **The guard** is the remote core's. Started by `sshd`, it sees no agent among its ancestors, so a person at
  the app can decide. Each decision asks for the passphrase of the signing key on that machine, which travels
  there through the SSH connection.
- **States:**
  - an unreachable host or a lost connection keeps the last data greyed, with *Reconnect* and *Use this
    computer*;
  - a machine without AQT gets the install hint, with the command that shows what an SSH command finds there;
  - a refused key gets the list of what to check;
  - a lost connection is started again once by itself.

  A request that was sent and got no answer is never sent again: the signing sheet says the outcome is unknown
  and offers a reload.
- **The queue and notifications** come from the chosen machine. Notifications and the tray's tooltip name it.
- **Files:** downloads are saved on this computer. The folder dialog shows this computer's folders, so for
  another machine Projects asks for the path there, as the browser page does.

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
- **SSH** was checked on Linux against an sshd in a container: the round trip, a queue event and its
  notification, an unknown host, a refused key, an unreachable host, no AQT, a dropped connection, and a
  decision whose connection was lost. The OpenSSH of Windows and macOS has not been run yet. On Windows a key
  with a passphrase needs the *OpenSSH Authentication Agent* service. Agent forwarding is off (`-a`): the remote
  core signs with that machine's own key and needs none.
- **AppImage `aqt` speed:** each call mounts the AppImage and runs its start script first (here 0.16 s for
  `aqt --version`, against 0.07 s through the .deb's `/usr/bin/aqt`); agent hooks run on every tool call, so
  the .deb is the better choice for heavy use.

## Updates

The app updates itself from the GitHub release (`src-tauri/src/updates.rs`, tauri-plugin-updater), but only in a
build whose `tauri.conf.json` has the owner's public key in `plugins.updater.pubkey`. While it is empty, as now, the
plugin is not loaded and the app never asks; [RELEASING.md](../RELEASING.md#updates-of-the-desktop-app) has the
owner's steps to switch it on.

- **Look:** a minute after start, then once a day, the app reads `latest.json` of the newest release
  (`releases/latest/download/latest.json`). A newer version only shows: a dot at *Settings* in the rail and a line
  under *Settings*, *This app*. Nothing is downloaded before the person agrees.
- **Agree:** *Install at next start* downloads the file for this bundle type (`linux-x86_64-appimage`,
  `linux-x86_64-deb`, `darwin-<arch>-app`, `windows-x86_64-nsis`) and checks its minisign signature against the
  public key built into the app, including the version it was signed for (`requireSignedVersion`). It keeps the file
  in the app's cache folder (`update/`) until the next start. *Don't install* drops it.
- **Install:** the next start installs it before the core starts, after checking the signature again: the AppImage
  file is replaced, the .deb goes through `pkexec dpkg -i`, the macOS app bundle is swapped, and on Windows the NSIS
  installer runs and the app ends. Then the new version starts. A failed install is tried once; Settings shows why.
- **The page's command** `updates` answers `{enabled, current}` and, when on, `checked`, `available` (`{version,
  notes}`), `ready` (the version waiting for the next start), `busy`, `error` and `failed`. `{"change": {"install":
  "<version>"}}` agrees, `{"change": {"cancel": true}}` drops it. The app also hands each check's result to the
  page (`window.aqtUpdate`).

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

## Build (macOS)

You need Xcode's command line tools, Rust, Node and uv.

```bash
aqt-desktop/scripts/build-macos.sh        # .dmg (and .app.tar.gz, the update) for this Mac's architecture in aqt-desktop/dist/
aqt-desktop/scripts/build-macos.sh --app  # only the .app (the .dmg's layout step talks to the Finder)
```

The app is ad-hoc signed (`src-tauri/tauri.macos.conf.json`: Apple silicon runs no unsigned code), and the script
checks that signature with `codesign --verify --deep --strict`; the frozen runtime inside is signed by PyInstaller.
CI (the `macos` job of `.github/workflows/desktop.yml`) builds it on `macos-15` (Apple silicon) and
`macos-15-intel` (Intel), runs the smoke test on the app taken out of the .dmg, and uploads the .dmg and the
.app.tar.gz files as the artifacts `aqt-desktop-macos-arm64` and `aqt-desktop-macos-x86_64`.

## Install on macOS

The app is not signed with an Apple Developer ID and not notarized, so macOS blocks its first start. On macOS 15
(Sequoia) and later:

1. Open the .dmg and drag *Agent Quality Toolkit* into *Applications*.
2. Open the app. macOS says that it cannot check the app for malware; click *Done* (not *Move to Trash*).
3. Open *System Settings → Privacy & Security*, scroll to *Security*: next to "Agent Quality Toolkit was blocked
   to protect your Mac" click *Open Anyway*, then confirm with your password or Touch ID and click *Open*.

Later starts open normally. On macOS 14 and earlier, Control-click the app in *Applications*, choose *Open*, then
*Open* again. Each new version needs this once more.

Start the app from where it lies (*Applications*, or the opened .dmg), not through a path with a symbolic link:
Tauri then finds no bundled runtime (the window says that the AQT core could not start).

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

On macOS, `scripts/smoke.sh --dmg aqt-desktop/dist/aqt-desktop_*.dmg` copies the app out of the disk image and runs it
in the login session (there is no Xvfb), then the runtime's `aqt` inside the app. CI runs it on the runner; do not
run it on a Mac someone is using, because the window opens on its screen.

CI (`.github/workflows/desktop.yml`) builds both bundles, smoke-tests each of them, and uploads them as the
artifact `aqt-desktop-linux`.

## Releases

The release workflow (`.github/workflows/release.yml`) calls `desktop.yml` and attaches every `aqt-desktop-*`
artifact to the GitHub release, with `SHA256SUMS` and, once the updater key is set up, the signed `latest.json`
(`scripts/desktop_release.py`). A new platform job in `desktop.yml` that uploads an `aqt-desktop-<platform>` artifact
is released without a change there. [RELEASING.md](../RELEASING.md) has the steps.
