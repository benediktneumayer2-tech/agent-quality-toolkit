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
  - the window may call only these commands: the three above, `desktop_settings`, `show_notifications`,
    `pick_folder` and `machines` (`src-tauri/capabilities/main.json`);
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
- **An app started by an agent never decides, here or there.** The remote guard cannot see who started the app,
  so before the app opens another machine it asks the local Python guard: `aqt core --mode-check`, run like
  its local core (the same command, environment and ancestry), prints the verdict as JSON. When that verdict is
  read-only, or the check cannot run, the remote core is started with `--read-only`, and the page shows the
  read-only banner with the local reason. The app asks once; *Test connection* shows the same mode.
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
notifications. That bus starts no services on demand, so there is no desktop portal to wait for (25 s on a
desktop machine). For a bundle it then runs the bundle's `aqt --version` and `aqt status --json` (the .deb's
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

## SSH end-to-end check (for developers)

`scripts/e2e-ssh.sh` checks "another machine over SSH" against an sshd in a throw-away container
(`scripts/e2e-ssh.Dockerfile`, with AQT installed from the clone's working tree). It does not run in CI. It needs
Docker, `xvfb-run`, `dbus-run-session`, `dbus-monitor`, `ssh`, `ssh-keygen` and `python3`, and takes about three
minutes, most of it the image:

```bash
aqt-desktop/scripts/build-linux.sh --debug
aqt-desktop/scripts/e2e-ssh.sh            # or: e2e-ssh.sh path/to/aqt-desktop
```

It checks:
- the round trip with AQT only in `~/.local/bin` there, with `aqt` on the PATH, and behind aqtinstall's `aqt`;
- the remote mode is the local guard's verdict, and `CLAUDECODE=1` in the app's environment makes it read-only;
- an unknown host, a refused key, an unreachable host and a machine without AQT;
- a queue event whose notification names the machine (seen with `dbus-monitor`);
- a dropped connection that is started again.

It never uses your display, `~/.ssh` or your ssh-agent: ssh runs with its own config (`-F`) and throw-away
keys. The container listens on 127.0.0.1 only and is removed at the end, as are the keys. The local core it
asks is `AQT_CORE`, by default the `aqt-cli/.venv` that `scripts/test_all.sh` creates. Started from an agent
session, the round trip is read-only too, which the check expects.
