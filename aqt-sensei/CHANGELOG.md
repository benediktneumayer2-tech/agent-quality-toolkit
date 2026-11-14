# Changelog

## Unreleased

- Windows: `sensei ask` and the owner commands say that the sensei is not available on this system, not that the
  bridge is offline.
- Windows: `aqt-sensei serve` says that the sensei is not available there (its sandbox needs Linux) instead of
  failing on import; the package's other commands load.
- The advisor sandbox on macOS: `sandbox-exec` with a Seatbelt profile generated per pair (`launch`, `login`, `doctor`). The project is read-only, the user folders are refused except the project, the CLI, the private home, the scratch folder and the pair's runtime folder; the keychain is closed; `HOME` is the private home and `TMPDIR` a folder in the scratch folder. `docs/sandbox.md` compares it with the bubblewrap sandbox.
- Runs on macOS except the advisor sandbox: the bridge identifies callers with `LOCAL_PEERCRED` and `sysctl`
  (through `aqt_evidence.platform`). Pairing, `launch`, `login` and `doctor` say that the sandbox is not available
  on this system and why (bubblewrap is Linux only; a Seatbelt profile follows); the fake backend still pairs.
  Linux behaviour is unchanged.
- macOS: a CLI started through a link in a user folder, such as Claude Code's installer's `~/.local/bin/claude`,
  starts in the advisor sandbox (the link was refused). With the keychain closed, Claude Code reads the advisor's
  login from `.credentials.json` in the private home.

## 0.2.0 — 2026-11-13

- Packaging: released at 0.2.0, the version of every AQT package; the other AQT packages it needs are required at `>=0.2,<0.3`; the licence is an SPDX expression with the licence files in the package (PEP 639).
- The bridge notifies the owner (a Herdr notification, or the tmux status line) once when a message starts waiting for approval or forwarding.
- Fix (Herdr): the context digest and `sensei worker-log` were empty, because `herdr pane read --format text` prints the text itself rather than JSON.
- Fix: a worker's pane hint that names no pane of the bridge's host is ignored. Herdr inside tmux passes the outer `TMUX_PANE` to its panes, so `aqt-sensei ask` was refused with "the declared pane does not match the calling process".
- Fix: `data.peer` leaves out `client_time` and unknown process start times instead of writing `null`, as the
  trail's `observed` does; records with a peer now pass the aqt-spec payload schemas.
- Sandbox: runs without `bwrap --new-session`, so the advisor keeps its pane's terminal.

## 0.1.0 — 2026-10-21

First MVP.

- Bridge daemon (`aqt-sensei serve`) with three sockets: owner (uid + token + not a paired pane + terminal), worker (pair derived from the caller's process ancestry) and one advisor socket per pair.
- Modes manual (explicit `forward` only), confirm (approve / edit / discard with reason) and auto, with budgets on messages, exchanges and declared cost, and fallback to confirm.
- tmux backend (bracketed paste; hook-reported or quiet-screen idle detection) and Herdr backend behind one host interface; fake host for tests and demos.
- bubblewrap sandbox from data profiles (claude, codex, pi, custom): project read-only, scratch writable, private agent homes, cleared environment, Herdr report proxy, in-sandbox `sensei` shim.
- `aqt-sensei doctor` probes the exact sandbox; `aqt-sensei login` signs private advisor homes in.
- Advice ledger: `sensei.pair`, `sensei.message`, `sensei.decision`, `sensei.budget`, `sensei.refused` through `aqt_evidence.open_sink()`; record-first owner decisions; local spool for automatic events.
- Persisted open turns; `no-reply` notice when the advisor ends a turn without answering.
