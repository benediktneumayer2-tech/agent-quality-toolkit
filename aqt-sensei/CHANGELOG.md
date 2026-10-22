# Changelog

## 0.1.0 — 2026-10-21

First MVP.

- Bridge daemon (`aqt-sensei serve`) with three sockets: owner (uid + token + not a paired pane + terminal), worker (pair derived from the caller's process ancestry) and one advisor socket per pair.
- Modes manual (explicit `forward` only), confirm (approve / edit / discard with reason) and auto, with budgets on messages, exchanges and declared cost, and fallback to confirm.
- tmux backend (bracketed paste; hook-reported or quiet-screen idle detection) and Herdr backend behind one host interface; fake host for tests and demos.
- bubblewrap sandbox from data profiles (claude, codex, pi, custom): project read-only, scratch writable, private agent homes, cleared environment, Herdr report proxy, in-sandbox `sensei` shim.
- `aqt-sensei doctor` probes the exact sandbox; `aqt-sensei login` signs private advisor homes in.
- Advice ledger: `sensei.pair`, `sensei.message`, `sensei.decision`, `sensei.budget`, `sensei.refused` through `aqt_evidence.open_sink()`; record-first owner decisions; local spool for automatic events.
- Persisted open turns; `no-reply` notice when the advisor ends a turn without answering.
