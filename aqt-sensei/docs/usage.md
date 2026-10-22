# Using aqt-sensei

## Setup

```bash
aqt-sensei init [--owner-id ID] [--display NAME]
```

This writes `$XDG_CONFIG_HOME/aqt/sensei.toml` (see `examples/sensei.toml`) if it is missing, and creates the owner token `$XDG_CONFIG_HOME/aqt/sensei/owner.token` (mode 0600). Never give the token to an agent.

Paths can be overridden with `AQT_SENSEI_CONFIG`, `AQT_SENSEI_STATE` (default `$XDG_STATE_HOME/aqt/sensei`), `AQT_SENSEI_RUNTIME` (default `$XDG_RUNTIME_DIR/aqt-sensei`) and `AQT_SENSEI_TOKEN`. Evidence records go to `AQT_SINK` or the `[bridge] sink` setting (`file:/path.jsonl` or `unix:/path/trail.sock`).

Sign each advisor platform in once, into its private home:

```bash
aqt-sensei login claude     # starts Claude Code in the sandbox: run /login, then quit
aqt-sensei login codex      # device sign-in into the advisor's own CODEX_HOME
```

## Running the bridge

`aqt-sensei serve [--backend tmux|herdr]` runs in the foreground. Without `--backend` it picks tmux, or Herdr when started inside Herdr outside tmux. `examples/aqt-sensei.service` is a systemd user unit template. One bridge serves one backend.

## Pairing

```bash
aqt-sensei pair --worker PANE --advisor ADVISOR --project DIR --reason TEXT
    [--mode manual|confirm|auto] [--max-exchanges N] [--max-messages N] [--max-cost N]
    [--model ID] [--worker-platform claude|codex|pi|…] [--worker-model ID]
    [--name NAME] [--network share|none] [--first-prompt TEXT --start-with worker|advisor]
```

- `PANE` is the worker's pane: tmux `%N` (see `tmux display -p '#{pane_id}'` in that pane) or Herdr `wN:pN`.
- `ADVISOR` is `claude`, `codex`, `pi`, a profile from the config, or any command line (for example `"myagent --flag"`).
- In auto mode without explicit limits, `[bridge.auto_budget]` applies (8 exchanges by default).
- `--worker-platform` and `--worker-model` feed the independence class (`same-model`, `same-vendor`, `different-vendor`, `unknown`) and the tmux prompt detection.

The bridge splits the worker's pane, runs `aqt-sensei launch --pair ID` in the new pane (which `exec`s bubblewrap) and queues an intro for the worker.

Run owner commands from your own terminal, not from inside an agent: they are refused (and recorded) when they come from a paired pane, from a process with agent-session markers, or without a terminal.

## Deciding

| Command | Effect |
|---|---|
| `aqt-sensei list [--pair ID]` | Pairs, pending messages, recent messages, ledger records waiting for the sink |
| `aqt-sensei show MSG` | The message exactly as it will be typed, plus the original text after an edit |
| `aqt-sensei approve MSG --reason R [--text T \| --edit-file F]` | Confirm mode: release (optionally edited) |
| `aqt-sensei forward MSG --reason R` | Manual mode: release this one message |
| `aqt-sensei discard MSG --reason R` | Drop a pending message |
| `aqt-sensei mode PAIR manual\|confirm\|auto --reason R` | Switching to auto releases messages waiting for approval, never manual-held ones |
| `aqt-sensei budget PAIR [--max-* N] [--clear] [--add-cost N] --reason R` | Change limits or record a cost |
| `aqt-sensei pause PAIR` / `resume PAIR` | Hold or continue all deliveries |
| `aqt-sensei end PAIR --reason R` | Discard pending messages, close the advisor pane |

`--json` gives machine-readable output. Exit codes: 0 ok, 1 refused or a check failed, 2 usage or runtime error (including the bridge being offline).

## The agents' side

- **Worker:** `aqt-sensei ask "…" [--file PATH]…`, then end the turn; `aqt-sensei status`.
- **Advisor (inside the sandbox):** `sensei reply "…" [--file PATH]`, `sensei send "…"`, `sensei status`, `sensei worker-log [--last LINES]`.

Message headers show the exchange and the budget, for example `[Worker → Sensei · 3/8]`. A context digest of the worker pane's recent output goes with every question. Long content belongs in files in the scratch folder `<project>/.sensei/<pair>/`, which the worker can read.

If the advisor ends its turn without replying, the bridge records `no-reply`, sets a note on the pair and queues a short notice to the worker (subject to the mode).

## tmux hooks

Without hooks, a tmux pane counts as idle when its screen has not changed for `quiet_seconds` and a prompt (`>`, `❯`, `›`) is visible near the bottom. For exact states, let the agent report them. `examples/claude-code-hooks.json` maps Claude Code's `UserPromptSubmit`, `Stop` and permission `Notification` hooks to `aqt-sensei hook-state working|idle|blocked`. Check the hook names against your Claude Code version. Other harnesses can call the same command from their own hooks.

## Ledger records

| Type | Actions | Key `data` |
|---|---|---|
| `sensei.pair` | `attached`, `updated`, `paused`, `resumed`, `ended`, `doctor` | `pair_id`, `backend`, `worker`, `advisor`, `profile_sha256`, `sandbox_argv_sha256`, `independence`, `mode`, `budget`, `used` |
| `sensei.message` | `enqueued`, `delivered`, `failed`, `no-reply` | `pair_id`, `message_id`, `from`, `to`, `kind`, `exchange`, `state`, `excerpt`, `files`, `rendered_sha256`, `peer` |
| `sensei.decision` | `approved`, `edited`, `discarded`, `forwarded` | `decision`, `message_id`, `pair_id`, `peer`; `meaning`, `reason`, `before`/`after` |
| `sensei.budget` | `consumed`, `reached`, `set`, `cost-added` | counters and limits |
| `sensei.refused` | `refused` | `attempted_action`, `reason_code`, `agent_markers`, `peer` |

`data.peer` describes the caller as the bridge observed it through `SO_PEERCRED` and `/proc`, with the field names of the trail's `observed` object. The envelope's own `observed` is left to aqt-trail.
