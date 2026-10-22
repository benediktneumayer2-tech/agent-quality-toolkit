# Manual verification: one live run with real advisor CLIs

The automated tests use fakes, plus opt-in runs with real tmux and bubblewrap and *scripted* agents. This procedure checks the parts they cannot: real Claude Code or Codex advisors, their sign-in in private homes, and two flags that were not verified against installed versions. It takes about 20 minutes and uses one or two short model exchanges.

Use a **throwaway copy of a small project**, never a project you care about. Run every `aqt-sensei` owner command from your own terminal, not from inside an agent.

## 0. Preparation

```bash
export AQT_SINK=file:$HOME/aqt-sensei-check/evidence.jsonl    # a separate ledger for this check
mkdir -p ~/aqt-sensei-check && cp -r ~/code/small-project ~/aqt-sensei-check/project
aqt-sensei init                                               # config + owner token, if not done yet
```

## 1. Sandbox proof and sign-in

```bash
aqt-sensei doctor --profile claude --project ~/aqt-sensei-check/project
aqt-sensei login claude            # inside: /login, finish the sign-in, then /exit
aqt-sensei doctor --profile claude --project ~/aqt-sensei-check/project
```

**Expect:** every line `PASS`, including "advisor CLI starts in the sandbox". If "bubblewrap can create namespaces" fails, see `docs/sandbox.md` (AppArmor). For Codex, repeat with `codex` (`login` runs the device sign-in).

## 2. Pair

1. Start the worker agent in a tmux pane inside the project, for example `claude` (confirm mode needs no special settings).
2. In that pane's shell, before starting the agent, or from another pane: `tmux display -p -t <pane> '#{pane_id}'` gives the pane id, for example `%3`.
3. In a second terminal (outside tmux or in an unrelated pane):

```bash
aqt-sensei serve                                   # leave it running
aqt-sensei pair --worker %3 --advisor claude --project ~/aqt-sensei-check/project \
    --worker-platform claude --mode confirm --max-exchanges 2 --reason "manual verification"
aqt-sensei doctor --pair <pair id>                 # expect all PASS; recorded as sensei.pair doctor
```

**Expect:** a new pane to the right running the advisor, and an intro message in the worker's conversation.

## 3. One exchange

1. Tell the worker: *"Run `aqt-sensei ask "Which function in this project is the most complex, and why?"` and then end your turn."*
2. `aqt-sensei list`: the ask is `awaiting_approval`. Run `aqt-sensei show <message id>` and check that the text is exactly what you expect to be typed.
3. `aqt-sensei approve <message id> --reason "verification question"`. The question appears in the advisor pane with the header `[Worker → Sensei · 1/2]`.
4. The advisor answers with `sensei reply`. Approve the reply the same way; it appears in the worker's conversation as `[Sensei → Worker · 1/2]`.

## 4. The advisor cannot write, the worker cannot decide

1. Type directly into the advisor pane: *"With your shell tool, try to create `probe.txt` in the project root, then run `ls ~` and `cat ~/.config/aqt/sensei/owner.token`. Report the exact errors."*
   - **Expect:** a read-only file system error, an empty home, and no such file.
   - Then check `ls ~/aqt-sensei-check/project/probe.txt`: it must not exist.
2. Tell the worker: *"Run `aqt-sensei mode <pair id> auto --reason test`."*
   - **Expect:** the command fails with "owner operations cannot come from a paired agent pane".

## 5. Check the ledger

```bash
aqt-evidence validate ~/aqt-sensei-check/evidence.jsonl
python3 - <<'EOF'
import json, os
for line in open(os.path.expanduser("~/aqt-sensei-check/evidence.jsonl")):
    r = json.loads(line)
    print(f"{r['type']:<16} {r['action']:<10} {r['actor']['id']:<40} {r.get('reason') or ''}")
EOF
```

**Expect:**
- `sensei.pair attached` with your reason, and `sensei.pair doctor`;
- `sensei.message enqueued` and `delivered` for intro, ask and reply;
- two `sensei.decision approved` records carrying your reasons;
- `sensei.budget consumed`;
- `sensei.refused` with `reason_code: paired-pane` from step 4.

No record contains the full message texts; only excerpts of at most 280 characters and hashes.

## 6. The two unverified flags

**Claude Code `Notification` matcher `permission_prompt`** (`examples/claude-code-hooks.json`, tmux idle detection):
1. Merge the example hooks into the worker project's `.claude/settings.json` and restart the worker.
2. Ask the worker to run a shell command that needs your permission, and leave the prompt open.
3. Run `cat "$XDG_RUNTIME_DIR/aqt-sensei/panes/_3.state"` (pane `%3` becomes `_3`). **Expect:** `"state": "blocked"`. After you answer the prompt and the turn ends, it should read `"idle"`.
4. If it never shows `blocked`, look up the notification matcher names for your Claude Code version (`/hooks` in Claude Code, or its hooks documentation), correct the example, and note the version.

**pi `PI_CODING_AGENT_DIR`** (the pi profile's private home):
1. Run `aqt-sensei login pi`, set up a model inside, then quit.
2. Run `ls ~/.local/state/aqt/sensei/homes/pi`. **Expect:** pi's settings and sessions there.
3. If it is empty, pi uses another variable. Check `pi --help` or its documentation for the configuration folder variable and override it in the config:

```toml
[profiles.pi]
env = { CORRECT_VARIABLE = "{home}" }
```

## 7. Clean up

```bash
aqt-sensei end <pair id> --reason "verification done"
# stop `aqt-sensei serve` with Ctrl-C
rm -rf ~/aqt-sensei-check
```

Record the result (date, CLI versions, PASS/FAIL per step, any corrected flag) in the package's `CHANGELOG.md` or the project's tracker.
