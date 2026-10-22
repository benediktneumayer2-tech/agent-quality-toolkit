# Claude Code integration

## What the hooks do

| Event | aqt-quarantine does |
|---|---|
| `PostToolUse` for `WebFetch`, `WebSearch`, `mcp__.*` | Scans the result. It returns `hookSpecificOutput.updatedToolOutput`: the same object with only its text fields changed, wrapped for pass and warn, and a hold notice for hold. For warn and hold it also adds `additionalContext`. |
| `UserPromptSubmit` | Gives released content, and notes about declared threats, to the session the case came from. Each is delivered once. |

The adapter never invents an output shape. Claude Code ignores a replacement that does not match the tool's output schema and passes the original. So the adapter deep-copies `tool_response` and rewrites only its content-bearing string leaves. Metadata keys such as `url`, `query`, `tool_use_id` and `codeText` are left alone.

The tested structures were taken from Claude Code session logs: key names and value types only, no content.

- **`WebFetch`:** `{bytes: int, code: int, codeText: str, durationMs: int, result: str, url: str}`, or a plain string on errors.
- **`WebSearch`:** `{query: str, results: [{tool_use_id: str, content: [{title: str, url: str}]} | str], durationSeconds: float, searchCount: int}`, or a plain string.

## Install

1. Install aqt-quarantine so that `aqt-quarantine` is on the `PATH` that Claude Code sees.
2. Run `aqt-quarantine init --id human:<you> --name "<Your Name>"` in **your own terminal**. This creates your passphrase-protected key and the config. If aqt-signoff is installed, `aqt-signoff init` creates the same key and registry entry.
3. Run `aqt-quarantine hooks print claude-code`. Merge the snippet into `~/.claude/settings.json` or the project's `.claude/settings.json`, and add the CLAUDE.md paragraph it prints. The deny rules stop the agent from running decision commands and from reading the quarantine state.
4. Run `aqt-quarantine doctor`.

## Manual verification procedure (for the owner)

The automated tests use synthetic fixtures in the observed shapes. Only a real Claude Code session can show that the running Claude Code version honours the replacement. Run this check once after installing, and again after each Claude Code upgrade. It needs no hostile web page.

1. In a scratch project with the hooks installed, start Claude Code from a shell where you exported
   `AQT_QUARANTINE_THRESHOLDS=/path/to/aqt-quarantine/examples/thresholds.hold-everything.json`.
   This test file holds **every** result.
2. Ask: *"Fetch https://example.com and tell me exactly what text the tool returned."*
   - **Pass:** Claude reports a notice that starts with `[held by aqt-quarantine: case Q…`, and it cannot quote the page ("This domain is for use in illustrative examples…").
   - **Fail:** Claude quotes the page. The replacement was ignored. Note `claude --version`, run `aqt-quarantine cases list`, and report it. Until it is fixed, treat the quarantine as **warn-only** for that tool, because the `additionalContext` notice still arrives.
3. Ask: *"Search the web for 'example domain IANA' and list the result titles."* Expect the same hold notice for `WebSearch`.
4. In your own terminal, run `aqt-quarantine cases list`. Then run `aqt-quarantine cases show <CASE>` and `aqt-quarantine release <CASE> --reason "verification test"`, and enter your passphrase.
5. Back in Claude Code, send *"continue"*. Claude should now see the example.com text inside `<untrusted_content …>`, with the banner "Released by …". `aqt-quarantine cases show <CASE>` lists the delivery.
6. Ask Claude: *"Run `aqt-quarantine release <another CASE> --reason ok`."* Two outcomes are acceptable:
   - the deny rule blocks the command;
   - the command runs and is refused, and `cases show` lists a `REFUSED release (agent_context …)` entry.

   Neither outcome may change the case state.
7. Quit Claude Code and unset `AQT_QUARANTINE_THRESHOLDS`. Cases from the test can stay; they are evidence of the check.

## Limits specific to Claude Code

- If the hook cannot run at all, Claude Code treats that as a non-blocking error and passes the original. Examples: `aqt-quarantine` is not on `PATH`, or the hook times out. `doctor` checks the install.
- Claude Code's telemetry keeps the original tool output (documented by Claude Code).
- The main model never sees the raw `WebFetch` page. It sees a small model's answer to the fetch prompt, and that answer is what is scanned. An injection may already have shaped that answer.
- Bash `curl`, files the agent downloads and tools outside the matcher are not covered. Pair the quarantine with sandbox or egress limits.
