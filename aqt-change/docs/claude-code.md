# Claude Code hooks: setup and one-time check

The hook tests use synthetic payloads, because Claude Code does not store `TaskCompleted` hook payloads in its session files. The hook therefore does not rely on exact field names: it scans every string field of the payload for verification IDs such as `[V01]`. Check it once in a real session with this procedure (about five minutes, no model output is kept).

## Setup

1. Install aqt-change so that `aqt-change` is on the `PATH` Claude Code uses (`aqt-change --version`).
2. `aqt-change hooks print` and merge the snippet into the project's `.claude/settings.json` (or your user settings). It registers `TaskCompleted`, `Stop` and `SubagentStop`.
3. Optional: `aqt-change hooks install-git` for the commit-msg trailer check.

## One-time check in a real session

Use a throw-away repository with one plan, for example the one `examples/quickstart.sh` creates (step 1 and 2 only), then `aqt-change begin plans/s01.md`.

1. **Stop blocks a phantom completion.** In the plan, tick `- [x] [V01]` yourself without running anything. Start Claude Code in the repository and ask it to reply "ok" and stop. Expected: the stop is blocked once and Claude sees the message "V01 is ticked but has no fresh passing receipt". On the second stop (`stop_hook_active`) it is not blocked again.
2. **The receipt clears it.** Run `aqt-change run --plan plans/s01.md --item V01` in a terminal. Ask Claude to stop again. Expected: no block.
3. **TaskCompleted with an ID.** Edit any file under `src/` (this makes the receipt stale). Ask Claude to create a task named "Verify [V01]" and mark it completed. Expected: completion is blocked with "V01: no fresh passing receipt (stale)". A task without a `[V..]` ID completes normally.
4. **Unreconciled plan.** Change a word in the plan's Outcome and ask Claude to stop. Expected: blocked with "plan edits are unreconciled".

If step 3 does not block, the `TaskCompleted` payload carries the task text in a form the scan does not reach. Record the payload's *structure only* (key names, no content), for example with a temporary hook command `jq 'paths|map(tostring)|join(".")' > /tmp/keys.txt`, and report it so the scan can be adjusted. Remove the temporary hook afterwards.
