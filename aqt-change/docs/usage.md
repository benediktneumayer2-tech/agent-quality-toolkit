# aqt-change usage

## Plan format

```markdown
---
tracker:                      # Project Tracker Next compatible
  schema: 1
  kind: sprint
  id: s01                     # stable ID, unique per project
  implementation: calc
  status: planned             # draft|planned|in_progress|blocked|completed|failed|cancelled|superseded
aqt:                          # optional, ignored by Project Tracker Next
  paths: ["src/**", "tests/**"]          # approved change scope (globs; ** spans directories)
  review: {min_independence: fresh-context}   # tightens the configured gate policy (block form also works)
---
# Title
## Tasks
- [ ] [T01] Implement sub
## Verification
- [ ] [V01] Unit tests pass `$ python -m pytest -q`     # declared command: inline code starting with "$ "
- [ ] [V02] README example checked by a person          # manual item: needs `aqt-change attest`
## Progress Log / ## Blockers / ## Deviations / ## Failures And Learnings / ## Decisions
### 2026-10-21T10:00:00Z — Title                          # append-only event entries
## Completion
```

The front matter accepts a strict YAML subset: mappings, scalars, quoted strings, flow and block lists of scalars. Anything else is refused with an error. Declared commands are split with `shlex` and run **without a shell**; put pipelines in a script. Every item needs a stable ID.

## What counts as a change

| Edit | Plan state | Needed |
|---|---|---|
| Tick or untick a box, append an event entry | `status_neutral` | nothing |
| Change prose (Outcome, Scope …) | `unreconciled` | `reconcile --kind editorial` (reason needed while active or terminal) |
| Add, remove or rename items, change a declared command, `aqt` block, `sequence`, `depends_on` | `unreconciled` | `reconcile --kind semantic --reason …` (refused for terminal plans; completed items must stay intact while active) |
| Edit or delete an earlier event entry | `history_rewritten` | restore it (always refused) |
| Change `status`, `started_at`, `completed_at`, `git` by hand | `lifecycle_changed` | restore it (written by `begin`/`finish` only) |
| Change `id`, `kind`, `schema`, `implementation` | — | refused (`plan_identity_changed`) |

## Freshness and output files

A receipt is fresh while the plan basis hash and the tree fingerprint match the current state. The fingerprint covers all tracked files plus untracked files that are not ignored, and leaves out the plan file. This is strict on purpose: a file a later command leaves behind in the working tree (`coverage.xml`, `report.html`, scratch notes) makes earlier receipts stale. Keep outputs in paths covered by `.gitignore` (for example `build/`, `.pytest_cache/`), or add globs to `fingerprint_exclude` in `change.toml`. The `--junit` file of a run is excluded automatically. A run that changes the working tree itself records the warning `command_modified_worktree`.

The fingerprint hashes the content of every tracked file; it does not trust Git's stat cache, an fsmonitor hook or index flags (Git calls run with `core.fsmonitor`, `core.untrackedCache` and relaxed stat checks switched off). A tracked file whose content differs from the index while `git status`, with the repository's own settings, does not show it is a *hidden change*: the file is marked `git update-index --skip-worktree` or `--assume-unchanged` (flag of that name; a missing file counts too), or a `core.fsmonitor` hook, `core.checkStat = minimal`, `core.trustctime = false` or edited index data make Git believe it is unchanged (flag `stat-cache`). Then a run records the warning `hidden_worktree_change`, the gate is NO-GO, `finish` refuses (`finish_hidden_changes`) and the hooks block: the commit would not contain what the command tested. Clear the flags (`git update-index --no-skip-worktree PATH`, `--no-assume-unchanged PATH`), or remove the fsmonitor or stat settings and `touch` the files, and run the checks again. Files outside a sparse checkout are not an error but give MANUAL (`sparse_checkout`). Hashing every file costs one `git hash-object` pass per run, gate or hook (about 0.5 s for 10,000 tracked files).

## Evidence and the trail

`gate`, `finish` and the hooks read receipts and reviews from the ledger's local copy of the records (`<git-dir>/aqt-change/records.jsonl`), which the agent's user can edit. When a trail is in use, they count a receipt or review only if the trail log confirms it:

- A trail is in use when a trail log exists or records go to an aqt-trail writer (`aqt_evidence.resolve_sink()` kind `unix`). `AQT_SINK=file:` does not switch the check off while a log exists, because an agent sets its own environment; records written to a file sink are then not confirmed. The log is each `AQT_EVIDENCE` entry named `trail.jsonl`, else `trail.jsonl` in the trail state directory; the sink file and the spool never count. In separate-user mode, set `AQT_EVIDENCE` to the trail log (for example `/var/lib/aqt-trail/trail.jsonl`).
- Where the log is comes from the environment of the process that runs `gate`, `finish` or a hook, and an agent sets that environment (for example by pointing `XDG_STATE_HOME` at an empty directory or unsetting `AQT_EVIDENCE`). Two things keep the check on anyway. First, the project setting `require_trail = true` (see *Project settings*): with it, a trail is always in use, and when no log is found the gate is NO-GO (`trail_required`), `finish` refuses (`finish_trail_required`), the hooks block and the commit-msg hook rejects `AQT-Receipts`. Second, without the setting, when a record of the local copy came back from a writer (it carries a `chain`), a trail stays in use: no log found gives MANUAL and `finish` refuses. The second rule is a safety net only: the agent can rewrite the local copy.
- A record is confirmed when the log holds a record with the same id and content hash (`record_content_hash`, which leaves out the writer's `time`, `chain`, `observed` and `sig`) that the writer received over its socket (`observed.via = socket`).
- A fresh passing receipt that is not confirmed makes its item `unverified` (gate `receipt_unverified`): NO-GO when the log lacks the record or holds a different one with that id; MANUAL when the record reached the trail through the spool (no observed sender) or no log is readable. `finish` refuses unverified items and the hooks block on them. A failing or stale receipt counts from the local copy as before.
- A PASS, CONCERNS or WAIVED review that is not confirmed does not count (gate `review_unverified`, NO-GO or MANUAL as above) and cannot replace an earlier FAIL. A FAIL review counts from the local copy.
- The commit-msg hook rejects an `AQT-Receipts` entry that the log lacks or contradicts.
- The gate JSON reports `trail: {checked, logs, required}`.

When the writer was down, records wait in the spool and are not confirmed yet; run the commands again with the writer running (`gate --rerun` does this for the gate). Without any trail log, without a writer, without `require_trail` and without records that came back from a writer, the local copy counts as it is; see the limits in the README.

## Project settings

`.aqt/change.toml` in the repository holds settings that belong to the project, not to one user's environment. Commit it with the code. Today it has one key:

```toml
# aqt-change project settings (committed). They can only make checks stricter.
require_trail = true   # receipts and reviews count only when an aqt-trail log confirms them; no log found: NO-GO
```

A setting counts when the copy in the working tree, the copy at HEAD or the copy at the base commit of a plan in progress sets it, so neither an uncommitted edit nor a commit during a plan switches it off. Turning it off is a commit that removes it; review it like code. A change to the file inside a plan's diff gives MANUAL (`project_settings_changed`) and is listed by `reconcile-diff` (`settings_changed`). A copy that cannot be read refuses with `config_invalid`. Set `require_trail` once the project's records go to an aqt-trail writer for everyone who works on it, including CI.

## Commands

All commands accept `--root`, `--state` and `--json`. Exit codes: 0 ok, 1 check failed or refused, 2 usage or runtime error.

| Command | Purpose |
|---|---|
| `plan new PATH --id ID --title T [--implementation I] [--follows ID]` | Write and register a plan from the template |
| `plan add PATH` | Register an existing plan (baseline record) |
| `plan status [PATH…]` | Reconciliation state; exit 1 unless every plan is clean or status-neutral |
| `reconcile PATH --kind editorial\|semantic [--reason R] [--expect SHA]` | Accept the current version |
| `begin PATH [--reason R]` | `in_progress`, `started_at`, Git base commit; baseline record |
| `run [--plan P] [--item ID \| --all] [--junit FILE] [--timeout S] [--quiet] -- CMD…` | Run and record receipts; an explicit command must equal the declared one |
| `attest PATH --item ID [--evidence FILE…] --reason R` | Evidence for a manual item (`meaning: verified`) |
| `review add PATH --reviewer ID --independence C --verdict V --reason R [--findings F.json] [--harness H --model M] [--base REV] [--qualification REC]` | Review record bound to the diff |
| `reconcile-diff PATH [--evidence F…]` | Approved scope versus actual diff and missing evidence |
| `finish PATH --key K --summary S [--path F…] [--message M] [--waive ID=REASON…] [--ack-warnings R] [--remaining R] [--no-commit]` | Checked completion, scoped commit, `change.finish` |
| `report PATH [--format md\|html] [--out F] [--gate F] [--rerun] [--evidence F…]` | Trace report and gate file |
| `gate PATH [--rerun] [--evidence F…]` | Gate JSON; exit 0 only for GO |
| `hook claude-code` | Claude Code hook (stdin JSON; exit 2 blocks) |
| `hook commit-msg FILE [--require]` | Trailer check |
| `hooks print` / `hooks install-git` | Settings snippet / commit-msg shim (never overwrites an existing hook) |

## Finish in detail

1. **Preflight** (nothing is written if it fails): plan in progress (unless `lifecycle_owner = "external"`), plan clean or status-neutral, and a fresh passing receipt for every verification item (or a waiver with a reason). Open tasks, anti-gaming warnings, unapproved paths, an open FAIL review or a stale approval need `--ack-warnings REASON`. Unrelated *staged* files abort the finish.
2. **prepared → plan_written_commit_pending:** the final plan is written atomically. Verification items with fresh passing receipts are ticked, `status: completed` and `completed_at` are set, and a completion entry is appended, generated from the receipts.
3. **→ commit_created_record_pending:** `git add` and `git commit` of exactly the plan plus the `--path` files, with trailers `AQT-Plan`, `AQT-Task`, `AQT-Receipts` and `AQT-Finish: <plan>/<key>`. Hooks run; a failure stops here and is never bypassed.
4. **→ completed:** the trailers are verified, then `change.finish` is written.

Run the same command again with the same `--key` to resume after a hook failure or a crash. A commit that was already made is adopted, not made twice. The same key with different inputs fails with `idempotency_conflict`.

## Gate codes

- **NO-GO:** `plan_unreconciled`, `receipt_missing`, `receipt_stale`, `receipt_failed`, `receipt_unverified` / `review_unverified` (the trail log lacks or contradicts the record, or `require_trail` is set and no log is found), `trail_required`, `hidden_worktree_change`, `unapproved_change`, `review_fail` (the latest counted review is FAIL), `not_finished`; `anti_gaming_warning` when `warnings_block = true`.
- **MANUAL_VERIFY_REQUIRED:** `waiver_present`, `manual_item_agent_attested`, `receipt_unverified` / `review_unverified` (record came through the spool, or no trail log is readable), `sparse_checkout`, `anti_gaming_warning`, `approval_stale`, `approval_invalid`, `approval_unsigned` / `approval_unverified` (with `require_signed_approval`), `review_concerns`, `review_waived`, `review_independence_below_policy`, `scope_undeclared`, `scope_unverifiable`, `project_settings_changed`.

## Approval with aqt-signoff

The approval target is the latest `baseline`/`begin`/semantic `reconcile` record of the plan (`gate` shows its ID as `approval.record`, the trace report in its *Approval* row; `plan status` does not). A person signs it with aqt-signoff (`--record <id> --meaning approved`). The signature subject is `{kind: record, ref, sha256: record_content_hash(record)}`. aqt-change asks `aqt_signoff.is_approved` when it is installed (`signed`). Otherwise it looks for matching `signoff.signature` records in `--evidence` files, `AQT_EVIDENCE`, the sink or the trail log, and reports them as `unverified`. If aqt-signoff is installed and rejects the signature, the state is `invalid` (gate: MANUAL).

## Claude Code hooks

`aqt-change hooks print` prints a snippet for `TaskCompleted`, `Stop` and `SubagentStop`; merge it into `.claude/settings.json`. On `Stop`, the hook blocks while a plan is unreconciled, a *ticked* verification item has no fresh passing (and, with a trail, confirmed) receipt, or Git hides working-tree changes (`hidden_worktree_change`). When `stop_hook_active` is true it reports the problem without blocking a second time, and `finish` still refuses. On `TaskCompleted`, it blocks when the task text names a verification ID (`[V01]`) that has no fresh passing receipt. The hook never runs tests.

## Working with Project Tracker Next (PTN)

The files are the same. With the default `lifecycle_owner = "aqt-change"`, use aqt-change's `begin`/`finish` *instead of* PTN's for that plan. With `lifecycle_owner = "external"`, PTN keeps `begin_work`/`finish_work`. aqt-change then records the baseline, receipts, reviews, scope checks and a record-only `change.finish` (no plan write, no commit), and lifecycle field changes count as status-neutral.

## Records

| Type | Action | Fixed `data` fields ([aqt-spec §11](../../aqt-spec/spec/evidence-records-0.1.md#11-record-type-registry)) |
|---|---|---|
| `change.plan.reconciled` | `baseline`, `begin`, `reconcile` | `plan_id`, `kind`, `basis_before/after`, `items` |
| `change.receipt` | `run`, `attest` | `argv`, `exit_code`, `passed`, `plan_basis_hash`, `tree_fingerprint`, `counts` |
| `change.review` | `review` | `verdict`, `independence`, `diff_sha256`, `findings` |
| `change.reconciliation` | `reconcile-diff` | `unapproved`, `missing_evidence`, `approval`, `result` |
| `change.finish` | `finish` | `plan_ref`, `receipts`, `waivers`, `gate` |
| `change.refused` | `refused` | `attempted_action`, `reason_code`, `agent_markers` |
