# Security review, October 2026

In October 2026, eight AI reviewers tried to break the Agent Quality Toolkit (AQT) from the position of an AI coding agent that runs as the same Linux user as the person it works for. They reported 81 findings, 58 after merging duplicates. None of the 58 was rated critical, and 21 were rated high. 57 are fixed; one is a documented limit. Some fixes leave a smaller limit, listed [below](#limits-that-remain).

**This was an AI-assisted review, not a professional security audit.** The reviewers were AI models, not human security specialists. Read the results as a first pass, not as a certificate. This page lists every finding and what was done about it; the fixes are public in the git history and in each package's `CHANGELOG.md`.

## At a glance

| Severity | Reported | After merging duplicates | Fixed | Documented limit |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 29 | 21 | 21 | 0 |
| Medium | 31 | 23 | 23 | 0 |
| Low | 17 | 11 | 10 | 1 |
| Info | 4 | 3 | 3 | 0 |
| **Total** | **81** | **58** | **57** | **1** |

The severity is the reviewers' own rating. When several reviewers reported the same problem, the finding is counted once, at the highest rating any of them gave. "Fixed" means that the code was changed to stop the reported attack; for A-12, an over-broad claim, it means that the documentation was corrected. A second check of the high-severity fixes is described under [Verification of the fixes](#verification-of-the-fixes).

## What was reviewed

The code at commit `363b445` (22 October 2026), split into five trust boundaries. A trust boundary is a place where the toolkit has to tell trusted input from input an agent could have forged.

| | Boundary | What the reviewers tried to break | Main packages |
|---|---|---|---|
| a | Evidence integrity | Make two different records hash or verify the same, or change, reorder, cut short, replay or swap records, signatures or checkpoints unnoticed | aqt-spec and every verifier in the other packages |
| b | Keys and identities | Sign, add or swap a key, edit the signer registry, replay a signature or meet a two-person rule alone, unnoticed | aqt-signoff, key encryption, every package that loads keys or trusts the registry |
| c | The audit trail | Write as someone else, or change, hide or fake trail records, anchors, reviews and archives | aqt-trail (writer service, attribution, verification, review, export, time stamps) |
| d | Workflow decisions | Get past a decision that belongs to a person: release quarantined content, reach GO, run an approved action twice, close a deviation | aqt-quarantine, aqt-change, approved actions in aqt-signoff, aqt-capa |
| e | The local web page | Make another local process, an agent or a web page in the browser trigger or forge a decision, read secrets or inject script | aqt-ui |

## How

- **Eight reviewers.** Each boundary had one reviewer running Claude Opus 5.5 (Anthropic). Boundaries a, b and e also had a reviewer running OpenAI Codex, with a model from another vendor. None of them had written the code, and each started with a fresh context, without the conversations in which the code was built.
- **Independence has a limit.** The toolkit was built with AI coding agents, also running Claude Opus 5.5. The Opus reviewers are therefore the same model as the author, though not the same session. The Codex reviewers are the independent part.
- **Threat model.** An AI agent running as the same Linux user is a capable adversary. It can read and write everything the user can, but does not know the person's passphrase. Detecting an attack instead of preventing it was acceptable only where the documentation says so.
- **Method.** The reviewers read the code without changing it and reproduced each finding, with proof-of-concept scripts or test fixtures in throw-away folders. Each finding came with a location, reproduction steps, impact, a suggested fix and a confidence. They also listed the claims they checked and found sound.
- **Fixes.** Seven fix workers (AI agents) took the findings package by package. They were asked to reproduce each finding first, then make the smallest sound fix and add a regression test that fails before the fix and passes after it. Where a proper fix would have needed a breaking change or a redesign, they proposed a documented limit instead, and the lead agent that coordinated the fixes decided. After the fixes and their integration, all 884 offline tests pass (`scripts/test_all.sh`), and the record library agrees with all 87 test vectors of the specification (57 before the review).

## Results

Each finding is listed once, under the boundary it concerns. The IDs in brackets are the reviewers' own and show who reported it: `A-`, `B-`, `C-`, `D-`, `E-` the Opus reviewers of boundaries a to e; `AQT-EI-`, `KEYS-` and `AQT-UI-` the Codex reviewers of boundaries a, b and e.

### a. Evidence integrity

| Finding | Severity | What it allowed | Fix or limit |
|---|---|---|---|
| A side file could hide trail records (A-1, C-17) | high | An agent could write a line with the same record ID into the plain evidence file it can edit. Every tool that reads evidence then used that copy instead of the chained, signed record in the trail, for example to bring back a withdrawn approval. | Fixed: the trail log is always read first; a different copy elsewhere is not used and is reported. |
| Lenient reading in the verifiers (A-5, AQT-EI-001, C-19) | high | A line edited to contain the same key twice still verified as "intact", so two programs could read different content under one verified hash. | Fixed: `aqt-evidence verify` and `aqt-trail verify` read every line strictly and accept only the canonical form. |
| "Require a signature" without a key (A-6, AQT-EI-013) | medium | `aqt-evidence verify --require-signature` without `--key` checked nothing and reported a forged, unsigned chain as intact. | Fixed: the command refuses this combination. |
| Conformance level 1 too lenient (A-7, AQT-EI-014) | medium | Records with wrong member types (a list as an ID, a number as a time zone, `null` values) were certified valid, up to level 3, and `sig: null` crashed the verifier. | Fixed: member types are checked, `null` is rejected, and level 1 applies the envelope schema when `jsonschema` is installed. |
| Patterns accepted a trailing newline and non-ASCII digits (A-8) | low | Look-alike IDs and impossible times passed validation. | Fixed: patterns match the whole string with ASCII digits; times must be real dates. |
| Checkpoint shape not checked (A-10) | low | Any object signed with a trusted key verified as a checkpoint, and a malformed checkpoint crashed the check. | Fixed: the checkpoint shape is required; a malformed one fails cleanly. |
| Deep nesting crashed the parser (A-11) | low | One crafted line stopped the conformance check of a whole file. | Fixed: it is reported as a parse problem. |
| Truncation claim too broad (A-12) | info | The documentation suggested that checkpoints reveal any cut-off end of the log; they reveal it only down to their own sequence number. | Fixed: the specification and READMEs say so, and `aqt-trail verify` says how many records follow the newest checkpoint. |

### b. Keys and identities

| Finding | Severity | What it allowed | Fix or limit |
|---|---|---|---|
| A copied signature counted again (A-2, AQT-EI-007, KEYS-04) | high | Copying a person's signed approval into a new record made it count again, even after the person had withdrawn it. | Fixed: a signed statement is identified by its own hash and counts once; a copy is reported `invalid` (replay), and a withdrawal applies to every copy. |
| A withdrawal could be redirected (AQT-EI-012, also part of A-2) | medium | A person's withdrawal of one signature could be pointed, through an unsigned field, at another of their signatures. | Fixed: a new withdrawal names the withdrawn statement inside the signed bytes (`withdraws`); an older withdrawal applies only to the record its signed subject names. |
| The signer registry was not checked (B-1, KEYS-01, B-5) | high | A same-user agent could add a person or a key to `signers.json`, change a role, or undo or backdate a revocation, and then meet two-person, role and "not the author" rules alone. No tool compared the file with the enrolment records. | Fixed in aqt-signoff, and so in the aqt-change and aqt-capa approvals that use it: a registry key counts only when its signed enrolment record matches it (from the trail when there is one). New: `aqt-signoff signers check`. Limits below. |
| Weak key encryption (B-2, KEYS-11) | high | Key files used PBKDF2 with 2,048 iterations, so an agent that copied a key file could guess the passphrase offline, cheaply. | Fixed: new keys use scrypt (128 MiB of memory per guess) and AES-256-GCM; older keys are re-encrypted at their next use or with `aqt-signoff rekey`. Limit: copies of old key files keep the weak encryption. |
| Roles chosen by the signer (KEYS-05) | high | Any enrolled key could state any role in its signature and pass a rule such as "only the quality manager releases". | Fixed: the role comes from the registry and must equal the signed role. |
| Author not excluded everywhere (KEYS-06) | high | The rule "the approver is not the author" was skipped in the shared approval check that aqt-change uses, and when the page signed a plan approval. | Fixed: `sign`, `verify` and `is_approved` all exclude the author of the signed record. |
| Key folder readable by others (B-4) | low | On a shared machine, other users could list who has a signing key. | Fixed: `aqt-signoff init` sets the key folder to mode 0700. |

### c. The audit trail

| Finding | Severity | What it allowed | Fix or limit |
|---|---|---|---|
| Incomplete process chains counted as human (C-1) | high | An agent could send a record claiming to be a person from a process whose ancestry the writer could not follow to the end, for example after its parent had exited. The review and the ALCOA++ report then showed it as correctly attributed. | Fixed: the writer records how far it could see (`chain_status`: complete, partial or unavailable), and review and ALCOA++ count a human claim as attributed only with a complete chain without an agent in it. Limit: still a heuristic, see below. |
| The review worksheet was trusted (C-2, KEYS-09) | high | An agent could edit the worksheet to remove findings or to drop the reviewer from the people in scope, so that a person signed an incomplete review, or a review of their own work. | Fixed: `review sign` recomputes the worksheet from the trail and refuses an edited one. |
| Review signatures not bound to the reviewer (AQT-EI-008, KEYS-08, A-9, C-6) | high | A signature approving a file could pass as a signed audit-trail review, one key holder could sign as another reviewer, and a review without any signature passed verification silently. | Fixed: `verify` checks that a review is signed by its reviewer, with that person's key, valid at signing time, for this record type and meaning. With a signer registry, the reviewer must be registered. |
| An archive bundle trusted itself (AQT-EI-010, C-7) | high | A modified export bundle could bring its own time-stamp CA (even the TEST ONLY one, trusted automatically) and its own signer list, so forged time stamps and signatures verified. | Fixed: `verify --bundle` trusts only the service key, CA and signer registry you pass (`--pin-key`, `--tsa-ca`, `--signers`), and the test CA only with `--test-tsa`. |
| Time-stamp certificate path too lenient (AQT-EI-009, C-8) | high | Anyone holding an ordinary certificate issued by the configured CA could issue time stamps that verified. | Fixed: every issuer must be a CA certificate, and the time-stamp certificate must be for time stamping only. |
| One record could break verification for good (A-3) | medium | One appended record with a malformed anchor or review crashed or permanently failed `verify`, the ALCOA++ report and the page, even in separate-user mode. | Fixed: malformed content is reported as a problem, never a crash, and the writer refuses malformed reviews from clients. |
| Records in the writer's name (C-5) | medium | Clients could send records as the writer itself, or of types only the writer writes (anchors, gap markers, start and stop), and review and ALCOA++ trusted them. | Fixed: the writer refuses them and records the attempt. |
| Faked anchor freshness (A-4) | medium | Any `trail.anchor` record, including one a client wrote, made the trail look recently anchored. | Fixed: only RFC 3161 anchors that the writer wrote count. |
| The drain operation dropped the sender (C-3) | medium | An agent could send its own records through the writer's "drain" operation, so they were stored as "spooled", without the writer's observation of who sent them. | Fixed: drained records keep the observation of the client that sent them (`observed.drained_by`). |
| ALCOA++ ignored verification problems (C-4) | medium | A cut-off or rolled-back trail was reported as "original: pass" and "complete: pass". | Fixed: both attributes fail on verification problems. |
| Duplicate record IDs (C-9) | medium | Two different records could be stored under one ID, so that references by ID became ambiguous. | Fixed: each ID is stored once; a different record with a known ID is refused. |
| "Intact" said nothing about coverage (C-10) | medium | "Intact" could be read as proof that nothing changed, although in user mode anyone who can read the service key can rewrite records after the last copy kept elsewhere. | Fixed: `verify` names the records that no outside head copy or verified anchor covers, and the README says what "intact" covers. |
| Secrets in excerpts (C-11) | medium | Common secret forms (for example `DB_PASSWORD=…`, `Authorization:` headers, private keys) passed the masking and stayed in the log for good. | Fixed: masking covers many more forms. Limit: masking is a safety net, and the log cannot be redacted later; set `excerpt_chars = 0` to keep no excerpts. |
| The setup script trusted the installation (C-14) | medium | In separate-user mode, an installation that the owner (and so an agent) could change let the agent run code as the writer and rewrite the log. | Fixed: the script refuses an installation that is not root's alone; `--check` runs only the checks. |
| Client-chosen time-stamp authority (C-12) | low | A client could make the writer ask any URL, or a test authority of its choice, for a time stamp. | Fixed: only the configured authority or the built-in TEST ONLY one (`test:`). |
| Lock file open to clients (C-13) | low | In separate-user mode, a client could hold the writer's lock and keep it from starting. | Fixed: the lock file is mode 0600. |
| Raw text in the terminal and in Markdown (C-15) | low | A crafted record could change what a reviewer saw in the terminal or in a Markdown report. | Fixed: control characters and markup that clients wrote are escaped. |
| A failed write broke the chain (C-16) | low | A disk error could leave a half-written line and a permanently "broken" trail. | Fixed: short writes are completed and a failed write is cut back. |
| No review in separate-user mode (C-18) | info | `review run` could not save its worksheet when the trail belongs to another user. | Fixed: `review run --out DIR`, with a fallback folder. |

### d. Workflow decisions

| Finding | Severity | What it allowed | Fix or limit |
|---|---|---|---|
| A quarantine signature reused for another case (D-1, AQT-EI-002, KEYS-03) | high | With one genuine signed decision as a template, an agent could release any held content, turn a revocation into a trust, or trust any domain, without key or passphrase, because unsigned fields chose the case. | Fixed: a decision acts only through what it signs; a record whose other fields differ is a `mismatch` and has no effect. |
| An old trust replayed over a revocation (AQT-EI-003) | high | Appending an old "trust this source" record again undid a later signed revocation. | Fixed: each signed decision counts once, in the order it was signed. |
| Quarantine signatures from before enrolment (KEYS-10, B-3) | medium | A decision signed before its key was enrolled was honoured. | Fixed: it is `unknown-signer`, as in aqt-signoff. |
| CAPA independence checked on the wrong signatures (AQT-EI-011, KEYS-07) | high | An unverified record naming another signer, combined with a valid self-approval, met the rule that the implementer may not approve their own corrective action. | Fixed: independence and policy are checked on exactly the signatures that verify, and an error in the check never counts as an approval. |
| CAPA steps are unsigned (D-6) | low | In a plain evidence file, an agent can forge an unsigned closure, and rebuilding the CAPA index then shows the deviation as closed. | Documented limit: with aqt-trail, such a record is attributed to the process that wrote it. Signed CAPA steps are deferred work. |
| Action approval tied to a stored hash (AQT-EI-004, KEYS-02) | high | Editing the action database could run a different command under an existing approval. | Fixed: the stored action is hashed again before an approval counts and before a claim, and `run` executes that verified command. |
| A file approval used as an action approval (AQT-EI-005) | high | A signature approving a document could authorise running an action. | Fixed: only approvals of the action itself authorise a claim. |
| A database rollback allowed a second run (AQT-EI-006) | high | Resetting one status in the action database let an approved action run twice. | Fixed: a claim record in the evidence refuses a second claim. Limit: with a plain evidence file, an agent can delete that record too; the trail would show it. |
| Grace period shorter than the run time (D-4) | medium | A command that was still running was shown as "unknown", could be resolved as "not applied" and then run again. | Fixed: the grace period is never shorter than the run timeout (default 11 minutes). |
| Payload binding was optional (D-5) | medium | A person approved content X, but the executor could leave out the payload and use content Y. | Fixed: an action that binds a payload needs exactly those bytes at claim and run, and `run` passes them on standard input. Limit: a command that reads its payload from a file path is not bound. |
| The change gate trusted the agent's own copy (D-2) | medium | The gate and `finish` counted receipts and reviews from aqt-change's local copy of its records, which the agent can edit, even when aqt-trail was in use. | Fixed: with aqt-trail in use, a receipt or review counts only if the trail holds the same record, received from its sender over the writer's socket; otherwise the gate gives NO-GO or MANUAL. Limits below. |
| Hidden working-tree changes (D-3) | medium | Marking files with `git update-index --skip-worktree` hid a change, so the tests ran on one version and GO shipped another. | Fixed: such files are checked by their content; a hidden change gives NO-GO, and `finish` refuses. |

### e. The local web page

| Finding | Severity | What it allowed | Fix or limit |
|---|---|---|---|
| Release of content that was not shown (AQT-UI-001) | high | The page could show harmless text while the signature released different held content. | Fixed: held content is shown and released only while it has the recorded hash, and the hash shown is passed to the release. |
| Worksheet swapped before signing (AQT-UI-002) | high | An agent could change the worksheet file between showing and signing, so the person signed findings they never saw. | Fixed: the page signs the worksheet it showed, bound by a digest. |
| Action shown is not the action approved (AQT-UI-003) | high | The page approved the stored hash even when the specification it showed did not match it. | Fixed: an action can be decided only while its specification hashes to the hash that is signed. |
| Green status after the file changed (AQT-UI-004) | medium | After a good check, a replaced or edited trail file still showed "intact". | Fixed: the status is bound to the bytes verified; a change shows "changed since the last check". Limit: a swap exactly while the check runs is not caught. |
| No request timeouts (AQT-UI-005, E-7) | medium | Any local process could tie up the page with unfinished requests. | Fixed: 20-second timeouts and at most 32 connections at once. |
| Negative `Content-Length` (AQT-UI-006, E-5) | medium | A request could get past the 64 KiB body limit and exhaust memory. | Fixed: refused; the body is read exactly. |
| Login token visible to other processes (E-1) | medium | The browser was started with the login link in its command line, which every local process can read, so another process could log in first. | Fixed: the browser opens a private page that forwards to the link; a fresh link replaces older ones, and each use is printed in the terminal. |
| Cookie shared with other local servers (E-2) | medium | Browsers send cookies for 127.0.0.1 to every port, and the cookie alone gave a full session. | Fixed: every request also needs a session key that the page keeps per tab and sends in a header, never in a cookie. |
| Hidden characters in shown text (E-3) | medium | Invisible or right-to-left characters could make a command read differently from what is stored and signed. | Fixed: they are shown as `<U+XXXX>`, and an action that contains them is flagged. |
| The agent check around the page (E-4) | low | A request from a detached process that still carried an agent's environment passed the check, and nothing recorded which process had sent it. | Fixed: the sender's environment is checked, other users' processes are refused, and the terminal log names the process. Limit: the check is a guard, not a boundary. |
| A foreign cookie locked you out (E-6) | low | Any other local page could set a cookie that broke the login. | Fixed: the cookie header is parsed by hand. |
| File verification read any file (E-8) | info | Verifying a path loaded the whole file into memory. | Fixed: only regular files up to 64 MiB, read in pieces. |

## Limits that remain

These are known and documented in the package READMEs. They follow from the threat model: an agent that runs as you can do what you can do, so in the default setup the toolkit detects many attacks rather than preventing them.

**Keys and signatures**

- **The registry check covers aqt-signoff only.** aqt-signoff, and the plan and CAPA approvals that aqt-change and aqt-capa ask it about, count a key only with its enrolment record. aqt-quarantine decisions and aqt-trail review signatures still trust `signers.json` as it is. Run `aqt-signoff signers check` to find keys that lack an enrolment record.
- **An agent can still enrol a key of its own.** It needs no passphrase but one it chose itself: it can write an enrolment record signed with its own new key. The record is then in the trail, attributed to the agent's process, and `aqt-signoff signers check` lists the key. Review every enrolment.
- **Old key backups.** Copies of key files made before the review keep the weak PBKDF2 encryption. After `aqt-signoff rekey`, replace those backups.
- **Revocation is judged by the signed time.** Someone who holds a revoked key can still sign with an earlier date; `verify` warns when such a signature was stored after the revocation.

**The audit trail**

- **Tamper-evident, not tamper-proof.** In user mode, the writer's service key is readable by any process of your user. A re-signed edit is then found only by head copies kept on another device, or RFC 3161 time stamps, made after the edit. Separate-user mode prevents this.
- **Attribution is a heuristic.** A process started with `setsid -f`, `systemd-run --user` or `tmux send-keys` into a person's shell can still look like a complete, human process chain.
- **Test time stamps.** A client can still ask the writer for a TEST ONLY time stamp (`test:`). `verify` and the ALCOA++ report count it as verified only with `--test-tsa`, but the review query `unanchored_head` does not check the certificate chain, so a test time stamp resets it.
- **Unsigned bundle manifest.** `MANIFEST.json` in an export bundle is a convenience; trust comes from the key, CA and registry you pass.
- **Unregistered reviewers.** Without any signer registry, a review can still be signed; `verify` then only warns that the reviewer's identity is unchecked.
- **Side files.** Records that exist only in the plain evidence file or the spool are not chained or signed by the writer. The tools do not yet insist on trail records when a trail exists (specification §10.5).

**Workflow decisions**

- **aqt-change with aqt-trail.** A same-user agent can still send a made-up receipt through the writer's socket; the trail keeps it together with the agent's process chain. In user mode it can also edit the trail file; `aqt-trail verify` reports that, but the gate only looks records up. aqt-change's local copy still decides which records belong to a project and in which order, so deleting a later failing run of an unchanged tree from it is not noticed by the gate (the trail keeps the run). The `change.finish` record and the approval target are read from the local copy. Without aqt-trail, nothing changed: the local copy counts as it is.
- **Approved actions with a plain evidence file.** "Runs at most once" relies on the claim record. In a plain evidence file, an agent can delete it together with the database state; in the trail, the deletion is detected.
- **Quarantine journal.** Deleting a later decision (for example a revocation) from the journal, which the agent can write, brings the earlier decision back. With aqt-trail, the deleted record is still in the trail.
- **CAPA.** Accept, dismiss, classify, investigation, recorded approval, cancel, extend and close are unsigned records. Without aqt-signoff installed, a signature found in the evidence counts as `signed-unverified`.

**The local web page**

- A decision made in the page is recorded with the observation of the aqt-ui server, not of the browser; the terminal log names the sending process.
- A same-user process that detaches from the agent and clears its environment, reads the private login page before the browser does, or swaps the trail file exactly during a check is not stopped. The passphrase remains the real control.
- The private forward page that opens the browser has not been tested in a real browser yet.

**Deferred, not security-critical**

- A malformed `quarantine.held` line in the journal stops the journal from being read; the hook then withholds all tool output. This fails safe but blocks work.
- A forged later `quarantine.held` record for an existing case replaces that case in the case store. It cannot release anything, because a release binds the case ID and the content hash.

## Verification of the fixes

A second, independent check of the high-severity fixes is in progress.

## Sources

- Reviewed commit: `363b445` (22 October 2026). Findings reported: 29 October 2026. Fixes merged: 29 October 2026.
- The fixes: `git log 363b445..` and the "Security" entries in the `CHANGELOG.md` of [aqt-spec](../aqt-spec/CHANGELOG.md), [aqt-trail](../aqt-trail/CHANGELOG.md), [aqt-signoff](../aqt-signoff/CHANGELOG.md), [aqt-change](../aqt-change/CHANGELOG.md), [aqt-quarantine](../aqt-quarantine/CHANGELOG.md), [aqt-capa](../aqt-capa/CHANGELOG.md) and [aqt-ui](../aqt-ui/CHANGELOG.md).
- The threat model and limits per package: the "Threat model and limits" section of each package README.
- How to report a vulnerability: [SECURITY.md](../SECURITY.md).

Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.
