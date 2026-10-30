# Security review, October 2026

In October 2026, eight AI reviewers tried to break the Agent Quality Toolkit (AQT) from the position of an AI coding agent that runs as the same Linux user as the person it works for. They reported 81 findings, 58 after merging duplicates. None of the 58 was rated critical, and 21 were rated high. 57 are fixed; one is a documented limit. Some fixes leave a smaller limit, listed [below](#limits-that-remain).

Two fresh AI verifiers then checked the fixes of all 21 high-rated findings and of five medium-rated ones. They found most of them sound, five only partly effective, and 13 new problems. Two further fix rounds addressed all of these; see [Verification of the fixes](#verification-of-the-fixes) and [Fix rounds 2 and 3](#fix-rounds-2-and-3). A second verification of those two rounds found six more problems, none rated high, and a fourth fix round fixed them; see [Fix round 4](#fix-round-4). The [status](#status) at the end sums up what this means.

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

The severity is the reviewers' own rating. When several reviewers reported the same problem, the finding is counted once, at the highest rating any of them gave. "Fixed" means that the code was changed to stop the reported attack; for A-12, an over-broad claim, it means that the documentation was corrected. The table counts the first fix round. Where the verification later found a fix incomplete, the row below says so.

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
- **Fixes.** Seven fix workers (AI agents) took the findings package by package. They were asked to reproduce each finding first, then make the smallest sound fix and add a regression test that fails before the fix and passes after it. Where a proper fix would have needed a breaking change or a redesign, they proposed a documented limit instead, and the lead agent that coordinated the fixes decided. After the first fix round and its integration, all 884 offline tests passed (`scripts/test_all.sh`), and the record library agreed with all 87 test vectors of the specification (57 before the review). After fix rounds 2 and 3, all 968 offline tests passed, and after fix round 4, all 985 pass.

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
| The signer registry was not checked (B-1, KEYS-01, B-5) | high | A same-user agent could add a person or a key to `signers.json`, change a role, or undo or backdate a revocation, and then meet two-person, role and "not the author" rules alone. No tool compared the file with the enrolment records. | Fixed in aqt-signoff, and so in the aqt-change and aqt-capa approvals that use it: a registry key counts only when its signed enrolment record matches it (from the trail when there is one). New: `aqt-signoff signers check`. The verification found this fix incomplete; it was completed in [round 3](#fix-rounds-2-and-3). |
| Weak key encryption (B-2, KEYS-11) | high | Key files used PBKDF2 with 2,048 iterations, so an agent that copied a key file could guess the passphrase offline, cheaply. | Fixed: new keys use scrypt (128 MiB of memory per guess) and AES-256-GCM; older keys are re-encrypted at their next use or with `aqt-signoff rekey`. Limit: copies of old key files keep the weak encryption. |
| Roles chosen by the signer (KEYS-05) | high | Any enrolled key could state any role in its signature and pass a rule such as "only the quality manager releases". | Fixed: the role comes from the registry and must equal the signed role. The verification found this fix incomplete; it was completed in [round 3](#fix-rounds-2-and-3). |
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
| Records in the writer's name (C-5) | medium | Clients could send records as the writer itself, or of types only the writer writes (anchors, gap markers, start and stop), and review and ALCOA++ trusted them. | Fixed: the writer refuses them and records the attempt. The verification found this fix incomplete; it was completed in [round 2](#fix-rounds-2-and-3). |
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
| The change gate trusted the agent's own copy (D-2) | medium | The gate and `finish` counted receipts and reviews from aqt-change's local copy of its records, which the agent can edit, even when aqt-trail was in use. | Fixed: with aqt-trail in use, a receipt or review counts only if the trail holds the same record, received from its sender over the writer's socket; otherwise the gate gives NO-GO or MANUAL. The verification found this fix incomplete; it was completed in [rounds 2 and 3](#fix-rounds-2-and-3). |
| Hidden working-tree changes (D-3) | medium | Marking files with `git update-index --skip-worktree` hid a change, so the tests ran on one version and GO shipped another. | Fixed: such files are checked by their content; a hidden change gives NO-GO, and `finish` refuses. The verification found this fix incomplete; it was completed in [rounds 2 and 3](#fix-rounds-2-and-3). |

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

## Verification of the fixes

**What was checked.** After the first fix round, two verifiers checked the fixes at commit `2d410e5` (29 October 2026). Each was a fresh Claude Opus 5.5 session, without the conversations in which the code was written or fixed; as in the review, that is the same model as the authors. Verification runs with OpenAI Codex were planned as well, for a second vendor, but OpenAI's safety filter for cybersecurity content stopped them, so they produced no results. This verification, unlike the review, therefore used models from one vendor only.

**How.** The verifiers read the changes since the reviewed commit, ran the package test suites, and re-ran the original proofs of concept, adapted to the new code, against a real trail writer in throw-away folders. They also looked for new ways around each fix.

**Results.** The counts use the reviewers' original IDs, so one finding of the tables above can appear under several IDs.

| Verifier | Scope | Fixed | Partly fixed | New problems |
|---|---|---|---|---|
| V1 | aqt-spec, aqt-signoff, aqt-quarantine, aqt-capa, aqt-change: 24 IDs (22 high, 2 medium) | 19 | 5: B-1, KEYS-01, KEYS-05, D-2, D-3 | 5: 1 high, 4 medium |
| V2 | aqt-trail, aqt-ui: 11 IDs (8 high, 3 medium) | 10 | 1: C-5 | 8: 2 medium, 6 low |

In plain words, the partly fixed findings were these:

- **Signer registry and roles (B-1, KEYS-01, KEYS-05).** Editing `signers.json` no longer worked, but an agent could still create its own key, write an enrolment record signed with that key, and so get a key that counted, an extra key for a real person, or a different role. This was the one new high-rated problem.
- **Change gate and the trail (D-2).** Whether the trail check ran depended on the environment of the process that ran the gate, which the agent controls.
- **Hidden working-tree changes (D-3).** Git settings other than the two index flags (an fsmonitor hook, relaxed stat checks) could still hide a change from `git status`.
- **Test time stamps (C-5).** Any client could ask the writer for a TEST ONLY time stamp and so make the trail look recently anchored.

The new problems, and what was done about each, are in [Fix rounds 2 and 3](#fix-rounds-2-and-3). These two rounds addressed every partly fixed and every new finding, with a fix or a documented limit. After them, all 968 offline tests passed.

**Second verification.** After fix rounds 2 and 3, one more fresh Claude Opus 5.5 session (V3) checked them at commit `3a6dc1e` (30 October 2026), in the same way and again without changing the code: it ran the package test suites in an offline copy, re-ran the earlier proofs of concept and wrote new ones, partly against a real trail writer. It re-checked 19 earlier findings and fixes: 14 held, 5 held only in part. It found no regressions, and 6 new problems: 5 rated medium, 1 low, none high or critical.

In plain words, the partly effective fixes were these:

- **Re-bootstrap warning.** The documented limit relied on a loud warning after a re-bootstrap. A key that the re-bootstrapped key had approved itself could "confirm" it, which ended the warning, and revocations that nobody had signed left no trace in `signers check`.
- **Local ignore rules.** An untracked `.gitignore` inside the working tree still counted as a rule of the repository.
- **Project settings for the change gate.** They could be dropped in the middle of a plan.
- **TEST ONLY anchors and the review profile (C-5 and a V2 finding).** Test mode and changed review parameters, both set in a file the agent can edit, were not shown on the aqt-ui page.

The six new problems, and what was done about each, are in [Fix round 4](#fix-round-4).

## Fix rounds 2 and 3

Round 2 followed the verification on 29 October 2026. Round 3 (29 and 30 October 2026) completed the change gate and, after the owner decided that a new signer must be approved by someone already enrolled (counter-signature), the enrolment. "V1" and "V2" name the verifier who found the problem; the rating is the verifier's, and problems found during the fix rounds were not rated (–).

| Problem | Rating | Fix (round) | Limit that remains |
|---|---|---|---|
| **An agent could enrol a key of its own** (V1; completes B-1, KEYS-01, KEYS-05). A self-signed enrolment record made a key count. | high | **Counter-signed enrolment** (3). The first signer counts at once. Every later enrolment, extra key or role change counts only after an enrolled signer approves it with their passphrase (`aqt-signoff signers approve`); until then the key is *pending* and cannot sign. Nobody approves their own enrolment or role. A key rotation (`init --add-key`) is approved by the old key, which is revoked in the same step. Enrolment times are the trail writer's times, not times the client states. | The first enrolment of an empty store counts without approval. After every key was revoked, a new key counts as a flagged *re-bootstrap*. Without a trail, the evidence file can be reordered. See [below](#limits-that-remain). |
| **aqt-trail, aqt-quarantine and the page trusted `signers.json` as it is** (V1 and V2) | medium | aqt-trail counts a registry key only when its enrolment records in the trail back it, with aqt-signoff's rules; `review sign` refuses another key (`unenrolled_key`) and `verify` reports its signatures; the page's "last review" uses the same check (2). aqt-quarantine decisions and the page's record inspector use it too, all with the counter-signature rules (3). | Without aqt-signoff installed, the keys rest on `signers.json` alone; `aqt-trail verify` and `aqt-quarantine doctor` say so. |
| **Adding aqt-trail later made earlier signatures `unknown-signer`** (V1, a regression of the first round) | medium | `aqt-signoff signers import` carries the enrolment and revocation records written before the trail into it once, signed by a signer whose key counts, keeping their order and times (3). Until then `signers check` and `aqt status` say so, and signing refuses (`import_needed`). | Records added to the old file after the import do not count (enforced only since [round 4](#fix-round-4)). |
| **The change gate's trail check depended on the agent's environment** (V1; completes D-2) | medium | Project setting `require_trail = true` in the committed `.aqt/change.toml`: when no trail log is found, the gate is NO-GO, `finish` refuses and the hooks block (2). Without the setting, records that came back from a writer keep the check on (MANUAL). `trail_keys` pins the trail writer's key, so a log the agent wrote itself confirms nothing, and gate policy committed in `[gate]` cannot be relaxed by the user configuration (3). | In user mode the agent can read the writer's key, so the pin is real only in separate-user mode. A gate is only as trustworthy as the environment it runs in (your own shell or CI). |
| **Changes hidden by an fsmonitor hook or relaxed stat checks** (V1; completes D-3) | medium | The tree fingerprint hashes the content of every tracked file instead of trusting `git status`; Git runs with these settings switched off; a hidden change gives NO-GO (2). Untracked files that only local ignore rules hide (`.git/info/exclude`, a global excludes file) are fingerprinted and give MANUAL (3). | Local clean filters (`.git/info/attributes`) are not covered, because hashing raw content would break Git LFS. A committed `.gitignore` change can hide a file, visibly in the diff. |
| **Release offered for content the person was not shown** (V2): the full view stopped at 200,000 characters, and a later journal line could steer the highlighted passages | medium | The full content is shown in pages of 200,000 characters, and a release is offered and accepted only after every page was shown in that browser session. A case is what its first opening record says: a later `quarantine.held` line for the same case changes nothing and is listed on the case (2). A threat may be declared from the highlighted passages, because a threat keeps the content withheld (lead decision after round 2). | – |
| **Any client could reset `unanchored_head` with a TEST ONLY time stamp** (V2; completes C-5) | low | TEST ONLY anchors count only in test mode (`--test-tsa`, or `[anchor] test_tsa = true`); otherwise `verify` warns and the review, ALCOA++ `enduring`, `status` and the page ignore them. An exported-head note no longer improves `enduring` (2). | Clients may still request test time stamps, for the documented demo flow. |
| **A review profile named `default` could weaken the queries** (V2) | low | The profile's parameters are shown on the worksheet and before signing, differences from the built-in defaults are flagged and signed, and `verify` checks them; a profile named `default` may not change parameters (2). | – |
| **A copied review counted twice, and any review reset "review due"** (V2) | low | A copied review counts once (`verify` reports the copy); `status` and the page show the last review whose signature is valid (2). | – |
| **A person's claim pushed through the drain operation by an agent was not flagged** (V2) | low | Such a record is judged by the process that pushed it (`observed.drained_by`): an agent is an `attribution_mismatch`, an incomplete chain an unconfirmed claim (2). | Attribution stays a heuristic. |
| **The page's record inspector ignored chain status and signature status** (V2) | low | The inspector shows `chain_status` and `drained_by`, marks unconfirmed human claims, and shows each detached signature with its verification status (2), checked against the enrolment records (3). | – |
| **The login page was unreachable for snap-packaged browsers** (V2) | low | The private forward page is now in `~/aqt-ui-login-*` (folder 0700, file 0600), which snap browsers can read (2). | Flatpak browsers: use the printed link. After a crash, a folder with a dead link may remain; delete it. |
| **A tested change could stay out of the finish commit** (found during round 2) | – | `finish` refuses when its commit would not hold what the receipts tested; after a finish without a commit, the gate gives MANUAL until HEAD holds it (3). | Untracked files outside the plan's paths may stay out; the scope check lists them. |
| **The user configuration could weaken aqt-change** (found during round 3), for example `fingerprint_exclude = ["**"]` | – | From the user configuration, `fingerprint_exclude` leaves out only untracked files outside the plan's paths, and a path allowed only by its `always_allowed_paths` gives MANUAL; both count fully only in `.aqt/change.toml` (3). | – |
| **A check run that changed the code while it ran counted as a pass** (found during round 3), for example a test that patches the code and deletes itself | – | Such a run gives MANUAL (`command_modified_worktree`), and `finish` refuses until a later run of the same check leaves the tree unchanged (3). | The Claude Code `Stop` hook does not block on it; the gate and `finish` do. |
| **Two quarantine journal problems listed as deferred after round 1:** one malformed line stopped all reading of the journal, and a later `quarantine.held` line could replace a case | – | Malformed lines are skipped and reported, and the first opening record of a case wins (2). | – |

## Fix round 4

Round 4 (30 October 2026) followed the second verification. It fixed the six new problems of V3, and one that the lead agent found while updating these documents. The rating is V3's; the lead's problem was not rated (–). After the round, all 985 offline tests pass. No further verifier has checked the round-4 fixes yet.

| Problem | Rating | Fix | Limit that remains |
|---|---|---|---|
| **A re-bootstrap could be "confirmed" by a key it had approved itself** (V3). A process without any passphrase could write unsigned revocations of every key, enrol a key of its own (a re-bootstrap, which counts), enrol a second key, approve it with the first, and let the second "confirm" the first. `signers check` then passed, and two-person approvals by the two keys verified. | medium | Only a key that counted before the re-bootstrap can confirm it; a key that counts through the re-bootstrapped key (approved by it, directly or through others) never does. Every key that counted before is revoked by then, so a re-bootstrap stays flagged: `signers check` (exit 1), `aqt-signoff verify` and `aqt status` (warn). `signers check` also reports every revocation that neither the revoked key nor another counting key signed, and the re-bootstrap warning names the unsigned revocations before it. A backdated enrolment request is pending, never a re-bootstrap. | A re-bootstrap still counts, so that a solo owner can recover from a lost key, and so do keys it approves: the warning is the control. It cannot be acknowledged away, because an attacker could use that step too (lead decision). Enrol a second person in time: then a lost key is replaced through an ordinary approval, and any re-bootstrap that appears is a warning sign. |
| **A copied enrolment request disabled a person's key for good** (V3). Any process could append a copy of a signer's own enrolment request under a new record ID. The key then never counted again, all its earlier signatures showed `unknown-signer`, and this could not be undone. | medium | A copy of a request (the same signed statement in another record) counts once. A second, differently signed request for the same key, which needs that key, is still a conflict, but the key stops counting only from that record's time: earlier signatures keep counting, and `signers check` reports it. | – |
| **A second `signers import` could bring in a planted, backdated key** (V3). After the first import, any process could add a self-signed request to the old evidence file. The tools then asked the person to import again, and the second import made the planted key count from its made-up date. | medium | Only the first import counts: a second one is refused (`already_imported`) and ignored if written anyway. Records added to the old file after the trail started or after the import are never imported; `signers check` lists them as ignored instead of asking for an import. The preview of an import says what each key will become. | The first import carries what the old file holds at that moment, and that file is agent-writable: read the preview before you sign. |
| **Verifying signatures on another machine failed** (found by the lead agent). `signers export` wrote only the registry, so elsewhere no key counted ("without matching enrolment evidence"), and signed content showed UNSIGNED. | – | `signers export` adds the enrolment records that make the keys count (`enrolment_evidence`: requests, approvals, imports and revocations, in their order). `aqt-signoff --registry FILE` uses them when the evidence it reads holds no trail, and checks them like any other evidence. With a trail they are ignored, so an edited `signers.json` cannot bring in enrolments. | The export is only as trustworthy as the way it reached the verifier. `aqt-trail verify --signers FILE` does not use these records; the trail carries its own. |
| **Ignored files could decide a test run** (V3). An untracked `.gitignore` that ignores itself hid a helper that patched the code during the test run; a compiled `.pyc` file in `__pycache__/` could stand in for the source or for a test. The run passed, `finish` committed the wrong code, and the gate, even `gate --rerun`, said GO; a clean checkout of the commit failed. | medium | Only `.gitignore` files that are part of the repository take a file out of the tree fingerprint. Files that an untracked `.gitignore` hides are fingerprinted and give MANUAL (`locally_ignored_files`), and inside the plan's paths `finish` refuses. The `.gitignore` that tools put into their own folders (`.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.venv`, `.tox`, `.nox`) still counts. Every check run gives Python a fresh, empty bytecode cache, and the receipt records this (`env.python_bytecode: fresh`). | Other ignored files that a run may load are not checked: compiled extension modules next to the source, `.pyc` files without a source, other tools' build caches, the virtual environment. A command that clears its child processes' environment (for example tox) does not pass the fresh cache on. `gate --rerun` runs in the same working tree, so only a run on a clean checkout (CI) is decisive. |
| **The change gate's project settings could be dropped in the middle of a plan** (V3). A plain commit that removed `.aqt/change.toml`, plus an edit of the plan's base commit in `.git/aqt-change/plans/`, left no copy of the settings that counted. A plan that needed a signed approval reached GO without one. | medium | The settings also count from every base commit that the plan's `begin` records name (in aqt-change's own copy of the records and in the trail) and from every commit since a base that changed the file. A plan state whose base commit its records do not name gives `plan_base_mismatch`: NO-GO when the trail confirms another base commit, otherwise MANUAL; `finish` refuses. A commit that changed the file, even if a later one changed it back, gives MANUAL (`project_settings_changed`). | Without a trail, an agent that also rewrites the `begin` record in aqt-change's own copy is not noticed. A made-up second `begin` record sent through the writer gives only MANUAL. |
| **Test mode and changed review parameters did not show on the page** (V3). Both are set in `~/.config/aqt/trail.toml`, which the agent can edit. With them, the aqt-ui page dropped findings from the review worksheet and showed the trail as recently anchored, and a person signing the review there could not see why. | low | The page shows TEST MODE in the top bar and in Needs you, lists every review parameter that differs from aqt-trail's built-in defaults in Needs you, and shows the profile, all its parameters and each difference in the review panel before signing. A review prepared in test mode binds test mode into its signed profile, as `aqt-trail review run` does. | `trail.toml` can still be edited by any process of your user; the page makes the change visible, it does not prevent it. |

## Limits that remain

These are known and documented in the package READMEs. They follow from the threat model: an agent that runs as you can do what you can do, so in the default setup the toolkit detects many attacks rather than preventing them.

**Keys and signatures**

- **The first signer.** The first enrolment of an empty evidence store, or the first import into an empty trail, counts without approval. An agent that enrols before you becomes the first signer, and your own enrolment then waits. Enrol yourself first and check the first signer that `aqt-signoff signers check` and `aqt status` name.
- **Re-bootstrap.** After every counting key is revoked, the next new key counts without approval, so that a solo owner can recover from a lost key. A revocation without a signature (`--lost`) is accepted from anyone, because it can only take rights away; so forged revocations of every key followed by a new enrolment look the same as a recovery. `signers check`, `aqt-signoff verify` and `aqt status` keep flagging a re-bootstrap for good, and say when the revocations before it were unsigned; on purpose there is no step to acknowledge the flag, because an attacker could use that step too. Until you act on it, the new key and the keys it approves count. **Advice:** enrol a second person in time. Then a lost key is replaced through an ordinary approval, you never need a re-bootstrap, and any re-bootstrap that appears is a warning sign.
- **Approvals are human decisions.** Approve only people and keys you have checked; `signers check` shows who requested what, with the writer's observation of the sending process.
- **Without a trail**, the plain evidence file is agent-writable: an agent can reorder or delete enrolment and approval records. Use aqt-trail, and import the earlier records once; read the import's preview before you sign it.
- **Without aqt-signoff installed**, aqt-trail and aqt-quarantine cannot check enrolment records; the keys rest on `signers.json` alone, and they warn.
- **Enrolment while the writer is down** counts from when the spool is drained; signatures made in between show `unknown-signer` until signed again.
- **Old key backups.** Copies of key files made before the review keep the weak PBKDF2 encryption. After `aqt-signoff rekey`, replace those backups.
- **Revocation is judged by the signed time.** Someone who holds a revoked key can still sign with an earlier date; `verify` warns when such a signature was stored after the revocation. The same holds after a role change.

**The audit trail**

- **Tamper-evident, not tamper-proof.** In user mode, the writer's service key is readable by any process of your user. A re-signed edit is then found only by head copies kept on another device, or RFC 3161 time stamps, made after the edit. Separate-user mode prevents this.
- **Attribution is a heuristic.** A process started with `setsid -f`, `systemd-run --user` or `tmux send-keys` into a person's shell can still look like a complete, human process chain.
- **Unsigned bundle manifest.** `MANIFEST.json` in an export bundle is a convenience; trust comes from the key, CA and registry you pass.
- **Unregistered reviewers.** Without any signer registry, a review can still be signed; `verify` then only warns that the reviewer's identity is unchecked.
- **Side files.** Records that exist only in the plain evidence file or the spool are not chained or signed by the writer. The tools do not yet insist on trail records when a trail exists (specification §10.5).

**Workflow decisions**

- **aqt-change with aqt-trail.** A same-user agent can still send a made-up receipt through the writer's socket; the trail keeps it together with the agent's process chain. In user mode it can also edit the trail file; `aqt-trail verify` reports that, but the gate only looks records up. aqt-change's local copy still decides which records belong to a project and in which order, so deleting a later failing run of an unchanged tree from it is not noticed by the gate (the trail keeps the run). The `change.finish` record and the approval target are read from the local copy. Without aqt-trail and without `require_trail`, the local copy counts as it is, and an agent that rewrites both a plan's base commit and its `begin` record there is not noticed.
- **aqt-change and Git.** Git clean filters set only locally (in `.git/info/attributes`) are not covered; a committed `.gitignore` change can hide a file (visible in the diff); projects that rely on global ignore rules, or on an untracked `.gitignore`, see MANUAL until those patterns move into a committed `.gitignore`.
- **Ignored build output in the working tree.** A check run may load ignored files that the tree fingerprint does not cover: compiled extension modules next to the source, `.pyc` files without a source, other tools' build caches, the virtual environment. Python's own bytecode cache is fresh for every run, but a tool that clears the environment of its child processes (for example tox) does not pass that on. `gate --rerun` runs in the same working tree. Only a run on a clean checkout of the commit, for example in CI, is decisive; run the gate you rely on there.
- **Approved actions with a plain evidence file.** "Runs at most once" relies on the claim record. In a plain evidence file, an agent can delete it together with the database state; in the trail, the deletion is detected.
- **Quarantine journal.** Deleting a later decision (for example a revocation) from the journal, which the agent can write, brings the earlier decision back. With aqt-trail, the deleted record is still in the trail.
- **CAPA.** Accept, dismiss, classify, investigation, recorded approval, cancel, extend and close are unsigned records. Without aqt-signoff installed, a signature found in the evidence counts as `signed-unverified`.

**The local web page**

- A decision made in the page is recorded with the observation of the aqt-ui server, not of the browser; the terminal log names the sending process.
- Test mode and the review parameters come from `trail.toml`, which any process of your user can edit; the page shows them, it does not prevent the change.
- A same-user process that detaches from the agent and clears its environment, reads the private login page before the browser does, or swaps the trail file exactly during a check is not stopped. The passphrase remains the real control.
- The private forward page that opens the browser has not been tested end to end in a real browser. A browser that cannot open it, for example a Flatpak browser, needs the printed link.

**Deferred work**

- With a signed quarantine decision in the evidence, the quarantine hook reads the trail once per run (about 0.7 s with 100,000 records). A cache is planned.
- aqt-change: a mode in which `gate --rerun` runs the checks in a clean checkout of the commit, and MANUAL for ignored compiled modules or source-less `.pyc` files inside a plan's paths.
- `aqt-trail verify --signers FILE` does not use the enrolment records of a `signers export` file; with a trail, the trail's own records decide.

## Status

After four fix rounds and two verifications, no open high-rated finding is known. Every finding of the review and of both verifications was fixed or documented as a limit, and what remains is listed [above](#limits-that-remain) and in the package READMEs. The fixes of round 4 have not yet been checked by a further verifier. This was an AI-assisted review, not a professional security audit: read it as a careful first pass, not as a certificate, and check the controls you rely on in your own setup.

## Sources

- Reviewed commit: `363b445` (22 October 2026). Findings reported: 29 October 2026. First fix round merged: 29 October 2026.
- First verification: commit `2d410e5` (29 October 2026). Fix rounds 2 and 3: `git log 2d410e5..3a6dc1e`, merged on 29 and 30 October 2026.
- Second verification: commit `3a6dc1e` (30 October 2026). Fix round 4: `git log 3a6dc1e..ab1083c`, merged on 30 October 2026.
- The fixes: `git log 363b445..` and the "Security" entries in the `CHANGELOG.md` of [aqt-spec](../aqt-spec/CHANGELOG.md), [aqt-trail](../aqt-trail/CHANGELOG.md), [aqt-signoff](../aqt-signoff/CHANGELOG.md), [aqt-change](../aqt-change/CHANGELOG.md), [aqt-quarantine](../aqt-quarantine/CHANGELOG.md), [aqt-capa](../aqt-capa/CHANGELOG.md) and [aqt-ui](../aqt-ui/CHANGELOG.md).
- The threat model and limits per package: the "Threat model and limits" section of each package README.
- How to report a vulnerability: [SECURITY.md](../SECURITY.md).

Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.
