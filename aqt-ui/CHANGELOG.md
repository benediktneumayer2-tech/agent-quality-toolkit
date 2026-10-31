# Changelog

## 0.1.0 — unreleased

First version.

One flow (same version, not yet released):

- Home is the *Needs you* queue: one line per case with how long it has been waiting, an empty queue
  says "Everything in order" with the trail status line. Trail status, ALCOA++, tool health and the
  refusals moved to a *Health* view; the tool views stay as secondary views.
- One page per case (`/case/<id>`): the subject and its STOP point (a red STOP when it waits for you),
  the evidence, and the allowed decisions, each with one sentence on its consequence, in the existing
  decision panel; after a decision the page shows the record ID and time and offers *Next case*.
  Cases without a decision show the evidence and the exact command. The case pages reuse the panels
  and server checks of the tool views.
- One page per change (`/change/<project>/<plan>`, API `GET /api/change/<project>/<plan>[?fresh=1]`):
  the timeline Plan → Checks → Review → Gate → Release with each step's state and evidence, the
  current STOP marked, whether the change is released (verified as `aqt-signoff verify --require
  released`, recording nothing) and the manifest.
- *Sign released* (`POST /api/change/<project>/<plan>/release`): `aqt-signoff sign --record
  <change.finish> --meaning released` after the agent check, a fresh gate evaluation that must be GO,
  the change.finish record and hash shown, and no earlier valid "released" signature by the same
  signer; `[policy.released]` applies as in `sign()` and is shown.
- The queue has one entry per plan, for the step it stops at: `plan_approval` (the gate waits for a
  signed plan version), `gate` (NO-GO or MANUAL), or `release` (finished, GO, not yet released).
  Queue entries carry `id` (the case page) and `since`; codes and keys stay next to the words.
- Keyboard: `j`/`k` move through the queue, `Enter` opens, `n` opens the next case, `Escape` closes a
  sheet; never while typing in a field. A banner names the fix when the trail writer is down.
- Labels in English and German; the change steps have their own German nouns (`STEPS_DE`).

Security review fixes (same version, not yet released):

- Round 4: test mode (`[anchor] test_tsa = true`) and the review profile's parameters are visible before signing:
  `/api/trail/status` has `test_mode` and `review_profile` (`params`, `differs_from_builtin`, `description`); the top
  bar says TEST MODE; Needs you has `test_mode` (high) and `review_params` (medium, every differing parameter with
  its built-in value); the review panel shows the profile, all parameters and a warning for each difference. A
  review prepared here binds `test_tsa` into the profile in test mode, as `aqt-trail review run` does.

- Round 3: the record inspector checks a detached signature against the registry reconciled with the trail's
  enrolment records (`TrailView.enrolled_signers`, shared with "last review"), so a key an agent added to
  `signers.json` with a self-signed enrolment record shows `unknown-key` (its enrolment waits for approval), not
  `valid`. Quarantine decisions follow aqt-quarantine's enrolment check.

- What you see is what you sign: held content is shown and can be released only while it has the
  recorded hash, and the hash shown is passed to aqt-quarantine (`expected_sha256`); a prepared
  action is decidable only while its stored specification hashes to the action hash; the review is
  signed over the worksheet this server prepared and showed (digest sent back), not the file on disk.
- The trail status is bound to the bytes that were verified: a replaced, truncated or modified file
  shows "changed since the last check" (critical in "Needs you") instead of "intact".
- Login: the browser is started with a private `0600` page that forwards to the link, so the token is
  in no command line; a fresh link replaces older unused ones; each use is printed in the terminal.
  The answer to the link is the page itself, carrying a per-session key that every API request must
  send in `X-AQT-CSRF`, so the cookie (sent by browsers to every port of 127.0.0.1) alone is no
  session. The page shell is served without a session; download links fetch with the key.
- The cookie header is parsed by hand: a foreign malformed cookie no longer locks you out.
- Hidden characters are shown as `<U+XXXX>` in every text of the page (`static/text.js`); a prepared
  action whose specification contains them is flagged.
- The peer check also reads the agent markers in the peer's environment and refuses other users'
  processes; the terminal log names the process (pid, uid, parents) behind every decision request.
- Request limits: a negative or malformed `Content-Length` is refused and the body is read exactly;
  20-second socket timeout; at most 32 connections at once; file verification reads only regular
  files up to 64 MiB, hashed in pieces.

Integration with the hardened packages (same version, not yet released):

- The review worksheet's digest is aqt-trail's `worksheet_digest`; it is kept with the worksheet in
  memory, compared with the one the page sends back and passed to `build_review` as `expected_sha256`,
  together with the service keys (`keys=`) and the log id (`log_id=`), as `aqt-trail review sign` does.
  The trail is read strictly for signing (`load_lines`). The signed review records the digest shown.
- Worksheets go to `<state>/reviews`, or to `$XDG_STATE_HOME/aqt/trail-reviews` when the trail state
  is not writable (separate-user mode), as `aqt-trail review run` chooses.
- "Last anchor" counts only writer-written RFC 3161 anchors whose token covers the checkpoint
  (`anchored_seq`); "last review" only reviews whose signature is `valid` against the signer registry
  (`signature_status`), a copied statement once. A forged, unsigned or replayed review or anchor no
  longer clears "Audit-trail review due" or "not anchored" in Needs you.
- Refusal codes of aqt-signoff and of the review (`registry_mismatch`, `payload_required`,
  `self_approval`, `not_independent`, ...) are shown in words (English and German) next to the code,
  in decision results and in the Overview's refusal list; the Signatures table shows why a signature
  is not valid (for example a replayed copy).
- Tests use a cheap scrypt cost for their keys (the suite runs in about half the time).

Second review round (same version, not yet released):

- Quarantine: a release needs the whole content on screen first (declaring a threat keeps the content withheld
  and may rest on the excerpt). The full view
  shows the content in pages of 200,000 characters; the browser session notes which pages of which
  content (case id and hash) it was sent, and the server refuses a decision (nothing signed) until
  every page was shown in that session. The excerpt view alone no longer offers a release. Journal
  lines that aqt-quarantine ignored (malformed, or a later `quarantine.held` for an existing case)
  are listed on the case and counted in the case list. API: `GET /api/quarantine/<id>?full=1&page=N`;
  the case answer adds `content.page`, `content.pages`, `content.complete`, `unseen_pages`,
  `needs_full_view` and `journal_problems`.
- Record inspector: shows `observed.chain_status` (and `drained_by`) and marks a human claim the
  writer could not confirm as "unconfirmed", with the review's wording (aqt-trail `attribution`; a
  spooled human claim is unconfirmed, or "agent" when an agent harness drained it); the Trail list
  marks such rows too. A detached signature is shown with its `signature_status` against the signer
  registry, and the list says "signature attached" instead of "signed".
- Login: the private forward page is in `~/aqt-ui-login-*` (folder `0700`, file `0600`), because
  snap-packaged browsers cannot read `$XDG_RUNTIME_DIR` or the host's `/tmp` (checked under snap
  Firefox's confinement); `$XDG_RUNTIME_DIR` or the temp directory remain the fallback without a
  usable home directory. The link is still printed.

Second slice (same version, not yet released):

- More decisions in the page, each with the passphrase, the hash or version shown, the read-only and
  peer checks, and recorded by the owning package as its command line does: trust a source or revoke
  that trust (aqt-quarantine), approve a plan version (aqt-signoff signature over the approval target),
  accept or dismiss a CAPA candidate, approve an implemented corrective action (aqt-signoff signature
  over the implementation record) and close a deviation (aqt-capa), sign the audit-trail review with
  the independence rule (aqt-trail). Download a verification bundle (no passphrase, records nothing).
- English and German labels with a switch in the top bar, remembered in `localStorage`.
- Trail list paged on the server (offset and limit, 100 per page); the record index keeps per-type
  aggregates, filtered selections and evidence-derived Overview results are cached until the trail
  grows. Tested with a generated 50,000-record trail.
- A light, quiet design (colour only for status and the one primary action); the decision panel is
  laid out as a signature block. "Needs you" comes first on the Overview, CAPA opens on waiting
  candidates, receipt test counts in words, long hashes wrap in the inspector, the Trail filters take
  two columns on a phone.

- Local web server on `127.0.0.1` only (Python standard library), one-time login link, session cookie,
  CSRF header and `Origin` check, Host check, strict Content-Security-Policy.
- Read-only mode with a ribbon when started inside an agent session or with `--read-only`.
- Per-request peer check: a decision sent by a process that runs under an agent is refused and the
  refusal is recorded by the owning package.
- Overview (trail state, ALCOA++ attributes, "Needs you" queue, tool health), Trail list with record
  inspector and verification, Quarantine cases with release and declare threat.
- Read-only Changes (gates, receipts, prepared actions), Signatures (verify, signer registry), CAPA and
  Qualifications views; approving a prepared action with the passphrase.
