# Changelog

## 0.1.0 — unreleased

First version.

Security review fixes (same version, not yet released):

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
