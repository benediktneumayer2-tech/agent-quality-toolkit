# Changelog

## 0.1.0 — unreleased

First version.

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
