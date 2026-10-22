# Changelog

## 0.1.0 — unreleased

First version.

- Local web server on `127.0.0.1` only (Python standard library), one-time login link, session cookie,
  CSRF header and `Origin` check, Host check, strict Content-Security-Policy.
- Read-only mode with a ribbon when started inside an agent session or with `--read-only`.
- Per-request peer check: a decision sent by a process that runs under an agent is refused and the
  refusal is recorded by the owning package.
- Overview (trail state, ALCOA++ attributes, "Needs you" queue, tool health), Trail list with record
  inspector and verification, Quarantine cases with release and declare threat.
- Read-only Changes (gates, receipts, prepared actions), Signatures (verify, signer registry), CAPA and
  Qualifications views; approving a prepared action with the passphrase.
