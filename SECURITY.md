# Security policy

Agent Quality Toolkit handles signatures, hash chains and sandbox boundaries, so security reports are welcome.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") instead of a public issue. Include the package, version, a description and, if possible, a reproduction. You will get an answer within two weeks.

## Scope

In scope: signature and chain verification that accepts tampered records, signature statements that can be replayed or rebound to other content, agent-context checks (`require_human`) that an agent can bypass without operating-system access, sandbox escapes in aqt-sensei, and secrets reaching evidence records.

Out of scope: attacks that need the owner's private keys or passphrases, root on the host, or a modified installation; detector evasion by adaptive prompt injection (detectors are a triage layer, see the README's honest scope).

## Threat model in brief

The adversary is an AI agent that runs as your Linux user: it can read and change what you can, but it does not know your passphrase. The passphrase-protected key is the real control for human decisions; the check for an agent session is a guard, not a boundary. In the default user mode the toolkit is tamper-evident, not tamper-proof: an agent can read the trail writer's service key, so a re-signed edit is found only by head copies kept on another device or by RFC 3161 time stamps made after it. Separate-user mode for the trail prevents that.

Since the October 2026 review:

- **Keys.** Passphrase-protected keys use scrypt and AES-256-GCM. Keys from earlier versions are re-encrypted at their next use or with `aqt-signoff rekey`; backup copies of those older key files keep the weak encryption, so replace them.
- **Signer registry.** aqt-signoff counts a key in `signers.json` only when its signed enrolment record (in the trail, when there is one) matches it. `aqt-signoff signers check` lists every key that does not count. aqt-quarantine and aqt-trail still read `signers.json` as it is. An agent can still write an enrolment record for a key of its own, signed with a passphrase it chose; that record is in the trail with the agent's process chain, and `signers check` lists the key, so review every enrolment.
- **Signatures count once.** A copy of a signed statement in another record is a replay (`invalid`). A quarantine decision acts only through what it signs, once, in the order it was signed.
- **Verification is strict.** `aqt-evidence verify` and `aqt-trail verify` accept only canonical record lines, and `--require-signature` needs `--key`.
- **Bundles need explicit trust.** `aqt-trail verify --bundle` trusts only the service key, time-stamp CA and signer registry you pass (`--pin-key`, `--tsa-ca`, `--signers`), never the copies inside the bundle.
- **Attribution is a heuristic.** The trail writer records how far it could follow the sender's process chain (`observed.chain_status`), and a record that claims a person counts as attributed only with a complete chain without an agent in it. A process started with `setsid -f`, `systemd-run --user` or `tmux send-keys` into a person's shell can still look complete.
- **Change control with the trail.** With aqt-trail in use, aqt-change counts a receipt or review only when the trail holds the same record, received from its sender over the writer's socket. A same-user agent can still send a made-up receipt through the socket (the trail keeps its process chain), and aqt-change's local copy still decides which records belong to a project.
- **The local web page.** The aqt-ui cookie alone is no session: every request also needs a session key that the page keeps per browser tab.

The full list of limits is in the [review report](docs/security-review-2026-10.md#limits-that-remain) and in the "Threat model and limits" section of each package README.

## Review status

In October 2026, AI reviewers running models from two vendors reviewed the code at commit `363b445` from the position of a same-user agent. This was an AI-assisted review, not a professional security audit. Every finding, its fix or documented limit, and what remains open are in the [review report](docs/security-review-2026-10.md).

Version 0.1 is a preview.
