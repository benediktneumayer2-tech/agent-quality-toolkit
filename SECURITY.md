# Security policy

Agent Quality Toolkit handles signatures, hash chains and sandbox boundaries, so security reports are welcome.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") instead of a public issue. Include the package, version, a description and, if possible, a reproduction. You will get an answer within two weeks.

## Scope

In scope: signature and chain verification that accepts tampered records, signature statements that can be replayed or rebound to other content, agent-context checks (`require_human`) that an agent can bypass without operating-system access, sandbox escapes in aqt-sensei, and secrets reaching evidence records.

Out of scope: attacks that need the owner's private keys or passphrases, root on the host, or a modified installation; detector evasion by adaptive prompt injection (detectors are a triage layer, see the README's honest scope).

## Status

Version 0.1 is a preview. The signing and verification code has not yet had an independent security review.
