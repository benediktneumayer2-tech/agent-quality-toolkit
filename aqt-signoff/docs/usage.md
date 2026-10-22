# Using aqt-signoff

## Signing practice

- Enrol each person once (`aqt-signoff init`). Choose a long passphrase; it is asked for at every signing. Never type it into an agent chat.
- Sign the exact artefact that was reviewed. For a changing document, sign each released revision; older signatures then show `invalidated`, which is the intended "appears unsigned" behaviour for content that changed.
- Do not paste the signature block into the signed file: that changes the file. Render it separately (`manifest --out`) or sign the file that already contains the text you want.
- Use `--author` (or an `authored` signature) so the two-person rule can exclude the author from approving.
- Share `signers export` with anyone who verifies elsewhere; they pass it with `--registry`.

## Statuses at a glance

| Status | What to do |
|---|---|
| `valid` | Nothing |
| `invalidated` | Content changed or the signer withdrew: review the new content and sign again |
| `revoked` | The key was revoked (or compromised) before this signature: investigate, re-sign with a new key |
| `unknown-signer` | Key not in your registry (or signed before enrolment): obtain the signer's registry entry, or treat as unsigned |
| `invalid` | The statement was altered or signed with another key: treat as a data-integrity event (raise a deviation) |

## Approved actions for agents

1. The agent prepares the action and tells the human its id: `aqt-signoff prepare --request-key <stable key> --description "…" -- <argv>`. Re-running the same command returns the same action; changing the argv under the same key is refused.
2. The human inspects `aqt-signoff show <id>` (argv, payload hash, preparer) and approves the shown hash: `aqt-signoff approve <id> --hash <hash> --reason "…"`.
3. The executor runs `aqt-signoff run <id>` (commands) or, for HTTP and manual effects, `claim` → do the effect once → `outcome`. In Python, use `with so.actions.claim(...) as claim:`; leaving the block without a report records `unknown`.
4. `failed` means a definite failure: prepare a revision (`prepare --revise <id> …`) and approve again. `unknown` means nobody knows: check the external system, then `resolve --as succeeded|not-applied --reason "…"`. Nothing is ever retried automatically.

Exit codes make this scriptable: `run` exits 0 only on `succeeded`; 1 for failed, unknown or refused; 2 when the record could not reach the sink (the outcome is kept; run `sync`).

## Running agents so they cannot approve

The passphrase is the control; the agent-session guard only catches accidents. For a stronger boundary, run agents in a sandbox (e.g. bubblewrap) that hides `$XDG_CONFIG_HOME/aqt/keys` and mounts `signers.json` and the state directory read-only. The agent can then prepare and claim but never enrol a key, sign or approve.

## Use from other tools

```python
from aqt_signoff import is_approved, verify_subject
statuses = verify_subject(sha256, sources=[trail_log])          # list[SignatureStatus]
ok = is_approved(sha256, meaning="approved", policy={"min_signatures": 2, "distinct_from_author": True})
```

To sign a record from another tool, use `subject = {"kind": "record", "ref": record["id"], "sha256": aqt_evidence.record_content_hash(record)}` and `Signoff.open().sign(subject, meaning, reason)`.
