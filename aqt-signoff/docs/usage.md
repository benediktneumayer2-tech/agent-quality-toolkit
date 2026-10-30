# Using aqt-signoff

## Signing practice

- Enrol each person once (`aqt-signoff init`). Choose a long passphrase; it is asked for at every signing. Never type it into an agent chat.
- The first person enrolled counts at once. Everyone after that waits until an enrolled person approves them: the new person runs `init`, and someone who knows them runs `aqt-signoff signers check` (it prints the key id and the approve command) and then `aqt-signoff signers approve <id> --key <key id> --signer <you>`. Approve only people and keys you have checked; an approval is retroactive to the moment the request was recorded.
- Change a role with `aqt-signoff signers approve <id> --key <key id> --role <new role>` (by another signer); earlier signatures keep the role they were made with. Rotate your own key with `aqt-signoff init --id <id> --add-key` while the old key still counts: the old key approves the new one and is revoked. After a lost key (`revoke --lost`) the new key needs another signer's approval; if nobody else can approve, it is a re-bootstrap, which `signers check` flags until another signer approves it.
- Added aqt-trail after using the evidence file? Run `aqt-signoff signers import` once (it shows the earlier enrolment records and asks for your passphrase); until then keys enrolled before the trail do not count.
- Sign the exact artefact that was reviewed. For a changing document, sign each released revision; older signatures then show `invalidated`, which is the intended "appears unsigned" behaviour for content that changed.
- Do not paste the signature block into the signed file: that changes the file. Render it separately (`manifest --out`) or sign the file that already contains the text you want.
- Use `--author` (or an `authored` signature) so the two-person rule can exclude the author from approving.
- Share `signers export` with anyone who verifies elsewhere; they pass it with `--registry`.
- Run `aqt-signoff signers check` after enrolling someone and in periodic reviews: every key must count, the first signer must be who you expect, and a pending enrolment or a re-bootstrap you do not recognise is an incident (notes also mark keys enrolled outside `aqt-signoff init`). An edited role in `signers.json` makes the key stop counting; change roles with `signers approve --role`.
- Keys created before this version use PKCS#8 with a weak passphrase KDF; they are re-encrypted with scrypt at their next use, or now with `aqt-signoff rekey --signer <id>`.

## Statuses at a glance

| Status | What to do |
|---|---|
| `valid` | Nothing |
| `invalidated` | Content changed or the signer withdrew: review the new content and sign again |
| `revoked` | The key was revoked (or compromised) before this signature: investigate, re-sign with a new key |
| `unknown-signer` | Key not in your registry, its enrolment pending or not backed by the enrolment evidence (`aqt-signoff signers check` says why), or signed before enrolment: approve a pending enrolment you know, obtain the signer's registry entry and enrolment evidence, or treat as unsigned |
| `invalid` | The statement was altered, signed with another key, or copied into a second record (replay): treat as a data-integrity event (raise a deviation) |

## Approved actions for agents

1. The agent prepares the action and tells the human its id: `aqt-signoff prepare --request-key <stable key> --description "…" -- <argv>`. Re-running the same command returns the same action; changing the argv under the same key is refused.
2. The human inspects `aqt-signoff show <id>` (argv, payload hash, preparer) and approves the shown hash: `aqt-signoff approve <id> --hash <hash> --reason "…"`. A payload bound by hash must be presented to `claim`/`run` (`--payload FILE`); `run` passes it to the command on stdin, so write commands that read the payload from stdin rather than from a file path.
3. The executor runs `aqt-signoff run <id>` (commands) or, for HTTP and manual effects, `claim` → do the effect once → `outcome`. In Python, use `with so.actions.claim(...) as claim:`; leaving the block without a report records `unknown`.
4. `failed` means a definite failure: prepare a revision (`prepare --revise <id> …`) and approve again. `unknown` means nobody knows: check the external system, then `resolve --as succeeded|not-applied --reason "…"`. Nothing is ever retried automatically.

Exit codes make this scriptable: `run` exits 0 only on `succeeded`; 1 for failed, unknown or refused; 2 when the record could not reach the sink (the outcome is kept; run `sync`).

## Running agents so they cannot approve

The passphrase is the control; the agent-session guard only catches accidents. For a stronger boundary, run agents in a sandbox (e.g. bubblewrap) that hides `$XDG_CONFIG_HOME/aqt/keys` and mounts `signers.json` and the state directory read-only. The agent can then prepare and claim but never enrol a key, sign or approve.

## Use from other tools

```python
from aqt_signoff import check_signers, is_approved, verify_subject
statuses = verify_subject(sha256, sources=[trail_log])          # list[SignatureStatus]
ok = is_approved(sha256, meaning="approved", policy={"min_signatures": 2, "distinct_from_author": True})
# authors: the actor of any record with this content hash is excluded automatically; pass more with authors=[...]
report = check_signers()      # "ok"; "keys" (counts, pending, problems, notes); "pending"; "rebootstrap"; "problems"
problems = [k for k in report["keys"] if not k["counts"]]           # registry keys that do not count
```

To sign a record from another tool, use `subject = {"kind": "record", "ref": record["id"], "sha256": aqt_evidence.record_content_hash(record)}` and `Signoff.open().sign(subject, meaning, reason)`.
