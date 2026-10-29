# Audit-trail review

Draft Annex 11 (2025) §12.5–12.8 asks for a documented, risk-based review of audit trails by people not involved
in the activities, with significant findings investigated. aqt-trail supplies the tooling; the procedure,
frequency and follow-up remain yours.

## 1. Run

```sh
aqt-trail review run --since 2026-10-14T00:00:00Z --until 2026-10-21T00:00:00Z [--profile FILE] [--out DIR]
```

The scope is every record whose writer time falls in the period. The queries see the trail up to the end of the
scope (not records written later), so the worksheet can be recomputed exactly when it is signed. The worksheet
(`<id>/worksheet.json` and `.md` in `--out`, else `<state>/reviews`, else — when that is not writable, as in
separate-user mode — `$XDG_STATE_HOME/aqt/trail-reviews`) contains the seq range, the head hash at its end, the
profile (name, queries, parameters, hash), the actors in scope (they may not sign) and the findings. It is a working
copy, not evidence: anyone who can write the folder can change it, so signing never trusts it (section 2).

| Query | Flags | Severity |
|---|---|---|
| `self_approval` | approved/released/verified/reviewed by the actor who authored the linked or same-subject record | major |
| `missing_reason` | human decisions (meaning set, or an action such as approve/release/waive) without a reason | major |
| `attribution_mismatch` | claims a human but an agent harness was observed (major); claims a human but the sender's process chain was incomplete or unreadable, `observed.chain_status` partial/unavailable (minor); claims an agent but none was observed (minor); claims a human in records written before `chain_status` existed (info) | major … info |
| `gaps` | `trail.gap`, spooled records, `log.repaired`, writer downtime, a start without a stop | major … info |
| `out_of_hours` | human actions outside configured hours and workdays (`[review] timezone`) | minor |
| `repeated_failures` | ≥ N failed, refused or unknown outcomes by the same actor on the same action within a window | major |
| `time_anomalies` | `clock.jump`, client/writer skew above `skew_ms`, writer time going backwards | major / minor |
| `actor_changes` | the same subject acted on by several actors within a window | info |
| `invalidated_signatures` | `signoff.invalidation` records | major |
| `unanchored_head` | records after the last RFC 3161 anchor the writer wrote, when that anchor is older than `unanchored_hours` (exported heads are not counted: the trail cannot see where you keep them) | minor |

A profile file can select queries and override parameters (`examples/review-profile.toml`); a profile that leaves
out queries may not be called `default`.

## 2. Sign

```sh
aqt-trail review sign <worksheet.json> --reviewer human:dora \
    --disposition all=ok --disposition F3=deviation --note F3="opened CAPA for the self-approval" \
    --reason "weekly audit-trail review"
```

- Dispositions: `ok`, `explained` or `deviation`; the last two need a `--note`. Every
  finding needs one (`all=` sets a default).
- Before the passphrase prompt, `review sign` recomputes the worksheet from the trail itself (never from the
  `trail` path written in the worksheet) and prints what will be signed: scope, profile, actors and findings.
  Only the recomputed values are signed.
- The key: `--key PEM`, or the reviewer's key in the shared key directory `$XDG_CONFIG_HOME/aqt/keys/` (as
  enrolled by aqt-signoff). An encrypted key asks for its passphrase at the terminal (re-authentication). With a
  signer registry (`$XDG_CONFIG_HOME/aqt/signers.json`), the reviewer must be in it and sign with one of their
  active keys; a revoked key is refused, and a key registered to someone else is always refused. Name and role
  come from the registry. Without any registry a review can still be signed, but `verify` then reports the
  reviewer's identity as unchecked. `AQT_SIGNERS` and `AQT_KEYS_DIR` point to another registry or key directory,
  as in aqt-signoff and aqt-quarantine; `verify` uses the same registry (or `--signers FILE`).
- **Refused** (and recorded as `trail.refused` with `attempted_action: review.sign`) when the command runs inside
  an agent session or without a terminal (`aqt_evidence.require_human`), when the reviewer was an actor in scope
  (`not_independent`), is not a `human:` identity, is not registered (`unknown_signer`), uses another signer's key
  (`key_mismatch`) or an unregistered or revoked key (`unknown_key`, `revoked_key`), when the trail at the end of
  the scope no longer has the worksheet's head (`stale_worksheet`), when the trail does not verify up to there
  (`trail_broken`), or when the worksheet's scope, profile, actors or findings differ from the trail
  (`worksheet_mismatch`; run `review run` again).

The `trail.review` record carries `meaning: reviewed`, the reviewer as actor, a link to the record at the end of
the scope, and `data`: `worksheet`, `log_id`, `scope`, `head`, `profile`, `profile_sha256`, `profile_queries`,
`worksheet_sha256`, `actors_reviewed`, `findings` (`id`, `query`, `severity`, `record_ids`, `disposition`,
`note`), `conclusion`, `signer_registered` and `signature` — a detached statement (`aqt_signature`,
`signer {id, name, role}`, `key`, `meaning`, `reason`, `signed_at`, `tz`, `record_type`, `nonce`, `subject`;
aqt-spec `signature.schema.json`) signed with Ed25519 over its canonical JSON. The statement's subject hash is the
content hash of `data` without `signature`.

`verify` reports as a problem a `trail.review` that is unsigned; whose statement is not for `trail.review` with
meaning `reviewed`, or does not cover the review's content; whose signer is not the record's actor; whose key
belongs to someone else, was not enrolled yet or was revoked at `signed_at`, or (with a registry) is not in the
registry at all; whose head does not match the record at `scope.to_seq`; or whose `actors_reviewed` differ from the
trail or include the reviewer. Without a registry it warns that review signatures were not checked. `review list`
shows each review's signature state.

### For user interfaces

`aqt_trail.review.check_worksheet(sheet, records, log_id=, keys=, expected_sha256=)` recomputes a worksheet and
raises `ReviewRefused` with the codes above. A UI that shows a worksheet keeps `worksheet_digest(sheet)` (computed
over `aqt_worksheet`, `id`, `log_id`, `scope`, `profile`, `actors_reviewed`, `findings`) and passes it to
`build_review(..., expected_sha256=...)`; a worksheet changed or swapped after display is refused with
`worksheet_changed`. `records` must be read from the trail file itself.

Findings with disposition `deviation` are the input aqt-capa's `scan` looks for.
