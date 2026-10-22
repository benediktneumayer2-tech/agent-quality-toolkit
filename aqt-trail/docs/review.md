# Audit-trail review

Draft Annex 11 (2025) §12.5–12.8 asks for a documented, risk-based review of audit trails by people not involved
in the activities, with significant findings investigated. aqt-trail supplies the tooling; the procedure,
frequency and follow-up remain yours.

## 1. Run

```sh
aqt-trail review run --since 2026-10-14T00:00:00Z --until 2026-10-21T00:00:00Z [--profile FILE]
```

The scope is every record whose writer time falls in the period. The worksheet
(`<state>/reviews/<id>/worksheet.json` and `.md`) contains the seq range, the head hash at its end, the profile
and its hash, the actors in scope (they may not sign) and the findings.

| Query | Flags | Severity |
|---|---|---|
| `self_approval` | approved/released/verified/reviewed by the actor who authored the linked or same-subject record | major |
| `missing_reason` | human decisions (meaning set, or an action such as approve/release/waive) without a reason | major |
| `attribution_mismatch` | claims a human but an agent harness was observed; claims an agent but none was observed | major / minor |
| `gaps` | `trail.gap`, spooled records, `log.repaired`, writer downtime, a start without a stop | major … info |
| `out_of_hours` | human actions outside configured hours and workdays (`[review] timezone`) | minor |
| `repeated_failures` | ≥ N failed, refused or unknown outcomes by the same actor on the same action within a window | major |
| `time_anomalies` | `clock.jump`, client/writer skew above `skew_ms`, writer time going backwards | major / minor |
| `actor_changes` | the same subject acted on by several actors within a window | info |
| `invalidated_signatures` | `signoff.invalidation` records | major |
| `unanchored_head` | records not covered by an anchor older than `unanchored_hours` | minor |

A profile file can select queries and override parameters (`examples/review-profile.toml`).

## 2. Sign

```sh
aqt-trail review sign <worksheet.json> --reviewer human:dora \
    --disposition all=ok --disposition F3=deviation --note F3="opened CAPA for the self-approval" \
    --reason "weekly audit-trail review"
```

- Dispositions per INTERFACES I6: `ok`, `explained` or `deviation`; the last two need a `--note`. Every
  finding needs one (`all=` sets a default).
- The key: `--key PEM`, or the reviewer's key in the shared key directory `$XDG_CONFIG_HOME/aqt/keys/` (as
  enrolled by aqt-signoff). An encrypted key asks for its passphrase at the terminal (re-authentication). When
  the reviewer is in `$XDG_CONFIG_HOME/aqt/signers.json`, the key must be one of their active keys; a revoked key
  is refused. Name and role come from the registry.
- **Refused** (and recorded as `trail.refused` with `attempted_action: review.sign`) when the command runs inside
  an agent session or without a terminal (`aqt_evidence.require_human`), when the reviewer was an actor in scope
  (`not_independent`), is not a `human:` identity, or when the trail at the end of the scope no longer has the
  worksheet's head (`stale_worksheet`).

The `trail.review` record carries `meaning: reviewed`, the reviewer as actor, a link to the record at the end of
the scope, and `data`: `worksheet`, `log_id`, `scope`, `head`, `profile`, `profile_sha256`, `actors_reviewed`,
`findings` (`id`, `query`, `severity`, `record_ids`, `disposition`, `note`), `conclusion`, `signer_registered`
and `signature` — a detached statement (`aqt_signature`, `signer {id, name, role}`, `key`, `meaning`,
`reason`, `signed_at`, `tz`, `record_type`, `nonce`, `subject`; aqt-spec `signature.schema.json`) signed with Ed25519 over its canonical JSON. The statement's subject hash
is the content hash of `data` without `signature`; `verify` checks both.

Findings with disposition `deviation` are the input aqt-capa's `scan` looks for.
