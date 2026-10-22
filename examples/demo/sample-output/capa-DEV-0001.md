{
  "actions": [
    {
      "action_id": "CAPA-0001-1",
      "after_sha256": "sha256:8680250597770f0cb10cd3161c1a10b4b822c6f2352cefe6af5239ca35bb8957",
      "approval": {
        "approved": true,
        "at": "2026-10-22T17:16:26.509422Z",
        "by": "human:qm-demo",
        "record": "rec_01a1649d340dbfbe466a6cb79a7e",
        "status": "signed-verified"
      },
      "before_sha256": "sha256:4838893782e1e388ed5656d81e487d17708e7480a437ac1e0e09cc1158c6e37b",
      "criterion": {
        "match": {
          "category": "instructions"
        },
        "max": 0,
        "type": "no-recurrence",
        "window": {
          "days": 7,
          "sessions": 2
        }
      },
      "description": "Forbid agents to decide quarantine cases",
      "kind": "corrective",
      "last_evaluation": {
        "action_id": "CAPA-0001-1",
        "approval": "signed-verified",
        "counts": {
          "days": 8,
          "gaps": 0,
          "recurrences": 0,
          "sessions": 2,
          "undecided": 0
        },
        "dev_id": "DEV-0001",
        "reasons": [
          "no recurrence in a complete window"
        ],
        "recurrences": [],
        "result": "effective",
        "start": "2026-10-22T17:16:26.509422Z",
        "target_hash_ok": true,
        "undecided": [],
        "window": {
          "days": 7,
          "sessions": 2
        }
      },
      "path": "AGENTS.md",
      "state": "implemented",
      "verify": "ok"
    }
  ],
  "deviation": {
    "basis": "effective",
    "candidate_id": "C-cecc9d10",
    "category": "instructions",
    "closed_at": "2026-10-22T17:16:27.046359Z",
    "description": null,
    "dev_id": "DEV-0001",
    "due": "2026-10-29T17:16:26.318961Z",
    "num": 1,
    "occurred_at": "2026-10-22T17:16:24.953464Z",
    "opened_at": "2026-10-22T17:16:26.319505Z",
    "opened_by": "human:dev-demo",
    "severity": "major",
    "source_ref": "rec_01a1649d2df69ea7ba713b9f7320",
    "source_type": "quarantine.refused",
    "state": "closed",
    "subject_ref": null,
    "title": "Refused attempt: release by human:qm-demo (agent_context)"
  },
  "investigation": {
    "dev_id": "DEV-0001",
    "factors": [
      {
        "category": "method",
        "text": "no rule on quarantine decisions in AGENTS.md"
      },
      {
        "category": "environment",
        "text": "deny rules for decision commands not installed"
      }
    ],
    "root_category": "instructions",
    "root_cause": "Agent instructions do not forbid deciding quarantine cases",
    "whys": [
      "the agent ran aqt-quarantine release",
      "it treated the hold as a blocker to remove",
      "AGENTS.md says nothing about quarantine decisions"
    ]
  },
  "links": [
    {
      "ref": "rec_01a1649d2df69ea7ba713b9f7320",
      "rel": "source"
    }
  ],
  "similar": [],
  "timeline": [
    {
      "action": "accepted",
      "actor": "human:dev-demo",
      "id": "rec_01a1649d334eda7dca485075c834",
      "reason": "The agent tried to release its own quarantined input",
      "time": "2026-10-22T17:16:26.319505Z",
      "type": "capa.deviation"
    },
    {
      "action": "recorded",
      "actor": "human:dev-demo",
      "id": "rec_01a1649d335c11b6d16aca2c872e",
      "reason": null,
      "time": "2026-10-22T17:16:26.332519Z",
      "type": "capa.investigation"
    },
    {
      "action": "planned",
      "actor": "agent:demo-agent:worker-1",
      "id": "rec_01a1649d338e8216f4b0d2eb20e4",
      "reason": null,
      "time": "2026-10-22T17:16:26.382836Z",
      "type": "capa.action"
    },
    {
      "action": "implemented",
      "actor": "agent:demo-agent:worker-1",
      "id": "rec_01a1649d33c252e27d89a24c0b49",
      "reason": null,
      "time": "2026-10-22T17:16:26.435266Z",
      "type": "capa.action"
    },
    {
      "action": "evaluated",
      "actor": "service:aqt-capa",
      "id": "rec_01a1649d341d825e64f30b5282cf",
      "reason": null,
      "time": "2026-10-22T17:16:26.525509Z",
      "type": "capa.effectiveness"
    },
    {
      "action": "evaluated",
      "actor": "service:aqt-capa",
      "id": "rec_01a1649d3616d37dd2b186f1909f",
      "reason": null,
      "time": "2026-10-22T17:16:27.030808Z",
      "type": "capa.effectiveness"
    },
    {
      "action": "closed",
      "actor": "human:qm-demo",
      "id": "rec_01a1649d36252d33b1fdf0c14758",
      "reason": "Corrective action effective; no recurrence in the window",
      "time": "2026-10-22T17:16:27.046359Z",
      "type": "capa.closure"
    }
  ]
}
