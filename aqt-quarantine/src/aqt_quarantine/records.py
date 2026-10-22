"""Builders for the ``quarantine.*`` evidence records (aqt-spec 0.1, INTERFACES.md I5/I6)."""

from __future__ import annotations

from aqt_evidence import actor, new_record, subject

SERVICE = actor("service", "service:aqt-quarantine", role="quarantine")


def case_subject(case_id: str, content_sha256: str) -> dict:
    return subject("tool-result", f"case:{case_id}", sha256=content_sha256)


def passed(data: dict, *, tz: str | None) -> dict:
    ref = f"case:{data['case_id']}" if data.get("case_id") else f"tool-use:{data['source'].get('tool_use_id') or 'n/a'}"
    return new_record("quarantine.passed", SERVICE, "pass", subject=subject("tool-result", ref,
                                                                           sha256=data["content_sha256"]),
                      data=data, tz=tz)


def held(data: dict, *, tz: str | None) -> dict:
    return new_record("quarantine.held", SERVICE, "hold", subject=case_subject(data["case_id"], data["content_sha256"]),
                      data=data, tz=tz)


def decision(kind: str, who: dict, *, action: str, meaning: str, reason: str, subject_: dict, data: dict,
             links: list[dict] | None, tz: str | None) -> dict:
    return new_record(kind, who, action, subject=subject_, reason=reason, meaning=meaning, links=links, data=data,
                      tz=tz)


def refused(who: dict, *, attempted_action: str, reason_code: str, agent_markers: list[str], detail: str,
            extra: dict, tz: str | None) -> dict:
    data = {"attempted_action": attempted_action, "reason_code": reason_code, "agent_markers": agent_markers,
            "detail": detail[:500], **extra}
    return new_record("quarantine.refused", who, "refused", data=data, tz=tz)


def delivered(*, case_id: str, kind: str, decision_id: str, harness: str, session: str | None, mode: str,
              content_sha256: str | None, opened_id: str, tz: str | None) -> dict:
    data = {"case_id": case_id, "kind": kind, "decision": decision_id, "harness": harness, "session": session,
            "mode": mode}
    if content_sha256:
        data["content_sha256"] = content_sha256
    return new_record("quarantine.delivered", SERVICE, "deliver",
                      subject=subject("tool-result", f"case:{case_id}", sha256=content_sha256) if content_sha256
                      else subject("tool-result", f"case:{case_id}"),
                      links=[{"rel": "case", "ref": opened_id}, {"rel": "decision", "ref": decision_id}],
                      data=data, tz=tz)
