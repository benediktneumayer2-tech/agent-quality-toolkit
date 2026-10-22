"""Human qualification decisions and requalification checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aqt_evidence import HumanCheckError, bytes_hash, require_human, subject

from . import evidence
from .protocol import Protocol, configuration_hash
from .stats import rate


class DecisionError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def qualify(run_dir: str | Path, *, decision: str, reason: str, sink, records: list[dict], human: dict,
            claimed_actor: dict, valid_days: int | None = None, accept_deviation: bool = False,
            environ: dict | None = None, chain: list[str] | None = None, stdin=None,
            now: datetime | None = None) -> dict:
    """Record a human ``validate.qualification`` (approve or reject) for a test run.

    Refuses inside agent sessions (``aqt_evidence.require_human``) and records the refusal as
    ``validate.refused``.
    """
    if decision not in ("approve", "reject"):
        raise DecisionError("decision must be approve or reject")
    if not reason or not reason.strip():
        raise DecisionError("a qualification decision needs a reason")
    run_dir = Path(run_dir)
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        results = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    except OSError as error:
        raise DecisionError(f"{run_dir}: not a run directory ({error.strerror})") from None
    try:
        require_human(environ=environ, chain=chain, stdin=stdin)
    except HumanCheckError as error:
        context = error.context
        evidence.emit(sink, evidence.REFUSED, claimed_actor, "refused",
                      reason=str(error),
                      data={"attempted_action": "qualify", "reason_code": "agent-context" if context.is_agent
                            else "no-terminal", "agent_markers": context.markers,
                            "run": manifest.get("run_record", manifest.get("run_id"))})
        raise
    if manifest.get("split_read") != "test":
        raise DecisionError("only a test run of a locked protocol can be qualified (this was a dev run)")
    report_record = evidence.by_id(records, manifest.get("report_record", ""))
    report_hash = bytes_hash((run_dir / "report.md").read_bytes())
    if report_record and report_record.get("subject", {}).get("sha256") != report_hash:
        raise DecisionError("report.md differs from the issued report record; regenerate the run")
    issued_thresholds = (report_record or {}).get("data", {}).get("thresholds_sha256")
    if issued_thresholds and bytes_hash((run_dir / "thresholds.json").read_bytes()) != issued_thresholds:
        raise DecisionError("thresholds.json differs from the issued report record; regenerate the run")
    if decision == "approve" and results["conclusion"] != "meets" and not accept_deviation:
        raise DecisionError(f"the run's conclusion is {results['conclusion']}; approving needs --accept-deviation "
                            "and a reason that justifies it")
    moment = now or _now()
    days = manifest.get("validity_days", 90) if valid_days is None else valid_days
    valid_until = moment + timedelta(days=days) if decision == "approve" else moment
    data = {
        "configuration_hash": manifest["configuration_hash"], "valid_until": _iso(valid_until),
        "valid_from": _iso(moment), "kind": manifest["kind"], "subject_id": manifest["subject_id"],
        "protocol": {k: manifest["protocol"][k] for k in ("id", "sha256")},
        "report": manifest.get("report_record"), "run": manifest.get("run_record"),
        "conclusion": results["conclusion"], "decision": decision, "triggers": manifest.get("triggers", []),
        "accepted_deviation": bool(accept_deviation and results["conclusion"] != "meets"),
        "confidence_ppm": round(results.get("confidence", 0.95) * 1_000_000),
    }
    if manifest["kind"] == "detector":
        data["thresholds_sha256"] = bytes_hash((run_dir / "thresholds.json").read_bytes())
        severe = results["bands"][-1]
        data["expected_fpr_upper_ppm"] = severe["fpr_heldout"].get("upper1_ppm", 1_000_000)
        data["band"] = severe["name"]
    links = [{"rel": rel, "ref": ref} for rel, ref in (("report", data["report"]), ("run", data["run"])) if ref]
    data = {k: v for k, v in data.items() if v is not None}
    return evidence.emit(sink, evidence.QUALIFICATION, human, decision,
                         meaning="approved" if decision == "approve" else "rejected", reason=reason.strip(),
                         subject=subject("validation-report", data.get("report") or manifest["run_id"], sha256=report_hash),
                         links=links or None, data=data)


@dataclass
class CheckResult:
    status: str  # valid | requalify | not-qualified
    fired: list[dict] = field(default_factory=list)
    qualification: dict | None = None
    record: dict | None = None
    message: str = ""

    @property
    def exit_code(self) -> int:
        return 0 if self.status == "valid" else 1

    def as_dict(self) -> dict:
        q = self.qualification or {}
        return {"status": self.status, "fired": self.fired, "qualification": q.get("id"),
                "valid_until": (q.get("data") or {}).get("valid_until"),
                "requalification_record": (self.record or {}).get("id"), "message": self.message}


def check(protocol: Protocol, *, records: list[dict], sink, actor: dict, thresholds: str | Path | None = None,
          observed_fp: tuple[int, int] | None = None, now: datetime | None = None) -> CheckResult:
    current = configuration_hash(protocol)  # first: a broken or mismatched configuration is an error, not "valid"
    q = evidence.last_qualification(records, protocol.subject, protocol.kind)
    if q is None:
        return CheckResult("not-qualified", message=f"no qualification found for {protocol.subject!r}")
    if q.get("action") != "approve":
        return CheckResult("not-qualified", qualification=q, message="the last qualification decision was a rejection")
    qd = q["data"]
    triggers = set(qd.get("triggers") or protocol.triggers)
    fired = []
    if "configuration-changed" in triggers and current != qd["configuration_hash"]:
        fired.append({"trigger": "configuration-changed", "detail": f"{qd['configuration_hash']} -> {current}"})
    if thresholds is not None and "thresholds-changed" in triggers and qd.get("thresholds_sha256"):
        actual = bytes_hash(Path(thresholds).read_bytes())
        if actual != qd["thresholds_sha256"]:
            fired.append({"trigger": "thresholds-changed", "detail": f"{qd['thresholds_sha256']} -> {actual}"})
    moment = now or _now()
    if "expired" in triggers and moment > _parse(qd["valid_until"]):
        fired.append({"trigger": "expired", "detail": f"valid until {qd['valid_until']}"})
    if observed_fp is not None and "drift" in triggers and "expected_fpr_upper_ppm" in qd:
        k, n = observed_fp
        observed = rate(k, n, qd.get("confidence_ppm", 950_000) / 1_000_000)
        if n and observed["lower1_ppm"] > qd["expected_fpr_upper_ppm"]:
            fired.append({"trigger": "drift", "detail": f"observed FP {k}/{n} (lower bound {observed['lower1_ppm']} ppm) "
                                                        f"above qualified upper bound {qd['expected_fpr_upper_ppm']} ppm"})
    if not fired:
        return CheckResult("valid", qualification=q, message=f"qualified until {qd['valid_until']}")
    names = sorted(f["trigger"] for f in fired)
    for previous in evidence.requalifications_for(records, q["id"]):
        pd = previous.get("data") or {}
        if sorted(f["trigger"] for f in pd.get("fired", [])) == names and pd.get("configuration_hash") == current:
            return CheckResult("requalify", fired, q, previous, "requalification already recorded")
    record = evidence.emit(
        sink, evidence.REQUALIFICATION, actor, "triggered",
        links=[{"rel": "qualification", "ref": q["id"]}],
        reason="; ".join(f"{f['trigger']}: {f['detail']}" for f in fired),
        data={"configuration_hash": current, "valid_until": qd["valid_until"], "trigger": fired[0]["trigger"],
              "fired": fired, "qualification": q["id"], "configuration_hash_qualified": qd["configuration_hash"],
              "subject_id": protocol.subject, "kind": protocol.kind})
    return CheckResult("requalify", fired, q, record, "requalification needed")
