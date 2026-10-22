"""Validation protocols: intended use, configuration under test, acceptance criteria.

A protocol is a TOML file. Its SHA-256 is locked (``protocol lock``) before the test split
is read, so acceptance criteria cannot be chosen after seeing results.
"""

from __future__ import annotations

import operator
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from aqt_evidence import bytes_hash, content_hash

from .stats import PPM, rate

KINDS = ("detector", "reviewer")
OPS = {">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt}
RATE_METRICS = {"tpr", "fpr", "detection_rate", "false_alarm_rate"}
DETECTOR_METRICS = {"tpr", "fpr", "auroc", "latency_p95_ms", "errors"}
REVIEWER_METRICS = {"detection_rate", "false_alarm_rate", "agreement", "kappa", "errors"}


class ProtocolError(ValueError):
    pass


@dataclass
class Protocol:
    path: Path
    sha256: str
    raw: dict
    kind: str
    id: str
    subject: str
    intended_use: str
    confidence: float
    validity_days: int
    triggers: list[str]
    max_errors: int
    criteria: list[dict] = field(default_factory=list)

    @property
    def base(self) -> Path:
        return self.path.parent

    def resolve(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.base / path

    @property
    def ref(self) -> dict:
        return {"id": self.id, "sha256": self.sha256}


def template(kind: str) -> str:
    if kind not in KINDS:
        raise ProtocolError(f"kind must be one of {', '.join(KINDS)}")
    return resources.files("aqt_validate").joinpath(f"templates/{kind}.toml").read_text(encoding="utf-8")


def load_protocol(path: str | Path) -> Protocol:
    path = Path(path).resolve()
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ProtocolError(f"{path}: {error.strerror}") from None
    try:
        raw = tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ProtocolError(f"{path}: not valid TOML ({error})") from None
    head = raw.get("protocol")
    if not isinstance(head, dict):
        raise ProtocolError(f"{path}: missing [protocol] table")
    kind = head.get("kind")
    if kind not in KINDS:
        raise ProtocolError(f"{path}: [protocol] kind must be detector or reviewer")
    for key in ("id", "intended_use"):
        if not isinstance(head.get(key), str) or not head[key].strip():
            raise ProtocolError(f"{path}: [protocol] needs a non-empty {key}")
    confidence = float(head.get("confidence", 0.95))
    if not 0.5 <= confidence < 1.0:
        raise ProtocolError(f"{path}: confidence must be in [0.5, 1)")
    protocol = Protocol(
        path=path, sha256=bytes_hash(data), raw=raw, kind=kind, id=head["id"],
        subject=head.get("subject") or head["id"], intended_use=head["intended_use"].strip(),
        confidence=confidence, validity_days=int(head.get("validity_days", 90)),
        triggers=list(head.get("requalify_on", ["configuration-changed", "thresholds-changed", "expired", "drift"])),
        max_errors=int(head.get("max_errors", 0)),
    )
    protocol.criteria = [_criterion(c, kind, n, path) for n, c in enumerate(raw.get("criteria", []), 1)]
    if kind == "detector":
        _check_detector(protocol)
    else:
        _check_reviewer(protocol)
    return protocol


def _criterion(c: dict, kind: str, n: int, path: Path) -> dict:
    allowed = DETECTOR_METRICS if kind == "detector" else REVIEWER_METRICS
    metric = c.get("metric")
    if metric not in allowed:
        raise ProtocolError(f"{path}: criterion {n}: metric must be one of {', '.join(sorted(allowed))}")
    op = c.get("op", ">=")
    if op not in OPS:
        raise ProtocolError(f"{path}: criterion {n}: op must be one of {', '.join(OPS)}")
    if not isinstance(c.get("target"), (int, float)) or isinstance(c.get("target"), bool):
        raise ProtocolError(f"{path}: criterion {n}: target must be a number")
    default_bound = ("lower" if op in (">=", ">") else "upper") if metric in RATE_METRICS else "point"
    bound = c.get("bound", default_bound)
    if bound not in ("lower", "upper", "point"):
        raise ProtocolError(f"{path}: criterion {n}: bound must be lower, upper or point")
    out = dict(c)
    out.update({"id": c.get("id", f"C{n}"), "op": op, "bound": bound})
    return out


def _check_detector(p: Protocol) -> None:
    raw = p.raw
    data = raw.get("data") or {}
    if not data.get("benign"):
        raise ProtocolError(f"{p.path}: [data] needs benign = [files]")
    if not data.get("attacks"):
        raise ProtocolError(f"{p.path}: [data] needs attacks = [files]")
    detectors = raw.get("detectors") or []
    if not detectors:
        raise ProtocolError(f"{p.path}: at least one [[detectors]] entry is needed")
    ids = [d.get("id") for d in detectors]
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        raise ProtocolError(f"{p.path}: every detector needs a unique id")
    for d in detectors:
        kinds = [k for k in ("scores", "command", "callable", "plugin") if k in d]
        if len(kinds) != 1:
            raise ProtocolError(f"{p.path}: detector {d['id']}: give exactly one of scores, command, callable, plugin")
    bands = raw.get("bands") or []
    if not bands:
        raise ProtocolError(f"{p.path}: at least one [[bands]] entry is needed")
    for b in bands:
        if b.get("name") not in ("warn", "hold") or not 0 < float(b.get("fpr_target", 0)) < 1:
            raise ProtocolError(f"{p.path}: every band needs a name (warn or hold, as aqt-quarantine reads them) "
                                "and 0 < fpr_target < 1")
    if len({b["name"] for b in bands}) != len(bands):
        raise ProtocolError(f"{p.path}: band names must be unique")
        if "at_least" in b and not 1 <= int(b["at_least"]) <= len(detectors):
            raise ProtocolError(f"{p.path}: band {b['name']}: at_least must be between 1 and the number of detectors")
    names = {b["name"] for b in bands}
    for c in p.criteria:
        if c["metric"] in ("tpr", "fpr") and c.get("band", bands[-1]["name"]) not in names:
            raise ProtocolError(f"{p.path}: criterion {c['id']}: unknown band {c.get('band')!r}")


def _check_reviewer(p: Protocol) -> None:
    reviewer = p.raw.get("reviewer")
    if not isinstance(reviewer, dict) or not reviewer.get("id"):
        raise ProtocolError(f"{p.path}: [reviewer] needs an id")
    argv = reviewer.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ProtocolError(f"{p.path}: [reviewer] argv must be a non-empty list of strings")
    if int(reviewer.get("runs", 3)) < 1:
        raise ProtocolError(f"{p.path}: [reviewer] runs must be >= 1")
    cases = p.raw.get("cases") or {}
    if not cases.get("dir"):
        raise ProtocolError(f"{p.path}: [cases] needs dir (from reviewer build-cases)")


# --------------------------------------------------------------------------- configuration hash

def _file_hash(p: Protocol, value: str) -> str:
    path = p.resolve(value)
    if not path.exists():
        raise ProtocolError(f"{p.path}: file not found: {value}")
    return bytes_hash(path.read_bytes())


def detector_components(p: Protocol) -> list[dict]:
    """The detectors as they actually are now: effective (loaded) versions and code hashes."""
    from .adapters import AdapterError, detector_identity

    out = []
    for d in p.raw["detectors"]:
        kind = next(k for k in ("scores", "command", "callable", "plugin") if k in d)
        try:
            identity = detector_identity(d, p.base)
        except AdapterError as error:
            raise ProtocolError(str(error)) from None
        component = {"id": d["id"], "version": identity["version"], "adapter": kind,
                     "value": _file_hash(p, d[kind]) if kind == "scores" else d[kind]}
        if identity.get("code_sha256"):
            component["code_sha256"] = identity["code_sha256"]
        if d.get("options"):
            component["options"] = d["options"]
        if d.get("model_file"):
            component["model_sha256"] = _file_hash(p, d["model_file"])
        elif d.get("model_sha256"):
            component["model_sha256"] = d["model_sha256"]
        out.append(component)
    return out


def reviewer_components(p: Protocol) -> dict:
    r = p.raw["reviewer"]
    keys = ("id", "harness", "model", "version", "argv", "stdin", "runs", "timeout_s", "min_severity",
            "line_tolerance", "detect_min_runs")
    component = {k: r[k] for k in keys if k in r}
    if r.get("prompt_template"):
        component["prompt_sha256"] = _file_hash(p, r["prompt_template"])
    return component


def configuration_hash(p: Protocol) -> str:
    components = detector_components(p) if p.kind == "detector" else reviewer_components(p)
    return content_hash({"kind": p.kind, "subject": p.subject, "components": components})


# --------------------------------------------------------------------------- criteria

def _to_ppm(value: float) -> int:
    return round(value * PPM)


def evaluate_criterion(c: dict, observed, conf: float = 0.95) -> dict:
    """``observed`` is a rate dict (stats.rate) for rate metrics, else a number or None."""
    out = {"id": c["id"], "metric": c["metric"], "op": c["op"], "bound": c["bound"]}
    for key in ("band", "split", "family", "category", "detector", "period"):
        if key in c:
            out[key] = c[key]
    compare = OPS[c["op"]]
    target = float(c["target"])
    if c["metric"] in RATE_METRICS or c["metric"] in ("auroc", "agreement", "kappa"):
        out["target_ppm"] = _to_ppm(target)
    else:
        out["target"] = int(target)
    if isinstance(observed, dict):
        n = observed.get("n", 0)
        out["observed"] = observed
        if n == 0:
            out["status"] = "inconclusive"
            out["note"] = "no items"
            return out
        key = {"lower": "lower1_ppm", "upper": "upper1_ppm", "point": "rate_ppm"}[c["bound"]]
        value = observed[key] / PPM
        # Could any outcome at this n meet the criterion?
        best = rate(n if c["op"] in (">=", ">") else 0, n, conf)
        if not compare(best[key] / PPM, target):
            out["status"] = "inconclusive"
            out["note"] = f"not demonstrable with n={n}"
            return out
        out["status"] = "pass" if compare(value, target) else "fail"
        return out
    if observed is None:
        out["status"] = "inconclusive"
        out["note"] = "not measurable"
        return out
    if isinstance(observed, float):
        out["observed_ppm"] = _to_ppm(observed)
    else:
        out["observed"] = int(observed)
    out["status"] = "pass" if compare(observed, target) else "fail"
    return out


def conclusion(results: list[dict]) -> str:
    statuses = {r["status"] for r in results}
    if "fail" in statuses:
        return "does-not-meet"
    if "inconclusive" in statuses or not results:
        return "inconclusive"
    return "meets"
