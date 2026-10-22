"""Thresholds file (aqt-validate Design §2.2, in ppm; INTERFACES.md I7/I8).

A band fires when a detector's score is strictly greater than its threshold.
``rule`` is ``"any"`` (one detector is enough) or ``{"at_least": k}``.
Thresholds may be integers or decimal strings in the detector's unit (ppm for
aqt-quarantine detectors). The file's SHA-256 goes into every record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from importlib import resources
from pathlib import Path

from aqt_evidence import bytes_hash

BANDS = ("hold", "warn")  # evaluated in this order


class ThresholdsError(ValueError):
    pass


@dataclass(frozen=True)
class BandRule:
    name: str
    at_least: int               # 1 for "any"
    thresholds: dict[str, int]  # detector id -> ppm


@dataclass(frozen=True)
class Thresholds:
    path: str
    sha256: str
    version: str                # run record id, or "uncalibrated"
    calibrated: bool
    bands: dict[str, BandRule]

    def band(self, scores: dict[str, int]) -> tuple[str, list[str]]:
        """Return the band and the detectors that fired it."""
        for name in BANDS:
            rule = self.bands.get(name)
            if rule is None:
                continue
            fired = [d for d, limit in rule.thresholds.items() if d in scores and scores[d] > limit]
            if fired and len(fired) >= rule.at_least:
                return name, fired
        return "pass", []

    def summary(self) -> dict:
        return {"version": self.version, "sha256": self.sha256, "calibrated": self.calibrated}


def _ppm(value, where: str) -> int:
    if isinstance(value, bool):
        raise ThresholdsError(f"{where}: threshold must be a number")
    if isinstance(value, int):
        return value
    try:
        return int(Decimal(str(value)).to_integral_value(rounding="ROUND_FLOOR"))
    except (InvalidOperation, ValueError) as error:
        raise ThresholdsError(f"{where}: threshold {value!r} is not a number") from error


def parse(data: bytes, path: str) -> Thresholds:
    try:
        doc = json.loads(data)
    except ValueError as error:
        raise ThresholdsError(f"{path}: not valid JSON") from error
    if not isinstance(doc, dict) or doc.get("aqt_thresholds") != "0.1":
        raise ThresholdsError(f"{path}: expected aqt_thresholds 0.1")
    bands: dict[str, BandRule] = {}
    for entry in doc.get("bands") or []:
        name = entry.get("name") if isinstance(entry, dict) else None
        if name not in BANDS:
            raise ThresholdsError(f"{path}: band name must be warn or hold, got {name!r}")
        rule = entry.get("rule", "any")
        if rule == "any":
            at_least = 1
        elif isinstance(rule, dict) and isinstance(rule.get("at_least"), int) and rule["at_least"] >= 1:
            at_least = rule["at_least"]
        else:
            raise ThresholdsError(f"{path}: rule must be 'any' or {{'at_least': k}}")
        limits = entry.get("thresholds")
        if not isinstance(limits, dict) or not limits:
            raise ThresholdsError(f"{path}: band {name} needs thresholds")
        bands[name] = BandRule(name, at_least, {k: _ppm(v, f"{path} {name}.{k}") for k, v in limits.items()})
    if not bands:
        raise ThresholdsError(f"{path}: no bands")
    calibration = doc.get("calibration") or {}
    run = doc.get("run")
    calibrated = bool(run) and isinstance(calibration.get("n"), int) and calibration["n"] > 0
    return Thresholds(path, bytes_hash(data), run if run else "uncalibrated", calibrated, bands)


def default_path() -> str:
    return str(resources.files("aqt_quarantine") / "data" / "thresholds.uncalibrated.json")


def load(path: str | None = None) -> Thresholds:
    path = path or default_path()
    try:
        data = Path(path).expanduser().read_bytes()
    except OSError as error:
        raise ThresholdsError(f"cannot read thresholds file {path}: {error}") from error
    return parse(data, str(path))
