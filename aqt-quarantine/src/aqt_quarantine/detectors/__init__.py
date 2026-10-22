"""Detector plugin interface (see docs/detectors.md).

A detector has a ``name``, a ``version`` and ``score(text) -> DetectorResult``.
Scores are integers in parts per million (0 = no sign of injection,
1,000,000 = certain); higher means more suspicious. ``spans`` point into the
``text`` that was passed in.

Detectors are found, in this order, as built-in names, as entry points of the
group ``aqt.detectors`` (installed packages), or as ``"package.module:factory"``.
This module imports only the standard library, so aqt-validate can load it
without heavy dependencies.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Protocol, runtime_checkable

ENTRY_POINT_GROUP = "aqt.detectors"
MAX_SCORE_PPM = 1_000_000
BUILTIN = {
    "heuristics": "aqt_quarantine.detectors.heuristics:HeuristicsDetector",
    "onnx": "aqt_quarantine.detectors.onnx:OnnxDetector",
}


@dataclass(frozen=True)
class Span:
    """Evidence: ``text[start:end]`` triggered ``label``; ``reason`` explains it in plain words."""
    start: int
    end: int
    label: str
    reason: str = ""


@dataclass
class DetectorResult:
    score_ppm: int
    spans: list[Span] = field(default_factory=list)


@runtime_checkable
class Detector(Protocol):
    name: str
    version: str

    def score(self, text: str) -> DetectorResult: ...


class DetectorError(RuntimeError):
    pass


def _resolve(target: str) -> Any:
    module, _, attribute = target.partition(":")
    if not module or not attribute:
        raise DetectorError(f"detector reference must look like 'package.module:factory', got {target!r}")
    try:
        value = importlib.import_module(module)
        for part in attribute.split("."):
            value = getattr(value, part)
    except (ImportError, AttributeError) as error:
        raise DetectorError(f"cannot load detector {target!r}: {error}") from error
    return value


def available() -> dict[str, str]:
    """Detector kinds that can be loaded by name: built-ins plus installed entry points."""
    found = dict(BUILTIN)
    for point in entry_points(group=ENTRY_POINT_GROUP):
        found.setdefault(point.name, point.value)
    return found


def load_detector(kind: str, **options: Any) -> Detector:
    """Create a detector from a built-in name, an entry-point name or ``module:factory``.

    ``options`` are passed to the factory (e.g. ``model_dir`` for ``onnx``).
    """
    target = BUILTIN.get(kind)
    if target is None:
        for point in entry_points(group=ENTRY_POINT_GROUP):
            if point.name == kind:
                target = point.value
                break
    factory = _resolve(target or kind)
    detector = factory(**options)
    if not isinstance(detector, Detector) or not detector.name or not detector.version:
        raise DetectorError(f"{kind!r} did not produce a detector with name, version and score()")
    return detector


def check_result(result: Any, text: str) -> DetectorResult:
    """Validate a detector's answer; raises ``DetectorError`` for anything off-contract."""
    if not isinstance(result, DetectorResult):
        raise DetectorError("detector returned something other than DetectorResult")
    if type(result.score_ppm) is not int or not 0 <= result.score_ppm <= MAX_SCORE_PPM:
        raise DetectorError(f"score_ppm must be an integer 0..{MAX_SCORE_PPM}, got {result.score_ppm!r}")
    for span in result.spans:
        if not (isinstance(span, Span) and 0 <= span.start < span.end <= len(text)):
            raise DetectorError(f"span out of range: {span!r}")
    return result


__all__ = ["BUILTIN", "Detector", "DetectorError", "DetectorResult", "ENTRY_POINT_GROUP", "MAX_SCORE_PPM", "Span",
           "available", "check_result", "load_detector"]
