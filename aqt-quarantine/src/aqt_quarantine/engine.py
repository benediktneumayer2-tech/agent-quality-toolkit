"""Scan pipeline: detect → fuse → band → case → record. Fails closed.

The record and, for warn/hold, the case file are written *before* anything is
returned to the adapter, so nothing reaches the agent unrecorded. Any detector
error, unreadable thresholds file or oversize text yields ``hold``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from aqt_evidence import bytes_hash

from . import records
from . import thresholds as thresholds_mod
from .config import Config
from .detectors import DetectorError, Span, check_result, load_detector
from .store import Store, TrustedSource
from .wrap import hold_notice, warn_banner, wrap

PRIORITY = ("override", "exfil", "toolcall", "hidden", "encoded", "framing", "secret", "addressed")
MAX_EVIDENCE, MAX_EXCERPT = 12, 200
_VISIBLE = {0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0xFEFF: "BOM", 0x2060: "WJ"}


@dataclass
class Source:
    tool: str
    ref: str | None = None          # URL, query or other locator given by the caller
    harness: str | None = None
    session: str | None = None
    tool_use_id: str | None = None

    @property
    def domain(self) -> str | None:
        if self.ref and self.ref.startswith(("http://", "https://")):
            host = urlsplit(self.ref).hostname
            return host.lower().rstrip(".") if host else None
        return None

    def as_data(self) -> dict:
        data = {"tool": self.tool, "ref": self.ref, "domain": self.domain}
        for key in ("harness", "session", "tool_use_id"):
            if getattr(self, key):
                data[key] = getattr(self, key)
        return data


@dataclass
class ScanResult:
    band: str                       # pass | warn | hold
    record: dict | None
    case_id: str | None = None
    reason_code: str = "risk"       # risk | unchecked | oversize
    reasons: list[str] = field(default_factory=list)
    content_sha256: str = ""
    trusted: bool = False

    def banner(self) -> str | None:
        return warn_banner(self.case_id or "?", self.reasons, self.trusted) if self.band == "warn" else None

    def notice(self) -> str:
        return hold_notice(self.case_id or "?", self.reason_code, self.reasons)

    def render(self, text: str, source: Source) -> str:
        if self.band == "hold":
            return self.notice()
        return wrap(text, source=source.ref, tool=source.tool, case_id=self.case_id, sha256=self.content_sha256,
                    banner=self.banner())


def text_hash(text: str) -> str:
    return bytes_hash(text.encode("utf-8", "surrogatepass"))


def _clean(text: str) -> str:
    text = "".join(f"<U+{ord(c):04X}>" if ord(c) in _VISIBLE or 0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069
                   or 0xE0000 <= ord(c) <= 0xE007F else c for c in text)
    return text.encode("utf-8", "replace").decode("utf-8")


def select_evidence(text: str, spans: list[tuple[str, Span]]) -> list[dict]:
    """Up to 12 spans, round-robin over labels in priority order, each with a short excerpt."""
    by_label: dict[str, list[tuple[str, Span]]] = {}
    for item in spans:
        by_label.setdefault(item[1].label, []).append(item)
    order = [label for label in PRIORITY if label in by_label] + sorted(set(by_label) - set(PRIORITY))
    chosen: list[tuple[str, Span]] = []
    while len(chosen) < MAX_EVIDENCE and any(by_label.get(label) for label in order):
        for label in order:
            if by_label.get(label) and len(chosen) < MAX_EVIDENCE:
                chosen.append(by_label[label].pop(0))
    chosen.sort(key=lambda item: (item[1].start, item[1].end))
    return [{"detector": name, "start": span.start, "end": span.end, "label": span.label,
             "reason": span.reason, "excerpt": _clean(text[span.start:span.end][:MAX_EXCERPT])}
            for name, span in chosen]


def reasons_of(evidence: list[dict], limit: int = 4) -> list[str]:
    seen: list[str] = []
    for label in PRIORITY + tuple(sorted({item["label"] for item in evidence} - set(PRIORITY))):
        for item in evidence:
            if item["label"] == label and item["reason"] and item["reason"] not in seen:
                seen.append(item["reason"])
                break
    return seen[:limit]


class Engine:
    def __init__(self, config: Config, store: Store):
        self.config, self.store = config, store
        self._detectors = None
        self._detector_error: str | None = None

    def detectors(self):
        if self._detectors is None and self._detector_error is None:
            loaded = []
            try:
                for entry in self.config.detectors:
                    options = dict(entry)
                    kind = options.pop("kind", None)
                    if not kind:
                        raise DetectorError("each [[detectors]] entry needs kind")
                    loaded.append(load_detector(kind, **options))
                self._detectors = loaded
            except Exception as error:  # noqa: BLE001 - any load failure must fail closed
                self._detector_error = f"{type(error).__name__}: {error}"
        return self._detectors or []

    def scan(self, text: str, source: Source, *, unscanned_parts: int = 0,
             sources: list[TrustedSource] | None = None) -> ScanResult:
        config = self.config
        content_sha256 = text_hash(text)
        scores: dict[str, int] = {}
        spans: list[tuple[str, Span]] = []
        errors: list[dict] = []
        used: list[dict] = []
        reason_code = "risk"
        try:
            thresholds = thresholds_mod.load(config.thresholds)
            thresholds_info = thresholds.summary()
        except thresholds_mod.ThresholdsError as error:
            thresholds, thresholds_info = None, {"version": "unreadable", "sha256": None, "calibrated": False}
            errors.append({"detector": "thresholds", "error": str(error)[:300]})
        if len(text) > config.max_scan_chars:
            reason_code = "oversize"
        else:
            detectors = self.detectors()
            if self._detector_error:
                errors.append({"detector": "load", "error": self._detector_error[:300]})
            for detector in detectors:
                used.append({"id": detector.name, "version": detector.version})
                try:
                    result = check_result(detector.score(text), text)
                except Exception as error:  # noqa: BLE001 - fail closed on anything
                    errors.append({"detector": detector.name, "error": f"{type(error).__name__}: {error}"[:300]})
                    continue
                scores[detector.name] = result.score_ppm
                spans.extend((detector.name, span) for span in result.spans)
            if errors or thresholds is None or not detectors:
                reason_code = "unchecked"
        if reason_code == "risk":
            band, fired = thresholds.band(scores)
        else:
            band, fired = "hold", []
        trusted = None
        if reason_code == "risk" and source.domain:
            trusted = next((item for item in (sources or []) if item.active() and item.matches(source.domain)), None)
            if trusted and band != "pass":
                band = "pass" if config.trusted_source_policy == "pass" else {"hold": "warn", "warn": "pass"}[band]
        extra = []
        if band == "pass" and unscanned_parts:
            band = "warn"
            extra.append(f"{unscanned_parts} non-text part(s) such as images were not scanned")
        evidence = select_evidence(text, spans) if band != "pass" else []
        reasons = reasons_of(evidence) + extra
        data = {
            "band": band, "score_ppm": max(scores.values(), default=0), "source": source.as_data(),
            "scores": scores, "fired": fired, "detectors": used, "thresholds": thresholds_info,
            "content_sha256": content_sha256, "chars": len(text), "reason_code": reason_code,
        }
        if errors:
            data["errors"] = errors
        if unscanned_parts:
            data["unscanned_parts"] = unscanned_parts
        if trusted:
            data["trusted_source"] = {"domain": trusted.domain, "record": trusted.record["id"]}
        result = ScanResult(band, None, None, reason_code, reasons, content_sha256, bool(trusted))
        if band == "pass":
            if config.record_passes:
                result.record = self.store.write(records.passed(data, tz=config.tz))
            return result
        case_id = self.store.new_case_id()
        data["case_id"] = case_id
        data["evidence"] = evidence
        data["original"] = {"sha256": content_sha256, "chars": len(text),
                            "path_ref": self.store.save_original(case_id, text)}
        result.case_id = case_id
        build = records.held if band == "hold" else records.passed
        result.record = self.store.write(build(data, tz=config.tz))
        return result
