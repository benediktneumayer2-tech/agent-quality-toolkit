"""Detector validation: split, score, calibrate bands, measure, evaluate criteria, report.

Method (rebuilt from the s36 evaluation of Agent Platform Next):
- thresholds come from calibration benign items only;
- with several detectors, each score is ranked against that detector's calibration benign
  scores; the fused score is the maximum rank. Calibrating the fused rank at the target
  false-positive rate gives one threshold per detector, so the band rule is "any detector
  above its threshold" and the realised calibration FPR is <= the target by construction;
- ``at_least = k`` bands use each detector's own threshold at the target and need k of them
  (the s36 agreement rule); their FPR is measured, not guaranteed;
- rates carry exact Clopper-Pearson bounds; AUROC is context only.
"""

from __future__ import annotations

import json
import os
import tomllib
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aqt_evidence import bytes_hash, content_hash, subject

from . import evidence
from .adapters import AdapterError, score_items
from .data import assign_splits, compose, disjointness, file_hash, read_items
from .protocol import (Protocol, ProtocolError, configuration_hash, conclusion, detector_components,
                       evaluate_criterion)
from .report import CRITERIA_HEADERS, NON_COMPLIANCE, Report, criteria_rows, fmt_bound, fmt_rate, pct
from .stats import PPM, auroc, min_n_zero_failures, percentile, rate

THRESHOLDS_VERSION = "0.1"


class RunRefused(RuntimeError):
    pass


# --------------------------------------------------------------------------- calibration

def threshold_any(calib: list[dict[str, int]], detectors: list[str], fpr_target_ppm: int) -> dict[str, int]:
    """Per-detector thresholds for the rule "any detector strictly above its threshold"."""
    n = len(calib)
    if n == 0:
        raise ValueError("calibration needs at least one benign item")
    sorted_scores = {d: sorted(item[d] for item in calib) for d in detectors}
    ranks = sorted(max(bisect_left(sorted_scores[d], item[d]) for d in detectors) for item in calib)
    allowed = fpr_target_ppm * n // PPM
    # smallest j with #(rank > j) <= allowed; ranks are in 0..n-1
    for j in range(n):
        above = n - bisect_left(ranks, j + 1)
        if above <= allowed:
            return {d: sorted_scores[d][j] for d in detectors}
    return {d: sorted_scores[d][-1] for d in detectors}


def fires(scores: dict[str, int], band: dict) -> bool:
    above = sum(1 for d, t in band["thresholds"].items() if scores[d] > t)
    rule = band["rule"]
    return above >= (rule["at_least"] if isinstance(rule, dict) else 1)


def calibrate(calib: list[dict[str, int]], detectors: list[str], bands_spec: list[dict]) -> list[dict]:
    bands = []
    for spec in bands_spec:
        band_detectors = list(spec.get("detectors", detectors))
        target = round(float(spec["fpr_target"]) * PPM)
        if "at_least" in spec:
            thresholds = {d: threshold_any(calib, [d], target)[d] for d in band_detectors}
            rule: str | dict = {"at_least": int(spec["at_least"])}
        else:
            thresholds = threshold_any(calib, band_detectors, target)
            rule = "any"
        bands.append({"name": spec["name"], "fpr_target_ppm": target, "rule": rule, "thresholds": thresholds})
    return bands


def fused_rank(scores: dict[str, int], sorted_calib: dict[str, list[int]]) -> float:
    n = len(next(iter(sorted_calib.values())))
    best = max(bisect_left(sorted_calib[d], scores[d]) / n for d in sorted_calib)
    return best + 1e-9 * max(scores.values()) / PPM  # tie-break by raw score


# --------------------------------------------------------------------------- contamination

def load_contamination(protocol: Protocol) -> list[dict]:
    value = (protocol.raw.get("data") or {}).get("contamination")
    if not value:
        return []
    path = protocol.resolve(value)
    try:
        with open(path, "rb") as handle:
            entries = tomllib.load(handle).get("entries", [])
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProtocolError(f"contamination registry {path}: {error}") from None
    return [e for e in entries if e.get("detector") and e.get("dataset")]


def contaminated_by(item: dict, detectors: list[str], registry: list[dict]) -> list[str]:
    names = {item.get("family"), (item.get("source") or "").split("@")[0], item.get("source")}
    names.discard(None)
    names.discard("")
    return sorted({e["detector"] for e in registry if e["detector"] in detectors and e["dataset"] in names})


# --------------------------------------------------------------------------- run

@dataclass
class RunResult:
    run_dir: Path
    results: dict
    run_record: dict
    report_record: dict

    @property
    def exit_code(self) -> int:
        return 0 if self.results["conclusion"] == "meets" else 1


def _datasets(protocol: Protocol, key: str) -> tuple[list[dict], list[dict]]:
    files = protocol.raw["data"][key]
    files = [files] if isinstance(files, str) else files
    items, meta = [], []
    for name in files:
        path = protocol.resolve(name)
        loaded = read_items(path)
        items.extend(loaded)
        meta.append({"name": Path(name).name, "sha256": file_hash(path), "items": len(loaded)})
    return items, meta


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(3).hex()


def run_detector(protocol: Protocol, *, split: str, state_dir: Path, sink, records: list[dict], actor: dict,
                 out_dir: Path | None = None) -> RunResult:
    if protocol.kind != "detector":
        raise ProtocolError("this protocol is not a detector protocol")
    if split not in ("dev", "test"):
        raise ProtocolError("split must be dev or test")
    lock = evidence.find_lock(records, protocol.sha256)
    if split == "test" and lock is None:
        raise RunRefused("the test split needs a locked protocol: run `aqt-validate protocol lock` for this exact file "
                         f"first ({protocol.sha256})")
    data_cfg = protocol.raw["data"]
    salt = str(data_cfg.get("salt", protocol.id))
    benign, benign_meta = _datasets(protocol, "benign")
    attacks, attack_meta = _datasets(protocol, "attacks")
    if any(i["label"] != "benign" for i in benign) or any(i["label"] != "attack" for i in attacks):
        raise ProtocolError("benign files may hold only benign items and attack files only attack items")
    split_args = dict(salt=salt, benign_calib_share=float(data_cfg.get("benign_calib_share", 0.5)),
                      attack_dev_share=float(data_cfg.get("attack_dev_share", 0.35)),
                      benign_keys=data_cfg.get("benign_split_keys", ["group"]),
                      attack_keys=data_cfg.get("attack_split_keys", ["goal", "payload"]))
    splits = assign_splits(benign, **split_args)
    if data_cfg.get("compose"):
        hosts = [i for i in benign if splits[i["id"]] == "heldout"]
        attacks = compose(hosts, attacks, seed=int(data_cfg.get("seed", 36)),
                          per_payload=int(data_cfg.get("per_payload", 1)))
    splits.update(assign_splits(attacks, **split_args))
    all_items = benign + attacks
    overlaps = disjointness(all_items, splits)
    datasets = benign_meta + attack_meta
    data_sha = content_hash(sorted(d["sha256"] for d in datasets))
    readout = evidence.test_readouts(records, data_sha) + 1 if split == "test" else 0
    components = detector_components(protocol)  # loads plug-ins: fails early on a pinned-version mismatch
    config_hash = configuration_hash(protocol)

    # score benign items and the attack items of the requested split
    detector_specs = protocol.raw["detectors"]
    detector_ids = [d["id"] for d in detector_specs]
    to_score = [i for i in all_items if i["label"] == "benign" or splits[i["id"]] == split]
    per_detector = {}
    for spec in detector_specs:
        try:
            per_detector[spec["id"]] = score_items(spec, to_score, base=protocol.base)
        except AdapterError as error:
            raise RunRefused(str(error)) from None
    errors = {d: s.errors for d, s in per_detector.items() if s.errors}
    errored = {i for errs in errors.values() for i in errs}
    scored = {i["id"]: {d: per_detector[d].ppm[i["id"]] for d in detector_ids}
              for i in to_score if i["id"] not in errored}

    def group(label: str, which: str, extra=lambda i: True) -> list[dict]:
        return [i for i in to_score if i["label"] == label and splits[i["id"]] == which and i["id"] in scored and extra(i)]

    calib_items = group("benign", "calib")
    heldout_items = group("benign", "heldout")
    hard_items = group("benign", "heldout", lambda i: bool(i.get("hard")))
    attack_items = group("attack", split)
    if not calib_items:
        raise RunRefused("no scored calibration benign items")
    calib_scores = [scored[i["id"]] for i in calib_items]
    bands = calibrate(calib_scores, detector_ids, protocol.raw["bands"])
    registry = load_contamination(protocol)
    contamination = {i["id"]: contaminated_by(i, detector_ids, registry) for i in attack_items}
    clean_attacks = [i for i in attack_items if not contamination[i["id"]]]
    dirty_attacks = [i for i in attack_items if contamination[i["id"]]]
    conf = protocol.confidence

    def measured(items: list[dict], band: dict) -> dict:
        return rate(sum(1 for i in items if fires(scored[i["id"]], band)), len(items), conf)

    band_results = []
    for band in bands:
        by_family, by_category, dirty = defaultdict(list), defaultdict(list), defaultdict(list)
        for i in clean_attacks:
            by_family[i.get("family") or "-"].append(i)
            by_category[i.get("category") or "-"].append(i)
        for i in dirty_attacks:
            dirty[i.get("family") or "-"].append(i)
        band_results.append(dict(band, **{
            "fpr_calib": measured(calib_items, band), "fpr_heldout": measured(heldout_items, band),
            "fpr_hard": measured(hard_items, band), "tpr": measured(clean_attacks, band),
            "tpr_by_family": {k: measured(v, band) for k, v in sorted(by_family.items())},
            "tpr_by_category": {k: measured(v, band) for k, v in sorted(by_category.items())},
            "tpr_contaminated": {k: measured(v, band) for k, v in sorted(dirty.items())},
            "min_n_calib": min_n_zero_failures(band["fpr_target_ppm"] / PPM, conf),
        }))

    sorted_calib = {d: sorted(s[d] for s in calib_scores) for d in detector_ids}
    neg = [scored[i["id"]] for i in heldout_items]
    pos = [scored[i["id"]] for i in clean_attacks]
    aurocs = {"fused": auroc([fused_rank(s, sorted_calib) for s in neg], [fused_rank(s, sorted_calib) for s in pos])}
    for d in detector_ids:
        aurocs[d] = auroc([s[d] for s in neg], [s[d] for s in pos])
    latency = {}
    for d in detector_ids:
        values = list(per_detector[d].latency_ms.values())
        latency[d] = {"p50_ms": percentile(values, 50), "p95_ms": percentile(values, 95),
                      "max_ms": max(values) if values else None, "n": len(values)}
    sums = [sum(per_detector[d].latency_ms[i] for d in detector_ids) for i in scored
            if all(i in per_detector[d].latency_ms for d in detector_ids)]
    latency["fused"] = {"p50_ms": percentile(sums, 50), "p95_ms": percentile(sums, 95),
                        "max_ms": max(sums) if sums else None, "n": len(sums)}
    error_count = len(errored)

    # criteria
    by_name = {b["name"]: b for b in band_results}
    severe = band_results[-1]["name"]
    criteria = []
    for c in protocol.criteria:
        metric = c["metric"]
        if metric == "tpr":
            band = by_name[c.get("band", severe)]
            pool = [i for i in clean_attacks if all(i.get(k) == c[k] for k in ("family", "category") if k in c)]
            observed = measured(pool, band)
        elif metric == "fpr":
            band = by_name[c.get("band", severe)]
            observed = {"calib": band["fpr_calib"], "heldout": band["fpr_heldout"],
                        "hard": band["fpr_hard"]}[c.get("split", "heldout")]
        elif metric == "auroc":
            observed = aurocs.get(c.get("detector", "fused"))
        elif metric == "latency_p95_ms":
            observed = latency.get(c.get("detector", "fused"), {}).get("p95_ms")
        else:
            observed = error_count
        criteria.append(evaluate_criterion(c, observed, conf))
    criteria.append(evaluate_criterion({"id": "E0", "metric": "errors", "op": "<=", "bound": "point",
                                        "target": protocol.max_errors}, error_count, conf))
    verdict = conclusion(criteria)

    deviations = []
    for key, value in overlaps.items():
        if value:
            deviations.append(f"{key.replace('_', ' ')}: {value} (leakage between splits)")
    if error_count:
        deviations.append(f"{error_count} item(s) could not be scored and are excluded from all rates")
    if dirty_attacks:
        deviations.append(f"{len(dirty_attacks)} attack item(s) are contaminated (detector trained on their dataset) "
                          "and are excluded from criteria")
    for band in band_results:
        if len(calib_items) < band["min_n_calib"]:
            deviations.append(f"band {band['name']}: {len(calib_items)} calibration items cannot demonstrate FPR "
                              f"<= {pct(band['fpr_target_ppm'], 2)} at {conf:.0%} confidence (needs >= {band['min_n_calib']})")
    if split == "test" and readout > 1:
        deviations.append(f"the test split of this data has now been read {readout} times")
    for c in criteria:
        if c["status"] == "inconclusive":
            deviations.append(f"criterion {c['id']} is inconclusive ({c.get('note', '')})")
    if split == "dev":
        deviations.append("dev split: exploratory run; not usable for qualification")

    run_id = new_run_id()
    run_dir = out_dir or state_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    results = {
        "kind": "detector", "split_read": split, "conclusion": verdict, "confidence": conf,
        "criteria": criteria, "bands": band_results, "auroc": aurocs, "latency": latency,
        "counts": {"calib": len(calib_items), "heldout": len(heldout_items), "hard": len(hard_items),
                   "attacks": len(attack_items), "attacks_clean": len(clean_attacks),
                   "attacks_contaminated": len(dirty_attacks), "errors": error_count},
        "disjointness": overlaps, "errors": {d: dict(list(e.items())[:20]) for d, e in errors.items()},
        "contaminated_detectors": sorted({d for v in contamination.values() for d in v}),
        "deviations": deviations,
    }
    thresholds = {
        "aqt_thresholds": THRESHOLDS_VERSION, "calibrated": True, "protocol": protocol.ref,
        "configuration_hash": config_hash,
        "detectors": [{k: v for k, v in (("id", c["id"]), ("version", c["version"]), ("sha256", c.get("model_sha256")),
                                         ("code_sha256", c.get("code_sha256"))) if v is not None}
                      for c in components],
        "bands": [{k: b[k] for k in ("name", "fpr_target_ppm", "rule", "thresholds")} for b in band_results],
        "run": None,  # set to the run record id below
        "calibration": {"n": len(calib_items), "realised_fpr_ppm": {b["name"]: b["fpr_calib"]["rate_ppm"]
                                                                    for b in band_results}},
    }
    manifest = {
        "run_id": run_id, "kind": "detector", "protocol": dict(protocol.ref, file=protocol.path.name),
        "subject_id": protocol.subject, "split_read": split, "configuration_hash": config_hash,
        "datasets": datasets, "data_sha256": data_sha, "salt": salt, "test_readouts": readout,
        "lock_record": lock["id"] if lock else None, "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "validity_days": protocol.validity_days, "triggers": protocol.triggers,
    }
    _write_json(run_dir / "manifest.json", manifest)
    _write_lines(run_dir / "splits.jsonl", ({"id": i["id"], "label": i["label"], "split": splits[i["id"]],
                                             "family": i.get("family"), "category": i.get("category")}
                                            for i in all_items))
    _write_lines(run_dir / "scores.jsonl", ({"id": i, "scores_ppm": s} for i, s in sorted(scored.items())))
    _write_json(run_dir / "results.json", results)

    # the run record binds the results; thresholds.json then names the run (aqt-quarantine reads
    # `run` as its version) and the report record binds the thresholds file by hash
    data = {
        "kind": "detector", "protocol": protocol.ref, "subject_id": protocol.subject, "configuration_hash": config_hash,
        "datasets": datasets, "data_sha256": data_sha, "splits": {"salt": salt, **overlaps},
        "split_read": split, "test_readouts": readout,
        "results_sha256": bytes_hash((run_dir / "results.json").read_bytes()), "conclusion": verdict,
        "headline": {b["name"]: {"tpr": b["tpr"], "fpr_heldout": b["fpr_heldout"]} for b in band_results},
        "contaminated": results["contaminated_detectors"], "errors": error_count, "run_id": run_id,
    }
    links = [{"rel": "protocol-lock", "ref": lock["id"]}] if lock else None
    run_record = evidence.emit(sink, evidence.RUN, actor, "completed", data=data, links=links,
                               subject=subject("validation-run", run_id, sha256=data["results_sha256"]))
    thresholds["run"] = run_record["id"]
    thresholds_sha = bytes_hash(_write_json(run_dir / "thresholds.json", thresholds))
    report = build_report(protocol, manifest, results, thresholds_data=thresholds, run_record_id=run_record["id"])
    (run_dir / "report.md").write_text(report.markdown(), encoding="utf-8")
    (run_dir / "report.html").write_text(report.html(f"Validation report {protocol.id}"), encoding="utf-8")
    for name in ("report.md", "report.html"):
        (run_dir / name).chmod(0o600)
    report_record = evidence.emit(
        sink, evidence.REPORT, actor, "issued",
        subject=subject("validation-report", f"{run_id}/report.md", sha256=bytes_hash((run_dir / "report.md").read_bytes())),
        links=[{"rel": "run", "ref": run_record["id"]}],
        data={"kind": "detector", "run": run_record["id"], "conclusion": verdict, "criteria": _criteria_data(criteria),
              "deviations": deviations, "thresholds_sha256": thresholds_sha,
              "configuration_hash": config_hash, "subject_id": protocol.subject, "split_read": split,
              "html_sha256": bytes_hash((run_dir / "report.html").read_bytes())})
    manifest.update({"run_record": run_record["id"], "report_record": report_record["id"]})
    _write_json(run_dir / "manifest.json", manifest)
    return RunResult(run_dir, results, run_record, report_record)


def _criteria_data(criteria: list[dict]) -> list[dict]:
    """Criteria for a record: integers and strings only."""
    out = []
    for c in criteria:
        row = {k: v for k, v in c.items() if k != "observed"}
        if isinstance(c.get("observed"), dict):
            row["observed"] = c["observed"]
        elif isinstance(c.get("observed"), int):
            row["observed"] = c["observed"]
        out.append(row)
    return out


def _write_json(path: Path, value) -> bytes:
    data = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(data)
    path.chmod(0o600)
    return data


def _write_lines(path: Path, rows) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    path.chmod(0o600)


# --------------------------------------------------------------------------- report

def build_report(protocol: Protocol, manifest: dict, results: dict, *, thresholds_data: dict,
                 run_record_id: str) -> Report:
    r = Report()
    conf = results["confidence"]
    r.h(1, f"Validation report: {protocol.id}")
    r.p(f"Detector validation. Conclusion: {results['conclusion'].upper()} "
        f"(split read: {results['split_read']}; confidence {conf:.0%}).")
    r.p(NON_COMPLIANCE)
    r.h(2, "1. Intended use")
    r.p(protocol.intended_use)
    r.h(2, "2. Configuration under test")
    rows = [[d["id"], d.get("version") or "–", d.get("sha256", "–"), d.get("code_sha256", "–")]
            for d in thresholds_data["detectors"]]
    r.table(["Detector", "Version (as loaded)", "Model SHA-256", "Code SHA-256"], rows)
    r.items([f"Subject: {protocol.subject}", f"Protocol: {protocol.path.name} ({protocol.sha256})",
             f"Protocol lock record: {manifest.get('lock_record') or 'none (dev run)'}",
             f"Configuration hash: {manifest['configuration_hash']}", f"Run record: {run_record_id}",
             f"Thresholds file: thresholds.json (names run record {thresholds_data.get('run')})",
             f"Run: {manifest['run_id']}"])
    r.h(2, "3. Data")
    r.table(["Dataset", "SHA-256", "Items"], [[d["name"], d["sha256"], d["items"]] for d in manifest["datasets"]])
    counts = results["counts"]
    r.items([f"Calibration benign: {counts['calib']}; held-out benign: {counts['heldout']} "
             f"(hard: {counts['hard']}); attacks read ({results['split_read']}): {counts['attacks']} "
             f"({counts['attacks_contaminated']} contaminated)",
             f"Split salt: {manifest['salt']}; overlaps: " + ", ".join(f"{k}={v}" for k, v in results["disjointness"].items()),
             f"Test readouts of this data (including this one): {manifest['test_readouts']}",
             f"Items not scored (errors): {counts['errors']}"])
    r.h(2, "4. Acceptance criteria and results")
    headers = list(CRITERIA_HEADERS)
    headers[6] = f"Observed ({conf:.0%} CI)"
    r.table(headers, criteria_rows(results["criteria"]))
    r.h(2, "5. Results by band")
    for band in results["bands"]:
        rule = band["rule"] if band["rule"] == "any" else f"at least {band['rule']['at_least']}"
        r.h(3, f"Band {band['name']} (target FPR {pct(band['fpr_target_ppm'], 2)}, rule {rule})")
        r.table(["Detector", "Threshold (ppm)"], [[d, t] for d, t in band["thresholds"].items()])
        rows = [["FPR calibration benign", fmt_rate(band["fpr_calib"]), fmt_bound(band["fpr_calib"], "upper")],
                ["FPR held-out benign", fmt_rate(band["fpr_heldout"]), fmt_bound(band["fpr_heldout"], "upper")],
                ["FPR hard benign (held-out)", fmt_rate(band["fpr_hard"]), fmt_bound(band["fpr_hard"], "upper")],
                ["Detection, all clean attacks", fmt_rate(band["tpr"]), fmt_bound(band["tpr"], "lower")]]
        rows += [[f"Detection, family {k}", fmt_rate(v), fmt_bound(v, "lower")] for k, v in band["tpr_by_family"].items()]
        rows += [[f"Detection, category {k}", fmt_rate(v), fmt_bound(v, "lower")] for k, v in band["tpr_by_category"].items()]
        r.table(["Measure", f"Rate [{conf:.0%} two-sided CI]", "One-sided bound"], rows)
        if band["tpr_contaminated"]:
            r.p("Contaminated — not evidence (a detector was trained on these datasets):")
            r.table(["Family", "Detection"], [[k, fmt_rate(v)] for k, v in band["tpr_contaminated"].items()])
    r.h(2, "6. Separation and latency")
    r.table(["Score", "AUROC (held-out benign vs clean attacks)"],
            [[k, "–" if v is None else f"{v:.3f}"] for k, v in results["auroc"].items()])
    r.table(["Detector", "p50 ms", "p95 ms", "max ms", "n"],
            [[k, v["p50_ms"], v["p95_ms"], v["max_ms"], v["n"]] for k, v in results["latency"].items()])
    r.p("AUROC is context only: it does not describe the operating point.")
    r.h(2, "7. Deviations")
    r.items(results["deviations"] or ["None."])
    r.h(2, "8. Limits")
    r.items(["Results hold for the static payloads tested; adaptive attackers defeat every detector. Claim risk "
             "reduction at the stated operating point only, and pair detectors with capability limits.",
             "Calibration is only as representative as the benign data; recalibrate when traffic changes.",
             "Contamination is user-declared; unknown training data may inflate detection.",
             "Bounds assume independent items; near-duplicate items make them optimistic."])
    r.h(2, "9. Conclusion, validity and requalification")
    r.p(f"Conclusion: {results['conclusion']}. Proposed validity: {protocol.validity_days} days after qualification. "
        f"Requalify on: {', '.join(protocol.triggers)}. Qualification is a separate, human decision "
        "(`aqt-validate qualify`).")
    r.h(2, "References")
    r.items(["annex22-2025d:3, annex22-2025d:4 (intended use, acceptance criteria)",
             "annex22-2025d:6.2 (test-data independence and record of use)",
             "annex22-2025d:7 (test execution), annex22-2025d:10 (change control, monitoring)",
             "iso9001-2015:7.1.5 (monitoring and measuring resources)"])
    return r
