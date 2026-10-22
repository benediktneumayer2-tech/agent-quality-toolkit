import json
import random
import sys
from types import SimpleNamespace

import pytest

from aqt_evidence import JsonlSink, validate_record
from aqt_validate import adapters, evidence
from aqt_validate.adapters import to_ppm
from aqt_validate.config import records
from aqt_validate.detector import RunRefused, calibrate, fires, run_detector, threshold_any
from aqt_validate.protocol import ProtocolError, load_protocol
from conftest import FIXTURES, attack_items, benign_items, detector_project, read_records

ACTOR = {"kind": "human", "id": "human:tester"}


def lock(protocol, sink):
    return evidence.emit(sink, evidence.RUN, ACTOR, "protocol-locked", reason="test",
                         data={"kind": protocol.kind, "protocol": protocol.ref})


def run(protocol, env, split="test"):
    sink = JsonlSink(env.sink)
    return run_detector(protocol, split=split, state_dir=env.state, sink=sink, records=records({}), actor=ACTOR)


# --------------------------------------------------------------------------- calibration

def brute_threshold(scores, alpha_ppm):
    """Smallest threshold t from the scores with #(s > t) <= floor(alpha n)."""
    allowed = alpha_ppm * len(scores) // 1_000_000
    return min(t for t in scores if sum(s > t for s in scores) <= allowed)


@pytest.mark.parametrize("seed", range(20))
def test_single_detector_threshold_matches_brute_force(seed):
    rng = random.Random(seed)
    scores = [rng.choice([rng.randrange(0, 1_000_000), rng.randrange(0, 50)]) for _ in range(rng.randint(5, 300))]
    for alpha in (0, 10_000, 30_000, 100_000, 500_000):
        t = threshold_any([{"d": s} for s in scores], ["d"], alpha)["d"]
        assert t == brute_threshold(scores, alpha)
        assert sum(s > t for s in scores) <= alpha * len(scores) // 1_000_000


@pytest.mark.parametrize("seed", range(20))
def test_any_rule_controls_fused_fpr(seed):
    rng = random.Random(seed)
    calib = [{"a": rng.randrange(1_000_000), "b": rng.randrange(1_000_000), "c": rng.randrange(1000)}
             for _ in range(rng.randint(20, 400))]
    for alpha in (10_000, 50_000):
        bands = calibrate(calib, ["a", "b", "c"], [{"name": "x", "fpr_target": alpha / 1_000_000}])
        flagged = sum(fires(s, bands[0]) for s in calib)
        assert flagged <= alpha * len(calib) // 1_000_000


def test_at_least_rule_uses_own_thresholds():
    calib = [{"a": i, "b": 100 - i} for i in range(100)]
    band = calibrate(calib, ["a", "b"], [{"name": "hold", "fpr_target": 0.05, "at_least": 2}])[0]
    assert band["rule"] == {"at_least": 2}
    assert band["thresholds"] == {"a": 94, "b": 95}
    assert not fires({"a": 99, "b": 0}, band) and fires({"a": 99, "b": 99}, band)


def test_to_ppm():
    assert to_ppm(0.5) == 500_000 and to_ppm(12) == 12 and to_ppm({"score_ppm": 7}) == 7
    assert to_ppm(SimpleNamespace(score_ppm=3)) == 3
    for bad in (True, 1.5, -1, 2_000_000, "x", {"other": 1}):
        with pytest.raises(ValueError):
            to_ppm(bad)


# --------------------------------------------------------------------------- full runs

def test_test_split_needs_lock(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p"))
    with pytest.raises(RunRefused, match="locked protocol"):
        run(protocol, aqt_env)


def test_dev_run_without_lock_then_locked_test_run(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p"))
    dev = run(protocol, aqt_env, split="dev")
    assert dev.results["split_read"] == "dev"
    assert any("dev split" in d for d in dev.results["deviations"])
    lock_record = lock(protocol, JsonlSink(aqt_env.sink))
    result = run(protocol, aqt_env)
    res = result.results
    assert res["conclusion"] == "meets", res["criteria"]
    assert result.exit_code == 0
    warn, hold = res["bands"]
    assert warn["fpr_calib"]["k"] <= warn["fpr_calib"]["n"] * 0.05
    assert hold["fpr_calib"]["k"] <= hold["fpr_calib"]["n"] * 0.01
    assert warn["tpr"]["n"] == res["counts"]["attacks"] > 0
    assert set(warn["tpr_by_family"]) == {"fam-a", "fam-b"}
    assert res["disjointness"] == {"goal_overlap": 0, "payload_overlap": 0, "attack_host_in_calib": 0}
    assert res["auroc"]["marker"] > 0.8
    # thresholds file: shared schema, integers in ppm
    thresholds = json.loads((result.run_dir / "thresholds.json").read_text())
    assert thresholds["aqt_thresholds"] == "0.1" and thresholds["calibrated"] is True
    assert thresholds["protocol"] == protocol.ref
    assert [b["name"] for b in thresholds["bands"]] == ["warn", "hold"]
    assert all(isinstance(v, int) for b in thresholds["bands"] for v in b["thresholds"].values())
    assert thresholds["detectors"][0]["sha256"].startswith("sha256:")
    # records
    recs = read_records(aqt_env.sink)
    assert all(validate_record(r) == [] for r in recs)
    completed = [r for r in recs if r["type"] == "validate.run" and r["action"] == "completed"]
    assert [r["data"]["split_read"] for r in completed] == ["dev", "test"]
    test_run = completed[-1]
    assert test_run["data"]["test_readouts"] == 1
    assert test_run["links"] == [{"rel": "protocol-lock", "ref": lock_record["id"]}]
    report = next(r for r in recs if r["type"] == "validate.report" and r["data"]["run"] == test_run["id"])
    assert report["data"]["conclusion"] == "meets"
    md = (result.run_dir / "report.md").read_text()
    assert "Intended use" in md and "not a validated system" in md and "C1" in md
    assert "<table>" in (result.run_dir / "report.html").read_text()
    # private text never lands in records or run files other than the inputs
    blob = aqt_env.sink.read_text() + (result.run_dir / "splits.jsonl").read_text()
    assert "synthetic goal" not in blob
    # a second test readout is counted and reported
    again = run(protocol, aqt_env)
    assert again.run_record["data"]["test_readouts"] == 2
    assert any("read 2 times" in d for d in again.results["deviations"])


def test_metrics_are_reproducible(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p"))
    lock(protocol, JsonlSink(aqt_env.sink))
    a, b = run(protocol, aqt_env).results, run(protocol, aqt_env).results
    for key in ("bands", "criteria", "auroc", "counts"):
        assert a[key] == b[key]


def test_small_calibration_set_is_inconclusive(aqt_env):
    criteria = """
[[criteria]]
id = "F1"
metric = "fpr"
band = "hold"
op = "<="
target = 0.01
"""
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", criteria=criteria))
    lock(protocol, JsonlSink(aqt_env.sink))
    res = run(protocol, aqt_env).results
    f1 = next(c for c in res["criteria"] if c["id"] == "F1")
    assert f1["status"] == "inconclusive" and "not demonstrable" in f1["note"]
    assert res["conclusion"] == "inconclusive"
    assert any("cannot demonstrate" in d for d in res["deviations"])


def test_failing_criterion(aqt_env):
    criteria = """
[[criteria]]
id = "T1"
metric = "tpr"
band = "hold"
family = "fam-a"
op = ">="
bound = "point"
target = 0.95
"""
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", criteria=criteria))
    lock(protocol, JsonlSink(aqt_env.sink))
    result = run(protocol, aqt_env)
    assert result.results["conclusion"] == "does-not-meet" and result.exit_code == 1


def test_contamination_is_excluded(aqt_env):
    root = aqt_env.tmp / "p"
    root.mkdir()
    (root / "contamination.toml").write_text('[[entries]]\ndetector = "marker"\ndataset = "fam-b"\nnote = "trained"\n')
    protocol = load_protocol(detector_project(root, contamination='contamination = "contamination.toml"'))
    lock(protocol, JsonlSink(aqt_env.sink))
    res = run(protocol, aqt_env).results
    warn = res["bands"][0]
    assert set(warn["tpr_by_family"]) == {"fam-a"} and set(warn["tpr_contaminated"]) == {"fam-b"}
    assert res["counts"]["attacks_contaminated"] > 0 and res["contaminated_detectors"] == ["marker"]


def test_detector_errors_fail_e0(aqt_env):
    benign = benign_items()
    benign[10]["text"] += " STUB-ERROR"
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", benign=benign))
    lock(protocol, JsonlSink(aqt_env.sink))
    res = run(protocol, aqt_env).results
    assert res["counts"]["errors"] == 1
    e0 = next(c for c in res["criteria"] if c["id"] == "E0")
    assert e0["status"] == "fail" and res["conclusion"] == "does-not-meet"


def test_compose_uses_heldout_hosts(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", compose=True))
    lock(protocol, JsonlSink(aqt_env.sink))
    result = run(protocol, aqt_env)
    assert result.results["disjointness"]["attack_host_in_calib"] == 0
    assert result.results["counts"]["attacks"] > 0


def test_callable_plugin_and_at_least(aqt_env, monkeypatch):
    extra = f"""
[[detectors]]
id = "length"
version = "0.1"
callable = "stub_detectors:length_score"

[[detectors]]
id = "plugin"
plugin = "fake-plugin"
"""
    sys.path.insert(0, str(FIXTURES))

    class EntryPoint:
        name = "fake-plugin"

        def load(self):
            import stub_detectors
            return stub_detectors.PluginDetector

    monkeypatch.setattr(adapters.metadata, "entry_points", lambda group: [EntryPoint()] if group == "aqt.detectors" else [])
    root = aqt_env.tmp / "p"
    protocol = load_protocol(detector_project(root, extra_detectors=extra, hold_rule="at_least = 2"))
    (root / "stub_detectors.py").write_text((FIXTURES / "stub_detectors.py").read_text())
    lock(protocol, JsonlSink(aqt_env.sink))
    res = run(protocol, aqt_env).results
    hold = res["bands"][1]
    assert hold["rule"] == {"at_least": 2} and set(hold["thresholds"]) == {"marker", "length", "plugin"}
    assert res["latency"]["length"]["n"] > 0 and "fused" in res["auroc"]
    assert adapters.available_plugins() == ["fake-plugin"]


def test_missing_plugin_is_a_clear_error(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", extra_detectors='[[detectors]]\nid = "x"\nplugin = "absent"\n'))
    with pytest.raises(ProtocolError, match="aqt.detectors"):
        run(protocol, aqt_env, split="dev")


def test_score_file_adapter(aqt_env):
    root = aqt_env.tmp / "p"
    benign, attacks = benign_items(100, 10, 0), attack_items(20, 1)
    rows = [{"id": i["id"], "score": 0.9 if i["label"] == "attack" else (n % 50) / 100} for n, i in enumerate(benign + attacks)]
    root.mkdir()
    (root / "scores.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    path = detector_project(root, benign=benign, attacks=attacks, criteria="")
    text = path.read_text().replace(f'command = ["{sys.executable}", "{FIXTURES / "stub_detector.py"}"]', 'scores = "scores.jsonl"')
    path.write_text(text)
    protocol = load_protocol(path)
    res = run(protocol, aqt_env, split="dev").results
    assert res["bands"][0]["tpr"]["k"] == res["bands"][0]["tpr"]["n"]


def test_real_quarantine_heuristics_plugin(aqt_env):
    """Integration with aqt-quarantine's built-in detector via the aqt.detectors entry point (skipped if absent)."""
    pytest.importorskip("aqt_quarantine")
    from aqt_quarantine.thresholds import load as load_thresholds
    root = aqt_env.tmp / "p"
    path = detector_project(root, criteria="")
    text = path.read_text().replace(f'command = ["{sys.executable}", "{FIXTURES / "stub_detector.py"}"]', 'plugin = "heuristics"')
    text = text.replace('id = "marker"\nversion = "1.0"', 'id = "heuristics"')  # version comes from the plug-in
    path.write_text(text)
    protocol = load_protocol(path)
    lock(protocol, JsonlSink(aqt_env.sink))
    result = run(protocol, aqt_env)
    assert result.results["counts"]["errors"] == 0
    assert result.results["auroc"]["heuristics"] > 0.5
    thresholds = load_thresholds(str(result.run_dir / "thresholds.json"))
    assert thresholds.calibrated and thresholds.version == result.run_record["id"]
    from aqt_quarantine.detectors.heuristics import HeuristicsDetector
    written = json.loads((result.run_dir / "thresholds.json").read_text())["detectors"][0]
    assert written["version"] == HeuristicsDetector().version
