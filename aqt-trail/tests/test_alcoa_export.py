import json

import pytest
from aqt_evidence import catalogues

from aqt_trail import anchors
from aqt_trail.alcoa import alcoa_report, export_dry_run, render
from aqt_trail.export import export_bundle, render_html, render_markdown, select, verify_bundle
from aqt_trail.state import open_writer, read_records, service_keys
from aqt_trail.tsa import load_ca
from aqt_trail.verify import verify_trail

from conftest import event, human, observed_stub

ATTRIBUTES = ["attributable", "legible", "contemporaneous", "original", "accurate", "complete", "consistent",
              "enduring", "available", "traceable"]


@pytest.fixture
def anchored(config):
    w = open_writer(config)
    first = w.append(event("one"), observed_stub())[0]
    w.append(event("two", links=[{"rel": "follows", "ref": first["id"]}]), observed_stub())
    anchors.checkpoint(w, tsa_url="test:", test_dir=config.state / "test-tsa")
    w.close()
    return config


def report_for(config, **kw):
    records = read_records(config.trail_path)
    ca = load_ca(config.state / "test-tsa" / "ca.pem") if (config.state / "test-tsa").exists() else None
    report = verify_trail(config.trail_path, keys=service_keys(config), checkpoints=config.checkpoints_path, tsa_ca=ca)
    return alcoa_report(records, report, export_check=lambda: export_dry_run(config), **kw)


def test_clean_anchored_trail_passes_every_attribute(anchored):
    results = report_for(anchored)
    assert [r["attribute"] for r in results] == ATTRIBUTES
    assert all(r["id"] == f"alcoa:{r['attribute']}" for r in results)
    assert all(catalogues.item(ref) for r in results for ref in r["related"])  # cited clauses exist
    assert {r["attribute"]: r["status"] for r in results} == {a: "pass" for a in ATTRIBUTES}, render(results)


def test_problems_show_up(config):
    w = open_writer(config)
    w.append(event("claims-human", who=human("owner")), observed_stub(harness="codex"))
    w.append(event("dangling", links=[{"rel": "x", "ref": "rec_" + "0" * 28}]), observed_stub())
    w.drain([event("late")], source="spool")
    w.close()
    status = {r["attribute"]: r["status"] for r in report_for(config)}
    assert status["attributable"] == "fail" and status["enduring"] == "fail"
    assert status["complete"] == "warn" and status["traceable"] == "warn" and status["original"] == "pass"
    assert "alcoa:enduring" in render(report_for(config), "md")


def test_export_bundle_verifies_and_detects_tampering(anchored, tmp_path):
    bundle = export_bundle(anchored, tmp_path / "bundle")
    manifest = json.loads((bundle / "MANIFEST.json").read_text())
    assert set(manifest["files"]) >= {"trail.jsonl", "checkpoints.jsonl", "keys/service.key.pub", "VERIFY.md",
                                      "tsa-ca.TEST-ONLY.pem"}
    report = verify_bundle(bundle)
    assert report.ok and report.anchors_verified == 1
    trail = bundle / "trail.jsonl"
    trail.write_bytes(trail.read_bytes().replace(b'"one"', b'"ONE"'))
    broken = verify_bundle(bundle)
    assert not broken.ok and "does not match MANIFEST.json" in broken.problems[0]
    archive = export_bundle(anchored, tmp_path / "packed", tar=True)
    assert archive.name == "packed.tar.gz" and archive.exists()


def test_report_rendering_and_filters(anchored):
    records = read_records(anchored.trail_path)
    chosen = select(records, type="trail.event")
    assert [r["action"] for r in chosen] == ["one", "two"]
    assert select(records, type="trail.*") == records
    md = render_markdown(chosen, title="Trail", summary="intact")
    assert md.count("\n| ") == 3 and "human:alice" in md
    page = render_html(records, title="Trail <x>", summary="intact")
    assert "&lt;x&gt;" in page and "prefers-color-scheme" in page
