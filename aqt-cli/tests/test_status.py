import json

import aqt_evidence
from aqt_evidence import spool_file
from aqt_trail import anchors
from aqt_trail.config import load_config
from aqt_trail.state import init_state, open_writer

from aqt_cli import checks
from aqt_cli.checks import Context, run_checks
from aqt_cli.cli import main
from conftest import PASSPHRASE, by_id, enrol


def _trail_with_records(count=3, checkpoint=True):
    config = load_config()
    init_state(config, log_id="trail_test")
    with open_writer(config) as writer:
        for number in range(count):
            writer.write_internal("trail.event", "demo", reason=f"record {number}")
        if checkpoint:
            anchors.save_checkpoint(writer, anchors.current_checkpoint(writer))
    return config


def test_fresh_machine_fails_with_a_fix_per_problem_and_pure_json(capsys):
    assert main(["status", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)          # stdout is JSON only
    checks_ = {c["id"]: c for c in report["checks"]}
    assert report["verdict"] == "fail"
    assert [c["id"] for c in report["checks"]] == [c.id for c in checks.CHECKS]
    assert checks_["packages"]["result"] == "ok" and checks_["packages"]["data"]["versions"]["aqt-ui"]
    assert checks_["trail.init"] == {"id": "trail.init", "result": "fail", "fix": "aqt-trail init",
                                     "explanation": checks_["trail.init"]["explanation"]}
    assert checks_["service"]["result"] == "skip"                       # no systemd --user here
    assert checks_["writer"]["result"] == "skip"
    assert checks_["sink"]["result"] == "warn" and checks_["sink"]["data"]["kind"] == "file"
    assert checks_["signer"]["result"] == "fail" and "aqt-signoff init" in checks_["signer"]["fix"]
    assert checks_["vectors"]["result"] == "ok"
    assert all(set(c) >= {"id", "result", "explanation", "fix"} for c in report["checks"])


def test_text_output_shows_verdict_and_fixes(capsys):
    assert main(["status"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("aqt status: FAIL") and "fix: aqt-trail init" in out


def test_malformed_aqt_sink_fails(monkeypatch):
    monkeypatch.setenv("AQT_SINK", "tcp:somewhere")
    sink = by_id(run_checks(Context()))["sink"]
    assert sink.result == "fail" and sink.fix == "set AQT_SINK to file:PATH or unix:PATH, or unset it"


def test_sink_unknown_when_aqt_spec_is_too_old(monkeypatch):
    monkeypatch.delattr(aqt_evidence, "resolve_sink")
    sink = by_id(run_checks(Context()))["sink"]
    assert sink.result == "warn" and "unknown" in sink.explanation


def test_stub_sink_on_the_trail_is_ok(monkeypatch):
    monkeypatch.setattr(aqt_evidence, "resolve_sink", lambda environ=None: {
        "kind": "unix", "target": "/run/x/trail.sock", "source": "discovered", "writer": True, "warning": None},
        raising=False)
    assert by_id(run_checks(Context()))["sink"].result == "ok"


def test_spooled_records_are_a_warning_with_drain_as_fix():
    spool_file().parent.mkdir(parents=True)
    spool_file().write_text('{"id": "rec_1"}\n{"id": "rec_2"}\n')
    spool = by_id(run_checks(Context()))["spool"]
    assert spool.result == "warn" and spool.fix == "aqt-trail drain" and spool.data == {"spooled": 2}


def test_intact_is_cheap_by_default_and_full_with_verify():
    config = _trail_with_records()
    assert by_id(run_checks(Context()))["trail.intact"].result == "ok"
    lines = config.trail_path.read_bytes().splitlines(keepends=True)
    lines[0] = lines[0].replace(b"record 0", b"record X")        # an edit in the middle of the log
    config.trail_path.write_bytes(b"".join(lines))
    quick = by_id(run_checks(Context()))["trail.intact"]
    assert quick.result == "ok" and "aqt status --verify" in quick.explanation
    full = by_id(run_checks(Context(verify=True)))["trail.intact"]
    assert full.result == "fail" and full.fix == "aqt-trail verify"


def test_cut_short_trail_is_found_without_full_verification():
    config = _trail_with_records()
    lines = config.trail_path.read_bytes().splitlines(keepends=True)
    config.trail_path.write_bytes(b"".join(lines[:-1]))            # the last record removed
    intact = by_id(run_checks(Context()))["trail.intact"]
    assert intact.result == "fail" and "cut short" in intact.explanation


def test_writer_and_service_with_systemd(systemd, start_writer):
    _trail_with_records(checkpoint=False)
    systemd.available = True
    results = by_id(run_checks(Context()))
    assert results["service"].result == "warn" and results["service"].fix == "aqt setup"
    assert results["writer"].result == "fail"
    start_writer()
    results = by_id(run_checks(Context()))
    assert results["writer"].result == "ok" and results["sink"].result == "ok"
    assert results["trail.intact"].result == "ok" and "matches the writer" in results["trail.intact"].explanation


def test_unit_with_a_missing_program_is_reported_not_rewritten(systemd):
    _trail_with_records(checkpoint=False)
    systemd.available = True
    unit = checks.unit_path()
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=%h/gone/.venv/bin/aqt-trail serve\n")
    service = by_id(run_checks(Context()))["service"]
    assert service.result == "warn" and not service.can_apply and "does not exist" in service.explanation


def test_time_zone_detection(monkeypatch):
    assert checks.detect_timezone() == "Europe/Vienna"
    monkeypatch.setenv("TZ", ":America/New_York")
    assert checks.detect_timezone() == "America/New_York"
    monkeypatch.setenv("TZ", "Not/AZone")
    assert checks.detect_timezone() != "Not/AZone"


# -- signer: every registry key backed by its enrolment record (aqt_signoff.check_signers) ---------------------
def _registry_edit(**fields):
    from aqt_signoff.settings import load_settings
    path = load_settings().registry_path
    registry = json.loads(path.read_text())
    registry["signers"][0].update(fields)
    path.write_text(json.dumps(registry))


def test_signer_enrolled_with_aqt_signoff_counts():
    enrol()
    signer = by_id(run_checks(Context()))["signer"]
    assert signer.result == "ok" and "human:alice" in signer.explanation and "enrolment records" in signer.explanation
    assert signer.data["keys"][0]["counts"] is True


def test_key_without_enrolment_record_fails_with_rekey_as_fix():
    from aqt_quarantine.config import load_config as quarantine_config
    from aqt_quarantine.decisions import create_identity
    create_identity(quarantine_config(), signer_id="human:bob", name="Bob Example", role="developer",
                    passphrase=lambda _prompt: PASSPHRASE)      # a key enrolled by another tool, no record
    signer = by_id(run_checks(Context()))["signer"]
    assert signer.result == "fail" and not signer.can_apply
    assert "human:bob" in signer.explanation and "no signoff.key.enrolled record" in signer.explanation
    assert signer.fix == "aqt-signoff rekey --signer human:bob"


def test_registry_that_contradicts_the_enrolment_record_fails():
    enrol()
    _registry_edit(role="auditor")                  # the role was changed in signers.json, not re-enrolled
    signer = by_id(run_checks(Context()))["signer"]
    assert signer.result == "fail" and "enrolled role" in signer.explanation
    assert signer.fix == "aqt-signoff signers check" and signer.data["keys"][0]["counts"] is False


def test_discrepancy_that_does_not_stop_the_key_is_a_warning():
    enrol()
    _registry_edit(name="Alice Renamed")
    signer = by_id(run_checks(Context()))["signer"]
    assert signer.result == "warn" and "enrolled name" in signer.explanation
    assert signer.fix == "aqt-signoff signers check" and not signer.can_apply


def test_signer_check_with_an_aqt_signoff_too_old_to_check_keys(monkeypatch):
    import aqt_signoff
    enrol()
    monkeypatch.delattr(aqt_signoff, "check_signers")
    signer = by_id(run_checks(Context()))["signer"]
    assert signer.result == "warn" and "too old" in signer.explanation and "human:alice" in signer.explanation
