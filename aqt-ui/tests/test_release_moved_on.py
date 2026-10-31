"""Third review of Sign released (R-e3): the record signed must be a finish of what the fresh gate evaluated,
not merely some finish in the repository's history: the accepted plan version, the receipts the gate counts
now and, for a finish that committed, HEAD (or a commit with HEAD's files). The agent here uses only what its
user can do: git in the repository, aqt-change, appending to the mirror and ``Ledger.emit`` (the sink)."""

import json
import subprocess
import sys
import threading
from pathlib import Path

from conftest import trail_records
from test_release import P, body, change_of, finish_project, finished, git  # noqa: F401 - fixture
from test_release_binding import finish_of, mirror, mirror_records, queue

from aqt_ui.config import UiConfig

MOVED_ON = {"ui.release.other_plan_version", "ui.release.other_receipts", "ui.release.other_head"}


def out(root: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()


def rerun(root: Path, monkeypatch, env) -> None:
    from aqt_change import receipts
    from aqt_change.ledger import Ledger
    monkeypatch.chdir(root)
    receipts.run(Ledger.open(root), [], plan_path=P, all_items=True, echo=False)
    monkeypatch.chdir(env)


def forge_finish(root: Path, monkeypatch, env, **data) -> dict:
    """The agent writes its own change.finish record through the sink and the mirror (no aqt-change finish)."""
    from aqt_change.actors import current_actor
    from aqt_change.ledger import Ledger
    from aqt_evidence import new_record, subject
    monkeypatch.chdir(root)
    ledger = Ledger.open(root)
    real = [r for r in mirror_records(root) if r["type"] == "change.finish"][-1]
    record = new_record("change.finish", current_actor(ledger.config.actor), "finish",
                        subject=subject("plan", "s01", sha256=real["subject"]["sha256"]),
                        before=real.get("before"), after=real.get("after"), links=real.get("links"),
                        data={**real["data"], **data})
    record["data"] = {k: v for k, v in record["data"].items() if v is not None}
    stored = ledger.emit(record)
    monkeypatch.chdir(env)
    return stored


def refused(client, trail, data, codes=MOVED_ON):
    plan = data["plan"]
    assert plan["release"]["state"] == "unbound" and plan["finish_problem_code"] in codes, plan.get("finish_problem")
    assert [s["state"] for s in data["steps"] if s["id"] == "release"] == ["person"]
    before = len(trail_records(trail))
    status, result, _ = client.post("/api/change/0/s01/release", body(data))
    assert status == 409 and result["message_args"]["why"]["code"] in codes, result
    assert not [r for r in trail_records(trail)[before:] if r["type"] == "signoff.signature"]


# -- E3-3a: commits after the finish ----------------------------------------------------------------------------
def test_a_finish_is_not_released_after_later_commits(finished, trail, env, ui_factory, monkeypatch):
    (finished / "src" / "calc.py").write_text("def add(a, b):\n    return a + b  # changed after finish\n"
                                             "\ndef exfiltrate():\n    return open('/etc/hostname').read()\n")
    git(finished, "commit", "-qam", "more work after finish (no new finish)")
    rerun(finished, monkeypatch, env)
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    assert data["plan"]["decision"] == "GO" and data["plan"]["head"] == out(finished, "rev-parse", "HEAD")
    refused(client, trail, data)
    assert queue(client)["release:0:s01"]["code"] == "finish_unbound"


# -- E3-2: an agent-written finish naming an untested ancestor ----------------------------------------------------
def test_a_forged_finish_naming_an_untested_ancestor_is_refused(finished, trail, env, ui_factory, monkeypatch):
    good = (finished / "src" / "calc.py").read_text()
    (finished / "src" / "calc.py").write_text("def add(a, b):\n    return a - b  # BAD\n")
    git(finished, "commit", "-qam", "bad build\n\nAQT-Finish: s01/forged")
    bad = out(finished, "rev-parse", "HEAD")
    (finished / "src" / "calc.py").write_text(good)
    git(finished, "commit", "-qam", "restore")
    forged = forge_finish(finished, monkeypatch, env, idempotency_key="forged", commit=bad, head=bad, gate="GO")
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    assert data["plan"]["finish"] == forged["id"]
    refused(client, trail, data, {"ui.release.other_head"})


# -- E3-4: the --no-commit shape: bound by receipts and plan version, the head labelled as before the change -------
def test_a_finish_without_a_commit_is_bound_by_receipts_and_plan_version(finished, trail, env, ui_factory, monkeypatch):
    initial = out(finished, "rev-list", "--max-parents=0", "HEAD")
    forged = forge_finish(finished, monkeypatch, env, idempotency_key="nc", commit=None, head=initial)
    client = ui_factory(config=UiConfig(projects=[finished]))
    client.login()
    data = change_of(client)
    plan = data["plan"]
    assert plan["finish"] == forged["id"] and plan["release"]["state"] == "unreleased"
    assert plan["finish_record"]["commit"] is None and plan["finish_record"]["head"] == initial
    assert plan["head"] == out(finished, "rev-parse", "HEAD") != initial          # HEAD is shown beside it
    app = (Path(__file__).resolve().parents[1] / "src" / "aqt_ui" / "static" / "app.js").read_text()
    assert 't("Head before the change")' in app and "head before the change {before}, HEAD {head}" in app
    # the same shape after a later commit names receipts the gate no longer counts
    (finished / "src" / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    git(finished, "commit", "-qam", "later")
    rerun(finished, monkeypatch, env)
    refused(client, trail, change_of(client))


# -- E3-1: another project's finish after its history was merged with -s ours ---------------------------------------
def test_another_projects_finish_is_refused_after_merge_ours(finished, trail, env, ui_factory, monkeypatch):
    from aqt_change.ledger import Ledger
    from aqt_change.review import add_review
    other = finish_project(env / "other", env, monkeypatch)
    monkeypatch.chdir(other)
    add_review(Ledger.open(other), P, reviewer="agent:x:3", independence="different-model", verdict="FAIL",
               reason="broken")
    monkeypatch.chdir(env)
    theirs = finish_of(other)
    git(finished, "fetch", "-q", str(other), "main")
    git(finished, "merge", "-q", "-s", "ours", "--allow-unrelated-histories", "-m", "merge (tree unchanged)",
        "FETCH_HEAD")
    with open(mirror(finished), "a") as handle:
        handle.write(json.dumps(theirs) + "\n")
    client = ui_factory(config=UiConfig(projects=[finished, other]))
    client.login()
    data = change_of(client)
    assert data["plan"]["decision"] == "GO" and data["plan"]["finish"] == theirs["id"]
    refused(client, trail, data, {"ui.release.other_plan_version", "ui.release.other_receipts"})
    status, other_data, _ = client.get("/api/change/1/s01?fresh=1")
    assert other_data["plan"]["release"]["state"] == "unreleased"


# -- E3-3b: the finish of an older plan version (lifecycle_owner = external) ---------------------------------------
def test_the_finish_of_an_older_plan_version_is_refused(trail, signer, env, ui_factory, monkeypatch):
    from aqt_change import plans, receipts
    from aqt_change.ledger import Ledger
    (env / "config" / "aqt").mkdir(parents=True, exist_ok=True)
    (env / "config" / "aqt" / "change.toml").write_text('lifecycle_owner = "external"\n')
    root = finish_project(env / "ext", env, monkeypatch)
    monkeypatch.chdir(root)
    plan = root / P
    plan.write_text(plan.read_text().replace("## Progress Log", "- [ ] [V02] Second check passes `$ " + sys.executable
                                             + " tests/check.py`\n\n## Progress Log"))
    plans.reconcile(Ledger.open(root), P, "semantic", "add V02 after finish")
    receipts.run(Ledger.open(root), [], plan_path=P, all_items=True, echo=False)
    git(root, "commit", "-qam", "plan v2")
    monkeypatch.chdir(env)
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    data = change_of(client)
    assert data["plan"]["decision"] == "GO"
    refused(client, trail, data, {"ui.release.other_plan_version", "ui.release.other_receipts"})


# -- the legitimate paths keep working ------------------------------------------------------------------------------
def test_release_with_require_trail_and_pinned_trail_keys(trail, signer, env, ui_factory, monkeypatch):
    from aqt_change.ledger import Ledger
    from aqt_evidence import load_public_key
    import test_release
    kid, _ = load_public_key(f"{trail.key_path}.pub")
    real_git = test_release.git

    def git_with_pin(root, *args):
        real_git(root, *args)
        if args[:2] == ("config", "user.name"):
            (root / ".aqt").mkdir(exist_ok=True)
            (root / ".aqt" / "change.toml").write_text(f'require_trail = true\ntrail_keys = ["{kid}"]\n')
    monkeypatch.setattr(test_release, "git", git_with_pin)
    root = finish_project(env / "pinned", env, monkeypatch)
    settings = Ledger.open(root).project_settings("s01")
    assert settings["require_trail"] and settings["trail_keys"] == [kid]
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    data = change_of(client)
    fin = data["plan"]["finish_record"]
    assert data["plan"]["release"]["state"] == "unreleased" and fin["commit"] == data["plan"]["head"]
    assert fin["observed"]["via"] == "socket"                                       # E3-6: the writer's view
    assert client.post("/api/change/0/s01/release", body(data))[0] == 200
    assert change_of(client, fresh=False)["plan"]["release"]["state"] == "released"
    assert "release:0:s01" not in queue(client)


def test_release_without_a_trail(signer, env, ui_factory, monkeypatch):
    root = finish_project(env / "plain", env, monkeypatch)
    client = ui_factory(config=UiConfig(projects=[root]))
    client.login()
    data = change_of(client)
    assert data["plan"]["release"]["state"] == "unreleased" and data["plan"]["finish_record"]["observed"] is None
    assert client.post("/api/change/0/s01/release", body(data))[0] == 200
    assert change_of(client, fresh=False)["plan"]["release"]["state"] == "released"


# -- E3-5: the shared release-state cache is used under a lock --------------------------------------------------------
def test_the_release_cache_is_changed_only_under_its_lock():
    from aqt_ui.views import changes
    changes._RELEASES[("rec_x", (), ())] = {"state": "released"}
    with changes._RELEASES_LOCK:
        worker = threading.Thread(target=changes.forget_release, args=("rec_x",))
        worker.start()
        worker.join(0.3)
        assert worker.is_alive() and ("rec_x", (), ()) in changes._RELEASES     # waits for the lock
    worker.join(5)
    assert not worker.is_alive() and ("rec_x", (), ()) not in changes._RELEASES
