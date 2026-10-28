import json
import tomllib

from aqt_signoff.settings import load_settings
from aqt_trail.config import config_dir, load_config

from aqt_cli import checks, tools
from aqt_cli.checks import Context
from aqt_cli.cli import main, setup
from conftest import enrol


class Tools:
    """Runs the real tools, except ``aqt-signoff init``: its passphrase prompt is replaced by the API."""

    def __init__(self):
        self.calls = []

    def __call__(self, name, argv):
        self.calls.append((name, argv))
        if name == "signoff" and argv[0] == "init":
            options = dict(zip(argv[1::2], argv[2::2]))
            enrol(options["--id"], options["--name"], options["--role"])
            return 0
        return tools.run_tool(name, argv)


def _ctx(**kw):
    kw.setdefault("say", lambda text: None)
    kw.setdefault("writer_wait_s", 2.0)
    return Context(**kw)


def test_setup_yes_reaches_green_status_and_a_rerun_changes_nothing(systemd, start_writer, capsys):
    systemd.available = True
    systemd.on_start = start_writer
    runner = Tools()
    code = setup(_ctx(yes=True, signer_id="human:alice", name="Alice Example", role="quality-manager",
                      run_tool=runner))
    assert code == 0
    unit = checks.unit_path().read_text()
    assert f"ExecStart={checks.serve_command()}" in unit and "aqt-trail serve" in unit
    assert f"Environment=XDG_STATE_HOME={load_config().state.parent.parent}" in unit
    assert ("daemon-reload",) in systemd.calls and ("enable", "--now", "aqt-trail") in systemd.calls
    signoff = tomllib.loads(load_settings().config_path.read_text())["signoff"]
    assert signoff == {"signer": "human:alice", "tz": "Europe/Vienna"}
    assert tomllib.loads((config_dir() / "trail.toml").read_text())["review"]["timezone"] == "Europe/Vienna"
    trail = [json.loads(line) for line in load_config().trail_path.read_text().splitlines()]
    assert any(r["type"] == "signoff.key.enrolled" for r in trail)   # the enrolment reached the trail
    capsys.readouterr()                                              # the tools' own output
    assert main(["status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "ok"

    files = {path: path.read_bytes() for path in (checks.unit_path(), load_settings().config_path,
                                                  load_settings().registry_path, config_dir() / "trail.toml")}
    said = []
    runner.calls.clear()
    assert setup(_ctx(yes=True, signer_id="human:bob", name="Bob", role="developer", run_tool=runner,
                      say=said.append)) == 0
    assert said[0] == "aqt setup: nothing to do" and runner.calls == []
    assert {path: path.read_bytes() for path in files} == files


def test_without_systemd_or_a_person_setup_does_the_rest_and_says_what_is_left(systemd):
    said = []
    runner = Tools()
    assert setup(_ctx(yes=True, run_tool=runner, say=said.append)) == 1
    assert runner.calls[0] == ("trail", ["init"]) and load_config().meta_path.exists()
    assert not any(name == "signoff" for name, _ in runner.calls)       # no person at the keyboard
    assert any(line.startswith("signer: skipped: needs you") for line in said)
    assert any(line.startswith("writer: yours to do: ") and "aqt-trail serve" in line for line in said)
    assert not checks.unit_path().exists() and not load_settings().config_path.exists()
    assert (config_dir() / "trail.toml").exists()


def test_existing_files_are_never_overwritten(systemd):
    systemd.available = True
    mine = {checks.unit_path(): "[Service]\nExecStart=/bin/true\n",
            config_dir() / "trail.toml": "[review]\ntimezone = \"UTC\"\n",
            load_settings().config_path: "[signoff]\ntz = \"UTC\"\n"}
    for path, text in mine.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    enrol()
    setup(_ctx(yes=True, run_tool=Tools(), writer_wait_s=0))
    assert {path: path.read_text() for path in mine} == mine
    assert ("enable", "--now", "aqt-trail") in systemd.calls          # enabled, not rewritten


def test_setup_asks_before_each_step_and_respects_no():
    asked = []
    runner = Tools()

    def answer(question):
        asked.append(question)
        return "n"

    setup(_ctx(ask=answer, interactive=True, run_tool=runner))
    assert asked[0].startswith("No trail in ") and asked[0].endswith("Create the trail (aqt-trail init)? [Y/n] ")
    assert runner.calls == [] and not load_config().meta_path.exists()


def test_interactive_enrolment_asks_for_id_name_and_role_but_never_the_passphrase():
    answers = iter(["", "alice", "Alice Example", "quality-manager"])   # yes, ID, name, role
    asked = []

    def answer(question):
        asked.append(question)
        return next(answers)

    runner = Tools()
    checks.step_signer(_ctx(ask=answer, interactive=True, yes=True, run_tool=runner))
    assert runner.calls == [("signoff", ["init", "--id", "human:alice", "--name", "Alice Example",
                                         "--role", "quality-manager"])]
    assert len(asked) == 4      # the passphrase is typed at aqt-signoff's own prompt
