import json
from pathlib import Path

import pytest

from aqt_evidence import validate_record

from aqt_quarantine.config import load_config
from aqt_quarantine.decisions import Decider, create_identity
from aqt_quarantine.engine import Engine
from aqt_quarantine.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
PASSPHRASE = "correct horse battery"
AGENT_ENV = ("AQT_AGENT_SESSION", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX",
             "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_THREAD_ID", "PI_CODING_AGENT", "GEMINI_CLI", "AIDER_MODEL",
             "GOOSE_SESSION_ID", "OPENCODE")


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated XDG dirs; no sink override, no agent markers."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # doctor looks for ~/.claude/settings.json
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))  # no discovery of a real trail writer
    for name in ("AQT_SINK", "AQT_SIGNERS", "AQT_KEYS_DIR", "AQT_QUARANTINE_CONFIG", "AQT_QUARANTINE_STATE",
                 "AQT_QUARANTINE_THRESHOLDS", "AQT_TRAIL_STATE", "TZ"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


class World:
    """Config, store, engine and a decider whose human check passes and whose passphrase is known."""

    def __init__(self, *, signer: bool = True, passphrase: str = PASSPHRASE, **overrides):
        self.config = load_config()
        for key, value in overrides.items():
            setattr(self.config, key, value)
        if signer:
            create_identity(self.config, signer_id="human:alex", name="Alex Example", role="quality-manager",
                            passphrase=lambda _prompt: PASSPHRASE)
        self.store = Store(self.config.state_dir, sink=self.config.sink)
        self.engine = Engine(self.config, self.store)
        self.passphrase = passphrase
        self.human = lambda: None

    def decider(self, *, human=None, passphrase=None) -> Decider:
        return Decider(self.config, self.store, passphrase=lambda _p: passphrase or self.passphrase,
                       human_check=human or self.human)

    def journal(self) -> list[dict]:
        records = list(self.store.records())
        for record in records:
            assert validate_record(record) == [], record
        return records


@pytest.fixture
def world(env):
    return World()
