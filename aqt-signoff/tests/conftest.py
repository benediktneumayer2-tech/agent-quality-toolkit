from datetime import UTC, datetime, timedelta

import pytest

from aqt_signoff import Signoff, StaticPassphrase, load_settings

PASSWORDS = {"human:alice": "alice-passphrase-1", "human:bob": "bob-passphrase-22", "human:carol": "carol-passphrase-3"}


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Keep every test away from the real XDG directories and the real agent environment."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))  # no discovery of a real trail writer
    for name in ("AQT_SINK", "AQT_EVIDENCE", "AQT_SIGNERS", "AQT_KEYS_DIR", "AQT_SIGNOFF_STATE",
                 "AQT_SIGNOFF_CONFIG", "AQT_ACTOR", "AQT_TRAIL_STATE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("aqt_evidence.crypto.SCRYPT_N", 2**10)   # fast keys; files record their cost
    return tmp_path


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "signoff.toml"
    path.write_text('[signoff]\ntz = "America/New_York"\n', encoding="utf-8")
    return path


@pytest.fixture
def make(tmp_path, clock, config):
    """``make("human:alice")`` -> a Signoff acting with Alice's passphrase; ``environ``/``chain`` overridable."""
    sink = tmp_path / "evidence.jsonl"

    def factory(signer=None, *, passphrase=None, environ=None, chain=None, config_path=None, **settings_kwargs):
        settings = load_settings(config=config_path or config, sink=f"file:{sink}", **settings_kwargs)
        if signer:
            settings.signer = signer
        auth = StaticPassphrase(passphrase or PASSWORDS.get(signer or "", "default-passphrase"))
        return Signoff(settings, authenticator=auth, environ={} if environ is None else environ,
                       chain=[] if chain is None else chain, require_tty=False, clock=clock)

    factory.sink = sink
    return factory


def key_id_of(make, signer_id: str) -> str:
    return make(signer_id).reload_registry().get(signer_id).active_key().key_id


@pytest.fixture
def people(make, clock):
    """Alice (quality-manager, the first signer), Bob (developer) and Carol (qa) enrolled; Alice approved
    Bob's and Carol's enrolments (every enrolment after the first needs an enrolled signer's approval)."""
    for signer, name, role in (("human:alice", "Alice Example", "quality-manager"),
                               ("human:bob", "Bob Example", "developer"),
                               ("human:carol", "Carol Example", "qa")):
        make(signer).init_signer(signer, name, role)
    for signer in ("human:bob", "human:carol"):
        make("human:alice").approve_enrolment(signer, key_id_of(make, signer))
    clock.advance(seconds=1)
    return {signer: make(signer) for signer in PASSWORDS}
