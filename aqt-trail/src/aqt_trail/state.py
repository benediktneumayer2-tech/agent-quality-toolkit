"""Creating and opening a trail state directory."""

from __future__ import annotations

import json
import os
from pathlib import Path

from aqt_evidence import generate_key, load_public_key, load_signer, utc_now

from .config import Config
from .writer import TrailWriter


def init_state(config: Config, *, log_id: str | None = None) -> dict:
    """Create the state directory, the service key and ``trail.json``. Idempotent."""
    config.state.mkdir(parents=True, exist_ok=True)
    if not str(config.section("writer")["log_mode"]).endswith("40"):
        os.chmod(config.state, 0o700)
    if config.meta_path.exists():
        return config.meta()
    if not config.key_path.exists():
        generate_key(config.key_path)  # unencrypted: the writer must start unattended
    key_id, _ = load_public_key(f"{config.key_path}.pub")
    meta = {"log_id": log_id or f"trail_{os.urandom(8).hex()}", "key_id": key_id, "created": utc_now()}
    config.meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def service_keys(config: Config) -> dict:
    """Public keys of this trail's writer (all ``keys/*.pub`` in the state directory)."""
    keys = {}
    for path in sorted((config.state / "keys").glob("*.pub")):
        key_id, public = load_public_key(path)
        keys[key_id] = public
    return keys


def open_writer(config: Config) -> TrailWriter:
    if not config.meta_path.exists():
        raise FileNotFoundError(f"no trail at {config.state}; run 'aqt-trail init' first")
    meta = config.meta()
    signer = load_signer(config.key_path)
    writer = TrailWriter(config.state, signer, meta["log_id"],
                         clock_jump_ms=int(config.section("writer")["clock_jump_ms"]),
                         file_mode=int(str(config.section("writer")["log_mode"]), 8))
    return writer.open()


def read_records(path: str | os.PathLike) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    records = []
    with open(path, "rb") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records
