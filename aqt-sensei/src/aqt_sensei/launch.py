"""`aqt-sensei launch --pair ID`: started by the bridge inside the advisor pane.

Renders the advisor prompt, starts the Herdr report proxy when the pane is a
Herdr pane, and replaces itself with bubblewrap running the advisor CLI.
"""

from __future__ import annotations

import json
import os
from dataclasses import fields

from .config import Config, Paths
from .sandbox import Profile, SandboxError, build_argv, resolve_cli, start_herdr_proxy, write_prompt


def load_pair(paths: Paths, pair_id: str) -> dict:
    try:
        data = json.loads((paths.state / "pairs.json").read_text())
    except (OSError, ValueError) as error:
        raise SandboxError(f"no pairs file in {paths.state}") from error
    for pair in data.get("pairs", []):
        if pair.get("id") == pair_id:
            return pair
    raise SandboxError(f"no pair {pair_id!r}")


def profile_of(pair: dict) -> Profile:
    names = {field.name for field in fields(Profile)}
    return Profile(**{key: value for key, value in pair["profile"].items() if key in names})


def home_of(paths: Paths, profile: Profile):
    return paths.home(profile.platform if profile.platform != "custom" else f"custom-{profile.name}")


def prepare(pair: dict, *, paths: Paths, config: Config, command: list[str] | None = None,
            environ: dict | None = None, resolve=resolve_cli, proxy: bool = True) -> list[str]:
    """Everything up to the exec: prompt, private home, proxy; returns the bwrap argv."""
    environ = os.environ if environ is None else environ
    profile = profile_of(pair)
    cli_path, cli_binds = resolve(profile.command[0])
    write_prompt(pair, profile)
    home_of(paths, profile).mkdir(parents=True, exist_ok=True, mode=0o700)
    paths.pair_runtime(pair["id"]).mkdir(parents=True, exist_ok=True, mode=0o700)
    bridge_proxy = None
    upstream = environ.get("HERDR_SOCKET_PATH")
    if proxy and pair.get("backend") == "herdr" and upstream:
        path = paths.pair_runtime(pair["id"]) / "herdr.sock"
        start_herdr_proxy(path, pair["advisor"]["pane_id"], upstream)
        bridge_proxy = (str(path), upstream)
    return build_argv(pair, profile, paths=paths, config=config, cli_path=cli_path, cli_binds=cli_binds,
                      environ=environ, command=command, proxy=bridge_proxy)


def launch(pair_id: str, *, paths: Paths, config: Config, command: list[str] | None = None) -> int:
    pair = load_pair(paths, pair_id)
    if pair.get("state") == "ended":
        raise SandboxError("the pair has ended")
    argv = prepare(pair, paths=paths, config=config, command=command)
    os.chdir(pair["scratch_dir"])
    os.execvp(argv[0], argv)
    return 1  # not reached
