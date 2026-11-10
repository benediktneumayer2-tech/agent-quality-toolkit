"""Pass-through: ``aqt <tool> ARGS...`` runs that tool's command line with the same arguments.

The tool's ``cli.main(argv)`` runs in this process; when the package cannot be imported, its
console script is started instead. A tool that is not installed prints the command that adds it.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

# name in ``aqt <name>`` -> (CLI module, console script, distribution)
TOOLS: dict[str, tuple[str, str, str]] = {
    "trail": ("aqt_trail.cli", "aqt-trail", "aqt-trail"),
    "signoff": ("aqt_signoff.cli", "aqt-signoff", "aqt-signoff"),
    "change": ("aqt_change.cli", "aqt-change", "aqt-change"),
    "sensei": ("aqt_sensei.cli", "aqt-sensei", "aqt-sensei"),
    "quarantine": ("aqt_quarantine.cli", "aqt-quarantine", "aqt-quarantine"),
    "validate": ("aqt_validate.cli", "aqt-validate", "aqt-validate"),
    "capa": ("aqt_capa.cli", "aqt-capa", "aqt-capa"),
    "ui": ("aqt_ui.cli", "aqt-ui", "aqt-ui"),
    "egress": ("aqt_egress.cli", "aqt-egress", "aqt-egress"),     # optional: agent-quality-toolkit[egress]
    "spec": ("aqt_evidence.cli", "aqt-evidence", "aqt-spec"),
    "evidence": ("aqt_evidence.cli", "aqt-evidence", "aqt-spec"),
}


# what a package needs beyond the toolkit's own Python 3.11
REQUIRES = {"aqt-egress": "Python 3.12 or newer, bubblewrap"}
TOOLKIT = "agent-quality-toolkit"
EXTRAS = {"aqt-egress": "egress"}       # optional packages, installed as extras of the toolkit


def install_route() -> str:
    """How this ``aqt`` was installed: ``uv-tool``, ``pipx``, ``clone`` (editable, from a repository clone)
    or ``pip`` (any other environment)."""
    prefix = Path(sys.prefix)
    if (prefix / "uv-receipt.toml").is_file():
        return "uv-tool"
    if (prefix / "pipx_metadata.json").is_file():
        return "pipx"
    try:
        origin = json.loads(metadata.distribution(TOOLKIT).read_text("direct_url.json") or "{}")
    except (metadata.PackageNotFoundError, ValueError):
        origin = {}
    return "clone" if origin.get("dir_info", {}).get("editable") else "pip"


def _installed(dist: str) -> bool:
    try:
        metadata.version(dist)
    except metadata.PackageNotFoundError:
        return False
    return True


def install_command(*distributions: str) -> str:
    """The command that adds these packages to this installation of the toolkit; from a repository clone
    (the developer route), the editable install."""
    route = install_route()
    needs = [f"{dist} needs {REQUIRES[dist]}" for dist in distributions if dist in REQUIRES]
    if route == "clone":
        return ("uv pip install " + " ".join(f"-e ./{dist}" for dist in distributions) + "   (in the repository clone"
                + "".join(f"; {need}" for need in needs) + ")")
    if route in ("uv-tool", "pipx"):       # the toolkit again, with the extras it has plus the missing ones
        extras = sorted({EXTRAS[dist] for dist in EXTRAS if dist in distributions or _installed(dist)})
        spec = f'"{TOOLKIT}[{",".join(extras)}]"' if extras else TOOLKIT
        older = "egress" in extras and sys.version_info < (3, 12)
        if route == "uv-tool":
            command = "uv tool install " + ("--python 3.12 " if older else "") + spec
        else:
            command = "pipx install --force " + ("--python python3.12 " if older else "") + spec
    else:
        command = "pip install " + " ".join(distributions)
    return command + (f"   ({'; '.join(needs)})" if needs else "")


def distribution_of(module: str | None) -> str:
    """``aqt_trail.cli`` -> ``aqt-trail``; the record library ``aqt_evidence`` ships as ``aqt-spec``."""
    package = (module or "").split(".")[0]
    for cli_module, _script, dist in TOOLS.values():
        if cli_module.split(".")[0] == package:
            return dist
    return package.replace("_", "-")


def _exit_code(code) -> int:
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    print(code, file=sys.stderr)  # sys.exit("message")
    return 1


def run_tool(name: str, argv: list[str]) -> int:
    """Run tool ``name`` with ``argv``; returns its exit code (2 when it is not installed)."""
    module_name, script, dist = TOOLS[name]
    if importlib.util.find_spec(module_name.split(".")[0]) is not None:
        module = importlib.import_module(module_name)
        try:
            return _exit_code(module.main(list(argv)))
        except SystemExit as exit_:  # argparse errors and --help
            return _exit_code(exit_.code)
    executable = shutil.which(script)
    if executable:
        return subprocess.run([executable, *argv]).returncode
    print(f"aqt: {dist} is not installed; install it with: {install_command(dist)}", file=sys.stderr)
    return 2
