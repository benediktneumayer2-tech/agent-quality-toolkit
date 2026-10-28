"""Pass-through: ``aqt <tool> ARGS...`` runs that tool's command line with the same arguments.

The tool's ``cli.main(argv)`` runs in this process; when the package cannot be imported, its
console script is started instead. A tool that is not installed prints the install command.
"""

from __future__ import annotations

import importlib
import importlib.util
import shutil
import subprocess
import sys

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
    "spec": ("aqt_evidence.cli", "aqt-evidence", "aqt-spec"),
    "evidence": ("aqt_evidence.cli", "aqt-evidence", "aqt-spec"),
}


def install_command(*distributions: str) -> str:
    """How to install packages today: editable from a clone of the repository (not on PyPI yet)."""
    return "uv pip install " + " ".join(f"-e ./{dist}" for dist in distributions) + "   (in the repository clone)"


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
