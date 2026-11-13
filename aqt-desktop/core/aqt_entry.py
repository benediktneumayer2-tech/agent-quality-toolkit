"""Entry point of the frozen AQT runtime (PyInstaller): the `aqt` command with every tool as a subcommand,
and the core of the desktop app (`aqt core --stdio`).

The packages start helpers with their own interpreter, `sys.executable -m <module> ...` (the trail writer,
the git commit-msg hook, the egress network helper, the sensei launcher). Frozen, sys.executable is this
program, so `aqt [-I] -m <module> ...` runs that module as `python -m` would.
"""

import sys


def main() -> int:
    args = sys.argv[1:]
    flags = 0
    while flags < len(args) and args[flags] in ("-I", "-E", "-s", "-u", "-B"):   # interpreter flags: accepted
        flags += 1
    if flags + 1 < len(args) and args[flags] == "-m":
        import runpy
        module = args[flags + 1]
        sys.argv = [module, *args[flags + 2:]]
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return 0
    from aqt_cli.cli import main as aqt
    return aqt()


if __name__ == "__main__":
    sys.exit(main())
