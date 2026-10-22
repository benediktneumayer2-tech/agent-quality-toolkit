# Contributing

Issues and pull requests are welcome.

- `scripts/test_all.sh` creates each package's `.venv` with uv, runs every package's suite and the demo; `scripts/test_all.sh aqt-trail` runs one package. Packages depend on `aqt-spec` (installed from this repository, not yet from PyPI).
- Tests must stay offline and must isolate state: set `XDG_STATE_HOME` and `XDG_CONFIG_HOME` to temporary folders (see the existing `conftest.py` files).
- Interfaces between packages follow the evidence record specification in `aqt-spec/spec/`. Changes to record types or `data` fields that other tools read need a spec change first.
- Regulatory catalogues are paraphrases in your own words (CC BY 4.0). Cite the clause as numbered in the source and say which text you checked.
- No claims that the toolkit makes a process compliant; see the README's honest scope.
