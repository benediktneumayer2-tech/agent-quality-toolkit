# Using aqt-validate

## Data

The generic format is JSON lines with `id`, `label` (`benign` | `attack`) and `text`. These fields are optional:
- `group`: session or source; benign items of one group land in the same split;
- `family`, `category`;
- `goal`: attacks with the same goal land in the same split;
- `payload`, `template`;
- `hard`: hard-benign;
- `source` (`name@version`), `license`;
- `context`: passed to detectors unchanged;
- `split`: an explicit split overrides the hash rule.

| Source | Command |
|---|---|
| Benign traffic | Export it yourself (for example from aqt-quarantine `cases export` / passed items) in the generic format. It stays local. |
| BIPIA (MIT) | `data import CLONE --format bipia` (attacks; BIPIA train/test become dev/test). Add `--what benign` for the clean contexts |
| InjecAgent (MIT) | `data import CLONE --format injecagent` |
| LLMail-Inject (MIT) | `data import EXPORT.json --format llmail`. Needs a JSON/JSONL export with `subject`/`body`; parquet must be converted first. Many 2026 guards were trained on it: declare that in the contamination registry |
| AgentDojo (MIT) | `data import CLONE --format agentdojo [--templates-per-goal 2]`. Goals and templates are read by `ast` without importing the package |
| Anything else | Write the generic format, for example from garak/promptfoo output or your own cases |

Always record the benchmark version (`--dataset-version <commit>`). Payload text is never copied into code or records.

## Detector adapters

In `[[detectors]]`, give exactly one of:
- `command = [argv]`: no shell. Batch mode (the default) sends JSONL `{id, text, context}` on stdin and reads JSONL `{id, score_ppm}` (or `score` in [0, 1]) on stdout; it may add `latency_ms` and `error`. With `batch = false` the command runs once per item.
- `callable = "module:function"`: the function takes the text and returns ppm or a probability. The protocol's folder is put on `sys.path`.
- `plugin = "name"`: a detector from the `aqt.detectors` entry-point group (see [aqt-quarantine's detector interface](../../aqt-quarantine/docs/detectors.md)), with `name`, `version` and `score(text) -> DetectorResult(score_ppm, spans)`. A class or factory is called with the `options` table, for example `options = {model_dir = "models/horizon"}` for aqt-quarantine's `onnx` detector. Install `aqt-validate[quarantine]` for aqt-quarantine's detectors. `aqt-validate detector plugins` lists what is installed.
- `scores = "file.jsonl"`: precomputed scores.

Add `model_file = "path"` so that a swapped model changes the configuration hash.

## Reviewer adapters

`argv` placeholders: `{diff}` (diff file), `{workdir}` (snapshot directory, also the working directory), `{prompt}` (rendered prompt file). `stdin = "prompt" | "diff" | "none"`. The prompt template (`prompt_template`) may use `${diff_text}`, `${diff_path}` and `${workdir}`; a default prompt asks for the findings JSON:

```json
{"findings": [{"file": "src/x.py", "line": 12, "end_line": 14, "severity": "high", "summary": "..."}]}
```

Output wrapped in prose, or in `{"result": "..."}` as with `claude -p --output-format json`, is accepted. These argv examples have not been tested against the real CLIs; check them with `reviewer run --split dev --limit 1`:

```toml
argv = ["claude", "-p", "--output-format", "json"]           # stdin = "prompt"
argv = ["codex", "exec", "--sandbox", "read-only", "-"]      # stdin = "prompt"
argv = ["pi", "-p", "@{prompt}"]                             # stdin = "none"; adapt to your pi version
```

A case counts as found when at least `detect_min_runs` runs (default: half, rounded up) name the defect's file and a line within its changed lines ± `line_tolerance`, at or above `min_severity`. A clean case counts as a false alarm on the same rule. Failed runs are errors: they are excluded from the rates, and criterion E0 (`max_errors`, default 0) fails the conclusion. They are cached and rerun only with `--retry-errors`.

## Dev and test

`--split dev` needs no lock and can be repeated. Detector dev runs read the dev attacks; reviewer dev runs are a trial on `--limit` cases. Dev runs cannot be qualified. `--split test` (the default) needs `protocol lock` for the exact protocol file, and each test readout of the same data is counted in the record and the report.
