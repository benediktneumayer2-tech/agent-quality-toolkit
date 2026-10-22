"""Detector adapters: how aqt-validate obtains a score for each item.

- ``scores``: a JSONL file of precomputed ``{id, score_ppm | score, latency_ms?}``;
- ``command``: an argv (no shell). Batch mode (default) sends every item as JSONL
  ``{id, text, context}`` on stdin and reads JSONL ``{id, score_ppm | score, latency_ms?}``;
  ``batch = false`` runs the command once per item with one JSON object on stdin and
  reads one JSON object (``score_ppm`` or ``score``) on stdout;
- ``callable``: ``module:function`` called with the item text;
- ``plugin``: a detector from the ``aqt.detectors`` entry-point group (aqt-quarantine docs/detectors.md):
  an object with ``name``, ``version`` and ``score(text) -> DetectorResult(score_ppm, spans)``;
  a class or factory is called with the spec's ``options`` table (e.g. ``model_dir``).

Scores are integers in ppm (0..1,000,000). A float in [0, 1] is read as a probability and
converted. Anything else is an error for that item; errors are reported, never guessed.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from .stats import PPM


class AdapterError(RuntimeError):
    pass


@dataclass
class Scores:
    detector: str
    version: str
    ppm: dict[str, int] = field(default_factory=dict)
    latency_ms: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def to_ppm(value) -> int:
    if hasattr(value, "score_ppm"):
        value = value.score_ppm
    elif isinstance(value, dict):
        if "score_ppm" in value:
            value = value["score_ppm"]
        elif "score" in value:
            value = value["score"]
        else:
            raise ValueError("no score_ppm or score field")
    if isinstance(value, bool):
        raise ValueError("score must be a number")
    if isinstance(value, int):
        if not 0 <= value <= PPM:
            raise ValueError(f"score_ppm {value} outside 0..{PPM}")
        return value
    if isinstance(value, float):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"float score {value} outside [0, 1]")
        return round(value * PPM)
    raise ValueError(f"score must be a number, got {type(value).__name__}")


def _item_payload(item: dict) -> dict:
    out = {"id": item["id"], "text": item["text"]}
    if "context" in item:
        out["context"] = item["context"]
    return out


def score_items(spec: dict, items: list[dict], *, base: Path) -> Scores:
    kind = next(k for k in ("scores", "command", "callable", "plugin") if k in spec)
    result = Scores(spec["id"], str(spec.get("version", "")))
    if kind == "scores":
        _from_file(result, base / spec["scores"] if not Path(spec["scores"]).is_absolute() else Path(spec["scores"]), items)
    elif kind == "command":
        if spec.get("batch", True):
            _command_batch(result, spec, items, base)
        else:
            _per_item(result, items, lambda item: _command_one(spec, item, base))
    elif kind == "callable":
        function = load_callable(spec["callable"], base)
        _per_item(result, items, lambda item: function(item["text"]))
    else:
        detector = load_plugin(spec["plugin"], spec.get("options") or {})
        result.version = result.version or str(getattr(detector, "version", ""))
        _per_item(result, items, lambda item: detector.score(item["text"]))
    return result


def _from_file(result: Scores, path: Path, items: list[dict]) -> None:
    if not path.exists():
        raise AdapterError(f"score file not found: {path}")
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows[str(row.get("id"))] = row
    for item in items:
        row = rows.get(item["id"])
        if row is None:
            result.errors[item["id"]] = "missing from score file"
            continue
        try:
            result.ppm[item["id"]] = to_ppm(row)
        except ValueError as error:
            result.errors[item["id"]] = str(error)
        if isinstance(row.get("latency_ms"), (int, float)):
            result.latency_ms[item["id"]] = int(row["latency_ms"])


def _per_item(result: Scores, items: list[dict], call) -> None:
    for item in items:
        start = time.perf_counter()
        try:
            value = call(item)
            result.ppm[item["id"]] = to_ppm(value)
        except Exception as error:  # an error is a result: recorded per item, never a guess
            result.errors[item["id"]] = f"{type(error).__name__}: {error}"[:300]
            continue
        result.latency_ms[item["id"]] = round((time.perf_counter() - start) * 1000)


def _command_batch(result: Scores, spec: dict, items: list[dict], base: Path) -> None:
    stdin = "".join(json.dumps(_item_payload(i), ensure_ascii=False) + "\n" for i in items)
    try:
        done = subprocess.run(spec["command"], input=stdin, capture_output=True, text=True, cwd=base,
                              timeout=float(spec.get("timeout_s", 3600)))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AdapterError(f"detector {spec['id']}: command failed: {error}") from None
    if done.returncode != 0:
        raise AdapterError(f"detector {spec['id']}: command exited {done.returncode}: {done.stderr.strip()[:300]}")
    rows = {}
    for line in done.stdout.splitlines():
        if line.strip():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                raise AdapterError(f"detector {spec['id']}: output line is not JSON: {line[:120]}") from None
            rows[str(row.get("id"))] = row
    for item in items:
        row = rows.get(item["id"])
        if row is None:
            result.errors[item["id"]] = "no output for item"
            continue
        if row.get("error"):
            result.errors[item["id"]] = str(row["error"])[:300]
            continue
        try:
            result.ppm[item["id"]] = to_ppm(row)
        except ValueError as error:
            result.errors[item["id"]] = str(error)
        if isinstance(row.get("latency_ms"), (int, float)):
            result.latency_ms[item["id"]] = int(row["latency_ms"])


def _command_one(spec: dict, item: dict, base: Path):
    done = subprocess.run(spec["command"], input=json.dumps(_item_payload(item), ensure_ascii=False),
                          capture_output=True, text=True, cwd=base, timeout=float(spec.get("timeout_s", 120)))
    if done.returncode != 0:
        raise AdapterError(f"exit {done.returncode}: {done.stderr.strip()[:200]}")
    return json.loads(done.stdout)


def load_callable(target: str, base: Path):
    module_name, _, attr = target.partition(":")
    if not attr:
        raise AdapterError(f"callable must look like module:function, got {target!r}")
    if str(base) not in sys.path:
        sys.path.insert(0, str(base))  # the protocol is trusted input; its folder may hold the detector
    try:
        module = importlib.import_module(module_name)
        return getattr(module, attr)
    except (ImportError, AttributeError) as error:
        raise AdapterError(f"cannot load {target}: {error}") from None


def detector_identity(spec: dict, base: Path) -> dict:
    """What actually runs for a detector spec: the effective version and a code hash.

    - plugin: the loaded plug-in's own ``version`` (e.g. aqt-quarantine's heuristics version
      includes its pattern-table hash). A version pinned in the protocol must match it.
    - command: hash of the argv plus the bytes of every argv element that is an existing file
      (the detector script), so an edited script changes the configuration hash.
    - callable: hash of the target string plus the module's source file.
    """
    from aqt_evidence import bytes_hash, content_hash

    declared = str(spec.get("version", ""))
    identity = {"version": declared}
    if "plugin" in spec:
        detector = load_plugin(spec["plugin"], spec.get("options") or {})
        loaded = str(getattr(detector, "version", "") or "")
        if declared and loaded and declared != loaded:
            raise AdapterError(f"detector {spec['id']}: the protocol pins version {declared!r} but the installed "
                               f"plug-in {spec['plugin']!r} reports {loaded!r}; update the protocol (and requalify) "
                               "or install the pinned version")
        identity["version"] = loaded or declared
    elif "command" in spec:
        files = {}
        for arg in spec["command"]:
            path = Path(arg) if Path(arg).is_absolute() else base / arg
            if arg and path.is_file():
                files[arg] = bytes_hash(path.read_bytes())
        identity["code_sha256"] = content_hash({"argv": list(spec["command"]), "files": files})
    elif "callable" in spec:
        module_name = spec["callable"].partition(":")[0]
        origin = None
        try:
            import importlib.util
            if str(base) not in sys.path:
                sys.path.insert(0, str(base))
            found = importlib.util.find_spec(module_name)
            origin = found.origin if found else None
        except (ImportError, ValueError):
            origin = None
        source = {"target": spec["callable"]}
        if origin and Path(origin).is_file():
            source["module_sha256"] = bytes_hash(Path(origin).read_bytes())
        identity["code_sha256"] = content_hash(source)
    return identity


def available_plugins() -> list[str]:
    return sorted(ep.name for ep in metadata.entry_points(group="aqt.detectors"))


def load_plugin(name: str, options: dict | None = None):
    matches = [ep for ep in metadata.entry_points(group="aqt.detectors") if ep.name == name]
    if not matches:
        raise AdapterError(f"no detector plugin {name!r} in entry-point group aqt.detectors "
                           f"(installed: {', '.join(available_plugins()) or 'none'}; "
                           "install aqt-validate[quarantine] or use a command detector)")
    obj = matches[0].load()
    if not hasattr(obj, "score") or isinstance(obj, type):
        try:
            obj = obj(**(options or {}))  # a class or factory, e.g. aqt_quarantine's OnnxDetector(model_dir=...)
        except Exception as error:
            raise AdapterError(f"detector plugin {name!r} could not be created: {error}") from None
    if not callable(getattr(obj, "score", None)):
        raise AdapterError(f"detector plugin {name!r} has no score(text) method")
    return obj
