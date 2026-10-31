"""Optional transformer detector: a local ONNX sequence-classification export.

Install with ``pip install 'aqt-quarantine[hf]'``. Nothing is downloaded: point
``model_dir`` at a directory with ``model.onnx`` (or ``model_file``) and
``tokenizer.json``, for example an ONNX export of Horizon prompt-injection-guard,
Wolf Defender, PIGuard or deepset deberta-v3-base-injection (check each model's
licence and card). The text is split into overlapping token windows; the score
is the highest probability of the positive label over all windows, in ppm.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from . import DetectorError, DetectorResult, Span

MODEL_WINDOW = "highest-scoring model window"     # the span reason; message code quarantine.detector.model_window


class OnnxDetector:
    def __init__(self, *, model_dir: str, name: str = "onnx", version: str | None = None,
                 model_file: str = "model.onnx", positive_index: int = 1, window_tokens: int = 512,
                 stride_tokens: int = 128, max_windows: int = 256, threads: int = 2,
                 session: Any = None, tokenizer: Any = None):
        self.name = name
        directory = Path(model_dir).expanduser()
        self.version = version or f"{directory.name}/{model_file}"
        self.positive_index = positive_index
        self.window, self.stride, self.max_windows = window_tokens, stride_tokens, max_windows
        if session is None or tokenizer is None:
            try:
                import onnxruntime  # noqa: PLC0415 (optional dependency, loaded on demand)
                from tokenizers import Tokenizer  # noqa: PLC0415
            except ImportError as error:
                raise DetectorError("the onnx detector needs the [hf] extra: pip install 'aqt-quarantine[hf]'") from error
            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = threads
            session = session or onnxruntime.InferenceSession(str(directory / model_file), options,
                                                              providers=["CPUExecutionProvider"])
            tokenizer = tokenizer or Tokenizer.from_file(str(directory / "tokenizer.json"))
        self.session, self.tokenizer = session, tokenizer
        self.inputs = {item.name for item in session.get_inputs()}

    def _windows(self, ids: list[int]) -> list[tuple[int, int]]:
        size = self.window - 2  # room for special tokens
        if len(ids) <= size:
            return [(0, len(ids))]
        step = max(1, size - self.stride)
        return [(start, min(start + size, len(ids))) for start in range(0, len(ids) - self.stride, step)][: self.max_windows]

    def score(self, text: str) -> DetectorResult:
        encoding = self.tokenizer.encode(text, add_special_tokens=False)
        ids, offsets = list(encoding.ids), list(encoding.offsets)
        if not ids:
            return DetectorResult(0)
        best, best_span = 0.0, (0, 0)
        for start, end in self._windows(ids):
            window = ids[start:end]
            feeds = {"input_ids": [window]}
            if "attention_mask" in self.inputs:
                feeds["attention_mask"] = [[1] * len(window)]
            if "token_type_ids" in self.inputs:
                feeds["token_type_ids"] = [[0] * len(window)]
            logits = list(self.session.run(None, self._as_arrays(feeds))[0][0])
            peak = max(logits)
            exps = [math.exp(value - peak) for value in logits]
            probability = exps[self.positive_index] / sum(exps)
            if probability > best:
                best, best_span = probability, (offsets[start][0], offsets[end - 1][1])
        spans = [Span(best_span[0], best_span[1], self.name, MODEL_WINDOW)] \
            if best_span[1] > best_span[0] else []
        return DetectorResult(int(round(best * 1_000_000)), spans)

    @staticmethod
    def _as_arrays(feeds: dict) -> dict:
        try:
            import numpy  # noqa: PLC0415
        except ImportError:
            return feeds  # test doubles accept plain lists
        return {key: numpy.asarray(value, dtype=numpy.int64) for key, value in feeds.items()}
