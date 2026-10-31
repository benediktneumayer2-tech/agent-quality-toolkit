"""Records: built on the proxy's event loop, appended by one background thread.

Every record goes through ``aqt_evidence.open_sink()`` (sink discovery, spec section 10.1): to the
aqt-trail writer when one runs, through the spool while it is down, or to the fallback file. The
writer attributes the records to this process; what the box sent is in ``data.process``.
"""

from __future__ import annotations

import queue
import sys
import threading

from aqt_evidence import actor, new_record, open_sink

ACTOR = actor("service", "service:aqt-egress")


class RecordWriter:
    def __init__(self, sink=None, *, log=None):
        self.sink = sink if sink is not None else open_sink()
        self.queue: queue.Queue = queue.Queue()
        self.written = 0
        self.failed = 0
        self.last_error: str | None = None
        self.log = log
        self.thread = threading.Thread(target=self._run, name="aqt-egress-records", daemon=True)
        self.thread.start()

    def emit(self, type_: str, action: str, data: dict, *, subject: dict | None = None,
             links: list[dict] | None = None) -> str:
        """Queue a record; returns its id at once."""
        record = new_record(type_, ACTOR, action, subject=subject, links=links, data=data)
        self.queue.put(record)
        return record["id"]

    def submit(self, build) -> None:
        """Queue ``build() -> (type, action, data, subject, links)``; it runs on the record thread
        (where the body store does its work), then the record is appended."""
        self.queue.put(build)

    def _run(self) -> None:
        while True:
            record = self.queue.get()
            if record is None:
                return
            try:
                if callable(record):
                    type_, action, data, subject, links = record()
                    record = new_record(type_, ACTOR, action, subject=subject, links=links, data=data)
                self.sink.append(record)
                self.written += 1
            except Exception as error:  # noqa: BLE001 - count it, say it once at the end
                self.failed += 1
                self.last_error = f"{type(error).__name__}: {error}"
                if self.log:
                    name = record.get("type", "?") if isinstance(record, dict) else "deferred record"
                    self.log(f"{name} not written: {self.last_error}")

    def close(self, timeout: float = 30.0) -> None:
        self.queue.put(None)
        self.thread.join(timeout)
        if self.failed:
            print(f"aqt-egress: {self.failed} record(s) could not be written ({self.last_error})", file=sys.stderr)
