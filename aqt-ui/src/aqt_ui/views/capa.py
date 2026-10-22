"""CAPA view (aqt-capa), read-only: candidates, deviations with their timeline, effectiveness.

``effectiveness(record=False)`` writes no evidence; it runs aqt-capa's scan first, which
refreshes its SQLite working index (not evidence), exactly as the CLI's read commands do.
"""

from __future__ import annotations

from . import NotFound, require


class CapaView:
    def __init__(self):
        require("aqt_capa", "aqt-capa")
        from aqt_capa import Capa, load_config
        self.capa = Capa(load_config())

    def summary(self) -> dict:
        capa = self.capa
        try:
            effectiveness = capa.effectiveness(record=False)
        except Exception as error:  # noqa: BLE001 - shown as a message in the view
            effectiveness, error_text = [], f"{type(error).__name__}: {error}"
        else:
            error_text = None
        deviations = capa.list()
        deviations.sort(key=lambda d: (d.get("state") == "closed", not d.get("overdue"), d.get("num") or 0))
        effectiveness.sort(key=lambda e: {"not-effective": 0, "pending": 1}.get(e.get("result"), 2))
        return {"candidates": capa.candidates(), "deviations": deviations,
                "effectiveness": [{k: e.get(k) for k in ("action_id", "dev_id", "result", "reasons", "counts",
                                                         "window", "approval")} for e in effectiveness],
                "effectiveness_error": error_text,
                "counts": {"candidates": len(capa.candidates()),
                           "overdue": sum(1 for d in deviations if d.get("overdue")),
                           "open": sum(1 for d in deviations if d.get("state") != "closed"),
                           "not_effective": sum(1 for e in effectiveness if e.get("result") == "not-effective")}}

    def counts(self) -> dict:
        """Cheap counts for the home queue (no scan)."""
        deviations = self.capa.list()
        return {"candidates": len(self.capa.candidates()), "overdue": sum(1 for d in deviations if d.get("overdue")),
                "open": sum(1 for d in deviations if d.get("state") != "closed")}

    def deviation(self, dev_id: str) -> dict:
        from aqt_capa import CapaError
        try:
            return self.capa.show(dev_id)
        except CapaError as error:
            raise NotFound(str(error)) from error

    def trends(self) -> str:
        from aqt_capa import render_markdown, trends
        return render_markdown(trends(self.capa))
