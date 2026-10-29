"""Quarantine view: cases folded by aqt-quarantine, the evidence as inert text, and the two
human decisions (release, declare threat) through ``aqt_quarantine.decisions.Decider``.

A decision is signed over the content hash recorded when the case was opened. The stored
original is shown only when it still has that hash (``Decider.case_content``), it is checked
again right before a decision, and the hash shown is passed to the decision as
``expected_sha256``, so the person signs over the text they were shown.

A release or threat declaration also needs the whole of that text on screen first. The default
view shows only the passages around the detector evidence, and the full view shows the content in
pages of ``FULL_LIMIT`` characters. The browser session notes which pages of which content (case
id and hash) it was sent; release and declare are offered, and accepted, only once every page was
shown in that session (a default view that covers the whole text counts as all pages)."""

from __future__ import annotations

from typing import Callable

from . import NotFound, Stale, UsageProblem, require

FULL_LIMIT = 200_000      # characters per page of the full view
CHANGED = ("{error}. Only content with the hash recorded when the case was opened is shown and decided on, so "
           "nothing is shown and no decision can be made here.")
CONTEXT = 300             # characters around each evidence span in the default view
STATE_ORDER = {"held": 0, "warned": 1, "threat": 2, "released": 3}


def pages_of(length: int) -> int:
    """Number of full-view pages for content of ``length`` characters (at least one)."""
    return max(1, -(-length // FULL_LIMIT))


def segments(text: str, evidence: list[dict], *, full: bool, visible: Callable[[str], str], page: int = 0) -> dict:
    """The content split into plain and highlighted pieces: the evidence passages, or with
    ``full`` one page of ``FULL_LIMIT`` characters. ``complete`` says whether this view shows the
    whole text. Hidden characters are made visible by aqt-quarantine's own ``visible()``; the
    browser renders every piece as text."""
    length = len(text)
    pages = pages_of(length)
    page = min(max(0, int(page)), pages - 1)
    spans: list[list] = []
    for item in sorted(evidence, key=lambda e: (e.get("start", 0), e.get("end", 0))):
        start, end = max(0, int(item.get("start", 0))), min(length, int(item.get("end", 0)))
        if end <= start:
            continue
        reason = str(item.get("reason") or item.get("label") or "")
        if spans and start <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], end)
            if reason and reason not in spans[-1][2]:
                spans[-1][2] += "; " + reason
        else:
            spans.append([start, end, reason])
    if full:
        windows = [[page * FULL_LIMIT, min(length, (page + 1) * FULL_LIMIT)]]
    elif not spans:
        windows = [[0, min(length, 2 * CONTEXT)]]
    else:
        windows = []
        for start, end, _ in spans:
            a, b = max(0, start - CONTEXT), min(length, end + CONTEXT)
            if windows and a <= windows[-1][1]:
                windows[-1][1] = max(windows[-1][1], b)
            else:
                windows.append([a, b])
    parts = []
    for a, b in windows:
        pieces, cursor = [], a
        for start, end, reason in spans:
            if end <= a or start >= b:
                continue
            start, end = max(start, a), min(end, b)
            if start > cursor:
                pieces.append({"text": visible(text[cursor:start])})
            pieces.append({"text": visible(text[start:end]), "mark": reason})
            cursor = end
        if b > cursor:
            pieces.append({"text": visible(text[cursor:b])})
        parts.append({"from": a, "to": b, "pieces": pieces, "cut_before": a > 0, "cut_after": b < length})
    return {"chars": length, "full": full, "page": page if full else None, "pages": pages,
            "complete": windows == [[0, length]], "truncated": full and pages > 1, "windows": parts}


class QuarantineView:
    def __init__(self):
        require("aqt_quarantine", "aqt-quarantine")
        from aqt_quarantine.config import load_config
        self.config = load_config()

    def decider(self, *, passphrase: str | None = None, human_check: Callable | None = None):
        from aqt_quarantine.decisions import Decider
        from aqt_quarantine.store import Store
        store = Store(self.config.state_dir, sink=self.config.sink)

        def no_prompt(_prompt: str) -> str:
            if passphrase is None:
                raise ValueError("no passphrase given")
            return passphrase

        def never(*_args):  # reads never decide
            raise RuntimeError("read-only use of the decider")

        return Decider(self.config, store, passphrase=no_prompt, human_check=human_check or never)

    def signers(self, decider) -> list[dict]:
        ids = self.config.responsible or list(decider.registry)
        return [{"id": ident, "name": (decider.registry.get(ident) or {}).get("name", ""),
                 "role": (decider.registry.get(ident) or {}).get("role", "")} for ident in ids]

    @staticmethod
    def row(case) -> dict:
        data = case.data
        source = data.get("source") or {}
        return {"case_id": case.case_id, "state": case.state, "band": case.band,
                "score_ppm": data.get("score_ppm", 0), "domain": source.get("domain"), "ref": source.get("ref"),
                "tool": source.get("tool"), "session": case.session, "opened": case.opened.get("time"),
                "reason_code": data.get("reason_code"), "reached_model": case.reached_model,
                "refused": len(case.refused), "content_sha256": data.get("content_sha256")}

    def cases(self, state: str | None = None) -> dict:
        decider = self.decider()
        cases, sources = decider.fold()
        rows = [self.row(case) for case in cases.values()]
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        if state and state != "all":
            rows = [row for row in rows if row["state"] == state]
        rows.sort(key=lambda r: r["opened"] or "", reverse=True)       # newest first ...
        rows.sort(key=lambda r: STATE_ORDER.get(r["state"], 9))       # ... within held, warned, threat, released
        trusted = [{"domain": s.domain, "subdomains": s.subdomains, "expires": s.expires, "active": s.active(),
                    "record": s.record.get("id"), "by": (s.record.get("actor") or {}).get("id"),
                    "reason": s.record.get("reason")} for s in sources]
        return {"cases": rows, "counts": counts, "sources": trusted, "signers": self.signers(decider),
                "state_dir": str(self.config.state_dir), "outbox": decider.store.outbox_size(),
                "journal_problems": [str(p) for p in decider.store.journal_problems[:20]],
                "journal_problem_count": len(decider.store.journal_problems)}

    @staticmethod
    def original(decider, case) -> tuple[str | None, str | None]:
        """(text, None) when the stored original has the case's recorded hash, else (None, why)."""
        content = decider.case_content(case.case_id)
        if content.text is None:
            return None, CHANGED.format(error=content.error or "the stored original is not available")
        return content.text, None

    def case(self, case_id: str, *, full: bool = False, page: int = 0, shown: dict | None = None) -> dict:
        """One case. ``shown`` is the browser session's record of the content pages it was sent
        (``(case_id, content_sha256) -> set of pages``); this view's pages are added to it."""
        from aqt_quarantine.report import summary_lines, visible
        from aqt_quarantine.store import StoreError, normalise_case_id
        try:
            case_id = normalise_case_id(case_id)
        except StoreError as error:
            raise UsageProblem(str(error)) from error
        decider = self.decider()
        cases, _ = decider.fold()
        case = cases.get(case_id)
        if case is None:
            raise NotFound(f"no case {case_id}")
        text, text_error = self.original(decider, case)
        verified = text is not None           # decisions only over content the person can see
        data = case.data
        content = segments(text, data.get("evidence", []), full=full, visible=visible, page=page) \
            if verified else None
        unseen: list[int] = []
        if content is not None:
            seen = (shown if shown is not None else {}).setdefault((case_id, data.get("content_sha256")), set())
            seen.update(range(content["pages"]) if content["complete"] else [content["page"]] if full else [])
            unseen = [number for number in range(content["pages"]) if number not in seen]
        evidence = [{"start": e.get("start"), "end": e.get("end"), "label": e.get("label"),
                     "detector": e.get("detector"), "reason": e.get("reason"),
                     "excerpt": visible(str(e.get("excerpt", "")))} for e in data.get("evidence", [])]
        decisions = [{"id": d.record.get("id"), "time": d.record.get("time"), "action": d.record.get("action"),
                      "type": d.record.get("type"), "by": (d.record.get("actor") or {}).get("id"),
                      "display": (d.record.get("actor") or {}).get("display"), "status": d.status,
                      "honoured": d.honoured, "note": d.note, "reason": visible(str(d.record.get("reason", "")))}
                     for d in case.decisions]
        refused = [{"id": r.get("id"), "time": r.get("time"), "by": (r.get("actor") or {}).get("id"),
                    "attempted": (r.get("data") or {}).get("attempted_action"),
                    "reason_code": (r.get("data") or {}).get("reason_code"),
                    "markers": (r.get("data") or {}).get("agent_markers", []),
                    "detail": visible(str((r.get("data") or {}).get("detail", "")))} for r in case.refused]
        thresholds = data.get("thresholds") or {}
        return {
            **self.row(case),
            "summary": [visible(line) for line in summary_lines(case)],
            "detectors": [{"id": d.get("id"), "version": d.get("version"),
                           "score_ppm": (data.get("scores") or {}).get(d.get("id"))} for d in data.get("detectors", [])],
            "thresholds": {"version": thresholds.get("version"), "sha256": thresholds.get("sha256"),
                           "calibrated": bool(thresholds.get("calibrated"))},
            "chars": data.get("chars"), "evidence": evidence, "decisions": decisions, "refusals": refused,
            "delivered": len(case.delivered), "opened_record": case.opened.get("id"),
            "content": content, "content_error": text_error, "signers": self.signers(decider),
            "content_verified": verified, "unseen_pages": unseen,
            "needs_full_view": verified and bool(unseen) and case.state in ("held", "warned", "threat", "released"),
            "can_release": verified and not unseen and case.state in ("held", "warned", "threat"),
            "can_declare": verified and not unseen and case.state in ("held", "warned", "released"),
            "journal_problems": [str(p) for p in decider.store.journal_problems if p.case_id == case_id],
        }

    def decide(self, case_id: str, kind: str, *, reason: str, passphrase: str, shown_sha256: str,
               signer_id: str | None, human_check: Callable, overrule_threat: bool = False,
               shown: dict | None = None) -> dict:
        """Release or declare a threat. Refused as stale when the case content is not the one shown,
        or when not all of it was shown in this browser session (``shown``, as in ``case``)."""
        from aqt_evidence import HumanCheckError
        from aqt_quarantine.decisions import DecisionError
        from aqt_quarantine.store import StoreError, normalise_case_id
        try:
            case_id = normalise_case_id(case_id)
        except StoreError as error:
            raise UsageProblem(str(error)) from error
        decider = self.decider(passphrase=passphrase, human_check=human_check)
        cases, _ = decider.fold()
        case = cases.get(case_id)
        if case is None:
            raise NotFound(f"no case {case_id}")
        stale = None
        if not shown_sha256 or case.data.get("content_sha256") != shown_sha256:
            stale = "the case content is not the one shown; nothing was signed. Reload the case."
        else:
            text, changed = self.original(decider, case)
            stale = f"nothing was signed: {changed}" if changed else None
            if text is not None:
                seen = (shown or {}).get((case_id, shown_sha256), set())
                missing = [number + 1 for number in range(pages_of(len(text))) if number not in seen]
                if missing:
                    stale = (f"nothing was signed: the whole content of case {case_id} ({len(text):,} characters) "
                             "has not been shown in this browser session (page "
                             f"{', '.join(map(str, missing[:10]))}{' …' if len(missing) > 10 else ''} not shown). "
                             "Show the full content first.")
        if stale:
            try:
                human_check()
            except HumanCheckError:
                pass                      # refused first: aqt-quarantine records the refusal below
            else:
                raise Stale(stale)
        try:
            if kind == "release":
                outcome = decider.release(case_id, reason, signer_id=signer_id or None,
                                          overrule_threat=overrule_threat, expected_sha256=shown_sha256)
            elif kind == "threat":
                outcome = decider.declare_threat(case_id, reason, signer_id=signer_id or None,
                                                 expected_sha256=shown_sha256)
            else:
                raise UsageProblem(f"unknown decision {kind}")
        except DecisionError as error:
            raise (UsageProblem if error.exit_code == 2 else Stale)(str(error)) from error
        except StoreError as error:
            raise UsageProblem(str(error)) from error
        return _outcome(outcome)

    def trust(self, domain: str, *, reason: str, passphrase: str, signer_id: str | None, human_check: Callable,
              expires: str | None = None, subdomains: bool = False, revoke: bool = False,
              shown_record: str | None = None) -> dict:
        """Trust a source domain until a date (or revoke that trust), as ``aqt-quarantine trust-source``.
        Trust only lowers the band of later content from the domain; it releases no case."""
        from aqt_evidence import HumanCheckError
        from aqt_quarantine.decisions import DecisionError
        decider = self.decider(passphrase=passphrase, human_check=human_check)
        if revoke:
            wanted = (domain or "").strip().lower().rstrip(".")
            _, sources = decider.fold()
            current = next((s for s in sources if s.domain == wanted and s.active()), None)
            if current is None or not shown_record or current.record.get("id") != shown_record:
                try:
                    human_check()
                except HumanCheckError:
                    pass                  # refused first: aqt-quarantine records the refusal below
                else:
                    if current is None:
                        raise NotFound(f"{wanted} is not a trusted source")
                    raise Stale("the trust entry is not the one shown; nothing was signed. Reload the sources.")
        try:
            outcome = decider.trust_source(domain or "", reason, expires=expires or None, signer_id=signer_id or None,
                                           subdomains=bool(subdomains), revoke=revoke)
        except DecisionError as error:
            raise (UsageProblem if error.exit_code == 2 else Stale)(str(error)) from error
        return _outcome(outcome)


def _outcome(outcome) -> dict:
    record = outcome.record
    data = record.get("data") or {}
    return {"ok": outcome.ok, "message": outcome.message, "record_id": record.get("id"),
            "record_type": record.get("type"), "time": record.get("time"),
            "reason_code": data.get("reason_code"), "markers": data.get("agent_markers", [])}
