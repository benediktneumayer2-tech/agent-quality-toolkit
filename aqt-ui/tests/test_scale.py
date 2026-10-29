"""Large trails: the Trail view pages on the server and the Overview stays fast with 50,000
records; cached results are rebuilt when the trail grows. The time budgets are loose on purpose
(slow CI machines); they catch a return to "read and filter everything on every request"."""

import json
import time

import pytest

RECORDS = 50_000
TYPES = ("change.receipt", "quarantine.passed", "signoff.signature", "trail.event", "trail.anchor")


def synthetic(seq: int, kind: str | None = None) -> dict:
    kind = kind or TYPES[seq % len(TYPES)]
    return {"id": f"rec_{seq:026d}", "time": f"2026-10-{1 + seq % 20:02d}T10:{seq % 60:02d}:00Z", "type": kind,
            "action": "run", "actor": {"id": f"agent:test:worker-{seq % 7}", "kind": "agent",
                                       "agent": {"session": f"s{seq % 13}"}},
            "subject": {"kind": "record", "ref": f"ref-{seq % 101}"}, "chain": {"seq": seq, "prev": "sha256:" + "0" * 64},
            "reason": "synthetic record for the scale test", "data": {"n": seq, "text": "x" * 200}}


@pytest.fixture
def big_trail(env):
    from aqt_trail.config import load_config
    path = load_config().trail_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as handle:
        for seq in range(RECORDS):
            handle.write(json.dumps(synthetic(seq)) + "\n")
    return path


def timed(client, path):
    started = time.monotonic()
    status, data, _ = client.get(path)
    assert status == 200, (path, data)
    return data, time.monotonic() - started


def test_trail_and_overview_stay_fast_with_50000_records(big_trail, ui_factory):
    client = ui_factory()
    client.login()
    _, cold = timed(client, "/api/overview")                 # first request parses the trail once
    overview, warm = timed(client, "/api/overview")
    assert overview["status"]["records"] == RECORDS
    newest, first_page = timed(client, "/api/trail/records")
    assert newest["total"] == RECORDS and len(newest["rows"]) == 100 and newest["more"]
    assert newest["rows"][0]["chain"]["seq"] == RECORDS - 1
    oldest, last_page = timed(client, f"/api/trail/records?offset={RECORDS - 50}&limit=100")
    assert [r["chain"]["seq"] for r in oldest["rows"]] == list(range(49, -1, -1)) and not oldest["more"]
    _, filtered_first = timed(client, "/api/trail/records?type=signoff.signature")
    page2, filtered_next = timed(client, "/api/trail/records?type=signoff.signature&offset=100")
    assert page2["total"] == RECORDS // len(TYPES) and page2["rows"][0]["type"] == "signoff.signature"
    _, lookup = timed(client, f"/api/trail/record/rec_{1234:026d}")
    timings = {"overview cold": cold, "overview warm": warm, "newest page": first_page, "oldest page": last_page,
               "filter": filtered_first, "filter next page": filtered_next, "record": lookup}
    print("\n" + ", ".join(f"{name} {seconds * 1000:.0f} ms" for name, seconds in timings.items()))
    assert cold < 30
    assert max(warm, first_page, last_page, filtered_next, lookup) < 2.0, timings
    assert filtered_first < 5.0, timings

    # the trail grows: totals, pages and the cached selection follow
    with open(big_trail, "a") as handle:
        for seq in range(RECORDS, RECORDS + 3):
            handle.write(json.dumps(synthetic(seq, "signoff.signature")) + "\n")
    grown, _ = timed(client, "/api/trail/records?type=signoff.signature")
    assert grown["total"] == RECORDS // len(TYPES) + 3 and grown["rows"][0]["chain"]["seq"] == RECORDS + 2
    status, _ = timed(client, "/api/trail/status")
    assert status["status"]["records"] == RECORDS + 3


def test_paging_and_cursor_on_a_small_trail(env, tmp_path):
    from aqt_ui.views.trail import TrailIndex, TrailView
    view = TrailView()
    view.index = TrailIndex(tmp_path / "trail.jsonl")
    with open(view.index.path, "w") as handle:
        for seq in range(25):
            handle.write(json.dumps(synthetic(seq)) + "\n")
    page = view.records(limit=10)
    assert [r["chain"]["seq"] for r in page["rows"]] == list(range(24, 14, -1)) and page["more"]
    page = view.records(limit=10, offset=20)
    assert [r["chain"]["seq"] for r in page["rows"]] == [4, 3, 2, 1, 0] and not page["more"]
    assert [r["chain"]["seq"] for r in view.records(limit=3, before=10)["rows"]] == [9, 8, 7]
    assert view.records(type="trail.anchor")["total"] == 5
    assert view.index.last_anchor is None     # an anchor the writer did not write (no RFC 3161 token) never counts
    assert view.record(f"rec_{7:026d}")["record"]["chain"]["seq"] == 7 and view.record("7")["record"]["id"]
