"""collect.pull_domain: the Timespan reaches the slice's own start, the newer
half of a split comes first, the per-domain row budget stops the walk at the
older slices, and pull_maillog notes the time span the rows really cover.
No network."""

import csv
import re
import subprocess
import sys
from pathlib import Path

import collect

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ('let sender_domain = "example.com";\nlet window_start  = ago(30d);\n'
            'let window_end    = now();\nEmailEvents\n')


def bounds(kql):
    start = int(re.search(r"window_start\s*=\s*ago\((\d+)d\)", kql).group(1))
    m = re.search(r"window_end\s*=\s*ago\((\d+)d\)", kql)
    return start, (int(m.group(1)) if m else 0)


def rows_for(start, end, n):
    return {"results": [{"Internet message ID": "%d-%d-%d" % (start, end, i),
                         "Timestamp": "2026-09-%02dT00:00:00Z" % (30 - start)} for i in range(n)],
            "schema": [{"name": "Internet message ID"}, {"name": "Timestamp"}]}


def test_timespan_reaches_the_slice_start_not_its_length(monkeypatch):
    seen = []

    def fake_hunting(tok, kql, ts=None):
        start, end = bounds(kql)
        seen.append((start, end, ts))
        return rows_for(start, end, collect.ROW_CAP if start - end > 10 else 1)
    monkeypatch.setattr(collect.graph_client, "hunting", fake_hunting)
    rows, cols, calls = collect.pull_domain("tok", TEMPLATE, "example.com", 30, 0, [])
    assert calls == 4 and len(rows) == 4
    assert all(ts == "P%dD" % start for start, end, ts in seen)
    # a slice that does not end today still reaches back to its own start
    assert (30, 15, "P30D") in seen and (22, 15, "P22D") in seen and (15, 7, "P15D") in seen


def test_newer_half_first_and_the_budget_stops_at_the_older_slices(monkeypatch):
    monkeypatch.setattr(collect, "ROW_CAP", 10)  # every slice comes back capped, like the apex
    order = []

    def fake_hunting(tok, kql, ts=None):
        start, end = bounds(kql)
        order.append((start, end))
        return rows_for(start, end, 10)
    monkeypatch.setattr(collect.graph_client, "hunting", fake_hunting)
    notes = []
    rows, cols, calls = collect.pull_domain("tok", TEMPLATE, "example.com", 4, 0, notes, {"rows": 25})
    assert order == [(4, 0), (2, 0), (1, 0), (2, 1), (4, 2), (3, 2)]  # newest day first, oldest never asked for
    assert calls == 3 and len(rows) == 30  # the budget is checked before a call, so it overshoots by one slice at most
    assert cols == ["Internet message ID", "Timestamp"]
    assert not [r for r in rows if r["Internet message ID"].startswith("4-3-")]
    budget_notes = [n for n in notes if "row budget reached" in n]
    assert len(budget_notes) == 1 and "example.com row budget reached at 4d..3d ago" in budget_notes[0]
    assert sum(1 for n in notes if "STILL at the 100,000-row cap" in n) == 3
    # no budget: every day is pulled
    order.clear()
    rows, cols, calls = collect.pull_domain("tok", TEMPLATE, "example.com", 4, 0, [], None)
    assert calls == 4 and len(rows) == 40 and (4, 3) in order


def test_pull_maillog_notes_the_time_span_the_rows_cover(monkeypatch, tmp_path):
    def fake_hunting(tok, kql, ts=None):
        return {"results": [{"Internet message ID": "a", "Timestamp": "2026-09-02T12:00:00Z"},
                            {"Internet message ID": "b", "Timestamp": "2026-09-01T00:00:00Z"}],
                "schema": [{"name": "Internet message ID"}, {"name": "Timestamp"}]}
    monkeypatch.setattr(collect.graph_client, "hunting", fake_hunting)
    path, notes = collect.pull_maillog("tok", ["example.com"], tmp_path / "maillog.csv", 30, 100)
    assert any(n == "mail log: 2 rows for example.com (last 30 days); rows span 2026-09-01T00:00:00Z to 2026-09-02T12:00:00Z"
               for n in notes), notes
    with open(path, newline="", encoding="utf-8") as fh:
        assert len(list(csv.DictReader(fh))) == 2


def test_max_rows_is_a_cli_flag():
    p = subprocess.run([sys.executable, str(ROOT / "src" / "collect.py"), "--help"],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "--max-rows" in p.stdout and "250000" in p.stdout
