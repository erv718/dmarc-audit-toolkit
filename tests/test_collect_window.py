"""collect.pull_domain sizes a domain by the hour with one count query, then
pulls a busy domain in complete windows, newest first; every Timespan reaches
its slice's own start; a row budget stops at the older slices; a planned
slice that still hits the cap is halved; a single hour above the cap is kept
and noted; pull_maillog notes the time span the rows really cover. A
customized query with no projection line falls back to splitting on the cap
(see test_collect.py). No network."""

import csv
import re
import subprocess
import sys
from pathlib import Path

import collect

ROOT = Path(__file__).resolve().parent.parent
REAL = (ROOT / "queries" / "raw_maillog.kql").read_text(encoding="utf-8-sig")
BARE = ('let sender_domain = "example.com";\nlet window_start  = ago(30d);\n'
        'let window_end    = now();\nEmailEvents\n')  # no projection line: no sizing


def bounds(kql):
    start = int(re.search(r"window_start\s*=\s*ago\((\d+)h\)", kql).group(1))
    m = re.search(r"window_end\s*=\s*ago\((\d+)h\)", kql)
    return start, (int(m.group(1)) if m else 0)


class Tenant:
    """A fake hunting endpoint over per-hour row counts (hours ago -> rows). It
    answers the sizing query with the counts inside the window and a row
    query with that many rows, cut at collect.ROW_CAP like the real API."""

    def __init__(self, per_hour):
        self.per_hour, self.calls = per_hour, []

    def hunting(self, tok, kql, ts=None):
        start, end = bounds(kql)
        sizing = "summarize n = count()" in kql
        self.calls.append((start, end, ts, "count" if sizing else "rows"))
        hours = [h for h in range(end, start) if self.per_hour.get(h)]
        if sizing:
            return {"schema": [{"name": "hago"}, {"name": "n"}],
                    "results": [{"hago": h, "n": self.per_hour[h]} for h in hours]}
        rows = [{"Internet message ID": "%d-%d" % (h, i), "Timestamp": "2026-09-30T%02d:00:00Z" % (h % 24)}
                for h in hours for i in range(self.per_hour[h])]
        return {"schema": [{"name": "Internet message ID"}, {"name": "Timestamp"}],
                "results": rows[:collect.ROW_CAP]}


def small_caps(monkeypatch, cap=100, target=90):
    monkeypatch.setattr(collect, "ROW_CAP", cap)
    monkeypatch.setattr(collect, "SLICE_TARGET", target)


def test_the_sizing_query_keeps_the_row_query_filters():
    kql = collect.count_kql(REAL, "example.com", 720)
    assert kql.rstrip().endswith(collect.COUNT_TAIL)
    assert 'let sender_domain = "example.com";' in kql and "ago(720h)" in kql
    for keep in ("EmailDirection in (directions)", "isnotempty(InternetMessageId)", "SenderFromDomain =~"):
        assert keep in kql
    assert "['Internet message ID']" not in kql and "parse_json(AuthenticationDetails)" not in kql
    assert collect.count_kql(BARE, "example.com", 720) is None  # nothing to cut at: no sizing


def test_plan_slices_newest_first_and_never_above_target():
    counts = {0: 50, 1: 50, 2: 10, 5: 95, 6: 20, 9: 30}
    # hour 5 (95) is above the target and becomes a slice of its own
    assert collect.plan_slices(counts, 12, 0, 90) == [(1, 0), (5, 1), (6, 5), (12, 6)]
    assert collect.plan_slices({0: 10}, 720) == [(720, 0)]           # a quiet domain: one window
    assert collect.plan_slices({}, 720) == [(720, 0)]                # nothing counted: still one window
    # the last slice always reaches the window start, so drift between the calls is not dropped
    assert collect.plan_slices({0: 95}, 720, 0, 90) == [(1, 0), (720, 1)]
    # an over-target hour behind empty newer hours gets a call of its own
    assert collect.plan_slices({3: 150}, 720, 0, 90) == [(3, 0), (4, 3), (720, 4)]


def test_a_busy_domain_is_sized_then_pulled_in_complete_windows_newest_first(monkeypatch):
    small_caps(monkeypatch)
    t = Tenant({h: 40 for h in range(10)})  # 400 rows over ten hours: four times the cap
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    notes = []
    rows, cols, calls = collect.pull_domain("tok", REAL, "example.com", 720, 0, notes)
    assert len(rows) == 400 and calls == 5  # every row, and no download thrown away
    assert [k for *_, k in t.calls] == ["count"] + ["rows"] * 5
    assert [(s, e) for s, e, ts, k in t.calls if k == "rows"] == [(2, 0), (4, 2), (6, 4), (8, 6), (720, 8)]
    # every Timespan reaches back to its slice's own start (the API applies it from now)
    assert all(ts == "P%dD" % max(1, -(-s // 24)) for s, e, ts, k in t.calls)
    assert cols == ["Internet message ID", "Timestamp"]
    assert any("about 400 rows in the window (5 planned slices of up to 90 rows, newest first)" in n
               for n in notes)
    assert not any("cap" in n for n in notes)


def test_a_domain_with_no_rows_costs_only_the_sizing_call(monkeypatch):
    t = Tenant({})
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    rows, cols, calls = collect.pull_domain("tok", REAL, "quiet.example", 720, 0, [])
    assert rows == [] and calls == 0 and [k for *_, k in t.calls] == ["count"]


def test_the_row_budget_stops_at_the_older_slices(monkeypatch):
    small_caps(monkeypatch)
    t = Tenant({h: 40 for h in range(48)})
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    notes = []
    rows, cols, calls = collect.pull_domain("tok", REAL, "example.com", 720, 0, notes, {"rows": 200})
    assert len(rows) == 240 and calls == 3  # checked before each call: overshoots by one slice at most
    assert [(s, e) for s, e, ts, k in t.calls if k == "rows"] == [(2, 0), (4, 2), (6, 4)]
    budget_notes = [n for n in notes if "row budget reached" in n]
    assert len(budget_notes) == 1
    assert "example.com row budget reached at 8h..6h ago" in budget_notes[0]
    assert "cover only the last 6h" in budget_notes[0]


def test_a_planned_slice_that_still_hits_the_cap_is_halved(monkeypatch):
    small_caps(monkeypatch)

    class Drifting(Tenant):  # the sizing undercounts hour 0: mail landed between the calls
        def hunting(self, tok, kql, ts=None):
            res = super().hunting(tok, kql, ts)
            if "summarize n = count()" in kql:
                for r in res["results"]:
                    if r["hago"] == 0:
                        r["n"] = 30
            return res
    t = Drifting({0: 60, 1: 30, 2: 30})  # 120 real rows, sized as 90: one planned slice comes back capped
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    notes = []
    rows, cols, calls = collect.pull_domain("tok", REAL, "example.com", 720, 0, notes)
    assert len({r["Internet message ID"] for r in rows}) == 120  # every row despite the drift
    assert any("hit the 100,000-row API cap" in n for n in notes)


def test_a_single_hour_above_the_cap_is_kept_and_noted_as_truncated(monkeypatch):
    small_caps(monkeypatch)
    t = Tenant({0: 150})
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    notes = []
    rows, cols, calls = collect.pull_domain("tok", REAL, "example.com", 720, 0, notes)
    assert len(rows) == 100
    assert any("more than 100,000 rows within one hour (1h..0h ago) - that hour is truncated" in n for n in notes)


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


def test_max_rows_and_rua_max_are_cli_flags():
    p = subprocess.run([sys.executable, str(ROOT / "src" / "collect.py"), "--help"],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0
    assert "--max-rows" in p.stdout and "250000" in p.stdout
    assert "--rua-max" in p.stdout and "10000" in p.stdout


def test_pull_maillog_reports_each_orgs_internal_mail_from_the_sizing_call(monkeypatch, tmp_path):
    def hunting(tok, kql, ts=None):
        if "summarize n = count()" in kql:
            dom = re.search(r'let sender_domain = "([^"]+)"', kql).group(1)
            rows = {"busy.example": [(0, "Intra-org", 30), (0, "Inbound", 5), (1, "Intra-org", 20)],
                    "brand.example": [(0, "Inbound", 70)],
                    "quiet.example": []}[dom]
            return {"schema": [{"name": "hago"}, {"name": "dir"}, {"name": "n"}],
                    "results": [{"hago": h, "dir": d, "n": n} for h, d, n in rows]}
        return {"schema": [{"name": "Internet message ID"}], "results": [{"Internet message ID": "x"}]}
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)
    volumes = {}
    collect.pull_maillog("tok", ["busy.example", "brand.example", "quiet.example"], tmp_path / "m.csv",
                         30, 0, volumes)
    # inbound mail claiming a domain (where spoofing lives) does not count; an empty domain counts as zero
    assert volumes == {"busy.example": 50, "brand.example": 0, "quiet.example": 0}


def test_the_summary_note_says_when_the_budget_kept_only_the_newest_part(monkeypatch, tmp_path):
    small_caps(monkeypatch)
    per_hour = {h: 40 for h in range(48)}
    t = Tenant(per_hour)
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    path, notes = collect.pull_maillog("tok", ["example.com"], tmp_path / "m.csv", 30, 200)
    planned = len(collect.plan_slices(per_hour, 720, 0, 90))
    summary = [n for n in notes if n.startswith("mail log: 240 rows for example.com")]
    assert summary, notes
    assert ("the newest part of about 1920 rows in the last 30 days (3 of %d planned slices, row budget 200)"
            % planned) in summary[0]


def test_a_failed_row_pull_keeps_the_measured_volume(monkeypatch, tmp_path):
    def hunting(tok, kql, ts=None):
        if "summarize n = count()" in kql:
            return {"schema": [{"name": "hago"}, {"name": "dir"}, {"name": "n"}],
                    "results": [{"hago": 0, "dir": "Intra-org", "n": 40}]}
        raise collect.graph_client.GraphError("HTTP 400 on hunting: the service rejected the query")
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)
    volumes = {}
    path, notes = collect.pull_maillog("tok", ["busy.example"], tmp_path / "m.csv", 30, 0, volumes)
    assert volumes == {"busy.example": 40} and path is None
    assert any("mail log for busy.example not pulled" in n for n in notes)


def test_a_template_with_a_filter_after_the_projection_is_not_sized():
    assert collect.count_kql(REAL.rstrip() + '\n| where Subject != ""\n', "example.com", 720) is None


def test_a_template_without_the_sender_domain_line_is_noted_not_a_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(collect, "QUERY", tmp_path / "custom.kql")
    (tmp_path / "custom.kql").write_text("EmailEvents | take 10\n", encoding="utf-8")
    monkeypatch.setattr(collect.graph_client, "hunting", lambda *a, **k: {"results": [], "schema": []})
    volumes = {}
    path, notes = collect.pull_maillog("tok", ["example.com"], tmp_path / "m.csv", 30, 0, volumes)
    assert path is None and volumes == {}
    assert any("mail log for example.com not pulled" in n and "placeholder" in n for n in notes)


def test_a_dynamic_column_in_a_customized_projection_does_not_crash_the_merge(monkeypatch, tmp_path):
    def hunting(tok, kql, ts=None):
        if "summarize n = count()" in kql:
            return {"schema": [{"name": "hago"}, {"name": "n"}], "results": [{"hago": 0, "n": 2}]}
        row = {"Internet message ID": "a", "Timestamp": "2026-09-30T00:00:00Z", "Tags": ["x", {"k": 1}]}
        return {"schema": [{"name": k} for k in row], "results": [dict(row), dict(row)]}  # a repeated leg
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)
    path, notes = collect.pull_maillog("tok", ["example.com"], tmp_path / "m.csv", 30, 0)
    assert path is not None
    with open(path, encoding="utf-8", newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 1  # the repeated leg was dropped, the list value kept


def test_the_summary_note_is_honest_when_the_budget_cuts_an_unsized_pull(monkeypatch, tmp_path):
    small_caps(monkeypatch)
    monkeypatch.setattr(collect, "QUERY", tmp_path / "bare.kql")
    (tmp_path / "bare.kql").write_text(BARE, encoding="utf-8")
    tenant = Tenant({0: 60, 1: 60, 2: 60})
    monkeypatch.setattr(collect.graph_client, "hunting", tenant.hunting)
    path, notes = collect.pull_maillog("tok", ["example.com"], tmp_path / "m.csv", 30, 100)
    assert any("row budget reached" in n for n in notes)
    summary = [n for n in notes if n.startswith("mail log: 120 rows for example.com")]
    assert summary and "the newest part of the last 30 days (2 window slices, row budget 100)" in summary[0]
    assert not any("(last 30 days)" in n for n in notes)  # no note claims the whole window


def test_the_headline_note_reports_what_the_gate_chose():
    orgs = ["aaa.example", "corp.example"]
    gate = {"headline_domain": "corp.example", "headline_source": "most internal mail"}
    assert collect.headline_note(gate, orgs, {"aaa.example": 0, "corp.example": 120}) == (
        "headline signal: internal mail per org domain - corp.example 120, aaa.example 0; "
        "the headline is corp.example (most internal mail)")
    gate = {"headline_domain": "aaa.example", "headline_source": "first on the command line"}
    assert collect.headline_note(gate, orgs, {"aaa.example": 0, "corp.example": 0}) == (
        "headline signal: no internal mail in any org domain this run - "
        "the headline is aaa.example (first on the command line)")
    assert collect.headline_note(gate, orgs, {"aaa.example": 7}) == (
        "headline signal: internal-mail volume missing for corp.example - "
        "the headline is aaa.example (first on the command line)")


def test_truncation_text_comes_from_the_slicers_own_notes():
    notes = ["mail log: example.com has about 5168817 rows in the window (62 planned slices of up to 90000 rows, newest first)",
             "mail log: example.com row budget reached at 47h..41h ago - older rows skipped; the rows cover only the last 41h "
             "(raise --max-rows to keep more)",
             "mail log: corp.example has more than 100,000 rows within one hour (3h..2h ago) - that hour is truncated",
             "mail log: 30 rows for other.example (last 30 days)"]
    assert collect.truncation_text(notes) == ("row budget kept only the newest 41h for example.com; "
                                              "an hour of corp.example (3h..2h ago) is truncated at the API cap")
    assert collect.truncation_text(["mail log: 30 rows for other.example (last 30 days)"]) is None
