"""Round 10, comparability: whether two runs' mail-log counts compare is
decided from the cuts collect.py recorded (its row budget, or an hour at the
API cap, cut an organization's pull), never guessed from a domain's span or
row count. collect.py records them and names its run in report.json; the
delta, the Slack trend and the document's trend decide from them; domains.txt
leads with the headline. Synthetic data, offline, no network."""

import csv
import json
import re
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import audit
import collect
import discover
import next_steps
import notify

ROOT = Path(__file__).resolve().parent.parent
COLS = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
        "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC"]
END = datetime(2026, 10, 7, 12, 0, 0)
CUT = {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T19:00:00Z"}
CUT_NOTE = ("the row budget cut corp.example's mail log in %s (newest 41 hours kept): failure counts for its "
            "domains, and the whole log's, are not compared")


def rows_for(domain, n, hours_back, fail=0, tag=0, end=END):
    """n one-leg messages from domain, spread evenly over the newest hours_back
    hours before end; the first `fail` failed DMARC with no passing copy."""
    out = []
    for i in range(n):
        t = end - timedelta(hours=hours_back * i / max(1, n - 1)) if n > 1 else end - timedelta(hours=hours_back / 2)
        ok = i >= fail
        out.append([t.strftime("%Y-%m-%dT%H:%M:%SZ"), "<m%d.%d@%s>" % (tag, i, domain), "app@" + domain, domain, domain,
                    "user@example.com", "Notice %d" % i, "Delivered" if ok else "Blocked",
                    "Inbox/folder" if ok else "Quarantine", "pass" if ok else "fail"])
    return out


def build(tmp_path, name, rows, domains, **kw):
    """report.json for one run over these rows, as the next run reads it back."""
    path = tmp_path / (name + ".csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLS)
        writer.writerows(rows)
    rep = audit.build_report(domains=domains, maillog=str(path), offline=True, auth_column="DMARC", **kw)
    return json.loads(json.dumps(rep))


def delta_report(gf, hours, by_domain, cuts=None, gen="2026-10-07T15:00:00Z", **extra):
    """A report reduced to what build_delta reads."""
    doc = {"generated_utc": gen, "gate": {"domains": {}}, "findings": [],
           "maillog": {"counters": {"genuine_failures": gf, "delivered_despite_fail": 0}, "window": {"hours": hours},
                       "by_domain": {d: {"genuine_failures": n, "delivered_despite_fail": 0, "window": {"hours": h}}
                                     for d, (n, h) in by_domain.items()}}}
    if cuts is not None:
        doc["maillog"]["cuts"] = cuts
    doc.update(extra)
    return doc


def trend_line(text):
    return next(l for l in text.splitlines() if l.startswith("- trend over"))


def ns_report(gf, window, delta=None, rua=None, cuts=None):
    """A report reduced to what next_steps' trend reads."""
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["corp.example"]}, "gate": {"domains": {}},
           "maillog": {"counters": {"genuine_failures": gf, "raw_failing_rows": gf, "raw_rows": 900, "logical_messages": 800,
                                    "delivered_despite_fail": 0, "by_likely": {}}, "auth_column": "DMARC", "window": window}}
    if delta is not None:
        rep["delta"] = delta
    if rua is not None:
        rep["rua"] = {"totals": rua}
    if cuts is not None:
        rep["maillog"]["cuts"] = cuts
    return rep


def stand_trend(doc):
    return next(l for l in doc["stand"]["lines"] if l.startswith("**Trend"))


# ------------------------------------------------------------------ the delta (audit.build_delta)

def test_c1_every_name_under_a_cut_org_is_withheld_quiet_or_empty_in_both_directions(tmp_path):
    doms = ["corp.example", "hr.corp.example", "pay.corp.example", "shop.example"]
    whole = (rows_for("corp.example", 6000, 719, 0, 1) + rows_for("hr.corp.example", 40, 700, 20, 2)
             + rows_for("pay.corp.example", 30, 700, 20, 3) + rows_for("shop.example", 300, 719, 10, 4))
    cut = (rows_for("corp.example", 2000, 41, 0, 1) + rows_for("hr.corp.example", 4, 40, 2, 2)
           + rows_for("shop.example", 300, 719, 10, 4))  # pay.corp.example has no row inside the kept hours
    prev = build(tmp_path, "prev", whole, doms, maillog_cuts={})
    now = build(tmp_path, "now", cut, doms, previous_report=prev, maillog_cuts={"corp.example": CUT})
    dl = now["delta"]
    withheld = ["corp.example", "hr.corp.example", "pay.corp.example"]
    assert dl["maillog_window"]["domains_not_comparable"] == withheld and set(dl["by_domain"]) == {"shop.example"}
    assert dl["genuine_failures"] is None and dl["maillog_window"]["comparable"] is False
    assert CUT_NOTE % "this run" in dl["notes"]
    assert prev["maillog"]["cuts"] == {} and now["maillog"]["cuts"] == {"corp.example": CUT}
    hr = next(l for l in notify.summarize(now, prev).splitlines() if "`hr.corp.example`" in l)
    assert "2 genuine failures of its own" in hr and "vs last run" not in hr
    per_domain = next(l for l in audit.render_md(now).splitlines() if l.startswith("- per domain:"))
    assert per_domain == "- per domain: shop.example +0 genuine, +0 delivered despite fail"
    # the next whole run against the cut one: the previous report carries the cut
    nxt = build(tmp_path, "next", whole, doms, previous_report=now, maillog_cuts={})
    assert nxt["delta"]["maillog_window"]["domains_not_comparable"] == withheld
    assert set(nxt["delta"]["by_domain"]) == {"shop.example"} and CUT_NOTE % "the previous run" in nxt["delta"]["notes"]
    # a previous report written before cuts were recorded says the same in maillog.truncation
    del now["maillog"]["cuts"]
    now["maillog"]["truncation"] = "row budget kept only the newest 41h for corp.example"
    old = audit.build_delta(nxt, now)
    assert old["maillog_window"]["domains_not_comparable"] == withheld and set(old["by_domain"]) == {"shop.example"}


def test_d2_an_audited_subdomain_holding_a_few_percent_of_the_log_is_cut_with_its_org(tmp_path):
    """a.example.com: 1200 rows, 6% of the log, cut at the same hour as its busy apex."""
    doms = ["example.com", "a.example.com", "other.example"]
    prev = build(tmp_path, "prev", rows_for("example.com", 6000, 720, 0, 1) + rows_for("a.example.com", 1200, 720, 40, 2)
                 + rows_for("other.example", 15000, 720, 5, 3), doms, maillog_cuts={})
    now = build(tmp_path, "now", rows_for("example.com", 3000, 41, 0, 1) + rows_for("a.example.com", 1200, 41, 5, 2)
                + rows_for("other.example", 15000, 720, 5, 3), doms, previous_report=prev,
                maillog_cuts={"example.com": dict(CUT)})
    dl = now["delta"]
    assert dl["maillog_window"]["domains_not_comparable"] == ["a.example.com", "example.com"]
    assert "a.example.com" not in dl["by_domain"] and dl["by_domain"]["other.example"]["genuine_failures"] == 0
    assert "(-35 vs last run)" not in notify.summarize(now, prev)


def test_c2_a_recorded_cut_withholds_the_whole_logs_counts_whatever_rows_the_audited_names_hold(tmp_path):
    # shape 1: the cut org's busy rows belong to an unaudited subdomain, the apex holds a few of its own
    doms = ["corp.example", "shop.example"]
    prev = build(tmp_path, "prev", rows_for("corp.example", 600, 719, 30, 1) + rows_for("mail.corp.example", 6000, 719, 300, 2)
                 + rows_for("shop.example", 300, 719, 10, 3), doms, maillog_cuts={})
    now = build(tmp_path, "now", rows_for("corp.example", 35, 41, 2, 1) + rows_for("mail.corp.example", 2000, 41, 100, 2)
                + rows_for("shop.example", 300, 719, 10, 3), doms, previous_report=prev, maillog_cuts={"corp.example": CUT})
    assert now["delta"]["genuine_failures"] is None and now["delta"]["delivered_despite_fail"] is None
    assert "genuine failures vs last run" not in notify.summarize(now, prev)
    # shape 2: the org's mail spread over many audited subdomains, each a small share of the log
    subs = {"d%d.corp.example" % i: (15, 41.0) for i in range(12)}
    now_d = delta_report(195, 719.0, dict(subs, **{"shop.example": (10, 719.0)}), {"corp.example": CUT})
    prev_d = delta_report(739, 719.0, dict({d: (60, 719.0) for d in subs}, **{"shop.example": (10, 719.0)}), {})
    dl = audit.build_delta(now_d, prev_d)
    assert dl["genuine_failures"] is None and dl["maillog_window"]["domains_not_comparable"] == sorted(subs)
    # shape 3: eleven orgs, each cut by its own budget, each under a tenth of the log
    orgs = {"b%d.invalid" % i: (15, 41.0) for i in range(1, 12)}
    dl = audit.build_delta(delta_report(175, 719.0, dict(orgs, **{"shop.example": (10, 719.0)}), {o: CUT for o in orgs}),
                           delta_report(670, 719.0, dict({o: (60, 719.0) for o in orgs}, **{"shop.example": (10, 719.0)}), {}))
    assert dl["genuine_failures"] is None and dl["maillog_window"]["domains_not_comparable"] == sorted(orgs)
    assert dl["by_domain"] == {"shop.example": {"genuine_failures": 0, "delivered_despite_fail": 0}}
    L = []
    audit._md_delta(L, dl)
    assert "n/a (mail log cut for b1.invalid, b10.invalid, b11.invalid and 8 more, see the notes below)" in "\n".join(L)


def test_d9_a_busy_domains_ordinary_span_change_is_no_cut(tmp_path):
    """Last run: shop.example's monthly 3-hour burst plus one stray message 19
    days later; this run: the same burst. Both logs span 30 days and no budget
    was reached: the counts compare like any other week's."""
    doms = ["shop.example", "corp.example"]
    stray_end = END - timedelta(hours=100)
    prev = build(tmp_path, "prev", rows_for("shop.example", 5000, 3, 35, 1, end=END - timedelta(hours=560))
                 + rows_for("shop.example", 1, 0, 0, 9, end=stray_end) + rows_for("corp.example", 3000, 720, 10, 2), doms)
    now = build(tmp_path, "now", rows_for("shop.example", 5000, 3, 35, 1) + rows_for("corp.example", 3000, 720, 12, 2),
                doms, previous_report=prev)
    dl = now["delta"]
    assert now["maillog"]["by_domain"]["shop.example"]["window"]["hours"] == 3.0
    assert dl["genuine_failures"] == 2 and dl["maillog_window"]["comparable"] is True
    assert dl["maillog_window"]["domains_not_comparable"] == [] and dl["by_domain"]["shop.example"]["genuine_failures"] == 0
    assert not any("shop.example" in n for n in dl["notes"])
    trend = next_steps.apply_comparability(next_steps.trend_from_delta(dl, 47, None), dl, now, next_steps.maillog_view(now))
    assert trend["previous_genuine_failures"] == 45 and trend["not_comparable"] == []


def test_c7_d1_a_short_whole_log_withholds_every_domains_delta(tmp_path):
    doms = ["corp.example"]
    prev = build(tmp_path, "prev", rows_for("corp.example", 400, 696, 30, 1), doms)
    now = build(tmp_path, "now", rows_for("corp.example", 300, 41, 20, 1), doms, previous_report=prev)
    dl = now["delta"]
    assert dl["by_domain"] == {} and dl["maillog_window"]["domains_not_comparable"] == ["corp.example"]
    assert dl["maillog_window"]["log_comparable"] is False and dl["maillog_window"]["cut_orgs"] == {}
    line = next(l for l in notify.summarize(now, prev).splitlines() if "`corp.example`" in l)
    assert "20 genuine failures of its own" in line and "vs last run" not in line
    md = audit.render_md(now)
    assert "- per domain:" not in md and "n/a (mail-log spans not comparable, see the note below)" in md
    # D1: a one-domain log covering 2 days now and 30 days last run
    prev = build(tmp_path, "prev2", rows_for("corp.example", 900, 719, 20, 1), doms)
    now = build(tmp_path, "now2", rows_for("corp.example", 60, 48, 3, 1), doms, previous_report=prev)
    assert now["delta"]["by_domain"] == {} and "(-17 vs last run)" not in notify.summarize(now, prev)
    assert "per domain: corp.example -17" not in audit.render_md(now)


def test_c19_a_cut_on_the_longer_side_is_still_a_cut_and_its_mirror_too():
    cut_prev = delta_report(905, 719.0, {"corp.example": (900, 41.0), "shop.example": (5, 719.0)}, gen="2026-09-30T12:00:00Z")
    cut_prev["maillog"]["truncation"] = "row budget kept only the newest 41h for corp.example"  # an older report
    quiet_now = delta_report(7, 719.0, {"corp.example": (2, 10.0), "shop.example": (5, 719.0)}, {})
    for now, prev in ((quiet_now, cut_prev), (dict(cut_prev, generated_utc="2026-10-07T12:00:00Z"), quiet_now)):
        dl = audit.build_delta(now, prev)
        assert dl["genuine_failures"] is None and dl["maillog_window"]["domains_not_comparable"] == ["corp.example"]
        assert "corp.example" not in dl["by_domain"] and dl["by_domain"]["shop.example"]["genuine_failures"] == 0


def test_c20_the_cut_note_names_the_run_and_the_hours_kept_never_a_share():
    now = delta_report(600, 719.0, {"corp.example": (600, 719.0)}, {})
    prev = delta_report(2450, 719.0, {"corp.example": (2450, 41.0)}, {"corp.example": CUT})
    notes = audit.build_delta(now, prev)["notes"]
    assert notes == [CUT_NOTE % "the previous run", "sender census missing on one side (older report, or no mail log): "
                                                    "new_senders not computed"]
    both = audit.build_delta(delta_report(600, 719.0, {"corp.example": (600, 58.0)},
                                          {"corp.example": dict(CUT, kept_hours=58)}), prev)["notes"][0]
    assert both.startswith("the row budget cut corp.example's mail log in both runs (newest 58 hours kept now; "
                           "newest 41 hours kept in the previous run)")
    cap = {"corp.example": {"reason": "api cap", "api_cap_hours": ["3h..2h"]}}
    assert audit.build_delta(delta_report(600, 719.0, {"corp.example": (600, 719.0)}, cap), now)["notes"][0] == (
        "the API row cap cut corp.example's mail log in this run (an hour truncated, 3h..2h ago): failure counts for "
        "its domains, and the whole log's, are not compared")


def test_c32_a_cut_previous_run_withholds_and_an_uncut_one_compares_whichever_side_is_shorter():
    # busy then quiet: last run's corp.example was cut at 41 hours, this run it is whole and quiet
    busy = delta_report(255000, 719.0, {"corp.example": (900, 41.0), "shop.example": (5, 719.0)}, {"corp.example": CUT})
    quiet = delta_report(310, 719.0, {"corp.example": (305, 719.0), "shop.example": (5, 719.0)}, {})
    dl = audit.build_delta(quiet, busy)
    assert dl["genuine_failures"] is None and dl["maillog_window"]["domains_not_comparable"] == ["corp.example"]
    # quiet then busy: one row last run, 5000 rows over 30 days now, nothing cut
    one = delta_report(5, 719.0, {"new.example": (0, 0.0), "shop.example": (5, 719.0)}, {})
    many = delta_report(42, 719.0, {"new.example": (37, 719.0), "shop.example": (5, 719.0)}, {})
    dl = audit.build_delta(many, one)
    assert dl["genuine_failures"] == 37 and dl["maillog_window"]["comparable"] is True
    assert dl["maillog_window"]["domains_not_comparable"] == []


def test_c33_the_share_of_the_log_decides_nothing_the_recorded_cut_does():
    def rep(shop_gf, shop_hours, total, cuts):
        doc = delta_report(shop_gf + 100, 719.0, {"shop.example": (shop_gf, shop_hours), "big.example": (100, 719.0)}, cuts)
        doc["maillog"]["window"]["rows"] = total
        doc["maillog"]["by_domain"]["shop.example"]["window"]["rows"] = 5000
        return doc
    # 5000 rows, 2% of this log, its span 719 h -> 41 h: no cut recorded, the counts compare
    dl = audit.build_delta(rep(20, 41.0, 255000, {}), rep(130, 719.0, 30000, {}))
    assert dl["genuine_failures"] == -110 and dl["maillog_window"]["domains_not_comparable"] == []
    # the same domain under a recorded cut is withheld, however small its share
    dl = audit.build_delta(rep(20, 41.0, 255000, {"shop.example": CUT}), rep(130, 719.0, 30000, {}))
    assert dl["genuine_failures"] is None and dl["maillog_window"]["domains_not_comparable"] == ["shop.example"]
    assert not hasattr(audit, "CUT_ROWS") and not hasattr(audit, "CUT_SHARE") and not hasattr(audit, "_row_share")


def test_d7_damaged_windows_and_cuts_read_as_unknown_never_raise():
    now = delta_report(10, 720.0, {"corp.example": (5, 720.0)})
    prev = delta_report(12, 720.0, {"corp.example": (7, 41.0)})
    prev["maillog"]["window"] = "720 hours"
    prev["maillog"]["by_domain"]["corp.example"]["window"] = ["x"]
    dl = audit.build_delta(now, prev)
    assert dl["genuine_failures"] == -2 and dl["maillog_window"]["previous"] is None
    for window in ({"hours": "inf"}, {"hours": float("nan")}, {"from": "0001-01-01T00:30:00+01:00", "to": 5},
                   {"from": "2026-01-01T00:00:00Z", "to": "9999-12-31T23:59:59-01:00"}, 7, None):
        prev["maillog"]["window"] = window
        audit.build_delta(now, prev)
        audit._md_delta([], audit.build_delta(now, prev))
    for odd in ({"cuts": "corp.example"}, {"cuts": [1]}, {"truncation": 5}, {"cuts": {"corp.example": "yes", 7: {}, "": {}}},
                {"cuts": {"corp.example": {"kept_hours": "41", "api_cap_hours": "3h..2h", "reason": ["x"]}}}):
        doc = dict(prev, maillog=dict(prev["maillog"], **odd), caveats="mail log: corp.example row budget reached")
        audit.build_delta(now, doc)
        audit._md_delta([], audit.build_delta(doc, now))
    assert audit.maillog_cuts({"maillog": {"cuts": {"corp.example": "yes", 7: {}, "": {}}}}) == {"corp.example": {}}
    for bad in (None, [], "x", {"maillog": "x"}, {"maillog": {"truncation": ["x"]}, "caveats": {"a": 1}}):
        assert audit.maillog_cuts(bad) == {}
    assert audit.build_delta(dict(now, maillog="x"), dict(prev, maillog=[1]))["maillog_window"]["cut_orgs"] == {}


def test_d15_the_unknown_sender_check_running_in_one_run_only_is_not_a_finding_change():
    def rep(known, ids):
        return {"generated_utc": "2026-10-07T15:00:00Z", "gate": {"domains": {}},
                "rua": {"filters": {"known": known}, "totals": {"messages": 100, "pass_rate": 0.9}},
                "findings": [{"id": i, "source": "rua", "severity": "major", "title": i} for i in ids]}
    old = rep({"given": True}, ["OUTSIDE-002", "OUTSIDE-003"])  # vendors switched the check on before round 9
    new = rep({"given": False, "ip_check": False}, ["OUTSIDE-009", "OUTSIDE-003"])
    dl = audit.build_delta(new, old)
    assert dl["findings_new"] == [] and dl["findings_resolved"] == []
    assert ("the unknown-sender check ran in one of the two runs only: its findings (OUTSIDE-002, OUTSIDE-009) "
            "are not compared") in dl["notes"]
    # a known list with no IP prefix: given, yet the per-IP half did not run
    dl = audit.build_delta(rep({"given": True, "ip_check": False}, ["OUTSIDE-009"]), rep({"given": True}, ["OUTSIDE-002"]))
    assert dl["findings_new"] == [] and dl["findings_resolved"] == []
    # the check ran in both runs: its findings compare as any other
    dl = audit.build_delta(rep({"given": True, "ip_check": True}, []), rep({"given": True}, ["OUTSIDE-002"]))
    assert [f["id"] for f in dl["findings_resolved"]] == ["OUTSIDE-002"] and not any("unknown-sender" in n for n in dl["notes"])


def test_a_sender_a_cut_run_may_have_missed_is_neither_new_nor_gone(tmp_path):
    doms = ["corp.example", "shop.example"]
    whole = (rows_for("corp.example", 3000, 719, 0, 1) + [r[:2] + ["billing@pay.corp.example", "pay.corp.example",
                                                                   "pay.corp.example"] + r[5:]
                                                          for r in rows_for("pay.corp.example", 5, 600, 5, 2, end=END - timedelta(hours=100))]
             + rows_for("shop.example", 300, 719, 10, 3))
    cut = rows_for("corp.example", 1000, 41, 0, 1) + rows_for("shop.example", 300, 719, 10, 3)
    prev = build(tmp_path, "prev", whole, doms, maillog_cuts={})
    now = build(tmp_path, "now", cut, doms, previous_report=prev, maillog_cuts={"corp.example": CUT})
    assert now["delta"]["gone_senders"] == []
    assert "1 sender under corp.example not listed as gone: this run's cut mail log may simply have missed it" in now["delta"]["notes"]
    nxt = build(tmp_path, "next", whole, doms, previous_report=now, maillog_cuts={})
    assert nxt["delta"]["new_senders"] == [] and "new failing senders" not in notify.summarize(nxt, now)
    assert any(n.startswith("1 sender under corp.example not listed as new") for n in nxt["delta"]["notes"])


def test_maillog_cuts_reads_the_recorded_cuts_and_parses_an_older_reports_text():
    assert audit.maillog_cuts({"maillog": {"cuts": {"Corp.Example.": CUT}}}) == {"corp.example": CUT}
    assert audit.maillog_cuts({"maillog": {"cuts": {}, "truncation": "row budget kept only the newest 41h for x.example"}}) == {}
    older = {"maillog": {"truncation": "row budget kept only the newest 2d for corp.example; an hour of corp.example "
                                       "(3h..2h ago) is truncated at the API cap; an hour of b.example (7h..6h ago) "
                                       "is truncated at the API cap"},
             "caveats": ["mail log: shop.example row budget reached at 47h..41h ago - older rows skipped; the rows cover "
                         "only the last 41h (raise --max-rows to keep more) - mail-log counts for that domain cover that span only",
                         "mail log: b.example has more than 100,000 rows within one hour (7h..6h ago) - that hour is truncated "
                         "- mail-log counts for that domain are a floor and its failures are not verified"]}
    assert audit.maillog_cuts(older) == {
        "corp.example": {"reason": "row budget", "kept_hours": 48, "api_cap_hours": ["3h..2h"]},
        "b.example": {"reason": "api cap", "api_cap_hours": ["7h..6h"]},
        "shop.example": {"reason": "row budget", "kept_hours": 41}}


# ------------------------------------------------------------------ collect: recording, the run stamp, domains.txt

class Tenant:
    """In-memory hunting over (hours ago, org-suffix domain, row) legs, cut at collect.ROW_CAP like the API."""

    def __init__(self, legs):
        self.legs = legs

    def hunting(self, tok, kql, ts=None):
        named = re.search(r'let sender_domain = "([^"]+)";', kql)
        if not named:  # the mail-flow aggregate collect runs on every run with a token: nothing seen here
            return {"schema": [], "results": []}
        org = named.group(1)
        start = int(re.search(r"let window_start\s*=\s*ago\((\d+)h\);", kql).group(1))
        m = re.search(r"let window_end\s*=\s*ago\((\d+)h\);", kql)
        end = int(m.group(1)) if m else 0
        mine = [(a, r) for a, d, r in self.legs if (d == org or d.endswith("." + org)) and end <= a < start]
        if "summarize n = count()" in kql:
            counts = {}
            for a, _ in mine:
                counts[int(a)] = counts.get(int(a), 0) + 1
            return {"schema": [{"name": "hago"}, {"name": "dir"}, {"name": "n"}],
                    "results": [{"hago": h, "dir": "Intra-org", "n": n} for h, n in sorted(counts.items())]}
        rows = [r for _, r in mine]
        return {"schema": [{"name": c} for c in (rows[0] if rows else {"Timestamp": 1})], "results": rows[:collect.ROW_CAP]}


def legs(now, spec):
    """spec: {domain: (legs per hour, every Nth hour, failing every Nth leg or 0, from hour, to hour)}."""
    out, i = [], 0
    for dom, (per, every, fail_every, lo, hi) in spec.items():
        for h in range(lo, hi):
            if h % every:
                continue
            for k in range(per):
                i += 1
                ago = h + k / float(per + 1)
                ok = not (fail_every and i % fail_every == 0)
                out.append((ago, dom, {"Internet message ID": "<t%d@%s>" % (i, dom), "Recipients": "user@example.com",
                                       "Sender address": "app@" + dom, "Sender domain": dom,
                                       "Sender mail from domain": dom,
                                       "Delivery action": "Delivered" if ok else "Blocked",
                                       "Latest delivery location": "Inbox/folder" if ok else "Quarantine",
                                       "Subject": "Notice", "DMARC": "pass" if ok else "fail", "SPF": "pass",
                                       "DKIM": "pass" if ok else "fail", "Envelope domain": dom,
                                       "Sender IP": "203.0.113.%d" % (i % 250 + 1),
                                       "Timestamp": (now - timedelta(hours=ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                       "Direction": "Intra-org"}))
    return out


def test_pull_maillog_records_each_org_the_row_budget_or_the_api_cap_cut(monkeypatch, tmp_path):
    monkeypatch.setattr(collect, "ROW_CAP", 100)
    monkeypatch.setattr(collect, "SLICE_TARGET", 90)
    now = datetime(2026, 10, 7, 12, 0, 0)
    t = Tenant(legs(now, {"busy.example": (40, 1, 0, 0, 48), "quiet.example": (1, 10, 0, 0, 700),
                          "burst.example": (150, 1, 0, 5, 6)}))
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    cuts = {}
    path, notes = collect.pull_maillog("tok", ["busy.example", "quiet.example", "burst.example"], tmp_path / "m.csv",
                                       30, 200, None, cuts)
    assert set(cuts) == {"busy.example", "burst.example"}  # quiet.example came back whole
    busy = cuts["busy.example"]
    assert busy["reason"] == "row budget" and busy["kept_hours"] == 6 and re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", busy["kept_from"])
    assert any("busy.example row budget reached at 8h..6h ago" in n and "cover only the last 6h" in n for n in notes)
    assert cuts["burst.example"] == {"reason": "api cap", "api_cap_hours": ["6h..5h"]}
    assert collect.truncation_text(notes) == ("row budget kept only the newest 6h for busy.example; "
                                              "an hour of burst.example (6h..5h ago) is truncated at the API cap")
    # without a budget nothing is cut, and the dict stays optional
    cuts = {}
    collect.pull_maillog("tok", ["busy.example"], tmp_path / "w.csv", 30, 0, None, cuts)
    assert cuts == {}
    assert collect.pull_maillog("tok", ["busy.example"], tmp_path / "x.csv", 30, 200)[0]


def test_metrics_render_marks_a_cut_runs_count_as_a_floor_and_reads_odd_values_as_unknown():
    entries = [{"run": "2026-10-01T060000Z", "domains": {"corp.example": {"policy": "none", "gate": "no_go"}},
                "findings": {"major": 1}, "genuine_failures": 613, "rua_pass_rate": 0.9, "plan_changes": 1,
                "plan_priority1": 0, "maillog_cut_orgs": ["corp.example"]},
               1, {"run": None, "domains": [1], "findings": "x", "genuine_failures": "12", "rua_pass_rate": "x",
                   "plan_changes": "2", "maillog_cut_orgs": "corp.example"}]
    md = collect.render_metrics(entries)
    assert "| 2026-10-01T060000Z | corp.example none/no_go | major 1 | 613 (floor, corp.example cut) | 90.0% | 1 (0 now) |" in md
    assert "| - |  | - | - | - | 0 (0 now) |" in md


def test_collect_records_its_cuts_names_its_run_and_leads_domains_txt_with_the_headline(monkeypatch, tmp_path):
    """The real collect.main against an in-memory tenant (every network seam
    stubbed, sockets refused): a whole run, a run the row budget cut, a whole
    run again. The cut is in report.json before the delta reads it, every
    name under the cut org is withheld both times, and the next run names
    which run was cut."""
    attempts = []

    def refuse(*a, **k):
        attempts.append(a)  # recorded too, in case a caller swallows the error
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.delenv("RUA_MAILBOX", raising=False)
    now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
    t = Tenant(legs(now, {"corp.example": (10, 1, 0, 0, 720), "hr.corp.example": (1, 10, 2, 0, 720),
                          "pay.corp.example": (1, 50, 1, 200, 720), "shop.example": (1, 2, 4, 0, 720)}))
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    monkeypatch.setattr(collect.graph_client, "creds", lambda env_file=None: ("tenant", "client", "secret"))
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([], None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
    monkeypatch.setattr(audit, "run_dns", lambda domains, resolver, selectors=(): None)
    monkeypatch.setattr(collect, "ROW_CAP", 300)
    monkeypatch.setattr(collect, "SLICE_TARGET", 270)
    out = tmp_path / "out"

    def run(max_rows):
        monkeypatch.setattr(sys, "argv", ["collect.py", "shop.example", "corp.example", "hr.corp.example",
                                          "pay.corp.example", "--no-config", "--no-owners", "--no-notify",
                                          "--out", str(out), "--max-rows", str(max_rows)])
        try:
            collect.main()
        except SystemExit:
            pass
        latest = out / "latest"
        return (json.loads((latest / "report.json").read_text(encoding="utf-8")),
                json.loads((latest / "run.json").read_text(encoding="utf-8")), latest)

    whole, run1, latest = run(0)
    assert whole["maillog"]["cuts"] == {} and whole["inputs"]["run"] == run1["run"]
    # shop.example was typed first: the inventory is sorted, domains.txt leads with the headline
    assert whole["gate"]["headline_domain"] == "shop.example"
    assert (latest / "domains.txt").read_text(encoding="utf-8").split() == [
        "shop.example", "corp.example", "hr.corp.example", "pay.corp.example"]
    cut, run2, latest = run(1500)
    assert set(cut["maillog"]["cuts"]) == {"corp.example"} and cut["maillog"]["cuts"]["corp.example"]["reason"] == "row budget"
    assert cut["inputs"]["run"] == run2["run"] != run1["run"]
    mw = cut["delta"]["maillog_window"]
    assert mw["domains_not_comparable"] == ["corp.example", "hr.corp.example", "pay.corp.example"]
    assert set(cut["delta"]["by_domain"]) == {"shop.example"} and cut["delta"]["genuine_failures"] is None
    summary = (latest / "summary.txt").read_text(encoding="utf-8")
    assert "vs last run" not in next(l for l in summary.splitlines() if "`hr.corp.example`" in l)
    assert "failure counts not compared: the mail log was cut for corp.example in one of these runs" in summary
    assert "the row budget cut the mail log for corp.example in this run" in (latest / "next_steps.md").read_text(encoding="utf-8")
    again, run3, latest = run(0)
    assert again["delta"]["maillog_window"]["domains_not_comparable"] == ["corp.example", "hr.corp.example", "pay.corp.example"]
    assert any("cut corp.example's mail log in the previous run" in n for n in again["delta"]["notes"])
    assert "the row budget cut the mail log for corp.example in the previous run" in (latest / "next_steps.md").read_text(encoding="utf-8")
    metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert [m["maillog_cut_orgs"] for m in metrics] == [[], ["corp.example"], []]
    assert all("maillog_hours_by_domain" not in m for m in metrics)
    assert attempts == []


# ------------------------------------------------------------------ the Slack trend (notify)

def test_c3_a_quiet_domain_moving_its_few_rows_leaves_the_slack_trend_on_the_counts(tmp_path):
    doms = ["corp.example", "quiet.example"]
    prev = build(tmp_path, "prev", rows_for("corp.example", 600, 700, 20, 1) + rows_for("quiet.example", 3, 480, 2, 2), doms)
    now = build(tmp_path, "now", rows_for("corp.example", 600, 700, 10, 1) + rows_for("quiet.example", 1, 0, 1, 2), doms,
                previous_report=prev)
    entries = [collect.metrics_entry("2026-10-01T120000Z", prev, {"changes": []}),
               collect.metrics_entry("2026-10-08T120000Z", now, {"changes": []})]
    text = notify.summarize(now, prev, history=entries)
    assert "- genuine failures vs last run: -11" in text
    assert trend_line(text) == "- trend over the last 2 runs (improving): genuine failures 22, 11"


def test_c6_an_older_entrys_per_domain_hours_no_longer_switch_the_word():
    history = [{"genuine_failures": 50, "rua_pass_rate": 0.90, "maillog_hours": 696.0,
                "maillog_hours_by_domain": {"corp.example": 696.0, "shop.example": 300.0}},
               {"genuine_failures": 30, "rua_pass_rate": 0.899, "maillog_hours": 696.0,
                "maillog_hours_by_domain": {"corp.example": 696.0, "shop.example": 20.0}}]
    line = trend_line(notify.summarize({"gate": {}}, history=history))
    assert "(improving)" in line and "not compared" not in line
    history.insert(0, dict(history[0]))
    assert "(improving)" in trend_line(notify.summarize({"gate": {}}, history=history))


def test_c11_a_quiet_domains_span_leaves_a_rising_count_worsening():
    history = [{"genuine_failures": 22, "rua_pass_rate": 0.867, "maillog_hours": 720.0, "maillog_cut_orgs": [],
                "maillog_hours_by_domain": {"corp.example": 480.0, "example.com": 720.0}},
               {"genuine_failures": 23, "rua_pass_rate": 0.88, "maillog_hours": 720.0, "maillog_cut_orgs": [],
                "maillog_hours_by_domain": {"corp.example": 2.0, "example.com": 720.0}}]
    assert trend_line(notify.summarize({"gate": {}}, history=history)) == (
        "- trend over the last 2 runs (worsening): genuine failures 22, 23; pass rate 86.7%, 88.0%")
    three = [dict(history[0], genuine_failures=11), dict(history[1], genuine_failures=12), dict(history[1], genuine_failures=13)]
    assert "(worsening)" in trend_line(notify.summarize({"gate": {}}, history=three))


def test_d3_a_comparable_delta_and_a_quiet_domains_span_give_one_story():
    rep = {"gate": {}, "delta": {"previous_generated_utc": "2026-10-01T06:00:00Z", "genuine_failures": -2,
                                 "maillog_window": {"comparable": True, "log_comparable": True, "cut_orgs": {}}}}
    history = [{"genuine_failures": 8, "maillog_hours": 720.0, "maillog_hours_by_domain": {"shop.example": 480.0}},
               {"genuine_failures": 6, "maillog_hours": 720.0, "maillog_hours_by_domain": {"shop.example": 0.0}}]
    text = notify.summarize(rep, history=history)
    assert "- genuine failures vs last run: -2" in text
    assert trend_line(text) == "- trend over the last 2 runs (improving): genuine failures 8, 6"


def test_d11_a_busy_domains_ordinary_span_change_leaves_the_word_on_the_counts():
    history = [{"genuine_failures": 45, "maillog_hours": 720.0, "maillog_hours_by_domain": {"shop.example": 468.0}},
               {"genuine_failures": 45, "maillog_hours": 720.0, "maillog_hours_by_domain": {"shop.example": 468.0}},
               {"genuine_failures": 47, "maillog_hours": 720.0, "maillog_hours_by_domain": {"shop.example": 3.0},
                "maillog_cut_orgs": []}]
    assert trend_line(notify.summarize({"gate": {}}, history=history)) == (
        "- trend over the last 3 runs (worsening): genuine failures 45, 45, 47")


def test_c9_a_near_empty_first_archive_never_decides_the_word():
    history = [{"genuine_failures": None, "rua_pass_rate": 0.25, "rua_messages": 4},
               {"genuine_failures": None, "rua_pass_rate": 0.95, "rua_messages": 1000}]
    assert trend_line(notify.summarize({"gate": {}}, history=history)) == (
        "- trend over the last 2 runs (not comparable): pass rate 25.0%, 95.0%; "
        "pass rate not compared: the outside views differ tenfold in size")
    history.append({"genuine_failures": None, "rua_pass_rate": 0.93, "rua_messages": 1100})
    assert "(not comparable)" in trend_line(notify.summarize({"gate": {}}, history=history))
    history[0]["rua_messages"] = 900  # a full first archive: the rate decides
    assert "(improving)" in trend_line(notify.summarize({"gate": {}}, history=history))


def test_c10_spans_that_differ_and_views_that_differ_leave_no_basis_for_a_word():
    history = [{"genuine_failures": 400, "rua_pass_rate": 0.95, "rua_messages": 100, "maillog_hours": 719.0},
               {"genuine_failures": 200, "rua_pass_rate": 0.60, "rua_messages": 50000, "maillog_hours": 41.0}]
    assert trend_line(notify.summarize({"gate": {}}, history=history)) == (
        "- trend over the last 2 runs (not comparable): genuine failures 400, 200; pass rate 95.0%, 60.0%; "
        "failure counts not compared: the mail-log spans differ; pass rate not compared: the outside views differ tenfold in size")


def test_c42_empty_outside_views_are_never_flat():
    history = [{"genuine_failures": None, "rua_pass_rate": 0.0, "rua_messages": 0},
               {"genuine_failures": None, "rua_pass_rate": 0.0, "rua_messages": 0}]
    line = trend_line(notify.summarize({"gate": {}}, history=history))
    assert line == ("- trend over the last 2 runs (not comparable): pass rate 0.0%, 0.0%; "
                    "pass rate not compared: neither outside view carries messages")
    history[1].update(rua_pass_rate=0.95, rua_messages=5000)
    assert "(not comparable)" in trend_line(notify.summarize({"gate": {}}, history=history))
    assert notify._views_differ([0, 5000]) == "one outside view carries no messages"
    assert notify._views_differ([None, 5000]) is None and notify._views_differ([None, 0]) == "one outside view carries no messages"


def test_c21_an_entry_without_the_cut_key_cannot_hide_a_cut_the_other_end_records():
    history = [{"genuine_failures": 610, "rua_pass_rate": 0.80, "maillog_hours": 719.0},  # written before the key
               {"genuine_failures": 610, "rua_pass_rate": 0.80, "maillog_hours": 719.0, "maillog_cut_orgs": []},
               {"genuine_failures": 50, "rua_pass_rate": 0.79, "maillog_hours": 719.0, "maillog_cut_orgs": ["corp.example"]}]
    line = trend_line(notify.summarize({"gate": {}}, history=history))
    assert "(improving)" not in line and "(worsening)" in line  # the pass rate fell: that is the word
    assert "failure counts not compared: the mail log was cut for corp.example in one of these runs" in line


def test_c28_the_word_judges_the_entries_figures_whatever_pair_a_delta_judged():
    rep = {"gate": {}, "delta": {"previous_generated_utc": "2026-10-08T18:38:20Z", "genuine_failures": None,
                                 "maillog_window": {"comparable": False, "log_comparable": False, "cut_orgs": {}}}}
    history = [{"genuine_failures": 50, "maillog_hours": 696.0, "maillog_cut_orgs": []},
               {"genuine_failures": 30, "maillog_hours": 696.0, "maillog_cut_orgs": []}]
    assert trend_line(notify.summarize(rep, history=history)) == "- trend over the last 2 runs (improving): genuine failures 50, 30"
    rates = [{"genuine_failures": None, "rua_pass_rate": 0.70}, {"genuine_failures": None, "rua_pass_rate": 0.72}]
    assert trend_line(notify.summarize(rep, history=rates)) == "- trend over the last 2 runs (improving): pass rate 70.0%, 72.0%"
    one = [{"genuine_failures": 5, "maillog_hours": 41.0, "rua_pass_rate": 0.7},
           {"genuine_failures": None, "rua_pass_rate": 0.72, "maillog_cut_orgs": ["corp.example"]}]
    assert "failure counts not compared" not in trend_line(notify.summarize(rep, history=one))  # one count is no comparison


def test_c37_no_delta_verdict_is_applied_at_any_trend_length():
    history = [{"genuine_failures": 900, "rua_pass_rate": 0.82, "maillog_hours": 719.0, "maillog_cut_orgs": []},
               {"genuine_failures": 150, "rua_pass_rate": 0.81, "maillog_hours": 719.0, "maillog_cut_orgs": ["corp.example"]},
               {"genuine_failures": 600, "rua_pass_rate": 0.80, "maillog_hours": 719.0, "maillog_cut_orgs": []}]
    rep = {"gate": {}, "delta": {"previous_generated_utc": "2026-10-02T06:00:00Z", "maillog_window": {"comparable": False}}}
    line = trend_line(notify.summarize(rep, history=history))
    assert line == "- trend over the last 3 runs (improving): genuine failures 900, 150, 600; pass rate 82.0%, 81.0%, 80.0%"
    assert "(improving)" in trend_line(notify.summarize(rep, history=[history[0], history[2]]))


def test_c31_odd_values_in_the_history_read_as_unknown_never_raise():
    rep = {"gate": {}}
    for odd in (["corp.example"], 696.0, True, "x", {"corp.example": 1}, None):
        history = [{"genuine_failures": 5, "maillog_hours": odd, "maillog_hours_by_domain": odd, "maillog_cut_orgs": odd,
                    "rua_pass_rate": odd, "rua_messages": odd},
                   {"genuine_failures": "12", "maillog_hours": 696.0, "maillog_hours_by_domain": odd,
                    "maillog_cut_orgs": odd, "rua_pass_rate": 0.5, "rua_messages": odd}, 7, None]
        notify.summarize(rep, history=history)
        collect.render_metrics(history)
    history = [{"genuine_failures": 5}, {"genuine_failures": "12"}, {"genuine_failures": 3}]
    assert trend_line(notify.summarize(rep, history=history)) == "- trend over the last 3 runs (improving): genuine failures 5, -, 3"
    assert notify.trend_word([5, "x", True, 3]) == "improving"


# ------------------------------------------------------------------ who is new (notify --senders)

SENDERS = {"updated": "2026-10-07T150000Z", "senders": {
    "ip:203.0.113.9": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
    "envelope:example.com": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
    "ip:198.51.100.7": {"first_seen": "2026-10-07T150000Z", "last_seen": "2026-10-07T150000Z"}}}
NEW_LINE = "- *newly identified senders* (never seen in an earlier run): 198.51.100.7"


def senders_cli(tmp_path, generated, run=None, senders=SENDERS):
    rep = {"generated_utc": generated, "inputs": {"run": run} if run else {"domains": ["example.com"]},
           "gate": {"domains": {}}, "summary": {"findings": 0, "by_severity": {}}, "findings": [],
           "maillog": {"counters": {"genuine_failures": 1},
                       "census": {"by_envelope": [{"envelope_domain": "example.com", "genuine_failures": 1}]}},
           "rua": {"totals": {"messages": 10, "pass_rate": 0.5}, "source_ips": ["203.0.113.9", "198.51.100.7"]}}
    d = tmp_path / re.sub(r"\W", "", generated + (run or ""))
    d.mkdir()
    (d / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    (d / "senders.json").write_text(json.dumps(senders), encoding="utf-8")
    p = subprocess.run([sys.executable, str(Path(notify.__file__)), "--report", str(d / "report.json"),
                        "--senders", str(d / "senders.json"), "--dry-run"], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and "Traceback" not in p.stderr, p.stderr
    return next(l for l in p.stdout.splitlines() if "newly identified" in l)


def test_c8_audit_pys_own_report_hours_after_a_collect_run_announces_nothing_again(tmp_path):
    for generated in ("2026-10-07T16:00:00Z", "2026-10-07T17:59:00Z", "2026-10-07T15:00:05Z"):
        assert senders_cli(tmp_path, generated) == "- newly identified senders: none"


def test_d5_a_report_without_a_run_stamp_counts_every_recorded_sender_as_known(tmp_path):
    assert senders_cli(tmp_path, "2026-10-07T17:05:00Z") == "- newly identified senders: none"
    assert notify._report_run({"inputs": {"run": " 2026-10-07T150000Z "}}) == "2026-10-07T150000Z"
    assert notify._report_run({"inputs": {"run": 5}}) is None and notify._report_run({"inputs": "x"}) is None
    assert not hasattr(notify, "_report_stamp") and not hasattr(notify, "_same_run")


def test_c29_collects_report_names_its_run_however_long_the_run_or_old_the_report(tmp_path):
    assert senders_cli(tmp_path, "2026-10-07T18:10:00Z", run="2026-10-07T150000Z") == NEW_LINE  # 3h10m into the run
    older = {"updated": "2026-10-07T150000Z", "senders": dict(SENDERS["senders"], **{
        "ip:198.51.100.7": {"first_seen": "2026-10-01T060000Z", "last_seen": "2026-10-07T150000Z"}})}
    assert senders_cli(tmp_path, "2026-10-01T06:05:00Z", run="2026-10-01T060000Z", senders=older) == NEW_LINE
    assert senders_cli(tmp_path, "2026-10-08T06:05:00Z", run="2026-10-08T060000Z", senders=older) == (
        "- newly identified senders: none")  # a later run: it was known by then


def test_c30_a_generation_time_out_of_range_never_crashes_the_message(tmp_path):
    for generated in ("0001-01-01T00:30:00+01:00", "9999-12-31T23:59:59-01:00"):
        assert senders_cli(tmp_path, generated) == "- newly identified senders: none"


# ------------------------------------------------------------------ the document's trend (next_steps)

def test_c5_c12_the_documents_reason_names_the_run_the_cut_was_in():
    window = {"from": "2026-09-07T15:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 720.0}
    for now_cut, prev_cut, when in ((None, CUT, "the previous run"), (CUT, None, "this run"), (CUT, CUT, "both runs")):
        prev = delta_report(40, 720.0, {"corp.example": (40, 6.0)}, {"corp.example": prev_cut} if prev_cut else {},
                            gen="2026-10-01T15:00:00Z")
        now = ns_report(400, window, cuts={"corp.example": now_cut} if now_cut else {})
        now["maillog"]["by_domain"] = {"corp.example": {"genuine_failures": 400, "delivered_despite_fail": 0}}
        now["delta"] = audit.build_delta(now, prev)
        line = stand_trend(next_steps.build(now))
        assert line == ("**Trend vs 2026-10-01: not comparable** - failure counts are not compared: the row budget cut "
                        "the mail log for corp.example in %s" % when)
        assert "shorter span" not in line
    cuts = {"%s.example" % c: {"now": CUT, "previous": None} for c in "abcde"}
    cuts["f.example"] = {"now": None, "previous": {"reason": "api cap", "api_cap_hours": ["3h..2h"]}}
    assert next_steps._cut_reason(cuts) == ("the row budget cut the mail log for a.example, b.example, c.example and 2 more "
                                            "in this run; the API row cap cut the mail log for f.example in the previous run")


def test_d10_a_refusal_without_a_recorded_cut_never_names_the_row_budget():
    window = {"from": "2026-10-05T22:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 41.0}
    trend = {"source": "delta", "label": "2026-10-01", "previous_genuine_failures": 45, "previous_pass_rate": None}
    spans = {"previous_generated_utc": "2026-10-01T15:00:00Z",
             "maillog_window": {"comparable": False, "log_comparable": False, "cut_orgs": {}}}
    rep = ns_report(47, window, delta=spans)
    t = next_steps.apply_comparability(dict(trend), spans, rep, next_steps.maillog_view(rep))
    assert t["not_comparable"] == ["failure counts are not compared: the two mail logs cover very different spans"]
    older = {"previous_generated_utc": "2026-10-01T15:00:00Z",  # written by round 9's span guess
             "maillog_window": {"comparable": False, "domains_not_comparable": ["shop.example"]}}
    t = next_steps.apply_comparability(dict(trend), older, rep, next_steps.maillog_view(rep))
    assert t["not_comparable"] == ["failure counts are not compared: the mail-log rows of shop.example cover very "
                                   "different spans in the two runs"]
    assert not any("row budget" in r for r in t["not_comparable"])


def test_c22_a_refused_delta_about_another_run_does_not_hide_a_comparable_trend():
    window = {"from": "2026-10-06T15:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 24.0}
    refused = {"previous_generated_utc": "2026-09-01T15:00:00Z", "genuine_failures": None,
               "maillog_window": {"comparable": False, "log_comparable": False, "cut_orgs": {}}, "notes": []}
    yesterday = {"generated_utc": "2026-10-06T15:00:00Z", "gate": {},
                 "maillog": {"counters": {"genuine_failures": 42},
                             "window": {"from": "2026-10-05T15:00:00Z", "to": "2026-10-06T15:00:00Z", "hours": 24.0}}}
    expected = "**Trend vs 2026-10-06: -12 genuine failures (42 -> 30)**"
    assert stand_trend(next_steps.build(ns_report(30, window, delta=refused), previous=yesterday)) == expected
    metrics = [{"run": "2026-10-06T150000Z", "genuine_failures": 42, "maillog_hours": 24.0, "maillog_cut_orgs": []}]
    assert stand_trend(next_steps.build(ns_report(30, window, delta=refused), metrics=metrics)) == expected
    # with no other candidate, the refused delta is still the trend line, never "first run"
    assert stand_trend(next_steps.build(ns_report(30, window, delta=refused))).startswith("**Trend vs 2026-09-01: not comparable**")
    trend = next_steps.merge_trends([None, {"source": "metrics", "label": "2026-10-06", "previous_genuine_failures": None,
                                            "previous_pass_rate": 0.9}])
    assert trend["source"] == "metrics"


def test_c40_two_sub_hour_spans_compare_in_the_document_too():
    window = {"from": "2026-10-07T14:42:00Z", "to": "2026-10-07T15:00:00Z", "hours": 0.3}
    metrics = [{"run": "2026-09-30T150000Z", "genuine_failures": 5, "maillog_hours": 0.9, "maillog_cut_orgs": []}]
    assert stand_trend(next_steps.build(ns_report(3, window), metrics=metrics)) == "**Trend vs 2026-09-30: -2 genuine failures (5 -> 3)**"
    metrics[0]["maillog_hours"] = 40.0
    assert "not comparable" in stand_trend(next_steps.build(ns_report(3, window), metrics=metrics))


def test_d6_without_a_delta_the_document_reads_both_runs_cuts():
    window = {"from": "2026-09-07T15:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 720.0}
    metrics = [{"run": "2026-10-01T150000Z", "genuine_failures": 80, "maillog_hours": 719.0, "maillog_cut_orgs": ["corp.example"]}]
    assert stand_trend(next_steps.build(ns_report(12, window), metrics=metrics)) == (
        "**Trend vs 2026-10-01: not comparable** - failure counts are not compared: the mail log was cut for "
        "corp.example in the previous run")
    metrics[0]["maillog_cut_orgs"] = []
    assert stand_trend(next_steps.build(ns_report(12, window, cuts={"corp.example": CUT}), metrics=metrics)) == (
        "**Trend vs 2026-10-01: not comparable** - failure counts are not compared: the row budget cut the mail log for "
        "corp.example in this run")
    prev = {"generated_utc": "2026-10-01T15:00:00Z", "gate": {},
            "maillog": {"counters": {"genuine_failures": 80}, "window": {"hours": 719.0},
                        "truncation": "row budget kept only the newest 41h for corp.example"}}
    assert stand_trend(next_steps.build(ns_report(12, window), previous=prev)).endswith(
        "the row budget cut the mail log for corp.example in the previous run")
    sub = {"from": "2026-10-07T14:48:00Z", "to": "2026-10-07T15:00:00Z", "hours": 0.2}
    metrics = [{"run": "2026-10-01T150000Z", "genuine_failures": 6, "maillog_hours": 0.5}]
    assert stand_trend(next_steps.build(ns_report(4, sub), metrics=metrics)) == "**Trend vs 2026-10-01: -2 genuine failures (6 -> 4)**"


# ------------------------------------------------------------------ the docs

def test_c38_the_readme_ties_the_trend_word_to_what_compares():
    text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "the trend word then follows the pass rate rather than the failure counts" not in text
    assert ("it follows the failure counts when they compare, else the pass rate when the outside views compare, "
            "else it says \"not comparable\"") in text
    assert "the row budget (or an hour at the API row cap) cut an organization's mail log in either run" in text
