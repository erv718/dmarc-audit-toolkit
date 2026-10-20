"""Round 13, T-05 (and T-06, below): one status per plan row, used everywhere.

plan.py computes each row's status once (status, status_text, status_reason: address, host, held,
gated, later, check, now - the first that applies), and every file that lays the plan out reads it:
the ask and the owners' line say "zero-risk" and "ready" only for a row that is ready now, todo.md's
Do now lists only those, the cards and At a glance carry the status as a pill, and verify.md opens
each row's section with it. Synthetic data, offline."""

import re

import pytest

import brief
import collect
import next_steps
import notify
import plan as plan_mod
import r13_fixtures as F
import verify


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_status_estate"))


def statuses(plan):
    return {c["id"]: c["status"] for c in plan["changes"]}


def test_every_estate_row_gets_one_status_and_none_is_ready(run):
    plan = run["plan"]
    st = statuses(plan)
    # after T-10 the quiet names' quarantine-now rows wait on their own checks only
    assert {i: st[i] for i in ("P-01", "P-02", "P-08")} == {"P-01": "check", "P-02": "check", "P-08": "check"}
    assert all(st["P-%02d" % i] == "check" for i in range(3, 8)) and st["P-09"] == "check"
    assert st["P-10"] == st["P-11"] == "host"
    assert st["P-12"] == st["P-13"] == st["P-14"] == "gated"
    assert "now" not in st.values()
    row = {c["id"]: c for c in plan["changes"]}
    assert row["P-09"]["status_text"] == "after 2 checks"  # its external-destination record and one change a week
    assert row["P-03"]["status_text"] == "after 1 check"
    assert row["P-03"]["status_reason"].startswith("corp.example publishes e.example.com._report._dmarc.corp.example")
    assert row["P-10"]["status_text"] == "find its DNS host first" and row["P-10"]["status_reason"] == ""
    assert row["P-12"]["status_text"] == "the gate says not yet"
    assert row["P-12"]["status_reason"].startswith("spoofing source 203.0.113.66 (120 msgs) saw disposition none")
    assert row["P-13"]["status_reason"].startswith("spoofing source 203.0.113.9 (40 msgs)")
    # the prerequisites stay as they were: the status is beside them
    assert row["P-09"]["prerequisites"][1].startswith("one change to _dmarc.example.net a week")
    assert all(set(c) >= {"status", "status_text", "status_reason"} for c in plan["changes"])


def test_the_ask_never_calls_a_row_zero_risk_or_ready_unless_it_is_ready_now(run):
    ask = run["doc"]["ask"]
    assert "zero-risk" not in ask and "ready" not in ask
    assert ("approval to publish 6 records (plan P-03, P-04, P-05, P-06, P-07, P-09) once the checks listed with each "
            "are confirmed") in ask
    assert ("approval to move 3 domains that send no mail straight to quarantine (plan P-01, P-02, P-08) once the checks "
            "listed with each are confirmed") in ask
    assert "the DNS host of 2 records found first (plan P-10 to P-11)" in ask
    for g in run["doc"]["actions_by_owner"]:
        for i in g["items"]:
            if i["kind"] == "p1summary":
                assert "zero-risk" not in i["hook"] and "ready to publish" not in i["action"], i


def test_todo_md_does_now_only_what_is_ready_now(run):
    todo = collect.render_todo(run["report"], run["plan"])
    do_now = todo.split("## 2. Do now", 1)[1].split("\n## ", 1)[0].strip().splitlines()
    assert do_now[1:] == ["", "- none"]
    after = todo.split("## 2b. After a check", 1)[1].split("\n## ", 1)[0]
    assert [l.split()[1] for l in after.splitlines() if l.startswith("- P-")] == [
        "P-01", "P-02", "P-03", "P-04", "P-05", "P-06", "P-07", "P-08", "P-09"]
    assert "  - status: after 2 checks - corp.example publishes example.net._report._dmarc.corp.example" in after
    waiting = todo.split("## 2c. Waiting", 1)[1].split("\n## ", 1)[0]
    assert [l.split()[1] for l in waiting.splitlines() if l.startswith("- P-")] == ["P-10", "P-11"]
    assert waiting.count("  - status: find its DNS host first") == 2
    text = notify.summarize(run["report"], plan=run["plan"])
    assert ("- plan: 14 change(s) waiting: 9 after their checks (3 move domains that send no mail straight to "
            "quarantine), 2 need their DNS host found first, 3 not this week (held, gated or after another change to "
            "the same record); 1 hold(s)") in text
    assert "zero-risk" not in text


def test_the_second_change_to_one_record_waits_for_the_first(tmp_path):
    run = F.estate(tmp_path, net_clean=True)  # example.net's gate is go
    assert run["report"]["gate"]["domains"]["example.net"]["verdict"] == "go"
    row = {c["id"]: c for c in run["plan"]["changes"]}
    assert (row["P-13"]["status"], row["P-13"]["status_text"]) == ("later", "after P-09")
    assert row["P-09"]["status"] == "check"  # the first of the pair waits only on its checks
    assert row["P-14"]["status"] == "gated"  # example.com's gate is still not go
    # its card is quiet and says so; the ask asks only for the first one
    page = brief.render(run["doc"], run["plan"])
    card = re.search(r'<article class="card quiet" id="rec-\d+"><div class="card-head"><span class="pill info">after '
                     r'P-09</span> <span class="tag rid">P-13</span>', page)
    assert card
    assert "P-13" not in run["doc"]["ask"]


def test_a_quarantine_now_row_the_gate_holds_is_held_everywhere(tmp_path):
    run = F.estate(tmp_path, nobodys_stream=True)  # 192.0.2.99 fails with no From domain: it holds every gate
    rep, plan, doc = run["report"], run["plan"], run["doc"]
    row = {c["id"]: c for c in plan["changes"]}
    for rid in ("P-01", "P-02", "P-08"):
        assert (row[rid]["status"], row[rid]["status_text"]) == ("held", "held (Per domain says why)")
        assert row[rid]["status_reason"].startswith("192.0.2.99 fails DMARC on 30/30 msgs")
    # the ask never asks for them; it says they are not for this week
    assert "approval to move" not in doc["ask"]
    assert "not this week: plan P-01, P-02, P-08, held (Per domain says why)" in doc["ask"]
    # todo.md waits on them, with the reason; the cards are quiet and say what holds them
    todo = collect.render_todo(rep, plan)
    waiting = todo.split("## 2c. Waiting", 1)[1].split("\n## ", 1)[0]
    assert ("  - status: held (Per domain says why) - 192.0.2.99 fails DMARC on 30/30 msgs (looks like our own system "
            "misconfigured)") in waiting
    page = brief.render(doc, plan)
    head = re.search(r'<article class="card quiet" id="rec-\d+"><div class="card-head"><span class="pill bad">held'
                     r'</span> <span class="tag rid">P-01</span>.*?</div><p class="held">Held by: (.*?)</p>', page)
    assert head and "192.0.2.99" in head.group(1)
    # verify.md opens the row's section with the same status
    md = verify.render(rep, plan)
    assert re.search(r"#### P-01 [^\n]*\n\nStatus: held \(Per domain says why\) - 192\.0\.2\.99 fails DMARC", md)


def test_the_cards_and_at_a_glance_carry_each_rows_status(run):
    page = brief.render(run["doc"], run["plan"])
    index = re.search(r'<table class="index">.*?</table>', page).group(0)
    assert "<th>Status</th>" in index.replace(' scope="col"', "")
    cells = re.findall(r'<tr><td><a href="#rec-\d+">(P-\d+)</a></td><td class="status"><span class="pill (\w+)">'
                       r'([^<]+)</span></td>', index)
    want = {c["id"]: c for c in run["plan"]["changes"]}
    assert [i for i, _, _ in cells] == list(want)
    for rid, cls, words in cells:
        assert words == want[rid]["status_text"].split(" (")[0]
        assert cls == brief.STATUS_PILLS[want[rid]["status"]]
    # every card leads with the same pill; only the rows that do not go out this week are quiet
    cards = re.findall(r'<article class="card( quiet)?" id="rec-\d+"><div class="card-head"><span class="pill (\w+)">'
                       r'([^<]+)</span> <span class="tag rid">(P-\d+)</span>', page)
    assert [(q == " quiet", rid) for q, _, _, rid in cards] == [
        (want[rid]["status"] in plan_mod.WAITING_STATUSES, rid) for rid in want]
    assert {rid for q, _, _, rid in cards if q} == {"P-12", "P-13", "P-14"}


def test_verify_md_opens_each_row_with_its_status(run):
    md = verify.render(run["report"], run["plan"])
    for c in run["plan"]["changes"]:
        m = re.search(r"#### %s [^\n]*\n\nStatus: ([^\n]+)\n" % c["id"], md)
        assert m and m.group(1).startswith(c["status_text"]), c["id"]
    assert re.search(r"#### P-10 [^\n]*\n\nStatus: find its DNS host first\.\n", md)
    assert re.search(r"#### P-09 [^\n]*\n\nStatus: after 2 checks - corp\.example publishes example\.net\._report", md)


def test_a_first_run_with_a_report_address_has_its_record_ready_now(tmp_path):
    run = F.first_run(tmp_path, F.FR_RUA)
    row = {c["id"]: c for c in run["plan"]["changes"]}
    assert (row["P-01"]["kind"], row["P-01"]["status"], row["P-01"]["status_text"]) == ("modify", "now", "ready now")
    assert "approval to publish the 1 zero-risk record (plan P-01) in the next DNS change window" in run["doc"]["ask"]
    todo = collect.render_todo(run["report"], run["plan"])
    do_now = todo.split("## 2. Do now", 1)[1].split("\n## ", 1)[0]
    assert [l.split()[1] for l in do_now.splitlines() if l.startswith("- P-")] == ["P-01"]
    assert run["doc"]["one_liner"].endswith("The next safe step is to add rua reporting to the DMARC record, and it is "
                                            "ready now.")


def test_an_older_plan_without_statuses_is_never_read_as_ready_on_a_guess():
    # a row plan.py wrote before it set statuses: computed from the row alone
    assert plan_mod.status_of({"priority": 3, "zone_host": "Route53", "prerequisites": []})[0] == "gated"
    assert plan_mod.status_of({"priority": 1, "zone_host": "unknown", "prerequisites": []})[0] == "host"
    assert plan_mod.status_of({"priority": 1, "prerequisites": []})[0] == "now"  # no host recorded: none looked up
    assert plan_mod.status_of({"priority": 1, "prerequisites": ["verified unused: nothing sent"]})[0] == "now"
    assert plan_mod.status_of({"priority": 1, "prerequisites": ["verify unused first: x"]})[:2] == ("check", "after 1 check")
    assert plan_mod.status_of({"priority": 1, "value": "v=DMARC1; p=none; rua=%s;" % plan_mod.RUA_PLACEHOLDER})[0] == \
        "address"
    # a plan without an inventory looked up no DNS host: an unknown one is no status of its own
    rep = F.T.apex_report("v=DMARC1; p=none; rua=%s;" % F.RUA)
    assert all(c["status"] != "host" for c in plan_mod.build_plan(rep, None, F.RUA)["changes"])
