"""Round 13, T-05 (and T-06, below): one status per plan row, used everywhere.

plan.py computes each row's status once (status, status_text, status_reason: address, host, held,
gated, later, check, now - the first that applies), and every file that lays the plan out reads it:
the ask and the owners' line say "zero-risk" and "ready" only for a row that is ready now, todo.md's
Do now lists only those, the cards and At a glance carry the status as a pill, and verify.md opens
each row's section with it. T-11: the ask is built from short lists (next_steps.json ask_parts), at most 60
words, each id named once, the change window and approver at its end when audit.toml sets them; brief.html lays
the lists out (publish now, after a check, not this week). Synthetic data, offline."""

import re

import pytest

import brief
import collect
import config
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
    # round 13, T-11: under 60 words, by what each group of rows waits on; every id in the ask's lists
    assert ("approval to publish 6 records (P-03, P-04, P-05 and 3 more) once corp.example publishes one "
            "report-authorization record") in ask
    assert "3 domains that send no mail moved to quarantine once their checks are confirmed" in ask
    assert "2 records once their DNS host is found" in ask
    parts = run["doc"]["ask_parts"]
    assert parts["groups"][0]["ids"] == ["P-03", "P-04", "P-05", "P-06", "P-07", "P-09"]
    assert parts["quiet"] == ["P-01", "P-02", "P-08"] and parts["host"] == ["P-10", "P-11"]
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
    assert "approval to move" not in doc["ask"] and "moved to quarantine" not in doc["ask"]
    # round 13, T-11: counted with the rows not for this week, by their status words in the ask's lists
    assert {"words": "held (Per domain says why)", "ids": ["P-01", "P-02", "P-08"]} in doc["ask_parts"]["later"]
    assert "6 not this week" in doc["ask"]
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


# ------------------------------------------------------------------ T-06: the placeholder report address


@pytest.fixture(scope="module")
def first(tmp_path_factory):
    return F.first_run(tmp_path_factory.mktemp("r13_first_run"))  # no report mailbox, no --rua-address


def test_the_rows_that_carry_the_placeholder_need_the_report_address(first):
    plan = first["plan"]
    assert plan["rua_is_placeholder"]
    st = {c["id"]: (c["status"], c["status_text"]) for c in plan["changes"]}
    assert [i for i, (s, _) in st.items() if s == "address"] == ["P-01", "P-02", "P-04"]
    assert all(t == "needs the report address" for s, t in st.values() if s == "address")
    assert st["P-03"] == ("check", "after 1 check")  # v=spf1 -all carries no address: it waits on its unused check
    md = plan_mod.render_md(plan).splitlines()
    assert md[4].startswith("**Choose where DMARC reports go first.**") and "`--rua-address mailto:...`" in md[4]
    assert "set RUA_MAILBOX in .env" in md[4]
    assert "Re-run with `--rua mailto:...`" not in "\n".join(md)


def test_the_first_step_is_choosing_where_reports_go_never_ready_now(first):
    doc = first["doc"]
    assert doc["next_step"]["kind"] == "address" and doc["next_step"]["label"] == next_steps.ADDRESS_STEP
    assert doc["next_step"]["placeholder_ids"] == ["P-01", "P-02", "P-04"]
    assert doc["one_liner"].endswith(
        "The first step is to choose where DMARC reports go, then rerun with --rua-address mailto:<that address> (a "
        "mailbox you own, or a reporting service; RUA_MAILBOX in .env does the same): until then 3 records carry a "
        "placeholder report address (plan P-01, P-02, P-04) and none is ready.")
    assert "ready now" not in doc["one_liner"] and "ready when" not in doc["one_liner"]
    md = next_steps.render_md(doc)
    assert "choose where DMARC reports go" in md
    assert doc["ask"].startswith(
        "The ask this week: first, choose where DMARC reports go (a mailbox you own, or a reporting service), then "
        "rerun with --rua-address mailto:<that address> (or set RUA_MAILBOX in .env); until then 3 records carry a "
        "placeholder report address (plan P-01, P-02, P-04) and none is ready")
    assert "zero-risk" not in doc["ask"] and "ready now" not in doc["ask"]
    # todo.md has nothing to do now; the placeholder rows wait, and say on what
    todo = collect.render_todo(first["report"], first["plan"])
    assert todo.split("## 2. Do now", 1)[1].split("\n## ", 1)[0].strip().endswith("- none")
    waiting = todo.split("## 2c. Waiting", 1)[1].split("\n## ", 1)[0]
    assert waiting.count("  - status: needs the report address") == 3
    # the brief's note says the same, with collect.py's own option
    page = brief.render(doc, first["plan"])
    assert ("<strong>Choose where DMARC reports go first.</strong> No existing record carried a rua, so the new records "
            "here carry the placeholder") in page
    assert "then rerun collect.py with <code>--rua-address mailto:...</code> (or set RUA_MAILBOX in .env)" in page
    text = notify.summarize(first["report"], plan=first["plan"])
    assert "3 need the report address first" in text and "zero-risk" not in text


def test_the_documents_placeholder_is_the_plans():
    assert next_steps.PLACEHOLDER == plan_mod.RUA_PLACEHOLDER


def test_collect_refuses_a_report_address_given_to_rua_before_anything_runs(tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(collect.graph_client, "creds", lambda *a, **k: calls.append("creds"))
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: calls.append("setup") or [])
    out = tmp_path / "out"
    monkeypatch.setattr("sys.argv", ["collect.py", "--no-config", "--env-file", str(tmp_path / "none.env"),
                                     "--out", str(out), "--rua", "mailto:a@b.example"])
    with pytest.raises(SystemExit) as exc:
        collect.main()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--rua takes report files or folders; did you mean --rua-address mailto:a@b.example?" in err
    assert calls == [] and not out.exists()  # no tenant call, and no history folder for a run that never ran
    # the same with the address among report paths, and spelled in capitals
    monkeypatch.setattr("sys.argv", ["collect.py", "--no-config", "--env-file", str(tmp_path / "none.env"),
                                     "--out", str(out), "--rua", "samples/rua", "MAILTO:a@b.example"])
    with pytest.raises(SystemExit) as exc:
        collect.main()
    assert exc.value.code == 2 and "did you mean --rua-address MAILTO:a@b.example?" in capsys.readouterr().err
    assert calls == [] and not out.exists()


# ------------------------------------------------------------------ T-11: the ask as short lists

def test_t11_the_estates_ask_is_short_and_names_each_id_once(run):
    ask = run["doc"]["ask"]
    assert len(ask.split()) <= next_steps.ASK_WORDS == 60
    ids = re.findall(r"\bP-\d{2}\b", ask)
    assert ids and len(ids) == len(set(ids))
    assert ask == ("The ask this week: approval to publish 6 records (P-03, P-04, P-05 and 3 more) once corp.example "
                   "publishes one report-authorization record; 3 domains that send no mail moved to quarantine once "
                   "their checks are confirmed; 2 records once their DNS host is found; 3 not this week; and a decision "
                   "on 1 plan hold.")
    # the lists it is built from hold every row once, by when it can go out
    parts = run["doc"]["ask_parts"]
    assert parts["lines"] == {"now": [], "check": ["P-01", "P-02", "P-03", "P-04", "P-05", "P-06", "P-07", "P-08",
                                                   "P-09", "P-10", "P-11"], "later": ["P-12", "P-13", "P-14"]}
    assert parts["later"] == [{"words": "the gate says not yet", "ids": ["P-12", "P-13", "P-14"]}]
    assert parts["holds"] == [{"domain": "example.com", "text": next_steps._hold_summary(run["plan"]["holds"][0]["reason"])}]
    assert (parts["window"], parts["approver"]) == (None, None)
    # a small plan keeps the full words: what each row waits on, the step after it and the hold's own words
    doc = next_steps.build(run["report"], plan=dict(run["plan"], changes=[F.row(run["plan"], "P-09")]),
                           org_name="example.net")
    assert doc["ask"].startswith("The ask this week: approval to publish 1 record (plan P-09) once corp.example "
                                 "publishes one report-authorization record")
    assert "a decision on example.com: publish the monitoring records for e.example.com" in doc["ask"]


def test_t11_the_change_window_and_approver_end_the_ask_and_the_call(run):
    window = {"change_window": "Thursday 18:00-20:00 UTC"}
    doc = next_steps.build(run["report"], plan=run["plan"], date=F.ESTATE_DATE, org_name="example.com",
                           settings=window)
    assert doc["ask"].endswith(" - window: Thursday 18:00-20:00 UTC.")
    assert doc["top"]["call"]["text"].endswith(" - window: Thursday 18:00-20:00 UTC.")
    assert doc["ask_parts"]["window"] == "Thursday 18:00-20:00 UTC" and len(doc["ask"].split()) <= 66
    both = next_steps.build(run["report"], plan=run["plan"], org_name="example.com",
                            settings=dict(window, approver="IT change board"))
    assert both["ask"].endswith(" - window: Thursday 18:00-20:00 UTC; approver: IT change board.")
    assert both["top"]["call"]["text"].endswith(" - window: Thursday 18:00-20:00 UTC; approver: IT change board.")
    # without them, no window words anywhere
    plain = run["doc"]
    assert "window:" not in plain["ask"] and "window:" not in plain["top"]["call"]["text"]
    assert "approver" not in plain["ask"]
    # audit.toml's [brief] table, read as written, each key optional
    assert config.brief_settings({"brief": {"change_window": "  Thursday   18:00 "}}) == {
        "change_window": "Thursday 18:00", "approver": None}
    assert config.brief_settings({}) == {"change_window": None, "approver": None}
    for bad in ({"brief": "x"}, {"brief": {"window": "Thursday"}}, {"brief": {"approver": 7}}):
        with pytest.raises(config.ConfigError):
            config.brief_settings(bad)


def test_t11_the_brief_lays_the_ask_out_as_three_lists(run):
    page = brief.render(run["doc"], run["plan"])
    ask = page[page.index('<section id="ask"'):]
    ask = ask[:ask.index("</section>")]
    labels = re.findall(r"<dt>([^<]+)</dt>", ask)
    assert labels == ["Publish now", "After a check", "Not this week"]
    publish, after, later = re.findall(r"<dd>(.*?)</dd>", ask)
    assert publish == '<span class="muted">none</span>'
    # each id a tag linked to its card, with its host name beside it
    places = brief.card_places(run["plan"], "example.com")
    assert re.findall(r'<a class="tag" href="#rec-(\d+)"[^>]*>(P-\d+)</a>', later) == [
        (str(places[i]), i) for i in ("P-12", "P-13", "P-14")]
    assert '<a class="tag" href="#rec-%d" title="_dmarc.example.org">P-01</a>' % places["P-01"] in after
    assert "_dmarc.parked.example" in after and after.count('class="idhost"') == 11
    assert "<p>%s</p>" % brief.prose(run["doc"]["ask"]) in ask  # the sentence under the lists
