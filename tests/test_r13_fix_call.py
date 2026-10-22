"""Round 13 review fixes: Your call, the band's answer to "what do you need from me".

A DNS-window reader, a weekly reader and leadership each need the call to say which records go out now - by id,
each with its host name as its zone's console wants it, up to eight named - and what every other row waits on, by
id: the groups one check clears first (a report-authorization record, the domain's unused check, a lookup), then
the rows' own checks, then the steps past monitoring, never "other checks". The plan's holds say which domains, and
one or two say what they decide. The headline never reads as an ask when nothing can be approved; an empty plan
says nothing needs the reader. The terminal and Slack carry the call in plain words, ids included, and the ask
counts the same rows the call counts. Synthetic data, offline."""

import re

import pytest

import brief
import next_steps
import notify
import r13_fixtures as F


@pytest.fixture(scope="module")
def weekly(tmp_path_factory):
    return F.weekly(tmp_path_factory.mktemp("r13_fix_call_weekly"))


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_fix_call_estate"))


def test_the_weekly_call_names_the_rows_ready_now_with_their_host_names(weekly):
    top = weekly["doc"]["top"]
    call = top["call"]
    now = [c["id"] for c in weekly["plan"]["changes"] if c["status"] == "now"]
    assert call["now"] == now == ["P-08", "P-10", "P-11", "P-14"]
    # every one named, each with its host name relative to its zone, more than three of them
    assert call["text"].startswith("Approve 4 DNS records with no mail impact - ready now in corp.example: P-08 "
                                   "_dmarc.alerts, P-10 _dmarc.careers, P-11 _dmarc.events, P-14 _dmarc.mkt; ")
    assert ["host", "_dmarc.alerts"] in call["parts"] and ["name", "corp.example"] in call["parts"]
    # the terminal and Slack: the ids, plain, on a line of their own
    line = "Your call: approve P-08, P-10, P-11, P-14 (ready now, no mail impact); "
    assert any(l.startswith(line) for l in top["lines_plain"])
    summary = notify.summarize(weekly["report"], plan=weekly["plan"], top=top)
    assert any(l.startswith(line) for l in summary.splitlines())
    # the page shows each host name beside its tag, in mono: no hover needed, on a phone or on paper
    band = brief.now_section(weekly["doc"], weekly["plan"], "corp.example")
    assert '<span class="mono"><span class="d">_dmarc.alerts</span></span>' in band


def test_the_one_record_that_unblocks_a_group_is_named_before_their_own_checks(weekly):
    call = weekly["doc"]["top"]["call"]
    text = call["text"]
    assert "5 after one report-authorization record at corp.example (P-01 to P-05)" in text
    assert "2 after the domain's unused check (P-06, P-07)" in text
    assert text.index("report-authorization") < text.index("unused check") < text.index("after their own checks")
    assert "other checks" not in text
    assert [g["words"] for g in call["groups"]] == [
        "one report-authorization record at corp.example", "the domain's unused check", "their own checks",
        "policy steps"]


def test_every_waiting_group_names_its_ids_when_the_band_has_room(estate, weekly):
    # the estate's band fits whole: every group with its ids, runs as ranges
    text = estate["doc"]["top"]["call"]["text"]
    assert text == (
        "Nothing can go out unchecked; 6 after one report-authorization record at corp.example (P-03 to P-07, P-09); 3 "
        "after their own checks (P-01, P-02, P-08); 2 need their DNS host found first (P-10, P-11); 3 not this week "
        "(P-12 to P-14); decide 1 plan hold (example.com: sending subdomains need records of their own before sp= "
        "moves).")
    # at full detail every row of the weekly plan is named in the call, a run of three or more as a range
    pp = next_steps.plan_parts(weekly["plan"])
    text = next_steps._call(weekly["plan"], pp, weekly["report"])["text"]
    ids = [c["id"] for c in weekly["plan"]["changes"]]
    covered = set(re.findall(r"P-\d+", text))
    for first, last in re.findall(r"(P-\d+) to (P-\d+)", text):
        covered |= {i for i in ids if first <= i <= last}
    assert covered == set(ids)
    assert "12 not this week (P-20, P-22 to P-28, P-30 to P-33)" in text
    assert "4 need their DNS host found first (P-16 to P-19)" in text


def test_more_than_eight_ready_rows_are_named_eight_and_counted(tmp_path):
    rows = [{"id": "P-%02d" % i, "domain": "s%d.example.com" % i, "kind": "new", "priority": 1, "zone": "example.com",
             "hostname": "_dmarc.s%d.example.com" % i, "value": "v=DMARC1; p=none;", "zone_host": "Route53",
             "prerequisites": [], "status": "now", "status_text": "ready now", "status_reason": ""}
            for i in range(1, 11)]
    rows.append(dict(rows[0], id="P-11", domain="example.com", hostname="example.com", value="v=spf1 -all"))
    call = next_steps.build_top({"gate": {"domains": {}}, "dns": {"example.com": {}}},
                                {"changes": rows, "holds": []}, {})["call"]
    assert call["text"].startswith("Approve 11 DNS records with no mail impact - ready now in example.com: P-01 "
                                   "_dmarc.s1, P-02 _dmarc.s2, ")
    assert "P-08 _dmarc.s8 and 3 more." in call["text"] and "P-09" not in call["text"]
    assert call["plain"] == "approve P-01, P-02, P-03, P-04, P-05, P-06, P-07, P-08 and 3 more (ready now, no mail impact)"
    # the zone's own name is '@' in its console, and a row with no zone keeps its full host name
    assert next_steps.relative_host({"hostname": "example.com", "zone": "example.com"}) == "@"
    assert next_steps.relative_host({"hostname": "_dmarc.a.example.com", "zone": "a.example.com"}) == "_dmarc"
    assert next_steps.relative_host({"hostname": "_dmarc.example.org"}) == "_dmarc.example.org"
    assert next_steps.relative_host({"hostname": "_dmarc.example.org", "zone": "example.com"}) == "_dmarc.example.org"


def test_the_plan_holds_say_which_domains_and_what_they_decide(tmp_path):
    run = F.estate(tmp_path, two_records=True)
    call = run["doc"]["top"]["call"]
    assert call["text"].endswith(
        "decide 2 plan holds (example.com: sending subdomains need records of their own before sp= moves, and "
        "example.net: two DMARC records at _dmarc.example.net).")
    assert call["plain"].endswith("decide 2 plan holds (example.com and example.net)")
    # three holds: the domains alone
    plan = dict(run["plan"], holds=run["plan"]["holds"] + [{"domain": "brand.example", "reason": "x - y"}])
    text = next_steps._call(plan, next_steps.plan_parts(plan), run["report"])["text"]
    assert text.endswith("decide 3 plan holds (example.com, example.net and brand.example).")


def test_the_headline_never_reads_as_an_ask_when_nothing_can_be_approved(estate, tmp_path):
    assert estate["doc"]["top"]["headline"].endswith("Your call: nothing to approve yet - 9 DNS records wait on checks.")
    # an empty plan: nothing needs the reader, and nothing is said to be held
    docs = {"example.com": F.T.own_record("example.com", "v=DMARC1; p=reject; rua=%s;" % F.RUA)}
    rep = F.T.audited(tmp_path / "clean", docs, F.T.Log().add("staff@example.com", "Weekly #", times=10))
    top = next_steps.build(rep, plan={"changes": [], "holds": []})["top"]
    assert top["call"]["text"] == "Nothing needs you this week: the plan has no rows."
    assert "unchecked" not in top["call"]["text"] and top["headline"].endswith("Your call: nothing needs you this week.")
    assert "Your call: nothing needs you this week: the plan has no rows." in top["lines_plain"]


def test_the_ask_counts_the_rows_the_call_counts(weekly):
    doc = weekly["doc"]
    ap = doc["ask_parts"]
    rows = [c["id"] for c in weekly["plan"]["changes"]]
    # the steps past monitoring that wait on their checks are a list of their own
    steps = [c["id"] for c in weekly["plan"]["changes"] if c["priority"] >= 2 and c["status"] == "check"]
    assert ap["steps"] == steps == ["P-21", "P-29"] and ap["steps_words"] == "policy steps"
    asked = (ap["address"] + ap["now"] + [i for g in ap["groups"] for i in g["ids"]] + ap["quiet"] + ap["steps"]
             + ap["host"] + [i for g in ap["later"] for i in g["ids"]])
    assert sorted(asked) == sorted(rows) and len(asked) == len(set(asked))
    call = doc["top"]["call"]
    in_call = call["now"] + [i for g in call["groups"] for i in g["ids"]]
    assert len(in_call) + call["host"] + call["later"] == len(rows)
    # the ask's sentence counts them too: 8 after their checks = 2 unused + 4 quiet + 2 policy steps
    assert "8 more after their checks" in doc["ask"]
    parts = next_steps.ask_text(ap, doc["org_domain"], doc["next_step"], 4)[0]
    assert "2 policy steps once their checks are confirmed" in parts
