"""Round 13: the status band's data (next_steps.json "top").

T-09, here first: say what the run cannot see. next_steps.top_gaps is the band's "Not in this data" (top.gaps,
top.evidence_through, top.stale): at most two data gaps, the rest counted, and always last the scope line -
bounces and lost mail are in no file this toolkit reads. Where we stand says when the passing copy of a message
went only to an on-premises or external hop, and verify.md gives a message-trace lookup per own sender that
fails.

T-01: next_steps.build_top - the band itself: Protected?, the most critical organizations worst first (tiers,
counts, the line's words), the reader's call, what changed, and the plain lines the terminal and Slack print; every
figure in it is in the run's files, and the same inputs give the same band. T-03: next_steps.md leads with it, the
one-liner under The next step, the sources last. Synthetic data, offline."""

import json
import re
import sys
from pathlib import Path

import pytest

import audit
import next_steps
import r13_fixtures as F
import verify

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_doc  # noqa: E402

SCOPE = "bounces and lost mail (NDRs): use message trace"


@pytest.fixture(scope="module")
def incident(tmp_path_factory):
    return F.incident(tmp_path_factory.mktemp("r13_top_incident"))


def test_the_incident_says_its_relayed_copies_need_message_trace(incident):
    gaps = next_steps.top_gaps(incident["report"])
    assert "36 messages passed but went only to an on-premises or external hop: check message trace" in gaps["gaps"]
    assert gaps["gaps"][-1] == SCOPE == next_steps.SCOPE_GAP
    assert gaps["evidence_through"] == "2026-10-07" and gaps["stale"] is None
    md = next_steps.render_md(incident["doc"])
    assert "not broken senders" not in md
    assert ("**Genuine failures: 117** (raw counts would say 153 - the gap is failing copies of messages that also had a "
            "passing copy; 36 of those passing copies went only to an on-premises or external hop - check message "
            "trace)") in md
    assert incident["doc"]["stand"]["relayed_only"] == 36


def test_verify_md_gives_each_failing_own_sender_a_message_trace(incident):
    md = verify.render(incident["report"], incident["plan"])
    assert ("Get-MessageTraceV2 -SenderAddress 'hr@example.com' -StartDate 2026-10-07T06:00:00Z -EndDate "
            "2026-10-09T06:00:00Z -Status Failed") in md
    assert md.count("Get-MessageTraceV2") == 1  # our own system only: never a spoofed address
    assert "message trace for hr@example.com, our own system, 65 of whose messages failed with no passing copy" in md


def echo_log(where):
    """Ten messages that passed, each with a failing copy (a relay echo), delivered to an inbox or only to an
    on-premises hop; and two failing ones."""
    log = F.O.Log(overrides=True).add("staff@example.com", "Weekly #", 20)
    start = len(log.rows)
    log.add("app@example.com", "Notice #", 10, env="example.com", where=where)
    for row in log.rows[start:start + 10]:
        echo = list(row)
        echo[9:12] = ["fail", "fail", "fail"]
        log.rows.append(echo)
    return log.add("app@example.com", "Notice #", 2, env="example.com", dmarc="fail")


def test_a_run_with_no_relayed_copies_keeps_the_echo_sentence(tmp_path):
    docs = {"example.com": F.T.own_record("example.com")}
    rep = F.T.audited(tmp_path / "inbox", docs, echo_log(F.O.INBOX))
    assert rep["maillog"]["counters"]["relayed_only"] == 0
    line = next_steps.build(rep)["stand"]["lines"][0]
    assert "(raw counts would say 12 - the gap is relay echoes, not broken senders)" in line
    assert "check message trace" not in line
    assert not any("on-premises" in g for g in next_steps.top_gaps(rep)["gaps"])
    # the same echoes with their passing copy routed out: the sentence says so instead
    rep = F.T.audited(tmp_path / "onprem", docs, echo_log(F.ON_PREM))
    assert rep["maillog"]["counters"]["relayed_only"] == 10
    line = next_steps.build(rep)["stand"]["lines"][0]
    assert "not broken senders" not in line and "10 of those passing copies went only to an on-premises" in line


def mixed_log():
    """Four echoes whose passing copy went only to an on-premises hop, six single passing copies that went the same
    way, three failing messages that did too, and two failing ones delivered to an inbox."""
    log = echo_log(F.ON_PREM)
    log.rows = log.rows[:20]  # the staff mail only
    start = len(log.rows)
    log.add("app@example.com", "Notice #", 4, env="example.com", where=F.ON_PREM)
    for row in log.rows[start:start + 4]:
        echo = list(row)
        echo[9:12] = ["fail", "fail", "fail"]
        log.rows.append(echo)
    log.add("relay@example.com", "Digest #", 6, env="example.com", where=F.ON_PREM)
    log.add("app@example.com", "Notice #", 3, env="example.com", where=F.ON_PREM, dmarc="fail")
    return log.add("app@example.com", "Notice #", 2, env="example.com", dmarc="fail")


def test_each_kind_of_relayed_message_is_said_as_what_it_is(tmp_path):
    rep = F.T.audited(tmp_path, {"example.com": F.T.own_record("example.com")}, mixed_log())
    c = rep["maillog"]["counters"]
    assert (c["relayed_only"], c["relayed_only_passed"], c["relayed_only_echo"]) == (13, 10, 4)
    assert (c["genuine_failures"], c["raw_failing_rows"]) == (5, 9)
    line = next_steps.build(rep)["stand"]["lines"][0]
    # the echoes' passing copies inside the gap's clause, the single passing copies at the line's end, and the
    # failing ones relayed out are failures already: never said to have passed
    assert line.startswith("**Genuine failures: 5** (raw counts would say 9 - the gap is failing copies of messages "
                           "that also had a passing copy; 4 of those passing copies went only to an on-premises or "
                           "external hop - check message trace), over ")
    assert line.endswith("; 6 more messages passed but went only to an on-premises or external hop: check message "
                         "trace")
    assert "not broken senders" not in line
    gaps = next_steps.top_gaps(rep)["gaps"]
    assert "10 messages passed but went only to an on-premises or external hop: check message trace" in gaps
    # an older report counts them without saying which passed: how many went that way, never that they passed
    for key in ("relayed_only_passed", "relayed_only_echo"):
        del c[key]
    line = next_steps.build(rep)["stand"]["lines"][0]
    assert "(raw counts would say 9 - the gap is failing copies of messages that also had a passing copy), over " in line
    assert line.endswith("; 13 messages went only to an on-premises or external hop: check message trace")
    assert "passed but" not in line and "not broken senders" not in line
    assert next_steps.top_gaps(rep)["data_gaps"] == [
        "no aggregate reports: what outside receivers see is not in this run",
        "13 messages went only to an on-premises or external hop: check message trace"]
    # its verdicts, when it kept them, say it message by message
    rep = F.T.audited(tmp_path / "kept", {"example.com": F.T.own_record("example.com")}, mixed_log(),
                      keep_verdicts=True)
    for key in ("relayed_only", "relayed_only_passed", "relayed_only_echo"):
        del rep["maillog"]["counters"][key]
    assert next_steps.relayed_counts(rep["maillog"]) == {"relayed_only": 13, "relayed_only_passed": 10,
                                                         "relayed_only_echo": 4}
    # only failing messages went that way: they are failures, so nothing is said to have passed
    log = F.O.Log(overrides=True).add("staff@example.com", "Weekly #", 20)
    log.add("app@example.com", "Notice #", 3, env="example.com", where=F.ON_PREM, dmarc="fail")
    rep = F.T.audited(tmp_path / "failing", {"example.com": F.T.own_record("example.com")}, log)
    c = rep["maillog"]["counters"]
    assert (c["relayed_only"], c["relayed_only_passed"], c["relayed_only_echo"]) == (3, 0, 0)
    assert "passed but" not in next_steps.build(rep)["stand"]["lines"][0]
    assert next_steps.top_gaps(rep)["data_gaps"] == ["no aggregate reports: what outside receivers see is not in this run"]


def test_message_trace_is_for_our_own_failing_senders_only(incident, tmp_path):
    rep = incident["report"]
    # hr@example.com fails 65 as our own system and 12 more spoofed through another envelope: the trace counts its own
    rows = [r for r in rep["maillog"]["census"]["by_sender"] if r["sender"] == "hr@example.com" and r["genuine_failures"]]
    assert sorted(r["genuine_failures"] for r in rows) == [12, 65]
    steps = verify.message_trace_steps(rep, "example.com")
    assert [s["code"].split()[2] for s in steps] == ["'hr@example.com'"]
    assert "65 of whose messages failed with no passing copy" in steps[0]["text"]
    # example.net's newsletter fails through an outside envelope (called spoofing on a weak sign) and the payroll
    # vendor the same: not ours to trace until someone says they are
    assert verify.message_trace_steps(rep, "example.net") == []
    assert verify.message_trace_steps(rep, "parked.example") == []
    # a sender under an unaudited subdomain is traced in its parent's section; an address that is not one, never
    log = (F.O.Log(overrides=True).add("staff@example.com", "Weekly #", 20)
           .add("alerts@ops.example.com", "Status report #", 5, env="ops.example.com", dmarc="fail")
           .add("odd name@example.com", "Status report #", 5, env="example.com", dmarc="fail"))
    rep = F.T.audited(tmp_path, {"example.com": F.T.own_record("example.com")}, log)
    codes = [s["code"] for s in verify.message_trace_steps(rep, "example.com")]
    assert codes == ["Get-MessageTraceV2 -SenderAddress 'alerts@ops.example.com' -StartDate 2026-10-07T06:00:00Z "
                     "-EndDate 2026-10-09T06:00:00Z -Status Failed"]
    # no usable run time: no window to give, so no step
    assert verify.message_trace_steps(dict(rep, generated_utc="not a time"), "example.com") == []
    # more own senders than a section gives steps: the busiest first, in the one rank, and the rest named, never dropped
    log = F.O.Log(overrides=True).add("staff@example.com", "Weekly #", 20)
    for k, name in enumerate(("e", "d", "c", "b", "a")):
        log.add("%s@example.com" % name, "Status report #", 2 + k, env="example.com", dmarc="fail")
    rep = F.T.audited(tmp_path / "five", {"example.com": F.T.own_record("example.com")}, log)
    steps = verify.message_trace_steps(rep, "example.com")
    assert [s["code"].split()[2] for s in steps] == ["'a@example.com'", "'b@example.com'", "'c@example.com'"]
    assert steps[-1]["text"].endswith(" 2 more of our own senders fail here (d@example.com, e@example.com): the same "
                                      "lookup with each address.")


def test_the_gaps_run_in_their_order_two_shown_and_the_scope_line_last():
    rep = {"generated_utc": "2026-10-20T06:00:00Z", "dns": None, "maillog": None,
           "rua": {"totals": {"end_date": "2026-09-02"}}}
    g = next_steps.top_gaps(rep)
    assert g["data_gaps"] == [
        "offline run: DNS not read, so policies come from the aggregate reports or are unknown",
        "no mail log: our own senders are not checked",
        "the newest evidence is from 2026-09-02, 48 days before this run"]
    assert g["gaps"] == g["data_gaps"][:2] + ["(+1 more under Where we stand)", SCOPE]
    assert (g["evidence_through"], g["stale"]) == ("2026-09-02", 48)
    # exactly seven days old is not stale yet; a report with no dates says nothing about age
    rep["rua"]["totals"]["end_date"] = "2026-10-13"
    assert next_steps.top_gaps(rep)["stale"] is None
    assert next_steps.top_gaps({"dns": {"example.com": {}}, "maillog": {}, "rua": {}}) == {
        "gaps": [SCOPE], "evidence_through": None, "stale": None, "data_gaps": []}


def test_cut_organizations_are_one_clause_and_a_failed_pull_its_own():
    rep = {"generated_utc": "2026-10-20T06:00:00Z", "dns": {"corp.example": {}},
           "rua": {"totals": {"end_date": "2026-10-19"}},
           "maillog": {"window": {"to": "2026-10-20T05:00:00Z"}, "counters": {},
                       "cuts": {"corp-brand.example": {"reason": "row budget", "kept_hours": 627},
                                "corp.example": {"reason": "row budget", "kept_hours": 241},
                                "corp.co.uk": {"reason": "not pulled", "error": "HTTP 503"}},
                       "window_totals": {"hours": 720, "orgs": {
                           "corp.example": {"by_domain": {"corp.example": {"genuine_failures": 202}}},
                           "corp-brand.example": {"by_domain": {"corp-brand.example": {"genuine_failures": 157}}}}}}}
    g = next_steps.top_gaps(rep, "corp.example")
    assert g["data_gaps"] == [
        "mail log for corp.co.uk not read this run (its pull failed): its senders are not checked",
        "corp.example and corp-brand.example: the row budget kept only the newest 241 and 627 hours, so their counts "
        "are floors (359 genuine failures over the full window)"]
    assert g["gaps"][-1] == SCOPE and len(g["gaps"]) == 3
    assert g["evidence_through"] == "2026-10-20" and g["stale"] is None
    # one cut organization: its counts
    del rep["maillog"]["cuts"]["corp-brand.example"], rep["maillog"]["cuts"]["corp.co.uk"]
    assert re.match(r"^corp\.example: the row budget kept only the newest 241 hours, so its counts are floors",
                    next_steps.top_gaps(rep)["data_gaps"][0])


# ------------------------------------------------------------------ T-01: the band, next_steps.json "top"

@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_top_estate"))


@pytest.fixture(scope="module")
def stress(tmp_path_factory):
    return F.stress(tmp_path_factory.mktemp("r13_top_stress"))


@pytest.fixture(scope="module")
def first(tmp_path_factory):
    return F.first_run(tmp_path_factory.mktemp("r13_top_first"))


def strip(top):
    return [(e["org"], e["tier"]) for e in top["domains"]]


def test_t01_the_estate_names_its_organizations_worst_first(estate):
    top = estate["doc"]["top"]
    assert strip(top) == [("example.com", 1), ("brand.example", 1), ("example.net", 6), ("example.org", 6),
                          ("parked.example", 6)]
    assert top["headline"] == ("Partly: 2 of 9 domains block spoofed mail. Urgent: spoofed mail reached inboxes on "
                               "example.com and brand.example. Your call: 9 DNS records wait on a check.")
    assert top["protected"] == {"word": "partly", "total": 9, "protected": 2, "source": "dns",
                                "counts": {"reject": 1, "quarantine": 1, "none": 5, "absent": 2},
                                "text": "Partly: 2 of 9 domains refuse or junk spoofed mail; 5 only report (p=none), 2 "
                                        "have no DMARC record."}
    com, brand, net, org, parked = top["domains"]
    # a delivered lure: the address, its subject quoted as the sender's, and what the run cannot say
    assert next_steps.strip_line_md(com) == (
        "**URGENT - example.com** (+4 names below it that only report): Spoofed mail reached inboxes - 7 as "
        "ceo@example.com (the sender's subject: \"Urgent wire transfer 78\"). Do first: check who got them; find what "
        "let them in (the mail log does not say).")
    assert (com["badge"], com["pill"], com["count"], com["below"]) == (
        "urgent", "bad", 7, {"count": 4, "words": "+4 names below it that only report"})
    assert ["subject", "Urgent wire transfer 78"] in com["finding_parts"] and ["addr", "ceo@example.com"] in \
        com["finding_parts"]
    # under ten failures and no lure: a small failure, never a headline, never hidden
    assert next_steps.strip_line_md(net) == ("**Reports only - example.net**: Small failures only (6, under 10). Next: "
                                             "add our report address (P-09) - after 2 checks.")
    assert net["flags"] == ["small"] and net["ids"] == ["P-09"]
    assert next_steps.strip_line_md(parked) == (
        "**No record - parked.example**: Anyone can send as it; nothing sent or received in 30 days. Next: park it "
        "(P-10, P-11) - find its DNS host first.")
    assert org["action_plain"] == "quarantine now (P-01) - after 3 checks"
    assert top["call"]["text"] == (
        "Nothing can go out unchecked; 6 after one report-authorization record at corp.example (P-03, P-04, P-05 and 3 "
        "more); 3 after their own checks; 2 need their DNS host found first; 3 not this week; decide 1 plan hold.")
    assert top["call"]["groups"][0] == {"words": "one report-authorization record at corp.example",
                                        "ids": ["P-03", "P-04", "P-05", "P-06", "P-07", "P-09"]}
    assert (top["call"]["host"], top["call"]["later"], top["call"]["holds"]) == (2, 3, 1)
    assert top["changed"]["text"] == "First run: this is the baseline." and top["changed"]["since"] is None
    assert top["gaps"] == [SCOPE] and (top["orgs"], top["evidence_through"], top["stale"]) == (5, "2026-10-08", None)
    assert top["more"] is None and top["version"] == 1


def lure_log(n):
    return F.T.Log().add("staff@example.com", "Weekly #", times=20).add(
        "ceo@example.com", "Urgent wire #", dmarc="fail", times=n, env="evil.invalid")


def test_t01_a_delivered_lure_under_ten_is_urgent(tmp_path):
    rep = F.T.audited(tmp_path, {"example.com": F.T.own_record("example.com")}, lure_log(3))
    top = next_steps.build(rep)["top"]
    e = top["domains"][0]
    assert (e["tier"], e["count"], e["badge"], e["finding_plain"]) == (
        1, 3, "urgent", "spoofed mail reached inboxes - 3 messages")
    assert top["headline"] == ("Not yet: example.com does not block spoofed mail yet. Urgent: spoofed mail reached "
                               "inboxes on example.com. Your call: nothing to approve (no plan this run).")
    assert top["protected"]["text"] == "Not yet: example.com reports only, blocks nothing (p=none)."


def test_t01_a_weak_sign_spoof_is_never_urgent_and_never_named_as_spoofing(tmp_path):
    o = F.O
    log = (o.Log(overrides=True).add("staff@example.net", "Roster #", 20)
           .add("billing@example.net", "Invoice # is ready", 6, env="mailer.vendor.invalid", dmarc="fail")
           .add("ceo@example.net", "Urgent wire today #", 4, env="evil.invalid", where=o.QUARANTINED, dmarc="fail"))
    rep = F.T.audited(tmp_path / "small", {"example.net": F.T.own_record("example.net")}, log)
    labels = {r["sender"]: r["likely"] for r in rep["maillog"]["census"]["by_sender"] if r["genuine_failures"]}
    assert labels == {"billing@example.net": "likely_spoof", "ceo@example.net": "likely_spoof"}
    e = next_steps.build(rep)["top"]["domains"][0]
    # the lure nobody received: spoofing no policy stops (tier 4), counted without the weak-sign six
    assert (e["tier"], e["count"]) == (4, 4)
    line = next_steps.strip_line_md(e)
    assert "4 spoof-looking messages as it, and no policy stops them; small failures only (6, under 10)" in line
    assert "billing@" not in line and "ceo@" not in line
    # the weak-sign stream delivered, at ten or more: it could be our own vendor (tier 3), never urgent
    log = (o.Log(overrides=True).add("staff@example.net", "Roster #", 20)
           .add("billing@example.net", "Invoice # is ready", 12, env="mailer.vendor.invalid", dmarc="fail"))
    rep = F.T.audited(tmp_path / "vendor", {"example.net": F.T.own_record("example.net")}, log)
    top = next_steps.build(rep)["top"]
    e = top["domains"][0]
    assert (e["tier"], e["count"]) == (3, 12) and "urgent" not in top["headline"].lower()
    assert next_steps.strip_line_md(e) == (
        "**Reports only - example.net**: 12 failing messages could be our own vendors (billing@example.net via "
        "mailer.vendor.invalid). Do first: confirm who sends them before any policy step.")


def test_t01_a_cut_organization_counts_at_least_and_one_not_pulled_is_a_data_gap(incident):
    rep = json.loads(json.dumps(incident["report"]))
    rep["maillog"]["cuts"] = {"example.com": {"reason": "row budget", "kept_hours": 41}}
    top = next_steps.build(rep, plan=incident["plan"])["top"]
    e = top["domains"][0]
    assert (e["org"], e["tier"], e["flags"]) == ("example.com", 2, ["floor"])
    assert next_steps.strip_line_md(e).startswith(
        "**Junks spoofs - example.com**: At least 65 of our own messages fail DMARC and receivers junk them. Do first: "
        "DKIM-sign hr@example.com (owner: no owner yet); keep the transport rule that lets 27 in until it passes.")
    assert e["finding_plain"] == "at least 65 of our own messages fail DMARC and receivers junk them"
    assert "example.com: the row budget kept only the newest 41 hours, so its counts are floors" in top["gaps"]
    rep["maillog"]["cuts"]["example.net"] = {"reason": "not pulled", "error": "HTTP 500"}
    e = {x["org"]: x for x in next_steps.build(rep, plan=incident["plan"])["top"]["domains"]}["example.net"]
    assert e["tier"] == 5 and "not_pulled" in e["flags"]
    assert e["finding_plain"].startswith("mail log not read this run (its pull failed): its senders are not checked")


def test_t01_without_a_mail_log_nothing_is_said_to_be_passing(tmp_path):
    docs, _, reports, flows, sources, _ = F.estate_parts(tmp_path)
    rep = F.T.audited(tmp_path / "run", docs, None, reports, flows=flows, sources=sources)
    assert rep["maillog"] is None
    top = next_steps.build(rep)["top"]
    said = "\n".join(top["lines_md"] + top["lines_plain"]).lower()
    assert "nothing of ours failing" not in said and "small failures" not in said
    assert "no mail log: our own senders are not checked" in top["data_gaps"]
    lines = {e["org"]: e["finding_plain"] for e in top["domains"]}
    assert lines["brand.example"] == "our own senders not checked (no mail log)"
    # with no mail-log rows of its own, an organization's failing outside sources are its own mail failing
    assert lines["example.com"] == ("60 of our own messages fail DMARC at outside receivers (aggregate reports) and "
                                    "receivers junk them")


def test_t01_the_same_inputs_give_the_same_band(estate):
    rep, plan = estate["report"], estate["plan"]
    one = next_steps.build(rep, plan=plan, date=F.ESTATE_DATE, org_name="example.com")
    two = next_steps.build(json.loads(json.dumps(rep)), plan=json.loads(json.dumps(plan)), date=F.ESTATE_DATE,
                           org_name="example.com")
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
    assert one["top"] == estate["doc"]["top"]


def run_folder(run, tmp_path):
    """The run's files as check_doc reads them, and the band as a polished copy would quote it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "next_steps.json").write_text(json.dumps(run["doc"], indent=1), encoding="utf-8")
    (tmp_path / "plan.json").write_text(json.dumps(run["plan"], indent=1), encoding="utf-8")
    rep = dict(run["report"], findings=audit.flatten_findings(run["report"]))  # as collect.py writes it
    (tmp_path / "report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    top = run["doc"]["top"]
    (tmp_path / "top.md").write_text("**%s**\n\n%s\n" % (top["headline"], "\n".join(top["lines_md"])), encoding="utf-8")
    (tmp_path / "top.txt").write_text("\n".join(top["lines_plain"]) + "\n", encoding="utf-8")
    return tmp_path


def test_t01_every_figure_the_band_shows_is_in_the_runs_files(estate, incident, stress, first, tmp_path):
    for name, run in (("estate", estate), ("incident", incident), ("stress", stress), ("first", first)):
        folder = run_folder(run, tmp_path / name)
        for copy in ("top.md", "top.txt"):
            assert check_doc.main([str(folder / copy), "--run", str(folder)]) == 0, (name, copy)


def test_t01_the_plain_lines_carry_no_address_and_the_band_stays_short(estate, incident, stress, first):
    for run in (estate, incident, stress, first):
        top = run["doc"]["top"]
        assert "@" not in top["headline"] and not any("@" in line for line in top["lines_plain"])
        assert len(top["headline"].split()) <= next_steps.HEADLINE_WORDS
        for e in top["domains"]:  # a line's own words: its badge, organization and a quoted subject apart
            assert next_steps._band_words(e["finding_parts"] + e["action_parts"]) <= next_steps.LINE_WORDS, e["org"]
        assert sum(len(line.split()) for line in top["lines_md"]) <= 300
    # ten organizations: five named, the rest counted by what they are
    top = stress["doc"]["top"]
    assert top["orgs"] == 10 and len(top["domains"]) == next_steps.TOP_SHOW
    assert top["more"] == {"count": 5, "by_tier": {"unprotected": 5},
                           "text": "+5 more organizations (5 unprotected) - Per domain lists them"}
    assert top["lines_md"][7] == "  6. +5 more organizations (5 unprotected) - Per domain lists them"
    assert "  (+5 more organizations: Per domain lists them)" in top["lines_plain"]


def test_t01_protected_says_what_each_policy_does(tmp_path, estate):
    # offline, the policy from the aggregate reports: said so
    rep = F.T.audited(tmp_path / "one", {"example.com": F.T.own_record("example.com", F.ESTATE_APEX)}, lure_log(1))
    rep["gate"]["domains"]["example.com"]["policy_source"] = "aggregate reports (example.com, 1 report(s))"
    assert next_steps.build(rep)["top"]["protected"]["text"] == (
        "Protected (per the aggregate reports: DNS not read): example.com sends spoofed mail to junk (p=quarantine).")
    # every name at reject or quarantine
    docs = {"example.com": F.T.own_record("example.com", "v=DMARC1; p=reject; rua=%s;" % F.RUA),
            "example.net": F.T.own_record("example.net", "v=DMARC1; p=quarantine; rua=%s;" % F.RUA)}
    log = F.T.Log().add("staff@example.com", "Weekly #", times=10).add("staff@example.net", "Roster #", times=10)
    rep = F.T.audited(tmp_path / "clean", docs, log)
    doc = next_steps.build(rep, plan={"changes": [], "holds": []})
    top = doc["top"]
    assert top["protected"]["text"] == "Protected: all 2 domains refuse or junk spoofed mail."
    assert top["headline"] == ("Protected: all 2 domains block spoofed mail. Nothing urgent. Your call: nothing needs "
                               "you this week.")
    assert [next_steps.strip_line_md(e) for e in top["domains"]] == [
        "**Refuses spoofs - example.com**: Nothing of ours failing. Next: nothing to do.",
        "**Junks spoofs - example.net**: Nothing of ours failing. Next: nothing to do."]
    # a share of failing mail, and a record receivers cannot apply
    docs["example.net"] = F.T.own_record("example.net", "v=DMARC1; p=quarantine; pct=25; rua=%s;" % F.RUA)
    rep = F.T.audited(tmp_path / "share", docs, log)
    assert next_steps.build(rep)["top"]["protected"]["text"] == (
        "Partly: 1 of 2 domains refuse or junk spoofed mail; 1 enforces a share (pct below 100).")
    assert next_steps.band_status(rep, "example.net") == ("partial", "p=quarantine, pct=25")
    # DNS never read and no report names a policy: unknown, never a guess
    rep = F.T.audited(tmp_path / "unread", docs, log)
    rep["dns"] = None
    for g in rep["gate"]["domains"].values():
        g.update(current_policy=None, next_step="unknown - no DMARC policy determined")
    top = next_steps.build(rep)["top"]
    assert top["protected"] == {"word": "unknown", "text": "Unknown: this run read no DNS (offline), so it cannot say.",
                                "total": 2, "protected": 0, "counts": {"unread": 2}, "source": "dns"}
    assert top["headline"].startswith("Unknown: this run cannot say which of the 2 domains block spoofed mail.")
    # no audited name at all: not in this run, never a zero
    rep = dict(rep, gate={"domains": {}})
    assert next_steps.build_top(rep, None, {})["protected"]["text"] == next_steps.NO_NAMES


def test_t01_since_last_run_names_what_changed(estate):
    rep = json.loads(json.dumps(estate["report"]))
    rep["delta"] = {
        "previous_generated_utc": "2026-10-06T06:00:00Z",
        "by_domain": {"example.net": {"genuine_failures": 4}, "brand.example": {"genuine_failures": -2},
                      "example.org": {"genuine_failures": 0}},
        "new_senders": [{"sender": "payslips@example.net", "domain": "example.net", "envelope_domain": "mail.vendor.example",
                         "genuine_failures": 14, "excepted": 0}],
        "gone_senders": [{"sender": "old@example.com", "domain": "example.com", "envelope_domain": "example.com",
                          "genuine_failures": 3}],
        "policy_changes": {"brand.example": {"from": "quarantine", "to": "reject"}},
        "findings_resolved": [{"id": "DMARC-002", "source": "dns:brand.example", "title": "DMARC p=none - monitoring only"}],
        "maillog_window": {"comparable": False, "cut_orgs": {"example.com": {
            "now": {"reason": "row budget", "kept_hours": 41}, "previous": {"reason": "row budget", "kept_hours": 60}}}}}
    changed = next_steps.build(rep, plan=estate["plan"], org_name="example.com")["top"]["changed"]
    assert changed["text"] == (
        "Since 2026-10-06: worse - example.net +4; better - brand.example -2; fixed - old@example.com no longer fails; "
        "new - payslips@example.net x14; records - brand.example p=quarantine -> p=reject; resolved - DMARC p=none - "
        "monitoring only; failure counts for example.com not compared (the row budget cut both runs).")
    assert changed["plain"] == (
        "since 2026-10-06: worse - example.net +4; better - brand.example -2; fixed - an example.com sender no longer "
        "fails; new - example.net via mail.vendor.example x14; records - brand.example p=quarantine -> p=reject; "
        "resolved - DMARC p=none - monitoring only; failure counts for example.com not compared (the row budget cut both "
        "runs)")
    assert changed["since"] == "2026-10-06" and "@" not in changed["plain"]
    rep["delta"] = {"previous_generated_utc": "2026-10-06T06:00:00Z", "by_domain": {}, "new_senders": [],
                    "gone_senders": []}
    assert next_steps.build(rep)["top"]["changed"]["text"] == (
        "Since 2026-10-06: no change in failures, findings or records.")


def test_t01_a_band_that_cannot_be_built_never_costs_the_document(estate, monkeypatch):
    def broken(*a, **k):
        raise ValueError("a damaged field")
    monkeypatch.setattr(next_steps, "build_top", broken)
    doc = next_steps.build(estate["report"], plan=estate["plan"], date=F.ESTATE_DATE, org_name="example.com")
    assert doc["top"] is None and doc["sources"]["top_note"] == "the status band was not built (ValueError: a damaged field)"
    md = next_steps.render_md(doc)
    assert "## This week" not in md and "**%s**" % doc["one_liner"] in md  # the document as it was
    # damaged fields read as absent, never a crash
    rep = json.loads(json.dumps(estate["report"]))
    rep["maillog"]["census"]["by_sender"] = "x"
    rep["maillog"]["by_domain"] = ["x"]
    rep["mailflow"] = "x"
    rep["delta"] = {"by_domain": "x", "new_senders": "x", "policy_changes": ["x"]}
    monkeypatch.undo()
    top = next_steps.build(rep, plan=estate["plan"])["top"]
    assert top is not None and top["headline"]


def test_t01_your_call_groups_the_rows_after_a_check_by_what_they_wait_on():
    def row(rid, kind, prereqs, priority=1):
        return {"id": rid, "domain": "example.com", "kind": kind, "priority": priority, "hostname": "_dmarc.example.com",
                "value": "v=DMARC1; p=none;", "zone_host": "Route53", "prerequisites": prereqs,
                "status": "check", "status_text": "after 1 check", "status_reason": ""}
    auth = ("the external-destination record exists: receivers send example.com's aggregate data to r@corp.example "
            "only when corp.example publishes example.com._report._dmarc.corp.example TXT v=DMARC1")
    own = ["no sender that mails monthly or less often uses this domain"]
    plan = {"changes": [row("P-01", "no_mail", own), row("P-02", "no_mail", own), row("P-03", "new", [auth]),
                        row("P-04", "park", ["verify unused first: no passing volume"])], "holds": []}
    call = next_steps.build_top({"gate": {"domains": {}}, "dns": {"example.com": {}}}, plan, {})["call"]
    # the largest group is the rows' own checks: the others are said by what they wait on, never 'own' twice
    assert call["text"] == "Nothing can go out unchecked; 2 after their own checks (P-01, P-02); 2 after other checks."
    plan["changes"] = plan["changes"][:3]
    call = next_steps.build_top({"gate": {"domains": {}}, "dns": {"example.com": {}}}, plan, {})["call"]
    assert call["text"] == ("Nothing can go out unchecked; 2 after their own checks (P-01, P-02); 1 after one "
                            "report-authorization record at corp.example.")
    # a sentence never capitalizes a name
    assert next_steps.cap_sentence("corp.example and corp.co.uk: the row budget") == \
        "corp.example and corp.co.uk: the row budget"
    assert next_steps.cap_sentence("bounces and lost mail") == "Bounces and lost mail"
    assert next_steps.gaps_text(["corp.example: kept 41 hours", next_steps.SCOPE_GAP]) == (
        "corp.example: kept 41 hours; bounces and lost mail (NDRs): use message trace.")


# ------------------------------------------------------------------ T-03: the top of next_steps.md

def test_t03_next_steps_md_leads_with_the_band(estate, tmp_path):
    doc = estate["doc"]
    md = next_steps.render_md(doc)
    blocks = md.split("\n\n")
    assert blocks[0] == "# DMARC rollout - status and next steps, 2026-10-13"
    assert blocks[1] == "**%s**" % doc["top"]["headline"] and blocks[2] == "## This week (the 45-second read)"
    assert blocks[3] == "\n".join(doc["top"]["lines_md"])
    heads = [line for line in md.splitlines() if line.startswith("## ")]
    assert heads == ["## This week (the 45-second read)", "## Where we stand (2026-09-18 to 2026-10-08, deduplicated)",
                     "## The next step for example.com", "## What is failing", "## Per domain",
                     "## What happens next, by owner", "## The ask", "## Open questions", "## Sources and how to check"]
    # the one-liner once, unchanged and not bold, under The next step
    assert md.count(doc["one_liner"]) == 1 and "**" + doc["one_liner"] not in md
    assert md.split("## The next step for example.com\n\n", 1)[1].startswith(doc["one_liner"] + "\n\n## What is failing")
    # the sources and the verify.md pointer last, before the glossary
    tail = md.split("## Sources and how to check\n\n", 1)[1]
    assert tail.startswith("Sources: audit report generated ") and doc["sources"]["audience"] not in tail
    assert tail.split("\n\n")[1] == next_steps.VERIFY_POINTER and tail.split("\n\n")[2] == "---"
    assert tail.split("\n\n")[3].startswith("Glossary. DMARC is ")
    folder = run_folder(estate, tmp_path)
    (folder / "next_steps.md").write_text(md, encoding="utf-8")
    assert check_doc.main([str(folder / "next_steps.md"), "--run", str(folder)]) == 0
    # a custom audience is kept whole in the sources
    custom = next_steps.build(estate["report"], plan=estate["plan"], audience="For the board")
    assert next_steps.render_md(custom).split("## Sources and how to check\n\n", 1)[1].startswith("For the board. Sources: ")
