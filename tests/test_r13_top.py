"""Round 13: the status band's data (next_steps.json "top").

T-09, here first: say what the run cannot see. next_steps.top_gaps is the band's "Not in this data" (top.gaps,
top.evidence_through, top.stale): at most two data gaps, the rest counted, and always last the scope line -
bounces and lost mail are in no file this toolkit reads. Where we stand says when the passing copy of a message
went only to an on-premises or external hop, and verify.md gives a message-trace lookup per own sender that
fails. (T-01's tests for build_top belong in this file too.) Synthetic data, offline."""

import re

import pytest

import next_steps
import r13_fixtures as F
import verify

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
