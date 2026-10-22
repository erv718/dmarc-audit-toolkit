"""Round 13 review fixes: Since last run and Not in this data.

A failing sender first seen under an organization the previous run's row budget cut is named as new or missed by
that cut, never left out; a resolved finding names its domain, its title quoted and its id; the plain line says the
previous run's date once and a sender by its From domain (the envelope only when it differs); a damaged delta
entry reads as absent. The cut clause's full-window figure counts the organizations it names, and a pull that
failed says what was counted for it; old evidence reaches the terminal and Slack; messages relayed only to an
on-premises hop say whose they are; and the gaps past the first two are named, never a count pointing elsewhere.
Synthetic data, offline."""

import json

import pytest

import next_steps
import notify
import r13_fixtures as F


@pytest.fixture(scope="module")
def weekly(tmp_path_factory):
    return F.weekly(tmp_path_factory.mktemp("r13_fix_since_weekly"))


@pytest.fixture(scope="module")
def incident(tmp_path_factory):
    return F.incident(tmp_path_factory.mktemp("r13_fix_since_incident"))


def test_a_new_sender_under_a_cut_organization_is_named_new_or_missed(weekly):
    dl = weekly["report"]["delta"]
    assert [s["sender"] for s in dl["new_senders_held"] if s["genuine_failures"]] == ["newsletter@news.corp.example"]
    assert "newsletter@news.corp.example" not in [s["sender"] for s in dl["new_senders"]]
    changed = weekly["doc"]["top"]["changed"]
    assert "new (or missed by the last run's cut) - newsletter@news.corp.example x60" in changed["text"]
    assert "new (or missed by the last run's cut) - a news.corp.example sender x60" in changed["plain"]
    assert changed["new_or_missed"][0]["count"] == 60


def test_the_plain_since_line_says_the_date_once_and_a_sender_by_its_domain(weekly):
    line = next(l for l in weekly["doc"]["top"]["lines_plain"] if l.startswith("Since last run"))
    assert line.startswith("Since last run (2026-10-09): worse - corp.co.uk +14; new - a corp.co.uk sender x14; ")
    assert line.lower().count("since") == 1 and "via corp.co.uk" not in line
    summary = notify.summarize(weekly["report"], plan=weekly["plan"], top=weekly["doc"]["top"])
    assert line in summary.splitlines()


def test_a_resolved_finding_names_its_domain_title_and_id(weekly):
    dns = {"id": "DMARC-003", "source": "dns:harborfoods.example", "severity": "major",
           "title": "DMARC has no rua - failures are invisible to you"}
    log = {"id": "MAILFLOW-002", "source": "maillog", "severity": "major",
           "title": "3 messages failed authentication but reached a mailbox"}
    assert next_steps.resolved_words(dns) == 'harborfoods.example: "DMARC has no rua" (DMARC-003)'
    assert next_steps.resolved_words(dns, rich=False) == "harborfoods.example: DMARC has no rua (DMARC-003)"
    assert next_steps.resolved_words(log) == '"3 messages failed authentication but reached a mailbox" (MAILFLOW-002)'
    rep = json.loads(json.dumps(weekly["report"]))
    rep["delta"]["findings_resolved"] = [dns]
    changed = next_steps.build_top(rep, weekly["plan"], {})["changed"]
    assert 'resolved - harborfoods.example: "DMARC has no rua" (DMARC-003)' in changed["text"]
    assert "resolved - harborfoods.example: DMARC has no rua (DMARC-003)" in changed["plain"]


def test_a_damaged_record_change_reads_as_absent(weekly):
    rep = json.loads(json.dumps(weekly["report"]))
    rep["delta"]["policy_changes"] = {"corp.example": "x", "corp.de": {}, "corp.fr": {"from": None, "to": "none"}}
    changed = next_steps.build_top(rep, weekly["plan"], {})["changed"]
    assert changed["records"] == ["corp.fr no policy read -> p=none"]
    assert "corp.example no policy read" not in changed["text"] and "corp.de" not in changed["text"]


def test_the_cut_clause_counts_the_organizations_it_names(weekly):
    rep = json.loads(json.dumps(weekly["report"]))
    # the weekly review's failpull run: corp.co.uk's pull failed, its whole window counted all the same
    rep["maillog"]["cuts"]["corp.co.uk"] = {"reason": "not pulled", "error": "HTTP 500 on hunting"}
    rep["maillog"]["window_totals"]["orgs"]["corp.co.uk"] = {"source": "Advanced Hunting aggregate", "by_domain": {
        "corp.co.uk": {"logical_messages": 80, "genuine_failures": 44, "delivered_despite_fail": 44}}}
    gaps = next_steps.top_gaps(rep, "corp.example")["data_gaps"]
    assert gaps[:2] == [
        "mail log for corp.co.uk not read this run (its pull failed): its senders are not checked (44 genuine failures "
        "over the full window, counted in advanced hunting)",
        "corp.example and corp-brand.example: the row budget kept only the newest 241 and 627 hours, so their counts "
        "are floors (502 genuine failures over the full window)"]
    assert next_steps.full_window(rep, ["corp.example", "corp-brand.example"])["genuine_failures"] == 502
    assert next_steps.full_window(rep)["genuine_failures"] == 546  # the whole log's, Where we stand's own


def test_old_evidence_reaches_the_terminal_and_slack():
    rep = {"generated_utc": "2026-10-20T06:00:00Z", "dns": None, "maillog": None,
           "rua": {"totals": {"end_date": "2026-09-02"}}, "gate": {"domains": {"example.com": {
               "verdict": "no_go", "current_policy": "reject",
               "policy_source": "aggregate reports (example.com, 1 report(s))"}}}}
    top = next_steps.build_top(rep, None, {})
    line = next(l for l in top["lines_plain"] if l.startswith("Not in this data: "))
    assert line == ("Not in this data: offline run: DNS not read, so policies come from the aggregate reports or are "
                    "unknown; the newest evidence is from 2026-09-02, 48 days before this run; bounces and lost mail - "
                    "use message trace")
    assert line in notify.band_lines(top, "2026-10-20")


def test_relayed_messages_say_whose_mail_they_are(incident):
    c = incident["report"]["maillog"]["counters"]
    assert c["relayed_only_passed_by_domain"] == {"example.com": 36}
    assert c["relayed_only_passed_by_sender"] == {"hr@example.com": 36}
    rep = json.loads(json.dumps(incident["report"]))
    rep["rua"] = {"totals": {"end_date": "2026-10-07"}}  # reports read: the relayed gap is the first one
    gaps = next_steps.top_gaps(rep)
    rich = ("36 example.com messages, all from hr@example.com, passed but went only to an on-premises or external hop: "
            "check message trace")
    assert gaps["data_gaps"] == [rich]
    assert gaps["gaps_plain"][0] == ("36 example.com messages passed but went only to an on-premises or external hop: "
                                     "check message trace")
    assert not any("@" in g for g in gaps["gaps_plain"])
    # several From domains: the busiest named with its share; a sender named only when most of them are its
    rep["maillog"]["counters"]["relayed_only_passed_by_domain"] = {"example.com": 30, "example.net": 6}
    rep["maillog"]["counters"]["relayed_only_passed_by_sender"] = {"hr@example.com": 12, "a@example.net": 6}
    assert next_steps.relayed_whose(rep["maillog"], 36) == (
        "36 messages, 30 of them as example.com, passed but went only to an on-premises or external hop: check message "
        "trace", "36 messages, 30 of them as example.com, passed but went only to an on-premises or external hop: check "
        "message trace")
    rep["maillog"]["counters"]["relayed_only_passed_by_sender"] = {"hr@example.com": 30, "a@example.net": 6}
    assert next_steps.relayed_whose(rep["maillog"], 36)[0].startswith(
        "36 messages, 30 of them as example.com, most from hr@example.com, passed but went only to ")


def test_the_gaps_past_the_first_two_are_named():
    rep = {"generated_utc": "2026-10-20T06:00:00Z", "dns": None, "maillog": None, "rua": None}
    gaps = next_steps.top_gaps(rep)["gaps"]
    assert gaps == ["offline run: DNS not read, so policies come from the aggregate reports or are unknown",
                    "no mail log: our own senders are not checked", "(+1 more: no aggregate reports)",
                    next_steps.SCOPE_GAP]
    assert not any("Where we stand" in g for g in gaps)
