"""audit.py attributes the mail log per sender domain: each gate sees only
its own rows, unaudited subdomains and outside domains are counted apart,
and the headline names the domain given first. Synthetic mail log, offline,
no network."""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import audit

ROOT = Path(__file__).resolve().parent.parent
COLUMNS = ["Email date (UTC)", "Internet message ID", "Sender address", "Sender domain",
           "Sender mail from domain", "Recipients", "Subject", "Delivery action",
           "Latest delivery location", "DMARC"]
DOMAINS = ["example.com", "sub.example.com", "quiet.example"]


def _row(rows, mid, sender, domain, env, subject, action, location, dmarc):
    rows.append(["2026-05-01 09:00:00", mid, sender, domain, env, "user@example.com", subject,
                 action, location, dmarc])


def maillog_rows(extra_sender=False, drop_one=False):
    rows = []
    # example.com: 3 passing, 2 failing billing messages delivered to an inbox, 1 echo
    for i in range(3):
        _row(rows, "<ok%d@example.com>" % i, "noreply@example.com", "example.com", "example.com",
             "Your statement", "Delivered", "Inbox/folder", "pass")
    for i in range(1 if drop_one else 2):
        _row(rows, "<bill%d@example.com>" % i, "billing@example.com", "example.com", "example.com",
             "Purchase order 100%d acknowledged" % i, "Delivered", "Inbox/folder", "fail")
    _row(rows, "<echo@example.com>", "noreply@example.com", "example.com", "example.com",
         "Your statement", "Delivered", "Inbox/folder", "pass")
    _row(rows, "<echo@example.com>", "noreply@example.com", "example.com", "example.com",
         "Your statement", "Delivered", "On-prem/External", "fail")
    # sub.example.com: 4 failing from its own system, 1 spoof with a lure subject
    for i in range(4):
        _row(rows, "<alert%d@sub.example.com>" % i, "alerts@sub.example.com", "sub.example.com",
             "sub.example.com", "Nightly export complete", "Blocked", "Quarantine", "fail")
    _row(rows, "<spoof@mta7.hosting.example>", "ceo@sub.example.com", "sub.example.com",
         "mta7.hosting.example", "Invoice #77 past due", "Blocked", "Quarantine", "fail")
    # deep.example.com: a subdomain of example.com that is not audited
    for i in range(2):
        _row(rows, "<deep%d@deep.example.com>" % i, "app@deep.example.com", "deep.example.com",
             "deep.example.com", "Build %d finished" % (40 + i), "Blocked", "Quarantine", "fail")
    # other.example: under no audited domain
    for i in range(3):
        _row(rows, "<news%d@other.example>" % i, "news@other.example", "other.example", "other.example",
             "Weekly digest", "Blocked", "Quarantine", "fail")
    _row(rows, "<newsok@other.example>", "news@other.example", "other.example", "other.example",
         "Weekly digest", "Delivered", "Inbox/folder", "pass")
    if extra_sender:  # a sender the previous run never saw
        for i in range(2):
            _row(rows, "<crm%d@example.com>" % i, "crm@example.com", "example.com", "bnc.salesforce.example",
                 "Opportunity %d updated" % i, "Blocked", "Quarantine", "fail")
    return rows


def write_maillog(path, **kw):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        w.writerows(maillog_rows(**kw))
    return path


def build(path, domains=DOMAINS, **kw):
    return audit.build_report(domains=list(domains), maillog=str(path), offline=True, auth_column="DMARC",
                              domain_sources={d: ["cli"] for d in domains}, **kw)


@pytest.fixture(scope="module")
def maillog(tmp_path_factory):
    return write_maillog(tmp_path_factory.mktemp("attribution") / "maillog.csv")


@pytest.fixture(scope="module")
def report(maillog):
    return build(maillog, keep_verdicts=True)  # these tests attribute from the verdicts themselves


def test_each_audited_domain_gets_its_own_counters(report):
    bd = report["maillog"]["by_domain"]
    assert list(bd) == DOMAINS + [audit.OTHER]  # the order given, then (other)
    ex, sub, quiet = bd["example.com"], bd["sub.example.com"], bd["quiet.example"]
    assert (ex["logical_messages"], ex["genuine_failures"], ex["echo_messages"],
            ex["delivered_despite_fail"], ex["blocked_despite_pass"]) == (6, 2, 1, 2, 0)
    assert ex["top_senders"] == [{"sender": "billing@example.com", "genuine_failures": 2}]
    assert ex["by_likely"] == {"likely_spoof": 0, "likely_misconfigured_sender": 2, "unknown": 0}
    assert (sub["logical_messages"], sub["genuine_failures"], sub["delivered_despite_fail"]) == (5, 5, 0)
    assert sub["by_likely"] == {"likely_spoof": 1, "likely_misconfigured_sender": 4, "unknown": 0}
    assert sub["top_senders"] == [{"sender": "alerts@sub.example.com", "genuine_failures": 4},
                                  {"sender": "ceo@sub.example.com", "genuine_failures": 1}]
    assert quiet["logical_messages"] == 0 and quiet["genuine_failures"] == 0 and quiet["top_senders"] == []
    # the whole-log numbers are the sum of the parts, and no part carries the whole
    whole = report["maillog"]["counters"]
    assert (whole["logical_messages"], whole["genuine_failures"], whole["delivered_despite_fail"]) == (17, 12, 2)
    parts = sum(c["genuine_failures"] for c in bd.values()) + ex["subdomains_total"]["genuine_failures"]
    assert parts == whole["genuine_failures"]


def test_unaudited_subdomain_rows_sit_under_the_apex_not_in_its_own_rows(report):
    bd = report["maillog"]["by_domain"]
    st = bd["example.com"]["subdomains_total"]
    assert st["domains"] == ["deep.example.com"]
    assert (st["logical_messages"], st["genuine_failures"]) == (2, 2)
    assert st["top_senders"] == [{"sender": "app@deep.example.com", "genuine_failures": 2}]
    empty = bd["sub.example.com"]["subdomains_total"]  # always present, zeros when none
    assert empty["domains"] == [] and empty["logical_messages"] == 0
    assert bd["quiet.example"]["subdomains_total"]["logical_messages"] == 0


def test_outside_domains_land_under_other_once(report):
    other = report["maillog"]["by_domain"][audit.OTHER]
    assert (other["logical_messages"], other["genuine_failures"]) == (4, 3)
    assert other["sender_domains"] == [{"domain": "other.example", "logical_messages": 4, "genuine_failures": 3}]
    assert other["top_senders"] == [{"sender": "news@other.example", "genuine_failures": 3}]
    assert "subdomains_total" not in other
    joined = " ".join(r for g in report["gate"]["domains"].values() for r in g["reasons"])
    assert "other.example" not in joined  # attached to no gate


def test_gate_reasons_carry_only_the_domains_own_rows(report):
    gd = report["gate"]["domains"]
    ex, sub, quiet = gd["example.com"]["reasons"], gd["sub.example.com"]["reasons"], gd["quiet.example"]["reasons"]
    assert ("example.com: 2 logical message(s) from this domain failed with no passing copy (deduplicated); "
            "top senders: billing@example.com x2") in ex
    assert ("example.com: 2 message(s) from this domain failed authentication but reached a mailbox - "
            "a local override is masking failures external receivers enforce") in ex
    assert ("sub.example.com: 5 logical message(s) from this domain failed with no passing copy (deduplicated); "
            "top senders: alerts@sub.example.com x4, ceo@sub.example.com x1") in sub
    assert not [r for r in sub if "reached a mailbox" in r]
    # the whole-log totals (12 failing, 17 messages) appear in no domain's reasons
    for reasons in (ex, sub, quiet):
        assert not [r for r in reasons if "12 logical message" in r or "17 logical message" in r]
        assert not [r for r in reasons if "in the mail log failed" in r]  # the old shared wording
    assert gd["example.com"]["maillog_rows"] == 6
    assert gd["sub.example.com"]["maillog_rows"] == 5
    assert gd["quiet.example"]["maillog_rows"] == 0
    assert gd["example.com"]["verdict"] == gd["sub.example.com"]["verdict"] == "no_go"
    note = [r for r in ex if r.startswith("example.com: unaudited subdomain(s) deep.example.com carry "
                                          "2 logical message(s), 2 genuine failure(s)")]
    assert len(note) == 1 and "not gated here" in note[0]
    assert not [r for r in sub if "unaudited subdomain" in r]


def test_domain_without_rows_says_so(report):
    g = report["gate"]["domains"]["quiet.example"]
    assert g["verdict"] == "insufficient_data"
    assert "quiet.example: no mail-log rows for this domain in the window" in g["reasons"]
    assert not [r for r in g["reasons"] if "failed with no passing copy" in r]
    md = audit.render_md(report)
    assert "- quiet.example: no mail-log rows for this domain in the window" in md


def test_sender_domain_scope_is_named_for_a_domain_outside_it(maillog):
    doc = build(maillog, domains=["example.com", "other.example"], sender_domain="example.com")
    g = doc["gate"]["domains"]["other.example"]
    assert ("other.example: no mail-log rows for this domain in the window "
            "(the mail log was restricted to --sender-domain example.com)") in g["reasons"]
    bd = doc["maillog"]["by_domain"]
    assert bd[audit.OTHER]["logical_messages"] == 0 and bd["example.com"]["logical_messages"] == 6
    st = bd["example.com"]["subdomains_total"]  # everything under the filter that is not audited
    assert st["domains"] == ["deep.example.com", "sub.example.com"] and st["genuine_failures"] == 7


def test_headline_is_the_first_cli_domain_and_the_verdict_the_worst(report, maillog):
    g = report["gate"]
    assert (g["headline_domain"], g["headline_source"]) == ("example.com", "first on the command line")
    assert g["overall"] == "worst of 3 domains" and g["domain_count"] == 3
    assert g["verdict"] == "no_go" and g["worst_domain"] in ("example.com", "sub.example.com")
    assert g["reasons"][0].startswith("overall: worst of 3 domains; headline domain example.com "
                                      "(first on the command line)")
    assert g["reasons"][-1] == g["evidence"]["statement"]
    assert g["current_policy"] is None and g["next_step"] == "unknown - no DMARC policy determined"
    assert g["policies"] == {d: None for d in DOMAINS}
    # naming the domains in another order moves the headline, not the verdict
    rev = build(maillog, domains=["sub.example.com", "example.com"])
    assert rev["gate"]["headline_domain"] == "sub.example.com" and rev["gate"]["verdict"] == "no_go"
    assert list(rev["gate"]["domains"]) == ["sub.example.com", "example.com"]
    assert rev["gate"]["overall"] == "worst of 2 domains"


def test_headline_domain_rules():
    assert audit.headline_domain([]) == (None, None)
    assert audit.headline_domain(["sub.example.com", "example.com"]) == ("sub.example.com", "first domain given")
    srcs = {"sub.example.com": ["tenant"], "example.com": ["tenant"], "b.example": ["file"]}
    assert audit.headline_domain(["sub.example.com", "example.com", "b.example"], srcs) == ("b.example", "first in --file")
    srcs = {"sub.example.com": ["tenant"], "example.com": ["tenant"], "longer.example": ["tenant"]}
    assert audit.headline_domain(["sub.example.com", "example.com", "longer.example"], srcs) == (
        "example.com", "shortest audited apex")
    srcs = {"b.example": ["file"], "a.example": ["cli", "file"]}
    assert audit.headline_domain(["b.example", "a.example"], srcs) == ("a.example", "first on the command line")
    srcs = {"deep.sub.example.com": ["mailflow"], "sub.example.com": ["mailflow"]}
    assert audit.headline_domain(["deep.sub.example.com", "sub.example.com"], srcs) == (
        "sub.example.com", "shortest audited domain")


def test_maillog_by_domain_normalises_the_domain_list(report):
    bd = audit.maillog_by_domain(report["maillog"], ["Example.COM.", "SUB.example.com", "example.com"])
    assert list(bd) == ["example.com", "sub.example.com", audit.OTHER]
    assert bd["example.com"]["genuine_failures"] == 2 and bd["sub.example.com"]["genuine_failures"] == 5
    assert bd[audit.OTHER]["genuine_failures"] == 3


def test_no_domain_named_keeps_the_whole_log_verdict(maillog):
    doc = audit.build_report(domains=[], maillog=str(maillog), offline=True, auth_column="DMARC")
    g = doc["gate"]
    assert g["domains"] == {} and g["headline_domain"] is None and g["domain_count"] == 0
    assert g["overall"] == "no domain named - one verdict over the files given"
    assert "12 logical message(s) in the mail log failed with no passing copy (deduplicated)" in g["reasons"]
    bd = doc["maillog"]["by_domain"]
    assert list(bd) == [audit.OTHER] and bd[audit.OTHER]["logical_messages"] == 17
    assert [r["domain"] for r in bd[audit.OTHER]["sender_domains"]] == [
        "sub.example.com", "other.example", "example.com", "deep.example.com"]
    md = audit.render_md(doc)
    assert "- no domain named: all 17 logical messages (12 genuine failures) counted once under (other)" in md


def test_census_verified_line_and_markdown(report):
    cs = report["maillog"]["census"]
    assert [e["envelope_domain"] for e in cs["by_envelope"]][:2] == ["sub.example.com", "other.example"]
    assert [e["sender"] for e in cs["by_sender"]][:2] == ["alerts@sub.example.com", "news@other.example"]
    assert [e["sender"] for e in cs["by_sender"] if not e["genuine_failures"]] == ["noreply@example.com"]
    assert "note" in cs
    verified = report["verified_vs_inferred"]["verified"]
    assert ("mail log attributed per sender domain (maillog.by_domain): 2 of 3 audited domain(s) have rows, "
            "4 message(s) under (other)") in verified
    md = audit.render_md(report)
    assert "Per sender domain (each gate uses only its own rows):" in md
    assert ("- example.com: 6 logical messages, 2 genuine failures, 1 echo; delivered despite fail 2, "
            "blocked despite pass 0; likely split: 2 likely_misconfigured_sender; "
            "top failing senders: billing@example.com x2") in md
    assert ("  - unaudited subdomains (deep.example.com): 2 logical messages, 2 genuine failures - "
            "counted separately, not gated; add them to the domain list to gate them") in md
    assert ("- (other) - sender domains outside the audited list: 4 logical messages, 3 genuine failures "
            "(other.example 3 failing of 4) - reported once, attached to no gate") in md
    assert "## Failing senders (census)" in md
    assert "  - alerts@sub.example.com (envelope sub.example.com): 4 failing of 4 message(s); " in md
    assert "- headline domain: example.com (first on the command line) - **no_go**; policy unknown" in md


def test_previous_report_yields_a_delta_with_new_senders(maillog, tmp_path, report):
    second = write_maillog(tmp_path / "maillog2.csv", extra_sender=True, drop_one=True)
    now = build(second, previous_report=report)
    dl = now["delta"]
    assert dl["previous_generated_utc"] == report["generated_utc"]
    assert dl["previous_version"] == audit.VERSION
    assert dl["genuine_failures"] == 1 and dl["delivered_despite_fail"] == -1  # -1 billing, +2 crm
    assert [s["sender"] for s in dl["new_senders"]] == ["crm@example.com"]
    assert dl["new_senders"][0]["envelope_domain"] == "bnc.salesforce.example"
    assert dl["new_senders"][0]["genuine_failures"] == 2
    assert dl["gone_senders"] == [] and dl["policy_changes"] == {} and dl["gate_changes"] == {}
    assert dl["domains_added"] == [] and dl["domains_removed"] == [] and dl["notes"] == []
    assert dl["by_domain"]["example.com"] == {"genuine_failures": 1, "delivered_despite_fail": -1}
    assert dl["by_domain"]["sub.example.com"] == {"genuine_failures": 0, "delivered_despite_fail": 0}
    assert dl["by_domain"][audit.OTHER] == {"genuine_failures": 0, "delivered_despite_fail": 0}
    assert now["inputs"]["previous"] == report["generated_utc"]
    assert "delta" not in report  # a first run carries none
    md = audit.render_md(now)
    assert "## Since the previous run" in md
    assert "- new senders (1): crm@example.com (envelope bnc.salesforce.example) 2 failing of 2" in md
    assert "- per domain: example.com +1 genuine, -1 delivered despite fail; " in md
    with pytest.raises(audit.UsageError):
        build(second, previous_report="not a dict")


def run_cli(*argv):
    return subprocess.run([sys.executable, str(ROOT / "src" / "audit.py"), *argv],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)


def test_cli_prints_the_headline_and_writes_the_delta(maillog, tmp_path):
    out1 = tmp_path / "run1"
    args = ["sub.example.com", "example.com", "--offline", "--maillog", str(maillog), "--auth-column", "DMARC"]
    p = run_cli(*args, "--out", str(out1))
    assert p.returncode == 1, p.stderr  # major findings, as in every run with genuine failures
    assert "gate: no_go - worst of 2 domains; headline sub.example.com (first on the command line)" in p.stdout
    assert "- sub.example.com: 5 logical message(s) from this domain failed with no passing copy" in p.stdout
    assert "- example.com: 2 logical message(s) from this domain failed with no passing copy" in p.stdout
    doc = json.loads((out1 / "report.json").read_text(encoding="utf-8"))
    assert doc["gate"]["headline_domain"] == "sub.example.com"
    assert doc["inputs"]["domain_sources"] == {"sub.example.com": ["cli"], "example.com": ["cli"]}
    assert doc["inputs"]["previous"] is None and "delta" not in doc
    out2 = tmp_path / "run2"
    p = run_cli(*args, "--out", str(out2), "--previous", str(out1))  # the folder holding report.json
    assert p.returncode == 1, p.stderr
    assert "since the previous run (" in p.stdout and "genuine failures +0" in p.stdout
    assert "0 new sender(s)" in p.stdout
    doc2 = json.loads((out2 / "report.json").read_text(encoding="utf-8"))
    assert doc2["delta"]["genuine_failures"] == 0 and doc2["delta"]["new_senders"] == []
    assert doc2["delta"]["previous_generated_utc"] == doc["generated_utc"]
    assert doc2["inputs"]["previous"] == doc["generated_utc"]
    assert "## Since the previous run" in (out2 / "report.md").read_text(encoding="utf-8")
    bad = run_cli(*args, "--out", str(tmp_path / "run3"), "--previous", str(tmp_path / "missing.json"))
    assert bad.returncode == 2 and "cannot read --previous" in bad.stderr and "Traceback" not in bad.stderr
    (tmp_path / "nogate.json").write_text('{"hello": 1}', encoding="utf-8")
    bad = run_cli(*args, "--out", str(tmp_path / "run3"), "--previous", str(tmp_path / "nogate.json"))
    assert bad.returncode == 2 and "no gate section" in bad.stderr


def test_discovered_domains_headline_the_busiest_org_family():
    names = ["alpha.example", "short.example", "busy.example", "sub.busy.example"]
    tags = {d: ["tenant"] for d in names}
    vol = {"alpha.example": 30, "busy.example": 99000, "sub.busy.example": 120000}
    # the busiest org family wins and its audited apex leads - never the alphabet or the shortest name
    assert audit.headline_domain(names, tags, volume=vol, volume_label="most internal mail") == (
        "busy.example", "most internal mail")
    # an exact tie goes to the family holding the tenant default domain
    tags["short.example"] = ["tenant", "default"]
    assert audit.headline_domain(names, tags, volume={"alpha.example": 50, "short.example": 50}) == (
        "short.example", "most mail in this run")
    # with no volume, the tenant's default domain
    assert audit.headline_domain(names, tags) == ("short.example", "tenant default domain")
    # a typed domain still wins over both
    tags["alpha.example"] = ["cli", "tenant"]
    assert audit.headline_domain(names, tags, volume=vol) == ("alpha.example", "first on the command line")


def test_a_family_whose_apex_was_not_audited_leads_with_its_busiest_member():
    names = ["sub.quiet.example", "alpha.example"]
    tags = {d: ["tenant"] for d in names}
    vol = {"sub.quiet.example": 900, "other.quiet.example": 50, "alpha.example": 100}
    assert audit.headline_domain(names, tags, volume=vol) == ("sub.quiet.example", "most mail in this run")
    # an apex with no mail of its own, when a member carries it, cedes to the member
    names = ["busy.example", "mail.busy.example", "alpha.example"]
    tags = {d: ["tenant"] for d in names}
    v = {"mail.busy.example": 900, "alpha.example": 100}
    assert audit.headline_domain(names, tags, volume=v, own_volume=v) == ("mail.busy.example", "most mail in this run")


def test_an_explicit_headline_is_labelled_by_its_own_source():
    srcs = {"b.example": ["file"], "a.example": ["file"]}
    assert audit.headline_domain(["b.example", "a.example"], srcs, headline="a.example") == (
        "a.example", "first in --file")
    srcs["a.example"] = ["cli", "file"]
    assert audit.headline_domain(["b.example", "a.example"], srcs, headline="a.example") == (
        "a.example", "first on the command line")


def test_mail_volume_counts_passing_mail_in_the_log_then_the_reports():
    by_domain = {"example.com": {"logical_messages": 6, "genuine_failures": 2,
                                 "subdomains_total": {"logical_messages": 7, "genuine_failures": 7}},
                 "quiet.example": {"logical_messages": 0, "genuine_failures": 0, "subdomains_total": {}}}
    assert audit.mail_volume(by_domain, None, ["example.com", "quiet.example"]) == (
        {"example.com": 4}, "most passing or internal mail in the mail log")
    # a log scoped to one --sender-domain cannot rank the others: the reports decide
    rua = {"by_header_from": [{"domain": "m.example.com", "count": 500, "pass": 480, "fail": 20},
                              {"domain": "example.com", "count": 20, "pass": 20, "fail": 0}]}
    assert audit.mail_volume(by_domain, rua, ["example.com"], {"sender_domain": "example.com"}) == (
        {"example.com": 500}, "most passing mail in the reports")  # m.example.com counts for its audited apex
    assert audit.mail_volume(None, None, ["example.com"]) == ({}, None)


def test_names_taken_from_the_reports_are_ranked_not_taken_in_order():
    doc = audit.build_report(domains=[], rua_paths=["samples/rua"], offline=True)
    g = doc["gate"]
    assert g["headline_domain"] and g["headline_source"] != "first domain given"


def test_collect_volume_outranks_the_mail_log(maillog):
    domains = ["aaa.example", "example.com", "quiet.example"]
    doc = audit.build_report(domains=domains, maillog=str(maillog), offline=True, auth_column="DMARC",
                             domain_sources={d: ["tenant"] for d in domains},
                             volume={"aaa.example": 5000, "example.com": 40, "quiet.example": 0})
    assert (doc["gate"]["headline_domain"], doc["gate"]["headline_source"]) == ("aaa.example", "most internal mail")
    assert doc["inputs"]["volume"] == {"aaa.example": 5000, "example.com": 40, "quiet.example": 0}  # traceable


def test_a_tenant_run_headlines_the_busiest_domain_not_the_first_alphabetically(maillog):
    domains = ["aaa.example", "example.com", "quiet.example"]  # sorted, as a tenant inventory is
    doc = audit.build_report(domains=domains, maillog=str(maillog), offline=True, auth_column="DMARC",
                             domain_sources={d: ["tenant"] for d in domains})
    g = doc["gate"]
    assert (g["headline_domain"], g["headline_source"]) == ("example.com", "most passing or internal mail in the mail log")


def test_org_totals_pick_the_family_and_each_domains_own_mail_picks_the_member():
    names = ["a.org.example", "b.org.example", "other.example"]  # the family's apex was not audited
    tags = {d: ["tenant"] for d in names}
    vol = {"org.example": 5000, "other.example": 100}  # collect's per-org totals
    own = {"b.org.example": 300, "other.example": 50}  # each audited domain's own passing mail
    assert audit.headline_domain(names, tags, volume=vol, volume_label="most internal mail", own_volume=own) == (
        "b.org.example", "most internal mail")
    # an audited apex with no mail of its own cedes to the member that carries it
    names = ["org.example", "mail.org.example"]
    tags = {d: ["tenant"] for d in names}
    assert audit.headline_domain(names, tags, volume={"org.example": 5000},
                                 own_volume={"mail.org.example": 90}) == ("mail.org.example", "most mail in this run")


def test_report_volume_lands_on_the_closest_audited_domain():
    rua = {"by_header_from": [{"domain": "m.example.com", "pass": 500}, {"domain": "sub.example.com", "pass": 10}]}
    assert audit.mail_volume(None, rua, ["example.com", "sub.example.com"]) == (
        {"example.com": 500, "sub.example.com": 10}, "most passing mail in the reports")


def test_spoofs_of_an_unprotected_domain_do_not_count_as_its_mail(tmp_path):
    rows = []
    for i in range(300):
        rows.append(["2026-05-01 09:00:00", "<c%d@corp.example>" % i, "news@corp.example", "corp.example",
                     "corp.example", "user@example.com", "News", "Delivered", "Inbox/folder", "pass"])
    for i in range(900):  # no DMARC record on parked.example, so the spoofs carry the verdict none
        rows.append(["2026-05-01 09:00:00", "<p%d@spam.invalid>" % i, "ceo@parked.example", "parked.example",
                     "spam.invalid", "user@example.com", "Invoice", "Delivered", "Junk folder", "none"])
    path = tmp_path / "log.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        w.writerows(rows)
    domains = ["aaa.example", "corp.example", "parked.example"]
    doc = audit.build_report(domains=domains, maillog=str(path), offline=True, auth_column="DMARC",
                             domain_sources={d: ["tenant"] for d in domains})
    assert (doc["gate"]["headline_domain"], doc["gate"]["headline_source"]) == (
        "corp.example", "most passing or internal mail in the mail log")
    assert doc["maillog"]["by_domain"]["parked.example"]["passing_messages"] == 0


def test_internal_mail_is_the_domains_own_so_the_apex_leads_its_family(tmp_path):
    rows = [["2026-05-01 09:00:00", "<i%d@corp.example>" % i, "staff@corp.example", "corp.example", "corp.example",
             "colleague@corp.example", "Lunch", "Delivered", "Inbox/folder", "none", "Intra-org"] for i in range(400)]
    rows += [["2026-05-01 09:00:00", "<v%d@vendor.invalid>" % i, "deals@mkt.corp.example", "mkt.corp.example",
              "vendor.invalid", "user@corp.example", "Deals", "Delivered", "Inbox/folder", "pass", "Inbound"]
             for i in range(100)]
    # one message with an outside leg is not internal, whatever its other leg says
    rows += [["2026-05-01 09:00:00", "<x@spam.invalid>", "ceo@corp.example", "corp.example", "spam.invalid",
              "cfo@corp.example", "Wire", "Delivered", "Inbox/folder", "none", leg] for leg in ("Inbound", "Intra-org")]
    # a spoof's copy that a mailbox rule redirected to another recipient is its own group with
    # one Intra-org leg: still not internal, because that Message-ID arrived from outside
    rows += [["2026-05-01 09:00:00", "<r%d@spam.invalid>" % i, "ceo@corp.example", "corp.example", "spam.invalid",
              rcpt, "Wire", "Delivered", "Inbox/folder", "none", leg]
             for i in range(5) for rcpt, leg in (("cfo@corp.example", "Inbound"), ("pa@corp.example", "Intra-org"))]
    path = tmp_path / "log.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS + ["Direction"])
        w.writerows(rows)
    domains = ["aaa.example", "corp.example", "mkt.corp.example"]
    doc = audit.build_report(domains=domains, maillog=str(path), offline=True, auth_column="DMARC",
                             domain_sources={d: ["tenant"] for d in domains})
    c = doc["maillog"]["by_domain"]["corp.example"]
    assert (c["logical_messages"], c["passing_messages"], c["internal_messages"]) == (411, 0, 400)
    # a pass-only count would hand the family to the subdomain that only receives vendor mail
    assert (doc["gate"]["headline_domain"], doc["gate"]["headline_source"]) == (
        "corp.example", "most passing or internal mail in the mail log")


def _write(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def test_a_direction_column_named_by_hand_must_exist(tmp_path):
    path = tmp_path / "log.csv"
    _write(path, COLUMNS, [["2026-05-01 09:00:00", "<a@x>", "hi@corp.example", "corp.example", "corp.example",
                            "u@example.com", "Hello", "Delivered", "Inbox/folder", "pass"]])
    quiet = audit.run_maillog(str(path), auth_column="DMARC")  # no Direction column: the default stays silent
    assert "Direction" not in (quiet.get("missing_optional_columns") or [])
    loud = audit.run_maillog(str(path), auth_column="DMARC", columns={"direction": "Mail direction"})
    assert "Mail direction" in loud["missing_optional_columns"]
    p = subprocess.run([sys.executable, str(ROOT / "src" / "dedupe.py"), str(path), "--auth-column", "DMARC",
                        "--direction-column", "Mail direction", "--json"], capture_output=True, text=True)
    assert p.returncode in (0, 1) and "warning: column not found: Mail direction" in p.stderr


def test_the_mcp_wrapper_reads_the_direction_column(tmp_path):
    import mcp_server
    path = tmp_path / "log.csv"
    _write(path, COLUMNS + ["Direction"], [
        ["2026-05-01 09:00:00", "<i1@x>", "staff@corp.example", "corp.example", "corp.example",
         "colleague@corp.example", "Lunch", "Blocked", "Quarantine", "fail", "Intra-org"],
        ["2026-05-01 09:00:00", "<v1@x>", "deals@corp.example", "corp.example", "vendor.invalid",
         "u@corp.example", "Deals", "Blocked", "Quarantine", "fail", "Inbound"]])
    reply = mcp_server.dedupe_maillog(str(path), auth_column="DMARC")
    details = {d["msgid"]: d for d in reply["genuine_failure_details"]}
    assert details["<i1@x>"]["internal"] is True and details["<v1@x>"]["internal"] is False
    assert details["<i1@x>"]["passed"] is False
    loud = mcp_server.dedupe_maillog(str(path), auth_column="DMARC", direction_column="Mail direction")
    assert "Mail direction" in loud["missing_optional_columns"]


def test_the_mcp_wrapper_buckets_alignment_and_lists_spf_only_senders(tmp_path):
    import mcp_server
    path = tmp_path / "log.csv"
    _write(path, COLUMNS + ["SPF", "DKIM"], [
        ["2026-05-01 09:00:00", "<a@x>", "billing@corp.example", "corp.example", "corp.example",
         "u@example.com", "Statement", "Delivered", "Inbox/folder", "pass", "pass", "none"],
        ["2026-05-01 09:00:00", "<b@x>", "news@corp.example", "corp.example", "bounce.vendor.example",
         "u@example.com", "News", "Delivered", "Inbox/folder", "pass", "fail", "pass"]])
    reply = mcp_server.dedupe_maillog(str(path), auth_column="DMARC")
    assert reply["alignment"]["available"] and reply["alignment"]["spf_only"] == 1 and reply["alignment"]["dkim_aligned"] == 1
    assert [s["sender"] for s in reply["spf_only_senders"]] == ["billing@corp.example"]
    assert any(f["id"] == "MAILFLOW-010" for f in reply["findings"])
    loud = mcp_server.dedupe_maillog(str(path), auth_column="DMARC", spf_column="SPF verdict")
    assert "SPF verdict" in loud["missing_optional_columns"]


def test_the_mcp_audit_reads_the_settings_file(tmp_path):
    import mcp_server
    path = tmp_path / "log.csv"
    _write(path, COLUMNS, [["2026-05-01 09:00:00", "<f@x>", "printer@corp.example", "corp.example",
                            "printer.vendor.example", "u@corp.example", "Invoice", "Blocked", "Quarantine", "fail"]])
    cfg = tmp_path / "audit.toml"
    cfg.write_text('[audit]\nvendor_domains = ["vendor.example"]\n\n[[exceptions]]\nmatch = "vendor.example"\n'
                   'reason = "printer"\nuntil = 2099-01-01\nremoval_criterion = "replaced"\n', encoding="utf-8")
    out = mcp_server.ROOT / "audit-out" / ("mcp-test-%d" % os.getpid())
    try:
        reply = mcp_server.run_audit(domains=["corp.example"], maillog=str(path), offline=True, out_dir=str(out),
                                     config=str(cfg))
        assert "error" not in reply, reply
        assert reply["exceptions"]["applied"][0]["match"] == "vendor.example"
        assert reply["exceptions"]["excepted_maillog_failures"] == 1
        assert reply["gate"]["domains"]["corp.example"]["verdict"] != "no_go"
        assert str(reply["settings"]).endswith("audit.toml")
    finally:
        import shutil
        shutil.rmtree(out, ignore_errors=True)


def test_a_trailing_dot_in_the_sender_domain_cell_is_attributed_like_its_window(tmp_path):
    path = tmp_path / "log.csv"
    _write(path, COLUMNS, [["2026-05-01 09:00:00", "<a@x>", "hi@corp.example", "corp.example.", "corp.example",
                            "u@example.com", "Hello", "Blocked", "Quarantine", "fail"]])
    doc = audit.build_report(domains=["corp.example"], maillog=str(path), offline=True, auth_column="DMARC")
    c = doc["maillog"]["by_domain"]["corp.example"]
    assert c["logical_messages"] == 1 and c["genuine_failures"] == 1 and c["window"]["rows"] == 1
    assert doc["maillog"]["by_domain"][audit.OTHER]["logical_messages"] == 0


def test_the_delta_does_not_compare_logs_or_views_that_differ_too_much():
    now = {"generated_utc": "2026-10-07T15:00:00Z",
           "maillog": {"counters": {"genuine_failures": 613, "delivered_despite_fail": 1}, "window": {"hours": 41.0},
                       "by_domain": {"corp.example": {"genuine_failures": 613, "delivered_despite_fail": 1}}},
           "rua": {"totals": {"messages": 828000, "pass_rate": 0.98}}, "gate": {"domains": {}}, "findings": []}
    prev = {"generated_utc": "2026-10-01T15:00:00Z",
            "maillog": {"counters": {"genuine_failures": 2100, "delivered_despite_fail": 0}, "window": {"hours": 719.0},
                        "by_domain": {"corp.example": {"genuine_failures": 2100, "delivered_despite_fail": 0}}},
            "rua": {"totals": {"messages": 40, "pass_rate": 0.0}}, "gate": {"domains": {}}, "findings": []}
    dl = audit.build_delta(now, prev)
    assert dl["genuine_failures"] is None and dl["by_domain"] == {} and dl["maillog_window"]["comparable"] is False
    assert dl["rua"] == {"now_messages": 828000, "previous_messages": 40, "comparable": False, "pass_rate_change": None}
    assert any("cover different spans (41 hours now, 30 days in the previous run)" in n for n in dl["notes"])
    assert any("not comparable with the previous run (828000 messages now, 40 then)" in n for n in dl["notes"])
    prev["maillog"]["window"]["hours"] = 45.0
    prev["rua"]["totals"] = {"messages": 700000, "pass_rate": 0.95}
    dl = audit.build_delta(now, prev)
    assert dl["genuine_failures"] == -1487 and dl["by_domain"]["corp.example"]["genuine_failures"] == -1487
    assert dl["rua"]["comparable"] is True and dl["rua"]["pass_rate_change"] == 3.0
    now["rua"]["totals"]["messages"] = prev["rua"]["totals"]["messages"] = 0  # no reports on either side: nothing to judge
    dl = audit.build_delta(now, prev)
    assert dl["rua"]["comparable"] is None and not any("outside view" in n for n in dl["notes"])


def test_report_json_drops_the_verdicts_and_caps_the_source_tables(tmp_path):
    rep = audit.build_report(domains=["example.com"], maillog=str(ROOT / "samples" / "sample_maillog.csv"),
                             rua_paths=[str(ROOT / "samples" / "rua")], offline=True, auth_column="DMARC")
    assert rep["maillog"]["verdicts"] == [] and rep["maillog"]["verdicts_omitted"] == rep["maillog"]["counters"]["logical_messages"]
    assert rep["maillog"]["census"]["by_sender"] and rep["maillog"]["by_domain"]["example.com"]["genuine_failures"] > 0
    kept = audit.build_report(domains=["example.com"], maillog=str(ROOT / "samples" / "sample_maillog.csv"),
                              offline=True, auth_column="DMARC", keep_verdicts=True)
    assert len(kept["maillog"]["verdicts"]) == kept["maillog"]["counters"]["logical_messages"]
    doc = {"by_source_ip": [{"source_ip": "2001:db8::%x" % i, "count": 5000 - i} for i in range(1500)],
           "unknown_senders": [{"kind": "ip", "value": "2001:db8::%x" % i, "count": 5000 - i} for i in range(1200)]}
    audit._trim_rua(doc, 1000)
    assert len(doc["by_source_ip"]) == 1000 and len(doc["unknown_senders"]) == 1000
    assert doc["truncated"] == {"by_source_ip": {"kept": 1000, "total": 1500}, "unknown_senders": {"kept": 1000, "total": 1200}}
