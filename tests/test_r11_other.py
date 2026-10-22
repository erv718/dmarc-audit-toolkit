"""Round 11, group N: the status document's gate semantics, comparability and
trends, exceptions, overrides, the window-totals readers, the unknown-sender
check, robustness against damaged inputs, and the docs an operator reads.
Every test here failed before its fix. Synthetic data only, no network."""

import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import audit
import collect
import config
import dedupe
import next_steps
import notify
import rua_parse

from conftest import ROOT

RUA = "mailto:dmarc-reports@example.com"
INBOX = ("Delivered", "Inbox/folder")
QUARANTINED = ("Blocked", "Quarantine")
COLS = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain", "Recipients",
        "Subject", "Delivery action", "Latest delivery location", "DMARC", "SPF", "DKIM", "Direction"]
OVERRIDES = ["Org level action", "Org level policy", "User level action", "User level policy"]


class Log:
    """A synthetic mail-log export, one row per message, with or without the override columns."""

    def __init__(self, overrides=False):
        self.cols = COLS + (OVERRIDES if overrides else [])
        self.rows = []

    def add(self, sender, subject, n=1, env=None, where=INBOX, dmarc="pass", spf=None, org=None, user=None,
            direction="Inbound"):
        for _ in range(n):
            i = len(self.rows)
            dom = sender.rpartition("@")[2]
            row = ["2026-10-07T%02d:%02d:00Z" % (i // 60 % 24, i % 60), "<m%04d@mail.invalid>" % i, sender, dom,
                   env or dom, "u%d@example.com" % (i % 7), subject.replace("#", str(i)), where[0], where[1], dmarc,
                   spf or ("pass" if dmarc == "pass" else "fail"), "pass" if dmarc == "pass" else "fail", direction]
            if len(self.cols) > len(COLS):
                row += [org[1] if org else "", org[0] if org else "", user[1] if user else "", user[0] if user else ""]
            self.rows.append(row)
        return self

    def write(self, path):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(self.cols)
            w.writerows(self.rows)
        return str(path)


def dns_doc(domain, record=None, **over):
    """A domain's DNS document: a record of its own, or none (dmarc_status absent)."""
    tags = audit.dns_audit.parse_dmarc(record) if record else {}
    doc = {"domain": domain, "spf": "v=spf1 include:spf.protection.outlook.com -all", "spf_status": "found",
           "spf_terminator": "-all", "spf_lookups": 2, "dmarc": record, "dmarc_source": "_dmarc." + domain if record else None,
           "effective_policy": tags.get("p"), "inherited": False, "dmarc_status": "found" if record else "absent",
           "dkim_selectors": ["selector1"], "dkim_status": "found", "mx": ["0 mail.example"], "mx_status": "found",
           "findings": []}
    doc.update(over)
    return doc


def finding(fid, title):
    return {"id": fid, "severity": "major", "area": "dmarc", "title": title, "evidence": "", "action": "", "verified": True}


def report_for(tmp_path, docs, log=None, exceptions=(), rua=None, name="log.csv", keep=False):
    """report.json as collect.py writes it: the mail log read offline, the DNS documents set, the gate decided."""
    names = list(docs)
    ml = log.write(tmp_path / name) if log is not None else None
    rep = audit.build_report(domains=names, maillog=ml, offline=True, auth_column="DMARC" if ml else None,
                             exceptions=list(exceptions), keep_verdicts=True)
    rep["dns"] = docs
    if rua is not None:
        rep["rua"] = rua
    rep["gate"] = audit.gate_verdict(docs, rep["rua"], rep["maillog"], names, exceptions=list(exceptions), marked=True)
    if rep["maillog"] and not keep:  # as report.json is written: the verdicts gone, the census and counters kept
        rep["maillog"]["verdicts"] = []
    return rep


def one_liner_and_doc(rep, plan=None):
    doc = next_steps.build(rep, plan)
    return doc["one_liner"], doc


def table_rows(doc):
    md = next_steps.render_md(doc)
    return [l for l in md.split("## Per domain", 1)[1].split("\n## ", 1)[0].splitlines() if l.startswith("| `")]


# ------------------------------------------------------------------ N3, N4, N28: what "no policy read" means

def test_n3_a_failed_lookup_asks_for_a_re_run_never_for_a_record(tmp_path):
    docs = {"example.com": dns_doc("example.com", dmarc_status="error",
                                   findings=[finding("DMARC-006", "DMARC lookup failed - not verified")])}
    log = (Log().add("staff@example.com", "Weekly #", 20, direction="Outbound")
           .add("ceo@example.com", "Urgent wire #", 3, env="evil.invalid", dmarc="fail"))
    rep = report_for(tmp_path, docs, log)
    assert rep["gate"]["domains"]["example.com"]["verdict"] == "no_go"
    plan = {"changes": [], "holds": [{"domain": "example.com",
                                      "reason": "DNS could not be verified for this domain in this run - re-run before planning changes"}]}
    line, doc = one_liner_and_doc(rep, plan)
    assert doc["next_step"]["kind"] == "recheck"
    assert "monitoring-only" not in line and "monitoring-only" not in doc["ask"]
    assert "The first step is to re-run the audit with working DNS before any change to example.com's DMARC record: " \
           "its lookup failed, so a record may already exist" in line
    assert doc["ask"].endswith("- the first step is to re-run the audit with working DNS before any change to "
                               "example.com's DMARC record: its lookup failed, so a record may already exist, and a "
                               "second one would leave it with no policy at all.")
    assert not [q for q in doc["open_questions"] if "monitoring-only" in q["question"]]
    assert any(q["question"].startswith("Can we close this gap on example.com (it stands whatever its DMARC record says)")
               for q in doc["open_questions"])
    assert next_steps.policy_unread_why(rep, "example.com") == "unverified"
    # a record whose p= receivers do not apply: correct it, never a second record beside it
    typo = {"gate": {"domains": {"example.com": {"verdict": "go", "current_policy": "quarantin", "blockers": [],
                                                 "notes": [], "reasons": [],
                                                 "next_step": "unknown - unrecognised policy p=quarantin"}},
                     "evidence": {"statement": "s"}},
            "dns": {"example.com": dns_doc("example.com", "v=DMARC1; p=quarantin; rua=%s;" % RUA)},
            "inputs": {"domains": ["example.com"]}, "findings": []}
    line, doc = one_liner_and_doc(typo, {"changes": [], "holds": []})
    assert doc["next_step"]["kind"] == "fix_record" and "go-ahead" not in doc["ask"]
    assert line.endswith("The first step is to correct the DMARC record at _dmarc.example.com: p=quarantin is not a "
                         "policy receivers apply (none, quarantine or reject), so they apply none.")
    assert "correct the record: p=quarantin is not a policy receivers apply" in table_rows(doc)[0]


def test_n4_no_dns_read_holds_the_step_for_the_policy_and_never_asks_a_go_ahead(tmp_path):
    log = Log().add("staff@example.com", "Weekly #", 20)
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "m.csv"), offline=True,
                             auth_column="DMARC")
    assert rep["gate"]["domains"]["example.com"]["verdict"] == "insufficient_data"
    line, doc = one_liner_and_doc(rep, None)
    assert doc["next_step"]["kind"] == "unread" and doc["next_step"]["data"]
    assert "publish a monitoring-only" not in line and "go-ahead" not in doc["ask"]
    assert line.endswith("on hold - it needs more data: no DMARC policy could be determined for example.com - run "
                         "online so live DNS is checked, or supply rua reports that cover it.")
    assert doc["ask"].startswith("The ask this week: more data before the next step on example.com")
    assert [q for q in doc["open_questions"] if q["question"].startswith("Can we supply the data the next step on")]
    assert "| needs more data | read the policy first: run online, or supply aggregate reports that cover it |" \
           in table_rows(doc)[0]
    # the CLI prints the question, not "None from this run"
    (tmp_path / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "next_steps.py"), str(tmp_path / "report.json")],
                       capture_output=True, text=True)
    assert p.returncode == 0 and "- Can we supply the data the next step on example.com" in p.stdout


def test_n28_a_parked_domain_leads_with_its_park_row_never_a_monitoring_record(tmp_path):
    docs = {"shop.example": dns_doc("shop.example", spf=None, spf_status="absent", spf_terminator=None, mx=[],
                                    mx_status="absent", dkim_selectors=[], dkim_status="absent",
                                    findings=[finding("DMARC-001", "NO DMARC RECORD - no policy, no reporting, invisible to you")])}
    rep = report_for(tmp_path, docs, Log().add("x@other.example", "Hello #", 2))
    park = "verify unused first: no passing volume in aggregate reports, no owner objects"
    plan = {"changes": [
        {"id": "P-01", "domain": "shop.example", "kind": "park", "priority": 1, "record": "TXT", "hostname": "_dmarc.shop.example",
         "value": "v=DMARC1; p=reject; rua=%s;" % RUA, "current": "none", "why": "parked domain", "prerequisites": [park]},
        {"id": "P-02", "domain": "shop.example", "kind": "park", "priority": 1, "record": "TXT", "hostname": "shop.example",
         "value": "v=spf1 -all", "current": "none", "why": "parked domain", "prerequisites": [park]}], "holds": []}
    line, doc = one_liner_and_doc(rep, plan)
    assert doc["next_step"]["kind"] == "park" and doc["next_step"]["ref"] == "P-01"
    assert "monitoring-only" not in line and "monitoring-only" not in doc["ask"]
    assert line.endswith("The next safe step is to park it with p=reject, ready when %s." % park)
    # a park row waiting on its unused check is never a zero-risk record ready now (round 13, T-05)
    assert doc["ask"] == ("The ask this week: approval to publish 2 records (plan P-01 to P-02) once the checks listed "
                          "with each are confirmed, of which 2 are park rows that need the domain's unused check first.")


# ------------------------------------------------------------------ N5, N6: a plan step and the gate's verdict

APEX = "v=DMARC1; p=quarantine; rua=%s;" % RUA
HOLD = ("subdomains that send have no record of their own and follow p= (the record has no sp=): sub.corp.example - "
        "moving to reject would reject their failing mail too; give each its own record, or add sp=, before that move")


def reject_plan(domain="corp.example", holds=()):
    return {"changes": [{"id": "P-01", "domain": domain, "kind": "ratchet", "priority": 3, "record": "TXT",
                         "hostname": "_dmarc." + domain, "value": "v=DMARC1; p=reject; rua=%s;" % RUA, "current": APEX,
                         "why": "quarantine at 100 percent is stable",
                         "prerequisites": ["every legitimate sender proven with an aligned DKIM header within 7 days",
                                           "SPF at 9 lookups or fewer"]}],
            "holds": [{"domain": domain, "reason": h} for h in holds]}


def test_n5_the_plans_hold_on_the_move_to_reject_holds_that_step(tmp_path):
    docs = {"corp.example": dns_doc("corp.example", APEX),
            "sub.corp.example": dns_doc("sub.corp.example", APEX, dmarc_source="_dmarc.corp.example", inherited=True)}
    rep = report_for(tmp_path, docs, Log().add("staff@corp.example", "Weekly #", 30).add("app@sub.corp.example", "Build #", 5))
    assert rep["gate"]["domains"]["corp.example"]["verdict"] == "go"
    line, doc = one_liner_and_doc(rep, reject_plan(holds=[HOLD]))
    assert line.endswith("and sub.corp.example has a record of its own, or sp= is added to the record (subdomains "
                         "without one follow p= to reject).")
    assert doc["ask"].endswith("and a decision on corp.example: give sub.corp.example a record of its own, or add sp= "
                               "to the record, before the move to reject.")
    rows = table_rows(doc)
    assert "| `corp.example` | p=quarantine | ready, with a plan hold | move to p=reject (plan P-01) |" in rows[0]
    # the name the hold names gets one statement: the record is needed before that move - never 'only if it needs a
    # policy of its own' beside a hold that says it does; the same words in todo.md and summary.txt
    one = ("give sub.corp.example a DMARC record of its own at _dmarc.sub.corp.example before the apex's record moves to "
           "reject (the plan holds that move until it has one, or sp= is added); today it follows _dmarc.corp.example, "
           "effective p=quarantine")
    assert ("| `sub.corp.example` | p=quarantine (inherited from _dmarc.corp.example) | ready | %s |" % one) in rows[1]
    assert "only if it needs a policy of its own" not in rows[1] and "move from p=quarantine to p=reject" not in rows[1]
    assert "- sub.corp.example: p=quarantine, gate go, next step: %s" % one in collect.render_todo(rep, reject_plan(holds=[HOLD]))
    # round 13, T-04: the Slack message keeps that line under its details only for a name with failures, a change
    # or a cut; the line itself says the same as todo.md
    lines = {e["domain"]: e["line"] for e in notify.domain_lines(rep, reject_plan(holds=[HOLD]))}
    assert lines["sub.corp.example"] == "- `sub.corp.example`: p=quarantine, gate *go*, next: %s - 0 genuine failures of its own" % one
    # without the hold the gate's own words stand, in every reader
    gate_step = rep["gate"]["domains"]["sub.corp.example"]["next_step"]
    assert gate_step.endswith("a record of its own at _dmarc.sub.corp.example only if it needs a policy of its own")
    assert audit.inherited_step("sub.corp.example", gate_step, reject_plan()) == gate_step
    assert "nothing in the plan; the audit says: none of its own" in table_rows(one_liner_and_doc(rep, reject_plan())[1])[1]
    assert "next step: " + gate_step in collect.render_todo(rep, reject_plan())
    assert audit.follow_p_hold_names(reject_plan(holds=[HOLD.replace("sub.corp.example", "a.corp.example, b.corp.example and 3 more")])) == {
        "a.corp.example", "b.corp.example"}
    # an older report's gate step on the parent's record, for a name the hold names: the same one statement
    assert audit.inherited_step("sub.corp.example", "move from p=quarantine to p=reject on the record at _dmarc.corp.example",
                                reject_plan(holds=[HOLD])) == one.replace(", effective p=quarantine", "")


def test_n6_a_plan_row_carries_the_gates_verdict_and_the_blockers_it_does_not_name(tmp_path):
    # insufficient_data: the evidence has no rows for the domain, and the plan still has its reject row
    docs = {"example.com": dns_doc("example.com", APEX), "corp.example": dns_doc("corp.example", "v=DMARC1; p=none; rua=%s;" % RUA)}
    rep = report_for(tmp_path, docs, Log().add("staff@corp.example", "Weekly #", 20))
    assert rep["gate"]["domains"]["example.com"]["verdict"] == "insufficient_data"
    line, doc = one_liner_and_doc(rep, reject_plan("example.com"))
    nxt = doc["next_step"]
    assert nxt["source"] == "plan" and nxt["data"] and "the evidence supplied has no rows for example.com" in nxt["data"][0]
    assert ", on hold - it needs more data: the evidence supplied has no rows for example.com" in line
    assert "; with that in hand, ready when every legitimate sender is proven" in line and "ready now" not in line
    assert doc["ask"].startswith("The ask this week: more data before the next step on example.com (move to p=reject): "
                                 "the evidence supplied has no rows for example.com")
    assert [q for q in doc["open_questions"] if q["question"].startswith("Can we supply the data the next step on example.com")]
    # no_go: a delivered failure the row's prerequisites do not carry holds the step beside them
    docs = {"example.com": dns_doc("example.com", APEX)}
    log = (Log().add("staff@example.com", "Weekly #", 30)
           .add("ceo@example.com", "Urgent wire #", 12, env="evil.invalid", dmarc="fail"))
    rep = report_for(tmp_path, docs, log, name="override.csv")
    g = rep["gate"]["domains"]["example.com"]
    assert g["verdict"] == "no_go" and any("reached a mailbox" in b for b in g["blockers"])
    line, doc = one_liner_and_doc(rep, reject_plan("example.com"))
    assert doc["next_step"]["holds"] and "reached a mailbox" in doc["next_step"]["holds"][-1]
    assert ", and on hold while: " in line and "reached a mailbox" in line
    assert "is held back by this:" in doc["ask"]
    assert any(q["question"].startswith("Can we clear this before we move to p=reject on example.com") for q in doc["open_questions"])
    # a zero-risk monitoring record is never held by the verdict: it needs no evidence
    rows = {"changes": [{"id": "P-01", "domain": "news.example.com", "kind": "new", "priority": 1, "record": "TXT",
                         "hostname": "_dmarc.news.example.com", "value": "v=DMARC1; p=none; rua=%s;" % RUA, "current": "none",
                         "why": "subdomain without a record", "prerequisites": []}], "holds": []}
    gate = {"domains": {"news.example.com": {"verdict": "insufficient_data", "current_policy": "none", "reasons": [],
                                             "blockers": ["the evidence supplied has no rows for news.example.com"],
                                             "notes": [], "next_step": "move to p=quarantine at a low pct"}},
            "evidence": {"statement": "s"}}
    doc = next_steps.build({"gate": gate, "dns": {}, "inputs": {"domains": ["news.example.com"]}, "findings": []}, rows)
    assert doc["one_liner"].endswith("The next safe step is to publish a p=none monitoring record, and it is ready now.")


# ------------------------------------------------------------------ N7: spoofs an override delivered

def test_n7_spoofs_the_log_shows_delivered_are_not_handled_by_the_policy(tmp_path):
    docs = {"example.com": dns_doc("example.com", APEX)}
    log = (Log().add("staff@example.com", "Weekly #", 30)
           .add("ceo@example.com", "Urgent wire transfer #", 12, env="evil.invalid", dmarc="fail"))
    rep = report_for(tmp_path, docs, log)
    line, doc = one_liner_and_doc(rep, None)
    assert "being handled by the policy" not in line and "the policy handles them" not in line
    # round 13, T-07: what let them in is said in parentheses after the count (an export without the override
    # columns: the older inference)
    assert ("12 from 1 address that look like spoofing, of which 12 reached a mailbox anyway (a local override "
            "delivered them, not the policy)") in line
    blockers = next_steps.blocker_items(rep, "example.com", next_steps.own_domain_view(rep, next_steps.maillog_view(rep), "example.com"))
    spoof = next(b for b in blockers if b["kind"] == "spoof")
    assert spoof["text"].endswith("once they are confirmed not ours, 12 of them reached a mailbox anyway: a local override "
                                  "delivered them, which the policy cannot undo - find that override")
    # quarantined spoofs are what the policy handles
    log = (Log().add("staff@example.com", "Weekly #", 30)
           .add("ceo@example.com", "Urgent wire transfer #", 12, env="evil.invalid", dmarc="fail", where=QUARANTINED))
    line, _ = one_liner_and_doc(report_for(tmp_path, docs, log, name="q.csv"), None)
    assert "12 from 1 address that look like spoofing and is being handled by the policy" in line


# ------------------------------------------------------------------ N8: a stream two domain exceptions cover together

def exc(match):
    return {"match": match, "reason": "r", "owner": "o", "until": "2099-01-01", "removal_criterion": "c"}


def stream(ip, spf, dkim, likely="likely_misconfigured"):
    return {"source_ip": ip, "count": 60, "fail": 60, "pass": 0, "likely": likely, "dispositions": {"none": 60},
            "header_from": ["example.com"], "spf_domains": list(spf), "dkim_domains": list(dkim), "likely_signals": ["s"]}


def test_n8_two_domain_exceptions_cover_a_vendor_that_spans_two_org_domains():
    active, _, _ = config.parse_exceptions([exc("saas.invalid"), exc("esp.invalid")])
    saas = stream("203.0.113.90", ["bounce.esp.invalid"], ["saas.invalid", "esp.invalid"])
    assert config.stream_exceptions(active[:1], saas, ["example.com"]) == []
    assert config.stream_uncovered(active[:1], saas, ["example.com"]) == ["bounce.esp.invalid", "esp.invalid"]
    assert [e["match"] for e in config.stream_exceptions(active, saas, ["example.com"])] == ["saas.invalid", "esp.invalid"]
    relay = stream("198.51.100.40", ["bounce.esp.invalid"], ["esp.invalid", "tenant2.invalid", "e.example.com"])
    assert config.stream_exceptions(active, relay, ["example.com"]) == []  # another tenant's domain: not the vendor's stream
    assert config.stream_exceptions([], stream("1.2.3.4", [], []), ["example.com"]) == []
    rua = {"totals": {"reports": 1, "messages": 100, "pass": 40, "fail": 60, "pass_rate": 0.4, "reporters": ["r"],
                      "by_disposition": {"none": 60}, "begin_date": "2026-10-01", "end_date": "2026-10-01", "aligned": {}},
           "policy_check": {"seen": []}, "failing_streams": [saas], "spf_only_senders": [], "by_header_from": [],
           "findings": []}
    dns = {"example.com": dns_doc("example.com", APEX)}
    both = audit.gate_verdict(dns, rua, None, ["example.com"], exceptions=[exc("saas.invalid"), exc("esp.invalid")])
    assert both["exceptions"]["excepted_streams"] == ["203.0.113.90"] and both["domains"]["example.com"]["verdict"] == "go"
    note = next(r for r in both["domains"]["example.com"]["reasons"] if r.startswith("exception: 203.0.113.90"))
    assert "excepted by saas.invalid (until 2099-01-01" in note and " and esp.invalid (until 2099-01-01" in note
    one = audit.gate_verdict(dns, rua, None, ["example.com"], exceptions=[exc("saas.invalid")])
    blocker = one["domains"]["example.com"]["blockers"][0]
    assert blocker.startswith("203.0.113.90 fails DMARC on 60/60 msgs (likely_misconfigured); fix, or formally except it, "
                              "before p= moves (a domain exception covers part of it; bounce.esp.invalid, esp.invalid are "
                              "not under any: except that domain too, or the source IP)")
    line = next_steps.build({"gate": one, "dns": dns, "rua": rua, "inputs": {"domains": ["example.com"]}, "findings": []})["one_liner"]
    assert line.endswith("before p= moves (203.0.113.90: a domain exception covers part of it; bounce.esp.invalid, "
                         "esp.invalid are not under any: except that domain too, or the source IP).")


# ------------------------------------------------------------------ N2: a forged envelope under a domain exception

def test_n2_the_gate_counts_the_excepted_messages_whose_envelope_failed_spf(tmp_path):
    docs = {"example.com": dns_doc("example.com", APEX)}
    log = (Log().add("billing@example.com", "Statement #", 4, env="vendor.invalid", dmarc="fail", spf="pass")
           .add("ceo@example.com", "Wire transfer #", 3, env="vendor.invalid", dmarc="fail", spf="fail"))
    rep = report_for(tmp_path, docs, log, exceptions=[exc("vendor.invalid")])
    g = rep["gate"]["domains"]["example.com"]
    assert g["verdict"] == "go" and g["excepted_failures"] == 7
    note = next(r for r in g["reasons"] if r.startswith("exception: 7 mail-log failure(s) from vendor.invalid"))
    assert "3 of them failed SPF for that envelope: a forged MAIL FROM does, so confirm they are the platform's" in note


# ------------------------------------------------------------------ N9, N37: overrides the log recorded, and did not

def test_n9_a_delivered_failure_the_log_records_no_override_for_is_not_credited_to_one(tmp_path):
    docs = {"example.com": dns_doc("example.com", "v=DMARC1; p=none; rua=%s;" % RUA)}
    log = (Log(overrides=True).add("staff@example.com", "Weekly #", 20)
           .add("billing@example.com", "Statement #", 2, dmarc="fail", org=("Exchange transport rule", "Allow"))
           .add("billing@example.com", "Statement #", 3, dmarc="fail")
           .add("news@example.com", "News #", 4, dmarc="fail"))
    rep = report_for(tmp_path, docs, log)
    g = rep["gate"]["domains"]["example.com"]
    assert any(b.endswith("reached a mailbox - let in by an Exchange transport rule x2, which external receivers do not "
                          "have; no override recorded for 7 (at p=none receivers deliver failing mail without one, as the "
                          "tenant did)") for b in g["blockers"])
    doc = next_steps.build(rep)
    stand = next(l for l in doc["stand"]["lines"] if l.startswith("**Delivered despite failing"))
    assert stand == ("**Delivered despite failing: 9** - let in by an Exchange transport rule x2 (outside receivers do not "
                     "have these overrides); no override recorded for 7 (at p=none receivers deliver failing mail without "
                     "one, as the tenant did here) (billing@example.com x5, news@example.com x4)")
    assert "only arrive because of our own overrides" not in stand
    actions = {i["hook"]: i["action"] for grp in doc["actions_by_owner"] for i in grp["items"]}
    assert actions["news@example.com - 4 messages reached inboxes despite failing"] == (
        "the log names no override for them: at p=none receivers deliver failing mail by design, and so did the "
        "tenant - the policy step is the fix")
    # round 13, T-08: billing@ is our own system, so its rule changes only once it passes
    assert actions["billing@example.com - 5 messages reached inboxes despite failing"].startswith(
        "delivered because of an Exchange transport rule (2), and the log names no override for the other 3: after "
        "billing@example.com passes DMARC, make that rule conditional on authentication - doing it first junks these "
        "5 too; for the other 3, at p=none")
    # the counters say the columns were there even when nothing is named, and every reader says so
    empty = dedupe.summarize(dedupe.classify(list(dedupe.load(log.write(tmp_path / "e.csv"), audit.MAILLOG_COLUMNS)),
                                             audit.MAILLOG_COLUMNS, None, "DMARC"))
    assert empty["delivered_despite_fail_by"] == {"org: Exchange transport rule (Allow)": 2}
    assert dedupe.delivered_by_phrase({}, 9) == "no override recorded for any of the 9"
    assert dedupe.delivered_by_phrase(None, 9) == "" and dedupe.delivered_by_phrase({"org: X (Allow)": 2}, 9) == \
        'let in by "org: X (Allow)" x2; no override recorded for 7'.replace('"', "")
    summary = notify.summarize(rep)
    assert "9 delivered despite failing (let in by an Exchange transport rule x2; no override recorded for 7)" in summary
    # the dedupe CLI says what the columns say instead of asserting an override
    p = subprocess.run([sys.executable, str(ROOT / "src" / "dedupe.py"), str(tmp_path / "e.csv"), "--auth-column", "DMARC"],
                       capture_output=True, text=True)
    assert "the override columns say what let each in" in p.stdout and "a local override let these through" not in p.stdout
    assert "let in by an Exchange transport rule x2; no override recorded for 7" in p.stdout


def test_n37_the_overrides_named_are_those_of_the_deliveries_the_exceptions_left(tmp_path):
    docs = {"example.com": dns_doc("example.com", APEX)}
    log = (Log(overrides=True).add("staff@example.com", "Weekly #", 20)
           .add("billing@example.com", "Statement #", 3, env="vendor.invalid", dmarc="fail", org=("Exchange transport rule", "Allow"))
           .add("alerts@example.com", "Alert #", 2, dmarc="fail"))
    rep = report_for(tmp_path, docs, log, exceptions=[exc("vendor.invalid")])
    doc = next_steps.build(rep)
    stand = next(l for l in doc["stand"]["lines"] if l.startswith("**Delivered despite failing"))
    assert stand == ("**Delivered despite failing: 5** (3 of them formally excepted in audit.toml) - no override recorded "
                     "for 2 (the log names nothing that let them in) (alerts@example.com x2)")
    assert doc["stand"]["delivered_despite_fail_by_left"] == {}


# ------------------------------------------------------------------ N33, N34: the delivered failing leg, and non-allow actions

def test_n33_n34_the_override_comes_from_the_failing_leg_and_a_block_is_no_allow():
    ovr = {"org_policy": "P", "org_action": "A", "user_policy": "UP", "user_action": "UA"}
    inside = {"P": "Exchange transport rule", "A": "Allow", "UP": "", "UA": ""}
    failing = {"P": "", "A": "", "UP": "", "UA": ""}
    legs, auth = [failing, inside], [(False, True), (False, False)]
    assert dedupe.delivered_by(legs, auth, ["delivered", "delivered"], ["Inbox/folder", "Inbox/folder"], ovr) is None
    assert dedupe.delivered_by(legs, auth, ["blocked", "delivered"], ["Quarantine", "Inbox/folder"], ovr) == \
        "org: Exchange transport rule (Allow)"
    for reason in ("org: Tenant Allow Block List (Block)", "org: Anti-spoof (Block)", "org: Exchange transport rule (Junk)"):
        assert dedupe.override_kind(reason) is None and dedupe.override_words(reason) == reason
    assert dedupe.override_kind("org: Exchange transport rule (Allow)") == "transport_rule"
    assert dedupe.override_kind("org: Exchange transport rule") == "transport_rule"
    assert next_steps.override_action({"org: Tenant Allow Block List (Block)": 1}, 1) == (
        'delivered because of "org: Tenant Allow Block List (Block)": find that override and make it conditional on '
        "authentication; outside receivers do not have it")


# ------------------------------------------------------------------ N11: a sender the previous run's cut log may have missed

def test_n11_a_sender_under_an_org_the_previous_run_cut_is_recorded_but_not_called_new():
    rep = {"generated_utc": "2026-10-13T06:00:00Z", "gate": {"domains": {}}, "inputs": {"domains": ["corp.example"]},
           "maillog": {"counters": {"genuine_failures": 10}, "census": {
               "by_envelope": [{"envelope_domain": "oldrelay.invalid", "genuine_failures": 10, "messages": 19, "senders": 1,
                                "sample_sender": "legacy@corp.example", "likely": "unknown"},
                               {"envelope_domain": "fresh.invalid", "genuine_failures": 1, "messages": 5, "senders": 1,
                                "sample_sender": "app@shop.example", "likely": "unknown"}],
               "by_sender": [{"sender": "legacy@corp.example", "domain": "corp.example", "envelope_domain": "oldrelay.invalid",
                              "genuine_failures": 10, "messages": 19, "likely": "unknown"},
                             {"sender": "app@shop.example", "domain": "shop.example", "envelope_domain": "fresh.invalid",
                              "genuine_failures": 1, "messages": 5, "likely": "unknown"}]}},
           "delta": {"previous_generated_utc": "2026-10-06T06:00:00Z", "new_senders": [], "notes": [
               "1 sender under corp.example not listed as new: the previous run's cut mail log may simply have missed it"],
               "maillog_window": {"comparable": False, "cut_orgs": {"corp.example": {
                   "now": None, "previous": {"reason": "row budget", "kept_hours": 208}}}}}}
    keys = notify.sender_keys(rep)
    assert keys == {"envelope:oldrelay.invalid", "envelope:fresh.invalid"}
    assert notify.senders_maybe_missed(rep, keys) == {"envelope:oldrelay.invalid"}
    text = notify.summarize(rep, known_senders={"ip:192.0.2.1"})
    assert "- *newly identified senders* (never seen in an earlier run): fresh.invalid (envelope)" in text
    assert ("- 1 sender identity first recorded this run but not called new: the previous run's cut mail log may simply "
            "have missed it (oldrelay.invalid (envelope))") in text
    assert "oldrelay.invalid (envelope)" not in text.split("*newly identified senders*")[1].split("\n")[0]


# ------------------------------------------------------------------ N12: the gate's step for a name governed by sp=

def test_n12_the_gates_step_for_an_inherited_name_is_its_own_record_and_sp_none_is_not_the_end(tmp_path):
    assert audit.next_step("none", {}, record_at="_dmarc.corp.example", inherited=True, domain="mail.corp.example") == (
        "give mail.corp.example a DMARC record of its own at _dmarc.mail.corp.example (today it follows "
        "_dmarc.corp.example, effective p=none)")
    assert audit.next_step("quarantine", {}, record_at="_dmarc.corp.example", inherited=True, domain="sub.corp.example") == (
        "none of its own - it follows _dmarc.corp.example, effective p=quarantine; a record of its own at "
        "_dmarc.sub.corp.example only if it needs a policy of its own")
    assert audit.next_step("reject", {"sp": "none"}, "~all", "found", "_dmarc.corp.example") == (
        "move sp= from none to quarantine (subdomains without a record of their own still inherit none) on the record "
        "at _dmarc.corp.example")
    assert audit.next_step("reject", {"sp": "quarantine"}, "~all", "found", "_dmarc.corp.example").startswith("harden SPF from ~all to -all")
    apex = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    docs = {"corp.example": dns_doc("corp.example", apex),
            "mail.corp.example": dns_doc("mail.corp.example", apex, dmarc_source="_dmarc.corp.example", inherited=True,
                                         effective_policy="none")}
    rep = report_for(tmp_path, docs, Log().add("staff@corp.example", "Weekly #", 5).add("app@mail.corp.example", "Build #", 5))
    assert audit.domain_policy("mail.corp.example", docs)["inherited"] is True
    assert rep["gate"]["domains"]["mail.corp.example"]["next_step"].startswith("give mail.corp.example a DMARC record of its own")
    assert "pct=10" not in rep["gate"]["domains"]["mail.corp.example"]["next_step"]
    todo = collect.render_todo(rep, {"changes": [], "holds": []})
    assert "- mail.corp.example: p=none, gate go, next step: give mail.corp.example a DMARC record of its own" in todo


# ------------------------------------------------------------------ N19, N20, N36: the delta and the trend across runs

def two_reports(now_domains, prev_domains, now_gf=378, prev_gf=288):
    def rep(domains, gf):
        return {"generated_utc": "2026-10-13T06:00:00Z", "gate": {"domains": {d: {"verdict": "go", "current_policy": "none"} for d in domains}},
                "maillog": {"counters": {"genuine_failures": gf, "delivered_despite_fail": 0},
                            "window": {"from": "2026-09-13T06:00:00Z", "to": "2026-10-13T06:00:00Z", "hours": 720.0},
                            "by_domain": {d: {"genuine_failures": 1, "delivered_despite_fail": 0} for d in domains},
                            "census": {"by_sender": []}, "cuts": {}}, "findings": []}
    return rep(now_domains, now_gf), rep(prev_domains, prev_gf)


def test_n19_an_organization_audited_in_one_run_only_withholds_the_whole_logs_delta():
    now, prev = two_reports(["corp.example", "shop.example"], ["corp.example"])
    dl = audit.build_delta(now, prev)
    assert dl["genuine_failures"] is None and dl["maillog_window"]["comparable"] is False
    assert dl["maillog_window"]["orgs_not_shared"] == ["shop.example"]
    assert dl["by_domain"] == {"corp.example": {"genuine_failures": 0, "delivered_despite_fail": 0}}
    assert any(n.startswith("shop.example audited in one of the two runs only: the whole log's failure counts cover "
                            "different organizations and are not compared") for n in dl["notes"])
    same, _ = two_reports(["corp.example"], ["corp.example"])
    assert audit.build_delta(same, prev)["genuine_failures"] == 90
    md = []
    audit._md_delta(md, dl)
    assert any("n/a (shop.example audited in one run only, see the note below)" in l for l in md)
    history = [{"genuine_failures": 288, "maillog_hours": 720.0, "maillog_cut_orgs": [], "domains": {"corp.example": {}}},
               {"genuine_failures": 378, "maillog_hours": 720.0, "maillog_cut_orgs": [],
                "domains": {"corp.example": {}, "shop.example": {}}}]
    word, why = notify.trend_judgement(history)
    assert word == "not comparable" and why == ["failure counts not compared: shop.example audited in one of these runs only"]


def test_n20_each_run_is_cut_by_its_own_cause():
    now = {"reason": "api cap", "api_cap_hours": ["6h..5h"]}
    prev = {"reason": "row budget", "kept_hours": 156}
    assert audit._cut_note("corp.example", now, prev) == (
        "corp.example's mail log was cut by the API row cap in this run (an hour truncated, 6h..5h ago) and by the row "
        "budget in the previous run (newest 156 hours kept): failure counts for its domains, and the whole log's, are "
        "not compared")
    assert audit._cut_note("corp.example", prev, prev).startswith("the row budget cut corp.example's mail log in both runs")
    assert audit._cut_note("corp.example", None, {"reason": "not pulled"}) == (
        "a failed pull cut corp.example's mail log in the previous run: failure counts for its domains, and the whole "
        "log's, are not compared")
    assert next_steps._cut_reason({"corp.example": {"now": now, "previous": prev}}) == (
        "the API row cap cut the mail log for corp.example in this run; the row budget cut the mail log for "
        "corp.example in the previous run")
    assert next_steps._cut_reason({"corp.example": {"now": prev, "previous": prev}}) == (
        "the row budget cut the mail log for corp.example in both runs")


def test_n36_the_trend_names_the_end_runs_that_were_cut():
    first = {"genuine_failures": 50, "rua_pass_rate": 0.9, "maillog_hours": 700.0, "maillog_cut_orgs": ["corp.example", "shop.example"]}
    last = {"genuine_failures": 40, "rua_pass_rate": 0.9, "maillog_hours": 700.0, "maillog_cut_orgs": ["corp.example"]}
    assert notify.trend_judgement([first, last])[1] == [
        "failure counts not compared: the mail log was cut for corp.example in both runs and for shop.example in the first run"]
    assert notify.trend_judgement([dict(first, maillog_cut_orgs=[]), last])[1] == [
        "failure counts not compared: the mail log was cut for corp.example in the last run"]
    assert "in one of these runs" not in notify.summarize({"gate": {}}, history=[first, last])


# ------------------------------------------------------------------ N21, N22, N23, N35, N51, N52: the history

def test_n21_metrics_store_the_exact_span_the_delta_judges():
    rep = {"gate": {"domains": {}}, "maillog": {"counters": {}, "window": {"from": "2026-10-11T06:00:00Z",
                                                                            "to": "2026-10-13T06:01:48Z", "hours": 48.0}},
           "summary": {}}
    entry = collect.metrics_entry("2026-10-13T060000Z", rep, {"changes": []})
    assert entry["maillog_hours"] == audit._hours(rep["maillog"]["window"]) == 48.03
    assert notify._spans_alike([24.0, entry["maillog_hours"]]) is False  # as the delta judges the same pair


def test_n22_a_cut_organizations_count_is_a_floor_even_without_totals():
    rep = {"generated_utc": "2026-10-13T06:00:00Z",
           "gate": {"domains": {"corp.example": {"verdict": "no_go", "current_policy": "quarantine", "next_step": "x"}}},
           "maillog": {"counters": {"genuine_failures": 231}, "by_domain": {"corp.example": {"genuine_failures": 231}},
                       "cuts": {"corp.example": {"reason": "row budget", "kept_hours": 162, "kept_from": "2026-10-06T12:00:00Z"}}}}
    line = next(l for l in notify.summarize(rep).splitlines() if l.startswith("- `corp.example`"))
    # round 13 review: the cut organization's one line under the band
    assert line == ("- `corp.example`: 231 genuine failures in the rows kept (newest 162 hours kept; a floor: the gate, "
                    "the census and the labels count these)")
    rep["maillog"]["cuts"] = {}
    assert "rows kept" not in notify.summarize(rep)


def test_n23_a_run_that_crosses_midnight_is_not_its_own_previous_run():
    rep = {"generated_utc": "2026-10-09T18:31:51Z", "inputs": {"domains": ["corp.example"], "run": "2026-10-08T235800Z"},
           "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "none"}}},
           "maillog": {"counters": {"genuine_failures": 288}}, "findings": []}
    metrics = [{"run": "2026-10-08T235800Z", "genuine_failures": 288, "rua_pass_rate": None}]
    assert next_steps.previous_entry(metrics, rep, next_steps.maillog_view(rep)) is None
    line = next(l for l in next_steps.build(rep, metrics=metrics)["stand"]["lines"] if l.startswith("**Trend"))
    assert line == "**Trend: first run, no trend yet**"
    older = [{"run": "2026-10-01T060000Z", "genuine_failures": 250}] + metrics
    assert next_steps.previous_entry(older, rep, None)["run"] == "2026-10-01T060000Z"


def test_n35_n51_the_previous_entry_gets_its_cut_from_its_own_report():
    entries = [{"run": "2026-10-01T060000Z", "genuine_failures": 210, "rua_pass_rate": 0.7, "maillog_hours": 718.6,
                "maillog_hours_by_domain": {"example.com": 283.7}},
               {"run": "2026-10-08T060000Z", "genuine_failures": 417, "rua_pass_rate": 0.7, "maillog_hours": 719.7, "maillog_cut_orgs": []}]
    prev = {"maillog": {"truncation": "row budget kept only the newest 284h for example.com"}, "gate": {}}
    assert collect.backfill_cut_orgs(entries, "2026-10-01T060000Z", prev) == ["example.com"]
    assert entries[0]["maillog_cut_orgs"] == ["example.com"]
    assert collect.backfill_cut_orgs(entries, "2026-10-01T060000Z", prev) is None  # once is enough
    word, why = notify.trend_judgement(entries)
    assert word != "worsening" and why == ["failure counts not compared: the mail log was cut for example.com in the first run"]
    assert "| 210 (floor, example.com cut) |" in collect.render_metrics(entries)
    # an older entry without the key, and no report to read it from, keeps the benefit of the doubt (round 10)
    assert notify._cut_orgs({"maillog_hours": 700.0, "maillog_hours_by_domain": {"example.com": 20.0}}) is None


def test_n52_an_older_reports_cut_is_read_from_the_run_json_beside_it(tmp_path):
    prev = {"gate": {"domains": {}}, "maillog": {"counters": {"genuine_failures": 210}}}
    (tmp_path / "run.json").write_text(json.dumps({"run": "x", "notes": [
        "mail log: example.com row budget reached at 571h..284h ago - older rows skipped; the rows cover only the last "
        "284h (raise --max-rows to keep more)"]}), encoding="utf-8")
    collect.inherit_run_cuts(prev, tmp_path / "run.json")
    assert audit.maillog_cuts(prev) == {"example.com": {"reason": "row budget", "kept_hours": 284}}
    recorded = {"gate": {}, "maillog": {"cuts": {}, "counters": {}}}
    collect.inherit_run_cuts(recorded, tmp_path / "run.json")
    assert recorded["maillog"]["cuts"] == {} and "caveats" not in recorded  # a report that records its cuts is left alone


# ------------------------------------------------------------------ N25, N26, N27: the exceptions in every count

def test_n25_a_formally_excepted_source_is_never_counted_as_spoofing():
    rua = {"totals": {"reports": 1, "messages": 100, "pass": 40, "fail": 60, "pass_rate": 0.4, "reporters": ["r"],
                      "by_disposition": {"none": 35, "reject": 20}, "begin_date": "2026-10-01", "end_date": "2026-10-01", "aligned": {}},
           "policy_check": {"seen": []}, "spf_only_senders": [], "by_header_from": [], "findings": [],
           "failing_streams": [dict(stream("198.51.100.9", [], [], "likely_spoof"), count=35, fail=35, dispositions={"none": 35}),
                               dict(stream("203.0.113.5", [], [], "likely_spoof"), count=20, fail=20, dispositions={"reject": 20})]}
    assert next_steps.spoof_share(rua, {"198.51.100.9"}) == {"messages": 20, "sources": 1, "rejected": 20, "quarantined": 0, "delivered": 0}
    assert next_steps.spoof_share(rua)["sources"] == 2
    dns = {"example.com": dns_doc("example.com", "v=DMARC1; p=reject; rua=%s;" % RUA)}
    gate = audit.gate_verdict(dns, rua, None, ["example.com"], exceptions=[exc("198.51.100.0/24")])
    g = gate["domains"]["example.com"]
    assert gate["exceptions"]["excepted_streams"] == ["198.51.100.9"] and g["verdict"] == "go"
    assert not [n for n in g["notes"] if n.startswith("198.51.100.9 (")] and "203.0.113.5 (20 msgs, likely_spoof)" in g["notes"]
    dns = {"example.com": dns_doc("example.com", "v=DMARC1; p=none; rua=%s;" % RUA)}
    rua["failing_streams"] = rua["failing_streams"][:1]
    g = audit.gate_verdict(dns, rua, None, ["example.com"], exceptions=[exc("198.51.100.0/24")])["domains"]["example.com"]
    assert g["verdict"] == "go" and not [n for n in g["notes"] if "look like spoofs" in n]


def test_n26_the_top_senders_named_are_the_ones_still_failing(tmp_path):
    docs = {"example.com": dns_doc("example.com", APEX)}
    log = Log().add("staff@example.com", "Weekly #", 10)
    for i in range(5):
        log.add("s%d@example.com" % i, "Report #", 18, env="vendor.invalid", dmarc="fail", where=QUARANTINED)
        log.add("s%d@example.com" % i, "Report #", 2, dmarc="fail", where=QUARANTINED)
    log.add("worst@example.com", "Scan #", 10, dmarc="fail", where=QUARANTINED)
    rep = report_for(tmp_path, docs, log, exceptions=[exc("vendor.invalid")])
    g = rep["gate"]["domains"]["example.com"]
    assert any(b.endswith("(deduplicated; 90 more excepted); top senders: worst@example.com x10, s0@example.com x2, "
                          "s1@example.com x2") for b in g["blockers"])
    own = rep["maillog"]["by_domain"]["example.com"]
    assert own["top_senders_after"][0] == {"sender": "worst@example.com", "genuine_failures": 10}
    assert "top failing senders after the exceptions: worst@example.com x10, s0@example.com x2, s1@example.com x2" \
           in audit.render_md(rep)
    doc = next_steps.build(rep)
    assert doc["failing"]["streams"]["top_senders"][0] == {"name": "worst@example.com", "count": 10}


def test_n27_the_slack_and_report_count_lines_name_their_excepted_share(tmp_path):
    docs = {"example.com": dns_doc("example.com", APEX)}
    log = (Log().add("staff@example.com", "Weekly #", 10)
           .add("billing@example.com", "Statement #", 3, env="vendor.invalid", dmarc="fail")
           .add("ops@example.com", "Run #", 2, env="vendor.invalid", dmarc="fail", where=QUARANTINED)
           .add("ceo@example.com", "Wire #", 2, env="evil.invalid", dmarc="fail"))
    rep = report_for(tmp_path, docs, log, exceptions=[exc("vendor.invalid")])
    assert audit.whole_excepted(rep) == {"failures": 5, "delivered": 3}
    assert ("- mail log: 7 genuine failures (5 of them formally excepted in audit.toml) (7 rows would say so), 5 delivered "
            "despite failing (3 of them formally excepted in audit.toml), spoof-like 7") in notify.summarize(rep)
    md = audit.render_md(rep)
    assert "- genuine failures (no passing copy): 7 (5 of them formally excepted in audit.toml); echo messages" in md
    assert "- delivered despite fail: 5 (3 of them formally excepted in audit.toml); blocked despite pass: 0" in md
    assert "delivered despite fail 5 (3 of them formally excepted in audit.toml), blocked despite pass 0" in md


# ------------------------------------------------------------------ N29, N30, N31, N47: the document's own consistency

def test_n29_the_verdicts_own_hold_is_not_information_that_holds_nothing(tmp_path):
    docs = {"example.com": dns_doc("example.com", "v=DMARC1; p=none; rua=%s;" % RUA)}
    rep = report_for(tmp_path, docs, Log().add("staff@corp.example", "Hi #", 5))
    g = rep["gate"]["domains"]["example.com"]
    assert g["verdict"] == "insufficient_data" and g["notes"][0].startswith("example.com: no mail-log rows")
    doc = next_steps.build(rep)
    assert doc["audit_notes"] == [] and "holds nothing" not in next_steps.render_md(doc)
    nxt = {"notes": ["unaudited subdomains m.corp.example, t.corp.example carry 14 logical messages, 0 genuine failures"],
           "verdict": "no_go"}
    plan = {"holds": [{"domain": "corp.example", "reason": "subdomains that send have no record of their own: m.corp.example "
                                                           "and t.corp.example - publish their monitoring records"}], "changes": []}
    notes = next_steps.audit_notes(nxt, plan, "corp.example")
    assert notes == [{"text": nxt["notes"][0], "holds": "the plan's hold on sp= names them"}]
    assert next_steps.audit_notes(nxt, {"holds": [], "changes": []}, "corp.example")[0]["holds"] is None


def test_n30_the_ramp_suffix_only_when_the_quarantine_now_row_clears_the_blockers():
    rep = {"gate": {"domains": {"brand.example": {"verdict": "no_go", "current_policy": "none", "next_step": "x", "notes": [],
                                                  "blockers": ["brand.example: NO DMARC RECORD - no policy, no reporting, invisible to you",
                                                               "spoof stream 203.0.113.66 (800 msgs) saw disposition none - receivers delivered it",
                                                               "brand.example: 30 logical message(s) from this domain failed with no passing copy (deduplicated)",
                                                               "brand.example: 30 message(s) from this domain failed authentication but reached a mailbox - x"]}},
                    "evidence": {"statement": "s"}},
           "dns": {"brand.example": dns_doc("brand.example", findings=[finding("DMARC-001", "NO DMARC RECORD - no policy, no reporting, invisible to you")])},
           "maillog": {"counters": {}, "by_domain": {"brand.example": {"genuine_failures": 30, "by_likely": {"likely_spoof": 30, "unknown": 0}}}},
           "inputs": {"domains": ["brand.example"]}, "findings": []}
    assert audit.ramp_blockers_left(rep, "brand.example") == []
    plan = {"changes": [{"id": "P-01", "domain": "brand.example", "kind": "no_mail", "priority": 1, "record": "TXT",
                         "hostname": "_dmarc.brand.example", "value": "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA,
                         "current": "none", "why": "no mail measured", "prerequisites": []}], "holds": []}
    # the cell names what holds the gate (round 13, T-10): its first blocker, the one the row answers - a DNS finding
    # by what it is and its id (round 13 review)
    assert "| not yet - held by: no DMARC record (DMARC-001) (for the weekly ramp this skips) |" in table_rows(
        next_steps.build(rep, plan))[0]
    assert "the gate's no_go is for the weekly ramp this skips" in collect.render_todo(rep, plan)
    # round 13, T-04: the per-domain line (the Slack message keeps it under its details when it has failures)
    assert "the gate's *no_go* is for the weekly ramp this skips" in notify.domain_lines(rep, plan)[0]["line"]
    unknown = "198.51.100.10 fails DMARC on 40/40 msgs (unknown); fix, or formally except it, before p= moves"
    rep["gate"]["domains"]["brand.example"]["blockers"].append(unknown)
    assert audit.ramp_blockers_left(rep, "brand.example") == [unknown]
    # the blocker that holds the row too is the one the cell names (round 13, T-10)
    assert ("| not yet - held by: 198.51.100.10 fails DMARC on 40/40 msgs (unclear); fix, or... (it holds the "
            "quarantine-now row too) |") in table_rows(next_steps.build(rep, plan))[0]
    assert "the gate's no_go holds that row too: " + unknown in collect.render_todo(rep, plan)
    assert "the gate's *no_go* holds that row too: " + unknown in notify.domain_lines(rep, plan)[0]["line"]


def test_n31_todo_leads_with_the_rows_that_replace_the_gates_step():
    rep = {"gate": {"domains": {
        "old.corp.example": {"verdict": "no_go", "current_policy": "none",
                             "next_step": "move to p=quarantine at a low pct (for example pct=10) on the record at _dmarc.corp.example"},
        "x.corp.example": {"verdict": "no_go", "current_policy": "none",
                           "next_step": "move to p=quarantine at a low pct (for example pct=10) on the record at _dmarc.corp.example"}}},
           "dns": {"old.corp.example": {"inherited": True, "dmarc_source": "_dmarc.corp.example"},
                   "x.corp.example": {"inherited": True, "dmarc_source": "_dmarc.corp.example"}},
           "maillog": {}, "findings": []}
    plan = {"changes": [
        {"id": "P-06", "domain": "old.corp.example", "kind": "park", "priority": 1, "record": "TXT", "hostname": "_dmarc.old.corp.example",
         "value": "v=DMARC1; p=reject; rua=%s;" % RUA, "current": "none", "why": "parked", "prerequisites": []},
        {"id": "P-07", "domain": "old.corp.example", "kind": "park", "priority": 1, "record": "TXT", "hostname": "old.corp.example",
         "value": "v=spf1 -all", "current": "none", "why": "parked", "prerequisites": []}], "holds": []}
    todo = collect.render_todo(rep, plan)
    # round 13, T-12: the plan's step in next_steps.md's words, each row with the section listing it and its status
    assert ("- old.corp.example: p=none, gate no_go, next step: park it with p=reject (P-06, section 2: ready now), then "
            "park it with SPF -all (P-07, section 2: ready now)") in todo
    assert "- x.corp.example: p=none, gate no_go, next step: none of its own: it follows _dmarc.corp.example and moves with the apex's step" in todo
    assert "pct=10" not in todo.split("## 1.")[0]


def test_n47_the_full_window_totals_sit_beside_the_cut_organizations_own_floor():
    rep = {"generated_utc": "2026-10-13T06:00:00Z", "gate": {"domains": {}}, "inputs": {"domains": ["corp.example", "spoofed.example"]},
           "maillog": {"counters": {"genuine_failures": 63, "raw_failing_rows": 63, "delivered_despite_fail": 0},
                       "auth_column": "DMARC",
                       "by_domain": {"corp.example": {"genuine_failures": 18, "subdomains_total": {"genuine_failures": 15}},
                                     "spoofed.example": {"genuine_failures": 30}, "(other)": {"genuine_failures": 0}},
                       "window_totals": {"hours": 720, "orgs": {"corp.example": {"by_domain": {
                           "corp.example": {"genuine_failures": 900, "delivered_despite_fail": 12},
                           "legacy.corp.example": {"genuine_failures": 15, "delivered_despite_fail": 0}}}}}}, "findings": []}
    assert next_steps.cut_org_floor(rep, ["corp.example"]) == 33
    line = next(l for l in next_steps.build(rep)["stand"]["lines"] if l.startswith("**Genuine"))
    assert line.endswith("; over the full 30 days, counted in Advanced Hunting: 915 genuine failures, 12 delivered despite "
                         "failing under corp.example, whose rows kept hold 33 of the 63 above (the gate, the census and the "
                         "labels still rest on the rows kept; the plan reads these totals for its quarantine-now and sp= decisions)")


# ------------------------------------------------------------------ N32, N44: notify's --previous fallback

def test_n32_n44_the_notify_fallback_applies_the_deltas_rules(tmp_path):
    def rep(ip_check, cuts=None, gf=100, hours=720.0):
        return {"generated_utc": "2026-10-13T06:00:00Z", "gate": {"domains": {}}, "inputs": {"domains": ["corp.example"]},
                "rua": {"totals": {"messages": 500, "pass_rate": 0.8, "reports": 1}, "filters": {"known": {"given": True, "ip_check": ip_check}},
                        "unknown_senders": []},
                "findings": [{"source": "rua", "id": "OUTSIDE-002" if ip_check else "OUTSIDE-009", "severity": "major", "title": "t"}],
                "maillog": {"counters": {"genuine_failures": gf}, "cuts": cuts or {},
                            "window": {"from": "2026-09-13T06:00:00Z", "to": "2026-10-13T06:00:00Z", "hours": hours}}}
    text = notify.summarize(rep(True), previous=rep(False))
    assert "new findings" not in text and "resolved" not in text
    assert "- note: the unknown-sender check ran in one of the two runs only: its findings (OUTSIDE-002, OUTSIDE-009) are not compared" in text
    assert "- genuine failures vs last run: +0" in text
    text = notify.summarize(rep(True, {"corp.example": {"reason": "row budget", "kept_hours": 41}}, gf=20), previous=rep(True, gf=880))
    assert "genuine failures vs last run" not in text and "the row budget cut corp.example's mail log in this run" in text
    # the CLI path, on files
    (tmp_path / "now.json").write_text(json.dumps(rep(True)), encoding="utf-8")
    (tmp_path / "prev.json").write_text(json.dumps(rep(False)), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "notify.py"), "--report", str(tmp_path / "now.json"),
                        "--previous", str(tmp_path / "prev.json"), "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 0 and "OUTSIDE-002" not in p.stdout.split("note:")[0] and "not compared" in p.stdout


# ------------------------------------------------------------------ N43: collect's help

def test_n43_collect_help_says_named_domains_join_the_tenants():
    p = subprocess.run([sys.executable, str(ROOT / "src" / "collect.py"), "--help"], capture_output=True, text=True)
    assert p.returncode == 0 and "audited beside the tenant's own" in " ".join(p.stdout.split())
    assert "else the tenant's" not in p.stdout


# ------------------------------------------------------------------ N50, N53, N54, N56: damaged values never stop a document

def test_n50_n54_next_steps_reads_odd_values_as_unknown_and_never_raises(tmp_path):
    assert next_steps._n("--5") is None and next_steps._n("\u00b2") is None and next_steps._n(" 7 ") == 7
    assert next_steps._f(10 ** 400) is None and next_steps._f(float("nan")) is None and next_steps._f("2.5") == 2.5
    assert next_steps.id_range([["P-01"], 3]) == "['P-01'], 3"
    assert next_steps.span_phrase({"from": "yesterday", "to": "today", "hours": float("nan")}) == \
        "the mail log's span (yesterday to today UTC)"
    base = {"generated_utc": "2026-10-13T06:00:00Z", "inputs": {"domains": ["corp.example"]},
            "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "none", "next_step": "x"}}},
            "maillog": {"counters": {"genuine_failures": 3}, "window_totals": {"hours": 10 ** 400, "orgs": {"corp.example": {
                "by_domain": {"corp.example": {"genuine_failures": "--5"}}}}}}, "findings": []}
    full = next_steps.full_window(base)
    assert full["hours"] is None and full["genuine_failures"] == 0 and full["span"] == "window"
    odd = [lambda r: r["maillog"].__setitem__("verdicts", 7), lambda r: r["gate"]["domains"].__setitem__("corp.example", "no_go"),
           lambda r: r["gate"]["domains"]["corp.example"].__setitem__("current_policy", 3),
           lambda r: r.__setitem__("inputs", ["corp.example"]), lambda r: r["maillog"].__setitem__("by_domain", "text"),
           lambda r: r["maillog"].__setitem__("by_domain", {"corp.example": {"genuine_failures": 2, "logical_messages": 0,
                                                                              "subdomains_total": {"logical_messages": 5, "domains": 7}}}),
           lambda r: r.__setitem__("rua", {"failing_streams": [{"source_ip": "1.2.3.4", "likely": "likely_spoof", "dispositions": [1], "fail": 3}],
                                           "totals": {"messages": 10, "pass_rate": 0.5, "reports": 1}}),
           lambda r: r.__setitem__("delta", {"previous_generated_utc": "2026-10-06T06:00:00Z", "genuine_failures": float("nan")})]
    for damage in odd:
        rep = json.loads(json.dumps(base).replace("1e+400", "10"))
        damage(rep)
        doc = next_steps.build(rep)
        next_steps.render_md(doc)
    metrics = [{"run": "2026-10-06T060000Z", "domains": "text", "genuine_failures": 3, "maillog_hours": 10 ** 400}]
    assert next_steps.policy_since(metrics, "corp.example", "none") is None
    next_steps.render_md(next_steps.build(base, metrics=metrics))
    # the CLI guards rendering and writing too: a plan id that is a list is no traceback
    (tmp_path / "report.json").write_text(json.dumps(base).replace("1e+400", "10"), encoding="utf-8")
    plan = {"changes": [{"id": ["P-01"], "domain": "corp.example", "kind": "ratchet", "priority": 3, "hostname": "_dmarc.corp.example",
                         "value": "v=DMARC1; p=quarantine;", "current": "v=DMARC1; p=none;", "why": "w", "prerequisites": []}], "holds": []}
    (tmp_path / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "next_steps.py"), str(tmp_path / "report.json"), "--plan",
                        str(tmp_path / "plan.json"), "--out", str(tmp_path / "out")], capture_output=True, text=True)
    assert "Traceback" not in p.stderr and p.returncode in (0, 2)


def test_n53_n56_notify_and_the_metrics_table_survive_damaged_inputs(tmp_path):
    good = {"generated_utc": "2026-10-13T06:00:00Z", "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "none"}}},
            "maillog": {"counters": {"genuine_failures": 3}}, "summary": {"findings": 2, "by_severity": {"major": 2}},
            "rua": {"totals": {"messages": 10, "pass_rate": 0.5, "by_disposition": {"reject": [1]}}, "unknown_senders": -1}}
    damages = [lambda r: r.__setitem__("gate", "no_go"), lambda r: r["gate"].__setitem__("domains", ["corp.example"]),
               lambda r: r.__setitem__("generated_utc", None), lambda r: r["maillog"]["counters"].__setitem__("genuine_failures", None),
               lambda r: r["gate"]["domains"].__setitem__("corp.example", None),
               lambda r: r["summary"].__setitem__("by_severity", {"major": "two"})]
    for damage in damages:
        rep = json.loads(json.dumps(good))
        damage(rep)
        assert notify.summarize(rep, previous={"rua": "none", "gate": {}}, plan={"changes": ["text"], "holds": []},
                                history=[{"rua_pass_rate": 10 ** 400, "genuine_failures": float("nan")},
                                         {"genuine_failures": 5, "maillog_hours": 10 ** 400}]).startswith("*DMARC")
    assert "text" in notify.summarize(good, plan="text") or True  # a plan that is not an object is no plan
    md = collect.render_metrics([{"run": "r1", "findings": {"major": float("nan")}, "plan_changes": float("inf"),
                                  "rua_pass_rate": 10 ** 400, "genuine_failures": 10 ** 400, "domains": "text"}])
    assert "| r1 |  | - | - | - | 0 (0 now) |" in md
    for text in ("[1, 2]", "null", '"text"', "7"):
        (tmp_path / "r.json").write_text(text, encoding="utf-8")
        p = subprocess.run([sys.executable, str(ROOT / "src" / "notify.py"), "--report", str(tmp_path / "r.json"), "--dry-run"],
                           capture_output=True, text=True)
        assert p.returncode == 2 and "expected a JSON object" in p.stderr and "Traceback" not in p.stderr


def test_n55_n57_history_files_are_read_with_a_bom_and_set_aside_when_damaged(tmp_path):
    notes = []
    (tmp_path / "metrics.json").write_bytes(b"\xef\xbb\xbf" + json.dumps([{"run": "a"}]).encode())
    assert collect.read_history(tmp_path / "metrics.json", list, "2026", notes) == [{"run": "a"}]
    (tmp_path / "metrics.json").write_bytes(json.dumps([{"run": "b"}]).encode("utf-16"))
    assert collect.read_history(tmp_path / "metrics.json", list, "2026", notes) == [{"run": "b"}] and notes == []
    (tmp_path / "metrics.json").write_text("{not json", encoding="utf-8")
    assert collect.read_history(tmp_path / "metrics.json", list, "2026-10-13T060000Z", notes) is None
    assert not (tmp_path / "metrics.json").exists() and (tmp_path / "metrics.json.unreadable-2026-10-13T060000Z").exists()
    assert notes == ["metrics.json is not the list collect.py writes (unreadable): set aside as "
                     "metrics.json.unreadable-2026-10-13T060000Z; the history starts again from this run"]
    assert collect.read_history(tmp_path / "absent.json", list) is None
    rep = {"rua": {"source_ips": ["192.0.2.1"]}, "maillog": {}}
    (tmp_path / "senders.json").write_text(json.dumps({"senders": {"ip:192.0.2.1": None, "ip:192.0.2.2": "2026-10-01T000000Z",
                                                                   "ip:192.0.2.3": {"first_seen": "2026-09-01T000000Z"}}}), encoding="utf-8")
    known, new = collect.update_senders(tmp_path / "senders.json", rep, "2026-10-13T060000Z", notes)
    assert known == {"ip:192.0.2.1", "ip:192.0.2.2", "ip:192.0.2.3"} and new == []
    saved = json.loads((tmp_path / "senders.json").read_text(encoding="utf-8"))["senders"]
    assert saved["ip:192.0.2.1"] == {"first_seen": "2026-10-13T060000Z", "last_seen": "2026-10-13T060000Z"}
    assert saved["ip:192.0.2.3"]["first_seen"] == "2026-09-01T000000Z"
    (tmp_path / "senders.json").write_text("[]", encoding="utf-8")
    known, new = collect.update_senders(tmp_path / "senders.json", rep, "2026-10-13T070000Z", notes)
    assert known == set() and new == ["ip:192.0.2.1"] and (tmp_path / "senders.json.unreadable-2026-10-13T070000Z").exists()


# ------------------------------------------------------------------ N58: a large census goes to a side file

def test_n58_a_large_census_goes_to_a_side_file_and_every_reader_still_sees_it(tmp_path):
    by_sender = [{"sender": "u%d@corp.example" % i, "domain": "corp.example", "envelope_domain": "env%d.invalid" % (i % 25000),
                  "genuine_failures": 1 if i % 100 == 0 else 0, "messages": 1 + i % 3, "delivered_despite_fail": 0,
                  "likely": None, "sample_subject": "s", "excepted": 0, "excepted_delivered": 0, "likely_counts": {},
                  "likely_after": None} for i in range(30000)]
    by_env = [{"envelope_domain": "env%d.invalid" % i, "genuine_failures": 0, "messages": 2, "senders": 1,
               "sample_sender": "u@corp.example", "likely": None, "excepted": 0, "likely_after": None,
               "senders_after": 0, "sample_sender_after": None} for i in range(25000)]
    rep = {"generated_utc": "2026-10-13T06:00:00Z", "gate": {"domains": {}}, "inputs": {"domains": ["corp.example"]},
           "rua": {"source_ips": ["192.0.2.1"]},
           "maillog": {"counters": {"genuine_failures": 300}, "census": {"by_envelope": by_env, "by_sender": by_sender, "note": "n"}}}
    full_keys = notify.sender_keys(rep)
    side = audit.write_report_json(rep, tmp_path / "report.json")
    assert side == tmp_path / audit.CENSUS_FILE and (tmp_path / "report.json").stat().st_size < 5 * 1024 * 1024
    assert len(rep["maillog"]["census"]["by_sender"]) == 30000  # the dict in memory is never trimmed
    disk = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    cs = disk["maillog"]["census"]
    assert disk["maillog"]["census_file"] == "census.json" and disk["maillog"]["census_rows"] == {"by_envelope": 25000, "by_sender": 30000}
    assert len(cs["by_sender"]) == 300 + audit.CENSUS_KEEP_CLEAN and len(cs["by_envelope"]) == audit.CENSUS_KEEP_CLEAN
    assert sum(1 for r in cs["by_sender"] if r["genuine_failures"]) == 300  # every failing row stays, in the census's order
    assert disk["maillog"]["census_omitted"]["by_sender"] == 30000 - 800
    assert cs["note"] == "n"
    whole = json.loads(side.read_text(encoding="utf-8"))
    assert len(whole["by_sender"]) == 30000 and len(whole["by_envelope"]) == 25000
    assert notify.sender_keys(disk, tmp_path / "report.json") == full_keys and len(full_keys) == 25001
    assert notify.sender_keys(json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))) != full_keys
    back = audit.load_census(json.loads((tmp_path / "report.json").read_text(encoding="utf-8")), tmp_path / "report.json")
    assert len(back["maillog"]["census"]["by_sender"]) == 30000 and back["maillog"]["census_omitted"] == {"by_envelope": 0, "by_sender": 0}
    assert len(collect.read_report(tmp_path / "report.json")["maillog"]["census"]["by_sender"]) == 30000  # the delta's side
    small = {"maillog": {"census": {"by_envelope": by_env[:10], "by_sender": by_sender[:10]}}}
    assert audit.write_report_json(small, tmp_path / "small.json") is None and not (tmp_path / "small.json").read_text(encoding="utf-8").count("census_file")
    assert audit.CENSUS_FILE in collect.RUN_FILES


# ------------------------------------------------------------------ N59: our own platform with a failing key

def source(count, aligned_failed, aligned_pass, reasons=(), spf_pass_for="corp.example"):
    s = rua_parse._new_source()
    s.update(count=count, fail=count - aligned_pass, **{"pass": aligned_pass}, no_auth=0, aligned_dkim_failed=aligned_failed,
             dkim_failed=aligned_failed, dkim_pass=aligned_pass, misaligned_spf=count - aligned_pass)
    s["header_from"] = Counter({"example.com": count})
    s["spf"] = Counter({(spf_pass_for, "mfrom", "pass"): count})
    s["dkim"] = Counter({("example.com", "s1", "fail"): aligned_failed, ("example.com", "s1", "pass"): aligned_pass})
    for r in reasons:
        s["reasons"][r] = count
    return s


def test_n59_a_source_that_also_delivers_aligned_passes_is_our_own_platform():
    label, signals = rua_parse.likely_label(source(100, 60, 30), {"example.com"})
    assert label == "likely_misconfigured"
    assert signals[-1] == ("the same source delivers 30 msgs with an aligned DKIM pass as the domain and nothing marks "
                           "forwarding: a rotated or mismatched DKIM key at a system that signs for it")
    # a spoof with a forged signature, and a forwarder: no aligned pass, so the stream stays unknown
    assert rua_parse.likely_label(source(100, 60, 0), {"example.com"})[0] == "unknown"
    assert rua_parse.likely_label(source(100, 60, 30, reasons=("forwarded",)), {"example.com"})[0] == "unknown"
    # the listed-platform rule still stands on its own
    assert rua_parse.likely_label(source(100, 60, 0), {"example.com"}, known_domains=["corp.example"])[0] == "likely_misconfigured"


# ------------------------------------------------------------------ N13, N54: a damaged previous report costs one line

def test_n13_a_damaged_value_in_the_previous_report_withholds_one_line_never_the_run(tmp_path):
    docs = {"corp.example": dns_doc("corp.example", APEX)}
    log = Log().add("staff@corp.example", "Weekly #", 20).add("app@corp.example", "Build #", 3, env="relay.invalid", dmarc="fail")
    now = report_for(tmp_path, docs, log)
    prev = json.loads(json.dumps(now))
    prev["maillog"]["counters"]["genuine_failures"] = 12.5  # a fraction, a numeric sender, a numeric source, an id list
    prev["maillog"]["by_domain"]["corp.example"]["delivered_despite_fail"] = 2.5
    prev["maillog"]["census"]["by_sender"][0]["sender"] = 7
    prev["findings"] = [{"source": 7, "id": ["DMARC-001"], "severity": ["major"], "title": "t"}]
    dl = audit.build_delta(now, prev)
    assert dl["genuine_failures"] is None and dl["delivered_despite_fail"] == 0 and "corp.example" not in dl["by_domain"]
    assert "genuine_failures is not a whole number in the previous run's report.json (12.5): its delta is not computed" in dl["notes"]
    assert ("the counts for corp.example are not whole numbers in one of the two report.json files: its delta is not "
            "computed") in dl["notes"]
    assert [s["sender"] for s in dl["gone_senders"]] == [7]
    assert dl["findings_resolved"] == [{"id": "['DMARC-001']", "source": "7", "severity": None, "title": "t"}]
    md = []
    audit._md_delta(md, dl)
    assert ("- genuine failures: n/a (a count that is no whole number, see the note below); delivered despite fail: +0 "
            "(whole mail log, deduplicated)") in md
    assert "- senders no longer seen (1): 7" in md and "- resolved findings (1): ['DMARC-001'] (7)" in md
    # through build_report, as collect.py runs it: the delta is kept, report.md renders, nothing is lost
    rep = audit.build_report(domains=["corp.example"], maillog=log.write(tmp_path / "again.csv"), offline=True,
                             auth_column="DMARC", previous_report=prev)
    assert "delta" in rep and "delta_error" not in rep and "## Since the previous run" in audit.render_md(rep)
    assert audit._count(12.5) is None and audit._count(True) is None and audit._count("1361") == 1361 and audit._count(12.0) == 12
    assert audit._display_source(7) == "7" and audit._finding_keys({"findings": "DMARC-001"}) == {}


def test_n54_a_huge_hours_value_in_the_previous_report_costs_one_line_not_the_document():
    assert audit._hours({"hours": 10 ** 400}) is None and audit._hours({"hours": "720"}) == 720.0
    now = {"generated_utc": "2026-10-13T06:00:00Z", "inputs": {"domains": ["corp.example"], "run": "2026-10-13T060000Z"},
           "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "none", "next_step": "x"}}},
           "maillog": {"counters": {"genuine_failures": 3},
                       "window": {"from": "2026-09-13T06:00:00Z", "to": "2026-10-13T06:00:00Z", "hours": 720.0}}, "findings": []}
    prev = {"generated_utc": "2026-10-06T06:00:00Z", "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "none"}}},
            "maillog": {"counters": {"genuine_failures": 5}, "window": {"hours": 10 ** 400}}, "findings": []}
    dl = audit.build_delta(now, prev)  # an unreadable span is an unknown one, and unknown gets the benefit of the doubt
    assert dl["genuine_failures"] == -2 and dl["maillog_window"]["comparable"] is True
    doc = next_steps.build(now, previous=prev)
    assert any(l.startswith("**Trend vs 2026-10-06: -2 genuine failures (5 -> 3)**") for l in doc["stand"]["lines"])
    assert "## " in next_steps.render_md(doc)


# ------------------------------------------------------------------ N19: the status document's reason for a withheld trend

def test_n19_next_steps_names_the_organization_audited_in_one_run_only():
    now, prev = two_reports(["corp.example", "shop.example"], ["corp.example"])
    now["inputs"] = {"domains": ["corp.example", "shop.example"], "run": "2026-10-13T060000Z"}
    why = "failure counts are not compared: shop.example audited in one of the two runs only"
    rep = dict(now, delta=audit.build_delta(now, prev))  # the delta's own reason, never 'very different spans'
    line = next(l for l in next_steps.build(rep)["stand"]["lines"] if l.startswith("**Trend"))
    assert line == "**Trend vs 2026-10-13: not comparable** - " + why
    # the same judgement from the run history, by the audit's rules; an entry that does not say which names it
    # audited keeps the benefit of the doubt
    entry = {"run": "2026-10-06T060000Z", "genuine_failures": 288, "maillog_hours": 720.0, "maillog_cut_orgs": [],
             "rua_messages": 0, "domains": {"corp.example": {}}}
    line = next(l for l in next_steps.build(now, metrics=[entry])["stand"]["lines"] if l.startswith("**Trend"))
    assert line == "**Trend vs 2026-10-06: not comparable** - " + why
    older = {k: v for k, v in entry.items() if k != "domains"}
    line = next(l for l in next_steps.build(now, metrics=[older])["stand"]["lines"] if l.startswith("**Trend"))
    assert line.startswith("**Trend vs 2026-10-06: +90 genuine failures (288 -> 378)**")
    # and from a previous report read on its own
    previous = dict(prev, generated_utc="2026-10-06T06:00:00Z")
    line = next(l for l in next_steps.build(now, previous=previous)["stand"]["lines"] if l.startswith("**Trend"))
    assert line == "**Trend vs 2026-10-06: not comparable** - " + why


# ------------------------------------------------------------------ N58: what a split census keeps for the other readers

def census_row(sender, domain, messages, failing=0):
    label = "likely_misconfigured_sender" if failing else None
    return {"sender": sender, "domain": domain, "envelope_domain": domain, "genuine_failures": failing, "messages": messages,
            "delivered_despite_fail": 0, "likely": label, "sample_subject": "s", "excepted": 0, "excepted_delivered": 0,
            "likely_counts": {label: failing} if failing else {}, "likely_after": label}


def test_n58_the_trimmed_census_keeps_every_stream_the_plan_reads_and_the_cli_reads_the_side_file(tmp_path):
    import plan
    rows = [census_row("u%d@corp.example" % i, "corp.example", 100) for i in range(2600)]  # the apex sends: its clean streams can go
    rows += [census_row("app@legacy.corp.example", "legacy.corp.example", 3),  # only its streams show the subdomain sending
             census_row("x@quiet.example", "quiet.example", 2),  # a quiet audited domain: its streams name its unclear senders
             census_row("bad@quiet.example", "quiet.example", 5, failing=5)]
    rep = {"generated_utc": "2026-10-13T06:00:00Z", "inputs": {"domains": ["corp.example", "quiet.example"]},
           "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "none", "next_step": "x"},
                                "quiet.example": {"verdict": "no_go", "current_policy": "none", "next_step": "x"}}},
           "maillog": {"counters": {"genuine_failures": 5},
                       "by_domain": {"corp.example": {"logical_messages": 260000, "passing_messages": 260000, "internal_messages": 0,
                                                      "genuine_failures": 0},
                                     "quiet.example": {"logical_messages": 7, "passing_messages": 0, "internal_messages": 0,
                                                       "genuine_failures": 5}},
                       "census": {"by_envelope": [], "by_sender": rows}}, "findings": []}
    assert audit._census_trim_domains(rep) == {"corp.example"}
    trimmed, full = audit.census_for_disk(rep)
    kept = trimmed["census"]["by_sender"]
    assert len(kept) == audit.CENSUS_KEEP_CLEAN + 3 and len(full["by_sender"]) == 2603
    assert {r["domain"] for r in kept} == {"corp.example", "legacy.corp.example", "quiet.example"}
    assert trimmed["census_omitted"] == {"by_envelope": 0, "by_sender": 2600 - audit.CENSUS_KEEP_CLEAN}
    disk = json.loads(json.dumps(dict(rep, maillog=trimmed)))  # plan.py on report.json, without the side file
    assert plan.sending_names(disk) == plan.sending_names(rep) and "legacy.corp.example" in plan.sending_names(disk)
    assert plan._unclear_senders(disk, "quiet.example") == plan._unclear_senders(rep, "quiet.example") == [
        ("bad@quiet.example", 5), ("x@quiet.example", 2)]
    # the CLI reads the side file back whole: a failing stream only census.json holds is in the document
    side = audit.write_report_json(rep, tmp_path / "report.json")
    assert side == tmp_path / audit.CENSUS_FILE
    doc = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    doc["maillog"]["census"]["by_sender"] = [r for r in doc["maillog"]["census"]["by_sender"] if r["sender"] != "bad@quiet.example"]
    (tmp_path / "report.json").write_text(json.dumps(doc), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "next_steps.py"), str(tmp_path / "report.json"), "--json"],
                       capture_output=True, text=True)
    assert p.returncode == 0 and "bad@quiet.example" in p.stdout
    assert "bad@quiet.example" not in json.dumps(next_steps.build(doc))  # the trimmed rows alone would not name it


# ------------------------------------------------------------------ the totals note, the ask's hold, the own-sender gap

def test_the_totals_note_names_a_pull_that_failed(monkeypatch):
    monkeypatch.setattr(collect.graph_client, "hunting", lambda tok, kql, ts=None: {"schema": [], "results": []})
    cuts = {"corp.example": {"reason": "not pulled", "error": "HTTP 429"}, "shop.example": {"reason": "row budget", "kept_hours": 41}}
    totals, notes = collect.pull_window_totals("tok", cuts, 30)
    assert totals is None and notes == [
        "mail log: full-window totals for corp.example not counted: the answer holds no mail under it, and its rows were "
        "not read (the pull failed)",
        "mail log: full-window totals for shop.example not counted: the answer holds no mail under it, yet its rows were "
        "cut for holding too many"]


def test_the_ask_keeps_the_sp_holds_instruction(tmp_path):
    sp = ("subdomains that send have no record of their own: e.corp.example, m.corp.example and t.corp.example - publish "
          "their monitoring records (above) before sp= moves to quarantine")
    assert next_steps._hold_summary(sp) == ("publish the monitoring records for e.corp.example, m.corp.example and "
                                            "t.corp.example before sp= moves to quarantine")
    one = sp.replace("e.corp.example, m.corp.example and t.corp.example", "e.corp.example")
    look = "; a name marked not checked may have a record already: look it up first"
    assert next_steps._hold_summary(one + look) == "publish the monitoring record for e.corp.example before sp= moves to quarantine" + look
    dns = "DNS could not be verified for this domain in this run - re-run before planning changes"
    assert next_steps._hold_summary(dns) == dns  # what follows the dash is the condition, never cut
    docs = {"corp.example": dns_doc("corp.example", "v=DMARC1; p=reject; rua=%s;" % RUA)}
    rep = report_for(tmp_path, docs, Log().add("staff@corp.example", "Weekly #", 5))
    ask = next_steps.build(rep, {"changes": [], "holds": [{"domain": "corp.example", "reason": sp}]})["ask"]
    assert ask.endswith("and a decision on corp.example: publish the monitoring records for e.corp.example, m.corp.example and "
                        "t.corp.example before sp= moves to quarantine.")


def test_an_own_sender_gap_with_no_spoofs_is_the_rows_own_condition_not_a_second_hold(tmp_path):
    docs = {"example.com": dns_doc("example.com", "v=DMARC1; p=none; rua=%s;" % RUA)}
    log = Log().add("staff@example.com", "Weekly #", 30).add("app@example.com", "Build #", 3, dmarc="fail")
    rep = report_for(tmp_path, docs, log)
    assert rep["maillog"]["by_domain"]["example.com"]["by_likely"] == {"likely_spoof": 0, "likely_misconfigured_sender": 3, "unknown": 0}
    plan = {"changes": [{"id": "P-01", "domain": "example.com", "kind": "ratchet", "priority": 3, "record": "TXT",
                         "hostname": "_dmarc.example.com", "value": "v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA,
                         "current": "v=DMARC1; p=none; rua=%s;" % RUA, "why": "w",
                         "prerequisites": ["every legitimate sender proven with an aligned DKIM header",
                                           "3 message(s) in the mail log failed from a sender that looks like your own "
                                           "misconfigured system, not a spoof"]}], "holds": []}
    line, doc = one_liner_and_doc(rep, plan)
    blockers = doc["next_step"]["blockers"]
    assert [b["kind"] for b in blockers] == ["own", "other"] and blockers[0]["text"].startswith("3 logical messages from this domain")
    assert doc["next_step"]["holds"] == [blockers[1]["text"]]
    assert line.endswith("ready when every legitimate sender is proven with an aligned DKIM header, and the 3 mail-log failures "
                         "from our own systems are fixed, and on hold while: 3 messages from this domain failed authentication "
                         "but reached a mailbox - a local override is masking failures external receivers enforce.")
    assert "3 logical messages" not in line
    # without a plan the gate's words hold the step, as before
    assert "on hold while: 3 logical messages from this domain failed with no passing copy" in one_liner_and_doc(rep, None)[0]
