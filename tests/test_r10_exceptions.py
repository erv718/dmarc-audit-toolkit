"""Round 10, exceptions: audit.py marks every verdict a formal exception
covers, the census carries the counts per stream, and every reader subtracts
exact numbers; the gate excepts delivered-despite-fail too; next_steps decides
by the gate's verdict and reads the aggregate reports' labels and exceptions.
Synthetic mail logs and reports, offline, no network."""

import csv
import json

import audit
import collect
import dedupe
import next_steps
import notify

COLUMNS = ["Email date (UTC)", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
           "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC"]
QUARANTINED = ("Blocked", "Quarantine")
DELIVERED = ("Delivered", "Inbox/folder")


class Log:
    """A synthetic mail-log export, one row per message."""

    def __init__(self):
        self.rows = []

    def add(self, sender, env, subject, n=1, where=QUARANTINED, dmarc="fail"):
        """n messages from sender through the envelope env; a '#' in the subject becomes the row number."""
        for _ in range(n):
            i = len(self.rows)
            self.rows.append(["2026-05-01 %02d:%02d:00" % (i // 60 % 24, i % 60), "<m%04d@mail.invalid>" % i, sender,
                              sender.rpartition("@")[2], env, "u%d@example.com" % (i % 7),
                              subject.replace("#", str(i)), where[0], where[1], dmarc])
        return self

    def write(self, path):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            w.writerows(self.rows)
        return str(path)


def exc(match, until="2099-01-01"):
    return {"match": match, "reason": "accepted for the test", "owner": "it", "until": until,
            "removal_criterion": "the sender signs with DKIM"}


def dns(policy="none", pct="100", *domains):
    record = "v=DMARC1; p=%s; sp=%s; pct=%s; rua=mailto:reports@example.com;" % (policy, policy, pct)
    return {d: {"domain": d, "dmarc": record, "dmarc_source": "_dmarc." + d, "effective_policy": policy,
                "inherited": False, "dmarc_status": "found", "spf": "v=spf1 include:mail.example -all",
                "spf_status": "found", "spf_terminator": "-all", "spf_lookups": 1, "findings": []}
            for d in (domains or ("example.com",))}


def report(tmp_path, log, domains=("example.com",), exceptions=(), policy=None, name="log.csv", keep=False, **kw):
    """build_report over the log; with a policy, the gate is decided again over a DNS section, as an online
    run would (the verdicts are kept for that and dropped afterwards, as build_report does). keep: the
    verdicts stay in the report, as --keep-verdicts writes it."""
    rep = audit.build_report(domains=list(domains), maillog=log.write(tmp_path / name), offline=True,
                             auth_column="DMARC", exceptions=list(exceptions), keep_verdicts=bool(policy) or keep, **kw)
    if policy:
        rep["dns"] = dns(policy, "100", *domains)
        rep["gate"] = audit.gate_verdict(rep["dns"], None, rep["maillog"], list(domains), exceptions=list(exceptions))
        if not keep:
            rep["maillog"]["verdicts"] = []
    return rep


def doc_md(rep, **kw):
    doc = next_steps.build(rep, **kw)
    return doc, next_steps.render_md(doc)


def actions(doc):
    return [i["hook"] for g in doc["actions_by_owner"] for i in g["items"]]


def reports_doc(streams, messages=500):
    """An aggregate-report section as audit.run_rua writes it, with these failing streams."""
    return {"totals": {"reports": 1, "messages": messages, "pass_rate": 0.8, "by_disposition": {"quarantine": 100},
                       "begin_date": "2026-10-06", "end_date": "2026-10-06"},
            "policy_check": {"seen": []}, "failing_streams": streams, "spf_only_senders": [],
            "by_header_from": [{"domain": "example.com", "count": messages, "pass": 400, "fail": 100}]}


def stream(ip, fail, likely, spf_domains=(), signals=()):
    return {"source_ip": ip, "count": fail, "fail": fail, "pass": 0, "likely": likely,
            "dispositions": {"quarantine": fail}, "header_from": ["example.com"], "spf_domains": list(spf_domains),
            "dkim_domains": ["example.com"], "likely_signals": list(signals) or ["synthetic signal"]}


# ------------------------------------------------------------------ the shared interface

def test_the_marks_reach_the_census_the_attribution_and_the_gate(tmp_path):
    log = (Log().add("staff@example.com", "example.com", "Hello", 5, DELIVERED, "pass")
           .add("ops@example.com", "vendor.invalid", "Statement #", 3)
           .add("ops@example.com", "vendor.invalid", "Invoice #", 1, DELIVERED)
           .add("app@a.example.com", "vendor.invalid", "Build #", 2)
           .add("news@outside.invalid", "vendor.invalid", "Digest #", 2)
           .add("billing@example.com", "example.com", "Receipt #", 2))
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "log.csv"), offline=True,
                             auth_column="DMARC", exceptions=[exc("vendor.invalid")], keep_verdicts=True)
    marks = {v["sender"]: v["excepted"] for v in rep["maillog"]["verdicts"] if v["genuine_failure"]}
    assert marks["ops@example.com"] == "vendor.invalid" and marks["billing@example.com"] is False
    assert all(v["excepted"] is False for v in rep["maillog"]["verdicts"] if not v["genuine_failure"])
    ops = next(r for r in rep["maillog"]["census"]["by_sender"] if r["sender"] == "ops@example.com")
    assert (ops["genuine_failures"], ops["excepted"], ops["excepted_delivered"]) == (4, 4, 1)
    assert ops["likely_counts"] == {} and ops["likely_after"] is None
    env = next(r for r in rep["maillog"]["census"]["by_envelope"] if r["envelope_domain"] == "vendor.invalid")
    assert (env["excepted"], env["senders_after"], env["sample_sender_after"], env["likely_after"]) == (8, 0, None, None)
    own = rep["maillog"]["by_domain"]["example.com"]
    assert (own["excepted"], own["excepted_delivered"]) == (4, 1) and sum(own["excepted_by_likely"].values()) == 4
    assert own["subdomains_total"]["excepted"] == 2
    assert rep["maillog"]["excepted_elsewhere"] == {"outside.invalid": 2}
    g = rep["gate"]["domains"]["example.com"]
    assert g["excepted_failures"] == 4 and g["excepted_senders"] == {"ops@example.com": 4}
    assert g["excepted_senders_by_envelope"] == {"ops@example.com": {"vendor.invalid": 4}}
    assert rep["gate"]["exceptions"]["excepted_maillog_failures"] == 8
    assert g["blockers"] == ["example.com: 2 logical message(s) from this domain failed with no passing copy "
                             "(deduplicated; 4 more excepted); top senders: billing@example.com x2"]
    assert any(n.startswith("example.com: unaudited subdomain(s) a.example.com") for n in g["notes"])
    assert all(r in g["reasons"] for r in g["blockers"] + g["notes"])
    # an expired exception never marks
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "log.csv"), offline=True,
                             auth_column="DMARC", exceptions=[exc("vendor.invalid", until="2020-01-01")])
    assert not any(r["excepted"] for r in rep["maillog"]["census"]["by_sender"])


# ------------------------------------------------------------------ C4, C44: per stream, per label

def test_c4_an_exception_comes_off_its_own_stream_and_never_relabels_another(tmp_path):
    """ops@ fails through an excepted vendor stream (majority misconfigured, a minority of m=4 unknown or
    spoof-labelled) and through a foreign spoof stream of F messages: the spoof stream stays a spoof,
    whether F <= m or m < F <= 2m."""
    for minority in ("Note", "Invoice"):  # one-off subjects (unknown), then lure words (likely_spoof)
        for spoofs in (3, 5):
            log = Log().add("ops@example.com", "vendor.invalid", "Statement #", 6)
            for word in ("alpha", "bravo", "charlie", "delta"):
                log.add("ops@example.com", "vendor.invalid", "%s %s" % (minority, word))
            log.add("ops@example.com", "spoofer.invalid", "Hello there", spoofs)
            log.add("billing@example.com", "example.com", "Receipt #", 3)
            rep = report(tmp_path, log, exceptions=[exc("vendor.invalid")], vendor_domains=["vendor.invalid"],
                         name="%s%d.csv" % (minority, spoofs))
            doc, md = doc_md(rep)
            line = doc["one_liner"]
            assert "3 from 1 of our own senders (billing@example.com x3)" in line, (minority, spoofs, line)
            assert "%d from 1 address that look like spoofing" % spoofs in line, (minority, spoofs, line)
            assert "10 formally excepted in audit.toml" in line
            assert "ops@example.com - %d" % spoofs not in md  # never a DKIM item: it is the spoof part
            assert "Formally excepted in audit.toml and not counted above: 10 messages (ops@example.com x10)." in md


def test_c44_an_address_is_named_in_every_group_with_its_own_count(tmp_path):
    log = (Log().add("news@example.com", "example.com", "Weekly news #", 2)
           .add("news@example.com", "example.com", "Urgent payment update")
           .add("billing@example.com", "example.com", "Statement 100# ready", 3))
    rep = report(tmp_path, log, policy="none")
    doc, md = doc_md(rep)
    line = doc["one_liner"]
    assert "6 messages from example.com failed with no passing copy" in line
    assert "5 from 2 of our own senders (billing@example.com x3, news@example.com x2)" in line
    assert "1 from 1 address that look like spoofing" in line
    held = [b["text"] for b in doc["next_step"]["blockers"]]
    assert held == ["5 messages from our own senders failed with no passing copy (billing@example.com x3, "
                    "news@example.com x2); the other 1 look like spoofing, and p=none does not stop them yet"]
    assert doc["failing"]["streams"]["spoof"] == [{"name": "news@example.com", "count": 1}]
    assert "news@example.com - 2 messages" in md and "1 message from 1 address that looks like spoofing" in md


# ------------------------------------------------------------------ C14, C27: every From domain

def test_c14_exceptions_on_subdomain_and_outside_senders_leave_the_document(tmp_path):
    log = (Log().add("news@example.com", "bounce.esp.invalid", "News #", 3)
           .add("app@a.example.com", "bounce.esp.invalid", "Build #", 2)
           .add("digest@outside.invalid", "bounce.esp.invalid", "Digest #", 2)
           .add("hr@corp.example", "corp.example", "Hello", 4, DELIVERED, "pass"))
    rep = report(tmp_path, log, domains=("example.com", "corp.example"), exceptions=[exc("bounce.esp.invalid")])
    assert rep["gate"]["exceptions"]["excepted_maillog_failures"] == 7
    doc, md = doc_md(rep)
    assert ("Every genuine failure the census names this run is formally excepted in audit.toml: 7 messages "
            "(news@example.com x3, app@a.example.com x2, digest@outside.invalid x2).") in md
    assert not [h for h in actions(doc) if "app@a.example.com" in h or "digest@outside.invalid" in h]
    assert "bounce.esp.invalid x" not in md and "DKIM-sign" not in md
    assert "unaudited subdomains a.example.com carry 2 logical messages, 2 genuine failures (2 of them formally excepted)" in md
    assert rep["maillog"]["excepted_elsewhere"] == {"outside.invalid": 2}


def test_c27_an_excepted_vendor_stream_from_an_unaudited_subdomain_is_not_work(tmp_path):
    log = (Log().add("ops@example.com", "vendor.invalid", "Statement #", 3)
           .add("alerts@mail.example.com", "vendor.invalid", "Alert #", 4)
           .add("billing@example.com", "example.com", "Receipt #", 2))
    rep = report(tmp_path, log, exceptions=[exc("vendor.invalid")], vendor_domains=["vendor.invalid"])
    doc, md = doc_md(rep)
    assert "Formally excepted in audit.toml and not counted above: 7 messages (alerts@mail.example.com x4, ops@example.com x3)." in md
    assert actions(doc) == ["billing@example.com - 2 messages"]
    # the org's mail sits in its subdomains only: the one-liner counts those, less the excepted
    log = (Log().add("app@a.example.com", "bounce.esp.invalid", "Build #", 2)
           .add("hi@a.example.com", "a.example.com", "Hello", 20, DELIVERED, "pass"))
    rep = report(tmp_path, log, exceptions=[exc("bounce.esp.invalid")])
    doc, _ = doc_md(rep)
    assert "2 messages from its subdomains failed with no passing copy" in doc["one_liner"]
    assert "none from our own senders; 2 formally excepted in audit.toml" in doc["one_liner"]
    assert "app@a.example.com" not in doc["one_liner"]


# ------------------------------------------------------------------ C25, C35, C41/D4: envelopes

def test_c25_two_spellings_of_one_envelope_each_lose_only_their_own_streams(tmp_path):
    log = (Log().add("other@corp.example", "shop.example", "Order #", 5)
           .add("printer@corp.example", "shop.example", "Scan #", 4)
           .add("printer@corp.example", "shop.example.", "Scan #", 2))
    rep = report(tmp_path, log, domains=("corp.example",), exceptions=[exc("printer@corp.example")])
    doc, _ = doc_md(rep)
    envs = [(e["name"], e["count"], e.get("senders")) for e in doc["failing"]["by_envelope"]]
    assert envs == [("shop.example", 5, ["other@corp.example"])]
    assert sorted((e["envelope"], e["count"]) for e in doc["failing"]["excepted"]) == [("shop.example", 4),
                                                                                       ("shop.example.", 2)]


def test_c35_the_census_spelling_decides_and_an_older_census_is_left_whole(tmp_path):
    log = (Log().add("printer@corp.example", "v.example.", "Scan #", 12)
           .add("other@corp.example", "v.example.", "Order #", 10)
           .add("noreply@corp.example", "", "Out of office", 3))
    rep = report(tmp_path, log, domains=("corp.example",),
                 exceptions=[exc("printer@corp.example"), exc("noreply@corp.example")])
    doc, _ = doc_md(rep)
    assert doc["failing"]["excepted"] == [
        {"name": "printer@corp.example", "domain": "corp.example", "envelope": "v.example.", "count": 12},
        {"name": "noreply@corp.example", "domain": "corp.example", "envelope": "(blank)", "count": 3}]
    assert [(e["name"], e["count"], e["senders"]) for e in doc["failing"]["by_envelope"]] == [
        ("v.example.", 10, ["other@corp.example"])]
    # a census written before it counted the exceptions says nothing about which stream they covered:
    # nothing is taken off, and the gate's total is named as a part of the counts shown
    for rows in (rep["maillog"]["census"]["by_sender"], rep["maillog"]["census"]["by_envelope"]):
        for r in rows:
            for k in ("excepted", "excepted_delivered", "likely_counts", "likely_after", "senders_after",
                      "sample_sender_after"):
                r.pop(k, None)
    for k in ("excepted", "excepted_by_likely", "excepted_delivered"):
        rep["maillog"]["by_domain"]["corp.example"].pop(k, None)
    doc, _ = doc_md(rep)
    assert "excepted" not in doc["failing"] and doc["failing"]["by_envelope"][0]["count"] == 22
    assert "failed with no passing copy (15 of them formally excepted in audit.toml) in the mail log's" in doc["one_liner"]


def test_c41_a_reduced_envelope_is_labelled_by_what_is_left_both_ways(tmp_path):
    cases = (("alerts@example.com", "Nightly export #", "ceo@example.com", "Wire transfer request #", "looks like spoofing"),
             ("news@example.com", "Urgent payment update #", "billing@example.com", "Statement 100# ready",
              "looks like our own system misconfigured"))
    for excepted, subject, left, left_subject, words in cases:
        log = Log().add(excepted, "example.com", subject, 14).add(left, "example.com", left_subject, 12)
        rep = report(tmp_path, log, exceptions=[exc(excepted)])
        doc, md = doc_md(rep)
        assert "- **example.com - 12 messages** %s (1 sender address; such as %s)" % (words, left) in md
        assert doc["failing"]["by_envelope"][0]["likely"] == ("likely_spoof" if "spoof" in words
                                                             else "likely_misconfigured_sender")


# ------------------------------------------------------------------ C23, C24: a report from before the counts

def older_report(gate_fields):
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["corp.example"]},
           "gate": {"domains": {"corp.example": dict({
               "verdict": "no_go", "current_policy": "quarantine", "next_step": "move to p=reject",
               "reasons": ["corp.example: 3 logical message(s) from this domain failed with no passing copy "
                           "(deduplicated; 4 more excepted); top senders: ceo@corp.example x2, app@corp.example x1",
                           "step being gated: move to p=reject"]}, **gate_fields)},
                    "evidence": {"statement": "s"}},
           "maillog": {"counters": {"genuine_failures": 7, "raw_failing_rows": 7, "raw_rows": 20, "logical_messages": 20,
                                    "delivered_despite_fail": 0}, "auth_column": "DMARC",
                       "by_domain": {"corp.example": {"genuine_failures": 7, "logical_messages": 20, "delivered_despite_fail": 0,
                                                      "by_likely": {"likely_spoof": 2, "likely_misconfigured_sender": 5,
                                                                    "unknown": 0}, "top_senders": []}},
                       "census": {"by_envelope": [], "by_sender": [
                           {"sender": "printer@corp.example", "domain": "corp.example", "envelope_domain": "v.example",
                            "genuine_failures": 4, "messages": 4, "likely": "likely_misconfigured_sender"},
                           {"sender": "ceo@corp.example", "domain": "corp.example", "envelope_domain": "spam.invalid",
                            "genuine_failures": 2, "messages": 2, "likely": "likely_spoof"},
                           {"sender": "app@corp.example", "domain": "corp.example", "envelope_domain": "corp.example",
                            "genuine_failures": 1, "messages": 1, "likely": "likely_misconfigured_sender"}]}}}
    return rep


GATE_VINTAGES = ({"excepted_failures": 4},
                 {"excepted_failures": 4, "excepted_by_likely": {"likely_misconfigured_sender": 4}},
                 {"excepted_failures": 4, "excepted_by_likely": {"likely_misconfigured_sender": 4},
                  "excepted_senders": {"printer@corp.example": 4}},
                 {"excepted_failures": 4, "excepted_by_likely": {"likely_misconfigured_sender": 4},
                  "excepted_senders": {"printer@corp.example": 4},
                  "excepted_senders_by_likely": {"printer@corp.example": {"likely_misconfigured_sender": 4}},
                  "excepted_senders_by_envelope": {"printer@corp.example": {"v.example": 4}}})


def test_c23_an_older_reports_excepted_total_qualifies_the_total():
    for fields in GATE_VINTAGES:
        line = next_steps.build(older_report(fields))["one_liner"]
        assert ("7 messages from corp.example failed with no passing copy (4 of them formally excepted in "
                "audit.toml): 5 from 2 of our own senders") in line, line
        assert "(of which" not in line and "; 4 formally excepted" not in line


def test_c24_an_older_report_keeps_the_gates_own_sentence_as_the_hold():
    gate_reason = ("3 logical messages from this domain failed with no passing copy (deduplicated; 4 more excepted); "
                   "top senders: ceo@corp.example x2, app@corp.example x1")
    for fields in GATE_VINTAGES:
        doc = next_steps.build(older_report(fields))
        assert doc["next_step"]["blockers"] == [{"kind": "other", "text": gate_reason}]
        assert "on hold while: %s." % gate_reason in doc["one_liner"]
        assert "1 message from our own senders" not in doc["one_liner"]
    # a spoof-labelled exception: the hold stays the gate's own count, never a spoof item naming the excepted
    rep = older_report({"excepted_failures": 2, "excepted_by_likely": {"likely_spoof": 2},
                        "excepted_senders": {"ceo@corp.example": 2}})
    rep["gate"]["domains"]["corp.example"]["reasons"][0] = (
        "corp.example: 5 logical message(s) from this domain failed with no passing copy (deduplicated; 2 more "
        "excepted); top senders: printer@corp.example x4, app@corp.example x1")
    doc = next_steps.build(rep)
    assert [b["kind"] for b in doc["next_step"]["blockers"]] == ["other"]
    assert "printer@corp.example x4, app@corp.example x1" in doc["next_step"]["blockers"][0]["text"]


# ------------------------------------------------------------------ C26, C34: the whole-census fallback

def test_c26_c34_the_whole_census_fallback_counts_what_is_left_and_names_the_unit(tmp_path):
    log = (Log().add("printer@shop.example", "v.example", "Scan #", 40)
           .add("app@shop.example", "shop.example", "Order #", 3)
           .add("ceo@shop.example", "spam.invalid", "Invoice #", 1)
           .add("cfo@shop.example", "spam.invalid", "Invoice #", 1))
    rep = report(tmp_path, log, domains=("shop.example",), exceptions=[exc("printer@shop.example")])
    doc = next_steps.build(rep, org_name="example.com")  # a domain the audit did not attribute: the whole census
    line = doc["one_liner"]
    assert "Across all audited domains, in the mail log's" in line
    assert "1 of our own senders still fails (app@shop.example x3); 2 senders look like spoofing" in line
    assert "; 40 messages from 1 sender formally excepted in audit.toml." in line
    assert "printer@shop.example" not in line
    strm = doc["failing"]["streams"]
    assert strm["scope"] == "all audited domains" and (strm["excepted"], strm["excepted_senders"]) == (40, 1)


# ------------------------------------------------------------------ C36, D8, D17, D18, D19: all excepted, delivered

def test_c36_d8_when_every_failure_is_excepted_the_section_lists_it_once_and_works_nothing(tmp_path):
    log = Log().add("printer@corp.example", "v.example", "Scan #", 4).add("hi@corp.example", "corp.example", "Hi", 5,
                                                                         DELIVERED, "pass")
    rep = report(tmp_path, log, domains=("corp.example",), exceptions=[exc("v.example")])
    assert any(f["id"] == "MAILFLOW-001" and f["severity"] == "major" for f in rep["findings"])
    doc, md = doc_md(rep)
    assert ("Every genuine failure the census names this run is formally excepted in audit.toml: 4 messages "
            "(printer@corp.example x4).") in md
    assert md.count("printer@corp.example x4") == 1 and "not counted above" not in md
    assert ("- Nothing to do this week: no plan changes, and every failure this run names is formally excepted in "
            "audit.toml (What is failing lists them).") in md
    assert "no actionable findings" not in md


def test_d17_a_formally_excepted_sender_delivered_despite_failing_does_not_hold_the_gate(tmp_path):
    log = Log().add("staff@example.com", "example.com", "Hello #", 40, DELIVERED, "pass")
    log.add("scanner@example.com", "example.com", "Scan # complete", 4, DELIVERED)
    rep = report(tmp_path, log, exceptions=[exc("scanner@example.com")], policy="none")
    g = rep["gate"]["domains"]["example.com"]
    assert g["verdict"] == "go" and g["blockers"] == [] and g["excepted_delivered"] == 4
    assert not [r for r in g["reasons"] if "reached a mailbox -" in r]
    note = next(r for r in g["reasons"] if r.startswith("exception: "))
    assert "4 mail-log failure(s) from scanner@example.com excepted until 2099-01-01 (4 of them reached a mailbox " \
           "despite failing)" in note
    assert rep["maillog"]["by_domain"]["example.com"]["excepted_delivered"] == 4
    # a sender left alongside: the gate counts only it, and says how many more were excepted
    log.add("billing@example.com", "example.com", "Statement 100# ready", 3, DELIVERED)
    rep = report(tmp_path, log, exceptions=[exc("scanner@example.com")], policy="none")
    g = rep["gate"]["domains"]["example.com"]
    assert g["verdict"] == "no_go"
    assert ("example.com: 3 message(s) from this domain failed authentication but reached a mailbox (4 more excepted) - "
            "a local override is masking failures external receivers enforce") in g["blockers"]
    # and with no domain named, the whole log's blocker the same way
    rep = audit.build_report(domains=[], maillog=log.write(tmp_path / "all.csv"), offline=True, auth_column="DMARC",
                             exceptions=[exc("scanner@example.com")])
    assert ("3 message(s) failed authentication but reached a mailbox (4 more excepted) - a local override is masking "
            "failures external receivers enforce") in rep["gate"]["reasons"]


def test_d18_the_excepted_delivered_messages_are_not_override_work(tmp_path):
    log = Log().add("staff@example.com", "example.com", "Hello #", 40, DELIVERED, "pass")
    log.add("scanner@example.com", "example.com", "Scan # complete", 4, DELIVERED)
    for keep in (False, True):  # the census alone, then the verdicts kept beside it (--keep-verdicts)
        rep = report(tmp_path, log, exceptions=[exc("scanner@example.com")], policy="none", keep=keep)
        assert bool(rep["maillog"]["verdicts"]) is keep
        assert any(f["id"] == "MAILFLOW-002" and f["severity"] == "major" for f in rep["findings"])
        doc, md = doc_md(rep)
        assert "- **Delivered despite failing: 4** - all formally excepted in audit.toml" in md
        assert "reached inboxes despite failing" not in md and "scanner@example.com x4" in md
        assert "and it is ready now" in doc["one_liner"] and doc["ask"].startswith("The ask this week: a go-ahead")
        # MAILFLOW-002 is covered: nothing of it is left to hand out, as work or as an owner question
        section = md.split("## What happens next, by owner\n")[1].split("\n## ")[0].strip()
        assert section == ("- Nothing to do this week: no plan changes, and every failure this run names is formally "
                           "excepted in audit.toml (What is failing lists them)."), keep
        assert "MAILFLOW-002" not in md and not [q for q in doc["open_questions"] if q["kind"] == "unassigned"]
    # five excepted senders do not crowd out the one left
    log = Log().add("staff@example.com", "example.com", "Hello #", 40, DELIVERED, "pass")
    for i in range(1, 6):
        log.add("printer%d@example.com" % i, "example.com", "Scan # complete", 2, DELIVERED)
    log.add("billing@example.com", "example.com", "Statement 100# ready", 1, DELIVERED)
    rep = report(tmp_path, log, exceptions=[exc("printer%d@example.com" % i) for i in range(1, 6)])
    doc, md = doc_md(rep)
    assert [h for h in actions(doc) if "reached inboxes" in h] == ["billing@example.com - 1 message reached inboxes "
                                                                   "despite failing"]
    assert "- **Delivered despite failing: 11** (10 of them formally excepted in audit.toml)" in md


def test_d19_every_delivered_sender_past_the_fifth_is_still_handed_out(tmp_path):
    log = Log()
    for i, n in enumerate((7, 6, 5, 4, 3, 2, 1), 1):
        log.add("app%d@example.com" % i, "example.com", "Run # done", n, DELIVERED)
    rep = report(tmp_path, log)
    doc, _ = doc_md(rep)
    items = [h for h in actions(doc) if "reached inboxes" in h]
    assert len(items) == 6 and items[-1] == "2 more senders with 3 messages that reached inboxes despite failing"


# ------------------------------------------------------------------ C13, C15: the aggregate reports

def test_c13_an_excepted_aggregate_report_source_is_listed_once_and_never_handed_out():
    for match in ("198.51.100.20", "198.51.100.16/28", "bounce.esp.invalid"):
        rua = reports_doc([stream("203.0.113.66", 60, "likely_spoof"),
                       stream("198.51.100.20", 40, "likely_misconfigured", ["bounce.esp.invalid"])])
        rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["example.com"]}, "dns": dns("quarantine"),
               "rua": rua, "maillog": None, "findings": [{"id": "OUTSIDE-001", "severity": "major", "source": "rua",
                                                         "title": "failing sources", "action": "a", "evidence": "e"}],
               "gate": audit.gate_verdict(dns("quarantine"), rua, None, ["example.com"], exceptions=[exc(match)])}
        assert rep["gate"]["verdict"] == "go" and rep["gate"]["exceptions"]["excepted_streams"] == ["198.51.100.20"]
        doc, md = doc_md(rep)
        assert md.count("198.51.100.20") == 1, match
        assert "- Formally excepted in audit.toml and not counted above: 198.51.100.20 x40 (looks like our own system " \
               "misconfigured)" in md
        assert not [h for h in actions(doc) if "198.51.100.20" in h]
        assert "None of our own sending sources is failing (from the aggregate reports); 1 source looks like spoofing" \
               in doc["one_liner"] and "and it is ready now" in doc["one_liner"]
        assert doc["ask"].startswith("The ask this week: a go-ahead to move from p=quarantine to p=reject")
        assert doc["failing"]["outside_excepted"][0]["name"] == "198.51.100.20"


def test_c15_the_reports_likely_misconfigured_reads_as_our_own_system():
    deciding = ("SPF passes for a platform listed as ours (bounce.esp.invalid) and nothing marks forwarding: a broken, "
                "rotated or mismatched DKIM key at a system sending as the domain")
    rua = reports_doc([stream("198.51.100.20", 40, "likely_misconfigured", ["bounce.esp.invalid"],
                          ["DKIM signature for the domain itself present but failed verification (40 msgs): modified in "
                           "transit (forwarding, list) or a broken key", deciding])])
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["example.com"]}, "dns": dns("quarantine"),
           "rua": rua, "maillog": None, "findings": [],
           "gate": audit.gate_verdict(dns("quarantine"), rua, None, ["example.com"])}
    doc, md = doc_md(rep)
    assert "1 of our own sending sources still fails (from the aggregate reports) (198.51.100.20 as example.com x40)" \
           in doc["one_liner"]
    assert "unclear" not in doc["one_liner"]
    assert "- **198.51.100.20 - 40 failing messages as example.com** looks like our own system misconfigured" in md
    item = next(i for g in doc["actions_by_owner"] for i in g["items"] if i["hook"].startswith("198.51.100.20"))
    assert item["action"].startswith("DKIM-sign the system behind this IP with an aligned d=")
    assert deciding in item["action"]
    assert next_steps.LIKELY_WORDS["likely_misconfigured"] == next_steps.LIKELY_WORDS["likely_misconfigured_sender"]


# ------------------------------------------------------------------ C16, C17: the gate's verdict decides

def maillog_doc(tmp_path, log):
    return audit.run_maillog(log.write(tmp_path / "log.csv"), auth_column="DMARC")


def assemble(gate, dns_reports, maillog=None, rua=None, domains=("example.com",)):
    return {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": list(domains)}, "gate": gate,
            "dns": dns_reports, "maillog": maillog, "rua": rua, "findings": []}


def test_c16_insufficient_data_is_never_ready_and_never_a_go_ahead(tmp_path):
    passing = Log().add("hr@example.com", "example.com", "Hello", 5, DELIVERED, "pass")
    other = Log().add("hi@other.example", "other.example", "Hello", 5, DELIVERED, "pass")
    cases = (  # no failure evidence; no rows for the domain; no aligned-DKIM evidence before reject
        (dns("none"), None, ("example.com",), "no failure evidence was supplied"),
        (dns("none", "100", "example.com", "other.example"), maillog_doc(tmp_path, other),
         ("example.com", "other.example"), "the evidence supplied has no rows for example.com"),
        (dns("quarantine"), maillog_doc(tmp_path, passing), ("example.com",), "this run holds no aligned-DKIM evidence"))
    for dns_reports, ml, domains, why in cases:
        gate = audit.gate_verdict(dns_reports, None, ml, list(domains))
        assert gate["domains"]["example.com"]["verdict"] == "insufficient_data"
        for older in (False, True):  # the gate's blockers field, then an older report's prose
            if older:
                for g in gate["domains"].values():
                    g.pop("blockers")
                    g.pop("notes")
            doc = next_steps.build(assemble(gate, dns_reports, ml, domains=domains))
            assert "ready now" not in doc["one_liner"] and "on hold - it needs more data: " + why in doc["one_liner"]
            assert "go-ahead" not in doc["ask"]
            assert doc["ask"].startswith("The ask this week: more data before the next step on example.com")
            assert [b["kind"] for b in doc["next_step"]["blockers"]] == ["data"]
            assert any(q["question"].startswith("Can we supply the data the next step on example.com")
                       for q in doc["open_questions"])


def test_c17_a_go_verdict_is_ready_and_its_notes_hold_nothing(tmp_path):
    log = (Log().add("hr@example.com", "example.com", "Hello", 300, DELIVERED, "pass")
           .add("app@a.example.com", "a.example.com", "Build #", 3))
    ml = maillog_doc(tmp_path, log)
    gate = audit.gate_verdict(dns("none"), None, ml, ["example.com"])
    g = gate["domains"]["example.com"]
    assert g["verdict"] == "go"
    for older in (False, True):  # the gate's own fields, then an older report's prose
        doc, md = doc_md(assemble(gate, dns("none"), ml))
        assert doc["one_liner"].endswith("The next safe step is to move to p=quarantine at a low pct (for example "
                                         "pct=10), and it is ready now.")
        assert doc["ask"].startswith("The ask this week: a go-ahead to move to p=quarantine")
        assert not [q for q in doc["open_questions"] if q["kind"] == "blocker"]
        assert ("From the audit on example.com (information; it holds nothing):\n- unaudited subdomains a.example.com "
                "carry 3 logical messages, 3 genuine failures") in md
        if not older:
            assert g["blockers"] == [] and g["notes"][0].startswith("example.com: unaudited subdomain")
            g.pop("blockers")
            g.pop("notes")
    # at p=reject the go verdict's narration of the failing sources is not a gap to close
    rua = reports_doc([stream("198.51.100.66", 60, "likely_spoof")])
    gate = audit.gate_verdict(dns("reject"), rua, None, ["example.com"])
    assert gate["domains"]["example.com"]["verdict"] == "go"
    doc = next_steps.build(assemble(gate, dns("reject"), rua=rua))
    assert not [q for q in doc["open_questions"] if "198.51.100.66 (60" in q["question"]]
    assert "198.51.100.66 (60 msgs, likely_spoof)" in gate["domains"]["example.com"]["notes"]


def test_c16_c17_the_first_step_needs_no_evidence_and_a_no_go_always_holds():
    # no policy read because DNS was never read (an offline run): the step is to read it, held for that data -
    # never a monitoring record beside one nobody could see, never a go-ahead (round 11, N4)
    gate = audit.gate_verdict({}, None, None, ["example.com"])
    assert gate["domains"]["example.com"]["verdict"] == "insufficient_data"
    doc = next_steps.build(assemble(gate, {}))
    assert doc["next_step"]["kind"] == "unread" and doc["next_step"]["data"]
    assert "monitoring-only" not in doc["one_liner"] and "go-ahead" not in doc["ask"]
    assert doc["one_liner"].endswith("The next safe step is to determine example.com's DMARC policy, on hold - it needs "
                                     "more data: no DMARC policy could be determined for example.com - run online so "
                                     "live DNS is checked, or supply rua reports that cover it.")
    assert doc["ask"].startswith("The ask this week: more data before the next step on example.com (determine "
                                 "example.com's DMARC policy): no DMARC policy could be determined")
    assert [q for q in doc["open_questions"] if q["kind"] == "blocker"
            and q["question"].startswith("Can we supply the data the next step on example.com")]
    # DNS answered that there is no record at all: the first step is the monitoring-only record, which needs no
    # evidence, and the gate's missing-policy hold never holds it
    absent = {"example.com": dict(dns("none")["example.com"], dmarc=None, dmarc_source=None, effective_policy=None,
                                  dmarc_status="absent")}
    gate = audit.gate_verdict(absent, None, None, ["example.com"])
    doc = next_steps.build(assemble(gate, absent))
    assert doc["next_step"]["kind"] == "first" and doc["next_step"]["data"] == []
    assert not [q for q in doc["open_questions"] if q["kind"] == "blocker"]
    assert doc["one_liner"].endswith("The first step is to publish a monitoring-only DMARC record for example.com so "
                                     "reports start; no policy could be read.")
    # a no_go whose reasons the document does not recognise (an older report's prose) still holds the step
    gate = audit.gate_verdict(dns("none"), None, None, ["example.com"])
    g = gate["domains"]["example.com"]
    g.update(verdict="no_go", reasons=["exception: something", "step being gated: move to p=quarantine"])
    g.pop("blockers")
    g.pop("notes")
    doc = next_steps.build(assemble(gate, dns("none")))
    assert doc["one_liner"].endswith("on hold while: the audit's gate says not yet (report.md lists why).")
    assert "ready now" not in doc["one_liner"] and "go-ahead" not in doc["ask"]


# ------------------------------------------------------------------ C18, C43: todo.md and the Slack summary

def test_c18_todo_counts_and_names_only_what_the_exceptions_left(tmp_path):
    log = Log()
    for i in range(1, 7):
        log.add("news%d@example.com" % i, "bounce.esp.invalid", "Newsletter #", 3)
    log.add("billing@example.com", "example.com", "Statement 100# ready", 2)
    rep = report(tmp_path, log, exceptions=[exc("bounce.esp.invalid")])
    todo = collect.render_todo(rep, {"changes": [], "holds": []})
    section = todo.split("## 3. Fix senders (DKIM first)")[1].split("## 4.")[0]
    assert ("- mail log: 2 logical messages failed with no passing copy, from 1 sender, besides 18 formally excepted in "
            "audit.toml (section 6) (top senders: billing@example.com x2) - work the senders") in section
    assert "news1@example.com" not in section
    # every failure excepted: no work, the count named once
    log = Log().add("alerts@example.com", "example.com", "Nightly export #", 4)
    log.add("news@example.com", "bounce.esp.invalid", "Newsletter #", 4).add("postmaster@example.com", "", "Undeliverable", 2)
    rep = report(tmp_path, log, exceptions=[exc("alerts@example.com"), exc("bounce.esp.invalid"),
                                             exc("postmaster@example.com")])
    section = collect.render_todo(rep, {"changes": [], "holds": []}).split("## 3.")[1].split("## 4.")[0]
    assert "- mail log: nothing to fix - all 10 genuine failures are formally excepted in audit.toml (section 6)" in section
    assert "work the senders" not in section and "top senders" not in section


def test_d18_todo_hands_out_only_the_overrides_the_exceptions_left(tmp_path):
    log = Log().add("staff@example.com", "example.com", "Hello #", 40, DELIVERED, "pass")
    log.add("scanner@example.com", "example.com", "Scan # complete", 4, DELIVERED)
    log.add("billing@example.com", "example.com", "Statement 100# ready", 3, DELIVERED)
    rep = report(tmp_path, log, exceptions=[exc("scanner@example.com")])
    assert any(f["id"] == "MAILFLOW-002" for f in rep["maillog"]["findings"])
    section = collect.render_todo(rep, {"changes": [], "holds": []}).split("## 3.")[1].split("## 4.")[0]
    assert ("- mail log: 3 messages failed authentication but reached a mailbox, from 1 sender, besides 4 formally "
            "excepted in audit.toml (section 6) (top senders: billing@example.com x3) - find the override") in section
    assert "scanner@example.com" not in section
    # every delivered message excepted: the override stays accepted with the exception, and none of it is work
    log = Log().add("staff@example.com", "example.com", "Hello #", 40, DELIVERED, "pass")
    log.add("scanner@example.com", "example.com", "Scan # complete", 4, DELIVERED)
    rep = report(tmp_path, log, exceptions=[exc("scanner@example.com")])
    section = collect.render_todo(rep, {"changes": [], "holds": []}).split("## 3.")[1].split("## 4.")[0]
    assert "- mail log: nothing to fix - all 4 genuine failures are formally excepted in audit.toml (section 6)" in section
    assert "reached a mailbox" not in section and "scanner@example.com" not in section


def test_c43_new_and_top_failing_senders_leave_the_excepted_out(tmp_path):
    first = Log().add("billing@example.com", "example.com", "Statement 100# ready", 3)
    prev = report(tmp_path, first, exceptions=[exc("alerts@example.com")])
    second = Log().add("billing@example.com", "example.com", "Statement 100# ready", 3)
    second.add("alerts@example.com", "example.com", "Nightly export #", 2)
    rep = report(tmp_path, second, exceptions=[exc("alerts@example.com")], previous_report=prev)
    assert [s["sender"] for s in rep["delta"]["new_senders"]] == ["alerts@example.com"]
    doc, md = doc_md(rep)
    assert "Failing senders not seen in the previous run" not in md
    assert "fail only where audit.toml formally excepts them: 2 messages (alerts@example.com x2)." in md
    text = notify.summarize(rep)
    assert "- top failing senders (census): example.com x3 (likely_misconfigured_sender); 2 formally excepted in audit.toml" in text
    assert "- new failing senders: none left; 2 formally excepted in audit.toml" in text
    assert notify.census_excepted(rep["maillog"]["census"]) == 2
    # a census from before the counts is read as it always was, clean entries and all
    old = {"by_envelope": [{"envelope_domain": "example.com", "genuine_failures": 5, "likely": "unknown"},
                           {"envelope_domain": "news.example.com", "genuine_failures": 0, "likely": None}]}
    assert notify.census_top(old) == (["example.com x5 (unknown)"], 1) and notify.census_excepted(old) == 0


def test_the_census_counts_survive_dedupe_json_and_a_verdict_list():
    vs = [{"sender": "a@example.com", "domain": "example.com", "envelope_domain": "example.com", "genuine_failure": True,
           "likely": "likely_spoof", "excepted": "a@example.com", "delivered_despite_fail": True},
          {"sender": "a@example.com", "domain": "example.com", "envelope_domain": "example.com", "genuine_failure": True,
           "likely": "unknown", "excepted": False}]
    row = dedupe.census(vs)["by_sender"][0]
    assert (row["excepted"], row["excepted_delivered"], row["likely_counts"], row["likely_after"]) == (
        1, 1, {"unknown": 1}, "unknown")
    json.dumps(dedupe.census(vs))


# ------------------------------------------------------------------ what the verification of these fixes found

def test_when_the_gate_marks_a_library_callers_verdicts_the_census_follows(tmp_path):
    """run_maillog's document carries a census written before any exception is known; the gate marks the
    verdicts itself and the census counts those marks, so the excepted sender is never work - read from
    the census, or from the verdicts when the document has no census."""
    log = (Log().add("hr@example.com", "example.com", "Hello", 20, DELIVERED, "pass")
           .add("scanner@example.com", "example.com", "Scan # complete", 4)
           .add("billing@example.com", "example.com", "Statement 100# ready", 3))
    for has_census in (True, False):
        ml = maillog_doc(tmp_path, log)
        assert "census" in ml
        if not has_census:
            del ml["census"]
        gate = audit.gate_verdict(dns("none"), None, ml, ["example.com"], exceptions=[exc("scanner@example.com")])
        if has_census:
            row = next(r for r in ml["census"]["by_sender"] if r["sender"] == "scanner@example.com")
            assert (row["excepted"], row["likely_after"]) == (4, None)
        doc, md = doc_md(assemble(gate, dns("none"), ml))
        assert actions(doc) == ["billing@example.com - 3 messages"], has_census
        assert "Formally excepted in audit.toml and not counted above: 4 messages (scanner@example.com x4)." in md
        assert md.count("scanner@example.com") == 1
        assert ("1 of our own senders still fails (billing@example.com x3); 4 messages from 1 sender formally "
                "excepted in audit.toml") in doc["one_liner"]
    # a report built without the exceptions and gated again with them: its attribution follows the marks too
    log.add("digest@outside.invalid", "outside.invalid", "Digest #", 2)
    rep = report(tmp_path, log, keep=True)
    rep["dns"] = dns("none")
    rep["gate"] = audit.gate_verdict(rep["dns"], None, rep["maillog"], ["example.com"],
                                     exceptions=[exc("scanner@example.com"), exc("digest@outside.invalid")])
    assert rep["maillog"]["by_domain"]["example.com"]["excepted"] == 4
    assert rep["maillog"]["excepted_elsewhere"] == {"outside.invalid": 2}
    line = doc_md(rep)[0]["one_liner"]
    assert "7 messages from example.com failed with no passing copy" in line
    assert "3 from 1 of our own senders (billing@example.com x3); 4 formally excepted in audit.toml" in line


def test_the_top_failing_senders_are_the_worst_of_what_the_exceptions_left(tmp_path):
    log = Log()
    for i, env in enumerate(("relay1.invalid", "relay2.invalid", "relay3.invalid"), 1):
        log.add("scanner%d@example.com" % i, env, "Scan # complete", 30 - i)  # excepted below
        log.add("app%d@example.com" % i, env, "Build # done", 1)
    log.add("billing@example.com", "billing.invalid", "Statement 100# ready", 10)  # the one real stream
    rep = report(tmp_path, log, exceptions=[exc("scanner%d@example.com" % i) for i in (1, 2, 3)])
    top, failing = notify.census_top(rep["maillog"]["census"])
    assert [t.split(" (")[0] for t in top] == ["billing.invalid x10", "relay1.invalid x1", "relay2.invalid x1"]
    assert failing == 4
    assert "- top failing senders (census): billing.invalid x10 (" in notify.summarize(rep)
    # a tie keeps the census's own order (more messages first), as it did before the exceptions were counted
    census = {"by_envelope": [{"envelope_domain": "b.example", "genuine_failures": 2, "messages": 9},
                              {"envelope_domain": "a.example", "genuine_failures": 2, "messages": 3}]}
    assert notify.census_top(census) == (["b.example x2 (unknown)", "a.example x2 (unknown)"], 2)


def test_the_spoof_action_says_which_envelope_carried_most_of_the_messages(tmp_path):
    log = Log().add("staff@example.com", "example.com", "Hello #", 40, DELIVERED, "pass")
    log.add("ceo@example.com", "spoofer.invalid", "Wire transfer request #", 5)
    for who in ("news", "promo"):  # two streams of our own, each with one lure-word message split off as a spoof
        log.add("%s@example.com" % who, "example.com", "Weekly %s #" % who, 3)
        log.add("%s@example.com" % who, "example.com", "Urgent payment update")
    rep = report(tmp_path, log, policy="none")
    doc, _ = doc_md(rep)
    item = next(i for g in doc["actions_by_owner"] for i in g["items"] if i["kind"] == "spoof")
    assert item["hook"] == "7 messages from 3 addresses that look like spoofing"
    assert item["action"].endswith("(most came in via spoofer.invalid, as example.com)"), item["action"]


def test_at_the_end_of_the_ratchet_the_data_question_names_no_next_step(tmp_path):
    other = Log().add("hi@other.example", "other.example", "Hello", 5, DELIVERED, "pass")
    cases = ((dns("reject"), None, ("example.com",), "supply aggregate reports and/or a mail log"),
             (dns("reject", "100", "example.com", "other.example"), maillog_doc(tmp_path, other),
              ("example.com", "other.example"), "the evidence supplied has no rows for example.com"))
    for dns_reports, ml, domains, why in cases:
        gate = audit.gate_verdict(dns_reports, None, ml, list(domains))
        g = gate["domains"]["example.com"]
        assert (g["verdict"], g["next_step"]) == ("insufficient_data", "none - already at the end")
        for older in (False, True):  # the gate's blockers field, then an older report's prose
            if older:
                for d in gate["domains"].values():
                    d.pop("blockers")
                    d.pop("notes")
            doc = next_steps.build(assemble(gate, dns_reports, ml, domains=domains))
            qs = [q["question"] for q in doc["open_questions"] if q["kind"] == "blocker"]
            assert len(qs) == 1 and qs[0].startswith("Can we supply the data that confirms enforcement on example.com "
                                                     "is safe: "), qs
            assert why in qs[0] and "already at the end" not in qs[0] and "next step" not in qs[0]
            assert "ready now" not in doc["one_liner"] and "go-ahead" not in doc["ask"]


def test_odd_census_shapes_read_as_no_rows():
    for odd in (5, "x", {"a": 1}, None):
        census = {"by_envelope": odd, "by_sender": odd}
        assert notify.census_top(census) == ([], 0) and notify.census_excepted(census) == 0
        rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["example.com"]}, "gate": {},
               "maillog": {"counters": {"genuine_failures": 0, "delivered_despite_fail": 0}, "census": census},
               "findings": []}
        collect.render_todo(rep, {"changes": [], "holds": []})
        next_steps.build(rep)
