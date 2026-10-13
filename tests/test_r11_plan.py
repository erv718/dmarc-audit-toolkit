"""Round 11, group P: the plan's rows that could junk or reject legitimate
mail, the evidence they rest on, and the words that describe them.
P2: the move to reject keeps the sending subdomains where they are, and the
step to sp=reject proposes their records at quarantine. P3: a quarantine-now
record keeps sp=none on any domain, and where the names below inherit
quarantine today the ones that send get records at that policy first. P5: a
spoof label on the envelope alone or on a billing word, and failing report
volume without a spoof sign, are checks, never spoofing; the sp= step and
the ramp name such mail. P6: a step on a domain no evidence covers says so.
P7: a derived report address is named. P8: the sp= step asks about rarer
senders and names the span of the reports about the record (each report's
own dates, implausible ones ignored); a reject row whose subdomains follow
p= asks the same. P9: a mail log from another period verifies nothing. P10:
the park check names what measures the mail flow. P12: the full-window
totals cover the mail flow only over its whole span and at its grain. P13:
a tag written with spaces around '=' is still that tag. P14: a failed MX
lookup never parks a domain. P15: a first record of its own keeps the
reporting it inherits. P16: the mailflow tag never makes a domain
tenant-carried. P18, P19, P21 to P23: the full-window totals the plan reads
are kept, set aside and said right. P24 to P26: damaged values never end in
a traceback. Synthetic data, offline: nothing here touches the network."""

import csv
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

import audit
import collect
import dedupe
import discover
import dns_audit
import next_steps
import plan as plan_mod
import test_r10_phase2 as phase2  # the in-memory tenant collect.py runs against
import verify

ROOT = Path(__file__).resolve().parent.parent
RUA = "mailto:dmarc-reports@corp.example"
APEX = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
M365 = "v=spf1 include:spf.protection.outlook.com -all"
GOOGLE = {"spf": "v=spf1 include:_spf.google.com ~all", "spf_terminator": "~all", "dkim_selectors": ["google"],
          "mx": ["1 smtp.google.com"]}
COLS = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
        "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC", "Direction"]
DAY = 86400
BEGIN = 1791417600  # 2026-10-08 00:00:00 UTC: the synthetic reports' first day
MONTHLY = "no sender that mails monthly or less often (statements, renewals) uses this domain"


def day(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%d")


# ------------------------------------------------------------------ a synthetic tenant, built offline

class Log:
    """A synthetic mail-log export (raw_maillog.kql's columns, one row per recipient, one Message-ID per message).
    when: the day and hour the rows carry (ISO, UTC), minutes counting up per message."""

    def __init__(self):
        self.rows, self.n = [], 0

    def add(self, sender, subject, dmarc="pass", times=1, env=None, direction="Inbound", recipients=1,
            when="2026-10-07T10:00:00Z"):
        for _ in range(times):
            self.n += 1
            dom = sender.rpartition("@")[2]
            stamp = when[:14] + "%02d:00Z" % (self.n % 60)
            for k in range(recipients):
                self.rows.append([stamp, "<r%05d@mail.invalid>" % self.n, sender, dom, env or dom,
                                  "user%d@corp.example" % ((self.n + k) % 7), subject.replace("#", str(self.n)),
                                  "Delivered", "Inbox", dmarc, direction])
        return self

    def write(self, path):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(COLS)
            w.writerows(self.rows)
        return str(path)


def rua_report(path, domain, policy, rows, begin=BEGIN, end=None):
    """One aggregate report about domain's record over [begin, end]; rows: (source_ip, count, header_from,
    dkim_domain, dkim_result, spf_domain, spf_result), with relaxed alignment judged here."""
    def aligned(d, hf):
        return bool(d) and (d == hf or hf.endswith("." + d) or d.endswith("." + hf))
    recs = "".join(
        "<record><row><source_ip>%s</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition>"
        "<dkim>%s</dkim><spf>%s</spf></policy_evaluated></row><identifiers><header_from>%s</header_from></identifiers>"
        "<auth_results>%s<spf><domain>%s</domain><scope>mfrom</scope><result>%s</result></spf></auth_results></record>"
        % (ip, n, "pass" if dres == "pass" and aligned(dkd, hf) else "fail",
           "pass" if spr == "pass" and aligned(spd, hf) else "fail", hf,
           ("<dkim><domain>%s</domain><selector>s1</selector><result>%s</result></dkim>" % (dkd, dres)) if dkd else "",
           spd, spr)
        for ip, n, hf, dkd, dres, spd, spr in rows)
    end = begin + DAY - 1 if end is None else end
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<feedback><report_metadata><org_name>reporter.invalid</org_name>'
        "<email>noreply@reporter.invalid</email><report_id>%s</report_id><date_range><begin>%d</begin>"
        "<end>%d</end></date_range></report_metadata><policy_published><domain>%s</domain><adkim>r</adkim>"
        "<aspf>r</aspf><p>%s</p><sp>none</sp><pct>100</pct></policy_published>%s</feedback>\n"
        % (path.stem, begin, end, domain, policy, recs), encoding="utf-8")
    return str(path)


def fid(*ids):
    return [{"id": i, "severity": "major", "area": i.split("-")[0].lower(), "title": i, "evidence": "",
             "action": "", "verified": True} for i in ids]


def dns_doc(domain, **over):
    """A domain on Microsoft 365: MX at the tenant, SPF through it, a DKIM selector; no DMARC record."""
    base = {"domain": domain, "spf": M365, "spf_status": "found", "spf_terminator": "-all", "spf_lookups": 2,
            "spf_lookups_failed": 0, "spf_verified": True, "dmarc": None, "dmarc_source": None,
            "effective_policy": None, "inherited": False, "dmarc_status": "absent",
            "dkim_selectors": ["selector1"], "dkim_status": "found",
            "mx": ["0 %s.mail.protection.outlook.com" % domain.replace(".", "-")], "mx_null": False,
            "mx_status": "found", "flags": [], "findings": [], "evidence": []}
    base.update(over)
    return base


def own_record(domain, record=None, **over):
    """A domain with a DMARC record of its own (p=none with the run's rua unless given)."""
    record = record or "v=DMARC1; p=none; rua=%s;" % RUA
    p = plan_mod.dmarc_tags(record).get("p", "none")
    return dns_doc(domain, dmarc=record, dmarc_source="_dmarc." + domain, effective_policy=p, dmarc_status="found",
                   findings=fid("DMARC-002") if p == "none" else [], **over)


def inherits(domain, record=APEX, source="_dmarc.corp.example", **over):
    """A subdomain with no record of its own, under the record its organization publishes."""
    policy = plan_mod.dmarc_tags(record).get("sp") or plan_mod.dmarc_tags(record).get("p")
    return dns_doc(domain, dmarc=record, dmarc_source=source, inherited=True, effective_policy=policy,
                   dmarc_status="found", mx=[], mx_status="absent",
                   findings=fid("DMARC-002") if policy == "none" else [], **over)


def flow(out=0, inn=0, last_seen=None):
    return {"messages": out + inn, "outbound": out, "inbound": inn, "last_seen": last_seen}


def no_record(*names):
    """report.dns_extra as collect.py writes it when DNS shows no record at these names' own _dmarc."""
    return {n: {"dmarc": None, "status": "absent", "source": None, "path": "port53-udp"} for n in names}


def audited(tmp_path, docs, log=None, reports=(), flows=None, sources=None, **kw):
    """report.json as collect.py writes it for the domains in docs: the mail log and the aggregate reports read
    offline, the mail flow measured over 30 days, and the gate decided on all of it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    names = list(docs)
    maillog = log.write(tmp_path / "maillog.csv") if log is not None else None
    rep = audit.build_report(domains=names, rua_paths=list(reports), maillog=maillog, offline=True,
                             auth_column="DMARC" if maillog else None, domain_sources=sources,
                             mailflow={"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": dict(flows or {})},
                             **kw)
    rep["dns"] = docs
    rep["gate"] = audit.gate_verdict(docs, rep["rua"], rep["maillog"], names, None, {}, rep["inputs"]["domain_sources"])
    rep["generated_utc"] = "2026-10-09T06:00:00Z"
    return rep


def apex_report(record, subs=(), flows=None, rua=None, maillog=None, sub_record=None):
    """corp.example at the given record with audited subdomains inheriting it, hand-built like plan.py's inputs."""
    dns = {"corp.example": own_record("corp.example", record)}
    for s in subs:
        dns[s] = inherits(s, sub_record or record)
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": sorted(dns)}, "gate": {"domains": {}},
           "dns": dns, "maillog": maillog, "rua": rua}
    if flows is not None:
        rep["mailflow"] = {"days": 30, "domains": flows}
    return rep


def rua_doc(domain="corp.example", by_header_from=(), streams=(), begin=None, end=None):
    """A hand-built rua section: one report about domain's record (rua.sources.reports, as rua_parse writes
    it) over the span given, the totals' span the same, and the rows given."""
    totals = {"messages": 100, "domains": [domain]}
    doc = {"totals": totals, "policy_check": {"seen": [{"domain": domain, "p": "quarantine"}]},
           "by_header_from": list(by_header_from), "failing_streams": list(streams), "spf_only_senders": []}
    if begin is not None:
        totals.update(begin=begin, end=end)
        doc["sources"] = {"reports": [{"source": "report.xml", "domain": domain, "begin": begin, "end": end}]}
    return doc


def spoof_stream(domain, n=40, ip="203.0.113.66"):
    return {"source_ip": ip, "count": n, "pass": 0, "fail": n, "header_from": [domain], "likely": "likely_spoof",
            "likely_signals": ["no DKIM signature and no SPF pass on any domain (%d of %d msgs)" % (n, n)]}


def plan_of(rep, rua=RUA, inventory=None):
    return plan_mod.build_plan(rep, inventory, rua)


def rows(p, domain=None, kind=None, host=None):
    return [c for c in p["changes"] if (domain is None or c["domain"] == domain) and (kind is None or c["kind"] == kind)
            and (host is None or c["hostname"] == host)]


def one(p, domain=None, kind=None, host=None):
    hits = rows(p, domain, kind, host)
    assert len(hits) == 1, (domain, kind, host, [(c["domain"], c["kind"], c["hostname"]) for c in p["changes"]])
    return hits[0]


def holds_of(p, domain):
    return [h["reason"] for h in p["holds"] if h["domain"] == domain]


# ------------------------------------------------------------------ P2: reject keeps the subdomains where they are

def test_p2_the_move_to_reject_keeps_the_sending_subdomains_where_they_are():
    """An apex at p=quarantine with no sp=: its subdomains without a record of their own inherit quarantine today
    and would follow p= to reject. The reject row adds sp=quarantine, so they stay where they are, the row holds
    nothing and its plain words say so; next_steps carries the same words."""
    flows = {"corp.example": flow(500), "a.corp.example": flow(40)}
    rec = "v=DMARC1; p=quarantine; rua=%s;" % RUA
    p = plan_of(apex_report(rec, ("a.corp.example",), flows, sub_record="v=DMARC1; p=quarantine; rua=%s;" % RUA))
    reject = one(p, "corp.example", "ratchet")
    assert reject["value"] == "v=DMARC1; p=reject; sp=quarantine; rua=%s;" % RUA and reject["current"] == rec
    assert reject["why"].endswith("; sp=quarantine keeps the subdomains without a record of their own at quarantine, "
                                  "where the record has them today: the ones that send (a.corp.example) would otherwise "
                                  "follow p= to reject; they move with a later sp= step")
    assert reject["human_summary"] == ("Move corp.example to reject so mail that fails checks is refused instead of "
                                       "junked; subdomains without a record of their own stay at quarantine, where they "
                                       "are today (the same change adds sp=quarantine), as a separate later step.")
    assert not holds_of(p, "corp.example")
    assert "subdomains are a separate later step" not in reject["human_summary"]
    doc = next_steps.build(apex_report(rec, ("a.corp.example",), flows), p)
    assert "stay at quarantine, where they are today (the same change adds sp=quarantine)" in next_steps.render_md(doc)
    # the sending subdomain has a record of its own: nothing follows p= that sends, so the row moves p= alone
    rep = apex_report(rec, (), flows)
    rep["dns"]["a.corp.example"] = own_record("a.corp.example")
    rep["inputs"]["domains"].append("a.corp.example")
    reject = one(plan_of(rep), "corp.example", "ratchet")
    assert reject["value"] == "v=DMARC1; p=reject; rua=%s;" % RUA
    assert reject["human_summary"].endswith("; subdomains without a record of their own move to reject with it (the "
                                            "record has no sp=).")
    # sp=none: the sp= step is its own row, and the words say so, as before
    reject = next(c for c in rows(plan_of(apex_report(APEX, ("a.corp.example",), flows)), "corp.example", "ratchet")
                  if c["priority"] == 3)
    assert reject["value"] == "v=DMARC1; p=reject; sp=none; rua=%s;" % RUA
    assert reject["human_summary"].endswith("; subdomains are a separate later step.")


def test_p2_the_sp_reject_step_names_the_sending_subdomains_without_a_record():
    """At p=reject; sp=quarantine the next subdomain step is sp=reject, where the failing mail of a sending
    subdomain without a record of its own bounces: the row names them, the domain is held for them, and the
    plan proposes each one's record at p=quarantine - where sp= has it today - so the hold has a row to
    publish; a p=none record would lower it from quarantine to none."""
    rec = "v=DMARC1; p=reject; sp=quarantine; rua=%s;" % RUA
    flows = {"corp.example": flow(500), "a.corp.example": flow(40), "b.corp.example": flow()}
    p = plan_of(apex_report(rec, ("a.corp.example", "b.corp.example"), flows))
    step = one(p, "corp.example", "ratchet")
    assert step["value"] == "v=DMARC1; p=reject; sp=reject; rua=%s;" % RUA
    assert step["prerequisites"][:2] == [
        "a week of subdomain reports at sp=quarantine showing only spoofing",
        "every subdomain that sends has its own _dmarc record: a.corp.example has none yet (the records above, at "
        "p=quarantine), and at sp=reject their failing mail is refused"]
    assert holds_of(p, "corp.example") == [
        "subdomains that send have no record of their own: a.corp.example - at sp=reject their failing mail is refused "
        "instead of junked; publish their records (above, at p=quarantine, where sp= has them today) before sp= moves "
        "to reject"]
    own = one(p, "a.corp.example", "new")
    assert own["value"] == "v=DMARC1; p=quarantine; rua=%s;" % RUA and own["current"] == "none"
    assert own["priority"] == 1 and own["hostname"] == "_dmarc.a.corp.example"
    assert own["why"] == ("sending subdomain without a record of its own: it inherits p=quarantine from corp.example "
                          "today, and this record keeps it there while corp.example's sp= moves to reject (seen "
                          "sending: 40 out in the tenant's mail flow); DNS shows no record at _dmarc.a.corp.example")
    assert not rows(p, "b.corp.example")  # quiet, inherits quarantine: nothing to shield
    # the apex's record carries a pct: the subdomain's record keeps it, where it is today
    p = plan_of(apex_report("v=DMARC1; p=reject; sp=quarantine; pct=50; rua=%s;" % RUA, ("a.corp.example",), flows))
    assert one(p, "a.corp.example", "new")["value"] == "v=DMARC1; p=quarantine; pct=50; rua=%s;" % RUA
    # an unaudited sender nobody looked up gets it with a lookup first; the lookup that showed none, outright
    rep = apex_report(rec, (), {"corp.example": flow(500), "a.corp.example": flow(40)},
                      rua=rua_doc(by_header_from=[{"domain": "x.corp.example", "count": 30, "pass": 30, "fail": 0}]))
    row = one(plan_of(rep), "x.corp.example", "new")
    assert row["value"] == "v=DMARC1; p=quarantine; rua=%s;" % RUA
    assert row["current"] == "not checked (not an audited domain)" and row["prerequisites"] == [
        plan_mod.lookup_first("x.corp.example")]
    assert row["why"].startswith("sending subdomain whose own record this run did not look up: it inherits p=quarantine "
                                 "from corp.example today, and this record keeps it there while corp.example's sp= "
                                 "moves to reject if it has none (seen sending: 30 passing in the aggregate reports)")
    rep["dns_extra"] = no_record("x.corp.example")
    assert one(plan_of(rep), "x.corp.example", "new")["current"] == "none"
    # an audited subdomain whose own plan proposes a row at its _dmarc name (here: the record it inherits lacks a
    # rua, DMARC-003) gets no second row from the apex: its own row wins
    rep = apex_report("v=DMARC1; p=reject; sp=quarantine;", ("a.corp.example",),
                      {"corp.example": flow(500), "a.corp.example": flow(40)})
    rep["dns"]["a.corp.example"]["findings"] = fid("DMARC-003")
    p = plan_of(rep)
    assert [c["domain"] for c in rows(p, host="_dmarc.a.corp.example")] == ["a.corp.example"]
    assert one(p, "a.corp.example")["kind"] == "modify"
    # none sends without a record: the step as it always was
    p = plan_of(apex_report(rec, ("b.corp.example",), {"corp.example": flow(500), "b.corp.example": flow()}))
    assert one(p, "corp.example", "ratchet")["prerequisites"][0] == ("a week of subdomain reports at sp=quarantine "
                                                                       "showing only spoofing")
    assert not holds_of(p, "corp.example")


def test_p2_a_reject_row_whose_subdomains_follow_p_asks_about_rarer_senders():
    """An apex at quarantine with no sp= and a known quiet subdomain (nothing sends without a record, so no
    sp=quarantine is added): the subdomains without a record of their own move to reject with it, so the row
    carries the sp= step's checks on what the evidence cannot reach - the rarer senders, and the span of the
    reports about the record."""
    rec = "v=DMARC1; p=quarantine; rua=%s;" % RUA
    flows = {"corp.example": flow(500), "a.corp.example": flow()}
    reject = one(plan_of(apex_report(rec, ("a.corp.example",), flows, sub_record=rec)), "corp.example", "ratchet")
    assert reject["value"] == "v=DMARC1; p=reject; rua=%s;" % RUA
    assert reject["why"].endswith("; the record has no sp=, so its subdomains without a record of their own move to "
                                  "reject with it")
    assert reject["prerequisites"][-1] == RARER_NONE
    # one day of reports about the record: the span, and a week of them
    rep = apex_report(rec, ("a.corp.example",), flows, rua=rua_doc(begin=BEGIN, end=BEGIN + DAY - 1), sub_record=rec)
    span = "%s .. %s" % (day(BEGIN), day(BEGIN + DAY - 1))
    reject = one(plan_of(rep), "corp.example", "ratchet")
    assert reject["prerequisites"][-2:] == [rarer_span("corp.example", span, "1 day"), week_of("corp.example", span)]
    # the quiet apex at quarantine 100 moving to reject: the same checks beside its own
    rep = apex_report(rec, ("a.corp.example",), {"corp.example": flow(), "a.corp.example": flow()},
                      rua=rua_doc(streams=[spoof_stream("corp.example")], begin=BEGIN, end=BEGIN + DAY - 1),
                      sub_record=rec)
    reject = one(plan_of(rep), "corp.example", "ratchet")
    assert reject["why"].startswith("quarantine at 100 percent is stable and no mail is measured as the domain")
    assert rarer_span("corp.example", span, "1 day") in reject["prerequisites"]
    assert week_of("corp.example", span) in reject["prerequisites"]
    # a subdomain that sends: sp=quarantine keeps them where they are, nothing follows p=, and no such check
    reject = one(plan_of(apex_report(rec, ("a.corp.example",), {"corp.example": flow(500), "a.corp.example": flow(40)},
                                     sub_record=rec)), "corp.example", "ratchet")
    assert reject["value"] == "v=DMARC1; p=reject; sp=quarantine; rua=%s;" % RUA
    assert not any("mails less often" in x for x in reject["prerequisites"])
    # sp=none: the sp= step carries them, not the reject row
    reject = next(c for c in rows(plan_of(apex_report(APEX, ("a.corp.example",), flows)), "corp.example", "ratchet")
                  if c["priority"] == 3)
    assert not any("mails less often" in x for x in reject["prerequisites"])


# ------------------------------------------------------------------ P3: sp=none on any quiet domain

def test_p3_a_quiet_subdomain_keeps_the_names_below_it_where_they_are():
    """A receiver that walks up the tree (dns_audit does) applies mail.corp.example's record to
    alerts.mail.corp.example: the quarantine-now record of an audited subdomain pins sp=none too, and the plan
    proposes the sending name's own record below it."""
    rep = apex_report(APEX, ("mail.corp.example",), {"corp.example": flow(500), "mail.corp.example": flow()},
                      rua=rua_doc(by_header_from=[{"domain": "alerts.mail.corp.example", "count": 30, "pass": 30,
                                                   "fail": 0}]))
    rep["dns_extra"] = no_record("alerts.mail.corp.example")
    p = plan_of(rep)
    quiet = one(p, "mail.corp.example", "no_mail")
    assert quiet["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    assert "sp=none keeps its subdomains where they are until the ones that send (alerts.mail.corp.example)" in \
        quiet["why"]
    sub = one(p, "alerts.mail.corp.example", "new")
    assert sub["value"] == "v=DMARC1; p=none; rua=%s;" % RUA and sub["current"] == "none"
    # a quiet subdomain with nothing below it pins all the same: a name that mails less often is unseen
    rep = apex_report(APEX, ("legacy.corp.example",), {"corp.example": flow(500), "legacy.corp.example": flow()},
                      rua=rua_doc())
    assert one(plan_of(rep), "legacy.corp.example", "no_mail")["value"] == \
        "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA


def test_p3_a_quiet_apex_whose_names_below_inherit_quarantine_keeps_the_senders_there():
    """corp.example at p=quarantine; pct=25 (no sp=) sends nothing; a.corp.example inherits that quarantine today
    and sends. The quarantine-now record pins sp=none, which would lower a. to none: a.'s own record at the policy
    it inherits today comes first (its row, and the quiet row's prerequisite), and the why never calls that drop
    'where they are'."""
    rec = "v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA
    rep = apex_report(rec, ("a.corp.example",), {"corp.example": flow(), "a.corp.example": flow(40)},
                      rua=rua_doc(streams=[spoof_stream("corp.example")],
                                  by_header_from=[{"domain": "a.corp.example", "count": 30, "pass": 30, "fail": 0}]))
    assert rep["dns"]["a.corp.example"]["effective_policy"] == "quarantine"
    p = plan_of(rep)
    quiet = one(p, "corp.example", "no_mail")
    assert quiet["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    assert quiet["why"].endswith("; sp=none takes the names below it out of this record's quarantine (they inherit "
                                 "p=quarantine at pct=25 today) until the sp= step moves them with its own checks; the "
                                 "ones that send (a.corp.example) keep that policy through records of their own, "
                                 "published first (above)")
    assert "where they are" not in quiet["why"]
    assert quiet["prerequisites"][-1] == ("every subdomain that sends has its own _dmarc record: a.corp.example has "
                                          "none yet (the records above keep each at p=quarantine, pct=25, where this "
                                          "record has it today, so sp=none here lowers nothing that sends)")
    assert plan_mod.prereq_kind(quiet["prerequisites"][-1]) == "other"
    own = one(p, "a.corp.example", "new")
    assert own["value"] == "v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA and own["priority"] == 1
    assert own["why"] == ("sending subdomain without a record of its own: it inherits p=quarantine, pct=25 from "
                          "corp.example today, and this record keeps it there while corp.example's record moves to "
                          "quarantine at 100 percent with sp=none (seen sending: 40 out in the tenant's mail flow; 30 "
                          "passing in the aggregate reports); DNS shows no record at _dmarc.a.corp.example")
    assert own["current"] == "none" and not holds_of(p, "corp.example")
    # nothing below it sends: sp=none still takes the names below out of the quarantine, said so, and no record
    rep = apex_report(rec, ("a.corp.example",), {"corp.example": flow(), "a.corp.example": flow()},
                      rua=rua_doc(streams=[spoof_stream("corp.example")]))
    p = plan_of(rep)
    quiet = one(p, "corp.example", "no_mail")
    assert quiet["why"].endswith("until the sp= step moves them with its own checks, and none of them was seen "
                                 "sending")
    assert not any("has its own _dmarc record" in x for x in quiet["prerequisites"]) and not rows(p, "a.corp.example")
    # the names below inherit none today (p=none, or no record): sp=none keeps them where they are, as before, and
    # the audited sender's own row proposes its monitoring record - once
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, ("a.corp.example",),
                      {"corp.example": flow(), "a.corp.example": flow(40)},
                      rua=rua_doc(streams=[spoof_stream("corp.example")]))
    p = plan_of(rep)
    assert "sp=none keeps its subdomains where they are until the ones that send (a.corp.example)" in \
        one(p, "corp.example", "no_mail")["why"]
    assert one(p, "a.corp.example", "new")["value"] == "v=DMARC1; p=none; rua=%s;" % RUA


# ------------------------------------------------------------------ P5: what counts as spoofing

def test_p5_a_spoof_label_on_the_envelope_alone_is_a_check_never_spoofing(tmp_path):
    """dedupe calls a failure likely_spoof when its envelope is neither the sender's domain nor a known platform,
    lure word or not - which is how a monthly statements vendor sending unaligned from its own envelope looks.
    Only a lure word makes the label strong: the rest is named as a check, with the sender."""
    docs = {"brand.example": own_record("brand.example")}
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [
        ("203.0.113.5", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    log = (Log().add("statements@brand.example", "Your October statement", dmarc="fail", times=3,
                     env="mailer.billing-vendor.invalid")
           .add("ceo@brand.example", "Urgent wire transfer #", dmarc="fail", times=2, env="evil.invalid"))
    rep = audited(tmp_path / "run", docs, log, reports, flows={"brand.example": flow(0, 5)})
    assert rep["maillog"]["by_domain"]["brand.example"]["by_likely"]["likely_spoof"] == 5  # dedupe's label, both
    row = one(plan_of(rep), "brand.example", "no_mail")
    assert ("none of the 5 message(s) that came in with it as the From domain passed, and the mail log examined every "
            "one: 5 logical message(s), 2 look like spoofing, which quarantine stops, and 3 it cannot call spoofing, "
            "named in the checks") in row["why"]
    assert row["prerequisites"] == [MONTHLY, WEAK % ("3", "statements@brand.example x3")]
    # lure words alone: the row reads as before, and the envelope clause is not added
    rep = audited(tmp_path / "lure", docs, Log().add("ceo@brand.example", "Urgent wire transfer #", dmarc="fail",
                                                     times=2, env="evil.invalid"), reports,
                  flows={"brand.example": flow(0, 2)})
    row = one(plan_of(rep), "brand.example", "no_mail")
    assert "2 look like spoofing, which quarantine stops" in row["why"] and row["prerequisites"] == [MONTHLY]
    assert plan_mod.lure("Your October statement") is False and plan_mod.lure("Urgent wire transfer") is True


WEAK = ("the %s message(s) that came in as brand.example and that the mail log cannot call spoofing (a failure "
        "labelled unknown, or no DMARC verdict at all, or one called spoofing on the envelope or a billing word alone "
        "- no lure word phishing leans on in the subject, and a vendor sending unaligned from its own envelope, or "
        "about its invoices and payroll, looks the same: %s) are spoofs rather than a sender of ours")


def test_p5_a_billing_word_in_the_subject_is_no_strong_sign(tmp_path):
    """dedupe's lure words include the daily vocabulary of billing and payroll vendors (invoice, payment, payroll,
    remittance ...): a payroll vendor sending unaligned as a quiet brand carries them in every subject. Only the
    words phishing leans on and no vendor's automated mail carries (urgent, password, voicemail, docusign, wire)
    make the label strong; a billing word counts like the envelope alone, and the sender is named in the check."""
    for word in ("urgent", "password", "voicemail", "docusign", "wire"):
        assert word in plan_mod.STRONG_LURES and word in plan_mod.dedupe.LURE_WORDS, word
    for subject in ("Invoice 10234 from Acme Billing", "Your payroll summary for October", "ACH payment remittance",
                    "Invoice overdue", "Direct deposit advice", "Past due notice"):
        assert plan_mod.lure(subject) is False, subject
    for subject in ("Reset your password", "New voicemail", "Please DocuSign the agreement", "Wire transfer request",
                    "Urgent: invoice overdue"):
        assert plan_mod.lure(subject) is True, subject
    docs = {"brand.example": own_record("brand.example")}
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [
        ("203.0.113.5", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    log = (Log().add("payroll@brand.example", "Your payroll summary for October #", dmarc="fail", times=3,
                     env="mailer.vendor-platform.invalid")
           .add("billing@brand.example", "Invoice 10234 from Acme Billing #", dmarc="fail", times=3,
                env="mailer.vendor-platform.invalid")
           .add("ceo@brand.example", "Urgent wire transfer #", dmarc="fail", times=2, env="evil.invalid"))
    rep = audited(tmp_path / "run", docs, log, reports, flows={"brand.example": flow(0, 8)})
    assert rep["maillog"]["by_domain"]["brand.example"]["by_likely"]["likely_spoof"] == 8  # dedupe's label, all
    row = one(plan_of(rep), "brand.example", "no_mail")
    assert ("8 logical message(s), 2 look like spoofing, which quarantine stops, and 6 it cannot call spoofing, named "
            "in the checks") in row["why"]
    assert row["prerequisites"] == [MONTHLY, WEAK % ("6", "billing@brand.example x3; payroll@brand.example x3")]
    assert plan_mod.doubtful_names(rep) == {
        "brand.example": ["6 failing in the mail log called spoofing on the envelope or a billing word alone"]}
    assert "look like spoofing, which quarantine stops" not in one(plan_of(audited(
        tmp_path / "payroll", docs, Log().add("payroll@brand.example", "Your payroll summary for October #",
                                              dmarc="fail", times=3, env="mailer.vendor-platform.invalid"),
        reports, flows={"brand.example": flow(0, 3)})), "brand.example", "no_mail")["why"]


def test_p5_failing_report_volume_without_a_spoofs_sign_is_a_check(tmp_path):
    """The reports count 15 failing as brand.example from a source signing with the vendor's own domain and passing
    SPF for its envelope: under the stream floor, so unlabelled, and exactly what a vendor produces. The row
    names it as a check and says so in its why. A source with no authentication at all, and a stream labelled
    likely_spoof, are spoofing on a strong sign: no check."""
    docs = {"brand.example": own_record("brand.example")}
    vendor = ("198.51.100.60", 15, "brand.example", "billing-vendor.invalid", "pass", "mailer.billing-vendor.invalid",
              "pass")
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [vendor])]
    rep = audited(tmp_path / "vendor", docs, None, reports, flows={"brand.example": flow()})
    assert plan_mod.report_doubt(rep, "brand.example") == 15
    row = one(plan_of(rep), "brand.example", "no_mail")
    assert row["prerequisites"] == [
        MONTHLY,
        "the 15 message(s) as brand.example that failed in the aggregate reports outside a stream labelled "
        "likely_spoof (a source under 20 messages carries no label, and a vendor signing with its own domain, or "
        "passing SPF for its own envelope, fails there the same way) are spoofs rather than a sender of ours"]
    assert ("the aggregate reports count none passing as it; 15 failing as it there that they cannot call spoofing, "
            "named in the checks, so a weekly ramp would protect nobody") in row["why"]
    # no signature and no SPF pass, under the floor; and a labelled spoof stream: strong signs, no check
    reports = [rua_report(tmp_path / "spoof.xml", "brand.example", "none", [
        ("203.0.113.9", 5, "brand.example", None, None, "evil.invalid", "fail"),
        ("203.0.113.66", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    rep = audited(tmp_path / "spoof", docs, None, reports, flows={"brand.example": flow()})
    assert plan_mod.report_doubt(rep, "brand.example") == 0
    assert one(plan_of(rep), "brand.example", "no_mail")["prerequisites"] == [MONTHLY]
    # an older report without the per-source table: the labelled streams alone decide
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow()},
                      rua=rua_doc(by_header_from=[{"domain": "corp.example", "count": 50, "pass": 0, "fail": 50}],
                                  streams=[spoof_stream("corp.example", 30)]))
    assert plan_mod.report_doubt(rep, "corp.example") == 20


def test_p5_the_sp_step_names_the_subdomains_it_cannot_call_spoofed(tmp_path):
    """billing.corp.example fails 15 times in the reports through a vendor's own signature and 3 times in the mail
    log from the vendor's envelope: not a sender by the sending rule (every failure reads as spoofing), so the sp=
    step would read ready and sp=quarantine would junk the vendor's mail. The row names it, and the step is
    held, until a person says whether it sends for us."""
    docs = {"corp.example": own_record("corp.example", APEX), "b.corp.example": own_record("b.corp.example")}
    log = (Log().add("staff@corp.example", "Weekly #", times=5, direction="Outbound")
           .add("statements@billing.corp.example", "Your October statement", dmarc="fail", times=3,
                env="mailer.billing-vendor.invalid"))
    reports = [rua_report(tmp_path / "corp.xml", "corp.example", "quarantine", [
        ("192.0.2.10", 900, "corp.example", "corp.example", "pass", "corp.example", "pass"),
        ("198.51.100.60", 15, "billing.corp.example", "billing-vendor.invalid", "pass",
         "mailer.billing-vendor.invalid", "pass")])]
    rep = audited(tmp_path / "run", docs, log, reports, flows={"corp.example": flow(500), "b.corp.example": flow()})
    assert plan_mod.doubtful_names(rep) == {"billing.corp.example": [
        "3 failing in the mail log called spoofing on the envelope or a billing word alone",
        "15 failing in the aggregate reports with no spoof sign"]}
    p = plan_of(rep)
    sp = next(c for c in rows(p, "corp.example", "ratchet") if c["priority"] == 4)
    named = ("billing.corp.example (3 failing in the mail log called spoofing on the envelope or a billing word alone; "
             "15 failing in the aggregate reports with no spoof sign)")
    assert sp["prerequisites"][:2] == [
        "every subdomain that sends has its own _dmarc record (this run saw none sending without one)",
        "the subdomains whose failing mail this run cannot call spoofing send nothing of ours: %s - a vendor sending as "
        "one of them unaligned fails the same way, and sp=quarantine junks its mail, so give such a name a record of "
        "its own first" % named]
    assert holds_of(p, "corp.example") == [
        "subdomains whose failing mail this run cannot call spoofing: %s - a vendor sending as one of them unaligned "
        "fails the same way, and sp=quarantine junks its mail; decide whether each sends for you, and give it a record "
        "of its own first, before sp= moves" % named]
    assert not rows(p, "billing.corp.example")  # not a sender: no monitoring record of its own is proposed yet
    # with a record of its own (DNS says so) it is covered: nothing to name
    rep["dns_extra"] = {"billing.corp.example": {"dmarc": "v=DMARC1; p=none; rua=%s;" % RUA, "status": "found",
                                                 "source": "_dmarc.billing.corp.example"}}
    p = plan_of(rep)
    assert not holds_of(p, "corp.example")
    assert not any("send nothing of ours" in x for x in next(c for c in rows(p, "corp.example", "ratchet")
                                                                   if c["priority"] == 4)["prerequisites"])


def test_p5_the_ramp_names_the_apex_mail_it_cannot_call_spoofing(tmp_path):
    """A sending apex on the ordinary ramp with a statements vendor failing as it: 3 mail-log failures called
    spoofing on the envelope alone, 15 report failures from a source under the stream floor. The quiet row
    would name them; so does each ramp step, as a check beside the DKIM proof, and verify.md says how to settle
    it. A labelled stream the gate already holds the step for is not named twice."""
    docs = {"corp.example": own_record("corp.example")}
    vendor = ("198.51.100.60", 15, "corp.example", "billing-vendor.invalid", "pass", "mailer.billing-vendor.invalid",
              "pass")
    own = ("192.0.2.10", 900, "corp.example", "corp.example", "pass", "corp.example", "pass")
    reports = [rua_report(tmp_path / "corp.xml", "corp.example", "none", [own, vendor])]
    log = (Log().add("staff@corp.example", "Weekly #", times=20, direction="Outbound")
           .add("statements@corp.example", "Your October statement #", dmarc="fail", times=3,
                env="mailer.billing-vendor.invalid"))
    rep = audited(tmp_path / "run", docs, log, reports, flows={"corp.example": flow(500, 3)})
    assert plan_mod.doubts_for(rep, "corp.example", held=True) == [
        "3 failing in the mail log called spoofing on the envelope or a billing word alone",
        "15 failing in the aggregate reports with no spoof sign"]
    check = ("the mail as corp.example this run cannot call spoofing sends nothing of ours: 3 failing in the mail log "
             "called spoofing on the envelope or a billing word alone; 15 failing in the aggregate reports with no "
             "spoof sign - a vendor sending as it unaligned fails the same way, and %s its mail")
    p = plan_of(rep)
    ramp = one(p, "corp.example", "ratchet")
    assert ramp["value"] == "v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA
    assert ramp["prerequisites"] == ["every legitimate sender proven with an aligned DKIM header",
                                     check % "p=quarantine at pct=25 junks a quarter of"]
    assert not holds_of(p, "corp.example")
    texts = [s["text"] for s in verify.change_steps(ramp, rep)]
    assert any("not a vendor sending as corp.example unaligned" in t for t in texts)
    assert any(t.startswith("Re-read the aggregate reports: in the by_source_ip table every source that fails as "
                            "corp.example") for t in texts)
    # the next steps: pct=50, then reject
    for rec, effect in (("v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA, "p=quarantine at pct=50 junks half of"),
                        ("v=DMARC1; p=quarantine; rua=%s;" % RUA, "p=reject refuses")):
        later = dict(rep, dns={"corp.example": own_record("corp.example", rec)})
        assert check % effect in one(plan_of(later), "corp.example", "ratchet")["prerequisites"], rec
    # the vendor above the stream floor is a labelled stream (likely_misconfigured): the gate's hold names it, and
    # the check names the mail-log part alone
    reports = [rua_report(tmp_path / "corp50.xml", "corp.example", "none", [own, vendor[:1] + (50,) + vendor[2:]])]
    rep = audited(tmp_path / "held", docs, log, reports, flows={"corp.example": flow(500, 3)})
    assert rep["rua"]["failing_streams"][0]["likely"] == "likely_misconfigured"
    assert plan_mod.doubts_for(rep, "corp.example") == [
        "3 failing in the mail log called spoofing on the envelope or a billing word alone",
        "50 failing in the aggregate reports with no spoof sign"]
    ramp = one(plan_of(rep), "corp.example", "ratchet")
    assert ("the mail as corp.example this run cannot call spoofing sends nothing of ours: 3 failing in the mail log "
            "called spoofing on the envelope or a billing word alone - a vendor sending as it unaligned fails the same "
            "way, and p=quarantine at pct=25 junks a quarter of its mail") in ramp["prerequisites"]
    assert any(x.startswith("aggregate reports: 198.51.100.60 sends 50 message(s) as corp.example and fails "
                            "(likely_misconfigured") for x in ramp["prerequisites"])
    # nothing doubtful: the ramp as it always was
    rep = audited(tmp_path / "clean", docs, Log().add("staff@corp.example", "Weekly #", times=20, direction="Outbound"),
                  [rua_report(tmp_path / "clean.xml", "corp.example", "none", [own])], flows={"corp.example": flow(500)})
    assert one(plan_of(rep), "corp.example", "ratchet")["prerequisites"] == [
        "every legitimate sender proven with an aligned DKIM header"]


# ------------------------------------------------------------------ P6: a step on a domain no evidence covers

def test_p6_a_step_on_a_domain_no_evidence_covers_says_so(tmp_path):
    """The gate rules example.com insufficient_data when the run's evidence has no rows for it; its ramp row
    carries the same condition, so the status document never calls the step ready on other domains' rows."""
    docs = {"corp.example": own_record("corp.example"), "example.com": own_record("example.com", **GOOGLE)}
    log = Log().add("staff@corp.example", "Weekly #", times=5, direction="Outbound")
    reports = [rua_report(tmp_path / "corp.xml", "corp.example", "none", [
        ("192.0.2.10", 90, "corp.example", "corp.example", "pass", "corp.example", "pass")])]
    rep = audited(tmp_path / "run", docs, log, reports, flows={"corp.example": flow(500), "example.com": flow(5)},
                  sources={"corp.example": ["tenant"], "example.com": ["env"]})
    assert rep["gate"]["domains"]["example.com"]["verdict"] == "insufficient_data"
    p = plan_of(rep)
    note = ("a mail log or aggregate reports that cover example.com are supplied: the evidence this run read has no "
            "rows for it (no mail-log rows of its own, none in the aggregate reports with it as the From domain), so a "
            "sender of ours failing as it could not show")
    step = one(p, "example.com", "ratchet")
    assert step["prerequisites"] == ["every legitimate sender proven with an aligned DKIM header", note]
    assert plan_mod.prereq_kind(note) == "evidence"
    assert not any("no rows for it" in x for x in one(p, "corp.example", "ratchet")["prerequisites"])
    doc = next_steps.build(rep, p)
    assert "the evidence this run read has no rows for it" in next_steps.render_md(doc)
    # rows for it in the reports: nothing to ask
    reports.append(rua_report(tmp_path / "example.xml", "example.com", "none", [
        ("203.0.113.5", 12, "example.com", None, None, "evil.invalid", "fail")]))
    rep = audited(tmp_path / "covered", docs, log, reports, flows={"corp.example": flow(500), "example.com": flow(5)})
    assert not any("no rows for it" in x for x in one(plan_of(rep), "example.com", "ratchet")["prerequisites"])
    # no evidence at all: the run-wide note, once, as before
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow(5)})
    pre = one(plan_of(rep), "corp.example", "ratchet")["prerequisites"]
    assert pre == ["every legitimate sender proven with an aligned DKIM header",
                   "no failure evidence in this run - supply --maillog and/or --rua before applying any enforcement step"]


# ------------------------------------------------------------------ P7: a derived report address is named

def test_p7_a_derived_report_address_is_said_in_plan_md():
    rep = apex_report("v=DMARC1; p=none; rua=mailto:dmarc@saas.invalid;", (), {"corp.example": flow(5)})
    rep["dns"]["brand.example"] = own_record("brand.example", "v=DMARC1; p=none; rua=mailto:dmarc@saas.invalid;")
    rep["dns"]["other.example"] = dns_doc("other.example", findings=fid("DMARC-001"))
    rep["inputs"]["domains"] += ["brand.example", "other.example"]
    p = plan_of(rep, rua=None)
    assert p["rua"] == "mailto:dmarc@saas.invalid" and p["rua_derived"] is True and p["report_address"] is None
    assert one(p, "other.example", "new")["value"] == "v=DMARC1; p=none; rua=mailto:dmarc@saas.invalid;"
    md = plan_mod.render_md(p)
    assert ("**Check the reporting address.** The run had no report address of its own, so new records use "
            "`mailto:dmarc@saas.invalid`, the rua most existing records already use - which may be a reporting "
            "service's mailbox the toolkit never reads.") in md
    # with the run's own address: nothing derived, nothing said
    p = plan_of(rep, rua=RUA)
    assert p["rua_derived"] is False and "Check the reporting address" not in plan_mod.render_md(p)
    # no record carries a rua: the placeholder, and that note alone
    rep = apex_report("v=DMARC1; p=none;", (), {"corp.example": flow(5)})
    p = plan_of(rep, rua=None)
    assert p["rua_is_placeholder"] and p["rua_derived"] is False
    assert "Set the reporting address" in plan_mod.render_md(p) and "Check the reporting address" not in \
        plan_mod.render_md(p)


# ------------------------------------------------------------------ P8: rarer senders and the reports' span

RARER = ("no subdomain without a record of its own mails less often than this run's evidence reaches back (a "
         "quarterly newsletter, a yearly renewal): %s, and such a sender shows nowhere in it")
RARER_NONE = RARER % ("the mail flow and the mail log reach back 30 days at most, and no dated aggregate report about "
                      "corp.example's record in this run says what lies beyond")


def rarer_span(domain, text, days):
    return RARER % ("the aggregate reports this run read about %s's record span %s (%s), the mail flow and the mail "
                    "log 30 days at most" % (domain, text, days))


def week_of(domain, text, days="1 day"):
    return "a week of aggregate reports about %s's record at least: the ones this run read span only %s (%s)" % (
        domain, days, text)


def test_p8_the_sp_step_names_rarer_senders_and_the_span_of_the_reports():
    flows = {"corp.example": flow(500), "a.corp.example": flow()}
    # one day of reports: the span is named, and a week of them is asked for
    rep = apex_report(APEX, ("a.corp.example",), flows, rua=rua_doc(begin=BEGIN, end=BEGIN + DAY - 1))
    span = "%s .. %s" % (day(BEGIN), day(BEGIN + DAY - 1))
    assert plan_mod.report_span(rep, "corp.example") == (1, span) and plan_mod.report_span(rep) == (1, span)
    sp = next(c for c in rows(plan_of(rep), "corp.example", "ratchet") if c["priority"] == 4)
    assert sp["prerequisites"][1:3] == [rarer_span("corp.example", span, "1 day"), week_of("corp.example", span)]
    for x in sp["prerequisites"][1:3]:
        assert plan_mod.prereq_kind(x) == "evidence"  # what would prove it: evidence over a longer span
    # ten days of reports (the ten before the run): the span is named, and nothing more is asked
    rep = apex_report(APEX, ("a.corp.example",), flows, rua=rua_doc(begin=BEGIN - 9 * DAY, end=BEGIN + DAY - 1))
    sp = next(c for c in rows(plan_of(rep), "corp.example", "ratchet") if c["priority"] == 4)
    assert sp["prerequisites"][1] == rarer_span("corp.example", "%s .. %s" % (day(BEGIN - 9 * DAY), day(BEGIN + DAY - 1)),
                                                "10 days")
    assert not any(x.startswith("a week of aggregate reports") for x in sp["prerequisites"])
    # no reports: the mail flow and the log reach back 30 days at most, and nothing says what lies beyond
    sp = next(c for c in rows(plan_of(apex_report(APEX, ("a.corp.example",), flows)), "corp.example", "ratchet")
              if c["priority"] == 4)
    assert sp["prerequisites"][1] == RARER_NONE
    assert plan_mod.report_span({"rua": {"totals": {"begin": "x", "end": 5}}}) == (None, None)


def test_p8_the_span_is_the_reports_about_the_record_not_the_whole_mailbox(tmp_path):
    """One report mailbox serves many brands: 31 days of reports about corp.example's record say nothing about
    brand.example, whose own record has one day of them. The span each row names is its record's; a report with
    a 1970 date, or one ending after the run, says nothing; an older report.json without the per-report list
    gives the totals' span for every record."""
    hosted = {k: v for k, v in GOOGLE.items() if k != "mx"}  # a subdomain on the same platform, no MX of its own
    docs = {"corp.example": own_record("corp.example", APEX), "a.corp.example": inherits("a.corp.example"),
            "brand.example": own_record("brand.example", "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA, **GOOGLE),
            "a.brand.example": inherits("a.brand.example", "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA,
                                        source="_dmarc.brand.example", **hosted)}
    corp = rua_report(tmp_path / "corp.xml", "corp.example", "quarantine", [
        ("192.0.2.10", 900, "corp.example", "corp.example", "pass", "corp.example", "pass")],
        begin=BEGIN - 30 * DAY, end=BEGIN + DAY - 1)
    brand = rua_report(tmp_path / "brand.xml", "brand.example", "quarantine", [
        ("203.0.113.9", 40, "brand.example", None, None, "evil.invalid", "fail")], begin=BEGIN, end=BEGIN + DAY - 1)
    flows = {d: flow() for d in docs}
    flows["corp.example"] = flow(500)
    sources = {d: ["env"] if "brand" in d else ["tenant"] for d in docs}
    rep = audited(tmp_path / "run", docs, None, [corp, brand], flows=flows, sources=sources)
    long, short = "%s .. %s" % (day(BEGIN - 30 * DAY), day(BEGIN + DAY - 1)), "%s .. %s" % (day(BEGIN), day(BEGIN + DAY - 1))
    assert plan_mod.report_span(rep) == (31, long)
    assert plan_mod.report_span(rep, "corp.example") == (31, long)
    assert plan_mod.report_span(rep, "brand.example") == (1, short)
    assert plan_mod.report_span(rep, "a.brand.example") == (None, None)  # no report is about a record there
    p = plan_of(rep)
    sp = {d: next(c for c in rows(p, d, "ratchet") if c["priority"] == 4) for d in ("corp.example", "brand.example")}
    assert sp["corp.example"]["prerequisites"][1] == rarer_span("corp.example", long, "31 days")
    assert not any(x.startswith("a week of") for x in sp["corp.example"]["prerequisites"])
    assert sp["brand.example"]["prerequisites"][1:3] == [rarer_span("brand.example", short, "1 day"),
                                                         week_of("brand.example", short)]
    # the quiet brand off the tenant: its own record's one day, named on the row (the apex's 31 days are not its);
    # a quiet subdomain inheriting that record rests on the same reports, and names the record they are about
    docs["brand.example"] = own_record("brand.example", **GOOGLE)
    docs["a.brand.example"] = inherits("a.brand.example", "v=DMARC1; p=none; rua=%s;" % RUA,
                                       source="_dmarc.brand.example", **hosted)
    brand = rua_report(tmp_path / "brand1.xml", "brand.example", "none", [
        ("203.0.113.9", 40, "brand.example", None, None, "evil.invalid", "fail")], begin=BEGIN, end=BEGIN + DAY - 1)
    rep = audited(tmp_path / "quiet", docs, None, [corp, brand], flows={"corp.example": flow(500), "a.corp.example": flow(),
                                                                       "brand.example": flow(), "a.brand.example": flow()},
                  sources=sources)
    p = plan_of(rep)
    span_check = ("aggregate reports that cover %s over 30 days show nothing passing as it: the ones this run read "
                  "about brand.example's record span only 1 day (%s), and a sender that mails less often than that "
                  "shows nowhere in them")
    assert one(p, "brand.example", "no_mail")["prerequisites"] == [MONTHLY, span_check % ("brand.example", short)]
    sub = one(p, "a.brand.example", "no_mail")  # its rua is in another organization: that prerequisite follows
    assert sub["prerequisites"][:2] == [MONTHLY, span_check % ("a.brand.example", short)] and len(sub["prerequisites"]) == 3
    # a report with a 1970 date beside a normal one: the normal one's span, and the week is still asked for
    bogus = rua_report(tmp_path / "bogus.xml", "corp.example", "quarantine", [
        ("192.0.2.11", 1, "corp.example", "corp.example", "pass", "corp.example", "pass")], begin=0, end=86399)
    short_corp = rua_report(tmp_path / "corp1.xml", "corp.example", "quarantine", [
        ("192.0.2.10", 9, "corp.example", "corp.example", "pass", "corp.example", "pass")], begin=BEGIN,
        end=BEGIN + DAY - 1)
    future = rua_report(tmp_path / "future.xml", "corp.example", "quarantine", [
        ("192.0.2.12", 1, "corp.example", "corp.example", "pass", "corp.example", "pass")], begin=BEGIN,
        end=BEGIN + 40 * DAY)  # ends a month after the run (generated 2026-10-09)
    rep = audited(tmp_path / "dates", {"corp.example": docs["corp.example"], "a.corp.example": docs["a.corp.example"]},
                  None, [short_corp, bogus, future], flows={"corp.example": flow(500), "a.corp.example": flow()})
    assert rep["rua"]["totals"]["begin_date"] == "1970-01-01"  # what the whole set would say
    assert plan_mod.report_span(rep, "corp.example") == (1, short)
    sp = next(c for c in rows(plan_of(rep), "corp.example", "ratchet") if c["priority"] == 4)
    assert sp["prerequisites"][1:3] == [rarer_span("corp.example", short, "1 day"), week_of("corp.example", short)]
    # reports about the record with no usable dates at all: no span, and the row says the reach is unknown
    rep = audited(tmp_path / "undated", {"corp.example": docs["corp.example"], "a.corp.example": docs["a.corp.example"]},
                  None, [bogus], flows={"corp.example": flow(500), "a.corp.example": flow()})
    assert plan_mod.report_span(rep, "corp.example") == (None, None)
    sp = next(c for c in rows(plan_of(rep), "corp.example", "ratchet") if c["priority"] == 4)
    assert sp["prerequisites"][1] == RARER_NONE
    # an older report.json without the per-report list: the totals' span stands for every record
    older = {"generated_utc": "2026-10-09T06:00:00Z", "rua": {"totals": {"begin": BEGIN - 3 * DAY, "end": BEGIN - 1}}}
    assert plan_mod.report_span(older, "brand.example") == (3, "%s .. %s" % (day(BEGIN - 3 * DAY), day(BEGIN - 1)))
    # and a totals' span that ends after the run says nothing either
    assert plan_mod.report_span(dict(older, rua={"totals": {"begin": BEGIN, "end": BEGIN + 3 * DAY}}), "x") == (None, None)


def test_p8_a_quiet_domain_off_the_tenant_names_the_span_its_reports_cover():
    """A domain the tenant does not carry rests on the reports alone: two days of them say nothing about a sender
    that mails every few weeks, so the row names the span and asks about senders rarer than it; reports about
    its record with no usable dates leave the reach unknown, and the row says so."""
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow()},
                      rua=rua_doc(streams=[spoof_stream("corp.example", 30)], begin=BEGIN, end=BEGIN + 2 * DAY - 1))
    rep["dns"]["corp.example"].update(GOOGLE)
    rep["inputs"]["domain_sources"] = {"corp.example": ["env"]}
    row = one(plan_of(rep), "corp.example", "no_mail")
    assert row["prerequisites"] == [
        MONTHLY,
        "aggregate reports that cover corp.example over 30 days show nothing passing as it: the ones this run read "
        "about corp.example's record span only 2 days (%s .. %s), and a sender that mails less often than that shows "
        "nowhere in them" % (day(BEGIN), day(BEGIN + 2 * DAY - 1))]
    rep["rua"] = rua_doc(streams=[spoof_stream("corp.example", 30)])  # about its record, undated
    assert one(plan_of(rep), "corp.example", "no_mail")["prerequisites"] == [
        MONTHLY,
        "aggregate reports that cover corp.example over 30 days show nothing passing as it: the ones this run read "
        "about corp.example's record carry no usable dates, so how far back they reach is unknown"]
    # a tenant domain: the mail flow's 30 days are the evidence, and the reports' span is not the question
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow()},
                      rua=rua_doc(streams=[spoof_stream("corp.example", 30)], begin=BEGIN, end=BEGIN + 2 * DAY - 1))
    assert one(plan_of(rep), "corp.example", "no_mail")["prerequisites"] == [MONTHLY]


# ------------------------------------------------------------------ P9: a mail log from another period

def test_p9_a_mail_log_from_another_period_examined_none_of_the_mail_that_came_in(tmp_path):
    """--maillog can be an older export, or last week's maillog.csv: its rows may add up to the mail flow's inbound
    count without one of them being a message the flow counted. The log must reach the newest message the flow
    saw (last_seen); otherwise the ramp stays, and the row never claims the log examined every one."""
    docs = {"brand.example": own_record("brand.example")}
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [
        ("203.0.113.5", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    newest = "2026-10-08T10:00:00Z"

    def kinds(when, last_seen=newest):
        log = Log().add("ceo@brand.example", "Reset your password #", dmarc="fail", times=3, env="evil.invalid",
                        when=when)
        rep = audited(tmp_path / when[:13].replace(":", ""), docs, log, reports,
                      flows={"brand.example": flow(0, 3, last_seen)})
        assert rep["maillog"]["window"]["to"].startswith(when[:13])
        return [c["kind"] for c in plan_of(rep)["changes"]]

    assert kinds("2026-08-01T00:00:00Z") == ["ratchet"]  # an export from August: 69 days before the newest message
    assert kinds("2026-10-01T09:00:00Z") == ["ratchet"]  # last week's log: the newest message came in after it
    assert kinds("2026-10-08T09:00:00Z") == ["no_mail"]  # the log reaches it
    assert kinds("2026-10-08T05:00:00Z") == ["no_mail"]  # within the slack ingestion lag allows (6 hours)
    assert kinds("2026-10-07T20:00:00Z") == ["ratchet"]  # beyond it
    assert kinds("2026-08-01T00:00:00Z", None) == ["no_mail"]  # nothing to compare: the count test alone, as before
    assert plan_mod.log_reaches({"maillog": {"window": {"to": "2026-10-08T09:00:00Z"}}}, "2026-10-08T10:00:00.1234567Z")
    assert plan_mod.log_reaches({"maillog": {"window": {"to": "not a date"}}}, newest)  # unreadable: no comparison


# ------------------------------------------------------------------ P10: what measures the mail flow

def test_p10_the_park_check_names_what_measures_the_mail_flow():
    """discover.py --mailflow counts only the subdomains its answer holds, never an unused name: the check names
    the run that does measure it."""
    note = plan_mod.unused_note(None, None, 30, True)
    assert note == ("verify unused first: no outbound mail in 30 days (this run did not measure it: a collect.py run "
                    "with the app registration does), no owner objects")
    assert "discover.py --mailflow" not in note
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, ("old.corp.example",))
    rep["dns"]["old.corp.example"].update(spf=None, spf_status="absent", spf_terminator=None, dkim_selectors=[],
                                          dkim_status="absent", findings=fid("DMARC-002", "SPF-001"))
    park = one(plan_of(rep), "old.corp.example", "park", "_dmarc.old.corp.example")
    assert park["prerequisites"][0].startswith("verify unused first: no outbound mail in 30 days (this run did not "
                                               "measure it: a collect.py run with the app registration does)")


# ------------------------------------------------------------------ P12: the full window's span and grain

def cut_report(tmp_path, log, inbound, totals, hours=720):
    tmp_path.mkdir(parents=True, exist_ok=True)
    docs = {"brand.example": own_record("brand.example")}
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [
        ("203.0.113.5", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    cut = {"brand.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T22:00:00Z"}}
    wt = {"hours": hours, "orgs": {"brand.example": {"source": collect.AGGREGATE_SOURCE,
                                                     "by_domain": {"brand.example": totals}}}}
    return audited(tmp_path, docs, log, reports, flows={"brand.example": flow(0, inbound)}, maillog_cuts=cut,
                   window_totals=wt)


def test_p12_full_window_totals_cover_only_the_mail_flows_whole_span(tmp_path):
    """collect --days 7 counts the totals over 168 hours while the mail flow counts 30 days: 23 days of mail the
    flow counted lie outside the totals, so they cover nothing."""
    log = Log().add("ceo@brand.example", "Reset your password #", dmarc="fail", times=2, env="evil.invalid")
    totals = {"logical_messages": 20, "passing": 0, "genuine_failures": 20, "delivered_despite_fail": 0}
    assert [c["kind"] for c in plan_of(cut_report(tmp_path / "week", log, 20, totals, hours=168))["changes"]] == \
        ["ratchet"]
    assert [c["kind"] for c in plan_of(cut_report(tmp_path / "month", log, 20, totals, hours=720))["changes"]] == \
        ["no_mail"]
    rep = cut_report(tmp_path / "none", log, 20, totals)
    del rep["maillog"]["window_totals"]["hours"]  # a count whose span nothing records covers nothing
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]
    assert plan_mod._totals_span(rep, 30) is False and plan_mod._totals_span(cut_report(tmp_path / "ok", log, 20,
                                                                                            totals), 30) is True


def test_p12_the_totals_are_read_at_the_mail_flows_grain(tmp_path):
    """The totals count (Message-ID, recipient) pairs, the mail flow distinct messages. The rows kept show 2
    messages to 5 recipients each (10 pairs): 20 pairs over the full window are about 4 messages, which never
    stand for the 20 that came in. A totals answer that carries a message count is read as such."""
    fan = Log().add("ceo@brand.example", "Reset your password #", dmarc="fail", times=2, env="evil.invalid",
                    recipients=5)
    pairs = {"logical_messages": 20, "passing": 0, "genuine_failures": 20, "delivered_despite_fail": 0}
    rep = cut_report(tmp_path / "pairs", fan, 20, pairs)
    own = rep["maillog"]["by_domain"]["brand.example"]
    assert (own["logical_messages"], own["message_ids"]) == (10, 2)
    assert plan_mod._full_messages(pairs, 10, 2) == 4
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]
    # the same 20 pairs with no fan-out in the rows kept cover 20 messages, as before
    flat = Log().add("ceo@brand.example", "Reset your password #", dmarc="fail", times=2, env="evil.invalid")
    row = one(plan_of(cut_report(tmp_path / "flat", flat, 20, pairs)), "brand.example", "no_mail")
    assert "none of the about 20 message(s) that came in with it as the From domain passed over the full window" in \
        row["why"]
    assert "the about 18 message(s) that came in as brand.example outside the mail-log rows kept" in \
        row["prerequisites"][-1]
    # a totals answer that counts messages: its count, whatever the rows kept show
    msgs = dict(pairs, messages=20)
    assert plan_mod._full_messages(msgs, 10, 2) == 20
    row = one(plan_of(cut_report(tmp_path / "msgs", fan, 20, msgs)), "brand.example", "no_mail")
    assert "the about 18 message(s) that came in as brand.example outside the mail-log rows kept" in \
        row["prerequisites"][-1]


# ------------------------------------------------------------------ P13: tags written with spaces

def test_p13_a_tag_written_with_spaces_around_the_equals_sign_is_still_that_tag():
    rec = "v=DMARC1; p = none; rua = mailto:a@corp.example;"
    assert plan_mod.tag_key("p = none") == "p" and plan_mod.tag_key("DMARC1") == ""
    assert plan_mod.set_tag(rec, "p", "quarantine") == "v=DMARC1; p=quarantine; rua = mailto:a@corp.example;"
    assert plan_mod.set_tag(rec, "sp", "none") == "v=DMARC1; p = none; sp=none; rua = mailto:a@corp.example;"
    assert plan_mod.drop_tag("v=DMARC1; p=quarantine; pct = 25; rua=mailto:a@corp.example;", "pct") == \
        "v=DMARC1; p=quarantine; rua=mailto:a@corp.example;"
    assert plan_mod.set_tag("v=DMARC1; p=quarantine; sp = none; rua=mailto:a@corp.example;", "sp", "quarantine") == \
        "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:a@corp.example;"
    assert plan_mod.with_rua(rec, "mailto:b@corp.example") == "v=DMARC1; p = none; rua=mailto:b@corp.example;"
    assert plan_mod.set_tag("v = DMARC1; p=none;", "sp", "none") == "v = DMARC1; p=none; sp=none;"
    # through the plan: one p tag, and a quarantine-now row that changes the record
    rep = apex_report("v=DMARC1; p = none; rua = %s;" % RUA, (), {"corp.example": flow()},
                      rua=rua_doc(streams=[spoof_stream("corp.example")]))
    assert one(plan_of(rep), "corp.example", "no_mail")["value"] == "v=DMARC1; p=quarantine; sp=none; rua = %s;" % RUA
    rep = apex_report("v=DMARC1; p=quarantine; pct = 25; rua=%s;" % RUA, (), {"corp.example": flow()},
                      rua=rua_doc(streams=[spoof_stream("corp.example")]))
    row = one(plan_of(rep), "corp.example", "no_mail")
    assert row["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA and row["value"] != row["current"]


# ------------------------------------------------------------------ P14: a failed MX lookup

def test_p14_a_failed_mx_lookup_never_parks_a_domain():
    def brand(mx_status, flows):
        rep = apex_report(APEX, (), flows)
        rep["dns"]["brand-b.invalid"] = dns_doc("brand-b.invalid", spf=None, spf_status="absent", spf_terminator=None,
                                                dkim_selectors=[], dkim_status="absent", mx=[], mx_status=mx_status,
                                                findings=fid("DMARC-001", "SPF-001"))
        rep["inputs"]["domains"].append("brand-b.invalid")
        return plan_of(rep)
    quiet = {"corp.example": flow(500), "brand-b.invalid": flow()}
    p = brand("error", quiet)
    assert not rows(p, "brand-b.invalid", "park")
    assert holds_of(p, "brand-b.invalid") == [
        "the MX lookup for brand-b.invalid failed in this run, so whether it receives mail is unknown: not parked on "
        "that (p=reject and v=spf1 -all wait for a lookup that answers) - re-run before parking it"]
    assert one(p, "brand-b.invalid", "no_mail")["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    # not measured either: the monitoring record, and the same hold
    p = brand("error", {"corp.example": flow(500)})
    assert [c["kind"] for c in rows(p, "brand-b.invalid")] == ["new"] and len(holds_of(p, "brand-b.invalid")) == 1
    # the lookup answered that there is no MX: parked, as before
    p = brand("absent", quiet)
    assert sorted(c["value"] for c in rows(p, "brand-b.invalid", "park")) == ["v=DMARC1; p=reject; rua=%s;" % RUA,
                                                                              "v=spf1 -all"]
    assert not holds_of(p, "brand-b.invalid")


# ------------------------------------------------------------------ P15: a first record keeps its reporting

def test_p15_a_first_record_keeps_the_reporting_it_inherits():
    parent = ("v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:a@vendor.invalid,mailto:b@corp.example; "
              "ruf=mailto:f@corp.example; fo=1; adkim=s;")
    assert plan_mod.new_record("none", RUA) == "v=DMARC1; p=none; rua=%s;" % RUA
    assert plan_mod.new_record("none", RUA, parent) == (
        "v=DMARC1; p=none; rua=mailto:a@vendor.invalid,mailto:b@corp.example; ruf=mailto:f@corp.example; fo=1; adkim=s;")
    assert plan_mod.new_record("none", RUA, parent, RUA) == (
        "v=DMARC1; p=none; rua=mailto:a@vendor.invalid,mailto:b@corp.example,%s; ruf=mailto:f@corp.example; fo=1; "
        "adkim=s;" % RUA)
    assert plan_mod.new_record("reject", RUA, "v=DMARC1; p=none;", RUA) == "v=DMARC1; p=reject; rua=%s;" % RUA
    assert plan_mod.new_record("none", RUA, "v=DMARC1; p=none; rua=%s; fo=1;" % RUA, RUA) == \
        "v=DMARC1; p=none; rua=%s; fo=1;" % RUA
    assert plan_mod.inherited_order(parent, RUA) == [plan_mod.rua_order(parent, RUA)]
    assert plan_mod.inherited_order("v=DMARC1; p=none; rua=mailto:b@corp.example;", RUA) == []
    # the quarantine-now record of an inheriting name, the monitoring record of an unaudited one, and a park row
    flows = {"corp.example": flow(500), "hr.corp.example": flow(), "old.corp.example": flow()}
    rep = apex_report(parent, ("hr.corp.example", "old.corp.example"), flows,
                      rua=rua_doc(by_header_from=[{"domain": "m.corp.example", "count": 30, "pass": 30, "fail": 0}]))
    rep["dns"]["old.corp.example"].update(spf=None, spf_status="absent", spf_terminator=None, dkim_selectors=[],
                                          dkim_status="absent", findings=fid("DMARC-002", "SPF-001"))
    rep["dns_extra"] = no_record("m.corp.example")
    p = plan_of(rep)
    hr = one(p, "hr.corp.example", "no_mail")
    assert hr["value"] == ("v=DMARC1; p=quarantine; sp=none; rua=mailto:a@vendor.invalid,mailto:b@corp.example,%s; "
                           "ruf=mailto:f@corp.example; fo=1; adkim=s;" % RUA)
    assert plan_mod.rua_order(parent, RUA) in hr["prerequisites"]
    assert plan_mod.external_destination("hr.corp.example", "mailto:a@vendor.invalid") in hr["prerequisites"]
    m = one(p, "m.corp.example", "new")
    assert m["value"] == ("v=DMARC1; p=none; rua=mailto:a@vendor.invalid,mailto:b@corp.example,%s; "
                          "ruf=mailto:f@corp.example; fo=1; adkim=s;" % RUA)
    assert m["prerequisites"][0] == plan_mod.rua_order(parent, RUA)
    park = one(p, "old.corp.example", "park", "_dmarc.old.corp.example")
    assert park["value"].startswith("v=DMARC1; p=reject; rua=mailto:a@vendor.invalid,mailto:b@corp.example,")
    # a name that inherits nothing, and a run with no report address: the plain record, as before
    assert one(plan_of(apex_report("v=DMARC1; p=none;", ("x.corp.example",)), rua=None), "x.corp.example",
               "new")["value"] == "v=DMARC1; p=none; rua=%s;" % plan_mod.RUA_PLACEHOLDER
    p = plan_of(rep, rua=None)
    assert one(p, "hr.corp.example", "no_mail")["value"] == (
        "v=DMARC1; p=quarantine; sp=none; rua=mailto:a@vendor.invalid,mailto:b@corp.example; ruf=mailto:f@corp.example; "
        "fo=1; adkim=s;")


# ------------------------------------------------------------------ P16: the mailflow tag

def test_p16_the_mailflow_tag_never_makes_a_domain_tenant_carried():
    """discover's --mailflow expansion tags every name its answer holds, inbound sightings included: on the quiet
    path that is all the tag can mean, which says nothing about where the name's own mail goes."""
    doc = dns_doc("m.corp.example", spf=None, spf_status="absent", dkim_selectors=[])

    def carried(tags):
        return plan_mod.tenant_carries({"inputs": {"domain_sources": {"m.corp.example": tags}}}, "m.corp.example", doc)
    assert carried(["env", "mailflow"]) is False and carried(["mailflow"]) is False
    assert carried(["tenant"]) is True and carried(["cli", "mailflow"]) is False and carried([]) is True
    assert "mailflow" not in plan_mod.TENANT_SOURCES
    rep = apex_report(APEX, (), {"corp.example": flow(500), "m.corp.example": flow(0, 3)})
    rep["dns"]["m.corp.example"] = own_record("m.corp.example", "v=DMARC1; p=none; rua=mailto:dmarc@esp.invalid;",
                                              spf=None, spf_status="absent", dkim_selectors=[])
    rep["inputs"]["domains"].append("m.corp.example")
    rep["inputs"]["domain_sources"] = {"corp.example": ["tenant"], "m.corp.example": ["env", "mailflow"]}
    kinds = [c["kind"] for c in rows(plan_of(rep), "m.corp.example")]
    assert "no_mail" not in kinds and "ratchet" in kinds  # no report covers it: the ramp stays


# ------------------------------------------------------------------ P24 to P26: damaged values

def test_p24_dkim_selectors_that_are_not_a_list_read_as_none():
    for odd in (2, 1.5, "selector1", None, {"a": 1}):
        assert plan_mod.foreign_senders(dns_doc("x.example", dkim_selectors=odd)) == [], odd
    assert plan_mod.foreign_senders(dns_doc("x.example", dkim_selectors=[1, "k1", None])) == ["DKIM selector k1"]
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow(5)})
    rep["dns"]["corp.example"]["dkim_selectors"] = 2
    assert plan_of(rep)["changes"]


def test_p25_an_absurd_inbound_count_never_overflows():
    assert plan_mod._slack(10 ** 400) == 10 ** 400 * 2 // 100 and plan_mod._slack(49) == 0
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow(0, 10 ** 400)},
                      maillog={"sender_domain": None, "counters": {"by_likely": {}},
                               "by_domain": {"corp.example": {"logical_messages": 3, "passing_messages": 0,
                                                              "internal_messages": 0, "genuine_failures": 3,
                                                              "by_likely": {"likely_spoof": 3}}}},
                      rua=rua_doc(streams=[spoof_stream("corp.example")]))
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]  # the rows hold less than came in
    rep["maillog"]["window_totals"] = {"hours": 720, "orgs": {"corp.example": {"by_domain": {
        "corp.example": {"logical_messages": 10 ** 400, "passing": 0}}}}}
    rep["maillog"]["cuts"] = {"corp.example": {"reason": "row budget"}}
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["no_mail"]


def damaged_report():
    rep = apex_report("v=DMARC1; p=none; rua=%s;" % RUA, (), {"corp.example": flow(10), "quiet.example": flow(0, 3)},
                      maillog={"sender_domain": None, "counters": {"by_likely": {}}, "alignment": {"available": True},
                               "by_domain": {"quiet.example": {"logical_messages": 3, "passing_messages": 0,
                                                               "internal_messages": 0, "genuine_failures": 3,
                                                               "by_likely": {"likely_spoof": 3}}}},
                      rua=rua_doc(streams=[spoof_stream("quiet.example")]))
    rep["dns"]["quiet.example"] = own_record("quiet.example")
    rep["inputs"]["domains"].append("quiet.example")
    rep["gate"] = {"domains": {"corp.example": {"verdict": "go"}}}
    return rep


def test_p26_a_damaged_report_or_inventory_is_an_error_never_a_traceback(tmp_path):
    for bad in ([1, 2], None, "text", 7):
        try:
            plan_mod.build_plan(bad, None, RUA)
            assert False, bad
        except ValueError as err:
            assert "not a JSON object" in str(err)
    rep = damaged_report()
    rep["dns"] = [1]
    try:
        plan_mod.build_plan(rep, None, RUA)
        assert False
    except ValueError as err:
        assert "DNS section is not an object" in str(err)
    for inv in ("text", 7):
        try:
            plan_mod.build_plan(damaged_report(), inv, RUA)
            assert False, inv
        except ValueError as err:
            assert "inventory is not a JSON object or list" in str(err)
    # a row without a domain, no rows at all, a zone host that is not text: planned all the same
    for inv in ({"domains": [{"zone_host": "x"}]}, {"domains": None}, [{"domain": "corp.example", "zone_host": 7}],
                [None, 3]):
        p = plan_mod.build_plan(damaged_report(), inv, RUA)
        assert p["changes"] and all(isinstance(c["zone_host"], str) for c in p["changes"]), inv
    # the command line says error, exit 2
    path = tmp_path / "report.json"
    path.write_text("[1, 2]", encoding="utf-8")
    r = subprocess.run([sys.executable, str(ROOT / "src" / "plan.py"), str(path), "--json"], capture_output=True,
                       text=True, cwd=str(ROOT))
    assert r.returncode == 2 and r.stderr.strip().startswith("error: the report is not a JSON object")
    assert "Traceback" not in r.stderr


def test_p26_a_damaged_value_in_a_section_is_held_or_read_as_empty():
    # a DNS entry that is not an object, or whose text fields are not text: the domain is held, the rest planned
    rep = damaged_report()
    rep["dns"]["corp.example"] = None
    p = plan_mod.build_plan(rep, None, RUA)
    assert holds_of(p, "corp.example") == ["the report's DNS entry for corp.example is not an object - re-run the "
                                           "audit before planning this domain"]
    assert rows(p, "quiet.example")
    for key, value in (("spf", 1), ("dmarc", 5), ("dmarc_status", ["found"]), ("effective_policy", {})):
        rep = damaged_report()
        rep["dns"]["corp.example"][key] = value
        p = plan_mod.build_plan(rep, None, RUA)
        assert holds_of(p, "corp.example") == ["the report's DNS entry for corp.example is damaged (%s not text) - "
                                               "re-run the audit before planning this domain" % key], key
        assert not rows(p, "corp.example")
    assert plan_mod.dmarc_tags(5) == {} and plan_mod.spf_sends(1) is False and plan_mod.derive_rua({"a": None}) is None
    # odd values in the evidence sections read as empty, never raise
    for path, value in ((("gate", "domains", "corp.example"), "no_go"),
                        (("rua", "failing_streams"), [None]),
                        (("rua", "failing_streams"), [{"source_ip": "192.0.2.1", "count": 30,
                                                       "header_from": [7, "corp.example"], "likely": "unknown"}]),
                        (("rua", "failing_streams"), [{"source_ip": ["192.0.2.1"], "count": None,
                                                       "header_from": ["corp.example"], "likely": "unknown"}]),
                        (("rua", "spf_only_senders"), ["x", None, 3]),
                        (("maillog", "by_domain", "quiet.example", "by_likely"), [3]),
                        (("maillog", "spf_only_senders"), [None, "x"]),
                        (("gate", "exceptions"), "none"),
                        (("inputs", "domains"), "corp.example"),
                        (("rua", "by_source_ip"), [None, {"header_from": "x"}])):
        rep = damaged_report()
        node = rep
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
        p = plan_mod.build_plan(rep, None, RUA)
        assert p["changes"], path
    rep = damaged_report()
    rep["rua"]["failing_streams"] = [{"source_ip": ["192.0.2.1"], "count": None, "header_from": ["corp.example"],
                                      "likely": "unknown"}]
    step = one(plan_mod.build_plan(rep, None, RUA), "corp.example", "ratchet")
    assert "aggregate reports: ['192.0.2.1'] sends ? message(s) as corp.example and fails (unknown; )" in \
        step["prerequisites"]


# ------------------------------------------------------------------ P18, P19, P21 to P23: the totals the plan reads

def collect_run(monkeypatch, out, tenant, *extra):
    """collect.main against the phase-2 tenant stub (hunting answered in memory, DNS stubbed, no sign-in, no
    network): (files, text) of latest/."""
    monkeypatch.setattr(collect.graph_client, "hunting", tenant.hunting)
    monkeypatch.setattr(collect.graph_client, "creds", lambda env_file=None: ("tenant", "client", "secret"))
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    monkeypatch.setattr(collect.graph_client, "token", lambda cred: "second")
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([], None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
    monkeypatch.setattr(audit, "run_dns", phase2.live_dns)
    monkeypatch.setattr(dns_audit, "resolve_ex", lambda resolver, name, rtype: (
        [], {"path": "stub", "ttl": None, "status": "absent"}))
    monkeypatch.setattr(collect, "ROW_CAP", 300)
    monkeypatch.setattr(collect, "SLICE_TARGET", 270)
    monkeypatch.delenv("RUA_MAILBOX", raising=False)
    monkeypatch.setattr(sys, "argv", ["collect.py", "corp.example", "hr.corp.example", "shop.example", "--no-config",
                                      "--no-owners", "--no-notify", "--out", str(out)] + list(extra))
    try:
        collect.main()
    except SystemExit:
        pass
    latest = out / "latest"
    return ({n: json.loads((latest / n).read_text(encoding="utf-8")) for n in ("report.json", "run.json")},
            {n: (latest / n).read_text(encoding="utf-8") for n in ("report.md", "next_steps.md", "summary.txt")})


def totals_answer(**counts):
    row = {"fromdom": "corp.example", "logical_messages": 9000, "passing": 8990, "delivered_by": "",
           "genuine_failures": 2, "delivered_despite_fail": 0}
    row.update(counts)
    return {"schema": phase2.TOTALS["schema"], "results": [row]}


def test_p18_a_totals_answer_the_audit_sets_aside_is_never_shown_as_a_count(monkeypatch, tmp_path):
    """collect.py said the counts of every answer before the audit's floor check ran, so an answer the audit set
    aside stayed in run.json as 'counted ... (the rows kept stay a floor)' beside the note that set it aside.
    The counts are said once the audit has kept them; a set-aside answer appears only in that note."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, tzinfo=None)
    t = phase2.Tenant(phase2.tenant_legs(now), {"corp.example": totals_answer()})
    files, text = collect_run(monkeypatch, tmp_path / "out", t, "--max-rows", "1500")
    ml = files["report.json"]["maillog"]
    assert "window_totals" not in ml and list(ml["window_totals_rejected"]) == ["corp.example"]
    notes = files["run.json"]["notes"]
    assert not any("counted in Advanced Hunting" in n for n in notes + files["run.json"]["degraded"])
    assert len([n for n in notes if n.startswith("mail log: full-window totals for corp.example set aside, not shown: "
                                                  "the answer holds 2 genuine failures over the whole window")]) == 1
    assert "Advanced Hunting" not in text["summary.txt"] + text["next_steps.md"] + text["report.md"]
    # an answer the audit keeps: its counts are said, once, after the audit's own notes
    t.totals = {"corp.example": totals_answer(genuine_failures=160, delivered_despite_fail=15)}
    files, text = collect_run(monkeypatch, tmp_path / "kept", t, "--max-rows", "1500")
    notes = files["run.json"]["notes"]
    counted = [n for n in notes if "counted in Advanced Hunting" in n]
    assert counted == ["mail log: full-window totals for corp.example over the last 30 days, counted in Advanced "
                       "Hunting: about 9000 logical messages, 160 genuine failures, 15 delivered despite failing (the "
                       "rows kept stay a floor)"]
    assert "window_totals" in files["report.json"]["maillog"] and "set aside" not in "\n".join(notes)
    assert notes.index(counted[0]) > max(i for i, n in enumerate(notes) if n.startswith("mail log: ") and "rows for" in n)


def test_p19_an_hour_at_the_api_cap_is_no_floor_for_failures(tmp_path):
    """An hour kept at the API row cap holds an arbitrary part of its legs: a failure whose passing copy was
    dropped reads as genuine, so the rows kept overcount failures there. The whole-window answer that corrects
    them is kept, not set aside for 'fewer failures'; a row-budget cut keeps the failure test, and the message
    test applies to both."""
    def totals(messages, failures):
        return {"hours": 720, "orgs": {"corp.example": {"source": collect.AGGREGATE_SOURCE, "by_domain": {
            "corp.example": {"logical_messages": messages, "passing": messages - failures, "genuine_failures": failures,
                             "delivered_despite_fail": 0}}}}}
    verdicts = [{"domain": "corp.example", "genuine_failure": i < 101} for i in range(920)]
    api = {"corp.example": {"reason": "api cap", "api_cap_hours": ["6h..5h"]}}
    budget = {"corp.example": {"reason": "row budget", "kept_hours": 156, "kept_from": "2026-10-07T04:03:28Z"}}
    fewer = {"corp.example": "0 genuine failures over the whole window, fewer than the 101 in the rows kept"}
    assert audit.window_totals_below_floor(totals(920, 0), verdicts, api) == {}
    assert audit.window_totals_below_floor(totals(920, 0), verdicts, budget) == fewer
    assert audit.window_totals_below_floor(totals(920, 0), verdicts) == fewer  # an older report, cuts unknown
    assert audit.window_totals_below_floor(totals(920, 0), verdicts, dict(budget, **{
        "corp.example": dict(budget["corp.example"], api_cap_hours=["6h..5h"])})) == {}  # both: the hour overcounts
    assert audit.window_totals_below_floor(totals(500, 0), verdicts, api) == {
        "corp.example": "about 500 logical messages over the whole window, fewer than the 920 in the rows kept"}
    # through the audit: the cut recorded as an API cap keeps the answer (six failures in the rows kept, beyond
    # the slack a pair or two straddling the cut hour gets), a row-budget cut sets it aside
    log = (Log().add("staff@corp.example", "Weekly #", times=5)
           .add("app@corp.example", "Build #", dmarc="fail", times=6, env="corp.example"))
    path = log.write(tmp_path / "log.csv")
    kept = audit.build_report(domains=["corp.example"], maillog=path, offline=True, auth_column="DMARC",
                              maillog_cuts=api, window_totals=totals(900, 0))
    assert kept["maillog"]["window_totals"] == totals(900, 0) and "window_totals_rejected" not in kept["maillog"]
    aside = audit.build_report(domains=["corp.example"], maillog=path, offline=True, auth_column="DMARC",
                               maillog_cuts=budget, window_totals=totals(900, 0))
    assert "window_totals" not in aside["maillog"] and aside["maillog"]["window_totals_rejected"] == {
        "corp.example": "0 genuine failures over the whole window, fewer than the 6 in the rows kept"}


def test_p21_the_verified_lines_name_the_floor_and_what_rests_on_which_count(tmp_path):
    log = (Log().add("staff@corp.example", "Weekly #", times=5)
           .add("app@corp.example", "Build #", dmarc="fail", times=3, env="corp.example"))
    path = log.write(tmp_path / "log.csv")
    totals = {"hours": 720, "orgs": {"corp.example": {"source": collect.AGGREGATE_SOURCE, "by_domain": {
        "corp.example": {"logical_messages": 7000, "passing": 6900, "genuine_failures": 100,
                         "delivered_despite_fail": 5}}}}}
    cut = {"corp.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T22:00:00Z"}}
    rep = audit.build_report(domains=["corp.example"], maillog=path, offline=True, auth_column="DMARC",
                             maillog_cuts=cut, window_totals=totals)
    lines = rep["verified_vs_inferred"]["verified"]
    assert rep["maillog"]["cuts"] == cut  # stored before the lines are written, so they can name it
    assert [x for x in lines if x.startswith("mail log: 8 rows deduplicated to 8 logical messages, 3 genuine failures")] == [
        "mail log: 8 rows deduplicated to 8 logical messages, 3 genuine failures, 3 delivered despite fail; the rows "
        "kept are a floor for corp.example (the row budget kept the newest 41h only)"]
    assert [x for x in lines if x.startswith("full-window totals for corp.example")] == [
        "full-window totals for corp.example, counted in advanced hunting over 30 days (maillog.window_totals): 100 "
        "genuine failures, 5 delivered despite failing; its logical messages and passing are Kusto estimates. The gate, "
        "the census and the labels rest on the rows kept; the plan's no-mail check and its list of sending subdomains "
        "read these totals too"]
    assert "the rows kept" in audit.render_md(rep)
    # an hour at the API cap, a failed pull, nothing cut
    assert audit._cut_words({"corp.example": {"reason": "api cap", "api_cap_hours": ["6h..5h", "9h..8h"]},
                             "shop.example": {"reason": "not pulled", "error": "HTTP 500"}}) == (
        "; the rows kept are incomplete for corp.example (an hour at the API cap: 6h..5h, 9h..8h; its failures are not "
        "verified), missing shop.example (its pull failed)")
    assert audit._cut_words({}) == "" and audit._cut_words(None) == ""
    plain = audit.build_report(domains=["corp.example"], maillog=path, offline=True, auth_column="DMARC")
    assert [x for x in plain["verified_vs_inferred"]["verified"] if x.startswith("mail log: 8 rows")] == [
        "mail log: 8 rows deduplicated to 8 logical messages, 3 genuine failures, 3 delivered despite fail"]


def test_p22_a_totals_query_saved_as_utf16_leaves_a_note_never_a_crash(monkeypatch, tmp_path):
    """PowerShell's > and Out-File save a customized query as UTF-16: the read raised UnicodeDecodeError past the
    OSError guard and ended collect.main after the mail-log pull, with no report written."""
    custom = tmp_path / "maillog_totals.kql"
    custom.write_text(collect.TOTALS_QUERY.read_text(encoding="utf-8"), encoding="utf-16")
    monkeypatch.setattr(collect, "TOTALS_QUERY", custom)
    calls = []
    monkeypatch.setattr(collect.graph_client, "hunting", lambda *a, **k: calls.append(a) or {})
    totals, notes = collect.pull_window_totals("tok", {"corp.example": {"reason": "row budget"}}, 30)
    assert totals is None and calls == []
    assert len(notes) == 1 and notes[0].startswith("mail log: full-window totals not counted: cannot read "
                                                   "maillog_totals.kql ('utf-8' codec can't decode byte")
    monkeypatch.setattr(collect, "TOTALS_QUERY", tmp_path / "no_such.kql")
    totals, notes = collect.pull_window_totals("tok", {"corp.example": {"reason": "row budget"}}, 30)
    assert totals is None and notes[0].startswith("mail log: full-window totals not counted: cannot read no_such.kql (")


def test_p23_the_totals_query_reads_a_dmarc_verdict_as_dedupe_does():
    """Exchange records bestguesspass for a From domain with no DMARC record whose mail would have passed:
    dedupe counts it as a pass, so the query that sits beside dedupe's counts must too, or a first run's full
    window shows 'about 0 passing' next to rows kept that pass."""
    kql = (ROOT / "queries" / "maillog_totals.kql").read_text(encoding="utf-8")
    assert not re.search(r'dmarc\s*=~\s*"(?:pass|fail)"', kql)
    assert kql.count('dmarc contains "pass"') == 2 and kql.count('dmarc contains "fail"') == 4
    cols = {"action": "Delivery action"}
    assert dedupe.leg_auth({"DMARC": "bestguesspass"}, cols, "DMARC") == (True, False)
    assert dedupe.leg_auth({"DMARC": "pass"}, cols, "DMARC") == (True, False)
    assert dedupe.leg_auth({"DMARC": "fail"}, cols, "DMARC") == (False, True)
    assert dedupe.leg_auth({"DMARC": "none"}, cols, "DMARC") == (False, False)
    assert "bestguesspass" in kql  # the header says so


# ------------------------------------------------------------------ verify.md and the documents

def test_verify_md_shows_how_to_check_each_new_prerequisite(tmp_path):
    docs = {"corp.example": own_record("corp.example", APEX), "b.corp.example": own_record("b.corp.example"),
            "brand.example": own_record("brand.example"), "example.com": own_record("example.com", **GOOGLE)}
    log = (Log().add("staff@corp.example", "Weekly #", times=5, direction="Outbound")
           .add("statements@billing.corp.example", "Your October statement", dmarc="fail", times=3,
                env="mailer.billing-vendor.invalid"))
    reports = [rua_report(tmp_path / "corp.xml", "corp.example", "quarantine", [
        ("192.0.2.10", 900, "corp.example", "corp.example", "pass", "corp.example", "pass"),
        ("198.51.100.60", 15, "billing.corp.example", "billing-vendor.invalid", "pass",
         "mailer.billing-vendor.invalid", "pass")]),
        rua_report(tmp_path / "brand.xml", "brand.example", "none", [
            ("198.51.100.61", 15, "brand.example", "billing-vendor.invalid", "pass", "mailer.billing-vendor.invalid",
             "pass")])]
    rep = audited(tmp_path / "run", docs, log, reports, flows={"corp.example": flow(500), "b.corp.example": flow(),
                                                               "brand.example": flow(), "example.com": flow(5)})
    p = plan_of(rep)
    sp = next(c for c in rows(p, "corp.example", "ratchet") if c["priority"] == 4)
    texts = [s["text"] for s in verify.change_steps(sp, rep)]
    assert any(t.startswith("Read a longer span than this run's: every aggregate report in the archive") for t in texts)
    assert any("compare the envelope and signing domains behind them" in t for t in texts)
    assert any("queries/subdomain_health_corp.example.kql" in t for t in texts)
    quiet = one(p, "brand.example", "no_mail")
    texts = [s["text"] for s in verify.change_steps(quiet, rep)]
    assert any(t.startswith("Re-read the aggregate reports: in the by_source_ip table every source that fails as "
                            "brand.example is one you can name as a spoof") for t in texts)
    ramp = one(p, "example.com", "ratchet")
    steps = verify.change_steps(ramp, rep)
    assert any(s["text"].startswith("Supply evidence that covers example.com:") and s["code"] ==
               "python src/collect.py example.com" for s in steps)
    text = verify.render(rep, p)
    assert "Read a longer span than this run's" in text and text.isascii()


def test_docs_say_monthly_or_less_often_and_the_new_rules():
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())  # the prose wraps at 78 columns
    method = " ".join((ROOT / "docs" / "methodology.md").read_text(encoding="utf-8").split())
    for text in (readme, method):
        assert "monthly or less often" in text and "less often than monthly" not in text
        assert "sp=quarantine` added" in text
    assert "a log from another period" in readme and "a failed MX lookup never parks a domain" in readme
    assert "`sp=none` on any" in readme and "the span of the aggregate reports about this record" in readme
    assert "A mail log from another period" in method and "the span of the reports about the record it rests on" in method
    for text in (readme, method):
        assert "phishing leans on" in text and "a billing word" in text
        assert "records of their own at that policy first" in text and "carries the same check on each step" in text
        assert "one mailbox serves many brands" in text
    assert "proposes each one's record at `p=quarantine`, where `sp=` has it today" in readme
    assert "proposes those subdomains' records at quarantine, where `sp=` has them today" in method


def test_plain_ascii():
    for rel in ("src/plan.py", "src/verify.py", "tests/test_r11_plan.py", "README.md", "docs/methodology.md"):
        assert (ROOT / rel).read_text(encoding="utf-8").isascii(), rel
