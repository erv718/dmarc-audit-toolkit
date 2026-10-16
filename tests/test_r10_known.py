"""Round 10, workstream 5: four known plan and query defects, found on a live
tenant's data. K1: whether a sending subdomain has a DMARC record of its own
is a DNS lookup - collect.py's for an unaudited one (report.dns_extra), the
audit's for an audited one - never what an old aggregate report says was
published there; a name whose own lookup failed (DMARC-007 too) gets its
record only after a lookup. K2: a record whose rua reports only to a vendor
or a mailbox of its own gets the run's report address appended, in a
zero-risk row of its own that no gated step carries; a record that gains an
address in another organization names the external-destination record. K3:
the SPF-007 hold says what SPF-007 is, an include that did not resolve. K4:
queries/delivered_despite_failure.kql counts what the report counts.
Synthetic data, offline: DNS answers from tables at dns_audit.resolve_ex and
spf_lookups.get_spf_status, advanced hunting at graph_client.hunting, and
every socket refuses."""

import csv
import json
import re
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import collect
import discover
import dns_audit
import next_steps
import plan as plan_mod
import spf_lookups
import verify

ROOT = Path(__file__).resolve().parent.parent
MAILBOX = "dmarc-reports@corp.example"
REPORTS = "mailto:" + MAILBOX
CORP = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % REPORTS
BRAND = "v=DMARC1; p=reject; rua=mailto:dmarc@vendor.example,mailto:dmarc@brand.example; fo=1"
SHOP = "v=DMARC1; p=none; rua=mailto:dmarc@vendor.example,mailto:postmaster@shop.example;"
E_OWN = "v=DMARC1; p=none; rua=%s;" % REPORTS
M365 = "v=spf1 include:spf.protection.outlook.com -all"
GOOGLE = "v=spf1 include:_spf.google.com ~all"
KEY = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


# ------------------------------------------------------------------ a tenant shaped like the live one

# corp.example at p=quarantine; sp=none, reporting to the toolkit's mailbox. Its marketing platform sends as m.
# and t.corp.example, which are not audited: old aggregate reports still name a record of their own at each, but
# DNS today has none. e.corp.example really has one. The lookup for s.corp.example fails on every path, and
# q.corp.example, the quietest, lies past this run's lookup limit. brand.example, a sister brand in the tenant,
# reports only to a vendor and its own mailbox; shop.example, a brand on Google listed in EXTRA_DOMAINS, too.
TXT = {"_dmarc.corp.example": [CORP], "_dmarc.brand.example": [BRAND], "_dmarc.shop.example": [SHOP],
       "_dmarc.e.corp.example": ["google-site-verification=abc", E_OWN],
       "_dmarc.m.corp.example": ["google-site-verification=xyz"],  # a TXT answer, but no DMARC record
       "selector1._domainkey.corp.example": [KEY], "selector1._domainkey.brand.example": [KEY],
       "google._domainkey.shop.example": [KEY]}
MX = {"corp.example": ["0 corp-example.mail.protection.outlook.com"],
      "brand.example": ["0 brand-example.mail.protection.outlook.com"], "shop.example": ["1 smtp.google.com"]}
SPF = {"corp.example": M365, "brand.example": M365, "shop.example": GOOGLE,
       "spf.protection.outlook.com": "v=spf1 ip4:192.0.2.0/24 -all", "_spf.google.com": "v=spf1 ip4:198.51.100.0/24 ~all"}
FAILING = {"_dmarc.s.corp.example"}  # times out on port 53 and over HTTPS alike


class Resolver:
    """dns_audit's resolver path and spf_lookups' SPF fetch, answered from the tables above; every name asked is
    recorded."""

    def __init__(self):
        self.asked = []

    def resolve_ex(self, resolver, name, rtype):
        name = name.lower()
        self.asked.append((name, rtype))
        if name in FAILING:
            return [], {"path": "doh", "ttl": None, "status": "error", "err": "timeout"}
        recs = {"TXT": TXT, "MX": MX}.get(rtype, {}).get(name, [])
        return list(recs), {"path": "port53-udp", "ttl": 300, "status": "found" if recs else "absent"}

    def spf(self, domain, resolver):
        rec = SPF.get(domain.lower())
        return (rec, "found", "port53-udp") if rec else (None, "absent", "port53-udp NOERROR, 0 TXT, none v=spf1")


def report_xml(domain, rows, policy="none", sp="none"):
    """One aggregate report a receiver sent about domain's record, dated three days ago; rows: (source_ip, count,
    header_from, signing domain, envelope domain), each passing DMARC on an aligned DKIM signature (SPF passes
    for the envelope domain, aligned only when that is the header From)."""
    begin = int((NOW - timedelta(days=3)).timestamp())
    recs = "".join(
        "<record><row><source_ip>%s</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition>"
        "<dkim>pass</dkim><spf>%s</spf></policy_evaluated></row><identifiers><header_from>%s</header_from>"
        "</identifiers><auth_results><dkim><domain>%s</domain><selector>s1</selector><result>pass</result></dkim>"
        "<spf><domain>%s</domain><scope>mfrom</scope><result>pass</result></spf></auth_results></record>"
        % (ip, n, "pass" if env == hf else "fail", hf, dkd, env) for ip, n, hf, dkd, env in rows)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<feedback><report_metadata><org_name>reporter.example</org_name>'
            "<email>noreply@reporter.example</email><report_id>%s-%d</report_id><date_range><begin>%d</begin>"
            "<end>%d</end></date_range></report_metadata><policy_published><domain>%s</domain><adkim>r</adkim>"
            "<aspf>r</aspf><p>%s</p><sp>%s</sp><pct>100</pct></policy_published>%s</feedback>\n"
            % (domain, begin, begin, begin + 86399, domain, policy, sp, recs))


STALE = {  # what the report mailbox holds: the apex's reports, and two about m. and t.'s records of old
    "reporter.example!corp.example!1.xml": report_xml("corp.example", [
        ("192.0.2.10", 4000, "corp.example", "corp.example", "corp.example"),
        ("198.51.100.21", 900, "m.corp.example", "m.corp.example", "esp.invalid"),
        ("198.51.100.22", 600, "t.corp.example", "t.corp.example", "esp.invalid"),
        ("198.51.100.23", 300, "e.corp.example", "e.corp.example", "esp.invalid"),
        ("198.51.100.24", 120, "s.corp.example", "s.corp.example", "esp.invalid"),
        ("198.51.100.25", 40, "q.corp.example", "q.corp.example", "esp.invalid")], "quarantine"),
    "reporter.example!m.corp.example!2.xml": report_xml("m.corp.example", [
        ("198.51.100.21", 500, "m.corp.example", "m.corp.example", "esp.invalid")]),
    "reporter.example!t.corp.example!3.xml": report_xml("t.corp.example", [
        ("198.51.100.22", 300, "t.corp.example", "t.corp.example", "esp.invalid")]),
}
FLOWS = [{"d": "corp.example", "messages": 5800, "outbound": 5000, "inbound": 800, "last_seen": None},
         {"d": "m.corp.example", "messages": 8, "outbound": 0, "inbound": 8, "last_seen": None},
         {"d": "t.corp.example", "messages": 6, "outbound": 0, "inbound": 6, "last_seen": None},
         {"d": "brand.example", "messages": 350, "outbound": 300, "inbound": 50, "last_seen": None}]
LOG_COLS = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
            "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC", "Direction"]


def maillog(path):
    """The mail log: staff mail, the marketing platform's copies to staff as m. and t., a sister-brand note, and
    a spoof of the apex."""
    rows = []

    def add(sender, env, subject, dmarc, times, direction="Inbound", where=("Delivered", "Inbox/folder")):
        for _ in range(times):
            n = len(rows) + 1
            rows.append([(NOW - timedelta(hours=n)).strftime("%Y-%m-%dT%H:%M:%SZ"), "<k%04d@mail.invalid>" % n, sender,
                         sender.rpartition("@")[2], env, "user%d@corp.example" % (n % 5), "%s %d" % (subject, n),
                         where[0], where[1], dmarc, direction])
    add("staff@corp.example", "corp.example", "Weekly report", "pass", 20, "Intra-org")
    add("news@m.corp.example", "esp.invalid", "Offer", "pass", 8)
    add("deals@t.corp.example", "esp.invalid", "Deal", "pass", 6)
    add("people@brand.example", "brand.example", "Note", "pass", 4, "Intra-org")
    add("ceo@corp.example", "evil.invalid", "Urgent wire transfer", "fail", 5, where=("Blocked", "Quarantine"))
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(LOG_COLS)
        w.writerows(rows)
    return str(path)


def live_run(monkeypatch, tmp_path, cap=4, extra=()):
    """The real collect.main for the tenant above, every network seam stubbed and every socket refused; extra: more
    command-line arguments. Returns ({file name: JSON or text} from latest/, the resolver, the socket attempts)."""
    attempts = []

    def refuse(*a, **k):
        attempts.append(a)  # recorded too, in case a caller swallows the error
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "sendto", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    dns = Resolver()
    monkeypatch.setattr(dns_audit, "resolve_ex", dns.resolve_ex)
    monkeypatch.setattr(spf_lookups, "get_spf_status", dns.spf)
    monkeypatch.setattr(collect.graph_client, "creds", lambda env_file=None: ("tenant", "client", "secret"))
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([
        {"domain": "corp.example", "verified": True, "services": ["Email"], "default": True},
        {"domain": "brand.example", "verified": True, "services": ["Email"]}], None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "Route53", "ns_path": "skipped"})
    calls = []

    def hunting(tok, kql, ts=None):
        calls.append(kql)
        assert "summarize messages = dcount(InternetMessageId)" in kql, kql  # the mail-flow aggregate alone
        return {"schema": [{"name": c} for c in ("d", "messages", "outbound", "inbound", "last_seen")],
                "results": FLOWS}
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)

    def fetch(tok, mailbox, dest_dir, state_file=None, **kw):
        assert mailbox == MAILBOX
        Path(dest_dir).mkdir(parents=True, exist_ok=True)
        for name, xml in STALE.items():
            (Path(dest_dir) / name).write_text(xml, encoding="utf-8")
        return len(STALE), ["report mailbox: %d reports saved" % len(STALE)]
    monkeypatch.setattr(collect.fetch_rua, "fetch", fetch)
    monkeypatch.setenv(discover.EXTRA_KEY, "shop.example")
    monkeypatch.delenv("RUA_MAILBOX", raising=False)
    monkeypatch.setattr(collect, "EXTRA_DNS_MAX", cap)
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["collect.py", "--no-config", "--no-owners", "--no-notify", "--out", str(out),
                                      "--maillog", maillog(tmp_path / "log.csv"), "--auth-column", "DMARC",
                                      "--rua-mailbox", MAILBOX] + list(extra))
    try:
        collect.main()
    except SystemExit:
        pass
    latest = out / "latest"
    files = {n: json.loads((latest / n).read_text(encoding="utf-8")) for n in ("report.json", "plan.json", "run.json")}
    files.update({n: (latest / n).read_text(encoding="utf-8")
                  for n in ("plan.md", "todo.md", "verify.md", "next_steps.md")})
    assert len(calls) == 1  # one mail-flow aggregate; the mail log came from the file
    return files, dns, attempts


def row(plan, host, kind=None):
    hits = [c for c in plan["changes"] if c["hostname"] == host and (kind is None or c["kind"] == kind)]
    assert len(hits) == 1, (host, kind, [(c["kind"], c["hostname"]) for c in plan["changes"]])
    return hits[0]


def section(md, name):
    """One domain's section of verify.md."""
    return md.split("\n## %s\n" % name, 1)[1].split("\n## ", 1)[0]


def row_block(md, cid):
    """One plan row's block in verify.md: its heading down to the next heading."""
    return md.split("\n#### %s " % cid, 1)[1].split("\n#### ", 1)[0].split("\n## ", 1)[0]


LOOK_FIRST = "look up _dmarc.%s first: publish only if it has no record"
HOLD = ("subdomains that send have no record of their own: m.corp.example, q.corp.example (not checked), "
        "s.corp.example (not checked) and t.corp.example - publish their monitoring records (above) before sp= moves "
        "to quarantine; a name marked not checked may have a record already: look it up first")


# ------------------------------------------------------------------ K1: DNS decides, never a stale report

def test_k1_collect_looks_up_the_sending_subdomains_and_the_plan_believes_dns(monkeypatch, tmp_path):
    files, dns, attempts = live_run(monkeypatch, tmp_path)
    rep, plan, run = files["report.json"], files["plan.json"], files["run.json"]
    assert attempts == []  # nothing left the machine
    # the stale reports still say m. and t. publish a record of their own; DNS today shows none
    seen = {s["domain"] for s in rep["rua"]["policy_check"]["seen"]}
    assert {"m.corp.example", "t.corp.example"} <= seen
    # collect looked up the four busiest unaudited senders' own records, and only those (q. is past the limit)
    looked = sorted(n for n, t in dns.asked if t == "TXT" and n.startswith("_dmarc.") and n.count(".") == 3)
    assert looked == ["_dmarc.e.corp.example", "_dmarc.m.corp.example", "_dmarc.s.corp.example", "_dmarc.t.corp.example"]
    assert rep["dns_extra"] == {
        "m.corp.example": {"dmarc": None, "status": "absent", "source": None, "path": "port53-udp"},
        "t.corp.example": {"dmarc": None, "status": "absent", "source": None, "path": "port53-udp"},
        "e.corp.example": {"dmarc": E_OWN, "status": "found", "source": "_dmarc.e.corp.example", "path": "port53-udp"},
        "s.corp.example": {"dmarc": None, "status": "error", "source": None, "path": "doh", "err": "timeout"}}
    assert ("DNS: _dmarc looked up for 4 unaudited sending subdomains: e.corp.example has a record of its own; "
            "m.corp.example and t.corp.example have none; the lookup failed for s.corp.example, so the plan asks for a "
            "lookup first") in run["notes"]
    assert ("DNS: 1 more unaudited sending subdomain not looked up (at most 4 a run, the busiest first): "
            "q.corp.example - the plan asks for a lookup first for each") in run["notes"]
    # m. and t. get the monitoring record that shields them from the apex's sp=, outright: DNS showed none
    for name, saw in (("m.corp.example", "1400 passing in the aggregate reports"),
                      ("t.corp.example", "900 passing in the aggregate reports")):
        c = row(plan, "_dmarc." + name)
        assert (c["kind"], c["priority"], c["current"], c["prerequisites"]) == ("new", 1, "none", [])
        assert c["value"] == "v=DMARC1; p=none; rua=%s;" % REPORTS
        assert saw in c["why"] and c["why"].endswith("; DNS shows no record at _dmarc.%s" % name)
    # the one with a record of its own gets nothing: a second record would leave it with no policy at all
    assert not [c for c in plan["changes"] if c["domain"] == "e.corp.example"]
    # the failed lookup and the one past the limit: proposed, with the lookup first
    s, q = row(plan, "_dmarc.s.corp.example"), row(plan, "_dmarc.q.corp.example")
    assert s["current"] == "not checked (its lookup failed in this run)" and s["prerequisites"] == [
        LOOK_FIRST % "s.corp.example"]
    assert q["current"] == "not checked (not an audited domain)" and q["prerequisites"] == [LOOK_FIRST % "q.corp.example"]
    assert s["why"].startswith("sending subdomain whose own record this run could not look up: ")
    assert q["why"].startswith("sending subdomain whose own record this run did not look up: ")
    assert q["human_summary"].startswith("Publish a monitoring-only DMARC record for q.corp.example once a lookup shows "
                                         "it has none of its own")
    # the sp= step is held, naming what has no record and what nobody could check; e. holds nothing
    assert {"domain": "corp.example", "reason": HOLD} in plan["holds"]
    assert not any("e.corp.example" in h["reason"] for h in plan["holds"])
    sp = next(c for c in plan["changes"] if c["domain"] == "corp.example" and c["priority"] == 4)
    assert sp["prerequisites"][0] == (
        "every subdomain that sends has its own _dmarc record: m.corp.example, q.corp.example (not checked), "
        "s.corp.example (not checked) and t.corp.example have none yet (the monitoring records above)")


def test_k1_plan_md_todo_md_and_verify_md_read_right_on_monday(monkeypatch, tmp_path):
    files, _, _ = live_run(monkeypatch, tmp_path)
    plan, md, todo, ver = files["plan.json"], files["plan.md"], files["todo.md"], files["verify.md"]
    m, s, q = (row(plan, "_dmarc.%s.corp.example" % x) for x in "msq")
    # plan.md: the hold first, each row with its current value and what to do before applying it
    holds = md.split("## Fix or decide first", 1)[1].split("\n## ", 1)[0]
    assert "- **corp.example**: " + HOLD in holds
    assert "- **%s** m.corp.example - sending subdomain without a record of its own:" % m["id"] in md
    block = md.split("- **%s** s.corp.example - " % s["id"], 1)[1].split("\n- **", 1)[0]
    assert "  - current: `not checked (its lookup failed in this run)`" in block
    assert "  - before applying: " + LOOK_FIRST % "s.corp.example" in block
    # todo.md: decide the hold first, then the rows to publish now, each with its lookup where one is owed
    decide = todo.split("## 1. Decide first", 1)[1].split("## 2.", 1)[0]
    assert "- corp.example: " + HOLD in decide
    now = todo.split("## 2. Do now", 1)[1].split("## 3.", 1)[0]
    assert ("- %s m.corp.example: TXT at `_dmarc.m.corp.example` = `v=DMARC1; p=none; rua=%s;` (current: `none`) - "
            % (m["id"], REPORTS)) in now
    assert ("- %s q.corp.example: TXT at `_dmarc.q.corp.example` = `v=DMARC1; p=none; rua=%s;` (current: `not checked "
            "(not an audited domain)`) - " % (q["id"], REPORTS)) in now
    assert "  - before applying: " + LOOK_FIRST % "q.corp.example" in now
    assert "e.corp.example" not in now
    # verify.md: what the run looked up for each name, and the lookup that settles it before publishing
    sec = section(ver, "m.corp.example")
    assert ("Not audited in this run: m.corp.example is not on the domain list, so no gate judged it and the run looked "
            "up only its _dmarc record, for the plan's subdomain rule: DNS showed no record there;") in sec
    assert "None, and none looked for: m.corp.example is not audited, so this run looked up nothing but its _dmarc" in sec
    blk = row_block(ver, m["id"])
    assert "1. DNS: Before: look up _dmarc.m.corp.example: no answer starts with v=DMARC1 today (current: none)." in blk
    assert "Resolve-DnsName -Name _dmarc.m.corp.example -Type TXT -Server 8.8.8.8" in blk
    assert "https://dns.google/resolve?name=_dmarc.m.corp.example&type=TXT" in blk  # a claimed absence, cross-checked
    sec = section(ver, "s.corp.example")
    assert "the lookup failed, so the plan asks for it to be looked up first" in sec
    assert ("no answer should start with v=DMARC1 - the run's own lookup of it failed (plan.json says: not checked (its "
            "lookup failed in this run)); if one does, do not publish: s.corp.example already has a record of its own"
            in row_block(ver, s["id"]))
    sec = section(ver, "q.corp.example")
    assert "Not audited in this run: q.corp.example is not on the domain list, so its DNS was not looked up" in sec
    assert "no answer should start with v=DMARC1 - the run did not look (plan.json says: not checked (not an audited " \
           "domain))" in row_block(ver, q["id"])
    assert "## e.corp.example" not in ver  # no row names it
    # the sp= step's proof looks up every subdomain's own record, e. among them: the plan counts it as covered
    sp = next(c for c in plan["changes"] if c["domain"] == "corp.example" and c["priority"] == 4)
    blk = row_block(ver, sp["id"])
    assert "Look up the subdomains' own records:" in blk and "e.corp.example answers already: DNS showed its own " \
                                                             "record in this run" in blk
    for name in ("m", "q", "s", "t", "e"):
        assert "Resolve-DnsName -Name _dmarc.%s.corp.example -Type TXT" % name in blk, name
    assert ver.isascii() and md.isascii() and todo.isascii()


def apex(record=CORP, **over):
    """corp.example alone, audited, at the given record, its mail measured; reports about its record name
    m.corp.example passing, and say m.corp.example published a record of its own."""
    doc = {"domain": "corp.example", "spf": M365, "spf_status": "found", "spf_terminator": "-all", "spf_lookups": 1,
           "dmarc": record, "dmarc_source": "_dmarc.corp.example", "effective_policy": plan_mod.dmarc_tags(record)["p"],
           "inherited": False, "dmarc_status": "found", "dkim_selectors": ["selector1"], "dkim_status": "found",
           "mx": ["0 corp-example.mail.protection.outlook.com"], "mx_null": False, "mx_status": "found",
           "findings": [], "evidence": []}
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": ["corp.example"]}, "gate": {"domains": {}},
           "dns": {"corp.example": doc}, "maillog": None,
           "mailflow": {"days": 30, "domains": {"corp.example": {"messages": 900, "outbound": 800, "inbound": 100,
                                                                 "last_seen": None}}},
           "rua": {"totals": {"messages": 1000, "domains": ["corp.example", "m.corp.example"]},
                   "policy_check": {"seen": [{"domain": "corp.example", "p": "quarantine"},
                                             {"domain": "m.corp.example", "p": "none"}]},
                   "by_header_from": [{"domain": "corp.example", "count": 800, "pass": 800, "fail": 0},
                                      {"domain": "m.corp.example", "count": 200, "pass": 200, "fail": 0}],
                   "failing_streams": [], "spf_only_senders": []}}
    rep.update(over)
    return rep


def subs_rows(p):
    return [c for c in p["changes"] if c["domain"] == "m.corp.example"]


def test_k1_a_policy_an_aggregate_report_saw_never_counts_as_a_record():
    # no lookup at all (plan.py on audit.py's report, or an older collect report): proposed with the lookup first
    p = plan_mod.build_plan(apex(), rua=REPORTS)
    m = row(p, "_dmarc.m.corp.example")
    assert m["current"] == "not checked (not an audited domain)" and m["prerequisites"] == [LOOK_FIRST % "m.corp.example"]
    assert p["holds"][0]["reason"].startswith("subdomains that send have no record of their own: m.corp.example (not "
                                              "checked) - ")
    # DNS shows none at its own name: proposed outright, and the hold names it plainly
    absent = {"m.corp.example": {"dmarc": None, "status": "absent", "source": None, "path": "doh"}}
    p = plan_mod.build_plan(apex(dns_extra=absent), rua=REPORTS)
    assert (row(p, "_dmarc.m.corp.example")["current"], row(p, "_dmarc.m.corp.example")["prerequisites"]) == ("none", [])
    assert p["holds"] == [{"domain": "corp.example", "reason": "subdomains that send have no record of their own: "
                           "m.corp.example - publish their monitoring records (above) before sp= moves to quarantine"}]
    # DNS shows its own record: no row, no hold, and the sp= step reads ready on that
    found = {"m.corp.example": {"dmarc": E_OWN, "status": "found", "source": "_dmarc.m.corp.example"}}
    p = plan_mod.build_plan(apex(dns_extra=found), rua=REPORTS)
    assert not subs_rows(p) and not p["holds"]
    sp = next(c for c in p["changes"] if c["priority"] == 4)
    assert sp["prerequisites"][0] == ("every subdomain that sends has its own _dmarc record (this run saw none sending "
                                      "without one)")
    # a record found somewhere else (the apex's, say) is not one of its own; damaged answers are no lookup at all
    for extra in ({"m.corp.example": dict(found["m.corp.example"], source="_dmarc.corp.example")},
                  {"m.corp.example": {"status": "maybe"}}, {"m.corp.example": "found"}, ["m.corp.example"], "x"):
        p = plan_mod.build_plan(apex(dns_extra=extra), rua=REPORTS)
        assert row(p, "_dmarc.m.corp.example")["prerequisites"] == [LOOK_FIRST % "m.corp.example"], extra
    # an audited subdomain: its own DNS decides, whatever a dns_extra entry says (today's behaviour)
    rep = apex(dns_extra=absent)
    rep["inputs"]["domains"].append("m.corp.example")
    rep["dns"]["m.corp.example"] = dict(rep["dns"]["corp.example"], domain="m.corp.example", dmarc=E_OWN,
                                        dmarc_source="_dmarc.m.corp.example", effective_policy="none")
    p = plan_mod.build_plan(rep, rua=REPORTS)
    assert not [c for c in subs_rows(p) if c["kind"] == "new"] and not p["holds"]


def test_k1_odd_lookups_in_a_report_never_raise():
    for value in (None, "x", 3, [1], {"m.corp.example": None}, {5: {"status": "found"}},
                  {"m.corp.example": {"status": "error"}}, {"M.Corp.Example.": {"status": "absent"}}):
        rep = apex(dns_extra=value)
        p = plan_mod.build_plan(rep, rua=REPORTS)
        assert row(p, "_dmarc.m.corp.example")["kind"] == "new", value
        assert verify.render(rep, p).startswith("# Verify it yourself"), value
    # a name written in another case, or with a trailing dot, is the same name
    assert row(p, "_dmarc.m.corp.example")["current"] == "none"


def test_k1_the_busiest_are_looked_up_first_and_a_lookup_never_stops_the_run(monkeypatch):
    rep = apex()
    rep["rua"]["by_header_from"] += [{"domain": "%s.corp.example" % x, "count": n, "pass": n, "fail": 0}
                                     for x, n in (("a", 5), ("b", 700), ("c", 70))]
    rep["mailflow"]["unaudited"] = {"d.corp.example": {"messages": 90, "outbound": 90, "inbound": 0, "last_seen": None}}
    rep["rua"]["by_header_from"].append({"domain": "elsewhere.example", "count": 999, "pass": 999, "fail": 0})
    assert plan_mod.unaudited_senders(rep) == [("b.corp.example", 700), ("m.corp.example", 200),
                                               ("d.corp.example", 90), ("c.corp.example", 70), ("a.corp.example", 5)]
    asked = []

    def resolve_ex(resolver, name, rtype):
        asked.append(name)
        if name == "_dmarc.m.corp.example":
            raise RuntimeError("resolver blew up")
        if name == "_dmarc.b.corp.example":
            return ["v=spf1 -all", "v=DMARC1; p=none;", "v=DMARC1; p=reject;"], {"path": "doh", "status": "found"}
        return [], {"path": "port53-tcp", "status": "absent", "xchk": "doh:absent"}
    monkeypatch.setattr(dns_audit, "resolve_ex", resolve_ex)
    extra, notes = collect.lookup_unaudited(rep, {}, None, cap=3)
    assert asked == ["_dmarc.b.corp.example", "_dmarc.m.corp.example", "_dmarc.d.corp.example"]
    assert extra == {"b.corp.example": {"dmarc": "v=DMARC1; p=none;", "status": "found",
                                        "source": "_dmarc.b.corp.example", "path": "doh"},
                     "m.corp.example": {"dmarc": None, "status": "error", "source": None, "path": None,
                                        "err": "RuntimeError"},
                     "d.corp.example": {"dmarc": None, "status": "absent", "source": None, "path": "port53-tcp"}}
    assert notes == ["DNS: _dmarc looked up for 3 unaudited sending subdomains: b.corp.example has a record of its own; "
                     "d.corp.example has none; the lookup failed for m.corp.example, so the plan asks for a lookup first",
                     "DNS: 2 more unaudited sending subdomains not looked up (at most 3 a run, the busiest first): "
                     "c.corp.example and a.corp.example - the plan asks for a lookup first for each"]
    assert collect.lookup_unaudited(apex(maillog=None, rua=None), {}, None) == ({}, [])  # nobody sends: no lookup


def test_k1_an_offline_run_looks_nothing_up(monkeypatch, tmp_path):
    dns = Resolver()
    monkeypatch.setattr(dns_audit, "resolve_ex", dns.resolve_ex)
    monkeypatch.setattr(sys, "argv", ["collect.py", "example.com", "--offline", "--no-config", "--no-owners",
                                      "--no-notify", "--rua", str(ROOT / "samples" / "rua"), "--maillog",
                                      str(ROOT / "samples" / "sample_maillog.csv"), "--auth-column", "DMARC",
                                      "--out", str(tmp_path / "out")])
    try:
        collect.main()
    except SystemExit:
        pass
    rep = json.loads((tmp_path / "out" / "latest" / "report.json").read_text(encoding="utf-8"))
    assert "dns_extra" not in rep and dns.asked == []


F7 = {"id": "DMARC-007", "severity": "minor", "area": "dmarc", "verified": False,
      "title": "_dmarc.mkt.corp.example lookup failed - inheritance from _dmarc.corp.example assumed, not verified",
      "evidence": "own lookup errored, _dmarc.corp.example answered", "action": "re-check _dmarc.mkt.corp.example by "
                                                                                "another path"}


def blind_sub(**over):
    """corp.example and its audited subdomain mkt.corp.example, whose own _dmarc lookup failed while the apex's
    answered (DMARC-007): the audit assumed it inherits sp=none. Both send, measured; over: mkt's DNS fields."""
    rep = apex(inputs={"domains": ["corp.example", "mkt.corp.example"]},
               rua={"totals": {"messages": 800, "domains": ["corp.example"]}, "policy_check": {"seen": []},
                    "by_header_from": [{"domain": "corp.example", "count": 800, "pass": 800, "fail": 0}],
                    "failing_streams": [], "spf_only_senders": []})
    doc = dict(rep["dns"]["corp.example"], domain="mkt.corp.example", inherited=True, effective_policy="none",
               findings=[F7])
    doc.update(over)
    rep["dns"]["mkt.corp.example"] = doc
    rep["mailflow"]["domains"]["mkt.corp.example"] = {"messages": 60, "outbound": 60, "inbound": 0, "last_seen": None}
    rep["findings"] = [dict(F7, source="dns:mkt.corp.example")]
    return rep


def test_k1_an_audited_name_whose_own_lookup_failed_is_not_checked_either():
    # DMARC-007: the apex's record answered, the subdomain's own lookup did not - a record of its own may be there,
    # so the monitoring record waits on a lookup, exactly as for an unaudited name whose lookup failed
    rep = blind_sub()
    p = plan_mod.build_plan(rep, rua=REPORTS)
    m = row(p, "_dmarc.mkt.corp.example")
    assert (m["kind"], m["priority"], m["current"]) == ("new", 1, "not checked (its lookup failed in this run)")
    assert m["prerequisites"] == [LOOK_FIRST % "mkt.corp.example"] and "DMARC-007" in m["finding_ids"]
    assert m["why"].startswith("subdomain whose own _dmarc lookup failed in this run (DMARC-007): if it has no record "
                               "of its own, it inherits policy none from _dmarc.corp.example")
    assert m["human_summary"].startswith("Publish a monitoring-only DMARC record for mkt.corp.example once a lookup "
                                         "shows it has none of its own")
    assert p["holds"] == [{"domain": "corp.example", "reason": "subdomains that send have no record of their own: "
                           "mkt.corp.example (not checked) - publish their monitoring records (above) before sp= moves "
                           "to quarantine; a name marked not checked may have a record already: look it up first"}]
    # verify.md: the Before step says the run's own lookup failed, and not to publish when a record answers
    blk = row_block(verify.render(rep, p), m["id"])
    assert ("Before: look up _dmarc.mkt.corp.example: no answer should start with v=DMARC1 - the run's own lookup of "
            "it failed (plan.json says: not checked (its lookup failed in this run)); if one does, do not publish: "
            "mkt.corp.example already has a record of its own") in blk
    assert "https://dns.google/resolve?name=_dmarc.mkt.corp.example&type=TXT" in blk
    # the status document asks for the lookup with the approval, and its per-domain row says so too
    doc = next_steps.build(rep, p)
    assert ("approval to publish the 1 zero-risk record (plan %s) in the next DNS change window, of which 1 needs a "
            "lookup of the name's own _dmarc record first (publish only if it has none)" % m["id"]) in doc["ask"]
    assert [g["next_step"] for g in doc["per_domain"] if g["domains"] == ["mkt.corp.example"]] == [
        "publish a p=none monitoring record (once a lookup shows it has no record of its own)"]
    # a quiet one, a parked one: the same lookup comes first
    for over, kind in (({}, "no_mail"), ({"mx": [], "mx_status": "absent", "spf": None, "spf_status": "absent",
                                           "dkim_selectors": [], "dkim_status": "absent"}, "park")):
        rep = blind_sub(**over)
        rep["mailflow"]["domains"]["mkt.corp.example"] = {"messages": 0, "outbound": 0, "inbound": 0, "last_seen": None}
        c = row(plan_mod.build_plan(rep, rua=REPORTS), "_dmarc.mkt.corp.example")
        assert (c["kind"], c["current"], c["prerequisites"][0]) == (
            kind, "not checked (its lookup failed in this run)", LOOK_FIRST % "mkt.corp.example"), kind
    # not measured either: the hold says both
    rep = blind_sub()
    del rep["mailflow"]["domains"]["mkt.corp.example"]
    assert "mkt.corp.example (not measured, not checked)" in plan_mod.build_plan(rep, rua=REPORTS)["holds"][0]["reason"]
    # its own lookup answered (no DMARC-007): today's behaviour, a plain record with current none
    rep = blind_sub(findings=[])
    m = row(plan_mod.build_plan(rep, rua=REPORTS), "_dmarc.mkt.corp.example")
    assert (m["current"], m["prerequisites"]) == ("none", [])


# ------------------------------------------------------------------ K2: the toolkit's address in every rua

OUTSIDE = ('the external-destination record exists: receivers send %s\'s aggregate data to dmarc-reports@corp.example '
           'only when corp.example publishes %s._report._dmarc.corp.example TXT "v=DMARC1" (or a wildcard '
           '*._report._dmarc.corp.example); without it they drop the new address')
THIRD = ("decide the order of the rua addresses: receivers need send to the first two only (RFC 7489 6.2) and the "
         "record already lists %d, so dmarc-reports@corp.example, appended after them, may get no data from some "
         "receivers - list it among the first two (drop or move another), or accept partial data")
WEEK = "one change to _dmarc.%s a week: this row and the other row%s for it (%s) each rewrite today's record"


def test_k2_a_record_that_reports_elsewhere_gets_the_report_address_appended(monkeypatch, tmp_path):
    files, _, _ = live_run(monkeypatch, tmp_path)
    plan, todo, ver = files["plan.json"], files["todo.md"], files["verify.md"]
    # the run's report address is the mailbox the reports are read from: new records carry it, and so must rua
    assert plan["report_address"] == REPORTS and plan["rua"] == REPORTS
    # brand.example: nothing else rewrites its record this run, so the append is a zero-risk row of its own
    b = row(plan, "_dmarc.brand.example")
    assert (b["kind"], b["priority"], b["current"]) == ("modify", 1, BRAND)
    assert b["value"] == ("v=DMARC1; p=reject; rua=mailto:dmarc@vendor.example,mailto:dmarc@brand.example,%s; fo=1"
                          % REPORTS)  # the addresses already there first, every other tag as it was
    assert b["rollback"] == "publish the current string verbatim"
    # two addresses there already, and receivers need send to two only: the row says so, then names the record
    # corp.example publishes before receivers send brand.example's data to its mailbox
    assert b["prerequisites"] == [THIRD % 2, OUTSIDE % ("brand.example", "brand.example")]
    assert b["human_summary"] == ("Add the toolkit's report address to the brand.example DMARC record, after the "
                                  "addresses it already reports to, so its aggregate reports start reaching the "
                                  "toolkit's archive - from every receiver only once it is among the record's first "
                                  "two addresses (see the check listed with it); no effect on delivery.")
    # shop.example reports to a vendor and its own mailbox only, so the gate lacks the evidence for its first
    # enforcement step: the append that starts that evidence never rides on the gated step. It is a zero-risk row
    # of its own, and the gated step, which rewrites the same record from today's value, waits a week for it
    assert files["report.json"]["gate"]["domains"]["shop.example"]["verdict"] == "insufficient_data"
    a, s = row(plan, "_dmarc.shop.example", "modify"), row(plan, "_dmarc.shop.example", "ratchet")
    assert (a["priority"], a["current"], s["priority"], s["current"]) == (1, SHOP, 3, SHOP)
    assert a["value"] == ("v=DMARC1; p=none; rua=mailto:dmarc@vendor.example,mailto:postmaster@shop.example,%s;"
                          % REPORTS)
    assert s["value"] == ("v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@vendor.example,"
                          "mailto:postmaster@shop.example;")
    assert a["prerequisites"][:2] == [THIRD % 2, OUTSIDE % ("shop.example", "shop.example")]
    assert a["prerequisites"][2].startswith(WEEK % ("shop.example", "", s["id"]))
    assert s["prerequisites"][-1].startswith(WEEK % ("shop.example", "", a["id"]))
    assert "the same change adds" not in s["why"] and not any("external-destination" in t for t in s["prerequisites"])
    # corp.example reports to the mailbox already: nothing to add
    assert not [c for c in plan["changes"] if c["hostname"] == "_dmarc.corp.example" and c["kind"] == "modify"]
    now = todo.split("## 2. Do now", 1)[1].split("## 3.", 1)[0]
    for c in (b, a):
        assert ("- %s %s: TXT at `%s` = `%s` (current: `%s`) - the run's report address is missing from the "
                "record's rua: " % (c["id"], c["domain"], c["hostname"], c["value"], c["current"])) in now
    assert "  - before applying: " + THIRD % 2 in now
    assert "  - before applying: " + OUTSIDE % ("brand.example", "brand.example") in now
    gated = todo.split("## 5. Gated", 1)[1].split("\n## ", 1)[0]
    assert "- %s shop.example (enforcement step, gated): `_dmarc.shop.example` = `%s`" % (s["id"], s["value"]) in gated
    # plan.md's advice on priority 1 says such a check comes first
    assert ("a row that lists a check before applying (a lookup first, an external-destination record, the order of "
            "the rua addresses) waits on it") in files["plan.md"]
    # verify.md: before, publish, after, roll back, and the lookup of the record the receivers check
    blk = row_block(ver, b["id"])
    assert "1. DNS: Before: look up _dmarc.brand.example: the answer starting with v=DMARC1 reads '%s'" % BRAND in blk
    assert "2. Portal: Publish at Route53 (zone brand.example): a TXT record named _dmarc.brand.example" in blk
    assert "4. Portal: Roll back: publish the current string verbatim" in blk
    assert ("Look up brand.example._report._dmarc.corp.example: an answer starting with v=DMARC1 - published at that "
            "name, or by a wildcard *._report._dmarc.corp.example - means receivers send the record's aggregate data to "
            "the new address; no answer means they drop it") in blk
    assert "Resolve-DnsName -Name brand.example._report._dmarc.corp.example -Type TXT -Server 8.8.8.8" in blk
    assert "https://dns.google/resolve?name=brand.example._report._dmarc.corp.example&type=TXT" in blk
    assert "Look up shop.example._report._dmarc.corp.example" in row_block(ver, a["id"])
    assert "_report._dmarc" not in row_block(ver, s["id"])


def test_k1_k2_next_steps_names_the_append_and_the_lookups_still_owed(monkeypatch, tmp_path):
    files, _, _ = live_run(monkeypatch, tmp_path)
    plan, doc = files["plan.json"], files["next_steps.md"]
    b, a = row(plan, "_dmarc.brand.example"), row(plan, "_dmarc.shop.example", "modify")
    s = row(plan, "_dmarc.shop.example", "ratchet")
    q, f = row(plan, "_dmarc.q.corp.example"), row(plan, "_dmarc.s.corp.example")
    p1 = [c["id"] for c in plan["changes"] if c["priority"] == 1]
    # the per-domain table: a record that reports already gets the toolkit's address, not "rua reporting"
    assert "| `brand.example` | p=reject | ready | add the toolkit's report address to rua (plan %s) |" % b["id"] in doc
    assert ("| `shop.example` | p=none | needs more data | add the toolkit's report address to rua or move to "
            "p=quarantine at pct=25, one a week (plan %s, %s) |" % (a["id"], s["id"])) in doc
    assert "add rua reporting" not in doc
    # the zero-risk records, one item per organization (round 12: an organization's line holds its own records):
    # the two whose own record nobody saw wait on a lookup, and corp.example's item says so
    corp = [c["id"] for c in plan["changes"] if c["priority"] == 1 and c["domain"].endswith("corp.example")]
    assert ("- **%d zero-risk monitoring records for corp.example** ready to publish, of which 2 (%s, %s) need a lookup "
            "first: the name may have a record of its own already (plan %s to %s)"
            % (len(corp), q["id"], f["id"], corp[0], corp[-1]) in doc)
    assert ("- **1 zero-risk monitoring record for brand.example** ready to publish (plan %s)" % b["id"] in doc
            and "- **1 zero-risk monitoring record for shop.example** ready to publish (plan %s)" % a["id"] in doc)
    assert len(corp) + 2 == len(p1)
    assert ("approval to publish the %d zero-risk records (plan %s to %s) in the next DNS change window, of which 2 "
            "need a lookup of the name's own _dmarc record first (publish only if it has none)"
            % (len(p1), p1[0], p1[-1])) in doc


def own(domain, record, **over):
    doc = {"domain": domain, "spf": M365, "spf_status": "found", "spf_terminator": "-all", "spf_lookups": 1,
           "dmarc": record, "dmarc_source": "_dmarc." + domain, "effective_policy": plan_mod.dmarc_tags(record)["p"],
           "inherited": False, "dmarc_status": "found", "dkim_selectors": ["selector1"], "dkim_status": "found",
           "mx": [], "mx_null": False, "mx_status": "absent", "findings": [], "evidence": []}
    doc.update(over)
    return doc


def none_yet(domain, **over):
    """An audited domain with no DMARC record at all (DMARC-001); over: more DNS fields."""
    doc = own(domain, "v=DMARC1; p=none;", dmarc=None, dmarc_source=None, effective_policy=None,
              dmarc_status="absent", findings=[{"id": "DMARC-001"}])
    doc.update(over)
    return doc


def plan_for(docs, address=REPORTS, **over):
    """The plan for these audited DNS documents, the run's report address given (or None); over: report keys."""
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": sorted(docs)}, "gate": {"domains": {}},
           "dns": docs, "maillog": None, "rua": None,
           "mailflow": {"days": 30, "domains": {d: {"messages": 50, "outbound": 40, "inbound": 10, "last_seen": None}
                                                for d in docs}}}
    rep.update(over)
    return plan_mod.build_plan(rep, rua=address)


def test_k2_the_append_changes_nothing_else_and_comes_once_per_record():
    assert plan_mod.add_rua("v=DMARC1;p=reject;rua=mailto:a@x.example ; ruf=mailto:f@x.example", REPORTS) == (
        "v=DMARC1;p=reject;rua=mailto:a@x.example,%s ; ruf=mailto:f@x.example" % REPORTS)
    assert plan_mod.add_rua("v=DMARC1; p=none; rua=", REPORTS) == "v=DMARC1; p=none; rua=" + REPORTS
    assert plan_mod.add_rua("v=DMARC1; p=none; RUA=mailto:a@x.example,", REPORTS) == (
        "v=DMARC1; p=none; RUA=mailto:a@x.example," + REPORTS)
    assert plan_mod.report_uri(MAILBOX) == plan_mod.report_uri("MAILTO:" + MAILBOX) == REPORTS
    assert plan_mod.report_uri("not an address") is None and plan_mod.report_uri(None) is None
    # already there, in any case, with a size limit: nothing to add
    for rua in ("mailto:DMARC-Reports@Corp.Example!10m", "mailto:a@x.example, %s" % REPORTS):
        p = plan_for({"x.example": own("x.example", "v=DMARC1; p=reject; rua=%s;" % rua)})
        assert not p["changes"], rua
    # without a report address of the run's own (only the rua the records already use), nothing is appended
    rec = "v=DMARC1; p=reject; rua=mailto:a@vendor.example;"
    assert not plan_for({"x.example": own("x.example", rec)}, address=None)["changes"]
    # an address in the record's own organization needs no external-destination record
    p = plan_for({"hr.corp.example": own("hr.corp.example", rec)})
    assert [(c["kind"], c["prerequisites"]) for c in p["changes"]] == [("modify", [])]
    # the "no rua at all" row stays as it was (naming the record an address in another organization needs), and
    # two records at one name are a hold, never a rewrite
    p = plan_for({"x.example": own("x.example", "v=DMARC1; p=reject;", findings=[{"id": "DMARC-003"}])})
    assert [(c["value"], c["why"], c["prerequisites"]) for c in p["changes"]] == [
        ("v=DMARC1; p=reject; rua=%s;" % REPORTS, "the record has no rua - failures are invisible until reports flow",
         [OUTSIDE % ("x.example", "x.example")])]
    assert not plan_for({"x.example": own("x.example", rec, findings=[{"id": "DMARC-005"}])})["changes"]


def test_k2_a_gated_step_never_carries_the_append_it_waits_for():
    # quarantine at 100 with sp=none, reports to a vendor only, a subdomain sending: the move to reject waits for
    # aligned-DKIM evidence the run lacks, and the sp= step for the subdomain's record. The append that brings the
    # reports is a zero-risk row of its own; all three rewrite today's record, so each names the others: one a week
    rec = "v=DMARC1; p=quarantine; sp=none; rua=mailto:a@vendor.example;"
    p = plan_for({"x.example": own("x.example", rec)},
                 rua={"by_header_from": [{"domain": "news.x.example", "count": 9, "pass": 9, "fail": 0}]},
                 dns_extra={"news.x.example": {"status": "absent", "dmarc": None, "source": None}})
    rows = sorted((c for c in p["changes"] if c["hostname"] == "_dmarc.x.example"), key=lambda c: c["priority"])
    assert [(c["kind"], c["priority"], c["value"]) for c in rows] == [
        ("modify", 1, "v=DMARC1; p=quarantine; sp=none; rua=mailto:a@vendor.example,%s;" % REPORTS),
        ("ratchet", 3, "v=DMARC1; p=reject; sp=none; rua=mailto:a@vendor.example;"),
        ("ratchet", 4, "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:a@vendor.example;")]
    assert any(t.startswith("no aligned-DKIM evidence in this run") for t in rows[1]["prerequisites"])
    assert rows[0]["prerequisites"][0] == OUTSIDE % ("x.example", "x.example")
    for c in rows:
        others = ", ".join(o["id"] for o in rows if o is not c)
        assert any(t.startswith(WEEK % ("x.example", "s", others)) for t in c["prerequisites"]), c["id"]
        assert c is rows[0] or not any("external-destination" in t for t in c["prerequisites"]), c["id"]
    # at p=none with a rua, the first enforcement step waits for it the same way
    p = plan_for({"x.example": own("x.example", "v=DMARC1; p=none; rua=mailto:a@vendor.example;")})
    assert sorted((c["kind"], c["priority"], REPORTS in c["value"]) for c in p["changes"]) == [
        ("modify", 1, True), ("ratchet", 3, False)]


def quiet(rec):
    """quiet.example at rec, measured sending nothing; the aggregate reports that cover it count none passing."""
    return {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": ["quiet.example"]}, "gate": {"domains": {}},
            "dns": {"quiet.example": own("quiet.example", rec)}, "maillog": None,
            "mailflow": {"days": 30, "domains": {"quiet.example": {"messages": 0, "outbound": 0, "inbound": 0,
                                                                   "last_seen": None}}},
            "rua": {"totals": {"messages": 5, "domains": ["quiet.example"]},
                    "policy_check": {"seen": [{"domain": "quiet.example", "p": "none"}]},
                    "by_header_from": [{"domain": "quiet.example", "count": 5, "pass": 0, "fail": 5}],
                    "failing_streams": [], "spf_only_senders": []}}


def test_k2_a_quarantine_now_row_carries_the_address_too():
    # quarantine now rewrites the record anyway, at priority 1: it carries the address, one change to the record
    p = plan_mod.build_plan(quiet("v=DMARC1; p=none; rua=mailto:a@vendor.example;"), rua=REPORTS)
    assert [(c["kind"], c["priority"], c["value"]) for c in p["changes"]] == [
        ("no_mail", 1, "v=DMARC1; p=quarantine; sp=none; rua=mailto:a@vendor.example,%s;" % REPORTS)]
    assert p["changes"][0]["prerequisites"][-1] == OUTSIDE % ("quiet.example", "quiet.example")
    assert p["changes"][0]["human_summary"].endswith(
        " The same change adds dmarc-reports@corp.example to the record's reporting addresses, so its aggregate reports "
        "start reaching the toolkit's archive.")


def test_k2_the_address_is_never_written_twice():
    # an empty rua= that quarantine now fills with the address: once, never appended again
    for rec in ("v=DMARC1; p=none; rua=;", "v=DMARC1; p=none; rua= ;"):
        p = plan_mod.build_plan(quiet(rec), rua=REPORTS)
        assert [(c["kind"], c["value"]) for c in p["changes"]] == [
            ("no_mail", "v=DMARC1; p=quarantine; sp=none; rua=%s;" % REPORTS)], rec
        assert p["changes"][0]["prerequisites"].count(OUTSIDE % ("quiet.example", "quiet.example")) == 1
    # two rua= tags: the plan reads the last one, as dmarc_tags and the audit do, so it checks and edits that one
    two = "v=DMARC1; p=reject; rua=%s; rua=mailto:dmarc@vendor.example;" % REPORTS
    assert plan_mod.rua_addresses(two) == ["dmarc@vendor.example"]
    p = plan_for({"x.example": own("x.example", two)})
    assert [c["value"] for c in p["changes"]] == [
        "v=DMARC1; p=reject; rua=%s; rua=mailto:dmarc@vendor.example,%s;" % (REPORTS, REPORTS)]
    assert plan_mod.rua_addresses(p["changes"][0]["value"]) == ["dmarc@vendor.example", MAILBOX]
    assert not plan_for({"x.example": own("x.example", "v=DMARC1; p=reject; rua=mailto:dmarc@vendor.example; rua=%s;"
                                          % REPORTS)})["changes"]


def test_k2_a_third_address_says_receivers_may_stop_at_two():
    # one address there: the toolkit's comes second, and every receiver sends to it
    p = plan_for({"x.example": own("x.example", "v=DMARC1; p=reject; rua=mailto:a@vendor.example;")})
    assert p["changes"][0]["prerequisites"] == [OUTSIDE % ("x.example", "x.example")]
    assert "first two" not in p["changes"][0]["human_summary"]
    # two there (whatever their case or size limit): appended third, where receivers may stop (RFC 7489 6.2)
    p = plan_for({"x.example": own("x.example", "v=DMARC1; p=reject; rua=mailto:A@Vendor.example!10m, "
                                                "mailto:b@x.example;")})
    assert p["changes"][0]["prerequisites"] == [THIRD % 2, OUTSIDE % ("x.example", "x.example")]
    # folded into quarantine now, the same check comes along
    p = plan_mod.build_plan(quiet("v=DMARC1; p=none; rua=mailto:a@vendor.example,mailto:b@quiet.example,"
                                  "mailto:c@vendor.example;"), rua=REPORTS)
    c = p["changes"][0]
    assert c["kind"] == "no_mail" and THIRD % 3 in c["prerequisites"]
    assert c["human_summary"].endswith(" - from every receiver only once it is among the record's first two addresses "
                                       "(see the check listed with it).")


def test_k2_every_record_that_gains_an_outside_address_names_the_external_destination():
    # a new monitoring record that reports to corp.example's mailbox from another organization
    c = row(plan_for({"brand.example": none_yet("brand.example")}), "_dmarc.brand.example")
    assert (c["kind"], c["value"], c["prerequisites"]) == (
        "new", "v=DMARC1; p=none; rua=%s;" % REPORTS, [OUTSIDE % ("brand.example", "brand.example")])
    # a parked one: after its unused check; its SPF record carries no rua
    parked = none_yet("parked.example", spf=None, spf_status="absent", dkim_selectors=[], dkim_status="absent")
    p = plan_for({"parked.example": parked}, mailflow={"days": 30, "domains": {"parked.example": {
        "messages": 0, "outbound": 0, "inbound": 0, "last_seen": None}}})
    c = row(p, "_dmarc.parked.example")
    assert c["kind"] == "park" and c["prerequisites"][1:] == [OUTSIDE % ("parked.example", "parked.example")]
    assert row(p, "parked.example")["prerequisites"] == c["prerequisites"][:1]
    # one in the same organization, and the placeholder of a run with no address at all, need none
    assert row(plan_for({"hr.corp.example": none_yet("hr.corp.example")}), "_dmarc.hr.corp.example")[
        "prerequisites"] == []
    p = plan_for({"brand.example": none_yet("brand.example")}, address=None)
    assert p["rua_is_placeholder"] and row(p, "_dmarc.brand.example")["prerequisites"] == []
    # an unaudited sending subdomain's record, when the run's mailbox lies in another organization
    absent = {"m.corp.example": {"dmarc": None, "status": "absent", "source": None}}
    p = plan_mod.build_plan(apex(dns_extra=absent), rua="mailto:dmarc@reports.example")
    m = row(p, "_dmarc.m.corp.example")
    assert m["prerequisites"] == [plan_mod.external_destination("m.corp.example", "mailto:dmarc@reports.example")]
    assert "m.corp.example._report._dmarc.reports.example TXT" in m["prerequisites"][0]


def test_k2_a_prerequisite_kind_never_follows_the_words_in_a_name_or_an_address():
    # an address or a name holding a keyword (reports, lookups, dkim, list) once decided what proves the check
    two = "v=DMARC1; p=none; rua=mailto:a@b.example,mailto:c@d.example;"
    for addr in ("dmarc-reports@corp.example", "rua@dmarc-lookups.example", "dkim-team@corp.example",
                 "list@corp.example", "dmarc@corp.example"):
        assert plan_mod.prereq_kind(plan_mod.external_destination("brand.example", addr)) == "other", addr
        assert plan_mod.prereq_kind(plan_mod.rua_order(two, addr)) == "other", addr
    for name in ("reports.corp.example", "lookups.corp.example", "dkim.corp.example", "list.corp.example"):
        assert plan_mod.prereq_kind(plan_mod.lookup_first(name)) == "other", name
    # the sp= step names its subdomains: one called dkim.corp.example still gets its own-record lookup in verify.md,
    # never the DKIM proof
    rep = apex(dns_extra={"dkim.corp.example": {"dmarc": None, "status": "absent", "source": None}})
    rep["rua"]["by_header_from"] = [{"domain": "dkim.corp.example", "count": 200, "pass": 200, "fail": 0}]
    p = plan_mod.build_plan(rep, rua=REPORTS)
    sp = next(c for c in p["changes"] if c["priority"] == 4)
    assert sp["prerequisite_items"][0] == {"text": "every subdomain that sends has its own _dmarc record: "
                                                   "dkim.corp.example has none yet (the monitoring records above)",
                                           "kind": "other", "met": None}
    steps = verify.prerequisite_steps(sp, rep)
    assert steps[0]["text"].startswith("Look up the subdomains' own records:")
    assert "_dmarc.dkim.corp.example" in steps[0]["code"]


def test_k2_a_size_limit_or_a_list_never_silently_stops_the_append(monkeypatch, tmp_path):
    sized = REPORTS + "!10m"
    assert plan_mod.report_uri(sized) == plan_mod.report_uri(MAILBOX + "!10m") == sized
    rec = "v=DMARC1; p=reject; rua=mailto:a@vendor.example;"
    p = plan_for({"x.example": own("x.example", rec)}, address=sized)
    assert p["report_address"] == sized
    assert [(c["value"], c["prerequisites"]) for c in p["changes"]] == [
        ("v=DMARC1; p=reject; rua=mailto:a@vendor.example,%s;" % sized, [OUTSIDE % ("x.example", "x.example")])]
    assert not plan_for({"x.example": own("x.example", "v=DMARC1; p=reject; rua=%s;" % REPORTS)},
                        address=sized)["changes"]
    # given without mailto:, it is one address all the same, and new records carry it as a URI
    p = plan_for({"hr.corp.example": none_yet("hr.corp.example")}, address=MAILBOX)
    assert p["rua"] == REPORTS and row(p, "_dmarc.hr.corp.example")["value"] == "v=DMARC1; p=none; rua=%s;" % REPORTS
    # a list: new records carry it as given, nothing is appended, and the run says why
    both = "mailto:dmarc@vendor.example,%s" % REPORTS
    note = ("the report address %s is not one mailto: address: new records carry it as given, and no record gets it "
            "appended to its rua (give one address to have it appended)" % both)
    assert plan_mod.report_uri(both) is None and plan_mod.address_note(both) == note
    assert plan_mod.address_note(REPORTS) is None and plan_mod.address_note(sized) is None
    p = plan_for({"x.example": own("x.example", rec), "hr.corp.example": none_yet("hr.corp.example")}, address=both)
    assert p["report_address"] is None and [c["kind"] for c in p["changes"]] == ["new"]
    files, _, _ = live_run(monkeypatch, tmp_path, extra=("--rua-address", both))
    assert "plan: " + note in files["run.json"]["notes"]
    assert not [c for c in files["plan.json"]["changes"] if c["kind"] == "modify"]
    # audit.py's --rua-address says it is appended too
    out = subprocess.run([sys.executable, str(ROOT / "src" / "audit.py"), "--help"], capture_output=True, text=True)
    assert "appends it to a record's rua that lacks it" in " ".join(out.stdout.split())


# ------------------------------------------------------------------ K3: SPF-007 is an include that did not resolve

SPF7 = ("an SPF include could not be resolved, so the lookup count is a lower bound: look the include up through two "
        "resolvers (verify.md) or re-run; fix or remove it only if it fails there too, and add no sender until it "
        "resolves")


def test_k3_the_spf_007_hold_names_the_unresolved_include_and_the_safe_rows_stay():
    ids = ("SPF-007", "SPF-003")
    doc = own("n.example", "v=DMARC1; p=reject; rua=%s;" % REPORTS, spf="v=spf1 include:gone.invalid ?all",
              spf_terminator="?all", findings=[{"id": i} for i in ids])
    p = plan_for({"n.example": doc})
    # no resolver path answered for the include in this run, which may be the run's own failing: it is looked up
    # again before anyone removes it, and no sender is added until it resolves
    assert p["holds"] == [{"domain": "n.example", "reason": SPF7}]
    assert "more than one SPF record" not in json.dumps(p)
    # the terminator fix adds no sender: it is still proposed beside the hold
    assert [(c["kind"], c["value"]) for c in p["changes"]] == [("modify", "v=spf1 include:gone.invalid ~all")]
    # verify.md points the hold at SPF-007's own check, which looks the include up through two resolvers
    f = {"id": "SPF-007", "severity": "major", "area": "spf", "source": "dns:n.example", "verified": False,
         "title": "SPF lookup count incomplete - 1 include(s) could not be resolved, 1 is a lower bound",
         "evidence": "gone.invalid: LOOKUP FAILED - could not verify (doh NXDOMAIN)", "action": "re-run"}
    md = verify.render({"dns": {"n.example": dict(doc, findings=[f])}, "findings": [f]}, p)
    held = next(l for l in md.splitlines() if l.startswith("- Held, not proposed: an SPF include could not be resolved"))
    assert held == "- Held, not proposed: %s - check: SPF-007 (Findings above)" % SPF7
    assert "Look up each include that failed through two resolvers" in section(md, "n.example")


# ------------------------------------------------------------------ K4: the override query counts like the report

def test_k4_the_override_query_counts_what_dedupe_and_maillog_totals_count():
    raw = (ROOT / "queries" / "delivered_despite_failure.kql").read_bytes()
    assert raw.count(b"\r\n") in (0, raw.count(b"\n")) and raw.isascii()  # one line ending throughout, as checked out
    kql = raw.decode("ascii").replace("\r\n", "\n")
    code = "\n".join(l.split("//", 1)[0] for l in kql.splitlines() if not l.startswith("//"))
    # all four override columns through column_ifexists, UserLevelPolicy included; none read directly
    for col in ("OrgLevelAction", "OrgLevelPolicy", "UserLevelAction", "UserLevelPolicy"):
        assert code.count('column_ifexists("%s", "")' % col) == 1, col
        assert len(re.findall(r"\b%s\b" % col, code)) == 1, col
    # the reached-mailbox rule is maillog_totals.kql's, word for word, and the grain is (Message-ID, recipient)
    totals = (ROOT / "queries" / "maillog_totals.kql").read_text(encoding="utf-8").replace("\r\n", "\n")

    def rule(text):
        loc = re.search(r"\| extend loc = [^\n/]*", text).group(0).strip()
        return loc, re.search(r"\| extend on_mailbox = [^\n]*\n[^\n]*\n", text).group(0)
    assert rule(totals) == rule(kql)
    assert "DeliveredToDeletedFolder" in rule(kql)[1]
    assert "delivered = max(iff(on_mailbox, 1, 0))" in code and "on_delivered" not in code
    assert re.search(r"by InternetMessageId, rcpt\n\| where anyfail > 0 and anypass == 0 and delivered == 1", code)
    # the documented columns stay, user_policy beside them, and the header says how it counts
    assert code.rstrip().endswith("by env, org_action, org_policy, user_action, user_policy, compauth\n"
                                  "| order by msgs desc")
    for name in ("msgs = count()", "senders = dcount(addr)", "recipients = dcount(rcpt)", "sample_sender = any(addr)"):
        assert name in code
    head = kql.split('let sender_domain', 1)[0]
    for said in ("user_policy = UserLevelPolicy", "column_ifexists", "msgs adds up to", "Message-ID,",
                 "DeliveredToDeletedFolder, to the inbox, junk or deleted items"):
        assert said in head, said
    assert kql.count('let sender_domain = "example.com";') == 1  # the one line collect.py and verify.py fill in
    # verify.md no longer says its count runs higher than the report's
    assert "a little above" not in (ROOT / "src" / "verify.py").read_text(encoding="utf-8")


def test_plain_ascii():
    for p in ("src/plan.py", "src/collect.py", "src/verify.py", "src/next_steps.py", "src/audit.py",
              "tests/test_r10_known.py", "tests/test_r10_phase2.py", "tests/test_r10_requests.py", "AGENTS.md",
              "README.md", "audit.example.toml", "docs/methodology.md", "docs/templates/next-steps.md"):
        assert (ROOT / p).read_text(encoding="utf-8").isascii(), p
