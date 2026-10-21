"""Round 10, workstream 4: "verify it yourself" for every finding and every
plan row. verify.md says, per domain and for the run as a whole, the
read-only check a person runs to see each number and each record for
themselves - the DNS lookup, the Advanced Hunting query (a shipped query
with only its sender_domain line set), the recount, the admin page and
cmdlet - with the value the report or the plan expects. Synthetic data,
offline: live DNS is stubbed at audit.run_dns, nothing touches a network."""

import csv
import json
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import audit
import collect
import discover
import next_steps
import plan as plan_mod
import verify

ROOT = Path(__file__).resolve().parent.parent
QUERIES = ROOT / "queries"
SCRIPT = str(ROOT / "src" / "verify.py")
HOWS = {"dns", "kql", "command", "portal"}
NOW = datetime.now(timezone.utc).replace(microsecond=0)
RUA = "mailto:reports@corp.example"


# ------------------------------------------------------------------ a synthetic run with every family

def finding(fid, severity, area, title, evidence, action="act", verified=True):
    return {"id": fid, "severity": severity, "area": area, "title": title, "evidence": evidence, "action": action,
            "verified": verified}


def dns_doc(domain, findings=(), **over):
    """A live-DNS answer in dns_audit's shape; by default a domain with nothing published."""
    doc = {"domain": domain, "spf": None, "spf_status": "absent", "spf_terminator": None, "spf_lookups": 0,
           "spf_lookups_failed": 0, "dmarc": None, "dmarc_source": None, "effective_policy": None, "inherited": False,
           "dmarc_status": "absent", "dkim_selectors": [], "dkim_status": "absent", "dkim_probed": ["selector1"],
           "dkim_dangling": [], "dkim_wildcard": False, "mx": [], "mx_null": False, "mx_status": "absent",
           "findings": list(findings), "evidence": []}
    doc.update(over)
    return doc


CORP_DMARC = "v=DMARC1; p=none; rua=mailto:reports@corp.example;"
CORP_SPF = "v=spf1 include:spf.esp.example ?all"
SHOP_DMARC = "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:reports@corp.example;"
SHOP_SPF = "v=spf1 include:a.example include:b.example ~all"


def live_dns(domains, resolver, selectors=()):
    """dns_audit's answers for the five synthetic domains, findings worded as dns_audit words them."""
    docs = {
        "corp.example": dns_doc("corp.example", [
            finding("SPF-003", "major", "spf", "SPF terminator is '?all' - effectively no protection", CORP_SPF),
            finding("DMARC-002", "minor", "dmarc", "DMARC p=none - monitoring only", CORP_DMARC),
            finding("DKIM-002", "minor", "dkim", "no common DKIM selector found - domain may authenticate on SPF alone, "
                    "which breaks on forwarding", "probed: selector1, selector2, google, s1, s2, k1, k2, everlytickey1, "
                    "dkim", verified=False)],
            dmarc=CORP_DMARC, dmarc_source="_dmarc.corp.example", effective_policy="none", dmarc_status="found",
            spf=CORP_SPF, spf_status="found", spf_terminator="?all", spf_lookups=3, mx=["10 mx1.corp.example"],
            mx_status="found", dkim_probed=["selector1", "selector2", "google", "s1", "s2", "k1", "k2", "everlytickey1",
                                            "dkim"],
            evidence=[{"name": "_dmarc.corp.example", "type": "TXT", "path": "port53-udp", "ttl": 1800,
                       "status": "found"}]),
        "hr.corp.example": dns_doc("hr.corp.example", [
            finding("SPF-001", "major", "spf", "no SPF record", "no v=spf1 TXT at hr.corp.example"),
            finding("DMARC-002", "minor", "dmarc", "DMARC effective policy none - inherited (p=none on "
                    "_dmarc.corp.example, no sp=) - monitoring only", CORP_DMARC)],
            dmarc=CORP_DMARC, dmarc_source="_dmarc.corp.example", effective_policy="none", inherited=True,
            dmarc_status="found", mx=["10 mx1.corp.example"], mx_status="found"),
        "dup.example": dns_doc("dup.example", [
            finding("DMARC-005", "major", "dmarc", "multiple DMARC records at _dmarc.dup.example - receivers treat "
                    "this as no policy", "2 v=DMARC1 TXT records")],
            dmarc="v=DMARC1; p=none; rua=mailto:a@dup.example;", dmarc_source="_dmarc.dup.example",
            effective_policy="none", dmarc_status="found", spf="v=spf1 -all", spf_status="found",
            spf_terminator="-all", mx=["0 ."], mx_null=True, mx_status="found"),
        "parked.example": dns_doc("parked.example", [
            finding("DMARC-001", "major", "dmarc", "NO DMARC RECORD - no policy, no reporting, invisible to you",
                    "no v=DMARC1 TXT at any of: _dmarc.parked.example"),
            finding("SPF-001", "major", "spf", "no SPF record", "no v=spf1 TXT at parked.example")]),
        "shop.example": dns_doc("shop.example", [
            finding("SPF-005", "major", "spf", "SPF at the 10-lookup limit - no room for another vendor",
                    "10 DNS-querying mechanisms after expanding includes")],
            dmarc=SHOP_DMARC, dmarc_source="_dmarc.shop.example", effective_policy="quarantine", dmarc_status="found",
            spf=SHOP_SPF, spf_status="found", spf_terminator="~all", spf_lookups=10, dkim_selectors=["selector1"],
            dkim_status="found", mx=["10 mx.shop.example"], mx_status="found"),
    }
    return {d: docs[d] for d in domains}


LOG_COLS = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
            "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC", "SPF", "DKIM", "Direction",
            "Org level action", "Org level policy", "User level action", "User level policy"]


def maillog(path):
    """30 days of mail: corp.example's own staff mail passing, a vendor failing and delivered through a transport
    rule, a spoof campaign, an SPF-only newsletter; news.corp.example (unaudited) failing; hr.corp.example and
    shop.example passing."""
    rows, n = [], [0]

    def add(sender, env, subject, dmarc, where=("Delivered", "Inbox/folder"), times=1, spf="pass", dkim="pass",
            org=("", ""), hours=0):
        for k in range(times):
            n[0] += 1
            at = NOW - timedelta(hours=hours + k * 7 % 700 + 1)
            rows.append({"Timestamp": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "Internet message ID": "<v%04d@mail.invalid>" % n[0], "Sender address": sender,
                         "Sender domain": sender.rpartition("@")[2], "Sender mail from domain": env,
                         "Recipients": "user%d@corp.example" % (n[0] % 4), "Subject": subject,
                         "Delivery action": where[0], "Latest delivery location": where[1], "DMARC": dmarc,
                         "SPF": spf, "DKIM": dkim, "Direction": "Inbound", "Org level action": org[1],
                         "Org level policy": org[0], "User level action": "", "User level policy": ""})
    add("staff@corp.example", "corp.example", "Weekly report", "pass", times=30)
    add("billing@corp.example", "billing.vendor.example", "Statement", "fail", times=4, spf="fail", dkim="fail",
        org=("Exchange transport rule", "Allow"))
    add("ceo@corp.example", "mta.attacker.invalid", "Urgent wire transfer", "fail", ("Blocked", "Quarantine"), times=6,
        spf="fail", dkim="fail")
    add("news@corp.example", "corp.example", "Newsletter", "pass", times=5, dkim="none")
    add("alerts@news.corp.example", "esp.example", "Alert", "fail", ("Blocked", "Quarantine"), times=3, spf="fail",
        dkim="fail")
    add("people@hr.corp.example", "hr.corp.example", "Benefits", "pass", times=4)
    add("orders@shop.example", "shop.example", "Your order", "pass", times=6)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LOG_COLS)
        w.writeheader()
        w.writerows(rows)
    return str(path)


def rua_xml(path, rows):
    """One aggregate report about corp.example's record: rows of (source_ip, count, header_from, dkim, spf)."""
    begin = int((NOW - timedelta(days=2)).timestamp())
    records = "".join(
        "<record><row><source_ip>%s</source_ip><count>%d</count><policy_evaluated><disposition>%s</disposition>"
        "<dkim>%s</dkim><spf>%s</spf></policy_evaluated></row><identifiers><header_from>%s</header_from>"
        "</identifiers><auth_results>%s<spf><domain>%s</domain><scope>mfrom</scope><result>%s</result></spf>"
        "</auth_results></record>" % (
            ip, count, "none" if "pass" in (dkim, spf) else "reject", dkim, spf, hf,
            "<dkim><domain>%s</domain><selector>s1</selector><result>pass</result></dkim>" % hf if dkim == "pass" else "",
            hf if spf == "pass" else "attacker.invalid", spf)
        for ip, count, hf, dkim, spf in rows)
    path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<feedback><report_metadata><org_name>reporter.example'
                    '</org_name><email>r@reporter.example</email><report_id>%s</report_id><date_range><begin>%d</begin>'
                    '<end>%d</end></date_range></report_metadata><policy_published><domain>corp.example</domain>'
                    '<adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct></policy_published>%s</feedback>\n'
                    % (path.stem, begin, begin + 86399, records), encoding="utf-8")


def exports(tmp_path):
    rules = {"tool": "audit_rules", "rules": [], "findings": [
        finding("RULES-001", "major", "rules", "Allow rule without authentication gate: Partner bypass",
                "SetSCL=-1; no dmarc=pass, compauth=pass or Authentication-Results condition; State=Enabled")]}
    bypasses = {"tool": "audit_bypasses", "findings": [
        dict(finding("RULES-106", "minor", "rules", "Spoof allow: billing@corp.example from vendor.example (External)",
                     "SpoofedUser=billing@corp.example; SendingInfrastructure=vendor.example; SpoofType=External; "
                     "Action=Allow"), object="billing@corp.example|vendor.example"),
        dict(finding("RULES-107", "major", "rules", "Connector treats external mail as internal: Legacy relay",
                     "ConnectorType=Partner; Enabled=True"), object="Legacy relay")]}
    groups = {"tool": "audit_groups", "findings": [
        dict(finding("GROUPS-003", "major", "groups", "Open to external senders and redistributes to external "
                     "members: all@corp.example", "DistributionGroup; RequireSenderAuthenticationEnabled=False; "
                     "sender restrictions=0; external members (1): partner@outside.invalid"),
             object="all@corp.example")]}
    out = {}
    for name, doc in (("rules", rules), ("bypasses", bypasses), ("groups", groups)):
        p = tmp_path / ("%s.json" % name)
        p.write_text(json.dumps(doc), encoding="utf-8")
        out[name] = str(p)
    return out


HEADER = ("From: Staff <staff@corp.example>\nTo: user@corp.example\nSubject: hello\nMessage-ID: <h1@corp.example>\n"
          "Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=none; "
          "dmarc=pass header.from=corp.example\nReturn-Path: <bounce@corp.example>\n")
NAMES = ["corp.example", "hr.corp.example", "dup.example", "parked.example", "shop.example"]


def world(tmp_path, monkeypatch):
    """(report, plan) of a run that carries every family the toolkit reports."""
    monkeypatch.setattr(audit, "run_dns", live_dns)
    rua_dir = tmp_path / "rua"
    rua_dir.mkdir()
    rua_xml(rua_dir / "r1.xml", [("203.0.113.5", 300, "corp.example", "fail", "fail"),
                                 ("198.51.100.20", 120, "corp.example", "fail", "pass"),
                                 ("192.0.2.10", 800, "corp.example", "pass", "pass"),
                                 ("2001:db8::25", 40, "corp.example", "fail", "fail")])
    (tmp_path / "msg.txt").write_text(HEADER, encoding="utf-8")
    ex = exports(tmp_path)
    flows = {"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": {
        "corp.example": {"messages": 900, "outbound": 700, "inbound": 200, "last_seen": "2026-10-07T14:02:11Z"},
        "hr.corp.example": {"messages": 4, "outbound": 4, "inbound": 0, "last_seen": None},
        "dup.example": None, "parked.example": dict(discover.MAILFLOW_NONE),
        "shop.example": {"messages": 60, "outbound": 60, "inbound": 0, "last_seen": None}}}
    cuts = {"corp.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-07T22:00:00Z"}}
    totals = {"hours": 720, "orgs": {"corp.example": {"source": collect.AGGREGATE_SOURCE, "by_domain": {
        "corp.example": {"logical_messages": 5000, "passing": 4800, "genuine_failures": 160, "delivered_despite_fail": 15,
                         "delivered_by": {"org: Exchange transport rule (Allow)": 15}},
        "news.corp.example": {"logical_messages": 40, "passing": 0, "genuine_failures": 40, "delivered_despite_fail": 0,
                              "delivered_by": {}}}}}}
    report = audit.build_report(
        domains=NAMES, domain_sources={d: ["cli"] for d in NAMES}, rua_paths=[str(rua_dir)],
        maillog=maillog(tmp_path / "log.csv"), header_files=[str(tmp_path / "msg.txt")], offline=False,
        known="192.0.2.0/24,esp.example", auth_column="DMARC", rules_json=ex["rules"], bypasses_json=ex["bypasses"],
        groups_json=ex["groups"], maillog_cuts=cuts, window_totals=totals, mailflow=flows, headline="corp.example")
    report["inputs"]["run"] = "2026-10-09T120000Z"
    inventory = {"domains": [{"domain": d, "zone": discover.org_domain(d), "zone_host": "Route53",
                              "mailflow": flows["domains"][d]} for d in NAMES]}
    plan = plan_mod.build_plan(report, inventory, RUA)
    return report, plan


@pytest.fixture
def offline(monkeypatch):
    """No network in these tests: every socket call fails loudly."""
    def refuse(*a, **k):
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def steps_of(report, fid, source=None):
    f = next(f for f in report["findings"] if f["id"] == fid and (source is None or f["source"] == source))
    return verify.finding_steps(f, report)


def texts(steps):
    return " ".join(s["text"] for s in steps)


def codes(steps):
    return "\n".join(s["code"] for s in steps)


def check_shape(steps):
    assert steps, "no steps"
    for s in steps:
        assert set(s) == {"how", "text", "code"} and s["how"] in HOWS and s["text"].strip(), s
        assert isinstance(s["code"], str)


@pytest.fixture
def run(tmp_path, monkeypatch, offline):
    report, plan = world(tmp_path, monkeypatch)
    return report, plan, tmp_path


def lookups(code, name, rtype="TXT", servers=("8.8.8.8",)):
    """True when code holds both forms of the lookup of name through each server."""
    return all(("Resolve-DnsName -Name %s -Type %s -Server %s | Where-Object { $_.Type -eq '%s' }" % (name, rtype, s, rtype)
                in code and "nslookup -type=%s %s %s" % (rtype, name, s) in code) for s in servers)


# ------------------------------------------------------------------ DNS findings

DNS_CASES = {
    "SPF-001": ("no SPF record", "no v=spf1 TXT at corp.example", [("corp.example", "TXT")]),
    "SPF-002": ("SPF lookup failed - not verified", "TXT lookup for corp.example failed on every resolver path",
                [("corp.example", "TXT", 2)]),
    "SPF-003": ("SPF terminator is '?all' - effectively no protection", CORP_SPF, [("corp.example", "TXT")]),
    "SPF-004": ("SPF over the 10-lookup limit (11) - PERMERROR", "11 DNS-querying mechanisms after expanding includes",
                [("corp.example", "TXT")]),
    "SPF-005": ("SPF at the 10-lookup limit - no room for another vendor",
                "10 DNS-querying mechanisms after expanding includes", [("corp.example", "TXT")]),
    "SPF-006": ("SPF one include away from the limit - new senders need DKIM",
                "9 DNS-querying mechanisms after expanding includes", [("corp.example", "TXT")]),
    "SPF-007": ("SPF lookup count incomplete - 1 include(s) could not be resolved, 3 is a lower bound",
                "spf.esp.example: LOOKUP FAILED (timeout)", [("spf.esp.example", "TXT", 2)]),
    "DMARC-001": ("NO DMARC RECORD - no policy, no reporting, invisible to you",
                  "no v=DMARC1 TXT at any of: _dmarc.corp.example", [("_dmarc.corp.example", "TXT")]),
    "DMARC-002": ("DMARC p=none - monitoring only", CORP_DMARC, [("_dmarc.corp.example", "TXT")]),
    "DMARC-003": ("DMARC has no rua - failures are invisible to you", "v=DMARC1; p=none;", [("_dmarc.corp.example", "TXT")]),
    "DMARC-004": ("no explicit sp= - subdomains inherit p; make sure that is intentional", "v=DMARC1; p=reject; rua=x;",
                  [("_dmarc.corp.example", "TXT")]),
    "DMARC-005": ("multiple DMARC records at _dmarc.corp.example - receivers treat this as no policy",
                  "2 v=DMARC1 TXT records", [("_dmarc.corp.example", "TXT")]),
    "DMARC-006": ("DMARC lookup failed - not verified", "TXT lookup failed on every resolver path for: _dmarc.corp.example",
                  [("_dmarc.corp.example", "TXT", 2)]),
    "DMARC-007": ("_dmarc.corp.example lookup failed - inheritance from _dmarc.example assumed, not verified",
                  "own lookup errored, _dmarc.example answered", [("_dmarc.corp.example", "TXT", 2)]),
    "DMARC-008": ("DMARC pct=25 - policy applies to a sample of failing mail only", "v=DMARC1; p=quarantine; pct=25; rua=x;",
                  [("_dmarc.corp.example", "TXT")]),
    "DKIM-001": ("wildcard at _domainkey - selector probing unreliable, verify DKIM from message headers",
                 "zz-audit-canary-zz._domainkey.corp.example resolved",
                 [("zz-audit-canary-zz._domainkey.corp.example", "TXT")]),
    "DKIM-002": ("no common DKIM selector found - domain may authenticate on SPF alone, which breaks on forwarding",
                 "probed: selector1, selector2, google", [("selector1._domainkey.corp.example", "CNAME"),
                                                          ("selector2._domainkey.corp.example", "CNAME")]),
    "DKIM-003": ("DKIM selector CNAME with no key at the target: s1", "s1._domainkey.corp.example",
                 [("s1._domainkey.corp.example", "CNAME"), ("s1._domainkey.corp.example", "TXT")]),
    "DKIM-004": ("DKIM lookup failed - not verified", "1 of 9 selector probes failed on every resolver path: k1",
                 [("k1._domainkey.corp.example", "TXT", 2)]),
}


def test_every_dns_finding_gets_both_lookups_for_its_own_names_and_what_the_audit_saw():
    report = {"dns": live_dns(["corp.example"], None)}

    def one(fid):
        title, ev, _ = DNS_CASES[fid]
        return verify.finding_steps(dict(finding(fid, "major", "dns", title, ev), source="dns:corp.example"), report)
    for fid, (_, _, names) in DNS_CASES.items():
        steps = one(fid)
        check_shape(steps)
        code = codes(steps)
        for name, rtype, *n in names:
            assert lookups(code, name, rtype, verify.RESOLVERS[:n[0] if n else 1]), (fid, name, code)
        assert "corp.example" in texts(steps) + code, fid
    # a lookup that claims something is missing, or that failed, also asks over HTTPS (port 53 interception fakes both)
    doh = "(Invoke-RestMethod -Uri 'https://dns.google/resolve?name=%s&type=TXT').Answer.data"
    for fid, name in (("SPF-001", "corp.example"), ("DMARC-001", "_dmarc.corp.example"), ("SPF-002", "corp.example"),
                      ("DMARC-006", "_dmarc.corp.example"), ("DKIM-004", "k1._domainkey.corp.example")):
        assert doh % name in codes(one(fid)), fid
    assert "dns.google" not in codes(one("DMARC-002")) + codes(one("SPF-003"))
    # what the audit saw is what the lookup should show
    assert "reads 'v=DMARC1; p=none;', with no rua= tag" in texts(one("DMARC-003"))
    assert "'v=spf1 include:spf.esp.example ?all' and ends in ?all" in texts(one("SPF-003"))
    assert "2 of the answers start with v=DMARC1" in texts(one("DMARC-005"))
    assert "with pct=25" in texts(one("DMARC-008"))
    # the lookup count comes from the toolkit's own counter, with the figure the audit counted
    s = one("SPF-004")
    assert s[0]["code"] == "python src/spf_lookups.py corp.example" and "the lookups line shows 11 / 10" in s[0]["text"]
    assert "shows 10 / 10" in one("SPF-005")[0]["text"] and "shows 9 / 10" in one("SPF-006")[0]["text"]
    # Microsoft 365 DKIM: the Defender page, the cmdlet and the two selector CNAMEs
    s = one("DKIM-002")
    assert any(x["how"] == "portal" and "Email & collaboration > Policies & rules > Threat policies > Email authentication "
               "settings > DKIM" in x["text"] for x in s)
    assert ("Get-DkimSigningConfig -Identity corp.example | Format-List Enabled,Status,Selector1CNAME,Selector2CNAME"
            in codes(s))
    assert "python src/headers.py header.txt" in codes(s)
    # an inherited policy: the name's own lookup and the record it inherits
    hr = {"dns": live_dns(["hr.corp.example"], None)}
    s = verify.finding_steps(next(dict(f, source="dns:hr.corp.example") for f in hr["dns"]["hr.corp.example"]["findings"]
                                  if f["id"] == "DMARC-002"), hr)
    assert lookups(s[0]["code"], "_dmarc.hr.corp.example") and lookups(s[0]["code"], "_dmarc.corp.example")
    assert "has no record of its own" in s[0]["text"]


# ------------------------------------------------------------------ mail-log findings

FLOOR = "a floor: the row budget cut corp.example's mail log in this run (newest 41 hours kept)"


def without_totals(report):
    """The same run without maillog.window_totals: a cut organization whose full window nobody counted."""
    doc = json.loads(json.dumps(report))
    doc["maillog"].pop("window_totals", None)
    return doc


def test_mail_log_findings_fill_their_domain_into_the_query_and_quote_the_report(run):
    report, _, tmp = run
    log = verify.shown(tmp / "log.csv")
    s = steps_of(report, "MAILFLOW-001")
    check_shape(s)
    assert s[0]["code"] == "python src/dedupe.py %s --auth-column DMARC" % verify.ps(log)
    assert "the GENUINE failures line shows 13" in s[0]["text"]
    census = next(x for x in s if "queries/sender_census_corp.example.kql" in x["text"])
    assert census["how"] == "kql" and 'let sender_domain = "corp.example";' in census["code"]
    # corp.example's organization was cut by the row budget and collect.py counted its full window: the query should
    # show the full-window count, and the report's own figure is the floor beside it
    assert "genuine_failures column adds up to 160, the full-window count" in census["text"]
    assert "the report's own rows count 10, " + FLOOR in census["text"]
    # a cut nobody counted in full: the report's figure is a floor, the query counts more
    bare = verify.finding_steps(next(f for f in report["findings"] if f["id"] == "MAILFLOW-001"), without_totals(report))
    census = next(x for x in bare if "queries/sender_census_corp.example.kql" in x["text"])
    assert "genuine_failures column adds up to 10;" in census["text"] and "expect more" in census["text"]
    assert "the row budget cut corp.example's mail log in this run (newest 41 hours kept)" in census["text"]
    # the closing pointer has nothing to run: a command step without code, which verify.md prints as a note
    rest = s[-1]
    assert rest["how"] == "command" and rest["code"] == "" and "3 from unaudited subdomains" in rest["text"]
    assert re.search(r"\n\d\. Note: The rest of the 13: 3 from unaudited subdomains", verify.render(report))
    s = steps_of(report, "MAILFLOW-002")
    assert "failed authentication but DELIVERED shows 4" in s[0]["text"] and "an Exchange transport rule x4" in s[0]["text"]
    totals = next(x for x in s if "queries/maillog_totals_corp.example.kql" in x["text"])
    assert "delivered_despite_fail adds up to 15" in totals["text"]
    assert "(org: Exchange transport rule (Allow) x15)" in totals["text"]
    assert "the report's own rows hold 4 of them (org: Exchange transport rule (Allow) x4), " + FLOOR in totals["text"]
    for col in ("OrgLevelAction", "OrgLevelPolicy", "UserLevelAction", "UserLevelPolicy"):  # what let it in, named
        assert 'column_ifexists("%s", "")' % col in totals["code"] and col in totals["text"]
    bare = verify.finding_steps(next(f for f in report["findings"] if f["id"] == "MAILFLOW-002"), without_totals(report))
    totals = next(x for x in bare if "queries/maillog_totals_corp.example.kql" in x["text"])
    assert "delivered_despite_fail adds up to 4" in totals["text"] and "the report: org: Exchange transport rule " \
        "(Allow) x4" in totals["text"] and "expect more" in totals["text"]
    s = steps_of(report, "MAILFLOW-010")
    alignment = next(x for x in s if x["how"] == "kql")
    assert "queries/dkim_alignment_corp.example.kql" in alignment["text"]
    assert "news@corp.example (envelope corp.example) 5" in alignment["text"]
    assert "genuine failures by likely cause lines show 13 likely_spoof" in steps_of(report, "MAILFLOW-004")[0]["text"]
    # one domain's share of the mail log: its own counts, the full window, the overrides, its senders, its unaudited
    # subdomains, its SPF-only senders and the recount, each with the report's figure
    corp = verify.maillog_steps(report, "corp.example")
    check_shape(corp)
    t = texts(corp)
    for said in ("total column comes to about 5000, passing to about 4800 and genuine_failures to 160, the "
                 "full-window counts collect.py took in Advanced Hunting (maillog.window_totals) over the same 30 days",
                 "the report's own rows count total 45, passing 35 and genuine_failures 10 (by envelope domain: "
                 "mta.attacker.invalid 6, billing.vendor.example 4), " + FLOOR,
                 "genuine_failures adds up to 160 and delivered_despite_fail to 15, and delivered_by names the override "
                 "that let each delivered one in",
                 "the report's own rows hold 10 of the failures and 4 of the deliveries (org: Exchange transport rule "
                 "(Allow) x4), " + FLOOR,
                 "counted the way the report counts them (a copy that reached the inbox, junk or deleted items, at the "
                 "(Message-ID, recipient) grain), so its msgs column adds up to the full-window 15 of maillog_totals",
                 "the report's top ones are ceo@corp.example x6, billing@corp.example x4",
                 "unaudited subdomain news.corp.example come to about total 40 and genuine_failures 40",
                 "the report's own rows count 3 and 3, " + FLOOR,
                 "the spf_only column shows the senders that pass on SPF alone: news@corp.example (envelope "
                 "corp.example) 5",
                 "the GENUINE failures line shows 13 and logical messages 52",
                 "failed authentication but DELIVERED shows 4"):
        assert said in t, said
    assert corp[-1]["code"].endswith("--auth-column DMARC --sender-domain corp.example")
    # one query file, one expected figure: every step that names maillog_totals_corp.example.kql for corp.example's
    # deliveries quotes the same full-window count, never the floor as the figure the query shows
    md = verify.render(report)
    said = re.findall(r"maillog_totals_corp\.example\.kql \(saved next to this file\): in the rows for fromdom "
                      r"corp\.example, (?:genuine_failures adds up to \d+ and )?delivered_despite_fail (?:adds up )?to "
                      r"(\d+)", md)
    assert len(said) == 2 and set(said) == {"15"}, said
    # without the full window the pair still runs: the override query with the report's count, the shipped one beside it
    corp = verify.maillog_steps(without_totals(report), "corp.example")
    t = texts(corp)
    assert "total column adds up to 45, passing to 35 and genuine_failures to 10" in t and "expect more" in t
    assert "delivered_despite_fail adds up to 4, and delivered_by names the override" in t
    assert "so its msgs column adds up to the report's 4; " in t and "a little above" not in t
    assert "unaudited subdomain news.corp.example add up to total 3 and genuine_failures 3" in t
    hr = verify.maillog_steps(report, "hr.corp.example")
    assert 'let sender_domain = "hr.corp.example";' in hr[0]["code"] and "adds up to 4, passing to 4" in hr[0]["text"]
    # the figures are the report's: change the report and the steps change with it
    doc = json.loads(json.dumps(report))
    doc["maillog"]["by_domain"]["corp.example"]["genuine_failures"] = 77
    doc["maillog"]["window_totals"]["orgs"]["corp.example"]["by_domain"]["corp.example"]["genuine_failures"] = 177
    t = texts(verify.maillog_steps(doc, "corp.example"))
    assert "genuine_failures to 177" in t and "genuine_failures 77" in t


def test_the_window_clause_says_how_the_query_relates_to_the_reports_figure():
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    rep = {"generated_utc": NOW.strftime(stamp),
           "maillog": {"window": {"from": (NOW - timedelta(days=30)).strftime(stamp),
                                  "to": (NOW - timedelta(minutes=5)).strftime(stamp)}, "cuts": {}}}
    assert verify.window_note(rep, "corp.example", 30).startswith("the query covers the same 30 days, so small differences")
    assert verify.window_note(rep, "corp.example", 7).startswith(
        "the query covers only the last 7 days of the report's 30 days")
    short = json.loads(json.dumps(rep))
    short["maillog"]["window"]["from"] = (NOW - timedelta(days=7)).strftime(stamp)
    assert verify.window_note(short, "corp.example", 30).startswith("the run read 7 days of mail log")
    old = json.loads(json.dumps(rep))
    old["maillog"]["window"] = {"from": "2026-05-01T03:00:44Z", "to": "2026-05-09T16:01:00Z"}
    old["generated_utc"] = "2026-10-09T16:14:09Z"
    assert "covering 2026-05-01 03:00 to 2026-05-09 16:01 UTC, which the query's last 30 days do not match" in \
        verify.window_note(old, "corp.example", 30)
    cut = dict(rep, maillog=dict(rep["maillog"], cuts={"corp.example": {"reason": "row budget", "kept_hours": 41}}))
    assert verify.window_note(cut, "hr.corp.example", 30) == (
        "the row budget cut corp.example's mail log in this run (newest 41 hours kept), so the report's figure is a floor "
        "over the hours kept while the query counts 30 days: expect more")
    assert "no time span" in verify.window_note({"maillog": {"window": "x"}}, "corp.example", 30)


# ------------------------------------------------------------------ aggregate reports

def test_aggregate_report_findings_rerun_the_parser_with_the_runs_filters_and_find_a_source_in_a_raw_file(run):
    report, _, tmp = run
    folder = verify.ps(verify.shown(tmp / "rua"))
    cmd = "python src/rua_parse.py %s --known '192.0.2.0/24,esp.example'" % folder
    s = steps_of(report, "OUTSIDE-001")
    check_shape(s)
    assert s[0]["code"] == cmd
    assert "the failing streams section lists 2 sources: 203.0.113.5 300 msgs 0.0% pass, likely_spoof" in s[0]["text"]
    raw = s[1]["code"]
    assert raw.startswith("$ips = @('203.0.113.5', '2001:db8::25')") and "<source_ip>" in raw and ".gz" in raw
    assert "Get-ChildItem -Path %s -File -Recurse" % folder in raw
    s = steps_of(report, "OUTSIDE-002")
    assert s[0]["code"] == cmd and "198.51.100.20 x120 (120 pass)" in s[0]["text"]
    s = steps_of(report, "OUTSIDE-003")
    assert "198.51.100.20 120 msgs as corp.example" in s[0]["text"] and "'198.51.100.20'" in s[1]["code"]
    # the run's window and thresholds come along, so the parser prints the same figures
    doc = json.loads(json.dumps(report))
    doc["rua"]["filters"].update(since="2026-09-09", until="2026-10-08", min_volume=50, fail_threshold=0.3,
                                 expect_policy="reject", retiring_selectors=["legacy2019"])
    assert verify.rua_command(doc) == (
        "python src/rua_parse.py %s --since 2026-09-09 --until 2026-10-08 --known '192.0.2.0/24,esp.example' "
        "--min-volume 50 --fail-threshold 0.3 --expect-policy reject --retiring-selector legacy2019" % folder)
    # every other aggregate-report finding names the part of the output that shows it
    doc["rua"]["policy_check"]["seen"] = [{"domain": "corp.example", "p": "none", "reports": 1}]
    doc["rua"]["retiring_selectors"] = [{"retiring": "legacy2019", "domain": "corp.example", "messages": 40}]
    parts = {"OUTSIDE-004": "policy published", "OUTSIDE-005": "retiring selector", "OUTSIDE-006": "retiring selector",
             "OUTSIDE-007": "likely label", "OUTSIDE-008": "files read", "OUTSIDE-009": "unknown senders heading",
             "OUTSIDE-010": "policy published", "OUTSIDE-011": "files read", "OUTSIDE-012": "count caveat"}
    for fid, part in parts.items():
        s = verify.finding_steps(dict(finding(fid, "info", "outside_view", "retiring selector legacy2019 x", "seen"),
                                      source="rua"), doc)
        check_shape(s)
        assert s[0]["code"].startswith("python src/rua_parse.py ") and part in s[0]["text"], fid
    s = verify.finding_steps(dict(finding("OUTSIDE-004", "major", "outside_view", "t", "e"), source="rua"), doc)
    assert lookups(s[1]["code"], "_dmarc.corp.example")
    s = verify.finding_steps(dict(finding("OUTSIDE-005", "blocking", "outside_view", "t", "e"), source="rua"), doc)
    assert lookups(s[1]["code"], "legacy2019._domainkey.corp.example")
    assert verify.rua_command({"rua": None}) is None


# ------------------------------------------------------------------ headers and the tenant

TENANT_CMDLETS = {
    "RULES-002": "Get-TransportRule", "RULES-003": "Get-TransportRule", "RULES-004": "Get-TransportRule",
    "RULES-005": "Get-TransportRule", "RULES-006": "Get-MailDetailTransportRuleReport",
    "RULES-007": "Get-MailDetailTransportRuleReport", "RULES-101": "Get-HostedContentFilterPolicy",
    "RULES-102": "Get-HostedContentFilterPolicy", "RULES-103": "Get-TenantAllowBlockListItems",
    "RULES-104": "Get-TenantAllowBlockListItems", "RULES-105": "Get-TenantAllowBlockListSpoofItems",
    "RULES-108": "Get-InboundConnector", "RULES-109": "Get-InboundConnector", "RULES-117": "Get-AcceptedDomain",
    "RULES-118": "Get-HostedContentFilterRule", "GROUPS-001": "Get-DistributionGroup",
    "GROUPS-002": "Get-DistributionGroup", "GROUPS-004": "Get-Mailbox", "GROUPS-005": "Get-Mailbox",
    "GROUPS-006": "Get-InboxRule", "GROUPS-007": "Get-RemoteDomain", "GROUPS-008": "Get-HostedOutboundSpamFilterPolicy",
    "GROUPS-009": "Get-DistributionGroupMember",
    # the Issues codes audit.py reads as ids when an export carries no findings list
    "ALLOW-WITHOUT-AUTH": "Get-TransportRule", "FORGEABLE-CONDITION": "Get-TransportRule",
    "AUDIT-MODE-BLOCK": "Get-TransportRule", "LARGE-EXCEPTION-LIST": "Get-TransportRule",
    "ALLOW-IP-GATED-ONLY": "Get-TransportRule", "TREATS-AS-INTERNAL": "Get-InboundConnector",
    "EF-SKIP": "Get-InboundConnector", "UNPINNED-ONPREM": "Get-InboundConnector",
    "OPEN-AND-REDISTRIBUTES-EXTERNAL": "Get-DistributionGroup", "OPEN-TO-EXTERNAL": "Get-DistributionGroup",
    "REDISTRIBUTES-EXTERNAL": "Get-DistributionGroup", "MEMBERS-NOT-READ": "Get-DistributionGroupMember",
}
TENANT_CMDLETS.update({fid: "Get-AntiPhishPolicy" for fid in (
    "RULES-110", "RULES-111", "RULES-112", "RULES-113", "RULES-114", "RULES-115", "RULES-116", "RULES-119", "RULES-120",
    "POLICY-DISABLED", "SPOOF-INTEL-OFF", "DMARC-NOT-HONORED", "UNAUTH-INDICATORS-OFF", "MAILBOX-INTEL-OFF",
    "USER-IMPERSONATION-OFF", "DOMAIN-IMPERSONATION-OFF", "IMPERSONATION-EXCLUSIONS")})
TENANT_OBJECTS = {"RULES-103": "TenantAllowBlockList/Sender", "RULES-104": "TenantAllowBlockList/Url",
                  "RULES-105": "ceo@corp.example|mail.vendor.example",
                  "RULES-118": "HostedContentFilterRule", "GROUPS-009": "all@corp.example",
                  "RULES-117": "relay.corp.example", "RULES-007": None}
# evidence as the exports word it: a group finding names the group's kind first
TENANT_EVIDENCE = {"GROUPS-001": "DistributionGroup; RequireSenderAuthenticationEnabled=False; sender restrictions=0",
                   "GROUPS-002": "DistributionGroup; external members (1): p@outside.invalid",
                   "GROUPS-003": "DistributionGroup; RequireSenderAuthenticationEnabled=False; external members (1): x",
                   "GROUPS-009": "DistributionGroup membership cmdlet failed"}
# the groups table's Issues codes: audit.py's finding carries the code alone, the table row the group's kind and address
ISSUE_GROUP_CODES = ("OPEN-AND-REDISTRIBUTES-EXTERNAL", "OPEN-TO-EXTERNAL", "REDISTRIBUTES-EXTERNAL", "MEMBERS-NOT-READ")


def test_header_and_tenant_findings_name_the_file_or_the_page_and_the_read_only_cmdlet(run):
    report, _, tmp = run
    s = steps_of(report, "PROOF-001")
    check_shape(s)
    assert s[0]["code"] == "python src/headers.py %s" % verify.ps(verify.shown(tmp / "msg.txt"))
    assert "Select-String -Path" in s[1]["code"] and "DKIM-Signature|Authentication-Results" in s[1]["code"]
    f = dict(finding("PROOF-010", "major", "proof", "no DKIM key published at s1._domainkey.corp.example", "TXT absent"),
             source="headers:" + str(tmp / "msg.txt"))
    assert lookups(verify.finding_steps(f, report)[-1]["code"], "s1._domainkey.corp.example")
    s = steps_of(report, "RULES-001")
    assert "Exchange admin center (admin.exchange.microsoft.com) > Mail flow > Rules" in s[0]["text"]
    assert s[1]["code"].startswith("Get-TransportRule -Identity 'Partner bypass' | Format-List Name,State,Mode")
    assert "SetSCL=-1" in s[1]["text"]
    s = steps_of(report, "RULES-106")
    assert ("Where-Object { $_.SpoofedUser -eq 'billing@corp.example' -and $_.SendingInfrastructure -eq "
            "'vendor.example' }") in s[1]["code"]
    assert steps_of(report, "RULES-107")[1]["code"].startswith("Get-InboundConnector -Identity 'Legacy relay'")
    s = steps_of(report, "GROUPS-003")
    assert s[1]["code"].startswith("Get-DistributionGroup -Identity 'all@corp.example'")
    assert "Get-DistributionGroupMember -Identity 'all@corp.example' -ResultSize Unlimited" in s[1]["code"]
    # every other id the three PowerShell exports write, and the Issues codes
    doc = json.loads(json.dumps(report))
    doc["groups"]["tables"]["groups"] = [{"Name": "Thing one", "Address": "thing@corp.example",
                                          "Kind": "DistributionGroup", "Issues": "OPEN-TO-EXTERNAL"}]
    for fid, cmdlet in TENANT_CMDLETS.items():
        section = "groups" if fid.startswith("GROUPS-") or "EXTERNAL" in fid or fid == "MEMBERS-NOT-READ" else "rules"
        obj = TENANT_OBJECTS.get(fid, "Thing one")
        ev = TENANT_EVIDENCE.get(fid) or (fid if fid in ISSUE_GROUP_CODES else
                                          "Rule one, Rule two" if obj is None else "evidence")
        f = dict(finding(fid, "minor", "rules", "%s: %s" % (fid, obj or "x"), ev), source=section)
        if obj and fid.startswith(("RULES-1", "GROUPS-")):
            f["object"] = obj
        s = verify.finding_steps(f, doc)
        check_shape(s)
        assert cmdlet in codes(s), (fid, codes(s))
        # a group the groups table lists is named by the row's address
        ident = "thing@corp.example" if fid in ISSUE_GROUP_CODES + ("GROUPS-001", "GROUPS-002", "GROUPS-003") else obj
        if ident and "|" not in ident and "/" not in ident and fid != "RULES-118":
            assert verify.ps(ident) in codes(s), (fid, codes(s))
    s = verify.finding_steps(dict(finding("RULES-104", "info", "rules", "t", "e"), source="bypasses",
                                  object="TenantAllowBlockList/Url"), report)
    assert "Get-TenantAllowBlockListItems -ListType Url -Allow" in codes(s)
    s = verify.finding_steps(dict(finding("RULES-007", "info", "rules", "Hit counts unavailable for 2 rules",
                                          "Rule one, Rule two"), source="rules"), report)
    assert "-TransportRule 'Rule one'" in codes(s) and "-TransportRule 'Rule two'" in codes(s)


def test_a_finding_with_an_unknown_id_gets_the_generic_fallback(run):
    report, _, tmp = run
    cases = {"dns:corp.example": ("python src/dns_audit.py corp.example", "DNS-999"),
             "maillog": ("python src/dedupe.py ", "MAILFLOW-999"),
             "rua": ("python src/rua_parse.py ", "OUTSIDE-999"),
             "rules": ("(& .\\src\\audit_rules.ps1 -Json -SkipHits | ConvertFrom-Json).findings | Where-Object "
                       "{ $_.id -eq 'RULES-999' }", "RULES-999"),
             "bypasses": ("(& .\\src\\audit_bypasses.ps1 -Json | ConvertFrom-Json).findings | Where-Object "
                          "{ $_.id -eq 'RULES-998' }", "RULES-998"),
             "groups": ("(& .\\src\\audit_groups.ps1 -Json | ConvertFrom-Json).findings | Where-Object "
                        "{ $_.id -eq 'GROUPS-999' }", "GROUPS-999"),
             "headers:" + str(tmp / "msg.txt"): ("python src/headers.py ", "PROOF-999")}
    for source, (code, fid) in cases.items():
        s = verify.finding_steps(dict(finding(fid, "info", "x", "something new", "seen this"), source=source), report)
        check_shape(s)
        assert code in s[0]["code"] and fid in s[0]["text"], (source, s)
    s = verify.finding_steps(finding("ODD-1", "info", "x", "t", "seen this"), {})
    check_shape(s)
    assert s[0]["text"].startswith("No check is known for ODD-1") and "seen this" in s[0]["text"]
    for fid, src in (("MAILFLOW-001", "maillog"), ("OUTSIDE-001", "rua"), ("PROOF-001", "headers:")):
        check_shape(verify.finding_steps(dict(finding(fid, "major", "x", "t", "e"), source=src), {}))


# ------------------------------------------------------------------ plan rows

def row(plan, domain, kind, host=None):
    return next(c for c in plan["changes"] if c["domain"] == domain and c["kind"] == kind
                and (host is None or c["hostname"] == host))


def test_plan_rows_go_before_publish_after_and_roll_back_with_the_plans_values(run):
    report, plan, _ = run
    for c in plan["changes"]:
        s = verify.change_steps(c, report)
        check_shape(s)
        heads = [x["text"].split(":")[0] for x in s]
        assert heads[0] == "Before" and heads[1].startswith("Publish") and heads[2] == "After", (c["id"], heads)
        assert "Roll back" in heads, c["id"]
    s = verify.change_steps(row(plan, "corp.example", "modify"), report)
    assert lookups(s[0]["code"], "corp.example") and "reads 'v=spf1 include:spf.esp.example ?all'" in s[0]["text"]
    assert s[1]["code"] == "v=spf1 include:spf.esp.example ~all" and "TTL 3600" in s[1]["text"] and "Route53" in s[1]["text"]
    assert "reads 'v=spf1 include:spf.esp.example ~all'" in s[2]["text"] and lookups(s[2]["code"], "corp.example")
    assert s[3]["text"].startswith("Roll back: publish the current string verbatim") and s[3]["code"] == CORP_SPF
    s = verify.change_steps(row(plan, "corp.example", "ratchet"), report)
    assert "up to 1800 seconds, the TTL on the answer the audit saw" in s[2]["text"]  # the audit's own answer carried it
    assert "python src/headers.py header.txt" in codes(s)  # its prerequisite is DKIM proof
    s = verify.change_steps(row(plan, "hr.corp.example", "new"), report)
    assert "no answer starts with v=DMARC1 today (current: none)" in s[0]["text"]
    assert s[1]["code"] == "v=DMARC1; p=none; rua=%s;" % RUA and s[-1]["text"] == "Roll back: delete the record."
    # a park row proves the domain unused: the tenant's mail flow, the MX and the aggregate reports
    s = verify.change_steps(row(plan, "parked.example", "park", "_dmarc.parked.example"), report)
    flow = next(x for x in s if "queries/mailflow_parked.example.kql" in x["text"])
    assert 'd == "parked.example" or d endswith ".parked.example"' in flow["code"]
    assert "the run measured outbound 0 and inbound 0" in flow["text"]
    assert any(lookups(x["code"], "parked.example", "MX") for x in s)
    assert "has no row for parked.example, but no receiver reports on it until a record with rua covers it" in texts(s)
    # the move to reject: DKIM proof, the list-or-forwarder proof and the SPF lookup budget
    s = verify.change_steps(row(plan, "shop.example", "ratchet"), report)
    twin = next(x for x in s if "queries/delivered_twin_shop.example.kql" in x["text"])
    assert 'let sender_domain = "shop.example";' in twin["code"]
    assert "python src/spf_lookups.py shop.example" in codes(s) and "the audit counted 10" in texts(s)
    assert "queries/dkim_alignment_shop.example.kql" in texts(s)
    # a DKIM task: no record to paste; the selectors and Microsoft 365's own state instead
    s = verify.change_steps(row(plan, "corp.example", "todo", "<selector>._domainkey.corp.example"), report)
    assert lookups(s[0]["code"], "selector1._domainkey.corp.example", "CNAME")
    assert "this row is a task, not a record to paste" in s[1]["text"] and s[1]["code"] == ""
    assert "Get-DkimSigningConfig -Identity corp.example" in codes(s)
    # rows of the shapes the parallel plan work adds: the no-mail fast path, and a monitoring record for a sending
    # subdomain the run does not audit
    fast = {"id": "P-10", "domain": "parked.example", "kind": "ratchet", "priority": 1, "record": "TXT",
            "hostname": "_dmarc.parked.example", "value": "v=DMARC1; p=quarantine; rua=%s;" % RUA, "ttl": 3600,
            "current": "none", "rollback": "delete the record", "why": "no mail measured: quarantine now",
            "prerequisites": ["no sender that mails less often than monthly (statements, renewals) uses this domain"]}
    s = verify.change_steps(fast, report)
    assert "queries/mailflow_parked.example.kql" in texts(s) and "nothing left the tenant as it in 30 days" in texts(s)
    assert not any(lookups(x["code"], "parked.example", "MX") for x in s)  # not a park row: an MX proves nothing
    fast["prerequisites"].append("no third party sends as parked.example straight to outside recipients: no aggregate "
                                 "report in this run covers it, and only those would show such mail")
    s = verify.change_steps(fast, report)
    said = [x for x in s if "header_from domains table" in x["text"]]
    assert len(said) == 1 and "has no row for parked.example, but no receiver reports on it until a record with rua " \
        "covers it" in said[0]["text"]  # the prerequisite's table and the no-mail proof's are one step
    mono = {"id": "P-11", "domain": "m.corp.example", "kind": "new", "priority": 1, "record": "TXT",
            "hostname": "_dmarc.m.corp.example", "value": "v=DMARC1; p=none; rua=%s;" % RUA, "ttl": 3600,
            "current": "none", "rollback": "delete the record",
            "why": "an explicit record shields it from the apex's sp= change"}
    s = verify.change_steps(mono, report)
    assert [x["text"].split(":")[0] for x in s] == ["Before", "Publish at the DNS host", "After", "Roll back"]
    # the sp= step waits on the sending subdomains' own records: each one the prerequisite names is looked up
    sp = dict(row(plan, "corp.example", "ratchet"), value="v=DMARC1; p=quarantine; sp=quarantine; rua=%s;" % RUA,
              prerequisites=["every subdomain that sends has its own _dmarc record: m.corp.example, t.corp.example "
                             "have none yet (the monitoring records above)"], prerequisite_items=[])
    proof = verify.change_steps(sp, report)[-1]
    assert proof["how"] == "dns" and "each answers with a v=DMARC1 string of its own" in proof["text"]
    for name in ("_dmarc.m.corp.example", "_dmarc.t.corp.example", "_dmarc.hr.corp.example"):
        assert lookups(proof["code"], name), name
    check_shape(verify.change_steps({"hostname": "<x>", "record": "SRV", "value": "<y>", "kind": "mystery"}, {}))


# ------------------------------------------------------------------ the filled queries and the document

def test_filled_queries_carry_the_org_and_differ_from_the_shipped_query_in_its_sender_domain_line_only(run, tmp_path):
    report, plan, _ = run
    mpath, paths = verify.write(report, plan, tmp_path / "out")
    names = {p.name for p in paths}
    for org in ("corp.example", "dup.example", "parked.example", "shop.example"):
        for q in verify.ORG_QUERIES:
            assert "%s_%s.kql" % (q, org) in names, (q, org)
        assert (tmp_path / "out" / "queries" / ("mailflow_%s.kql" % org)).read_text(encoding="utf-8") == \
            discover.mailflow_kql([org], 30) + "\n"
    assert "sender_census_hr.corp.example.kql" in names and "delivered_twin_shop.example.kql" in names
    for p in paths:
        q = next(q for q in sorted(verify.QUERIES, key=len, reverse=True) if p.stem.startswith(q + "_"))
        domain = p.stem[len(q) + 1:]
        if q == "mailflow":
            continue
        shipped = (QUERIES / (q + ".kql")).read_bytes()
        filled = p.read_bytes()  # the shipped query's own line endings, so a diff shows one line
        assert filled == shipped.replace(verify.PLACEHOLDER.encode(), ('let sender_domain = "%s";' % domain).encode(), 1)
        diff = [(a, b) for a, b in zip(shipped.decode().splitlines(), filled.decode().splitlines()) if a != b]
        assert len(diff) == 1 and diff[0][1].startswith('let sender_domain = "%s";' % domain), (p.name, diff)
    text = mpath.read_text(encoding="utf-8")
    listed = re.findall(r"^- (queries/\S+\.kql), for ", text, re.M)
    assert sorted(listed) == sorted("queries/" + n for n in names)


def test_verify_md_leads_with_how_to_use_it_then_a_section_per_domain_in_the_reports_order(run):
    report, plan, tmp = run
    text = verify.render(report, plan)
    lead = text.split("## Contents", 1)[0]
    for said in ("Every check is read-only", "public resolvers (8.8.8.8", "in your own Defender portal",
                 "under your own sign-in", "nslookup line under a lookup works on any system"):
        assert said in lead, said
    heads = re.findall(r"^## (.+)$", text, re.M)
    assert heads == ["Contents"] + NAMES + ["Across the run", "Queries for the portal"]
    corp = text.split("## corp.example\n", 1)[1].split("\n## ", 1)[0]
    assert "#### [major] SPF-003 - SPF terminator is '?all' - effectively no protection" in corp
    assert "#### [minor] DKIM-002 - no common DKIM selector found" in corp and "(not verified)" in corp
    rows = [c["id"] for c in plan["changes"] if c["domain"] == "corp.example"]
    assert re.findall(r"^#### (P-\d+) ", corp, re.M) == rows
    assert "### Mail log" in corp and "### Mail flow (tenant)" in corp and "### Aggregate reports" in corp
    across = text.split("## Across the run\n", 1)[1].split("\n## ", 1)[0]
    for fid in ("OUTSIDE-001", "MAILFLOW-001", "PROOF-001", "RULES-001", "RULES-106", "GROUPS-003"):
        assert "] %s - " % fid in across, fid
    # commands sit in fenced blocks, values to paste as text, queries by their file only
    assert "   ```powershell\n   Resolve-DnsName -Name _dmarc.corp.example -Type TXT -Server 8.8.8.8" in text
    assert "   ```text\n   v=DMARC1; p=quarantine; pct=25; rua=mailto:reports@corp.example;\n   ```" in text
    assert "EmailEvents" not in text and text.count("```") % 2 == 0
    # a held domain names the finding behind the hold
    assert ("- Held, not proposed: two DMARC records at _dmarc.dup.example - receivers apply no policy and send no "
            "reports; find out who published the second record before collapsing to one - check: DMARC-005 (Findings "
            "above)") in text


def test_each_gate_reason_names_the_finding_behind_it_and_where_its_steps_are(run):
    report, plan, _ = run
    text = verify.render(report, plan)

    def section(d):
        return text.split("## %s\n" % d, 1)[1].split("\n## ", 1)[0]
    corp = section("corp.example")
    assert ("- rules: Allow rule without authentication gate: Partner bypass - unauthenticated mail is delivered past "
            "the policy - check: RULES-001 (Across the run)") in corp
    assert "from this domain failed with no passing copy (deduplicated); top senders: ceo@corp.example x6" in corp
    assert "- check: MAILFLOW-001 (Across the run); the mail-log checks in this section" in corp
    assert ("reached a mailbox - let in by an Exchange transport rule x4, which external receivers do not have - check: "
            "MAILFLOW-002") in corp
    assert "not gated here; add them to the domain list to gate them - check: the unaudited-subdomains check" in corp
    assert ("- step being gated: move to p=quarantine at pct=25 on the record at "  # the plan's first ramp step (T-12)
            "_dmarc.corp.example - check: the policy check above") in corp
    assert "check: DMARC-005 (Findings below)" in section("dup.example")
    assert ("- parked.example: NO DMARC RECORD - no policy, no reporting, invisible to you - check: DMARC-001 (Findings "
            "below)") in section("parked.example")
    assert verify.reason_checks("something the gate says", "x.example", report, {}) == \
        "no finding behind it: the gate's own reasoning over the evidence"
    # the policy check is the record the gate read
    assert ("1. DNS: Policy today: look up _dmarc.corp.example: the answer starting with v=DMARC1 reads "
            "'v=DMARC1; p=none; rua=mailto:reports@corp.example;'.") in corp


# ------------------------------------------------------------------ the shared-file wiring

def test_report_md_gives_each_finding_its_first_check(run, monkeypatch):
    report, _, _ = run
    md = audit.render_md(report)
    block = md.split("## Findings", 1)[1].split("\n## ", 1)[0]
    assert "Each verify line is the finding's first check; verify.md has every step" in block
    entries = block.split("\n- **[")[1:]
    assert entries and all("\n  - verify: " in e and "steps: verify.md)" in e for e in entries)
    # one finding seen on two domains is one entry: its check is the first source's, and says so
    both = next(e for e in entries if "SPF-001" in e.split("\n", 1)[0])
    assert "2 sources: dns:hr.corp.example, dns:parked.example" in both
    assert ("  - verify: `Resolve-DnsName -Name hr.corp.example -Type TXT -Server 8.8.8.8 | Where-Object { $_.Type -eq "
            "'TXT' } | ForEach-Object { $_.Strings -join '' }` (the first source's; every source's steps: verify.md)") in both
    spf = next(e for e in entries if "SPF-003" in e.split("\n", 1)[0])
    assert ("  - verify: `Resolve-DnsName -Name corp.example -Type TXT -Server 8.8.8.8 | Where-Object { $_.Type -eq "
            "'TXT' } | ForEach-Object { $_.Strings -join '' }` (all steps: verify.md)") in spf
    rules = next(e for e in entries if "RULES-001" in e.split("\n", 1)[0])
    assert "  - verify: In the Exchange admin center (admin.exchange.microsoft.com) > Mail flow > Rules" in rules
    # report.md never fails because of verify.py
    monkeypatch.setattr(verify, "first_check", lambda f, r: 1 / 0)
    md = audit.render_md(report)
    assert "  - verify: " not in md and "## Findings" in md


def test_next_steps_and_todo_point_to_verify_md(run):
    report, plan, _ = run
    md = next_steps.render_md(next_steps.build(report, plan))
    # round 13, T-03: the pointer closes the document, in its Sources and how to check section
    assert "To check any number or record here yourself, follow verify.md next to this file" in \
        md.split("## Sources and how to check", 1)[1].split("\n---\n", 1)[0]
    todo = collect.render_todo(report, plan)
    assert todo.split("## Where each domain stands", 1)[0].endswith(
        "verify.md, next to this file, says how to check every finding and every plan row yourself.\n\n")


def run_collect(monkeypatch, out):
    monkeypatch.setattr(sys, "argv", ["collect.py", "example.com", "--offline", "--no-config", "--no-owners",
                                      "--no-notify", "--rua", str(ROOT / "samples" / "rua"),
                                      "--maillog", str(ROOT / "samples" / "sample_maillog.csv"),
                                      "--auth-column", "DMARC", "--out", str(out)])
    try:
        collect.main()
    except SystemExit:
        pass
    return json.loads((out / "latest" / "run.json").read_text(encoding="utf-8"))


def test_collect_writes_verify_md_and_its_queries_and_a_verify_failure_is_a_note(tmp_path, monkeypatch, offline):
    out = tmp_path / "out"
    first = run_collect(monkeypatch, out)
    latest = out / "latest"
    text = (latest / "verify.md").read_text(encoding="utf-8")
    assert "verify.md" in collect.RUN_FILES and (out / "history" / first["run"] / "verify.md").exists()
    assert "### [major] MAILFLOW-001 - 21 logical messages failed with no passing copy, from 6 senders" in text
    assert "python src/dedupe.py samples/sample_maillog.csv --auth-column DMARC" in text
    assert "python src/rua_parse.py samples/rua" in text
    assert sorted(p.name for p in (latest / "queries").iterdir()) == sorted(
        "%s_example.com.kql" % q for q in verify.ORG_QUERIES)
    assert (out / "history" / first["run"] / "queries" / "sender_census_example.com.kql").exists()
    assert not any("verify.md" in n for n in first["notes"])
    assert "follow verify.md next to this file" in (latest / "next_steps.md").read_text(encoding="utf-8")
    assert "  - verify: `python src/rua_parse.py samples/rua` (all steps: verify.md)" in \
        (latest / "report.md").read_text(encoding="utf-8")

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(verify, "write", boom)
    second = run_collect(monkeypatch, out)
    assert second["run"] != first["run"] and "no verify.md written (RuntimeError: boom)" in second["notes"]
    assert not (latest / "verify.md").exists() and not (latest / "queries").exists()  # nothing stale left behind
    assert (latest / "report.md").exists() and (latest / "next_steps.md").exists()


def test_the_cli_writes_the_file_and_refuses_bad_input(run, tmp_path):
    report, plan, _ = run
    (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    p = subprocess.run([sys.executable, SCRIPT, str(tmp_path / "report.json"), "--plan", str(tmp_path / "plan.json"),
                        "--out", str(tmp_path / "cli")], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert (tmp_path / "cli" / "verify.md").read_text(encoding="utf-8") == verify.render(report, plan)
    assert "wrote" in p.stdout and (tmp_path / "cli" / "queries" / "maillog_totals_corp.example.kql").exists()
    for args in ([str(tmp_path / "missing.json")], [str(tmp_path / "plan.json")]):
        p = subprocess.run([sys.executable, SCRIPT] + args + ["--out", str(tmp_path / "x")], capture_output=True, text=True)
        assert p.returncode == 2 and p.stderr.startswith("error: ") and "Traceback" not in p.stderr, p.stderr
    (tmp_path / "list.json").write_text("[1]", encoding="utf-8")
    p = subprocess.run([sys.executable, SCRIPT, str(tmp_path / "list.json"), "--out", str(tmp_path / "x")],
                       capture_output=True, text=True)
    assert p.returncode == 2 and "not one JSON object" in p.stderr


def test_plain_ascii_and_odd_values_never_raise(run):
    report, plan, _ = run
    assert verify.render(report, plan).isascii()
    assert (ROOT / "src" / "verify.py").read_text(encoding="utf-8").isascii()
    assert Path(__file__).read_text(encoding="utf-8").isascii()
    for value in (None, "x", 3, [1, "y"], {"a": None}):
        for key in ("dns", "maillog", "rua", "gate", "inputs", "findings", "mailflow", "rules"):
            doc = dict(json.loads(json.dumps(report)), **{key: value})
            assert verify.render(doc, plan).startswith("# Verify it yourself"), (key, value)
        assert verify.render({"findings": [value]}, {"changes": [value], "holds": [value]})
    damaged = json.loads(json.dumps(report))
    damaged["maillog"]["by_domain"]["corp.example"] = {"logical_messages": "many", "top_senders": "x",
                                                       "subdomains_total": [1]}
    damaged["maillog"]["census"] = {"by_sender": ["x", {"domain": "corp.example", "delivered_by": "y"}]}
    damaged["maillog"]["cuts"] = {"corp.example": "x"}
    assert verify.maillog_steps(damaged, "corp.example") is not None
    assert verify.render(damaged, plan)


# ------------------------------------------------------------------ review fixes: ids, commands, row shapes, robustness

def monitoring_row(name="news.corp.example", parent="corp.example"):
    """A monitoring record for a sending subdomain the run does not audit, exactly as the parallel plan work writes
    it (plan.py's monitor_unaudited): its current value says nobody looked."""
    pre = ("_dmarc.%s has no record yet - it is not audited, so this run did not look (add it to audit.toml's domains "
           "or to EXTRA_DOMAINS so the next run checks it)" % name)
    return {"domain": name, "zone": parent, "zone_host": "Route53", "kind": "new", "priority": 1, "record": "TXT",
            "hostname": "_dmarc." + name, "value": "v=DMARC1; p=none; rua=%s;" % RUA, "ttl": 3600,
            "current": "not checked (not an audited domain)", "rollback": "delete the record",
            "why": "sending subdomain without a record of its own: an explicit record shields it from the apex's sp= "
                   "change on %s (seen sending: 3 in the mail log that did not fail)" % parent,
            "prerequisites": [pre], "finding_ids": [], "owner_hint": name,
            "prerequisite_items": [{"text": pre, "kind": "other", "met": None}],
            "human_summary": "Publish a monitoring-only DMARC record for %s so its reports start flowing; no effect on "
                             "delivery." % name, "id": "P-99"}


QUIET_DMARC = "v=DMARC1; p=none; rua=mailto:r@quiet.example;"


def quiet_report():
    """A run that measured nothing sent as quiet.example: it has an MX and receives mail, the tenant counted no mail
    out, its own mail-log rows are three failing spoofs, and the aggregate reports are about another record."""
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    doc = dns_doc("quiet.example", [finding("DMARC-002", "minor", "dmarc", "DMARC p=none - monitoring only",
                                            QUIET_DMARC)],
                  dmarc=QUIET_DMARC, dmarc_source="_dmarc.quiet.example", effective_policy="none", dmarc_status="found",
                  spf="v=spf1 -all", spf_status="found", spf_terminator="-all", mx=["10 mx.quiet.example"],
                  mx_status="found")
    return {"generated_utc": NOW.strftime(stamp), "inputs": {"domains": ["quiet.example"], "rua": ["rua"]},
            "dns": {"quiet.example": doc},
            "mailflow": {"days": 30, "domains": {"quiet.example": {"messages": 3, "outbound": 0, "inbound": 3,
                                                                   "last_seen": None}}},
            "maillog": {"window": {"from": (NOW - timedelta(days=30)).strftime(stamp), "to": NOW.strftime(stamp)},
                        "cuts": {}, "by_domain": {"quiet.example": {
                            "logical_messages": 3, "passing_messages": 0, "internal_messages": 0,
                            "genuine_failures": 3, "delivered_despite_fail": 0}}},
            "rua": {"filters": {}, "by_header_from": [{"domain": "corp.example", "count": 9, "pass": 9, "fail": 0}],
                    "totals": {"domains": ["corp.example"]},
                    "policy_check": {"seen": [{"domain": "corp.example", "p": "none", "reports": 1}]}}}


def no_mail_row():
    """The quarantine-now row the parallel plan work writes for quiet.example (kind no_mail)."""
    pre = ["no sender that mails less often than monthly (statements, renewals) uses this domain",
           "no third party sends as quiet.example straight to outside recipients: no aggregate report in this run "
           "covers it, and only those would show such mail"]
    return {"domain": "quiet.example", "zone": "quiet.example", "zone_host": "Cloudflare", "kind": "no_mail",
            "priority": 1, "record": "TXT", "hostname": "_dmarc.quiet.example",
            "value": "v=DMARC1; p=quarantine; rua=mailto:r@quiet.example;", "ttl": 3600, "current": QUIET_DMARC,
            "rollback": "publish the current string verbatim",
            "why": "quarantine now: the tenant measured no mail sent as quiet.example in 30 days (none of the 3 "
                   "message(s) that came in with it as the From domain passed: spoofing, which quarantine stops) and "
                   "nothing passes as it in the mail log or the aggregate reports, so a weekly ramp would protect "
                   "nobody; reject follows once a week of reports still shows nothing passing",
            "prerequisites": pre, "finding_ids": ["DMARC-002"], "owner_hint": "quiet.example",
            "prerequisite_items": [{"text": p, "kind": plan_mod.prereq_kind(p), "met": None} for p in pre],
            "human_summary": "Move quiet.example straight to quarantine: no mail sent as it was measured in 30 days, so "
                             "no legitimate sender is caught; mail that fails checks lands in junk from now on, and the "
                             "reporting address shows every attempt.", "id": "P-06"}


GROUPS_TABLE = {"groups": {"tables": {"groups": [
    {"Name": "Sales Team", "Address": "sales@corp.example", "Kind": "UnifiedGroup", "Issues": "MEMBERS-NOT-READ"},
    {"Name": "All Dynamic", "Address": "dyn@corp.example", "Kind": "DynamicDistributionGroup",
     "Issues": "OPEN-TO-EXTERNAL"}]}}}


def group_steps(fid, title, ev, obj=None, report=None):
    f = dict(finding(fid, "info", "groups", title, ev), source="groups")
    if obj:
        f["object"] = obj
    return verify.finding_steps(f, GROUPS_TABLE if report is None else report)


def test_tenant_findings_without_an_id_are_read_from_the_export_and_picked_by_title(run):
    report, _, _ = run
    doc = json.loads(json.dumps(report))
    doc["rules"]["window"] = {"days": 14, "hits_checked": True}
    doc["groups"]["options"] = {"top": 25, "include_inbox_rules": True, "skip_members": False}
    for section, fid, script in (("rules", "RULES-000", "audit_rules.ps1 -Json -Days 14"),
                                 ("bypasses", "BYPASSES-000", "audit_bypasses.ps1 -Json"),
                                 ("groups", "GROUPS-000", "audit_groups.ps1 -Json -IncludeInboxRules")):
        f = dict(finding(fid, "minor", section, "Custom check: Partner's relay", "seen this"), source=section)
        s = verify.finding_steps(f, doc)
        check_shape(s)
        assert len(s) == 2, (fid, s)
        assert s[0]["code"] == ("(Get-Content -Raw -Path %s | ConvertFrom-Json).findings | Where-Object { -not $_.id } "
                                "| Format-List" % verify.ps(verify.shown(doc[section]["source"])))
        assert "carried no id, so audit.py named it %s" % fid in s[0]["text"]
        assert "titled 'Custom check: Partner's relay' (seen this)" in s[0]["text"]
        assert s[1]["code"] == ("(& .\\src\\%s | ConvertFrom-Json).findings | Where-Object { $_.title -eq "
                                "'Custom check: Partner''s relay' } | Format-List" % script)
        assert "$_.id -eq" not in codes(s)  # an id the export never had matches nothing
    # a finding without a title either: the export file the report read is the one place to read it
    s = verify.finding_steps(dict(finding("RULES-000", "minor", "rules", "(untitled finding)", ""), source="rules"), doc)
    assert len(s) == 1 and "Where-Object { -not $_.id }" in s[0]["code"]
    # every re-run follows the options the export ran with
    doc["rules"]["window"] = {"days": 10, "hits_checked": False}
    doc["groups"]["options"] = {"skip_members": True}
    assert verify.script_command(doc, "rules") == "(& .\\src\\audit_rules.ps1 -Json -SkipHits | ConvertFrom-Json).findings"
    assert verify.script_command(doc, "groups") == ("(& .\\src\\audit_groups.ps1 -Json -SkipMembers | ConvertFrom-Json)"
                                                     ".findings")
    assert verify.script_command(doc, "dns") is None


def test_group_findings_read_the_members_with_the_cmdlet_for_the_groups_kind():
    # GROUPS-009 for one group: the export's evidence names the group's kind first
    s = group_steps("GROUPS-009", "Membership not read: dyn@corp.example",
                    "DynamicDistributionGroup membership cmdlet failed", "dyn@corp.example")
    check_shape(s)
    assert s[0]["code"].startswith("Get-DynamicDistributionGroupMember -Identity 'dyn@corp.example' -ResultSize "
                                   "Unlimited | Where-Object { $_.RecipientTypeDetails -match 'MailContact|MailUser' }")
    assert "Get-DistributionGroupMember" not in s[0]["code"]
    assert ("# Get-Recipient -RecipientPreviewFilter (Get-DynamicDistributionGroup -Identity 'dyn@corp.example')"
            ".RecipientFilter -ResultSize Unlimited") in s[0]["code"]  # what the export ran where that cmdlet is missing
    s = group_steps("GROUPS-009", "Membership not read: sales@corp.example", "UnifiedGroup membership cmdlet failed",
                    "sales@corp.example")
    assert s[0]["code"].startswith("Get-UnifiedGroupLinks -Identity 'sales@corp.example' -LinkType Members "
                                   "-ResultSize Unlimited")
    s = group_steps("GROUPS-009", "Membership not read: dl@corp.example", "DistributionGroup membership cmdlet failed",
                    "dl@corp.example")
    assert s[0]["code"].startswith("Get-DistributionGroupMember -Identity 'dl@corp.example' -ResultSize Unlimited")
    # an Issues code from an export without findings carries the code alone: the groups table row gives the kind and
    # the address
    s = group_steps("MEMBERS-NOT-READ", "MEMBERS-NOT-READ: Sales Team", "MEMBERS-NOT-READ")
    assert s[0]["code"].startswith("Get-UnifiedGroupLinks -Identity 'sales@corp.example' -LinkType Members")
    s = group_steps("OPEN-TO-EXTERNAL", "OPEN-TO-EXTERNAL: All Dynamic", "OPEN-TO-EXTERNAL")
    assert s[1]["code"].startswith("Get-DynamicDistributionGroup -Identity 'dyn@corp.example' | Format-List")
    assert "Get-DynamicDistributionGroupMember -Identity 'dyn@corp.example' -ResultSize Unlimited" in s[1]["code"]
    s = group_steps("GROUPS-003", "Open to external senders and redistributes to external members: sales@corp.example",
                    "UnifiedGroup; RequireSenderAuthenticationEnabled=False; sender restrictions=0; external members "
                    "(1): p@outside.invalid", "sales@corp.example")
    assert s[1]["code"].startswith("Get-UnifiedGroup -Identity 'sales@corp.example' | Format-List")
    assert "\nGet-UnifiedGroupLinks -Identity 'sales@corp.example' -LinkType Members" in s[1]["code"]
    # nothing names the kind: read it first, never run a cmdlet that fails for another kind
    s = group_steps("MEMBERS-NOT-READ", "MEMBERS-NOT-READ: Unknown Group", "MEMBERS-NOT-READ")
    assert s[0]["code"] == "Get-Recipient -Identity 'Unknown Group' | Format-List Name,PrimarySmtpAddress,RecipientTypeDetails"
    assert "Get-DynamicDistributionGroupMember" in s[0]["text"] and "Get-UnifiedGroupLinks -LinkType Members" in s[0]["text"]
    s = group_steps("GROUPS-009", "Membership not read: odd@corp.example", "membership cmdlet failed", "odd@corp.example")
    assert s[0]["code"].startswith("Get-Recipient -Identity 'odd@corp.example'")


def test_a_large_exception_list_is_shown_and_counted_over_all_five_lists(run):
    report, _, _ = run
    for fid, title, ev in (("RULES-004", "Large exception list: Partner bypass",
                            "23 excepted addresses, domains or subjects; State=Enabled"),
                           ("LARGE-EXCEPTION-LIST", "LARGE-EXCEPTION-LIST: Partner bypass",
                            "LARGE-EXCEPTION-LIST: 23 entries - each one is spoofable past this rule")):
        s = verify.finding_steps(dict(finding(fid, "minor", "rules", title, ev), source="rules"), report)
        check_shape(s)
        for prop in ("ExceptIfFrom", "ExceptIfSenderDomainIs", "ExceptIfSubjectContainsWords",
                     "ExceptIfFromAddressContainsWords", "ExceptIfFromAddressMatchesPatterns"):
            assert "," + prop in s[1]["code"] and "@($r.%s)" % prop in s[2]["code"], (fid, prop)
        assert s[2]["code"].startswith("$r = Get-TransportRule -Identity 'Partner bypass'; @(")
        assert "the count is 23" in s[2]["text"]


def test_the_aggregate_report_rerun_prints_every_row_a_step_reads(run):
    report, _, _ = run
    doc = json.loads(json.dumps(report))
    doc["rua"]["by_header_from"] = [{"domain": "d%02d.example" % i, "count": 100 - i, "pass": 100 - i, "fail": 0}
                                    for i in range(24)] + [{"domain": "shop.example", "count": 3, "pass": 0, "fail": 3}]
    s = verify.rua_domain_steps(doc, "shop.example")
    assert s[0]["code"].endswith(" --top 25") and "lists shop.example with count 3" in s[0]["text"]
    assert "--top" not in verify.rua_domain_steps(doc, "d03.example")[0]["code"]  # in the 20 rows printed anyway
    # an absence is read off the whole table
    assert verify.unused_steps(doc, "parked.example")[-1]["code"].endswith(" --top 25")
    # the unknown senders quoted sit below the signing domains that outnumber them
    doc["rua"]["unknown_senders"] = [{"kind": "dkim_domain", "value": "s%02d.example" % i, "count": 900 - i, "pass": 900,
                                      "fail": 0} for i in range(22)] + [
        {"kind": "ip", "value": "198.51.100.20", "count": 120, "pass": 120, "fail": 0}]
    f = next(f for f in doc["findings"] if f["id"] == "OUTSIDE-002")
    s = verify.finding_steps(f, doc)
    assert s[0]["code"].endswith(" --top 23") and "198.51.100.20 x120 (120 pass)" in s[0]["text"]
    # a step that reads every failing stream prints them all
    doc["rua"]["failing_streams"] = [dict(doc["rua"]["failing_streams"][0], source_ip="203.0.113.%d" % i)
                                     for i in range(30)]
    ev = verify.change_steps(dict(row_of(doc), prerequisites=["deduplicated failure check at the current step shows "
                                                              "only spoofing"], prerequisite_items=[]), doc)
    assert next(x for x in ev if "no failing stream sending as" in x["text"])["code"].endswith(" --top 30")
    f = dict(finding("OUTSIDE-007", "info", "outside_view", "heuristic split", "x"), source="rua")
    assert verify.finding_steps(f, doc)[0]["code"].endswith(" --top 30")


def row_of(report):
    """A plain enforcement row for corp.example."""
    return {"domain": "corp.example", "kind": "ratchet", "record": "TXT", "hostname": "_dmarc.corp.example",
            "value": "v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA, "current": CORP_DMARC, "ttl": 3600,
            "rollback": "publish the current string verbatim", "id": "P-01", "priority": 3}


def test_collect_survives_a_latest_queries_folder_it_cannot_clear(tmp_path, monkeypatch, offline):
    out = tmp_path / "out"
    run_collect(monkeypatch, out)
    held = out / "latest" / "queries"
    (held / "sender_census_old.example.kql").write_text("// an earlier run's query\n", encoding="utf-8")
    real = shutil.rmtree

    def rmtree(path, *a, **k):  # a shell open in latest/queries: the folder and what is in it stay
        if Path(path) == held:
            return None
        return real(path, *a, **k)
    monkeypatch.setattr(collect.shutil, "rmtree", rmtree)
    second = run_collect(monkeypatch, out)
    assert (out / "latest" / "summary.txt").exists() and second["exit_code"] in (0, 1)
    assert any(n.startswith("latest/queries keeps 1 file(s) an earlier run wrote that could not be removed "
                            "(sender_census_old.example.kql)") for n in second["notes"]), second["notes"]
    fresh = out / "history" / second["run"] / "queries" / "sender_census_example.com.kql"
    assert (held / "sender_census_example.com.kql").read_bytes() == fresh.read_bytes()

    def copytree(*a, **k):  # a read-only file in the way
        raise PermissionError(13, "Access is denied", str(held / "sender_census_example.com.kql"))
    monkeypatch.setattr(collect.shutil, "copytree", copytree)
    third = run_collect(monkeypatch, out)
    assert third["run"] != second["run"] and any(n.startswith("latest/queries not refreshed (") for n in third["notes"])
    assert (out / "latest" / "summary.txt").exists() and (out / "latest" / "verify.md").exists()


def test_a_monitoring_row_for_a_name_the_run_does_not_audit(run):
    report, plan, _ = run
    mono = monitoring_row()
    s = verify.change_steps(mono, report)
    check_shape(s)
    assert [x["text"].split(":")[0] for x in s] == ["Before", "Publish at Route53 (zone corp.example)", "After",
                                                    "Roll back"]
    before = s[0]["text"]
    assert ("no answer should start with v=DMARC1 - the run did not look (plan.json says: not checked (not an audited "
            "domain))") in before
    assert "do not publish: news.corp.example already has a record of its own" in before and "reads 'not" not in before
    assert "https://dns.google/resolve?name=_dmarc.news.corp.example&type=TXT" in s[0]["code"]
    assert "the zone's negative-caching time" in s[2]["text"] and s[3]["code"] == ""
    # an SPF row whose current value nobody read: never a second record, never the words pasted back
    s = verify.change_steps(dict(mono, hostname="news.corp.example", value="v=spf1 -all",
                                 rollback="publish the current string verbatim"), report)
    assert "a second v=spf1 record makes every SPF check of the name fail" in s[0]["text"] and s[-1]["code"] == ""
    # its section says it is not audited: no DNS looked up, no failed measurement, the census it does have
    md = verify.render(report, dict(plan, changes=plan["changes"] + [mono]))
    assert "- news.corp.example: not audited (only the plan names it), 1 plan row" in md
    # its section sits with its organization, in the one order every file follows (round 12): the headline's
    # organization first, its own domain before the names below it, then each organization by name
    assert re.findall(r"^## (.+)$", md, re.M)[1:] == ["corp.example", "hr.corp.example", "news.corp.example", "dup.example",
                                                      "parked.example", "shop.example", "Across the run",
                                                      "Queries for the portal"]
    sec = md.split("## news.corp.example\n", 1)[1].split("\n## ", 1)[0]
    assert "Not audited in this run: news.corp.example is not on the domain list, so its DNS was not looked up" in sec
    assert "None, and none looked for" in sec and "No DNS finding" not in sec
    assert "queries/sender_census_news.corp.example.kql" in sec
    assert "its total column comes to about 40 and genuine_failures to 40" in sec
    assert "the report's census counted 3 messages as news.corp.example, 3 of them genuine failures, " + FLOOR in sec
    assert "news.corp.example is not audited, so the report keeps no mail-flow count for it" in sec
    assert "did not measure" not in sec and "the query failed" not in sec
    assert "#### P-99 publish: TXT _dmarc.news.corp.example (priority 1)" in sec
    # a report that keeps the same query's rows for names it does not audit (mailflow.unaudited) quotes its row,
    # and one whose query answered for the organization without it says nothing was seen
    doc = json.loads(json.dumps(report))
    doc["mailflow"]["unaudited"] = {"news.corp.example": {"messages": 40, "outbound": 0, "inbound": 40,
                                                          "last_seen": None}}
    flow = verify.mailflow_steps(doc, "news.corp.example", False)[0]
    assert "the row with d news.corp.example shows messages about 40, outbound about 0 and inbound about 40, as the " \
        "run measured (dcount estimates" in flow["text"]
    assert flow["text"].endswith("; news.corp.example is not audited, so the report keeps the same query's row for it "
                                 "as mailflow.unaudited.")
    doc["mailflow"]["unaudited"] = {}
    assert "there is no row with d news.corp.example (or one with messages 0): the tenant carried nothing as it in 30 " \
           "days, as the run measured; news.corp.example is not audited" in verify.mailflow_steps(
               doc, "news.corp.example", False)[0]["text"]
    doc["mailflow"]["domains"] = {d: None for d in doc["mailflow"]["domains"]}  # the query failed: nothing measured
    assert "the report keeps no mail-flow count for it" in verify.mailflow_steps(doc, "news.corp.example", False)[0][
        "text"]
    # without the full window the census quotes the report's own count of it
    sec = verify.render(without_totals(report), dict(plan, changes=[mono]))
    assert "its total column adds up to 3 and genuine_failures to 3, the messages the report's census counted as " \
           "news.corp.example (by sender: alerts@news.corp.example 3)" in sec


def test_a_no_mail_row_proves_nothing_is_sent_without_asking_for_a_missing_mx():
    report = quiet_report()
    s = verify.change_steps(no_mail_row(), report)
    check_shape(s)
    assert not any(lookups(x["code"], "quiet.example", "MX") for x in s) and " MX " not in texts(s)
    flow = next(x for x in s if "queries/mailflow_quiet.example.kql" in x["text"])
    assert "the run measured outbound 0 and inbound 3" in flow["text"] and "inbound mail is allowed here" in flow["text"]
    census = next(x for x in s if "queries/sender_census_quiet.example.kql" in x["text"])
    assert "the passing column adds up to 0" in census["text"] and "0 passing and 0 sent inside the tenant, of 3" in \
        census["text"]
    said = [x for x in s if "header_from domains table" in x["text"]]
    assert len(said) == 1 and ("has no row for quiet.example, but none of the reports this run read is about the "
                               "record that applies to it") in said[0]["text"]
    # once the reports cover its record, an absence there is evidence
    covered = quiet_report()
    covered["rua"]["policy_check"]["seen"].append({"domain": "quiet.example", "p": "none", "reports": 1})
    said = [x for x in verify.change_steps(no_mail_row(), covered) if "header_from domains table" in x["text"]]
    assert "the reports cover the record that applies to it and name no mail as it" in said[0]["text"]
    # the move to reject a week later rests on the same proof
    later = dict(no_mail_row(), kind="ratchet", priority=3, current="v=DMARC1; p=quarantine; rua=mailto:r@quiet.example;",
                 value="v=DMARC1; p=reject; rua=mailto:r@quiet.example;", prerequisite_items=[],
                 why="quarantine at 100 percent is stable and no mail is measured as the domain: reject refuses failing "
                     "mail instead of junking it, and with no sender there is no DKIM proof to wait for",
                 prerequisites=["a week at p=quarantine with the aggregate reports still showing nothing passing as "
                                "quiet.example"])
    s = verify.change_steps(later, report)
    assert "queries/mailflow_quiet.example.kql" in texts(s) and not any(lookups(x["code"], "quiet.example", "MX")
                                                                         for x in s)
    # the checks the plan names on the row: what the labels could not call spoofing is named source by source
    unclear = dict(no_mail_row(), prerequisite_items=[], prerequisites=[
        "the 2 message(s) that came in as quiet.example and that the mail log cannot call spoofing (a failure labelled "
        "unknown, or no DMARC verdict at all: x@quiet.example x2) are spoofs rather than a sender of ours"])
    s = verify.change_steps(unclear, report)
    named = [x for x in s if "queries/sender_census_quiet.example.kql" in x["text"]]
    assert len(named) == 2 and "every envelope domain with genuine_failures or no_verdict above 0 is a source you can " \
        "name as a spoof" in named[0]["text"]
    assert not any("queries/genuine_failures_quiet.example.kql" in x["text"] for x in s)
    # a cut organization: the rows kept are a floor, so the full window says whether anything passed outside them
    cut = quiet_report()
    cut["maillog"]["cuts"] = {"quiet.example": {"reason": "row budget", "kept_hours": 41}}
    cut["maillog"]["window_totals"] = {"hours": 720, "orgs": {"quiet.example": {"by_domain": {"quiet.example": {
        "logical_messages": 9, "passing": 0, "genuine_failures": 9, "delivered_despite_fail": 0, "delivered_by": {}}}}}}
    totals = next(x for x in verify.change_steps(no_mail_row(), cut) if "maillog_totals_quiet.example" in x["text"])
    assert "passing reads 0 over the full window" in totals["text"] and "about 9 logical messages, 0 passing" in \
        totals["text"]
    # a parked row still proves the domain receives nothing: its MX
    park = dict(no_mail_row(), kind="park", prerequisites=["verify unused first: no owner objects"], prerequisite_items=[])
    assert any(lookups(x["code"], "quiet.example", "MX") for x in verify.change_steps(park, report))


def test_the_sp_step_reads_the_subdomains_mail_in_reports_that_cover_the_record(run):
    report, _, _ = run
    pre = ("no third party sends as a subdomain without a record of its own straight to outside recipients: no "
           "aggregate report in this run covers corp.example's record, and only those would show such mail")
    sp = dict(row_of(report), priority=4, value="v=DMARC1; p=quarantine; sp=quarantine; rua=%s;" % RUA,
              prerequisites=[pre], prerequisite_items=[{"text": pre, "kind": "reports", "met": None}])
    said = [x for x in verify.change_steps(sp, report) if "header_from" in x["text"]]
    assert len(said) == 1 and "no header_from row for a subdomain of corp.example shows a passing count unless that " \
        "subdomain has a record of its own." in said[0]["text"]  # this run's reports are about its record
    doc = json.loads(json.dumps(report))
    doc["rua"]["policy_check"]["seen"], doc["rua"]["totals"]["domains"] = [], []
    doc["rua"]["by_header_from"] = [h for h in doc["rua"]["by_header_from"] if h["domain"] != "corp.example"]
    said = [x for x in verify.change_steps(sp, doc) if "header_from" in x["text"]]
    assert "read the reports that reach the address in its rua= tag" in said[0]["text"]


def test_a_failed_dmarc_lookup_is_said_to_have_failed():
    broken = dns_doc("broken.example", [finding("DMARC-006", "major", "dmarc", "DMARC lookup failed - not verified",
                                                "TXT lookup failed on every resolver path for: _dmarc.broken.example",
                                                verified=False)], dmarc_status="error")
    s = verify.policy_step({"dns": {"broken.example": broken}}, "broken.example")
    assert s["text"].startswith("Policy today: unknown - the audit's DMARC lookups for broken.example failed on every "
                                "path") and "DMARC-006" in s["text"] and "as the audit saw" not in s["text"]
    assert lookups(s["code"], "_dmarc.broken.example", servers=verify.RESOLVERS) and "dns.google" in s["code"]
    sub = dns_doc("sub.inh.example", [
        finding("DMARC-007", "minor", "dmarc", "_dmarc.sub.inh.example lookup failed - inheritance from "
                "_dmarc.inh.example assumed, not verified", "own lookup errored, _dmarc.inh.example answered",
                verified=False),
        finding("DMARC-002", "minor", "dmarc", "DMARC effective policy none - inherited (p=none on _dmarc.inh.example, "
                "no sp=) - monitoring only", "v=DMARC1; p=none; rua=mailto:r@inh.example;")],
        dmarc="v=DMARC1; p=none; rua=mailto:r@inh.example;", dmarc_source="_dmarc.inh.example",
        effective_policy="none", inherited=True, dmarc_status="found")
    rep = {"dns": {"sub.inh.example": sub}}
    s = verify.policy_step(rep, "sub.inh.example")
    assert "the audit's lookup of _dmarc.sub.inh.example failed" in s["text"]
    assert "assumed sub.inh.example inherits it - not verified" in s["text"] and "has no record of its own" not in s["text"]
    assert lookups(s["code"], "_dmarc.sub.inh.example", servers=verify.RESOLVERS)
    s = verify.finding_steps(dict(sub["findings"][1], source="dns:sub.inh.example"), rep)
    assert "the audit's lookup of _dmarc.sub.inh.example failed (DMARC-007), so it assumed no record of its own" in \
        s[0]["text"] and "has no record of its own" not in s[0]["text"]
    # an answer that is simply absent still reads as absent
    gone = dns_doc("gone.example", [finding("DMARC-001", "major", "dmarc", "NO DMARC RECORD", "no v=DMARC1 TXT at any "
                                            "of: _dmarc.gone.example")])
    assert "no answer starts with v=DMARC1, as the audit saw" in verify.policy_step({"dns": {"gone.example": gone}},
                                                                                    "gone.example")["text"]


def test_the_cli_and_render_survive_damaged_kinds_and_addresses(run, tmp_path):
    report, plan, _ = run
    doc = json.loads(json.dumps(report))
    doc["rua"]["unknown_senders"] = [{"kind": "ip", "value": ["203.0.113.5"], "count": 500, "pass": 1, "fail": 499},
                                     {"kind": "ip", "value": {"a": 1}, "count": 400, "pass": 0, "fail": 400}]
    doc["rua"]["failing_streams"][0]["source_ip"] = {"a": 1}
    doc["rua"]["by_source_ip"][0]["as_reported"] = [["x"], {"y": 1}, "203.0.113.5"]
    bad = json.loads(json.dumps(plan))
    bad["changes"][0]["kind"] = ["x"]
    bad["changes"][1]["kind"] = {"a": 1}
    md = verify.render(doc, bad)
    assert md.isascii() and "#### %s change: " % bad["changes"][0]["id"] in md
    for f in doc["findings"]:
        check_shape(verify.finding_steps(f, doc))
    (tmp_path / "r.json").write_text(json.dumps(doc), encoding="utf-8")
    (tmp_path / "p.json").write_text(json.dumps(bad), encoding="utf-8")
    p = subprocess.run([sys.executable, SCRIPT, str(tmp_path / "r.json"), "--plan", str(tmp_path / "p.json"), "--out",
                        str(tmp_path / "o")], capture_output=True, text=True)
    assert p.returncode == 0 and "Traceback" not in p.stderr, p.stderr


def test_mail_log_findings_about_the_export_itself_read_the_export(run):
    report, _, tmp = run
    path = verify.ps(verify.shown(tmp / "log.csv"))

    def one(fid, title, ev):
        return verify.finding_steps(dict(finding(fid, "minor", "maillog", title, ev), source="maillog"), report)
    s = one("MAILFLOW-006", "no authentication column: 'failure' here means never delivered, not failed DMARC", "b")
    assert s[0]["code"] == "Get-Content -Path %s -TotalCount 1" % path and "no column holds a DMARC verdict" in s[0]["text"]
    s = one("MAILFLOW-008", "optional columns absent: Subject, Direction", "detail degrades")
    assert s[0]["code"] == "Get-Content -Path %s -TotalCount 1" % path and "it lacks Subject, Direction" in s[0]["text"]
    s = one("MAILFLOW-007", "auth column DMARC holds no pass or fail value in any in-scope row", "52 rows in scope")
    assert s[0]["code"] == "Import-Csv -Path %s | Group-Object -Property DMARC | Select-Object Name, Count" % path
    s = one("MAILFLOW-009", "no rows matched --sender-domain corp.example", "52 rows read, 0 in scope")
    assert s[0]["code"] == ("Import-Csv -Path %s | Group-Object -Property 'Sender domain' | Sort-Object Count "
                            "-Descending | Select-Object -First 10 Name, Count" % path)


def test_a_source_is_searched_in_every_spelling_its_reporters_used(run):
    report, _, _ = run
    doc = json.loads(json.dumps(report))
    row = next(s for s in doc["rua"]["by_source_ip"] if s["source_ip"] == "2001:db8::25")
    row["as_reported"] = ["2001:db8::25", "2001:DB8:0:0::25"]
    raw = verify.finding_steps(next(f for f in doc["findings"] if f["id"] == "OUTSIDE-001"), doc)[1]["code"]
    assert raw.startswith("$ips = @('203.0.113.5', '2001:db8::25', '2001:DB8:0:0::25')")
    assert raw.endswith("Select-Object -First 6")


def test_an_unresolved_include_shows_the_record_and_a_hold_worded_as_a_second_record_says_what_it_is():
    report = {"dns": live_dns(["corp.example"], None)}
    f = dict(finding("SPF-007", "major", "spf", "SPF lookup count incomplete - 1 include(s) could not be resolved, 3 is "
                     "a lower bound", "spf.esp.example: LOOKUP FAILED (timeout)"), source="dns:corp.example")
    s = verify.finding_steps(f, report)
    own = next(x for x in s if x["how"] == "dns" and lookups(x["code"], "corp.example"))
    assert "one string starts with v=spf1, the record the count expands, and it reads %s" % verify._q(CORP_SPF) in \
        own["text"]
    # the plan holds the domain in words meant for two SPF records: the pointer says what the check there shows
    report["findings"] = [f]
    md = verify.render(report, {"changes": [], "holds": [{"domain": "corp.example", "reason": (
        "more than one SPF record at corp.example - receivers return permerror; collapse to one after checking who "
        "published each")}]})
    assert ("check: SPF-007 (Findings above: SPF-007 is an include the audit could not resolve, not a second record, "
            "and the TXT lookup there shows how many strings start with v=spf1)") in md


def test_the_runs_overall_figures_are_reread_and_recounted(run):
    report, _, _ = run
    s = verify.totals_steps(report)
    check_shape(s)
    t, c = report["rua"]["totals"], report["maillog"]["counters"]
    assert "messages shows %d, DMARC pass %d and DMARC fail %d" % (t["messages"], t["pass"], t["fail"]) in s[0]["text"]
    assert s[0]["code"].startswith("python src/rua_parse.py ")
    assert ("rows read shows %d, logical messages %d and GENUINE failures 13, and failed authentication but DELIVERED 4"
            % (c["raw_rows"], c["logical_messages"])) in s[1]["text"]
    assert s[1]["code"].startswith("python src/dedupe.py ")
    assert "The run's overall figures, the ones the status document quotes:" in verify.render(report)


def review_fix_blocks(report, plan):
    """The PowerShell the steps above produce, for the parser check."""
    steps = verify.change_steps(monitoring_row(), report) + verify.change_steps(no_mail_row(), quiet_report())
    steps += verify.policy_step({"dns": {"broken.example": dns_doc("broken.example", dmarc_status="error")}},
                                "broken.example"),
    for fid, title, ev, obj in (("GROUPS-009", "Membership not read: dyn@corp.example",
                                 "DynamicDistributionGroup membership cmdlet failed", "dyn@corp.example"),
                                ("MEMBERS-NOT-READ", "MEMBERS-NOT-READ: Unknown Group", "MEMBERS-NOT-READ", None),
                                ("OPEN-TO-EXTERNAL", "OPEN-TO-EXTERNAL: All Dynamic", "OPEN-TO-EXTERNAL", None)):
        steps += group_steps(fid, title, ev, obj)
    for fid, title, section in (("RULES-000", "Custom check: Partner's relay", "rules"),
                                ("RULES-004", "Large exception list: Partner's bypass", "rules")):
        steps += verify.finding_steps(dict(finding(fid, "minor", section, title, "23 excepted"), source=section), report)
    return [s["code"] for s in steps if s["code"] and s["how"] in ("dns", "command")]


def test_powershell_parses_every_command_block(run, tmp_path):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        pytest.skip("no PowerShell on this machine: the Windows CI job parses the blocks")
    report, plan, _ = run
    text = verify.render(report, plan) + verify.render(json.loads(json.dumps(report)), None)
    blocks = ["\n".join(l[len(pad):] for l in body.split("\n"))
              for pad, kind, body in re.findall(r"^( *)```(\w+)\n(.*?)\n\1```", text, re.S | re.M) if kind == "powershell"]
    assert len(blocks) > 40
    blocks += review_fix_blocks(report, plan)  # the review's new step kinds: idless re-runs, group members, counts
    (tmp_path / "blocks.json").write_text(json.dumps(blocks), encoding="utf-8")
    script = ("$bad = 0; foreach ($b in (Get-Content -Raw -Path '%s' | ConvertFrom-Json)) { $t = $null; $e = $null; "
              "[void][System.Management.Automation.Language.Parser]::ParseInput($b, [ref]$t, [ref]$e); "
              "if ($e.Count -gt 0) { $bad++; Write-Output $b; Write-Output ($e | ForEach-Object { $_.Message }) } }; "
              "Write-Output \"bad=$bad\"" % (tmp_path / "blocks.json"))
    p = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                       timeout=300)
    assert p.returncode == 0 and p.stdout.strip().endswith("bad=0"), p.stdout + p.stderr
