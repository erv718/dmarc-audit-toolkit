"""Round 10, workstream 3: the operator's requests and the round-10 leftovers.
R1: EXTRA_DOMAINS in .env adds the domains the tenant does not hold. R2: a
domain the run measured sending nothing skips the weekly ramp and goes
straight to quarantine. R3: subdomains get their own records first, then
sp= moves to quarantine while the apex is still at quarantine. R4: the
excepted share named on every count line, the exceptions text, the vendor
IP-prefix warning, the unknown-sender count, a domain exception that never
lifts a shared relay stream, and the per-IP check's documentation.
Synthetic data, offline: every network seam is stubbed."""

import csv
import json
import os
import sys
from pathlib import Path

import audit
import collect
import config
import discover
import next_steps
import notify
import plan as plan_mod

ROOT = Path(__file__).resolve().parent.parent
RUA = "mailto:dmarc-reports@corp.example"
APEX = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
COLS = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
        "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC", "Direction"]


# ------------------------------------------------------------------ a tenant shaped like the live one

class Log:
    """A synthetic mail-log export (raw_maillog.kql's columns, one row per message)."""

    def __init__(self):
        self.rows, self.n = [], 0

    def add(self, sender, subject, dmarc="pass", times=1, env=None, direction="Inbound", where=("Delivered", "Inbox"),
            recipients=1):
        for _ in range(times):
            self.n += 1
            dom = sender.rpartition("@")[2]
            for k in range(recipients):  # one row per recipient, one Message-ID per message
                self.rows.append(["2026-10-07T%02d:%02d:00Z" % (self.n // 60 % 24, self.n % 60),
                                  "<r%05d@mail.invalid>" % self.n, sender, dom, env or dom,
                                  "user%d@corp.example" % ((self.n + k) % 7), subject.replace("#", str(self.n)),
                                  where[0], where[1], dmarc, direction])
        return self

    def write(self, path):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(COLS)
            w.writerows(self.rows)
        return str(path)


def rua_report(path, domain, policy, rows):
    """One aggregate report about domain's record; rows: (source_ip, count, header_from, dkim_domain, dkim_result,
    spf_domain, spf_result)."""
    recs = "".join(
        "<record><row><source_ip>%s</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition>"
        "<dkim>%s</dkim><spf>%s</spf></policy_evaluated></row><identifiers><header_from>%s</header_from></identifiers>"
        "<auth_results>%s<spf><domain>%s</domain><scope>mfrom</scope><result>%s</result></spf></auth_results></record>"
        % (ip, n, "pass" if dres == "pass" and dkd and (dkd == hf or hf.endswith("." + dkd) or dkd.endswith("." + hf))
           else "fail", "fail", hf,
           ("<dkim><domain>%s</domain><selector>s1</selector><result>%s</result></dkim>" % (dkd, dres)) if dkd else "",
           spd, spr)
        for ip, n, hf, dkd, dres, spd, spr in rows)
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<feedback><report_metadata><org_name>reporter.example</org_name>'
        "<email>noreply@reporter.example</email><report_id>%s</report_id><date_range><begin>1790000000</begin>"
        "<end>1790086399</end></date_range></report_metadata><policy_published><domain>%s</domain><adkim>r</adkim>"
        "<aspf>r</aspf><p>%s</p><sp>none</sp><pct>100</pct></policy_published>%s</feedback>\n"
        % (path.stem, domain, policy, recs), encoding="utf-8")
    return str(path)


def dns_doc(domain, **over):
    """A domain on Microsoft 365: MX at the tenant, SPF through it, a DKIM selector; no DMARC record."""
    base = {"domain": domain, "spf": "v=spf1 include:spf.protection.outlook.com -all", "spf_status": "found",
            "spf_terminator": "-all", "spf_lookups": 2, "spf_lookups_failed": 0, "spf_verified": True,
            "dmarc": None, "dmarc_source": None, "effective_policy": None, "inherited": False,
            "dmarc_status": "absent", "dkim_selectors": ["selector1"], "dkim_status": "found",
            "mx": ["0 %s.mail.protection.outlook.com" % domain.replace(".", "-")], "mx_null": False,
            "mx_status": "found", "flags": [], "findings": [], "evidence": []}
    base.update(over)
    return base


def fid(*ids):
    return [{"id": i, "severity": "major", "area": i.split("-")[0].lower(), "title": i, "evidence": "",
             "action": "", "verified": True} for i in ids]


def inherits(domain, **over):
    """A subdomain with no record of its own, under corp.example's p=quarantine; sp=none."""
    return dns_doc(domain, **dict(dict(dmarc=APEX, dmarc_source="_dmarc.corp.example", inherited=True,
                                       effective_policy="none", dmarc_status="found", mx=[], mx_status="absent",
                                       findings=fid("DMARC-002")), **over))


def flow(out=0, inn=0):
    return {"messages": out + inn, "outbound": out, "inbound": inn, "last_seen": None}


def no_record(*names):
    """report.dns_extra as collect.py writes it when DNS shows no record at these names' own _dmarc."""
    return {n: {"dmarc": None, "status": "absent", "source": None, "path": "port53-udp"} for n in names}


TENANT = ["corp.example", "mail.corp.example", "hr.corp.example", "old.corp.example", "legacy.corp.example",
          "brand.example", "spoofed.example"]
EXTRA = ["parked.example"]  # a registrar-only domain, from EXTRA_DOMAINS


def live_tenant(tmp_path):
    """report.json as collect.py writes it for a tenant shaped like the live one: corp.example at
    p=quarantine; sp=none, its row budget cut and its whole window counted in advanced hunting; audited
    subdomains that send (mail., hr. with a record of its own) and silent ones (old. parked, legacy. only
    spoofed); m., t. and e.corp.example sending through a marketing platform, unaudited, seen only in the
    mail log's subdomains_total and in the reports' by_header_from; brand.example on Microsoft 365 sending
    nothing; parked.example registrar-only with no records; spoofed.example whose only mail is spoofing."""
    log = (Log().add("staff@corp.example", "Weekly report #", times=40, direction="Outbound")
           .add("billing@corp.example", "Statement #", dmarc="fail", times=6, env="corp.example")
           .add("ceo@corp.example", "Urgent wire transfer #", dmarc="fail", times=12, env="evil.invalid")
           .add("relay@mail.corp.example", "Ticket #", times=10, direction="Outbound")
           .add("people@hr.corp.example", "Payslip #", times=5, direction="Outbound")
           .add("ceo@legacy.corp.example", "Invoice overdue #", dmarc="fail", times=15, env="evil.invalid")
           .add("news@m.corp.example", "Offer #", times=8, env="esp.invalid")
           .add("deals@t.corp.example", "Deal #", times=6, env="esp.invalid")
           .add("ceo@spoofed.example", "Password reset #", dmarc="fail", times=30, env="evil.invalid"))
    reports = [rua_report(tmp_path / "corp.xml", "corp.example", "quarantine", [
                   ("192.0.2.10", 900, "corp.example", "corp.example", "pass", "corp.example", "pass"),
                   ("198.51.100.20", 300, "e.corp.example", "e.corp.example", "pass", "esp.invalid", "pass"),
                   ("192.0.2.11", 50, "mail.corp.example", "mail.corp.example", "pass", "corp.example", "pass")]),
               rua_report(tmp_path / "spoofed.xml", "spoofed.example", "none", [
                   ("203.0.113.66", 800, "spoofed.example", None, None, "evil.invalid", "fail")])]
    names = TENANT + EXTRA
    flows = {"corp.example": flow(52000, 9000), "mail.corp.example": flow(400, 0), "hr.corp.example": flow(120, 3),
             "old.corp.example": flow(), "legacy.corp.example": flow(0, 15), "brand.example": flow(),
             "parked.example": flow(), "spoofed.example": flow(0, 30)}
    cut = {"corp.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T22:00:00Z"}}
    totals = {"hours": 720, "orgs": {"corp.example": {"source": collect.AGGREGATE_SOURCE, "by_domain": {
        "corp.example": {"logical_messages": 61000, "passing": 60000, "genuine_failures": 900,
                         "delivered_despite_fail": 12},
        "e.corp.example": {"logical_messages": 200, "passing": 200, "genuine_failures": 0, "delivered_despite_fail": 0},
        "legacy.corp.example": {"logical_messages": 15, "passing": 0, "genuine_failures": 15,
                                "delivered_despite_fail": 0}}}}}
    rep = audit.build_report(domains=names, rua_paths=reports, maillog=log.write(tmp_path / "maillog.csv"),
                             offline=True, auth_column="DMARC",
                             domain_sources=dict({d: ["tenant"] for d in TENANT}, **{d: ["env"] for d in EXTRA}),
                             mailflow={"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": flows},
                             maillog_cuts=cut, window_totals=totals)
    rep["dns"] = {
        "corp.example": dns_doc("corp.example", dmarc=APEX, dmarc_source="_dmarc.corp.example",
                                effective_policy="quarantine", dmarc_status="found"),
        "mail.corp.example": inherits("mail.corp.example"),
        "hr.corp.example": dns_doc("hr.corp.example", dmarc="v=DMARC1; p=none; rua=%s;" % RUA,
                                   dmarc_source="_dmarc.hr.corp.example", effective_policy="none", dmarc_status="found",
                                   mx=[], mx_status="absent", findings=fid("DMARC-002")),
        "old.corp.example": inherits("old.corp.example", spf=None, spf_status="absent", spf_terminator=None,
                                     dkim_selectors=[], dkim_status="absent", findings=fid("DMARC-002", "SPF-001")),
        "legacy.corp.example": inherits("legacy.corp.example", dkim_selectors=[], dkim_status="absent"),
        "brand.example": dns_doc("brand.example", dkim_selectors=[], dkim_status="absent", findings=fid("DMARC-001")),
        "parked.example": dns_doc("parked.example", spf=None, spf_status="absent", spf_terminator=None, mx=[],
                                  mx_status="absent", dkim_selectors=[], dkim_status="absent",
                                  findings=fid("DMARC-001", "SPF-001")),
        "spoofed.example": dns_doc("spoofed.example", dmarc="v=DMARC1; p=none; rua=%s;" % RUA,
                                   dmarc_source="_dmarc.spoofed.example", effective_policy="none",
                                   dmarc_status="found", findings=fid("DMARC-002")),
    }
    rep["gate"] = audit.gate_verdict(rep["dns"], rep["rua"], rep["maillog"], names, None, {},
                                     rep["inputs"]["domain_sources"])
    # collect.py looks up the unaudited sending subdomains' own records: DNS shows none at the three
    rep["dns_extra"] = no_record("m.corp.example", "t.corp.example", "e.corp.example")
    return rep


def audited(tmp_path, docs, log=None, reports=(), flows=None, sources=None, **kw):
    """report.json as collect.py writes it for the domains in docs (their DNS documents): the mail log and the
    aggregate reports read offline, the mail flow measured over 30 days, and the gate decided on all of it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    names = list(docs)
    maillog = log.write(tmp_path / "maillog.csv") if log is not None else None
    rep = audit.build_report(domains=names, rua_paths=list(reports), maillog=maillog, offline=True,
                             auth_column="DMARC" if maillog else None, domain_sources=sources,
                             mailflow={"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": dict(flows or {})}, **kw)
    rep["dns"] = docs
    rep["gate"] = audit.gate_verdict(docs, rep["rua"], rep["maillog"], names, None, {}, rep["inputs"]["domain_sources"])
    return rep


def own_record(domain, policy="none", extra=""):
    """A domain with a DMARC record of its own at this policy, on Microsoft 365."""
    return dns_doc(domain, dmarc="v=DMARC1; p=%s;%s rua=%s;" % (policy, extra, RUA), dmarc_source="_dmarc." + domain,
                   effective_policy=policy, dmarc_status="found", findings=fid("DMARC-002") if policy == "none" else [])


def rows_by(p):
    out = {}
    for c in p["changes"]:
        out.setdefault(c["domain"], []).append(c)
    return out


def plan_of(rep, inventory=None):
    return plan_mod.build_plan(rep, inventory, None)


def one(changes, kind=None, host=None):
    hits = [c for c in changes if (kind is None or c["kind"] == kind) and (host is None or c["hostname"] == host)]
    assert len(hits) == 1, (kind, host, [(c["kind"], c["hostname"]) for c in changes])
    return hits[0]


def alternative(other, host="_dmarc.corp.example"):
    """The prerequisite a row carries when another row rewrites the same record from today's value."""
    return ("one change to %s a week: this row and the other row for it (%s) each rewrite today's record, so apply "
            "one and let the next run propose the rest from the new value" % (host, other))


# ------------------------------------------------------------------ R1: EXTRA_DOMAINS

def test_r1_discover_adds_the_env_domains_as_their_own_source_and_notes_bad_entries():
    inv, notes = discover.discover(["corp.example"], use_graph=False, ns_lookup=False,
                                   extra_domains="brand.example, parked.example\tnot_a_domain corp.example")
    by = {r["domain"]: r for r in inv}
    assert set(by) == {"corp.example", "brand.example", "parked.example"}
    assert by["brand.example"]["sources"] == ["env"] and by["parked.example"]["sources"] == ["env"]
    assert by["corp.example"]["sources"] == ["cli", "env"]  # named twice, listed once
    assert by["brand.example"]["org_domain"] == "brand.example" and by["brand.example"]["tenant_verified"] is None
    assert "listed in .env (EXTRA_DOMAINS): 3 domains, 2 not already named" in notes
    assert "sources: cli = on the command line, env = listed in .env" in discover.render(inv, notes)
    assert "ignored non-domain entries in EXTRA_DOMAINS (.env): not_a_domain" in notes  # noted, never fatal
    inv, _ = discover.discover([], use_graph=False, ns_lookup=False, extra_domains=["x.example y.example"])
    assert [r["domain"] for r in inv] == ["x.example", "y.example"]  # a list of strings splits the same way
    assert discover.discover([], use_graph=False, ns_lookup=False, extra_domains="")[0] == []


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AZURE_", "EXO_")) and k not in (discover.EXTRA_KEY, "RUA_MAILBOX")}
    env.update(extra)
    return env


def test_r1_discover_cli_reads_extra_domains_with_the_env_file_and_not_with_no_graph(tmp_path):
    import subprocess
    env_file = tmp_path / "creds.env"
    env_file.write_text("# no credentials here\nEXTRA_DOMAINS=brand.example, parked.example, bad_one\n",
                        encoding="utf-8")
    script = str(ROOT / "src" / "discover.py")
    p = subprocess.run([sys.executable, script, "--env-file", str(env_file), "--no-ns", "--json"],
                       capture_output=True, text=True, env=clean_env(), timeout=120)
    assert p.returncode == 0, p.stderr
    data = json.loads(p.stdout)
    assert [(d["domain"], d["sources"]) for d in data["domains"]] == [("brand.example", ["env"]),
                                                                     ("parked.example", ["env"])]
    assert any("tenant lookup skipped" in n for n in data["notes"])  # no credentials: the tenant adds nothing
    assert "ignored non-domain entries in EXTRA_DOMAINS (.env): bad_one" in data["notes"]
    # --no-graph reads no .env, so no EXTRA_DOMAINS either
    p = subprocess.run([sys.executable, script, "--env-file", str(env_file), "--no-graph", "--no-ns"],
                       capture_output=True, text=True, env=clean_env(), timeout=120)
    assert p.returncode == 2 and "nothing to discover" in p.stderr


def empty_hunting(tok, kql, ts=None):
    """An advanced hunting endpoint with no mail at all: every count and every row query answers empty."""
    if "summarize messages = dcount(InternetMessageId)" in kql:
        return {"schema": [{"name": c} for c in ("d", "messages", "outbound", "inbound", "last_seen")], "results": []}
    if "summarize n = count()" in kql:
        return {"schema": [{"name": "hago"}, {"name": "dir"}, {"name": "n"}], "results": []}
    return {"schema": [{"name": c} for c in COLS], "results": []}


def stub_tenant(monkeypatch, tenant):
    """collect.main's network seams, stubbed; sockets refused. graph_client.creds is the real one: it loads
    the env file the test writes (into a private copy of the environment). The _dmarc lookups collect.py makes
    for the unaudited sending subdomains answer with no record."""
    import socket
    import dns_audit

    def refuse(*a, **k):
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(dns_audit, "resolve_ex", lambda resolver, name, rtype: (
        [], {"path": "stub", "ttl": None, "status": "absent"}))
    monkeypatch.setattr(os, "environ", clean_env())  # what the env file loads stays in this test
    monkeypatch.setattr(collect.graph_client, "hunting", empty_hunting)
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: (tenant, None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
    monkeypatch.setattr(audit, "run_dns", lambda domains, resolver, selectors=(): {
        d: dns_doc(d, dmarc="v=DMARC1; p=none; rua=%s;" % RUA, dmarc_source="_dmarc." + d, effective_policy="none",
                   dmarc_status="found") for d in domains})


def run_collect(monkeypatch, out, *argv):
    monkeypatch.setattr(sys, "argv", ["collect.py", "--no-config", "--no-owners", "--no-notify", "--out", str(out)]
                        + list(argv))
    try:
        collect.main()
    except SystemExit:
        pass
    latest = out / "latest"
    return {n: json.loads((latest / n).read_text(encoding="utf-8")) for n in ("report.json", "run.json", "inventory.json")}


def test_r1_collect_audits_the_tenants_domains_and_the_env_ones_beside_them(monkeypatch, tmp_path):
    tenant = [{"domain": "corp.example", "verified": True, "services": ["Email"], "default": True},
              {"domain": "corp.onmicrosoft.com", "verified": True, "services": ["Email"]}]
    stub_tenant(monkeypatch, tenant)
    env_file = tmp_path / "test.env"
    env_file.write_text("AZURE_TENANT_ID=t\nAZURE_CLIENT_ID=c\nAZURE_CLIENT_SECRET=s\n"
                        "EXTRA_DOMAINS=brand.example parked.example,not_a_domain\n", encoding="utf-8")
    files = run_collect(monkeypatch, tmp_path / "out", "--env-file", str(env_file))
    rep, run, inv = files["report.json"], files["run.json"], files["inventory.json"]
    sources = {r["domain"]: r["sources"] for r in inv["domains"]}
    assert sources == {"corp.example": ["tenant", "default"], "brand.example": ["env"], "parked.example": ["env"]}
    assert rep["inputs"]["domain_sources"] == sources
    assert set(rep["inputs"]["domains"]) == set(sources) and set(rep["gate"]["domains"]) == set(sources)
    # an env domain is never a typed headline: the tenant's default domain still heads the report
    assert rep["gate"]["headline_domain"] == "corp.example"
    assert "first" not in (rep["gate"]["headline_source"] or "")
    assert "ignored non-domain entries in EXTRA_DOMAINS (.env): not_a_domain" in run["notes"]
    # every audited name, the env ones included, has its mail flow measured
    assert rep["mailflow"]["domains"]["brand.example"] == discover.MAILFLOW_NONE


def test_r1_an_offline_or_no_graph_run_reads_no_env_domains(monkeypatch, tmp_path):
    stub_tenant(monkeypatch, [])
    os.environ[discover.EXTRA_KEY] = "brand.example"  # even when the environment holds it
    log = Log().add("staff@corp.example", "Weekly #", times=3).write(tmp_path / "log.csv")
    files = run_collect(monkeypatch, tmp_path / "out", "corp.example", "--offline", "--maillog", log,
                        "--auth-column", "DMARC")
    assert [r["domain"] for r in files["inventory.json"]["domains"]] == ["corp.example"]
    files = run_collect(monkeypatch, tmp_path / "out2", "corp.example", "--no-graph", "--maillog", log,
                        "--auth-column", "DMARC")  # DNS still runs (stubbed); .env is not read
    assert [r["domain"] for r in files["inventory.json"]["domains"]] == ["corp.example"]
    assert set(files["report.json"]["dns"]) == {"corp.example"}


def test_r1_docs_name_the_key_and_what_a_domain_hosted_elsewhere_shows():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "# EXTRA_DOMAINS=brand.example, parked.example" in env
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for text in (readme, agents):
        assert "EXTRA_DOMAINS" in text and "tenant" in text
    step2 = readme.split("## Step 2", 1)[1].split("## Step 3", 1)[0]
    assert "EXTRA_DOMAINS" in step2 and "aggregate reports" in step2
    tools = next(l for l in readme.splitlines() if l.startswith("| `src/discover.py`"))
    assert "EXTRA_DOMAINS" in tools


# ------------------------------------------------------------------ R2: no mail measured, quarantine now

def test_r2_a_domain_that_sends_nothing_goes_straight_to_quarantine(tmp_path):
    rep = live_tenant(tmp_path)
    p = plan_of(rep)
    by = rows_by(p)
    # brand.example: Microsoft 365 MX, no DMARC record, nothing in or out in 30 days, no report covers it
    brand = one(by["brand.example"], "no_mail")
    assert brand["priority"] == 1 and brand["hostname"] == "_dmarc.brand.example"
    assert brand["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA and brand["current"] == "none"
    assert brand["prerequisites"] == [
        "no sender that mails less often than monthly (statements, renewals) uses this domain",
        "no third party sends as brand.example straight to outside recipients: no aggregate report in this run "
        "covers it, and only those would show such mail",
        # its new record reports to corp.example's mailbox, in another organization (RFC 7489 7.1)
        plan_mod.external_destination("brand.example", RUA)]
    # the plain words say what was measured and that the checks come first, never that nobody can be caught
    assert brand["human_summary"].startswith("Move brand.example straight to quarantine instead of the weekly ramp, "
                                             "once the checks listed with it are confirmed: this run measured no mail "
                                             "sent as it")
    assert "no legitimate sender is caught" not in brand["human_summary"]
    assert [c["kind"] for c in by["brand.example"]] == ["no_mail"]  # no ramp row, no DKIM task: nothing sends
    # spoofed.example: its only mail is spoofing, which is no reason to wait; its own record keeps its rua
    spoofed = one(by["spoofed.example"], "no_mail")
    assert spoofed["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    assert spoofed["current"] == "v=DMARC1; p=none; rua=%s;" % RUA
    assert spoofed["prerequisites"] == ["no sender that mails less often than monthly (statements, renewals) uses "
                                        "this domain"]  # the reports cover it and show nothing passing
    assert ("none of the 30 message(s) that came in with it as the From domain passed, and the mail log examined "
            "every one: 30 logical message(s), 30 look like spoofing, which quarantine stops; the aggregate reports "
            "count none passing as it, so a weekly ramp would protect nobody") in spoofed["why"]
    assert not [c for c in by["spoofed.example"] if c["kind"] == "ratchet"]
    # legacy.corp.example: a silent subdomain with SPF, only spoofed; its own record, straight at quarantine
    legacy = one(by["legacy.corp.example"], "no_mail")
    assert legacy["value"] == "v=DMARC1; p=quarantine; rua=%s;" % RUA
    # the parked rule comes first where it applies: old.corp.example and the registrar-only parked.example
    for d in ("old.corp.example", "parked.example"):
        assert {c["kind"] for c in by[d]} == {"park"}
    # a domain that sends keeps its weekly ramp
    assert one(by["hr.corp.example"], "ratchet")["value"] == "v=DMARC1; p=quarantine; pct=25; rua=%s;" % RUA


def test_r2_the_plan_md_row_the_table_and_todo_say_it_in_plain_words(tmp_path):
    rep = live_tenant(tmp_path)
    p = plan_of(rep)
    brand = one(rows_by(p)["brand.example"], "no_mail")
    quiet = [c["id"] for c in p["changes"] if c["kind"] == "no_mail"]
    zero_risk = [c["id"] for c in p["changes"] if c["priority"] == 1 and c["kind"] != "no_mail"]
    md = plan_mod.render_md(p)
    assert "| %s | brand.example | unknown | 1 | no mail measured: quarantine now |" % brand["id"] in md
    # the row says what the run read, and nothing more: no mail log rows, no aggregate report about it
    assert ("- **%s** brand.example - quarantine now: the tenant measured no mail sent as brand.example in 30 days; "
            "nothing came in with it as the From domain; no aggregate report in this run covers it (see the checks), "
            "so a weekly ramp would protect nobody; reject follows once a week of reports still shows nothing "
            "passing" % brand["id"]) in md
    # priority 1 is zero-risk only for monitoring and hygiene; a quarantine-now row waits on its checks
    assert ("## Priority 1 - now - monitoring and hygiene (zero delivery risk), and quarantine where no mail is "
            "measured (after its checks)") in md
    assert "none of it touches mail anyone legitimately sends" not in md
    assert "A no-mail-measured row is different: it quarantines a domain the run measured sending nothing" in md
    doc = next_steps.build(rep, p)
    row = next(g for g in doc["per_domain"] if g["domains"] == ["brand.example"])
    assert row["next_step"] == "no mail measured: quarantine now"
    # the gate's verdict is the weekly ramp's, which the row skips: no cell reads as both at once
    assert ("| `brand.example` | no DMARC record | not yet (for the weekly ramp this skips) | no mail measured: "
            "quarantine now (plan %s) | nothing sent or received in 30 days (tenant) |" % brand["id"]) in \
        next_steps.render_md(doc)
    # the ask counts the quarantine-now rows apart from the zero-risk records
    assert ("approval to publish the %d zero-risk records (plan %s) in the next DNS change window, of which 2 are "
            "park rows that need the domain's unused check first; approval to move 3 domains that send no mail "
            "straight to quarantine (plan %s) once the checks listed with each are confirmed"
            % (len(zero_risk), next_steps.id_range(zero_risk), next_steps.id_range(quiet))) in doc["ask"]
    todo = collect.render_todo(rep, p)
    assert ("## 2. Do now (plan priority 1: monitoring and hygiene, zero delivery risk; quarantine where no mail is "
            "measured, after its checks)") in todo
    do_now = todo.split("## 2. Do now", 1)[1].split("## 3.", 1)[0]
    assert ("- %s brand.example: TXT at `_dmarc.brand.example` = `v=DMARC1; p=quarantine; sp=none; rua=%s;` (current: `none`) "
            "- quarantine now: " % (brand["id"], RUA)) in do_now
    assert do_now.count("  - before applying: no sender that mails less often than monthly (statements, renewals) "
                        "uses this domain") == 3
    stands = todo.split("## Where each domain stands", 1)[1].split("## 1.", 1)[0]
    assert ("- brand.example: p=unknown, next step: no mail measured, quarantine now (%s, section 2); the gate's no_go "
            "is for the weekly ramp this skips" % brand["id"]) in stands
    assert ("- spoofed.example: p=none, next step: no mail measured, quarantine now (%s, section 2); the gate's no_go "
            "is for the weekly ramp this skips" % one(rows_by(p)["spoofed.example"], "no_mail")["id"]) in stands
    text = notify.summarize(rep, plan=p)
    assert "are zero-risk monitoring/hygiene, 3 move domains that send no mail straight to quarantine;" in text
    assert ("- `spoofed.example`: p=none, next: no mail measured, quarantine now (plan %s); the gate's *no_go* is for "
            "the weekly ramp this skips - 30 genuine failures of its own"
            % one(rows_by(p)["spoofed.example"], "no_mail")["id"]) in text
    # no single line recommends the ramp's low pct and quarantine now at once
    for line in (stands + "\n" + text).splitlines():
        assert not ("quarantine now" in line and "pct=10" in line), line


def quiet_report(**over):
    """One domain, brand.example, on Microsoft 365 with a p=none record and rua; reports about that record; the
    tenant measured nothing in or out over 30 days; a mail log with no rows for it."""
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": ["brand.example"]}, "gate": {"domains": {}},
           "dns": {"brand.example": dns_doc("brand.example", dmarc="v=DMARC1; p=none; rua=%s;" % RUA,
                                            dmarc_source="_dmarc.brand.example", effective_policy="none",
                                            dmarc_status="found", findings=fid("DMARC-002"))},
           "mailflow": {"days": 30, "domains": {"brand.example": flow()}},
           "maillog": {"sender_domain": None, "counters": {"by_likely": {}}, "alignment": {"available": True},
                       "by_domain": {"brand.example": {"logical_messages": 0, "passing_messages": 0,
                                                       "internal_messages": 0, "genuine_failures": 0,
                                                       "by_likely": {}}}},
           "rua": {"totals": {"messages": 10, "domains": ["brand.example"]},
                   "policy_check": {"seen": [{"domain": "brand.example", "p": "none"}]},
                   "by_header_from": [{"domain": "brand.example", "count": 10, "pass": 0, "fail": 10}],
                   "failing_streams": [], "spf_only_senders": []}}
    for path, value in over.items():
        *keys, last = path.split("/")
        node = rep
        for k in keys:
            node = node[k]
        node[last] = value
    return rep


def kinds(rep):
    return sorted(c["kind"] for c in plan_of(rep)["changes"] if c["domain"] == "brand.example")


def test_r2_every_condition_must_hold_and_spoofing_is_no_reason_to_wait():
    assert kinds(quiet_report()) == ["no_mail"]
    own = "maillog/by_domain/brand.example"
    for path, value in (("mailflow/domains/brand.example", flow(out=3)),        # mail out from the tenant
                        ("mailflow/domains/brand.example", None),               # not measured
                        ("mailflow/days", 7),                                   # measured over too short a span
                        (own + "/passing_messages", 4),                         # a passing message of its own
                        (own + "/internal_messages", 2),                        # internal mail of its own
                        (own + "/by_likely", {"likely_misconfigured_sender": 1}),  # our own system, failing
                        (own + "/excepted", 1),                                  # an explained sender of ours
                        (own + "/passing_messages", "4"),                        # a damaged count verifies nothing
                        ("rua/by_header_from", [{"domain": "brand.example", "count": 9, "pass": 9, "fail": 0}]),
                        ("rua/failing_streams", [{"source_ip": "192.0.2.9", "count": 40, "fail": 40,
                                                  "header_from": ["brand.example"], "likely": "likely_misconfigured",
                                                  "likely_signals": []}])):
        assert "no_mail" not in kinds(quiet_report(**{path: value})), path
    # spoofing in, none of it passing, the mail log's rows holding every message: still quarantine now
    spoofed = {"logical_messages": 40, "passing_messages": 0, "internal_messages": 0, "genuine_failures": 40,
               "by_likely": {"likely_spoof": 40}}
    assert kinds(quiet_report(**{"mailflow/domains/brand.example": flow(inn=40), own: spoofed})) == ["no_mail"]
    # the rows hold less than came in (a cut log, a shorter window): what it did not see may pass, so not
    assert "no_mail" not in kinds(quiet_report(**{"mailflow/domains/brand.example": flow(inn=40),
                                                  own: dict(spoofed, logical_messages=4, genuine_failures=4)}))
    # with no mail log to tell that mail apart, not either
    no_log = quiet_report(**{"mailflow/domains/brand.example": flow(inn=40)})
    no_log["maillog"] = None
    assert "no_mail" not in kinds(no_log)
    no_log["mailflow"]["domains"]["brand.example"] = flow()  # nothing came in either: the log has nothing to add
    assert kinds(no_log) == ["no_mail"]
    # a cut organization: the full window counted in advanced hunting must show nothing passing as well
    cut = quiet_report()
    cut["maillog"]["window_totals"] = {"hours": 720, "orgs": {"brand.example": {"by_domain": {
        "brand.example": {"logical_messages": 5, "passing": 5, "genuine_failures": 0}}}}}
    assert "no_mail" not in kinds(cut)


def test_r2_quarantine_drops_the_pct_and_reject_follows_without_a_dkim_proof():
    sample = quiet_report(**{"dns/brand.example/dmarc": "v=DMARC1; p=quarantine; pct=25; rua=%s; fo=1;" % RUA,
                             "dns/brand.example/effective_policy": "quarantine"})
    row = one(plan_of(sample)["changes"], "no_mail")
    assert row["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s; fo=1;" % RUA  # no pct: 100 percent
    # a week later, at quarantine and still nothing passing: reject, with no DKIM proof to wait for
    week = quiet_report(**{"dns/brand.example/dmarc": "v=DMARC1; p=quarantine; rua=%s;" % RUA,
                           "dns/brand.example/effective_policy": "quarantine"})
    step = one(plan_of(week)["changes"], "ratchet")
    assert step["priority"] == 3 and step["value"] == "v=DMARC1; p=reject; rua=%s;" % RUA
    # the quarantine-now row's check stays open: a week at quarantine shows no sender that mails monthly
    assert step["prerequisites"] == ["a week at p=quarantine with the aggregate reports still showing nothing "
                                     "passing as brand.example",
                                     "no sender that mails less often than monthly (statements, renewals) uses this "
                                     "domain"]
    assert not any("DKIM" in x for x in step["prerequisites"])
    # no subdomain is known, so the row says nothing about sp=, and nothing about a step that never comes
    assert step["why"].endswith("with no sender there is no DKIM proof to wait for")
    # a week later with no report covering it: the reject row says so and carries the third-party check over
    unseen = quiet_report(**{"dns/brand.example/dmarc": "v=DMARC1; p=quarantine; rua=%s;" % RUA,
                             "dns/brand.example/effective_policy": "quarantine"})
    unseen["rua"] = None
    assert one(plan_of(unseen)["changes"], "ratchet")["prerequisites"] == [
        "a week at p=quarantine with aggregate reports that cover brand.example showing nothing passing as it (none "
        "in this run covers it yet)",
        "no sender that mails less often than monthly (statements, renewals) uses this domain",
        "no third party sends as brand.example straight to outside recipients: no aggregate report in this run "
        "covers it, and only those would show such mail"]
    # the same domain with a sender keeps the DKIM proof before reject
    busy = quiet_report(**{"dns/brand.example/dmarc": "v=DMARC1; p=quarantine; rua=%s;" % RUA,
                           "dns/brand.example/effective_policy": "quarantine",
                           "mailflow/domains/brand.example": flow(out=12)})
    assert any("aligned DKIM header" in x for x in one(plan_of(busy)["changes"], "ratchet")["prerequisites"])


def test_r2_a_quiet_apex_keeps_its_sending_subdomains_where_they_are():
    rep = quiet_report()
    rep["rua"]["by_header_from"].append({"domain": "news.brand.example", "count": 70, "pass": 70, "fail": 0})
    rep["dns_extra"] = no_record("news.brand.example")  # collect.py's lookup: DNS shows none at its own name
    p = plan_of(rep)
    row = one(p["changes"], "no_mail")
    assert row["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    assert "sp=none keeps its subdomains where they are until the ones that send (news.brand.example)" in row["why"]
    sub = one(p["changes"], "new", "_dmarc.news.brand.example")
    assert sub["domain"] == "news.brand.example" and sub["value"] == "v=DMARC1; p=none; rua=%s;" % RUA


def test_r2_a_failure_the_labels_cannot_call_spoofing_is_a_check_never_spoofing(tmp_path):
    """dedupe labels a failure unknown when its envelope is the domain itself or a sending platform and its subject
    is a one-off: our own statements system as readily as a spoof. The quiet row names it as a check, with the
    sender, and never calls it spoofing; a failure a formal exception covers is an explained sender of ours, and
    no quarantine-now row is proposed at all."""
    docs = {"brand.example": own_record("brand.example")}
    log = (Log().add("billing@brand.example", "Your October statement", dmarc="fail", env="brand.example")
           .add("ceo@brand.example", "Urgent wire #", dmarc="fail", times=2, env="evil.invalid"))
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [
        ("203.0.113.5", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    rep = audited(tmp_path / "unclear", docs, log, reports, flows={"brand.example": flow(0, 3)})
    assert rep["maillog"]["by_domain"]["brand.example"]["by_likely"] == {
        "likely_spoof": 2, "likely_misconfigured_sender": 0, "unknown": 1}
    row = one(plan_of(rep)["changes"], "no_mail")
    assert ("none of the 3 message(s) that came in with it as the From domain passed, and the mail log examined every "
            "one: 3 logical message(s), 2 look like spoofing, which quarantine stops, and 1 it cannot call spoofing, "
            "named in the checks") in row["why"]
    assert row["prerequisites"] == [
        "no sender that mails less often than monthly (statements, renewals) uses this domain",
        "the 1 message(s) that came in as brand.example and that the mail log cannot call spoofing (a failure "
        "labelled unknown, or no DMARC verdict at all: billing@brand.example x1) are spoofs rather than a sender of "
        "ours"]
    # an envelope at a sending platform reads the same way
    log = Log().add("renewals@brand.example", "Your renewal is due", dmarc="fail", env="sendgrid.net")
    rep = audited(tmp_path / "esp", docs, log, reports, flows={"brand.example": flow(0, 1)})
    row = one(plan_of(rep)["changes"], "no_mail")
    assert "every one: 1 logical message(s), 1 it cannot call spoofing, named in the checks" in row["why"]
    assert "like spoofing" not in row["why"]
    assert "renewals@brand.example x1" in row["prerequisites"][-1]
    # a failure a formal exception covers: the operator explained a sender of ours, so the ramp stays
    log = Log().add("scan@brand.example", "Scan #", dmarc="fail", times=2, env="printer.invalid")
    rep = audited(tmp_path / "excepted", docs, log, reports, flows={"brand.example": flow(0, 2)},
                  exceptions=[EXCEPTION])
    assert rep["maillog"]["by_domain"]["brand.example"]["excepted"] == 2
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]


def test_r2_the_mail_log_must_have_examined_the_mail_that_came_in(tmp_path):
    """The mail flow counts what came in over 30 days; the mail log's rows may hold less (the row budget cut the
    organization, or a shorter window). What it did not see may pass, so the fast path needs the rows, or a cut
    organization's full-window totals, to cover the inbound count - and never claims more than they examined."""
    docs = {"brand.example": own_record("brand.example")}
    reports = [rua_report(tmp_path / "brand.xml", "brand.example", "none", [
        ("203.0.113.5", 40, "brand.example", None, None, "evil.invalid", "fail")])]
    log = Log().add("ceo@brand.example", "Reset your password #", dmarc="fail", times=2, env="evil.invalid")
    cut = {"brand.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T22:00:00Z"}}
    # 20 came in, the rows kept hold 2, and the full window was not counted (the query failed): the ramp stays
    rep = audited(tmp_path / "cut", docs, log, reports, flows={"brand.example": flow(0, 20)}, maillog_cuts=cut)
    assert rep["maillog"].get("window_totals") is None
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]
    # a mail log over a shorter window than the mail flow (collect --days 7): 5 came in, the rows hold 2
    rep = audited(tmp_path / "short", docs, log, reports, flows={"brand.example": flow(0, 5)})
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]
    # every message in the rows: quarantine now, and the why says the log examined them all
    rep = audited(tmp_path / "all", docs, log, reports, flows={"brand.example": flow(0, 2)})
    assert ("the mail log examined every one: 2 logical message(s), 2 look like spoofing, which quarantine stops"
            in one(plan_of(rep)["changes"], "no_mail")["why"])
    # the same rows when the row budget cut the organization's log, with no full window: a floor, whatever it holds
    rep = audited(tmp_path / "floor", docs, log, reports, flows={"brand.example": flow(0, 2)}, maillog_cuts=cut)
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]
    # the mail flow counts messages, the rows one per recipient: 2 messages to 5 recipients each are 10 logical
    # messages, which never stand for the 10 messages that came in - 8 of them went unseen
    fan = Log().add("ceo@brand.example", "Reset your password #", dmarc="fail", times=2, env="evil.invalid",
                    recipients=5)
    rep = audited(tmp_path / "fan", docs, fan, reports, flows={"brand.example": flow(0, 10)})
    own = rep["maillog"]["by_domain"]["brand.example"]
    assert (own["logical_messages"], own.get("message_ids")) == (10, 2)
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]
    rep = audited(tmp_path / "fan2", docs, fan, reports, flows={"brand.example": flow(0, 2)})
    assert ("none of the 2 message(s) that came in with it as the From domain passed, and the mail log examined every "
            "one: 10 logical message(s), 10 look like spoofing" in one(plan_of(rep)["changes"], "no_mail")["why"])
    # the cut organization's full window, counted in advanced hunting, covers the 20 and counts none passing:
    # quarantine now, and the 18 outside the rows kept, never labelled, are a check of their own
    totals = {"hours": 720, "orgs": {"brand.example": {"source": collect.AGGREGATE_SOURCE, "by_domain": {
        "brand.example": {"logical_messages": 20, "passing": 0, "genuine_failures": 20, "delivered_despite_fail": 0}}}}}
    rep = audited(tmp_path / "full", docs, log, reports, flows={"brand.example": flow(0, 20)}, maillog_cuts=cut,
                  window_totals=totals)
    row = one(plan_of(rep)["changes"], "no_mail")
    assert ("none of the about 20 message(s) that came in with it as the From domain passed over the full window "
            "(counted in advanced hunting), and the mail-log rows kept hold 2 logical message(s) of them: 2 look like "
            "spoofing, which quarantine stops") in row["why"]
    assert "none of the 20 message(s) that came in with it as the From domain passed, and" not in row["why"]
    assert row["prerequisites"][-1] == (
        "the about 18 message(s) that came in as brand.example outside the mail-log rows kept are spoofs rather than "
        "a sender of ours: the full window, counted in advanced hunting, shows none of them passing, but only the "
        "rows kept carry labels")
    # a full window that counts fewer than came in covers nothing either
    short = json.loads(json.dumps(totals))
    short["orgs"]["brand.example"]["by_domain"]["brand.example"]["logical_messages"] = 10
    rep = audited(tmp_path / "fewer", docs, log, reports, flows={"brand.example": flow(0, 20)}, maillog_cuts=cut,
                  window_totals=short)
    assert [c["kind"] for c in plan_of(rep)["changes"]] == ["ratchet"]


GOOGLE = {"spf": "v=spf1 include:_spf.google.com ~all", "spf_terminator": "~all", "dkim_selectors": ["google"],
          "mx": ["1 smtp.google.com"]}


def test_r2_a_domain_the_tenant_does_not_carry_needs_reports_that_cover_it():
    """The tenant's zero says nothing about a domain whose mail goes elsewhere: one only EXTRA_DOMAINS names, or one
    whose SPF or DKIM points at another platform. Its fast path needs aggregate reports that cover it and show
    nothing passing; until then the monitoring record or the ramp stays, and its own platform is never called a
    third party."""
    assert plan_mod.foreign_senders(dns_doc("brand.example", **GOOGLE)) == ["SPF include:_spf.google.com",
                                                                             "DKIM selector google"]
    assert plan_mod.foreign_senders(dns_doc("corp.example")) == []  # Microsoft 365's include and selector1
    assert plan_mod.foreign_senders(dns_doc("x.example", spf="v=spf1 ip4:192.0.2.1 redirect=_spf.example ~all",
                                            dkim_selectors=["selector2"])) == ["SPF ip4:192.0.2.1",
                                                                               "SPF redirect=_spf.example"]
    env = {"inputs/domain_sources": {"brand.example": ["env"]}}
    # listed in EXTRA_DOMAINS, its mail on Google, no DMARC record so no report covers it: monitoring first
    elsewhere = quiet_report(**env)
    elsewhere["dns"]["brand.example"] = dns_doc("brand.example", findings=fid("DMARC-001"), **GOOGLE)
    elsewhere["rua"] = None
    assert kinds(elsewhere) == ["new"]
    # its p=none record and aggregate reports that cover it, nothing passing: quarantine now, on that evidence
    covered = quiet_report(**env)
    covered["dns"]["brand.example"].update(GOOGLE)
    row = one(plan_of(covered)["changes"], "no_mail")
    assert row["why"].startswith("quarantine now: the tenant does not carry brand.example's own mail (its DNS names "
                                 "other senders: SPF include:_spf.google.com, DKIM selector google), and the aggregate "
                                 "reports that cover it count none passing as it")
    assert not any("third party" in p for p in row["prerequisites"])
    # Microsoft 365 DNS, but only EXTRA_DOMAINS names it (another tenant, say), and no report: the ramp stays
    other_tenant = quiet_report(**env)
    other_tenant["rua"] = None
    assert kinds(other_tenant) == ["ratchet"]
    # a tenant domain whose SPF also lets a marketing platform send, and no report covers it: the ramp stays
    tenant = quiet_report(**{"inputs/domain_sources": {"brand.example": ["tenant"]}})
    tenant["dns"]["brand.example"]["spf"] = "v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all"
    tenant["rua"] = None
    assert kinds(tenant) == ["ratchet"]
    # the same tenant domain on Microsoft 365 alone: the tenant sees its mail, and the open check is named
    tenant["dns"]["brand.example"]["spf"] = "v=spf1 include:spf.protection.outlook.com -all"
    assert kinds(tenant) == ["no_mail"]
    assert any(p.startswith("no third party sends as brand.example straight to outside recipients")
               for p in one(plan_of(tenant)["changes"], "no_mail")["prerequisites"])


def test_r2_quarantine_now_says_only_what_the_run_read():
    """With the tenant's mail flow alone - no mail log, no aggregate reports - the row says that much: nothing came
    in, no report covers it, and the reject row a week later carries the open checks."""
    rep = quiet_report()
    rep["maillog"], rep["rua"] = None, None
    row = one(plan_of(rep)["changes"], "no_mail")
    assert row["why"] == ("quarantine now: the tenant measured no mail sent as brand.example in 30 days; nothing came "
                          "in with it as the From domain; no aggregate report in this run covers it (see the checks), "
                          "so a weekly ramp would protect nobody; reject follows once a week of reports still shows "
                          "nothing passing; sp=none keeps its subdomains where they are: they move with the sp= step, "
                          "once the reports show which of them send")
    assert "in the mail log or the aggregate reports" not in row["why"]
    assert "no legitimate sender is caught" not in row["human_summary"]


def test_r2_a_quiet_domain_with_no_record_leads_the_document_with_quarantine_now(tmp_path):
    """The headline domain has no DMARC record and the run measured it sending nothing: the plan's only row is the
    quarantine itself, so the one-liner, the ask and the questions say that - never a monitoring-only record."""
    docs = {"brand.example": dns_doc("brand.example", findings=fid("DMARC-001"))}
    log = Log().add("x@other.example", "Hello #", times=2)
    rep = audited(tmp_path, docs, log, flows={"brand.example": flow()})
    p = plan_mod.build_plan(rep, rua="mailto:agg@reports.example")
    assert [(c["id"], c["kind"]) for c in p["changes"]] == [("P-01", "no_mail")]
    doc = next_steps.build(rep, p)
    assert doc["next_step"]["kind"] == "no_mail" and doc["next_step"]["ref"] == "P-01"
    assert doc["one_liner"].startswith("brand.example has no DMARC policy this run could determine.")
    assert doc["one_liner"].endswith(
        "The next safe step is to move straight to p=quarantine (no mail measured), ready when no sender that mails "
        "less often than monthly (statements, renewals) uses this domain; no third party sends as brand.example "
        "straight to outside recipients: no aggregate report in this run covers it, and only those would show such "
        "mail; and reports.example publishes brand.example._report._dmarc.reports.example, so receivers send "
        "brand.example's aggregate reports to agg@reports.example.")
    assert doc["ask"] == ("The ask this week: approval to move 1 domain that sends no mail straight to quarantine "
                          "(plan P-01) once the checks listed with it are confirmed.")
    for text in [doc["one_liner"], doc["ask"]] + [q["question"] for q in doc["open_questions"]]:
        assert "monitoring-only" not in text, text


# ------------------------------------------------------------------ R3: own records first, then sp=

def test_r3_the_sp_step_at_quarantine_names_every_sending_subdomain_without_a_record(tmp_path):
    rep = live_tenant(tmp_path)
    p = plan_of(rep)
    by = rows_by(p)
    sp = next(c for c in by["corp.example"] if c["priority"] == 4)
    reject = next(c for c in by["corp.example"] if c["priority"] == 3)
    assert sp["value"] == "v=DMARC1; p=quarantine; sp=quarantine; rua=%s;" % RUA and sp["current"] == APEX
    missing = "e.corp.example, m.corp.example, mail.corp.example and t.corp.example"
    assert sp["prerequisites"] == ["every subdomain that sends has its own _dmarc record: %s have none yet (the "
                                   "monitoring records above)" % missing, alternative(reject["id"])]
    assert {"domain": "corp.example", "reason": "subdomains that send have no record of their own: %s - publish "
            "their monitoring records (above) before sp= moves to quarantine" % missing} in p["holds"]
    # the reject step is still the apex's own: sp stays as is there, and the two rows are this week's alternatives
    assert reject["value"] == "v=DMARC1; p=reject; sp=none; rua=%s;" % RUA and reject["current"] == APEX
    assert reject["why"].endswith("; sp=none stays as is: the sp= step for this record is offered beside this one, "
                                  "one change a week")
    assert reject["prerequisites"][-1] == alternative(sp["id"])
    # the unaudited senders get their monitoring records from the plan itself; the audited one has its own row
    for name, seen in (("m.corp.example", "8 in the mail log that did not fail"),
                       ("t.corp.example", "6 in the mail log that did not fail"),
                       ("e.corp.example", "300 passing in the aggregate reports")):
        row = one(by[name], "new")
        assert row["priority"] == 1 and row["value"] == "v=DMARC1; p=none; rua=%s;" % RUA
        assert row["why"].startswith("sending subdomain without a record of its own: an explicit record shields it "
                                     "from the apex's sp= change on corp.example (seen sending: ")
        assert seen in row["why"] and row["current"] == "none"  # DNS shows none (report.dns_extra)
    assert one(by["mail.corp.example"], "new")["why"].startswith("subdomain without a record of its own:")
    md = plan_mod.render_md(p)
    assert "| 4 | enforcement step: quarantine the subdomains without a record of their own |" in md
    assert "| 1 | publish: sending subdomain without a record of its own |" in md
    doc = next_steps.build(rep, p)
    assert "move to p=reject or set sp=quarantine, one a week (plan %s, %s)" % (reject["id"], sp["id"]) in \
        next_steps.render_md(doc)
    assert doc["one_liner"].endswith("and the other change to _dmarc.corp.example (plan %s) waits for another week, "
                                     "since both rewrite today's record." % sp["id"])


def test_r3_once_the_records_exist_the_step_is_ready(tmp_path):
    rep = live_tenant(tmp_path)
    rep["dns"]["mail.corp.example"] = dns_doc("mail.corp.example", dmarc="v=DMARC1; p=none; rua=%s;" % RUA,
                                              dmarc_source="_dmarc.mail.corp.example", effective_policy="none",
                                              dmarc_status="found", mx=[], findings=fid("DMARC-002"))
    # DNS shows the three unaudited senders' own records (what the aggregate reports say they saw proves nothing)
    rep["dns_extra"] = {d: {"dmarc": "v=DMARC1; p=none; rua=%s;" % RUA, "status": "found", "source": "_dmarc." + d,
                            "path": "port53-udp"} for d in ("m.corp.example", "t.corp.example", "e.corp.example")}
    p = plan_of(rep)
    sp = next(c for c in rows_by(p)["corp.example"] if c["priority"] == 4)
    reject = next(c for c in rows_by(p)["corp.example"] if c["priority"] == 3)
    assert sp["prerequisites"] == ["every subdomain that sends has its own _dmarc record (this run saw none "
                                   "sending without one)", alternative(reject["id"])]
    assert not [h for h in p["holds"] if h["domain"] == "corp.example"]
    assert not [c for c in p["changes"] if c["domain"] in ("m.corp.example", "t.corp.example", "e.corp.example")]


def apex_report(record, subs=(), flows=None, rua=None):
    dns = {"corp.example": dns_doc("corp.example", dmarc=record, dmarc_source="_dmarc.corp.example",
                                   effective_policy=plan_mod.dmarc_tags(record).get("p"), dmarc_status="found")}
    for s in subs:
        dns[s] = inherits(s)
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": sorted(dns)}, "gate": {"domains": {}},
           "dns": dns, "maillog": None, "rua": rua}
    if flows is not None:
        rep["mailflow"] = {"days": 30, "domains": flows}
    return rep


def test_r3_where_the_sp_step_appears_and_what_counts_as_sending():
    at = "v=DMARC1; p=%s; sp=%s; rua=" + RUA + ";"
    quiet_subs = {"corp.example": flow(500), "a.corp.example": flow(), "b.corp.example": flow(0, 9)}
    # quarantine at 100 percent with sp=none: the step, ready (the audited subdomains measured silent)
    p = plan_of(apex_report(at % ("quarantine", "none"), ("a.corp.example", "b.corp.example"), quiet_subs))
    sp = [c for c in p["changes"] if c["priority"] == 4]
    assert len(sp) == 1 and "sp=quarantine" in sp[0]["value"] and not p["holds"]
    # quarantine at 25 percent: not yet
    p = plan_of(apex_report(at.replace("sp=", "pct=25; sp=") % ("quarantine", "none"), ("a.corp.example",), quiet_subs))
    assert not [c for c in p["changes"] if c["priority"] == 4]
    # reject with sp=none: the step; reject with no sp=: the subdomains already follow p=reject, no step back down
    p = plan_of(apex_report(at % ("reject", "none"), ("a.corp.example",), quiet_subs))
    assert [c["value"] for c in p["changes"] if c["priority"] == 4] == [at % ("reject", "quarantine")]
    p = plan_of(apex_report("v=DMARC1; p=reject; rua=%s;" % RUA, ("a.corp.example",), quiet_subs))
    assert not [c for c in p["changes"] if "sp=quarantine" in c["value"]]
    # nothing measured at all: an audited subdomain may send, and is named as not measured
    p = plan_of(apex_report(at % ("quarantine", "none"), ("a.corp.example",)))
    assert p["holds"] == [{"domain": "corp.example", "reason": "subdomains that send have no record of their own: "
                           "a.corp.example (not measured) - publish their monitoring records (above) before sp= "
                           "moves to quarantine"}]
    # a subdomain whose only mail fails while looking like our own system sends all the same
    rua = {"totals": {"messages": 60, "domains": ["corp.example"]}, "by_header_from": [],
           "policy_check": {"seen": [{"domain": "corp.example", "p": "quarantine"}]}, "spf_only_senders": [],
           "failing_streams": [{"source_ip": "198.51.100.9", "count": 60, "fail": 60, "header_from": ["x.corp.example"],
                                "likely": "likely_misconfigured", "likely_signals": []}]}
    p = plan_of(apex_report(at % ("quarantine", "none"), ("a.corp.example",), quiet_subs, rua))
    assert "x.corp.example" in next(h["reason"] for h in p["holds"])
    assert "60 failing in the aggregate reports from what looks like our own system" in \
        one(p["changes"], "new", "_dmarc.x.corp.example")["why"]
    # no sp= at quarantine 100: the sending subdomains follow p= to reject, so the reject step is held for them
    p = plan_of(apex_report("v=DMARC1; p=quarantine; rua=%s;" % RUA, ("a.corp.example",),
                            dict(quiet_subs, **{"a.corp.example": flow(40)})))
    assert any(h["reason"].startswith("subdomains that send have no record of their own and follow p= (the record "
                                      "has no sp=): a.corp.example") for h in p["holds"])


def test_r3_a_subdomain_whose_failures_may_be_ours_counts_as_sending(tmp_path):
    """A subdomain whose only mail fails sends all the same when the failure may be ours: labelled unknown in the
    mail log or in the aggregate reports, or covered by a formal exception (an explained sender). Only a failure
    that looks like spoofing is no sender, and sp= is what protects that subdomain."""
    apex = dns_doc("corp.example", dmarc=APEX, dmarc_source="_dmarc.corp.example", effective_policy="quarantine",
                   dmarc_status="found")
    docs = {"corp.example": apex, "b.corp.example": own_record("b.corp.example")}
    log = (Log().add("staff@corp.example", "Weekly #", times=6, direction="Intra-org")
           .add("ci@x.corp.example", "Nightly build failed", dmarc="fail", env="x.corp.example")
           .add("ceo@y.corp.example", "Urgent wire #", dmarc="fail", times=3, env="evil.invalid")
           .add("scan@z.corp.example", "Scan #", dmarc="fail", times=2, env="printer.invalid"))
    rep = audited(tmp_path / "log", docs, log, flows={"corp.example": flow(500, 20), "b.corp.example": flow()},
                  exceptions=[EXCEPTION])
    rep["dns_extra"] = no_record("x.corp.example", "y.corp.example", "z.corp.example")  # collect.py's lookups
    p = plan_of(rep)
    assert {"domain": "corp.example", "reason": "subdomains that send have no record of their own: x.corp.example "
            "and z.corp.example - publish their monitoring records (above) before sp= moves to quarantine"} in p["holds"]
    assert ("1 failing in the mail log that may be our own system (the labels cannot tell)"
            in one(p["changes"], "new", "_dmarc.x.corp.example")["why"])
    assert ("2 failing in the mail log from a sender formally excepted in audit.toml"
            in one(p["changes"], "new", "_dmarc.z.corp.example")["why"])
    assert not [c for c in p["changes"] if c["domain"] == "y.corp.example"]  # spoofing only: sp= protects it
    # an older report whose census carries no streams: each unaudited subdomain its parent's total lists counts
    older = json.loads(json.dumps(rep))
    older["maillog"]["census"]["by_sender"] = []
    hold = next(h["reason"] for h in plan_of(older)["holds"] if h["domain"] == "corp.example")
    assert hold.startswith("subdomains that send have no record of their own: x.corp.example, y.corp.example and "
                           "z.corp.example - ")  # the total cannot tell them apart, so all three may send
    # an audited subdomain that inherits, measured sending nothing out, whose only mail is such a failure
    docs = {"corp.example": apex, "c.corp.example": inherits("c.corp.example")}
    log = Log().add("ci@c.corp.example", "Nightly build failed", dmarc="fail", env="c.corp.example")
    p = plan_of(audited(tmp_path / "audited", docs, log, flows={"corp.example": flow(500), "c.corp.example": flow(0, 1)}))
    assert {"domain": "corp.example", "reason": "subdomains that send have no record of their own: c.corp.example - "
            "publish their monitoring records (above) before sp= moves to quarantine"} in p["holds"]
    # the aggregate reports' unknown label reads the same way
    rua = {"totals": {"messages": 25, "domains": ["corp.example"]}, "by_header_from": [], "spf_only_senders": [],
           "policy_check": {"seen": [{"domain": "corp.example", "p": "quarantine"}]},
           "failing_streams": [{"source_ip": "198.51.100.9", "count": 25, "fail": 25, "header_from": ["w.corp.example"],
                                "likely": "unknown", "likely_signals": []}]}
    p = plan_of(apex_report(APEX, ("a.corp.example",), {"corp.example": flow(500), "a.corp.example": flow()}, rua))
    assert ("25 failing in the aggregate reports that may be our own system (the labels cannot tell)"
            in one(p["changes"], "new", "_dmarc.w.corp.example")["why"])
    # a quiet apex whose only subdomain mail is such a failure keeps that subdomain at sp=none until it has a record
    log = Log().add("app@alerts.brand.example", "Build finished", dmarc="fail", env="alerts.brand.example")
    p = plan_of(audited(tmp_path / "pin", {"brand.example": own_record("brand.example")}, log,
                        flows={"brand.example": flow()}))
    assert one(p["changes"], "no_mail")["value"] == "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    assert one(p["changes"], "new", "_dmarc.alerts.brand.example")["domain"] == "alerts.brand.example"


def flow_hunting(rows):
    """An advanced hunting endpoint whose mail-flow aggregate answers these rows; every other query answers empty."""
    def hunting(tok, kql, ts=None):
        if "summarize messages = dcount(InternetMessageId)" in kql:
            return {"schema": [{"name": c} for c in ("d", "messages", "outbound", "inbound", "last_seen")],
                    "results": rows}
        return empty_hunting(tok, kql, ts)
    return hunting


def test_r3_an_unaudited_subdomain_the_mail_flow_sees_sending_is_named(monkeypatch, tmp_path):
    """The mail-flow query counts every name under the audited organizations. An unaudited subdomain sending out
    through the tenant (an app relaying alerts to outside recipients) shows nowhere else when the mail log carries
    only inbound and internal legs: its counts are kept (report.mailflow.unaudited), so the sp= step names it and
    the plan proposes its record."""
    stub_tenant(monkeypatch, [{"domain": "corp.example", "verified": True, "services": ["Email"], "default": True}])
    rows = [{"d": "corp.example", "messages": 1100, "outbound": 1000, "inbound": 100, "last_seen": None},
            {"d": "alerts.corp.example", "messages": 300, "outbound": 300, "inbound": 0, "last_seen": None},
            {"d": "lure.corp.example", "messages": 9, "outbound": 0, "inbound": 9, "last_seen": None}]
    monkeypatch.setattr(collect.graph_client, "hunting", flow_hunting(rows))
    monkeypatch.setattr(audit, "run_dns", lambda domains, resolver, selectors=(): {
        d: dns_doc(d, dmarc=APEX, dmarc_source="_dmarc." + d, effective_policy="quarantine", dmarc_status="found")
        for d in domains})
    env_file = tmp_path / "test.env"
    env_file.write_text("AZURE_TENANT_ID=t\nAZURE_CLIENT_ID=c\nAZURE_CLIENT_SECRET=s\n", encoding="utf-8")
    log = Log().add("staff@corp.example", "Weekly #", times=6, direction="Intra-org").write(tmp_path / "log.csv")
    out = tmp_path / "out"
    rep = run_collect(monkeypatch, out, "--env-file", str(env_file), "--maillog", log, "--auth-column",
                      "DMARC")["report.json"]
    assert rep["mailflow"]["unaudited"] == {
        "alerts.corp.example": {"messages": 300, "outbound": 300, "inbound": 0, "last_seen": None},
        "lure.corp.example": {"messages": 9, "outbound": 0, "inbound": 9, "last_seen": None}}
    assert list(rep["mailflow"]["domains"]) == ["corp.example"]  # the audited names, as before
    p = json.loads((out / "latest" / "plan.json").read_text(encoding="utf-8"))
    assert {"domain": "corp.example", "reason": "subdomains that send have no record of their own: "
            "alerts.corp.example - publish their monitoring records (above) before sp= moves to quarantine"} in p["holds"]
    assert "300 out in the tenant's mail flow" in one(p["changes"], "new", "_dmarc.alerts.corp.example")["why"]
    assert not [c for c in p["changes"] if c["domain"] == "lure.corp.example"]  # mail in only: spoofs, or a vendor
    md = (out / "latest" / "report.md").read_text(encoding="utf-8")
    assert ("- not audited, seen sending through the tenant: alerts.corp.example 300 out - the plan counts them among "
            "the subdomains that send") in md


def test_r3_the_sp_step_says_what_the_run_could_not_see():
    """The sp= step reads ready only on evidence: an audited subdomain whose mail out was not measured counts as not
    measured whatever else the run read (the mail log carries no outbound leg); a run that read no mail log and no
    aggregate reports says so on the row; one whose reports do not cover the apex's record names what only those
    would show."""
    log_doc = {"sender_domain": None, "counters": {"by_likely": {}}, "by_domain": {}}
    # the mail-flow query failed for the subdomain, and the mail log has nothing from it
    rep = apex_report(APEX, ("a.corp.example",), {"corp.example": flow(500), "a.corp.example": None})
    rep["maillog"] = dict(log_doc)
    assert plan_of(rep)["holds"] == [{"domain": "corp.example", "reason": "subdomains that send have no record of "
                                      "their own: a.corp.example (not measured) - publish their monitoring records "
                                      "(above) before sp= moves to quarantine"}]
    # every subdomain measured silent, but no mail log and no aggregate reports: the gate's note is on the row
    quiet_subs = {"corp.example": flow(500), "a.corp.example": flow()}

    def sp_row(rep):
        p = plan_of(rep)
        return next(c for c in p["changes"] if c["priority"] == 4), next(c for c in p["changes"] if c["priority"] == 3)

    sp, reject = sp_row(apex_report(APEX, ("a.corp.example",), quiet_subs))
    assert sp["prerequisites"] == ["every subdomain that sends has its own _dmarc record (this run saw none sending "
                                   "without one)", "no failure evidence in this run - supply --maillog and/or --rua "
                                   "before applying any enforcement step", alternative(reject["id"])]
    # a mail log, but no aggregate report about the apex's record
    rep = apex_report(APEX, ("a.corp.example",), quiet_subs)
    rep["maillog"] = dict(log_doc)
    sp, reject = sp_row(rep)
    assert sp["prerequisites"][1] == ("no third party sends as a subdomain without a record of its own straight to "
                                      "outside recipients: no aggregate report in this run covers corp.example's "
                                      "record, and only those would show such mail")
    # reports about the record: the row is ready on the evidence
    rua = {"totals": {"messages": 10, "domains": ["corp.example"]}, "by_header_from": [], "failing_streams": [],
           "spf_only_senders": [], "policy_check": {"seen": [{"domain": "corp.example", "p": "quarantine"}]}}
    sp, reject = sp_row(apex_report(APEX, ("a.corp.example",), quiet_subs, rua))
    assert sp["prerequisites"] == ["every subdomain that sends has its own _dmarc record (this run saw none sending "
                                   "without one)", alternative(reject["id"])]


# ------------------------------------------------------------------ R4: the round-10 leftovers

EXCEPTION = {"match": "printer.invalid", "reason": "the scanner relays through the printer vendor", "owner": "it",
             "until": "2099-12-31", "removal_criterion": "the scanner is retired"}


def excepted_report(tmp_path):
    """corp.example's own rows: 4 failures through the excepted printer.invalid, 3 spoofs; its unaudited
    a.corp.example: 2 more through the printer."""
    log = (Log().add("staff@corp.example", "Weekly report #", times=10, direction="Outbound")
           .add("scan@corp.example", "Scan #", dmarc="fail", times=4, env="printer.invalid")
           .add("ceo@corp.example", "Urgent wire #", dmarc="fail", times=3, env="evil.invalid")
           .add("app@a.corp.example", "Build #", dmarc="fail", times=2, env="printer.invalid"))
    return audit.build_report(domains=["corp.example"], maillog=log.write(tmp_path / "log.csv"), offline=True,
                              auth_column="DMARC", exceptions=[EXCEPTION])


def test_r4_1_every_count_line_names_its_excepted_share(tmp_path):
    rep = excepted_report(tmp_path)
    own = rep["maillog"]["by_domain"]["corp.example"]
    assert (own["genuine_failures"], own["excepted"], own["subdomains_total"]["excepted"]) == (7, 4, 2)
    md = audit.render_md(rep)
    assert "- corp.example: 17 logical messages, 7 genuine failures (4 of them formally excepted in audit.toml), " in md
    assert ("  - unaudited subdomains (a.corp.example): 2 logical messages, 2 genuine failures (2 of them formally "
            "excepted in audit.toml) - counted separately") in md
    line = next(l for l in next_steps.build(rep)["stand"]["lines"] if l.startswith("**Genuine failures"))
    assert line.startswith("**Genuine failures: 9** (6 of them formally excepted in audit.toml; raw row counts agree")
    summary = notify.summarize(rep)
    assert "- 7 genuine failures of its own (4 of them formally excepted in audit.toml)" in \
        next(l for l in summary.splitlines() if l.startswith("- `corp.example`"))
    # an older report, whose census does not count the excepted ones per stream: the gate's total
    old = json.loads(json.dumps(rep))
    for r in old["maillog"]["census"]["by_sender"] + old["maillog"]["census"]["by_envelope"]:
        r.pop("excepted", None)
    line = next(l for l in next_steps.build(old)["stand"]["lines"] if l.startswith("**Genuine failures"))
    assert "(6 of them formally excepted in audit.toml;" in line
    # nothing excepted: the lines read as before
    plain_rep = audit.build_report(domains=["corp.example"], maillog=str(tmp_path / "log.csv"), offline=True,
                                   auth_column="DMARC")
    assert "formally excepted" not in audit.render_md(plain_rep).split("Per sender domain", 1)[1].split("##", 1)[0]
    assert "formally excepted" not in notify.summarize(plain_rep)


def test_r4_2_readme_says_an_address_covers_forged_copies_and_a_vendor_takes_its_envelope():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    bullet = " ".join(readme.split("- **Formal exceptions.**", 1)[1].split("\n\n", 1)[0].split("\n- ", 1)[0].split())
    assert "forged copies" in bullet and "envelope domain" in bullet


def test_r4_3_an_ip_prefix_among_the_vendor_domains_warns_on_every_run(monkeypatch, tmp_path):
    domains, warnings = config.split_vendor_domains(["vendor.example", "192.0.2.0/24", " ", "2001:db8::/32"])
    assert domains == ["vendor.example"] and len(warnings) == 2
    assert warnings[0].startswith("vendor domain 192.0.2.0/24 is an IP prefix, not a domain: ignored")
    # a run that reads no aggregate report says it too, and the audit gets the domains alone
    stub_tenant(monkeypatch, [])
    log = Log().add("staff@corp.example", "Weekly #", times=3).write(tmp_path / "log.csv")
    files = run_collect(monkeypatch, tmp_path / "out", "corp.example", "--offline", "--maillog", log,
                        "--auth-column", "DMARC", "--vendor-domain", "192.0.2.0/24", "--vendor-domain", "vendor.example")
    assert warnings[0] in files["run.json"]["notes"]
    assert files["report.json"]["maillog"]["heuristic"]["vendor_domains"] == ["vendor.example"]
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "an IP prefix here never matches anything (every run warns about it)" in readme


def test_r4_3_audit_py_and_the_mcp_tool_warn_about_it_too(monkeypatch, tmp_path):
    """audit.py and the MCP audit tool read vendor_domains too (the flag, audit.toml): each warns, as collect.py
    does, and hands the audit the domains alone."""
    import subprocess
    import mcp_server
    log = Log().add("staff@corp.example", "Weekly #", times=3).write(tmp_path / "log.csv")
    warning = config.split_vendor_domains(["192.0.2.0/24"])[1][0]
    out = tmp_path / "cli"
    p = subprocess.run([sys.executable, str(ROOT / "src" / "audit.py"), "--offline", "--no-config", "--no-plan",
                        "--maillog", log, "--auth-column", "DMARC", "--vendor-domain", "192.0.2.0/24",
                        "--vendor-domain", "vendor.example", "--out", str(out)],
                       capture_output=True, text=True, env=clean_env(), timeout=120)
    assert p.returncode in (0, 1), p.stderr
    assert "note: " + warning in p.stderr
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["maillog"]["heuristic"]["vendor_domains"] == ["vendor.example"]
    settings = tmp_path / "audit.toml"
    settings.write_text('[audit]\nvendor_domains = ["192.0.2.0/24", "vendor.example"]\n', encoding="utf-8")
    monkeypatch.setattr(mcp_server, "ROOT", tmp_path)  # its out_dir must stay inside the repo: here, the test's folder
    reply = mcp_server.run_audit(maillog=log, out_dir=str(tmp_path / "mcp"), offline=True, config=str(settings))
    assert reply.get("warnings") == [warning]
    rep = json.loads((tmp_path / "mcp" / "report.json").read_text(encoding="utf-8"))
    assert rep["maillog"]["heuristic"]["vendor_domains"] == ["vendor.example"]


def test_r4_4_the_unknown_sender_count_is_the_per_ip_checks_alone():
    known = {"given": True, "ip_check": True, "networks": ["192.0.2.0/24"], "domains": []}
    unk = [{"kind": "dkim_domain", "value": "crm.invalid", "count": 80, "pass": 80, "fail": 0},
           {"kind": "ip", "value": "198.51.100.7", "count": 30, "pass": 0, "fail": 30},
           {"kind": "dkim_domain", "value": "esp.invalid", "count": 20, "pass": 20, "fail": 0}]
    rua = {"totals": {"messages": 110}, "filters": {"known": known}, "unknown_senders": unk}
    assert ("- unknown senders in reports: 1 (top: ip 198.51.100.7); 2 signing domains not in the known list (top: "
            "crm.invalid, esp.invalid)") in notify.summarize({"rua": rua})
    # a table capped to its busiest rows: the IPs recounted over every source the outside view saw
    capped = dict(rua, unknown_senders=unk[:2], source_ips=["192.0.2.5", "198.51.100.7", "203.0.113.8", "203.0.113.9"],
                  truncated={"unknown_senders": {"kept": 2, "total": 6}})
    assert ("- unknown senders in reports: 3 (top: ip 198.51.100.7); 3 signing domains not in the known list (top: "
            "crm.invalid)") in notify.summarize({"rua": capped})


def relay_reports(tmp_path):
    """Aggregate reports about corp.example: a shared Microsoft relay that carries an SES stream beside another
    tenant's mail and one of our own subdomains, and a pure SES stream (amazonses.com's signature, and ours that
    does not verify) - all failing DMARC."""
    relay, ses = "198.51.100.40", "203.0.113.70"
    return [rua_report(tmp_path / "relay.xml", "corp.example", "quarantine", [
        (relay, 30, "corp.example", "amazonses.com", "pass", "amazonses.com", "pass"),
        (relay, 30, "corp.example", "other.onmicrosoft.com", "pass", "other.onmicrosoft.com", "pass"),
        (relay, 10, "corp.example", "e.corp.example", "fail", "corp.example", "fail"),
        (ses, 40, "corp.example", "amazonses.com", "pass", "us-east-1.amazonses.com", "pass"),
        (ses, 10, "corp.example", "corp.example", "fail", "us-east-1.amazonses.com", "pass")])]


def test_r4_5_a_domain_exception_covers_a_vendor_stream_never_a_shared_relay(tmp_path):
    exc = {"match": "amazonses.com", "kind": "domain"}
    relay = {"source_ip": "198.51.100.40", "spf_domains": ["amazonses.com", "corp.example", "other.onmicrosoft.com"],
             "dkim_domains": ["amazonses.com", "e.corp.example", "other.onmicrosoft.com"]}
    vendor = {"source_ip": "203.0.113.70", "spf_domains": ["us-east-1.amazonses.com"],
              "dkim_domains": ["amazonses.com", "corp.example"]}
    assert not config.matches_stream(exc, relay, ["corp.example"])
    assert config.matches_stream(exc, vendor, ["corp.example"])
    assert config.matches_stream(exc, dict(relay, spf_domains=["amazonses.com"],  # every other domain is ours
                                           dkim_domains=["amazonses.com", "e.corp.example"]), ["corp.example"])
    # the gate, end to end: the SES stream is excepted, the relay still holds the step
    rep = audit.build_report(domains=["corp.example"], rua_paths=relay_reports(tmp_path), offline=True,
                             exceptions=[dict(EXCEPTION, match="amazonses.com")])
    assert rep["gate"]["exceptions"]["excepted_streams"] == ["203.0.113.70"]
    blockers = rep["gate"]["domains"]["corp.example"]["blockers"]
    assert any(b.startswith("198.51.100.40 fails DMARC on 70/70 msgs") for b in blockers), blockers


def test_r4_6_the_template_and_the_mcp_tool_say_the_per_ip_check_needs_ip_prefixes():
    template = " ".join((ROOT / "docs" / "templates" / "next-steps.md").read_text(encoding="utf-8").split())
    assert "no `--known` list with IP prefixes (the per-IP unknown-sender check runs only on IP prefixes" in template
    import ast
    tree = ast.parse((ROOT / "src" / "mcp_server.py").read_text(encoding="utf-8"))
    doc = next(ast.get_docstring(n) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "parse_rua")
    assert "per-IP unknown-sender check runs only on the IP prefixes" in " ".join(doc.split())
