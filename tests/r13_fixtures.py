"""Round 13: the synthetic runs the round's tests share, built with the round-11 helpers
(test_r11_plan's Log, rua_report, own_record, inherits, audited) the way the review's estate
builder builds them. Synthetic names only (example.com, example.net, example.org,
brand.example, .invalid, the documentation IP ranges); offline: nothing here touches the
network. Not a test module: the test_r13_*.py files import it."""

import audit
import next_steps
import plan as plan_mod
import test_r11_plan as T

RUA = T.RUA
ESTATE_APEX = "v=DMARC1; p=quarantine; sp=none; rua=%s; ruf=mailto:forensics@example.com; fo=1;" % RUA
ESTATE_DATE = "2026-10-13"


def estate_parts(tmp_path, net_clean=False, nobodys_stream=False, two_records=False):
    """The five-organization estate's inputs: (docs, log, reports, flows, sources, hosts). example.com with
    sending and quiet subdomains and a delegated zone (shop.example.com); example.net on p=none reporting
    to a vendor; brand.example at reject; example.org with no record and no mail; parked.example with
    nothing at all. The mail log holds our own senders, a vendor, weak and strong spoofing; the reports
    hold a failing vendor stream as example.com (198.51.100.20), a spoof receivers delivered as
    example.com (203.0.113.66) and one as example.net (203.0.113.9). net_clean: example.net has nothing
    failing (no failing sender in the log, no spoof stream), so its gate is go; nobodys_stream: the reports
    also hold a failing stream with no From domain (192.0.2.99), which nothing attributes to one name;
    two_records: example.net publishes two DMARC records (DMARC-005), as the DNS-window review's dup estate."""
    inp = tmp_path / "inputs"
    inp.mkdir(parents=True, exist_ok=True)
    docs = {
        "example.com": T.own_record("example.com", ESTATE_APEX),
        "dev.support.example.com": T.inherits("dev.support.example.com", ESTATE_APEX, "_dmarc.example.com"),
        "events.example.com": T.inherits("events.example.com", ESTATE_APEX, "_dmarc.example.com"),
        "pay.example.com": T.inherits("pay.example.com", ESTATE_APEX, "_dmarc.example.com"),
        "shop.example.com": T.own_record("shop.example.com", "v=DMARC1; p=none; rua=%s;" % RUA),
        "example.net": T.own_record("example.net", "v=DMARC1; p=none; rua=mailto:reports@vendor.invalid;"),
        "brand.example": T.own_record("brand.example", "v=DMARC1; p=reject; rua=%s;" % RUA),
        "example.org": T.dns_doc("example.org", findings=T.fid("DMARC-001")),
        "parked.example": T.dns_doc("parked.example", spf=None, spf_status="absent", spf_terminator=None,
                                    spf_lookups=0, dkim_selectors=[], dkim_status="absent", mx=[],
                                    mx_status="absent", findings=T.fid("DMARC-001", "SPF-001")),
    }
    if two_records:
        docs["example.net"]["findings"] = T.fid("DMARC-002", "DMARC-005")
    senders = [
        ("staff@example.com", "Weekly team update #", {"times": 60}),
        ("noreply@example.com", "Your receipt #", {"dmarc": "fail", "times": 12}),
        ("billing@example.com", "Invoice # is ready", {"dmarc": "fail", "times": 5, "env": "mailer.billing-vendor.invalid"}),
        ("ceo@example.com", "Urgent wire transfer #", {"dmarc": "fail", "times": 7, "env": "evil.invalid"}),
        ("alerts@pay.example.com", "Payment alert #", {"dmarc": "fail", "times": 9}),
        ("news@m.example.com", "Spring newsletter #", {"times": 40}),
        ("promo@t.example.com", "Weekend offer #", {"times": 25}),
        ("info@e.example.com", "Event reminder #", {"times": 15}),
        ("hello@example.net", "Welcome aboard #", {"dmarc": "pass" if net_clean else "fail", "times": 6}),
        ("staff@example.net", "Roster #", {"times": 30}),
        ("team@brand.example", "Brand update #", {"times": 20}),
        ("hr@brand.example", "Your password expires today #", {"dmarc": "fail", "times": 4, "env": "lure.invalid"})]
    log = T.Log()
    for sender, subject, kw in senders:
        log.add(sender, subject, **kw)
    com_rows = [("192.0.2.10", 500, "example.com", "example.com", "pass", "example.com", "pass"),
                ("192.0.2.40", 80, "m.example.com", "m.example.com", "pass", "m.example.com", "pass"),
                ("198.51.100.20", 60, "example.com", "esp.invalid", "pass", "esp.invalid", "pass"),
                ("203.0.113.66", 120, "example.com", None, None, "evil.invalid", "fail")]
    if nobodys_stream:  # an empty header_from: rua_parse files it under "(no header_from)"
        com_rows.append(("192.0.2.99", 30, "", "esp2.invalid", "pass", "esp2.invalid", "pass"))
    net_rows = [("198.51.100.7", 200, "example.net", "example.net", "pass", "example.net", "pass")]
    if not net_clean:
        net_rows.append(("203.0.113.9", 40, "example.net", None, None, "spoof.invalid", "fail"))
    reports = [
        T.rua_report(inp / "example-com.xml", "example.com", "quarantine", com_rows,
                     begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
        T.rua_report(inp / "example-net.xml", "example.net", "none", net_rows,
                     begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
        T.rua_report(inp / "brand.xml", "brand.example", "reject", [
            ("192.0.2.77", 150, "brand.example", "brand.example", "pass", "brand.example", "pass"),
        ], begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
    ]
    flows = {"example.com": T.flow(800, 1500), "dev.support.example.com": T.flow(0, 0),
             "events.example.com": T.flow(0, 3), "pay.example.com": T.flow(45, 10), "shop.example.com": T.flow(0, 0),
             "example.net": T.flow(120, 300), "brand.example": T.flow(50, 90), "example.org": T.flow(0, 0),
             "parked.example": T.flow(0, 0)}
    sources = {d: ["tenant"] for d in docs}
    hosts = {"example.com": ("example.com", "Route53"), "dev.support.example.com": ("example.com", "Route53"),
             "events.example.com": ("example.com", "Route53"), "pay.example.com": ("example.com", "Route53"),
             "shop.example.com": ("shop.example.com", "Route53"), "example.net": ("example.net", "Route53"),
             "brand.example": ("brand.example", "CSC"), "example.org": ("example.org", "CSC"),
             "parked.example": ("parked.example", "unknown")}
    return docs, log, reports, flows, sources, hosts


def inventory_of(hosts, flows):
    """inventory.json's rows for these names: each one's zone and DNS host, as discover.py writes them."""
    return {"domains": [{"domain": d, "sources": ["tenant"], "org_domain": plan_mod.org_domain(d), "zone": z,
                         "zone_host": h, "mailflow": flows.get(d)} for d, (z, h) in sorted(hosts.items())]}


def estate(tmp_path, rua=RUA, owners=True, **variant):
    """The estate run end to end: {"report", "plan", "inventory", "doc", "owners_path"}, as collect.py would
    write report.json, plan.json and next_steps.json for it (the owners file names three owners). variant:
    estate_parts' net_clean and nobodys_stream."""
    docs, log, reports, flows, sources, hosts = estate_parts(tmp_path, **variant)
    rep = T.audited(tmp_path / "run", docs, log, reports, flows=flows, sources=sources)
    rep["dns_extra"] = T.no_record("m.example.com", "t.example.com", "e.example.com")
    inventory = inventory_of(hosts, flows)
    plan = plan_mod.build_plan(rep, inventory, rua)
    owners_path, owner_rows = None, []
    if owners:
        owners_path = tmp_path / "inputs" / "owners.csv"
        owners_path.write_text("pattern,owner,channel,note\n"
                               "noreply@example.com,Receipts platform team,#receipts,\n"
                               "example.com,DNS and messaging team,#dns-changes,\n"
                               "example.net,Network brand team,#net-brand,\n", encoding="utf-8")
        owner_rows = next_steps.read_owners(owners_path)
    doc = next_steps.build(rep, plan=plan, owners=owner_rows, owners_path=str(owners_path) if owners_path else None,
                           date=ESTATE_DATE, org_name="example.com")
    return {"report": rep, "plan": plan, "inventory": inventory, "doc": doc, "owners_path": owners_path}


def row(plan, rid):
    """The plan row with this id."""
    return next(c for c in plan["changes"] if c["id"] == rid)


# ------------------------------------------------------------------ a first run: three domains, no aggregate reports

import test_r11_other as O  # noqa: E402  (its Log carries the override columns)

FR_RUA = "mailto:dmarc-reports@harborfoods.example"
FR_HOST = "other (ns1.registrar-dns.example)"
JUNK = ("Junked", "Junk folder")
TRANSPORT_RULE = ("Exchange transport rule", "Allow")


def first_run_parts():
    """A first-time admin's tenant, as the first-run review's simulated tenant holds it: harborfoods.example at
    p=none with no rua, sending (a newsletter platform and a payroll provider failing unaligned - the payroll one
    let in by a transport rule -, CEO-fraud and voicemail lures quarantined or junked, a helpdesk that passes);
    harbor-old.example with nothing at all (parked); harborfoods-shop.example with no DMARC record, receiving its
    web shop's order copies and refund lures. (docs, log, flows, hosts)."""
    docs = {
        "harborfoods.example": T.dns_doc("harborfoods.example", dmarc="v=DMARC1; p=none",
                                         dmarc_source="_dmarc.harborfoods.example", effective_policy="none",
                                         dmarc_status="found", spf="v=spf1 include:spf.mailhost.example -all",
                                         dkim_selectors=["selector1", "selector2"],
                                         findings=T.fid("DMARC-002", "DMARC-003")),
        "harbor-old.example": T.dns_doc("harbor-old.example", spf=None, spf_status="absent", spf_terminator=None,
                                        spf_lookups=0, dkim_selectors=[], dkim_status="absent", mx=[],
                                        mx_status="absent", findings=T.fid("SPF-001", "DMARC-001", "DKIM-002")),
        "harborfoods-shop.example": T.dns_doc("harborfoods-shop.example",
                                              spf="v=spf1 include:spf.mailhost.example include:_spf.shopesp.example "
                                                  "~all", spf_terminator="~all", dkim_selectors=[],
                                              dkim_status="absent", findings=T.fid("DMARC-001", "DKIM-002")),
    }
    log = (O.Log(overrides=True)
           .add("ana@harborfoods.example", "Re: weekly ops #", 20, direction="Intra-org")
           .add("support@harborfoods.example", "Ticket # updated", 10, env="helpdesk-mail.example")
           .add("news@harborfoods.example", "Harbor Foods news - issue #", 16, env="bounce.newsesp.example",
                dmarc="fail", spf="pass")
           .add("news@harborfoods.example", "Harbor Foods news - issue #", 16, env="bounce.newsesp.example",
                where=JUNK, dmarc="fail", spf="pass")
           .add("payroll@harborfoods.example", "Your payslip is ready", 16, env="mail.payrollco.example",
                dmarc="fail", spf="pass", org=TRANSPORT_RULE)
           .add("ceo@harborfoods.example", "Urgent: wire transfer needed today", 7, env="smtp.badhost.example",
                where=O.QUARANTINED, dmarc="fail")
           .add("it-support@harborfoods.example", "Voicemail received (2) - listen now", 5,
                env="mailer.badhost2.example", where=JUNK, dmarc="fail")
           .add("orders@harborfoods-shop.example", "New order #", 30, env="bounce.shopesp.example", dmarc="none")
           .add("refunds@harborfoods-shop.example", "Your refund is pending - confirm your card", 4,
                env="x.spamhost.example", where=JUNK, dmarc="none"))
    flows = {"harborfoods.example": T.flow(2583, 132), "harbor-old.example": T.flow(0, 0),
             "harborfoods-shop.example": T.flow(0, 34)}
    hosts = {d: (d, FR_HOST) for d in docs}
    return docs, log, flows, hosts


IN_APEX = "v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:dmarc-reports@example.com; fo=1"
ON_PREM = ("Delivered", "On-premises/external")
SAFE_SENDERS = ("Safe senders list", "Allow")


def relayed(log, sender, subject, n, env):
    """n messages that passed but went only to an on-premises or external hop, each with a failing copy of the same
    message looped back (a relay echo): the mail log counts them relayed_only, never delivered."""
    start = len(log.rows)
    log.add(sender, subject, n, env=env, where=ON_PREM)
    for row in log.rows[start:start + n]:
        echo = list(row)
        echo[9:12] = ["fail", "fail", "fail"]  # DMARC, SPF, DKIM
        log.rows.append(echo)
    return log


def incident_parts():
    """A help desk's incident ("HR mail is failing"), as the incident review's tenant holds it: example.com at
    p=quarantine, its HR platform (hr@example.com through hrmail.example.com) failing 65 messages of its own, 27
    of them let in by a transport rule, and 36 more passing only to an on-premises hop; the same From address
    spoofed with a password lure (lure-mail.invalid, 12); CEO fraud quarantined (20); a payroll vendor failing
    unaligned (14, 4 let in by users' safe sender lists); example.net at p=none with a newsletter that fails
    (6); parked.example with nothing. (docs, log, flows, hosts)."""
    docs = {"example.com": T.dns_doc("example.com", dmarc=IN_APEX, dmarc_source="_dmarc.example.com",
                                     effective_policy="quarantine", dmarc_status="found"),
            "example.net": T.own_record("example.net", "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"),
            "parked.example": T.dns_doc("parked.example", spf=None, spf_status="absent", spf_terminator=None,
                                        spf_lookups=0, dkim_selectors=[], dkim_status="absent", mx=[],
                                        mx_status="absent", findings=T.fid("DMARC-001", "SPF-001"))}
    pay = "Your pay statement is ready (#)"
    log = (O.Log(overrides=True)
           .add("staff@example.com", "Team notes #", 40)
           .add("hr@example.com", pay, 60, env="hrmail.example.com")
           .add("hr@example.com", pay, 27, env="hrmail.example.com", dmarc="fail", spf="pass", org=TRANSPORT_RULE)
           .add("hr@example.com", pay, 38, env="hrmail.example.com", where=O.QUARANTINED, dmarc="fail", spf="pass")
           .add("hr@example.com", "Your password expires today #", 12, env="lure-mail.invalid", where=O.QUARANTINED,
                dmarc="fail")
           .add("ceo@example.com", "Urgent wire transfer today #", 20, env="evil.invalid", where=O.QUARANTINED,
                dmarc="fail")
           .add("payroll@example.com", "Your pay stub for period #", 4, env="mail.paysvc.invalid", dmarc="fail",
                spf="pass", user=SAFE_SENDERS)
           .add("payroll@example.com", "Your pay stub for period #", 10, env="mail.paysvc.invalid",
                where=O.QUARANTINED, dmarc="fail", spf="pass")
           .add("hello@example.net", "Welcome to the club #", 6, env="bounce.esp.invalid", dmarc="fail")
           .add("staff@example.net", "Roster #", 20))
    relayed(log, "hr@example.com", pay, 36, "hrmail.example.com")
    flows = {"example.com": T.flow(2400, 300), "example.net": T.flow(100, 50), "parked.example": T.flow(0, 0)}
    hosts = {"example.com": ("example.com", "Route53"), "example.net": ("example.net", "Route53"),
             "parked.example": ("parked.example", "unknown")}
    return docs, log, flows, hosts


def incident(tmp_path, rua="mailto:dmarc-reports@example.com"):
    """The incident run end to end: {"report", "plan", "inventory", "doc"}; no owners file."""
    docs, log, flows, hosts = incident_parts()
    rep = T.audited(tmp_path / "run", docs, log, flows=flows, sources={d: ["tenant"] for d in docs})
    rep["findings"] = audit.flatten_findings(rep)
    inventory = inventory_of(hosts, flows)
    plan = plan_mod.build_plan(rep, inventory, rua)
    doc = next_steps.build(rep, plan=plan, date="2026-10-20")
    return {"report": rep, "plan": plan, "inventory": inventory, "doc": doc}


def first_run(tmp_path, rua=None):
    """The first run end to end, as collect.py writes it with no report mailbox (rua None: the plan's new records
    carry plan.RUA_PLACEHOLDER) or with --rua-address: {"report", "plan", "inventory", "doc"}; no owners file."""
    docs, log, flows, hosts = first_run_parts()
    rep = T.audited(tmp_path / "run", docs, log, flows=flows, sources={d: ["tenant"] for d in docs})
    rep["findings"] = audit.flatten_findings(rep)  # the DNS findings too, as collect.py's report carries them
    inventory = inventory_of(hosts, flows)
    plan = plan_mod.build_plan(rep, inventory, rua)
    doc = next_steps.build(rep, plan=plan, date="2026-10-20")
    return {"report": rep, "plan": plan, "inventory": inventory, "doc": doc}


# ------------------------------------------------------------------ a stress estate: ten organizations

STRESS_LONGORG = "an-extraordinarily-long-organizational-domain-name-for-layout.example"
STRESS_LONGSUB = "transactional-notifications-for-customer-accounts-and-billing.eu-west-1.mail.example.com"
STRESS_SENDING = ["alerts", "billing", "careers", "community", "docs", "events", "investor-relations", "marketing",
                  "news", "pay", "status", "support", "surveys", "webinars", "rewards"]
STRESS_QUIET = ["archive", "beta", "dev.support", "intranet-legacy", "labs", "old-shop", "partners", "staging", "test",
                "wiki"]


def stress(tmp_path):
    """The layout review's stress estate through the real pipeline (its make_stress.py builder): ten organizations
    on three DNS hosts and unknown ones, example.com with fifteen sending and ten quiet subdomains and a delegated
    zone, a 63-character organization, more than forty plan rows, an owners file: {"report", "plan", "inventory",
    "doc"}."""
    inp = tmp_path / "inputs"
    inp.mkdir(parents=True, exist_ok=True)
    apex = ESTATE_APEX
    docs = {"example.com": T.own_record("example.com", apex)}
    flows = {"example.com": T.flow(800, 1500)}
    hosts = {"example.com": ("example.com", "Route53")}
    for s in STRESS_SENDING:
        d = "%s.example.com" % s
        docs[d], flows[d], hosts[d] = T.inherits(d, apex, "_dmarc.example.com"), T.flow(20 + len(s), 5), (
            "example.com", "Route53")
    for s in STRESS_QUIET:
        d = "%s.example.com" % s
        docs[d], flows[d], hosts[d] = T.inherits(d, apex, "_dmarc.example.com"), T.flow(0, 0), ("example.com", "Route53")
    docs[STRESS_LONGSUB] = T.inherits(STRESS_LONGSUB, apex, "_dmarc.example.com")
    flows[STRESS_LONGSUB], hosts[STRESS_LONGSUB] = T.flow(400, 2), ("eu-west-1.mail.example.com", "Cloudflare")
    docs["shop.example.com"] = T.own_record("shop.example.com", "v=DMARC1; p=none; rua=%s;" % RUA)
    flows["shop.example.com"], hosts["shop.example.com"] = T.flow(0, 0), ("shop.example.com", "Route53")
    docs["example.net"] = T.own_record("example.net", "v=DMARC1; p=none; rua=%s;" % RUA)
    flows["example.net"], hosts["example.net"] = T.flow(120, 300), ("example.net", "CSC")
    docs["brand.example"] = T.own_record("brand.example", "v=DMARC1; p=reject; rua=%s;" % RUA)
    flows["brand.example"], hosts["brand.example"] = T.flow(50, 90), ("brand.example", "CSC")
    docs["alpha.example"] = T.own_record("alpha.example", "v=DMARC1; p=none; rua=%s;" % RUA)
    flows["alpha.example"], hosts["alpha.example"] = T.flow(30, 10), ("alpha.example", "CSC")
    docs["example.org"] = T.dns_doc("example.org", findings=T.fid("DMARC-001"))
    flows["example.org"], hosts["example.org"] = T.flow(0, 0), ("example.org", "Cloudflare")
    for p in ("parked.example", "parked-two.example", "holding.example", "legacy.example", STRESS_LONGORG):
        docs[p] = T.dns_doc(p, spf=None, spf_status="absent", spf_terminator=None, spf_lookups=0, dkim_selectors=[],
                            dkim_status="absent", mx=[], mx_status="absent", findings=T.fid("DMARC-001", "SPF-001"))
        flows[p], hosts[p] = T.flow(0, 0), (p, "unknown" if p != "legacy.example" else "Cloudflare")
    log = (T.Log()
           .add("staff@example.com", "Weekly team update #", times=60)
           .add("noreply@example.com", "Your receipt #", dmarc="fail", times=31)
           .add("automated-notifications-noreply@" + STRESS_LONGSUB, "Your monthly statement is now available #",
                dmarc="fail", times=22)
           .add("billing@example.com", "Invoice # is ready", dmarc="fail", times=14, env="mailer.billing-vendor.invalid")
           .add("ceo@example.com", "Urgent wire transfer #", dmarc="fail", times=12, env="evil.invalid")
           .add("alerts@pay.example.com", "Payment alert #", dmarc="fail", times=11)
           .add("hello@example.net", "Welcome aboard #", dmarc="fail", times=10)
           .add("team@brand.example", "Brand update #", times=20)
           .add("hr@brand.example", "Your password expires today #", dmarc="fail", times=4, env="lure.invalid"))
    for i, s in enumerate(STRESS_SENDING):
        log.add("info@%s.example.com" % s, "Update from %s #" % s, dmarc="fail", times=2 + i % 7)
    log.add("news@example.org", "Hello #", dmarc="fail", times=3)
    log.add("ops@alpha.example", "Ops digest #", dmarc="fail", times=6)
    rows = [("192.0.2.10", 500, "example.com", "example.com", "pass", "example.com", "pass"),
            ("198.51.100.20", 60, "example.com", "esp.invalid", "pass", "esp.invalid", "pass")]
    for k in range(12):
        rows.append(("203.0.113.%d" % (40 + k), 9 + 7 * k, "example.com", None, None, "spoof%d.invalid" % k, "fail"))
    reports = [T.rua_report(inp / "example-com.xml", "example.com", "quarantine", rows,
                            begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
               T.rua_report(inp / "example-net.xml", "example.net", "none", [
                   ("198.51.100.7", 200, "example.net", "example.net", "pass", "example.net", "pass"),
                   ("203.0.113.9", 40, "example.net", None, None, "spoof.invalid", "fail")],
                   begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
               T.rua_report(inp / "brand.xml", "brand.example", "reject", [
                   ("192.0.2.77", 150, "brand.example", "brand.example", "pass", "brand.example", "pass")],
                   begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN)]
    rep = T.audited(tmp_path / "run", docs, log, reports, flows=flows, sources={d: ["tenant"] for d in docs})
    rep["dns_extra"] = T.no_record("m.example.com", "t.example.com", "e.example.com")
    inventory = inventory_of(hosts, flows)
    plan = plan_mod.build_plan(rep, inventory, RUA)
    doc = next_steps.build(rep, plan=plan, date=ESTATE_DATE, org_name="example.com")
    return {"report": rep, "plan": plan, "inventory": inventory, "doc": doc}


# ------------------------------------------------------------------ a weekly run at scale: thirteen organizations

WS_RUA = "mailto:dmarc-reports@corp.example"
WS_APEX = "v=DMARC1; p=quarantine; sp=none; rua=%s; fo=1;" % WS_RUA
WS_SUBS = ["hr", "billing", "alerts", "news", "support", "events", "mkt", "careers"]
WS_QUIET = ["archive", "labs", "test", "legacy"]
WS_PUBLISHED = ["hr", "billing", "news", "support"]  # own p=none records published between the two weeks
WS_HOSTS = {"corp.example": "Route53", "corp-brand.example": "Cloudflare", "corp.co.uk": "CSC", "corp.de": "CSC",
            "corp.fr": "CSC", "corpbank.example": "Route53", "corp-careers.example": "Cloudflare",
            "corp-events.example": "GoDaddy", "corp-foundation.example": "Cloudflare", "corp-labs.example": "Route53",
            "parked-one.example": "unknown", "parked-two.example": "unknown", "old-brand.example": "GoDaddy"}
WS_OWNERS = ("pattern,owner,channel,note\ncorp.example,Messaging team,#mail-ops,\n*.corp.example,Messaging team,#mail-ops,\n"
             "corp-brand.example,Brand web team,#brand-web,\ncorp.co.uk,UK IT,#uk-it,\n"
             "corpbank.example,Bank security,#bank-sec,\n")


def weekly_docs(week):
    """The weekly review's thirteen organizations (28 audited names, 12 of them under corp.example): DNS as week 1
    or week 2 finds it (four subdomains publish p=none records of their own between the two)."""
    docs = {"corp.example": T.own_record("corp.example", WS_APEX)}
    for s in WS_SUBS + WS_QUIET:
        name = s + ".corp.example"
        docs[name] = (T.own_record(name, "v=DMARC1; p=none; rua=%s;" % WS_RUA) if week >= 2 and s in WS_PUBLISHED
                      else T.inherits(name, WS_APEX, "_dmarc.corp.example"))
    brand = "v=DMARC1; p=none; rua=mailto:dmarc@corp-brand.example;"
    docs["corp-brand.example"] = T.own_record("corp-brand.example", brand)
    docs["shop.corp-brand.example"] = T.own_record("shop.corp-brand.example", "v=DMARC1; p=none; rua=%s;" % WS_RUA)
    docs["mail.corp-brand.example"] = T.inherits("mail.corp-brand.example", brand, "_dmarc.corp-brand.example")
    uk = "v=DMARC1; p=none; rua=%s;" % WS_RUA
    docs["corp.co.uk"] = T.own_record("corp.co.uk", uk)
    docs["mail.corp.co.uk"] = T.inherits("mail.corp.co.uk", uk, "_dmarc.corp.co.uk")
    docs["corp.de"] = T.own_record("corp.de", "v=DMARC1; p=quarantine; pct=25; rua=%s;" % WS_RUA)
    docs["corp.fr"] = T.dns_doc("corp.fr", findings=T.fid("DMARC-001"))
    docs["corpbank.example"] = T.own_record("corpbank.example", "v=DMARC1; p=reject; rua=%s;" % WS_RUA)
    for d in ("corp-careers.example", "corp-foundation.example", "corp-labs.example"):
        docs[d] = T.own_record(d, "v=DMARC1; p=none; rua=%s;" % WS_RUA)
    docs["corp-events.example"] = T.own_record("corp-events.example",
                                               "v=DMARC1; p=none; rua=mailto:dmarc@events-vendor.invalid;")
    for p in ("parked-one.example", "parked-two.example", "old-brand.example"):
        docs[p] = T.dns_doc(p, spf=None, spf_status="absent", spf_terminator=None, spf_lookups=0, dkim_selectors=[],
                            dkim_status="absent", mx=[], mx_status="absent", findings=T.fid("DMARC-001", "SPF-001"))
    return docs


def weekly_log(week):
    """The week's mail log, its counts the weekly review's: our own senders failing (two let in by a transport
    rule), vendors on a weak sign, lures receivers quarantined; week 2 doubles the receipts, fixes the alerts and
    adds two new failing senders (one under corp.example, which the row budget cut in both weeks)."""
    log = (O.Log(overrides=True)
           .add("staff@corp.example", "Weekly team update #", 40, direction="Intra-org")
           .add("noreply@corp.example", "Your receipt #", 112 if week >= 2 else 56, dmarc="fail", org=TRANSPORT_RULE)
           .add("payroll@corp.example", "Payroll run # complete", 21, env="payroll-vendor.invalid", dmarc="fail")
           .add("ceo@corp.example", "Urgent wire transfer #", 11, env="evil.invalid", where=O.QUARANTINED,
                dmarc="fail")
           .add("alerts@alerts.corp.example", "Service alert #", 12, dmarc="pass" if week >= 2 else "fail")
           .add("hr@hr.corp.example", "Benefits enrolment #", 10, direction="Intra-org")
           .add("rsvp@events.corp.example", "Event # reminder", 11, env="events-vendor.invalid", dmarc="fail")
           .add("offers@mkt.corp.example", "Spring offer #", 11, dmarc="fail")
           .add("team@corp-brand.example", "Brand standup #", 30, direction="Intra-org")
           .add("orders@shop.corp-brand.example", "Order # shipped", 157, dmarc="fail", org=TRANSPORT_RULE)
           .add("staff@corp.co.uk", "UK update #", 20, direction="Intra-org")
           .add("billing@corp.co.uk", "Statement # ready", 30, dmarc="fail")
           .add("team@corp.de", "Wochenbericht #", 10, direction="Intra-org")
           .add("factures@corp.fr", "Facture # disponible", 15, dmarc="fail")
           .add("staff@corpbank.example", "Bank memo #", 10, direction="Intra-org")
           .add("security@corpbank.example", "Your password expires today #", 30, env="lure.invalid",
                where=O.QUARANTINED, dmarc="fail")
           .add("hello@corp-events.example", "Save the date #", 15, dmarc="fail")
           .add("donate@corp-foundation.example", "Thank you for your gift #", 30, env="donor-platform.invalid",
                dmarc="fail")
           .add("staff@corp-foundation.example", "Foundation notes #", 10, direction="Intra-org"))
    if week >= 2:
        log.add("newsletter@news.corp.example", "Weekly digest #", 60, dmarc="fail")
        log.add("payslips@corp.co.uk", "Payslip # issued", 14, dmarc="fail")
    return log


def weekly_flows():
    flows = {d: T.flow(40, 40) for d in weekly_docs(2)}
    for s in WS_QUIET + ["parked-one", "parked-two", "old-brand"]:
        flows[s + (".corp.example" if s in WS_QUIET else ".example")] = T.flow(0, 0)
    return flows


def weekly_week(tmp_path, week):
    """One week's report as collect.py writes it under a row budget that cut corp.example and corp-brand.example
    (maillog.cuts, and the full window counted in advanced hunting: maillog.window_totals)."""
    inp = tmp_path / ("inputs-week%d" % week)
    inp.mkdir(parents=True, exist_ok=True)
    spoofs = [("203.0.113.%d" % (k + 1), 8 + 9 * k, "corp.example", None, None, "spoof%d.invalid" % k, "fail")
              for k in range(6)]
    reports = [T.rua_report(inp / "corp-example.xml", "corp.example", "quarantine", [
                   ("192.0.2.10", 4000, "corp.example", "corp.example", "pass", "corp.example", "pass")] + spoofs,
                   begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
               T.rua_report(inp / "corp-uk.xml", "corp.co.uk", "none", [
                   ("192.0.2.40", 700, "corp.co.uk", "corp.co.uk", "pass", "corp.co.uk", "pass")],
                   begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN)]
    docs = weekly_docs(week)
    rep = T.audited(tmp_path / ("week%d" % week), docs, weekly_log(week), reports, flows=weekly_flows(),
                    sources={d: ["tenant"] for d in docs})
    rep["findings"] = audit.flatten_findings(rep)
    rep["maillog"]["cuts"] = {
        "corp.example": {"reason": "row budget", "kept_hours": 241 if week >= 2 else 256,
                         "kept_from": "2026-09-28T13:00:00Z"},
        "corp-brand.example": {"reason": "row budget", "kept_hours": 627, "kept_from": "2026-09-13T03:00:00Z"}}
    rep["maillog"]["window_totals"] = {"hours": 720, "orgs": {
        "corp.example": {"source": "Advanced Hunting aggregate", "by_domain": {
            "corp.example": {"logical_messages": 900, "genuine_failures": 202, "delivered_despite_fail": 172},
            "events.corp.example": {"logical_messages": 30, "genuine_failures": 30, "delivered_despite_fail": 30},
            "mkt.corp.example": {"logical_messages": 30, "genuine_failures": 30, "delivered_despite_fail": 30},
            "news.corp.example": {"logical_messages": 60, "genuine_failures": 60, "delivered_despite_fail": 60}}},
        "corp-brand.example": {"source": "Advanced Hunting aggregate", "by_domain": {
            "corp-brand.example": {"logical_messages": 90, "genuine_failures": 0, "delivered_despite_fail": 0},
            "shop.corp-brand.example": {"logical_messages": 180, "genuine_failures": 180,
                                        "delivered_despite_fail": 180}}}}}
    if week >= 2:
        rep["generated_utc"] = "2026-10-14T06:00:00Z"
    return rep, docs


def weekly(tmp_path):
    """The weekly review's week 2 end to end, with week 1 as the previous run (the delta collect.py writes):
    {"report", "plan", "inventory", "doc", "previous", "owners_path"}. The owners file names five owners."""
    previous, _ = weekly_week(tmp_path, 1)
    rep, docs = weekly_week(tmp_path, 2)
    rep["delta"] = audit.build_delta(rep, previous)
    hosts = {d: (org_of(d), WS_HOSTS[org_of(d)]) for d in docs}
    inventory = inventory_of(hosts, weekly_flows())
    plan = plan_mod.build_plan(rep, inventory, WS_RUA)
    owners_path = tmp_path / "owners.csv"
    owners_path.write_text(WS_OWNERS, encoding="utf-8")
    doc = next_steps.build(rep, plan=plan, owners=next_steps.read_owners(owners_path), owners_path=str(owners_path),
                           date="2026-10-14")
    return {"report": rep, "plan": plan, "inventory": inventory, "doc": doc, "previous": previous,
            "owners_path": owners_path}


def org_of(name):
    return plan_mod.org_domain(name)
