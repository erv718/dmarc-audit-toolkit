"""Round 13: the synthetic runs the round's tests share, built with the round-11 helpers
(test_r11_plan's Log, rua_report, own_record, inherits, audited) the way the review's estate
builder builds them. Synthetic names only (example.com, example.net, example.org,
brand.example, .invalid, the documentation IP ranges); offline: nothing here touches the
network. Not a test module: the test_r13_*.py files import it."""

import next_steps
import plan as plan_mod
import test_r11_plan as T

RUA = T.RUA
ESTATE_APEX = "v=DMARC1; p=quarantine; sp=none; rua=%s; ruf=mailto:forensics@example.com; fo=1;" % RUA
ESTATE_DATE = "2026-10-13"


def estate_parts(tmp_path, net_clean=False, nobodys_stream=False):
    """The five-organization estate's inputs: (docs, log, reports, flows, sources, hosts). example.com with
    sending and quiet subdomains and a delegated zone (shop.example.com); example.net on p=none reporting
    to a vendor; brand.example at reject; example.org with no record and no mail; parked.example with
    nothing at all. The mail log holds our own senders, a vendor, weak and strong spoofing; the reports
    hold a failing vendor stream as example.com (198.51.100.20), a spoof receivers delivered as
    example.com (203.0.113.66) and one as example.net (203.0.113.9). net_clean: example.net has nothing
    failing (no failing sender in the log, no spoof stream), so its gate is go; nobodys_stream: the reports
    also hold a failing stream with no From domain (192.0.2.99), which nothing attributes to one name."""
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


def first_run(tmp_path, rua=None):
    """The first run end to end, as collect.py writes it with no report mailbox (rua None: the plan's new records
    carry plan.RUA_PLACEHOLDER) or with --rua-address: {"report", "plan", "inventory", "doc"}; no owners file."""
    docs, log, flows, hosts = first_run_parts()
    rep = T.audited(tmp_path / "run", docs, log, flows=flows, sources={d: ["tenant"] for d in docs})
    inventory = inventory_of(hosts, flows)
    plan = plan_mod.build_plan(rep, inventory, rua)
    doc = next_steps.build(rep, plan=plan, date="2026-10-20")
    return {"report": rep, "plan": plan, "inventory": inventory, "doc": doc}
