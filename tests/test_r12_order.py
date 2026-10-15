"""Round 12: one order for every list of domains. A subdomain sits with its
own organization, the organizational domain first and the names below it by
name; the headline's organization - the one the status document leads with -
leads when one is given. Every file of a run follows it: plan.json and
plan.md (a zone line under a DNS host that holds several zones),
next_steps.json and next_steps.md (the per-domain table, the owners' items
grouped by organization, the open questions grouped by kind), todo.md,
summary.txt, verify.md and report.md. Synthetic data, offline: no network."""

import re
from collections import Counter

import pytest

import audit
import collect
import discover
import next_steps
import notify
import plan as plan_mod
import test_r11_plan as r11  # the synthetic tenant pieces: DNS documents, a mail-log export, aggregate reports
import verify


NAMES = ["t.example.com", "example.net", "e.example.com", "example.com", "a.example.net", "dev.support.example.com",
         "m.example.com", "b.example.co.uk", "example.co.uk"]


def test_a_subdomain_sits_with_its_own_organization():
    assert audit.order_domains(NAMES) == [
        "example.co.uk", "b.example.co.uk",
        "example.com", "dev.support.example.com", "e.example.com", "m.example.com", "t.example.com",
        "example.net", "a.example.net"]
    # a plain text sort is what put the names out of order: e.example.com between two other organizations
    assert sorted(NAMES).index("e.example.com") < sorted(NAMES).index("example.com")


def test_the_headline_organization_leads():
    assert audit.order_domains(NAMES, headline="mail.example.net")[:2] == ["example.net", "a.example.net"]
    assert audit.order_domains(NAMES, headline="example.com")[:5] == [
        "example.com", "dev.support.example.com", "e.example.com", "m.example.com", "t.example.com"]
    assert audit.order_domains(NAMES, headline="") == audit.order_domains(NAMES)


def test_names_compare_as_gate_keys_spell_them_and_odd_values_drop_out():
    assert audit.order_domains(["Example.COM.", "example.com", " e.example.com", None, "", 7]) == [
        "Example.COM.", " e.example.com"]
    assert audit.domain_key("Sub.Example.com.") == audit.domain_key("sub.example.com")
    assert sorted(["b.example.com", "example.com", "a.example.com"], key=audit.domain_key) == [
        "example.com", "a.example.com", "b.example.com"]


# ------------------------------------------------------------------ one synthetic estate, through every file

RUA = "mailto:dmarc-reports@example.com"
APEX = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
OWN = "v=DMARC1; p=none; rua=%s;" % RUA
NET = "v=DMARC1; p=none;"  # no rua: a hygiene row adds the report address
# the domains as a tenant lists them: an order nobody reading the files would follow
GIVEN = ["t.example.com", "example.net", "brand.example", "m.example.com", "shop.example.com", "a.example.com",
         "example.com", "mail.example.net", "e.example.com", "dev.support.example.com"]
# the one order: the headline's organization (example.com, with its delegated shop.example.com), then each
# organization by name - brand.example before example.net, and never between two of example.com's names
ORDER = ["example.com", "a.example.com", "dev.support.example.com", "e.example.com", "m.example.com",
         "shop.example.com", "t.example.com", "brand.example", "example.net", "mail.example.net"]
HOSTS = {"example.com": "Alpha DNS", "shop.example.com": "Alpha DNS", "brand.example": "Alpha DNS",
         "example.net": "Beta DNS"}
# e., m. and t. say the same in every column; dev.support. was not measured
FLOWS = {"example.com": r11.flow(500, 40), "a.example.com": r11.flow(30), "e.example.com": r11.flow(10),
         "m.example.com": r11.flow(10), "t.example.com": r11.flow(10), "dev.support.example.com": None,
         "shop.example.com": r11.flow(60), "example.net": r11.flow(100), "mail.example.net": r11.flow(5),
         "brand.example": r11.flow(3, 1)}
OWNERS = [{"pattern": "brand.example", "kind": "domain", "owner": "Brand team", "channel": "#brand", "note": ""}]
HOLD = ("subdomains that send have no record of their own: dev.support.example.com (not measured), e.example.com, "
        "m.example.com, news.example.com (not checked) and t.example.com")


def zone_of(name):
    """shop.example.com is a zone of its own, delegated from example.com; every other name sits in its
    organization's zone."""
    return "shop.example.com" if name == "shop.example.com" else discover.org_domain(name)


def finding(fid, source, title, severity="major", verified=True, obj=None):
    f = {"id": fid, "severity": severity, "area": fid.split("-")[0].lower(), "title": title, "evidence": title,
         "action": "look into it", "verified": verified, "source": source}
    if obj:
        f["object"] = obj
    return f


def estate(tmp_path):
    """(report, plan) for three organizations on two DNS hosts: example.com (the headline) with a., e., m., t.,
    dev.support. and shop. - shop. a delegated zone of its own - and news.example.com seen sending but not
    audited; example.net with mail.; brand.example. Built offline by audit.build_report and plan.build_plan."""
    docs = {n: r11.inherits(n, APEX, "_dmarc.example.com")
            for n in ("e.example.com", "m.example.com", "t.example.com", "dev.support.example.com")}
    docs.update({
        "example.com": r11.own_record("example.com", APEX),
        "a.example.com": r11.own_record("a.example.com", OWN),
        "shop.example.com": r11.own_record("shop.example.com", OWN),
        "example.net": r11.dns_doc("example.net", dmarc=NET, dmarc_source="_dmarc.example.net",
                                   effective_policy="none", dmarc_status="found",
                                   findings=r11.fid("DMARC-002", "DMARC-003")),
        "mail.example.net": r11.inherits("mail.example.net", NET, "_dmarc.example.net"),
        "brand.example": r11.dns_doc("brand.example", spf="v=spf1 include:spf.protection.outlook.com ?all",
                                     spf_terminator="?all", findings=r11.fid("DMARC-001", "SPF-003", "SPF-005"))})
    log = r11.Log()
    log.add("staff@example.com", "Weekly report #", times=20)
    log.add("hr@example.com", "Payslip # issued", "fail", 3)  # our own system, misconfigured
    log.add("ceo@example.com", "Urgent wire request #", "fail", 4, env="spoofer.invalid")  # spoofing
    log.add("billing@a.example.com", "Statement # ready", "fail", 12)
    log.add("notify@example.net", "Notice # sent", "fail", 10)
    log.add("team@example.net", "Hello #", times=5)
    rua_dir = tmp_path / "rua"
    rua_dir.mkdir(parents=True)
    r11.rua_report(rua_dir / "net.xml", "example.net", "none", [
        ("192.0.2.10", 200, "example.net", "example.net", "pass", "example.net", "pass"),
        ("198.51.100.7", 40, "example.net", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("203.0.113.9", 30, "example.net", "", "", "spoofer.invalid", "fail"),
        ("192.0.2.30", 50, "mail.example.net", "", "", "mail.example.net", "pass")])
    sources = {d: ["tenant"] for d in GIVEN}
    rep = audit.build_report(domains=GIVEN, rua_paths=[str(rua_dir)], maillog=log.write(tmp_path / "maillog.csv"),
                             offline=True, auth_column="DMARC", domain_sources=sources, headline="example.com",
                             mailflow={"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": dict(FLOWS),
                                       "unaudited": {"news.example.com": r11.flow(8)}})
    rep["dns"] = docs
    rep["gate"] = audit.gate_verdict(docs, rep["rua"], rep["maillog"], GIVEN, None, {}, sources, "example.com")
    rep["generated_utc"] = "2026-10-09T06:00:00Z"
    rep["findings"] = rep["findings"] + [
        finding("SPF-006", "dns:example.net", "SPF one include away from the limit - new senders need DKIM"),
        finding("RULES-002", "rules", "Transport rule skips spam filtering for a partner", obj="Partner bypass"),
        finding("DKIM-001", "dns:brand.example", "wildcard at _domainkey", "minor", verified=False)]
    inventory = {"domains": [{"domain": d, "zone": zone_of(d), "zone_host": HOSTS[zone_of(d)]} for d in GIVEN]}
    return rep, plan_mod.build_plan(rep, inventory, RUA)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    rep, plan = estate(tmp_path_factory.mktemp("estate"))
    doc = next_steps.build(rep, plan, owners=OWNERS)
    return {"report": rep, "plan": plan, "doc": doc, "md": next_steps.render_md(doc)}


def section(md, title):
    """The lines under one '## ' heading, up to the next one."""
    return md.split("\n## %s" % title, 1)[1].split("\n## ", 1)[0].splitlines()[1:]


def test_every_file_leads_with_the_organization_the_status_document_leads_with(run):
    rep = run["report"]
    assert run["doc"]["org_domain"] == "example.com" and next_steps.headline_org(rep) == "example.com"
    assert next_steps.headline_org(rep, "Mail.Example.NET.") == "example.net"  # --org-name, as its organization
    # no domain to choose from: no headline, and the lists keep plain organization order
    assert next_steps.headline_org({"inputs": {"domains": []}, "gate": {}}) is None
    assert next_steps.headline_org({"gate": "damaged"}) is None and next_steps.headline_org(None) is None


# ------------------------------------------------------------------ O1, O2: the plan

def test_plan_rows_run_by_priority_host_zone_domain_and_record(run):
    """Priority, DNS host, then zone and domain in the one order (the headline's organization first, the
    delegated shop.example.com zone right after example.com's own), then the record; ids follow the sort. A
    plain text sort put brand.example first and a.example.com before example.com."""
    plan = run["plan"]
    assert [(c["id"], c["priority"], c["zone_host"], c["zone"], c["hostname"]) for c in plan["changes"]] == [
        ("P-01", 1, "Alpha DNS", "example.com", "_dmarc.dev.support.example.com"),
        ("P-02", 1, "Alpha DNS", "example.com", "_dmarc.e.example.com"),
        ("P-03", 1, "Alpha DNS", "example.com", "_dmarc.m.example.com"),
        ("P-04", 1, "Alpha DNS", "example.com", "_dmarc.news.example.com"),
        ("P-05", 1, "Alpha DNS", "example.com", "_dmarc.t.example.com"),
        ("P-06", 1, "Alpha DNS", "brand.example", "_dmarc.brand.example"),
        ("P-07", 1, "Alpha DNS", "brand.example", "brand.example"),
        ("P-08", 1, "Beta DNS", "example.net", "_dmarc.example.net"),
        ("P-09", 1, "Beta DNS", "example.net", "_dmarc.mail.example.net"),
        ("P-10", 3, "Alpha DNS", "example.com", "_dmarc.example.com"),
        ("P-11", 3, "Alpha DNS", "example.com", "_dmarc.a.example.com"),
        ("P-12", 3, "Alpha DNS", "shop.example.com", "_dmarc.shop.example.com"),
        ("P-13", 4, "Alpha DNS", "example.com", "_dmarc.example.com")]
    assert plan["by_zone_host"] == {"Alpha DNS": ["P-%02d" % i for i in (1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13)],
                                    "Beta DNS": ["P-08", "P-09"]}
    # the two rows that rewrite example.com's record still name each other by their new ids
    assert any("(P-13)" in p for p in plan["changes"][9]["prerequisites"])


def test_a_domains_dmarc_record_comes_first_and_an_unknown_host_last():
    """Within one domain its _dmarc record leads, then its own name (SPF), then its _domainkey names; a host
    nobody named (unknown) comes after the named ones. Text put 0.example.org's SPF row before its DMARC row,
    and 'unknown' before a host spelled in lower case."""
    rec = "v=DMARC1; p=none; rua=%s;" % RUA
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": ["example.org", "0.example.org"]},
           "gate": {"domains": {}}, "maillog": None, "rua": None,
           "dns": {"example.org": r11.own_record("example.org", rec),
                   "0.example.org": r11.inherits("0.example.org", rec, "_dmarc.example.org",
                                                 spf="v=spf1 include:spf.protection.outlook.com ?all",
                                                 spf_terminator="?all")}}
    plan = plan_mod.build_plan(rep, {"domains": [{"domain": "example.org", "zone": "example.org", "zone_host": "zns"}]},
                               RUA)
    assert [(c["zone_host"], c["hostname"]) for c in plan["changes"] if c["priority"] == 1] == [
        ("unknown", "_dmarc.0.example.org"), ("unknown", "0.example.org")]
    rows = [{"priority": 1, "zone_host": h, "zone": "example.org", "domain": "example.org", "hostname": n}
            for h, n in (("unknown", "_dmarc.example.org"), ("zns", "s1._domainkey.example.org"),
                         ("zns", "example.org"), ("zns", "_dmarc.example.org"), ("", "x.example.org"))]
    assert [(r["zone_host"], r["hostname"]) for r in sorted(rows, key=plan_mod.row_key)] == [
        ("zns", "_dmarc.example.org"), ("zns", "example.org"), ("zns", "s1._domainkey.example.org"),
        ("", "x.example.org"), ("unknown", "_dmarc.example.org")]


def test_plan_md_names_each_zone_under_a_host_that_holds_several(run):
    md = plan_mod.render_md(run["plan"])
    heads = re.findall(r"^(#{2,4} .+)$", md, re.M)
    p1 = heads.index("## Priority 1 - %s" % plan_mod.PRIORITY_LABEL[1])
    assert heads[p1:p1 + 5] == ["## Priority 1 - %s" % plan_mod.PRIORITY_LABEL[1], "### Alpha DNS",
                                "#### example.com", "#### brand.example", "### Beta DNS"]  # one zone: no zone line
    p3 = heads.index("## Priority 3 - %s" % plan_mod.PRIORITY_LABEL[3])
    assert heads[p3:] == ["## Priority 3 - %s" % plan_mod.PRIORITY_LABEL[3], "### Alpha DNS", "#### example.com",
                          "#### shop.example.com", "## Priority 4 - %s" % plan_mod.PRIORITY_LABEL[4], "### Alpha DNS",
                          "## How to use this"]
    # each zone's own table and rows under its line, the row text as before
    shop = md.split("#### shop.example.com\n", 1)[1].split("\n## ", 1)[0]
    assert shop.startswith("\n| # | Record | Hostname | Value | TTL |\n|---|---|---|---|---|\n| P-12 | TXT | "
                           "`_dmarc.shop.example.com` | `%s` | 3600 |" % OWN.replace("p=none", "p=quarantine; pct=25"))
    assert "- **P-12** shop.example.com - first enforcement step" in shop and "P-11" not in shop


def test_a_holds_name_list_runs_in_order_with_its_marks(run):
    """The sp= hold names the sending subdomains and the unmeasured ones as one list in the one order, each
    keeping its mark; two sorted lists end to end put dev.support.example.com last. The holds themselves run
    in the domains' order, the headline's first."""
    plan = run["plan"]
    assert [h["domain"] for h in plan["holds"]] == ["example.com", "brand.example"]
    assert plan["holds"][0]["reason"].startswith(HOLD + " - publish their monitoring records (above) before sp= moves")
    sp = plan["changes"][12]
    assert sp["prerequisites"][0] == "every subdomain that sends has its own _dmarc record: %s have none yet (the " \
                                     "monitoring records above)" % HOLD.split(": ", 1)[1]
    assert "example.com: %s - publish" % HOLD in run["md"]
    todo = collect.render_todo(run["report"], plan)
    assert section(todo, "1. Decide first (plan holds)")[1].startswith("- example.com: %s - publish" % HOLD)


# ------------------------------------------------------------------ O4 to O6, O11: the status document

def test_the_per_domain_rows_run_in_order_and_merge_only_next_to_each_other(run):
    """The headline's organization first, its own domain before its subdomains; e. and m. share a row, and
    t. - which says the same in every column - keeps its own, because shop. sits between them."""
    rows = run["doc"]["per_domain"]
    assert [r["domains"] for r in rows] == [["example.com"], ["a.example.com"], ["dev.support.example.com"],
                                            ["e.example.com", "m.example.com"], ["shop.example.com"], ["t.example.com"],
                                            ["brand.example"], ["example.net"], ["mail.example.net"]]
    assert [r["org"] for r in rows] == ["example.com"] * 6 + ["brand.example", "example.net", "example.net"]
    assert rows[3]["plan_ids"] == ["P-02", "P-03"] and rows[5]["plan_ids"] == ["P-05"]
    assert {k: rows[5][k] for k in ("policy_today", "gate", "next_step", "mailflow_text")} == \
        {k: rows[3][k] for k in ("policy_today", "gate", "next_step", "mailflow_text")}
    table = [l for l in section(run["md"], "Per domain") if l.startswith("| `")]
    assert [re.findall(r"`([^`]+)`", l.split(" | ")[0]) for l in table] == [r["domains"] for r in rows]
    # the document's organization leads, whichever it is
    other = next_steps.build(run["report"], run["plan"], owners=OWNERS, org_name="example.net")
    assert [d for r in other["per_domain"] for d in r["domains"]][:4] == [
        "example.net", "mail.example.net", "brand.example", "example.com"]


def test_an_owners_items_run_by_kind_then_organization_and_a_big_group_is_grouped(run):
    groups = {g["owner"]: g["items"] for g in run["doc"]["actions_by_owner"]}
    items = groups[next_steps.UNASSIGNED]
    assert all(set(i) >= {"domains", "org"} for g in groups.values() for i in g)
    # the zero-risk bundle, the plan rows in plan order, sender fixes, overrides, outside sources, other findings
    assert [i["kind"] for i in items] == ["p1summary"] + ["dns"] * 4 + ["sender"] * 3 + ["override"] * 4 + [
        "spoof", "stream", "spoof", "spf_only", "finding", "finding"]
    assert items[0]["domains"] == ["dev.support.example.com", "e.example.com", "m.example.com", "news.example.com",
                                   "t.example.com", "example.net", "mail.example.net"] and items[0]["org"] == "example.com"
    assert [i["ref"] for i in items if i["kind"] == "dns"] == ["P-10", "P-11", "P-12", "P-13"]
    # within a kind: the headline's organization first, then by domain, then as they were ranked
    assert [i["hook"] for i in items if i["kind"] == "sender"] == [
        "hr@example.com - 3 messages", "billing@a.example.com - 12 messages", "notify@example.net - 10 messages"]
    assert [(i["org"], i["domains"]) for i in items if i["kind"] == "override"] == [
        ("example.com", ["example.com"]), ("example.com", ["example.com"]), ("example.com", ["a.example.com"]),
        ("example.net", ["example.net"])]
    assert (items[-1]["ref"], items[-1]["domains"], items[-1]["org"]) == ("RULES-002", [], "")  # tenant-wide: last
    # next_steps.md: a group of six items or more over two organizations gets a line per organization
    body = section(run["md"], "What happens next, by owner")
    start = body.index("- **%s**" % next_steps.UNASSIGNED)
    heads = [l for l in body[start:] if l.startswith("  - **")]
    assert heads == ["  - **example.com** - 11 items", "  - **example.net** - 6 items", "  - **Tenant-wide** - 1 item"]
    under = body[start + 1:]
    assert under[1].startswith("    - **7 zero-risk monitoring records** ready to publish")
    assert all(l.startswith(("  - **", "    - **")) for l in under if l)
    # a small group stays flat
    assert body[:2] == ["", "- **Brand team** (#brand)"]
    assert body[2].startswith("  - **2 zero-risk monitoring and hygiene records** ready to publish (plan P-06 to P-07)")


def test_the_open_questions_run_by_kind_then_organization_and_are_grouped_by_kind(run):
    qs = run["doc"]["open_questions"]
    kinds = [q["kind"] for q in qs]
    assert list(dict.fromkeys(kinds)) == ["blocker", "prerequisite", "hold", "unverified", "unassigned"]
    assert kinds == sorted(kinds, key=list(next_steps.QUESTION_KINDS).index)  # each kind together
    assert all(set(q) >= {"domains", "org"} for q in qs)
    assert [q["domains"] for q in qs if q["kind"] == "hold"] == [["example.com"], ["brand.example"]]
    unverified = [q for q in qs if q["kind"] == "unverified"]
    assert unverified[0]["domains"] == ["brand.example"] and [q["org"] for q in unverified[1:]] == ["", "", ""]
    # within one domain (here: none, tenant-wide) the questions keep the order they were asked in - the report's
    # findings order for these - never the alphabet: a plan row lists its prerequisites most important first
    ids = [f["id"] for f in run["report"]["findings"] if f.get("verified") is False]
    asked = [next(i for i in ids if "(%s," % i in q["question"]) for q in unverified[1:]]
    assert asked == sorted(asked, key=ids.index)
    owned = [q for q in qs if q["kind"] == "unassigned"]
    assert [q["org"] for q in owned] == ["example.com"] * 11 + ["example.net"] * 6 + [""]
    assert owned[-1]["question"] == "Who owns this: Partner bypass (RULES-002)?"
    # next_steps.md: one bold line per kind, in plain words, with its count, and the questions under it
    body = [l for l in section(run["md"], "Open questions") if l and l != "---"]
    assert [l for l in body if l.startswith("**")] == [
        "**Blockers (3)**", "**Prerequisites (9)**", "**Plan holds (2)**", "**Not verified yet (4)**",
        "**Needs an owner (18)**"]
    holds = body.index("**Plan holds (2)**")
    assert body[holds + 1].startswith("- example.com: %s" % HOLD) and body[holds + 2].startswith("- brand.example: ")


def flat_actions(groups, failing=None, headline=None):
    """The owners' items as r12-base wrote them: one flat list per owner."""
    L = []
    for g in groups:
        L.append("- **%s**" % g["owner"] + (" (%s)" % g["channel"] if g["channel"] else ""))
        L += ["  - **%s** %s%s" % (i["hook"], i["action"], (" (%s)" % i["ref"]) if i.get("ref") else "")
              for i in g["items"]]
    return L


def flat_questions(questions):
    """The open questions as r12-base wrote them: one flat list."""
    return ["- %s%s (owner: %s)" % (q["question"], (" x %d" % q["count"]) if q.get("count", 1) > 1 else "", q["owner"])
            for q in questions]


def test_the_grouping_moves_lines_and_adds_only_its_own(run, monkeypatch):
    """Every line the flat document held is still there, once; what the grouped one adds is the lines that
    name an organization or a kind, nothing else."""
    new = next_steps.render_md(run["doc"])
    monkeypatch.setattr(next_steps, "render_actions", flat_actions)
    monkeypatch.setattr(next_steps, "render_questions", flat_questions, raising=False)
    old = next_steps.render_md(run["doc"])

    def body(md):
        return Counter(l.strip() for l in md.splitlines() if l.strip() and not l.startswith("#"))
    added = body(new) - body(old)
    assert body(old) - body(new) == Counter()  # nothing the old document said is gone
    grouping = re.compile(r"^(- \*\*(\S+\.\S+|Tenant-wide)\*\* - \d+ items?|\*\*[A-Z][a-z ]+ \(\d+\)\*\*)$")
    assert added and all(grouping.match(l) for l in added), added
    assert sum(1 for l in added if l.startswith("**")) == 5 and sum(1 for l in added if l.startswith("- **")) == 3


# ------------------------------------------------------------------ O7 to O10: todo.md, summary.txt, verify.md, report.md

def test_todo_md_names_the_domains_in_order(run):
    todo = collect.render_todo(run["report"], run["plan"])
    stands = [l for l in section(todo, "Where each domain stands") if l.startswith("- ")]
    assert [l[2:].split(":")[0] for l in stands] == ORDER
    assert [l.split()[1] for l in section(todo, "2. Do now") if l.startswith("- P-")] == [
        "P-%02d" % i for i in range(1, 10)]


def test_summary_txt_names_the_domains_in_order(run):
    text = notify.summarize(run["report"], None, run["plan"])
    assert re.findall(r"^- `([^`]+)`: p=", text, re.M) == ORDER


def test_verify_md_runs_domain_by_domain_in_order(run, tmp_path):
    mpath, _ = verify.write(run["report"], run["plan"], tmp_path)
    md = mpath.read_text(encoding="utf-8")
    with_news = ORDER[:5] + ["news.example.com"] + ORDER[5:]  # the name only the plan names sits with its family
    assert re.findall(r"^## (.+)$", md, re.M) == ["Contents"] + with_news + ["Across the run", "Queries for the portal"]
    assert [l[2:].split(":")[0] for l in section(md, "Contents") if l.startswith("- ")][:-2] == with_news
    # a domain's plan rows in plan order
    apex = md.split("\n## example.com\n", 1)[1].split("\n## ", 1)[0]
    assert re.findall(r"^#### (P-\d+) ", apex, re.M) == ["P-10", "P-13"]
    files = re.findall(r"^- queries/\S+?_([a-z.]+)\.kql, for ", md, re.M)
    assert list(dict.fromkeys(files)) == ORDER  # the queries for the portal, name by name in the same order


def test_report_md_runs_domain_by_domain_in_order(run):
    md = audit.render_md(run["report"])
    assert re.findall(r"^- ([a-z.]+): \*\*", md, re.M) == ORDER
    assert re.findall(r"^### (.+)$", md, re.M) == ORDER
    assert re.findall(r"^- ([a-z.]+): (?:sends|not measured)", md, re.M) == ORDER
    assert "- domains: %s\n" % ", ".join(ORDER) in md
    assert [d for d in re.findall(r"^- ([a-z.]+): (?:\d+ logical|no mail-log rows)", md, re.M)] == ORDER


def test_a_list_ranked_by_a_count_breaks_ties_in_the_one_order():
    """Counts rank; on a tie the one order decides (the headline's organization first, an organization's own
    domain before its names), where plain text put e.example.com ahead of example.com."""
    census = {"by_envelope": [{"envelope_domain": d, "genuine_failures": 5, "messages": 5}
                              for d in ("e.example.com", "brand.example", "example.com", "x.example.net")]}
    rep = {"maillog": {"counters": {"genuine_failures": 20}, "census": census}}
    names = [e["name"] for e in next_steps.maillog_view(rep)["by_envelope"]]
    assert names == ["brand.example", "example.com", "e.example.com", "x.example.net"]
    names = [e["name"] for e in next_steps.maillog_view(rep, "example.com")["by_envelope"]]
    assert names == ["example.com", "e.example.com", "brand.example", "x.example.net"]
    assert notify.census_top(census, 4, "x.example.net")[0] == [
        "x.example.net x5 (unknown)", "brand.example x5 (unknown)", "example.com x5 (unknown)",
        "e.example.com x5 (unknown)"]


def test_a_sentence_that_names_organizations_names_the_headlines_first():
    """The trend line's reasons name the organizations a cut or a change of scope touched, in the one order: by
    name with no headline, the headline's first when there is one."""
    cut = {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T19:00:00Z"}
    cuts = {o: {"now": cut, "previous": None} for o in ("example.net", "brand.example", "example.com")}
    assert next_steps._cut_reason(cuts) == ("the row budget cut the mail log for brand.example, example.com and "
                                            "example.net in this run")
    assert next_steps._cut_reason(cuts, "example.com") == ("the row budget cut the mail log for example.com, "
                                                           "brand.example and example.net in this run")
    assert next_steps._orgs_reason({"example.net", "brand.example"}, "example.net") == (
        "example.net and brand.example audited in one of the two runs only")
    first = {"genuine_failures": 50, "maillog_hours": 700.0, "maillog_cut_orgs": ["example.net", "brand.example"]}
    last = dict(first, genuine_failures=40)
    assert notify.trend_judgement([first, last], "example.net")[1] == [
        "failure counts not compared: the mail log was cut for example.net and brand.example in both runs"]
