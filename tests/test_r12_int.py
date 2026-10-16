"""Round 12, integration: what the review of the merged fixes found. The
brief groups an owner's items and splits What is failing with the helpers
next_steps.md uses, so the two never disagree on a line or a count; a long
DNS label wraps instead of passing the screen's edge, and every table reads
as blocks on a narrow screen; Where we stand says "deduplicated" of the
mail-log counts only; an empty Per domain says so above the audit's notes;
only the characters that reorder or hide text show as a marker, and every
data string sits in its own bidi isolate; the aggregate-report one-liner
puts each count with its source; tied senders are ranked alike in every
file; report.md's caveats and the stored cut clause name the headline's
organization first. Synthetic data, offline: nothing here touches the
network."""

import html
import io
import json
import re
import socket
import subprocess
import sys
import tokenize
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest

import audit
import brief
import collect
import discover
import next_steps
import plan as plan_mod
import test_r10_comparability as comp  # the in-memory tenant collect.main pulls a mail log from
import test_r11_plan as r11  # the synthetic tenant pieces: DNS documents, a mail-log export, aggregate reports
import test_r12_order as r12  # the round's three-organization estate
import verify

ROOT = Path(__file__).resolve().parent.parent
RLM = chr(0x200F)  # a right-to-left mark: it renders as itself, and reorders what follows it in its isolate


def section_of(page, sid):
    """One section's markup, from its id to its end."""
    start = page.index('id="%s"' % sid)
    return page[start:page.index("</section>", start)]


def text_of(fragment):
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def md_section(md, title):
    return md.split("\n## %s" % title, 1)[1].split("\n## ", 1)[0]


# ------------------------------------------------------------------ three estates, through next_steps and the brief

def stress_estate(tmp):
    """(report, plan, owners): ten organizations on three DNS hosts and unknown, two delegated zones, a 61-character
    label, one owner that holds most of the items (the visual review's stress estate)."""
    T = r11
    apex = "v=DMARC1; p=quarantine; sp=none; rua=%s; ruf=mailto:forensics@example.com; fo=1;" % T.RUA
    longsub = "transactional-notifications-for-customer-accounts-and-billing.eu-west-1.mail.example.com"
    longorg = "an-extraordinarily-long-organizational-domain-name-for-layout.example"
    sending = ["alerts", "billing", "careers", "community", "docs", "events", "investor-relations", "marketing",
               "news", "pay", "status", "support", "surveys", "webinars", "rewards"]
    quiet = ["archive", "beta", "dev.support", "intranet-legacy", "labs", "old-shop", "partners", "staging", "test",
             "wiki"]
    docs, flows, hosts = {"example.com": T.own_record("example.com", apex)}, {"example.com": T.flow(800, 1500)}, {}
    hosts["example.com"] = ("example.com", "Route53")
    for s in sending + quiet:
        d = "%s.example.com" % s
        docs[d] = T.inherits(d, apex, "_dmarc.example.com")
        flows[d] = T.flow(20 + len(s), 5) if s in sending else T.flow(0, 0)
        hosts[d] = ("example.com", "Route53")
    docs[longsub] = T.inherits(longsub, apex, "_dmarc.example.com")
    flows[longsub], hosts[longsub] = T.flow(400, 2), ("eu-west-1.mail.example.com", "Cloudflare")
    docs["shop.example.com"] = T.own_record("shop.example.com", "v=DMARC1; p=none; rua=%s;" % T.RUA)
    flows["shop.example.com"], hosts["shop.example.com"] = T.flow(0, 0), ("shop.example.com", "Route53")
    docs["example.net"] = T.own_record("example.net", "v=DMARC1; p=none; rua=%s;" % T.RUA)
    flows["example.net"], hosts["example.net"] = T.flow(120, 300), ("example.net", "CSC")
    docs["brand.example"] = T.own_record("brand.example", "v=DMARC1; p=reject; rua=%s;" % T.RUA)
    flows["brand.example"], hosts["brand.example"] = T.flow(50, 90), ("brand.example", "CSC")
    docs["alpha.example"] = T.own_record("alpha.example", "v=DMARC1; p=none; rua=%s;" % T.RUA)
    flows["alpha.example"], hosts["alpha.example"] = T.flow(30, 10), ("alpha.example", "CSC")
    docs["example.org"] = T.dns_doc("example.org", findings=T.fid("DMARC-001"))
    flows["example.org"], hosts["example.org"] = T.flow(0, 0), ("example.org", "Cloudflare")
    for p in ("parked.example", "parked-two.example", "holding.example", "legacy.example", longorg):
        docs[p] = T.dns_doc(p, spf=None, spf_status="absent", spf_terminator=None, spf_lookups=0, dkim_selectors=[],
                            dkim_status="absent", mx=[], mx_status="absent", findings=T.fid("DMARC-001", "SPF-001"))
        flows[p], hosts[p] = T.flow(0, 0), (p, "unknown" if p != "legacy.example" else "Cloudflare")
    log = (T.Log().add("staff@example.com", "Weekly team update #", times=60)
           .add("noreply@example.com", "Your receipt #", dmarc="fail", times=31)
           .add("automated-notifications-noreply@" + longsub, "Your monthly statement #", dmarc="fail", times=22)
           .add("billing@example.com", "Invoice # is ready", dmarc="fail", times=14, env="mailer.billing-vendor.invalid")
           .add("ceo@example.com", "Urgent wire transfer #", dmarc="fail", times=12, env="evil.invalid")
           .add("alerts@pay.example.com", "Payment alert #", dmarc="fail", times=11)
           .add("hello@example.net", "Welcome aboard #", dmarc="fail", times=10)
           .add("team@brand.example", "Brand update #", times=20)
           .add("hr@brand.example", "Your password expires today #", dmarc="fail", times=4, env="lure.invalid"))
    for i, s in enumerate(sending):
        log.add("info@%s.example.com" % s, "Update from %s #" % s, dmarc="fail", times=2 + i % 7)
    log.add("news@example.org", "Hello #", dmarc="fail", times=3).add("ops@alpha.example", "Ops digest #", "fail", 6)
    rows = [("192.0.2.10", 500, "example.com", "example.com", "pass", "example.com", "pass"),
            ("198.51.100.20", 60, "example.com", "esp.invalid", "pass", "esp.invalid", "pass")]
    rows += [("203.0.113.%d" % (40 + k), 9 + 7 * k, "example.com", None, None, "spoof%d.invalid" % k, "fail")
             for k in range(12)]
    reports = [T.rua_report(tmp / "com.xml", "example.com", "quarantine", rows, begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN),
               T.rua_report(tmp / "net.xml", "example.net", "none", [
                   ("198.51.100.7", 200, "example.net", "example.net", "pass", "example.net", "pass"),
                   ("203.0.113.9", 40, "example.net", None, None, "spoof.invalid", "fail")],
                   begin=T.BEGIN - 20 * T.DAY, end=T.BEGIN)]
    rep = T.audited(tmp / "run", docs, log, reports, flows=flows, sources={d: ["tenant"] for d in docs})
    rep["dns_extra"] = T.no_record("m.example.com", "t.example.com", "e.example.com")
    inventory = {"domains": [{"domain": d, "sources": ["tenant"], "org_domain": plan_mod.org_domain(d), "zone": z,
                              "zone_host": h, "mailflow": flows.get(d)} for d, (z, h) in sorted(hosts.items())]}
    owners_csv = tmp / "owners.csv"
    owners_csv.write_text("pattern,owner,channel,note\nexample.com,DNS and messaging team,#dns-changes,\n"
                          "example.org,DNS and messaging team,#dns-changes,\n"
                          "parked.example,DNS and messaging team,#dns-changes,\n"
                          "legacy.example,DNS and messaging team,#dns-changes,\n"
                          "example.net,Network brand team,#net-brand,\n", encoding="utf-8")
    return rep, plan_mod.build_plan(rep, inventory, T.RUA), next_steps.read_owners(owners_csv)


def awkward_estate(tmp):
    """(report, plan, owners): five organizations with awkward names (a deep x.y.example.org, a delegated
    shop.example.org, example.co.uk), six DNS hosts, mail-log cuts in three organizations and outside streams that
    name several organizations (the order review's awkward estate); example.org leads."""
    head, rua = "example.org", "mailto:dmarc-reports@example.org"
    apex, own = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % rua, "v=DMARC1; p=none; rua=%s;" % rua
    given = ["mail.example.co.uk", "example.net", "zeta.example.org", "brand.example", "x.y.example.org", "example.org",
             "y.example.org", "shop.example.org", "a.shop.example.org", "example.co.uk", "mail.example.net",
             "example.com", "e.example.com"]
    zones = {"shop.example.org": "shop.example.org", "a.shop.example.org": "shop.example.org"}
    hosts = {"example.org": "Route53", "shop.example.org": "other (ns1.example.net)", "example.co.uk": "NS1",
             "example.net": "Namecheap", "brand.example": "DNS Made Easy", "example.com": "DigitalOcean"}
    docs = {n: r11.inherits(n, apex, "_dmarc.example.org") for n in ("x.y.example.org", "y.example.org",
                                                                      "zeta.example.org")}
    docs.update({
        "example.org": r11.own_record("example.org", apex), "shop.example.org": r11.own_record("shop.example.org", own),
        "a.shop.example.org": r11.inherits("a.shop.example.org", own, "_dmarc.shop.example.org"),
        "example.co.uk": r11.own_record("example.co.uk", own),
        "mail.example.co.uk": r11.inherits("mail.example.co.uk", own, "_dmarc.example.co.uk"),
        "example.net": r11.dns_doc("example.net", dmarc="v=DMARC1; p=none;", dmarc_source="_dmarc.example.net",
                                   effective_policy="none", dmarc_status="found",
                                   findings=r11.fid("DMARC-002", "DMARC-003")),
        "mail.example.net": r11.inherits("mail.example.net", "v=DMARC1; p=none;", "_dmarc.example.net"),
        "brand.example": r11.dns_doc("brand.example", spf="v=spf1 include:spf.protection.outlook.com ?all",
                                     spf_terminator="?all", findings=r11.fid("DMARC-001", "SPF-003")),
        "example.com": r11.own_record("example.com", "v=DMARC1; p=reject; rua=%s;" % rua),
        "e.example.com": r11.inherits("e.example.com", "v=DMARC1; p=reject; rua=%s;" % rua, "_dmarc.example.com")})
    log = r11.Log()
    log.add("staff@example.org", "Weekly report #", times=20)
    for sender, env in (("hr@example.org", None), ("app@zeta.example.org", None), ("ops@x.y.example.org", None),
                        ("billing@example.co.uk", None), ("news@mail.example.co.uk", None),
                        ("notify@example.net", None), ("ceo@brand.example", "spoofer.invalid"),
                        ("info@e.example.com", None), ("x@news.example.org", None)):
        log.add(sender, "Notice #", "fail", 5, env=env)
    log.add("team@y.example.org", "Roster #", times=4).add("promo@b.example.org", "Offer #", times=6)
    rua_dir = tmp / "rua"
    rua_dir.mkdir(parents=True, exist_ok=True)
    r11.rua_report(rua_dir / "org.xml", "example.org", "quarantine", [
        ("192.0.2.10", 300, "example.org", "example.org", "pass", "example.org", "pass"),
        ("198.51.100.7", 40, "zeta.example.org", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.7", 40, "example.org", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.7", 40, "a.shop.example.org", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("203.0.113.9", 30, "x.y.example.org", "", "", "spoofer.invalid", "fail"),
        ("203.0.113.9", 30, "example.org", "", "", "spoofer.invalid", "fail")])
    r11.rua_report(rua_dir / "uk.xml", "example.co.uk", "none", [
        ("192.0.2.11", 100, "example.co.uk", "example.co.uk", "pass", "example.co.uk", "pass"),
        ("198.51.100.8", 40, "mail.example.co.uk", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.8", 40, "example.co.uk", "esp.invalid", "pass", "esp.invalid", "pass")])
    flows = {d: r11.flow(10, 1) for d in given}
    flows["example.org"] = r11.flow(500, 40)
    sources = {d: ["tenant"] for d in given}
    cuts = {"example.org": {"reason": "api cap", "api_cap_hours": ["6h..5h"]},
            "brand.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T22:00:00Z"}}
    rep = audit.build_report(domains=given, rua_paths=[str(rua_dir)], maillog=log.write(tmp / "maillog.csv"),
                             offline=True, auth_column="DMARC", domain_sources=sources, headline=head,
                             mailflow={"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": dict(flows),
                                       "unaudited": {"news.example.org": r11.flow(8), "b.example.org": r11.flow(8)}},
                             maillog_cuts=cuts)
    rep["dns"] = docs
    rep["gate"] = audit.gate_verdict(docs, rep["rua"], rep["maillog"], given, None, {}, sources, head)
    rep["generated_utc"] = "2026-10-09T06:00:00Z"
    rep["dns_extra"] = r11.no_record("news.example.org", "b.example.org")
    zone_of = lambda n: zones.get(n) or plan_mod.org_domain(n)  # noqa: E731
    inventory = {"domains": [{"domain": d, "zone": zone_of(d), "zone_host": hosts[zone_of(d)]} for d in given]}
    owners = [{"pattern": "brand.example", "kind": "domain", "owner": "Brand team", "channel": "#brand", "note": ""}]
    return rep, plan_mod.build_plan(rep, inventory, rua), owners


@pytest.fixture(scope="module")
def estates(tmp_path_factory):
    """{name: (doc, plan, next_steps.md, brief.html)} for the shipped, the stress and the awkward estate."""
    out = {}
    rep, plan = r12.estate(tmp_path_factory.mktemp("shipped"))
    built = {"shipped": (rep, plan, r12.OWNERS),
             "stress": stress_estate(tmp_path_factory.mktemp("stress")),
             "awkward": awkward_estate(tmp_path_factory.mktemp("awkward"))}
    for name, (rep, plan, owners) in built.items():
        doc = json.loads(json.dumps(next_steps.build(rep, plan, owners=owners)))  # as next_steps.json holds it
        out[name] = (doc, plan, next_steps.render_md(doc), brief.render(doc, plan))
    return out


# ------------------------------------------------------------------ I1: an owner's group, as next_steps.md groups it

def md_owner_groups(md):
    """next_steps.md's owner groups: {owner: [[line or None, count or None, [hooks]], ...]}, a flat group as one
    part with no line."""
    groups, owner = {}, None
    for line in md_section(md, "What happens next, by owner").splitlines():
        m = re.match(r"^- \*\*(.+?)\*\*", line)
        if m:
            owner = m.group(1)
            groups[owner] = []
            continue
        m = re.match(r"^  - \*\*(.+?)\*\* - (\d+) items?$", line)
        if m:
            groups[owner].append([m.group(1), int(m.group(2)), []])
            continue
        m = re.match(r"^( +)- \*\*(.+?)\*\* ", line)
        if m:
            if len(m.group(1)) == 2:
                if not groups[owner] or groups[owner][-1][0] is not None:
                    groups[owner].append([None, None, []])
            groups[owner][-1][2].append(m.group(2))
    return groups


def page_owner_groups(page):
    """brief.html's owner groups, in the same shape."""
    groups = {}
    for block in section_of(page, "owners").split('<div class="owner">')[1:]:
        h3 = re.search(r"<h3>(.*?)</h3>", block).group(1)
        owner = text_of(re.sub(r'<span class="channel">.*?</span>', "", h3)).strip()
        hooks = lambda part: [text_of(h) for h in re.findall(r'<span class="hook">(.*?)</span>', part)]  # noqa: E731
        pieces = block.split('<div class="org-block">')
        parts = [[None, None, hooks(pieces[0])]] if 'class="hook"' in pieces[0] else []
        for piece in pieces[1:]:
            m = re.match(r'<p class="org-head">(.*?) <span class="count">(\d+) items?</span></p>', piece)
            parts.append([text_of(m.group(1)), int(m.group(2)), hooks(piece)])
        groups[owner] = parts
    return groups


@pytest.mark.parametrize("name", ["shipped", "stress", "awkward"])
def test_the_brief_groups_an_owners_items_exactly_as_next_steps_md_does(estates, name):
    """One helper, next_steps.owner_parts, splits a group for both: the same organization lines in the same order, a
    one-item organization's line included, Several organizations and Tenant-wide, the same counts and the same items
    under each. The brief grouped by each item's first organization and folded a one-item line into a plain item,
    so the stress estate's DNS team read 30 items under example.com where next_steps.md says 28."""
    doc, plan, md, page = estates[name]
    want = md_owner_groups(md)
    assert want and page_owner_groups(page) == want
    lines = [part[0] for parts in want.values() for part in parts if part[0]]
    if name == "shipped":
        assert lines == ["example.com", "example.net", next_steps.TENANT_WIDE]
    else:
        assert next_steps.SEVERAL_ORGS in lines
    if name == "stress":  # the line the review counted: 28 items, as next_steps.md says, and example.org's single one
        dns = want["DNS and messaging team"]
        assert [(p[0], p[1]) for p in dns][:2] == [("example.com", 28), ("example.org", 1)]
    # the group split comes from next_steps.py, whatever order the document lists the items in
    for g in doc["actions_by_owner"]:
        assert [(n, len(p)) for n, p in next_steps.owner_parts(g["items"], doc["org_domain"])] == [
            (part[0], len(part[2])) for part in want[g["owner"]]]
    # listed in another order, the items still land on the same lines (ties within a kind keep the listed order)
    shuffled = json.loads(json.dumps(doc))
    for g in shuffled["actions_by_owner"]:
        g["items"].reverse()

    def lines_of(groups):
        return {o: [(p[0], p[1], sorted(p[2])) for p in parts] for o, parts in groups.items()}
    assert lines_of(page_owner_groups(brief.render(shuffled, plan))) == lines_of(want)


# ------------------------------------------------------------------ I2: What is failing, each entry once

@pytest.fixture(scope="module")
def failing_run(tmp_path_factory):
    """Senders, envelope domains and outside sources at 50, 40, 30, 20, 15, 12, 11, 4 and 3 failing messages, and 14
    more outside sources at 2: two of each list at ten or more beyond the top five, and outside notes past the cap."""
    tmp = tmp_path_factory.mktemp("failing")
    counts = (50, 40, 30, 20, 15, 12, 11, 4, 3)
    log = r11.Log()
    log.add("staff@example.com", "Weekly report #", times=20)
    for i, n in enumerate(counts, 1):
        log.add("s%d@example.com" % i, "Notice #", "fail", n, env="env%d.example.net" % i)
    names = ["example.com"]
    rep = audit.build_report(domains=names, maillog=log.write(tmp / "maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={d: ["cli"] for d in names})

    def stream(ip, n):  # an outside source as the aggregate reports' parser writes it
        return {"source_ip": ip, "count": n, "pass": 0, "fail": n, "header_from": ["example.com"],
                "dispositions": {"none": n}, "likely": "likely_spoof",
                "likely_signals": ["no DKIM signature and no SPF pass on any domain (%d of %d msgs)" % (n, n)]}
    rep["rua"] = {"failing_streams": [stream("198.51.100.%d" % (10 + i), n) for i, n in enumerate(counts, 1)]
                  + [stream("192.0.2.%d" % (50 + k), 2) for k in range(1, 15)], "spf_only_senders": []}
    doc = json.loads(json.dumps(next_steps.build(rep, None)))
    return doc, next_steps.render_md(doc), brief.render(doc)


def page_blocks(page):
    """What is failing's lists on the page: {title: (table row names, [note lines as text])}."""
    out = {}
    sec = section_of(page, "failing")
    for block in sec.split('<div class="group"><h3>')[1:]:
        title = block.split(" <span", 1)[0]
        rows = [text_of(n) for n in re.findall(r'<tr><td class="name">(.*?)</td>', block)]
        notes = [text_of(n) for n in re.findall(r'<p class="note">(.*?)</p>', block)]
        out[title] = (rows, notes, text_of(block))
    return out


def test_what_is_failing_names_each_entry_once_under_the_label_next_steps_md_uses(failing_run):
    """next_steps.headline_split splits each list for both: the top five in the table, the others at ten or more on
    the 'Also at 10 or more each' line, the rest on the notes line - the outside view's capped at NOTES_CAP with how
    many more. The brief kept its own split, so x12 and x11 showed twice (its notes line, and the core's line that
    fell through to the page's other sentences)."""
    doc, md, page = failing_run
    blocks = page_blocks(page)
    lists = (("By envelope domain", "by_envelope", "env%d.example.net"),
             ("By sender address", "by_sender", "s%d@example.com"), ("From the outside", "outside", "198.51.100.%d"))
    for title, key, form in lists:
        text = blocks[title][2]
        for n in [form % (i + (10 if key == "outside" else 0)) for i in range(1, 10)]:
            assert text.count(n) == 1, (title, n)  # every entry once in its list (no name holds another)
    md_lines = [l[2:] for l in md_section(md, "What is failing").splitlines() if l.startswith("- ")]
    for title, key, form in lists:
        rows, notes, text = blocks[title]
        head, more, rest = next_steps.headline_split(doc["failing"][key])
        assert [e["count"] for e in head] == [50, 40, 30, 20, 15] and [e["count"] for e in more] == [12, 11]
        assert rows == [e["name"] for e in head]
        # the two lines under the table are next_steps.md's own, word for word
        assert notes == [l for l in md_lines if l.startswith(next_steps.MORE_LINE) and more[0]["name"] in l] + [
            l for l in md_lines if l.startswith(("Notes, not headlines", next_steps.OUTSIDE_NOTES_LINE))
            and rest[0]["name"] in l]
        assert notes[0].startswith(next_steps.MORE_LINE) and notes[1].startswith(
            next_steps.NOTES_LINE if key != "outside" else next_steps.OUTSIDE_NOTES_LINE)
    outside_notes = blocks["From the outside"][1][1]
    assert outside_notes.endswith("(+4 more in report.json)") and outside_notes.count(" x2 ") == 10
    # the page's other sentences hold none of these lines again
    assert not any(l.startswith((next_steps.MORE_LINE, "Notes, not headlines")) for l in brief.failing_rest(
        doc["failing"]))


def test_the_outside_table_names_the_from_domains_as_next_steps_md_does():
    out = [{"name": "198.51.100.7", "count": 110, "likely": "likely_misconfigured", "dispositions": {"none": 110},
            "header_from": ["zeta.example.org", "example.org", "a.shop.example.org"],
            "as": "example.org, a.shop.example.org and 1 more"}]
    sec = section_of(brief.render({"failing": {"outside": out, "lines": []}}), "failing")
    cells = re.findall(r"<td[^>]*>(.*?)</td>", sec)
    assert text_of(cells[2]) == "example.org, a.shop.example.org and 1 more"
    del out[0]["as"]  # an older document: the first two it lists
    cells = re.findall(r"<td[^>]*>(.*?)</td>", section_of(brief.render({"failing": {"outside": out}}), "failing"))
    assert text_of(cells[2]) == "zeta.example.org, example.org"


# ------------------------------------------------------------------ B1 to B3: names that wrap, tables that stack

LONG_LABEL = ("customer-notifications-and-transactional-receipts-platform-eu1" + "x" * 63)[:63]  # a legal DNS label


def css_block(start):
    """The rules of one @media block of the page's style, by its opening line."""
    return brief.CSS.split(start + " {\n", 1)[1].split("\n}\n", 1)[0]


def test_a_long_label_may_wrap_and_a_short_one_never_breaks():
    """A 63-character label pushed a 400px page to 526px from the Decide first list (white-space: nowrap on every
    label, outside tables too). Now a label of LABEL_KEEP characters or fewer that holds a hyphen stays whole (w), a
    longer one may break where it must (long), and every name breaks after its dots; checked in Edge with
    overflow.py at 360 and 400 px on the long-label estate and every other: nothing passes the edge."""
    name = LONG_LABEL + ".example.com"
    for markup in (brief.name_html(name), brief.plain_name(name)):
        assert re.search(r'<(b|span) class="(?:apex )?long">%s\.</\1>' % LONG_LABEL, markup), markup
        assert text_of(markup) == name and markup.count("<wbr>") == 2
    assert brief.plain_name("mailer.billing-vendor.invalid") == (
        '<span class="dn"><span>mailer.</span><wbr><span class="w">billing-vendor.</span><wbr><span>invalid</span>'
        '</span>')
    assert brief.plain_name("198.51.100.7") == '<span class="dn"><span class="w">198.51.100.7</span></span>'
    assert 'class="long"' in brief.plain_name("2001:db8:0:0:0:0:0:7334")  # an IPv6 one longer than a label
    rules = {sel: css for sel, css in re.findall(r"(?m)^(\.dn > [^{]+?) \{([^}]*)\}", brief.CSS)}
    assert "white-space" not in rules[".dn > *"] and "overflow-wrap: break-word" in rules[".dn > *"]
    assert "white-space: nowrap" in rules[".dn > .w"] and "overflow-wrap: anywhere" in rules[".dn > .long"]
    # the hold that overflowed: its name is the long label's, and it can wrap now
    page = brief.render({"org_domain": "example.com"}, {"changes": [], "holds": [
        {"domain": name, "reason": "decide whether this platform keeps its own record"}]})
    decide = section_of(page, "dns")
    assert '<b class="long">%s.</b>' % LONG_LABEL in decide


def test_every_table_reads_as_blocks_under_one_breakpoint_so_no_column_is_out_of_sight():
    """At 641 to 768px the per-domain table (5 columns, a 26ch name) was wider than its wrapper and one column
    scrolled out of sight with nothing to show it; the failing tables and the plan at a glance did the same on a
    phone. Every table now has a fixed class whose rows read as labelled blocks on a screen under 48rem, and above
    it the tables fit: checked in Edge every 20px from 360 to 1280, and every pixel from 762 to 799, on the shipped,
    stress, awkward, long-label, aggregate-report, sample and widest-cell pages - no element past the edge, no table
    wrapper with a scrollWidth past its clientWidth; on paper (A4 and Letter widths) the tables fit as tables."""
    doc = {"org_domain": "example.com", "per_domain": [r12_row()],
           "failing": {"by_envelope": [{"name": "example.com", "count": 12, "senders": ["a@example.com"]}],
                       "by_sender": [{"name": "a@example.com", "count": 12, "envelope": "example.com"}],
                       "outside": [{"name": "203.0.113.5", "count": 40, "as": "example.com"}], "lines": []}}
    plan = {"changes": [{"id": "P-01", "priority": 1, "zone_host": "Route53", "zone": "example.com",
                         "domain": "example.com", "hostname": "_dmarc.dev.support.example.com", "kind": "new"}]}
    page = brief.render(doc, plan)
    classes = re.findall(r'<table(?: class="([^"]*)")?>', page)
    assert sorted(classes) == sorted(brief.TABLE_CLASSES) and "" not in classes
    narrow = css_block("@media screen and (max-width: 48rem)")
    for cls in brief.TABLE_CLASSES:
        sel = "table." + cls.split()[0]
        assert re.search(r"(?m)^  %s(?:, %s \w+)+ \{ display: block; \}" % (sel, sel), narrow), sel
        assert "%s thead { display: none; }" % sel in narrow, sel
    for name, heads in brief.LIST_HEADS:  # each list's columns named as labels, short enough for the label column
        for i, head in enumerate(heads, 1):
            assert 'table.%s td:nth-child(%d)::before { content: "%s"; }' % (name, i, head) in narrow
            assert len(head) <= 9
    assert "@media (max-width: 40rem) {" in brief.CSS and "table." not in css_block("@media (max-width: 40rem)")


def r12_row():
    return {"domains": ["example.com"], "org": "example.com", "policy_today": "p=none", "gate": "no_go",
            "gate_text": "not yet", "next_step": "move to p=quarantine at pct=25", "plan_ids": ["P-01"],
            "mailflow_text": "not measured"}


def test_the_plan_at_a_glance_puts_each_host_name_on_its_own_line_on_a_phone():
    """At 360 to 400px the index wrapped a host name one label per line (five lines for
    _dmarc.dev.support.example.com) and scrolled inside its wrapper (354 > 328). Under the breakpoint each row is
    now a grid: id, priority, kind and checks on one line, the host name on its own full-width line below (shot in
    Edge at 360px: _dmarc.dev.support.example.com on one line, no inner scroll)."""
    narrow = css_block("@media screen and (max-width: 48rem)")
    assert "table.index tr { display: grid;" in narrow
    assert "table.index td.name { grid-column: 1 / -1; grid-row: 2; }" in narrow
    assert 'table.index td:nth-child(2)::before { content: "priority "; ' in narrow
    assert 'table.index td:nth-child(5)::before { content: "checks "; ' in narrow
    plan = {"changes": [{"id": "P-01", "priority": 1, "zone_host": "Route53", "zone": "example.com",
                         "domain": "dev.support.example.com", "hostname": "_dmarc.dev.support.example.com",
                         "kind": "new", "prerequisites": ["a lookup shows no record"]}]}
    index = re.search(r'<table class="index">.*?</table>', brief.render({}, plan)).group(0)
    assert re.findall(r"<td( class=\"\w+\")?>", index) == ["", ' class="num"', ' class="name"', "", ' class="num"']


def test_a_sentence_in_a_per_domain_cell_breaks_a_name_between_its_labels():
    """The per-domain table's text names records (_dmarc.shop.example.org) whose width set the column's: each name
    in it now breaks only after its dots, so the table fits above the breakpoint whatever the names; the words and
    numbers are unchanged, and an IP address or a number with a dot stays whole."""
    said = "inherited from _dmarc.shop.example.org; 77.4% of 203.0.113.5's mail; see report.json"
    out = brief.prose(said)
    assert "_dmarc.<wbr>shop.<wbr>example.<wbr>org;" in out and "report.<wbr>json" in out
    assert "77.4%" in out and "203.0.113.5" in out and text_of(out) == said
    assert brief.prose("**P-04** `_dmarc.example.com`") == "<strong>P-04</strong> <code>_dmarc.<wbr>example.<wbr>com</code>"


# ------------------------------------------------------------------ B4, B5: the stand's meta, an empty Per domain

def test_where_we_stand_says_deduplicated_of_the_mail_log_counts_only():
    """The meta read 'aggregate reports 2026-09-18 to 2026-10-08, deduplicated' while the same page says the
    aggregate reports' counts cannot be deduplicated: the window keeps its source, and 'deduplicated' goes with the
    mail-log counts - when the page shows any. next_steps.md's heading is unchanged."""
    st = {"window": {"text": "2026-09-18 to 2026-10-08", "source": "aggregate reports"}, "genuine_failures": 43,
          "raw_failing_rows": 45, "delivered_despite_fail": 3, "trend": None, "lines": ["**Genuine failures: 43**"]}
    meta = re.search(r'<p class="meta">(.*?)</p>', section_of(brief.render({"stand": st}), "stand")).group(1)
    assert text_of(meta) == "aggregate reports 2026-09-18 to 2026-10-08; mail-log counts deduplicated"
    st.update(genuine_failures=None, raw_failing_rows=None, delivered_despite_fail=None)  # no mail log was read
    meta = re.search(r'<p class="meta">(.*?)</p>', section_of(brief.render({"stand": st}), "stand")).group(1)
    assert text_of(meta) == "aggregate reports 2026-09-18 to 2026-10-08"
    md = next_steps.render_md({"date": "2026-10-13", "sources": {"audience_line": ""}, "one_liner": "x",
                               "stand": {"window": st["window"], "lines": []}, "failing": {"lines": []},
                               "per_domain": [], "actions_by_owner": [], "ask": "", "open_questions": [],
                               "glossary": {}})
    assert "## Where we stand (2026-09-18 to 2026-10-08, deduplicated)" in md


def test_an_empty_per_domain_section_says_so_above_the_audits_notes():
    """next_steps.md says 'No domain was audited in this run.' and then the audit's notes; the brief showed the notes
    alone."""
    notes = [{"text": "unaudited subdomains send as example.com: news.example.com", "holds": ""}]
    doc = {"date": "2026-10-13", "org_domain": "example.com", "per_domain": [], "audit_notes": notes}
    sec = section_of(brief.render(doc), "domains")
    assert sec.index('<p class="empty">%s</p>' % brief.NO_DOMAINS) < sec.index("From the audit on")
    assert "unaudited subdomains send as example.com: news.example.com" in text_of(sec)
    md = next_steps.render_md(dict(doc, sources={"audience_line": ""}, one_liner="x", stand={"lines": []},
                                   failing={"lines": []}, actions_by_owner=[], ask="", open_questions=[],
                                   glossary={}))
    per = md_section(md, "Per domain")
    assert per.index(brief.NO_DOMAINS) < per.index("From the audit on example.com")
    # a document with rows keeps its table and no such sentence
    rows = dict(doc, per_domain=[r12_row()])
    assert brief.NO_DOMAINS not in section_of(brief.render(rows), "domains")


# ------------------------------------------------------------------ B6: real mail text shows as itself, isolated

KEPT = (0x200D, 0x200C, 0x200E, 0x200F, 0x00AD, 0x061C, 0x2061)  # joiners, direction marks, a soft hyphen...
MARKED = tuple(range(0x202A, 0x202F)) + tuple(range(0x2066, 0x206A)) + (0x200B, 0x2060, 0xFEFF, 0x07, 0x85)


def test_only_the_characters_that_reorder_or_hide_text_show_as_a_marker():
    """Every format character used to show as [U+XXXX]: the joiner inside an emoji, the direction marks of a
    right-to-left subject, a soft hyphen in a display name. Only the embeddings, overrides and isolates, the
    zero-width space, the word joiner, the BOM - and the controls - are marked now; the rest render as themselves."""
    for code in KEPT:
        assert brief.clean("a" + chr(code) + "b") == "a" + chr(code) + "b", hex(code)
        assert not brief.marked(chr(code))
    for code in MARKED:
        assert brief.clean("a" + chr(code) + "b") == "a[U+%04X]b" % code, hex(code)
        assert brief.marked(chr(code))
    family = chr(0x1F468) + chr(0x200D) + chr(0x1F469) + chr(0x200D) + chr(0x1F467)
    hebrew = chr(0x200F) + chr(0x05E9) + chr(0x05DC) + chr(0x05D5) + chr(0x05DD) + " 61"
    page = brief.render({"failing": {"by_sender": [{"name": "a@example.com", "count": 12,
                                                    "subjects": [family + " day", hebrew]}], "lines": []}})
    assert family in page and hebrew in page and "[U+200D]" not in page and "[U+200F]" not in page


VOID = {"wbr", "meta", "br", "img", "input", "link", "hr"}
BLOCK = {"html", "body", "main", "header", "footer", "nav", "section", "article", "div", "h1", "h2", "h3", "h4", "p",
         "ul", "ol", "li", "dl", "dt", "dd", "table", "thead", "tbody", "tr", "th", "td", "pre"}
ATOMIC = {"pill": "inline-block", "tag": "inline-block", "refs": "inline-flex"}  # laid out apart from their line


class Tree(HTMLParser):
    """A page as a tree of elements (tag, classes, children) and text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = self.cur = {"tag": "", "cls": set(), "kids": [], "up": None}

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "cls": set((dict(attrs).get("class") or "").split()), "kids": [], "up": self.cur}
        self.cur["kids"].append(node)
        if tag not in VOID:
            self.cur = node

    def handle_endtag(self, tag):
        node = self.cur
        while node["up"] is not None and node["tag"] != tag:
            node = node["up"]
        if node["up"] is not None:
            self.cur = node["up"]

    def handle_data(self, data):
        self.cur["kids"].append(data)


def isolates(page):
    """The text of every bidi isolate on the page's body, a nested isolate standing as one character (\\x00): a
    <bdi>, a block, an inline block, or an element whose class the style isolates (unicode-bidi: isolate)."""
    css_iso = set()
    for sels, body in re.findall(r"(?m)^([.\w][^{}\n]*?) \{([^}]*)\}", brief.CSS):
        if "unicode-bidi: isolate" in body:
            for sel in sels.split(","):
                css_iso |= set(re.findall(r"\.([\w-]+)", sel.split()[-1]))
    iso_classes = css_iso | set(ATOMIC)
    tree = Tree()
    tree.feed(page.split("<body>", 1)[1] if "<body>" in page else page)
    found = []

    def flat(node):
        parts = []
        for k in node["kids"]:
            if isinstance(k, str):
                parts.append(k)
            elif k["tag"] == "bdi" or k["tag"] in BLOCK or k["cls"] & iso_classes:
                found.append(flat(k))
                parts.append("\x00")
            else:
                parts.append(flat(k))
        return "".join(parts)
    found.append(flat(tree.root))
    return css_iso, found


def poisoned(value, keys_too=False):
    """Every string of a document with a right-to-left mark at its end (and the keys of a map the page shows)."""
    if isinstance(value, str):
        return value + RLM
    if isinstance(value, list):
        return [poisoned(v) for v in value]
    if isinstance(value, dict):
        return {(k + RLM if keys_too else k): poisoned(v, k in ("glossary", "dispositions")) for k, v in value.items()}
    return value


def test_every_data_string_sits_in_its_own_bidi_isolate(estates):
    """A mark at the end of a string from the data (U+200F renders as itself now) reorders whatever follows it in
    its paragraph: the count after a name, the tag after a step. Every string of a whole document and plan carries
    one here, and on the page each is the last thing in its isolate - a <bdi>, its own block, a pill or tag, or an
    element the style isolates - so nothing of the page's own follows it there."""
    doc, plan, _, _ = estates["shipped"]
    doc = json.loads(json.dumps(doc))
    doc["stand"]["trend"] = {"label": "2026-10-06", "previous_genuine_failures": None, "previous_pass_rate": None,
                             "not_comparable": ["the two runs read different mail logs"]}
    doc["sources"].update(owners_file="owners.csv", previous_report="2026-10-02T06:00:00Z", report_tool="audit.py")
    doc["audit_notes"] = [{"text": "unaudited subdomains send as example.com", "holds": "the sp= step"}]
    plan = dict(plan, rua_is_placeholder=True, rua="mailto:dmarc@example.invalid")
    page = brief.render(poisoned(doc), poisoned(plan))
    css_iso, runs = isolates(page)
    assert {"dn", "hook", "subject", "channel", "mono", "k", "d"} <= css_iso
    for cls, display in ATOMIC.items():
        assert re.search(r"(?m)^\.%s \{[^}]*display: %s;" % (cls, display), brief.CSS), cls
    assert page.count(RLM) > 200 and "[U+200F]" not in page
    for run in runs:
        bad = re.search(RLM + r"\s*[^\s]", run)
        assert not bad, repr(run[max(0, bad.start() - 60):bad.end() + 40])


def typo_like_run(tmp_path, subject):
    """A run folder whose one failing sender's subject is the one given: next_steps.md, .json and brief.html."""
    line = '- **noreply@example.com - 12 messages** looks like spoofing (envelope example.com; subjects like "%s")' % (
        subject)
    doc = {"date": "2026-10-13", "org_domain": "example.com", "one_liner": "example.com is at p=none.",
           "sources": {"audience": "For the people who own our email domains",
                       "audience_line": "For the people who own our email domains. Sources: a test run."},
           "stand": {"lines": ["**Genuine failures: 12**"]},
           "failing": {"lines": ["By sender address (what the reader sees in From):", line],
                       "by_sender": [{"name": "noreply@example.com", "count": 12, "likely": "likely_spoof",
                                      "subjects": [subject], "envelope": "example.com"}]},
           "per_domain": [], "actions_by_owner": [], "ask": "Nothing to approve.", "open_questions": [],
           "glossary": {}}
    run = tmp_path / "run"
    run.mkdir()
    next_steps.write(doc, run)
    brief.write_run(run)
    return run


def check(path, run):
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_doc.py"), str(path), "--run", str(run)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert "Traceback" not in p.stderr, p.stderr
    return p.returncode, p.stdout.splitlines()


def test_check_doc_names_the_characters_brief_html_marks_and_no_other(tmp_path):
    """The checker names exactly the characters brief.html shows as a marker (brief.marked), wherever they are; a
    joiner, a direction mark or a soft hyphen in a quoted subject or in the copy's own words is text."""
    family = chr(0x1F468) + chr(0x200D) + chr(0x1F469)
    subject = "Family day " + family + " " + chr(0x200F) + "61"
    run = typo_like_run(tmp_path, subject)
    for name in ("next_steps.md", "brief.html"):
        assert check(run / name, run)[0] == 0, name  # the run's own files pass, the subject's marks and all
    copy = tmp_path / "owner.md"
    kept = "".join(chr(c) for c in KEPT)
    copy.write_text('Your sender noreply@example.com, subject "%s", fails; soft%shyphen %s\n' % (subject, chr(0xAD), kept),
                    encoding="utf-8")
    assert check(copy, run) == (0, ["clean: every number, id and policy value in owner.md is in the run's files"])
    for code in MARKED:  # quoted or not, each one is named, as brief.html would show it
        copy.write_text('Quoted "%s%s" and "%s"\n' % (subject, chr(code), chr(code)), encoding="utf-8")
        code_, lines = check(copy, run)
        what = "a control character" if code < 0xA0 else "an invisible character"
        assert code_ == 1 and lines == ["line 1: U+%04X: %s: the voice rules forbid it, write it as brief.html shows "
                                        "it, [U+%04X], or delete it" % (code, what, code)], (hex(code), lines)


# ------------------------------------------------------------------ B7: no lost line continuation

def test_no_line_of_the_tools_holds_a_run_of_spaces_between_two_tokens():
    """scripts/check_doc.py held a lost line continuation - 13 spaces inside one conditional expression - which
    read as one line but looked like two; no line of src/ or scripts/ holds such a gap now."""
    for path in sorted((ROOT / "src").glob("*.py")) + sorted((ROOT / "scripts").glob("*.py")):
        toks = list(tokenize.generate_tokens(io.StringIO(path.read_text(encoding="utf-8")).readline))
        for a, b in zip(toks, toks[1:]):
            if a.end[0] == b.start[0] and b.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE) \
                    and a.type not in (tokenize.INDENT, tokenize.DEDENT):
                assert b.start[1] - a.end[1] < 4, "%s line %d" % (path.name, a.end[0])


# ------------------------------------------------------------------ C1: a source's count goes with the source

def test_the_aggregate_report_one_liner_puts_each_count_with_its_source():
    """'198.51.100.7 as example.org, a.shop.example.org and 1 more x110' read as if x110 counted the unnamed
    domain; the count now sits with the source it counts."""
    import test_r12_fix_core as fc
    rua = {"failing_streams": [fc.stream("198.51.100.7", 110, ["zeta.example.org", "example.org", "a.shop.example.org"]),
                               fc.stream("198.51.100.9", 85, ["example.net", "example.org"])],
           "by_source_ip": [fc.by_source("198.51.100.7", {"zeta.example.org": 30, "example.org": 40,
                                                          "a.shop.example.org": 40}),
                            fc.by_source("198.51.100.9", {"example.net": 60, "example.org": 25})],
           "spf_only_senders": []}
    report = {"generated_utc": "2026-10-09T06:00:00Z", "rua": rua, "inputs": {"domains": ["example.org"]},
              "findings": [{"id": "OUTSIDE-001", "severity": "major", "source": "rua"}],
              "gate": {"headline_domain": "example.org", "domains": {"example.org": {"verdict": "no_go"}}}}
    doc = next_steps.build(report)
    assert ("2 of our own sending sources still fail (from the aggregate reports) (198.51.100.7 x110 as "
            "example.org, a.shop.example.org and 1 more, 198.51.100.9 x85 as example.net, example.org)") in doc["one_liner"]
    assert "more x110" not in doc["one_liner"] and "example.org x85" not in doc["one_liner"]
    # next_steps.json keeps the source's name and count as they were
    assert doc["failing"]["streams"]["own"][0] == {"name": "198.51.100.7 as example.org, a.shop.example.org and 1 more",
                                                   "count": 110}
    # a mail-log sender is named as before
    assert next_steps._named([{"name": "a@example.com", "count": 5}]) == "a@example.com x5"


# ------------------------------------------------------------------ C3: tied senders, one rank in every file

TIED = ("hr@example.org", "x@news.example.org", "app@zeta.example.org")
BUSIER = ("billing@example.co.uk", "ceo@brand.example", "info@e.example.com")  # tied on failures, more mail


def test_tied_senders_are_named_in_one_order_in_every_file(tmp_path):
    """Six senders with five failures each; three also send passing mail. next_steps.md and the census ranked the
    busier three first (sender_rank's messages key); MAILFLOW-001's evidence - report.md, todo.md, verify.md -
    recounted the failures without the messages and named the headline's three first. Every file now names the
    same senders in the same order."""
    log = r11.Log()
    log.add("staff@example.org", "Weekly report #", times=20)
    for s in TIED:
        log.add(s, "Notice #", "fail", 5)
    for s in BUSIER:
        log.add(s, "Notice #", "fail", 5)
        log.add(s, "Statement #", "pass", 30)
    names = ["example.org", "news.example.org", "zeta.example.org", "example.co.uk", "brand.example", "e.example.com"]
    rep = audit.build_report(domains=names, maillog=log.write(tmp_path / "maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={d: ["cli"] for d in names}, headline="example.org")
    want = ["ceo@brand.example", "billing@example.co.uk", "info@e.example.com", "hr@example.org",
            "x@news.example.org", "app@zeta.example.org"]
    assert [s["name"] for s in next_steps.maillog_view(rep, "example.org")["by_sender"]] == want
    md = next_steps.render_md(next_steps.build(rep, None))
    notes = next(l for l in md.splitlines() if l.startswith("- Notes, not headlines") and "@" in l)
    assert [n.split(" x")[0] for n in notes.split(": ", 1)[1].split(", ")] == want
    report_md = audit.render_md(rep)
    census = md_section(report_md, "Failing senders (census)").splitlines()
    assert [l.split()[1] for l in census if l.startswith("  - ") and "(envelope" in l] == want[:audit.CENSUS_TOP]
    evidence = {f["id"]: f["evidence"] for f in rep["findings"]}
    top = "; ".join("%s x5" % s for s in want[:5])
    assert evidence["MAILFLOW-001"].endswith("; top senders: " + top) and top in report_md
    assert evidence["MAILFLOW-004"] == "; ".join("%s likely_misconfigured_sender x5" % s for s in want[:5])
    todo = collect.render_todo(rep, {"changes": [], "holds": []})
    assert "top senders: %s" % top in todo
    mpath, _ = verify.write(rep, {"changes": [], "holds": []}, tmp_path / "verify")
    vmd = mpath.read_text(encoding="utf-8")
    assert "top senders: " + top in vmd and evidence["MAILFLOW-004"] in vmd
    # the key, plainly: failures, then the messages behind them, then the one order with the headline first
    assert audit.top_senders(Counter({"a@example.org": 5, "b@brand.example": 5}), 2, "example.org",
                             {"a@example.org": 5, "b@brand.example": 35}) == [("b@brand.example", 5), ("a@example.org", 5)]


# ------------------------------------------------------------------ C4: the run's caveats, in the one order

CUT_NOTES = ["mail log: brand.example row budget reached at 41h..33h ago - older rows skipped; the rows cover only the "
             "last 41h (raise --max-rows to keep more)",
             "mail log: example.org has more than 100,000 rows within one hour (6h..5h ago) - that hour is truncated"]


def test_the_runs_caveats_and_its_cut_clause_name_the_headlines_organization_first():
    """collect.py wrote report.md's Caveats and maillog.truncation in the order it pulled the organizations; both
    follow the one order now, the headline's first, as next_steps.md and todo.md already did."""
    rep = {"gate": {"headline_domain": "example.org", "domains": {"example.org": {}, "brand.example": {}}},
           "inputs": {"domains": ["example.org", "brand.example"]}, "maillog": {"counters": {}}}
    caveats = collect.run_caveats(rep, CUT_NOTES + ["mail log: 30 rows for other.example (last 30 days)"])
    assert [c.split()[2] for c in caveats] == ["example.org", "brand.example"] and rep["caveats"] == caveats
    assert rep["maillog"]["truncation"] == ("an hour of example.org (6h..5h ago) is truncated at the API cap; row "
                                            "budget kept only the newest 41h for brand.example")
    assert collect.run_caveats(rep, ["mail log: 30 rows for other.example (last 30 days)"]) == []


def test_collect_writes_report_md_caveats_and_the_cut_clause_in_the_one_order(monkeypatch, tmp_path):
    """The real collect.main against an in-memory tenant (every network seam stubbed, sockets refused): the row
    budget cuts both organizations; it pulls corp.example first, but shop.example - typed first - leads."""
    attempts = []

    def refuse(*a, **k):
        attempts.append(a)
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.delenv("RUA_MAILBOX", raising=False)
    now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
    tenant = comp.Tenant(comp.legs(now, {"corp.example": (10, 1, 0, 0, 720), "shop.example": (10, 1, 7, 0, 720)}))
    monkeypatch.setattr(collect.graph_client, "hunting", tenant.hunting)
    monkeypatch.setattr(collect.graph_client, "creds", lambda env_file=None: ("tenant", "client", "secret"))
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([], None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
    monkeypatch.setattr(audit, "run_dns", lambda domains, resolver, selectors=(): None)
    monkeypatch.setattr(collect, "ROW_CAP", 300)
    monkeypatch.setattr(collect, "SLICE_TARGET", 270)
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["collect.py", "shop.example", "corp.example", "--no-config", "--no-owners",
                                      "--no-notify", "--out", str(out), "--max-rows", "1500"])
    with pytest.raises(SystemExit):
        collect.main()
    latest = out / "latest"
    report = json.loads((latest / "report.json").read_text(encoding="utf-8"))
    assert report["gate"]["headline_domain"] == "shop.example" and set(report["maillog"]["cuts"]) == {
        "corp.example", "shop.example"}
    assert [c.split()[2] for c in report["caveats"]] == ["shop.example", "corp.example"]
    assert re.fullmatch(r"row budget kept only the newest \d+h for shop\.example; row budget kept only the newest "
                        r"\d+h for corp\.example", report["maillog"]["truncation"])
    caveats = md_section((latest / "report.md").read_text(encoding="utf-8"), "Caveats").strip().splitlines()
    assert [l.split()[3] for l in caveats if l.startswith("- ")] == ["shop.example", "corp.example"]
    todo = md_section((latest / "todo.md").read_text(encoding="utf-8"), "Caveats")
    assert todo.index("shop.example row budget") < todo.index("corp.example row budget")
    assert attempts == []
