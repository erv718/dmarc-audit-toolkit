"""Round 12, integration round 2: what the parity and layout reviews of the
merged integration found. A sender is one address in every file, whatever
envelopes it came through; the brief keeps the plan's own order whatever
organization the document names; an outside source is counted by what it
sends as each From domain, its signals cut between them; a quoted subject is
cut at a word; the formally excepted line is an item of the list it
qualifies. On the page: a record card's short fields take the width their
value needs; ids, dates and names in running text never split, and a short
name in a cell is one piece; a long zone sits beside its label and with it
on paper; every format character mail text does not need shows as a marker.
(Tied senders ranked by their messages in every list: test_r12_int's
test_tied_senders_are_named_in_one_order_in_every_file.) Synthetic data,
offline: nothing here touches the network."""

import html
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

import audit
import brief
import next_steps
import plan as plan_mod
import test_r10_exceptions as r10  # a mail log with envelope domains of its own, and formal exceptions
import test_r11_plan as r11  # the synthetic tenant pieces: DNS documents, a mail-log export, aggregate reports
import test_r12_order as r12  # the round's three-organization estate

ROOT = Path(__file__).resolve().parent.parent


def section_of(page, sid):
    start = page.index('id="%s"' % sid)
    return page[start:page.index("</section>", start)]


def text_of(fragment):
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def md_section(md, title):
    return md.split("\n## %s" % title, 1)[1].split("\n## ", 1)[0]


def as_json(doc):
    return json.loads(json.dumps(doc))  # as next_steps.json holds it


# ------------------------------------------------------------------ N0: one sender, one address

def envelopes_report(tmp_path):
    """billing@ fails 6 + 6 through two vendors' envelopes; alerts@ 11 and news@ 5 through example.com."""
    log = r11.Log()
    log.add("staff@example.com", "Weekly report #", times=30)
    log.add("billing@example.com", "Invoice #", "fail", 6, env="mailer.vendor-one.invalid")
    log.add("billing@example.com", "Invoice #", "fail", 6, env="relay.vendor-two.invalid")
    log.add("alerts@example.com", "Alert #", "fail", 11)
    log.add("news@example.com", "News #", "fail", 5)
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={"example.com": ["cli"]})
    rep["generated_utc"] = "2026-10-09T06:00:00Z"
    return rep


def sender_rows(page):
    """The By sender address table: [(sender, messages, envelope cell)] as the page shows them."""
    sec = section_of(page, "failing")
    table = re.search(r'<table class="list snd">.*?</table>', sec, re.S).group(0)
    return [(text_of(a), text_of(b), text_of(c)) for a, b, c in re.findall(
        r'<tr><td class="name">(.*?)</td><td class="num">(.*?)</td><td>.*?</td><td>.*?</td>'
        r'<td class="name">(.*?)</td></tr>', table)]


def test_an_address_through_two_envelopes_is_one_sender_with_all_its_failures(tmp_path):
    """The census counts streams (address, From domain, envelope); next_steps.md and the brief listed each as a
    sender, so billing@ read 'billing@example.com x6, billing@example.com x6' under 'under 10 each' while
    MAILFLOW-001, todo.md and verify.md named 'billing@example.com x12' first. One address is one sender now, its
    envelopes named; report.md's census still lists the streams."""
    rep = envelopes_report(tmp_path)
    doc = as_json(next_steps.build(rep, None, date="2026-10-13"))
    assert [(e["name"], e["count"]) for e in doc["failing"]["by_sender"]] == [
        ("billing@example.com", 12), ("alerts@example.com", 11), ("news@example.com", 5)]
    evidence = next(f["evidence"] for f in rep["findings"] if f["id"] == "MAILFLOW-001")
    assert evidence.endswith("top senders: billing@example.com x12; alerts@example.com x11; news@example.com x5")
    md = next_steps.render_md(doc)
    failing = md_section(md, "What is failing")
    assert ('- **billing@example.com - 12 messages** looks like spoofing (envelopes mailer.vendor-one.invalid x6 and '
            'relay.vendor-two.invalid x6; subjects like "Invoice 31")') in failing
    assert "billing@example.com x6" not in md and "billing@example.com - 6" not in md
    notes = [l for l in failing.splitlines() if l.startswith("- " + next_steps.NOTES_LINE) and "@" in l]
    assert notes == ["- " + next_steps.NOTES_LINE + "news@example.com x5 (looks like our own system misconfigured)"]
    # the brief: one row for the address, its Envelope cell in next_steps.md's words
    page = brief.render(doc)
    assert sender_rows(page) == [
        ("billing@example.com", "12", "mailer.vendor-one.invalid x6 and relay.vendor-two.invalid x6"),
        ("alerts@example.com", "11", "example.com")]
    assert text_of(section_of(page, "failing")).count("billing@example.com") == 1
    # the owners' spoofing item counts the address once, with all its messages
    hooks = [i["hook"] for g in doc["actions_by_owner"] for i in g["items"]]
    assert "12 messages from 1 address that look like spoofing" in hooks
    # report.md's census stays per stream: each envelope its own line
    census = md_section(audit.render_md(rep), "Failing senders (census)")
    assert len(re.findall(r"(?m)^  - billing@example\.com \(envelope [^)]+\): 6 failing", census)) == 2


def test_an_address_spoofed_through_five_envelopes_is_one_headline_naming_the_busiest_two(tmp_path):
    """ceo@ spoofed through five envelope domains, four failures each, read as five notes of four; it is one
    headline of 20 now, as MAILFLOW-001 counts it, and the one-liner's '20 from 1 address' agrees."""
    log = r11.Log().add("staff@example.com", "Weekly #", times=20)
    for k in range(1, 6):
        log.add("ceo@example.com", "Urgent wire transfer #", "fail", 4, env="bulk%d.spoofer.invalid" % k)
    log.add("alerts@example.com", "Alert #", "fail", 11)
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={"example.com": ["cli"]})
    doc = as_json(next_steps.build(rep, None, date="2026-10-13"))
    first = doc["failing"]["by_sender"][0]
    assert (first["name"], first["count"], first["likely"]) == ("ceo@example.com", 20, "likely_spoof")
    assert next_steps.envelope_text(first) == ("envelopes bulk1.spoofer.invalid x4, bulk2.spoofer.invalid x4 and 3 "
                                               "more")
    md = next_steps.render_md(doc)
    assert "- **ceo@example.com - 20 messages** looks like spoofing (envelopes bulk1.spoofer.invalid x4, " in md
    assert "ceo@example.com x4" not in md and "20 from 1 address that look like spoofing" in doc["one_liner"]
    rows = sender_rows(brief.render(doc))
    assert rows[0] == ("ceo@example.com", "20", "bulk1.spoofer.invalid x4, bulk2.spoofer.invalid x4 and 3 more")


def test_an_address_an_exception_covers_through_two_envelopes_is_named_once(tmp_path):
    """The excepted line listed one entry per stream as well: 'billing@example.com x3, billing@example.com x2'."""
    log = (r10.Log().add("billing@example.com", "vendor-a.invalid", "Invoice #", 3)
           .add("billing@example.com", "vendor-b.invalid", "Invoice #", 2)
           .add("noreply@example.com", "example.com", "Receipt #", 12))
    doc, md = r10.doc_md(r10.report(tmp_path, log, exceptions=[r10.exc("billing@example.com")]))
    assert "- Formally excepted in audit.toml and not counted above: 5 messages (billing@example.com x5)." in md
    assert "; 5 formally excepted in audit.toml." in doc["one_liner"]  # the numbers themselves never change
    # next_steps.json keeps each stream an exception covered, with its envelope (test_r10_exceptions C25)
    assert sorted((e["envelope"], e["count"]) for e in doc["failing"]["excepted"]) == [("vendor-a.invalid", 3),
                                                                                       ("vendor-b.invalid", 2)]


def test_streams_merge_into_an_address_with_their_counts_their_labels_and_the_busiest_envelope():
    spoof = {"name": "a@example.com", "count": 3, "likely": "likely_spoof", "envelope": "x.invalid", "messages": 3,
             "likely_counts": {"likely_spoof": 3}, "excepted": 1, "domain": "example.com",
             "subjects": ["Urgent 1"]}
    own = {"name": "a@example.com", "count": 2, "likely": "likely_misconfigured_sender", "envelope": "example.com",
           "messages": 40, "likely_counts": {"likely_misconfigured_sender": 2}, "excepted": 0, "domain": "example.com",
           "subjects": ["Statement 7"]}
    merged = next_steps._per_address([own, spoof], {"a@example.com": 60})
    assert len(merged) == 1
    m = merged[0]
    assert (m["count"], m["likely"], m["excepted"], m["messages"]) == (5, "likely_spoof", 1, 60)
    assert m["likely_counts"] == {"likely_misconfigured_sender": 2, "likely_spoof": 3}
    assert (m["envelope"], m["subjects"]) == ("x.invalid", ["Urgent 1"])  # the busiest stream's
    assert m["envelopes"] == [{"name": "x.invalid", "count": 3}, {"name": "example.com", "count": 2}]
    assert next_steps._split(m) == {next_steps.SPOOF: 3, next_steps.OWN: 2}  # each part under its own label
    # no label holds more than half: mixed; one stream: the entry as it was
    even = next_steps._per_address([own, dict(spoof, count=2, likely_counts={"likely_spoof": 2})])[0]
    assert even["likely"] == "mixed" and next_steps.envelope_text(even) == (
        "envelopes example.com x2 and x.invalid x2")
    assert next_steps._per_address([own]) == [own]


# ------------------------------------------------------------------ N2: the plan's own order, whatever the headline

def ids_on(page):
    sec = section_of(page, "dns")
    return (re.findall(r'<tr><td><a href="#rec-\d+">(P-\d+)</a>', sec),
            re.findall(r'<span class="tag rid">(P-\d+)</span>', sec))


def test_the_brief_keeps_the_plans_order_when_the_document_names_another_organization(tmp_path):
    """next_steps.py --org-name example.net led the document with example.net, and the brief sorted plan.json's
    rows with row_key and the document's organization, so the DNS changes ran P-01, P-09, P-02 ... while
    plan.json, plan.md and todo.md run P-01 to P-14. plan.json records its own headline now, and the brief sorts
    with it; an older plan.json without one runs by its ids."""
    rep, plan = r12.estate(tmp_path)
    plan = as_json(plan)
    assert plan["headline"] == "example.com"
    want = [c["id"] for c in plan["changes"]]
    for org in ("example.net", "brand.example", None):
        doc = as_json(next_steps.build(rep, plan, owners=r12.OWNERS, org_name=org))
        assert doc["org_domain"] == (org or "example.com")
        assert ids_on(brief.render(doc, plan)) == (want, want), org
        older = {k: v for k, v in plan.items() if k != "headline"}  # a plan.json from before it recorded one
        shuffled = dict(older, changes=list(reversed(older["changes"])))
        assert ids_on(brief.render(doc, shuffled)) == (want, want), org
    # the holds follow the plan's headline too, as plan.py sorted them
    holds = [{"domain": "example.net", "reason": "decide the order of the rua addresses"},
             {"domain": "a.example.com", "reason": "two records at one name"}]
    page = brief.render({"org_domain": "example.net"}, dict(plan, holds=holds))
    decide = section_of(page, "dns").split("<h3>Decide first</h3>", 1)[1].split("</ul>", 1)[0]
    assert [text_of(n) for n in re.findall(r"<li>(.*?): ", decide)] == ["a.example.com", "example.net"]
    # rows without ids, in a plan that records no headline: row_key with the document's organization
    bare = [dict(c, id="") for c in plan["changes"]]
    keyed = sorted(bare, key=lambda c: plan_mod.row_key(c, "example.net"))
    assert brief.plan_order(bare, "example.net", by_ids=True) == keyed


# ------------------------------------------------------------------ N3, N5 (layout): what a source sends as a domain

RUA = "mailto:dmarc-reports@example.org"


def rua_estate(tmp_path):
    """Aggregate reports only: 198.51.100.7 fails as example.org (40), a.shop.example.org (40) and
    zeta.example.org (30); 198.51.100.9 as example.net (60) and example.org (25)."""
    apex = "v=DMARC1; p=quarantine; sp=none; rua=%s;" % RUA
    given = ["example.org", "zeta.example.org", "a.shop.example.org", "example.net"]
    docs = {n: r11.inherits(n, apex, "_dmarc.example.org") for n in ("zeta.example.org", "a.shop.example.org")}
    docs["example.org"] = r11.own_record("example.org", apex)
    docs["example.net"] = r11.own_record("example.net", "v=DMARC1; p=none; rua=%s;" % RUA)
    rua_dir = tmp_path / "rua"
    rua_dir.mkdir()
    r11.rua_report(rua_dir / "org.xml", "example.org", "quarantine", [
        ("192.0.2.10", 300, "example.org", "example.org", "pass", "example.org", "pass"),
        ("198.51.100.7", 30, "zeta.example.org", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.7", 40, "example.org", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.7", 40, "a.shop.example.org", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.9", 25, "example.org", "esp.invalid", "pass", "esp.invalid", "pass")])
    r11.rua_report(rua_dir / "net.xml", "example.net", "none", [
        ("192.0.2.11", 100, "example.net", "example.net", "pass", "example.net", "pass"),
        ("198.51.100.9", 60, "example.net", "esp.invalid", "pass", "esp.invalid", "pass")])
    sources = {d: ["tenant"] for d in given}
    rep = audit.build_report(domains=given, rua_paths=[str(rua_dir)], offline=True, domain_sources=sources,
                             headline="example.org")
    rep["dns"] = docs
    rep["gate"] = audit.gate_verdict(docs, rep["rua"], rep["maillog"], given, None, {}, sources, "example.org")
    rep["generated_utc"] = "2026-10-09T06:00:00Z"
    inventory = {"domains": [{"domain": d, "zone": plan_mod.org_domain(d), "zone_host": "Route53"} for d in given]}
    return rep, inventory


def source_prereqs(plan):
    return {(c["domain"], p.split(" sends ", 1)[0][len("aggregate reports: "):]): p
            for c in plan["changes"] for p in c.get("prerequisites") or [] if p.startswith("aggregate reports: ")}


def test_an_outside_source_is_counted_by_what_it_sends_as_the_rows_domain(tmp_path):
    """plan.py gave every From domain a source sends as the source's whole count: example.org's row said
    198.51.100.9 'sends 85 message(s) as example.org' and example.net's 'sends 85 message(s) as example.net',
    though it sends 25 and 60; the one-liner's busiest clause then ranked and named those 85s. Each row now says
    what the source sends as its domain, with the whole beside it, and the busiest clause ranks by that."""
    rep, inventory = rua_estate(tmp_path)
    plan = plan_mod.build_plan(rep, inventory, RUA)
    pre = source_prereqs(plan)
    assert pre[("example.org", "198.51.100.7")].startswith(
        "aggregate reports: 198.51.100.7 sends 40 of its 110 message(s) as example.org and fails (likely_misconfigured; ")
    assert pre[("example.org", "198.51.100.9")].startswith(
        "aggregate reports: 198.51.100.9 sends 25 of its 85 message(s) as example.org and fails")
    assert pre[("example.net", "198.51.100.9")].startswith(
        "aggregate reports: 198.51.100.9 sends 60 of its 85 message(s) as example.net and fails")
    doc = next_steps.build(rep, plan, date="2026-10-13")
    assert ("the 2 failing outside-view senders are fixed or formally excepted (busiest: 198.51.100.7 (40 of its 110 "
            "as example.org), 198.51.100.9 (25 of its 85 as example.org))") in doc["one_liner"]
    items = [i for g in doc["actions_by_owner"] for i in g["items"] if i.get("summary")]
    net = next(i for i in items if i["domains"] == ["example.net"] and "198.51.100.9" in i["action"])
    assert "the sender at 198.51.100.9 (60 of its 85 messages as example.net) is fixed" in net["prerequisites"]
    # the busiest by what each sends as the domain, never by its whole count
    texts = ["aggregate reports: 192.0.2.1 sends 30 of its 900 message(s) as example.org and fails (x; y)",
             "aggregate reports: 192.0.2.2 sends 50 message(s) as example.org and fails (x; y)"]
    assert next_steps.reword_prereqs(texts) == [
        "the 2 failing outside-view senders are fixed or formally excepted (busiest: 192.0.2.2 (50 as example.org), "
        "192.0.2.1 (30 of its 900 as example.org))"]
    # a source the per-source table does not name keeps its whole count, in the words it always had
    del rep["rua"]["by_source_ip"]
    pre = source_prereqs(plan_mod.build_plan(rep, inventory, RUA))
    assert pre[("example.org", "198.51.100.9")].startswith(
        "aggregate reports: 198.51.100.9 sends 85 message(s) as example.org and fails")


def test_a_sources_signals_are_quoted_whole_and_the_rest_counted():
    """The joined signals were cut at 120 characters, so a card read '... SPF passes for envelope domai)'."""
    first = "DKIM verifies for d=esp.invalid but that domain is not aligned with header_from (60 msgs)"
    second = "SPF passes for envelope domain esp.invalid which is not aligned with header_from (60 msgs)"
    assert plan_mod.quoted_signals([first, second]) == first + "; 1 more signal in report.json"
    assert plan_mod.quoted_signals([first]) == first and plan_mod.quoted_signals([]) == ""
    assert plan_mod.quoted_signals(["short one", "short two", second]) == "short one; short two; " + second
    long_one = "word " * 40
    out = plan_mod.quoted_signals([long_one.strip(), "x"])
    assert out.endswith("...; 1 more signal in report.json") and "wor..." not in out and len(out) < 160


# ------------------------------------------------------------------ N4: a quoted subject, cut at a word

SUBJECT = "Your statement is ready to download for account reference 4471902 #"


def test_a_quoted_subject_is_cut_at_a_word_so_no_number_shows_in_part(tmp_path):
    """next_steps.md cut a subject at 60 characters, so 'reference 4471902' read 'reference 44' in its bullet,
    its owner item and the brief's owner item, while report.md and the brief's table quote the whole number."""
    assert SUBJECT.index("4471902") == 58
    log = r11.Log().add("staff@example.com", "Weekly #", times=20).add("statements@example.com", SUBJECT, "fail", 12)
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={"example.com": ["cli"]})
    doc = as_json(next_steps.build(rep, None, date="2026-10-13"))
    md = next_steps.render_md(doc)
    page = text_of(brief.render(doc))
    for text in (md, page):
        quoted = re.findall(r"reference ?\d*", text)
        assert quoted and all(q in ("reference 4471902", "reference") for q in quoted), quoted
    assert 'subjects like "Your statement is ready to download for account reference..."' in md
    assert next_steps.cut_subject(SUBJECT[:-2]) == SUBJECT[:57] + "..."  # 65 characters: cut before the number
    assert next_steps.cut_subject("a" * 70) == "a" * 70 + "..."  # one word longer than the limit: whole
    assert next_steps.cut_subject("short subject") == "short subject"
    assert brief.render(doc).count("reference 4471902") >= 1  # the table's own, under its 100 characters


# ------------------------------------------------------------------ N5: the formally excepted line in its list

def test_the_formally_excepted_line_is_an_item_of_the_sender_list_it_qualifies(tmp_path):
    """'Formally excepted in audit.toml and not counted above: ...' followed the sender list with no blank line, so
    Markdown read it as part of the notes bullet; it is an item of that list now, and every line of What is
    failing that is not a list item follows a blank line."""
    log = (r10.Log().add("alerts@pay.example.com", "pay.example.com", "Payment alert #", 9)
           .add("noreply@example.com", "example.com", "Receipt #", 12)
           .add("billing@example.com", "vendor.invalid", "Invoice #", 5))
    rep = r10.report(tmp_path, log, exceptions=[r10.exc("vendor.invalid")])
    doc, md = r10.doc_md(rep)
    lines = md_section(md, "What is failing").strip("\n").splitlines()
    excepted = "- Formally excepted in audit.toml and not counted above: 5 messages (billing@example.com x5)."
    assert excepted in lines
    at = lines.index(excepted)
    assert lines[at - 1].startswith("- " + next_steps.NOTES_LINE)  # right under the list it qualifies
    for k, line in enumerate(lines):
        if line and not line.startswith("- "):
            assert k == 0 or lines[k - 1] == "", (k, line)
    # the brief keeps it in the sender list's block, under its table, as before
    blocks = section_of(brief.render(doc), "failing").split('<div class="group"><h3>')
    senders = next(b for b in blocks if b.startswith("By sender address"))
    assert senders.index("<table") < senders.index("Formally excepted")
    assert sum(b.count("Formally excepted") for b in blocks) == 1


# ------------------------------------------------------------------ N0 (layout): a record card's short fields

def test_a_record_cards_type_and_ttl_take_the_width_their_values_need():
    """Above 40rem every field kept a 5.5rem label column in a 1fr track, leaving the Type and TTL values 6 to 29px
    at 641 to 788px: TTL 3600 read as 360 over 0. The two short fields now take the width their value needs and
    never wrap it (checked in Edge with the layout review's fields_wrap.py on the estate and stress pages: no
    width from 360 to 1280 px; sweep.py at every pixel from 630 to 660 and 760 to 800 finds no spill)."""
    css = brief.CSS
    assert ".fields { display: grid; grid-template-columns: minmax(0, 1fr) auto auto;" in css
    assert ".field.short { grid-template-columns: auto auto; }" in css
    assert ".field.short dd { white-space: nowrap; }" in css
    narrow = css.split("@media (max-width: 40rem) {\n", 1)[1].split("\n}\n", 1)[0]
    assert ".field.short { grid-template-columns: 5.5rem minmax(0, 1fr); }" in narrow  # one column: labels aligned
    card = brief.record_card({"id": "P-01", "kind": "new", "domain": "example.com", "hostname": "_dmarc.example.com",
                              "record": "TXT", "ttl": 3600, "value": "v=DMARC1; p=none;"}, 1)
    assert re.findall(r'<div class="field( short| wide)?"><dt>(Type|TTL)</dt>', card) == [(" short", "Type"),
                                                                                       (" short", "TTL")]
    # a value too long to be a record type (a damaged plan) keeps the field's own column, and wraps
    odd = brief.record_card({"record": "x" * 40, "ttl": "3600"}, 2)
    assert '<div class="field"><dt>Type</dt>' in odd and '<div class="field short"><dt>TTL</dt>' in odd


# ------------------------------------------------------------------ N1, N2 (layout): nothing in running text splits

class Splittable(HTMLParser):
    """The page's text a browser may break inside: every text node outside the pieces the page keeps whole or
    lays out apart (a name piece, an id or date piece, a tag, a pill, a label, mono values such as a record, a
    number cell, the index's id link), each with whether it sits in running text (a list item, a table cell,
    the lede, the ask, the step, a note, a why, a card)."""

    WHOLE = {"d", "dn", "tag", "pill", "k", "mono", "num", "value", "channel", "count", "eyebrow"}
    RUNNING = {"lede", "ask", "step", "note", "why", "card"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.texts = [], []

    def handle_starttag(self, tag, attrs):
        if tag in ("wbr", "meta", "br"):
            return
        cls = set((dict(attrs).get("class") or "").split())
        whole, running = self.stack[-1] if self.stack else (False, False)
        self.stack.append((whole or bool(cls & self.WHOLE) or tag in ("title", "style", "a", "pre"),
                           running or bool(cls & self.RUNNING) or tag in ("li", "td")))

    def handle_endtag(self, tag):
        if self.stack and tag not in ("wbr", "meta", "br"):
            self.stack.pop()

    def handle_data(self, data):
        if self.stack and not self.stack[-1][0] and data.strip():
            self.texts.append((data, self.stack[-1][1]))


ID_OR_DATE = re.compile(r"(?<![A-Za-z0-9-])(?:[A-Z]+-[0-9]+|[0-9]{4}-[0-9]{2}-[0-9]{2})(?![0-9])")


def splittable(page):
    p = Splittable()
    p.feed(page.split("<body>", 1)[1] if "<body>" in page else page)
    return p.texts


def test_ids_dates_and_names_in_running_text_never_split(tmp_path):
    """The checklists, the ask, the lede, the notes lines and the cards' text went through marks() alone: '(plan
    P-|14)', 'P-01, P-02, P-|08)', '2026-|10-07', 'corp.exa|mple' and 'investor-|relations.example.com x8' on a
    phone, '(P- | 13)' on paper. Every id and ISO date in running text is one unbroken piece now, every name of
    LABEL_KEEP characters or fewer one piece too, and a longer one breaks between its labels only (checked in
    Edge with the layout review's breaks.py on the estate, stress, awkward, fold, rua, quiet, order, long-label and
    sample pages at 360 and 400 px, and in print at 688 and 720 px: no split id, date or short label)."""
    import test_r12_int as ri
    for name in ("shipped", "stress", "awkward"):
        (tmp_path / name).mkdir()
    rep, plan = r12.estate(tmp_path / "shipped")
    built = [(rep, plan, r12.OWNERS), ri.stress_estate(tmp_path / "stress"), ri.awkward_estate(tmp_path / "awkward")]
    for rep, plan, owners in built:
        doc = as_json(next_steps.build(rep, plan, owners=owners))
        page = brief.render(doc, plan)
        texts = splittable(page)
        loose = [t for t, _ in texts if ID_OR_DATE.search(t)]
        assert not loose, loose[:5]
        # a name a browser could split - one with a hyphen, or longer than LABEL_KEEP - is never loose in running
        # text: a short one is one piece, a longer one breaks between its labels only
        names = [m.group(0) for t, running in texts if running for m in brief.NAME_IN_TEXT_RX.finditer(t)
                 if "-" in m.group(0) or len(m.group(0)) > brief.LABEL_KEEP]
        assert not names, names[:5]
    # the pieces themselves
    assert brief.prose("before we move (plan P-14) on 2026-10-07") == (
        'before we move (plan <span class="d">P-14</span>) on <span class="d">2026-10-07</span>')
    long_name = "dev.support.example.com._report._dmarc.corp.example"
    assert brief.prose("publish " + long_name) == "publish " + brief.text_name(long_name)
    assert brief.text_name(long_name).startswith('<span class="d dl">')  # moves whole; breaks between labels
    note = brief._note_line([{"name": "investor-relations.example.com", "count": 8, "likely": "likely_spoof"}])
    assert '<span class="w">investor-relations.</span>' in note  # a short label with a hyphen never breaks


def test_a_short_name_in_a_cell_is_one_piece_and_an_address_never_breaks_in_its_local_part():
    """5d205a2 put a break after every dot and @ of every name in a cell's sentence, so the browser split names it
    could have moved whole: 'such as noreply@' / 'example.com', 'it follows _dmarc.example.' / 'com'. A name of
    LABEL_KEEP characters or fewer is one piece now (the line breaks at the space before it); only a longer one
    breaks, between its labels; an address's local part is one piece (sweep.py at every pixel from 760 to 800 px:
    every table still fits)."""
    assert brief.prose("it follows _dmarc.example.com, effective p=reject") == (
        'it follows <span class="d">_dmarc.example.com</span>, effective p=reject')
    assert brief.text_name("noreply@example.com") == '<span class="d">noreply@example.com</span>'
    assert brief.plain_name("first.last@mail.example.com") == (
        '<span class="dn keep"><span>first.last@</span><span>mail.</span><span>example.</span>'
        '<span>com</span></span>')
    doc = {"failing": {"by_envelope": [{"name": "example.com", "count": 12, "sender_count": 1,
                                        "senders": ["noreply@example.com"], "likely": "likely_spoof"}],
                       "outside": [{"name": "198.51.100.7", "count": 110, "likely": "likely_misconfigured",
                                    "as": "example.org, x.y.example.org and 1 more"}], "lines": []}}
    sec = section_of(brief.render(doc), "failing")
    assert 'such as <span class="d">noreply@example.com</span>' in sec
    assert ('<td class="name"><bdi><span class="d">example.org</span>, <span class="d">x.y.example.org</span> and 1 '
            'more</bdi></td>') in sec


# ------------------------------------------------------------------ N3 (layout): a long zone beside its label

def test_a_long_zone_sits_beside_its_label_and_stays_with_it_on_paper():
    """p.zone fell under '.section p { max-width: 70ch }', so a 68-character zone wrapped below its label at 1280
    px, and on paper its label ended one page and its name began the next (print_check.py: Letter page 45, A4
    page 38). The zone line takes the column's width, never splits across pages, and its name breaks between its
    labels (zone_probe.py: one line at 1024 and 1280 px; print_check.py: no page ends on a label)."""
    css = brief.CSS
    assert ".section p.zone { max-width: none; }" in css
    printed = css.split("@media print {\n", 1)[1]
    assert ".tile, .card, .ask, tr, .checklist li, .zone, .now { break-inside: avoid; }" in printed  # round 13: .now
    zone = "an-extraordinarily-long-organizational-domain-name-for-layout.example"
    page = brief.render({}, {"changes": [{"id": "P-01", "priority": 1, "zone_host": "unknown", "zone": zone,
                                          "domain": zone, "hostname": "_dmarc." + zone, "kind": "new"}]})
    assert ('<p class="zone"><span class="k">Zone</span><span class="mono">%s</span></p>' % brief.plain_name(zone)
            in page)


# ------------------------------------------------------------------ N4 (layout): every invisible format character

INVISIBLE = (0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, 0xFFF9,
             0xFFFA, 0xFFFB, 0xE0001, 0xE0020, 0xE0041, 0xE007F)
FLAG = "".join(chr(c) for c in (0x1F3F4, 0xE0067, 0xE0062, 0xE0073, 0xE0063, 0xE0074, 0xE007F))  # Scotland


def test_two_addresses_that_differ_by_an_invisible_character_never_look_alike(tmp_path):
    """B6 narrowed the marked set to the bidi controls and three zero-width characters, so ceo@example.com and the
    same with U+2063, U+2061, U+180E or U+E0041 after 'exam' rendered as five identical rows. Every format
    character but the joiners, the direction marks and the soft hyphen shows as a marker again - and a flag's tag
    characters, which spell the flag, stay text; check_doc names the same set."""
    for code in INVISIBLE:
        assert brief.marked(chr(code)), hex(code)
        assert brief.clean("ceo@exam" + chr(code) + "ple.com") == "ceo@exam[U+%04X]ple.com" % code
    for code in (0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x00AD):
        assert not brief.marked(chr(code)), hex(code)
    assert brief.clean("go " + FLAG + " team") == "go " + FLAG + " team"
    assert brief.clean(FLAG[1:]) == "".join("[U+%04X]" % ord(c) for c in FLAG[1:])  # no flag: each tag shows
    senders = ["ceo@example.com"] + ["ceo@exam%sple.com" % chr(c) for c in (0x2063, 0x2061, 0x180E, 0xE0041)]
    page = brief.render({"failing": {"by_sender": [{"name": s, "count": 12, "likely": "likely_spoof"}
                                                   for s in senders], "lines": []}})
    shown = [text_of(n) for n in re.findall(r'<tr><td class="name">(.*?)</td>', section_of(page, "failing"))]
    assert len(set(shown)) == 5, shown
    # the checker names them in a polished copy, and lets a flag pass
    run = tmp_path / "run"
    run.mkdir()
    (run / "next_steps.md").write_text("A run file. Team flag " + FLAG + ".\n", encoding="utf-8")
    copy = tmp_path / "copy.md"
    copy.write_text("Sender ceo@exam%sple.com fails; our flag %s\n" % (chr(0x2063), FLAG), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_doc.py"), str(copy), "--run", str(run)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 1 and p.stdout.splitlines() == [
        "line 1: U+2063: an invisible character: the voice rules forbid it, write it as brief.html shows it, "
        "[U+2063], or delete it"], p.stdout
