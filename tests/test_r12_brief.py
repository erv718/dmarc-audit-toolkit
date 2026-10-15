"""Round 12, workstream B: the designed brief. src/brief.py lays the run's
status document (next_steps.json, with plan.json) out as one self-contained
page, collect.py writes it into every run, the dmarc-status-brief skill
drives it, and scripts/check_doc.py checks a polished copy against its run.
Synthetic data, offline: nothing here touches the network."""

import html
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

import audit
import brief
import collect
import next_steps
import plan as plan_mod

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / ".claude" / "skills" / "dmarc-status-brief"
PAYLOADS = ("<img src=x onerror=alert(1)>", '"><script>alert(1)</script>', "**bold** <b>x</b>")
EM = chr(0x2014)  # an em dash, spelled as a number so this file stays ASCII
TAGS = {"html", "head", "meta", "title", "style", "body", "main", "div", "nav", "section", "article", "footer", "h1",
        "h2", "h3", "h4", "p", "span", "b", "strong", "code", "pre", "a", "ol", "ul", "li", "dl", "dt", "dd", "table",
        "thead", "tbody", "tr", "th", "td"}
ATTRS = {"class", "id", "href", "lang", "charset", "name", "content", "http-equiv", "aria-label", "aria-hidden", "scope",
         "colspan"}
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")


class Tags(HTMLParser):
    """Every start tag of a page with its attributes, as a browser reads them."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    handle_startendtag = handle_starttag


def tags_of(page):
    p = Tags()
    p.feed(page)
    p.close()
    return p.tags


def section_of(page, sid):
    """One section's markup, from its id to its end."""
    start = page.index('id="%s"' % sid)
    return page[start:page.index("</section>", start)]


def text_of(fragment):
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def run_cli(script, *argv):
    return subprocess.run([sys.executable, str(ROOT / script), *argv], cwd=ROOT, capture_output=True, text=True,
                          timeout=120)


def collect_samples(out, monkeypatch=None):
    """collect.py over the bundled samples, offline, as tests/test_r10_monday.py runs it."""
    argv = ["collect.py", "--no-config", "--no-graph", "--offline", "--no-notify", "--no-owners", "example.com",
            "--rua", str(ROOT / "samples" / "rua"), "--maillog", str(ROOT / "samples" / "sample_maillog.csv"),
            "--auth-column", "DMARC", "--out", str(out)]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as stop:
            collect.main()
    assert stop.value.code in (0, 1)  # findings or none, never a traceback
    return out / "latest"


@pytest.fixture(scope="module")
def sample_run(tmp_path_factory):
    return collect_samples(tmp_path_factory.mktemp("brief_samples") / "out")


def dns_doc(domain, **over):
    base = {"domain": domain, "spf": "v=spf1 include:spf.protection.outlook.com -all", "spf_status": "found",
            "spf_terminator": "-all", "spf_lookups": 2, "spf_lookups_failed": 0, "spf_verified": True, "dmarc": None,
            "dmarc_source": None, "effective_policy": None, "inherited": False, "dmarc_status": "absent",
            "dkim_selectors": ["selector1"], "dkim_status": "found", "mx": ["0 mx.example.com"], "mx_null": False,
            "mx_status": "found", "flags": [], "findings": [], "evidence": []}
    base.update(over)
    return base


def minor(fid, title):
    return {"id": fid, "severity": "minor", "area": "dmarc", "title": title, "evidence": "",
            "action": "publish a record", "verified": True}


@pytest.fixture(scope="module")
def quiet_run(tmp_path_factory):
    """A whole run folder that never says p=reject: example.com at p=none with a subdomain inheriting it, the
    sample mail log, no aggregate reports, and a plan - report, plan, next steps and brief, as a run writes them."""
    out = tmp_path_factory.mktemp("quiet_run")
    rec = "v=DMARC1; p=none; rua=mailto:reports@example.com;"
    names = ["example.com", "news.example.com"]
    rep = audit.build_report(domains=names, maillog=str(ROOT / "samples" / "sample_maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={d: ["cli"] for d in names})
    rep["dns"] = {
        "example.com": dns_doc("example.com", dmarc=rec, dmarc_source="_dmarc.example.com", effective_policy="none",
                               dmarc_status="found", findings=[minor("DMARC-002", "DMARC p=none - monitoring only")]),
        "news.example.com": dns_doc("news.example.com", dmarc=rec, dmarc_source="_dmarc.example.com", inherited=True,
                                    effective_policy="none", dmarc_status="found", mx=[], mx_status="absent",
                                    findings=[minor("DMARC-002", "inherits p=none from example.com")]),
    }
    rep["gate"] = audit.gate_verdict(rep["dns"], rep["rua"], rep["maillog"], names, None, {},
                                     rep["inputs"]["domain_sources"])
    rep["findings"] = audit.reword_for_reject(audit.flatten_findings(rep), rep["gate"])
    rep["summary"].update(gate=rep["gate"]["verdict"], next_step=rep["gate"]["next_step"])
    rep["verified_vs_inferred"] = audit.verified_vs_inferred(rep)
    pl = plan_mod.build_plan(rep, None, "mailto:reports@example.com")
    (out / "report.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    (out / "report.md").write_text(audit.render_md(rep), encoding="utf-8")
    plan_mod.write(pl, out)
    next_steps.write(next_steps.build(rep, pl), out)
    brief.write_run(out)
    return out


# ------------------------------------------------------------------ B2: every run writes it

def test_collect_writes_the_brief_into_the_run_and_into_latest(sample_run):
    page = (sample_run / "brief.html").read_text(encoding="utf-8")
    doc = json.loads((sample_run / "next_steps.json").read_text(encoding="utf-8"))
    assert "brief.html" in collect.RUN_FILES
    history = list((sample_run.parent / "history").glob("*/brief.html"))
    assert len(history) == 1 and history[0].read_bytes() == (sample_run / "brief.html").read_bytes()
    # every section in its place, in order, each with its id - and no other id on the page
    assert re.findall(r'\sid="([^"]+)"', page) == list(brief.SECTION_IDS)
    assert re.findall(r'href="#([^"]+)"', page) == [sid for sid, _ in brief.SECTIONS]  # the contents, in order
    assert "<p>%s</p>" % brief.marks(doc["one_liner"]) in section_of(page, "summary")
    assert page.startswith("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
    assert '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">' in page
    assert '<meta http-equiv="Content-Security-Policy" content="%s">' % CSP in page
    assert "<title>example.com DMARC brief %s</title>" % doc["date"] in page
    # nothing runs, nothing loads, nothing links out
    assert "<script" not in page.lower()
    assert "http://" not in page and "https://" not in page
    assert not re.search(r"\son[a-z]+=", page)
    assert not any(name.startswith("on") for _, attrs in tags_of(page) for name, _ in attrs)
    style = page.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "url(" not in style and "@import" not in style
    # the template parts are ASCII: the module, the style, and the page the ASCII samples give
    assert (ROOT / "src" / "brief.py").read_bytes().isascii()
    assert brief.CSS.isascii() and page.isascii()
    assert "DNS changes" in page and brief.NOT_IN_RUN in section_of(page, "dns")  # an offline run writes no plan


@pytest.mark.parametrize("module, name, note", [
    (brief, "render", "no brief.html written (ValueError: a damaged document)"),
    (next_steps, "build", "no brief.html written (BriefError: no next-steps document in this run)"),
])
def test_a_brief_that_cannot_be_built_is_a_run_note_never_the_end_of_the_run(monkeypatch, tmp_path, module, name,
                                                                              note):
    def broken(*a, **k):
        raise ValueError("a damaged document")
    monkeypatch.setattr(module, name, broken)
    latest = collect_samples(tmp_path / "out")
    run = json.loads((latest / "run.json").read_text(encoding="utf-8"))
    assert note in run["notes"]
    assert not (latest / "brief.html").exists()
    for f in ("report.json", "todo.md", "verify.md", "summary.txt"):
        assert (latest / f).is_file(), f


def test_the_command_line_rebuilds_the_same_page_and_refuses_what_is_not_a_document(sample_run, tmp_path):
    out = tmp_path / "copy.html"
    p = run_cli("src/brief.py", str(sample_run), "--out", str(out))
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "wrote %s" % out
    assert out.read_bytes() == (sample_run / "brief.html").read_bytes()  # the same files, the same bytes
    p = run_cli("src/brief.py", str(sample_run), "--out", str(tmp_path / "frag.html"), "--fragment")
    assert p.returncode == 0 and (tmp_path / "frag.html").read_text(encoding="utf-8").startswith("<title>")
    empty = tmp_path / "empty"
    empty.mkdir()
    p = run_cli("src/brief.py", str(empty))
    assert p.returncode == 2 and len(p.stderr.strip().splitlines()) == 1 and "next_steps.json is missing" in p.stderr
    (empty / "next_steps.json").write_text("[1, 2]", encoding="utf-8")
    p = run_cli("src/brief.py", str(empty))
    assert p.returncode == 2 and "is not one JSON object" in p.stderr and "Traceback" not in p.stderr
    (empty / "next_steps.json").write_text("{not json", encoding="utf-8")
    p = run_cli("src/brief.py", str(empty))
    assert p.returncode == 2 and "is not valid JSON" in p.stderr
    assert not (empty / "brief.html").exists()


# ------------------------------------------------------------------ B1: the page

def test_render_is_deterministic_and_the_fragment_is_title_style_and_body_only(sample_run):
    doc = json.loads((sample_run / "next_steps.json").read_text(encoding="utf-8"))
    page = brief.render(doc)
    assert page == brief.render(json.loads(json.dumps(doc)))
    frag = brief.render(doc, fragment=True)
    assert frag.startswith("<title>")
    for tag in ("<html", "<head", "<body", "<!doctype", "<meta"):
        assert tag not in frag.lower(), tag
    title, rest = frag.split("</title>\n", 1)
    assert title + "</title>\n" in page and rest.split("</style>\n", 1)[1] in page  # the same body as the page
    assert "<style>\n/* Layout: one reading column" in frag


def test_the_brief_carries_the_documents_own_sentences(sample_run):
    """Same content as next_steps.md: every sentence of the document is on the page, as the generator wrote it."""
    doc = json.loads((sample_run / "next_steps.json").read_text(encoding="utf-8"))
    page = (sample_run / "brief.html").read_text(encoding="utf-8")
    texts = [doc["one_liner"], doc["ask"], doc["mailflow"]["note"], doc["next_step"]["label"],
             *doc["stand"]["lines"], *doc["next_step"]["prerequisites"], *doc["glossary"].values(),
             *(q["question"] for q in doc["open_questions"]),
             *(i[k] for g in doc["actions_by_owner"] for i in g["items"] for k in ("hook", "action")),
             *brief.failing_rest(doc["failing"])]
    for t in texts:
        assert brief.marks(t) in page, t
    for r in doc["per_domain"]:
        assert brief.marks(r["next_step"]) in section_of(page, "domains")
    audience, sources = doc["sources"]["audience"], doc["sources"]["audience_line"][len(doc["sources"]["audience"]) + 2:]
    assert '<p class="audience">%s.</p>' % audience in page and brief.marks(sources) in page
    assert brief.VERIFY_LINE == next_steps.render_md(doc).split("\n\n")[2]  # the pointer next_steps.md opens with
    # the tiles: genuine failures with the raw count beside them, and receivers' verdicts from spoofing_blocked
    st = doc["stand"]
    assert '<p class="figure">%d <span class="side">raw %d</span></p>' % (st["genuine_failures"],
                                                                        st["raw_failing_rows"]) in page
    sb = st["spoofing_blocked"]
    assert '<p class="figure">%d / %d</p>' % (sb["rejected"], sb["quarantined"]) in page


def test_every_string_from_the_data_is_escaped_and_only_the_generators_marks_become_tags():
    bad = " | ".join(PAYLOADS)
    doc = {"date": "2026-10-13", "org_domain": "example.com", "one_liner": "example.com is at p=none. " + bad,
           "stand": {"lines": ["**Genuine failures: 12** " + bad], "genuine_failures": 12, "trend": None},
           "failing": {"by_sender": [{"name": "x%s@example.com" % PAYLOADS[0], "count": 12, "likely": "likely_spoof",
                                      "subjects": list(PAYLOADS[1:]), "envelope": PAYLOADS[1]}],
                       "outside": [{"name": PAYLOADS[1], "count": 40, "likely": "unknown", "header_from": [PAYLOADS[0]],
                                    "dispositions": {"none": 40}}],
                       "lines": [bad]},
           "per_domain": [{"domains": ["example.com"], "policy_today": PAYLOADS[1], "gate": PAYLOADS[0],
                           "gate_text": bad, "next_step": bad, "plan_ids": [PAYLOADS[1]], "mailflow_text": bad,
                           "org": PAYLOADS[1]}],
           "actions_by_owner": [{"owner": bad, "channel": PAYLOADS[1],
                                 "items": [{"hook": bad, "action": bad, "ref": PAYLOADS[0], "kind": PAYLOADS[1],
                                            "domains": [PAYLOADS[0]], "org": PAYLOADS[0]}]}],
           "ask": bad, "open_questions": [{"question": bad, "owner": bad, "kind": PAYLOADS[0], "count": 2}],
           "glossary": {PAYLOADS[0]: bad}, "next_step": {"label": bad, "ref": PAYLOADS[1], "verdict": PAYLOADS[0],
                                                         "prerequisites": [bad], "holds": [bad], "why": bad},
           "sources": {"audience": bad, "audience_line": bad + ". Sources: " + bad, "owners_file": PAYLOADS[0]}}
    plan = {"changes": [{"id": PAYLOADS[1], "priority": 1, "zone_host": PAYLOADS[0], "zone": PAYLOADS[1],
                         "domain": "pay.example.com", "hostname": PAYLOADS[0], "record": "TXT", "kind": PAYLOADS[1],
                         "value": PAYLOADS[1], "current": PAYLOADS[0], "ttl": PAYLOADS[1], "rollback": bad, "why": bad,
                         "prerequisites": [bad], "finding_ids": [PAYLOADS[0]], "human_summary": bad}],
            "holds": [{"domain": PAYLOADS[0], "reason": bad}], "rua_is_placeholder": True, "rua": PAYLOADS[1]}
    page = brief.render(doc, plan)
    seen = tags_of(page)
    assert {t for t, _ in seen} <= TAGS
    for tag, attrs in seen:
        for name, value in attrs:
            assert name in ATTRS, (tag, name)
            if name == "href":
                assert value.startswith("#") and value[1:] in brief.SECTION_IDS
            if name == "id":
                assert value in brief.SECTION_IDS
            if name == "class":
                assert re.fullmatch(r"[a-z][a-z -]*", value), value
    for p in PAYLOADS:
        assert html.escape(p, quote=True).replace("**bold**", "<strong>bold</strong>") in page or \
            html.escape(p, quote=True) in page, p
    lede = section_of(page, "summary")
    assert "<strong>bold</strong> &lt;b&gt;x&lt;/b&gt;" in lede  # the bold mark became a tag, the raw tag stayed text
    assert "&lt;img src=x onerror=alert(1)&gt;" in lede and "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in lede
    assert "<script" not in page and "<img" not in page and "<b>x</b>" not in page
    assert "<strong>bold</strong>" in section_of(page, "owners") and "<strong>bold</strong>" in section_of(page, "ask")
    # a sender, a subject, a hook and an owner each come back as the text they were
    assert "x&lt;img src=x onerror=alert(1)&gt;@example.com" in section_of(page, "failing")
    assert '"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"' in section_of(page, "failing")
    owners = section_of(page, "owners")
    assert text_of(owners).count("<img src=x onerror=alert(1)>") >= 2  # the owner and the hook, as text


def test_the_next_step_says_what_holds_it_and_a_missing_figure_is_never_a_zero():
    own = "the 3 mail-log failures from our own systems are fixed"
    doc = {"org_domain": "example.com",
           "next_step": {"label": "raise pct to 50", "ref": "P-04", "source": "plan", "verdict": "no_go",
                         "prerequisites": [own], "holds": [own, "3 messages reached a mailbox despite failing"],
                         "data": [], "why": "the next step on the ramp"},
           "stand": {"genuine_failures": 21, "raw_failing_rows": 33, "truncation": "row budget",
                     "delivered_despite_fail": None, "spoofing_blocked": None, "lines": [],
                     "trend": {"label": "2026-10-06", "previous_genuine_failures": 30, "previous_pass_rate": None,
                               "not_comparable": []}}}
    page = brief.render(doc)
    nxt = section_of(page, "next-step")
    assert '<p class="step-label">raise pct to 50 <span class="tag">P-04</span></p>' in nxt
    assert '<span class="k">Gate</span><span class="pill warn">not yet</span>' in nxt
    assert '<h3>Ready when</h3><ul class="checklist"><li><span class="box" aria-hidden="true"></span>' in nxt
    assert '<h3>Also on hold while</h3><ul class="lines"><li>3 messages reached a mailbox despite failing</li>' in nxt
    assert nxt.count('class="box"') == 1  # a hold the row carries as its own prerequisite is not said twice
    # a gate step: its prerequisites are what holds it; an insufficient_data verdict says what data it needs
    doc["next_step"].update(source="gate", ref=None, verdict="insufficient_data", data=["a mail log is supplied"])
    nxt = section_of(brief.render(doc), "next-step")
    assert "<h3>Needs more data</h3>" in nxt and "<h3>On hold while</h3>" in nxt and "Ready when" not in nxt
    assert '<span class="pill info">needs data</span>' in nxt
    stand = section_of(page, "stand")
    assert ('<p class="figure">21 <span class="side">raw 33</span></p>'
            '<p class="caption">no passing copy, in the rows the cut log kept</p>') in stand
    assert stand.count('<p class="figure na">not in this run</p>') == 2  # delivered despite failing, receivers
    assert '<p class="figure">-9</p><p class="caption">genuine failures, 30 -&gt; 21</p>' in stand


# ------------------------------------------------------------------ the one domain order

def row(names, org=None, policy="p=none", gate="insufficient_data", step="publish a p=none monitoring record",
        ids=(), flow="not measured"):
    r = {"domains": list(names), "policy_today": policy, "gate": gate, "gate_text": next_steps.GATE_WORDS.get(gate, gate),
         "next_step": step, "plan_ids": list(ids), "maillog": {}, "mailflow_text": flow, "mailflow": {}}
    if org is not None:
        r["org"] = org
    return r


def change(cid, prio, host, zone, domain, hostname, value="v=DMARC1; p=none; rua=mailto:reports@example.com;",
           kind="new"):
    return {"id": cid, "priority": prio, "zone_host": host, "zone": zone, "domain": domain, "hostname": hostname,
            "record": "TXT", "kind": kind, "value": value, "current": "none", "ttl": 3600,
            "rollback": "delete the record", "why": "synthetic row for %s" % domain, "prerequisites": [],
            "finding_ids": [], "human_summary": "Publish a record for %s." % domain}


ESTATE_ROWS = [  # next_steps.json's per-domain rows, listed out of order; e. and m. merged, as next_steps merges them
    ("brand.example", ["brand.example"], "no DMARC record", "insufficient_data", ["P-09"]),
    ("example.com", ["e.example.com", "m.example.com"], "p=none (inherited from _dmarc.example.com)", "insufficient_data",
     ["P-04", "P-05"]),
    ("example.net", ["mail.example.net"], "p=none (inherited from _dmarc.example.net)", "no_go", ["P-02"]),
    ("example.com", ["example.com"], "p=quarantine, pct=25", "go", ["P-03"]),
    ("example.com", ["a.example.com"], "p=none (inherited from _dmarc.example.com)", "insufficient_data", []),
    ("example.net", ["example.net"], "p=reject", "no_go", []),
    ("example.com", ["dev.support.example.com"], "p=none (inherited from _dmarc.example.com)", "not checked", []),
]
IN_ORDER = ["example.net", "mail.example.net", "brand.example", "example.com", "a.example.com",
            "dev.support.example.com", "e.example.com", "m.example.com"]


def estate_doc(with_org=True, head="example.net"):
    return {"date": "2026-10-13", "org_domain": head,
            "per_domain": [row(names, org if with_org else None, policy, gate, ids=ids)
                           for org, names, policy, gate, ids in ESTATE_ROWS]}


def names_in(section):
    return [text_of(m) for m in re.findall(r'<td class="name">(.*?)</td>', section)]


def test_per_domain_rows_follow_the_one_order_with_the_headline_first_whatever_the_input_order():
    plan = {"changes": [change("P-04", 1, "Route53", "example.com", "e.example.com", "_dmarc.e.example.com"),
                        change("P-05", 1, "Route53", "example.com", "m.example.com", "_dmarc.m.example.com")]}
    page = brief.render(estate_doc(), plan)
    sec = section_of(page, "domains")
    assert names_in(sec) == IN_ORDER
    # one group row per organization, the headline's first, each with its count
    assert re.findall(r'<tr class="org"><th colspan="5" scope="colgroup">([^<]+) <span class="count">([^<]+)</span>',
                      sec) == [("example.net", "2 domains"), ("brand.example", "1 domain"), ("example.com", "5 domains")]
    # a merged row is expanded, and each name takes its own plan id from the plan
    rows = dict(zip(names_in(sec), re.findall(r"<tr><td.*?</tr>", sec)))
    assert '<span class="tag">P-04</span>' in rows["e.example.com"] and "P-05" not in rows["e.example.com"]
    assert '<span class="tag">P-05</span>' in rows["m.example.com"] and "P-04" not in rows["m.example.com"]
    # without plan.json an id cannot be placed: it stays on each name of its row, as next_steps.md shows it
    loose = dict(zip(IN_ORDER, re.findall(r"<tr><td.*?</tr>", section_of(brief.render(estate_doc()), "domains"))))
    assert "P-04" in loose["m.example.com"] and "P-05" in loose["e.example.com"]
    # the names: a subdomain's own labels in front, its organization muted; an apex bold
    assert '<td class="name"><b>dev.support</b><span class="apex">.example.com</span></td>' in sec
    assert '<td class="name"><b>example.com</b></td>' in sec
    # policy and gate pills by the design's colors
    assert '<span class="pill warn">p=quarantine, pct=25</span>' in rows["example.com"]
    assert '<span class="pill ok">go</span>' in rows["example.com"]
    assert '<span class="pill bad">no DMARC record</span>' in rows["brand.example"]
    assert '<span class="pill ok">p=reject</span>' in rows["example.net"]
    assert '<span class="pill warn">not yet</span>' in rows["example.net"]
    assert ('<span class="pill bad">p=none</span><span class="rest">(inherited from _dmarc.example.com)</span>'
            in rows["a.example.com"])
    assert '<span class="pill info">needs data</span>' in rows["a.example.com"]
    assert '<span class="pill info">not checked</span>' in rows["dev.support.example.com"]
    # whatever order the rows come in, the page is the same
    shuffled = estate_doc()
    shuffled["per_domain"].reverse()
    assert brief.render(shuffled, plan) == page
    # with another headline, its organization leads
    assert names_in(section_of(brief.render(estate_doc(head="pay.example.com")), "domains"))[:5] == IN_ORDER[3:]


def test_plan_rows_are_grouped_by_priority_host_and_zone_in_domain_order_whatever_plan_json_lists():
    changes = [
        change("P-01", 1, "Route53", "example.com", "t.example.com", "_dmarc.t.example.com"),
        change("P-02", 3, "Route53", "example.com", "example.com", "_dmarc.example.com", kind="ratchet"),
        change("P-03", 1, "unknown", "brand.example", "brand.example", "brand.example", "v=spf1 ~all", "modify"),
        change("P-04", 1, "Route53", "shop.example.com", "shop.example.com", "_dmarc.shop.example.com"),
        change("P-05", 1, "Cloudflare", "example.net", "mail.example.net", "_dmarc.mail.example.net"),
        change("P-06", 1, "Route53", "example.com", "a.example.com", "_dmarc.a.example.com"),
        change("P-07", 1, "unknown", "brand.example", "brand.example", "_dmarc.brand.example"),
        change("P-08", 1, "Route53", "example.com", "e.example.com", "_dmarc.e.example.com"),
        change("P-09", 1, "Route53", "example.com", "example.com", "_dmarc.example.com", kind="modify"),
        change("P-10", 1, "Route53", "example.com", "example.com", "example.com", "v=spf1 -all", "modify"),
        change("P-11", 1, "Route53", "example.com", "example.com", "selector1._domainkey.example.com", "v=DKIM1; p=x"),
    ]
    holds = [{"domain": "example.net", "reason": "decide the order of the rua addresses"},
             {"domain": "t.example.com", "reason": "a lookup failed"},
             {"domain": "a.example.com", "reason": "two records at one name"}]
    doc = {"date": "2026-10-13", "org_domain": "example.com"}
    page = brief.render(doc, {"changes": changes, "holds": holds})
    sec = section_of(page, "dns")
    # priority, then host (unknown last), then zone (a delegated zone right after its organization's own), then
    # domain in the one order, then the record: the domain's _dmarc first, its own name (SPF), _domainkey names
    assert re.findall(r'<span class="tag rid">(P-\d+)</span>', sec) == [
        "P-05", "P-09", "P-10", "P-11", "P-06", "P-08", "P-01", "P-04", "P-07", "P-03", "P-02"]
    heads = re.findall(r"<h3>(Priority \d+)|<h4>DNS host: ([^<]+)</h4>|<span class=\"mono\">([^<]+)</span></p>", sec)
    assert [a or b or c for a, b, c in heads] == [
        "Priority 1", "Cloudflare", "example.net", "Route53", "example.com", "shop.example.com", "unknown",
        "brand.example", "Priority 3", "Route53", "example.com"]
    for prio in (1, 3):
        assert esc_in(plan_mod.PRIORITY_LABEL[prio], sec)
    # the holds come first, as what to decide first, in the one order with the headline's organization first
    decide = sec.index("<h3>Decide first</h3>")
    assert decide < sec.index('class="card"')
    assert [text_of(n) for n in re.findall(r"<li>(.*?): ", sec[decide:sec.index("Priority 1")])] == [
        "a.example.com", "t.example.com", "example.net"]
    # a record card: id, kind, the name, the host name in mono, type, value block, current, TTL, rollback, why
    card = re.search(r'<article class="card"><div class="card-head"><span class="tag rid">P-04</span>.*?</article>',
                     sec).group(0)
    for part in ('<span class="k">publish</span>', '<b>shop</b><span class="apex">.example.com</span>',
                 "<dt>Host name</dt><dd><span class=\"mono\">_dmarc.shop.example.com</span></dd>",
                 "<dt>Type</dt><dd><span class=\"mono\">TXT</span></dd>",
                 '<pre class="value">v=DMARC1; p=none; rua=mailto:reports@example.com;</pre>',
                 '<span class="mono muted">none</span>', "<dt>TTL</dt><dd><span class=\"mono\">3600</span></dd>",
                 "<dt>Rollback</dt><dd>delete the record</dd>", '<p class="why">synthetic row for shop.example.com</p>'):
        assert part in card, part
    # whatever order plan.json lists its rows in, the page is the same
    assert brief.render(doc, {"changes": list(reversed(changes)), "holds": list(reversed(holds))}) == page


def esc_in(text, markup):
    return brief.esc(text) in markup


def test_owners_and_open_questions_group_by_organization_and_kind():
    head = "example.com"
    items = [
        {"hook": "billing@example.net - 12 messages", "action": "DKIM-sign it", "ref": "MAILFLOW-001", "kind": "sender",
         "domains": ["example.net"], "org": "example.net"},
        {"hook": "198.51.100.20 - 40 messages pass on SPF alone", "action": "set up DKIM", "ref": "OUTSIDE-003",
         "kind": "spf_only", "domains": [], "org": ""},
        {"hook": "t.example.com", "action": "raise pct", "ref": "P-07", "kind": "dns", "domains": ["t.example.com"],
         "org": "example.com"},
        {"hook": "news@example.com - 11 messages", "action": "DKIM-sign it", "ref": "MAILFLOW-001", "kind": "sender",
         "domains": ["example.com"], "org": "example.com"},
        {"hook": "3 zero-risk monitoring records", "action": "ready to publish", "ref": "plan P-01 to P-03",
         "kind": "p1summary", "domains": ["a.example.com", "e.example.com"], "org": "example.com"},
        {"hook": "example.com", "action": "move to p=quarantine", "ref": "P-05", "kind": "dns",
         "domains": ["example.com"], "org": "example.com"},
    ]
    questions = [
        {"question": "Who owns this: t.example.com (P-07)?", "owner": "unassigned", "kind": "unassigned",
         "domains": ["t.example.com"], "org": "example.com"},
        {"question": "Is this right (OUTSIDE-007)?", "owner": "unassigned", "kind": "unverified", "domains": [],
         "org": ""},
        {"question": "Can we confirm this before we publish (plan P-05): b?", "owner": "unassigned",
         "kind": "prerequisite", "domains": ["example.net"], "org": "example.net"},
        {"question": "Can we confirm this before we publish (plan P-07): a?", "owner": "unassigned",
         "kind": "prerequisite", "domains": ["t.example.com"], "org": "example.com"},
        {"question": "Can we clear this before we move: c?", "owner": "unassigned", "kind": "blocker",
         "domains": ["example.com"], "org": "example.com", "count": 2},
        {"question": "Something else?", "owner": "unassigned", "kind": "zeta"},
    ]
    doc = {"org_domain": head, "actions_by_owner": [{"owner": "Mail team", "channel": "#mail", "items": items}],
           "open_questions": questions}
    page = brief.render(doc)
    owners = section_of(page, "owners")
    assert '<h3>Mail team <span class="channel">#mail</span></h3>' in owners
    assert re.findall(r'<p class="org-head">([^<]+) <span class="count">([^<]+)</span>', owners) == [
        ("example.com", "4 items"), ("example.net", "1 item"), ("Tenant-wide", "1 item")]
    # within an organization: the zero-risk bundle, then the DNS changes in plan order, then the sender fixes
    assert re.findall(r'<span class="hook">([^<]+)</span>', owners) == [
        "3 zero-risk monitoring records", "example.com", "t.example.com", "news@example.com - 11 messages",
        "billing@example.net - 12 messages", "198.51.100.20 - 40 messages pass on SPF alone"]
    qs = section_of(page, "questions")
    assert re.findall(r'<h3>([^<]+) <span class="count">(\d+)</span></h3>', qs) == [
        ("Blockers", "1"), ("Prerequisites", "2"), ("Not verified yet", "1"), ("Needs an owner", "1"), ("Zeta", "1")]
    prereqs = re.findall(r"<li>Can we confirm this before we publish \(plan (P-\d+)\)", qs)
    assert prereqs == ["P-07", "P-05"]  # the headline's organization first
    assert '<span class="count">x 2</span>' in qs and qs.count("owner: unassigned") == len(questions)


# ------------------------------------------------------------------ an older document, no plan, empty sections

def strip_round12(doc):
    """next_steps.json as a run before round 12 wrote it: no "org" on the per-domain rows, no "org" or
    "domains" on the actions and the open questions."""
    doc = json.loads(json.dumps(doc))
    for r in doc.get("per_domain") or []:
        r.pop("org", None)
    for g in doc.get("actions_by_owner") or []:
        for i in g.get("items") or []:
            i.pop("org", None)
            i.pop("domains", None)
    for q in doc.get("open_questions") or []:
        q.pop("org", None)
        q.pop("domains", None)
    return doc


def test_an_older_document_renders_flat_and_without_a_plan_the_dns_section_says_so(sample_run):
    old = strip_round12(estate_doc())
    sec = section_of(brief.render(old), "domains")
    assert 'class="org"' not in sec and names_in(sec) == IN_ORDER  # flat, still in the one order
    doc = strip_round12(json.loads((sample_run / "next_steps.json").read_text(encoding="utf-8")))
    page = brief.render(doc)
    assert 'class="org"' not in page and 'class="org-head"' not in page
    owners = section_of(page, "owners")
    hooks = re.findall(r'<span class="hook">([^<]+)</span>', owners)
    assert sorted(hooks) == sorted(brief.esc(i["hook"]) for g in doc["actions_by_owner"] for i in g["items"])
    # no plan: the DNS changes section is there and says so
    dns = section_of(page, "dns")
    assert "<h2>DNS changes</h2>" in dns and brief.NOT_IN_RUN in dns and "card" not in dns
    assert brief.NOT_IN_RUN in section_of(brief.render(doc, {"changes": [], "holds": []}), "dns")


def test_a_document_with_empty_sections_says_not_in_this_run_in_each():
    doc = {"date": "2026-10-13", "org_domain": "example.com", "one_liner": "", "stand": {}, "next_step": None,
           "per_domain": [], "failing": {}, "actions_by_owner": [], "ask": "", "open_questions": [], "glossary": {},
           "sources": {}}
    page = brief.render(doc)
    for sid in ("summary",) + tuple(s for s, _ in brief.SECTIONS):
        assert brief.NOT_IN_RUN in section_of(page, sid), sid
    assert page.count(brief.NOT_IN_RUN) == 1 + len(brief.SECTIONS)
    assert "<title>example.com DMARC brief 2026-10-13</title>" in page
    bare = brief.render({})  # nothing at all: still a page, never a traceback
    assert "<title>DMARC brief</title>" in bare and bare.count(brief.NOT_IN_RUN) == 1 + len(brief.SECTIONS)


def test_the_style_takes_every_color_from_the_design_tokens():
    css = brief.CSS
    assert css.startswith("/* Layout: one reading column read like a change-control sheet")
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    for token in ("--bg: #f3f5f8;", "--surface: #ffffff;", "--ink: #16202b;", "--accent: #1b5a83;", "--radius: 6px;",
                  "--font-mono: ui-monospace,"):
        assert token in root, token
    assert '@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {' in css
    dark = css.split('@media (prefers-color-scheme: dark)', 1)[1].split("} }", 1)[0].split("{\n", 1)[1]
    assert ":root[data-theme=\"dark\"] {\n" + dark in css  # the same dark values, for a host that sets the theme
    assert "--bg: #0e131a;" in dark and "color-scheme: dark" in dark
    printed = css.split("@media print { ", 1)[1].split("} }", 1)[0]
    assert "--bg: #f3f5f8;" in printed and "color-scheme: light" in printed
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", brief.COMPONENTS)  # no literal color in a component
    for rule in ("repeat(auto-fit, minmax(12rem, 1fr))", "overflow-x: auto", "overflow-wrap: anywhere",
                 "font-variant-numeric: tabular-nums", "text-wrap: balance", "break-inside: avoid", "max-width: 72rem",
                 "padding-inline: clamp(16px"):
        assert rule in css, rule
    assert "box-shadow" not in css and "gradient" not in css and "url(" not in css


# ------------------------------------------------------------------ B4: the checker

def check(path, run):
    return run_cli("scripts/check_doc.py", str(path), "--run", str(run))


def test_check_doc_passes_the_runs_own_documents(sample_run, quiet_run):
    for run in (sample_run, quiet_run):
        for name in ("next_steps.md", "brief.html"):
            p = check(run / name, run)
            assert p.returncode == 0, (run, name, p.stdout, p.stderr)
            assert p.stdout.startswith("clean")


@pytest.mark.parametrize("line, text, token, why", [
    ("zebra saw 4242 more failures", "4242", "4242", "number not in the run's files"),
    ("zebra: apply P-77 first", "P-77", "P-77", "plan id not in plan.json"),
    ("zebra: see DMARC-999", "DMARC-999", "DMARC-999", "finding id not in report.json or report.md"),
    ("zebra: move example.com to p=reject now", "p=reject", "p=reject", "policy value the run's files never write"),
    ("zebra " + EM + " an em dash", EM, "U+2014", "an em dash: the voice rules forbid it, use a hyphen"),
])
def test_check_doc_names_what_the_run_does_not_carry(quiet_run, tmp_path, line, text, token, why):
    files = {p.name: p.read_text(encoding="utf-8") for p in quiet_run.iterdir() if p.is_file()}
    md = files["next_steps.md"]
    if token == "p=reject":
        # the run never states it; report.md names it only in the explanation it prints on every run
        assert "aligned-DKIM evidence (needed before p=reject)" in files["report.md"]
        assert not any(re.search(r"(?<![a-z])p=reject", t) for n, t in files.items() if n not in ("report.md",
                                                                                                   "report.json"))
    else:
        assert not any(text in t for t in files.values())
    copy = tmp_path / "polished.md"
    copy.write_text(md + "\n" + line + "\n", encoding="utf-8")
    p = check(copy, quiet_run)
    assert p.returncode == 1, p.stdout
    n = len((md + "\n" + line).splitlines())
    assert p.stdout.splitlines() == ["line %d: %s: %s" % (n, token, why)]
    assert "zebra" not in p.stdout + p.stderr  # never the file's other content


def test_check_doc_names_every_problem_in_one_copy_and_reads_html_as_text(quiet_run, tmp_path):
    md = (quiet_run / "next_steps.md").read_text(encoding="utf-8")
    copy = tmp_path / "polished.md"
    copy.write_text(md + "\nWe saw 4242 failures; apply P-77 (DMARC-999) and move to p=reject " + EM + " really" + chr(0x2026)
                    + " " + chr(0x201C) + "done" + chr(0x201D) + chr(0xA0) + "now\n", encoding="utf-8")
    p = check(copy, quiet_run)
    assert p.returncode == 1
    tokens = [l.split(": ")[1] for l in p.stdout.splitlines()]
    assert tokens == ["4242", "P-77", "DMARC-999", "p=reject", "U+2014", "U+2026", "U+201C", "U+201D", "U+00A0"]
    # an .html copy is read as its text: the style's numbers are not the document's, an invented one in a cell is
    page = (quiet_run / "brief.html").read_text(encoding="utf-8")
    bad = tmp_path / "copy.html"
    bad.write_text(page.replace("</main>", "<p>4242 &mdash; invented</p>\n</main>"), encoding="utf-8")
    p = check(bad, quiet_run)
    assert p.returncode == 1
    n = page[:page.index("</main>")].count("\n") + 1
    assert p.stdout.splitlines() == ["line %d: 4242: number not in the run's files" % n,
                                     "line %d: U+2014: an em dash: the voice rules forbid it, use a hyphen" % n]


def test_check_doc_usage_errors_exit_2(quiet_run, tmp_path):
    p = check(tmp_path / "missing.md", quiet_run)
    assert p.returncode == 2 and "does not exist" in p.stderr and not p.stdout
    (tmp_path / "copy.md").write_text("21 messages\n", encoding="utf-8")
    p = check(tmp_path / "copy.md", tmp_path / "no-run-here")
    assert p.returncode == 2 and "holds none of the run's files" in p.stderr


# ------------------------------------------------------------------ B3: the skill

def test_the_skill_is_discoverable_short_ascii_and_names_only_real_paths():
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, "SKILL.md opens with its frontmatter"
    fields = {}
    for line in m.group(1).splitlines():
        key, sep, value = line.partition(":")
        assert sep, line
        fields[key.strip()] = value.strip()
    assert set(fields) == {"name", "description"}
    assert fields["name"] == SKILL.name == "dmarc-status-brief"
    assert 0 < len(fields["description"]) < 1000
    for word in ("status doc", "meeting doc", "brief", "leadership update", "owner messages", "DNS change ticket",
                 "organized"):
        assert word in fields["description"], word
    assert len(text.splitlines()) < 200
    reference = (SKILL / "reference.md").read_text(encoding="utf-8")
    for doc in (text, reference):
        assert doc.isascii() and "\\" not in doc  # plain ASCII, POSIX paths
    # every repo path it names exists (what a run writes under audit-out/ is made by the run, never shipped)
    paths = set(re.findall(r"(?<![\w/.-])((?:src|scripts|docs|samples|queries|tests|\.claude)/[\w./-]*[\w/]|"
                           r"AGENTS\.md|CLAUDE\.md|README\.md)", text + reference))
    assert paths >= {"AGENTS.md", "src/brief.py", "src/collect.py", "scripts/check_doc.py",
                     "docs/templates/next-steps.md", ".claude/skills/dmarc-status-brief/reference.md"}
    for p in paths:
        assert (ROOT / p).exists(), p
    # the ground rules by pointer, the run, the render, the polish folder and the check, in that order
    steps = ["AGENTS.md", "Rule 13", "Rule 12", "Rule 11", "Rule 3", "maillog.csv", "census.json", "## 2. Find the run",
             "python src/collect.py", "python src/brief.py audit-out/latest", "audit-out/latest/polished/",
             "python scripts/check_doc.py audit-out/latest/polished/<file> --run audit-out/latest", "## 6. Other formats",
             "## 7. Voice"]
    at = 0
    for s in steps:
        at = text.find(s, at)
        assert at >= 0, s
