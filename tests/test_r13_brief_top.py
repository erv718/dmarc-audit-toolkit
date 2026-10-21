"""Round 13, T-02: the status band in brief.html.

The page leads with next_steps.json's top under a slim masthead: the eyebrow counts the organizations and domains
and says how far the evidence reaches (old evidence in the warn color), the band answers Protected?, Most critical,
Your call (each plan id a tag linked to its record card), Since last run and Not in this data, and Contents follows
it. The sources and the verify.md pointer move to the footer, and the one-liner sits folded under The next step. A
document without the band renders the page it had. Every string from the data goes through the page's escaping and
isolation helpers. Synthetic data, offline."""

import html
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

import audit
import brief
import next_steps
import r13_fixtures as F

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_doc  # noqa: E402

RLO = chr(0x202E)  # a right-to-left override, spelled as a number so this file stays ASCII


class Tags(HTMLParser):
    """Every start tag of a page with its attributes, as a browser reads them."""

    def __init__(self):
        super().__init__()
        self.seen = []

    def handle_starttag(self, tag, attrs):
        self.seen.append((tag, attrs))


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_brief_estate"))


def band_of(page):
    return page[page.index('<section id="now"'):page.index("</section>", page.index('<section id="now"'))]


def test_the_band_comes_first_and_the_masthead_is_slim(estate):
    doc, plan = estate["doc"], estate["plan"]
    page = brief.render(doc, plan)
    ids = re.findall(r'\sid="([^"]+)"', page)
    assert [i for i in ids if not i.startswith("rec-")] == list(brief.SECTION_IDS)
    assert page.index('<section id="now" class="now"') < page.index('<nav id="contents"')
    top = page[page.index('<div id="top"'):page.index("</div>", page.index('<div id="top"'))]
    assert 'class="sources"' not in top and 'class="audience"' not in top
    assert ('<p class="eyebrow"><span>DMARC rollout</span> <span class="mono">2026-10-13</span> <span class="mono '
            'org">5 organizations, 9 domains</span> <span class="mono org">evidence to <span class="d">2026-10-08</span>'
            '</span></p>') in top
    assert '<p class="reading">%s</p>' % brief.READING_LINE in top
    assert "<title>DMARC brief 2026-10-13: 5 organizations, 9 domains</title>" in page
    band = band_of(page)
    assert '<p class="headline">%s</p>' % brief.prose(doc["top"]["headline"]) in band
    assert re.findall(r"<dt>([^<]+)</dt>", band) == ["Protected?", "Most critical", "Your call", "Since last run",
                                                    "Not in this data"]
    # the strip: one line per organization, its badge a pill of the fixed set, a delivered lure marked
    items = re.findall(r"<li( class=\"t1\")?><span class=\"pill (\w+)\">([^<]+)</span>", band)
    assert items == [(' class="t1"', "bad", "urgent"), (' class="t1"', "bad", "urgent"), ("", "bad", "reports only"),
                     ("", "bad", "no record"), ("", "bad", "no record")]
    assert '<span class="below">(<bdi>+4 names below it that only report</bdi>)</span>' in band
    # Your call: each id a tag linked to its card, its host name in the title
    places = brief.card_places(plan, "example.com")
    assert '<a class="tag" href="#rec-%d" title="_dmarc.e.example.com">P-03</a>' % places["P-03"] in band
    assert 'id="rec-%d"' % places["P-03"] in page and "Nothing can go out unchecked" in band
    assert '<div class="answer quiet"><dt>Not in this data</dt><dd><bdi>Bounces and lost mail (NDRs): use message trace' \
           '</bdi>.</dd></div>' in band
    # the one-liner folded under The next step; the sources and the pointer in the footer
    step = page[page.index('<section id="next-step"'):]
    step = step[:step.index("</section>")]
    assert ('<details class="para"><summary>The status in one paragraph</summary><p>%s</p></details>'
            % brief.prose(doc["one_liner"])) in step
    assert 'id="summary"' not in page and 'class="lede"' not in page
    foot = page[page.index('<footer id="footer"'):]
    assert "<p>%s</p>" % brief.prose(next_steps.sources_text(doc)) in foot
    assert "<p>%s</p>" % html.escape(brief.VERIFY_LINE, quote=True) in foot


def test_old_evidence_is_said_in_the_eyebrow_and_a_custom_audience_replaces_the_reading_line(estate):
    doc = json.loads(json.dumps(estate["doc"]))
    doc["top"]["stale"] = 48
    doc["sources"]["audience"] = "For the board"
    page = brief.render(doc, estate["plan"])
    top = page[page.index('<div id="top"'):page.index("</div>", page.index('<div id="top"'))]
    assert '<span class="pill warn">evidence is 48 days old</span>' in top
    assert '<p class="audience"><bdi>For the board</bdi>.</p>' in top and 'class="reading"' not in top
    # one organization: the page keeps its title
    doc["top"]["orgs"] = 1
    assert "<title>example.com DMARC brief 2026-10-13</title>" in brief.render(doc)


def test_the_page_stays_self_contained_and_every_string_from_the_data_is_escaped(estate):
    doc = json.loads(json.dumps(estate["doc"]))
    e = doc["top"]["domains"][0]
    e["finding_parts"] = [["text", "Spoofed mail reached inboxes - 7 as "], ["addr", "ceo" + RLO + "@example.com"],
                          ["text", " "], ["subject", "Urgent " + RLO + "<script>alert(1)</script> wire"]]
    e["org"] = "example" + RLO + ".com"
    doc["top"]["headline"] = "Partly: <img src=x onerror=alert(1)> " + RLO
    doc["top"]["changed"]["text"] = "Since 2026-10-06: new - x" + RLO + "@example.com x3."
    page = brief.render(doc, estate["plan"])
    band = band_of(page)
    assert '(the sender&#x27;s subject: &quot;<bdi>Urgent [U+202E]&lt;script&gt;alert(1)&lt;/script&gt; wire</bdi>&quot;)' \
           in band
    assert '<span class="d">ceo[U+202E]@example.com</span>' in band  # an address: one piece, the mark shown
    assert "<b class=\"w\">example[U+202E].</b>" in band and "&lt;img src=x onerror=alert(1)&gt; [U+202E]" in band
    assert "x[U+202E]@example.com" in band and RLO not in page
    assert '<meta http-equiv="Content-Security-Policy" content="%s">' % brief.CSP in page
    assert "<script" not in page.lower() and "http://" not in page and "https://" not in page
    tags = Tags()
    tags.feed(page)
    assert not any(name.startswith("on") for _, attrs in tags.seen for name, _ in attrs)  # text, never markup
    assert all(h.startswith("#") for h in re.findall(r'href="([^"]+)"', page))
    style = page.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "url(" not in style and "@import" not in style and page.isascii()


# what b41c326 rendered for a document without the band: the masthead, the contents and the lede, byte for byte
OLD_LEAD = (
    '<div id="top" class="masthead">\n<p class="eyebrow"><span>DMARC rollout</span><span class="mono">2026-10-13</span>'
    '<span class="mono org">example.com</span></p>\n<h1>Status and next steps</h1>\n<p class="audience"><bdi>For the '
    'people who own our email domains and sending systems</bdi>.</p>\n<p class="sources">Sources: audit report '
    'generated <span class="d">2026-10-13</span> 06:00 UTC (a mail log).</p>\n<p class="sources">To check any number '
    'or record here yourself, follow verify.md next to this file: the lookup, query or command for every finding and '
    'every plan row, with the value to expect.</p>\n</div>\n<nav id="contents" class="toc" aria-label="Contents"><p '
    'class="eyebrow">Contents</p><ol><li><a href="#stand">Where we stand</a></li><li><a href="#next-step">The next '
    'step</a></li><li><a href="#domains">Per domain</a></li><li><a href="#failing">What is failing</a></li><li><a '
    'href="#owners">What happens next, by owner</a></li><li><a href="#ask">The ask</a></li><li><a href="#dns">DNS '
    'changes</a></li><li><a href="#questions">Open questions</a></li><li><a href="#glossary">Glossary</a></li></ol>'
    '</nav>\n<section id="summary" class="lede" aria-label="In one line"><p><span class="d">example.com</span> is at '
    'p=none. 12 messages failed.</p></section>\n')


def test_a_document_without_the_band_renders_the_page_it_had(estate):
    doc = {"date": "2026-10-13", "org_domain": "example.com", "one_liner": "example.com is at p=none. 12 messages failed.",
           "sources": {"audience": next_steps.DEFAULT_AUDIENCE,
                       "audience_line": next_steps.DEFAULT_AUDIENCE + ". Sources: audit report generated 2026-10-13 "
                                                                      "06:00 UTC (a mail log)."},
           "stand": {"lines": []}, "per_domain": [], "open_questions": []}
    page = brief.render(doc)
    assert page[page.index('<div id="top"'):page.index('<section id="stand"')] == OLD_LEAD
    assert re.findall(r'\sid="([^"]+)"', page) == list(brief.OLD_SECTION_IDS)
    assert "<title>example.com DMARC brief 2026-10-13</title>" in page
    # the same for a whole document whose band was not built (top: null)
    old = dict(json.loads(json.dumps(estate["doc"])), top=None)
    page = brief.render(old, estate["plan"])
    assert '<section id="now"' not in page and '<section id="summary" class="lede"' in page
    assert page.count('class="sources"') == 2 and "<details" not in page


def test_check_doc_reads_the_estates_brief_clean(estate, tmp_path):
    rep = dict(estate["report"], findings=audit.flatten_findings(estate["report"]))
    (tmp_path / "report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    (tmp_path / "plan.json").write_text(json.dumps(estate["plan"], indent=1), encoding="utf-8")
    (tmp_path / "next_steps.json").write_text(json.dumps(estate["doc"], indent=1), encoding="utf-8")
    (tmp_path / "next_steps.md").write_text(next_steps.render_md(estate["doc"]), encoding="utf-8")
    page = brief.render(estate["doc"], estate["plan"])
    (tmp_path / "brief.html").write_text(page, encoding="utf-8")
    # the page as a reader's copy: the band's every figure, id and date is the run's (its eyebrow's parts read apart)
    text = check_doc.html_text(page)
    assert "DMARC rollout 2026-10-13 5 organizations, 9 domains evidence to 2026-10-08" in text
    assert "Partly: 2 of 9 domains block spoofed mail." in text and "Not in this data" in text
    assert check_doc.main([str(tmp_path / "brief.html"), "--run", str(tmp_path)]) == 0


def test_the_band_reads_on_a_phone_and_holds_together_on_paper():
    css = brief.CSS
    phone = css.split("@media (max-width: 40rem) {\n", 1)[1].split("\n}\n", 1)[0]
    assert ".answer { grid-template-columns: minmax(0, 1fr); }" in phone  # labels above their text
    assert ".strip li { grid-template-columns: minmax(0, 1fr); }" in phone  # badge, name, text on separate lines
    assert ".strip li.t1 { border-left: 3px solid var(--bad);" in css
    assert ".masthead.slim h1 { font-size: 1.5rem; }" in css
    assert ".answer { display: grid; grid-template-columns: 8.5rem minmax(0, 1fr);" in css
    printed = css.split("@media print {\n", 1)[1]
    assert ".now { break-inside: avoid; }" in printed or ", .now { break-inside: avoid; }" in printed
