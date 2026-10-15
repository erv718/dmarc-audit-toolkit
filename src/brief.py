#!/usr/bin/env python3
"""The status brief: the run's status document as one designed HTML page.

brief.html is next_steps.json (src/next_steps.py's document, as data) and,
when the run has one, plan.json (src/plan.py's records), laid out for the
people who read it: domain owners, IT leadership and whoever publishes DNS.
It says what next_steps.md says, in the generator's words - every number,
verdict, policy value, plan id and finding id is copied from the two files,
and no AI writes any of it (AGENTS.md rule 13) - and adds the plan's records
as cards a DNS change ticket can be built from. collect.py writes it into
every run folder; this command rebuilds it from any run's files:

  python src/brief.py audit-out/latest
  python src/brief.py audit-out/latest --out brief-copy.html
  python src/brief.py audit-out/latest --fragment --out brief-body.html   # title, style and body content only

A browser prints it to PDF (A4 or Letter, light palette). The page is one
self-contained file: no script, no font, no image, no link out, and a
Content-Security-Policy that forbids them anyway. Part of the data is
written by strangers (spoofed subject lines, display names, sender
addresses), so every string from either file is HTML-escaped, and the only
marks honoured inside one are the generator's own **bold** and `code`,
converted after escaping. The same inputs give the same bytes. Every list of
domains follows the run's one order (audit.domain_key): the headline
organization (next_steps.json org_domain) first, then each organization by
name, its organizational domain first and the names below it by name.

Relative paths resolve from the repo root, as in every tool here. Exit
codes: 0 written, 2 usage or input error. Never a traceback.
"""

import argparse
import html
import itertools
import json
import re
import sys
from pathlib import Path

import audit  # the one domain order (domain_key) every list of names follows
import next_steps  # the document's own words and thresholds, so the page says what next_steps.md says
import plan as plan_mod  # the plan's priority and kind words

ROOT = Path(__file__).resolve().parent.parent
NOT_IN_RUN = "Not in this run."
# the page's sections, in order, with the titles the table of contents links: (fixed id, title)
SECTIONS = (("stand", "Where we stand"), ("next-step", "The next step"), ("domains", "Per domain"),
            ("failing", "What is failing"), ("owners", "What happens next, by owner"), ("ask", "The ask"),
            ("dns", "DNS changes"), ("questions", "Open questions"), ("glossary", "Glossary"))
# every id on the page, in page order: the masthead, the contents and the one-liner, the sections, the footer
SECTION_IDS = ("top", "contents", "summary") + tuple(sid for sid, _ in SECTIONS) + ("footer",)
VERIFY_LINE = ("To check any number or record here yourself, follow verify.md next to this file: the lookup, query "
               "or command for every finding and every plan row, with the value to expect.")
CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
# the gate's verdict as a pill: (class, word)
GATE_PILLS = {"go": ("ok", "go"), "no_go": ("warn", "not yet"), "insufficient_data": ("info", "needs data")}
NOT_CHECKED = ("info", "not checked")
# the open questions' kinds in the order the reader takes them, in plain words; any other kind follows by name
QUESTION_KINDS = tuple(next_steps.QUESTION_KINDS.items())  # next_steps.md's own words for them
# an owner's items by kind: the zero-risk records first, then the other plan rows (DNS changes) in plan order,
# then sender fixes, overrides, outside and unknown sources, other findings; anything else last
ACTION_RANK = {"p1summary": 0, "p1record": 0, "dns": 1, "sender": 2, "override": 3, "spoof": 4, "stream": 4,
               "spf_only": 4, "outside": 4, "unknown": 4, "finding": 5}
# the What is failing blocks the tables replace: the line that opens each in next_steps.md, and its data
FAILING_BLOCKS = (("By envelope domain (", "by_envelope"), ("By sender address (", "by_sender"),
                  ("From the outside (aggregate reports; these counts", "outside"))
SUBJECT_MAX = 100  # characters of a subject shown in a table cell; the rest is in next_steps.json

# The design plan: every color and font on the page comes from these tokens, light by default, dark when the
# reader's system asks for it (or a host sets data-theme), and light again on paper.
LIGHT = (("--bg", "#f3f5f8"), ("--surface", "#ffffff"), ("--sunken", "#eaeef3"), ("--ink", "#16202b"),
         ("--muted", "#566273"), ("--line", "#d7dde5"), ("--accent", "#1b5a83"),
         ("--ok", "#1f6f45"), ("--ok-bg", "#e1f1e7"), ("--warn", "#8f5600"), ("--warn-bg", "#faedd5"),
         ("--bad", "#a2301d"), ("--bad-bg", "#f8e1dc"), ("--info", "#44546a"), ("--info-bg", "#e6eaf0"))
DARK = (("--bg", "#0e131a"), ("--surface", "#151c25"), ("--sunken", "#1b2430"), ("--ink", "#e5eaf1"),
        ("--muted", "#9aa5b5"), ("--line", "#2a3441"), ("--accent", "#72afdb"),
        ("--ok", "#63c48f"), ("--ok-bg", "#143322"), ("--warn", "#e3a54a"), ("--warn-bg", "#3a2a0f"),
        ("--bad", "#f08473"), ("--bad-bg", "#3d1913"), ("--info", "#a9b6c8"), ("--info-bg", "#222c39"))
FONTS = ('  --font-body: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;\n'
         '  --font-mono: ui-monospace, "Cascadia Mono", "Cascadia Code", Consolas, "SFMono-Regular", Menlo, '
         'monospace;\n  --radius: 6px;\n')


def _tokens(pairs):
    """A token block's declarations, a few to a line."""
    decls = ["%s: %s;" % kv for kv in pairs]
    return "".join("  %s\n" % " ".join(decls[i:i + 5]) for i in range(0, len(decls), 5))


COMPONENTS = """\
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body { margin: 0; font-size: 1rem; line-height: 1.55; overflow-wrap: break-word; }
h1, h2, h3, h4, p, ol, ul, dl, dd, pre { margin: 0; }
h1, h2, h3, h4 { line-height: 1.25; text-wrap: balance; break-after: avoid; }
h1 { font-size: 2rem; font-weight: 650; letter-spacing: -0.01em; }
h2 { font-size: 1.5rem; font-weight: 600; }
h3 { font-size: 1.125rem; font-weight: 600; }
h4 { font-size: 1rem; font-weight: 600; }
a { color: var(--accent); text-underline-offset: 0.15em; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 2px; }
code, pre, .mono { font-family: var(--font-mono); }
code { font-size: 0.875em; overflow-wrap: anywhere; }
strong { font-weight: 650; }
.brief { max-width: 72rem; margin-inline: auto; padding-inline: clamp(16px, 4vw, 48px);
  padding-block: 2.5rem 4rem; display: flex; flex-direction: column; gap: 2.25rem; }
.masthead { display: flex; flex-direction: column; gap: 0.6rem; }
.eyebrow, .label, .k { font-family: var(--font-mono); font-size: 0.78rem; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--muted); }
.eyebrow { display: flex; flex-wrap: wrap; gap: 0.25rem 1.25rem; }
.eyebrow .org { text-transform: none; letter-spacing: 0.02em; color: var(--ink); }
.audience { font-size: 1.125rem; max-width: 70ch; }
.sources { font-size: 0.875rem; color: var(--muted); max-width: 70ch; }
.toc { display: flex; flex-direction: column; gap: 0.4rem; }
.toc ol { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.3rem 1.25rem; font-size: 0.875rem; }
.lede { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 1.1rem 1.25rem; break-inside: avoid; }
.lede p { font-size: 1.125rem; max-width: 70ch; }
.section { display: flex; flex-direction: column; gap: 1rem; border-top: 1px solid var(--line); padding-top: 1.5rem; }
.section-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 1rem; }
.meta { font-family: var(--font-mono); font-size: 0.78rem; color: var(--muted); }
.section p, .section li { max-width: 70ch; }
.group { display: flex; flex-direction: column; gap: 0.6rem; }
.lines { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 0.45rem; }
.lines > li { position: relative; padding-left: 1rem; }
.lines > li::before { content: ""; position: absolute; left: 0.2rem; top: 0.62em; width: 0.34rem; height: 0.34rem;
  border: 0.17rem solid var(--muted); border-radius: 50%; }
.note, .why, .empty, .muted { color: var(--muted); }
.note { font-size: 0.875rem; }
.empty { font-style: italic; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: 0.75rem; }
.tile { min-width: 0; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 0.85rem 1rem; display: flex; flex-direction: column; gap: 0.3rem; break-inside: avoid; }
.figure { font-size: 2rem; font-weight: 650; line-height: 1.15; font-variant-numeric: tabular-nums; }
.figure .side { font-size: 0.875rem; font-weight: 400; color: var(--muted); }
.figure.words { font-size: 1.125rem; line-height: 2.05; }
.figure.na { font-size: 1.125rem; line-height: 2.05; font-weight: 400; color: var(--muted); }
.caption { font-size: 0.875rem; color: var(--muted); font-variant-numeric: tabular-nums; }
.pill { display: inline-block; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.5;
  padding: 0 0.55rem; border: 1px solid currentColor; border-radius: 999px; white-space: nowrap; }
.pill.ok { color: var(--ok); background: var(--ok-bg); }
.pill.warn { color: var(--warn); background: var(--warn-bg); }
.pill.bad { color: var(--bad); background: var(--bad-bg); }
.pill.info { color: var(--info); background: var(--info-bg); }
.tag { display: inline-block; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.5;
  padding: 0 0.4rem; border: 1px solid var(--line); border-radius: 4px; color: var(--ink); white-space: nowrap; }
.step { display: flex; flex-direction: column; gap: 0.75rem; }
.step-label { font-size: 1.125rem; font-weight: 600; }
.verdict { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 0.6rem; }
.checklist { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
.checklist li { display: grid; grid-template-columns: 1rem minmax(0, 1fr); gap: 0.6rem; align-items: start; }
.box { width: 0.95rem; height: 0.95rem; margin-top: 0.3rem; border: 1.5px solid var(--muted); border-radius: 3px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th, td { text-align: left; vertical-align: top; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--line); }
thead th { font-size: 0.78rem; font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--muted);
  white-space: nowrap; }
tr { break-inside: avoid; }
tr.org th { background: var(--sunken); font-family: var(--font-mono); font-weight: 600; }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.name { font-family: var(--font-mono); overflow-wrap: anywhere; min-width: 12ch; }
td.name b, .card-head .name b { font-weight: 600; }
.apex { color: var(--muted); }
.rest { display: block; font-size: 0.78rem; color: var(--muted); }
.subject { display: block; }
.owner { display: flex; flex-direction: column; gap: 0.6rem; }
.owner > h3 { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.75rem; }
.channel { font-family: var(--font-mono); font-size: 0.78rem; font-weight: 400; color: var(--muted); }
.org-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.75rem; font-family: var(--font-mono);
  font-size: 0.875rem; font-weight: 600; background: var(--sunken); border-radius: 4px; padding: 0.3rem 0.6rem; }
.count, .sub { font-family: var(--font-body); font-size: 0.78rem; font-weight: 400; color: var(--muted);
  font-variant-numeric: tabular-nums; }
.hook { font-weight: 600; }
.ask { background: var(--sunken); border-radius: var(--radius); padding: 1rem 1.25rem; }
.cards { display: flex; flex-direction: column; gap: 0.75rem; }
.card { min-width: 0; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 1rem 1.1rem; display: flex; flex-direction: column; gap: 0.65rem; break-inside: avoid; }
.card-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.3rem 0.75rem; }
.card-head .name { font-family: var(--font-mono); overflow-wrap: anywhere; }
.fields { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 0.35rem 1rem; font-size: 0.875rem; }
.fields dt { color: var(--muted); }
.fields dd { min-width: 0; overflow-wrap: anywhere; }
pre.value { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 0.875rem; background: var(--sunken);
  border-radius: 4px; padding: 0.45rem 0.6rem; }
.zone { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.6rem; }
.glossary { display: flex; flex-direction: column; gap: 0.5rem; }
.term { display: grid; grid-template-columns: minmax(7rem, 11rem) minmax(0, 1fr); gap: 0.15rem 1.25rem; }
.term dt { font-weight: 600; }
.foot { display: flex; flex-direction: column; gap: 0.35rem; border-top: 1px solid var(--line); padding-top: 1rem;
  font-size: 0.78rem; color: var(--muted); }
@media (max-width: 40rem) { .term { grid-template-columns: minmax(0, 1fr); } }
@page { margin: 16mm 14mm; }
@media print {
  html { font-size: 11pt; }
  body { background: var(--surface); }
  .brief { max-width: none; padding: 0; gap: 1.5rem; }
  .tiles { grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); }
  .table-wrap { overflow: visible; }
  a { color: inherit; text-decoration: none; }
  .tile, .card, .lede, .ask, tr, .checklist li { break-inside: avoid; }
}
"""

CSS = ("/* Layout: one reading column read like a change-control sheet: verdict, figures, domains, actions,\n"
       "   then the records to publish. Mono carries every DNS name and record value. */\n"
       ":root {\n" + _tokens(LIGHT) + FONTS + "}\n"
       "@media (prefers-color-scheme: dark) { :root:not([data-theme=\"light\"]) {\n" + _tokens(DARK) +
       "  color-scheme: dark } }\n"
       ":root[data-theme=\"dark\"] {\n" + _tokens(DARK) + "  color-scheme: dark }\n"
       # on paper the light values win whatever the screen asked for: the dark rules above are as specific
       "@media print { :root, :root:not([data-theme=\"light\"]), :root[data-theme=\"dark\"] {\n" + _tokens(LIGHT) +
       "  color-scheme: light } }\n"
       "body { background: var(--bg); color: var(--ink); font-family: var(--font-body); }\n" + COMPONENTS)


class BriefError(Exception):
    """An input the brief cannot be built from; the CLI turns it into exit 2."""


# ------------------------------------------------------------------ the data, read defensively

def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _text(value):
    """A string field as text; anything else (a number, None, a damaged value) as ''."""
    return value.strip() if isinstance(value, str) else ""


def _texts(value):
    """The non-empty strings of a list field, in order."""
    return [x for x in _list(value) if isinstance(x, str) and x.strip()]


def _num(value):
    """A count the document carries, else None: never a bool, never NaN or
    an infinity (JSON as Python reads it can spell both)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return None
    return None if value in (float("inf"), float("-inf")) else value


def _norm(name):
    return str(name or "").strip().lower().rstrip(".")


def _plural(n, one, many=None):
    return one if n == 1 else (many or one + "s")


def _counted(n, one, many=None):
    return "%s %s" % (n, _plural(n, one, many))


# ------------------------------------------------------------------ escaping: every string from the data goes here

def esc(value):
    """Data as HTML text: escaped, quotes included, so no string from either
    file can open a tag or leave an attribute."""
    return html.escape("" if value is None else str(value), quote=True)


CODE_RX = re.compile(r"`([^`\n]+)`")
BOLD_RX = re.compile(r"\*\*(.+?)\*\*")
KEPT_RX = re.compile(r"<c(\d+)>")  # a code span set aside; '<' never survives escaping, so data cannot spell it


def marks(value):
    """A data string as HTML: escaped first, then the generator's two marks
    turned into tags - **bold** and `code`, nothing else. The code spans are
    set aside before the bold ones are read, so the two never interleave."""
    text = esc(value)
    codes = []

    def keep(m):
        codes.append("<code>%s</code>" % m.group(1))
        return "<c%d>" % (len(codes) - 1)
    text = CODE_RX.sub(keep, text)
    text = BOLD_RX.sub(r"<strong>\1</strong>", text)
    return KEPT_RX.sub(lambda m: codes[int(m.group(1))], text)


# ------------------------------------------------------------------ the one domain order

def org_of(name):
    """The organization a name belongs to, as the run's one order groups it."""
    return audit.domain_key(name)[1]


def dkey(name, headline):
    """audit.domain_key: the headline's organization first, then each
    organization by name, its organizational domain first and the names
    below it by name."""
    return audit.domain_key(name, headline)


def name_html(name, org=None):
    """A domain as the tables and cards show it: a subdomain's own labels in
    the foreground and its organization's part muted
    (<b>pay</b><span class="apex">.example.com</span>); an apex in bold."""
    text = str(name or "").strip()
    base = text.rstrip(".")
    org = _norm(org) or org_of(base)
    suffix = "." + org
    if org and len(base) > len(suffix) and base[-len(suffix):].lower() == suffix:
        own = base[:-len(suffix)]
        return '<b>%s</b><span class="apex">%s</span>' % (esc(own), esc(text[len(own):]))
    return "<b>%s</b>" % esc(text)


# ------------------------------------------------------------------ small parts

def pill(cls, word):
    """A status pill; cls comes from a fixed set (ok, warn, bad, info), never from the data."""
    return '<span class="pill %s">%s</span>' % (cls if cls in ("ok", "warn", "bad", "info") else "info", esc(word))


def policy_class(text):
    """A policy's pill color: reject is where enforcement ends, quarantine on
    the way, none and no record are unprotected; anything else is plain."""
    t = str(text or "").strip().lower()
    if t.startswith("p=reject"):
        return "ok"
    if t.startswith("p=quarantine"):
        return "warn"
    if t.startswith("p=none") or t.startswith("no dmarc record"):
        return "bad"
    return "info"


def policy_cell(text):
    """The policy pill, with what follows the policy itself ('(inherited
    from example.com)') muted beneath it."""
    text = str(text or "").strip()
    if not text:
        return ""
    head, sep, rest = text.partition(" (")
    out = pill(policy_class(head), head)
    if sep:
        out += '<span class="rest">(%s</span>' % marks(rest)
    return out


def gate_cell(gate, gate_text):
    """The gate pill, with what the document adds to its word ('(for the
    weekly ramp this skips)', ', with a plan hold') muted beneath it."""
    gate = gate if isinstance(gate, str) and gate else "not checked"
    cls, word = GATE_PILLS.get(gate, NOT_CHECKED)
    said = _text(gate_text)
    lead = next_steps.GATE_WORDS.get(gate, gate)
    rest = said[len(lead):] if said.startswith(lead) else said
    rest = rest.strip().lstrip(",").strip()
    return pill(cls, word) + ('<span class="rest">%s</span>' % marks(rest) if rest else "")


def tag(text, cls="tag"):
    return '<span class="%s">%s</span>' % (cls, esc(text))


def id_tags(ids):
    """Plan ids as small tags after a step; more than three as one range."""
    ids = list(dict.fromkeys(i for i in ids if i))
    if not ids:
        return ""
    if len(ids) > 3:
        return " " + tag(next_steps.id_range(ids))
    return " " + " ".join(tag(i) for i in ids)


def checklist(texts):
    """Conditions as a checklist of unchecked boxes: the reader ticks them."""
    return '<ul class="checklist">%s</ul>' % "".join(
        '<li><span class="box" aria-hidden="true"></span><span>%s</span></li>' % marks(t) for t in texts)


def bullets(texts, cls="lines"):
    return '<ul class="%s">%s</ul>' % (cls, "".join("<li>%s</li>" % marks(t) for t in texts))


def block(title, inner):
    """A titled part of a section."""
    return '<div class="group"><h3>%s</h3>%s</div>' % (esc(title), inner)


def table(heads, body_rows, numeric=()):
    """A table inside its scrolling wrapper: heads as column titles (fixed
    text), body_rows as already-built <tr> or <tbody> markup."""
    th = "".join('<th scope="col"%s>%s</th>' % (' class="num"' if i in numeric else "", esc(h))
                 for i, h in enumerate(heads))
    body = "".join(body_rows)
    if not body.startswith("<tbody"):
        body = "<tbody>%s</tbody>" % body
    return '<div class="table-wrap"><table><thead><tr>%s</tr></thead>%s</table></div>' % (th, body)


def section(sid, title, parts, meta=""):
    """One section: its fixed id and title, then its parts - or Not in this
    run. when it has none, as next_steps.md says of a section with no
    evidence (a zero is not evidence of health)."""
    parts = [p for p in parts if p] or ['<p class="empty">%s</p>' % NOT_IN_RUN]
    head = "<h2>%s</h2>" % esc(title)
    if meta:
        head = '<div class="section-head">%s<p class="meta">%s</p></div>' % (head, meta)
    return '<section id="%s" class="section">\n%s\n%s\n</section>' % (sid, head, "\n".join(parts))


# ------------------------------------------------------------------ the sections

def masthead(doc):
    """The eyebrow (DMARC rollout, the date, the organization), the title,
    the audience line and the sources line - next_steps.md's audience line,
    split where its own first sentence ends - and the verify.md pointer."""
    src = _dict(doc.get("sources"))
    eyebrow = ["<span>DMARC rollout</span>"]
    for value, cls in ((_text(doc.get("date")), "mono"), (_text(doc.get("org_domain")), "mono org")):
        if value:
            eyebrow.append('<span class="%s">%s</span>' % (cls, esc(value)))
    audience = _text(src.get("audience")).rstrip(".")
    line = _text(src.get("audience_line"))
    sources = line[len(audience) + 1:].strip() if audience and line.startswith(audience + ".") else line
    parts = ['<p class="eyebrow">%s</p>' % "".join(eyebrow), "<h1>Status and next steps</h1>"]
    if audience:
        parts.append('<p class="audience">%s.</p>' % marks(audience))
    if sources:
        parts.append('<p class="sources">%s</p>' % marks(sources))
    parts.append('<p class="sources">%s</p>' % esc(VERIFY_LINE))
    return '<div id="top" class="masthead">\n%s\n</div>' % "\n".join(parts)


def contents():
    links = "".join('<li><a href="#%s">%s</a></li>' % (sid, esc(title)) for sid, title in SECTIONS)
    return ('<nav id="contents" class="toc" aria-label="Contents"><p class="eyebrow">Contents</p><ol>%s</ol></nav>'
            % links)


def lede(doc):
    """The one-liner, as the lede: policy today, who still fails, the next safe step."""
    text = _text(doc.get("one_liner"))
    inner = "<p>%s</p>" % marks(text) if text else '<p class="empty">%s</p>' % NOT_IN_RUN
    return '<section id="summary" class="lede" aria-label="In one line">%s</section>' % inner


def tile(label, figure, caption, side=""):
    """One KPI tile: the label above, the figure, a one-line caption below.
    A figure the run does not have says so in words, never as a zero."""
    if figure is None:
        fig = '<p class="figure na">not in this run</p>'
    elif isinstance(figure, str) and not re.match(r"^[+-]?\d", figure):
        fig = '<p class="figure words">%s</p>' % esc(figure)
    else:
        fig = '<p class="figure">%s%s</p>' % (esc(figure), (' <span class="side">%s</span>' % esc(side)) if side else "")
    return '<div class="tile"><p class="label">%s</p>%s<p class="caption">%s</p></div>' % (esc(label), fig, marks(caption))


def trend_tile(st):
    """The trend as next_steps.md's trend line computes it: the change in
    genuine failures, else in the pass rate, from the previous run's figures
    and this run's."""
    tr = st.get("trend")
    if not isinstance(tr, dict):
        return tile("Trend", "first run", "no trend yet")
    label = "Trend vs %s" % (_text(tr.get("label")) or "the previous run")
    gf, prev_gf = _num(st.get("genuine_failures")), _num(tr.get("previous_genuine_failures"))
    sb = _dict(st.get("spoofing_blocked"))
    pr, prev_pr = _num(sb.get("pass_rate")), _num(tr.get("previous_pass_rate"))
    if gf is not None and prev_gf is not None:
        return tile(label, "%+d" % (gf - prev_gf), "genuine failures, %d -> %d" % (prev_gf, gf))
    if pr is not None and prev_pr is not None:
        return tile(label, "%+.1f pts" % (100 * (pr - prev_pr)),
                    "pass rate, %.1f%% -> %.1f%%" % (100 * prev_pr, 100 * pr))
    why = _texts(tr.get("not_comparable"))
    return tile(label, "not comparable", why[0] if why else "the two runs share no failure count or pass rate")


def stand_tiles(st):
    """The four figures of Where we stand as tiles - genuine failures with
    the raw count beside them, delivered despite failing, what receivers
    rejected and quarantined, the trend - each label short enough to stay on
    one line, so the figures line up; none when the document carries none of
    them. The section's lines below say each figure in full."""
    if not any(k in st for k in ("genuine_failures", "delivered_despite_fail", "spoofing_blocked", "trend")):
        return ""
    tiles = []
    gf, raw = _num(st.get("genuine_failures")), _num(st.get("raw_failing_rows"))
    if gf is None:
        tiles.append(tile("Genuine failures", None, "no mail log was read"))
    else:
        # a log the row budget or the API cap cut holds only the rows kept: the tile says so, the line below says how
        gone = _num(st.get("genuine_failures_excepted"))
        cap = "no passing copy, in the rows the cut log kept" if st.get("truncation") else "messages with no passing copy"
        tiles.append(tile("Genuine failures", gf, cap + ("; %s formally excepted" % gone if gone else ""),
                          ("raw %s" % raw) if raw is not None else ""))
    ddf = _num(st.get("delivered_despite_fail"))
    tiles.append(tile("Delivered despite failing", ddf,
                      "reached a mailbox anyway" if ddf is not None else "no mail log was read"))
    sb = st.get("spoofing_blocked")
    if isinstance(sb, dict):
        rej, qua = _num(sb.get("rejected")) or 0, _num(sb.get("quarantined")) or 0
        msgs = _num(sb.get("messages"))
        tiles.append(tile("Rejected / quarantined", "%s / %s" % (rej, qua),
                          "by receivers, of %s" % _counted(msgs, "message") if msgs is not None else "by receivers"))
    else:
        tiles.append(tile("Rejected / quarantined", None, "no aggregate reports were read"))
    tiles.append(trend_tile(st))
    return '<div class="tiles">%s</div>' % "".join(tiles)


def stand_section(doc):
    """Where we stand: the figures as tiles, then every line of the section
    as next_steps.md writes it, the caveats with them."""
    st = _dict(doc.get("stand"))
    lines = _texts(st.get("lines"))
    for c in _texts(st.get("caveats")):  # an older document kept them apart from the lines
        if not any(c in line for line in lines):
            lines.append("**Caveat:** %s" % c)
    parts = [stand_tiles(st), bullets(lines) if lines else ""]
    window = _text(_dict(st.get("window")).get("text")) or "this run's window"
    meta = "%s, deduplicated" % esc(window) if any(parts) else ""
    return section("stand", "Where we stand", parts, meta)


def next_step_section(doc):
    """The organization's next step: its label and plan id, the gate's
    verdict, then what holds it - a plan step's prerequisites are the
    conditions that make it ready, a gate step's are what holds it - and the
    data an insufficient_data verdict asks for."""
    nxt = doc.get("next_step")
    if not isinstance(nxt, dict) or not _text(nxt.get("label")):
        return section("next-step", "The next step", [])
    ref = _text(nxt.get("ref"))
    cls, word = GATE_PILLS.get(_text(nxt.get("verdict")), NOT_CHECKED)
    prereqs = _texts(nxt.get("prerequisites"))
    holds = [h for h in _texts(nxt.get("holds")) if h not in prereqs]
    data = _texts(nxt.get("data"))
    gate_step = nxt.get("source") == "gate"
    parts = ['<p class="step-label">%s%s</p>' % (marks(nxt["label"]), (" " + tag(ref)) if ref else ""),
             '<p class="verdict"><span class="k">Gate</span>%s</p>' % pill(cls, word)]
    if _text(nxt.get("why")):
        parts.append('<p class="why">%s</p>' % marks(nxt["why"]))
    if data:
        parts.append(block("Needs more data", checklist(data)))
    if prereqs:
        parts.append(block("On hold while" if gate_step else "Ready when", checklist(prereqs)))
    if holds:  # the gate's blockers the plan row does not carry itself: observations, not boxes to tick
        parts.append(block("Also on hold while", bullets(holds)))
    org = _text(doc.get("org_domain"))
    meta = ("for %s" % esc(org)) if org else ""
    return section("next-step", "The next step", ['<div class="step">%s</div>' % "".join(parts)], meta)


def plan_owners(plan):
    """{plan id: the domain its row is for}, so a merged per-domain row's
    ids go back to the name each belongs to."""
    out = {}
    for c in _list(_dict(plan).get("changes")):
        if isinstance(c, dict) and _text(c.get("id")):
            out[c["id"].strip()] = _norm(c.get("domain"))
    return out


def domain_rows(doc, plan, head):
    """One entry per audited name, in domain order with the headline first:
    a merged row of next_steps.md (subdomains that share their status) is
    expanded into one row per name. Each name takes the plan ids the plan
    says are its own; an id the plan does not know (no plan.json beside the
    document) stays on every name of its row, as next_steps.md shows it.
    With "org" on the rows (next_steps.json from round 12 on) each entry
    carries its organization, for the group rows; without it, None."""
    rows = [r for r in _list(doc.get("per_domain")) if isinstance(r, dict)]
    grouped = any("org" in r for r in rows)
    owners = plan_owners(plan)
    out = []
    for r in rows:
        names = _texts(r.get("domains")) or ([r["domain"]] if _text(r.get("domain")) else [])
        ids = [i.strip() for i in _texts(r.get("plan_ids"))]
        for n in names:
            mine = [i for i in ids if i in owners and owners[i] == _norm(n)]
            loose = [i for i in ids if i not in owners]
            org = (_norm(r.get("org")) or org_of(n)) if grouped else None
            out.append({"name": n.strip(), "org": org, "row": r, "ids": mine + loose})
    out.sort(key=lambda e: ((dkey(e["org"], head),) if grouped else ()) + (dkey(e["name"], head), e["name"]))
    return out, grouped


def domain_row(e):
    r = e["row"]
    step = marks(r.get("next_step")) + id_tags(e["ids"])
    return ('<tr><td class="name">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
            % (name_html(e["name"], e["org"]), policy_cell(r.get("policy_today")),
               gate_cell(r.get("gate"), r.get("gate_text")), step, marks(_text(r.get("mailflow_text")) or "not measured")))


def domains_section(doc, plan, head):
    """Per domain: grouped by organization (headline first) when the rows
    say which, one row per name; then the mail-flow note and the gate's notes
    next_steps.md shows under its table."""
    entries, grouped = domain_rows(doc, plan, head)
    parts = []
    if entries:
        heads = ("Domain", "Policy", "Gate", "Next step", "Mail flow")
        if grouped:
            bodies = []
            for org, members in itertools.groupby(entries, key=lambda e: e["org"]):
                members = list(members)
                bodies.append('<tbody><tr class="org"><th colspan="5" scope="colgroup">%s <span class="count">%s'
                              '</span></th></tr>%s</tbody>'
                              % (esc(org), _counted(len(members), "domain"), "".join(domain_row(e) for e in members)))
            parts.append(table(heads, bodies))
        else:
            parts.append(table(heads, [domain_row(e) for e in entries]))
        note = _text(_dict(doc.get("mailflow")).get("note"))
        if note:
            parts.append('<p class="note">%s</p>' % marks(note))
    notes = [n for n in _list(doc.get("audit_notes")) if isinstance(n, dict) and _text(n.get("text"))]
    if notes:
        org = esc(_text(doc.get("org_domain")))
        if any(_text(n.get("holds")) for n in notes):
            lead = "From the audit on %s:" % org
            items = ["%s (%s)" % (marks(n["text"]), marks(_text(n.get("holds")) or "information; it holds nothing"))
                     for n in notes]
        else:
            lead = "From the audit on %s (information; it holds nothing):" % org
            items = [marks(n["text"]) for n in notes]
        parts.append('<div class="group"><p class="note">%s</p><ul class="lines note">%s</ul></div>'
                     % (lead, "".join("<li>%s</li>" % i for i in items)))
    return section("domains", "Per domain", parts)


def _label(e):
    return next_steps.LIKELY_WORDS.get(_text(e.get("likely")) or "unknown", "unclear")


def _headlines(entries):
    """next_steps.md's split: the busiest entries with at least HEADLINE_MIN
    messages are headlines (a few at most), the rest are notes."""
    head = [e for e in entries if (_num(e.get("count")) or 0) >= next_steps.HEADLINE_MIN][:next_steps.TOP_ENTRIES]
    return head, [e for e in entries if e not in head]


def _note_line(entries, cap=None):
    """The entries that are notes, not headlines, in next_steps.md's words
    ('name xN (label)', the first NOTES_CAP of them, then how many more);
    a damaged entry is shown as it is, never a reason to fail."""
    cap = next_steps.NOTES_CAP if cap is None else cap
    text = ", ".join("%s x%s (%s)" % (e.get("name"), _num(e.get("count")), _label(e)) for e in entries[:cap])
    if len(entries) > cap:
        text += " (+%d more in report.json)" % (len(entries) - cap)
    return text


def _subjects(e):
    out = []
    for s in _list(e.get("subjects"))[:2]:
        s = str(s)
        if len(s) > SUBJECT_MAX:  # cut at a word, so no number is left half shown
            s = (s[:SUBJECT_MAX].rsplit(" ", 1)[0] or s[:SUBJECT_MAX]) + "..."
        out.append('<span class="subject">"%s"</span>' % marks(s))
    return "".join(out)


def failing_tables(failing):
    """The headline entries of next_steps.md's What is failing lists as
    tables, each followed by its notes line (the entries under the headline
    threshold, as next_steps.md writes it)."""
    parts = []
    env = [e for e in _list(failing.get("by_envelope")) if isinstance(e, dict)]
    head, rest = _headlines(env)
    rows = []
    for e in head:
        senders = [s for s in _list(e.get("senders")) if isinstance(s, str)]
        n = _num(e.get("sender_count")) or len(senders)
        detail = []
        if n:
            detail.append(esc(_counted(n, "sender address", "sender addresses")))
        if senders:
            detail.append("such as %s" % esc(", ".join(senders[:2])))
        rows.append('<tr><td class="name">%s</td><td class="num">%s</td><td>%s</td><td>%s%s</td></tr>'
                    % (esc(e.get("name")), esc(_num(e.get("count"))), esc(_label(e)), "; ".join(detail), _subjects(e)))
    parts.append(failing_block("By envelope domain", "who actually handed the mail over", rows,
                               ("Envelope domain", "Messages", "Label", "Senders"), rest,
                               "Notes, not headlines (under %d each): " % next_steps.HEADLINE_MIN))
    snd = [e for e in _list(failing.get("by_sender")) if isinstance(e, dict)]
    head, rest = _headlines(snd)
    rows = ['<tr><td class="name">%s</td><td class="num">%s</td><td>%s</td><td>%s</td><td class="name">%s</td></tr>'
            % (esc(e.get("name")), esc(_num(e.get("count"))), esc(_label(e)), _subjects(e), esc(_text(e.get("envelope"))))
            for e in head]
    parts.append(failing_block("By sender address", "what the reader sees in From", rows,
                               ("Sender", "Messages", "Label", "Subjects", "Envelope"), rest,
                               "Notes, not headlines (under %d each): " % next_steps.HEADLINE_MIN))
    out = [e for e in _list(failing.get("outside")) if isinstance(e, dict)]
    head, rest = _headlines(out)
    rows = []
    for e in head:
        disp = ", ".join("%s %s" % (_num(v), k) for k, v in _dict(e.get("dispositions")).items() if _num(v))
        rows.append('<tr><td class="name">%s</td><td class="num">%s</td><td class="name">%s</td><td>%s</td><td>%s</td></tr>'
                    % (esc(e.get("name")), esc(_num(e.get("count"))),
                       esc(", ".join(str(h) for h in _list(e.get("header_from"))[:2]) or "?"), esc(_label(e)), esc(disp)))
    notes = ("Notes, not headlines: " + _note_line(rest, len(rest))) if rest else ""  # next_steps.md lists them all
    parts.append(failing_block("From the outside", "aggregate reports; these counts include forwarded copies and "
                               "cannot be deduplicated", rows, ("Source", "Failing", "As", "Label", "Receivers"),
                               [], "", notes))
    return [p for p in parts if p]


def failing_block(title, sub, rows, heads, rest, lead, notes=""):
    """One What is failing list: its title, the table of headline rows, the notes line."""
    if rest:
        notes = lead + _note_line(rest)
    if not rows and not notes:
        return ""
    inner = table(heads, rows, numeric=(1,)) if rows else ""
    if notes:
        inner += '<p class="note">%s</p>' % esc(notes)
    return '<div class="group"><h3>%s <span class="sub">%s</span></h3>%s</div>' % (esc(title), esc(sub), inner)


def failing_rest(failing):
    """What is failing's other sentences (formal exceptions, new senders, a
    log without verdicts, nothing failing), as next_steps.md writes them: its
    lines without the lists the tables carry. A list whose data the document
    lacks keeps its lines."""
    out, skipping = [], False
    for line in _list(failing.get("lines")):
        s = line.strip() if isinstance(line, str) else ""
        if not s:
            skipping = False
            continue
        block_key = next((key for title, key in FAILING_BLOCKS if s.startswith(title) and s.endswith(":")), None)
        if block_key is not None:
            skipping = isinstance(failing.get(block_key), list)
            if skipping:
                continue
        if skipping and (s.startswith("- **") or s.startswith("- Notes, not headlines")):
            continue
        out.append(s[2:] if s.startswith("- ") else s)
    return out


def failing_section(doc):
    failing = _dict(doc.get("failing"))
    parts = failing_tables(failing)
    rest = failing_rest(failing)
    if rest:
        parts.append(bullets(rest))
    notes = _texts(failing.get("notes"))
    if notes:
        parts.append('<div class="group"><p class="note">Notes:</p>%s</div>' % bullets(notes, "lines note"))
    return section("failing", "What is failing", parts)


def _action_key(item, idx, head):
    """An owner's items in the order the reader works them: by kind, a plan
    row by its plan order, then by the first domain it concerns, then as the
    document listed them."""
    kind = _text(item.get("kind"))
    order = 0
    if kind == "dns":
        m = re.match(r"^P-(\d+)$", _text(item.get("ref")))
        order = int(m.group(1)) if m else 0
    names = _texts(item.get("domains"))
    return (ACTION_RANK.get(kind, 6), order, dkey(names[0], head) if names else (), idx)


def action_item(item):
    ref = _text(item.get("ref"))
    return '<li><span class="hook">%s</span> %s%s</li>' % (marks(item.get("hook")), marks(item.get("action")),
                                                        (" " + tag(ref)) if ref else "")


def owner_group(g, head):
    """One owner with its channel and its items. Items that say which
    organization they concern (next_steps.json from round 12 on) are grouped
    by it when they span more than one: the headline's first, then each by
    name, the tenant-wide ones last."""
    items = [(i, it) for i, it in enumerate(_list(g.get("items"))) if isinstance(it, dict)]
    if not items:
        return ""
    title = '<h3>%s%s</h3>' % (marks(_text(g.get("owner")) or next_steps.UNASSIGNED),
                               (' <span class="channel">%s</span>' % esc(g["channel"])) if _text(g.get("channel")) else "")
    if any("org" in it for _, it in items):
        buckets = {}
        for i, it in items:
            buckets.setdefault(_norm(it.get("org")), []).append((i, it))
        orgs = sorted((o for o in buckets if o), key=lambda o: dkey(o, head)) + ([""] if "" in buckets else [])
        if len(orgs) > 1:
            body = []
            for o in orgs:
                members = sorted(buckets[o], key=lambda t: _action_key(t[1], t[0], head))
                body.append('<p class="org-head">%s <span class="count">%s</span></p><ul class="lines">%s</ul>'
                            % (esc(o) if o else "Tenant-wide", _counted(len(members), "item"),
                               "".join(action_item(it) for _, it in members)))
            return '<div class="owner">%s%s</div>' % (title, "".join(body))
    members = sorted(items, key=lambda t: _action_key(t[1], t[0], head))
    return '<div class="owner">%s<ul class="lines">%s</ul></div>' % (title, "".join(action_item(it) for _, it in members))


def owners_section(doc, head):
    parts = [owner_group(g, head) for g in _list(doc.get("actions_by_owner")) if isinstance(g, dict)]
    parts = [p for p in parts if p]
    failing = _dict(doc.get("failing"))
    if not parts and (failing.get("excepted") or failing.get("outside_excepted")):
        parts = ['<p class="empty">%s</p>' % NOT_IN_RUN,
                 '<p class="note">No plan changes, and every failure this run names is formally excepted in '
                 'audit.toml (What is failing lists them).</p>']
    return section("owners", "What happens next, by owner", parts)


def ask_section(doc):
    text = _text(doc.get("ask"))
    return section("ask", "The ask", ['<div class="ask"><p>%s</p></div>' % marks(text)] if text else [])


def _record_rank(c):
    """A domain's records in the order a publisher reads them: its _dmarc
    record first, then its own name (SPF), then _domainkey names, then the rest."""
    host, dom = _norm(c.get("hostname")), _norm(c.get("domain"))
    if host == "_dmarc." + dom:
        return 0
    if host == dom:
        return 1
    if "_domainkey" in host:
        return 2
    return 3


def _priority(c):
    p = c.get("priority")
    return p if isinstance(p, int) and not isinstance(p, bool) else None


def _row_key(c, idx, head):
    """The plan's rows by priority, then DNS host (unknown last), then zone,
    then domain - the zones and the domains in the one domain order, so a
    delegated zone sits right after its organization's own - then record."""
    p = _priority(c)
    host = _text(c.get("zone_host"))
    return ((0, p) if p is not None else (1, 0), (1, "") if host.lower() in ("", "unknown") else (0, host.lower()),
            dkey(_text(c.get("zone")) or _text(c.get("domain")), head), dkey(c.get("domain"), head),
            _record_rank(c), _norm(c.get("hostname")), idx)


def record_card(c, head):
    """One plan row as a record card: id, kind and domain; what it does in
    plain words; host name, type, value, current value, TTL and rollback;
    the prerequisites as a checklist; the why, muted."""
    kind = _text(c.get("kind"))
    rid = _text(c.get("id"))
    head_parts = [tag(rid, "tag rid") if rid else "", '<span class="k">%s</span>' % esc(plan_mod.KIND_LABEL.get(kind, kind)),
                  '<span class="name">%s</span>' % name_html(c.get("domain")),
                  "".join(" " + tag(f) for f in _texts(c.get("finding_ids")))]
    fields = (("Host name", '<span class="mono">%s</span>' % esc(c.get("hostname"))),
              ("Type", '<span class="mono">%s</span>' % esc(c.get("record"))),
              ("Value", '<pre class="value">%s</pre>' % esc(c.get("value"))),
              ("Current", '<span class="mono muted">%s</span>' % esc(c.get("current"))),
              ("TTL", '<span class="mono">%s</span>' % esc(c.get("ttl"))),
              ("Rollback", marks(c.get("rollback"))))
    parts = ['<div class="card-head">%s</div>' % "".join(p for p in head_parts if p)]
    if _text(c.get("human_summary")):
        parts.append("<p>%s</p>" % marks(c["human_summary"]))
    parts.append('<dl class="fields">%s</dl>' % "".join("<dt>%s</dt><dd>%s</dd>" % (esc(k), v) for k, v in fields))
    prereqs = _texts(c.get("prerequisites"))
    if prereqs:
        parts.append('<div class="group"><p class="k">Before applying</p>%s</div>' % checklist(prereqs))
    if _text(c.get("why")):
        parts.append('<p class="why">%s</p>' % marks(c["why"]))
    return '<article class="card">%s</article>' % "".join(parts)


def address_note(plan):
    """plan.md's warning about the report address new records carry, when it
    is a placeholder or one the run only derived."""
    rua = _text(plan.get("rua"))
    if plan.get("rua_is_placeholder"):
        return ('<p class="note"><strong>Set the reporting address.</strong> No existing record carried a rua, so new '
                'records use the placeholder <code>%s</code>; plan.md says how to re-run with a real one.</p>' % esc(rua))
    if plan.get("rua_derived"):
        return ('<p class="note"><strong>Check the reporting address.</strong> The run had no report address of its own, '
                'so new records use <code>%s</code>, the rua most existing records already use; plan.md says more.</p>'
                % esc(rua))
    return ""


def dns_section(plan, head):
    """DNS changes, from plan.json when the run has one: the holds first, as
    what to decide first, then one record card per row, grouped by priority
    (in plan.py's words), DNS host and zone, in domain order."""
    if not isinstance(plan, dict):
        return section("dns", "DNS changes", [])
    changes = [c for c in _list(plan.get("changes")) if isinstance(c, dict)]
    holds = [h for h in _list(plan.get("holds")) if isinstance(h, dict)]
    if not changes and not holds:
        return section("dns", "DNS changes", [])
    parts = [address_note(plan)]
    if holds:
        ordered = sorted(enumerate(holds), key=lambda t: (dkey(t[1].get("domain"), head), t[0]))
        parts.append(block("Decide first", '<ul class="lines">%s</ul>' % "".join(
            "<li>%s: %s</li>" % (name_html(h.get("domain")), marks(h.get("reason"))) for _, h in ordered)))
    rows = [c for _, c in sorted(enumerate(changes), key=lambda t: _row_key(t[1], t[0], head))]
    for prio, in_prio in itertools.groupby(rows, key=_priority):
        title = "Priority %s" % prio if prio is not None else "Priority not stated"
        words = plan_mod.PRIORITY_LABEL.get(prio, "")
        inner = []
        for host, in_host in itertools.groupby(in_prio, key=lambda c: _text(c.get("zone_host")) or "unknown"):
            zones = []
            for zone, in_zone in itertools.groupby(in_host, key=lambda c: _text(c.get("zone")) or org_of(c.get("domain"))):
                zones.append('<p class="zone"><span class="k">Zone</span><span class="mono">%s</span></p>'
                             '<div class="cards">%s</div>' % (esc(zone), "".join(record_card(c, head) for c in in_zone)))
            inner.append('<div class="group"><h4>DNS host: %s</h4>%s</div>' % (esc(host), "".join(zones)))
        parts.append('<div class="group"><h3>%s%s</h3>%s</div>'
                     % (esc(title), (' <span class="count">%s</span>' % esc(words)) if words else "", "".join(inner)))
    return section("dns", "DNS changes", parts)


def _question_key(q, idx, head, located):
    """Within a kind: by organization (the headline's first, a tenant-wide
    question last) and domain when the questions say which (round 12 on),
    then in the document's own order, as next_steps.md lists them; an
    older document's questions keep its order."""
    if not located:
        return (idx,)
    org = _norm(q.get("org"))
    names = _texts(q.get("domains"))
    return ((0, dkey(org, head)) if org else (1, ()), dkey(names[0], head) if names else (), idx)


def questions_section(doc, head):
    """Open questions, one group per kind with its count, in the order the
    reader takes them: blockers, prerequisites, holds, gaps, the unverified
    heuristics, the items with no owner, then any other kind by name."""
    qs = [q for q in _list(doc.get("open_questions")) if isinstance(q, dict) and _text(q.get("question"))]
    located = any("org" in q or "domains" in q for q in qs)
    words = dict(QUESTION_KINDS)
    known = [k for k, _ in QUESTION_KINDS]
    by_kind = {}
    for i, q in enumerate(qs):
        by_kind.setdefault(_text(q.get("kind")) or "other", []).append((i, q))
    kinds = [k for k in known if k in by_kind] + sorted(k for k in by_kind if k not in known)
    parts = []
    for k in kinds:
        members = sorted(by_kind[k], key=lambda t: _question_key(t[1], t[0], head, located))
        items = []
        for _, q in members:
            n = _num(q.get("count")) or 1
            items.append('<li>%s%s <span class="count">owner: %s</span></li>'
                         % (marks(q["question"]), (' <span class="count">x %s</span>' % n) if n > 1 else "",
                            esc(_text(q.get("owner")) or "unassigned")))
        title = words.get(k) or k.replace("_", " ").capitalize()
        parts.append('<div class="group"><h3>%s <span class="count">%s</span></h3><ul class="lines">%s</ul></div>'
                     % (esc(title), len(members), "".join(items)))
    return section("questions", "Open questions", parts)


def glossary_section(doc):
    terms = [(k, v) for k, v in _dict(doc.get("glossary")).items() if isinstance(v, str) and v.strip()]
    if not terms:
        return section("glossary", "Glossary", [])
    return section("glossary", "Glossary", ['<dl class="glossary">%s</dl>' % "".join(
        '<div class="term"><dt>%s</dt><dd>%s</dd></div>' % (esc(k), marks(v)) for k, v in terms)])


def footer(doc, with_plan=False):
    """The sources the document was built from, when the report was
    generated, and which version of the toolkit wrote it; with_plan says
    whether the page read plan.json too."""
    src = _dict(doc.get("sources"))
    facts = []
    when, tool = _text(src.get("report_generated_utc")), _text(src.get("report_tool"))
    if when:
        facts.append("audit report generated %s%s" % (when, (" by " + tool) if tool else ""))
    if src.get("plan") is True:
        facts.append("rollout plan (%s, %s)" % (_counted(_num(src.get("plan_changes")) or 0, "change"),
                                                _counted(_num(src.get("plan_holds")) or 0, "hold")))
    elif src.get("plan") is False:
        facts.append("no rollout plan")
    runs = _num(src.get("metrics_runs"))
    if runs is not None:
        facts.append("run history (%s)" % _counted(runs, "run"))
    if _text(src.get("previous_report")):
        facts.append("previous report %s" % src["previous_report"].strip())
    if _text(src.get("owners_file")):
        facts.append("owners file %s (%s)" % (src["owners_file"].strip(),
                                              _counted(_num(src.get("owner_patterns")) or 0, "pattern")))
    elif "owners_file" in src:
        facts.append("no owners file")
    made = _text(doc.get("tool")) or "next_steps.py"
    version = _text(doc.get("version"))
    lines = []
    if facts:
        lines.append("<p>Sources: %s.</p>" % esc("; ".join(facts)))
    lines.append("<p>Written by %s%s from the run's own data and laid out by brief.py from next_steps.json%s: every "
                 "number traces to the run's files, and no sentence here was written by an AI.</p>"
                 % (esc(made), (" " + esc(version)) if version else "", " and plan.json" if with_plan else ""))
    return '<footer id="footer" class="foot">%s</footer>' % "".join(lines)


# ------------------------------------------------------------------ the page

def page_title(doc):
    """'<organization> DMARC brief <date>', each part only when the document has it."""
    org, date = _text(doc.get("org_domain")), _text(doc.get("date"))
    return " ".join(([org] if org else []) + ["DMARC brief"] + ([date] if date else []))


def render(doc, plan=None, fragment=False):
    """The brief as HTML, from next_steps.json (doc) and plan.json (plan, or
    None: the DNS changes section then says Not in this run.). Standalone by
    default: the whole page with its Content-Security-Policy. fragment=True
    returns only the <title>, the <style> and the body's content, for a host
    that supplies the document skeleton itself. Deterministic: no clock, no
    randomness, every list in a stable order."""
    doc = doc if isinstance(doc, dict) else {}
    plan = plan if isinstance(plan, dict) else None
    head = _text(doc.get("org_domain")) or None
    body = "\n".join([masthead(doc), contents(), lede(doc), stand_section(doc), next_step_section(doc),
                      domains_section(doc, plan, head), failing_section(doc), owners_section(doc, head),
                      ask_section(doc), dns_section(plan, head), questions_section(doc, head),
                      glossary_section(doc), footer(doc, plan is not None)])
    main = '<main class="brief">\n%s\n</main>\n' % body
    title = "<title>%s</title>\n<style>\n%s</style>\n" % (esc(page_title(doc)), CSS)
    if fragment:
        return title + main
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            '<meta http-equiv="Content-Security-Policy" content="%s">\n%s</head>\n<body>\n%s</body>\n</html>\n'
            % (CSP, title, main))  # CSP is fixed text with no quote, '<' or '&' in it: written as is


def read_json(path, required):
    """One JSON object from a run file; None for an optional file that is not
    there. Raises BriefError for anything else that is not one object."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        if required:
            raise BriefError("%s is missing (run collect.py or next_steps.py --out first)" % path) from None
        return None
    except OSError as exc:
        raise BriefError("cannot read %s: %s" % (path, exc.strerror or exc)) from exc
    except UnicodeDecodeError:
        raise BriefError("%s is not UTF-8 text" % path) from None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BriefError("%s is not valid JSON (%s at line %d)" % (path, exc.msg, exc.lineno)) from exc
    if not isinstance(doc, dict):
        raise BriefError("%s is not one JSON object" % path)
    return doc


def write_run(run_dir, out=None, fragment=False):
    """brief.html for a run folder: its next_steps.json (required) and its
    plan.json (when there) in, the page written to out (default
    RUN_DIR/brief.html). collect.py and the command line both build it here,
    so a rerun on the same files gives the same bytes. Returns the path."""
    run = next_steps.repo_path(run_dir)
    doc = read_json(run / "next_steps.json", True)
    plan = read_json(run / "plan.json", False)
    target = next_steps.repo_path(out) if out else run / "brief.html"
    text = render(doc, plan, fragment)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return target


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", metavar="RUN_DIR", help="a run folder holding next_steps.json (and plan.json), "
                                                       "for example audit-out/latest")
    ap.add_argument("--out", metavar="FILE", help="write the page here (default: RUN_DIR/brief.html)")
    ap.add_argument("--fragment", action="store_true",
                    help="write only the title, the style and the body's content, for a host page that supplies "
                         "the rest (with no --out it takes brief.html's place: pass --out to keep the full page)")
    args = ap.parse_args(argv)
    try:
        path = write_run(args.run_dir, args.out, args.fragment)
    except BriefError as exc:
        die(str(exc))
    except OSError as exc:
        die("cannot write the brief: %s" % (exc.strerror or exc))
    except Exception as exc:  # never a traceback for the reader
        die("could not build the brief from these files (%s: %s)" % (type(exc).__name__, exc))
    print("wrote %s" % path)
    sys.exit(0)


if __name__ == "__main__":
    main()
