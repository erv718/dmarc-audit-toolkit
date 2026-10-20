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
addresses), so every string from either file is HTML-escaped and set in a
bidi isolate of its own, a character that would hide or reorder the text
around it (U+202E, a zero-width space) shows as a visible marker such as
[U+202E] - the marks real mail text needs (a joiner in an emoji, a
direction mark in a right-to-left subject) show as themselves - and the
only marks honoured inside a string are the generator's own **bold** and
`code`, converted after escaping. The same inputs give the same bytes.
Every list of domains follows the run's one order (audit.domain_key): the
headline organization (next_steps.json org_domain) first, then each
organization by name, its organizational domain first and the names below
it by name; the plan's records run in the plan's own order (plan.row_key
led by the headline plan.json records), the order plan.md, todo.md and the
plan ids follow, whatever organization the document names. What next_steps.md
splits or groups, the page splits and groups with the same helpers
(next_steps.headline_split, next_steps.owner_parts), so the two never
disagree on a line or a count.

Relative paths resolve from the repo root, as in every tool here. Exit
codes: 0 written, 2 usage or input error. Never a traceback.
"""

import argparse
import html
import itertools
import json
import math
import os
import re
import sys
import unicodedata
from pathlib import Path

import audit  # the one domain order (domain_key) every list of names follows
import next_steps  # the document's own words and thresholds, so the page says what next_steps.md says
import plan as plan_mod  # the plan's priority and kind words, and its row order

ROOT = Path(__file__).resolve().parent.parent
NOT_IN_RUN = "Not in this run."
NO_QUESTIONS = "None from this run."  # next_steps.md's words for an Open questions section the run left empty
NO_DOMAINS = "No domain was audited in this run."  # and for a Per domain section with no row
EMPTY_PLAN = "No DNS changes: the plan proposes no record and holds nothing."
# the page's sections, in order, with the titles the table of contents links: (fixed id, title)
SECTIONS = (("stand", "Where we stand"), ("next-step", "The next step"), ("domains", "Per domain"),
            ("failing", "What is failing"), ("owners", "What happens next, by owner"), ("ask", "The ask"),
            ("dns", "DNS changes"), ("questions", "Open questions"), ("glossary", "Glossary"))
# every id on the page, in page order: the masthead, the contents and the one-liner, the sections, the footer
SECTION_IDS = ("top", "contents", "summary") + tuple(sid for sid, _ in SECTIONS) + ("footer",)
# a record card's id, from its place in the DNS changes section (never from the data): the index links to it
CARD_ID = "rec-%d"
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
# a per-domain row read as a block on a phone: the column names, fixed text in the style, never from the data
DOMAIN_HEADS = ("Domain", "Policy", "Gate", "Next step", "Mail flow")
# What is failing's tables, read as blocks the same way: each table's class and its columns' short names
LIST_HEADS = (("env", ("Envelope", "Messages", "Label", "Senders")),
              ("snd", ("Sender", "Messages", "Label", "Subjects", "Envelope")),
              ("out", ("Source", "Failing", "As", "Label", "Receivers")))
# the classes a table may carry (a fixed set): the per-domain table, the plan at a glance, What is failing's three
TABLE_CLASSES = ("stack", "index") + tuple("list " + name for name, _ in LIST_HEADS)

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


def _stacked_labels():
    """The per-domain table's column names as the labels of a row read as a block (fixed text)."""
    return "".join('  table.stack td:nth-child(%d)::before { content: "%s"; }\n' % (i, h)
                   for i, h in enumerate(DOMAIN_HEADS, 1))


def _list_labels():
    """What is failing's tables' column names as the labels of a row read as a block (fixed text)."""
    return "".join('  table.%s td:nth-child(%d)::before { content: "%s"; }\n' % (name, i, h)
                   for name, heads in LIST_HEADS for i, h in enumerate(heads, 1))


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
.lede { width: fit-content; max-width: 100%; background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); padding: 1.1rem 1.25rem; }
.lede p { font-size: 1.125rem; max-width: 70ch; }
.section { display: flex; flex-direction: column; gap: 1rem; border-top: 1px solid var(--line); padding-top: 1.5rem; }
.section-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 1rem; }
.meta { font-family: var(--font-mono); font-size: 0.78rem; color: var(--muted); }
.section p, .section li { max-width: 70ch; }
.section-head .meta { max-width: none; }
.group { display: flex; flex-direction: column; gap: 0.6rem; }
.lines { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 0.45rem; }
.lines > li { position: relative; padding-left: 1rem; }
.lines > li::before { content: ""; position: absolute; left: 0.2rem; top: 0.62em; width: 0.34rem; height: 0.34rem;
  border: 0.17rem solid var(--muted); border-radius: 50%; }
.lines > li.item { display: flex; flex-direction: column; gap: 0.35rem; }
.note, .why, .empty, .muted { color: var(--muted); }
.note { font-size: 0.875rem; }
.empty { font-style: italic; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: 0.75rem; }
.tile { min-width: 0; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 0.85rem 1rem; display: grid; grid-row: span 4; grid-template-rows: subgrid; row-gap: 0.3rem;
  align-content: start; break-inside: avoid; }
.figure { font-size: 2rem; font-weight: 650; line-height: 1.15; font-variant-numeric: tabular-nums; }
.figure .side { font-size: 0.875rem; font-weight: 400; color: var(--muted); }
.figure.words { font-size: 1.125rem; line-height: 2.05; }
.figure.na { font-size: 1.125rem; line-height: 2.05; font-weight: 400; color: var(--muted); }
.caption { font-size: 0.875rem; color: var(--muted); font-variant-numeric: tabular-nums; }
.scope { font-size: 0.78rem; line-height: 1.4; color: var(--muted); font-variant-numeric: tabular-nums; }
.d { white-space: nowrap; }
.d.dl, .count.owner { display: inline-block; max-width: 100%; white-space: normal; vertical-align: top; }
.pill { display: inline-block; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.5;
  padding: 0 0.55rem; border: 1px solid currentColor; border-radius: 999px; white-space: nowrap; }
.pill.ok { color: var(--ok); background: var(--ok-bg); }
.pill.warn { color: var(--warn); background: var(--warn-bg); }
.pill.bad { color: var(--bad); background: var(--bad-bg); }
.pill.info { color: var(--info); background: var(--info-bg); }
.tag { display: inline-block; max-width: 100%; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.5;
  padding: 0 0.4rem; border: 1px solid var(--line); border-radius: 4px; color: var(--ink); overflow-wrap: anywhere; }
.refs { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem; max-width: 100%; }
.refs .muted { font-size: 0.875rem; }
.dn, .hook, .subject, .channel, .mono, .k, .d { unicode-bidi: isolate; }
.dn > * { overflow-wrap: break-word; }
.dn > .w { white-space: nowrap; }
.dn > .long { overflow-wrap: anywhere; }
.dn.keep { white-space: nowrap; }
.step { display: flex; flex-direction: column; gap: 0.75rem; }
.step-label { font-size: 1.125rem; font-weight: 600; }
.verdict { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 0.6rem; }
.verdict .mono { font-size: 0.875rem; }
.checklist { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
.checklist li { display: grid; grid-template-columns: 1rem minmax(0, 1fr); gap: 0.6rem; align-items: start; }
.box { width: 0.95rem; height: 0.95rem; margin-top: 0.3rem; border: 1.5px solid var(--muted); border-radius: 3px; }
.checklist.compact { gap: 0.2rem; font-size: 0.875rem; }
.checklist.compact li { grid-template-columns: 0.85rem minmax(0, 1fr); gap: 0.5rem; }
.checklist.compact .box { width: 0.8rem; height: 0.8rem; margin-top: 0.28rem; }
.pre { display: flex; flex-direction: column; gap: 0.25rem; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th, td { text-align: left; vertical-align: top; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--line); }
thead th { font-size: 0.78rem; font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--muted);
  white-space: nowrap; }
tr { break-inside: avoid; }
tr.org th { background: var(--sunken); font-family: var(--font-mono); font-weight: 600; }
tbody + tbody > tr:first-child > * { border-top: 1px solid var(--muted); }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.name { font-family: var(--font-mono); }
table.stack td.name { width: 26ch; min-width: 26ch; }
td.name b, .card-head .name b { font-weight: 600; }
.apex { color: var(--muted); }
.rest { display: block; font-size: 0.78rem; color: var(--muted); text-wrap: balance; }
.subject { display: block; overflow-wrap: anywhere; }
.owner { display: flex; flex-direction: column; gap: 0.6rem; }
.owner > h3 { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.75rem; }
.channel { font-family: var(--font-mono); font-size: 0.78rem; font-weight: 400; color: var(--muted); }
.org-block { display: flex; flex-direction: column; gap: 0.5rem; }
.org-block > .lines { padding-inline-start: 1rem; }
.org-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.75rem; font-family: var(--font-mono);
  font-size: 0.875rem; font-weight: 600; background: var(--sunken); border-radius: 4px; padding: 0.3rem 0.6rem; }
.count, .sub { font-family: var(--font-body); font-size: 0.78rem; font-weight: 400; color: var(--muted);
  font-variant-numeric: tabular-nums; }
.hook { font-weight: 600; }
.ask { width: fit-content; max-width: 100%; background: var(--sunken); border-radius: var(--radius);
  padding: 1rem 1.25rem; }
table.index td:first-child { font-family: var(--font-mono); white-space: nowrap; }
.cards { display: flex; flex-direction: column; gap: 0.75rem; }
.card { min-width: 0; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 0.85rem 1rem; display: flex; flex-direction: column; gap: 0.55rem; break-inside: avoid; }
.card.quiet { background: var(--sunken); border-style: dashed; }
.card .held { font-size: 0.875rem; color: var(--muted); }
.card-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.3rem 0.75rem; }
.card-head .name { font-family: var(--font-mono); min-width: 0; }
.fields { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 0.45rem 1.25rem;
  font-size: 0.875rem; }
.field { display: grid; grid-template-columns: 5.5rem minmax(0, 1fr); gap: 0.6rem; align-items: baseline;
  min-width: 0; }
.field.short { grid-template-columns: auto auto; }
.field.short dd { white-space: nowrap; }
.field.wide { grid-column: 1 / -1; }
.fields dt { font-family: var(--font-mono); font-size: 0.72rem; letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--muted); }
.fields dd { min-width: 0; overflow-wrap: anywhere; }
pre.value { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 0.875rem; background: var(--sunken);
  border-radius: 4px; padding: 0.4rem 0.6rem; }
.card .why { font-size: 0.875rem; }
.zone { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.6rem; }
.section p.zone { max-width: none; }
.glossary { display: flex; flex-direction: column; gap: 0.5rem; }
.term { display: grid; grid-template-columns: minmax(7rem, 11rem) minmax(0, 1fr); gap: 0.15rem 1.25rem; }
.term dt { font-weight: 600; }
.term dd, .foot p { max-width: 70ch; }
.foot { display: flex; flex-direction: column; gap: 0.35rem; border-top: 1px solid var(--line); padding-top: 1rem;
  font-size: 0.78rem; color: var(--muted); }
@media (max-width: 40rem) {
  .term { grid-template-columns: minmax(0, 1fr); }
  .fields { grid-template-columns: minmax(0, 1fr); }
  .field.short { grid-template-columns: 5.5rem minmax(0, 1fr); }
}
@media screen and (max-width: 48rem) {
  table.stack, table.stack tbody, table.stack tr, table.stack th, table.stack td { display: block; }
  table.stack thead { display: none; }
  table.stack tr { padding-block: 0.45rem; border-bottom: 1px solid var(--line); }
  table.stack tr.org { padding-block: 0; border-bottom: 0; }
  table.stack td { position: relative; min-width: 0; padding: 0.15rem 0 0.15rem 6.5rem; border: 0; }
  table.stack td.name { width: auto; min-width: 0; }
  table.stack td::before { position: absolute; left: 0; top: 0.3rem; font-family: var(--font-mono); font-size: 0.7rem;
    letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  table.stack tbody + tbody > tr:first-child > * { border-top: 0; }
  table.stack tbody + tbody { border-top: 1px solid var(--muted); }
""" + _stacked_labels() + """\
  table.list, table.list tbody, table.list tr, table.list td { display: block; }
  table.list thead { display: none; }
  table.list tr { padding-block: 0.45rem; border-bottom: 1px solid var(--line); }
  table.list td { position: relative; min-width: 0; padding: 0.15rem 0 0.15rem 6.5rem; border: 0; text-align: left; }
  table.list td::before { position: absolute; left: 0; top: 0.3rem; font-family: var(--font-mono); font-size: 0.7rem;
    letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
""" + _list_labels() + """\
  table.index, table.index tbody, table.index td { display: block; }
  table.index thead { display: none; }
  table.index tr { display: grid; grid-template-columns: auto auto minmax(0, 1fr) auto; gap: 0.1rem 0.75rem;
    align-items: baseline; padding-block: 0.45rem; border-bottom: 1px solid var(--line); }
  table.index td { padding: 0; border: 0; text-align: left; }
  table.index td.status { grid-column: 1 / -1; grid-row: 2; }
  table.index td.name { grid-column: 1 / -1; grid-row: 3; }
  table.index td:nth-child(3)::before { content: "priority "; color: var(--muted); }
  table.index td:nth-child(6)::before { content: "checks "; color: var(--muted); }
}
@page { margin: 16mm 14mm; }
@media print {
  html { font-size: 11pt; }
  body { background: var(--surface); }
  .brief { max-width: none; padding: 0; gap: 1.5rem; }
  .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .table-wrap { overflow: visible; }
  a { color: inherit; text-decoration: none; }
  .tile, .card, .ask, tr, .checklist li, .zone { break-inside: avoid; }
  .zone, tr.org, .org-head, .pre > .k { break-after: avoid; }
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


def _shown(value):
    """A field a record card shows: a string as it is, a whole number in digits (a TTL); anything else (None, a
    list, an object, a boolean - a damaged file) as '', never as Python would spell it."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return ""


def _num(value):
    """A count the document carries, else None: never a bool, never NaN or
    an infinity (JSON as Python reads it can spell both)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return None
    return None if value in (float("inf"), float("-inf")) else value


def _count(value):
    """A count as the page shows it: its digits, or '?' when the document's value is missing or damaged."""
    n = _num(value)
    return "?" if n is None else str(n)


def _norm(name):
    return _text(name).lower().rstrip(".")


def _plural(n, one, many=None):
    return one if n == 1 else (many or one + "s")


def _counted(n, one, many=None):
    return "%s %s" % (n, _plural(n, one, many))


# ------------------------------------------------------------------ escaping: every string from the data goes here

ODD_RX = re.compile(r"[^\t\n\r\x20-\x7e]")  # anything but printable ASCII and the three whitespace controls
# The format characters (Unicode class Cf) real mail text needs, which show as themselves: the joiners inside an
# emoji or a Persian word (U+200D, U+200C), the direction marks of a right-to-left subject (U+200E, U+200F, U+061C)
# and a soft hyphen in a display name (U+00AD) - each string sits in its own bidi isolate (iso), so a mark moves only
# its own text - and the tag characters that spell a flag's emoji sequence (FLAG_RX). Every other format character
# reorders or hides the text around it, or draws nothing at all - the bidi embeddings, overrides and isolates
# (U+202A to U+202E, U+2066 to U+2069), the zero-width space, the word joiner and the BOM, the invisible operators
# (U+2061 to U+2064), the Mongolian vowel separator, the deprecated format controls (U+206A to U+206F), the
# interlinear annotation marks, a tag character outside a flag - so two addresses that differ only by one would look
# identical: it shows as a marker, as a control does.
SHOWN_FORMAT = frozenset((0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x00AD))
# a flag's emoji sequence (the flag of Scotland: U+1F3F4, the tags g b s c t, the cancel tag U+E007F), its tag
# characters spelled as numbers so this file stays ASCII
FLAG_RX = re.compile("%s[%s-%s]+%s" % (chr(0x1F3F4), chr(0xE0020), chr(0xE007E), chr(0xE007F)))


# The default-ignorable code points outside class Cf (Unicode's Default_Ignorable_Code_Point): the combining
# grapheme joiner, the Hangul fillers, the Khmer inherent vowels, the Mongolian variation selectors and vowel
# separator, the unassigned specials and the reserved block after the tags. They draw nothing, so two addresses
# that differ by one look alike, and mail text has no use for them: each is marked wherever it is.
IGNORABLE = ((0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F), (0x3164, 0x3164),
             (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0080, 0xE0FFF))
# What a name (an address, a domain, a host name, an IP) marks besides: the characters real mail text needs
# (SHOWN_FORMAT) and the variation selectors an emoji takes have no place in a DNS name or an address, where they
# would only hide a look-alike.
NAME_HIDDEN = ((0x200C, 0x200F), (0x061C, 0x061C), (0x00AD, 0x00AD), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def _within(cp, ranges):
    return any(a <= cp <= b for a, b in ranges)


def marked(ch):
    """True for a character the page shows as a marker, [U+202E], never as
    itself: a format character mail text does not need (every Cf but
    SHOWN_FORMAT), which reorders or hides the text around it, a
    default-ignorable code point that draws nothing (IGNORABLE), and a
    control other than tab and the line breaks. A tag character is marked
    on its own; inside a flag's emoji sequence it is text (flag_tags).
    scripts/check_doc.py names exactly these in a polished copy, wherever
    they are; a name marks NAME_HIDDEN as well (clean)."""
    cat = unicodedata.category(ch)
    return ((cat == "Cf" and ord(ch) not in SHOWN_FORMAT) or (cat == "Cc" and ch not in "\t\n\r")
            or _within(ord(ch), IGNORABLE))


def flag_tags(text):
    """The positions of the tag characters in text that spell a flag's emoji
    sequence (FLAG_RX): text, never markers, though marked() picks each on
    its own."""
    if chr(0x1F3F4) not in text:
        return frozenset()
    return frozenset(i for m in FLAG_RX.finditer(text) for i in range(m.start() + 1, m.end()))


def clean(value, name=False):
    """Data as a reader may see it: a character marked() picks - U+202E,
    U+200B, U+2063, a control - becomes a visible marker, [U+202E]; a lone
    surrogate (JSON can spell one, UTF-8 cannot carry it) becomes U+FFFD;
    every other character is itself, the tags of a flag's emoji sequence
    too. Text from mail can then neither mirror nor hide the generator's
    words, counts, ids or IPs around it, and two addresses that differ by an
    invisible character never look alike."""
    text = "" if value is None else str(value)
    if not ODD_RX.search(text):
        return text
    flag = flag_tags(text)
    out = []
    for i, ch in enumerate(text):
        if " " <= ch <= "~" or ch in "\t\n\r":
            out.append(ch)
        elif unicodedata.category(ch) == "Cs":
            out.append("\ufffd")
        elif (marked(ch) or (name and _within(ord(ch), NAME_HIDDEN))) and i not in flag:
            out.append("[U+%04X]" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def esc(value):
    """Data as HTML text: made visible (clean), then escaped, quotes
    included, so no string from either file can open a tag, leave an
    attribute or turn the line around it."""
    return html.escape(clean(value), quote=True)


def esc_name(value):
    """A name (an address, a domain, a host, an IP) as HTML text: esc, with
    the characters a name has no use for marked as well (clean name=True)."""
    return html.escape(clean(value, name=True), quote=True)


def iso(markup):
    """Markup made from one data string, in its own bidi isolate (<bdi>,
    whose direction its own first letter sets): a right-to-left subject, or
    a direction mark it carries, can reorder only its own text - never the
    page's words, counts and ids after it. Every data string that shares
    its line with anything else goes through here; one that is alone in its
    block, or in an element the style isolates (a name, a hook, a pill, a
    tag), is isolated already. '' stays ''."""
    return "<bdi>%s</bdi>" % markup if markup else ""


def iso_text(value):
    """A data string as isolated HTML text: esc, then iso."""
    return iso(esc(value))


CODE_RX = re.compile(r"`([^`\n]+)`")
BOLD_RX = re.compile(r"\*\*(.+?)\*\*")
KEPT_RX = re.compile(r"<c(\d+)>")  # a code span set aside; '<' never survives escaping, so data cannot spell it
# a DNS name or an address inside a sentence: labels joined by dots (and an @), the last one starting with a letter -
# never a number such as 77.4 or an IP address such as 203.0.113.5
NAME_IN_TEXT_RX = re.compile(r"(?<![\w.@-])[\w-]+(?:[.@][\w-]+)*\.[^\W\d][\w-]*")
# what a sentence must never split: a DNS name or an address (group 1, cut by text_name), and an id - a plan or a
# finding id such as P-14 or MAILFLOW-001 - or an ISO date such as 2026-10-07, each one unbroken piece (group 2)
UNSPLIT_RX = re.compile(r"(%s)|((?<![A-Za-z0-9-])[A-Z]+-[0-9]+(?![0-9A-Za-z-])|(?<![0-9-])[0-9]{4}-[0-9]{2}-[0-9]{2}"
                        r"(?![0-9]))" % NAME_IN_TEXT_RX.pattern)


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


def prose(value):
    """A data sentence as the page sets it, in running text (a bullet, a
    checklist, the lede, the ask, a step, a card's summary) or a table
    cell: marks, then every DNS name or address in it cut as text_name cuts
    one - a short one an unbroken piece, so the line breaks at the space
    before it; a longer one between its labels only, so it never sets a
    column's width on its own - and every plan or finding id and ISO date
    one unbroken piece, so no line ends in 'P-' or '2026-'. Numbers and IP
    addresses stay whole as they are. The text is unchanged."""
    def unsplit(m):
        if m.group(1):  # the name as marks() escaped it: escaping leaves a name's characters as they are
            return text_name(m.group(1))
        return '<span class="d">%s</span>' % m.group(2)
    return UNSPLIT_RX.sub(unsplit, marks(value))


# ------------------------------------------------------------------ the one domain order, and names that break well

def org_of(name):
    """The organization a name belongs to, as the run's one order groups it."""
    return audit.domain_key(_text(name))[1]


def dkey(name, headline):
    """audit.domain_key: the headline's organization first, then each
    organization by name, its organizational domain first and the names
    below it by name."""
    return audit.domain_key(_text(name), headline)


NAME_RUN_RX = re.compile(r"[^.@]*[.@]|[^.@]+")
# A label of this many characters or fewer (its dot included) is never cut: it fits the narrowest place a name is
# shown, a stacked row on a 360px phone. A longer one - DNS allows 63 - may break inside where it must, so it never
# passes the screen's edge or sets a table column's width on its own.
LABEL_KEEP = 20
# A name of this many characters or fewer is never cut anywhere: it fits a line of the narrowest place a name is
# shown (a stacked row or a sentence on a 360px phone), so a line breaks before it, never inside it. A longer one
# moves whole to the next line in a sentence (text_name) and breaks between its labels only when it is longer
# than a whole line, or than its table column (name_html, plain_name).
NAME_KEEP = 28
BREAK_AT_RX = re.compile(r"[^\w.@]")  # a hyphen, a slash, a plus...: a character a browser may break a line after


def _runs(text):
    """A DNS name or an address cut after each dot and each @, the places
    it breaks: 'dev.support.example.com' is dev. support. example. com.;
    an address's local part is one piece with its @ ('first.last@'), never
    cut inside."""
    at = text.rfind("@")
    if at > 0:
        return [text[:at + 1]] + NAME_RUN_RX.findall(text[at + 1:])
    return NAME_RUN_RX.findall(text)


def _keep(run):
    """The class of one label's piece of a name (a fixed set): 'long' for a
    label longer than LABEL_KEEP characters, which may break anywhere it
    must; 'w' for a shorter one with a hyphen or another place a browser
    would break a line at, kept whole; '' for one with no such place - it
    never breaks, and wraps only if it cannot fit a line at all."""
    if len(run) > LABEL_KEEP:
        return "long"
    return "w" if BREAK_AT_RX.search(run) else ""


def _piece(tag, classes, markup):
    """One piece of a name as an element: <b class="w">investor-relations.</b>, <span>example.</span>."""
    classes = " ".join(c for c in classes if c)
    return "<%s%s>%s</%s>" % (tag, (' class="%s"' % classes) if classes else "", markup, tag)


def name_html(name, org=None):
    """A domain as the tables and cards show it: a subdomain's own labels in
    the foreground and its organization's part muted
    (<b>pay.</b><wbr><span class="apex">example.</span>...); an apex in
    bold. A name breaks at the break opportunity after each dot, and a
    label of LABEL_KEEP characters or fewer never inside (_keep): a narrow
    column shows 'investor-relations.' / 'example.com', never 'investor-' /
    'relations.example.com'; only a longer label breaks inside, where it
    must, so it never passes the edge of its column or of the screen."""
    text = _text(name)
    if not text:
        return ""
    base = text.rstrip(".")
    org = _norm(org) or org_of(base)
    suffix = "." + org
    own = len(text)
    if org and len(base) > len(suffix) and base[-len(suffix):].lower() == suffix:
        own = len(base) - len(suffix) + 1  # the subdomain's own labels and the dot after them
    parts, pos = [], 0
    for run in _runs(text):
        end = pos + len(run)
        if end <= own:
            parts.append(_piece("b", (_keep(run),), esc_name(run)))
        elif pos >= own:
            parts.append(_piece("span", ("apex", _keep(run)), esc_name(run)))
        else:
            parts.append(_piece("span", (_keep(run),), '<b>%s</b><span class="apex">%s</span>'
                                % (esc_name(text[pos:own]), esc_name(text[own:end]))))
        pos = end
    # a name of NAME_KEEP characters or fewer never breaks (keep): no break opportunity at all, since Edge and
    # Chrome break at a <wbr> even under white-space: nowrap; its column is at least as wide as it
    keep = len(text) <= NAME_KEEP
    return '<span class="dn%s">%s</span>' % (" keep" if keep else "", ("" if keep else "<wbr>").join(parts))


IP_RX = re.compile(r"[0-9.]+|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")  # an IPv4 or IPv6 address: one piece


def plain_name(value):
    """A name or address with no emphasis (a sender, an envelope domain, a
    record's host name), cut the same way: it breaks after a dot or an @,
    never inside a label of LABEL_KEEP characters or fewer; an IP address
    is one piece, never cut unless it is longer than that (an IPv6 one).
    '?' when the document has none."""
    text = _text(value)
    if not text:
        return "?"
    keep = " keep" if len(text) <= NAME_KEEP else ""  # never cut (no <wbr>): its column is at least as wide as it
    if IP_RX.fullmatch(text):
        return '<span class="dn%s">%s</span>' % (keep, _piece("span", ("w" if len(text) <= LABEL_KEEP else "long",),
                                                               esc_name(text)))
    return '<span class="dn%s">%s</span>' % (keep, ("" if keep else "<wbr>").join(
        _piece("span", (_keep(r),), esc_name(r)) for r in _runs(text)))


def text_name(value):
    """A DNS name or an address where it sits among words - a sentence, a
    note line, a list of names in a cell - so a line breaks at the space
    before it, never inside it while the whole fits on the next line: one
    unbroken piece (class d) when it is NAME_KEEP characters or fewer (or an
    IP address); a longer one an inline block (class dl) that moves whole to
    the next line and breaks between its labels only when it is longer than
    a whole line. '?' when the document has none."""
    text = _text(value)
    if not text:
        return "?"
    if IP_RX.fullmatch(text) or len(text) <= NAME_KEEP:
        return '<span class="d">%s</span>' % esc_name(text)
    return '<span class="d dl">%s</span>' % "<wbr>".join(_piece("span", (_keep(r),), esc_name(r))
                                                         for r in _runs(text))


# ------------------------------------------------------------------ small parts

def pill(cls, word):
    """A status pill; cls comes from a fixed set (ok, warn, bad, info), never from the data."""
    return '<span class="pill %s">%s</span>' % (cls if cls in ("ok", "warn", "bad", "info") else "info", esc(word))


def policy_class(text):
    """A policy's pill color: reject is where enforcement ends, quarantine on
    the way, none and no record are unprotected; anything else is plain."""
    t = _text(text).lower()
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
    text = _text(text)
    if not text:
        return ""
    head, sep, rest = text.partition(" (")
    out = pill(policy_class(head), head)
    if sep:
        out += '<span class="rest">(%s</span>' % prose(rest)
    return out


def gate_cell(gate, gate_text):
    """The gate pill, with what the document adds to its word ('held by: ...',
    '(for the weekly ramp this skips)', ', with a plan hold') muted beneath
    it. A name with no policy step left reads 'no step left' in the pill the
    verdict colors, the verdict word muted after it."""
    gate = gate if isinstance(gate, str) and gate else "not checked"
    cls, word = GATE_PILLS.get(gate, NOT_CHECKED)
    said = _text(gate_text)
    lead = next_steps.GATE_WORDS.get(gate, gate)
    if said.startswith(next_steps.NO_STEP_LEFT):
        word, lead = next_steps.NO_STEP_LEFT, next_steps.NO_STEP_LEFT
    rest = said[len(lead):] if said.startswith(lead) else said
    rest = rest.strip().lstrip(",").strip()
    if rest.startswith("- "):  # 'not yet - held by: ...': the pill says the verdict, the rest says what holds it
        rest = rest[2:].strip()
    return pill(cls, word) + ('<span class="rest">%s</span>' % prose(rest) if rest else "")


def tag(text, cls="tag"):
    return '<span class="%s">%s</span>' % (cls, esc(text))


def refs_html(tags):
    """Several tags in one row that wraps between them, never one box wider than the page."""
    return '<span class="refs">%s</span>' % " ".join(tags)


REF_ID_RX = re.compile(r"(?<![A-Za-z0-9])[A-Z]+-\d+(?: to [A-Z]+-\d+)?(?![0-9])")


def ref_tags(ref):
    """An item's reference as tags. One id or one range ('P-04', 'plan P-03
    to P-07', 'MAILFLOW-002') is one tag, as next_steps.md writes it;
    several ('plan P-01, P-03, P-05, ...', a bundle whose ids do not run
    without a gap) are one tag each, in a row that wraps between them, with
    the words around them ('plan') muted - so a long list of ids never
    pushes the page sideways."""
    ref = _text(ref)
    if not ref:
        return ""
    found = list(REF_ID_RX.finditer(ref))
    if len(found) <= 1:
        return tag(ref)
    out, pos = [], 0
    for m in found:
        words = ref[pos:m.start()].strip(" ,;")
        if words and words != "and":
            out.append('<span class="muted">%s</span>' % esc(words))
        out.append(tag(m.group(0)))
        pos = m.end()
    tail = ref[pos:].strip(" ,;")
    if tail:
        out.append('<span class="muted">%s</span>' % esc(tail))
    return refs_html(out)


def id_tags(ids):
    """A per-domain row's plan ids after its step: one tag each in a row that
    wraps, or one tag for a run of more than three that has no gap (as
    next_steps.md writes it, 'P-03 to P-07')."""
    ids = list(dict.fromkeys(i for i in ids if i))
    if not ids:
        return ""
    if len(ids) == 1:
        return " " + tag(ids[0])
    joined = next_steps.id_range(ids)
    if len(ids) > 3 and " to " in joined and ", " not in joined:
        return " " + tag(joined)
    return " " + refs_html([tag(i) for i in ids])


def checklist(texts, cls="checklist"):
    """Conditions as a checklist of unchecked boxes: the reader ticks them."""
    return '<ul class="%s">%s</ul>' % (cls, "".join(
        '<li><span class="box" aria-hidden="true"></span><span>%s</span></li>' % prose(t) for t in texts))


def bullets(texts, cls="lines"):
    return '<ul class="%s">%s</ul>' % (cls, "".join("<li>%s</li>" % prose(t) for t in texts))


def block(title, inner):
    """A titled part of a section."""
    return '<div class="group"><h3>%s</h3>%s</div>' % (esc(title), inner)


def table(heads, body_rows, numeric=(), cls=""):
    """A table inside its scrolling wrapper: heads as column titles (fixed
    text), body_rows as already-built <tr> or <tbody> markup; cls one of the
    page's fixed table classes (TABLE_CLASSES), each of which reads as
    blocks on a narrow screen, so no column is ever out of sight."""
    th = "".join('<th scope="col"%s>%s</th>' % (' class="num"' if i in numeric else "", esc(h))
                 for i, h in enumerate(heads))
    body = "".join(body_rows)
    if not body.startswith("<tbody"):
        body = "<tbody>%s</tbody>" % body
    return '<div class="table-wrap"><table%s><thead><tr>%s</tr></thead>%s</table></div>' % (
        (' class="%s"' % cls) if cls in TABLE_CLASSES else "", th, body)


def section(sid, title, parts, meta="", empty=NOT_IN_RUN):
    """One section: its fixed id and title, then its parts - or, when it has
    none, the sentence next_steps.md says there (empty): Not in this run.
    for a section with no evidence (a zero is not evidence of health)."""
    parts = [p for p in parts if p] or ['<p class="empty">%s</p>' % esc(empty)]
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
        parts.append('<p class="audience">%s.</p>' % iso(prose(audience)))
    if sources:
        parts.append('<p class="sources">%s</p>' % prose(sources))
    parts.append('<p class="sources">%s</p>' % esc(VERIFY_LINE))
    return '<div id="top" class="masthead">\n%s\n</div>' % "\n".join(parts)


def contents():
    links = "".join('<li><a href="#%s">%s</a></li>' % (sid, esc(title)) for sid, title in SECTIONS)
    return ('<nav id="contents" class="toc" aria-label="Contents"><p class="eyebrow">Contents</p><ol>%s</ol></nav>'
            % links)


def lede(doc):
    """The one-liner, as the lede: policy today, who still fails, the next
    safe step. Its panel is as wide as its text, never a band of empty
    surface beside it."""
    text = _text(doc.get("one_liner"))
    inner = "<p>%s</p>" % prose(text) if text else '<p class="empty">%s</p>' % NOT_IN_RUN
    return '<section id="summary" class="lede" aria-label="In one line">%s</section>' % inner


def tile(label, figure, caption, side="", scope=""):
    """One KPI tile: the label above, the figure, a one-line caption below
    it and the scope the figure counts (scope: markup from log_scope or
    outside_scope - which source, which domains, which span) - always four
    rows, so the tiles' rows line up. A figure the run does not have says
    so in words, never as a zero."""
    if figure is None:
        fig = '<p class="figure na">not in this run</p>'
    elif isinstance(figure, str) and not re.match(r"^[+-]?\d", figure):
        fig = '<p class="figure words">%s</p>' % esc(figure)
    else:
        fig = '<p class="figure">%s%s</p>' % (esc(figure), (' <span class="side">%s</span>' % esc(side)) if side else "")
    return ('<div class="tile"><p class="label">%s</p>%s<p class="caption">%s</p><p class="scope">%s</p></div>'
            % (prose(label), fig, prose(caption), scope))


def _unbroken(text):
    """A span or a date that must not break across lines ('59-minute span', '2026-09-18'), as markup."""
    return '<span class="d">%s</span>' % esc(text)


def log_scope(st):
    """What a mail-log figure counts, as markup: every domain in the mail
    log - the one-liner counts one organization's, so the two figures
    differ - over the span next_steps.md names ('59-minute')."""
    try:
        phrase = next_steps.span_phrase(_dict(st.get("maillog_window")) or None) or ""
    except Exception:  # a damaged window names no span; the figure still counts the whole log
        phrase = ""
    m = re.match(r"the mail log's (\S+) span", phrase)
    return "all domains in the mail log" + (", " + _unbroken("%s span" % m.group(1)) if m else "")


def outside_scope(sb):
    """What the receivers' figures count, as markup: the outside view, the
    aggregate reports over their own window."""
    win = _texts(sb.get("window"))
    return "aggregate reports" + (", %s to %s" % (_unbroken(win[0]), _unbroken(win[1])) if len(win) == 2 else "")


def trend_tile(st):
    """The trend as next_steps.md's trend line computes it: the change in
    genuine failures, else in the pass rate, from the previous run's figures
    and this run's. A difference that is not a finite number (a damaged
    figure) is not comparable, never a crash."""
    tr = st.get("trend")
    if not isinstance(tr, dict):
        return tile("Trend", "first run", "no trend yet")
    label = "Trend vs %s" % (_text(tr.get("label")) or "the previous run")
    gf, prev_gf = _num(st.get("genuine_failures")), _num(tr.get("previous_genuine_failures"))
    sb = _dict(st.get("spoofing_blocked"))
    pr, prev_pr = _num(sb.get("pass_rate")), _num(tr.get("previous_pass_rate"))
    if gf is not None and prev_gf is not None and math.isfinite(gf - prev_gf):
        return tile(label, "%+d" % (gf - prev_gf), "genuine failures, %d -> %d" % (prev_gf, gf), scope=log_scope(st))
    if pr is not None and prev_pr is not None and math.isfinite(100 * (pr - prev_pr)):
        return tile(label, "%+.1f pts" % (100 * (pr - prev_pr)),
                    "pass rate, %.1f%% -> %.1f%%" % (100 * prev_pr, 100 * pr), scope=outside_scope(sb))
    why = _texts(tr.get("not_comparable"))
    return tile(label, "not comparable", why[0] if why else "the two runs share no failure count or pass rate")


def stand_tiles(st):
    """The four figures of Where we stand as tiles - genuine failures with
    the raw count beside them, delivered despite failing, what receivers
    rejected and quarantined, the trend - each label short enough to stay on
    one line, and each with its scope: the mail-log figures count every
    domain in the mail log (the one-liner counts one organization's), the
    receivers' the aggregate reports. None when the document carries none
    of them. The section's lines below say each figure in full."""
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
                          ("raw %s" % raw) if raw is not None else "", log_scope(st)))
    ddf = _num(st.get("delivered_despite_fail"))
    tiles.append(tile("Delivered despite failing", ddf, "reached a mailbox anyway" if ddf is not None else
                      "no mail log was read", scope=log_scope(st) if ddf is not None else ""))
    sb = st.get("spoofing_blocked")
    if isinstance(sb, dict):
        rej, qua = _num(sb.get("rejected")) or 0, _num(sb.get("quarantined")) or 0
        msgs = _num(sb.get("messages"))
        tiles.append(tile("Rejected / quarantined", "%s / %s" % (rej, qua),
                          "by receivers, of %s" % _counted(msgs, "message") if msgs is not None else "by receivers",
                          scope=outside_scope(sb)))
    else:
        tiles.append(tile("Rejected / quarantined", None, "no aggregate reports were read"))
    tiles.append(trend_tile(st))
    return '<div class="tiles">%s</div>' % "".join(tiles)


def stand_section(doc):
    """Where we stand: the figures as tiles, then every line of the section
    as next_steps.md writes it, the caveats with them. The heading's dates
    say whose window they are (the aggregate reports'), so no reader dates
    the mail-log figures by them, and 'deduplicated' is said of the
    mail-log counts alone ('aggregate reports 2026-09-18 to 2026-10-08;
    mail-log counts deduplicated'): the same page says the aggregate
    reports' counts cannot be. With no mail-log figure, the window alone."""
    st = _dict(doc.get("stand"))
    lines = _texts(st.get("lines"))
    for c in _texts(st.get("caveats")):  # an older document kept them apart from the lines
        if not any(c in line for line in lines):
            lines.append("**Caveat:** %s" % c)
    parts = [stand_tiles(st), bullets(lines) if lines else ""]
    window = _dict(st.get("window"))
    text, source = _text(window.get("text")), _text(window.get("source"))
    # the window's dates as running text sets them (prose): never split at a hyphen
    span = ("%s %s" % (iso_text(source), iso(prose(text)))) if text and source else (
        iso(prose(text)) if text else "this run's window")
    counted = any(_num(st.get(k)) is not None for k in ("genuine_failures", "delivered_despite_fail"))
    meta = (span + ("; " + _unbroken("mail-log counts deduplicated") if counted else "")) if any(parts) else ""
    return section("stand", "Where we stand", parts, meta)


def next_step_section(doc):
    """The organization's next step: its label and plan id, the gate's
    verdict, then what holds it - a plan step's prerequisites are the
    conditions that make it ready, a gate step's are what holds it - and the
    data an insufficient_data verdict asks for, each said once. A domain
    with no step left ('none - already at the end') has nothing on hold: its
    gate's blockers are what is left to fix, and the pill is its gate's."""
    nxt = doc.get("next_step")
    if not isinstance(nxt, dict) or not _text(nxt.get("label")):
        return section("next-step", "The next step", [])
    label, ref = _text(nxt.get("label")), _text(nxt.get("ref"))
    at_end = label.lower().startswith("none") and not ref  # next_steps.py's own test for no step left
    cls, word = GATE_PILLS.get(_text(nxt.get("verdict")), NOT_CHECKED)
    data = _texts(nxt.get("data"))
    prereqs = [p for p in _texts(nxt.get("prerequisites")) if p not in data]
    holds = [h for h in _texts(nxt.get("holds")) if h not in prereqs and h not in data]
    gate_step = nxt.get("source") == "gate"
    org = _text(doc.get("org_domain"))
    gate = ('<span class="k">Gate on</span><span class="mono">%s</span>' % esc(org)) if at_end and org else \
        '<span class="k">Gate</span>'
    parts = ['<p class="step-label">%s%s</p>' % (iso(prose(label)), (" " + ref_tags(ref)) if ref else ""),
             '<p class="verdict">%s%s</p>' % (gate, pill(cls, word))]
    if _text(nxt.get("why")):
        parts.append('<p class="why">%s</p>' % prose(nxt["why"]))
    if data:
        parts.append(block("Needs more data", checklist(data)))
    if prereqs and at_end:
        parts.append(block("What is left", bullets(prereqs)))
    elif prereqs:
        parts.append(block("On hold while" if gate_step else "Ready when", checklist(prereqs)))
    if holds:  # the gate's blockers the plan row does not carry itself: observations, not boxes to tick
        parts.append(block("Also left" if at_end else "Also on hold while", bullets(holds)))
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
    step = iso(prose(_text(r.get("next_step")))) + id_tags(e["ids"])
    return ('<tr><td class="name">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
            % (name_html(e["name"], e["org"]), policy_cell(r.get("policy_today")),
               gate_cell(r.get("gate"), r.get("gate_text")), step, prose(_text(r.get("mailflow_text")) or "not measured")))


def domains_section(doc, plan, head):
    """Per domain: grouped by organization (headline first) when the rows
    say which, one row per name - an organization's group row only where it
    holds two names or more; a one-domain organization is a plain row in
    its place - then the mail-flow note and the gate's notes next_steps.md
    shows under its table. On a phone each row reads as a block, the column
    names as its labels. With no row, the section says what next_steps.md
    says there - No domain was audited in this run. - above the gate's
    notes too."""
    entries, grouped = domain_rows(doc, plan, head)
    none = doc.get("per_domain") == []  # a document that lists no domain says so, as next_steps.md does
    parts = []
    if entries:
        if grouped:
            bodies = []
            for org, members in itertools.groupby(entries, key=lambda e: e["org"]):
                members = list(members)
                group_row = ('<tr class="org"><th colspan="5" scope="colgroup">%s <span class="count">%s</span></th></tr>'
                             % (iso_text(org), _counted(len(members), "domain"))) if len(members) > 1 else ""
                bodies.append("<tbody>%s%s</tbody>" % (group_row, "".join(domain_row(e) for e in members)))
            parts.append(table(DOMAIN_HEADS, bodies, cls="stack"))
        else:
            parts.append(table(DOMAIN_HEADS, [domain_row(e) for e in entries], cls="stack"))
        note = _text(_dict(doc.get("mailflow")).get("note"))
        if note:
            parts.append('<p class="note">%s</p>' % prose(note))
    notes = [n for n in _list(doc.get("audit_notes")) if isinstance(n, dict) and _text(n.get("text"))]
    if notes:
        if not entries:  # the notes never stand in for the sentence that says why the table is missing
            parts.append('<p class="empty">%s</p>' % esc(NO_DOMAINS if none else NOT_IN_RUN))
        org = iso_text(_text(doc.get("org_domain")))
        if any(_text(n.get("holds")) for n in notes):
            lead = "From the audit on %s:" % org
            items = ["%s (%s)" % (iso(prose(n["text"])), iso(prose(n["holds"])) if _text(n.get("holds")) else
                                  "information; it holds nothing") for n in notes]
        else:
            lead = "From the audit on %s (information; it holds nothing):" % org
            items = [prose(n["text"]) for n in notes]
        parts.append('<div class="group"><p class="note">%s</p><ul class="lines note">%s</ul></div>'
                     % (lead, "".join("<li>%s</li>" % i for i in items)))
    return section("domains", "Per domain", parts, empty=NO_DOMAINS if none else NOT_IN_RUN)


def _label(e):
    return next_steps.LIKELY_WORDS.get(_text(e.get("likely")) or "unknown", "unclear")


def _note_line(entries, cap=None):
    """Entries named on a line rather than in a table, in next_steps.md's
    words and as markup ('name xN (label)', the first NOTES_CAP of them,
    then how many more), each name in its own bidi isolate so nothing in it
    moves the count after it, and cut as text_name cuts one - whole, or
    between its labels - so 'investor-relations.example.com x8' never
    breaks at its hyphen; a damaged entry shows '?' where its name or count
    should be, never a reason to fail and never Python's None."""
    cap = next_steps.NOTES_CAP if cap is None else cap
    text = ", ".join("%s x%s (%s)" % (text_name(e.get("name")), esc(_count(e.get("count"))), esc(_label(e)))
                     for e in entries[:cap])
    if len(entries) > cap:
        text += " (+%d more in report.json)" % (len(entries) - cap)
    return text


def _subjects(e):
    """Up to two subjects, each cut at a word past SUBJECT_MAX characters by next_steps.md's own rule
    (next_steps.cut_subject), so no number in one is ever shown in part."""
    out = []
    for s in _texts(e.get("subjects"))[:2]:
        out.append('<span class="subject">"%s"</span>' % iso(marks(next_steps.cut_subject(s, SUBJECT_MAX))))
    return "".join(out)


def failing_kept(failing):
    """[(block, line)]: What is failing's other sentences (formal
    exceptions, new senders, a log without verdicts, nothing failing), as
    next_steps.md writes them - its lines without the lists the tables
    carry - each with the FAILING_BLOCKS key of the list it sits under
    (None for a line outside every list), so the page keeps a 'formally
    excepted ... not counted above' line right after the table it
    qualifies. A list whose data the document lacks keeps its lines."""
    out, skipping, current = [], False, None
    for line in _list(failing.get("lines")):
        s = line.strip() if isinstance(line, str) else ""
        if not s:
            skipping, current = False, None
            continue
        block_key = next((key for title, key in FAILING_BLOCKS if s.startswith(title) and s.endswith(":")), None)
        if block_key is not None:
            current = block_key
            skipping = isinstance(failing.get(block_key), list)
            if skipping:
                continue
        if skipping and (s.startswith("- **") or s.startswith("- Notes, not headlines")
                         or s.startswith("- " + next_steps.MORE_LINE) or s.startswith("- " + next_steps.REACHED_LINE)):
            continue  # a line the table, the more line or the notes line under it says again
        out.append((current, s[2:] if s.startswith("- ") else s))
    return out


def failing_sequence(failing):
    """next_steps.md's What is failing in its own order: ("block", key)
    where one of its lists starts (FAILING_BLOCKS), ("line", text) for a
    sentence outside every list. The page puts each table where its list
    starts and each sentence where next_steps.md has it, so a 'No genuine
    failures in the mail log' line never moves below the outside table."""
    seq, seen, current = [], set(), None
    for line in _list(failing.get("lines")):
        s = line.strip() if isinstance(line, str) else ""
        if not s:
            current = None
            continue
        key = next((k for title, k in FAILING_BLOCKS if s.startswith(title) and s.endswith(":")), None)
        if key is not None:
            current = key
            if key not in seen:
                seen.add(key)
                seq.append(("block", key))
            continue
        if current is None:
            seq.append(("line", s[2:] if s.startswith("- ") else s))
    return seq


def failing_rest(failing):
    """What is failing's other sentences, in next_steps.md's order (failing_kept without the blocks)."""
    return [line for _, line in failing_kept(failing)]


def _as_names(e):
    """The From domains an outside source fails as: the document's own words for them ("as", the busiest
    first and the rest counted, as next_steps.md says them), else the first two it lists; each name breaking
    between its labels only."""
    said = _text(e.get("as"))
    if said:
        return iso(prose(said))
    return ", ".join(text_name(h) for h in _texts(e.get("header_from"))[:2]) or "?"


def _envelopes(e):
    """A sender row's Envelope cell: the envelope domain its mail came in by,
    or - for an address whose failures came through several - the busiest
    with their counts and how many more, in next_steps.md's words
    (next_steps.envelope_parts); each name breaks between its labels only."""
    envs = [x for x in _list(e.get("envelopes")) if isinstance(x, dict) and _text(x.get("name"))]
    if len(envs) > 1:
        named, more = next_steps.envelope_parts({"envelopes": envs})
        items = ["%s x%s" % (plain_name(n), esc(_count(c))) for n, c in named] + (["%d more" % more] if more else [])
        return ", ".join(items[:-1]) + " and " + items[-1]
    return plain_name(e.get("envelope")) if _text(e.get("envelope")) else ""


def failing_tables(failing):
    """The headline entries of next_steps.md's What is failing lists as
    tables, each split as next_steps.md splits it (next_steps.headline_split:
    the first TOP_ENTRIES at HEADLINE_MIN messages or more in the table, the
    others at HEADLINE_MIN or more on the MORE_LINE line, the rest on the
    notes line, each entry once), then the document's own lines that belong
    to that list (a formal exception it does not count)."""
    kept = failing_kept(failing)

    def own(key):
        return [line for k, line in kept if k == key]
    parts = []
    env = [e for e in _list(failing.get("by_envelope")) if isinstance(e, dict)]
    head, more, notes = next_steps.headline_split(env)
    rows = []
    for e in head:
        senders = _texts(e.get("senders"))
        n = _num(e.get("sender_count")) or len(senders)
        detail = []
        if n:
            detail.append(esc(_counted(n, "sender address", "sender addresses")))
        if senders:
            detail.append("such as %s" % ", ".join(text_name(s) for s in senders[:2]))
        rows.append('<tr><td class="name">%s</td><td class="num">%s</td><td>%s</td><td>%s%s</td></tr>'
                    % (plain_name(e.get("name")), esc(_count(e.get("count"))), esc(_label(e)), "; ".join(detail),
                       _subjects(e)))
    parts.append(failing_block("By envelope domain", "who actually handed the mail over", rows,
                               ("Envelope domain", "Messages", "Label", "Senders"), more, notes,
                               next_steps.NOTES_LINE, own("by_envelope"), "list env"))
    snd = [e for e in _list(failing.get("by_sender")) if isinstance(e, dict)]
    # one row per address and label group (next_steps.label_rows), and a spoof with a lure word that reached a
    # mailbox gets a row of its own under HEADLINE_MIN too (next_steps.reached_split), as next_steps.md gives it a line
    reached, snd = next_steps.reached_split(snd)
    head, more, notes = next_steps.headline_split(snd)
    rows = ['<tr><td class="name">%s</td><td class="num">%s</td><td>%s</td><td>%s</td><td class="name">%s</td></tr>'
            % (plain_name(e.get("name")), esc(_count(e.get("count"))), esc(_label(e)), _subjects(e), _envelopes(e))
            for e in head]
    rows += ['<tr class="reached"><td class="name">%s</td><td class="num">%s</td><td>%s %s</td><td>%s</td>'
             '<td class="name">%s</td></tr>'
             % (plain_name(e.get("name")), esc(_count(e.get("count"))), esc(_label(e)),
                pill("bad", "reached inboxes: %s" % _count(e.get("reached"))), _subjects(e), _envelopes(e))
             for e in reached]
    parts.append(failing_block("By sender address", "what the reader sees in From", rows,
                               ("Sender", "Messages", "Label", "Subjects", "Envelope"), more, notes,
                               next_steps.NOTES_LINE, own("by_sender"), "list snd"))
    out = [e for e in _list(failing.get("outside")) if isinstance(e, dict)]
    head, more, notes = next_steps.headline_split(out)
    rows = []
    for e in head:
        disp = ", ".join("%s %s" % (_num(v), iso_text(k)) for k, v in _dict(e.get("dispositions")).items() if _num(v))
        rows.append('<tr><td class="name">%s</td><td class="num">%s</td><td class="name">%s</td><td>%s</td><td>%s</td></tr>'
                    % (plain_name(e.get("name")), esc(_count(e.get("count"))), _as_names(e), esc(_label(e)), disp))
    parts.append(failing_block("From the outside", "aggregate reports; these counts include forwarded copies and "
                               "cannot be deduplicated", rows, ("Source", "Failing", "As", "Label", "Receivers"),
                               more, notes, next_steps.OUTSIDE_NOTES_LINE, own("outside"), "list out"))
    return dict(zip(("by_envelope", "by_sender", "outside"), parts))


def failing_block(title, sub, rows, heads, more, notes, notes_lead, extra=(), cls=""):
    """One What is failing list: its title, the table of headline rows (cls:
    its class in TABLE_CLASSES), the line of the others at HEADLINE_MIN or
    more (next_steps.MORE_LINE) and the notes line (notes_lead,
    next_steps.md's words for that list), each capped at NOTES_CAP as
    next_steps.md caps it, then the document's lines that belong to it
    (extra). A list with no table keeps only those lines, in its place."""
    lines = [esc(lead) + _note_line(entries) for lead, entries in ((next_steps.MORE_LINE, more),
                                                                   (notes_lead, notes)) if entries]
    if not rows and not lines:
        return bullets(extra) if extra else ""
    inner = table(heads, rows, numeric=(1,), cls=cls) if rows else ""
    inner += "".join('<p class="note">%s</p>' % line for line in lines)
    if extra:
        inner += bullets(extra)
    return '<div class="group"><h3>%s <span class="sub">%s</span></h3>%s</div>' % (esc(title), esc(sub), inner)


def failing_section(doc):
    failing = _dict(doc.get("failing"))
    tables = failing_tables(failing)
    parts, used, run = [], set(), []
    for kind, value in failing_sequence(failing):
        if kind == "line":
            run.append(value)
            continue
        if run:
            parts.append(bullets(run))
            run = []
        if tables.get(value):
            parts.append(tables[value])
        used.add(value)
    if run:
        parts.append(bullets(run))
    # a list the document's lines never open (an older or a hand-made document): in the usual place, after
    parts += [tables[k] for k in ("by_envelope", "by_sender", "outside") if k not in used and tables.get(k)]
    notes = _texts(failing.get("notes"))
    if notes:
        parts.append('<div class="group"><p class="note">Notes:</p>%s</div>' % bullets(notes, "lines note"))
    return section("failing", "What is failing", parts)


def _id_order(ref):
    """A plan row's place by its id's digits, compared as (length, digits) without leading zeros: no int() of a
    damaged id that runs to thousands of digits, and P-7 still before P-12."""
    m = re.match(r"^P-(\d+)$", _text(ref))
    digits = (m.group(1).lstrip("0") or "0") if m else ""
    return (len(digits), digits)


def _action_key(item, idx, head):
    """An owner's items in the order next_steps.py gives them
    (next_steps._item_key): by kind - the zero-risk records, the other plan
    rows in plan order (their ids follow it), sender fixes, overrides,
    outside and unknown sources, other findings, anything else last - then
    by organization (the headline's first, a tenant-wide item after the
    others) and the first domain it concerns, then as the document listed
    them. A document the generator wrote is in this order already, so the
    page keeps it item for item; one listed out of order is put back."""
    kind = _text(item.get("kind"))
    order = _id_order(item.get("ref")) if kind == "dns" else (0, "")
    names = _texts(item.get("domains"))
    return (ACTION_RANK.get(kind, 6), order, not names, dkey(item.get("org"), head),
            dkey(names[0] if names else "", head), idx)


def _filed(item):
    """What next_steps.owner_parts reads of an item - the organizations it
    concerns - as text only (a damaged value reads as none, never as Python
    spells it), with the item itself beside it."""
    view = {"org": _text(item.get("org")), "item": item}
    if isinstance(item.get("orgs"), list):
        view["orgs"] = _texts(item["orgs"])
    return view


def action_item(item):
    """One owner's item: its hook, then what to do and its reference. An item
    from a plan row that names its prerequisites apart (summary and
    prerequisites in next_steps.json) reads as its summary, then a compact
    checklist of what must be true before it is applied - the same words
    next_steps.md puts in its '(before applying: ...)' clause."""
    ref = ref_tags(item.get("ref"))
    hook = '<span class="hook">%s</span>' % prose(_text(item.get("hook")))
    summary, prereqs = _text(item.get("summary")), item.get("prerequisites")
    if summary and isinstance(prereqs, list):
        head = "%s %s%s" % (hook, iso(prose(summary)), (" " + ref) if ref else "")
        checks = _texts(prereqs)
        if not checks:
            return "<li>%s</li>" % head
        return ('<li class="item"><p>%s</p><div class="pre"><p class="k">Before applying</p>%s</div></li>'
                % (head, checklist(checks, "checklist compact")))
    return '<li>%s %s%s</li>' % (hook, iso(prose(_text(item.get("action")))), (" " + ref) if ref else "")


def owner_group(g, head):
    """One owner with its channel and its items, in next_steps.md's order
    (_action_key) and split as next_steps.md splits them - the same helper,
    next_steps.owner_parts: a group of GROUP_BY_ORG items or more that
    spans two organizations or more gets a line per organization (the
    headline's first, then by name) with the items that concern it alone,
    one item included, then Several organizations, then Tenant-wide, each
    with its count; a smaller group, or one whose items name no
    organization (an older next_steps.json), stays one list."""
    items = [(i, it) for i, it in enumerate(_list(g.get("items"))) if isinstance(it, dict)]
    if not items:
        return ""
    title = '<h3>%s%s</h3>' % (iso(prose(_text(g.get("owner")) or next_steps.UNASSIGNED)),
                               (' <span class="channel">%s</span>' % esc(g["channel"])) if _text(g.get("channel")) else "")
    ordered = [_filed(it) for _, it in sorted(items, key=lambda t: _action_key(t[1], t[0], head))]
    body = []
    for name, part in next_steps.owner_parts(ordered, head):
        lines = '<ul class="lines">%s</ul>' % "".join(action_item(v["item"]) for v in part)
        if name is None:
            body.append(lines)
            continue
        label = esc(name) if name in (next_steps.SEVERAL_ORGS, next_steps.TENANT_WIDE) else iso_text(name)
        body.append('<div class="org-block"><p class="org-head">%s <span class="count">%s</span></p>%s</div>'
                    % (label, _counted(len(part), "item"), lines))
    return '<div class="owner">%s%s</div>' % (title, "".join(body))


def owners_section(doc, head):
    """What happens next, by owner. A document that lists no item says what
    next_steps.md says there - nothing to do this week, and why - in its
    own words; Not in this run. only when the document has no such list."""
    groups = doc.get("actions_by_owner")
    parts = [p for p in (owner_group(g, head) for g in _list(groups) if isinstance(g, dict)) if p]
    if not parts and isinstance(groups, list):
        parts = ['<p class="empty">%s</p>' % prose(line[2:] if line.startswith("- ") else line)
                 for line in next_steps.render_actions([], _dict(doc.get("failing")))]
    return section("owners", "What happens next, by owner", parts)


def ask_section(doc):
    text = _text(doc.get("ask"))
    return section("ask", "The ask", ['<div class="ask"><p>%s</p></div>' % prose(text)] if text else [])


def _priority(c):
    p = c.get("priority")
    return p if isinstance(p, int) and not isinstance(p, bool) else None


def plan_head(plan, head):
    """The organization the plan's rows and holds are led by: the headline
    plan.py recorded in plan.json, which a status document that names
    another organization (next_steps.py --org-name) does not move; for a
    plan that records none (written before it did), the document's."""
    plan = _dict(plan)
    if "headline" in plan:
        return _text(plan.get("headline")) or None
    return head


def plan_order(changes, head, by_ids=False):
    """plan.json's rows in the plan's own order - the order plan.py numbered
    the ids in, and the one plan.md, todo.md and verify.md follow - whatever
    order the file lists them in: plan.row_key (priority, DNS host with
    unknown last, zone and domain in the one order led by head - the plan's
    own headline, plan_head - then record and hostname), the ids breaking a
    tie as plan.py's stable sort did. by_ids: the plan records no headline
    (an older plan.json), so its ids are its order whenever every row
    carries one, and row_key with the document's headline is left for a
    plan whose rows do not. Each row is read through a clean copy, so a
    damaged priority or name sorts last instead of stopping the sort."""
    ids = [_id_order(c.get("id")) for c in changes]
    if by_ids and changes and all(i[0] for i in ids) and len(set(ids)) == len(ids):
        return [changes[k] for k in sorted(range(len(changes)), key=lambda k: ids[k])]

    def safe(c):
        p = _priority(c)
        return {"priority": p if p is not None else math.inf, "zone_host": _text(c.get("zone_host")),
                "zone": _text(c.get("zone")), "domain": _text(c.get("domain")), "hostname": _text(c.get("hostname"))}
    try:
        return [changes[k] for k in sorted(range(len(changes)), key=lambda k: (
            plan_mod.row_key(safe(changes[k]), head), ids[k], k))]
    except Exception:  # a key the plan's own sort cannot read: as plan.json lists them
        return list(changes)


SHORT_FIELD = 12  # characters a Type or TTL value may have and still take only the width it needs, unwrapped


def _short(value):
    """' short' for a Type or TTL value of SHORT_FIELD characters or fewer
    (TXT, CNAME, 3600): its field takes the width the value needs and never
    wraps it, so 3600 never reads as 360 over 0; a longer (damaged) value
    keeps the field's own column and wraps."""
    return " short" if len(value) <= SHORT_FIELD else ""


# a row's status (plan.row_status) as a pill: the class from this fixed map, the words the plan's own
STATUS_PILLS = {"now": "ok", "check": "warn", "address": "bad", "held": "bad", "host": "info", "later": "info",
                "gated": "info"}


def status_pill(c):
    """The row's status pill: its status_text up to any parenthesis ('held',
    never '(Per domain says why)' in a pill), colored by STATUS_PILLS; ''
    for a row with no status the plan recognizes."""
    status, text, _ = plan_mod.status_of(c)
    if status not in STATUS_PILLS:
        return ""
    return pill(STATUS_PILLS[status], text.split(" (", 1)[0])


def record_card(c, n):
    """One plan row as a record card (its id on the page is its place, n):
    its status first, as a pill (plan.row_status), then id, kind and domain;
    what it does in plain words; the host name, type and TTL side by side
    (the two short ones as wide as their values), then the value, the
    current value and the rollback; the prerequisites as a compact
    checklist; the why, muted. A row that does not go out this week (held,
    gated, after another row) is a quiet card, with what holds it under the
    head."""
    kind = _text(c.get("kind"))
    rid = _text(c.get("id"))
    status, _, reason = plan_mod.status_of(c)
    head_parts = [status_pill(c), tag(rid, "tag rid") if rid else "",
                  '<span class="k">%s</span>' % esc(plan_mod.KIND_LABEL.get(kind, kind)),
                  '<span class="name">%s</span>' % name_html(c.get("domain")),
                  " ".join(tag(f) for f in _texts(c.get("finding_ids")))]
    rtype, ttl = _shown(c.get("record")), _shown(c.get("ttl"))
    fields = (("Host name", '<span class="mono">%s</span>' % plain_name(c.get("hostname")), ""),
              ("Type", '<span class="mono">%s</span>' % esc(rtype), _short(rtype)),
              ("TTL", '<span class="mono">%s</span>' % esc(ttl), _short(ttl)),
              ("Value", '<pre class="value">%s</pre>' % esc(_shown(c.get("value"))), " wide"),
              ("Current", '<span class="mono muted">%s</span>' % esc(_shown(c.get("current"))), " wide"),
              ("Rollback", prose(_shown(c.get("rollback"))), " wide"))
    parts = ['<div class="card-head">%s</div>' % " ".join(p for p in head_parts if p)]
    if reason and status in ("held", "gated"):  # what holds it, in the plan's words; a check is listed below
        parts.append('<p class="held">%s</p>' % prose(("Held by: " if status == "held" else "The gate: ") + reason))
    if _text(c.get("human_summary")):
        parts.append("<p>%s</p>" % prose(c["human_summary"]))
    parts.append('<dl class="fields">%s</dl>' % "".join('<div class="field%s"><dt>%s</dt><dd>%s</dd></div>'
                                                       % (wide, esc(k), v) for k, v, wide in fields))
    prereqs = _texts(c.get("prerequisites"))
    if prereqs:
        parts.append('<div class="pre"><p class="k">Before applying</p>%s</div>' % checklist(prereqs, "checklist compact"))
    if _text(c.get("why")):
        parts.append('<p class="why">%s</p>' % prose(c["why"]))
    quiet = " quiet" if status in plan_mod.WAITING_STATUSES else ""
    return '<article class="card%s" id="%s">%s</article>' % (quiet, CARD_ID % n, "".join(parts))


def plan_index(rows):
    """Every row at a glance, in the cards' order: its id (a link to its
    card), its status (plan.row_status, as the card's pill), priority, host
    name, kind and how many checks wait before it - so a publisher scans
    the whole plan at once, sees which rows can go out, and jumps to one."""
    body = []
    for n, c in enumerate(rows, 1):
        kind = _text(c.get("kind"))
        checks = len(_texts(c.get("prerequisites")))
        body.append('<tr><td><a href="#%s">%s</a></td><td class="status">%s</td><td class="num">%s</td>'
                    '<td class="name">%s</td><td>%s</td><td class="num">%s</td></tr>'
                    % (CARD_ID % n, esc(_text(c.get("id")) or "row %d" % n), status_pill(c),
                       esc(_shown(c.get("priority")) or "?"), plain_name(c.get("hostname")),
                       esc(plan_mod.KIND_LABEL.get(kind, kind)), checks or "none"))
    return table(("Id", "Status", "Priority", "Host name", "Kind", "Checks"), body, numeric=(2, 5), cls="index")


def address_note(plan):
    """plan.md's warning about the report address new records carry, when it
    is a placeholder (no record carrying it is ready: the step before them
    is choosing where reports go, with collect.py's own option for it) or
    one the run only derived."""
    rua = _text(plan.get("rua"))
    if plan.get("rua_is_placeholder"):
        return ('<p class="note"><strong>Choose where DMARC reports go first.</strong> No existing record carried a rua, '
                'so the new records here carry the placeholder <code>%s</code> and none of them is ready: choose a '
                'mailbox you own or a reporting service, then rerun collect.py with <code>--rua-address '
                'mailto:...</code> (or set RUA_MAILBOX in .env).</p>' % iso_text(rua))
    if plan.get("rua_derived"):
        return ('<p class="note"><strong>Check the reporting address.</strong> The run had no report address of its own, '
                'so new records use <code>%s</code>, the rua most existing records already use; if it is not a mailbox '
                'you read, rerun collect.py with <code>--rua-address mailto:...</code> (plan.md says more).</p>'
                % iso_text(rua))
    return ""


def dns_section(plan, head):
    """DNS changes, from plan.json when the run has one, laid out as plan.md
    lays it out: every row at a glance (each a link to its card), the holds
    as what to decide first, then one record card per row, grouped by
    priority (in plan.py's words), DNS host and zone, in the plan's own
    order (plan_order, led by the plan's own headline, plan_head). A plan
    that proposes nothing says so; Not in this run. means the run has no
    plan."""
    if not isinstance(plan, dict):
        return section("dns", "DNS changes", [])
    changes = [c for c in _list(plan.get("changes")) if isinstance(c, dict)]
    holds = [h for h in _list(plan.get("holds")) if isinstance(h, dict)]
    if not changes and not holds:
        return section("dns", "DNS changes", [], empty=EMPTY_PLAN)
    head = plan_head(plan, head)  # the plan's own order, whatever organization the document leads with
    rows = plan_order(changes, head, by_ids="headline" not in plan)
    parts = [address_note(plan)]
    if rows:
        parts.append(block("At a glance", plan_index(rows)))
    if holds:
        ordered = sorted(enumerate(holds), key=lambda t: (dkey(t[1].get("domain"), head), t[0]))
        parts.append(block("Decide first", '<ul class="lines">%s</ul>' % "".join(
            "<li>%s: %s</li>" % (name_html(h.get("domain")), prose(_text(h.get("reason")))) for _, h in ordered)))
    place = {id(c): n for n, c in enumerate(rows, 1)}
    for prio, in_prio in itertools.groupby(rows, key=_priority):
        title = "Priority %s" % prio if prio is not None else "Priority not stated"
        words = plan_mod.PRIORITY_LABEL.get(prio, "")
        inner = []
        for host, in_host in itertools.groupby(in_prio, key=lambda c: _text(c.get("zone_host")) or "unknown"):
            zones = []
            for zone, in_zone in itertools.groupby(in_host, key=lambda c: _text(c.get("zone")) or org_of(c.get("domain"))):
                zones.append('<p class="zone"><span class="k">Zone</span><span class="mono">%s</span></p>'
                             '<div class="cards">%s</div>' % (plain_name(zone), "".join(record_card(c, place[id(c)])
                                                                                 for c in in_zone)))
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
    heuristics, the items with no owner, then any other kind by name. A
    document whose list is empty says what next_steps.md says: None from
    this run."""
    raw = doc.get("open_questions")
    qs = [q for q in _list(raw) if isinstance(q, dict) and _text(q.get("question"))]
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
            items.append('<li>%s%s <span class="count owner">owner: %s</span></li>'
                         % (iso(prose(q["question"])), (' <span class="count">x %s</span>' % n) if n > 1 else "",
                            esc(_text(q.get("owner")) or "unassigned")))
        # a kind next_steps.py names in words is the page's own text; any other is the document's, isolated
        title = esc(words[k]) if words.get(k) else iso_text(k.replace("_", " ").capitalize())
        parts.append('<div class="group"><h3>%s <span class="count">%s</span></h3><ul class="lines">%s</ul></div>'
                     % (title, len(members), "".join(items)))
    return section("questions", "Open questions", parts, empty=NO_QUESTIONS if isinstance(raw, list) and not raw
                   else NOT_IN_RUN)


def glossary_section(doc):
    terms = [(k, v) for k, v in _dict(doc.get("glossary")).items() if isinstance(v, str) and v.strip()]
    if not terms:
        return section("glossary", "Glossary", [])
    return section("glossary", "Glossary", ['<dl class="glossary">%s</dl>' % "".join(
        '<div class="term"><dt>%s</dt><dd>%s</dd></div>' % (esc(k), prose(v)) for k, v in terms)])


def footer(doc, with_plan=False):
    """The sources the document was built from, when the report was
    generated, and which version of the toolkit wrote it; with_plan says
    whether the page read plan.json too. Each value from the document (a
    date - kept on one line too - a tool, a path) is isolated from the
    words around it."""
    src = _dict(doc.get("sources"))
    facts = []
    when, tool = _text(src.get("report_generated_utc")), _text(src.get("report_tool"))
    if when:
        facts.append("audit report generated %s%s" % (_unbroken(when), (" by " + iso_text(tool)) if tool else ""))
    if src.get("plan") is True:
        facts.append("rollout plan (%s, %s)" % (esc(_counted(_num(src.get("plan_changes")) or 0, "change")),
                                                esc(_counted(_num(src.get("plan_holds")) or 0, "hold"))))
    elif src.get("plan") is False:
        facts.append("no rollout plan")
    runs = _num(src.get("metrics_runs"))
    if runs is not None:
        facts.append("run history (%s)" % esc(_counted(runs, "run")))
    if _text(src.get("previous_report")):
        facts.append("previous report %s" % _unbroken(src["previous_report"].strip()))
    if _text(src.get("owners_file")):
        facts.append("owners file %s (%s)" % (iso_text(src["owners_file"].strip()),
                                              esc(_counted(_num(src.get("owner_patterns")) or 0, "pattern"))))
    elif "owners_file" in src:
        facts.append("no owners file")
    made = _text(doc.get("tool")) or "next_steps.py"
    version = _text(doc.get("version"))
    lines = []
    if facts:
        lines.append("<p>Sources: %s.</p>" % "; ".join(facts))
    lines.append("<p>Written by %s%s from the run's own data and laid out by brief.py from next_steps.json%s: every "
                 "number traces to the run's files, and no sentence here was written by an AI.</p>"
                 % (iso_text(made), (" " + iso_text(version)) if version else "", " and plan.json" if with_plan else ""))
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
    except RecursionError:
        raise BriefError("%s is nested too deeply to read" % path) from None
    if not isinstance(doc, dict):
        raise BriefError("%s is not one JSON object" % path)
    return doc


def write_atomic(target, text):
    """text into target, all or nothing: encoded first, written to a file
    beside it, then moved into its place. A failure on the way (a disk that
    fills, a character UTF-8 cannot carry) leaves the page that was there
    untouched and no half-written one."""
    target = Path(target)
    data = text.encode("utf-8", errors="replace")
    tmp = target.with_name(".%s.%d.tmp" % (target.name, os.getpid()))
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def write_run(run_dir, out=None, fragment=False):
    """brief.html for a run folder: its next_steps.json (required) and its
    plan.json (when there) in, the page written to out (default
    RUN_DIR/brief.html), all or nothing. collect.py and the command line
    both build it here, so a rerun on the same files gives the same bytes.
    Returns the path."""
    run = next_steps.repo_path(run_dir)
    doc = read_json(run / "next_steps.json", True)
    plan = read_json(run / "plan.json", False)
    target = next_steps.repo_path(out) if out else run / "brief.html"
    write_atomic(target, render(doc, plan, fragment))
    return target


def _console():
    """Print what a console code page cannot show as an escape, never a
    UnicodeEncodeError: a Windows console or pipe is often cp1252, and a
    run folder or an --out name may hold any character."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def main(argv=None):
    _console()
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
