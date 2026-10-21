#!/usr/bin/env python3
"""Check a polished status document against the run it came from.

Whoever polishes the toolkit's status document - a person, or an agent with
the dmarc-status-brief skill - may change the hooks, the order and the
audience, never a number, a verdict, a policy value, a plan id or a finding
id (AGENTS.md rule 13). This script reads the polished copy and the run's
own files, and names every token in the copy the run does not carry:

  - a number (digits, with dots between them: 21, 77.4, 203.0.113.5) that
    occurs nowhere in the run's files as a whole number; a number written
    with thousands separators (1,361) is read as the number it is (1361), a
    percentage (12%) must be one the run states (or its pass rate, or a
    pct= it writes), a date (2026-10-13) must be one of the run's dates as
    a whole, and a digit outside 0-9 (a fullwidth 4) is named and read as
    the digit it is
  - a plan id (P-07) that plan.json does not hold
  - a finding id (DMARC-002) that is neither among report.json's findings
    nor in report.md
  - a p=, sp= or pct= value the run's files never write (the fixed
    explanations a run prints whatever it found - p=reject in report.md's
    gate rule, and pct=10 in the example older runs gave of a low pct - do
    not count, in the run's files or in the copy)
  - the punctuation and spacing the voice rules forbid: any dash but the
    hyphen (the em dash, the en dash, the minus sign and the other Unicode
    dashes), curly and angle quotes, the ellipsis characters, any space but
    the plain one; in a Markdown or text copy an HTML entity counts as the
    character it renders (&mdash;). A stretch the copy quotes ("...") that
    the run's files hold word for word - a subject line as mail wrote it -
    keeps its own punctuation
  - the characters brief.html shows as a marker (brief.marked: a format
    character that reorders or hides the words around it, such as U+202E,
    U+200B or U+2063, and a control), named wherever they are, quoted data
    too; the format characters real mail text carries (a joiner in an
    emoji, a direction mark in a right-to-left subject, a soft hyphen, the
    tags of a flag) are text, never named

It checks what the copy says, not what it covers: 'P-02 to P-14' passes
when both ends are real plan ids, whichever rows lie between them.

The run's files are next_steps.md, next_steps.json, plan.json, plan.md,
report.md, todo.md, summary.txt and verify.md, whichever exist; a JSON file
is read as the text it holds (an escape such as \\u2019 is the character it
stands for, never a number), and quoted absolute paths in them are blanked
first (a digit in a folder name is not evidence). Some figures are derived
rather than copied, and allowed: the pass rate as a percentage, the
numbers of the mail log's span as next_steps.py words it, for the windows
in report.json, and the counts brief.html works out (names per
organization, the items under each line of an owner group, checks before
a plan row).

  python scripts/check_doc.py audit-out/latest/polished/leadership.md
  python scripts/check_doc.py polished-ticket.md --run audit-out/history/<run>

FILE is markdown or text; an .html file is read as the text a browser shows
(comments, styles and scripts dropped, a block tag a space, entities
decoded), line for line. The output is one line per problem, `line N:
<token>: <why>`, where line N is the file's line N, counting line feeds
only, and never the file's other content; a character a console cannot
show is printed as an escape. Relative paths resolve from the repo root, as
in every tool here; --run defaults to audit-out/latest.

Exit codes: 0 clean, 1 problems found, 2 usage error (a file that cannot be
read, a run folder holding none of the run's files). Never a traceback.
"""

import argparse
import bisect
import html
import itertools
import json
import re
import sys
import unicodedata
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import brief  # noqa: E402  (clean, and the counts brief.html derives: the page as the run lays it out)
import next_steps  # noqa: E402  (span_phrase: the mail log's span, in the document's words)

DEFAULT_RUN = "audit-out/latest"
CORPUS = ("next_steps.md", "next_steps.json", "plan.json", "plan.md", "report.md", "todo.md", "summary.txt",
          "verify.md")
PATH_RX = re.compile(r'"(?:[A-Za-z]:\\\\|/)[^"\n]*"')  # a quoted absolute path, as JSON writes one
# every digit is read as 0-9 first (ascii_digits), so the patterns below spell digits as [0-9]
NUMBER_RX = re.compile(r"[0-9]+(?:\.[0-9]+)*")
DATE_RX = re.compile(r"(?<![0-9.])[0-9]{4}-[0-9]{2}-[0-9]{2}(?![0-9])")
GROUPED_RX = re.compile(r"(?<![0-9.,])[0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?(?![0-9])(?!,[0-9])")
PERCENT_RX = re.compile(r"(?<![0-9.])([0-9]+(?:\.[0-9]+)?) ?%")
CODEPOINT_RX = re.compile(r"(?<![A-Za-z0-9])U\+[0-9A-F]{4,6}(?![0-9A-Za-z])")  # a character named, as brief.html does
CHARREF_RX = re.compile(r"&#(?:[0-9]+|[xX][0-9A-Fa-f]+);")
OTHER_DIGIT_RX = re.compile(r"(?![0-9])\d")  # a decimal digit outside 0-9: fullwidth, Arabic-Indic, Devanagari...
PLAN_ID_RX = re.compile(r"(?<![A-Za-z0-9_-])P-[0-9]+(?![0-9])")
FINDING_ID_RX = re.compile(r"(?<![A-Za-z0-9_-])(?!P-[0-9])[A-Z]+-[0-9]{3}(?![0-9])")
POLICY_RX = re.compile(r"(?<![A-Za-z0-9_])(?:p|sp|pct)=[A-Za-z0-9]+", re.I)
QUOTED_RX = re.compile(r'"([^"\n]*)"')
ODD_RX = re.compile(r"[^\t\x20-\x7e]")  # any character the voice check looks at: all but printable ASCII and tab
# the explanations the run's files print on every run, whatever the run found: report.md's gate rule and the label
# of its DKIM evidence line name p=reject, and in runs before round 13 the gate's first enforcement step gave pct=10
# as an example of a low pct (it now names the plan's first ramp step, a value the run states; the entry stays so an
# older run still checks clean). A value in them is not a value the run states, so none is read there - in the run's
# files or in the copy
FIXED_TEXT = (re.compile(r"(?m)^Gate rule: .*$"), re.compile(r"aligned-DKIM evidence \(needed before p=reject\)"),
              re.compile(r"\(for example pct=10\)"))
# the voice rules: hyphens only, straight quotes, three dots, plain spaces, nothing invisible (code points as
# numbers, so this file stays ASCII and passes its own check); unicodedata classes the rest (voice)
VOICE = {0x2014: ("an em dash", "use a hyphen"), 0x2013: ("an en dash", "use a hyphen"),
         0x2010: ("a Unicode hyphen", "use a hyphen"), 0x2011: ("a non-breaking hyphen", "use a hyphen"),
         0x2012: ("a figure dash", "use a hyphen"), 0x2015: ("a horizontal bar", "use a hyphen"),
         0x2212: ("a minus sign", "use a hyphen"), 0x2026: ("the ellipsis character", "use three dots"),
         0x22EF: ("an ellipsis character", "use three dots"), 0xFE19: ("an ellipsis character", "use three dots"),
         0x00A0: ("a non-breaking space", "use a plain space"),
         0x202F: ("a narrow non-breaking space", "use a plain space"),
         0x201A: ("a curly quote", "use a straight quote"), 0x201E: ("a curly quote", "use a straight quote"),
         0xFF02: ("a fullwidth quote", "use a straight quote"), 0xFF07: ("a fullwidth quote", "use a straight quote"),
         0x00B4: ("an accent used as a quote", "use a straight quote")}
VOICE.update({code: ("a prime used as a quote", "use a straight quote") for code in range(0x2032, 0x2038)})
VOICE.update({code: ("a curly quote", "use a straight quote") for code in (0x2018, 0x2019, 0x201B, 0x201C, 0x201D,
                                                                           0x201F)})
VOICE_BY_CLASS = {"Pd": ("a Unicode dash", "use a hyphen"), "Pi": ("an angle or curly quote", "use a straight quote"),
                  "Pf": ("an angle or curly quote", "use a straight quote"), "Zs": ("a Unicode space", "use a plain space"),
                  "Zl": ("a Unicode line break", "use a plain line break"),
                  "Zp": ("a Unicode line break", "use a plain line break")}
# the characters brief.html shows as a marker (brief.marked: one that reorders or hides the text around it, or a
# control): never data's own punctuation, so named even inside a quote. The other format characters - a joiner in an
# emoji, a direction mark in a right-to-left subject, a soft hyphen - are text, and named nowhere
UNSEEN = (("an invisible character", "delete it"), ("a control character", "delete it"))
INLINE_TAGS = frozenset(("a", "abbr", "b", "bdi", "bdo", "cite", "code", "data", "dfn", "em", "i", "kbd", "mark", "q",
                         "s", "samp", "small", "span", "strong", "sub", "sup", "time", "u", "var", "wbr"))
QUOTE_LOOKUPS = 64  # quoted stretches looked up in the run's files per line, at most: a hostile line stays cheap


class UsageError(Exception):
    """A file or folder that cannot be read; main turns it into exit 2."""


def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def shown(text):
    """A token or a path as the output prints it: ASCII, anything else as an escape (\\u2014), so no console code
    page can turn a problem into a crash, and no character in the copy can redraw the line it is printed on."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


def read_text(path, what):
    """A file's text, its line breaks as line feeds: a CRLF file reads as its lines, and a lone carriage return
    or a Unicode line separator stays a character on its line, so line N is the file's line N."""
    try:
        return path.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")
    except FileNotFoundError:
        raise UsageError("%s %s does not exist" % (what, path)) from None
    except OSError as exc:
        raise UsageError("cannot read %s %s: %s" % (what, path, exc.strerror or exc)) from None
    except UnicodeDecodeError:
        raise UsageError("%s %s is not UTF-8 text" % (what, path)) from None


def ascii_digits(text):
    """Every decimal digit as its 0-9 twin, one character for one (positions hold): a fullwidth 43 is 43."""
    if text.isascii():
        return text
    return OTHER_DIGIT_RX.sub(lambda m: str(unicodedata.digit(m.group(0), 0)), text)


def _flat(text):
    """Decoded text that must stay on its line: a line break an entity spelled is a space."""
    return text.replace("\r", " ").replace("\n", " ")


class _Text(HTMLParser):
    """An HTML file's text as a browser lays it out, line for line: styles,
    scripts and comments dropped, a block tag a space (two cells never run
    together), an inline tag nothing (a name a page breaks with <wbr> or
    spans stays one name), entities decoded in place. Every piece of text
    lands on the source line it starts on, so line N is the file's line N.
    Linear in the size of the file, whatever it holds."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.lines = [[]]
        self.hidden = None

    def put(self, text):
        at = self.getpos()[0] - 1
        for i, part in enumerate(text.split("\n")):
            while len(self.lines) <= at + i:
                self.lines.append([])
            self.lines[at + i].append(part)

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.hidden = tag
        if tag not in INLINE_TAGS:
            self.put(" ")

    def handle_startendtag(self, tag, attrs):
        if tag not in INLINE_TAGS:
            self.put(" ")

    def handle_endtag(self, tag):
        if tag == self.hidden:
            self.hidden = None
        if tag not in INLINE_TAGS:
            self.put(" ")

    def handle_data(self, data):
        if not self.hidden:
            self.put(data)

    def handle_entityref(self, name):
        if not self.hidden:
            self.put(_flat(html.unescape("&%s;" % name)))

    def handle_charref(self, name):
        if not self.hidden:
            self.put(_flat(html.unescape("&#%s;" % name)))

    def text(self):
        return "\n".join("".join(parts) for parts in self.lines)


def html_text(raw):
    """An HTML file's text, line for line (_Text); a file the parser cannot
    read at all is checked as it is written."""
    p = _Text()
    try:
        p.feed(raw)
        p.close()
    except Exception:  # never a traceback: the raw text still has its numbers and its lines
        return raw
    return p.text()


def corpus_text(path):
    """One run file's text as the checks read it: a JSON file as the text it
    holds (re-written with its characters, so \\u2019 is a quote, never the
    number 2019); one that does not parse, as it is written."""
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            raw = json.dumps(json.loads(raw), ensure_ascii=False, indent=1)
        except (ValueError, RecursionError):
            pass
    return PATH_RX.sub('""', raw)


def _json(path):
    """A run's JSON file as an object; {} when it is missing or damaged
    (nested past what the parser can read, too) - the checks it feeds then
    find nothing there, and say so."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _dig(obj, *keys):
    """obj[k1][k2]... through objects only; None when a level is missing or damaged."""
    for k in keys:
        obj = obj.get(k) if isinstance(obj, dict) else None
    return obj


def _rate(value):
    """'77.4' for a pass rate of 0.774, as the documents print it; None for anything that is not a rate."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return None
    try:
        return "%.1f" % (100 * value)
    except (OverflowError, ValueError):
        return None


def derived_counts(doc, plan):
    """The counts brief.html works out from the run's files rather than
    copies: the names an organization holds in the per-domain table, the
    items under each line of an owner group (next_steps.owner_parts, the
    split next_steps.md prints too), and the checks that wait before each
    plan row. A copy of the page may quote them."""
    out = set()
    try:
        head = brief._text(doc.get("org_domain")) or None
        entries, grouped = brief.domain_rows(doc, plan or None, head)
        if grouped:
            out |= {str(len(list(m))) for _, m in itertools.groupby(entries, key=lambda e: e["org"])}
        for g in brief._list(doc.get("actions_by_owner")):
            items = [brief._filed(it) for it in brief._list(g.get("items") if isinstance(g, dict) else None)
                     if isinstance(it, dict)]
            out |= {str(len(part)) for name, part in next_steps.owner_parts(items, head) if name is not None}
        out |= {str(len(brief._texts(c.get("prerequisites")))) for c in brief._list(plan.get("changes"))
                if isinstance(c, dict)}
    except Exception:  # a damaged file derives nothing
        pass
    return out


def _blank_fixed(text):
    for rx in FIXED_TEXT:
        text = rx.sub("", text)
    return text


class Run:
    """What one run's files carry: the whole numbers, the dates, the
    percentages, the policy values, the plan ids and the finding ids a
    polished copy may quote, and their text, for the stretches a copy
    quotes word for word."""

    def __init__(self, run_dir):
        self.dir = run_dir
        texts = {}
        for name in CORPUS:
            p = run_dir / name
            if p.is_file():
                try:
                    texts[name] = corpus_text(p)
                except OSError as exc:
                    raise UsageError("cannot read %s: %s" % (p, exc.strerror or exc)) from None
        if not texts:
            raise UsageError("%s holds none of the run's files (%s): pass --run with a run folder"
                             % (run_dir, ", ".join(CORPUS)))
        corpus = ascii_digits("\n".join(texts.values()))
        self.text = corpus
        self._shown = None
        self.numbers = set(NUMBER_RX.findall(corpus)) | {g.replace(",", "") for g in GROUPED_RX.findall(corpus)}
        self.dates = set(DATE_RX.findall(corpus))
        self.percents = set(PERCENT_RX.findall(corpus))
        self.policies = {m.lower() for m in POLICY_RX.findall(_blank_fixed(corpus))}
        self.percents |= {p.split("=", 1)[1] for p in self.policies if p.startswith("pct=")}  # pct=25 is 25%
        report = _json(run_dir / "report.json")
        # derived, not copied: the pass rate as a percentage, and the mail log's span in the document's words
        rates = [_dig(report, "rua", "totals", "pass_rate"),
                 _dig(_json(run_dir / "next_steps.json"), "stand", "spoofing_blocked", "pass_rate")]
        for r in filter(None, map(_rate, rates)):
            self.numbers.add(r)
            self.percents.add(r)
        by = _dig(report, "maillog", "window_by_domain")
        for window in [_dig(report, "maillog", "window"), *(by.values() if isinstance(by, dict) else ())]:
            try:
                phrase = next_steps.span_phrase(window)
            except Exception:  # a damaged window is no span to allow
                phrase = None
            if phrase:
                self.numbers |= set(NUMBER_RX.findall(phrase))
                self.dates |= set(DATE_RX.findall(phrase))
        plan = _json(run_dir / "plan.json")
        changes = _dig(plan, "changes")
        self.has_plan = (run_dir / "plan.json").is_file()
        self.plan_ids = {str(c["id"]) for c in (changes if isinstance(changes, list) else [])
                         if isinstance(c, dict) and c.get("id")}
        self.numbers |= derived_counts(_json(run_dir / "next_steps.json"), plan)
        findings = _dig(report, "findings")
        self.finding_ids = {str(f["id"]) for f in (findings if isinstance(findings, list) else [])
                            if isinstance(f, dict) and f.get("id")}
        self.finding_ids |= set(FINDING_ID_RX.findall(ascii_digits(texts.get("report.md", ""))))

    def holds(self, stretch):
        """True when the run's files hold this stretch word for word: as mail
        wrote it, or as brief.html shows it (an invisible character as its
        [U+...] marker, a subject cut short with three dots)."""
        stretch = ascii_digits(stretch)
        if stretch.endswith("...") and len(stretch) > 3:
            stretch = stretch[:-3]
        if not stretch.strip() or stretch in self.text:
            return bool(stretch.strip())
        if self._shown is None:
            self._shown = brief.clean(self.text)
        return stretch in self._shown


def voice(ch):
    """(what it is, the fix) when the voice rules forbid this character, else None. A character brief.html marks
    is UNSEEN (a control, or one that reorders or hides the text around it); a format character it shows as
    itself is no problem anywhere."""
    code = ord(ch)
    if code in VOICE:
        return VOICE[code]
    if code < 0x80:
        return None if ch == "\t" or " " <= ch <= "~" else UNSEEN[1]
    if brief.marked(ch):
        return UNSEEN[1] if unicodedata.category(ch) == "Cc" else UNSEEN[0]
    cat = unicodedata.category(ch)
    if cat == "Nd":
        return ("a non-ASCII digit", "write 0-9")
    return VOICE_BY_CLASS.get(cat)


def punctuation(line, run):
    """[(position, token, why)] for the characters the voice rules forbid in
    one line, each character once (and a non-ASCII digit once, whichever
    it is), at its first place outside a quoted stretch the run's files
    hold word for word: a subject line keeps the quotes and dots mail wrote
    it with. A character no reader can see (U+200B, U+202E) is named
    wherever it is, quoted data or not: in a copy it would hide or reorder
    the words around it, so it is written as brief.html shows it."""
    found, reported = [], set()  # a character once per line; every non-ASCII digit counts as one
    spans = [(m.start(1), m.end(1)) for m in QUOTED_RX.finditer(line)]
    starts = [a for a, _ in spans]
    verdicts, lookups = {}, 0
    flag = brief.flag_tags(line)  # the tags of a flag's emoji sequence are text, as brief.html shows them
    for m in ODD_RX.finditer(line):
        ch = m.group(0)
        if m.start() in flag:
            continue
        rule = voice(ch)
        key = "digit" if rule and rule[0] == "a non-ASCII digit" else ch
        if rule is None or key in reported:
            continue
        at = m.start()
        i = bisect.bisect_right(starts, at) - 1
        if rule not in UNSEEN and i >= 0 and spans[i][0] <= at < spans[i][1]:
            if spans[i] not in verdicts and lookups < QUOTE_LOOKUPS:
                lookups += 1
                verdicts[spans[i]] = run.holds(line[spans[i][0]:spans[i][1]])
            if verdicts.get(spans[i]):
                continue
        reported.add(key)
        what, fix = rule
        if rule in UNSEEN:
            fix = "write it as brief.html shows it, [U+%04X], or delete it" % ord(ch)
        if what == "a non-ASCII digit":
            why = "%s: %s" % (what, fix)
        else:
            why = "%s: the voice rules forbid it, %s" % (what, fix)
        found.append((at, "U+%04X" % ord(ch), why))
    return found


def problems(text, run, entities=False):
    """[(line, token, why)] for every token in text the run does not carry,
    in reading order, each once per line. Lines are counted by line feeds
    only. entities: the copy is Markdown or text, where an HTML entity
    renders as its character - the voice check reads it so, and a numeric
    one (&#8212;) is no number."""
    out = []
    for n, raw in enumerate(text.split("\n"), 1):
        line = ascii_digits(raw)
        found = []
        taken = bytearray(len(line))

        def take(a, b):
            taken[a:b] = b"\x01" * (b - a)

        fixed = []
        for rx in FIXED_TEXT:
            for m in rx.finditer(line):
                take(*m.span())
                fixed.append(m.span())
        for rx in (CODEPOINT_RX, CHARREF_RX) if entities else (CODEPOINT_RX,):
            for m in rx.finditer(line):
                take(*m.span())
        for m in PLAN_ID_RX.finditer(line):
            take(*m.span())
            if m.group(0) not in run.plan_ids:
                found.append((m.start(), m.group(0), "plan id not in plan.json" if run.has_plan
                              else "plan id, and the run has no plan.json"))
        for m in FINDING_ID_RX.finditer(line):
            take(*m.span())
            if m.group(0) not in run.finding_ids:
                found.append((m.start(), m.group(0), "finding id not in report.json or report.md"))
        for m in POLICY_RX.finditer(line):
            if any(a <= m.start() < b for a, b in fixed):
                continue
            take(*m.span())
            if m.group(0).lower() not in run.policies:
                found.append((m.start(), m.group(0), "policy value the run's files never write"))
        for rx, why, value in ((DATE_RX, "date not in the run's files", lambda m: (m.group(0), run.dates)),
                               (PERCENT_RX, "percentage not in the run's files", lambda m: (m.group(1), run.percents)),
                               (GROUPED_RX, "number not in the run's files",
                                lambda m: (m.group(0).replace(",", ""), run.numbers))):
            for m in rx.finditer(line):
                if taken[m.start()]:
                    continue
                take(*m.span())
                token, known = value(m)
                if token not in known:
                    found.append((m.start(), m.group(0), why))
        for m in NUMBER_RX.finditer(line):
            if not taken[m.start()] and m.group(0) not in run.numbers:
                found.append((m.start(), m.group(0), "number not in the run's files"))
        found += punctuation(_flat(html.unescape(raw)) if entities else raw, run)
        seen = set()
        for _, token, why in sorted(found, key=lambda t: t[0]):
            if (token, why) not in seen:
                seen.add((token, why))
                out.append((n, token, why))
    return out


def _console():
    """Print what a console code page cannot show as an escape, never a UnicodeEncodeError (a Windows pipe is
    often cp1252, and a file or folder name may hold any character)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv=None):
    _console()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", metavar="FILE", help="the polished copy: markdown or text, or .html")
    ap.add_argument("--run", metavar="DIR", default=DEFAULT_RUN,
                    help="the run folder it was polished from (default: %s)" % DEFAULT_RUN)
    args = ap.parse_args(argv)
    try:
        path = repo_path(args.file)
        text = read_text(path, "file")
        is_html = path.suffix.lower() in (".html", ".htm")
        if is_html:
            text = html_text(text)
        run = Run(repo_path(args.run))
    except UsageError as exc:
        print("error: %s" % shown(exc), file=sys.stderr)
        return 2
    found = problems(text, run, entities=not is_html)
    for n, token, why in found:
        print("line %d: %s: %s" % (n, shown(token), why))
    if found:
        print("%d problem%s in %s against %s" % (len(found), "" if len(found) == 1 else "s", shown(path.name),
                                                 shown(run.dir)), file=sys.stderr)
        return 1
    print("clean: every number, id and policy value in %s is in the run's files" % shown(path.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
