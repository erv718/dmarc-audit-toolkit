#!/usr/bin/env python3
"""Check a polished status document against the run it came from.

Whoever polishes the toolkit's status document - a person, or an agent with
the dmarc-status-brief skill - may change the hooks, the order and the
audience, never a number, a verdict, a policy value, a plan id or a finding
id (AGENTS.md rule 13). This script reads the polished copy and the run's
own files, and names every token in the copy the run does not carry:

  - a number (digits, with dots between them: 21, 77.4, 203.0.113.5) that
    occurs nowhere in the run's files as a whole number
  - a plan id (P-07) that plan.json does not hold
  - a finding id (DMARC-002) that is neither among report.json's findings
    nor in report.md
  - a p=, sp= or pct= value the run's files never write (report.md's fixed
    explanation, which names p=reject on every run, does not count)
  - the punctuation the voice rules forbid: the em dash, the en dash and
    the other Unicode dashes, curly quotes, the ellipsis character and the
    non-breaking space

The run's files are next_steps.md, next_steps.json, plan.json, plan.md,
report.md, todo.md, summary.txt and verify.md, whichever exist; quoted
absolute paths in them are blanked first (a digit in a folder name is not
evidence). Two figures are derived rather than copied, and allowed: the
pass rate as a percentage, and the numbers of the mail log's span as
next_steps.py words it, for the windows in report.json.

  python scripts/check_doc.py audit-out/latest/polished/leadership.md
  python scripts/check_doc.py polished-ticket.md --run audit-out/history/<run>

FILE is markdown or text; an .html file is read as its text (comments,
styles and scripts dropped, tags blanked, entities decoded), line for line.
The output is one line per problem, `line N: <token>: <why>`, and never the
file's other content. Relative paths resolve from the repo root, as in every
tool here; --run defaults to audit-out/latest.

Exit codes: 0 clean, 1 problems found, 2 usage error (a file that cannot be
read, a run folder holding none of the run's files).
"""

import argparse
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import next_steps  # noqa: E402  (span_phrase: the mail log's span, in the document's words)

DEFAULT_RUN = "audit-out/latest"
CORPUS = ("next_steps.md", "next_steps.json", "plan.json", "plan.md", "report.md", "todo.md", "summary.txt",
          "verify.md")
PATH_RX = re.compile(r'"(?:[A-Za-z]:\\\\|/)[^"\n]*"')  # a quoted absolute path, as JSON writes one
NUMBER_RX = re.compile(r"\d+(?:\.\d+)*")
PLAN_ID_RX = re.compile(r"(?<![A-Za-z0-9_-])P-\d+(?![0-9])")
FINDING_ID_RX = re.compile(r"(?<![A-Za-z0-9_-])(?!P-\d)[A-Z]+-\d{3}(?![0-9])")
POLICY_RX = re.compile(r"(?<![A-Za-z0-9_])(?:p|sp|pct)=[A-Za-z0-9]+", re.I)
# the explanation report.md prints on every run, whatever the run found (the gate's rule, and the label of the
# DKIM evidence line): it names p=reject without the run saying anything about it, so no policy value is read there
FIXED_TEXT = (re.compile(r"(?m)^Gate rule: .*$"), re.compile(r"aligned-DKIM evidence \(needed before p=reject\)"))
# the voice rules: hyphens only, straight quotes, three dots, plain spaces (code points as numbers, so this file
# stays ASCII and passes its own check)
PUNCTUATION = tuple((chr(code), name) for code, name in (
    (0x2014, "an em dash"), (0x2013, "an en dash"), (0x2010, "a Unicode hyphen"), (0x2011, "a non-breaking hyphen"),
    (0x2012, "a figure dash"), (0x2015, "a horizontal bar"), (0x2018, "a curly quote"), (0x2019, "a curly quote"),
    (0x201A, "a curly quote"), (0x201B, "a curly quote"), (0x201C, "a curly quote"), (0x201D, "a curly quote"),
    (0x201E, "a curly quote"), (0x201F, "a curly quote"), (0x2026, "the ellipsis character"),
    (0x00A0, "a non-breaking space"), (0x202F, "a narrow non-breaking space")))
PUNCTUATION_FIX = {"an em dash": "use a hyphen", "an en dash": "use a hyphen", "the ellipsis character": "use three dots",
                   "a curly quote": "use a straight quote", "a non-breaking space": "use a plain space",
                   "a narrow non-breaking space": "use a plain space"}


class UsageError(Exception):
    """A file or folder that cannot be read; main turns it into exit 2."""


def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def read_text(path, what):
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise UsageError("%s %s does not exist" % (what, path)) from None
    except OSError as exc:
        raise UsageError("cannot read %s %s: %s" % (what, path, exc.strerror or exc)) from None
    except UnicodeDecodeError:
        raise UsageError("%s %s is not UTF-8 text" % (what, path)) from None


def html_text(raw):
    """An HTML file's text, line for line: comments, styles and scripts
    dropped, every tag a space (so two cells never run together), entities
    decoded. Each dropped part keeps its line breaks, so line N is the
    source's line N."""
    def blank(m):
        return " " + "\n" * m.group(0).count("\n")
    raw = re.sub(r"<!--.*?-->", blank, raw, flags=re.S)
    raw = re.sub(r"<(style|script)\b.*?</\1\s*>", blank, raw, flags=re.S | re.I)
    raw = re.sub(r"<(?:[^>\"']|\"[^\"]*\"|'[^']*')*>", blank, raw)
    return html.unescape(raw)


def _json(path):
    """A run's JSON file as an object; {} when it is missing or damaged (the
    checks it feeds then find nothing there, and say so)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError):
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
    return "%.1f" % (100 * value)


class Run:
    """What one run's files carry: the whole numbers, the policy values, the
    plan ids and the finding ids a polished copy may quote."""

    def __init__(self, run_dir):
        self.dir = run_dir
        texts = {}
        for name in CORPUS:
            p = run_dir / name
            if p.is_file():
                try:
                    texts[name] = PATH_RX.sub('""', p.read_text(encoding="utf-8-sig", errors="replace"))
                except OSError as exc:
                    raise UsageError("cannot read %s: %s" % (p, exc.strerror or exc)) from None
        if not texts:
            raise UsageError("%s holds none of the run's files (%s): pass --run with a run folder"
                             % (run_dir, ", ".join(CORPUS)))
        corpus = "\n".join(texts.values())
        self.numbers = set(NUMBER_RX.findall(corpus))
        stated = corpus
        for rx in FIXED_TEXT:
            stated = rx.sub("", stated)
        self.policies = {m.lower() for m in POLICY_RX.findall(stated)}
        report = _json(run_dir / "report.json")
        # derived, not copied: the pass rate as a percentage, and the mail log's span in the document's words
        rates = [_dig(report, "rua", "totals", "pass_rate"),
                 _dig(_json(run_dir / "next_steps.json"), "stand", "spoofing_blocked", "pass_rate")]
        self.numbers |= {r for r in map(_rate, rates) if r}
        by = _dig(report, "maillog", "window_by_domain")
        for window in [_dig(report, "maillog", "window"), *(by.values() if isinstance(by, dict) else ())]:
            try:
                phrase = next_steps.span_phrase(window)
            except Exception:  # a damaged window is no span to allow
                phrase = None
            if phrase:
                self.numbers |= set(NUMBER_RX.findall(phrase))
        changes = _dig(_json(run_dir / "plan.json"), "changes")
        self.has_plan = (run_dir / "plan.json").is_file()
        self.plan_ids = {str(c["id"]) for c in (changes if isinstance(changes, list) else [])
                         if isinstance(c, dict) and c.get("id")}
        findings = _dig(report, "findings")
        self.finding_ids = {str(f["id"]) for f in (findings if isinstance(findings, list) else [])
                            if isinstance(f, dict) and f.get("id")}
        self.finding_ids |= set(FINDING_ID_RX.findall(texts.get("report.md", "")))


def problems(text, run):
    """[(line, token, why)] for every token in text the run does not carry,
    in reading order, each once per line."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        found, taken = [], []  # (position, token, why); the spans the id and policy checks already read
        for m in PLAN_ID_RX.finditer(line):
            taken.append(m.span())
            if m.group(0) not in run.plan_ids:
                found.append((m.start(), m.group(0), "plan id not in plan.json" if run.has_plan
                              else "plan id, and the run has no plan.json"))
        for m in FINDING_ID_RX.finditer(line):
            taken.append(m.span())
            if m.group(0) not in run.finding_ids:
                found.append((m.start(), m.group(0), "finding id not in report.json or report.md"))
        for m in POLICY_RX.finditer(line):
            taken.append(m.span())
            if m.group(0).lower() not in run.policies:
                found.append((m.start(), m.group(0), "policy value the run's files never write"))
        for m in NUMBER_RX.finditer(line):
            if not any(a <= m.start() < b for a, b in taken) and m.group(0) not in run.numbers:
                found.append((m.start(), m.group(0), "number not in the run's files"))
        for ch, name in PUNCTUATION:
            at = line.find(ch)
            if at >= 0:
                found.append((at, "U+%04X" % ord(ch), "%s: the voice rules forbid it, %s"
                              % (name, PUNCTUATION_FIX.get(name, "use a hyphen"))))
        seen = set()
        for _, token, why in sorted(found, key=lambda t: t[0]):
            if (token, why) not in seen:
                seen.add((token, why))
                out.append((n, token, why))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", metavar="FILE", help="the polished copy: markdown or text, or .html")
    ap.add_argument("--run", metavar="DIR", default=DEFAULT_RUN,
                    help="the run folder it was polished from (default: %s)" % DEFAULT_RUN)
    args = ap.parse_args(argv)
    try:
        path = repo_path(args.file)
        text = read_text(path, "file")
        if path.suffix.lower() in (".html", ".htm"):
            text = html_text(text)
        run = Run(repo_path(args.run))
    except UsageError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    found = problems(text, run)
    for n, token, why in found:
        print("line %d: %s: %s" % (n, token, why))
    if found:
        print("%d problem%s in %s against %s" % (len(found), "" if len(found) == 1 else "s", path.name, run.dir),
              file=sys.stderr)
        return 1
    print("clean: every number, id and policy value in %s is in the run's files" % path.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
