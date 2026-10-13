#!/usr/bin/env python3
"""Turn one audit run into the stakeholder document, deterministically.

Input is report.json from src/audit.py, plus - when they exist - plan.json
from src/plan.py, metrics.json from src/collect.py (the run history) and an
owners file that maps senders and domains to the people who fix them.
Output is next_steps.md in the shape of docs/templates/next-steps.md, and
next_steps.json carrying the same content as data. Every sentence is
assembled from the inputs, every number is copied from them, and failure
counts are the deduplicated ones (never a raw row count). Audit and plan
prose never reaches the page verbatim: plain() turns "(s)" plurals, CLI
flags, heuristic labels and internal jargon into words a reader can act on,
and gate verdicts print as ready / not yet / needs more data.

The report is read defensively. maillog.census and a top-level delta are
used when present; otherwise the same facts are derived from
maillog.verdicts, and when neither exists the document says "not in this
run". The trend comes from delta, else --previous, else metrics.json. The
one-liner counts the organization domain's own mail from maillog.by_domain
when the report carries it, else the whole census "across all audited
domains". The window in the heading is the aggregate reports' own date
range, else the requested --since/--until bounds, else "this run's window";
no number of days is ever assumed. --audience replaces the default first
sentence of the audience line. What audit.toml formally excepts comes off
every list that names senders exactly as the census counts it per stream,
and is listed once, as excepted; the gate's verdict decides whether the
next step reads ready, on hold, or in need of more data. When the mail log
recorded the local overrides, mail delivered despite failing names the one
that let it in (maillog.counters.delivered_despite_fail_by, the census's
delivered_by), and each sender's action says what to change; the
per-domain table says what the tenant measured of each domain's mail flow
(report.mailflow) or that it was not measured; for an organization whose
rows the row budget cut, the genuine-failure line adds the full-window
totals counted in advanced hunting (maillog.window_totals) beside the
floor, which every verdict still rests on.

Owners file (default <repo root>/owners.csv, gitignored; see
samples/owners.csv.example): CSV with columns pattern,owner,channel,note.
A pattern matches case-insensitively as an exact sender address when it
contains @, as a domain (itself and every subdomain) when it is a bare
name, and as a glob when it contains *. DNS changes map by domain; sender
fixes map by sender address, then sender domain, then envelope domain.
Anything unmatched lands under "Unassigned - needs an owner".

  python src/next_steps.py audit-out/latest/report.json --plan audit-out/latest/plan.json --out audit-out/latest
  python src/next_steps.py audit-out/latest/report.json --metrics audit-out/metrics.json --owners owners.csv
  python src/next_steps.py audit-out/latest/report.json --previous audit-out/history/<run>/report.json

Relative paths resolve from the repo root, as in every tool here. --date
defaults to the report's own generation date, so a rerun on the same inputs
gives the same document.

Exit codes: 0 written (or printed), 2 usage or input error. Never a traceback.
"""

import argparse
import csv
import fnmatch
import json
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path

import audit  # the delta's own rules: the recorded cuts, a window's span, which spans compare
import dedupe  # the overrides that let a delivered failure in, in plain words

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.5"
DEFAULT_OWNERS = "owners.csv"
UNASSIGNED = "Unassigned - needs an owner"
HEADLINE_MIN = 10          # a failing entry with fewer messages is a note, never a headline
TOP_ENTRIES = 5            # headline bullets per list
NOTES_CAP = 12             # entries named on a "notes, not headlines" line before "+N more"
SENDER_ITEMS_CAP = 10      # per-sender action lines before the rest collapse into one
ACTIONABLE = ("major", "blocking")
DEFAULT_AUDIENCE = "For the people who own our email domains and sending systems"
LIKELY_WORDS = {"likely_spoof": "looks like spoofing",
                "likely_misconfigured_sender": "looks like our own system misconfigured",
                "likely_misconfigured": "looks like our own system misconfigured",
                "unknown": "unclear", "mixed": "mixed - some look like spoofing, some like our own systems"}
# the three groups every heuristic label falls into; rua_parse spells the middle one likely_misconfigured
OWN, SPOOF, UNCLEAR = "likely_misconfigured_sender", "likely_spoof", "unknown"
GATE_WORDS = {"go": "ready", "no_go": "not yet", "insufficient_data": "needs more data"}
FIRST_STEP = "publish a monitoring-only DMARC record for %s so reports start"
# CLI flags in audit prose, as the words a reader without the CLI can act on.
# Any --flag these do not name is dropped by plain(): a flag means nothing here.
FLAG_WORDS = tuple((re.compile(p), r) for p, r in (
    (r"no --known list: unknown-sender check not run, every source is listed as unknown",
     "no list of known senders was given, so every outside source is listed as unclear"),
    (r"\bnot in --known\b", "not in the list of known senders"),
    (r"\badd it to --known\b", "add it to the list of known senders"),
    (r"\bpass --known with your vendors' domains and IP prefixes \(comma list or file\)",
     "give the audit the list of known senders (your vendors' domains and IP prefixes)"),
    (r"\bno --authserv-id( given)?\b", "no trusted authentication server name was given"),
    (r"\bre-run with --authserv-id <[^>]*>", "re-run naming the authentication server id your receiving host writes"),
    (r"(?<!\S)--authserv-id\b", "the trusted authentication server name"),
    (r"(?<!\S)--trust-subdomains\b", "the subdomain-trust option"),
    (r"\bbut --expect-policy is\b", "but the expected policy is"),
    (r"\bwiden --since\b", "widen the report window"),
    (r"\bthe --since/--until window\b", "the requested window"),
    (r"\brestricted to --sender-domain\b", "restricted to the sender domain"),
    (r"\bmatched --sender-domain\b", "matched the sender domain"),
    (r"\bpass --auth-column\b", "name the authentication column"),
    (r"\bcheck --auth-column names the verdict column\b",
     "check that the authentication column named is the verdict column"),
    (r"\brun without --offline so\b", "run online so"),
    (r"\b(pass|supply) --rua reports and/or --maillog\b", r"\1 aggregate reports and/or a mail log"),
    (r"(?<!\S)--vendor-domain teaches\b", "the vendor-domain list teaches"),
    (r"(?<!\S)--retiring-selector\b", "the retiring-selector check"),
))
# Heuristic labels in audit prose ("1 likely_spoof, 0 unknown"), as phrases.
LABEL_WORDS = (
    (re.compile(r"\b(\d+) likely_spoof\b"),
     lambda m: "%s that %s like spoofing" % (m.group(1), "looks" if m.group(1) == "1" else "look")),
    (re.compile(r"\b(\d+) likely_misconfigured(?:_sender)?\b"),
     lambda m: "%s that %s like our own system misconfigured" % (m.group(1), "looks" if m.group(1) == "1" else "look")),
    (re.compile(r"\b(\d+) unknown\b(?! sender)"), lambda m: "%s unclear" % m.group(1)),
    (re.compile(r"\blikely_spoof\b"), "looks like spoofing"),
    (re.compile(r"\blikely_misconfigured(?:_sender)?\b"), "looks like our own system misconfigured"),
    (re.compile(r"\(unknown\)"), "(unclear)"),
    (re.compile(r", unknown\)"), ", unclear)"),
    (re.compile(r"\blisted as unknown\b"), "listed as unclear"),
    (re.compile(r"\bevery source is unknown\b"), "every source is unclear"),
    (re.compile(r"\bheader_from\b"), "the From domain"),
)
# Internal jargon, in the glossary's words: a step, senders, an SPF ending.
JARGON_WORDS = tuple((re.compile(p, re.I), r) for p, r in (
    (r"\bnothing (?:is )?(?:left )?to ratchet\b", "no policy step is left"),
    (r"\bno ratchet to wait for\b", "no policy step to wait for"),
    (r"\bbefore ratcheting to\b", "before moving to"),
    (r"\bratcheting\b", "stepping the policy up"),
    (r"\bratchet the policy\b", "step the policy up"),
    (r"\bthe ratchet step\b", "the policy step"),
    (r"\ba ratchet\b", "a policy step"),
    (r"\bratchets?\b", "policy step"),
    (r"\bSPF terminator\b", "SPF ending"),
    (r"\bterminators?\b", "ending"),
    (r"\bspoof stream\b", "spoofing source"),
    (r"\bfailing stream\(s\)", "failing senders"),
    (r"\bstream\(s\)", "senders"),
    (r"\bstreams\b", "senders"),
    (r"\bstream\b", "sender"),
))
# A finding or plan id outside parentheses: kept, but only as a reference in parentheses.
ID_RX = re.compile(r"(?<![\w(-])((?:[A-Z]{2,}|P)-\d{2,})(?![\w-])(?![^(]*\))")
# The gate's mail-log blocker, split by blocker_items() so spoofs are never a gap to close.
GAP_RX = re.compile(r"^(\d+) logical message\(s\) from this domain failed with no passing copy "
                    r"\(deduplicated(?:; (\d+) more excepted)?\)"
                    r"(?:; top senders: .*)?$")
# The gate's blocker for one failing outside-view source (audit._shared_blockers): collapsed to one line per domain.
STREAM_RX = re.compile(r"^(\S+) fails DMARC on (\d+)/(\d+) msgs \(([^)]*)\)(.*)$")
# the gate's hint on a stream a domain exception covers only in part: which domains are left uncovered
STREAM_HINT_RX = re.compile(r"\((a domain exception covers part of it; .*?)\)$")
STREAM_NAMES = 3  # sources named in that line; the rest are counted and left to report.md
# the gate's blocker for one spoofing source receivers delivered under the policy (audit._shared_blockers)
SPOOF_STREAM_RX = re.compile(r"^spoof stream (\S+) \((\d+) msgs\) saw disposition none")
# Plan prerequisites written as observations, reworded as the condition that clears them.
PREREQ_REWORDS = (
    (re.compile(r"^(\d+) message\(s\) in the mail log failed from a sender that looks like your own "
                r"misconfigured system, not a spoof(?: \((\d+) more are excepted in the gate\))?$"),
     lambda m: "the %s mail-log failure%s from our own systems %s fixed%s"
     % (m.group(1), "" if m.group(1) == "1" else "s", "is" if m.group(1) == "1" else "are",
        (" (%s more are formally excepted in audit.toml)" % m.group(2)) if m.group(2) else "")),
    (re.compile(r"^aggregate reports: (\S+) sends (\d+) message\(s\) as (\S+) and fails"),
     lambda m: "the sender at %s (%s messages as %s) is fixed" % (m.group(1), m.group(2), m.group(3))),
    (re.compile(r"^no failure evidence in this run"),
     lambda m: "a mail log or aggregate reports are supplied to the audit"),
    (re.compile(r"^no aligned-DKIM evidence in this run"),
     lambda m: "the run carries aligned-DKIM evidence (aggregate reports, or a mail log pulled with SPF and DKIM columns)"),
    (re.compile(r"^SPF-only aligned senders(?: in the aggregate reports)? \((.+)\): they break on forwarding at reject"
                r"(?: - aligned DKIM first)?$"),
     lambda m: "the SPF-only senders (%s) are DKIM-signed, because SPF alone breaks on forwarding" % m.group(1)),
    (re.compile(r"^every legitimate sender proven with an aligned DKIM header( within 7 days)?$"),
     lambda m: "every legitimate sender is proven with an aligned DKIM header%s" % (m.group(1) or "")),
    (re.compile(r"^one change to (\S+) a week: this row and the other rows? for it \(([^)]+)\) each rewrite "),
     lambda m: "the other change to %s (plan %s) waits for another week, since both rewrite today's record"
     % (m.group(1), m.group(2))),
    (re.compile(r"^the external-destination record exists: receivers send (\S+)'s aggregate data to (\S+) only when "
                r"(\S+) publishes (\S+) TXT"),
     lambda m: "%s publishes %s, so receivers send %s's aggregate reports to %s"
     % (m.group(3), m.group(4), m.group(1), m.group(2))),
    (re.compile(r"^look up (_dmarc\.\S+) first: publish only if it has no record"),
     lambda m: "a lookup shows %s has no record yet" % m.group(1)),
)
GLOSSARY = OrderedDict([
    ("DMARC", "the published rule that tells receiving mail systems what to do with mail that claims "
              "to come from our domain but cannot prove it"),
    ("SPF", "the list of servers allowed to send mail for a domain"),
    ("DKIM", "a signature the sending system adds so the receiver can check the message was not "
             "altered and really came from that domain"),
    ("rua", "the address in the DMARC record where receivers send their daily summary reports"),
    ("p=", "the policy for the domain itself: none (only report), quarantine (send failing mail to "
           "junk) or reject (refuse it)"),
    ("sp=", "the same policy applied to subdomains that have no record of their own"),
    ("pct=", "the share of failing mail the policy is applied to, so a rollout can start small"),
    ("genuine failure", "a message where no copy passed authentication for a given recipient, counted "
                        "once per message and recipient rather than once per log row"),
    ("relay echo", "a failing log row for a message that also has a passing copy, created when the "
                   "message is relayed or forwarded; it is not a failure"),
])


class UsageError(Exception):
    """Input problems; main turns it into exit 2."""


# ------------------------------------------------------------------ helpers

def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def display_path(p):
    """A file as the document names it: the basename only, never a directory,
    so no local path (or profile name) reaches the page."""
    return Path(str(p)).name or str(p)


def read_json(path, what, expect=dict):
    p = repo_path(path)
    if p.is_dir():
        raise UsageError("%s %s is a directory, expected a JSON file" % (what, p))
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise UsageError("cannot read %s %s: %s" % (what, p, exc.strerror or exc)) from exc
    except UnicodeDecodeError as exc:
        raise UsageError("%s %s is not UTF-8 text" % (what, p)) from exc
    except json.JSONDecodeError as exc:
        raise UsageError("%s %s is not valid JSON (%s at line %d)" % (what, p, exc.msg, exc.lineno)) from exc
    if not isinstance(doc, expect):
        raise UsageError("%s %s: expected a JSON %s, got %s"
                         % (what, p, "object" if expect is dict else "array", type(doc).__name__))
    return doc


def org_domain(name):
    """Registrable domain, with the common two-label public suffixes (same table as plan.py)."""
    labels = (name or "").split(".")
    two = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
           "com.br", "com.mx", "co.za", "com.sg", "com.hk", "co.in", "co.kr", "com.tr", "com.ar"}
    if len(labels) > 2 and ".".join(labels[-2:]) in two:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def dmarc_tags(record):
    """'v=DMARC1; p=none; rua=mailto:a' -> {'v': 'DMARC1', 'p': 'none', ...}"""
    tags = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _under(name, domain):
    return bool(name) and bool(domain) and (name == domain or name.endswith("." + domain))


def _dom(value):
    """A domain name as the report keys it: lower case, no surrounding space or trailing dot."""
    return str(value or "").strip().lower().rstrip(".")


def _n(value):
    """int for anything that carries a whole number, else None (never a bool,
    never an exception: '--5' and a superscript digit are no numbers)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value.strip()):
        return int(value.strip())
    return None


def _f(value):
    """A finite float, else None: nan, an infinity and an integer too large to be a float read as unknown."""
    if isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def _likely(label):
    """A heuristic label as this document reads it: the aggregate reports'
    likely_misconfigured is the mail log's likely_misconfigured_sender (our
    own system, misconfigured), one meaning in two spellings; no label is
    unknown."""
    if not isinstance(label, str) or not label:
        return UNCLEAR
    return OWN if label == "likely_misconfigured" else label


def _group(label):
    """The one-liner's group for a label: our own, spoofing, or unclear."""
    label = _likely(label)
    return label if label in (OWN, SPOOF) else UNCLEAR


def _day(value):
    """'YYYY-MM-DD' from a run stamp or ISO timestamp, else None."""
    m = re.match(r"^\s*(\d{4}-\d{2}-\d{2})", str(value or ""))
    return m.group(1) if m else None


def _plural(n, one, many=None):
    return one if n == 1 else (many if many is not None else one + "s")


def _join(items, last="and"):
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    sep = "; " if any("," in i for i in items) else ", "
    return sep.join(items[:-1]) + sep.rstrip() + " " + last + " " + items[-1]


def _short_step(text):
    """The gate's next_step without the 'on the record at ...' tail."""
    return re.sub(r"\s+on the record at \S+$", "", text or "").strip()


def hyphens(text):
    """ASCII hyphens only, whatever an input string carried (U+2010 to U+2015:
    the hyphen, dash and bar code points, spelled as numbers so this file
    itself stays ASCII)."""
    for code in range(0x2010, 0x2016):
        text = text.replace(chr(code), "-")
    return text


def _clean(obj):
    if isinstance(obj, str):
        return hyphens(obj)
    if isinstance(obj, list):
        return [_clean(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    return obj


def _expand_plurals(text):
    """'21 logical message(s)' -> '21 logical messages', '1 message(s)' -> '1 message';
    a '(s)' with no count in front of it reads as the plural."""
    def fix(m):
        n, between, word = m.group(1), m.group(2), m.group(3)
        return "%s%s %s%s" % (n, between, word, "" if n == "1" else "s")
    text = re.sub(r"\b(\d+)((?: [A-Za-z-]+){0,2}?) ([A-Za-z-]+)\(s\)", fix, text)
    return text.replace("(s)", "s")


def plain(text):
    """Audit and plan prose as the reader should see it: CLI flags turned into
    words (any flag left over is dropped), heuristic labels and internal jargon
    replaced by the glossary's words, '(s)' plurals expanded, and finding or
    plan ids kept only as references in parentheses. Data (sender addresses,
    subjects, domains) never goes through here."""
    text = str(text or "")
    if not text:
        return text
    for rx, rep in FLAG_WORDS:
        text = rx.sub(rep, text)
    text = re.sub(r"(?<!\S)--[\w][\w.-]*(?:=\S+)?", "", text)
    for rx, rep in LABEL_WORDS:
        text = rx.sub(rep, text)
    for rx, rep in JARGON_WORDS:
        text = rx.sub(rep, text)
    text = _expand_plurals(text)
    text = ID_RX.sub(r"(\1)", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\s+([,;:.)])", r"\1", text)
    text = re.sub(r"\(\s+", "(", text)
    return text.strip()


def id_range(ids):
    """['P-01','P-02','P-03'] -> 'P-01 to P-03'; gaps listed; one id as is."""
    nums = []
    for i in ids:
        m = re.match(r"^([A-Za-z]+-)(\d+)$", str(i))
        if not m:  # an id of any shape (a list, a number): listed once each, as text
            return ", ".join(dict.fromkeys(str(x) for x in ids))
        nums.append((m.group(1), int(m.group(2)), len(m.group(2))))
    nums = sorted(set(nums), key=lambda t: (t[0], t[1]))
    if not nums:
        return ""
    if len(nums) == 1:
        return "%s%0*d" % (nums[0][0], nums[0][2], nums[0][1])
    if all(n[0] == nums[0][0] for n in nums) and nums[-1][1] - nums[0][1] == len(nums) - 1:
        return "%s%0*d to %s%0*d" % (nums[0][0], nums[0][2], nums[0][1], nums[-1][0], nums[-1][2], nums[-1][1])
    return ", ".join("%s%0*d" % (p, w, n) for p, n, w in nums)


# ------------------------------------------------------------------ owners

def read_owners(path):
    """pattern,owner,channel,note rows; each pattern typed as address, domain or glob."""
    p = repo_path(path)
    if p.is_dir():
        raise UsageError("owners file %s is a directory, expected a CSV" % p)
    rows = []
    try:
        with open(p, encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            names = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
            if "pattern" not in names or "owner" not in names:
                raise UsageError("owners file %s needs the columns pattern,owner,channel,note (found: %s)"
                                 % (p, ", ".join(n for n in names if n) or "none"))
            for raw in reader:
                row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k is not None}
                pat = row.get("pattern", "")
                if not pat or pat.startswith("#") or not row.get("owner"):
                    continue
                kind = "glob" if "*" in pat else ("address" if "@" in pat else "domain")
                rows.append({"pattern": pat.lower().rstrip("."), "kind": kind, "owner": row["owner"],
                             "channel": row.get("channel", ""), "note": row.get("note", "")})
    except OSError as exc:
        raise UsageError("cannot read owners file %s: %s" % (p, exc.strerror or exc)) from exc
    except UnicodeDecodeError as exc:
        raise UsageError("owners file %s is not UTF-8 text" % p) from exc
    except csv.Error as exc:
        raise UsageError("cannot parse owners file %s as CSV: %s" % (p, exc)) from exc
    return rows


def match_owner(owners, *keys):
    """First owner row hit, trying the keys in the order given: an exact
    address, a domain (itself or a parent, the longest pattern wins), then a glob."""
    for key in keys:
        key = (key or "").strip().lower().rstrip(".")
        if not key:
            continue
        if "@" in key:
            for o in owners:
                if o["kind"] == "address" and o["pattern"] == key:
                    return o
        else:
            best = None
            for o in owners:
                if o["kind"] == "domain" and _under(key, o["pattern"]):
                    if best is None or len(o["pattern"]) > len(best["pattern"]):
                        best = o
            if best:
                return best
        for o in owners:
            if o["kind"] == "glob" and fnmatch.fnmatchcase(key, o["pattern"]):
                return o
    return None


# ------------------------------------------------------------------ the report, read defensively

COUNT_KEYS = ("genuine_failures", "failures", "failing", "count", "messages", "msgs", "n")
ENV_KEYS = ("_key", "env", "envelope", "envelope_domain", "mail_from", "domain", "name")
SENDER_KEYS = ("_key", "sender", "addr", "address", "sender_address", "from", "name")


def _entries(obj, name_keys):
    """A summary list (list of dicts) or map (name -> count or dict) as
    [{name, count, likely, ...}] worst first, entries with no genuine failures
    dropped (audit.py's census lists clean senders too); None when the shape
    is not understood. The census's exception counts ride along (excepted,
    likely_counts, likely_after, ...) for _after_exceptions."""
    if isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            items.append(dict(v, _key=str(k)) if isinstance(v, dict) else {"_key": str(k), "count": v})
    elif isinstance(obj, list):
        items = [x for x in obj if isinstance(x, dict)]
        if len(items) != len(obj):
            return None
    else:
        return None
    out = []
    for it in items:
        name = next((str(it[k]) for k in name_keys if it.get(k) not in (None, "")), None)
        count = next((_n(it[k]) for k in COUNT_KEYS if _n(it.get(k)) is not None), None)
        if name is None or count is None:
            return None
        if count <= 0:
            continue
        likely = it.get("likely") or it.get("label")
        entry = {"name": name.strip().lower(), "count": count,
                 "likely": _likely(likely) if isinstance(likely, str) else None, "messages": _n(it.get("messages"))}
        for key in ("excepted", "excepted_delivered", "senders_after"):
            if _n(it.get(key)) is not None:
                entry[key] = _n(it[key])
        if isinstance(it.get("likely_counts"), dict):
            counts = Counter()
            for label, n in it["likely_counts"].items():
                counts[_likely(label)] += _n(n) or 0
            entry["likely_counts"] = dict(counts)
        if "likely_after" in it:
            entry["likely_after"] = _likely(it["likely_after"]) if it["likely_after"] else None
        if it.get("sample_sender_after"):
            entry["sample_sender_after"] = str(it["sample_sender_after"])
        senders = it.get("senders")
        if isinstance(senders, list) and senders:
            entry["senders"] = [str(s) for s in senders]
            entry["sender_count"] = len(senders)
        elif _n(senders) is not None:
            entry["sender_count"] = _n(senders)
        if _n(it.get("sender_count")) is not None:
            entry["sender_count"] = _n(it["sender_count"])
        if it.get("sample_sender"):
            entry.setdefault("senders", [str(it["sample_sender"])])
        subjects = it.get("subjects")
        if isinstance(subjects, list) and subjects:
            entry["subjects"] = [str(s) for s in subjects]
        elif it.get("sample_subject"):
            entry["subjects"] = [str(it["sample_subject"])]
        for src, dst in (("envelope_domain", "envelope"), ("envelope", "envelope"), ("domain", "domain")):
            if isinstance(it.get(src), str) and it[src] and dst not in entry:
                entry[dst] = it[src].strip().lower()
        out.append(entry)
    return sorted(out, key=lambda e: (-e["count"], e["name"]))


def _dominant(labels):
    """One likely label for a group: the majority label, else 'mixed'."""
    c = Counter(l or "unknown" for l in labels)
    if not c:
        return "unknown"
    label, n = c.most_common(1)[0]
    return label if n * 2 > sum(c.values()) else "mixed"


def _from_verdicts(genuine):
    by_env, by_sender = OrderedDict(), OrderedDict()
    for v in genuine:
        env = (v.get("envelope_domain") or "(no envelope domain)").lower()
        snd = (v.get("sender") or "(no sender)").lower()
        e = by_env.setdefault(env, {"labels": [], "senders": Counter(), "subjects": Counter()})
        e["labels"].append(v.get("likely"))
        e["senders"][snd] += 1
        e["subjects"][v.get("subject") or "(no subject)"] += 1
        s = by_sender.setdefault(snd, {"labels": [], "envelopes": Counter(), "subjects": Counter(),
                                       "domain": (v.get("domain") or snd.rpartition("@")[2]).lower()})
        s["labels"].append(v.get("likely"))
        s["envelopes"][env] += 1
        s["subjects"][v.get("subject") or "(no subject)"] += 1
    envs = [{"name": k, "count": len(e["labels"]), "likely": _dominant(e["labels"]),
             "sender_count": len(e["senders"]), "senders": [s for s, _ in e["senders"].most_common(3)],
             "subjects": [s for s, _ in e["subjects"].most_common(2)]} for k, e in by_env.items()]
    senders = [{"name": k, "count": len(s["labels"]), "likely": _dominant(s["labels"]),
                "domain": s["domain"], "envelope": s["envelopes"].most_common(1)[0][0],
                "subjects": [x for x, _ in s["subjects"].most_common(2)]} for k, s in by_sender.items()]

    def key(e):
        return (-e["count"], e["name"])
    return sorted(envs, key=key), sorted(senders, key=key)


def _stamp(value):
    """'2026-10-05 22:25' from an ISO timestamp; the text itself when it is not one."""
    txt = str(value or "")
    return txt[:16].replace("T", " ") if len(txt) >= 16 and txt[10] == "T" else txt


def _span_seconds(window):
    """The exact span between the window's stamps, in seconds; None when they do not parse."""
    try:
        a = datetime.fromisoformat(str(window.get("from")).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(window.get("to")).replace("Z", "+00:00"))
        a = a if a.tzinfo else a.replace(tzinfo=timezone.utc)  # a stamp without a zone is read as UTC
        b = b if b.tzinfo else b.replace(tzinfo=timezone.utc)
        return max(0.0, (b - a).total_seconds())
    except (TypeError, ValueError, AttributeError):
        return None


def span_phrase(window):
    """'the mail log's 41-hour span (2026-10-05 22:25 to 2026-10-07 15:20 UTC)',
    in days from 48 hours on, in minutes under an hour; None without a
    window. The figure comes from the window's own stamps (the stored hours
    are rounded), so it never contradicts them. The mail log often reaches
    less far back than the report window (a row budget keeps the newest
    hours), and every mail-log number should say how far."""
    if not window:
        return None
    secs = _span_seconds(window)
    hours = secs / 3600 if secs is not None else _f(window.get("hours"))
    if hours is None:
        return "the mail log's span (%s to %s UTC)" % (_stamp(window.get("from")), _stamp(window.get("to")))
    if hours >= 48:  # halves round up: 60 hours is a 3-day span, as 84 is a 4-day one
        return "the mail log's %d-day span (%s to %s)" % (int(hours / 24 + 0.5), str(window.get("from"))[:10],
                                                         str(window.get("to"))[:10])
    if hours < 1:
        minutes = int(hours * 60 + 0.5)
        if minutes < 1:
            return "the mail log's under-a-minute span (%s to %s UTC)" % (_stamp(window.get("from")),
                                                                            _stamp(window.get("to")))
        return "the mail log's %d-minute span (%s to %s UTC)" % (minutes, _stamp(window.get("from")),
                                                                  _stamp(window.get("to")))
    return "the mail log's %d-hour span (%s to %s UTC)" % (int(hours + 0.5), _stamp(window.get("from")),
                                                            _stamp(window.get("to")))


def truncation_note(ml):
    """One clause when the mail-log section says its export was cut short."""
    for key in ("truncated", "truncation", "capped", "cap", "row_cap", "rows_capped"):
        val = ml.get(key)
        if val:
            return val if isinstance(val, str) else key.replace("_", " ")
    for key in ("note", "notes", "warnings"):
        vals = ml.get(key)
        vals = [vals] if isinstance(vals, str) else (vals if isinstance(vals, list) else [])
        for v in vals:
            if isinstance(v, str) and re.search(r"\b(cap|capped|truncat\w*)\b", v, re.I):
                return v
    return None


def full_window(report):
    """What collect.py counted in advanced hunting over the whole window for
    the organizations whose rows its row budget or the API cap cut
    (maillog.window_totals), added up over their From domains: {"orgs",
    "hours", "span", "genuine_failures", "delivered_despite_fail"}; None
    when the report carries none. Beside the floor, never instead of it."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    wt = ml.get("window_totals") if isinstance(ml.get("window_totals"), dict) else {}
    orgs = wt.get("orgs") if isinstance(wt.get("orgs"), dict) else {}
    names, gf, ddf = [], 0, 0
    for org, info in sorted(orgs.items()):
        bd = info.get("by_domain") if isinstance(info, dict) else None
        if not isinstance(bd, dict):
            continue
        names.append(str(org))
        for c in bd.values():
            if isinstance(c, dict):
                gf += max(0, _n(c.get("genuine_failures")) or 0)
                ddf += max(0, _n(c.get("delivered_despite_fail")) or 0)
    if not names:
        return None
    hours = _f(wt.get("hours"))
    if hours is not None and not 0 < hours < float("inf"):  # nan, an infinity, zero or less: an unnamed span
        hours = None
    return {"orgs": names, "hours": hours, "span": audit._hours_text(hours) if hours else "window",
            "genuine_failures": gf, "delivered_despite_fail": ddf}


def _carries_exceptions(obj):
    """True when census rows carry the exception counts (an audit.py that marks excepted verdicts)."""
    rows = obj.values() if isinstance(obj, dict) else (obj if isinstance(obj, list) else [])
    return any(isinstance(r, dict) and "excepted" in r for r in rows)


def _after_exceptions(entries, what):
    """(left, excepted) for census entries that carry the exception counts:
    each entry keeps the failures no exception covers, labelled by what is
    left (likely_after), and an envelope names the senders still failing
    through it; an entry with nothing left drops out. excepted: one
    {name, domain, envelope, count} per stream an exception covered, so the
    excepted messages are listed once, as such."""
    left, excepted = [], []
    for e in entries:
        n_exc = min(e.get("excepted") or 0, e["count"])
        if n_exc and what == "sender":
            excepted.append({"name": e["name"], "domain": e.get("domain"), "envelope": e.get("envelope"),
                             "count": n_exc})
        e = dict(e, count=e["count"] - n_exc)
        if e["count"] <= 0:
            continue
        if "likely_after" in e:
            e["likely"] = e["likely_after"] or e.get("likely")
        if what == "envelope" and e.get("senders_after") is not None:
            e["sender_count"] = e["senders_after"]
            e["senders"] = [e["sample_sender_after"]] if e.get("sample_sender_after") else []
        left.append(e)
    left.sort(key=lambda e: (-e["count"], e["name"]))
    excepted.sort(key=lambda e: (-e["count"], e["name"], str(e.get("envelope") or "")))
    return left, excepted


def maillog_view(report):
    """What the document needs from the mail log: summaries when the report
    carries them, else derived from the verdicts. None when there is no mail log.

    The lists that name senders are what the formal exceptions left: the
    census counts the excepted failures per stream (audit.py marks every
    verdict an exception covers), so each stream loses exactly its own, and
    the excepted messages are listed once, in view["excepted"]. A report
    whose census does not carry those counts (written before audit.py marked
    them) is not reduced at all: nothing in it says which stream an
    exception covered, so its excepted total (excepted_unsplit) can only be
    named as a part of the counts shown."""
    ml = report.get("maillog")
    if not isinstance(ml, dict):
        return None
    counters = ml.get("counters") if isinstance(ml.get("counters"), dict) else {}
    verdicts = [v for v in ml["verdicts"] if isinstance(v, dict)] if isinstance(ml.get("verdicts"), list) else []
    genuine = [v for v in verdicts if v.get("genuine_failure")]
    window = ml.get("window") if isinstance(ml.get("window"), dict) else None
    if window and not (window.get("from") and window.get("to")):
        window = None
    view = {"auth_column": ml.get("auth_column"), "sender_domain": ml.get("sender_domain"),
            "truncation": truncation_note(ml), "basis": None, "window": window}
    for key in ("genuine_failures", "raw_failing_rows", "raw_rows", "logical_messages",
                "delivered_despite_fail", "blocked_despite_pass", "echo_messages"):
        view[key] = _n(counters.get(key))
    if view["genuine_failures"] is None and verdicts:
        view["genuine_failures"] = len(genuine)
    if view["delivered_despite_fail"] is None and verdicts:
        view["delivered_despite_fail"] = sum(1 for v in verdicts if v.get("delivered_despite_fail"))
    if view["logical_messages"] is None and verdicts:
        view["logical_messages"] = len(verdicts)
    by_likely = counters.get("by_likely") if isinstance(counters.get("by_likely"), dict) else None
    if by_likely is None and verdicts:
        c = Counter(v.get("likely") or "unknown" for v in genuine)
        by_likely = {k: c.get(k, 0) for k in ("likely_spoof", "likely_misconfigured_sender", "unknown")}
    view["by_likely"] = {k: _n(v) or 0 for k, v in (by_likely or {}).items()}

    census = ml.get("census")
    by_env = by_sender = None
    counted = False  # the excepted failures are counted per stream: what is left can be named exactly
    excepted = []
    if isinstance(census, dict):
        env_obj = next((census[k] for k in ("by_envelope", "envelope", "env", "envelopes") if k in census), None)
        snd_obj = next((census[k] for k in ("by_sender", "sender", "senders", "addr") if k in census), None)
        by_env = _entries(env_obj, ENV_KEYS) if env_obj is not None else None
        by_sender = _entries(snd_obj, SENDER_KEYS) if snd_obj is not None else None
        counted = _carries_exceptions(snd_obj) and by_sender is not None
        if counted:
            by_sender, excepted = _after_exceptions(by_sender, "sender")
            if by_env is not None:
                by_env = _after_exceptions(by_env, "envelope")[0]
    elif isinstance(census, list):
        by_env = _entries(census, ENV_KEYS)
    if by_env is not None or by_sender is not None:
        view["basis"] = "census"
    if (by_env is None or by_sender is None) and verdicts:
        # the verdicts themselves: the ones an exception covers carry its mark and are listed apart
        v_env, v_snd = _from_verdicts([v for v in genuine if not v.get("excepted")])
        if by_sender is None:
            counted = any("excepted" in v for v in genuine)
            gone = Counter(((v.get("sender") or "(no sender)").lower(), (v.get("domain") or "").lower(),
                            (v.get("envelope_domain") or "(blank)").lower()) for v in genuine if v.get("excepted"))
            excepted = [{"name": s, "domain": d, "envelope": e, "count": n}
                        for (s, d, e), n in sorted(gone.items(), key=lambda kv: (-kv[1], kv[0]))]
        by_env = by_env if by_env is not None else v_env
        by_sender = by_sender if by_sender is not None else v_snd
        view["basis"] = view["basis"] or "verdicts"
    view["by_envelope"] = by_env or []
    view["by_sender"] = by_sender or []
    view["census_missing"] = by_env is None and by_sender is None
    view["excepted"] = excepted
    view["exceptions_counted"] = counted
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    gate_exc = gate.get("exceptions") if isinstance(gate.get("exceptions"), dict) else {}
    unsplit = _n(gate_exc.get("excepted_maillog_failures"))
    if unsplit is None:  # a gate older still: what it excepted per domain
        doms = gate.get("domains") if isinstance(gate.get("domains"), dict) else {}
        unsplit = sum(_n(g.get("excepted_failures")) or 0 for g in doms.values() if isinstance(g, dict))
    view["excepted_unsplit"] = 0 if counted else unsplit
    # delivered despite failing, per sender: what the exceptions left (an excepted sender is not told to
    # find its override), with how many the exceptions cover, and what let the rest in when the log says
    ddf, env_of, ddf_excepted, by = Counter(), {}, 0, {}
    for v in verdicts:
        if not v.get("delivered_despite_fail"):
            continue
        if v.get("excepted"):
            ddf_excepted += 1
            continue
        s = (v.get("sender") or "(no sender)").lower()
        ddf[s] += 1
        env_of.setdefault(s, v.get("envelope_domain") or "")
        if v.get("delivered_by"):
            by.setdefault(s, Counter())[str(v["delivered_by"])] += 1
    if not verdicts:  # report.json carries the census, not the verdicts: the census names them per sender stream
        raw = census.get("by_sender") if isinstance(census, dict) else None
        for r in raw if isinstance(raw, list) else []:
            n = _n(r.get("delivered_despite_fail")) if isinstance(r, dict) else None
            if not n:
                continue
            gone = min(max(_n(r.get("excepted_delivered")) or 0, 0), n)
            ddf_excepted += gone
            if n > gone:
                s = str(r.get("sender") or "(no sender)").lower()
                ddf[s] += n - gone
                env_of.setdefault(s, str(r.get("envelope_domain") or ""))
                # a stream's overrides are counted over all of its messages: they are what is left only when
                # no exception covered any of them (an exception covers a stream whole: its address or envelope)
                if not gone and isinstance(r.get("delivered_by"), dict):
                    for reason, k in r["delivered_by"].items():
                        if reason and (_n(k) or 0) > 0:
                            by.setdefault(s, Counter())[str(reason)] += _n(k)
    view["ddf_senders"] = [dict({"name": s, "count": n, "domain": (s.rpartition("@")[2] if "@" in s else ""),
                                 "envelope": env_of.get(s, "")}, **({"by": dict(by[s])} if by.get(s) else {}))
                           for s, n in sorted(ddf.items(), key=lambda kv: (-kv[1], kv[0]))]
    view["delivered_excepted"] = ddf_excepted
    # the whole log's overrides, over every delivered failure as the count beside them (excepted or not); the
    # export recorded the overrides when the counter is there (empty when none was named) or a verdict carries one
    whole = counters.get("delivered_despite_fail_by")
    view["overrides_recorded"] = isinstance(whole, dict) or any("delivered_by" in v for v in verdicts)
    if not isinstance(whole, dict):  # a report from before the counter, or a damaged one: the verdicts, if any
        whole = Counter(str(v["delivered_by"]) for v in verdicts
                        if v.get("delivered_despite_fail") and v.get("delivered_by"))
    view["ddf_by"] = {str(k): _n(n) for k, n in whole.items() if k and (_n(n) or 0) > 0}
    # the overrides of the deliveries the exceptions left, from the senders still counted (a stream's overrides
    # are known only when no exception covered it)
    left_by = Counter()
    for s in view["ddf_senders"]:
        left_by.update(s.get("by") or {})
    view["ddf_by_left"] = dict(left_by)
    for s in view["by_sender"]:
        s["likely"] = s.get("likely") or "unknown"
    return view


# streams() scopes whose numbers come from maillog.by_domain: the org's own rows, or
# its unaudited subdomains' rows when it has none of its own
OWN_SCOPES = ("own domain", "unaudited subdomains")


def _split(s):
    """{group: failures} for one census stream: from its likely_counts when
    the census carries them (what the exceptions left, label by label), else
    the whole stream under its own label."""
    n = _n(s.get("count")) or 0
    split = s.get("likely_counts") if isinstance(s.get("likely_counts"), dict) else None
    out = Counter()
    if split and sum(_n(v) or 0 for v in split.values()) == n:
        for label, v in split.items():
            out[_group(label)] += _n(v) or 0
    else:
        out[_group(s.get("likely"))] += n
    return out


def _by_address(entries, delivered=None):
    """Census streams merged per address, each with what it has left per
    group (likes: own, spoof, unclear, from _split): an address with
    failures under two labels is named under both, with each count. An
    address with nothing left drops out. delivered: {address: messages
    delivered despite failing} (the view's ddf_senders), carried along so
    a spoof the policy was supposed to stop is never called handled."""
    merged = {}
    delivered = delivered or {}
    for s in entries:
        name = str(s.get("name") or "?").lower()
        e = merged.setdefault(name, {"name": name, "count": 0, "domain": s.get("domain"), "likes": Counter(),
                                     "delivered": _n(delivered.get(name)) or 0})
        e["count"] += _n(s.get("count")) or 0
        e["likes"].update(_split(s))
    out = []
    for e in merged.values():
        likes = Counter({k: v for k, v in e["likes"].items() if v > 0})
        e.update(likes=dict(likes), likely=likes.most_common(1)[0][0] if likes else UNCLEAR)
        if e["count"] > 0:
            out.append(e)
    return sorted(out, key=lambda e: (-e["count"], e["name"]))


def _groups(senders):
    """{own, spoof, unclear} for the one-liner: every address with what it
    has left under that group, worst first, with how many of its messages
    reached a mailbox despite failing."""
    groups = {OWN: [], SPOOF: [], UNCLEAR: []}
    for s in senders:
        for label, n in (s.get("likes") or {s.get("likely"): s.get("count") or 0}).items():
            if n > 0:
                groups[_group(label)].append({"name": s["name"], "count": n, "domain": s.get("domain"),
                                              "likely": _group(label), "delivered": s.get("delivered") or 0})
    for g in groups.values():
        g.sort(key=lambda e: (-e["count"], e["name"]))
    return groups


def _delivered_of(view):
    """{address: messages delivered despite failing} the exceptions left, from the view."""
    return {s["name"]: s["count"] for s in (view or {}).get("ddf_senders") or []}


def own_domain_view(report, view, org):
    """The organization domain's own mail-log numbers (maillog.by_domain[org]:
    its genuine failures, top senders and the likely split), with the census
    entries for its senders merged per address; None when the report carries
    no per-domain attribution, in which case the one-liner falls back to the
    whole census. What the formal exceptions cover comes off exactly:
    by_domain counts the excepted failures per label and the census per
    stream, both from the marks audit.py put on the verdicts. A report from
    before those counts keeps every number raw, and its excepted total (the
    gate's) is only named as a part of them (excepted_reduced False)."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else None
    bd = (ml or {}).get("by_domain")
    c = bd.get(org) if isinstance(bd, dict) else None
    if not isinstance(c, dict) or _n(c.get("genuine_failures")) is None:
        return None
    subs = []
    sub = c.get("subdomains_total") if isinstance(c.get("subdomains_total"), dict) else None
    if not _n(c.get("logical_messages")) and sub and _n(sub.get("logical_messages")):
        # the org's mail all sits in its subdomains (a damaged domains list reads as none named)
        c, subs = sub, [str(d) for d in (sub.get("domains") if isinstance(sub.get("domains"), list) else [])]
    senders = _by_address([s for s in (view["by_sender"] if view else [])
                           if s.get("domain") == org or s.get("domain") in subs], _delivered_of(view))
    by_likely = c.get("by_likely") if isinstance(c.get("by_likely"), dict) else None
    reduced = _n(c.get("excepted")) is not None
    if reduced:
        excepted = _n(c["excepted"])
        gone = c.get("excepted_by_likely") if isinstance(c.get("excepted_by_likely"), dict) else {}
        if by_likely is not None:
            by_likely = {k: max(0, (_n(v) or 0) - (_n(gone.get(k)) or 0)) for k, v in by_likely.items()}
    else:
        gate_dom = ((report.get("gate") or {}).get("domains") or {}).get(org) or {}
        gone = gate_dom.get("excepted_by_likely") if isinstance(gate_dom.get("excepted_by_likely"), dict) else {}
        excepted = sum(_n(v) or 0 for v in gone.values()) or (_n(gate_dom.get("excepted_failures")) or 0)
    if by_likely is None and senders:
        cnt = Counter()
        for s in senders:
            cnt.update(s["likes"])
        by_likely = {k: cnt.get(k, 0) for k in (SPOOF, OWN, UNCLEAR)}
    # the busiest senders among the failures no exception covers, when the report counts them (top_senders_after)
    tops = c.get("top_senders_after") if isinstance(c.get("top_senders_after"), list) and reduced else c.get("top_senders")
    return {"genuine_failures": _n(c.get("genuine_failures")) or 0, "logical_messages": _n(c.get("logical_messages")),
            "delivered_despite_fail": _n(c.get("delivered_despite_fail")), "excepted_reduced": reduced,
            "by_likely": {k: _n(v) or 0 for k, v in by_likely.items()} if by_likely else None,
            "top_senders": _entries(tops, SENDER_KEYS) or [], "senders": senders,
            "subdomains": subs, "window": c.get("window") if isinstance(c.get("window"), dict) else None,
            "excepted": excepted}


def _excepted_names(entries, cap=3):
    return ", ".join("%s x%d" % (e["name"], e["count"]) for e in entries[:cap]) + (", ..." if len(entries) > cap else "")


def _excepted_ips(report):
    """The aggregate-report sources the gate formally excepted: never work, never listed as failing."""
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    exc = gate.get("exceptions") if isinstance(gate.get("exceptions"), dict) else {}
    ips = exc.get("excepted_streams")
    return {str(ip) for ip in ips if ip} if isinstance(ips, list) else set()


def streams(view, rua, own=None, excepted_ips=()):
    """The one-liner's senders: the organization domain's own (from
    maillog.by_domain), else every sender in the census 'across all audited
    domains', else source IPs from the aggregate reports when there is no mail
    log, less the ones the gate formally excepted (excepted_ips). An address
    is named in every group where it has failures left, with that many."""
    if own is not None:
        groups = _groups(own["senders"])
        scope = "unaudited subdomains" if own.get("subdomains") else "own domain"
        # the domain's own span when the report carries it: the whole log often reaches further
        return {"basis": "mail log", "scope": scope, "window": own.get("window") or (view or {}).get("window"),
                "excepted": own.get("excepted") or 0, "excepted_reduced": own.get("excepted_reduced", True),
                "own": groups[OWN], "spoof": groups[SPOOF], "unclear": groups[UNCLEAR],
                "genuine_failures": own["genuine_failures"], "logical_messages": own["logical_messages"],
                "by_likely": own["by_likely"], "top_senders": own["top_senders"],
                "subdomains": own.get("subdomains") or []}
    if view is not None and (view["by_sender"] or view["genuine_failures"] is not None):
        groups = _groups(_by_address(view["by_sender"], _delivered_of(view)))
        excepted = view.get("excepted") or []
        out = {"basis": "mail log", "scope": "all audited domains", "window": view.get("window"),
               "excepted": sum(e["count"] for e in excepted), "excepted_reduced": True,
               "excepted_senders": len({str(e["name"]).lower() for e in excepted}),
               "own": groups[OWN], "spoof": groups[SPOOF], "unclear": groups[UNCLEAR]}
        if not view.get("exceptions_counted") and view.get("excepted_unsplit"):
            out.update(excepted=view["excepted_unsplit"], excepted_reduced=False, excepted_senders=None)
        return out
    if isinstance(rua, dict):
        skip = {str(ip) for ip in excepted_ips or ()}
        fs = [s for s in (rua.get("failing_streams") or []) if isinstance(s, dict) and str(s.get("source_ip")) not in skip]

        def conv(s):
            return {"name": "%s as %s" % (s.get("source_ip", "?"), ", ".join(s.get("header_from") or [])[:60] or "?"),
                    "count": _n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0),
                    "likely": _group(s.get("likely"))}
        groups = {OWN: [], SPOOF: [], UNCLEAR: []}
        for s in fs:
            e = conv(s)
            groups[e["likely"]].append(e)
        return {"basis": "aggregate reports", "scope": "aggregate reports", "own": groups[OWN],
                "spoof": groups[SPOOF], "unclear": groups[UNCLEAR]}
    return None


def spoof_share(rua, excepted_ips=()):
    """What the aggregate reports' sources labelled likely_spoof add up to:
    failing messages, sources, and what receivers did with them - less the
    sources the gate formally excepted (excepted_ips), which are listed once
    as excepted and never counted as spoofing."""
    skip = {str(ip) for ip in excepted_ips or ()}
    fs = [s for s in (rua.get("failing_streams") if isinstance(rua, dict) and isinstance(rua.get("failing_streams"), list) else [])
          if isinstance(s, dict) and s.get("likely") == "likely_spoof" and str(s.get("source_ip")) not in skip]
    if not fs:
        return None
    disp = Counter()
    for s in fs:
        for k, v in (s.get("dispositions") if isinstance(s.get("dispositions"), dict) else {}).items():
            disp[k] += _n(v) or 0
    msgs = sum((_n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0)) for s in fs)
    return {"messages": msgs, "sources": len(fs), "rejected": disp.get("reject", 0),
            "quarantined": disp.get("quarantine", 0), "delivered": disp.get("none", 0)}


def window_of(report):
    """The date window the inputs state: the aggregate reports' own range,
    else the requested --since/--until bounds, else 'this run's window'.
    Never a number of days the inputs do not carry. The mail log's own span
    (maillog.window, when the export has a time column) is stated next to
    every mail-log number instead: it is often far shorter."""
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else {}
    tot = rua.get("totals") if isinstance(rua.get("totals"), dict) else {}
    begin, end = _day(tot.get("begin_date")), _day(tot.get("end_date"))
    if begin or end:
        text = begin if begin == end else "%s to %s" % (begin or "the first report", end or "the last report")
        return {"text": text, "source": "aggregate reports", "begin": begin, "end": end}
    inp = report.get("inputs") if isinstance(report.get("inputs"), dict) else {}
    filt = rua.get("filters") if isinstance(rua.get("filters"), dict) else {}
    since, until = _day(inp.get("since") or filt.get("since")), _day(inp.get("until") or filt.get("until"))
    if since or until:
        if since and until:
            text = "%s to %s" % (since, until)
        else:
            text = ("from %s" % since) if since else ("up to %s" % until)
        return {"text": text, "source": "the requested window", "begin": since, "end": until}
    return {"text": "this run's window", "source": None, "begin": None, "end": None}


# ------------------------------------------------------------------ history and trend

def _pair(obj):
    """{previous, now, change} from a delta value of any reasonable shape."""
    out = {"previous": None, "now": None, "change": None}
    if isinstance(obj, dict):
        out["previous"] = next((_f(obj[k]) for k in ("previous", "prev", "before", "last", "from")
                                if _f(obj.get(k)) is not None), None)
        out["now"] = next((_f(obj[k]) for k in ("now", "current", "after", "to", "this")
                           if _f(obj.get(k)) is not None), None)
        out["change"] = next((_f(obj[k]) for k in ("change", "delta", "diff") if _f(obj.get(k)) is not None), None)
    elif _f(obj) is not None:
        out["change"] = _f(obj)
    return out


def trend_from_delta(delta, now_gf, now_pr):
    if not isinstance(delta, dict):
        return None
    label = None
    for k in ("previous_generated_utc", "previous_run", "previous", "prev_run", "compared_to", "baseline", "since", "vs"):
        v = delta.get(k)
        if isinstance(v, dict):
            v = v.get("generated_utc") or v.get("run") or v.get("date")
        if isinstance(v, str) and v:
            label = _day(v) or v
            break
    gf = _pair(delta.get("genuine_failures"))
    pr = _pair(delta.get("pass_rate") if "pass_rate" in delta else delta.get("rua_pass_rate"))
    prev_gf = gf["previous"]
    if prev_gf is None and gf["change"] is not None and now_gf is not None:
        prev_gf = now_gf - gf["change"]
    prev_pr = pr["previous"]
    if prev_pr is None and pr["change"] is not None and now_pr is not None:
        change = pr["change"] if abs(pr["change"]) <= 1 else pr["change"] / 100.0
        prev_pr = now_pr - change
    if prev_gf is None and prev_pr is None:
        mw = delta.get("maillog_window") if isinstance(delta.get("maillog_window"), dict) else None
        if label and mw and mw.get("comparable") is False:  # refused on purpose: say so, never "first run"
            return {"source": "delta", "label": label, "previous_genuine_failures": None, "previous_pass_rate": None}
        return None
    return {"source": "delta", "label": label or "the previous run",
            "previous_genuine_failures": int(prev_gf) if prev_gf is not None else None,
            "previous_pass_rate": prev_pr}


def merge_trends(candidates):
    """The first candidate that carries a figure (a failure count or a pass
    rate), its gaps filled from the other candidates that describe the same
    previous run (audit.py's delta carries the failure change but no pass
    rate; metrics.json carries both). A delta the audit refused to compare
    carries no figure: it is the trend only when no candidate carries one."""
    cands = [c for c in candidates if c]
    if not cands:
        return None
    base = next((c for c in cands if c.get("previous_genuine_failures") is not None
                 or c.get("previous_pass_rate") is not None), cands[0])
    out = dict(base)
    for c in cands:
        if c is base or c["label"] != out["label"]:
            continue
        for k in ("previous_genuine_failures", "previous_pass_rate", "previous_rua_messages", "previous_maillog_hours",
                  "previous_cuts", "previous_orgs"):
            if out.get(k) is None and c.get(k) is not None:
                out[k] = c[k]
                if k in ("previous_genuine_failures", "previous_pass_rate"):
                    out["source"] += " + " + c["source"]
    return out


def _cut_reason(cut_orgs):
    """'the row budget cut the mail log for corp.example in the previous run',
    from {org: {"now": cut info or None, "previous": cut info or None}}: the
    orgs cut in each run, each run under the cause its own record names
    (none when it does not say; a budget that cut the previous run is never
    said to have cut this one), 'and N more' past three."""
    order = ("this run", "the previous run", "both runs")
    by_cause = {}
    for org, sides in sorted(cut_orgs.items()):
        now, prev = (sides.get("now"), sides.get("previous")) if isinstance(sides, dict) else (None, None)
        if now is None and prev is None:
            continue
        if now is not None and prev is not None and audit._cut_cause(now) == audit._cut_cause(prev):
            by_cause.setdefault(audit._cut_cause(now) or "", {}).setdefault(order[2], []).append(str(org))
            continue
        if now is not None:
            by_cause.setdefault(audit._cut_cause(now) or "", {}).setdefault(order[0], []).append(str(org))
        if prev is not None:
            by_cause.setdefault(audit._cut_cause(prev) or "", {}).setdefault(order[1], []).append(str(org))
    parts = []  # this run's cuts first, then the previous run's; a named cause before an unnamed one
    for cause in sorted(by_cause, key=lambda c: (min(order.index(w) for w in by_cause[c]), not c, c)):
        runs = " and ".join("for %s in %s" % (audit._names(by_cause[cause][w]), w) for w in order if w in by_cause[cause])
        parts.append("%s cut the mail log %s" % (cause, runs) if cause else "the mail log was cut %s" % runs)
    return "; ".join(parts)


def _report_orgs(report):
    """The organizations a report audited, from its gate: a set of org domains (empty when it has no gate)."""
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    doms = gate.get("domains") if isinstance(gate.get("domains"), dict) else {}
    return {org_domain(_dom(d)) for d in doms if _dom(d)}


def _orgs_reason(orgs):
    """'shop.example audited in one of the two runs only', the delta's reason in the trend's words."""
    return "%s audited in one of the two runs only" % audit._names(sorted(str(o) for o in orgs if o))


def apply_comparability(trend, delta, report, view):
    """Drop a comparison the two runs cannot bear, and say why: failure
    counts when collect.py cut an organization's mail log in either run (the
    row budget keeps the newest hours of an org's pull; an hour can stay at
    the API cap) or the two mail logs cover very different spans, the pass
    rate when the outside views differ tenfold in size (a first full archive
    against an empty one). The audit's delta carries the judgement when it
    is about the trend's own run; otherwise it is made here, by the audit's
    rules, from this report's cuts and span and the previous run's."""
    if not trend:
        return trend
    t, why = dict(trend), []
    # the delta's judgement is about its own previous run: it applies only to a trend labelled with
    # that run (a trend from --previous or metrics.json about another run is judged on its own figures)
    same_run = isinstance(delta, dict) and _day(delta.get("previous_generated_utc")) == t.get("label")
    mw = delta.get("maillog_window") if same_run and isinstance(delta.get("maillog_window"), dict) else None
    fail_ok = mw.get("comparable") if mw and isinstance(mw.get("comparable"), bool) else None
    fail_why = []
    if fail_ok is False and ("cut_orgs" in mw or "log_comparable" in mw or "orgs_not_shared" in mw):
        # the delta's own reasons, each as it recorded it: the cuts, an organization audited in one run only
        # (the whole log then covers different populations), the spans
        if isinstance(mw.get("cut_orgs"), dict) and mw["cut_orgs"]:
            fail_why.append(_cut_reason(mw["cut_orgs"]))
        shared = mw.get("orgs_not_shared") if isinstance(mw.get("orgs_not_shared"), list) else []
        if shared:
            fail_why.append(_orgs_reason(shared))
        if mw.get("log_comparable") is False:
            fail_why.append("the two mail logs cover very different spans")
    elif fail_ok is False:  # a delta from before the cuts were recorded named the domains whose own spans differed
        listed = mw.get("domains_not_comparable")
        names = sorted(str(d) for d in listed if d) if isinstance(listed, list) else []
        if names:
            fail_why.append("the mail-log rows of %s cover very different spans in the two runs" % audit._names(names))
    elif fail_ok is None and None not in (t.get("previous_genuine_failures"), (view or {}).get("genuine_failures")):
        # no verdict about this trend's run: the audit's rules on both runs' own figures - the cuts each
        # recorded, the organizations each audited (an entry that does not say gets the benefit of the doubt),
        # and the whole log's spans (this one from its stamps, two spans under an hour alike)
        now_cut = audit.maillog_cuts(report)
        prev_cut = audit._dict(t.get("previous_cuts"))
        if now_cut or prev_cut:
            fail_why.append(_cut_reason({org: {"now": now_cut.get(org), "previous": prev_cut.get(org)}
                                         for org in set(now_cut) | set(prev_cut)}))
        prev_orgs, now_orgs = t.get("previous_orgs"), _report_orgs(report)
        if isinstance(prev_orgs, list) and now_orgs and set(prev_orgs) != now_orgs:
            fail_why.append(_orgs_reason(set(prev_orgs) ^ now_orgs))
        if not audit._spans_comparable(audit._hours(audit._dict(report.get("maillog")).get("window")),
                                       audit._hours({"hours": t.get("previous_maillog_hours")})):
            fail_why.append("the two mail logs cover very different spans")
        fail_ok = not fail_why
    if fail_ok is False:
        t["previous_genuine_failures"] = None
        why.append("failure counts are not compared: %s"
                   % (", and ".join(fail_why) or "the two mail logs cover very different spans"))
    # the pass rate is judged from the trend's own figures, by the audit's tenfold rule: the delta carries no
    # rate, and a trend merged by day could hold another same-day run's outside view
    now_m = _n(((report.get("rua") or {}).get("totals") or {}).get("messages"))
    prev_m = _n(t.get("previous_rua_messages"))
    if now_m is not None and prev_m is not None and (now_m or prev_m):
        if not (now_m and prev_m and min(now_m, prev_m) / max(now_m, prev_m) >= 0.1):
            t["previous_pass_rate"] = None
            why.append("the pass rate is not compared: the two outside views differ too much in size")
    elif now_m == 0 and prev_m == 0:
        t["previous_pass_rate"] = None  # two empty outside views: a 0/0 rate on each side
        why.append("the pass rate is not compared: neither outside view carries messages")
    t["not_comparable"] = why
    return t


def trend_from_report(previous):
    if not isinstance(previous, dict):
        return None
    ml = audit._dict(previous.get("maillog"))
    tot = audit._dict(audit._dict(previous.get("rua")).get("totals"))
    gf = _n(audit._dict(ml.get("counters")).get("genuine_failures"))
    pr = _f(tot.get("pass_rate"))
    if gf is None and pr is None:
        return None
    orgs = _report_orgs(previous)
    return {"source": "previous report", "label": _day(previous.get("generated_utc")) or "the previous run",
            "previous_genuine_failures": gf, "previous_pass_rate": pr,
            "previous_rua_messages": _n(tot.get("messages")),
            "previous_maillog_hours": audit._hours(ml.get("window")),  # from its stamps, as the audit reads it
            "previous_cuts": audit.maillog_cuts(previous),
            "previous_orgs": sorted(orgs) if orgs else None}  # None: the report does not say, benefit of the doubt


def _same_run(entry, report, view):
    """A metrics entry is this run when it is from the same UTC day and carries the same counts."""
    if _day(entry.get("run")) != _day(report.get("generated_utc")):
        return False
    gf = view["genuine_failures"] if view else None
    rm = _n(((report.get("rua") or {}).get("totals") or {}).get("messages"))
    return _n(entry.get("genuine_failures")) == gf and _n(entry.get("rua_messages")) == rm


def previous_entry(metrics, report, view):
    """The run before this one in metrics.json, whether or not this run is
    already in it: the entry whose run is the report's own (inputs.run,
    collect.py's stamp) is never the previous run, and without that stamp
    the same UTC day with the same counts is taken for this run."""
    entries = sorted((e for e in metrics if isinstance(e, dict) and e.get("run")), key=lambda e: str(e["run"]))
    inputs = report.get("inputs") if isinstance(report.get("inputs"), dict) else {}
    run = str(inputs.get("run") or "").strip()
    now = str(report.get("generated_utc") or "").replace(":", "")
    before = [e for e in entries
              if not now or str(e["run"]).replace(":", "") <= now or _day(e["run"]) == _day(now) or str(e["run"]) == run]
    before = [e for e in before if (str(e["run"]) != run if run else not _same_run(e, report, view))]
    return before[-1] if before else None


def trend_from_metrics(metrics, report, view):
    e = previous_entry(metrics, report, view)
    if not e:
        return None
    gf, pr = _n(e.get("genuine_failures")), _f(e.get("rua_pass_rate"))
    if gf is None and pr is None:
        return None
    orgs = e.get("maillog_cut_orgs")  # names only, no cause; an entry from before they were recorded has none
    doms = e.get("domains")  # the names the run audited, as collect.py records them; an older entry has none
    audited = {org_domain(_dom(d)) for d in doms if _dom(d)} if isinstance(doms, dict) else set()
    return {"source": "metrics", "label": _day(e.get("run")) or str(e.get("run")),
            "previous_genuine_failures": gf, "previous_pass_rate": pr,
            "previous_rua_messages": _n(e.get("rua_messages")), "previous_maillog_hours": _f(e.get("maillog_hours")),
            "previous_cuts": ({str(o).strip().lower(): {} for o in orgs if isinstance(o, str) and o.strip()}
                              if isinstance(orgs, list) else None),
            "previous_orgs": sorted(audited) if audited else None}


def policy_since(metrics, org, policy):
    """The run date on which the current policy first appeared in the history,
    only when the history also shows a different policy before it."""
    if not policy:
        return None
    entries = sorted((e for e in metrics if isinstance(e, dict) and e.get("run")), key=lambda e: str(e["run"]))
    seq = [audit._dict(audit._dict(e.get("domains")).get(org)).get("policy") for e in entries]  # odd shapes: unknown
    last = max((i for i, p in enumerate(seq) if p == policy), default=None)
    if last is None:
        return None
    start = last
    while start > 0 and seq[start - 1] == policy:
        start -= 1
    if start == 0 or not seq[start - 1]:
        return None
    return _day(entries[start].get("run"))


# ------------------------------------------------------------------ plan helpers

def plan_changes(plan):
    return [c for c in ((plan or {}).get("changes") or []) if isinstance(c, dict)]


def step_label(change):
    """A short action for one plan change, from its record rather than its prose."""
    kind = change.get("kind")
    host = str(change.get("hostname") or "")
    value = str(change.get("value") or "")
    why = str(change.get("why") or "")
    first = why.split(":")[0].strip() or kind or "change"
    is_dmarc = value.lower().startswith("v=dmarc1")
    is_spf = value.lower().startswith("v=spf1")
    tags = dmarc_tags(value) if is_dmarc else {}
    current = str(change.get("current") or "")
    cur = dmarc_tags(current) if current.lower().startswith("v=dmarc1") else {}
    if kind == "park":
        return "park it with SPF -all" if is_spf else "park it with p=reject"
    if kind == "no_mail":
        return "move straight to p=quarantine (no mail measured)"
    if kind == "new":
        return "publish a p=%s monitoring record" % tags.get("p", "none")
    if kind == "modify":
        if is_spf:
            parts = value.split()
            return "change the SPF ending to %s" % (parts[-1] if parts else "~all")
        if "rua" in why.lower() and cur.get("rua"):  # it reports already, just not to the toolkit
            return "add the toolkit's report address to rua"
        if "rua" in why.lower():
            return "add rua reporting to the DMARC record"
        return first
    if kind == "todo":
        if "_domainkey" in host:
            return "set up DKIM signing"
        if is_spf or "spf" in why.lower():
            if "lookup" in why.lower():
                return "cut SPF lookups under the limit"
            return "publish an SPF record from the sender inventory"
        return first
    if kind == "ratchet":
        if is_spf:
            return "harden SPF to -all"
        if tags.get("p") and tags.get("p") != cur.get("p"):
            s = "move to p=%s" % tags["p"]
            if tags.get("pct", "").isdigit() and int(tags["pct"]) < 100:
                s += " at pct=%s" % tags["pct"]
            return s
        if tags.get("pct") and tags.get("pct") != cur.get("pct"):
            return "raise pct to %s" % tags["pct"]
        if tags.get("sp") and tags.get("sp") != cur.get("sp"):
            return "set sp=%s" % tags["sp"]
        return first
    return first


def table_step(change):
    """A plan change as the per-domain table's Next step cell: a domain the
    run measured sending nothing reads 'no mail measured: quarantine now';
    any other change, its step_label. A record for a name whose own _dmarc
    lookup failed says it waits on a lookup."""
    step = "no mail measured: quarantine now" if change.get("kind") == "no_mail" else step_label(change)
    return step + (" (once a lookup shows it has no record of its own)" if looks_first(change) else "")


def reword_prereq(text):
    """A plan prerequisite as the condition that clears it; never verbatim."""
    for rx, fn in PREREQ_REWORDS:
        m = rx.match(text or "")
        if m:
            return plain(fn(m))
    return plain(text)


LOOKUP_FIRST = re.compile(r"^look up _dmarc\.\S+ first:")
# the plan's prerequisite for one failing outside-view source (plan.evidence_for), one per source
STREAM_PREREQ_RX = re.compile(r"^aggregate reports: (\S+) sends (\d+) message\(s\) as (\S+) and fails")


def reword_prereqs(texts):
    """Every plan prerequisite reworded as its condition (reword_prereq), with
    the per-source aggregate-report ones folded into one condition that names
    the busiest: a busy tenant's reject row carried ninety of them, and a
    sentence with ninety clauses is not a sentence anyone reads."""
    out, streams = [], []
    for p in texts:
        m = STREAM_PREREQ_RX.match(p or "")
        if m:
            streams.append((int(m.group(2)), m.group(1), m.group(3)))
        else:
            out.append(reword_prereq(p))
    if len(streams) == 1:
        n, ip, dom = streams[0]
        out.append("the sender at %s (%d messages as %s) is fixed" % (ip, n, dom))
    elif streams:
        streams.sort(key=lambda s: (-s[0], s[1]))
        top = ", ".join("%s (%d as %s)" % (ip, n, dom) for n, ip, dom in streams[:STREAM_NAMES])
        more = len(streams) - STREAM_NAMES
        out.append("the %d failing outside-view senders are fixed or formally excepted (busiest: %s%s)"
                   % (len(streams), top, ("; %d more in report.md" % more) if more > 0 else ""))
    return out


def looks_first(change):
    """True when a record waits on a lookup of the name's own _dmarc record
    (plan.lookup_first): nobody saw whether it has one, and a second record
    would leave it with no policy at all."""
    return any(LOOKUP_FIRST.match(p) for p in prereqs_of(change))


def prereqs_of(change):
    """A change's prerequisites still to confirm, as text: plan.py's typed
    prerequisite_items when present (an item marked met is done), else the
    plain prerequisites list; either may hold strings or {text, ...} dicts."""
    src = change.get("prerequisite_items")
    if not (isinstance(src, list) and src):
        src = change.get("prerequisites") or []
    out = []
    for p in src:
        if isinstance(p, dict):
            if p.get("met") is True or not p.get("text"):
                continue
            out.append(str(p["text"]))
        elif isinstance(p, str) and p:
            out.append(p)
    return out


def changes_for(plan, domain):
    return [c for c in plan_changes(plan) if (c.get("domain") or "").lower() == domain]


def holds_for(plan, domain=None):
    return [h for h in ((plan or {}).get("holds") or [])
            if isinstance(h, dict) and (domain is None or (h.get("domain") or "").lower() == domain)]


# ------------------------------------------------------------------ the document

WEAK_HEADLINES = ("shortest audited apex", "shortest audited domain")
TYPED_HEADLINES = ("first on the command line", "first in --file", "first in audit.toml", "first domain given")
# labels the gate gives a headline its volume rule chose: it ranked the org families
# and picked the member already, so the subject is settled
VOLUME_HEADLINES = ("most internal mail", "most passing or internal mail in the mail log",
                    "most passing mail in the mail log", "most passing mail in the reports", "most mail in this run")


def _passing(c, verdicts=True):
    """Mail a domain itself sent, counted the way audit.mail_volume counts it:
    messages that passed authentication or stayed inside the tenant when the
    log carried verdicts and the report has those counts, else logical
    messages minus genuine failures (a report from before the counts)."""
    c = c if isinstance(c, dict) else {}
    if verdicts and c.get("passing_messages") is not None:
        return (_n(c.get("passing_messages")) or 0) + (_n(c.get("internal_messages")) or 0)
    return max(0, (_n(c.get("logical_messages")) or 0) - (_n(c.get("genuine_failures")) or 0))


def _rua_own(domain, froms, audited):
    """Passing messages the aggregate reports attribute to the domain itself or
    to its unaudited subdomains - audit.mail_volume's attribution."""
    total = 0
    for h in froms:
        if not isinstance(h, dict):
            continue
        d = _dom(h.get("domain"))
        if not d:
            continue
        home = d if d in audited else max((a for a in audited if d.endswith("." + a)), key=len, default=None)
        if home != domain:
            continue
        ok = h.get("pass")
        if ok is None:
            ok = (_n(h.get("count")) or 0) - (_n(h.get("fail")) or 0)
        total += max(0, _n(ok) or 0)
    return total


def pick_org(report, org_name=None):
    """--org-name, else the gate's headline domain. A typed headline (command
    line, --file, or the first domain given when nothing carries a source) is
    always the subject, and so is a headline the volume rule chose: the gate
    ranked the org families and picked the member already. Any other
    subdomain headline (a tenant default domain, an older report) maps to its
    audited apex only when that apex sends mail of its own - by the mail log,
    else by the aggregate reports; an apex seen only in the reports, or one
    that only gets spoofed, does not count. With no headline: the first
    audited apex in the order given, else the first audited domain. A report
    written before the volume rule, whose headline is only the shortest name,
    is re-ranked the way the gate ranks now: typed sources first, then org
    families by the mail each audited domain itself sent (its rows plus its
    unaudited subdomains' in an unscoped mail log, else its passing mail in
    the reports), the apex leading its family when it has mail of its own,
    else the busiest member."""
    if org_name:
        return org_name.strip().lower().rstrip(".")
    gate = audit._dict(report.get("gate"))
    inputs = audit._dict(report.get("inputs"))
    given = inputs.get("domains") if isinstance(inputs.get("domains"), list) else []
    audited = [_dom(d) for d in given if d]
    audited += [_dom(d) for d in audit._dict(gate.get("domains"))]
    audited = [d for d in dict.fromkeys(audited) if d]
    covered = audit._dict(audit._dict(report.get("rua")).get("totals")).get("domains")
    names = audited + [_dom(d) for d in (covered if isinstance(covered, list) else [])]
    names = [d for d in dict.fromkeys(names) if d]
    if not names:
        raise UsageError("the report names no audited domain; pass --org-name")
    src = gate.get("headline_source")
    head = _dom(gate.get("headline_domain"))
    maillog = audit._dict(report.get("maillog"))
    by = {_dom(d): c for d, c in audit._dict(maillog.get("by_domain")).items()}
    verdicts = bool(maillog.get("auth_column"))

    def own_mail(d):
        c = by.get(d) if isinstance(by.get(d), dict) else {}
        return _passing(c, verdicts) + _passing(c.get("subdomains_total"), verdicts)

    if head and src in WEAK_HEADLINES:
        given = [_dom(d) for d in given if d]
        if given and not inputs.get("domain_sources"):
            return given[0]  # nothing carries a source: the first domain given is the typed one, as the gate rules now
        srcs = {_dom(d): tags for d, tags in audit._dict(inputs.get("domain_sources")).items()}
        for tag in ("cli", "file"):
            typed = [d for d in audited if tag in (srcs.get(d) or ())]
            if typed:
                return typed[0]
        scoped = bool(maillog.get("sender_domain"))  # a log scoped to one domain cannot rank the rest
        own = {d: own_mail(d) for d in audited if d in by} if (by and not scoped) else {}
        if not any(own.values()):  # no mail log to rank by: the reports' passing mail, as the gate does
            froms = (report.get("rua") or {}).get("by_header_from") or []
            own = {d: _rua_own(d, froms, audited) for d in audited} if froms else {}
        family = {}
        for d, n in own.items():
            family[org_domain(d)] = family.get(org_domain(d), 0) + n
        family = {o: n for o, n in family.items() if n > 0}
        if family:
            first = {o: min(audited.index(d) for d in audited if org_domain(d) == o) for o in family}
            best = max(family, key=lambda o: (family[o], -first[o]))
            members = [d for d in audited if org_domain(d) == best]
            busy = [d for d in members if own.get(d, 0) > 0]
            if best in members and (own.get(best, 0) > 0 or not busy):
                return best
            return max(busy, key=lambda d: (own[d], -audited.index(d))) if busy else members[0]
    if head:
        apex = org_domain(head)
        if apex == head or src in TYPED_HEADLINES or src in VOLUME_HEADLINES:
            return head
        gd = {_dom(d): g for d, g in audit._dict(gate.get("domains")).items()}
        if apex not in gd:
            return head  # an apex that was never audited cannot be the subject
        froms = audit._dict(report.get("rua")).get("by_header_from")
        froms = froms if isinstance(froms, list) else []
        if by:
            sends = own_mail(apex) > 0
        elif froms:
            sends = _rua_own(apex, froms, audited) > 0
        else:
            rows = _n(audit._dict(gd.get(apex)).get("maillog_rows"))
            sends = rows is None or rows > 0 or not report.get("maillog")
        return apex if sends else head
    for d in names:
        if org_domain(d) == d:
            return d
    return head or names[0]


def policy_tags(report, domain):
    dns_doc = (report.get("dns") or {}).get(domain) or {}
    if dns_doc.get("dmarc"):
        return dmarc_tags(dns_doc["dmarc"])
    for s in ((report.get("rua") or {}).get("policy_check") or {}).get("seen") or []:
        if isinstance(s, dict) and (s.get("domain") or "").lower() == domain:
            tags = {"p": (s.get("p") or "none").lower()}
            for k in ("sp", "pct"):
                if s.get(k):
                    tags[k] = str(s[k])
            return tags
    return {}


def current_policy(report, domain):
    """The gate's policy for one domain; the overall one when the gate has no
    per-domain entries. Text or None: a damaged value reads as unknown."""
    gate = audit._dict(report.get("gate"))
    doms = audit._dict(gate.get("domains"))
    g = audit._dict(doms.get(domain))
    policy = g.get("current_policy") if doms else gate.get("current_policy")
    return policy if isinstance(policy, str) and policy else None


def policy_text(report, domain):
    policy = current_policy(report, domain)
    dns_doc = audit._dict(audit._dict(report.get("dns")).get(domain))
    if not policy:
        return ("no DMARC record" if dns_doc.get("dmarc_status") == "absent" else "unknown"), None
    tags = policy_tags(report, domain)
    text = "p=" + policy
    pct = tags.get("pct", "")
    low = pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject")  # pct means nothing at p=none
    if low:
        text += ", pct=" + pct
    if dns_doc.get("inherited") and dns_doc.get("dmarc_source"):
        text += " (inherited from %s)" % dns_doc["dmarc_source"]
    return text, (pct if low else None)


# A report from before the gate split its reasons into blockers and notes: the gate's framing of the
# verdict (FRAME_RX: an insufficient_data verdict says there what evidence is missing), and what it notes
# without holding anything (NOTE_RX: the mail-log notes, the go verdict's narration, the exception notes).
FRAME_RX = re.compile(r"^(policy (is|p=)|step being gated|no DMARC policy could be determined)")
NOTE_RX = re.compile(r"^(unaudited subdomain\(s\) .* not gated here|no mail-log rows for this domain in the window"
                     r"|\d+ failing stream\(s\) look like spoofs|\S+ \(\d+ msgs, [\w-]+\)$|exception: )")
# the gate's notes the document shows under the per-domain table, as plain() words them: what the
# mail log says about the domain that no other section does (the rest is already in What is failing)
SHOWN_NOTES = re.compile(r"^(unaudited subdomains |no mail-log rows )")


def _data_hold(reason):
    """The evidence an insufficient_data reason says is missing, without the
    policy narration around it ('policy is p=none (...) but no failure
    evidence was supplied: ...; step being gated: ...')."""
    text = re.sub(r"; (?:step being gated|next step): .*$", "", reason)
    for rx in (r"\bbut (.+)$", r"nothing to ratchet - (.+)$"):
        m = re.search(rx, text)
        if m:
            return m.group(1)
    return text


def gate_split(report, domain):
    """(verdict, blockers, notes) for one domain as the gate decided them:
    what holds its next step (for insufficient_data, the evidence it needs)
    and what holds nothing. gate.domains[d] carries both lists since the
    gate wrote them; for an older report they are sorted out of the reasons.
    Either way the verdict decides: a go holds nothing, whatever its reasons
    say. The verdict is None for a gate with no verdict for the domain."""
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    doms = gate.get("domains") if isinstance(gate.get("domains"), dict) else {}
    g = doms.get(domain) if doms else gate
    g = g if isinstance(g, dict) else {}
    verdict = g.get("verdict") if isinstance(g.get("verdict"), str) else None

    def bare(r):
        return re.sub(r"^%s: " % re.escape(domain), "", str(r)) if domain else str(r)
    if isinstance(g.get("blockers"), list):
        notes = g.get("notes") if isinstance(g.get("notes"), list) else []
        return verdict, [bare(r) for r in g["blockers"] if r], [bare(r) for r in notes if r]
    evidence = gate.get("evidence") if isinstance(gate.get("evidence"), dict) else {}
    blockers, notes, data = [], [], []
    for r in g.get("reasons") if isinstance(g.get("reasons"), list) else []:
        r = bare(r)
        if r == evidence.get("statement"):
            continue
        if NOTE_RX.match(r):
            notes.append(r)
        elif FRAME_RX.match(r):
            data.append(_data_hold(r))
        else:
            blockers.append(r)
    if verdict == "go":
        return verdict, [], notes + blockers
    if verdict == "insufficient_data":
        return verdict, data[:1], notes + blockers
    return verdict, blockers, notes


def gate_reasons(report, domain):
    """The gate's blockers for one domain, as the audit wrote them: what holds its next step."""
    return gate_split(report, domain)[1]


def _named(entries, cap=3):
    return ", ".join("%s x%d" % (s["name"], s["count"]) for s in entries[:cap])


def _spoof_clause(policy, delivered=0):
    """What happens to failures that look like spoofing, given the policy -
    unless the mail log shows them delivered despite failing: then an
    override let them in, and no policy handles what an override admits."""
    if delivered:
        return ("%d of them reached a mailbox anyway: a local override delivered them, which the policy cannot "
                "undo - find that override" % delivered)
    if policy in ("quarantine", "reject"):
        return "the policy handles them"
    if policy == "none":
        return "p=none does not stop them yet"
    return "no policy stops them until one is published"


def _part(senders, labels):
    """Each address with its failures under these groups, worst first, and
    how many of its messages reached a mailbox despite failing."""
    out = [{"name": s["name"], "count": sum((s.get("likes") or {}).get(k, 0) for k in labels),
            "delivered": s.get("delivered") or 0} for s in senders]
    return sorted((s for s in out if s["count"] > 0), key=lambda s: (-s["count"], s["name"]))


def _delivered(entries):
    """Messages delivered despite failing among these addresses' entries."""
    return sum(_n(e.get("delivered")) or 0 for e in entries)


def blocker_items(report, domain, own=None):
    """The gate's blockers for one domain as the reader sees them, each typed:
    'own' (our senders: a gap to close), 'spoof' (failures that look like
    spoofing, which the policy handles once they are confirmed not ours),
    'data' (insufficient_data: the evidence the step still needs) or
    'other'. The mail-log failure count is split with the domain's own likely
    split, and each address is named with its failures in each part, so
    spoofs are never asked to be closed. A report whose split and names
    still hold the excepted messages (written before the census counted
    them) keeps the gate's own sentence: its count is after the exceptions."""
    verdict, blockers, _ = gate_split(report, domain)
    if verdict == "insufficient_data":
        return [{"kind": "data", "text": plain(b)} for b in blockers]
    out = []
    bl = (own or {}).get("by_likely") or {}
    unsplit = bool(own) and not own.get("excepted_reduced", True)  # the split and names still hold the excepted
    policy = current_policy(report, domain)
    streams = []  # the gate names every failing outside-view source; the reader gets one line for all of them
    delivered_spoofs, spoof_at = [], None  # and every spoofing source receivers delivered under the policy: one line too
    for r in blockers:
        d = SPOOF_STREAM_RX.match(r)
        if d:
            spoof_at = len(out) if spoof_at is None else spoof_at  # the line takes the first one's place
            delivered_spoofs.append((int(d.group(2)), d.group(1), r))
            continue
        s = STREAM_RX.match(r)
        if s:
            hint = STREAM_HINT_RX.search(s.group(5).strip())
            streams.append((int(s.group(2)), int(s.group(3)), s.group(1), s.group(4), hint.group(1) if hint else ""))
            continue
        m = GAP_RX.match(r)
        if m and bl.get(SPOOF) and not (unsplit and (own.get("excepted") or m.group(2))):
            total, spoof_n = int(m.group(1)), bl[SPOOF]
            rest = total - spoof_n
            senders = (own or {}).get("senders") or []
            spoofs = _part(senders, (SPOOF,))
            clause = _spoof_clause(policy, min(_delivered(spoofs), spoof_n))
            if rest > 0:
                who = "our own senders" if not bl.get(UNCLEAR) else "senders that are ours or unclear"
                names = _named(_part(senders, (OWN, UNCLEAR)))
                out.append({"kind": "own", "text": "%d %s from %s failed with no passing copy%s; the other %d look "
                            "like spoofing, and %s" % (rest, _plural(rest, "message"), who,
                                                       (" (%s)" % names) if names else "", spoof_n, clause)})
            else:
                names = _named(spoofs)
                out.append({"kind": "spoof", "text": "%d %s from %s that look like spoofing failed with no passing "
                            "copy%s; once they are confirmed not ours, %s"
                            % (spoof_n, _plural(spoof_n, "message"),
                               ("%d %s" % (len(spoofs), _plural(len(spoofs), "address", "addresses"))) if spoofs
                               else "addresses", (" (%s)" % names) if names else "", clause)})
            continue
        if m and not bl.get(SPOOF) and (bl.get(OWN) or bl.get(UNCLEAR)):
            # no failure labelled spoofing: the whole gap is our own senders' (or unclear), in the gate's words, and
            # a plan row whose own-sender condition covers it does not say it twice
            out.append({"kind": "own", "text": plain(r)})
            continue
        out.append({"kind": "other", "text": plain(r)})
    if streams:
        streams.sort(key=lambda s: (-s[0], s[2]))
        top = ", ".join("%s (%d of %d msgs, %s)" % (ip, fail, count, LIKELY_WORDS.get(label, label))
                        for fail, count, ip, label, _ in streams[:STREAM_NAMES])
        more = len(streams) - STREAM_NAMES
        # a stream a domain exception covers only in part says which domain a second exception would have to name
        hints = "; ".join("%s: %s" % (ip, hint) for _, _, ip, _, hint in streams[:STREAM_NAMES] if hint)
        out.append({"kind": "outside", "text": "%d outside-view %s %s DMARC with real volume (%s%s); fix, or formally "
                    "except %s, before p= moves%s" % (len(streams), _plural(len(streams), "sender"),
                                                      _plural(len(streams), "fails", "fail"), top,
                                                      (" and %d more in report.md" % more) if more > 0 else "",
                                                      "it" if len(streams) == 1 else "them",
                                                      (" (%s)" % hints) if hints else "")})
    if len(delivered_spoofs) == 1:  # one source keeps the gate's own sentence
        out.insert(spoof_at, {"kind": "spoof-delivered", "text": plain(delivered_spoofs[0][2])})
    elif delivered_spoofs:
        delivered_spoofs.sort(key=lambda s: (-s[0], s[1]))
        total = sum(n for n, _, _ in delivered_spoofs)
        top = ", ".join("%s (%d msgs)" % (ip, n) for n, ip, _ in delivered_spoofs[:STREAM_NAMES])
        more = len(delivered_spoofs) - STREAM_NAMES
        out.insert(spoof_at, {"kind": "spoof-delivered", "text": "%d spoofing sources (%d msgs) saw disposition none at "
                    "receivers (%s%s) - the current policy is not catching them" % (
                        len(delivered_spoofs), total, top, ("; %d more in report.md" % more) if more > 0 else "")})
    if verdict == "no_go" and not out:  # the gate holds the step even when its words were not recognised
        out.append({"kind": "other", "text": "the audit's gate says not yet (report.md lists why)"})
    return out


def gate_blockers(report, domain, own=None):
    """The gate's blockers for one domain, as text."""
    return [b["text"] for b in blocker_items(report, domain, own)]


def policy_unread_why(report, org):
    """Why the run read no policy for a domain, when it read none: 'absent'
    (DNS answered that there is no record at its name or a parent's),
    'unverified' (its DMARC lookup failed, or the record's text is missing:
    a record may well exist), 'unrecognised' (a record whose p= is none
    receivers apply) or 'unread' (DNS was not read - an offline run - and
    no report names its policy). None when a policy was read. Only 'absent'
    makes a monitoring-only record the first step: publishing one next to a
    record nobody could read leaves the name with two, and receivers then
    apply neither (DMARC-005)."""
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    doms = gate.get("domains") if isinstance(gate.get("domains"), dict) else {}
    g = doms.get(org) if isinstance(doms.get(org), dict) else {}
    step = str(g.get("next_step") or (gate.get("next_step") if not doms else "") or "")
    policy = current_policy(report, org)
    if policy is not None and not step.lower().startswith("unknown"):
        return None
    if policy is not None:
        return "unrecognised"
    dns = report.get("dns") if isinstance(report.get("dns"), dict) else {}
    doc = dns.get(org) if isinstance(dns.get(org), dict) else None
    if doc is None:
        return "unread"
    ids = {f.get("id") for f in (doc.get("findings") if isinstance(doc.get("findings"), list) else []) if isinstance(f, dict)}
    if doc.get("dmarc_status") == "error" or "DMARC-006" in ids or (doc.get("dmarc_status") == "found" and not doc.get("dmarc")):
        return "unverified"
    return "absent"


# the plan's hold on an apex's move to reject while subdomains without a record of their own follow its p=
FOLLOW_P_HOLD = audit.FOLLOW_P_HOLD
# the plan's hold on sp= while subdomains that send have no record of their own: the records to publish first
SP_HOLD = re.compile(r"^subdomains that send have no record of their own: (.+?) - publish their monitoring records "
                     r"\(above\) before sp= moves to quarantine(.*)$")


def _hold_conditions(plan, org, change):
    """The plan's holds that name this very change, as the conditions that
    clear them: the hold on the apex's move to reject while subdomains
    without a record of their own would follow it (plan.py keeps it out of
    the row's prerequisites). Empty for any other change."""
    value = str(change.get("value") or "")
    if change.get("kind") != "ratchet" or dmarc_tags(value).get("p") != "reject":
        return []
    out = []
    for h in holds_for(plan, org):
        m = FOLLOW_P_HOLD.match(str(h.get("reason") or ""))
        if m:
            names = m.group(1)
            many = "," in names or " and " in names
            out.append("%s %s a record of its own, or sp= is added to the record (subdomains without one follow "
                       "p= to reject)" % (names, "have" if many else "has"))
    return out


def _hold_summary(reason):
    """A plan hold for the ask: the condition it sets, never cut short of it
    - the follow-p= hold as the record or the sp= tag before the move, the
    sp= hold as the monitoring records to publish first, any other hold
    whole (what follows its dash is the condition, not a footnote)."""
    text = str(reason or "")
    m = FOLLOW_P_HOLD.match(text)
    if m:
        return "give %s a record of its own, or add sp= to the record, before the move to reject" % m.group(1)
    m = SP_HOLD.match(text)
    if m:
        many = "," in m.group(1) or " and " in m.group(1)
        return "publish the monitoring record%s for %s before sp= moves to quarantine%s" % (
            "s" if many else "", m.group(1), plain(m.group(2)) if m.group(2) else "")
    return plain(text)


def _row_covers(item, prereqs):
    """True when a plan row's prerequisites already carry what a gate blocker
    says, so the hold is not said twice: the row's own-sender fix for the
    gate's own-sender count, its per-source conditions for the gate's
    outside-view line, its SPF-only condition for the gate's SPF-only hold."""
    texts = " ".join(prereqs).lower()
    if item["kind"] == "own":
        return "mail-log failure" in texts or "from our own systems" in texts
    if item["kind"] == "outside":
        return "outside-view sender" in texts or "the sender at " in texts
    if item["kind"] == "other" and "pass on spf alone" in item["text"].lower():
        return "spf-only" in texts
    return False


def _step(label, source, kind, verdict, notes, items, prerequisites=(), ref=None, why=None, priority=None,
          holds=None):
    """One next step, whatever its source, in the shape every reader takes:
    prerequisites (conditions to confirm), blockers (the gate's, typed),
    holds (what holds the step beyond its own prerequisites: for a gate step
    its blockers, for a plan step the gate's blockers its row does not carry)
    and data (the evidence an insufficient_data verdict asks for)."""
    data = [b["text"] for b in items if b["kind"] == "data"]
    if holds is None:
        holds = [b["text"] for b in items if b["kind"] != "data"]
    return {"label": label, "ref": ref, "prerequisites": list(prerequisites), "why": why, "source": source,
            "kind": kind, "priority": priority, "verdict": verdict, "notes": notes, "blockers": items,
            "holds": holds, "data": data}


def org_next(report, plan, org, own=None):
    """The org domain's next step: the first plan change for it, else the
    gate's, held by what the gate's verdict says: a go is ready, a no_go
    waits on its blockers, an insufficient_data verdict on the evidence it
    needs - a plan row too, which carries the gate's blockers it does not
    name itself, and the plan's own hold on it. With no policy read, why
    decides (policy_unread_why): no record at all makes the monitoring-only
    record the first step, needing no evidence (a park row for the name
    leads instead when the plan parks it); a lookup that failed or an
    unreadable record asks for a re-run before any record is published; a
    policy receivers do not apply asks for the record to be corrected; DNS
    never read asks for the data, never a go-ahead. The plan's
    quarantine-now row (no mail measured) is the step whatever the policy,
    with its checks. The gate's notes ride along; they hold nothing."""
    changes = changes_for(plan, org)
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    doms = gate.get("domains") if isinstance(gate.get("domains"), dict) else {}
    g = doms.get(org) if isinstance(doms.get(org), dict) else {}
    gate_step = _short_step(str(g.get("next_step") or (gate.get("next_step") if not doms else "") or ""))
    verdict, _, notes = gate_split(report, org)
    notes = [plain(n) for n in notes]
    items = blocker_items(report, org, own)
    quiet = next((c for c in changes if c.get("kind") == "no_mail"), None)
    if quiet is not None:  # the run measured no mail sent as it: the quarantine-now row is the step, policy or not
        return _step(plain(step_label(quiet)), "plan", "no_mail", verdict, notes, items,
                     reword_prereqs(prereqs_of(quiet)), quiet.get("id"), quiet.get("why"), _n(quiet.get("priority")),
                     holds=[])
    why = policy_unread_why(report, org)
    if why == "unverified":
        held = [b for b in items if b["kind"] != "data" and "lookup failed" not in b["text"].lower()]
        return _step("re-run the audit with working DNS before any change to %s's DMARC record: its lookup failed, "
                     "so a record may already exist, and a second one would leave it with no policy at all" % org,
                     "gate", "recheck", verdict, notes, held, [b["text"] for b in held])
    if why == "unrecognised":
        held = [b for b in items if b["kind"] != "data"]
        return _step("correct the DMARC record at _dmarc.%s: p=%s is not a policy receivers apply (none, quarantine "
                     "or reject), so they apply none" % (org, current_policy(report, org)),
                     "gate", "fix_record", verdict, notes, held, [b["text"] for b in held])
    if why == "unread":
        return _step("determine %s's DMARC policy" % org, "gate", "unread", verdict, notes, items,
                     [b["text"] for b in items])
    if why == "absent" or gate_step.lower().startswith("unknown"):
        rec = next((c for c in changes if c.get("kind") in ("new", "park")
                    and str(c.get("hostname") or "").lower() == "_dmarc." + org), None)
        if rec is not None and rec.get("kind") == "park":  # the plan parks the name: never a monitoring record beside it
            return _step(plain(step_label(rec)), "plan", "park", verdict, notes, items, reword_prereqs(prereqs_of(rec)),
                         rec.get("id"), rec.get("why"), _n(rec.get("priority")), holds=[])
        return _step(FIRST_STEP % org, "plan" if rec else "gate", "first", verdict, notes,
                     [b for b in items if b["kind"] != "data"], (), rec.get("id") if rec else None,
                     "no policy could be read", _n(rec.get("priority")) if rec else None, holds=[])
    if changes:
        c = changes[0]
        prereqs = reword_prereqs(prereqs_of(c)) + _hold_conditions(plan, org, c)
        if _n(c.get("priority")) == 1 and c.get("kind") in ("new", "modify"):
            # a zero-risk record (monitoring, hygiene): it touches no mail anyone sends, so no verdict holds it
            # and it needs no evidence - its own checks, if any, are its prerequisites
            return _step(plain(step_label(c)), "plan", c.get("kind"), verdict, notes,
                         [b for b in items if b["kind"] != "data"], prereqs, c.get("id"), c.get("why"),
                         c.get("priority"), holds=[])
        holds = [b["text"] for b in items if b["kind"] != "data" and not _row_covers(b, prereqs)]
        return _step(plain(step_label(c)), "plan", c.get("kind"), verdict, notes, items, prereqs, c.get("id"),
                     c.get("why"), c.get("priority"), holds=holds)
    if gate_step:
        return _step(plain(gate_step), "gate", None, verdict, notes, items, [b["text"] for b in items])
    return None


def _needs_data(nxt):
    """True for a step the gate cannot judge yet (insufficient_data): the
    evidence it asks for holds the step, whatever its source - except the
    quarantine-now row, whose checks are its own, and the first record for a
    name DNS shows none at, which needs no evidence."""
    return (bool(nxt) and nxt.get("verdict") == "insufficient_data" and bool(nxt.get("data"))
            and nxt.get("kind") not in ("no_mail", "first", "park"))


def _readiness(nxt):
    """', ready when ...' for a plan step (its prerequisites are conditions),
    ', on hold while: ...' for a gate step (its blockers are observations),
    ', on hold - it needs more data: ...' when the gate says
    insufficient_data; a plan step the gate also holds says both. A step is
    ready now only when nothing holds it and its verdict is not
    insufficient_data."""
    if _needs_data(nxt):
        text = ", on hold - it needs more data: %s" % "; ".join(nxt["data"])
        if nxt["source"] == "plan" and nxt["prerequisites"]:
            text += "; with that in hand, ready when %s" % _join(nxt["prerequisites"])
        return text + "."
    holds = nxt.get("holds") or []
    if nxt["source"] == "gate":
        return (", on hold while: %s." % "; ".join(nxt["prerequisites"])) if nxt["prerequisites"] else ", and it is ready now."
    if not nxt["prerequisites"] and not holds:
        return ", and it is ready now."
    if not holds:
        return ", ready when %s." % _join(nxt["prerequisites"])
    if not nxt["prerequisites"]:
        return ", on hold while: %s." % "; ".join(holds)
    return ", ready when %s, and on hold while: %s." % (_join(nxt["prerequisites"]), "; ".join(holds))


def _handled(policy, n, delivered=0):
    """What the policy does about n senders that look like spoofing; when
    the mail log shows delivered of their messages reaching a mailbox
    despite failing, an override did that, and the policy handles nothing
    an override admits."""
    if delivered:
        return (", of which %d reached a mailbox anyway: a local override delivered them, not the policy"
                % delivered)
    if policy in ("quarantine", "reject"):
        return " and %s being handled by the policy" % _plural(n, "is", "are")
    if policy == "none":
        return ", which p=none does not stop yet"
    return ", which no policy stops until one is published"


def _own_domain_sentence(org, policy, strm):
    """The one-liner's middle from the org domain's own rows (maillog.by_domain),
    or from its unaudited subdomains' rows when it has none of its own."""
    gf, seen, bl = strm["genuine_failures"], strm["logical_messages"], strm["by_likely"]
    subs, subject, lead = strm.get("subdomains") or [], org, ""
    if subs and seen:
        listed = ", ".join(subs[:3]) + (" and %d more" % (len(subs) - 3) if len(subs) > 3 else "")
        lead = "%s has no mail-log rows of its own; its subdomains (%s) carry %d %s. " % (
            org, listed, seen, _plural(seen, "message"))
        subject = "its subdomains"
        if not gf:
            return lead + "None of them failed with no passing copy."
    if not gf:
        if seen:
            return "None of %s's own mail failed with no passing copy in the mail log (%d %s checked)." % (
                org, seen, _plural(seen, "message"))
        return "The mail log has no rows for %s, so nothing here can say which of its senders fail." % org
    span = span_phrase(strm.get("window"))
    # an older report: the parts below still hold the excepted messages, so their count qualifies the total
    unsplit = bool(strm.get("excepted")) and not strm.get("excepted_reduced", True)
    mid = lead + "%d %s from %s failed with no passing copy%s%s" % (
        gf, _plural(gf, "message"), subject,
        (" (%d of them formally excepted in audit.toml)" % strm["excepted"]) if unsplit else "",
        (" in %s" % span) if span else "")
    if bl:
        own_n, spoof_n = bl.get(OWN, 0), bl.get(SPOOF, 0)
        unclear_n = bl.get(UNCLEAR, 0)
        parts = []
        if own_n:
            who = ("%d of our own senders" % len(strm["own"])) if strm["own"] else "our own senders"
            names = _named(strm["own"], 2)
            parts.append("%d from %s%s" % (own_n, who, (" (%s)" % names) if names else ""))
        else:
            parts.append("none from our own senders")
        if unclear_n:
            k = len(strm["unclear"])
            who = "senders that are unclear"
            if k:
                who = "%d %s that %s unclear" % (k, _plural(k, "sender"), _plural(k, "is", "are"))
            names = _named(strm["unclear"], 2)
            parts.append("%d from %s and %s a look%s" % (unclear_n, who, "needs" if k == 1 else "need",
                                                       (" (%s)" % names) if names else ""))
        if spoof_n:
            k = len(strm["spoof"])
            who = ("%d %s" % (k, _plural(k, "address", "addresses"))) if k else "addresses"
            parts.append("%d from %s that look like spoofing%s"
                         % (spoof_n, who, _handled(policy, k or spoof_n, min(_delivered(strm["spoof"]), spoof_n))))
        if strm.get("excepted") and not unsplit:
            parts.append("%d formally excepted in audit.toml" % strm["excepted"])
        mid += ": " + "; ".join(parts)
    else:
        tops = _named(strm["top_senders"])
        if tops:
            mid += " (top senders: %s)" % tops
    return mid + "."


def one_liner(org, policy, pct, since, strm, nxt):
    head = "%s is at p=%s" % (org, policy) if policy else "%s has no DMARC policy this run could determine" % org
    if policy and pct:
        head += ", pct=%s" % pct
    if since:
        head += " since %s" % since
    head += "."
    if strm is None:
        mid = "No mail-log evidence in this run, so nothing here can say which of our own senders still fail."
    elif strm.get("scope") in OWN_SCOPES:
        mid = _own_domain_sentence(org, policy, strm)
    else:
        own, spoof, unclear = strm["own"], strm["spoof"], strm["unclear"]
        unit = "sender" if strm["basis"] == "mail log" else "source"
        ours = "senders" if strm["basis"] == "mail log" else "sending sources"
        via = " (from the aggregate reports)" if strm["basis"] != "mail log" else ""
        span = span_phrase(strm.get("window")) if strm["basis"] == "mail log" else None
        lead = ("Across all audited domains, in %s, " % span if span else "Across all audited domains, ") \
            if strm["basis"] == "mail log" else ""
        if own:
            mid = "%s%d of our own %s still %s%s (%s)" % (lead, len(own), ours, _plural(len(own), "fails", "fail"),
                                                          via, _named(own, 2))
        else:
            mid = "%snone of our own %s is failing%s" % (lead, ours, via)
        mid = mid[0].upper() + mid[1:]
        if unclear:
            mid += "; %d %s unclear and %s a look" % (len(unclear), _plural(len(unclear), unit + " is", unit + "s are"),
                                                       _plural(len(unclear), "needs", "need"))
        if spoof:
            mid += "; %d %s like spoofing%s" % (len(spoof), _plural(len(spoof), unit + " looks", unit + "s look"),
                                                _handled(policy, len(spoof), _delivered(spoof)))
        n = strm.get("excepted") or 0
        if n and strm.get("excepted_reduced", True):  # the senders above are what the exceptions left
            k = strm.get("excepted_senders")
            mid += "; %d %s%s formally excepted in audit.toml" % (
                n, _plural(n, "message"), (" from %d %s" % (k, _plural(k, "sender"))) if k else "")
        elif n:  # an older report: the senders above still hold them
            mid += "; %d of their failing %s %s formally excepted in audit.toml" % (
                n, _plural(n, "message"), _plural(n, "is", "are"))
        mid += "."
    if nxt and nxt.get("kind") == "first":
        ref = (" (plan %s)" % nxt["ref"]) if nxt.get("ref") else ""
        tail = "The first step is to %s%s; no policy could be read." % (nxt["label"], ref)
    elif nxt and nxt.get("kind") in ("recheck", "fix_record"):  # nothing is planned until the record can be read
        tail = "The first step is to %s." % nxt["label"]
        if nxt.get("holds"):
            tail += " What the audit found stands whatever the record says: %s." % "; ".join(nxt["holds"])
    elif policy == "reject":
        tail = "No policy step is left"
        if nxt and not nxt["label"].lower().startswith("none"):
            tail += "; the remaining hardening step is to %s%s" % (nxt["label"], _readiness(nxt))
        else:
            tail += "; what is left is keeping our own senders passing."
    elif nxt is None:
        tail = "No next step could be determined from this run."
    else:
        tail = "The next safe step is to %s%s" % (nxt["label"], _readiness(nxt))
    return " ".join([head, mid, tail])


def cut_org_floor(report, orgs):
    """The genuine failures in the rows kept for the names under these
    organizations (maillog.by_domain: each audited name's own rows and its
    unaudited subdomains'), the floor the full-window totals sit beside;
    None when the report attributes nothing to them."""
    bd = audit._dict(audit._dict(report.get("maillog")).get("by_domain"))
    total, seen = 0, False
    for d, c in bd.items():
        if d == audit.OTHER or not isinstance(c, dict) or not any(_under(_dom(d), _dom(o)) for o in orgs):
            continue
        seen = True
        total += _n(c.get("genuine_failures")) or 0
        total += _n(audit._dict(c.get("subdomains_total")).get("genuine_failures")) or 0
    return total if seen else None


def _delivered_line(ddf, gone, view, policy):
    """The 'Delivered despite failing' line: when the mail log recorded the
    overrides, only the deliveries that name one are credited to overrides
    (the ones the exceptions left, so an excepted sender's override is never
    pinned on another sender), and the rest are what the log says they are,
    none recorded; without the columns, the older wording: a local override
    let them in."""
    text = "**Delivered despite failing: %d**" % ddf
    if gone:
        text += " (%d of them formally excepted in audit.toml)" % gone
    left = max(ddf - gone, 0)
    named = ", ".join("%s x%d" % (s["name"], s["count"]) for s in view["ddf_senders"][:3])
    if not view.get("overrides_recorded"):
        return text + (" - these only arrive because of our own overrides; outside receivers are not as forgiving"
                       + ((" (%s)" % named) if named else ""))
    by = dedupe.delivered_by_text(view.get("ddf_by_left"))  # 'an Exchange transport rule x2' or ''
    rest = left - sum(_n(n) or 0 for n in (view.get("ddf_by_left") or {}).values())
    parts = []
    if by:
        parts.append("let in by %s (outside receivers do not have these overrides)" % by)
    if rest > 0:
        parts.append("no override recorded for %d%s" % (
            rest, " (at p=none receivers deliver failing mail without one, as the tenant did here)" if policy == "none"
            else " (the log names nothing that let them in)"))
    return text + ((" - " + "; ".join(parts)) if parts else "") + ((" (%s)" % named) if named else "")


def where_we_stand(report, view, trend, window=None, policy=None):
    """The four 'Where we stand' lines, as data and as text. policy: the
    organization domain's, which says whether a delivered failure with no
    override recorded is the policy's own doing (p=none)."""
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else None
    tot = (rua or {}).get("totals") or {}
    lines, data = [], {"window": window or window_of(report)}
    if view is None or view["genuine_failures"] is None:
        data["genuine_failures"] = None
        lines.append("**Genuine failures: not in this run** - no mail log was read, so this run cannot count them")
    else:
        gf, raw = view["genuine_failures"], view["raw_failing_rows"]
        # the share the formal exceptions cover: the census counts it per stream, an older report's gate in total
        gone = (sum(e["count"] for e in view.get("excepted") or []) if view.get("exceptions_counted")
                else view.get("excepted_unsplit") or 0)
        gone = min(max(gone, 0), gf)
        data.update({"genuine_failures": gf, "raw_failing_rows": raw, "truncation": view["truncation"],
                     "genuine_failures_excepted": gone})
        text = "**Genuine failures: %d**" % gf
        share = ("%d of them formally excepted in audit.toml" % gone) if gone else ""
        if raw is not None and raw > gf:
            text += " (%sraw counts would say %d - the gap is relay echoes, not broken senders)" % (
                (share + "; ") if share else "", raw)
        elif raw is not None:
            text += " (%sraw row counts agree: no relay echoes)" % ((share + "; ") if share else "")
        elif share:
            text += " (%s)" % share
        span = span_phrase(view.get("window"))
        data["maillog_window"] = view.get("window")
        if span:
            text += ", over %s" % span
        if view["truncation"]:
            text += "; the log export was cut short (%s), so this count is a floor" % view["truncation"]
        full = full_window(report)
        if full:  # beside the floor, never instead of it: every verdict still rests on the rows kept
            data["window_totals"] = full
            floor = cut_org_floor(report, full["orgs"])
            data["window_totals"]["floor"] = floor
            text += ("; over the full %s, counted in Advanced Hunting: %d genuine %s, %d delivered despite failing "
                     "under %s, %s (the gate, the census and the labels still rest on the rows kept; the plan "
                     "reads these totals for its quarantine-now and sp= decisions)"
                     % (full["span"], full["genuine_failures"], _plural(full["genuine_failures"], "failure"),
                        full["delivered_despite_fail"], audit._names(full["orgs"]),
                        ("whose rows kept hold %d of the %d above" % (floor, gf)) if floor is not None and floor != gf
                        else "whose rows kept are the %d above" % gf))
        if not view["auth_column"]:
            text += ("; the export carried no authentication column, so failure here means never delivered "
                     "rather than failed DMARC")
        lines.append(text)
        ddf = view["delivered_despite_fail"]
        data["delivered_despite_fail"] = ddf
        data["delivered_despite_fail_senders"] = view["ddf_senders"][:3]
        gone = view.get("delivered_excepted") or 0
        data["delivered_despite_fail_excepted"] = gone
        # what let them in, when the log recorded it (an export without the override columns says nothing new)
        by = dedupe.delivered_by_text(view.get("ddf_by"), ddf) if ddf else ""
        if by:
            data["delivered_despite_fail_by"] = dict(view["ddf_by"])
        if view.get("overrides_recorded"):
            data["delivered_despite_fail_by_left"] = dict(view.get("ddf_by_left") or {})
        if ddf is None:
            lines.append("**Delivered despite failing: not in this run**")
        elif ddf and gone >= ddf:  # every one is formally excepted: whatever delivers them is accepted
            lines.append("**Delivered despite failing: %d** - all formally excepted in audit.toml; what delivers them%s "
                         "stays accepted until the exceptions expire" % (ddf, (" (%s)" % by) if by else ""))
        elif ddf:
            lines.append(_delivered_line(ddf, gone, view, policy))
        else:
            lines.append("**Delivered despite failing: 0**")
    if tot:
        disp = tot.get("by_disposition") or {}
        rej, qua = _n(disp.get("reject")) or 0, _n(disp.get("quarantine")) or 0
        msgs, reports, rate = _n(tot.get("messages")), _n(tot.get("reports")) or 0, _f(tot.get("pass_rate"))
        share = spoof_share(rua, _excepted_ips(report))
        data["spoofing_blocked"] = {"rejected": rej, "quarantined": qua, "messages": msgs, "pass_rate": rate,
                                    "reports": reports, "window": [tot.get("begin_date"), tot.get("end_date")],
                                    "spoof_share": share}
        text = ("**Mail refused or quarantined by receivers under our policy: %d rejected / %d quarantined** - this "
                "includes any of our own senders that are not yet aligned, not only spoofing" % (rej, qua))
        if msgs is not None and rate is not None:
            text += " (%d messages seen by %d %s, %.1f%% passing)" % (msgs, reports, _plural(reports, "report"), 100 * rate)
        if share:
            what = [("%d rejected", share["rejected"]), ("%d quarantined", share["quarantined"]),
                    ("%d delivered anyway", share["delivered"])]
            seen = ", ".join(fmt % n for fmt, n in what if n)
            text += ". The spoofing share: %d %s from %d %s that %s like spoofing%s." % (
                share["messages"], _plural(share["messages"], "message"), share["sources"],
                _plural(share["sources"], "source"), _plural(share["sources"], "looks", "look"),
                (" (%s)" % seen) if seen else "")
        lines.append(text)
    else:
        data["spoofing_blocked"] = None
        lines.append("**Mail refused or quarantined by receivers: outside view not in this run** "
                     "(no aggregate reports were read)")
    caveats = [str(c) for c in (report.get("caveats") or []) if c] if isinstance(report.get("caveats"), list) else []
    data["caveats"] = caveats
    for c in caveats:
        lines.append("**Caveat:** %s" % c)
    data["trend"] = trend
    if trend is None:
        lines.append("**Trend: first run, no trend yet**")
    else:
        parts = []
        gf_now = view["genuine_failures"] if view else None
        if trend["previous_genuine_failures"] is not None and gf_now is not None:
            parts.append("%+d genuine failures (%d -> %d)" % (gf_now - trend["previous_genuine_failures"],
                                                             trend["previous_genuine_failures"], gf_now))
        pr_now = _f(tot.get("pass_rate")) if tot else None
        if trend["previous_pass_rate"] is not None and pr_now is not None:
            parts.append("%+.1f pts pass rate (%.1f%% -> %.1f%%)" % (100 * (pr_now - trend["previous_pass_rate"]),
                                                                     100 * trend["previous_pass_rate"], 100 * pr_now))
        why = trend.get("not_comparable") or []
        if parts:
            lines.append("**Trend vs %s: %s**%s" % (trend["label"], ", ".join(parts),
                                                   (" - " + "; ".join(why)) if why else ""))
        else:
            lines.append("**Trend vs %s: not comparable** - %s"
                         % (trend["label"], "; ".join(why) or "the two runs do not share a failure count or a pass rate"))
    data["lines"] = lines
    return data


def _entry_bullet(e, what):
    hook = "**%s - %d %s**" % (e["name"], e["count"], _plural(e["count"], "message"))
    words = LIKELY_WORDS.get(e.get("likely") or "unknown", "unclear")
    detail = []
    if what == "envelope":
        n = e.get("sender_count") or (len(e["senders"]) if isinstance(e.get("senders"), list) else None)
        if n:
            detail.append("%d sender %s" % (n, _plural(n, "address", "addresses")))
        if isinstance(e.get("senders"), list) and e["senders"]:
            detail.append("such as %s" % ", ".join(str(s) for s in e["senders"][:2]))
    elif e.get("envelope"):
        detail.append("envelope %s" % e["envelope"])
    subs = e.get("subjects") if isinstance(e.get("subjects"), list) else []
    if subs:
        detail.append('subjects like "%s"' % str(subs[0])[:60])
    return "%s %s%s" % (hook, words, (" (" + "; ".join(detail) + ")") if detail else "")


def _note_line(entries, cap=NOTES_CAP):
    text = ", ".join("%s x%d (%s)" % (e["name"], e["count"], LIKELY_WORDS.get(e.get("likely") or "unknown", "unclear"))
                     for e in entries[:cap])
    if len(entries) > cap:
        text += " (+%d more in report.json)" % (len(entries) - cap)
    return text


def what_is_failing(report, view):
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else None
    lines, data = [], {"basis": None, "by_envelope": [], "by_sender": [], "outside": [], "notes": []}
    if view is None and not rua:
        lines.append("Not in this run: no mail log and no aggregate reports were read, so nothing here can say "
                     "what is failing.")
        data["notes"].append("no mail log and no aggregate reports in this run")
        return data, lines
    if view is not None:
        data["basis"] = view["basis"] or "counters only"
        if view["census_missing"]:
            lines.append("The mail log carried counts but no per-sender detail, so the census is not in this run.")
            data["notes"].append("mail log without verdicts or census")
        elif not view["by_envelope"] and not view["by_sender"]:
            if view.get("excepted"):
                n = sum(e["count"] for e in view["excepted"])
                lines.append("Every genuine failure the census names this run is formally excepted in audit.toml: "
                             "%d %s (%s)." % (n, _plural(n, "message"), _excepted_names(view["excepted"])))
                data["excepted"] = list(view["excepted"])
            else:
                lines.append("No genuine failures in the mail log this run - every message that failed also had a "
                             "passing copy, or nothing failed.")
        else:
            for what, key, title in (("envelope", "by_envelope", "By envelope domain (who actually handed the mail over)"),
                                     ("sender", "by_sender", "By sender address (what the reader sees in From)")):
                entries = view[key]
                if not entries:
                    continue
                head = [e for e in entries if e["count"] >= HEADLINE_MIN][:TOP_ENTRIES]
                rest = [e for e in entries if e not in head]
                lines.append("%s:" % title)
                for e in head:
                    lines.append("- " + _entry_bullet(e, what))
                if rest:
                    lines.append("- Notes, not headlines (under %d each): %s" % (HEADLINE_MIN, _note_line(rest)))
                data[key] = entries
                lines.append("")
            if lines and lines[-1] == "":
                lines.pop()
        if view.get("excepted") and "excepted" not in data:  # listed once, as what they are: not failures to fix
            n = sum(e["count"] for e in view["excepted"])
            lines.append("Formally excepted in audit.toml and not counted above: %d %s (%s)." % (
                n, _plural(n, "message"), _excepted_names(view["excepted"])))
            data["excepted"] = list(view["excepted"])
    if rua:
        fs = [s for s in (rua.get("failing_streams") or []) if isinstance(s, dict)]
        skip = _excepted_ips(report)
        out, excepted = [], []
        for s in fs:
            fail = _n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0)
            e = {"name": s.get("source_ip") or "?", "count": fail, "total": _n(s.get("count")),
                 "likely": _likely(s.get("likely")), "header_from": list(s.get("header_from") or []),
                 "dispositions": s.get("dispositions") if isinstance(s.get("dispositions"), dict) else {}}
            (excepted if str(s.get("source_ip")) in skip else out).append(e)
        data["outside"] = out
        if excepted:  # listed once, as what they are: not sources to chase
            data["outside_excepted"] = excepted
        if view is not None:
            lines.append("")
        if out:
            lines.append("From the outside (aggregate reports; these counts include forwarded copies and cannot be "
                         "deduplicated):")
            head = [e for e in out if e["count"] >= HEADLINE_MIN][:TOP_ENTRIES]
            rest = [e for e in out if e not in head]
            for e in head:
                disp = ", ".join("%d %s" % (_n(v) or 0, k) for k, v in (e["dispositions"] or {}).items() if _n(v))
                lines.append("- **%s - %d failing %s as %s** %s%s" % (
                    e["name"], e["count"], _plural(e["count"], "message"), ", ".join(e["header_from"][:2]) or "?",
                    LIKELY_WORDS.get(e["likely"], "unclear"), (" (receivers: %s)" % disp) if disp else ""))
            if rest:
                lines.append("- Notes, not headlines: %s" % ", ".join(
                    "%s x%d (%s)" % (e["name"], e["count"], LIKELY_WORDS.get(e["likely"], "unclear")) for e in rest))
            if excepted:
                lines.append("- Formally excepted in audit.toml and not counted above: %s" % _note_line(excepted))
        elif excepted:
            lines.append("From the outside (aggregate reports): every source that fails with volume is formally "
                         "excepted in audit.toml: %s." % _note_line(excepted))
        else:
            lines.append("From the outside (aggregate reports): no source fails with volume.")
    dl = report.get("delta") if isinstance(report.get("delta"), dict) else None
    if dl and isinstance(dl.get("new_senders"), list):
        new = _entries(dl["new_senders"], SENDER_KEYS) or []
        gone = []
        if _carries_exceptions(dl["new_senders"]):  # the census rows say what an exception covered
            new, gone = _after_exceptions(new, "sender")
        day = _day(dl.get("previous_generated_utc")) or "date unknown"
        n = sum(e["count"] for e in gone)
        if new:
            more = (" (+%d more)" % (len(new) - TOP_ENTRIES)) if len(new) > TOP_ENTRIES else ""
            lines.append("")
            lines.append("Failing senders not seen in the previous run (%s): %s%s%s"
                         % (day, _note_line(new[:TOP_ENTRIES]), more,
                            ("; formally excepted in audit.toml and not counted here: %d %s (%s)"
                             % (n, _plural(n, "message"), _excepted_names(gone))) if gone else ""))
            data["new_senders"] = new
        elif gone:
            lines.append("")
            lines.append("Senders not seen in the previous run (%s) fail only where audit.toml formally excepts them: "
                         "%d %s (%s)." % (day, n, _plural(n, "message"), _excepted_names(gone)))
        if gone:
            data["new_senders_excepted"] = gone
    return data, lines


def _unread_step(report, domain):
    """The per-domain table's step when the gate read no policy: what to do
    about that, by why it could not (policy_unread_why), never a record to
    publish beside one nobody could read."""
    why = policy_unread_why(report, domain)
    if why == "unverified":
        return "re-run with working DNS first: the DMARC lookup failed, so a record may already exist"
    if why == "unrecognised":
        return "correct the record: p=%s is not a policy receivers apply" % current_policy(report, domain)
    if why == "unread":
        return "read the policy first: run online, or supply aggregate reports that cover it"
    return "publish a monitoring-only DMARC record so reports start (no record found)"


def per_domain(report, plan):
    gate_domains = (report.get("gate") or {}).get("domains") or {}
    gate_domains = gate_domains if isinstance(gate_domains, dict) else {}
    planned = audit._dict(plan).get("domains")
    names = list(gate_domains) + [d for d in (planned if isinstance(planned, list) else []) if isinstance(d, str)]
    given = audit._dict(report.get("inputs")).get("domains")
    names += [str(d) for d in (given if isinstance(given, list) else [])]
    if not names:  # an offline run with no domain named: the reports say what they cover
        covered = audit._dict(audit._dict(report.get("rua")).get("totals")).get("domains")
        names = [str(d) for d in (covered if isinstance(covered, list) else [])]
    names = list(dict.fromkeys(n.lower() for n in names if n))
    names.sort(key=lambda d: (org_domain(d), d != org_domain(d), d))
    bd = (report.get("maillog") or {}).get("by_domain") if isinstance(report.get("maillog"), dict) else None
    bd = bd if isinstance(bd, dict) else {}
    mf = report.get("mailflow") if isinstance(report.get("mailflow"), dict) else {}
    flows = mf.get("domains") if isinstance(mf.get("domains"), dict) else {}  # what collect.py measured, per name
    dns = report.get("dns") if isinstance(report.get("dns"), dict) else {}
    rows = []
    for d in names:
        policy, _pct = policy_text(report, d)
        g = gate_domains.get(d) if isinstance(gate_domains.get(d), dict) else {}
        verdict = g.get("verdict") if isinstance(g.get("verdict"), str) else None
        gate = verdict or "not checked"
        gate_text = GATE_WORDS.get(verdict, verdict) if verdict else "not checked"
        ml = bd.get(d) if isinstance(bd.get(d), dict) else None
        # a domain the run measured sending nothing leads with its quarantine-now row; the gate judged the
        # weekly ramp that row skips, and its verdict says so - unless its blockers hold that row too
        changes = sorted(changes_for(plan, d), key=lambda c: c.get("kind") != "no_mail")
        holds = holds_for(plan, d)
        if changes and changes[0].get("kind") == "no_mail" and verdict:
            gate_text += (" (for the weekly ramp this skips)" if not audit.ramp_blockers_left(report, d)
                          else " (it holds the quarantine-now row too)")
        elif verdict == "go" and holds:  # the gate found nothing; the plan still holds a step for the domain
            gate_text += ", with a plan hold"
        ids = [c.get("id") for c in changes if c.get("id")]
        raw_step = str(g.get("next_step") or "")
        audit_step = _short_step(raw_step)
        if audit_step.lower().startswith("unknown"):
            audit_step = _unread_step(report, d)
        at = re.search(r"\s+on the record at (\S+)$", raw_step)
        doc = dns.get(d) if isinstance(dns.get(d), dict) else {}
        inherited = bool(doc.get("inherited")) and doc.get("dmarc_source") and doc["dmarc_source"] != "_dmarc." + d
        held = None  # the one statement for a name a plan hold says needs a record before the apex moves to reject
        if inherited:
            held = audit.inherited_step(d, raw_step, plan)
            held = held if held != raw_step else None
        if at and at.group(1) != "_dmarc." + d and inherited:
            # an older report's gate step for a name without a record of its own is a step on its parent's record:
            # never shown as the subdomain's own move (read literally it would downgrade the apex)
            audit_step = "no record of its own: it follows %s and moves with the apex's step" % at.group(1)
        if changes:
            step = table_step(changes[0])
            if len(changes) > 1:
                # two rows that rewrite one DMARC record from today's value are this week's alternatives (the
                # plan says so on each), not a sequence
                same = (str(changes[0].get("hostname") or "").startswith("_dmarc.")
                        and all(str(changes[0].get(k)) == str(changes[1].get(k)) for k in ("hostname", "current")))
                step += (" or %s, one a week" if same else ", then %s") % table_step(changes[1])
            if len(changes) > 2:
                step += " (+%d more in the plan)" % (len(changes) - 2)
        elif holds:
            step = "hold: " + str(holds[0].get("reason") or "").split(" - ")[0]
        elif held:  # the plan's hold on the apex names this name: that is its step, never 'only if it needs one'
            step = held
        elif plan is not None and audit_step:
            step = "nothing in the plan; the audit says: " + audit_step
        elif audit_step:
            step = audit_step
        else:
            step = "not audited in this run"
        flow = flows.get(d) if isinstance(flows.get(d), dict) else None
        rows.append({"domain": d, "apex": org_domain(d), "policy_today": policy, "gate": gate, "gate_text": gate_text,
                     "next_step": plain(step), "plan_ids": ids,
                     "maillog": ({k: _n(ml.get(k)) for k in ("logical_messages", "genuine_failures",
                                                              "delivered_despite_fail")} if ml else None),
                     "mailflow": flow, "mailflow_text": audit.mailflow_text(flow, mf.get("days"))})
    grouped = OrderedDict()
    for r in rows:
        if r["domain"] == r["apex"]:
            key = ("apex", r["domain"])
        else:  # subdomains share a row only when they also share what their mail flow says
            key = ("sub", r["apex"], r["policy_today"], r["gate"], r["next_step"], r["mailflow_text"])
        grp = grouped.setdefault(key, {"domains": [], "policy_today": r["policy_today"], "gate": r["gate"],
                                       "gate_text": r["gate_text"], "next_step": r["next_step"], "plan_ids": [],
                                       "maillog": {}, "mailflow_text": r["mailflow_text"], "mailflow": {}})
        grp["domains"].append(r["domain"])
        grp["plan_ids"] += r["plan_ids"]
        if r["maillog"]:
            grp["maillog"][r["domain"]] = r["maillog"]
        if r["mailflow"]:
            grp["mailflow"][r["domain"]] = r["mailflow"]
    return list(grouped.values())


def render_per_domain(groups):
    L = ["| Domain | Policy today | Gate | Next step | Mail flow |", "|---|---|---|---|---|"]
    for g in groups:
        step = g["next_step"]
        if g["plan_ids"]:
            step += " (plan %s)" % id_range(g["plan_ids"])
        L.append("| %s | %s | %s | %s | %s |" % (", ".join("`%s`" % d for d in g["domains"]), g["policy_today"],
                                               g.get("gate_text") or g["gate"], step,
                                               g.get("mailflow_text") or "not measured"))
    return L


def mailflow_note(report):
    """The sentence under the per-domain table: what its mail-flow column
    counts, and the mail it can never see - a third party sending as one of
    our domains straight to outside recipients, which only the aggregate
    reports show."""
    mf = report.get("mailflow") if isinstance(report.get("mailflow"), dict) else {}
    doms = mf.get("domains") if isinstance(mf.get("domains"), dict) else {}
    measured = any(isinstance(c, dict) for c in doms.values())
    unseen = ("Mail a third party sends as one of our domains straight to outside recipients never passes through "
              "our tenant, so only the aggregate reports show it.")
    if not measured:
        return ("Mail flow was not measured in this run (it is counted in our tenant on every run that can reach "
                "it). " + unseen)
    return ("Mail flow is what passed through our own tenant in %s with that domain as the sender: out is "
            "mail our people and systems sent, in is mail that arrived from outside (a vendor sending for us, or "
            "a spoof); the counts are close estimates, and zero means none. %s"
            % (audit._last_days_text(mf.get("days")), unseen))


# What to do about each common override (dedupe.OVERRIDE_WORDS' kinds) a delivered failure names.
OVERRIDE_FIXES = {
    "transport_rule": "find that rule and make it conditional on authentication",
    "allowed_senders": "take the sender off the allowed sender list in the anti-spam policy",
    "allowed_domains": "take the domain off the allowed sender domain list in the anti-spam policy",
    "spoof_allow": "fix the sender's authentication, then remove that allow entry",
    "safe_senders": "ask the mailbox owners to take the sender off their safe sender lists",
}
OVERRIDE_FIX_OTHER = "find that override and make it conditional on authentication"


def _no_override_fix(policy):
    """What to do about delivered failures the log recorded no override for."""
    if policy == "none":
        return "at p=none receivers deliver failing mail by design, and so did the tenant - the policy step is the fix"
    return "look for what the log does not record (a mailbox rule, a connector, a filter in front of the tenant)"


def override_action(by, count, recorded=False, policy=None):
    """The action for a sender delivered despite failing, from what let its
    messages in ({delivered_by reason: messages} over count messages):
    'delivered because of an Exchange transport rule: find that rule and
    make it conditional on authentication; outside receivers do not have
    it'. Several overrides are named with their counts, and messages that
    name none are named as such. None when no override is known and the
    log recorded none (recorded False): the generic action stands. When the
    log recorded the overrides (recorded True) and names none for this
    sender, the action says so instead of sending the reader after an
    override the log would have named: at p=none the delivery is the
    policy's own doing (policy, the sender's domain's)."""
    merged = OrderedDict()  # plain words -> [messages, kind]
    for reason, n in sorted(((str(r), _n(n) or 0) for r, n in (by or {}).items()), key=lambda kv: (-kv[1], kv[0])):
        if reason and n > 0:
            words = dedupe.override_words(reason)
            m = merged.setdefault(words, [0, dedupe.override_kind(reason)])
            m[0] += n
    if not merged:
        return ("the log names no override for them: %s" % _no_override_fix(policy)) if recorded else None
    rest = (count or 0) - sum(m[0] for m in merged.values())
    single = len(merged) == 1 and rest <= 0
    causes = [(w if kind else '"%s"' % w) + ("" if single else " (%d)" % n) for w, (n, kind) in merged.items()]
    because = audit._names(causes)
    fixes = list(dict.fromkeys(OVERRIDE_FIXES.get(kind, OVERRIDE_FIX_OTHER) for n, kind in merged.values()))
    if rest > 0:
        because += ", and the log names no override for the other %d" % rest
        fixes.append(("for the other %d, %s" % (rest, _no_override_fix(policy))) if recorded else
                     "find what let the other %d in (a transport rule, an allow list or a safe sender list)" % rest)
    return "delivered because of %s: %s; outside receivers do not have %s" % (
        because, "; ".join(fixes), "it" if single else "them")


def build_actions(report, plan, view, owners):
    """Every plan change and every actionable finding as an item with the keys
    it is matched to an owner by, then grouped by owner."""
    items = []
    findings = [f for f in (report.get("findings") or []) if isinstance(f, dict)]
    ids_present = {f.get("id") for f in findings}
    covered = set()

    for c in plan_changes(plan):
        dom = (c.get("domain") or "").lower()
        keys = [dom, str(c.get("owner_hint") or "").lower()]
        prio = _n(c.get("priority"))
        if prio == 1 and c.get("kind") in ("new", "modify"):
            items.append({"kind": "p1record", "keys": keys, "ref": c.get("id"), "domain": dom,
                          "hostname": c.get("hostname"), "hook": dom, "action": step_label(c),
                          "is_dmarc": str(c.get("hostname") or "").startswith("_dmarc."), "lookup": looks_first(c)})
        else:
            action = plain(step_label(c))
            why = plain(str(c.get("human_summary") or c.get("why") or "").strip())  # plan.py's plain words first
            if why:
                action += " - " + why
            pre = reword_prereqs(prereqs_of(c))
            if pre:
                action += " (before applying: %s)" % _join(pre)
            items.append({"kind": "dns", "keys": keys, "ref": c.get("id"), "domain": dom, "hook": dom, "action": action})
        for fid in c.get("finding_ids") or []:
            covered.add(("dns:" + dom, fid))

    if view is not None:
        ref = "MAILFLOW-001" if "MAILFLOW-001" in ids_present else "mail log"
        # each stream as the exceptions left it, its spoof-labelled failures apart from the rest
        own_all, spoof = [], []
        for s in view["by_sender"]:
            split = _split(s)
            ours = split.get(OWN, 0) + split.get(UNCLEAR, 0)
            if ours > 0:
                own_all.append(dict(s, count=ours, likely=OWN if split.get(OWN, 0) >= split.get(UNCLEAR, 0) else UNCLEAR))
            if split.get(SPOOF, 0) > 0:
                spoof.append(dict(s, count=split[SPOOF]))
        own_all.sort(key=lambda s: (-s["count"], s["name"]))
        for s in own_all[:SENDER_ITEMS_CAP]:
            hook = "%s - %d %s" % (s["name"], s["count"], _plural(s["count"], "message"))
            subj = ('subjects like "%s"' % str(s["subjects"][0])[:60]) if s.get("subjects") else ""
            env = ("envelope %s" % s["envelope"]) if s.get("envelope") else ""
            detail = "; ".join(x for x in (subj, env) if x)
            if s["likely"] == OWN:
                action = ("DKIM-sign this sender (or align its SPF): the messages failed with no passing copy "
                          "and look like our own system")
            else:
                action = ("find out whose system this is: the messages failed with no passing copy and the "
                          "heuristic could not tell spoof from our own system")
            if detail:
                action += " (%s)" % detail
            items.append({"kind": "sender", "keys": [s["name"], s.get("domain"), s.get("envelope")], "ref": ref,
                          "sender": s["name"], "hook": hook, "action": action})
        rest = own_all[SENDER_ITEMS_CAP:]
        if rest:
            total = sum(s["count"] for s in rest)
            items.append({"kind": "sender", "keys": [], "ref": ref,
                          "hook": "%d more senders with %d %s between them" % (len(rest), total, _plural(total, "message")),
                          "action": "work through them from the census in report.json (maillog.census); "
                                    "none is a headline on its own"})
        if spoof:
            total = sum(s["count"] for s in spoof)
            k = len({s["name"] for s in spoof})
            # "most" counts messages: a one-message part split off a mixed stream weighs one, not a stream
            doms, envs = Counter(), Counter()
            for s in spoof:
                doms[s.get("domain") or ""] += s["count"]
                envs[s.get("envelope") or ""] += s["count"]
            top_dom, top_env = doms.most_common(1)[0][0], envs.most_common(1)[0][0]
            hook = "%d %s from %d %s that %s like spoofing" % (total, _plural(total, "message"), k,
                                                                 _plural(k, "address", "addresses"),
                                                                 _plural(total, "looks", "look"))
            action = "confirm none of them is ours, then leave them to the policy"
            if top_env:
                action += " (most came in via %s%s)" % (top_env, (", as %s" % top_dom) if top_dom else "")
            items.append({"kind": "spoof", "keys": [top_dom, top_env], "ref": ref, "hook": hook, "action": action})
        if view["by_sender"] or view["genuine_failures"] == 0 or view.get("excepted"):
            covered.add(("maillog", "MAILFLOW-001"))  # nothing left to work: every named failure is excepted
        ref = "MAILFLOW-002" if "MAILFLOW-002" in ids_present else "mail log"
        ddf = view["ddf_senders"]  # what the exceptions left: an excepted sender's override is accepted
        for s in ddf[:TOP_ENTRIES]:
            hook = "%s - %d %s reached inboxes despite failing" % (s["name"], s["count"], _plural(s["count"], "message"))
            # the override the log recorded for them, named; else the ones to look for - unless the log recorded
            # the overrides and names none for this sender
            action = override_action(s.get("by"), s["count"], view.get("overrides_recorded", False),
                                     current_policy(report, s.get("domain") or "")) or (
                "find the override (transport rule, allow list, safe sender) that let them in and make it "
                "conditional on authentication; outside receivers do not have it")
            items.append({"kind": "override", "keys": [s["name"], s.get("domain"), s.get("envelope")], "ref": ref,
                          "sender": s["name"], "hook": hook, "action": action})
        rest = ddf[TOP_ENTRIES:]
        if rest:
            total = sum(s["count"] for s in rest)
            items.append({"kind": "override", "keys": [], "ref": ref,
                          "hook": "%d more %s with %d %s that reached inboxes despite failing"
                                  % (len(rest), _plural(len(rest), "sender"), total, _plural(total, "message")),
                          "action": "find the overrides that let them in from the census in report.json "
                                    "(maillog.census, delivered_despite_fail per sender) and make each conditional "
                                    "on authentication"})
        delivered = view["delivered_despite_fail"]
        if ddf or delivered == 0 or (delivered is not None and delivered <= (view.get("delivered_excepted") or 0)):
            covered.add(("maillog", "MAILFLOW-002"))

    rua = report.get("rua") if isinstance(report.get("rua"), dict) else None
    if rua:
        skip = _excepted_ips(report)  # formally excepted: listed once in What is failing, never work
        fs = [s for s in (rua.get("failing_streams") or []) if isinstance(s, dict) and str(s.get("source_ip")) not in skip]
        ref = "OUTSIDE-001" if "OUTSIDE-001" in ids_present else "aggregate reports"
        spoof_fs = []
        for s in fs:
            hf = [h for h in (s.get("header_from") or []) if isinstance(h, str)]
            fail = _n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0)
            label = _likely(s.get("likely"))
            if label == SPOOF:
                spoof_fs.append((s, hf, fail))
                continue
            hook = "%s - %d failing %s as %s" % (s.get("source_ip") or "?", fail, _plural(fail, "message"),
                                                 ", ".join(hf[:2]) or "?")
            if label == OWN:
                action = "DKIM-sign the system behind this IP with an aligned d=: receivers see it fail"
            else:
                action = ("find out whose system this IP is: receivers see it fail and the heuristic could not "
                          "tell spoof from our own")
            sig = plain("; ".join(str(x) for x in (s.get("likely_signals") or [])[:2]))
            if sig:  # whole: the signal that decided the label is often the second one
                action += " (%s)" % sig
            items.append({"kind": "stream", "keys": hf + [org_domain(h) for h in hf], "ref": ref,
                          "hook": hook, "action": action})
        if spoof_fs:
            total = sum(f for _, _, f in spoof_fs)
            disp = Counter()
            for s, _, _ in spoof_fs:
                for k, v in (s.get("dispositions") if isinstance(s.get("dispositions"), dict) else {}).items():
                    disp[k] += _n(v) or 0
            hf_all = [h for _, hf, _ in spoof_fs for h in hf]
            top = Counter(hf_all).most_common(1)[0][0] if hf_all else ""
            hook = "%d %s from %d outside %s that look like spoofing" % (total, _plural(total, "message"), len(spoof_fs),
                                                                         _plural(len(spoof_fs), "IP"))
            seen = ", ".join("%d %s" % (disp[k], k) for k in ("reject", "quarantine", "none") if disp.get(k))
            action = "confirm none of the IPs is ours; receivers reported %s" % (seen or "no dispositions")
            if disp.get("none"):
                action += " - the ones delivered (disposition none) are what the next policy step is for"
            items.append({"kind": "spoof", "keys": [top], "ref": ref, "hook": hook, "action": action})
        covered.add(("rua", "OUTSIDE-001"))
        ref = "OUTSIDE-003" if "OUTSIDE-003" in ids_present else "aggregate reports"
        for s in [s for s in (rua.get("spf_only_senders") or []) if isinstance(s, dict)]:
            hf = [h for h in (s.get("header_from") or []) if isinstance(h, str)]
            n = _n(s.get("spf_only")) or _n(s.get("count")) or 0
            hook = "%s - %d %s pass on SPF alone" % (s.get("source_ip") or "?", n, _plural(n, "message"))
            action = "set up aligned DKIM at the platform behind this IP (SPF alone breaks when the mail is forwarded)"
            spf_doms = [d for d in (s.get("spf_domains") or []) if isinstance(d, str)]
            if spf_doms:
                action += "; its envelope domain is %s" % ", ".join(spf_doms[:2])
            items.append({"kind": "spf_only", "keys": hf + spf_doms + [org_domain(h) for h in hf], "ref": ref,
                          "hook": hook, "action": action})
        covered.add(("rua", "OUTSIDE-003"))

    for f in findings:
        if f.get("severity") not in ACTIONABLE:
            continue
        src = str(f.get("source") or "")
        if (src, f.get("id")) in covered:
            continue
        if src.startswith("dns:"):
            dom = src[4:].lower()
            keys, hook = [dom], dom
        elif src.startswith("headers:"):
            keys, hook = [f.get("object") or ""], "message header " + display_path(src[8:])
        else:
            keys, hook = [f.get("object") or ""], (f.get("object") or src or "finding")
        title = plain(str(f.get("title") or "").strip())
        action = plain(str(f.get("action") or "").strip())
        text = (title + " - " + action) if title and action else (title or action)
        if f.get("verified") is False:
            text += " (not verified)"
        items.append({"kind": "finding", "keys": keys, "ref": f.get("id"), "hook": hook, "action": text})

    groups = OrderedDict()
    for name in dict.fromkeys(o["owner"] for o in owners):
        groups[name] = {"owner": name, "items": [],
                        "channel": next((o["channel"] for o in owners if o["owner"] == name and o["channel"]), "")}
    groups[UNASSIGNED] = {"owner": UNASSIGNED, "channel": "", "items": []}
    for it in items:
        o = match_owner(owners, *it["keys"])
        name = o["owner"] if o else UNASSIGNED
        it = dict(it, owner=name, matched_by=o["pattern"] if o else None)
        groups[name]["items"].append(it)
    out = []
    for g in groups.values():
        if not g["items"]:
            continue
        p1 = [i for i in g["items"] if i["kind"] == "p1record"]
        rest = [i for i in g["items"] if i["kind"] != "p1record"]
        lines = []
        if p1:
            ids = [i["ref"] for i in p1 if i["ref"]]
            what = "monitoring" if all(i["is_dmarc"] for i in p1) else "monitoring and hygiene"
            # a record for a name whose own _dmarc record nobody saw waits on a lookup: a second record breaks it
            looks = [i["ref"] or i["domain"] for i in p1 if i.get("lookup")]
            lines.append({"hook": "%d zero-risk %s %s" % (len(p1), what, _plural(len(p1), "record")),
                          "action": "ready to publish" + (", of which %d (%s) %s a lookup first: the name may have a "
                                                          "record of its own already" % (
                                                              len(looks), ", ".join(looks),
                                                              "needs" if len(looks) == 1 else "need") if looks else ""),
                          "ref": ("plan " + id_range(ids)) if ids else None,
                          "kind": "p1summary", "domains": [i["domain"] for i in p1]})
        for i in rest:
            lines.append({"hook": i["hook"], "action": i["action"], "ref": i["ref"], "kind": i["kind"],
                          "matched_by": i.get("matched_by")})
        out.append({"owner": g["owner"], "channel": g["channel"], "items": lines})
    return out


def render_actions(groups, failing=None):
    """The owner groups as markdown; failing (the document's What is failing
    data) says why nothing is left when the exceptions took it all."""
    L = []
    if not any(g["items"] for g in groups):
        if (failing or {}).get("excepted") or (failing or {}).get("outside_excepted"):
            return ["- Nothing to do this week: no plan changes, and every failure this run names is formally "
                    "excepted in audit.toml (What is failing lists them)."]
        return ["- Nothing to do this week: no plan changes and no actionable findings in this run."]
    for g in groups:
        L.append("- **%s**" % g["owner"] + (" (%s)" % g["channel"] if g["channel"] else ""))
        for i in g["items"]:
            ref = (" (%s)" % i["ref"]) if i.get("ref") else ""
            L.append("  - **%s** %s%s" % (i["hook"], i["action"], ref))
    return L


def build_ask(plan, org, nxt, policy):
    p1 = [c for c in plan_changes(plan) if _n(c.get("priority")) == 1]
    # a no_mail row quarantines a domain the run measured sending nothing: priority 1, but not zero-risk
    quiet = [c for c in p1 if c.get("kind") == "no_mail"]
    p1 = [c for c in p1 if c.get("kind") != "no_mail"]
    holds = holds_for(plan, org) or holds_for(plan)
    parts = []
    if p1:
        ids = [c.get("id") for c in p1 if c.get("id")]
        text = ("approval to publish the %d zero-risk %s (plan %s) in the next DNS change window"
                % (len(p1), _plural(len(p1), "record"), id_range(ids)))
        # a park row the plan verified unused needs no check; the others say which checks are open. A record for a
        # name whose own _dmarc record nobody saw waits on a lookup of it
        park = sum(1 for c in p1 if c.get("kind") == "park"
                   and not any(str(p).startswith("verified unused") for p in prereqs_of(c)))
        looks = sum(1 for c in p1 if looks_first(c))
        said = []
        if park:
            said.append("%d %s the domain's unused check first" % (
                park, "is a park row that needs" if park == 1 else "are park rows that need"))
        if looks:
            said.append("%d %s a lookup of the name's own _dmarc record first (publish only if it has none)" % (
                looks, "needs" if looks == 1 else "need"))
        if said:
            text += ", of which " + " and ".join(said)
        parts.append(text)
    if quiet:
        ids = [c.get("id") for c in quiet if c.get("id")]
        parts.append("approval to move %d %s no mail straight to quarantine (plan %s) once the checks listed with "
                     "%s are confirmed" % (len(quiet), "domain that sends" if len(quiet) == 1 else "domains that send",
                                           id_range(ids), "it" if len(quiet) == 1 else "each"))
    at_end = not nxt or nxt["label"].lower().startswith("none")
    first = nxt is not None and nxt.get("kind") in ("first", "recheck", "fix_record")
    asked = {c.get("id") for c in p1 + quiet if c.get("id")}  # the rows the clauses above already ask for
    which = "the step after that" if parts else "the next step"
    if first:
        pass  # no policy could be read: the ask is the record, or the re-run, below
    elif _needs_data(nxt) and not at_end:  # the gate cannot judge the step yet: the ask is the evidence, never a go-ahead
        parts.append("more data before %s on %s (%s): %s" % (which, org, nxt["label"], nxt["data"][0]))
    elif nxt and nxt.get("ref") in asked:
        pass  # a park or monitoring row of the org's own: asked with the rows above, with its checks
    elif nxt and nxt.get("holds") and not at_end and nxt.get("kind") != "no_mail":  # the gate holds it, whoever named the step
        parts.append("%s on %s (%s) is held back by this: %s" % (which, org, nxt["label"], nxt["holds"][0]))
    elif nxt and nxt["prerequisites"] and not at_end and nxt.get("kind") != "no_mail":  # a no_mail step is asked above
        parts.append("%s on %s (%s) is held until this is confirmed: %s" % (which, org, nxt["label"], nxt["prerequisites"][0]))
    elif nxt and not nxt["prerequisites"] and not at_end and not (p1 or quiet):
        parts.append("a go-ahead to %s on %s, which this run finds ready" % (nxt["label"], org))
    if holds:
        h = holds[0]
        more = (" (+%d more %s in the plan)" % (len(holds) - 1, _plural(len(holds) - 1, "hold"))) if len(holds) > 1 else ""
        parts.append("a decision on %s: %s%s" % (h.get("domain") or org, _hold_summary(h.get("reason")), more))
    if first:
        text = ("the first step is to %s; no policy could be read" % (FIRST_STEP % org) if nxt.get("kind") == "first"
                else "the first step is to %s" % nxt["label"])
        if parts:
            return "The ask this week: " + _join(parts, "and") + " - " + text + "."
        if nxt.get("kind") != "first":
            return "The ask this week: " + text + "."
        return "The ask this week: a go-ahead, because " + text + "."
    if not parts:
        if policy == "reject":
            return ("Nothing to approve this week: %s is at p=reject and the work left is keeping our own "
                    "senders passing." % org)
        return "Nothing to approve this week; the next run will show whether %s is ready for its next step." % org
    return "The ask this week: " + _join(parts, "and") + "."


def open_questions(report, plan, org, nxt, owners, groups):
    qs = []

    def owner_for(*keys):
        o = match_owner(owners, *keys)
        return o["owner"] if o else "unassigned"

    for c in changes_for(plan, org):
        for text in reword_prereqs(prereqs_of(c)):
            qs.append({"question": "Can we confirm this before we %s (plan %s): %s?"
                       % (step_label(c), c.get("id") or "?", text),
                       "owner": owner_for(c.get("domain"), c.get("owner_hint")), "kind": "prerequisite",
                       "ref": c.get("id")})
    if nxt and nxt.get("kind") not in ("no_mail", "park"):
        at_end = nxt["label"].lower().startswith("none")
        # the gate's blockers that hold this step: all of them for a gate step, the ones its row does not carry
        # for a plan step (the row's own prerequisites are asked above), and the evidence an insufficient_data
        # verdict asks for
        blockers = nxt.get("blockers") or [{"kind": "other", "text": p} for p in nxt["prerequisites"]]
        if nxt["source"] == "plan" and nxt.get("kind") != "first":
            keep = set(nxt.get("holds") or []) | set(nxt.get("data") or [])
            blockers = [b for b in blockers if b["text"] in keep]
        for b in blockers:
            if b["kind"] == "spoof":
                q = "Can we confirm none of these is ours on %s: %s?" % (org, b["text"])
            elif b["kind"] == "data" and at_end:  # no step left: the data confirms the enforcement in place
                q = "Can we supply the data that confirms enforcement on %s is safe: %s?" % (org, b["text"])
            elif b["kind"] == "data":
                q = "Can we supply the data the next step on %s (%s) needs: %s?" % (org, nxt["label"], b["text"])
            elif nxt.get("kind") == "first":
                q = ("Can we close this gap on %s (a monitoring-only record reports it but does not fix it): %s?"
                     % (org, b["text"]))
            elif nxt.get("kind") in ("recheck", "fix_record"):
                q = "Can we close this gap on %s (it stands whatever its DMARC record says): %s?" % (org, b["text"])
            elif at_end:
                q = "Can we close this gap on %s (enforcement does not fix it by itself): %s?" % (org, b["text"])
            else:
                q = "Can we clear this before we %s on %s: %s?" % (nxt["label"], org, b["text"])
            qs.append({"question": q, "owner": owner_for(org), "kind": "blocker", "ref": None})
    for h in holds_for(plan):
        qs.append({"question": "%s: %s - who decides?" % (h.get("domain") or org, plain(h.get("reason") or "")),
                   "owner": owner_for(h.get("domain")), "kind": "hold", "ref": None})
    for f in (report.get("findings") or []):
        if not isinstance(f, dict) or f.get("verified", True):
            continue
        src = str(f.get("source") or "")
        keys = [src[4:]] if src.startswith("dns:") else [f.get("object") or "", org if src in ("rua", "maillog") else ""]
        qs.append({"question": "Is this right (%s, a heuristic, not verified): %s?"
                   % (f.get("id") or "finding", plain(f.get("title") or "")),
                   "owner": owner_for(*keys), "kind": "unverified", "ref": f.get("id")})
    for g in groups:
        if g["owner"] != UNASSIGNED:
            continue
        for i in g["items"]:
            qs.append({"question": "Who owns this: %s%s?" % (i["hook"], (" (%s)" % i["ref"]) if i.get("ref") else ""),
                       "owner": "unassigned", "kind": "unassigned", "ref": i.get("ref")})
    # byte-identical questions (the same heuristic once per header file) collapse into one, counted
    merged = OrderedDict()
    for q in qs:
        key = (q["question"], q["owner"])
        if key in merged:
            merged[key]["count"] += 1
        else:
            merged[key] = dict(q, count=1)
    return list(merged.values())


def audit_notes(nxt, plan, org):
    """The gate's notes the document shows under the per-domain table, each
    with what it holds: nothing, as the gate says - unless the note is the
    verdict's own hold (no rows for the domain, under insufficient_data: the
    one-liner says it already, so it is not repeated as holding nothing), or
    names unaudited subdomains a plan hold on sp= names too."""
    out = []
    for n in (nxt or {}).get("notes") or []:
        if not SHOWN_NOTES.match(n):
            continue
        if n.startswith("no mail-log rows") and (nxt or {}).get("verdict") == "insufficient_data":
            continue
        holds = None
        m = re.match(r"^unaudited subdomains (.+?) carry ", n)
        if m:
            names = [x.strip() for x in m.group(1).split(",") if x.strip()]
            if any(x in str(h.get("reason") or "") for h in holds_for(plan, org) for x in names):
                holds = "the plan's hold on sp= names them"
        out.append({"text": n, "holds": holds})
    return out


def sources_line(report, plan, metrics, owners, owners_path, previous, previous_path, view, window=None,
                 audience=None):
    ev = (report.get("gate") or {}).get("evidence") or {}
    window = window or window_of(report)
    audience = (audience or DEFAULT_AUDIENCE).strip().rstrip(".") or DEFAULT_AUDIENCE
    inputs = []
    if _n(ev.get("rua_reports")):
        inputs.append("%d aggregate %s" % (ev["rua_reports"], _plural(ev["rua_reports"], "report")))
    if view is not None and view["raw_rows"] is not None:
        inputs.append("%d mail-log rows" % view["raw_rows"])
    elif view is not None:
        inputs.append("a mail log")
    if _n(ev.get("header_files")):
        inputs.append("%d header %s" % (ev["header_files"], _plural(ev["header_files"], "file")))
    if report.get("dns"):
        inputs.append("live DNS for %d %s" % (len(report["dns"]), _plural(len(report["dns"]), "domain")))
    when = str(report.get("generated_utc") or "")[:16].replace("T", " ")
    parts = ["audit report generated %s UTC (%s)" % (when or "at an unknown time", ", ".join(inputs) or "no failure evidence")]
    mlw = (view or {}).get("window")
    mlw_text = ("mail log %s to %s UTC (%s hours)" % (_stamp(mlw["from"]), _stamp(mlw["to"]), mlw.get("hours"))
                if mlw else None)
    if window["source"]:
        note = ""
        if view is not None and window["source"] == "aggregate reports":
            note = ("; " + mlw_text) if mlw_text else "; the mail-log export carries no dates"
        parts.append("window %s (%s%s)" % (window["text"], window["source"], note))
    elif mlw_text:
        parts.append("window: " + mlw_text)
    else:
        parts.append("window not stated by the inputs (this run's window)")
    if plan is not None:
        n_ch, n_h = len(plan_changes(plan)), len(holds_for(plan))
        parts.append("rollout plan (%d %s, %d %s)" % (n_ch, _plural(n_ch, "change"), n_h, _plural(n_h, "hold")))
    else:
        parts.append("no rollout plan was supplied")
    if metrics is not None:
        parts.append("run history (%d %s)" % (len(metrics), _plural(len(metrics), "run")))
    if previous is not None:
        parts.append("previous report %s" % (_day(previous.get("generated_utc")) or display_path(previous_path)))
    if owners_path:
        parts.append("owners file %s (%d %s)" % (display_path(owners_path), len(owners), _plural(len(owners), "pattern")))
    else:
        parts.append("no owners file (everything is unassigned)")
    return ("%s. Sources: %s. Counts are deduplicated; raw row counts appear only where marked. Generated by the "
            "toolkit from the run's own data; every number traces to report.json or plan.json, and no "
            "sentence here was written by an AI."
            % (audience, "; ".join(parts)))


def build(report, plan=None, metrics=None, owners=(), previous=None, date=None, org_name=None,
          owners_path=None, previous_path=None, audience=None):
    """The whole document as data. Raises UsageError on unusable inputs."""
    owners = list(owners or [])
    audience = (audience or DEFAULT_AUDIENCE).strip().rstrip(".") or DEFAULT_AUDIENCE
    org = pick_org(report, org_name)
    date = date or _day(report.get("generated_utc")) or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    view = maillog_view(report)
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else None
    policy_str, pct = policy_text(report, org)
    policy = current_policy(report, org)
    since = policy_since(metrics, org, policy) if metrics else None
    delta = report.get("delta") if isinstance(report.get("delta"), dict) else {}
    changed = (delta.get("policy_changes") or {}).get(org) if isinstance(delta.get("policy_changes"), dict) else None
    if not since and isinstance(changed, dict) and changed.get("to") == policy and changed.get("from"):
        since = date  # the delta shows the policy changed in this very run
    own = own_domain_view(report, view, org)
    strm = streams(view, rua, own, _excepted_ips(report))
    nxt = org_next(report, plan, org, own)
    line = one_liner(org, policy, pct, since, strm, nxt)
    window = window_of(report)

    now_gf = view["genuine_failures"] if view else None
    now_pr = _f(((rua or {}).get("totals") or {}).get("pass_rate"))
    trend = merge_trends([trend_from_delta(delta, now_gf, now_pr),
                          trend_from_report(previous),
                          trend_from_metrics(metrics, report, view) if metrics else None])
    trend = apply_comparability(trend, delta, report, view)
    stand = where_we_stand(report, view, trend, window, policy)
    failing, failing_lines = what_is_failing(report, view)
    domains = per_domain(report, plan)
    groups = build_actions(report, plan, view, owners)
    ask = build_ask(plan, org, nxt, policy)
    questions = open_questions(report, plan, org, nxt, owners, groups)
    strm_data = None
    if strm is not None:
        strm_data = {"basis": strm["basis"], "scope": strm.get("scope")}
        for k in ("own", "spoof", "unclear"):
            strm_data[k] = [{"name": s["name"], "count": s["count"]} for s in strm[k]]
        if strm.get("scope") in OWN_SCOPES:
            strm_data.update({"genuine_failures": strm["genuine_failures"], "logical_messages": strm["logical_messages"],
                              "by_likely": strm["by_likely"], "excepted": strm.get("excepted") or 0,
                              "top_senders": [{"name": s["name"], "count": s["count"]} for s in strm["top_senders"]]})
            if strm.get("subdomains"):
                strm_data["subdomains"] = list(strm["subdomains"])  # whose rows these numbers are
        elif strm["basis"] == "mail log":  # the whole census: the excepted messages, and from how many senders
            strm_data.update({"excepted": strm.get("excepted") or 0, "excepted_senders": strm.get("excepted_senders")})
    doc = {
        "tool": "next_steps.py", "version": VERSION, "date": date, "org_domain": org,
        "policy": {"p": policy, "pct": pct, "since": since, "text": policy_str},
        "next_step": nxt,
        "audit_notes": audit_notes(nxt, plan, org),
        "one_liner": line,
        "stand": stand,
        "failing": dict(failing, lines=failing_lines, streams=strm_data),
        "per_domain": domains,
        "mailflow": {"days": audit._dict(report.get("mailflow")).get("days"), "note": mailflow_note(report)},
        "actions_by_owner": groups,
        "ask": ask,
        "open_questions": questions,
        "glossary": dict(GLOSSARY),
        "sources": {"report_generated_utc": report.get("generated_utc"), "report_tool": report.get("tool"),
                    "plan": plan is not None, "plan_changes": len(plan_changes(plan)), "plan_holds": len(holds_for(plan)),
                    "metrics_runs": len(metrics) if metrics is not None else None,
                    "previous_report": (previous.get("generated_utc") if previous else None),
                    "owners_file": display_path(owners_path) if owners_path else None, "owner_patterns": len(owners),
                    "maillog_basis": (view or {}).get("basis"), "trend_source": (trend or {}).get("source"),
                    "window": window, "audience": audience,
                    "audience_line": sources_line(report, plan, metrics, owners, owners_path, previous, previous_path,
                                                  view, window, audience)},
    }
    return _clean(doc)


def render_md(doc):
    L = []
    L.append("# DMARC rollout - status and next steps, %s" % doc["date"])
    L.append("")
    L.append(doc["sources"]["audience_line"])
    L.append("")
    L.append("To check any number or record here yourself, follow verify.md next to this file: the lookup, query or "
             "command for every finding and every plan row, with the value to expect.")
    L.append("")
    L.append("**%s**" % doc["one_liner"])
    L.append("")
    window = (doc["stand"].get("window") or {}).get("text") or "this run's window"
    L.append("## Where we stand (%s, deduplicated)" % window)
    L.append("")
    L += ["- " + l for l in doc["stand"]["lines"]]
    L.append("")
    L.append("## What is failing")
    L.append("")
    L += doc["failing"]["lines"]
    L.append("")
    L.append("## Per domain")
    L.append("")
    if doc["per_domain"]:
        L += render_per_domain(doc["per_domain"])
        if (doc.get("mailflow") or {}).get("note"):
            L.append("")
            L.append(doc["mailflow"]["note"])
    else:
        L.append("No domain was audited in this run.")
    notes = doc.get("audit_notes") or []
    if notes:
        L.append("")
        if any(n.get("holds") for n in notes):
            L.append("From the audit on %s:" % doc["org_domain"])
            L += ["- %s (%s)" % (n["text"], n["holds"] or "information; it holds nothing") for n in notes]
        else:
            L.append("From the audit on %s (information; it holds nothing):" % doc["org_domain"])
            L += ["- %s" % n["text"] for n in notes]
    L.append("")
    L.append("## What happens next, by owner")
    L.append("")
    L += render_actions(doc["actions_by_owner"], doc["failing"])
    L.append("")
    L.append("## The ask")
    L.append("")
    L.append(doc["ask"])
    L.append("")
    L.append("## Open questions")
    L.append("")
    if doc["open_questions"]:
        L += ["- %s%s (owner: %s)" % (q["question"], (" x %d" % q["count"]) if q.get("count", 1) > 1 else "", q["owner"])
              for q in doc["open_questions"]]
    else:
        L.append("- None from this run.")
    L.append("")
    L.append("---")
    L.append("")
    L.append("Glossary. " + " ".join("%s is %s." % (("A " + k) if " " in k else k, v) for k, v in doc["glossary"].items()))
    L.append("")
    return hyphens("\n".join(L))


def write(doc, out_dir):
    out = repo_path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    mpath, jpath = out / "next_steps.md", out / "next_steps.json"
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_md(doc))
    with open(jpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    return mpath, jpath


# ------------------------------------------------------------------ cli

def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="report.json from src/audit.py (or collect.py's latest/report.json)")
    ap.add_argument("--plan", metavar="JSON", help="plan.json from src/plan.py")
    ap.add_argument("--metrics", metavar="JSON", help="metrics.json from src/collect.py (the run history)")
    ap.add_argument("--owners", metavar="CSV",
                    help="owners file (default: <repo root>/%s when it exists)" % DEFAULT_OWNERS)
    ap.add_argument("--previous", metavar="JSON",
                    help="the previous run's report.json, for the trend when the report carries no delta")
    ap.add_argument("--date", help="date in the title (default: the report's generation date)")
    ap.add_argument("--org-name", metavar="DOMAIN",
                    help="the organization domain the one-liner is about (default: the report's headline domain, else the first audited apex)")
    ap.add_argument("--audience", metavar="TEXT", default=None,
                    help="the first sentence of the audience line (default: '%s')" % DEFAULT_AUDIENCE)
    ap.add_argument("--out", metavar="DIR",
                    help="write next_steps.md and next_steps.json here (default: print next_steps.md)")
    ap.add_argument("--json", action="store_true", help="print next_steps.json instead of next_steps.md")
    ap.add_argument("--debug", action="store_true",
                    help="show the traceback for an internal error instead of a one-line message")
    args = ap.parse_args(argv)
    try:
        # a census split off to census.json beside the report is read back whole, as collect.py and notify.py read it
        report = audit.load_census(read_json(args.report, "report"), args.report)
        plan = read_json(args.plan, "--plan") if args.plan else None
        metrics = read_json(args.metrics, "--metrics", list) if args.metrics else None
        previous = audit.load_census(read_json(args.previous, "--previous"), args.previous) if args.previous else None
        owners_path, owners = None, []
        if args.owners:
            owners_path = repo_path(args.owners)
            owners = read_owners(owners_path)
        elif (ROOT / DEFAULT_OWNERS).is_file():
            owners_path = ROOT / DEFAULT_OWNERS
            owners = read_owners(owners_path)
        if not isinstance(report.get("gate"), dict) and not report.get("inputs"):
            raise UsageError("%s does not look like an audit report (no gate and no inputs section)"
                             % repo_path(args.report))
        doc = build(report, plan, metrics, owners, previous, args.date, args.org_name,
                    owners_path, repo_path(args.previous) if args.previous else None, args.audience)
        if args.out:
            try:
                mpath, jpath = write(doc, args.out)
            except OSError as exc:
                die("cannot write to %s: %s" % (repo_path(args.out), exc.strerror or exc))
            print("wrote %s" % mpath)
            print("wrote %s" % jpath)
            if not owners_path:
                print("note: no owners file - every action is under '%s' (see samples/owners.csv.example)"
                      % UNASSIGNED, file=sys.stderr)
        elif args.json:
            print(json.dumps(doc, indent=1))
        else:
            print(render_md(doc))
    except UsageError as exc:
        die(str(exc))
    except Exception as exc:  # never a traceback for the reader, rendering and writing included; --debug for the developer
        if args.debug:
            raise
        die("could not build the document from these inputs (%s: %s); re-run with --debug for the traceback"
            % (type(exc).__name__, exc))
    sys.exit(0)


if __name__ == "__main__":
    main()
