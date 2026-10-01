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
sentence of the audience line.

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
                "unknown": "unclear", "mixed": "mixed - some look like spoofing, some like our own systems"}
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
GAP_RX = re.compile(r"^(\d+) logical message\(s\) from this domain failed with no passing copy \(deduplicated\)"
                    r"(?:; top senders: .*)?$")
# Plan prerequisites written as observations, reworded as the condition that clears them.
PREREQ_REWORDS = (
    (re.compile(r"^(\d+) message\(s\) in the mail log failed from a sender that looks like your own "
                r"misconfigured system, not a spoof$"),
     lambda m: "the %s mail-log failure%s from our own systems %s fixed"
     % (m.group(1), "" if m.group(1) == "1" else "s", "is" if m.group(1) == "1" else "are")),
    (re.compile(r"^aggregate reports: (\S+) sends (\d+) message\(s\) as (\S+) and fails"),
     lambda m: "the sender at %s (%s messages as %s) is fixed" % (m.group(1), m.group(2), m.group(3))),
    (re.compile(r"^no failure evidence in this run"),
     lambda m: "a mail log or aggregate reports are supplied to the audit"),
    (re.compile(r"^SPF-only aligned senders in the aggregate reports \((.+)\): they break on forwarding at reject$"),
     lambda m: "the SPF-only senders (%s) are DKIM-signed, because SPF alone breaks on forwarding" % m.group(1)),
    (re.compile(r"^every legitimate sender proven with an aligned DKIM header( within 7 days)?$"),
     lambda m: "every legitimate sender is proven with an aligned DKIM header%s" % (m.group(1) or "")),
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


def _n(value):
    """int for anything that carries a whole number, else None (never a bool)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _f(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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
        if not m:
            return ", ".join(str(x) for x in dict.fromkeys(ids))
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
    is not understood."""
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
                 "likely": likely if isinstance(likely, str) else None, "messages": _n(it.get("messages"))}
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


def maillog_view(report):
    """What the document needs from the mail log: summaries when the report
    carries them, else derived from the verdicts. None when there is no mail log."""
    ml = report.get("maillog")
    if not isinstance(ml, dict):
        return None
    counters = ml.get("counters") if isinstance(ml.get("counters"), dict) else {}
    verdicts = [v for v in (ml.get("verdicts") or []) if isinstance(v, dict)]
    genuine = [v for v in verdicts if v.get("genuine_failure")]
    view = {"auth_column": ml.get("auth_column"), "sender_domain": ml.get("sender_domain"),
            "truncation": truncation_note(ml), "basis": None}
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
    if isinstance(census, dict):
        env_obj = next((census[k] for k in ("by_envelope", "envelope", "env", "envelopes") if k in census), None)
        snd_obj = next((census[k] for k in ("by_sender", "sender", "senders", "addr") if k in census), None)
        by_env = _entries(env_obj, ENV_KEYS) if env_obj is not None else None
        by_sender = _entries(snd_obj, SENDER_KEYS) if snd_obj is not None else None
    elif isinstance(census, list):
        by_env = _entries(census, ENV_KEYS)
    if by_env is not None or by_sender is not None:
        view["basis"] = "census"
    if (by_env is None or by_sender is None) and verdicts:
        v_env, v_snd = _from_verdicts(genuine)
        by_env = by_env if by_env is not None else v_env
        by_sender = by_sender if by_sender is not None else v_snd
        view["basis"] = view["basis"] or "verdicts"
    view["by_envelope"] = by_env or []
    view["by_sender"] = by_sender or []
    view["census_missing"] = by_env is None and by_sender is None
    ddf = Counter((v.get("sender") or "(no sender)").lower() for v in verdicts if v.get("delivered_despite_fail"))
    view["ddf_senders"] = [{"name": s, "count": n, "domain": (s.rpartition("@")[2] if "@" in s else ""),
                            "envelope": next(((v.get("envelope_domain") or "") for v in verdicts
                                              if (v.get("sender") or "").lower() == s), "")}
                           for s, n in sorted(ddf.items(), key=lambda kv: (-kv[1], kv[0]))]
    for s in view["by_sender"]:
        s["likely"] = s.get("likely") or "unknown"
    return view


def own_domain_view(report, view, org):
    """The organization domain's own mail-log numbers (maillog.by_domain[org]:
    its genuine failures, top senders and the likely split), with the census
    entries for its senders; None when the report carries no per-domain
    attribution, in which case the one-liner falls back to the whole census."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else None
    bd = (ml or {}).get("by_domain")
    c = bd.get(org) if isinstance(bd, dict) else None
    if not isinstance(c, dict) or _n(c.get("genuine_failures")) is None:
        return None
    senders = [s for s in (view["by_sender"] if view else []) if s.get("domain") == org]
    by_likely = c.get("by_likely") if isinstance(c.get("by_likely"), dict) else None
    if by_likely is None and senders:
        cnt = Counter()
        for s in senders:
            cnt[s.get("likely") or "unknown"] += s["count"]
        by_likely = {k: cnt.get(k, 0) for k in ("likely_spoof", "likely_misconfigured_sender", "unknown")}
    return {"genuine_failures": _n(c["genuine_failures"]), "logical_messages": _n(c.get("logical_messages")),
            "delivered_despite_fail": _n(c.get("delivered_despite_fail")),
            "by_likely": {k: _n(v) or 0 for k, v in by_likely.items()} if by_likely else None,
            "top_senders": _entries(c.get("top_senders"), SENDER_KEYS) or [], "senders": senders}


def streams(view, rua, own=None):
    """The one-liner's senders: the organization domain's own (from
    maillog.by_domain), else every sender in the census 'across all audited
    domains', else source IPs from the aggregate reports when there is no mail log."""
    if own is not None:
        groups = {"likely_misconfigured_sender": [], "likely_spoof": [], "unknown": []}
        for s in own["senders"]:
            groups[s["likely"] if s.get("likely") in groups else "unknown"].append(s)
        return {"basis": "mail log", "scope": "own domain", "own": groups["likely_misconfigured_sender"],
                "spoof": groups["likely_spoof"], "unclear": groups["unknown"],
                "genuine_failures": own["genuine_failures"], "logical_messages": own["logical_messages"],
                "by_likely": own["by_likely"], "top_senders": own["top_senders"]}
    if view is not None and (view["by_sender"] or view["genuine_failures"] is not None):
        own_s = [s for s in view["by_sender"] if s["likely"] == "likely_misconfigured_sender"]
        spoof = [s for s in view["by_sender"] if s["likely"] == "likely_spoof"]
        unclear = [s for s in view["by_sender"] if s["likely"] not in ("likely_misconfigured_sender", "likely_spoof")]
        return {"basis": "mail log", "scope": "all audited domains", "own": own_s, "spoof": spoof, "unclear": unclear}
    if isinstance(rua, dict):
        fs = [s for s in (rua.get("failing_streams") or []) if isinstance(s, dict)]

        def conv(s):
            return {"name": "%s as %s" % (s.get("source_ip", "?"), ", ".join(s.get("header_from") or [])[:60] or "?"),
                    "count": _n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0),
                    "likely": s.get("likely") or "unknown"}
        own_s = [conv(s) for s in fs if s.get("likely") == "likely_misconfigured_sender"]
        spoof = [conv(s) for s in fs if s.get("likely") == "likely_spoof"]
        unclear = [conv(s) for s in fs if s.get("likely") not in ("likely_misconfigured_sender", "likely_spoof")]
        return {"basis": "aggregate reports", "scope": "aggregate reports", "own": own_s, "spoof": spoof,
                "unclear": unclear}
    return None


def spoof_share(rua):
    """What the aggregate reports' sources labelled likely_spoof add up to:
    failing messages, sources, and what receivers did with them."""
    fs = [s for s in ((rua or {}).get("failing_streams") or [])
          if isinstance(s, dict) and s.get("likely") == "likely_spoof"]
    if not fs:
        return None
    disp = Counter()
    for s in fs:
        for k, v in (s.get("dispositions") or {}).items():
            disp[k] += _n(v) or 0
    msgs = sum((_n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0)) for s in fs)
    return {"messages": msgs, "sources": len(fs), "rejected": disp.get("reject", 0),
            "quarantined": disp.get("quarantine", 0), "delivered": disp.get("none", 0)}


def window_of(report):
    """The date window the inputs state: the aggregate reports' own range,
    else the requested --since/--until bounds, else 'this run's window'.
    Never a number of days the inputs do not carry. The mail-log export
    carries no dates, and the sources line says so."""
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
        return None
    return {"source": "delta", "label": label or "the previous run",
            "previous_genuine_failures": int(prev_gf) if prev_gf is not None else None,
            "previous_pass_rate": prev_pr}


def merge_trends(candidates):
    """The first candidate that knows anything, its gaps filled from later
    candidates that describe the same previous run (audit.py's delta carries
    the failure change but no pass rate; metrics.json carries both)."""
    cands = [c for c in candidates if c]
    if not cands:
        return None
    out = dict(cands[0])
    for c in cands[1:]:
        if c["label"] != out["label"]:
            continue
        for k in ("previous_genuine_failures", "previous_pass_rate"):
            if out.get(k) is None and c.get(k) is not None:
                out[k] = c[k]
                out["source"] += " + " + c["source"]
    return out


def trend_from_report(previous):
    if not isinstance(previous, dict):
        return None
    gf = _n(((previous.get("maillog") or {}).get("counters") or {}).get("genuine_failures"))
    pr = _f(((previous.get("rua") or {}).get("totals") or {}).get("pass_rate"))
    if gf is None and pr is None:
        return None
    return {"source": "previous report", "label": _day(previous.get("generated_utc")) or "the previous run",
            "previous_genuine_failures": gf, "previous_pass_rate": pr}


def _same_run(entry, report, view):
    """A metrics entry is this run when it is from the same UTC day and carries the same counts."""
    if _day(entry.get("run")) != _day(report.get("generated_utc")):
        return False
    gf = view["genuine_failures"] if view else None
    rm = _n(((report.get("rua") or {}).get("totals") or {}).get("messages"))
    return _n(entry.get("genuine_failures")) == gf and _n(entry.get("rua_messages")) == rm


def previous_entry(metrics, report, view):
    """The run before this one in metrics.json, whether or not this run is already in it."""
    entries = sorted((e for e in metrics if isinstance(e, dict) and e.get("run")), key=lambda e: str(e["run"]))
    now = str(report.get("generated_utc") or "").replace(":", "")
    before = [e for e in entries
              if not now or str(e["run"]).replace(":", "") <= now or _day(e["run"]) == _day(now)]
    before = [e for e in before if not _same_run(e, report, view)]
    return before[-1] if before else None


def trend_from_metrics(metrics, report, view):
    e = previous_entry(metrics, report, view)
    if not e:
        return None
    gf, pr = _n(e.get("genuine_failures")), _f(e.get("rua_pass_rate"))
    if gf is None and pr is None:
        return None
    return {"source": "metrics", "label": _day(e.get("run")) or str(e.get("run")),
            "previous_genuine_failures": gf, "previous_pass_rate": pr}


def policy_since(metrics, org, policy):
    """The run date on which the current policy first appeared in the history,
    only when the history also shows a different policy before it."""
    if not policy:
        return None
    entries = sorted((e for e in metrics if isinstance(e, dict) and e.get("run")), key=lambda e: str(e["run"]))
    seq = [((e.get("domains") or {}).get(org) or {}).get("policy") for e in entries]
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
    if kind == "new":
        return "publish a p=%s monitoring record" % tags.get("p", "none")
    if kind == "modify":
        if is_spf:
            parts = value.split()
            return "change the SPF ending to %s" % (parts[-1] if parts else "~all")
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


def reword_prereq(text):
    """A plan prerequisite as the condition that clears it; never verbatim."""
    for rx, fn in PREREQ_REWORDS:
        m = rx.match(text or "")
        if m:
            return plain(fn(m))
    return plain(text)


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

def pick_org(report, org_name=None):
    """--org-name, else the first audited apex (in the order the domains were
    given), else the gate's headline domain, else the first audited domain."""
    if org_name:
        return org_name.strip().lower().rstrip(".")
    gate = report.get("gate") or {}
    names = [str(d).lower() for d in ((report.get("inputs") or {}).get("domains") or []) if d]
    names += [d.lower() for d in (gate.get("domains") or {})]
    names += [str(d).lower() for d in ((report.get("rua") or {}).get("totals") or {}).get("domains") or []]
    names = list(dict.fromkeys(names))
    if not names:
        raise UsageError("the report names no audited domain; pass --org-name")
    for d in names:
        if org_domain(d) == d:
            return d
    return str(gate.get("headline_domain") or names[0]).lower()


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
    """The gate's policy for one domain; the overall one when the gate has no per-domain entries."""
    gate = report.get("gate") or {}
    g = (gate.get("domains") or {}).get(domain) or {}
    if g.get("current_policy"):
        return g["current_policy"]
    if not gate.get("domains"):
        return gate.get("current_policy")
    return None


def policy_text(report, domain):
    policy = current_policy(report, domain)
    dns_doc = (report.get("dns") or {}).get(domain) or {}
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


def gate_reasons(report, domain):
    """The gate's reasons that are blockers, not narration, as the audit wrote them."""
    gate = report.get("gate") or {}
    g = (gate.get("domains") or {}).get(domain) or {}
    statement = (gate.get("evidence") or {}).get("statement")
    out = []
    for r in g.get("reasons") or (gate.get("reasons") if not gate.get("domains") else []) or []:
        if domain:
            r = re.sub(r"^%s: " % re.escape(domain), "", r)
        if r == statement or re.match(r"^(policy (is|p=)|step being gated|no DMARC policy could be determined"
                                      r"|\d+ failing stream\(s\) look like spoofs)", r):
            continue
        out.append(r)
    return out


def _named(entries, cap=3):
    return ", ".join("%s x%d" % (s["name"], s["count"]) for s in entries[:cap])


def _spoof_clause(policy):
    """What happens to failures that look like spoofing, given the policy."""
    if policy in ("quarantine", "reject"):
        return "the policy handles them"
    if policy == "none":
        return "p=none does not stop them yet"
    return "no policy stops them until one is published"


def blocker_items(report, domain, own=None):
    """The gate's blockers for one domain as the reader sees them, each typed:
    'own' (our senders: a gap to close), 'spoof' (failures that look like
    spoofing, which the policy handles once they are confirmed not ours) or
    'other'. The mail-log failure count is split with the domain's own likely
    split, so spoofs are never asked to be closed."""
    out = []
    bl = (own or {}).get("by_likely") or {}
    clause = _spoof_clause(current_policy(report, domain))
    for r in gate_reasons(report, domain):
        m = GAP_RX.match(r)
        if m and bl.get("likely_spoof"):
            total, spoof_n = int(m.group(1)), bl["likely_spoof"]
            rest = total - spoof_n
            senders = (own or {}).get("senders") or []
            if rest > 0:
                ours = [s for s in senders if s.get("likely") != "likely_spoof"]
                who = "our own senders" if not bl.get("unknown") else "senders that are ours or unclear"
                names = _named(ours)
                out.append({"kind": "own", "text": "%d %s from %s failed with no passing copy%s; the other %d look "
                            "like spoofing, and %s" % (rest, _plural(rest, "message"), who,
                                                       (" (%s)" % names) if names else "", spoof_n, clause)})
            else:
                spoofs = [s for s in senders if s.get("likely") == "likely_spoof"]
                names = _named(spoofs)
                out.append({"kind": "spoof", "text": "%d %s from %s that look like spoofing failed with no passing "
                            "copy%s; once they are confirmed not ours, %s"
                            % (spoof_n, _plural(spoof_n, "message"),
                               ("%d %s" % (len(spoofs), _plural(len(spoofs), "address", "addresses"))) if spoofs
                               else "addresses", (" (%s)" % names) if names else "", clause)})
            continue
        out.append({"kind": "other", "text": plain(r)})
    return out


def gate_blockers(report, domain, own=None):
    """The gate's blockers for one domain, as text."""
    return [b["text"] for b in blocker_items(report, domain, own)]


def org_next(report, plan, org, own=None):
    """The org domain's next step: the first plan change for it, else the
    gate's. With no policy read (the gate says 'unknown'), the first step is
    always the monitoring-only record, never the gate's placeholder."""
    changes = changes_for(plan, org)
    gate = report.get("gate") or {}
    g = (gate.get("domains") or {}).get(org) or {}
    gate_step = _short_step(g.get("next_step") or (gate.get("next_step") if not gate.get("domains") else "") or "")
    if current_policy(report, org) is None or gate_step.lower().startswith("unknown"):
        rec = next((c for c in changes if c.get("kind") == "new"
                    and str(c.get("hostname") or "").lower().startswith("_dmarc.")), None)
        return {"label": FIRST_STEP % org, "ref": rec.get("id") if rec else None, "prerequisites": [],
                "why": "no policy could be read", "source": "plan" if rec else "gate", "kind": "first",
                "priority": _n(rec.get("priority")) if rec else None, "blockers": blocker_items(report, org, own)}
    if changes:
        c = changes[0]
        prereqs = [reword_prereq(p) for p in prereqs_of(c)]
        return {"label": plain(step_label(c)), "ref": c.get("id"), "prerequisites": prereqs,
                "why": c.get("why"), "source": "plan", "kind": c.get("kind"), "priority": c.get("priority"),
                "blockers": []}
    if gate_step:
        items = blocker_items(report, org, own)
        return {"label": plain(gate_step), "ref": None, "prerequisites": [b["text"] for b in items],
                "why": None, "source": "gate", "kind": None, "priority": None, "blockers": items}
    return None


def _readiness(nxt):
    """', ready when ...' for a plan step (its prerequisites are conditions),
    ', on hold while: ...' for a gate step (its blockers are observations)."""
    if not nxt["prerequisites"]:
        return ", and it is ready now."
    if nxt["source"] == "gate":
        return ", on hold while: %s." % "; ".join(nxt["prerequisites"])
    return ", ready when %s." % _join(nxt["prerequisites"])


def _handled(policy, n):
    """What the policy does about n senders that look like spoofing."""
    if policy in ("quarantine", "reject"):
        return " and %s being handled by the policy" % _plural(n, "is", "are")
    if policy == "none":
        return ", which p=none does not stop yet"
    return ", which no policy stops until one is published"


def _own_domain_sentence(org, policy, strm):
    """The one-liner's middle from the org domain's own rows (maillog.by_domain)."""
    gf, seen, bl = strm["genuine_failures"], strm["logical_messages"], strm["by_likely"]
    if not gf:
        if seen:
            return "None of %s's own mail failed with no passing copy in the mail log (%d %s checked)." % (
                org, seen, _plural(seen, "message"))
        return "The mail log has no rows for %s, so nothing here can say which of its senders fail." % org
    mid = "%d %s from %s failed with no passing copy" % (gf, _plural(gf, "message"), org)
    if bl:
        own_n, spoof_n = bl.get("likely_misconfigured_sender", 0), bl.get("likely_spoof", 0)
        unclear_n = bl.get("unknown", 0)
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
            parts.append("%d from %s that look like spoofing%s" % (spoof_n, who, _handled(policy, k or spoof_n)))
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
    elif strm.get("scope") == "own domain":
        mid = _own_domain_sentence(org, policy, strm)
    else:
        own, spoof, unclear = strm["own"], strm["spoof"], strm["unclear"]
        unit = "sender" if strm["basis"] == "mail log" else "source"
        ours = "senders" if strm["basis"] == "mail log" else "sending sources"
        via = " (from the aggregate reports)" if strm["basis"] != "mail log" else ""
        lead = "Across all audited domains, " if strm["basis"] == "mail log" else ""
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
                                                _handled(policy, len(spoof)))
        mid += "."
    if nxt and nxt.get("kind") == "first":
        ref = (" (plan %s)" % nxt["ref"]) if nxt.get("ref") else ""
        tail = "The first step is to %s%s; no policy could be read." % (nxt["label"], ref)
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


def where_we_stand(report, view, trend, window=None):
    """The four 'Where we stand' lines, as data and as text."""
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else None
    tot = (rua or {}).get("totals") or {}
    lines, data = [], {"window": window or window_of(report)}
    if view is None or view["genuine_failures"] is None:
        data["genuine_failures"] = None
        lines.append("**Genuine failures: not in this run** - no mail log was read, so this run cannot count them")
    else:
        gf, raw = view["genuine_failures"], view["raw_failing_rows"]
        data.update({"genuine_failures": gf, "raw_failing_rows": raw, "truncation": view["truncation"]})
        text = "**Genuine failures: %d**" % gf
        if raw is not None:
            text += " (raw counts would say %d - the gap is relay echoes, not broken senders)" % raw
        if view["truncation"]:
            text += "; the log export was cut short (%s), so this count is a floor" % view["truncation"]
        if not view["auth_column"]:
            text += ("; the export carried no authentication column, so failure here means never delivered "
                     "rather than failed DMARC")
        lines.append(text)
        ddf = view["delivered_despite_fail"]
        data["delivered_despite_fail"] = ddf
        data["delivered_despite_fail_senders"] = view["ddf_senders"][:3]
        if ddf is None:
            lines.append("**Delivered despite failing: not in this run**")
        else:
            text = "**Delivered despite failing: %d**" % ddf
            if ddf:
                text += " - these only arrive because of our own overrides; outside receivers are not as forgiving"
                if view["ddf_senders"]:
                    text += " (%s)" % ", ".join("%s x%d" % (s["name"], s["count"]) for s in view["ddf_senders"][:3])
            lines.append(text)
    if tot:
        disp = tot.get("by_disposition") or {}
        rej, qua = _n(disp.get("reject")) or 0, _n(disp.get("quarantine")) or 0
        msgs, reports, rate = _n(tot.get("messages")), _n(tot.get("reports")) or 0, _f(tot.get("pass_rate"))
        share = spoof_share(rua)
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
        if parts:
            lines.append("**Trend vs %s: %s**" % (trend["label"], ", ".join(parts)))
        else:
            lines.append("**Trend vs %s: not comparable** - the two runs do not share a failure count or a pass rate"
                         % trend["label"])
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
    if rua:
        fs = [s for s in (rua.get("failing_streams") or []) if isinstance(s, dict)]
        out = []
        for s in fs:
            fail = _n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0)
            out.append({"name": s.get("source_ip") or "?", "count": fail, "total": _n(s.get("count")),
                        "likely": s.get("likely") or "unknown", "header_from": list(s.get("header_from") or []),
                        "dispositions": s.get("dispositions") or {}})
        data["outside"] = out
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
        else:
            lines.append("From the outside (aggregate reports): no source fails with volume.")
    dl = report.get("delta") if isinstance(report.get("delta"), dict) else None
    if dl and isinstance(dl.get("new_senders"), list):
        new = _entries(dl["new_senders"], SENDER_KEYS) or []
        if new:
            more = (" (+%d more)" % (len(new) - TOP_ENTRIES)) if len(new) > TOP_ENTRIES else ""
            lines.append("")
            lines.append("Failing senders not seen in the previous run (%s): %s%s"
                         % (_day(dl.get("previous_generated_utc")) or "date unknown", _note_line(new[:TOP_ENTRIES]), more))
            data["new_senders"] = new
    return data, lines


def per_domain(report, plan):
    gate_domains = (report.get("gate") or {}).get("domains") or {}
    names = list(gate_domains) + [d for d in ((plan or {}).get("domains") or []) if isinstance(d, str)]
    names += [str(d) for d in ((report.get("inputs") or {}).get("domains") or [])]
    if not names:  # an offline run with no domain named: the reports say what they cover
        names = [str(d) for d in ((report.get("rua") or {}).get("totals") or {}).get("domains") or []]
    names = list(dict.fromkeys(n.lower() for n in names if n))
    names.sort(key=lambda d: (org_domain(d), d != org_domain(d), d))
    bd = (report.get("maillog") or {}).get("by_domain") if isinstance(report.get("maillog"), dict) else None
    bd = bd if isinstance(bd, dict) else {}
    rows = []
    for d in names:
        policy, _pct = policy_text(report, d)
        g = gate_domains.get(d) or {}
        verdict = g.get("verdict")
        gate = verdict or "not checked"
        gate_text = GATE_WORDS.get(verdict, verdict) if verdict else "not checked"
        ml = bd.get(d) if isinstance(bd.get(d), dict) else None
        changes = changes_for(plan, d)
        holds = holds_for(plan, d)
        ids = [c.get("id") for c in changes if c.get("id")]
        audit_step = _short_step(g.get("next_step") or "")
        if audit_step.lower().startswith("unknown"):
            audit_step = "publish a monitoring-only DMARC record so reports start (no policy could be read)"
        if changes:
            step = step_label(changes[0])
            if len(changes) > 1:
                step += ", then " + step_label(changes[1])
            if len(changes) > 2:
                step += " (+%d more in the plan)" % (len(changes) - 2)
        elif holds:
            step = "hold: " + str(holds[0].get("reason") or "").split(" - ")[0]
        elif plan is not None and audit_step:
            step = "nothing in the plan; the audit says: " + audit_step
        elif audit_step:
            step = audit_step
        else:
            step = "not audited in this run"
        rows.append({"domain": d, "apex": org_domain(d), "policy_today": policy, "gate": gate, "gate_text": gate_text,
                     "next_step": plain(step), "plan_ids": ids,
                     "maillog": ({k: _n(ml.get(k)) for k in ("logical_messages", "genuine_failures",
                                                              "delivered_despite_fail")} if ml else None)})
    grouped = OrderedDict()
    for r in rows:
        if r["domain"] == r["apex"]:
            key = ("apex", r["domain"])
        else:
            key = ("sub", r["apex"], r["policy_today"], r["gate"], r["next_step"])
        grp = grouped.setdefault(key, {"domains": [], "policy_today": r["policy_today"], "gate": r["gate"],
                                       "gate_text": r["gate_text"], "next_step": r["next_step"], "plan_ids": [],
                                       "maillog": {}})
        grp["domains"].append(r["domain"])
        grp["plan_ids"] += r["plan_ids"]
        if r["maillog"]:
            grp["maillog"][r["domain"]] = r["maillog"]
    return list(grouped.values())


def render_per_domain(groups):
    L = ["| Domain | Policy today | Gate | Next step |", "|---|---|---|---|"]
    for g in groups:
        step = g["next_step"]
        if g["plan_ids"]:
            step += " (plan %s)" % id_range(g["plan_ids"])
        L.append("| %s | %s | %s | %s |" % (", ".join("`%s`" % d for d in g["domains"]), g["policy_today"],
                                          g.get("gate_text") or g["gate"], step))
    return L


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
                          "is_dmarc": str(c.get("hostname") or "").startswith("_dmarc.")})
        else:
            action = plain(step_label(c))
            why = plain(str(c.get("human_summary") or c.get("why") or "").strip())  # plan.py's plain words first
            if why:
                action += " - " + why
            pre = [reword_prereq(p) for p in prereqs_of(c)]
            if pre:
                action += " (before applying: %s)" % _join(pre)
            items.append({"kind": "dns", "keys": keys, "ref": c.get("id"), "domain": dom, "hook": dom, "action": action})
        for fid in c.get("finding_ids") or []:
            covered.add(("dns:" + dom, fid))

    if view is not None:
        ref = "MAILFLOW-001" if "MAILFLOW-001" in ids_present else "mail log"
        own_all = [s for s in view["by_sender"] if s["likely"] != "likely_spoof"]
        for s in own_all[:SENDER_ITEMS_CAP]:
            hook = "%s - %d %s" % (s["name"], s["count"], _plural(s["count"], "message"))
            subj = ('subjects like "%s"' % str(s["subjects"][0])[:60]) if s.get("subjects") else ""
            env = ("envelope %s" % s["envelope"]) if s.get("envelope") else ""
            detail = "; ".join(x for x in (subj, env) if x)
            if s["likely"] == "likely_misconfigured_sender":
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
        spoof = [s for s in view["by_sender"] if s["likely"] == "likely_spoof"]
        if spoof:
            total = sum(s["count"] for s in spoof)
            top_dom = Counter(s.get("domain") or "" for s in spoof).most_common(1)[0][0]
            top_env = Counter(s.get("envelope") or "" for s in spoof).most_common(1)[0][0]
            hook = "%d %s from %d %s that look like spoofing" % (total, _plural(total, "message"), len(spoof),
                                                                   _plural(len(spoof), "address", "addresses"))
            action = "confirm none of them is ours, then leave them to the policy"
            if top_env:
                action += " (most came in via %s%s)" % (top_env, (", as %s" % top_dom) if top_dom else "")
            items.append({"kind": "spoof", "keys": [top_dom, top_env], "ref": ref, "hook": hook, "action": action})
        if view["by_sender"] or view["genuine_failures"] == 0:
            covered.add(("maillog", "MAILFLOW-001"))
        ref = "MAILFLOW-002" if "MAILFLOW-002" in ids_present else "mail log"
        for s in view["ddf_senders"][:TOP_ENTRIES]:
            hook = "%s - %d %s reached inboxes despite failing" % (s["name"], s["count"], _plural(s["count"], "message"))
            action = ("find the override (transport rule, allow list, safe sender) that let them in and make it "
                      "conditional on authentication; outside receivers do not have it")
            items.append({"kind": "override", "keys": [s["name"], s.get("domain"), s.get("envelope")], "ref": ref,
                          "sender": s["name"], "hook": hook, "action": action})
        if view["ddf_senders"] or view["delivered_despite_fail"] == 0:
            covered.add(("maillog", "MAILFLOW-002"))

    rua = report.get("rua") if isinstance(report.get("rua"), dict) else None
    if rua:
        fs = [s for s in (rua.get("failing_streams") or []) if isinstance(s, dict)]
        ref = "OUTSIDE-001" if "OUTSIDE-001" in ids_present else "aggregate reports"
        spoof_fs = []
        for s in fs:
            hf = [h for h in (s.get("header_from") or []) if isinstance(h, str)]
            fail = _n(s.get("fail")) if _n(s.get("fail")) is not None else (_n(s.get("count")) or 0)
            if s.get("likely") == "likely_spoof":
                spoof_fs.append((s, hf, fail))
                continue
            hook = "%s - %d failing %s as %s" % (s.get("source_ip") or "?", fail, _plural(fail, "message"),
                                                 ", ".join(hf[:2]) or "?")
            if s.get("likely") == "likely_misconfigured_sender":
                action = "DKIM-sign the system behind this IP with an aligned d=: receivers see it fail"
            else:
                action = ("find out whose system this IP is: receivers see it fail and the heuristic could not "
                          "tell spoof from our own")
            sig = plain("; ".join(str(x) for x in (s.get("likely_signals") or [])[:2]))
            if sig:
                action += " (%s)" % sig[:140]
            items.append({"kind": "stream", "keys": hf + [org_domain(h) for h in hf], "ref": ref,
                          "hook": hook, "action": action})
        if spoof_fs:
            total = sum(f for _, _, f in spoof_fs)
            disp = Counter()
            for s, _, _ in spoof_fs:
                for k, v in (s.get("dispositions") or {}).items():
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
            lines.append({"hook": "%d zero-risk %s %s" % (len(p1), what, _plural(len(p1), "record")),
                          "action": "ready to publish", "ref": ("plan " + id_range(ids)) if ids else None,
                          "kind": "p1summary", "domains": [i["domain"] for i in p1]})
        for i in rest:
            lines.append({"hook": i["hook"], "action": i["action"], "ref": i["ref"], "kind": i["kind"],
                          "matched_by": i.get("matched_by")})
        out.append({"owner": g["owner"], "channel": g["channel"], "items": lines})
    return out


def render_actions(groups):
    L = []
    if not any(g["items"] for g in groups):
        return ["- Nothing to do this week: no plan changes and no actionable findings in this run."]
    for g in groups:
        L.append("- **%s**" % g["owner"] + (" (%s)" % g["channel"] if g["channel"] else ""))
        for i in g["items"]:
            ref = (" (%s)" % i["ref"]) if i.get("ref") else ""
            L.append("  - **%s** %s%s" % (i["hook"], i["action"], ref))
    return L


def build_ask(plan, org, nxt, policy):
    p1 = [c for c in plan_changes(plan) if _n(c.get("priority")) == 1]
    holds = holds_for(plan, org) or holds_for(plan)
    parts = []
    if p1:
        ids = [c.get("id") for c in p1 if c.get("id")]
        text = ("approval to publish the %d zero-risk %s (plan %s) in the next DNS change window"
                % (len(p1), _plural(len(p1), "record"), id_range(ids)))
        park = sum(1 for c in p1 if c.get("kind") == "park")
        if park:
            text += ", of which %d %s the domain's unused check first" % (
                park, "is a park row that needs" if park == 1 else "are park rows that need")
        parts.append(text)
    at_end = not nxt or nxt["label"].lower().startswith("none")
    first = nxt is not None and nxt.get("kind") == "first"
    if first:
        pass  # no policy could be read: the ask is the monitoring record, below
    elif nxt and nxt["prerequisites"] and not at_end:
        held = "is held back by this" if nxt["source"] == "gate" else "is held until this is confirmed"
        which = "the step after that" if parts else "the next step"
        parts.append("%s on %s (%s) %s: %s" % (which, org, nxt["label"], held, nxt["prerequisites"][0]))
    elif nxt and not nxt["prerequisites"] and not at_end and not p1:
        parts.append("a go-ahead to %s on %s, which this run finds ready" % (nxt["label"], org))
    if holds:
        h = holds[0]
        more = (" (+%d more %s in the plan)" % (len(holds) - 1, _plural(len(holds) - 1, "hold"))) if len(holds) > 1 else ""
        reason = plain(str(h.get("reason") or "").split(" - ")[0])
        parts.append("a decision on %s: %s%s" % (h.get("domain") or org, reason, more))
    if first:
        text = "the first step is to %s; no policy could be read" % (FIRST_STEP % org)
        if parts:
            return "The ask this week: " + _join(parts, "and") + " - " + text + "."
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
        for p in prereqs_of(c):
            qs.append({"question": "Can we confirm this before we %s (plan %s): %s?"
                       % (step_label(c), c.get("id") or "?", reword_prereq(p)),
                       "owner": owner_for(c.get("domain"), c.get("owner_hint")), "kind": "prerequisite",
                       "ref": c.get("id")})
    if nxt and (nxt["source"] == "gate" or nxt.get("kind") == "first"):
        at_end = nxt["label"].lower().startswith("none")
        blockers = nxt.get("blockers") or [{"kind": "other", "text": p} for p in nxt["prerequisites"]]
        for b in blockers:
            if b["kind"] == "spoof":
                q = "Can we confirm none of these is ours on %s: %s?" % (org, b["text"])
            elif nxt.get("kind") == "first":
                q = ("Can we close this gap on %s (a monitoring-only record reports it but does not fix it): %s?"
                     % (org, b["text"]))
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
    if window["source"]:
        note = ""
        if view is not None and window["source"] == "aggregate reports":
            note = "; the mail-log export carries no dates"
        parts.append("window %s (%s%s)" % (window["text"], window["source"], note))
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
    strm = streams(view, rua, own)
    nxt = org_next(report, plan, org, own)
    line = one_liner(org, policy, pct, since, strm, nxt)
    window = window_of(report)

    now_gf = view["genuine_failures"] if view else None
    now_pr = _f(((rua or {}).get("totals") or {}).get("pass_rate"))
    trend = merge_trends([trend_from_delta(delta, now_gf, now_pr),
                          trend_from_report(previous),
                          trend_from_metrics(metrics, report, view) if metrics else None])
    stand = where_we_stand(report, view, trend, window)
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
        if strm.get("scope") == "own domain":
            strm_data.update({"genuine_failures": strm["genuine_failures"], "logical_messages": strm["logical_messages"],
                              "by_likely": strm["by_likely"],
                              "top_senders": [{"name": s["name"], "count": s["count"]} for s in strm["top_senders"]]})
    doc = {
        "tool": "next_steps.py", "version": VERSION, "date": date, "org_domain": org,
        "policy": {"p": policy, "pct": pct, "since": since, "text": policy_str},
        "next_step": nxt,
        "one_liner": line,
        "stand": stand,
        "failing": dict(failing, lines=failing_lines, streams=strm_data),
        "per_domain": domains,
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
    else:
        L.append("No domain was audited in this run.")
    L.append("")
    L.append("## What happens next, by owner")
    L.append("")
    L += render_actions(doc["actions_by_owner"])
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
                    help="the organization domain the one-liner is about (default: the first audited apex)")
    ap.add_argument("--audience", metavar="TEXT", default=None,
                    help="the first sentence of the audience line (default: '%s')" % DEFAULT_AUDIENCE)
    ap.add_argument("--out", metavar="DIR",
                    help="write next_steps.md and next_steps.json here (default: print next_steps.md)")
    ap.add_argument("--json", action="store_true", help="print next_steps.json instead of next_steps.md")
    ap.add_argument("--debug", action="store_true",
                    help="show the traceback for an internal error instead of a one-line message")
    args = ap.parse_args(argv)
    try:
        report = read_json(args.report, "report")
        plan = read_json(args.plan, "--plan") if args.plan else None
        metrics = read_json(args.metrics, "--metrics", list) if args.metrics else None
        previous = read_json(args.previous, "--previous") if args.previous else None
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
    except UsageError as exc:
        die(str(exc))
    except Exception as exc:  # never a traceback for the reader; --debug for the developer
        if args.debug:
            raise
        die("could not build the document from these inputs (%s: %s); re-run with --debug for the traceback"
            % (type(exc).__name__, exc))
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
    sys.exit(0)


if __name__ == "__main__":
    main()
