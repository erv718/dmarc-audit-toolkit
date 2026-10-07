"""The orchestrator: one audit report from every read-only tool in the repo.

Each tool in src/ answers one question well - dns_audit the DNS posture,
rua_parse what receivers see, dedupe what the tenant log proves, headers what
a single message proves, and the three PowerShell scripts (audit_rules,
audit_bypasses, audit_groups, consumed here through their -Json exports) what
the tenant configuration lets through. The ratchet decision ("can p= move
forward") needs all of them at once, plus a verdict a human can act on. This
module wires them together (imports only, no subprocess), collects every
finding into one severity-ordered list, and ends with a gate verdict PER
DOMAIN plus an overall verdict that is the worst of them:

  go                - nothing unexplained is failing; the policy can move
  no_go             - something is still failing or unprotected; fix or
                      formally except it before p= moves (AGENTS.md gate rule)
  insufficient_data - the policy or the failure evidence is unknown; a zero
                      count here is not evidence of health

Every verdict names the concrete step being gated (gate.next_step):
  p=none                   -> p=quarantine at a low pct
  p=quarantine, pct < 100  -> raise pct
  p=quarantine, pct = 100  -> p=reject
  p=reject, no sp=         -> add an explicit sp=
  p=reject, SPF not -all   -> harden SPF to -all
  otherwise                -> none - already at the end
and every branch states whether failure evidence (aggregate reports, mail-log
rows) was supplied, so a DNS-only run never reads as a completed audit.

The gate rule, deliberately conservative:
  - any blocking finding, any failing stream not labelled likely_spoof, any
    genuine failure in the mail log, any delivered-despite-fail, and any
    tenant allow that delivers unauthenticated mail (TENANT_GATE_BLOCKS): no_go
  - a likely_spoof stream does NOT block: failing spoofs are what enforcement
    stops. It blocks only when receivers deliver it anyway (disposition none)
  - SPF-only senders block the move quarantine -> reject (DKIM before reject),
    not the move none -> quarantine; they come from the aggregate reports and,
    when the mail log carries SPF and DKIM columns (queries/raw_maillog.kql
    writes them), from the mail log too
  - the move to p=reject with no aligned-DKIM evidence at all (no aggregate
    reports, no SPF/DKIM columns) is insufficient_data, never go
  - a sender formally excepted in audit.toml ([[exceptions]]: reason, owner,
    until, removal criterion) does not block until its date passes; expired
    and incomplete entries are named in the verdict and ignored
  - no DMARC record / no rua / DMARC lookup failed: no_go (you cannot ratchet
    a policy you cannot see)
  - if no policy could be determined at all, or no failure evidence was
    supplied (no rua reports, no mail log), the verdict is insufficient_data
  - at p=reject there is nothing to ratchet; every branch says so, and the
    verdict then describes the state of enforcement rather than a move

With several domains the mail log is attributed per sender domain (the
verdict's domain field): each gate sees only its own rows, an audited apex
carries a separate subdomains_total for unaudited subdomains under it, and
rows under no audited domain count once under "(other)", attached to no gate
(maillog.by_domain). A domain with no rows of its own in the mail log and
none in the aggregate reports is insufficient_data, whatever the run holds
about other domains. The overall verdict is the worst of all domains, and
gate.current_policy, gate.policy_source and gate.next_step describe that
worst-ranked domain (on a tie the headline domain, then the order given).
gate.headline describes the headline domain: a typed one (command line,
then --file) when there is one; among discovered domains the org family
carrying the most internal mail (collect.py's hourly sizing), else the most
passing or internal mail in the mail log (passing_messages plus
internal_messages), else the most passing mail in the reports, else the
tenant default domain, else the shortest audited apex - the label says
which. A sender
census (maillog.census, from
dedupe.census) and, with --previous, a delta against an earlier report.json
(report.delta) round the report out.

Outputs: report.md (human) and report.json (machine) in the output directory
(default audit-out/), plus plan.md and plan.json when the run has a DNS
section and --no-plan is not given. Nothing else is written - everything
else stays read-only.

Usage:
    python src/audit.py example.com
    python src/audit.py --file domains.txt --rua exports/rua --maillog exports/log.csv
    python src/audit.py example.com --previous audit-out/history/<stamp>/report.json
    python src/audit.py example.com --offline --rua samples/rua \
        --maillog samples/sample_maillog.csv --headers samples/headers
    python src/audit.py example.com --rules-json exports/rules.json \
        --bypasses-json exports/bypasses.json --groups-json exports/groups.json

--offline skips all live DNS and network work and analyses only the files
given. Relative paths resolve from the repo root, as in every tool here.

Exit codes: 0 clean, 1 at least one major or blocking finding, 2 usage or
input error - the same convention as the other tools.
"""

import argparse
import contextlib
import csv
import io
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

import config as config_mod
import console
import dedupe
import dns_audit
import discover
import headers as headers_mod
import rua_parse
from spf_lookups import LIMIT as SPF_LIMIT

try:
    import dns.resolver
except ImportError:
    dns = None

VERSION = "0.5"
SEVERITY_RANK = {"info": 0, "minor": 1, "major": 2, "blocking": 3}
GATE_VERDICTS = ("go", "no_go", "insufficient_data")
GATE_RANK = {"go": 0, "insufficient_data": 1, "no_go": 2}
# DNS findings that make a ratchet meaningless: the policy or its reporting
# cannot even be seen.
DNS_GATE_BLOCKS = ("DMARC-001", "DMARC-003", "DMARC-005", "DMARC-006", "SPF-002")
# Tenant-configuration findings (audit_rules / audit_bypasses -Json) that
# deliver unauthenticated mail past the policy: the configuration twin of
# delivered-despite-fail, so at severity major they block the gate too.
TENANT_GATE_BLOCKS = ("RULES-001", "RULES-002", "RULES-101", "RULES-102", "RULES-105",
                      "RULES-107", "RULES-111")
# dedupe's default column names (Microsoft 365 Defender "All email" export);
# the --*-column flags override one entry each.
MAILLOG_COLUMNS = {"msgid": "Internet message ID", "recipient": "Recipients",
                   "sender": "Sender address", "domain": "Sender domain",
                   "action": "Delivery action", "location": "Latest delivery location",
                   "subject": "Subject", "envelope": "Sender mail from domain",
                   "direction": "Direction", "spf": "SPF", "dkim": "DKIM"}
# the time column a mail-log export may carry, first match wins: the Defender
# "All email" export, then queries/raw_maillog.kql, then common names
TIME_COLUMNS = ("Email date (UTC)", "Timestamp", "Received", "Date")
# maillog.by_domain bucket for rows whose sender domain is under no audited domain
OTHER = "(other)"
# census entries under this many genuine failures are notes, not headlines
# (docs/templates/next-steps.md voice rule)
CENSUS_HEADLINE_MIN = 10
CENSUS_TOP = 15
# maillog.census comes from dedupe.census; these are the fields the report, the
# delta and the markdown read from it, and the note the report adds to it
CENSUS_FIELDS = {
    "by_envelope": ("envelope_domain", "genuine_failures", "messages", "senders", "sample_sender", "likely"),
    "by_sender": ("sender", "domain", "envelope_domain", "genuine_failures", "messages", "likely", "sample_subject"),
}
CENSUS_NOTE = (f"sorted by genuine failures; entries under {CENSUS_HEADLINE_MIN} are notes, "
               "not headlines; likely labels are heuristics")
CENSUS_UNAVAILABLE = ("sender census unavailable: this dedupe.py has no census() with the expected "
                      "fields - update src/dedupe.py and rerun")
# The three PowerShell exports: report key -> (script, tool tag, default finding area, title).
TENANT_SECTIONS = {
    "rules": ("audit_rules.ps1", "audit_rules", "rules", "Transport rules"),
    "bypasses": ("audit_bypasses.ps1", "audit_bypasses", "rules", "Filtering bypasses"),
    "groups": ("audit_groups.ps1", "audit_groups", "groups", "Groups and forwarding"),
}
# Tables inside each export, and the (table, row label column) pairs whose
# Issues column stands in for findings when an export carries none.
TENANT_TABLES = {
    "rules": ("rules",),
    "bypasses": ("spam_policies", "spoof_allows", "inbound_connectors", "antiphish_policies", "relay_domains"),
    "groups": ("groups", "forwards", "remote_domains"),
}
TENANT_ISSUE_ROWS = {
    "rules": (("rules", "Name"),),
    "bypasses": (("inbound_connectors", "Name"), ("antiphish_policies", "Policy")),
    "groups": (("groups", "Name"),),
}
GATE_RULE = ("failing streams not labelled likely_spoof, genuine mail-log failures, "
             "delivered-despite-fail, blocking findings, tenant allows that deliver "
             "unauthenticated mail, and invisible DMARC state block the gate; spoofs "
             "already rejected do not; a sender formally excepted in audit.toml "
             "([[exceptions]] with an unexpired until and a removal criterion) does not; "
             "the move to p=reject needs aligned-DKIM evidence (aggregate reports, or a "
             "mail log with SPF and DKIM columns) or the verdict is insufficient_data")
RATCHET_PHRASE = "before ratcheting to p=reject"
RATCHET_AT_END = ("now - the policy is already p=reject, nothing is left to ratchet, and "
                  "every forwarded copy of their mail is rejected today")


class UsageError(Exception):
    """Raised for input problems; main turns it into exit 2, MCP into an error string."""


class _NoSuchError(Exception):
    """Stands in for rua_parse.RuaInputError until that class exists."""


# ------------------------------------------------------------------ helpers

def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def display_path(p):
    """Paths under the repo root shown relative to it; anything else as given."""
    path = Path(p)
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def make_resolver(addr="8.8.8.8"):
    """A real port-53 resolver when dnspython is present; the audited modules
    fall back to DNS-over-HTTPS on their own when it fails or is absent."""
    if dns is None:
        return None
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [addr]
    r.lifetime = 10
    return r


def worst_severity(findings):
    return max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)


def exit_code(findings):
    return 1 if any(f["severity"] in ("major", "blocking") for f in findings) else 0


def _source_list(paths):
    return [str(repo_path(p)) for p in paths]


def _under(name, domain):
    return bool(name) and bool(domain) and (name == domain or name.endswith("." + domain))


def _norm_name(name):
    """A domain name the way every gate key is spelled: lower-case, no
    surrounding space, no trailing dot. None and '' become ''."""
    return str(name or "").strip().lower().rstrip(".")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return list(value)


def _plain(d, order=()):
    """'key value, key value' for a small counter dict - no Python repr in the report."""
    if not d:
        return "none"
    keys = [k for k in order if k in d] + [k for k in d if k not in order]
    return ", ".join(f"{k} {d[k] if isinstance(d[k], (int, float, str)) or d[k] is None else json.dumps(d[k])}"
                     for k in keys)


def read_domain_file(path):
    """One domain per line; blanks and # comments skipped. UsageError if unreadable."""
    p = repo_path(path)
    if p.is_dir():
        raise UsageError(f"--file {p} is a directory, expected a text file with one domain per line")
    try:
        with open(p, encoding="utf-8-sig") as fh:
            return [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    except OSError as exc:
        raise UsageError(f"cannot read --file {p}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise UsageError(f"--file {p} is not UTF-8 text") from exc


def _decode_export(raw):
    """PowerShell 5.1's '>' writes UTF-16 LE; pwsh and Out-File -Encoding utf8
    write UTF-8, with or without a BOM. Accept all three."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def read_json_export(path, what):
    """One JSON document (a PowerShell -Json export) as a dict; UsageError otherwise."""
    p = repo_path(path)
    if p.is_dir():
        raise UsageError(f"{what} {p} is a directory, expected a JSON file")
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read {what} {p}: {exc.strerror or exc}") from exc
    try:
        doc = json.loads(_decode_export(raw))
    except UnicodeDecodeError as exc:
        raise UsageError(f"{what} {p} is neither UTF-8 nor UTF-16 text") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"{what} {p} is not JSON ({exc.msg} at line {exc.lineno}); "
                         "write it with the script's -Json switch") from exc
    if not isinstance(doc, dict):
        raise UsageError(f"{what} {p}: expected one JSON object (the script's -Json document), "
                         f"got {type(doc).__name__}")
    return doc, p


def _known_path_check(known):
    """--known naming a file that does not exist must say so, not 'not a domain'."""
    if not known or "," in known or ("/" not in known and "\\" not in known):
        return
    try:
        ipaddress.ip_network(known, strict=False)
        return
    except ValueError:
        pass
    p = repo_path(known)
    if not p.exists():
        raise UsageError(f"--known file not found: {p}")


# ------------------------------------------------------------------ inputs

def run_dns(domains, resolver, selectors=()):
    """dns_audit.audit_domain per domain. Keys are exactly what that function returns."""
    return {d: dns_audit.audit_domain(d, resolver, list(selectors) or None) for d in domains}


def run_rua(paths, known=None, min_volume=20, fail_threshold=0.5, since=None, until=None,
            expect_policy=None, retiring=()):
    """rua_parse.analyse as a library call; its input errors become a UsageError
    carrying the real message.

    rua_parse raises RuaInputError for those where that class exists. An older
    rua_parse prints 'error: ...' to stderr and exits 2 instead, so the fallback
    captures stderr, lifts the message out of it and replays the warnings."""
    err_cls = getattr(rua_parse, "RuaInputError", None) or _NoSuchError
    args = ([str(repo_path(p)) for p in paths],)
    kwargs = dict(known=known, min_volume=min_volume, fail_threshold=fail_threshold,
                  since=since, until=until, expect_policy=expect_policy, retiring=retiring)
    if err_cls is not _NoSuchError:
        try:
            doc, _agg = rua_parse.analyse(*args, **kwargs)
        except err_cls as exc:
            raise UsageError(f"rua: {exc}") from exc
        except SystemExit as exc:
            raise UsageError(f"rua: input error (exit {exc.code}); details on stderr") from exc
        return doc
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf):
            doc, _agg = rua_parse.analyse(*args, **kwargs)
    except SystemExit as exc:  # die() printed the cause and tried to exit 2
        lines = buf.getvalue().splitlines()
        errors = [l[len("error: "):] for l in lines if l.startswith("error: ")]
        for l in lines:
            if not l.startswith("error: "):
                print(l, file=sys.stderr)
        raise UsageError("rua: " + (errors[-1] if errors else f"input error (exit {exc.code})")) from exc
    if buf.getvalue():
        sys.stderr.write(buf.getvalue())
    return doc


def detect_auth_column(header):
    """The DMARC verdict column, when the export carries one under a known name."""
    for name in ("DMARC", "DMARC verdict", "dmarc"):
        if name in header:
            return name
    return None


def _parse_time(text):
    """A naive UTC datetime from an export's time cell (ISO 8601 with Z or an
    offset, or 'YYYY-MM-DD HH:MM:SS'), or None."""
    txt = str(text or "").strip()
    if not txt:
        return None
    txt = re.sub(r"(\.\d{6})\d+", r"\1", txt.replace("Z", "+00:00"))  # fromisoformat takes six fraction digits at most
    try:
        t = datetime.fromisoformat(txt)
    except ValueError:
        return None
    if t.tzinfo is not None:
        t = t.astimezone(timezone.utc).replace(tzinfo=None)
    return t


def maillog_window(rows, header, cols, sender_domain=None):
    """The time span the in-scope rows cover, from the first TIME_COLUMNS
    column the export carries: {column, from, to, hours, rows}, or None when
    there is no such column or no cell parses. This is how far the mail-log
    numbers reach - a row budget or a cap can make it far shorter than the
    window that was asked for."""
    col = next((c for c in TIME_COLUMNS if c in header), None)
    if not col:
        return None
    lo = hi = None
    n = 0
    for row in rows:
        if not dedupe.in_scope(row, cols, sender_domain):
            continue
        t = _parse_time(row.get(col))
        if t is None:
            continue
        n += 1
        lo = t if lo is None or t < lo else lo
        hi = t if hi is None or t > hi else hi
    if lo is None:
        return None
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return {"column": col, "from": lo.strftime(fmt), "to": hi.strftime(fmt),
            "hours": round((hi - lo).total_seconds() / 3600, 1), "rows": n}


def run_maillog(csv_path, sender_domain=None, auth_column=None, vendor_domains=(), columns=None):
    """dedupe as a library call. Returns dedupe.build_doc's document.

    columns: {logical name: column name} overrides for MAILLOG_COLUMNS (the
    --*-column flags). The auth column is auto-detected (a 'DMARC' column)
    when not given, because a verdict column the caller forgot to name
    silently turns the failure counts into delivery-action guesses."""
    path = repo_path(csv_path)
    if path.is_dir():
        raise UsageError(f"{path} is a directory, expected a CSV")
    cols = dict(MAILLOG_COLUMNS)
    for key, name in (columns or {}).items():
        if key not in MAILLOG_COLUMNS:
            raise UsageError(f"unknown mail-log column key: {key} (expected one of "
                             + ", ".join(MAILLOG_COLUMNS) + ")")
        if name:
            cols[key] = name
    try:
        header = dedupe.read_header(path)
        rows = list(dedupe.load(str(path), cols))
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise UsageError(f"{path} is not UTF-8 (re-export or convert it)") from exc
    except csv.Error as exc:
        raise UsageError(f"cannot parse {path} as CSV: {exc}") from exc

    detected = False
    if not auth_column:
        auth_column = detect_auth_column(header)
        detected = bool(auth_column)
    missing_req, missing_opt = dedupe.check_columns(header, cols, auth_column, sender_domain)
    for key in ("direction", "spf", "dkim"):  # named by hand and absent: say so, as for any other column
        if (columns or {}).get(key) and cols[key] not in header:
            missing_opt.append(cols[key])
    if missing_req:
        raise UsageError("column not found: %s. Available columns: %s"
                         % (", ".join(missing_req), ", ".join(header) or "(none)"))

    counts = dedupe.count_rows(rows, cols, sender_domain, auth_column)
    verdicts = dedupe.classify(rows, cols, sender_domain, auth_column, vendor_domains)
    counts.update(dedupe.summarize(verdicts))
    findings = dedupe.build_findings(counts, verdicts, auth_column, missing_opt, sender_domain)
    doc = dedupe.build_doc(path, counts, verdicts, findings, sender_domain, auth_column, vendor_domains)
    doc["columns"] = cols
    window = maillog_window(rows, header, cols, sender_domain)
    if window:
        doc["window"] = window
    if detected:
        doc["auth_column_detected"] = True
    if missing_opt:
        doc["missing_optional_columns"] = missing_opt
    return doc


# ------------------------------------------- per-domain attribution, census

def _counters(verdicts):
    """dedupe.summarize-style counters over one slice of verdicts, plus the
    senders behind its genuine failures. passing_messages had a copy pass
    authentication; internal_messages stayed inside the tenant without one
    (internal mail gets no DMARC verdict): together, the mail the domain
    itself sent, which a spoof never is."""
    failing = [v for v in verdicts if v.get("genuine_failure")]
    by_likely = Counter(v.get("likely") or "unknown" for v in failing)
    senders = Counter((v.get("sender") or "?").lower() for v in failing)
    return {"logical_messages": len(verdicts),
            "genuine_failures": len(failing),
            "passing_messages": sum(1 for v in verdicts if v.get("passed")),
            "internal_messages": sum(1 for v in verdicts if v.get("internal") and not v.get("passed")
                                     and not v.get("genuine_failure")),
            "echo_messages": sum(1 for v in verdicts if v.get("echo_present")),
            "delivered_despite_fail": sum(1 for v in verdicts if v.get("delivered_despite_fail")),
            "blocked_despite_pass": sum(1 for v in verdicts if v.get("blocked_despite_pass")),
            "by_likely": {k: by_likely.get(k, 0) for k in dedupe.LIKELY_LABELS},
            "top_senders": [{"sender": s, "genuine_failures": n} for s, n in senders.most_common(5)]}


def _home_domain(domain, audited):
    """(audited domain, is_unaudited_subdomain) for one sender domain: itself
    when audited, else its closest audited parent, else (None, False)."""
    if domain in audited:
        return domain, False
    parents = [a for a in audited if domain.endswith("." + a)]
    if parents:
        return max(parents, key=len), True
    return None, False


def maillog_by_domain(maillog_doc, domains=()):
    """Mail-log counters per audited sender domain, from each verdict's domain
    field (lower-cased). A subdomain's rows belong to the subdomain; an audited
    apex gets its own rows only, plus subdomains_total for rows from subdomains
    of it that are not audited themselves. Rows under no audited domain land
    under OTHER and count once, attached to no gate."""
    audited = [d for d in dict.fromkeys((d or "").strip().lower().rstrip(".") for d in domains) if d]
    own = {d: [] for d in audited}
    under = {d: {} for d in audited}
    other = {}
    for v in maillog_doc.get("verdicts") or []:
        dom = (v.get("domain") or "").strip().lower()
        home, is_sub = _home_domain(dom, audited)
        if home is None:
            other.setdefault(dom or "(blank)", []).append(v)
        elif is_sub:
            under[home].setdefault(dom, []).append(v)
        else:
            own[home].append(v)
    out = {}
    for d in audited:
        c = _counters(own[d])
        subs = under[d]
        c["subdomains_total"] = dict(_counters([v for vs in subs.values() for v in vs]), domains=sorted(subs))
        out[d] = c
    c = _counters([v for vs in other.values() for v in vs])
    c["sender_domains"] = sorted(
        ({"domain": d, "logical_messages": len(vs),
          "genuine_failures": sum(1 for v in vs if v.get("genuine_failure"))} for d, vs in other.items()),
        key=lambda r: (-r["genuine_failures"], -r["logical_messages"], r["domain"]))
    out[OTHER] = c
    return out


def _census_fields_match(cs):
    """True when a census document carries both lists with every field the
    report, the delta and the markdown read (CENSUS_FIELDS)."""
    if not isinstance(cs, dict):
        return False
    for key, fields in CENSUS_FIELDS.items():
        rows = cs.get(key)
        if not isinstance(rows, list) or not all(isinstance(r, dict) and set(fields) <= set(r) for r in rows):
            return False
    return True


def maillog_census(maillog_doc):
    """Sender census over the verdicts: dedupe.census, the one implementation
    behind dedupe.py --json and this report, plus the note the report adds.
    An older dedupe.py without census(), or one whose fields differ, yields
    empty lists and CENSUS_UNAVAILABLE as the note - never a second census
    computed here."""
    fn = getattr(dedupe, "census", None)
    cs = fn(maillog_doc.get("verdicts") or []) if callable(fn) else None
    if not _census_fields_match(cs):
        return {"by_envelope": [], "by_sender": [], "note": CENSUS_UNAVAILABLE}
    return {"by_envelope": cs["by_envelope"], "by_sender": cs["by_sender"], "note": CENSUS_NOTE}

# source tags a human put a domain on the list with, and the headline label each earns
TYPED_LABELS = (("cli", "first on the command line"), ("file", "first in --file"), ("settings", "first in audit.toml"))


def _typed_label(tags):
    return next((label for tag, label in TYPED_LABELS if tag in (tags or ())), TYPED_LABELS[0][1])


def headline_domain(domains, domain_sources=None, headline=None, volume=None,
                    volume_label="most mail in this run", own_volume=None):
    """The domain the overall verdict line names, and why. Domains a human
    named win: an explicit headline (labelled by its own source tag), the
    first command-line domain, the first --file domain; with no source tags
    at all, the first domain given. Discovered domains (tenant, mail flow,
    reports) carry no order a human chose, so for them volume decides:
    volume (per org domain, or per domain rolled up to its org domain)
    picks the busiest family with an audited member - an exact tie goes to
    the family holding the tenant default domain - and own_volume, each
    audited domain's own mail (mail_volume), picks inside it: the audited
    apex when it carries mail of its own or no member does, else the member
    carrying the most. With no volume: the tenant's default domain (the
    "default" source tag), else the shortest audited apex, else the shortest
    audited domain - never whichever happens to sort first. (domain, why)."""
    names = [n for n in dict.fromkeys(_norm_name(d) for d in domains) if n]
    if not names:
        return None, None
    srcs = {_norm_name(d): tags for d, tags in (domain_sources or {}).items()}
    want = _norm_name(headline)
    if want and want in names:
        tags = srcs.get(want) or ()
        return want, _typed_label(tags)
    if not domain_sources:
        return names[0], "first domain given"
    for tag, label in TYPED_LABELS:
        tagged = [d for d in names if tag in (srcs.get(d) or ())]
        if tagged:
            return tagged[0], label
    defaults = [d for d in names if "default" in (srcs.get(d) or ())]
    family = {}
    for d, n in (volume or {}).items():
        d = _norm_name(d)
        if d and n and n > 0:
            org = discover.org_domain(d)
            family[org] = family.get(org, 0) + n
    if family:
        members = {}
        for d in names:
            members.setdefault(discover.org_domain(d), []).append(d)
        ranked = [o for o in family if o in members]
        if ranked:
            default_orgs = {discover.org_domain(d) for d in defaults}
            best = max(ranked, key=lambda o: (family[o], o in default_orgs, -names.index(members[o][0])))
            audited = members[best]
            own = {}
            for d, n in (own_volume or {}).items():
                d = _norm_name(d)
                if d in audited and n and n > 0:
                    own[d] = own.get(d, 0) + n
            busy = [d for d in audited if own.get(d, 0) > 0]
            if best in audited and (own.get(best, 0) > 0 or not busy):
                return best, volume_label
            pool = busy or audited
            return max(pool, key=lambda d: (own.get(d, 0), d in defaults, -len(d), -names.index(d))), volume_label
    if defaults:
        return defaults[0], "tenant default domain"
    apex = [d for d in names if discover.org_domain(d) == d]
    if apex:
        return min(apex, key=lambda d: (len(d), names.index(d))), "shortest audited apex"
    return min(names, key=lambda d: (len(d), names.index(d))), "shortest audited domain"


def mail_volume(by_domain, rua_doc, names, maillog_doc=None):
    """Mail each domain itself sent, the headline signal when collect.py's
    internal-mail totals are not available: the mail log's logical messages
    that passed authentication or stayed inside the tenant (when the log
    carries verdicts; else logical messages minus genuine failures), for each
    audited domain plus its unaudited subdomains - unless the log was scoped
    to one --sender-domain, which
    cannot rank the rest; else the aggregate reports' passing counts per
    header-from domain. Spoofed mail fails, so it does not count. Returns
    (volume, label), or ({}, None) when neither source carries passing mail."""
    vol = {}
    scoped = bool(maillog_doc and maillog_doc.get("sender_domain"))
    verdicts_known = bool(maillog_doc and maillog_doc.get("auth_column"))
    if by_domain and not scoped:
        for d in names:
            c = by_domain.get(d) or {}
            sub = c.get("subdomains_total") or {}
            for part in (c, sub):
                if verdicts_known and part.get("passing_messages") is not None:
                    # passed, or never left the tenant: a spoof of an unprotected domain is neither
                    ok = (part.get("passing_messages") or 0) + (part.get("internal_messages") or 0)
                else:
                    ok = (part.get("logical_messages") or 0) - (part.get("genuine_failures") or 0)
                if ok > 0:
                    vol[d] = vol.get(d, 0) + ok
        if vol:
            return vol, "most passing or internal mail in the mail log"
    audited = set(names)
    for h in ((rua_doc or {}).get("by_header_from") or []):
        dom = _norm_name(h.get("domain"))
        ok = h.get("pass")
        if ok is None:
            ok = (h.get("count") or 0) - (h.get("fail") or 0)
        if dom and ok and ok > 0:
            home, _ = _home_domain(dom, audited)  # an unaudited subdomain counts for its closest audited parent
            key = home or dom
            vol[key] = vol.get(key, 0) + ok
    return (vol, "most passing mail in the reports") if vol else ({}, None)


def run_headers(files, authserv_id=None, strict=False):
    """headers.analyze per file; directories are recursed for .txt/.eml.
    DNS selector verification stays off: it is a live lookup, and
    headers.py --verify-dns is the tool for it."""
    paths = []
    for f in files:
        path = repo_path(f)
        if path.is_dir():
            paths += sorted(p for p in path.rglob("*") if p.suffix.lower() in (".txt", ".eml"))
        else:
            paths.append(path)
    if not paths:
        raise UsageError("no header files (.txt, .eml) found under: " + ", ".join(files))
    results = []
    for path in paths:
        try:
            msg = headers_mod.read_headers(path)
        except OSError as exc:
            raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from exc
        if not msg.keys():
            raise UsageError(f"{path}: no headers found (expected a raw header block or a .eml file)")
        results.append(headers_mod.analyze(msg, authserv_id=authserv_id, strict=strict,
                                           file=str(path)))
    return {"messages": results,
            "findings": [dict(f, file=r["file"]) for r in results for f in r["findings"]],
            "ar_note": None if authserv_id else
            "no authserv-id given; each message's topmost Authentication-Results was trusted unverified"}


def _norm_finding(f, area, section):
    """A script finding in the shared shape, with defaults for anything an export left out."""
    sev = str(f.get("severity") or "").strip().lower()
    out = {"id": str(f.get("id") or f"{section.upper()}-000").strip(),
           "severity": sev if sev in SEVERITY_RANK else "info",
           "area": str(f.get("area") or area),
           "title": str(f.get("title") or "(untitled finding)"),
           "evidence": "" if f.get("evidence") is None else str(f["evidence"]),
           "action": str(f.get("action") or "see the script's own output for the recommended action"),
           "verified": bool(f.get("verified", True))}
    if f.get("object"):
        out["object"] = str(f["object"])
    if sev and sev not in SEVERITY_RANK:
        out["evidence"] = (out["evidence"] + f" (severity '{sev}' not recognised, shown as info)").strip()
    return out


def _issue_findings(rows, area, section, label_key):
    """Fallback for an export without a findings list: one finding per issue
    code in the rows' Issues column (the code before the colon is the id)."""
    script = TENANT_SECTIONS[section][0]
    out = []
    for row in rows:
        for issue in [i.strip() for i in str(row.get("Issues") or "").split("|") if i.strip()]:
            code = issue.split(":", 1)[0].strip()
            out.append({"id": code, "severity": "minor", "area": area,
                        "title": f"{code}: {row.get(label_key) or '?'}", "evidence": issue,
                        "action": f"re-export with the current {script} -Json for the recommended action",
                        "verified": True})
    return out


def run_tenant_export(path, section):
    """One PowerShell -Json export (audit_rules, audit_bypasses or audit_groups)
    as a report section: the script's findings in the shared shape, its
    tables, counts and skipped sections. UsageError on input problems."""
    if section not in TENANT_SECTIONS:
        raise UsageError(f"unknown tenant section: {section}")
    script, tag, area, _title = TENANT_SECTIONS[section]
    doc, p = read_json_export(path, f"--{section}-json")
    tool = doc.get("tool")
    if tool and tool != tag:
        raise UsageError(f"--{section}-json {p} was written by {tool}, expected {script} -Json")
    tables = {k: [r for r in _as_list(doc.get(k)) if isinstance(r, dict)] for k in TENANT_TABLES[section]}
    findings = [_norm_finding(f, area, section) for f in _as_list(doc.get("findings")) if isinstance(f, dict)]
    if "findings" not in doc:
        for table, label in TENANT_ISSUE_ROWS[section]:
            findings += _issue_findings(tables.get(table, []), area, section, label)
    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    return {"source": str(p), "tool": tool or tag, "section": section,
            "counts": doc.get("counts") if isinstance(doc.get("counts"), dict) else {},
            "window": doc.get("window"), "options": doc.get("options"),
            "tables": tables,
            "skipped": [str(s) for s in _as_list(doc.get("skipped"))],
            "findings": findings,
            "summary": {"findings": len(findings),
                        "actionable": sum(1 for f in findings if f["severity"] in ("major", "blocking")),
                        "worst": worst_severity(findings),
                        "script_summary": doc.get("summary")},
            "exit_code": exit_code(findings)}


# ------------------------------------------------------------------ gate

def current_policy(dns_reports, rua_doc):
    """Legacy single answer: (policy, where_from) for the first domain that has
    one. The gate is per domain now; see domain_policy."""
    for d, r in (dns_reports or {}).items():
        if r.get("effective_policy"):
            return r["effective_policy"], f"live DNS ({r['dmarc_source']})"
    info = domain_policy(None, None, rua_doc)
    return info["policy"], info["source"]


def domain_policy(domain, dns_reports=None, rua_doc=None):
    """Where one domain's policy comes from. DNS first: it is live. Aggregate
    reports lag 24 to 48 hours, so they are the fallback, not the source of
    truth. domain None means 'whatever the reports cover'."""
    none = {"policy": None, "source": None, "tags": {}, "record_at": None,
            "spf_terminator": None, "spf_status": None}
    r = (dns_reports or {}).get(domain) if domain else None
    if r and r.get("effective_policy"):
        tags = dns_audit.parse_dmarc(r["dmarc"]) if r.get("dmarc") else {}
        return {"policy": r["effective_policy"], "source": f"live DNS ({r['dmarc_source']})",
                "tags": tags, "record_at": r["dmarc_source"],
                "spf_terminator": r.get("spf_terminator"), "spf_status": r.get("spf_status")}
    if not rua_doc:
        return none
    seen = rua_doc["policy_check"]["seen"]
    for exact in (True, False):
        for s in seen:
            if domain is None:
                hit, policy = True, s["p"]
            elif exact:
                hit, policy = _norm_name(s["domain"]) == domain, s["p"]
            else:  # a subdomain of a reported domain: the org record's sp= (else p=) governs it
                hit, policy = _under(domain, _norm_name(s["domain"])), (s.get("sp") or s["p"])
            if not hit:
                continue
            tags = {"p": (s["p"] or "none").lower()}
            if s.get("sp"):
                tags["sp"] = s["sp"]
            if s.get("pct"):
                tags["pct"] = str(s["pct"])
            return {"policy": (policy or "none").lower(),
                    "source": f"aggregate reports ({s['domain']}, {s['reports']} report(s))",
                    "tags": tags, "record_at": f"_dmarc.{s['domain']}",
                    "spf_terminator": None, "spf_status": None}
    return none


def next_step(policy, tags=None, spf_terminator=None, spf_status=None, record_at=None):
    """The concrete policy step this gate decides on (see the module docstring)."""
    tags = tags or {}
    where = f" on the record at {record_at}" if record_at else ""
    if policy is None:
        return "unknown - no DMARC policy determined"
    pct = str(tags.get("pct", "100")).strip()
    pct_n = int(pct) if pct.isdigit() else 100
    if policy == "none":
        return "move to p=quarantine at a low pct (for example pct=10)" + where
    if policy == "quarantine":
        if pct_n < 100:
            return f"raise pct from {pct_n} toward 100 while at p=quarantine" + where
        return "move from p=quarantine to p=reject" + where
    if policy == "reject":
        if pct_n < 100:
            return f"raise pct from {pct_n} to 100 at p=reject" + where
        if "sp" not in tags:
            return "add an explicit subdomain policy (sp=reject)" + where
        if spf_status == "error":
            return "none for DMARC - already at the end; SPF could not be verified (lookup failed), re-check it"
        if spf_status == "absent":
            return "publish an SPF record ending in -all (the DMARC policy is already at the end)"
        if spf_terminator is None:
            return "none - already at the end (SPF terminator not checked in this run)"
        if spf_terminator.lower().startswith("redirect="):
            return "none - already at the end (SPF ends in a redirect; confirm the target ends in -all)"
        if spf_terminator.lower() != "-all":
            return f"harden SPF from {spf_terminator} to -all (the DMARC policy is already at the end)"
        return "none - already at the end"
    return f"unknown - unrecognised policy p={policy}"


def evidence_summary(rua_doc, maillog_doc, headers_doc=None):
    """What failure evidence this run had. Counted, not assumed: a DNS-only
    run has none, and says so in every gate branch. Also where aligned-DKIM
    evidence came from, if anywhere: the move to p=reject needs some."""
    rua_n = rua_doc["totals"]["reports"] if rua_doc else 0
    rua_m = rua_doc["totals"]["messages"] if rua_doc else 0
    raw = maillog_doc["counters"]["raw_rows"] if maillog_doc else 0
    rows = maillog_doc["counters"]["rows_in_scope"] if maillog_doc else 0
    hdr = len(headers_doc["messages"]) if headers_doc else 0
    supplied = bool(rua_n and rua_m) or bool(rows)
    align = (maillog_doc or {}).get("alignment") or {}
    dkim_sources = []
    if rua_n and rua_m:
        dkim_sources.append("aggregate reports (aligned DKIM per source)")
    if align.get("available"):
        dkim_sources.append("mail log SPF/DKIM columns (dkim_alignment buckets)")
    if supplied:
        stmt = (f"failure evidence supplied: {rua_n} aggregate report(s) ({rua_m} messages), "
                f"{rows} mail-log row(s) in scope of {raw} read, {hdr} header file(s)")
    else:
        stmt = (f"no failure evidence supplied ({rua_n} aggregate reports, {rows} mail-log rows, "
                f"{hdr} header files): this is a posture check, not a completed audit - "
                "pass --rua reports and/or --maillog")
    stmt += "; aligned-DKIM evidence: " + (", ".join(dkim_sources) if dkim_sources else "none in this run")
    return {"rua_reports": rua_n, "rua_messages": rua_m, "maillog_rows": raw,
            "maillog_rows_in_scope": rows, "header_files": hdr,
            "failure_evidence": supplied, "dkim_evidence": bool(dkim_sources),
            "dkim_evidence_sources": dkim_sources, "statement": stmt}


def _shared_blockers(rua_doc, maillog_doc, tenant_docs=None, exceptions=None):
    """Blockers that apply to every domain in the run, plus what the formal
    exceptions (audit.toml [[exceptions]], already split to the active ones)
    lifted: notes naming each excepted sender, the excepted rua source IPs,
    and how many deduplicated mail-log failures were excepted. maillog_doc
    counts here only on the no-domain path: with named domains the mail log
    is attributed per sender domain (_maillog_blockers, _excepted_by_domain),
    so no gate inherits another's rows."""
    blockers, notes, excepted_streams = [], [], []
    active = list(exceptions or [])
    if rua_doc:
        for f in rua_doc["failing_streams"]:
            hit = next((e for e in active if config_mod.matches_stream(e, f)), None)
            if hit:
                excepted_streams.append(f["source_ip"])
                notes.append(f"{f['source_ip']} ({f['count']} msgs, {f['likely']}) excepted until {hit['until']}: "
                             f"{hit['reason']}; remove when {hit['removal_criterion']}")
                continue
            if f["likely"] == "likely_spoof":
                if f["dispositions"].get("none", 0):
                    blockers.append(
                        f"spoof stream {f['source_ip']} ({f['count']} msgs) saw disposition none - "
                        "receivers delivered it; the current policy is not catching it")
                # a spoof already rejected is what enforcement looks like; not a blocker
            else:
                blockers.append(
                    f"{f['source_ip']} fails DMARC on {f['fail']}/{f['count']} msgs "
                    f"({f['likely']}); fix, or formally except it, before p= moves")
    excepted_failures = 0
    if maillog_doc:
        c = maillog_doc["counters"]
        if active and maillog_doc.get("verdicts"):
            hits = {}
            for v in maillog_doc["verdicts"]:
                if not v.get("genuine_failure"):
                    continue
                hit = next((e for e in active if config_mod.matches_verdict(e, v)), None)
                if hit:
                    hits.setdefault(hit["match"], [hit, 0])[1] += 1
            for match, (hit, n) in hits.items():
                excepted_failures += n
                notes.append(f"{n} mail-log failure(s) from {match} excepted until {hit['until']}: "
                             f"{hit['reason']}; remove when {hit['removal_criterion']}")
        remaining = c["genuine_failures"] - excepted_failures
        if remaining > 0:
            tail = f"; {excepted_failures} more excepted" if excepted_failures else ""
            blockers.append(f"{remaining} logical message(s) in the mail log failed with "
                            f"no passing copy (deduplicated{tail})")
        if c["delivered_despite_fail"]:
            blockers.append(f"{c['delivered_despite_fail']} message(s) failed authentication but reached "
                            "a mailbox - a local override is masking failures external receivers enforce")
    for name, doc in (tenant_docs or {}).items():
        for f in (doc or {}).get("findings", []):
            if f["severity"] == "blocking" or (f["severity"] == "major" and f["id"] in TENANT_GATE_BLOCKS):
                blockers.append(f"{name}: {f['title']} - unauthenticated mail is delivered past the policy")
    return blockers, {"notes": notes, "excepted_streams": excepted_streams,
                      "excepted_maillog_failures": excepted_failures}


def _excepted_by_domain(maillog_doc, active, names):
    """The deduplicated mail-log failures the active exceptions cover, per
    audited domain (its own rows, as maillog_by_domain attributes them: a
    dict of total, by_likely and senders), the notes naming each excepted
    sender, and the total excepted."""
    counts, hits, total = {}, {}, 0
    if not (active and maillog_doc and maillog_doc.get("verdicts")):
        return counts, [], total
    for v in maillog_doc["verdicts"]:
        if not v.get("genuine_failure"):
            continue
        hit = next((e for e in active if config_mod.matches_verdict(e, v)), None)
        if not hit:
            continue
        total += 1
        home, is_sub = _home_domain(_norm_name(v.get("domain")), names)
        if home and not is_sub:
            d = counts.setdefault(home, {"total": 0, "by_likely": {}, "senders": {}})
            d["total"] += 1
            label = v.get("likely") or "unknown"
            d["by_likely"][label] = d["by_likely"].get(label, 0) + 1
            sender = (v.get("sender") or "?").lower()
            d["senders"][sender] = d["senders"].get(sender, 0) + 1
        hits.setdefault(hit["match"], [hit, 0])[1] += 1
    notes = [f"{n} mail-log failure(s) from {match} excepted until {hit['until']}: {hit['reason']}; "
             f"remove when {hit['removal_criterion']}" for match, (hit, n) in hits.items()]
    return counts, notes, total


def _dns_blockers(r, domain):
    return [f"{domain}: {f['title']}" for f in r["findings"]
            if f["severity"] == "blocking" or f["id"] in DNS_GATE_BLOCKS]


def _maillog_blockers(domain, c, excepted=None):
    """One domain's mail-log blockers, from its own counters only; excepted
    (total, by_likely, senders) is what a formal exception covers of them,
    and the top senders named are the ones still failing."""
    out = []
    exc = excepted or {}
    n_exc = exc.get("total", 0)
    remaining = c["genuine_failures"] - n_exc
    if remaining > 0:
        gone = exc.get("senders") or {}
        left = [(t["sender"], t["genuine_failures"] - gone.get(str(t["sender"]).lower(), 0))
                for t in (c.get("top_senders") or [])]
        tops = ", ".join(f"{s} x{n}" for s, n in [x for x in left if x[1] > 0][:3])
        tail = f"; {n_exc} more excepted" if n_exc else ""
        out.append(f"{domain}: {remaining} logical message(s) from this domain failed with "
                   f"no passing copy (deduplicated{tail})" + (f"; top senders: {tops}" if tops else ""))
    if c["delivered_despite_fail"]:
        out.append(f"{domain}: {c['delivered_despite_fail']} message(s) from this domain failed authentication "
                   "but reached a mailbox - a local override is masking failures external receivers enforce")
    return out


def _maillog_notes(domain, c, scope=None):
    """Non-blocking mail-log facts about one domain: no rows at all, and
    rows from its unaudited subdomains (counted separately, never inherited)."""
    out = []
    if not c["logical_messages"]:
        line = f"{domain}: no mail-log rows for this domain in the window"
        if scope and not _under(domain, scope):
            line += f" (the mail log was restricted to --sender-domain {scope})"
        out.append(line)
    st = c.get("subdomains_total") or {}
    if st.get("logical_messages"):
        subs = st.get("domains") or []
        shown = ", ".join(subs[:5]) + (f" (+{len(subs) - 5} more)" if len(subs) > 5 else "")
        out.append(f"{domain}: unaudited subdomain(s) {shown} carry {st['logical_messages']} logical "
                   f"message(s), {st['genuine_failures']} genuine failure(s) - counted separately under "
                   "this record's sp=, not gated here; add them to the domain list to gate them")
    return out


def _rua_covers(rua_doc, domain):
    """True when the aggregate reports carry evidence about this domain: a
    policy record seen for it (policy_check.seen), rows with it as the header
    From (by_header_from), or a failing or SPF-only stream sending as it.
    Reports about other domains say nothing about this one."""
    if not rua_doc or not domain:
        return False
    seen = (rua_doc.get("policy_check") or {}).get("seen") or []
    froms = rua_doc.get("by_header_from") or []
    names = {_norm_name(s.get("domain")) for s in seen if isinstance(s, dict)}
    names |= {_norm_name(f.get("domain")) for f in froms if isinstance(f, dict)}
    for s in list(rua_doc.get("failing_streams") or []) + list(rua_doc.get("spf_only_senders") or []):
        if isinstance(s, dict):
            names |= {_norm_name(h) for h in (s.get("header_from") or [])}
    return domain in names


def _domain_gate(domain, info, shared, dns_blockers, rua_doc, evidence, maillog=None, scope=None,
                 ml_spf_only=(), exception_notes=(), excepted=None):
    """One domain's verdict. Every branch names the step being gated and
    whether failure evidence was supplied. maillog: this domain's own
    counters from maillog_by_domain (None when no mail log was supplied);
    excepted: what a formal exception covers of its genuine failures (total,
    by_likely, senders); ml_spf_only: the mail-log senders attributed to this
    domain (its own rows and its unaudited subdomains', like the counters)
    that pass on SPF alone. The move to p=reject additionally needs
    aligned-DKIM evidence from somewhere (DKIM before reject, always)."""
    policy, policy_from = info["policy"], info["source"]
    blockers = list(dns_blockers) + list(shared)
    notes = []
    if maillog is not None and domain:
        blockers += _maillog_blockers(domain, maillog, excepted)
        notes = _maillog_notes(domain, maillog, scope)
    own_rows = maillog["logical_messages"] if maillog is not None and domain else 0
    no_rows = bool(domain) and not own_rows and not _rua_covers(rua_doc, domain)
    if policy == "quarantine":
        if rua_doc:
            spf_only = [f for f in rua_doc["spf_only_senders"]
                        if domain is None or any(_under(hf, domain) for hf in f["header_from"])]
            if spf_only:
                msgs = sum(f["spf_only"] for f in spf_only)
                blockers.append(f"{len(spf_only)} sender(s) pass on SPF alone ({msgs} msgs): "
                                "set up aligned DKIM before moving quarantine -> reject")
        if ml_spf_only:
            msgs = sum(s["spf_only"] for s in ml_spf_only)
            blockers.append(f"{len(ml_spf_only)} sender(s) in the mail log pass on SPF alone ({msgs} msgs, no DKIM "
                            "pass on any leg): set up aligned DKIM before moving quarantine -> reject")
    step = next_step(policy, info["tags"], info["spf_terminator"], info["spf_status"], info["record_at"])
    at_end = policy == "reject"
    pct = str((info["tags"] or {}).get("pct", "100")).strip()
    reject_step = policy == "quarantine" and (int(pct) if pct.isdigit() else 100) >= 100
    name = domain or "the domain"
    if blockers:
        verdict = "no_go"
        reasons = list(blockers)
        if at_end:
            reasons.append(f"policy is already p=reject ({policy_from}); nothing to ratchet - the items "
                           f"above are gaps enforcement does not close by itself; next step: {step}")
        elif policy:
            reasons.append(f"step being gated: {step}")
        else:
            reasons.append(f"no DMARC policy could be determined for {name}; the blockers above stand regardless")
    elif policy is None:
        verdict = "insufficient_data"
        reasons = [f"no DMARC policy could be determined for {name} - run without --offline so live "
                   "DNS is checked, or supply rua reports that cover it"]
    elif not evidence["failure_evidence"]:
        verdict = "insufficient_data"
        if at_end:
            reasons = [f"policy is already p=reject ({policy_from}); nothing to ratchet - supply --rua "
                       "reports and/or --maillog to confirm enforcement is not rejecting your own mail; "
                       f"next step: {step}"]
        else:
            reasons = [f"policy is p={policy} ({policy_from}) but no failure evidence was supplied: "
                       "pass --rua reports and/or --maillog; a ratchet on zero data is a guess; "
                       f"step being gated: {step}"]
    elif no_rows:
        # the run has evidence, but none of it is about this domain: no mail-log
        # rows of its own, no aggregate-report rows with it as the From domain
        verdict = "insufficient_data"
        if at_end:
            reasons = [f"policy is already p=reject ({policy_from}); nothing to ratchet - the evidence "
                       f"supplied has no rows for {name} (none in the mail log, none in the aggregate "
                       f"reports), so enforcement cannot be confirmed safe for it; next step: {step}"]
        else:
            reasons = [f"policy is p={policy} ({policy_from}) but the evidence supplied has no rows for "
                       f"{name} (none in the mail log, none in the aggregate reports): a zero count is "
                       f"not evidence of health - supply a mail log or aggregate reports that cover it; "
                       f"step being gated: {step}"]
    elif reject_step and not evidence.get("dkim_evidence"):
        verdict = "insufficient_data"
        reasons = [f"policy is p=quarantine at pct=100 ({policy_from}) and the step being gated is the move to "
                   "p=reject, but this run holds no aligned-DKIM evidence: supply --rua reports, or a mail log "
                   "pulled with SPF and DKIM columns (queries/raw_maillog.kql; queries/dkim_alignment.kql gives "
                   "the same buckets in the portal), before that move - DKIM before reject, always"]
    else:
        verdict = "go"
        if at_end:
            reasons = [f"policy is already p=reject ({policy_from}); nothing to ratchet - keep watching "
                       f"the failing streams; next step: {step}"]
            reasons += [f"{s['source_ip']} ({s['count']} msgs, {s['likely']})"
                        for s in (rua_doc["failing_streams"] if rua_doc else [])[:5]]
        else:
            reasons = [f"policy p={policy} ({policy_from}); no unexplained failures in the evidence "
                       f"supplied - next step: {step}"]
            if rua_doc and rua_doc["failing_streams"]:
                spoof = [s for s in rua_doc["failing_streams"] if s["likely"] == "likely_spoof"]
                if spoof:
                    reasons.append(f"{len(spoof)} failing stream(s) look like spoofs - moving p= forward "
                                   "is exactly what stops them")
    reasons += notes
    reasons += [f"exception: {n}" for n in exception_notes]
    reasons.append(evidence["statement"])
    return {"verdict": verdict, "current_policy": policy, "policy_source": policy_from,
            "next_step": step, "reasons": reasons,
            "maillog_rows": maillog["logical_messages"] if maillog is not None else None,
            "excepted_failures": (excepted or {}).get("total", 0),
            "excepted_by_likely": dict((excepted or {}).get("by_likely") or {})}


def _gate_names(dns_reports, rua_doc, domains=()):
    """The domains the gate decides on, in the order they were given, each
    spelled the way every gate key is (_norm_name) so a library caller's
    Mixed.Case or trailing dot keeps its mail-log attribution."""
    names = [n for n in dict.fromkeys(_norm_name(d) for d in domains) if n]
    if not names:
        names = [n for n in dict.fromkeys(_norm_name(d) for d in (dns_reports or {})) if n]
    if not names and rua_doc:
        names = [n for n in dict.fromkeys(_norm_name(s["domain"]) for s in rua_doc["policy_check"]["seen"]) if n]
    return names


def gate_verdict(dns_reports, rua_doc, maillog_doc, domains=(), headers_doc=None, tenant_docs=None,
                 domain_sources=None, headline=None, volume=None, exceptions=None):
    """The ratchet decision, per domain, plus the overall verdict (the worst).
    See the module docstring for the rule. Each domain's mail-log blockers
    come from its own rows (maillog.by_domain). The top-level current_policy,
    policy_source and next_step are the worst-ranked domain's (on a tie the
    headline domain, then the order given); gate.headline carries the
    headline domain's. headline: an optional explicit override; otherwise
    headline_domain picks it: a typed domain first (command line, then
    --file), else the org family carrying the most mail - volume, the
    internal-mail totals per org that collect.py measures, else passing or
    internal mail from the mail log, else passing mail from the reports
    (mail_volume) - else the tenant default domain, else the shortest apex.
    exceptions: the raw or normalised [[exceptions]] entries; expired and
    incomplete ones are named, not applied."""
    evidence = evidence_summary(rua_doc, maillog_doc, headers_doc)
    if dns_reports:  # a library caller's spelling must not lose the DNS blockers
        dns_reports = {_norm_name(d): r for d, r in dns_reports.items()}
    names = _gate_names(dns_reports, rua_doc, domains)
    active, expired, invalid = config_mod.parse_exceptions(exceptions or [])
    shared, exc = _shared_blockers(rua_doc, None if names else maillog_doc, tenant_docs, active)
    notes = list(exc["notes"])
    excepted = {}
    if names:
        excepted, ml_notes, total = _excepted_by_domain(maillog_doc, active, names)
        notes += ml_notes
        exc["excepted_maillog_failures"] = total
    notes += [f"{e['match']} expired {e['until']} and blocks again until renewed or removed ({e['reason']})"
              for e in expired]
    notes += [f"{e['entry']} not applied: {e['problem']}" for e in invalid]
    # SPF-only senders are attributed like the rows: an audited subdomain's reach its own gate only,
    # an unaudited subdomain's reach its closest audited parent
    ml_spf = {}
    for s in (maillog_doc or {}).get("spf_only_senders") or []:
        home = _home_domain(_norm_name(s.get("domain")), names)[0] if names else None
        ml_spf.setdefault(home, []).append(s)
    by_domain, scope = None, None
    if maillog_doc and names:
        by_domain = maillog_doc.get("by_domain")
        if not by_domain or any(d not in by_domain for d in names):
            by_domain = maillog_by_domain(maillog_doc, names)
        scope = _norm_name(maillog_doc.get("sender_domain")) or None
    per_domain = {}
    for d in names:
        info = domain_policy(d, dns_reports, rua_doc)
        dns_b = _dns_blockers(dns_reports[d], d) if dns_reports and d in dns_reports else []
        per_domain[d] = _domain_gate(d, info, shared, dns_b, rua_doc, evidence,
                                     by_domain.get(d) if by_domain else None, scope,
                                     ml_spf.get(d, []), notes, excepted.get(d))
    head_sources = domain_sources
    if not domains and not domain_sources and names:
        head_sources = {d: ["reports"] for d in names}  # nothing was named: every name came from the files
    own, own_label = mail_volume(by_domain, rua_doc, names, maillog_doc)
    if volume and any(v and v > 0 for v in volume.values()):
        vol, vlabel = volume, "most internal mail"
    else:
        vol, vlabel = own, own_label
    head_name, why = headline_domain(names, head_sources, headline, vol, vlabel or "most mail in this run", own)
    worst, head = None, None
    if per_domain:
        ranked = [head_name] + [d for d in per_domain if d != head_name]  # a tie goes to the headline
        worst = max(ranked, key=lambda d: GATE_RANK[per_domain[d]["verdict"]])
        top, head, verdict = per_domain[worst], per_domain[head_name], per_domain[worst]["verdict"]
        n = len(per_domain)
        if n == 1:
            overall = "1 domain audited"
            lead = f"overall: {overall}; {head_name} ({why}): {verdict}"
        else:
            overall = f"worst of {n} domains"
            if head_name == worst:
                lead = f"overall: {overall}; headline domain {head_name} ({why}) is the worst: {verdict}"
            else:
                lead = (f"overall: {overall}; worst is {worst} ({verdict}); headline domain {head_name} "
                        f"({why}) is {head['verdict']}")
        merged = {lead: None}
        for d, g in per_domain.items():
            for r in g["reasons"]:
                if (r == evidence["statement"] or r in shared or len(per_domain) == 1 or r.startswith(f"{d}: ")
                        or r.startswith("exception: ")):
                    merged.setdefault(r, None)
                else:
                    merged.setdefault(f"{d}: {r}", None)
        merged.pop(evidence["statement"], None)
        reasons = list(merged) + [evidence["statement"]]
    else:
        top = _domain_gate(None, domain_policy(None, dns_reports, rua_doc), shared, [], rua_doc, evidence,
                           None, None, (maillog_doc or {}).get("spf_only_senders") or [], notes)
        verdict, overall = top["verdict"], "no domain named - one verdict over the files given"
        reasons = top["reasons"]
    return {"verdict": verdict, "current_policy": top["current_policy"],
            "policy_source": top["policy_source"], "next_step": top["next_step"],
            "reasons": reasons,
            "policies": {d: g["current_policy"] for d, g in per_domain.items()},
            "domains": per_domain,
            "evidence": evidence,
            "exceptions": {"applied": active, "expired": expired, "invalid": invalid,
                           "excepted_streams": exc["excepted_streams"],
                           "excepted_maillog_failures": exc["excepted_maillog_failures"]},
            "rule": GATE_RULE,
            "overall": overall, "domain_count": len(per_domain),
            "headline": ({"domain": head_name, "source_label": why, "verdict": head["verdict"],
                          "current_policy": head["current_policy"], "policy_source": head["policy_source"],
                          "next_step": head["next_step"]} if head else None),
            "headline_domain": head_name, "headline_source": why, "worst_domain": worst}


# ------------------------------------------------------------------ report

def flatten_findings(report):
    """One severity-ordered list across all sections, each carrying its source."""
    out = []
    for d, r in (report["dns"] or {}).items():
        out += [dict(f, source=f"dns:{d}") for f in r["findings"]]
    if report["rua"]:
        out += [dict(f, source="rua") for f in report["rua"]["findings"]]
    if report["maillog"]:
        out += [dict(f, source="maillog") for f in report["maillog"]["findings"]]
    if report["headers"]:
        out += [dict(f, source=f"headers:{m['file']}") for m in report["headers"]["messages"]
                for f in m["findings"]]
    for name in TENANT_SECTIONS:
        if report.get(name):
            out += [dict(f, source=name) for f in report[name]["findings"]]
    return sorted(out, key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))


def reword_for_reject(findings, gate):
    """At p=reject a finding cannot ask for work 'before ratcheting to
    p=reject'; say what is true for that domain instead. In place."""
    policies = gate.get("policies") or {}
    known = [p for p in policies.values() if p]
    all_reject = (all(p == "reject" for p in known) if known
                  else gate.get("current_policy") == "reject")
    for f in findings:
        src = f.get("source", "")
        at_end = policies.get(_norm_name(src[4:])) == "reject" if src.startswith("dns:") else all_reject
        if at_end and RATCHET_PHRASE in (f.get("action") or ""):
            f["action"] = f["action"].replace(RATCHET_PHRASE, RATCHET_AT_END)
            f["note"] = "reworded: the policy is already p=reject, so there is no ratchet to wait for"
    return findings


def verified_vs_inferred(report):
    """The split AGENTS.md rule 11 asks for in every summary: what was measured
    (live DNS, parsed reports, parsed headers, dedupe counts) against what was
    inferred (heuristic labels, gate reasoning, unverified findings)."""
    verified, inferred = [], []
    dns_reports = report["dns"] or {}
    if dns_reports:
        ok = [d for d, r in dns_reports.items()
              if "error" not in (r.get("spf_status"), r.get("dmarc_status"), r.get("mx_status"))]
        failed = [d for d in dns_reports if d not in ok]
        if ok:
            verified.append(f"live DNS answers for {', '.join(ok)} (SPF, DMARC, DKIM selector probes, MX)")
        if failed:
            inferred.append(f"DNS lookups failed for {', '.join(failed)}: absence there is not verified")
    if report["rua"]:
        t = report["rua"]["totals"]
        verified.append(f"{t['reports']} aggregate report(s) parsed: {t['messages']} messages, "
                        f"{t['pass']} pass / {t['fail']} fail, from {len(t['reporters'])} reporter(s)")
    if report["maillog"]:
        c = report["maillog"]["counters"]
        verified.append(f"mail log: {c['raw_rows']} rows deduplicated to {c['logical_messages']} logical "
                        f"messages, {c['genuine_failures']} genuine failures, "
                        f"{c['delivered_despite_fail']} delivered despite fail")
        bd = report["maillog"].get("by_domain") or {}
        if bd:
            named = [d for d in bd if d != OTHER]
            with_rows = [d for d in named if bd[d]["logical_messages"]]
            verified.append(f"mail log attributed per sender domain (maillog.by_domain): {len(with_rows)} of "
                            f"{len(named)} audited domain(s) have rows, "
                            f"{(bd.get(OTHER) or {}).get('logical_messages', 0)} message(s) under {OTHER}")
    if report["headers"]:
        verified.append(f"{len(report['headers']['messages'])} message header file(s) parsed")
        if report["headers"]["ar_note"]:
            inferred.append("header verdicts: " + report["headers"]["ar_note"])
    for name in TENANT_SECTIONS:
        doc = report.get(name)
        if doc:
            verified.append(f"{name}: {doc['summary']['findings']} finding(s) read from the "
                            f"{doc['tool']} -Json export" + (
                                f"; sections not checked: {', '.join(doc['skipped'])}" if doc["skipped"] else ""))
    if (report["rua"] and report["rua"]["failing_streams"]) or \
            (report["maillog"] and report["maillog"]["counters"]["genuine_failures"]):
        inferred.append("likely labels (likely_spoof, likely_misconfigured_sender, unknown) are heuristics, "
                        "not verdicts")
    g = report["gate"]
    inferred.append(f"gate verdict {g['verdict']} and next step ({g['next_step']}) are reasoning over "
                    "the evidence above, not a measurement")
    exc = g.get("exceptions") or {}
    applied = exc.get("applied") or []
    if applied:
        streams, failures = len(exc.get("excepted_streams") or []), exc.get("excepted_maillog_failures") or 0
        if streams or failures:
            inferred.append(f"{len(applied)} active exception(s) from audit.toml: {streams} stream(s) and {failures} "
                            "mail-log failure(s) excepted - a human decision with an expiry and a removal criterion, "
                            "not a measurement")
        else:
            inferred.append(f"{len(applied)} active exception(s) from audit.toml; none matched the evidence in this run")
    seen_v, seen_i = set(), set()
    for f in report["findings"]:
        bucket, seen = (verified, seen_v) if f.get("verified", True) else (inferred, seen_i)
        if f["id"] not in seen:
            seen.add(f["id"])
            bucket.append(f["id"])
    return {"verified": verified, "inferred": inferred,
            "note": "finding ids listed under inferred carry verified=false (heuristic or unconfirmed lookup)"}


def read_previous_report(path):
    """An earlier run's report.json (or the folder holding one) as a dict;
    UsageError otherwise. utf-8-sig: a BOM from a Windows editor is fine."""
    p = repo_path(path)
    if p.is_dir():
        p = p / "report.json"
    try:
        with open(p, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise UsageError(f"cannot read --previous {p}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise UsageError(f"--previous {p} is not UTF-8 text") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"--previous {p} is not JSON ({exc.msg} at line {exc.lineno})") from exc
    if not isinstance(doc, dict) or "gate" not in doc:
        raise UsageError(f"--previous {p} is not an audit.py report.json (no gate section)")
    return doc


def _finding_keys(doc):
    return {((f.get("source") or ""), (f.get("id") or "")): f for f in doc.get("findings") or []}


def _sender_key(s):
    return (s.get("sender"), s.get("domain"), s.get("envelope_domain"))


def build_delta(report, previous):
    """What changed since an earlier report.json: whole-log and per-domain
    counters, findings, policies, gates and census senders. A counter delta
    is None when either side lacks the data; notes say why."""
    notes = []
    now_c = (report.get("maillog") or {}).get("counters") or {}
    prev_c = (previous.get("maillog") or {}).get("counters") or {}

    def diff(key):
        return now_c[key] - prev_c[key] if key in now_c and key in prev_c else None

    if bool(now_c) != bool(prev_c):
        notes.append("a mail log on one side only: counter deltas not computed")
    now_f, prev_f = _finding_keys(report), _finding_keys(previous)

    def brief(f, key):
        return {"id": key[1], "source": key[0], "severity": f.get("severity"), "title": f.get("title")}

    findings_new = sorted((brief(now_f[k], k) for k in now_f if k not in prev_f),
                          key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["source"], f["id"]))
    findings_resolved = sorted((brief(prev_f[k], k) for k in prev_f if k not in now_f),
                               key=lambda f: (f["source"], f["id"]))
    now_g = (report.get("gate") or {}).get("domains") or {}
    prev_g = (previous.get("gate") or {}).get("domains") or {}
    policy_changes, gate_changes = {}, {}
    for d, g in now_g.items():
        p = prev_g.get(d)
        if not p:
            continue
        if p.get("current_policy") != g.get("current_policy"):
            policy_changes[d] = {"from": p.get("current_policy"), "to": g.get("current_policy")}
        if p.get("verdict") != g.get("verdict"):
            gate_changes[d] = {"from": p.get("verdict"), "to": g.get("verdict")}
    now_s = ((report.get("maillog") or {}).get("census") or {}).get("by_sender")
    prev_s = ((previous.get("maillog") or {}).get("census") or {}).get("by_sender")
    new_senders, gone_senders = [], []
    if now_s is None or prev_s is None:
        if now_c or prev_c:
            notes.append("sender census missing on one side (older report, or no mail log): "
                         "new_senders not computed")
    else:
        prev_keys = {_sender_key(s) for s in prev_s}
        now_keys = {_sender_key(s) for s in now_s}
        new_senders = [s for s in now_s if _sender_key(s) not in prev_keys]
        gone_senders = [s for s in prev_s if _sender_key(s) not in now_keys]
    by_domain = {}
    now_bd = (report.get("maillog") or {}).get("by_domain") or {}
    prev_bd = (previous.get("maillog") or {}).get("by_domain") or {}
    for d, c in now_bd.items():
        p = prev_bd.get(d)
        if p:
            by_domain[d] = {k: c.get(k, 0) - p.get(k, 0) for k in ("genuine_failures", "delivered_despite_fail")}
    return {"previous_generated_utc": previous.get("generated_utc"),
            "previous_version": previous.get("version"),
            "genuine_failures": diff("genuine_failures"),
            "delivered_despite_fail": diff("delivered_despite_fail"),
            "findings_new": findings_new, "findings_resolved": findings_resolved,
            "policy_changes": policy_changes, "gate_changes": gate_changes,
            "domains_added": [d for d in now_g if d not in prev_g],
            "domains_removed": [d for d in prev_g if d not in now_g],
            "new_senders": new_senders, "gone_senders": gone_senders,
            "by_domain": by_domain, "notes": notes}


def build_report(domains=(), rua_paths=(), maillog=None, header_files=(), offline=False,
                 resolver_addr="8.8.8.8", selectors=(), known=None, sender_domain=None,
                 auth_column=None, vendor_domains=(), authserv_id=None, strict=False,
                 min_volume=20, fail_threshold=0.5, since=None, until=None,
                 expect_policy=None, retiring=(), columns=None, domain_file=None,
                 rules_json=None, bypasses_json=None, groups_json=None, domain_sources=None,
                 previous_report=None, headline=None, volume=None, exceptions=None):
    """The whole audit as one document. Raises UsageError on input problems.
    previous_report: an earlier run's report.json as a dict; adds report["delta"].
    headline: an optional explicit headline override; without it the headline
    is a typed domain (cli, then --file), else the org family carrying the
    most mail, else the tenant default domain - see headline_domain.
    volume: internal-mail rows per org domain (collect.py's sizing calls),
    the preferred headline signal for discovered domains. exceptions: the
    audit.toml [[exceptions]] entries the gate honours."""
    domains = [part for d in domains for part in str(d).split(",")]
    if domain_file:
        domains += read_domain_file(domain_file)
    domains = list(dict.fromkeys(d.strip().lower().rstrip(".") for d in domains if d.strip()))
    tenant_paths = {"rules": rules_json, "bypasses": bypasses_json, "groups": groups_json}
    if offline and not (rua_paths or maillog or header_files or any(tenant_paths.values())):
        raise UsageError("--offline with no inputs: pass --rua, --maillog, --headers and/or "
                         "--rules-json, --bypasses-json, --groups-json")
    if not offline and not domains:
        raise UsageError("no domains to audit: name them on the command line, pass --file, or put "
                         "app registration credentials in .env so the tenant's list is read "
                         "(docs/app-registration.md); --offline audits the given files only")
    _known_path_check(known)

    dns_reports = None
    if not offline and domains:
        dns_reports = run_dns(domains, make_resolver(resolver_addr), selectors)

    rua_doc = run_rua(rua_paths, known, min_volume, fail_threshold, since, until,
                      expect_policy, retiring) if rua_paths else None
    maillog_doc = run_maillog(maillog, sender_domain, auth_column, vendor_domains, columns) if maillog else None
    headers_doc = run_headers(header_files, authserv_id, strict) if header_files else None
    tenant_docs = {name: (run_tenant_export(path, name) if path else None)
                   for name, path in tenant_paths.items()}
    if maillog_doc:
        # each gate reads its own rows from here; the census is the sender inventory
        maillog_doc["by_domain"] = maillog_by_domain(maillog_doc, _gate_names(dns_reports, rua_doc, domains))
        maillog_doc["census"] = maillog_census(maillog_doc)
    if previous_report is not None and not isinstance(previous_report, dict):
        raise UsageError("previous_report must be an earlier run's report.json document (a dict)")
    headline = _norm_name(headline) or None

    report = {
        "tool": "audit.py", "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "offline": offline,
        "inputs": {"domains": domains, "domain_sources": domain_sources or {}, "headline": headline,
                   "volume": volume or {},
                   "domain_file": str(repo_path(domain_file)) if domain_file else None,
                   "rua": _source_list(rua_paths),
                   "maillog": str(repo_path(maillog)) if maillog else None,
                   "maillog_columns": {k: v for k, v in (columns or {}).items() if v},
                   "headers": _source_list(header_files),
                   "rules": str(repo_path(rules_json)) if rules_json else None,
                   "bypasses": str(repo_path(bypasses_json)) if bypasses_json else None,
                   "groups": str(repo_path(groups_json)) if groups_json else None,
                   "authserv_id": authserv_id, "sender_domain": sender_domain,
                   "known": known, "since": since, "until": until,
                   "expect_policy": expect_policy, "retiring_selectors": list(retiring),
                   "previous": (previous_report.get("generated_utc") or "unknown") if previous_report else None,
                   "exceptions": [str(e.get("match")) for e in (exceptions or []) if isinstance(e, dict)]},
        "dns": dns_reports,
        "rua": rua_doc,
        "maillog": maillog_doc,
        "headers": headers_doc,
    }
    report.update(tenant_docs)
    report["gate"] = gate_verdict(dns_reports, rua_doc, maillog_doc, domains, headers_doc, tenant_docs,
                                  domain_sources, headline, volume, exceptions)
    findings = reword_for_reject(flatten_findings(report), report["gate"])
    report["findings"] = findings
    by_sev, by_area = {}, {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_area[f["area"]] = by_area.get(f["area"], 0) + 1
    code = exit_code(findings)
    report["summary"] = {"findings": len(findings), "by_severity": by_sev, "by_area": by_area,
                         "actionable": sum(1 for f in findings if f["severity"] in ("major", "blocking")),
                         "worst": worst_severity(findings), "exit_code": code,
                         "gate": report["gate"]["verdict"], "next_step": report["gate"]["next_step"]}
    report["verified_vs_inferred"] = verified_vs_inferred(report)
    if previous_report:
        report["delta"] = build_delta(report, previous_report)
    report["exit_code"] = code
    return report


def write_reports(report, out_dir):
    """Writes the two report files, report.json and report.md (plan.py writes the plan)."""
    out = repo_path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jpath, mpath = out / "report.json", out / "report.md"
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
        fh.write("\n")
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(render_md(report))
    return jpath, mpath


# ------------------------------------------------------------------ markdown

def _display_source(source):
    if source.startswith("headers:"):
        return "headers:" + display_path(source[len("headers:"):])
    return source


def _md_findings(findings, limit=None):
    """Findings grouped so one problem seen in several files is one entry."""
    groups = {}
    for f in (findings[:limit] if limit else findings):
        groups.setdefault((f["id"], f["severity"], f["title"], f["action"]), []).append(f)
    lines = []
    for (fid, sev, title, action), items in groups.items():
        verified = "" if all(i.get("verified", True) for i in items) else " (not verified)"
        sources = list(dict.fromkeys(_display_source(i["source"]) for i in items))
        src = sources[0] if len(sources) == 1 else f"{len(sources)} sources: " + ", ".join(sources)
        lines.append(f"- **[{sev}] {fid}** ({src}) {title}{verified}")
        evidence = list(dict.fromkeys(i["evidence"] for i in items))
        if len(evidence) == 1:
            lines.append(f"  - evidence: {evidence[0]}")
        else:
            lines.append("  - evidence:")
            for i in items:
                lines.append(f"    - {_display_source(i['source'])}: {i['evidence']}")
        lines.append(f"  - action: {action}")
        if items[0].get("note"):
            lines.append(f"  - note: {items[0]['note']}")
    return lines or ["- none"]


def _md_rows(L, label, rows, fmt, cap=20):
    if not rows:
        return
    L.append(f"- {label} ({len(rows)}):")
    for r in rows[:cap]:
        L.append(f"  - {fmt(r)}")
    if len(rows) > cap:
        L.append(f"  - (+{len(rows) - cap} more in report.json)")


def _md_tenant(L, name, doc):
    script, _tag, _area, title = TENANT_SECTIONS[name]
    tables = doc["tables"]
    counts = doc.get("counts") or {}
    L.append(f"## {title} ({script} export)")
    L.append("")
    L.append(f"- source: {display_path(doc['source'])}")
    if name == "rules":
        rows = tables.get("rules", [])
        flagged = [r for r in rows if r.get("Issues")]
        L.append(f"- {len(rows)} transport rule(s) inventoried, {len(flagged)} flagged")
        w = doc.get("window") or {}
        if w:
            hits = "checked" if w.get("hits_checked") else "not checked (-SkipHits)"
            L.append(f"- hit-count window: {w.get('days', '?')} days "
                     f"({w.get('start', '?')} .. {w.get('end', '?')}); hit counts {hits}")
        _md_rows(L, "flagged rules", flagged,
                 lambda r: f"{r.get('Name')} [{r.get('State')}, priority {r.get('Priority')}]: {r.get('Issues')}")
    elif name == "bypasses":
        if counts:
            L.append("- counts: " + _plain(counts))
        _md_rows(L, "spoof allows", tables.get("spoof_allows", []),
                 lambda r: f"{r.get('SpoofedUser')} <- {r.get('SendingInfrastructure')} "
                           f"[{r.get('SpoofType')}, {r.get('Action')}]")
        _md_rows(L, "flagged inbound connectors",
                 [r for r in tables.get("inbound_connectors", []) if r.get("Issues")],
                 lambda r: f"{r.get('Name')} [{r.get('ConnectorType')}, enabled={r.get('Enabled')}]: {r.get('Issues')}")
        _md_rows(L, "flagged anti-phishing policies",
                 [r for r in tables.get("antiphish_policies", []) if r.get("Issues")],
                 lambda r: f"{r.get('Policy')}: {r.get('Issues')}")
        _md_rows(L, "anti-spam policies with allow entries",
                 [r for r in tables.get("spam_policies", [])
                  if r.get("AllowedSenders") or r.get("AllowedSenderDomains")],
                 lambda r: f"{r.get('Policy')}: {r.get('AllowedSenders') or 0} sender(s), "
                           f"{r.get('AllowedSenderDomains') or 0} domain(s) allowed by address")
    elif name == "groups":
        if counts:
            L.append("- counts: " + _plain(counts))
        _md_rows(L, "flagged groups", [r for r in tables.get("groups", []) if r.get("Issues")],
                 lambda r: f"{r.get('Name')} <{r.get('Address')}> [{r.get('Kind')}]: {r.get('Issues')}")
        _md_rows(L, "external forwards", [r for r in tables.get("forwards", []) if r.get("External")],
                 lambda r: f"{r.get('Mailbox')} -> {r.get('Target')} ({r.get('Source')}"
                           + (f", rule {r.get('RuleName')}" if r.get("RuleName") else "") + ")")
    if doc.get("skipped"):
        L.append("- sections not checked (query failed or not licensed): " + ", ".join(doc["skipped"]))
    s = doc["summary"]
    L.append(f"- {s['findings']} finding(s) from the export, {s['actionable']} major or blocking")
    L.append("")


def _dkim_line(r):
    if r.get("dkim_wildcard"):
        line = "unknown (wildcard at _domainkey - probing is unreliable, read s= from a live header)"
    elif r["dkim_selectors"]:
        line = ", ".join(r["dkim_selectors"])
    else:
        line = f"none of {len(r.get('dkim_probed') or [])} probed found"
    if r.get("dkim_dangling"):
        line += " (dangling CNAME: " + ", ".join(r["dkim_dangling"]) + ")"
    return line


def _mx_line(r):
    if r.get("mx_status") == "error":
        return "LOOKUP FAILED - not verified"
    if r.get("mx_null"):
        return "null MX (0 .) - the domain declares it receives no mail"
    if not r["mx"]:
        return "none (no MX record)"
    return ", ".join(r["mx"])


def _md_domain_counters(c):
    """One domain's mail-log line, from its own counters."""
    if not c["logical_messages"]:
        return "no mail-log rows for this domain in the window"
    likely = ", ".join(f"{n} {label}" for label, n in c["by_likely"].items() if n) or "none"
    tops = ", ".join(f"{t['sender']} x{t['genuine_failures']}" for t in (c.get("top_senders") or [])[:3])
    return (f"{c['logical_messages']} logical messages, {c['genuine_failures']} genuine failures, "
            f"{c['echo_messages']} echo; delivered despite fail {c['delivered_despite_fail']}, "
            f"blocked despite pass {c['blocked_despite_pass']}; likely split: {likely}"
            + (f"; top failing senders: {tops}" if tops else ""))


def _md_by_domain(L, bd):
    L.append("")
    L.append("Per sender domain (each gate uses only its own rows):")
    L.append("")
    oc = bd.get(OTHER) or {}
    if not any(d != OTHER for d in bd):
        doms = oc.get("sender_domains") or []
        shown = ", ".join(f"{r['domain']} {r['genuine_failures']} failing of {r['logical_messages']}"
                          for r in doms[:8]) + (f" (+{len(doms) - 8} more)" if len(doms) > 8 else "")
        L.append(f"- no domain named: all {oc.get('logical_messages', 0)} logical messages "
                 f"({oc.get('genuine_failures', 0)} genuine failures) counted once under {OTHER}"
                 + (f"; sender domains seen: {shown}" if shown else ""))
        return
    for d, dc in bd.items():
        if d == OTHER:
            continue
        L.append(f"- {d}: {_md_domain_counters(dc)}")
        st = dc.get("subdomains_total") or {}
        if st.get("logical_messages"):
            subs = st.get("domains") or []
            shown = ", ".join(subs[:8]) + (f" (+{len(subs) - 8} more)" if len(subs) > 8 else "")
            L.append(f"  - unaudited subdomains ({shown}): {st['logical_messages']} logical messages, "
                     f"{st['genuine_failures']} genuine failures - counted separately, not gated; "
                     "add them to the domain list to gate them")
    if oc.get("logical_messages"):
        doms = oc.get("sender_domains") or []
        shown = ", ".join(f"{r['domain']} {r['genuine_failures']} failing of {r['logical_messages']}"
                          for r in doms[:8]) + (f" (+{len(doms) - 8} more)" if len(doms) > 8 else "")
        L.append(f"- {OTHER} - sender domains outside the audited list: {oc['logical_messages']} logical "
                 f"messages, {oc['genuine_failures']} genuine failures ({shown}) - reported once, "
                 "attached to no gate")
    else:
        L.append(f"- {OTHER}: no rows from sender domains outside the audited list")


def _md_census(L, cs):
    L.append("## Failing senders (census)")
    L.append("")
    L.append(f"Top {CENSUS_TOP} of each list, worst first; the full census is in report.json "
             f"(maillog.census). Entries under {CENSUS_HEADLINE_MIN} genuine failures are listed "
             "but are notes, not headlines. Likely labels are heuristics, not verdicts.")
    L.append("")
    env_all, snd_all = cs.get("by_envelope") or [], cs.get("by_sender") or []
    if cs.get("note") == CENSUS_UNAVAILABLE:
        L.append(f"- {CENSUS_UNAVAILABLE}")
        L.append("")
        return
    env = [r for r in env_all if r["genuine_failures"]]
    snd = [r for r in snd_all if r["genuine_failures"]]
    L.append(f"- by envelope (MAIL FROM) domain: {len(env)} failing, {len(env_all) - len(env)} clean")
    for r in env[:CENSUS_TOP]:
        L.append(f"  - {r['envelope_domain']}: {r['genuine_failures']} failing of {r['messages']} message(s), "
                 f"{r['senders']} sender(s), for example {r['sample_sender']}; {r['likely'] or 'n/a'}")
    if len(env) > CENSUS_TOP:
        L.append(f"  - (+{len(env) - CENSUS_TOP} more in report.json)")
    L.append(f"- by sender: {len(snd)} failing, {len(snd_all) - len(snd)} clean")
    for r in snd[:CENSUS_TOP]:
        L.append(f"  - {r['sender']} (envelope {r['envelope_domain']}): {r['genuine_failures']} failing of "
                 f"{r['messages']} message(s); {r['likely'] or 'n/a'}; \"{r['sample_subject'] or 'no subject'}\"")
    if len(snd) > CENSUS_TOP:
        L.append(f"  - (+{len(snd) - CENSUS_TOP} more in report.json)")
    L.append("")


def _md_delta(L, dl):
    def signed(n):
        return "n/a (no mail log on one side)" if n is None else f"{n:+d}"

    def more(items, cap=10):
        return " ..." if len(items) > cap else ""

    L.append("## Since the previous run")
    L.append("")
    L.append(f"Compared with the report generated {dl.get('previous_generated_utc') or 'unknown'}"
             + (f" (audit.py {dl['previous_version']})" if dl.get("previous_version") else "") + ".")
    L.append("")
    L.append(f"- genuine failures: {signed(dl.get('genuine_failures'))}; delivered despite fail: "
             f"{signed(dl.get('delivered_despite_fail'))} (whole mail log, deduplicated)")
    bd = dl.get("by_domain") or {}
    if bd:
        L.append("- per domain: " + "; ".join(f"{d} {v['genuine_failures']:+d} genuine, "
                                              f"{v['delivered_despite_fail']:+d} delivered despite fail"
                                              for d, v in bd.items()))
    new = dl.get("findings_new") or []
    L.append(f"- new findings ({len(new)}): " + (", ".join(
        f"[{f['severity']}] {f['id']} ({_display_source(f['source'])})" for f in new[:10]) + more(new)
        if new else "none"))
    gone = dl.get("findings_resolved") or []
    L.append(f"- resolved findings ({len(gone)}): " + (", ".join(
        f"{f['id']} ({_display_source(f['source'])})" for f in gone[:10]) + more(gone) if gone else "none"))
    pc = dl.get("policy_changes") or {}
    L.append("- policy changes: " + (", ".join(f"{d} p={v['from']} -> p={v['to']}" for d, v in pc.items())
                                     if pc else "none"))
    gc = dl.get("gate_changes") or {}
    if gc:
        L.append("- gate changes: " + ", ".join(f"{d} {v['from']} -> {v['to']}" for d, v in gc.items()))
    added, removed = dl.get("domains_added") or [], dl.get("domains_removed") or []
    if added or removed:
        L.append(f"- domains added: {', '.join(added) or 'none'}; removed: {', '.join(removed) or 'none'}")
    ns = dl.get("new_senders") or []
    L.append(f"- new senders ({len(ns)}): " + (", ".join(
        f"{s['sender']} (envelope {s['envelope_domain']}) {s['genuine_failures']} failing of {s['messages']}"
        for s in ns[:10]) + more(ns) if ns else "none"))
    gs = dl.get("gone_senders") or []
    if gs:
        L.append(f"- senders no longer seen ({len(gs)}): " + ", ".join(s["sender"] for s in gs[:10]) + more(gs))
    for n in dl.get("notes") or []:
        L.append(f"- note: {n}")
    L.append("")


def render_md(report):
    g = report["gate"]
    ev = g.get("evidence") or {}
    inp = report["inputs"]
    L = []
    L.append(f"# DMARC audit - gate: {g['verdict'].upper()}")
    L.append("")
    L.append(f"Generated {report['generated_utc']} by audit.py {VERSION} "
             f"({'offline, files only' if report['offline'] else 'live DNS + files'}). "
             "Read-only: nothing here changed DNS, mail rules, or tenant configuration.")
    L.append("")
    L.append("## Gate verdict")
    L.append("")
    per = g.get("domains") or {}
    hl = g.get("headline") or {}
    hd, worst = hl.get("domain"), g.get("worst_domain")
    if per and hd in per:
        head = f"**{g['verdict']}** - {g.get('overall')}"
        if worst and worst != hd:
            head += f"; worst: {worst} ({per[worst]['verdict']})"
        L.append(head)
        pol = (f"current policy p={hl['current_policy']} ({hl['policy_source']})" if hl.get("current_policy")
               else "policy unknown")
        L.append(f"- headline domain: {hd} ({hl.get('source_label')}) - **{hl.get('verdict')}**; {pol}")
        L.append(f"- step being gated for {hd}: {hl.get('next_step') or 'unknown'}")
        if worst and worst != hd:
            wpol = (f"current policy p={g['current_policy']} ({g['policy_source']})" if g.get("current_policy")
                    else "policy unknown")
            L.append(f"- worst domain: {worst} - **{per[worst]['verdict']}**; {wpol}; next step: "
                     f"{g.get('next_step') or 'unknown'} (gate.current_policy and gate.next_step describe it)")
    else:
        head = f"**{g['verdict']}**"
        if g["current_policy"]:
            head += f" - current policy p={g['current_policy']} ({g['policy_source']})"
        L.append(head)
        L.append(f"- step being gated: {g.get('next_step') or 'unknown'}")
    L.append(f"- evidence: {ev.get('statement') or 'not recorded'}")
    L.append("- aligned-DKIM evidence (needed before p=reject): "
             + (", ".join(ev.get("dkim_evidence_sources") or []) or "none in this run"))
    if per:
        L.append("")
        L.append(f"Per domain ({g.get('overall') or 'the overall verdict is the worst of these'}; "
                 "each gate uses only its own mail-log rows):")
        L.append("")
        for d, dg in per.items():
            pol = f"p={dg['current_policy']} ({dg['policy_source']})" if dg["current_policy"] else "policy unknown"
            L.append(f"- {d}: **{dg['verdict']}** - {pol}; next step: {dg['next_step']}")
            for r in dg["reasons"]:
                if r != ev.get("statement"):
                    L.append(f"  - {r}")
    else:
        for r in g["reasons"]:
            if r != ev.get("statement"):
                L.append(f"- {r}")
    L.append("")
    L.append(f"Gate rule: {g['rule']}.")
    L.append("")

    if report.get("delta"):
        _md_delta(L, report["delta"])

    L.append("## Inputs")
    L.append("")
    L.append(f"- domains: {', '.join(inp['domains']) or 'none'}"
             + (f" (from {display_path(inp['domain_file'])})" if inp.get("domain_file") else ""))
    L.append(f"- aggregate reports: {', '.join(display_path(p) for p in inp['rua']) or 'none'}")
    L.append(f"- mail log: {display_path(inp['maillog']) if inp['maillog'] else 'none'}"
             + (f" (columns: {_plain(inp['maillog_columns'])})" if inp.get("maillog_columns") else ""))
    L.append(f"- headers: {', '.join(display_path(p) for p in inp['headers']) or 'none'}")
    for name in TENANT_SECTIONS:
        L.append(f"- {name} export: {display_path(inp[name]) if inp.get(name) else 'none'}")
    if inp.get("previous"):
        L.append(f"- previous run: report generated {inp['previous']}")
    opts = {k: inp[k] for k in ("known", "sender_domain", "authserv_id", "since", "until", "expect_policy")
            if inp.get(k)}
    if inp.get("retiring_selectors"):
        opts["retiring_selectors"] = ", ".join(inp["retiring_selectors"])
    L.append(f"- options: {_plain(opts)}")
    L.append("")

    if report["dns"]:
        L.append("## DNS posture (live)")
        L.append("")
        for d, r in report["dns"].items():
            if r.get("spf_status") == "error":
                spf = "LOOKUP FAILED - not verified"
            else:
                spf = r["spf"] or "MISSING"
            if r.get("dmarc_status") == "error":
                dmarc = "LOOKUP FAILED - not verified"
            elif not r["dmarc"]:
                dmarc = "MISSING"
            elif r["inherited"]:
                dmarc = f"inherited from {r['dmarc_source']}: {r['dmarc']}"
            else:
                dmarc = r["dmarc"]
            L.append(f"### {d}")
            L.append(f"- SPF: {spf}")
            L.append(f"- SPF lookups: {r['spf_lookups']}/{SPF_LIMIT}, "
                     f"terminator {r['spf_terminator'] or 'n/a'}")
            L.append(f"- DMARC: {dmarc} (effective policy: {r['effective_policy'] or 'unknown'})")
            L.append(f"- DKIM selectors found: {_dkim_line(r)}")
            L.append(f"- MX: {_mx_line(r)}")
            L.append("")

    if report["rua"]:
        t = report["rua"]["totals"]
        L.append("## Aggregate reports (what receivers see)")
        L.append("")
        L.append(f"- {t['reports']} reports, {t['messages']} messages, "
                 f"{t['pass']} pass / {t['fail']} fail ({t['pass_rate'] * 100:.1f}% pass)")
        L.append(f"- window: {t['begin_date']} .. {t['end_date']}; reporters: {', '.join(t['reporters'])}")
        L.append(f"- alignment: {_plain(t['aligned'], ('both', 'dkim_only', 'spf_only', 'neither'))}")
        L.append(f"- dispositions: {_plain(t.get('by_disposition') or {}, ('none', 'quarantine', 'reject'))}")
        fs = report["rua"]["failing_streams"]
        if fs:
            L.append("- failing streams:")
            for f in fs:
                L.append(f"  - {f['source_ip']}: {f['fail']}/{f['count']} fail, "
                         f"dispositions {_plain(f['dispositions'])}, {f['likely']} (heuristic)")
        so = report["rua"]["spf_only_senders"]
        if so:
            L.append("- SPF-only senders (break on forwarding):")
            for f in so:
                L.append(f"  - {f['source_ip']}: {f['spf_only']} msgs as {', '.join(f['header_from'][:2])}")
        L.append("")

    if report["maillog"]:
        c = report["maillog"]["counters"]
        L.append("## Mail log (deduplicated)")
        L.append("")
        L.append(f"- {c['raw_rows']} raw rows -> {c['logical_messages']} logical messages "
                 f"(never report the raw count)")
        L.append(f"- {c['raw_failing_rows']} rows would count as failures; "
                 f"{c['genuine_failures']} genuine after deduplication")
        L.append(f"- genuine failures (no passing copy): {c['genuine_failures']}; "
                 f"echo messages (fail + pass legs): {c['echo_messages']}")
        L.append(f"- delivered despite fail: {c['delivered_despite_fail']}; "
                 f"blocked despite pass: {c['blocked_despite_pass']}")
        L.append("- likely split of failures (heuristic): "
                 + ", ".join(f"{n} {label}" for label, n in c["by_likely"].items()))
        al = report["maillog"].get("alignment") or c.get("alignment") or {}
        if al.get("available"):
            L.append(f"- alignment of passing mail (dkim_alignment buckets): {al['dkim_aligned']} DKIM-carried, "
                     f"{al['spf_and_dkim']} SPF and DKIM, {al['spf_only']} SPF only (break on forwarding)")
            so = report["maillog"].get("spf_only_senders") or []
            if so:
                L.append("- SPF-only senders in the mail log (aligned DKIM before reject):")
                for sender in so[:20]:
                    L.append(f"  - {sender['sender'] or '?'} (envelope {sender['envelope_domain'] or '?'}): "
                             f"{sender['spf_only']} of {sender['passing']} passing msgs")
        else:
            L.append("- alignment: not judged - the export has no SPF/DKIM columns "
                     "(queries/raw_maillog.kql adds them)")
        if c.get("auth_column"):
            L.append(f"- verdict basis: column '{c['auth_column']}'")
        elif report["maillog"].get("auth_column"):
            L.append(f"- verdict basis: column '{report['maillog']['auth_column']}'"
                     + (" (auto-detected)" if report["maillog"].get("auth_column_detected") else ""))
        if report["maillog"].get("by_domain"):
            _md_by_domain(L, report["maillog"]["by_domain"])
        L.append("")
        if report["maillog"].get("census"):
            _md_census(L, report["maillog"]["census"])

    if report["headers"]:
        L.append("## Message headers")
        L.append("")
        if report["headers"]["ar_note"]:
            L.append(f"- warning: {report['headers']['ar_note']}")
        for m in report["headers"]["messages"]:
            sigs = ", ".join(f"d={s['d']} s={s['s'] or '?'} ({s['ar_result'] or 'no verdict'})"
                             for s in m["dkim_signatures"]) or "none on the wire"
            L.append(f"- {display_path(m['file'])}: from {m['from'] or '(unparseable From)'} - "
                     f"would pass DMARC via {m['dmarc_would_pass_via']}; signatures: {sigs}")
        L.append("")

    for name in TENANT_SECTIONS:
        if report.get(name):
            _md_tenant(L, name, report[name])

    s = report["summary"]
    L.append(f"## Findings ({s['findings']}, worst: {s['worst'] or 'none'}; "
             f"by area: {_plain(s.get('by_area') or {})})")
    L.append("")
    L += _md_findings(report["findings"])
    L.append("")

    vi = report.get("verified_vs_inferred")
    if vi:
        L.append("## Verified vs inferred")
        L.append("")
        L.append("- verified (measured):")
        L += [f"  - {x}" for x in vi["verified"]] or ["  - nothing"]
        L.append("- inferred (heuristic, reasoning, or unconfirmed lookup):")
        L += [f"  - {x}" for x in vi["inferred"]] or ["  - nothing"]
        L.append("")
    L.append("Every finding carries a recommended action; `not verified` marks inference over proof.")
    L.append("")
    return "\n".join(L)


# ------------------------------------------------------------------ cli

def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*", help="domains to audit (live DNS unless --offline)")
    ap.add_argument("--file", metavar="PATH", help="file with one domain per line (added to the positional domains)")
    ap.add_argument("--no-graph", action="store_true",
                    help="do not read the tenant's domain list through the app registration")
    ap.add_argument("--mailflow", action="store_true",
                    help="add subdomains seen sending in the last 30 days (needs ThreatHunting.Read.All)")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    ap.add_argument("--rua", nargs="+", metavar="PATH", default=[],
                    help="aggregate report files or directories (.xml .xml.gz .zip; directories recursed)")
    ap.add_argument("--maillog", metavar="CSV", help="mail-log export for dedupe (Message-ID grouping)")
    ap.add_argument("--headers", nargs="+", metavar="FILE", default=[],
                    help="raw header blocks or .eml files")
    ap.add_argument("--rules-json", metavar="JSON", help="audit_rules.ps1 -Json export")
    ap.add_argument("--bypasses-json", metavar="JSON", help="audit_bypasses.ps1 -Json export")
    ap.add_argument("--groups-json", metavar="JSON", help="audit_groups.ps1 -Json export")
    ap.add_argument("--previous", metavar="PATH",
                    help="an earlier run's report.json (or the folder holding it), for the "
                         "'since the previous run' deltas")
    ap.add_argument("--out", default="audit-out", metavar="DIR",
                    help="output directory for report.md, report.json, plan.md, plan.json (default audit-out/)")
    ap.add_argument("--no-plan", action="store_true", help="do not write the rollout plan (plan.md, plan.json)")
    ap.add_argument("--rua-address", metavar="MAILTO",
                    help="reporting address the plan puts in new DMARC records (default: the one your records already use)")
    ap.add_argument("--inventory", metavar="JSON", help="inventory.json from discover.py, for the zone host per domain")
    ap.add_argument("--offline", action="store_true",
                    help="no live DNS or network work; analyse only the files given")
    ap.add_argument("--resolver", default="8.8.8.8", help="port-53 resolver (DoH is the fallback)")
    ap.add_argument("--selectors", help="comma-separated DKIM selectors to probe in addition to the common list")
    ap.add_argument("--known", metavar="LIST_OR_FILE",
                    help="known sender domains and IP prefixes for the rua unknown-sender check")
    ap.add_argument("--sender-domain", help="restrict the mail log to this domain and its subdomains")
    ap.add_argument("--auth-column", help="mail-log column holding the DMARC verdict "
                                          "(default: auto-detect a 'DMARC' column)")
    cols = ap.add_argument_group("mail-log column names (defaults are dedupe.py's)")
    for key, default in MAILLOG_COLUMNS.items():
        cols.add_argument(f"--{key}-column", metavar="NAME", default=None,
                          help=f"column holding the {key} field (default '{default}')")
    ap.add_argument("--vendor-domain", action="append", default=[], metavar="DOMAIN",
                    help="envelope domain known to be one of your vendors (repeatable)")
    ap.add_argument("--authserv-id", help="authserv-id your receiving host writes into "
                                          "Authentication-Results (headers input)")
    ap.add_argument("--strict", action="store_true", help="strict alignment for the header analysis")
    ap.add_argument("--min-volume", type=int, default=20, metavar="N",
                    help="messages a source needs before it counts as a stream (default 20)")
    ap.add_argument("--fail-threshold", type=float, default=0.5, metavar="RATE",
                    help="pass rate under which a source is a failing stream (default 0.5)")
    ap.add_argument("--since", metavar="YYYY-MM-DD", help="keep rua reports ending on or after this day (UTC)")
    ap.add_argument("--until", metavar="YYYY-MM-DD", help="keep rua reports starting on or before this day (UTC)")
    ap.add_argument("--expect-policy", choices=("none", "quarantine", "reject"),
                    help="flag rua reports that saw a different p= than this")
    ap.add_argument("--retiring-selector", action="append", default=[], metavar="NAME",
                    help="DKIM selector you plan to delete; checked against the rua reports (repeatable)")
    ap.add_argument("--config", metavar="TOML",
                    help="settings file read for [[exceptions]] and vendor_domains "
                         "(default: <repo root>/audit.toml when it exists)")
    ap.add_argument("--no-config", action="store_true", help="ignore audit.toml even if it exists")
    args = ap.parse_args()

    exceptions, cfg_vendors = [], []
    if not args.no_config:
        try:
            cfg = config_mod.load(args.config)
        except config_mod.ConfigError as exc:
            die(str(exc))
        exceptions = cfg.get("exceptions") or []
        cfg_vendors = [str(v) for v in ((cfg.get("audit") or {}).get("vendor_domains") or [])]

    # Domains: command line (comma or space separated), --file, and - unless
    # --no-graph or --offline - the tenant's own verified domain list, merged
    # with duplicates dropped. No domains at all means "audit the tenant".
    domains, bad = discover.parse_domains(list(args.domains))
    headline = domains[0] if domains else None  # typed first: the report's headline domain
    domain_sources = {d: ["cli"] for d in domains}
    if args.file:
        try:
            file_domains, bad_file = discover.parse_domains(read_domain_file(args.file))
        except UsageError as exc:
            die(str(exc))
        bad += bad_file
        for d in file_domains:
            domain_sources.setdefault(d, []).append("file")
            if d not in domains:
                domains.append(d)
    if bad:
        die("not a domain name: " + ", ".join(bad))
    if not args.offline and not args.no_graph:
        tenant, note = discover.graph_domains(args.env_file)
        if note:
            print("note: " + note, file=sys.stderr)
        new = 0
        for t in tenant:
            d = t["domain"]
            if d.endswith(".onmicrosoft.com") or not t.get("verified"):
                continue
            domain_sources.setdefault(d, []).append("tenant")
            if t.get("default"):
                domain_sources[d].append("default")
            if d not in domains:
                domains.append(d)
                new += 1
        if tenant:
            print("note: %d verified domains read from the tenant, %d not already named"
                  % (sum(1 for t in tenant if t.get("verified")), new), file=sys.stderr)
    if not args.offline and args.mailflow and domains:
        orgs = sorted({discover.org_domain(d) for d in domains})
        rows, note = discover.mailflow_subdomains(orgs, args.env_file)
        if note:
            print("note: " + note, file=sys.stderr)
        for r in rows:
            domain_sources.setdefault(r["domain"], []).append("mailflow")
            if r["domain"] not in domains:
                domains.append(r["domain"])
        if rows:
            print("note: %d sending domains under %s seen in mail flow" % (len(rows), ", ".join(orgs)),
                  file=sys.stderr)
    columns = {key: getattr(args, f"{key}_column") for key in MAILLOG_COLUMNS
               if getattr(args, f"{key}_column")}

    try:
        previous = read_previous_report(args.previous) if args.previous else None
        report = build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=args.rua, maillog=args.maillog, header_files=args.headers,
            offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, sender_domain=args.sender_domain, auth_column=args.auth_column,
            vendor_domains=list(args.vendor_domain) + cfg_vendors, authserv_id=args.authserv_id, strict=args.strict,
            min_volume=args.min_volume, fail_threshold=args.fail_threshold,
            since=args.since, until=args.until, expect_policy=args.expect_policy,
            retiring=args.retiring_selector, columns=columns,
            rules_json=args.rules_json, bypasses_json=args.bypasses_json, groups_json=args.groups_json,
            previous_report=previous, headline=headline, exceptions=exceptions)
    except UsageError as exc:
        die(str(exc))

    try:
        jpath, mpath = write_reports(report, args.out)
    except OSError as exc:
        die(f"cannot write reports: {exc.strerror or exc}")

    g = report["gate"]
    s = report["summary"]
    statement = g["evidence"]["statement"]
    paint = console.painter()
    hl = g.get("headline") or {}
    line = "gate: " + paint.status(g["verdict"])
    if hl.get("domain"):
        line += f" - {g['overall']}"
        if g.get("worst_domain") and g["worst_domain"] != hl["domain"]:
            line += f" (worst: {g['worst_domain']})"
        line += f"; headline {hl['domain']} ({hl['source_label']})"
        if hl.get("current_policy"):
            line += f" p={hl['current_policy']}"
    elif g["current_policy"]:
        line += f" (current policy p={g['current_policy']})"
    print(line)
    if g["domains"]:
        for d, dg in g["domains"].items():
            pol = f"p={dg['current_policy']} ({dg['policy_source']})" if dg["current_policy"] else "policy unknown"
            print(f"  {d}: " + paint.status(dg["verdict"]) + f" - {pol}; next step: {dg['next_step']}")
            for r in dg["reasons"]:
                if r != statement:
                    print(paint.dim(f"    - {r}"))
    else:
        for r in g["reasons"]:
            if r != statement:
                print(paint.dim(f"  - {r}"))
    print(paint.dim(f"  evidence: {statement}"))
    print(paint.by_exit(f"findings: {s['findings']} (worst {s['worst'] or 'none'}), "
                        f"{s['actionable']} major or blocking", report["exit_code"]))
    dl = report.get("delta")
    if dl:
        gf = dl.get("genuine_failures")
        print(paint.dim(f"since the previous run ({dl.get('previous_generated_utc') or 'unknown'}): "
                        + (f"genuine failures {gf:+d}, " if gf is not None else "")
                        + f"{len(dl['findings_new'])} new finding(s), {len(dl['findings_resolved'])} resolved, "
                          f"{len(dl['policy_changes'])} policy change(s), {len(dl['new_senders'])} new sender(s)"))
    print(f"wrote {mpath}")
    print(f"wrote {jpath}")
    if not args.no_plan and report.get("dns"):
        import plan as plan_mod
        inventory = None
        if args.inventory:
            try:
                inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as err:
                print(f"note: inventory not used ({err})", file=sys.stderr)
        try:
            pm, pj = plan_mod.write(plan_mod.build_plan(report, inventory, args.rua_address), args.out)
            print(f"wrote {pm}")
            print(f"wrote {pj}")
        except ValueError as err:
            print(f"note: no plan written ({err})", file=sys.stderr)
    sys.exit(report["exit_code"])


if __name__ == "__main__":
    main()
