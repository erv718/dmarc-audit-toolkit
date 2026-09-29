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
    not the move none -> quarantine
  - no DMARC record / no rua / DMARC lookup failed: no_go (you cannot ratchet
    a policy you cannot see)
  - if no policy could be determined at all, or no failure evidence was
    supplied (no rua reports, no mail log), the verdict is insufficient_data
  - at p=reject there is nothing to ratchet; every branch says so, and the
    verdict then describes the state of enforcement rather than a move

Outputs: report.md (human) and report.json (machine) in the output directory
(default audit-out/). Those two files are the only writes - everything else
stays read-only.

Usage:
    python src/audit.py example.com
    python src/audit.py --file domains.txt --rua exports/rua --maillog exports/log.csv
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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

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
                   "subject": "Subject", "envelope": "Sender mail from domain"}
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
             "already rejected do not")
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
    if missing_req:
        raise UsageError("column not found: %s. Available columns: %s"
                         % (", ".join(missing_req), ", ".join(header) or "(none)"))

    counts = dedupe.count_rows(rows, cols, sender_domain, auth_column)
    verdicts = dedupe.classify(rows, cols, sender_domain, auth_column, vendor_domains)
    counts.update(dedupe.summarize(verdicts))
    findings = dedupe.build_findings(counts, verdicts, auth_column, missing_opt, sender_domain)
    doc = dedupe.build_doc(path, counts, verdicts, findings, sender_domain, auth_column, vendor_domains)
    doc["columns"] = cols
    if detected:
        doc["auth_column_detected"] = True
    if missing_opt:
        doc["missing_optional_columns"] = missing_opt
    return doc


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
                hit, policy = s["domain"] == domain, s["p"]
            else:  # a subdomain of a reported domain: the org record's sp= (else p=) governs it
                hit, policy = _under(domain, s["domain"]), (s.get("sp") or s["p"])
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
    run has none, and says so in every gate branch."""
    rua_n = rua_doc["totals"]["reports"] if rua_doc else 0
    rua_m = rua_doc["totals"]["messages"] if rua_doc else 0
    raw = maillog_doc["counters"]["raw_rows"] if maillog_doc else 0
    rows = maillog_doc["counters"]["rows_in_scope"] if maillog_doc else 0
    hdr = len(headers_doc["messages"]) if headers_doc else 0
    supplied = bool(rua_n and rua_m) or bool(rows)
    if supplied:
        stmt = (f"failure evidence supplied: {rua_n} aggregate report(s) ({rua_m} messages), "
                f"{rows} mail-log row(s) in scope of {raw} read, {hdr} header file(s)")
    else:
        stmt = (f"no failure evidence supplied ({rua_n} aggregate reports, {rows} mail-log rows, "
                f"{hdr} header files): this is a posture check, not a completed audit - "
                "pass --rua reports and/or --maillog")
    return {"rua_reports": rua_n, "rua_messages": rua_m, "maillog_rows": raw,
            "maillog_rows_in_scope": rows, "header_files": hdr,
            "failure_evidence": supplied, "statement": stmt}


def _shared_blockers(rua_doc, maillog_doc, tenant_docs=None):
    """Blockers that apply to every domain in the run."""
    blockers = []
    if rua_doc:
        for f in rua_doc["failing_streams"]:
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
    if maillog_doc:
        c = maillog_doc["counters"]
        if c["genuine_failures"]:
            blockers.append(f"{c['genuine_failures']} logical message(s) in the mail log failed with "
                            "no passing copy (deduplicated)")
        if c["delivered_despite_fail"]:
            blockers.append(f"{c['delivered_despite_fail']} message(s) failed authentication but reached "
                            "a mailbox - a local override is masking failures external receivers enforce")
    for name, doc in (tenant_docs or {}).items():
        for f in (doc or {}).get("findings", []):
            if f["severity"] == "blocking" or (f["severity"] == "major" and f["id"] in TENANT_GATE_BLOCKS):
                blockers.append(f"{name}: {f['title']} - unauthenticated mail is delivered past the policy")
    return blockers


def _dns_blockers(r, domain):
    return [f"{domain}: {f['title']}" for f in r["findings"]
            if f["severity"] == "blocking" or f["id"] in DNS_GATE_BLOCKS]


def _domain_gate(domain, info, shared, dns_blockers, rua_doc, evidence):
    """One domain's verdict. Every branch names the step being gated and
    whether failure evidence was supplied."""
    policy, policy_from = info["policy"], info["source"]
    blockers = list(dns_blockers) + list(shared)
    if policy == "quarantine" and rua_doc:
        spf_only = [f for f in rua_doc["spf_only_senders"]
                    if domain is None or any(_under(hf, domain) for hf in f["header_from"])]
        if spf_only:
            msgs = sum(f["spf_only"] for f in spf_only)
            blockers.append(f"{len(spf_only)} sender(s) pass on SPF alone ({msgs} msgs): "
                            "set up aligned DKIM before moving quarantine -> reject")
    step = next_step(policy, info["tags"], info["spf_terminator"], info["spf_status"], info["record_at"])
    at_end = policy == "reject"
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
    reasons.append(evidence["statement"])
    return {"verdict": verdict, "current_policy": policy, "policy_source": policy_from,
            "next_step": step, "reasons": reasons}


def gate_verdict(dns_reports, rua_doc, maillog_doc, domains=(), headers_doc=None, tenant_docs=None):
    """The ratchet decision, per domain, plus the overall verdict (the worst).
    See the module docstring for the rule."""
    evidence = evidence_summary(rua_doc, maillog_doc, headers_doc)
    shared = _shared_blockers(rua_doc, maillog_doc, tenant_docs)
    names = list(dict.fromkeys(domains)) or list((dns_reports or {}).keys())
    if not names and rua_doc:
        names = list(dict.fromkeys(s["domain"] for s in rua_doc["policy_check"]["seen"] if s["domain"]))
    per_domain = {}
    for d in names:
        info = domain_policy(d, dns_reports, rua_doc)
        dns_b = _dns_blockers(dns_reports[d], d) if dns_reports and d in dns_reports else []
        per_domain[d] = _domain_gate(d, info, shared, dns_b, rua_doc, evidence)
    if per_domain:
        lead = max(per_domain, key=lambda d: GATE_RANK[per_domain[d]["verdict"]])
        overall = per_domain[lead]
        merged = {}
        for d, g in per_domain.items():
            for r in g["reasons"]:
                if r == evidence["statement"] or r in shared or len(per_domain) == 1 or r.startswith(f"{d}: "):
                    merged.setdefault(r, None)
                else:
                    merged.setdefault(f"{d}: {r}", None)
        merged.pop(evidence["statement"], None)
        reasons = list(merged) + [evidence["statement"]]
    else:
        overall = _domain_gate(None, domain_policy(None, dns_reports, rua_doc), shared, [], rua_doc, evidence)
        reasons = overall["reasons"]
    return {"verdict": overall["verdict"], "current_policy": overall["current_policy"],
            "policy_source": overall["policy_source"], "next_step": overall["next_step"],
            "reasons": reasons,
            "policies": {d: g["current_policy"] for d, g in per_domain.items()},
            "domains": per_domain,
            "evidence": evidence,
            "rule": GATE_RULE}


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
        at_end = policies.get(src[4:]) == "reject" if src.startswith("dns:") else all_reject
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
    seen_v, seen_i = set(), set()
    for f in report["findings"]:
        bucket, seen = (verified, seen_v) if f.get("verified", True) else (inferred, seen_i)
        if f["id"] not in seen:
            seen.add(f["id"])
            bucket.append(f["id"])
    return {"verified": verified, "inferred": inferred,
            "note": "finding ids listed under inferred carry verified=false (heuristic or unconfirmed lookup)"}


def build_report(domains=(), rua_paths=(), maillog=None, header_files=(), offline=False,
                 resolver_addr="8.8.8.8", selectors=(), known=None, sender_domain=None,
                 auth_column=None, vendor_domains=(), authserv_id=None, strict=False,
                 min_volume=20, fail_threshold=0.5, since=None, until=None,
                 expect_policy=None, retiring=(), columns=None, domain_file=None,
                 rules_json=None, bypasses_json=None, groups_json=None, domain_sources=None):
    """The whole audit as one document. Raises UsageError on input problems."""
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

    report = {
        "tool": "audit.py", "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "offline": offline,
        "inputs": {"domains": domains, "domain_sources": domain_sources or {},
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
                   "expect_policy": expect_policy, "retiring_selectors": list(retiring)},
        "dns": dns_reports,
        "rua": rua_doc,
        "maillog": maillog_doc,
        "headers": headers_doc,
    }
    report.update(tenant_docs)
    report["gate"] = gate_verdict(dns_reports, rua_doc, maillog_doc, domains, headers_doc, tenant_docs)
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
    report["exit_code"] = code
    return report


def write_reports(report, out_dir):
    """The only writes in the whole toolchain: report.json and report.md."""
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
    head = f"**{g['verdict']}**"
    if g["current_policy"]:
        head += f" - current policy p={g['current_policy']} ({g['policy_source']})"
    L.append(head)
    L.append(f"- step being gated: {g.get('next_step') or 'unknown'}")
    L.append(f"- evidence: {ev.get('statement') or 'not recorded'}")
    per = g.get("domains") or {}
    if per:
        L.append("")
        L.append("Per domain (the overall verdict is the worst of these):")
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
        if c.get("auth_column"):
            L.append(f"- verdict basis: column '{c['auth_column']}'")
        elif report["maillog"].get("auth_column"):
            L.append(f"- verdict basis: column '{report['maillog']['auth_column']}'"
                     + (" (auto-detected)" if report["maillog"].get("auth_column_detected") else ""))
        L.append("")

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
    args = ap.parse_args()

    # Domains: command line (comma or space separated), --file, and - unless
    # --no-graph or --offline - the tenant's own verified domain list, merged
    # with duplicates dropped. No domains at all means "audit the tenant".
    domains, bad = discover.parse_domains(list(args.domains))
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
        report = build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=args.rua, maillog=args.maillog, header_files=args.headers,
            offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, sender_domain=args.sender_domain, auth_column=args.auth_column,
            vendor_domains=args.vendor_domain, authserv_id=args.authserv_id, strict=args.strict,
            min_volume=args.min_volume, fail_threshold=args.fail_threshold,
            since=args.since, until=args.until, expect_policy=args.expect_policy,
            retiring=args.retiring_selector, columns=columns,
            rules_json=args.rules_json, bypasses_json=args.bypasses_json, groups_json=args.groups_json)
    except UsageError as exc:
        die(str(exc))

    try:
        jpath, mpath = write_reports(report, args.out)
    except OSError as exc:
        die(f"cannot write reports: {exc.strerror or exc}")

    g = report["gate"]
    s = report["summary"]
    statement = g["evidence"]["statement"]
    print(f"gate: {g['verdict']}" + (f" (current policy p={g['current_policy']})" if g["current_policy"] else ""))
    if g["domains"]:
        for d, dg in g["domains"].items():
            pol = f"p={dg['current_policy']} ({dg['policy_source']})" if dg["current_policy"] else "policy unknown"
            print(f"  {d}: {dg['verdict']} - {pol}; next step: {dg['next_step']}")
            for r in dg["reasons"]:
                if r != statement:
                    print(f"    - {r}")
    else:
        for r in g["reasons"]:
            if r != statement:
                print(f"  - {r}")
    print(f"  evidence: {statement}")
    print(f"findings: {s['findings']} (worst {s['worst'] or 'none'}), "
          f"{s['actionable']} major or blocking")
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
