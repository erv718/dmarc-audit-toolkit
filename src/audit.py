"""The orchestrator: one audit report from every read-only tool in the repo.

Each tool in src/ answers one question well - dns_audit the DNS posture,
rua_parse what receivers see, dedupe what the tenant log proves, headers what
a single message proves. The ratchet decision ("can p= move forward") needs
all four at once, plus a verdict a human can act on. This module wires them
together (imports only, no subprocess), collects every finding into one
severity-ordered list, and ends with a gate verdict:

  go                - nothing unexplained is failing; the policy can move
  no_go             - something is still failing or unprotected; fix or
                      formally except it before p= moves (AGENTS.md gate rule)
  insufficient_data - the policy or the failure evidence is unknown; a zero
                      count here is not evidence of health

The gate rule, deliberately conservative:
  - any blocking finding, any failing stream not labelled likely_spoof, any
    genuine failure in the mail log, any delivered-despite-fail: no_go
  - a likely_spoof stream does NOT block: failing spoofs are what enforcement
    stops. It blocks only when receivers deliver it anyway (disposition none)
  - SPF-only senders block the move quarantine -> reject (DKIM before reject),
    not the move none -> quarantine
  - no DMARC record / no rua / DMARC lookup failed: no_go (you cannot ratchet
    a policy you cannot see)
  - if no policy could be determined at all, or no failure evidence was
    supplied (no rua reports, no mail log), the verdict is insufficient_data

Outputs: report.md (human) and report.json (machine) in the output directory
(default audit-out/). Those two files are the only writes - everything else
stays read-only.

Usage:
    python src/audit.py example.com
    python src/audit.py example.com --rua exports/rua --maillog exports/log.csv
    python src/audit.py example.com --offline --rua samples/rua \
        --maillog samples/sample_maillog.csv --headers samples/headers

--offline skips all live DNS and network work and analyses only the files
given. Relative paths resolve from the repo root, as in every tool here.

Exit codes: 0 clean, 1 at least one major or blocking finding, 2 usage or
input error - the same convention as the other tools.
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

import dedupe
import dns_audit
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
# DNS findings that make a ratchet meaningless: the policy or its reporting
# cannot even be seen.
DNS_GATE_BLOCKS = ("DMARC-001", "DMARC-003", "DMARC-005", "DMARC-006", "SPF-002")


class UsageError(Exception):
    """Raised for input problems; main turns it into exit 2, MCP into an error string."""


# ------------------------------------------------------------------ helpers

def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


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


# ------------------------------------------------------------------ inputs

def run_dns(domains, resolver, selectors=()):
    """dns_audit.audit_domain per domain. Keys are exactly what that function returns."""
    return {d: dns_audit.audit_domain(d, resolver, list(selectors) or None) for d in domains}


def run_rua(paths, known=None, min_volume=20, fail_threshold=0.5, since=None, until=None,
            expect_policy=None, retiring=()):
    """rua_parse.analyse as a library call; its die() becomes a UsageError."""
    try:
        doc, _agg = rua_parse.analyse(
            [str(repo_path(p)) for p in paths], known=known, min_volume=min_volume,
            fail_threshold=fail_threshold, since=since, until=until,
            expect_policy=expect_policy, retiring=retiring)
    except SystemExit as exc:  # rua_parse reports input errors via die() -> exit 2
        raise UsageError("rua analysis failed (input error, see the message above)") from exc
    return doc


def detect_auth_column(header):
    """The DMARC verdict column, when the export carries one under a known name."""
    for name in ("DMARC", "DMARC verdict", "dmarc"):
        if name in header:
            return name
    return None


def run_maillog(csv_path, sender_domain=None, auth_column=None, vendor_domains=()):
    """dedupe as a library call. Returns dedupe.build_doc's document.

    The auth column is auto-detected (a 'DMARC' column) when not given,
    because a verdict column the caller forgot to name silently turns the
    failure counts into delivery-action guesses."""
    path = repo_path(csv_path)
    cols = {"msgid": "Internet message ID", "recipient": "Recipients",
            "sender": "Sender address", "domain": "Sender domain",
            "action": "Delivery action", "location": "Latest delivery location",
            "subject": "Subject", "envelope": "Sender mail from domain"}
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


# ------------------------------------------------------------------ gate

def current_policy(dns_reports, rua_doc):
    """(policy, where_from). DNS first: it is live. Aggregate reports lag 24
    to 48 hours, so they are the fallback, not the source of truth."""
    for d, r in (dns_reports or {}).items():
        if r.get("effective_policy"):
            return r["effective_policy"], f"live DNS ({r['dmarc_source']})"
    if rua_doc:
        seen = rua_doc["policy_check"]["seen"]
        if seen:
            top = seen[0]
            return (top["p"] or "none"), f"aggregate reports ({top['domain']}, {top['reports']} report(s))"
    return None, None


def gate_verdict(dns_reports, rua_doc, maillog_doc):
    """The ratchet decision. See the module docstring for the rule."""
    reasons = []
    blockers = []

    if dns_reports:
        for d, r in dns_reports.items():
            for f in r["findings"]:
                if f["severity"] == "blocking":
                    blockers.append(f"{d}: {f['title']}")
                elif f["id"] in DNS_GATE_BLOCKS:
                    blockers.append(f"{d}: {f['title']}")

    failure_evidence = False
    if rua_doc:
        totals = rua_doc["totals"]
        if totals["reports"] and totals["messages"]:
            failure_evidence = True
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
        streams_note = len(rua_doc["failing_streams"])
    else:
        streams_note = None

    if maillog_doc:
        c = maillog_doc["counters"]
        if c["rows_in_scope"]:
            failure_evidence = True
        if c["genuine_failures"]:
            blockers.append(f"{c['genuine_failures']} logical message(s) in the mail log failed with "
                            "no passing copy (deduplicated)")
        if c["delivered_despite_fail"]:
            blockers.append(f"{c['delivered_despite_fail']} message(s) failed authentication but reached "
                            "a mailbox - a local override is masking failures external receivers enforce")

    policy, policy_from = current_policy(dns_reports, rua_doc)

    if policy == "quarantine" and rua_doc:
        spf_only = rua_doc["spf_only_senders"]
        if spf_only:
            msgs = sum(f["spf_only"] for f in spf_only)
            blockers.append(f"{len(spf_only)} sender(s) pass on SPF alone ({msgs} msgs): "
                            "set up aligned DKIM before moving quarantine -> reject")

    if blockers:
        verdict = "no_go"
        reasons = blockers
    elif policy is None:
        verdict = "insufficient_data"
        reasons = ["no DMARC policy could be determined - run without --offline so live DNS is "
                   "checked, or supply rua reports"]
    elif not failure_evidence:
        verdict = "insufficient_data"
        reasons = [f"policy is p={policy} ({policy_from}) but no failure evidence was supplied: "
                   "pass --rua reports and/or --maillog; a ratchet on zero data is a guess"]
    else:
        verdict = "go"
        reasons = [f"policy p={policy} ({policy_from}); no unexplained failures in the evidence supplied"]
        if policy == "reject":
            reasons = [f"policy is already p=reject ({policy_from}); nothing to ratchet - "
                       "keep watching the failing streams"] + [
                       f"{s['source_ip']} ({s['count']} msgs, {s['likely']})"
                       for s in (rua_doc["failing_streams"] if rua_doc else [])[:5]]
        elif rua_doc and rua_doc["failing_streams"]:
            spoof = [s for s in rua_doc["failing_streams"] if s["likely"] == "likely_spoof"]
            if spoof:
                reasons.append(f"{len(spoof)} failing stream(s) look like spoofs - moving p= forward "
                               "is exactly what stops them")

    return {"verdict": verdict, "current_policy": policy, "policy_source": policy_from,
            "reasons": reasons,
            "rule": "failing streams not labelled likely_spoof, genuine mail-log failures, "
                    "delivered-despite-fail, blocking findings, and invisible DMARC state block "
                    "the gate; spoofs already rejected do not"}


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
    return sorted(out, key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))


def build_report(domains=(), rua_paths=(), maillog=None, header_files=(), offline=False,
                 resolver_addr="8.8.8.8", selectors=(), known=None, sender_domain=None,
                 auth_column=None, vendor_domains=(), authserv_id=None, strict=False,
                 min_volume=20, fail_threshold=0.5, since=None, until=None,
                 expect_policy=None, retiring=()):
    """The whole audit as one document. Raises UsageError on input problems."""
    domains = [d.strip().lower().rstrip(".") for d in domains if d.strip()]
    if offline and not (rua_paths or maillog or header_files):
        raise UsageError("--offline with no inputs: pass --rua, --maillog and/or --headers")
    if not offline and not domains:
        raise UsageError("no domains given (or pass --offline with input files)")

    dns_reports = None
    if not offline and domains:
        dns_reports = run_dns(domains, make_resolver(resolver_addr), selectors)

    rua_doc = run_rua(rua_paths, known, min_volume, fail_threshold, since, until,
                      expect_policy, retiring) if rua_paths else None
    maillog_doc = run_maillog(maillog, sender_domain, auth_column, vendor_domains) if maillog else None
    headers_doc = run_headers(header_files, authserv_id, strict) if header_files else None

    report = {
        "tool": "audit.py", "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "offline": offline,
        "inputs": {"domains": domains,
                   "rua": _source_list(rua_paths),
                   "maillog": str(repo_path(maillog)) if maillog else None,
                   "headers": _source_list(header_files),
                   "authserv_id": authserv_id, "sender_domain": sender_domain,
                   "known": known, "since": since, "until": until,
                   "expect_policy": expect_policy, "retiring_selectors": list(retiring)},
        "dns": dns_reports,
        "rua": rua_doc,
        "maillog": maillog_doc,
        "headers": headers_doc,
    }
    report["gate"] = gate_verdict(dns_reports, rua_doc, maillog_doc)
    findings = flatten_findings(report)
    report["findings"] = findings
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    code = exit_code(findings)
    report["summary"] = {"findings": len(findings), "by_severity": by_sev,
                         "actionable": sum(1 for f in findings if f["severity"] in ("major", "blocking")),
                         "worst": worst_severity(findings), "exit_code": code,
                         "gate": report["gate"]["verdict"]}
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

def _md_findings(findings, limit=None):
    lines = []
    for f in findings[:limit] if limit else findings:
        verified = "" if f.get("verified", True) else " (not verified)"
        lines.append(f"- **[{f['severity']}] {f['id']}** ({f['source']}) {f['title']}{verified}")
        lines.append(f"  - evidence: {f['evidence']}")
        lines.append(f"  - action: {f['action']}")
    return lines or ["- none"]


def render_md(report):
    g = report["gate"]
    L = []
    L.append(f"# DMARC audit - gate: {g['verdict'].upper()}")
    L.append("")
    L.append(f"Generated {report['generated_utc']} by audit.py {VERSION} "
             f"({'offline, files only' if report['offline'] else 'live DNS + files'}). "
             "Read-only: nothing here changed DNS, mail rules, or tenant configuration.")
    L.append("")
    L.append("## Gate verdict")
    L.append("")
    L.append(f"**{g['verdict']}**" + (f" - current policy p={g['current_policy']} ({g['policy_source']})"
                                      if g["current_policy"] else ""))
    for r in g["reasons"]:
        L.append(f"- {r}")
    L.append("")
    L.append(f"Gate rule: {g['rule']}.")
    L.append("")

    if report["dns"]:
        L.append("## DNS posture (live)")
        L.append("")
        for d, r in report["dns"].items():
            dmarc = r["dmarc"] or "MISSING"
            if r["inherited"] and r["dmarc"]:
                dmarc = f"inherited from {r['dmarc_source']}: {dmarc}"
            spf = r["spf"] or "MISSING"
            L.append(f"### {d}")
            L.append(f"- SPF: {spf}")
            L.append(f"- SPF lookups: {r['spf_lookups']}/{SPF_LIMIT}, "
                     f"terminator {r['spf_terminator']}")
            L.append(f"- DMARC: {dmarc} (effective policy: {r['effective_policy'] or '?'})")
            L.append(f"- DKIM selectors found: {', '.join(r['dkim_selectors']) or 'none probed'}")
            L.append(f"- MX: {', '.join(r['mx']) or 'none'}")
            L.append("")

    if report["rua"]:
        t = report["rua"]["totals"]
        L.append("## Aggregate reports (what receivers see)")
        L.append("")
        L.append(f"- {t['reports']} reports, {t['messages']} messages, "
                 f"{t['pass']} pass / {t['fail']} fail ({t['pass_rate'] * 100:.1f}% pass)")
        L.append(f"- window: {t['begin_date']} .. {t['end_date']}; reporters: {', '.join(t['reporters'])}")
        L.append(f"- alignment: {t['aligned']}")
        fs = report["rua"]["failing_streams"]
        if fs:
            L.append("- failing streams:")
            for f in fs:
                L.append(f"  - {f['source_ip']}: {f['fail']}/{f['count']} fail, "
                         f"dispositions {f['dispositions']}, {f['likely']}")
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
        L.append(f"- genuine failures (no passing copy): {c['genuine_failures']}; "
                 f"echo messages (fail + pass legs): {c['echo_messages']}")
        L.append(f"- delivered despite fail: {c['delivered_despite_fail']}; "
                 f"blocked despite pass: {c['blocked_despite_pass']}")
        L.append(f"- likely split of failures: {c['by_likely']}")
        if c.get("auth_column"):
            L.append(f"- verdict basis: column '{c['auth_column']}'")
        L.append("")

    if report["headers"]:
        L.append("## Message headers")
        L.append("")
        if report["headers"]["ar_note"]:
            L.append(f"- warning: {report['headers']['ar_note']}")
        for m in report["headers"]["messages"]:
            sigs = ", ".join(f"d={s['d']} s={s['s'] or '?'} ({s['ar_result'] or 'no verdict'})"
                             for s in m["dkim_signatures"]) or "none on the wire"
            L.append(f"- {m['file']}: from {m['from'] or '?'} - "
                     f"would pass DMARC via {m['dmarc_would_pass_via']}; signatures: {sigs}")
        L.append("")

    L.append(f"## Findings ({report['summary']['findings']}, worst: {report['summary']['worst'] or 'none'})")
    L.append("")
    L += _md_findings(report["findings"])
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
    ap.add_argument("--rua", nargs="+", metavar="PATH", default=[],
                    help="aggregate report files or directories (.xml .xml.gz .zip; directories recursed)")
    ap.add_argument("--maillog", metavar="CSV", help="mail-log export for dedupe (Message-ID grouping)")
    ap.add_argument("--headers", nargs="+", metavar="FILE", default=[],
                    help="raw header blocks or .eml files")
    ap.add_argument("--out", default="audit-out", metavar="DIR",
                    help="output directory for report.md and report.json (default audit-out/)")
    ap.add_argument("--offline", action="store_true",
                    help="no live DNS or network work; analyse only the files given")
    ap.add_argument("--resolver", default="8.8.8.8", help="port-53 resolver (DoH is the fallback)")
    ap.add_argument("--selectors", help="comma-separated DKIM selectors to probe in addition to the common list")
    ap.add_argument("--known", metavar="LIST_OR_FILE",
                    help="known sender domains and IP prefixes for the rua unknown-sender check")
    ap.add_argument("--sender-domain", help="restrict the mail log to this domain and its subdomains")
    ap.add_argument("--auth-column", help="mail-log column holding the DMARC verdict "
                                          "(default: auto-detect a 'DMARC' column)")
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

    domains = [d.strip().lower().rstrip(".") for d in args.domains if d.strip()]
    bad = [d for d in domains if not re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*", d)]
    if bad:
        die("not a domain name: " + ", ".join(bad))

    try:
        report = build_report(
            domains=domains, rua_paths=args.rua, maillog=args.maillog, header_files=args.headers,
            offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, sender_domain=args.sender_domain, auth_column=args.auth_column,
            vendor_domains=args.vendor_domain, authserv_id=args.authserv_id, strict=args.strict,
            min_volume=args.min_volume, fail_threshold=args.fail_threshold,
            since=args.since, until=args.until, expect_policy=args.expect_policy,
            retiring=args.retiring_selector)
    except UsageError as exc:
        die(str(exc))

    try:
        jpath, mpath = write_reports(report, args.out)
    except OSError as exc:
        die(f"cannot write reports: {exc.strerror or exc}")

    g = report["gate"]
    s = report["summary"]
    print(f"gate: {g['verdict']}" + (f" (current policy p={g['current_policy']})" if g["current_policy"] else ""))
    for r in g["reasons"]:
        print(f"  - {r}")
    print(f"findings: {s['findings']} (worst {s['worst'] or 'none'}), "
          f"{s['actionable']} major or blocking")
    print(f"wrote {mpath}")
    print(f"wrote {jpath}")
    sys.exit(report["exit_code"])


if __name__ == "__main__":
    main()
