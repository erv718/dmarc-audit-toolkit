#!/usr/bin/env python3
r"""MCP server exposing this toolkit's read-only DMARC tools to AI clients.

Nothing here writes to DNS, tenant configuration, or vendor settings - the
protocol surface IS the permission boundary. The only write any tool can
perform is the CSV export you explicitly request via out_csv, and that path
is confined to this repo's folder. Credentials for the hunting tool come
from the repo's .env exactly as they do for run_hunting.py, and never
transit the conversation.

Register once and the client launches this file on demand. Give the
registration the absolute path to your clone: an MCP client starts the
server from its own working directory, not from this repo, so a relative
path fails everywhere except inside the repo folder.

  Windows:
    claude mcp add dmarc-audit-toolkit -- python "C:\path\to\dmarc-audit-toolkit\src\mcp_server.py"
  macOS / Linux:
    claude mcp add dmarc-audit-toolkit -- python /path/to/dmarc-audit-toolkit/src/mcp_server.py

Requires: pip install -r requirements-mcp.txt, and AI_ANALYSIS_ENABLED=true
in the repo's .env or in the environment (see .env.example).
"""

import csv
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
sys.path.insert(0, str(ROOT / "src"))

import dedupe as dedupe_mod
import dns_audit
import spf_lookups
import run_hunting
import audit as audit_mod

try:
    import dns.resolver
except ImportError:
    dns = None


def _mcp_import_error():
    """Tell a 1.x install apart from no install: both raise ImportError on
    mcp.server.mcpserver, but the fix is different."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        return "the MCP SDK is not installed - run: pip install -r requirements-mcp.txt"
    found = ""
    try:
        from importlib.metadata import version
        found = " (installed: %s)" % version("mcp")
    except Exception:
        pass
    return ("mcp 1.x found%s; this server needs mcp 2.x - "
            "pip install -r requirements-mcp.txt" % found)


try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    print(_mcp_import_error(), file=sys.stderr)
    sys.exit(2)

server = MCPServer(
    name="dmarc-audit-toolkit",
    instructions=(
        "Read-only DMARC auditing tools. Follow the repo's AGENTS.md: report "
        "deduplicated numbers with the naive count alongside, never diagnose "
        "DNS from a single resolver path, and treat dashboard toggles as "
        "claims, not proof. No tool here can change DNS, mail rules, or "
        "tenant configuration."
    ),
)

ROW_PREVIEW_CAP = 50        # hard ceiling on rows any reply may carry
HUNT_PREVIEW_DEFAULT = 20   # run_hunting_query default; 0 disables the preview
FIELD_CLIP = 300
MAX_DOMAINS = 25

# Every row a tool returns is copied into the client's conversation, which
# may be logged or synced off this machine - AGENTS.md rule 3.
TENANT_DATA_NOTE = (
    "preview rows are live tenant data and have now left this machine via the "
    "conversation; redact company domains, names and IPs before any of it is "
    "published or pasted externally (AGENTS.md rule 3). Pass out_csv to keep "
    "the full result set local, and preview_rows=0 to send no rows at all.")


def _make_resolver(addr):
    """A real port-53 resolver when dnspython is present; the audited
    modules fall back to DNS-over-HTTPS on their own when it fails."""
    if dns is None:
        return None
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [addr]
    r.lifetime = 10
    return r


def _clip(value):
    if isinstance(value, str) and len(value) > FIELD_CLIP:
        return value[:FIELD_CLIP] + "...[truncated]"
    return value


def _clip_row(row):
    return {k: _clip(v) for k, v in row.items()}


def _read_env(path):
    """Parse KEY=VALUE lines fresh on every call, without touching
    os.environ - a long-lived server must see .env edits and secret
    rotations immediately, and must never die on a badly encoded file."""
    values = {}
    try:
        with open(path, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                values[key.strip()] = val.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError) as err:
        return {"__error__": ".env unreadable (%s) - if PowerShell wrote it,"
                             " re-save as UTF-8" % err.__class__.__name__}
    return values


def ai_analysis_enabled():
    """The AI master switch (.env.example): an environment variable wins over
    .env, and only the exact value "true" opts in. Everything else - missing,
    blank, "yes", "1" - means off, because the default must be safe."""
    val = os.environ.get("AI_ANALYSIS_ENABLED")
    if val is None:
        val = _read_env(ENV_PATH).get("AI_ANALYSIS_ENABLED", "")
    return str(val).strip().lower() == "true"


@server.tool()
def audit_dns(domains: list[str], resolver: str = "8.8.8.8") -> dict:
    """Audit the DNS authentication posture of one or more domains: SPF
    presence/terminator/lookup budget, DMARC policy gaps, common DKIM
    selectors (with wildcard detection), and MX. Returns one report per
    domain, exactly as dns_audit.py --json emits it: `flags` (finding
    titles), `findings` (id, severity, evidence, action, verified),
    `dmarc_source` and `inherited` (which label answered, walk-up to the
    organisational domain), `effective_policy`, and `evidence` (every
    lookup with its status). A failed lookup is reported as failed, never
    as absent. Max 25 domains per call."""
    cleaned = [d.strip().lower().rstrip(".") for d in domains if d.strip()]
    if not cleaned:
        return {"error": "no domains given"}
    if len(cleaned) > MAX_DOMAINS:
        return {"error": "more than %d domains in one call - split the list"
                         % MAX_DOMAINS}
    res = _make_resolver(resolver)
    # each report is dns_audit.audit_domain's dict, passed through untouched
    return {"reports": [dns_audit.audit_domain(d, res) for d in cleaned]}


@server.tool()
def walk_spf(domain: str, resolver: str = "8.8.8.8") -> dict:
    """Expand a domain's SPF record recursively and count DNS-querying
    mechanisms against the RFC 7208 limit of ten. Use before recommending
    any new SPF include. `status` is found, absent or error and `evidence`
    names the resolver path that answered; `verified` is false whenever a
    lookup failed, and `lookups` is then a lower bound. A failed lookup is
    never reported as "no SPF record"."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return {"error": "no domain given"}
    if any(c in domain for c in " \t/@"):
        return {"error": "%r is not a domain name" % domain}
    res = _make_resolver(resolver)
    # spf_lookups.analyse is what the CLI renders: get_spf_status for the
    # record and its status, walk for the mechanisms, classify(status,
    # cost, failed) for the verdict - so the two surfaces cannot disagree
    r = spf_lookups.analyse(domain, res)
    failed = sum(1 for m in r["mechanisms"] if m["mechanism"].startswith("LOOKUP FAILED"))
    return {
        "domain": r["domain"],
        "record": r["record"],
        "status": r["status"],
        "evidence": r["evidence"],
        "lookups": r["lookups"],
        "limit": r["limit"],
        "failed_lookups": failed,
        "mechanisms": [_clip_row(m) for m in r["mechanisms"]],
        "verdict": r["verdict"],
        "severity": r["severity"],
        "verified": r["verified"],
        "exit_code": r["exit_code"],
    }


@server.tool()
def dedupe_maillog(
    csv_path: str,
    sender_domain: str | None = None,
    auth_column: str | None = None,
    msgid_column: str = "Internet message ID",
    recipient_column: str = "Recipients",
    sender_column: str = "Sender address",
    domain_column: str = "Sender domain",
    action_column: str = "Delivery action",
    location_column: str = "Latest delivery location",
    subject_column: str = "Subject",
    envelope_column: str = "Sender mail from domain",
    vendor_domains: list[str] | None = None,
) -> dict:
    """Collapse a mail-log CSV into logical messages by Message-ID plus
    recipient and classify each one. Returns the deduplicated failure count
    next to the naive count - a message is failing only if NO copy of it
    passed. Pass auth_column (the DMARC verdict column) to get the two
    crossings dedupe.py reports: delivered_despite_fail (a local override
    let a failing message through) and blocked_despite_pass (something
    other than DMARC caught it); without it 'failure' means never
    delivered. Every genuine failure carries a likely_* label - a
    heuristic from the subject and envelope domain, not a verdict;
    vendor_domains teaches it your vendors' envelope domains. Column
    defaults match a Microsoft 365 Defender 'All email' export; a
    misspelled column is an error, never a silent zero."""
    cols = {"msgid": msgid_column, "recipient": recipient_column,
            "sender": sender_column, "domain": domain_column,
            "action": action_column, "location": location_column,
            "subject": subject_column, "envelope": envelope_column}
    sender_domain = (sender_domain or "").strip().lower() or None
    auth_column = (auth_column or "").strip() or None
    vendors = [v.strip().lower() for v in (vendor_domains or []) if v and v.strip()]
    path = Path(csv_path)
    if not path.is_absolute():
        path = ROOT / path
    if path.is_dir():
        return {"error": "%s is a directory, not a CSV file" % csv_path}
    try:
        header = dedupe_mod.read_header(path)
        rows = list(dedupe_mod.load(str(path), cols))
    except UnicodeDecodeError:
        return {"error": "%s is not UTF-8 (PowerShell may have written UTF-16; "
                         "re-export or convert it)" % csv_path}
    except OSError as err:
        return {"error": "cannot read %s: %s" % (csv_path, err.strerror or err)}
    except csv.Error as err:
        return {"error": "cannot parse %s as CSV: %s" % (csv_path, err)}

    # the same column gate audit.py and dedupe.py apply before counting
    # anything: a typo in a column name dies loudly, it never returns zero
    missing_req, missing_opt = dedupe_mod.check_columns(header, cols, auth_column, sender_domain)
    if missing_req:
        return {"error": "column not found: %s. Available columns: %s"
                         % (", ".join(missing_req), ", ".join(header) or "(none)")}

    counts = dedupe_mod.count_rows(rows, cols, sender_domain, auth_column)
    verdicts = dedupe_mod.classify(rows, cols, sender_domain, auth_column, vendors)
    counts.update(dedupe_mod.summarize(verdicts))
    findings = dedupe_mod.build_findings(counts, verdicts, auth_column, missing_opt, sender_domain)

    def messages_where(flag):
        return [dict(v, msgid=k[0], recipient=k[1]) for k, v in verdicts.items() if v[flag]]

    reply = {
        "source": str(path),
        "sender_domain": sender_domain,
        "auth_column": auth_column,
        "basis": ("auth column %s" % auth_column) if auth_column
                 else "delivery action only (no auth column)",
        "raw_rows": counts["raw_rows"],
        "rows_in_scope": counts["rows_in_scope"],
        "rows_without_msgid": counts["rows_without_msgid"],
        "raw_failing_rows": counts["raw_failing_rows"],
        "logical_messages": counts["logical_messages"],
        "genuine_failures": counts["genuine_failures"],
        "echo_legs_with_a_pass": counts["echo_messages"],
        "relayed_only": counts["relayed_only"],
        "delivered_despite_fail": counts["delivered_despite_fail"],
        "blocked_despite_pass": counts["blocked_despite_pass"],
        "by_likely": counts["by_likely"],
        "counters": counts,
        "findings": findings,
        "summary": {"findings": len(findings),
                    "actionable": sum(1 for f in findings if f["severity"] in ("major", "blocking")),
                    "worst": dedupe_mod.worst_severity(findings),
                    "exit_code": dedupe_mod.exit_code(findings)},
        # the naive number is the raw failing-row count, exactly what the CLI
        # prints - an echo message with two failing legs counts twice there
        "note": "counting rows would report %d failures; the true count is %d"
                % (counts["raw_failing_rows"], counts["genuine_failures"]),
    }
    if missing_opt:
        reply["missing_optional_columns"] = missing_opt
    reply.update(_cap_list(messages_where("genuine_failure"), "genuine_failure_details"))
    reply["detail_truncated"] = reply["genuine_failure_details_truncated"]
    reply.update(_cap_list(messages_where("delivered_despite_fail"), "delivered_despite_fail_details"))
    reply.update(_cap_list(messages_where("blocked_despite_pass"), "blocked_despite_pass_details"))
    return reply


@server.tool()
def run_hunting_query(
    query_file: str,
    timespan: str | None = None,
    out_csv: str | None = None,
    preview_rows: int = HUNT_PREVIEW_DEFAULT,
) -> dict:
    """Run a saved KQL file from queries/ against Microsoft Graph advanced
    hunting, using the read-only App Registration credentials in the repo's
    .env (see docs/app-registration.md). Full results go to out_csv when
    given (a path inside the repo folder); the response carries the row
    count and a preview of at most preview_rows rows (default 20, ceiling
    50, 0 for none). Preview rows are live tenant data entering the
    conversation - prefer out_csv plus a small preview."""
    env = _read_env(ENV_PATH)
    if "__error__" in env:
        return {"error": env["__error__"]}
    creds = {k: env.get(k) or os.environ.get(k) for k in run_hunting.ENV_KEYS}
    missing = [k for k, v in creds.items() if not v]
    if missing:
        return {"error": "missing credentials: " + ", ".join(missing)
                         + " - copy .env.example to .env and fill them in (docs/app-registration.md)"}
    try:
        limit = max(0, min(int(preview_rows), ROW_PREVIEW_CAP))
    except (TypeError, ValueError):
        return {"error": "preview_rows must be an integer from 0 to %d"
                         % ROW_PREVIEW_CAP}
    qpath = Path(query_file)
    if not qpath.is_absolute():
        qpath = ROOT / qpath
    try:
        kql = qpath.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as err:
        return {"error": "cannot read query file: %s" % err}

    try:
        token = run_hunting.get_token(*(creds[k] for k in run_hunting.ENV_KEYS))
        result = run_hunting.run_query(token, kql, timespan)
    except SystemExit as err:
        # run_hunting reports API/network failures via sys.exit; surface the
        # message as a tool error instead of killing the server process.
        return {"error": str(err)}

    rows = result.get("results") or []
    preview = [_clip_row(r) for r in rows[:limit]]
    if limit == 0:
        note = ("preview disabled (preview_rows=0): no result rows entered the "
                "conversation; the full result set is only in out_csv, when "
                "given, and stays on this machine.")
    elif not rows:
        note = "the query returned no rows; nothing entered the conversation."
    else:
        note = TENANT_DATA_NOTE
    reply = {
        "rows": len(rows),
        "columns": [c.get("name") for c in (result.get("schema") or []) if c.get("name")],
        "preview": preview,
        "preview_rows": len(preview),
        "preview_truncated": len(rows) > limit,
        "note": note,
    }
    if "example.com" in kql:
        reply["warning"] = ("the query still targets example.com - edit the "
                            "domain placeholder first")
    if out_csv:
        opath = Path(out_csv)
        opath = (opath if opath.is_absolute() else ROOT / opath).resolve()
        if not opath.is_relative_to(ROOT):
            reply["csv_error"] = ("out_csv must stay inside the repo folder; "
                                  "got a path resolving outside it")
        else:
            try:
                with open(opath, "w", newline="", encoding="utf-8") as fh:
                    run_hunting.write_csv(result, fh)
                reply["csv"] = str(opath)
            except OSError as err:
                reply["csv_error"] = str(err)
    return reply


def _cap_list(items, key):
    """A capped, clipped preview of a list of dicts, plus a truncation flag."""
    rows = [_clip_row(i) if isinstance(i, dict) else i for i in items[:ROW_PREVIEW_CAP]]
    return {key: rows, key + "_truncated": len(items) > ROW_PREVIEW_CAP,
            key + "_total": len(items)}


def _trim_message(m):
    """The decision-relevant fields of one headers.analyze document; the full
    document stays on disk via run_audit's report.json."""
    spf = m.get("spf")
    return _clip_row({
        "file": m["file"], "from": m["from"], "from_domain": m["from_domain"],
        "return_path_domain": m["return_path_domain"],
        "ar_trusted": m["ar_trusted"], "ar_reason": m["ar_reason"],
        "spf": ({"result": spf["result"], "domain": spf.get("domain"),
                 "aligned_relaxed": spf.get("aligned_relaxed")} if spf else None),
        "dkim_signatures": [{"d": s["d"], "s": s["s"], "ar_result": s["ar_result"],
                             "aligned_relaxed": s["aligned_relaxed"]}
                            for s in m["dkim_signatures"]],
        "dmarc": m["dmarc"], "dmarc_would_pass_via": m["dmarc_would_pass_via"],
        "first_external_ip": m["first_external_ip"],
        "platform": (m.get("fingerprint") or {}).get("vendor"),
        "findings": m["findings"],
    })


@server.tool()
def parse_rua(
    paths: list[str],
    known: str | None = None,
    min_volume: int = 20,
    fail_threshold: float = 0.5,
    since: str | None = None,
    until: str | None = None,
    expect_policy: str | None = None,
) -> dict:
    """Parse DMARC aggregate (rua) reports - .xml, .xml.gz, .zip, directories
    recursed - into the receiver-side view: totals, failing streams, SPF-only
    senders, unknown senders, policy seen by reporters. Counts are
    receiver-reported and include forwarded copies; cross-check any failure
    number against the tenant log with dedupe_maillog before reporting it.
    known: comma-separated sender domains/IP prefixes you recognise.
    Relative paths resolve from the repo root."""
    if not paths:
        return {"error": "no paths given"}
    if expect_policy is not None and expect_policy not in ("none", "quarantine", "reject"):
        return {"error": "expect_policy must be one of none, quarantine, reject"}
    try:
        doc = audit_mod.run_rua(paths, known=known, min_volume=min_volume,
                                fail_threshold=fail_threshold, since=since,
                                until=until, expect_policy=expect_policy)
    except audit_mod.UsageError as err:
        return {"error": str(err)}
    reply = {
        "totals": doc["totals"],
        "policy_check": doc["policy_check"],
        "selectors": doc["selectors"][:ROW_PREVIEW_CAP],
        "findings": doc["findings"],
        "warnings": doc["warnings"],
        "summary": doc["summary"],
        "exit_code": doc["exit_code"],
        "note": ("receiver-reported counts include forwarded copies and cannot "
                 "be deduplicated (no Message-ID); the likely_* labels are a "
                 "heuristic, not a verdict. Redact domains and IPs before any "
                 "of this is published or pasted externally."),
    }
    for key in ("failing_streams", "spf_only_senders", "unknown_senders",
                "retiring_selectors", "by_header_from", "by_reporter"):
        reply.update(_cap_list(doc[key], key))
    return reply


@server.tool()
def parse_headers(
    files: list[str],
    authserv_id: str | None = None,
    strict: bool = False,
) -> dict:
    """Analyse raw header blocks or .eml files (directories recursed for
    .txt/.eml): the Authentication-Results worth trusting, every DKIM
    signature's d=/s= and alignment, what DMARC would pass via, the Received
    chain, and a sending-platform fingerprint. Pass authserv_id (the id your
    receiving host writes, e.g. example.com or mail.protection.outlook.com) -
    without it the topmost AR header is trusted unverified, and senders can
    inject that header. Relative paths resolve from the repo root."""
    if not files:
        return {"error": "no files given"}
    try:
        doc = audit_mod.run_headers(files, authserv_id=authserv_id, strict=strict)
    except audit_mod.UsageError as err:
        return {"error": str(err)}
    messages = doc["messages"]
    return {
        "messages": [_trim_message(m) for m in messages[:ROW_PREVIEW_CAP]],
        "messages_truncated": len(messages) > ROW_PREVIEW_CAP,
        "messages_total": len(messages),
        "findings": doc["findings"],
        "ar_note": doc["ar_note"],
        "summary": {"messages": len(messages), "findings": len(doc["findings"]),
                    "worst": audit_mod.worst_severity(doc["findings"])},
    }


@server.tool()
def run_audit(
    domains: list[str] | None = None,
    rua: list[str] | None = None,
    maillog: str | None = None,
    header_files: list[str] | None = None,
    out_dir: str = "audit-out",
    offline: bool = False,
    known: str | None = None,
    sender_domain: str | None = None,
    authserv_id: str | None = None,
) -> dict:
    """Run the full audit: DNS posture (live, unless offline), aggregate
    reports, deduplicated mail log, and message headers, ending in a gate
    verdict (go / no_go / insufficient_data) for the DMARC policy ratchet.
    Writes report.md and report.json into out_dir, which must resolve inside
    the repo folder - those two files are the only writes. The reply carries
    the verdict, a capped findings preview, and the report paths."""
    opath = Path(out_dir)
    opath = (opath if opath.is_absolute() else ROOT / opath).resolve()
    if not opath.is_relative_to(ROOT):
        return {"error": "out_dir must stay inside the repo folder; "
                         "got a path resolving outside it"}
    try:
        report = audit_mod.build_report(
            domains=domains or (), rua_paths=rua or (), maillog=maillog,
            header_files=header_files or (), offline=offline, known=known,
            sender_domain=sender_domain, authserv_id=authserv_id)
    except audit_mod.UsageError as err:
        return {"error": str(err)}
    reply = {
        "gate": report["gate"],
        "summary": report["summary"],
        "offline": report["offline"],
        "note": ("full detail is in the two report files on this machine; the "
                 "preview below may contain tenant data now in the conversation "
                 "- redact before publishing (AGENTS.md rule 3)."),
    }
    reply.update(_cap_list(report["findings"], "findings"))
    try:
        jpath, mpath = audit_mod.write_reports(report, opath)
        reply["report_json"] = str(jpath)
        reply["report_md"] = str(mpath)
    except OSError as err:
        reply["write_error"] = str(err)
    return reply


if __name__ == "__main__":
    if not ai_analysis_enabled():
        # exit 2 (usage), the same status as a missing MCP SDK: the server
        # was asked to run without its prerequisite, nothing failed inside it
        print("AI analysis is off (the deliberate default): set"
              " AI_ANALYSIS_ENABLED=true in the repo's .env, or in the"
              " environment, to start this server. See .env.example.",
              file=sys.stderr)
        sys.exit(2)
    server.run()
