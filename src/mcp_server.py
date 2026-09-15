#!/usr/bin/env python3
"""MCP server exposing this toolkit's read-only DMARC tools to AI clients.

Nothing here writes to DNS, tenant configuration, or vendor settings - the
protocol surface IS the permission boundary. The only write any tool can
perform is the CSV export you explicitly request via out_csv, and that path
is confined to this repo's folder. Credentials for the hunting tool come
from the repo's .env exactly as they do for run_hunting.py, and never
transit the conversation.

Register once and the client launches this file on demand:

  claude mcp add dmarc-audit-toolkit -- python src/mcp_server.py

Requires: pip install -r requirements-mcp.txt
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

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    sys.exit("the MCP SDK is not installed - run: pip install -r requirements-mcp.txt")

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

ROW_PREVIEW_CAP = 50
FIELD_CLIP = 300
MAX_DOMAINS = 25


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


@server.tool()
def audit_dns(domains: list[str], resolver: str = "8.8.8.8") -> dict:
    """Audit the DNS authentication posture of one or more domains: SPF
    presence/terminator/lookup budget, DMARC policy gaps, common DKIM
    selectors (with wildcard detection), and MX. Returns one report per
    domain with a `flags` list of findings. Max 25 domains per call."""
    cleaned = [d.strip().lower().rstrip(".") for d in domains if d.strip()]
    if not cleaned:
        return {"error": "no domains given"}
    if len(cleaned) > MAX_DOMAINS:
        return {"error": "more than %d domains in one call - split the list"
                         % MAX_DOMAINS}
    res = _make_resolver(resolver)
    return {"reports": [dns_audit.audit_domain(d, res) for d in cleaned]}


@server.tool()
def walk_spf(domain: str, resolver: str = "8.8.8.8") -> dict:
    """Expand a domain's SPF record recursively and count DNS-querying
    mechanisms against the RFC 7208 limit of ten. Use before recommending
    any new SPF include."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return {"error": "no domain given"}
    res = _make_resolver(resolver)
    record = spf_lookups.get_spf(domain, res)
    entries = spf_lookups.walk(domain, res)
    cost = sum(1 for _, _, _, billable in entries if billable)
    return {
        "domain": domain,
        "record": record,
        "lookups": cost,
        "limit": spf_lookups.LIMIT,
        "mechanisms": [_clip_row({"depth": d, "owner": o, "mechanism": m,
                                  "counts": b}) for d, o, m, b in entries],
        "verdict": ("no SPF record" if record is None
                    else "OVER LIMIT - SPF returns PERMERROR" if cost > spf_lookups.LIMIT
                    else "at the limit - no room for another vendor" if cost == spf_lookups.LIMIT
                    else "one include away from breaking - new senders need DKIM"
                    if cost == spf_lookups.LIMIT - 1 else "ok"),
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
) -> dict:
    """Collapse a mail-log CSV into logical messages by Message-ID and
    classify each one. Returns the deduplicated failure count next to the
    naive count - a message is failing only if NO copy of it passed.
    Column defaults match a Microsoft 365 Defender 'All email' export."""
    cols = {"msgid": msgid_column, "recipient": recipient_column,
            "sender": sender_column, "domain": domain_column,
            "action": action_column, "location": location_column,
            "subject": subject_column}
    path = Path(csv_path)
    if not path.is_absolute():
        path = ROOT / path
    try:
        rows = list(dedupe_mod.load(str(path), cols))
    except (OSError, UnicodeDecodeError, csv.Error) as err:
        return {"error": "cannot read %s: %s" % (csv_path, err)}
    verdicts = dedupe_mod.classify(rows, cols, sender_domain, auth_column)
    genuine = [dict(v, msgid=k[0], recipient=k[1]) for k, v in verdicts.items()
               if v["genuine_failure"]]
    echoes = sum(1 for v in verdicts.values() if v["echo_present"])
    naive = len(genuine) + echoes
    return {
        "raw_rows": len(rows),
        "logical_messages": len(verdicts),
        "genuine_failures": len(genuine),
        "echo_legs_with_a_pass": echoes,
        "relayed_only": sum(1 for v in verdicts.values() if v["relayed_only"]),
        "genuine_failure_details": [_clip_row(g) for g in genuine[:ROW_PREVIEW_CAP]],
        "detail_truncated": len(genuine) > ROW_PREVIEW_CAP,
        "note": "counting rows would report %d failures; the true count is %d"
                % (naive, len(genuine)),
    }


@server.tool()
def run_hunting_query(
    query_file: str,
    timespan: str | None = None,
    out_csv: str | None = None,
) -> dict:
    """Run a saved KQL file from queries/ against Microsoft Graph advanced
    hunting, using the read-only App Registration credentials in the repo's
    .env (see docs/app-registration.md). Full results go to out_csv when
    given (a path inside the repo folder); the response carries the row
    count and a capped preview so large result sets stay out of the
    conversation."""
    env = _read_env(ENV_PATH)
    if "__error__" in env:
        return {"error": env["__error__"]}
    creds = {k: env.get(k) or os.environ.get(k) for k in run_hunting.ENV_KEYS}
    missing = [k for k, v in creds.items() if not v]
    if missing:
        return {"error": "missing credentials: " + ", ".join(missing)
                         + " - put them in .env, see docs/app-registration.md"}
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
    reply = {
        "rows": len(rows),
        "columns": [c.get("name") for c in (result.get("schema") or []) if c.get("name")],
        "preview": [_clip_row(r) for r in rows[:ROW_PREVIEW_CAP]],
        "preview_truncated": len(rows) > ROW_PREVIEW_CAP,
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


if __name__ == "__main__":
    server.run()
