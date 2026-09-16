#!/usr/bin/env python3
"""Run a saved KQL file against Microsoft Graph advanced hunting.

Auth is app-only via an Entra ID App Registration holding the read-only
ThreatHunting.Read.All application permission - see docs/app-registration.md
for the five-minute setup. Credentials come from .env or the environment and
are never printed, logged, or written anywhere by this script.

Usage:
  python src/run_hunting.py queries/genuine_failures.kql --out failures.csv
  python src/run_hunting.py queries/sender_census.kql --timespan P30D
  python src/run_hunting.py queries/sender_census.kql --json

Exit codes: 0 ok, 1 the token or query request failed, 2 usage or input
error (missing credentials, unreadable file, bad path).
"""

import argparse
import csv
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
HUNT_URL = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
ENV_KEYS = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")

# Resolve from this file, not the cwd, so the script finds the same .env
# the MCP server does no matter which folder it is launched from.
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV = ROOT / ".env"


def usage_error(msg):
    """Input or usage problem: clear message on stderr, exit 2, no traceback."""
    print(msg, file=sys.stderr)
    sys.exit(2)


def default_env_file():
    """<repo root>/.env first; ./.env only when the root one is absent."""
    if DEFAULT_ENV.exists():
        return str(DEFAULT_ENV)
    return ".env"


def load_env(path=None):
    """Read KEY=VALUE lines into the environment without overriding it."""
    if path is None:
        path = default_env_file()
    if not os.path.exists(path):
        return
    try:
        # utf-8-sig: PowerShell redirects write a BOM that would otherwise
        # corrupt the first key name into an invisible mismatch.
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.readlines()
    except UnicodeDecodeError:
        usage_error("%s is not UTF-8 (PowerShell may have written UTF-16;"
                    " re-save it as UTF-8)" % path)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def require_creds(env_path=None):
    missing = [k for k in ENV_KEYS if not os.environ.get(k)]
    if missing:
        where = env_path or default_env_file()
        usage_error("missing credentials: " + ", ".join(missing)
                    + "  (put them in %s - see docs/app-registration.md)" % where)
    return tuple(os.environ[k] for k in ENV_KEYS)


def get_token(tenant, client_id, client_secret):
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    req = urllib.request.Request(TOKEN_URL.format(tenant=tenant), data=body)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            token = json.load(resp).get("access_token")
    except urllib.error.HTTPError as err:
        # Deliberately do not echo the response body: keep anything the
        # token endpoint reflects back out of logs and chat transcripts.
        sys.exit("token request failed: HTTP %d - check the tenant id, client id,"
                 " and that the client secret has not expired" % err.code)
    except (OSError, json.JSONDecodeError) as err:
        sys.exit("token request failed before completing: %s"
                 % getattr(err, "reason", err.__class__.__name__))
    if not token:
        sys.exit("token endpoint answered without an access token - check the"
                 " app registration")
    return token


def run_query(token, kql, timespan=None):
    payload = {"Query": kql}
    if timespan:
        payload["Timespan"] = timespan
    req = urllib.request.Request(
        HUNT_URL,
        data=json.dumps(payload).encode(),
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        detail = ""
        try:
            detail = json.loads(err.read()).get("error", {}).get("message", "")
        except Exception:
            pass
        # Remote text: cap length and drop control characters before printing.
        detail = "".join(ch for ch in str(detail) if ch >= " ")[:300]
        hint = {
            400: "the service rejected the query - test the KQL in the portal first",
            401: "token rejected - was admin consent granted?",
            403: "permission denied - the app registration needs the"
                 " ThreatHunting.Read.All application permission with admin consent",
            429: "rate limited - wait a minute and retry",
        }.get(err.code, "")
        sys.exit(("query failed: HTTP %d  %s  %s" % (err.code, hint, detail)).rstrip())
    except (OSError, json.JSONDecodeError) as err:
        sys.exit("query did not complete (network drop or timeout): %s"
                 % getattr(err, "reason", err.__class__.__name__))


def columns(result):
    """Column names from the schema, or from the first row when absent."""
    cols = [c.get("name") for c in (result.get("schema") or []) if c.get("name")]
    rows = result.get("results") or []
    if not cols and rows:
        cols = list(rows[0].keys())
    return cols


def write_csv(result, out):
    cols = columns(result)
    rows = result.get("results") or []
    writer = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return len(rows)


def main():
    ap = argparse.ArgumentParser(
        description="Run a saved KQL file against Microsoft Graph advanced hunting.")
    ap.add_argument("query", help="path to a .kql file")
    ap.add_argument("--out", help="CSV output path (default: stdout)")
    ap.add_argument("--timespan",
                    help="ISO 8601 duration such as P7D or P30D; the narrower of"
                         " this and the KQL's own time filter wins")
    ap.add_argument("--env-file",
                    help="credentials file (default: <repo root>/.env, then ./.env)")
    ap.add_argument("--json", action="store_true",
                    help="print a JSON object to stdout instead of CSV; with"
                         " --out the rows go to the CSV and the JSON carries"
                         " the count, columns and csv path only")
    args = ap.parse_args()

    env_file = args.env_file or default_env_file()
    if args.env_file and not os.path.exists(env_file):
        usage_error("env file not found: %s" % env_file)
    load_env(env_file)
    tenant, client_id, client_secret = require_creds(env_file)
    try:
        with open(args.query, encoding="utf-8-sig") as fh:
            kql = fh.read()
    except OSError as err:
        usage_error("cannot read query file: %s" % err)
    except UnicodeDecodeError:
        usage_error("%s is not UTF-8 - re-save the query file as UTF-8" % args.query)
    warning = None
    if "example.com" in kql:
        warning = ("the query still targets example.com - edit the domain"
                   " placeholder first")
        print("warning: " + warning, file=sys.stderr)

    token = get_token(tenant, client_id, client_secret)
    result = run_query(token, kql, args.timespan)
    rows = result.get("results") or []

    count = len(rows)
    if args.out:
        try:
            with open(args.out, "w", newline="", encoding="utf-8") as fh:
                count = write_csv(result, fh)
        except OSError as err:
            usage_error("cannot write output file: %s" % err)
        if not args.json:
            print("%d rows -> %s" % (count, args.out), file=sys.stderr)

    if args.json:
        doc = {"query": args.query, "timespan": args.timespan,
               "rows": count, "columns": columns(result)}
        if args.out:
            doc["csv"] = args.out
        else:
            doc["results"] = rows
        if warning:
            doc["warning"] = warning
        json.dump(doc, sys.stdout, indent=2)
        print()
    elif not args.out:
        # Re-wrap stdout: without newline="" the csv module's \r\n gets
        # doubled on Windows, and the console codepage can choke on
        # non-Latin subject lines.
        out = io.TextIOWrapper(sys.stdout.buffer, newline="", encoding="utf-8")
        write_csv(result, out)
        out.flush()


if __name__ == "__main__":
    main()
