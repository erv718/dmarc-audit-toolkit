#!/usr/bin/env python3
"""Prove the app registration works, and that it is not over-permissioned.

Run this once after docs/app-registration.md, and again whenever a run
starts failing. Every check prints PASS, WARN or FAIL with the exact fix.
Nothing here writes to the tenant, and no token or secret is ever printed.

  python src/verify_setup.py
  python src/verify_setup.py --expect-denied someone.else@example.com
  python src/verify_setup.py --json

Checks:
  1. credentials present in .env
  2. a token can be obtained (tenant id, client id, secret all valid)
  3. roles the token carries: required, recommended, and anything EXTRA
     (a leaked secret can do everything the extras allow, so they are flagged)
  4. GET /domains works (Domain.Read.All or Directory.Read.All)
  5. an advanced hunting query works (ThreatHunting.Read.All)
  6. the report mailbox can be read (Mail.Read), when RUA_MAILBOX is set
  7. optional: another mailbox is DENIED, proving the Application Access
     Policy scopes Mail.Read to the report mailbox only

Exit codes: 0 every check passed (warnings allowed), 1 a check failed,
2 usage error.
"""

import argparse
import json
import os
import sys

import graph_client
import run_hunting

REQUIRED = {"ThreatHunting.Read.All": "run the hunting queries (30-day mail-flow data)"}
DOMAIN_ROLES = {"Domain.Read.All": "list the tenant's domains (least privilege)",
                "Directory.Read.All": "list the tenant's domains (broader than needed; Domain.Read.All suffices)"}
MAIL_ROLES = {"Mail.Read": "read the aggregate report mailbox (must be scoped by an Application Access Policy)",
              "Mail.ReadBasic.All": "read mailbox metadata (not enough for attachments)"}
ALLOWED = set(REQUIRED) | set(DOMAIN_ROLES) | set(MAIL_ROLES)
WRITE_MARKERS = ("ReadWrite", "Write", "Manage", "FullControl", "Send", "Create", "Delete")


def check(results, name, status, detail, fix=""):
    results.append({"check": name, "status": status, "detail": detail, "fix": fix})


def role_review(roles):
    """Classify the token's roles against what the toolkit needs."""
    have = set(roles)
    review = {"required_missing": sorted(set(REQUIRED) - have),
              "domain_role": next((r for r in DOMAIN_ROLES if r in have), None),
              "mail_role": next((r for r in MAIL_ROLES if r in have), None),
              "extra": sorted(have - ALLOWED),
              "extra_write": sorted(r for r in have - ALLOWED if any(m in r for m in WRITE_MARKERS))}
    return review


def run_checks(env_file=None, expect_denied=None, mailbox=None):
    results = []

    # 1. credentials
    try:
        cred = graph_client.creds(env_file)
    except graph_client.GraphError as err:
        check(results, "credentials", "FAIL", str(err), "re-save .env as UTF-8")
        return results
    if cred is None:
        check(results, "credentials", "FAIL",
              "missing: " + ", ".join(graph_client.missing_keys()),
              "copy .env.example to .env and fill AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
        return results
    check(results, "credentials", "PASS", "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET present")

    # 2. token
    try:
        tok = graph_client.token(cred)
    except graph_client.GraphError as err:
        check(results, "token", "FAIL", str(err),
              "check the tenant id and client id, and that the client secret has not expired "
              "(Certificates & secrets on the app registration)")
        return results
    check(results, "token", "PASS", "token obtained (never printed)")

    # 3. roles
    roles = graph_client.roles(tok)
    rv = role_review(roles)
    if not roles:
        check(results, "roles", "FAIL", "the token carries no application roles",
              "add the Application permissions and click Grant admin consent - without consent the "
              "token is issued with no roles")
    elif rv["required_missing"]:
        check(results, "roles", "FAIL", "missing required: " + ", ".join(rv["required_missing"]),
              "add %s as an Application permission and grant admin consent"
              % ", ".join(rv["required_missing"]))
    else:
        check(results, "roles", "PASS", "present: " + ", ".join(roles))
    if not rv["domain_role"]:
        check(results, "roles: domain list", "WARN", "no Domain.Read.All - discover.py cannot read the tenant's domains",
              "add Domain.Read.All (Application) and grant admin consent; or pass domains on the command line")
    elif rv["domain_role"] == "Directory.Read.All":
        check(results, "roles: domain list", "WARN", "Directory.Read.All present - broader than needed",
              "replace with Domain.Read.All (least privilege)")
    if rv["extra_write"]:
        check(results, "roles: excess (write-capable)", "WARN",
              "the app can WRITE through: " + ", ".join(rv["extra_write"]),
              "this toolkit is read-only; remove these permissions so a leaked secret cannot change anything")
    extra_read = [r for r in rv["extra"] if r not in rv["extra_write"]]
    if extra_read:
        check(results, "roles: excess (read)", "WARN", "not needed by this toolkit: " + ", ".join(extra_read),
              "remove to keep the registration at least privilege")
    check(results, "roles: note", "PASS",
          "Exchange.ManageAsApp does not appear in a Graph token; check its Exchange role assignment "
          "separately (it should be a view-only role)")

    # 4. domains
    try:
        doms = graph_client.list_domains(tok)
        check(results, "GET /domains", "PASS", "%d domains, %d verified"
              % (len(doms), sum(1 for d in doms if d["verified"])))
    except graph_client.GraphError as err:
        sev = "WARN" if err.status in (401, 403) else "FAIL"
        check(results, "GET /domains", sev, str(err),
              "add Domain.Read.All (Application) with admin consent; until then pass domains on the command line")

    # 5. hunting
    try:
        res = graph_client.hunting(tok, "EmailEvents | take 1", "P1D")
        n = len(res.get("results") or [])
        check(results, "advanced hunting", "PASS", "query ran (%d row returned)" % n)
    except graph_client.GraphError as err:
        check(results, "advanced hunting", "FAIL", str(err),
              "ThreatHunting.Read.All (Application) with admin consent; if the tenant has no Defender for "
              "Office 365 plan the endpoint answers 403 regardless")

    # 6. report mailbox
    mailbox = mailbox or os.environ.get("RUA_MAILBOX")
    if mailbox:
        try:
            msgs = graph_client.mailbox_messages(tok, mailbox, top=1)
            check(results, "report mailbox", "PASS", "%s readable (%d message sampled)" % (mailbox, len(msgs)))
        except graph_client.GraphError as err:
            check(results, "report mailbox", "FAIL", str(err),
                  "Mail.Read (Application) with admin consent, and an Application Access Policy that "
                  "includes %s: New-ApplicationAccessPolicy -AppId <client id> -PolicyScopeGroupId %s "
                  "-AccessRight RestrictAccess" % (mailbox, mailbox))
    else:
        check(results, "report mailbox", "WARN", "RUA_MAILBOX not set - aggregate report ingestion is off",
              "set RUA_MAILBOX=<the mailbox on your rua= line> in .env to enable it")

    # 7. scope proof
    if expect_denied:
        try:
            graph_client.mailbox_messages(tok, expect_denied, top=1)
            check(results, "mailbox scope", "FAIL", "%s is READABLE - Mail.Read is not scoped" % expect_denied,
                  "create the Application Access Policy (RestrictAccess) for the report mailbox group and "
                  "re-run; Test-ApplicationAccessPolicy must say Denied for other users")
        except graph_client.GraphError as err:
            if err.status in (403, 404):
                check(results, "mailbox scope", "PASS", "%s denied (HTTP %d) - policy in effect" % (expect_denied, err.status))
            else:
                check(results, "mailbox scope", "WARN", "unexpected answer: %s" % err, "re-run; if it persists, check the policy")
    return results


def main():
    ap = argparse.ArgumentParser(description="Prove the app registration works and is not over-permissioned.")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    ap.add_argument("--mailbox", help="report mailbox to test (default: RUA_MAILBOX from .env)")
    ap.add_argument("--expect-denied", metavar="USER", help="a mailbox the app must NOT be able to read")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = run_checks(args.env_file, args.expect_denied, args.mailbox)
    failed = any(r["status"] == "FAIL" for r in results)
    if args.json:
        print(json.dumps({"results": results, "ok": not failed}, indent=1))
    else:
        for r in results:
            print("%-5s %-28s %s" % (r["status"], r["check"], r["detail"]))
            if r["fix"] and r["status"] != "PASS":
                print("      fix: %s" % r["fix"])
        print()
        print("setup: %s" % ("FAILED - fix the items above" if failed else "OK"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
