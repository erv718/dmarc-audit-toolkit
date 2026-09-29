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
  3b. the consent grants behind those roles, with the date each was granted -
      the self-proving answer to "the portal says I removed that already"
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
# The color helper lives in console.py so every tool paints the same way;
# Paint, color_wanted and enable_windows_ansi stay importable from here.
from console import Paint, color_wanted, enable_windows_ansi, painter

REQUIRED = {"ThreatHunting.Read.All": "run the hunting queries (30-day mail-flow data)"}
DOMAIN_ROLES = {"Domain.Read.All": "list the tenant's domains (least privilege)",
                "Directory.Read.All": "list the tenant's domains (broader than needed; Domain.Read.All suffices)"}
MAIL_ROLES = {"Mail.Read": "read the aggregate report mailbox (must be scoped by an Application Access Policy)",
              "Mail.ReadBasic.All": "read mailbox metadata (not enough for attachments)"}
ALLOWED = set(REQUIRED) | set(DOMAIN_ROLES) | set(MAIL_ROLES)
WRITE_MARKERS = ("ReadWrite", "Write", "Manage", "FullControl", "Send", "Create", "Delete")
GRANT_READERS = ("Application.Read.All", "Directory.Read.All")

STATUSES = ("PASS", "WARN", "FAIL", "INFO")


def check(results, name, status, detail, fix="", lines=None):
    entry = {"check": name, "status": status, "detail": detail, "fix": fix}
    if lines:
        entry["lines"] = lines
    results.append(entry)


def role_review(roles):
    """Classify the token's roles against what the toolkit needs."""
    have = set(roles)
    review = {"required_missing": sorted(set(REQUIRED) - have),
              "domain_role": next((r for r in DOMAIN_ROLES if r in have), None),
              "mail_role": next((r for r in MAIL_ROLES if r in have), None),
              "extra": sorted(have - ALLOWED),
              "extra_write": sorted(r for r in have - ALLOWED if any(m in r for m in WRITE_MARKERS))}
    return review


def sp_grants(tok, client_id):
    """(role name, granted-on date) per consent grant on the app's service
    principal. This is the live tenant truth behind the token's role list:
    a permission 'removed' in the portal still works until its grant here is
    revoked, and this list shows each grant's birthday."""
    sps = graph_client.get(tok, "/servicePrincipals", params={
        "$filter": "appId eq '%s'" % client_id,
        "$select": "id,appDisplayName"}).get("value") or []
    if not sps:
        raise graph_client.GraphError("no service principal found for this client id")
    assignments = graph_client.get(
        tok, "/servicePrincipals/%s/appRoleAssignments" % sps[0]["id"]).get("value") or []
    names_by_resource = {}
    grants = []
    for a in assignments:
        rid = a.get("resourceId")
        if rid not in names_by_resource:
            try:
                res = graph_client.get(tok, "/servicePrincipals/%s" % rid,
                                       params={"$select": "appRoles"})
                names_by_resource[rid] = {r["id"]: r.get("value") for r in res.get("appRoles") or []}
            except graph_client.GraphError:
                # one unreadable catalog (the big first-party ones are heavy)
                # must not hide the rest of the grants
                names_by_resource[rid] = {}
        name = (names_by_resource[rid].get(a.get("appRoleId"))
                or "role id %s" % str(a.get("appRoleId"))[:8])
        grants.append((name, (a.get("createdDateTime") or "?")[:10]))
    return sorted(grants)


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
        check(results, "roles", "PASS",
              "granted to the app right now, per the token just issued: " + ", ".join(roles))
    if not rv["domain_role"]:
        check(results, "roles: domain list", "WARN", "no Domain.Read.All - discover.py cannot read the tenant's domains",
              "add Domain.Read.All (Application) and grant admin consent; or pass domains on the command line")
    elif rv["domain_role"] == "Directory.Read.All":
        check(results, "roles: domain list", "WARN", "Directory.Read.All present - broader than needed",
              "replace with Domain.Read.All (least privilege)")
    revoke_hint = ("remove under BOTH App registrations > API permissions and Enterprise applications > "
                   "Permissions (the grant lives in both places); new tokens drop the role within ~30 minutes")
    if rv["extra_write"]:
        check(results, "roles: excess (write-capable)", "WARN",
              "the app can WRITE through: " + ", ".join(rv["extra_write"]),
              "this toolkit is read-only; " + revoke_hint)
    extra_read = [r for r in rv["extra"] if r not in rv["extra_write"]]
    if extra_read:
        check(results, "roles: excess (read)", "WARN", "not needed by this toolkit: " + ", ".join(extra_read),
              "least privilege: " + revoke_hint)
    check(results, "roles: note", "INFO",
          "Exchange.ManageAsApp does not appear in a Graph token; check its Exchange role assignment "
          "separately (it should be a view-only role)")

    # 3b. grant provenance
    if set(roles) & set(GRANT_READERS):
        try:
            grants = sp_grants(tok, cred[1])
            check(results, "roles: grant dates", "INFO",
                  "%d consent grant(s) on the service principal, live from Graph - "
                  "a role above works until its grant here is revoked" % len(grants),
                  lines=["%s  granted %s" % (name, when) for name, when in grants])
        except graph_client.GraphError as err:
            check(results, "roles: grant dates", "WARN", "could not enumerate grants: %s" % err)
    else:
        check(results, "roles: grant dates", "INFO",
              "skipped - listing consent grants needs %s (read-only)" % " or ".join(GRANT_READERS))

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


def print_report(results, paint):
    print(paint.bold("dmarc-audit-toolkit - setup verification"))
    print(paint.dim("read-only checks; no token or secret is ever printed"))
    print()
    for r in results:
        tag = paint.status(r["status"]) + " " * max(0, 5 - len(r["status"]))
        print("%s %-28s %s" % (tag, r["check"], r["detail"]))
        for line in r.get("lines", []):
            print(paint.dim("      %s" % line))
        if r["fix"] and r["status"] not in ("PASS", "INFO"):
            print(paint.dim("      fix: %s" % r["fix"]))
    counts = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    failed = counts["FAIL"]
    print()
    verdict = "FAILED - fix the items above" if failed else (
        "OK" if not counts["WARN"] else "OK - with warnings worth fixing")
    tail = "%d passed, %d warnings, %d failed" % (counts["PASS"], counts["WARN"], failed)
    banner = "setup: %s (%s)" % (verdict, tail)
    level = "fail" if failed else ("warn" if counts["WARN"] else "ok")
    print(paint.banner(banner, level))


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
        print_report(results, painter(sys.stdout))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
