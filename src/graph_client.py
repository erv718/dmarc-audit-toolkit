#!/usr/bin/env python3
"""Shared Microsoft Graph helpers for the tools that talk to a tenant.

App-only (client credentials) against the read-only App Registration from
docs/app-registration.md. Everything here raises GraphError instead of
exiting, so the callers (verify_setup.py, discover.py, collect.py) decide what
a failure means. Nothing in this module prints a token or a secret.

Credentials come from .env (AZURE_TENANT_ID, AZURE_CLIENT_ID,
AZURE_CLIENT_SECRET) exactly as run_hunting.py reads them.
"""

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

import run_hunting

GRAPH = "https://graph.microsoft.com/v1.0"


class GraphError(Exception):
    """A Graph or token failure with the HTTP status when there was one."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def creds(env_file=None):
    """(tenant, client_id, secret) from .env or the environment, or None."""
    try:
        run_hunting.load_env(env_file)
    except SystemExit as err:
        raise GraphError("credentials file unreadable: %s" % err)
    values = [os.environ.get(k) for k in run_hunting.ENV_KEYS]
    if not all(values):
        return None
    return tuple(values)


def missing_keys():
    return [k for k in run_hunting.ENV_KEYS if not os.environ.get(k)]


def token(cred):
    """Access token for the Graph .default scope. Never printed."""
    try:
        return run_hunting.get_token(*cred)
    except SystemExit as err:
        raise GraphError(str(err))


def jwt_claims(tok):
    """Decode the payload of a JWT without verifying it - only to read the
    roles the token carries. Not a security check; the service verifies."""
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except Exception:
        return {}


def roles(tok):
    return sorted(jwt_claims(tok).get("roles", []) or [])


def get(tok, url, params=None):
    """GET a Graph URL (absolute, or a path under GRAPH). Returns JSON."""
    if not url.startswith("http"):
        url = GRAPH + "/" + url.lstrip("/")
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        detail = ""
        try:
            detail = json.loads(err.read()).get("error", {}).get("message", "")
        except Exception:
            pass
        detail = "".join(ch for ch in str(detail) if ch >= " ")[:300]
        raise GraphError("HTTP %d on %s: %s" % (err.code, url.split("?")[0], detail), err.code)
    except (OSError, json.JSONDecodeError) as err:
        raise GraphError("request did not complete: %s"
                         % getattr(err, "reason", err.__class__.__name__))


def get_all(tok, url, params=None):
    """Iterate every item of a paged collection (follows @odata.nextLink)."""
    page = get(tok, url, params)
    while True:
        for item in page.get("value", []):
            yield item
        nxt = page.get("@odata.nextLink")
        if not nxt:
            break
        page = get(tok, nxt)


def list_domains(tok):
    """Every domain the tenant knows about, verified or not.

    Needs Domain.Read.All (least privilege) or Directory.Read.All.
    """
    out = []
    for d in get_all(tok, "domains", {"$select": "id,isVerified,isDefault,isInitial,"
                                                   "supportedServices,authenticationType"}):
        out.append({
            "domain": str(d.get("id", "")).lower().rstrip("."),
            "verified": bool(d.get("isVerified")),
            "default": bool(d.get("isDefault")),
            "initial": bool(d.get("isInitial")),
            "services": list(d.get("supportedServices") or []),
            "authentication_type": d.get("authenticationType"),
        })
    return [d for d in out if d["domain"]]


def hunting(tok, kql, timespan=None):
    """Run a KQL query through the advanced hunting endpoint."""
    try:
        return run_hunting.run_query(tok, kql, timespan)
    except SystemExit as err:
        raise GraphError(str(err))


def mailbox_messages(tok, mailbox, top=1, select="id,subject,receivedDateTime,hasAttachments"):
    """First messages of a mailbox. Needs Mail.Read, scoped by an
    Application Access Policy to this one mailbox."""
    url = "users/%s/messages" % urllib.parse.quote(mailbox)
    return get(tok, url, {"$top": top, "$select": select, "$orderby": "receivedDateTime desc"}).get("value", [])
