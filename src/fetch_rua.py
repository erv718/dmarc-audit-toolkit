#!/usr/bin/env python3
"""Pull DMARC aggregate reports out of a mailbox through Microsoft Graph.

Receivers mail aggregate (rua) reports as .xml, .xml.gz or .zip attachments
to the address on your DMARC record. Point that address at a mailbox you
own, give the app registration Mail.Read scoped to that one mailbox
(docs/app-registration.md), and this pulls every new report into a folder
that src/rua_parse.py and src/audit.py --rua read. A state file remembers
the newest message seen, so each run fetches only what is new; the first
run backfills everything the mailbox holds - years, if it has them.

Read-only: nothing is marked, moved or deleted in the mailbox.

  python src/fetch_rua.py --mailbox reports@example.com --out audit-out/rua
  python src/fetch_rua.py --mailbox reports@example.com --out audit-out/rua --since 2026-01-01

Exit codes: 0 ok, 1 Graph failure, 2 usage error.
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

import graph_client
import run_hunting

REPORT_SUFFIXES = (".xml", ".xml.gz", ".gz", ".zip")
MAX_ATTACHMENT = 50 * 1024 * 1024
EPOCH = "1970-01-01T00:00:00Z"


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def is_report_name(name):
    return str(name or "").lower().endswith(REPORT_SUFFIXES)


def safe_name(received, name):
    """<received compact>_<attachment name with anything odd replaced>."""
    stamp = re.sub(r"[^0-9]", "", str(received or ""))[:14] or "unknown"
    clean = re.sub(r"[^A-Za-z0-9._!-]", "_", str(name))[:150]
    return "%s_%s" % (stamp, clean)


def load_state(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


STATE_EVERY = 50  # messages between state saves: a crash loses at most this much progress


def save_state(state_file, newest, mailbox, notes):
    """Remember the newest message seen; a failure is a note, never a crash."""
    if not (state_file and newest):
        return
    try:
        Path(state_file).write_text(json.dumps({"last_received": newest, "mailbox": mailbox}), encoding="utf-8")
    except OSError as err:
        notes.append("state not saved: %s" % err)


def fetch(tok, mailbox, dest_dir, state_file=None, since=None, max_messages=500):
    """Download new report attachments. Returns (saved_count, notes).

    tok may be a token string or a graph_client.TokenSource: the second
    keeps a backfill alive past one token's lifetime. Messages come oldest
    first, so the state file is safe to save every STATE_EVERY messages:
    everything before the saved timestamp has been handled."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    state = load_state(state_file) if state_file else {}
    since = since or state.get("last_received") or EPOCH
    if len(since) == 10:
        since += "T00:00:00Z"
    box = urllib.parse.quote(mailbox)
    params = {"$filter": "receivedDateTime ge %s and hasAttachments eq true" % since,
              "$select": "id,receivedDateTime,subject,hasAttachments",
              "$orderby": "receivedDateTime asc", "$top": "50"}
    saved, seen, notes, newest = 0, 0, [], state.get("last_received")
    skipped, hold = 0, None  # hold: the first skipped message's time; the state never moves past it
    for msg in graph_client.get_all(tok, "users/%s/messages" % box, params):
        seen += 1
        if seen > max_messages:
            notes.append("stopped after %d messages; run again to continue the backfill" % max_messages)
            seen -= 1
            break
        try:
            atts = graph_client.get(tok, "users/%s/messages/%s/attachments" % (box, msg["id"]))
        except graph_client.GraphError as err:
            # one unreadable message must not end a backfill of thousands;
            # the state stays before it, so the next run tries it again
            skipped += 1
            hold = hold or msg.get("receivedDateTime")
            if skipped <= 5:
                notes.append("message received %s skipped, attachments not read: %s"
                             % (msg.get("receivedDateTime"), err))
            continue
        for att in atts.get("value", []):
            name = att.get("name", "")
            if not is_report_name(name):
                continue
            if (att.get("size") or 0) > MAX_ATTACHMENT:
                notes.append("skipped oversized attachment %s (%d bytes)" % (name, att.get("size")))
                continue
            data = att.get("contentBytes")
            if not data:
                continue
            path = dest / safe_name(msg.get("receivedDateTime"), name)
            if path.exists():
                continue
            try:
                path.write_bytes(base64.b64decode(data))
                saved += 1
            except (OSError, ValueError) as err:
                notes.append("could not save %s: %s" % (name, err.__class__.__name__))
        received = msg.get("receivedDateTime")
        if received and (newest is None or received > newest):
            newest = received
        if seen % STATE_EVERY == 0:
            save_state(state_file, resume_point(newest, hold), mailbox, notes)
    save_state(state_file, resume_point(newest, hold), mailbox, notes)
    if skipped:
        notes.append("%d message(s) skipped this run; the state file stays at %s so they are tried again"
                     % (skipped, resume_point(newest, hold)))
    notes.append("report mailbox: %d message(s) checked, %d new report file(s) saved to %s" % (seen, saved, dest))
    return saved, notes


def resume_point(newest, hold):
    """The timestamp to remember: the newest message handled, unless one was
    skipped earlier, in which case that one, so a rerun starts there."""
    if hold and (newest is None or hold < newest):
        return hold
    return newest


def main():
    ap = argparse.ArgumentParser(description="Pull DMARC aggregate reports out of a mailbox (read-only).")
    ap.add_argument("--mailbox", help="the mailbox on your rua= line (default: RUA_MAILBOX from .env)")
    ap.add_argument("--out", required=True, metavar="DIR", help="folder for the report files")
    ap.add_argument("--since", metavar="YYYY-MM-DD", help="ignore messages before this day (default: the state file, else everything)")
    ap.add_argument("--state", metavar="FILE", help="state file remembering the newest message (default: <out>/../rua_state.json)")
    ap.add_argument("--max", type=int, default=500, help="messages per run (default 500)")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    args = ap.parse_args()

    try:
        cred = graph_client.creds(args.env_file)
    except graph_client.GraphError as err:
        die(str(err))
    if cred is None:
        die("missing credentials: " + ", ".join(graph_client.missing_keys())
            + " - copy .env.example to .env and fill them in (docs/app-registration.md)")
    mailbox = args.mailbox or os.environ.get("RUA_MAILBOX")
    if not mailbox:
        die("no mailbox: pass --mailbox or set RUA_MAILBOX in .env")
    state = args.state or str(Path(args.out).parent / "rua_state.json")
    try:
        tok = graph_client.TokenSource(cred)  # re-acquires past the token lifetime
        saved, notes = fetch(tok, mailbox, args.out, state, args.since, args.max)
    except graph_client.GraphError as err:
        print("error: " + str(err), file=sys.stderr)
        sys.exit(1)
    for n in notes:
        print(n)


if __name__ == "__main__":
    main()
