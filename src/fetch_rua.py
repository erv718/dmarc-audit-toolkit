#!/usr/bin/env python3
"""Pull DMARC aggregate reports out of a mailbox through Microsoft Graph.

Receivers mail aggregate (rua) reports as .xml, .xml.gz or .zip attachments
to the address on your DMARC record. Point that address at a mailbox you
own, give the app registration Mail.Read scoped to that one mailbox
(docs/app-registration.md), and this pulls every new report into a folder
that src/rua_parse.py and src/audit.py --rua read. A state file remembers
the newest message seen, so each run fetches only what is new. Standalone,
the first run backfills everything the mailbox holds - years, if it has
them; collect.py's weekly job starts at its 30-day archive window instead.

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


def save_state(state_file, newest, mailbox, notes, covered=None, extra=None):
    """Remember the newest message handled, where the archive's unbroken
    coverage starts when known, and any unfinished --since backfill (extra);
    a failure is a note, never a crash."""
    if not (state_file and newest):
        return
    doc = {"last_received": newest, "mailbox": mailbox}
    if covered:
        doc["covered_from"] = covered
    doc.update(extra or {})
    try:
        Path(state_file).write_text(json.dumps(doc), encoding="utf-8")
    except OSError as err:
        notes.append("state not saved: %s" % err)


PAGE = 20  # messages per listing call when the attachments come back inline


def _iso(value):
    """A YYYY-MM-DD day as the start of that day in ISO form; anything else as given."""
    value = str(value or "")
    return value + "T00:00:00Z" if len(value) == 10 else value


def _save_reports(atts, msg, dest, notes):
    """Write one message's report attachments; returns how many files are new."""
    saved = 0
    for att in atts or []:
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
    return saved


def _inline_complete(atts):
    """True when every report attachment that came back inline carries its content."""
    return all(a.get("contentBytes") or not is_report_name(a.get("name"))
               or (a.get("size") or 0) > MAX_ATTACHMENT for a in atts)


def fetch(tok, mailbox, dest_dir, state_file=None, since=None, max_messages=500, floor=None):
    """Download new report attachments. Returns (saved_count, notes).

    tok may be a token string or a graph_client.TokenSource: the second
    keeps a backfill alive past one token's lifetime. Messages come oldest
    first, so the state file is safe to save every STATE_EVERY messages:
    everything before the saved timestamp has been handled. The saved
    position never moves backwards: a --since backfill keeps the newer one,
    and a message it cannot read is named for a retry instead.

    The state also records covered_from, where the archive's unbroken
    coverage starts: a first run (or a jump to the floor) starts it, resumes
    keep it, a forward --since restarts it at its start once the position
    moves past the unread gap, and a --since backfill extends it back only
    when it read through to the old coverage with no skip before it (a skip
    inside the old coverage is a message the weekly runs read already). A
    backfill that stops early (--max, a skipped message, a failure) records
    the stretch it read unbroken (backfill_from, backfill_to), so the next
    leg, --since where it stopped, extends the coverage from the first leg.

    The listing asks Graph for the attachments inline ($expand), so one call
    reads a page of reports instead of one call per message. A message whose
    inline attachments came back without content is read the classic way,
    and a page that will not come back inline (a dropped stream on a large
    page) switches the rest of the run to one call per message, restarting
    at the last message this run handled. floor (YYYY-MM-DD or an ISO time):
    with no saved position, or one older than the floor, reading starts at
    the floor instead of at the start of the mailbox. A state file written
    for a different mailbox is ignored. max_messages <= 0 means no limit; a
    run that stops says where to resume. On a Graph failure the handled
    position is saved and the notes so far ride on the exception (.notes)."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    notes = []
    state = load_state(state_file) if state_file else {}
    if state.get("mailbox") and mailbox and str(state["mailbox"]).lower() != str(mailbox).lower():
        notes.append("state file %s is for %s, not %s - ignored" % (state_file, state["mailbox"], mailbox))
        state = {}
    start_pos, covered = state.get("last_received"), state.get("covered_from")
    explicit = since is not None
    since = _iso(since or start_pos or EPOCH)
    jumped = False
    if floor and since < _iso(floor):
        why = ("the saved position %s is older" % str(start_pos)[:10]) if start_pos else "there is no saved position"
        notes.append("report mailbox: reading from %s, the start of the archive window (%s); "
                     "fetch_rua.py --since <day> backfills anything older" % (_iso(floor)[:10], why))
        since, jumped = _iso(floor), True
    start = since
    cov = start if (jumped or not start_pos) else covered  # a fresh archive starts where this run starts
    against = bool(explicit and start_pos and not jumped)  # a --since run against a saved position
    before = against and start <= _iso(start_pos)  # a backfill: it reads what lies behind the saved position
    forward = against and start > _iso(start_pos)  # a jump ahead: [saved position, start) is never read
    bf_from, bf_to = state.get("backfill_from"), state.get("backfill_to")
    eff_from = start
    if before and bf_from and bf_to and start <= _iso(bf_to):
        eff_from = min(start, _iso(bf_from))  # this leg continues a backfill that stopped at bf_to
    pending = {"backfill_from": bf_from, "backfill_to": bf_to} if (bf_from and bf_to and not before) else {}
    complete = False
    limit = max_messages if max_messages and max_messages > 0 else None
    box = urllib.parse.quote(mailbox)
    saved, seen, newest, last = 0, 0, start_pos, None
    skipped, hold = set(), None  # hold: the first skipped message's time; the state never moves past it
    inline, done, reached_end = True, False, False

    def position():
        p = resume_point(newest, hold)
        return start_pos if (start_pos and p and p < start_pos) else p  # never backwards

    def coverage():
        p = position()
        if forward and p and p > start_pos:
            return start  # the position moved past the unread gap: the coverage starts again here
        return cov

    def span():
        """An unfinished backfill's unbroken stretch, kept so the next leg continues
        it; any other run carries a pending one forward untouched."""
        if not before:
            return pending
        if complete:
            return {}
        return {"backfill_from": eff_from, "backfill_to": hold or last or start}  # everything before hold was read

    def save():
        save_state(state_file, position(), mailbox, notes, coverage(), span())

    try:
        while not done:
            params = {"$filter": "receivedDateTime ge %s and hasAttachments eq true" % since,
                      "$select": "id,receivedDateTime,subject,hasAttachments",
                      "$orderby": "receivedDateTime asc", "$top": str(PAGE if inline else 50)}
            if inline:
                params["$expand"] = "attachments"
            try:
                for msg in graph_client.get_all(tok, "users/%s/messages" % box, params):
                    if limit and seen >= limit:
                        if explicit:
                            at = min(hold, last) if (hold and last) else (hold or last or since)
                            notes.append("stopped after %d messages, at %s; continue with --since %s"
                                         % (limit, at, at))
                        else:
                            notes.append("stopped after %d messages; run again to continue from the saved "
                                         "position (%s)" % (limit, position()))
                        done = True
                        break
                    seen += 1
                    atts = msg.get("attachments") if inline else None
                    if atts is not None and not _inline_complete(atts):
                        atts = None  # content missing inline: read this message the classic way
                    if atts is None:
                        try:
                            atts = graph_client.get(tok, "users/%s/messages/%s/attachments"
                                                    % (box, msg["id"])).get("value", [])
                        except graph_client.GraphError as err:
                            # one unreadable message must not end a backfill of thousands;
                            # the state stays before it, so the next run tries it again
                            if msg.get("id") not in skipped:
                                skipped.add(msg.get("id"))
                                if len(skipped) <= 5:
                                    notes.append("message received %s skipped, attachments not read: %s"
                                                 % (msg.get("receivedDateTime"), err))
                            hold = hold or msg.get("receivedDateTime")
                            continue
                    saved += _save_reports(atts, msg, dest, notes)
                    received = msg.get("receivedDateTime")
                    if received and (newest is None or received > newest):
                        newest = received
                    if received and (last is None or received > last):
                        last = received
                    if seen % STATE_EVERY == 0:
                        save()
                else:
                    done = reached_end = True  # the listing ran to the end
            except graph_client.GraphError as err:
                if not inline:
                    raise
                # a page with its attachments inline did not come back: keep what is
                # handled, then finish the run one message at a time from there
                save()
                restart = max(since, _iso(last or since))
                notes.append("report listing with attachments inline failed (%s) - continuing one message "
                             "at a time from %s" % (err, restart))
                inline, since = False, restart
    except graph_client.GraphError as err:
        save()
        err.notes = notes
        raise
    # a skip inside the old coverage is no hole: the saved position never passes a skipped message,
    # so the weekly runs read that one already and [eff_from, hold) joins the old coverage unbroken
    unbroken = not skipped or bool(covered and hold and hold >= covered)
    if before and unbroken and (reached_end or (covered and last and last >= covered)):
        # the backfill reached the old coverage unbroken: the archive is covered from its first leg on
        cov = min(eff_from, covered) if covered else eff_from
        complete = True
    save()
    if skipped:
        if hold and start_pos and hold < start_pos:
            notes.append("%d message(s) skipped this run, the first received %s; the saved position stays at %s, "
                         "so retry them with --since %s" % (len(skipped), hold, position(), hold))
        else:
            notes.append("%d message(s) skipped this run; the state file stays at %s so they are tried again"
                         % (len(skipped), position()))
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
    ap.add_argument("--since", metavar="WHEN",
                    help="start reading here (YYYY-MM-DD, or a full time such as 2026-09-01T04:09:00Z) "
                         "instead of the saved position, for a manual backfill "
                         "(the saved position is kept and never moves backwards; default: the state file, "
                         "else everything)")
    ap.add_argument("--state", metavar="FILE", help="state file remembering the newest message (default: <out>/../rua_state.json)")
    ap.add_argument("--max", type=int, default=10000,
                    help="messages read per run (0 = no limit, default 10000); a run that stops says "
                         "where to resume")
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
        for n in getattr(err, "notes", None) or []:
            print(n)  # where the run got to, so a manual backfill knows where to resume
        print("error: " + str(err), file=sys.stderr)
        sys.exit(1)
    for n in notes:
        print(n)


if __name__ == "__main__":
    main()
