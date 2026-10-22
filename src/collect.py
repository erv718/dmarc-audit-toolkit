#!/usr/bin/env python3
"""One command for the whole audit, built to run unattended every week.

What it does, in order, and what it skips when it cannot:

  1. verify the app registration (skipped with no credentials or --offline)
  2. discover the domains: command line, --file, the tenant's own list,
     the domains EXTRA_DOMAINS in .env adds (ones the tenant does not hold:
     a registrar-only domain, a brand on another mail platform), and with
     --mailflow every subdomain seen sending in 30 days; with a
     token, one aggregate query measures every audited name's mail flow
     over the last 30 days (sent from inside, received from outside, last
     seen) on every run, the organizational domains included - the plan's
     evidence that a domain is unused, and the per-domain "sends" line in
     the report. --days narrows the mail log, never this 30-day count
  3. pull the raw mail log for each organizational domain through advanced
     hunting; a domain that lands on the 100,000-row API cap is pulled in
     window slices (skipped with no credentials; --maillog uses a file instead).
     An organization the row budget or the API cap cut keeps only its newest
     hours, a floor: queries/maillog_totals.kql then counts its whole window
     in advanced hunting (maillog.window_totals), beside the floor
  4. pull new aggregate reports from the report mailbox (RUA_MAILBOX in .env;
     --rua uses saved files instead)
  5. run the audit: DNS posture, deduplicated mail log, outside view, headers;
     the previous run's report.json goes in too, so the report carries a
     delta section (what changed since last time); the domain typed first on
     the command line is the report's headline domain (gate.headline) - the
     inventory itself is sorted, so the audit is told what was typed first
  6. write the rollout plan (the exact records to publish next) and todo.md,
     the one prioritised list built from the report and the plan. First the
     _dmarc record of every unaudited subdomain seen sending is looked up in
     DNS (report.dns_extra; at most 50, the busiest first, none with
     --offline): only DNS says such a name has a record of its own. The
     plan's report address is --rua-address, else the report mailbox: new
     records carry it, and a record whose rua lacks it gets it appended
  7. keep a dated history and the running metrics, so the next run can say
     what changed
  8. write the stakeholder document, next_steps.md and next_steps.json, from
     the report, the plan, the metrics and the owners file (<repo root>/
     owners.csv when it exists; --owners PATH points elsewhere, --no-owners
     skips it; start from samples/owners.csv.example), and brief.html, the
     same document with the plan's records designed as one page (src/brief.py)
  9. post the summary to Slack or Teams (SLACK_WEBHOOK_URL in .env; --dry-run
     prints it under its own header; --no-notify skips it; with no webhook
     the run says summary.txt was written and not posted)
 10. end, after every note, with the run's last lines: done, the exit code
     and what it means, the status band in plain words (next_steps.json
     top: the headline, the most critical organizations, what changed, what
     this data cannot show), the run folder and the file to open first

Everything is read-only toward the tenant. No AI is involved at any step;
the outputs are what a human reads, and what an AI agent may read later.

  python src/collect.py                              # tenant domains, tenant data, weekly shape
  python src/collect.py example.com,other.example    # named domains merged with the tenant's
  python src/collect.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --auth-column DMARC --no-notify

Settings: audit.toml in the repo root (copy audit.example.toml) supplies the
domains, known senders, retention, the notification switch, the change
window and approver the ask ends with ([brief]) and the formal exceptions
the gate honours; a command-line flag beats the file. Secrets stay in .env.

Outputs under --out (default audit-out/):
  history/<UTC stamp>/   report.md report.json plan.md plan.json next_steps.md next_steps.json
                         brief.html todo.md inventory.json domains.txt summary.txt run.json
                         verify.md and queries/ (how to check every finding and plan row yourself)
  latest/                the newest run, same files
  metrics.json           one entry per run (policy, gate, findings, failure counts, pass rate)
  metrics.md             the last runs as a table
  senders.json           every sender identity ever seen, with its first and last run
  rua/                   every report file ever pulled from the mailbox

Exit codes: 0 no major or blocking findings, 1 findings at that level, 2 usage
error or setup failure. --strict widens 1 to: a gate that is not go, a plan
hold, or a tenant step that failed or was truncated.
"""

import argparse
import csv
import inspect
import json
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import audit
import brief
import config as config_mod
import console
import discover
import dns_audit
import graph_client
import next_steps
import notify
import plan as plan_mod
import run_hunting
import verify
import verify_setup

try:
    import fetch_rua
except ImportError:  # pragma: no cover
    fetch_rua = None

ROOT = Path(__file__).resolve().parent.parent
QUERY = ROOT / "queries" / "raw_maillog.kql"
TOTALS_QUERY = ROOT / "queries" / "maillog_totals.kql"
PLACEHOLDER = 'let sender_domain = "example.com";'
# where the per-domain mail flow and the full-window totals of a cut organization come from: counts the
# hunting service computes itself, as opposed to the deduplicated rows collect.py pulls
AGGREGATE_SOURCE = "Advanced Hunting aggregate"
# the mail flow is always counted over 30 days, whatever --days says: one cheap aggregate, and the plan calls a
# domain unused only over 30 silent days (--mailflow's new subdomains are the ones seen in those 30 days too)
MAILFLOW_DAYS = 30
TOTALS_COLUMNS = ("fromdom", "logical_messages", "passing", "genuine_failures", "delivered_despite_fail")
RUN_JSON_SENDERS = 200  # new sender identities listed in run.json; senders.json holds them all, the count says how many
RUN_FILES = ("report.md", "report.json", audit.CENSUS_FILE, "plan.md", "plan.json", "next_steps.md", "next_steps.json",
             "brief.html", "todo.md", "inventory.json", "domains.txt", "summary.txt", "run.json", "setup.json",
             "maillog.csv", "verify.md")
# what a plan row's priority holds, in todo.md's words - never when it can go out: each row's status says that
PRIORITY_WORD = {1: "monitoring and hygiene", 2: "before enforcement", 3: "enforcement step", 4: "subdomain policy",
                 5: "final hardening"}


def die(msg):
    print(console.painter(sys.stderr).red("error: ") + msg, file=sys.stderr)
    sys.exit(2)


def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def unique_run_dir(history, stamp):
    """history/<stamp>, or history/<stamp>-2, -3 ... if a run already used it."""
    run_dir, n = history / stamp, 1
    while run_dir.exists():
        n += 1
        run_dir = history / ("%s-%d" % (stamp, n))
    return run_dir, run_dir.name


ROW_CAP = 100000  # one hunting call never returns more than this
SLICE_TARGET = 90000  # rows planned per call: headroom under the cap for mail that lands meanwhile
ROW_BUDGET = 250000  # rows kept per domain before older hours are skipped (0 = no limit)
RUA_MAX = 10000  # report-mailbox messages read per run; a run that stops resumes next time
ARCHIVE_DAYS = 30  # the report archive window: a first run, or a stale saved position, starts here
EXTRA_DNS_MAX = 50  # unaudited sending subdomains whose own _dmarc record one run looks up, the busiest first


def _ago(hours):
    """A span for notes: whole days as Nd, anything else as Nh."""
    return "%dd" % (hours // 24) if hours and hours % 24 == 0 else "%dh" % hours


def _window(start_hours, end_hours):
    """A window for notes, one unit throughout: days when both edges fall on
    whole days, else hours."""
    if start_hours % 24 == 0 and end_hours % 24 == 0:
        return "%dd..%dd" % (start_hours // 24, end_hours // 24)
    return "%dh..%dh" % (start_hours, end_hours)


def _timespan(start_hours):
    """The Timespan reaching back to a slice's own start, in whole days rounded
    up. The API applies Timespan from now, so a Timespan shorter than the
    slice's start empties the slice."""
    return "P%dD" % max(1, -(-start_hours // 24))


def kql_for_domain(template, domain, start_hours=720, end_hours=0):
    """raw_maillog.kql for one domain over ago(start)..ago(end), in hours."""
    if PLACEHOLDER not in template:
        raise ValueError("the sender_domain placeholder line was not found in queries/raw_maillog.kql")
    kql = template.replace(PLACEHOLDER, 'let sender_domain = "%s";' % domain, 1)
    kql = re.sub(r"let window_start\s*=[^;]+;", "let window_start  = ago(%dh);" % start_hours, kql, count=1)
    if end_hours:
        kql = re.sub(r"let window_end\s*=[^;]+;", "let window_end    = ago(%dh);" % end_hours, kql, count=1)
    return kql


COUNT_TAIL = "| summarize n = count() by hago = toint((now() - Timestamp) / 1h), dir = tostring(EmailDirection)"


def count_kql(template, domain, start_hours, end_hours=0):
    """The row query's own filters summarized to rows per hour-ago and mail
    direction, or None when the query has no extend/project line to cut at
    (a customized template): the caller then falls back to splitting on the
    row cap."""
    kql = kql_for_domain(template, domain, start_hours, end_hours)
    m = re.search(r"^[ \t]*\|[ \t]*(extend|project)\b", kql, flags=re.M)
    if not m:
        return None
    if re.search(r"^[ \t]*\|[ \t]*where\b", kql[m.start():], flags=re.M):
        return None  # a filter after the cut: sizing here would count rows the row query drops
    return kql[:m.start()].rstrip() + "\n" + COUNT_TAIL


def hourly_counts(tok, template, org, start_hours, end_hours=0, info=None):
    """{hours ago: rows} over the window, or None when sizing is unavailable
    (no line to cut at, a failed call, or an answer that is not a count). An
    empty answer is a valid count: the domain has no rows. With info, records
    the window's total rows and its internal (Intra-org) rows - mail the
    tenant's own people sent, which spoofing cannot inflate."""
    try:
        kql = count_kql(template, org, start_hours, end_hours)
    except ValueError:  # a customized query without the sender_domain line: no sizing, and no crash
        return None
    if not kql:
        return None
    try:
        res = graph_client.hunting(tok, kql, _timespan(start_hours))
    except graph_client.GraphError:
        return None
    results = res.get("results") or []
    cols = set(run_hunting.columns(res))
    if results and not {"hago", "n"} <= cols:
        return None
    counts, internal = {}, 0
    for r in results:
        try:
            h, n = int(r["hago"]), int(r["n"])
        except (KeyError, TypeError, ValueError):
            continue
        counts[h] = counts.get(h, 0) + n
        if str(r.get("dir") or "").lower() == "intra-org":
            internal += n
    if info is not None:
        info["total"] = sum(counts.values())
        if "dir" in cols or not results:
            info["internal"] = internal
    return counts


def plan_slices(counts, start_hours, end_hours=0, target=SLICE_TARGET):
    """Contiguous (start, end) hour windows, newest first, covering the whole
    window: each holds at most target rows by the hourly counts, except an
    hour above target, which is a slice of its own (a run of empty hours
    ahead of it is a cheap slice of its own too, so the busy hour never
    shares a call). The last slice always reaches the window start, so rows
    that land between the sizing call and the pull are not dropped."""
    slices, end, acc = [], end_hours, 0
    for h in range(end_hours, start_hours):
        n = counts.get(h, 0)
        if acc and acc + n > target:
            slices.append((h, end))
            end, acc = h, 0
        elif not acc and n > target and h > end:
            slices.append((h, end))
            end = h
        acc += n
    if end < start_hours:
        slices.append((start_hours, end))
    return slices


def pull_domain(tok, template, org, start_hours, end_hours, notes, budget=None, sized=False, info=None):
    """One domain's rows for ago(start)..ago(end), in hours.

    A cheap count query first sizes the window by the hour, with the same
    filters as the row query, so a busy domain comes back in complete windows
    of at most SLICE_TARGET rows, newest first, instead of a 100,000-row
    download thrown away only to learn it was capped; a domain with no rows
    costs only the count. A truncated day can orphan a message's passing copy
    and overcount genuine failures, so complete windows matter. When sizing
    is unavailable (a customized query, a failed count call), or a planned
    slice still lands on the cap, the window halves until each call fits,
    down to one hour; a single hour still at the cap is kept and noted as
    truncated. A window whose response keeps dropping mid-stream after the
    retries in run_hunting halves the same way.

    Every call's Timespan reaches back to the slice's own start (the API
    applies Timespan from now). budget, a dict holding {"rows": n}, stops the
    walk at the older slices once n rows are in hand, and records how many
    hours back the kept rows reach (kept_hours). info, a dict, receives the
    sizing totals (total, internal), the planned and pulled slice counts, and
    each hour kept at the API cap (capped, as 'Xh..Yh'). Returns (rows,
    columns, data calls)."""
    if budget is not None and budget.get("rows", 0) <= 0:
        if not budget.get("noted"):
            notes.append("mail log: %s row budget reached at %s ago - older rows skipped; the rows "
                         "cover only the last %s (raise --max-rows to keep more)"
                         % (org, _window(start_hours, end_hours), _ago(end_hours)))
            budget["noted"] = True
            budget["kept_hours"] = end_hours  # the cut: pull_maillog records it for the delta
        return [], None, 0
    if not sized:
        counts = hourly_counts(tok, template, org, start_hours, end_hours, info)
        if counts is not None:
            total = sum(counts.values())
            if not total:
                return [], None, 0
            slices = plan_slices(counts, start_hours, end_hours, SLICE_TARGET)
            if info is not None:
                info["planned"] = len(slices)
            if len(slices) > 1:
                notes.append("mail log: %s has about %d rows in the window (%d planned slices of up to %d "
                             "rows, newest first)" % (org, total, len(slices), SLICE_TARGET))
            rows, cols, calls, pulled = [], None, 0, 0
            for a, b in slices:
                got, c, n = pull_domain(tok, template, org, a, b, notes, budget, sized=True, info=info)
                rows.extend(got)
                cols = cols or c
                calls += n
                pulled += 1 if n else 0
            if info is not None:
                info["pulled"] = pulled
            return rows, cols, calls
    span = start_hours - end_hours
    try:
        res = graph_client.hunting(tok, kql_for_domain(template, org, start_hours, end_hours),
                                   _timespan(start_hours))
    except graph_client.GraphError as err:
        if "did not complete" not in str(err) or span <= 1:
            raise
        notes.append("mail log: %s window %s ago dropped mid-stream after retries - splitting "
                     "the window" % (org, _window(start_hours, end_hours)))
        return pull_halves(tok, template, org, start_hours, end_hours, notes, budget, info)
    got = res.get("results") or []
    cols = run_hunting.columns(res)
    if len(got) < ROW_CAP or span <= 1:
        if len(got) >= ROW_CAP:
            notes.append("mail log: %s has more than 100,000 rows within one hour (%s ago) - that "
                         "hour is truncated" % (org, _window(start_hours, end_hours)))
            if info is not None:
                info.setdefault("capped", []).append(_window(start_hours, end_hours))
        if budget is not None:
            budget["rows"] -= len(got)
        return got, cols, 1
    notes.append("mail log: %s hit the 100,000-row API cap (%s ago) - splitting the window"
                 % (org, _window(start_hours, end_hours)))
    return pull_halves(tok, template, org, start_hours, end_hours, notes, budget, info)


def pull_halves(tok, template, org, start_hours, end_hours, notes, budget, info=None):
    """Both halves of a window, the newer one first so a row budget keeps
    the hours that matter most."""
    mid = end_hours + (start_hours - end_hours) // 2
    right, cols_r, n2 = pull_domain(tok, template, org, mid, end_hours, notes, budget, sized=True, info=info)
    left, cols_l, n1 = pull_domain(tok, template, org, start_hours, mid, notes, budget, sized=True, info=info)
    return right + left, cols_r or cols_l, n1 + n2


def org_cut(budget, info, pulled_at):
    """What collect cut of one org's pull, as report.json's maillog.cuts
    records it, or None: the row budget kept only the rows of the last
    kept_hours (from kept_from on), and/or an hour stayed at the API cap."""
    cut = {}
    if budget is not None and budget.get("noted"):
        kept = budget.get("kept_hours", 0)
        cut = {"reason": "row budget", "kept_hours": kept,
               "kept_from": (pulled_at - timedelta(hours=kept)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if info.get("capped"):
        cut.setdefault("reason", "api cap")
        cut["api_cap_hours"] = list(info["capped"])
    return cut or None


def pull_maillog(tok, org_domains, out_csv, days=30, max_rows=ROW_BUDGET, volumes=None, cuts=None):
    """raw_maillog.kql per organizational domain, merged into one CSV. Each
    domain's note names the rows it got and the time span they cover; when
    the row budget kept only the newest part of a busy domain, the note says
    so, with the sized total. volumes, a dict, receives each org domain's
    internal (Intra-org) row count from its sizing call: the uncapped,
    spoof-proof volume collect.py hands audit.py for the headline. cuts, a
    dict, receives each org domain whose rows the row budget or the API cap
    cut (org_cut): the apex and every subdomain of that org at one cutoff."""
    template = QUERY.read_text(encoding="utf-8-sig")
    rows, cols, notes = [], None, []
    seen = set()
    for org in org_domains:
        budget = {"rows": max_rows} if max_rows else None
        info = {}
        pulled_at = datetime.now(timezone.utc).replace(microsecond=0)
        try:
            got, res_cols, calls = pull_domain(tok, template, org, days * 24, 0, notes, budget, info=info)
        except (graph_client.GraphError, ValueError) as err:
            notes.append("mail log for %s not pulled: %s" % (org, err))
            got = None
            if cuts is not None:  # the whole org is missing from this run's log: nothing compares across it
                cuts[org] = {"reason": "not pulled", "error": str(err)[:200]}
        if volumes is not None:
            if "internal" not in info:  # the sizing did not answer: one more try, for the volume alone
                hourly_counts(tok, template, org, days * 24, 0, info)
            if "internal" in info:
                volumes[org] = info["internal"]  # measured even when the rows themselves failed
        if got is None:
            continue
        cut = org_cut(budget, info, pulled_at)
        if cut and cuts is not None:
            cuts[org] = cut
        cols = cols or res_cols
        before = len(rows)
        for r in got:
            key = json.dumps(r, sort_keys=True, default=str)  # slice boundaries can repeat a leg; a customized
            # projection can keep a dynamic column, whose value is a list or an object
            if key not in seen:
                seen.add(key)
                rows.append(r)
        stamps = sorted(str(r.get("Timestamp")) for r in rows[before:] if r.get("Timestamp"))
        span = "; rows span %s to %s" % (stamps[0], stamps[-1]) if stamps else ""
        if budget is not None and budget.get("noted"):
            about = ("about %d rows in " % info["total"]) if info.get("total") else ""
            how = (("%d of %d planned slices" % (info.get("pulled", 0), info["planned"])) if "planned" in info
                   else "%d window slice%s" % (calls, "" if calls == 1 else "s"))
            notes.append("mail log: %d rows for %s - the newest part of %sthe last %d days (%s, row budget %d)%s"
                         % (len(rows) - before, org, about, days, how, max_rows, span))
        else:
            suffix = " (%d window slices)" % calls if calls > 1 else ""
            notes.append("mail log: %d rows for %s (last %d days)%s%s"
                         % (len(rows) - before, org, days, suffix, span))
    if not rows:
        return None, notes
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    return str(out_csv), notes


def _tally(value):
    """A count in a hunting answer as the mail-flow answer reads one (a whole
    number >= 0, a long may come as text, "1234.0" included), 0 for a null
    or an empty string (an empty join side), None for anything else."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return 0
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            return None
    return discover._count(value)


def totals_rejection(result, org):
    """Why totals_by_domain refused an answer, in one clause for the run
    note, so a rejected answer on a live tenant explains itself: the shape
    seen and, when the columns are there, the first value that is not a
    count."""
    results = result.get("results") if isinstance(result, dict) else None
    if not isinstance(results, list) or any(not isinstance(r, dict) for r in results):
        return "no results list of rows (%s)" % _answer_shape(result)
    schema = result.get("schema")
    names = {c.get("name") for c in schema if isinstance(c, dict)} if isinstance(schema, list) else set()
    if results:
        missing = sorted(set(TOTALS_COLUMNS) - (names | set(results[0])))
        if missing:
            return "columns missing: %s (%s)" % (", ".join(missing), _answer_shape(result))
    for i, r in enumerate(results):
        dom = str(r.get("fromdom") or "").strip().lower().rstrip(".")
        if not (dom == org or dom.endswith("." + org)):
            continue
        for k in TOTALS_COLUMNS[1:]:
            if _tally(r.get(k)) is None:
                v = r.get(k)
                return "row %d has a %s of type %s where a count was expected (%s)" % (
                    i + 1, k, type(v).__name__, _answer_shape(result))
    return "unknown (%s)" % _answer_shape(result)


def _answer_shape(result):
    """What a hunting answer looks like, for a note that explains a rejected
    one: the top-level keys, the schema's column names, how many rows, and
    the first row's columns with their value types (never the values)."""
    if not isinstance(result, dict):
        return "a %s, not an object" % type(result).__name__
    schema = result.get("schema")
    names = [c.get("name") for c in schema if isinstance(c, dict)] if isinstance(schema, list) else None
    rows = result.get("results")
    parts = ["keys %s" % ",".join(sorted(str(k) for k in result)), "schema %s" % (names if names is not None else "absent")]
    if isinstance(rows, list):
        parts.append("%d rows" % len(rows))
        if rows and isinstance(rows[0], dict):
            parts.append("first row %s" % ",".join("%s:%s" % (k, type(v).__name__) for k, v in rows[0].items()))
    else:
        parts.append("results %s" % type(rows).__name__)
    return "; ".join(parts)


def totals_by_domain(result, org):
    """maillog_totals.kql's answer for one organization as {From domain:
    {"logical_messages", "passing", "genuine_failures",
    "delivered_despite_fail", "delivered_by"}}, for the names under org. The
    query answers one row per From domain and override: the failure counts
    add up, logical_messages and passing repeat on each row, and
    delivered_by ({reason: messages}) gathers the delivered failures that
    name their override. None when the answer is not those totals (no
    results list, rows without its columns, a count that is not a whole
    number) - totals_rejection says which; {} when it holds no row under org."""
    results = result.get("results") if isinstance(result, dict) else None
    if not isinstance(results, list) or any(not isinstance(r, dict) for r in results):
        return None
    schema = result.get("schema")  # the column names, and the first row's keys (run_hunting.columns' rule)
    names = {c.get("name") for c in schema if isinstance(c, dict)} if isinstance(schema, list) else set()
    if results and not set(TOTALS_COLUMNS) <= (names | set(results[0])):
        return None
    out = {}
    for r in results:
        dom = str(r.get("fromdom") or "").strip().lower().rstrip(".")
        if not (dom == org or dom.endswith("." + org)):
            continue
        n = {k: _tally(r.get(k)) for k in TOTALS_COLUMNS[1:]}
        if None in n.values():
            return None
        d = out.setdefault(dom, {"logical_messages": 0, "passing": 0, "genuine_failures": 0,
                                 "delivered_despite_fail": 0, "delivered_by": {}})
        d["logical_messages"] = max(d["logical_messages"], n["logical_messages"])
        d["passing"] = max(d["passing"], n["passing"])
        d["genuine_failures"] += n["genuine_failures"]
        d["delivered_despite_fail"] += n["delivered_despite_fail"]
        reason = str(r.get("delivered_by") or "").strip()
        if reason and n["delivered_despite_fail"]:
            d["delivered_by"][reason] = d["delivered_by"].get(reason, 0) + n["delivered_despite_fail"]
    for d in out.values():
        d["delivered_by"] = dict(sorted(d["delivered_by"].items(), key=lambda kv: (-kv[1], kv[0])))
    return dict(sorted(out.items()))


def pull_window_totals(tok, orgs, days=30):
    """queries/maillog_totals.kql for each organization whose pull the row
    budget or the API cap cut (pull_maillog's cuts), with a Timespan over
    the full window: per From domain under it, the totals at dedupe.py's
    grain, counted by the hunting service itself. The rows kept, and every
    count the gate, the census and the plan build from them, stay a floor;
    these say how far below the whole window that floor sits. Returns
    ({"hours": window hours, "orgs": {org: {"by_domain": ..., "source":
    AGGREGATE_SOURCE}}}, notes), or (None, notes) when no organization was
    counted; an organization whose query fails leaves a note and no entry,
    and so does one whose answer counts no mail under it at all: it was cut
    because it has more rows than the budget keeps, so an empty answer is a
    failed one (audit.build_report also sets aside totals below the rows
    kept). orgs may be pull_maillog's cuts dict: the note then names the
    cut's own cause (a pull that failed left no rows to hold too many)."""
    notes, counted = [], {}
    if not orgs:
        return None, notes
    cuts = orgs if isinstance(orgs, dict) else {}
    try:
        template = TOTALS_QUERY.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as err:  # unreadable, or saved as UTF-16 (PowerShell's > and Out-File)
        return None, ["mail log: full-window totals not counted: cannot read %s (%s)"
                      % (TOTALS_QUERY.name, getattr(err, "strerror", None) or err)]
    for org in sorted(orgs):
        try:
            res = graph_client.hunting(tok, kql_for_domain(template, org, days * 24), _timespan(days * 24))
        except (graph_client.GraphError, ValueError) as err:
            notes.append("mail log: full-window totals for %s not counted: %s" % (org, err))
            continue
        by_domain = totals_by_domain(res, org)
        if by_domain is None:
            notes.append("mail log: full-window totals for %s not counted: the answer is not the totals %s asks for - %s"
                         % (org, TOTALS_QUERY.name, totals_rejection(res, org)))
            continue
        if not by_domain:
            cut = cuts.get(org) if isinstance(cuts.get(org), dict) else {}
            notes.append("mail log: full-window totals for %s not counted: the answer holds no mail under it, %s"
                         % (org, "and its rows were not read (the pull failed)" if cut.get("reason") == "not pulled"
                            else "yet its rows were cut for holding too many"))
            continue
        counted[org] = {"by_domain": by_domain, "source": AGGREGATE_SOURCE}
        sums = {k: sum(c[k] for c in by_domain.values())
                for k in ("logical_messages", "genuine_failures", "delivered_despite_fail")}
        notes.append("mail log: full-window totals for %s over the last %d days, counted in Advanced Hunting: about %d "
                     "logical messages, %d genuine failures, %d delivered despite failing (the rows kept stay a floor)"
                     % (org, days, sums["logical_messages"], sums["genuine_failures"], sums["delivered_despite_fail"]))
    if not counted:
        return None, notes
    return {"hours": days * 24, "orgs": counted}, notes


def own_dmarc(name, resolver):
    """The DMARC record at _dmarc.<name> itself, never a parent's: one TXT
    lookup by dns_audit's resolver path (port 53 first, DNS over HTTPS as
    the cross-check of a negative answer and the fallback when port 53
    fails). {"dmarc": the first v=DMARC1 string or None, "status": found |
    absent | error, "source": the _dmarc name when found, else None,
    "path": the resolver path that answered}, plus "err" when it failed."""
    host = "_dmarc." + name
    try:
        recs, meta = dns_audit.resolve_ex(resolver, host, "TXT")
    except Exception as err:  # a lookup that raises is a lookup that failed, never the end of the run
        recs, meta = [], {"path": None, "status": "error", "err": type(err).__name__}
    txts = [str(t) for t in recs or [] if str(t).lower().startswith("v=dmarc1")]
    status = "found" if txts else ("error" if meta.get("status") == "error" else "absent")
    out = {"dmarc": txts[0] if txts else None, "status": status, "source": host if txts else None,
           "path": meta.get("path")}
    if status == "error" and meta.get("err"):
        out["err"] = meta["err"]
    return out


def lookup_unaudited(report, inventory_rows, resolver, cap=None):
    """report.dns_extra: the own _dmarc record of every unaudited subdomain
    the plan's sending rule finds (plan.unaudited_senders), looked up in DNS
    - only DNS says such a name has a record of its own; an aggregate report
    names the policy a receiver saw, maybe months ago. At most cap names
    (EXTRA_DNS_MAX), the busiest first: the plan asks for a lookup first for
    the rest, and for one whose lookup failed. Returns (dns_extra, notes)."""
    cap = EXTRA_DNS_MAX if cap is None else cap
    names = [n for n, _ in plan_mod.unaudited_senders(report, inventory_rows)]
    extra = {n: own_dmarc(n, resolver) for n in names[:cap]}
    notes = []
    if extra:
        by = {s: [n for n in extra if extra[n]["status"] == s] for s in ("found", "absent", "error")}
        parts = []
        if by["found"]:
            parts.append("%s %s" % (plan_mod._listed(by["found"]), "has a record of its own" if len(by["found"]) == 1
                                    else "have records of their own"))
        if by["absent"]:
            parts.append("%s %s none" % (plan_mod._listed(by["absent"]), "has" if len(by["absent"]) == 1 else "have"))
        if by["error"]:
            parts.append("the lookup failed for %s, so the plan asks for a lookup first" % plan_mod._listed(by["error"]))
        notes.append("DNS: _dmarc looked up for %d unaudited sending subdomain%s: %s"
                     % (len(extra), "" if len(extra) == 1 else "s", "; ".join(parts)))
    skipped = names[cap:]
    if skipped:
        notes.append("DNS: %d more unaudited sending subdomain%s not looked up (at most %d a run, the busiest first): "
                     "%s - the plan asks for a lookup first for each"
                     % (len(skipped), "" if len(skipped) == 1 else "s", cap, plan_mod._listed(skipped)))
    return extra, notes


def previous_run(history_dir, current_stamp):
    if not history_dir.exists():
        return None
    runs = sorted(p.name for p in history_dir.iterdir() if p.is_dir() and p.name < current_stamp)
    for name in reversed(runs):
        if (history_dir / name / "report.json").exists():
            return history_dir / name
    return None


def read_report(path):
    """An earlier run's report.json as a dict, else None: a broken previous
    run must not stop this one. utf-8-sig, so a BOM from an editor is fine.
    A census split off to census.json beside it is read back whole, so the
    delta's new senders compare whole censuses."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return audit.load_census(doc, path) if isinstance(doc, dict) and doc.get("gate") else None


def inherit_run_cuts(report, run_json):
    """An earlier report that records no cut (written before maillog.cuts,
    maillog.truncation and the caveats existed) says nothing about the row
    budget that cut its mail log; the run.json beside it does, in
    collect.py's own notes. Those notes join the report's caveats, in
    memory, so audit.maillog_cuts reads the cut and the delta withholds the
    comparison. Nothing when the report records its cuts, or run.json is
    missing or unreadable."""
    ml = report.get("maillog") if isinstance(report, dict) and isinstance(report.get("maillog"), dict) else None
    if ml is None or isinstance(ml.get("cuts"), dict) or audit.maillog_cuts(report):
        return
    try:
        doc = json.loads(Path(run_json).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return
    notes = doc.get("notes") if isinstance(doc, dict) and isinstance(doc.get("notes"), list) else []
    texts = [n for n in notes if isinstance(n, str)
             and ("row budget reached" in n or "rows within one hour" in n)]
    if texts:
        caveats = report.get("caveats") if isinstance(report.get("caveats"), list) else []
        report["caveats"] = caveats + [t for t in texts if t not in caveats]


def accepts(fn, name):
    """True when fn takes a keyword argument called name (an older audit.py
    without the delta feature does not; the run still works without it)."""
    try:
        return name in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def load_owners(explicit=None, skip=False):
    """(rows, path, problem) for the owners file: --owners PATH, else
    <repo root>/owners.csv when it exists, else nothing. problem is the read
    error text, or None."""
    if skip:
        return [], None, None
    path = next_steps.repo_path(explicit) if explicit else ROOT / next_steps.DEFAULT_OWNERS
    if not explicit and not path.is_file():
        return [], None, None
    try:
        return next_steps.read_owners(path), path, None
    except next_steps.UsageError as err:
        return [], None, str(err)


def write_next_steps(run_dir, report, plan, entries, owners, owners_path, prev_report, prev_dir, note, settings=None):
    """next_steps.md and next_steps.json in the run dir, from the report, the
    plan (None when none was written), the metrics history, the owners rows
    and the previous run; settings: audit.toml's [brief] table (the change
    window and approver the ask ends with). Returns the document, or None
    after a note: the document is derived from files already on disk, so it
    never fails the run."""
    prev_path = (prev_dir / "report.json").resolve() if prev_dir else None
    try:
        doc = next_steps.build(report, plan, entries, owners, prev_report,
                               owners_path=owners_path, previous_path=prev_path, settings=settings)
        next_steps.write(doc, run_dir.resolve())  # absolute: next_steps resolves relative paths from the repo root
    except next_steps.UsageError as err:
        note("no next-steps document written: %s" % err)
        return None
    except Exception as err:  # the same guard next_steps.py's own CLI has: a reader never sees a traceback
        note("no next-steps document written (%s: %s)" % (type(err).__name__, err))
        return None
    return doc


def metrics_entry(stamp, report, plan):
    per = (report.get("gate") or {}).get("domains") or {}
    ml = (report.get("maillog") or {}).get("counters") or {}
    tot = (report.get("rua") or {}).get("totals") or {}
    return {
        "run": stamp,
        "domains": {d: {"policy": g.get("current_policy"), "gate": g.get("verdict"), "next_step": g.get("next_step")}
                    for d, g in sorted(per.items())},
        "findings": (report.get("summary") or {}).get("by_severity") or {},
        "genuine_failures": ml.get("genuine_failures"),
        # the exact span from the window's stamps, as the delta judges it (the stored hours are rounded, and a
        # rounded figure can fall on the other side of the half-span rule the delta applies)
        "maillog_hours": audit._hours((report.get("maillog") or {}).get("window")),
        # the orgs whose pull the row budget or the API cap cut: their counts, and the whole log's, are a
        # floor over the hours kept, so the trend never compares them (the whole log's span can still hold)
        "maillog_cut_orgs": sorted(audit.maillog_cuts(report)),
        "delivered_despite_fail": ml.get("delivered_despite_fail"),
        "likely_spoof": (ml.get("by_likely") or {}).get("likely_spoof"),
        "rua_messages": tot.get("messages"),
        "rua_pass_rate": tot.get("pass_rate"),
        "rua_rejected": (tot.get("by_disposition") or {}).get("reject"),
        "plan_changes": len(plan.get("changes") or []),
        "plan_priority1": sum(1 for c in plan.get("changes") or [] if c.get("priority") == 1),
    }


def _number(value):
    """A metrics value as a finite number, else None: a hand-edited or damaged entry (text, nan, an infinity,
    an integer too large to be a float) reads as unknown."""
    return notify._finite(value)


def backfill_cut_orgs(entries, prev_name, prev_report):
    """Give the previous run's metrics entry the maillog_cut_orgs key when
    it was written before the cuts were recorded (round 9), from what that
    run's own report says (audit.maillog_cuts parses its truncation and
    caveats): the Slack trend then refuses the comparison the delta refuses,
    instead of calling a floor against a whole count worsening. The entry
    is found by its run stamp; nothing changes when it has the key. Returns
    the orgs filled in, or None."""
    if not prev_name or not isinstance(prev_report, dict):
        return None
    for e in entries:
        if isinstance(e, dict) and str(e.get("run")) == str(prev_name) and "maillog_cut_orgs" not in e:
            e["maillog_cut_orgs"] = sorted(audit.maillog_cuts(prev_report))
            return e["maillog_cut_orgs"]
    return None


def _whole_number(value):
    """A metrics count for a %d: its whole part, 0 when it is no number."""
    n = _number(value)
    return int(n) if n is not None else 0


def render_metrics(entries, last=12):
    """metrics.md, the last runs as a table (metrics.json holds every run).
    A run whose mail log the row budget or the API cap cut shows its failure
    count as the floor it is - a run from before the cuts were recorded by
    its per-domain spans, as notify reads them; an entry or a value of the
    wrong type reads as unknown, never an error."""
    rows = [e for e in entries if isinstance(e, dict)][-last:]
    L = ["# Runs", "", "| run | domains: policy / gate | findings | genuine failures | pass rate | plan rows |", "|---|---|---|---|---|---|"]
    for e in rows:
        per = e.get("domains") if isinstance(e.get("domains"), dict) else {}
        doms = "; ".join("%s %s/%s" % (d, (v.get("policy") if isinstance(v, dict) else None) or "unknown",
                                       v.get("gate") if isinstance(v, dict) else None)
                         for d, v in list(per.items())[:4])
        if len(per) > 4:
            doms += " (+%d)" % (len(per) - 4)
        f = e.get("findings") if isinstance(e.get("findings"), dict) else {}
        fs = ", ".join("%s %d" % (k, _whole_number(v)) for k, v in sorted(f.items(), key=str)
                       if _number(v) is not None) or "-"
        gf = _number(e.get("genuine_failures"))
        cut = notify._cut_orgs(e) or []
        gfs = "-" if gf is None else ("%d (floor, %s cut)" % (gf, ", ".join(cut)) if cut else "%d" % gf)
        rate = _number(e.get("rua_pass_rate"))
        pr = "%.1f%%" % (100 * rate) if rate is not None else "-"
        L.append("| %s | %s | %s | %s | %s | %d (%d now) |" % (e.get("run") or "-", doms, fs, gfs, pr,
                                                               _whole_number(e.get("plan_changes")),
                                                               _whole_number(e.get("plan_priority1"))))
    L.append("")
    return "\n".join(L)


def truncation_text(notes):
    """One clause for maillog.truncation (the status document's 'the log export
    was cut short (...)' line) from the mail-log notes: a row budget that kept
    only the newest hours, or an hour still at the API cap. None otherwise."""
    parts = []
    for n in notes:
        m = re.search(r"mail log: (\S+) row budget reached .*? cover only the last (\S+)", n)
        if m:
            parts.append("row budget kept only the newest %s for %s" % (m.group(2), m.group(1)))
            continue
        m = re.search(r"mail log: (\S+) has more than [\d,]+ rows within one hour \((.+?) ago\)", n)
        if m:
            parts.append("an hour of %s (%s ago) is truncated at the API cap" % (m.group(1), m.group(2)))
    return "; ".join(parts) or None


def run_caveats(report, notes):
    """The run's caveats from its mail-log notes - an hour still at the API
    row cap dropped rows, a row budget kept only the newest hours: the
    mail-log counts for that organization are a floor - stored in the
    report as report["caveats"] and, as one clause, maillog.truncation
    (the status document's 'cut short, so a floor' clause). Both name the
    organizations in the one order every file follows, the headline's
    first (next_steps.order_by_org), never in the order the pull reached
    them, so report.md's Caveats, report.json and todo.md agree with
    next_steps.md. Returns the caveats; [] when nothing was cut."""
    caveats = []
    for n in notes:
        if "that hour is truncated" in n:
            caveats.append("%s - mail-log counts for that domain are a floor and its failures are not verified" % n)
        elif "row budget reached" in n:
            caveats.append("%s - mail-log counts for that domain cover that span only" % n)
    if not caveats:
        return caveats
    head = next_steps.headline_org(report)
    caveats = next_steps.order_by_org(caveats, head)
    report["caveats"] = caveats
    cut = truncation_text(notes)
    if cut and isinstance(report.get("maillog"), dict):
        report["maillog"]["truncation"] = "; ".join(next_steps.order_by_org(cut.split("; "), head))
    return caveats


def headline_note(gate, orgs, volumes):
    """The run note on the headline signal, written from the gate the report
    chose rather than a guess at the fallback: the internal mail per org
    domain when the sizing measured any, else what the headline rested on."""
    chosen = "the headline is %s (%s)" % (gate.get("headline_domain"), gate.get("headline_source"))
    missing = [o for o in orgs if o not in volumes]
    if missing:
        return "headline signal: internal-mail volume missing for %s - %s" % (", ".join(missing), chosen)
    if any(v > 0 for v in volumes.values()):
        top = sorted(volumes.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        return "headline signal: internal mail per org domain - %s; %s" % (", ".join("%s %d" % kv for kv in top), chosen)
    return "headline signal: no internal mail in any org domain this run - %s" % chosen


def read_history(path, expect, stamp=None, notes=None):
    """A history file collect.py keeps (metrics.json, senders.json) as the
    shape it expects (list or dict), or None when the file is absent. A file
    that exists but cannot be read as that shape - broken JSON, a BOM or a
    UTF-16 encoding from an editor is read fine - is never overwritten by a
    fresh history: it is set aside under its name plus .unreadable-<stamp>,
    the note says so, and the history starts again."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        doc = json.loads(audit._decode_export(p.read_bytes()))
    except (OSError, ValueError):
        doc = None
    if isinstance(doc, expect):
        return doc
    aside = p.with_name("%s.unreadable-%s" % (p.name, stamp or utc_stamp()))
    try:
        p.replace(aside)
        where = "set aside as %s" % aside.name
    except OSError as err:
        where = "could not be set aside (%s)" % err
    if notes is not None:
        notes.append("%s is not the %s collect.py writes (%s): %s; the history starts again from this run"
                     % (p.name, "list" if expect is list else "object", "unreadable" if doc is None else type(doc).__name__,
                        where))
    return None


def load_json(path, default):
    try:
        return json.loads(audit._decode_export(Path(path).read_bytes()))
    except (OSError, ValueError):
        return default


def update_senders(path, report, stamp, notes=None):
    """senders.json remembers every sender identity ever seen (notify.sender_keys:
    rua source IPs and mail-log envelope domains) with its first and last run,
    so "newly identified" means new to the whole history, not merely absent
    last week. An entry that is not an object (a hand edit) is replaced by a
    fresh one; a file that is not the object collect.py writes is set aside
    (read_history). Returns (keys known before this run, keys new in this run)."""
    state = read_history(path, dict, stamp, notes) or {}
    seen = state.get("senders") if isinstance(state.get("senders"), dict) else {}
    seen = {k: (v if isinstance(v, dict) else {"first_seen": stamp}) for k, v in seen.items()}
    known_before = set(seen)
    now = notify.sender_keys(report)
    new = sorted(k for k in now if k not in seen)
    for k in now:
        entry = seen.setdefault(k, {"first_seen": stamp})
        entry["last_seen"] = stamp
    Path(path).write_text(json.dumps({"updated": stamp, "senders": dict(sorted(seen.items()))}, indent=1),
                          encoding="utf-8")
    return known_before, new


def render_todo(report, plan, caveats=()):
    """todo.md: one prioritised list to work top to bottom, assembled from what
    report.json and plan.json already say. Nothing new is inferred here, and
    every line says which file holds the evidence. The domains run in the one
    order every file follows, led by the organization the status document
    leads with (next_steps.headline_org); the plan's rows and holds in the
    plan's own order, which is that order already; senders ranked by count,
    a tie in that order."""
    headline = next_steps.headline_org(report)
    gate = report.get("gate") or {}
    exc = gate.get("exceptions") or {}
    excepted_ips = set(exc.get("excepted_streams") or [])
    changes = plan.get("changes") or []
    holds = plan.get("holds") or []
    L = ["# To-do", "",
         "Built from report.json and plan.json of %s. Work top to bottom. Nothing here has been applied; "
         "every DNS row is a proposal for a human to review." % (report.get("generated_utc") or "this run"), "",
         "verify.md, next to this file, says how to check every finding and every plan row yourself.", ""]

    L.append("## Where each domain stands")
    L.append("")
    per = gate.get("domains") or {}
    # a domain the run measured sending nothing skips the weekly ramp whose first step the gate judges: its line
    # leads with the quarantine-now row and gives the gate's verdict as the ramp's - unless the gate's blockers hold
    # that row too. Any other domain with a plan row leads with the plan's first row the same way, as next_steps.md's
    # table and summary.txt name it (next_steps.plan_step), each row with its id, the section that lists it and its
    # status: the gate's ramp step is the next step only of a domain the plan has no row for. A policy the run did
    # not read is said in words (no DMARC record, lookup failed, not read), never p=unknown
    quiet = {c.get("domain"): c for c in changes if isinstance(c, dict) and c.get("kind") == "no_mail"}

    def where(c):
        """' (P-02, section 2c: needs the report address)': a row's id, the section of this file that lists it, and
        its status."""
        status, text, _ = plan_mod.status_of(c)
        prio = c.get("priority")
        section = (("2" if status == "now" else "2b" if status == "check" else "2c") if prio == 1
                   else "3" if prio == 2 else "5")
        return " (%s, section %s: %s)" % (c.get("id") or "?", section, text)

    dns = report.get("dns") if isinstance(report.get("dns"), dict) else {}
    for d, g in sorted(per.items(), key=lambda kv: (audit.domain_key(kv[0], headline), str(kv[0]))):
        policy = next_steps.policy_words(report, d)
        if d in quiet:
            left = audit.ramp_blockers_left(report, d)
            L.append("- %s: %s, next step: no mail measured, quarantine now%s; the gate's %s %s"
                     % (d, policy, where(quiet[d]), g.get("verdict"),
                        "is for the weekly ramp this skips" if not left else "holds that row too: %s" % left[0]))
            continue
        step = next_steps.plan_step(plan, str(d).lower(), where)
        if step is None:
            step = str(g.get("next_step") or "")
            if step.lower().startswith("unknown"):
                step = next_steps._unread_step(report, d)
            at = re.search(r"\s+on the record at (\S+)$", step)
            doc = dns.get(d) if isinstance(dns.get(d), dict) else {}
            if doc.get("inherited"):
                # a name a plan hold says needs a record of its own before the apex moves to reject: one statement
                held = audit.inherited_step(d, step, plan)
                if held != step:
                    step = held
                elif at and at.group(1) != "_dmarc." + d:
                    # the gate's step on the parent's record is the apex's step, not this name's
                    step = "none of its own: it follows %s and moves with the apex's step" % at.group(1)
        L.append("- %s: %s, gate %s, next step: %s" % (d, policy, g.get("verdict"), step))
    if not per:
        L.append("- no per-domain verdict in this run")
    L.append("")

    L.append("## 1. Decide first (plan holds)")
    L.append("")
    L += ["- %s: %s" % (h["domain"], h["reason"]) for h in holds] or ["- none"]
    L.append("")

    # the plan's priority-1 rows by the status plan.py gave each (plan.row_status): only the ones ready now touch
    # no mail anyone sends and wait on nothing; the rest wait on their checks, or cannot go out this week
    rows = [c for c in changes if c.get("priority") == 1]
    status = {id(c): plan_mod.status_of(c) for c in rows}
    ready = [c for c in rows if status[id(c)][0] == "now"]
    checked = [c for c in rows if status[id(c)][0] == "check"]
    waiting = [c for c in rows if status[id(c)][0] not in ("now", "check")]
    keeps = any(c.get("kind") == "new" and not re.search(r"(?:^|;)\s*p\s*=\s*none\b", str(c.get("value") or ""), re.I)
                for c in ready)

    def row_line(c):
        return ("- %s %s: %s at `%s` = `%s` (current: `%s`) - %s"
                % (c["id"], c["domain"], c["record"], c["hostname"], c["value"], c["current"], c["why"]))

    def status_line(c):
        _, text, reason = status[id(c)]
        return "  - status: %s%s" % (text, (" - " + reason) if reason else "")

    L.append("## 2. Do now (plan priority 1, ready now: monitoring and hygiene%s with no mail impact and nothing "
             "to check first)" % (" and records that keep a subdomain at the policy it follows today" if keeps else ""))
    L.append("")
    L += [row_line(c) for c in ready] or ["- none"]
    L.append("")
    L.append("## 2b. After a check (plan priority 1: publish each once the checks listed with it are confirmed; a "
             "quarantine-now row changes delivery for a domain the run measured sending nothing)")
    L.append("")
    items = []
    for c in checked:
        items += [row_line(c), status_line(c)]
        # a park row waits on its unused check, a task row on its inventory: said here, not only in plan.md
        items += ["  - before applying: %s" % pre for pre in c.get("prerequisites") or []]
    L += items or ["- none"]
    L.append("")
    L.append("## 2c. Waiting (plan priority 1 rows that cannot go out this week, and what each waits on)")
    L.append("")
    items = []
    for c in waiting:
        items += [row_line(c), status_line(c)]
        items += ["  - before applying: %s" % pre for pre in c.get("prerequisites") or []]
    L += items or ["- none"]
    L.append("")

    L.append("## 3. Fix senders (DKIM first)")
    L.append("")
    items = []
    ml = report.get("maillog") or {}
    # the census counts what the formal exceptions cover per sender stream (audit.py marks every excepted
    # message): the work is what they left, and the excepted count is named once; a census without those
    # counts (an older report) leaves the findings' own lines as they are
    census = ml.get("census") if isinstance(ml.get("census"), dict) else {}
    rows = census.get("by_sender") if isinstance(census.get("by_sender"), list) else []
    rows = [r for r in rows if isinstance(r, dict)]
    counted = any("excepted" in r for r in rows)

    def whole(value):
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0

    def left(total_key, excepted_key):
        """({sender: what is left}, how many the exceptions cover) over the census streams."""
        out, gone = {}, 0
        for r in rows:
            n = whole(r.get(total_key))
            x = min(whole(r.get(excepted_key)), n)
            gone += x
            if n > x:
                s = str(r.get("sender") or "?")
                out[s] = out.get(s, 0) + n - x
        return out, gone

    sent = {}  # every message each sender sent, its clean streams too: what breaks a tie, as in MAILFLOW-001's list
    for r in rows:
        s = str(r.get("sender") or "?")
        sent[s] = sent.get(s, 0) + whole(r.get("messages"))

    def tops(senders):
        """The busiest five as every list of senders ranks them (audit.sender_rank): the count, then the
        messages behind it, a tie by the sender's domain in the one order, then by address."""
        return "; ".join("%s x%d" % kv for kv in sorted(senders.items(), key=lambda kv: audit.sender_rank(
            kv[0], kv[1], headline, sent.get(kv[0])))[:5])

    for f in ml.get("findings") or []:
        if f.get("id") not in ("MAILFLOW-001", "MAILFLOW-002"):
            continue
        failures = f["id"] == "MAILFLOW-001"
        senders, gone = left(*(("genuine_failures", "excepted") if failures
                               else ("delivered_despite_fail", "excepted_delivered")))
        if not counted or not gone:
            items.append("- mail log: %s (%s) - %s" % (f["title"], f["evidence"], f["action"]))
        elif senders:
            n = sum(senders.values())
            what = ("logical %s failed with no passing copy" % ("message" if n == 1 else "messages") if failures
                    else "%s failed authentication but reached a mailbox" % ("message" if n == 1 else "messages"))
            items.append("- mail log: %d %s, from %d %s, besides %d formally excepted in audit.toml (section 6) "
                         "(top senders: %s) - %s" % (n, what, len(senders), "sender" if len(senders) == 1 else "senders",
                                                     gone, tops(senders), f["action"]))
        elif failures:  # nothing left to work; the delivered ones are among these
            items.append("- mail log: nothing to fix - %s formally excepted in audit.toml (section 6)"
                         % ("the 1 genuine failure is" if gone == 1 else "all %d genuine failures are" % gone))
    for sender in ml.get("spf_only_senders") or []:
        items.append("- mail log: %s (envelope %s) passes on SPF alone, %d msgs - aligned DKIM at that platform before reject"
                     % (sender.get("sender") or "?", sender.get("envelope_domain") or "?", sender.get("spf_only") or 0))
    rua = report.get("rua") or {}
    counts = audit.from_counts(rua)  # every From domain a source sends as, named, the busiest first (from_names)
    for stream in rua.get("failing_streams") or []:
        if stream.get("likely") == "likely_spoof" or stream.get("source_ip") in excepted_ips:
            continue
        items.append("- aggregate reports: %s fails %s/%s msgs as %s (%s) - find the owner; DKIM-sign it, or except it "
                     "with a removal criterion" % (stream.get("source_ip"), stream.get("fail"), stream.get("count"),
                                                   audit.from_names(stream.get("header_from"),
                                                                    counts.get(str(stream.get("source_ip"))), headline),
                                                   stream.get("likely")))
    for sender in rua.get("spf_only_senders") or []:
        items.append("- aggregate reports: %s passes on SPF alone, %d msgs as %s - aligned DKIM before reject"
                     % (sender.get("source_ip"), sender.get("spf_only") or 0,
                        audit.from_names(sender.get("header_from"), counts.get(str(sender.get("source_ip"))), headline)))
    for c in changes:
        if c.get("priority") == 2:
            items.append("- %s %s: %s" % (c["id"], c["domain"], c["why"]))
    L += items or ["- none"]
    L.append("")

    L.append("## 4. Tenant configuration (major or blocking findings from the PowerShell exports)")
    L.append("")
    items = []
    for name in ("rules", "bypasses", "groups"):
        for f in (report.get(name) or {}).get("findings") or []:
            if f.get("severity") in ("major", "blocking"):
                items.append("- %s: %s - %s" % (name, f["title"], f["action"]))
    L += items or ["- none, or no export was supplied (report.md says which)"]
    L.append("")

    L.append("## 5. Enforcement steps (each with its status; apply only when every prerequisite holds)")
    L.append("")
    rows = [c for c in changes if c.get("priority", 0) >= 3]
    for c in rows:
        # the row's own status (plan.row_status): a step whose gate says go waits on its checks, never "gated"
        L.append("- %s %s (%s): `%s` = `%s` - %s" % (c["id"], c["domain"], PRIORITY_WORD.get(c["priority"], "step"),
                                                      c["hostname"], c["value"], c["why"]))
        _, text, reason = plan_mod.status_of(c)
        L.append("  - status: %s%s" % (text, (" - " + reason) if reason else ""))
        for pre in c.get("prerequisites") or []:
            L.append("  - before applying: %s" % pre)
    if not rows:
        L.append("- none yet: the plan adds them once the earlier rows are done and a week of reports has flowed")
    L.append("")

    if exc.get("applied") or exc.get("expired") or exc.get("invalid"):
        L.append("## 6. Exceptions (audit.toml)")
        L.append("")
        for e in exc.get("applied") or []:
            owner = " (owner %s)" % e["owner"] if e.get("owner") else ""
            L.append("- in force until %s: %s - %s; remove when %s%s"
                     % (e["until"], e["match"], e["reason"], e["removal_criterion"], owner))
        for e in exc.get("expired") or []:
            L.append("- EXPIRED %s: %s - it blocks the gate again; renew with a new date or remove it" % (e["until"], e["match"]))
        for e in exc.get("invalid") or []:
            L.append("- NOT APPLIED: %s - %s" % (e.get("entry"), e.get("problem")))
        L.append("")

    if caveats:
        L.append("## Caveats")
        L.append("")
        # one per cut organization, in the order the pull ran: listed in the one order, the headline's first
        L += ["- %s" % c for c in next_steps.order_by_org(caveats, headline)]
        L.append("")

    L.append("Spoof streams that receivers already reject are not work items: enforcement is what stops them. "
             "report.md has every finding; plan.md has every record with its rollback.")
    return "\n".join(L) + "\n"


# what the run says about its summary, instead of the text itself (the text is in summary.txt)
DRY_RUN_HEADER = "Slack summary (dry run, not posted):"
NOT_POSTED = "summary.txt written (not posted: %s)"
# what each exit code means, said on the run's done line
EXIT_MEANING = {0: "nothing major found", 1: "findings to act on, not a crash"}
OPEN_ALSO = (("detail", "next_steps.md"), ("records", "plan.md"), ("how to check", "verify.md"))


def last_lines(report, top, code, strict_reasons, stamp, run_dir, latest, paint=None):
    """The last lines a run prints (plain words: domains and counts, never an address or a subject): the done line
    with the exit code and what it means, the status band's plain lines (next_steps.json top.lines_plain: the
    headline, the most critical organizations, the call with the plan ids ready now, what changed, what this data
    cannot show), the run folder, and the
    file to open first with the others beside it. Without a band, the done line and the paths."""
    paint = paint or console.painter()
    gate = (report.get("gate") or {}) if isinstance(report, dict) else {}
    names = [d for d in (gate.get("domains") or {})] if isinstance(gate.get("domains"), dict) else []
    orgs = top.get("orgs") if isinstance(top, dict) else None
    if not isinstance(orgs, int):
        orgs = len({next_steps.org_domain(str(d).lower()) for d in names})
    meaning = ("--strict (%s)" % strict_reasons[0]) if strict_reasons and code == 1 else EXIT_MEANING.get(code, "")
    done = "done: %d %s in %d %s audited - exit %d%s" % (
        len(names), "domain" if len(names) == 1 else "domains", orgs, "organization" if orgs == 1 else "organizations",
        code, (": " + meaning) if meaning else "")
    out = [paint.bold(done)]
    if isinstance(top, dict) and isinstance(top.get("lines_plain"), list):
        out += [str(line) for line in top["lines_plain"]]
    out.append(paint.bold("run %s:" % stamp) + " %s" % run_dir)
    first = next((n for n in ("brief.html", "next_steps.md", "report.md") if (latest / n).exists()), None)
    if first:
        also = ["%s: %s" % (what, n) for what, n in OPEN_ALSO if n != first and (latest / n).exists()]
        out.append(paint.bold("Open first:") + " %s%s" % (latest / first, ("  (%s)" % "; ".join(also)) if also else ""))
    return out


def main():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", metavar="TOML",
                     help="settings file (default: <repo root>/audit.toml when it exists; copy audit.example.toml)")
    pre.add_argument("--no-config", action="store_true", help="ignore audit.toml even if it exists")
    pre_args, _rest = pre.parse_known_args()
    ap = argparse.ArgumentParser(parents=[pre],
                                 description="Run the whole DMARC audit and write report, plan, to-do, history and summary.")
    ap.add_argument("domains", nargs="*",
                    help="domains, comma or space separated, audited beside the tenant's own (those are read whenever "
                         "the app registration can; default list: audit.toml's domains)")
    ap.add_argument("--file", metavar="PATH", help="file with one domain per line")
    ap.add_argument("--no-graph", action="store_true", help="never touch the tenant: no domain list, no mail log, no mailbox")
    ap.add_argument("--mailflow", action="store_true", help="add subdomains seen sending in the last 30 days")
    ap.add_argument("--offline", action="store_true", help="no DNS and no tenant; audit the given files only")
    ap.add_argument("--days", type=int, default=30,
                    help="mail-log window in days (max 30); the mail flow is always counted over 30 days")
    ap.add_argument("--max-rows", type=int, default=ROW_BUDGET, metavar="N",
                    help="mail-log rows kept per domain before older hours are skipped "
                         "(0 = no limit, default %d)" % ROW_BUDGET)
    ap.add_argument("--rua-max", type=int, default=RUA_MAX, metavar="N",
                    help="report-mailbox messages read per run (0 = no limit, default %d); a run "
                         "that stops resumes where it left off" % RUA_MAX)
    ap.add_argument("--report-days", type=int, default=30, help="aggregate-report window in days for this run's analysis")
    ap.add_argument("--maillog", metavar="CSV", help="use this mail-log export instead of pulling one")
    ap.add_argument("--auth-column", help="mail-log column holding the DMARC verdict (default DMARC when pulled)")
    ap.add_argument("--rua", nargs="+", default=[], metavar="PATH", help="saved aggregate report files or folders")
    ap.add_argument("--rua-mailbox", help="report mailbox (default: RUA_MAILBOX from .env)")
    ap.add_argument("--headers", nargs="+", default=[], metavar="FILE", help="message header files for DKIM proof")
    ap.add_argument("--known", metavar="LIST_OR_FILE", help="known sender domains and IP prefixes")
    ap.add_argument("--selectors", help="extra DKIM selectors to probe, comma separated")
    ap.add_argument("--resolver", default="8.8.8.8")
    ap.add_argument("--rua-address", metavar="MAILTO",
                    help="the run's report address: the plan puts it in new records and appends it to a record's rua "
                         "that lacks it (default: the report mailbox, --rua-mailbox or RUA_MAILBOX)")
    ap.add_argument("--owners", metavar="CSV",
                    help="who fixes what, for next_steps.md (default: <repo root>/%s when it exists; "
                         "see samples/owners.csv.example)" % next_steps.DEFAULT_OWNERS)
    ap.add_argument("--no-owners", action="store_true", help="write next_steps.md without an owners file")
    ap.add_argument("--out", default="audit-out", metavar="DIR")
    ap.add_argument("--keep", type=int, default=12, help="history runs to keep (default 12)")
    ap.add_argument("--vendor-domain", action="append", default=[], metavar="DOMAIN",
                    help="envelope domain known to be one of your vendors (repeatable; audit.toml vendor_domains)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 also when a gate is not go, the plan has holds, or a tenant step failed or was truncated")
    ap.add_argument("--no-notify", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the summary instead of posting it")
    ap.add_argument("--ignore-setup", action="store_true", help="continue even if verify_setup reports a failure")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    cfg, defaults = {}, {}
    try:
        if not pre_args.no_config:
            cfg = config_mod.load(pre_args.config)
            defaults = config_mod.collect_defaults(cfg)
            ap.set_defaults(**defaults)
        notify_cfg = config_mod.notify_settings(cfg)
        brief_cfg = config_mod.brief_settings(cfg)
    except config_mod.ConfigError as err:
        die(str(err))
    args = ap.parse_args()
    # --rua takes saved report files; the report address is --rua-address. Said before anything runs: read as a path,
    # an address fails only after the whole tenant pull
    addressed = [p for p in args.rua if str(p).strip().lower().startswith("mailto:")]
    if addressed:
        die("--rua takes report files or folders; did you mean --rua-address %s?" % addressed[0].strip())
    from_settings = "domains" in defaults and args.domains is defaults["domains"]  # nothing typed: the file's list
    owners, owners_path, owners_problem = load_owners(args.owners, args.no_owners)
    if owners_problem and args.owners:
        die(owners_problem)
    exceptions = cfg.get("exceptions") or []

    out = Path(args.out)
    run_dir, stamp = unique_run_dir(out / "history", utc_stamp())
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except OSError as err:
        die("cannot create %s: %s" % (run_dir, err))
    notes = []
    degraded = []  # tenant steps that failed or were cut short: --strict turns these into exit 1
    paint = console.painter(sys.stderr)

    def note(msg, shown=None):
        """Record msg for run.json; print it, or a painted variant of it, to stderr."""
        notes.append(msg)
        print(paint.dim("note: ") + (shown if shown is not None else msg), file=sys.stderr)

    def degrade(msg):
        degraded.append(msg)
        note(msg)

    if cfg.get("_path"):
        note("settings read from %s" % cfg["_path"])
    # an IP prefix among the vendor domains matches nothing: said on every run, and left out of the audit
    vendors, vendor_warnings = config_mod.split_vendor_domains(args.vendor_domain)
    for w in vendor_warnings:
        note(w)
    if owners_problem:  # the default file, unreadable: say so, carry on unassigned
        note("owners file skipped: %s" % owners_problem)
    elif not owners_path and not args.no_owners:
        note("no owners file - next_steps.md lists every action as unassigned "
             "(copy samples/owners.csv.example to %s)" % next_steps.DEFAULT_OWNERS)

    # 1. credentials and setup
    cred = None
    if not (args.offline or args.no_graph):
        try:
            cred = graph_client.creds(args.env_file)
        except graph_client.GraphError as err:
            note(str(err))
        if cred is None:
            note("no credentials in .env - tenant steps skipped (DNS still runs)")
    tok = None
    if cred:
        results = verify_setup.run_checks(args.env_file, mailbox=args.rua_mailbox)
        (run_dir / "setup.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
        failed = [r for r in results if r["status"] == "FAIL"]
        for r in results:
            if r["status"] != "PASS":
                note("setup %s: %s - %s" % (r["status"], r["check"], r["detail"]),
                     "setup %s: %s - %s" % (paint.status(r["status"]), r["check"], r["detail"]))
        if failed and not args.ignore_setup:
            die("setup check failed (%s); fix it or pass --ignore-setup" % "; ".join(r["check"] for r in failed))
        if failed:
            degrade("setup check failed (%s) - continuing because of --ignore-setup" % "; ".join(r["check"] for r in failed))
        try:
            tok = graph_client.TokenSource(cred)  # re-acquired on demand: a long run outlives one token
            tok()  # fail here, early, when the credentials are wrong
        except graph_client.GraphError as err:
            tok = None
            degrade("token failed, tenant steps skipped: %s" % err)

    # 2. domains, and with a token the mail flow of every one of them: one aggregate query, this token
    days = min(args.days, 30)  # the mail-log window, which the full-window totals share
    # the domains the tenant does not hold, from .env: read once step 1 loaded it (not with --offline or --no-graph)
    extra = os.environ.get(discover.EXTRA_KEY) if not (args.offline or args.no_graph) else None
    unaudited = {}  # every other name the mail-flow query saw under those orgs: the plan's sending subdomains
    inventory, dnotes = discover.discover(args.domains, args.file, use_graph=bool(tok), mailflow=bool(tok) and args.mailflow,
                                          resolver_addr=args.resolver, env_file=args.env_file, ns_lookup=not args.offline,
                                          tok=tok, days=MAILFLOW_DAYS, extra_domains=extra, seen=unaudited)
    for n in dnotes:
        note(n)
        if n.startswith("mail flow not measured"):
            degraded.append(n)
    if not inventory:
        die("nothing to audit: give domains, --file, credentials with Domain.Read.All, or EXTRA_DOMAINS in .env")
    domains = [r["domain"] for r in inventory]
    if from_settings:  # the domains came from audit.toml, not the command line: label them so
        for row in inventory:
            row["sources"] = ["settings" if s == "cli" else s for s in (row.get("sources") or [])]
    domain_sources = {r["domain"]: r["sources"] for r in inventory}
    typed, _ = discover.parse_domains(list(args.domains))  # the inventory is sorted; this is the order typed
    headline = typed[0] if typed and typed[0] in domain_sources else None
    if headline is None and args.file:  # nothing typed: the file's first line, in the order written
        try:
            listed, _ = discover.parse_domains(discover.read_domain_file(args.file))
        except Exception:  # discover read it already; failing again here only costs the hint
            listed = []
        headline = listed[0] if listed and listed[0] in domain_sources else None
    orgs = sorted({r["org_domain"] for r in inventory})
    (run_dir / "inventory.json").write_text(json.dumps({"domains": inventory, "notes": dnotes}, indent=1), encoding="utf-8")
    (run_dir / "domains.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")

    # 3. mail log
    maillog, auth_column = args.maillog, args.auth_column
    volumes = {}  # internal mail per org domain, from the sizing calls: the headline signal
    cuts = {}  # the orgs whose pull the row budget or the API cap cut: the report records them for the delta
    window_totals = None  # what the hunting service counts for those orgs over the full window
    counted_notes = []  # the counts, said once the audit has kept them: an answer it sets aside is not shown
    if tok and not maillog:
        maillog, mnotes = pull_maillog(tok, orgs, run_dir / "maillog.csv", days, args.max_rows, volumes, cuts)
        for n in mnotes:
            note(n)
            if "not pulled" in n or "that hour is truncated" in n:
                degraded.append(n)
        if maillog and not auth_column:
            auth_column = "DMARC"
        # a cut org's rows reach back only a few hours: its whole window is counted server side instead
        if maillog and cuts:
            window_totals, tnotes = pull_window_totals(tok, cuts, days)
            for n in tnotes:
                if ", counted in Advanced Hunting:" in n:
                    counted_notes.append(n)
                    continue
                note(n)
                if " not counted" in n:
                    degraded.append(n)

    # 4. aggregate reports
    rua_paths = list(args.rua)
    since = None
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(days=args.report_days)).strftime("%Y-%m-%d")
    archive_floor = (now - timedelta(days=max(args.report_days, ARCHIVE_DAYS))).strftime("%Y-%m-%d")
    mailbox = args.rua_mailbox or os.environ.get("RUA_MAILBOX")
    if tok and mailbox and fetch_rua is not None:
        stopped = None
        try:
            saved, rnotes = fetch_rua.fetch(tok, mailbox, out / "rua", out / "rua_state.json",
                                            max_messages=args.rua_max, floor=archive_floor)
        except graph_client.GraphError as err:
            # what was read before the failure is on disk and still counts
            rnotes = list(getattr(err, "notes", None) or [])
            stopped = "report mailbox read stopped early: %s - the reports saved so far are still used" % err
        for n in rnotes:
            note(n)
        if stopped:
            degrade(stopped)
    archived = (out / "rua").is_dir() and any((out / "rua").iterdir())
    if archived and mailbox and not args.offline:
        if not tok:
            note("report mailbox not read this run (no token) - analysing the reports already archived")
        rua_paths.append(str(out / "rua"))
        since = window_start

    # the run before this one: its report.json feeds the delta section, the summary and the trend
    prev_dir = previous_run(out / "history", stamp)
    prev_report = read_report(prev_dir / "report.json") if prev_dir else None
    if prev_dir and prev_report is None:
        note("previous run %s: report.json unreadable - no delta this run" % prev_dir.name)
    if prev_report is not None:  # an older report's cut is in the run.json beside it, nowhere in the report
        inherit_run_cuts(prev_report, prev_dir / "run.json")

    # 5. audit
    extra = {}
    if prev_report is not None and accepts(audit.build_report, "previous_report"):
        extra["previous_report"] = prev_report
    if headline and accepts(audit.build_report, "headline"):
        extra["headline"] = headline
    if volumes and len(volumes) == len(orgs) and accepts(audit.build_report, "volume"):
        extra["volume"] = volumes  # only a complete set ranks: a missing org would lose by default
    if accepts(audit.build_report, "maillog_cuts"):
        extra["maillog_cuts"] = cuts  # read before the delta is built: a cut org's counts are never compared
    if window_totals and accepts(audit.build_report, "window_totals"):
        extra["window_totals"] = window_totals
    if tok and accepts(audit.build_report, "mailflow"):
        # every audited name, measured (counts, zeros for nothing seen) or not (None: the query failed); and the
        # unaudited names the same query saw, so the plan knows which subdomains send through the tenant
        extra["mailflow"] = {"days": MAILFLOW_DAYS, "source": AGGREGATE_SOURCE,
                             "domains": {r["domain"]: r.get("mailflow") for r in inventory},
                             "unaudited": unaudited}
    try:
        report = audit.build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=rua_paths, maillog=maillog,
            header_files=args.headers, offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, auth_column=auth_column, since=since,
            vendor_domains=vendors, exceptions=exceptions, **extra)
    except audit.UsageError as err:
        die(str(err))
    if isinstance(report.get("inputs"), dict):
        report["inputs"]["run"] = stamp  # which run wrote it, for a reader that finds report.json on its own
    # the unaudited subdomains that send: whether each has a DMARC record of its own is a question for DNS, asked
    # before the plan reads it (never with --offline; a run whose DNS did not run has nothing to plan anyway)
    if report.get("dns") and not args.offline:
        report["dns_extra"], xnotes = lookup_unaudited(report, {r["domain"]: r for r in inventory},
                                                       audit.make_resolver(args.resolver))
        for n in xnotes:
            note(n)
    # the full-window totals the audit kept are said now, with their counts; the ones it set aside (fewer than the
    # rows kept, so not the whole window) appear only in the note that says so - never as a count
    rejected = (report.get("maillog") or {}).get("window_totals_rejected") or {}
    for n in counted_notes:
        org = n.split("full-window totals for ", 1)[1].split(" over the last ", 1)[0]
        if org.lower().rstrip(".") not in {str(o).lower().rstrip(".") for o in rejected}:
            note(n)
    for org, why in sorted(rejected.items()):
        n = "mail log: full-window totals for %s set aside, not shown: the answer holds %s" % (org, why)
        note(n)
        degraded.append(n)
    head = (report.get("gate") or {}).get("headline_domain")
    if head in domains:  # the headline first: a --file domains.txt re-run types it first, and so keeps it
        (run_dir / "domains.txt").write_text("\n".join([head] + [d for d in domains if d != head]) + "\n",
                                             encoding="utf-8")
    if tok and not args.maillog and orgs:
        note(headline_note(report.get("gate") or {}, orgs, volumes))
    if report.get("delta_error"):
        note(report["delta_error"])
    # an hour still at the API row cap dropped rows, and a row budget kept only the newest
    # hours: the mail-log counts for that domain are a floor, said so in the report too
    caveats = run_caveats(report, notes)
    md = audit.render_md(report)
    if caveats:
        md += "\n## Caveats\n\n" + "\n".join("- " + c for c in caveats) + "\n"
    if audit.write_report_json(report, run_dir / "report.json"):  # a large census goes to census.json beside it
        note("report.json keeps %s of the census; the whole census is in %s next to it"
             % (audit.CENSUS_KEEPS, audit.CENSUS_FILE))
    (run_dir / "report.md").write_text(md, encoding="utf-8")
    covered = str(fetch_rua.load_state(out / "rua_state.json").get("covered_from") or "")[:10] if fetch_rua else ""
    if since and covered and covered > since:
        note("the report archive starts at %s, after the %s start of this run's %d-day report window: reports "
             "before it were never read (fetch_rua.py --since %s fills them in)"
             % (covered, since, args.report_days, since))

    # 6. plan; its report address is --rua-address, else the mailbox the reports are read from: new records carry
    # it, and a record whose rua lacks it gets it appended (with neither, nothing is appended; with a list of
    # addresses, nothing either, and a note says so)
    plan, plan_doc = {"changes": [], "holds": []}, None  # plan_doc: only a plan that was written
    if report.get("dns"):
        try:
            plan = plan_mod.build_plan(report, {"domains": inventory}, args.rua_address or plan_mod.report_uri(mailbox))
            plan_mod.write(plan, run_dir)
            plan_doc = plan
            if plan_mod.address_note(args.rua_address):
                note("plan: " + plan_mod.address_note(args.rua_address))
        except ValueError as err:
            note("no plan written: %s" % err)
    else:
        note("no DNS section (offline run): no plan written")
    (run_dir / "todo.md").write_text(render_todo(report, plan, caveats), encoding="utf-8")

    # 7. history and metrics
    metrics_path = out / "metrics.json"
    history_notes = []  # a history file that is not what collect.py writes is set aside, never overwritten
    entries = read_history(metrics_path, list, stamp, history_notes) or []
    filled = backfill_cut_orgs(entries, prev_dir.name if prev_dir else None, prev_report)
    if filled:  # an entry from before the cuts were recorded: its own report says which orgs were cut
        note("metrics.json: the previous run's entry now records the mail log cut for %s, from its report"
             % ", ".join(filled))
    entries.append(metrics_entry(stamp, report, plan))
    metrics_path.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    (out / "metrics.md").write_text(render_metrics(entries), encoding="utf-8")

    # 8. the stakeholder document (entries already holds this run; next_steps skips it for the trend)
    steps = write_next_steps(run_dir, report, plan_doc, entries, owners, owners_path, prev_report, prev_dir, note,
                             brief_cfg)
    try:  # the same document designed as one page, from the files just written, as brief.py builds it by hand: it
        # never fails the run (absolute: brief resolves relative paths from the repo root)
        if steps is None:  # the note above says why there is no document; the page would have nothing to lay out
            raise brief.BriefError("no next-steps document in this run")
        brief.write_run(run_dir.resolve())
    except Exception as err:
        note("no brief.html written (%s: %s)" % (type(err).__name__, err))
        # the note says there is no page, so none may be left for latest/ to copy: brief.py writes all or nothing,
        # and whatever failed on the way, a half-written brief.html never stands in for this run's
        try:
            (run_dir / "brief.html").unlink(missing_ok=True)
        except OSError as gone:
            note("a partial brief.html is left in %s (%s): it is not this run's page" % (run_dir, gone))
    try:  # how to check every finding and plan row by hand, from the files above: it never fails the run
        verify.write(report, plan_doc, run_dir)
    except Exception as err:
        note("no verify.md written (%s: %s)" % (type(err).__name__, err))

    latest = out / "latest"
    latest.mkdir(parents=True, exist_ok=True)
    for name in RUN_FILES:  # latest/ holds exactly this run's files: one an earlier run wrote and this one did not goes
        (latest / name).unlink(missing_ok=True)
    for name in RUN_FILES:
        src = run_dir / name
        if src.exists():
            shutil.copy2(src, latest / name)
    try:  # verify.md's filled queries, this run's only; a folder that cannot be cleared (a shell open in it, a
        # read-only file) is a note, never the end of the run: run.json, summary.txt and the post still follow
        shutil.rmtree(latest / "queries", ignore_errors=True)
        if (run_dir / "queries").is_dir():
            shutil.copytree(run_dir / "queries", latest / "queries", dirs_exist_ok=True)
        fresh = {p.name for p in (run_dir / "queries").iterdir()} if (run_dir / "queries").is_dir() else set()
        stale = sorted(p.name for p in (latest / "queries").iterdir() if p.name not in fresh) \
            if (latest / "queries").is_dir() else []
        if stale:
            note("latest/queries keeps %d file(s) an earlier run wrote that could not be removed (%s); this run's "
                 "queries are the ones verify.md lists" % (len(stale), ", ".join(stale[:3])))
    except OSError as err:
        note("latest/queries not refreshed (%s): this run's queries are in %s" % (err, run_dir / "queries"))
    history = sorted(p for p in (out / "history").iterdir() if p.is_dir())
    for old in history[:-args.keep] if args.keep > 0 else []:
        shutil.rmtree(old, ignore_errors=True)

    known_before, new_senders = update_senders(out / "senders.json", report, stamp, history_notes)
    for n in history_notes:
        degrade(n)
    # a sender identity under an organization the previous run's cut log may have missed is recorded, but not
    # announced as new: the delta withholds it for the same reason (notify says so in the summary)
    maybe_missed = sorted(notify.senders_maybe_missed(report, new_senders))
    announced = [k for k in new_senders if k not in maybe_missed]

    # 9. summary and notification: the plan as written (plan_doc), never the empty stand-in an offline run uses
    # above - a plan this run did not build is not "0 changes waiting"
    try:
        text = notify.summarize(report, prev_report, plan_doc, known_senders=known_before, history=entries,
                                top=(steps or {}).get("top"), where="%s/latest" % (out.name or "audit-out"))
    except Exception as exc:  # a damaged earlier report or history entry: the run's files still get written
        text = "*DMARC audit* summary not built: %s: %s (report.md and next_steps.md hold the run)" % (
            type(exc).__name__, exc)
        note("summary not built: %s: %s" % (type(exc).__name__, exc))
    (run_dir / "summary.txt").write_text(text + "\n", encoding="utf-8")
    shutil.copy2(run_dir / "summary.txt", latest / "summary.txt")
    strict_reasons = []
    if args.strict:
        for d, g in ((report.get("gate") or {}).get("domains") or {}).items():
            if g.get("verdict") != "go":
                strict_reasons.append("%s: gate %s" % (d, g.get("verdict")))
        if plan.get("holds"):
            strict_reasons.append("%d plan hold(s)" % len(plan["holds"]))
        strict_reasons += degraded
    code = 1 if (report.get("exit_code") == 1 or strict_reasons) else 0

    def write_run_json():
        (run_dir / "run.json").write_text(json.dumps({"run": stamp, "notes": notes, "domains": domains,
                                                      "maillog": bool(maillog), "rua_paths": rua_paths,
                                                      "previous_run": prev_dir.name if prev_dir else None,
                                                      "owners_file": str(owners_path) if owners_path else None,
                                                      "next_steps": steps is not None,
                                                      "settings": cfg.get("_path"),
                                                      "new_senders": announced[:RUN_JSON_SENDERS],
                                                      "new_senders_count": len(announced),
                                                      "new_senders_maybe_missed": maybe_missed[:RUN_JSON_SENDERS],
                                                      "new_senders_maybe_missed_count": len(maybe_missed),
                                                      "caveats": caveats, "degraded": degraded,
                                                      "strict_reasons": strict_reasons,
                                                      "exit_code": code}, indent=1), encoding="utf-8")
        shutil.copy2(run_dir / "run.json", latest / "run.json")  # written after the RUN_FILES copy, like summary.txt

    write_run_json()  # now, so a failure inside the notification still leaves a run record
    said = None  # what became of the summary, said once before the run's last lines; never the text unlabeled
    if args.no_notify:
        pass
    elif args.dry_run:
        said = "%s\n%s" % (DRY_RUN_HEADER, text)
    elif not notify_cfg["enabled"]:
        note("summary not posted: [notify] enabled = false in audit.toml")
        said = NOT_POSTED % "[notify] enabled = false in audit.toml"
    else:
        try:
            run_hunting.load_env(args.env_file)
        except SystemExit:
            pass
        webhook = next((os.environ.get(k) for k in notify.WEBHOOK_KEYS if os.environ.get(k)), None)
        if webhook:
            try:
                notify.post(webhook, text, notify_cfg["target"])
                note("summary posted")
            except RuntimeError as err:
                note("summary not posted: %s" % err)
        else:
            said = NOT_POSTED % "no SLACK_WEBHOOK_URL"
    write_run_json()  # once more: the notification outcome is on record too

    for r in strict_reasons:
        print("strict: %s" % r, file=sys.stderr)
    if said:
        print(said)
    sys.stdout.flush()
    sys.stderr.flush()
    print()  # after every note: the run's last lines, what to read first
    for line in last_lines(report, (steps or {}).get("top"), code, strict_reasons, stamp, run_dir, latest,
                           console.painter()):
        print(line)
    sys.exit(code)


if __name__ == "__main__":
    main()
