#!/usr/bin/env python3
"""One command for the whole audit, built to run unattended every week.

What it does, in order, and what it skips when it cannot:

  1. verify the app registration (skipped with no credentials or --offline)
  2. discover the domains: command line, --file, the tenant's own list,
     and with --mailflow every subdomain seen sending in 30 days
  3. pull the raw mail log for each organizational domain through advanced
     hunting; a domain that lands on the 100,000-row API cap is pulled in
     window slices (skipped with no credentials; --maillog uses a file instead)
  4. pull new aggregate reports from the report mailbox (RUA_MAILBOX in .env;
     --rua uses saved files instead)
  5. run the audit: DNS posture, deduplicated mail log, outside view, headers;
     the previous run's report.json goes in too, so the report carries a
     delta section (what changed since last time); the domain typed first on
     the command line is the report's headline domain (gate.headline) - the
     inventory itself is sorted, so the audit is told what was typed first
  6. write the rollout plan (the exact records to publish next) and todo.md,
     the one prioritised list built from the report and the plan
  7. keep a dated history and the running metrics, so the next run can say
     what changed
  8. write the stakeholder document, next_steps.md and next_steps.json, from
     the report, the plan, the metrics and the owners file (<repo root>/
     owners.csv when it exists; --owners PATH points elsewhere, --no-owners
     skips it; start from samples/owners.csv.example)
  9. post the summary to Slack or Teams (SLACK_WEBHOOK_URL in .env; --dry-run
     prints it; --no-notify skips it)

Everything is read-only toward the tenant. No AI is involved at any step;
the outputs are what a human reads, and what an AI agent may read later.

  python src/collect.py                              # tenant domains, tenant data, weekly shape
  python src/collect.py example.com,other.example    # named domains merged with the tenant's
  python src/collect.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --auth-column DMARC

Settings: audit.toml in the repo root (copy audit.example.toml) supplies the
domains, known senders, retention, the notification switch and the formal
exceptions the gate honours; a command-line flag beats the file. Secrets stay
in .env.

Outputs under --out (default audit-out/):
  history/<UTC stamp>/   report.md report.json plan.md plan.json next_steps.md next_steps.json
                         todo.md inventory.json domains.txt summary.txt run.json
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
import config as config_mod
import console
import discover
import graph_client
import next_steps
import notify
import plan as plan_mod
import run_hunting
import verify_setup

try:
    import fetch_rua
except ImportError:  # pragma: no cover
    fetch_rua = None

ROOT = Path(__file__).resolve().parent.parent
QUERY = ROOT / "queries" / "raw_maillog.kql"
PLACEHOLDER = 'let sender_domain = "example.com";'
RUN_FILES = ("report.md", "report.json", "plan.md", "plan.json", "next_steps.md", "next_steps.json", "todo.md",
             "inventory.json", "domains.txt", "summary.txt", "run.json", "setup.json", "maillog.csv")
PRIORITY_WORD = {1: "now, zero delivery risk", 2: "before enforcement", 3: "enforcement step, gated",
                 4: "subdomain policy, gated", 5: "final hardening, gated"}


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
    walk at the older slices once n rows are in hand. info, a dict, receives
    the sizing totals (total, internal) and the planned and pulled slice
    counts. Returns (rows, columns, data calls)."""
    if budget is not None and budget.get("rows", 0) <= 0:
        if not budget.get("noted"):
            notes.append("mail log: %s row budget reached at %s ago - older rows skipped; the rows "
                         "cover only the last %s (raise --max-rows to keep more)"
                         % (org, _window(start_hours, end_hours), _ago(end_hours)))
            budget["noted"] = True
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
                got, c, n = pull_domain(tok, template, org, a, b, notes, budget, sized=True)
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
        return pull_halves(tok, template, org, start_hours, end_hours, notes, budget)
    got = res.get("results") or []
    cols = run_hunting.columns(res)
    if len(got) < ROW_CAP or span <= 1:
        if len(got) >= ROW_CAP:
            notes.append("mail log: %s has more than 100,000 rows within one hour (%s ago) - that "
                         "hour is truncated" % (org, _window(start_hours, end_hours)))
        if budget is not None:
            budget["rows"] -= len(got)
        return got, cols, 1
    notes.append("mail log: %s hit the 100,000-row API cap (%s ago) - splitting the window"
                 % (org, _window(start_hours, end_hours)))
    return pull_halves(tok, template, org, start_hours, end_hours, notes, budget)


def pull_halves(tok, template, org, start_hours, end_hours, notes, budget):
    """Both halves of a window, the newer one first so a row budget keeps
    the hours that matter most."""
    mid = end_hours + (start_hours - end_hours) // 2
    right, cols_r, n2 = pull_domain(tok, template, org, mid, end_hours, notes, budget, sized=True)
    left, cols_l, n1 = pull_domain(tok, template, org, start_hours, mid, notes, budget, sized=True)
    return right + left, cols_r or cols_l, n1 + n2


def pull_maillog(tok, org_domains, out_csv, days=30, max_rows=ROW_BUDGET, volumes=None):
    """raw_maillog.kql per organizational domain, merged into one CSV. Each
    domain's note names the rows it got and the time span they cover; when
    the row budget kept only the newest part of a busy domain, the note says
    so, with the sized total. volumes, a dict, receives each org domain's
    internal (Intra-org) row count from its sizing call: the uncapped,
    spoof-proof volume collect.py hands audit.py for the headline."""
    template = QUERY.read_text(encoding="utf-8-sig")
    rows, cols, notes = [], None, []
    seen = set()
    for org in org_domains:
        budget = {"rows": max_rows} if max_rows else None
        info = {}
        try:
            got, res_cols, calls = pull_domain(tok, template, org, days * 24, 0, notes, budget, info=info)
        except (graph_client.GraphError, ValueError) as err:
            notes.append("mail log for %s not pulled: %s" % (org, err))
            got = None
        if volumes is not None:
            if "internal" not in info:  # the sizing did not answer: one more try, for the volume alone
                hourly_counts(tok, template, org, days * 24, 0, info)
            if "internal" in info:
                volumes[org] = info["internal"]  # measured even when the rows themselves failed
        if got is None:
            continue
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
    run must not stop this one. utf-8-sig, so a BOM from an editor is fine."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("gate") else None


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


def write_next_steps(run_dir, report, plan, entries, owners, owners_path, prev_report, prev_dir, note):
    """next_steps.md and next_steps.json in the run dir, from the report, the
    plan (None when none was written), the metrics history, the owners rows
    and the previous run. Returns the document, or None after a note: the
    document is derived from files already on disk, so it never fails the run."""
    prev_path = (prev_dir / "report.json").resolve() if prev_dir else None
    try:
        doc = next_steps.build(report, plan, entries, owners, prev_report,
                               owners_path=owners_path, previous_path=prev_path)
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
        "maillog_hours": ((report.get("maillog") or {}).get("window") or {}).get("hours"),
        # each audited domain's own span: the row budget cuts one busy domain while the whole log's span holds
        "maillog_hours_by_domain": {d: c["window"].get("hours")
                                    for d, c in (((report.get("maillog") or {}).get("by_domain") or {}).items())
                                    if d != audit.OTHER and isinstance(c, dict) and isinstance(c.get("window"), dict)
                                    and c["window"].get("hours") is not None},
        "delivered_despite_fail": ml.get("delivered_despite_fail"),
        "likely_spoof": (ml.get("by_likely") or {}).get("likely_spoof"),
        "rua_messages": tot.get("messages"),
        "rua_pass_rate": tot.get("pass_rate"),
        "rua_rejected": (tot.get("by_disposition") or {}).get("reject"),
        "plan_changes": len(plan.get("changes") or []),
        "plan_priority1": sum(1 for c in plan.get("changes") or [] if c.get("priority") == 1),
    }


def render_metrics(entries, last=12):
    rows = entries[-last:]
    L = ["# Runs", "", "| run | domains: policy / gate | findings | genuine failures | pass rate | plan rows |", "|---|---|---|---|---|---|"]
    for e in rows:
        doms = "; ".join("%s %s/%s" % (d, v.get("policy") or "unknown", v.get("gate"))
                         for d, v in list(e["domains"].items())[:4])
        if len(e["domains"]) > 4:
            doms += " (+%d)" % (len(e["domains"]) - 4)
        f = e.get("findings") or {}
        fs = ", ".join("%s %d" % (k, v) for k, v in sorted(f.items())) or "-"
        pr = "%.1f%%" % (100 * float(e["rua_pass_rate"])) if e.get("rua_pass_rate") is not None else "-"
        L.append("| %s | %s | %s | %s | %s | %d (%d now) |" % (e["run"], doms, fs,
                                                               e.get("genuine_failures") if e.get("genuine_failures") is not None else "-",
                                                               pr, e.get("plan_changes", 0), e.get("plan_priority1", 0)))
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


def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def update_senders(path, report, stamp):
    """senders.json remembers every sender identity ever seen (notify.sender_keys:
    rua source IPs and mail-log envelope domains) with its first and last run,
    so "newly identified" means new to the whole history, not merely absent
    last week. Returns (keys known before this run, keys new in this run)."""
    state = load_json(path, {})
    seen = state.get("senders") if isinstance(state.get("senders"), dict) else {}
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
    every line says which file holds the evidence."""
    gate = report.get("gate") or {}
    exc = gate.get("exceptions") or {}
    excepted_ips = set(exc.get("excepted_streams") or [])
    changes = plan.get("changes") or []
    holds = plan.get("holds") or []
    L = ["# To-do", "",
         "Built from report.json and plan.json of %s. Work top to bottom. Nothing here has been applied; "
         "every DNS row is a proposal for a human to review." % (report.get("generated_utc") or "this run"), ""]

    L.append("## Where each domain stands")
    L.append("")
    per = gate.get("domains") or {}
    for d, g in sorted(per.items()):
        L.append("- %s: p=%s, gate %s, next step: %s"
                 % (d, g.get("current_policy") or "unknown", g.get("verdict"), g.get("next_step")))
    if not per:
        L.append("- no per-domain verdict in this run")
    L.append("")

    L.append("## 1. Decide first (plan holds)")
    L.append("")
    L += ["- %s: %s" % (h["domain"], h["reason"]) for h in holds] or ["- none"]
    L.append("")

    L.append("## 2. Do now (plan priority 1, zero delivery risk)")
    L.append("")
    rows = [c for c in changes if c.get("priority") == 1]
    L += ["- %s %s: %s at `%s` = `%s` (current: `%s`) - %s"
          % (c["id"], c["domain"], c["record"], c["hostname"], c["value"], c["current"], c["why"]) for c in rows] or ["- none"]
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

    def tops(senders):
        return "; ".join("%s x%d" % kv for kv in sorted(senders.items(), key=lambda kv: (-kv[1], kv[0]))[:5])

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
    for stream in rua.get("failing_streams") or []:
        if stream.get("likely") == "likely_spoof" or stream.get("source_ip") in excepted_ips:
            continue
        items.append("- aggregate reports: %s fails %s/%s msgs as %s (%s) - find the owner; DKIM-sign it, or except it "
                     "with a removal criterion" % (stream.get("source_ip"), stream.get("fail"), stream.get("count"),
                                                   ", ".join((stream.get("header_from") or [])[:2]), stream.get("likely")))
    for sender in rua.get("spf_only_senders") or []:
        items.append("- aggregate reports: %s passes on SPF alone, %d msgs as %s - aligned DKIM before reject"
                     % (sender.get("source_ip"), sender.get("spf_only") or 0, ", ".join((sender.get("header_from") or [])[:2])))
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

    L.append("## 5. Gated enforcement steps (apply only when every prerequisite holds)")
    L.append("")
    rows = [c for c in changes if c.get("priority", 0) >= 3]
    for c in rows:
        L.append("- %s %s (%s): `%s` = `%s` - %s" % (c["id"], c["domain"], PRIORITY_WORD.get(c["priority"], "gated"),
                                                      c["hostname"], c["value"], c["why"]))
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
        L += ["- %s" % c for c in caveats]
        L.append("")

    L.append("Spoof streams that receivers already reject are not work items: enforcement is what stops them. "
             "report.md has every finding; plan.md has every record with its rollback.")
    return "\n".join(L) + "\n"


def main():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", metavar="TOML",
                     help="settings file (default: <repo root>/audit.toml when it exists; copy audit.example.toml)")
    pre.add_argument("--no-config", action="store_true", help="ignore audit.toml even if it exists")
    pre_args, _rest = pre.parse_known_args()
    ap = argparse.ArgumentParser(parents=[pre],
                                 description="Run the whole DMARC audit and write report, plan, to-do, history and summary.")
    ap.add_argument("domains", nargs="*", help="domains, comma or space separated (default: audit.toml, else the tenant's)")
    ap.add_argument("--file", metavar="PATH", help="file with one domain per line")
    ap.add_argument("--no-graph", action="store_true", help="never touch the tenant: no domain list, no mail log, no mailbox")
    ap.add_argument("--mailflow", action="store_true", help="add subdomains seen sending in the last 30 days")
    ap.add_argument("--offline", action="store_true", help="no DNS and no tenant; audit the given files only")
    ap.add_argument("--days", type=int, default=30, help="mail-log window in days (max 30)")
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
    ap.add_argument("--rua-address", metavar="MAILTO", help="reporting address the plan puts in new records")
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
    except config_mod.ConfigError as err:
        die(str(err))
    args = ap.parse_args()
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

    # 2. domains
    inventory, dnotes = discover.discover(args.domains, args.file, use_graph=bool(tok), mailflow=bool(tok) and args.mailflow,
                                          resolver_addr=args.resolver, env_file=args.env_file, ns_lookup=not args.offline)
    for n in dnotes:
        note(n)
    if not inventory:
        die("nothing to audit: give domains, --file, or credentials with Domain.Read.All")
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
    if tok and not maillog:
        maillog, mnotes = pull_maillog(tok, orgs, run_dir / "maillog.csv", min(args.days, 30), args.max_rows,
                                       volumes)
        for n in mnotes:
            note(n)
            if "not pulled" in n or "that hour is truncated" in n:
                degraded.append(n)
        if maillog and not auth_column:
            auth_column = "DMARC"

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

    # 5. audit
    extra = {}
    if prev_report is not None and accepts(audit.build_report, "previous_report"):
        extra["previous_report"] = prev_report
    if headline and accepts(audit.build_report, "headline"):
        extra["headline"] = headline
    if volumes and len(volumes) == len(orgs) and accepts(audit.build_report, "volume"):
        extra["volume"] = volumes  # only a complete set ranks: a missing org would lose by default
    try:
        report = audit.build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=rua_paths, maillog=maillog,
            header_files=args.headers, offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, auth_column=auth_column, since=since,
            vendor_domains=args.vendor_domain, exceptions=exceptions, **extra)
    except audit.UsageError as err:
        die(str(err))
    if tok and not args.maillog and orgs:
        note(headline_note(report.get("gate") or {}, orgs, volumes))
    # an hour still at the API row cap dropped rows, and a row budget kept only the newest
    # hours: the mail-log counts for that domain are a floor, said so in the report too
    caveats = []
    for n in notes:
        if "that hour is truncated" in n:
            caveats.append("%s - mail-log counts for that domain are a floor and its failures are not verified" % n)
        elif "row budget reached" in n:
            caveats.append("%s - mail-log counts for that domain cover that span only" % n)
    if caveats:
        report["caveats"] = caveats
        cut = truncation_text(notes)
        if cut and isinstance(report.get("maillog"), dict):
            report["maillog"]["truncation"] = cut  # the status document's 'cut short, so a floor' clause
    md = audit.render_md(report)
    if caveats:
        md += "\n## Caveats\n\n" + "\n".join("- " + c for c in caveats) + "\n"
    (run_dir / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(md, encoding="utf-8")
    covered = str(fetch_rua.load_state(out / "rua_state.json").get("covered_from") or "")[:10] if fetch_rua else ""
    if since and covered and covered > since:
        note("the report archive starts at %s, after the %s start of this run's %d-day report window: reports "
             "before it were never read (fetch_rua.py --since %s fills them in)"
             % (covered, since, args.report_days, since))

    # 6. plan
    plan, plan_doc = {"changes": [], "holds": []}, None  # plan_doc: only a plan that was written
    if report.get("dns"):
        try:
            plan = plan_mod.build_plan(report, {"domains": inventory}, args.rua_address)
            plan_mod.write(plan, run_dir)
            plan_doc = plan
        except ValueError as err:
            note("no plan written: %s" % err)
    else:
        note("no DNS section (offline run): no plan written")
    (run_dir / "todo.md").write_text(render_todo(report, plan, caveats), encoding="utf-8")

    # 7. history and metrics
    metrics_path = out / "metrics.json"
    try:
        entries = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else []
    except ValueError:
        entries = []
    entries.append(metrics_entry(stamp, report, plan))
    metrics_path.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    (out / "metrics.md").write_text(render_metrics(entries), encoding="utf-8")

    # 8. the stakeholder document (entries already holds this run; next_steps skips it for the trend)
    steps = write_next_steps(run_dir, report, plan_doc, entries, owners, owners_path, prev_report, prev_dir, note)

    latest = out / "latest"
    latest.mkdir(parents=True, exist_ok=True)
    for name in RUN_FILES:  # latest/ holds exactly this run's files: one an earlier run wrote and this one did not goes
        (latest / name).unlink(missing_ok=True)
    for name in RUN_FILES:
        src = run_dir / name
        if src.exists():
            shutil.copy2(src, latest / name)
    history = sorted(p for p in (out / "history").iterdir() if p.is_dir())
    for old in history[:-args.keep] if args.keep > 0 else []:
        shutil.rmtree(old, ignore_errors=True)

    known_before, new_senders = update_senders(out / "senders.json", report, stamp)

    # 9. summary and notification
    text = notify.summarize(report, prev_report, plan, known_senders=known_before, history=entries)
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
                                                      "settings": cfg.get("_path"), "new_senders": new_senders,
                                                      "caveats": caveats, "degraded": degraded,
                                                      "strict_reasons": strict_reasons,
                                                      "exit_code": code}, indent=1), encoding="utf-8")
        shutil.copy2(run_dir / "run.json", latest / "run.json")  # written after the RUN_FILES copy, like summary.txt

    write_run_json()  # now, so a failure inside the notification still leaves a run record
    if args.no_notify:
        pass
    elif args.dry_run:
        print(text)
    elif not notify_cfg["enabled"]:
        note("summary not posted: [notify] enabled = false in audit.toml")
        print(text)
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
            print(text)
    write_run_json()  # once more: the notification outcome is on record too

    out_paint = console.painter()
    if steps and steps.get("one_liner"):
        print(out_paint.bold("next steps:") + " " + steps["one_liner"])
    print(out_paint.bold("run %s:" % stamp) + " %s" % run_dir)
    print(out_paint.bold("latest:") + " %s" % latest)
    for r in strict_reasons:
        print("strict: %s" % r, file=sys.stderr)
    sys.exit(code)


if __name__ == "__main__":
    main()
