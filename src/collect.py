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
  6. write the rollout plan: the exact records to publish next
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

Outputs under --out (default audit-out/):
  history/<UTC stamp>/   report.md report.json plan.md plan.json next_steps.md next_steps.json
                         inventory.json domains.txt summary.txt run.json
  latest/                the newest run, same files
  metrics.json           one entry per run (policy, gate, findings, failure counts, pass rate)
  metrics.md             the last runs as a table
  rua/                   every report file ever pulled from the mailbox

Exit codes: 0 no major or blocking findings, 1 findings at that level, 2 usage error or setup failure.
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
RUN_FILES = ("report.md", "report.json", "plan.md", "plan.json", "next_steps.md", "next_steps.json",
             "inventory.json", "domains.txt", "summary.txt", "run.json", "setup.json", "maillog.csv")


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
ROW_BUDGET = 250000  # rows kept per domain before older slices are skipped (0 = no limit)


def kql_for_domain(template, domain, start_days=30, end_days=0):
    if PLACEHOLDER not in template:
        raise ValueError("the sender_domain placeholder line was not found in queries/raw_maillog.kql")
    kql = template.replace(PLACEHOLDER, 'let sender_domain = "%s";' % domain, 1)
    kql = re.sub(r"let window_start\s*=[^;]+;", "let window_start  = ago(%dd);" % start_days, kql, count=1)
    if end_days:
        kql = re.sub(r"let window_end\s*=[^;]+;", "let window_end    = ago(%dd);" % end_days, kql, count=1)
    return kql


def pull_domain(tok, template, org, start_days, end_days, notes, budget=None):
    """One domain's rows for ago(start)..ago(end), splitting the window when
    a call lands exactly on the 100,000-row API cap - that many rows means
    rows were silently dropped, so the window halves until every call fits.
    A window whose response keeps dropping mid-stream after the retries in
    run_hunting is halved the same way: a smaller body survives a flaky
    connection that a 30-day apex log does not.

    The Timespan sent with every call reaches back to the slice's own start.
    The API applies Timespan from now, so a Timespan equal to the slice
    length empties every slice that does not end today; that bug left runs
    with apex rows from the newest day only. The newer half of a split is
    pulled first, and budget, a dict holding {"rows": n}, stops the walk at
    the older slices once n rows are in hand, so a domain busier than the
    cap on a single day cannot flood memory with thirty truncated days."""
    if budget is not None and budget.get("rows", 0) <= 0:
        if not budget.get("noted"):
            notes.append("mail log: %s row budget reached at %dd..%dd ago - older slices skipped; "
                         "the rows cover the newest days only (raise --max-rows or narrow the query)"
                         % (org, start_days, end_days))
            budget["noted"] = True
        return [], None, 0
    span = start_days - end_days
    try:
        res = graph_client.hunting(tok, kql_for_domain(template, org, start_days, end_days),
                                   "P%dD" % start_days)
    except graph_client.GraphError as err:
        if "did not complete" not in str(err) or span <= 1:
            raise
        notes.append("mail log: %s window %dd..%dd ago dropped mid-stream after retries - "
                     "splitting the window" % (org, start_days, end_days))
        return pull_halves(tok, template, org, start_days, end_days, notes, budget)
    got = res.get("results") or []
    cols = run_hunting.columns(res)
    if len(got) < ROW_CAP or span <= 1:
        if span <= 1 and len(got) >= ROW_CAP:
            notes.append("mail log: %s STILL at the 100,000-row cap on a single day "
                         "(%dd..%dd ago) - that slice is truncated; split the query "
                         "by subdomain for this domain" % (org, start_days, end_days))
        if budget is not None:
            budget["rows"] -= len(got)
        return got, cols, 1
    notes.append("mail log: %s hit the 100,000-row API cap (%dd..%dd ago) - splitting the window"
                 % (org, start_days, end_days))
    return pull_halves(tok, template, org, start_days, end_days, notes, budget)


def pull_halves(tok, template, org, start_days, end_days, notes, budget):
    """Both halves of a window, the newer one first so a row budget keeps
    the days that matter most."""
    mid = end_days + (start_days - end_days) // 2
    right, cols_r, n2 = pull_domain(tok, template, org, mid, end_days, notes, budget)
    left, cols_l, n1 = pull_domain(tok, template, org, start_days, mid, notes, budget)
    return left + right, cols_l or cols_r, n1 + n2


def pull_maillog(tok, org_domains, out_csv, days=30, max_rows=ROW_BUDGET):
    """raw_maillog.kql per organizational domain, merged into one CSV. Each
    domain's note names the rows it got and the time span they cover: when
    the API cap or the row budget cut the walk short, that span is the real
    window, whatever `days` asked for."""
    template = QUERY.read_text(encoding="utf-8-sig")
    rows, cols, notes = [], None, []
    seen = set()
    for org in org_domains:
        budget = {"rows": max_rows} if max_rows else None
        try:
            got, res_cols, calls = pull_domain(tok, template, org, days, 0, notes, budget)
        except (graph_client.GraphError, ValueError) as err:
            notes.append("mail log for %s not pulled: %s" % (org, err))
            continue
        cols = cols or res_cols
        before = len(rows)
        for r in got:
            key = tuple(sorted(r.items()))  # slice boundaries can repeat a leg
            if key not in seen:
                seen.add(key)
                rows.append(r)
        suffix = " (%d window slices)" % calls if calls > 1 else ""
        stamps = sorted(str(r.get("Timestamp")) for r in rows[before:] if r.get("Timestamp"))
        span = "; rows span %s to %s" % (stamps[0], stamps[-1]) if stamps else ""
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
        doms = "; ".join("%s %s/%s" % (d, v.get("policy"), v.get("gate")) for d, v in list(e["domains"].items())[:4])
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


def main():
    ap = argparse.ArgumentParser(description="Run the whole DMARC audit and write report, plan, history and summary.")
    ap.add_argument("domains", nargs="*", help="domains, comma or space separated (default: the tenant's)")
    ap.add_argument("--file", metavar="PATH", help="file with one domain per line")
    ap.add_argument("--no-graph", action="store_true", help="never touch the tenant: no domain list, no mail log, no mailbox")
    ap.add_argument("--mailflow", action="store_true", help="add subdomains seen sending in the last 30 days")
    ap.add_argument("--offline", action="store_true", help="no DNS and no tenant; audit the given files only")
    ap.add_argument("--days", type=int, default=30, help="mail-log window in days (max 30)")
    ap.add_argument("--max-rows", type=int, default=ROW_BUDGET, metavar="N",
                    help="mail-log rows kept per domain before older days are skipped "
                         "(0 = no limit, default %d)" % ROW_BUDGET)
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
    ap.add_argument("--keep", type=int, default=52, help="history runs to keep (default 52)")
    ap.add_argument("--no-notify", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the summary instead of posting it")
    ap.add_argument("--ignore-setup", action="store_true", help="continue even if verify_setup reports a failure")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    args = ap.parse_args()
    owners, owners_path, owners_problem = load_owners(args.owners, args.no_owners)
    if owners_problem and args.owners:
        die(owners_problem)

    out = Path(args.out)
    run_dir, stamp = unique_run_dir(out / "history", utc_stamp())
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except OSError as err:
        die("cannot create %s: %s" % (run_dir, err))
    notes = []
    paint = console.painter(sys.stderr)

    def note(msg, shown=None):
        """Record msg for run.json; print it, or a painted variant of it, to stderr."""
        notes.append(msg)
        print(paint.dim("note: ") + (shown if shown is not None else msg), file=sys.stderr)

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
        try:
            tok = graph_client.token(cred)
        except graph_client.GraphError as err:
            note("token failed, tenant steps skipped: %s" % err)

    # 2. domains
    inventory, dnotes = discover.discover(args.domains, args.file, use_graph=bool(tok), mailflow=bool(tok) and args.mailflow,
                                          resolver_addr=args.resolver, env_file=args.env_file, ns_lookup=not args.offline)
    for n in dnotes:
        note(n)
    if not inventory:
        die("nothing to audit: give domains, --file, or credentials with Domain.Read.All")
    domains = [r["domain"] for r in inventory]
    domain_sources = {r["domain"]: r["sources"] for r in inventory}
    typed, _ = discover.parse_domains(list(args.domains))  # the inventory is sorted; this is the order typed
    headline = typed[0] if typed and typed[0] in domain_sources else None
    orgs = sorted({r["org_domain"] for r in inventory})
    (run_dir / "inventory.json").write_text(json.dumps({"domains": inventory, "notes": dnotes}, indent=1), encoding="utf-8")
    (run_dir / "domains.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")

    # 3. mail log
    maillog, auth_column = args.maillog, args.auth_column
    if tok and not maillog:
        maillog, mnotes = pull_maillog(tok, orgs, run_dir / "maillog.csv", min(args.days, 30), args.max_rows)
        for n in mnotes:
            note(n)
        if maillog and not auth_column:
            auth_column = "DMARC"

    # 4. aggregate reports
    rua_paths = list(args.rua)
    since = None
    mailbox = args.rua_mailbox or os.environ.get("RUA_MAILBOX")
    if tok and mailbox and fetch_rua is not None:
        try:
            saved, rnotes = fetch_rua.fetch(tok, mailbox, out / "rua", out / "rua_state.json")
            for n in rnotes:
                note(n)
            if any((out / "rua").iterdir()):
                rua_paths.append(str(out / "rua"))
                since = (datetime.now(timezone.utc) - timedelta(days=args.report_days)).strftime("%Y-%m-%d")
        except graph_client.GraphError as err:
            note("report mailbox not read: %s" % err)

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
    try:
        report = audit.build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=rua_paths, maillog=maillog,
            header_files=args.headers, offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, auth_column=auth_column, since=since, **extra)
    except audit.UsageError as err:
        die(str(err))
    (run_dir / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(audit.render_md(report), encoding="utf-8")

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
    for name in RUN_FILES:
        src = run_dir / name
        if src.exists():
            shutil.copy2(src, latest / name)
    history = sorted(p for p in (out / "history").iterdir() if p.is_dir())
    for old in history[:-args.keep] if args.keep > 0 else []:
        shutil.rmtree(old, ignore_errors=True)

    # 9. summary and notification
    text = notify.summarize(report, prev_report, plan)
    (run_dir / "summary.txt").write_text(text + "\n", encoding="utf-8")
    shutil.copy2(run_dir / "summary.txt", latest / "summary.txt")
    (run_dir / "run.json").write_text(json.dumps({"run": stamp, "notes": notes, "domains": domains,
                                                  "maillog": bool(maillog), "rua_paths": rua_paths,
                                                  "previous_run": prev_dir.name if prev_dir else None,
                                                  "owners_file": str(owners_path) if owners_path else None,
                                                  "next_steps": steps is not None,
                                                  "exit_code": report.get("exit_code", 0)}, indent=1), encoding="utf-8")
    shutil.copy2(run_dir / "run.json", latest / "run.json")  # written after the RUN_FILES copy, like summary.txt
    if args.no_notify:
        pass
    elif args.dry_run:
        print(text)
    else:
        try:
            run_hunting.load_env(args.env_file)
        except SystemExit:
            pass
        webhook = next((os.environ.get(k) for k in notify.WEBHOOK_KEYS if os.environ.get(k)), None)
        if webhook:
            try:
                notify.post(webhook, text)
                note("summary posted")
            except RuntimeError as err:
                note("summary not posted: %s" % err)
        else:
            print(text)

    out_paint = console.painter()
    if steps and steps.get("one_liner"):
        print(out_paint.bold("next steps:") + " " + steps["one_liner"])
    print(out_paint.bold("run %s:" % stamp) + " %s" % run_dir)
    print(out_paint.bold("latest:") + " %s" % latest)
    sys.exit(1 if report.get("exit_code") == 1 else 0)


if __name__ == "__main__":
    main()
