#!/usr/bin/env python3
"""One command for the whole audit, built to run unattended every week.

What it does, in order, and what it skips when it cannot:

  1. verify the app registration (skipped with no credentials or --offline)
  2. discover the domains: command line, --file, the tenant's own list,
     and with --mailflow every subdomain seen sending in 30 days
  3. pull the raw mail log for each organizational domain through advanced
     hunting (skipped with no credentials; --maillog uses a file instead)
  4. pull new aggregate reports from the report mailbox (RUA_MAILBOX in .env;
     --rua uses saved files instead)
  5. run the audit: DNS posture, deduplicated mail log, outside view, headers
  6. write the rollout plan: the exact records to publish next
  7. keep a dated history and the running metrics, so the next run can say
     what changed
  8. post the summary to Slack or Teams (SLACK_WEBHOOK_URL in .env; --dry-run
     prints it; --no-notify skips it)

Everything is read-only toward the tenant. No AI is involved at any step;
the outputs are what a human reads, and what an AI agent may read later.

  python src/collect.py                              # tenant domains, tenant data, weekly shape
  python src/collect.py example.com,other.example    # named domains merged with the tenant's
  python src/collect.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --auth-column DMARC

Outputs under --out (default audit-out/):
  history/<UTC stamp>/   report.md report.json plan.md plan.json inventory.json domains.txt summary.txt run.json
  latest/                the newest run, same files
  metrics.json           one entry per run (policy, gate, findings, failure counts, pass rate)
  metrics.md             the last runs as a table
  rua/                   every report file ever pulled from the mailbox

Exit codes: 0 no major or blocking findings, 1 findings at that level, 2 usage error or setup failure.
"""

import argparse
import csv
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import audit
import discover
import graph_client
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
RUN_FILES = ("report.md", "report.json", "plan.md", "plan.json", "inventory.json", "domains.txt",
             "summary.txt", "run.json", "setup.json", "maillog.csv")


def die(msg):
    print("error: " + msg, file=sys.stderr)
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


def kql_for_domain(template, domain):
    if PLACEHOLDER not in template:
        raise ValueError("the sender_domain placeholder line was not found in queries/raw_maillog.kql")
    return template.replace(PLACEHOLDER, 'let sender_domain = "%s";' % domain, 1)


def pull_maillog(tok, org_domains, out_csv, days=30):
    """raw_maillog.kql once per organizational domain, merged into one CSV."""
    template = QUERY.read_text(encoding="utf-8-sig")
    rows, cols, notes = [], None, []
    for org in org_domains:
        try:
            res = graph_client.hunting(tok, kql_for_domain(template, org), "P%dD" % days)
        except (graph_client.GraphError, ValueError) as err:
            notes.append("mail log for %s not pulled: %s" % (org, err))
            continue
        got = res.get("results") or []
        cols = cols or run_hunting.columns(res)
        rows.extend(got)
        notes.append("mail log: %d rows for %s (last %d days)" % (len(got), org, days))
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
    ap.add_argument("--out", default="audit-out", metavar="DIR")
    ap.add_argument("--keep", type=int, default=52, help="history runs to keep (default 52)")
    ap.add_argument("--no-notify", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the summary instead of posting it")
    ap.add_argument("--ignore-setup", action="store_true", help="continue even if verify_setup reports a failure")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    args = ap.parse_args()

    out = Path(args.out)
    run_dir, stamp = unique_run_dir(out / "history", utc_stamp())
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except OSError as err:
        die("cannot create %s: %s" % (run_dir, err))
    notes = []

    def note(msg):
        notes.append(msg)
        print("note: " + msg, file=sys.stderr)

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
                note("setup %s: %s - %s" % (r["status"], r["check"], r["detail"]))
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
    orgs = sorted({r["org_domain"] for r in inventory})
    (run_dir / "inventory.json").write_text(json.dumps({"domains": inventory, "notes": dnotes}, indent=1), encoding="utf-8")
    (run_dir / "domains.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")

    # 3. mail log
    maillog, auth_column = args.maillog, args.auth_column
    if tok and not maillog:
        maillog, mnotes = pull_maillog(tok, orgs, run_dir / "maillog.csv", min(args.days, 30))
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

    # 5. audit
    try:
        report = audit.build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=rua_paths, maillog=maillog,
            header_files=args.headers, offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, auth_column=auth_column, since=since)
    except audit.UsageError as err:
        die(str(err))
    (run_dir / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(audit.render_md(report), encoding="utf-8")

    # 6. plan
    plan = {"changes": [], "holds": []}
    if report.get("dns"):
        try:
            plan = plan_mod.build_plan(report, {"domains": inventory}, args.rua_address)
            plan_mod.write(plan, run_dir)
        except ValueError as err:
            note("no plan written: %s" % err)
    else:
        note("no DNS section (offline run): no plan written")

    # 7. history, latest, metrics
    prev_dir = previous_run(out / "history", stamp)
    prev_report = None
    if prev_dir:
        try:
            prev_report = json.loads((prev_dir / "report.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev_report = None
    metrics_path = out / "metrics.json"
    try:
        entries = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else []
    except ValueError:
        entries = []
    entries.append(metrics_entry(stamp, report, plan))
    metrics_path.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    (out / "metrics.md").write_text(render_metrics(entries), encoding="utf-8")
    latest = out / "latest"
    latest.mkdir(parents=True, exist_ok=True)
    for name in RUN_FILES:
        src = run_dir / name
        if src.exists():
            shutil.copy2(src, latest / name)
    history = sorted(p for p in (out / "history").iterdir() if p.is_dir())
    for old in history[:-args.keep] if args.keep > 0 else []:
        shutil.rmtree(old, ignore_errors=True)

    # 8. summary and notification
    text = notify.summarize(report, prev_report, plan)
    (run_dir / "summary.txt").write_text(text + "\n", encoding="utf-8")
    shutil.copy2(run_dir / "summary.txt", latest / "summary.txt")
    (run_dir / "run.json").write_text(json.dumps({"run": stamp, "notes": notes, "domains": domains,
                                                  "maillog": bool(maillog), "rua_paths": rua_paths,
                                                  "exit_code": report.get("exit_code", 0)}, indent=1), encoding="utf-8")
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

    print("run %s: %s" % (stamp, run_dir))
    print("latest: %s" % latest)
    sys.exit(1 if report.get("exit_code") == 1 else 0)


if __name__ == "__main__":
    main()
