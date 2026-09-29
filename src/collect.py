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
  5. run the audit: DNS posture, deduplicated mail log, outside view, headers
  6. write the rollout plan (the exact records to publish next) and todo.md,
     the one prioritised list built from the report and the plan
  7. keep a dated history and the running metrics, so the next run can say
     what changed
  8. post the summary to Slack or Teams (SLACK_WEBHOOK_URL in .env; --dry-run
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
  history/<UTC stamp>/   report.md report.json plan.md plan.json todo.md inventory.json domains.txt summary.txt run.json
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
import json
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import audit
import config as config_mod
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
RUN_FILES = ("report.md", "report.json", "plan.md", "plan.json", "todo.md", "inventory.json", "domains.txt",
             "summary.txt", "run.json", "setup.json", "maillog.csv")
PRIORITY_WORD = {1: "now, zero delivery risk", 2: "before enforcement", 3: "enforcement step, gated",
                 4: "subdomain policy, gated", 5: "final hardening, gated"}


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


ROW_CAP = 100000  # one hunting call never returns more than this


def kql_for_domain(template, domain, start_days=30, end_days=0):
    if PLACEHOLDER not in template:
        raise ValueError("the sender_domain placeholder line was not found in queries/raw_maillog.kql")
    kql = template.replace(PLACEHOLDER, 'let sender_domain = "%s";' % domain, 1)
    kql = re.sub(r"let window_start\s*=[^;]+;", "let window_start  = ago(%dd);" % start_days, kql, count=1)
    if end_days:
        kql = re.sub(r"let window_end\s*=[^;]+;", "let window_end    = ago(%dd);" % end_days, kql, count=1)
    return kql


def pull_domain(tok, template, org, start_days, end_days, notes):
    """One domain's rows for ago(start)..ago(end), splitting the window when
    a call lands exactly on the 100,000-row API cap - that many rows means
    rows were silently dropped, so the window halves until every call fits."""
    res = graph_client.hunting(tok, kql_for_domain(template, org, start_days, end_days),
                               "P%dD" % (start_days - end_days))
    got = res.get("results") or []
    cols = run_hunting.columns(res)
    if len(got) < ROW_CAP:
        return got, cols, 1
    span = start_days - end_days
    if span <= 1:
        notes.append("mail log: %s STILL at the 100,000-row cap on a single day "
                     "(%dd..%dd ago) - that slice is truncated; split the query "
                     "by subdomain for this domain" % (org, start_days, end_days))
        return got, cols, 1
    mid = end_days + span // 2
    notes.append("mail log: %s hit the 100,000-row API cap (%dd..%dd ago) - splitting the window"
                 % (org, start_days, end_days))
    left, cols, n1 = pull_domain(tok, template, org, start_days, mid, notes)
    right, cols, n2 = pull_domain(tok, template, org, mid, end_days, notes)
    return left + right, cols, n1 + n2


def pull_maillog(tok, org_domains, out_csv, days=30):
    """raw_maillog.kql per organizational domain, merged into one CSV."""
    template = QUERY.read_text(encoding="utf-8-sig")
    rows, cols, notes = [], None, []
    seen = set()
    for org in org_domains:
        try:
            got, res_cols, calls = pull_domain(tok, template, org, days, 0, notes)
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
        notes.append("mail log: %d rows for %s (last %d days)%s"
                     % (len(rows) - before, org, days, suffix))
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
    for f in ml.get("findings") or []:
        if f.get("id") in ("MAILFLOW-001", "MAILFLOW-002"):
            items.append("- mail log: %s (%s) - %s" % (f["title"], f["evidence"], f["action"]))
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
    ap.add_argument("--keep", type=int, default=12, help="history runs to keep (default 12)")
    ap.add_argument("--vendor-domain", action="append", default=[], metavar="DOMAIN",
                    help="envelope domain known to be one of your vendors (repeatable; audit.toml vendor_domains)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 also when a gate is not go, the plan has holds, or a tenant step failed or was truncated")
    ap.add_argument("--no-notify", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the summary instead of posting it")
    ap.add_argument("--ignore-setup", action="store_true", help="continue even if verify_setup reports a failure")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    cfg = {}
    try:
        if not pre_args.no_config:
            cfg = config_mod.load(pre_args.config)
            ap.set_defaults(**config_mod.collect_defaults(cfg))
        notify_cfg = config_mod.notify_settings(cfg)
    except config_mod.ConfigError as err:
        die(str(err))
    args = ap.parse_args()
    exceptions = cfg.get("exceptions") or []

    out = Path(args.out)
    run_dir, stamp = unique_run_dir(out / "history", utc_stamp())
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except OSError as err:
        die("cannot create %s: %s" % (run_dir, err))
    notes = []
    degraded = []  # tenant steps that failed or were cut short: --strict turns these into exit 1

    def note(msg):
        notes.append(msg)
        print("note: " + msg, file=sys.stderr)

    def degrade(msg):
        degraded.append(msg)
        note(msg)

    if cfg.get("_path"):
        note("settings read from %s" % cfg["_path"])

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
        if failed:
            degrade("setup check failed (%s) - continuing because of --ignore-setup" % "; ".join(r["check"] for r in failed))
        try:
            tok = graph_client.token(cred)
        except graph_client.GraphError as err:
            degrade("token failed, tenant steps skipped: %s" % err)

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
            if "not pulled" in n or "STILL at the" in n:
                degraded.append(n)
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
            degrade("report mailbox not read: %s" % err)

    # 5. audit
    try:
        report = audit.build_report(
            domains=domains, domain_sources=domain_sources, rua_paths=rua_paths, maillog=maillog,
            header_files=args.headers, offline=args.offline, resolver_addr=args.resolver,
            selectors=[s.strip() for s in args.selectors.split(",")] if args.selectors else (),
            known=args.known, auth_column=auth_column, since=since,
            vendor_domains=args.vendor_domain, exceptions=exceptions)
    except audit.UsageError as err:
        die(str(err))
    # a slice still at the API row cap dropped rows: the mail-log counts for that domain
    # are a floor, and a failure in it may be an echo whose passing leg was cut off
    caveats = ["%s - mail-log counts for that domain are a floor and its failures are not verified" % n
               for n in notes if "STILL at the" in n]
    if caveats:
        report["caveats"] = caveats
    md = audit.render_md(report)
    if caveats:
        md += "\n## Caveats\n\n" + "\n".join("- " + c for c in caveats) + "\n"
    (run_dir / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(md, encoding="utf-8")

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
    (run_dir / "todo.md").write_text(render_todo(report, plan, caveats), encoding="utf-8")

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

    known_before, new_senders = update_senders(out / "senders.json", report, stamp)

    # 8. summary and notification
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
    (run_dir / "run.json").write_text(json.dumps({"run": stamp, "notes": notes, "domains": domains,
                                                  "maillog": bool(maillog), "rua_paths": rua_paths,
                                                  "settings": cfg.get("_path"), "new_senders": new_senders,
                                                  "caveats": caveats, "degraded": degraded,
                                                  "strict_reasons": strict_reasons,
                                                  "exit_code": code}, indent=1), encoding="utf-8")
    shutil.copy2(run_dir / "run.json", latest / "run.json")  # written after the copy loop above on purpose
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

    print("run %s: %s" % (stamp, run_dir))
    print("latest: %s" % latest)
    for r in strict_reasons:
        print("strict: %s" % r, file=sys.stderr)
    sys.exit(code)


if __name__ == "__main__":
    main()
