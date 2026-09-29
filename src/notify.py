#!/usr/bin/env python3
"""Post a short status to Slack after an audit run.

Reads report.json (and optionally the previous run's report.json and this
run's plan.json) and writes one message: policy and gate per domain, what
changed since last time (new findings, resolved findings, newly identified
senders, spoofing blocked, failure counts), the trend over the last runs,
and how many plan rows are waiting. Aggregates only: domains, counts and
sender identities (source IPs, envelope domains), never addresses or
subject lines. Nothing is posted unless a webhook is given; --dry-run prints
the message instead. The webhook URL is read from SLACK_WEBHOOK_URL in .env
or the environment and is never printed. Teams is designed in
(TEAMS_WEBHOOK_URL, build_payload) but not yet verified against a live
webhook.

  python src/notify.py --report audit-out/report.json --dry-run
  python src/notify.py --report audit-out/report.json --previous audit-out/history/2026-01-01/report.json --plan audit-out/plan.json

Exit codes: 0 posted or printed, 1 the post failed, 2 usage error.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import run_hunting

WEBHOOK_KEYS = ("SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL")
TARGETS = ("slack", "teams")
TREND_RUNS = 4


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except OSError as err:
        die("cannot read %s: %s" % (path, err))
    except json.JSONDecodeError as err:
        die("%s is not valid JSON: %s" % (path, err))


def finding_keys(report):
    return {(f.get("source") or f.get("domain") or "", f.get("id")) for f in report.get("findings") or []}


def rua_sources(report):
    """Sending sources by IP from the outside view (rua_parse's by_source_ip)."""
    rua = report.get("rua") or {}
    out = {}
    for s in rua.get("by_source_ip") or []:
        if isinstance(s, dict) and s.get("source_ip"):
            out[s["source_ip"]] = s
    return out


def sender_label(u):
    """A short name for an unknown-sender entry, whatever its shape."""
    if isinstance(u, dict):
        return u.get("source_ip") or (" ".join(str(u.get(k)) for k in ("kind", "value") if u.get(k)) or "?")
    return str(u)


def sender_keys(report):
    """Sender identities one run saw, as aggregates: rua source IPs and
    mail-log envelope domains, keyed ip:<address> and envelope:<domain>. No
    From addresses, no people - this set is what collect.py remembers in
    senders.json so 'newly identified' means new to the whole history."""
    keys = set()
    for s in (report.get("rua") or {}).get("by_source_ip") or []:
        if isinstance(s, dict) and s.get("source_ip"):
            keys.add("ip:" + str(s["source_ip"]))
    for v in (report.get("maillog") or {}).get("verdicts") or []:
        env = (v.get("envelope_domain") or "").strip().lower() if isinstance(v, dict) else ""
        if env:
            keys.add("envelope:" + env)
    return keys


def _key_label(key):
    kind, _, value = key.partition(":")
    return value + (" (envelope)" if kind == "envelope" else "")


def trend_word(values):
    """improving / worsening / flat from the first and last known value."""
    pts = [v for v in values if v is not None]
    if len(pts) < 2:
        return "too few runs to call"
    if pts[-1] < pts[0]:
        return "improving"
    if pts[-1] > pts[0]:
        return "worsening"
    return "flat"


def summarize(report, previous=None, plan=None, known_senders=None, history=None):
    """Plain-text (Slack mrkdwn) message. Deterministic, no secrets.

    known_senders: every sender key seen in earlier runs (collect.py keeps
    them); with it, "newly identified" means never seen before, not merely
    absent last week. history: the metrics.json entries, newest last, for
    the trend line over the last TREND_RUNS runs."""
    lines = []
    gen = report.get("generated_utc", "")
    lines.append("*DMARC audit* %s" % gen[:16].replace("T", " "))

    gate = report.get("gate") or {}
    per = gate.get("domains") or {}
    for dom in sorted(per):
        g = per[dom]
        lines.append("- `%s`: p=%s, gate *%s*, next: %s" % (dom, g.get("current_policy", "?"), g.get("verdict", "?"),
                                                            g.get("next_step", "?")))

    summ = report.get("summary") or {}
    sev = summ.get("by_severity") or {}
    lines.append("- findings: %d (%s)" % (summ.get("findings", 0),
                                          ", ".join("%s %d" % (k, v) for k, v in sorted(sev.items())) or "none"))

    ml = (report.get("maillog") or {}).get("counters") or {}
    if ml:
        lines.append("- mail log: %d genuine failures (%d rows would say so), %d delivered despite failing, spoof-like %d"
                     % (ml.get("genuine_failures", 0), ml.get("raw_failing_rows", 0), ml.get("delivered_despite_fail", 0),
                        (ml.get("by_likely") or {}).get("likely_spoof", 0)))
    rua = report.get("rua") or {}
    tot = rua.get("totals") or {}
    if tot:
        disp = tot.get("by_disposition") or {}
        lines.append("- outside view: %d messages, pass rate %.1f%%, spoofing blocked by receivers: %d rejected, %d quarantined"
                     % (tot.get("messages", 0), 100 * float(tot.get("pass_rate", 0) or 0),
                        disp.get("reject", 0), disp.get("quarantine", 0)))
        unk = rua.get("unknown_senders") or []
        if unk:
            lines.append("- unknown senders in reports: %d (top: %s)"
                         % (len(unk), ", ".join(sender_label(u) for u in unk[:3])))

    if previous:
        now_f, prev_f = finding_keys(report), finding_keys(previous)
        new_f, gone_f = sorted(now_f - prev_f), sorted(prev_f - now_f)
        if new_f:
            lines.append("- *new findings*: " + ", ".join("%s %s" % (d.replace("dns:", ""), i) for d, i in new_f[:8])
                         + (" ..." if len(new_f) > 8 else ""))
        if gone_f:
            lines.append("- resolved: " + ", ".join("%s %s" % (d.replace("dns:", ""), i) for d, i in gone_f[:8]))
        prev_per = (previous.get("gate") or {}).get("domains") or {}
        for dom in sorted(per):
            a, b = prev_per.get(dom, {}), per[dom]
            if a and (a.get("current_policy") != b.get("current_policy") or a.get("verdict") != b.get("verdict")):
                lines.append("- `%s` changed: p=%s/%s -> p=%s/%s" % (dom, a.get("current_policy"), a.get("verdict"),
                                                                     b.get("current_policy"), b.get("verdict")))
        if known_senders is None:
            now_s, prev_s = rua_sources(report), rua_sources(previous)
            new_s = sorted(set(now_s) - set(prev_s))
            if new_s:
                lines.append("- *newly seen senders*: " + ", ".join(new_s[:6]) + (" ..." if len(new_s) > 6 else ""))
        pml = (previous.get("maillog") or {}).get("counters") or {}
        if ml and pml:
            d = ml.get("genuine_failures", 0) - pml.get("genuine_failures", 0)
            lines.append("- genuine failures vs last run: %+d" % d)
        ptot = (previous.get("rua") or {}).get("totals") or {}
        if tot and ptot:
            d = 100 * (float(tot.get("pass_rate", 0) or 0) - float(ptot.get("pass_rate", 0) or 0))
            lines.append("- pass rate vs last run: %+.1f points" % d)

    if known_senders is not None:
        now_keys = sender_keys(report)
        if not known_senders:
            lines.append("- baseline run: %d sender identities recorded; newly identified senders are reported "
                         "from the next run" % len(now_keys))
        else:
            new_s = sorted(k for k in now_keys if k not in known_senders)
            if new_s:
                lines.append("- *newly identified senders* (never seen in an earlier run): "
                             + ", ".join(_key_label(k) for k in new_s[:6]) + (" ..." if len(new_s) > 6 else ""))
            else:
                lines.append("- newly identified senders: none")

    if history and len(history) >= 2:
        pts = list(history)[-TREND_RUNS:]
        gf = [h.get("genuine_failures") for h in pts]
        pr = [h.get("rua_pass_rate") for h in pts]
        parts = []
        if any(x is not None for x in gf):
            parts.append("genuine failures " + ", ".join("-" if x is None else str(x) for x in gf))
        if any(x is not None for x in pr):
            parts.append("pass rate " + ", ".join("-" if x is None else "%.1f%%" % (100 * float(x)) for x in pr))
        if parts:
            lines.append("- trend over the last %d runs (%s): %s" % (len(pts), trend_word(gf), "; ".join(parts)))

    if plan:
        ch = plan.get("changes") or []
        p1 = sum(1 for c in ch if c.get("priority") == 1)
        lines.append("- plan: %d change(s) waiting, %d are zero-risk monitoring/hygiene; %d hold(s)"
                     % (len(ch), p1, len(plan.get("holds") or [])))
    return "\n".join(lines)


def target_for(webhook):
    """slack, unless the URL is a Teams workflow or connector endpoint."""
    w = (webhook or "").lower()
    return "teams" if ("webhook.office.com" in w or "logic.azure.com" in w) else "slack"


def build_payload(text, target="slack"):
    """The JSON body for one target. Slack incoming webhooks take {"text"} in
    mrkdwn. Teams is designed in here so a card layout can be added without
    touching any caller; until it is verified against a live webhook it sends
    the same plain-text body, which the legacy Teams connectors accepted."""
    if target not in TARGETS:
        raise ValueError("unknown notify target: %s (expected one of %s)" % (target, ", ".join(TARGETS)))
    return {"text": text}


def post(webhook, text, target=None):
    body = json.dumps(build_payload(text, target or target_for(webhook))).encode("utf-8")
    req = urllib.request.Request(webhook, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        raise RuntimeError("webhook answered HTTP %d" % err.code)
    except OSError as err:
        raise RuntimeError("webhook unreachable: %s" % getattr(err, "reason", err.__class__.__name__))


def main():
    ap = argparse.ArgumentParser(description="Post a short DMARC audit status to a Slack or Teams webhook.")
    ap.add_argument("--report", required=True, help="this run's report.json")
    ap.add_argument("--previous", help="the previous run's report.json, for deltas")
    ap.add_argument("--plan", help="this run's plan.json")
    ap.add_argument("--webhook", help="webhook URL (default: SLACK_WEBHOOK_URL or TEAMS_WEBHOOK_URL from .env)")
    ap.add_argument("--target", choices=TARGETS, help="payload shape (default: guessed from the URL; slack)")
    ap.add_argument("--dry-run", action="store_true", help="print the message, post nothing")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    args = ap.parse_args()

    report = load(args.report)
    previous = load(args.previous) if args.previous else None
    plan = load(args.plan) if args.plan else None
    text = summarize(report, previous, plan)
    if args.dry_run:
        print(text)
        return
    try:
        run_hunting.load_env(args.env_file)
    except SystemExit as err:
        die(str(err))
    webhook = args.webhook or next((os.environ.get(k) for k in WEBHOOK_KEYS if os.environ.get(k)), None)
    if not webhook:
        die("no webhook: pass --webhook or set SLACK_WEBHOOK_URL in .env (or use --dry-run)")
    try:
        post(webhook, text, args.target)
    except RuntimeError as err:
        print("error: " + str(err), file=sys.stderr)
        sys.exit(1)
    print("posted %d characters" % len(text))


if __name__ == "__main__":
    main()
