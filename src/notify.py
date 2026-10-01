#!/usr/bin/env python3
"""Post a short status to Slack (or Teams) after an audit run.

Reads report.json (and optionally the previous run's report.json and this
run's plan.json) and writes one message: policy and gate per domain (with the
domain's own genuine failures when the report attributes the mail log per
domain, maillog.by_domain), the worst census entries (maillog.census), what
changed since last time (new findings, resolved findings, newly seen senders,
spoofing blocked, failure counts), and how many plan rows are waiting. When
the report carries its own delta (audit.py --previous writes report.delta)
the deltas come from there; --previous is then only needed for the pass-rate
and newly-seen-source deltas, which the delta does not hold. Nothing is
posted unless a webhook is given; --dry-run prints the message instead. The
webhook URL is read from SLACK_WEBHOOK_URL (or TEAMS_WEBHOOK_URL) in .env or
the environment and is never printed.

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

# census entries named in the message (the rest is a "+N more")
CENSUS_TOP = 3


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


def delta_finding_keys(entries):
    """(source, id) pairs from a delta's findings_new or findings_resolved list, in its order."""
    return [((f.get("source") or ""), f.get("id")) for f in entries or [] if isinstance(f, dict)]


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


def census_top(census, n=CENSUS_TOP):
    """(labels, failing) for a census dict: the n worst entries as short labels,
    senders when the census has them, else envelope domains; entries with no
    genuine failures are skipped. failing counts every failing entry."""
    rows = census.get("by_sender") or census.get("by_envelope") or []
    rows = [r for r in rows if isinstance(r, dict) and r.get("genuine_failures")]
    out = []
    for r in rows[:n]:
        name = r.get("sender") or r.get("envelope_domain") or "?"
        via = (" via %s" % r["envelope_domain"]) if r.get("sender") and r.get("envelope_domain") else ""
        out.append("%s x%d%s (%s)" % (name, int(r["genuine_failures"]), via, r.get("likely") or "unknown"))
    return out, len(rows)


def _more(shown, total):
    return (" (+%d more)" % (total - shown)) if total > shown else ""


def summarize(report, previous=None, plan=None):
    """Plain-text (Slack mrkdwn) message. Deterministic, no secrets. Deltas
    come from report["delta"] when the run carried one, else are recomputed
    from previous; pass rate and newly seen sources always need previous."""
    lines = []
    gen = report.get("generated_utc", "")
    lines.append("*DMARC audit* %s" % gen[:16].replace("T", " "))

    maillog = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    by_dom = maillog.get("by_domain") if isinstance(maillog.get("by_domain"), dict) else {}
    dl = report.get("delta") if isinstance(report.get("delta"), dict) else None
    dl_dom = (dl or {}).get("by_domain") or {}
    gate = report.get("gate") or {}
    per = gate.get("domains") or {}
    for dom in sorted(per):
        g = per[dom]
        line = "- `%s`: p=%s, gate *%s*, next: %s" % (dom, g.get("current_policy", "?"), g.get("verdict", "?"),
                                                      g.get("next_step", "?"))
        own = by_dom.get(dom)
        if isinstance(own, dict) and own.get("genuine_failures") is not None:
            line += " - %d genuine failures of its own" % own["genuine_failures"]
            d = dl_dom.get(dom)
            if isinstance(d, dict) and d.get("genuine_failures") is not None:
                line += " (%+d vs last run)" % d["genuine_failures"]
        lines.append(line)

    summ = report.get("summary") or {}
    sev = summ.get("by_severity") or {}
    lines.append("- findings: %d (%s)" % (summ.get("findings", 0),
                                          ", ".join("%s %d" % (k, v) for k, v in sorted(sev.items())) or "none"))

    ml = maillog.get("counters") or {}
    if ml:
        lines.append("- mail log: %d genuine failures (%d rows would say so), %d delivered despite failing, spoof-like %d"
                     % (ml.get("genuine_failures", 0), ml.get("raw_failing_rows", 0), ml.get("delivered_despite_fail", 0),
                        (ml.get("by_likely") or {}).get("likely_spoof", 0)))
    census = maillog.get("census")
    if isinstance(census, dict):
        top, failing = census_top(census)
        if top:
            lines.append("- top failing senders (census): " + ", ".join(top) + _more(len(top), failing))
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

    if dl or previous:
        prev_gen = (dl or {}).get("previous_generated_utc") or (previous or {}).get("generated_utc")
        if prev_gen:
            lines.append("- previous run: %s" % str(prev_gen)[:16].replace("T", " "))
        if dl:
            new_f = delta_finding_keys(dl.get("findings_new"))
            gone_f = delta_finding_keys(dl.get("findings_resolved"))
        else:
            now_f, prev_f = finding_keys(report), finding_keys(previous)
            new_f, gone_f = sorted(now_f - prev_f), sorted(prev_f - now_f)
        if new_f:
            lines.append("- *new findings*: " + ", ".join("%s %s" % (d.replace("dns:", ""), i) for d, i in new_f[:8])
                         + (" ..." if len(new_f) > 8 else ""))
        if gone_f:
            lines.append("- resolved: " + ", ".join("%s %s" % (d.replace("dns:", ""), i) for d, i in gone_f[:8]))
        if dl:
            pol, gch = dl.get("policy_changes") or {}, dl.get("gate_changes") or {}
            for dom in sorted(set(pol) | set(gch)):
                b = per.get(dom) or {}
                p, v = pol.get(dom) or {}, gch.get(dom) or {}
                lines.append("- `%s` changed: p=%s/%s -> p=%s/%s"
                             % (dom, p.get("from", b.get("current_policy")), v.get("from", b.get("verdict")),
                                p.get("to", b.get("current_policy")), v.get("to", b.get("verdict"))))
        else:
            prev_per = (previous.get("gate") or {}).get("domains") or {}
            for dom in sorted(per):
                a, b = prev_per.get(dom, {}), per[dom]
                if a and (a.get("current_policy") != b.get("current_policy") or a.get("verdict") != b.get("verdict")):
                    lines.append("- `%s` changed: p=%s/%s -> p=%s/%s" % (dom, a.get("current_policy"), a.get("verdict"),
                                                                         b.get("current_policy"), b.get("verdict")))
        if previous:
            now_s, prev_s = rua_sources(report), rua_sources(previous)
            new_s = sorted(set(now_s) - set(prev_s))
            if new_s:
                lines.append("- *newly seen senders*: " + ", ".join(new_s[:6]) + (" ..." if len(new_s) > 6 else ""))
        if dl:
            if dl.get("genuine_failures") is not None:
                lines.append("- genuine failures vs last run: %+d" % dl["genuine_failures"])
            if dl.get("delivered_despite_fail"):
                lines.append("- delivered despite failing vs last run: %+d" % dl["delivered_despite_fail"])
            top, failing = census_top({"by_sender": dl.get("new_senders") or []})
            if top:
                lines.append("- *new failing senders*: " + ", ".join(top) + _more(len(top), failing))
            for note in dl.get("notes") or []:
                lines.append("- note: %s" % note)
        elif previous:
            pml = (previous.get("maillog") or {}).get("counters") or {}
            if ml and pml:
                d = ml.get("genuine_failures", 0) - pml.get("genuine_failures", 0)
                lines.append("- genuine failures vs last run: %+d" % d)
        if previous:
            ptot = (previous.get("rua") or {}).get("totals") or {}
            if tot and ptot:
                d = 100 * (float(tot.get("pass_rate", 0) or 0) - float(ptot.get("pass_rate", 0) or 0))
                lines.append("- pass rate vs last run: %+.1f points" % d)

    if plan:
        ch = plan.get("changes") or []
        p1 = sum(1 for c in ch if c.get("priority") == 1)
        lines.append("- plan: %d change(s) waiting, %d are zero-risk monitoring/hygiene; %d hold(s)"
                     % (len(ch), p1, len(plan.get("holds") or [])))
    return "\n".join(lines)


def post(webhook, text):
    body = json.dumps({"text": text}).encode("utf-8")
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
    ap.add_argument("--previous", help="the previous run's report.json, for deltas (report.delta wins when present)")
    ap.add_argument("--plan", help="this run's plan.json")
    ap.add_argument("--webhook", help="webhook URL (default: SLACK_WEBHOOK_URL or TEAMS_WEBHOOK_URL from .env)")
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
        post(webhook, text)
    except RuntimeError as err:
        print("error: " + str(err), file=sys.stderr)
        sys.exit(1)
    print("posted %d characters" % len(text))


if __name__ == "__main__":
    main()
