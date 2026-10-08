#!/usr/bin/env python3
"""Post a short status to Slack after an audit run.

Reads report.json (and optionally the previous run's report.json and this
run's plan.json) and writes one message: policy and gate per domain (with the
domain's own genuine failures when the report attributes the mail log per
domain, maillog.by_domain), the worst census entries (maillog.census), what
changed since last time (new findings, resolved findings, newly identified
senders, spoofing blocked, failure counts), the trend over the last runs,
and how many plan rows are waiting. When the report carries its own delta
(audit.py --previous writes report.delta) the deltas come from there;
--previous is then only needed for the pass-rate and newly-seen-source
deltas, which the delta does not hold. Aggregates only: domains, counts and
sender identities (source IPs, envelope domains), never addresses or
subject lines. Nothing is posted unless a webhook is given; --dry-run prints
the message instead. The webhook URL is read from SLACK_WEBHOOK_URL in .env
or the environment and is never printed. Teams is designed in
(TEAMS_WEBHOOK_URL, build_payload) but not yet verified against a live
webhook.

  python src/notify.py --report audit-out/report.json --dry-run
  python src/notify.py --report audit-out/latest/report.json --senders audit-out/senders.json --metrics audit-out/metrics.json --dry-run

The newly-identified-senders and trend lines need senders.json and
metrics.json, which collect.py supplies when it posts; standalone, pass them
with --senders and --metrics or the message carries the rest only.
  python src/notify.py --report audit-out/report.json --previous audit-out/history/2026-01-01/report.json --plan audit-out/plan.json

Exit codes: 0 posted or printed, 1 the post failed, 2 usage error.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import run_hunting

WEBHOOK_KEYS = ("SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL")
TARGETS = ("slack", "teams")
TREND_RUNS = 4

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


def source_ips(report):
    """Every source IP the outside view saw: rua.source_ips, the plain list
    audit.py keeps when it caps by_source_ip to the busiest rows, else the
    table itself."""
    rua = report.get("rua") or {}
    ips = rua.get("source_ips") if isinstance(rua.get("source_ips"), list) else None
    if ips is None:
        ips = [s.get("source_ip") for s in rua.get("by_source_ip") or [] if isinstance(s, dict)]
    return {str(ip) for ip in ips if ip}


def rua_sources(report):
    """Sending sources by IP from the outside view, as a set of addresses."""
    return source_ips(report)


def sender_label(u):
    """A short name for an unknown-sender entry, whatever its shape."""
    if isinstance(u, dict):
        return u.get("source_ip") or (" ".join(str(u.get(k)) for k in ("kind", "value") if u.get(k)) or "?")
    return str(u)


def _whole(value):
    """A positive count, 0 for anything else (a bool, a non-number, a negative)."""
    if isinstance(value, bool):
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(n, 0)


def _left(r):
    """A census entry's genuine failures less the ones a formal exception covers (the census counts
    them per entry since audit.py marks every excepted message), and the label of what is left."""
    gf = _whole(r.get("genuine_failures"))
    return gf - min(_whole(r.get("excepted")), gf), (r.get("likely_after") or r.get("likely") or "unknown")


def _rows(value):
    """A census list as it is; anything else (a count, a map, None) reads as no rows."""
    return value if isinstance(value, list) else []


def census_top(census, n=CENSUS_TOP):
    """(labels, failing) for a census dict: the n worst entries as short labels
    made of domains only - envelope domains with their genuine failures, and
    sender rows (the delta's new senders) folded to their From domain and
    envelope domain first - never a From address: the message is aggregates
    only. Entries with no genuine failures are skipped; failing counts every
    failing entry. The failures are what the formal exceptions left
    (census_excepted counts the rest), and they decide which entries are the
    worst."""
    rows = []
    for r in _rows(census.get("by_envelope")):
        failing, label = _left(r) if isinstance(r, dict) else (0, None)
        if failing:
            rows.append(dict(r, genuine_failures=failing, likely=label))
    rows.sort(key=lambda r: -r["genuine_failures"])  # stable: on a tie the census's own order stands
    if not rows:
        folded = {}
        for r in _rows(census.get("by_sender")):
            failing, label = _left(r) if isinstance(r, dict) else (0, None)
            if not failing:
                continue
            dom = str(r.get("domain") or str(r.get("sender") or "").rpartition("@")[2] or "?").lower()
            env = str(r.get("envelope_domain") or "").lower()
            f = folded.setdefault((dom, env), {"domain": dom, "envelope_domain": env, "genuine_failures": 0,
                                              "likely": label})
            f["genuine_failures"] += failing
        rows = sorted(folded.values(), key=lambda r: (-r["genuine_failures"], r["domain"]))
    out = []
    for r in rows[:n]:
        name = r.get("envelope_domain") or r.get("domain") or "?"
        if r.get("domain") and r.get("envelope_domain") and r["domain"] != r["envelope_domain"]:
            name = "%s via %s" % (r["domain"], r["envelope_domain"])
        out.append("%s x%d (%s)" % (name, int(r["genuine_failures"]), r.get("likely") or "unknown"))
    return out, len(rows)


def census_excepted(census):
    """How many of a census's genuine failures the formal exceptions cover (0 when it does not count them)."""
    rows = _rows(census.get("by_sender")) or _rows(census.get("by_envelope"))
    return sum(min(_whole(r.get("excepted")), _whole(r.get("genuine_failures"))) for r in rows if isinstance(r, dict))


def _excepted_tail(n):
    return "; %d formally excepted in audit.toml" % n if n else ""


def _more(shown, total):
    return (" (+%d more)" % (total - shown)) if total > shown else ""


def sender_keys(report):
    """Sender identities one run saw, as aggregates: rua source IPs and
    mail-log envelope domains, keyed ip:<address> and envelope:<domain>. No
    From addresses, no people - this set is what collect.py remembers in
    senders.json so 'newly identified' means new to the whole history."""
    keys = {"ip:" + ip for ip in source_ips(report)}  # every source, not only the busiest rows kept
    maillog = report.get("maillog") or {}
    census = maillog.get("census") if isinstance(maillog.get("census"), dict) else {}
    rows = census.get("by_envelope") or []
    if rows:  # the census names every envelope domain seen; the verdicts are no longer in report.json by default
        for r in rows:
            env = str(r.get("envelope_domain") or "").strip().lower() if isinstance(r, dict) else ""
            if env and env != "(blank)":
                keys.add("envelope:" + env)
    else:
        for v in maillog.get("verdicts") or []:
            env = (v.get("envelope_domain") or "").strip().lower() if isinstance(v, dict) else ""
            if env:
                keys.add("envelope:" + env)
    return keys


def _key_label(key):
    kind, _, value = key.partition(":")
    return value + (" (envelope)" if kind == "envelope" else "")


def _spans_alike(hours):
    """Mail-log spans (hours; None unknown) that bear comparing failure counts:
    an unknown span gets the benefit of the doubt, two spans under an hour are
    alike, otherwise neither may be under half of the other."""
    known = [float(h) for h in hours if isinstance(h, (int, float)) and not isinstance(h, bool) and h >= 0]
    if len(known) < 2 or max(known) < 1:
        return True
    return min(known) / max(known) >= 0.5


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
    """Plain-text (Slack mrkdwn) message. Deterministic, no secrets. Deltas
    come from report["delta"] when the run carried one, else are recomputed
    from previous; pass rate and newly seen sources always need previous.

    known_senders: every sender key seen in earlier runs (collect.py keeps
    them); with it, "newly identified" means never seen before, not merely
    absent last week. history: the metrics.json entries, newest last, for
    the trend line over the last TREND_RUNS runs."""
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
        line = "- `%s`: p=%s, gate *%s*, next: %s" % (dom, g.get("current_policy") or "unknown", g.get("verdict", "?"),
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
        gone = census_excepted(census)
        if top:
            lines.append("- top failing senders (census): " + ", ".join(top) + _more(len(top), failing)
                         + _excepted_tail(gone))
        elif gone:
            lines.append("- top failing senders (census): none left%s" % _excepted_tail(gone))
    rua = report.get("rua") or {}
    tot = rua.get("totals") or {}
    if tot:
        disp = tot.get("by_disposition") or {}
        lines.append("- outside view: %d messages, pass rate %.1f%%, spoofing blocked by receivers: %d rejected, %d quarantined"
                     % (tot.get("messages", 0), 100 * float(tot.get("pass_rate", 0) or 0),
                        disp.get("reject", 0), disp.get("quarantine", 0)))
        unk = rua.get("unknown_senders") or []
        if unk:
            cut = rua.get("truncated") if isinstance(rua.get("truncated"), dict) else {}
            try:  # the table may be capped to its busiest rows: the count is the total, not the rows kept
                total = int((cut.get("unknown_senders") or {}).get("total") or len(unk))
            except (TypeError, ValueError):
                total = len(unk)
            lines.append("- unknown senders in reports: %d (top: %s)"
                         % (total, ", ".join(sender_label(u) for u in unk[:3])))

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
        if previous and known_senders is None:  # with the history known, senders.json decides what is new
            now_s, prev_s = rua_sources(report), rua_sources(previous)
            new_s = sorted(set(now_s) - set(prev_s))
            if new_s:
                lines.append("- *newly seen senders*: " + ", ".join(new_s[:6]) + (" ..." if len(new_s) > 6 else ""))
        if dl:
            if dl.get("genuine_failures") is not None:
                lines.append("- genuine failures vs last run: %+d" % dl["genuine_failures"])
            if dl.get("delivered_despite_fail"):
                lines.append("- delivered despite failing vs last run: %+d" % dl["delivered_despite_fail"])
            new = {"by_sender": dl.get("new_senders") or []}
            top, failing = census_top(new)
            gone = census_excepted(new)
            if top:
                lines.append("- *new failing senders*: " + ", ".join(top) + _more(len(top), failing) + _excepted_tail(gone))
            elif gone:
                lines.append("- new failing senders: none left%s" % _excepted_tail(gone))
            for note in dl.get("notes") or []:
                lines.append("- note: %s" % note)
        elif previous:
            pml = (previous.get("maillog") or {}).get("counters") or {}
            if ml and pml:
                d = ml.get("genuine_failures", 0) - pml.get("genuine_failures", 0)
                lines.append("- genuine failures vs last run: %+d" % d)
        cmp = (dl or {}).get("rua") if isinstance((dl or {}).get("rua"), dict) else None
        if cmp and cmp.get("comparable") is False:
            lines.append("- outside view not comparable with last run (%s messages now, %s then): no pass-rate delta"
                         % (cmp.get("now_messages"), cmp.get("previous_messages")))
        elif cmp and cmp.get("pass_rate_change") is not None:
            lines.append("- pass rate vs last run: %+.1f points" % cmp["pass_rate_change"])
        elif previous:
            ptot = (previous.get("rua") or {}).get("totals") or {}
            if tot and ptot:
                nm, pm = tot.get("messages") or 0, ptot.get("messages") or 0
                if nm and pm and min(nm, pm) / max(nm, pm) >= 0.1:
                    d = 100 * (float(tot.get("pass_rate", 0) or 0) - float(ptot.get("pass_rate", 0) or 0))
                    lines.append("- pass rate vs last run: %+.1f points" % d)
                elif nm or pm:  # two empty outside views have nothing to compare, and nothing to say
                    lines.append("- outside view not comparable with last run (%s messages now, %s then): no "
                                 "pass-rate delta" % (nm, pm))

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

    pts = [h for h in (history or []) if isinstance(h, dict)][-TREND_RUNS:]
    if len(pts) >= 2:
        gf = [h.get("genuine_failures") for h in pts]
        pr = [h.get("rua_pass_rate") for h in pts]
        parts = []
        if any(x is not None for x in gf):
            parts.append("genuine failures " + ", ".join("-" if x is None else str(x) for x in gf))
        if any(x is not None for x in pr):
            parts.append("pass rate " + ", ".join("-" if x is None else "%.1f%%" % (100 * float(x)) for x in pr))
        if parts:
            known = [i for i, x in enumerate(gf) if x is not None]
            # the word compares the first and last failure counts, which means something only when their
            # mail logs cover alike spans, whole log and busy domain alike (a row budget can keep 41 hours of
            # one domain in one run and 30 days in another while the whole log's span holds); otherwise, as
            # with no counts at all, the pass rate decides: a higher rate is the improvement
            ends = [known[0], known[-1]] if len(known) >= 2 else []
            spans_ok = _spans_alike([pts[i].get("maillog_hours") for i in ends])
            if ends:
                a, b = pts[ends[0]].get("maillog_hours_by_domain") or {}, pts[ends[-1]].get("maillog_hours_by_domain") or {}
                for d in set(a) & set(b):
                    spans_ok = spans_ok and _spans_alike([a.get(d), b.get(d)])
            if len(pts) == 2 and dl and (dl.get("maillog_window") or {}).get("comparable") is False:
                spans_ok = False  # the audit already judged these two runs
            if len(known) >= 2 and spans_ok:
                word = trend_word(gf)
            else:
                word = trend_word([None if x is None else -float(x) for x in pr])
                if not spans_ok and word == "too few runs to call":
                    word = "not comparable"
            if not spans_ok:
                parts.append("failure counts not comparable: the mail-log spans differ")
            lines.append("- trend over the last %d runs (%s): %s" % (len(pts), word, "; ".join(parts)))

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


def _run_stamp(report_path):
    """collect.py's run stamp for a report, from the run.json beside it; None otherwise."""
    try:
        doc = json.loads((Path(report_path).resolve().parent / "run.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return str(doc.get("run")) if isinstance(doc, dict) and doc.get("run") else None


def _report_stamp(report):
    """The report's own generation time in collect.py's run-stamp form
    (2026-10-08T090000Z): the cut-off for 'new' when no run.json sits beside it."""
    try:
        t = datetime.fromisoformat(str((report or {}).get("generated_utc") or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    t = t.astimezone(timezone.utc) if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return t.strftime("%Y-%m-%dT%H%M%SZ")


def _same_run(updated, stamp, hours=3):
    """Was a report generated by the run that last wrote senders.json? Its
    generation time then falls within a few hours after that run's stamp."""
    try:
        a = datetime.strptime(str(updated), "%Y-%m-%dT%H%M%SZ")
        b = datetime.strptime(str(stamp), "%Y-%m-%dT%H%M%SZ")
    except (TypeError, ValueError):
        return False
    return timedelta(0) <= b - a <= timedelta(hours=hours)


def main():
    ap = argparse.ArgumentParser(description="Post a short DMARC audit status to a Slack or Teams webhook.")
    ap.add_argument("--report", required=True, help="this run's report.json")
    ap.add_argument("--previous", help="the previous run's report.json, for deltas (report.delta wins when present)")
    ap.add_argument("--plan", help="this run's plan.json")
    ap.add_argument("--senders", help="collect.py's senders.json: 'newly identified' then means new to the whole history")
    ap.add_argument("--metrics", help="collect.py's metrics.json, for the trend over the last runs")
    ap.add_argument("--webhook", help="webhook URL (default: SLACK_WEBHOOK_URL or TEAMS_WEBHOOK_URL from .env)")
    ap.add_argument("--target", choices=TARGETS, help="payload shape (default: guessed from the URL; slack)")
    ap.add_argument("--dry-run", action="store_true", help="print the message, post nothing")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    args = ap.parse_args()

    report = load(args.report)
    previous = load(args.previous) if args.previous else None
    plan = load(args.plan) if args.plan else None
    known = history = None
    if args.senders:
        try:
            state = json.loads(Path(args.senders).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as err:
            die("cannot read %s: %s" % (args.senders, err))
        senders = state.get("senders") if isinstance(state, dict) else None
        if not isinstance(senders, dict):
            die("%s: expected the senders.json collect.py writes" % args.senders)
        # known = the identities first seen BEFORE the run this report describes; collect.py records a
        # run's own new senders into senders.json before the summary, so those must still count as new
        # a report with no run.json beside it (audit.py's own) is dated by its generation time, so a
        # sender first seen by the last collect run counts as known, not announced a second time - unless
        # that run is the one that generated this report (collect.py's report.json copied on its own)
        stamp = _run_stamp(args.report) or _report_stamp(report) or state.get("updated")
        if not _run_stamp(args.report) and state.get("updated") and _same_run(state.get("updated"), stamp):
            stamp = state.get("updated")
        known = {k for k, v in senders.items()
                 if not (stamp and isinstance(v, dict) and str(v.get("first_seen") or "") >= str(stamp))}
    if args.metrics:
        try:
            history = json.loads(Path(args.metrics).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as err:
            die("cannot read %s: %s" % (args.metrics, err))
        if not isinstance(history, list) or not all(isinstance(h, dict) for h in history):
            die("%s: expected the metrics list collect.py writes" % args.metrics)
    text = summarize(report, previous, plan, known_senders=known, history=history)
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
