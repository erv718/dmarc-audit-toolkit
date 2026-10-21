#!/usr/bin/env python3
"""Post a short status to Slack after an audit run.

Reads report.json (and optionally the previous run's report.json and this
run's plan.json) and writes one message: policy, gate and next step per
domain (the plan's first row for it when the plan has one; a policy the run
could not read in words, never p=unknown; with the
domain's own genuine failures when the report attributes the mail log per
domain, maillog.by_domain, and for a domain under an organization the row
budget cut, the full-window totals collect.py counted in advanced hunting,
maillog.window_totals, beside that floor), the mail log's counts (with the
overrides that let mail in despite failing, when the log recorded them),
the worst census entries (maillog.census), what
changed since last time (new findings, resolved findings, newly identified
senders, spoofing blocked, failure counts), the trend over the last runs,
and how many plan rows are waiting (an offline run says it has no plan).
When the report carries its own delta
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
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import audit  # the delta's own rules, the recorded cuts, what a quarantine-now row clears, a split census
import dedupe  # the overrides that let a delivered failure in, in plain words
import next_steps  # the organization the status document leads with, which the per-domain lines lead with too
import plan as plan_mod  # each plan row's status, as plan.py set it once
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


def finding_rows(report):
    """{(source, id): {"source", "id", "severity"}} over a report's findings, the
    way the delta lists them: what a summary compares when the run carries no
    delta of its own."""
    out = {}
    for f in _rows(_d(report).get("findings")):
        if isinstance(f, dict):
            key = (str(f.get("source") or f.get("domain") or ""), str(f.get("id") or ""))
            out.setdefault(key, {"source": key[0], "id": key[1], "severity": f.get("severity")})
    return out


def findings_text(rows, severity=True):
    """'example.com DKIM-009, e.example.com DKIM-009 (major); t.example.com
    DMARC-004 (minor)': findings as a summary names them, in the order given;
    with severity, each run of findings that share one is followed by it,
    so a list ranked by severity says why it runs as it does."""
    parts, run, sev = [], [], None
    for f in rows:
        text = "%s %s" % (str(f.get("source") or "").replace("dns:", ""), f.get("id"))
        this = f.get("severity") if severity and isinstance(f.get("severity"), str) else None
        if run and this != sev:
            parts.append(", ".join(run) + (" (%s)" % sev if sev else ""))
            run = []
        run.append(text)
        sev = this
    if run:
        parts.append(", ".join(run) + (" (%s)" % sev if sev else ""))
    return "; ".join(parts)


def source_ips(report):
    """Every source IP the outside view saw: rua.source_ips, the plain list
    audit.py keeps when it caps by_source_ip to the busiest rows, else the
    table itself. An outside view of the wrong shape reads as none."""
    rua = report.get("rua") if isinstance(report, dict) and isinstance(report.get("rua"), dict) else {}
    ips = rua.get("source_ips") if isinstance(rua.get("source_ips"), list) else None
    if ips is None:
        ips = [s.get("source_ip") for s in _rows(rua.get("by_source_ip")) if isinstance(s, dict)]
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


def ip_check_ran(rua):
    """Did the outside view's per-IP unknown-sender check run? Only then are
    rua.unknown_senders the sources outside the known IP prefixes; without
    prefixes the list holds every source by construction (OUTSIDE-009). A
    report from before rua.filters.known.ip_check ran it when it listed
    networks."""
    if not isinstance(rua, dict):
        return False
    flt = rua.get("filters") if isinstance(rua.get("filters"), dict) else {}
    known = flt.get("known") if isinstance(flt.get("known"), dict) else {}
    if "ip_check" in known:
        return known["ip_check"] is True
    return bool(known.get("given") and known.get("networks"))


def unknown_counts(rua):
    """(ip entries, signing-domain entries, how many IPs, how many signing
    domains) in rua.unknown_senders. The per-IP check's result is the ip
    entries alone: a signing domain's counts are signatures on those same
    messages, so it never adds to the sender count. When audit.py capped the
    table to its busiest rows the kept entries are a part of the list: the IPs
    are then recounted over every source the outside view saw (rua.source_ips,
    else by_source_ip) that no listed prefix covers, and the signing domains
    are the rest of the table's total."""
    unk = [u for u in _rows(rua.get("unknown_senders")) if u]
    doms = [u for u in unk if isinstance(u, dict) and u.get("kind") == "dkim_domain"]
    ips = [u for u in unk if not (isinstance(u, dict) and u.get("kind") == "dkim_domain")]
    cut = rua.get("truncated") if isinstance(rua.get("truncated"), dict) else {}
    table = cut.get("unknown_senders") if isinstance(cut.get("unknown_senders"), dict) else None
    if table is None:
        return ips, doms, len(ips), len(doms)
    flt = rua.get("filters") if isinstance(rua.get("filters"), dict) else {}
    known = flt.get("known") if isinstance(flt.get("known"), dict) else {}
    nets = []
    for n in known.get("networks") if isinstance(known.get("networks"), list) else []:
        try:
            nets.append(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            continue

    def outside(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # an address the check could not read is listed as unknown there too
        return not any(addr.version == net.version and addr in net for net in nets)

    n_ips = max(len(ips), sum(1 for ip in source_ips({"rua": rua}) if outside(ip)))
    total = _whole(table.get("total"))
    return ips, doms, n_ips, max(len(doms), total - n_ips)


def census_top(census, n=CENSUS_TOP, headline=None):
    """(labels, failing) for a census dict: the n worst entries as short labels
    made of domains only - envelope domains with their genuine failures, and
    sender rows (the delta's new senders) folded to their From domain and
    envelope domain first - never a From address: the message is aggregates
    only. Entries with no genuine failures are skipped; failing counts every
    failing entry. The failures are what the formal exceptions left
    (census_excepted counts the rest), and they decide which entries are the
    worst; a tie goes by messages, as the census ranks them, then in the one
    order every list of names follows (audit.domain_key, the headline's
    organization first): audit.sender_rank, the key next_steps.md's lists
    sort by, so a tie names the same entries in both."""
    rows = []
    for r in _rows(census.get("by_envelope")):
        failing, label = _left(r) if isinstance(r, dict) else (0, None)
        if failing:
            rows.append(dict(r, genuine_failures=failing, likely=label))
    rows.sort(key=lambda r: audit.sender_rank(str(r.get("envelope_domain") or ""), r["genuine_failures"], headline,
                                              _whole(r.get("messages"))))
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
        rows = sorted(folded.values(), key=lambda r: (-r["genuine_failures"], audit.domain_key(r["domain"], headline),
                                                      r["envelope_domain"]))
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


def sender_keys(report, report_path=None):
    """Sender identities one run saw, as aggregates: rua source IPs and
    mail-log envelope domains, keyed ip:<address> and envelope:<domain>. No
    From addresses, no people - this set is what collect.py remembers in
    senders.json so 'newly identified' means new to the whole history. A
    report read from disk whose census was split off (maillog.census_file)
    is read whole again from the side file next to report_path, so every
    envelope counts, not only the rows report.json kept."""
    if report_path and isinstance(report, dict):
        report = audit.load_census(report, report_path)
    keys = {"ip:" + ip for ip in source_ips(report)}  # every source, not only the busiest rows kept
    maillog = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    census = maillog.get("census") if isinstance(maillog.get("census"), dict) else {}
    rows = _rows(census.get("by_envelope"))
    if rows:  # the census names every envelope domain seen; the verdicts are no longer in report.json by default
        for r in rows:
            env = str(r.get("envelope_domain") or "").strip().lower() if isinstance(r, dict) else ""
            if env and env != "(blank)" and _sender_envelope(r):
                keys.add("envelope:" + env)
    else:
        for v in _rows(maillog.get("verdicts")):
            env = (v.get("envelope_domain") or "").strip().lower() if isinstance(v, dict) else ""
            if env:
                keys.add("envelope:" + env)
    return keys


def senders_maybe_missed(report, keys):
    """The sender identities among keys that the previous run's cut mail log
    may simply have missed: envelope domains every census stream of which
    sends as a domain under an organization the previous run cut (the
    delta's cut_orgs with a previous side), so the 'newly identified' line
    never contradicts the delta's own note that withholds them. A source IP
    comes from the aggregate reports, which no cut touches."""
    dl = report.get("delta") if isinstance(report.get("delta"), dict) else {}
    mw = dl.get("maillog_window") if isinstance(dl.get("maillog_window"), dict) else {}
    cut = mw.get("cut_orgs") if isinstance(mw.get("cut_orgs"), dict) else {}
    families = {dedupe.org_domain(str(org).strip().lower()) for org, sides in cut.items()
                if isinstance(sides, dict) and sides.get("previous") is not None}
    if not families:
        return set()
    maillog = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    census = maillog.get("census") if isinstance(maillog.get("census"), dict) else {}
    by_env = {}
    for r in _rows(census.get("by_sender")):
        if not isinstance(r, dict):
            continue
        env = str(r.get("envelope_domain") or "").strip().lower()
        dom = str(r.get("domain") or str(r.get("sender") or "").rpartition("@")[2]).strip().lower()
        if env and dom:
            by_env.setdefault(env, set()).add(dedupe.org_domain(dom))
    return {k for k in keys if k.startswith("envelope:") and by_env.get(k[len("envelope:"):])
            and by_env[k[len("envelope:"):]] <= families}


def _sender_envelope(row):
    """Is a census envelope domain a sender identity worth remembering? One
    that carried a message that did not fail, or whose failures are not all
    read as spoofing. A domain every message from which failed as spoofing is
    a spoofer's throwaway (a live tenant saw twenty thousand of them in a
    month), not a sender to announce as new. A census without the counts
    (an older report) keeps every envelope, as before."""
    messages, failures = _whole(row.get("messages")), _whole(row.get("genuine_failures"))
    if "messages" not in row or "genuine_failures" not in row:
        return True
    if messages > failures:
        return True
    return (row.get("likely_after") or row.get("likely")) not in ("likely_spoof",)


def _key_label(key):
    kind, _, value = key.partition(":")
    return value + (" (envelope)" if kind == "envelope" else "")


def _number(value):
    """A metrics value as a number, else None: a damaged entry reads as unknown."""
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _finite(value):
    """A metrics value as a finite float, else None: nan, an infinity and an integer too large to be a float
    read as unknown (a hand-edited or damaged entry never stops the summary)."""
    if _number(value) is None:
        return None
    try:
        f = float(value)
    except OverflowError:
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def _spans_alike(hours):
    """Mail-log spans (hours; None unknown) that bear comparing failure counts:
    an unknown span gets the benefit of the doubt, two spans under an hour are
    alike, otherwise neither may be under half of the other."""
    known = [h for h in map(_finite, hours) if h is not None and h >= 0]
    if len(known) < 2 or max(known) < 1:
        return True
    return min(known) / max(known) >= 0.5


def _views_differ(sizes):
    """Why two outside views (message counts; None unknown) do not bear comparing
    pass rates, by the audit's rule, or None when they do: a view with no
    messages never compares, nor two sizes more than tenfold apart; an unknown
    size gets the benefit of the doubt."""
    known = [s for s in sizes if _number(s) is not None and s >= 0]
    if len(known) == 2 and not any(known):
        return "neither outside view carries messages"
    if not all(known):
        return "one outside view carries no messages"
    if len(known) == 2 and min(known) / max(known) < 0.1:
        return "the outside views differ tenfold in size"
    return None


def _cut_orgs(entry):
    """The orgs a metrics entry says the row budget or the API cap cut, or None
    when it does not say (an entry from before they were recorded, or a value
    of the wrong type): that gets the benefit of the doubt - a quiet domain's
    short span is no cut, so no span heuristic stands in. collect.py fills
    the key in for the previous run's entry from that run's own report
    (collect.backfill_cut_orgs), so a floor an older run recorded in its
    report is read here too."""
    orgs = entry.get("maillog_cut_orgs")
    return [str(o) for o in orgs if isinstance(o, str) and o.strip()] if isinstance(orgs, list) else None


def _entry_orgs(entry):
    """The organizations a metrics entry audited (its domains), or None when it does not say."""
    doms = entry.get("domains")
    if not isinstance(doms, dict):
        return None
    return {dedupe.org_domain(str(d).strip().lower()) for d in doms if isinstance(d, str) and d.strip()}


def _names(items, cap=3):
    """'a', 'a and b', 'a, b and c', 'a, b, c and 2 more'."""
    items = list(items)
    if len(items) > cap:
        items = items[:cap] + ["%d more" % (len(items) - cap)]
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def full_window_line(window_totals, domain):
    """'; over the full 30 days, counted in Advanced Hunting: 613 genuine
    failures, 12 delivered despite failing' for an audited domain under an
    organization whose rows the row budget or the API cap cut, from what
    collect.py counted there (maillog.window_totals; a domain its answer left
    out had none), else ''."""
    wt = window_totals if isinstance(window_totals, dict) else {}
    orgs = wt.get("orgs") if isinstance(wt.get("orgs"), dict) else {}
    org = next((o for o in sorted(orgs, key=len, reverse=True)
                if isinstance(o, str) and (domain == o or domain.endswith("." + o))), None)
    info = orgs.get(org) if org else None
    by = info.get("by_domain") if isinstance(info, dict) else None
    if not isinstance(by, dict):
        return ""
    c = by.get(domain) if isinstance(by.get(domain), dict) else {}
    hours = _whole(wt.get("hours"))
    span = ("%d days" % (hours // 24)) if hours and hours % 24 == 0 else ("%d hours" % hours if hours else "window")
    gf = _whole(c.get("genuine_failures"))
    return "; over the full %s, counted in Advanced Hunting: %d genuine failure%s, %d delivered despite failing" % (
        span, gf, "" if gf == 1 else "s", _whole(c.get("delivered_despite_fail")))


def trend_word(values):
    """improving / worsening / flat from the first and last known value."""
    pts = [v for v in values if _number(v) is not None]
    if len(pts) < 2:
        return "too few runs to call"
    if pts[-1] < pts[0]:
        return "improving"
    if pts[-1] > pts[0]:
        return "worsening"
    return "flat"


def trend_judgement(pts, headline=None):
    """(word, reasons) for the trend line over metrics entries: the failure
    counts decide when two runs carry them, the two ends' mail logs cover
    alike spans and neither end's org was cut by the row budget or the API
    cap; else the pass rate, when the first and last runs that carry one have
    outside views of comparable size; else "not comparable". A reason names
    each comparison refused, only when the line shows what it explains; the
    organizations it names run in the one order every list of names follows
    (the headline's first)."""
    gf = [_finite(h.get("genuine_failures")) for h in pts]
    pr = [_finite(h.get("rua_pass_rate")) for h in pts]
    counted = [i for i, x in enumerate(gf) if x is not None]
    rated = [i for i, x in enumerate(pr) if x is not None]
    why_counts = why_rate = None
    if len(counted) >= 2:
        first, last = pts[counted[0]], pts[counted[-1]]
        cf, cl = set(_cut_orgs(first) or []), set(_cut_orgs(last) or [])
        orgs_f, orgs_l = _entry_orgs(first), _entry_orgs(last)
        def ordered(orgs):
            return sorted(orgs, key=lambda o: (audit.domain_key(o, headline), o))

        if cf or cl:  # which end runs were cut, as the delta says it
            parts = [("for %s in both runs", cf & cl), ("for %s in the first run", cf - cl),
                     ("for %s in the last run", cl - cf)]
            why_counts = "the mail log was cut " + " and ".join(fmt % _names(ordered(s)) for fmt, s in parts if s)
        elif orgs_f is not None and orgs_l is not None and orgs_f != orgs_l:
            why_counts = "%s audited in one of these runs only" % _names(ordered(orgs_f ^ orgs_l))
        elif not _spans_alike([first.get("maillog_hours"), last.get("maillog_hours")]):
            why_counts = "the mail-log spans differ"
    if len(rated) >= 2:
        why_rate = _views_differ([pts[rated[0]].get("rua_messages"), pts[rated[-1]].get("rua_messages")])
    if len(counted) >= 2 and not why_counts:
        word = trend_word(gf)
    elif len(rated) >= 2 and not why_rate:
        word = trend_word([None if x is None else -x for x in pr])  # a higher pass rate is the improvement
    else:
        word = "not comparable" if len(counted) >= 2 or len(rated) >= 2 else "too few runs to call"
    reasons = (["failure counts not compared: " + why_counts] if why_counts else []) + \
              (["pass rate not compared: " + why_rate] if why_rate else [])
    return word, reasons


def summarize(report, previous=None, plan=None, known_senders=None, history=None):
    """Plain-text (Slack mrkdwn) message. Deterministic, no secrets. Deltas
    come from report["delta"] when the run carried one, else are recomputed
    from previous; pass rate and newly seen sources always need previous.

    known_senders: every sender key seen in earlier runs (collect.py keeps
    them); with it, "newly identified" means never seen before, not merely
    absent last week. history: the metrics.json entries, newest last, for
    the trend line over the last TREND_RUNS runs. The per-domain lines run
    in the one order every file of the run follows, led by the organization
    the status document leads with (next_steps.headline_org); each names
    the domain's policy (in words when none was read: no DMARC record,
    lookup failed, not read) and its next step - the plan's first row for
    it when the plan has one (next_steps.plan_step, as next_steps.md's
    table and todo.md name it), else the gate's - and for a domain with no
    DMARC record, that its failures are not measurable rather than a zero.
    plan None: no plan line, except for an offline run, which says it has
    none (NO_PLAN_LINE)."""
    lines = []
    gen = str(report.get("generated_utc") or "")
    lines.append("*DMARC audit* %s" % gen[:16].replace("T", " "))

    maillog = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    by_dom = maillog.get("by_domain") if isinstance(maillog.get("by_domain"), dict) else {}
    dl = report.get("delta") if isinstance(report.get("delta"), dict) else None
    if dl is None and isinstance(previous, dict):
        # the documented --previous use with an audit.py report: the same rules as collect.py's delta (the
        # recorded cuts, the spans, the unknown-sender check that ran in one run only), never a bare subtraction
        try:
            dl = audit.build_delta(report, previous)
        except Exception:  # a damaged earlier report: no delta, the rest of the message stands
            dl = None
    dl_dom = _d(dl).get("by_domain") if isinstance(_d(dl).get("by_domain"), dict) else {}
    gate = _d(report.get("gate"))
    per = _d(gate.get("domains"))
    cuts = audit.maillog_cuts(report)  # the orgs whose mail log this run cut: their counts are a floor
    # a domain the run measured sending nothing: the plan moves it straight to quarantine, skipping the weekly
    # ramp whose first step the gate judges, so its line leads with the plan and gives the gate's verdict as
    # such - unless the gate's blockers hold that row too
    quiet = {}
    for c in _rows(plan.get("changes")) if isinstance(plan, dict) else []:
        if isinstance(c, dict) and c.get("kind") == "no_mail" and c.get("domain"):
            quiet.setdefault(str(c["domain"]).lower(), c.get("id") or "?")
    # the domains in the one order every file follows: the status document's organization first, each
    # organization's own domain before the names below it
    headline = next_steps.headline_org(report)
    for dom in sorted(per, key=lambda d: (audit.domain_key(d, headline), str(d))):
        g = _d(per[dom])
        # the policy in the band's words when none was read (no DMARC record, lookup failed, not read): never p=unknown
        policy = next_steps.policy_words(report, str(dom))
        verdict = g.get("verdict") if isinstance(g.get("verdict"), str) else "?"
        if str(dom).lower() in quiet:
            left = audit.ramp_blockers_left(report, str(dom).lower())
            line = "- `%s`: %s, next: no mail measured, quarantine now (plan %s); the gate's *%s* %s" % (
                dom, policy, quiet[str(dom).lower()], verdict,
                "is for the weekly ramp this skips" if not left else "holds that row too: %s" % left[0])
        else:
            # a domain with a plan row: the plan's first row is its next step, as next_steps.md's table and todo.md
            # name it, each row with its id and status; else the gate's step, a policy it did not read in words
            step = next_steps.plan_step(plan, str(dom).lower(), plan_note) if isinstance(plan, dict) else None
            if step is None:
                step = g.get("next_step") if isinstance(g.get("next_step"), str) else "?"
                if step.lower().startswith("unknown"):
                    step = next_steps._unread_step(report, str(dom))
                if isinstance(plan, dict):  # a name a plan hold says needs a record of its own: one statement, the plan's
                    step = audit.inherited_step(str(dom), step, plan)
            line = "- `%s`: %s, gate *%s*, next: %s" % (dom, policy, verdict, step)
        own = by_dom.get(dom)
        # a domain under an org the row budget cut: its own count is the floor the gate decides on, and the
        # whole window, counted server side, goes beside it when it was counted
        full = full_window_line(maillog.get("window_totals"), dom)
        cut = next((o for o in cuts if isinstance(o, str) and (dom == o or str(dom).endswith("." + o))), None)
        unmeasured = (isinstance(own, dict) and not _whole(own.get("genuine_failures"))
                      and next_steps.policy_unread_why(report, str(dom)) == "absent")
        if unmeasured:  # with no DMARC record nothing it sends can fail DMARC: a zero would read as health
            n = _whole(own.get("logical_messages"))
            line += (" - failures not measurable without a DMARC record (%d messages)" % n if n
                     else " - no mail-log rows of its own")
        elif isinstance(own, dict) and _number(own.get("genuine_failures")) is not None:
            line += " - %d genuine failures of its own" % _whole(own.get("genuine_failures"))
            gone = min(_whole(own.get("excepted")), _whole(own.get("genuine_failures")))
            if gone:  # the count holds every one; the share an exception covers is named beside it
                line += " (%d of them formally excepted in audit.toml)" % gone
            if cut:
                kept = audit._cut_kept(cuts.get(cut))
                line += " in the rows kept (%s; a floor: the gate, the census and the labels count these)" % (
                    kept or "cut by %s" % (audit._cut_cause(cuts.get(cut)) or "an unrecorded cause"))
            d = dl_dom.get(dom)
            if isinstance(d, dict) and _number(d.get("genuine_failures")) is not None:
                line += " (%+d vs last run)" % d["genuine_failures"]
        lines.append(line + full)

    summ = _d(report.get("summary"))
    sev = _d(summ.get("by_severity"))
    lines.append("- findings: %d (%s)" % (_whole(summ.get("findings")),
                                          ", ".join("%s %d" % (k, _whole(v)) for k, v in sorted(sev.items(), key=str)
                                                    if _number(v) is not None) or "none"))

    ml = _d(maillog.get("counters"))
    if ml:
        # what let the delivered ones in, when the log recorded the overrides ('' without the columns leaves the
        # line as it was), and the share the formal exceptions cover of each count, as next_steps.md names it
        gone = audit.whole_excepted(report)
        gf, ddf = _whole(ml.get("genuine_failures")), _whole(ml.get("delivered_despite_fail"))
        by = dedupe.delivered_by_phrase(ml.get("delivered_despite_fail_by"), ddf)
        lines.append("- mail log: %d genuine failures%s (%d rows would say so), %d delivered despite failing%s%s, "
                     "spoof-like %d"
                     % (gf, (" (%d of them formally excepted in audit.toml)" % gone["failures"]) if 0 < gone["failures"] <= gf else "",
                        _whole(ml.get("raw_failing_rows")), ddf,
                        (" (%d of them formally excepted in audit.toml)" % gone["delivered"]) if 0 < gone["delivered"] <= ddf else "",
                        (" (%s)" % by) if by else "", _whole(_d(ml.get("by_likely")).get("likely_spoof"))))
    census = maillog.get("census")
    if isinstance(census, dict):
        top, failing = census_top(census, headline=headline)
        gone = census_excepted(census)
        if top:
            lines.append("- top failing senders (census): " + ", ".join(top) + _more(len(top), failing)
                         + _excepted_tail(gone))
        elif gone:
            lines.append("- top failing senders (census): none left%s" % _excepted_tail(gone))
    rua = _d(report.get("rua"))
    tot = _d(rua.get("totals"))
    if tot:
        disp = _d(tot.get("by_disposition"))
        lines.append("- outside view: %d messages, pass rate %.1f%%, spoofing blocked by receivers: %d rejected, %d quarantined"
                     % (_whole(tot.get("messages")), 100 * (_finite(tot.get("pass_rate")) or 0),
                        _whole(disp.get("reject")), _whole(disp.get("quarantine"))))
        unk = _rows(rua.get("unknown_senders"))
        if unk and ip_check_ran(rua):  # without the check the list names every source, the tenant's own too
            # the count is the per-IP check's (ip entries, over the whole table when it was capped); the
            # signing domains not in the known list are a clause of their own
            ips, doms, n_ips, n_doms = unknown_counts(rua)
            line = "- unknown senders in reports: %d" % n_ips if n_ips else \
                "- unknown senders in reports: none outside the known IP prefixes"
            if n_ips and ips:
                line += " (top: %s)" % ", ".join(sender_label(u) for u in ips[:3])
            if n_doms:
                top = ", ".join(str(u.get("value") or "?") for u in doms[:3])
                line += "; %d signing domain%s not in the known list%s" % (
                    n_doms, "" if n_doms == 1 else "s", (" (top: %s)" % top) if top else "")
            lines.append(line)

    if dl or isinstance(previous, dict):
        prev_gen = _d(dl).get("previous_generated_utc") or _d(previous).get("generated_utc")
        if prev_gen:
            lines.append("- previous run: %s" % str(prev_gen)[:16].replace("T", " "))
        if dl:
            new_f = [f for f in _rows(dl.get("findings_new")) if isinstance(f, dict)]
            gone_f = [f for f in _rows(dl.get("findings_resolved")) if isinstance(f, dict)]
        else:
            now_f, prev_f = finding_rows(report), finding_rows(previous)
            new_f = [now_f[k] for k in now_f if k not in prev_f]
            gone_f = [prev_f[k] for k in prev_f if k not in now_f]
        # the most severe first, then by the domain each names in the one order (the headline's organization
        # first); the severity is named after each run of findings that share it, so the order reads as one
        new_f.sort(key=lambda f: audit.finding_order(f, headline))
        gone_f.sort(key=lambda f: audit.finding_order(f, headline, severity=False))
        if new_f:
            lines.append("- *new findings*: " + findings_text(new_f[:8], True) + _more(min(len(new_f), 8), len(new_f)))
        if gone_f:
            lines.append("- resolved: " + findings_text(gone_f[:8], False) + _more(min(len(gone_f), 8), len(gone_f)))
        if dl:
            pol, gch = _d(dl.get("policy_changes")), _d(dl.get("gate_changes"))
            for dom in sorted(set(pol) | set(gch), key=lambda d: (audit.domain_key(d, headline), str(d))):
                b = _d(per.get(dom))
                p, v = _d(pol.get(dom)), _d(gch.get(dom))
                lines.append("- `%s` changed: p=%s/%s -> p=%s/%s"
                             % (dom, p.get("from", b.get("current_policy")), v.get("from", b.get("verdict")),
                                p.get("to", b.get("current_policy")), v.get("to", b.get("verdict"))))
        if isinstance(previous, dict) and known_senders is None:  # with the history known, senders.json decides
            now_s, prev_s = rua_sources(report), rua_sources(previous)
            new_s = sorted(set(now_s) - set(prev_s))
            if new_s:
                lines.append("- *newly seen senders*: " + ", ".join(new_s[:6]) + (" ..." if len(new_s) > 6 else ""))
        if dl:
            if _number(dl.get("genuine_failures")) is not None:
                lines.append("- genuine failures vs last run: %+d" % dl["genuine_failures"])
            if _number(dl.get("delivered_despite_fail")):
                lines.append("- delivered despite failing vs last run: %+d" % dl["delivered_despite_fail"])
            new = {"by_sender": _rows(dl.get("new_senders"))}
            top, failing = census_top(new, headline=headline)
            gone = census_excepted(new)
            if top:
                lines.append("- *new failing senders*: " + ", ".join(top) + _more(len(top), failing) + _excepted_tail(gone))
            elif gone:
                lines.append("- new failing senders: none left%s" % _excepted_tail(gone))
            for note in _rows(dl.get("notes")):
                lines.append("- note: %s" % note)
        cmp = dl.get("rua") if dl and isinstance(dl.get("rua"), dict) else None
        if cmp and cmp.get("comparable") is False:
            lines.append("- outside view not comparable with last run (%s messages now, %s then): no pass-rate delta"
                         % (cmp.get("now_messages"), cmp.get("previous_messages")))
        elif cmp and _finite(cmp.get("pass_rate_change")) is not None:
            lines.append("- pass rate vs last run: %+.1f points" % cmp["pass_rate_change"])

    if known_senders is not None:
        now_keys = sender_keys(report)
        if not known_senders:
            lines.append("- baseline run: %d sender identities recorded; newly identified senders are reported "
                         "from the next run" % len(now_keys))
        else:
            new_s = sorted(k for k in now_keys if k not in known_senders)
            missed = senders_maybe_missed(report, new_s)  # under an org the previous run's cut log may have missed
            sure = [k for k in new_s if k not in missed]
            if sure:
                lines.append("- *newly identified senders* (never seen in an earlier run): "
                             + ", ".join(_key_label(k) for k in sure[:6]) + (" ..." if len(sure) > 6 else ""))
            elif not missed:
                lines.append("- newly identified senders: none")
            if missed:
                held = sorted(missed)
                lines.append("- %d sender identit%s first recorded this run but not called new: the previous run's "
                             "cut mail log may simply have missed %s (%s%s)"
                             % (len(held), "y" if len(held) == 1 else "ies", "it" if len(held) == 1 else "them",
                                ", ".join(_key_label(k) for k in held[:6]), " ..." if len(held) > 6 else ""))

    pts = [h for h in (history or []) if isinstance(h, dict)][-TREND_RUNS:]
    if len(pts) >= 2:
        gf = [_finite(h.get("genuine_failures")) for h in pts]
        pr = [_finite(h.get("rua_pass_rate")) for h in pts]
        parts = []
        if any(x is not None for x in gf):
            parts.append("genuine failures " + ", ".join("-" if x is None else str(int(x)) if x.is_integer() else str(x)
                                                         for x in gf))
        if any(x is not None for x in pr):
            parts.append("pass rate " + ", ".join("-" if x is None else "%.1f%%" % (100 * x) for x in pr))
        if parts:
            # the word compares the first and last runs on the entries' own figures: failure counts over
            # mail logs that were not cut and cover alike spans, else pass rates over outside views of a
            # comparable size, else nothing
            word, why = trend_judgement(pts, headline)
            lines.append("- trend over the last %d runs (%s): %s" % (len(pts), word, "; ".join(parts + why)))

    if isinstance(plan, dict):
        lines.append(plan_line(plan))
    elif report.get("offline") is True or ("dns" in report and not report.get("dns")):
        lines.append(NO_PLAN_LINE)  # an offline run builds no plan: it says so, never "0 change(s) waiting"
    return "\n".join(lines)


NO_PLAN_LINE = "- plan: not in this run (offline: no DNS read)"


def plan_note(row):
    """' (plan P-01, needs the report address)': one plan row's id and the
    status plan.py gave it, after the step a per-domain line names it by."""
    return " (plan %s, %s)" % (row.get("id") or "?", plan_mod.status_of(row)[1])


def plan_line(plan):
    """The summary's plan line, by the status plan.py gave each row
    (plan.row_status): how many are ready now (zero-risk only then: no mail
    impact and nothing to check), how many wait on their checks (a
    quarantine-now row, which changes delivery for a domain the run measured
    sending nothing, and a record that waits on a lookup of the name's own
    record, said apart), how many need the report address or their DNS
    host first, and how many are not for this week; then the holds."""
    ch = [c for c in _rows(plan.get("changes")) if isinstance(c, dict)]
    status = {id(c): plan_mod.status_of(c)[0] for c in ch}
    ready = [c for c in ch if status[id(c)] == "now"]
    checked = [c for c in ch if status[id(c)] == "check"]
    quiet = sum(1 for c in checked if c.get("kind") == "no_mail")
    looks = sum(1 for c in checked if any(str(p).startswith("look up _dmarc.") for p in _rows(c.get("prerequisites"))))
    # a record that keeps a subdomain at the p=quarantine it follows today is zero-risk, but not monitoring
    keeps = sum(1 for c in ready if c.get("kind") == "new" and re.search(r"(?:^|;)\s*p\s*=\s*(?!none\b)\w",
                                                                         str(c.get("value") or ""), re.I))
    parts = []
    if ready:
        parts.append("%d ready now, zero-risk monitoring/hygiene%s" % (
            len(ready), (" (%d %s a subdomain at the policy it follows today)" % (keeps, "keeps" if keeps == 1 else "keep"))
            if keeps else ""))
    if checked:
        said = (["%d %s no mail straight to quarantine" % (quiet, "moves a domain that sends" if quiet == 1
                                                          else "move domains that send")] if quiet else []) + \
            (["%d after a lookup of the name's own record" % looks] if looks else [])
        parts.append("%d after their checks%s" % (len(checked), (" (%s)" % "; ".join(said)) if said else ""))
    for key, words in (("address", "need the report address first"), ("host", "need their DNS host found first")):
        n = sum(1 for c in ch if status[id(c)] == key)
        if n:
            parts.append("%d %s" % (n, words))
    waiting = sum(1 for c in ch if status[id(c)] in plan_mod.WAITING_STATUSES)
    if waiting:
        parts.append("%d not this week (held, gated or after another change to the same record)" % waiting)
    return "- plan: %d change(s) waiting%s; %d hold(s)" % (len(ch), (": " + ", ".join(parts)) if parts else "",
                                                           len(_rows(plan.get("holds"))))


def _d(value):
    """value when it is a dict, else {}: a damaged section reads as an empty one."""
    return value if isinstance(value, dict) else {}


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


def _report_run(report):
    """The run stamp collect.py writes into its report.json (inputs.run), so the
    report names its run wherever it is copied; None for audit.py's own report."""
    inp = report.get("inputs") if isinstance(report, dict) else None
    run = inp.get("run") if isinstance(inp, dict) else None
    return run.strip() if isinstance(run, str) and run.strip() else None


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

    report = audit.load_census(load(args.report), args.report)  # a split census is read whole again
    previous = audit.load_census(load(args.previous), args.previous) if args.previous else None
    plan = load(args.plan) if args.plan else None
    for what, doc, given in (("--report", report, True), ("--previous", previous, bool(args.previous)),
                             ("--plan", plan, bool(args.plan))):
        if given and not isinstance(doc, dict):
            die("%s: expected a JSON object (the file audit.py or collect.py writes), got %s"
                % (what, type(doc).__name__))
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
        # run's own new senders into senders.json before the summary, so those must still count as new.
        # The run is the stamp collect.py writes into report.json (inputs.run), else the run.json beside
        # it; a report with neither is audit.py's own, which describes no collect run: every sender
        # senders.json holds was seen, and announced, by a run before it
        stamp = _report_run(report) or _run_stamp(args.report)
        known = {k for k, v in senders.items()
                 if not (stamp and isinstance(v, dict) and str(v.get("first_seen") or "") >= stamp)}
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
