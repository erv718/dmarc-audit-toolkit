#!/usr/bin/env python3
"""Verify it yourself: how to check every finding and every plan row by hand.

The operator who publishes DNS records from this toolkit's output has to be
able to defend every number and every record without trusting the tool.
This module turns a run's report.json (and plan.json) into verify.md: for
each finding and each plan row, the read-only checks a person runs to see
the same thing with their own eyes, and what they should see.

  DNS              the exact lookup, in PowerShell (Resolve-DnsName) and with
                   nslookup on any system, through a public resolver, and
                   the answer the audit saw; a lookup that claims something
                   is missing, or that failed, also asks over HTTPS, the
                   path dns_audit.py falls back to when port 53 is filtered
  mail log         the Advanced Hunting query to paste into the Defender
                   portal under your own sign-in - a shipped query from
                   queries/ with only its let sender_domain line set, the way
                   collect.py sets it - with the figure the report counted,
                   and the command that recounts the export the report read
  aggregate        python src/rua_parse.py over the same reports, the part
  reports          of its output that shows the figure, and how to find a
                   source IP in one raw report file
  tenant           the admin center page and the read-only cmdlet that show
                   the same setting
  gate             each reason the gate gives, with the finding behind it
  plan rows        before (what the lookup shows today), publish, after (once
                   the TTL has passed), roll back, and the query or lookup
                   that proves a prerequisite needing evidence

A step is a dict {"how": "dns" | "kql" | "command" | "portal", "text": one
plain sentence saying what to do and what you should see, "code": the exact
command or query, or ""}. finding_steps() and change_steps() build them for
one finding and one plan row; render() is the text of verify.md; write()
also saves the filled queries as queries/<query>_<domain>.kql next to it,
one set for every audited organizational domain plus the per-domain ones
the steps name. Every expected value is copied from the report or the plan:
nothing here looks anything up, and nothing here changes anything.

  python src/verify.py audit-out/latest/report.json --plan audit-out/latest/plan.json --out audit-out/latest

collect.py writes verify.md and queries/ into every run folder (and
latest/). Relative paths resolve from the repo root, as in every tool here.

Exit codes: 0 written, 2 usage or input error.
"""

import argparse
import functools
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import audit
import dedupe
import discover
import dns_audit
import next_steps  # the organization the status document leads with, which the sections lead with too
import plan as plan_mod

ROOT = Path(__file__).resolve().parent.parent
QUERY_DIR = ROOT / "queries"
# the audit's own resolver first; the second public path checks a lookup that failed on the first
RESOLVERS = ("8.8.8.8", "1.1.1.1")
# the line collect.kql_for_domain sets in every shipped query; nothing else in a filled query changes
PLACEHOLDER = 'let sender_domain = "example.com";'
MAILFLOW_DAYS = 30
PORTAL = "the Defender portal (security.microsoft.com > Hunting > Advanced hunting)"
EAC = "the Exchange admin center (admin.exchange.microsoft.com)"
THREAT_POLICIES = "the Defender portal (security.microsoft.com) > Email & collaboration > Policies & rules > Threat policies"
DKIM_PAGE = THREAT_POLICIES + " > Email authentication settings > DKIM"
EXO = "In Exchange Online PowerShell (Connect-ExchangeOnline first; Get- cmdlets only read)"
HEADER_FILE = "header.txt"  # where a step asks the operator to save a live message header (the toolkit folder)
NAME_RX = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
# the filled queries: name -> (days the query reaches back, what it answers). The first six are the
# shipped queries; mailflow is the aggregate collect.py measures every audited name with
# (discover.mailflow_kql); delivered_twin is filled only when a plan row asks for its proof
QUERIES = {
    "genuine_failures": (7, "genuine failures by envelope domain and From address, deduplicated at "
                            "(Message-ID, recipient), last 7 days"),
    "delivered_despite_failure": (30, "failing mail that reached a mailbox anyway, deduplicated at (Message-ID, "
                                      "recipient), grouped by envelope domain and the override on the delivered copy "
                                      "(org_action, org_policy, user_action, user_policy, compauth), last 30 days"),
    "sender_census": (30, "every envelope domain sending as the domain: total, passing, genuine_failures, last 30 days"),
    "subdomain_health": (30, "every subdomain under the domain: total and genuine_failures, last 30 days"),
    "dkim_alignment": (30, "passing senders under the domain by bucket: dkim_aligned, spf_and_dkim, spf_only, last 30 days"),
    "maillog_totals": (30, "every From domain under the organization: logical_messages and passing (estimates), "
                           "genuine_failures and delivered_despite_fail (exact), and delivered_by, the override that let "
                           "a failure in, last 30 days"),
    "mailflow": (MAILFLOW_DAYS, "every From domain under the organization: messages, outbound, inbound and last_seen, the "
                                "mail-flow count collect.py makes (estimates; zero means none)"),
    "delivered_twin": (30, "lost-looking copies paired with their delivered twins: echo or true loss, last 30 days"),
}
ORG_QUERIES = ("genuine_failures", "delivered_despite_failure", "sender_census", "subdomain_health",
               "dkim_alignment", "maillog_totals", "mailflow")
FILE_RX = re.compile(r"queries/(%s)_([a-z0-9_.-]+?)\.kql" % "|".join(sorted(QUERIES, key=len, reverse=True)))
HOW_LABEL = {"dns": "DNS", "kql": "Query", "command": "Command", "portal": "Portal"}
RUA_TOP = 20  # rows per table rua_parse.py prints unless --top says more
IP_RX = re.compile(r"[0-9A-Fa-f:.]+")
# the same question over DNS-over-HTTPS, the way dns_audit.py asks it when port 53 fails
DOH = "(Invoke-RestMethod -Uri 'https://dns.google/resolve?name=%s&type=%s').Answer.data"
# the external-destination record a prerequisite names (plan.external_destination): <record domain>._report._dmarc.<host>
DESTINATION_RX = re.compile(r"([a-z0-9_.-]+\._report\._dmarc\.([a-z0-9_.-]+)) TXT")
LOOKUP_SHOW = {"TXT": "ForEach-Object { $_.Strings -join '' }",
               "CNAME": "ForEach-Object { $_.NameHost }",
               "MX": "ForEach-Object { '{0} {1}' -f $_.Preference, $_.NameExchange }"}


# ------------------------------------------------------------------ helpers

def _d(value):
    return value if isinstance(value, dict) else {}


def _l(value):
    return value if isinstance(value, list) else []


def _n(value):
    """A count as a whole number >= 0, else None: a damaged value reads as unknown, never as zero."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def _name(value):
    return str(value or "").strip().lower().rstrip(".")


def _ok(name):
    """True for a DNS name that goes into a command or a query as it is."""
    return bool(NAME_RX.match(name or ""))


def _q(text):
    return "'%s'" % text


def _rate(value):
    """A share between 0 and 1 as a float, else 0.0: a damaged value never raises."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1 else 0.0


def _plural(n, one, many=None):
    return one if n == 1 else (many or one + "s")


def step(how, text, code=""):
    return {"how": how, "text": text, "code": code}


def ps(text):
    """One PowerShell argument: bare when it is plain, else single-quoted with any quote doubled."""
    s = str(text)
    if s and re.fullmatch(r"[A-Za-z0-9_./:\\-]+", s) and not s.startswith("-"):
        return s
    return "'" + s.replace("'", "''") + "'"


def ps_quote(text):
    """A PowerShell single-quoted string, whatever the text holds."""
    return "'" + str(text).replace("'", "''") + "'"


def shown(path):
    """A path the way a command takes it: relative to the repo root, with forward slashes, when it lies under it."""
    text = str(path or "")
    for base in (ROOT, ROOT.resolve()):
        try:
            return Path(text).relative_to(base).as_posix()
        except (ValueError, OSError):
            continue
    return text


def _when(text):
    """An aware UTC datetime from an ISO stamp ('2026-10-07T15:00:00Z'), or None."""
    try:
        t = datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _stamp(text):
    t = _when(text)
    return t.strftime("%Y-%m-%d %H:%M") if t else str(text or "?")


def org_of(domain):
    return discover.org_domain(domain) if domain else ""


def lookup(names, rtype="TXT", servers=RESOLVERS[:1], https=False):
    """The exact lookups for one or more names: Resolve-DnsName in PowerShell, one
    line per name and resolver (TXT strings joined the way receivers read them),
    then the same with nslookup for any system. https: also ask over HTTPS, the
    path the toolkit falls back to, for a lookup that claims something is absent
    or that failed - port 53 interception fakes both (AGENTS.md rule 7)."""
    names = [names] if isinstance(names, str) else list(names)
    lines = ["Resolve-DnsName -Name %s -Type %s -Server %s | Where-Object { $_.Type -eq '%s' } | %s"
             % (n, rtype, s, rtype, LOOKUP_SHOW[rtype]) for n in names for s in servers]
    lines.append("# or, on any system:")
    lines += ["nslookup -type=%s %s %s" % (rtype, n, s) for n in names for s in servers]
    if https:
        lines.append("# or over HTTPS, where port 53 to public resolvers is filtered:")
        lines += [DOH % (n, rtype) for n in names]
    return "\n".join(lines)


# ------------------------------------------------------------------ queries

@functools.lru_cache(maxsize=None)
def _template(name):
    with open(QUERY_DIR / (name + ".kql"), encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def query_text(name, domain):
    """The query `name` filled in for domain: a shipped query with only its let
    sender_domain line set (collect.kql_for_domain's substitution, its window
    left as shipped), or the mail-flow aggregate collect.py runs. Raises
    OSError or ValueError when the shipped query cannot be read or has no
    placeholder line."""
    if name == "mailflow":
        return discover.mailflow_kql([domain], MAILFLOW_DAYS) + "\n"
    text = _template(name)
    if PLACEHOLDER not in text:
        raise ValueError("the sender_domain placeholder line was not found in queries/%s.kql" % name)
    return text.replace(PLACEHOLDER, 'let sender_domain = "%s";' % domain, 1)


def query_path(name, domain):
    return "queries/%s_%s.kql" % (name, domain)


def kql_step(name, domain, says):
    """Run one filled query in the portal and read `says` off its result."""
    try:
        code = query_text(name, domain)
    except (OSError, ValueError) as err:
        return step("kql", "queries/%s.kql could not be read here (%s), so this query is not filled in for %s; "
                           "with it, %s" % (name, getattr(err, "strerror", None) or err, domain, says))
    return step("kql", "In %s, run %s (saved next to this file): %s" % (PORTAL, query_path(name, domain), says), code)


def cut_clause(report, domain):
    """'the row budget cut corp.example's mail log in this run (newest 41 hours kept)' when the run cut the
    organization of domain, else None."""
    org = org_of(domain)
    cut = audit.maillog_cuts(report).get(org) if org else None
    if cut is None:
        return None
    return "%s cut %s's mail log in this run (%s)" % (audit._cut_cause(cut) or "the row budget", org,
                                                       audit._cut_kept(cut) or "newest hours kept")


def full_window(report, domain):
    """(hours, counts) of one From domain in maillog.window_totals - what
    collect.py counted in Advanced Hunting over the whole window for an
    organization the row budget or the API cap cut, with maillog_totals.kql -
    else (None, None)."""
    totals = _d(_d(report.get("maillog")).get("window_totals"))
    counts = _d(_d(_d(totals.get("orgs")).get(org_of(domain))).get("by_domain")).get(domain)
    return (_n(totals.get("hours")), counts) if isinstance(counts, dict) else (None, None)


def full_window_span(hours):
    """How a 30-day query relates to collect.py's full-window totals over `hours`. One clause, no full stop."""
    if hours == 720:
        return "the same 30 days, so small differences come from mail that arrived since"
    if hours is None:
        return "the window collect.py counted, so expect about these"
    return "collect.py counted the last %s and the query counts 30 days, so expect at least these" % (
        audit._hours_text(hours))


def window_note(report, domain, days):
    """How a query that reaches `days` back relates to the report's figure for
    domain: the same window, a narrower, wider or older one, or the floor of
    an organization the row budget or the API cap cut. One clause, no full stop."""
    ml = _d(report.get("maillog"))
    org = org_of(domain)
    cut = audit.maillog_cuts(report).get(org) if org else None
    if cut is not None:
        kept = _n(cut.get("kept_hours"))
        if kept and kept > days * 24:
            return ("%s, and the query covers only the last %d days of the hours kept, so it shows the recent part"
                    % (cut_clause(report, domain), days))
        return ("%s, so the report's figure is a floor over the hours kept while the query counts %d days: expect more"
                % (cut_clause(report, domain), days))
    w = _d(ml.get("window"))
    frm, to, gen = _when(w.get("from")), _when(w.get("to")), _when(report.get("generated_utc"))
    if not (frm and to and gen):
        return ("the report records no time span for its mail log, so compare loosely; small differences come from mail "
                "that arrived while the run was pulling and since")
    span = audit._hours(w) or 0
    if (gen - to).total_seconds() > 2 * 86400:
        return ("the report read a mail-log export covering %s to %s UTC, which the query's last %d days do not match: it "
                "shows the last %d days instead, so check the report's own number with the recount"
                % (_stamp(w.get("from")), _stamp(w.get("to")), days, days))
    if span > (days + 1) * 24:
        return "the query covers only the last %d days of the report's %s, so it shows the recent part" % (
            days, audit._hours_text(span))
    if span >= (days - 1) * 24:
        return ("the query covers the same %d days, so small differences come from mail that arrived while the run was "
                "pulling and since" % days)
    return ("the run read %s of mail log (%s to %s UTC) and the query counts %d days, so expect at least the report's "
            "figure; small differences also come from mail that arrived since"
            % (audit._hours_text(span), _stamp(w.get("from")), _stamp(w.get("to")), days))


# ------------------------------------------------------------------ the mail log

def _export(report):
    """The mail-log export the report read, as a command takes it, or None."""
    path = _d(report.get("inputs")).get("maillog") or _d(report.get("maillog")).get("source")
    return shown(path) if path else None


def recount_command(report, scope=None):
    """dedupe.py over the export the report read, with the run's column names,
    verdict column and vendor domains: the same deduplication, counted again.
    scope: --sender-domain (the domain and its subdomains). None without an export."""
    path = _export(report)
    if not path:
        return None
    ml = _d(report.get("maillog"))
    parts = ["python", "src/dedupe.py", ps(path)]
    if ml.get("auth_column"):
        parts += ["--auth-column", ps(ml["auth_column"])]
    scope = scope or _name(ml.get("sender_domain"))
    if scope and _ok(scope):
        parts += ["--sender-domain", scope]
    for key, col in sorted(_d(_d(report.get("inputs")).get("maillog_columns")).items()):
        if key in audit.MAILLOG_COLUMNS and col:
            parts += ["--%s-column" % key, ps(col)]
    for v in _l(_d(ml.get("heuristic")).get("vendor_domains")):
        if v:
            parts += ["--vendor-domain", ps(v)]
    return " ".join(parts)


def _buckets(report):
    """maillog.by_domain without the (other) bucket and without damaged entries."""
    return {d: c for d, c in _d(_d(report.get("maillog")).get("by_domain")).items()
            if d != audit.OTHER and isinstance(c, dict)}


def _under(report, domain):
    """The figures dedupe.py --sender-domain domain recounts: the domain's own
    rows, its audited subdomains' and every unaudited subdomain's under them."""
    tot = {"logical_messages": 0, "genuine_failures": 0, "delivered_despite_fail": 0}
    for name, c in _buckets(report).items():
        if name == domain or name.endswith("." + domain):
            for part in (c, _d(c.get("subdomains_total"))):
                for k in tot:
                    tot[k] += _n(part.get(k)) or 0
    return tot


def _streams(report, domain):
    """The census streams (by_sender rows) whose From domain is domain."""
    cs = _d(_d(report.get("maillog")).get("census"))
    return [r for r in _l(cs.get("by_sender")) if isinstance(r, dict) and _name(r.get("domain")) == domain]


def _top(counts, cap=3):
    return sorted(((k, n) for k, n in counts.items() if n), key=lambda kv: (-kv[1], kv[0]))[:cap]


def _env_split(report, domain):
    out = {}
    for r in _streams(report, domain):
        env = str(r.get("envelope_domain") or "(blank)")
        out[env] = out.get(env, 0) + (_n(r.get("genuine_failures")) or 0)
    return _top(out)


def _delivered_by(report, domain):
    out = {}
    for r in _streams(report, domain):
        for reason, n in _d(r.get("delivered_by")).items():
            if str(reason or "").strip() and _n(n):
                out[str(reason)] = out.get(str(reason), 0) + _n(n)
    return _top(out, 4)


def _spf_only(report, domain):
    """The mail log's SPF-only senders the gate attributes to domain (its own rows and its unaudited subdomains')."""
    names = list(_buckets(report))
    out = []
    for s in _l(_d(report.get("maillog")).get("spf_only_senders")):
        if isinstance(s, dict):
            home = audit._home_domain(_name(s.get("domain")), names)[0] if names else None
            if home == domain:
                out.append(s)
    return out


def _join(pairs, fmt="%s %d"):
    return ", ".join(fmt % kv for kv in pairs)


OVERRIDE_COLUMNS = ("read from the OrgLevelPolicy, OrgLevelAction, UserLevelPolicy and UserLevelAction columns through "
                    "column_ifexists")


def _by_text(counts, cap=4):
    """'org: Exchange transport rule (Allow) x55, user: Safe senders list (Allow) x4' from {reason: messages}."""
    return _join(_top({str(k): _n(v) or 0 for k, v in _d(counts).items() if str(k or "").strip()}, cap), "%s x%d")


def _floor(report, domain):
    """', a floor: the row budget cut corp.example's mail log in this run (newest 41 hours kept)', or ', a floor'."""
    cut = cut_clause(report, domain)
    return ", a floor" + (": " + cut if cut else "")


def delivered_says(report, domain, n):
    """What maillog_totals.kql shows for one domain's mail delivered despite
    failing, and what let it in: for an organization the run cut, the
    full-window totals collect.py counted with that very query (the report's
    own count, a floor, beside them); else the report's own count."""
    mine = _join(_delivered_by(report, domain), "%s x%d")
    hours, wt = full_window(report, domain)
    if wt is not None:
        by = _by_text(wt.get("delivered_by"))
        return ("in the rows for fromdom %s, delivered_despite_fail adds up to %d%s: the full-window totals collect.py "
                "counted in Advanced Hunting with this query (maillog.window_totals) over %s; the report's own rows hold "
                "%d of them%s%s." % (domain, _n(wt.get("delivered_despite_fail")) or 0,
                                     ", and delivered_by names the override that let each one in, %s (%s)" % (
                                         OVERRIDE_COLUMNS, by) if by else "",
                                     full_window_span(hours), n, " (%s)" % mine if mine else "", _floor(report, domain)))
    return ("in the rows for fromdom %s, delivered_despite_fail adds up to %d, and delivered_by names the override that "
            "let each one in, %s (%s); %s." % (
                domain, n, OVERRIDE_COLUMNS, "the report: %s" % mine if mine else
                "the report's export recorded no override for them, so compare the count",
                window_note(report, domain, 30)))


def census_says(report, domain, n):
    """What sender_census.kql shows for one domain's genuine failures: the full-window count for an organization
    the run cut (the report's own count, a floor, beside it), else the report's own count."""
    hours, wt = full_window(report, domain)
    if wt is not None:
        return ("for %s's own mail its genuine_failures column adds up to %d, the full-window count collect.py took in "
                "Advanced Hunting (maillog.window_totals) over %s; the report's own rows count %d%s." % (
                    domain, _n(wt.get("genuine_failures")) or 0, full_window_span(hours), n, _floor(report, domain)))
    return "for %s's own mail its genuine_failures column adds up to %d; %s." % (domain, n, window_note(report, domain, 30))


def census_steps(report, domain):
    """A name with mail-log rows but no share of its own in the report (an
    unaudited name only the plan names): the census query for it, with what
    the report's census counted as it (maillog.census)."""
    rows = _streams(report, domain)
    if not rows or not _ok(domain) or domain in _buckets(report):
        return []
    m = sum(_n(r.get("messages")) or 0 for r in rows)
    f = sum(_n(r.get("genuine_failures")) or 0 for r in rows)
    senders = {}
    for r in rows:
        senders[str(r.get("sender") or "?")] = senders.get(str(r.get("sender") or "?"), 0) + (_n(r.get("messages")) or 0)
    hours, wt = full_window(report, domain)
    if wt is not None:
        says = ("its total column comes to about %d and genuine_failures to %d, the full-window counts collect.py took in "
                "Advanced Hunting (maillog.window_totals) over %s; the report's census counted %d messages as %s, %d of "
                "them genuine failures%s." % (_n(wt.get("logical_messages")) or 0, _n(wt.get("genuine_failures")) or 0,
                                              full_window_span(hours), m, domain, f, _floor(report, domain)))
    else:
        says = ("its total column adds up to %d and genuine_failures to %d, the messages the report's census counted as %s "
                "(by sender: %s); %s." % (m, f, domain, _join(_top(senders)), window_note(report, domain, 30)))
    return [kql_step("sender_census", domain, says)]


def maillog_steps(report, domain):
    """Checks for one audited domain's share of the mail log: its own rows'
    counts (the census query), a cut organization's full window and the
    overrides behind its deliveries (maillog_totals.kql), its top failing
    senders, its unaudited subdomains, its SPF-only senders, and the recount
    of the export. For an organization the run cut, the query's expected
    figures are the full-window totals collect.py counted in Advanced
    Hunting, and the report's own rows are the floor beside them."""
    c = _buckets(report).get(domain)
    if c is None or not _ok(domain):
        return []
    org = org_of(domain)
    lm, gf = _n(c.get("logical_messages")) or 0, _n(c.get("genuine_failures")) or 0
    passing, ddf = _n(c.get("passing_messages")) or 0, _n(c.get("delivered_despite_fail")) or 0
    hours, wt = full_window(report, domain)
    envs = _env_split(report, domain)
    by_env = " (by envelope domain: %s)" % _join(envs) if envs else ""
    steps = []
    if wt is not None:
        steps.append(kql_step("sender_census", domain, "for %s's own mail its total column comes to about %d, passing to "
                                                       "about %d and genuine_failures to %d, the full-window counts "
                                                       "collect.py took in Advanced Hunting (maillog.window_totals) over "
                                                       "%s; the report's own rows count total %d, passing %d and "
                                                       "genuine_failures %d%s%s." % (
                                                           domain, _n(wt.get("logical_messages")) or 0,
                                                           _n(wt.get("passing")) or 0, _n(wt.get("genuine_failures")) or 0,
                                                           full_window_span(hours), lm, passing, gf, by_env,
                                                           _floor(report, domain))))
    elif lm:
        steps.append(kql_step("sender_census", domain, "for %s's own mail its total column adds up to %d, passing to %d and "
                                                       "genuine_failures to %d%s; %s." % (
                                                           domain, lm, passing, gf, by_env,
                                                           window_note(report, domain, 30))))
    else:
        steps.append(kql_step("sender_census", domain, "it returns no rows, as the report found no mail-log rows of %s's "
                                                       "own; %s." % (domain, window_note(report, domain, 30))))
    full_ddf = _n(_d(wt).get("delivered_despite_fail")) or 0
    if wt is not None:  # one query file, one expected figure: the full window's, with the rows kept as the floor
        by = _by_text(wt.get("delivered_by"))
        mine = _join(_delivered_by(report, domain), "%s x%d")
        steps.append(kql_step("maillog_totals", org, "in the rows for fromdom %s, genuine_failures adds up to %d and "
                                                     "delivered_despite_fail to %d%s: the full-window totals collect.py "
                                                     "counted in Advanced Hunting with this query (maillog.window_totals) "
                                                     "over %s; the report's own rows hold %d of the failures and %d of the "
                                                     "deliveries%s%s, and the gate rests on them." % (
                                                         domain, _n(wt.get("genuine_failures")) or 0, full_ddf,
                                                         ", and delivered_by names the override that let each delivered "
                                                         "one in, %s (%s)" % (OVERRIDE_COLUMNS, by) if by else "",
                                                         full_window_span(hours), gf, ddf,
                                                         " (%s)" % mine if mine else "", _floor(report, domain))))
    elif ddf:
        steps.append(kql_step("maillog_totals", org, delivered_says(report, domain, ddf)))
    if full_ddf or ddf:
        steps.append(kql_step("delivered_despite_failure", domain,
                              "it groups the same failures by envelope domain and by the override on the delivered "
                              "copy, counted the way the report counts them (a copy that reached the inbox, junk or "
                              "deleted items, at the (Message-ID, recipient) grain), so its msgs column adds up to %s%s."
                              % ("the full-window %d of maillog_totals" % full_ddf if wt is not None else
                                 "the report's %d" % ddf,
                                 "" if wt is not None else "; " + window_note(report, domain, 30))))
    tops = [(str(t.get("sender") or "?"), _n(t.get("genuine_failures")) or 0)
            for t in _l(c.get("top_senders")) if isinstance(t, dict)][:3]
    if gf and tops:
        steps.append(kql_step("genuine_failures", domain, "the addr rows name the senders that failed with no passing "
                                                          "copy; the report's top ones are %s; %s." % (
                                                              _join(tops, "%s x%d"),
                                                              window_note(report, domain, 7))))
    st = _d(c.get("subdomains_total"))
    if _n(st.get("logical_messages")):
        subs = audit.order_domains([str(s) for s in _l(st.get("domains"))])  # one organization's: no headline needed
        full = [full_window(report, _name(s))[1] for s in subs]
        if subs and all(isinstance(x, dict) for x in full):
            counted = ("come to about total %d and genuine_failures %d, the full-window counts collect.py took in "
                       "Advanced Hunting (maillog.window_totals) over %s (rows for audited subdomains are counted in "
                       "their own sections); the report's own rows count %d and %d%s" % (
                           sum(_n(x.get("logical_messages")) or 0 for x in full),
                           sum(_n(x.get("genuine_failures")) or 0 for x in full),
                           full_window_span(full_window(report, _name(subs[0]))[0]),
                           _n(st.get("logical_messages")) or 0, _n(st.get("genuine_failures")) or 0,
                           _floor(report, domain)))
        else:
            counted = ("add up to total %d and genuine_failures %d (rows for audited subdomains are counted in their own "
                       "sections); %s" % (_n(st.get("logical_messages")) or 0, _n(st.get("genuine_failures")) or 0,
                                          window_note(report, domain, 30)))
        steps.append(kql_step("subdomain_health", domain, "the rows for the unaudited subdomain%s %s %s." % (
            "" if len(subs) == 1 else "s", audit._names(subs, 5), counted)))
    so = _spf_only(report, domain)
    if so:
        shown_so = ", ".join("%s (envelope %s) %d" % (s.get("sender") or "?", s.get("envelope_domain") or "?",
                                                      _n(s.get("spf_only")) or 0) for s in so[:3])
        steps.append(kql_step("dkim_alignment", org, "the spf_only column shows the senders that pass on SPF alone: %s%s; "
                                                     "%s." % (shown_so, " and %d more" % (len(so) - 3) if len(so) > 3 else "",
                                                              window_note(report, domain, 30))))
    rc = recount_command(report, domain)
    if rc:
        u = _under(report, domain)
        steps.append(step("command", "Recount the export the report read for %s and its subdomains: the GENUINE failures "
                                     "line shows %d and logical messages %d%s." % (
                                         domain, u["genuine_failures"], u["logical_messages"],
                                         ", and failed authentication but DELIVERED shows %d" % u["delivered_despite_fail"]
                                         if _d(report.get("maillog")).get("auth_column") else ""), rc))
    return steps


def mailflow_steps(report, domain, audited=True):
    """The tenant's mail-flow count for one name (report.mailflow), when the
    run carries that section. audited False: a name the run does not audit
    (only the plan names it): the same query's row for it when the report
    keeps the names it saw beyond the audited ones (mailflow.unaudited),
    nothing seen when that query answered for its organization without it,
    else a report that keeps no count for it."""
    mf = report.get("mailflow")
    if not isinstance(mf, dict) or not _ok(domain):
        return []
    flows = _d(mf.get("domains"))
    counts = flows.get(domain)
    org = org_of(domain)
    if not isinstance(counts, dict) and not audited:
        seen = mf.get("unaudited")
        counts = _d(seen).get(domain)
        answered = isinstance(seen, dict) and any(isinstance(c, dict) for d, c in flows.items()
                                                  if _name(d) == org or _name(d).endswith("." + org))
        if not isinstance(counts, dict) and answered:
            counts = {}  # the query answered for the organization and returned no row for it: nothing seen
        elif not isinstance(counts, dict):
            return [kql_step("mailflow", org, "%s is not audited, so the report keeps no mail-flow count for it (it keeps "
                                              "the audited names only); in this query, filled for %s and every name "
                                              "under it, the row with d %s shows what the tenant carried as it in 30 "
                                              "days (no row means nothing)." % (domain, org, domain))]
    if not isinstance(counts, dict):
        return [kql_step("mailflow", org, "this run did not measure %s's mail flow (%s), so this is the measurement: the "
                                          "row with d %s shows what the tenant carried as it in 30 days (no row means "
                                          "nothing)." % (domain, "the query failed or answered something else"
                                                         if domain in flows else "the report carries no count for it",
                                                         domain))]
    m, o, i = (_n(counts.get(k)) or 0 for k in ("messages", "outbound", "inbound"))
    if not (m or o or i):
        says = ("there is no row with d %s (or one with messages 0): the tenant carried nothing as it in 30 days, as the "
                "run measured" % domain)
    else:
        says = ("the row with d %s shows messages about %d, outbound about %d and inbound about %d, as the run measured "
                "(dcount estimates: zero means none, larger numbers are close, not exact; mail sent since the run moves "
                "them a little)" % (domain, m, o, i))
    if not audited:
        says += "; %s is not audited, so the report keeps the same query's row for it as mailflow.unaudited" % domain
    return [kql_step("mailflow", org, says + ".")]


def _index(rows, pred):
    """The position of the first row of a report table that pred accepts, or None."""
    for i, r in enumerate(_l(rows)):
        if isinstance(r, dict) and pred(r):
            return i
    return None


def header_from_row(report, domain):
    """(row, rows to print) for one domain in the aggregate reports'
    header_from table: its row and how many rows rua_parse.py must print to
    show it, or (None, the table's length) when it has none - the whole
    table, so the reader can see it is not there."""
    rows = _l(_d(report.get("rua")).get("by_header_from"))
    i = _index(rows, lambda h: _name(h.get("domain")) == domain)
    return (rows[i], i + 1) if i is not None else (None, len(rows))


def rua_domain_steps(report, domain):
    """What the aggregate reports say about mail sent as one domain: its header-from row."""
    row, top = header_from_row(report, domain)
    cmd = rua_command(report, top)
    if not cmd or row is None:
        return []
    return [step("command", "Re-read the aggregate reports: the header_from domains table lists %s with count %d, pass "
                            "%d and fail %d (receivers' counts, forwarded copies included)." % (
                                domain, _n(row.get("count")) or 0, _n(row.get("pass")) or 0, _n(row.get("fail")) or 0),
                 cmd)]


# ------------------------------------------------------------------ aggregate reports

def rua_command(report, rows=0):
    """rua_parse.py over the reports the run read, with the run's filters (the
    window, the known list with the vendor domains, the thresholds), so its
    output carries the same figures. rows: how many rows of a table the step
    reads must be printed (rua_parse.py prints RUA_TOP unless --top says
    more), so a row the step quotes, or the whole table it reads for an
    absence, is never cut off. None when the run read no reports."""
    inp, rua = _d(report.get("inputs")), _d(report.get("rua"))
    if not rua:
        return None
    flt = _d(rua.get("filters"))
    paths = [p for p in _l(inp.get("rua")) if p] or [p for p in _l(_d(rua.get("sources")).get("paths")) if p]
    if not paths:
        return None
    parts = ["python", "src/rua_parse.py"] + [ps(shown(p)) for p in paths]
    for flag, key in (("--since", "since"), ("--until", "until")):
        value = flt.get(key) or inp.get(key)
        if value:
            parts += [flag, ps(value)]
    known = _d(flt.get("known"))
    entries = [str(x) for x in _l(known.get("networks")) + _l(known.get("domains")) if x]
    if entries:
        parts += ["--known", ps(",".join(entries))]
    mv = _n(flt.get("min_volume"))
    if mv is not None and mv != 20:
        parts += ["--min-volume", str(mv)]
    ft = flt.get("fail_threshold")
    if isinstance(ft, (int, float)) and not isinstance(ft, bool) and ft != 0.5:
        parts += ["--fail-threshold", "%g" % ft]
    ep = flt.get("expect_policy") or inp.get("expect_policy")
    if ep in ("none", "quarantine", "reject"):
        parts += ["--expect-policy", ep]
    for s in _l(flt.get("retiring_selectors")) or _l(inp.get("retiring_selectors")):
        if s:
            parts += ["--retiring-selector", ps(s)]
    if isinstance(rows, int) and rows > RUA_TOP:
        parts += ["--top", str(rows)]
    return " ".join(parts)


# Windows PowerShell 5.1 and PowerShell 7 alike: every report the run read, inflated in memory (zip, gz) or read as
# it is (xml), searched for the <row> of each address; each address prints once, with the file it was found in
RAW_ROW = r"""$ips = @(%s); $found = @{}
Add-Type -AssemblyName System.IO.Compression.FileSystem
Get-ChildItem -Path %s -File -Recurse | ForEach-Object {
    $file = $_; $texts = @()
    if ($file.Extension -eq '.zip') {
        $zip = [IO.Compression.ZipFile]::OpenRead($file.FullName)
        foreach ($entry in $zip.Entries) {
            $reader = New-Object IO.StreamReader($entry.Open()); $texts += $reader.ReadToEnd(); $reader.Close()
        }
        $zip.Dispose()
    } elseif ($file.Extension -eq '.gz') {
        $gzip = New-Object IO.Compression.GZipStream($file.OpenRead(), [IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object IO.StreamReader($gzip); $texts += $reader.ReadToEnd(); $reader.Close()
    } elseif ($file.Extension -eq '.xml') { $texts += [IO.File]::ReadAllText($file.FullName) }
    foreach ($text in $texts) { foreach ($ip in $ips) {
        if ($found.ContainsKey($ip)) { continue }
        $row = '(?s)<row>(?:(?!</row>).)*?<source_ip>\s*' + [regex]::Escape($ip) + '\s*</source_ip>.*?</row>'
        $hit = [regex]::Match($text, $row)
        if ($hit.Success) { $found[$ip] = $true; $file.Name; $hit.Value }
    } }
} | Select-Object -First %d"""


def raw_row_step(report, ips):
    """Find each source IP in one raw report file: a PowerShell block that opens
    every report (xml, gz or zip) the run read and prints the first <row> naming it."""
    inp, rua = _d(report.get("inputs")), _d(report.get("rua"))
    paths = [p for p in _l(inp.get("rua")) if p] or [p for p in _l(_d(rua.get("sources")).get("paths")) if p]
    # an address is a string; anything else in a damaged report is skipped, never raised on
    ips = list(dict.fromkeys(i for i in ips if isinstance(i, str) and IP_RX.fullmatch(i)))
    if not paths or not ips:
        return None
    forms = []
    for ip in ips:  # every spelling a reporter used for it (rua_parse keeps them as as_reported)
        row = next((s for s in _l(rua.get("by_source_ip")) if isinstance(s, dict) and s.get("source_ip") == ip), {})
        forms += [f for f in _l(row.get("as_reported")) if isinstance(f, str) and IP_RX.fullmatch(f)] or [ip]
    forms = list(dict.fromkeys(forms))
    code = RAW_ROW % (", ".join(ps_quote(f) for f in forms),
                      ", ".join(ps(shown(p)) for p in paths), 2 * len(forms))
    return step("command", "Find %s in one raw report file: the block opens each report the run read (xml, gz or zip) and "
                           "prints, for %s, the file name and the first <row> whose <source_ip> it is, with its <count>, "
                           "<disposition> and the dkim and spf results the reporter saw." % (
                               audit._names(ips), "that address" if len(ips) == 1 else "each address"), code)


def rua_finding_steps(f, report):
    fid = str(f.get("id") or "")
    rua = _d(report.get("rua"))
    cmd = rua_command(report)
    if not cmd:
        return [step("command", "This report carries no aggregate-report section to re-read; the finding's evidence: %s."
                                % (f.get("evidence") or "none recorded"))]
    head = "Re-read the aggregate reports the run read with the run's filters: "
    steps = []
    streams = [s for s in _l(rua.get("failing_streams")) if isinstance(s, dict)]
    if fid == "OUTSIDE-001":
        shown_s = "; ".join("%s %d msgs %.1f%% pass, %s" % (s.get("source_ip"), _n(s.get("count")) or 0,
                                                              100 * _rate(s.get("pass_rate")), s.get("likely") or "?")
                            for s in streams[:5])
        steps.append(step("command", head + "the failing streams section lists %d %s: %s." % (
            len(streams), _plural(len(streams), "source"), shown_s or "none"), cmd))
        raw = raw_row_step(report, [s.get("source_ip") for s in streams[:3]])
    elif fid == "OUTSIDE-002":
        mv = _n(_d(rua.get("filters")).get("min_volume")) or 20
        ips = [(i, u) for i, u in enumerate(_l(rua.get("unknown_senders"))) if isinstance(u, dict)
               and u.get("kind") == "ip" and (_n(u.get("count")) or 0) >= mv][:5]
        listed = ", ".join("%s x%d (%d pass)" % (u.get("value"), _n(u.get("count")) or 0, _n(u.get("pass")) or 0)
                           for _, u in ips)
        # the table lists signing domains too, so the addresses quoted can sit below the first rows printed
        steps.append(step("command", head + "the unknown senders section lists the sources outside the known list; with "
                                            "volume: %s." % (listed or f.get("evidence") or "none"),
                          rua_command(report, ips[-1][0] + 1 if ips else 0)))
        raw = raw_row_step(report, [u.get("value") for _, u in ips[:3]])
    elif fid == "OUTSIDE-003":
        so = [s for s in _l(rua.get("spf_only_senders")) if isinstance(s, dict)]
        steps.append(step("command", head + "the SPF-only aligned senders section lists %d %s: %s." % (
            len(so), _plural(len(so), "sender"), "; ".join("%s %d msgs as %s" % (
                s.get("source_ip"), _n(s.get("spf_only")) or 0, ", ".join(str(h) for h in _l(s.get("header_from"))[:2]))
                for s in so[:5]) or "none"), cmd))
        raw = raw_row_step(report, [s.get("source_ip") for s in so[:3]])
    else:
        raw = None
        says = {
            "OUTSIDE-004": "the policy published lines show what receivers saw (%s), not the policy given to "
                           "--expect-policy" % (f.get("evidence") or "?"),
            "OUTSIDE-005": "the retiring selector line says %s" % (f.get("title") or "?"),
            "OUTSIDE-006": "the retiring selector line says %s" % (f.get("title") or "?"),
            "OUTSIDE-007": "the failing streams section shows each stream's likely label and the first signal behind it (%s); "
                           "a label is a heuristic, so confirm a stream from a live header before acting" % (
                               f.get("evidence") or "?"),
            "OUTSIDE-008": "the files read line counts the skipped files and the warnings name them (%s)" % (
                f.get("evidence") or "?"),
            "OUTSIDE-009": "the unknown senders heading says the per-IP check did not run, so every source is listed, "
                           "its ip rows the source IPs (%s)" % (f.get("evidence") or "?"),
            "OUTSIDE-010": "the policy published lines show more than one p= across reporters (%s)" % (
                f.get("evidence") or "?"),
            "OUTSIDE-011": "the files read, window and messages lines show %s" % (f.get("evidence") or "?"),
            "OUTSIDE-012": "the count caveat line shows the records counted as one message or rejected (%s)" % (
                f.get("evidence") or "?"),
        }.get(fid, "the findings list at the end shows %s %s" % (fid, f.get("title") or ""))
        steps.append(step("command", head + says + ".", rua_command(report, len(streams)) if fid == "OUTSIDE-007" else cmd))
        if fid in ("OUTSIDE-004", "OUTSIDE-010"):
            doms = [_name(s.get("domain")) for s in _l(_d(rua.get("policy_check")).get("seen")) if isinstance(s, dict)]
            doms = [d for d in dict.fromkeys(doms) if _ok(d)][:3]
            if doms:
                steps.append(step("dns", "Look up the live record%s: what it says now is the policy receivers apply from "
                                         "their next report on (reports lag 24 to 48 hours behind a change)." % (
                                             "" if len(doms) == 1 else "s"), lookup(["_dmarc." + d for d in doms])))
        if fid == "OUTSIDE-005":
            for r in _l(rua.get("retiring_selectors"))[:3]:
                name = "%s._domainkey.%s" % (_name(_d(r).get("retiring")), _name(_d(r).get("domain")))
                if _d(r).get("messages") and _ok(name):
                    steps.append(step("dns", "Look up %s: the key is still published, and the reports show mail signed "
                                             "with it; keep it until they stop." % name, lookup(name)))
    if raw:
        steps.append(raw)
    return steps


def totals_steps(report):
    """The run's overall figures, the ones the status document quotes: the
    aggregate reports' totals and the mail log's deduplicated counters."""
    steps = []
    cmd = rua_command(report)
    tot = _d(_d(report.get("rua")).get("totals"))
    if cmd and tot:
        steps.append(step("command", "Re-read the aggregate reports the run read: messages shows %d, DMARC pass %d and "
                                     "DMARC fail %d, over %s to %s; receivers count forwarded copies too, so these never "
                                     "match the deduplicated mail log." % (
                                         _n(tot.get("messages")) or 0, _n(tot.get("pass")) or 0, _n(tot.get("fail")) or 0,
                                         tot.get("begin_date") or "?", tot.get("end_date") or "?"), cmd))
    c = _d(_d(report.get("maillog")).get("counters"))
    rc = recount_command(report)
    if rc and c:
        steps.append(step("command", "Recount the mail-log export the run read: rows read shows %d, logical messages %d "
                                     "and GENUINE failures %d%s." % (
                                         _n(c.get("raw_rows")) or 0, _n(c.get("logical_messages")) or 0,
                                         _n(c.get("genuine_failures")) or 0,
                                         ", and failed authentication but DELIVERED %d" % (
                                             _n(c.get("delivered_despite_fail")) or 0)
                                         if _d(report.get("maillog")).get("auth_column") else ""), rc))
    return steps


# ------------------------------------------------------------------ DNS

def m365_dkim_steps(domain):
    """Microsoft 365's own DKIM state for a domain: the portal page, the cmdlet and the two selector CNAMEs."""
    return [step("portal", "If Microsoft 365 sends as %s: in %s, select %s; the page shows whether DKIM signing is on "
                           "and the two CNAME records it needs." % (domain, DKIM_PAGE, domain)),
            step("command", "%s: Enabled shows True and Status Valid once Microsoft 365 signs as %s, and Selector1CNAME and "
                            "Selector2CNAME are the targets the two selector names must point to (an error that the "
                            "identity cannot be found means Microsoft 365 has no DKIM configuration for it)." % (EXO, domain),
                 "Get-DkimSigningConfig -Identity %s | Format-List Enabled,Status,Selector1CNAME,Selector2CNAME" % domain),
            step("dns", "Look up the two Microsoft 365 selector names: each answers with the target Get-DkimSigningConfig "
                        "names; no answer means the CNAMEs are not published.",
                 lookup(["selector1._domainkey." + domain, "selector2._domainkey." + domain], "CNAME"))]


def header_step(domain):
    return step("command", "Save the full header of a recent message each sender sent as %s to %s, then read it: the "
                           "DKIM line shows a signature with d=%s (or a subdomain of it) that the receiver passed, and "
                           "DMARC would pass via dkim; a dashboard toggle is not proof." % (domain, HEADER_FILE, domain),
                "python src/headers.py %s" % HEADER_FILE)


def dns_finding_steps(f, domain, report):
    fid = str(f.get("id") or "")
    ev = str(f.get("evidence") or "")
    title = str(f.get("title") or "")
    if not _ok(domain):
        return [step("command", "Re-run the DNS audit for this domain: it reports %s again (the audit saw: %s)." % (fid, ev))]
    r = _d(_d(report.get("dns")).get(domain))
    src = _name(r.get("dmarc_source")) or "_dmarc." + domain
    src = src if _ok(src) else "_dmarc." + domain
    tags = dns_audit.parse_dmarc(ev) if ev.lower().startswith("v=dmarc1") else {}
    if fid == "SPF-001":
        return [step("dns", "Look up the TXT records at %s: none of the answers starts with v=spf1, as the audit saw (%s)."
                            % (domain, ev), lookup(domain, https=True))]
    if fid == "SPF-002":
        return [step("dns", "The audit's TXT lookup for %s failed on every path (%s); look it up through two public "
                            "resolvers: an answer from either settles whether %s publishes SPF, and a failure on both "
                            "means the zone does not answer receivers either." % (domain, ev, domain),
                     lookup(domain, servers=RESOLVERS, https=True)),
                step("command", "Once it answers, count the lookups: the lookups line shows the record's DNS lookups out "
                                "of 10.", "python src/spf_lookups.py %s" % domain)]
    if fid == "SPF-003":
        term = r.get("spf_terminator") or (ev.split()[-1] if ev.split() else "?")
        return [step("dns", "Look up the TXT records at %s: the one starting with v=spf1 reads %s and ends in %s, which "
                            "protects nothing." % (domain, _q(ev), term), lookup(domain))]
    if fid in ("SPF-004", "SPF-005", "SPF-006"):
        m = re.search(r"(\d+) DNS-querying", ev)
        n = int(m.group(1)) if m else _n(r.get("spf_lookups"))
        steps = [step("command", "Count the lookups: the lookups line shows %s / 10 (%s)." % (
            n if n is not None else "the count", ev), "python src/spf_lookups.py %s" % domain)]
        if r.get("spf"):
            steps.append(step("dns", "Look up the TXT records at %s: the count starts from the one starting with v=spf1, "
                                     "which reads %s." % (domain, _q(r["spf"])), lookup(domain)))
        return steps
    if fid == "SPF-007":
        owners = [p.split(":", 1)[0].strip().lower() for p in ev.split("; ")]
        owners = [o for o in dict.fromkeys(owners) if _ok(o)][:3]
        steps = [step("command", "Count the lookups: the include%s the audit could not resolve show%s as LOOKUP FAILED "
                                 "(%s), so the count is a lower bound." % (
                                     "" if len(owners) == 1 else "s", "s" if len(owners) == 1 else "", ev),
                      "python src/spf_lookups.py %s" % domain)]
        if r.get("spf"):
            steps.append(step("dns", "Look up the TXT records at %s: one string starts with v=spf1, the record the count "
                                     "expands, and it reads %s." % (domain, _q(r["spf"])), lookup(domain)))
        if owners:
            steps.append(step("dns", "Look up each include that failed through two resolvers: an answer means the count "
                                     "can be completed; none on both means the include fails for receivers too.",
                              lookup(owners, servers=RESOLVERS, https=True)))
        return steps
    if fid in ("DMARC-001", "DMARC-006"):
        names = [n.strip().lower() for n in ev.split(":", 1)[-1].split(",")]
        names = [n for n in names if _ok(n)] or dns_audit.dmarc_candidates(domain)
        if fid == "DMARC-001":
            return [step("dns", "Look up the TXT records at %s: none of the answers starts with v=DMARC1, as the audit "
                                "saw: no policy and no reporting for %s." % (audit._names(names, 5), domain),
                         lookup(names, https=True))]
        return [step("dns", "The audit's DMARC lookups failed on every path (%s); look the names up through two public "
                            "resolvers: an answer from either settles what %s publishes." % (ev, domain),
                     lookup(names, servers=RESOLVERS, https=True))]
    if fid == "DMARC-002":
        if r.get("inherited"):
            own = "_dmarc." + domain
            if any(isinstance(x, dict) and x.get("id") == "DMARC-007" for x in _l(r.get("findings"))):
                return [step("dns", "Look up %s and %s: the audit's lookup of %s failed (DMARC-007), so it assumed no record "
                                    "of its own; the one at %s reads %s, so its subdomain policy (sp=, else p=) of none "
                                    "applies, monitoring only - unless %s answers with a v=DMARC1 string of its own "
                                    "here." % (own, src, own, src, _q(ev), own),
                             lookup([own, src], servers=RESOLVERS, https=True))]
            return [step("dns", "Look up %s and %s: %s has no record of its own, and the one at %s reads %s, so its "
                                "subdomain policy (sp=, else p=) of none applies: monitoring only." % (
                                    own, src, own, src, _q(ev)), lookup([own, src]))]
        return [step("dns", "Look up the TXT records at %s: the one starting with v=DMARC1 reads %s, with p=none: "
                            "monitoring only." % (src, _q(ev)), lookup(src))]
    if fid == "DMARC-003":
        return [step("dns", "Look up the TXT records at %s: the one starting with v=DMARC1 reads %s, with no rua= tag, so "
                            "no receiver sends aggregate reports for it." % (src, _q(ev)), lookup(src))]
    if fid == "DMARC-004":
        return [step("dns", "Look up the TXT records at %s: the one starting with v=DMARC1 reads %s, with p=%s and no sp= "
                            "tag, so subdomains without a record of their own inherit p=%s." % (
                                src, _q(ev), tags.get("p", "?"), tags.get("p", "?")), lookup(src))]
    if fid == "DMARC-005":
        m = re.search(r"at (_dmarc\.[a-z0-9_.-]+)", title)
        at = m.group(1) if m and _ok(m.group(1)) else src
        n = re.match(r"(\d+)", ev)
        return [step("dns", "Look up the TXT records at %s: %s of the answers start with v=DMARC1; with more than one, "
                            "receivers apply no policy and send no reports." % (at, n.group(1) if n else "more than one"),
                     lookup(at))]
    if fid == "DMARC-007":
        own = "_dmarc." + domain
        return [step("dns", "The audit's lookup of %s failed while %s answered (%s); look %s up through two public "
                            "resolvers: no v=DMARC1 answer means %s really inherits the record at %s." % (
                                own, src, ev, own, domain, src), lookup(own, servers=RESOLVERS, https=True))]
    if fid == "DMARC-008":
        return [step("dns", "Look up the TXT records at %s: the one starting with v=DMARC1 reads %s, with pct=%s: the "
                            "policy applies to that share of failing mail only." % (src, _q(ev), tags.get("pct", "?")),
                     lookup(src))]
    if fid == "DKIM-001":
        canary = ev.split()[0].lower() if ev.split() else ""
        steps = []
        if _ok(canary):
            steps.append(step("dns", "Look up %s, a selector nobody publishes: it answers anyway, so the zone has a "
                                     "wildcard under _domainkey and probing selectors proves nothing." % canary,
                              lookup(canary)))
        return steps + [header_step(domain)]
    if fid == "DKIM-002":
        probed = [p.strip() for p in ev.split(":", 1)[-1].split(",") if p.strip()]
        names = ["%s._domainkey.%s" % (p, domain) for p in probed if _ok("%s._domainkey.%s" % (p, domain))][:4]
        steps = [step("dns", "Look up the selector names the audit probed: none answers with a key (%s), so no common "
                             "selector is published; a sender may still sign with one only a live header names." % ev,
                      lookup(names or ["selector1._domainkey." + domain, "selector2._domainkey." + domain],
                             https=True))]
        return steps + m365_dkim_steps(domain) + [header_step(domain)]
    if fid == "DKIM-003":
        names = [n.strip().lower() for n in ev.split(",") if _ok(n.strip().lower())][:4]
        if not names:
            return [header_step(domain)]
        return [step("dns", "Look up the selector name%s as CNAME: each answers with a target." % (
                    "" if len(names) == 1 else "s"), lookup(names, "CNAME")),
                step("dns", "Look up the same name%s as TXT, which follows the CNAME: no answer starts with v=DKIM1 or "
                            "carries a p= key, so nothing can verify a signature with %s." % (
                                "" if len(names) == 1 else "s", "it" if len(names) == 1 else "them"),
                     lookup(names, https=True))]
    if fid == "DKIM-004":
        sels = [s.strip() for s in ev.split(":", 1)[-1].split(",") if s.strip()]
        names = [n for n in ("%s._domainkey.%s" % (s, domain) for s in sels) if _ok(n)][:4]
        return [step("dns", "The audit's selector lookups failed on every path (%s); look them up through two public "
                            "resolvers: answers from either settle which keys exist." % ev,
                     lookup(names or ["selector1._domainkey." + domain], servers=RESOLVERS, https=True))]
    return [step("command", "Re-run the DNS audit for %s: its findings list shows %s, %s (the audit saw: %s)." % (
        domain, fid or "the finding", title or "?", ev or "nothing recorded"), "python src/dns_audit.py %s" % domain)]


# ------------------------------------------------------------------ mail-log findings

def _domains_by(report, key, cap=5):
    """(audited domain, its own count of key) for the domains carrying any, the most first, a tie in the one
    order every list of names follows (the status document's organization first)."""
    rows = [(d, _n(c.get(key)) or 0) for d, c in _buckets(report).items()]
    head = next_steps.headline_org(report)
    return sorted([r for r in rows if r[1] and _ok(r[0])], key=lambda r: (-r[1], audit.domain_key(r[0], head)))[:cap]


def _csv_path(report):
    path = _export(report)
    return ps(path) if path else None


def maillog_finding_steps(f, report):
    fid = str(f.get("id") or "")
    ml = _d(report.get("maillog"))
    c = _d(ml.get("counters"))
    rc = recount_command(report)
    steps = []
    if fid == "MAILFLOW-001":
        if rc:
            steps.append(step("command", "Recount the export the report read: the GENUINE failures line shows %d, the "
                                         "logical messages with no passing copy for their recipient." % (
                                             _n(c.get("genuine_failures")) or 0), rc))
        top = _domains_by(report, "genuine_failures")
        for d, n in top:
            steps.append(kql_step("sender_census", d, census_says(report, d, n)))
        rest = sum(_n(cc.get("genuine_failures")) or 0 for dd, cc in _buckets(report).items()
                   if dd not in dict(top))
        subs = sum(_n(_d(cc.get("subdomains_total")).get("genuine_failures")) or 0 for cc in _buckets(report).values())
        other = _n(_d(_d(ml.get("by_domain")).get(audit.OTHER)).get("genuine_failures")) or 0
        parts = [p for p in ("%d more from other audited domains (their sections)" % rest if rest else "",
                             "%d from unaudited subdomains (the subdomain check in their parent's section)" % subs
                             if subs else "",
                             "%d from domains outside the audited list (maillog.by_domain %s)" % (other, audit.OTHER)
                             if other else "") if p]
        if parts:  # a pointer to other checks, nothing to run: verify.md shows it as a note
            steps.append(step("command", "The rest of the %d: %s." % (_n(c.get("genuine_failures")) or 0,
                                                                       "; ".join(parts))))
        return steps
    if fid == "MAILFLOW-002":
        if rc:
            by = dedupe.delivered_by_text(c.get("delivered_despite_fail_by"), c.get("delivered_despite_fail"))
            steps.append(step("command", "Recount the export the report read: failed authentication but DELIVERED shows "
                                         "%d%s." % (_n(c.get("delivered_despite_fail")) or 0,
                                                     ", and its let in by line names %s" % by if by else ""), rc))
        for d, n in _domains_by(report, "delivered_despite_fail"):
            steps.append(kql_step("maillog_totals", org_of(d), delivered_says(report, d, n)))
        return steps
    if fid == "MAILFLOW-010":
        if rc:
            steps.append(step("command", "Recount the export the report read: the senders passing on SPF alone list shows "
                                         "%s." % (f.get("evidence") or "them"), rc))
        orgs = []
        for s in _l(ml.get("spf_only_senders")):
            o = org_of(_name(_d(s).get("domain")))
            if _ok(o) and o not in orgs:
                orgs.append(o)
        for o in orgs[:3]:
            mine = [s for s in _l(ml.get("spf_only_senders")) if org_of(_name(_d(s).get("domain"))) == o][:3]
            steps.append(kql_step("dkim_alignment", o, "the spf_only column shows %s; %s." % (
                ", ".join("%s (envelope %s) %d" % (s.get("sender") or "?", s.get("envelope_domain") or "?",
                                                   _n(s.get("spf_only")) or 0) for s in mine),
                window_note(report, o, 30))))
        return steps
    path = _csv_path(report)
    if fid in ("MAILFLOW-006", "MAILFLOW-008") and path:
        return [step("command", "Read the export's header row: %s." % (
            "no column holds a DMARC verdict, so a failure there means never delivered" if fid == "MAILFLOW-006" else
            "it lacks %s" % (f.get("title") or "").split(": ", 1)[-1]), "Get-Content -Path %s -TotalCount 1" % path)]
    if fid == "MAILFLOW-007" and path and ml.get("auth_column"):
        return [step("command", "Count the values in the verdict column %s: none reads pass or fail (%s)." % (
            ml["auth_column"], f.get("evidence") or ""),
            "Import-Csv -Path %s | Group-Object -Property %s | Select-Object Name, Count" % (path, ps(ml["auth_column"])))]
    if fid == "MAILFLOW-009" and path:
        col = _d(ml.get("columns")).get("domain") or audit.MAILLOG_COLUMNS["domain"]
        return [step("command", "List the sender domains the export holds: none is %s or under it (%s)." % (
            ml.get("sender_domain") or "the --sender-domain", f.get("evidence") or ""),
            "Import-Csv -Path %s | Group-Object -Property %s | Sort-Object Count -Descending | Select-Object -First 10 "
            "Name, Count" % (path, ps(col)))]
    says = {"MAILFLOW-003": "passed authentication but BLOCKED/QUARANTINED shows %d, and the list under it names the "
                            "messages" % (_n(c.get("blocked_despite_pass")) or 0),
            "MAILFLOW-004": "the genuine failures by likely cause lines show %s; a label is a heuristic, so confirm a sender "
                            "from a live header before acting" % ", ".join(
                                "%d %s" % (_n(v) or 0, k) for k, v in _d(c.get("by_likely")).items()),
            "MAILFLOW-005": "the without a Message-ID line shows %d rows the dedupe cannot group" % (
                _n(c.get("rows_without_msgid")) or 0)}.get(fid, "its findings list shows %s %s" % (fid, f.get("title") or ""))
    if rc:
        return [step("command", "Recount the export the report read: %s." % says, rc)]
    return [step("command", "This report names no mail-log export to recount; the finding's evidence: %s." % (
        f.get("evidence") or "none recorded"))]


# ------------------------------------------------------------------ message headers

def header_finding_steps(f, report):
    fid = str(f.get("id") or "")
    path = str(f.get("source") or "")[len("headers:"):] or str(f.get("file") or "")
    if not path:
        return [step("command", "This finding names no header file; its evidence: %s." % (f.get("evidence") or "none"))]
    authserv = _d(report.get("inputs")).get("authserv_id")
    cmd = "python src/headers.py %s" % ps(shown(path)) + (" --authserv-id %s" % ps(authserv) if authserv else "")
    steps = [step("command", "Re-read the header file: its findings list shows [%s] %s %s." % (
        f.get("severity") or "?", fid, f.get("title") or ""), cmd)]
    if fid in ("PROOF-001", "PROOF-002", "PROOF-003", "PROOF-008", "PROOF-009"):
        steps.append(step("command", "List the header lines that decide it: the DKIM-Signature lines carry d= and s=, and "
                                     "the Authentication-Results lines carry the receiver's spf, dkim and dmarc verdicts "
                                     "(%s)." % (f.get("evidence") or "?"),
                          "Select-String -Path %s -Pattern '^(DKIM-Signature|Authentication-Results):'" % ps(shown(path))))
    m = re.search(r"at ([a-z0-9_-]+\._domainkey\.[a-z0-9_.-]+)", str(f.get("title") or "").lower())
    if fid in ("PROOF-010", "PROOF-011", "PROOF-012") and m and _ok(m.group(1).rstrip(".")):
        steps.append(step("dns", "Look up %s: %s." % (
            m.group(1).rstrip("."), "an answer carrying p= is the key (existence only; it proves no signature)"
            if fid == "PROOF-012" else "no answer with a p= key (or an empty p=) means nothing verifies with this "
                                       "selector today"), lookup(m.group(1).rstrip("."))))
    return steps


# ------------------------------------------------------------------ tenant configuration

TRANSPORT_RULE = ("Get-TransportRule -Identity %s | Format-List Name,State,Mode,Priority,SetSCL,SenderIpRanges,"
                  "ExceptIfSenderIpRanges,HeaderContainsMessageHeader,HeaderContainsWords,HeaderMatchesMessageHeader,"
                  "HeaderMatchesPatterns,ExceptIfHeaderContainsMessageHeader,ExceptIfHeaderContainsWords,"
                  "ExceptIfHeaderMatchesMessageHeader,ExceptIfHeaderMatchesPatterns,Quarantine,DeleteMessage,ExceptIfFrom,"
                  "ExceptIfSenderDomainIs,ExceptIfSubjectContainsWords,ExceptIfFromAddressContainsWords,"
                  "ExceptIfFromAddressMatchesPatterns")
# the five exception lists audit_rules.ps1 adds up for RULES-004 (LARGE-EXCEPTION-LIST), counted the way it counts them
EXCEPTION_COUNT = ("$r = Get-TransportRule -Identity %s; @(@($r.ExceptIfFrom) + @($r.ExceptIfSenderDomainIs) + "
                   "@($r.ExceptIfSubjectContainsWords) + @($r.ExceptIfFromAddressContainsWords) + "
                   "@($r.ExceptIfFromAddressMatchesPatterns) | Where-Object { $null -ne $_ -and \"$_\" -ne '' }).Count")
CONNECTOR = ("Get-InboundConnector -Identity %s | Format-List Name,ConnectorType,Enabled,TreatMessagesAsInternal,"
             "SenderIPAddresses,SenderDomains,TlsSenderCertificateName,RestrictDomainsToIPAddresses,EFSkipLastIP,EFSkipIPs,"
             "EFUsers")
ANTIPHISH = ("Get-AntiPhishPolicy -Identity %s | Format-List Name,Enabled,EnableSpoofIntelligence,HonorDmarcPolicy,"
             "DmarcRejectAction,DmarcQuarantineAction,AuthenticationFailAction,EnableUnauthenticatedSender,EnableViaTag,"
             "EnableMailboxIntelligence,EnableMailboxIntelligenceProtection,EnableTargetedUserProtection,"
             "TargetedUsersToProtect,EnableOrganizationDomainsProtection,ExcludedSenders,ExcludedDomains")
# per group kind (audit_groups.ps1's Kind): the group's settings, and its members the way the export read them
GROUP_CMDS = {
    "DistributionGroup": ("Get-DistributionGroup -Identity %s | Format-List DisplayName,PrimarySmtpAddress,"
                          "RequireSenderAuthenticationEnabled,AcceptMessagesOnlyFrom,AcceptMessagesOnlyFromDLMembers,"
                          "AcceptMessagesOnlyFromSendersOrMembers",
                          "Get-DistributionGroupMember -Identity %s -ResultSize Unlimited"),
    "DynamicDistributionGroup": ("Get-DynamicDistributionGroup -Identity %s | Format-List DisplayName,PrimarySmtpAddress,"
                                 "RequireSenderAuthenticationEnabled,RecipientFilter",
                                 "Get-DynamicDistributionGroupMember -Identity %s -ResultSize Unlimited"),
    "UnifiedGroup": ("Get-UnifiedGroup -Identity %s | Format-List DisplayName,PrimarySmtpAddress,"
                     "RequireSenderAuthenticationEnabled",
                     "Get-UnifiedGroupLinks -Identity %s -LinkType Members -ResultSize Unlimited"),
}
# where Get-DynamicDistributionGroupMember is missing, audit_groups.ps1 previews the group's filter instead
DYNAMIC_PREVIEW = ("# where Get-DynamicDistributionGroupMember is not available, the export previewed the filter:\n"
                   "# Get-Recipient -RecipientPreviewFilter (Get-DynamicDistributionGroup -Identity %s).RecipientFilter "
                   "-ResultSize Unlimited")
EXTERNAL_MEMBERS = (" | Where-Object { $_.RecipientTypeDetails -match 'MailContact|MailUser' } | "
                    "Format-Table Name,PrimarySmtpAddress,RecipientTypeDetails")
# what a tenant finding is about, by id: the export's own ids, and the Issues codes audit.py reads when an
# export carries no findings list
TENANT_KINDS = {
    "transport_rule": ("RULES-001", "RULES-002", "RULES-003", "RULES-004", "RULES-005", "ALLOW-WITHOUT-AUTH",
                       "ALLOW-IP-GATED-ONLY", "FORGEABLE-CONDITION", "AUDIT-MODE-BLOCK", "LARGE-EXCEPTION-LIST"),
    "rule_hits": ("RULES-006", "RULES-007"),
    "spam_policy": ("RULES-101", "RULES-102"),
    "allow_list": ("RULES-103", "RULES-104"),
    "spoof_allow": ("RULES-105", "RULES-106"),
    "connector": ("RULES-107", "RULES-108", "RULES-109", "TREATS-AS-INTERNAL", "EF-SKIP", "UNPINNED-ONPREM"),
    "antiphish": ("RULES-110", "RULES-111", "RULES-112", "RULES-113", "RULES-114", "RULES-115", "RULES-116",
                  "RULES-119", "RULES-120", "POLICY-DISABLED", "SPOOF-INTEL-OFF", "DMARC-NOT-HONORED",
                  "UNAUTH-INDICATORS-OFF", "MAILBOX-INTEL-OFF", "USER-IMPERSONATION-OFF", "DOMAIN-IMPERSONATION-OFF",
                  "IMPERSONATION-EXCLUSIONS"),
    "accepted_domain": ("RULES-117",),
    "section": ("RULES-118",),
    "group": ("GROUPS-001", "GROUPS-002", "GROUPS-003", "OPEN-AND-REDISTRIBUTES-EXTERNAL", "OPEN-TO-EXTERNAL",
              "REDISTRIBUTES-EXTERNAL"),
    "members": ("MEMBERS-NOT-READ",),
    "forward": ("GROUPS-004", "GROUPS-005"),
    "inbox_rule": ("GROUPS-006",),
    "remote_domain": ("GROUPS-007",),
    "outbound_spam": ("GROUPS-008",),
    "group_section": ("GROUPS-009",),
}
TENANT_KIND = {fid: kind for kind, ids in TENANT_KINDS.items() for fid in ids}
# the cmdlet behind each section an export reports as not checked (RULES-118, GROUPS-009)
SECTION_CMDS = (
    ("HostedContentFilterRule", "Get-HostedContentFilterRule"),
    ("HostedContentFilterPolicy", "Get-HostedContentFilterPolicy"),
    ("TenantAllowBlockListSpoofItems", "Get-TenantAllowBlockListSpoofItems -Action Allow"),
    ("TenantAllowBlockListItems/", "Get-TenantAllowBlockListItems -ListType %s -Allow"),
    ("HostedOutboundSpamFilterPolicy", "Get-HostedOutboundSpamFilterPolicy"),
    ("InboundConnector", "Get-InboundConnector"),
    ("AntiPhishPolicy", "Get-AntiPhishPolicy"),
    ("AcceptedDomain", "Get-AcceptedDomain"),
    ("DynamicDistributionGroup", "Get-DynamicDistributionGroup -ResultSize Unlimited"),
    ("DistributionGroup", "Get-DistributionGroup -ResultSize Unlimited"),
    ("UnifiedGroup", "Get-UnifiedGroup -ResultSize Unlimited"),
    ("Mailbox forwarding", "Get-Mailbox -ResultSize Unlimited -Filter 'ForwardingSmtpAddress -ne $null -or "
                           "ForwardingAddress -ne $null'"),
    ("Mailbox list", "Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox"),
    ("RemoteDomain", "Get-RemoteDomain"),
)
UNTITLED = "(untitled finding)"  # the title audit._norm_finding gives an export finding that carried none


def script_command(report, section):
    """The export a tenant section came from, run again the way the report's
    export ran (audit_rules.ps1's -Days and -SkipHits from its window,
    audit_groups.ps1's -IncludeInboxRules and -SkipMembers from its options),
    as an expression whose value is its findings; None for another section."""
    doc = _d(report.get(section))
    if section == "rules":
        w = _d(doc.get("window"))
        days = _n(w.get("days"))
        args = (" -Days %d" % days if days and days != 10 else "") + ("" if w.get("hits_checked") is True else " -SkipHits")
    elif section == "groups":
        o = _d(doc.get("options"))
        args = (" -IncludeInboxRules" if o.get("include_inbox_rules") is True else "") + (
            " -SkipMembers" if o.get("skip_members") is True else "")
    elif section == "bypasses":
        args = ""
    else:
        return None
    return "(& .\\src\\%s -Json%s | ConvertFrom-Json).findings" % (audit.TENANT_SECTIONS[section][0], args)


def _object(f):
    """What a tenant finding is about: the export's object, else the name after the title's first ': '
    ('?' is the label audit.py gives an Issues row that named nothing, so it is nothing here too)."""
    if f.get("object"):
        return str(f["object"])
    title = str(f.get("title") or "")
    obj = title.split(": ", 1)[1].strip() if ": " in title else ""
    return "" if obj == "?" else obj


def group_of(f, report, obj):
    """(kind, identity) of the group a finding names: the kind (DistributionGroup,
    DynamicDistributionGroup or UnifiedGroup) is the first word of the export's
    evidence; an Issues-code finding, whose evidence is the code alone, takes
    it from the groups table row naming the group, and that row's address
    becomes the identity. Kind None when nothing says."""
    first = re.split(r"[;\s]", str(f.get("evidence") or "").strip(), maxsplit=1)[0]
    want = obj.strip().lower()
    for row in _l(_d(_d(report.get("groups")).get("tables")).get("groups")):
        if not isinstance(row, dict) or not want:
            continue
        if want in (str(row.get("Name") or "").strip().lower(), str(row.get("Address") or "").strip().lower()):
            kind = row.get("Kind") if isinstance(row.get("Kind"), str) else None
            address = str(row.get("Address") or "").strip()
            return (first if first in GROUP_CMDS else kind if kind in GROUP_CMDS else None), address or obj
    return (first if first in GROUP_CMDS else None), obj


def members_step(kind, ident, says):
    """List a group's members outside the tenant with the cmdlet for its kind; an unknown kind is read first."""
    if kind is None:
        return step("command", "%s: %s; the export did not record the group's kind, so read it first: RecipientTypeDetails "
                               "names it, then list the members with Get-DistributionGroupMember (a distribution or "
                               "mail-enabled security group), Get-DynamicDistributionGroupMember (DynamicDistributionGroup) "
                               "or Get-UnifiedGroupLinks -LinkType Members (GroupMailbox, a Microsoft 365 group), each with "
                               "-Identity %s -ResultSize Unlimited." % (EXO, says, ps(ident)),
                    "Get-Recipient -Identity %s | Format-List Name,PrimarySmtpAddress,RecipientTypeDetails" % ps(ident))
    code = GROUP_CMDS[kind][1] % ps(ident) + EXTERNAL_MEMBERS
    if kind == "DynamicDistributionGroup":
        code += "\n" + DYNAMIC_PREVIEW % ps(ident)
    return step("command", "%s: %s." % (EXO, says), code)


def idless_steps(f, report, section):
    """An export finding that carried no id: audit.py names it <SECTION>-000,
    an id the export never had, so it is read from the export file the
    report read (its findings without an id) and, run again, picked by its
    title."""
    fid, title, ev = str(f.get("id") or ""), str(f.get("title") or ""), str(f.get("evidence") or "")
    steps = []
    src = _d(report.get(section)).get("source")
    if isinstance(src, str) and src:
        steps.append(step("command", "The export's finding carried no id, so audit.py named it %s, an id no export has: "
                                     "read the export file the report read, where it is among the findings without an id"
                                     "%s (%s)." % (fid, "" if title == UNTITLED else ", titled " + _q(title),
                                                   ev or "no evidence recorded"),
                          "(Get-Content -Raw -Path %s | ConvertFrom-Json).findings | Where-Object { -not $_.id } | "
                          "Format-List" % ps(shown(src))))
    cmd = script_command(report, section)
    if cmd and title and title != UNTITLED:
        steps.append(step("command", "Run the %s export again and pick the finding by its title, since it has no id to pick "
                                     "it by: it shows %s while the tenant still has it." % (section, _q(title)),
                          "%s | Where-Object { $_.title -eq %s } | Format-List" % (cmd, ps_quote(title))))
    return steps


def tenant_finding_steps(f, report):
    fid = str(f.get("id") or "")
    section = str(f.get("source") or "")
    kind = TENANT_KIND.get(fid)
    obj = _object(f)
    ev = str(f.get("evidence") or "")
    shows = "it shows %s" % ev if ev else "it shows the setting the finding names"
    if kind == "transport_rule" and obj:
        steps = [step("portal", "In %s > Mail flow > Rules, open the rule %s: its conditions, exceptions and actions match "
                                "the export (%s)." % (EAC, obj, ev)),
                 step("command", "%s: %s." % (EXO, shows), TRANSPORT_RULE % ps(obj))]
        if fid in ("RULES-004", "LARGE-EXCEPTION-LIST"):
            n = re.search(r"(\d+) (?:excepted|entries)", ev)
            steps.append(step("command", "Count the entries the way the export counted them, over its five exception "
                                         "lists (senders, sender domains, subject words, address words and address "
                                         "patterns): the count is %s." % (n.group(1) if n else "20 or more"),
                              EXCEPTION_COUNT % ps(obj)))
        return steps
    if kind == "rule_hits":
        days = re.search(r"in (\d+) days", str(f.get("title") or ""))
        days = int(days.group(1)) if days else 10
        names = [obj] if fid == "RULES-006" and obj else [n.strip() for n in ev.split(",") if n.strip()][:3]
        if names:
            return [step("command", "%s: the count of the rule's hits over the last %d days is %s (%s)." % (
                EXO, days, "0" if fid == "RULES-006" else "not available, the cmdlet fails", ev or obj),
                "\n".join("Get-MailDetailTransportRuleReport -TransportRule %s -StartDate (Get-Date).AddDays(-%d) "
                          "-EndDate (Get-Date) | Measure-Object | Select-Object Count" % (ps(n), days) for n in names))]
    if kind == "spam_policy" and obj:
        return [step("portal", "In %s > Anti-spam, open the policy %s: its allowed senders and domains list the entries "
                               "the export counted (%s)." % (THREAT_POLICIES, obj, ev)),
                step("command", "%s: %s." % (EXO, shows),
                     "Get-HostedContentFilterPolicy -Identity %s | Format-List Name,IsDefault,AllowedSenders,"
                     "AllowedSenderDomains" % ps(obj))]
    if kind == "allow_list":
        list_type = obj.split("/", 1)[1] if "/" in obj else "Sender"
        list_type = list_type if list_type in ("Sender", "Url", "FileHash") else "Sender"
        return [step("portal", "In %s > Tenant Allow/Block Lists, the allow entries on the %s tab are the ones the export "
                               "counted (%s)." % (THREAT_POLICIES, {"Sender": "Domains & addresses", "Url": "URLs",
                                                                     "FileHash": "Files"}[list_type], ev)),
                step("command", "%s: %s." % (EXO, shows),
                     "Get-TenantAllowBlockListItems -ListType %s -Allow | Format-Table Value,ExpirationDate,ListSubType"
                     % list_type)]
    if kind == "spoof_allow":
        user, _, infra = obj.partition("|")
        code = "Get-TenantAllowBlockListSpoofItems -Action Allow"
        if user and infra:
            code += " | Where-Object { $_.SpoofedUser -eq %s -and $_.SendingInfrastructure -eq %s }" % (
                ps_quote(user), ps_quote(infra))
        return [step("portal", "In %s > Tenant Allow/Block Lists > Spoofed senders, the allow entry for %s sent from %s "
                               "is there (%s)." % (THREAT_POLICIES, user or "the spoofed user", infra or "its "
                                                   "infrastructure", ev)),
                step("command", "%s: %s." % (EXO, shows), code + " | Format-List SpoofedUser,SendingInfrastructure,"
                                                                 "SpoofType,Action")]
    if kind == "connector" and obj:
        return [step("portal", "In %s > Mail flow > Connectors, open the inbound connector %s (%s)." % (EAC, obj, ev)),
                step("command", "%s: %s." % (EXO, shows), CONNECTOR % ps(obj))]
    if kind == "antiphish" and obj:
        return [step("portal", "In %s > Anti-phishing, open the policy %s (%s)." % (THREAT_POLICIES, obj, ev)),
                step("command", "%s: %s." % (EXO, shows), ANTIPHISH % ps(obj))]
    if kind == "accepted_domain" and obj:
        return [step("portal", "In %s > Mail flow > Accepted domains, the domain %s shows its domain type (%s)." % (
            EAC, obj, ev)),
                step("command", "%s: %s." % (EXO, shows),
                     "Get-AcceptedDomain -Identity %s | Format-List DomainName,DomainType,Default" % ps(obj))]
    if kind == "group" and obj:
        gkind, ident = group_of(f, report, obj)
        portal = step("portal", "In %s > Recipients > Groups, open %s: its delivery management says who may send to it, "
                                "and its members list the outside ones (%s)." % (EAC, obj, ev))
        if gkind is None:
            return [portal, members_step(None, ident, "the group's settings and its members outside the tenant "
                                                      "(MailContact, MailUser) match the export")]
        code = GROUP_CMDS[gkind][0] % ps(ident) + "\n" + members_step(gkind, ident, "")["code"]
        return [portal, step("command", "%s: the group's settings match the export, and the second line lists its members "
                                        "outside the tenant (MailContact, MailUser)." % EXO, code)]
    if kind == "members" and obj:  # MEMBERS-NOT-READ, an Issues code: the group whose membership the export missed
        gkind, ident = group_of(f, report, obj)
        return [members_step(gkind, ident, "the group's membership is read here; the export could not read it (%s)" % (
            ev or fid))]
    if kind == "forward" and obj:
        return [step("portal", "In %s > Recipients > Mailboxes, open %s: its mail flow settings show the forwarding "
                               "address (%s)." % (EAC, obj, ev)),
                step("command", "%s: %s." % (EXO, shows),
                     "Get-Mailbox -Identity %s | Format-List PrimarySmtpAddress,ForwardingSmtpAddress,ForwardingAddress,"
                     "DeliverToMailboxAndForward" % ps(obj))]
    if kind == "inbox_rule" and obj:
        return [step("command", "%s: the mailbox's inbox rule forwards or redirects outside the tenant (%s); admins see "
                                "inbox rules only here." % (EXO, ev),
                     "Get-InboxRule -Mailbox %s | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or "
                     "$_.RedirectTo } | Format-List Name,Enabled,ForwardTo,ForwardAsAttachmentTo,RedirectTo" % ps(obj))]
    if kind == "remote_domain" and obj:
        return [step("portal", "In %s > Mail flow > Remote domains, open %s: automatic forwarding is allowed (%s)." % (
            EAC, obj, ev)),
                step("command", "%s: %s." % (EXO, shows),
                     "Get-RemoteDomain -Identity %s | Format-List Name,DomainName,AutoForwardEnabled" % ps(obj))]
    if kind == "outbound_spam" and obj:
        return [step("portal", "In %s > Anti-spam, open the outbound policy %s: its forwarding rules setting matches "
                               "(%s)." % (THREAT_POLICIES, obj, ev)),
                step("command", "%s: %s." % (EXO, shows),
                     "Get-HostedOutboundSpamFilterPolicy -Identity %s | Format-List Name,AutoForwardingMode" % ps(obj))]
    if kind in ("section", "group_section") and obj:
        # GROUPS-009 'Membership not read: <address>' ('<Kind> membership cmdlet failed'): one group, read with the
        # cmdlet for its kind; any other GROUPS-009 or RULES-118 is a section the export could not read
        if kind == "group_section" and ("membership cmdlet failed" in ev or "@" in obj):
            gkind, ident = group_of(f, report, obj)
            return [members_step(gkind, ident, "the group's membership is read here; it failed in the export (%s)" % ev)]
        cmd = next((c for label, c in SECTION_CMDS if obj.startswith(label)), None)
        if cmd:
            if "%s" in cmd:
                cmd = cmd % (obj.split("/", 1)[1] if "/" in obj else "Sender")
            return [step("command", "%s: the cmdlet the export could not run answers now, or fails with the reason "
                                    "(%s)." % (EXO, ev), cmd)]
    if fid.endswith("-000"):
        steps = idless_steps(f, report, section)
        if steps:
            return steps
    cmd = script_command(report, section)
    if cmd:
        return [step("command", "Run the %s export again and pick the finding: it shows %s %s (%s)." % (
            section, fid or "the finding", f.get("title") or "", ev or "no evidence recorded"),
            "%s | Where-Object { $_.id -eq %s } | Format-List" % (cmd, ps_quote(fid)))]
    return [step("command", "No check is known for %s; the finding's evidence: %s." % (fid or "this finding", ev or "none"))]


# ------------------------------------------------------------------ findings

def finding_domain(f):
    """The audited domain a finding is about (a DNS finding), else None."""
    src = str(f.get("source") or "")
    if src.startswith("dns:"):
        return _name(src[4:])
    if not src and f.get("domain"):
        return _name(f.get("domain"))
    return None


def finding_steps(finding, report):
    """The read-only checks for one finding (an entry of report["findings"],
    which carries its source), in the order a person runs them. A finding
    nothing here knows, or one whose report lacks the section to check it
    against, gets one step quoting what the audit saw."""
    f, report = _d(finding), _d(report)
    src = str(f.get("source") or "")
    fid = str(f.get("id") or "")
    domain = finding_domain(f)
    steps = []
    if domain is not None:
        steps = dns_finding_steps(f, domain, report)
    elif src == "maillog" or (not src and fid.startswith("MAILFLOW-")):
        steps = maillog_finding_steps(f, report)
    elif src == "rua" or (not src and fid.startswith("OUTSIDE-")):
        steps = rua_finding_steps(f, report)
    elif src.startswith("headers:") or (not src and f.get("file")):
        steps = header_finding_steps(f, report)
    elif src in audit.TENANT_SECTIONS or fid in TENANT_KIND:
        steps = tenant_finding_steps(f, report)
    return steps or [step("command", "No check is known for %s from %s in this report; the finding's evidence: %s." % (
        fid or "this finding", src or "an unnamed source", f.get("evidence") or "none recorded"))]


def first_check(finding, report):
    """The one-line check report.md shows under a finding: the first step's
    command when it is one line (a lookup's first line), else its sentence."""
    steps = finding_steps(finding, report)
    if not steps:
        return None
    s = steps[0]
    code = str(s.get("code") or "")
    line = code.splitlines()[0] if code and (s["how"] == "dns" or "\n" not in code) else ""
    if line and "`" not in line:
        return "`%s`" % line
    return s["text"]


# ------------------------------------------------------------------ plan rows

def _ttl_seen(report, domain, host):
    """The TTL the audit's own lookup of host carried, or None."""
    for e in _l(_d(_d(report.get("dns")).get(domain)).get("evidence")):
        if isinstance(e, dict) and _name(e.get("name")) == host and e.get("type") == "TXT" and _n(e.get("ttl")):
            return _n(e.get("ttl"))
    return None


def _no_mail(change):
    text = " ".join([str(change.get("why") or ""), str(change.get("human_summary") or "")]
                    + [str(p) for p in _l(change.get("prerequisites"))])
    return bool(re.search(r"\bno mail\b|\bsends? nothing\b|\bnothing (?:is )?sent\b", text, re.I))


def _header_from_says(report, domain, sends="it is not unused"):
    """(what the aggregate reports' header_from table shows for domain, rows to print): its row's passing count,
    or no row - which proves nothing for a name no record with rua covers yet."""
    row, top = header_from_row(report, domain)
    if row is not None:
        n = _n(row.get("pass")) or 0
        return ("lists %s with pass %d: %s" % (domain, n, "something sends as it, so " + sends if n else
                                               "no receiver saw passing mail as it"), top)
    doc = _d(_d(report.get("dns")).get(domain))
    if not doc.get("dmarc"):  # no record, no rua: no report can name it yet, so its silence there proves nothing
        return ("has no row for %s, but no receiver reports on it until a record with rua covers it: re-check a week "
                "after its record is published" % domain, top)
    if plan_mod.aggregate_volume(report, domain, doc)[0]:  # the plan's own test of what the reports cover
        return "has no row for %s: the reports cover the record that applies to it and name no mail as it" % domain, top
    return ("has no row for %s, but none of the reports this run read is about the record that applies to it (its rua "
            "sends them to another mailbox, or none arrived), so its silence there proves nothing" % domain, top)


def _sent_as(report, domain):
    """'the run measured outbound 0 and inbound 3' from report.mailflow, or 'this run did not measure it'."""
    counts = _d(_d(report.get("mailflow")).get("domains")).get(domain)
    if not isinstance(counts, dict):
        return "this run did not measure it"
    return "the run measured outbound %d and inbound %d" % (_n(counts.get("outbound")) or 0, _n(counts.get("inbound")) or 0)


def unused_steps(report, domain):
    """The proof that a parked domain is unused: nothing sent as it in the tenant's mail flow, no MX (it receives
    nothing either), and no passing mail as it in the aggregate reports."""
    steps = []
    if _ok(domain):
        steps.append(kql_step("mailflow", org_of(domain), "the row with d %s is missing or shows outbound 0: nothing "
                                                          "left the tenant as it in 30 days (%s; any inbound is a vendor "
                                                          "or a spoof, which only a person can tell apart)." % (
                                                              domain, _sent_as(report, domain))))
        r = _d(_d(report.get("dns")).get(domain))
        mx = ", ".join(str(m) for m in _l(r.get("mx"))) or "none"
        steps.append(step("dns", "Look up the MX records of %s: none, or only the null MX 0 ., as the audit saw (%s): the "
                                 "domain receives no mail." % (domain, mx), lookup(domain, "MX", https=True)))
    says, top = _header_from_says(report, domain)
    cmd = rua_command(report, top)
    if cmd:
        steps.append(step("command", "Re-read the aggregate reports: the header_from domains table %s." % says, cmd))
    else:
        steps.append(step("command", "This run read no aggregate reports; once they flow, the header_from domains table "
                                     "of rua_parse.py must show no passing mail as %s." % domain,
                          "python src/rua_parse.py audit-out/rua"))
    return steps


def no_mail_steps(report, domain):
    """The proof behind a no-mail-measured row (quarantine now, and reject a
    week later): nothing sent as the domain in the tenant's mail flow, no
    passing message as it in its mail-log rows, and no passing volume as it
    in the aggregate reports. Unlike a parked domain it may receive mail, so
    an MX is no part of the proof, and what came in as it and failed is the
    spoofing enforcement stops."""
    if not _ok(domain):
        return []
    steps = [kql_step("mailflow", org_of(domain), "the row with d %s is missing or shows outbound 0: nothing left the "
                                                  "tenant as it in 30 days (%s); inbound mail is allowed here, since the "
                                                  "domain may receive mail, and what came in as it and failed is the "
                                                  "spoofing quarantine stops." % (domain, _sent_as(report, domain)))]
    c = _buckets(report).get(domain)
    if c is not None:
        steps.append(kql_step("sender_census", domain, "the passing column adds up to 0: no message as %s passed DMARC "
                                                       "(the report's own rows: %d passing and %d sent inside the tenant, "
                                                       "of %d); a row with passing above 0 is a sender, so stop and find "
                                                       "it before publishing; %s." % (
                                                           domain, _n(c.get("passing_messages")) or 0,
                                                           _n(c.get("internal_messages")) or 0,
                                                           _n(c.get("logical_messages")) or 0,
                                                           window_note(report, domain, 30))))
    hours, wt = full_window(report, domain)
    if wt is not None:  # the rows kept are a floor: the full window says whether anything passed outside them
        steps.append(kql_step("maillog_totals", org_of(domain), "in the rows for fromdom %s, passing reads 0 over the "
                                                                "full window, as collect.py counted it in Advanced "
                                                                "Hunting (maillog.window_totals: about %d logical "
                                                                "messages, %d passing) over %s; passing above 0 is a "
                                                                "sender outside the rows the run kept." % (
                                                                    domain, _n(wt.get("logical_messages")) or 0,
                                                                    _n(wt.get("passing")) or 0,
                                                                    full_window_span(hours))))
    says, top = _header_from_says(report, domain, "it is not quiet")
    cmd = rua_command(report, top)
    if cmd:
        steps.append(step("command", "Re-read the aggregate reports: the header_from domains table %s." % says, cmd))
    return steps


def dkim_proof_steps(report, domain, lookups=True):
    r = _d(_d(report.get("dns")).get(domain))
    sels = [s for s in _l(r.get("dkim_selectors")) if s] or ["selector1", "selector2"]
    names = [n for n in ("%s._domainkey.%s" % (s, domain) for s in sels) if _ok(n)][:4]
    steps = [header_step(domain)]
    if names and lookups:
        steps.append(step("dns", "Look up the selector%s the audit found or Microsoft 365 uses: each answers with a key "
                                 "(TXT with p=) or a CNAME to one." % ("" if len(names) == 1 else "s"), lookup(names)))
    if _ok(org_of(domain)):
        steps.append(kql_step("dkim_alignment", org_of(domain), "over the last 30 days no sender as %s shows spf_only "
                                                                "above 0: each passing message was carried by DKIM, or "
                                                                "by both." % domain))
    return steps


def prerequisite_steps(change, report):
    """The query or lookup that proves each prerequisite needing evidence."""
    domain = _name(change.get("domain"))
    items = [i for i in _l(change.get("prerequisite_items")) if isinstance(i, dict)] or [
        {"text": str(p), "kind": plan_mod.prereq_kind(str(p))} for p in _l(change.get("prerequisites"))]
    steps, done = [], set()
    streams = len(_l(_d(report.get("rua")).get("failing_streams")))
    parked = str(change.get("kind") or "") == "park"
    no_mail = not parked and _no_mail(change)

    def once(kind, more):
        if kind not in done:
            done.add(kind)
            steps.extend(more)

    for item in items:
        text, kind = str(item.get("text") or ""), str(item.get("kind") or "")
        if re.search(r"SPF-only|no aligned-DKIM evidence", text):
            kind = "dkim_proof"
        if "send nothing of ours" in text and _ok(domain):
            # the sp= step: subdomains whose failing mail the run cannot call spoofing on a strong sign - a vendor
            # sending as one of them unaligned fails the same way, so a person says which sends for you
            once("doubt", [kql_step("subdomain_health", org_of(domain), "every subdomain the check names shows only "
                                    "failures you can name as spoofs: compare the envelope and signing domains behind "
                                    "them (the census, and the by_source_ip table of the aggregate reports) with your "
                                    "vendors', since a vendor sending as the subdomain unaligned fails the same way; "
                                    "one that sends for you gets a record of its own before sp= moves.")])
            continue
        if "failed in the aggregate reports outside a stream labelled likely_spoof" in text:
            # a quiet domain: failing report volume nothing marks as spoofing (under the stream floor, or
            # authenticated for another domain), which a vendor would produce the same way
            rows = len(_l(_d(report.get("rua")).get("by_source_ip")))
            once("report_doubt", [step("command", "Re-read the aggregate reports: in the by_source_ip table every "
                                                  "source that fails as %s is one you can name as a spoof - no DKIM "
                                                  "signature and no SPF pass on its mail - and not a vendor signing with "
                                                  "its own domain or passing SPF for its own envelope." % domain,
                                       rua_command(report, rows) or "python src/rua_parse.py audit-out/rua")])
            continue
        if re.search(r"mails less often than this run's evidence reaches back|a week of aggregate reports about", text):
            # a subdomain that mails quarterly or yearly shows nowhere in 30 days of evidence, or in a few days of
            # reports about the record: only a longer span, or the sending platforms themselves, can show it
            once("longer", [step("command", "Read a longer span than this run's: every aggregate report in the archive "
                                            "about %s's record (no --since; the span the check names is theirs, not "
                                            "the whole mailbox's), and the sending platforms' own logs; a subdomain "
                                            "that mails quarterly or yearly shows there or nowhere, and gets a record "
                                            "of its own before the subdomains move." % domain,
                                 "python src/rua_parse.py audit-out/rua")])
            continue
        if text.startswith("the mail as ") and "cannot call spoofing sends nothing of ours" in text and _ok(domain):
            # the ramp: this domain's own failures the run cannot call spoofing on a strong sign (a vendor sending as
            # it unaligned fails the same way), which the step would junk or refuse: a person names each source first
            rows = len(_l(_d(report.get("rua")).get("by_source_ip")))
            once("own_doubt", [kql_step("sender_census", domain, "every envelope domain with genuine_failures above 0 "
                                                                 "is a source you can name as a spoof, not a vendor "
                                                                 "sending as %s unaligned (its invoices, statements or "
                                                                 "payroll from its own envelope); %s."
                                        % (domain, window_note(report, domain, 30))),
                               step("command", "Re-read the aggregate reports: in the by_source_ip table every source "
                                               "that fails as %s is one you can name as a spoof - no DKIM signature and "
                                               "no SPF pass on its mail - and not a vendor signing with its own domain "
                                               "or passing SPF for its own envelope." % domain,
                                    rua_command(report, rows) or "python src/rua_parse.py audit-out/rua")])
            continue
        if "has no rows for it" in text and _ok(domain):
            # the gate's no-rows rule, carried on the row: nothing this run read is about the domain
            once("rows", [step("command", "Supply evidence that covers %s: pull its mail log (collect.py, or "
                                          "queries/raw_maillog.kql with sender_domain set to it) and read the aggregate "
                                          "reports its rua= receives; the gate judged it insufficient_data on the same "
                                          "absence." % domain, "python src/collect.py %s" % domain)])
            continue
        if re.search(r"cannot call spoofing|outside the mail-log rows kept", text) and _ok(domain):
            # mail that came in as a quiet domain which the labels cannot call spoofing, or that the rows kept
            # missed: a person names each source before the record moves
            once("unclear", [kql_step("sender_census", domain, "every envelope domain with genuine_failures or "
                                                               "no_verdict above 0 is a source you can name as a "
                                                               "spoof, not a sender of ours, and passing stays 0 on "
                                                               "every row - the plan asks this of the messages the "
                                                               "mail log could not call spoofing, or did not keep; "
                                                               "%s." % window_note(report, domain, 30))])
            continue
        m = DESTINATION_RX.search(text)
        if m and _ok(m.group(1)):
            # a rua address in another organization: receivers send to it only when its domain says they may
            once("destination", [step("dns", "Look up %s: an answer starting with v=DMARC1 - published at that name, "
                                             "or by a wildcard *._report._dmarc.%s - means receivers send the record's "
                                             "aggregate data to the new address; no answer means they drop it, so have "
                                             "%s publish it first." % (m.group(1), m.group(2), m.group(2)),
                                      lookup(m.group(1), https=True))])
            continue
        if kind == "verify_unused":
            once("unused", unused_steps(report, domain))
        elif kind == "dkim_proof":
            once("dkim", dkim_proof_steps(report, domain, "_domainkey" not in str(change.get("hostname") or "")))
        elif kind == "spf_budget" and _ok(domain):
            r = _d(_d(report.get("dns")).get(domain))
            once("spf", [step("command", "Count the SPF lookups: the lookups line shows at most 9 / 10 (the audit counted "
                                         "%s)." % (_n(r.get("spf_lookups")) if _n(r.get("spf_lookups")) is not None
                                                   else "none"), "python src/spf_lookups.py %s" % domain)])
        elif kind == "evidence" and _ok(domain):
            more = [kql_step("genuine_failures", domain, "every row left is a sender you can name as a spoof, the "
                                                          "deduplicated failure check over the last 7 days that the gate "
                                                          "asks for before a step.")]
            if rua_command(report):  # every failing stream is read, so the whole table is printed
                more.append(step("command", "Re-read the aggregate reports: no failing stream sending as %s is labelled "
                                            "other than likely_spoof, unless audit.toml formally excepts it." % domain,
                                 rua_command(report, streams)))
            once("evidence", more)
        elif kind == "reports" and rua_command(report):
            if re.search(r"nothing passing|outside recipients", text) and no_mail and _ok(domain):
                once("no_mail", no_mail_steps(report, domain))  # the no-mail proof reads that table, with the rest
                continue
            if re.search(r"as a subdomain\b.*outside recipients", text):  # the sp= step: its subdomains' mail
                doc = _d(_d(report.get("dns")).get(domain))
                rows = _l(_d(report.get("rua")).get("by_header_from"))
                says = ("no header_from row for a subdomain of %s shows a passing count unless that subdomain has a "
                        "record of its own%s" % (domain, "" if doc.get("dmarc") and plan_mod.aggregate_volume(
                            report, domain, doc)[0] else "; the reports this run read are not about its record (its "
                            "rua sends them to another mailbox, or none arrived), so read the reports that reach the "
                            "address in its rua= tag"))
                top = len(rows)
            elif re.search(r"nothing passing|outside recipients", text):  # a domain that should send nothing
                says = "the header_from domains table shows no passing count for %s" % domain
                top = header_from_row(report, domain)[1]
            else:
                says = "the header_from rows for %s and its subdomains fail only from streams labelled likely_spoof" % domain
                top = max([streams] + [i + 1 for i, h in enumerate(_l(_d(report.get("rua")).get("by_header_from")))
                                       if isinstance(h, dict) and (_name(h.get("domain")) == domain
                                                                   or _name(h.get("domain")).endswith("." + domain))])
            once("reports", [step("command", "Re-read the aggregate reports over the last week: %s." % says,
                                  rua_command(report, top))])
        elif kind == "list_proof" and _ok(domain):
            once("list", [kql_step("delivered_twin", domain, "every row's verdict reads echo (a delivered twin exists); a "
                                                             "true loss is a list or forwarder path still failing.")])
        elif kind == "other" and "sender inventory" in text and _ok(domain):
            once("inventory", [kql_step("sender_census", domain, "every envelope domain with real volume over the last "
                                                                 "30 days is a sender you know, and the SPF record "
                                                                 "names each one that sends on SPF.")])
        elif "_dmarc record" in text and _ok(domain):
            # the sending subdomains the prerequisite names (audited or not), the unaudited ones whose own record DNS
            # showed in this run (report.dns_extra: the plan counts them as covered), then the audited ones
            seen = audit.order_domains([n for n, x in plan_mod.dns_extra(report).items()
                                        if n.endswith("." + domain) and plan_mod.has_own_record(n, x)])
            named = re.findall(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+", text.lower()) + seen + _names_in_order(report, [], [])
            # the first six named, looked up in the one order every list of names follows (one organization's)
            subs = audit.order_domains([s for s in dict.fromkeys(named)
                                        if s.endswith("." + domain) and _ok("_dmarc." + s)][:6])
            have = [s for s in subs if s in seen]
            if subs:
                once("own_records", [step("dns", "Look up the subdomains' own records: each answers with a v=DMARC1 "
                                                 "string of its own once the plan's record for it is published%s." % (
                                                     "; %s %s already: DNS showed %s in this run" % (
                                                         audit._names(have), "answers" if len(have) == 1 else "answer",
                                                         "its own record" if len(have) == 1 else "their own records")
                                                     if have else ""),
                                          lookup(["_dmarc." + s for s in subs]))])
    # a row that rests on no mail being sent as the domain: a parked one proves it unused (no MX either), a
    # no-mail-measured one proves nothing is sent as it - it may receive mail, so its MX proves nothing
    if parked and _ok(domain):
        once("unused", unused_steps(report, domain))
    elif no_mail and _ok(domain):
        once("no_mail", no_mail_steps(report, domain))
    return steps


def change_steps(change, report):
    """Before, publish, after and roll back for one plan row (plan.json
    "changes"), then the proof each prerequisite needing evidence asks for."""
    c, report = _d(change), _d(report)
    domain = _name(c.get("domain"))
    host = _name(c.get("hostname"))
    rtype = str(c.get("record") or "TXT").upper()
    value, current = str(c.get("value") or ""), str(c.get("current") or "none")
    ttl = _n(c.get("ttl"))
    task = "<" in value or "<" in host  # a placeholder: a task to do, not a record to paste
    dmarc = host.startswith("_dmarc.")
    spf = value.lower().startswith("v=spf1") or current.lower().startswith("v=spf1")
    what = "the answer starting with v=DMARC1" if dmarc else ("the TXT string starting with v=spf1" if spf
                                                              else "the answer")
    head = "v=DMARC1" if dmarc else "v=spf1" if spf else "the new value"
    # the current value: none (nothing published), a record, or words saying nobody looked - a name the run does
    # not audit ('not checked (not an audited domain)'), which is unknown, never a record to expect or restore
    absent = current.strip().lower() in ("none", "")
    unknown = rtype == "TXT" and not absent and not current.strip().lower().startswith("v=")
    # a name whose own _dmarc lookup failed: an unaudited one collect.py looked up (report.dns_extra), or an audited
    # one the audit assumed inherits (DMARC-007)
    name = host[len("_dmarc."):]
    failed = dmarc and (_d(plan_mod.dns_extra(report).get(name)).get("status") == "error"
                        or plan_mod.own_lookup_failed(_d(_d(report.get("dns")).get(name))))
    steps = []
    if _ok(host) and rtype == "TXT":
        if absent:
            before = "Before: look up %s: no answer starts with %s today (current: none)." % (host, head)
        elif unknown:
            before = ("Before: look up %s: no answer should start with %s - %s (plan.json says: %s); if "
                      "one does, do not publish: %s." % (
                          host, head, "the run's own lookup of it failed" if failed else "the run did not look", current,
                          "%s already has a record of its own, and a second v=DMARC1 record would leave it with no policy "
                          "at all" % host[len("_dmarc."):] if dmarc else
                          "a second v=spf1 record makes every SPF check of the name fail (permerror), so change the "
                          "existing one instead" if spf else "compare what is there with the value below first"))
        else:
            before = "Before: look up %s: %s reads %s, the current value." % (host, what, _q(current))
        steps.append(step("dns", before, lookup(host, https=absent or unknown)))
    elif "_domainkey" in host and _ok(domain):
        names = ["selector1._domainkey." + domain, "selector2._domainkey." + domain]
        steps.append(step("dns", "Before: look up the Microsoft 365 selector names of %s: neither answers with a key "
                                 "today (other platforms use their own selector names)." % domain,
                          lookup(names, "CNAME")))
    where = c.get("zone_host") or "the DNS host"
    if c.get("zone"):
        where = "%s (zone %s)" % (where, c["zone"])
    if task:
        steps.append(step("portal", "Publish: this row is a task, not a record to paste - %s; the %s record at %s takes "
                                    "the value the task produces (%s)." % (c.get("why") or "see plan.md", rtype, host,
                                                                           value)))
    else:
        steps.append(step("portal", "Publish at %s: a %s record named %s with the value below, TTL %s." % (
            where, rtype, host, ttl if ttl is not None else "as plan.json says"), value))
    if _ok(host) and rtype == "TXT":
        seen = _ttl_seen(report, domain, host)
        if seen:
            wait = "up to %d seconds, the TTL on the answer the audit saw" % seen
        elif absent or unknown:
            wait = "the zone's negative-caching time, often an hour, for a name that had no record"
        else:
            wait = "the current record's TTL, which the audit did not record; an hour is common"
        if not task:
            after = _q(value)
        elif absent or unknown:
            after = "the record you published"
        else:
            after = "the record you published, and no longer %s" % _q(current)
        steps.append(step("dns", "After: wait out the TTL (%s), then run the same lookup: %s reads %s." % (
            wait, what, after), lookup(host)))
    elif "_domainkey" in host and _ok(domain):
        steps.append(step("dns", "After: once a platform's selector records are published and their TTL has passed, the "
                                 "selector names answer; for Microsoft 365 the two names below answer with the "
                                 "Selector1CNAME and Selector2CNAME targets Get-DkimSigningConfig names.",
                          lookup(["selector1._domainkey." + domain, "selector2._domainkey." + domain], "CNAME")))
        steps.append(m365_dkim_steps(domain)[1])
    rollback = str(c.get("rollback") or "")
    if rollback:
        verbatim = "verbatim" in rollback and not (absent or unknown)
        steps.append(step("portal", "Roll back: %s%s." % (rollback, " - the value below, as the Before lookup showed it"
                                                                    if verbatim else ""), current if verbatim else ""))
    steps += prerequisite_steps(c, report)
    return steps


# ------------------------------------------------------------------ the gate

REASON_IDS = (
    (re.compile(r"failed with no passing copy"), ("MAILFLOW-001",), "the mail-log checks in this section"),
    (re.compile(r"failed authentication but reached a mailbox"), ("MAILFLOW-002",), "the mail-log checks in this section"),
    (re.compile(r"in the mail log pass on SPF alone"), ("MAILFLOW-010",), "the SPF-only check in this section"),
    (re.compile(r"pass on SPF alone"), ("OUTSIDE-003",), None),
    (re.compile(r"^spoof stream |fails DMARC on \d+/\d+ msgs|failing stream\(s\) look like spoofs"), ("OUTSIDE-001",),
     None),
    (re.compile(r"msgs, [\w-]+\) excepted until"), ("OUTSIDE-001",), "its [[exceptions]] entry in audit.toml"),
    (re.compile(r"unaudited subdomain\(s\)"), (), "the unaudited-subdomains check in this section"),
    (re.compile(r"no mail-log rows for this domain"), (), "the mail-log checks in this section"),
    (re.compile(r"no aligned-DKIM evidence"), (), "the dkim_alignment query of its organization (queries/)"),
    (re.compile(r"^exception: |expired \S+ and blocks again|not applied: "), (), "its [[exceptions]] entry in audit.toml"),
    (re.compile(r"no failure evidence was supplied|has no rows for"), (),
     "the mail-log and aggregate-report checks in this section"),
    (re.compile(r"^(policy (is|p=)|step being gated|no DMARC policy could be determined)"), (), "the policy check above"),
)


def reason_checks(reason, domain, report, places):
    """Where to check one gate reason: the findings behind it (with the
    section their steps are in) and the checks in this domain's section."""
    text = reason[len(domain) + 2:] if reason.startswith(domain + ": ") else reason
    ids, also = [], None
    for f in _l(_d(_d(report.get("dns")).get(domain)).get("findings")):
        if isinstance(f, dict) and f.get("title") == text:
            ids.append(str(f.get("id")))
    m = re.match(r"^(rules|bypasses|groups): (.+) - unauthenticated mail is delivered past the policy$", text)
    if m:
        ids += [str(f.get("id")) for f in _l(_d(report.get(m.group(1))).get("findings"))
                if isinstance(f, dict) and f.get("title") == m.group(2)]
    if not ids:
        for rx, found, where in REASON_IDS:
            if rx.search(text):
                ids, also = list(found), where
                break
    shown_ids = ["%s (%s)" % (i, places.get(i, "Across the run")) for i in dict.fromkeys(ids) if i in places]
    parts = shown_ids + ([also] if also else [])
    return "; ".join(parts) if parts else "no finding behind it: the gate's own reasoning over the evidence"


def policy_step(report, domain):
    """What the gate read the domain's policy from: the live record, or the
    aggregate reports. A lookup that failed is said to have failed, never
    read as an answer, and points to the finding whose steps settle it."""
    r = _d(_d(report.get("dns")).get(domain))
    if r and _ok(domain):
        src = _name(r.get("dmarc_source"))
        src = src if _ok(src) else "_dmarc." + domain
        own = "_dmarc." + domain
        ids = {str(f.get("id")) for f in _l(r.get("findings")) if isinstance(f, dict)}
        if r.get("dmarc") and r.get("inherited") and "DMARC-007" in ids:
            return step("dns", "Policy today: the audit's lookup of %s failed, so the gate read the record at %s, which "
                               "reads %s, and assumed %s inherits it - not verified: the DMARC-007 steps below look %s up "
                               "through two public resolvers, and an answer starting with v=DMARC1 there is the policy "
                               "instead." % (own, src, _q(r["dmarc"]), domain, own),
                        lookup([own, src], servers=RESOLVERS, https=True))
        if r.get("dmarc"):
            return step("dns", "Policy today: look up %s: the answer starting with v=DMARC1 reads %s%s." % (
                src, _q(r["dmarc"]), " (%s has no record of its own and inherits it)" % domain
                if r.get("inherited") else ""), lookup(src))
        if r.get("dmarc_status") == "error" or "DMARC-006" in ids:
            names = [n for n in dns_audit.dmarc_candidates(domain) if _ok(n)] or [own]
            return step("dns", "Policy today: unknown - the audit's DMARC lookups for %s failed on every path, so the gate "
                               "read no policy and assumed none; the DMARC-006 steps below look the names up through two "
                               "public resolvers, and an answer from either settles it." % domain,
                        lookup(names, servers=RESOLVERS, https=True))
        return step("dns", "Policy today: look up _dmarc.%s: no answer starts with v=DMARC1, as the audit saw." % domain,
                    lookup("_dmarc." + domain, https=True))
    g = _d(_d(_d(report.get("gate")).get("domains")).get(domain))
    cmd = rua_command(report)
    if cmd and str(g.get("policy_source") or "").startswith("aggregate reports"):
        return step("command", "Policy as the receivers saw it (this run had no live DNS): the policy published line for "
                               "%s shows p=%s (%s)." % (domain, g.get("current_policy") or "?", g.get("policy_source")),
                    cmd)
    return None


# ------------------------------------------------------------------ the document

# a finding the plan holds a domain for, recognised in the hold's own words
HOLD_IDS = {"DMARC-005": re.compile(r"two DMARC records"), "SPF-005": re.compile(r"10-lookup limit"),
            "DMARC-006": re.compile(r"could not be verified"), "SPF-002": re.compile(r"could not be verified"),
            "SPF-007": re.compile(r"SPF record|could not be resolved|lower bound")}
# a hold an older plan worded for another finding than the one the audit raised (plan.py now holds SPF-007 as the
# unresolved include it is): what the check there shows instead
HOLD_NOTES = {"SPF-007": ": SPF-007 is an include the audit could not resolve, not a second record, and the TXT lookup "
                         "there shows how many strings start with v=spf1"}
# what collect.py's lookup of an unaudited name's own _dmarc record saw (report.dns_extra), by status
EXTRA_SAW = {"found": "DNS showed a record of its own there", "absent": "DNS showed no record there",
             "error": "the lookup failed, so the plan asks for it to be looked up first"}


def _steps_md(L, steps):
    """Numbered steps; a command in a fenced block under its step (a value to paste into a DNS console as text). A
    query is named by its file, listed under Queries for the portal, and not repeated here."""
    for i, s in enumerate(steps, 1):
        code = str(s.get("code") or "").replace("\r\n", "\n").rstrip("\n")
        # a command step with nothing to run is a pointer or a fact: a note
        label = "Note" if s.get("how") == "command" and not code else HOW_LABEL.get(s.get("how"), "Check")
        L.append("%d. %s: %s" % (i, label, s.get("text") or ""))
        if code and s.get("how") != "kql":
            pad = " " * (len(str(i)) + 2)
            L.append(pad + "```" + ("text" if s.get("how") == "portal" else "powershell"))
            L += [pad + line if line else "" for line in code.split("\n")]
            L.append(pad + "```")
    L.append("")


def _finding_head(f, level="####"):
    return "%s [%s] %s - %s%s" % (level, f.get("severity") or "?", f.get("id") or "?", f.get("title") or "",
                                  "" if f.get("verified", True) else " (not verified)")


def _names_in_order(report, changes, holds, headline=None):
    """Every name the run audits or the plan names, each once, in the one order
    every list of names follows (audit.domain_key: the headline's
    organization first, each organization's own domain before the names
    below it)."""
    names = [_name(d) for d in _l(_d(report.get("inputs")).get("domains"))]
    names += [_name(d) for d in _d(_d(report.get("gate")).get("domains"))]
    names += [_name(d) for d in _d(report.get("dns"))]
    names += [_name(c.get("domain")) for c in changes] + [_name(h.get("domain")) for h in holds]
    return audit.order_domains(names, headline)


def _orgs(names, headline=None):
    """The organizations of names, in that same order."""
    return audit.order_domains({org_of(d) for d in names if _ok(d) and _ok(org_of(d))}, headline)


def build(report, plan=None):
    """(verify.md text, {relative path: query text}) for one report and plan."""
    report = _d(report)
    plan = plan if isinstance(plan, dict) else None
    findings = [f for f in _l(report.get("findings")) if isinstance(f, dict)]
    changes = [c for c in _l((plan or {}).get("changes")) if isinstance(c, dict)]
    holds = [h for h in _l((plan or {}).get("holds")) if isinstance(h, dict)]
    # one section per name, in the order the status document's own lists follow; each section's plan rows keep
    # the plan's order
    headline = next_steps.headline_org(report)
    names = _names_in_order(report, changes, holds, headline)
    mine = {}
    for f in findings:
        d = finding_domain(f)
        if d:
            mine.setdefault(d, []).append(f)
    names = audit.order_domains(names + [d for d in mine if d not in names], headline)
    across = [f for f in findings if not finding_domain(f)]
    places = {str(f.get("id")): "Across the run" for f in across}
    gates = _d(_d(report.get("gate")).get("domains"))
    inp = _d(report.get("inputs"))
    # the names the run audits; any other name has a section only because the plan names it
    audited = {_name(d) for d in _l(inp.get("domains"))} | {_name(d) for d in gates} | {
        _name(d) for d in _d(report.get("dns"))}
    extra = plan_mod.dns_extra(report)  # the unaudited names whose own _dmarc record collect.py looked up

    L = ["# Verify it yourself", ""]
    when = _stamp(report.get("generated_utc"))
    L.append("%sReport generated %s UTC (%s). For every finding and every plan row in this run, the checks below say "
             "where to look and what you should see, so each number and each record can be defended without trusting "
             "the toolkit." % ("Run %s. " % inp["run"] if inp.get("run") else "", when,
                               "offline, files only" if report.get("offline") else "live DNS and files"))
    L.append("")
    L.append("How to use this file:")
    L.append("")
    L.append("- Every check is read-only. DNS lookups go to public resolvers (%s, and %s where a second path settles a "
             "failed lookup; a lookup that shows something missing also asks over HTTPS, the path the toolkit falls back "
             "to when port 53 is filtered); queries run in your own Defender portal (security.microsoft.com > Hunting > "
             "Advanced hunting) under your own sign-in; the commands only read." % RESOLVERS)
    L.append("- PowerShell lines are for Windows; the nslookup line under a lookup works on any system. Run the python "
             "commands from the toolkit folder (the one holding src/), where the paths below resolve.")
    L.append("- Each query is saved next to this file under queries/ (listed at the end): a shipped query from the "
             "toolkit's queries/ with only its let sender_domain line set. Open it, paste it into the query editor and "
             "run it; it sets its own time window.")
    L.append("- Expected values are copied from this run's report.json and plan.json. A query counts up to the moment "
             "you run it, so small differences come from mail that arrived while the run was pulling and since, and from "
             "DMARC verdicts other than pass and fail (bestguesspass, for one), which the deduplication reads as a pass "
             "and the shipped queries do not; a DNS answer differs once someone has changed the record.")
    L.append("- report.md shows each finding's first check on its verify line; this file has all of them.")
    L.append("")
    L.append("## Contents")
    L.append("")
    for d in names:
        g = _d(gates.get(d))
        n_f = len(mine.get(d, []))
        n_c = sum(1 for c in changes if _name(c.get("domain")) == d)
        if d in audited or n_f:
            L.append("- %s: gate %s, %d DNS %s, %d plan %s" % (d, g.get("verdict") or "not judged", n_f,
                                                                _plural(n_f, "finding"), n_c, _plural(n_c, "row")))
        else:
            L.append("- %s: not audited (only the plan names it), %d plan %s" % (d, n_c, _plural(n_c, "row")))
    L.append("- Across the run: %d %s (aggregate reports, the mail log as a whole, headers, tenant configuration)"
             % (len(across), _plural(len(across), "finding")))
    L.append("- Queries for the portal")
    L.append("")

    for d in names:
        for f in mine.get(d, []):
            places.setdefault(str(f.get("id")), "%s, Findings" % d)
    for d in names:
        L.append("## %s" % d)
        L.append("")
        g = _d(gates.get(d))
        if g:
            L.append("Gate: **%s** - step being gated: %s." % (g.get("verdict") or "?", g.get("next_step") or "unknown"))
            L.append("")
            ps_step = policy_step(report, d)
            if ps_step:
                _steps_md(L, [ps_step])
            stmt = _d(_d(report.get("gate")).get("evidence")).get("statement")
            reasons = [str(r) for r in _l(g.get("reasons")) if r and r != stmt]
            if reasons:
                L.append("Each reason the gate gives, and where to check it:")
                L.append("")
                local = dict(places)
                for f in mine.get(d, []):
                    local[str(f.get("id"))] = "Findings below"
                L += ["- %s - check: %s" % (r, reason_checks(r, d, report, local)) for r in reasons]
                L.append("")
        elif d not in audited and d in extra:
            L.append("Not audited in this run: %s is not on the domain list, so no gate judged it and the run looked up "
                     "only its _dmarc record, for the plan's subdomain rule: %s; it has a section because the plan names "
                     "it." % (d, EXTRA_SAW[extra[d]["status"]]))
            L.append("")
        elif d not in audited:
            L.append("Not audited in this run: %s is not on the domain list, so its DNS was not looked up and no gate "
                     "judged it; it has a section because the plan names it." % d)
            L.append("")
        L.append("### Findings")
        L.append("")
        if not mine.get(d) and d not in audited and d in extra:
            L.append("None, and none looked for: %s is not audited, so this run looked up nothing but its _dmarc record "
                     "(add it to the domain list and the next run checks the rest)." % d)
            L.append("")
        elif not mine.get(d) and d not in audited:
            L.append("None, and none looked for: %s is not audited, so this run did not look up its DNS (add it to the "
                     "domain list and the next run checks it)." % d)
            L.append("")
        elif not mine.get(d):
            L.append("No DNS finding for %s in this run%s." % (d, "" if report.get("dns") else
                                                                " (no live DNS: an offline run looks nothing up)"))
            L.append("")
        for f in mine.get(d, []):
            L.append(_finding_head(f))
            L.append("")
            if f.get("evidence"):
                L.append("The audit saw: %s" % f["evidence"])
                L.append("")
            _steps_md(L, finding_steps(f, report))
        checks = maillog_steps(report, d)
        if checks:
            c = _buckets(report).get(d) or {}
            L.append("### Mail log")
            L.append("")
            L.append("The report counted %s's own rows: %d logical messages, %d passing, %d genuine failures, %d delivered "
                     "despite failing (maillog.by_domain; MAILFLOW findings for the whole log are under Across the run)."
                     % (d, _n(c.get("logical_messages")) or 0, _n(c.get("passing_messages")) or 0,
                        _n(c.get("genuine_failures")) or 0, _n(c.get("delivered_despite_fail")) or 0))
            L.append("")
            _steps_md(L, checks)
        census = census_steps(report, d) if d not in audited else []
        if census:
            L.append("### Mail log")
            L.append("")
            L.append("%s is not audited, so the mail log gives it no share of its own; the report's census counted its "
                     "messages (maillog.census; MAILFLOW findings for the whole log are under Across the run)." % d)
            L.append("")
            _steps_md(L, census)
        flow = mailflow_steps(report, d, d in audited)
        if flow:
            L.append("### Mail flow (tenant)")
            L.append("")
            _steps_md(L, flow)
        outside = rua_domain_steps(report, d)
        if outside:
            L.append("### Aggregate reports")
            L.append("")
            _steps_md(L, outside)
        rows = [c for c in changes if _name(c.get("domain")) == d]
        held = [h for h in holds if _name(h.get("domain")) == d]
        if rows or held or plan is not None:
            L.append("### Plan rows")
            L.append("")
            if not rows and not held:
                L.append("No plan row for %s in this run." % d)
                L.append("")
            for h in held:
                why = str(h.get("reason") or "")
                ids = [i for i in re.findall(r"\b[A-Z]{2,}-\d{3}\b", why)]
                ids += [str(f.get("id")) for f in mine.get(d, []) if str(f.get("id")) in HOLD_IDS
                        and HOLD_IDS[str(f.get("id"))].search(why)]
                pointer = ", ".join("%s (Findings above%s)" % (i, HOLD_NOTES[i] if i in HOLD_NOTES and re.search(
                    r"more than one SPF record", why) else "") for i in dict.fromkeys(ids))
                L.append("- Held, not proposed: %s%s" % (why, " - check: %s" % pointer if pointer else ""))
            if held:
                L.append("")
            for c in rows:
                kind = c.get("kind") if isinstance(c.get("kind"), str) else ""  # a damaged kind reads as a change
                L.append("#### %s %s: %s %s (priority %s)" % (c.get("id") or "?", plan_mod.KIND_LABEL.get(
                    kind, kind or "change"), c.get("record") or "?", c.get("hostname") or "?",
                    c.get("priority") if c.get("priority") is not None else "?"))
                L.append("")
                if c.get("human_summary"):
                    L.append("In plain words: %s" % c["human_summary"])
                    L.append("")
                pre = [str(p) for p in _l(c.get("prerequisites"))]
                if pre:
                    L.append("Before applying (plan.json prerequisites):")
                    L += ["- %s" % p for p in pre]
                    L.append("")
                if c.get("finding_ids"):
                    L.append("It answers %s (Findings above)." % ", ".join(str(i) for i in _l(c.get("finding_ids"))))
                    L.append("")
                _steps_md(L, change_steps(c, report))
        elif plan is None and report.get("dns"):
            L.append("No plan was supplied, so no plan rows are checked here.")
            L.append("")

    L.append("## Across the run")
    L.append("")
    L.append("Findings about the aggregate reports, the mail log as a whole, message headers and the tenant configuration, "
             "worst first.")
    L.append("")
    totals = totals_steps(report)
    if totals:
        L.append("The run's overall figures, the ones the status document quotes:")
        L.append("")
        _steps_md(L, totals)
    if not across:
        L.append("No finding of this kind in this run.")
        L.append("")
    for f in across:
        L.append(_finding_head(f, "###") + " (%s)" % audit._display_source(str(f.get("source") or "?")))
        L.append("")
        if f.get("evidence"):
            L.append("The audit saw: %s" % f["evidence"])
            L.append("")
        _steps_md(L, finding_steps(f, report))

    files = {}
    for org in _orgs(names, headline):
        for name in ORG_QUERIES:
            files[query_path(name, org)] = (name, org)
    for m in FILE_RX.finditer("\n".join(L)):
        files.setdefault("queries/%s_%s.kql" % (m.group(1), m.group(2)), (m.group(1), m.group(2)))
    texts = {}
    L.append("## Queries for the portal")
    L.append("")
    L.append("Each file sits under queries/ next to this one. It is a shipped query from the toolkit's queries/ with only "
             "its let sender_domain line set, the way collect.py sets it (mailflow_*.kql is the mail-flow aggregate "
             "collect.py runs, from src/discover.py). Open it, paste it into the query editor in %s, and run it; each "
             "sets its own window in its text (ago(30d), or ago(7d) for genuine_failures), so where the portal's time "
             "range control applies, set it to cover the same window." % PORTAL)
    L.append("")
    for path in sorted(files, key=lambda p: (audit.domain_key(files[p][1], headline), files[p][1], files[p][0])):
        name, domain = files[path]
        try:
            texts[path] = query_text(name, domain)
        except (OSError, ValueError) as err:
            L.append("- %s: not written (%s)" % (path, getattr(err, "strerror", None) or err))
            continue
        L.append("- %s, for %s: %s" % (path, domain, QUERIES[name][1]))
    L.append("")
    return "\n".join(L), texts


def render(report, plan=None):
    """The text of verify.md."""
    return build(report, plan)[0]


def write(report, plan, out_dir):
    """out_dir/verify.md and out_dir/queries/*.kql (each filled query keeps the
    shipped query's line endings, so it differs from it in one line only).
    Returns (the verify.md path, [query file paths])."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    text, queries = build(report, plan)
    paths = []
    if queries:
        (out / "queries").mkdir(exist_ok=True)
    for rel, body in sorted(queries.items()):
        p = out / rel
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        paths.append(p)
    mpath = out / "verify.md"
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return mpath, paths


# ------------------------------------------------------------------ cli

def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def _read(path, what):
    p = audit.repo_path(path)
    try:
        with open(p, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except OSError as err:
        die("cannot read %s %s: %s" % (what, p, err.strerror or err))
    except ValueError as err:
        die("%s %s is not JSON: %s" % (what, p, err))
    if not isinstance(doc, dict):
        die("%s %s is not one JSON object" % (what, p))
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="report.json from src/audit.py or src/collect.py")
    ap.add_argument("--plan", metavar="JSON", help="plan.json from src/plan.py or src/collect.py")
    ap.add_argument("--out", metavar="DIR", required=True, help="write verify.md and queries/ here")
    args = ap.parse_args(argv)
    report = audit.load_census(_read(args.report, "report"), args.report)  # a split census is read whole again
    if not isinstance(report.get("gate"), dict) and not report.get("inputs"):
        die("%s does not look like an audit report (no gate and no inputs section)" % audit.repo_path(args.report))
    plan = _read(args.plan, "--plan") if args.plan else None
    try:
        mpath, paths = write(report, plan, audit.repo_path(args.out))
    except OSError as err:
        die("cannot write to %s: %s" % (audit.repo_path(args.out), err.strerror or err))
    print("wrote %s" % mpath)
    print("wrote %d %s under %s" % (len(paths), _plural(len(paths), "query", "queries"), mpath.parent / "queries"))
    sys.exit(0)


if __name__ == "__main__":
    main()
