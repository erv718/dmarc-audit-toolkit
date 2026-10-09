#!/usr/bin/env python3
"""Turn an audit report into a rollout plan: the exact records to publish.

Input is report.json from src/audit.py (optionally plus inventory.json from
src/discover.py for the zone host of every domain). Output is plan.md, in the
Record / Hostname / Value table form a DNS change ticket wants, grouped by
where each zone is hosted, plus plan.json for tools.

The rules are the methodology, encoded (docs/methodology.md):

  monitoring first     no DMARC record, or a subdomain inheriting nothing:
                       publish p=none with rua before anything else. A record
                       without rua gets rua added; a record whose rua lacks
                       the run's report address (--rua: collect.py's
                       --rua-address, else its report mailbox) gets it
                       appended after the addresses already there, nothing
                       else changed: a zero-risk row of its own, never gated
                       on the reports it starts (a gated step on the record
                       waits a week for it), or inside the quarantine-now
                       row that rewrites the record anyway. Appended after
                       two addresses or more, it may get partial reports
                       (receivers need send to two only): the row says so.
                       A record that gains an address in another
                       organization, a new record too, waits on the
                       external-destination record that address's domain
                       must publish. Two records at one name get collapsed
                       - after an ownership check.
  SPF hygiene          no terminator or +all/?all becomes ~all; over the
                       lookup limit is a fix-first; at the limit is a freeze;
                       an include that does not resolve (the count is a lower
                       bound) holds any new sender until it resolves - looked
                       up again first, since the failure may be the run's own.
  parked domains       no mail in, no mail out, nothing signing: v=spf1 -all
                       and p=reject, once "unused" is verified. Verified
                       means the tenant measured no mail out and none in
                       over 30 days and aggregate reports that cover the
                       domain count no passing mail as it; otherwise the
                       row names the checks still open. Passing mail as it
                       in those reports means something sends: not parked.
  no mail measured     a domain the run measured sending nothing (no mail
                       out in 30 days of tenant mail flow, nothing passing,
                       internal, excepted or failing as our own system in
                       its mail-log rows, which examined all the mail that
                       came in as it, no passing volume in the aggregate
                       reports) skips the ramp: p=quarantine now, priority
                       1, and p=reject after a week of reports still showing
                       nothing passing, with no DKIM proof to wait for.
                       Failing inbound mail that looks like spoofing is what
                       enforcement stops; what the labels cannot call
                       spoofing is a check named on the row. A domain whose
                       mail the tenant does not carry (not a tenant domain,
                       or SPF or DKIM naming another platform) needs
                       aggregate reports that cover it. The parked rule
                       comes first when it applies.
  DKIM before reject   a domain that sends without a DKIM selector gets a
                       signing task before any enforcement step.
  one ratchet at a time
                       none -> quarantine pct=25 -> pct=100 -> reject ->
                       sp= -> SPF -all, each with the gate conditions the
                       report can and cannot prove; two rows that rewrite
                       one record from today's value say they are
                       alternatives for the week.
  subdomains           own records first, then sp=: with the apex at
                       quarantine (pct 100) or reject and sp=none, every
                       subdomain that sends or may send - in the tenant's
                       mail flow, the mail log or the aggregate reports,
                       audited or not, and an audited one whose mail out
                       was not measured - needs a _dmarc record of its own
                       before sp=quarantine; the plan proposes the missing
                       monitoring records and holds the step naming them.
                       Only DNS says a name has a record of its own: an
                       audited name's lookup, and for an unaudited one the
                       lookup collect.py made (report.dns_extra) - never the
                       policy an aggregate report says it saw. A name nobody
                       looked up, or whose lookup failed (an audited one's
                       too: DMARC-007), is named as not checked and its
                       record waits on a lookup first.
  evidence holds       a mail log or aggregate reports showing a legitimate
                       sender still failing holds that domain's next
                       enforcement step, and says why - unless the gate
                       formally excepted it (audit.toml [[exceptions]]).
  DKIM before reject   the move to p=reject is held when the run carries no
                       aligned-DKIM evidence at all, and when senders pass on
                       SPF alone (aggregate reports, or a mail log with SPF
                       and DKIM columns).

Every change also carries a plain-language layer for the next-steps document
(src/next_steps.py): owner_hint (the domain whose DNS the change touches),
human_summary (one sentence for a reader who does not read DNS) and
prerequisite_items (each prerequisite typed by what would prove it; met stays
null for the reader to decide). next_step_for(plan, domain) picks a domain's
pending enforcement step.

Nothing here changes DNS. Every change carries the current value and the
rollback so the human can apply and revert it.

  python src/plan.py audit-out/report.json --out audit-out
  python src/plan.py report.json --inventory exports/inventory.json --rua mailto:reports@example.com

Without --rua, new records take the rua most existing records use, and no
record gets an address appended: the run has no report address of its own.
"""

import argparse
import collections
import json
import re
import sys
from pathlib import Path

DEFAULT_TTL = 3600
RUA_PLACEHOLDER = "mailto:<your aggregate reports address>"
PCT_STEPS = (25, 50, 100)


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------
# helpers over the report

def dmarc_tags(record):
    """'v=DMARC1; p=none; rua=mailto:a' -> {'v': 'DMARC1', 'p': 'none', ...}"""
    tags = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def rua_of(record):
    return dmarc_tags(record).get("rua", "")


def with_rua(record, rua):
    """The same record with rua added or replaced, tag order preserved."""
    parts = [p.strip() for p in (record or "").split(";") if p.strip()]
    out, done = [], False
    for p in parts:
        if p.lower().startswith("rua="):
            out.append("rua=" + rua)
            done = True
        else:
            out.append(p)
    if not done:
        # rua goes right after the policy tags, before ruf if present
        idx = next((i for i, p in enumerate(out) if p.lower().startswith("ruf=")), len(out))
        out.insert(idx, "rua=" + rua)
    return "; ".join(out) + ";"


def _bare(address):
    """One rua address as the plan compares it: lower-cased, without mailto: and without a !size limit."""
    a = str(address or "").strip()
    a = a[len("mailto:"):] if a.lower().startswith("mailto:") else a
    return a.split("!", 1)[0].strip().lower()


def rua_addresses(record):
    """The addresses a record's rua= sends to, lower-cased, without mailto: and without a !size limit."""
    return [a for a in (_bare(part) for part in rua_of(record).split(",")) if a]


def has_address(record, uri):
    """True when the record's rua= already sends to the address of uri, whatever its case or size limit."""
    return _bare(uri) in rua_addresses(record)


REPORT_ADDRESS = re.compile(r"^(?:mailto:)?([^@\s,;!]+@[^@\s,;!]+)(![0-9]+[kmgt]?)?$", re.I)


def report_uri(address):
    """'mailto:name@example.com' for one report address given with or without
    mailto: (a !size limit kept), else None: a list of addresses, or none."""
    m = REPORT_ADDRESS.match(str(address or "").strip())
    return "mailto:" + m.group(1) + (m.group(2) or "") if m else None


def address_note(rua):
    """What a run says when its report address cannot be appended to a
    record's rua (a list of addresses, say); None when it can or there is
    none."""
    if not rua or report_uri(rua):
        return None
    return ("the report address %s is not one mailto: address: new records carry it as given, and no record gets it "
            "appended to its rua (give one address to have it appended)" % rua)


def add_rua(record, address):
    """The same record with address appended to its rua= list, after the
    addresses already there; every other character as it was. The rua= tag
    edited is the one dmarc_tags reads (the last, should a record carry two).
    A record with no rua tag gets one (with_rua)."""
    found = list(re.finditer(r"(?:^|;)\s*rua\s*=([^;]*)", record or "", re.I))
    if not found:
        return with_rua(record, address)
    m = found[-1]
    value = m.group(1)
    kept = value.rstrip()
    sep = "" if not kept.strip() or kept.endswith(",") else ","
    return record[:m.start(1)] + kept + sep + address + value[len(kept):] + record[m.end(1):]


def set_tag(record, key, value):
    """Set or replace one tag (p, sp, pct) in a DMARC record string."""
    parts = [p.strip() for p in (record or "").split(";") if p.strip()]
    out, done = [], False
    for p in parts:
        if p.lower().startswith(key + "="):
            out.append("%s=%s" % (key, value))
            done = True
        else:
            out.append(p)
    if not done:
        idx = 1 if out and out[0].lower().startswith("v=") else 0
        if key == "sp":
            idx = next((i + 1 for i, p in enumerate(out) if p.lower().startswith("p=")), idx)
        elif key == "pct":
            idx = next((i + 1 for i, p in enumerate(out) if p.lower().startswith(("sp=", "p="))), idx)
        out.insert(idx, "%s=%s" % (key, value))
    return "; ".join(out) + ";"


def drop_tag(record, key):
    """The same record without one tag (pct), tag order preserved."""
    parts = [p.strip() for p in (record or "").split(";") if p.strip()]
    return "; ".join(p for p in parts if not p.lower().startswith(key + "=")) + ";"


def spf_with_terminator(record, terminator):
    parts = (record or "").split()
    if parts and parts[-1].lower().lstrip("+-~?") == "all":
        parts[-1] = terminator
    else:
        parts.append(terminator)
    return " ".join(parts)


def spf_sends(spf_record):
    """True when the SPF record authorizes any sender (more than v=spf1 and a terminator)."""
    parts = [p for p in (spf_record or "").split() if p]
    return any(not p.lower().startswith("v=") and p.lower().lstrip("+-~?") != "all" for p in parts)


def finding_ids(dns_doc):
    return {f.get("id") for f in (dns_doc or {}).get("findings", []) if f.get("id")}


def derive_rua(dns_docs):
    """The rua address most of your existing records already use."""
    counts = collections.Counter()
    for d in dns_docs.values():
        rua = rua_of(d.get("dmarc"))
        if rua:
            counts[rua] += 1
    return counts.most_common(1)[0][0] if counts else None


def org_domain(name):
    labels = name.split(".")
    two = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
           "com.br", "com.mx", "co.za", "com.sg", "com.hk", "co.in", "co.kr", "com.tr", "com.ar"}
    if len(labels) > 2 and ".".join(labels[-2:]) in two:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def external_destination(domain, address):
    """The prerequisite a record needs when its rua sends to an address in
    another organization (RFC 7489 7.1): receivers deliver the record's
    aggregate data there only when the address's domain publishes the
    external-destination record for it. None for an address in the record's
    own organization, and for anything that is not an address (the
    placeholder)."""
    bare = _bare(address)
    host = bare.rpartition("@")[2].rstrip(".")
    if "@" not in bare or not re.match(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$", host):
        return None
    if org_domain(host) == org_domain(domain):
        return None
    return ('the external-destination record exists: receivers send %s\'s aggregate data to %s only when %s publishes '
            '%s._report._dmarc.%s TXT "v=DMARC1" (or a wildcard *._report._dmarc.%s); without it they drop the new '
            'address' % (domain, bare, host, domain, host, host))


def destinations(domain, value, current):
    """The external-destination prerequisites of a DMARC record a row
    publishes: one for every rua address it adds to the current record (each
    one, for a name with no record) that lies in another organization."""
    before = set(rua_addresses(current)) if str(current or "").lower().startswith("v=dmarc1") else set()
    out = []
    for a in rua_addresses(value):
        text = None if a in before else external_destination(domain, a)
        if text and text not in out:
            out.append(text)
    return out


def rua_order(current, address):
    """The prerequisite of a row that appends address to a record whose rua=
    already sends to two addresses or more: receivers need send to the first
    two only (RFC 7489 6.2), so the one appended after them may get nothing
    from some. None for a record with fewer."""
    n = len(rua_addresses(current))
    if n < 2:
        return None
    return ("decide the order of the rua addresses: receivers need send to the first two only (RFC 7489 6.2) and the "
            "record already lists %d, so %s, appended after them, may get no data from some receivers - list it among "
            "the first two (drop or move another), or accept partial data" % (n, _bare(address)))


def lookup_first(name):
    """The prerequisite of a record for a name whose own _dmarc record this run could not see."""
    return "look up _dmarc.%s first: publish only if it has no record" % name


# --------------------------------------------------------------------------
# evidence from the mail log and the aggregate reports

def _audited(report):
    """The audited names, as the gate keys them."""
    names = {str(x).lower() for x in ((report.get("inputs") or {}).get("domains") or [])}
    names |= {str(x).lower() for x in ((report.get("gate") or {}).get("domains") or {})}
    return names


def _home(name, audited):
    """The audited domain a sender domain belongs to: itself when audited,
    else its closest audited parent (the gate's rule), else None."""
    name = (name or "").lower().rstrip(".")
    if name in audited:
        return name
    return max((a for a in audited if name.endswith("." + a)), key=len, default=None)


def mailflow_of(report, inventory_row, domain):
    """The domain's measured mail flow ({"messages", "outbound", "inbound",
    "last_seen"}), from its inventory row, else from the report collect.py
    wrote (report.mailflow, measured on every run with a token); {} when
    neither measured it."""
    flow = (inventory_row or {}).get("mailflow")
    if not isinstance(flow, dict):
        mf = report.get("mailflow") if isinstance(report.get("mailflow"), dict) else {}
        doms = mf.get("domains") if isinstance(mf.get("domains"), dict) else {}
        flow = doms.get(domain)
    return flow if isinstance(flow, dict) else {}


# A parked candidate is verified unused only over a measurement this long (the methodology's 30 days).
UNUSED_DAYS = 30


def _measured(value):
    """A count as measured: a whole number >= 0, else None. A damaged count
    (text, a negative, a fraction) reads as not measured, never as zero."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def mailflow_days(report):
    """The days the measured mail flow covers: report.mailflow's (collect.py
    counts 30), None when that says nothing usable, and 30 without
    report.mailflow (discover.py --mailflow, the only other source of an
    inventory row's counts, measures 30 days). A shorter measurement never
    verifies a domain unused."""
    mf = report.get("mailflow")
    if isinstance(mf, dict):
        return _measured(mf.get("days"))
    return UNUSED_DAYS


def _name(value):
    return str(value or "").strip().lower().rstrip(".")


def _rows(value):
    """value when it is a list, else []: a damaged report section reads as an empty one."""
    return value if isinstance(value, list) else []


def aggregate_volume(report, domain, dns_doc):
    """What this run's aggregate reports say about mail sent as the domain:
    (covered, passing). covered: the run carries reports about the DMARC
    record that applies to the domain (its own, or the one it inherits), or
    reports that name it as the header From - so mail anyone sent as it to
    a receiver that reports would be counted there. A domain with no DMARC
    record is covered by no report. passing: the DMARC-passing messages
    they count with it as the header From."""
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else {}
    named, passing = False, 0
    for h in _rows(rua.get("by_header_from")):
        if isinstance(h, dict) and _name(h.get("domain")) == domain:
            named = True
            passing += _measured(h.get("pass")) or 0
    totals = rua.get("totals") if isinstance(rua.get("totals"), dict) else {}
    check = rua.get("policy_check") if isinstance(rua.get("policy_check"), dict) else {}
    about = {_name(d) for d in _rows(totals.get("domains"))}  # the records the reports are about
    about |= {_name(s.get("domain")) for s in _rows(check.get("seen")) if isinstance(s, dict)}
    source = _name((dns_doc or {}).get("dmarc_source"))  # where the record that applies was found: _dmarc.<name>
    record = source[len("_dmarc."):] if source.startswith("_dmarc.") else source
    return named or bool(record and record in about), passing


def unused_note(outbound, inbound, days, reports_cover):
    """A park row's prerequisite. 'verified unused: ...' only when every
    check it names was made: the tenant measured no mail out and none in
    over at least UNUSED_DAYS, and aggregate reports that cover the domain
    count no passing mail as it. Otherwise 'verify unused first: ...' with
    the checks still open - an inbound count is named, since only a person
    can tell a vendor sending as the domain from a spoof - and the owner
    objects, which nothing here checks. outbound, inbound: whole numbers
    measured over `days`, both None when not measured."""
    span = ("%d day%s" % (days, "" if days == 1 else "s")) if days else "an unknown span"
    open_checks = []
    if outbound is None:
        open_checks.append("no outbound mail in 30 days (discover.py --mailflow)")
    elif days is None or days < UNUSED_DAYS:
        open_checks.append("no outbound mail in 30 days (the tenant measured %s)" % (span + " only" if days else span))
    if inbound:
        open_checks.append("the %d inbound message(s) from it in %s are spoofs rather than a vendor sending as it"
                           % (inbound, span))
    if not reports_cover:
        open_checks.append("no passing volume in aggregate reports")
    if not open_checks:
        return "verified unused: no outbound mail in 30 days, no passing aggregate volume"
    return "verify unused first: " + ", ".join(open_checks + ["no owner objects"])


def _full_window(report, domain):
    """The domain's counts in the full-window totals collect.py took in
    advanced hunting for an organization its row budget or the API cap cut
    (maillog.window_totals: logical_messages, passing, genuine_failures ...);
    {} when the run carries none for it."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    wt = ml.get("window_totals") if isinstance(ml.get("window_totals"), dict) else {}
    orgs = wt.get("orgs") if isinstance(wt.get("orgs"), dict) else {}
    for org, info in orgs.items():
        org = _name(org)
        if not org or not (domain == org or domain.endswith("." + org)):
            continue
        by = info.get("by_domain") if isinstance(info, dict) else None
        counts = by.get(domain) if isinstance(by, dict) else None
        if isinstance(counts, dict):
            return counts
    return {}


# The mail flow's counts are advanced hunting estimates (dcount, a percent or two either way): a domain's
# mail-log rows that fall this share short of its inbound count still examined all of it.
ESTIMATE_SHARE = 0.02


def _cut(report, domain):
    """True when collect.py cut the mail log of the domain's organization in
    this run (maillog.cuts: the row budget, or an hour at the API cap), so
    its rows are a floor, not the window."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    cuts = ml.get("cuts") if isinstance(ml.get("cuts"), dict) else {}
    return any(org and (domain == org or domain.endswith("." + org)) for org in (_name(o) for o in cuts))


def _own_rows(report, domain):
    """The domain's own mail-log counters (maillog.by_domain), or None when
    the run read no mail log or the log was restricted to another domain."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else None
    if ml is None:
        return None
    scope = _name(ml.get("sender_domain"))
    by_dom = ml.get("by_domain")
    if (scope and domain != scope and not domain.endswith("." + scope)) or not isinstance(by_dom, dict):
        return None
    return by_dom.get(domain) if isinstance(by_dom.get(domain), dict) else None


def _unclear_senders(report, domain, cap=3):
    """[(sender, n)] for the census streams sending as the domain whose
    messages the labels do not call spoofing (failures labelled unknown,
    messages with no DMARC verdict), most first, at most cap of them."""
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    census = ml.get("census") if isinstance(ml.get("census"), dict) else {}
    out = {}
    for r in _rows(census.get("by_sender")):
        if not isinstance(r, dict) or _name(r.get("domain")) != domain:
            continue
        counts = r.get("likely_counts") if isinstance(r.get("likely_counts"), dict) else None
        spoof = (_measured(counts.get("likely_spoof")) if counts is not None
                 else (_measured(r.get("genuine_failures")) if r.get("likely") == "likely_spoof" else 0)) or 0
        n = (_measured(r.get("messages")) or 0) - spoof
        if n > 0:
            name = str(r.get("sender") or "?")
            out[name] = out.get(name, 0) + n
    return sorted(out.items(), key=lambda kv: (-kv[1], kv[0]))[:cap]


def quiet_evidence(report, domain, outbound, inbound, days, passing):
    """What the run MEASURED about the mail sent as the domain when that is
    nothing legitimate, so a weekly ramp would protect nobody; None
    otherwise (the ramp stays). Every condition: the tenant's mail flow over
    30 days counts no mail out (outbound 0); nothing passes as it in the
    aggregate reports (passing 0, also when they carry no rows for it), in a
    cut organization's full-window totals or in its own mail-log rows
    (maillog.by_domain), which also hold no internal message, no failure
    labelled as our own system and none a formal exception covers (an
    explained sender of ours); no aggregate-report stream as it looks like
    our own system; and the mail log examined the mail that came in with it
    as the From domain: its rows hold at least the mail flow's inbound
    messages (distinct Message-IDs, the mail flow's grain, when the report
    counts them) and its organization's log was not cut - or the full-window
    totals cover them. A run whose mail log examined only part of that mail
    (the row budget or the API cap cut it, a shorter window, no log)
    verifies nothing: what it did not see may pass. Inbound mail that fails
    and looks like spoofing is no reason to wait: it is what enforcement
    stops. What the labels cannot call spoofing is counted for the row to
    name, never called spoofing:
    {"inbound", "examined" (the logical messages the rows hold), "spoof",
    "unclear" (the rest: failures labelled unknown, messages with no DMARC
    verdict), "unclear_senders" [(sender, n)], "outside" (about how many came
    in outside the rows kept, counted only over the full window), "full"
    (the full-window totals cover the inbound mail, the rows do not)}."""
    if outbound != 0 or inbound is None or days is None or days < UNUSED_DAYS or passing:
        return None
    full = _full_window(report, domain)
    if (_measured(full.get("passing")) or 0) > 0 or _own_streams(report, domain):
        return None
    ev = {"inbound": inbound, "examined": 0, "spoof": 0, "unclear": 0, "unclear_senders": [], "outside": 0,
          "full": False}
    own = _own_rows(report, domain)
    if own is None:
        return None if inbound else ev  # nothing came in either: there is nothing for a mail log to tell apart
    by = own.get("by_likely") if isinstance(own.get("by_likely"), dict) else {}
    counts = [_measured(own.get(k, 0)) for k in ("logical_messages", "passing_messages", "internal_messages",
                                                 "excepted")]
    labels = [_measured(by.get(k, 0)) for k in ("likely_spoof", OWN_LABELS[0])]
    if None in counts + labels:  # damaged counts verify nothing, and could hide a passing message
        return None
    examined, passed, internal, excepted = counts
    spoof, ours = labels
    if passed or internal or ours or excepted:
        return None
    slack = int(inbound * ESTIMATE_SHARE)
    full_n = _measured(full.get("logical_messages"))
    # the rows' distinct messages, the mail flow's grain (a logical message is one per recipient), when counted
    ids = _measured(own.get("message_ids"))
    seen = examined if ids is None else ids
    if inbound and (_cut(report, domain) or seen + slack < inbound):
        # the rows kept are a floor (the row budget or the API cap cut the organization) or hold less than came
        # in (a shorter window): only the full-window totals can cover the rest
        if full_n is None or full_n + slack < inbound:
            return None
        ev["full"] = True
    if full_n is not None and full_n > examined + int(full_n * ESTIMATE_SHARE):
        ev["outside"] = full_n - examined  # never labelled: the full window counts them, the rows kept do not
    spoof = min(spoof, examined)
    ev.update(examined=examined, spoof=spoof, unclear=examined - spoof,
              unclear_senders=_unclear_senders(report, domain) if examined > spoof else [])
    return ev


# The tenant's own platform, Microsoft 365, in a domain's DNS: its SPF include and its two DKIM selectors. A
# domain whose SPF or DKIM names any other sender can send through a platform the tenant's mail flow never sees.
TENANT_SPF = ("include:spf.protection.outlook.com",)
TENANT_SELECTORS = ("selector1", "selector2")
# the inventory sources that put a domain in the tenant (discover.py): listed by it, or seen in its mail flow
TENANT_SOURCES = ("tenant", "default", "mailflow")


def foreign_senders(dns_doc):
    """What the domain's DNS authorizes to send as it beyond the tenant's
    own platform: SPF mechanisms other than Microsoft 365's include (a
    redirect too, whose target is not read here) and DKIM selectors other
    than its two. [] when only the tenant sends as it."""
    out = []
    for part in str((dns_doc or {}).get("spf") or "").split():
        p = part.lower().lstrip("+-~?")
        if p.startswith(("v=", "exp=")) or p == "all" or p in TENANT_SPF:
            continue
        out.append("SPF " + part)
    out += ["DKIM selector %s" % s for s in ((dns_doc or {}).get("dkim_selectors") or [])
            if str(s).lower() not in TENANT_SELECTORS]
    return out


def tenant_carries(report, domain, dns_doc):
    """True when the tenant's mail flow sees the domain's own mail: the
    tenant lists it (a run that says nothing about where a domain came from
    is judged by DNS alone) and its DNS authorizes no sender beyond the
    tenant's platform. A domain only EXTRA_DOMAINS, a file or the command
    line names, or one whose SPF or DKIM points at another platform, sends
    where the tenant never looks: only aggregate reports can say nothing
    passes as it."""
    sources = (report.get("inputs") or {}).get("domain_sources")
    tags = sources.get(domain) if isinstance(sources, dict) else None
    if isinstance(tags, list) and tags and not set(TENANT_SOURCES) & {str(t) for t in tags}:
        return False
    return not foreign_senders(dns_doc)


# the heuristic label for a failure from our own system: dedupe.py's, and rua_parse's spelling of it
OWN_LABELS = ("likely_misconfigured_sender", "likely_misconfigured")
# what the labels cannot call spoofing or our own system: dedupe.py's and rua_parse's word for it
UNCLEAR_LABEL = "unknown"


def _own_streams(report, domain):
    """The aggregate-report failing streams sending as the domain that look like our own system
    (likely_misconfigured), excepted or not: a sender, however it fails."""
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else {}
    return [f for f in _rows(rua.get("failing_streams")) if isinstance(f, dict) and f.get("likely") in OWN_LABELS
            and domain in {_name(h) for h in _rows(f.get("header_from"))}]


def _dns_name(value):
    """A name a sending check may list: a domain, never a placeholder like '(other)' or '(no header_from)'."""
    name = _name(value)
    return name if name and "." in name and not name.startswith("(") else None


SAID_OWN = "failing in the mail log from what looks like our own system"
SAID_UNCLEAR = "failing in the mail log that may be our own system (the labels cannot tell)"
SAID_EXCEPTED = "failing in the mail log from a sender formally excepted in audit.toml"


def sending_names(report, inventory_rows=None, volume=None):
    """{name: [what shows it sending]} for every From domain this run saw
    sending, or possibly sending, audited or not: mail out in the tenant's
    mail flow (report.mailflow: an audited name's row or inventory row, and
    every other name the same query returned, mailflow.unaudited), mail in
    the mail log that did not fail (an audited domain's own rows,
    maillog.by_domain; the census's streams for any other name, or - with no
    census - each unaudited subdomain an audited domain's subdomains_total
    lists, when that total holds such mail), passing mail in a cut
    organization's full-window totals, or passing volume as it in the
    aggregate reports (rua.by_header_from). A failure is a sender too when it
    looks like our own system, when the labels cannot tell spoof from our
    own system (unknown), or when a formal exception covers it (an explained
    sender of ours), in the mail log or in the reports; only a failure that
    looks like spoofing is not. Each entry is a short phrase with the count.
    volume, a dict, receives each name's largest count among them (0 when
    none carries one): how busy it is."""
    out = {}

    def saw(name, text, n=0):
        name = _dns_name(name)
        if name and text not in out.setdefault(name, []):
            out[name].append(text)
        if name and volume is not None:
            volume[name] = max(volume.get(name, 0), n or 0)

    mf = report.get("mailflow") if isinstance(report.get("mailflow"), dict) else {}
    flows = dict(mf.get("unaudited")) if isinstance(mf.get("unaudited"), dict) else {}
    flows.update(mf.get("domains") if isinstance(mf.get("domains"), dict) else {})
    for name, row in (inventory_rows or {}).items():
        if isinstance(row, dict) and isinstance(row.get("mailflow"), dict):
            flows[name] = row["mailflow"]  # an inventory row first, as mailflow_of reads it
    for name, flow in flows.items():
        n = _measured(flow.get("outbound")) if isinstance(flow, dict) else None
        if n:
            saw(name, "%d out in the tenant's mail flow" % n, n)
    ml = report.get("maillog") if isinstance(report.get("maillog"), dict) else {}
    by_dom = ml.get("by_domain") if isinstance(ml.get("by_domain"), dict) else {}

    def failures(c):
        """(ours, unclear, excepted) among one counters slice's genuine failures, the excepted ones apart."""
        by = c.get("by_likely") if isinstance(c.get("by_likely"), dict) else {}
        gone = c.get("excepted_by_likely") if isinstance(c.get("excepted_by_likely"), dict) else {}
        return tuple(max((_measured(by.get(k)) or 0) - (_measured(gone.get(k)) or 0), 0)
                     for k in (OWN_LABELS[0], UNCLEAR_LABEL)) + (_measured(c.get("excepted")) or 0,)

    for name, c in by_dom.items():
        if isinstance(c, dict):
            n = (_measured(c.get("passing_messages")) or 0) + (_measured(c.get("internal_messages")) or 0)
            if n:
                saw(name, "%d in the mail log that did not fail" % n, n)
            for n, said in zip(failures(c), (SAID_OWN, SAID_UNCLEAR, SAID_EXCEPTED)):
                if n:
                    saw(name, "%d %s" % (n, said), n)
    census = ml.get("census") if isinstance(ml.get("census"), dict) else {}
    tally, failing = {}, {}
    for r in _rows(census.get("by_sender")):
        name = _dns_name(r.get("domain")) if isinstance(r, dict) else None
        if not name or name in by_dom:  # an audited domain's own rows say it above
            continue
        m, f = _measured(r.get("messages")), _measured(r.get("genuine_failures"))
        if m is not None and f is not None and m > f:
            tally[name] = tally.get(name, 0) + m - f
        counts = r.get("likely_counts") if isinstance(r.get("likely_counts"), dict) else None
        if counts is not None:  # the failures no exception covers, by label; the excepted ones apart
            k = [_measured(counts.get(OWN_LABELS[0])) or 0, _measured(counts.get(UNCLEAR_LABEL)) or 0]
        else:  # an older census: the stream's majority label stands for all its failures
            k = [(f or 0) if r.get("likely") == label else 0 for label in (OWN_LABELS[0], UNCLEAR_LABEL)]
        k.append(_measured(r.get("excepted")) or 0)
        failing[name] = [a + b for a, b in zip(failing.get(name, [0, 0, 0]), k)]
    for name, n in tally.items():
        saw(name, "%d in the mail log that did not fail" % n, n)
    for name, ks in failing.items():
        for n, said in zip(ks, (SAID_OWN, SAID_UNCLEAR, SAID_EXCEPTED)):
            if n:
                saw(name, "%d %s" % (n, said), n)
    if not _rows(census.get("by_sender")):
        for name, c in by_dom.items():
            st = c.get("subdomains_total") if isinstance(c, dict) else None
            if not isinstance(st, dict):
                continue
            if (_measured(st.get("passing_messages")) or 0) + (_measured(st.get("internal_messages")) or 0):
                for sub in _rows(st.get("domains")):
                    saw(sub, "mail that did not fail among %s's unaudited subdomains in the mail log" % name)
            if any(failures(st)):
                for sub in _rows(st.get("domains")):
                    saw(sub, "failures that may be our own system's among %s's unaudited subdomains in the mail "
                             "log" % name)
    wt = ml.get("window_totals") if isinstance(ml.get("window_totals"), dict) else {}
    for info in (wt.get("orgs") if isinstance(wt.get("orgs"), dict) else {}).values():
        by = info.get("by_domain") if isinstance(info, dict) else None
        for name, c in (by if isinstance(by, dict) else {}).items():
            n = _measured(c.get("passing")) if isinstance(c, dict) else None
            if n:
                saw(name, "about %d passing over the full window (advanced hunting)" % n, n)
    rua = report.get("rua") if isinstance(report.get("rua"), dict) else {}
    for h in _rows(rua.get("by_header_from")):
        n = _measured(h.get("pass")) if isinstance(h, dict) else None
        if n:
            saw(h.get("domain"), "%d passing in the aggregate reports" % n, n)
    for f in _rows(rua.get("failing_streams")):
        if not isinstance(f, dict) or f.get("likely") not in OWN_LABELS + (UNCLEAR_LABEL,):
            continue
        said = ("from what looks like our own system" if f.get("likely") in OWN_LABELS
                else "that may be our own system (the labels cannot tell)")
        for h in _rows(f.get("header_from")):
            saw(h, "%s failing in the aggregate reports %s" % (_measured(f.get("fail")) or "some", said),
                _measured(f.get("fail")))
    return out


def unaudited_senders(report, inventory_rows=None):
    """[(name, volume)] for the names below an audited domain that the
    sending rule finds (sending_names) and the run does not audit, the
    busiest first (volume: the largest count any source shows for it). Only
    DNS says whether such a name has a DMARC record of its own: collect.py
    looks these up (report.dns_extra) before the plan reads them."""
    dns = report.get("dns") if isinstance(report.get("dns"), dict) else {}
    audited = {_name(d) for d in dns}
    volume = {}
    names = sending_names(report, inventory_rows, volume)
    below = [n for n in names if n not in audited and any(n.endswith("." + a) for a in audited if a)]
    return sorted(((n, volume.get(n, 0)) for n in below), key=lambda kv: (-kv[1], kv[0]))


EXTRA_STATUSES = ("found", "absent", "error")


def dns_extra(report):
    """{name: answer} from report.dns_extra: the _dmarc lookups collect.py
    made for the unaudited subdomains that send ({"dmarc": the record or
    None, "status": found | absent | error, "source": the _dmarc name where
    found}). An entry of the wrong shape reads as no lookup at all."""
    extra = report.get("dns_extra") if isinstance(report.get("dns_extra"), dict) else {}
    return {name: x for name, x in ((_dns_name(k), v) for k, v in extra.items())
            if name and isinstance(x, dict) and x.get("status") in EXTRA_STATUSES}


def has_own_record(name, answer):
    """True when a dns_extra answer shows a DMARC record at the name's own _dmarc name."""
    return answer.get("status") == "found" and _name(answer.get("source")) == "_dmarc." + name


def own_lookup_failed(dns_doc):
    """True when an audited name's own _dmarc lookup failed: every lookup
    (DMARC-006), or its own while a parent's record answered (DMARC-007, the
    audit assumed it inherits). A record of its own may be there all the
    same."""
    ids = {f.get("id") for f in _rows((dns_doc or {}).get("findings")) if isinstance(f, dict)}
    return (dns_doc or {}).get("dmarc_status") == "error" or bool(ids & {"DMARC-006", "DMARC-007"})


def subdomain_context(report, inventory_rows, dns_docs):
    """What the plan knows about the names below each audited domain:
    senders (sending_names), own (the names with a DMARC record of their own,
    as DNS shows it: an audited name's lookup, and for an unaudited one the
    lookup collect.py made, report.dns_extra - the policy an aggregate report
    says it saw is no proof: those reports can be months old), checked (the
    names whose own record DNS answered for: an audited name unless its own
    _dmarc lookup failed - DMARC-006, or DMARC-007, where the audit assumed
    it inherits - and an unaudited one whose lookup found a record or none),
    extra (the dns_extra answers), audited, and unmeasured (the audited
    names whose mail out this run did not measure: no mail flow for them,
    whatever else the run read - the mail log carries no outbound leg, and
    mail to receivers that send no reports shows nowhere else - so they may
    send, and count as if they did)."""
    audited = {_name(d) for d in dns_docs}
    own = {_name(d) for d, doc in dns_docs.items()
           if isinstance(doc, dict) and doc.get("dmarc") and not doc.get("inherited")}
    extra = {n: x for n, x in dns_extra(report).items() if n not in audited}  # DNS decides for an audited name
    own |= {n for n, x in extra.items() if has_own_record(n, x)}
    blind = {_name(d) for d, doc in dns_docs.items() if isinstance(doc, dict) and own_lookup_failed(doc)}
    checked = (audited - blind) | {n for n, x in extra.items() if has_own_record(n, x) or x["status"] == "absent"}
    unmeasured = {d for d in audited
                  if _measured(mailflow_of(report, (inventory_rows or {}).get(d), d).get("outbound")) is None}
    return {"senders": sending_names(report, inventory_rows), "own": own, "checked": checked, "extra": extra,
            "audited": audited, "unmeasured": unmeasured}


def missing_records(apex, ctx):
    """(sending, unmeasured): the names below apex that send (or that this
    run could not measure) and have no DMARC record of their own, sorted."""
    def below(n):
        return n != apex and n.endswith("." + apex) and n not in ctx["own"]
    sending = sorted(n for n in ctx["senders"] if below(n))
    return sending, sorted(n for n in ctx["unmeasured"] if below(n) and n not in ctx["senders"])


def _listed(names, cap=6):
    """'a', 'a and b', 'a, b and c', ... 'and N more' past cap."""
    names = list(names)
    if len(names) > cap:
        names = names[:cap] + ["%d more" % (len(names) - cap)]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def evidence_for(report, domain):
    """What the report proves about this domain's legitimate senders."""
    ev = {"legit_failing": [], "spf_only": [], "has_maillog": False, "has_rua": False,
          "outbound_seen": None, "dkim_evidence": False}
    audited = _audited(report)
    gate_exc = (report.get("gate") or {}).get("exceptions") or {}
    excepted_ips = set(gate_exc.get("excepted_streams") or [])
    ml = report.get("maillog") or {}
    if ml:
        ev["has_maillog"] = True
        scope = (ml.get("sender_domain") or "").lower()
        if not scope or domain == scope or domain.endswith("." + scope):
            by_dom = ml.get("by_domain") if isinstance(ml.get("by_domain"), dict) else {}
            own = by_dom.get(domain) if isinstance(by_dom.get(domain), dict) else None
            if own is not None:
                # the report attributes the log per domain: this domain's own rows, and the
                # exceptions the gate applied to them - the same numbers the status document shows
                by = own.get("by_likely") or {}
                gate_dom = ((report.get("gate") or {}).get("domains") or {}).get(domain) or {}
                if "excepted_by_likely" in gate_dom:  # the gate's split: only excepted own-sender failures count here
                    excepted = (gate_dom.get("excepted_by_likely") or {}).get("likely_misconfigured_sender", 0)
                else:  # a gate from before the split: every excepted failure counts
                    excepted = gate_dom.get("excepted_failures") or 0
            else:
                # a report from before the attribution: the whole log, less everything excepted
                by = (ml.get("counters") or {}).get("by_likely") or {}
                excepted = gate_exc.get("excepted_maillog_failures") or 0
            n = by.get("likely_misconfigured_sender", 0)
            remaining = n - min(excepted, n)
            if remaining > 0:  # only what the gate did not formally except holds the step
                ev["legit_failing"].append("%d message(s) in the mail log failed from a sender that looks like your own misconfigured system, not a spoof%s"
                                           % (remaining, " (%d more are excepted in the gate)" % excepted if excepted else ""))
        if (ml.get("alignment") or {}).get("available"):
            ev["dkim_evidence"] = True
        for s in ml.get("spf_only_senders") or []:
            if _home(s.get("domain"), audited) == domain:  # attributed as the gate does: an audited subdomain is its own
                d = (s.get("domain") or "").lower()
                ev["spf_only"].append("%s (mail log, %d msgs)" % (s.get("sender") or d, s.get("spf_only") or 0))
    rua = report.get("rua") or {}
    if rua:
        ev["has_rua"] = True
        if (rua.get("totals") or {}).get("messages"):
            ev["dkim_evidence"] = True
        for s in rua.get("failing_streams") or []:
            if s.get("source_ip") in excepted_ips:
                continue
            froms = [h.lower() for h in s.get("header_from") or []]
            # rua_parse labels these likely_misconfigured; older reports said likely_misconfigured_sender.
            # Anything not labelled a spoof is a sender to fix or except before p= moves (the gate rule).
            if domain in froms and s.get("likely") != "likely_spoof":
                ev["legit_failing"].append("aggregate reports: %s sends %d message(s) as %s and fails (%s; %s)"
                                           % (s.get("source_ip"), s.get("count"), domain, s.get("likely") or "unlabelled",
                                              "; ".join(s.get("likely_signals") or [])[:120]))
        for s in rua.get("spf_only_senders") or []:
            froms = [h.lower() for h in (s.get("header_from") or [])] if isinstance(s, dict) else []
            if not froms or any(_home(h, audited) == domain for h in froms):  # the gate's attribution, mirrored
                ev["spf_only"].append(str(s.get("source_ip", s)) if isinstance(s, dict) else str(s))
    return ev


# --------------------------------------------------------------------------
# the plain-language layer (what src/next_steps.py reads)

PREREQ_KINDS = ("dkim_proof", "list_proof", "spf_budget", "evidence", "verify_unused", "reports", "other")
# first match wins, so the order matters: an evidence hold can mention DKIM and
# a DKIM prerequisite can mention forwarding. A DNS check worded around the names
# and addresses it quotes (a lookup first, an external-destination record, the
# order of the rua addresses, the subdomains' own records, one change a week)
# comes first: a name or an address in it never decides its kind
PREREQ_RULES = (
    ("other", re.compile(r"^(?:look up _dmarc\.\S+ first:|the external-destination record exists:|decide the order "
                         r"of the rua addresses:|every subdomain that sends has its own _dmarc record\b|one change to "
                         r"\S+ a week:)", re.I)),
    ("verify_unused", re.compile(r"verif(?:y|ied) unused", re.I)),
    ("spf_budget", re.compile(r"\blookups?\b", re.I)),
    ("other", re.compile(r"sender inventory", re.I)),
    ("evidence", re.compile(r"mail log|aggregate reports|failure evidence|failure check|--maillog|--rua", re.I)),
    ("reports", re.compile(r"\breports?\b|stable for \d+ days", re.I)),
    ("dkim_proof", re.compile(r"\bdkim\b|_domainkey", re.I)),
    ("list_proof", re.compile(r"\blist\b|forwarder|forwarding|canary|delivered_twin", re.I)),
)
ENFORCEMENT_PRIORITIES = (3, 4, 5)


def prereq_kind(text):
    """What would prove a prerequisite, by keyword: one of PREREQ_KINDS."""
    for kind, rx in PREREQ_RULES:
        if rx.search(text or ""):
            return kind
    return "other"


def prereq_items(prereqs):
    """The structured twin of a prerequisites list. met stays None: the reader decides."""
    return [{"text": p, "kind": prereq_kind(p), "met": None} for p in prereqs]


def _share(pct):
    n = int(pct) if str(pct or "").isdigit() else 100
    return {25: "a quarter of", 50: "half of", 100: "all of"}.get(n, "%d percent of" % n)


def human_summary(change):
    """One plain sentence about a change for a reader who does not read DNS;
    a second when the change also appends the run's report address to the
    record's rua (folded into a quarantine-now row that rewrites the record
    anyway)."""
    text = _summary(change)
    value, current = str(change.get("value") or ""), str(change.get("current") or "")
    if change.get("kind") not in ("modify", "new", "park") and current.lower().startswith("v=dmarc1") \
            and rua_of(current) and value.lower().startswith("v=dmarc1"):
        added = [a for a in rua_addresses(value) if a not in rua_addresses(current)]
        if added:
            text += (" The same change adds %s to the record's reporting addresses, so its aggregate reports start "
                     "reaching the toolkit's archive%s." % (", ".join(added), _third(current)))
    return text


def _third(current):
    """The caveat of an address appended after two or more (RFC 7489 6.2), for a plain sentence; '' otherwise."""
    return (" - from every receiver only once it is among the record's first two addresses (see the check listed with "
            "it)" if len(rua_addresses(current)) >= 2 else "")


def _summary(change):
    domain = change.get("domain") or change.get("hostname") or "the domain"
    kind = change.get("kind")
    host = str(change.get("hostname") or "")
    value = str(change.get("value") or "")
    current = str(change.get("current") or "")
    why = str(change.get("why") or "")
    is_spf = value.lower().startswith("v=spf1")
    is_dmarc = host.startswith("_dmarc.") or value.lower().startswith("v=dmarc1")
    new = dmarc_tags(value) if is_dmarc else {}
    old = dmarc_tags(current) if current.lower().startswith("v=dmarc1") else {}
    if kind == "park":
        if is_spf:
            return ("Declare that no server may send mail as %s, which sends nothing today; this stops the parked "
                    "domain being used for spoofing and affects no legitimate mail." % domain)
        return ("Tell receivers to refuse anything claiming to come from %s, which sends no mail; the reporting "
                "address still shows every attempt." % domain)
    if kind == "new":
        if current.lower().startswith("not checked"):  # nobody saw whether it has one: a second record breaks it
            return ("Publish a monitoring-only DMARC record for %s once a lookup shows it has none of its own, so its "
                    "reports start flowing; no effect on delivery." % domain)
        return "Publish a monitoring-only DMARC record for %s so its reports start flowing; no effect on delivery." % domain
    if kind == "no_mail":
        return ("Move %s straight to quarantine instead of the weekly ramp, once the checks listed with it are "
                "confirmed: this run measured no mail sent as it, so the ramp would protect no sender of ours; mail "
                "that fails checks lands in junk from then on, and the reporting address shows every attempt."
                % domain)
    if kind == "modify":
        if is_spf:
            parts = value.split()
            return ("Change the end of the %s SPF record to %s so mail from unlisted servers is treated as suspicious "
                    "instead of ignored; listed senders are unaffected." % (domain, parts[-1] if parts else "~all"))
        if old.get("rua"):  # it reports already, just not to the toolkit
            return ("Add the toolkit's report address to the %s DMARC record, after the addresses it already reports "
                    "to, so its aggregate reports start reaching the toolkit's archive%s; no effect on delivery."
                    % (domain, _third(current)))
        return ("Add a reporting address to the %s DMARC record so receivers start telling us what fails; "
                "no effect on delivery." % domain)
    if kind == "todo":
        if "_domainkey" in host:
            return ("Turn on DKIM signing at every platform that sends as %s so its mail carries a signature that "
                    "survives forwarding; this comes before any enforcement step." % domain)
        if "lookup" in why.lower():
            return ("Trim the %s SPF record below the 10-lookup limit; today every SPF check for it returns an error, "
                    "so this can only help delivery." % domain)
        return ("Publish an SPF record for %s naming the systems that send its mail, built from the sender "
                "inventory; until then receivers cannot check its senders." % domain)
    if kind == "ratchet":
        if is_spf:
            return ("Change the %s SPF record to a hard fail (-all) so mail from unlisted servers is refused "
                    "outright; only after reject is stable and every sender signs with DKIM." % domain)
        if new.get("p") == "quarantine" and old.get("p") != "quarantine":
            return ("Move %s to quarantine for %s the mail that fails checks, so spoofed mail starts landing in "
                    "junk while reports confirm no legitimate sender is caught." % (domain, _share(new.get("pct"))))
        if new.get("p") == "reject" and old.get("p") != "reject":
            return ("Move %s to reject so mail that fails checks is refused instead of junked; subdomains are a "
                    "separate later step." % domain)
        if new.get("pct") and new.get("pct") != old.get("pct"):
            return ("Raise the %s quarantine share from %s to %s percent of failing mail; mail that passes is "
                    "untouched." % (domain, old.get("pct", "100"), new["pct"]))
        if new.get("sp") and new.get("sp") != old.get("sp"):
            return ("Apply %s to subdomains of %s that have no record of their own, so mail failing checks from "
                    "them is %s; subdomains with their own record are unaffected."
                    % (new["sp"], domain, "sent to junk" if new["sp"] == "quarantine" else "refused"))
    first = why.split(":")[0].strip()
    return "%s for %s%s." % (KIND_LABEL.get(kind, kind or "change").capitalize(), domain, (": " + first) if first else "")


def next_step_for(plan, domain):
    """The change dict for this domain's most urgent enforcement step (priority
    3 to 5, lowest number first), or None. Every change in a generated plan is
    pending: a step that has been applied is absent from the next run's plan."""
    domain = (domain or "").strip().lower().rstrip(".")
    best = None
    for c in (plan or {}).get("changes") or []:
        if not isinstance(c, dict) or (c.get("domain") or "").lower().rstrip(".") != domain:
            continue
        try:
            prio = int(c.get("priority"))
        except (TypeError, ValueError):
            continue
        if prio in ENFORCEMENT_PRIORITIES and (best is None or prio < best[0]):
            best = (prio, c)
    return best[1] if best else None


# --------------------------------------------------------------------------
# the rules

def plan_domain(domain, dns_doc, report, inventory_row, rua_addr, ttl, all_domains, subs=None, report_addr=None):
    """Changes and next steps for one domain. Returns (changes, holds).
    subs: subdomain_context() for the run (build_plan passes it): what the
    run knows about the names below this domain, audited or not.
    report_addr: the run's report address (a mailto: URI), which the
    domain's own record must carry in its rua; None when the run has none."""
    changes, holds = [], []
    ids = finding_ids(dns_doc)
    dmarc = dns_doc.get("dmarc")
    tags = dmarc_tags(dmarc)
    policy = dns_doc.get("effective_policy")
    inherited = bool(dns_doc.get("inherited"))
    spf = dns_doc.get("spf")
    spf_status = dns_doc.get("spf_status")
    term = (dns_doc.get("spf_terminator") or "").lower()
    lookups = dns_doc.get("spf_lookups") or 0
    dkim_status = dns_doc.get("dkim_status")
    selectors = dns_doc.get("dkim_selectors") or []
    mx_null = bool(dns_doc.get("mx_null"))
    has_mx = bool(dns_doc.get("mx")) and not mx_null
    zone = (inventory_row or {}).get("zone") or org_domain(domain)
    zone_host = (inventory_row or {}).get("zone_host") or "unknown"
    mailflow = mailflow_of(report, inventory_row, domain)  # measured on every collect run with a token
    outbound, inbound = _measured(mailflow.get("outbound")), _measured(mailflow.get("inbound"))
    if outbound is None or inbound is None:  # not measured, or damaged: never read as nothing sent
        outbound = inbound = None
    reports_cover, passing = aggregate_volume(report, domain, dns_doc)
    ev = evidence_for(report, domain)
    hostname = "_dmarc." + domain
    subdomains = sorted(d for d in all_domains if d != domain and d.endswith("." + domain))
    subs = subs if subs is not None else subdomain_context(report, {}, report.get("dns") or {})
    # the names below this domain that send (or that nothing measured) and have no record of their own; one whose
    # own record nobody saw (no lookup, or one that failed - an audited name's too) is named as not checked
    sending_subs, unmeasured_subs = missing_records(domain, subs)
    missing = sending_subs + unmeasured_subs
    unchecked = [n for n in missing if n not in subs.get("checked", ())]

    def marked(n):
        said = (["not measured"] if n in unmeasured_subs else []) + (["not checked"] if n in unchecked else [])
        return "%s (%s)" % (n, ", ".join(said)) if said else n
    missing_text = _listed([marked(n) for n in missing]) if missing else ""
    look_first = "; a name marked not checked may have a record already: look it up first" if unchecked else ""
    # this domain's own _dmarc lookup failed (DMARC-007: the audit assumed it inherits): a record proposed for it
    # waits on a lookup, as for an unaudited name nobody checked - a second record would leave it with no policy
    blind = own_lookup_failed(dns_doc)
    unseen = "not checked (its lookup failed in this run)" if blind else "none"
    first = [lookup_first(domain)] if blind else []
    pct = int(tags.get("pct", "100") or 100) if tags.get("pct", "100").isdigit() else 100
    sp_tag = (tags.get("sp") or "").strip().lower() or None

    def add(kind, priority, record, host, value, current, rollback, why, prereqs=(), fids=(), name=None):
        d = name or domain
        prereqs = list(prereqs)
        if host == "_dmarc." + d and str(value).lower().startswith("v=dmarc1"):
            # a rua address the record gains in another organization: receivers send there only once it agrees
            prereqs += [p for p in destinations(d, value, current) if p not in prereqs]
        c = {"domain": d, "zone": zone, "zone_host": zone_host, "kind": kind,
             "priority": priority, "record": record, "hostname": host, "value": value,
             "ttl": ttl, "current": current, "rollback": rollback, "why": why,
             "prerequisites": list(prereqs), "finding_ids": sorted(set(fids)),
             "owner_hint": d, "prerequisite_items": prereq_items(list(prereqs))}
        c["human_summary"] = human_summary(c)
        changes.append(c)

    def monitor_unaudited():
        """p=none records for the subdomains below this domain that send and
        are not audited (no row of their own covers them): the record that
        shields each from this domain's sp= change. A name whose own _dmarc
        lookup (report.dns_extra) showed none gets it outright; one nobody
        looked up, or whose lookup failed, gets it with a lookup first: a
        second record would leave it with no policy at all."""
        for n in sending_subs:
            if n in subs["audited"]:
                continue  # an audited subdomain's own row proposes its record
            seen = "; ".join(subs["senders"].get(n) or ["?"])
            if n not in unchecked:  # DNS answered with no record at its own name
                add("new", 1, "TXT", "_dmarc." + n, "v=DMARC1; p=none; rua=%s;" % rua_addr, "none", "delete the record",
                    "sending subdomain without a record of its own: an explicit record shields it from the apex's sp= "
                    "change on %s (seen sending: %s); DNS shows no record at _dmarc.%s" % (domain, seen, n), (), (),
                    name=n)
                continue
            failed = (subs.get("extra", {}).get(n) or {}).get("status") == "error"
            add("new", 1, "TXT", "_dmarc." + n, "v=DMARC1; p=none; rua=%s;" % rua_addr,
                "not checked (%s)" % ("its lookup failed in this run" if failed else "not an audited domain"),
                "delete the record",
                "sending subdomain whose own record this run %s: an explicit record shields it from the apex's sp= "
                "change on %s if it has none (seen sending: %s)" % ("could not look up" if failed else "did not look up",
                                                                     domain, seen),
                [lookup_first(n)], (), name=n)

    # Not verified: do not plan against a guess.
    if dns_doc.get("dmarc_status") == "error" or spf_status == "error":
        holds.append({"domain": domain, "reason": "DNS could not be verified for this domain in this run - re-run before planning changes"})
        return changes, holds
    if dns_doc.get("dmarc_status") == "found" and not dmarc:
        holds.append({"domain": domain, "reason": "a DMARC record was found at %s but its text is missing from the report - re-run the audit before planning this domain" % (dns_doc.get("dmarc_source") or hostname)})
        return changes, holds

    # --- parked domain: nothing in, nothing out, nothing signing -------------
    # passing mail as it in the aggregate reports is a sender too: a third party mailing outside recipients
    # as the domain never passes through the tenant, so its mail flow cannot show it
    sends = spf_sends(spf) or bool(selectors) or (outbound or 0) > 0 or passing > 0
    parked_candidate = (not has_mx) and not sends
    parked_note = unused_note(outbound, inbound, mailflow_days(report), reports_cover)
    needs_record = not dmarc or "DMARC-001" in ids or (inherited and policy in (None, "none"))

    # --- no mail measured: the ramp protects nobody, so quarantine now ---------
    # the run measured that nothing legitimate is sent as the domain; the parked logic, when it applies, comes first
    days = mailflow_days(report)
    carried = tenant_carries(report, domain, dns_doc)
    qev = quiet_evidence(report, domain, outbound, inbound, days, passing)
    if qev is not None and not carried and not reports_cover:
        qev = None  # the tenant sees none of its own mail: only aggregate reports that cover it can say none passes
    quiet = qev is not None and not (parked_candidate and needs_record) and "DMARC-005" not in ids
    # an organizational domain whose sending subdomains have no record of their own keeps them where they are
    pin = quiet and domain == org_domain(domain) and bool(missing) and not (dmarc and not inherited and sp_tag)
    # what the run could not settle itself, each a check for a person before the record moves
    quiet_checks = ["no sender that mails less often than monthly (statements, renewals) uses this domain"]
    if quiet and not reports_cover:
        quiet_checks.append("no third party sends as %s straight to outside recipients: no aggregate report in "
                            "this run covers it, and only those would show such mail" % domain)
    if quiet and qev["unclear"]:
        names = "; ".join("%s x%d" % kv for kv in qev["unclear_senders"])
        quiet_checks.append("the %d message(s) that came in as %s and that the mail log cannot call spoofing (a "
                            "failure labelled unknown, or no DMARC verdict at all%s) are spoofs rather than a sender "
                            "of ours" % (qev["unclear"], domain, (": " + names) if names else ""))
    if quiet and qev["outside"]:
        quiet_checks.append("the about %d message(s) that came in as %s outside the mail-log rows kept are spoofs "
                            "rather than a sender of ours: the full window, counted in advanced hunting, shows none "
                            "of them passing, but only the rows kept carry labels" % (qev["outside"], domain))
    quiet_prereqs = quiet_checks + ev["legit_failing"]

    def quiet_value(base):
        """The quarantine-now record: p=quarantine (no pct, so 100 percent), the record's own rua or the
        run's, and sp=none while its sending subdomains still need records of their own."""
        v = drop_tag(set_tag(base, "p", "quarantine"), "pct") if base else "v=DMARC1; p=quarantine;"
        if not rua_of(v):
            v = with_rua(v, rua_addr)
        return set_tag(v, "sp", "none") if pin and "sp" not in dmarc_tags(v) else v

    def quiet_why():
        """Why the record moves now, in what the run read and nothing more: the tenant's mail flow (or, for a
        domain whose mail goes elsewhere, the aggregate reports), the mail log over the mail that came in as
        it, and the reports."""
        if carried:
            parts = ["the tenant measured no mail sent as %s in %d days" % (domain, days)]
        else:
            other = foreign_senders(dns_doc)
            parts = ["the tenant does not carry %s's own mail (%s), and the aggregate reports that cover it count "
                     "none passing as it" % (domain, ("its DNS names other senders: " + ", ".join(other[:3]))
                                             if other else "the tenant does not list it")]
        n = qev["inbound"]
        if not n:
            parts.append("nothing came in with it as the From domain")
        else:
            labels = []
            if qev["spoof"]:
                labels.append("%d %s like spoofing, which quarantine stops"
                              % (qev["spoof"], "looks" if qev["spoof"] == 1 else "look"))
            if qev["unclear"]:
                labels.append("%d it cannot call spoofing, named in the checks" % qev["unclear"])
            held = ", and ".join(labels) or "none labelled"
            if qev["full"]:
                parts.append("none of the about %d message(s) that came in with it as the From domain passed over "
                             "the full window (counted in advanced hunting), and the mail-log rows kept hold %d "
                             "logical message(s) of them: %s" % (n, qev["examined"], held))
            else:
                parts.append("none of the %d message(s) that came in with it as the From domain passed, and the mail "
                             "log examined every one: %d logical message(s), %s" % (n, qev["examined"], held))
        if carried:
            parts.append("the aggregate reports count none passing as it" if reports_cover
                         else "no aggregate report in this run covers it (see the checks)")
        why = ("quarantine now: %s, so a weekly ramp would protect nobody; reject follows once a week of reports "
               "still shows nothing passing" % "; ".join(parts))
        if pin:
            why += ("; sp=none keeps its subdomains where they are until the ones that send (%s) have records of "
                    "their own" % missing_text)
        return why

    fast = False  # a quarantine-now record replaces this run's ramp rows
    # --- monitoring first --------------------------------------------------
    if "DMARC-005" in ids:
        holds.append({"domain": domain, "reason": "two DMARC records at %s - receivers apply no policy and send no reports; find out who published the second record before collapsing to one" % hostname})
    elif needs_record:
        fids = ids & {"DMARC-001", "DMARC-002", "DMARC-007"}
        if parked_candidate:
            add("park", 1, "TXT", hostname, "v=DMARC1; p=reject; rua=%s;" % rua_addr, unseen,
                "delete the record", "parked domain: nothing sends as it, so reject spoofing outright and keep rua to see attempts",
                first + [parked_note], fids)
        elif quiet:
            fast = True
            add("no_mail", 1, "TXT", hostname, quiet_value(None), unseen, "delete the record", quiet_why(),
                first + quiet_prereqs, fids)
        else:
            if blind:
                why = ("subdomain whose own _dmarc lookup failed in this run (DMARC-007): if it has no record of its "
                       "own, it inherits policy none from %s, and an explicit record starts its own reporting and "
                       "shields it from the apex's sp= change" % dns_doc.get("dmarc_source"))
            elif inherited:
                why = ("subdomain without a record of its own: it inherits policy none from %s; an explicit record "
                       "starts its own reporting and shields it from the apex's sp= change" % dns_doc.get("dmarc_source"))
            else:
                why = "no DMARC record: no policy and no reporting - monitoring starts here"
            add("new", 1, "TXT", hostname, "v=DMARC1; p=none; rua=%s;" % rua_addr, unseen, "delete the record", why,
                first, fids)
    elif quiet and not inherited and (policy == "none" or (policy == "quarantine" and pct < 100)):
        fast = True
        add("no_mail", 1, "TXT", hostname, quiet_value(dmarc), dmarc, "publish the current string verbatim", quiet_why(),
            quiet_prereqs, ids & {"DMARC-002", "DMARC-003", "DMARC-008"})
    elif "DMARC-003" in ids:
        add("modify", 1, "TXT", hostname, with_rua(dmarc, rua_addr), dmarc, "publish the current string verbatim",
            "the record has no rua - failures are invisible until reports flow", (), {"DMARC-003"})
    if fast and pin:
        monitor_unaudited()

    # --- SPF hygiene --------------------------------------------------------
    # dns_audit's SPF ids: 001 no record, 002 the lookup failed (held above), 003 a weak terminator, 004 over the
    # 10-lookup limit, 005 at it, 006 one under it, 007 an include that did not resolve (the count a lower bound).
    # None of them is two v=spf1 records: dns_audit reads the first one it finds, so no hold says that. SPF-007 is
    # an include no resolver path answered for in this run (one with no SPF record reads NO SPF RECORD instead), so
    # the failure may be the run's own: the include is looked up again before anyone removes it
    if "SPF-007" in ids:
        holds.append({"domain": domain, "reason": "an SPF include could not be resolved, so the lookup count is a lower "
                                                  "bound: look the include up through two resolvers (verify.md) or "
                                                  "re-run; fix or remove it only if it fails there too, and add no "
                                                  "sender until it resolves"})
    if "SPF-001" in ids or not spf:
        if parked_candidate:
            add("park", 1, "TXT", domain, "v=spf1 -all", "none", "delete the record",
                "parked domain: no sender is authorized, every SPF check fails", [parked_note], {"SPF-001"})
        elif has_mx or sends or "DMARC-001" not in ids:
            add("todo", 1, "TXT", domain, "v=spf1 <includes and ip4/ip6 from the sender inventory> ~all", "none", "delete the record",
                "no SPF record: publish one built from the sender inventory (the census query) - never guess includes",
                ["sender inventory for %s complete (queries/sender_census.kql or the aggregate reports)" % domain], {"SPF-001"})
    else:
        if "SPF-004" in ids:
            add("todo", 1, "TXT", domain, "<same record with fewer includes: move senders to DKIM, drop unused includes, flatten if needed>",
                spf, "publish the current string verbatim",
                "over the 10-lookup limit: SPF returns permerror for every message today", (), {"SPF-004"})
        if term in ("?all", "+all") or "SPF-003" in ids:
            add("modify", 1, "TXT", domain, spf_with_terminator(spf, "~all"), spf, "publish the current string verbatim",
                "terminator '%s' gives no protection; ~all is the safe step (never straight to -all before reject is stable)" % (term or "missing"),
                (), {"SPF-003"})

    # --- DKIM before enforcement ------------------------------------------------
    # (no mail measured: nothing sends as the domain, so there is no platform to sign at)
    sends_real = spf_sends(spf) or (outbound or 0) > 0
    if sends_real and dkim_status == "absent" and not parked_candidate and not quiet:
        add("todo", 2, "CNAME/TXT", "<selector>._domainkey." + domain, "<generated by the sending platform>", "none",
            "delete the selector records",
            "the domain sends but no DKIM selector was found: SPF-only authentication breaks on forwarding and lists; enable signing at every platform that sends as %s (Microsoft 365: selector1/selector2 CNAMEs; Google Workspace: the google selector; ESPs: their CNAME pair)" % domain,
            ["one live header per sender showing dkim=pass with d=%s (src/headers.py)" % domain], {"DKIM-002"})

    # --- the ratchet, one step at a time ----------------------------------------
    legit = list(ev["legit_failing"])
    spf_hold = []
    if ev["spf_only"] and policy in ("quarantine",):
        spf_hold.append("SPF-only aligned senders (%s): they break on forwarding at reject - aligned DKIM first" % ", ".join(ev["spf_only"][:5]))
    dkim_hold = []
    if policy == "quarantine" and pct >= 100 and (ev["has_maillog"] or ev["has_rua"]) and not ev["dkim_evidence"]:
        dkim_hold.append("no aligned-DKIM evidence in this run (no aggregate reports; the mail log has no SPF/DKIM columns): "
                         "run queries/dkim_alignment.kql or supply reports before this step - DKIM before reject, always")
    hold_reasons = legit + spf_hold + dkim_hold
    if not (ev["has_maillog"] or ev["has_rua"]):
        gate_note = "no failure evidence in this run - supply --maillog and/or --rua before applying any enforcement step"
    else:
        gate_note = None

    # the subdomains this run knows of below the domain: audited ones, and the ones it saw sending
    known = subdomains or [n for n in subs["senders"] if n.endswith("." + domain)]
    sp_now = sp_tag == "none" and bool(known)  # the sp= step is on offer (sp_step)

    def sp_step():
        """sp=quarantine on this domain's record (the apex at quarantine with pct 100, or at reject), once
        every subdomain that sends has a record of its own; the sending ones without one get their
        monitoring records and a hold naming them. A run that read no mail log and no aggregate reports
        says so, and one whose reports do not cover this record says what only they would show. False
        when sp= is not none or no subdomain is known."""
        if not sp_now:
            return False
        monitor_unaudited()
        if missing:
            holds.append({"domain": domain, "reason": "subdomains that send have no record of their own: %s - publish "
                          "their monitoring records (above) before sp= moves to quarantine%s"
                          % (missing_text, look_first)})
            pre = ["every subdomain that sends has its own _dmarc record: %s %s none yet (the monitoring records "
                   "above)" % (missing_text, "has" if len(missing) == 1 else "have")]
        else:
            pre = ["every subdomain that sends has its own _dmarc record (this run saw none sending without one)"]
        if gate_note:
            pre.append(gate_note)
        elif not reports_cover:
            pre.append("no third party sends as a subdomain without a record of its own straight to outside "
                       "recipients: no aggregate report in this run covers %s's record, and only those would show "
                       "such mail" % domain)
        add("ratchet", 4, "TXT", hostname, set_tag(dmarc, "sp", "quarantine"), dmarc, "publish the current string verbatim",
            "quarantine the subdomains without a record of their own: the apex is at %s but they inherit sp=none; "
            "apply once every subdomain that sends has its own record" % policy, pre)
        return True

    # what happens to sp= when the apex moves to reject
    if sp_now:
        sp_words = "; sp=none stays as is: the sp= step for this record is offered beside this one, one change a week"
    elif sp_tag is None and known:
        sp_words = "; the record has no sp=, so its subdomains without a record of their own move to reject with it"
    elif sp_tag:
        sp_words = "; sp stays as is"
    else:
        sp_words = ""

    if dmarc and "DMARC-005" not in ids and not inherited and not fast:
        if policy == "none" and rua_of(dmarc):
            add("ratchet", 3, "TXT", hostname, set_tag(set_tag(dmarc, "p", "quarantine"), "pct", "25"), dmarc,
                "publish the current string verbatim",
                "first enforcement step: quarantine a quarter of failing mail while reports confirm no legitimate sender is in the failing set",
                [p for p in ["every legitimate sender proven with an aligned DKIM header", gate_note] if p] + hold_reasons,
                {"DMARC-002"})
        elif policy == "quarantine" and pct < 100:
            nxt = next((s for s in PCT_STEPS if s > pct), 100)
            add("ratchet", 3, "TXT", hostname, set_tag(dmarc, "pct", str(nxt)), dmarc, "publish the current string verbatim",
                "raise the quarantine sample from %d to %d percent" % (pct, nxt),
                [p for p in ["deduplicated failure check at the current step shows only spoofing", gate_note] if p] + hold_reasons)
        elif policy == "quarantine" and pct >= 100:
            if sp_tag is None and missing:  # no sp=: the subdomains without a record follow p= to reject
                holds.append({"domain": domain, "reason": "subdomains that send have no record of their own and follow "
                              "p= (the record has no sp=): %s - moving to reject would reject their failing mail too; "
                              "give each its own record, or add sp=, before that move%s" % (missing_text, look_first)})
            if quiet:  # no sender to prove with DKIM: reports that keep showing nothing passing are the evidence
                # the checks the quarantine-now row carried stay open: a week at quarantine settles none of them
                week = ("a week at p=quarantine with the aggregate reports still showing nothing passing as %s" % domain
                        if reports_cover else
                        "a week at p=quarantine with aggregate reports that cover %s showing nothing passing as it "
                        "(none in this run covers it yet)" % domain)
                add("ratchet", 3, "TXT", hostname, set_tag(dmarc, "p", "reject"), dmarc, "publish the current string verbatim",
                    "quarantine at 100 percent is stable and no mail is measured as the domain: reject refuses failing "
                    "mail instead of junking it, and with no sender there is no DKIM proof to wait for" + sp_words,
                    [week] + quiet_checks + [p for p in [gate_note] if p] + legit + spf_hold)
            else:
                add("ratchet", 3, "TXT", hostname, set_tag(dmarc, "p", "reject"), dmarc, "publish the current string verbatim",
                    "quarantine at 100 percent is stable: reject refuses failing mail instead of junking it" + sp_words,
                    [p for p in ["every legitimate sender proven with an aligned DKIM header within 7 days",
                                 "no list or forwarder path for your own senders still failing (delivered_twin.kql; a canary post)",
                                 "SPF at 9 lookups or fewer", gate_note] if p] + hold_reasons)
            sp_step()
        elif policy == "reject":
            stepped = sp_step()  # the subdomains come first: sp=quarantine, then sp=reject, then SPF -all
            if not stepped and sp_tag == "quarantine":
                add("ratchet", 4, "TXT", hostname, set_tag(dmarc, "sp", "reject"), dmarc, "publish the current string verbatim",
                    "final subdomain step", ["a week of subdomain reports at sp=quarantine showing only spoofing"])
            elif not stepped and term == "~all" and spf_sends(spf):
                add("ratchet", 5, "TXT", domain, spf_with_terminator(spf, "-all"), spf, "publish the current string verbatim",
                    "last hardening: SPF hard fail, only after reject has been stable and every sender is DKIM-signed",
                    ["reject stable for 30 days", "every sender DKIM-signed and aligned (SPF -all breaks SPF-only senders on forwarding)"])
    if "SPF-005" in ids:
        holds.append({"domain": domain, "reason": "SPF is at the 10-lookup limit: no new include for any reason; new senders authenticate with DKIM"})

    # --- the run's report address in the record's rua ------------------------------------------------------
    # a record that reports only to a vendor or a mailbox of its own hides its outside view from the toolkit; the
    # address joins the ones already there, and nothing else changes. The zero-risk change that starts those reports
    # is never gated on the evidence they bring: it is a priority-1 row of its own, and a gated step that rewrites
    # the record from today's value names it as the other change this week (alternatives), to be proposed again
    # from the new value. Only a priority-1 row that rewrites the record anyway (quarantine now) carries it instead:
    # one change to the record
    if (report_addr and dmarc and not inherited and "DMARC-005" not in ids and "rua" in tags
            and not has_address(dmarc, report_addr)):
        order = [p for p in [rua_order(dmarc, report_addr)] if p]
        same = [c for c in changes if c["hostname"] == hostname and c["current"] == dmarc and c["priority"] == 1]
        for c in same:
            if has_address(c["value"], report_addr):
                continue  # the row fills an empty rua with it already
            c["value"] = add_rua(c["value"], report_addr)
            c["why"] += ("; the same change adds %s to rua, after the addresses already there, so the aggregate "
                         "reports reach the toolkit's archive (one change to this record a week)" % report_addr)
            c["prerequisites"] += [p for p in order + destinations(domain, c["value"], c["current"])
                                   if p not in c["prerequisites"]]
            c["prerequisite_items"] = prereq_items(c["prerequisites"])
            c["human_summary"] = human_summary(c)
        if not same:
            add("modify", 1, "TXT", hostname, add_rua(dmarc, report_addr), dmarc, "publish the current string verbatim",
                "the run's report address is missing from the record's rua: %s goes after the addresses already there, "
                "so the aggregate reports reach the toolkit's archive; nothing else changes" % report_addr, order)
    return changes, holds


def alternatives(changes):
    """Rows that rewrite one DMARC record from the same current value (the
    move to reject and the sp= step at quarantine 100) are alternatives for
    the week: applied together, the second would silently undo the first. Each
    gets a prerequisite naming the others, in place; ids must be set."""
    same = collections.OrderedDict()
    for c in changes:
        if c.get("record") == "TXT" and str(c.get("hostname") or "").startswith("_dmarc."):
            same.setdefault((c["hostname"], c.get("current")), []).append(c)
    for rows in same.values():
        for c in rows if len(rows) > 1 else ():
            others = [o["id"] for o in rows if o is not c]
            c["prerequisites"].append(
                "one change to %s a week: this row and the other %s for it (%s) each rewrite today's record, so "
                "apply one and let the next run propose the rest from the new value"
                % (c["hostname"], "row" if len(others) == 1 else "rows", ", ".join(others)))
            c["prerequisite_items"] = prereq_items(c["prerequisites"])


def build_plan(report, inventory=None, rua=None, ttl=DEFAULT_TTL):
    """The plan for a report. rua: the run's report address (collect.py's
    --rua-address, else the mailbox it reads the reports from): new records
    carry it (with mailto: added when it came without), and a record whose
    rua lacks it gets it appended - when it is one address (address_note
    says why not otherwise). Without it, new records take the rua most
    existing records use and nothing is appended."""
    dns_docs = report.get("dns") or {}
    if not dns_docs:
        raise ValueError("the report has no DNS section (run audit.py without --offline, or with domains)")
    inv_rows = {}
    for row in (inventory or {}).get("domains", []) if isinstance(inventory, dict) else (inventory or []):
        inv_rows[row["domain"]] = row
    report_addr = report_uri(rua)  # a derived address is no report address: nothing is appended without one
    rua_addr = report_addr or rua or derive_rua(dns_docs) or RUA_PLACEHOLDER
    all_domains = sorted(dns_docs)
    subs = subdomain_context(report, inv_rows, dns_docs)
    changes, holds, proposed = [], [], set()
    for domain in all_domains:
        c, h = plan_domain(domain, dns_docs[domain], report, inv_rows.get(domain), rua_addr, ttl, all_domains, subs,
                           report_addr)
        for change in c:  # an unaudited subdomain's record, proposed by two audited parents, is one row
            if change["domain"] != domain:
                if change["hostname"] in proposed:
                    continue
                proposed.add(change["hostname"])
            changes.append(change)
        holds += h
    changes.sort(key=lambda c: (c["priority"], c["zone_host"], c["domain"], c["hostname"]))
    for i, c in enumerate(changes, 1):
        c["id"] = "P-%02d" % i
    alternatives(changes)
    by_host = collections.OrderedDict()
    for c in changes:
        by_host.setdefault(c["zone_host"], []).append(c)
    return {"rua": rua_addr, "rua_is_placeholder": rua_addr == RUA_PLACEHOLDER, "report_address": report_addr,
            "ttl": ttl, "domains": all_domains, "changes": changes, "holds": holds,
            "by_zone_host": {k: [c["id"] for c in v] for k, v in by_host.items()},
            "source_report": report.get("generated_utc")}


# --------------------------------------------------------------------------
# rendering

KIND_LABEL = {"new": "publish", "modify": "change", "park": "park", "todo": "task", "ratchet": "enforcement step",
              "no_mail": "no mail measured"}
PRIORITY_LABEL = {1: "now - monitoring and hygiene (zero delivery risk), and quarantine where no mail is measured "
                     "(after its checks)",
                  2: "before enforcement - DKIM",
                  3: "enforcement - gated", 4: "subdomain policy - gated", 5: "final hardening - gated"}


def render_md(plan):
    L = []
    L.append("# DMARC rollout plan")
    L.append("")
    L.append("Generated from the audit report%s. Every change lists the current value and the rollback. "
             "Nothing here has been applied; the human applies each row through the normal DNS change process."
             % (" of " + plan["source_report"] if plan.get("source_report") else ""))
    L.append("")
    if plan["rua_is_placeholder"]:
        L.append("**Set the reporting address.** No existing record carried a rua, so new records use the placeholder "
                 "`%s`. Re-run with `--rua mailto:...` (your aggregate reporting tool's address, or a mailbox you own)." % RUA_PLACEHOLDER)
        L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| # | Domain | Zone host | Priority | Change |")
    L.append("|---|---|---|---|---|")
    for c in plan["changes"]:
        L.append("| %s | %s | %s | %d | %s: %s |" % (c["id"], c["domain"], c["zone_host"], c["priority"],
                                                    KIND_LABEL.get(c["kind"], c["kind"]), c["why"].split(":")[0][:80]))
    L.append("")
    if plan["holds"]:
        L.append("## Fix or decide first")
        L.append("")
        for h in plan["holds"]:
            L.append("- **%s**: %s" % (h["domain"], h["reason"]))
        L.append("")
    for prio in sorted({c["priority"] for c in plan["changes"]}):
        L.append("## Priority %d - %s" % (prio, PRIORITY_LABEL.get(prio, "")))
        L.append("")
        hosts = collections.OrderedDict()
        for c in plan["changes"]:
            if c["priority"] == prio:
                hosts.setdefault(c["zone_host"], []).append(c)
        for host, rows in hosts.items():
            L.append("### %s" % host)
            L.append("")
            L.append("| # | Record | Hostname | Value | TTL |")
            L.append("|---|---|---|---|---|")
            for c in rows:
                L.append("| %s | %s | `%s` | `%s` | %d |" % (c["id"], c["record"], c["hostname"], c["value"], c["ttl"]))
            L.append("")
            for c in rows:
                L.append("- **%s** %s - %s" % (c["id"], c["domain"], c["why"]))
                L.append("  - current: `%s`" % c["current"])
                L.append("  - rollback: %s" % c["rollback"])
                for p in c["prerequisites"]:
                    L.append("  - before applying: %s" % p)
                if c.get("human_summary"):
                    L.append("  - *in plain words:* %s" % c["human_summary"])
            L.append("")
    L.append("## How to use this")
    L.append("")
    L.append("Apply priority 1 as one change per zone host: its monitoring and hygiene rows touch no mail anyone "
             "legitimately sends today, and every new record starts reporting; a row that lists a check before "
             "applying (a lookup first, an external-destination record, the order of the rua addresses) waits on "
             "it. A no-mail-measured row is different: it quarantines a domain the run measured sending nothing, so "
             "it waits on the checks listed with it. Re-run the audit after reports have flowed "
             "for a week; the enforcement steps re-appear only when their prerequisites are met, and the "
             "plan regenerates from the new report. One ratchet per domain per week, and one change per "
             "record: rows that rewrite the same record say so.")
    L.append("")
    return "\n".join(L)


def write(plan, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.md").write_text(render_md(plan), encoding="utf-8")
    (out / "plan.json").write_text(json.dumps(plan, indent=1), encoding="utf-8")
    return out / "plan.md", out / "plan.json"


def main():
    ap = argparse.ArgumentParser(description="Turn an audit report into the DNS records to publish next.")
    ap.add_argument("report", help="report.json from src/audit.py")
    ap.add_argument("--inventory", help="inventory.json from src/discover.py (zone host per domain)")
    ap.add_argument("--rua", help="the run's report address, e.g. mailto:reports@example.com: new records carry it, "
                                  "and a record whose rua lacks it gets it appended")
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    ap.add_argument("--out", metavar="DIR", help="write plan.md and plan.json here (default: print plan.md)")
    ap.add_argument("--json", action="store_true", help="print plan.json instead of plan.md")
    args = ap.parse_args()
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8-sig"))
        inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8-sig")) if args.inventory else None
    except OSError as err:
        die("cannot read input: %s" % err)
    except json.JSONDecodeError as err:
        die("not valid JSON: %s" % err)
    if args.rua and not re.match(r"^mailto:[^@\s]+@[^@\s]+$", args.rua):
        die("--rua must look like mailto:name@example.com")
    try:
        plan = build_plan(report, inventory, args.rua, args.ttl)
    except ValueError as err:
        die(str(err))
    if args.out:
        md, js = write(plan, args.out)
        print("wrote %s and %s" % (md, js), file=sys.stderr)
    if args.json:
        print(json.dumps(plan, indent=1))
    elif not args.out:
        print(render_md(plan))


if __name__ == "__main__":
    main()
