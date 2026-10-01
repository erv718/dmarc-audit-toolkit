#!/usr/bin/env python3
"""Turn an audit report into a rollout plan: the exact records to publish.

Input is report.json from src/audit.py (optionally plus inventory.json from
src/discover.py for the zone host of every domain). Output is plan.md, in the
Record / Hostname / Value table form a DNS change ticket wants, grouped by
where each zone is hosted, plus plan.json for tools.

The rules are the methodology, encoded (docs/methodology.md):

  monitoring first     no DMARC record, or a subdomain inheriting nothing:
                       publish p=none with rua before anything else. A record
                       without rua gets rua added. Two records at one name
                       get collapsed - after an ownership check.
  SPF hygiene          no terminator or +all/?all becomes ~all; over the
                       lookup limit is a fix-first; at the limit is a freeze.
  parked domains       no mail in, no mail out, nothing signing: v=spf1 -all
                       and p=reject, once "unused" is verified.
  DKIM before reject   a domain that sends without a DKIM selector gets a
                       signing task before any enforcement step.
  one ratchet at a time
                       none -> quarantine pct=25 -> pct=100 -> reject ->
                       sp= -> SPF -all, each with the gate conditions the
                       report can and cannot prove.
  evidence holds       a mail log or aggregate reports showing a legitimate
                       sender still failing holds that domain's next
                       enforcement step, and says why.

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


# --------------------------------------------------------------------------
# evidence from the mail log and the aggregate reports

def evidence_for(report, domain):
    """What the report proves about this domain's legitimate senders."""
    ev = {"legit_failing": [], "spf_only": [], "has_maillog": False, "has_rua": False,
          "outbound_seen": None}
    ml = report.get("maillog") or {}
    if ml:
        ev["has_maillog"] = True
        scope = (ml.get("sender_domain") or "").lower()
        if not scope or domain == scope or domain.endswith("." + scope):
            by = (ml.get("counters") or {}).get("by_likely") or {}
            n = by.get("likely_misconfigured_sender", 0)
            if n:
                ev["legit_failing"].append("%d message(s) in the mail log failed from a sender that looks like your own misconfigured system, not a spoof" % n)
    rua = report.get("rua") or {}
    if rua:
        ev["has_rua"] = True
        for s in rua.get("failing_streams") or []:
            froms = [h.lower() for h in s.get("header_from") or []]
            if domain in froms and s.get("likely") == "likely_misconfigured_sender":
                ev["legit_failing"].append("aggregate reports: %s sends %d message(s) as %s and fails (%s)"
                                           % (s.get("source_ip"), s.get("count"), domain,
                                              "; ".join(s.get("likely_signals") or [])[:120]))
        for s in rua.get("spf_only_senders") or []:
            froms = [h.lower() for h in (s.get("header_from") or [])] if isinstance(s, dict) else []
            if not froms or domain in froms:
                ev["spf_only"].append(str(s.get("source_ip", s)) if isinstance(s, dict) else str(s))
    return ev


# --------------------------------------------------------------------------
# the plain-language layer (what src/next_steps.py reads)

PREREQ_KINDS = ("dkim_proof", "list_proof", "spf_budget", "evidence", "verify_unused", "reports", "other")
# first match wins, so the order matters: an evidence hold can mention DKIM and
# a DKIM prerequisite can mention forwarding
PREREQ_RULES = (
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
    """One plain sentence about a change for a reader who does not read DNS."""
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
        return "Publish a monitoring-only DMARC record for %s so its reports start flowing; no effect on delivery." % domain
    if kind == "modify":
        if is_spf:
            parts = value.split()
            return ("Change the end of the %s SPF record to %s so mail from unlisted servers is treated as suspicious "
                    "instead of ignored; listed senders are unaffected." % (domain, parts[-1] if parts else "~all"))
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

def plan_domain(domain, dns_doc, report, inventory_row, rua_addr, ttl, all_domains):
    """Changes and next steps for one domain. Returns (changes, holds)."""
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
    mailflow = (inventory_row or {}).get("mailflow") or {}
    outbound = mailflow.get("outbound") if mailflow else None
    ev = evidence_for(report, domain)
    hostname = "_dmarc." + domain
    subdomains = sorted(d for d in all_domains if d != domain and d.endswith("." + domain))

    def add(kind, priority, record, host, value, current, rollback, why, prereqs=(), fids=()):
        c = {"domain": domain, "zone": zone, "zone_host": zone_host, "kind": kind,
             "priority": priority, "record": record, "hostname": host, "value": value,
             "ttl": ttl, "current": current, "rollback": rollback, "why": why,
             "prerequisites": list(prereqs), "finding_ids": sorted(set(fids)),
             "owner_hint": domain, "prerequisite_items": prereq_items(list(prereqs))}
        c["human_summary"] = human_summary(c)
        changes.append(c)

    # Not verified: do not plan against a guess.
    if dns_doc.get("dmarc_status") == "error" or spf_status == "error":
        holds.append({"domain": domain, "reason": "DNS could not be verified for this domain in this run - re-run before planning changes"})
        return changes, holds
    if dns_doc.get("dmarc_status") == "found" and not dmarc:
        holds.append({"domain": domain, "reason": "a DMARC record was found at %s but its text is missing from the report - re-run the audit before planning this domain" % (dns_doc.get("dmarc_source") or hostname)})
        return changes, holds

    # --- parked domain: nothing in, nothing out, nothing signing -------------
    sends = spf_sends(spf) or bool(selectors) or (outbound or 0) > 0
    parked_candidate = (not has_mx) and not sends
    if parked_candidate and (outbound is None):
        parked_note = "verify unused first: no outbound mail in 30 days (discover.py --mailflow), no passing volume in aggregate reports, no owner objects"
    else:
        parked_note = "verified unused: no outbound mail in 30 days, no passing aggregate volume"

    # --- monitoring first --------------------------------------------------
    if "DMARC-005" in ids:
        holds.append({"domain": domain, "reason": "two DMARC records at %s - receivers apply no policy and send no reports; find out who published the second record before collapsing to one" % hostname})
    elif not dmarc or "DMARC-001" in ids or (inherited and policy in (None, "none")):
        if parked_candidate:
            add("park", 1, "TXT", hostname, "v=DMARC1; p=reject; rua=%s;" % rua_addr, "none",
                "delete the record", "parked domain: nothing sends as it, so reject spoofing outright and keep rua to see attempts",
                [parked_note], ids & {"DMARC-001", "DMARC-002"})
        else:
            why = ("subdomain inherits sp=%s from %s - an explicit record starts its own reporting and shields it from a later sp= change"
                   % (dmarc_tags((report.get("dns") or {}).get(dns_doc.get("dmarc_source") or "", {}).get("dmarc")).get("sp", "none"), dns_doc.get("dmarc_source"))
                   if inherited else "no DMARC record: no policy and no reporting - monitoring starts here")
            add("new", 1, "TXT", hostname, "v=DMARC1; p=none; rua=%s;" % rua_addr, "none", "delete the record", why, (),
                ids & {"DMARC-001", "DMARC-002"})
    elif "DMARC-003" in ids:
        add("modify", 1, "TXT", hostname, with_rua(dmarc, rua_addr), dmarc, "publish the current string verbatim",
            "the record has no rua - failures are invisible until reports flow", (), {"DMARC-003"})

    # --- SPF hygiene --------------------------------------------------------
    if "SPF-007" in ids:
        holds.append({"domain": domain, "reason": "more than one SPF record at %s - receivers return permerror; collapse to one after checking who published each" % domain})
    elif "SPF-001" in ids or not spf:
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
    sends_real = spf_sends(spf) or (outbound or 0) > 0
    if sends_real and dkim_status == "absent" and not parked_candidate:
        add("todo", 2, "CNAME/TXT", "<selector>._domainkey." + domain, "<generated by the sending platform>", "none",
            "delete the selector records",
            "the domain sends but no DKIM selector was found: SPF-only authentication breaks on forwarding and lists; enable signing at every platform that sends as %s (Microsoft 365: selector1/selector2 CNAMEs; Google Workspace: the google selector; ESPs: their CNAME pair)" % domain,
            ["one live header per sender showing dkim=pass with d=%s (src/headers.py)" % domain], {"DKIM-002"})

    # --- the ratchet, one step at a time ----------------------------------------
    hold_reasons = list(ev["legit_failing"])
    if ev["spf_only"] and policy in ("quarantine",):
        hold_reasons.append("SPF-only aligned senders in the aggregate reports (%s): they break on forwarding at reject" % ", ".join(ev["spf_only"][:5]))
    if not (ev["has_maillog"] or ev["has_rua"]):
        gate_note = "no failure evidence in this run - supply --maillog and/or --rua before applying any enforcement step"
    else:
        gate_note = None

    pct = int(tags.get("pct", "100") or 100) if tags.get("pct", "100").isdigit() else 100
    if dmarc and "DMARC-005" not in ids and not inherited:
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
            without_own = [s for s in subdomains
                           if (report.get("dns") or {}).get(s, {}).get("inherited")
                           or not (report.get("dns") or {}).get(s, {}).get("dmarc")]
            if without_own:
                holds.append({"domain": domain, "reason": "subdomains %s have no records of their own - publish their monitoring records (above) before touching sp= on the apex" % ", ".join(without_own[:6])})
            add("ratchet", 3, "TXT", hostname, set_tag(dmarc, "p", "reject"), dmarc, "publish the current string verbatim",
                "quarantine at 100 percent is stable: reject refuses failing mail instead of junking it; sp stays as is, its own step comes next",
                [p for p in ["every legitimate sender proven with an aligned DKIM header within 7 days",
                             "no list or forwarder path for your own senders still failing (delivered_twin.kql; a canary post)",
                             "SPF at 9 lookups or fewer", gate_note] if p] + hold_reasons)
        elif policy == "reject":
            sp = tags.get("sp")
            if subdomains and sp in (None, "none"):
                add("ratchet", 4, "TXT", hostname, set_tag(dmarc, "sp", "quarantine"), dmarc, "publish the current string verbatim",
                    "the apex is at reject but subdomains without records inherit %s - quarantine them once each real subdomain has its own record" % (sp or "p"),
                    ["every subdomain that sends has its own _dmarc record (the monitoring records above)"] + hold_reasons)
            elif sp == "quarantine":
                add("ratchet", 4, "TXT", hostname, set_tag(dmarc, "sp", "reject"), dmarc, "publish the current string verbatim",
                    "final subdomain step", ["a week of subdomain reports at sp=quarantine showing only spoofing"])
            elif term == "~all" and spf_sends(spf):
                add("ratchet", 5, "TXT", domain, spf_with_terminator(spf, "-all"), spf, "publish the current string verbatim",
                    "last hardening: SPF hard fail, only after reject has been stable and every sender is DKIM-signed",
                    ["reject stable for 30 days", "every sender DKIM-signed and aligned (SPF -all breaks SPF-only senders on forwarding)"])
    if "SPF-005" in ids:
        holds.append({"domain": domain, "reason": "SPF is at the 10-lookup limit: no new include for any reason; new senders authenticate with DKIM"})
    return changes, holds


def build_plan(report, inventory=None, rua=None, ttl=DEFAULT_TTL):
    dns_docs = report.get("dns") or {}
    if not dns_docs:
        raise ValueError("the report has no DNS section (run audit.py without --offline, or with domains)")
    inv_rows = {}
    for row in (inventory or {}).get("domains", []) if isinstance(inventory, dict) else (inventory or []):
        inv_rows[row["domain"]] = row
    rua_addr = rua or derive_rua(dns_docs) or RUA_PLACEHOLDER
    all_domains = sorted(dns_docs)
    changes, holds = [], []
    for domain in all_domains:
        c, h = plan_domain(domain, dns_docs[domain], report, inv_rows.get(domain), rua_addr, ttl, all_domains)
        changes += c
        holds += h
    changes.sort(key=lambda c: (c["priority"], c["zone_host"], c["domain"], c["hostname"]))
    for i, c in enumerate(changes, 1):
        c["id"] = "P-%02d" % i
    by_host = collections.OrderedDict()
    for c in changes:
        by_host.setdefault(c["zone_host"], []).append(c)
    return {"rua": rua_addr, "rua_is_placeholder": rua_addr == RUA_PLACEHOLDER, "ttl": ttl,
            "domains": all_domains, "changes": changes, "holds": holds,
            "by_zone_host": {k: [c["id"] for c in v] for k, v in by_host.items()},
            "source_report": report.get("generated_utc")}


# --------------------------------------------------------------------------
# rendering

KIND_LABEL = {"new": "publish", "modify": "change", "park": "park", "todo": "task", "ratchet": "enforcement step"}
PRIORITY_LABEL = {1: "now - monitoring and hygiene, zero delivery risk", 2: "before enforcement - DKIM",
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
    L.append("Apply priority 1 as one change per zone host: none of it changes what any receiver does with "
             "mail today, and every new record starts reporting. Re-run the audit after reports have flowed "
             "for a week; the enforcement steps re-appear only when their prerequisites are met, and the "
             "plan regenerates from the new report. One ratchet per domain per week.")
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
    ap.add_argument("--rua", help="reporting address for new records, e.g. mailto:reports@example.com")
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
