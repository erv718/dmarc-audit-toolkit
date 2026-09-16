"""Multi-domain DNS posture audit for a DMARC program.

For every domain you give it, reports:
  - SPF: present, terminator strength, DNS lookup count vs the limit of 10
  - DMARC: the record that applies (the name's own, or inherited from the
    closest ancestor up to the organizational domain), effective policy,
    subdomain policy, sampling rate, reporting addresses
  - DKIM: which common (or supplied) selectors resolve
  - MX: where mail is received, including a null MX

This is the tool that finds the subdomain nobody remembered - the one with no
DKIM, no DMARC record, and a spoofing campaign already using it.

Usage:
    python dns_audit.py example.com mail.example.com sub.example.com
    python dns_audit.py --file domains.txt --json
    python dns_audit.py example.com --selectors mail,sig1 --selectors-file selectors.txt

Exit codes: 0 clean, 1 at least one major or blocking finding, 2 usage or
input error. Informational findings never set exit 1.

Read-only. Queries public DNS, falls back to DNS-over-HTTPS when port 53 is
filtered (corporate networks produce SERVFAILs that look exactly like missing
records - do not diagnose a broken zone from one resolver path). Every answer
records which path produced it, so a "missing" verdict can be traced.
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request

try:
    import dns.exception
    import dns.resolver
except ImportError:
    dns = None

import spf_lookups
from spf_lookups import get_spf, walk, LIMIT

# Selectors worth probing: Microsoft 365, Google, common ESP defaults.
COMMON_SELECTORS = ["selector1", "selector2", "google", "s1", "s2", "k1", "k2", "everlytickey1", "dkim"]

# Two-level public suffixes under which the organizational domain is three labels.
# Deliberately small: the DMARC walk stops here, it never queries _dmarc.co.uk.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "net.nz", "org.nz", "co.za", "org.za",
    "com.mx", "com.ar", "com.cn", "net.cn", "org.cn", "co.in", "com.sg",
    "com.hk", "com.tw", "co.kr", "com.tr", "com.my", "co.id", "com.sa",
}

DOH_URL = "https://dns.google/resolve"
DOH_TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
SEVERITY_RANK = {"info": 0, "minor": 1, "major": 2, "blocking": 3}
P53_SKIP_AFTER = 2      # names that timed out on port 53 in a row before it is skipped
P53_SKIP_SECONDS = 600  # how long port 53 stays skipped (long-lived MCP process)
CANARY = "zz-provenance-canary-zz"

# Process-wide resolver-path state: one-time notices, port-53 skip window.
_net = {"doh_notice": False, "p53_timeouts": 0, "p53_skip_until": 0.0}


# ---------------------------------------------------------------- resolving

def _norm(rtype, value):
    """Normalize one rdata string so both resolver paths produce the same text."""
    value = value.strip()
    if rtype == "TXT":
        return value.strip('"').replace('" "', "")
    if rtype == "MX":
        pref, _, target = value.partition(" ")
        target = target.strip()
        return f"{pref} {target if target == '.' else target.rstrip('.')}"
    return value.rstrip(".")


def doh_ex(name, rtype):
    """DNS-over-HTTPS lookup. Returns (records, meta); meta.status is found|absent|error."""
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        return [], {"path": "doh", "ttl": None, "status": "error", "err": exc.__class__.__name__}
    rcode = data.get("Status")
    if rcode == 3:  # NXDOMAIN
        return [], {"path": "doh", "ttl": None, "status": "absent"}
    if rcode != 0:
        return [], {"path": "doh", "ttl": None, "status": "error", "err": f"rcode {rcode}"}
    want = DOH_TYPES.get(rtype)
    answers = [a for a in data.get("Answer", []) if want is None or a.get("type") == want]
    records = [_norm(rtype, a.get("data", "")) for a in answers]
    ttls = [a["TTL"] for a in answers if isinstance(a.get("TTL"), int)]
    return records, {"path": "doh", "ttl": min(ttls) if ttls else None,
                     "status": "found" if records else "absent"}


def doh(name, rtype):
    return doh_ex(name, rtype)[0]


def _port53(resolver, name, rtype, tcp):
    """One port-53 attempt. status is found|absent|timeout|error."""
    path = "port53-tcp" if tcp else "port53-udp"
    try:
        ans = resolver.resolve(name, rtype, tcp=tcp)
    except Exception as exc:
        if dns is not None and isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
            return [], {"path": path, "ttl": None, "status": "absent"}
        if dns is not None and isinstance(exc, dns.exception.Timeout):
            return [], {"path": path, "ttl": None, "status": "timeout"}
        return [], {"path": path, "ttl": None, "status": "error", "err": exc.__class__.__name__}
    if rtype == "TXT":
        records = [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    else:
        records = [_norm(rtype, str(r)) for r in ans]
    return records, {"path": path, "ttl": getattr(ans.rrset, "ttl", None), "status": "found"}


def _p53_failed(resolver, name, meta):
    """Port 53 gave no answer: say so once, and stop waiting on it after repeats."""
    ns = (getattr(resolver, "nameservers", None) or ["?"])[0]
    why = meta.get("err") or meta["status"]
    if not _net["doh_notice"]:
        _net["doh_notice"] = True
        print(f"note: port 53 to {ns} failed for {name} ({why}) - falling back to DNS-over-HTTPS"
              f" via dns.google; slow progress here is the port-53 wait, not a hang",
              file=sys.stderr, flush=True)
    if meta["status"] != "timeout":
        return
    _net["p53_timeouts"] += 1
    if _net["p53_timeouts"] >= P53_SKIP_AFTER:
        _net["p53_timeouts"] = 0
        _net["p53_skip_until"] = time.time() + P53_SKIP_SECONDS
        print(f"note: port 53 to {ns} timed out {P53_SKIP_AFTER} names in a row - using DNS-over-HTTPS"
              f" only for the next {P53_SKIP_SECONDS // 60} minutes", file=sys.stderr, flush=True)


def resolve_ex(resolver, name, rtype):
    """Port 53 first, DoH as the cross-check. Returns (records, meta).

    meta: path (port53-udp | port53-tcp | doh), ttl, status (found | absent |
    error), plus xchk when a negative answer was cross-checked on the other
    path and err when nothing answered. A negative port-53 answer is always
    cross-checked over DoH: interception fakes NXDOMAIN as easily as SERVFAIL.
    """
    p53 = None
    if resolver is not None and time.time() >= _net["p53_skip_until"]:
        for tcp in (False, True):
            recs, p53 = _port53(resolver, name, rtype, tcp)
            if p53["status"] in ("found", "absent"):
                break
        if p53["status"] == "found":
            _net["p53_timeouts"] = 0
            return recs, p53
        if p53["status"] == "absent":
            _net["p53_timeouts"] = 0
        else:
            _p53_failed(resolver, name, p53)
    recs, meta = doh_ex(name, rtype)
    if p53 is None or p53["status"] != "absent":
        return recs, meta  # DoH is the only answer we have
    if meta["status"] == "found":  # port 53 said no, DoH says yes: interception smell
        meta["xchk"] = p53["path"] + ":absent"
        return recs, meta
    p53["xchk"] = "doh:" + meta["status"]
    return [], p53


def resolve(resolver, name, rtype):
    """Port 53 first, DoH as the cross-check. Records only; see resolve_ex for the path."""
    return resolve_ex(resolver, name, rtype)[0]


# ---------------------------------------------------------------- parsing

def parse_dmarc(txt):
    tags = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def org_domain(domain):
    """Registrable-looking apex: last two labels, or three under a known two-level suffix."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def dmarc_candidates(domain):
    """_dmarc names to try, the name itself first, then each ancestor up to the apex."""
    labels = domain.split(".")
    depth = len(org_domain(domain).split("."))
    return [f"_dmarc.{'.'.join(labels[i:])}" for i in range(0, len(labels) - depth + 1)]


def find_dmarc(domain, q):
    """Walk up to the closest _dmarc record.

    Returns (source, txts, inherited, status, own_status). status is found |
    absent | error (error: nothing found and at least one lookup failed).
    """
    own_status = None
    errored = False
    for i, name in enumerate(dmarc_candidates(domain)):
        recs, status = q(name, "TXT")
        if i == 0:
            own_status = status
        txts = [t for t in recs if t.lower().startswith("v=dmarc1")]
        if txts:
            return name, txts, i > 0, "found", own_status
        if status == "error":
            errored = True
    return None, [], False, ("error" if errored else "absent"), own_status


def _is_dkim(txt):
    low = txt.lower().strip()
    return low.startswith("v=dkim1") or re.search(r"(^|;)\s*p=", low) is not None


def _spf_evidence(domain, status, ev):
    """Turn whatever get_spf_status hands back into evidence entries shaped like ours."""
    out = []
    for item in (ev if isinstance(ev, list) else [ev]):
        if isinstance(item, dict):
            out.append(dict({"name": domain, "type": "TXT", "path": None, "ttl": None, "status": status}, **item))
            continue
        note = str(item).strip()
        head = note.split(" ", 1)[0] if note else ""
        path = head if head in ("port53-udp", "port53-tcp", "doh") and status != "error" else None
        out.append({"name": domain, "type": "TXT", "path": path, "ttl": None, "status": status,
                    "note": note or None, "src": "spf_lookups"})
    return out


def _spf_status(domain, resolver, q):
    """(record, status, evidence). Uses spf_lookups.get_spf_status when it exists."""
    try:
        fn = spf_lookups.get_spf_status
    except AttributeError:
        fn = None
    if fn is not None:
        record, status, ev = fn(domain, resolver)
        return record, status, _spf_evidence(domain, status, ev)
    recs, status = q(domain, "TXT")
    if status == "error":
        return None, "error", None
    record = next((t for t in recs if t.lower().startswith("v=spf1")), None)
    return record, ("found" if record else "absent"), None


def worst_severity(findings):
    return max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)


def exit_code(findings):
    return 1 if any(f["severity"] in ("major", "blocking") for f in findings) else 0


# ---------------------------------------------------------------- audit

def audit_domain(domain, resolver, extra_selectors=None):
    domain = domain.strip().lower().rstrip(".")
    evidence = []
    findings = []

    def q(name, rtype):
        recs, meta = resolve_ex(resolver, name, rtype)
        entry = {"name": name, "type": rtype, "path": meta.get("path"), "ttl": meta.get("ttl"),
                 "status": meta["status"]}
        for k in ("xchk", "err"):
            if meta.get(k):
                entry[k] = meta[k]
        evidence.append(entry)
        return recs, meta["status"]

    def add(fid, severity, area, title, seen, action, verified=True):
        findings.append({"id": fid, "severity": severity, "area": area, "title": title,
                         "evidence": seen, "action": action, "verified": verified})

    # --- SPF
    spf, spf_status, spf_ev = _spf_status(domain, resolver, q)
    if spf_ev:
        evidence.extend(spf_ev if isinstance(spf_ev, list) else [spf_ev])
    lookups = 0
    terminator = None
    if spf_status == "error":
        add("SPF-002", "major", "spf", "SPF lookup failed - not verified",
            f"TXT lookup for {domain} failed on every resolver path",
            "re-run from a network with working DNS, or query the TXT record by another path, before concluding anything about SPF",
            verified=False)
    elif spf:
        lookups = sum(1 for _, _, _, billable in walk(domain, resolver) if billable)
        terminator = spf.split()[-1] if spf.split() else "?"
        if terminator.lower() not in ("-all", "~all") and not terminator.lower().startswith("redirect="):
            add("SPF-003", "major", "spf", f"SPF terminator is '{terminator}' - effectively no protection",
                spf, "end the record with -all (or ~all while senders are still being inventoried)")
        if lookups > LIMIT:
            add("SPF-004", "blocking", "spf", f"SPF over the {LIMIT}-lookup limit ({lookups}) - PERMERROR",
                f"{lookups} DNS-querying mechanisms after expanding includes",
                "receivers return PERMERROR and DMARC fails on SPF for every message: remove or flatten includes now, authenticate senders with DKIM")
        elif lookups == LIMIT:
            add("SPF-005", "major", "spf", f"SPF at the {LIMIT}-lookup limit - no room for another vendor",
                f"{lookups} DNS-querying mechanisms after expanding includes",
                "do not add another include; onboard new senders with DKIM and prune includes nobody uses")
        elif lookups == LIMIT - 1:
            add("SPF-006", "minor", "spf", "SPF one include away from the limit - new senders need DKIM",
                f"{lookups} DNS-querying mechanisms after expanding includes",
                "plan the next sender on DKIM, not an SPF include")
    else:
        add("SPF-001", "major", "spf", "no SPF record",
            f"no v=spf1 TXT at {domain}",
            "publish v=spf1 listing the domain's senders and ending in -all; a non-sending name gets 'v=spf1 -all'")

    # --- DMARC (the name's own record, else the closest ancestor up to the apex)
    source, txts, inherited, dmarc_status, own_status = find_dmarc(domain, q)
    dmarc = parse_dmarc(txts[0]) if txts else None
    effective = None
    if dmarc is not None:
        if inherited:
            effective = (dmarc.get("sp") or dmarc.get("p", "none")).lower()
        else:
            effective = dmarc.get("p", "none").lower()
    tried = ", ".join(dmarc_candidates(domain))
    if dmarc_status == "error":
        add("DMARC-006", "major", "dmarc", "DMARC lookup failed - not verified",
            f"TXT lookup failed on every resolver path for: {tried}",
            "re-run from a network with working DNS before concluding anything about DMARC",
            verified=False)
    elif dmarc is None:
        add("DMARC-001", "major", "dmarc", "NO DMARC RECORD - no policy, no reporting, invisible to you",
            f"no v=DMARC1 TXT at any of: {tried}",
            f"publish TXT at _dmarc.{org_domain(domain)} 'v=DMARC1; p=none; rua=mailto:<aggregate reports address>' to start reporting, then ratchet the policy")
    else:
        if len(txts) > 1:
            add("DMARC-005", "major", "dmarc", f"multiple DMARC records at {source} - receivers treat this as no policy",
                f"{len(txts)} v=DMARC1 TXT records", f"remove all but one v=DMARC1 TXT at {source}")
        if inherited and own_status == "error":
            add("DMARC-007", "minor", "dmarc", f"_dmarc.{domain} lookup failed - inheritance from {source} assumed, not verified",
                f"own lookup errored, {source} answered", "re-check _dmarc." + domain + " by another path",
                verified=False)
        if effective == "none":
            if inherited:
                how = f"sp=none on {source}" if "sp" in dmarc else f"p=none on {source}, no sp="
                add("DMARC-002", "minor", "dmarc", f"DMARC effective policy none - inherited ({how}) - monitoring only",
                    txts[0], f"set sp=quarantine or sp=reject on {source}, or publish a record at _dmarc.{domain}, once deduplicated failures are understood")
            else:
                add("DMARC-002", "minor", "dmarc", "DMARC p=none - monitoring only", txts[0],
                    "move to p=quarantine once deduplicated failures are understood, then p=reject")
        if "rua" not in dmarc:
            where = f" (record at {source})" if inherited else ""
            add("DMARC-003", "major", "dmarc", f"DMARC has no rua{where} - failures are invisible to you", txts[0],
                f"add rua=mailto:<aggregate reports address> to the record at {source}")
        if not inherited and dmarc.get("p", "").lower() in ("quarantine", "reject") and "sp" not in dmarc:
            add("DMARC-004", "info", "dmarc", "no explicit sp= - subdomains inherit p; make sure that is intentional",
                txts[0], "add sp=reject if subdomains never send, or confirm inheriting p is what you want")
        pct = dmarc.get("pct", "100")
        if pct.isdigit() and int(pct) < 100 and effective != "none":
            add("DMARC-008", "info", "dmarc", f"DMARC pct={pct} - policy applies to a sample of failing mail only",
                txts[0], "raise pct to 100 when the ratchet step is complete")

    # --- DKIM. Wildcard guard: if a random selector "resolves", every probe
    # below is meaningless and DKIM presence cannot be inferred from DNS at all.
    canary = f"{CANARY}._domainkey.{domain}"
    wildcarded = bool(q(canary, "CNAME")[0] or q(canary, "TXT")[0])
    probed = list(COMMON_SELECTORS)
    for sel in (extra_selectors or []):
        sel = sel.strip().lower().rstrip(".")
        if sel and sel not in probed:
            probed.append(sel)
    selectors, dangling = [], []
    for sel in ([] if wildcarded else probed):
        name = f"{sel}._domainkey.{domain}"
        cname = q(name, "CNAME")[0]
        keyed = any(_is_dkim(t) for t in q(name, "TXT")[0])
        if keyed:
            selectors.append(sel)
        elif cname:
            dangling.append(sel)  # CNAME exists, target has no key: removed vendor key or takeover bait
    custom = len(probed) - len(COMMON_SELECTORS)
    if wildcarded:
        add("DKIM-001", "info", "dkim", "wildcard at _domainkey - selector probing unreliable, verify DKIM from message headers",
            f"{canary} resolved", "read the s= tag from a live DKIM-Signature header and confirm that selector by hand",
            verified=False)
    elif not selectors:
        what = f"none of the {len(probed)} probed DKIM selectors found" if custom else "no common DKIM selector found"
        add("DKIM-002", "minor", "dkim", f"{what} - domain may authenticate on SPF alone, which breaks on forwarding",
            "probed: " + ", ".join(probed),
            "take the selector from a live DKIM-Signature header and pass it with --selectors; if there is none, set up DKIM for every sender",
            verified=False)
    if dangling:
        add("DKIM-003", "minor", "dkim", "DKIM selector CNAME with no key at the target: " + ", ".join(dangling),
            ", ".join(f"{s}._domainkey.{domain}" for s in dangling),
            "confirm with the vendor whether the key was retired; remove the CNAME if nothing signs with it")

    # --- MX
    mx, mx_status = q(domain, "MX")
    mx_null = bool(mx) and all(m.split()[-1] == "." for m in mx)

    return {"domain": domain,
            "spf": spf, "spf_status": spf_status, "spf_terminator": terminator, "spf_lookups": lookups,
            "dmarc": txts[0] if txts else None, "dmarc_source": source, "effective_policy": effective,
            "inherited": inherited, "dmarc_status": dmarc_status,
            "dkim_selectors": selectors, "dkim_probed": probed, "dkim_dangling": dangling, "dkim_wildcard": wildcarded,
            "mx": mx, "mx_null": mx_null, "mx_status": mx_status,
            "flags": [f["title"] for f in findings], "findings": findings, "evidence": evidence}


# ---------------------------------------------------------------- cli

def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def read_list(path):
    """One entry per line; blanks and # comments skipped. Exit 2 if unreadable."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    except OSError as exc:
        die(f"cannot read {path}: {exc.strerror or exc}")


def _mx_line(r):
    if r["mx_status"] == "error":
        return "LOOKUP FAILED - not verified"
    if r["mx_null"]:
        return "null MX - domain declares it receives no mail"
    if not r["mx"]:
        return "none (no MX record)"
    ordered = sorted(r["mx"], key=lambda m: int(m.split()[0]) if m.split()[0].isdigit() else 999)
    return ", ".join(ordered[:3]) + (f" (+{len(ordered) - 3} more)" if len(ordered) > 3 else "")


def print_report(r):
    print(f"=== {r['domain']} ===")
    if r["spf_status"] == "error":
        spf_line = "LOOKUP FAILED - not verified"
    elif r["spf"]:
        spf_line = f"yes, {r['spf_lookups']}/{LIMIT} lookups, {r['spf_terminator']}"
    else:
        spf_line = "MISSING"
    print(f"  SPF   : {spf_line}")

    if r["dmarc_status"] == "error":
        dmarc_line = "LOOKUP FAILED - not verified"
    elif not r["dmarc"]:
        apex = org_domain(r["domain"])
        dmarc_line = "MISSING" + (f" (none at any ancestor up to {apex})" if apex != r["domain"] else "")
    elif r["inherited"]:
        dmarc_line = f"inherited from {r['dmarc_source']} (effective policy {r['effective_policy']}): {r['dmarc']}"
    else:
        dmarc_line = r["dmarc"]
    print(f"  DMARC : {dmarc_line}")

    if r["dkim_wildcard"]:
        dkim_line = "unknown (wildcard at _domainkey)"
    elif r["dkim_selectors"]:
        dkim_line = ", ".join(r["dkim_selectors"])
    elif len(r["dkim_probed"]) > len(COMMON_SELECTORS):
        dkim_line = f"none of {len(r['dkim_probed'])} probed selectors found"
    else:
        dkim_line = "no common selectors found"
    if r["dkim_dangling"]:
        dkim_line += " (dangling CNAME: " + ", ".join(r["dkim_dangling"]) + ")"
    print(f"  DKIM  : {dkim_line}")
    print(f"  MX    : {_mx_line(r)}")
    for f in r["findings"]:
        print(f"  !! [{f['severity']}] {f['title']}" + ("" if f["verified"] else " (not verified)"))
        print(f"       fix: {f['action']}")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*")
    ap.add_argument("--file", help="file with one domain per line")
    ap.add_argument("--resolver", default="8.8.8.8")
    ap.add_argument("--selectors", help="comma-separated DKIM selectors to probe in addition to the common list")
    ap.add_argument("--selectors-file", help="file with one DKIM selector per line, probed in addition to the common list")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        domains += read_list(args.file)
    domains = [d.strip().lower().rstrip(".") for d in domains]
    domains = [d for d in domains if d]
    if not domains:
        ap.error("no domains given")
    bad = [d for d in domains if not re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*", d)]
    if bad:
        die("not a domain name: " + ", ".join(bad))

    extra = []
    if args.selectors:
        extra += [s.strip() for s in args.selectors.split(",")]
    if args.selectors_file:
        extra += read_list(args.selectors_file)

    resolver = None
    if dns is not None:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [args.resolver]
        resolver.lifetime = 10

    results = [audit_domain(d, resolver, extra) for d in domains]
    all_findings = [dict(f, domain=r["domain"]) for r in results for f in r["findings"]]
    code = exit_code(all_findings)
    actionable = sum(1 for f in all_findings if f["severity"] in ("major", "blocking"))

    if args.json:
        print(json.dumps({"domains": results, "findings": all_findings,
                          "summary": {"domains": len(results), "findings": len(all_findings),
                                      "actionable": actionable, "worst": worst_severity(all_findings),
                                      "exit_code": code}}, indent=1))
        sys.exit(code)

    for r in results:
        print_report(r)
    print(f"{len(results)} domains audited, {len(all_findings)} findings, {actionable} major or blocking")
    sys.exit(code)


if __name__ == "__main__":
    main()
