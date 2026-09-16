"""Count the DNS lookups an SPF record costs, against the RFC 7208 limit of 10.

Why this matters
----------------
SPF evaluation is capped at 10 DNS-querying mechanisms. Exceed it and the
result is PERMERROR, which most receivers treat as a failure - for the whole
domain, every message, immediately. Domains drift toward the limit one vendor
at a time and nobody notices until the record breaks.

Mechanisms that cost a lookup: include, a, mx, ptr, exists, redirect.
Mechanisms that cost nothing: ip4, ip6, all.

A lookup that fails is reported as FAILED, never as "no SPF record". Port 53
interception produces SERVFAILs that look identical to a missing record, so a
negative answer is cross-checked over DNS-over-HTTPS before it is believed,
and "absent" is only ever said after an authoritative NOERROR or NXDOMAIN.

Usage
-----
    python spf_lookups.py example.com [more.example.com ...]
    python spf_lookups.py --json example.com

Exit codes: 0 clean, 1 at or over the limit (or no SPF record), 2 lookup
failed or bad input.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

try:
    import dns.resolver  # dnspython
    _NEGATIVE = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)  # authoritative "nothing here"
except ImportError:  # pragma: no cover
    dns = None
    _NEGATIVE = ()

COSTLY = ("include:", "redirect=", "a:", "mx:", "ptr:", "exists:")
LIMIT = 10
DOH_URL = "https://dns.google/resolve"
DOH_TIMEOUT = 20
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_doh_noticed = False


def _describe(exc):
    """Short single-line reason for a failed lookup."""
    name = type(exc).__name__
    if name in ("Timeout", "LifetimeTimeout"):
        return "timeout"
    if name == "NoNameservers":  # dnspython: every server errored; say how, not who
        seen = []
        for err in getattr(exc, "kwargs", {}).get("errors") or []:
            what = err[3] if len(err) > 3 else None
            what = what if isinstance(what, str) and what else (
                type(what).__name__ if what is not None else "no response")
            if what not in seen:
                seen.append(what)
        return "NoNameservers (" + ", ".join(seen or ["SERVFAIL or REFUSED"]) + ")"
    lines = str(exc).strip().splitlines()
    msg = lines[0][:100] if lines else ""
    return f"{name}: {msg}" if msg else name


def _pick_spf(records):
    for txt in records:
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def _doh_notice(domain, why):
    """One line on stderr the first time we go over HTTPS, so a slow fallback
    does not look like a hang."""
    global _doh_noticed
    if not _doh_noticed:
        _doh_noticed = True
        print(f"note: {why} for {domain}, querying DNS-over-HTTPS "
              f"(dns.google, up to {DOH_TIMEOUT}s per lookup)", file=sys.stderr)


def _doh_txt_status(domain):
    """Resolve TXT over DNS-over-HTTPS.

    Returns (records, note): records is a list on NOERROR and None otherwise;
    note names the rcode, or what failed.
    """
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": domain, "type": "TXT"})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=DOH_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        return None, "unreachable (" + _describe(exc) + ")"
    if not isinstance(data, dict):
        return None, "malformed response"
    rcode = data.get("Status")
    if rcode != 0:
        return None, _RCODES.get(rcode, f"rcode {rcode}")
    return [a.get("data", "").strip('"').replace('" "', "")
            for a in data.get("Answer", []) if a.get("type", 16) == 16], "NOERROR"


def _doh_txt(domain):
    """Old helper, kept for callers: TXT strings over DoH, or None."""
    return _doh_txt_status(domain)[0]


def get_spf_status(domain, resolver):
    """Fetch a domain's SPF record and say how sure we are.

    Returns (record, status, evidence):
      "found"  - record is the v=spf1 TXT; evidence names the path that answered
      "absent" - an authoritative NOERROR/NXDOMAIN carried no v=spf1 TXT
      "error"  - every path failed; nothing can be concluded about the zone
    Port 53 first (UDP, then TCP). DNS-over-HTTPS cross-checks a negative
    answer and is the fallback when port 53 fails outright.
    """
    failures = []
    negative = None
    if resolver is not None:
        for use_tcp in (False, True):
            path = "port53-tcp" if use_tcp else "port53-udp"
            try:
                answers = resolver.resolve(domain, "TXT", tcp=use_tcp)
            except _NEGATIVE as exc:
                rcode = "NXDOMAIN" if isinstance(exc, dns.resolver.NXDOMAIN) else "NOERROR, no TXT"
                negative = f"{path} {rcode}"
                break
            except Exception as exc:
                failures.append(f"{path} {_describe(exc)}")
                continue
            records = [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
            spf = _pick_spf(records)
            if spf:
                return spf, "found", path
            return None, "absent", f"{path} NOERROR, {len(records)} TXT, none v=spf1"

    if resolver is None:
        prior, why = ["no dnspython"], "dnspython is not installed"
    elif negative:
        prior, why = [negative], negative
    else:
        prior, why = failures, "port 53 failed (" + "; ".join(failures) + ")"
    _doh_notice(domain, why)
    records, note = _doh_txt_status(domain)
    if records is not None:
        spf = _pick_spf(records)
        if spf:
            return spf, "found", "doh (" + "; ".join(prior) + ")"
        return None, "absent", "; ".join(prior + [f"doh NOERROR, {len(records)} TXT, none v=spf1"])
    if note == "NXDOMAIN":
        return None, "absent", "; ".join(prior + ["doh NXDOMAIN"])
    if negative:  # port 53 was authoritative; DoH just could not confirm it
        return None, "absent", "; ".join(prior + [f"doh {note} - not cross-checked"])
    return None, "error", "; ".join(prior + [f"doh {note}"])


def get_spf(domain, resolver):
    """Record or None. Use get_spf_status when absent and failed must differ."""
    return get_spf_status(domain, resolver)[0]


def walk(domain, resolver, depth=0, seen=None, out=None, spf=None):
    """Recursively expand an SPF record, counting lookup-costing mechanisms.

    Rows are (depth, owner, mechanism, counts). A target whose lookup fails
    gets a "LOOKUP FAILED" row, so the total is known to be a lower bound.
    `spf` lets a caller hand in a record it already fetched for `domain`.
    """
    seen = seen if seen is not None else set()
    out = out if out is not None else []
    if domain in seen or depth > 10:
        return out
    seen.add(domain)

    if spf is None:
        spf, status, evidence = get_spf_status(domain, resolver)
        if spf is None:
            label = ("NO SPF RECORD" if status == "absent"
                     else f"LOOKUP FAILED - could not verify ({evidence})")
            out.append((depth, domain, label, False))
            return out

    for token in spf.split():
        low = token.lower().lstrip("+-~?")
        target = None
        if low.startswith("include:"):
            target = low[8:]
        elif low.startswith("redirect="):
            target = low[9:]
        elif low.split(":", 1)[0].split("/", 1)[0] not in ("a", "mx", "ptr", "exists"):
            continue  # ip4, ip6, all, exp=, v=spf1 - free

        out.append((depth, domain, low, True))
        if target:
            walk(target, resolver, depth + 1, seen, out)
    return out


def classify(status, cost, failed=0):
    """(verdict, severity, exit_code) for one domain."""
    if status == "error":
        return "SPF lookup FAILED - could not verify", "major", 2
    if status == "absent":
        return "no SPF record", "major", 1
    if cost > LIMIT:
        return "OVER LIMIT - SPF returns PERMERROR", "blocking", 1
    if failed:
        return f"INCOMPLETE - {failed} nested lookup(s) failed, {cost} is a lower bound", "major", 2
    if cost == LIMIT:
        return "at the limit - no room for another vendor", "major", 1
    if cost == LIMIT - 1:
        return "one include away from breaking - new senders need DKIM", "minor", 0
    return "ok", "info", 0


def analyse(domain, resolver):
    """One domain as a dict; the text report and --json both render this."""
    record, status, evidence = get_spf_status(domain, resolver)
    entries = walk(domain, resolver, spf=record) if record else []
    cost = sum(1 for _, _, _, billable in entries if billable)
    failed = sum(1 for _, _, mech, _ in entries if mech.startswith("LOOKUP FAILED"))
    verdict, severity, code = classify(status, cost, failed)
    return {
        "domain": domain,
        "record": record,
        "status": status,
        "evidence": evidence,
        "lookups": cost,
        "limit": LIMIT,
        "verdict": verdict,
        "severity": severity,
        "verified": status != "error" and failed == 0,
        "mechanisms": [{"depth": d, "owner": o, "mechanism": m, "counts": b}
                       for d, o, m, b in entries],
        "exit_code": code,
    }


def report(r):
    """Human-readable block for one analysed domain."""
    print(f"=== {r['domain']} ===")
    if r["status"] == "error":
        print(f"  SPF lookup FAILED for {r['domain']} - could not verify ({r['evidence']})")
        print()
        return
    if r["status"] == "absent":
        print(f"  (no SPF record)   {r['evidence']}")
        print(f"  verdict: {r['verdict']}")
        print()
        return
    print(f"  {r['record']}")
    print(f"  source: {r['evidence']}")
    for m in r["mechanisms"]:
        marker = "*" if m["counts"] else " "
        print(f"  {'  ' * m['depth']}{marker} {m['mechanism']}")
    print(f"  lookups: {r['lookups']} / {r['limit']}   {r['verdict']}")
    if r["lookups"] >= LIMIT - 1:
        print("  note: authenticate new senders with DKIM rather than an SPF include.")
    print()


def audit(domain, resolver):
    """Print one domain's report and return its lookup count (old entry point)."""
    r = analyse(domain, resolver)
    report(r)
    return r["lookups"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--resolver", default="8.8.8.8", help="port 53 resolver IP (default 8.8.8.8)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output on stdout: one object, or a list when given several domains")
    args = ap.parse_args()

    domains = [d.strip().lower().rstrip(".") for d in args.domains]
    for d in domains:
        if not d or any(c in d for c in " \t/@"):
            print(f"error: {d!r} is not a domain name", file=sys.stderr)
            sys.exit(2)

    resolver = None
    if dns is not None:
        resolver = dns.resolver.Resolver(configure=False)
        try:
            resolver.nameservers = [args.resolver]
        except Exception as exc:
            print(f"error: --resolver {args.resolver!r} is not a usable nameserver ({exc})", file=sys.stderr)
            sys.exit(2)
        resolver.lifetime = 10

    results = []
    for d in domains:
        r = analyse(d, resolver)
        results.append(r)
        if not args.json:
            report(r)
    if args.json:
        print(json.dumps(results[0] if len(results) == 1 else results, indent=1))
    sys.exit(max(r["exit_code"] for r in results))


if __name__ == "__main__":
    main()
