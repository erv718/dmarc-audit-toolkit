"""Count the DNS lookups an SPF record costs, against the RFC 7208 limit of 10.

Why this matters
----------------
SPF evaluation is capped at 10 DNS-querying mechanisms. Exceed it and the
result is PERMERROR, which most receivers treat as a failure - for the whole
domain, every message, immediately. Domains drift toward the limit one vendor
at a time and nobody notices until the record breaks.

Mechanisms that cost a lookup: include, a, mx, ptr, exists, redirect.
Mechanisms that cost nothing: ip4, ip6, all.

Usage
-----
    python spf_lookups.py example.com [more.example.com ...]
"""

import argparse
import sys

import json
import urllib.parse
import urllib.request

try:
    import dns.resolver  # dnspython
except ImportError:  # pragma: no cover
    dns = None

COSTLY = ("include:", "redirect=", "a:", "mx:", "ptr:", "exists:")
LIMIT = 10


def _doh_txt(domain):
    """Resolve TXT over DNS-over-HTTPS.

    Port 53 is filtered or intercepted on plenty of corporate networks, which
    produces SERVFAIL or truncation that looks exactly like a broken zone. That
    misdiagnosis is expensive, so we always cross-check over HTTPS before
    reporting that a domain has no SPF record.
    """
    url = "https://dns.google/resolve?" + urllib.parse.urlencode(
        {"name": domain, "type": "TXT"})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    if data.get("Status") != 0:
        return None
    return [a.get("data", "").strip('"').replace('" "', "")
            for a in data.get("Answer", [])]


def get_spf(domain, resolver):
    """Fetch a domain's SPF record, over port 53 first and HTTPS as a fallback."""
    records = None
    if resolver is not None:
        for use_tcp in (False, True):
            try:
                answers = resolver.resolve(domain, "TXT", tcp=use_tcp)
                records = [b"".join(r.strings).decode("utf-8", "replace")
                           for r in answers]
                break
            except Exception:
                continue
    if not records:
        records = _doh_txt(domain)
    if not records:
        return None
    for txt in records:
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def walk(domain, resolver, depth=0, seen=None, out=None):
    """Recursively expand an SPF record, counting lookup-costing mechanisms."""
    seen = seen if seen is not None else set()
    out = out if out is not None else []
    if domain in seen or depth > 10:
        return out
    seen.add(domain)

    spf = get_spf(domain, resolver)
    if spf is None:
        out.append((depth, domain, "NO SPF RECORD", False))
        return out

    for token in spf.split():
        low = token.lower().lstrip("+-~?")
        target = None
        if low.startswith("include:"):
            target, kind = low[8:], "include"
        elif low.startswith("redirect="):
            target, kind = low[9:], "redirect"
        elif low in ("a", "mx", "ptr") or low.startswith(("a:", "mx:", "ptr:", "exists:")):
            kind = low.split(":")[0]
        else:
            continue  # ip4, ip6, all, v=spf1 - free

        out.append((depth, domain, f"{kind}{':' + target if target else ''}", True))
        if target:
            walk(target, resolver, depth + 1, seen, out)
    return out


def audit(domain, resolver):
    entries = walk(domain, resolver)
    cost = sum(1 for _, _, _, billable in entries if billable)
    print(f"=== {domain} ===")
    root = get_spf(domain, resolver)
    print(f"  {root or '(no SPF record)'}")
    for depth, owner, mech, billable in entries:
        marker = "*" if billable else " "
        print(f"  {'  ' * depth}{marker} {mech}")
    verdict = "OVER LIMIT - SPF returns PERMERROR" if cost > LIMIT else (
        "at the limit - no room for another vendor" if cost == LIMIT else "ok")
    print(f"  lookups: {cost} / {LIMIT}   {verdict}")
    if cost >= LIMIT - 1:
        print("  note: authenticate new senders with DKIM rather than an SPF include.")
    print()
    return cost


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--resolver", default="8.8.8.8")
    args = ap.parse_args()

    resolver = None
    if dns is not None:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [args.resolver]
        resolver.lifetime = 10

    worst = 0
    for domain in args.domains:
        worst = max(worst, audit(domain, resolver))
    sys.exit(1 if worst > LIMIT else 0)


if __name__ == "__main__":
    main()
