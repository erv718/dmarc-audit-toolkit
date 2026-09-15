"""Multi-domain DNS posture audit for a DMARC program.

For every domain you give it, reports:
  - SPF: present, terminator strength, DNS lookup count vs the limit of 10
  - DMARC: present, policy, subdomain policy, sampling rate, reporting addresses
  - DKIM: which common selectors resolve
  - MX: where mail is received

This is the tool that finds the subdomain nobody remembered - the one with no
DKIM, no DMARC record, and a spoofing campaign already using it.

Usage:
    python dns_audit.py example.com mail.example.com sub.example.com
    python dns_audit.py --file domains.txt

Read-only. Queries public DNS, falls back to DNS-over-HTTPS when port 53 is
filtered (corporate networks produce SERVFAILs that look exactly like missing
records - do not diagnose a broken zone from one resolver path).
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

try:
    import dns.resolver
except ImportError:
    dns = None

from spf_lookups import get_spf, walk, LIMIT

# Selectors worth probing: Microsoft 365, Google, common ESP defaults.
COMMON_SELECTORS = ["selector1", "selector2", "google", "s1", "s2", "k1", "k2", "everlytickey1", "dkim"]


def doh(name, rtype):
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []
    if data.get("Status") != 0:
        return []
    return [a.get("data", "").strip('"').replace('" "', "") for a in data.get("Answer", [])]


def resolve(resolver, name, rtype):
    """Port 53 first, DoH as the cross-check."""
    if resolver is not None:
        for tcp in (False, True):
            try:
                ans = resolver.resolve(name, rtype, tcp=tcp)
                if rtype == "TXT":
                    return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
                return [str(r).rstrip(".") for r in ans]
            except Exception:
                continue
    return doh(name, rtype)


def parse_dmarc(txt):
    tags = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def audit_domain(domain, resolver):
    flags = []

    spf = get_spf(domain, resolver)
    lookups = 0
    if spf:
        lookups = sum(1 for _, _, _, billable in walk(domain, resolver) if billable)
        terminator = spf.split()[-1] if spf.split() else "?"
        if terminator not in ("-all", "~all"):
            flags.append(f"SPF terminator is '{terminator}' - effectively no protection")
        if lookups >= LIMIT:
            flags.append(f"SPF at/over the {LIMIT}-lookup limit - PERMERROR territory")
        elif lookups == LIMIT - 1:
            flags.append("SPF one include away from breaking - new senders need DKIM")
    else:
        terminator = None
        flags.append("no SPF record")

    dmarc_txts = [t for t in resolve(resolver, f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    dmarc = parse_dmarc(dmarc_txts[0]) if dmarc_txts else None
    if dmarc is None:
        flags.append("NO DMARC RECORD - no policy, no reporting, invisible to you")
    else:
        if dmarc.get("p", "none") == "none":
            flags.append("DMARC p=none - monitoring only")
        if "rua" not in dmarc:
            flags.append("DMARC has no rua - failures are invisible to you")
        if dmarc.get("p") in ("quarantine", "reject") and "sp" not in dmarc:
            flags.append("no explicit sp= - subdomains inherit p; make sure that is intentional")

    # Wildcard guard: if a random selector "resolves", every probe below is
    # meaningless and DKIM presence cannot be inferred from DNS at all.
    canary = "zz-audit-canary-zz"
    wildcarded = bool(resolve(resolver, f"{canary}._domainkey.{domain}", "CNAME") or
                      resolve(resolver, f"{canary}._domainkey.{domain}", "TXT"))
    selectors = []
    for sel in ([] if wildcarded else COMMON_SELECTORS):
        name = f"{sel}._domainkey.{domain}"
        if resolve(resolver, name, "CNAME") or any(
                t.lower().startswith("v=dkim1") for t in resolve(resolver, name, "TXT")):
            selectors.append(sel)
    if wildcarded:
        flags.append("wildcard at _domainkey - selector probing unreliable, verify DKIM from message headers")
    elif not selectors:
        flags.append("no common DKIM selector found - domain may authenticate on SPF alone, which breaks on forwarding")

    mx = resolve(resolver, domain, "MX")

    return {"domain": domain, "spf": spf, "spf_terminator": terminator, "spf_lookups": lookups,
            "dmarc": dmarc_txts[0] if dmarc_txts else None, "dkim_selectors": selectors,
            "mx": mx, "flags": flags}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*")
    ap.add_argument("--file", help="file with one domain per line")
    ap.add_argument("--resolver", default="8.8.8.8")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            domains += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not domains:
        ap.error("no domains given")

    resolver = None
    if dns is not None:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [args.resolver]
        resolver.lifetime = 10

    results = [audit_domain(d, resolver) for d in domains]

    if args.json:
        print(json.dumps(results, indent=1))
        return

    total_flags = 0
    for r in results:
        print(f"=== {r['domain']} ===")
        print(f"  SPF   : {'yes, ' + str(r['spf_lookups']) + '/' + str(LIMIT) + ' lookups, ' + str(r['spf_terminator']) if r['spf'] else 'MISSING'}")
        print(f"  DMARC : {r['dmarc'] or 'MISSING'}")
        print(f"  DKIM  : {', '.join(r['dkim_selectors']) if r['dkim_selectors'] else 'no common selectors found'}")
        print(f"  MX    : {', '.join(r['mx'][:3]) if r['mx'] else 'none (does not receive mail)'}")
        for f in r["flags"]:
            total_flags += 1
            print(f"  !! {f}")
        print()
    print(f"{len(results)} domains audited, {total_flags} findings")
    sys.exit(1 if total_flags else 0)


if __name__ == "__main__":
    main()
