#!/usr/bin/env python3
"""Discover the domains to audit, and where each zone is hosted.

Sources, unioned and deduplicated (a domain named twice is listed once, with
every source that named it):

  positional      python src/discover.py example.com,sub.example.com other.example
  --file          one domain per line
  the tenant      GET /domains through the app registration (Domain.Read.All,
                  or Directory.Read.All) - used automatically when .env holds
                  credentials, skipped with --no-graph
  --mailflow      subdomains of your domains seen sending in the last 30
                  days, from advanced hunting (ThreatHunting.Read.All)

For every domain the inventory records which sources named it, whether the
tenant has verified it, and the DNS zone host (Route53, CSC, Cloudflare,
Azure DNS, ...), which is what decides how a change gets made. Read-only.

  python src/discover.py                       # tenant domains only
  python src/discover.py example.com --mailflow --out exports
  python src/discover.py --file domains.txt --no-graph --json

Exit codes: 0 ok, 2 nothing to discover (no domains, no file, no credentials)
or an input error.
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import dns.resolver
except ImportError:
    dns = None

ROOT = Path(__file__).resolve().parent.parent
DOH_URL = "https://dns.google/resolve"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Common two-level public suffixes so the organizational domain is right.
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
             "co.jp", "co.nz", "com.br", "com.mx", "co.za", "com.sg", "com.hk",
             "co.in", "co.kr", "com.tr", "com.ar"}

# NS name fragment -> hosting provider. Order matters; first match wins.
ZONE_HOSTS = [
    ("awsdns", "Route53"),
    ("cscdns", "CSC"),
    ("cloudflare", "Cloudflare"),
    ("azure-dns", "Azure DNS"),
    ("domaincontrol", "GoDaddy"),
    ("googledomains", "Google Domains"),
    ("google.com", "Google Cloud DNS"),
    ("nsone.net", "NS1"),
    ("ultradns", "UltraDNS"),
    ("dnsmadeeasy", "DNS Made Easy"),
    ("akam.net", "Akamai"),
    ("registrar-servers", "Namecheap"),
    ("dynect", "Dyn"),
    ("markmonitor", "MarkMonitor"),
    ("gandi", "Gandi"),
    ("ovh", "OVH"),
    ("hetzner", "Hetzner"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"),
    ("wordpress", "WordPress"),
    ("squarespace", "Squarespace"),
    ("wixdns", "Wix"),
    ("shopify", "Shopify"),
]


def usage_error(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def normalize(name):
    return str(name).strip().lower().rstrip(".")


def parse_domains(tokens):
    """Split 'a.com,b.com' and 'a.com, b.com' and separate args into one
    ordered, deduplicated list. Non-domains are reported and dropped."""
    seen, out, bad = set(), [], []
    for tok in tokens or []:
        for part in re.split(r"[,\s]+", str(tok)):
            d = normalize(part)
            if not d:
                continue
            if not DOMAIN_RE.match(d):
                bad.append(d)
                continue
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out, bad


def read_domain_file(path):
    p = Path(path)
    try:
        lines = p.read_text(encoding="utf-8-sig").splitlines()
    except OSError as err:
        usage_error("cannot read domain file: %s" % err)
    except UnicodeDecodeError:
        usage_error("%s is not UTF-8 - re-save the domain file as UTF-8" % path)
    return [l.split("#", 1)[0] for l in lines]


def org_domain(name):
    """Organizational domain: the registrable part, with a small public
    suffix list so sub.example.co.uk maps to example.co.uk."""
    labels = normalize(name).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def make_resolver(addr):
    if dns is None or not addr:
        return None
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [addr]
    r.lifetime = 8
    return r


def lookup_ns(name, resolver=None):
    """NS names for a zone: port 53 first when dnspython is present, then
    DNS-over-HTTPS. Returns (names, path) where path says which answered."""
    if resolver is not None:
        try:
            ans = resolver.resolve(name, "NS")
            names = sorted(str(r.target).rstrip(".").lower() for r in ans)
            if names:
                return names, "port53"
        except Exception:
            pass
    try:
        url = DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": "NS"})
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
        names = sorted(a["data"].rstrip(".").lower() for a in data.get("Answer", []) if a.get("type") == 2)
        return names, "doh" if names else "doh (no NS)"
    except Exception as err:
        return [], "failed (%s)" % err.__class__.__name__


def zone_host(ns_names):
    """Hosting provider from the NS names, or 'other (<first ns>)'."""
    joined = " ".join(ns_names)
    for fragment, label in ZONE_HOSTS:
        if fragment in joined:
            return label
    return "other (%s)" % ns_names[0] if ns_names else "unknown"


def zone_for(domain, resolver=None):
    """The zone that actually holds this name: the name itself if it has NS
    records, else its organizational domain."""
    names, path = lookup_ns(domain, resolver)
    if names:
        return {"zone": domain, "ns": names, "zone_host": zone_host(names), "ns_path": path}
    org = org_domain(domain)
    if org != domain:
        names, path = lookup_ns(org, resolver)
        if names:
            return {"zone": org, "ns": names, "zone_host": zone_host(names), "ns_path": path}
    return {"zone": org, "ns": [], "zone_host": "unknown", "ns_path": path}


def graph_domains(env_file=None):
    """Domains the tenant knows, via the app registration. Returns
    (list, note) where note explains a skip or failure in one line."""
    import graph_client
    try:
        cred = graph_client.creds(env_file)
    except graph_client.GraphError as err:
        return [], str(err)
    if cred is None:
        return [], "no credentials in .env (%s) - tenant lookup skipped" % ", ".join(graph_client.missing_keys())
    try:
        tok = graph_client.token(cred)
        return graph_client.list_domains(tok), None
    except graph_client.GraphError as err:
        return [], "tenant lookup failed: %s" % err


def mailflow_subdomains(org_domains, env_file=None, days=30):
    """Subdomains of the given organizational domains seen in mail flow.

    Every row is a subdomain that appeared as the header-from domain in the
    window, with message counts by direction. Outbound or Intra-org volume
    means something in the tenant really sends as it; Inbound-only volume is
    either an outside vendor or spoofing - the audit decides which.
    """
    import graph_client
    orgs = [normalize(o) for o in org_domains if o]
    if not orgs:
        return [], "no organizational domains to expand"
    try:
        cred = graph_client.creds(env_file)
    except graph_client.GraphError as err:
        return [], str(err)
    if cred is None:
        return [], "no credentials in .env - mail-flow expansion skipped"
    cond = " or ".join('d endswith ".%s"' % o.replace('"', "") for o in orgs)
    kql = (
        "EmailEvents\n"
        "| where Timestamp > ago(%dd)\n"
        "| extend d = tolower(SenderFromDomain)\n"
        "| where %s\n"
        "| summarize messages = dcount(InternetMessageId),\n"
        "            outbound = dcountif(InternetMessageId, EmailDirection in~ (\"Outbound\", \"Intra-org\")),\n"
        "            inbound = dcountif(InternetMessageId, EmailDirection =~ \"Inbound\"),\n"
        "            last_seen = max(Timestamp)\n"
        "    by d\n"
        "| order by messages desc" % (days, cond)
    )
    try:
        tok = graph_client.token(cred)
        result = graph_client.hunting(tok, kql, "P%dD" % days)
    except graph_client.GraphError as err:
        return [], "mail-flow expansion failed: %s" % err
    rows = []
    for r in result.get("results") or []:
        d = normalize(r.get("d", ""))
        if d and DOMAIN_RE.match(d):
            rows.append({"domain": d, "messages": r.get("messages", 0),
                         "outbound": r.get("outbound", 0), "inbound": r.get("inbound", 0),
                         "last_seen": r.get("last_seen")})
    return rows, None


def discover(domains=(), domain_file=None, use_graph=True, mailflow=False,
             resolver_addr="8.8.8.8", env_file=None, ns_lookup=True):
    """Build the inventory. Returns (inventory list, notes list)."""
    notes = []
    inv = {}

    def add(domain, source, **extra):
        d = normalize(domain)
        if not d:
            return
        row = inv.setdefault(d, {"domain": d, "sources": [], "tenant_verified": None,
                                 "tenant_services": [], "org_domain": org_domain(d),
                                 "mailflow": None})
        if source not in row["sources"]:
            row["sources"].append(source)
        for k, v in extra.items():
            row[k] = v

    cli, bad = parse_domains(domains)
    for d in cli:
        add(d, "cli")
    if bad:
        notes.append("ignored non-domain input: %s" % ", ".join(bad))
    if domain_file:
        file_domains, bad = parse_domains(read_domain_file(domain_file))
        for d in file_domains:
            add(d, "file")
        if bad:
            notes.append("ignored non-domain lines in %s: %s" % (domain_file, ", ".join(bad)))

    if use_graph:
        tenant, note = graph_domains(env_file)
        if note:
            notes.append(note)
        for t in tenant:
            d = t["domain"]
            if d.endswith(".onmicrosoft.com"):
                continue
            add(d, "tenant", tenant_verified=t["verified"], tenant_services=t["services"])
        if tenant:
            notes.append("tenant: %d domains (%d verified)" % (len(tenant), sum(1 for t in tenant if t["verified"])))

    if mailflow:
        orgs = sorted({row["org_domain"] for row in inv.values()})
        rows, note = mailflow_subdomains(orgs, env_file)
        if note:
            notes.append(note)
        for r in rows:
            add(r["domain"], "mailflow", mailflow={k: r[k] for k in ("messages", "outbound", "inbound", "last_seen")})
        if rows:
            notes.append("mail flow: %d sending domains under %s" % (len(rows), ", ".join(orgs)))

    resolver = make_resolver(resolver_addr) if ns_lookup else None
    zone_cache = {}
    for row in inv.values():
        if not ns_lookup:
            row.update({"zone": org_domain(row["domain"]), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
            continue
        key = row["domain"]
        if key not in zone_cache:
            zone_cache[key] = zone_for(key, resolver)
        row.update(zone_cache[key])

    ordered = sorted(inv.values(), key=lambda r: (r["org_domain"], r["domain"] != r["org_domain"], r["domain"]))
    return ordered, notes


def render(inventory, notes):
    lines = []
    lines.append("%-34s %-10s %-22s %-16s %s" % ("domain", "verified", "sources", "zone host", "zone"))
    for r in inventory:
        ver = {True: "yes", False: "no", None: "-"}[r.get("tenant_verified")]
        lines.append("%-34s %-10s %-22s %-16s %s" % (r["domain"], ver, ",".join(r["sources"]),
                                                     r.get("zone_host", "?"), r.get("zone", "")))
    lines.append("")
    lines.append("%d domains" % len(inventory))
    for n in notes:
        lines.append("note: " + n)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Discover the domains to audit and where each zone is hosted.")
    ap.add_argument("domains", nargs="*", help="domains, comma or space separated")
    ap.add_argument("--file", metavar="PATH", help="file with one domain per line")
    ap.add_argument("--no-graph", action="store_true", help="do not read the tenant's domain list")
    ap.add_argument("--mailflow", action="store_true",
                    help="add subdomains seen sending in the last 30 days (needs ThreatHunting.Read.All)")
    ap.add_argument("--no-ns", action="store_true", help="skip the zone-host lookup")
    ap.add_argument("--resolver", default="8.8.8.8", help="port-53 resolver for NS lookups (DoH is the fallback)")
    ap.add_argument("--env-file", help="credentials file (default: <repo root>/.env)")
    ap.add_argument("--out", metavar="DIR", help="write domains.txt and inventory.json here")
    ap.add_argument("--json", action="store_true", help="print the inventory as JSON")
    args = ap.parse_args()

    inventory, notes = discover(args.domains, args.file, not args.no_graph, args.mailflow,
                                args.resolver, args.env_file, not args.no_ns)
    if not inventory:
        for n in notes:
            print("note: " + n, file=sys.stderr)
        usage_error("nothing to discover: give domains on the command line, --file, or credentials in .env")

    if args.out:
        out = Path(args.out)
        try:
            out.mkdir(parents=True, exist_ok=True)
            (out / "domains.txt").write_text("\n".join(r["domain"] for r in inventory) + "\n", encoding="utf-8")
            (out / "inventory.json").write_text(json.dumps({"domains": inventory, "notes": notes}, indent=1),
                                                encoding="utf-8")
        except OSError as err:
            usage_error("cannot write to %s: %s" % (args.out, err))
        print("wrote %s and %s" % (out / "domains.txt", out / "inventory.json"), file=sys.stderr)

    if args.json:
        print(json.dumps({"domains": inventory, "notes": notes}, indent=1))
    else:
        print(render(inventory, notes))


if __name__ == "__main__":
    main()
