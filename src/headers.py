"""Message header analyzer - the proof tool.

Two rules in this repo need a live header to settle: "only a live message
header proves DKIM signing" and "usage, not origin, decides whether a key is
safe to remove". This tool reads that header and says what it proves.

For every file (a raw header block pasted from a mail client, or a full .eml):
  - Authentication-Results: which one to believe (--authserv-id), then the
    spf / dkim / dmarc / compauth / arc verdicts it carries
  - DKIM-Signature: every signature's d= s= a= c= i= h=, whether each one is
    aligned to the From domain (relaxed and strict), and what the receiver
    said about it. Optionally (--verify-dns) whether the selector's key exists.
  - From, Return-Path, Sender, Reply-To, Message-ID, Date, To
  - the Received chain in transit order, hop count, first external IP
  - dmarc_would_pass_via: dkim | spf | both | none, from the receiver's
    verdicts plus alignment
  - a sending-platform fingerprint (Return-Path / VERP, Received hosts,
    X- headers) with an account hint where the platform leaks one

Authentication-Results headers can be injected by a sender, so the receiver's
own header is the only one worth trusting. Give --authserv-id (the id the
receiving host writes at the front of its AR header, e.g. example.com or
mail.protection.outlook.com). Without it the topmost AR is used and the
report says so.

The tool cannot verify a DKIM signature cryptographically: that needs the
message body and the public key at signing time. It proves that a signature
with this d= and s= was on the wire and what the receiver concluded.

Usage:
    python headers.py samples/headers/aligned_dkim_pass.txt --authserv-id mail.example.com
    python headers.py msg1.eml msg2.eml --authserv-id example.com --json
    python headers.py msg.eml --verify-dns

Relative paths resolve from the repo root, not from the current directory.

Exit codes: 0 clean, 1 findings at severity major or blocking, 2 usage or
input error.
"""

import argparse
import email.utils
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import Parser
from pathlib import Path

try:
    import dns.resolver  # dnspython, optional: port 53 path for --verify-dns
except ImportError:
    dns = None

try:
    import dns_audit  # sibling tool: resolver with DoH fallback and org_domain()
except ImportError:
    dns_audit = None

ROOT = Path(__file__).resolve().parent.parent

SEVERITY_RANK = {"info": 0, "minor": 1, "major": 2, "blocking": 3}

# ------------------------------------------------ platform fingerprints (edit freely)
# (vendor, where, regex, account-hint group or None)
#   where: return_path  - the Return-Path address, lower case
#          received     - each Received header, whitespace collapsed
#          header:<X>   - the named header's value
#          dkim_d       - each DKIM-Signature d= value
# First match per (vendor, where) is kept; return_path and header matches
# weigh more than a Received host, which forwarders also leave behind.
FINGERPRINTS = [
    ("SendGrid", "return_path", r"^bounces\+(\d+)-", 1),
    ("SendGrid", "return_path", r"@(u\d+)\.wl\d+\.sendgrid\.net$", 1),
    ("SendGrid", "received", r"\b(u\d+)\.wl\d+\.sendgrid\.net\b", 1),
    ("SendGrid", "received", r"\bsendgrid\.net\b|\bfilterdrecv\b", None),
    ("SendGrid", "header:X-SG-EID", r".", None),
    ("Amazon SES", "return_path", r"^([0-9a-f]{16,}-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-\d{6})@", 1),
    ("Amazon SES", "return_path", r"@[a-z0-9.-]*amazonses\.com$", None),
    ("Amazon SES", "received", r"\bamazonses\.com\b", None),
    ("Amazon SES", "header:X-SES-Outgoing", r".", None),
    ("Amazon SES", "dkim_d", r"^amazonses\.com$", None),
    ("Salesforce", "return_path", r"@[a-z0-9.-]*\.bnc\.salesforce\.com$", None),
    ("Salesforce", "received", r"\.bnc\.salesforce\.com\b|\bsalesforce\.com\b", None),
    ("Mailchimp/Mandrill", "return_path", r"@[a-z0-9.-]*(?:mcsv\.net|rsgsv\.net|mandrillapp\.com)$", None),
    ("Mailchimp/Mandrill", "received", r"\b(?:mcsv\.net|rsgsv\.net|mandrillapp\.com)\b", None),
    ("Mailchimp/Mandrill", "header:X-Mandrill-User", r"^(.+)$", 1),
    ("HubSpot", "return_path", r"@[a-z0-9.-]*hubspotemail\.net$", None),
    ("HubSpot", "received", r"\bhubspotemail\.net\b", None),
    ("Mailgun", "return_path", r"@[a-z0-9.-]*mailgun\.org$", None),
    ("Mailgun", "received", r"\bmailgun\.org\b", None),
    ("Mailgun", "header:X-Mailgun-Sending-Ip", r".", None),
    ("SparkPost", "return_path", r"@[a-z0-9.-]*sparkpostmail\.com$", None),
    ("SparkPost", "received", r"\bsparkpostmail\.com\b", None),
    ("Postmark", "return_path", r"@[a-z0-9.-]*mtasv\.net$", None),
    ("Postmark", "received", r"\bmtasv\.net\b", None),
    ("Postmark", "header:X-PM-Message-Id", r".", None),
    ("Google Workspace", "received", r"\bfrom\s+\S+\.google\.com\b.*\bwith\s+ESMTPS\b", None),
    ("Google Workspace", "dkim_d", r"\.gappssmtp\.com$", None),
    ("Microsoft 365", "received", r"\boutbound\.protection\.outlook\.com\b", None),
    ("Microsoft 365", "header:X-MS-Exchange-CrossTenant-Id", r"^(.+)$", 1),
]
WHERE_WEIGHT = {"return_path": 3, "header": 3, "dkim_d": 2, "received": 1}
# Account hints the platform writes as bare digits get the prefix its own hostnames use.
HINT_PREFIX = {"SendGrid": "u"}

# Explanations attached to a fingerprint when they change what the header proves.
FINGERPRINT_NOTES = {
    "Google Workspace": "DKIM d= under gappssmtp.com is Google's default key, never aligned; "
                        "DMARC on this mail rides on SPF until a domain key is set up in Admin",
}

# Hops from these ranges are inside somebody's network; every other address is
# an external handoff. Explicit on purpose: ipaddress.is_private also covers the
# documentation ranges (192.0.2.0/24 etc.), which would hide them in samples.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "::/128")]


# ---------------------------------------------------------------- helpers

def org_domain(domain):
    if dns_audit is not None:
        return dns_audit.org_domain(domain)
    labels = domain.lower().strip(".").split(".")
    return ".".join(labels[-2:])


def _unfold(value):
    """Header value with folding undone and whitespace collapsed."""
    return re.sub(r"\s+", " ", (value or "").replace("\r", " ").replace("\n", " ")).strip()


def _strip_comments(text):
    """Remove (comments), nested ones included; quoted strings are left alone."""
    out, depth, quoted, i = [], 0, False, 0
    while i < len(text):
        ch = text[i]
        if quoted:
            if ch == "\\" and i + 1 < len(text):
                if depth == 0:
                    out.append(text[i:i + 2])
                i += 2
                continue
            if ch == '"':
                quoted = False
            if depth == 0:
                out.append(ch)
        elif ch == '"' and depth == 0:
            quoted = True
            out.append(ch)
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif depth == 0:
            out.append(ch)
        i += 1
    return "".join(out)


def _split_unquoted(text, sep):
    """Split on sep outside double quotes."""
    parts, cur, quoted = [], [], False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == sep and not quoted:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _addr_domain(addr):
    """Domain of an address (or of a bare domain), lower case, or None."""
    if not addr:
        return None
    addr = addr.strip().strip("<>").strip()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    addr = addr.strip().lower().rstrip(".")
    return addr or None


def _address(value):
    """Bare address from a From/Reply-To style header, or None."""
    value = _unfold(value)
    if not value:
        return None
    _, addr = email.utils.parseaddr(value)
    return addr.strip().lower() or None


def _is_external(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


def aligned(domain, from_domain, strict=False):
    """DKIM/SPF identifier alignment to the From domain (RFC 7489 section 3.1)."""
    if not domain or not from_domain:
        return False
    domain, from_domain = domain.lower(), from_domain.lower()
    if strict:
        return domain == from_domain
    return org_domain(domain) == org_domain(from_domain)


# ---------------------------------------------------------------- input

def read_headers(path):
    """Parse a header block or .eml into a Message. Raises OSError / UnicodeDecodeError."""
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        text = fh.read()
    return parse_headers(text)


def parse_headers(text):
    """Message (headers only) from raw text. Tolerates a leading mbox From line and blank lines."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].startswith("From ") and ":" not in lines[0].split(" ", 1)[0]:
        lines.pop(0)
    # Mail clients paste headers with a bare "  " continuation or a stray blank
    # line inside a folded value; only a blank line followed by a non-header
    # line really starts the body, so drop blank lines that sit between headers.
    cleaned = []
    for i, line in enumerate(lines):
        if not line.strip():
            rest = [l for l in lines[i + 1:] if l.strip()]
            if rest and re.match(r"^[!-9;-~]+:", rest[0]):
                continue  # blank inside the header block
            cleaned.extend(lines[i:])
            break
        cleaned.append(line)
    return Parser(policy=policy.compat32).parsestr("\n".join(cleaned), headersonly=True)


def header_all(msg, name):
    """All values of a header, unfolded, in header order (topmost first)."""
    return [_unfold(str(v)) for v in (msg.get_all(name) or [])]


def header_one(msg, name):
    vals = header_all(msg, name)
    return vals[0] if vals else None


# ---------------------------------------------------------------- Authentication-Results

def parse_ar(value, source="Authentication-Results"):
    """One AR header -> {source, instance, authserv_id, methods, dmarc_policy, raw}.

    methods: [{method, result, props}] in header order; a receiver that checked
    two DKIM signatures writes two dkim= entries. Comments are dropped, except
    the "(p=... sp=... dis=...)" one some receivers put after dmarc=, which is
    the policy they applied.
    """
    raw = _unfold(value)
    pol = re.search(r"\bdmarc=\w+\s*\(([^)]*)\)", raw, re.I)
    policy_tags = {}
    if pol:
        for tok in pol.group(1).split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                policy_tags[k.lower()] = v.lower()
    parts = [p.strip() for p in _split_unquoted(_strip_comments(raw), ";") if p.strip()]
    instance = None
    if parts and re.fullmatch(r"i=\d+", parts[0]):
        instance = int(parts[0][2:])
        parts.pop(0)
    authserv = None
    if parts:
        head = parts[0].split()
        if head and "=" not in head[0]:  # authserv-id [version]; M365 writes none
            authserv = head[0].lower().rstrip(".")
            parts.pop(0)
    methods = []
    for part in parts:
        tokens = [t for t in _split_unquoted(part, " ") if t]
        if not tokens or "=" not in tokens[0]:
            continue
        method, result = tokens[0].split("=", 1)
        props = {}
        for tok in tokens[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                props[k.lower()] = v.strip('"')
        methods.append({"method": method.lower(), "result": result.lower(), "props": props})
    return {"source": source, "instance": instance, "authserv_id": authserv, "methods": methods,
            "dmarc_policy": policy_tags.get("p"), "raw": raw}


def ar_verdicts(ar):
    """spf / dkim / dmarc / compauth / arc as the receiver wrote them. dkim is a list."""
    out = {"spf": None, "dkim": [], "dmarc": None, "compauth": None, "arc": None}
    if ar is None:
        return out
    for m in ar["methods"]:
        p, method = m["props"], m["method"]
        if method == "spf" and out["spf"] is None:
            mf = p.get("smtp.mailfrom") or p.get("smtp.helo")
            out["spf"] = {"result": m["result"], "smtp_mailfrom": mf, "domain": _addr_domain(mf)}
        elif method == "dkim":
            d = (p.get("header.d") or "").lower()
            out["dkim"].append({"result": m["result"], "d": d if d and d != "none" else None,
                                "s": p.get("header.s"), "i": p.get("header.i")})
        elif method == "dmarc" and out["dmarc"] is None:
            out["dmarc"] = {"result": m["result"], "header_from": (p.get("header.from") or "").lower() or None,
                            "action": p.get("action"), "policy": p.get("policy") or ar.get("dmarc_policy"),
                            "reason": p.get("reason")}
        elif method == "compauth" and out["compauth"] is None:
            out["compauth"] = {"result": m["result"], "reason": p.get("reason")}
        elif method == "arc" and out["arc"] is None:
            out["arc"] = dict(p, result=m["result"])
    return out


def collect_ar(msg):
    """Every AR-like header, topmost first: Authentication-Results, then the
    ARC and -Original variants that forwarders leave behind."""
    ars = []
    for name in ("Authentication-Results", "ARC-Authentication-Results", "Authentication-Results-Original"):
        ars += [parse_ar(v, name) for v in header_all(msg, name)]
    return ars


def _under(host, want):
    host = (host or "").lower().rstrip(".")
    return bool(host) and (host == want or host.endswith("." + want))


def choose_ar(ars, authserv_id=None, hops=None):
    """(ar, trusted, why). Only a plain Authentication-Results whose authserv-id
    is the one asked for counts as trusted; anything else may have been injected
    by the sender or copied through a forwarder.

    Microsoft 365 writes its AR with no authserv-id at all. That header is
    accepted only when it is the topmost one and a Received hop was handled by
    a host under --authserv-id (e.g. mail.protection.outlook.com).
    """
    plain = [a for a in ars if a["source"] == "Authentication-Results"]
    if authserv_id:
        want = authserv_id.strip().lower().rstrip(".")
        for a in plain:
            if _under(a["authserv_id"], want):
                return a, True, f"authserv-id {a['authserv_id']} matched --authserv-id {want}"
        if plain and not plain[0]["authserv_id"]:
            by = next((h["by"] for h in (hops or []) if _under((h["by"] or "").strip("[]"), want)), None)
            if by:
                return plain[0], True, (f"topmost Authentication-Results carries no authserv-id (Microsoft 365 style);"
                                        f" accepted because {by} under {want} handled the message")
        if not plain:
            return None, False, f"no Authentication-Results header at all (expected one from {want})"
        top = plain[0]
        return top, False, (f"no Authentication-Results from {want}; using the topmost one"
                            f" ({top['authserv_id'] or 'no authserv-id'}) unverified")
    if not plain:
        return None, False, "no Authentication-Results header"
    top = plain[0]
    return top, False, (f"no --authserv-id given; topmost Authentication-Results"
                        f" ({top['authserv_id'] or 'no authserv-id'}) trusted unverified")


# ---------------------------------------------------------------- DKIM-Signature

def parse_dkim_signature(value):
    tags = {}
    for part in _unfold(value).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    return {"d": (tags.get("d") or "").lower() or None, "s": tags.get("s") or None,
            "a": tags.get("a"), "c": tags.get("c"), "i": tags.get("i"),
            "h": [h.lower() for h in (tags.get("h") or "").split(":") if h],
            "bh_present": bool(tags.get("bh")), "b_present": bool(tags.get("b")),
            "t": tags.get("t"), "x": tags.get("x")}


def match_ar_dkim(sig, ar_dkim):
    """The receiver's verdict for this signature: same d= (and s= when the AR has one)."""
    for v in ar_dkim:
        if v["d"] == sig["d"] and (not v["s"] or not sig["s"] or v["s"] == sig["s"]):
            return v["result"]
    return None


# ---------------------------------------------------------------- Received

_IP_BRACKET = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_IP_BARE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def _find_ip(text):
    for rx in (_IP_BRACKET, _IP_BARE):
        for m in rx.finditer(text):
            try:
                return str(ipaddress.ip_address(m.group(1)))
            except ValueError:
                continue
    return None


def parse_received(value):
    """One Received header -> {from, by, ip, with, timestamp, external, raw}."""
    raw = _unfold(value)
    head, sep, date = raw.rpartition(";")
    if not sep:
        head, date = raw, ""
    ts = None
    if date.strip():
        try:
            ts = email.utils.parsedate_to_datetime(date.strip()).isoformat()
        except (TypeError, ValueError, IndexError, OverflowError):
            ts = None
    plain = _strip_comments(head)
    m_from = re.search(r"(?:^|\s)from\s+(\S+)", plain)
    m_by = re.search(r"(?:^|\s)by\s+(\S+)", plain)
    m_with = re.search(r"(?:^|\s)with\s+(\S+)", plain)
    ip = None
    if m_from:
        # the IP sits in a (comment) after the host, so search the raw from-clause
        start = max(head.find(m_from.group(1)), 0)
        end = head.find(" by ", start)
        ip = _find_ip(head[start:end] if end > 0 else head[start:])
    return {"from": m_from.group(1) if m_from else None,
            "by": m_by.group(1).rstrip(";,") if m_by else None,
            "ip": ip, "with": m_with.group(1) if m_with else None,
            "timestamp": ts, "external": bool(ip and _is_external(ip)), "raw": raw}


def received_chain(msg):
    """Hops in transit order (origin first), so hop 1 is where the message entered the mail system."""
    hops = [parse_received(v) for v in header_all(msg, "Received")]
    hops.reverse()
    for n, h in enumerate(hops, 1):
        h["hop"] = n
    return hops


def first_external_ip(hops):
    return next((h["ip"] for h in hops if h["external"]), None)


def external_receivers(hops):
    """Distinct organizations whose hosts accepted the message over the public
    internet. Two or more means it was handed on: a forward or a relay."""
    orgs = []
    for h in hops:
        if h["external"] and h["by"] and "." in h["by"]:
            org = org_domain(h["by"].strip("[]"))
            if org and org not in orgs:
                orgs.append(org)
    return orgs


# ---------------------------------------------------------------- fingerprint

def fingerprint(msg, return_path, hops, sigs):
    """Best-guess sending platform from the pattern table. A guess about the
    platform, not about who owns the account."""
    hits, order = {}, []
    for vendor, where, pattern, grp in FINGERPRINTS:
        kind, _, hname = where.partition(":")
        if kind == "return_path":
            subjects = [(return_path or "").lower()]
        elif kind == "received":
            subjects = [h["raw"] for h in hops]
        elif kind == "header":
            subjects = header_all(msg, hname)
        else:
            subjects = [s["d"] or "" for s in sigs]
        for subj in subjects:
            m = re.search(pattern, subj, re.I)
            if not m:
                continue
            if vendor not in hits:
                hits[vendor] = {"score": 0, "evidence": [], "account_hint": None}
                order.append(vendor)
            h = hits[vendor]
            h["score"] += WHERE_WEIGHT[kind]
            if kind == "header":
                ev = f"{hname} header present"
            else:
                ev = f"{kind}: " + (subj if len(subj) <= 90 else subj[:87] + "...")
            if ev not in h["evidence"]:
                h["evidence"].append(ev)
            if grp and not h["account_hint"]:
                hint = m.group(grp)
                if hint.isdigit() and vendor in HINT_PREFIX:
                    hint = HINT_PREFIX[vendor] + hint
                h["account_hint"] = hint
            break
    if not hits:
        return {"vendor": None, "account_hint": None, "evidence": "no known platform pattern matched",
                "note": None, "candidates": []}
    best = max(order, key=lambda v: (hits[v]["score"], -order.index(v)))
    return {"vendor": best, "account_hint": hits[best]["account_hint"],
            "evidence": "; ".join(hits[best]["evidence"]), "note": FINGERPRINT_NOTES.get(best),
            "candidates": [{"vendor": v, "score": hits[v]["score"]} for v in order]}


# ---------------------------------------------------------------- DNS (optional, --verify-dns)

def make_resolver(addr):
    if dns is None:
        return None
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [addr]
    r.lifetime = 10
    return r


def _looks_like_key(txt):
    low = txt.lower().strip()
    return low.startswith("v=dkim1") or re.search(r"(^|;)\s*p=", low) is not None


def verify_selector(sig, resolver):
    """Does s._domainkey.d publish a key? Existence only, never a signature check.

    Uses dns_audit's resolver: port 53 first, DNS-over-HTTPS cross-check, so a
    'missing' verdict is not one resolver path's opinion.
    """
    name = f"{sig['s']}._domainkey.{sig['d']}"
    if dns_audit is None:
        return {"name": name, "status": "error", "path": None, "key_found": False, "revoked": False,
                "err": "dns_audit unavailable"}
    resolve_ex = getattr(dns_audit, "resolve_ex", None)
    if resolve_ex is not None:
        recs, meta = resolve_ex(resolver, name, "TXT")
    else:
        recs, meta = dns_audit.resolve(resolver, name, "TXT"), {"status": None, "path": None}
        meta["status"] = "found" if recs else "absent"
    keys = [t for t in recs if _looks_like_key(t)]
    revoked = bool(keys) and all(re.search(r"(^|;)\s*p=\s*(;|$)", k) for k in keys)
    out = {"name": name, "status": meta.get("status"), "path": meta.get("path"),
           "key_found": bool(keys), "revoked": revoked}
    if meta.get("err"):
        out["err"] = meta["err"]
    return out


# ---------------------------------------------------------------- analysis

def would_pass_via(spf, sigs, strict=False):
    """What DMARC would pass on, from the receiver's verdicts plus alignment."""
    key = "aligned_strict" if strict else "aligned_relaxed"
    dkim_ok = any(s["ar_result"] == "pass" and s[key] for s in sigs)
    spf_ok = bool(spf and spf.get("result") == "pass" and spf[key])
    if dkim_ok and spf_ok:
        return "both"
    return "dkim" if dkim_ok else "spf" if spf_ok else "none"


def build_findings(r, authserv_id=None):
    """Standard finding objects (area proof) from one analyzed message."""
    findings = []

    def add(fid, severity, title, evidence, action, verified=True):
        findings.append({"id": fid, "severity": severity, "area": "proof", "title": title,
                         "evidence": evidence, "action": action, "verified": verified})

    fd = r["from_domain"] or "?"
    sigs = r["dkim_signatures"]
    on_wire = [s for s in sigs if s["header_present"]]
    spf, dmarc = r["spf"], r["dmarc"]
    seen_ids = sorted({a["authserv_id"] or "(no authserv-id)" for a in r["ar_headers"]})

    # --- is the proof trustworthy
    if r["ar_header_count"] == 0:
        add("PROOF-004", "major", "no Authentication-Results header - this header proves nothing about authentication",
            "0 Authentication-Results headers", "get the header from a mailbox on the receiving side, after the filtering host wrote its verdicts",
            verified=False)
    elif not r["ar_trusted"]:
        if authserv_id:
            add("PROOF-004", "major", f"Authentication-Results is not from {authserv_id} - verdicts below are untrusted",
                "authserv-ids present: " + ", ".join(seen_ids),
                "senders can inject this header; use the header as received by the host whose authserv-id you passed, or pass the id that host actually writes",
                verified=False)
        else:
            add("PROOF-005", "info", "no --authserv-id given: topmost Authentication-Results trusted without verification",
                "authserv-ids present: " + ", ".join(seen_ids),
                "re-run with --authserv-id <id your receiving host writes> so an injected header cannot pass as proof",
                verified=False)

    # --- DKIM on the wire
    if not on_wire:
        ar_dkim = ", ".join(f"{v['result']} d={v['d']}" for v in r["ar_dkim"]) or "none"
        add("PROOF-001", "major", f"no DKIM-Signature on the wire - nothing here proves DKIM signing for {fd}",
            f"0 DKIM-Signature headers; receiver dkim verdicts: {ar_dkim}",
            "DKIM-sign at the sending platform, then re-send a test and look for d=" + fd + " in this header; a dashboard toggle is not proof")
    elif not any(s["aligned_relaxed"] for s in sigs):
        ds = ", ".join(f"d={s['d']} s={s['s']} ({s['ar_result'] or 'no verdict'})" for s in sigs)
        google = any((s["d"] or "").endswith(".gappssmtp.com") for s in sigs)
        if google:
            title = f"Google default key (gappssmtp.com) - DKIM is not set up for {fd}, signature does not align"
            action = f"in Google Admin, generate and publish a DKIM key for {fd} and turn on authentication; until then DMARC for this mail rides on SPF alone"
        else:
            title = f"DKIM signed, but not as {fd} - no signature domain aligns with From"
            action = f"set up domain authentication at the platform so d= is {fd} or a subdomain of it; the platform's own domain in d= does nothing for DMARC"
        add("PROOF-002", "major", title, ds, action)
    else:
        for s in sigs:
            if s["aligned_relaxed"] and s["ar_result"] is None:
                add("PROOF-009", "minor", f"aligned signature d={s['d']} s={s['s']} has no verdict in the Authentication-Results used",
                    "receiver dkim verdicts: " + (", ".join(f"{v['result']} d={v['d']}" for v in r["ar_dkim"]) or "none"),
                    "the receiver did not evaluate this signature; pass/fail for it is unknown from this header",
                    verified=False)

    # --- SPF-only pass
    if r["dmarc_would_pass_via"] == "spf":
        add("PROOF-003", "minor", "DMARC passes on SPF alone - breaks the moment this mail is forwarded",
            f"spf={spf['result']} smtp.mailfrom={spf.get('smtp_mailfrom')} aligned; no aligned DKIM pass",
            "add aligned DKIM at this platform; SPF-only senders are the echo failures dedupe.py keeps finding")

    # --- Reply-To
    rt = r["reply_to_domain"]
    if rt and r["from_domain"] and org_domain(rt) != org_domain(r["from_domain"]):
        add("PROOF-006", "minor", f"Reply-To domain {rt} differs from From domain {r['from_domain']}",
            f"From: {r['from']}  Reply-To: {r['reply_to']}",
            "normal for some ESP reply-tracking flows; otherwise an impersonation signal - check the sender inventory before trusting it",
            verified=False)

    # --- forwarded chain vs genuine failure
    spf_fail = bool(spf and spf.get("result") and spf["result"] != "pass")
    dmarc_fail = bool(dmarc and dmarc.get("result") and dmarc["result"] != "pass")
    forwarded = r["arc_present"] or len(r["external_receivers"]) >= 2
    if forwarded and (spf_fail or dmarc_fail):
        earlier = [a for a in r["ar_headers"] if a is not r["_ar"]
                   and any(m["method"] == "dmarc" and m["result"] == "pass" for m in a["methods"])]
        bits = []
        if r["arc_present"]:
            bits.append("ARC sealed by " + ", ".join(r["arc_sealers"]))
        if len(r["external_receivers"]) >= 2:
            bits.append("accepted by " + " then ".join(r["external_receivers"]))
        for a in earlier:
            bits.append(f"earlier {a['source']} from {a['authserv_id'] or '?'} recorded dmarc=pass")
        add("PROOF-007", "info",
            "forwarded chain explains the failure - an echo of a message that passed, not a genuine failure"
            if earlier else "forwarded chain - the failure is likely an echo, not the sender's fault",
            "; ".join(bits),
            "dedupe by Message-ID against the delivered copy before counting this; if no copy passed, the sender still needs aligned DKIM (SPF never survives a forward)",
            verified=False)
    elif dmarc_fail:
        add("PROOF-008", "major", f"DMARC {dmarc['result']} with no forwarding in the chain - genuine failure",
            f"spf={spf['result'] if spf else '?'} dkim={', '.join(f'{v['result']} d={v['d']}' for v in r['ar_dkim']) or 'none'} "
            f"header.from={dmarc.get('header_from')} action={dmarc.get('action')}",
            "if this sender is yours, fix alignment at the platform (DKIM d= or MAIL FROM domain); if it is not, this is a spoof and no override should let it through")

    # --- DNS existence of the selector (only with --verify-dns)
    for s in sigs:
        d = s.get("dns")
        if not d:
            continue
        if d["status"] == "error":
            add("PROOF-011", "minor", f"selector lookup failed for {d['name']} - key presence not verified",
                f"status {d['status']} via {d.get('path') or 'no path'}: {d.get('err') or '?'}",
                "re-run from a network with working DNS before concluding anything about this key",
                verified=False)
        elif not d["key_found"]:
            add("PROOF-010", "major", f"no DKIM key published at {d['name']}",
                f"TXT {d['status']} via {d.get('path')}; receiver said dkim={s['ar_result'] or 'no verdict'}",
                "if the receiver said pass, the key was removed since or the header is not genuine; either way nothing can verify with this selector today")
        elif d["revoked"]:
            add("PROOF-010", "major", f"DKIM key at {d['name']} is revoked (empty p=)",
                f"TXT via {d.get('path')}; receiver said dkim={s['ar_result'] or 'no verdict'}",
                "the platform is signing with a selector whose key was revoked; rotate at the platform and republish")
        else:
            add("PROOF-012", "info", f"DKIM key exists at {d['name']} (existence only, signature not cryptographically checked)",
                f"TXT found via {d.get('path')}", "no action; this shows the selector is live, the receiver's verdict says whether it verified")
    return findings


def analyze(msg, authserv_id=None, strict=False, verify=False, resolver=None, file=None):
    """Full analysis of one parsed message (headers only). Returns the per-message document."""
    from_addr = _address(header_one(msg, "From"))
    from_domain = _addr_domain(from_addr)
    return_path = _address(header_one(msg, "Return-Path"))
    reply_to = _address(header_one(msg, "Reply-To"))
    sender = _address(header_one(msg, "Sender"))

    hops = received_chain(msg)
    ars = collect_ar(msg)
    ar, trusted, why = choose_ar(ars, authserv_id, hops)
    v = ar_verdicts(ar)

    spf = v["spf"]
    if spf is None and return_path:
        spf = {"result": None, "smtp_mailfrom": return_path, "domain": _addr_domain(return_path),
               "note": "no spf verdict in the Authentication-Results used; domain taken from Return-Path"}
    if spf is not None:
        spf["aligned_relaxed"] = aligned(spf["domain"], from_domain)
        spf["aligned_strict"] = aligned(spf["domain"], from_domain, strict=True)

    sigs = []
    for val in header_all(msg, "DKIM-Signature"):
        s = parse_dkim_signature(val)
        s["header_present"] = True
        s["aligned_relaxed"] = aligned(s["d"], from_domain)
        s["aligned_strict"] = aligned(s["d"], from_domain, strict=True)
        s["ar_result"] = match_ar_dkim(s, v["dkim"])
        sigs.append(s)
    for vd in v["dkim"]:  # receiver verdicts for signatures not in the paste
        if vd["d"] and vd["result"] != "none" and not any(s["d"] == vd["d"] and (not vd["s"] or not s["s"] or s["s"] == vd["s"]) for s in sigs):
            sigs.append({"d": vd["d"], "s": vd["s"], "a": None, "c": None, "i": vd["i"], "h": [],
                         "bh_present": False, "b_present": False, "t": None, "x": None,
                         "header_present": False,
                         "aligned_relaxed": aligned(vd["d"], from_domain),
                         "aligned_strict": aligned(vd["d"], from_domain, strict=True),
                         "ar_result": vd["result"]})
    if verify:
        for s in sigs:
            if s["d"] and s["s"]:
                s["dns"] = verify_selector(s, resolver)

    arc_sealers = sorted({(parse_dkim_signature(x).get("d") or "?") for x in header_all(msg, "ARC-Seal")})
    arc_present = bool(arc_sealers or any(a["source"] == "ARC-Authentication-Results" for a in ars))

    r = {"file": file,
         "from": from_addr, "from_domain": from_domain,
         "return_path": return_path, "return_path_domain": _addr_domain(return_path),
         "sender": sender, "reply_to": reply_to, "reply_to_domain": _addr_domain(reply_to),
         "to": header_one(msg, "To"), "message_id": header_one(msg, "Message-ID"),
         "date": header_one(msg, "Date"),
         "authserv_id_used": ar["authserv_id"] if ar else None,
         "ar_trusted": trusted, "ar_reason": why, "ar_header_count": sum(1 for a in ars if a["source"] == "Authentication-Results"),
         "ar_headers": ars, "_ar": ar, "ar_dkim": v["dkim"],
         "spf": spf, "dkim_signatures": sigs, "dmarc": v["dmarc"], "compauth": v["compauth"], "arc": v["arc"],
         "dmarc_would_pass_via": would_pass_via(spf, sigs, strict),
         "received": hops, "received_count": len(hops), "first_external_ip": first_external_ip(hops),
         "external_receivers": external_receivers(hops),
         "arc_present": arc_present, "arc_sealers": arc_sealers,
         "fingerprint": fingerprint(msg, return_path, hops, [s for s in sigs if s["header_present"]])}
    r["findings"] = build_findings(r, authserv_id)
    del r["_ar"]
    return r


def worst_severity(findings):
    return max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)


def exit_code(findings):
    return 1 if any(f["severity"] in ("major", "blocking") for f in findings) else 0


# ---------------------------------------------------------------- cli

def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def _align_word(item):
    if item.get("aligned_strict"):
        return "aligned (strict)"
    if item.get("aligned_relaxed"):
        return "aligned (relaxed)"
    return "NOT aligned"


def print_report(r):
    print(f"=== {r['file']} ===")
    print(f"  From        : {r['from'] or '?'}" + (f"   Reply-To: {r['reply_to']}" if r["reply_to"] and r["reply_to"] != r["from"] else ""))
    print(f"  Return-Path : {r['return_path'] or '(none)'}")
    print(f"  Message-ID  : {r['message_id'] or '(none)'}")
    print(f"  Date        : {r['date'] or '(none)'}")
    trust = "trusted" if r["ar_trusted"] else "UNTRUSTED"
    print(f"  AR used     : {r['authserv_id_used'] or '(none)'} - {trust}: {r['ar_reason']}")
    spf = r["spf"]
    if spf:
        print(f"  SPF         : {spf['result'] or 'no verdict'} smtp.mailfrom={spf.get('smtp_mailfrom') or '?'} - {_align_word(spf)}")
    else:
        print("  SPF         : no verdict, no Return-Path")
    sigs = r["dkim_signatures"]
    on_wire = sum(1 for s in sigs if s["header_present"])
    print(f"  DKIM        : {on_wire} signature{'s' if on_wire != 1 else ''} on the wire")
    for s in sigs:
        src = "" if s["header_present"] else " (verdict only, no DKIM-Signature in the paste)"
        dnsnote = ""
        if s.get("dns"):
            d = s["dns"]
            dnsnote = "; key " + ("revoked" if d["revoked"] else "exists" if d["key_found"] else
                                  "lookup failed" if d["status"] == "error" else "MISSING") + f" via {d.get('path') or '?'}"
        print(f"     d={s['d']} s={s['s'] or '?'} a={s['a'] or '?'} c={s['c'] or '?'} -> receiver: {s['ar_result'] or 'no verdict'}, {_align_word(s)}{dnsnote}{src}")
    dm = r["dmarc"]
    if dm:
        extra = " ".join(f"{k.replace('_', '.')}={dm[k]}" for k in ("action", "policy", "header_from") if dm.get(k))
        print(f"  DMARC       : {dm['result']} {extra} -> would pass via: {r['dmarc_would_pass_via']}")
    else:
        print(f"  DMARC       : no verdict -> would pass via: {r['dmarc_would_pass_via']}")
    if r["compauth"]:
        print(f"  compauth    : {r['compauth']['result']} reason={r['compauth'].get('reason')}")
    ext = ", ".join(r["external_receivers"]) or "none"
    arc = " ARC sealed by " + ", ".join(r["arc_sealers"]) if r["arc_present"] else ""
    n = r["received_count"]
    print(f"  Received    : {n} hop{'s' if n != 1 else ''}, first external IP {r['first_external_ip'] or 'none'}, external receivers: {ext}{arc}")
    for h in r["received"]:
        ip = f" [{h['ip']}]" if h["ip"] else ""
        print(f"     {h['hop']}. {h['from'] or '-'}{ip} -> {h['by'] or '-'} ({h['with'] or '?'}) {h['timestamp'] or ''}")
    fp = r["fingerprint"]
    hint = f" (account hint {fp['account_hint']})" if fp["account_hint"] else ""
    print(f"  Platform    : {fp['vendor'] or 'unknown'}{hint} - {fp['evidence']}")
    if fp["note"]:
        print(f"                {fp['note']}")
    for f in r["findings"]:
        print(f"  !! [{f['severity']}] {f['id']} {f['title']}" + ("" if f["verified"] else " (not verified)"))
        print(f"       fix: {f['action']}")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="raw header blocks or .eml files (relative paths resolve from the repo root)")
    ap.add_argument("--authserv-id", help="authserv-id your receiving host writes into Authentication-Results, "
                                          "e.g. example.com or mail.protection.outlook.com; without it the topmost header is trusted unverified")
    ap.add_argument("--strict", action="store_true", help="require strict alignment (adkim=s / aspf=s) when deciding what DMARC would pass on")
    ap.add_argument("--verify-dns", action="store_true", help="look up each signature's selector TXT to show the key exists (existence only, no crypto)")
    ap.add_argument("--resolver", default="8.8.8.8", help="port-53 resolver for --verify-dns; DNS-over-HTTPS is the fallback")
    ap.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    args = ap.parse_args()

    if args.verify_dns and dns_audit is None:
        die("--verify-dns needs dns_audit.py next to this script")
    resolver = make_resolver(args.resolver) if args.verify_dns else None
    if not args.authserv_id:
        print("warning: no --authserv-id; the topmost Authentication-Results is trusted unverified "
              "(senders can inject that header)", file=sys.stderr)

    results = []
    for f in args.files:
        path = repo_path(f)
        try:
            msg = read_headers(path)
        except OSError as exc:
            die(f"cannot read {path}: {exc.strerror or exc}")
        if not msg.keys():
            die(f"{path}: no headers found (expected a raw header block or a .eml file)")
        r = analyze(msg, args.authserv_id, args.strict, args.verify_dns, resolver, file=str(path))
        if args.authserv_id and not r["ar_trusted"]:
            print(f"warning: {path}: {r['ar_reason']}", file=sys.stderr)
        results.append(r)

    all_findings = [dict(f, file=r["file"]) for r in results for f in r["findings"]]
    code = exit_code(all_findings)
    actionable = sum(1 for f in all_findings if f["severity"] in ("major", "blocking"))

    if args.json:
        print(json.dumps({"messages": results, "findings": all_findings,
                          "summary": {"messages": len(results), "findings": len(all_findings),
                                      "actionable": actionable, "worst": worst_severity(all_findings),
                                      "exit_code": code}}, indent=1))
        sys.exit(code)

    for r in results:
        print_report(r)
    print(f"{len(results)} message{'s' if len(results) != 1 else ''} analyzed, {len(all_findings)} findings, {actionable} major or blocking")
    sys.exit(code)


if __name__ == "__main__":
    main()
