"""Parse DMARC aggregate (rua) reports - the outside view.

Tenant logs only cover mail that touched your tenant. Aggregate reports are
what the rest of the world saw: every receiver that honours your rua address
tells you which IPs sent as your domain, whether DKIM or SPF aligned, and what
it did with the mail. This parser reads those reports directly, stdlib only,
so the answers do not depend on a dashboard.

What it answers
---------------
  - who sends as the domain, from where, at what volume, how it authenticated
  - which DKIM selectors are actually signing, per signing domain: the
    evidence CLAUDE.md rule 8 demands before any key is deleted
    (--retiring-selector NAME shows the count for one key)
  - which sources are not in your inventory (--known: domains and IP prefixes)
  - which sources fail with real volume, with a heuristic likely label
  - who passes on SPF alone (breaks on forwarding, so DKIM before p=reject)
  - whether receivers saw the policy you think you published (--expect-policy)

Input: files or directories (recursed). Files may be .xml, .xml.gz, .gz or
.zip; the format is sniffed, so a mislabeled file still parses. A malformed
file is skipped with a warning, never a crash, and decompression is capped at
50 MB per file. Relative paths resolve from the repo root, not the cwd.

Usage
-----
    python rua_parse.py samples/rua
    python rua_parse.py reports/ --known vendor.example,192.0.2.0/24 --retiring-selector legacy2019
    python rua_parse.py reports/ --since 2026-09-01 --expect-policy reject --json

Counts here are what receivers reported and cannot be deduplicated (aggregate
reports carry no Message-ID): a forwarded copy that failed counts as a failure
even when the original passed. Read fail counts with that in mind and
cross-check volume against tenant logs (src/dedupe.py) before acting.

Exit codes: 0 clean, 1 findings at severity major or blocking, 2 usage or
input error.
"""

import argparse
import gzip
import io
import ipaddress
import json
import re
import socket
import sys
import threading
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from dns_audit import org_domain  # same apex logic as the DNS audit
except ImportError:  # running outside the repo: a small local copy
    _TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp",
                  "com.br", "co.nz", "co.za", "co.in", "com.mx", "com.sg", "com.hk", "com.tw", "co.kr"}

    def org_domain(domain):
        labels = domain.lower().strip(".").split(".")
        if len(labels) > 2 and ".".join(labels[-2:]) in _TWO_LEVEL:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

ROOT = Path(__file__).resolve().parent.parent

AREA = "outside_view"
MAX_BYTES = 50 * 1024 * 1024        # decompressed cap per file: zip bombs and runaway reports
REPORT_SUFFIXES = (".xml", ".gz", ".zip")
RDNS_TIMEOUT = 3
SEVERITY_RANK = {"info": 0, "minor": 1, "major": 2, "blocking": 3}
DISPOSITIONS = ("none", "quarantine", "reject")
POLICIES = ("none", "quarantine", "reject")
LIKELY_LABELS = ("likely_spoof", "likely_misconfigured", "unknown")
DOMAIN_RE = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*")


# ------------------------------------------------------------------ input

def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def read_list(path):
    """One entry per line; blanks and # comments skipped. Exit 2 if unreadable."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    except OSError as exc:
        die(f"cannot read {path}: {exc.strerror or exc}")


def collect_files(paths):
    """Report files under the given paths; directories are recursed. Exit 2 on a missing path."""
    files = []
    for p in paths:
        path = repo_path(p)
        if path.is_dir():
            files += sorted(f for f in path.rglob("*")
                            if f.is_file() and f.suffix.lower() in REPORT_SUFFIXES)
        elif path.is_file():
            files.append(path)
        else:
            die(f"no such file or directory: {path}")
    return files


def _capped(fh, what=""):
    data = fh.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{what}decompressed size over the {MAX_BYTES // (1024 * 1024)} MB cap")
    return data


def read_payloads(path):
    """(label, xml_bytes) for every report inside one file.

    The container format is sniffed from magic bytes, not trusted from the
    name. A zip may hold several reports; a gzipped member inside it is
    unpacked too. Raises on anything unreadable; the caller turns that into
    a warning for this one file."""
    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(b"PK") and zipfile.is_zipfile(path):
        out, total = [], 0
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                label = f"{path.name}:{info.filename}"
                with zf.open(info) as member:
                    data = _capped(member, f"member {info.filename}: ")
                if data[:2] == b"\x1f\x8b":
                    data = _capped(gzip.GzipFile(fileobj=io.BytesIO(data)), f"member {info.filename}: ")
                total += len(data)
                if total > MAX_BYTES:
                    raise ValueError(f"members exceed the {MAX_BYTES // (1024 * 1024)} MB cap together")
                out.append((label, data))
        if not out:
            raise ValueError("empty zip")
        return out
    if head.startswith(b"\x1f\x8b"):
        with gzip.open(path, "rb") as fh:
            return [(path.name, _capped(fh))]
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"over the {MAX_BYTES // (1024 * 1024)} MB cap")
    with open(path, "rb") as fh:
        return [(path.name, fh.read())]


# ---------------------------------------------------------------- parsing

def _local(tag):
    """Local element name, lower-case, with any {namespace} prefix dropped."""
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _children(el, name):
    return [] if el is None else [c for c in el if _local(c.tag) == name]


def _child(el, *names):
    """First element along a path of local names; None when any step is missing."""
    for name in names:
        if el is None:
            return None
        el = next((c for c in el if _local(c.tag) == name), None)
    return el


def _text(el, *names, lower=False):
    node = _child(el, *names)
    txt = (node.text or "").strip() if node is not None else ""
    if not txt:
        return None
    return txt.lower() if lower else txt


def _int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def _find_root(root):
    """The <feedback> element: the document root, or the first one below it."""
    if _local(root.tag) == "feedback":
        return root
    for el in root.iter():
        if _local(el.tag) == "feedback":
            return el
    if _child(root, "report_metadata") is not None or _children(root, "record"):
        return root  # no <feedback> wrapper but the report parts are there
    raise ValueError("no <feedback> element")


def parse_report(data, label="report"):
    """One aggregate report as a dict. Tolerates namespaces, missing elements
    and odd casing; raises ValueError or ET.ParseError on a broken file."""
    if b"<!ENTITY" in data or b"<!DOCTYPE" in data:
        raise ValueError("DTD or entity declaration present - not an aggregate report")
    root = _find_root(ET.fromstring(data))
    meta = _child(root, "report_metadata")
    pol = _child(root, "policy_published")
    rep = {
        "source": label,
        "org_name": _text(meta, "org_name"),
        "email": _text(meta, "email"),
        "report_id": _text(meta, "report_id"),
        "begin": _int(_text(meta, "date_range", "begin")),
        "end": _int(_text(meta, "date_range", "end")),
        "policy": {k: _text(pol, k, lower=True) for k in ("domain", "adkim", "aspf", "p", "sp", "pct")},
        "records": [],
    }
    for rec in _children(root, "record"):
        row = _child(rec, "row")
        pe = _child(row, "policy_evaluated")
        ids = _child(rec, "identifiers")
        auth = _child(rec, "auth_results")
        rep["records"].append({
            "source_ip": _text(row, "source_ip", lower=True),
            "count": _int(_text(row, "count"), 1),
            "disposition": _text(pe, "disposition", lower=True),
            "dkim": _text(pe, "dkim", lower=True),
            "spf": _text(pe, "spf", lower=True),
            "reasons": [t for t in (_text(rs, "type", lower=True) for rs in _children(pe, "reason")) if t],
            "header_from": _text(ids, "header_from", lower=True),
            "envelope_from": _text(ids, "envelope_from", lower=True),
            "envelope_to": _text(ids, "envelope_to", lower=True),
            "dkim_auth": [{"domain": _text(d, "domain", lower=True), "selector": _text(d, "selector", lower=True),
                           "result": _text(d, "result", lower=True)} for d in _children(auth, "dkim")],
            "spf_auth": [{"domain": _text(s, "domain", lower=True), "scope": _text(s, "scope", lower=True),
                          "result": _text(s, "result", lower=True)} for s in _children(auth, "spf")],
        })
    return rep


def load_reports(files, warnings=None):
    """Parse every file; a bad file gets a warning line, never a crash.

    Returns (reports, skipped). warnings, when given, collects the lines."""
    reports, skipped = [], 0
    for path in files:
        try:
            payloads = read_payloads(path)
        except Exception as exc:  # zip, gzip, size cap, permissions: all per-file problems
            msg = f"skipped {path}: {exc}"
            print(f"warning: {msg}", file=sys.stderr)
            if warnings is not None:
                warnings.append(msg)
            skipped += 1
            continue
        for label, data in payloads:
            try:
                reports.append(parse_report(data, label))
            except (ET.ParseError, ValueError) as exc:
                msg = f"skipped {label}: not an aggregate report ({exc})"
                print(f"warning: {msg}", file=sys.stderr)
                if warnings is not None:
                    warnings.append(msg)
                skipped += 1
    return reports, skipped


# -------------------------------------------------------------- alignment

def aligned(domain, header_from, mode):
    """DMARC identifier alignment: strict is equal, relaxed is same apex."""
    if not domain or not header_from:
        return False
    if (mode or "r").startswith("s"):
        return domain == header_from
    return org_domain(domain) == org_domain(header_from)


def evaluate(rec, policy):
    """(dkim_aligned, spf_aligned) for one record: the reporter's
    policy_evaluated verdict when present, else derived from auth_results
    under the published alignment mode."""
    hf = rec["header_from"]
    dk, sp = rec["dkim"], rec["spf"]
    if dk is None:
        dk = "pass" if any(a["result"] == "pass" and aligned(a["domain"], hf, policy.get("adkim"))
                           for a in rec["dkim_auth"]) else "fail"
    if sp is None:
        sp = "pass" if any(a["result"] == "pass" and aligned(a["domain"], hf, policy.get("aspf"))
                           for a in rec["spf_auth"]) else "fail"
    return dk == "pass", sp == "pass"


def _under(domain, roots):
    return bool(domain) and any(domain == r or domain.endswith("." + r) for r in roots if r)


def _day(ts):
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def _span(d, begin, end):
    for key, val, pick in (("begin", begin, min), ("end", end, max)):
        if val is None:
            continue
        d[key] = val if d[key] is None else pick(d[key], val)


# -------------------------------------------------------------- aggregate

def _new_source():
    return {"count": 0, "pass": 0, "fail": 0, "dkim_pass": 0, "spf_pass": 0, "both": 0, "dkim_only": 0,
            "spf_only": 0, "no_auth": 0, "misaligned_dkim": 0, "misaligned_spf": 0, "dkim_failed": 0,
            "aligned_dkim_failed": 0,
            "header_from": Counter(), "envelope_from": Counter(), "dispositions": Counter(),
            "reasons": Counter(), "dkim": Counter(), "spf": Counter(), "reporters": set(),
            "begin": None, "end": None}


def _new_from():
    return {"count": 0, "pass": 0, "fail": 0, "dispositions": Counter(), "sources": set(),
            "dkim_pass": 0, "spf_pass": 0}


def _new_reporter():
    return {"reports": 0, "records": 0, "messages": 0, "pass": 0, "fail": 0, "emails": set(),
            "policies": Counter(), "begin": None, "end": None}


def _new_selector():
    return {"messages": 0, "pass": 0, "sources": set(), "header_from": set(), "begin": None, "end": None}


def aggregate(reports):
    """Roll every record up by source IP, header_from, reporter and DKIM selector."""
    agg = {"reports": len(reports), "records": 0, "messages": 0, "pass": 0, "fail": 0,
           "dispositions": Counter(), "aligned": Counter(), "raw_dkim_pass": 0, "raw_spf_pass": 0,
           "domains": set(), "policies": Counter(), "begin": None, "end": None,
           "sources": defaultdict(_new_source), "header_from": defaultdict(_new_from),
           "reporters": defaultdict(_new_reporter), "selectors": defaultdict(_new_selector)}
    for rep in reports:
        pol = rep["policy"]
        dom = pol.get("domain")
        if dom:
            agg["domains"].add(dom)
        agg["policies"][(dom, pol.get("p"), pol.get("sp"), pol.get("pct"), pol.get("adkim"), pol.get("aspf"))] += 1
        _span(agg, rep["begin"], rep["end"])
        org = rep["org_name"] or "(unknown org)"
        r = agg["reporters"][org]
        r["reports"] += 1
        r["records"] += len(rep["records"])
        r["policies"][pol.get("p") or "(missing)"] += 1
        if rep["email"]:
            r["emails"].add(rep["email"])
        _span(r, rep["begin"], rep["end"])

        for rec in rep["records"]:
            n = rec["count"]
            dk_al, sp_al = evaluate(rec, pol)
            passed = dk_al or sp_al
            raw_dk = any(a["result"] == "pass" for a in rec["dkim_auth"])
            raw_sp = any(a["result"] == "pass" for a in rec["spf_auth"])
            disp = rec["disposition"] if rec["disposition"] in DISPOSITIONS else (rec["disposition"] or "(missing)")
            hf = rec["header_from"] or "(no header_from)"
            ip = rec["source_ip"] or "(no source_ip)"

            agg["records"] += 1
            agg["messages"] += n
            agg["pass" if passed else "fail"] += n
            agg["dispositions"][disp] += n
            agg["aligned"]["both" if dk_al and sp_al else "dkim_only" if dk_al else "spf_only" if sp_al else "neither"] += n
            agg["raw_dkim_pass"] += n if raw_dk else 0
            agg["raw_spf_pass"] += n if raw_sp else 0
            r["messages"] += n
            r["pass" if passed else "fail"] += n

            s = agg["sources"][ip]
            s["count"] += n
            s["pass" if passed else "fail"] += n
            s["dkim_pass"] += n if dk_al else 0
            s["spf_pass"] += n if sp_al else 0
            s["both"] += n if dk_al and sp_al else 0
            s["dkim_only"] += n if dk_al and not sp_al else 0
            s["spf_only"] += n if sp_al and not dk_al else 0
            s["no_auth"] += n if not rec["dkim_auth"] and not raw_sp else 0
            s["misaligned_dkim"] += n if raw_dk and not dk_al else 0
            s["misaligned_spf"] += n if raw_sp and not sp_al else 0
            s["dkim_failed"] += n if rec["dkim_auth"] and not raw_dk else 0
            # a signature for the domain itself that did not verify: the mark of a forward or a broken key
            s["aligned_dkim_failed"] += n if any(a["result"] != "pass" and aligned(a["domain"], rec["header_from"], "r")
                                                 for a in rec["dkim_auth"]) and not dk_al else 0
            s["header_from"][hf] += n
            s["envelope_from"][rec["envelope_from"] or "(none)"] += n
            s["dispositions"][disp] += n
            for reason in rec["reasons"]:
                s["reasons"][reason] += n
            for a in rec["dkim_auth"]:
                s["dkim"][(a["domain"], a["selector"], a["result"])] += n
            for a in rec["spf_auth"]:
                s["spf"][(a["domain"], a["scope"], a["result"])] += n
            s["reporters"].add(org)
            _span(s, rep["begin"], rep["end"])

            f = agg["header_from"][hf]
            f["count"] += n
            f["pass" if passed else "fail"] += n
            f["dkim_pass"] += n if dk_al else 0
            f["spf_pass"] += n if sp_al else 0
            f["dispositions"][disp] += n
            f["sources"].add(ip)

            for a in rec["dkim_auth"]:
                if not a["domain"] and not a["selector"]:
                    continue
                k = agg["selectors"][(a["domain"] or "(no domain)", a["selector"] or "(no selector)")]
                k["messages"] += n
                k["pass"] += n if a["result"] == "pass" else 0
                k["sources"].add(ip)
                k["header_from"].add(hf)
                _span(k, rep["begin"], rep["end"])
    return agg


# ---------------------------------------------------------------- derived

def parse_known(value):
    """(networks, domains) from a comma list, or a file with one entry per line."""
    if not value:
        return [], []
    path = repo_path(value)
    raw = read_list(path) if path.is_file() else [value]
    nets, domains = [], []
    for line in raw:
        for e in line.split(","):
            e = e.strip().lower().rstrip(".")
            if not e:
                continue
            try:
                nets.append(ipaddress.ip_network(e, strict=False))
                continue
            except ValueError:
                pass
            if not DOMAIN_RE.fullmatch(e):
                die(f"--known entry is neither an IP prefix nor a domain: {e}")
            domains.append(e)
    return nets, domains


def ip_known(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def selectors_in_use(agg):
    """Every (signing domain, selector) seen, busiest first within each domain."""
    rows = []
    for (dom, sel), k in agg["selectors"].items():
        rows.append({"domain": dom, "selector": sel, "messages": k["messages"], "pass": k["pass"],
                     "source_ips": sorted(k["sources"]), "header_from": sorted(k["header_from"]),
                     "first_seen": _day(k["begin"]), "last_seen": _day(k["end"])})
    return sorted(rows, key=lambda r: (r["domain"], -r["messages"], r["selector"]))


def retiring_selectors(agg, names):
    """Per --retiring-selector name: where it still signs, or a zero row."""
    out = []
    rows = selectors_in_use(agg)
    for name in names:
        hits = [r for r in rows if r["selector"] == name]
        if hits:
            out += [dict(r, retiring=name) for r in hits]
        else:
            out.append({"domain": None, "selector": name, "messages": 0, "pass": 0, "source_ips": [],
                        "header_from": [], "first_seen": None, "last_seen": None, "retiring": name})
    return out


def unknown_senders(agg, nets, domains):
    """Source IPs outside the known prefixes and DKIM signing domains outside
    the known domains. The domains the reports are about count as known."""
    own = set(agg["domains"]) | set(domains)
    out = []
    for ip, s in agg["sources"].items():
        if ip_known(ip, nets):
            continue
        out.append({"kind": "ip", "value": ip, "count": s["count"], "pass": s["pass"], "fail": s["fail"],
                    "header_from": [d for d, _ in s["header_from"].most_common()],
                    "dkim_domains": sorted({d for (d, _, _) in s["dkim"] if d}),
                    "spf_domains": sorted({d for (d, _, _) in s["spf"] if d})})
    by_dom = defaultdict(lambda: {"count": 0, "pass": 0, "fail": 0, "ips": set(), "selectors": set()})
    for ip, s in agg["sources"].items():
        for (dom, sel, res), n in s["dkim"].items():
            if not dom or _under(dom, own):
                continue
            d = by_dom[dom]
            d["count"] += n
            d["pass" if res == "pass" else "fail"] += n
            d["ips"].add(ip)
            d["selectors"].add(sel or "(no selector)")
    for dom, d in by_dom.items():
        out.append({"kind": "dkim_domain", "value": dom, "count": d["count"], "pass": d["pass"],
                    "fail": d["fail"], "source_ips": sorted(d["ips"]), "selectors": sorted(d["selectors"])})
    return sorted(out, key=lambda u: (-u["count"], u["kind"], u["value"]))


def likely_label(s, domains):
    """Heuristic (label, signals) for one failing source. A guess, not a verdict."""
    signals = []
    own = all(_under(hf, domains) for hf in s["header_from"]) if domains else True
    unauth = s["no_auth"]
    if unauth * 2 >= s["count"]:
        signals.append(f"no DKIM signature and no SPF pass on any domain ({unauth} of {s['count']} msgs)")
        if own:
            signals.append("header_from is the domain itself")
            return "likely_spoof", signals
        signals.append("header_from is not one of the reported domains")
        return "unknown", signals
    fwd = sum(n for r, n in s["reasons"].items() if r in ("forwarded", "mailing_list", "trusted_forwarder"))
    if s["aligned_dkim_failed"] * 2 >= s["count"] or fwd * 2 >= s["count"]:
        if s["aligned_dkim_failed"]:
            signals.append(f"DKIM signature for the domain itself present but failed verification "
                           f"({s['aligned_dkim_failed']} msgs): modified in transit (forwarding, list) or a broken key")
        if fwd:
            signals.append(f"reporter marked {fwd} msgs as forwarded or list traffic")
        if s["misaligned_spf"]:
            doms = sorted({d for (d, _, r) in s["spf"] if r == "pass" and d})
            signals.append(f"SPF passes for {', '.join(doms) or '?'}, which looks like the forwarding hop")
        signals.append("not a sender misconfiguration if the original passed at the first hop; check tenant logs")
        return "unknown", signals
    if s["misaligned_dkim"]:
        doms = sorted({d for (d, _, r) in s["dkim"] if r == "pass" and d})
        signals.append(f"DKIM verifies for d={', '.join(doms) or '?'} but that domain is not aligned "
                       f"with header_from ({s['misaligned_dkim']} msgs)")
    if s["misaligned_spf"]:
        doms = sorted({d for (d, _, r) in s["spf"] if r == "pass" and d})
        signals.append(f"SPF passes for envelope domain {', '.join(doms) or '?'} which is not aligned "
                       f"with header_from ({s['misaligned_spf']} msgs)")
    if signals:
        return "likely_misconfigured", signals
    if s["dkim_failed"]:
        signals.append(f"DKIM signature present but failed verification ({s['dkim_failed']} msgs): "
                       "modified in transit (forwarding, list) or a broken key")
    for reason, n in s["reasons"].most_common(3):
        signals.append(f"reporter reason {reason} x{n}")
    if not signals:
        signals.append("mixed results with no single explanation")
    return "unknown", signals


def failing_streams(agg, min_volume, fail_threshold):
    """Sources with real volume and a pass rate under the threshold, labelled."""
    total = agg["messages"] or 1
    out = []
    for ip, s in agg["sources"].items():
        rate = s["pass"] / s["count"] if s["count"] else 0.0
        if s["count"] < min_volume or rate >= fail_threshold:
            continue
        label, signals = likely_label(s, agg["domains"])
        out.append({"source_ip": ip, "count": s["count"], "pass": s["pass"], "fail": s["fail"],
                    "pass_rate": round(rate, 4), "share": round(s["count"] / total, 4),
                    "header_from": [d for d, _ in s["header_from"].most_common()],
                    "dispositions": dict(s["dispositions"]),
                    "dkim_domains": sorted({d for (d, _, _) in s["dkim"] if d}),
                    "spf_domains": sorted({d for (d, _, _) in s["spf"] if d}),
                    "selectors": sorted({f"{d}/{sel}" for (d, sel, _) in s["dkim"] if d or sel}),
                    "likely": label, "likely_signals": signals})
    return sorted(out, key=lambda f: (-f["count"], f["source_ip"]))


def spf_only_senders(agg, min_volume):
    """Sources that pass DMARC on aligned SPF alone: fine today, broken by any forwarder."""
    out = []
    for ip, s in agg["sources"].items():
        if s["dkim_pass"] or s["spf_only"] < min_volume:
            continue
        signed = sorted({d for (d, _, r) in s["dkim"] if r == "pass" and d})
        out.append({"source_ip": ip, "count": s["count"], "spf_only": s["spf_only"],
                    "header_from": [d for d, _ in s["header_from"].most_common()],
                    "spf_domains": sorted({d for (d, _, r) in s["spf"] if r == "pass" and d}),
                    "unaligned_dkim_domains": signed})
    return sorted(out, key=lambda f: (-f["spf_only"], f["source_ip"]))


def policy_check(agg, expect):
    """What receivers saw published, and whether it matches --expect-policy."""
    seen = []
    for (dom, p, sp, pct, adkim, aspf), n in sorted(agg["policies"].items(), key=lambda kv: -kv[1]):
        seen.append({"domain": dom, "p": p, "sp": sp, "pct": pct, "adkim": adkim, "aspf": aspf, "reports": n})
    by_org = {org: dict(r["policies"]) for org, r in agg["reporters"].items()}
    mismatched = [dict(s) for s in seen if expect and (s["p"] or "(missing)") != expect]
    return {"expected": expect, "seen": seen, "by_reporter": by_org, "mismatched": mismatched,
            "reporters_disagree": len({s["p"] for s in seen}) > 1}


def rdns(ip, timeout=RDNS_TIMEOUT):
    """PTR name for ip, or None. Runs in a daemon thread so a hung resolver
    cannot stall the report past the timeout."""
    out = []

    def look():
        try:
            out.append(socket.gethostbyaddr(ip)[0])
        except Exception:
            out.append(None)

    t = threading.Thread(target=look, daemon=True)
    t.start()
    t.join(timeout)
    return out[0] if out else None


# --------------------------------------------------------------- findings

def _sample(items, fmt, n=5):
    return "; ".join(fmt(i) for i in items[:n]) + (f" ... +{len(items) - n} more" if len(items) > n else "")


def build_findings(agg, derived, opts, skipped=0, warnings=()):
    """Standard finding objects (area outside_view)."""
    findings = []
    min_volume = opts["min_volume"]

    def add(fid, severity, title, evidence, action, verified=True):
        findings.append({"id": fid, "severity": severity, "area": AREA, "title": title,
                         "evidence": evidence, "action": action, "verified": verified})

    streams = derived["failing_streams"]
    if streams:
        msgs = sum(f["fail"] for f in streams)
        add("OUTSIDE-001", "major",
            f"{len(streams)} source(s) fail DMARC with volume: {msgs} failing messages "
            f"(>= {min_volume} msgs, pass rate < {opts['fail_threshold']:.2f})",
            _sample(streams, lambda f: f"{f['source_ip']} x{f['count']} {f['pass_rate'] * 100:.0f}% pass "
                                       f"{'/'.join(f'{d} {n}' for d, n in f['dispositions'].items())} {f['likely']}"),
            "DKIM-sign the ones that are yours; confirm the spoofs show disposition reject and that no "
            "local override delivers them anyway; counts include forwarded copies, so cross-check volume "
            "against tenant logs (dedupe.py) before reporting a number")
        split = Counter(f["likely"] for f in streams)
        add("OUTSIDE-007", "info",
            "heuristic split of the failing streams: " + ", ".join(f"{split[l]} {l}" for l in LIKELY_LABELS),
            _sample(streams, lambda f: f"{f['source_ip']} {f['likely']}: {f['likely_signals'][0]}"),
            "verify from the sender inventory and live headers before acting; a label points the "
            "investigation, it is not a verdict",
            verified=False)

    if opts["known_given"]:
        unknown = [u for u in derived["unknown_senders"] if u["count"] >= min_volume]
        if unknown:
            passing = sum(u["pass"] for u in unknown)
            failing = sum(u["fail"] for u in unknown)
            add("OUTSIDE-002", "major",
                f"{len(unknown)} unknown sender(s) with volume, not in --known: {passing} msgs passing, {failing} failing",
                _sample(unknown, lambda u: f"{u['kind']} {u['value']} x{u['count']} ({u['pass']} pass) "
                                           f"from {', '.join((u.get('header_from') or u.get('source_ips') or ['?'])[:3])}"),
                "a passing unknown is a vendor missing from the inventory or an account you did not "
                "authorise: find the owner, then add it to --known; a failing unknown is either a spoof "
                "(leave it failing) or a sender that needs DKIM")
    elif agg["sources"]:
        add("OUTSIDE-009", "info",
            "no --known list: unknown-sender check not run, every source is listed as unknown",
            f"{len(agg['sources'])} source IPs seen",
            "pass --known with your vendors' domains and IP prefixes (comma list or file) to narrow the list",
            verified=False)

    spf_only = derived["spf_only_senders"]
    if spf_only:
        msgs = sum(f["spf_only"] for f in spf_only)
        add("OUTSIDE-003", "major",
            f"{len(spf_only)} sender(s) pass on SPF alone ({msgs} msgs): breaks on forwarding, rejected at p=reject",
            _sample(spf_only, lambda f: f"{f['source_ip']} x{f['spf_only']} as {', '.join(f['header_from'][:2])} "
                                        f"via spf {', '.join(f['spf_domains'][:2]) or '?'}"
                                        + (f" (signs unaligned d={', '.join(f['unaligned_dkim_domains'][:2])})"
                                           if f["unaligned_dkim_domains"] else "")),
            "set up DKIM with an aligned d= for these senders before ratcheting to p=reject; they pass "
            "today only because the receiving hop is direct")

    pc = derived["policy_check"]
    if pc["mismatched"]:
        add("OUTSIDE-004", "major",
            f"receivers saw p={', '.join(sorted({m['p'] or '(missing)' for m in pc['mismatched']}))} "
            f"but --expect-policy is {pc['expected']}",
            "; ".join(f"{m['domain'] or '?'} p={m['p'] or '(missing)'} sp={m['sp'] or '-'} pct={m['pct'] or '-'} "
                      f"in {m['reports']} report(s)" for m in pc["mismatched"]),
            "check the live _dmarc record with dns_audit.py; if DNS is right the reports predate the "
            "change (reports lag 24 to 48 hours), so re-run on a later window before trusting the gate")
    elif pc["reporters_disagree"]:
        add("OUTSIDE-010", "info",
            "reporters disagree on the published policy: " + ", ".join(
                f"p={s['p'] or '(missing)'} x{s['reports']}" for s in pc["seen"]),
            "; ".join(f"{org}: {', '.join(f'p={p} x{n}' for p, n in ps.items())}" for org, ps in pc["by_reporter"].items()),
            "a DNS change is propagating, or one reporter cached an old record; confirm with dns_audit.py")

    for r in derived["retiring_selectors"]:
        if r["messages"]:
            add("OUTSIDE-005", "blocking",
                f"retiring selector {r['retiring']} is still signing: {r['messages']} msgs for d={r['domain']} "
                f"(last seen {r['last_seen'] or '?'})",
                f"{r['pass']} verified; from {', '.join(r['source_ips'][:5])}; header_from {', '.join(r['header_from'][:3])}",
                "do not delete the key; find the sender behind those IPs, move it to the replacement "
                "selector, then re-check on a later window")
        else:
            window = f"{_day(agg['begin']) or '?'} .. {_day(agg['end']) or '?'}"
            add("OUTSIDE-006", "info",
                f"retiring selector {r['retiring']} not seen in {agg['reports']} report(s) ({window}): "
                "absence in this window is not proof",
                f"selectors seen: {', '.join(f'{s['domain']}/{s['selector']}' for s in derived['selectors'][:8]) or 'none'}",
                "retire only once the window covers every sender's cadence (monthly runs, quarterly "
                "statements); widen --since before deleting the key")

    if skipped:
        add("OUTSIDE-008", "minor",
            f"{skipped} file(s) skipped as unreadable or malformed",
            _sample(list(warnings), lambda w: w, 3),
            "a skipped report can hide a sender; re-fetch or inspect the file before trusting the totals")

    if not agg["reports"]:
        add("OUTSIDE-011", "info",
            "no reports fall in the --since/--until window",
            f"{opts.get('parsed_total', 0)} report(s) parsed, 0 in {opts['since'] or 'start'} .. {opts['until'] or 'end'}",
            "zero counts are not evidence of health; widen the window or fetch newer reports")
    elif not agg["messages"]:
        add("OUTSIDE-011", "info",
            "the parsed reports carry no messages",
            f"{agg['reports']} report(s), {agg['records']} records",
            "zero counts are not evidence of health; check the window and that rua reports are arriving")
    return findings


def worst_severity(findings):
    return max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)


def exit_code(findings):
    return 1 if any(f["severity"] in ("major", "blocking") for f in findings) else 0


# ------------------------------------------------------------------ doc

def _source_doc(ip, s, total, nets, known_given, names):
    return {
        "source_ip": ip, "count": s["count"], "share": round(s["count"] / (total or 1), 4),
        "pass": s["pass"], "fail": s["fail"], "pass_rate": round(s["pass"] / s["count"], 4) if s["count"] else 0.0,
        "dkim_aligned_pass": s["dkim_pass"], "spf_aligned_pass": s["spf_pass"],
        "both": s["both"], "dkim_only": s["dkim_only"], "spf_only": s["spf_only"], "no_auth": s["no_auth"],
        "header_from": [{"domain": d, "count": n} for d, n in s["header_from"].most_common()],
        "envelope_from": [{"domain": d, "count": n} for d, n in s["envelope_from"].most_common()],
        "dkim": [{"domain": d, "selector": sel, "result": r, "count": n}
                 for (d, sel, r), n in s["dkim"].most_common()],
        "spf": [{"domain": d, "scope": sc, "result": r, "count": n} for (d, sc, r), n in s["spf"].most_common()],
        "selectors": sorted({f"{d}/{sel}" for (d, sel, _) in s["dkim"] if d or sel}),
        "dispositions": dict(s["dispositions"]), "reasons": dict(s["reasons"]),
        "reporters": sorted(s["reporters"]),
        "first_seen": _day(s["begin"]), "last_seen": _day(s["end"]),
        "known": ip_known(ip, nets) if known_given else None,
        "rdns": names.get(ip),
    }


def build_doc(files, reports, agg, derived, findings, opts, skipped, warnings, names):
    total = agg["messages"]
    code = exit_code(findings)
    by_ip = sorted(agg["sources"].items(), key=lambda kv: (-kv[1]["count"], kv[0]))
    by_from = sorted(agg["header_from"].items(), key=lambda kv: (-kv[1]["count"], kv[0]))
    by_org = sorted(agg["reporters"].items(), key=lambda kv: (-kv[1]["messages"], kv[0]))
    return {
        "sources": {
            "paths": [str(p) for p in opts["paths"]], "files": len(files), "parsed": len(reports),
            "skipped": skipped,
            "reports": [{"source": r["source"], "org_name": r["org_name"], "email": r["email"],
                         "report_id": r["report_id"], "begin": r["begin"], "end": r["end"],
                         "begin_date": _day(r["begin"]), "end_date": _day(r["end"]),
                         "domain": r["policy"].get("domain"), "policy": r["policy"],
                         "records": len(r["records"]), "messages": sum(x["count"] for x in r["records"])}
                        for r in reports],
        },
        "filters": {"since": opts["since"], "until": opts["until"], "min_volume": opts["min_volume"],
                    "fail_threshold": opts["fail_threshold"], "expect_policy": opts["expect_policy"],
                    "retiring_selectors": opts["retiring"], "rdns": opts["rdns"],
                    "known": {"given": opts["known_given"], "networks": [str(n) for n in opts["nets"]],
                              "domains": opts["known_domains"],
                              "note": "the domains the reports are about count as known signing domains"}},
        "totals": {
            "reports": agg["reports"], "records": agg["records"], "messages": total,
            "pass": agg["pass"], "fail": agg["fail"],
            "pass_rate": round(agg["pass"] / total, 4) if total else 0.0,
            "by_disposition": {k: agg["dispositions"].get(k, 0) for k in DISPOSITIONS}
                              | {k: v for k, v in agg["dispositions"].items() if k not in DISPOSITIONS},
            "aligned": {k: agg["aligned"].get(k, 0) for k in ("both", "dkim_only", "spf_only", "neither")},
            "raw": {"dkim_verified_any_domain": agg["raw_dkim_pass"], "spf_pass_any_domain": agg["raw_spf_pass"]},
            "domains": sorted(agg["domains"]), "reporters": [org for org, _ in by_org],
            "begin": agg["begin"], "end": agg["end"], "begin_date": _day(agg["begin"]), "end_date": _day(agg["end"]),
        },
        "by_source_ip": [_source_doc(ip, s, total, opts["nets"], opts["known_given"], names) for ip, s in by_ip],
        "by_header_from": [{"domain": d, "apex": org_domain(d) if not d.startswith("(") else None,
                            "is_subdomain": not d.startswith("(") and org_domain(d) != d,
                            "count": f["count"], "pass": f["pass"], "fail": f["fail"],
                            "dkim_aligned_pass": f["dkim_pass"], "spf_aligned_pass": f["spf_pass"],
                            "share": round(f["count"] / (total or 1), 4),
                            "dispositions": dict(f["dispositions"]), "source_ips": len(f["sources"])}
                           for d, f in by_from],
        "by_reporter": [{"org_name": org, "reports": r["reports"], "records": r["records"],
                         "messages": r["messages"], "pass": r["pass"], "fail": r["fail"],
                         "emails": sorted(r["emails"]), "policies_seen": dict(r["policies"]),
                         "begin_date": _day(r["begin"]), "end_date": _day(r["end"])} for org, r in by_org],
        "selectors": derived["selectors"],
        "unknown_senders": derived["unknown_senders"],
        "failing_streams": derived["failing_streams"],
        "spf_only_senders": derived["spf_only_senders"],
        "retiring_selectors": derived["retiring_selectors"],
        "policy_check": derived["policy_check"],
        "warnings": list(warnings),
        "heuristic": {"labels": list(LIKELY_LABELS),
                      "note": "likely labels are a heuristic, not a verdict; counts are receiver-reported "
                              "and include forwarded copies (no Message-ID, cannot be deduplicated)"},
        "findings": findings,
        "summary": {"findings": len(findings),
                    "actionable": sum(1 for f in findings if f["severity"] in ("major", "blocking")),
                    "worst": worst_severity(findings), "exit_code": code},
        "exit_code": code,
    }


# --------------------------------------------------------------- report

def _pct(part, whole):
    return f"{(part / whole * 100) if whole else 0:.1f}%"


def _auth_line(s):
    dk = ", ".join(f"d={d or '?'} s={sel or '?'} {r or '?'} x{n}" for (d, sel, r), n in s["dkim"].most_common(3))
    sp = ", ".join(f"{d or '?'} {r or '?'} x{n}" for (d, _, r), n in s["spf"].most_common(3))
    return f"dkim: {dk or 'none'} | spf: {sp or 'none'}"


def _more(items, n):
    return f"  ... {len(items) - n} more, use --json for the full list" if len(items) > n else None


def print_report(doc, agg, top=20):
    t, src = doc["totals"], doc["sources"]
    flt = doc["filters"]
    print(f"files read                  : {src['files']}   ({src['parsed']} reports parsed, {src['skipped']} skipped)")
    if flt["since"] or flt["until"]:
        print(f"window                      : {flt['since'] or 'start'} .. {flt['until'] or 'end'} (report date ranges overlapping this, UTC)")
    orgs = t["reporters"]
    print(f"reporting orgs              : {len(orgs)}" + (f": {', '.join(orgs[:5])}" + (f" +{len(orgs) - 5} more" if len(orgs) > 5 else "") if orgs else ""))
    print(f"domains reported on         : {', '.join(t['domains']) or '(none)'}")
    print(f"date range                  : {t['begin_date'] or '?'} .. {t['end_date'] or '?'} (UTC)")
    print(f"messages                    : {t['messages']}")
    print(f"  DMARC pass                : {t['pass']}   ({_pct(t['pass'], t['messages'])})")
    print(f"  DMARC fail                : {t['fail']}")
    print(f"  by disposition            : " + ", ".join(f"{k} {v}" for k, v in t["by_disposition"].items()))
    al = t["aligned"]
    print(f"  aligned via               : DKIM+SPF {al['both']}, DKIM only {al['dkim_only']}, "
          f"SPF only {al['spf_only']}, neither {al['neither']}   <-- SPF-only breaks on forwarding")
    pc = doc["policy_check"]
    for s in pc["seen"]:
        print(f"policy published            : {s['domain'] or '?'} p={s['p'] or '(missing)'} sp={s['sp'] or '-'} "
              f"pct={s['pct'] or '-'} adkim={s['adkim'] or 'r'} aspf={s['aspf'] or 'r'}   ({s['reports']} report(s))")
    print()
    print("counts are receiver-reported and include forwarded copies; without a Message-ID they cannot be deduplicated.")

    ips = doc["by_source_ip"]
    if ips:
        print(f"\ntop source IPs ({min(top, len(ips))} of {len(ips)}; share of all messages):")
        print(f"  {'count':>7} {'share':>6} {'pass':>7} {'fail':>7}  {'source_ip':<39} header_from")
        for s in ips[:top]:
            tag = "" if s["known"] is None else ("  known" if s["known"] else "  UNKNOWN")
            hf = ", ".join(h["domain"] for h in s["header_from"][:2]) + (f" +{len(s['header_from']) - 2}" if len(s["header_from"]) > 2 else "")
            print(f"  {s['count']:>7} {s['share'] * 100:>5.1f}% {s['pass']:>7} {s['fail']:>7}  {s['source_ip']:<39} {hf}{tag}"
                  + (f"  rdns={s['rdns']}" if s["rdns"] else ""))
            print(f"           {_auth_line(agg['sources'][s['source_ip']])}")
        line = _more(ips, top)
        if line:
            print(line)

    froms = doc["by_header_from"]
    if froms:
        print(f"\nheader_from domains ({len(froms)}):")
        print(f"  {'count':>7} {'pass':>7} {'fail':>7} {'IPs':>5}  domain")
        for f in froms[:top]:
            sub = f"   (subdomain of {f['apex']})" if f["is_subdomain"] else ""
            print(f"  {f['count']:>7} {f['pass']:>7} {f['fail']:>7} {f['source_ips']:>5}  {f['domain']}{sub}")
        line = _more(froms, top)
        if line:
            print(line)

    orgs = doc["by_reporter"]
    if orgs:
        print(f"\nreporting orgs ({len(orgs)}):")
        print(f"  {'reports':>7} {'msgs':>7} {'pass':>7} {'fail':>7}  org  (window, policies seen)")
        for r in orgs[:top]:
            pols = ", ".join(f"p={p} x{n}" for p, n in r["policies_seen"].items())
            print(f"  {r['reports']:>7} {r['messages']:>7} {r['pass']:>7} {r['fail']:>7}  {r['org_name']}  "
                  f"({r['begin_date'] or '?'} .. {r['end_date'] or '?'}; {pols})")

    sels = doc["selectors"]
    print(f"\nDKIM selectors in use ({len(sels)}; messages carrying the signature, verified = result pass):")
    if not sels:
        print("  none: no DKIM auth results in these reports")
    for k in sels[:max(top, 10)]:
        ipl = ", ".join(k["source_ips"][:3]) + (f" +{len(k['source_ips']) - 3}" if len(k["source_ips"]) > 3 else "")
        print(f"  {k['messages']:>7} msgs {k['pass']:>7} verified  d={k['domain']} s={k['selector']}  "
              f"last seen {k['last_seen'] or '?'}  from {ipl}")
    line = _more(sels, max(top, 10))
    if line:
        print(line)

    for r in doc["retiring_selectors"]:
        if r["messages"]:
            print(f"\nretiring selector {r['retiring']}: STILL SIGNING {r['messages']} msgs for d={r['domain']} "
                  f"(last seen {r['last_seen'] or '?'}, from {', '.join(r['source_ips'][:5])})   <-- do not delete the key")
        else:
            print(f"\nretiring selector {r['retiring']}: not seen in {t['reports']} report(s) "
                  f"({t['begin_date'] or '?'} .. {t['end_date'] or '?'}); absence in this window is not proof")

    unk = doc["unknown_senders"]
    kn = flt["known"]
    if kn["given"]:
        what = ", ".join(kn["networks"] + kn["domains"])
        print(f"\nunknown senders ({len(unk)}; not in --known {what}; reported domains count as known signers):")
    else:
        print(f"\nunknown senders ({len(unk)}; no --known list, so every source is unknown - pass --known to narrow):")
    print(f"  {'count':>7} {'pass':>7} {'fail':>7}  {'kind':<12} value" if unk else "  none")
    for u in unk[:top]:
        detail = ", ".join(u.get("header_from") or u.get("source_ips") or [])
        extra = (f"; dkim {', '.join(u['dkim_domains'])}" if u.get("dkim_domains") else "") + \
                (f"; selectors {', '.join(u['selectors'])}" if u.get("selectors") else "")
        print(f"  {u['count']:>7} {u['pass']:>7} {u['fail']:>7}  {u['kind']:<12} {u['value']:<39} {detail}{extra}")
    line = _more(unk, top)
    if line:
        print(line)

    streams = doc["failing_streams"]
    print(f"\nfailing streams ({len(streams)}; >= {flt['min_volume']} msgs and pass rate < {flt['fail_threshold']:.2f}; "
          "likely = heuristic, not a verdict):")
    if not streams:
        print("  none")
    for f in streams[:top]:
        disp = ", ".join(f"{d} {n}" for d, n in f["dispositions"].items())
        names = doc["by_source_ip"]
        rd = next((s["rdns"] for s in names if s["source_ip"] == f["source_ip"] and s["rdns"]), None)
        print(f"  {f['count']:>7} msgs {f['pass_rate'] * 100:>5.1f}% pass  {f['source_ip']:<39} {f['likely']}"
              + (f"  rdns={rd}" if rd else ""))
        print(f"           as {', '.join(f['header_from'][:3])}; disposition {disp}")
        for sig in f["likely_signals"]:
            print(f"           - {sig}")
    line = _more(streams, top)
    if line:
        print(line)

    so = doc["spf_only_senders"]
    if so:
        print(f"\nSPF-only aligned senders ({len(so)}; no aligned DKIM pass at all, >= {flt['min_volume']} msgs):")
        for f in so[:top]:
            note = f"  signs unaligned d={', '.join(f['unaligned_dkim_domains'])}" if f["unaligned_dkim_domains"] else ""
            print(f"  {f['spf_only']:>7} msgs  {f['source_ip']:<39} as {', '.join(f['header_from'][:2])}  "
                  f"via spf {', '.join(f['spf_domains'][:2]) or '?'}{note}")

    fl = doc["findings"]
    actionable = sum(1 for f in fl if f["severity"] in ("major", "blocking"))
    print(f"\n{len(fl)} findings, {actionable} major or blocking")
    for f in fl:
        print(f"  [{f['severity']}] {f['id']} {f['title']}" + ("" if f["verified"] else " (heuristic, not verified)"))
        print(f"       fix: {f['action']}")


# ------------------------------------------------------------------ cli

def parse_day(value, end=False):
    """YYYY-MM-DD as a UTC epoch: start of day, or its last second with end=True."""
    try:
        d = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        die(f"not a date (YYYY-MM-DD): {value}")
    return int(d.timestamp()) + (86399 if end else 0)


def in_window(rep, since, until):
    """A report is in the window when its date range overlaps it; an undated report stays."""
    b, e = rep["begin"], rep["end"]
    if b is None and e is None:
        return True
    b = b if b is not None else e
    e = e if e is not None else b
    return (since is None or e >= since) and (until is None or b <= until)


def analyse(paths, known=None, min_volume=20, fail_threshold=0.5, since=None, until=None,
            expect_policy=None, retiring=(), use_rdns=False, top=20):
    """Everything main does short of printing: the --json document. Exit 2 on input errors."""
    files = collect_files(paths)
    if not files:
        die("no report files (.xml, .xml.gz, .gz, .zip) found under: " + ", ".join(str(repo_path(p)) for p in paths))
    warnings = []
    reports, skipped = load_reports(files, warnings)
    if not reports:
        die(f"no aggregate reports could be parsed from {len(files)} file(s); see the warnings above")
    lo = parse_day(since) if since else None
    hi = parse_day(until, end=True) if until else None
    if lo is not None and hi is not None and lo > hi:
        die(f"--since {since} is after --until {until}")
    parsed_total = len(reports)
    reports = [r for r in reports if in_window(r, lo, hi)]

    nets, known_domains = parse_known(known)
    names = [s.strip().lower() for arg in (retiring or []) for s in arg.split(",") if s.strip()]
    agg = aggregate(reports)
    derived = {
        "selectors": selectors_in_use(agg),
        "unknown_senders": unknown_senders(agg, nets, known_domains),
        "failing_streams": failing_streams(agg, min_volume, fail_threshold),
        "spf_only_senders": spf_only_senders(agg, min_volume),
        "retiring_selectors": retiring_selectors(agg, names),
        "policy_check": policy_check(agg, expect_policy),
    }
    opts = {"paths": list(paths), "since": since, "until": until, "min_volume": min_volume,
            "fail_threshold": fail_threshold, "expect_policy": expect_policy, "retiring": names,
            "rdns": use_rdns, "nets": nets, "known_domains": known_domains, "known_given": bool(known),
            "parsed_total": parsed_total}

    ptr = {}
    if use_rdns:  # only the IPs the report shows, so a big set does not turn into minutes of waiting
        shown = [ip for ip, _ in sorted(agg["sources"].items(), key=lambda kv: -kv[1]["count"])[:top]]
        shown += [f["source_ip"] for f in derived["failing_streams"]]
        shown += [u["value"] for u in derived["unknown_senders"] if u["kind"] == "ip"][:top]
        for ip in dict.fromkeys(shown):
            ptr[ip] = rdns(ip)

    findings = build_findings(agg, derived, opts, skipped, warnings)
    doc = build_doc(files, reports, agg, derived, findings, opts, skipped, warnings, ptr)
    return doc, agg


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="report files or directories (recursed); relative to the repo root")
    ap.add_argument("--known", metavar="LIST_OR_FILE",
                    help="known domains and IP prefixes, comma-separated or one per line in a file; "
                         "the domains the reports are about are always treated as known signers")
    ap.add_argument("--min-volume", type=int, default=20, metavar="N",
                    help="messages a source needs before it counts as a stream (default 20)")
    ap.add_argument("--fail-threshold", type=float, default=0.5, metavar="RATE",
                    help="pass rate under which a source is a failing stream (default 0.5)")
    ap.add_argument("--since", metavar="YYYY-MM-DD", help="keep reports whose range ends on or after this day (UTC)")
    ap.add_argument("--until", metavar="YYYY-MM-DD", help="keep reports whose range starts on or before this day (UTC)")
    ap.add_argument("--expect-policy", choices=POLICIES, help="flag reports that saw a different p= than this")
    ap.add_argument("--retiring-selector", action="append", default=[], metavar="NAME",
                    help="DKIM selector you plan to delete; shows whether anything still signs with it (repeatable)")
    ap.add_argument("--rdns", action="store_true", help=f"reverse-DNS the shown IPs ({RDNS_TIMEOUT}s each, off by default)")
    ap.add_argument("--top", type=int, default=20, metavar="N", help="rows per table in the text report (default 20)")
    ap.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    args = ap.parse_args()

    if args.top < 1:
        ap.error("--top must be at least 1")
    if args.min_volume < 1:
        ap.error("--min-volume must be at least 1")
    if not 0 <= args.fail_threshold <= 1:
        ap.error("--fail-threshold must be between 0 and 1")

    doc, agg = analyse(args.paths, args.known, args.min_volume, args.fail_threshold, args.since, args.until,
                       args.expect_policy, args.retiring_selector, args.rdns, args.top)
    code = doc["exit_code"]
    if args.json:
        print(json.dumps(doc, indent=1))
        sys.exit(code)
    print_report(doc, agg, args.top)
    sys.exit(code)


if __name__ == "__main__":
    main()
