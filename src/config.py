#!/usr/bin/env python3
"""Optional settings file for the one-command run: audit.toml.

Secrets never live here - .env holds the app registration. audit.toml holds
what a scheduled run would otherwise need as command-line flags: the domains
to audit, known senders and vendors, the reporting address for new records,
how many runs to keep, whether the Slack summary is on, and the formal
exceptions the gate honours. Copy audit.example.toml to audit.toml; the copy
is gitignored because it names your domains.

Precedence, everywhere the file is read: a command-line flag beats the file,
the file beats the built-in default.

Exceptions (docs/methodology.md step 5, the AGENTS.md gate check): a failing
sender that is explained and accepted can be excepted so the ratchet is not
held by it forever. Every exception carries a reason, an expiry (until,
YYYY-MM-DD) and a written removal criterion; one without all of them is
reported and NOT applied, and one past its expiry blocks the gate again. The
match is an IP, an IP prefix, a domain (the envelope or DKIM signing domain of
the sender), or a From address. Each kind covers different evidence: an IP
or a prefix covers aggregate-report streams by source IP and never a mail-log
message (the log carries no source IP at the dedupe grain); an address covers
mail-log messages with that From address, forged copies included, and never a
stream; a domain covers mail-log messages whose MAIL FROM is under it - a
forged MAIL FROM too, and every customer of a shared platform, so the gate's
note counts the excepted messages that failed SPF for that envelope when the
export carries the verdict - and aggregate-report streams whose SPF and DKIM
domains, other than the audited ones, are all under some domain exception
(stream_exceptions: a vendor that signs with its own domain and sends through
an ESP needs an exception for each, or one for the source IP).

Reading TOML needs Python 3.11 or newer (tomllib in the standard library).
"""

import datetime
import ipaddress
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10 and older
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "audit.toml"
EXAMPLE_PATH = ROOT / "audit.example.toml"
DOMAIN_RE = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")

# [audit] key -> (collect.py argparse dest, how the value is shaped).
# csv: a list or string becomes the comma list the flag already takes.
COLLECT_KEYS = {
    "domains": ("domains", "list"),
    "file": ("file", "str"),
    "mailflow": ("mailflow", "bool"),
    "days": ("days", "int"),
    "report_days": ("report_days", "int"),
    "known": ("known", "csv"),
    "selectors": ("selectors", "csv"),
    "vendor_domains": ("vendor_domain", "list"),
    "headers": ("headers", "list"),
    "rua": ("rua", "list"),
    "maillog": ("maillog", "str"),
    "auth_column": ("auth_column", "str"),
    "resolver": ("resolver", "str"),
    "rua_address": ("rua_address", "str"),
    "out": ("out", "str"),
    "keep": ("keep", "int"),
    "strict": ("strict", "bool"),
}
NOTIFY_TARGETS = ("slack", "teams")
EXCEPTION_REQUIRED = ("match", "reason", "until", "removal_criterion")


class ConfigError(Exception):
    """The settings file could not be read or is not valid; callers print it and exit 2."""


def load(path=None):
    """The parsed settings, or {} when no file was named and the default one is absent.

    path None means <repo root>/audit.toml if it exists; a path given
    explicitly must exist. Raises ConfigError for an unreadable or invalid
    file, and when the Python running this predates tomllib."""
    explicit = path is not None
    p = Path(path) if explicit else DEFAULT_PATH
    if not p.is_absolute():
        p = ROOT / p
    if not p.exists():
        if explicit:
            raise ConfigError("settings file not found: %s" % p)
        return {}
    if tomllib is None:
        raise ConfigError("%s needs Python 3.11 or newer to read (tomllib); this is Python %s"
                          % (p.name, sys.version.split()[0]))
    try:
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as err:
        raise ConfigError("cannot read %s: %s" % (p, err.strerror or err))
    except tomllib.TOMLDecodeError as err:
        raise ConfigError("%s is not valid TOML: %s" % (p, err))
    data["_path"] = str(p)
    return data


def _as_list(value, key):
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.replace(",", " ").split() if v.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    raise ConfigError("[audit] %s must be a string or a list of strings" % key)


def collect_defaults(cfg):
    """argparse defaults for collect.py from the [audit] table (dest -> value)."""
    table = cfg.get("audit") or {}
    if not isinstance(table, dict):
        raise ConfigError("[audit] must be a table")
    unknown = sorted(k for k in table if k not in COLLECT_KEYS)
    if unknown:
        raise ConfigError("[audit] has keys collect.py does not know: %s (known: %s)"
                          % (", ".join(unknown), ", ".join(COLLECT_KEYS)))
    out = {}
    for key, (dest, kind) in COLLECT_KEYS.items():
        if key not in table:
            continue
        val = table[key]
        if kind == "list":
            out[dest] = _as_list(val, key)
        elif kind == "csv":
            items = _as_list(val, key)
            out[dest] = ",".join(items) if items else None
        elif kind == "bool":
            if not isinstance(val, bool):
                raise ConfigError("[audit] %s must be true or false" % key)
            out[dest] = val
        elif kind == "int":
            if isinstance(val, bool) or not isinstance(val, int):
                raise ConfigError("[audit] %s must be a whole number" % key)
            out[dest] = val
        else:
            out[dest] = str(val)
    return out


def audit_list(cfg, key):
    """One [audit] list key as a list of strings however it was written (a
    list, or a comma or space separated string), shaped as collect_defaults
    shapes it, so every reader of audit.toml agrees."""
    table = cfg.get("audit") or {}
    if not isinstance(table, dict):
        raise ConfigError("[audit] must be a table")
    return _as_list(table.get(key), key)


def split_vendor_domains(values):
    """(domains, warnings) for the vendor domains (--vendor-domain, audit.toml
    vendor_domains). An IP or an IP prefix there never matches anything -
    vendor domains name sending platforms by domain - so it is left out, with
    one warning naming where it belongs (known, for the per-IP check). The
    caller says it on every run, whatever else the run reads."""
    domains, warnings = [], []
    for v in values or ():
        name = str(v).strip().lower().rstrip(".")
        if not name:
            continue
        try:
            ipaddress.ip_network(name, strict=False)
        except ValueError:
            domains.append(v)
            continue
        warnings.append("vendor domain %s is an IP prefix, not a domain: ignored; vendor domains name sending "
                        "platforms for the labels, IP prefixes go in known (audit.toml known, or --known) for "
                        "the per-IP unknown-sender check" % name)
    return domains, warnings


def notify_settings(cfg):
    """{enabled, target} from the [notify] table; enabled defaults to true so a
    webhook in .env keeps working for anyone without a settings file."""
    table = cfg.get("notify") or {}
    if not isinstance(table, dict):
        raise ConfigError("[notify] must be a table")
    enabled = table.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError("[notify] enabled must be true or false")
    target = str(table.get("target", "slack")).strip().lower()
    if target not in NOTIFY_TARGETS:
        raise ConfigError("[notify] target must be one of: " + ", ".join(NOTIFY_TARGETS))
    return {"enabled": enabled, "target": target}


BRIEF_KEYS = ("change_window", "approver")


def brief_settings(cfg):
    """{change_window, approver} from the [brief] table: free text the ask and
    the status band's call end with, quoted as written (' - window: <text>;
    approver: <text>'); None for a key that is not set. Both optional."""
    table = cfg.get("brief") or {}
    if not isinstance(table, dict):
        raise ConfigError("[brief] must be a table")
    unknown = sorted(k for k in table if k not in BRIEF_KEYS)
    if unknown:
        raise ConfigError("[brief] has keys collect.py does not know: %s (known: %s)"
                          % (", ".join(unknown), ", ".join(BRIEF_KEYS)))
    out = {}
    for key in BRIEF_KEYS:
        val = table.get(key)
        if val is not None and not isinstance(val, str):
            raise ConfigError("[brief] %s must be a string" % key)
        out[key] = " ".join(val.split()) or None if isinstance(val, str) else None
    return out


def exception_kind(match):
    """address | ip | prefix | domain, or None when the text is none of them."""
    if "@" in match:
        local, _, dom = match.rpartition("@")
        return "address" if local and DOMAIN_RE.fullmatch(dom) else None
    try:
        ipaddress.ip_network(match, strict=False)
        return "prefix" if "/" in match else "ip"
    except ValueError:
        pass
    return "domain" if DOMAIN_RE.fullmatch(match) else None


def _as_date(value):
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    return datetime.date.fromisoformat(str(value).strip())


def parse_exceptions(raw, today=None):
    """(active, expired, invalid) from the [[exceptions]] entries.

    active and expired hold normalised entries (match, kind, reason, owner,
    until, removal_criterion); invalid pairs what was written with what is
    wrong, so the report can say why an entry was not applied. Normalised
    entries pass through unchanged, so the split can be repeated."""
    today = today or datetime.date.today()
    active, expired, invalid = [], [], []
    for i, e in enumerate(raw or [], 1):
        if not isinstance(e, dict):
            invalid.append({"entry": str(e)[:80], "problem": "not a table"})
            continue
        match = str(e.get("match") or "").strip().lower().rstrip(".")
        missing = [k for k in EXCEPTION_REQUIRED if not str(e.get(k) or "").strip()]
        if missing:
            invalid.append({"entry": match or "exception %d" % i, "problem": "missing " + ", ".join(missing)})
            continue
        try:
            until = _as_date(e["until"])
        except ValueError:
            invalid.append({"entry": match, "problem": "until is not a date (YYYY-MM-DD)"})
            continue
        kind = exception_kind(match)
        if kind is None:
            invalid.append({"entry": match, "problem": "match is not an IP, an IP prefix, a domain or an address"})
            continue
        norm = {"match": match, "kind": kind, "reason": str(e["reason"]).strip(),
                "owner": (str(e.get("owner") or "").strip() or None), "until": until.isoformat(),
                "removal_criterion": str(e["removal_criterion"]).strip()}
        (expired if until < today else active).append(norm)
    return active, expired, invalid


def _domain_under(name, match):
    name = (name or "").lower()
    return bool(name) and (name == match or name.endswith("." + match))


def matches_stream(exc, stream, audited=()):
    """Does an exception cover one rua failing stream? IPs and prefixes match
    the source IP. A domain matches by the SPF (envelope) and DKIM signing
    domains the stream authenticated with - the vendor's identity, never
    header_from - and covers the stream only when every one of those domains
    that is not an audited domain (or under one) is under the match. A relay
    stream carrying the vendor's mail beside other senders' (a shared
    Microsoft relay signing for the vendor, for one of our subdomains and for
    another tenant) is then not the vendor's stream, and the other senders'
    failures stay in view. audited: the audited domains (the gate's names)."""
    if exc["kind"] in ("ip", "prefix"):
        try:
            return ipaddress.ip_address(stream.get("source_ip") or "") in ipaddress.ip_network(exc["match"], strict=False)
        except ValueError:
            return False
    if exc["kind"] == "domain":
        doms = [str(d).lower() for d in list(stream.get("spf_domains") or []) + list(stream.get("dkim_domains") or [])
                if d]
        if not any(_domain_under(d, exc["match"]) for d in doms):
            return False
        own = [a for a in (str(a).strip().lower().rstrip(".") for a in audited or ()) if a]
        return all(_domain_under(d, exc["match"]) or any(_domain_under(d, a) for a in own) for d in doms)
    return False


def _foreign_domains(stream, audited=()):
    """The SPF and DKIM domains a stream authenticated with that are not audited domains (or under one)."""
    doms = [str(d).lower() for d in list(stream.get("spf_domains") or []) + list(stream.get("dkim_domains") or []) if d]
    own = [a for a in (str(a).strip().lower().rstrip(".") for a in audited or ()) if a]
    return [d for d in doms if not any(_domain_under(d, a) for a in own)]


def stream_exceptions(exceptions, stream, audited=()):
    """The active exceptions that together cover one rua failing stream: an
    IP or prefix exception matching its source IP covers it alone; domain
    exceptions cover it together when every domain the stream
    authenticated with, other than the audited ones, is under one of them
    and at least one is (a SaaS signing with its own domain through an ESP
    whose bounce domain differs needs one exception per domain). [] when
    nothing covers it; a relay carrying another tenant's domain beside the
    vendor's stays uncovered, so the other senders' failures stay in view."""
    for e in exceptions or ():
        if e.get("kind") in ("ip", "prefix") and matches_stream(e, stream, audited):
            return [e]
    foreign = _foreign_domains(stream, audited)
    used = [e for e in exceptions or () if e.get("kind") == "domain"
            and any(_domain_under(d, e["match"]) for d in foreign)]
    if used and all(any(_domain_under(d, e["match"]) for e in used) for d in foreign):
        return used
    return []


def stream_uncovered(exceptions, stream, audited=()):
    """The stream's domains no domain exception covers, when some domain
    exception covers part of it: what a second exception (or one for the
    source IP) would have to name. [] when nothing matched at all, or when
    the stream is covered."""
    foreign = _foreign_domains(stream, audited)
    doms = [e["match"] for e in exceptions or () if e.get("kind") == "domain"]
    if not any(_domain_under(d, m) for d in foreign for m in doms):
        return []
    return sorted({d for d in foreign if not any(_domain_under(d, m) for m in doms)})


def matches_verdict(exc, verdict):
    """Does an exception cover one deduplicated mail-log message? An address
    matches the From address exactly, forged copies included; a domain
    matches the envelope (MAIL FROM) domain, the sender's own identity -
    never the From domain, which is the one being spoofed. A spoofer can set
    any MAIL FROM, so a domain match covers forged copies that borrow the
    envelope too, and a shared platform's envelope is carried by all of its
    customers: the gate's note names how many excepted messages failed SPF
    for that envelope when the export says (the verdict's spf_pass), which
    a forged MAIL FROM does and the platform's own mail does not. IPs and
    prefixes never match: the mail log carries no source IP at this grain."""
    if exc["kind"] == "address":
        return (verdict.get("sender") or "").lower() == exc["match"]
    if exc["kind"] == "domain":
        return _domain_under(verdict.get("envelope_domain"), exc["match"])
    return False
