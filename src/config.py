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
the sender), or a From address.

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


def matches_stream(exc, stream):
    """Does an exception cover one rua failing stream? IPs and prefixes match
    the source IP; a domain matches the SPF (envelope) or DKIM signing domains
    the stream authenticated with - the vendor's identity, never header_from."""
    if exc["kind"] in ("ip", "prefix"):
        try:
            return ipaddress.ip_address(stream.get("source_ip") or "") in ipaddress.ip_network(exc["match"], strict=False)
        except ValueError:
            return False
    if exc["kind"] == "domain":
        doms = list(stream.get("spf_domains") or []) + list(stream.get("dkim_domains") or [])
        return any(_domain_under(d, exc["match"]) for d in doms)
    return False


def matches_verdict(exc, verdict):
    """Does an exception cover one deduplicated mail-log message? An address
    matches the From address exactly; a domain matches the envelope domain or
    the From domain. The mail log carries no source IP at this grain."""
    if exc["kind"] == "address":
        return (verdict.get("sender") or "").lower() == exc["match"]
    if exc["kind"] == "domain":
        sender_dom = (verdict.get("sender") or "").rpartition("@")[2]
        return _domain_under(verdict.get("envelope_domain"), exc["match"]) or _domain_under(sender_dom, exc["match"])
    return False
