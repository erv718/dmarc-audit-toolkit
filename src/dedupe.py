"""Collapse mail-log rows into logical messages, then classify each one.

The problem this solves
-----------------------
A single email often appears as several rows in mail logs. Causes include
relay hops (the message leaves your mail system and comes back), forwarding,
and multi-recipient fan-out. Authentication results differ between legs: the
original leg carries valid SPF and DKIM, while a relayed leg usually does not,
because the relaying host is not in the sender's SPF record and the message may
have been altered in transit.

Counting rows therefore overstates failures, sometimes dramatically. A sender
whose mail is arriving perfectly can look badly broken.

The rule used here
------------------
Group by Message-ID plus recipient. A logical message is a GENUINE FAILURE only
when no copy of it passed:

    anyfail > 0 AND anypass == 0

If any copy passed, the recipient received an authenticated message and the
failing rows are echoes of it.

Delivery is a separate question from authentication. With --auth-column the
report also lists messages that failed authentication but were DELIVERED (a
local override let them through) and messages that passed but were BLOCKED or
QUARANTINED (something other than DMARC caught them). When the export records
the local overrides (the Org level / User level policy and action columns
queries/raw_maillog.kql writes), each delivered failure names the one that let
it in, delivered_by, from its delivered failing leg: "org: <policy>
(<action>)", else "user: <policy> (<action>)". Without those columns nothing
changes.

Every genuine failure gets a "likely" label from the heuristic table below:
likely_spoof, likely_misconfigured_sender or unknown. It points the
investigation; it is not a verdict.

The census lists every envelope (MAIL FROM) domain and every sender seen,
with its genuine failures, worst first: the sender inventory to work through
before enforcement. The report prints the failing top of each list; --json
carries the full lists under "census".

When the export also carries SPF and DKIM verdict columns (the ones
queries/raw_maillog.kql writes), every passing message is bucketed the way
queries/dkim_alignment.kql does - dkim_aligned, spf_only, spf_and_dkim - and
the senders that pass on SPF alone are listed. They break on forwarding, so
they are the DKIM-before-reject work (docs/methodology.md step 8). A
Direction column (the same query writes it) marks the messages whose every
leg stayed inside the tenant.

Usage
-----
    python dedupe.py export.csv --sender-domain example.com --auth-column DMARC
    python dedupe.py export.csv --auth-column DMARC --json --out verdicts.json

Relative paths resolve from the repo root, not from the current directory.

Expects a CSV export (Microsoft 365 Defender "All email" export naming;
override with the --*-column flags for other tools) with these columns:

    required : Internet message ID, Recipients, Delivery action,
               plus the --auth-column when given and Sender domain when
               --sender-domain is given
    optional : Sender address, Sender domain, Latest delivery location,
               Subject, Sender mail from domain (a warning names any absent one)
    alignment: SPF and DKIM - used only when both are present, for the
               dkim_alignment buckets and the SPF-only sender list
    overrides: Org level action, Org level policy, User level action, User
               level policy - used when present, never warned about

Exit codes: 0 clean, 1 findings at severity major or blocking, 2 usage or
input error.
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from dns_audit import org_domain  # same apex logic as the DNS audit
except ImportError:  # running outside the repo: last two labels
    def org_domain(domain):
        return ".".join(domain.lower().strip(".").split(".")[-2:])
import console

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

ROOT = Path(__file__).resolve().parent.parent

PASS_ACTIONS = {"delivered", "deliveredtodeletedfolder"}
FAIL_ACTIONS = {"blocked", "quarantined", "junked", "replaced"}

REQUIRED_COLS = ("msgid", "recipient", "action")
OPTIONAL_COLS = ("sender", "domain", "location", "subject", "envelope")
# mail sent from inside the tenant (a Direction column, when the log has one): it carries
# no DMARC verdict, and no outside sender can fake it
INTERNAL_DIRECTIONS = ("intra-org", "outbound")
ALIGNMENT_COLS = ("spf", "dkim")
ALIGNMENT_BUCKETS = ("dkim_aligned", "spf_only", "spf_and_dkim")
# The local overrides recorded on a leg (EmailEvents' OrgLevel*/UserLevel* columns, under the names
# queries/raw_maillog.kql writes; a caller's cols may map a key elsewhere). Optional and silent: an
# export without them reads exactly as before, and with them a delivered failure names what let it in.
OVERRIDE_COLS = {"org_action": "Org level action", "org_policy": "Org level policy",
                 "user_action": "User level action", "user_policy": "User level policy"}
# Plain words for the overrides a reader meets most, by what the policy column says; first match
# wins (the domain list before the sender list). Anything else is shown verbatim.
OVERRIDE_WORDS = (
    ("transport_rule", re.compile(r"transport rule|mail flow rule|\betr\b", re.I), "an Exchange transport rule"),
    ("allowed_domains", re.compile(r"allowed (?:sender )?domain", re.I), "the allowed sender domain list"),
    ("allowed_senders", re.compile(r"allowed sender", re.I), "the allowed sender list"),
    ("spoof_allow", re.compile(r"spoof|tenant allow|\btabl\b", re.I), "a spoof allow / Tenant Allow Block List entry"),
    ("safe_senders", re.compile(r"safe (?:sender|domain)", re.I), "a user's safe sender list"),
)

SEVERITY_RANK = {"info": 0, "minor": 1, "major": 2, "blocking": 3}

# ------------------------------------------------ heuristic table (edit freely)
# "Our vendor to fix, or an attacker?" guessed from two weak signals: the
# subject line and the envelope (MAIL FROM) domain. A guess, never a verdict.

# Subject words phishing lures lean on. Whole words, case-insensitive, plural ok.
LURE_WORDS = ("invoice", "payment", "ach", "wire", "voicemail", "docusign", "password",
              "urgent", "overdue", "past due", "remittance", "direct deposit", "payroll")

# Envelope domains of well-known sending platforms (SendGrid, Amazon SES,
# Mailchimp, Salesforce, Mailgun, SparkPost, Postmark, HubSpot, Constant
# Contact). A failure whose envelope sits here is usually a customer account on
# that platform sending without DKIM. Add your own vendors with --vendor-domain.
ESP_DOMAINS = ("sendgrid.net", "amazonses.com", "mcsv.net", "mcdlv.net", "rsgsv.net",
               "mandrillapp.com", "exacttarget.com", "bnc.salesforce.com", "mailgun.org",
               "sparkpostmail.com", "mtasv.net", "hubspotemail.net", "constantcontact.com")

# A sender whose subject template (digits collapsed) recurs this often counts as
# "repeated stable subjects", the mark of an automated system rather than a lure.
STABLE_REPEATS = 2

LIKELY_LABELS = ("likely_spoof", "likely_misconfigured_sender", "unknown")

# the report prints this many census entries per list; --json carries them all
CENSUS_TOP = 10


# ------------------------------------------------------------------ input

def read_header(path):
    """Header row of the CSV, [] when the file is empty."""
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return next(csv.reader(fh), [])


def check_columns(header, cols, auth_column=None, sender_domain=None):
    """(missing_required, missing_optional) column names for this run.

    The domain column joins the required set when --sender-domain is given,
    because the filter would otherwise drop every row and report zero."""
    present = set(header)
    required = [cols[k] for k in REQUIRED_COLS]
    optional = [cols[k] for k in OPTIONAL_COLS if cols.get(k)]
    if auth_column:
        required.append(auth_column)
    if sender_domain and cols.get("domain"):
        required.append(cols["domain"])
        optional.remove(cols["domain"])
    return ([c for c in required if c not in present],
            [c for c in optional if c not in present])


def load(path, cols):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            yield row


def field(row, cols, key):
    """Cell text for a logical column; "" when the column is unmapped or absent."""
    name = cols.get(key)
    return ((row.get(name) if name else "") or "").strip()


def in_scope(row, cols, sender_domain):
    """False when --sender-domain is set and the row's sender domain is outside it."""
    if not sender_domain:
        return True
    dom = field(row, cols, "domain").lower()
    return dom == sender_domain or dom.endswith("." + sender_domain)


def leg_auth(leg, cols, auth_column):
    """(passed, failed) for one row: from the auth column, else the delivery action."""
    if auth_column:
        val = (leg.get(auth_column) or "").lower()
        return "pass" in val, "fail" in val
    act = field(leg, cols, "action").lower()
    return act in PASS_ACTIONS, act in FAIL_ACTIONS


def envelope_domain(value):
    """Domain part of a MAIL FROM address, or the value itself when already a domain."""
    val = (value or "").strip().strip("<>").lower()
    return val.rpartition("@")[2] if "@" in val else val


def subject_template(subject):
    """Subject with digits collapsed, so that two purchase-order numbers match."""
    return re.sub(r"\d+", "0", re.sub(r"\s+", " ", (subject or "").strip().lower()))


def _reached(action, location):
    """One leg reached a mailbox: delivered, to the inbox, junk or deleted items."""
    loc = (location or "").lower()
    return action in PASS_ACTIONS and ("inbox" in loc or "junk" in loc or "deleted" in loc)


def override_columns(cols, row):
    """{key: column name} for the OVERRIDE_COLS this export carries (row: any row, for its header)."""
    names = {k: (cols.get(k) or name) for k, name in OVERRIDE_COLS.items()}
    return {k: n for k, n in names.items() if n in row}


def leg_override(leg, ovr):
    """What a leg's own record says let it in: 'org: <policy> (<action>)' when
    its org-level policy is set, else 'user: <policy> (<action>)' when its
    user-level policy is (no parentheses for an empty action), else None."""
    for side in ("org", "user"):
        policy = field(leg, ovr, side + "_policy")
        if policy:
            action = field(leg, ovr, side + "_action")
            return "%s: %s%s" % (side, policy, " (%s)" % action if action else "")
    return None


def delivered_by(legs, auth, actions, locations, ovr):
    """What let a delivered failure in, taken from its delivered failing leg:
    the legs that reached a mailbox, the ones with a failing verdict first,
    and the first of them whose record names an override (leg_override).
    None when none does."""
    reached = [i for i, (a, l) in enumerate(zip(actions, locations)) if _reached(a, l)]
    for i in [i for i in reached if auth[i][1]] + [i for i in reached if not auth[i][1]]:
        reason = leg_override(legs[i], ovr)
        if reason:
            return reason
    return None


def override_kind(reason):
    """The common override a delivered_by reason names (an OVERRIDE_WORDS kind), or None."""
    text = str(reason or "")
    return next((kind for kind, rx, _ in OVERRIDE_WORDS if rx.search(text)), None)


def override_words(reason):
    """A delivered_by reason as a reader sees it: the common overrides in
    plain words, anything else verbatim."""
    text = str(reason or "").strip()
    return next((words for _, rx, words in OVERRIDE_WORDS if rx.search(text)), text)


def _whole(value):
    """A count from a document that may have been edited by hand: a whole number >= 0, else 0."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def delivered_by_text(by, total=None, cap=4):
    """'an Exchange transport rule x2, a user's safe sender list x1' from
    {delivered_by reason: messages}: plain words (override_words; reasons
    that read the same are added up), the most first, '+N more' past cap.
    With total (the delivered-despite-fail count they belong to), the
    messages no reason covers follow: '; no override recorded for 1'. ''
    when no reason is known: the reader keeps its words from before."""
    merged = Counter()
    for reason, n in (by.items() if isinstance(by, dict) else ()):
        if str(reason or "").strip() and _whole(n):
            merged[override_words(reason)] += _whole(n)
    if not merged:
        return ""
    parts = ["%s x%d" % kv for kv in sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))]
    if len(parts) > cap:
        parts = parts[:cap] + ["+%d more" % (len(parts) - cap)]
    rest = _whole(total) - sum(merged.values()) if total is not None else 0
    return ", ".join(parts) + ("; no override recorded for %d" % rest if rest > 0 else "")


def count_rows(rows, cols, sender_domain=None, auth_column=None):
    """Row-level tallies before any grouping. This is what 'counting rows' sees."""
    sender_domain = (sender_domain or "").strip().lower() or None
    c = {"raw_rows": 0, "rows_in_scope": 0, "rows_without_msgid": 0,
         "rows_with_auth_verdict": 0, "raw_failing_rows": 0}
    for row in rows:
        c["raw_rows"] += 1
        if not in_scope(row, cols, sender_domain):
            continue
        c["rows_in_scope"] += 1
        if not field(row, cols, "msgid"):
            c["rows_without_msgid"] += 1
        passed, failed = leg_auth(row, cols, auth_column)
        c["rows_with_auth_verdict"] += passed or failed
        c["raw_failing_rows"] += failed
    return c


# --------------------------------------------------------------- classify

def _aligned(envelope, from_domain):
    """Relaxed SPF alignment: the envelope domain shares the From domain's apex."""
    return bool(envelope) and bool(from_domain) and org_domain(envelope) == org_domain(from_domain)


def message_alignment(legs, cols, auth, from_domain):
    """queries/dkim_alignment.kql's bucket for one logical message, or
    not_passing. dkim_aligned: a leg passed DMARC without an aligned SPF pass
    and with a DKIM pass, so DKIM carried it. spf_only: passed, and no leg had a DKIM pass at all -
    breaks on forwarding. spf_and_dkim: both passed; DKIM alignment likely but
    unproven from this table (confirm d= in one live header, rule 9)."""
    if not any(p for p, _ in auth):
        return "not_passing"
    carried = dkim_any = False
    env_known = bool(cols.get("envelope")) and cols["envelope"] in legs[0]  # without it, alignment of an SPF pass is unknown
    for leg, (passed, _) in zip(legs, auth):
        spf_ok = field(leg, cols, "spf").lower() == "pass" and (
            not env_known or _aligned(envelope_domain(field(leg, cols, "envelope")), from_domain))
        if passed and not spf_ok and field(leg, cols, "dkim").lower() == "pass":
            carried = True  # DKIM carried it only when a DKIM pass is on that leg
        if field(leg, cols, "dkim").lower() == "pass":
            dkim_any = True
    if carried:
        return "dkim_aligned"
    return "spf_and_dkim" if dkim_any else "spf_only"


def classify(rows, cols, sender_domain=None, auth_column=None, vendor_domains=None):
    """Return per-message verdicts keyed by (message-id, recipient)."""
    sender_domain = (sender_domain or "").strip().lower() or None
    groups = defaultdict(list)
    for row in rows:
        if not in_scope(row, cols, sender_domain):
            continue
        mid = field(row, cols, "msgid")
        rcpt = field(row, cols, "recipient").lower()
        if not mid:
            continue
        groups[(mid, rcpt)].append(row)

    verdicts = {}
    # Message-IDs with a leg from outside: a copy a mailbox rule redirected to another
    # recipient is its own group, with internal legs only, and is still not internal mail
    external = {key[0] for key, legs in groups.items()
                if any(field(leg, cols, "direction").lower() not in INTERNAL_DIRECTIONS for leg in legs)}
    for key, legs in groups.items():
        actions = [field(leg, cols, "action").lower() for leg in legs]
        locations = [field(leg, cols, "location") for leg in legs]

        # authentication verdict, when the export carries one
        auth = [leg_auth(leg, cols, auth_column) for leg in legs]
        anypass = any(p for p, _ in auth)
        anyfail = any(f for _, f in auth)
        internal = key[0] not in external  # every leg of this Message-ID, for every recipient, stayed inside

        reached_mailbox = any(_reached(a, l) for a, l in zip(actions, locations))
        relayed_only = (
            any("on-prem" in l.lower() or "external" in l.lower() for l in locations)
            and not reached_mailbox
        )
        caught = any(a in FAIL_ACTIONS for a in actions)
        sender = field(legs[0], cols, "sender").lower()
        domain = field(legs[0], cols, "domain").lower() or sender.rpartition("@")[2]
        alignment = None
        if auth_column and all(cols.get(k) and cols[k] in legs[0] for k in ALIGNMENT_COLS):
            alignment = message_alignment(legs, cols, auth, domain)

        verdicts[key] = {
            "legs": len(legs),
            "passed": anypass,  # some copy passed authentication
            "internal": internal,  # every leg stayed inside the tenant
            "genuine_failure": anyfail and not anypass,
            "echo_present": anyfail and anypass,
            "reached_mailbox": reached_mailbox,
            "relayed_only": relayed_only,
            # delivery and authentication are separate questions; these two mean
            # something only when the export carries an authentication verdict
            "delivered_despite_fail": bool(auth_column) and anyfail and not anypass and reached_mailbox,
            "blocked_despite_pass": bool(auth_column) and anypass and caught and not reached_mailbox,
            "sender": sender,
            "domain": domain,
            "envelope_domain": envelope_domain(field(legs[0], cols, "envelope")),
            "subject": field(legs[0], cols, "subject"),
            "actions": actions,
            "locations": locations,
            "alignment": alignment,
            "likely": None,
            "likely_signals": [],
        }
        ovr = override_columns(cols, legs[0])
        if ovr:  # the export records the local overrides: a delivered failure says which one let it in
            verdicts[key]["delivered_by"] = (delivered_by(legs, auth, actions, locations, ovr)
                                             if verdicts[key]["delivered_despite_fail"] else None)
    label_failures(verdicts, vendor_domains)
    return verdicts


# -------------------------------------------------------------- heuristic

def _under(domain, roots):
    return any(domain == r or domain.endswith("." + r) for r in roots if r)


def likely_cause(v, repeats, known_domains=ESP_DOMAINS):
    """Heuristic (label, signals) for one genuine failure. A guess, not a verdict.

    repeats: how often this sender's subject template recurs among the genuine
    failures. known_domains: envelope domains treated as recognised platforms."""
    subject, env, dom = v["subject"], v["envelope_domain"], v["domain"]
    lure = [w for w in LURE_WORDS if re.search(r"\b" + re.escape(w) + r"s?\b", subject, re.I)]
    own = bool(env and dom) and (_under(env, [dom]) or _under(dom, [env]))
    platform = bool(env) and _under(env, known_domains)
    signals = []
    if lure:
        signals.append("lure words in subject: " + ", ".join(lure))
    if env and not own and not platform:
        signals.append("envelope domain %s is neither the sender domain nor a known platform" % env)
    if signals:
        return "likely_spoof", signals
    if not env:
        signals.append("no envelope domain in the export")
    elif own:
        signals.append("envelope domain is the sender domain itself")
    else:
        signals.append("envelope domain %s is a known sending platform" % env)
    signals.append("subject template seen %dx from this sender" % repeats)
    if env and repeats >= STABLE_REPEATS:
        return "likely_misconfigured_sender", signals
    return "unknown", signals


def label_failures(verdicts, vendor_domains=None):
    """Attach 'likely' and 'likely_signals' to every genuine failure, in place."""
    known = tuple(ESP_DOMAINS) + tuple((d or "").strip().lower() for d in (vendor_domains or []))
    failing = [v for v in verdicts.values() if v["genuine_failure"]]
    seen = Counter((v["sender"], subject_template(v["subject"])) for v in failing)
    for v in failing:
        v["likely"], v["likely_signals"] = likely_cause(
            v, seen[(v["sender"], subject_template(v["subject"]))], known)


# ---------------------------------------------------------------- summary

def alignment_summary(vs):
    """Counts of the alignment buckets over passing messages; available says
    whether the export carried SPF and DKIM columns at all."""
    seen = [v.get("alignment") for v in vs if v.get("alignment")]
    by = Counter(a for a in seen if a in ALIGNMENT_BUCKETS)
    out = {"available": bool(seen), "passing": sum(by.values())}
    out.update({k: by.get(k, 0) for k in ALIGNMENT_BUCKETS})
    return out


def spf_only_senders(verdicts):
    """Passing senders that had no DKIM pass on any leg, by From address and
    envelope domain (the dkim_alignment.kql grain): fine at quarantine, bounced
    at reject once a forwarder touches the mail."""
    by = {}
    for v in verdicts.values():
        a = v.get("alignment")
        if a not in ALIGNMENT_BUCKETS:
            continue
        key = (v["sender"], v["envelope_domain"])
        s = by.setdefault(key, {"sender": v["sender"], "domain": v["domain"], "envelope_domain": v["envelope_domain"],
                                "passing": 0, "dkim_aligned": 0, "spf_only": 0, "spf_and_dkim": 0})
        s["passing"] += 1
        s[a] += 1
    out = [dict(s, spf_only_pct=round(100.0 * s["spf_only"] / s["passing"], 1)) for s in by.values() if s["spf_only"]]
    return sorted(out, key=lambda s: (-s["spf_only"], s["sender"]))


def summarize(verdicts):
    """Message-level counters over the verdicts. delivered_despite_fail_by
    ({delivered_by reason: messages}, the most first) is there only when at
    least one delivered failure names the override that let it in."""
    vs = list(verdicts.values())
    by_likely = Counter(v["likely"] for v in vs if v["genuine_failure"])
    by_override = Counter(v["delivered_by"] for v in vs if v["delivered_despite_fail"] and v.get("delivered_by"))
    out = {
        "logical_messages": len(vs),
        "multi_leg": sum(1 for v in vs if v["legs"] > 1),
        "genuine_failures": sum(1 for v in vs if v["genuine_failure"]),
        "echo_messages": sum(1 for v in vs if v["echo_present"]),
        "relayed_only": sum(1 for v in vs if v["relayed_only"]),
        "delivered_despite_fail": sum(1 for v in vs if v["delivered_despite_fail"]),
    }
    if by_override:
        out["delivered_despite_fail_by"] = dict(sorted(by_override.items(), key=lambda kv: (-kv[1], kv[0])))
    out.update({
        "blocked_despite_pass": sum(1 for v in vs if v["blocked_despite_pass"]),
        "by_likely": {k: by_likely.get(k, 0) for k in LIKELY_LABELS},
        "alignment": alignment_summary(vs),
    })
    return out


def _dominant(counter):
    return counter.most_common(1)[0][0] if counter else None


def census(verdicts):
    """Sender census over the verdicts: every envelope (MAIL FROM) domain and
    every (sender, domain, envelope) stream seen, with its genuine failures
    (and, per stream, how many were delivered despite failing), worst first. Clean entries stay in, so a new sender shows up before it
    fails. Takes the verdict dict from classify() or the --json verdict list.
    {"by_envelope": [...], "by_sender": [...]}

    Formal exceptions: audit.py marks every verdict an [[exceptions]] entry
    covers (v["excepted"]), and each entry says how much of it was excepted
    and what is left, so a reader subtracts exact numbers. Per stream:
    excepted (genuine failures excepted), excepted_delivered (the excepted
    ones delivered despite failing), likely_counts ({label: n} over the
    failures not excepted) and likely_after (their majority label, None when
    none is left). Per envelope: excepted, likely_after, senders_after (the
    senders with a failure left) and sample_sender_after. Every other field
    counts every failure, excepted or not.

    Local overrides: when the verdicts carry delivered_by (the export
    recorded the overrides), each stream says what let its delivered
    failures in, delivered_by ({reason: messages}), over the same messages
    as its delivered_despite_fail."""
    vs = list(verdicts.values()) if isinstance(verdicts, dict) else list(verdicts)
    overrides = any("delivered_by" in v for v in vs)
    envs, senders = {}, {}
    for v in vs:
        env = (v.get("envelope_domain") or "").strip().lower() or "(blank)"
        sender = (v.get("sender") or "").strip().lower() or "?"
        dom = (v.get("domain") or "").strip().lower()
        failing = bool(v.get("genuine_failure"))
        likely = v.get("likely") or "unknown"
        e = envs.setdefault(env, {"messages": 0, "genuine_failures": 0, "excepted": 0, "all": Counter(),
                                  "fail": Counter(), "likely": Counter(), "fail_after": Counter(), "after": Counter()})
        e["messages"] += 1
        e["all"][sender] += 1
        s = senders.setdefault((sender, dom, env), {"messages": 0, "genuine_failures": 0, "likely": Counter(),
                                                    "delivered_despite_fail": 0, "excepted": 0,
                                                    "excepted_delivered": 0, "after": Counter(), "by": Counter(),
                                                    "subject": v.get("subject") or "", "fail_subject": None})
        s["messages"] += 1
        if v.get("delivered_despite_fail"):
            s["delivered_despite_fail"] += 1
            if v.get("delivered_by"):
                s["by"][str(v["delivered_by"])] += 1
        if failing:
            e["genuine_failures"] += 1
            e["fail"][sender] += 1
            e["likely"][likely] += 1
            s["genuine_failures"] += 1
            s["likely"][likely] += 1
            if s["fail_subject"] is None:
                s["fail_subject"] = v.get("subject") or ""
            if v.get("excepted"):
                e["excepted"] += 1
                s["excepted"] += 1
                s["excepted_delivered"] += bool(v.get("delivered_despite_fail"))
            else:
                e["fail_after"][sender] += 1
                e["after"][likely] += 1
                s["after"][likely] += 1
    by_env = [{"envelope_domain": env, "genuine_failures": e["genuine_failures"], "messages": e["messages"],
               "senders": len(e["all"]), "sample_sender": _dominant(e["fail"]) or _dominant(e["all"]),
               "likely": _dominant(e["likely"]),
               "excepted": e["excepted"], "likely_after": _dominant(e["after"]),
               "senders_after": len(e["fail_after"]), "sample_sender_after": _dominant(e["fail_after"])}
              for env, e in envs.items()]
    by_sender = []
    for (sender, dom, env), s in senders.items():
        row = {"sender": sender, "domain": dom, "envelope_domain": env,
               "genuine_failures": s["genuine_failures"], "messages": s["messages"],
               "delivered_despite_fail": s["delivered_despite_fail"]}
        if overrides:
            row["delivered_by"] = dict(sorted(s["by"].items(), key=lambda kv: (-kv[1], kv[0])))
        row.update({"likely": _dominant(s["likely"]),
                    "sample_subject": s["fail_subject"] if s["fail_subject"] is not None else s["subject"],
                    "excepted": s["excepted"], "excepted_delivered": s["excepted_delivered"],
                    "likely_counts": dict(sorted(s["after"].items())), "likely_after": _dominant(s["after"])})
        by_sender.append(row)
    by_env.sort(key=lambda r: (-r["genuine_failures"], -r["messages"], r["envelope_domain"]))
    by_sender.sort(key=lambda r: (-r["genuine_failures"], -r["messages"], r["sender"], r["envelope_domain"]))
    return {"by_envelope": by_env, "by_sender": by_sender}


def _sample(items, n=5):
    return "; ".join("%s -> %s (%s)" % (v["sender"] or "?", k[1] or "?", v["subject"] or "no subject")
                     for k, v in items[:n]) + (" ..." if len(items) > n else "")


def build_findings(c, verdicts, auth_column=None, missing_optional=(), sender_domain=None):
    """Standard finding objects (area mailflow) from the counters."""
    findings = []

    def add(fid, severity, title, evidence, action, verified=True):
        findings.append({"id": fid, "severity": severity, "area": "mailflow", "title": title,
                         "evidence": evidence, "action": action, "verified": verified})

    basis = ("auth column %s" % auth_column) if auth_column else "delivery action only (no auth column)"
    if c["raw_rows"] and not c["rows_in_scope"]:
        add("MAILFLOW-009", "minor",
            "no rows matched --sender-domain %s" % sender_domain,
            "%d rows read, 0 in scope" % c["raw_rows"],
            "check the domain for a typo; the zero counts are not evidence of health")
    genuine = [(k, v) for k, v in verdicts.items() if v["genuine_failure"]]
    if genuine:
        senders = Counter(v["sender"] for _, v in genuine)
        add("MAILFLOW-001", "major",
            "%d logical messages failed with no passing copy, from %d senders" % (len(genuine), len(senders)),
            "basis: %s; raw rows with a failing verdict: %d; top senders: %s"
            % (basis, c["raw_failing_rows"], "; ".join("%s x%d" % s for s in senders.most_common(5))),
            "work the senders: DKIM-sign the ones that are yours, confirm the rest are spoofs; "
            "never report the raw row count")
    if c["delivered_despite_fail"]:
        items = [(k, v) for k, v in verdicts.items() if v["delivered_despite_fail"]]
        by = delivered_by_text(c.get("delivered_despite_fail_by"), len(items))  # '' when no leg named one
        add("MAILFLOW-002", "major",
            "%d messages failed authentication but reached a mailbox" % len(items),
            ("let in by %s; " % by if by else "") + _sample(items),
            "find the override (transport rule, allow list, safe sender) and make it conditional on "
            "authentication; external receivers do not have this override")
    if c["blocked_despite_pass"]:
        items = [(k, v) for k, v in verdicts.items() if v["blocked_despite_pass"]]
        add("MAILFLOW-003", "minor",
            "%d messages passed authentication but were blocked or quarantined" % len(items),
            _sample(items),
            "read the quarantine reason (bulk, malware, custom rule); this is not a DMARC problem")
    if genuine:
        split = c["by_likely"]
        per_sender = Counter((v["sender"], v["likely"]) for _, v in genuine)
        add("MAILFLOW-004", "info",
            "heuristic split of the failures: %s" % ", ".join("%d %s" % (split[l], l) for l in LIKELY_LABELS),
            "; ".join("%s %s x%d" % (s, l, n) for (s, l), n in per_sender.most_common(5)),
            "verify from live headers and the sender inventory before acting; "
            "--vendor-domain teaches the heuristic your vendors' envelope domains",
            verified=False)
    spf_only = spf_only_senders(verdicts)
    if spf_only:
        msgs = sum(s["spf_only"] for s in spf_only)
        add("MAILFLOW-010", "minor",
            "%d sender(s) pass DMARC on SPF alone in the mail log (%d msgs): breaks on forwarding, rejected at p=reject"
            % (len(spf_only), msgs),
            "; ".join("%s (envelope %s) x%d" % (s["sender"] or "?", s["envelope_domain"] or "?", s["spf_only"])
                      for s in spf_only[:5]) + (" ..." if len(spf_only) > 5 else ""),
            "set up aligned DKIM at each of these platforms before ratcheting to p=reject, and confirm "
            "it with one live header (src/headers.py); SPF alone is fine at quarantine only")
    if c["rows_without_msgid"]:
        add("MAILFLOW-005", "minor",
            "%d rows have no Message-ID and were left out of the dedupe" % c["rows_without_msgid"],
            "%d of %d in-scope rows" % (c["rows_without_msgid"], c["rows_in_scope"]),
            "check the export; rows without a Message-ID cannot be deduplicated and may hide failures")
    if not auth_column:
        add("MAILFLOW-006", "info",
            "no authentication column: 'failure' here means never delivered, not failed DMARC",
            basis,
            "re-export with an authentication verdict column and pass --auth-column")
    elif c["rows_in_scope"] and not c["rows_with_auth_verdict"]:
        add("MAILFLOW-007", "minor",
            "auth column %s holds no pass or fail value in any in-scope row" % auth_column,
            "%d rows in scope, 0 with a verdict" % c["rows_in_scope"],
            "the zero counts above are not evidence of health; check --auth-column names the verdict column")
    if missing_optional:
        add("MAILFLOW-008", "info",
            "optional columns absent: " + ", ".join(missing_optional),
            "sender, subject, location and envelope detail degrade without them",
            "map them with the --*-column flags if the export names them differently")
    return findings


def worst_severity(findings):
    return max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)


def exit_code(findings):
    return 1 if any(f["severity"] in ("major", "blocking") for f in findings) else 0


def build_doc(source, counts, verdicts, findings, sender_domain=None, auth_column=None, vendor_domains=None):
    """The --json document: counters, findings, every verdict and the heuristic in force."""
    code = exit_code(findings)
    return {
        "source": str(source),
        "sender_domain": sender_domain,
        "auth_column": auth_column,
        "counters": counts,
        "findings": findings,
        "verdicts": [dict(v, msgid=k[0], recipient=k[1]) for k, v in verdicts.items()],
        "census": census(verdicts),
        "alignment": counts.get("alignment") or alignment_summary(list(verdicts.values())),
        "spf_only_senders": spf_only_senders(verdicts),
        "heuristic": {"lure_words": list(LURE_WORDS), "esp_domains": list(ESP_DOMAINS),
                      "vendor_domains": list(vendor_domains or []), "stable_repeats": STABLE_REPEATS,
                      "note": "likely labels are a heuristic, not a verdict"},
        "summary": {"findings": len(findings),
                    "actionable": sum(1 for f in findings if f["severity"] in ("major", "blocking")),
                    "worst": worst_severity(findings), "exit_code": code},
        "exit_code": code,
    }


# ----------------------------------------------------------------- report

def _more(pairs):
    return "" if len(pairs) <= 1 else " (+%d more)" % (len(pairs) - 1)


def _fmt_msg(key, v):
    legs = "; ".join("%s/%s" % (a or "?", l or "?") for a, l in zip(v["actions"], v["locations"]))
    return "%s -> %s  \"%s\"  %s  envelope=%s%s%s" % (
        v["sender"] or "(no sender)", key[1] or "(no recipient)", v["subject"] or "(no subject)",
        legs, v["envelope_domain"] or "(none)", ("  " + v["likely"]) if v["likely"] else "",
        ("  let in by " + override_words(v["delivered_by"])) if v.get("delivered_by") else "")


def _list(title, why, items, top):
    if not items:
        return
    print("\n%s (%d; %s):" % (title, len(items), why))
    for key, v in items[:top]:
        print("  " + _fmt_msg(key, v))
    if len(items) > top:
        print("  ... %d more, use --json for the full list" % (len(items) - top))


def _print_census(title, entries, name, top, detail):
    """One census list: failing entries only, worst first, top N, a detail line
    each. The full list, clean entries included, is in --json (census)."""
    failing = [e for e in entries if e["genuine_failures"]]
    if not failing:
        return
    print("\n%s (%d failing of %d seen; likely = heuristic):" % (title, len(failing), len(entries)))
    for e in failing[:top]:
        print(f"  {e['genuine_failures']:>6}  {e[name]:<40} {e['likely'] or 'unknown'}")
        print("          " + detail(e))
    if len(failing) > top:
        print("  ... %d more, use --json for the full list" % (len(failing) - top))


def print_report(c, verdicts, findings, auth_column=None, top=20):
    paint = console.painter()
    scope = ""
    if c["rows_in_scope"] != c["raw_rows"]:
        scope = "   (%d in scope after --sender-domain)" % c["rows_in_scope"]
    print(f"rows read                   : {c['raw_rows']}{scope}")
    if c["rows_without_msgid"]:
        print(f"  without a Message-ID      : {c['rows_without_msgid']}"
              + paint.dim("   <-- cannot be deduplicated, left out below"))
    print(f"logical messages            : {c['logical_messages']}")
    print(f"  with more than one leg    : {c['multi_leg']}")
    print("  GENUINE failures          : " + paint.bold(str(c["genuine_failures"]))
          + paint.dim("   <-- the real number"))
    print(f"  messages with an echo leg : {c['echo_messages']}"
          + paint.dim("   <-- a failing copy of a message that also passed; not failures"))
    print(f"  delivered only via relay  : {c['relayed_only']}")
    if auth_column:
        print()
        print(f"delivery vs authentication (auth column: {auth_column}):")
        print(f"  failed authentication but DELIVERED           : {c['delivered_despite_fail']}"
              + paint.dim("   <-- a local override let these through"))
        by = delivered_by_text(c.get("delivered_despite_fail_by"), c["delivered_despite_fail"])
        if by:
            print(f"    let in by: {by}")
        print(f"  passed authentication but BLOCKED/QUARANTINED : {c['blocked_despite_pass']}"
              + paint.dim("   <-- something other than DMARC caught these"))
    print()
    print(f"raw rows with a failing verdict: {c['raw_failing_rows']}")
    if c["logical_messages"]:
        print(paint.bold(f"counting rows would report {c['raw_failing_rows']} failures; "
                         f"the true count is {c['genuine_failures']}."))
    al = c.get("alignment") or {}
    if al.get("available"):
        print()
        print("alignment of passing mail (dkim_alignment.kql buckets, from the SPF and DKIM columns):")
        print(f"  DKIM carried it (aligned)   : {al['dkim_aligned']}")
        print(f"  SPF and DKIM both passed    : {al['spf_and_dkim']}   <-- DKIM alignment likely; confirm d= in a live header")
        print(f"  SPF only                    : {al['spf_only']}   <-- breaks on forwarding; DKIM before reject")
        so = spf_only_senders(verdicts)
        if so:
            print("\nsenders passing on SPF alone (no DKIM pass on any leg):")
            for s in so[:top]:
                print(f"  {s['spf_only']:>6}  {(s['sender'] or '(no sender)'):<40} envelope {s['envelope_domain'] or '(none)'}"
                      f"  ({s['spf_only_pct']}% of {s['passing']} passing)")

    genuine = {k: v for k, v in verdicts.items() if v["genuine_failure"]}
    if genuine:
        print("\ngenuine failures by likely cause (heuristic, not a verdict):")
        for label in LIKELY_LABELS:
            print(f"  {label:<27} : {c['by_likely'][label]}")
        print("\ntop genuinely failing senders (likely = heuristic):")
        by_sender = defaultdict(list)
        for v in genuine.values():
            by_sender[v["sender"]].append(v)
        for sender, n in Counter(v["sender"] for v in genuine.values()).most_common(top):
            vs = by_sender[sender]
            labels = Counter(v["likely"] for v in vs).most_common()
            label = labels[0][0] if len(labels) == 1 else "mixed: " + ", ".join("%s %d" % l for l in labels)
            envs = Counter(v["envelope_domain"] or "(none)" for v in vs).most_common()
            subs = Counter(v["subject"] or "(no subject)" for v in vs).most_common()
            print(f"  {n:>6}  {(sender or '(no sender)'):<40} {label}")
            print(f"          envelope: {envs[0][0]}{_more(envs)}   subject: {subs[0][0]}{_more(subs)}")
        cs = census(verdicts)
        n = min(top, CENSUS_TOP)
        _print_census("genuine failures by envelope domain", cs["by_envelope"], "envelope_domain", n,
                      lambda e: "%d of %d messages fail   senders: %d, e.g. %s"
                      % (e["genuine_failures"], e["messages"], e["senders"], e["sample_sender"]))
        _print_census("genuine failures by sender", cs["by_sender"], "sender", n,
                      lambda e: "%d of %d messages fail   domain: %s   envelope: %s   subject: %s"
                      % (e["genuine_failures"], e["messages"], e["domain"] or "(none)", e["envelope_domain"],
                         e["sample_subject"] or "(no subject)"))
    if auth_column:
        _list("failed authentication but DELIVERED", "a local override let these through",
              [(k, v) for k, v in verdicts.items() if v["delivered_despite_fail"]], top)
        _list("passed authentication but BLOCKED or QUARANTINED", "something other than DMARC caught these",
              [(k, v) for k, v in verdicts.items() if v["blocked_despite_pass"]], top)

    actionable = sum(1 for f in findings if f["severity"] in ("major", "blocking"))
    print("\n" + paint.banner(f"{len(findings)} findings, {actionable} major or blocking",
                              "warn" if actionable else "ok"))
    for f in findings:
        print("  [" + paint.severity(f["severity"]) + f"] {f['id']} {f['title']}"
              + ("" if f["verified"] else paint.dim(" (heuristic, not verified)")))


# -------------------------------------------------------------------- cli

def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def repo_path(p):
    """Absolute paths as given; relative paths resolve from the repo root, never the cwd."""
    path = Path(p)
    return path if path.is_absolute() else ROOT / path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path", help="mail log export (relative paths resolve from the repo root)")
    ap.add_argument("--sender-domain", help="restrict to this domain and its subdomains")
    ap.add_argument("--auth-column", help="column holding the DMARC verdict, if present")
    ap.add_argument("--msgid-column", default="Internet message ID")
    ap.add_argument("--recipient-column", default="Recipients")
    ap.add_argument("--sender-column", default="Sender address")
    ap.add_argument("--domain-column", default="Sender domain")
    ap.add_argument("--action-column", default="Delivery action")
    ap.add_argument("--location-column", default="Latest delivery location")
    ap.add_argument("--subject-column", default="Subject")
    ap.add_argument("--envelope-column", default="Sender mail from domain",
                    help="column holding the MAIL FROM (envelope) address or domain")
    ap.add_argument("--direction-column", default="Direction",
                    help="column holding the mail direction (Inbound, Intra-org, Outbound); a message "
                         "whose every leg stayed inside the tenant is marked internal")
    ap.add_argument("--spf-column", default="SPF",
                    help="column holding the SPF verdict (with --dkim-column: alignment buckets and SPF-only senders)")
    ap.add_argument("--dkim-column", default="DKIM", help="column holding the DKIM verdict")
    ap.add_argument("--vendor-domain", action="append", default=[], metavar="DOMAIN",
                    help="envelope domain you know belongs to one of your vendors; the heuristic "
                         "treats it like a known platform (repeatable)")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    ap.add_argument("--out", metavar="FILE", help="also write the JSON document to this file")
    args = ap.parse_args()

    cols = {
        "msgid": args.msgid_column,
        "recipient": args.recipient_column,
        "sender": args.sender_column,
        "domain": args.domain_column,
        "action": args.action_column,
        "location": args.location_column,
        "subject": args.subject_column,
        "envelope": args.envelope_column,
        "direction": args.direction_column,
        "spf": args.spf_column,
        "dkim": args.dkim_column,
    }

    csv_path = repo_path(args.csv_path)
    try:
        header = read_header(csv_path)
        rows = list(load(csv_path, cols))
    except OSError as err:
        die("cannot read %s: %s" % (csv_path, err.strerror or err))
    except UnicodeDecodeError:
        die("%s is not UTF-8 (PowerShell may have written UTF-16; re-export or convert it)" % csv_path)
    except csv.Error as err:
        die("cannot parse %s as CSV: %s" % (csv_path, err))

    missing_req, missing_opt = check_columns(header, cols, args.auth_column, args.sender_domain)
    for key in ("direction", "spf", "dkim"):  # named by hand and absent: say so, as for any other column
        if getattr(args, key + "_column") != ap.get_default(key + "_column") and cols[key] not in header:
            missing_opt.append(cols[key])
    if missing_req:
        die("column not found: %s. Available columns: %s"
            % (", ".join(missing_req), ", ".join(header) or "(none)"))
    for name in missing_opt:
        print("warning: column not found: %s (continuing without it)" % name, file=sys.stderr)

    counts = count_rows(rows, cols, args.sender_domain, args.auth_column)
    if counts["raw_rows"] and not counts["rows_in_scope"]:
        seen = Counter(field(r, cols, "domain").lower() or "(blank)" for r in rows).most_common(5)
        print("warning: no rows match --sender-domain %s; domains seen: %s"
              % (args.sender_domain, ", ".join("%s x%d" % d for d in seen)), file=sys.stderr)
    if args.auth_column and counts["rows_in_scope"] and not counts["rows_with_auth_verdict"]:
        print("warning: auth column %s holds no pass or fail value in any in-scope row; "
              "the zero counts below are not evidence of health" % args.auth_column, file=sys.stderr)

    verdicts = classify(rows, cols, args.sender_domain, args.auth_column, args.vendor_domain)
    counts.update(summarize(verdicts))
    findings = build_findings(counts, verdicts, args.auth_column, missing_opt, args.sender_domain)
    code = exit_code(findings)

    out = None
    if args.json or args.out:
        doc = build_doc(csv_path, counts, verdicts, findings, args.sender_domain, args.auth_column,
                        args.vendor_domain)
        if args.out:
            out = repo_path(args.out)
            try:
                with open(out, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh, indent=1)
                    fh.write("\n")
            except OSError as err:
                die("cannot write %s: %s" % (out, err.strerror or err))
        if args.json:
            print(json.dumps(doc, indent=1))
            sys.exit(code)

    print_report(counts, verdicts, findings, args.auth_column, args.top)
    if out:
        print(f"\nJSON written to {out}")
    sys.exit(code)


if __name__ == "__main__":
    main()
