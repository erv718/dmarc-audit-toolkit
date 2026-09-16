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
QUARANTINED (something other than DMARC caught them).

Every genuine failure gets a "likely" label from the heuristic table below:
likely_spoof, likely_misconfigured_sender or unknown. It points the
investigation; it is not a verdict.

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

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

ROOT = Path(__file__).resolve().parent.parent

PASS_ACTIONS = {"delivered", "deliveredtodeletedfolder"}
FAIL_ACTIONS = {"blocked", "quarantined", "junked", "replaced"}

REQUIRED_COLS = ("msgid", "recipient", "action")
OPTIONAL_COLS = ("sender", "domain", "location", "subject", "envelope")

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
    for key, legs in groups.items():
        actions = [field(leg, cols, "action").lower() for leg in legs]
        locations = [field(leg, cols, "location") for leg in legs]

        # authentication verdict, when the export carries one
        auth = [leg_auth(leg, cols, auth_column) for leg in legs]
        anypass = any(p for p, _ in auth)
        anyfail = any(f for _, f in auth)

        reached_mailbox = any(
            a in PASS_ACTIONS and ("inbox" in l.lower() or "junk" in l.lower() or "deleted" in l.lower())
            for a, l in zip(actions, locations)
        )
        relayed_only = (
            any("on-prem" in l.lower() or "external" in l.lower() for l in locations)
            and not reached_mailbox
        )
        caught = any(a in FAIL_ACTIONS for a in actions)
        sender = field(legs[0], cols, "sender").lower()
        domain = field(legs[0], cols, "domain").lower() or sender.rpartition("@")[2]

        verdicts[key] = {
            "legs": len(legs),
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
            "likely": None,
            "likely_signals": [],
        }
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

def summarize(verdicts):
    """Message-level counters over the verdicts."""
    vs = list(verdicts.values())
    by_likely = Counter(v["likely"] for v in vs if v["genuine_failure"])
    return {
        "logical_messages": len(vs),
        "multi_leg": sum(1 for v in vs if v["legs"] > 1),
        "genuine_failures": sum(1 for v in vs if v["genuine_failure"]),
        "echo_messages": sum(1 for v in vs if v["echo_present"]),
        "relayed_only": sum(1 for v in vs if v["relayed_only"]),
        "delivered_despite_fail": sum(1 for v in vs if v["delivered_despite_fail"]),
        "blocked_despite_pass": sum(1 for v in vs if v["blocked_despite_pass"]),
        "by_likely": {k: by_likely.get(k, 0) for k in LIKELY_LABELS},
    }


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
        add("MAILFLOW-002", "major",
            "%d messages failed authentication but reached a mailbox" % len(items),
            _sample(items),
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
    return "%s -> %s  \"%s\"  %s  envelope=%s%s" % (
        v["sender"] or "(no sender)", key[1] or "(no recipient)", v["subject"] or "(no subject)",
        legs, v["envelope_domain"] or "(none)", ("  " + v["likely"]) if v["likely"] else "")


def _list(title, why, items, top):
    if not items:
        return
    print("\n%s (%d; %s):" % (title, len(items), why))
    for key, v in items[:top]:
        print("  " + _fmt_msg(key, v))
    if len(items) > top:
        print("  ... %d more, use --json for the full list" % (len(items) - top))


def print_report(c, verdicts, findings, auth_column=None, top=20):
    scope = ""
    if c["rows_in_scope"] != c["raw_rows"]:
        scope = "   (%d in scope after --sender-domain)" % c["rows_in_scope"]
    print(f"rows read                   : {c['raw_rows']}{scope}")
    if c["rows_without_msgid"]:
        print(f"  without a Message-ID      : {c['rows_without_msgid']}   <-- cannot be deduplicated, left out below")
    print(f"logical messages            : {c['logical_messages']}")
    print(f"  with more than one leg    : {c['multi_leg']}")
    print(f"  GENUINE failures          : {c['genuine_failures']}   <-- the real number")
    print(f"  messages with an echo leg : {c['echo_messages']}   <-- a failing copy of a message that also passed; not failures")
    print(f"  delivered only via relay  : {c['relayed_only']}")
    if auth_column:
        print()
        print(f"delivery vs authentication (auth column: {auth_column}):")
        print(f"  failed authentication but DELIVERED           : {c['delivered_despite_fail']}   <-- a local override let these through")
        print(f"  passed authentication but BLOCKED/QUARANTINED : {c['blocked_despite_pass']}   <-- something other than DMARC caught these")
    print()
    print(f"raw rows with a failing verdict: {c['raw_failing_rows']}")
    if c["logical_messages"]:
        print(f"counting rows would report {c['raw_failing_rows']} failures; the true count is {c['genuine_failures']}.")

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
    if auth_column:
        _list("failed authentication but DELIVERED", "a local override let these through",
              [(k, v) for k, v in verdicts.items() if v["delivered_despite_fail"]], top)
        _list("passed authentication but BLOCKED or QUARANTINED", "something other than DMARC caught these",
              [(k, v) for k, v in verdicts.items() if v["blocked_despite_pass"]], top)

    actionable = sum(1 for f in findings if f["severity"] in ("major", "blocking"))
    print(f"\n{len(findings)} findings, {actionable} major or blocking")
    for f in findings:
        print(f"  [{f['severity']}] {f['id']} {f['title']}" + ("" if f["verified"] else " (heuristic, not verified)"))


# -------------------------------------------------------------------- cli

def die(msg):
    print(msg, file=sys.stderr)
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
