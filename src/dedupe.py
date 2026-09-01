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

Usage
-----
    python dedupe.py export.csv --sender-domain example.com

Expects a CSV export containing at least these columns (Microsoft 365 Defender
"All email" export naming, override with flags for other tools):

    Internet message ID, Recipients, Sender address, Sender domain,
    Delivery action, Latest delivery location
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

PASS_ACTIONS = {"delivered", "deliveredtodeletedfolder"}
FAIL_ACTIONS = {"blocked", "quarantined", "junked", "replaced"}


def load(path, cols):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            yield row


def classify(rows, cols, sender_domain=None, auth_column=None):
    """Return per-message verdicts keyed by (message-id, recipient)."""
    groups = defaultdict(list)
    for row in rows:
        if sender_domain:
            dom = (row.get(cols["domain"]) or "").lower()
            if dom != sender_domain and not dom.endswith("." + sender_domain):
                continue
        mid = (row.get(cols["msgid"]) or "").strip()
        rcpt = (row.get(cols["recipient"]) or "").lower().strip()
        if not mid:
            continue
        groups[(mid, rcpt)].append(row)

    verdicts = {}
    for key, legs in groups.items():
        actions = [(leg.get(cols["action"]) or "").strip().lower() for leg in legs]
        locations = [(leg.get(cols["location"]) or "").strip() for leg in legs]

        # authentication verdict, when the export carries one
        anypass = anyfail = False
        if auth_column:
            for leg in legs:
                val = (leg.get(auth_column) or "").lower()
                if "pass" in val:
                    anypass = True
                if "fail" in val:
                    anyfail = True
        else:
            anypass = any(a in PASS_ACTIONS for a in actions)
            anyfail = any(a in FAIL_ACTIONS for a in actions)

        reached_mailbox = any(
            a in PASS_ACTIONS and ("inbox" in l.lower() or "junk" in l.lower() or "deleted" in l.lower())
            for a, l in zip(actions, locations)
        )
        relayed_only = (
            any("on-prem" in l.lower() or "external" in l.lower() for l in locations)
            and not reached_mailbox
        )

        verdicts[key] = {
            "legs": len(legs),
            "genuine_failure": anyfail and not anypass,
            "echo_present": anyfail and anypass,
            "reached_mailbox": reached_mailbox,
            "relayed_only": relayed_only,
            "sender": (legs[0].get(cols["sender"]) or "").lower(),
            "subject": legs[0].get(cols.get("subject", ""), ""),
        }
    return verdicts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path")
    ap.add_argument("--sender-domain", help="restrict to this domain and its subdomains")
    ap.add_argument("--auth-column", help="column holding the DMARC verdict, if present")
    ap.add_argument("--msgid-column", default="Internet message ID")
    ap.add_argument("--recipient-column", default="Recipients")
    ap.add_argument("--sender-column", default="Sender address")
    ap.add_argument("--domain-column", default="Sender domain")
    ap.add_argument("--action-column", default="Delivery action")
    ap.add_argument("--location-column", default="Latest delivery location")
    ap.add_argument("--subject-column", default="Subject")
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    cols = {
        "msgid": args.msgid_column,
        "recipient": args.recipient_column,
        "sender": args.sender_column,
        "domain": args.domain_column,
        "action": args.action_column,
        "location": args.location_column,
        "subject": args.subject_column,
    }

    rows = load(args.csv_path, cols)
    verdicts = classify(rows, cols, args.sender_domain, args.auth_column)

    total = len(verdicts)
    genuine = [v for v in verdicts.values() if v["genuine_failure"]]
    echoes = [v for v in verdicts.values() if v["echo_present"]]
    relayed = [v for v in verdicts.values() if v["relayed_only"]]
    multileg = [v for v in verdicts.values() if v["legs"] > 1]

    print(f"logical messages            : {total}")
    print(f"  with more than one leg    : {len(multileg)}")
    print(f"  GENUINE failures          : {len(genuine)}   <-- the real number")
    print(f"  failing legs w/ a pass    : {len(echoes)}   <-- echoes, not failures")
    print(f"  delivered only via relay  : {len(relayed)}")
    if total:
        naive = len(genuine) + len(echoes)
        print()
        print(f"counting rows would report {naive} failures; the true count is {len(genuine)}.")

    if genuine:
        print("\ntop genuinely failing senders:")
        for sender, n in Counter(v["sender"] for v in genuine).most_common(args.top):
            print(f"  {n:>6}  {sender}")


if __name__ == "__main__":
    main()
