# Running this against Google Workspace

The core tools in this repo are platform-neutral: `dedupe.py` eats any CSV,
`spf_lookups.py` and `dns_audit.py` only talk to DNS. What differs per
platform is where the mail log lives and where local override rules hide.
This guide maps every step of the methodology onto Google Workspace.

## Where the log lives: Gmail logs in BigQuery

The Microsoft 365 equivalent of Advanced Hunting is the Workspace logs
export to BigQuery (Admin console > Reporting > Data integrations). It
requires an Enterprise or Education edition and a GCP project to receive
the data. Once flowing, per-message rows land in an `activity` table with
the fields this project cares about:

| Field | What it is |
|---|---|
| `gmail.message_info.rfc2822_message_id` | The Message-ID - dedupe key |
| `gmail.message_info.destination[].address` | Recipient(s), repeated record |
| `gmail.message_info.connection_info.spf_pass` | SPF verdict (boolean) |
| `gmail.message_info.connection_info.dkim_pass` | DKIM verdict (boolean) |
| `gmail.message_info.connection_info.dmarc_pass` | DMARC verdict (boolean) |
| `gmail.message_info.source.address` | Envelope sender (SPF identity) |
| `gmail.message_info.source.from_header_address` | Header From (DMARC identity) |
| `gmail.message_info.triggered_rule_info[]` | Which local rules touched the message |
| `gmail.message_info.spam_info.disposition` | 1 not spam, 2 spam, 3 phishing, 4 suspicious, 5 malware |

SQL versions of all four hunting queries are in `queries/bigquery/`.
Replace `YOUR_PROJECT.YOUR_DATASET` and `example.com`, and verify the field
paths against your dataset preview first - Google has changed this schema
before and the legacy Gmail-only export shapes tables differently.

The dedupe rule is identical to Microsoft 365: forwarding and Google
Groups redistribution produce extra log rows that fail authentication for
mail that already delivered. A message is failing only if no row for its
(Message-ID, recipient) pair passed. Export rows to CSV and `dedupe.py`
works unchanged with the `--*-column` flags.

No BigQuery edition? Email Log Search (Admin console > Reporting) is the
message-trace equivalent: 30 days, per-message SPF/DKIM/DMARC verdicts in
the message details, but no bulk export worth analyzing. It is fine for
verifying a single sender, not for a census.

## The DKIM trap specific to Google

A Workspace tenant that never configured DKIM still signs its outbound
mail - as `d=<domain>.gappssmtp.com`. That signature does NOT align with
your domain, so it does nothing for DMARC. "Our mail is DKIM signed" is
true and useless at the same time. Turn on DKIM in Admin console > Apps >
Google Workspace > Gmail > Authenticate email (default selector `google`,
2048-bit), publish the record, then verify alignment from a live header:
`d=` must equal your header-from domain. `dns_audit.py` probes the
`google` selector by default. CLAUDE.md rule 9 applies: the admin console
saying "Authenticating email" is a toggle, only a header is proof.

## Where local overrides hide (the transport-rule equivalent)

There is no API that enumerates Gmail routing and compliance settings, so
this audit is manual. Walk Admin console > Apps > Google Workspace >
Gmail > Spam, phishing, and malware + Compliance + Routing, and apply the
same issue taxonomy `audit_rules.ps1` uses:

- **ALLOW-WITHOUT-AUTH:** any approved sender list or spam bypass where
  the "Only bypass filters for messages from senders that pass SPF or
  DKIM" style checkbox is unchecked. An address list without required
  authentication is a standing invitation to spoof exactly the senders
  you trust most.
- **FORGEABLE-CONDITION:** content compliance or routing rules keyed on
  headers or body strings a sender controls. Anyone who learns the magic
  string inherits the rule's consequence.
- **AUDIT-MODE-BLOCK:** rules set to log or quarantine-with-release that
  everyone assumes are blocking. Check the quarantine (Admin console >
  Manage quarantines) for what they actually caught.
- **Inbound gateway:** if a third-party filter fronts Gmail and the
  inbound gateway setting is on, SPF is evaluated against the gateway's
  IPs. Misconfigured, this either breaks all SPF or trusts everything.

## Google Groups: the distribution list problem

Groups are where DMARC enforcement bites on Google, the same way DLs bite
on Exchange. A group that redistributes external mail re-sends it from
your infrastructure: SPF alignment breaks immediately, and if the group
adds a subject prefix or footer, the original DKIM signature breaks too.
Symptoms show up as internal-to-internal DMARC failures from your busiest
group senders. Check each group's posting permissions and whether it
rewrites or preserves the original From. Mail from an enforced external
domain through a rewriting group will be rejected by member mailboxes -
find these before the sending domain reaches p=reject, not after.

## The outside view is unchanged

Aggregate reports (Valimail, dmarcian, or raw rua parsing) work the same
regardless of mailbox provider - that side of the methodology needs no
translation. Your BigQuery logs only see mail that touches your tenant;
the rua feed sees what the rest of the world receives.
