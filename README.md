# provenance

Tools for auditing a DMARC rollout using real mail data instead of dashboard
guesswork.

Built while taking two domains from `p=none` to enforcement across roughly
thirty sending services. Every tool here exists because something went wrong
that a report did not show.

The full story: [Your DMARC Failure Count Is Wrong](https://blog.soarsystems.cc/your-dmarc-failure-count-is-wrong/)

## Why

Most DMARC guidance stops at "publish a record, read the reports, ratchet the
policy." The hard part is everything after that.

**Your failure count is wrong until you deduplicate.** One logical email can
produce several rows in mail logs. Relay hops, forwarding, and multi-recipient
fan-out all create extra legs, and those legs authenticate differently. The
original leg passes; a relayed leg fails, because the relaying host is not in
the sender's SPF record and the message may have been altered. Count rows and a
perfectly healthy sender looks broken.

**"Blocked" and "failed DMARC" are different questions.** Mail can be
quarantined by a filtering rule while DMARC passes, or fail DMARC and be
delivered anyway by a local allow rule. A domain can look healthy inside your
own tenant while external receivers are already junking it.

**SPF has a hard limit of ten DNS lookups.** Past it, evaluation returns
PERMERROR and most receivers treat that as failure, for the whole domain, every
message. Domains drift toward the limit one vendor at a time and nobody
notices until the record breaks.

## Quick start

No credentials needed for either tool.

```bash
pip install -r requirements.txt

# How close is a domain to the SPF lookup limit?
python src/spf_lookups.py example.com

# What is the real failure count in a mail log export?
python src/dedupe.py samples/sample_maillog.csv --sender-domain example.com --auth-column DMARC
```

The sample output shows the whole point:

```
logical messages            : 76
  with more than one leg    : 12
  GENUINE failures          : 18   <-- the real number
  failing legs w/ a pass    : 12   <-- echoes, not failures
  delivered only via relay  : 6

counting rows would report 30 failures; the true count is 18.
```

## Contents

| Path | What it does |
|---|---|
| `src/dedupe.py` | Collapses mail-log rows into logical messages by Message-ID and classifies each one. Works on any CSV export; column names are configurable. |
| `src/spf_lookups.py` | Recursively expands an SPF record and counts DNS-querying mechanisms against the RFC 7208 limit of ten. |
| `queries/` | Advanced-hunting queries for Microsoft 365 Defender. Deduplicated failures, sender census, subdomain health, and what your local overrides are masking. |
| `samples/` | Synthetic mail log containing clean passes, echo pairs, genuine spoofing, and relay-only delivery. |
| `docs/` | Methodology and the reasoning behind each tool. |

## What you need to supply

**For `dedupe.py`:** a mail log export containing a **Message-ID**, a recipient,
and a delivery action. An authentication verdict column is strongly preferred;
without one the tool falls back to delivery outcome, which answers "was it
blocked" rather than "did it fail authentication." Microsoft 365 Defender's
"All email" export works with the default column names; other tools need the
`--*-column` flags.

Message-ID is not optional. Most DMARC aggregate reports do not include it,
which means RUA data alone cannot be deduplicated this way.

**For `spf_lookups.py`:** a domain name. Nothing else.

**For the queries:** Microsoft 365 Defender or Sentinel with Advanced Hunting
access.

## Safety

Everything here is read-only. Nothing modifies DNS, mail flow rules, or tenant
configuration. Credentials, if you use any, come from environment variables and
are never written to disk by these tools. See `.env.example`.

## License

MIT.
