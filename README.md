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
| `src/dns_audit.py` | Multi-domain posture sweep: SPF strength and lookup budget, DMARC policy gaps, DKIM selector presence, MX. Finds the subdomain nobody remembered. |
| `src/audit_rules.ps1` | Read-only Exchange Online transport-rule audit: allow rules without authentication conditions, forgeable header matches, audit-mode blocks, oversized exception lists, dead rules. |
| `src/run_hunting.py` | Runs the saved KQL by API through a read-only App Registration and writes CSV. The intended data plane - no portal copy-paste. |
| `src/mcp_server.py` | Exposes the tools above to any MCP client (Claude Code, Claude Desktop, others). One registration command; nothing to deploy. |
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

**For the outside view:** an aggregate reporting service on your `rua` address.
This project used Valimail; dmarcian or a raw rua parser gives the same lens.
Your tenant logs only cover mail that touches your tenant - aggregate reports
are the only way to see the rest.

**For the queries:** an Entra ID App Registration with the read-only
`ThreatHunting.Read.All` permission, run through `src/run_hunting.py` (setup:
`docs/app-registration.md`). Pasting them into Defender Advanced Hunting by
hand works too, but the app registration is the intended path.

## Safety

Everything here is read-only. Nothing modifies DNS, mail flow rules, or tenant
configuration. Credentials, if you use any, come from environment variables and
are never written to disk by these tools. See `.env.example`.

## Using this with an AI agent

The intended end state: the app registration is the data plane and the agent
is the analysis layer. The agent pulls fresh results through
`src/run_hunting.py`, the script reads credentials from `.env`, and the
secret never appears in the conversation.

Two ways to wire that up. Claude Code needs nothing: it reads `CLAUDE.md`
and runs the scripts directly. Clients without shell access (Claude
Desktop, or any MCP client) use the bundled MCP server instead - you do
not build or deploy anything, the client launches it on demand:

```
pip install -r requirements-mcp.txt
claude mcp add dmarc-provenance -- python src/mcp_server.py
```

The server exposes `audit_dns`, `walk_spf`, `dedupe_maillog`, and
`run_hunting_query`. The protocol surface is the permission boundary: no
tool can write to DNS, mail rules, or tenant config. The only write any
tool performs is the local CSV export you explicitly request via
`out_csv`, and that path is confined to the repo folder.

The repo ships a `CLAUDE.md` with agent ground rules distilled from running
this exact project agent-assisted, including the verification habits that
prevent the classic wrong conclusions: echo miscounts, resolver-path
misdiagnosis, and deleting keys something still signs with. See
`docs/ai-assisted-workflow.md` for the human and agent split that worked, and
the failure modes to watch for.

## Planned

Everything in this repo was used on a real enforcement rollout before it was
published. Support for other platforms ships the same way: written, then
validated against a real tenant, then released.

- **Google Workspace** - the method ports (Gmail logs in BigQuery carry a
  Message-ID and per-row SPF/DKIM/DMARC verdicts, so deduplication works
  identically), and `dedupe.py`, `spf_lookups.py`, and `dns_audit.py` are
  already platform-neutral. SQL query equivalents and a rules checklist land
  here once they have been proven against a live tenant.

## License

MIT.
