# dmarc-audit-toolkit

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

The DNS and file tools need nothing installed but Python (they fall back to
DNS-over-HTTPS when port 53 is in the way). Pulling tenant data by API needs
the read-only app registration described below.

```bash
pip install -r requirements.txt

# How close is a domain to the SPF lookup limit?
python src/spf_lookups.py example.com

# What is the real failure count in a mail log export?
python src/dedupe.py samples/sample_maillog.csv --sender-domain example.com --auth-column DMARC

# The whole sweep - DNS posture, rua reports, mail log, headers - ending in a gate verdict
python src/audit.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --headers samples/headers
```

The sample output shows the whole point:

```
rows read                   : 93
logical messages            : 81
  with more than one leg    : 12
  GENUINE failures          : 21   <-- the real number
  messages with an echo leg : 12   <-- echoes, not failures
  delivered only via relay  : 6

4 findings, 2 major or blocking
  [major] MAILFLOW-001 21 logical messages failed with no passing copy, from 6 senders
  [major] MAILFLOW-002 3 messages failed authentication but reached a mailbox
```

Counting rows would report 33 failures; the true count is 21.

## Contents

| Path | What it does |
|---|---|
| `src/audit.py` | The orchestrator: runs the whole sweep (DNS posture, rua reports, mail log, headers) and writes `report.md` + `report.json` with severity-ranked findings and a go / no-go gate verdict for the next policy step. Works `--offline` from saved files. |
| `src/dedupe.py` | Collapses mail-log rows into logical messages by (Message-ID, recipient) and classifies each one. Reports failed-but-delivered and passed-but-blocked separately, and dies loudly on a misspelled column instead of returning a silent zero. |
| `src/spf_lookups.py` | Recursively expands an SPF record and counts DNS-querying mechanisms against the RFC 7208 limit of ten. Falls back to DNS-over-HTTPS; reports lookup errors as errors, never as "no record". |
| `src/dns_audit.py` | Multi-domain posture sweep: SPF strength and lookup budget, DMARC policy and subdomain inheritance, DKIM selectors (incl. dangling CNAMEs), MX. One findings list per domain with evidence. |
| `src/rua_parse.py` | Turns rua aggregate XML (plain, .gz, or .zip) into answers: selectors still in use, unknown senders, failing streams, SPF-only senders who break at reject. |
| `src/headers.py` | Parses one live message header and calls SPF/DKIM/DMARC alignment explicitly - the proof behind rule 9 (a toggle is not a working feature). |
| `src/audit_rules.ps1` | Read-only Exchange Online transport-rule audit: allow rules without authentication conditions, forgeable header matches, audit-mode blocks, oversized exception lists, dead rules. |
| `src/audit_bypasses.ps1` / `src/audit_groups.ps1` | Read-only companions: who can bypass filtering (connectors, safe lists) and which groups expand to external forwarding. |
| `src/run_hunting.py` | Runs the saved KQL by API through a read-only App Registration and writes CSV. The intended data plane - no portal copy-paste. |
| `src/mcp_server.py` | Exposes the tools above to any MCP client (Claude Code, Claude Desktop, others). One registration command; nothing to deploy. |
| `queries/` | Eight advanced-hunting queries for Microsoft 365 Defender: deduplicated census and failures, subdomain health, override audit, echo-vs-loss twins, pre-reject DKIM alignment, impersonation, and a raw per-leg export that pipes straight into `dedupe.py`. |
| `samples/` | Synthetic mail log (clean passes, echo pairs, genuine spoofing, relay-only delivery), sample rua reports, and four annotated message headers. |
| `docs/` | Methodology and the reasoning behind each tool. |

## What you need to supply

**For `dedupe.py`:** a mail log export containing a **Message-ID**, a recipient,
and a delivery action. The easiest source is your own tenant:
`queries/raw_maillog.kql` projects exactly the columns `dedupe.py` expects, so
`src/run_hunting.py queries/raw_maillog.kql --out maillog.csv` followed by
`src/dedupe.py maillog.csv --auth-column DMARC` needs no column flags. A
Microsoft 365 Defender "All email" export works the same way; other tools need
the `--*-column` flags. Misspell a column name and the tool exits with the
list of columns it can see rather than reporting a silent zero.

Message-ID is not optional. Most DMARC aggregate reports do not include it,
which means RUA data alone cannot be deduplicated this way.

**For `spf_lookups.py`:** a domain name. Nothing else.

**For the outside view:** the rua reports your DMARC record already asks
receivers for. Download the XML (any reporter, plain or zipped) and point
`src/rua_parse.py` at the files - no account or API key needed. Your tenant
logs only cover mail that touches your tenant; aggregate reports are the only
way to see the rest.

**For the queries:** an Entra ID App Registration with the read-only
`ThreatHunting.Read.All` permission, run through `src/run_hunting.py` (setup:
`docs/app-registration.md`). Edit the `let sender_domain` line at the top of
each `.kql` file to your domain (keep your edited copies in gitignored
`queries/live/`). Pasting them into Defender Advanced Hunting by hand works
too, but the app registration is the intended path.

## Safety

Everything here is read-only. Nothing modifies DNS, mail flow rules, or tenant
configuration. Credentials, if you use any, come from environment variables and
are never written to disk by these tools. See `.env.example`.

## Using this with an AI agent

The intended end state: the app registration is the data plane and the agent
is the analysis layer. The agent pulls fresh results through
`src/run_hunting.py`, the script reads credentials from `.env`, and the
secret never appears in the conversation.

AI access is opt-in, off by default: nothing in this repo lets an AI client
touch your data until `.env` contains `AI_ANALYSIS_ENABLED=true`. The MCP
server refuses to start without it, and `AGENTS.md` instructs every agent
to stop without it. Running the Python tools yourself needs no toggle.

Two ways to wire that up. Claude Code needs nothing: it is pointed at
`AGENTS.md` from `CLAUDE.md` and runs the scripts directly. Agents that read
`AGENTS.md` natively (most coding agents) need even less. Clients without
shell access (Claude Desktop, or any MCP client) use the bundled MCP server
instead - you do not build or deploy anything, the client launches it on
demand:

```
pip install -r requirements-mcp.txt
claude mcp add dmarc-audit-toolkit -- python "C:\path\to\dmarc-audit-toolkit\src\mcp_server.py"
```

(The registration needs the absolute path to your clone; the server confines
its file reads and CSV writes to that folder.)

The server exposes `audit_dns`, `walk_spf`, `dedupe_maillog`,
`run_hunting_query`, `parse_rua`, `parse_headers`, and `run_audit`. The
protocol surface is the permission boundary: no tool can write to DNS, mail
rules, or tenant config. The only writes any tool performs are the local CSV
or report files you explicitly request, and those paths are confined to the
repo folder.

The repo ships an `AGENTS.md` with agent ground rules distilled from running
this exact project agent-assisted, including the verification habits that
prevent the classic wrong conclusions: echo miscounts, resolver-path
misdiagnosis, and deleting keys something still signs with. (`CLAUDE.md`
points Claude Code at it.) See
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
