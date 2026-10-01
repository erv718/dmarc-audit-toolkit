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

## Two ways to use this

**1. Audit with no AI.** Python, an optional `.env`, one command. You get
`report.md` (findings ranked by severity, a go / no-go gate per domain, the
next policy step) and `report.json`, plus `plan.md` with the records to
publish next whenever live DNS was checked. One more command,
`src/next_steps.py`, turns that run into `next_steps.md`, the status
document you send to the people who fix things (the weekly job below writes
it for you). No AI, no MCP, nothing beyond `requirements.txt`.

```bash
pip install -r requirements.txt
python src/verify_setup.py                       # only if you gave it an app registration
python src/audit.py                              # domains read from your tenant
python src/audit.py example.com,other.example    # or name them; the two lists are merged
```

Domains come from three places and are merged with duplicates dropped: the
command line (comma or space separated), a file (`--file`), and the tenant
itself when the app registration has `Domain.Read.All` (run with no domains
and it audits everything the tenant has verified). `--mailflow` adds every
subdomain seen sending in the last 30 days; `--no-graph` skips the tenant.

**2. Then add the AI, if you want it.** Set `AI_ANALYSIS_ENABLED=true` in
`.env`, point Claude Code, Codex, Cursor or any agent that reads `AGENTS.md`
at the repo, and hand it `next_steps.md` to polish and `report.json` for the
evidence. The contract keeps the agent read-only and explicit about verified
versus inferred, and it forbids writing a status document from memory when
the generated one exists. Clients without shell access use the MCP server
instead (`pip install -r requirements-mcp.txt`, then the registration
command below). The AI reads what the tools produced; it never touches the
tenant itself.

## One command, every week

`collect.py` is the whole audit as a scheduled job. With an app registration
in `.env` it verifies the registration, reads the tenant's domain list, pulls
the raw mail log for each organizational domain, pulls new aggregate reports
out of your report mailbox, runs the audit, writes the rollout plan, keeps a
dated history with running metrics, writes the status document, and posts a
one-message summary to Slack or Teams. Without credentials it still runs DNS,
the plan, the document, and whatever files you hand it.

```bash
python src/collect.py                       # everything, from the tenant
python src/collect.py --dry-run             # same, print the summary instead of posting it
.\scripts\register_weekly_task.ps1         # Windows: run it every Monday at 06:00
```

What you get under `audit-out/`, in the order people read it:

- `latest/next_steps.md` - **the document you send.** Where the rollout
  stands in one sentence, deduplicated failure counts with the raw number
  alongside, what is failing by envelope domain and by sender, a per-domain
  table (policy today, gate, next step), what happens next grouped by owner,
  the ask for the week, the open questions, and a glossary. Written by
  `src/next_steps.py` from the files below with no AI involved: every
  sentence is assembled from the run and every number is copied from it, so
  any tenant that runs the toolkit gets the same document from the same
  inputs. `latest/next_steps.json` is the same content as data.
- `latest/report.md` - the technical detail behind it: every finding with
  its evidence, the gate reasoning per domain, the mail-log and outside-view
  numbers, and what was verified versus inferred. `report.json` is what the
  other tools and any agent read.
- `latest/plan.md` - the DNS records to publish next, grouped by DNS host,
  with the current value, rollback and the prerequisites of each step. The
  plan is regenerated from each run, so an enforcement step appears only
  when its prerequisites are met - one ratchet per domain per week.
- `latest/summary.txt` - the one-message version posted to Slack or Teams:
  what changed since last time (new and resolved findings, policy changes,
  newly seen senders, spoofing blocked).
- `history/<date>/` for every run, and `metrics.md` across runs (the trend).

**Who owns what.** `next_steps.md` groups actions by owner, and the owners
come from `owners.csv` in the repo root: one row per sender address, domain
or glob, naming the team or person who fixes it and the channel to reach
them (`samples/owners.csv.example` shows the three pattern kinds). The file
is local and gitignored, and it is optional: without it the document is
still written, with every action under "Unassigned - needs an owner" and a
"who owns this" line in the open questions. Add a row, rerun, and the action
moves under its owner. `--owners PATH` points at another file, `--no-owners`
skips the lookup.

## How far back can it see?

The hunting API shows a rolling 30 days - that is Microsoft's retention
ceiling, not a setting, and no query gets past it. The long view comes from
accumulation instead: the first run does a one-time backfill of your report
mailbox, every weekly run archives the new aggregate reports and stamps a
dated copy of everything under `audit-out/history/`. By week six you are
reading six weeks of local history even though the API still only shows 30
days - and `metrics.md` turns that into the trend line. Those files are
exactly what the AI layer reads when you opt it in: the archive lives on
your disk, and nothing leaves the machine unless you share it.

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

# The same run as the document you send: status, what is failing, who fixes it, the ask
python src/next_steps.py audit-out/report.json --owners samples/owners.csv.example
```

The sample output shows the whole point:

```
rows read                   : 93
logical messages            : 81
  with more than one leg    : 12
  GENUINE failures          : 21   <-- the real number
  messages with an echo leg : 12   <-- a failing copy of a message that also passed; not failures
  delivered only via relay  : 6

4 findings, 2 major or blocking
  [major] MAILFLOW-001 21 logical messages failed with no passing copy, from 6 senders
  [major] MAILFLOW-002 3 messages failed authentication but reached a mailbox
  [minor] MAILFLOW-003 2 messages passed authentication but were blocked or quarantined
  [info] MAILFLOW-004 heuristic split of the failures: 18 likely_spoof, 3 likely_misconfigured_sender, 0 unknown (heuristic, not verified)
```

Counting rows would report 33 failures; the true count is 21.

## Contents

| Path | What it does |
|---|---|
| `src/audit.py` | The orchestrator: runs the whole sweep (DNS posture, rua reports, mail log, headers) and writes `report.md` + `report.json` with severity-ranked findings and a go / no-go gate verdict for the next policy step, plus `plan.md` + `plan.json` when live DNS ran (`--no-plan` skips them). Works `--offline` from saved files. |
| `src/discover.py` | Finds the domains to audit: command line, file, the tenant (Graph), and subdomains seen in mail flow; merges and deduplicates; records each zone's DNS host (Route53, CSC, Cloudflare, ...), which decides how a change gets made. |
| `src/verify_setup.py` | Proves the app registration: token, required roles, roles in EXCESS (write-capable ones flagged), the consent grant and date behind each role, the domain list, a hunting query, the report mailbox, and that other mailboxes are denied. |
| `src/graph_client.py` | Shared Microsoft Graph helper (token, paging, domains, hunting, mailbox). Library only. |
| `src/collect.py` | The weekly job: verify, discover, pull mail log and reports, audit, plan, history and metrics, summary. |
| `src/plan.py` | report.json in, plan.md out: the exact records to publish per domain, grouped by DNS host, with current value, rollback, priority, and the prerequisites for each enforcement step. |
| `src/next_steps.py` | report.json in, `next_steps.md` + `next_steps.json` out: the status document you send. One-line status, deduplicated counts with the raw number alongside, what is failing, a per-domain table, actions grouped by owner, the ask and the open questions. Reads `plan.json`, `metrics.json`, the previous run and `owners.csv` when they exist; deterministic, no AI; `collect.py` runs it every week. |
| `src/fetch_rua.py` | Pulls aggregate (rua) reports out of your report mailbox by Graph (Mail.Read scoped to that mailbox), with a one-time backfill and delta runs after. |
| `src/notify.py` | One Slack or Teams message per run: policy and gate per domain, findings, failure counts, top failing senders, what changed since the last run. |
| `scripts/register_weekly_task.ps1` | Registers (or removes) the Windows scheduled task that runs `collect.py` weekly. |
| `src/dedupe.py` | Collapses mail-log rows into logical messages by (Message-ID, recipient) and classifies each one. Reports failed-but-delivered and passed-but-blocked separately, prints a census of the failing senders by envelope domain and by sender address (`--json` carries the full lists), and dies loudly on a misspelled column instead of returning a silent zero. |
| `src/spf_lookups.py` | Recursively expands an SPF record and counts DNS-querying mechanisms against the RFC 7208 limit of ten. Falls back to DNS-over-HTTPS; reports lookup errors as errors, never as "no record". |
| `src/dns_audit.py` | Multi-domain posture sweep: SPF strength and lookup budget, DMARC policy and subdomain inheritance, DKIM selectors (incl. dangling CNAMEs), MX. One findings list per domain with evidence. |
| `src/rua_parse.py` | Turns rua aggregate XML (plain, .gz, or .zip) into answers: selectors still in use, unknown senders, failing streams, SPF-only senders who break at reject. |
| `src/headers.py` | Parses one live message header and calls SPF/DKIM/DMARC alignment explicitly - the proof behind rule 9 (a toggle is not a working feature). |
| `src/audit_rules.ps1` | Read-only Exchange Online transport-rule audit: allow rules without authentication conditions, forgeable header matches, audit-mode blocks, oversized exception lists, dead rules. |
| `src/audit_bypasses.ps1` / `src/audit_groups.ps1` | Read-only companions: who can bypass filtering (connectors, safe lists) and which groups expand to external forwarding. |
| `src/run_hunting.py` | Runs the saved KQL by API through a read-only App Registration and writes CSV. The intended data plane - no portal copy-paste. |
| `src/mcp_server.py` | Exposes the tools above to any MCP client (Claude Code, Claude Desktop, others). One registration command; nothing to deploy. |
| `queries/` | Eight advanced-hunting queries for Microsoft 365 Defender: deduplicated census and failures, subdomain health, override audit, echo-vs-loss twins, pre-reject DKIM alignment, impersonation, and a raw per-leg export that pipes straight into `dedupe.py`. |
| `samples/` | Synthetic mail log (clean passes, echo pairs, genuine spoofing, relay-only delivery), sample rua reports, four annotated message headers, and `owners.csv.example`, the owners file to copy. |
| `docs/` | Methodology, the reasoning behind each tool, the AI-assisted workflow, and the shape of the generated status document (`docs/templates/next-steps.md`). |

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

The status document is not an AI product. `src/next_steps.py` writes
`next_steps.md` from `report.json`, `plan.json`, `metrics.json` and
`owners.csv`, deterministically, with no model in the loop, and `collect.py`
does that on every run. An agent's job is to refine that document - sharpen
the hooks, reorder it for the audience, split it into the Slack post, the
owner messages and the tracker entries - never to produce it from a
conversation. Nothing in the document depends on what an agent remembers:
any tenant that runs the toolkit gets the same document from the same
inputs, and `AGENTS.md` rule 13 tells the agent to edit the generated copy
rather than write its own.

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
misdiagnosis, deleting keys something still signs with, and writing a status
document from memory. (`CLAUDE.md` points Claude Code at it.) See
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
