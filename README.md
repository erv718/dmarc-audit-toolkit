# dmarc-audit-toolkit

**TL;DR.** One read-only command audits your DMARC rollout from real mail data
and tells you exactly what to do next. Give it an Entra ID App Registration
(three values in `.env`, about fifteen minutes with an admin, click paths
below) and run:

```
pip install -r requirements.txt            # Python 3.11 or newer, nothing else
copy .env.example .env                      # paste the app registration values (Step 1)
copy audit.example.toml audit.toml          # your domains and settings (Step 2)
python src/verify_setup.py                  # proves the registration: PASS / WARN / FAIL with the fix
python src/collect.py                       # the whole audit
```

You get, under `audit-out/latest/`: `next_steps.md` (the status document you
send: where the rollout stands in one sentence, what is failing, who fixes it,
the ask), `report.md` (every finding, and a go / no-go gate per domain),
`todo.md` (one prioritised list, top to bottom), `plan.md` (the exact DNS
records to publish next, with rollback), plus a dated history and running
metrics. Put it on a weekly schedule and it posts a short Slack summary when
you ask it to. Everything is read-only: nothing here changes DNS, mail flow
rules or tenant configuration, ever. AI is optional and off by default. On
macOS and Linux use `cp` for the two copy lines.

The full story: [Your DMARC Failure Count Is Wrong](https://blog.soarsystems.cc/your-dmarc-failure-count-is-wrong/)

## Why this exists

Most DMARC guidance stops at "publish a record, read the reports, ratchet the
policy." The hard part is everything after that, and three things bite every
time:

- **Your failure count is wrong until you deduplicate.** One email produces
  several log rows (relay hops, forwarding, fan-out) and the relayed rows fail
  authentication even when the original passed. Count rows and a healthy
  sender looks broken. Every number here is deduplicated by Message-ID and
  recipient, with the raw count shown next to it so you can see the gap.
- **"Blocked" and "failed DMARC" are different questions.** A local allow rule
  can deliver mail that fails; a filtering rule can quarantine mail that
  passes. A domain can look healthy inside your tenant while Gmail is already
  junking it.
- **SPF has a hard limit of ten DNS lookups.** Past it, every message fails for
  the whole domain. Domains drift toward the limit one vendor at a time.

Built while taking two domains from `p=none` to enforcement across roughly
thirty sending services; every tool exists because something went wrong that a
dashboard did not show.

## Before you start

- Python 3.11 or newer (the settings file is TOML). `pip install -r
  requirements.txt` installs the one dependency.
- A Microsoft 365 tenant with Defender for Office 365 (advanced hunting is the
  mail-flow data source). Without it the DNS audit, the report parser and the
  plan still work from files.
- Someone who can create an App Registration and grant tenant-wide admin
  consent for Microsoft Graph application permissions: a Global Administrator
  or a Privileged Role Administrator. One sitting, then the toolkit runs on
  its own.
- Optional: the mailbox your `rua=` address delivers aggregate reports to.
  Reading it is the outside view: what other receivers saw.

## Step 1 - create the App Registration (click paths)

Every step is in the Entra admin center (entra.microsoft.com). Nothing here
needs a script.

1. **Register the app.** Identity > Applications > App registrations > **New
   registration**. Name: `dmarc-audit-toolkit-readonly`. Supported account
   types: **Accounts in this organizational directory only**. Redirect URI:
   leave empty (nothing signs in interactively). **Register**. On the Overview
   page copy **Application (client) ID** and **Directory (tenant) ID**.
2. **Add the read-only permissions.** API permissions > **Add a permission** >
   **Microsoft Graph** > **Application permissions**. Search for and tick
   `ThreatHunting.Read.All`, `Domain.Read.All`, and `Mail.Read` (only if you
   will read the report mailbox) > **Add permissions**. Then remove the
   default delegated `User.Read` row: its `...` menu > **Remove permission**.
3. **Grant admin consent.** Still under API permissions: **Grant admin
   consent for <your tenant>** > **Yes**. Every row's Status turns to a green
   "Granted for ...". Until this is done every call answers 401 or 403.
4. **Create a client secret.** Certificates & secrets > Client secrets > **New
   client secret**. Description `dmarc-audit-toolkit`, expiry 6 months (put the
   rotation date in your calendar) > **Add**. Copy the **Value** column now; it
   is shown once. A secret is enough for the Python tools; only the optional
   PowerShell auditors need a certificate.
5. **Fill `.env`.** Copy `.env.example` to `.env` and paste the tenant ID,
   client ID and secret value. Set `RUA_MAILBOX` to the report mailbox if you
   added `Mail.Read`, otherwise leave it empty. `.env` is gitignored; never
   commit it, paste it into a chat, or send it anywhere.
6. **Scope `Mail.Read` to the report mailbox** (only if you set `RUA_MAILBOX`).
   As an application permission it can read every mailbox in the tenant; an
   Exchange Online Application Access Policy restricts it to the one that
   receives the reports. In Exchange Online PowerShell, as an Exchange admin:

   ```powershell
   New-ApplicationAccessPolicy -AppId <client id> -PolicyScopeGroupId dmarc-reports@example.com -AccessRight RestrictAccess -Description "dmarc-audit-toolkit: aggregate report mailbox only"
   Test-ApplicationAccessPolicy -Identity someone.else@example.com -AppId <client id>     # expect: Denied
   ```

   Point it at the mailbox on your `rua=` line, never the forensic (`ruf=`)
   one. Tenants on RBAC for Applications scope the app the same way there.
7. **Prove it.** `python src/verify_setup.py` (add `--expect-denied
   someone.else@example.com` after step 6). Every check prints PASS, WARN or
   FAIL with the exact fix, lists roles the app holds beyond the ones below,
   and flags any that can write. Nothing it prints is a secret.

### The permissions, and why nothing more

| Permission | Where it lives | What the toolkit does with it | Used by | Without it |
|---|---|---|---|---|
| `ThreatHunting.Read.All` | Microsoft Graph, Application | runs the advanced hunting queries: 30 days of mail-flow telemetry, deduplicated | `collect.py`, `run_hunting.py`, `discover.py --mailflow` | no tenant data; DNS, saved reports and files still work |
| `Domain.Read.All` | Microsoft Graph, Application | reads the tenant's verified domain list, so a run with no arguments audits everything you own | `collect.py`, `discover.py`, `audit.py` | list the domains in `audit.toml` or on the command line |
| `Mail.Read`, scoped by an Application Access Policy | Microsoft Graph, Application | reads aggregate (rua) reports out of one mailbox: the outside view | `fetch_rua.py`, `collect.py` | no outside view; save the report files by hand and pass `--rua` |
| `Exchange.ManageAsApp` (optional) | Office 365 Exchange Online, Application, plus the **Global Reader** directory role on the app and a certificate | lets the three PowerShell auditors run unattended; they read transport rules, bypasses and groups, which Graph does not expose | `audit_rules.ps1`, `audit_bypasses.ps1`, `audit_groups.ps1` through `ToolkitExo.ps1` | run those three yourself after `Connect-ExchangeOnline`, or skip them |

The first three can read mail-flow telemetry, a domain list and one mailbox.
They cannot read other mail, change a rule, or touch DNS, so a leaked secret
means "someone can read our authentication telemetry", not "someone can
reconfigure mail flow". For the optional fourth row, the **role** decides what
the app can change, not the permission name: Global Reader can change nothing,
which is why it is the one to document. Reusing an existing registration? Run
`verify_setup.py` first and remove every role it lists as excess.

### Optional: unattended PowerShell auditors (`Exchange.ManageAsApp`)

Skip this on the Python-only path. To run the three PowerShell scripts from
the weekly schedule with nobody signed in:

1. API permissions > **Add a permission** > **APIs my organization uses** >
   search **Office 365 Exchange Online** > **Application permissions** >
   `Exchange.ManageAsApp` > **Add permissions** > **Grant admin consent**.
2. Identity > Roles & admins > **Global Reader** > **Add assignments** >
   search the app's name > select it > **Add**. This is the least-privilege
   role that lets app-only Exchange PowerShell read settings.
3. Make a certificate **under `private/`** (gitignored) using the recipe for
   your platform in `docs/app-registration.md`, then Certificates & secrets >
   **Certificates** > **Upload certificate** > the `.cer` file. The `.key` and
   `.pfx` never leave `private/` and are never committed.
4. In `.env` set `EXO_ORGANIZATION` and either `EXO_CERT_THUMBPRINT` (Windows
   certificate store) or `EXO_CERT_FILE=private/dmarc-audit-readonly.pfx`.

## Step 2 - settings (`audit.toml`)

Copy `audit.example.toml` to `audit.toml` and edit it. It is gitignored because
it names your domains. Everything in it is optional and every value can also be
given as a command-line flag; a flag beats the file. The ones worth setting on
day one:

- `domains`: leave empty to audit every verified domain in the tenant, or list
  them. `mailflow = true` adds every subdomain seen sending in the last 30 days.
- `known`: your vendors' IP prefixes and domains. The unknown-sender check in
  the aggregate reports runs only on the IP prefixes: with them, every source
  outside them and every DKIM signing domain that is neither yours nor listed
  is reported once it has volume. Domains alone only narrow the
  signing-domain list and inform the aggregate reports' heuristic labels, and
  the report says the per-IP check did not run.
- `vendor_domains`: your sending platforms' envelope domains, so the heuristic
  labels in the mail log and in the aggregate reports start informed. Like the
  domains in `known` they narrow the signing-domain list, but they never
  switch the unknown-sender check on. Domains only: an IP prefix here never
  matches anything (a run that reads aggregate reports warns about it); IP
  prefixes go in `known`.
- `rua_address`: the `mailto:` the plan writes into new DMARC records.
- `keep = 12`: how many dated runs stay under `audit-out/history/`.
- `[notify] enabled`: whether the Slack summary posts when a webhook is set.

Secrets never go in this file; they stay in `.env`.

## Step 3 - run it once

```
python src/collect.py                       # tenant domains, tenant data, everything
python src/collect.py --dry-run             # same, but print the Slack summary instead of posting it
python src/collect.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --auth-column DMARC

python src/dedupe.py samples/sample_maillog.csv --auth-column DMARC    # the deduplication alone, on the same samples
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

The third line runs entirely from the bundled synthetic samples with no
credentials and no network, which is the quickest way to see the outputs; the
block under it is `dedupe.py`'s own report on those samples, the
deduplication every run performs. A run verifies the registration, reads the domain list, pulls the raw mail log
for each organizational domain (sized by the hour and pulled in complete
windows, newest first, so a busy domain never comes back as a truncated day),
pulls new aggregate reports from the report mailbox, audits DNS, runs the
deduplication, writes the report, the status document, the to-do list and the
plan, appends the history and metrics, and prints or posts the summary.

Exit codes: 0 clean, 1 at least one major or blocking finding, 2 a usage or
setup error. A brand-new rollout will exit 1 for weeks; that is the findings
list, not a crash. `--strict` widens 1 to also cover a gate that is not "go",
a plan hold, or a tenant step that failed or was truncated, for schedulers
that alert on exit codes.

## Step 4 - read the results

Read them in this order, all under `audit-out/latest/`:

1. **`next_steps.md`**: the document you send. Where the rollout stands in
   one sentence, deduplicated failure counts with the raw number alongside,
   what is failing by envelope domain and by sender, a per-domain table
   (policy today, gate, next step), what happens next grouped by owner, the
   ask for the week, the open questions, and a glossary. Written by
   `src/next_steps.py` from the files below with no AI involved: every
   sentence is assembled from the run and every number is copied from it, so
   any tenant that runs the toolkit gets the same document from the same
   inputs. `next_steps.json` is the same content as data.
2. **`todo.md`**: one prioritised list. Decide the holds first, then the
   zero-risk DNS rows, then the senders to fix DKIM-first, then tenant
   configuration, then the gated enforcement steps with their prerequisites.
   Every line says which file holds the evidence.
3. **`report.md`**: the gate verdict per domain (`go`, `no_go`, or
   `insufficient_data` when a zero would only mean "no data"), each finding
   with its severity, evidence and action, the mail log attributed to each
   audited domain (its own rows, with its unaudited subdomains counted
   separately), and a "verified vs inferred" split so you always know what
   was measured and what was reasoned. `report.json` is the same as data and
   stays readable at scale: the per-message verdicts are dropped once the
   gate and the census have used them (`maillog.verdicts_omitted` says how
   many; `audit.py --keep-verdicts` keeps them), and the aggregate-report source
   tables keep their 1000 busiest rows with the totals in `rua.truncated` -
   the sender history still records every source.
4. **`plan.md`**: the rollout plan as a DNS change ticket wants it: record,
   hostname, value, TTL, current value and rollback, grouped by the DNS host
   of each zone. You apply the rows; the tool never touches DNS.

**Who owns what.** `next_steps.md` groups actions by owner, and the owners
come from `owners.csv` in the repo root: one row per sender address, domain
or glob, naming the team or person who fixes it and the channel to reach
them (`samples/owners.csv.example` shows the three pattern kinds). The file
is local and gitignored, and it is optional: without it the document is
still written, with every action under "Unassigned - needs an owner" and a
"who owns this" line in the open questions. Add a row, rerun, and the action
moves under its owner. `--owners PATH` points at another file, `--no-owners`
skips the lookup.

How the plan is gated (the methodology, encoded in `src/plan.py` and
`src/audit.py`):

- **Monitoring first.** Every domain and subdomain gets `p=none` with a `rua`
  address before anything else; parked domains get `v=spf1 -all` and
  `p=reject` once "unused" is verified.
- **One ratchet per domain per week**: `p=none` to `p=quarantine; pct=25`, to
  `pct=100`, to `p=reject`, then the subdomain policy `sp=`, then SPF `-all`.
  A step appears only when the earlier ones are done and a week of reports has
  flowed.
- **Deduplicated failure gate.** A legitimate sender still failing holds the
  next step and the hold says who. Spoofs that receivers already reject do not
  hold anything: enforcement is what stops them. Each domain is judged on its
  own rows: a domain with no rows anywhere is `insufficient_data`, never a
  silent go, and never inherits another domain's failures.
- **DKIM before reject, always.** The move to `p=reject` needs aligned-DKIM
  evidence from the aggregate reports or from a mail log carrying SPF and DKIM
  verdicts (`queries/raw_maillog.kql` writes them). Senders passing on SPF
  alone hold the move, because forwarding breaks SPF. With no DKIM evidence at
  all the verdict is `insufficient_data`, never "go".
- **Formal exceptions.** A failing sender you have explained and accepted can
  be excepted in `audit.toml` (`[[exceptions]]`: match, reason, owner, until,
  removal criterion). Entries missing a field are reported and ignored;
  expired ones block again.

## Step 5 - put it on a weekly schedule

Windows, from the repo folder in PowerShell:

```powershell
.\scripts\register_weekly_task.ps1                    # Monday 06:00, runs whether or not you are logged on
.\scripts\register_weekly_task.ps1 -Day Tuesday -Time 07:30
.\scripts\register_weekly_task.ps1 -Unregister
```

The task runs as you with no stored password (logon type S4U), so `.env` stays
readable only by your account. Test it right away with `Start-ScheduledTask
-TaskName 'dmarc-audit-toolkit weekly'` and read `audit-out\latest\next_steps.md`.

Linux or macOS, `crontab -e`:

```
0 6 * * 1 cd /path/to/dmarc-audit-toolkit && python3 src/collect.py >> audit-out/cron.log 2>&1
```

What accumulates, all local and gitignored (back the folder up; it is the only
copy): `audit-out/history/<run>/` for the last 12 runs, `metrics.json` and
`metrics.md` with one line per run from day one, `senders.json` with every
sender identity ever seen and when, `rua/` with every aggregate report ever
pulled. The hunting API only ever shows 30 days; the long view is this
folder. The first run reads the last 30 days of the report mailbox
(`fetch_rua.py --since` backfills older history once, if you want it; a long
backfill stops at `--max` and names the `--since` that continues it), and
every weekly run archives the new reports. By week six you are reading six
weeks of local history even though the API still only shows 30 days, and
`metrics.md` turns that into the trend line.

**Slack, off by default.** Set `SLACK_WEBHOOK_URL` in `.env` and each run posts
one message: policy and gate per domain, deduplicated failure counts next to
the raw ones, the worst failing senders from the census, spoofing blocked by
receivers, newly identified senders (new to the whole history, not just absent
last week), the week-over-week deltas, and the trend over the last four runs.
A delta is withheld, and the message says so, when two runs cannot bear the
comparison. Failure counts are not compared when the row budget (or an hour
at the API row cap) cut an organization's mail log in either run - the note
names the organization, the run and how many hours were kept, and every
domain under that organization is withheld with it - or when the two mail
logs' spans differ by half or more. The pass rate is not compared when the
outside views differ tenfold in size (a first full archive against a
near-empty one) or carry no messages. The trend word compares the first and
last runs: it follows the failure counts when they compare, else the pass
rate when the outside views compare, else it says "not comparable"; a short
clause names what was not compared and why.
Aggregates only: domains, counts and sender identities, never addresses or
subject lines. `[notify] enabled = false` in `audit.toml` pauses posting
without removing the webhook; `--dry-run` prints the message. Teams is
designed in but not yet verified against a live webhook.

## With AI or without AI

**Without AI** is the complete product. Everything above runs with Python and
the one dependency. No AI library is installed, no data leaves your machine
except the Slack message you opted into, and `AGENTS.md` is just a file.

**With AI**, when you want it. Set `AI_ANALYSIS_ENABLED=true` in `.env` (off by
default; the MCP server refuses to start without it and `AGENTS.md` tells
every agent to stop). Point Claude Code, Codex, Cursor or any agent that reads
`AGENTS.md` at the repo. That file is the rules the agent works under: read
`audit-out/latest/` first, deduplicate before believing any number, cite the
artifact for every claim, draft DNS diffs and exception entries for a human to
apply, never change DNS or tenant configuration, never handle credentials in
chat. The agent's job is the analysis and the drafting of fixes; the tools
above stay the data plane and you stay the only one who changes anything.

The status document is not an AI product. `src/next_steps.py` writes
`next_steps.md` from `report.json`, `plan.json`, `metrics.json` and
`owners.csv`, deterministically, with no model in the loop, and `collect.py`
does that on every run. An agent's job is to refine that document (sharpen the
hooks, reorder it for the audience, split it into the Slack post, the owner
messages and the tracker entries), never to produce it from a conversation.
Nothing in the document depends on what an agent remembers: any tenant that
runs the toolkit gets the same document from the same inputs, and `AGENTS.md`
rule 13 tells the agent to edit the generated copy rather than write its own.

Clients without shell access (Claude Desktop or any MCP client) use the bundled
MCP server; there is nothing to build or deploy, the client launches it:

```
pip install -r requirements-mcp.txt
claude mcp add dmarc-audit-toolkit -- python "C:\path\to\dmarc-audit-toolkit\src\mcp_server.py"
```

Give it the absolute path to your clone; the server confines its file reads
and CSV writes to that folder. It exposes `audit_dns`, `walk_spf`,
`dedupe_maillog`, `run_hunting_query`, `parse_rua`, `parse_headers` and
`run_audit`; the protocol surface is the permission boundary and no tool can
write anywhere but the local report files. The MCP dependency stays in its own
`requirements-mcp.txt`. See `docs/ai-assisted-workflow.md` for the human and
agent split that worked, and the failure modes to watch for.

## The individual tools

`collect.py` wraps every one of these; each still runs alone when you want one
answer.

| Path | What it does |
|---|---|
| `src/collect.py` | The weekly job and the one command: verify, discover, pull mail log and reports, audit, plan, status document, to-do, history, metrics, summary. Reads `audit.toml`. |
| `src/audit.py` | The engine: DNS posture, aggregate reports, deduplicated mail log and headers in one report with the gate verdict per domain, each judged on its own rows. Works `--offline` from files. |
| `src/next_steps.py` | `report.json` in, `next_steps.md` + `next_steps.json` out: the status document you send. One-line status, deduplicated counts with the raw number alongside, what is failing, a per-domain table, actions grouped by owner, the ask and the open questions. Reads `plan.json`, `metrics.json`, the previous run and `owners.csv` when they exist; deterministic, no AI. |
| `src/plan.py` | `report.json` in, `plan.md` out: the exact records to publish, with current value, rollback, priority and prerequisites. |
| `src/config.py` | Reads `audit.toml`: settings and the formal exceptions. Library only. |
| `src/discover.py` | Finds the domains: command line, file, the tenant, subdomains seen in mail flow; records each zone's DNS host. |
| `src/verify_setup.py` | Proves the app registration: token, roles (required, recommended, excess), domain list, a hunting query, the report mailbox, and that other mailboxes are denied. |
| `src/graph_client.py` | Shared Microsoft Graph helper. Library only. |
| `src/fetch_rua.py` | Pulls aggregate (rua) reports out of the report mailbox. The weekly job reads the last 30 days on a first run and only new reports after; run standalone it backfills the whole mailbox, up to `--max` messages per run, and `--since` starts anywhere. Attachments come back inline, about 20 per call. |
| `src/notify.py` | The Slack summary: policy and gate per domain, the worst failing senders, what changed since last run, newly identified senders, trend. |
| `src/dedupe.py` | Collapses mail-log rows into logical messages by (Message-ID, recipient); reports failed-but-delivered and passed-but-blocked separately; prints a census of the failing senders by envelope domain and by sender address; marks mail that stayed inside the tenant (a Direction column); with SPF and DKIM columns, buckets passing mail into DKIM-carried, SPF-and-DKIM and SPF-only. Dies loudly on a misspelled column instead of returning a silent zero. |
| `src/spf_lookups.py` | Expands an SPF record and counts lookups against the limit of ten; a failed lookup is never reported as "no record". |
| `src/dns_audit.py` | Multi-domain posture: SPF, DMARC with inheritance, DKIM selectors, MX, with evidence per lookup. |
| `src/rua_parse.py` | Aggregate report XML (plain, gz, zip) into answers: selectors in use, unknown senders, failing streams, SPF-only senders. |
| `src/headers.py` | Parses one live message header and calls SPF, DKIM and DMARC alignment explicitly: the proof behind "a toggle is not a working feature". |
| `src/audit_rules.ps1`, `src/audit_bypasses.ps1`, `src/audit_groups.ps1` | Read-only Exchange Online auditors: transport rules, filtering bypasses, groups and forwarding. App-only through `ToolkitExo.ps1` when configured. |
| `src/run_hunting.py` | Runs a saved KQL file by API and writes CSV. |
| `src/mcp_server.py` | The tools above for any MCP client. |
| `scripts/register_weekly_task.ps1` | Registers or removes the Windows scheduled task. |
| `scripts/check_public.py` | Pre-push gate: deny terms, typographic dashes, and credential material never leave the repo. |
| `queries/` | Eight advanced-hunting queries: deduplicated census and failures, subdomain health, override audit, echo-vs-loss twins, pre-reject DKIM alignment, impersonation, and the raw per-leg export that feeds `dedupe.py`. |
| `samples/` | Synthetic mail log, aggregate reports, annotated headers and `owners.csv.example`, so every tool can be tried offline. |
| `docs/` | The methodology, the app registration walkthrough, the AI workflow guide, and the shape of the generated status document (`docs/templates/next-steps.md`). |

## Safety

Everything here is read-only. Nothing modifies DNS, mail flow rules, or tenant
configuration. Credentials come from `.env`, are read by the scripts
themselves, and are never printed or written anywhere by any tool. Outputs
stay under `audit-out/`, which is gitignored along with `.env`, `audit.toml`,
`owners.csv`, `private/` and every key or certificate suffix;
`scripts/check_public.py` is the pre-push gate that fails when any of that
would leave the machine.

## Troubleshooting

- **401 or 403 from every call**: admin consent was not granted, or the
  permission is delegated instead of Application. `verify_setup.py` names the
  missing role.
- **`advanced hunting` fails with 403 although the role is present**: the
  tenant has no Defender for Office 365 plan; the endpoint answers 403
  regardless.
- **`report mailbox` fails**: `Mail.Read` is missing, consent is missing, or
  the Application Access Policy does not include the mailbox.
- **429**: rate limited; the run retries once and otherwise waits for next
  week. Narrow `days` in `audit.toml` if it recurs.
- **"is not UTF-8"**: PowerShell wrote `.env` or a query as UTF-16; re-save as
  UTF-8.
- **Every DNS lookup fails on port 53**: a corporate resolver is intercepting;
  the tools fall back to DNS-over-HTTPS and say so. Never diagnose a missing
  record from one resolver path.
- **`insufficient_data` at the reject step**: the run has no aligned-DKIM
  evidence. Set `RUA_MAILBOX` so reports flow, or pull the mail log through
  `collect.py` (it carries SPF and DKIM columns).
- **`insufficient_data` for a domain with no rows**: the evidence supplied has
  nothing about that domain (no mail-log rows, no aggregate-report rows with it
  as the From domain). A zero is not health: audit the subdomain that actually
  sends, or supply reports that cover it.
- **The mail-log notes say the row budget was reached**: a busy domain has more
  rows in 30 days than `--max-rows` keeps (250,000 by default); the run kept
  the newest complete hours and the note says exactly how far back they reach.
  Raise `--max-rows` to keep more.
- **"needs Python 3.11 or newer"**: the settings file is TOML; upgrade Python
  or pass everything as flags.
- **The delta or the trend says "not comparable"**: the row budget or the
  API row cap cut an organization's mail log in one of the two runs (the note
  names it; raise `--max-rows` if it is the budget), the two runs' mail logs
  cover very different spans, or one outside view is near-empty. The counts
  are still in the report; only the comparison is withheld, and it returns
  once two runs of a similar shape follow each other.
- **One of your own platforms shows as `unknown` in the aggregate reports**,
  with "SPF passes for ..., which looks like the forwarding hop": if the
  domains that signal names send for you, list every one of them among the
  vendors in `audit.toml` (`vendor_domains`, or `--known`). The stream
  relabels only once all of them are listed, and the hint under the signal
  names any still missing; then, as long as nothing in the reports marks
  forwarding, it reads as a broken DKIM key at your own sender.

## Methodology and background

`docs/methodology.md` is the order the questions get asked in, and the tool
for each step. `docs/app-registration.md` is the long form of Step 1, with the
certificate recipes for the optional PowerShell path. `docs/ai-assisted-workflow.md`
is how the AI split worked on the real rollout, including the four times it
was wrong and what caught it.

## Planned

Everything here was used on a real enforcement rollout before it was
published. Support for other platforms ships the same way: written, then
validated against a live tenant, then released.

- **Google Workspace**: the method ports (Gmail logs in BigQuery carry a
  Message-ID and per-row SPF/DKIM/DMARC verdicts, so deduplication works
  identically), and `dedupe.py`, `spf_lookups.py` and `dns_audit.py` are
  already platform-neutral. Query equivalents and a rules checklist land here
  once proven against a live tenant.
- **Teams notifications**: designed in behind the same switch as Slack; ships
  once verified against a live webhook.

## License

MIT.
