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

You get, under `audit-out/latest/`: `report.md` (every finding, and a go /
no-go gate per domain), `todo.md` (one prioritised list, top to bottom),
`plan.md` (the exact DNS records to publish next, with rollback), plus a
dated history and running metrics. Put it on a weekly schedule and it posts a
short Slack summary when you ask it to. Everything is read-only: nothing here
changes DNS, mail flow rules or tenant configuration, ever. AI is optional and
off by default. On macOS and Linux use `cp` for the two copy lines.

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
- `known` and `vendor_domains`: your vendors' domains and IP prefixes, so the
  unknown-sender check and the heuristic labels start informed.
- `rua_address`: the `mailto:` the plan writes into new DMARC records.
- `keep = 12`: how many dated runs stay under `audit-out/history/`.
- `[notify] enabled`: whether the Slack summary posts when a webhook is set.

Secrets never go in this file; they stay in `.env`.

## Step 3 - run it once

```
python src/collect.py                       # tenant domains, tenant data, everything
python src/collect.py --dry-run             # same, but print the Slack summary instead of posting it
python src/collect.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --auth-column DMARC

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
credentials and no network, which is the quickest way to see the outputs. A
run verifies the registration, reads the domain list, pulls the raw mail log
for each domain (splitting the window when a call hits the API's 100,000-row
cap, then deduplicating across the slices), pulls new aggregate reports from
the report mailbox, audits DNS, runs the deduplication, writes the report, the
to-do list and the plan, appends the history and metrics, and prints or posts
the summary.

Exit codes: 0 clean, 1 at least one major or blocking finding, 2 a usage or
setup error. A brand-new rollout will exit 1 for weeks; that is the findings
list, not a crash. `--strict` widens 1 to also cover a gate that is not "go",
a plan hold, or a tenant step that failed or was truncated, for schedulers
that alert on exit codes.

## Step 4 - read the results

Read them in this order, all under `audit-out/latest/`:

1. **`todo.md`**: one prioritised list. Decide the holds first, then the
   zero-risk DNS rows, then the senders to fix DKIM-first, then tenant
   configuration, then the gated enforcement steps with their prerequisites.
   Every line says which file holds the evidence.
2. **`report.md`**: the gate verdict per domain (`go`, `no_go`, or
   `insufficient_data` when a zero would only mean "no data"), each finding
   with its severity, evidence and action, and a "verified vs inferred" split
   so you always know what was measured and what was reasoned.
3. **`plan.md`**: the rollout plan as a DNS change ticket wants it: record,
   hostname, value, TTL, current value and rollback, grouped by the DNS host
   of each zone. You apply the rows; the tool never touches DNS.

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
  hold anything: enforcement is what stops them.
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
-TaskName 'dmarc-audit-toolkit weekly'` and read `audit-out\latest\todo.md`.

Linux or macOS, `crontab -e`:

```
0 6 * * 1 cd /path/to/dmarc-audit-toolkit && python3 src/collect.py >> audit-out/cron.log 2>&1
```

What accumulates, all local and gitignored (back the folder up; it is the only
copy): `audit-out/history/<run>/` for the last 12 runs, `metrics.json` and
`metrics.md` with one line per run from day one, `senders.json` with every
sender identity ever seen and when, `rua/` with every aggregate report ever
pulled. The hunting API only ever shows 30 days; the long view is this
folder.

**Slack, off by default.** Set `SLACK_WEBHOOK_URL` in `.env` and each run posts
one message: policy and gate per domain, deduplicated failure counts next to
the raw ones, spoofing blocked by receivers, newly identified senders (new to
the whole history, not just absent last week), the week-over-week deltas, and
the trend over the last four runs. Aggregates only: domains, counts and sender
identities, never addresses or subject lines. `[notify] enabled = false` in
`audit.toml` pauses posting without removing the webhook; `--dry-run` prints
the message. Teams is designed in but not yet verified against a live webhook.

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

Clients without shell access (Claude Desktop or any MCP client) use the bundled
MCP server; there is nothing to build or deploy, the client launches it:

```
pip install -r requirements-mcp.txt
claude mcp add dmarc-audit-toolkit -- python "C:\path\to\dmarc-audit-toolkit\src\mcp_server.py"
```

Give it the absolute path to your clone. The server exposes `audit_dns`,
`walk_spf`, `dedupe_maillog`, `run_hunting_query`, `parse_rua`,
`parse_headers` and `run_audit`; the protocol surface is the permission
boundary and no tool can write anywhere but the local report files. The MCP
dependency stays in its own `requirements-mcp.txt`. See
`docs/ai-assisted-workflow.md` for the human and agent split that worked, and
the failure modes to watch for.

## The individual tools

`collect.py` wraps every one of these; each still runs alone when you want one
answer.

| Path | What it does |
|---|---|
| `src/collect.py` | The weekly job and the one command: verify, discover, pull mail log and reports, audit, plan, to-do, history, metrics, summary. Reads `audit.toml`. |
| `src/audit.py` | The engine: DNS posture, aggregate reports, deduplicated mail log and headers in one report with the gate verdict per domain. Works `--offline` from files. |
| `src/plan.py` | `report.json` in, `plan.md` out: the exact records to publish, with current value, rollback, priority and prerequisites. |
| `src/config.py` | Reads `audit.toml`: settings and the formal exceptions. Library only. |
| `src/discover.py` | Finds the domains: command line, file, the tenant, subdomains seen in mail flow; records each zone's DNS host. |
| `src/verify_setup.py` | Proves the app registration: token, roles (required, recommended, excess), domain list, a hunting query, the report mailbox, and that other mailboxes are denied. |
| `src/graph_client.py` | Shared Microsoft Graph helper. Library only. |
| `src/fetch_rua.py` | Pulls aggregate reports out of the report mailbox, one-time backfill then deltas. |
| `src/notify.py` | The Slack summary: what changed since last run, newly identified senders, trend. |
| `src/dedupe.py` | Collapses mail-log rows into logical messages by (Message-ID, recipient); reports failed-but-delivered and passed-but-blocked separately; with SPF and DKIM columns, buckets passing mail into DKIM-carried, SPF-and-DKIM and SPF-only. |
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
| `samples/` | Synthetic mail log, aggregate reports and annotated headers, so every tool can be tried offline. |
| `docs/` | The methodology, the app registration walkthrough, and the AI workflow guide. |

## Safety

Everything here is read-only. Nothing modifies DNS, mail flow rules, or tenant
configuration. Credentials come from `.env`, are read by the scripts
themselves, and are never printed or written anywhere by any tool. Outputs
stay under `audit-out/`, which is gitignored along with `.env`, `audit.toml`,
`private/` and every key or certificate suffix; `scripts/check_public.py` is
the pre-push gate that fails when any of that would leave the machine.

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
- **"needs Python 3.11 or newer"**: the settings file is TOML; upgrade Python
  or pass everything as flags.

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
