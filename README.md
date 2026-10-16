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
the ask), `brief.html` (the same document designed as one page, with the DNS
records to publish as cards: open it in a browser, present it, print it to
PDF), `report.md` (every finding, and a go / no-go gate per domain),
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
   added `Mail.Read`, otherwise leave it empty. `EXTRA_DOMAINS` (optional)
   adds domains the tenant does not hold; Step 2 says how. `.env` is
   gitignored; never commit it, paste it into a chat, or send it anywhere.
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
| `Domain.Read.All` | Microsoft Graph, Application | reads the tenant's verified domain list, so a run with no arguments audits everything you own | `collect.py`, `discover.py`, `audit.py` | `collect.py`: list the domains in `audit.toml`, on the command line or in `EXTRA_DOMAINS` (`.env`); `discover.py`: the command line or `EXTRA_DOMAINS`; `audit.py`: the command line or `--file` |
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

- `domains`: every domain the tenant lists is always audited when the app
  registration can read them; names listed here are audited beside them (and
  with no app registration, they are the list). Domains the tenant does not
  hold - a registrar-only domain, a brand on another mail platform - go in
  `.env` as `EXTRA_DOMAINS=brand.example, parked.example` (comma or space
  separated; an entry that is not a domain is noted and skipped).
  `collect.py` and `discover.py` read it with the credentials, so a run with
  `--offline` or `--no-graph` does not. The tenant's mail log only sees mail
  that touches the tenant, so for a domain hosted elsewhere the mail-flow
  measurement and the mail log say little and its aggregate reports carry
  the evidence: the plan never moves such a domain straight to quarantine on
  the tenant's zero alone. `mailflow = true` adds every subdomain seen
  sending in the last 30 days. Either way, every run that has the app
  registration measures each audited domain's own mail flow over the last
  30 days, the organizational domain included.
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
  matches anything (every run warns about it); IP prefixes go in `known`.
- `rua_address`: the run's report address, the `mailto:` the plan writes into
  new DMARC records and appends to an existing record's `rua` that lacks it
  (after the addresses already there, nothing else changed). One address,
  with or without a `!10m` size limit: a list goes into new records as given,
  is never appended, and the run says so. Without it, `collect.py` uses the
  report mailbox (`RUA_MAILBOX`); with neither, new records take the `rua`
  most existing records use and nothing is appended.
- `keep = 12`: how many dated runs stay under `audit-out/history/`.
- `[notify] enabled`: whether the Slack summary posts when a webhook is set.

Secrets never go in this file; they stay in `.env`.

## Step 3 - run it once

```
python src/collect.py                       # tenant domains, tenant data, everything
python src/collect.py --dry-run             # same, but print the Slack summary instead of posting it
python src/collect.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --auth-column DMARC --no-notify

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
credentials and no network (`--no-notify` keeps it that way: an `--offline`
run still posts the summary when `SLACK_WEBHOOK_URL` is set), which is the
quickest way to see the outputs; the
block under it is `dedupe.py`'s own report on those samples, the
deduplication every run performs. A run verifies the registration, reads the
domain list (the tenant's, plus `EXTRA_DOMAINS`), measures each audited
domain's mail flow with one aggregate query (what the tenant sent as it and
received with it as the From domain), pulls the raw mail log for each
organizational domain (sized by the hour and pulled in complete windows,
newest first, so a busy domain never comes back as a truncated day), counts
the whole window in advanced hunting for an organization whose rows the row
budget cut, pulls new aggregate reports from the report mailbox, audits DNS,
runs the deduplication, writes the report, the status document, the to-do
list and the plan, appends the history and metrics, and prints or posts the
summary.

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
   (policy today, gate, next step, and the mail flow the tenant measured -
   "sends: N out, M in", "nothing sent or received", or "not measured"), what
   happens next grouped by owner, the ask for the week, the open questions,
   and a glossary. Mail delivered despite failing names the override that let
   it in ("delivered because of an Exchange transport rule: find that rule
   ...") when the mail log recorded it. Written by
   `src/next_steps.py` from the files below with no AI involved: every
   sentence is assembled from the run and every number is copied from it, so
   any tenant that runs the toolkit gets the same document from the same
   inputs. `next_steps.json` is the same content as data.
2. **`todo.md`**: one prioritised list. Decide the holds first, then the
   priority-1 DNS rows (the zero-risk monitoring and hygiene rows, and a
   "quarantine now" row once its checks are confirmed), then the senders to
   fix DKIM-first, then tenant configuration, then the gated enforcement
   steps with their prerequisites.
   Every line says which file holds the evidence.
3. **`report.md`**: the gate verdict per domain (`go`, `no_go`, or
   `insufficient_data` when a zero would only mean "no data"), each finding
   with its severity, evidence and action, the mail log attributed to each
   audited domain (its own rows, with its unaudited subdomains counted
   separately), each domain's mail flow as the tenant measured it
   (`mailflow`; mail a third party sends as your domain straight to outside
   recipients never passes through the tenant, so only the aggregate reports
   show it), the override behind each message delivered despite failing when
   the mail log recorded one (`delivered_by` in the census,
   `delivered_despite_fail_by` in the counters; the mail log `collect.py`
   pulls carries the override columns), and for an organization
   whose rows the row budget or the API cap cut, its full-window totals counted in advanced
   hunting (`maillog.window_totals`) beside the floor the gate still uses -
   and a "verified vs inferred" split so you always know what
   was measured and what was reasoned. `report.json` is the same as data and
   stays readable at scale: the per-message verdicts are dropped once the
   gate and the census have used them (`maillog.verdicts_omitted` says how
   many; `audit.py --keep-verdicts` keeps them), and the aggregate-report source
   tables keep their 1000 busiest rows with the totals in `rua.truncated` -
   the sender history still records every source.
4. **`plan.md`**: the rollout plan as a DNS change ticket wants it: record,
   hostname, value, TTL, current value and rollback, grouped by the DNS host
   of each zone. You apply the rows; the tool never touches DNS.
5. **`verify.md`**: how to check every finding and every plan row yourself,
   without trusting the tool. Per domain: the DNS lookup (PowerShell's
   `Resolve-DnsName`, and `nslookup` on any system) with the answer the
   audit saw; the Advanced Hunting query to paste into your own Defender
   portal, saved under `queries/` next to it (a shipped query with only its
   `let sender_domain` line set), with the figure the report counted (for an
   organization the row budget or the API cap cut, the full-window figure collect.py
   counted, with the report's own as the floor beside it); the
   command that recounts the files the run read; the admin page and the
   read-only cmdlet behind each tenant finding; and for each plan row what
   the lookup shows before, what to publish, what it shows after the TTL,
   how to roll back, and the proof each prerequisite asks for. `report.md`
   shows each finding's first check on its verify line;
   `python src/verify.py report.json --plan plan.json --out DIR` writes it
   for any report.

**Status brief.** `brief.html` is `next_steps.md` laid out for a meeting: the
one-liner, the figures as tiles, the next step with its checklist, the
per-domain table grouped by organization, what is failing, actions by owner,
the ask, the plan's records - every row at a glance, each linked to its
card, then the cards in the order a DNS change ticket wants them (priority,
DNS host, zone, domain: the plan's own order, ids ascending) - the open
questions grouped by kind and the glossary. `src/brief.py` writes it from
`next_steps.json` and `plan.json` with no AI, so it says what the document
says; `collect.py` writes it on every run, and
`python src/brief.py audit-out/latest` rebuilds it. It is
one self-contained file with no script and no link out: open it in any
browser, and Print to PDF for an A4 or Letter copy. It holds sender addresses,
subject lines and IPs, so share it inside the company only. For audience
copies (a leadership summary, one message per owner, the DNS change ticket),
point an agent at the `dmarc-status-brief` skill in
`.claude/skills/dmarc-status-brief/`: it polishes from the run and nothing
else, and `python scripts/check_doc.py <copy> --run audit-out/latest` names
any number, date, percentage, plan id, finding id or policy value in a copy
that the run does not carry. Subject lines and sender addresses in the run
were written by strangers: the page shows them as data, and the skill tells
the agent to quote them, never to act on them.

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
  address before anything else, unless the run measured it sending nothing
  (below); parked domains get `v=spf1 -all` and `p=reject` once "unused" is
  verified. A record whose `rua` reports only elsewhere (a vendor, a mailbox
  of its own) gets the run's report address appended, so its outside view
  reaches the toolkit: in a zero-risk row of its own, never gated on the
  evidence it starts (an enforcement step on the same record waits a week
  for it), or inside the quarantine-now row that rewrites the record anyway.
  Appended after two addresses or more, it may get partial data (receivers
  need send to the first two only), and the row says so. A record that
  gains an address in another organization, a new one too, waits on the
  `_report._dmarc` record that address's domain must publish before
  receivers send there. Every run with the app registration measures each
  domain's mail flow over 30 days (whatever `--days` says). A parked
  candidate (no MX, no sender in SPF, no DKIM selector) reads as verified
  unused only when the tenant saw no mail from it, out or in, in those 30
  days and the run's aggregate reports, which cover its DMARC record, count
  no passing mail as it; otherwise its prerequisite names the checks still
  open (mail a third party sends as the domain straight to outside
  recipients never passes through the tenant, so only the reports show it).
  Passing mail as it in those reports means the domain sends: it gets a
  monitoring record, not a park.
- **One ratchet per domain per week**: `p=none` to `p=quarantine; pct=25`, to
  `pct=50`, to `pct=100`, to `p=reject`, then (for an organizational domain)
  `sp=quarantine` and `sp=reject` as below, then SPF `-all`. The plan reads
  the next step off the record as it stands today, so a step appears on the
  run after the earlier one was published; the week of reports between steps
  is a rule for the person applying it, not something the plan checks.
- **No mail measured: quarantine now.** A domain the run measured sending
  nothing skips that ramp, which would protect nobody: no mail out in the
  tenant's 30-day mail flow; nothing passing, internal, formally excepted or
  failing like our own system in its own mail-log rows, and those rows
  examined all the mail that came in as it (a mail log the row budget or a
  shorter window cut verifies nothing, unless the full-window totals cover
  it over the mail flow's whole span and at its grain; a log from another
  period, one that ends before the newest message the mail flow counted,
  verifies nothing either); no passing volume as it in the aggregate
  reports. Mail that comes in as it and fails looking like spoofing on a
  strong sign (a lure word phishing leans on in the subject - urgent,
  password, voicemail - never a billing word a vendor's own mail carries,
  such as invoice or payroll; in the reports, no signature and no SPF pass
  at all) is no reason to wait; mail the heuristic cannot call spoofing on
  such a sign - a failure called spoofing on its envelope or a billing word
  alone, report rows a vendor signing with its own domain would produce the
  same way - is named on the row as a check, never called spoofing, and a
  domain that sends carries the same check on each step of its ramp. A
  domain whose mail the tenant does not carry - one only `EXTRA_DOMAINS`
  (or a file, or the command line) names, or one whose SPF or DKIM points
  at another platform - needs aggregate reports that cover it; until then
  it gets the monitoring record or the ramp, and when the reports about
  its record span less than 30 days (each report's own dates: one mailbox
  serves many brands, so the whole mailbox's span says nothing about one
  record) the row says so and asks about senders rarer than that. The plan
  proposes its `p=quarantine` record (no `pct`; `sp=none` on any domain,
  so the names below it move only with the `sp=` step - where they inherit
  quarantine today, from a record at `p=quarantine` with a `pct` and no
  `sp=`, the ones that send get records of their own at that policy first,
  and the row waits for them) as a priority-1 row, "no mail measured:
  quarantine now", which is not one of the zero-risk rows: it waits until
  no sender that mails monthly or less often (statements, renewals) uses
  the domain, and until the checks it names are confirmed. An
  aggregate-report source a formal exception covers is set aside
  everywhere: it is not counted as a sender here, so this record will
  quarantine its mail at receivers. The row names each such source as a
  check (the business accepts that), so except a source by IP only once
  you accept that. `p=reject`
  follows after a week of reports still showing nothing passing, with no
  DKIM proof to wait for and the same checks carried over. The per-domain
  lines lead with it, and give the gate's verdict as the one for the weekly
  ramp it skips. The parked rule comes first where it applies; a failed MX
  lookup never parks a domain (the row is held until a lookup answers).
- **Subdomains: their own records first, then `sp=`.** With the apex at
  `p=quarantine` (pct 100) or `p=reject` and `sp=none`, the plan proposes
  `sp=quarantine` once every subdomain that sends or may send - outbound in
  the tenant's mail flow (the same query counts the unaudited names under
  your organizations), passing in the mail log or in the aggregate reports,
  failing in the mail log as our own system does, as an unclear sender or as
  a formally excepted one (a formally excepted aggregate-report source is
  set aside, not counted: the row names it as a check instead, since the
  step junks its mail), and an audited subdomain whose mail out was not
  measured - has a `_dmarc` record of its own. It proposes the missing
  monitoring records itself and holds the step, naming them, until they
  exist; with no aggregate report covering the apex's record it says what
  only those would show. The row also names the subdomains whose failing
  mail the run cannot call spoofing on a strong sign (a vendor sending as
  one of them unaligned fails the same way: such a name gets a record of
  its own first, and the step is held), the subdomains that mail less often
  than the run's evidence reaches back, and the span of the aggregate
  reports about this record it rests on (each report's own dates, a 1970
  date ignored; a week of them at least) - a reject row whose subdomains
  follow `p=` (no `sp=`, and none of them seen sending) carries the same
  check. A first record of its own keeps the reporting and alignment tags
  of the record the name inherits today (`rua`, `ruf`, `fo`, `adkim`,
  `aspf`), with the run's report address added. Only DNS says a subdomain
  has a record:
  `collect.py` looks up the `_dmarc` record of every unaudited one it sees
  sending (the busiest 50 a run); the policy an aggregate report says it saw
  proves nothing, since those reports can be months old. A name nobody
  looked up, or whose lookup failed (an audited one's too, DMARC-007), is
  named as not checked, and its record waits on a lookup: a second record
  would leave it with no policy at all. At quarantine the move to reject and
  the `sp=` step both rewrite the apex's record, so each row names the
  other: one a week. An apex at quarantine with no `sp=` moves to reject
  with `sp=quarantine` added when subdomains that send have no record of
  their own: they stay where the record has them today instead of following
  `p=` to reject, and move with a later `sp=` step. At `sp=quarantine` the
  step to `sp=reject` names the sending subdomains still without a record
  (their failing mail would bounce), proposes each one's record at
  `p=quarantine`, where `sp=` has it today, and holds until they exist.
- **Deduplicated failure gate.** A legitimate sender still failing holds the
  next step and the hold says who. Spoofs that receivers already reject do not
  hold anything: enforcement is what stops them. Each domain is judged on its
  own rows: a domain with no rows anywhere is `insufficient_data`, never a
  silent go, and never inherits another domain's failures.
- **DKIM before reject, always.** The move to `p=reject` needs aligned-DKIM
  evidence from the aggregate reports or from a mail log carrying SPF and DKIM
  verdicts (`queries/raw_maillog.kql` writes them). Senders passing on SPF
  alone hold the move, because forwarding breaks SPF. With no DKIM evidence at
  all the verdict is `insufficient_data`, never "go". (A domain the run
  measured sending nothing has no sender to prove: its reject row waits on a
  week of reports showing nothing passing instead.)
- **Formal exceptions.** A failing sender you have explained and accepted can
  be excepted in `audit.toml` (`[[exceptions]]`: match, reason, until and
  removal criterion are required, owner is optional). Entries missing a
  required field are reported and ignored; expired ones block again. Each
  match kind covers different evidence. An IP or an IP prefix covers
  aggregate-report streams by source IP, never a mail-log message (the log
  carries no source IP at the deduplicated grain). A From address covers
  mail-log messages with that address, forged copies included, never a
  stream. A domain covers mail-log messages whose envelope domain (MAIL FROM)
  is under it - forged envelopes too, since a spoofer can set any MAIL FROM,
  and every customer of a shared platform; when the log carries the SPF
  verdict the gate's note counts the excepted messages that failed SPF for
  that envelope, which a forged one does - and aggregate-report streams whose
  SPF and DKIM domains, other than your audited ones, are all under some
  domain exception: a vendor that signs with its own domain and sends through
  an ESP needs an exception for each domain, or one for its source IP, and
  the blocker says which domain is left uncovered. A shared relay that also
  carries other senders' mail is never lifted by one vendor's exception. An
  exception lifts failures; it never lifts the DKIM-before-reject hold on an
  SPF-only sender.

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
copy): `audit-out/history/<run>/` for the last 12 runs, `metrics.json` with
one entry per run from day one (`metrics.md` shows the last 12 as a table),
`senders.json` with every sender identity ever seen and when, `rua/` with
every aggregate report ever pulled. Each run folder, and its copy in
`latest/`, holds `report.md`, `report.json` (with `census.json` beside it
when the sender census is large: report.json then keeps the failing,
delivered and excepted census rows, every row of a name that is not an
audited domain with mail of its own, and the busiest clean rows of those
domains, so `plan.py` and `verify.py` read the same senders from it with or
without the side file; `next_steps.py` and `notify.py` read the side file
back whole), `plan.md`,
`plan.json`, `next_steps.md`, `next_steps.json`, `brief.html`, `todo.md`, `verify.md` and
`queries/`, `summary.txt`, `run.json`, `inventory.json`, `domains.txt`,
`setup.json` and `maillog.csv` - the raw per-recipient mail log the run
pulled, with recipient addresses and subject lines: personal data that stays
on this machine and is never handed to an AI tool. The hunting API only ever shows 30 days; the long view is this
folder. The first run reads the last 30 days of the report mailbox
(`fetch_rua.py --since` backfills older history once, if you want it; a long
backfill stops at `--max` and names the `--since` that continues it), and
every weekly run archives the new reports. By week six you are reading six
weeks of local history even though the API still only shows 30 days, and
`metrics.md` turns that into the trend line.

**Slack, off by default.** Set `SLACK_WEBHOOK_URL` in `.env` and each run posts
one message: policy and gate per domain, deduplicated failure counts next to
the raw ones (with the overrides that let failing mail in, when the mail log
recorded them), the worst failing senders from the census, spoofing blocked by
receivers, newly identified senders (new to the whole history, not just absent
last week), the week-over-week deltas, and the trend over the last four runs.
A domain under an organization whose rows the row budget or the API cap cut shows its count
from the rows kept as the floor it is, with its full-window totals counted in
advanced hunting beside it.
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
default; an environment variable of the same name overrides `.env`; the MCP
server refuses to start without it and `AGENTS.md` tells every agent to stop;
`python .claude/skills/dmarc-status-brief/ai_switch.py` prints `on` or `off`
and nothing of what `.env` holds). Point Claude Code, Codex, Cursor or any
agent that reads `AGENTS.md` at the repo. That file is the rules the agent works under: read
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
| `src/brief.py` | `next_steps.json` and `plan.json` in, `brief.html` out: the status document designed as one self-contained page, with the plan's records as cards. Same content, every list in one domain order, no script, no AI; `--fragment` writes the title, style and body only. |
| `src/plan.py` | `report.json` in, `plan.md` out: the exact records to publish, with current value, rollback, priority and prerequisites. |
| `src/config.py` | Reads `audit.toml`: settings and the formal exceptions. Library only. |
| `src/discover.py` | Finds the domains: command line, file, the tenant, `EXTRA_DOMAINS` from `.env` (domains the tenant does not hold), subdomains seen in mail flow; records each zone's DNS host; with `collect.py`'s token, measures every domain's own mail flow in one aggregate query. |
| `src/verify_setup.py` | Proves the app registration: token, roles (required, recommended, excess), domain list, a hunting query, the report mailbox, and that other mailboxes are denied. |
| `src/graph_client.py` | Shared Microsoft Graph helper. Library only. |
| `src/fetch_rua.py` | Pulls aggregate (rua) reports out of the report mailbox. The weekly job reads the last 30 days on a first run and only new reports after; run standalone it backfills the whole mailbox, up to `--max` messages per run, and `--since` starts anywhere. Attachments come back inline, about 20 per call. |
| `src/notify.py` | The Slack summary: policy and gate per domain, the worst failing senders, what changed since last run, newly identified senders, trend. |
| `src/dedupe.py` | Collapses mail-log rows into logical messages by (Message-ID, recipient); reports failed-but-delivered and passed-but-blocked separately, naming the override that let each failure in when the export carries the override columns; prints a census of the failing senders by envelope domain and by sender address; marks mail that stayed inside the tenant (a Direction column); with SPF and DKIM columns, buckets passing mail into DKIM-carried, SPF-and-DKIM and SPF-only. Dies loudly on a misspelled column instead of returning a silent zero. |
| `src/spf_lookups.py` | Expands an SPF record and counts lookups against the limit of ten; a failed lookup is never reported as "no record". |
| `src/dns_audit.py` | Multi-domain posture: SPF, DMARC with inheritance, DKIM selectors, MX, with evidence per lookup. |
| `src/rua_parse.py` | Aggregate report XML (plain, gz, zip) into answers: selectors in use, unknown senders, failing streams, SPF-only senders. |
| `src/headers.py` | Parses one live message header and calls SPF, DKIM and DMARC alignment explicitly: the proof behind "a toggle is not a working feature". |
| `src/audit_rules.ps1`, `src/audit_bypasses.ps1`, `src/audit_groups.ps1` | Read-only Exchange Online auditors: transport rules, filtering bypasses, groups and forwarding. App-only through `ToolkitExo.ps1` when configured. |
| `src/run_hunting.py` | Runs a saved KQL file by API and writes CSV. |
| `src/mcp_server.py` | The tools above for any MCP client. |
| `scripts/register_weekly_task.ps1` | Registers or removes the Windows scheduled task. |
| `scripts/check_public.py` | Pre-push gate: deny terms, typographic dashes, and credential material never leave the repo. |
| `scripts/check_doc.py` | Checks a polished copy of the status document against its run: every number, date, percentage, plan id, finding id and `p=` / `sp=` / `pct=` value must be in the run's files, and the punctuation must follow the voice rules. One line per problem, never the copy's content. |
| `.claude/skills/dmarc-status-brief/` | The agent skill that finds the run, renders `brief.html`, and on request polishes the leadership summary, the owner messages and the DNS change ticket, each checked with `check_doc.py`. |
| `queries/` | Nine advanced-hunting queries: deduplicated census and failures, subdomain health, override audit, echo-vs-loss twins, pre-reject DKIM alignment, impersonation, the raw per-leg export that feeds `dedupe.py` (with the override each leg recorded), and the full-window totals `collect.py` counts for an organization its row budget or the API cap cut. |
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
  The run then counts that organization's whole window in advanced hunting
  itself (`queries/maillog_totals.kql`, the same deduplicated grain) and
  reports it beside the floor (`maillog.window_totals`, report.md's
  "Full-window totals for cut organizations", the genuine-failure line of
  `next_steps.md`); the gate, the census and the labels still use the rows
  kept, while the plan reads these totals for that organization's
  quarantine-now decision and its list of sending subdomains. An answer that
  holds no mail for that organization, or
  counts less than the rows kept, cannot be its whole window: the run sets
  it aside with a note (a degraded step) and shows the floor alone. Raise
  `--max-rows` to keep more.
- **"needs Python 3.11 or newer"**: the settings file is TOML; upgrade Python
  or pass everything as flags.
- **The delta or the trend says "not comparable"**: the row budget or the
  API row cap cut an organization's mail log in either run (the note names
  the run and the cause; raise `--max-rows` if it is the budget), the two
  runs' mail logs cover very different spans, an organization was audited in
  one run only, or one outside view is near-empty. The counts are still in
  the report; only the comparison is withheld. The delta returns once two
  consecutive runs are not cut - with a budget that cuts every run it never
  does until `--max-rows` is raised - and the Slack trend, which compares the
  first and last of the last four runs, once the cut run has left that
  window.
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
