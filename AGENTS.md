# AGENTS.md - agent instructions for DMARC auditing with this toolkit

You are assisting a DMARC enforcement project. This file is the contract for
how you work, whatever agent you are. It was written from a real rollout, and
every rule below exists because skipping it produced a wrong conclusion at
least once. (`CLAUDE.md` points here; keep the two in sync by editing THIS
file only.)

## Ground rules

1. **Read-only by default.** Every tool in this repo is read-only. You may run
   them freely. You may NOT change DNS records, mail flow rules, tenant
   configuration, or vendor settings without the human explicitly approving
   the specific change. Draft the change, show it, wait.
2. **Never handle credentials in chat.** Secrets live in `.env` (gitignored).
   Pull tenant data with `src/run_hunting.py`, which reads them itself; never
   hand-build an auth flow or paste a token into the conversation. If a
   credential is missing, name the variable and stop. Never echo, log, or
   commit a secret.
3. **Redact before anything leaves the machine.** Company domains, employee
   names, IPs, account numbers and ticket IDs stay out of anything published,
   pasted externally, or committed to a public repo. Grep before you push.

## Verification habits (the ones that prevent wrong conclusions)

4. **Never report a failure count from raw rows.** One email produces multiple
   log legs; relayed legs fail authentication even when the original passed.
   Run `src/dedupe.py` or the deduplicated query in
   `queries/genuine_failures.kql` first. A message is failing only if NO copy
   passed. The dedupe grain is (Message-ID, recipient); every query in this
   repo groups at that grain.
5. **A quarantined row is not a lost email** until you confirm there is no
   delivered leg with the same Message-ID for the same recipient.
   `queries/delivered_twin.kql` pairs each lost-looking row with its delivered
   twin and labels it echo or true loss. Check before declaring an outage.
6. **"Blocked" and "failed DMARC" are different questions.** Check both the
   authentication verdict and the delivery action, plus any local override.
   `src/dedupe.py` reports the two crossings separately (failed but delivered,
   passed but blocked); `queries/delivered_despite_failure.kql` names the
   override that let failing mail through. Local allow rules mask failures
   that external receivers still see.
7. **Do not diagnose DNS from one resolver path.** Port 53 interception
   produces SERVFAILs that look identical to a broken zone. `src/dns_audit.py`
   and `src/spf_lookups.py` fall back to DNS-over-HTTPS and report lookup
   errors as errors, not as missing records. If you query manually,
   cross-check the same way before reporting a record missing.
8. **Origin does not decide whether a record is safe to remove - usage does.**
   Before deleting any DKIM key, verify from live message headers or aggregate
   reports that nothing signs with it: `src/rua_parse.py --retiring-selector`
   lists selectors still in use across your rua data. "The vendor does not
   recognize it" is not proof.
9. **A dashboard toggle is not a working feature.** "DKIM enabled" means
   configuration exists. Only a live message header showing the expected
   signature proves signing - `src/headers.py` parses one and calls alignment
   explicitly. Confirm one header per sender before counting it safe.
10. **DMARC does not stop display-name impersonation.** An attacker sending
    from their own domain passes their own authentication perfectly while
    putting your executive's name in the From header. After enforcement, run
    `queries/impersonation.kql` to see what is left, and pair enforcement
    with impersonation protection and out-of-band verification for payment
    changes.
11. **State your confidence.** Separate what you verified from what you
    inferred, and say which is which. If the human challenges a claim,
    re-verify instead of defending it.
12. **Answer from pulled data, not memory.** Every claim about a domain's
    posture, usage, or ownership cites the artifact it came from and when
    that artifact was pulled. If no fresh artifact exists, run the pull -
    every tool here is read-only - or say the data is unavailable. A partial
    export is not a population: a domain missing from one system's list
    (accepted domains, one CSV, one portal view) is not missing from the
    world. Build domain and sender inventories from the aggregate-reporting
    account and DNS, cross-checked against the mail system - never from one
    source alone.

## The working sequence

`src/collect.py` runs the whole sweep and writes `report.md`, `plan.md`, the
history and the summary; read `latest/report.json` and `latest/plan.json`
before anything else, and `verify_setup.py` output when a tenant step is
missing. Then follow `docs/methodology.md`. In short: reporting on before anything changes,
then sender inventory, then deduplicated failure analysis, then fix senders
(DKIM preferred - check the SPF lookup budget with `src/spf_lookups.py`
before adding any include), then ratchet policy with a deduplicated gate check
at every step, then DKIM-before-reject, always. `src/audit.py` runs the whole
sweep and ends with the gate verdict; the individual tools are for digging
into one question at a time.

## Analyzing pulled exports

**Check the AI switch before anything else.** If `.env` does not contain
`AI_ANALYSIS_ENABLED=true`, the human has not opted in to AI analysis: name
the setting, stop, and let them flip it deliberately. Do not work around it,
and do not set it yourself.

The data plane is `src/run_hunting.py` (setup: `docs/app-registration.md`).
First run for a tenant: prove the plumbing with the validation step in that
doc before trusting any number the API returns.

Point the queries at your domain by editing the `let sender_domain` line at
the top of each `.kql` file; the runner warns if `example.com` is still in
there. Keep domain-edited copies in `queries/live/` (gitignored) so the
shipped templates stay pristine.

Each query writes a CSV whose columns come straight from the KQL:

| Query | Key columns | What it answers |
|---|---|---|
| `queries/sender_census.kql` | `env`, `total`, `passing`, `genuine_failures` | Every envelope (MailFrom) domain sending as yours, deduplicated. The sender inventory - your remediation list. |
| `queries/genuine_failures.kql` | `env`, `addr`, `genuine_failures` | Deduplicated failures by envelope domain and From address. The triage list. Already deduplicated; never re-count rows. |
| `queries/subdomain_health.kql` | `fromdom`, `total`, `genuine_failures` | Per-subdomain failure rates. A subdomain near 100% failure is usually inbound spoofing of an unprotected domain, not a broken sender. |
| `queries/delivered_despite_failure.kql` | `env`, `org_action`, `org_policy`, `user_action`, `compauth`, `msgs` | Failing mail that was delivered anyway, grouped by WHAT let it through. Your local overrides, named. External receivers do not forgive these. |
| `queries/raw_maillog.kql` | dedupe.py's default export columns plus `DMARC`/`SPF`/`DKIM` | Per-leg rows for one domain. Pipe straight into `src/dedupe.py` with no column flags - this is the API-to-dedupe pipeline. |
| `queries/delivered_twin.kql` | `lost_*`, `twin_*`, `gap_seconds`, `verdict` | Rule 5 as a query: which "lost" rows have a delivered twin (echoes) and which are true losses. |
| `queries/dkim_alignment.kql` | `dkim_aligned`, `spf_only`, `spf_and_dkim` per sender | Who survives forwarding and who breaks at `p=reject`. Run before any reject move. |
| `queries/impersonation.kql` | `display_name`, `from_domain`, `msgs`, `recipients` | External senders using your people's display names. What DMARC cannot stop (rule 10). |

PII: the aggregate queries return counts by sender, not people.
`raw_maillog.kql` and custom `EmailEvents` queries return recipient addresses
and subject lines - treat those as personal data. Keep exports local
(`exports/` and `queries/live/` are gitignored) and share only aggregates
with any cloud tool.

Starter tasks, in order:

1. **Sender inventory** - from the census CSV, rank envelope domains by
   `genuine_failures`; everything with real volume is a system to fix before
   enforcement.
2. **Failure triage** - group the failures CSV by `env`, identify the owning
   vendor or platform per group, and draft a DKIM-first fix for each (run
   `src/spf_lookups.py` before proposing any SPF include).
3. **Override audit** - from the delivered-despite-failure CSV, list which
   policies and rules are propping up failing senders; those senders fail at
   external receivers today.
4. **Gate check** - before any policy ratchet, rerun the failures query at
   `--timespan P7D` and the DKIM-alignment query before any move to reject;
   whatever is still failing must be explained, fixed, or formally excepted
   before `p=` moves. `src/audit.py` automates this verdict.

## What to hand back to the human

- Deduplicated numbers with the naive number alongside, so they see the gap
- Draft DNS changes as diffs with a rollback line and TTL noted
- Draft tickets and vendor messages; the human sends them
- A clear "verified" vs "assumed" split in every status summary
