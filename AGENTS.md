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
   passed.
5. **A quarantined row is not a lost email** until you confirm there is no
   delivered leg with the same Message-ID. Check the message trace before
   declaring an outage.
6. **"Blocked" and "failed DMARC" are different questions.** Check both the
   authentication verdict and the delivery action, plus any local override.
   Local allow rules mask failures that external receivers still see.
7. **Do not diagnose DNS from one resolver path.** Port 53 interception
   produces SERVFAILs that look identical to a broken zone. The tools here
   fall back to DNS-over-HTTPS; if you query manually, cross-check the same
   way before reporting a record missing.
8. **Origin does not decide whether a record is safe to remove - usage does.**
   Before deleting any DKIM key, verify from live message headers or aggregate
   reports that nothing signs with it. "The vendor does not recognize it" is
   not proof.
9. **A dashboard toggle is not a working feature.** "DKIM enabled" means
   configuration exists. Only a live message header showing the expected
   signature proves signing.
10. **State your confidence.** Separate what you verified from what you
    inferred, and say which is which. If the human challenges a claim,
    re-verify instead of defending it.

## The working sequence

Follow `docs/methodology.md`. In short: reporting on before anything changes,
then sender inventory, then deduplicated failure analysis, then fix senders
(DKIM preferred - check the SPF lookup budget with `src/spf_lookups.py`
before adding any include), then ratchet policy with a deduplicated gate check
at every step, then DKIM-before-reject, always.

## Analyzing pulled exports

The data plane is `src/run_hunting.py` (setup: `docs/app-registration.md`).
First run for a tenant: prove the plumbing with the validation step in that
doc before trusting any number the API returns.

Each shipped query writes a CSV whose columns come straight from the KQL:

| Query | Columns | What it answers |
|---|---|---|
| `queries/sender_census.kql` | `env`, `total`, `passing`, `genuine_failures` | Every envelope (MailFrom) domain sending as yours, with pass/fail split. The sender inventory - your remediation list. |
| `queries/genuine_failures.kql` | `env`, `addr`, `genuine_failures` | Deduplicated failures by envelope domain and From address. The triage list. Already deduplicated; never re-count rows. |
| `queries/subdomain_health.kql` | `fromdom`, `total`, `genuine_failures` | Per-subdomain failure rates. A subdomain near 100% failure is usually inbound spoofing of an unprotected domain, not a broken sender. |
| `queries/delivered_despite_failure.kql` | `SenderFromDomain`, `msgs`, `recipients`, `org_action` | Mail that failed DMARC and was delivered anyway - your local overrides. External receivers do not forgive these. |

PII: the shipped queries return aggregates (counts by sender), not people.
Custom `EmailEvents` queries can return recipient addresses and subject lines -
treat those as personal data. Keep exports local (`exports/` is gitignored)
and share only aggregates with any cloud tool.

Starter tasks, in order:

1. **Sender inventory** - from the census CSV, rank envelope domains by
   `genuine_failures`; everything with real volume is a system to fix before
   enforcement.
2. **Failure triage** - group the failures CSV by `env`, identify the owning
   vendor or platform per group, and draft a DKIM-first fix for each (run
   `src/spf_lookups.py` before proposing any SPF include).
3. **Override audit** - from the delivered-despite-failure CSV, list the
   domains that only look healthy because of local allows; those fail at
   external receivers today.
4. **Gate check** - before any policy ratchet, rerun the failures query at
   `--timespan P7D`; whatever is still failing must be explained, fixed, or
   formally excepted before `p=` moves.

## What to hand back to the human

- Deduplicated numbers with the naive number alongside, so they see the gap
- Draft DNS changes as diffs with a rollback line and TTL noted
- Draft tickets and vendor messages; the human sends them
- A clear "verified" vs "assumed" split in every status summary

## Domain placeholders

Replace before use:

- `YOUR_DOMAIN` - the apex domain under enforcement
- `YOUR_TENANT_QUERY_TOOL` - where the KQL runs (Defender Advanced Hunting)
- `YOUR_AGGREGATE_REPORTING` - Valimail, dmarcian, or raw rua parsing
