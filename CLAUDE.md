# CLAUDE.md - agent instructions for DMARC auditing with this toolkit

You are assisting a DMARC enforcement project. This file is the contract for
how you work. It was written from a real rollout, and every rule below exists
because skipping it produced a wrong conclusion at least once.

## Ground rules

1. **Read-only by default.** Every tool in this repo is read-only. You may run
   them freely. You may NOT change DNS records, mail flow rules, tenant
   configuration, or vendor settings without the human explicitly approving
   the specific change. Draft the change, show it, wait.
2. **Never handle credentials in chat.** Secrets live in `.env` (gitignored).
   If a tool needs a credential that is missing, name the variable and stop.
   Never echo, log, or commit a secret.
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

## What to hand back to the human

- Deduplicated numbers with the naive number alongside, so they see the gap
- Draft DNS changes as diffs with a rollback line and TTL noted
- Draft tickets and vendor messages; the human sends them
- A clear "verified" vs "assumed" split in every status summary

## Domain placeholders

Replace before use:

- `YOUR_DOMAIN` - the apex domain under enforcement
- `YOUR_TENANT_QUERY_TOOL` - where the hunting queries run (Defender
  Advanced Hunting for Microsoft 365, Gmail logs in BigQuery for Google
  Workspace - see `docs/google-workspace.md`)
- `YOUR_AGGREGATE_REPORTING` - Valimail, dmarcian, or raw rua parsing
