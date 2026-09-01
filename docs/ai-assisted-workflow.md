# Running a DMARC project with an AI agent

This toolkit was built during a rollout where an AI coding agent did the
query-writing, log analysis, ticket drafting, and DNS diff preparation, while
a human made every change. That split worked. This guide is how to reproduce
it, including the failure modes we hit.

## What the agent is good at

- Writing and iterating hunting queries, then interpreting results
- Deduplication analysis - the echo problem is exactly the kind of systematic
  error agents catch well once instructed (see CLAUDE.md rule 4)
- Fingerprinting senders from VERP addresses, headers, and reverse DNS
- Drafting tickets, PR bodies, vendor emails, and status updates in your house
  format
- Keeping the running state of a 30-sender remediation across weeks
- Building the change history afterward from merged PRs

## What stays human

- Merging any DNS change. The agent drafts the diff; you merge it
- Deleting anything. Records, rules, keys - the agent proposes with evidence;
  you act
- Sending external messages. Vendor emails and public posts get reviewed
- Credentials. The agent never sees them in chat; they live in env files
- Final go or no-go on every enforcement step

## Failure modes we hit, so you can watch for them

1. **The agent declared an outage twice from quarantine rows that were relay
   echoes.** Both times the mail had delivered seconds earlier on another leg.
   Fix: the dedupe rule is now rule 4 in CLAUDE.md, and the human asking
   "are you sure it is not forwarding or this dedupe thing?" is what caught it.
2. **The agent diagnosed a broken DNS zone from its own filtered network
   path.** Every resolver returned SERVFAIL from the agent machine; the zone
   was fine. Fix: DNS-over-HTTPS cross-check, now built into the tools.
3. **The agent overstated confidence about what a legacy DKIM record was.**
   "Almost certainly dormant" drifted toward "safe to delete" until aggregate
   reports showed something actively signing as that domain. Fix: usage over
   origin, rule 8.
4. **Sanitization is a process, not a promise.** Before anything went public
   we grepped for every company identifier the project ever touched. The one
   hit was the license line, which was intentional. Automate the deny-list.

The pattern in all four: the agent is fast and mostly right, and the human
challenging its conclusions is a load-bearing part of the system. Treat agent
confidence as a claim to verify, not a fact - the same way this toolkit treats
dashboard numbers.

## Setup

Point your agent at this repo and tell it to read `CLAUDE.md` first (Claude
Code and compatible agents load it automatically). Agents without shell
access connect through the bundled MCP server instead - see the README's
AI-agent section; it is one registration command, not something each user
builds. Fill in the placeholders.
Set up the read-only app registration (`docs/app-registration.md`) and put
its credentials in `.env`, kept out of the repo: the agent then pulls fresh
query results through `src/run_hunting.py` without the secret ever entering
the conversation. Keep write access to DNS and tenant config behind your own
hands.
