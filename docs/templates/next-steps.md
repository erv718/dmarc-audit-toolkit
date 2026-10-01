# The next-steps document: its generated shape, and how to polish it

`src/next_steps.py` writes this document. Nobody fills it in by hand and no
AI writes it: every `collect.py` run produces `audit-out/latest/next_steps.md`
(and `next_steps.json`, the same content as data) from `report.json`, plus
`plan.json`, `metrics.json`, the previous run's `report.json` and
`owners.csv` when they exist. Every number is copied from those files,
deduplicated (rule 4), and the same inputs always give the same document, so
anyone who runs the toolkit against their own tenant gets it without any
private context. On demand, for any run:

```bash
python src/next_steps.py audit-out/latest/report.json --plan audit-out/latest/plan.json --metrics audit-out/metrics.json --out audit-out/latest
python src/next_steps.py audit-out/latest/report.json --owners owners.csv     # no --out: print it
```

This page describes the shape the generator writes, what each section is
built from, and what a person or an agent may change before sending it.

## The shape, section by section

| Section | What it says | Built from |
|---|---|---|
| Title | `DMARC rollout - status and next steps, <date>` | the report's generation date (`--date` overrides it) |
| Audience line | who it is for, the sources with their sizes, and the statement that no sentence was written by an AI | `inputs`, the plan, the metrics history, the owners file |
| The one-liner (bold) | policy today (and since when, if the history shows the change), how many of our own streams still fail and how many look like spoofing, the next safe step and what it is ready when | `gate`, `dns`, `maillog.census`, the plan's next enforcement step and its prerequisites |
| Where we stand | genuine failures with the raw count alongside; delivered despite failing; spoofing blocked by receivers; trend versus the previous run | `maillog.counters`, `rua.by_disposition`, `delta` (else `--previous`, else `metrics.json`) |
| What is failing | the top failing envelope domains and sender addresses, each with its heuristic label; senders outside the audited domains; the outside view from aggregate reports | `maillog.census`, `maillog.by_domain`, `rua.failing_streams` |
| Per domain | one row per audited domain: policy today, gate, next step | `gate.domains`, `dns`, the plan |
| What happens next, by owner | one action per failing sender, override, SPF-only sender, unknown source and DNS change, grouped by the owner the owners file names; the last group is `Unassigned - needs an owner` | `findings`, the plan's changes, `owners.csv` |
| The ask | the approval or DNS window for this week's step, and what holds the step after it | the plan's zero-risk records and the next enforcement step |
| Open questions | unmet prerequisites, gaps enforcement does not close, heuristics not yet verified, unassigned items | `gate.reasons`, `findings` with `verified: false`, the plan's holds |
| Glossary | DMARC, SPF, DKIM, rua, p=, sp=, pct=, genuine failure, relay echo | fixed text |

Two rules the generator applies so the document reads like a person wrote
it: an entry under 10 genuine failures is a note, never a headline (they
collapse into one "notes, not headlines" line), and a section with no
evidence says "not in this run" instead of showing a zero, because a zero
count is not evidence of health.

## How to polish it

The generated copy is the starting point; the polished copy is what you
send. Rule 13 in `AGENTS.md`: never write a status document from memory
when `next_steps.md` exists - edit it.

Change freely:

- Order and emphasis: lead with what the reader cares about this week.
- The hook of each item: the subject line, the count or the system name the
  reader sees daily goes first. The generator puts one there; make it the
  one your readers will recognize.
- Owner labels into people: the owners file names a team and a channel; the
  polished copy can name who is on point this week.
- The audience split: the same facts become the Slack blast (the one-liner
  and "Where we stand"), one message per owner (their group from "What
  happens next"), and the tracker entries (one per action, with its finding
  id). Keep one message per audience layer.
- Register: soften or sharpen the tone, cut the glossary for readers who
  know the terms, drop the finding ids for leadership.

Never change:

- Any number, date, policy value, gate verdict or finding id. They came from
  `report.json`; if one looks wrong, the report is wrong and the fix is a
  rerun, not an edit.
- The deduplicated basis: raw row counts appear only where the generator
  marks them.
- An "Unassigned" owner into a guessed name. Add the row to `owners.csv`
  and rerun; the action moves under its owner.
- An open question into a statement. It stays open until something in the
  next run answers it.
- Nothing gets added that is not in the run: no sender, count or promise
  from memory or from a conversation (rule 12).

When something is missing from the document it is missing from the inputs:
no owners file (everything unassigned), no `--known` list (every outside
source is unknown), no plan (an offline run has no DNS section), no previous
run (no trend). Fix the input and regenerate.

## Voice rules for the final document

Hyphens only, plain conversational tone, one recognizable hook per item (a
subject line, a count, a vendor name the reader sees daily), and one message
per audience layer - Slack blast, owner DM, or tracker entry. Under-10-failure
senders are notes, never headlines.

## Filled example

The generator, run on the bundled samples with the sample owners file:

```bash
python src/audit.py example.com --offline --rua samples/rua --maillog samples/sample_maillog.csv --headers samples/headers --out audit-out
python src/next_steps.py audit-out/report.json --owners samples/owners.csv.example
```

What it writes (the one-liner, the first section and the first owner group;
the audience line above them names the sources and their sizes):

```markdown
**example.com is at p=reject. 1 of our own sending streams still fails (statements@example.com x3); 5 streams look like spoofing and are being handled by the policy. Nothing is left to ratchet; what is left is keeping our own senders passing.**

## Where we stand (last 30 days, deduplicated)

- **Genuine failures: 21** (raw counts would say 33 - the gap is relay echoes, not broken senders)
- **Delivered despite failing: 3** - these only arrive because of our own overrides; outside receivers are not as forgiving (statements@example.com x3)
- **Spoofing blocked by receivers: 300 rejected / 6 quarantined** - what enforcement is actually for (1361 messages seen by 3 reports, 77.4% passing)
- **Trend: first run, no trend yet**

## What happens next, by owner

- **Statements platform team** (#billing-systems)
  - **statements@example.com - 3 messages** DKIM-sign this sender (or align its SPF): the messages failed with no passing copy and look like our own system (subjects like "Purchase order 4471 acknowledged"; envelope example.com) (MAILFLOW-001)
  - **statements@example.com - 3 messages reached inboxes despite failing** find the override (transport rule, allow list, safe sender) that let them in and make it conditional on authentication; outside receivers do not have it (MAILFLOW-002)
```

The polished version below keeps every count from that output and changes
the rest: the hook comes first in each item, the owner labels become the
people on point, the actions are the two the reader must do this week, and
the ask names the DNS window. Its policy line and trend line are
illustrative - the sample reports publish `p=reject` and a single run has no
previous run - so that the example can show what a ratchet ask looks like.
In a real run you would leave both exactly as the generator wrote them.

---

# DMARC rollout - status and next steps, 2026-09-29

**example.com is at p=none. 6 senders still fail. The next safe step is
p=quarantine at pct=10, and it is ready once the statements system (3
misconfigured messages) is DKIM-signed.**

## Where we stand (last 30 days, deduplicated)

- **Genuine failures: 21** (raw counts would say 33)
- **Delivered despite failing: 3** - purchase-order mail from our own
  statements system, arriving only because of an override
- **Spoofing blocked by receivers: 300 rejected** - voicemail and ACH lures
  using our executives' names
- **Trend vs last week: -4 genuine failures, +2.1 pts pass rate**

## Per domain

| Domain | Policy today | Gate | Next step |
|---|---|---|---|
| `example.com` | p=none | no_go | p=quarantine at pct=10 once statements is signed |

## What happens next, by owner

- **Statements platform owner:** DKIM-sign `statements@example.com` - 3 real
  messages ("Purchase order 4471 acknowledged" and siblings) are failing
- **Security:** find the override that lets statements mail in despite
  failing, and make it conditional on authentication once statements is
  signed

## The ask

Approval to move example.com to `p=quarantine; pct=10` in this Thursday's
DNS window.
