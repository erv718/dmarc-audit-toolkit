# Next-steps report template

Fill this from `audit-out/latest/report.json`, `audit-out/latest/plan.md`,
and `audit-out/metrics.md`. Every number must come from those files - never
invented, never from raw row counts (rule 4). Delete this paragraph and every
`<placeholder>` before sending.

Voice rules for the final document: hyphens only, plain conversational tone,
one recognizable hook per item (a subject line, a count, a vendor name the
reader sees daily), and one message per audience layer - Slack blast, owner
DM, or tracker entry. Under-10-failure senders are notes, never headlines.

---

# DMARC rollout - status and next steps, <date>

**<Domain> is at p=<policy>. <N> legitimate senders still fail. The next safe
step is <action>, and it is ready when <prerequisite>.**

## Where we stand (last 30 days, deduplicated)

- **Genuine failures: <N>** (raw counts would say <M> - the gap is relay
  echoes, not broken senders)
- **Delivered despite failing: <N>** - these only arrive because of our own
  overrides; outside receivers are not as forgiving
- **Spoofing blocked by receivers: <N> rejected / <N> quarantined** - what
  enforcement is actually for
- **Trend vs <last run date>: <±N> genuine failures, <±pts> pass rate**

## Per domain

| Domain | Policy today | Gate | Next step |
|---|---|---|---|
| `<domain>` | p=<policy> | <go/no_go> | <the one line from plan.md> |

## What happens next, by owner

- **<Team/person 1>:** <action, with the hook first - subject line or count>
- **<Team/person 2>:** <action>
- **Vendors:** <vendor tickets, one line each with the recognizable detail>

## The ask

<One sentence: the approval, the meeting, or the DNS change window.>

---

## Filled example (delete this section)

The counts below come from the bundled samples (`src/audit.py example.com
--offline --rua samples/rua --maillog samples/sample_maillog.csv`). The policy
line and the trend line are illustrative: the sample reports publish
`p=reject`, and a single run has no previous run to compare against.

**example.com is at p=none. 6 senders still fail. The next safe step is
p=quarantine at pct=10, and it is ready once the 3 misconfigured senders are
DKIM-signed.**

## Where we stand (last 30 days, deduplicated)

- **Genuine failures: 21** (raw counts would say 33)
- **Delivered despite failing: 3** - purchase-order mail from our own
  statements system, arriving only because of an override
- **Spoofing blocked by receivers: 300 rejected** - voicemail and ACH lures
  using our executives' names
- **Trend vs last week: -4 genuine failures, +2.1 pts pass rate**

## What happens next, by owner

- **Statements platform owner:** DKIM-sign `statements@example.com` - 3 real
  messages ("Purchase order 4471 acknowledged" and siblings) are failing
- **Security:** remove the two stale allow entries once statements is signed

## The ask

Approval to move example.com to `p=quarantine; pct=10` in this Thursday's
DNS window.
