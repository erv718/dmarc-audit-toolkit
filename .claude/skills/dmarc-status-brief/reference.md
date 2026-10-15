# Polished copies: the three shapes

Every value below comes from the run's files, copied as written:
`next_steps.json` for the document, `plan.json` for the records, `verify.md`
for the lookups. Angle brackets mark what you fill in from them; everything
else is a suggestion you may reword. Check each copy with
`scripts/check_doc.py` before it goes anywhere.

## Leadership summary

One screen, for people who decide and do not read DNS.

```text
Subject: DMARC rollout, <org_domain>, <date>: <the hook - the step, or the one figure that moved>

<one_liner, verbatim; you may move its hook to the front>

Where we stand
- Genuine failures: <stand.genuine_failures> (raw <stand.raw_failing_rows>)
- Delivered despite failing: <stand.delivered_despite_fail>
- Receivers rejected / quarantined: <spoofing_blocked.rejected> / <spoofing_blocked.quarantined>
- Trend: <the trend line of stand.lines>
- <a caveat line from stand.lines, when there is one>

The ask
<ask, verbatim>

From the <date> run (brief.html, next_steps.json). Counts are deduplicated.
```

Drop finding ids and the glossary for this layer; keep plan ids only where
the ask names them.

## One message per owner

One per group in `actions_by_owner`, sent through the group's `channel`.

```text
To: <owner> (<channel>)
Subject: <the hook of the group's first item>

From the <date> DMARC run, for <owner>:
- <hook> - <action> (<ref>)
  ... one line per item, in the brief's order (grouped by organization when it groups them)
Open questions for you:
- <each open_questions entry whose owner is this owner>
To check any of it yourself: verify.md in the run folder, the section named after each domain or plan id.
```

An `Unassigned - needs an owner` group goes to the human who assigns owners,
never to a guessed person; the fix is an `owners.csv` row and a rerun.

## DNS change ticket

For whoever publishes DNS. One ticket per DNS host is usual; the rows stay
in the brief's order: priority, DNS host, zone, domain.

```text
Title: DNS change, <zone_host>, <date> run: <plan ids, as a range>
Window: <the window the ask names>

Decide first (no row below waits on these unless it says so):
- <plan.holds: domain - reason, verbatim>

<id> <kind word> <domain> (priority <priority>, zone <zone>)
  Host name: <hostname>
  Type: <record>   TTL: <ttl>
  Value (publish exactly this): <value>
  Current value: <current>
  Before applying:
    [ ] <each prerequisite, verbatim>
  Before: <verify.md, the row's section, step 1: the lookup and what it shows today>
  After: <verify.md, the row's After step: the same lookup and the value to expect>
  Rollback: <rollback>
```

Copy each value character for character; a record value retyped by hand is
how a working record breaks. A row whose prerequisites are not confirmed
stays out of the window.
