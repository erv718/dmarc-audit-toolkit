---
name: dmarc-status-brief
description: Builds the DMARC status brief from the toolkit's latest run - brief.html, the designed status document (the one-liner, the figures, the per-domain table, actions by owner, the ask and the DNS record cards), generated with no AI - and, only on request, polished copies for each audience (a leadership summary, one message per owner, the DNS change ticket), each checked against the run's own numbers and ids. Use it when asked for the status doc, a meeting doc, a brief, a leadership update, owner messages, a DNS change ticket, or to make the run's output look good, organized or presentable.
---

# DMARC status brief

The toolkit writes its status document itself: `src/next_steps.py` turns each
run into `next_steps.md` and `next_steps.json`, and `src/brief.py` lays the
same content, with the plan's records, out as one designed page,
`brief.html`. This skill finds that page, renders it again when needed, and
on request derives the copies each audience reads - never a new document
from memory.

## 1. Ground rules first

Read `AGENTS.md` before anything else; these rules bind every step below:

- The AI switch comes first (AGENTS.md, Analyzing pulled exports): if the
  human has not opted in to AI analysis (`AI_ANALYSIS_ENABLED=true`), name
  the setting and stop. The page needs no AI: the human can still run
  step 3 themselves and open it.
- Rule 13: the status document comes from the run. Polish may change hooks,
  order and audience, never a number, a verdict, a policy value, a plan id
  or a finding id. Something missing from the document is missing from the
  run's inputs: say which input (the owners file, the known-senders list,
  the evidence) and leave the copy as the run has it.
- Rule 12: answer from the run's files, and cite the file and the run's date.
- Rule 11: say what the run verified and what it inferred; an open question
  stays a question.
- Rule 3: nothing leaves the machine without the human's yes, and the brief
  holds sender addresses, subject lines and IPs.
- Read-only: this skill reads the run; it writes only `brief.html` (through
  `src/brief.py`) and the copies under `audit-out/latest/polished/`. It
  never changes DNS, tenant settings, `audit.toml` or the run's other files.
- Never hand `maillog.csv` or `census.json` to any tool, upload or
  connector: they are the raw per-recipient log.

## 2. Find the run

The run lives in `audit-out/latest/`: `next_steps.json` (the document as
data), `plan.json` (the records), `report.json` (the evidence) and
`run.json` (notes, caveats and the run's stamp).

- Say the run's date before anything else: `next_steps.json` `date`, and
  the stamp in `run.json` `run`.
- If the folder or `next_steps.json` is missing, or the run is older than
  the human expects, say so and offer the weekly run,
  `python src/collect.py` (it reads its settings and credentials itself).
  Run it only when the human asks for it.
- Read `run.json` notes and caveats: a caveat (a mail log cut short, a
  degraded step) travels with every copy you make.

## 3. Render

`collect.py` already wrote `audit-out/latest/brief.html`. Build it again
after any change to the run's files, or when it is missing:

```bash
python src/brief.py audit-out/latest
```

It prints `wrote <path>`. Tell the human where the page is, that it opens in
any browser with no network, and that the browser's Print to PDF gives an
A4 or Letter copy in the light palette. The page is the generator's: do not
edit it, and do not write another one by hand.

## 4. Polish, only on request

Polished copies go into `audit-out/latest/polished/` (gitignored with the
rest of `audit-out/`), one file per audience layer, named with the run's
date. A new run does not clear that folder: a copy belongs to the run it
was made from, so check it against that run (step 5) and make it again
for the next one.

The audience layers are the ones `docs/templates/next-steps.md` names; the
shapes of the three are in `.claude/skills/dmarc-status-brief/reference.md`:

- **Leadership summary**: the one-liner, Where we stand, the ask.
- **One message per owner**: that owner's group from What happens next, by
  owner, with the open questions that name them.
- **DNS change ticket**: the plan rows verbatim, in the brief's order
  (priority, DNS host, zone, domain), each with its before and after
  lookups and its rollback from `verify.md`.

What you may change: the hook of each item (the subject line, count or
system the reader knows goes first), the order and emphasis, the register,
and an owner label into the person on point when the human names them.
What you may not change: any number, date, policy value, gate verdict, plan
id or finding id; an Unassigned owner into a guess; an open question into a
statement. Add nothing that is not in the run.

## 5. Check every polished copy

```bash
python scripts/check_doc.py audit-out/latest/polished/<file> --run audit-out/latest
```

It names, one line each, every number, plan id, finding id or `p=`, `sp=`
or `pct=` value the run's files do not carry, and the punctuation the voice
rules forbid. Fix the copy until it exits 0 - never the run's files, and
never by deleting a number the reader needs: find the run's own figure in
`next_steps.json` and use it. For a copy made from an older run, pass that
run's folder (`audit-out/history/<run>`) to `--run`.

## 6. Other formats, only when asked

When the human wants Word, PDF, Google Docs or a page in a docs tool and
the session has a document skill or connector for it, convert the checked
copy with it: the same sections in the same order, every value unchanged,
then run step 5 on the converted text if the tool can export it. Anything
published or uploaded leaves the machine: confirm with the human first,
keep it private to the company, and remember what the brief holds (sender
addresses, subject lines, IPs; rule 3). Never publish `brief.html` itself to
a public place.

## 7. Voice

Hyphens only, plain conversational tone, one recognizable hook per item (a
subject line, a count, a vendor name the reader sees daily), one message per
audience layer. A sender with under 10 genuine failures is a note, never a
headline.
