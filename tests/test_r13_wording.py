"""Round 13, T-12: one next step, one ramp, honest absences.

The gate's step off p=none is the plan's own first ramp step (audit.RAMP_FIRST_PCT, tied here to
plan.PCT_STEPS[0]), never "a low pct (for example pct=10)"; a domain with a plan row gets the plan's first row as
its next step in next_steps.md, todo.md and summary.txt alike; a policy the run did not read is said in words (no
DMARC record, lookup failed, not read), never p=unknown; a domain with no DMARC record has failures that are not
measurable, never "0 genuine failures"; an offline run says it has no plan; and reading a policy the run could not
read is never "on hold while". Synthetic data, offline."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import audit
import brief
import collect
import next_steps
import notify
import plan as plan_mod
import r13_fixtures as F
import verify

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_doc  # noqa: E402

FR_DOMAINS = ("harborfoods.example", "harbor-old.example", "harborfoods-shop.example")


def outputs(run):
    """Every file a run writes from these inputs, as text: {name: text}. summary lines: every per-domain line the
    Slack message builds (round 13, T-04: it keeps some of them under its details, in these words)."""
    rep, plan, doc = run["report"], run["plan"], run["doc"]
    return {"next_steps.md": next_steps.render_md(doc), "next_steps.json": json.dumps(doc, indent=1),
            "todo.md": collect.render_todo(rep, plan), "summary.txt": notify.summarize(rep, plan=plan),
            "summary lines": "\n".join(e["line"] for e in notify.domain_lines(rep, plan)),
            "report.md": audit.render_md(rep), "plan.md": plan_mod.render_md(plan), "verify.md": verify.render(rep, plan),
            "brief.html": brief.render(json.loads(json.dumps(doc)), plan),
            "metrics.md": collect.render_metrics([collect.metrics_entry("2026-10-09T060000Z", rep, plan)])}


def line_of(text, start):
    return next(line for line in text.splitlines() if line.startswith(start))


@pytest.fixture(scope="module")
def first(tmp_path_factory):
    return F.first_run(tmp_path_factory.mktemp("r13_wording_first"))


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_wording_estate"))


def test_the_gates_first_step_is_the_plans_first_ramp_step(estate):
    assert audit.RAMP_FIRST_PCT == plan_mod.PCT_STEPS[0] == 25
    step = audit.next_step("none", record_at="_dmarc.example.net")
    assert step == "move to p=quarantine at pct=25 on the record at _dmarc.example.net" and "example" not in step[:40]
    # the gate and the plan give one ramp: example.net's step and its ratchet row name the same share
    assert estate["report"]["gate"]["domains"]["example.net"]["next_step"] == step
    assert F.row(estate["plan"], "P-13")["value"].startswith("v=DMARC1; p=quarantine; pct=25;")
    assert not any("for example pct" in text for text in outputs(estate).values())
    # an older run still checks clean: check_doc keeps reading the old example as fixed text, never as a value
    assert any(rx.search("move to p=quarantine at a low pct (for example pct=10)") for rx in check_doc.FIXED_TEXT)


def test_the_first_run_gives_one_next_step_in_every_file(tmp_path):
    for rua in (None, F.FR_RUA):
        run = F.first_run(tmp_path / ("rua" if rua else "placeholder"), rua)
        files = outputs(run)
        md, todo, summary = files["next_steps.md"], files["todo.md"], files["summary lines"]
        for d in FR_DOMAINS:
            rows = [c for c in run["plan"]["changes"] if c["domain"] == d][:2]
            lines = (line_of(md, "| `%s` |" % d), line_of(todo, "- %s: " % d), line_of(summary, "- `%s`: " % d))
            for line in lines:  # the plan's first row in the same words everywhere, then the second
                words = [next_steps.table_step(c) for c in rows]
                assert all(w in line for w in words), (d, line)
                assert [line.index(w) for w in words] == sorted(line.index(w) for w in words)
            assert "(%s, section 2" % rows[0]["id"] in lines[1] and rows[0]["status_text"] in lines[1]
            assert "(plan %s, %s)" % (rows[0]["id"], rows[0]["status_text"]) in lines[2]
        for text in (md, todo, summary):
            assert "pct=10" not in text and "for example pct" not in text
    # the placeholder run, word for word
    run = F.first_run(tmp_path / "words")
    files = outputs(run)
    assert ("- harborfoods.example: p=none, gate no_go, next step: add rua reporting to the DMARC record (P-01, "
            "section 2c: needs the report address)") in files["todo.md"]
    assert ("- `harborfoods.example`: p=none, gate *no_go*, next: add rua reporting to the DMARC record (plan P-01, "
            "needs the report address) - 60 genuine failures of its own") in files["summary lines"]
    assert "| add rua reporting to the DMARC record (plan P-01) |" in line_of(files["next_steps.md"],
                                                                            "| `harborfoods.example` |")


def test_no_output_says_p_unknown(first, estate):
    for run, said in ((first, {"harbor-old.example": "no DMARC record", "harborfoods-shop.example": "no DMARC record"}),
                      (estate, {"example.org": "no DMARC record", "parked.example": "no DMARC record"})):
        files = outputs(run)
        for name, text in files.items():
            assert "p=unknown" not in text and "p=None" not in text, name
        for d, words in said.items():
            assert line_of(files["summary lines"], "- `%s`: " % d).startswith("- `%s`: %s, " % (d, words))
            assert line_of(files["todo.md"], "- %s: " % d).startswith("- %s: %s, " % (d, words))
    # a lookup that failed and a policy nobody read say so, in the per-domain table too
    rep = json.loads(json.dumps(first["report"]))
    rep["dns"]["harbor-old.example"]["dmarc_status"] = "error"
    assert next_steps.policy_words(rep, "harbor-old.example") == "lookup failed"
    assert next_steps.policy_text(rep, "harbor-old.example") == ("lookup failed", None)
    del rep["dns"]["harbor-old.example"]
    assert next_steps.policy_words(rep, "harbor-old.example") == "not read"
    assert "- `harbor-old.example`: not read, gate *" in "\n".join(e["line"] for e in notify.domain_lines(rep, first["plan"]))
    assert "2. `harbor-old.example` not read - policy not read" in notify.summarize(rep, plan=first["plan"])
    # a p= receivers do not apply is an invalid record, its value beside it
    g = rep["gate"]["domains"]["harbor-old.example"]
    g.update(current_policy="quarantin", next_step="unknown - unrecognised policy p=quarantin")
    assert next_steps.policy_words(rep, "harbor-old.example") == "invalid record (p=quarantin)"
    assert next_steps.policy_text(rep, "harbor-old.example") == ("invalid record (p=quarantin)", None)


def test_a_domain_with_no_dmarc_record_has_failures_that_are_not_measurable(first):
    # round 13, T-04: every per-domain line the message builds (it keeps some of them under its details)
    summary = "\n".join(e["line"] for e in notify.domain_lines(first["report"], first["plan"]))
    assert not re.search(r"(?<![0-9])0 genuine failures", notify.summarize(first["report"], plan=first["plan"]))
    shop = line_of(summary, "- `harborfoods-shop.example`: ")
    assert shop.endswith(" - failures not measurable without a DMARC record (34 messages)")
    assert line_of(summary, "- `harbor-old.example`: ").endswith(" - no mail-log rows of its own")
    assert not re.search(r"(?<![0-9])0 genuine failures", summary)
    assert line_of(summary, "- `harborfoods.example`: ").endswith(" - 60 genuine failures of its own")
    # the document for that organization says so too, never that none of its mail failed
    doc = next_steps.build(first["report"], plan=first["plan"], date="2026-10-20", org_name="harborfoods-shop.example")
    assert ("harborfoods-shop.example's failures are not measurable without a DMARC record (34 messages in the mail "
            "log): with no record, no message can fail DMARC.") in doc["one_liner"]
    assert "failed with no passing copy" not in doc["one_liner"]


def run_offline(out):
    return subprocess.run([sys.executable, str(ROOT / "src" / "collect.py"), "example.com", "--offline", "--no-notify",
                           "--rua", str(ROOT / "samples" / "rua"), "--maillog",
                           str(ROOT / "samples" / "sample_maillog.csv"), "--auth-column", "DMARC", "--out", str(out)],
                          capture_output=True, text=True, timeout=300)


def test_an_offline_run_says_it_has_no_plan(tmp_path):
    p = run_offline(tmp_path / "audit-out")
    assert p.returncode in (0, 1) and "Traceback" not in p.stderr, p.stderr
    latest = tmp_path / "audit-out" / "latest"
    summary = (latest / "summary.txt").read_text(encoding="utf-8")
    assert summary.rstrip().endswith("plan: not in this run (offline: no DNS read)")
    assert "change(s) waiting" not in summary and "p=unknown" not in summary
    md = (latest / "next_steps.md").read_text(encoding="utf-8")
    assert "a check in the plan" not in md and "check in the plan" not in md
    # notify.py on its own says the same for an offline report, and counts a plan it is given
    rep = json.loads((latest / "report.json").read_text(encoding="utf-8"))
    assert notify.summarize(rep).endswith("\n" + notify.NO_PLAN_LINE)
    assert notify.summarize(rep, plan={"changes": [], "holds": []}).endswith("- plan: 0 change(s) waiting; 0 hold(s)")


def test_reading_a_policy_the_run_could_not_read_is_never_on_hold(tmp_path):
    log = (F.T.Log().add("staff@example.com", "Weekly report #", times=20)
           .add("app@example.com", "Notice #", "fail", 5))
    rep = audit.build_report(domains=["example.com"], maillog=log.write(tmp_path / "maillog.csv"), offline=True,
                             auth_column="DMARC", domain_sources={"example.com": ["cli"]})
    assert rep["gate"]["domains"]["example.com"]["verdict"] == "no_go"  # its own sender fails: the gate holds
    doc = next_steps.build(rep)
    nxt = doc["next_step"]
    assert nxt["kind"] == "unread" and nxt["prerequisites"] == [] and nxt["holds"] == [] and nxt["blockers"]
    assert "on hold" not in doc["one_liner"]
    assert ("The first step is to determine example.com's DMARC policy: run online, or supply aggregate reports that "
            "cover it. What the audit found stands whatever the policy is: 5 logical messages from this domain failed "
            "with no passing copy") in doc["one_liner"]
    assert doc["ask"] == ("The ask this week: the first step is to determine example.com's DMARC policy (run online, "
                          "or supply aggregate reports that cover it).")
    blockers = [q["question"] for q in doc["open_questions"] if q["kind"] == "blocker"]
    assert blockers and all(q.startswith("Can we close this gap on example.com (it stands whatever its DMARC record "
                                         "says): ") for q in blockers)
    assert not any("before we determine" in q["question"] for q in doc["open_questions"])
    page = brief.render(json.loads(json.dumps(doc)))
    step = page.split('id="next-step"', 1)[1].split("</section>", 1)[0]
    assert "on hold while" not in step.lower()
    summary = "\n".join(e["line"] for e in notify.domain_lines(rep))  # round 13, T-04: the line as built
    assert ("- `example.com`: not read, gate *no_go*, next: read the policy first: run online, or supply aggregate "
            "reports that cover it - 5 genuine failures of its own") in summary
    assert "- example.com: not read, gate no_go, next step: read the policy first" in collect.render_todo(
        rep, {"changes": [], "holds": []})
