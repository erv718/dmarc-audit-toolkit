"""Round 13 review fixes: the files around the band.

A priority's heading in brief.html and plan.md says what the priority holds and counts its rows by status - never
"now" or "zero delivery risk" over rows that are not ready; todo.md's enforcement steps each say their own status,
never "gated" for all of them. The one-liner folded under The next step prints. A Gate cell names a DNS finding by
what it is, an invalid record's pill is the band's color, and notify.py run on its own reads the plan beside the
report. Synthetic data, offline."""

import json
import re
import subprocess
import sys

import pytest

import brief
import collect
import next_steps
import plan as plan_mod
import r13_fixtures as F
from conftest import ROOT


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("r13_fix_files")
    return {"estate": F.estate(tmp / "estate"), "stress": F.stress(tmp / "stress"), "first": F.first_run(tmp / "first"),
            "weekly": F.weekly(tmp / "weekly")}


def test_no_priority_heading_promises_what_its_rows_are_not(runs):
    for name, run in runs.items():
        plan = run["plan"]
        md = plan_mod.render_md(plan)
        page = brief.dns_section(plan, plan.get("headline"))
        for prio in sorted({c["priority"] for c in plan["changes"]}):
            rows = [c for c in plan["changes"] if c["priority"] == prio]
            ready = sum(1 for c in rows if c["status"] == "now")
            head = "## Priority %d - %s" % (prio, plan_mod.PRIORITY_LABEL[prio])
            status = md.split(head + "\n\n", 1)[1].split("\n", 1)[0]
            assert status == "Status: %s." % plan_mod.status_summary(rows), (name, prio)
            span = re.search(r"<h3>Priority %d <span class=\"count\">([^<]*)</span>" % prio, page).group(1)
            for said in (head, status, span):
                assert "zero" not in said, (name, said)
                # 'now' only as the count of the rows ready now
                assert re.sub(r"\b%d ready now\b" % ready, "", said).count("now") == 0, (name, said)
    # the first run: the note says none is ready, and the heading under it never says otherwise
    md = plan_mod.render_md(runs["first"]["plan"])
    assert "## Priority 1 - monitoring, hygiene and parking; quarantine where no mail is measured\n\nStatus: 3 waiting " \
           "for the report address, 1 after a check." in md
    assert "  - status: needs the report address" in md


def test_enforcement_steps_say_their_own_status_in_todo_md(runs):
    run = runs["weekly"]
    todo = collect.render_todo(run["report"], run["plan"])
    section = todo.split("## 5. Enforcement steps (each with its status; apply only when every prerequisite holds)\n",
                         1)[1].split("\n## ", 1)[0]
    assert "gated" not in section
    for c in (c for c in run["plan"]["changes"] if c["priority"] >= 3):
        row = section.split("- %s %s (" % (c["id"], c["domain"]), 1)[1]
        status = row.split("\n", 2)[1]
        assert status.startswith("  - status: %s" % c["status_text"]), c["id"]
    p21 = section.split("- P-21 corp.de (enforcement step): ", 1)[1].split("\n")[1]
    assert p21.startswith("  - status: after 1 check - ")


def test_the_one_liner_folded_under_the_next_step_prints(runs):
    doc = runs["estate"]["doc"]
    page = brief.render(doc, runs["estate"]["plan"])
    assert '<p class="para-print">%s</p>' % brief.prose(doc["one_liner"]) in page
    printed = brief.CSS.split("@media print {\n  html {", 1)[1]
    assert "details.para { display: none; }" in printed and ".para-print { display: block;" in printed
    assert ".para-print { display: none; }" in brief.COMPONENTS.split("@media", 1)[0]  # on screen: folded only


def test_a_gate_cell_names_a_dns_finding_by_what_it_is(runs):
    rep = runs["estate"]["report"]
    assert next_steps.held_words(rep, "example.org", "example.org: DMARC-001") == "no DMARC record (DMARC-001)"
    titled = {"dns": {"example.org": {"findings": [
        {"id": "DMARC-001", "title": "NO DMARC RECORD - no policy, no reporting, invisible to you"},
        {"id": "SPF-009", "title": "SPF has too many includes - receivers may time out"}]}}}
    assert next_steps.held_words(titled, "example.org", "NO DMARC RECORD - no policy, no reporting, invisible to you") \
        == "no DMARC record (DMARC-001)"
    assert next_steps.held_words(titled, "example.org", "example.org: SPF-009") == "SPF has too many includes (SPF-009)"
    assert next_steps.held_words(titled, "example.org", "198.51.100.20 fails DMARC on 60/60 msgs") == \
        "198.51.100.20 fails DMARC on 60/60 msgs"
    row = next(r for r in runs["estate"]["doc"]["per_domain"] if r["domains"] == ["example.org"])
    assert row["gate_text"].startswith("not yet - held by: no DMARC record (DMARC-001)")


def test_an_invalid_record_has_the_bands_color_in_per_domain():
    assert brief.policy_class("invalid record (p=bogus)") == "bad"
    assert brief.policy_cell("invalid record (p=bogus)").startswith('<span class="pill bad">invalid record</span>')
    assert next_steps.BADGES["invalid"] == ("invalid record", "bad")


def test_notify_on_its_own_reads_the_plan_beside_the_report(runs, tmp_path):
    run = runs["estate"]
    (tmp_path / "report.json").write_text(json.dumps(run["report"], default=str), encoding="utf-8")
    (tmp_path / "plan.json").write_text(json.dumps(run["plan"]), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "notify.py"), "--report", str(tmp_path / "report.json"),
                        "--dry-run"], capture_output=True, text=True, cwd=str(tmp_path))
    assert p.returncode == 0, p.stderr
    assert "nothing to approve (no plan this run)" not in p.stdout
    assert "Your call: nothing to approve yet; 9 wait on checks; " in p.stdout
    assert "\n- plan: 14 change(s) waiting" in p.stdout
    # a plan.json that is not a plan is no plan, never a stop
    (tmp_path / "plan.json").write_text("[1]", encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "notify.py"), "--report", str(tmp_path / "report.json"),
                        "--dry-run"], capture_output=True, text=True, cwd=str(tmp_path))
    assert p.returncode == 0 and "Your call: nothing to approve (no plan this run)." in p.stdout
