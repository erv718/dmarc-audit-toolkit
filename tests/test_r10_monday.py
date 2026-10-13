"""The run never stops on a damaged earlier report or a failed summary, and a
mail-log pull that failed for one organization is a cut of its own kind, so
nothing compares a log that is missing that whole organization. No network."""

import json
import sys

import pytest

import audit
import collect
import graph_client
import notify

from conftest import ROOT


def sample_report(**kw):
    return audit.build_report(domains=["example.com"], maillog=str(ROOT / "samples" / "sample_maillog.csv"),
                              rua_paths=[str(ROOT / "samples" / "rua")], offline=True, auth_column="DMARC", **kw)


@pytest.mark.parametrize("damage, note, withheld", [
    (lambda p: p["maillog"]["counters"].__setitem__("genuine_failures", "x"),  # a count that is not a number
     "genuine_failures is not a whole number in the previous run's report.json (x): its delta is not computed",
     "- genuine failures: n/a (a count that is no whole number, see the note below); delivered despite fail: +0"),
    (lambda p: p["maillog"]["by_domain"]["example.com"].__setitem__("genuine_failures", None),  # a null count
     "the counts for example.com are not whole numbers in one of the two report.json files: its delta is not computed",
     "- genuine failures: +0; delivered despite fail: +0"),
])
def test_a_damaged_count_in_the_previous_report_withholds_that_delta_and_says_why(damage, note, withheld):
    previous = json.loads(json.dumps(sample_report()))
    damage(previous)
    rep = sample_report(previous_report=previous)  # the run's report is built, with the delta: one count withheld
    assert "delta_error" not in rep and note in rep["delta"]["notes"]
    assert rep["gate"]["verdict"] and rep["findings"] is not None
    md = audit.render_md(rep)  # and report.md renders the withheld count, never a traceback over a format code
    assert any(l.startswith(withheld) for l in md.splitlines())
    assert ("example.com +0 genuine" in md) == ("example.com" not in note)


@pytest.mark.parametrize("broken", ["build_delta", "_md_delta"])
def test_a_comparison_that_fails_or_cannot_be_rendered_leaves_the_delta_out_and_says_why(monkeypatch, broken):
    def fail(*a, **k):
        raise ValueError("a damaged previous report")
    monkeypatch.setattr(audit, broken, fail)  # the comparison itself, or report.md's rendering of it, fails
    rep = sample_report(previous_report=json.loads(json.dumps(sample_report())))  # and yet the run's report is built
    assert "delta" not in rep
    assert rep["delta_error"] == ("the previous run's report.json could not be compared (ValueError: a damaged previous "
                                  "report): no delta this run")
    assert rep["gate"]["verdict"] and rep["findings"] is not None
    assert "## Since the previous run" not in audit.render_md(rep)


def test_collect_writes_every_file_when_the_summary_cannot_be_built(monkeypatch, tmp_path):
    def broken(*a, **k):
        raise ValueError("a damaged history entry")
    monkeypatch.setattr(notify, "summarize", broken)
    monkeypatch.setattr(sys, "argv", ["collect.py", "--no-config", "--no-graph", "--offline", "--no-notify",
                                      "--no-owners", "example.com", "--rua", str(ROOT / "samples" / "rua"),
                                      "--maillog", str(ROOT / "samples" / "sample_maillog.csv"),
                                      "--auth-column", "DMARC", "--out", str(tmp_path / "out")])
    with pytest.raises(SystemExit) as stop:
        collect.main()
    assert stop.value.code in (0, 1)  # findings or none, never the traceback the damaged summary would raise
    latest = tmp_path / "out" / "latest"
    summary = (latest / "summary.txt").read_text(encoding="utf-8")
    assert summary.startswith("*DMARC audit* summary not built: ValueError: a damaged history entry")
    run = json.loads((latest / "run.json").read_text(encoding="utf-8"))
    assert any(n.startswith("summary not built: ValueError") for n in run["notes"])
    for name in ("report.json", "report.md", "next_steps.md", "todo.md", "verify.md"):
        assert (latest / name).is_file(), name


def test_a_failed_pull_is_recorded_as_a_cut_and_withholds_the_comparison(monkeypatch, tmp_path):
    def failing(*a, **k):
        raise graph_client.GraphError("hunting: 500 server error")
    monkeypatch.setattr(collect, "pull_domain", failing)
    monkeypatch.setattr(collect, "hourly_counts", lambda *a, **k: None)
    cuts = {}
    path, notes = collect.pull_maillog(None, ["corp.example"], tmp_path / "log.csv", cuts=cuts)
    assert path is None and any("mail log for corp.example not pulled" in n for n in notes)
    assert cuts == {"corp.example": {"reason": "not pulled", "error": "hunting: 500 server error"}}
    assert audit._cut_cause(cuts["corp.example"]) == "a failed pull"
    assert audit._cut_cause({"reason": "row budget", "kept_hours": 41}, {"reason": "not pulled"}) == \
        "the row budget and a failed pull"
    # the delta reads it like any other cut: the counts are not compared, and the note says why
    now = {"maillog": {"counters": {"genuine_failures": 3, "delivered_despite_fail": 0}, "cuts": cuts,
                       "by_domain": {"corp.example": {"genuine_failures": 3, "delivered_despite_fail": 0}}},
           "gate": {"domains": {}}, "findings": []}
    prev = {"generated_utc": "2026-10-05T06:00:00Z",
            "maillog": {"counters": {"genuine_failures": 90, "delivered_despite_fail": 2},
                        "by_domain": {"corp.example": {"genuine_failures": 90, "delivered_despite_fail": 2}}},
            "gate": {"domains": {}}, "findings": []}
    dl = audit.build_delta(now, prev)
    assert dl["genuine_failures"] is None and "corp.example" not in dl["by_domain"]
    assert any(n.startswith("a failed pull cut corp.example's mail log in this run") for n in dl["notes"])
