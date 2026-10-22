"""Round 13 review fixes: the band within its 75-second read, and a Slack message that does not run long.

At thirteen organizations the band past its headline stays within 300 words (BAND_WORDS: a 75-second read at four
words a second): it sheds its least needed detail first, in a fixed order (SHED), the host names of the rows ready
now among the last, and every figure and id it keeps is the run's. The page's reading line promises the first lines
in 45 seconds. Under the Slack message's details a cut organization is one line - its floor and its whole window -
and only its names with failures or a change keep lines of their own. Synthetic data, offline."""

import json
import sys
from pathlib import Path

import pytest

import audit
import brief
import next_steps
import notify
import r13_fixtures as F

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_doc  # noqa: E402


@pytest.fixture(scope="module")
def weekly(tmp_path_factory):
    return F.weekly(tmp_path_factory.mktemp("r13_fix_length_weekly"))


def band_at(run, level, monkeypatch):
    """The weekly band built to shed exactly level steps."""
    monkeypatch.setattr(next_steps, "BAND_WORDS", 0)
    monkeypatch.setattr(next_steps, "BAND_LEVELS", level)
    top = next_steps.build(run["report"], plan=run["plan"], owners=next_steps.read_owners(
        run["owners_path"]), date="2026-10-14")["top"]
    assert top["level"] == level
    return top


def test_thirteen_organizations_read_in_75_seconds(weekly, monkeypatch):
    top = weekly["doc"]["top"]
    assert next_steps.band_words(top) <= next_steps.BAND_WORDS == 300
    assert len(top["headline"].split()) <= next_steps.HEADLINE_WORDS
    # it had to shed to get there, and the host names of the rows ready now are still there
    assert 1 <= top["level"] < next_steps.SHED["hosts"]
    assert ["host", "_dmarc.alerts"] in top["call"]["parts"]
    full = band_at(weekly, 0, monkeypatch)
    assert next_steps.band_words(full) > 300


def test_the_band_sheds_the_least_needed_detail_first(weekly, monkeypatch):
    one = band_at(weekly, 1, monkeypatch)
    assert one["lines_md"][-1].startswith("- **Not in this data:** corp.example and corp-brand.example: the row budget "
                                          "cut their mail logs, so their counts are floors (502 genuine failures")
    two = band_at(weekly, 2, monkeypatch)
    assert "; 12 not this week; " in two["call"]["text"] and "(P-20" not in two["call"]["text"]
    four = band_at(weekly, 4, monkeypatch)
    assert four["changed"]["text"].endswith("failure counts for corp.example and corp-brand.example not compared.")
    assert next_steps.strip_line_md(four["domains"][2]).endswith("Do first: DKIM-sign billing@corp.co.uk.")
    assert next_steps.strip_line_md(four["domains"][1]).endswith("before the policy moves.")
    seven = band_at(weekly, 7, monkeypatch)
    first = next_steps.strip_line_md(seven["domains"][0])
    assert "(owner: " not in first and "; keep the transport rule that lets 112 in until it passes." in first
    assert seven["more"]["text"] == "+8 more organizations (1 with own mail failing, 5 unprotected, 2 clean)"
    assert "full window" not in " ".join(seven["gaps"]) and "_dmarc.alerts" in seven["call"]["text"]
    eight = band_at(weekly, 8, monkeypatch)
    assert "ready now (P-08, P-10, P-11, P-14)" in eight["call"]["text"] and "_dmarc" not in eight["call"]["text"]


def test_every_figure_and_id_of_the_weekly_band_is_in_the_runs_files(weekly, tmp_path):
    top = weekly["doc"]["top"]
    (tmp_path / "next_steps.json").write_text(json.dumps(weekly["doc"], indent=1), encoding="utf-8")
    (tmp_path / "plan.json").write_text(json.dumps(weekly["plan"], indent=1), encoding="utf-8")
    rep = dict(weekly["report"], findings=audit.flatten_findings(weekly["report"]))
    (tmp_path / "report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    (tmp_path / "top.md").write_text("**%s**\n\n%s\n" % (top["headline"], "\n".join(top["lines_md"])), encoding="utf-8")
    (tmp_path / "top.txt").write_text("\n".join(top["lines_plain"]) + "\n", encoding="utf-8")
    for copy in ("top.md", "top.txt"):
        assert check_doc.main([str(tmp_path / copy), "--run", str(tmp_path)]) == 0, copy
    assert not any("@" in line for line in top["lines_plain"])


def test_the_reading_line_promises_the_first_lines(weekly):
    assert brief.READING_LINE.startswith("Read the first lines in 45 seconds; ")
    page = brief.render(weekly["doc"], weekly["plan"])
    assert '<p class="reading">%s</p>' % brief.READING_LINE in page and "Read the block below" not in page


def test_a_cut_organization_is_one_line_under_the_details(weekly):
    rep = weekly["report"]
    text = notify.summarize(rep, plan=weekly["plan"], top=weekly["doc"]["top"])
    details = text.split("\nDetails:\n", 1)[1].splitlines()
    corp = [line for line in details if line.startswith("- `corp.example`")]
    names = [d for d in rep["gate"]["domains"] if d == "corp.example" or d.endswith(".corp.example")]
    floor = sum(rep["maillog"]["by_domain"].get(d, {}).get("genuine_failures", 0) for d in names)
    assert corp == ["- `corp.example` and its 12 names below it: %d genuine failures in the rows kept (newest 241 hours "
                    "kept; a floor: the gate, the census and the labels count these); over the full 30 days, counted in "
                    "Advanced Hunting: 322 genuine failures, 292 delivered despite failing" % floor]
    # its quiet names are counted, never a line each; its names with failures of their own keep theirs
    for quiet in ("archive", "labs", "legacy", "test", "alerts", "careers"):
        assert not any(line.startswith("- `%s.corp.example`:" % quiet) for line in details), quiet
    assert any(line.startswith("- `news.corp.example`:") for line in details)
    assert len(text.splitlines()) <= 36  # 44 before: a line for each of the cut organizations' names
