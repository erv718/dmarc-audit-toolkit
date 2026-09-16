"""Offline tests for the audit orchestrator and the library contracts it
depends on. Everything here runs against the bundled samples - no network,
no live DNS (dnspython resolving or not must not matter)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import audit
import spf_lookups

GATE_VERDICTS = {"go", "no_go", "insufficient_data"}
SEVERITIES = {"info", "minor", "major", "blocking"}

OFFLINE_ARGS = [
    "example.com", "--offline",
    "--rua", "samples/rua",
    "--maillog", "samples/sample_maillog.csv",
    "--headers", "samples/headers",
]


def run_cli(*argv):
    return subprocess.run([sys.executable, str(ROOT / "src" / "audit.py"), *argv],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)


def check_report_doc(doc):
    """The report.json contract, asserted the same way for CLI and library."""
    assert doc["gate"]["verdict"] in GATE_VERDICTS
    assert doc["findings"], "expected findings from the bundled samples"
    for f in doc["findings"]:
        assert f["severity"] in SEVERITIES, f
        assert f["action"].strip(), f
        assert f["title"].strip(), f
    assert doc["summary"]["findings"] == len(doc["findings"])
    assert doc["summary"]["gate"] == doc["gate"]["verdict"]


def test_offline_cli_writes_both_reports(tmp_path):
    proc = run_cli(*OFFLINE_ARGS, "--out", str(tmp_path))
    assert proc.returncode in (0, 1), proc.stderr
    jpath, mpath = tmp_path / "report.json", tmp_path / "report.md"
    assert jpath.is_file() and mpath.is_file()
    doc = json.loads(jpath.read_text(encoding="utf-8"))
    check_report_doc(doc)
    md = mpath.read_text(encoding="utf-8")
    assert "## Gate verdict" in md
    assert doc["gate"]["verdict"] in md


def test_offline_cli_exit_code_matches_findings(tmp_path):
    proc = run_cli(*OFFLINE_ARGS, "--out", str(tmp_path))
    doc = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert proc.returncode == doc["exit_code"]


def test_build_report_library_call():
    doc = audit.build_report(
        domains=["example.com"], rua_paths=["samples/rua"],
        maillog="samples/sample_maillog.csv", header_files=["samples/headers"],
        offline=True)
    check_report_doc(doc)
    assert doc["offline"] is True
    assert doc["dns"] is None  # offline: no live DNS section
    assert doc["rua"]["totals"]["messages"] > 0
    assert doc["maillog"]["counters"]["raw_rows"] > 0
    assert len(doc["headers"]["messages"]) == 4


def test_gate_blocks_on_genuine_maillog_failures():
    # the sample mail log carries genuine failures, so the gate cannot say go
    doc = audit.build_report(domains=["example.com"],
                             maillog="samples/sample_maillog.csv", offline=True)
    assert doc["gate"]["verdict"] == "no_go"


def test_offline_without_inputs_is_usage_error():
    proc = run_cli("example.com", "--offline", "--out", "audit-out-x")
    assert proc.returncode == 2
    assert "offline" in proc.stderr.lower()


def test_dedupe_misspelled_column_exits_2():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "src" / "dedupe.py"), "samples/sample_maillog.csv",
         "--msgid-column", "Internet message IDD"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2
    assert "column not found" in proc.stderr


def test_get_spf_status_returns_a_known_status():
    # Any of the three is acceptable offline: a blocked resolver path must
    # surface as "error", never as an exception or a made-up "absent".
    record, status, evidence = spf_lookups.get_spf_status("example.com", None)
    assert status in ("found", "absent", "error")
    assert (record is None) == (status != "found")
    assert evidence
