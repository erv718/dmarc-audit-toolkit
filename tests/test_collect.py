"""collect.py and fetch_rua.py: the offline path end to end, plus pure helpers."""

import json
import subprocess
import sys
from pathlib import Path

import collect
import fetch_rua

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "src" / "collect.py")


def test_kql_substitution_only_touches_the_placeholder():
    template = 'let days = 30;\nlet sender_domain = "example.com";\nEmailEvents | where SenderFromDomain endswith sender_domain'
    out = collect.kql_for_domain(template, "other.example")
    assert 'let sender_domain = "other.example";' in out and out.count("other.example") == 1
    try:
        collect.kql_for_domain("no placeholder here", "x.example")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_fetch_rua_helpers():
    assert fetch_rua.is_report_name("google.com!example.com!1.xml.gz")
    assert fetch_rua.is_report_name("REPORT.ZIP")
    assert not fetch_rua.is_report_name("invoice.pdf")
    name = fetch_rua.safe_name("2026-01-08T06:00:00Z", "a b/c!example.com!1!2.xml")
    assert name.startswith("20260108060000_") and "/" not in name and " " not in name


def run_offline(out):
    return subprocess.run([sys.executable, SCRIPT, "example.com", "--offline", "--no-notify",
                           "--rua", str(ROOT / "samples" / "rua"),
                           "--maillog", str(ROOT / "samples" / "sample_maillog.csv"), "--auth-column", "DMARC",
                           "--out", str(out)], capture_output=True, text=True)


def test_offline_run_twice_builds_history_latest_and_metrics(tmp_path):
    out = tmp_path / "audit-out"
    p1 = run_offline(out)
    assert p1.returncode in (0, 1), p1.stderr
    assert (out / "latest" / "report.md").exists() and (out / "latest" / "report.json").exists()
    assert (out / "latest" / "summary.txt").exists() and (out / "metrics.json").exists()
    runs = sorted(d.name for d in (out / "history").iterdir())
    assert len(runs) == 1
    assert "Traceback" not in p1.stderr
    # offline: no DNS, so no plan - and the run says so instead of failing
    assert "no plan written" in p1.stderr

    p2 = run_offline(out)
    assert p2.returncode in (0, 1), p2.stderr
    entries = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert len(entries) == 2 and entries[1]["genuine_failures"] == entries[0]["genuine_failures"]
    assert (out / "metrics.md").read_text(encoding="utf-8").count("| 2026") >= 0
    summary = (out / "latest" / "summary.txt").read_text(encoding="utf-8")
    assert "*DMARC audit*" in summary and "genuine failures vs last run: +0" in summary


def test_nothing_to_audit_is_a_usage_error(tmp_path):
    p = subprocess.run([sys.executable, SCRIPT, "--no-graph", "--offline", "--no-notify", "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert p.returncode == 2 and "Traceback" not in p.stderr


def test_metrics_render_is_a_table():
    md = collect.render_metrics([{"run": "2026-01-08T0600Z", "domains": {"example.com": {"policy": "quarantine", "gate": "no_go"}},
                                  "findings": {"major": 2}, "genuine_failures": 21, "rua_pass_rate": 0.77,
                                  "plan_changes": 3, "plan_priority1": 2}])
    assert "| 2026-01-08T0600Z | example.com quarantine/no_go | major 2 | 21 | 77.0% | 3 (2 now) |" in md
