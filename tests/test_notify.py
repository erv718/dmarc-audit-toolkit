"""notify.py: message building and posting, with the network stubbed."""

import json
import subprocess
import sys
from pathlib import Path

import notify

ROOT = Path(__file__).resolve().parent.parent


def report(policy="quarantine", verdict="no_go", findings=(), failures=21, pass_rate=0.77, sources=("192.0.2.10",)):
    return {
        "generated_utc": "2026-01-08T06:00:00Z",
        "gate": {"domains": {"example.com": {"current_policy": policy, "verdict": verdict, "next_step": "p=reject"}}},
        "summary": {"findings": len(findings), "by_severity": {"major": len(findings)}},
        "findings": [{"id": f, "source": "dns:example.com", "severity": "major"} for f in findings],
        "maillog": {"counters": {"genuine_failures": failures, "raw_failing_rows": failures + 12,
                                 "delivered_despite_fail": 3, "by_likely": {"likely_spoof": 18}}},
        "rua": {"totals": {"messages": 1000, "pass_rate": pass_rate, "by_disposition": {"reject": 300, "quarantine": 6}},
                "by_source_ip": [{"source_ip": ip, "count": 10} for ip in sources],
                "unknown_senders": [{"kind": "dkim_domain", "value": "vendor.example", "count": 800}]},
    }


def test_summary_covers_gate_findings_maillog_and_outside_view():
    text = notify.summarize(report(findings=("DMARC-003",)))
    assert "`example.com`: p=quarantine, gate *no_go*, next: p=reject" in text
    assert "findings: 1 (major 1)" in text
    assert "21 genuine failures (33 rows would say so)" in text
    assert "spoofing blocked by receivers: 300 rejected, 6 quarantined" in text
    assert "unknown senders in reports: 1" in text


def test_summary_deltas_against_previous_run():
    prev = report(policy="quarantine", verdict="no_go", findings=("DMARC-003", "SPF-005"), failures=30,
                  pass_rate=0.70, sources=("192.0.2.10",))
    now = report(policy="reject", verdict="go", findings=("SPF-005", "DKIM-002"), failures=21,
                 pass_rate=0.77, sources=("192.0.2.10", "198.51.100.7"))
    text = notify.summarize(now, prev, {"changes": [{"priority": 1}, {"priority": 3}], "holds": [{}]})
    assert "*new findings*: example.com DKIM-002" in text
    assert "resolved: example.com DMARC-003" in text
    assert "`example.com` changed: p=quarantine/no_go -> p=reject/go" in text
    assert "*newly seen senders*: 198.51.100.7" in text
    assert "genuine failures vs last run: -9" in text
    assert "pass rate vs last run: +7.0 points" in text
    assert "plan: 2 change(s) waiting, 1 are zero-risk monitoring/hygiene; 1 hold(s)" in text


def test_post_sends_json_text(monkeypatch):
    sent = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        sent["url"] = req.full_url
        sent["body"] = json.loads(req.data.decode("utf-8"))
        return Resp()
    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    assert notify.post("https://hooks.example/abc", "hello") == 200
    assert sent["url"] == "https://hooks.example/abc" and sent["body"] == {"text": "hello"}


def test_cli_dry_run_and_missing_webhook(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps(report()), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "notify.py"), "--report", str(tmp_path / "report.json"), "--dry-run"],
                       capture_output=True, text=True)
    assert p.returncode == 0 and "*DMARC audit*" in p.stdout
    env = {"PATH": "", "SYSTEMROOT": "C:\\Windows"}
    p = subprocess.run([sys.executable, str(ROOT / "src" / "notify.py"), "--report", str(tmp_path / "report.json"),
                        "--env-file", str(tmp_path / "none.env")], capture_output=True, text=True)
    assert p.returncode == 2 and "no webhook" in p.stderr and "Traceback" not in p.stderr
