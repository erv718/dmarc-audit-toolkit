"""collect.py with audit.toml: precedence, retention, strict mode, todo.md and
the notification switch. Offline runs over the bundled samples; no network."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "src" / "collect.py")
OFFLINE = ["--offline", "--rua", str(ROOT / "samples" / "rua"),
           "--maillog", str(ROOT / "samples" / "sample_maillog.csv"), "--auth-column", "DMARC"]


def run(*args, env_extra=None):
    env = dict(os.environ, SLACK_WEBHOOK_URL="", TEAMS_WEBHOOK_URL="")
    env.update(env_extra or {})
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, env=env, timeout=300)


def test_settings_supply_domains_and_retention(tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text('[audit]\ndomains = ["example.com"]\nkeep = 1\n', encoding="utf-8")
    out = tmp_path / "out"
    for _ in range(2):
        p = run("--config", str(cfg), "--no-notify", "--out", str(out), *OFFLINE)
        assert p.returncode in (0, 1), p.stderr
        assert "Traceback" not in p.stderr
    assert (out / "latest" / "domains.txt").read_text(encoding="utf-8").strip() == "example.com"
    assert len([d for d in (out / "history").iterdir() if d.is_dir()]) == 1   # keep = 1 pruned the older run
    assert "settings read from" in p.stderr
    run_doc = json.loads((out / "latest" / "run.json").read_text(encoding="utf-8"))
    assert run_doc["settings"].endswith("audit.toml") and run_doc["strict_reasons"] == []


def test_command_line_beats_the_settings_file(tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text('[audit]\ndomains = ["other.example"]\n', encoding="utf-8")
    out = tmp_path / "out"
    p = run("example.com", "--config", str(cfg), "--no-notify", "--out", str(out), *OFFLINE)
    assert p.returncode in (0, 1), p.stderr
    assert (out / "latest" / "domains.txt").read_text(encoding="utf-8").strip() == "example.com"


def test_unknown_settings_key_is_a_usage_error(tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text("[audit]\nbogus = 1\n", encoding="utf-8")
    p = run("example.com", "--config", str(cfg), "--no-notify", "--out", str(tmp_path / "out"), *OFFLINE)
    assert p.returncode == 2 and "bogus" in p.stderr and "Traceback" not in p.stderr


def test_todo_strict_and_first_seen_senders(tmp_path):
    out = tmp_path / "out"
    p1 = run("example.com", "--no-config", "--no-notify", "--strict", "--out", str(out), *OFFLINE)
    assert p1.returncode == 1, p1.stderr
    todo = (out / "latest" / "todo.md").read_text(encoding="utf-8")
    assert "## 3. Fix senders (DKIM first)" in todo and "passes on SPF alone" in todo
    assert "## Where each domain stands" in todo
    run_doc = json.loads((out / "latest" / "run.json").read_text(encoding="utf-8"))
    assert any("gate no_go" in r for r in run_doc["strict_reasons"])
    assert "strict:" in p1.stderr
    senders = json.loads((out / "senders.json").read_text(encoding="utf-8"))["senders"]
    assert any(k.startswith("ip:") for k in senders) and any(k.startswith("envelope:") for k in senders)
    assert "baseline run" in (out / "latest" / "summary.txt").read_text(encoding="utf-8")
    p2 = run("example.com", "--no-config", "--no-notify", "--out", str(out), *OFFLINE)
    assert p2.returncode in (0, 1), p2.stderr
    summary = (out / "latest" / "summary.txt").read_text(encoding="utf-8")
    assert "newly identified senders: none" in summary and "trend over the last 2 runs" in summary


def test_notify_switch_off_prints_instead_of_posting(tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text("[notify]\nenabled = false\n", encoding="utf-8")
    p = run("example.com", "--config", str(cfg), "--out", str(tmp_path / "out"), *OFFLINE,
            env_extra={"SLACK_WEBHOOK_URL": "https://hooks.example/never-called"})
    assert p.returncode in (0, 1), p.stderr
    assert "summary not posted: [notify] enabled = false" in p.stderr
    assert "*DMARC audit*" in p.stdout
