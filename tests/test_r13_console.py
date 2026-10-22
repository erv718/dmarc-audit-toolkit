"""Round 13, T-04: the terminal's last lines and the Slack summary lead with the status band.

collect.py ends, after every note, with a done line (the exit code and what it means), the band in plain words,
the run folder and the file to open first; it never echoes the summary unlabeled - it says summary.txt was written
and why it was not posted, or prints it under a dry-run header. summary.txt opens with the date and the band's
headline, one line per most critical organization, what changed and where the full brief is, then its details:
the per-domain lines for the domains the band does not lead with that have failures or a change, and every domain
of a cut organization, the rest counted on one line. Aggregates only: never an address or a subject. notify.py
run on its own builds the same band. Synthetic data, offline: nothing here touches the network."""

import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import audit
import collect
import discover
import dns_audit
import next_steps
import notify
import r13_fixtures as F
import test_r10_phase2 as phase2  # the in-memory tenant collect.py runs against

ROOT = Path(__file__).resolve().parent.parent


def no_network(monkeypatch):
    def refuse(*a, **k):
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for key in notify.WEBHOOK_KEYS + ("RUA_MAILBOX",):
        monkeypatch.delenv(key, raising=False)


def tenant_run(monkeypatch, capsys, out, *extra, config=None):
    """collect.main against the in-memory tenant (hunting answered in memory, DNS stubbed, no sign-in): (exit code,
    stdout, stderr, latest folder). Its env file is one that does not exist: no .env is ever read. config: a
    settings file to read instead of none."""
    no_network(monkeypatch)
    now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
    t = phase2.Tenant(phase2.tenant_legs(now), {"corp.example": {"schema": phase2.TOTALS["schema"],
                                                                  "results": phase2.TOTALS["results"][:4]}})
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    monkeypatch.setattr(collect.graph_client, "creds", lambda env_file=None: ("tenant", "client", "secret"))
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    monkeypatch.setattr(collect.graph_client, "token", lambda cred: "second")
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([], None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
    monkeypatch.setattr(audit, "run_dns", phase2.live_dns)
    monkeypatch.setattr(dns_audit, "resolve_ex", lambda resolver, name, rtype: (
        [], {"path": "stub", "ttl": None, "status": "absent"}))
    monkeypatch.setattr(collect, "ROW_CAP", 300)
    monkeypatch.setattr(collect, "SLICE_TARGET", 270)
    monkeypatch.setattr(sys, "argv", ["collect.py", "corp.example", "hr.corp.example", "shop.example", "parked.example",
                                      *(("--config", str(config)) if config else ("--no-config",)),
                                      "--no-owners", "--out", str(out), "--env-file",
                                      str(out.parent / "no-such.env")] + list(extra))
    capsys.readouterr()
    code = None
    try:
        collect.main()
    except SystemExit as exc:
        code = exc.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err, out / "latest"


def test_the_run_ends_with_what_to_read_first(monkeypatch, capsys, tmp_path):
    code, out, err, latest = tenant_run(monkeypatch, capsys, tmp_path / "out", "--max-rows", "1500")
    doc = json.loads((latest / "next_steps.json").read_text(encoding="utf-8"))
    run = json.loads((latest / "run.json").read_text(encoding="utf-8"))
    top = doc["top"]
    lines = out.splitlines()
    # no webhook: the run says where the summary is and why it was not posted, never the text itself
    assert lines[0] == "summary.txt written (not posted: no SLACK_WEBHOOK_URL)" and lines[1] == ""
    assert "*DMARC" not in out
    last = lines[2:]
    assert last[0] == "done: 4 domains in 3 organizations audited - exit %d: %s" % (
        code, collect.EXIT_MEANING[code])
    assert last[1:-2] == top["lines_plain"] and last[1] == top["headline"]
    numbered = [line for line in last if re.match(r"^  \d\. ", line)]
    assert 1 <= len(numbered) <= next_steps.TOP_SHOW
    assert last[-3].startswith("Not in this data: ") and last[-3].endswith("bounces and lost mail - use message trace")
    assert last[-4].startswith("Since last run: ")
    assert last[-2] == "run %s: %s" % (run["run"], tmp_path / "out" / "history" / run["run"])
    assert last[-1] == "Open first: %s  (detail: next_steps.md; records: plan.md; how to check: verify.md)" % (
        latest / "brief.html")
    assert len(last) <= 12 and "next steps:" not in out and "latest:" not in out
    assert not any("@" in line for line in last)
    # summary.txt: the date and the band's headline first
    summary = (latest / "summary.txt").read_text(encoding="utf-8")
    assert summary.splitlines()[0] == "*DMARC %s* - %s" % (doc["date"], top["headline"])
    assert "@" not in summary
    # the cut organization keeps one line under the details (review round 13): its floor, and the whole
    # organization's full window beside it
    details = summary.split("\nDetails:\n", 1)[1]
    corp = next(line for line in details.splitlines() if line.startswith("- `corp.example`"))
    assert corp.startswith("- `corp.example` and its 1 name below it: ") and "in the rows kept (" in corp
    assert corp.endswith(
        "; over the full 30 days, counted in Advanced Hunting: 160 genuine failures, 15 delivered despite failing")
    assert last[-5] == next_steps.call_line_plain(top["call"]) and last[-5].startswith("Your call: ")


def test_a_dry_run_prints_the_summary_under_its_header_and_no_notify_says_nothing(monkeypatch, capsys, tmp_path):
    code, out, err, latest = tenant_run(monkeypatch, capsys, tmp_path / "dry", "--dry-run")
    summary = (latest / "summary.txt").read_text(encoding="utf-8")
    assert out.startswith(collect.DRY_RUN_HEADER + "\n" + summary)
    assert collect.DRY_RUN_HEADER == "Slack summary (dry run, not posted):"
    code, out, err, latest = tenant_run(monkeypatch, capsys, tmp_path / "quiet", "--no-notify")
    assert out.startswith("\ndone: ") and "summary.txt" not in out and "*DMARC" not in out


def test_the_change_window_in_audit_toml_ends_the_ask_and_the_call(monkeypatch, capsys, tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text("[brief]\nchange_window = \"Thursday 18:00-20:00 UTC\"\napprover = \"IT change board\"\n",
                   encoding="utf-8")
    code, out, err, latest = tenant_run(monkeypatch, capsys, tmp_path / "out", "--no-notify", config=cfg)
    doc = json.loads((latest / "next_steps.json").read_text(encoding="utf-8"))
    tail = " - window: Thursday 18:00-20:00 UTC; approver: IT change board."
    assert doc["ask"].endswith(tail) and doc["top"]["call"]["text"].endswith(tail)
    assert doc["ask_parts"]["window"] == "Thursday 18:00-20:00 UTC"
    assert tail.rstrip(".") in (latest / "next_steps.md").read_text(encoding="utf-8")


def test_strict_says_why_it_exits_one(monkeypatch, capsys, tmp_path):
    code, out, err, latest = tenant_run(monkeypatch, capsys, tmp_path / "strict", "--no-notify", "--strict")
    run = json.loads((latest / "run.json").read_text(encoding="utf-8"))
    assert code == 1 and run["strict_reasons"]
    assert "done: 4 domains in 3 organizations audited - exit 1: --strict (%s)" % run["strict_reasons"][0] in out


def test_the_notify_switch_says_why_nothing_was_posted(tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text("[notify]\nenabled = false\n\n[brief]\nchange_window = \"Thursday 18:00 UTC\"\n", encoding="utf-8")
    import subprocess
    p = subprocess.run([sys.executable, str(ROOT / "src" / "collect.py"), "example.com", "--config", str(cfg), "--out",
                        str(tmp_path / "out"), "--offline", "--rua", str(ROOT / "samples" / "rua"), "--maillog",
                        str(ROOT / "samples" / "sample_maillog.csv"), "--auth-column", "DMARC"],
                       capture_output=True, text=True, cwd=str(tmp_path))
    assert p.returncode in (0, 1), p.stderr
    assert p.stdout.startswith("summary.txt written (not posted: [notify] enabled = false in audit.toml)\n\ndone: ")
    # audit.toml's [brief] table is read; an offline run builds no plan, so nothing is asked and no window named
    doc = json.loads((tmp_path / "out" / "latest" / "next_steps.json").read_text(encoding="utf-8"))
    assert doc["ask_parts"] is None and "window" not in doc["ask"] and "window" not in doc["top"]["call"]["text"]


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_console_estate"))


def test_summary_txt_leads_with_the_band_and_counts_the_quiet_domains(estate):
    rep, plan, doc = estate["report"], estate["plan"], estate["doc"]
    text = notify.summarize(rep, plan=plan, top=doc["top"])
    lines = text.splitlines()
    # the call in plain words on a line of its own, its ids when rows are ready (review round 13)
    assert lines[:10] == [
        "*DMARC 2026-10-09* - Partly: 2 of 9 domains block spoofed mail. Urgent: spoofed mail reached inboxes on "
        "example.com and brand.example. Your call: nothing to approve yet - 9 DNS records wait on checks.",
        "1. `example.com` urgent - spoofed mail reached inboxes - 7 messages",
        "2. `brand.example` urgent - spoofed mail reached inboxes - 4 messages",
        "3. `example.org` no record - anyone can send as it; nothing sent or received in 30 days",
        "4. `parked.example` no record - anyone can send as it; nothing sent or received in 30 days",
        "5. `example.net` reports only - small failures only (6, under 10)",
        "Your call: nothing to approve yet; 9 wait on checks; 2 need their DNS host found first; 3 not this week; "
        "decide 1 plan hold (example.com).",
        "Since last run: first run - this is the baseline.",
        "Not in this data: bounces and lost mail - use message trace",
        "Full brief: brief.html in audit-out/latest (inside the company only)"]
    assert len(" ".join(lines[:lines.index("Details:")]).split()) <= 200
    # under the details: pay.example.com fails and the strip does not lead with it; its line stays. The quiet
    # subdomains are counted; the strip's own lines are not said twice
    details = lines[lines.index("Details:") + 1:]
    kept = [line for line in details if line.startswith("- `")]
    assert len(kept) == 1 and kept[0].startswith("- `pay.example.com`: p=none, gate *no_go*, next: ")
    assert kept[0].endswith(" - 9 genuine failures of its own")
    assert "- 3 more domains: no failures, no change (brief.html Per domain)" in details
    assert details[-1].startswith("- plan: 14 change(s) waiting")
    assert "@" not in text


def test_notify_on_its_own_says_what_collect_says(estate, tmp_path):
    rep, plan, doc = estate["report"], estate["plan"], estate["doc"]
    built = next_steps.build(rep, plan)  # as notify.py builds it: no owners, the report's own date
    assert notify.summarize(rep, plan=plan) == notify.summarize(rep, plan=plan, top=built["top"])
    # a band from another document never changes the details, only the lead
    assert notify.summarize(rep, plan=plan).split("\nDetails:\n", 1)[1] == notify.summarize(
        rep, plan=plan, top=doc["top"]).split("\nDetails:\n", 1)[1]
    # a report that gives no document keeps the message's older first line
    assert notify.summarize({"generated_utc": "2026-10-09T06:00:00Z"}).startswith("*DMARC audit* 2026-10-09 06:00")


def test_no_summary_carries_an_address_or_a_subject(estate, tmp_path):
    runs = [estate, F.incident(tmp_path / "incident"), F.first_run(tmp_path / "first"),
            F.first_run(tmp_path / "rua", F.FR_RUA), F.stress(tmp_path / "stress")]
    for run in runs:
        text = notify.summarize(run["report"], plan=run["plan"], top=run["doc"]["top"])
        assert "@" not in text, text
        census = run["report"]["maillog"]["census"]["by_sender"]
        for r in census:
            subject = str(r.get("sample_subject") or "")
            assert not subject or subject not in text, subject
