"""notify.py across runs: first-seen senders from the whole history, the trend
line, and the payload seam that keeps Teams designed in without shipping it."""

import pytest

import notify


def report(sources=("192.0.2.10",), envelopes=("example.com",), failures=21, pass_rate=0.77):
    return {
        "generated_utc": "2026-01-15T06:00:00Z",
        "gate": {"domains": {"example.com": {"current_policy": "quarantine", "verdict": "no_go", "next_step": "p=reject"}}},
        "summary": {"findings": 0, "by_severity": {}},
        "findings": [],
        "maillog": {"counters": {"genuine_failures": failures, "raw_failing_rows": failures + 5,
                                 "delivered_despite_fail": 0, "by_likely": {"likely_spoof": 0}},
                    "verdicts": [{"sender": "x@example.com", "envelope_domain": e} for e in envelopes]},
        "rua": {"totals": {"messages": 100, "pass_rate": pass_rate, "by_disposition": {"reject": 3, "quarantine": 0}},
                "by_source_ip": [{"source_ip": ip, "count": 10} for ip in sources]},
    }


def test_sender_keys_cover_source_ips_and_envelope_domains():
    keys = notify.sender_keys(report(sources=("192.0.2.10", "198.51.100.7"), envelopes=("example.com", "bounce.vendor.example")))
    assert keys == {"ip:192.0.2.10", "ip:198.51.100.7", "envelope:example.com", "envelope:bounce.vendor.example"}


def test_first_run_is_a_baseline_and_later_runs_name_only_never_seen_senders():
    rep = report(sources=("192.0.2.10", "198.51.100.7"), envelopes=("example.com", "bounce.vendor.example"))
    text = notify.summarize(rep, known_senders=set())
    assert "baseline run: 4 sender identities recorded" in text
    known = {"ip:192.0.2.10", "envelope:example.com", "ip:203.0.113.5"}  # seen weeks ago, absent last week
    text = notify.summarize(rep, previous=report(sources=()), known_senders=known)
    assert "*newly identified senders* (never seen in an earlier run): bounce.vendor.example (envelope), 198.51.100.7" in text
    assert "newly seen senders" not in text  # the previous-run comparison is not used when history is known
    text = notify.summarize(rep, known_senders=known | {"ip:198.51.100.7", "envelope:bounce.vendor.example"})
    assert "newly identified senders: none" in text


def test_without_history_the_previous_run_comparison_still_applies():
    text = notify.summarize(report(sources=("192.0.2.10", "198.51.100.7")), previous=report(sources=("192.0.2.10",)))
    assert "*newly seen senders*: 198.51.100.7" in text


def test_trend_line_over_the_last_runs():
    history = [{"genuine_failures": 30, "rua_pass_rate": 0.70}, {"genuine_failures": 25, "rua_pass_rate": 0.72},
               {"genuine_failures": 21, "rua_pass_rate": 0.77}]
    text = notify.summarize(report(), history=history)
    assert "trend over the last 3 runs (improving): genuine failures 30, 25, 21; pass rate 70.0%, 72.0%, 77.0%" in text
    assert "trend" not in notify.summarize(report(), history=history[:1])
    assert notify.trend_word([21, 30]) == "worsening" and notify.trend_word([21, None, 21]) == "flat"
    assert notify.trend_word([None, 5]) == "too few runs to call"


def test_payload_seam_and_target_detection():
    assert notify.build_payload("hi", "slack") == {"text": "hi"}
    assert notify.build_payload("hi", "teams") == {"text": "hi"}
    with pytest.raises(ValueError):
        notify.build_payload("hi", "pager")
    assert notify.target_for("https://hooks.slack.com/services/x") == "slack"
    assert notify.target_for("https://example.webhook.office.com/webhookb2/x") == "teams"
    assert notify.target_for(None) == "slack"


def test_the_message_names_domains_never_addresses():
    census = {"by_envelope": [{"envelope_domain": "bounce.vendor.example", "genuine_failures": 7, "likely": "likely_misconfigured_sender"},
                              {"envelope_domain": "spam.invalid", "genuine_failures": 3, "likely": "likely_spoof"}],
              "by_sender": [{"sender": "billing@example.com", "domain": "example.com",
                             "envelope_domain": "bounce.vendor.example", "genuine_failures": 7, "likely": "likely_misconfigured_sender"}]}
    labels, failing = notify.census_top(census)
    assert labels == ["bounce.vendor.example x7 (likely_misconfigured_sender)", "spam.invalid x3 (likely_spoof)"] and failing == 2
    labels, failing = notify.census_top({"by_sender": census["by_sender"] + [
        {"sender": "alerts@example.com", "domain": "example.com", "envelope_domain": "bounce.vendor.example",
         "genuine_failures": 2, "likely": "likely_misconfigured_sender"}]})
    assert labels == ["example.com via bounce.vendor.example x9 (likely_misconfigured_sender)"] and failing == 1
    rep = report()
    rep["maillog"]["census"] = census
    text = notify.summarize(rep)
    assert "@" not in text.split("top failing senders (census): ")[1].splitlines()[0]


def test_the_trend_word_falls_back_to_the_pass_rate():
    history = [{"genuine_failures": None, "rua_pass_rate": 0.70}, {"genuine_failures": None, "rua_pass_rate": 0.77}]
    text = notify.summarize(report(), history=history)
    assert "trend over the last 2 runs (improving): pass rate 70.0%, 77.0%" in text
    history = [{"genuine_failures": None, "rua_pass_rate": 0.80}, {"genuine_failures": None, "rua_pass_rate": 0.72}]
    assert "(worsening)" in notify.summarize(report(), history=history)


def test_a_domain_without_a_record_is_not_p_none():
    rep = report()
    rep["gate"]["domains"]["example.com"]["current_policy"] = None
    # round 13, T-12: a policy the run did not read is said in words (here DNS was not read), never p=unknown
    text = notify.summarize(rep)
    assert "- `example.com`: not read, gate *no_go*" in text and "p=unknown" not in text and "p=None" not in text
    rep["dns"] = {"example.com": {"domain": "example.com", "dmarc": None, "dmarc_status": "absent"}}
    assert "- `example.com`: no DMARC record, gate *no_go*" in notify.summarize(rep)


def test_the_cli_counts_the_runs_own_new_senders_as_new_and_checks_the_file(tmp_path):
    import json as _json
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path
    rep = report(sources=("192.0.2.10", "198.51.100.7"), envelopes=("example.com",))
    run_dir = tmp_path / "latest"
    run_dir.mkdir()
    (run_dir / "report.json").write_text(_json.dumps(rep), encoding="utf-8")
    (run_dir / "run.json").write_text(_json.dumps({"run": "2026-10-07T150000Z"}), encoding="utf-8")
    senders = tmp_path / "senders.json"
    senders.write_text(_json.dumps({"updated": "2026-10-07T150000Z", "senders": {
        "ip:192.0.2.10": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
        "envelope:example.com": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
        "ip:198.51.100.7": {"first_seen": "2026-10-07T150000Z", "last_seen": "2026-10-07T150000Z"}}}), encoding="utf-8")
    script = str(_Path(notify.__file__))
    p = subprocess.run([_sys.executable, script, "--report", str(run_dir / "report.json"), "--senders", str(senders),
                        "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "*newly identified senders* (never seen in an earlier run): 198.51.100.7" in p.stdout
    for bad in ("[]", '{"not": "senders"}'):
        senders.write_text(bad, encoding="utf-8")
        p = subprocess.run([_sys.executable, script, "--report", str(run_dir / "report.json"), "--senders", str(senders),
                            "--dry-run"], capture_output=True, text=True)
        assert p.returncode == 2 and "expected the senders.json collect.py writes" in p.stderr


def test_no_pass_rate_jump_against_an_empty_outside_view():
    now = report(pass_rate=0.98)
    now["rua"]["totals"]["messages"] = 828000
    prev = report(pass_rate=0.0)
    prev["rua"]["totals"]["messages"] = 40
    text = notify.summarize(now, previous=prev)
    assert "pass rate vs last run" not in text
    assert "outside view not comparable with last run (828000 messages now, 40 then): no pass-rate delta" in text
    now["delta"] = {"previous_generated_utc": "2026-01-08T06:00:00Z", "rua": {"comparable": True, "pass_rate_change": 2.5,
                                                                            "now_messages": 100, "previous_messages": 90}}
    assert "- pass rate vs last run: +2.5 points" in notify.summarize(now, previous=prev)


def test_sender_keys_come_from_the_census_when_the_verdicts_are_gone():
    rep = report(envelopes=("example.com",))
    rep["maillog"]["verdicts"] = []
    rep["maillog"]["census"] = {"by_envelope": [{"envelope_domain": "bounce.vendor.example", "genuine_failures": 0},
                                                 {"envelope_domain": "(blank)", "genuine_failures": 0}]}
    assert notify.sender_keys(rep) == {"ip:192.0.2.10", "envelope:bounce.vendor.example"}


def test_the_trend_word_does_not_compare_failure_counts_across_different_spans():
    history = [{"genuine_failures": 118, "rua_pass_rate": 0.70, "maillog_hours": 720.0},
               {"genuine_failures": 120, "rua_pass_rate": 0.72, "maillog_hours": 720.0},
               {"genuine_failures": 5, "rua_pass_rate": 0.69, "maillog_hours": 41.0}]
    text = notify.summarize(report(), history=history)
    assert "(improving)" not in text and "(worsening)" in text  # the pass rate fell: that is the word
    assert "genuine failures 118, 120, 5" in text and "failure counts not compared: the mail-log spans differ" in text
    history[2]["maillog_hours"] = 700.0
    assert "(improving)" in notify.summarize(report(), history=history)
    assert "trend over the last 2 runs" in notify.summarize(report(), history=[1, history[0], history[1]])  # a corrupt entry is skipped


def test_two_empty_outside_views_say_nothing_about_the_pass_rate():
    now, prev = report(pass_rate=0.0), report(pass_rate=0.0)
    now["rua"]["totals"]["messages"] = prev["rua"]["totals"]["messages"] = 0
    text = notify.summarize(now, previous=prev)
    assert "not comparable" not in text and "pass rate vs last run" not in text


def test_counts_and_the_sender_history_see_every_source_when_the_tables_are_capped():
    rep = report(sources=("192.0.2.10",))
    rep["rua"]["source_ips"] = ["192.0.2.10", "198.51.100.7", "203.0.113.9"]
    rep["rua"]["unknown_senders"] = [{"kind": "ip", "value": "198.51.100.7", "count": 9}]
    rep["rua"]["truncated"] = {"by_source_ip": {"kept": 1, "total": 3}, "unknown_senders": {"kept": 1, "total": 1200}}
    rep["rua"]["filters"] = {"known": {"given": True, "ip_check": True, "networks": ["192.0.2.0/24"]}}
    assert notify.sender_keys(rep) >= {"ip:192.0.2.10", "ip:198.51.100.7", "ip:203.0.113.9"}
    text = notify.summarize(rep, previous=report(sources=("192.0.2.10",)))
    # the IPs outside the prefixes, recounted over every source (the table's other entries are signing domains)
    assert "unknown senders in reports: 2 (top: ip 198.51.100.7); 1198 signing domains not in the known list" in text
    assert "*newly seen senders*: 198.51.100.7, 203.0.113.9" in text


def test_a_report_without_a_run_stamp_counts_every_recorded_sender_as_known(tmp_path):
    import json as _json
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path
    rep = report(sources=("192.0.2.10", "198.51.100.7"), envelopes=("example.com",))
    rep["generated_utc"] = "2026-10-08T09:00:00Z"  # audit.py's own run, the day after the last collect run
    (tmp_path / "report.json").write_text(_json.dumps(rep), encoding="utf-8")
    senders = tmp_path / "senders.json"
    senders.write_text(_json.dumps({"updated": "2026-10-07T150000Z", "senders": {
        "ip:192.0.2.10": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
        "envelope:example.com": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
        "ip:198.51.100.7": {"first_seen": "2026-10-07T150000Z", "last_seen": "2026-10-07T150000Z"}}}), encoding="utf-8")
    script = str(_Path(notify.__file__))
    p = subprocess.run([_sys.executable, script, "--report", str(tmp_path / "report.json"), "--senders", str(senders),
                        "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "newly identified senders: none" in p.stdout  # 198.51.100.7 was seen, and announced, by the last run
    (tmp_path / "metrics.json").write_text("[1, 2]", encoding="utf-8")
    p = subprocess.run([_sys.executable, script, "--report", str(tmp_path / "report.json"), "--metrics",
                        str(tmp_path / "metrics.json"), "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 2 and "expected the metrics list collect.py writes" in p.stderr


def test_the_trend_word_honours_the_cuts_each_run_recorded():
    history = [{"genuine_failures": 2187, "rua_pass_rate": 0.70, "maillog_hours": 719.0, "maillog_cut_orgs": []},
               {"genuine_failures": 700, "rua_pass_rate": 0.69, "maillog_hours": 719.0, "maillog_cut_orgs": ["corp.example"]}]
    text = notify.summarize(report(), history=history)
    assert "(improving)" not in text and "(worsening)" in text
    assert "failure counts not compared: the mail log was cut for corp.example in the last run" in text
    history[1]["maillog_cut_orgs"] = []
    assert "(improving)" in notify.summarize(report(), history=history)
    rep = report()
    rep["delta"] = {"previous_generated_utc": "2026-01-08T06:00:00Z", "maillog_window": {"comparable": False}}
    assert "(improving)" in notify.summarize(rep, history=history)  # the entries carry each run's own figures
    # a span of minutes stored as 0.0 hours is a span, and with no pass rate the word says what it is
    history = [{"genuine_failures": 2187, "maillog_hours": 719.0}, {"genuine_failures": 3, "maillog_hours": 0.0}]
    text = notify.summarize(report(), history=history)
    assert "(not comparable)" in text and "too few runs" not in text
    assert notify._spans_alike([0.0, 0.3]) is True and notify._spans_alike([None, 5.0]) is True and notify._spans_alike([41.0, 719.0]) is False


def test_a_collect_report_copied_away_from_its_run_json_still_announces_that_runs_new_senders(tmp_path):
    import json as _json
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path
    rep = report(sources=("192.0.2.10", "198.51.100.7"), envelopes=("example.com",))
    rep["generated_utc"] = "2026-10-07T15:12:30Z"  # twelve minutes into the run that wrote senders.json
    rep["inputs"] = {"run": "2026-10-07T150000Z"}  # collect.py names its run in the report itself
    (tmp_path / "report.json").write_text(_json.dumps(rep), encoding="utf-8")
    senders = tmp_path / "senders.json"
    senders.write_text(_json.dumps({"updated": "2026-10-07T150000Z", "senders": {
        "ip:192.0.2.10": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
        "envelope:example.com": {"first_seen": "2026-09-30T060000Z", "last_seen": "2026-10-07T150000Z"},
        "ip:198.51.100.7": {"first_seen": "2026-10-07T150000Z", "last_seen": "2026-10-07T150000Z"}}}), encoding="utf-8")
    p = subprocess.run([_sys.executable, str(_Path(notify.__file__)), "--report", str(tmp_path / "report.json"),
                        "--senders", str(senders), "--dry-run"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "*newly identified senders* (never seen in an earlier run): 198.51.100.7" in p.stdout
