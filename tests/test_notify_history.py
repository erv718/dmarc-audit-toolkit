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
