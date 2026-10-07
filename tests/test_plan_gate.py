"""plan.py holds for DKIM-before-reject: SPF-only senders from the mail log,
a run with no aligned-DKIM evidence, rua streams under the label rua_parse
really emits, and streams the gate formally excepted. No network."""

import plan


def dns_quarantine_100():
    return {"example.com": {"domain": "example.com", "spf": "v=spf1 include:mail.example -all", "spf_status": "found",
                            "spf_terminator": "-all", "spf_lookups": 1, "spf_lookups_failed": 0, "spf_verified": True,
                            "dmarc": "v=DMARC1; p=quarantine; pct=100; rua=mailto:r@example.com;",
                            "dmarc_source": "_dmarc.example.com", "effective_policy": "quarantine", "inherited": False,
                            "dmarc_status": "found", "dkim_selectors": ["selector1"], "dkim_status": "found",
                            "mx": ["10 mail.example"], "mx_null": False, "mx_status": "found", "flags": [],
                            "findings": [], "evidence": []}}


def make_report(maillog=None, rua=None, gate_exceptions=None):
    return {"generated_utc": "2026-01-01T00:00:00Z", "dns": dns_quarantine_100(), "inputs": {"domains": ["example.com"]},
            "gate": {"domains": {}, "exceptions": gate_exceptions or {}}, "findings": [], "maillog": maillog, "rua": rua}


def reject_step(p):
    return next(c for c in p["changes"] if c["kind"] == "ratchet" and "p=reject" in c["value"])


def test_mail_log_spf_only_senders_hold_the_reject_step():
    ml = {"sender_domain": "example.com", "counters": {"by_likely": {}}, "alignment": {"available": True},
          "spf_only_senders": [{"sender": "billing@example.com", "domain": "example.com", "spf_only": 2}]}
    step = reject_step(plan.build_plan(make_report(maillog=ml)))
    joined = " ".join(step["prerequisites"])
    assert "billing@example.com (mail log, 2 msgs)" in joined and "aligned DKIM first" in joined
    assert "no aligned-DKIM evidence" not in joined


def test_no_dkim_evidence_holds_the_reject_step():
    ml = {"sender_domain": "example.com", "counters": {"by_likely": {}}, "alignment": {"available": False},
          "spf_only_senders": []}
    step = reject_step(plan.build_plan(make_report(maillog=ml)))
    assert any("no aligned-DKIM evidence" in x for x in step["prerequisites"])


def test_rua_stream_holds_under_the_real_label_unless_excepted():
    stream = {"source_ip": "192.0.2.9", "count": 50, "header_from": ["example.com"], "likely": "likely_misconfigured",
              "likely_signals": ["DKIM verifies for d=vendor.example but is not aligned"]}
    rua = {"totals": {"messages": 500}, "failing_streams": [stream], "spf_only_senders": []}
    step = reject_step(plan.build_plan(make_report(rua=rua)))
    assert any("192.0.2.9" in x and "likely_misconfigured" in x for x in step["prerequisites"])
    excepted = make_report(rua=rua, gate_exceptions={"excepted_streams": ["192.0.2.9"]})
    step = reject_step(plan.build_plan(excepted))
    assert not any("192.0.2.9" in x for x in step["prerequisites"])
    # spoofs never hold: enforcement is what stops them
    rua["failing_streams"] = [dict(stream, likely="likely_spoof")]
    step = reject_step(plan.build_plan(make_report(rua=rua)))
    assert not any("192.0.2.9" in x for x in step["prerequisites"])


def test_the_hold_counts_the_domains_own_rows_when_the_report_attributes_them():
    ml = {"sender_domain": None, "counters": {"by_likely": {"likely_misconfigured_sender": 155}},
          "alignment": {"available": True}, "spf_only_senders": [],
          "by_domain": {"example.com": {"by_likely": {"likely_misconfigured_sender": 90}}}}
    rep = make_report(maillog=ml, gate_exceptions={"excepted_maillog_failures": 7})
    rep["gate"]["domains"] = {"example.com": {"excepted_failures": 2}}
    ev = plan.evidence_for(rep, "example.com")
    assert ev["legit_failing"][0].startswith("90 message(s) in the mail log")
    assert "(2 failure(s) are excepted in the gate)" in ev["legit_failing"][0]
    del ml["by_domain"]  # a report without the attribution falls back to the whole log, as before
    ev = plan.evidence_for(rep, "example.com")
    assert ev["legit_failing"][0].startswith("155 message(s) in the mail log")
    assert "(7 failure(s) are excepted in the gate)" in ev["legit_failing"][0]
