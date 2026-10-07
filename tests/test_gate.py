"""The gate's DKIM-before-reject rule and the formal exceptions, with synthetic
inputs and no network: Gate B from the mail log's SPF/DKIM columns, the
insufficient_data verdict when no aligned-DKIM evidence exists, and the
audit.toml exceptions that lift (or, once expired, stop lifting) a blocker."""

import csv

import audit

COLS = ["Internet message ID", "Recipients", "Sender address", "Sender domain", "Sender mail from domain",
        "Delivery action", "Latest delivery location", "Subject", "DMARC", "SPF", "DKIM"]


def write_log(path, rows, with_alignment=True):
    cols = COLS if with_alignment else COLS[:-2]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in rows:
            w.writerow(r if with_alignment else r[:-2])
    return str(path)


def passing(msgid, sender, envelope, spf, dkim, rcpt="u1@example.com"):
    return [msgid, rcpt, sender, "example.com", envelope, "Delivered", "Inbox/folder", "Statement", "pass", spf, dkim]


def failing(msgid, sender, envelope, rcpt="u1@example.com"):
    return [msgid, rcpt, sender, "example.com", envelope, "Quarantined", "Quarantine", "Invoice", "fail", "fail", "none"]


def dns(policy="quarantine", pct="100"):
    record = "v=DMARC1; p=%s; pct=%s; rua=mailto:reports@example.com;" % (policy, pct)
    return {"example.com": {"domain": "example.com", "dmarc": record, "dmarc_source": "_dmarc.example.com",
                            "effective_policy": policy, "inherited": False, "dmarc_status": "found",
                            "spf": "v=spf1 include:mail.example -all", "spf_status": "found", "spf_terminator": "-all",
                            "spf_lookups": 1, "findings": []}}


def gate(dns_reports, maillog_doc, rua_doc=None, exceptions=None):
    return audit.gate_verdict(dns_reports, rua_doc, maillog_doc, ["example.com"], exceptions=exceptions)


def test_spf_only_sender_in_the_mail_log_blocks_the_move_to_reject(tmp_path):
    log = write_log(tmp_path / "log.csv", [
        passing("<m1@a>", "billing@example.com", "example.com", "pass", "none"),
        passing("<m2@a>", "news@example.com", "bounce.vendor.example", "fail", "pass"),
    ])
    doc = audit.run_maillog(log, auth_column="DMARC")
    assert doc["alignment"]["available"] and doc["alignment"]["spf_only"] == 1
    assert doc["spf_only_senders"][0]["sender"] == "billing@example.com"
    g = gate(dns(), doc)
    assert g["verdict"] == "no_go"
    assert any("pass on SPF alone" in r for r in g["domains"]["example.com"]["reasons"])
    assert g["evidence"]["dkim_evidence"] is True


def test_no_dkim_evidence_at_all_makes_the_reject_step_insufficient_data(tmp_path):
    log = write_log(tmp_path / "log.csv", [passing("<m1@a>", "hr@example.com", "example.com", "pass", "pass")],
                    with_alignment=False)
    doc = audit.run_maillog(log, auth_column="DMARC")
    assert doc["alignment"]["available"] is False
    g = gate(dns("quarantine", "100"), doc)
    assert g["verdict"] == "insufficient_data"
    assert any("no aligned-DKIM evidence" in r for r in g["reasons"])
    # the same run at p=none is a go: DKIM evidence is demanded for the move to reject, not before
    assert gate(dns("none"), doc)["verdict"] == "go"
    # and at quarantine with a partial pct the step is raising pct, not the reject move
    assert gate(dns("quarantine", "25"), doc)["verdict"] == "go"


def test_dkim_carried_mail_clears_the_reject_step(tmp_path):
    log = write_log(tmp_path / "log.csv", [passing("<m1@a>", "news@example.com", "bounce.vendor.example", "fail", "pass")])
    doc = audit.run_maillog(log, auth_column="DMARC")
    assert doc["alignment"]["dkim_aligned"] == 1 and not doc["spf_only_senders"]
    assert gate(dns(), doc)["verdict"] == "go"


def test_exception_lifts_a_mail_log_blocker_until_it_expires(tmp_path):
    log = write_log(tmp_path / "log.csv", [
        passing("<m1@a>", "news@example.com", "bounce.vendor.example", "fail", "pass"),
        failing("<m2@a>", "printer@example.com", "printer.vendor.example"),
    ])
    doc = audit.run_maillog(log, auth_column="DMARC")
    assert doc["counters"]["genuine_failures"] == 1
    blocked = gate(dns(), doc)
    assert blocked["verdict"] == "no_go"
    exc = {"match": "vendor.example", "reason": "printer, SPF-only by design", "owner": "facilities",
           "until": "2099-01-01", "removal_criterion": "printer replaced"}
    lifted = gate(dns(), doc, exceptions=[exc])
    assert lifted["verdict"] == "go"
    reasons = " ".join(lifted["reasons"])
    assert "exception: 1 mail-log failure(s) from vendor.example excepted until 2099-01-01" in reasons
    assert "remove when printer replaced" in reasons
    assert lifted["exceptions"]["applied"][0]["match"] == "vendor.example"
    assert lifted["exceptions"]["excepted_maillog_failures"] == 1
    expired = gate(dns(), doc, exceptions=[dict(exc, until="2020-01-01")])
    assert expired["verdict"] == "no_go"
    assert any("expired 2020-01-01" in r for r in expired["reasons"])
    incomplete = gate(dns(), doc, exceptions=[{"match": "vendor.example", "reason": "no date"}])
    assert incomplete["verdict"] == "no_go"
    assert any("not applied: missing until, removal_criterion" in r for r in incomplete["reasons"])


def test_exception_lifts_a_rua_stream_by_prefix():
    rua_doc = {"totals": {"reports": 2, "messages": 500},
               "policy_check": {"seen": []},
               "failing_streams": [{"source_ip": "192.0.2.9", "count": 50, "fail": 50, "likely": "unknown",
                                    "dispositions": {"quarantine": 50}, "header_from": ["example.com"],
                                    "spf_domains": ["vendor.example"], "dkim_domains": []}],
               "spf_only_senders": []}
    blocked = gate(dns(), None, rua_doc)
    assert blocked["verdict"] == "no_go" and any("192.0.2.9 fails DMARC" in r for r in blocked["reasons"])
    exc = {"match": "192.0.2.0/24", "reason": "list server", "until": "2099-01-01", "removal_criterion": "list retired"}
    lifted = gate(dns(), None, rua_doc, exceptions=[exc])
    assert lifted["verdict"] == "go"
    assert lifted["exceptions"]["excepted_streams"] == ["192.0.2.9"]
    assert any(r.startswith("exception: 192.0.2.9 (50 msgs, unknown) excepted until 2099-01-01") for r in lifted["reasons"])


def test_build_report_carries_exceptions_and_alignment_into_the_files(tmp_path):
    log = write_log(tmp_path / "log.csv", [passing("<m1@a>", "billing@example.com", "example.com", "pass", "none")])
    exc = {"match": "billing@example.com", "reason": "r", "until": "2099-01-01", "removal_criterion": "c"}
    report = audit.build_report(domains=["example.com"], maillog=log, offline=True, exceptions=[exc])
    assert report["inputs"]["exceptions"] == ["billing@example.com"]
    assert report["gate"]["exceptions"]["applied"][0]["kind"] == "address"
    md = audit.render_md(report)
    assert "alignment of passing mail" in md and "SPF-only senders in the mail log" in md
    assert "aligned-DKIM evidence (needed before p=reject)" in md
