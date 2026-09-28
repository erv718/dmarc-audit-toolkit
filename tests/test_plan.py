"""plan.py: the rollout rules over a synthetic report. No network."""

import json
import subprocess
import sys
from pathlib import Path

import plan

ROOT = Path(__file__).resolve().parent.parent


def dns(domain, **over):
    base = {"domain": domain, "spf": "v=spf1 include:mail.example -all", "spf_status": "found",
            "spf_terminator": "-all", "spf_lookups": 1, "spf_lookups_failed": 0, "spf_verified": True,
            "dmarc": None, "dmarc_source": None, "effective_policy": None, "inherited": False,
            "dmarc_status": "absent", "dkim_selectors": ["selector1"], "dkim_status": "found",
            "mx": ["10 mail.example"], "mx_null": False, "mx_status": "found", "flags": [], "findings": [],
            "evidence": []}
    base.update(over)
    return base


def finding(fid, sev="major"):
    return {"id": fid, "severity": sev, "area": fid.split("-")[0].lower(), "title": fid, "evidence": "", "action": "", "verified": True}


def make_report(domains):
    return {"generated_utc": "2026-01-01T00:00:00Z", "dns": domains, "inputs": {"domains": list(domains)},
            "gate": {"domains": {}}, "findings": [], "maillog": None, "rua": None}


def test_no_record_gets_monitoring_and_no_rua_gets_rua_added():
    rep = make_report({
        "example.com": dns("example.com", dmarc="v=DMARC1; p=quarantine; pct=100;", effective_policy="quarantine",
                           dmarc_status="found", findings=[finding("DMARC-003")]),
        "other.example": dns("other.example", findings=[finding("DMARC-001")]),
    })
    p = plan.build_plan(rep, rua="mailto:reports@example.com")
    by = {(c["domain"], c["kind"]): c for c in p["changes"]}
    new = by[("other.example", "new")]
    assert new["hostname"] == "_dmarc.other.example"
    assert new["value"] == "v=DMARC1; p=none; rua=mailto:reports@example.com;"
    assert new["priority"] == 1 and new["current"] == "none"
    mod = by[("example.com", "modify")]
    assert "rua=mailto:reports@example.com" in mod["value"]
    assert mod["current"] == "v=DMARC1; p=quarantine; pct=100;"


def test_subdomain_inheriting_none_gets_its_own_record():
    rep = make_report({
        "example.com": dns("example.com", dmarc="v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:r@example.com;",
                           effective_policy="quarantine", dmarc_status="found"),
        "sub.example.com": dns("sub.example.com", dmarc="v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:r@example.com;",
                               dmarc_source="example.com", inherited=True, effective_policy="none",
                               dmarc_status="found", findings=[finding("DMARC-002", "minor")]),
    })
    p = plan.build_plan(rep)
    subs = [c for c in p["changes"] if c["domain"] == "sub.example.com" and c["kind"] == "new"]
    assert len(subs) == 1 and subs[0]["value"].startswith("v=DMARC1; p=none; rua=mailto:r@example.com")
    assert p["rua"] == "mailto:r@example.com"          # derived from the existing records


def test_parked_domain_gets_reject_and_spf_minus_all_with_verify_prerequisite():
    rep = make_report({"parked.example": dns("parked.example", spf=None, spf_status="absent", spf_terminator=None,
                                               spf_lookups=0, dkim_selectors=[], dkim_status="absent",
                                               mx=[], mx_status="absent", findings=[finding("DMARC-001"), finding("SPF-001")])})
    p = plan.build_plan(rep, rua="mailto:reports@example.com")
    kinds = {(c["hostname"], c["value"]) for c in p["changes"] if c["kind"] == "park"}
    assert ("_dmarc.parked.example", "v=DMARC1; p=reject; rua=mailto:reports@example.com;") in kinds
    assert ("parked.example", "v=spf1 -all") in kinds
    assert all("verify unused" in c["prerequisites"][0] for c in p["changes"] if c["kind"] == "park")


def test_quarantine_100_proposes_reject_with_gates_and_subdomain_hold():
    rep = make_report({
        "example.com": dns("example.com", dmarc="v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:r@example.com;",
                           effective_policy="quarantine", dmarc_status="found", spf="v=spf1 include:a.example ~all",
                           spf_terminator="~all", spf_lookups=9),
        "pt.example.com": dns("pt.example.com", dmarc="v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:r@example.com;",
                              dmarc_source="example.com", inherited=True, effective_policy="none", dmarc_status="found"),
    })
    p = plan.build_plan(rep)
    step = next(c for c in p["changes"] if c["domain"] == "example.com" and c["kind"] == "ratchet")
    assert "p=reject" in step["value"] and "sp=none" in step["value"]      # sp is its own later step
    assert any("DKIM header" in x for x in step["prerequisites"])
    assert any("no failure evidence" in x for x in step["prerequisites"])
    assert any("pt.example.com" in h["reason"] for h in p["holds"])


def test_duplicate_records_are_holds_not_changes():
    rep = make_report({"dup.example": dns("dup.example", dmarc="v=DMARC1; p=none;", effective_policy="none",
                                            dmarc_status="found", findings=[finding("DMARC-005"), finding("SPF-007")])})
    p = plan.build_plan(rep)
    assert not [c for c in p["changes"] if c["domain"] == "dup.example" and c["kind"] in ("new", "modify")]
    reasons = " ".join(h["reason"] for h in p["holds"])
    assert "two DMARC records" in reasons and "more than one SPF record" in reasons


def test_spf_neutral_terminator_becomes_softfail():
    rep = make_report({"n.example": dns("n.example", spf="v=spf1 include:a.example ?all", spf_terminator="?all",
                                          dmarc="v=DMARC1; p=none; rua=mailto:r@example.com;", effective_policy="none",
                                          dmarc_status="found", findings=[finding("SPF-003")])})
    p = plan.build_plan(rep)
    mod = next(c for c in p["changes"] if c["hostname"] == "n.example" and c["kind"] == "modify")
    assert mod["value"] == "v=spf1 include:a.example ~all"


def test_evidence_hold_from_maillog_and_rua():
    rep = make_report({"example.com": dns("example.com", dmarc="v=DMARC1; p=none; rua=mailto:r@example.com;",
                                            effective_policy="none", dmarc_status="found")})
    rep["maillog"] = {"sender_domain": "example.com", "counters": {"by_likely": {"likely_misconfigured_sender": 4}}}
    rep["rua"] = {"failing_streams": [{"source_ip": "192.0.2.9", "count": 50, "header_from": ["example.com"],
                                       "likely": "likely_misconfigured_sender", "likely_signals": ["DKIM signs as vendor.example"]}]}
    p = plan.build_plan(rep)
    step = next(c for c in p["changes"] if c["kind"] == "ratchet")
    joined = " ".join(step["prerequisites"])
    assert "4 message(s)" in joined and "192.0.2.9" in joined


def test_render_and_cli(tmp_path):
    rep = make_report({"other.example": dns("other.example", findings=[finding("DMARC-001")])})
    md = plan.render_md(plan.build_plan(rep, rua="mailto:reports@example.com"))
    assert "| # | Record | Hostname | Value | TTL |" in md and "_dmarc.other.example" in md
    (tmp_path / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    p = subprocess.run([sys.executable, str(ROOT / "src" / "plan.py"), str(tmp_path / "report.json"),
                        "--rua", "mailto:reports@example.com", "--out", str(tmp_path)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert (tmp_path / "plan.md").exists() and (tmp_path / "plan.json").exists()
    bad = subprocess.run([sys.executable, str(ROOT / "src" / "plan.py"), str(tmp_path / "report.json"), "--rua", "nope"],
                         capture_output=True, text=True)
    assert bad.returncode == 2 and "mailto:" in bad.stderr
