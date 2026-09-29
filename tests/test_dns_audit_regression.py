"""dns_audit regressions with the resolver stubbed - no network.

The first case pins the bug where the DKIM selector probes reused the
variable holding the DMARC record, so any domain with a probed selector was
reported with dmarc=None while dmarc_status said found.
"""

import dns_audit

RECORD = "v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:reports@example.com;"


def canned_resolver(answers):
    """resolve_ex stand-in: answers is {(name, rtype): [records]}; missing means absent."""
    def resolve_ex(resolver, name, rtype):
        recs = answers.get((name.lower(), rtype), [])
        return list(recs), {"path": "stub", "ttl": 300, "status": "found" if recs else "absent"}
    return resolve_ex


def test_dmarc_text_survives_dkim_selector_probes(monkeypatch):
    answers = {
        ("_dmarc.example.com", "TXT"): [RECORD],
        ("selector1._domainkey.example.com", "CNAME"): ["selector1-example-com._domainkey.tenant.example"],
        # a real resolver follows the CNAME, so the TXT answers at both names
        ("selector1._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
        ("selector1-example-com._domainkey.tenant.example", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
        ("example.com", "MX"): ["10 mail.example"],
    }
    monkeypatch.setattr(dns_audit, "resolve_ex", canned_resolver(answers))
    monkeypatch.setattr(dns_audit, "_spf_status", lambda domain, resolver, q: ("v=spf1 include:mail.example -all", "found", []))
    d = dns_audit.audit_domain("example.com", None)
    assert d["dmarc_status"] == "found"
    assert d["dmarc"] == RECORD                      # was None before the fix
    assert d["effective_policy"] == "quarantine"
    assert "selector1" in d["dkim_selectors"]
    assert "DMARC-001" not in {f["id"] for f in d["findings"]}


def test_subdomain_inherits_sp_from_the_org_domain(monkeypatch):
    answers = {("_dmarc.example.com", "TXT"): [RECORD], ("sub.example.com", "MX"): []}
    monkeypatch.setattr(dns_audit, "resolve_ex", canned_resolver(answers))
    monkeypatch.setattr(dns_audit, "_spf_status", lambda domain, resolver, q: (None, "absent", []))
    d = dns_audit.audit_domain("sub.example.com", None)
    assert d["inherited"] is True
    assert d["dmarc_source"] == "_dmarc.example.com"
    assert d["effective_policy"] == "reject"          # sp=reject applies to the subdomain
    assert "DMARC-001" not in {f["id"] for f in d["findings"]}


def test_no_record_anywhere_is_dmarc_001(monkeypatch):
    monkeypatch.setattr(dns_audit, "resolve_ex", canned_resolver({}))
    monkeypatch.setattr(dns_audit, "_spf_status", lambda domain, resolver, q: (None, "absent", []))
    d = dns_audit.audit_domain("lonely.example", None)
    assert d["dmarc"] is None and d["dmarc_status"] == "absent"
    assert "DMARC-001" in {f["id"] for f in d["findings"]}
