"""Round 12: one order for every list of domains. A subdomain sits with its
own organization, the organizational domain first and the names below it by
name; the headline's organization leads when one is given. No network."""

import audit


NAMES = ["t.example.com", "example.net", "e.example.com", "example.com", "a.example.net", "dev.support.example.com",
         "m.example.com", "b.example.co.uk", "example.co.uk"]


def test_a_subdomain_sits_with_its_own_organization():
    assert audit.order_domains(NAMES) == [
        "example.co.uk", "b.example.co.uk",
        "example.com", "dev.support.example.com", "e.example.com", "m.example.com", "t.example.com",
        "example.net", "a.example.net"]
    # a plain text sort is what put the names out of order: e.example.com between two other organizations
    assert sorted(NAMES).index("e.example.com") < sorted(NAMES).index("example.com")


def test_the_headline_organization_leads():
    assert audit.order_domains(NAMES, headline="mail.example.net")[:2] == ["example.net", "a.example.net"]
    assert audit.order_domains(NAMES, headline="example.com")[:5] == [
        "example.com", "dev.support.example.com", "e.example.com", "m.example.com", "t.example.com"]
    assert audit.order_domains(NAMES, headline="") == audit.order_domains(NAMES)


def test_names_compare_as_gate_keys_spell_them_and_odd_values_drop_out():
    assert audit.order_domains(["Example.COM.", "example.com", " e.example.com", None, "", 7]) == [
        "Example.COM.", " e.example.com"]
    assert audit.domain_key("Sub.Example.com.") == audit.domain_key("sub.example.com")
    assert sorted(["b.example.com", "example.com", "a.example.com"], key=audit.domain_key) == [
        "example.com", "a.example.com", "b.example.com"]
