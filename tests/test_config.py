"""config.py: the optional audit.toml, its precedence, and the formal exceptions."""

import datetime

import pytest

import config


def write_toml(tmp_path, text):
    p = tmp_path / "audit.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_absent_default_is_empty_and_explicit_missing_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DEFAULT_PATH", tmp_path / "nope.toml")
    assert config.load() == {}
    with pytest.raises(config.ConfigError):
        config.load(str(tmp_path / "missing.toml"))


def test_collect_defaults_map_to_argparse_dests(tmp_path):
    p = write_toml(tmp_path, '''
[audit]
domains = ["Example.com", "sub.example.com"]
known = ["vendor.example", "192.0.2.0/24"]
selectors = "s1, mail"
vendor_domains = ["vendor.example"]
keep = 12
strict = true
mailflow = false
''')
    cfg = config.load(str(p))
    d = config.collect_defaults(cfg)
    assert d["domains"] == ["Example.com", "sub.example.com"]
    assert d["known"] == "vendor.example,192.0.2.0/24"      # the comma list --known already takes
    assert d["selectors"] == "s1,mail"
    assert d["vendor_domain"] == ["vendor.example"]
    assert d["keep"] == 12 and d["strict"] is True and d["mailflow"] is False
    assert cfg["_path"].endswith("audit.toml")


def test_unknown_or_mistyped_keys_are_errors(tmp_path):
    cfg = config.load(str(write_toml(tmp_path, "[audit]\nbogus = 1\n")))
    with pytest.raises(config.ConfigError) as err:
        config.collect_defaults(cfg)
    assert "bogus" in str(err.value)
    cfg = config.load(str(write_toml(tmp_path, '[audit]\nkeep = "twelve"\n')))
    with pytest.raises(config.ConfigError):
        config.collect_defaults(cfg)
    cfg = config.load(str(write_toml(tmp_path, "[notify]\ntarget = 'pager'\n")))
    with pytest.raises(config.ConfigError):
        config.notify_settings(cfg)


def test_notify_defaults_keep_a_webhook_working():
    assert config.notify_settings({}) == {"enabled": True, "target": "slack"}
    assert config.notify_settings({"notify": {"enabled": False}})["enabled"] is False


def test_parse_exceptions_splits_active_expired_invalid():
    today = datetime.date(2026, 6, 1)
    active, expired, invalid = config.parse_exceptions([
        {"match": "192.0.2.30", "reason": "printer", "owner": "finance", "until": "2026-12-31",
         "removal_criterion": "vendor signs with DKIM"},
        {"match": "Vendor.Example.", "reason": "old", "until": datetime.date(2026, 1, 1), "removal_criterion": "x"},
        {"match": "user@example.com", "reason": "no expiry"},
        {"match": "not a match", "reason": "r", "until": "2027-01-01", "removal_criterion": "c"},
        {"match": "10.0.0.0/8", "reason": "r", "until": "never", "removal_criterion": "c"},
        "just a string",
    ], today=today)
    assert [e["match"] for e in active] == ["192.0.2.30"]
    assert active[0]["kind"] == "ip" and active[0]["owner"] == "finance" and active[0]["until"] == "2026-12-31"
    assert [e["match"] for e in expired] == ["vendor.example"] and expired[0]["kind"] == "domain"
    problems = {i["entry"]: i["problem"] for i in invalid}
    assert "missing until, removal_criterion" == problems["user@example.com"]
    assert "not an IP" in problems["not a match"]
    assert "not a date" in problems["10.0.0.0/8"]
    assert any(v == "not a table" for v in problems.values())
    # normalised entries pass through the split unchanged
    again, _, _ = config.parse_exceptions(active, today=today)
    assert again == active


def test_exception_kinds():
    assert config.exception_kind("192.0.2.1") == "ip"
    assert config.exception_kind("192.0.2.0/24") == "prefix"
    assert config.exception_kind("2001:db8::1") == "ip"
    assert config.exception_kind("mail.vendor.example") == "domain"
    assert config.exception_kind("billing@example.com") == "address"
    assert config.exception_kind("nodot") is None


def test_matches_stream_and_verdict():
    ip = {"match": "192.0.2.0/24", "kind": "prefix"}
    dom = {"match": "vendor.example", "kind": "domain"}
    addr = {"match": "billing@example.com", "kind": "address"}
    stream = {"source_ip": "192.0.2.9", "spf_domains": ["bounce.vendor.example"], "dkim_domains": [],
              "header_from": ["example.com"]}
    assert config.matches_stream(ip, stream) and config.matches_stream(dom, stream)
    assert not config.matches_stream({"match": "example.com", "kind": "domain"}, stream)  # header_from never matches
    assert not config.matches_stream(addr, stream)
    verdict = {"sender": "billing@example.com", "envelope_domain": "bounce.vendor.example"}
    assert config.matches_verdict(addr, verdict) and config.matches_verdict(dom, verdict)
    assert not config.matches_verdict(ip, verdict)  # the mail log carries no source IP at this grain
