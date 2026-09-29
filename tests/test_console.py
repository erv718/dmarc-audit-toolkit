"""console.py: the shared color helper. Color only on a terminal; plain text everywhere else."""

import io

import console
import dedupe
import dns_audit
import spf_lookups
import verify_setup


class Tty(io.StringIO):
    def isatty(self):
        return True


def _clean_env(monkeypatch):
    for key in ("NO_COLOR", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(key, raising=False)


def test_disabled_paint_returns_text_unchanged():
    p = console.Paint(False)
    for fn in (p.bold, p.dim, p.red, p.green, p.yellow, p.cyan):
        assert fn("plain") == "plain"
    assert p.status("PASS") == "PASS"
    assert p.severity("major") == "major"
    assert p.banner("all good", "ok") == "all good"
    assert p.by_severity("x", "blocking") == "x"
    assert p.by_exit("x", 2) == "x"


def test_enabled_paint_wraps_in_ansi():
    p = console.Paint(True)
    assert p.status("PASS") == "\033[32;1mPASS\033[0m"
    assert p.status("FAIL").startswith("\033[31;1m")
    assert p.status("no_go").startswith("\033[31;1m")
    assert p.severity("minor") == "\033[33mminor\033[0m"
    assert p.banner("b", "warn") == "\033[33;1mb\033[0m"
    assert p.by_exit("x", 0).startswith("\033[32;1m")
    assert p.by_exit("x", 1).startswith("\033[33;1m")
    assert p.by_exit("x", 2).startswith("\033[31;1m")
    assert p.by_severity("x", "info").startswith("\033[32;1m")
    assert p.by_severity("x", "major").startswith("\033[31;1m")
    assert p.dim("d") == "\033[2md\033[0m"
    assert p.bold("") == ""  # nothing to color, nothing emitted


def test_color_wanted_rules(monkeypatch):
    _clean_env(monkeypatch)
    assert console.color_wanted(Tty()) is True
    assert console.color_wanted(io.StringIO()) is False
    assert console.color_wanted(object()) is False
    monkeypatch.setenv("NO_COLOR", "")
    assert console.color_wanted(Tty()) is False  # presence alone disables
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert console.color_wanted(Tty()) is False
    monkeypatch.delenv("TERM")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.color_wanted(io.StringIO()) is True  # forced on for a pipe
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert console.color_wanted(io.StringIO()) is False
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    assert console.color_wanted(Tty()) is False  # the explicit opt-out wins


def test_painter_is_off_for_a_pipe_and_windows_setup_is_safe(monkeypatch):
    _clean_env(monkeypatch)
    assert console.painter(io.StringIO()).enabled is False
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.painter(io.StringIO()).enabled is True
    console.enable_windows_ansi()  # must never raise, on any platform


def test_verify_setup_still_exports_the_helper_names():
    assert verify_setup.Paint is console.Paint
    assert verify_setup.color_wanted is console.color_wanted
    assert verify_setup.enable_windows_ansi is console.enable_windows_ansi


# Byte-identity guards: every human report is plain text when captured.

def test_dedupe_report_has_no_escape_codes_when_captured(capsys, monkeypatch):
    _clean_env(monkeypatch)
    cols = {"msgid": "Internet message ID", "recipient": "Recipients", "sender": "Sender address",
            "domain": "Sender domain", "action": "Delivery action", "location": "Latest delivery location",
            "subject": "Subject", "envelope": "Sender mail from domain"}
    rows = [
        {"Internet message ID": "<a@esp.example>", "Recipients": "v@example.com",
         "Sender address": "billing@example.com", "Sender domain": "example.com",
         "Delivery action": "Blocked", "Latest delivery location": "Quarantine",
         "Subject": "Invoice 41 past due", "Sender mail from domain": "203.0.113.5", "DMARC": "fail"},
        {"Internet message ID": "<b@esp.example>", "Recipients": "v@example.com",
         "Sender address": "hr@example.com", "Sender domain": "example.com",
         "Delivery action": "Delivered", "Latest delivery location": "Inbox",
         "Subject": "Payslip", "Sender mail from domain": "example.com", "DMARC": "pass"},
    ]
    counts = dedupe.count_rows(rows, cols, None, "DMARC")
    verdicts = dedupe.classify(rows, cols, None, "DMARC")
    counts.update(dedupe.summarize(verdicts))
    findings = dedupe.build_findings(counts, verdicts, "DMARC")
    dedupe.print_report(counts, verdicts, findings, "DMARC")
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "  GENUINE failures          : 1   <-- the real number" in out
    assert "counting rows would report 1 failures; the true count is 1." in out
    assert "  [major] MAILFLOW-001 " in out


def test_spf_report_has_no_escape_codes_when_captured(capsys, monkeypatch):
    _clean_env(monkeypatch)
    r = {"domain": "example.com", "record": "v=spf1 include:mail.example -all", "status": "found",
         "evidence": "doh", "lookups": 1, "limit": 10, "verdict": "ok", "severity": "info", "verified": True,
         "mechanisms": [{"depth": 0, "owner": "example.com", "mechanism": "include:mail.example", "counts": True}],
         "exit_code": 0}
    spf_lookups.report(r)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "  lookups: 1 / 10   ok" in out
    assert "  * include:mail.example" in out
    r.update({"status": "error", "evidence": "port53-udp timeout; doh unreachable"})
    spf_lookups.report(r)
    out = capsys.readouterr().out
    assert "\x1b" not in out and "SPF lookup FAILED for example.com" in out


def test_dns_audit_report_has_no_escape_codes_when_captured(capsys, monkeypatch):
    _clean_env(monkeypatch)
    r = {"domain": "example.com", "spf": None, "spf_status": "absent", "spf_terminator": None,
         "spf_lookups": 0, "spf_lookups_failed": 0, "dmarc": None, "dmarc_status": "absent",
         "dmarc_source": None, "effective_policy": None, "inherited": False, "dkim_wildcard": False,
         "dkim_status": "absent", "dkim_selectors": [], "dkim_probed": list(dns_audit.COMMON_SELECTORS),
         "dkim_dangling": [], "dkim_unresolved": [], "mx": [], "mx_null": False, "mx_status": "absent",
         "findings": [{"id": "DMARC-001", "severity": "major", "area": "dmarc",
                       "title": "NO DMARC RECORD", "evidence": "", "action": "publish one", "verified": True}]}
    dns_audit.print_report(r)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "  SPF   : MISSING" in out
    assert "  DMARC : MISSING" in out
    assert "  !! [major] NO DMARC RECORD" in out
    assert "       fix: publish one" in out


def test_verify_setup_report_banner_is_plain_when_captured(capsys):
    res = [{"check": "credentials", "status": "PASS", "detail": "present", "fix": ""},
           {"check": "roles: excess (read)", "status": "WARN", "detail": "extra", "fix": "remove it"}]
    verify_setup.print_report(res, console.Paint(False))
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "setup: OK - with warnings worth fixing (1 passed, 1 warnings, 0 failed)" in out
    assert "      fix: remove it" in out
