"""The AI master switch: exact "true" opts in, everything else is off."""

import os

import pytest

import mcp_server


def _isolate(monkeypatch, tmp_path, env_file_text=None):
    monkeypatch.delenv("AI_ANALYSIS_ENABLED", raising=False)
    env_path = tmp_path / ".env"
    if env_file_text is not None:
        env_path.write_text(env_file_text, encoding="utf-8")
    monkeypatch.setattr(mcp_server, "ENV_PATH", env_path)


def test_off_by_default(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)  # no .env at all
    assert mcp_server.ai_analysis_enabled() is False


def test_only_exact_true_opts_in(monkeypatch, tmp_path):
    for value in ("false", "1", "yes", "TRUE ", " true"):
        _isolate(monkeypatch, tmp_path, f"AI_ANALYSIS_ENABLED={value}\n")
        expected = value.strip().lower() == "true"
        assert mcp_server.ai_analysis_enabled() is expected, value


def test_env_var_beats_env_file(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, "AI_ANALYSIS_ENABLED=true\n")
    monkeypatch.setenv("AI_ANALYSIS_ENABLED", "false")
    assert mcp_server.ai_analysis_enabled() is False


def test_env_file_true_when_no_env_var(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, "AI_ANALYSIS_ENABLED=true\n")
    assert mcp_server.ai_analysis_enabled() is True


def test_the_server_module_imports_without_the_sdk(monkeypatch):
    import importlib
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "mcp.server.mcpserver", None)  # the import then raises ImportError
    mod = importlib.reload(mcp_server)
    try:
        assert mod.MCP_AVAILABLE is False and callable(mod.dedupe_maillog) and callable(mod.run_audit)
        with pytest.raises(SystemExit) as exc:
            mod.server.run()
        assert exc.value.code == 2
    finally:
        monkeypatch.undo()
        importlib.reload(mcp_server)


def test_parse_rua_counts_whole_tables_not_the_capped_preview(monkeypatch):
    seen = {}

    def fake(paths, **kw):
        seen.update(kw)
        return {"totals": {}, "policy_check": {}, "selectors": [], "findings": [], "warnings": [], "summary": "",
                "exit_code": 0, "failing_streams": [], "spf_only_senders": [], "retiring_selectors": [],
                "by_header_from": [], "by_reporter": [],
                "unknown_senders": [{"kind": "ip", "value": "203.0.113.%d" % i} for i in range(60)]}

    monkeypatch.setattr(mcp_server.audit_mod, "run_rua", fake)
    reply = mcp_server.parse_rua(["samples/rua"])
    assert seen["max_sources"] == 0 and reply["unknown_senders_total"] == 60 and reply["unknown_senders_truncated"] is True
