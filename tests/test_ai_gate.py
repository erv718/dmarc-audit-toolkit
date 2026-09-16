"""The AI master switch: exact "true" opts in, everything else is off."""

import os

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
