"""run_hunting.run_query survives a dropped stream, a timeout and a 429; collect splits a window that keeps dropping."""

import http.client
import io
import json
import urllib.error

import pytest

import collect
import graph_client
import run_hunting


class FakeResp(io.BytesIO):
    """Minimal stand-in for the urlopen context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _no_sleep(monkeypatch):
    monkeypatch.setattr(run_hunting.time, "sleep", lambda s: None)


def test_dropped_stream_is_retried_and_succeeds(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise http.client.IncompleteRead(b"x" * 10)
        return FakeResp(json.dumps({"schema": [{"name": "a"}], "results": [{"a": 1}]}).encode())
    monkeypatch.setattr(run_hunting.urllib.request, "urlopen", fake_urlopen)
    out = run_hunting.run_query("tok", "EmailEvents | take 1", "P1D")
    assert out["results"] == [{"a": 1}]
    assert len(calls) == 2


def test_persistent_drop_exits_cleanly_after_all_attempts(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        raise http.client.IncompleteRead(b"")
    monkeypatch.setattr(run_hunting.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit) as exc:
        run_hunting.run_query("tok", "EmailEvents | take 1", "P1D", retries=2)
    assert "did not complete after 3 attempts" in str(exc.value)
    assert "IncompleteRead" in str(exc.value)
    assert len(calls) == 3


def test_transient_429_is_retried_then_succeeds(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, io.BytesIO(b"{}"))
        return FakeResp(b'{"schema": [], "results": []}')
    monkeypatch.setattr(run_hunting.urllib.request, "urlopen", fake_urlopen)
    assert run_hunting.run_query("tok", "q") == {"schema": [], "results": []}
    assert len(calls) == 2


def test_non_transient_http_error_is_not_retried(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"{}"))
    monkeypatch.setattr(run_hunting.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit) as exc:
        run_hunting.run_query("tok", "q")
    assert "HTTP 403" in str(exc.value) and len(calls) == 1


def test_graph_client_hunting_turns_the_exit_into_grapherror(monkeypatch):
    _no_sleep(monkeypatch)
    monkeypatch.setattr(run_hunting.urllib.request, "urlopen",
                        lambda req, timeout=0: (_ for _ in ()).throw(http.client.IncompleteRead(b"")))
    with pytest.raises(graph_client.GraphError) as exc:
        graph_client.hunting("tok", "q", "P1D")
    assert "did not complete" in str(exc.value)


def test_pull_domain_splits_a_window_that_keeps_dropping(monkeypatch):
    """A slice that drops after every retry is halved, like a slice at the row cap."""
    seen = []

    def fake_hunting(tok, kql, timespan=None):
        start, end = (int(x) for x in kql.split()[1:])  # the window, not the timespan: that now reaches the start
        days = start - end
        seen.append(days)
        if days > 8:
            raise graph_client.GraphError("query did not complete after 3 attempts (network drop or timeout): IncompleteRead")
        return {"schema": [{"name": "Timestamp"}], "results": [{"Timestamp": "t%d" % days}]}
    monkeypatch.setattr(collect.graph_client, "hunting", fake_hunting)
    monkeypatch.setattr(collect, "kql_for_domain", lambda template, org, s=30, e=0: "kql %d %d" % (s, e))
    notes = []
    rows, cols, calls = collect.pull_domain("tok", "template", "example.com", 30, 0, notes)
    assert rows and cols == ["Timestamp"]
    assert max(seen) == 30 and all(d <= 8 for d in seen if d != 30 and d != 15)
    assert any("dropped" in n and "splitting" in n for n in notes)
    assert calls >= 4


def test_pull_domain_gives_up_on_a_one_day_drop(monkeypatch):
    def fake_hunting(tok, kql, timespan=None):
        raise graph_client.GraphError("query did not complete after 3 attempts (network drop or timeout): IncompleteRead")
    monkeypatch.setattr(collect.graph_client, "hunting", fake_hunting)
    monkeypatch.setattr(collect, "kql_for_domain", lambda template, org, s=30, e=0: "kql %d %d" % (s, e))
    with pytest.raises(graph_client.GraphError):
        collect.pull_domain("tok", "template", "example.com", 1, 0, [])
