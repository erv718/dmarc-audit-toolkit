"""A long mailbox backfill survives its token's lifetime and a crash: graph_client
refreshes a TokenSource once on 401, and fetch_rua saves its state every 50
messages so a rerun continues where the last one stopped. No network."""

import io
import json
import urllib.error

import pytest

import fetch_rua
import graph_client


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_token_source_reacquires_on_demand_and_after_max_age(monkeypatch):
    calls = []
    monkeypatch.setattr(graph_client, "token", lambda cred: calls.append(cred) or "tok%d" % len(calls))
    src = graph_client.TokenSource(("t", "c", "s"), max_age=0)
    assert src() == "tok1" and src(refresh=True) == "tok2"
    assert src() == "tok3"  # max_age 0: every call is stale
    assert src.acquired == 3 and calls == [("t", "c", "s")] * 3
    assert graph_client.bearer("plain") == "plain" and graph_client.bearer(src) == "tok4"


def test_get_refreshes_a_callable_token_once_on_401(monkeypatch):
    monkeypatch.setattr(graph_client.time, "sleep", lambda s: None)
    seen = []

    def fake_urlopen(req, timeout=0):
        seen.append(req.get_header("Authorization"))
        if len(seen) == 1:
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {},
                                         io.BytesIO(b'{"error": {"message": "Invalid token lifetime."}}'))
        return FakeResp(b'{"value": [1]}')
    monkeypatch.setattr(graph_client.urllib.request, "urlopen", fake_urlopen)
    tokens = iter(["old", "new"])
    monkeypatch.setattr(graph_client, "token", lambda cred: next(tokens))
    src = graph_client.TokenSource(("t", "c", "s"))
    assert graph_client.get(src, "users/x/messages") == {"value": [1]}
    assert seen == ["Bearer old", "Bearer new"] and src.acquired == 2


def test_get_with_a_plain_string_does_not_retry_a_401(monkeypatch):
    monkeypatch.setattr(graph_client.time, "sleep", lambda s: None)
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b"{}"))
    monkeypatch.setattr(graph_client.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(graph_client.GraphError) as exc:
        graph_client.get("plain", "users/x/messages")
    assert exc.value.status == 401 and len(calls) == 1


def messages(n):
    return [{"id": "m%d" % i, "receivedDateTime": "2026-09-%02dT00:00:%02dZ" % (1 + i // 60, i % 60),
             "hasAttachments": True} for i in range(n)]


def test_state_is_saved_every_fifty_messages_so_a_crash_resumes(monkeypatch, tmp_path):
    msgs = messages(120)

    def listing(tok, url, params=None):  # the message listing itself dies on page two
        for i, m in enumerate(msgs):
            if i == 74:
                raise graph_client.GraphError("HTTP 401 on ...: Invalid token lifetime.", 401)
            yield m
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", listing)
    monkeypatch.setattr(fetch_rua.graph_client, "get", lambda tok, url, params=None: {"value": []})
    state = tmp_path / "state.json"
    with pytest.raises(graph_client.GraphError):
        fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), None, 500)
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved == {"last_received": msgs[49]["receivedDateTime"], "mailbox": "box@example.com"}
    # the rerun starts from the saved timestamp and finishes; the state now holds the newest
    monkeypatch.setattr(fetch_rua.graph_client, "get", lambda tok, url, params=None: {"value": []})
    asked = []

    def get_all(tok, url, params=None):
        asked.append(params["$filter"])
        return iter([m for m in msgs if m["receivedDateTime"] >= saved["last_received"]])
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", get_all)
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), None, 500)
    assert asked == ["receivedDateTime ge %s and hasAttachments eq true" % msgs[49]["receivedDateTime"]]
    assert json.loads(state.read_text(encoding="utf-8"))["last_received"] == msgs[119]["receivedDateTime"]
    assert any("71 message(s) checked" in n for n in notes)


def test_a_message_whose_attachments_cannot_be_read_is_skipped_and_the_state_stays_before_it(monkeypatch, tmp_path):
    msgs = messages(120)
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", lambda tok, url, params=None: iter(msgs))

    def fake_get(tok, url, params=None):
        if url.endswith("/m74/attachments"):
            raise graph_client.GraphError("request did not complete: IncompleteRead")
        return {"value": []}
    monkeypatch.setattr(fetch_rua.graph_client, "get", fake_get)
    state = tmp_path / "state.json"
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), None, 500)
    assert any(n.startswith("message received %s skipped, attachments not read: request did not complete"
                            % msgs[74]["receivedDateTime"]) for n in notes), notes
    assert any(n.startswith("1 message(s) skipped this run; the state file stays at %s" % msgs[74]["receivedDateTime"])
               for n in notes)
    assert any("120 message(s) checked" in n for n in notes)
    # the run went on past the bad message, but the state points at it, not at message 120
    assert json.loads(state.read_text(encoding="utf-8"))["last_received"] == msgs[74]["receivedDateTime"]
    assert fetch_rua.resume_point("2026-09-03T00:00:00Z", None) == "2026-09-03T00:00:00Z"
    assert fetch_rua.resume_point("2026-09-03T00:00:00Z", "2026-09-02T00:00:00Z") == "2026-09-02T00:00:00Z"
    assert fetch_rua.resume_point(None, "2026-09-02T00:00:00Z") == "2026-09-02T00:00:00Z"


def test_get_retries_a_dropped_stream_twice_with_a_growing_pause(monkeypatch):
    import http.client
    pauses = []
    monkeypatch.setattr(graph_client.time, "sleep", lambda s: pauses.append(s))
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(1)
        if len(calls) < 3:
            raise http.client.IncompleteRead(b"")
        return FakeResp(b'{"value": []}')
    monkeypatch.setattr(graph_client.urllib.request, "urlopen", fake_urlopen)
    assert graph_client.get("tok", "users/x/messages") == {"value": []}
    assert len(calls) == 3 and pauses == [2, 4]
    calls.clear()
    monkeypatch.setattr(graph_client.urllib.request, "urlopen",
                        lambda req, timeout=0: (_ for _ in ()).throw(http.client.IncompleteRead(b"")))
    with pytest.raises(graph_client.GraphError) as exc:
        graph_client.get("tok", "users/x/messages")
    assert "did not complete" in str(exc.value)
