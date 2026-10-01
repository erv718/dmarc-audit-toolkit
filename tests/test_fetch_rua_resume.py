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


def filtered(msgs, fail_at=None, calls=None):
    """A message listing that honours the receivedDateTime filter, records each
    call's params, and dies when it reaches message index fail_at."""
    def get_all(tok, url, params=None):
        if calls is not None:
            calls.append(dict(params))
        since = params["$filter"].split("ge ")[1].split(" and")[0]
        for i, m in enumerate(msgs):
            if m["receivedDateTime"] < since:
                continue
            if fail_at is not None and i == fail_at:
                raise graph_client.GraphError("HTTP 401 on ...: Invalid token lifetime.", 401)
            yield m
    return get_all


def b64(data):
    import base64
    return base64.b64encode(data).decode()


def test_a_listing_failure_keeps_every_handled_message_and_a_rerun_resumes(monkeypatch, tmp_path):
    msgs = messages(120)
    calls = []
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs, fail_at=74, calls=calls))
    monkeypatch.setattr(fetch_rua.graph_client, "get", lambda tok, url, params=None: {"value": []})
    state = tmp_path / "state.json"
    with pytest.raises(graph_client.GraphError):
        fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), None, 500)
    # inline first; when that page died the run kept every message handled, switched to
    # one message at a time from there, and the state held when the listing died again
    assert [c.get("$expand") for c in calls] == ["attachments", None]
    assert calls[1]["$filter"] == "receivedDateTime ge %s and hasAttachments eq true" % msgs[73]["receivedDateTime"]
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["last_received"] == msgs[73]["receivedDateTime"] and saved["mailbox"] == "box@example.com"
    # a healthy rerun starts there and finishes; the state now holds the newest
    calls.clear()
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs, calls=calls))
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), None, 500)
    assert calls[0]["$filter"] == "receivedDateTime ge %s and hasAttachments eq true" % msgs[73]["receivedDateTime"]
    assert json.loads(state.read_text(encoding="utf-8"))["last_received"] == msgs[119]["receivedDateTime"]
    assert any("47 message(s) checked" in n for n in notes)


def test_attachments_come_back_inline_so_there_is_no_call_per_message(monkeypatch, tmp_path):
    msgs = messages(3)
    for i, m in enumerate(msgs):
        m["attachments"] = [{"name": "r!example.com!%d!%d.xml.gz" % (i, i + 1), "size": 10,
                             "contentBytes": b64(b"report %d" % i)},
                            {"name": "logo.png", "size": 5, "contentBytes": b64(b"png")}]
    calls = []
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs, calls=calls))

    def no_get(*a, **k):
        raise AssertionError("no per-message call when the attachments come back inline")
    monkeypatch.setattr(fetch_rua.graph_client, "get", no_get)
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", None, None, 500)
    assert count == 3
    assert calls[0]["$expand"] == "attachments" and calls[0]["$top"] == str(fetch_rua.PAGE)
    files = sorted(f.name for f in (tmp_path / "out").iterdir())
    assert len(files) == 3 and all(f.endswith(".xml.gz") for f in files)


def test_an_inline_attachment_without_content_is_read_the_classic_way(monkeypatch, tmp_path):
    msgs = messages(2)
    msgs[0]["attachments"] = [{"name": "a!example.com!1!2.xml.gz", "size": 10, "contentBytes": b64(b"a")}]
    msgs[1]["attachments"] = [{"name": "b!example.com!1!2.xml.gz", "size": 10}]  # content not inline
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs))
    asked = []

    def get(tok, url, params=None):
        asked.append(url)
        return {"value": [{"name": "b!example.com!1!2.xml.gz", "size": 10, "contentBytes": b64(b"b")}]}
    monkeypatch.setattr(fetch_rua.graph_client, "get", get)
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", None, None, 500)
    assert count == 2 and asked == ["users/box%40example.com/messages/m1/attachments"]


def test_the_read_starts_at_the_floor_when_the_state_is_missing_or_older(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered([], calls=calls))
    state, out = tmp_path / "state.json", tmp_path / "out"
    # no state: the floor, not the start of the mailbox
    count, notes = fetch_rua.fetch("tok", "box@example.com", out, str(state), None, 500, floor="2026-09-01")
    assert calls[-1]["$filter"].startswith("receivedDateTime ge 2026-09-01T00:00:00Z ")
    assert any("reading from 2026-09-01" in n for n in notes)
    # a state from March is older than the window: the floor again
    state.write_text(json.dumps({"last_received": "2026-03-10T16:00:49Z", "mailbox": "box@example.com"}),
                     encoding="utf-8")
    fetch_rua.fetch("tok", "box@example.com", out, str(state), None, 500, floor="2026-09-01")
    assert calls[-1]["$filter"].startswith("receivedDateTime ge 2026-09-01T00:00:00Z ")
    # a state inside the window drives the read, and there is no floor note
    state.write_text(json.dumps({"last_received": "2026-09-20T08:00:00Z", "mailbox": "box@example.com"}),
                     encoding="utf-8")
    count, notes = fetch_rua.fetch("tok", "box@example.com", out, str(state), None, 500, floor="2026-09-01")
    assert calls[-1]["$filter"].startswith("receivedDateTime ge 2026-09-20T08:00:00Z ")
    assert not any("reading from" in n for n in notes)


def test_a_state_file_for_another_mailbox_is_ignored(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered([], calls=calls))
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"last_received": "2026-09-20T08:00:00Z", "mailbox": "old@example.com"}),
                     encoding="utf-8")
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), None, 500,
                                   floor="2026-09-01")
    assert calls[-1]["$filter"].startswith("receivedDateTime ge 2026-09-01T00:00:00Z ")
    assert any("is for old@example.com, not box@example.com - ignored" in n for n in notes)


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


def test_a_zero_limit_reads_everything_and_a_stop_names_where_to_resume(monkeypatch, tmp_path):
    msgs = messages(5)
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs))
    monkeypatch.setattr(fetch_rua.graph_client, "get", lambda tok, url, params=None: {"value": []})
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "a", None, None, 0)
    assert any("5 message(s) checked" in n for n in notes) and not any("stopped after" in n for n in notes)
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "b", None, "2026-09-01", 2)
    stop = [n for n in notes if n.startswith("stopped after 2 messages")]
    assert stop and ("at %s" % msgs[1]["receivedDateTime"]) in stop[0] and "--since 2026-09-01" in stop[0]


def test_a_since_backfill_restarts_after_a_drop_at_its_own_last_message(monkeypatch, tmp_path):
    msgs = messages(120)
    calls = []
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs, fail_at=74, calls=calls))
    monkeypatch.setattr(fetch_rua.graph_client, "get", lambda tok, url, params=None: {"value": []})
    state = tmp_path / "state.json"
    newer = "2026-12-01T00:00:00Z"  # the weekly job's saved position, far ahead of this backfill
    state.write_text(json.dumps({"last_received": newer, "mailbox": "box@example.com"}), encoding="utf-8")
    with pytest.raises(graph_client.GraphError) as exc:
        fetch_rua.fetch("tok", "box@example.com", tmp_path / "out", str(state), "2026-09-01", 500)
    # the classic restart is this run's last message, not the saved position (that would skip the rest)
    assert calls[1]["$filter"] == "receivedDateTime ge %s and hasAttachments eq true" % msgs[73]["receivedDateTime"]
    # the saved position never moves backwards, and the notes so far ride on the exception
    assert json.loads(state.read_text(encoding="utf-8"))["last_received"] == newer
    assert any("continuing one message at a time" in n for n in exc.value.notes)


def test_the_state_records_where_the_unbroken_archive_starts(monkeypatch, tmp_path):
    msgs = messages(10)
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs))
    monkeypatch.setattr(fetch_rua.graph_client, "get", lambda tok, url, params=None: {"value": []})
    state, o = tmp_path / "state.json", tmp_path / "o"
    fetch_rua.fetch("tok", "box@example.com", o, str(state), None, 0, floor="2026-08-20")  # a first run
    st = json.loads(state.read_text(encoding="utf-8"))
    assert st["covered_from"] == "2026-08-20T00:00:00Z" and st["last_received"] == msgs[9]["receivedDateTime"]
    fetch_rua.fetch("tok", "box@example.com", o, str(state), None, 0, floor="2026-08-25")  # a resume keeps it
    assert json.loads(state.read_text(encoding="utf-8"))["covered_from"] == "2026-08-20T00:00:00Z"
    fetch_rua.fetch("tok", "box@example.com", o, str(state), "2026-08-01", 0)  # a full backfill extends it back
    st = json.loads(state.read_text(encoding="utf-8"))
    assert st["covered_from"] == "2026-08-01T00:00:00Z" and st["last_received"] == msgs[9]["receivedDateTime"]


def test_a_backfill_skip_never_moves_the_saved_position_back_and_names_the_retry(monkeypatch, tmp_path):
    msgs = messages(5)
    monkeypatch.setattr(fetch_rua.graph_client, "get_all", filtered(msgs))

    def get(tok, url, params=None):
        if url.endswith("/m2/attachments"):
            raise graph_client.GraphError("request did not complete: IncompleteRead")
        return {"value": []}
    monkeypatch.setattr(fetch_rua.graph_client, "get", get)
    state = tmp_path / "state.json"
    newer = "2026-12-01T00:00:00Z"
    state.write_text(json.dumps({"last_received": newer, "mailbox": "box@example.com"}), encoding="utf-8")
    count, notes = fetch_rua.fetch("tok", "box@example.com", tmp_path / "o", str(state), "2026-09-01", 0)
    st = json.loads(state.read_text(encoding="utf-8"))
    assert st["last_received"] == newer and "covered_from" not in st  # a hole: coverage is not claimed
    assert any("retry them with --since %s" % msgs[2]["receivedDateTime"] in n for n in notes)
