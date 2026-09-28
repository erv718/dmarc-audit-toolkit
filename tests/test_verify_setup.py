"""verify_setup.py: role review and the check sequence, with Graph stubbed."""

import graph_client
import verify_setup as vs


def test_role_review_flags_missing_extra_and_write_capable():
    rv = vs.role_review(["Mail.Read", "eDiscovery.ReadWrite.All", "AuditLog.Read.All", "Directory.Read.All"])
    assert rv["required_missing"] == ["ThreatHunting.Read.All"]
    assert rv["domain_role"] == "Directory.Read.All"
    assert rv["mail_role"] == "Mail.Read"
    assert rv["extra"] == ["AuditLog.Read.All", "eDiscovery.ReadWrite.All"]
    assert rv["extra_write"] == ["eDiscovery.ReadWrite.All"]


def test_role_review_minimal_set_is_clean():
    rv = vs.role_review(["ThreatHunting.Read.All", "Domain.Read.All", "Mail.Read"])
    assert rv["required_missing"] == [] and rv["extra"] == [] and rv["domain_role"] == "Domain.Read.All"


def test_run_checks_without_credentials(monkeypatch):
    monkeypatch.setattr(graph_client, "creds", lambda env_file=None: None)
    monkeypatch.setattr(graph_client, "missing_keys", lambda: ["AZURE_CLIENT_SECRET"])
    res = vs.run_checks()
    assert len(res) == 1
    assert res[0]["status"] == "FAIL" and "AZURE_CLIENT_SECRET" in res[0]["detail"]


def test_run_checks_token_failure_stops_early(monkeypatch):
    monkeypatch.setattr(graph_client, "creds", lambda env_file=None: ("t", "c", "s"))

    def boom(cred):
        raise graph_client.GraphError("token request failed: HTTP 401 - check the tenant id")
    monkeypatch.setattr(graph_client, "token", boom)
    res = vs.run_checks()
    assert res[-1]["check"] == "token" and res[-1]["status"] == "FAIL"
    assert "expired" in res[-1]["fix"]


def test_run_checks_happy_path_flags_excess_write_role(monkeypatch):
    monkeypatch.setattr(graph_client, "creds", lambda env_file=None: ("t", "c", "s"))
    monkeypatch.setattr(graph_client, "token", lambda cred: "tok")
    monkeypatch.setattr(graph_client, "roles", lambda tok: [
        "ThreatHunting.Read.All", "Domain.Read.All", "Mail.Read", "eDiscovery.ReadWrite.All"])
    monkeypatch.setattr(graph_client, "list_domains", lambda tok: [{"domain": "example.com", "verified": True}])
    monkeypatch.setattr(graph_client, "hunting", lambda tok, kql, ts=None: {"results": [{}]})

    def mbox(tok, mailbox, top=1, select=None):
        if mailbox == "reports@example.com":
            return [{"id": "1"}]
        raise graph_client.GraphError("HTTP 403 on users/x/messages", 403)
    monkeypatch.setattr(graph_client, "mailbox_messages", mbox)

    res = vs.run_checks(mailbox="reports@example.com", expect_denied="someone@example.com")
    by = {r["check"]: r for r in res}
    assert by["token"]["status"] == "PASS"
    assert by["roles"]["status"] == "PASS"
    assert by["roles: excess (write-capable)"]["status"] == "WARN"
    assert "eDiscovery.ReadWrite.All" in by["roles: excess (write-capable)"]["detail"]
    assert by["GET /domains"]["status"] == "PASS"
    assert by["advanced hunting"]["status"] == "PASS"
    assert by["report mailbox"]["status"] == "PASS"
    assert by["mailbox scope"]["status"] == "PASS"
    assert not any(r["status"] == "FAIL" for r in res)


def test_run_checks_unscoped_mailbox_is_a_failure(monkeypatch):
    monkeypatch.setattr(graph_client, "creds", lambda env_file=None: ("t", "c", "s"))
    monkeypatch.setattr(graph_client, "token", lambda cred: "tok")
    monkeypatch.setattr(graph_client, "roles", lambda tok: ["ThreatHunting.Read.All", "Domain.Read.All", "Mail.Read"])
    monkeypatch.setattr(graph_client, "list_domains", lambda tok: [])
    monkeypatch.setattr(graph_client, "hunting", lambda tok, kql, ts=None: {"results": []})
    monkeypatch.setattr(graph_client, "mailbox_messages", lambda tok, mailbox, top=1, select=None: [{"id": "1"}])
    res = vs.run_checks(mailbox="reports@example.com", expect_denied="someone@example.com")
    by = {r["check"]: r for r in res}
    assert by["mailbox scope"]["status"] == "FAIL"
    assert "not scoped" in by["mailbox scope"]["detail"]


def test_jwt_claims_decodes_roles_without_verifying():
    import base64
    import json
    payload = base64.urlsafe_b64encode(json.dumps({"roles": ["Mail.Read", "ThreatHunting.Read.All"]}).encode()).decode().rstrip("=")
    tok = "eyJhbGciOiJub25lIn0." + payload + ".sig"
    assert graph_client.roles(tok) == ["Mail.Read", "ThreatHunting.Read.All"]
    assert graph_client.roles("not-a-jwt") == []
