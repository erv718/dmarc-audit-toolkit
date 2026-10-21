"""Round 10, phase 2: three questions the operator answered in the portal by
hand, answered by the toolkit itself. G1: a message delivered despite failing
names the local override that let it in. G2: every audited name's mail flow,
the organizational domain included, is measured on every run that has a
token. G3: an organization whose rows the row budget cut gets its whole
window counted in advanced hunting, beside the floor the verdicts rest on.
Synthetic data, offline: the hunting seam (graph_client.hunting) answers
with recorded results."""

import csv
import json
import re
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import audit
import collect
import dedupe
import discover
import dns_audit
import graph_client
import next_steps
import notify
import plan as plan_mod

ROOT = Path(__file__).resolve().parent.parent
QUERIES = ROOT / "queries"
BASE = ["Timestamp", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
        "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC", "Direction"]
OVERRIDES = ["Org level action", "Org level policy", "User level action", "User level policy"]
INBOX = ("Delivered", "Inbox/folder")
QUARANTINED = ("Blocked", "Quarantine")
ETR = ("Exchange transport rule", "Allow")
SAFE = ("Safe senders list", "Allow")
COLS = {"msgid": "Internet message ID", "recipient": "Recipients", "sender": "Sender address",
        "domain": "Sender domain", "action": "Delivery action", "location": "Latest delivery location",
        "subject": "Subject", "envelope": "Sender mail from domain", "direction": "Direction"}


def leg(where=INBOX, dmarc="fail", org=None, user=None, direction="Inbound"):
    """One row of a message: where it went, its DMARC verdict, the override recorded on it ((policy, action))."""
    return {"where": where, "dmarc": dmarc, "org": org, "user": user, "direction": direction}


class Log:
    """A synthetic mail-log export, with or without the four override columns raw_maillog.kql writes."""

    def __init__(self, overrides=True):
        self.cols = BASE + (OVERRIDES if overrides else [])
        self.rows, self.n = [], 0

    def add(self, sender, subject, *legs, times=1, env=None):
        """times messages from sender; each message is one row per leg ('#' in the subject: the message number)."""
        for _ in range(times):
            self.n += 1
            for lg in legs or (leg(dmarc="pass"),):
                org, user = lg["org"] or ("", ""), lg["user"] or ("", "")
                row = {"Timestamp": "2026-10-07T%02d:%02d:00Z" % (self.n // 60 % 24, self.n % 60),
                       "Internet message ID": "<m%04d@mail.invalid>" % self.n, "Sender address": sender,
                       "Sender domain": sender.rpartition("@")[2], "Sender mail from domain": env or sender.rpartition("@")[2],
                       "Recipients": "user%d@example.com" % (self.n % 5), "Subject": subject.replace("#", str(self.n)),
                       "Delivery action": lg["where"][0], "Latest delivery location": lg["where"][1],
                       "DMARC": lg["dmarc"], "Direction": lg["direction"],
                       "Org level action": org[1], "Org level policy": org[0],
                       "User level action": user[1], "User level policy": user[0]}
                self.rows.append([row[c] for c in self.cols])
        return self

    def write(self, path):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(self.cols)
            w.writerows(self.rows)
        return str(path)


def dedupe_doc(path):
    """dedupe.py's --json document for an export, exactly as its main() builds it."""
    rows = list(dedupe.load(path, COLS))
    counts = dedupe.count_rows(rows, COLS, None, "DMARC")
    verdicts = dedupe.classify(rows, COLS, None, "DMARC")
    counts.update(dedupe.summarize(verdicts))
    _, missing = dedupe.check_columns(dedupe.read_header(path), COLS, "DMARC")
    findings = dedupe.build_findings(counts, verdicts, "DMARC", missing)
    return dedupe.build_doc(path, counts, verdicts, findings, None, "DMARC")


def finding(doc, fid):
    return next(f for f in doc["findings"] if f["id"] == fid)


def stand_line(doc, head):
    return next(l for l in doc["stand"]["lines"] if l.startswith(head))


def actions(doc):
    return {i["hook"]: i["action"] for g in doc["actions_by_owner"] for i in g["items"]}


def mail_log_line(text):
    return next(l for l in text.splitlines() if l.startswith("- mail log:"))


def overridden_log(overrides=True):
    """Seven messages delivered despite failing: three through a transport rule, two through a user's safe
    sender list and one with nothing recorded (one sender), one through a policy with no plain words."""
    return (Log(overrides).add("staff@example.com", "Weekly report #", times=20)
            .add("billing@example.com", "Statement #", leg(org=ETR), times=3)
            .add("alerts@example.com", "Alert #", leg(user=SAFE), times=2)
            .add("alerts@example.com", "Alert #", leg())
            .add("legacy@example.com", "Scan #", leg(org=("Connection policy", "Allow"))))


# ------------------------------------------------------------------ G1: the override, named

def test_g1_raw_maillog_appends_the_four_override_columns_after_every_existing_one():
    kql = (QUERIES / "raw_maillog.kql").read_text(encoding="utf-8")
    names = re.findall(r"\['([^']+)'\]\s*=", kql)
    assert names == ["Internet message ID", "Recipients", "Sender address", "Sender domain", "Sender mail from domain",
                     "Delivery action", "Latest delivery location", "Subject", "DMARC", "SPF", "DKIM",
                     "Envelope domain", "Sender IP", "Timestamp", "Direction"] + OVERRIDES
    for name, column in zip(OVERRIDES, ("OrgLevelAction", "OrgLevelPolicy", "UserLevelAction", "UserLevelPolicy")):
        # a tenant whose schema lacks the column gets an empty one, never a failed query
        assert re.search(r"\['%s'\]\s*= tostring\(column_ifexists\(\"%s\", \"\"\)\)" % (name, column), kql), name
    sizing = collect.count_kql(kql, "example.com", 720)  # the hourly sizing still cuts before the projection
    assert sizing and "column_ifexists" not in kql_body(sizing) and sizing.rstrip().endswith(collect.COUNT_TAIL)


def test_g1_an_export_without_the_override_columns_reads_exactly_as_before(tmp_path):
    doc = dedupe_doc(overridden_log(overrides=False).write(tmp_path / "plain.csv"))
    assert not any("delivered_by" in v for v in doc["verdicts"])
    assert "delivered_despite_fail_by" not in doc["counters"]
    assert not any("delivered_by" in r for r in doc["census"]["by_sender"] + doc["census"]["by_envelope"])
    items = [((v["msgid"], v["recipient"]), v) for v in doc["verdicts"] if v["delivered_despite_fail"]]
    assert finding(doc, "MAILFLOW-002")["evidence"] == dedupe._sample(items)  # the evidence as it always read
    assert not [f for f in doc["findings"] if f["id"] == "MAILFLOW-008"]  # nothing warns about the absent columns
    rep = audit.build_report(domains=["example.com"], maillog=str(tmp_path / "plain.csv"), offline=True,
                             auth_column="DMARC")
    assert "- delivered despite fail: 7; blocked despite pass: 0" in audit.render_md(rep).splitlines()
    assert ", 7 delivered despite failing, spoof-like " in mail_log_line(notify.summarize(rep))
    ns = next_steps.build(rep)
    assert stand_line(ns, "**Delivered despite failing") == (
        "**Delivered despite failing: 7** - these only arrive because of our own overrides; outside receivers are not "
        "as forgiving (alerts@example.com x3, billing@example.com x3, legacy@example.com x1)")
    # round 13, T-08: billing@ is our own system: its override goes only after it passes, and the line says why
    assert actions(ns)["billing@example.com - 3 messages reached inboxes despite failing"] == (
        "find the override (transport rule, allow list, safe sender) that let them in; after billing@example.com "
        "passes DMARC, make it conditional on authentication - doing it first junks these 3 too; outside receivers "
        "do not have it")
    assert "delivered_despite_fail_by" not in ns["stand"]
    # the columns present but empty: nothing is named, and the evidence reads the same
    empty = dedupe_doc(Log().add("billing@example.com", "Statement #", leg(), times=2).write(tmp_path / "empty.csv"))
    assert {v["delivered_by"] for v in empty["verdicts"]} == {None}
    assert empty["counters"]["delivered_despite_fail_by"] == {}  # the columns were there: an empty map says so
    assert empty["census"]["by_sender"][0]["delivered_by"] == {}
    assert not finding(empty, "MAILFLOW-002")["evidence"].startswith("let in by")


def test_g1_the_override_comes_from_the_delivered_failing_leg(tmp_path):
    log = (Log()
           # a blocked failing hop names a rule, the delivered failing copy a user's safe sender list
           .add("alerts@example.com", "Alert #", leg(QUARANTINED, org=("Exchange transport rule", "Block")),
                leg(user=SAFE, direction="Intra-org"))
           .add("billing@example.com", "Statement #", leg(org=ETR, user=SAFE))  # the org level wins
           .add("news@example.com", "News #", leg())  # delivered, nothing recorded
           # the only delivered leg carries no verdict: it is still the leg that delivered the failure
           .add("ops@example.com", "Run #", leg(QUARANTINED), leg(dmarc="", org=("Allowed sender list", "Allow"),
                                                                  direction="Intra-org"))
           .add("staff@example.com", "Hello #", leg(dmarc="pass", org=ETR))  # passed: nothing to name
           .add("printer@example.com", "Scan #", leg(org=("Exchange transport rule", ""))))  # no action recorded
    doc = dedupe_doc(log.write(tmp_path / "legs.csv"))
    by = {v["sender"]: v["delivered_by"] for v in doc["verdicts"]}
    assert by == {"alerts@example.com": "user: Safe senders list (Allow)",
                  "billing@example.com": "org: Exchange transport rule (Allow)", "news@example.com": None,
                  "ops@example.com": "org: Allowed sender list (Allow)", "staff@example.com": None,
                  "printer@example.com": "org: Exchange transport rule"}
    assert doc["counters"]["delivered_despite_fail"] == 5
    assert doc["counters"]["delivered_despite_fail_by"] == {
        "org: Allowed sender list (Allow)": 1, "org: Exchange transport rule": 1,
        "org: Exchange transport rule (Allow)": 1, "user: Safe senders list (Allow)": 1}
    census = {r["sender"]: r["delivered_by"] for r in doc["census"]["by_sender"]}
    assert census["alerts@example.com"] == {"user: Safe senders list (Allow)": 1}
    assert census["news@example.com"] == {} and census["staff@example.com"] == {}
    assert finding(doc, "MAILFLOW-002")["evidence"].startswith(
        "let in by an Exchange transport rule x2, a user's safe sender list x1, the allowed sender list x1; "
        "no override recorded for 1; ")


def test_g1_the_delivered_failing_leg_names_the_override_before_any_other_delivered_leg(tmp_path):
    # both copies reached the inbox: the one that stayed inside (no verdict) through a transport rule, the failing
    # one through a user's safe sender list - the failing copy's override is what let the failure in, in either order
    inside = leg(dmarc="none", org=ETR, direction="Intra-org")
    log = (Log().add("alerts@example.com", "Alert #", inside, leg(user=SAFE))
           .add("alerts@example.com", "Alert #", leg(user=SAFE), inside)
           # the failing copy reached the inbox and names nothing: the inside copy's rule is not what let it in,
           # so the data shows no cause; the other delivered copy speaks only when no failing copy was delivered
           .add("ops@example.com", "Run #", inside, leg())
           .add("ops@example.com", "Run #", inside, leg(where=QUARANTINED)))
    doc = dedupe_doc(log.write(tmp_path / "order.csv"))
    safe = ("alerts@example.com", "user: Safe senders list (Allow)")
    assert [(v["sender"], v["delivered_by"]) for v in doc["verdicts"]] == [
        safe, safe, ("ops@example.com", None), ("ops@example.com", "org: Exchange transport rule (Allow)")]
    # the full-window totals take it the same way: the delivered failing leg, else another delivered leg only
    # when no failing leg reached a mailbox
    body = kql_body((QUERIES / "maillog_totals.kql").read_text(encoding="utf-8"))
    assert 'by_failing = take_anyif(reason, on_mailbox and dmarc contains "fail" and isnotempty(reason))' in body
    assert 'iff(isnotempty(by_failing), by_failing, iff(failing_on == 1, "", by_other))' in body


def test_g1_plain_words_for_the_common_overrides_and_anything_else_verbatim():
    words = {"org: Exchange transport rule (Allow)": "an Exchange transport rule",
             "org: Mail flow rule (Allow)": "an Exchange transport rule",
             "org: Allowed sender list (Allow)": "the allowed sender list",
             "org: Allowed sender domain list (Allow)": "the allowed sender domain list",
             "org: Tenant Allow Block List (Allow)": "a spoof allow / Tenant Allow Block List entry",
             "org: Spoof allow (Allow)": "a spoof allow / Tenant Allow Block List entry",
             "user: Safe senders list (Allow)": "a user's safe sender list",
             "org: Connection policy (Allow)": "org: Connection policy (Allow)"}
    assert {r: dedupe.override_words(r) for r in words} == words
    assert dedupe.override_kind("org: Connection policy (Allow)") is None
    assert dedupe.delivered_by_text({"org: Exchange transport rule (Allow)": 2, "org: Exchange transport rule (Junk)": 1,
                                     "user: Safe senders list (Allow)": 1}, 6) == (
        "an Exchange transport rule x2, a user's safe sender list x1, org: Exchange transport rule (Junk) x1; "
        "no override recorded for 2")  # a Junk action is no allow: that reason keeps its own words
    assert dedupe.override_kind("org: Exchange transport rule (Junk)") is None
    assert dedupe.override_words("org: Tenant Allow Block List (Block)") == "org: Tenant Allow Block List (Block)"
    assert dedupe.delivered_by_text({}, 3) == "" and dedupe.delivered_by_text(None) == ""
    assert dedupe.delivered_by_text({"org: x": "two", "": 4, "org: y": True}, 1) == ""  # odd values read as nothing


def test_g1_the_readers_name_the_override_in_plain_words(tmp_path):
    rep = audit.build_report(domains=["example.com"], maillog=overridden_log().write(tmp_path / "log.csv"),
                             offline=True, auth_column="DMARC")
    named = "an Exchange transport rule x3, a user's safe sender list x2, org: Connection policy (Allow) x1"
    md = audit.render_md(rep).splitlines()
    assert "- delivered despite fail: 7 (let in by %s; no override recorded for 1); blocked despite pass: 0" % named in md
    assert finding(rep["maillog"], "MAILFLOW-002")["evidence"].startswith(
        "let in by %s; no override recorded for 1; " % named)
    assert "7 delivered despite failing (let in by %s; no override recorded for 1), spoof-like " % named \
        in mail_log_line(notify.summarize(rep))
    doc = next_steps.build(rep)
    assert stand_line(doc, "**Delivered despite failing") == (
        "**Delivered despite failing: 7** - let in by %s (outside receivers do not have these overrides); no override "
        "recorded for 1 (the log names nothing that let them in) (alerts@example.com x3, billing@example.com x3, "
        "legacy@example.com x1)" % named)
    assert doc["stand"]["delivered_despite_fail_by"] == rep["maillog"]["counters"]["delivered_despite_fail_by"]
    todo = actions(doc)
    # round 13, T-08: our own sender's rule goes only after the sender passes
    assert todo["billing@example.com - 3 messages reached inboxes despite failing"] == (
        "delivered because of an Exchange transport rule: after billing@example.com passes DMARC, make that rule "
        "conditional on authentication - doing it first junks these 3 too; outside receivers do not have it")
    assert todo["alerts@example.com - 3 messages reached inboxes despite failing"] == (
        "delivered because of a user's safe sender list (2), and the log names no override for the other 1: after "
        "alerts@example.com passes DMARC, ask the mailbox owners to take the sender off their safe sender lists - doing "
        "it first junks these 3 too; for the other 1, look for what the log does not record (a mailbox rule, a "
        "connector, a filter in front of the tenant); outside receivers do not have them")
    assert todo["legacy@example.com - 1 message reached inboxes despite failing"] == (
        'delivered because of "org: Connection policy (Allow)": after legacy@example.com passes DMARC, make that '
        "override conditional on authentication - doing it first junks this one too; outside receivers do not have it")
    # several overrides behind one sender: each named with its count, each with its own fix
    assert next_steps.override_action({"org: Allowed sender domain list (Allow)": 2, "org: Spoof allow (Allow)": 1}, 3) == (
        "delivered because of the allowed sender domain list (2) and a spoof allow / Tenant Allow Block List entry "
        "(1): take the domain off the allowed sender domain list in the anti-spam policy; fix the sender's "
        "authentication, then remove that allow entry; outside receivers do not have them")


def test_g1_an_excepted_sender_keeps_its_override_off_the_work_list_with_or_without_the_verdicts(tmp_path):
    exc = {"match": "billing@example.com", "reason": "accepted for the test", "owner": "it", "until": "2099-01-01",
           "removal_criterion": "the sender signs with DKIM"}
    path = overridden_log().write(tmp_path / "log.csv")
    for keep in (False, True):  # the census path (report.json as written) and the verdicts path
        rep = audit.build_report(domains=["example.com"], maillog=path, offline=True, auth_column="DMARC",
                                 exceptions=[exc], keep_verdicts=keep)
        doc = next_steps.build(rep)
        todo = actions(doc)
        assert not [h for h in todo if h.startswith("billing@example.com")], keep
        assert todo["legacy@example.com - 1 message reached inboxes despite failing"].startswith(
            'delivered because of "org: Connection policy (Allow)": '), keep
        line = stand_line(doc, "**Delivered despite failing")
        # the excepted sender's transport rule is not credited to the senders left (N37)
        assert line.startswith("**Delivered despite failing: 7** (3 of them formally excepted in audit.toml) - let in "
                               "by a user's safe sender list x2, org: Connection policy (Allow) x1 (outside "), keep
        assert "an Exchange transport rule" not in line and "no override recorded for 1" in line, keep


# ------------------------------------------------------------------ G2: the mail flow of every audited name

class Hunting:
    """graph_client.hunting answering the mail-flow aggregate with recorded rows (or an error), every call kept."""

    def __init__(self, rows=(), error=None, schema=("d", "messages", "outbound", "inbound", "last_seen")):
        self.rows, self.error, self.schema, self.calls = list(rows), error, schema, []

    def __call__(self, tok, kql, ts=None):
        self.calls.append((tok, kql, ts))
        if self.error:
            raise graph_client.GraphError(self.error)
        return {"schema": [{"name": c} for c in self.schema], "results": [dict(r) for r in self.rows]}


def flow(d, messages, outbound, inbound, last_seen="2026-10-07T14:02:11Z"):
    return {"d": d, "messages": messages, "outbound": outbound, "inbound": inbound, "last_seen": last_seen}


def no_sign_in(monkeypatch):
    """A second sign-in (credentials read, token fetched) fails the test."""
    def refuse(*a, **k):
        raise AssertionError("a second sign-in")
    monkeypatch.setattr(graph_client, "creds", refuse)
    monkeypatch.setattr(graph_client, "token", refuse)


def test_g2_the_mail_flow_query_counts_each_organization_itself_and_its_subdomains():
    kql = discover.mailflow_kql(["corp.example", "shop.example"], 7)
    assert ('| where d == "corp.example" or d endswith ".corp.example" or d == "shop.example" or d endswith '
            '".shop.example"') in kql
    assert "| where Timestamp > ago(7d)" in kql
    for column in ("messages = dcount(InternetMessageId)", "outbound = dcountif(InternetMessageId, EmailDirection in~ "
                   "(\"Outbound\", \"Intra-org\"))", "inbound = dcountif(InternetMessageId, EmailDirection =~ "
                   "\"Inbound\")", "last_seen = max(Timestamp)"):
        assert column in kql


def test_g2_discover_measures_every_name_with_the_token_it_holds(monkeypatch):
    no_sign_in(monkeypatch)
    hunt = Hunting([flow("corp.example", 120, 100, 20), flow("mail.corp.example", 5, 5, 0),
                    flow("new.corp.example", 3, 3, 0), flow("outside.example", 9, 9, 0)])
    monkeypatch.setattr(graph_client, "hunting", hunt)
    names = ["corp.example", "mail.corp.example", "shop.example"]
    inv, notes = discover.discover(names, use_graph=False, ns_lookup=False, tok="tok", days=30)
    by = {r["domain"]: r for r in inv}
    assert set(by) == set(names)  # without --mailflow nothing is added
    assert by["corp.example"]["mailflow"] == {"messages": 120, "outbound": 100, "inbound": 20,
                                              "last_seen": "2026-10-07T14:02:11Z"}  # the organization itself
    assert by["shop.example"]["mailflow"] == {"messages": 0, "outbound": 0, "inbound": 0, "last_seen": None}
    assert [(tok, ts) for tok, _, ts in hunt.calls] == [("tok", "P30D")]  # one query, the token handed over
    assert "mail flow over the last 30 days measured for 3 domains (2 sent or received mail, 1 none)" in notes
    # --mailflow adds the subdomains the same query saw, never the organization itself as a new name
    inv, notes = discover.discover(["mail.corp.example"], use_graph=False, mailflow=True, ns_lookup=False, tok="tok")
    by = {r["domain"]: r for r in inv}
    assert set(by) == {"mail.corp.example", "new.corp.example"} and len(hunt.calls) == 2
    assert by["new.corp.example"]["sources"] == ["mailflow"] and by["new.corp.example"]["mailflow"]["outbound"] == 3
    assert by["mail.corp.example"]["sources"] == ["cli", "mailflow"]
    assert "mail flow: 2 sending domains under corp.example" in notes


def test_g2_a_failed_mail_flow_query_measures_nothing(monkeypatch):
    no_sign_in(monkeypatch)
    monkeypatch.setattr(graph_client, "hunting", Hunting(error="HTTP 400 on hunting: bad query"))
    inv, notes = discover.discover(["corp.example", "shop.example"], use_graph=False, mailflow=True, ns_lookup=False,
                                   tok="tok")
    assert [r["mailflow"] for r in inv] == [None, None]  # not measured, never zeros
    assert [r["domain"] for r in inv] == ["corp.example", "shop.example"]
    assert "mail flow not measured: HTTP 400 on hunting: bad query" in notes
    # an answer that is not the counts the query asks for is no measurement either
    monkeypatch.setattr(graph_client, "hunting", Hunting([{"x": 1}], schema=("x",)))
    inv, notes = discover.discover(["corp.example"], use_graph=False, ns_lookup=False, tok="tok")
    assert inv[0]["mailflow"] is None
    assert "mail flow not measured: the answer is not the mail-flow counts the query asks for" in notes
    # no results list, rows that are not rows, counts that are not whole numbers: never read as nothing seen
    for answer, why in (({}, "the answer carries no results"),
                        ({"schema": [], "results": None}, "the answer carries no results"),
                        ({"results": [["corp.example", 5, 5, 0]]}, "the answer is not the mail-flow counts the query "
                                                                   "asks for"),
                        ({"results": [flow("corp.example", "x", 1, 0)]}, "the answer's counts for corp.example are "
                                                                         "not whole numbers"),
                        ({"results": [flow("corp.example", 5, -1, 0)]}, "the answer's counts for corp.example are not "
                                                                        "whole numbers"),
                        ({"results": [flow("corp.example", 5, 5, None)]}, "the answer's counts for corp.example are "
                                                                          "not whole numbers"),
                        ({"results": [flow("corp.example", 5.5, 5, 0)]}, "the answer's counts for corp.example are "
                                                                         "not whole numbers")):
        monkeypatch.setattr(graph_client, "hunting", lambda tok, kql, ts=None, a=answer: json.loads(json.dumps(a)))
        inv, notes = discover.discover(["corp.example", "shop.example"], use_graph=False, ns_lookup=False, tok="tok")
        assert [r["mailflow"] for r in inv] == [None, None], answer
        assert "mail flow not measured: " + why in notes, answer
    # an empty results list is an answer (nothing seen), counts sent as text are the numbers they spell, and a
    # row for a name outside the audited organizations is not read at all
    answer = {"results": [flow("corp.example", "12", "10", "2"), flow("outside.example", "x", None, -1)]}
    monkeypatch.setattr(graph_client, "hunting", lambda tok, kql, ts=None: json.loads(json.dumps(answer)))
    inv, _ = discover.discover(["corp.example", "shop.example"], use_graph=False, ns_lookup=False, tok="tok")
    assert [r["mailflow"] for r in inv] == [{"messages": 12, "outbound": 10, "inbound": 2,
                                             "last_seen": "2026-10-07T14:02:11Z"}, discover.MAILFLOW_NONE]
    monkeypatch.setattr(graph_client, "hunting", lambda tok, kql, ts=None: {"schema": [], "results": []})
    inv, _ = discover.discover(["corp.example"], use_graph=False, ns_lookup=False, tok="tok")
    assert inv[0]["mailflow"] == discover.MAILFLOW_NONE


def test_g2_mailflow_subdomains_signs_in_and_still_adds_subdomains_only(monkeypatch):
    monkeypatch.setattr(graph_client, "creds", lambda env_file=None: ("t", "c", "s"))
    monkeypatch.setattr(graph_client, "token", lambda cred: "tok")
    monkeypatch.setattr(graph_client, "hunting", Hunting([flow("corp.example", 120, 100, 20),
                                                          flow("mail.corp.example", 5, 5, 0)]))
    rows, note = discover.mailflow_subdomains(["corp.example"])
    assert note is None and [r["domain"] for r in rows] == ["mail.corp.example"]
    assert rows[0] == {"domain": "mail.corp.example", "messages": 5, "outbound": 5, "inbound": 0,
                       "last_seen": "2026-10-07T14:02:11Z"}
    monkeypatch.setattr(graph_client, "hunting", Hunting(error="HTTP 403 on hunting: denied"))
    assert discover.mailflow_subdomains(["corp.example"]) == ([], "mail-flow expansion failed: HTTP 403 on hunting: denied")


def dns_doc(domain, **over):
    """A live-DNS answer as dns_audit writes it; by default a domain with no records at all."""
    doc = {"domain": domain, "spf": None, "spf_status": "absent", "spf_terminator": None, "spf_lookups": 0,
           "dmarc": None, "dmarc_source": None, "effective_policy": None, "inherited": False, "dmarc_status": "absent",
           "dkim_selectors": [], "dkim_status": "absent", "dkim_probed": ["selector1"], "mx": [], "mx_null": False,
           "mx_status": "absent",
           "findings": [{"id": "DMARC-001", "severity": "major", "area": "dmarc", "title": "no DMARC record",
                         "evidence": "none", "action": "publish one", "verified": True},
                        {"id": "SPF-001", "severity": "minor", "area": "spf", "title": "no SPF record",
                         "evidence": "none", "action": "publish one", "verified": True}]}
    doc.update(over)
    return doc


RECORD = "v=DMARC1; p=none; rua=mailto:reports@example.com;"
VERIFIED = "verified unused: no outbound mail in 30 days, no passing aggregate volume"
UNVERIFIED = ("verify unused first: no outbound mail in 30 days (this run did not measure it: a collect.py run with the app registration does), no passing volume in "
              "aggregate reports, no owner objects")


def parked_report(rua=None, mailflow=None):
    """example.com sends and publishes p=none with rua; old.example.com inherits that record and has no MX, SPF
    or DKIM (a parked candidate); parked.example has no record at all."""
    dns = {"example.com": dns_doc("example.com", dmarc=RECORD, dmarc_source="_dmarc.example.com", effective_policy="none",
                                  dmarc_status="found", spf="v=spf1 include:mail.example -all", spf_status="found",
                                  spf_terminator="-all", spf_lookups=1, dkim_selectors=["selector1"], dkim_status="found",
                                  mx=["10 mx.example"], mx_status="found", findings=[]),
           "old.example.com": dns_doc("old.example.com", dmarc=RECORD, dmarc_source="_dmarc.example.com",
                                      inherited=True, effective_policy="none", dmarc_status="found",
                                      findings=[f for f in dns_doc("x")["findings"] if f["id"] == "SPF-001"]),
           "parked.example": dns_doc("parked.example")}
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "dns": dns, "gate": {"domains": {}},
           "inputs": {"domains": sorted(dns)}, "rua": rua}
    if mailflow is not None:
        rep["mailflow"] = mailflow
    return rep


def reports_about(*froms):
    """report.rua as audit.py keeps it: aggregate reports about example.com's record, with these header From rows
    ((domain, passing, failing))."""
    rows = [("example.com", 900, 0)] + list(froms)
    return {"totals": {"messages": sum(p + f for _, p, f in rows), "domains": ["example.com"]},
            "policy_check": {"seen": [{"domain": "example.com", "p": "none", "sp": None, "reports": 3}]},
            "by_header_from": [{"domain": d, "count": p + f, "pass": p, "fail": f} for d, p, f in rows],
            "failing_streams": [], "spf_only_senders": []}


def park_notes(rep, flows=None):
    """{domain: the prerequisites of its park rows} and the plan; flows: {domain: mailflow} as inventory rows."""
    inventory = {"domains": [{"domain": d, "mailflow": f} for d, f in (flows or {}).items()]}
    p = plan_mod.build_plan(rep, inventory if flows else None, "mailto:reports@example.com")
    out = {}
    for c in p["changes"]:
        if c["kind"] == "park":
            out.setdefault(c["domain"], set()).update(c["prerequisites"])
    return {d: sorted(v) for d, v in out.items()}, p


def zeros(**over):
    return dict(discover.MAILFLOW_NONE, **over)


def test_g2_the_plan_calls_a_domain_unused_only_when_every_check_was_made():
    covered = reports_about()  # reports about example.com's record: old.example.com's mail would show there
    # every check made: no mail in or out over 30 days, and the reports that cover it count no passing mail as it
    notes, p = park_notes(parked_report(covered), {"old.example.com": zeros(), "parked.example": zeros()})
    assert notes["old.example.com"] == [VERIFIED]
    assert len([c for c in p["changes"] if c["domain"] == "old.example.com" and c["kind"] == "park"]) == 2
    # parked.example has no DMARC record, so no report can cover it: measured silent, still not verified (its new
    # record reports to another organization's mailbox, so that row also names the external-destination record)
    assert notes["parked.example"] == [
        plan_mod.external_destination("parked.example", "mailto:reports@example.com"),
        "verify unused first: no passing volume in aggregate reports, no owner objects"]
    # the status document's ask counts only the park rows still waiting on a check: parked.example's two
    ask = next_steps.build_ask(p, "example.com", None, None)
    assert "of which 2 are park rows that need the domain's unused check first" in ask
    verified_only = dict(p, changes=[c for c in p["changes"] if c["domain"] != "parked.example"])
    assert "unused check" not in next_steps.build_ask(verified_only, "example.com", None, None)
    # no aggregate reports in the run: the tenant's silence alone verifies nothing
    assert park_notes(parked_report(None), {"old.example.com": zeros()})[0]["old.example.com"] == [
        "verify unused first: no passing volume in aggregate reports, no owner objects"]
    # nothing measured: the notes as they always were, or just the mail-flow check when the reports cover it
    assert park_notes(parked_report(None))[0]["old.example.com"] == [UNVERIFIED]
    assert park_notes(parked_report(covered))[0]["old.example.com"] == [
        "verify unused first: no outbound mail in 30 days (this run did not measure it: a collect.py run with the app registration does), no owner objects"]
    # mail that came in with it as the From domain: a vendor or a spoof, which only a person can tell apart
    assert park_notes(parked_report(covered), {"old.example.com": zeros(messages=240, inbound=240)})[0][
        "old.example.com"] == ["verify unused first: the 240 inbound message(s) from it in 30 days are spoofs rather "
                               "than a vendor sending as it, no owner objects"]
    # a measurement shorter than 30 days verifies nothing (plan.py on a report.json, no inventory)
    short = parked_report(covered, {"days": 7, "source": collect.AGGREGATE_SOURCE,
                                    "domains": {"old.example.com": zeros()}})
    assert park_notes(short)[0]["old.example.com"] == [
        "verify unused first: no outbound mail in 30 days (the tenant measured 7 days only), no owner objects"]
    month = parked_report(covered, {"days": 30, "source": collect.AGGREGATE_SOURCE,
                                    "domains": {"old.example.com": zeros()}})
    assert park_notes(month)[0]["old.example.com"] == [VERIFIED]
    # spoofs in the reports (failing, never passing) are what a park stops: still verified
    spoofed = reports_about(("old.example.com", 0, 75))
    assert park_notes(parked_report(spoofed), {"old.example.com": zeros()})[0]["old.example.com"] == [VERIFIED]
    # passing mail as it in the reports: a third party sends as it straight to outside recipients - not parked
    sending = reports_about(("old.example.com", 500, 0))
    notes, p = park_notes(parked_report(sending), {"old.example.com": zeros()})
    assert "old.example.com" not in notes
    assert {c["kind"] for c in p["changes"] if c["domain"] == "old.example.com"} == {"new", "todo"}
    # outbound mail: sends, as before
    notes, p = park_notes(parked_report(covered), {"old.example.com": zeros(messages=4, outbound=4)})
    assert "old.example.com" not in notes


def test_g2_a_damaged_mail_flow_count_is_never_read_as_nothing_sent():
    covered = reports_about()
    for bad in ("3", "x", [1], -1, True, 2.5, None, float("nan")):
        for key in ("outbound", "inbound"):
            flows = {"old.example.com": zeros(**{key: bad})}
            notes, _ = park_notes(parked_report(covered), flows)  # never a TypeError
            assert notes["old.example.com"] == [
                "verify unused first: no outbound mail in 30 days (this run did not measure it: a collect.py run with the app registration does), no owner objects"], (key, bad)
            rep = parked_report(covered, {"days": 30, "domains": flows})  # the same through report.mailflow
            assert park_notes(rep)[0]["old.example.com"][0].startswith("verify unused first"), (key, bad)
    odd_days = parked_report(covered, {"days": "x", "domains": {"old.example.com": zeros()}})
    assert park_notes(odd_days)[0]["old.example.com"] == [
        "verify unused first: no outbound mail in 30 days (the tenant measured an unknown span), no owner objects"]


def rua_xml(path, header_from, count, dkim="pass"):
    """One aggregate report about example.com's record: count messages with header_from, DKIM-signed by it."""
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<feedback><report_metadata><org_name>reporter.example</org_name>'
        '<email>reports@reporter.example</email><report_id>r-%s</report_id><date_range><begin>1790000000</begin>'
        '<end>1790086399</end></date_range></report_metadata><policy_published><domain>example.com</domain>'
        '<adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published><record><row>'
        '<source_ip>198.51.100.77</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition>'
        '<dkim>%s</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>%s</header_from>'
        '<envelope_from>esp.example</envelope_from></identifiers><auth_results><dkim><domain>%s</domain>'
        '<selector>s1</selector><result>%s</result></dkim><spf><domain>esp.example</domain><scope>mfrom</scope>'
        '<result>pass</result></spf></auth_results></record></feedback>\n'
        % (header_from, count, dkim, header_from, header_from if dkim == "pass" else "attacker.invalid", dkim),
        encoding="utf-8")
    return str(path)


def test_g2_the_parked_decision_reads_the_aggregate_reports_audit_py_keeps(tmp_path):
    flows = {"days": 30, "source": collect.AGGREGATE_SOURCE,
             "domains": {"example.com": zeros(messages=900, outbound=800, inbound=100),
                         "news.example.com": zeros(), "old.example.com": zeros()}}
    names = ["example.com", "news.example.com", "old.example.com"]
    paths = [rua_xml(tmp_path / "news.xml", "news.example.com", 500),  # an ESP signing as news.example.com
             rua_xml(tmp_path / "old.xml", "old.example.com", 60, dkim="fail")]  # a spoof of old.example.com
    rep = audit.build_report(domains=names, rua_paths=paths, offline=True, mailflow=flows)
    rep["dns"] = {d: v for d, v in parked_report()["dns"].items() if d in names}
    rep["dns"]["news.example.com"] = dict(rep["dns"]["old.example.com"], domain="news.example.com")
    notes, p = park_notes(rep)
    assert "news.example.com" not in notes  # 500 passing in the reports: it sends, so it gets monitoring
    assert {c["kind"] for c in p["changes"] if c["domain"] == "news.example.com"} == {"new", "todo"}
    assert notes["old.example.com"] == [VERIFIED]  # only spoofs in the reports, nothing in the tenant
    # the same domains with no aggregate reports at all: nothing is verified, and news.example.com is a candidate
    bare = dict(rep, rua=None)
    assert park_notes(bare)[0] == {d: ["verify unused first: no passing volume in aggregate reports, no owner objects"]
                                   for d in ("news.example.com", "old.example.com")}


def mailflow_report(tmp_path, mailflow):
    log = (Log().add("staff@example.com", "Weekly report #", times=4)
           .add("app@a.example.com", "Build #", times=2).add("app@other.example", "Note #"))
    names = ["example.com", "a.example.com", "b.example.com", "c.example.com", "other.example"]
    return audit.build_report(domains=names, maillog=log.write(tmp_path / "log.csv"), offline=True,
                              auth_column="DMARC", mailflow=mailflow)


def test_g2_the_report_and_the_document_say_per_domain_what_was_measured(tmp_path):
    rep = mailflow_report(tmp_path, {"days": 30, "source": collect.AGGREGATE_SOURCE, "domains": {
        "example.com": {"messages": 120, "outbound": 100, "inbound": 20, "last_seen": "2026-10-07T14:02:11Z"},
        "a.example.com": dict(discover.MAILFLOW_NONE), "b.example.com": dict(discover.MAILFLOW_NONE),
        "c.example.com": None}})
    md = audit.render_md(rep)
    section = md.split("## Mail flow per domain (tenant)\n\n", 1)[1].split("\n## ", 1)[0].splitlines()
    assert section[:6] == ["- example.com: sends: 100 out, 20 in (30 days, tenant); last seen 2026-10-07 14:02",
                           "- a.example.com: nothing sent or received in 30 days (tenant)",
                           "- b.example.com: nothing sent or received in 30 days (tenant)",
                           "- c.example.com: not measured", "- other.example: not measured", ""]
    assert section[6] == audit.MAILFLOW_NOTE and "only the aggregate reports show it" in section[6]
    assert "The counts are advanced hunting estimates (dcount): zero means none" in section[6]
    assert ("mail flow per audited domain from one advanced hunting aggregate over the last 30 days (report.mailflow): "
            "1 of 3 sent or received mail") in rep["verified_vs_inferred"]["verified"]
    doc = next_steps.build(rep)
    out = next_steps.render_md(doc)
    step = "read the policy first: run online, or supply aggregate reports that cover it"
    assert "| Domain | Policy today | Gate | Next step | Mail flow |" in out
    # a policy the run did not read says why (round 13, T-12): DNS was not read here
    assert "| `example.com` | not read | needs more data | %s | sends: 100 out, 20 in (30 days, tenant) |" % step in out
    # subdomains share a row only when their mail flow reads the same
    assert ("| `a.example.com`, `b.example.com` | not read | needs more data | %s | nothing sent or received in 30 days "
            "(tenant) |" % step) in out
    assert "| `c.example.com` | not read | needs more data | %s | not measured |" % step in out
    assert "| `other.example` | not read | needs more data | %s | not measured |" % step in out
    assert ("Mail flow is what passed through our own tenant in the last 30 days with that domain as the sender: out is "
            "mail our people and systems sent, in is mail that arrived from outside (a vendor sending for us, or a "
            "spoof); the counts are close estimates, and zero means none. Mail a third party sends as one of our "
            "domains straight to outside recipients never passes through our tenant, so only the aggregate reports "
            "show it.") in out
    # a run that did not measure says so, and says what the tenant can never see either way
    rep = mailflow_report(tmp_path, None)
    assert rep["mailflow"] is None
    assert ("- not measured in this run: collect.py measures every audited domain's mail flow with one advanced "
            "hunting query on each run that has the app registration's token") in audit.render_md(rep)
    out = next_steps.render_md(next_steps.build(rep))
    assert "| `example.com` | not read | needs more data | %s | not measured |" % step in out
    assert ("Mail flow was not measured in this run (it is counted in our tenant on every run that can reach it). "
            "Mail a third party sends as one of our domains straight to outside recipients never passes through our "
            "tenant, so only the aggregate reports show it.") in out


# ------------------------------------------------------------------ G3: the whole window of a cut organization

def kql_body(text):
    return "\n".join(l.split("//", 1)[0] for l in text.splitlines())


def constructs(kql):
    """The functions and the pipe operators a query uses."""
    body = kql_body(kql)
    return (set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", body)) | set(re.findall(r"\|\s*([a-z][\w-]*)", body))
            | set(re.findall(r"\bkind=(\w+)", body)))


def test_g3_the_totals_query_uses_only_constructs_the_existing_queries_already_use():
    before = set()
    for path in QUERIES.glob("*.kql"):
        if path.name != "maillog_totals.kql":
            before |= constructs(path.read_text(encoding="utf-8"))
    before |= constructs(discover.mailflow_kql(["example.com"])) | constructs(collect.COUNT_TAIL)
    allowed = before | {"column_ifexists", "dcount", "take_anyif"}
    kql = (QUERIES / "maillog_totals.kql").read_text(encoding="utf-8")
    assert constructs(kql) - allowed == set()
    assert {"column_ifexists", "dcount", "take_anyif", "dcountif", "join", "inner", "leftouter"} <= constructs(kql)


def test_g3_the_totals_query_keeps_the_expensive_part_to_the_failing_ids():
    kql = collect.kql_for_domain((QUERIES / "maillog_totals.kql").read_text(encoding="utf-8"), "corp.example", 720)
    assert 'let sender_domain = "corp.example";' in kql and "let window_start  = ago(720h);" in kql
    body = kql_body(kql)
    # first the distinct Message-IDs with a failing leg, then the per-(Message-ID, recipient) summary for those only
    ids = body.index("let failing_ids = base\n| where dmarc contains \"fail\"\n| summarize by InternetMessageId;")
    pairs = body.index("let failures = failing_ids")
    assert ids < pairs < body.index("  by InternetMessageId, rcpt\n| where anyfail > 0 and anypass == 0")
    assert "dcount(strcat(InternetMessageId, \"|\", rcpt))" in body  # logical messages and passing: every pair
    assert "dcountif(strcat(InternetMessageId, \"|\", rcpt), dmarc contains \"pass\")" in body  # as dedupe reads it
    for column in ("OrgLevelPolicy", "OrgLevelAction", "UserLevelPolicy", "UserLevelAction"):
        assert 'column_ifexists("%s", "")' % column in body
    last = [l for l in body.splitlines() if l.strip()][-2]
    assert last.split() == ["|", "project", "fromdom,", "logical_messages,", "passing,", "delivered_by,",
                            "genuine_failures,", "delivered_despite_fail"]
    assert set(collect.TOTALS_COLUMNS) <= set(re.findall(r"\w+", last))


TOTALS = {"schema": [{"name": c} for c in ("fromdom", "logical_messages", "passing", "delivered_by", "genuine_failures",
                                          "delivered_despite_fail")],
          "results": [
              {"fromdom": "corp.example", "logical_messages": 7150, "passing": 7000,
               "delivered_by": "org: Exchange transport rule (Allow)", "genuine_failures": 40, "delivered_despite_fail": 12},
              {"fromdom": "corp.example", "logical_messages": 7150, "passing": 7000, "delivered_by": "",
               "genuine_failures": 110, "delivered_despite_fail": 3},
              {"fromdom": "hr.corp.example", "logical_messages": 700, "passing": 690, "delivered_by": "",
               "genuine_failures": 10, "delivered_despite_fail": 0},
              {"fromdom": "quiet.corp.example", "logical_messages": 25, "passing": 25, "delivered_by": "",
               "genuine_failures": None, "delivered_despite_fail": None},  # no failure: the outer join's nulls
              {"fromdom": "elsewhere.example", "logical_messages": 5, "passing": 0, "delivered_by": "",
               "genuine_failures": 5, "delivered_despite_fail": 0}]}
CORP = {"corp.example": {"logical_messages": 7150, "passing": 7000, "genuine_failures": 150, "delivered_despite_fail": 15,
                         "delivered_by": {"org: Exchange transport rule (Allow)": 12}},
        "hr.corp.example": {"logical_messages": 700, "passing": 690, "genuine_failures": 10, "delivered_despite_fail": 0,
                            "delivered_by": {}},
        "quiet.corp.example": {"logical_messages": 25, "passing": 25, "genuine_failures": 0, "delivered_despite_fail": 0,
                               "delivered_by": {}}}


def test_g3_pull_window_totals_adds_up_the_answer_per_from_domain(monkeypatch):
    calls = []

    def hunting(tok, kql, ts=None):
        calls.append((re.search(r'let sender_domain = "([^"]+)";', kql).group(1), ts,
                      re.search(r"let window_start\s*=\s*(ago\(\d+h\));", kql).group(1)))
        return json.loads(json.dumps(TOTALS))
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)
    totals, notes = collect.pull_window_totals("tok", {"corp.example": {"reason": "row budget", "kept_hours": 41}}, 30)
    assert calls == [("corp.example", "P30D", "ago(720h)")]  # the full window, for the cut organization only
    assert totals == {"hours": 720, "orgs": {"corp.example": {"by_domain": CORP, "source": "Advanced Hunting aggregate"}}}
    assert notes == ["mail log: full-window totals for corp.example over the last 30 days, counted in Advanced Hunting: "
                     "about 7875 logical messages, 160 genuine failures, 15 delivered despite failing (the rows kept "
                     "stay a floor)"]
    assert collect.pull_window_totals("tok", {}, 30) == (None, []) and len(calls) == 1  # nothing cut, nothing run


def test_g3_a_failed_totals_query_leaves_a_note_and_no_totals(monkeypatch):
    def hunting(tok, kql, ts=None):
        org = re.search(r'let sender_domain = "([^"]+)";', kql).group(1)
        if org == "corp.example":
            raise collect.graph_client.GraphError("HTTP 400 on hunting: the query ran out of resources")
        if org == "odd.example":
            return {"schema": [{"name": "Internet message ID"}], "results": [{"Internet message ID": "x"}]}
        return {"schema": TOTALS["schema"], "results": [dict(TOTALS["results"][2], fromdom="shop.example")]}
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)
    totals, notes = collect.pull_window_totals("tok", ["corp.example", "odd.example"], 30)
    assert totals is None
    assert notes[0] == ("mail log: full-window totals for corp.example not counted: HTTP 400 on hunting: the query ran "
                        "out of resources")
    assert notes[1].startswith("mail log: full-window totals for odd.example not counted: the answer is not the totals "
                               "maillog_totals.kql asks for - columns missing: ") and len(notes) == 2
    totals, notes = collect.pull_window_totals("tok", ["corp.example", "shop.example"], 30)
    assert list(totals["orgs"]) == ["shop.example"] and len(notes) == 2  # the one that answered is kept
    # a customized query without the placeholder line is a note too, never a crash
    monkeypatch.setattr(collect, "TOTALS_QUERY", QUERIES / "no_such_query.kql")
    totals, notes = collect.pull_window_totals("tok", ["corp.example"], 30)
    assert totals is None and notes[0].startswith("mail log: full-window totals not counted: cannot read no_such_query.kql")


def test_g3_an_answer_that_counts_nothing_for_a_cut_org_is_no_count(monkeypatch):
    row = dict(TOTALS["results"][2])  # one From domain's totals, renamed per organization below
    answers = {"empty.example": {"schema": TOTALS["schema"], "results": []},
               "bare.example": {},
               "nulls.example": {"schema": TOTALS["schema"], "results": None},
               "lists.example": {"schema": TOTALS["schema"], "results": [["lists.example", 5]]},
               "other.example": TOTALS,  # rows, none of them under other.example
               "text.example": {"schema": TOTALS["schema"], "results": [dict(row, fromdom="text.example",
                                                                             logical_messages="lots")]},
               "minus.example": {"schema": TOTALS["schema"], "results": [dict(row, fromdom="minus.example",
                                                                              genuine_failures=-4)]},
               "digits.example": {"schema": TOTALS["schema"], "results": [dict(row, fromdom="digits.example",
                                                                               logical_messages="700")]}}

    def hunting(tok, kql, ts=None):
        return json.loads(json.dumps(answers[re.search(r'let sender_domain = "([^"]+)";', kql).group(1)]))
    monkeypatch.setattr(collect.graph_client, "hunting", hunting)
    totals, notes = collect.pull_window_totals("tok", sorted(answers), 30)
    assert list(totals["orgs"]) == ["digits.example"]  # a count sent as text is the number it spells
    assert totals["orgs"]["digits.example"]["by_domain"]["digits.example"]["logical_messages"] == 700
    nothing = "the answer holds no mail under it, yet its rows were cut for holding too many"
    unusable = "the answer is not the totals maillog_totals.kql asks for"
    why = dict(n.split(" not counted: ", 1) for n in notes if " not counted" in n)  # {"... totals for <org>": why}
    why = {k: v.split(" - ", 1)[0] for k, v in why.items()}  # the reason after " - " is checked in test_r11_scale
    why = {k.rsplit(" ", 1)[1]: v for k, v in why.items()}
    assert why == {"empty.example": nothing, "other.example": nothing, "bare.example": unusable,
                   "nulls.example": unusable, "lists.example": unusable, "text.example": unusable,
                   "minus.example": unusable}
    # nothing usable at all: no totals, every organization noted
    monkeypatch.setattr(collect.graph_client, "hunting", lambda tok, kql, ts=None: {"schema": [], "results": []})
    totals, notes = collect.pull_window_totals("tok", ["corp.example"], 30)
    assert totals is None and notes == ["mail log: full-window totals for corp.example not counted: " + nothing]


CUT = {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T19:00:00Z"}


def cut_report(tmp_path, window_totals, **kw):
    """corp.example, cut by the row budget, and shop.example, whole; corp.example's kept rows hold 3 failures."""
    log = (Log().add("staff@corp.example", "Weekly report #", times=30)
           .add("billing@corp.example", "Statement #", leg(org=ETR), times=2).add("ops@corp.example", "Run #", leg(QUARANTINED))
           .add("app@hr.corp.example", "Build #", leg(QUARANTINED)).add("shop@shop.example", "Order #", times=5))
    return audit.build_report(domains=["corp.example", "hr.corp.example", "shop.example"],
                              maillog=log.write(tmp_path / "cut.csv"), offline=True, auth_column="DMARC",
                              maillog_cuts={"corp.example": dict(CUT)}, window_totals=window_totals, **kw)


def test_g3_build_report_keeps_the_totals_beside_the_floor_and_changes_no_verdict(tmp_path):
    totals = {"hours": 720, "orgs": {"corp.example": {"by_domain": json.loads(json.dumps(CORP)),
                                                      "source": "Advanced Hunting aggregate"}}}
    rep = cut_report(tmp_path, totals)
    assert rep["maillog"]["window_totals"] == totals
    bare = cut_report(tmp_path, None)
    assert "window_totals" not in bare["maillog"]
    assert "window_totals" not in cut_report(tmp_path, {"hours": 720, "orgs": {}})["maillog"]  # nothing counted
    for key in ("counters", "census", "by_domain"):  # the floor is what every verdict rests on
        assert rep["maillog"][key] == bare["maillog"][key]
    assert rep["gate"] == bare["gate"]
    no_log = audit.build_report(domains=["corp.example"], offline=True, rua_paths=["samples/rua"], window_totals=totals)
    assert no_log["maillog"] is None  # totals with no mail log: nowhere to keep them
    assert ("full-window totals for corp.example, counted in advanced hunting over 30 days (maillog.window_totals): "
            "160 genuine failures, 15 delivered despite failing; its logical messages and passing are Kusto estimates. "
            "The gate, the census and the labels rest on the rows kept; the plan's no-mail check and its list of "
            "sending subdomains read these totals too") in rep["verified_vs_inferred"]["verified"]


def test_g3_totals_below_the_rows_kept_are_set_aside_and_never_shown(tmp_path):
    # the rows kept under corp.example: 34 logical messages, 4 genuine failures (billing x2, ops, app@hr)
    def totals(gf_corp, lm_corp=7150, shop=None):
        corp = {"corp.example": dict(CORP["corp.example"], genuine_failures=gf_corp, logical_messages=lm_corp),
                "hr.corp.example": dict(CORP["hr.corp.example"], genuine_failures=0, logical_messages=0, passing=0)}
        orgs = {"corp.example": {"by_domain": corp, "source": "Advanced Hunting aggregate"}}
        if shop is not None:
            orgs["shop.example"] = {"by_domain": {"shop.example": shop}, "source": "Advanced Hunting aggregate"}
        return {"hours": 720, "orgs": orgs}
    bare = cut_report(tmp_path, None)
    low = cut_report(tmp_path, totals(0))
    assert "window_totals" not in low["maillog"]
    assert low["maillog"]["window_totals_rejected"] == {
        "corp.example": "0 genuine failures over the whole window, fewer than the 4 in the rows kept"}
    for key in ("counters", "census", "by_domain"):
        assert low["maillog"][key] == bare["maillog"][key]
    assert low["gate"] == bare["gate"]
    assert "Full-window totals" not in audit.render_md(low) and "Advanced Hunting" not in notify.summarize(low)
    assert "Advanced Hunting" not in stand_line(next_steps.build(low), "**Genuine failures")
    assert not [v for v in low["verified_vs_inferred"]["verified"] if "full-window" in v]
    # a few under the floor is a pair or two straddling the cut hour, not a broken answer
    assert "window_totals_rejected" not in cut_report(tmp_path, totals(1))["maillog"]
    # logical messages, an estimate, may sit a little under the rows kept, never far under
    assert cut_report(tmp_path, totals(4, lm_corp=31))["maillog"]["window_totals"]["orgs"]["corp.example"]
    assert cut_report(tmp_path, totals(4, lm_corp=30))["maillog"]["window_totals_rejected"] == {
        "corp.example": "about 30 logical messages over the whole window, fewer than the 34 in the rows kept"}
    # one organization's answer set aside, another's kept
    shop = {"logical_messages": 5, "passing": 5, "genuine_failures": 0, "delivered_despite_fail": 0, "delivered_by": {}}
    both = cut_report(tmp_path, totals(0, shop=shop))
    assert list(both["maillog"]["window_totals"]["orgs"]) == ["shop.example"]
    assert list(both["maillog"]["window_totals_rejected"]) == ["corp.example"]


def test_g3_the_readers_put_the_full_window_beside_the_floor(tmp_path):
    totals = {"hours": 720, "orgs": {"corp.example": {"by_domain": json.loads(json.dumps(CORP)),
                                                      "source": "Advanced Hunting aggregate"}}}
    rep = cut_report(tmp_path, totals)
    rep["maillog"]["truncation"] = "row budget kept only the newest 41h for corp.example"
    md = audit.render_md(rep)
    block = md.split("\nFull-window totals for cut organizations ", 1)[1].split("\n\n## ", 1)[0].splitlines()
    assert block[0] == ("(counted in advanced hunting over the whole 30 days, at the same (Message-ID, recipient) "
                        "grain): the counts above keep only the rows the row budget or the API cap left, a floor. "
                        "Logical messages and passing here are Kusto estimates. The gate, the census and the labels "
                        "keep using the deduplicated rows above; the plan reads these totals for a cut "
                        "organization's quarantine-now decision and its list of sending subdomains.")
    assert block[2:] == [
        "- corp.example (newest 41 hours kept in the rows above): about 7875 logical messages, about 7715 passing, "
        "160 genuine failures, 15 delivered despite failing (let in by an Exchange transport rule x12; no override "
        "recorded for 3)",
        "  - corp.example: about 7150 logical messages, about 7000 passing, 150 genuine failures, 15 delivered despite "
        "failing (let in by an Exchange transport rule x12; no override recorded for 3)",
        "  - hr.corp.example: about 700 logical messages, about 690 passing, 10 genuine failures, 0 delivered despite "
        "failing",
        "  - quiet.corp.example: about 25 logical messages, about 25 passing, 0 genuine failures, 0 delivered despite "
        "failing"]
    assert md.index("Per sender domain (each gate uses only its own rows):") < md.index("Full-window totals for cut")
    doc = next_steps.build(rep)
    gf = rep["maillog"]["counters"]["genuine_failures"]
    assert stand_line(doc, "**Genuine failures") == (
        "**Genuine failures: %d** (raw row counts agree: no relay echoes), over the mail log's 38-minute span "
        "(2026-10-07 00:01 to 2026-10-07 00:39 UTC); the log export was cut short (row budget kept only the newest 41h "
        "for corp.example), so this count is a floor; over the full 30 days, counted in Advanced Hunting: 160 genuine "
        "failures, 15 delivered despite failing under corp.example, whose rows kept are the %d above (the gate, the "
        "census and the labels still rest on the rows kept; the plan reads these totals for its quarantine-now and "
        "sp= decisions)" % (gf, gf))
    assert doc["stand"]["window_totals"] == {"orgs": ["corp.example"], "hours": 720.0, "span": "30 days",
                                             "genuine_failures": 160, "delivered_despite_fail": 15, "floor": gf}
    lines = {l.split("`")[1]: l for l in notify.summarize(rep).splitlines() if l.startswith("- `")}
    assert lines["corp.example"].endswith(
        " - 3 genuine failures of its own in the rows kept (newest 41 hours kept; a floor: the gate, the census and the "
        "labels count these); over the full 30 days, counted in Advanced Hunting: 150 genuine failures, 15 delivered "
        "despite failing")
    assert lines["hr.corp.example"].endswith("; over the full 30 days, counted in Advanced Hunting: 10 genuine failures, "
                                             "0 delivered despite failing")
    # round 13, T-04: shop.example, not cut, leads its own line of the status band's strip and has no line below it
    assert "shop.example" not in lines and "1. `corp.example` " in notify.summarize(rep)
    # a report without the totals reads as before
    bare = cut_report(tmp_path, None)
    assert "Full-window totals" not in audit.render_md(bare)
    assert "Advanced Hunting" not in notify.summarize(bare)
    assert "Advanced Hunting" not in stand_line(next_steps.build(bare), "**Genuine failures")


def test_odd_values_in_the_new_fields_read_as_nothing_never_an_error(tmp_path):
    rep = audit.build_report(domains=["example.com"], maillog=overridden_log().write(tmp_path / "log.csv"),
                             offline=True, auth_column="DMARC")
    odd = [("mailflow", "x"), ("mailflow", {"days": "x", "domains": [1]}), ("mailflow", {"domains": {"example.com": "x"}}),
           ("window_totals", "x"), ("window_totals", {"hours": "x", "orgs": [1]}),
           ("window_totals", {"orgs": {"example.com": "x"}}), ("window_totals", {"orgs": {"example.com": {"by_domain": [1]}}}),
           ("window_totals", {"orgs": {"example.com": {"by_domain": {"example.com": "x"}}}}),
           ("ddf_by", ["x"]), ("ddf_by", {"org: x": "two"}), ("census_by", "x")]
    for key, value in odd:
        doc = json.loads(json.dumps(rep))
        if key == "mailflow":
            doc["mailflow"] = value
        elif key == "window_totals":
            doc["maillog"]["window_totals"] = value
        elif key == "ddf_by":
            doc["maillog"]["counters"]["delivered_despite_fail_by"] = value
        else:
            for r in doc["maillog"]["census"]["by_sender"]:
                r["delivered_by"] = value
        audit.render_md(doc)
        notify.summarize(doc)
        ns = next_steps.build(doc)
        next_steps.render_md(ns)
        plan_mod.build_plan(dict(doc, dns={"example.com": dns_doc("example.com")}), None, "mailto:r@example.com")
        if key == "mailflow":
            assert "| not measured |" in next_steps.render_md(ns), value
    # a span that is no number of hours (nan, an infinity - JSON's Infinity reads as one -, zero or less, a bool)
    # reads as the window, unnamed, in every reader; the counts beside it still show
    counted = {"example.com": {"by_domain": {"example.com": {"logical_messages": 40, "passing": 30,
                                                             "genuine_failures": 9, "delivered_despite_fail": 2}}}}
    for hours in ("nan", "inf", "-inf", float("inf"), float("nan"), -5, 0, True, "x", None):
        doc = json.loads(json.dumps(rep))
        doc["maillog"]["window_totals"] = {"hours": hours, "orgs": counted}
        md = audit.render_md(doc)
        assert "Full-window totals for cut organizations (counted in advanced hunting over the whole window," in md, hours
        assert ("full-window totals for example.com, counted in advanced hunting over an unknown span "
                "(maillog.window_totals): 9 genuine failures") in "\n".join(audit.verified_vs_inferred(doc)["verified"])
        line = stand_line(next_steps.build(doc), "**Genuine failures")
        assert ("; over the full window, counted in Advanced Hunting: 9 genuine failures, 2 delivered despite "
                in line), hours
        assert "; over the full window, counted in Advanced Hunting: 9 genuine failures" in notify.summarize(doc), hours
    # the mail flow's days and counts, damaged: nothing reads as measured silence, nothing raises
    for flow in ({"days": float("inf"), "domains": {"example.com": {"outbound": "3", "inbound": [1]}}},
                 {"days": "nan", "domains": {"example.com": {"messages": 0, "outbound": -1, "inbound": 0}}}):
        doc = dict(json.loads(json.dumps(rep)), mailflow=flow)
        audit.render_md(doc)
        next_steps.render_md(next_steps.build(doc))
        p = plan_mod.build_plan(dict(doc, dns={"example.com": dns_doc("example.com")}), None, "mailto:r@example.com")
        assert all(c["prerequisites"][0].startswith("verify unused first") for c in p["changes"] if c["kind"] == "park")
    # days that are no number of days (a bool is not 1) name the window instead of a span
    for days in (True, "x", -3, float("inf")):
        doc = dict(json.loads(json.dumps(rep)), mailflow={"days": days, "domains": {"example.com": zeros()}})
        assert "- example.com: nothing sent or received in the window (tenant)" in audit.render_md(doc), days
        assert ("mail flow per audited domain from one advanced hunting aggregate over the window (report.mailflow)"
                in "\n".join(audit.verified_vs_inferred(doc)["verified"])), days
        assert "Mail flow is what passed through our own tenant in the window with that domain as the sender" \
            in next_steps.render_md(next_steps.build(doc)), days


# ------------------------------------------------------------------ collect, end to end

class Tenant:
    """An in-memory advanced hunting endpoint: per-org sizing and row queries over (hours ago, row) legs, cut at
    collect.ROW_CAP like the API; the mail-flow aggregate counted from the same legs (or a recorded answer, or an
    error); the full-window totals as recorded answers per org. Every call is kept, the mail flow's with the days
    its query reaches back."""

    def __init__(self, legs, totals=None, mailflow_error=None):
        self.legs, self.totals, self.mailflow_error, self.calls = legs, totals or {}, mailflow_error, []
        self.mailflow_answer = None

    def hunting(self, tok, kql, ts=None):
        if "summarize messages = dcount(InternetMessageId)" in kql:  # discover.mailflow_kql
            self.calls.append(("mailflow", ts, int(re.search(r"Timestamp > ago\((\d+)d\)", kql).group(1))))
            if self.mailflow_error:
                raise graph_client.GraphError(self.mailflow_error)
            if self.mailflow_answer is not None:
                return json.loads(json.dumps(self.mailflow_answer))
            seen = {}
            for _, dom, row in self.legs:
                if re.search(r'd == "%s" or d endswith "\.%s"' % (discover.org_domain(dom), discover.org_domain(dom)), kql):
                    s = seen.setdefault(dom, {"ids": set(), "out": set(), "in": set(), "last": ""})
                    s["ids"].add(row["Internet message ID"])
                    s["out" if row["Direction"] in ("Outbound", "Intra-org") else "in"].add(row["Internet message ID"])
                    s["last"] = max(s["last"], row["Timestamp"])
            return {"schema": [{"name": c} for c in ("d", "messages", "outbound", "inbound", "last_seen")],
                    "results": [{"d": d, "messages": len(s["ids"]), "outbound": len(s["out"]), "inbound": len(s["in"]),
                                 "last_seen": s["last"]} for d, s in sorted(seen.items())]}
        org = re.search(r'let sender_domain = "([^"]+)";', kql).group(1)
        start = int(re.search(r"let window_start\s*=\s*ago\((\d+)h\);", kql).group(1))
        m = re.search(r"let window_end\s*=\s*ago\((\d+)h\);", kql)
        end = int(m.group(1)) if m else 0
        if "logical_messages" in kql:  # queries/maillog_totals.kql
            self.calls.append(("totals", ts, (org, start)))
            return json.loads(json.dumps(self.totals[org]))
        mine = [(a, r) for a, d, r in self.legs if (d == org or d.endswith("." + org)) and end <= a < start]
        if "summarize n = count()" in kql:
            self.calls.append(("sizing", ts, org))
            counts = {}
            for a, r in mine:
                counts[(int(a), r["Direction"])] = counts.get((int(a), r["Direction"]), 0) + 1
            return {"schema": [{"name": "hago"}, {"name": "dir"}, {"name": "n"}],
                    "results": [{"hago": h, "dir": d, "n": n} for (h, d), n in sorted(counts.items())]}
        self.calls.append(("rows", ts, org))
        rows = [r for _, r in mine]
        return {"schema": [{"name": c} for c in BASE + OVERRIDES], "results": rows[:collect.ROW_CAP]}


def tenant_legs(now):
    """corp.example busy (ten legs an hour for 30 days, one delivered failure an hour through a transport rule in
    the newest day), hr.corp.example and shop.example quiet, parked.example silent."""
    out, i = [], 0
    spec = {"corp.example": (10, 1, 720), "hr.corp.example": (1, 10, 720), "shop.example": (1, 6, 720)}
    for dom, (per, every, hours) in spec.items():
        for h in range(0, hours, every):
            for k in range(per):
                i += 1
                ago = h + k / float(per + 1)
                fail = dom == "corp.example" and k == 0 and h < 24
                bad = dom == "hr.corp.example" and h % 50 == 0
                out.append((ago, dom, {
                    "Timestamp": (now - timedelta(hours=ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "Internet message ID": "<t%d@%s>" % (i, dom), "Sender address": "app@" + dom, "Sender domain": dom,
                    "Sender mail from domain": dom, "Recipients": "user@example.com", "Subject": "Notice",
                    "Delivery action": "Blocked" if bad else "Delivered",
                    "Latest delivery location": "Quarantine" if bad else "Inbox/folder",
                    "DMARC": "fail" if fail or bad else "pass", "Direction": "Inbound" if fail or bad else "Intra-org",
                    "Org level action": "Allow" if fail else "", "Org level policy": "Exchange transport rule" if fail else "",
                    "User level action": "", "User level policy": ""}))
    return out


def live_dns(domains, resolver, selectors=()):
    record = "v=DMARC1; p=none; rua=mailto:reports@example.com;"
    sends = {"dmarc": record, "dmarc_source": "_dmarc.%s", "effective_policy": "none", "dmarc_status": "found",
             "spf": "v=spf1 include:mail.example -all", "spf_status": "found", "spf_terminator": "-all",
             "spf_lookups": 1, "dkim_selectors": ["selector1"], "dkim_status": "found", "mx": ["10 mx.example"],
             "mx_status": "found", "findings": []}
    return {d: (dns_doc(d) if d == "parked.example" else dns_doc(d, **dict(sends, dmarc_source="_dmarc." + d)))
            for d in domains}


def test_collect_measures_mail_flow_once_per_run_and_counts_a_cut_orgs_whole_window(monkeypatch, tmp_path):
    attempts = []

    def refuse(*a, **k):
        attempts.append(a)
        raise OSError("no network in this test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.delenv("RUA_MAILBOX", raising=False)
    now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
    recorded = {"schema": TOTALS["schema"], "results": TOTALS["results"][:4]}
    t = Tenant(tenant_legs(now), {"corp.example": recorded})
    monkeypatch.setattr(collect.graph_client, "hunting", t.hunting)
    monkeypatch.setattr(collect.graph_client, "creds", lambda env_file=None: ("tenant", "client", "secret"))
    monkeypatch.setattr(collect.graph_client, "TokenSource", lambda cred, **k: (lambda refresh=False: "tok"))
    signed = []
    monkeypatch.setattr(collect.graph_client, "token", lambda cred: signed.append(cred) or "second")
    monkeypatch.setattr(collect.verify_setup, "run_checks", lambda *a, **k: [])
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([], None))
    monkeypatch.setattr(discover, "zone_for", lambda domain, resolver=None: {
        "zone": discover.org_domain(domain), "ns": [], "zone_host": "not checked", "ns_path": "skipped"})
    monkeypatch.setattr(audit, "run_dns", live_dns)
    # the _dmarc lookup collect.py makes for quiet.corp.example, an unaudited name passing in the full window
    monkeypatch.setattr(dns_audit, "resolve_ex", lambda resolver, name, rtype: (
        [], {"path": "stub", "ttl": None, "status": "absent"}))
    monkeypatch.setattr(collect, "ROW_CAP", 300)
    monkeypatch.setattr(collect, "SLICE_TARGET", 270)
    out = tmp_path / "out"

    def run(max_rows, *extra):
        t.calls.clear()
        monkeypatch.setattr(sys, "argv", ["collect.py", "corp.example", "hr.corp.example", "shop.example",
                                          "parked.example", "--no-config", "--no-owners", "--no-notify",
                                          "--out", str(out), "--max-rows", str(max_rows)] + list(extra))
        try:
            collect.main()
        except SystemExit:
            pass
        latest = out / "latest"
        read = {n: (latest / n).read_text(encoding="utf-8")
                for n in ("report.md", "next_steps.md", "summary.txt", "todo.md")}
        return ({n: json.loads((latest / n).read_text(encoding="utf-8"))
                 for n in ("report.json", "run.json", "inventory.json", "plan.json")}, read)

    files, text = run(1500)  # corp.example is cut to its newest hours
    report, inventory = files["report.json"], files["inventory.json"]
    kinds = [k for k, *_ in t.calls]
    assert kinds.count("mailflow") == 1 and kinds[0] == "mailflow"  # one aggregate per run, before the pulls
    assert [(ts, arg) for k, ts, arg in t.calls if k == "mailflow"] == [("P30D", 30)]
    assert [(ts, arg) for k, ts, arg in t.calls if k == "totals"] == [("P30D", ("corp.example", 720))]
    assert signed == [] and attempts == []  # no second sign-in, no network
    # G2: every audited name measured, the organization itself included; the plan reads it, and calls
    # parked.example unused only once every check is made - no aggregate report covers it (it has no record)
    flows = {r["domain"]: r["mailflow"] for r in inventory["domains"]}
    assert flows["parked.example"] == discover.MAILFLOW_NONE and flows["corp.example"]["outbound"] > 0
    assert report["mailflow"]["days"] == 30 and report["mailflow"]["domains"] == flows
    open_checks = "verify unused first: no passing volume in aggregate reports, no owner objects"
    parks = [c for c in files["plan.json"]["changes"] if c["domain"] == "parked.example" and c["kind"] == "park"]
    assert len(parks) == 2 and all(c["prerequisites"][0] == open_checks for c in parks)
    # the new DMARC record reports to another organization's mailbox: it also waits on the external-destination record
    assert {c["hostname"]: c["prerequisites"][1:] for c in parks} == {
        "parked.example": [],
        "_dmarc.parked.example": [plan_mod.external_destination("parked.example", "mailto:reports@example.com")]}
    for c in parks:  # todo.md says what each park row waits on, as plan.md does: its status, then its checks
        row = "- %s parked.example: TXT at `%s` = `%s`" % (c["id"], c["hostname"], c["value"])
        after = text["todo.md"].split(row, 1)[1].split("\n")
        assert after[1].startswith("  - status: %s - " % c["status_text"])  # round 13, T-05
        assert after[2] == "  - before applying: " + open_checks
    # round 13, T-11: the ask stays under 60 words, so the park rows' group says what they wait on in short
    assert "approval to publish 2 records (plan %s) once the domain's unused check is done" % next_steps.id_range(
        [c["id"] for c in parks]) in text["next_steps.md"]
    assert "| `parked.example` | no DMARC record | " in text["next_steps.md"]
    assert "| nothing sent or received in 30 days (tenant) |" in text["next_steps.md"]
    assert "- shop.example: sends: 120 out, 0 in (30 days, tenant); last seen " in text["report.md"]
    assert "- parked.example: nothing sent or received in 30 days (tenant)" in text["report.md"]
    # G3: the cut organization's whole window beside the floor, the verdicts on the rows kept
    assert set(report["maillog"]["cuts"]) == {"corp.example"}
    assert report["maillog"]["window_totals"] == {"hours": 720, "orgs": {"corp.example": {
        "by_domain": CORP, "source": "Advanced Hunting aggregate"}}}
    assert "window_totals_rejected" not in report["maillog"]
    assert "- corp.example (newest " in text["report.md"] and "160 genuine failures, 15 delivered" in text["report.md"]
    assert ("over the full 30 days, counted in Advanced Hunting: 160 genuine failures, 15 delivered despite failing "
            "under corp.example, whose rows kept ") in text["next_steps.md"]
    assert ("(the gate, the census and the labels still rest on the rows kept; the plan reads these totals for its "
            "quarantine-now and sp= decisions)") in text["next_steps.md"]
    corp = next(l for l in text["summary.txt"].splitlines() if l.startswith("- `corp.example`"))
    assert corp.endswith("; over the full 30 days, counted in Advanced Hunting: 150 genuine failures, 15 delivered "
                         "despite failing")
    # G1 end to end: the pulled rows carry the override columns, and the run names the rule
    assert report["maillog"]["counters"]["delivered_despite_fail_by"] == {
        "org: Exchange transport rule (Allow)": report["maillog"]["counters"]["delivered_despite_fail"]}
    assert "app@corp.example - " in text["next_steps.md"]
    # round 13, T-08: app@ is our own system, so its rule changes only once it passes
    assert ("delivered because of an Exchange transport rule: after app@corp.example passes DMARC, make that rule "
            "conditional on authentication - doing it first junks these") in text["next_steps.md"]
    assert any(n.startswith("mail log: full-window totals for corp.example over the last 30 days") for n in
               files["run.json"]["notes"])
    assert files["run.json"]["degraded"] == []

    # --days narrows the mail log and its full-window totals, never the 30 days of mail flow the plan relies on
    files, text = run(1500, "--days", "7")
    assert [(ts, arg) for k, ts, arg in t.calls if k == "mailflow"] == [("P30D", 30)]
    assert [(ts, arg) for k, ts, arg in t.calls if k == "totals"] == [("P7D", ("corp.example", 168))]
    assert files["report.json"]["mailflow"]["days"] == 30
    assert files["report.json"]["maillog"]["window_totals"]["hours"] == 168
    parks = [c for c in files["plan.json"]["changes"] if c["domain"] == "parked.example" and c["kind"] == "park"]
    assert parks and all(c["prerequisites"][0] == open_checks for c in parks)
    assert "| nothing sent or received in 30 days (tenant) |" in text["next_steps.md"]

    files, text = run(0)  # nothing cut: no totals query, no totals
    assert [k for k, *_ in t.calls].count("mailflow") == 1 and "totals" not in [k for k, *_ in t.calls]
    assert "window_totals" not in files["report.json"]["maillog"] and "Full-window totals" not in text["report.md"]

    t.mailflow_error = "HTTP 429 on hunting: too many requests"  # the mail-flow query fails: nothing measured
    files, text = run(0)
    assert all(r["mailflow"] is None for r in files["inventory.json"]["domains"])
    assert set(files["report.json"]["mailflow"]["domains"].values()) == {None}
    assert "mail flow not measured: HTTP 429 on hunting: too many requests" in files["run.json"]["degraded"]
    assert "| `parked.example` | no DMARC record | " in text["next_steps.md"]
    parks = [c for c in files["plan.json"]["changes"] if c["domain"] == "parked.example" and c["kind"] == "park"]
    assert parks and all(c["prerequisites"][0] == UNVERIFIED for c in parks)
    assert "| not measured |" in text["next_steps.md"] and "- parked.example: not measured" in text["report.md"]

    # an answer with no results at all is no measurement: every name stays not measured, never "nothing sent"
    t.mailflow_error, t.mailflow_answer = None, {}
    files, text = run(0)
    assert set(files["report.json"]["mailflow"]["domains"].values()) == {None}
    assert "mail flow not measured: the answer carries no results" in files["run.json"]["degraded"]
    assert "nothing sent or received" not in text["next_steps.md"] + text["report.md"]
    t.mailflow_answer = None

    t.totals = {"corp.example": {"schema": [{"name": "x"}], "results": [{"x": 1}]}}
    files, text = run(1500)  # the totals answer is unusable: a note, no totals, the floor alone
    assert "window_totals" not in files["report.json"]["maillog"]
    assert any(d.startswith("mail log: full-window totals for corp.example not counted: the answer is not the totals "
                            "maillog_totals.kql asks for - ") for d in files["run.json"]["degraded"])
    assert "Advanced Hunting" not in text["summary.txt"]

    for answer in ({"schema": TOTALS["schema"], "results": []}, {}):  # no row, no results: never zero totals
        t.totals = {"corp.example": answer}
        files, text = run(1500)
        assert "window_totals" not in files["report.json"]["maillog"]
        assert any(n.startswith("mail log: full-window totals for corp.example not counted: ")
                   for n in files["run.json"]["degraded"]), answer
        assert "Advanced Hunting" not in text["summary.txt"] + text["next_steps.md"]
        assert "Full-window totals" not in text["report.md"]

    # an answer below the rows kept cannot be the whole window: set aside, said so, the floor alone
    t.totals = {"corp.example": {"schema": TOTALS["schema"], "results": [
        {"fromdom": "corp.example", "logical_messages": 9000, "passing": 8990, "delivered_by": "", "genuine_failures": 2,
         "delivered_despite_fail": 0}]}}
    files, text = run(1500)
    ml = files["report.json"]["maillog"]
    assert "window_totals" not in ml and list(ml["window_totals_rejected"]) == ["corp.example"]
    set_aside = [n for n in files["run.json"]["degraded"]
                 if n.startswith("mail log: full-window totals for corp.example set aside, not shown: the answer holds "
                                 "2 genuine failures over the whole window, fewer than the ")]
    assert len(set_aside) == 1 and set_aside[0].endswith(" in the rows kept")
    assert "Advanced Hunting" not in text["summary.txt"] + text["next_steps.md"]
