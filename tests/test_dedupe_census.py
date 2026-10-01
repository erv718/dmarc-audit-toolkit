"""dedupe.census: the sender inventory over deduplicated verdicts. Synthetic
in-memory rows plus the bundled sample; no network."""

import json
import subprocess
import sys
from pathlib import Path

import audit
import dedupe

ROOT = Path(__file__).resolve().parent.parent

# in-memory rows use the logical names as column names
COLS = {k: k for k in ("msgid", "recipient", "sender", "domain", "action", "location", "subject", "envelope")}


def row(mid, sender, domain, env, subject, dmarc, action="Blocked", location="Quarantine"):
    return {"msgid": mid, "recipient": "user@example.com", "sender": sender, "domain": domain,
            "envelope": env, "subject": subject, "action": action, "location": location, "DMARC": dmarc}


def rows():
    out = []
    # 4 failing from an own-envelope system with a stable subject: misconfigured
    for i in range(4):
        out.append(row("<a%d@sub.example.com>" % i, "alerts@sub.example.com", "sub.example.com",
                       "sub.example.com", "Nightly export complete", "fail"))
    # 3 failing via a platform envelope the heuristic does not know: spoof unless taught
    for i in range(3):
        out.append(row("<b%d@example.com>" % i, "billing@example.com", "example.com", "bounce.esp.example",
                       "Purchase order %d acknowledged" % (1000 + i), "fail"))
    # 2 passing via the same platform envelope, another sender
    for i in range(2):
        out.append(row("<p%d@example.com>" % i, "noreply@example.com", "example.com", "bounce.esp.example",
                       "Your statement", "pass", "Delivered", "Inbox/folder"))
    # lure subject and a foreign envelope: spoof
    out.append(row("<c0@mta7.hosting.example>", "ceo@example.com", "example.com", "mta7.hosting.example",
                   "Invoice #77 past due", "fail"))
    # own envelope, one unique subject: unknown
    out.append(row("<u0@example.com>", "hr@example.com", "example.com", "example.com", "Welcome aboard", "fail"))
    # no sender and no envelope at all
    out.append(row("<blank@example.com>", "", "", "", "no sender at all", "fail"))
    # a clean sender: in the inventory with zero failures
    out.append(row("<n0@example.com>", "news@example.com", "example.com", "news.example.com", "Weekly digest",
                   "pass", "Delivered", "Inbox/folder"))
    return out


def verdicts(vendor_domains=None):
    return dedupe.classify(rows(), COLS, None, "DMARC", vendor_domains)


def counters(v):
    c = dedupe.count_rows(rows(), COLS, None, "DMARC")
    c.update(dedupe.summarize(v))
    return c


def test_by_envelope_is_sorted_by_failures_then_volume_then_name():
    env = dedupe.census(verdicts())["by_envelope"]
    assert [e["envelope_domain"] for e in env] == [
        "sub.example.com", "bounce.esp.example", "(blank)", "example.com", "mta7.hosting.example", "news.example.com"]
    keys = [(-e["genuine_failures"], -e["messages"], e["envelope_domain"]) for e in env]
    assert keys == sorted(keys)
    esp = env[1]  # 3 failing of 5 messages, from 2 distinct senders
    assert (esp["genuine_failures"], esp["messages"], esp["senders"]) == (3, 5, 2)
    assert esp["sample_sender"] == "billing@example.com"  # the failing sender, not the passing one


def test_under_ten_and_clean_entries_stay_in_the_inventory():
    cs = dedupe.census(verdicts())
    assert all(e["genuine_failures"] < 10 for e in cs["by_envelope"])  # nothing here is a headline
    assert len(cs["by_envelope"]) == 6 and len(cs["by_sender"]) == 7
    clean = [e for e in cs["by_envelope"] if not e["genuine_failures"]]
    assert [(e["envelope_domain"], e["likely"], e["sample_sender"]) for e in clean] == [
        ("news.example.com", None, "news@example.com")]
    clean_s = [e for e in cs["by_sender"] if not e["genuine_failures"]]
    assert {e["sender"] for e in clean_s} == {"noreply@example.com", "news@example.com"}
    assert all(e["likely"] is None for e in clean_s)
    assert cs["by_sender"][-1]["genuine_failures"] == 0  # clean entries sort last


def test_likely_label_is_the_dominant_heuristic_and_follows_vendor_domains():
    by_env = {e["envelope_domain"]: e for e in dedupe.census(verdicts())["by_envelope"]}
    assert by_env["sub.example.com"]["likely"] == "likely_misconfigured_sender"
    assert by_env["mta7.hosting.example"]["likely"] == "likely_spoof"
    assert by_env["example.com"]["likely"] == "unknown"
    assert by_env["(blank)"]["likely"] == "unknown"
    assert by_env["bounce.esp.example"]["likely"] == "likely_spoof"  # an envelope the heuristic does not know
    taught = {e["envelope_domain"]: e for e in dedupe.census(verdicts(["bounce.esp.example"]))["by_envelope"]}
    assert taught["bounce.esp.example"]["likely"] == "likely_misconfigured_sender"


def test_by_sender_is_one_entry_per_sender_domain_and_envelope():
    snd = dedupe.census(verdicts())["by_sender"]
    top = snd[0]
    assert (top["sender"], top["genuine_failures"], top["messages"]) == ("alerts@sub.example.com", 4, 4)
    assert (top["domain"], top["envelope_domain"]) == ("sub.example.com", "sub.example.com")
    assert top["likely"] == "likely_misconfigured_sender" and top["sample_subject"] == "Nightly export complete"
    keys = [(-e["genuine_failures"], -e["messages"], e["sender"], e["envelope_domain"]) for e in snd]
    assert keys == sorted(keys)
    blank = next(e for e in snd if e["envelope_domain"] == "(blank)")
    assert blank["sender"] == "?" and blank["domain"] == ""
    passing = next(e for e in snd if e["sender"] == "noreply@example.com")
    assert passing["sample_subject"] == "Your statement" and passing["messages"] == 2
    # the same address through two envelopes is two streams
    extra = rows() + [row("<x%d@example.com>" % i, "billing@example.com", "example.com", "example.com",
                          "Purchase order %d acknowledged" % (2000 + i), "fail") for i in range(2)]
    v = dedupe.classify(extra, COLS, None, "DMARC")
    streams = [e for e in dedupe.census(v)["by_sender"] if e["sender"] == "billing@example.com"]
    assert sorted(e["envelope_domain"] for e in streams) == ["bounce.esp.example", "example.com"]


def test_totals_reconcile_with_the_counters():
    v = verdicts()
    c = dedupe.summarize(v)
    cs = dedupe.census(v)
    for key in ("by_envelope", "by_sender"):
        assert sum(e["genuine_failures"] for e in cs[key]) == c["genuine_failures"] == 10
        assert sum(e["messages"] for e in cs[key]) == c["logical_messages"] == 13


def test_census_accepts_the_json_verdict_list_and_matches_audit():
    v = verdicts()
    doc = dedupe.build_doc("export.csv", counters(v), v, [], None, "DMARC")
    keys = list(doc)
    assert keys[keys.index("verdicts") + 1] == "census"
    assert doc["census"] == dedupe.census(doc["verdicts"]) == dedupe.census(v)
    assert set(doc["census"]) == {"by_envelope", "by_sender"}
    json.dumps(doc["census"])  # no Counter leaks into the document
    # audit.py's own census over the same document agrees list for list
    mc = audit.maillog_census(doc)
    assert mc["by_envelope"] == doc["census"]["by_envelope"]
    assert mc["by_sender"] == doc["census"]["by_sender"]


def test_report_prints_the_failing_top_of_each_list_and_truncates(capsys):
    v = verdicts()
    c = counters(v)
    dedupe.print_report(c, v, dedupe.build_findings(c, v, "DMARC"), "DMARC", top=2)
    out = capsys.readouterr().out
    assert "genuine failures by envelope domain (5 failing of 6 seen; likely = heuristic):" in out
    assert "genuine failures by sender (5 failing of 7 seen; likely = heuristic):" in out
    assert "3 of 5 messages fail   senders: 2, e.g. billing@example.com" in out
    assert "domain: sub.example.com   envelope: sub.example.com   subject: Nightly export complete" in out
    assert out.count("... 3 more, use --json for the full list") == 2
    env_block = out.split("genuine failures by envelope domain")[1].split("genuine failures by sender")[0]
    assert "news.example.com" not in env_block  # clean entries are in --json only
    # the pre-existing lines around the new block are still there
    assert "raw rows with a failing verdict: 10" in out
    assert "counting rows would report 10 failures; the true count is 10." in out


def run_cli(*argv):
    return subprocess.run([sys.executable, str(ROOT / "src" / "dedupe.py"), "samples/sample_maillog.csv",
                           "--auth-column", "DMARC", *argv], cwd=ROOT, capture_output=True, text=True, timeout=120)


def test_cli_json_carries_the_full_census_and_the_report_prints_it():
    p = run_cli("--json")
    assert p.returncode in (0, 1), p.stderr
    doc = json.loads(p.stdout)
    cs = doc["census"]
    assert set(cs) == {"by_envelope", "by_sender"}
    assert sum(e["genuine_failures"] for e in cs["by_sender"]) == doc["counters"]["genuine_failures"]
    assert sum(e["messages"] for e in cs["by_envelope"]) == doc["counters"]["logical_messages"]
    assert any(not e["genuine_failures"] for e in cs["by_sender"])  # clean senders are in the inventory
    fails = [e["genuine_failures"] for e in cs["by_envelope"]]
    assert fails == sorted(fails, reverse=True)
    assert set(cs["by_envelope"][0]) == {"envelope_domain", "genuine_failures", "messages", "senders",
                                        "sample_sender", "likely"}
    assert set(cs["by_sender"][0]) == {"sender", "domain", "envelope_domain", "genuine_failures", "messages",
                                      "likely", "sample_subject"}
    p = run_cli()
    assert p.returncode in (0, 1), p.stderr
    assert "genuine failures by envelope domain (" in p.stdout
    assert "genuine failures by sender (" in p.stdout
