"""Round 13 review fixes: the strip, the band's most critical lines.

A domain with two DMARC records applies no policy and is said so (an invalid record, never "reports only - nothing
to do"); an organization with a plan hold and no row says to settle the hold. A quarantine-now row's short step
never says "now" beside a check, and a line that names several rows quotes each one's own status. Within the
unprotected tier the weakest status leads, so the headline's worst is the first line. A list of ids never leaves a
lone ')' at the start of a line. What outside receivers saw failing is said beside the mail log's count, the plain
lines name the envelope a failing sender came in through, and an organization the API row cap cut counts at least.
Synthetic data, offline."""

import json

import pytest

import brief
import next_steps
import notify
import r13_fixtures as F


@pytest.fixture(scope="module")
def incident(tmp_path_factory):
    return F.incident(tmp_path_factory.mktemp("r13_fix_strip_incident"))


def lines_by_org(top):
    return {e["org"]: e for e in top["domains"]}


def test_two_dmarc_records_read_as_an_invalid_record_with_the_hold_to_settle(tmp_path):
    run = F.estate(tmp_path, two_records=True)
    rep, top = run["report"], run["doc"]["top"]
    assert next_steps.band_status(rep, "example.net") == ("invalid", next_steps.TWO_RECORDS)
    assert top["protected"]["text"] == ("Partly: 2 of 9 domains refuse or junk spoofed mail; 4 only report (p=none), 2 "
                                        "have no DMARC record, 1 has an invalid record.")
    net = lines_by_org(top)["example.net"]
    assert (net["badge"], net["pill"], net["status"]) == ("invalid record", "bad", "invalid")
    assert next_steps.strip_line_md(net) == (
        "**Invalid record - example.net**: Receivers apply no policy: it has two DMARC records; small failures only (6, "
        "under 10). Next: settle the hold - two DMARC records at _dmarc.example.net.")
    assert "  5. example.net - invalid record: receivers apply no policy: it has two DMARC records; small failures only " \
           "(6, under 10)" in top["lines_plain"]
    # one name: its sentence says why it applies no policy
    one = dict(rep, gate={"domains": {"example.net": rep["gate"]["domains"]["example.net"]}})
    assert next_steps.build_top(one, None, {})["protected"]["text"] == (
        "Not yet: example.net has two DMARC records: receivers apply no policy.")


def test_a_quarantine_now_row_never_says_now_beside_its_checks(tmp_path):
    top = F.estate(tmp_path).get("doc")["top"]
    org = lines_by_org(top)["example.org"]
    assert org["action_plain"] == "go straight to quarantine (P-01) - after 3 checks"
    assert not any("quarantine now" in e["action_plain"] for e in top["domains"])
    assert next_steps.short_step({"kind": "no_mail"}) == "go straight to quarantine"


def test_a_line_naming_several_rows_quotes_each_ones_status(tmp_path):
    # a park pair: the record carries the placeholder address, the SPF row only waits on its check
    first = F.first_run(tmp_path)
    old = lines_by_org(first["doc"]["top"])["harbor-old.example"]
    assert old["action_plain"] == "park it - P-02 needs the report address, P-03 after 1 check"
    assert old["ids"] == ["P-02", "P-03"]
    # rows of one kind but another step are never named under the first one's step and status
    rows = [{"id": "P-12", "domain": "example.com", "kind": "ratchet", "priority": 3, "hostname": "_dmarc.example.com",
             "value": "v=DMARC1; p=reject; sp=none;", "current": "v=DMARC1; p=quarantine; sp=none;",
             "status": "gated", "status_text": "the gate says not yet", "status_reason": "x"},
            {"id": "P-14", "domain": "example.com", "kind": "ratchet", "priority": 4, "hostname": "_dmarc.example.com",
             "value": "v=DMARC1; p=quarantine; sp=quarantine;", "current": "v=DMARC1; p=quarantine; sp=none;",
             "status": "gated", "status_text": "the gate says not yet", "status_reason": "x"}]
    row, same = next_steps._band_row({"changes": rows}, ["example.com"], "example.com")
    assert row["id"] == "P-12" and [c["id"] for c in same] == ["P-12"]
    assert next_steps._parts_text(next_steps._step_parts(row, same)) == "move to p=reject (P-12) - the gate says not yet"


def test_the_weakest_unprotected_status_leads_and_the_headline_names_it(tmp_path):
    docs, _, flows, _ = F.first_run_parts()
    # no mail log (the review's nolicense run): one aggregate report, all passing, so nothing fails anywhere
    report = F.T.rua_report(tmp_path / "pass.xml", "harborfoods.example", "none", [
        ("192.0.2.5", 40, "harborfoods.example", "harborfoods.example", "pass", "harborfoods.example", "pass")])
    rep = F.T.audited(tmp_path / "nolog", docs, None, [report], flows=flows, sources={d: ["tenant"] for d in docs})
    top = next_steps.build(rep)["top"]
    assert [(e["org"], e["status"]) for e in top["domains"]] == [
        ("harbor-old.example", "absent"), ("harborfoods-shop.example", "absent"), ("harborfoods.example", "none")]
    assert "Worst: 2 domains have no DMARC record." in top["headline"]


def test_a_list_of_ids_keeps_its_brackets_on_its_tags_lines():
    parts = [["text", "park it ("], ["id", "P-02"], ["text", ", "], ["id", "P-03"], ["text", ") - needs the report address"]]
    html = brief.band_parts(parts, {}, {"P-02": "_dmarc.harbor-old.example"})
    assert html == ('<bdi>park it </bdi><span class="nb">(<span class="tag" title="_dmarc.harbor-old.example">P-02</span>,'
                    '</span><bdi> </bdi><span class="nb"><span class="tag">P-03</span>)</span><bdi> - needs the report '
                    'address</bdi>')
    assert ".nb { white-space: nowrap; }" in brief.CSS
    # a tag and its short host name stay on one line, with what closes them; a long host name may break inside
    parts = [["text", "ready now: "], ["id", "P-08"], ["text", " "], ["host", "_dmarc.alerts"], ["text", ", "],
             ["id", "P-09"], ["text", " "], ["host", "_dmarc." + "x" * 40], ["text", "; more"]]
    html = brief.band_parts(parts, {}, {})
    assert ('<span class="nb"><span class="tag">P-08</span> <span class="mono"><span class="d">_dmarc.alerts</span>'
            '</span>,</span>') in html
    assert '<span class="tag">P-09</span><bdi> </bdi><span class="mono"><span class="d dl">' in html


def test_outside_receivers_failing_is_said_beside_the_mail_logs_count(tmp_path):
    docs, log, flows, _ = F.incident_parts()
    report = F.T.rua_report(tmp_path / "net.xml", "example.net", "none", [
        ("192.0.2.81", 56, "example.net", "esp.invalid", "pass", "esp.invalid", "pass"),
        ("198.51.100.7", 200, "example.net", "example.net", "pass", "example.net", "pass")],
        begin=F.T.BEGIN - 20 * F.T.DAY, end=F.T.BEGIN)
    rep = F.T.audited(tmp_path / "run", docs, log, [report], flows=flows, sources={d: ["tenant"] for d in docs})
    net = lines_by_org(next_steps.build(rep)["top"])["example.net"]
    assert net["tier"] == 6 and "small" in net["flags"]
    assert net["finding_plain"] == ("small failures only (6, under 10); 56 failing at outside receivers (aggregate "
                                    "reports)")


def test_the_plain_lines_name_the_envelope_a_failing_sender_came_in_through(incident):
    top = incident["doc"]["top"]
    line = "  1. example.com - junks spoofs: 65 of our own messages fail DMARC (via hrmail.example.com) and receivers " \
           "junk them"
    assert line in top["lines_plain"]
    summary = notify.summarize(incident["report"], plan=incident["plan"], top=top)
    assert "1. `example.com` junks spoofs - 65 of our own messages fail DMARC (via hrmail.example.com) and receivers " \
           "junk them" in summary.splitlines()
    assert "@" not in summary
    assert next_steps._via({"sender": "billing@corp.co.uk", "env": "corp.co.uk"}) == ""


def test_an_hour_at_the_api_row_cap_makes_the_count_a_floor(incident):
    rep = json.loads(json.dumps(incident["report"]))
    rep["maillog"]["cuts"] = {"example.com": {"reason": "api cap", "api_cap_hours": ["6h..5h"]}}
    top = next_steps.build(rep, plan=incident["plan"])["top"]
    e = lines_by_org(top)["example.com"]
    assert e["flags"] == ["floor"] and next_steps.strip_line_md(e).startswith(
        "**Junks spoofs - example.com**: At least 65 of our own messages fail DMARC")
    assert "example.com: the API row cap cut 1 hour of its mail log, so its counts are floors" in top["gaps"]
    # a pull that failed is no floor: nothing was kept
    rep["maillog"]["cuts"] = {"example.net": {"reason": "not pulled", "error": "HTTP 500"}}
    net = lines_by_org(next_steps.build(rep, plan=incident["plan"])["top"])["example.net"]
    assert "floor" not in net["flags"] and "not_pulled" in net["flags"]
