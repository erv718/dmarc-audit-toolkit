"""What a live tenant at scale showed after round 10 (ISSUES.md B, G and C):
a rejected full-window answer explains itself, the gate's many outside-view
blockers become one line, the source tables' rows stay small, and a spoofer's
throwaway envelope domain is not a sender identity. No network."""

import json

import audit
import collect
import next_steps
import notify

TOTALS_ROW = {"fromdom": "corp.example", "logical_messages": 7000, "passing": 6800, "delivered_by": "",
              "genuine_failures": 150, "delivered_despite_fail": 12}


def test_a_rejected_totals_answer_says_why_and_numbers_as_text_are_counts():
    assert collect._tally("1234.0") == 1234 and collect._tally("  77 ") == 77 and collect._tally("") == 0
    assert collect._tally(None) == 0 and collect._tally("many") is None and collect._tally(-1) is None
    good = {"schema": [{"name": k} for k in TOTALS_ROW], "results": [dict(TOTALS_ROW, logical_messages="7000.0")]}
    assert collect.totals_by_domain(good, "corp.example")["corp.example"]["logical_messages"] == 7000
    # the schema names some columns and the row carries the rest: both are read, as run_hunting.columns reads them
    half = {"schema": [{"name": "fromdom"}], "results": [dict(TOTALS_ROW)]}
    assert collect.totals_by_domain(half, "corp.example")["corp.example"]["genuine_failures"] == 150
    cases = [
        ({"schema": [], "results": None}, "no results list of rows (keys results,schema; schema []; results NoneType)"),
        ({"schema": [{"name": "fromdom"}], "results": [{"fromdom": "corp.example", "passing": 1}]},
         "columns missing: delivered_despite_fail, genuine_failures, logical_messages (keys results,schema; "
         "schema ['fromdom']; 1 rows; first row fromdom:str,passing:int)"),
        ({"schema": [{"name": k} for k in TOTALS_ROW], "results": [dict(TOTALS_ROW, passing={"n": 1})]},
         "row 1 has a passing of type dict where a count was expected (keys results,schema; schema ['fromdom', "
         "'logical_messages', 'passing', 'delivered_by', 'genuine_failures', 'delivered_despite_fail']; 1 rows; "
         "first row fromdom:str,logical_messages:int,passing:dict,delivered_by:str,genuine_failures:int,"
         "delivered_despite_fail:int)"),
    ]
    for answer, why in cases:
        assert collect.totals_by_domain(answer, "corp.example") is None
        assert collect.totals_rejection(answer, "corp.example") == why
    # and the run note carries the reason, so the next live run explains a refusal itself
    calls = []

    def hunting(tok, kql, ts=None):
        calls.append(kql)
        return cases[1][0]
    import graph_client
    original = graph_client.hunting
    graph_client.hunting = hunting
    try:
        totals, notes = collect.pull_window_totals("tok", {"corp.example": {"reason": "row budget", "kept_hours": 63}}, 30)
    finally:
        graph_client.hunting = original
    assert totals is None and len(calls) == 1
    assert notes == ["mail log: full-window totals for corp.example not counted: the answer is not the totals "
                     "maillog_totals.kql asks for - " + cases[1][1]]


def gate_with_streams(n):
    reasons = ["203.0.113.%d fails DMARC on %d/%d msgs (%s); fix, or formally except it, before p= moves"
               % (i, 1000 - i * 7, 1000 - i * 7, "likely_misconfigured" if i == 1 else "unknown") for i in range(1, n + 1)]
    reasons.append("corp.example: 12 logical message(s) from this domain failed with no passing copy (deduplicated)")
    return {"inputs": {"domains": ["corp.example"]},
            "gate": {"domains": {"corp.example": {"verdict": "no_go", "current_policy": "none", "reasons": reasons,
                                                  "next_step": "move to p=quarantine at a low pct (for example pct=10)"}},
                     "evidence": {"statement": "s"}}}


def test_many_outside_view_blockers_become_one_bounded_line():
    items = next_steps.blocker_items(gate_with_streams(90), "corp.example")
    outside = [i for i in items if i["kind"] == "outside"]
    assert len(outside) == 1 and len(items) == 2
    text = outside[0]["text"]
    assert text.startswith("90 outside-view senders fail DMARC with real volume (203.0.113.1 (993 of 993 msgs, looks like "
                           "our own system misconfigured), 203.0.113.2 (986 of 986 msgs, unclear), 203.0.113.3 "
                           "(979 of 979 msgs, unclear) and 87 more in report.md); fix, or formally except them")
    assert text.count("203.0.113.") == 3 and len(text) < 400
    one = [i for i in next_steps.blocker_items(gate_with_streams(1), "corp.example") if i["kind"] == "outside"][0]
    assert one["text"].startswith("1 outside-view sender fails DMARC with real volume (203.0.113.1 (993 of 993 msgs")
    assert one["text"].endswith("; fix, or formally except it, before p= moves") and "more" not in one["text"]
    # the one-liner, the readiness and the open questions all read that one line, not ninety
    doc = next_steps.build(gate_with_streams(90))
    assert doc["one_liner"].count("fails DMARC") == 0 and "90 outside-view senders" in doc["one_liner"]
    assert len(doc["one_liner"]) < 900
    assert len(json.dumps(doc)) < 60000


def test_source_rows_keep_their_busiest_list_entries_and_say_how_many_were_cut():
    row = {"source_ip": "203.0.113.9", "count": 5000,
           "spf": [{"domain": "r%d.relay.example" % i, "scope": "mfrom", "result": "pass", "count": i} for i in range(3000)],
           "envelope_from": [{"domain": "r%d.relay.example" % i, "count": i} for i in range(3000)],
           "reporters": ["reporter-%d" % i for i in range(40)], "dkim": [{"domain": "d.example", "count": 1}]}
    unknown = {"kind": "ip", "value": "203.0.113.9", "count": 5000, "spf_domains": ["r%d.relay.example" % i for i in range(3000)],
               "dkim_domains": ["d.example"]}
    doc = {"by_source_ip": [row], "unknown_senders": [unknown]}
    audit._trim_rua(doc, 1000)  # under the row cap: the row lists are still cut
    assert len(row["spf"]) == audit.ROW_LIST_CAP and row["spf_total"] == 3000
    assert row["spf"][0]["count"] == 2999 and row["spf"][-1]["count"] == 2975  # the busiest, not the first seen
    assert len(row["envelope_from"]) == audit.ROW_LIST_CAP and row["envelope_from_total"] == 3000
    assert len(row["reporters"]) == audit.ROW_LIST_CAP and row["reporters_total"] == 40 and row["reporters"][0] == "reporter-0"
    assert row["dkim"] == [{"domain": "d.example", "count": 1}] and "dkim_total" not in row
    assert len(unknown["spf_domains"]) == audit.ROW_LIST_CAP and unknown["spf_domains_total"] == 3000
    assert unknown["dkim_domains"] == ["d.example"]
    assert len(json.dumps(doc)) < 12000


def test_a_spoofers_throwaway_envelope_is_not_a_sender_identity():
    rep = {"rua": {"by_source_ip": [{"source_ip": "192.0.2.10", "count": 10}]},
           "maillog": {"census": {"by_envelope": [
               {"envelope_domain": "bounce.vendor.example", "messages": 40, "genuine_failures": 0, "likely": None},
               {"envelope_domain": "throwaway.invalid", "messages": 30, "genuine_failures": 30, "likely": "likely_spoof"},
               {"envelope_domain": "mixed.example", "messages": 30, "genuine_failures": 30, "likely": "unknown"},
               {"envelope_domain": "rescued.example", "messages": 31, "genuine_failures": 30, "likely": "likely_spoof"},
               {"envelope_domain": "(blank)", "messages": 3, "genuine_failures": 0}]}}}
    assert notify.sender_keys(rep) == {"ip:192.0.2.10", "envelope:bounce.vendor.example", "envelope:mixed.example",
                                       "envelope:rescued.example"}
    older = {"rua": {}, "maillog": {"census": {"by_envelope": [{"envelope_domain": "old.example", "genuine_failures": 2}]}}}
    assert notify.sender_keys(older) == {"envelope:old.example"}  # a census without message counts keeps every envelope


def test_a_plan_rows_many_source_prerequisites_fold_into_one_condition():
    pre = ["every legitimate sender proven with an aligned DKIM header within 7 days"] + [
        "aggregate reports: 203.0.113.%d sends %d message(s) as corp.example and fails (unknown; x)" % (i, 500 - i)
        for i in range(1, 91)]
    out = next_steps.reword_prereqs(pre)
    assert out[0] == "every legitimate sender is proven with an aligned DKIM header within 7 days"
    assert out[1] == ("the 90 failing outside-view senders are fixed or formally excepted (busiest: 203.0.113.1 (499 as "
                      "corp.example), 203.0.113.2 (498 as corp.example), 203.0.113.3 (497 as corp.example); 87 more in "
                      "report.md)") and len(out) == 2
    assert next_steps.reword_prereqs(pre[:2]) == [out[0], "the sender at 203.0.113.1 (499 messages as corp.example) is fixed"]
    # through the document: one condition in the readiness, one open question, a bounded one-liner
    rep = gate_with_streams(0)
    rep["gate"]["domains"]["corp.example"] = {"verdict": "go", "current_policy": "quarantine", "reasons": [],
                                             "next_step": "move to p=reject"}
    rep["dns"] = {"corp.example": {"domain": "corp.example", "dmarc": "v=DMARC1; p=quarantine; pct=100; rua=mailto:r@corp.example;",
                                   "dmarc_source": "corp.example", "effective_policy": "quarantine", "inherited": False,
                                   "dmarc_status": "found", "spf": "v=spf1 -all", "spf_status": "found", "spf_terminator": "-all",
                                   "spf_lookups": 0, "dkim_selectors": ["s1"], "dkim_status": "found", "mx": ["0 mx.corp.example"],
                                   "mx_null": False, "mx_status": "found", "flags": [], "findings": [], "evidence": []}}
    plan = {"changes": [{"id": "P-01", "domain": "corp.example", "kind": "ratchet", "priority": 3, "record": "TXT",
                         "hostname": "_dmarc.corp.example", "value": "v=DMARC1; p=reject; pct=100; rua=mailto:r@corp.example;",
                         "current": rep["dns"]["corp.example"]["dmarc"], "rollback": "publish the current string verbatim",
                         "why": "reject", "prerequisites": pre, "finding_ids": [], "owner_hint": "corp.example",
                         "human_summary": "Move corp.example to reject."}], "holds": []}
    doc = next_steps.build(rep, plan=plan)
    assert doc["one_liner"].count("203.0.113.") == 3 and len(doc["one_liner"]) < 700
    assert sum(1 for q in doc["open_questions"] if q.get("kind") == "prerequisite") == 2
