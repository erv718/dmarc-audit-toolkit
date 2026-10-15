"""Round 12 fixes, core: what the review of the round's outputs found in the
status document and the files beside it. An owner's plan row carries its
action in parts (summary, prerequisites) for a reader that lays the
conditions out as a checklist; What is failing names the entries at 10 or
more beyond the top five apart from the notes, and caps the outside view's
notes; outside sources that share an owner, a finding and a diagnosis
become one item; an owner's items that concern several organizations are
filed apart, and its zero-risk records are bundled per organization; the
delta's findings, the cut organizations, the full-window totals, the From
domains of an outside source and every sender list ranked by a count follow
the one order, the headline's organization first; one table of two-label
public suffixes. Synthetic data, offline: nothing here touches the network."""

from collections import Counter

import pytest

import audit
import collect
import discover
import dns_audit
import next_steps
import notify
import plan as plan_mod
import test_r11_plan as r11
import test_r12_order as r12

HEAD = "example.org"


def section(md, title):
    """The lines under one '## ' heading, up to the next one."""
    return md.split("\n## %s" % title, 1)[1].split("\n## ", 1)[0].splitlines()[1:]


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    """The round's three-organization estate (tests/test_r12_order.py), through next_steps."""
    rep, plan = r12.estate(tmp_path_factory.mktemp("fix_core"))
    doc = next_steps.build(rep, plan, owners=r12.OWNERS)
    return {"report": rep, "plan": plan, "doc": doc, "md": next_steps.render_md(doc)}


# ------------------------------------------------------------------ an owner's plan row, in parts (CONTRACT)

def test_a_plan_rows_item_carries_its_summary_and_its_prerequisites_in_the_rows_order(estate):
    """summary is the action without its before-applying clause, prerequisites the clause's conditions in the
    row's order, worded as the clause words them; the action and next_steps.md say what they said."""
    rows = {c["id"]: c for c in estate["plan"]["changes"]}
    items = [i for g in estate["doc"]["actions_by_owner"] for i in g["items"] if i["kind"] == "dns"]
    assert [i["ref"] for i in items] == ["P-10", "P-11", "P-12", "P-13"]
    for i in items:
        want = next_steps.reword_prereqs(next_steps.prereqs_of(rows[i["ref"]]))
        assert i["prerequisites"] == want and len(want) >= 2
        assert i["action"] == "%s (before applying: %s)" % (i["summary"], next_steps._join(want))
        assert "before applying" not in i["summary"] and i["summary"].startswith(next_steps.plain(
            next_steps.step_label(rows[i["ref"]])) + " - ")
        assert "- **%s** %s (%s)" % (i["hook"], i["action"], i["ref"]) in estate["md"]
    # the order is the row's: P-10's own-sender condition before the other change's week
    p10 = items[0]["prerequisites"]
    assert p10[0].startswith("every legitimate sender is proven") and p10[-1].startswith("the other change to")
    # a row with nothing to confirm: the summary is the whole action, the list empty
    plan = {"changes": [{"id": "P-01", "priority": 3, "kind": "ratchet", "domain": "example.com",
                         "hostname": "_dmarc.example.com", "value": "v=DMARC1; p=quarantine; pct=50",
                         "current": "v=DMARC1; p=quarantine; pct=25", "why": "raise pct", "prerequisites": []}]}
    item = next_steps.build_actions({"findings": []}, plan, None, [])[0]["items"][0]
    assert (item["summary"], item["prerequisites"]) == (item["action"], []) == ("raise pct to 50 - raise pct", [])
    # the zero-risk bundle, a sender fix and the like are no plan row: no parts
    others = [i for g in estate["doc"]["actions_by_owner"] for i in g["items"] if i["kind"] != "dns"]
    assert others and not any("summary" in i or "prerequisites" in i for i in others)


# ------------------------------------------------------------------ What is failing: headlines, the rest, the notes

def census_report(counts):
    """A report whose census holds one envelope domain and one sender per count given (example.org audited)."""
    names = ["%s.example.org" % chr(ord("a") + k) for k in range(len(counts))]
    census = {"by_envelope": [{"envelope_domain": n, "genuine_failures": c, "messages": c} for n, c in zip(names, counts)],
              "by_sender": [{"sender": "ops@" + n, "domain": n, "envelope_domain": n, "genuine_failures": c,
                             "messages": c} for n, c in zip(names, counts)]}
    return {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": [HEAD]},
            "gate": {"headline_domain": HEAD, "domains": {HEAD: {}}},
            "maillog": {"counters": {"genuine_failures": sum(counts)}, "census": census}}


def test_entries_at_ten_or_more_beyond_the_top_five_are_named_apart_from_the_notes():
    counts = [50, 40, 30, 25, 20, 19, 12, 9, 3]
    doc = next_steps.build(census_report(counts))
    lines = doc["failing"]["lines"]
    env = lines[:lines.index("")]
    assert env[0] == "By envelope domain (who actually handed the mail over):"
    assert [l.split(" - ")[0] for l in env[1:6]] == ["- **%s.example.org" % c for c in "abcde"]
    assert env[6] == ("- Also at 10 or more each: f.example.org x19 (unclear), g.example.org x12 (unclear)")
    assert env[7] == "- Notes, not headlines (under 10 each): h.example.org x9 (unclear), i.example.org x3 (unclear)"
    assert len(env) == 8
    snd = lines[lines.index("") + 1:]
    assert snd[6].startswith("- Also at 10 or more each: ops@f.example.org x19") and "x12" in snd[6]
    assert snd[7] == ("- Notes, not headlines (under 10 each): ops@h.example.org x9 (unclear), ops@i.example.org x3 "
                      "(unclear)")
    assert "\n".join(env) in next_steps.render_md(doc)
    # next_steps.json keeps every entry, and the split the lines make is the helper brief.py can share
    data = doc["failing"]
    assert [e["count"] for e in data["by_envelope"]] == counts
    assert next_steps.headline_split(data["by_envelope"]) == (
        data["by_envelope"][:5], data["by_envelope"][5:7], data["by_envelope"][7:])
    # nothing at ten or more past the headlines: no such line
    assert not any("Also at" in l for l in next_steps.build(census_report([50, 9]))["failing"]["lines"])


def stream(ip, fail, froms, signals=None, likely="likely_misconfigured"):
    return {"source_ip": ip, "count": fail, "pass": 0, "fail": fail, "header_from": list(froms),
            "dispositions": {"none": fail}, "likely": likely,
            "likely_signals": signals if signals is not None else [
                "DKIM verifies for d=esp.invalid but that domain is not aligned with header_from (%d msgs)" % fail,
                "SPF passes for envelope domain esp.invalid which is not aligned with header_from (%d msgs)" % fail]}


def by_source(ip, counts):
    """rua.by_source_ip's row for one source: its messages per From domain."""
    return {"source_ip": ip, "count": sum(counts.values()),
            "header_from": [{"domain": d, "count": n} for d, n in counts.items()]}


def test_the_outside_views_notes_are_capped_and_split_like_the_others():
    fs = [stream("198.51.100.%d" % k, 60 - k, ["example.org"]) for k in range(1, 8)]  # 7 at ten or more
    fs += [stream("203.0.113.%d" % k, 5, ["example.org"]) for k in range(1, 21)]  # 20 notes
    report = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": [HEAD]},
              "gate": {"headline_domain": HEAD, "domains": {HEAD: {}}},
              "rua": {"failing_streams": fs, "spf_only_senders": []}}
    lines = next_steps.build(report)["failing"]["lines"]
    out = lines[lines.index("From the outside (aggregate reports; these counts include forwarded copies and cannot "
                            "be deduplicated):") + 1:]
    assert [l.split(" - ")[0] for l in out[:5]] == ["- **198.51.100.%d" % k for k in range(1, 6)]
    assert out[5] == ("- Also at 10 or more each: 198.51.100.6 x54 (looks like our own system misconfigured), "
                      "198.51.100.7 x53 (looks like our own system misconfigured)")
    notes = out[6]
    assert notes.startswith("- Notes, not headlines: 203.0.113.1 x5 (looks like our own system misconfigured), ")
    assert notes.count(" x5 ") == next_steps.NOTES_CAP and notes.endswith(" (+8 more in report.json)")
    assert len(out) == 7


# ------------------------------------------------------------------ outside sources with one diagnosis: one item

def test_outside_sources_with_one_owner_finding_and_diagnosis_become_one_item():
    fs = [stream("198.51.100.%d" % k, 10 * k, ["example.com"]) for k in range(1, 13)]  # 12 sources, one diagnosis
    fs.append(stream("192.0.2.40", 70, ["example.com"], [  # another signing domain: another diagnosis
        "DKIM verifies for d=other.invalid but that domain is not aligned with header_from (70 msgs)"]))
    fs += [stream("192.0.2.%d" % k, 20, ["example.net"], ["mixed results with no single explanation"], "unknown")
           for k in (51, 52, 53)]  # three of a kind: fewer than four stay as they are
    report = {"rua": {"failing_streams": fs, "spf_only_senders": []},
              "findings": [{"id": "OUTSIDE-001", "severity": "major", "source": "rua"}]}
    groups = next_steps.build_actions(report, None, None, [], "example.com")
    items = groups[0]["items"]
    folded = [i for i in items if i["hook"].startswith("12 outside sources")]
    assert len(folded) == 1 and len(items) == 1 + 1 + 3
    f = folded[0]
    total = sum(10 * k for k in range(1, 13))
    assert f["hook"] == "12 outside sources - %d failing messages as example.com" % total
    assert f["action"] == (
        "DKIM-sign the systems behind these IPs with an aligned d=: receivers see them fail (DKIM verifies for "
        "d=esp.invalid but that domain is not aligned with the From domain; SPF passes for envelope domain esp.invalid "
        "which is not aligned with the From domain); the busiest: 198.51.100.12 x120, 198.51.100.11 x110, "
        "198.51.100.10 x100; 9 more in report.md")
    assert (f["ref"], f["kind"], f["domains"], f["org"]) == ("OUTSIDE-001", "stream", ["example.com"], "example.com")
    assert "msgs" not in f["action"] and "_source" not in f
    # the other diagnosis and the three of a kind keep a line each, as one source does
    single = [i for i in items if i["hook"].startswith("192.0.2.40 ")]
    assert single[0]["hook"] == "192.0.2.40 - 70 failing messages as example.com" and "(70 msgs)" in single[0]["action"]
    assert sum(1 for i in items if i["hook"].startswith("192.0.2.5")) == 3
    # one owner question for the fold, and every source still named in What is failing
    doc_q = next_steps.open_questions(report, None, "example.com", None, [], groups, "example.com")
    assert sum(1 for q in doc_q if "12 outside sources" in q["question"]) == 1
    data, lines = next_steps.what_is_failing(report, None, "example.com")
    assert len(data["outside"]) == len(fs)
    # one source alone stays as it is
    alone = next_steps.build_actions(dict(report, rua={"failing_streams": fs[:1], "spf_only_senders": []}), None, None, [])
    assert alone[0]["items"][0]["hook"] == "198.51.100.1 - 10 failing messages as example.com"


# ------------------------------------------------------------------ an owner's items that concern several organizations

def test_an_owners_zero_risk_records_are_bundled_per_organization(estate):
    """example.net's records are in example.net's line, never in example.com's bundle: every organization with a
    planned record has a line of its own, and its bundle names it."""
    body = section(estate["md"], "What happens next, by owner")
    com = "\n".join(body[body.index("  - **example.com** - 11 items"):body.index("  - **example.net** - 7 items")])
    assert "P-08" not in com and "P-09" not in com
    net = body[body.index("  - **example.net** - 7 items") + 1]
    assert net.startswith("    - **2 zero-risk monitoring records for example.net** ready to publish (plan P-08 to P-09)")
    items = {g["owner"]: g["items"] for g in estate["doc"]["actions_by_owner"]}[next_steps.UNASSIGNED]
    bundles = [(i["hook"], i["ref"], i["org"], i["orgs"]) for i in items if i["kind"] == "p1summary"]
    assert bundles == [
        ("5 zero-risk monitoring records for example.com", "plan P-01 to P-05", "example.com", ["example.com"]),
        ("2 zero-risk monitoring records for example.net", "plan P-08 to P-09", "example.net", ["example.net"])]
    # one organization's records keep the bundle's old words
    brand = {g["owner"]: g["items"] for g in estate["doc"]["actions_by_owner"]}["Brand team"]
    assert brand[0]["hook"] == "2 zero-risk monitoring and hygiene records"


def test_an_item_that_concerns_several_organizations_is_filed_under_several_organizations():
    """The spoofing bundle and the 'N more senders' bundle span three organizations: they go under a line of
    their own, before the tenant-wide items, never under the organization of their first domain."""
    orgs = ("example.com", "brand.example", "example.net")
    fs = [stream("203.0.113.%d" % k, 30 + k, [d], ["no DKIM signature and no SPF pass on any domain (30 of 30 msgs)",
                                                   "header_from is the domain itself"], "likely_spoof")
          for k, d in enumerate(orgs, 1)]
    fs += [stream("198.51.100.%d" % k, 20 + k, [d]) for k, d in enumerate(orgs, 1)]
    plan = {"changes": [{"id": "P-%02d" % k, "priority": 1, "kind": "new", "domain": d, "hostname": "_dmarc." + d,
                         "value": "v=DMARC1; p=none;", "current": "none", "why": "monitoring"}
                        for k, d in enumerate(orgs, 1)]}
    report = {"rua": {"failing_streams": fs, "spf_only_senders": []},
              "findings": [{"id": "OUTSIDE-001", "severity": "major", "source": "rua"},
                           {"id": "RULES-002", "severity": "major", "source": "rules", "title": "bypass",
                            "action": "look", "object": "Partner bypass"}]}
    groups = next_steps.build_actions(report, plan, None, [], "example.com")
    md = next_steps.render_actions(groups, headline="example.com")
    heads = [l for l in md if l.startswith("  - **")]
    assert heads == ["  - **example.com** - 2 items", "  - **brand.example** - 2 items", "  - **example.net** - 2 items",
                     "  - **Several organizations** - 1 item", "  - **Tenant-wide** - 1 item"]
    several = md[md.index("  - **Several organizations** - 1 item") + 1]
    assert several.startswith("    - **96 messages from 3 outside IPs that look like spoofing**")
    # each organization's line holds its own zero-risk record and its own source
    com = md[md.index("  - **example.com** - 2 items") + 1:md.index("  - **brand.example** - 2 items")]
    assert com[0] == "    - **1 zero-risk monitoring record for example.com** ready to publish (plan P-01)"
    assert com[1].startswith("    - **198.51.100.1 - 21 failing messages as example.com** ")
    assert all("brand.example" not in l and "example.net" not in l for l in com)
    # next_steps.json: org stays the first domain's organization, orgs names every one
    spoof = [i for i in groups[0]["items"] if i["kind"] == "spoof"][0]
    assert spoof["orgs"] == ["example.com", "brand.example", "example.net"] and spoof["org"] == "example.com"
    # an older document's items, without orgs, are filed by their one org as before
    old = [dict(g, items=[{k: v for k, v in i.items() if k != "orgs"} for i in g["items"]]) for g in groups]
    assert "  - **Several organizations** - 1 item" not in next_steps.render_actions(old, headline="example.com")


# ------------------------------------------------------------------ the delta's lists, report.md and summary.txt

def delta_pair():
    """(report, previous): new findings on four names under two organizations and one tenant finding, resolved
    findings on twelve names; example.com is the headline."""
    def f(fid, dom, sev="major"):
        return {"id": fid, "severity": sev, "source": "dns:" + dom if dom else "rules", "title": fid}
    now = [f("DKIM-009", d) for d in ("brand.example", "e.example.com", "example.com")]
    now += [f("DMARC-004", "t.example.com", "minor"), f("RULES-001", "", "blocking")]
    gone = ["a.shop.example.com", "brand.example", "e.example.com", "example.co.uk", "example.com", "example.net",
            "m.example.com", "mail.example.co.uk", "shop.example.com", "t.example.com", "x.example.net", "zz.example"]
    report = {"generated_utc": "2026-10-09T06:00:00Z", "findings": now,
              "inputs": {"domains": ["example.com", "brand.example"]},
              "gate": {"headline_domain": "example.com", "domains": {"example.com": {}, "brand.example": {}}}}
    previous = {"generated_utc": "2026-10-02T06:00:00Z", "findings": [f("DMARC-007", d) for d in gone],
                "gate": {"headline_domain": "example.com", "domains": {"example.com": {}, "brand.example": {}}}}
    return report, previous


def test_the_deltas_findings_run_by_severity_then_in_the_one_order_in_report_md_and_summary_txt():
    report, previous = delta_pair()
    dl = audit.build_delta(report, previous)
    assert [(f["id"], f["source"]) for f in dl["findings_new"]] == [
        ("RULES-001", "rules"), ("DKIM-009", "dns:example.com"), ("DKIM-009", "dns:e.example.com"),
        ("DKIM-009", "dns:brand.example"), ("DMARC-004", "dns:t.example.com")]
    resolved = [f["source"][4:] for f in dl["findings_resolved"]]
    assert resolved == ["example.com", "a.shop.example.com", "e.example.com", "m.example.com", "shop.example.com",
                        "t.example.com", "brand.example", "example.co.uk", "mail.example.co.uk", "example.net",
                        "x.example.net", "zz.example"]
    L = []
    audit._md_delta(L, dl, "example.com")
    new = next(l for l in L if l.startswith("- new findings"))
    assert new == ("- new findings (5): [blocking] RULES-001 (rules), [major] DKIM-009 (dns:example.com), [major] "
                   "DKIM-009 (dns:e.example.com), [major] DKIM-009 (dns:brand.example), [minor] DMARC-004 "
                   "(dns:t.example.com)")
    assert next(l for l in L if l.startswith("- resolved findings")).startswith(
        "- resolved findings (12): DMARC-007 (dns:example.com), DMARC-007 (dns:a.shop.example.com), ")
    # a delta an earlier version stored in text order reads in the one order too
    stored = dict(dl, findings_new=sorted(dl["findings_new"], key=lambda f: f["source"]),
                  findings_resolved=sorted(dl["findings_resolved"], key=lambda f: f["source"]))
    L2 = []
    audit._md_delta(L2, stored, "example.com")
    assert L2 == L
    # summary.txt: the same order, the severity after each run of findings that share it, and a cut list counted
    text = notify.summarize(dict(report, delta=stored)).splitlines()
    assert ("- *new findings*: rules RULES-001 (blocking); example.com DKIM-009, e.example.com DKIM-009, brand.example "
            "DKIM-009 (major); t.example.com DMARC-004 (minor)") in text
    assert ("- resolved: example.com DMARC-007, a.shop.example.com DMARC-007, e.example.com DMARC-007, m.example.com "
            "DMARC-007, shop.example.com DMARC-007, t.example.com DMARC-007, brand.example DMARC-007, example.co.uk "
            "DMARC-007 (+4 more)") in text
    # without a stored delta, the summary compares the two reports itself, in the same order
    again = notify.summarize(report, previous)
    assert "- *new findings*: rules RULES-001 (blocking); example.com DKIM-009, e.example.com DKIM-009" in again
    assert "- resolved: example.com DMARC-007, a.shop.example.com DMARC-007, " in again


# ------------------------------------------------------------------ the cut organizations, in one order per sentence

CUTS = {"example.co.uk": {"reason": "not pulled", "error": "HTTP 500"},
        "brand.example": {"reason": "row budget", "kept_hours": 41, "kept_from": "2026-10-05T22:00:00Z"},
        "example.org": {"reason": "api cap", "api_cap_hours": ["6h..5h"]}}
# collect.py's clauses and caveats, in the order it pulled the organizations (plain text order)
TRUNCATION = ("row budget kept only the newest 41h for brand.example; an hour of example.org (6h..5h ago) is "
              "truncated at the API cap")
CAVEATS = ["mail log: brand.example row budget reached at 41h..33h ago - older rows skipped; the rows cover only the "
           "last 41h (raise --max-rows to keep more) - mail-log counts for that domain cover that span only",
           "mail log: example.org has more than 100,000 rows within one hour (6h..5h ago) - that hour is truncated "
           "- mail-log counts for that domain are a floor and its failures are not verified"]
TOTALS = {"hours": 720, "orgs": {o: {"by_domain": {o: {"logical_messages": 90, "passing": 70, "genuine_failures": 20,
                                                       "delivered_despite_fail": 3}}}
                                 for o in ("brand.example", "example.org")}}


def cut_report():
    gate = {"headline_domain": HEAD, "verdict": "no_go", "next_step": "move to p=reject",
            "domains": {d: {} for d in ("example.org", "brand.example", "example.co.uk")}}
    return {"generated_utc": "2026-10-09T06:00:00Z", "gate": gate, "dns": {}, "rua": None, "headers": None,
            "findings": [], "inputs": {"domains": list(gate["domains"])}, "caveats": list(CAVEATS),
            "maillog": {"counters": {"genuine_failures": 45, "raw_failing_rows": 45, "raw_rows": 90,
                                     "logical_messages": 90, "delivered_despite_fail": 0},
                        "cuts": dict(CUTS), "truncation": TRUNCATION, "window_totals": TOTALS,
                        "by_domain": {}}}


def test_a_sentence_that_names_the_cut_organizations_names_them_in_one_order():
    rep = cut_report()
    view = next_steps.maillog_view(rep, HEAD)
    stand = next_steps.where_we_stand(rep, view, None, None, "none", HEAD)
    first = stand["lines"][0]
    assert ("the log export was cut short (an hour of example.org (6h..5h ago) is truncated at the API cap; row "
            "budget kept only the newest 41h for brand.example); the rows kept are incomplete for example.org (an "
            "hour at the API cap: 6h..5h; its failures are not verified), a floor for brand.example (the row budget "
            "kept the newest 41h only), missing example.co.uk (its pull failed)") in first
    assert "under example.org and brand.example" in first
    assert audit._cut_words(CUTS) == (  # with no headline, plain organization order
        "; the rows kept are a floor for brand.example (the row budget kept the newest 41h only), missing "
        "example.co.uk (its pull failed), incomplete for example.org (an hour at the API cap: 6h..5h; its failures "
        "are not verified)")
    assert [c.split()[2] for c in stand["caveats"]] == ["example.org", "brand.example"]
    assert [l.split()[3] for l in stand["lines"] if l.startswith("**Caveat:**")] == ["example.org", "brand.example"]
    # report.md's verified-vs-inferred: the mail-log line and the full-window totals, the headline's first
    vi = audit.verified_vs_inferred(rep)["verified"]
    assert [l.split()[3].rstrip(",") for l in vi if l.startswith("full-window totals for")] == [
        "example.org", "brand.example"]
    assert "; the rows kept are incomplete for example.org" in next(l for l in vi if l.startswith("mail log:"))
    # todo.md's caveats, the same order
    todo = collect.render_todo(rep, {"changes": [], "holds": []}, rep["caveats"])
    assert [l.split()[3] for l in section(todo, "Caveats") if l.startswith("- ")] == ["example.org", "brand.example"]


def test_the_deltas_cut_notes_and_reasons_name_the_headlines_organization_first():
    now, prev = cut_report(), cut_report()
    now["gate"]["domains"]["example.net"] = {}  # an organization audited in this run only
    prev["maillog"]["cuts"] = {}
    dl = audit.build_delta(now, prev)
    assert list(dl["maillog_window"]["cut_orgs"]) == ["example.org", "brand.example", "example.co.uk"]
    cut_notes = [n.split("'s mail log")[0].split()[-1] for n in dl["notes"] if "mail log in this run" in n]
    assert cut_notes == ["example.org", "brand.example", "example.co.uk"]
    L = []
    audit._md_delta(L, dl, HEAD)
    assert ("- genuine failures: n/a (mail log cut for example.org, brand.example and example.co.uk; example.net "
            "audited in one run only, see the notes below)") in L[4]
    # summary.txt repeats the notes in the same order
    text = notify.summarize(dict(now, delta=dl))
    notes = [l for l in text.splitlines() if l.startswith("- note:") and "mail log in this run" in l]
    assert [n.split("'s mail log")[0].split()[-1] for n in notes] == ["example.org", "brand.example", "example.co.uk"]


# ------------------------------------------------------------------ the From domains an outside source fails as

def test_an_outside_source_names_every_from_domain_it_fails_as_the_busiest_first_a_tie_in_the_one_order(tmp_path):
    ip = "198.51.100.7"
    rua = {"failing_streams": [stream(ip, 120, ["zeta.example.org", "example.org", "a.shop.example.org"])],
           "by_source_ip": [by_source(ip, {"zeta.example.org": 40, "example.org": 40, "a.shop.example.org": 40})],
           "spf_only_senders": [{"source_ip": "192.0.2.30", "count": 50, "spf_only": 50, "spf_domains": ["y.example.org"],
                                 "header_from": ["mail.example.co.uk", "example.co.uk"]}]}
    rua["by_source_ip"].append(by_source("192.0.2.30", {"mail.example.co.uk": 25, "example.co.uk": 25}))
    report = {"generated_utc": "2026-10-09T06:00:00Z", "rua": rua,
              "findings": [{"id": "OUTSIDE-001", "severity": "major", "source": "rua"}],
              "gate": {"headline_domain": HEAD, "domains": {HEAD: {"verdict": "no_go"}}},
              "inputs": {"domains": [HEAD]}}
    doc = next_steps.build(report)
    want = "**198.51.100.7 - 120 failing messages as example.org, a.shop.example.org and 1 more**"
    assert any(l.startswith("- " + want) for l in doc["failing"]["lines"])
    item = [i for g in doc["actions_by_owner"] for i in g["items"] if i["kind"] == "stream"][0]
    assert item["hook"] == want.strip("*") and item["domains"] == ["example.org", "a.shop.example.org",
                                                                   "zeta.example.org"]
    todo = collect.render_todo(report, {"changes": [], "holds": []})
    assert "- aggregate reports: 198.51.100.7 fails 120/120 msgs as example.org, a.shop.example.org and 1 more (" in todo
    assert "- aggregate reports: 192.0.2.30 passes on SPF alone, 50 msgs as example.co.uk, mail.example.co.uk -" in todo
    # next_steps.json carries the words, for the brief's As column
    assert doc["failing"]["outside"][0]["as"] == "example.org, a.shop.example.org and 1 more"
    # the helper: the counts rank first, the busiest name leads whatever the one order says; a tie in the order
    assert audit.from_names(rua["failing_streams"][0]["header_from"], audit.from_counts(rua)[ip], HEAD) == (
        "example.org, a.shop.example.org and 1 more")
    assert audit.from_names(["example.org", "zeta.example.org"], {"zeta.example.org": 9, "example.org": 2}) == (
        "zeta.example.org, example.org")
    assert audit.from_names([], {}) == "" and audit.from_names(["a.example"], None) == "a.example"


# ------------------------------------------------------------------ senders ranked by a count: one tie key everywhere

TIED = ["app@zeta.example.org", "billing@example.co.uk", "ceo@brand.example", "hr@example.org", "info@e.example.com",
        "x@news.example.org"]


@pytest.fixture(scope="module")
def tied(tmp_path_factory):
    """Six senders under four organizations, five failures each, the mail log in plain text order; example.org,
    whose own senders sort last by address, is the headline."""
    tmp = tmp_path_factory.mktemp("tied")
    log = r11.Log()
    log.add("staff@example.org", "Weekly report #", times=20)
    for s in TIED:
        log.add(s, "Notice #", "fail", 5)
    names = ["example.org", "news.example.org", "zeta.example.org", "example.co.uk", "brand.example", "e.example.com"]
    rep = audit.build_report(domains=names, maillog=log.write(tmp / "maillog.csv"), offline=True, auth_column="DMARC",
                             domain_sources={d: ["cli"] for d in names}, headline=HEAD)
    return rep


def test_senders_tied_on_a_count_name_the_headlines_organization_first_in_every_file(tied):
    rep = tied
    head = ["hr@example.org", "x@news.example.org", "app@zeta.example.org"]
    want = head + ["ceo@brand.example", "billing@example.co.uk", "info@e.example.com"]
    view = next_steps.maillog_view(rep, HEAD)
    assert [s["name"] for s in view["by_sender"]] == want
    assert [s["name"] for s in view["ddf_senders"]] == want
    doc = next_steps.build(rep, None)
    assert "(hr@example.org x5, x@news.example.org x5, app@zeta.example.org x5)" in doc["stand"]["lines"][1]
    notes = next(l for l in doc["failing"]["lines"] if l.startswith("- Notes") and "@" in l)
    assert [n.split(" x")[0] for n in notes.split(": ", 1)[1].split(", ")] == want
    senders = [i["hook"].split(" - ")[0] for g in doc["actions_by_owner"] for i in g["items"] if i["kind"] == "sender"]
    assert senders[:3] == head
    # report.md's whole-log evidence (MAILFLOW-001) and the census, todo.md that quotes it, in the same order
    ev = next(f["evidence"] for f in rep["findings"] if f["id"] == "MAILFLOW-001")
    assert ev.split("; top senders: ")[1] == "; ".join("%s x5" % s for s in want[:5])
    md = audit.render_md(rep)
    census = section(md, "Failing senders (census)")
    by_sender = [l.split()[1] for l in census if l.startswith("  - ") and "(envelope" in l]
    assert by_sender == want[:audit.CENSUS_TOP]
    by_env = [l.split()[1].rstrip(":") for l in census if l.startswith("  - ") and "(envelope" not in l]
    assert by_env[:3] == ["example.org", "news.example.org", "zeta.example.org"]
    todo = collect.render_todo(rep, {"changes": [], "holds": []})
    assert "top senders: hr@example.org x5; x@news.example.org x5; app@zeta.example.org x5; " in todo
    # one domain's own top senders: by count, a tie by name, never by the row they came in
    assert audit.top_senders(Counter({"b@x.example": 2, "a@x.example": 2, "c@x.example": 3})) == [
        ("c@x.example", 3), ("a@x.example", 2), ("b@x.example", 2)]


def test_summary_txt_names_the_census_ties_next_steps_md_names():
    """census_top is called with the headline, and ranks a tie as next_steps.md's envelope list does: failures,
    then messages, then the one order."""
    census = {"by_envelope": [
        {"envelope_domain": d, "genuine_failures": 5, "messages": m}
        for d, m in (("x.example.net", 5), ("alpha.example", 5), ("brand.example", 5), ("example.org", 5),
                     ("news.example.org", 5), ("mail.brand.example", 9))]}
    rep = {"generated_utc": "2026-10-09T06:00:00Z", "inputs": {"domains": [HEAD, "brand.example"]},
           "gate": {"headline_domain": HEAD, "headline_source": "first on the command line",
                    "domains": {HEAD: {}, "brand.example": {}}},
           "maillog": {"counters": {"genuine_failures": 30}, "census": census}}
    text = notify.summarize(rep)
    line = next(l for l in text.splitlines() if l.startswith("- top failing senders (census):"))
    assert line == ("- top failing senders (census): mail.brand.example x5 (unknown), example.org x5 (unknown), "
                    "news.example.org x5 (unknown) (+3 more)")
    names = [e["name"] for e in next_steps.maillog_view(rep, HEAD)["by_envelope"]]
    assert names[:3] == ["mail.brand.example", "example.org", "news.example.org"]
    assert [x.split(" x")[0] for x in notify.census_top(census, 6, HEAD)[0]] == names


# ------------------------------------------------------------------ one table of two-label public suffixes

TW = ["z.brand.com.tw", "example.com", "a.example.com.tw", "brand.com.tw", "mail.example.com", "example.com.tw"]


def test_every_organization_is_named_by_the_suffix_table_the_dns_audit_uses():
    assert audit.order_domains(TW, "example.com.tw") == [
        "example.com.tw", "a.example.com.tw", "brand.com.tw", "z.brand.com.tw", "example.com", "mail.example.com"]
    for suffix in dns_audit.TWO_LEVEL_SUFFIXES:
        name = "a.b.example." + suffix
        want = dns_audit.org_domain(name)
        assert want == "example." + suffix
        assert discover.org_domain(name) == next_steps.org_domain(name) == plan_mod.org_domain(name) == want, suffix
        assert audit.domain_key(name)[1] == want
    assert discover.TWO_LEVEL == dns_audit.TWO_LEVEL_SUFFIXES
    # the status document: each row's organization, the headline's, never the public suffix
    rep = {"inputs": {"domains": TW}, "gate": {"headline_domain": "example.com.tw",
                                               "headline_source": "first on the command line",
                                               "domains": {d: {"verdict": "go"} for d in TW}}}
    assert next_steps.headline_org(rep) == "example.com.tw"
    rows = next_steps.per_domain(rep, None, "example.com.tw")
    assert [(r["domains"][0], r["org"]) for r in rows] == [
        ("example.com.tw", "example.com.tw"), ("a.example.com.tw", "example.com.tw"),
        ("brand.com.tw", "brand.com.tw"), ("z.brand.com.tw", "brand.com.tw"),
        ("example.com", "example.com"), ("mail.example.com", "example.com")]
