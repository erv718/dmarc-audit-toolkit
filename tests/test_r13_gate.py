"""Round 13, T-10: each domain's gate sees its own aggregate-report streams.

A failing or spoof-delivered stream holds the closest audited domain of each From domain it
carries (header_from), the way the mail-log rows and the SPF-only streams are attributed; only
a stream nothing attributes (no From domain under an audited name) holds every gate. The
per-domain table says what holds each gate ("not yet - held by: ...") and "no step left" at the
end of the road. Synthetic data, offline."""

import pytest

import audit
import brief
import next_steps
import r13_fixtures as F
import test_r11_plan as T

FOREIGN = ("198.51.100.20", "203.0.113.9")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_gate_estate"))


def blockers(rep, domain):
    return rep["gate"]["domains"][domain]["blockers"]


def test_each_gate_holds_only_the_streams_sent_as_it(run):
    rep = run["report"]
    for d in ("example.org", "parked.example", "brand.example", "dev.support.example.com", "events.example.com",
              "pay.example.com", "shop.example.com"):
        for b in blockers(rep, d):
            assert not any(ip in b for ip in FOREIGN), (d, b)
    com = " ".join(blockers(rep, "example.com"))
    assert "198.51.100.20 fails DMARC on 60/60 msgs" in com
    assert "spoof stream 203.0.113.66 (120 msgs) saw disposition none" in com
    assert "203.0.113.9" not in com
    assert any(b.startswith("spoof stream 203.0.113.9 (40 msgs)") for b in blockers(rep, "example.net"))
    assert not any("198.51.100.20" in b or "203.0.113.66" in b for b in blockers(rep, "example.net"))
    assert rep["gate"]["shared_blockers"] == []  # every stream here sends as an audited name


def test_a_domain_that_sends_nothing_is_no_longer_held_by_another_domains_streams(run):
    rep = run["report"]
    assert audit.ramp_blockers_left(rep, "example.org") == []
    # the quiet names' only hold is the gate's own: no rows about them, which the quarantine-now row answers
    for d in ("dev.support.example.com", "shop.example.com"):
        assert rep["gate"]["domains"][d]["verdict"] == "insufficient_data"
        assert blockers(rep, d)[0].startswith(audit.NO_ROWS_HOLD + d)
        assert audit.ramp_blockers_left(rep, d) == []


def test_the_ask_no_longer_names_another_domains_stream_for_example_com(run):
    ask = run["doc"]["ask"]
    assert "203.0.113.9" not in ask
    assert "198.51.100.20" not in ask or "example.com" in ask
    # round 13, T-11: the ask counts the step with the rows not for this week; what holds it is the step's own
    assert "3 not this week" in ask
    assert run["doc"]["next_step"]["holds"][0].startswith("spoofing source 203.0.113.66 (120 msgs)")


def test_the_overall_reasons_name_whose_stream_it_is(run):
    reasons = run["report"]["gate"]["reasons"]
    assert any(r.startswith("example.net: spoof stream 203.0.113.9") for r in reasons)
    assert any(r.startswith("example.com: 198.51.100.20 fails DMARC") for r in reasons)
    assert not any(r.startswith("spoof stream ") or r.startswith("198.51.100.20 ") for r in reasons)


def stream(ip, header_from, likely="likely_misconfigured", disp=None, n=50):
    return {"source_ip": ip, "count": n, "pass": 0, "fail": n, "header_from": list(header_from), "likely": likely,
            "dispositions": dict(disp or {"none": n}), "likely_signals": []}


def gate_of(streams, names=("example.com", "mail.example.com", "example.net")):
    docs = {d: T.own_record(d) for d in names}
    return audit.gate_verdict(docs, rua_of(streams), None, list(names))


def rua_of(streams):
    """A hand-built rua section with these failing streams (one report about example.com's record)."""
    rua = T.rua_doc("example.com", streams=streams)
    rua["totals"]["reports"] = 1
    return rua


def test_a_stream_with_no_from_domain_still_holds_every_gate():
    g = gate_of([stream("192.0.2.50", [])])
    for d in ("example.com", "mail.example.com", "example.net"):
        assert any(b.startswith("192.0.2.50 fails DMARC") for b in g["domains"][d]["blockers"]), d
    assert g["shared_blockers"] == [b for b in g["domains"]["example.net"]["blockers"] if "192.0.2.50" in b]
    # in the overall reasons it is said once, as every domain's
    assert any(r.startswith("192.0.2.50 fails DMARC") for r in g["reasons"])


def test_a_stream_whose_from_domain_is_not_ours_holds_every_gate_and_is_named_as_shared():
    g = gate_of([stream("192.0.2.51", ["(no header_from)"]), stream("192.0.2.52", ["other.invalid"]),
                 stream("192.0.2.53", ["example.net"])])
    for d in ("example.com", "mail.example.com", "example.net"):
        text = " ".join(g["domains"][d]["blockers"])
        assert "192.0.2.51" in text and "192.0.2.52" in text, d
    assert [b.split()[0] for b in g["shared_blockers"]] == ["192.0.2.51", "192.0.2.52"]
    assert "192.0.2.53" not in " ".join(g["domains"]["example.com"]["blockers"])


def test_a_stream_is_attributed_like_the_rows_audited_subdomain_unaudited_subdomain_and_two_domains():
    g = gate_of([stream("192.0.2.60", ["mail.example.com"]),          # an audited subdomain: its own gate only
                 stream("192.0.2.61", ["news.example.com"]),          # an unaudited one: its closest audited parent
                 stream("192.0.2.62", ["example.net", "example.com"]),  # two From domains: both homes
                 stream("203.0.113.70", ["example.net"], likely="likely_spoof")])  # a delivered spoof: its own
    text = {d: " ".join(g["domains"][d]["blockers"]) for d in g["domains"]}
    assert "192.0.2.60" in text["mail.example.com"] and "192.0.2.60" not in text["example.com"]
    assert "192.0.2.61" in text["example.com"] and "192.0.2.61" not in text["mail.example.com"]
    assert "192.0.2.62" in text["example.com"] and "192.0.2.62" in text["example.net"]
    assert "192.0.2.62" not in text["mail.example.com"]
    assert "spoof stream 203.0.113.70" in text["example.net"] and "203.0.113.70" not in text["example.com"]
    assert g["shared_blockers"] == []
    assert audit.stream_homes({"header_from": ["Mail.Example.COM."]}, ["example.com", "mail.example.com"]) == \
        ["mail.example.com"]
    assert audit.stream_homes({"header_from": "example.com"}, ["example.com"]) == []  # a damaged value: nobody's


def test_an_excepted_stream_holds_nothing_wherever_it_sends_and_the_rest_keep_their_homes():
    docs = {d: T.own_record(d) for d in ("example.com", "example.net")}
    rua = rua_of([stream("192.0.2.80", ["example.net"]), stream("192.0.2.81", ["example.net"])])
    exc = [{"match": "192.0.2.80", "reason": "vendor migrating", "until": "2099-01-01",
            "removal_criterion": "DKIM aligned"}]
    g = audit.gate_verdict(docs, rua, None, ["example.com", "example.net"], exceptions=exc)
    assert not any("192.0.2.80 fails" in b for d in g["domains"] for b in g["domains"][d]["blockers"])
    assert g["exceptions"]["excepted_streams"] == ["192.0.2.80"]
    assert any("192.0.2.81 fails" in b for b in g["domains"]["example.net"]["blockers"])
    assert not any("192.0.2.81" in b for b in g["domains"]["example.com"]["blockers"])
    assert g["shared_blockers"] == []


def table_row(doc, domain):
    md = next_steps.render_md(doc)
    return next(l for l in md.splitlines() if l.startswith("| `%s`" % domain))


def test_the_gate_cell_says_what_holds_each_domain(run):
    doc = run["doc"]
    assert ("| `example.com` | p=quarantine | not yet - held by: spoofing source 203.0.113.66 (120 msgs) saw "
            "disposition none... |") in table_row(doc, "example.com")
    assert "| not yet - held by: spoofing source 203.0.113.9 (40 msgs) saw disposition none -... |" in \
        table_row(doc, "example.net")
    # a quarantine-now row: the gate's hold is the weekly ramp's, and the cell says so
    assert "| needs more data (for the weekly ramp this skips) |" in table_row(doc, "shop.example.com")
    # a DNS finding that holds it by what it is, then its id - never a bare id (review round 13)
    assert "| not yet - held by: no DMARC record (DMARC-001) (for the weekly ramp this skips) |" in \
        table_row(doc, "example.org")
    # not yet on every row no longer: the words differ where the holds differ
    gates = {g["gate_text"] for g in doc["per_domain"]}
    assert len(gates) >= 6 and "not yet" not in gates


def test_a_held_by_text_is_cut_at_a_word_and_never_inherits_a_shared_blocker():
    rep = {"gate": {"domains": {"example.com": {
        "verdict": "no_go", "next_step": "move to p=quarantine at pct=25",
        "blockers": ["192.0.2.90 fails DMARC on 50/50 msgs (unknown); fix, or formally except it, before p= moves",
                     "example.com: 12 logical message(s) from this domain failed with no passing copy (deduplicated)"],
        "notes": []}},
        "shared_blockers": ["192.0.2.90 fails DMARC on 50/50 msgs (unknown); fix, or formally except it, before p= "
                            "moves"]}}
    text = next_steps.gate_words(rep, "example.com", "no_go", "move to p=quarantine at pct=25")
    assert text == "not yet - held by: 12 logical messages from this domain failed with no passing..."
    assert len(text.split("held by: ", 1)[1]) <= next_steps.HELD_BY_CUT + 3
    rep["gate"]["shared_blockers"] = []
    assert next_steps.gate_words(rep, "example.com", "no_go").startswith("not yet - held by: 192.0.2.90 fails DMARC")
    assert next_steps.gate_words(rep, "example.com", "go") == "ready"
    assert next_steps.gate_words(rep, "example.com", None) == "not checked"


def test_no_step_left_at_the_end_of_the_road(tmp_path):
    docs = {"brand.example": T.own_record("brand.example", "v=DMARC1; p=reject; sp=reject; rua=%s;" % T.RUA)}
    log = (T.Log().add("team@brand.example", "Brand update #", times=20)
           .add("hr@brand.example", "Your password expires today #", dmarc="fail", times=4, env="lure.invalid"))
    rep = T.audited(tmp_path, docs, log, flows={"brand.example": T.flow(50, 90)})
    g = rep["gate"]["domains"]["brand.example"]
    assert g["next_step"].startswith(next_steps.AT_END_STEP) and g["verdict"] == "no_go"
    doc = next_steps.build(rep)
    row = doc["per_domain"][0]
    assert row["gate_text"] == "no step left (not yet)"
    cell = brief.gate_cell(row["gate"], row["gate_text"])
    assert cell == '<span class="pill warn">no step left</span><span class="rest">(not yet)</span>'


def test_the_brief_cell_keeps_the_pill_and_mutes_what_holds_it():
    cell = brief.gate_cell("no_go", "not yet - held by: 9 logical messages from this domain failed")
    assert cell.startswith('<span class="pill warn">not yet</span><span class="rest">held by: 9 logical')
    assert brief.gate_cell("insufficient_data", "needs more data (for the weekly ramp this skips)").startswith(
        '<span class="pill info">needs data</span><span class="rest">(for the weekly ramp this skips)')
    assert brief.gate_cell("go", "ready") == '<span class="pill ok">go</span>'
