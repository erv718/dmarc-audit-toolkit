"""Round 12, the last pass: a name moves whole in a sentence and never breaks in a cell while it fits; an
own-system item quotes its own streams; a sender is new only when its address is; What is failing keeps
next_steps.md's order; invisible characters in names; the small wording items. Synthetic data only."""

import re

import audit
import brief
import next_steps

import test_r11_plan as T


def test_a_name_moves_whole_in_a_sentence_and_never_breaks_in_a_cell_while_it_fits():
    short, longer = "jacob.lastname@example.com", "vnx_apm00150816522_ops@mail.example.com"
    assert len(short) <= brief.NAME_KEEP < len(longer)
    assert brief.text_name(short) == '<span class="d">%s</span>' % short  # one piece: the line breaks before it
    moved = brief.text_name(longer)
    assert moved.startswith('<span class="d dl">') and moved.count("<wbr>") == 3  # breaks between labels only
    assert brief.plain_name(short).startswith('<span class="dn keep">')  # a cell never breaks it
    assert not brief.plain_name(longer).startswith('<span class="dn keep">')
    assert brief.name_html("dev.support.example.com").startswith('<span class="dn keep">')
    css = brief.CSS
    assert re.search(r"(?m)^\.d\.dl, \.count\.owner \{[^}]*display: inline-block;[^}]*max-width: 100%;", css)
    assert re.search(r"(?m)^\.dn\.keep \{ white-space: nowrap; \}", css)


def test_an_open_questions_owner_tag_moves_whole():
    doc = {"open_questions": [{"question": "Who owns this: example.org (P-01)?", "owner": "unassigned",
                               "kind": "unassigned"}]}
    sec = re.search(r'id="questions".*?</section>', brief.render(doc), re.S).group(0)
    assert '<span class="count owner">owner: unassigned</span>' in sec


def test_invisible_characters_are_marked_in_names_and_where_they_draw_nothing():
    cgj, zwj, rlm, vs16 = chr(0x034F), chr(0x200D), chr(0x200F), chr(0xFE0F)
    # a code point that draws nothing is marked everywhere: two addresses that differ by one never look alike
    assert brief.clean("ceo%s@example.com" % cgj) == "ceo[U+034F]@example.com"
    assert brief.marked(cgj) and brief.marked(chr(0x3164))
    # free text keeps what real mail needs: a joiner in an emoji, a direction mark, a variation selector
    assert brief.clean("party " + chr(0x1F468) + zwj + chr(0x1F469) + " heart" + chr(0x2764) + vs16) == \
        "party " + chr(0x1F468) + zwj + chr(0x1F469) + " heart" + chr(0x2764) + vs16
    assert brief.clean("shalom" + rlm) == "shalom" + rlm
    # a name has no use for any of them
    for ch in (zwj, rlm, vs16, chr(0x00AD)):
        assert "[U+%04X]" % ord(ch) in brief.plain_name("ce%so@example.com" % ch)
        assert "[U+%04X]" % ord(ch) in brief.text_name("ce%so@example.com" % ch)


def test_what_is_failing_keeps_next_steps_md_order_for_a_sentence_outside_the_lists():
    lines = ["No genuine failures in the mail log this run - every failing message had a passing copy.", "",
             "From the outside (aggregate reports; these counts include forwarded copies and cannot be deduplicated):",
             "- **203.0.113.5 - 300 failing messages as example.com** looks like spoofing"]
    doc = {"failing": {"lines": lines, "outside": [{"name": "203.0.113.5", "count": 300, "likely": "likely_spoof",
                                                    "as": "example.com", "dispositions": {"reject": 300}}]}}
    sec = re.search(r'id="failing".*?</section>', brief.render(doc), re.S).group(0)
    assert sec.index("No genuine failures in the mail log") < sec.index("From the outside")


def test_the_sources_of_the_aggregate_report_one_liner_part_with_semicolons():
    parts = [{"source": "198.51.100.7", "count": 110, "as": "example.org, a.shop.example.org and 1 more",
              "name": "198.51.100.7"}, {"source": "198.51.100.9", "count": 85, "as": "example.net", "name": "x"}]
    assert next_steps._named(parts) == ("198.51.100.7 x110 as example.org, a.shop.example.org and 1 more; "
                                        "198.51.100.9 x85 as example.net")
    assert next_steps._named([{"name": "a@example.com", "count": 5}, {"name": "b@example.com", "count": 4}]) == \
        "a@example.com x5, b@example.com x4"


def test_an_own_system_item_quotes_its_own_streams_never_the_spoof_one(tmp_path):
    docs = {"example.com": T.own_record("example.com", "v=DMARC1; p=quarantine; rua=%s;" % T.RUA)}
    log = (T.Log().add("ops@example.com", "Ops digest #", dmarc="fail", times=6)
           .add("ops@example.com", "Urgent wire transfer #", dmarc="fail", times=8, env="evil.invalid")
           .add("staff@example.com", "Weekly #", times=20))
    rep = T.audited(tmp_path / "run", docs, log, flows={"example.com": T.flow(20, 14)})
    doc = next_steps.build(rep, plan=T.plan_of(rep))
    items = [i for g in doc["actions_by_owner"] for i in g["items"] if str(i.get("hook", "")).startswith("ops@example.com")]
    own = [i for i in items if "DKIM-sign this sender" in i["action"] or "whose system" in i["action"]]
    assert own, items
    assert "Ops digest" in own[0]["action"] and "Urgent wire" not in own[0]["action"]
    assert "evil.invalid" not in own[0]["action"]


def _row(sender, env, n):
    return {"sender": sender, "domain": sender.rpartition("@")[2], "envelope_domain": env, "messages": n,
            "genuine_failures": n, "likely": "likely_misconfigured_sender", "sample_subject": "Digest"}


def test_a_sender_is_new_only_when_its_address_is():
    prev = {"generated_utc": "2026-10-05T06:00:00Z", "gate": {"domains": {}}, "findings": [],
            "maillog": {"counters": {"genuine_failures": 6, "delivered_despite_fail": 0},
                        "census": {"by_sender": [_row("ops@example.com", "example.com", 6)]}}}
    now = {"generated_utc": "2026-10-12T06:00:00Z", "gate": {"domains": {}}, "findings": [],
           "maillog": {"counters": {"genuine_failures": 16, "delivered_despite_fail": 0},
                       "census": {"by_sender": [_row("ops@example.com", "relay.vendor-two.invalid", 6),
                                                _row("new@example.com", "a.vendor.invalid", 6),
                                                _row("new@example.com", "b.vendor.invalid", 4)]}}}
    dl = audit.build_delta(now, prev)
    assert sorted({s["sender"] for s in dl["new_senders"]}) == ["new@example.com"]  # ops@ was seen before
    assert dl["gone_senders"] == []
