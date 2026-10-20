"""Round 13, T-07 and T-08: delivered counts and labels that match the evidence, and override fixes in a safe
order.

T-07: each stream's deliveries go with that stream's label, never with every label its address has; the
one-liner says what let delivered failures in ("16 let in by an Exchange transport rule; 16 delivered because
p=none lets failing mail through"); a spoof label resting on a weak sign (no lure word: plan.lure) is "could
be our own vendors", never spoofing; What is failing gives an address one row per label group; a spoof with a
lure word that reached a mailbox is never only a note; no owner item folds one sender into "1 more sender".
Synthetic data, offline."""

import re

import pytest

import brief
import next_steps
import plan as plan_mod
import r13_fixtures as F

OWN, SPOOF = next_steps.OWN, next_steps.SPOOF


@pytest.fixture(scope="module")
def first(tmp_path_factory):
    return F.first_run(tmp_path_factory.mktemp("r13_labels_first"), F.FR_RUA)


@pytest.fixture(scope="module")
def incident(tmp_path_factory):
    return F.incident(tmp_path_factory.mktemp("r13_labels_incident"))


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    return F.estate(tmp_path_factory.mktemp("r13_labels_estate"))


def test_the_first_run_lede_says_what_let_each_failure_in_and_that_vendors_could_be_ours(first):
    line = first["doc"]["one_liner"]
    assert ("48 that could be our own vendors (called spoofing on the envelope or a billing word alone: "
            "news@harborfoods.example x32, payroll@harborfoods.example x16), of which 32 reached a mailbox anyway (16 "
            "let in by an Exchange transport rule; 16 delivered because p=none lets failing mail through)") in line
    assert "12 from 2 addresses that look like spoofing, which p=none does not stop yet" in line
    # never "none from our own senders" while failures that could be our own vendors are in the count
    assert "none from our own senders" not in line
    assert "a local override delivered them" not in line  # the log recorded the overrides: it says which
    assert next_steps.WEAK_SIGN == plan_mod.WEAK_SPOOF_SIGN


def test_the_incident_spoof_clause_counts_no_delivery_of_our_own(incident):
    line = incident["doc"]["one_liner"]
    assert "65 from 1 of our own senders (hr@example.com x65)" in line
    assert ("14 that could be our own vendors (called spoofing on the envelope or a billing word alone: "
            "payroll@example.com x14), of which 4 reached a mailbox anyway (4 let in by a user's safe sender list)") in line
    # the lures: CEO fraud and the HR password lure under the HR address, none of them delivered
    assert "32 from 2 addresses that look like spoofing and are being handled by the policy" in line
    assert "31 reached a mailbox" not in line and "27 reached" not in line


def test_an_address_failing_under_two_labels_is_two_rows(incident):
    rows = [(e["name"], e["count"], e["likely"], e.get("envelope")) for e in incident["doc"]["failing"]["by_sender"]
            if e["name"] == "hr@example.com"]
    assert rows == [("hr@example.com", 65, OWN, "hrmail.example.com"), ("hr@example.com", 12, SPOOF, "lure-mail.invalid")]
    md = next_steps.render_md(incident["doc"])
    assert ('- **hr@example.com - 65 messages** looks like our own system misconfigured (envelope hrmail.example.com; '
            'subjects like "Your pay statement is ready (') in md
    assert ('- **hr@example.com - 12 messages** looks like spoofing (envelope lure-mail.invalid; subjects like "Your '
            'password expires today') in md
    # the brief's table follows the split: two rows, one per label
    page = brief.render(incident["doc"], incident["plan"])
    table = re.search(r'<table class="list snd">.*?</table>', page, re.S).group(0)
    labels = re.findall(r'<td class="name"><span class="dn[^"]*">(?:<span>[^<]*</span>)+</span></td>'
                        r'<td class="num">(\d+)</td><td>([^<]+)</td>', table)
    hr = [(n, label) for n, label in labels if n in ("65", "12")]
    assert hr == [("65", "looks like our own system misconfigured"), ("12", "looks like spoofing")]


def test_a_delivered_lure_under_ten_is_never_only_a_note(estate):
    md = next_steps.render_md(estate["doc"])
    senders = md.split("By sender address", 1)[1].split("\n\n", 1)[0]
    reached = [l for l in senders.splitlines() if l.startswith("- " + next_steps.REACHED_LINE)]
    assert reached == [
        '- Reached inboxes despite failing (under 10, never a note): **ceo@example.com - 7 messages** looks like '
        'spoofing (envelope evil.invalid; subjects like "Urgent wire transfer 78") - 7 reached a mailbox',
        '- Reached inboxes despite failing (under 10, never a note): **hr@brand.example - 4 messages** looks like '
        'spoofing (envelope lure.invalid; subjects like "Your password expires today 230") - 4 reached a mailbox']
    notes = next(l for l in senders.splitlines() if l.startswith("- Notes, not headlines"))
    assert "ceo@example.com" not in notes and "hr@brand.example" not in notes
    # a weak-sign spoof that reached a mailbox stays a note: billing@example.com (an invoice from a vendor envelope)
    assert "billing@example.com x5 (looks like spoofing)" in notes
    page = brief.render(estate["doc"], estate["plan"])
    table = re.search(r'<table class="list snd">.*?</table>', page, re.S).group(0)
    assert table.count('<tr class="reached">') == 2 and "reached inboxes: 7" in table
    assert '<span class="subject">"<bdi>Urgent wire transfer 78</bdi>"</span>' in table  # quoted as data
    note = page.split('<table class="list snd">', 1)[1].split("</div>", 2)[1]
    assert "ceo@example.com" not in re.sub(r"<[^>]+>", "", note.split("Notes, not headlines", 1)[-1][:400])


def test_deliveries_go_with_the_stream_that_had_them():
    view = {"by_sender": [{"name": "hr@example.com", "count": 77, "domain": "example.com",
                           "likely_counts": {OWN: 65, SPOOF: 12}, "likely": OWN}],
            "parts": next_steps.sender_parts([
                {"sender": "hr@example.com", "domain": "example.com", "envelope_domain": "hrmail.example.com",
                 "genuine_failures": 65, "likely": OWN, "likely_counts": {OWN: 65}, "excepted": 0,
                 "delivered_despite_fail": 27, "delivered_by": {"org: Exchange transport rule (Allow)": 27},
                 "sample_subject": "Your pay statement is ready"},
                {"sender": "hr@example.com", "domain": "example.com", "envelope_domain": "lure-mail.invalid",
                 "genuine_failures": 12, "likely": SPOOF, "likely_counts": {SPOOF: 12}, "excepted": 0,
                 "delivered_despite_fail": 0, "delivered_by": {}, "sample_subject": "Your password expires today"}])}
    senders = next_steps._by_address(view["by_sender"], {"hr@example.com": 27}, parts=view["parts"])
    groups = next_steps._groups(senders)
    assert [(e["count"], e["delivered"]) for e in groups[OWN]] == [(65, 27)]
    assert [(e["count"], e["delivered"], e["weak"], e["strong_dlv"]) for e in groups[SPOOF]] == [(12, 0, 0, 0)]
    assert next_steps._part(senders, (SPOOF,))[0]["delivered"] == 0
    assert next_steps._part(senders, (OWN,))[0]["by"] == {"org: Exchange transport rule (Allow)": 27}


def test_what_let_them_in_is_said_with_the_counts():
    split = next_steps.delivered_split
    by = {"org: Exchange transport rule (Allow)": 16}
    assert split(32, by, True, "none") == ("16 let in by an Exchange transport rule; 16 delivered because p=none lets "
                                           "failing mail through")
    assert split(20, by, True, "quarantine") == ("16 let in by an Exchange transport rule; 4 with no override recorded "
                                                 "(the log names nothing that let them in)")
    assert split(12, None, False, "quarantine") == "a local override delivered them, not the policy"  # no columns
    assert split(6, None, False, "none") == "6 delivered because p=none lets failing mail through"
    assert split(4, {"user: Safe senders list (Allow)": 4}, True, "quarantine") == "4 let in by a user's safe sender list"


def test_no_owner_item_folds_one_sender_into_one_more(estate, tmp_path):
    items = [i for g in estate["doc"]["actions_by_owner"] for i in g["items"]]
    assert not any(re.match(r"^1 more ", i["hook"]) for i in items)
    hooks = [i["hook"] for i in items if i["kind"] == "override"]
    assert "hr@brand.example - 4 messages reached inboxes despite failing" in hooks  # the sixth, named
    # two past the cap still fold, with their count
    log = F.T.Log()
    for k in range(next_steps.TOP_ENTRIES + 2):
        log.add("s%d@example.com" % k, "Notice #", dmarc="fail", times=k + 2, env="example.com")
    rep = F.T.audited(tmp_path, {"example.com": F.T.own_record("example.com")}, log)
    hooks = [i["hook"] for g in next_steps.build(rep)["actions_by_owner"] for i in g["items"] if i["kind"] == "override"]
    assert hooks[-1] == "2 more senders with 5 messages that reached inboxes despite failing"


# ------------------------------------------------------------------ T-08: override fixes in a safe order

def override_items(doc):
    return {i["hook"].split(" - ")[0]: i["action"] for g in doc["actions_by_owner"] for i in g["items"]
            if i["kind"] == "override"}


def test_an_override_that_lets_our_own_mail_in_goes_after_the_sender_passes(first, incident):
    fr = override_items(first["doc"])
    assert fr["payroll@harborfoods.example"] == (
        "delivered because of an Exchange transport rule: after payroll@harborfoods.example passes DMARC, make that "
        "rule conditional on authentication - doing it first junks these 16 too; outside receivers do not have it")
    inc = override_items(incident["doc"])
    assert inc["hr@example.com"] == (
        "delivered because of an Exchange transport rule: after hr@example.com passes DMARC, make that rule "
        "conditional on authentication - doing it first junks these 27 too; outside receivers do not have it")
    assert inc["payroll@example.com"] == (
        "delivered because of a user's safe sender list: after payroll@example.com passes DMARC, ask the mailbox "
        "owners to take the sender off their safe sender lists - doing it first junks these 4 too; outside receivers "
        "do not have it")
    for text in list(fr.values()) + list(inc.values()):
        assert "find that rule and make it conditional" not in text


def test_a_lure_an_override_let_in_keeps_the_do_it_now_fix(tmp_path):
    log = (F.O.Log(overrides=True).add("staff@example.com", "Weekly #", 20)
           .add("ceo@example.com", "Urgent wire transfer #", 3, env="evil.invalid", dmarc="fail", org=F.TRANSPORT_RULE)
           .add("hr@example.com", "Your pay statement #", 4, env="example.com", dmarc="fail", spf="pass",
                org=F.TRANSPORT_RULE))
    rep = F.T.audited(tmp_path, {"example.com": F.T.dns_doc("example.com", dmarc=F.IN_APEX,
                                                           dmarc_source="_dmarc.example.com",
                                                           effective_policy="quarantine", dmarc_status="found")}, log)
    items = override_items(next_steps.build(rep))
    assert items["ceo@example.com"] == ("delivered because of an Exchange transport rule: find that rule and make it "
                                        "conditional on authentication; outside receivers do not have it")
    assert items["hr@example.com"].startswith("delivered because of an Exchange transport rule: after hr@example.com "
                                              "passes DMARC, make that rule conditional on authentication - doing it "
                                              "first junks these 4 too")


def test_without_the_override_columns_our_own_mail_still_goes_first(estate):
    items = override_items(estate["doc"])
    assert items["noreply@example.com"] == (
        "find the override (transport rule, allow list, safe sender) that let them in; after noreply@example.com passes "
        "DMARC, make it conditional on authentication - doing it first junks these 12 too; outside receivers do not "
        "have it")
    # the lures keep the do-it-now words
    assert items["ceo@example.com"] == ("find the override (transport rule, allow list, safe sender) that let them in "
                                        "and make it conditional on authentication; outside receivers do not have it")
    assert items["hr@brand.example"] == items["ceo@example.com"]


def test_the_safe_order_reads_the_label_of_the_mail_delivered(incident):
    view = next_steps.maillog_view(incident["report"])
    by = {s["name"]: s for s in view["ddf_senders"]}
    assert next_steps.ours_delivered(view, by["hr@example.com"]) == 27  # the own stream's, never the lure's
    assert next_steps.ours_delivered(view, by["payroll@example.com"]) == 4  # a weak sign: could be our vendor
    assert next_steps.override_action({"org: Exchange transport rule (Allow)": 3}, 3, True, "quarantine") == (
        "delivered because of an Exchange transport rule: find that rule and make it conditional on authentication; "
        "outside receivers do not have it")
