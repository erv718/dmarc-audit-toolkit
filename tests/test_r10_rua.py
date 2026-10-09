"""Round 10, aggregate reports: the per-IP unknown-sender check runs only on
listed IP prefixes, OUTSIDE-002 counts each message once, the Slack line
follows the check, and the docs say what known and vendor_domains do.
Synthetic reports (example.com, *.invalid, documentation IPs); no network."""

import contextlib
import io
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import config
import notify
import rua_parse

ROOT = Path(__file__).resolve().parent.parent


def record(ip, n, dkims=(), spfs=(), dkim_eval="fail", spf_eval="fail"):
    d = "".join("<dkim><domain>%s</domain><selector>%s</selector><result>%s</result></dkim>" % x for x in dkims)
    s = "".join("<spf><domain>%s</domain><scope>mfrom</scope><result>%s</result></spf>" % x for x in spfs)
    return ("<record><row><source_ip>%s</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition>"
            "<dkim>%s</dkim><spf>%s</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from>"
            "</identifiers><auth_results>%s%s</auth_results></record>" % (ip, n, dkim_eval, spf_eval, d, s))


def write_report(folder, *records):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "report.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>reporter.invalid</org_name>'
        "<email>reports@example.com</email><report_id>r10</report_id><date_range><begin>1790000000</begin>"
        "<end>1790086399</end></date_range></report_metadata><policy_published><domain>example.com</domain>"
        "<adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published>"
        + "".join(records) + "</feedback>", encoding="utf-8")
    return folder


def clean(tmp_path):
    """Every source with volume passes DMARC: our own platform, and a vendor that
    signs d=example.com and its own d=vendor.invalid; a spoof under the floor."""
    return write_report(tmp_path / "clean",
                        record("203.0.113.10", 500, [("example.com", "s1", "pass")], [("example.com", "pass")],
                               "pass", "pass"),
                        record("203.0.113.11", 300, [("example.com", "vs1", "pass"), ("vendor.invalid", "v1", "pass")],
                               [("vendor.invalid", "pass")], "pass", "fail"),
                        record("198.51.100.7", 10, (), [("spoof.invalid", "fail")]))


def analyse(paths, **kw):
    with contextlib.redirect_stderr(io.StringIO()):
        doc, _ = rua_parse.analyse([str(p) for p in (paths if isinstance(paths, list) else [paths])], **kw)
    return doc


def ids(doc):
    return sorted(f["id"] for f in doc["findings"])


def finding(doc, fid):
    return next((f for f in doc["findings"] if f["id"] == fid), None)


def flat(text):
    return " ".join(text.split())


def test_d12_a_domain_only_known_list_does_not_run_the_per_ip_check(tmp_path):
    """Listed domains name platforms, not networks: like the vendors they narrow
    the signing-domain list and inform the labels, and the per-IP check waits
    for IP prefixes, so the tenant's own passing sources are never 'not in
    --known'."""
    rua = clean(tmp_path)
    vend = analyse(rua, vendors=["vendor.invalid"])
    for known in ("vendor.invalid", "example.com,vendor.invalid"):
        doc = analyse(rua, known=known)
        assert finding(doc, "OUTSIDE-002") is None and doc["exit_code"] == vend["exit_code"] == 0
        assert ids(doc) == ids(vend) == ["OUTSIDE-009"]
        kn = doc["filters"]["known"]
        assert kn["given"] is True and kn["ip_check"] is False and kn["networks"] == []
        title = finding(doc, "OUTSIDE-009")["title"]
        assert title.startswith("known list has no IP prefixes: per-IP unknown-sender check not run")
        assert all(s["known"] is None for s in doc["by_source_ip"])
        assert not any(u["kind"] == "dkim_domain" for u in doc["unknown_senders"])  # the listed domain still narrows
    both = analyse(rua, known="vendor.invalid,203.0.113.0/24")
    assert both["filters"]["known"]["ip_check"] is True and both["exit_code"] == 0 and ids(both) == []
    assert {s["source_ip"]: s["known"] for s in both["by_source_ip"]} == {
        "203.0.113.10": True, "203.0.113.11": True, "198.51.100.7": False}
    # the hint's two routes ("--known or the settings' vendors") now give the same findings and exit code
    hint = write_report(tmp_path / "hint",
                        record("203.0.113.10", 500, [("example.com", "s1", "pass")], [("example.com", "pass")],
                               "pass", "pass"),
                        record("203.0.113.11", 300, [("example.com", "vs1", "fail")], [("vendor.invalid", "pass")]))
    via_known, via_vendors = analyse(hint, known="vendor.invalid"), analyse(hint, vendors=["vendor.invalid"])
    assert [f["likely"] for f in via_known["failing_streams"]] == ["likely_misconfigured"]
    assert ids(via_known) == ids(via_vendors) and via_known["exit_code"] == via_vendors["exit_code"]
    assert finding(via_known, "OUTSIDE-002") is None


def test_c45_outside002_counts_each_message_once_with_its_dmarc_result(tmp_path):
    known = "esp.invalid,203.0.113.0/24"
    crm = record("198.51.100.30", 30, [("crm.invalid", "c1", "pass")], [("crm.invalid", "pass")])
    mix = analyse(write_report(tmp_path / "mix",
                               record("203.0.113.10", 700, [("example.com", "esp1", "pass")],
                                      [("bounce.esp.invalid", "pass")], "pass", "fail"),
                               record("198.51.100.20", 40, [("example.com", "esp1", "fail")],
                                      [("bounce.esp.invalid", "pass")]),
                               record("203.0.113.66", 60, (), [("example.com", "fail")]), crm), known=known)
    f = finding(mix, "OUTSIDE-002")
    assert f["title"] == ("2 unknown sender(s) with volume, not in --known: 0 msgs passing, 70 failing; "
                          "1 signing domain(s) not in --known: 30 signatures verified, 0 not")
    assert "ip 198.51.100.30 x30 (0 pass)" in f["evidence"]
    assert "dkim_domain crm.invalid x30 (30 verified)" in f["evidence"]
    # the message clause is the ground truth: the unknown sources' own DMARC totals, each message once
    outside = [s for s in mix["by_source_ip"] if s["known"] is False]
    assert sum(s["pass"] for s in outside) == 0 and sum(s["fail"] for s in outside) == 70
    # two foreign signatures on the same 30 messages: 30 messages, 60 signatures, never 60 passing messages
    two = analyse(write_report(tmp_path / "two", record("198.51.100.30", 30, [("crm.invalid", "c1", "pass"),
                                                                              ("mailer.invalid", "m1", "pass")],
                                                        [("crm.invalid", "pass")])), known=known)
    assert finding(two, "OUTSIDE-002")["title"] == (
        "1 unknown sender(s) with volume, not in --known: 0 msgs passing, 30 failing; "
        "2 signing domain(s) not in --known: 60 signatures verified, 0 not")
    # a DMARC pass on aligned SPF that also carries a foreign signature: 50 passing messages, not 100
    passing = analyse(write_report(tmp_path / "pass", record("198.51.100.40", 50, [("crm.invalid", "c1", "pass")],
                                                             [("example.com", "pass")], "fail", "pass")), known=known)
    assert "not in --known: 50 msgs passing, 0 failing;" in finding(passing, "OUTSIDE-002")["title"]
    # a failing foreign signature does not double the failures
    failing = analyse(write_report(tmp_path / "fail", record("198.51.100.50", 25, [("crm.invalid", "c1", "fail")],
                                                             [("crm.invalid", "fail")])), known=known)
    assert finding(failing, "OUTSIDE-002")["title"] == (
        "1 unknown sender(s) with volume, not in --known: 0 msgs passing, 25 failing; "
        "1 signing domain(s) not in --known: 0 signatures verified, 25 not")
    # a listed source that signs as an unlisted platform: the signing-domain clause alone
    inside = analyse(write_report(tmp_path / "inside", record("203.0.113.20", 40, [("example.com", "s1", "pass"),
                                                                                  ("crm.invalid", "c1", "pass")],
                                                              [("example.com", "pass")], "pass", "pass")), known=known)
    assert finding(inside, "OUTSIDE-002")["title"] == (
        "1 signing domain(s) with volume, not in --known: 40 signatures verified, 0 not")


def test_c45_the_cli_footnote_says_where_a_signers_messages_are_counted(tmp_path):
    """The unknown-sender table's footnote: dkim_domain rows count signatures.
    It says the ip rows already count those messages only where they do: with
    the per-IP check on, a signer sending from inside the known prefixes has
    no ip row (the ESP double-signing shape, as on the shipped samples)."""
    signer = write_report(tmp_path / "signer",
                          record("203.0.113.20", 40, [("example.com", "s1", "pass"), ("crm.invalid", "c1", "pass")],
                                 [("example.com", "pass")], "pass", "pass"),
                          record("198.51.100.30", 30, [("crm.invalid", "c1", "pass")], [("crm.invalid", "pass")]))
    runs = [(signer, None), (signer, "esp.invalid"), (signer, "esp.invalid,203.0.113.0/24"),
            (ROOT / "samples" / "rua", None), (ROOT / "samples" / "rua", "192.0.2.0/24")]
    notes = []
    for path, known in runs:
        with contextlib.redirect_stderr(io.StringIO()):
            doc, agg = rua_parse.analyse([str(path)], known=known)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rua_parse.print_report(doc, agg)
        note = [l.strip() for l in out.getvalue().splitlines() if l.strip().startswith("dkim_domain rows count")]
        ip_rows = {u["value"] for u in doc["unknown_senders"] if u["kind"] == "ip"}
        signers = [u for u in doc["unknown_senders"] if u["kind"] == "dkim_domain"]
        assert signers and len(note) == 1, (path, known)
        counted = all(set(u["source_ips"]) <= ip_rows for u in signers)
        assert counted is not doc["filters"]["known"]["ip_check"], (path, known)
        notes.append((path, known, note[0], counted))
    for path, known, note, counted in notes:  # the claim is made exactly where it is true
        assert ("already count" in note) is counted, (path, known, note)
    for path, known, note, counted in notes:
        assert "count signatures (pass = verified), not messages" in note
        if not counted:
            assert "in an ip row only when they came from outside the known prefixes" in note


def test_d13_an_ip_prefix_among_the_vendors_is_ignored_with_a_warning(tmp_path):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        doc, _ = rua_parse.analyse([str(clean(tmp_path))], vendors=["vendor.invalid", "203.0.113.0/24"])
    kn = doc["filters"]["known"]
    assert kn["domains"] == ["vendor.invalid"] and kn["networks"] == [] and kn["ip_check"] is False
    assert any("203.0.113.0/24 is an IP prefix, not a domain: ignored" in w for w in doc["warnings"])
    assert "warning: vendor domain 203.0.113.0/24 is an IP prefix" in err.getvalue()
    assert all(s["known"] is None for s in doc["by_source_ip"])  # a vendor prefix never runs the per-IP check
    assert ids(doc) == ["OUTSIDE-009"]


def test_d13_the_docs_say_what_known_and_vendor_domains_do(tmp_path):
    step2 = flat((ROOT / "README.md").read_text(encoding="utf-8").split("## Step 2", 1)[1].split("## Step 3", 1)[0])
    assert "`known` and `vendor_domains`: your vendors' domains and IP prefixes" not in step2
    known = step2.split("- `known`:", 1)[1].split(" - `", 1)[0]
    assert "runs only on the IP prefixes" in known and "Domains alone only narrow the signing-domain list" in known
    vendors = step2.split("- `vendor_domains`:", 1)[1].split(" - `", 1)[0]
    # only a run that reads aggregate reports warns about a prefix: the README promises no more than that
    assert "ignored with a warning" not in vendors and "a run that reads aggregate reports warns about it" in vendors
    assert "Domains only" in vendors and "IP prefixes go in `known`" in vendors
    assert "mail log and in the aggregate reports" in vendors and "never switch the unknown-sender check on" in vendors
    assert "they narrow the signing-domain list" in vendors
    # the example settings: the comments say the same, and the values follow them
    lines = (ROOT / "audit.example.toml").read_text(encoding="utf-8").splitlines()

    def comment_above(key):
        i = next(n for n, l in enumerate(lines) if l.startswith(key + " ="))
        block = []
        while i > 0 and lines[i - 1].startswith("#"):
            i -= 1
            block.insert(0, lines[i].lstrip("# "))
        return " ".join(block)

    assert "runs only on the IP prefixes" in comment_above("known")
    vend = comment_above("vendor_domains")
    assert "mail log" in vend and "aggregate reports" in vend
    assert "never the unknown-sender check" not in vend  # they do narrow its signing-domain half
    assert "narrow the signing-domain list" in vend and "never switch the unknown-sender check on" in vend
    cfg = config.load(str(ROOT / "audit.example.toml"))
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        doc, _ = rua_parse.analyse([str(clean(tmp_path))], known=",".join(config.audit_list(cfg, "known")),
                                   vendors=config.audit_list(cfg, "vendor_domains"))
    assert doc["filters"]["known"]["ip_check"] is True and doc["warnings"] == [] and "warning" not in err.getvalue()
    # what both say, as behaviour: a vendor narrows the signing-domain half of a check that the prefixes
    # in known switch on, and alone it never switches the check on
    signer = write_report(tmp_path / "signer", record("198.51.100.30", 30, [("crm.invalid", "c1", "pass")],
                                                      [("crm.invalid", "pass")]))
    checked = analyse(signer, known="203.0.113.0/24")
    narrowed = analyse(signer, known="203.0.113.0/24", vendors=["crm.invalid"])
    alone = analyse(signer, vendors=["crm.invalid"])
    assert "; 1 signing domain(s) not in --known: 30 signatures verified" in finding(checked, "OUTSIDE-002")["title"]
    assert "signing domain" not in finding(narrowed, "OUTSIDE-002")["title"]
    assert narrowed["filters"]["known"]["ip_check"] is True and alone["filters"]["known"]["ip_check"] is False
    assert finding(alone, "OUTSIDE-002") is None
    assert not any(u["kind"] == "dkim_domain" for u in narrowed["unknown_senders"] + alone["unknown_senders"])


def test_d14_slack_names_unknown_senders_only_when_the_per_ip_check_ran(tmp_path):
    rua = clean(tmp_path)
    line = "unknown senders in reports"
    for kw in ({}, {"vendors": ["vendor.invalid"]}, {"known": "vendor.invalid"}):
        doc = analyse(rua, **kw)
        assert doc["unknown_senders"] and line not in notify.summarize({"rua": doc}), kw
    ran = analyse(rua, known="vendor.invalid,203.0.113.0/24")
    assert "- unknown senders in reports: 1 (top: ip 198.51.100.7)" in notify.summarize({"rua": ran})
    # a report from before filters.known.ip_check: the check ran when it listed networks
    unk = [{"kind": "ip", "value": "198.51.100.7", "count": 10}]
    for known, shown in (({"given": True, "networks": ["203.0.113.0/24"], "domains": []}, True),
                         ({"given": True, "networks": [], "domains": ["vendor.invalid"]}, False),
                         ({"given": False, "networks": [], "domains": []}, False)):
        text = notify.summarize({"rua": {"totals": {"messages": 10}, "unknown_senders": unk,
                                         "filters": {"known": known}}})
        assert (line in text) is shown, known
    for odd in ("x", {"known": "x"}, {"known": {"ip_check": "yes"}}, None):  # odd shapes read as not run
        assert line not in notify.summarize({"rua": {"totals": {"messages": 10}, "unknown_senders": unk,
                                                     "filters": odd}})
    assert notify.ip_check_ran(None) is False and notify.ip_check_ran([]) is False


def test_d16_a_domain_only_known_list_behaves_like_the_vendors_on_the_samples():
    """The round-9 vendors test's sibling: a known list holding only a domain
    leaves the per-IP check off on samples/rua; one with a prefix runs it."""
    samples = ROOT / "samples" / "rua"
    plain, vend = analyse(samples), analyse(samples, vendors=["platform.example"])
    dom = analyse(samples, known="platform.example")
    assert all(s.get("known") is None for s in dom["by_source_ip"])
    assert ids(dom) == ids(plain) == ids(vend)
    assert finding(dom, "OUTSIDE-002") is None and dom["exit_code"] == plain["exit_code"]
    both = analyse(samples, known="platform.example,192.0.2.0/24")
    assert both["filters"]["known"]["ip_check"] is True
    assert all(isinstance(s["known"], bool) for s in both["by_source_ip"])
    assert any(s["known"] for s in both["by_source_ip"]) and not all(s["known"] for s in both["by_source_ip"])
    assert finding(both, "OUTSIDE-002") is not None and finding(both, "OUTSIDE-009") is None


def test_d16_settings_known_with_a_domain_keeps_an_all_passing_run_clean(tmp_path):
    """collect.py end to end: [audit] known holding only a domain, on reports and a
    mail log where everything passes, exits 0 with no OUTSIDE-002 and no
    unknown-sender line in the summary, exactly as vendor_domains would."""
    rua = clean(tmp_path)
    rows = ["Email date (UTC),Internet message ID,Sender address,Sender domain,Sender mail from domain,Recipients,"
            "Subject,Delivery action,Latest delivery location,DMARC"]
    rows += ["2026-09-20 08:%02d:00,<own%04d@mail.example.com>,noreply@example.com,example.com,example.com,"
             "user%d@example.com,Statement,Delivered,Inbox/folder,pass" % (i, i, i) for i in range(40)]
    maillog = tmp_path / "maillog.csv"
    maillog.write_text("\n".join(rows) + "\n", encoding="utf-8")
    env = dict(os.environ, SLACK_WEBHOOK_URL="", TEAMS_WEBHOOK_URL="", RUA_MAILBOX="")
    for name, setting in (("known", 'known = ["vendor.invalid"]'), ("vendors", 'vendor_domains = ["vendor.invalid"]')):
        cfg = tmp_path / ("%s.toml" % name)
        cfg.write_text('[audit]\ndomains = ["example.com"]\n%s\n' % setting, encoding="utf-8")
        out = tmp_path / ("out_%s" % name)
        p = subprocess.run([sys.executable, str(ROOT / "src" / "collect.py"), "--config", str(cfg), "--offline",
                            "--no-notify", "--no-owners", "--rua", str(rua), "--maillog", str(maillog),
                            "--auth-column", "DMARC", "--out", str(out)], capture_output=True, text=True, env=env,
                           timeout=300)
        assert p.returncode == 0, (name, p.stderr)
        report = json.loads((out / "latest" / "report.json").read_text(encoding="utf-8"))
        assert not any(f.get("id") == "OUTSIDE-002" for f in report["findings"]), name
        assert report["rua"]["filters"]["known"]["ip_check"] is False
        assert "unknown senders in reports" not in (out / "latest" / "summary.txt").read_text(encoding="utf-8")


def test_c39_the_relabel_needs_every_domain_the_signal_names_and_the_docs_say_so():
    s = {"count": 400, "no_auth": 0, "aligned_dkim_failed": 400, "misaligned_spf": 400, "misaligned_dkim": 0,
         "dkim_failed": 400, "header_from": {"a.example.com": 400}, "reasons": Counter(),
         "spf": {("platform.example", "mfrom", "pass"): 390, ("relay.example", "mfrom", "pass"): 10},
         "dkim": {("a.example.com", "s1", "fail"): 400}}
    label, signals = rua_parse.likely_label(s, {"example.com"})
    hint = next(x for x in signals if "broken DKIM key: if" in x)
    assert label == "unknown" and "if platform.example and relay.example send for us, list them under --known" in hint
    label, signals = rua_parse.likely_label(s, {"example.com"}, known_domains=["platform.example"])
    hint = next(x for x in signals if "broken DKIM key: if" in x)
    assert label == "unknown" and "if relay.example sends for us, list it under --known" in hint
    assert rua_parse.likely_label(s, {"example.com"},
                                  known_domains=["platform.example", "relay.example"])[0] == "likely_misconfigured"
    readme = flat((ROOT / "README.md").read_text(encoding="utf-8"))
    entry = readme.split("**One of your own platforms shows as `unknown` in the aggregate reports**", 1)[1]
    entry = entry.split(" - **", 1)[0].split("## ", 1)[0]
    assert "list its domain among the vendors" not in entry
    assert "list every one of them" in entry and "relabels only once all of them are listed" in entry
    assert "names any still missing" in entry
