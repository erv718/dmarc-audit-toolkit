"""next_steps.py: the stakeholder document from the bundled offline sample,
from a DNS-bearing synthetic report with a plan, and from degraded inputs.
Every number in the markdown must trace back to report.json or plan.json.
No network."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import audit
import next_steps
import plan

ROOT = Path(__file__).resolve().parent.parent
OWNERS = ROOT / "samples" / "owners.csv.example"
HEADINGS = ["## Where we stand (", "## What is failing", "## Per domain",
            "## What happens next, by owner", "## The ask", "## Open questions"]
DASHES = [chr(c) for c in range(0x2010, 0x2016)]  # hyphen, dashes and bar: never in the output
# numbers the template itself carries: the 30-day window and the under-10 headline rule
TEMPLATE_NUMBERS = {"30", str(next_steps.HEADLINE_MIN)}
no_root_owners = pytest.mark.skipif((ROOT / next_steps.DEFAULT_OWNERS).is_file(),
                                    reason="a private owners.csv at the repo root would be read")


def run_cli(*argv):
    return subprocess.run([sys.executable, str(ROOT / "src" / "next_steps.py"), *argv],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)


def dump(obj, path):
    path.write_text(json.dumps(obj, indent=1), encoding="utf-8")
    return path


def owners():
    return next_steps.read_owners(OWNERS)


def numbers_in(text):
    return set(re.findall(r"\d+(?:\.\d+)*", text))


PATH_RX = re.compile(r'"(?:[A-Za-z]:\\\\|/)[^"\n]*"')  # a quoted absolute path in report.json


def check_numbers(md, report, corpus_texts):
    """Every number token in the markdown occurs, as a whole token, in one of
    the input files. The input paths are blanked first: a digit in a temp
    folder's name is not evidence. Two figures are derived rather than
    copied: the pass rate as a percentage, and the mail log's span, which
    next_steps computes from the window's own stamps."""
    corpus = "\n".join(PATH_RX.sub('""', t) for t in corpus_texts)
    allowed = set(TEMPLATE_NUMBERS)
    rate = ((report.get("rua") or {}).get("totals") or {}).get("pass_rate")
    if rate is not None:
        allowed.add("%.1f" % (100 * rate))
    ml = report.get("maillog") or {}
    for window in [ml.get("window"), *(ml.get("window_by_domain") or {}).values()]:
        phrase = next_steps.span_phrase(window)
        if phrase:
            allowed |= numbers_in(phrase)
    missing = sorted(t for t in numbers_in(md) if t not in allowed
                     and not re.search(r"(?<![\d.])%s(?![\d.])" % re.escape(t), corpus))
    assert not missing, "numbers in next_steps.md with no source in the inputs: %s" % missing


def headings_in_order(md):
    positions = [md.index(h) for h in HEADINGS]
    assert positions == sorted(positions)
    assert md.count("\n## ") == len(HEADINGS)


def dns_doc(domain, **over):
    base = {"domain": domain, "spf": "v=spf1 include:mail.example -all", "spf_status": "found",
            "spf_terminator": "-all", "spf_lookups": 1, "spf_lookups_failed": 0, "spf_verified": True,
            "dmarc": None, "dmarc_source": None, "effective_policy": None, "inherited": False,
            "dmarc_status": "absent", "dkim_selectors": ["selector1"], "dkim_status": "found",
            "mx": ["10 mail.example"], "mx_null": False, "mx_status": "found", "flags": [], "findings": [],
            "evidence": []}
    base.update(over)
    return base


def minimal_report(subject):
    """The smallest report the generator accepts, with one failing own sender."""
    verdict = {"sender": "crm@example.com", "domain": "example.com", "envelope_domain": "example.com",
               "subject": subject, "genuine_failure": True, "likely": "likely_misconfigured_sender",
               "delivered_despite_fail": False, "echo_present": False, "blocked_despite_pass": False}
    step = "move to p=quarantine at a low pct (for example pct=10)"
    return {"generated_utc": "2026-01-08T06:00:00Z", "tool": "audit.py", "inputs": {"domains": ["example.com"]},
            "gate": {"verdict": "no_go", "current_policy": "none", "next_step": step,
                     "evidence": {"statement": "failure evidence supplied"},
                     "domains": {"example.com": {"verdict": "no_go", "current_policy": "none",
                                                 "policy_source": "live DNS (example.com)", "next_step": step,
                                                 "reasons": ["example.com: 2 logical message(s) from this domain "
                                                             "failed with no passing copy (deduplicated)"]}}},
            "findings": [], "dns": None, "rua": None, "headers": None,
            "maillog": {"counters": {"genuine_failures": 2, "raw_failing_rows": 3, "raw_rows": 5,
                                     "logical_messages": 4, "delivered_despite_fail": 0,
                                     "blocked_despite_pass": 0, "echo_messages": 1,
                                     "by_likely": {"likely_spoof": 0, "likely_misconfigured_sender": 2,
                                                   "unknown": 0}},
                        "auth_column": "DMARC", "verdicts": [dict(verdict), dict(verdict)]}}


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    """The bundled offline sample (aggregate reports and mail log, no headers)."""
    out = tmp_path_factory.mktemp("sample")
    rep = audit.build_report(domains=["example.com"], rua_paths=["samples/rua"],
                             maillog="samples/sample_maillog.csv", offline=True, auth_column="DMARC",
                             domain_sources={"example.com": ["cli"]})
    return {"report": rep, "path": dump(rep, out / "report.json"), "dir": out}


@pytest.fixture(scope="module")
def planned(tmp_path_factory, sample):
    """The sample plus a hand-written DNS section (p=quarantine pct=25 and an
    inheriting subdomain), the gate recomputed over it, and plan.py's plan."""
    out = tmp_path_factory.mktemp("planned")
    rep = json.loads(json.dumps(sample["report"]))
    rec = "v=DMARC1; p=quarantine; sp=none; pct=25; rua=mailto:reports@example.com;"
    finding = {"id": "DMARC-002", "severity": "minor", "area": "dmarc", "title": "inherits p=none from example.com",
               "evidence": "no _dmarc record of its own", "action": "publish a record", "verified": True}
    rep["dns"] = {
        "example.com": dns_doc("example.com", dmarc=rec, dmarc_source="example.com",
                               effective_policy="quarantine", dmarc_status="found"),
        "news.example.com": dns_doc("news.example.com", dmarc=rec, dmarc_source="example.com", inherited=True,
                                    effective_policy="none", dmarc_status="found", findings=[finding]),
    }
    domains = ["example.com", "news.example.com"]
    rep["inputs"]["domains"] = domains
    rep["gate"] = audit.gate_verdict(rep["dns"], rep["rua"], rep["maillog"], domains, None, {},
                                     {d: ["cli"] for d in domains})
    rep["findings"] = audit.reword_for_reject(audit.flatten_findings(rep), rep["gate"])
    rep["summary"].update(gate=rep["gate"]["verdict"], next_step=rep["gate"]["next_step"])
    rep["verified_vs_inferred"] = audit.verified_vs_inferred(rep)
    pl = plan.build_plan(rep)
    return {"report": rep, "plan": pl, "path": dump(rep, out / "report.json"),
            "plan_path": dump(pl, out / "plan.json"), "dir": out}


@pytest.fixture(scope="module")
def headers_only(tmp_path_factory):
    """A run with header files only: no mail log, no aggregate reports."""
    out = tmp_path_factory.mktemp("headers_only")
    rep = audit.build_report(domains=["example.com"], header_files=["samples/headers"], offline=True,
                             domain_sources={"example.com": ["cli"]})
    return {"report": rep, "path": dump(rep, out / "report.json"), "dir": out}


# ------------------------------------------------------------------ the sample document

def test_sample_document_has_the_template_shape(sample, tmp_path):
    p = run_cli(str(sample["path"]), "--owners", str(OWNERS), "--out", str(tmp_path))
    assert p.returncode == 0, p.stderr
    assert p.stdout.splitlines() == ["wrote %s" % (tmp_path / "next_steps.md"), "wrote %s" % (tmp_path / "next_steps.json")]
    md = (tmp_path / "next_steps.md").read_text(encoding="utf-8")
    doc = json.loads((tmp_path / "next_steps.json").read_text(encoding="utf-8"))
    rep = sample["report"]
    day = rep["generated_utc"][:10]
    assert md.startswith("# DMARC rollout - status and next steps, %s\n" % day)
    headings_in_order(md)
    assert doc["one_liner"].startswith("example.com is at p=reject.")  # the org domain and its policy
    assert "**%s**" % doc["one_liner"] in md
    assert (doc["org_domain"], doc["policy"]["p"], doc["date"]) == ("example.com", "reject", day)
    assert set(doc) >= {"tool", "version", "date", "org_domain", "policy", "next_step", "one_liner", "stand",
                        "failing", "per_domain", "actions_by_owner", "ask", "open_questions", "glossary", "sources"}
    c = rep["maillog"]["counters"]
    assert "- **Genuine failures: %d** (raw counts would say %d - the gap is relay echoes" % (
        c["genuine_failures"], c["raw_failing_rows"]) in md
    assert "- **Delivered despite failing: %d**" % c["delivered_despite_fail"] in md
    disp = rep["rua"]["totals"]["by_disposition"]
    assert "- **Mail refused or quarantined by receivers under our policy: %d rejected / %d quarantined**" % (
        disp.get("reject", 0), disp.get("quarantine", 0)) in md
    assert "- **Trend: first run, no trend yet**" in md
    # at p=reject no policy step is left: the cell says so, the gate's word after it (round 13, T-10)
    assert "| `example.com` | p=reject | no step left (not yet) |" in md
    assert doc["ask"].startswith("Nothing to approve this week: example.com is at p=reject")
    assert md.rstrip().endswith("it is not a failure.") and "Glossary. DMARC is " in md
    assert "no sentence here was written by an AI" in md


def test_every_number_in_the_sample_document_comes_from_the_inputs(sample):
    md = next_steps.render_md(next_steps.build(sample["report"], owners=owners(), owners_path=OWNERS))
    check_numbers(md, sample["report"], [sample["path"].read_text(encoding="utf-8"),
                                         OWNERS.read_text(encoding="utf-8")])
    assert len(numbers_in(md)) > 15  # the check saw real content


def test_under_ten_senders_are_notes_not_headlines(sample):
    rep = sample["report"]
    md = next_steps.render_md(next_steps.build(rep, owners=owners(), owners_path=OWNERS))
    env = [e for e in rep["maillog"]["census"]["by_envelope"] if e["genuine_failures"]]
    assert env and any(e["genuine_failures"] >= next_steps.HEADLINE_MIN for e in env)
    assert any(e["genuine_failures"] < next_steps.HEADLINE_MIN for e in env)
    for e in env:
        hook = "- **%s - %d message" % (e["envelope_domain"], e["genuine_failures"])
        if e["genuine_failures"] >= next_steps.HEADLINE_MIN:
            assert hook in md
        else:
            assert hook not in md
            assert "%s x%d (" % (e["envelope_domain"], e["genuine_failures"]) in md
    assert "- Notes, not headlines (under %d each): " % next_steps.HEADLINE_MIN in md
    # raw row counts appear only in the one marked place
    assert md.count("raw counts would say") == 1


# ------------------------------------------------------------------ with a plan

def test_with_a_plan_the_next_step_and_ids_come_from_the_plan(planned, tmp_path):
    p = run_cli(str(planned["path"]), "--plan", str(planned["plan_path"]), "--owners", str(OWNERS),
                "--out", str(tmp_path))
    assert p.returncode == 0, p.stderr
    md = (tmp_path / "next_steps.md").read_text(encoding="utf-8")
    doc = json.loads((tmp_path / "next_steps.json").read_text(encoding="utf-8"))
    headings_in_order(md)
    ratchet = plan.next_step_for(planned["plan"], "example.com")
    assert ratchet["kind"] == "ratchet" and "pct=50" in ratchet["value"]
    monitor = next(c for c in planned["plan"]["changes"] if c["domain"] == "news.example.com")
    assert monitor["kind"] == "new" and monitor["priority"] == 1
    assert doc["one_liner"].startswith("example.com is at p=quarantine, pct=25.")
    assert "The next safe step is to raise pct to 50, ready when " in doc["one_liner"]
    assert doc["next_step"]["ref"] == ratchet["id"] and doc["next_step"]["source"] == "plan"
    assert doc["next_step"]["prerequisites"]  # the plan's holds, reworded as conditions
    # the Gate cell names what holds the step (round 13, T-10): the gate's first blocker, cut short
    assert ("| `example.com` | p=quarantine, pct=25 | not yet - held by: 1 sender pass on SPF alone (190 msgs): set "
            "up aligned DKIM... | raise pct to 50 (plan %s) |" % ratchet["id"]) in md
    assert ("| `news.example.com` | p=none (inherited from example.com) | needs more data | "
            "publish a p=none monitoring record (plan %s) |" % monitor["id"]) in md
    assert ratchet["human_summary"] in md  # the plan's plain-language sentence rides along
    assert "- **1 zero-risk monitoring record** ready to publish (plan %s)" % monitor["id"] in md
    assert doc["ask"].startswith("The ask this week: approval to publish the 1 zero-risk record (plan %s)"
                                 % monitor["id"])
    assert any(q["kind"] == "prerequisite" and q["ref"] == ratchet["id"] for q in doc["open_questions"])
    assert doc["sources"]["plan"] is True and doc["sources"]["plan_changes"] == len(planned["plan"]["changes"])
    assert "rollout plan (%d changes, 0 holds)" % len(planned["plan"]["changes"]) in md
    check_numbers(md, planned["report"], [planned["path"].read_text(encoding="utf-8"),
                                          planned["plan_path"].read_text(encoding="utf-8"),
                                          OWNERS.read_text(encoding="utf-8")])


def test_org_name_and_date_overrides(planned):
    p = run_cli(str(planned["path"]), "--plan", str(planned["plan_path"]), "--owners", str(OWNERS),
                "--org-name", "news.example.com", "--date", "2026-01-01", "--json")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)
    assert doc["date"] == "2026-01-01" and doc["org_domain"] == "news.example.com"
    assert doc["one_liner"].startswith("news.example.com is at p=none.")
    assert "The next safe step is to publish a p=none monitoring record, and it is ready now." in doc["one_liner"]


# ------------------------------------------------------------------ owners

def test_unassigned_group_holds_everything_without_owners_and_clears_with_them(sample, tmp_path):
    rep = sample["report"]
    empty = tmp_path / "empty.csv"
    empty.write_text("pattern,owner,channel,note\n", encoding="utf-8")
    bare = next_steps.build(rep, owners=next_steps.read_owners(empty), owners_path=empty)
    groups = bare["actions_by_owner"]
    assert [g["owner"] for g in groups] == [next_steps.UNASSIGNED] and groups[0]["items"]
    assert "- **Unassigned - needs an owner**" in next_steps.render_md(bare)
    assert {q["owner"] for q in bare["open_questions"]} == {"unassigned"}
    assert sum(1 for q in bare["open_questions"] if q["kind"] == "unassigned") == len(groups[0]["items"])

    owned = next_steps.build(rep, owners=owners(), owners_path=OWNERS)
    names = [g["owner"] for g in owned["actions_by_owner"]]
    assert next_steps.UNASSIGNED not in names
    assert names == ["Statements platform team", "DNS and messaging team"]  # the owners file's order
    by_owner = {g["owner"]: g for g in owned["actions_by_owner"]}
    st = by_owner["Statements platform team"]
    assert st["channel"] == "#billing-systems"
    assert all(i["matched_by"] == "statements@example.com" for i in st["items"])
    assert {i["ref"] for i in st["items"]} == {"MAILFLOW-001", "MAILFLOW-002"}
    assert all(i["matched_by"] == "example.com" for i in by_owner["DNS and messaging team"]["items"])
    assert sum(len(g["items"]) for g in owned["actions_by_owner"]) == len(groups[0]["items"])
    md = next_steps.render_md(owned)
    assert next_steps.UNASSIGNED not in md and "(owner: unassigned)" not in md
    assert "- **Statements platform team** (#billing-systems)" in md
    assert "  - **statements@example.com - 3 messages** DKIM-sign this sender" in md
    assert "owners file owners.csv.example (3 patterns)" in md


@no_root_owners
def test_no_owners_file_falls_back_to_unassigned_with_a_note(sample, tmp_path):
    p = run_cli(str(sample["path"]), "--out", str(tmp_path))
    assert p.returncode == 0, p.stderr
    assert "note: no owners file - every action is under 'Unassigned - needs an owner'" in p.stderr
    doc = json.loads((tmp_path / "next_steps.json").read_text(encoding="utf-8"))
    assert doc["sources"]["owners_file"] is None and doc["sources"]["owner_patterns"] == 0
    assert [g["owner"] for g in doc["actions_by_owner"]] == [next_steps.UNASSIGNED]
    assert "no owners file (everything is unassigned)" in doc["sources"]["audience_line"]
    md = (tmp_path / "next_steps.md").read_text(encoding="utf-8")
    assert "- **Unassigned - needs an owner**" in md and "Who owns this: " in md


def test_owner_patterns_match_address_then_domain_then_glob(tmp_path):
    rows = owners()
    assert [(r["kind"], r["owner"]) for r in rows] == [
        ("address", "Statements platform team"), ("domain", "DNS and messaging team"), ("glob", "Marketing operations")]
    assert next_steps.match_owner(rows, "statements@example.com")["owner"] == "Statements platform team"
    assert next_steps.match_owner(rows, "other@example.com", "example.com")["owner"] == "DNS and messaging team"
    assert next_steps.match_owner(rows, "news.example.com")["owner"] == "DNS and messaging team"
    assert next_steps.match_owner(rows, "bounce.esp.example")["owner"] == "Marketing operations"
    assert next_steps.match_owner(rows, "vendor.example") is None
    assert next_steps.match_owner(rows, "", None) is None
    longest = [{"pattern": "example.com", "kind": "domain", "owner": "apex", "channel": "", "note": ""},
               {"pattern": "sub.example.com", "kind": "domain", "owner": "sub", "channel": "", "note": ""}]
    assert next_steps.match_owner(longest, "deep.sub.example.com")["owner"] == "sub"
    # header case, comment rows and rows without an owner are tolerated
    csv_path = tmp_path / "owners.csv"
    csv_path.write_text("Pattern,Owner,Channel,Note\n# a comment,x,,\nfoo.example,,,\n"
                        "Bar.Example,Team B,#b,note\n", encoding="utf-8")
    assert next_steps.read_owners(csv_path) == [
        {"pattern": "bar.example", "kind": "domain", "owner": "Team B", "channel": "#b", "note": "note"}]
    bad = tmp_path / "bad.csv"
    bad.write_text("who,what\nx,y\n", encoding="utf-8")
    with pytest.raises(next_steps.UsageError):
        next_steps.read_owners(bad)


# ------------------------------------------------------------------ hyphens only

def test_output_never_carries_a_dash_other_than_a_hyphen(sample):
    doc = next_steps.build(sample["report"], owners=owners(), owners_path=OWNERS)
    md, js = next_steps.render_md(doc), json.dumps(doc)
    assert not [d for d in DASHES if d in md or d in js]
    assert js.isascii()
    # a dash smuggled in through a subject line is normalised on the way out
    doc = next_steps.build(minimal_report("Quarterly review " + chr(0x2014) + " agenda"))
    md = next_steps.render_md(doc)
    assert "Quarterly review - agenda" in md
    assert not [d for d in DASHES if d in md or d in json.dumps(doc)]
    assert doc["one_liner"].startswith("example.com is at p=none. Across all audited domains, 1 of our own "
                                       "senders still fails (crm@example.com x2).")


# ------------------------------------------------------------------ errors and degraded inputs

def test_missing_report_exits_2_without_a_traceback(sample, tmp_path):
    p = run_cli(str(tmp_path / "missing.json"))
    assert p.returncode == 2 and not p.stdout
    assert p.stderr.startswith("error: cannot read report") and "Traceback" not in p.stderr
    p = run_cli(str(tmp_path))
    assert p.returncode == 2 and "is a directory, expected a JSON file" in p.stderr
    broken = tmp_path / "broken.json"
    broken.write_text('{"gate": ', encoding="utf-8")
    p = run_cli(str(broken))
    assert p.returncode == 2 and "is not valid JSON" in p.stderr and "Traceback" not in p.stderr
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}', encoding="utf-8")
    p = run_cli(str(other))
    assert p.returncode == 2 and "does not look like an audit report" in p.stderr
    p = run_cli(str(sample["path"]), "--metrics", str(other))
    assert p.returncode == 2 and "expected a JSON array, got dict" in p.stderr
    p = run_cli(str(sample["path"]), "--owners", str(tmp_path / "nope.csv"))
    assert p.returncode == 2 and "cannot read owners file" in p.stderr and "Traceback" not in p.stderr
    p = run_cli(str(sample["path"]), "--plan", str(tmp_path / "nope" / "plan.json"))
    assert p.returncode == 2 and "cannot read --plan" in p.stderr


def test_document_degrades_gracefully_without_a_mail_log(headers_only, tmp_path):
    rep = headers_only["report"]
    assert rep["maillog"] is None and rep["rua"] is None
    doc = next_steps.build(rep, owners=owners(), owners_path=OWNERS)
    lines = doc["stand"]["lines"]
    assert lines[0].startswith("**Genuine failures: not in this run** - no mail log was read")
    assert any(l.startswith("**Mail refused or quarantined by receivers: outside view not in this run**") for l in lines)
    assert lines[-1] == "**Trend: first run, no trend yet**"
    assert doc["stand"]["genuine_failures"] is None and doc["stand"]["spoofing_blocked"] is None
    assert doc["failing"]["lines"] == ["Not in this run: no mail log and no aggregate reports were read, "
                                       "so nothing here can say what is failing."]
    assert doc["failing"]["streams"] is None and doc["failing"]["basis"] is None
    assert "No mail-log evidence in this run" in doc["one_liner"]
    assert doc["per_domain"][0]["domains"] == ["example.com"]
    md = next_steps.render_md(doc)
    headings_in_order(md)
    assert "raw counts would say" not in md
    p = run_cli(str(headers_only["path"]), "--owners", str(OWNERS), "--out", str(tmp_path))
    assert p.returncode == 0 and "Traceback" not in p.stderr, p.stderr
    assert (tmp_path / "next_steps.md").read_text(encoding="utf-8") == md


def test_reports_only_run_keeps_the_outside_view():
    rep = audit.build_report(domains=["example.com"], rua_paths=["samples/rua"], offline=True,
                             domain_sources={"example.com": ["cli"]})
    assert rep["maillog"] is None and rep["rua"]
    doc = next_steps.build(rep, owners=owners(), owners_path=OWNERS)
    lines = doc["stand"]["lines"]
    assert lines[0].startswith("**Genuine failures: not in this run**")
    disp = rep["rua"]["totals"]["by_disposition"]
    assert lines[1].startswith("**Mail refused or quarantined by receivers under our policy: %d rejected / %d quarantined**"
                               % (disp.get("reject", 0), disp.get("quarantine", 0)))
    assert doc["failing"]["streams"]["basis"] == "aggregate reports"
    assert "(from the aggregate reports)" in doc["one_liner"]
    assert doc["failing"]["lines"][0].startswith("From the outside (aggregate reports;")


def test_unknown_policy_is_not_presented_as_a_ready_step(headers_only):
    doc = next_steps.build(headers_only["report"])
    assert doc["policy"]["p"] is None
    assert "ready now" not in doc["one_liner"]
    assert "unknown - no DMARC policy determined" not in doc["one_liner"]
    assert "go-ahead to unknown" not in doc["ask"]


# ------------------------------------------------------------------ trend and history

def test_previous_report_gives_the_trend_line(sample, tmp_path):
    rep = sample["report"]
    prev = json.loads(json.dumps(rep))
    prev["generated_utc"] = "2026-09-22T06:00:00Z"
    prev["maillog"]["counters"]["genuine_failures"] = rep["maillog"]["counters"]["genuine_failures"] + 4
    prev["rua"]["totals"]["pass_rate"] = rep["rua"]["totals"]["pass_rate"] - 0.05
    ppath = dump(prev, tmp_path / "previous.json")
    doc = next_steps.build(rep, previous=prev, previous_path=ppath)
    now_gf, now_pr = rep["maillog"]["counters"]["genuine_failures"], rep["rua"]["totals"]["pass_rate"]
    expected = "**Trend vs 2026-09-22: -4 genuine failures (%d -> %d), +5.0 pts pass rate (%.1f%% -> %.1f%%)**" % (
        now_gf + 4, now_gf, 100 * (now_pr - 0.05), 100 * now_pr)
    assert expected in doc["stand"]["lines"]
    assert doc["sources"]["trend_source"] == "previous report"
    assert doc["sources"]["previous_report"] == "2026-09-22T06:00:00Z"
    p = run_cli(str(sample["path"]), "--previous", str(ppath), "--owners", str(OWNERS))
    assert p.returncode == 0, p.stderr
    assert expected in p.stdout and "previous report 2026-09-22" in p.stdout


def test_metrics_history_gives_policy_since_and_the_trend(sample, tmp_path):
    rep = sample["report"]
    gf, pr = rep["maillog"]["counters"]["genuine_failures"], rep["rua"]["totals"]["pass_rate"]
    metrics = [
        {"run": "2026-09-15T06:00:00Z", "domains": {"example.com": {"policy": "quarantine"}},
         "genuine_failures": gf + 9, "rua_pass_rate": pr - 0.1, "rua_messages": 900},
        {"run": "2026-09-22T06:00:00Z", "domains": {"example.com": {"policy": "reject"}},
         "genuine_failures": gf + 2, "rua_pass_rate": pr, "rua_messages": 1000},
    ]
    mpath = dump(metrics, tmp_path / "metrics.json")
    doc = next_steps.build(rep, metrics=metrics)
    assert doc["policy"]["since"] == "2026-09-22"
    assert doc["one_liner"].startswith("example.com is at p=reject since 2026-09-22.")
    assert "**Trend vs 2026-09-22: -2 genuine failures (%d -> %d), +0.0 pts pass rate" % (gf + 2, gf) in doc["stand"]["lines"][-1]
    assert doc["sources"]["trend_source"] == "metrics" and doc["sources"]["metrics_runs"] == 2
    p = run_cli(str(sample["path"]), "--metrics", str(mpath), "--owners", str(OWNERS), "--json")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["policy"]["since"] == "2026-09-22"


# ------------------------------------------------------------------ determinism and output modes

def test_reruns_are_byte_identical_and_json_flag_prints_the_document(sample, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        p = run_cli(str(sample["path"]), "--owners", str(OWNERS), "--out", str(d))
        assert p.returncode == 0, p.stderr
    for name in ("next_steps.md", "next_steps.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes()
        assert b"\r\n" not in (a / name).read_bytes()  # LF on every platform
    p = run_cli(str(sample["path"]), "--owners", str(OWNERS), "--json")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == json.loads((a / "next_steps.json").read_text(encoding="utf-8"))
    p = run_cli(str(sample["path"]), "--owners", str(OWNERS))
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith("# DMARC rollout - status and next steps, ")
    assert p.stdout.strip() == (a / "next_steps.md").read_text(encoding="utf-8").strip()


def test_the_org_follows_the_gate_headline_not_the_alphabet():
    names = ["aaa.example", "example.com", "news.example.com"]
    rep = {"inputs": {"domains": list(names)}, "gate": {}}
    assert next_steps.pick_org(rep) == "aaa.example"  # no headline in the report: the old fallback
    rep["gate"] = {"headline_domain": "example.com", "domains": {d: {} for d in names}}
    assert next_steps.pick_org(rep) == "example.com"
    rep["gate"]["headline_domain"] = "news.example.com"  # a subdomain headline maps to its audited apex
    assert next_steps.pick_org(rep) == "example.com"
    # ...but not to an apex seen only in the reports: the audited headline itself leads
    only = {"inputs": {"domains": ["news.example.com"]},
            "gate": {"headline_domain": "news.example.com", "domains": {"news.example.com": {}}},
            "rua": {"totals": {"domains": ["example.com", "news.example.com"]}}}
    assert next_steps.pick_org(only) == "news.example.com"
    assert next_steps.pick_org(rep, org_name="Other.Example.") == "other.example"


def test_the_org_stays_on_a_member_when_the_apex_has_no_rows_of_its_own():
    rep = {"inputs": {"domains": ["mail.org.example", "org.example"]}, "maillog": {"by_domain": {}},
           "gate": {"headline_domain": "mail.org.example",
                    "domains": {"org.example": {"maillog_rows": 0}, "mail.org.example": {"maillog_rows": 900}}}}
    assert next_steps.pick_org(rep) == "mail.org.example"
    rep["gate"]["domains"]["org.example"]["maillog_rows"] = 12
    assert next_steps.pick_org(rep) == "org.example"


def test_an_old_reports_weak_headline_is_reranked_by_passing_mail():
    rep = {"inputs": {"domains": ["chosen.example", "busy.example"],
                      "domain_sources": {"chosen.example": ["tenant"], "busy.example": ["tenant"]}},
           "gate": {"headline_domain": "chosen.example", "headline_source": "shortest audited apex",
                    "domains": {"chosen.example": {}, "busy.example": {}}},
           "maillog": {"by_domain": {"chosen.example": {"logical_messages": 3, "genuine_failures": 0},
                                     "busy.example": {"logical_messages": 900, "genuine_failures": 10}}}}
    assert next_steps.pick_org(rep) == "busy.example"


def test_a_typed_subdomain_stays_the_subject():
    rep = {"inputs": {"domains": ["mail.corp.example", "corp.example"]},
           "maillog": {"auth_column": "DMARC",
                       "by_domain": {"corp.example": {"logical_messages": 1, "genuine_failures": 1,
                                                      "passing_messages": 0, "internal_messages": 0}}},
           "gate": {"headline_domain": "mail.corp.example", "headline_source": "first on the command line",
                    "domains": {"corp.example": {"maillog_rows": 1}, "mail.corp.example": {"maillog_rows": 62}}}}
    assert next_steps.pick_org(rep) == "mail.corp.example"
    # a headline the volume rule chose is settled: the gate picked the member of the busiest family
    rep["gate"]["headline_source"] = "most internal mail"
    rep["maillog"]["by_domain"]["corp.example"]["internal_messages"] = 40
    assert next_steps.pick_org(rep) == "mail.corp.example"
    # a label that skipped the in-family rule maps to the apex only when the apex sends mail of its own
    rep["gate"]["headline_source"] = "tenant default domain"
    assert next_steps.pick_org(rep) == "corp.example"  # 40 internal messages: internal mail is its own too
    rep["maillog"]["by_domain"]["corp.example"]["internal_messages"] = 0  # only the one spoof is left
    assert next_steps.pick_org(rep) == "mail.corp.example"


def test_an_old_report_is_reranked_by_family_not_by_apex_alone():
    names = ["aaa.example", "dom.example", "m.dom.example", "zz.example"]
    rep = {"inputs": {"domains": names, "domain_sources": {d: ["tenant"] for d in names}},
           "gate": {"headline_domain": "zz.example", "headline_source": "shortest audited apex",
                    "domains": {d: {} for d in names}},
           "maillog": {"by_domain": {"aaa.example": {"logical_messages": 40, "genuine_failures": 0},
                                     "dom.example": {"logical_messages": 2, "genuine_failures": 0},
                                     "m.dom.example": {"logical_messages": 5000, "genuine_failures": 0},
                                     "zz.example": {"logical_messages": 0, "genuine_failures": 0}}}}
    assert next_steps.pick_org(rep) == "dom.example"  # the busiest family, led by its audited apex


def test_the_one_liner_describes_the_subdomains_when_the_org_has_no_rows_of_its_own(tmp_path):
    import csv as _csv
    cols = ["Email date (UTC)", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
            "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC"]
    rows = [["2026-05-01 09:00:00", "<n%d@x>" % i, "news@news.corp.example", "news.corp.example",
             "news.corp.example", "u@example.com", "Weekly", "Delivered", "Inbox/folder", "pass"] for i in range(500)]
    rows += [["2026-05-01 09:00:00", "<f%d@x>" % i, "news@news.corp.example", "news.corp.example",
              "news.corp.example", "u@example.com", "Weekly", "Blocked", "Quarantine", "fail"] for i in range(30)]
    rows += [["2026-05-01 09:00:00", "<a%d@x>" % i, "hi@aaa.example", "aaa.example", "aaa.example",
              "u@example.com", "Hello", "Delivered", "Inbox/folder", "pass"] for i in range(50)]
    path = tmp_path / "log.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(cols)
        w.writerows(rows)
    domains = ["aaa.example", "corp.example"]
    rep = audit.build_report(domains=domains, maillog=str(path), offline=True, auth_column="DMARC",
                             domain_sources={d: ["tenant"] for d in domains})
    doc = next_steps.build(rep)
    assert doc["org_domain"] == "corp.example"
    assert ("corp.example has no mail-log rows of its own; its subdomains (news.corp.example) carry 530 messages"
            in doc["one_liner"])
    assert "30 messages from its subdomains failed with no passing copy" in doc["one_liner"]
    assert "The mail log has no rows for corp.example" not in doc["one_liner"]
    strm = doc["failing"]["streams"]  # the JSON says whose rows these numbers are
    assert strm["scope"] == "unaudited subdomains" and strm["subdomains"] == ["news.corp.example"]
    assert (strm["genuine_failures"], strm["logical_messages"]) == (30, 530)


def test_a_headline_the_volume_rule_chose_is_not_remapped_without_a_mail_log():
    # aggregate reports only: the apex gets spoofed (900 fail, 0 pass) while its subdomain sends
    rep = {"inputs": {"domains": ["corp.example", "mail.corp.example"]},
           "gate": {"headline_domain": "mail.corp.example", "headline_source": "most passing mail in the reports",
                    "domains": {"corp.example": {"maillog_rows": None}, "mail.corp.example": {"maillog_rows": None}}},
           "rua": {"by_header_from": [{"domain": "corp.example", "pass": 0, "fail": 900},
                                      {"domain": "mail.corp.example", "pass": 500, "fail": 0}]}}
    assert next_steps.pick_org(rep) == "mail.corp.example"
    rep["gate"]["headline_source"] = "most internal mail"  # collect's volume: the gate picked the member already
    assert next_steps.pick_org(rep) == "mail.corp.example"
    # a label that skipped the in-family rule maps to the apex only when the reports show it sending
    rep["gate"]["headline_source"] = "tenant default domain"
    assert next_steps.pick_org(rep) == "mail.corp.example"
    rep["rua"]["by_header_from"][0]["pass"] = 40
    assert next_steps.pick_org(rep) == "corp.example"


def test_the_first_domain_given_is_a_typed_headline_too():
    rep = {"inputs": {"domains": ["mail.corp.example", "corp.example"]},
           "maillog": {"auth_column": "DMARC",
                       "by_domain": {"corp.example": {"logical_messages": 40, "genuine_failures": 0,
                                                      "passing_messages": 0, "internal_messages": 40},
                                     "mail.corp.example": {"logical_messages": 325, "genuine_failures": 25,
                                                           "passing_messages": 300, "internal_messages": 0}}},
           "gate": {"headline_domain": "mail.corp.example", "headline_source": "first domain given",
                    "domains": {"corp.example": {"maillog_rows": 40}, "mail.corp.example": {"maillog_rows": 325}}}}
    assert next_steps.pick_org(rep) == "mail.corp.example"


def test_an_old_report_is_reranked_the_way_the_gate_ranks_now():
    # typed sources first, as the gate does
    rep = {"inputs": {"domains": ["zz.example", "corp.example"],
                      "domain_sources": {"zz.example": ["file"], "corp.example": ["file"]}},
           "gate": {"headline_domain": "zz.example", "headline_source": "shortest audited apex",
                    "domains": {"zz.example": {}, "corp.example": {}}},
           "maillog": {"by_domain": {"zz.example": {"logical_messages": 3, "genuine_failures": 0},
                                     "corp.example": {"logical_messages": 900, "genuine_failures": 0}}}}
    assert next_steps.pick_org(rep) == "zz.example"
    del rep["inputs"]["domain_sources"]  # no sources at all: the first domain given counts as typed
    assert next_steps.pick_org(rep) == "zz.example"
    rep["inputs"]["domain_sources"] = {"zz.example": ["tenant"], "corp.example": ["tenant"]}  # discovered: mail decides
    assert next_steps.pick_org(rep) == "corp.example"
    # an apex with no rows of its own still leads its family through its unaudited subdomains
    names = ["aaa.example", "app.corp.example", "corp.example"]
    rep = {"inputs": {"domains": names, "domain_sources": {d: ["tenant"] for d in names}},
           "gate": {"headline_domain": "aaa.example", "headline_source": "shortest audited apex",
                    "domains": {d: {} for d in names}},
           "maillog": {"by_domain": {
               "aaa.example": {"logical_messages": 100, "genuine_failures": 0},
               "app.corp.example": {"logical_messages": 50, "genuine_failures": 0},
               "corp.example": {"logical_messages": 0, "genuine_failures": 0,
                                "subdomains_total": {"logical_messages": 600, "genuine_failures": 0,
                                                     "domains": ["news.corp.example"]}}}}}
    assert next_steps.pick_org(rep) == "corp.example"
    # an apex that was never audited (seen only in the reports) cannot lead: its audited member does
    rep["inputs"]["domains"] = ["aaa.example", "app.corp.example"]
    del rep["gate"]["domains"]["corp.example"]
    del rep["maillog"]["by_domain"]["corp.example"]
    rep["maillog"]["by_domain"]["app.corp.example"]["logical_messages"] = 500
    rep["rua"] = {"totals": {"domains": ["corp.example", "app.corp.example", "aaa.example"]}}
    assert next_steps.pick_org(rep) == "app.corp.example"


def test_an_old_report_is_not_reranked_by_a_scoped_log_and_falls_back_to_the_reports():
    names = ["zz.example", "corp.example"]
    rep = {"inputs": {"domains": names, "domain_sources": {d: ["tenant"] for d in names}},
           "gate": {"headline_domain": "zz.example", "headline_source": "shortest audited apex",
                    "domains": {d: {} for d in names}},
           "maillog": {"sender_domain": "corp.example",  # a log scoped to one domain cannot rank the rest
                       "by_domain": {"corp.example": {"logical_messages": 900, "genuine_failures": 0},
                                     "zz.example": {"logical_messages": 0, "genuine_failures": 0}}}}
    assert next_steps.pick_org(rep) == "zz.example"
    rep["rua"] = {"by_header_from": [{"domain": "zz.example", "pass": 5, "fail": 0},
                                     {"domain": "news.corp.example", "pass": 400, "fail": 0}]}
    assert next_steps.pick_org(rep) == "corp.example"  # the reports rank instead; an unaudited subdomain counts for its apex
    del rep["maillog"]  # no mail log at all: the reports alone
    assert next_steps.pick_org(rep) == "corp.example"
    rep["inputs"]["domain_sources"]["zz.example"] = ["cli"]  # a typed domain wins before any ranking
    assert next_steps.pick_org(rep) == "zz.example"


def test_the_report_carries_the_mail_logs_time_span_and_the_document_states_it():
    rep = audit.build_report(domains=["example.com"], maillog=str(ROOT / "samples" / "sample_maillog.csv"),
                             offline=True, auth_column="DMARC")
    w = rep["maillog"]["window"]
    assert w["column"] == "Email date (UTC)" and w["from"] < w["to"] and w["hours"] > 0 and w["rows"] > 0
    doc = next_steps.build(rep)
    span = next_steps.span_phrase(w)
    assert span.startswith("the mail log's ") and ("-day span (" in span or "-hour span (" in span)
    assert ("failed with no passing copy in %s" % span) in doc["one_liner"]
    assert any(", over %s" % span in l for l in doc["stand"]["lines"])
    assert doc["stand"]["maillog_window"] == w
    assert "mail log %s to %s UTC (%s hours)" % (w["from"][:16].replace("T", " "), w["to"][:16].replace("T", " "),
                                                 w["hours"]) in doc["sources"]["audience_line"]
    assert "carries no dates" not in doc["sources"]["audience_line"]


def test_span_phrase_in_hours_and_days():
    assert next_steps.span_phrase({"from": "2026-10-05T22:25:07Z", "to": "2026-10-07T15:20:17Z", "hours": 40.9}) == (
        "the mail log's 41-hour span (2026-10-05 22:25 to 2026-10-07 15:20 UTC)")
    assert next_steps.span_phrase({"from": "2026-09-07T15:39:14Z", "to": "2026-10-07T15:02:21Z", "hours": 719.4}) == (
        "the mail log's 30-day span (2026-09-07 to 2026-10-07)")
    assert next_steps.span_phrase(None) is None


def test_caveats_and_a_cut_short_log_reach_the_stand_section():
    rep = audit.build_report(domains=["example.com"], maillog=str(ROOT / "samples" / "sample_maillog.csv"),
                             offline=True, auth_column="DMARC")
    rep["caveats"] = ["mail log: example.com row budget reached at 47h..41h ago - older rows skipped; the rows cover "
                      "only the last 41h (raise --max-rows to keep more) - mail-log counts for that domain cover that span only"]
    rep["maillog"]["truncation"] = "row budget kept only the newest 41h for example.com"
    doc = next_steps.build(rep)
    assert doc["stand"]["caveats"] == rep["caveats"]
    assert any(l.startswith("**Caveat:** mail log: example.com row budget reached") for l in doc["stand"]["lines"])
    assert any("the log export was cut short (row budget kept only the newest 41h for example.com), so this count "
               "is a floor" in l for l in doc["stand"]["lines"])


def test_plan_holds_from_the_merged_gate_are_reworded_as_conditions():
    def reword(text):
        for rx, fn in next_steps.PREREQ_REWORDS:
            m = rx.match(text)
            if m:
                return fn(m)
        return None
    assert reword("3 message(s) in the mail log failed from a sender that looks like your own misconfigured system, "
                  "not a spoof (2 more are excepted in the gate)") == (
        "the 3 mail-log failures from our own systems are fixed (2 more are formally excepted in audit.toml)")
    assert reword("SPF-only aligned senders (news@example.com (mail log, 2 msgs)): they break on forwarding at reject "
                  "- aligned DKIM first") == ("the SPF-only senders (news@example.com (mail log, 2 msgs)) are DKIM-signed, "
                                               "because SPF alone breaks on forwarding")
    assert reword("no aligned-DKIM evidence in this run (no aggregate reports; the mail log has no SPF/DKIM columns): "
                  "run queries/dkim_alignment.kql or supply reports before this step - DKIM before reject, always"
                  ).startswith("the run carries aligned-DKIM evidence")
    m = next_steps.GAP_RX.match("4 logical message(s) from this domain failed with no passing copy "
                                "(deduplicated; 2 more excepted); top senders: other@example.com x4")
    assert m and m.group(1) == "4"
    rep = {"gate": {"domains": {"example.com": {"reasons": [
        "exception: 1 mail-log failure(s) from vendor.example excepted until 2099-01-01: r; remove when c",
        "example.com: 4 logical message(s) from this domain failed with no passing copy (deduplicated; 2 more excepted)",
        "step being gated: p=reject"]}}, "evidence": {"statement": "s"}}}
    assert next_steps.gate_reasons(rep, "example.com") == [
        "4 logical message(s) from this domain failed with no passing copy (deduplicated; 2 more excepted)"]
    assert "first in audit.toml" in next_steps.TYPED_HEADLINES


def test_the_one_liner_states_the_headline_domains_own_span(tmp_path):
    import csv as _csv
    cols = ["Email date (UTC)", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
            "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC"]
    rows = [["2026-05-01 09:00:00", "<c1@x>", "hr@corp.example", "corp.example", "corp.example", "u@example.com",
             "Hello", "Delivered", "Inbox/folder", "pass"],
            ["2026-05-02 09:00:00", "<c2@x>", "hr@corp.example", "corp.example", "corp.example", "u@example.com",
             "Hello", "Blocked", "Quarantine", "fail"]]
    rows += [["2026-04-01 00:00:00" if i == 0 else "2026-05-09 00:00:00", "<o%d@x>" % i, "news@other.example",
              "other.example", "other.example", "u@example.com", "News", "Delivered", "Inbox/folder", "pass"]
             for i in range(2)]
    path = tmp_path / "log.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(cols)
        w.writerows(rows)
    domains = ["corp.example", "other.example"]
    rep = audit.build_report(domains=domains, maillog=str(path), offline=True, auth_column="DMARC",
                             domain_sources={d: ["tenant"] for d in domains},
                             volume={"corp.example": 100, "other.example": 1})
    assert rep["gate"]["headline_domain"] == "corp.example"
    assert rep["maillog"]["by_domain"]["corp.example"]["window"]["hours"] == 24.0
    assert rep["maillog"]["window"]["hours"] == 38 * 24.0  # the whole log reaches much further
    doc = next_steps.build(rep)
    assert "in the mail log's 24-hour span (2026-05-01 09:00 to 2026-05-02 09:00 UTC)" in doc["one_liner"]
    assert any("over the mail log's 38-day span (2026-04-01 to 2026-05-09)" in l for l in doc["stand"]["lines"])
    # a scope typed in mixed case still carries the span
    scoped = audit.run_maillog(str(path), sender_domain="Corp.Example", auth_column="DMARC")
    assert scoped["window"] == audit.run_maillog(str(path), sender_domain="corp.example", auth_column="DMARC")["window"]
    assert scoped["window"]["hours"] == 24.0


def test_span_phrase_rounds_halves_up_and_has_a_minute_form():
    def w(to):
        return {"from": "2026-10-05T22:00:00Z", "to": to}
    assert next_steps.span_phrase(w("2026-10-05T22:30:00Z")) == "the mail log's 30-minute span (2026-10-05 22:00 to 2026-10-05 22:30 UTC)"
    assert next_steps.span_phrase(w("2026-10-06T00:30:00Z")).startswith("the mail log's 3-hour span")   # 2.5 h
    assert next_steps.span_phrase(w("2026-10-08T10:00:00Z")).startswith("the mail log's 3-day span")    # 60 h
    assert next_steps.span_phrase(w("2026-10-09T10:00:00Z")).startswith("the mail log's 4-day span")    # 84 h


def test_exceptions_reduce_every_number_the_document_shows_for_the_domain(tmp_path):
    import csv as _csv
    cols = ["Email date (UTC)", "Internet message ID", "Sender address", "Sender domain", "Sender mail from domain",
            "Recipients", "Subject", "Delivery action", "Latest delivery location", "DMARC"]
    rows = [["2026-05-01 09:00:00", "<a%d@x>" % i, "app@corp.example", "corp.example", "corp.example",
             "u@example.com", "Purchase order 1 acknowledged", "Blocked", "Quarantine", "fail"] for i in range(3)]
    rows += [["2026-05-01 09:00:00", "<p%d@x>" % i, "printer@corp.example", "corp.example", "printer.vendor.example",
              "u@example.com", "Scan", "Blocked", "Quarantine", "fail"] for i in range(2)]
    rows += [["2026-05-01 09:00:00", "<p%d@y>" % i, "printer@corp.example", "corp.example", "other.vendor.example",
              "u@example.com", "Scan", "Blocked", "Quarantine", "fail"] for i in range(2)]
    rows += [["2026-05-01 09:00:00", "<s%d@x>" % i, "ceo@corp.example", "corp.example", "spam.invalid",
              "u@example.com", "Urgent wire transfer", "Blocked", "Quarantine", "fail"] for i in range(2)]
    path = tmp_path / "log.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(cols)
        w.writerows(rows)
    exc = {"match": "printer.vendor.example", "reason": "printer", "until": "2099-01-01", "removal_criterion": "replaced"}
    rep = audit.build_report(domains=["corp.example"], maillog=str(path), offline=True, auth_column="DMARC",
                             vendor_domains=["vendor.example"], exceptions=[exc])
    g = rep["gate"]["domains"]["corp.example"]
    assert g["excepted_failures"] == 2 and g["excepted_senders"] == {"printer@corp.example": 2}
    doc = next_steps.build(rep)
    line = doc["one_liner"]
    assert "9 messages from corp.example failed with no passing copy" in line
    assert "2 formally excepted in audit.toml" in line
    assert "printer@corp.example x2" in line and "printer@corp.example x4" not in line  # one entry, reduced
    strm = doc["failing"]["streams"]
    assert strm["excepted"] == 2 and strm["by_likely"] == {"likely_spoof": 2, "likely_misconfigured_sender": 5, "unknown": 0}
    assert "5 from 2 of our own senders" in line and "2 from 1 address that look like spoofing" in line
    assert g["excepted_senders_by_likely"] == {"printer@corp.example": {"likely_misconfigured_sender": 2}}
    assert g["excepted_senders_by_envelope"] == {"printer@corp.example": {"printer.vendor.example": 2}}
    # the sections that name senders show the same reduced numbers, and the excepted stream once, as such
    md = next_steps.render_md(doc)
    assert "printer@corp.example - 2 messages" in md and "printer@corp.example - 4 messages" not in md
    assert "Formally excepted in audit.toml and not counted above: 2 messages (printer@corp.example x2)." in md
    assert doc["failing"]["excepted"] == [{"name": "printer@corp.example", "domain": "corp.example",
                                           "envelope": "printer.vendor.example", "count": 2}]


def test_blocker_items_split_the_reduced_count_with_the_reduced_split():
    rep = {"inputs": {"domains": ["corp.example"]},
           "gate": {"domains": {"corp.example": {"verdict": "no_go", "current_policy": "reject",
                                                 "excepted_by_likely": {"likely_spoof": 2}, "excepted_senders": {"ceo@corp.example": 2},
                                                 "excepted_senders_by_likely": {"ceo@corp.example": {"likely_spoof": 2}},
                                                 "excepted_senders_by_envelope": {"ceo@corp.example": {"spam.invalid": 2}},
                                                 "reasons": ["corp.example: 5 logical message(s) from this domain failed with no "
                                                             "passing copy (deduplicated; 2 more excepted); top senders: "
                                                             "app@corp.example x3, printer@corp.example x2"]}},
                    "evidence": {"statement": "s"}},
           "maillog": {"by_domain": {"corp.example": {"genuine_failures": 7, "logical_messages": 7,
                                                      "by_likely": {"likely_spoof": 2, "likely_misconfigured_sender": 5, "unknown": 0},
                                                      "excepted": 2, "excepted_by_likely": {"likely_spoof": 2},
                                                      "top_senders": []}},
                       "census": {"by_sender": [
                           {"sender": "app@corp.example", "domain": "corp.example", "envelope_domain": "corp.example",
                            "genuine_failures": 3, "messages": 3, "likely": "likely_misconfigured_sender", "excepted": 0,
                            "likely_counts": {"likely_misconfigured_sender": 3}, "likely_after": "likely_misconfigured_sender"},
                           {"sender": "printer@corp.example", "domain": "corp.example", "envelope_domain": "v.example",
                            "genuine_failures": 2, "messages": 2, "likely": "likely_misconfigured_sender", "excepted": 0,
                            "likely_counts": {"likely_misconfigured_sender": 2}, "likely_after": "likely_misconfigured_sender"},
                           {"sender": "ceo@corp.example", "domain": "corp.example", "envelope_domain": "spam.invalid",
                            "genuine_failures": 2, "messages": 2, "likely": "likely_spoof", "excepted": 2,
                            "likely_counts": {}, "likely_after": None}]}}}
    view = next_steps.maillog_view(rep)
    own = next_steps.own_domain_view(rep, view, "corp.example")
    assert own["by_likely"] == {"likely_spoof": 0, "likely_misconfigured_sender": 5, "unknown": 0}
    assert [s["name"] for s in own["senders"]] == ["app@corp.example", "printer@corp.example"]  # the excepted spoof is gone
    items = next_steps.blocker_items(rep, "corp.example", own)
    # no failure left looks like spoofing: the gap is our own senders', in the gate's words (a plan row's own-sender
    # condition then covers it, so the hold is not said twice)
    assert len(items) == 1 and items[0]["kind"] == "own" and "5 logical message" in items[0]["text"]


def test_rewords_keep_the_excepted_count_and_the_stand_line_knows_when_there_is_no_gap():
    def reword(text):
        for rx, fn in next_steps.PREREQ_REWORDS:
            m = rx.match(text)
            if m:
                return fn(m)
    assert reword("3 message(s) in the mail log failed from a sender that looks like your own misconfigured system, "
                  "not a spoof (2 more are excepted in the gate)") == (
        "the 3 mail-log failures from our own systems are fixed (2 more are formally excepted in audit.toml)")
    rep = {"inputs": {"domains": ["corp.example"]}, "gate": {"domains": {}},
           "maillog": {"counters": {"genuine_failures": 4, "raw_failing_rows": 4, "raw_rows": 10, "logical_messages": 8,
                                    "delivered_despite_fail": 0, "by_likely": {}}, "auth_column": "DMARC"}}
    view = next_steps.maillog_view(rep)
    stand = next_steps.where_we_stand(rep, view, None)
    assert any("(raw row counts agree: no relay echoes)" in l for l in stand["lines"])
    assert not any("the gap is relay echoes" in l for l in stand["lines"])


def test_span_phrase_takes_its_minutes_from_the_stamps():
    w = {"from": "2026-10-05T22:00:00Z", "to": "2026-10-05T22:08:00Z", "hours": 0.1}  # stored hours are rounded
    assert next_steps.span_phrase(w) == "the mail log's 8-minute span (2026-10-05 22:00 to 2026-10-05 22:08 UTC)"
    w = {"from": "2026-10-05T22:00:00Z", "to": "2026-10-05T22:00:20Z", "hours": 0.0}
    assert next_steps.span_phrase(w).startswith("the mail log's under-a-minute span")
    assert "0-minute" not in next_steps.span_phrase(w) and "0-hour" not in next_steps.span_phrase(w)


def test_the_trend_does_not_compare_what_the_runs_cannot_bear():
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["example.com"]}, "gate": {"domains": {}},
           "maillog": {"counters": {"genuine_failures": 613, "raw_failing_rows": 900, "raw_rows": 1000,
                                    "logical_messages": 700, "delivered_despite_fail": 0, "by_likely": {}},
                       "auth_column": "DMARC", "window": {"from": "2026-10-05T22:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 41.0}},
           "rua": {"totals": {"messages": 828000, "pass_rate": 0.98, "reports": 6000, "by_disposition": {}}},
           "delta": {"previous_generated_utc": "2026-10-01T15:00:00Z", "genuine_failures": None,
                     "maillog_window": {"comparable": False}, "rua": {"comparable": False, "now_messages": 828000, "previous_messages": 40},
                     "notes": []}}
    view = next_steps.maillog_view(rep)
    trend = next_steps.merge_trends([next_steps.trend_from_delta(rep["delta"], 613, 0.98),
                                     next_steps.trend_from_report({"generated_utc": "2026-10-01T15:00:00Z",
                                                                   "maillog": {"counters": {"genuine_failures": 2100}},
                                                                   "rua": {"totals": {"messages": 40, "pass_rate": 0.0}}})])
    trend = next_steps.apply_comparability(trend, rep["delta"], rep, view)
    assert trend["previous_genuine_failures"] is None and trend["previous_pass_rate"] is None
    stand = next_steps.where_we_stand(rep, view, trend)
    line = next(l for l in stand["lines"] if l.startswith("**Trend vs"))
    assert "not comparable" in line and "different spans" in line and "differ too much in size" in line
    # without a delta, the previous report's own figures decide the same way
    prev = {"generated_utc": "2026-10-01T15:00:00Z", "maillog": {"counters": {"genuine_failures": 2100}, "window": {"hours": 719.0}},
            "rua": {"totals": {"messages": 40, "pass_rate": 0.0}}}
    del rep["delta"]
    trend = next_steps.apply_comparability(next_steps.trend_from_report(prev), {}, rep, view)
    assert trend["previous_genuine_failures"] is None and trend["previous_pass_rate"] is None
    prev["maillog"]["window"]["hours"] = 40.0
    prev["rua"]["totals"]["messages"] = 800000
    trend = next_steps.apply_comparability(next_steps.trend_from_report(prev), {}, rep, view)
    assert trend["previous_genuine_failures"] == 2100 and trend["previous_pass_rate"] == 0.0


def test_an_exception_comes_off_the_stream_it_covered_not_the_address_as_a_whole():
    """ops@ has two streams: 2 through its own platform (excepted) and 3 through a
    spam host that look like spoofing. What remains keeps the spoof label: the
    census counts the excepted messages per stream, so each loses its own."""
    rep = {"inputs": {"domains": ["corp.example"]},
           "gate": {"domains": {"corp.example": {"verdict": "no_go", "current_policy": "none", "reasons": [],
                                                 "excepted_failures": 2, "excepted_by_likely": {"likely_misconfigured_sender": 2},
                                                 "excepted_senders": {"ops@corp.example": 2},
                                                 "excepted_senders_by_likely": {"ops@corp.example": {"likely_misconfigured_sender": 2}},
                                                 "excepted_senders_by_envelope": {"ops@corp.example": {"corp.example": 2}}}},
                    "evidence": {"statement": "s"}},
           "maillog": {"by_domain": {"corp.example": {"genuine_failures": 7, "logical_messages": 7,
                                                      "by_likely": {"likely_spoof": 3, "likely_misconfigured_sender": 4, "unknown": 0},
                                                      "excepted": 2, "excepted_by_likely": {"likely_misconfigured_sender": 2},
                                                      "top_senders": []}},
                       "census": {"by_sender": [
                           {"sender": "ops@corp.example", "domain": "corp.example", "envelope_domain": "spam.invalid",
                            "genuine_failures": 3, "messages": 3, "likely": "likely_spoof", "excepted": 0,
                            "likely_counts": {"likely_spoof": 3}, "likely_after": "likely_spoof"},
                           {"sender": "ops@corp.example", "domain": "corp.example", "envelope_domain": "corp.example",
                            "genuine_failures": 2, "messages": 2, "likely": "likely_misconfigured_sender", "excepted": 2,
                            "likely_counts": {}, "likely_after": None},
                           {"sender": "app@corp.example", "domain": "corp.example", "envelope_domain": "corp.example",
                            "genuine_failures": 2, "messages": 2, "likely": "likely_misconfigured_sender", "excepted": 0,
                            "likely_counts": {"likely_misconfigured_sender": 2}, "likely_after": "likely_misconfigured_sender"}]}}}
    view = next_steps.maillog_view(rep)
    own = next_steps.own_domain_view(rep, view, "corp.example")
    assert own["by_likely"] == {"likely_spoof": 3, "likely_misconfigured_sender": 2, "unknown": 0} and own["excepted_reduced"]
    assert [(s["name"], s["count"], s["likely"]) for s in own["senders"]] == [
        ("ops@corp.example", 3, "likely_spoof"), ("app@corp.example", 2, "likely_misconfigured_sender")]
    strm = next_steps.streams(view, None, own)
    assert [s["name"] for s in strm["own"]] == ["app@corp.example"] and [s["name"] for s in strm["spoof"]] == ["ops@corp.example"]
    line = next_steps.one_liner("corp.example", "none", None, None, strm, None)
    # round 13, T-07: a spoof label with no lure word in the subject could be our own vendor, and is said so
    assert ("2 from 1 of our own senders (app@corp.example x2); 3 that could be our own vendors (called spoofing on "
            "the envelope or a billing word alone: ops@corp.example x3)") in line
    assert "; 2 formally excepted in audit.toml" in line
    # the sections that name senders: the excepted stream is gone, the spoof stream of the same address stays
    assert [(s["name"], s["count"]) for s in view["by_sender"]] == [("ops@corp.example", 3), ("app@corp.example", 2)]
    assert view["excepted"] == [{"name": "ops@corp.example", "domain": "corp.example", "envelope": "corp.example", "count": 2}]
    # a census from before it counted the exceptions (an older report.json) says nothing about which stream they
    # covered: the split and the names stay raw everywhere, and the excepted total qualifies the total
    for row in rep["maillog"]["census"]["by_sender"]:
        for field in ("excepted", "likely_counts", "likely_after"):
            del row[field]
    for field in ("excepted", "excepted_by_likely"):
        del rep["maillog"]["by_domain"]["corp.example"][field]
    view = next_steps.maillog_view(rep)
    own = next_steps.own_domain_view(rep, view, "corp.example")
    assert own["by_likely"] == {"likely_spoof": 3, "likely_misconfigured_sender": 4, "unknown": 0} and own["excepted"] == 2
    assert [(s["name"], s["count"]) for s in own["senders"]] == [("ops@corp.example", 5), ("app@corp.example", 2)]
    assert not own["excepted_reduced"] and view["excepted"] == []
    line = next_steps.one_liner("corp.example", "none", None, None, next_steps.streams(view, None, own), None)
    assert "failed with no passing copy (2 of them formally excepted in audit.toml): " in line
    assert "; 2 formally excepted" not in line
    # and so does a gate that names no excepted senders at all
    del rep["gate"]["domains"]["corp.example"]["excepted_senders"]
    own = next_steps.own_domain_view(rep, view, "corp.example")
    assert own["by_likely"] == {"likely_spoof": 3, "likely_misconfigured_sender": 4, "unknown": 0} and own["excepted"] == 2


def test_two_empty_outside_views_are_not_called_different_in_size():
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["example.com"]}, "gate": {"domains": {}},
           "maillog": {"counters": {"genuine_failures": 5, "raw_failing_rows": 5, "raw_rows": 9, "logical_messages": 9,
                                    "delivered_despite_fail": 0, "by_likely": {}}, "auth_column": "DMARC",
                       "window": {"hours": 700.0}},
           "rua": {"totals": {"messages": 0, "pass_rate": 0.0, "reports": 0, "by_disposition": {}}}}
    prev = {"generated_utc": "2026-10-06T15:00:00Z", "maillog": {"counters": {"genuine_failures": 5}, "window": {"hours": 710.0}},
            "rua": {"totals": {"messages": 0, "pass_rate": 0.0}}}
    view = next_steps.maillog_view(rep)
    trend = next_steps.apply_comparability(next_steps.trend_from_report(prev), {}, rep, view)
    assert trend["previous_genuine_failures"] == 5 and trend["previous_pass_rate"] is None
    assert trend["not_comparable"] == ["the pass rate is not compared: neither outside view carries messages"]
    stand = next_steps.where_we_stand(rep, view, trend)
    line = next(l for l in stand["lines"] if l.startswith("**Trend vs"))
    assert "differ too much" not in line and "+0 genuine failures (5 -> 5)" in line and "neither outside view" in line


def test_the_deltas_verdict_applies_only_to_a_trend_about_the_same_previous_run():
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["example.com"]}, "gate": {"domains": {}},
           "maillog": {"counters": {"genuine_failures": 613, "raw_failing_rows": 900, "raw_rows": 1000, "logical_messages": 700,
                                    "delivered_despite_fail": 0, "by_likely": {}}, "auth_column": "DMARC",
                       "window": {"from": "2026-10-05T22:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 41.0}},
           "rua": {"totals": {"messages": 828000, "pass_rate": 0.98, "reports": 6000, "by_disposition": {}}}}
    view = next_steps.maillog_view(rep)
    not_ok = {"previous_generated_utc": "2026-10-01T15:00:00Z", "genuine_failures": None,
              "maillog_window": {"comparable": False}, "rua": {"comparable": False, "now_messages": 828000, "previous_messages": 40}}
    # a metrics trend about another run (Sept 30: a 40-hour log, a full outside view) is judged on its own figures
    other = {"source": "metrics", "label": "2026-09-30", "previous_genuine_failures": 600, "previous_pass_rate": 0.97,
             "previous_maillog_hours": 40.0, "previous_rua_messages": 800000}
    t = next_steps.apply_comparability(dict(other), not_ok, rep, view)
    assert t["previous_genuine_failures"] == 600 and t["previous_pass_rate"] == 0.97 and t["not_comparable"] == []
    # the same trend labelled with the delta's run takes the delta's verdict on the failure counts; the pass
    # rate is judged from the trend's own figures, since a trend merged by day could hold another run's view
    t = next_steps.apply_comparability(dict(other, label="2026-10-01"), not_ok, rep, view)
    assert t["previous_genuine_failures"] is None and t["previous_pass_rate"] == 0.97 and len(t["not_comparable"]) == 1
    # a delta from before the cuts were recorded named the domains whose own spans differed: no cause, no direction
    cut = dict(not_ok, maillog_window={"comparable": False, "domains_not_comparable": ["corp.example"]})
    t = next_steps.apply_comparability(dict(other, label="2026-10-01"), cut, rep, view)
    assert t["not_comparable"] == ["failure counts are not compared: the mail-log rows of corp.example cover very "
                                   "different spans in the two runs"]
    # and a comparable delta does not vouch for a trend about a run whose log covered 30 days
    ok = dict(not_ok, maillog_window={"comparable": True}, rua={"comparable": True})
    t = next_steps.apply_comparability(dict(other, previous_maillog_hours=719.0), ok, rep, view)
    assert t["previous_genuine_failures"] is None and t["previous_pass_rate"] == 0.97
    # 0.0 stored hours is a span of minutes, not a missing window: it is not compared with 30 days
    rep["maillog"]["window"] = {"from": "2026-10-07T14:57:00Z", "to": "2026-10-07T15:00:00Z", "hours": 0.0}
    t = next_steps.apply_comparability(dict(other, previous_maillog_hours=719.0), {}, rep, next_steps.maillog_view(rep))
    assert t["previous_genuine_failures"] is None


def test_a_window_mixing_zoned_and_naive_stamps_still_gets_a_span():
    w = {"from": "2026-10-05T22:00:00Z", "to": "2026-10-06T07:00:00", "hours": 9.0}
    assert next_steps.span_phrase(w) == "the mail log's 9-hour span (2026-10-05 22:00 to 2026-10-06 07:00 UTC)"
    assert next_steps._span_seconds({"from": "2026-10-05T22:00:00Z", "to": None}) is None
    assert next_steps._span_seconds("not a window") is None


def test_a_fully_excepted_address_with_two_verdict_labels_leaves_the_one_liner():
    """The census files printer@'s stream under its majority label while the gate
    counts 3 misconfigured + 1 spoof verdicts: the address still loses all 4."""
    rep = {"inputs": {"domains": ["corp.example"]},
           "gate": {"domains": {"corp.example": {"verdict": "no_go", "current_policy": "none", "reasons": [],
                                                 "excepted_failures": 4,
                                                 "excepted_by_likely": {"likely_misconfigured_sender": 3, "likely_spoof": 1},
                                                 "excepted_senders": {"printer@corp.example": 4},
                                                 "excepted_senders_by_likely": {"printer@corp.example": {"likely_misconfigured_sender": 3, "likely_spoof": 1}},
                                                 "excepted_senders_by_envelope": {"printer@corp.example": {"v.example": 4}}}},
                    "evidence": {"statement": "s"}},
           "maillog": {"by_domain": {"corp.example": {"genuine_failures": 7, "logical_messages": 7,
                                                      "by_likely": {"likely_spoof": 1, "likely_misconfigured_sender": 6, "unknown": 0},
                                                      "excepted": 4, "excepted_by_likely": {"likely_misconfigured_sender": 3,
                                                                                            "likely_spoof": 1},
                                                      "top_senders": []}},
                       "census": {"by_sender": [
                           {"sender": "printer@corp.example", "domain": "corp.example", "envelope_domain": "v.example",
                            "genuine_failures": 4, "messages": 4, "likely": "likely_misconfigured_sender", "excepted": 4,
                            "likely_counts": {}, "likely_after": None},
                           {"sender": "app@corp.example", "domain": "corp.example", "envelope_domain": "corp.example",
                            "genuine_failures": 3, "messages": 3, "likely": "likely_misconfigured_sender", "excepted": 0,
                            "likely_counts": {"likely_misconfigured_sender": 3}, "likely_after": "likely_misconfigured_sender"}]}}}
    view = next_steps.maillog_view(rep)
    own = next_steps.own_domain_view(rep, view, "corp.example")
    assert [(s["name"], s["count"]) for s in own["senders"]] == [("app@corp.example", 3)]
    assert own["by_likely"] == {"likely_spoof": 0, "likely_misconfigured_sender": 3, "unknown": 0}
    line = next_steps.one_liner("corp.example", "none", None, None, next_steps.streams(view, None, own), None)
    assert "3 from 1 of our own senders (app@corp.example x3); 4 formally excepted in audit.toml" in line


def test_when_every_named_failure_is_excepted_the_document_says_so_and_works_nothing():
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["corp.example"]},
           "gate": {"domains": {"corp.example": {"verdict": "go", "current_policy": "quarantine", "reasons": [],
                                                 "excepted_failures": 4, "excepted_by_likely": {"likely_misconfigured_sender": 4},
                                                 "excepted_senders": {"printer@corp.example": 4},
                                                 "excepted_senders_by_likely": {"printer@corp.example": {"likely_misconfigured_sender": 4}},
                                                 "excepted_senders_by_envelope": {"printer@corp.example": {"v.example": 4}}}},
                    "evidence": {"statement": "s"}},
           "findings": [{"id": "MAILFLOW-001", "severity": "major", "area": "maillog", "source": "maillog", "verified": True,
                         "title": "4 logical messages failed with no passing copy, from 1 senders",
                         "evidence": "e", "action": "work the senders: DKIM-sign the ones that are yours"}],
           "maillog": {"counters": {"genuine_failures": 4, "raw_failing_rows": 4, "raw_rows": 9, "logical_messages": 9,
                                    "delivered_despite_fail": 0, "by_likely": {"likely_misconfigured_sender": 4}},
                       "auth_column": "DMARC",
                       "by_domain": {"corp.example": {"genuine_failures": 4, "logical_messages": 9,
                                                      "by_likely": {"likely_spoof": 0, "likely_misconfigured_sender": 4, "unknown": 0},
                                                      "excepted": 4, "excepted_by_likely": {"likely_misconfigured_sender": 4},
                                                      "top_senders": []}},
                       "census": {"by_envelope": [{"envelope_domain": "v.example", "genuine_failures": 4, "messages": 4,
                                                   "likely": "likely_misconfigured_sender", "senders": ["printer@corp.example"],
                                                   "excepted": 4, "likely_after": None, "senders_after": 0,
                                                   "sample_sender_after": None}],
                                  "by_sender": [{"sender": "printer@corp.example", "domain": "corp.example", "envelope_domain": "v.example",
                                                 "genuine_failures": 4, "messages": 4, "likely": "likely_misconfigured_sender",
                                                 "excepted": 4, "likely_counts": {}, "likely_after": None}]}}}
    doc = next_steps.build(rep)
    md = next_steps.render_md(doc)
    assert "Every genuine failure the census names this run is formally excepted in audit.toml: 4 messages (printer@corp.example x4)." in md
    assert "No genuine failures in the mail log" not in md
    assert md.count("printer@corp.example x4") == 1 and "not counted above" not in md  # listed once, as such
    assert "work the senders" not in md and "DKIM-sign" not in md and "find out whose system" not in md
    assert "Who owns this" not in md or "maillog" not in md.split("Open questions")[-1]
    assert "None of corp.example's own mail failed" in doc["one_liner"] or "4 formally excepted" in doc["one_liner"]


def test_a_reduced_envelope_is_re_sorted_and_names_the_senders_still_failing_through_it():
    rep = {"inputs": {"domains": ["corp.example"]},
           "gate": {"domains": {"corp.example": {"verdict": "no_go", "current_policy": "none", "reasons": [],
                                                 "excepted_failures": 11, "excepted_by_likely": {"likely_misconfigured_sender": 11},
                                                 "excepted_senders": {"printer@corp.example": 11},
                                                 "excepted_senders_by_likely": {"printer@corp.example": {"likely_misconfigured_sender": 11}},
                                                 "excepted_senders_by_envelope": {"printer@corp.example": {"v.example": 11}}}},
                    "evidence": {"statement": "s"}},
           "maillog": {"census": {
               "by_envelope": [{"envelope_domain": "v.example", "genuine_failures": 12, "messages": 12,
                                "likely": "likely_misconfigured_sender", "senders": ["printer@corp.example", "other@corp.example"],
                                "excepted": 11, "likely_after": "likely_misconfigured_sender", "senders_after": 1,
                                "sample_sender_after": "other@corp.example"},
                               {"envelope_domain": "w.example", "genuine_failures": 7, "messages": 7,
                                "likely": "unknown", "senders": ["x@corp.example"],
                                "excepted": 0, "likely_after": "unknown", "senders_after": 1, "sample_sender_after": "x@corp.example"}],
               "by_sender": [{"sender": "printer@corp.example", "domain": "corp.example", "envelope_domain": "v.example",
                              "genuine_failures": 11, "messages": 11, "likely": "likely_misconfigured_sender",
                              "excepted": 11, "likely_counts": {}, "likely_after": None},
                             {"sender": "x@corp.example", "domain": "corp.example", "envelope_domain": "w.example",
                              "genuine_failures": 7, "messages": 7, "likely": "unknown",
                              "excepted": 0, "likely_counts": {"unknown": 7}, "likely_after": "unknown"},
                             {"sender": "other@corp.example", "domain": "corp.example", "envelope_domain": "v.example",
                              "genuine_failures": 1, "messages": 1, "likely": "likely_misconfigured_sender",
                              "excepted": 0, "likely_counts": {"likely_misconfigured_sender": 1},
                              "likely_after": "likely_misconfigured_sender"}]}}}
    view = next_steps.maillog_view(rep)
    assert [(e["name"], e["count"]) for e in view["by_envelope"]] == [("w.example", 7), ("v.example", 1)]
    v = view["by_envelope"][1]
    assert v["senders"] == ["other@corp.example"] and v["sender_count"] == 1
    # a '(blank)' census envelope is a stream like any other: the census counted what was excepted of it
    rep["maillog"]["census"]["by_sender"][0]["envelope_domain"] = "(blank)"
    rep["maillog"]["census"]["by_envelope"][0]["envelope_domain"] = "(blank)"
    view = next_steps.maillog_view(rep)
    assert view["excepted"] == [{"name": "printer@corp.example", "domain": "corp.example", "envelope": "(blank)", "count": 11}]


def test_a_delta_the_audit_refused_to_compare_is_a_trend_line_not_a_first_run():
    rep = {"generated_utc": "2026-10-07T15:00:00Z", "inputs": {"domains": ["corp.example"]}, "gate": {"domains": {}},
           "maillog": {"counters": {"genuine_failures": 613, "raw_failing_rows": 900, "raw_rows": 1000, "logical_messages": 700,
                                    "delivered_despite_fail": 0, "by_likely": {}}, "auth_column": "DMARC",
                       "window": {"from": "2026-10-05T22:00:00Z", "to": "2026-10-07T15:00:00Z", "hours": 41.0}},
           "delta": {"previous_generated_utc": "2026-10-01T15:00:00Z", "genuine_failures": None, "delivered_despite_fail": None,
                     "maillog_window": {"comparable": False, "log_comparable": True, "domains_not_comparable": ["corp.example"],
                                        "cut_orgs": {"corp.example": {"now": {"reason": "row budget", "kept_hours": 41},
                                                                      "previous": None}}},
                     "rua": {"comparable": None}, "notes": []}}
    doc = next_steps.build(rep)
    line = next(l for l in doc["stand"]["lines"] if l.startswith("**Trend"))
    assert line.startswith("**Trend vs 2026-10-01: not comparable**") and "first run" not in line
    assert "the row budget cut the mail log for corp.example in this run" in line
    assert next_steps.trend_from_delta({"previous_generated_utc": "2026-10-01T15:00:00Z", "genuine_failures": None}, 1, None) is None


def test_the_whole_census_fallback_of_the_one_liner_uses_the_reduced_view():
    view = {"by_sender": [{"name": "app@corp.example", "count": 2, "likely": "likely_misconfigured_sender"}],
            "genuine_failures": 6, "window": None, "excepted": [{"name": "printer@corp.example", "count": 4}]}
    strm = next_steps.streams(view, None, None)
    assert strm["scope"] == "all audited domains" and strm["excepted"] == 4
    line = next_steps.one_liner("corp.example", "none", None, None, strm, None)
    assert "1 of our own senders still fails (app@corp.example x2); 4 messages from 1 sender formally excepted in audit.toml." in line


def test_an_api_cap_cut_is_never_called_a_floor():
    """An hour at the API row cap keeps an arbitrary part of its legs, so a passing copy can be dropped and the
    failures overcounted: the stand line says the rows kept are incomplete and not verified, as audit.py does,
    and keeps 'a floor' for the row budget's whole hours (round 11, P19's reader half)."""
    rep = audit.build_report(domains=["example.com"], maillog=str(ROOT / "samples" / "sample_maillog.csv"),
                             offline=True, auth_column="DMARC")
    rep["maillog"]["truncation"] = "API row cap hit for example.com (6h..5h)"
    rep["maillog"]["cuts"] = {"example.com": {"reason": "api cap", "api_cap_hours": ["6h..5h"]}}
    lines = next_steps.build(rep)["stand"]["lines"]
    assert any("the log export was cut short (API row cap hit for example.com (6h..5h)); the rows kept are incomplete "
               "for example.com (an hour at the API cap: 6h..5h; its failures are not verified)" in l for l in lines)
    assert not any("so this count is a floor" in l for l in lines)
    rep["maillog"]["truncation"] = "row budget kept only the newest 41h for example.com"
    rep["maillog"]["cuts"] = {"example.com": {"reason": "row budget", "kept_hours": 41}}
    assert any("the log export was cut short (row budget kept only the newest 41h for example.com), so this count "
               "is a floor" in l for l in next_steps.build(rep)["stand"]["lines"])
