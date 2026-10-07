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


def check_numbers(md, report, corpus_texts):
    """Every number token in the markdown occurs, as a whole token, in one of
    the input files; the pass rate as a percentage is the one derived figure."""
    corpus = "\n".join(corpus_texts)
    allowed = set(TEMPLATE_NUMBERS)
    rate = ((report.get("rua") or {}).get("totals") or {}).get("pass_rate")
    if rate is not None:
        allowed.add("%.1f" % (100 * rate))
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
    assert "| `example.com` | p=reject | not yet |" in md
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
    assert "| `example.com` | p=quarantine, pct=25 | not yet | raise pct to 50 (plan %s) |" % ratchet["id"] in md
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
