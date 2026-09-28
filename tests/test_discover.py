"""discover.py: domain parsing, merging, zone classification. No network."""

import json
import subprocess
import sys
from pathlib import Path

import discover

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "src" / "discover.py")


def test_parse_domains_splits_commas_and_spaces_and_dedupes():
    doms, bad = discover.parse_domains(["Example.com,sub.example.com", " other.example ", "example.com."])
    assert doms == ["example.com", "sub.example.com", "other.example"]
    assert bad == []


def test_parse_domains_reports_non_domains():
    doms, bad = discover.parse_domains(["example.com", "user@example.com", "nodot"])
    assert doms == ["example.com"]
    assert set(bad) == {"user@example.com", "nodot"}


def test_org_domain():
    assert discover.org_domain("sub.example.com") == "example.com"
    assert discover.org_domain("a.b.example.co.uk") == "example.co.uk"
    assert discover.org_domain("example.com") == "example.com"


def test_zone_host_classification():
    assert discover.zone_host(["ns-1.awsdns-00.org"]) == "Route53"
    assert discover.zone_host(["dns1.cscdns.net", "dns2.cscdns.net"]) == "CSC"
    assert discover.zone_host(["anita.ns.cloudflare.com"]) == "Cloudflare"
    assert discover.zone_host(["ns1-01.azure-dns.com"]) == "Azure DNS"
    assert discover.zone_host(["ns1.example.net"]).startswith("other (")
    assert discover.zone_host([]) == "unknown"


def test_discover_merges_sources_without_network(monkeypatch):
    monkeypatch.setattr(discover, "graph_domains", lambda env_file=None: ([
        {"domain": "example.com", "verified": True, "services": ["Email"]},
        {"domain": "tenant.example", "verified": True, "services": []},
        {"domain": "x.onmicrosoft.com", "verified": True, "services": []},
    ], None))
    inv, notes = discover.discover(["example.com,cli.example"], use_graph=True, ns_lookup=False)
    by = {r["domain"]: r for r in inv}
    assert set(by) == {"example.com", "cli.example", "tenant.example"}
    assert by["example.com"]["sources"] == ["cli", "tenant"]      # named twice, listed once
    assert by["example.com"]["tenant_verified"] is True
    assert by["cli.example"]["tenant_verified"] is None
    assert all(r["zone_host"] == "not checked" for r in inv)
    assert any(n.startswith("tenant: 3 domains") for n in notes)


def test_discover_without_credentials_still_works(monkeypatch):
    monkeypatch.setattr(discover, "graph_domains",
                        lambda env_file=None: ([], "no credentials in .env (AZURE_CLIENT_SECRET) - tenant lookup skipped"))
    inv, notes = discover.discover(["example.com"], use_graph=True, ns_lookup=False)
    assert [r["domain"] for r in inv] == ["example.com"]
    assert any("tenant lookup skipped" in n for n in notes)


def test_cli_json_no_graph_no_ns():
    p = subprocess.run([sys.executable, SCRIPT, "example.com,sub.example.com", "--no-graph", "--no-ns", "--json"],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    data = json.loads(p.stdout)
    assert [d["domain"] for d in data["domains"]] == ["example.com", "sub.example.com"]
    assert data["domains"][1]["org_domain"] == "example.com"


def test_cli_nothing_to_discover_exits_2():
    p = subprocess.run([sys.executable, SCRIPT, "--no-graph", "--no-ns"], capture_output=True, text=True)
    assert p.returncode == 2
    assert "nothing to discover" in p.stderr
    assert "Traceback" not in p.stderr


def test_cli_writes_domains_txt_and_inventory(tmp_path):
    p = subprocess.run([sys.executable, SCRIPT, "example.com", "--no-graph", "--no-ns", "--out", str(tmp_path)],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert (tmp_path / "domains.txt").read_text(encoding="utf-8").strip() == "example.com"
    inv = json.loads((tmp_path / "inventory.json").read_text(encoding="utf-8"))
    assert inv["domains"][0]["sources"] == ["cli"]
