"""scripts/check_public.py: credential material is a finding, by suffix and by content.

The fixtures below assemble the PEM markers and the typographic dashes at run
time, so this tracked file never carries the very strings the gate rejects."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_public  # noqa: E402

DASHES = "-----"
EM, EN = chr(0x2014), chr(0x2013)


def pem(kind):
    return DASHES + "BEGIN " + kind + DASHES


def test_credential_suffixes_are_flagged_without_reading_them(tmp_path):
    for name in ("dmarc-audit-readonly.pfx", "dmarc-audit.key", "server.PEM", "cert.cer", "trust.crt", "ks.jks", "a.p12"):
        assert check_public.credential_file(tmp_path / name), name
    for name in ("README.md", "collect.py", "audit.example.toml", ".env.example", "report.zip"):
        assert not check_public.credential_file(tmp_path / name), name


def test_private_key_header_in_a_text_file_is_a_hit(tmp_path):
    p = tmp_path / "notes.txt"
    lines = ["plain line", pem("PRIVATE KEY"), "MIIE...", DASHES + "END PRIVATE KEY" + DASHES,
             pem("RSA PRIVATE KEY"), pem("CERTIFICATE")]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    hits, allowed = check_public.scan_file(p, [])
    assert (2, "private key material") in hits and (5, "private key material") in hits
    assert not any(line == 6 for line, _ in hits)  # a certificate header alone is not key material
    assert allowed == []


def test_dash_and_deny_term_scan_still_work(tmp_path):
    p = tmp_path / "doc.md"
    lines = ["ok line", "bad " + EM + " dash", "mentions denyword here", "kept " + EN + " anyway  # publish-ok"]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    hits, allowed = check_public.scan_file(p, ["denyword"])
    assert (2, "em dash") in hits and (3, "deny term: denyword") in hits
    assert allowed == [4]
