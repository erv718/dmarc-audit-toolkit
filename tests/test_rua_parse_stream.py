"""rua_parse reads a report as a stream: a large report costs memory for its
records, not for its text, and the size cap, the DTD rejection and the odd
shapes (namespaces, a wrapper root, zip members) still hold. No network."""

import gzip
import zipfile

import rua_parse

DTD = b'<!DOCTYPE feedback [<!ENTITY a "b">]>'


def report_xml(n, ns=False, wrapper=False, dtd_after=None, bad_counts=False):
    """A synthetic aggregate report with n records. ns declares a default
    namespace, wrapper nests <feedback> under another root, dtd_after puts a
    DOCTYPE after that many bytes of comment, bad_counts adds one record with
    no <count> and one with a negative one."""
    recs = []
    for i in range(n):
        recs.append(
            "<record><row><source_ip>192.0.2.%d</source_ip><count>%d</count>"
            "<policy_evaluated><disposition>none</disposition><dkim>%s</dkim><spf>pass</spf></policy_evaluated></row>"
            "<identifiers><header_from>example.com</header_from></identifiers>"
            "<auth_results><dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>"
            "<spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>"
            % (i % 250, 1 + i % 7, "pass" if i % 3 else "fail"))
    if bad_counts:
        recs.append("<record><row><source_ip>198.51.100.1</source_ip><policy_evaluated><disposition>none</disposition>"
                    "</policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record>")
        recs.append("<record><row><source_ip>198.51.100.2</source_ip><count>-3</count></row>"
                    "<identifiers><header_from>example.com</header_from></identifiers></record>")
    body = ("<report_metadata><org_name>reporter.example</org_name><email>r@reporter.example</email>"
            "<report_id>%d</report_id><date_range><begin>1788739200</begin><end>1788825600</end></date_range>"
            "</report_metadata><policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>"
            "<p>quarantine</p><pct>100</pct></policy_published>" % n) + "".join(recs)
    head = '<?xml version="1.0" encoding="UTF-8"?>'.encode()
    if dtd_after is not None:
        head += b"<!--" + b"x" * dtd_after + b"-->" + DTD
    feedback = ('<feedback%s>%s</feedback>' % (' xmlns="urn:example:dmarc"' if ns else "", body)).encode()
    return head + (b"<wrapper>" + feedback + b"</wrapper>" if wrapper else feedback)


def gz(path, data, isize=None):
    blob = bytearray(gzip.compress(data))
    if isize is not None:  # a lying trailer: the declared size check passes, the read must still stop
        blob[-4:] = isize.to_bytes(4, "little")
    path.write_bytes(bytes(blob))
    return path


def test_a_gzipped_report_parses_as_a_stream(tmp_path):
    path = gz(tmp_path / "r.xml.gz", report_xml(3000))
    warnings = []
    reports, skipped = rua_parse.load_reports([path], warnings)
    assert skipped == 0 and warnings == [] and len(reports) == 1
    rep = reports[0]
    assert len(rep["records"]) == 3000 and rep["org_name"] == "reporter.example" and rep["begin"] == 1788739200
    assert rep["policy"]["domain"] == "example.com" and rep["policy"]["p"] == "quarantine"
    assert sum(r["count"] for r in rep["records"]) == sum(1 + i % 7 for i in range(3000))
    assert rep["records"][7]["source_ip"] == "192.0.2.7" and rep["records"][7]["dkim_auth"][0]["selector"] == "s1"


def test_namespaces_a_wrapper_root_and_bad_counts(tmp_path):
    path = tmp_path / "r.xml"
    path.write_bytes(report_xml(10, ns=True, wrapper=True, bad_counts=True))
    warnings = []
    reports, skipped = rua_parse.load_reports([path], warnings)
    assert skipped == 0 and len(reports) == 1
    rep = reports[0]
    assert len(rep["records"]) == 11 and rep["count_defaulted"] == 1 and rep["records_rejected"] == 1
    assert rep["policy"]["domain"] == "example.com" and rep["email"] == "r@reporter.example"
    assert any("record 11: no <count>" in w for w in warnings) and any("record 12: negative <count>" in w for w in warnings)


def test_a_dtd_anywhere_in_the_document_is_rejected(tmp_path):
    early = tmp_path / "early.xml"
    early.write_bytes(report_xml(5, dtd_after=10))
    late = gz(tmp_path / "late.xml.gz", report_xml(5, dtd_after=rua_parse.CHUNK_BYTES + rua_parse.CHUNK_BYTES // 2))
    warnings = []
    reports, skipped = rua_parse.load_reports([early, late], warnings)
    assert reports == [] and skipped == 2
    assert all("DTD or entity declaration present" in w for w in warnings) and len(warnings) == 2


def test_the_cap_applies_before_and_during_inflation(monkeypatch, tmp_path):
    monkeypatch.setattr(rua_parse, "MAX_BYTES", 1024 * 1024)
    big = report_xml(6000)
    assert len(big) > 2 * 1024 * 1024
    declared = gz(tmp_path / "declared.xml.gz", big)
    lying = gz(tmp_path / "lying.xml.gz", big, isize=100)
    plain = tmp_path / "plain.xml"
    plain.write_bytes(big)
    small = gz(tmp_path / "small.xml.gz", report_xml(300))
    warnings = []
    reports, skipped = rua_parse.load_reports([declared, lying, plain, small], warnings)
    assert len(reports) == 1 and len(reports[0]["records"]) == 300 and skipped == 3
    assert any("declared decompressed size" in w and "over the 1 MB cap, not inflated" in w for w in warnings)
    assert any(w.startswith("skipped lying.xml.gz: decompressed size over the 1 MB cap") for w in warnings)
    assert any("plain.xml" in w and "over the 1 MB cap" in w for w in warnings)
    assert not any("not an aggregate report" in w for w in warnings)


def test_zip_members_plain_and_gzipped(tmp_path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.xml", report_xml(20))
        zf.writestr("b.xml.gz", gzip.compress(report_xml(30)))
    warnings = []
    reports, skipped = rua_parse.load_reports([path], warnings)
    assert skipped == 0 and warnings == [] and sorted(len(r["records"]) for r in reports) == [20, 30]
    assert sorted(r["source"] for r in reports) == ["bundle.zip:a.xml", "bundle.zip:b.xml.gz"]


def test_the_stream_is_closed_after_parsing(tmp_path):
    path = gz(tmp_path / "r.xml.gz", report_xml(50))
    payloads = rua_parse.read_payloads(path)
    label, stream = payloads[0]
    rep = rua_parse.parse_report(stream, label)
    assert len(rep["records"]) == 50
    assert stream.fh.closed and all(f.closed for f in stream.owned)


def test_damaged_gzip_files_are_skipped_never_fatal(tmp_path):
    xml = report_xml(5)
    good = gzip.compress(xml)
    bad_crc = bytearray(good)
    bad_crc[-8:-4] = b"\0\0\0\0"
    damaged = {"bad_crc.xml.gz": bytes(bad_crc), "header_only.xml.gz": good[:10],
               "flipped.xml.gz": good[:20] + bytes([good[20] ^ 0xFF]) + good[21:],
               "method.xml.gz": good[:2] + b"\x07" + good[3:]}
    for name, blob in damaged.items():
        (tmp_path / name).write_bytes(blob)
    gz(tmp_path / "lying_small.xml.gz", xml, isize=1)  # the trailer passes the declared-size check, then lies
    gz(tmp_path / "fine.xml.gz", xml)
    warnings = []
    reports, skipped = rua_parse.load_reports(sorted(tmp_path.iterdir()), warnings)
    assert len(reports) == 1 and len(reports[0]["records"]) == 5
    assert skipped == 5 and len(warnings) == 5 and all(w.startswith("skipped ") for w in warnings)
    assert all("damaged file" in w and "not an aggregate report" not in w for w in warnings)
    result = rua_parse.analyse([str(tmp_path)])  # the whole sweep over the folder survives them too
    doc = result[0] if isinstance(result, tuple) else result
    assert doc["totals"]["reports"] == 1


def test_only_record_elements_count_and_several_feedback_blocks_merge(tmp_path):
    with_sub = report_xml(3).replace(b"</feedback>", b"<subrecord><row><count>500</count></row></subrecord></feedback>")
    (tmp_path / "a.xml").write_bytes(with_sub)
    rep = rua_parse.load_reports([tmp_path / "a.xml"], [])[0][0]
    assert len(rep["records"]) == 3 and sum(r["count"] for r in rep["records"]) == sum(1 + i % 7 for i in range(3))
    head = b'<?xml version="1.0" encoding="UTF-8"?>'
    two = head + b"<wrapper>" + report_xml(2)[len(head):] + report_xml(4)[len(head):] + b"</wrapper>"
    (tmp_path / "two.xml").write_bytes(two)
    rep = rua_parse.load_reports([tmp_path / "two.xml"], [])[0][0]
    assert len(rep["records"]) == 6 and rep["report_id"] == "2"  # one report under the first block's metadata


def test_an_unknown_encoding_and_a_utf16_dtd_are_skipped_not_fatal(tmp_path):
    odd = report_xml(5).replace(b'encoding="UTF-8"', b'encoding="UCS-2"')
    (tmp_path / "odd.xml").write_bytes(odd)
    utf16 = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE feedback [<!ENTITY a "b">]>'
             + report_xml(3)[len(b'<?xml version="1.0" encoding="UTF-8"?>'):].decode()).encode("utf-16")
    (tmp_path / "wide.xml").write_bytes(utf16)
    gz(tmp_path / "fine.xml.gz", report_xml(4))
    warnings = []
    reports, skipped = rua_parse.load_reports(sorted(tmp_path.iterdir()), warnings)
    assert len(reports) == 1 and len(reports[0]["records"]) == 4 and skipped == 2
    assert any("odd.xml" in w for w in warnings)
    assert any("wide.xml" in w and "DTD or entity declaration present" in w for w in warnings)


def test_an_own_platform_with_a_broken_dkim_key_is_likely_misconfigured_not_unknown():
    s = {"count": 400, "no_auth": 0, "aligned_dkim_failed": 400, "misaligned_spf": 400, "misaligned_dkim": 0,
         "dkim_failed": 400, "header_from": {"news.example.com": 400},
         "reasons": __import__("collections").Counter(), "spf": {("platform.example", "mfrom", "pass"): 400},
         "dkim": {("news.example.com", "s1", "fail"): 400}}
    label, signals = rua_parse.likely_label(s, {"example.com"})
    assert label == "likely_misconfigured" and any("broken, rotated or mismatched DKIM key" in x for x in signals)
    s["reasons"] = __import__("collections").Counter({"forwarded": 300})  # a forward, not our key: still unknown
    assert rua_parse.likely_label(s, {"example.com"})[0] == "unknown"
    s["reasons"] = __import__("collections").Counter()
    s["misaligned_spf"] = 0  # no platform passes SPF at all: could be a forged signature, stays unknown
    assert rua_parse.likely_label(s, {"example.com"})[0] == "unknown"
