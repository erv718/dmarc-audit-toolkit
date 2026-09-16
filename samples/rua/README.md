# samples/rua

Three synthetic DMARC aggregate reports for `example.com`, one per container
format `src/rua_parse.py` accepts: plain `.xml`, `.xml.gz`, and `.zip`. The
reporters are fictional (`reporter1.example`, `reporter2.example`), every IP
is from the documentation ranges, and the counts were chosen so each derived
list in the parser has something to show.

| Source | What it models | Messages |
|---|---|---|
| 192.0.2.10 | a vendor (vendor.example) signing d=example.com s=s1, DKIM-aligned; it also signs d=vendor.example s=v1, and SPF passes on vendor.example without aligning | 800 |
| 198.51.100.20 | an Amazon SES-like source passing on SPF alone through a bounce subdomain (bounce.example.com), no DKIM | 190 |
| 192.0.2.30 | a sender still signing with the legacy selector `legacy2019` | 40 |
| 203.0.113.5 | a spoof: header_from example.com, no authentication at all, disposition reject | 300 |
| 192.0.2.40 | mail from the subdomain mail.example.com, DKIM and SPF aligned | 20 |
| 203.0.113.99 | a stray sender signing d=other.example, unaligned, quarantined by the receiver's local policy | 6 |
| 198.51.100.77 and .78 | forwarded copies: one survives on DKIM, one arrives with a broken signature | 3 and 2 |

Run:

```
python src/rua_parse.py samples/rua --known vendor.example,192.0.2.0/24 --retiring-selector legacy2019
```

Expected: 1361 messages, 1053 pass, 308 fail; one failing stream labelled
likely_spoof; one SPF-only sender; `legacy2019` still signing 40 messages,
which is a blocking finding (do not delete the key); exit code 1.

The second report carries a default XML namespace and a `<version>` element,
the way some reporters emit them. The third is a zip holding the report. The
windows are 2026-09-01 and 2026-09-02 (UTC), so `--since 2026-09-02` keeps
only the zip.
