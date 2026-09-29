#!/usr/bin/env python3
"""Pre-push gate: nothing private and no typographic dashes leave this repo.

Three kinds of checks run over every tracked file:

1. Deny terms. Company names, employee names, account numbers, ticket IDs -
   the things that must never appear in a public commit. The real list lives
   in `.denylist` (gitignored, one term per line, # comments allowed) so the
   list itself is not published. Copy `.denylist.example` to `.denylist` and
   fill in your own terms before your first push.
2. Em dash (U+2014) and en dash (U+2013). The project style is " - ".
3. Credential material. A tracked file with a key or certificate suffix
   (.pfx .p12 .key .pem .cer .crt .der .jks), or any text line carrying a PEM
   private-key header, is a finding: those files are made under private/
   (gitignored) and never enter the repo, whatever the .gitignore says today.

Allowlisting one line: end it with the marker `# publish-ok` and the scanner
skips that line for both checks. The rule is "the line ends with publish-ok"
(case-insensitive; trailing whitespace and a closing `-->` or `*/` are
ignored), so any comment syntax works: `// publish-ok` in a .kql file, or
`<!-- publish-ok -->` in Markdown. Prose that mentions the marker mid-line
is still scanned. Every skipped line is counted on stderr so a bypass is
never silent, and --show-allowed lists them one per line.

Usage:
    python scripts/check_public.py                 # scan tracked files
    python scripts/check_public.py --staged        # scan files staged for commit
    python scripts/check_public.py --show-allowed  # also list the allowlisted lines

Exit 0 means clean; exit 1 prints every hit as path:line: term; exit 2 means
the file list could not be produced (git missing, or not run inside the repo).
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENYLIST = ROOT / ".denylist"
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
SKIP_SUFFIXES = {".gz", ".zip", ".pyc", ".png", ".jpg", ".pdf"}
DASHES = {"\u2014": "em dash", "\u2013": "en dash"}  # escapes, so this file passes its own scan
ALLOW_MARKER = "publish-ok"  # a line ENDING with this is skipped; canonical form: "# publish-ok"
COMMENT_CLOSERS = ("-->", "*/")  # closing tokens ignored after the marker (HTML and C-style comments)
BUILTIN_TERMS: list[str] = []  # built-ins stay empty on purpose; your terms go in .denylist
CREDENTIAL_SUFFIXES = {".pfx", ".p12", ".key", ".pem", ".cer", ".crt", ".der", ".jks"}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")


def tracked_files(staged_only):
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"] if staged_only \
        else ["git", "ls-files", "-z"]
    try:
        out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        detail = (getattr(e, "stderr", "") or str(e)).strip()
        print(f"error: cannot list files with '{' '.join(cmd)}': {detail}", file=sys.stderr)
        sys.exit(2)
    return [ROOT / name for name in out.split("\0") if name]


def load_terms():
    terms = list(BUILTIN_TERMS)
    if DENYLIST.exists():
        for line in DENYLIST.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms


def credential_file(path):
    """True for a key or certificate file by suffix; the content is never read."""
    return Path(path).suffix.lower() in CREDENTIAL_SUFFIXES


def is_allowed(line):
    """True when the line ends with the publish-ok marker (case-insensitive),
    ignoring trailing whitespace and a closing comment token such as -->."""
    tail = line.rstrip().lower()
    for closer in COMMENT_CLOSERS:
        if tail.endswith(closer):
            tail = tail[:-len(closer)].rstrip()
    return tail.endswith(ALLOW_MARKER)


def scan_file(path, terms):
    """Return (hits, allowed): hits as (lineno, what) pairs, allowed as the
    line numbers skipped because they end with the publish-ok marker."""
    hits, allowed = [], []
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return hits, allowed  # binary or unreadable: not a text leak vector
    for lineno, line in enumerate(text.splitlines(), 1):
        if is_allowed(line):
            allowed.append(lineno)
            continue
        for ch, name in DASHES.items():
            if ch in line:
                hits.append((lineno, name))
        if PRIVATE_KEY_RE.search(line):
            hits.append((lineno, "private key material"))
        lcline = line.lower()
        for term in terms:
            if term.lower() in lcline:
                hits.append((lineno, "deny term: " + term))
    return hits, allowed


def scan(path, terms):
    """Hits only, as (lineno, what) pairs; kept for callers of the original API."""
    return scan_file(path, terms)[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--staged", action="store_true",
                    help="scan only files staged for commit")
    ap.add_argument("--show-allowed", action="store_true",
                    help="list every line skipped because it ends with the publish-ok marker")
    args = ap.parse_args()

    terms = load_terms()
    if not DENYLIST.exists():
        print("note: no .denylist file - only the built-in checks ran."
              " Copy .denylist.example and add your terms.", file=sys.stderr)

    bad = 0
    allowed = []
    for path in tracked_files(args.staged):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if credential_file(path):
            bad += 1
            print(f"{rel}: credential material file ({path.suffix.lower()}) - keys and certificates never "
                  "belong in the repo: move it under private/, git rm --cached it, and treat the key as compromised")
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        hits, skipped = scan_file(path, terms)
        for lineno, what in hits:
            bad += 1
            print(f"{rel}:{lineno}: {what}")
        allowed.extend(f"{rel}:{lineno}" for lineno in skipped)

    if allowed:
        tail = "" if args.show_allowed else " (--show-allowed lists them)"
        print(f"note: {len(allowed)} line(s) skipped by the {ALLOW_MARKER} marker{tail}",
              file=sys.stderr)
        if args.show_allowed:
            for ref in allowed:
                print(f"  {ref}", file=sys.stderr)

    if bad:
        sys.exit(f"{bad} finding(s) - fix or redact before pushing.")
    print("clean")


if __name__ == "__main__":
    main()
