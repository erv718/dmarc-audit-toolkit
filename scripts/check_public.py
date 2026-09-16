#!/usr/bin/env python3
"""Pre-push gate: nothing private and no typographic dashes leave this repo.

Two kinds of checks run over every tracked text file:

1. Deny terms. Company names, employee names, account numbers, ticket IDs -
   the things that must never appear in a public commit. The real list lives
   in `.denylist` (gitignored, one term per line, # comments allowed) so the
   list itself is not published. Copy `.denylist.example` to `.denylist` and
   fill in your own terms before your first push.
2. Em dash (U+2014) and en dash (U+2013). The project style is " - ".

Usage:
    python scripts/check_public.py            # scan tracked files
    python scripts/check_public.py --staged   # scan files staged for commit

Exit 0 means clean; exit 1 prints every hit as path:line: term.
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENYLIST = ROOT / ".denylist"
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
SKIP_SUFFIXES = {".gz", ".zip", ".pyc", ".png", ".jpg", ".pdf"}
DASHES = {"\u2014": "em dash", "\u2013": "en dash"}  # escapes, so this file passes its own scan
BUILTIN_TERMS: list[str] = []  # built-ins stay empty on purpose; your terms go in .denylist


def tracked_files(staged_only):
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"] if staged_only \
        else ["git", "ls-files"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / line.strip() for line in out.splitlines() if line.strip()]


def load_terms():
    terms = list(BUILTIN_TERMS)
    if DENYLIST.exists():
        for line in DENYLIST.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms


def scan(path, terms):
    hits = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return hits  # binary or unreadable: not a text leak vector
    low = text.lower()
    for lineno, line in enumerate(text.splitlines(), 1):
        for ch, name in DASHES.items():
            if ch in line:
                hits.append((lineno, name))
        lcline = line.lower()
        for term in terms:
            if term.lower() in lcline:
                hits.append((lineno, "deny term: " + term))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--staged", action="store_true",
                    help="scan only files staged for commit")
    args = ap.parse_args()

    terms = load_terms()
    if not DENYLIST.exists():
        print("note: no .denylist file - only the built-in checks ran."
              " Copy .denylist.example and add your terms.", file=sys.stderr)

    bad = 0
    for path in tracked_files(args.staged):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES or not path.exists():
            continue
        for lineno, what in scan(path, terms):
            bad += 1
            print(f"{path.relative_to(ROOT)}:{lineno}: {what}")

    if bad:
        sys.exit(f"{bad} finding(s) - fix or redact before pushing.")
    print("clean")


if __name__ == "__main__":
    main()
