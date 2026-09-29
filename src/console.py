#!/usr/bin/env python3
"""Console color for the human-facing reports, shared by every tool here.

Color is on only when the output is a terminal, NO_COLOR is not set, and
TERM is not "dumb". FORCE_COLOR=1 turns it on for a pipe (screenshots, CI
logs that render ANSI); NO_COLOR still wins when both are set. With color
off, every helper returns its text unchanged, so piped, redirected and
captured output is byte-identical to a run without this module. JSON output
never goes through here.

    import console
    paint = console.painter()            # stdout, Windows console prepared
    print(paint.status("PASS"), paint.dim("fix: ..."))
    print(paint.banner("setup: OK", "ok"))
"""

import os
import sys

# ANSI SGR codes by label. Check statuses, finding severities and gate
# verdicts share one palette so the same color means the same thing everywhere.
COLORS = {
    "PASS": "32", "WARN": "33", "FAIL": "31", "INFO": "36",
    "blocking": "31", "major": "31", "minor": "33", "info": "36",
    "go": "32", "no_go": "31", "insufficient_data": "33",
    "ok": "32", "warn": "33", "fail": "31",
}

SEVERITY_LEVEL = {"blocking": "fail", "major": "fail", "minor": "warn", "info": "ok"}
EXIT_LEVEL = {0: "ok", 1: "warn"}


class Paint:
    """Wraps text in ANSI color when enabled; returns it untouched otherwise."""

    STATUS_COLOR = COLORS  # older callers read this attribute

    def __init__(self, enabled):
        self.enabled = bool(enabled)

    def _wrap(self, code, text):
        text = str(text)
        if not (self.enabled and text):
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def status(self, status):
        """PASS/WARN/FAIL/INFO, a severity, or a gate verdict: bold, in its color."""
        return self._wrap(COLORS.get(str(status), "0") + ";1", status)

    def severity(self, sev):
        """A finding severity, colored but not bold (it sits inside a line)."""
        return self._wrap(COLORS.get(str(sev), "0"), sev)

    def bold(self, text):
        return self._wrap("1", text)

    def dim(self, text):
        return self._wrap("2", text)

    def red(self, text):
        return self._wrap("31", text)

    def green(self, text):
        return self._wrap("32", text)

    def yellow(self, text):
        return self._wrap("33", text)

    def cyan(self, text):
        return self._wrap("36", text)

    def banner(self, text, level="ok"):
        """A one-line verdict: bold green (ok), bold yellow (warn), bold red (fail)."""
        return self._wrap(COLORS.get(level, "0") + ";1", text)

    def by_severity(self, text, sev):
        """Banner colored by a finding severity (blocking/major red, minor yellow, info green)."""
        return self.banner(text, SEVERITY_LEVEL.get(str(sev), "fail"))

    def by_exit(self, text, code):
        """Banner colored by an exit code: 0 green, 1 yellow, anything else red."""
        return self.banner(text, EXIT_LEVEL.get(code, "fail"))


def color_wanted(stream=None):
    """Color unless piped, explicitly disabled (NO_COLOR), or a dumb terminal.

    FORCE_COLOR set to anything except "" or "0" turns color on for a pipe;
    NO_COLOR is honored first because an explicit opt-out must never lose.
    """
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    force = os.environ.get("FORCE_COLOR")
    if force not in (None, "", "0"):
        return True
    if stream is None:
        stream = sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def enable_windows_ansi():
    """Turn on virtual-terminal processing for the Windows console; a no-op
    elsewhere and harmless when the streams are redirected."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        for std_handle in (-11, -12):  # stdout, stderr
            handle = kernel32.GetStdHandle(std_handle)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def painter(stream=None):
    """The Paint for a stream (default stdout), with the Windows console
    prepared when color is going to be used."""
    enabled = color_wanted(stream if stream is not None else sys.stdout)
    if enabled:
        enable_windows_ansi()
    return Paint(enabled)
