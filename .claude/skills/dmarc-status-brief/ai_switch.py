#!/usr/bin/env python3
"""Is AI analysis switched on? Prints one word, on or off, and nothing else.

The human opts in to AI analysis with AI_ANALYSIS_ENABLED=true: in the
environment, which wins, or else in the repo's .env (see .env.example).
This reads the switch exactly as the toolkit does (src/mcp_server.py,
ai_analysis_enabled: only the value "true" is on) and prints its state, so
an agent never opens .env, the file the credentials live in.

  python .claude/skills/dmarc-status-brief/ai_switch.py

Exit codes: 0 on, 1 off (a switch that cannot be read is off).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))


def main():
    try:
        import mcp_server  # the toolkit's own reading of the switch: the environment first, then .env
        on = mcp_server.ai_analysis_enabled()
    except Exception:  # an install the reader cannot load: the default must be safe
        on = False
    print("on" if on else "off")
    return 0 if on else 1


if __name__ == "__main__":
    sys.exit(main())
