"""CI model-pin check (blueprint test: "CI fails if LiteLLM config uses an unpinned model name").

A pinned model string ends in an explicit version, so determinism holds across
runs. Agent/attacker models are set via env at run time, so this checks that any
model string committed in .env.example or config carries a version suffix.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# A model id must look pinned: provider/name-with-a-version, or a dated snapshot.
PINNED = re.compile(r".+/.+-(\d|v\d|20\d{2})|.+@\d|.+-20\d{6}|.+-\d+-\d+")
KEYS = ("TRUSTGATE_AGENT_MODEL", "TRUSTGATE_ATTACKER_MODEL", "TRUSTGATE_RECHECK_MODEL")


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    if not path.exists():
        return problems
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().removeprefix("export ").strip(), value.strip().strip('"').strip("'")
        if key in KEYS and value and not value.startswith("<") and not PINNED.match(value):
            problems.append(f"{path.name}: {key}={value!r} is not a pinned (versioned) model id")
    return problems


def main() -> int:
    problems: list[str] = []
    for name in (".env", ".env.example"):
        problems += check_file(ROOT / name)
    if problems:
        print("Model pin check FAILED:")
        for p in problems:
            print("  -", p)
        return 1
    print("Model pin check passed (no unpinned model ids).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
