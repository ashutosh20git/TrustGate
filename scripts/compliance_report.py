"""Write a compliance evidence pack from the audit trail.

    python scripts/compliance_report.py --framework cert-in --format md > cert-in.md

Frameworks: cert-in, dpdp, iso27001. Evidence for a review, not a determination.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from trustgate.compliance import FRAMEWORKS, report, to_markdown  # noqa: E402
from trustgate.store import Store  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", required=True, choices=FRAMEWORKS)
    parser.add_argument("--format", default="json", choices=["json", "md"])
    args = parser.parse_args()
    rep = report(Store(), args.framework)
    print(to_markdown(rep) if args.format == "md" else json.dumps(rep, indent=2, default=str))


if __name__ == "__main__":
    main()
