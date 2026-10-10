"""Generate local secrets for Docker Compose (the mock SOC bearer token).

    python scripts/init_secrets.py

Writes secrets/mock_soc_token.txt (git-ignored) and prints it so you can set
MOCK_SOC_TOKEN in .env for host-side runs. Tool credentials live only in the
proxy and mock-soc containers.
"""

from __future__ import annotations

import pathlib
import secrets

ROOT = pathlib.Path(__file__).resolve().parent.parent
SECRETS = ROOT / "secrets"


def main() -> None:
    SECRETS.mkdir(exist_ok=True)
    path = SECRETS / "mock_soc_token.txt"
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        print(f"mock_soc_token already exists: {path}")
    else:
        token = secrets.token_urlsafe(32)
        path.write_text(token, encoding="utf-8")
        print(f"wrote {path}")
    print(f"MOCK_SOC_TOKEN={token}")


if __name__ == "__main__":
    main()
