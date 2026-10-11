"""Generate local secrets for Docker Compose.

    python scripts/init_secrets.py [--analyst NAME ...]

Writes (git-ignored):
  secrets/mock_soc_token.txt   the mock SOC bearer token, held by the proxy and mock-soc
  secrets/ingest_token.txt     the ingest bearer token, for the SIEM that posts alerts
  .env                         created from .env.example if missing; POSTGRES_PASSWORD
                               is filled with a random value if still a placeholder
  secrets/analyst_tokens.txt   "name:sha256(token)" per analyst; the proxy checks approvals against it

Each analyst's token is printed once and never stored in clear: hand it to that
analyst (they paste it into the dashboard). Never give one to the agent. Re-run
with a new --analyst name to add one; existing analysts are kept.
"""

from __future__ import annotations

import argparse
import pathlib
import secrets
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from trustgate.analysts import token_hash  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SECRETS = ROOT / "secrets"


def shared_token(name: str, env: str) -> None:
    path = SECRETS / f"{name}.txt"
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        print(f"{name} already exists: {path}")
    else:
        token = secrets.token_urlsafe(32)
        path.write_text(token, encoding="utf-8")
        print(f"wrote {path}")
    print(f"{env}={token}")


def analyst_tokens(names: list[str]) -> None:
    path = SECRETS / "analyst_tokens.txt"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    existing = {line.split(":", 1)[0].strip().lower() for line in lines if ":" in line}
    for name in names:
        if name.lower() in existing:
            print(f"analyst '{name}' already has a token (delete its line to rotate it)")
            continue
        token = secrets.token_urlsafe(32)
        lines.append(f"{name.lower()}:{token_hash(token)}")
        print(f"analyst token for {name}: {token}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} analysts)")


def env_file() -> None:
    path, example = ROOT / ".env", ROOT / ".env.example"
    if not path.exists():
        path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"wrote {path} from .env.example; fill in the keys you have")
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        key, _, value = line.partition("=")
        if key.strip() == "POSTGRES_PASSWORD" and (not value.strip() or value.strip().startswith("<")):
            lines[i] = f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"set a random POSTGRES_PASSWORD in {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyst", action="append", default=None,
                        help="analyst to issue a token for (repeatable; default: analyst1 and analyst2)")
    args = parser.parse_args()
    SECRETS.mkdir(exist_ok=True)
    env_file()
    shared_token("mock_soc_token", "MOCK_SOC_TOKEN")
    shared_token("ingest_token", "TRUSTGATE_INGEST_TOKEN")
    analyst_tokens(args.analyst or ["analyst1", "analyst2"])


if __name__ == "__main__":
    main()
