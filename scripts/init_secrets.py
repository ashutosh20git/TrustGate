"""Generate local secrets for Docker Compose.

    python3 scripts/init_secrets.py [--analyst NAME ...] [--dir DIR]

It needs only the Python standard library, so it also runs without the repo:

    curl -fsSL https://raw.githubusercontent.com/ashutosh20git/TrustGate/main/scripts/init_secrets.py \
        | python3 - --analyst alice

DIR defaults to the repo root when run from a checkout, else the current directory.

Writes (git-ignored):
  secrets/mock_soc_token.txt   the mock SOC bearer token, held by the proxy and mock-soc
  secrets/ingest_token.txt     the ingest bearer token, for the SIEM that posts alerts
  .env                         created from .env.example (or a minimal one without the repo)
                               if missing; POSTGRES_PASSWORD gets a random value if unset
  secrets/analyst_tokens.txt   "name:sha256(token)" per admin; the proxy checks sign-ins against it

The people in analyst_tokens.txt are admins (default: one called "admin"). Each
token is printed once and never stored in clear. The admin signs in to the
dashboard and adds the rest of the team on its Team page; nobody else needs this
script. Never give a token to the agent. Re-run with a new --analyst name to add
another admin (then restart the proxy); existing ones are kept.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import secrets


def token_hash(token: str) -> str:
    """Same as trustgate.analysts.token_hash. Kept local so this script needs only
    the standard library: run it before installing anything (tests check they match)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


_here = pathlib.Path(__file__).resolve()
REPO = _here.parent.parent if _here.is_file() else None  # None when piped into python3 -
ROOT = REPO or pathlib.Path.cwd()  # where .env and secrets/ go; --dir overrides
SECRETS = ROOT / "secrets"

# Written when .env.example is not at hand (no checkout). The full list of
# settings: https://github.com/ashutosh20git/TrustGate/blob/main/.env.example
MINIMAL_ENV = """\
# TrustGate settings. Full list with comments:
# https://github.com/ashutosh20git/TrustGate/blob/main/.env.example
POSTGRES_PASSWORD=
TRUSTGATE_MODE=enforce
TRUSTGATE_RECHECK_BACKEND=xgboost
TRUSTGATE_BIND_ADDR=127.0.0.1
# Your MTA's Authentication-Results authserv-id (trusted SPF/DKIM/DMARC facts):
# TRUSTGATE_MTA_AUTHSERV_ID=mx.corp.example
# Threat intel (optional): VIRUSTOTAL_API_KEY= ABUSEIPDB_API_KEY= OTX_API_KEY= URLHAUS_AUTH_KEY=
"""


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
            print(f"admin '{name}' already has a token (delete its line to rotate it)")
            continue
        token = secrets.token_urlsafe(32)
        lines.append(f"{name.lower()}:{token_hash(token)}")
        print(f"admin token for {name}: {token}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} admins)")
    print("sign in to the dashboard with that token, then add your analysts on the Team page")


def env_file() -> None:
    path = ROOT / ".env"
    example = (REPO / ".env.example") if REPO else None
    if not path.exists():
        if example is not None and example.exists():
            path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            print(f"wrote {path} from .env.example; fill in the keys you have")
        else:
            path.write_text(MINIMAL_ENV, encoding="utf-8")
            print(f"wrote a minimal {path}; see .env.example on GitHub for every setting")
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
                        help="admin to issue a token for (repeatable; default: admin)")
    parser.add_argument("--dir", type=pathlib.Path, default=None,
                        help="where to write .env and secrets/ (default: repo root, or the current directory)")
    args = parser.parse_args()
    if args.dir is not None:
        global ROOT, SECRETS
        ROOT = args.dir.resolve()
        SECRETS = ROOT / "secrets"
    SECRETS.mkdir(parents=True, exist_ok=True)
    env_file()
    shared_token("mock_soc_token", "MOCK_SOC_TOKEN")
    shared_token("ingest_token", "TRUSTGATE_INGEST_TOKEN")
    analyst_tokens(args.analyst or ["admin"])


if __name__ == "__main__":
    main()
