"""Triage one alert: python -m services.agent --alert-id A-1001"""

from __future__ import annotations

import argparse
import json

from services.agent.graph import run_agent
from services.agent.tools_client import ProxyToolsClient
from trustgate.config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="trustgate-soc-agent")
    parser.add_argument("--alert-id", required=True)
    args = parser.parse_args()
    settings = Settings()
    state = run_agent(args.alert_id, ProxyToolsClient(settings.proxy_url), settings)
    print(json.dumps({"action": state.get("action"), "outcome": state.get("outcome"), "tokens": state.get("tokens")},
                     indent=2, default=str))


if __name__ == "__main__":
    main()
