"""Property-based fuzzing of the proxy and ingest HTTP APIs with Schemathesis (docs/BENCHMARKS.md).

Requests are generated from each service's own OpenAPI schema: random paths, bodies, headers and
tokens. For every request, whatever its content:

  * no server error (a 5xx is a crash an attacker can trigger at will);
  * an analyst or ingest endpoint answers 2xx only to the right bearer token (no auth bypass);
  * nothing executes: no fuzzed ProposedAction may run a tool for an alert the store does not
    hold (the agent's endpoint cannot be used to act without evidence).

TRUSTGATE_API_FUZZ_EXAMPLES sets examples per operation (default 15; the benchmark run used 300).
"""

from __future__ import annotations

import os

import pytest

schemathesis = pytest.importorskip("schemathesis")
from conftest import requires_opa  # noqa: E402
from hypothesis import HealthCheck  # noqa: E402
from hypothesis import settings as hsettings  # noqa: E402

from trustgate.analysts import AnalystDirectory, token_hash  # noqa: E402

EXAMPLES = int(os.environ.get("TRUSTGATE_API_FUZZ_EXAMPLES", "15"))
ANALYST_TOKEN = "fuzz-analyst-token"
INGEST_TOKEN = "fuzz-ingest-token"
EXECUTED: list[tuple[str, dict]] = []


def _recorder(name):
    def run(**kwargs):
        EXECUTED.append((name, kwargs))
        return {"ok": True}
    return run


@pytest.fixture
def proxy_app(gate, settings):
    from services.proxy.main import create_app

    for tool, tier in (("close_alert", 1), ("downgrade_severity", 1), ("whitelist_indicator", 1), ("suppress_rule", 1),
                       ("block_ip", 2), ("isolate_host", 2), ("disable_account", 2), ("send_email", 3),
                       ("post_webhook", 3), ("add_note", 0), ("escalate", 0)):
        gate.register(tool, tier, _recorder(tool))
    EXECUTED.clear()
    return create_app(gate=gate, settings=settings, analysts=AnalystDirectory.parse(f"ana:{token_hash(ANALYST_TOKEN)}"))


@pytest.fixture
def ingest_app(splitter, store, monkeypatch):
    monkeypatch.setenv("TRUSTGATE_INGEST_TOKEN", INGEST_TOKEN)
    from services.ingest.main import create_app

    return create_app(splitter=splitter, store=store)


@pytest.fixture
def proxy_schema(proxy_app):
    return schemathesis.openapi.from_asgi("/openapi.json", proxy_app)


@pytest.fixture
def ingest_schema(ingest_app):
    return schemathesis.openapi.from_asgi("/openapi.json", ingest_app)


PUBLIC = {("POST", "/v1/tools/{tool}"), ("GET", "/healthz")}
_FUZZ = hsettings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))


def _check(case, response, valid_token):
    assert response.status_code < 500, f"{case.method} {case.path}: server error {response.status_code}"
    if (case.method.upper(), case.path) in PUBLIC or response.status_code >= 300:
        return
    auth = (case.headers or {}).get("authorization") or (case.headers or {}).get("Authorization")
    assert auth == f"Bearer {valid_token}", f"{case.method} {case.path} answered {response.status_code} without the token"


proxy = schemathesis.pytest.from_fixture("proxy_schema")
ingest = schemathesis.pytest.from_fixture("ingest_schema")


@requires_opa
@proxy.parametrize()
@_FUZZ
def test_proxy_api_fuzz(case):
    response = case.call()
    _check(case, response, ANALYST_TOKEN)
    assert not EXECUTED, f"a fuzzed request executed {EXECUTED[0][0]} for an alert the store does not hold"


@ingest.parametrize()
@_FUZZ
def test_ingest_api_fuzz(case):
    response = case.call()
    _check(case, response, INGEST_TOKEN)


@requires_opa
@proxy.parametrize()
@_FUZZ
def test_proxy_api_fuzz_authenticated(case):
    """The same, as a logged-in analyst: the request bodies behind authentication get fuzzed too."""
    response = case.call(headers={"Authorization": f"Bearer {ANALYST_TOKEN}"})
    assert response.status_code < 500, f"{case.method} {case.path}: server error {response.status_code}: {response.text[:200]}"
    assert not EXECUTED, f"a fuzzed request executed {EXECUTED[0][0]} for an alert the store does not hold"


@ingest.parametrize()
@_FUZZ
def test_ingest_api_fuzz_authenticated(case):
    response = case.call(headers={"Authorization": f"Bearer {INGEST_TOKEN}"})
    assert response.status_code < 500, f"{case.method} {case.path}: server error {response.status_code}: {response.text[:200]}"
