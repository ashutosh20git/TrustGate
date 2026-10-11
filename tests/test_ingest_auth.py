"""Ingest API authentication: alerts carry typed facts the gate trusts, so only
the holder of the ingest token (the SIEM) may post them or read stored evidence."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from services.ingest.main import create_app
from trustgate.ingest.split import Splitter

ALERT = {"alert_id": "E-1", "source": "email", "severity": "low",
         "observed": {"sender_prior_messages": 50}, "enrichment": {"url_reputation": "clean"}}


def _client(monkeypatch, settings, store, token):
    if token is None:
        monkeypatch.delenv("TRUSTGATE_INGEST_TOKEN", raising=False)
        monkeypatch.setattr("trustgate.config._read_secret", lambda name: None)
    else:
        monkeypatch.setenv("TRUSTGATE_INGEST_TOKEN", token)
    return TestClient(create_app(splitter=Splitter(settings, enrich=False), store=store))


def test_unconfigured_ingest_refuses_alerts(monkeypatch, settings, store):
    client = _client(monkeypatch, settings, store, None)
    assert client.post("/v1/alerts", json=ALERT).status_code == 503
    assert store.get_alert("E-1") is None
    assert client.get("/healthz").json()["auth_configured"] is False


@pytest.mark.parametrize("header", [None, "Bearer wrong", "tok-ingest", "Basic tok-ingest"])
def test_forged_alert_without_valid_token_is_refused(monkeypatch, settings, store, header):
    client = _client(monkeypatch, settings, store, "tok-ingest")
    headers = {"Authorization": header} if header else {}
    assert client.post("/v1/alerts", json=ALERT, headers=headers).status_code == 401
    assert client.get("/v1/alerts", headers=headers).status_code == 401
    assert store.get_alert("E-1") is None


def test_valid_token_posts_and_reads(monkeypatch, settings, store):
    client = _client(monkeypatch, settings, store, "tok-ingest")
    auth = {"Authorization": "Bearer tok-ingest"}
    assert client.post("/v1/alerts", json=ALERT, headers=auth).status_code == 200
    assert client.get("/v1/alerts/E-1", headers=auth).json()["alert_id"] == "E-1"
    assert client.get("/healthz").status_code == 200


# --- SOC connector is configurable (self-hosting with real tools) ----------------

class RecordingConnector:
    """A stand-in for a company's own connector (ticketing, firewall, EDR, IdP)."""
    def __init__(self, base_url, token):
        self.base_url, self.token = base_url, token


def test_proxy_loads_the_configured_soc_connector(monkeypatch):
    from services.proxy.main import load_soc_client
    from trustgate.config import Settings

    monkeypatch.setenv("TRUSTGATE_SOC_CLIENT", f"{__name__}:RecordingConnector")
    monkeypatch.setenv("MOCK_SOC_URL", "https://soar.corp.example")
    monkeypatch.setenv("MOCK_SOC_TOKEN", "tok-soar")
    client = load_soc_client(Settings())
    assert isinstance(client, RecordingConnector)
    assert (client.base_url, client.token) == ("https://soar.corp.example", "tok-soar")


def test_default_connector_is_the_mock_soc():
    from trustgate.config import Settings
    assert Settings().soc_client == "services.mock_soc.client:MockSOCClient"
