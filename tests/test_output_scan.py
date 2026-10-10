"""Output data-leak scanning (v2): Presidio-backed redaction and floor blocks.

Marked `presidio` so CI can run it only where the spaCy model is installed.
"""

from __future__ import annotations

import pytest

from trustgate.config import NotConfigured
from trustgate.output_scan import OutputScanner
from trustgate.policy_client import load_pack


def _scanner():
    try:
        scanner = OutputScanner(load_pack("packs/soc.rego"))
        scanner._load()
        return scanner
    except NotConfigured as exc:
        pytest.skip(f"output scanner backend unavailable: {exc.what}")


def test_email_address_redacted():
    scanner = _scanner()
    result = scanner.scan({"body": "Contact the user at john.doe@corp.example about this."})
    assert any(f.entity == "EMAIL_ADDRESS" for f in result.findings)
    assert "john.doe@corp.example" not in result.redacted["body"]


def test_floor_blocks_secret():
    scanner = _scanner()
    result = scanner.scan({"body": "The key is AKIAEXAMPLEKEY000001 for the backup."})
    assert "API_KEY" in result.blocked_entities


def test_allowed_entity_not_redacted():
    scanner = _scanner()
    result = scanner.scan({"body": "We blocked 203.0.113.9 at the firewall."})
    # IP_ADDRESS is on the SOC pack's allow list, so it survives.
    assert "203.0.113.9" in result.redacted["body"]
