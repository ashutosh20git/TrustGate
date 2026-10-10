"""Per-app policy packs (v2) and the OPA policy client.

A pack is a Rego file (packs/<name>.rego, package trustgate.<name>) plus one
OPA data document (packs/<name>.json, data.packs.<name>). Shared floor rules
live in packs/floor.rego and packs/floor.json and cannot be loosened by a pack:
loading a pack that tries to fails.

Decisions come from OPA, either the REST sidecar (OPA_URL, as deployed) or the
OPA binary (OPA_BIN, for local runs). No OPA means T1-T3 fail closed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from trustgate.config import NotConfigured, Settings
from trustgate.tiers import Tier

_PACKAGE = re.compile(r"^\s*package\s+trustgate\.([A-Za-z_][A-Za-z0-9_]*)\s*$", re.M)


class PackError(ValueError):
    """A pack that is malformed or tries to loosen the floor."""


class PolicyUnavailable(RuntimeError):
    """OPA could not give a decision (down, undefined result, bad response)."""


@dataclass
class PolicyPack:
    name: str
    rego_path: Path
    packs_dir: Path
    data: dict[str, Any]
    floor: dict[str, Any]
    block_entities: set[str] = field(default_factory=set)
    redact_entities: set[str] = field(default_factory=set)
    allow_entities: set[str] = field(default_factory=set)

    def tier_of(self, tool: str) -> Tier | None:
        tier = self.data.get("tools", {}).get(tool)
        return None if tier is None else Tier(int(tier))

    def _spec(self, section: str, tool: str) -> dict[str, Any] | None:
        specs = self.data.get(section, {})
        return specs.get(tool) or specs.get(tool.split("/", 1)[-1])

    def target_spec(self, tool: str) -> dict[str, Any] | None:
        return self._spec("targets", tool)

    def outbound_spec(self, tool: str) -> dict[str, Any] | None:
        return self._spec("outbound", tool)

    def expiry_spec(self, tool: str) -> dict[str, Any] | None:
        """T1 tools whose effect outlives the alert: {"ttl_arg": ..., "max_hours": ...}."""
        return self._spec("expiring_tools", tool)

    def campaign_limit(self, tier: Tier) -> tuple[int, int] | None:
        """(limit, window_s) for actions per sender domain, or None."""
        spec = self.data.get("campaign_rate_limits", {})
        limit = spec.get(str(int(tier)))
        return None if limit is None else (int(limit), int(spec.get("window_s", 3600)))

    @property
    def critical_assets(self) -> set[str]:
        return {str(v).lower() for v in self.data.get("critical_assets", [])}

    @property
    def allowlist(self) -> set[str]:
        return {str(v).lower() for v in self.data.get("allowlist", [])}

    def rate_limit(self, tier: Tier) -> int:
        pack_limit = int(self.data.get("rate_limits", {}).get(str(int(tier)), 60))
        floor_limit = int(self.floor.get("min_rate_limits", {}).get(str(int(tier)), pack_limit))
        return min(pack_limit, floor_limit)  # the floor caps how generous a pack can be

    @property
    def shared_sender_domains(self) -> set[str]:
        """Mail providers many unrelated senders share; a per-domain campaign key would throttle all of them.
        Fresh senders there are still caught per address by the attacker-cost floor."""
        return {str(v).lower() for v in self.data.get("campaign_rate_limits", {}).get("shared_domains", [])}

    @property
    def detector_sender_allowlist(self) -> set[str]:
        return {str(v).lower() for v in self.data.get("detector", {}).get("sender_allowlist", [])}


def load_pack(policy: str | Path) -> PolicyPack:
    """policy: "packs/soc.rego", "packs/soc" or "soc"."""
    path = Path(policy)
    if path.suffix == "":
        path = path.with_suffix(".rego") if path.parent != Path(".") else Path("packs") / f"{path.name}.rego"
    if path.suffix == ".json":
        path = path.with_suffix(".rego")
    if not path.exists():
        raise PackError(f"policy pack not found: {path}")
    match = _PACKAGE.search(path.read_text(encoding="utf-8"))
    if not match:
        raise PackError(f"{path} must declare 'package trustgate.<name>'")
    name = match.group(1)
    data_path = path.with_suffix(".json")
    floor_path = path.parent / "floor.json"
    try:
        data = json.loads(data_path.read_text(encoding="utf-8"))["packs"][name]
        floor = json.loads(floor_path.read_text(encoding="utf-8"))["floor"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise PackError(f"pack data missing or malformed: {data_path} / {floor_path}: {exc}") from exc

    for key in ("tools", "allowlist", "critical_assets", "output_scan"):
        if key not in data:
            raise PackError(f"pack '{name}' is missing '{key}'")
    for tool, tier in data["tools"].items():
        if int(tier) not in (0, 1, 2, 3):
            raise PackError(f"pack '{name}': tool {tool} has invalid tier {tier}")

    floor_block = set(floor.get("block_entities", []))
    scan = data["output_scan"]
    loosened = floor_block & (set(scan.get("allow_entities", [])) | set(scan.get("redact_entities", [])))
    if loosened:
        raise PackError(f"pack '{name}' tries to loosen floor-blocked entities: {sorted(loosened)}")

    return PolicyPack(
        name=name,
        rego_path=path,
        packs_dir=path.parent,
        data=data,
        floor=floor,
        block_entities=floor_block | set(scan.get("block_entities", [])),
        redact_entities=set(scan.get("redact_entities", [])),
        allow_entities=set(scan.get("allow_entities", [])),
    )


@dataclass
class PolicyResult:
    allow: bool
    deny: list[str]


class OPARestClient:
    """The OPA sidecar: POST /v1/data/trustgate/<pack>/decision."""

    def __init__(self, url: str, pack: str, *, timeout: float = 5.0, client: httpx.Client | None = None):
        self.endpoint = f"{url.rstrip('/')}/v1/data/trustgate/{pack}/decision"
        self._client = client or httpx.Client(timeout=timeout)

    def decide(self, policy_input: dict[str, Any]) -> PolicyResult:
        resp = self._client.post(self.endpoint, json={"input": policy_input})
        resp.raise_for_status()
        result = resp.json().get("result")
        return _parse_result(result)

    def healthy(self) -> bool:
        try:
            base = self.endpoint.split("/v1/", 1)[0]
            return self._client.get(f"{base}/health").status_code == 200
        except httpx.HTTPError:
            return False


class OPACliClient:
    """The OPA binary: `opa eval` per decision. Slower; meant for local runs and tests."""

    def __init__(self, binary: str, packs_dir: Path, pack: str, *, timeout: float = 10.0):
        resolved = Path(binary)
        self.binary = str(resolved.resolve()) if resolved.exists() else (shutil.which(binary) or binary)
        self.packs_dir = str(Path(packs_dir).resolve())
        self.query = f"data.trustgate.{pack}.decision"
        self.timeout = timeout

    def decide(self, policy_input: dict[str, Any]) -> PolicyResult:
        proc = subprocess.run(
            [self.binary, "eval", "--format", "json", "-d", self.packs_dir, "--stdin-input", self.query],
            input=json.dumps(policy_input), capture_output=True, text=True, timeout=self.timeout, check=False,
        )
        if proc.returncode != 0:
            raise PolicyUnavailable(f"opa eval failed with exit code {proc.returncode}")
        body = json.loads(proc.stdout or "{}")
        try:
            result = body["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError) as exc:
            raise PolicyUnavailable("opa eval returned no result") from exc
        return _parse_result(result)

    def healthy(self) -> bool:
        return Path(self.binary).exists() or shutil.which(self.binary) is not None


class UnconfiguredPolicy:
    """Placeholder: no OPA configured. Every T1-T3 decision fails closed."""

    def decide(self, policy_input: dict[str, Any]) -> PolicyResult:
        raise NotConfigured("OPA_URL / OPA_BIN", "run the OPA sidecar or point OPA_BIN at the opa binary")

    def healthy(self) -> bool:
        return False


def _parse_result(result: Any) -> PolicyResult:
    if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
        raise PolicyUnavailable("policy decision undefined")
    return PolicyResult(allow=result["allow"], deny=sorted(str(d) for d in result.get("deny", [])))


def policy_client(pack: PolicyPack, settings: Settings):
    if settings.opa_url:
        return OPARestClient(settings.opa_url, pack.name, timeout=settings.check_timeout_s)
    binary = settings.opa_bin
    if binary and (Path(binary).exists() or shutil.which(binary)):
        return OPACliClient(binary, pack.packs_dir, pack.name, timeout=settings.check_timeout_s)
    return UnconfiguredPolicy()
