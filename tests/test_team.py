"""The Team page: admins add, reset and remove members without a terminal or a restart.

The people in the setup secret file are admins. Members an admin adds live in the
database as token hashes; the token itself is returned once and stored nowhere. Only
admins reach /v1/team, and a removed member's token stops working on the next request.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from services.proxy.main import create_app as create_proxy
from test_silent_failures_v22 import _escalated_block
from conftest import requires_opa
from trustgate.analysts import AnalystDirectory, token_hash

ADMIN = {"Authorization": "Bearer root-token"}


def _proxy(gate, settings, setup: str | None = None) -> TestClient:
    directory = AnalystDirectory.parse(setup if setup is not None else f"root:{token_hash('root-token')}")
    return TestClient(create_proxy(gate=gate, settings=settings, analysts=directory))


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _add(proxy, name, role="analyst", auth=ADMIN):
    return proxy.post("/v1/team", json={"name": name, "role": role}, headers=auth)


def test_setup_people_are_admins_and_see_the_team(gate, settings):
    proxy = _proxy(gate, settings)
    assert proxy.get("/v1/me", headers=ADMIN).json() == {"name": "root", "role": "admin", "source": "setup"}
    assert proxy.get("/v1/team").status_code == 401
    assert [m["name"] for m in proxy.get("/v1/team", headers=ADMIN).json()] == ["root"]


def test_an_added_member_signs_in_at_once_and_the_token_is_never_stored(gate, store, settings):
    proxy = _proxy(gate, settings)
    resp = _add(proxy, "Bo")
    assert resp.status_code == 200
    token = resp.json()["token"]
    assert resp.json()["member"]["name"] == "bo"
    assert proxy.get("/v1/me", headers=_bearer(token)).json()["role"] == "analyst"
    assert proxy.get("/v1/metrics", headers=_bearer(token)).status_code == 200
    assert store.get_member("bo").token_sha256 == token_hash(token)
    trail = [r for r in store.audit_trail() if r.kind == "team"]
    assert trail[-1].details == {"event": "added", "member": "bo", "role": "analyst", "by": "root"}
    assert all(token not in str(r.details) for r in store.audit_trail())


def test_only_admins_manage_the_team(gate, settings):
    proxy = _proxy(gate, settings)
    analyst = _bearer(_add(proxy, "bo").json()["token"])
    assert proxy.get("/v1/team", headers=analyst).status_code == 403
    assert _add(proxy, "eve", auth=analyst).status_code == 403
    assert proxy.post("/v1/team/bo/token", headers=analyst).status_code == 403
    admin2 = _bearer(_add(proxy, "cy", role="admin").json()["token"])
    assert _add(proxy, "dee", auth=admin2).status_code == 200


def test_names_and_roles_are_checked(gate, settings):
    proxy = _proxy(gate, settings)
    assert _add(proxy, "bad name!").status_code == 422
    assert _add(proxy, "x", role="owner").status_code == 422
    assert _add(proxy, "root").status_code == 409
    assert _add(proxy, "bo").status_code == 200
    assert _add(proxy, "bo").status_code == 409


def test_removing_a_member_stops_their_token_and_they_can_be_added_back(gate, settings):
    proxy = _proxy(gate, settings)
    old = _add(proxy, "bo").json()["token"]
    assert proxy.post("/v1/team/bo/remove", headers=ADMIN).json()["active"] is False
    assert proxy.get("/v1/metrics", headers=_bearer(old)).status_code == 401
    assert proxy.post("/v1/team/bo/remove", headers=ADMIN).status_code == 404
    new = _add(proxy, "bo").json()["token"]
    assert proxy.get("/v1/metrics", headers=_bearer(new)).status_code == 200
    assert proxy.get("/v1/metrics", headers=_bearer(old)).status_code == 401


def test_a_token_reset_kills_the_old_token(gate, settings):
    proxy = _proxy(gate, settings)
    old = _add(proxy, "bo").json()["token"]
    new = proxy.post("/v1/team/bo/token", headers=ADMIN).json()["token"]
    assert new != old
    assert proxy.get("/v1/metrics", headers=_bearer(old)).status_code == 401
    assert proxy.get("/v1/metrics", headers=_bearer(new)).status_code == 200


def test_setup_people_and_yourself_cannot_be_changed_from_the_page(gate, settings):
    proxy = _proxy(gate, settings)
    assert proxy.post("/v1/team/root/remove", headers=ADMIN).status_code == 409
    me = _bearer(_add(proxy, "cy", role="admin").json()["token"])
    assert proxy.post("/v1/team/cy/remove", headers=me).status_code == 409
    assert proxy.post("/v1/team/cy/token", headers=me).status_code == 409


def test_members_count_as_configured_without_a_setup_file(gate, store, settings):
    proxy = _proxy(gate, settings, setup="")
    assert proxy.get("/v1/metrics", headers=ADMIN).status_code == 503
    from trustgate.store import TeamMember
    store.put_member(TeamMember(name="bo", token_sha256=token_hash("bo-token")))
    assert proxy.get("/v1/metrics", headers=_bearer("bo-token")).status_code == 200


@requires_opa
def test_a_team_member_can_be_the_second_analyst(gate, store, settings):
    esc_id, executed = _escalated_block(gate, store)
    proxy = _proxy(gate, settings)
    second = _add(proxy, "bo").json()["token"]
    ok = proxy.post(f"/v1/escalations/{esc_id}/approve", json={"reason": "ok"},
                    headers={**ADMIN, "X-Second-Analyst-Token": second})
    assert ok.status_code == 200 and executed == ["10.0.0.10"]
