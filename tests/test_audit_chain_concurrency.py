"""Several proxy replicas append to one audit hash chain (Helm: proxy.replicas > 1).

Needs a Postgres URL in TRUSTGATE_TEST_POSTGRES_URL; skipped otherwise.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import uuid

import pytest

PG = os.environ.get("TRUSTGATE_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG, reason="set TRUSTGATE_TEST_POSTGRES_URL to a scratch Postgres")


def _writer(url: str, n: int) -> None:
    from trustgate.store import Store
    store = Store(url)
    for i in range(n):
        store.audit("decision", alert_id=f"A-{os.getpid()}-{i}")


def test_concurrent_writers_keep_one_chain():
    from sqlalchemy import create_engine, text

    from trustgate.store import Store

    schema = f"t{uuid.uuid4().hex[:8]}"
    admin = create_engine(PG)
    with admin.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    url = f"{PG}{'&' if '?' in PG else '?'}options=-csearch_path%3D{schema}"
    try:
        Store(url)  # create tables once, before the writers race
        ctx = mp.get_context("spawn")
        procs = [ctx.Process(target=_writer, args=(url, 40)) for _ in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(120)
            assert p.exitcode == 0
        store = Store(url)
        assert len(store.audit_trail(limit=10_000)) == 160
        assert store.verify_audit_chain()
    finally:
        with admin.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
