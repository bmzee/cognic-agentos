from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore  # noqa: F401
from cognic_agentos.packs.storage import PackRecord, PackRecordStore


async def _store(tmp_path: Any) -> tuple[PackRecordStore, Any]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'pa.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    eng = create_async_engine(url)
    return PackRecordStore(eng), eng


@pytest.mark.asyncio
async def test_submit_threads_payload_adversarial_onto_chain_row(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        pack_id = uuid.uuid4()
        manifest = {"pack": {"id": "p", "kind": "tool"}}
        digest = hashlib.sha256(canonical_bytes(manifest)).digest()
        now = datetime.now(UTC)
        await store.save_draft(
            PackRecord(
                id=pack_id,
                kind="tool",
                pack_id="cognic-tool-pa",
                display_name="p",
                state="draft",
                manifest_digest=digest,
                signed_artefact_digest=b"\x02" * 32,
                sbom_pointer=None,
                tenant_id="t1",
                created_by="svc",
                last_actor="svc",
                created_at=now,
                updated_at=now,
            )
        )
        snap = {
            "pass_rate": 1.0,
            "high_severity_failures": 0,
            "regressions": 0,
            "regression_evaluated": False,
            "candidate_run_id": str(uuid.uuid4()),
            "baseline_run_id": None,
        }
        await store.transition(
            pack_id=pack_id,
            transition="submit",
            actor_id="svc",
            tenant_id="t1",
            evidence_pointer=None,
            request_id="pack-submit-" + uuid.uuid4().hex,
            payload_manifest=manifest,
            expected_manifest_digest=digest,
            payload_adversarial=snap,
        )
        async with eng.connect() as c:
            row = (
                await c.execute(
                    sa.text(
                        "SELECT payload FROM decision_history "
                        "WHERE event_type='pack.lifecycle.submitted'"
                    )
                )
            ).first()
        assert row is not None
        payload = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        assert payload["adversarial"] == snap
    finally:
        await eng.dispose()
