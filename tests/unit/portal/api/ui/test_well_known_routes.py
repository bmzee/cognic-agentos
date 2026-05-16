"""Sprint 7B.4 T12 — /.well-known/cognic-ui-events.json publication
+ snapshot-pinned drift regression.

Per ADR-020 §6: the .well-known endpoint publishes the portable JSON
schema for the 11 Wave-1 event families. Public + unauthenticated +
cacheable (Cache-Control: public, max-age=300, immutable). RFC 8615
requires the .well-known path to register AT ROOT, not under any
sub-prefix.

Snapshot regression catches Pydantic-model drift: any change to the
event-family models that affects their generated JSON schema MUST
update the snapshot file deliberately. Drift without snapshot update
fails the test."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI

from tests.unit.portal.api.ui.sse_test_helpers import _async_client


class TestWellKnownEndpoint:
    @pytest.mark.asyncio
    async def test_returns_200_unauth(self, app: FastAPI) -> None:
        """RFC 8615 + ADR-020 §6: public + unauth endpoint; UI clients
        + bank-overlay validators can fetch without an auth header."""
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_cache_control_immutable(self, app: FastAPI) -> None:
        """5-minute public cache + immutable hint so reverse proxies +
        browsers can cache aggressively (the schema is keyed by
        schema_version; clients invalidate by bumping the version)."""
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        assert r.headers["cache-control"] == "public, max-age=300, immutable"

    @pytest.mark.asyncio
    async def test_body_has_schema_version(self, app: FastAPI) -> None:
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        body = r.json()
        assert body["schema_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_body_has_11_families(self, app: FastAPI) -> None:
        from cognic_agentos.protocol.ui_events import _WAVE_1_FAMILIES

        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        body = r.json()
        assert set(body["families"]) == _WAVE_1_FAMILIES

    @pytest.mark.asyncio
    async def test_body_has_9_family_wave_1_sse_streamed_subset(self, app: FastAPI) -> None:
        from cognic_agentos.protocol.ui_events import _SSE_WAVE_1_STREAMED_FAMILIES

        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        body = r.json()
        assert set(body["wave_1_sse_streamed"]) == _SSE_WAVE_1_STREAMED_FAMILIES


class TestSchemaSnapshotPinned:
    """Drift detector — any Pydantic model change that affects the
    serialized JSON schema requires a deliberate snapshot update."""

    @pytest.mark.asyncio
    async def test_schema_matches_committed_snapshot(self, app: FastAPI) -> None:
        snapshot_path = Path("tests/unit/portal/api/ui/well_known_schema_snapshot.json")
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        live = r.text
        if not snapshot_path.exists():
            snapshot_path.write_text(live)
            pytest.fail(
                "snapshot created at "
                f"{snapshot_path} — commit it and re-run; this should "
                "happen ONLY once per Pydantic-schema change."
            )
        assert live == snapshot_path.read_text(), (
            f"schema drifted from snapshot at {snapshot_path}. "
            f"If the drift is intentional, regenerate via "
            f"`rm {snapshot_path} && uv run pytest "
            f"tests/unit/portal/api/ui/test_well_known_routes.py"
            f"::TestSchemaSnapshotPinned -x` then commit the new snapshot."
        )


class TestNotUnderApiV1UI:
    """RFC 8615 — .well-known MUST register at root, NOT under
    /api/v1/ui/. The root mount is what makes the endpoint
    auto-discoverable by standard well-known scanners."""

    @pytest.mark.asyncio
    async def test_route_not_under_api_v1_ui_prefix(self, app: FastAPI) -> None:
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/.well-known/cognic-ui-events.json" in paths
        assert "/api/v1/ui/.well-known/cognic-ui-events.json" not in paths
