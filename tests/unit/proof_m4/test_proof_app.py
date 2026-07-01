"""Structural pin — the proof_m4 multi-actor app + binder + the proof AgentOS
image (M4 Task 8).

Mirrors ``tests/unit/proof_1b_2c/test_proof_app.py`` but for the MULTI-ACTOR
operator-install proof: the 4 role actors, the role-separation reviewer≠author
invariant, the eager-injection routes-mount (the crux — the operator + configure
routers actually mount), and the Dockerfile that vendors the multi-actor factory.
"""

from pathlib import Path

import pytest
from fastapi import FastAPI, Request

from cognic_agentos.portal.rbac.actor import Actor
from tests.integration.proof_m4.proof_app import (
    PROOF_ROLE_HEADER,
    PROOF_TENANT,
    MultiActorProofBinder,
    UnknownProofRole,
)

DF = Path("infra/proof-m4/Dockerfile.agentos-proof").read_text()

# The 4 role actors + the exact scope each role must carry.
_EXPECTED_ROLE_SCOPES: dict[str, set[str]] = {
    "author": {"pack.submit"},
    "reviewer": {
        "pack.review.claim",
        "pack.review.approve",
        "pack.review.reject",
        "pack.override.approval_gate",
    },
    "operator": {
        "pack.allow_list",
        "pack.configure",
        "pack.install",
        "pack.disable",
        "pack.revoke",
        "pack.uninstall",
        "pack.audit.read",
    },
    "mcp": {"mcp.tool.list", "mcp.tool.invoke"},
}


def _bind(role: str | None) -> Actor:
    """Bind an actor for ``role`` via a real request-shaped header (or no
    header when ``role is None``)."""
    binder = MultiActorProofBinder()
    if role is None:
        return binder.bind(request=None)
    scope = {"type": "http", "headers": [(PROOF_ROLE_HEADER.lower().encode(), role.encode())]}
    return binder.bind(request=Request(scope))


def test_tenant_and_header_constants() -> None:
    assert PROOF_TENANT == "proof-m4"
    assert PROOF_ROLE_HEADER == "X-Proof-Role"


def test_binder_yields_four_distinct_role_actors() -> None:
    """The plan requires ≥4 distinct role actors — pin exactly 4, each with a
    distinct subject, all scoped to the proof tenant."""
    actors = MultiActorProofBinder.role_actors()
    assert set(actors) == {"author", "reviewer", "operator", "mcp"}
    subjects = {role: a.subject for role, a in actors.items()}
    # 4 DISTINCT subjects.
    assert len(set(subjects.values())) == 4
    for role, actor in actors.items():
        assert actor.tenant_id == PROOF_TENANT, role


@pytest.mark.parametrize("role", sorted(_EXPECTED_ROLE_SCOPES))
def test_each_role_carries_its_exact_scopes(role: str) -> None:
    actor = _bind(role)
    assert set(actor.scopes) == _EXPECTED_ROLE_SCOPES[role], role


def test_reviewer_subject_differs_from_author_for_role_separation() -> None:
    """RequireDifferentActorThanCreator: the reviewer MUST NOT be the creator."""
    author = _bind("author")
    reviewer = _bind("reviewer")
    assert author.subject != reviewer.subject
    # And the reviewer holds the override scope (the 5-gate override path runs on
    # the reviewer-scoped /approve endpoint).
    assert "pack.override.approval_gate" in reviewer.scopes


def test_operator_and_reviewer_are_human_mcp_is_service() -> None:
    """RequireHumanActor gates allow-list + configure → operator must be human;
    the reviewer approve is a human decision; the MCP caller is a service."""
    assert _bind("operator").actor_type == "human"
    assert _bind("reviewer").actor_type == "human"
    assert _bind("author").actor_type == "human"
    assert _bind("mcp").actor_type == "service"


def test_operator_holds_the_full_lifecycle_operator_surface() -> None:
    """The operator drives allow-list + configure + install + disable + revoke."""
    ops = set(_bind("operator").scopes)
    assert {
        "pack.allow_list",
        "pack.configure",
        "pack.install",
        "pack.disable",
        "pack.revoke",
    } <= ops


def test_absent_or_unknown_role_fails_loud() -> None:
    """Fail-loud (NOT a silent default) so a mis-headed proof step surfaces."""
    with pytest.raises(UnknownProofRole):
        _bind(None)  # no header
    with pytest.raises(UnknownProofRole):
        _bind("nope")  # unknown role


def test_image_uses_expected_base_and_root_then_cognic_ordering() -> None:
    assert "ARG BASE_IMAGE=cognic-agentos:proof1b2-base" in DF
    assert "FROM ${BASE_IMAGE}" in DF
    assert DF.index("USER root") < DF.index("RUN chmod -R a+rX")
    assert DF.index("RUN chmod -R a+rX") < DF.index("USER cognic")


def test_image_bakes_released_staging_tree() -> None:
    for line in (
        "COPY proof-m4-staging/wheel/ /tmp/wheel/",
        "COPY proof-m4-staging/pack-attestations/ /opt/cognic/pack-attestations/",
        "COPY proof-m4-staging/trust-roots/ /opt/cognic/trust-roots/",
        "COPY proof-m4-staging/policies/ /opt/cognic/policies/",
        "COPY proof-m4-staging/alembic.ini /app/alembic.ini",
    ):
        assert line in DF, f"missing staging COPY: {line}"
    # no stale proof-1b-2c staging/app references
    assert "proof1b2c-staging" not in DF
    assert "proof_1b_2c/" not in DF


def test_image_vendors_multi_actor_proof_app_and_sets_trust_env_and_cmd() -> None:
    assert "COPY proof_m4/ /app/proof_m4/" in DF
    assert "RUN chmod -R a+rX /opt/cognic /app/alembic.ini /app/proof_m4" in DF
    assert "COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations" in DF
    assert "COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots" in DF
    assert "COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json" in DF
    assert "ENV PYTHONPATH=/app" in DF
    assert "uvicorn proof_m4.proof_app:create_proof_app --factory --host 0.0.0.0 --port 8000" in DF


# ---------------------------------------------------------------------------
# The crux (Key Decision A): the eager-injection wiring MOUNTS the operator +
# configure routers. This mirrors the mount-assertion style in
# ``tests/unit/portal/api/test_app_m4_wiring.py`` — it drives the SAME create_app
# kwargs ``create_proof_app`` passes (multi-actor binder + eager pack/config
# stores + materializer + trust gate/resolver) against LAZY engines (mount is a
# pure route-registration step; no lifespan / no TestClient / no DB connect), so
# it verifies the routers actually mount WITHOUT needing a live cluster.
# ---------------------------------------------------------------------------

_INSTALL_PATH = "/api/v1/packs/{pack_id}/install"
_CONFIGURE_PATH = "/api/v1/packs/{pack_id}/runtime-config"
_APPROVE_PATH = "/api/v1/packs/{pack_id}/approve"
_DRAFTS_PATH = "/api/v1/packs/drafts"
_OVERRIDE_PATH = "/api/v1/tenants/{tenant_id}/mcp-overrides/{pack_id}"
_ALLOWLIST_PATH = "/api/v1/tenants/{tenant_id}/mcp-allowlist"


def _has(app: object, path: str) -> bool:
    return any(getattr(r, "path", "") == path for r in app.routes)  # type: ignore[attr-defined]


def _proof_shaped_app() -> FastAPI:
    """Build an app with the SAME create_app wiring ``create_proof_app`` uses,
    but over lazy (never-connected) engines. Mount-only — asserts the operator +
    configure routers register."""
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.core.mcp_config.materializer import RuntimeConfigMaterializer
    from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigStore
    from cognic_agentos.core.mcp_config.storage import (
        MCPInternalHostAllowlistStore,
        MCPServerUrlOverrideStore,
    )
    from cognic_agentos.packs.storage import PackRecordStore
    from cognic_agentos.portal.api.app import create_app

    def _lazy() -> AsyncEngine:
        return create_async_engine("sqlite+aiosqlite://")

    config_store = PackRuntimeConfigStore(_lazy())
    materializer = RuntimeConfigMaterializer(
        override_store=MCPServerUrlOverrideStore(_lazy()),
        allowlist_store=MCPInternalHostAllowlistStore(_lazy()),
        config_store=config_store,
        vault_reader=_StubVault(),
    )
    return create_app(
        build_settings_without_env_file(),
        actor_binder=MultiActorProofBinder(),
        pack_record_store=PackRecordStore(_lazy()),
        runtime_config_store=config_store,
        runtime_config_materializer=materializer,
    )


class _StubVault:
    async def read(self, path: str) -> None:  # pragma: no cover - never invoked in mount test
        return None


def test_eager_injection_mounts_operator_and_configure_routers() -> None:
    """The crux — with the proof-shaped create_app kwargs, the packs router (author
    + review + operator) AND the configure router mount at body time."""
    app = _proof_shaped_app()
    # configure surface (the M4 configure step).
    assert app.state.configure_router_mounted is True
    assert _has(app, _CONFIGURE_PATH)
    # operator install + reviewer approve + author drafts (the lifecycle the runner drives).
    assert _has(app, _INSTALL_PATH)
    assert _has(app, _APPROVE_PATH)
    assert _has(app, _DRAFTS_PATH)
    # app.state carries the runtime-config collaborators (injection-seam parity).
    assert app.state.runtime_config_store is not None
    assert app.state.runtime_config_materializer is not None


def test_standalone_mcp_write_routes_stay_unmounted_d7() -> None:
    """D7 — the materializer is the SOLE writer of the derived rows; the standalone
    override / allow-list write routes are NOT mounted even with the full M4 wiring."""
    app = _proof_shaped_app()
    assert app.state.mcp_override_router_mounted is False
    assert app.state.mcp_allowlist_router_mounted is False
    assert not _has(app, _OVERRIDE_PATH)
    assert not _has(app, _ALLOWLIST_PATH)
