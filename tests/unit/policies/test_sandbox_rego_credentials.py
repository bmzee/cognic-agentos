"""Sprint 10 T8 — ``policies/_default/sandbox.rego`` rule 6 — per-tenant
max credential TTL cap.

Direct-OPA matrix mirroring ``tests/unit/policies/test_sandbox_rego.py``
(Sprint-8A T11). Skipped on systems without the ``opa`` binary on PATH;
the non-OPA path is covered by the ``AsyncMock(OPAEngine)`` matrix at
``tests/unit/sandbox/test_admission_pipeline.py``.

This suite is the PRODUCTION-grade smoke for rule 6 — it shells out to
the real OPA binary through ``OPAEngine.evaluate`` and pins the
TTL-cap decision matrix end-to-end (no AsyncMock between the test +
the runtime). Without it, a Rego-syntax regression in rule 6 (e.g.
inverting the comparison, breaking the ``every`` quantifier, deleting
the ``is_number`` type guard) would go undetected until the first
admission with a dynamic-lease declaration.

Decision matrix covered (per spec §5.1 + §5.2 + the T8 plan-patch
positive-conjunction style):

* allow when ``requires_credentials[*].ttl_s ≤ kernel_default``
* refuse when any ``requires_credentials[*].ttl_s > kernel_default``
* tenant-overlay raise: ``ttl_s ≤ tenant.overlay.max_credential_ttl_s``
  passes even when above the kernel default
* tenant-overlay cap: ``ttl_s > tenant.overlay.max_credential_ttl_s``
  still refuses (overlay raise doesn't bypass the cap; bank overlays
  may TIGHTEN but not bypass)
* empty ``requires_credentials`` list (T7 backward-compat callers) is
  vacuously satisfied — Rego ``every`` over an empty collection holds
* PURE-Rego type-check defence-in-depth (Sprint-8A T11 R2-R3 contract):
  malformed ``ttl_s`` types (string instead of number) refuse
  fail-closed without an NPE
* ``every`` semantics: a list with one OK + one over-cap entry MUST
  refuse the WHOLE policy (rule 5's egress-list equivalent at
  test_sandbox_rego.py:347-364 is the pattern we mirror)
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip the direct-OPA smoke; the "
    "Stage-2 admission unit-test suite covers the Rego dispatch matrix "
    "via AsyncMock at tests/unit/sandbox/test_admission_pipeline.py",
)


SANDBOX_DECISION_POINT = "data.cognic.sandbox.admit.allow"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair so the engine's ``policy.bundle_loaded`` +
    ``policy.decision_evaluated`` audit emits don't error.

    Mirrors the canonical pattern at
    ``tests/unit/policies/test_sandbox_rego.py:61-92`` (Sprint-8A T11).
    Seeds both chain heads with the canonical :data:`ZERO_HASH` at
    sequence 0 so the per-evaluate hash-chain append has a parent.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'sandbox_rego_credentials_test.db'}"
    sa_engine = create_async_engine(url)
    async with sa_engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    audit = AuditStore(sa_engine)
    dh = DecisionHistoryStore(sa_engine)
    yield await OPAEngine.create(
        bundle_path=Path("policies/_default/sandbox.rego"),
        audit_store=audit,
        decision_history_store=dh,
    )
    await sa_engine.dispose()


def _safe_allow_input_with_credentials(
    *,
    ttl_s: int,
    tenant_overlay_max: int | None = None,
    kernel_default_max: int = 900,
) -> dict[str, Any]:
    """Happy-path admission input + one credential request.

    Mirrors :func:`tests.unit.policies.test_sandbox_rego._safe_allow_input`
    shape so the rest of the ``allow if`` conjunction passes; the only
    knob each test exercises is the TTL cap arm.

    The ``tenant`` key is OMITTED entirely when ``tenant_overlay_max``
    is None — matches the Wave-1 ``sandbox/admission.py`` wire shape
    per spec §5.2 (admission.py omits ``tenant.overlay``; the Rego
    ``else`` branch falls back to ``kernel_default.max_credential_ttl_s``).
    """
    payload: dict[str, Any] = {
        "pack_context": {
            "risk_tier": "internal_write",
            "declares_dynamic_install": False,
            "profile": "production",
        },
        "policy": {
            "cpu_cores": 0.5,
            "memory_mb": 256,
            "walltime_s": 30,
            "egress_allow_list": ["api.example.com"],
            "vault_path": None,
        },
        "tenant_max": {"cpu_cores": 4.0, "memory_mb": 1024, "walltime_s": 300},
        "credential_adapter_wired": True,
        "runtime_image_in_canonical_set": True,
        "runtime_image_in_tenant_allow_list": False,
        "kernel_default": {"max_credential_ttl_s": kernel_default_max},
        "requires_credentials": [
            {
                "secret_path": "database/creds/x",
                "ttl_s": ttl_s,
                "scope_label": "s",
            }
        ],
    }
    if tenant_overlay_max is not None:
        payload["tenant"] = {
            "overlay": {"max_credential_ttl_s": tenant_overlay_max},
        }
    return payload


@opa_required
class TestSandboxRegoRule6CredentialTTLCap:
    """Direct-OPA matrix for rule 6 — per-tenant max credential TTL.

    Positive-conjunction style matching the bundle's existing
    ``_within_tenant_max`` / ``_credential_precondition_satisfied`` /
    ``_runtime_image_authorised`` / ``_egress_http_only`` helpers
    (Sprint-8A T11). A standalone ``deny[reason]`` would be inert
    because the existing ``allow if { … }`` has no ``count(deny) == 0``
    precondition and the :class:`OPAEngine` wrapper's
    :class:`~cognic_agentos.core.policy.engine.Decision` return surfaces
    only ``allow: bool`` to Python (no ``deny`` set).
    """

    @pytest.mark.asyncio
    async def test_rule_6_admits_when_ttl_under_kernel_default(self, engine: OPAEngine) -> None:
        """``ttl_s`` (600) ≤ kernel default (900) → allow.

        Happy-path arm — pins that the helper participates in the
        ``allow if`` conjunction without inverting the comparison.
        """
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input_with_credentials(ttl_s=600),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_rule_6_refuses_when_ttl_exceeds_kernel_default(self, engine: OPAEngine) -> None:
        """``ttl_s`` (7200) > kernel default (900) → refuse.

        Sprint 10 T9 lifts the Stage-2 mapping into the specific
        closed-enum reason ``sandbox_credential_ttl_exceeds_tenant_max``;
        at T8 the refusal surfaces via the existing
        ``sandbox_policy_rego_denied`` arm at ``admission.py:584-588``.
        """
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input_with_credentials(ttl_s=7200),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_rule_6_respects_tenant_overlay_raise(self, engine: OPAEngine) -> None:
        """Tenant overlay raises cap above kernel default.

        ``ttl_s=1800`` > ``kernel_default=900`` but
        ≤ ``tenant_overlay=3600`` → allow. The bundle's
        ``tenant_max_credential_ttl_s`` helper reads the tenant overlay
        first and falls back to the kernel default via ``else``.
        """
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input_with_credentials(ttl_s=1800, tenant_overlay_max=3600),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_rule_6_refuses_when_ttl_exceeds_tenant_overlay(self, engine: OPAEngine) -> None:
        """Tenant overlay also caps. ``ttl_s=7200`` >
        ``tenant_overlay=3600`` → refuse.

        Overlay raise doesn't bypass the cap — bank overlays may
        TIGHTEN (lower TTL ceiling) but cannot LOOSEN the kernel
        default by exceeding the overlay they themselves set.
        """
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input_with_credentials(ttl_s=7200, tenant_overlay_max=3600),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_rule_6_admits_when_requires_credentials_is_empty(
        self, engine: OPAEngine
    ) -> None:
        """Empty ``requires_credentials`` list (no dynamic-lease
        requests) is vacuously satisfied by the ``every`` quantifier.

        Pinned so T7 backward-compat callers passing the default empty
        list don't trip rule 6 — every Sprint-8A admission path that
        does not declare dynamic-lease requests MUST continue to admit
        on the otherwise-passing conjunction.
        """
        payload = _safe_allow_input_with_credentials(ttl_s=600)
        payload["requires_credentials"] = []
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=payload,
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_rule_6_pure_rego_type_check_defense_in_depth(self, engine: OPAEngine) -> None:
        """Sprint-8A T11 R2-R3 pure-Rego defence-in-depth: malformed
        type at ``ttl_s`` (string instead of number) is REFUSED.

        The ``is_number(cred.ttl_s)`` guard inside the helper means the
        rule's conjunction fails fail-closed without an NPE. Without
        the type guard, Rego's ``"not-an-int" <= 900`` is undefined
        and would silently allow.
        """
        bad = _safe_allow_input_with_credentials(ttl_s=600)
        bad["requires_credentials"][0]["ttl_s"] = "not-an-int"
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=bad,
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_rule_6_refuses_with_mixed_request_list_when_one_exceeds(
        self, engine: OPAEngine
    ) -> None:
        """Pins the ``every`` semantics: a list with one OK + one
        over-cap entry MUST refuse the WHOLE policy.

        Rule 5's egress-list equivalent at ``test_sandbox_rego.py``
        ``test_egress_mixed_list_refused_when_any_entry_is_non_http``
        (lines 347-364) is the pattern we mirror — pins against a
        future regression where the guard checks only the first/last
        entry instead of iterating the full list.
        """
        bad = _safe_allow_input_with_credentials(ttl_s=600)
        bad["requires_credentials"].append(
            {
                "secret_path": "database/creds/y",
                "ttl_s": 7200,
                "scope_label": "s2",
            }
        )
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=bad,
        )
        assert d.allow is False
