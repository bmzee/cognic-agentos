"""Sprint 8A T11 — direct OPA invocation against
``policies/_default/sandbox.rego``.

Validates the Wave-1 sandbox admission bundle's `allow` rule against
the input shape the Stage-2 admission caller assembles per spec §13.
Skipped on systems without OPA installed (CI runs OPA-bearing lanes
by ensuring `opa` is on PATH); the non-OPA path is covered by the
``AsyncMock(OPAEngine)`` matrix at ``tests/unit/sandbox/
test_admission_pipeline.py``.

This suite is the PRODUCTION-grade smoke for the bundle — it shells
out to the real OPA binary through ``OPAEngine.evaluate`` and pins
the decision matrix end-to-end (no AsyncMock between the test + the
runtime). Without it, a Rego-syntax regression (e.g. accidentally
inverting a rule, mis-naming the package or decision point, deleting
``default allow := false``) would go undetected until the first
sandbox-admission deployment.

Decision matrix covered (per spec §13 + T11 implementation notes
recording the rule-4 patch):

* default-deny baseline (no input → deny)
* allow on ``{read_only, internal_write}`` tier + within tenant max
  + credential precondition + runtime_image authorised
* refuse on all 6 high-risk tiers unconditionally (pre-Sprint-13.5;
  no escalation-token bypass per spec round-1 P2)
* refuse on ``policy.vault_path`` set + credential adapter NOT wired
* refuse on policy exceeding tenant max (cpu / memory / walltime)
* refuse on runtime_image not in canonical catalog AND not in
  tenant allow-list (defence-in-depth with §6.1 step 6;
  the rule-4 patch documented in the T11 implementation notes)
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

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
    decision_history pair so the engine's `policy.bundle_loaded` +
    `policy.decision_evaluated` audit emits don't error.

    Mirrors the canonical pattern at
    ``tests/unit/policies/test_elicitation_rego.py`` (Sprint-7B.4 T8).
    Seeds both chain heads with the canonical :data:`ZERO_HASH` at
    sequence 0 so the per-evaluate hash-chain append has a parent.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'sandbox_rego_test.db'}"
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


def _safe_allow_input(
    *,
    risk_tier: str = "internal_write",
    cpu_cores: float = 0.5,
    memory_mb: int = 256,
    walltime_s: int = 30,
    vault_path: str | None = None,
    credential_adapter_wired: bool = True,
    runtime_image_in_canonical_set: bool = True,
    runtime_image_in_tenant_allow_list: bool = False,
    egress_allow_list: list[str] | None = None,
    tenant_max: dict[str, float | int] | None = None,
) -> dict[str, object]:
    """Construct a happy-path admission input dict; each test arm
    overrides one field to exercise its refusal path. Default tenant
    max is generous enough to accommodate the default policy values."""
    if tenant_max is None:
        tenant_max = {"cpu_cores": 4.0, "memory_mb": 1024, "walltime_s": 300}
    if egress_allow_list is None:
        egress_allow_list = ["api.example.com"]
    return {
        "pack_context": {
            "risk_tier": risk_tier,
            "declares_dynamic_install": False,
            "profile": "production",
        },
        "policy": {
            "cpu_cores": cpu_cores,
            "memory_mb": memory_mb,
            "walltime_s": walltime_s,
            "egress_allow_list": egress_allow_list,
            "vault_path": vault_path,
        },
        "tenant_max": tenant_max,
        "credential_adapter_wired": credential_adapter_wired,
        "runtime_image_in_canonical_set": runtime_image_in_canonical_set,
        "runtime_image_in_tenant_allow_list": runtime_image_in_tenant_allow_list,
    }


@opa_required
class TestSandboxRegoDecisionMatrix:
    """Direct-OPA decision matrix per spec §13 + the rule-4 patch
    recorded in the T11 implementation-notes block of the Sprint-8A
    plan-of-record."""

    @pytest.mark.asyncio
    async def test_default_deny_baseline(self, engine: OPAEngine) -> None:
        """``data.cognic.sandbox.admit.allow`` defaults to ``false``
        per ADR-015 default-deny. Empty input → deny."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input={},
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_internal_write_with_safe_policy_allows(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 1: tier ∈ {read_only, internal_write} +
        policy within tenant max + credential precondition satisfied +
        runtime_image authorised → allow."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(risk_tier="internal_write"),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_read_only_with_safe_policy_allows(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 1 — ``read_only`` is the other safe tier
        in the canonical Wave-1 safe-set."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(risk_tier="read_only"),
        )
        assert d.allow is True

    @pytest.mark.parametrize(
        "tier",
        [
            "customer_data_read",
            "customer_data_write",
            "payment_action",
            "regulator_communication",
            "cross_tenant",
            "high_risk_custom",
        ],
    )
    @pytest.mark.asyncio
    async def test_high_risk_tier_refused_unconditionally_pre_13_5(
        self, engine: OPAEngine, tier: str
    ) -> None:
        """Per spec §13 rule 2 — all 6 high-risk tiers refuse
        fail-closed pre-13.5; NO escalation-token bypass (spec
        round-1 P2 fix). Even with otherwise-passing policy +
        credential + runtime_image conditions, the rule refuses.
        """
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(risk_tier=tier),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_vault_path_with_default_credential_adapter_refused(
        self, engine: OPAEngine
    ) -> None:
        """Per spec §13 rule 3 — defence-in-depth with §6.1 step 3
        admission check. ``vault_path`` set + ``credential_adapter_wired``
        is false → refuse."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(
                vault_path="secret/data/example",
                credential_adapter_wired=False,
            ),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_vault_path_with_wired_credential_adapter_allows(self, engine: OPAEngine) -> None:
        """The credential-precondition rule is conditional on
        ``credential_adapter_wired``; with the adapter wired the
        precondition is satisfied even when a vault_path is requested.
        """
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(
                vault_path="secret/data/example",
                credential_adapter_wired=True,
            ),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_policy_exceeds_tenant_max_cpu_refused(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 1 — the tenant-max cap check refuses any
        policy exceeding the CPU axis. The three axes are pinned in
        separate test methods rather than parametrise + `**kwargs`
        because strict mypy cannot statically resolve the
        ``dict[str, object]`` unpack against the typed helper
        signature; explicit kwargs keep the call type-safe."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(cpu_cores=8.0),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_policy_exceeds_tenant_max_memory_refused(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 1 — memory axis (companion to the CPU +
        walltime arms above/below)."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(memory_mb=4096),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_policy_exceeds_tenant_max_walltime_refused(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 1 — walltime axis (third of three
        tenant-max axes; explicit per-axis methods keep the call
        sites type-safe under strict mypy)."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(walltime_s=9000),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_runtime_image_not_in_catalog_nor_tenant_allow_list_refused(
        self, engine: OPAEngine
    ) -> None:
        """Per spec §13 rule 4 (T11 implementation-notes patch) —
        defence-in-depth with §6.1 step 6 catalog-membership check.
        Refuse if ``runtime_image_in_canonical_set`` is false AND
        ``runtime_image_in_tenant_allow_list`` is false."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(
                runtime_image_in_canonical_set=False,
                runtime_image_in_tenant_allow_list=False,
            ),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_runtime_image_in_tenant_allow_list_allows(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 4 + spec §6.1 step 6 — tenant allow-list
        is the bank-overlay escape hatch for non-canonical images. A
        runtime image NOT in the canonical catalog but IN the tenant
        allow-list passes the rule-4 check."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(
                runtime_image_in_canonical_set=False,
                runtime_image_in_tenant_allow_list=True,
            ),
        )
        assert d.allow is True

    @pytest.mark.parametrize(
        "non_http_entry",
        [
            "ftp://files.example.com",
            "ssh://shell.example.com",
            "gopher://gopher.example.com",
            "file:///etc/passwd",
        ],
    )
    @pytest.mark.asyncio
    async def test_egress_with_non_http_scheme_refused(
        self, engine: OPAEngine, non_http_entry: str
    ) -> None:
        """Per spec §13 rule 5 (PURE-Rego defence-in-depth) + spec
        §2.1 doctrinal lock — Wave-1 sandbox egress is HTTP/HTTPS
        only. A future caller that bypasses Stage-1's
        ``_validate_egress_host`` (direct OPA eval, refactor, or
        a fresh admission path that forgets to call
        ``validate_policy_shape``) must still be refused by the
        wire-public bundle. Reviewer reproduction case:
        ``["ftp://files.example.com"]`` returned allow=true before
        this guard landed."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(egress_allow_list=[non_http_entry]),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_egress_with_http_scheme_allows(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 5 — explicit ``http://`` scheme passes
        the guard (positive arm; companion to the four-scheme
        negative-arm matrix above)."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(egress_allow_list=["http://api.example.com"]),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_egress_with_https_scheme_allows(self, engine: OPAEngine) -> None:
        """Per spec §13 rule 5 — explicit ``https://`` scheme also
        passes (Wave-1 §2.1 doctrinal lock permits both HTTP and
        HTTPS; this is the production-default scheme)."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(egress_allow_list=["https://api.example.com"]),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_egress_mixed_list_refused_when_any_entry_is_non_http(
        self, engine: OPAEngine
    ) -> None:
        """Per spec §13 rule 5 — the guard refuses the WHOLE policy
        if ANY single entry carries a non-HTTP/HTTPS scheme. Pinned
        to prevent a future regression where the guard checks only
        the first/last entry instead of iterating the full list."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(
                egress_allow_list=[
                    "api.example.com",
                    "https://safe.example.com",
                    "ftp://sneaky.example.com",
                ],
            ),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_egress_empty_list_allows(self, engine: OPAEngine) -> None:
        """An empty egress_allow_list is acceptable — the caller
        explicitly opts out of all egress. Pinned so future strict
        amendments to the guard don't accidentally demand at least
        one entry."""
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=_safe_allow_input(egress_allow_list=[]),
        )
        assert d.allow is True

    # -- Round-2 P1: malformed-shape arms ---------------------------------
    #
    # The PURE-Rego guard MUST refuse fail-closed when egress_allow_list
    # has an invalid runtime shape (the previous round's
    # `_has_non_http_scheme_entry` silently no-op'd on non-string types
    # because `contains(42, "://")` is undefined in Rego). Without
    # `is_array` + per-entry `is_string` checks, the four shapes below
    # all returned allow=true. Each test below builds the input dict
    # by hand (mutating the helper's output) because the helper's
    # `egress_allow_list: list[str] | None` signature can't express
    # non-string-list shapes without weakening every other call site.

    @pytest.mark.asyncio
    async def test_egress_field_is_bare_string_not_array_refused(self, engine: OPAEngine) -> None:
        """Reviewer round-2 P1 reproduction (a): ``egress_allow_list``
        is a string instead of an array. ``is_array(...)`` is false →
        ``_egress_http_only`` doesn't match → allow=False."""
        bad = _safe_allow_input()
        # type-erase via cast to a less-typed view; the bundle is
        # the system-under-test, not Python's type system. Wire-level
        # input may carry any JSON shape.
        bad_policy = cast(dict[str, object], bad["policy"])
        bad_policy["egress_allow_list"] = "ftp://files.example.com"
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=bad,
        )
        assert d.allow is False

    @pytest.mark.parametrize(
        ("non_string_entry", "label"),
        [
            (42, "int"),
            (None, "null"),
            ({"url": "ftp://files.example.com"}, "object"),
            (["https://api.example.com"], "nested_array"),
            (True, "bool"),
        ],
    )
    @pytest.mark.asyncio
    async def test_egress_list_with_non_string_entry_refused(
        self, engine: OPAEngine, non_string_entry: object, label: str
    ) -> None:
        """Reviewer round-2 P1 reproductions (b, c, d) + two extras
        (bool + nested array). Each entry-type that isn't a string
        MUST refuse, because the per-entry ``contains`` / ``startswith``
        ops silently no-op on non-string types without an
        ``is_string`` precondition. ``label`` keeps the parametrize
        ids stable (dict / list entry literals stringify
        unpredictably across Python versions)."""
        del label  # naming hint only; consumed by parametrize ids
        bad = _safe_allow_input()
        bad_policy = cast(dict[str, object], bad["policy"])
        bad_policy["egress_allow_list"] = [non_string_entry]
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=bad,
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_egress_list_with_one_valid_string_and_one_non_string_refused(
        self, engine: OPAEngine
    ) -> None:
        """Mixed-shape companion to the all-non-string parametrize
        matrix. A list with even ONE non-string entry MUST refuse
        — pins against a future regression where the guard checks
        only the first entry or skips entries that fail
        ``is_string``."""
        bad = _safe_allow_input()
        bad_policy = cast(dict[str, object], bad["policy"])
        bad_policy["egress_allow_list"] = ["https://api.example.com", 42]
        d = await engine.evaluate(
            decision_point=SANDBOX_DECISION_POINT,
            input=bad,
        )
        assert d.allow is False
