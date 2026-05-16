"""Sprint 7B.4 T7 — ElicitationAdapter Protocol + KernelDefault fail-loud scaffold.

Mirrors the Sprint 7B.3 T9 `KernelDefaultTrustRootResolver` precedent
(Protocol + frozen wire-types + fail-loud scaffold). Test surface:

  - `ElicitationMode` 2-value Literal vocabulary
  - `ElicitationContext` + `ElicitationResult` frozen dataclass field
    sets + frozen invariant
  - `ElicitationAdapter` Protocol structural shape (runtime_checkable
    isinstance accept / reject)
  - `KernelDefaultElicitationAdapter.get_context` +
    `.handle_submission` raise `NotImplementedError` pointing at ADR-020
    per the AGENTS.md production-grade rule (no silent in-process
    fallback that pretends to work)
  - `ElicitationBackendError` is a `RuntimeError` subclass (maps to
    `elicitation_backend_failed` ActionRejectionReason at T11)
  - Architectural-arrow invariant — the module imports nothing from
    `portal/`, `fastapi`, or `core/` (pinned by AST scan)
"""

from __future__ import annotations

import ast
import dataclasses
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

import pytest


class TestElicitationModeLiteral:
    def test_2_value_url_form(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationMode

        assert set(get_args(ElicitationMode)) == {"url", "form"}


class TestElicitationContextShape:
    def test_frozen_dataclass(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationContext

        assert dataclasses.is_dataclass(ElicitationContext)
        ctx = ElicitationContext(
            elicitation_id="elc_1",
            tenant_id="t1",
            originating_pack_id="pkg_1",
            originating_decision_record_id=uuid.uuid4(),
            elicitation_modes=("url",),
            data_classes=("public",),
            expires_at=None,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.tenant_id = "t2"  # type: ignore[misc]

    def test_required_fields(self) -> None:
        """7-field set — `expires_at` is the 7th field (Sprint-7B.4 T9 R13 #1
        verified at plan line 2273). Wire-protocol-public; drift breaks
        every adapter that constructs ElicitationContext positionally."""
        from cognic_agentos.protocol.elicitation_adapter import ElicitationContext

        field_names = {f.name for f in dataclasses.fields(ElicitationContext)}
        assert field_names == {
            "elicitation_id",
            "tenant_id",
            "originating_pack_id",
            "originating_decision_record_id",
            "elicitation_modes",
            "data_classes",
            "expires_at",
        }


class TestElicitationResultShape:
    def test_frozen_dataclass(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationResult

        assert dataclasses.is_dataclass(ElicitationResult)
        r = ElicitationResult(
            delivered_at=datetime.now(UTC),
            backend_correlation_id="b_1",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.backend_correlation_id = "other"  # type: ignore[misc]

    def test_required_fields(self) -> None:
        """2-field set. `backend_correlation_id` may be None for adapters
        that don't expose a backend-side correlation handle."""
        from cognic_agentos.protocol.elicitation_adapter import ElicitationResult

        field_names = {f.name for f in dataclasses.fields(ElicitationResult)}
        assert field_names == {"delivered_at", "backend_correlation_id"}


class TestElicitationAdapterProtocol:
    def test_runtime_checkable_accepts_full_implementation(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter

        class Stub:
            async def get_context(self, *, elicitation_id: str, tenant_id: str) -> None:
                pass

            async def handle_submission(
                self, *, ctx: object, mode: object, payload: dict[str, object]
            ) -> None:
                pass

        # @runtime_checkable Protocol — structural-shape isinstance accept.
        assert isinstance(Stub(), ElicitationAdapter)

    def test_missing_method_fails_isinstance(self) -> None:
        """Drop one of the two required methods — isinstance check refuses."""
        from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter

        class Incomplete:
            async def get_context(self, *, elicitation_id: str, tenant_id: str) -> None:
                pass

            # missing handle_submission

        assert not isinstance(Incomplete(), ElicitationAdapter)


class TestKernelDefaultElicitationAdapter:
    @pytest.mark.asyncio
    async def test_get_context_raises_not_implemented_pointing_at_adr(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import (
            KernelDefaultElicitationAdapter,
        )

        adapter = KernelDefaultElicitationAdapter()
        with pytest.raises(NotImplementedError, match="ADR-020"):
            await adapter.get_context(elicitation_id="elc_1", tenant_id="t1")

    @pytest.mark.asyncio
    async def test_handle_submission_raises_not_implemented_pointing_at_adr(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import (
            ElicitationContext,
            KernelDefaultElicitationAdapter,
        )

        adapter = KernelDefaultElicitationAdapter()
        ctx = ElicitationContext(
            elicitation_id="elc_1",
            tenant_id="t1",
            originating_pack_id="pkg_1",
            originating_decision_record_id=uuid.uuid4(),
            elicitation_modes=("url",),
            data_classes=("public",),
            expires_at=None,
        )
        with pytest.raises(NotImplementedError, match="ADR-020"):
            await adapter.handle_submission(ctx=ctx, mode="url", payload={})


class TestElicitationBackendError:
    def test_is_runtime_error_subclass(self) -> None:
        """Maps to `elicitation_backend_failed` ActionRejectionReason at
        T11's POST /actions handler. Subclassing RuntimeError lets it
        bubble through the standard exception path until the action
        handler explicitly catches it."""
        from cognic_agentos.protocol.elicitation_adapter import ElicitationBackendError

        assert issubclass(ElicitationBackendError, RuntimeError)


class TestModuleImportsClean:
    """Architectural-arrow invariant — protocol/elicitation_adapter must NOT
    import portal/, fastapi/starlette/sse_starlette, or core/. The module
    is consumed by portal route handlers (T11) + bank-overlay adapters;
    reverse-direction imports would create a circular dependency time
    bomb."""

    def test_no_forbidden_imports(self) -> None:
        src = Path("src/cognic_agentos/protocol/elicitation_adapter.py").read_text()
        tree = ast.parse(src)
        forbidden_roots = {"fastapi", "starlette", "sse_starlette"}
        forbidden_prefixes = (
            "cognic_agentos.portal",
            "cognic_agentos.core",
            "cognic_agentos.protocol.mcp_host",
        )
        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                root = mod.split(".")[0]
                if root in forbidden_roots or any(mod.startswith(p) for p in forbidden_prefixes):
                    offenders.append(f"from {mod} import ...")
            elif isinstance(node, ast.Import):
                for n in node.names:
                    root = n.name.split(".")[0]
                    if root in forbidden_roots or any(
                        n.name.startswith(p) for p in forbidden_prefixes
                    ):
                        offenders.append(f"import {n.name}")
        assert not offenders, (
            f"protocol/elicitation_adapter.py architectural-arrow violation: {offenders}"
        )
