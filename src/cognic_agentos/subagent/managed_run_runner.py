"""ManagedRunChildRunner — the default ChildRunner: a child sub-agent runs as a
governed managed run (ADR-005 + ADR-022). On-gate (subagent/ stop-rule + the
live-dispatch enforcement surface). Imports core/run TYPES + a consumer-owned
executor Protocol seam (the real ManagedRunExecutor structurally conforms), so
subagent/ stays decoupled from the executor's construction."""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal, Protocol

from cognic_agentos.core.run.executor import RunRequest, RunResult
from cognic_agentos.subagent._types import ChildResult, ChildRunContext


class _ManagedRunExecutorSeam(Protocol):
    async def run(self, request: RunRequest) -> RunResult: ...


class _PackStoreSeam(Protocol):
    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int,
        cursor: uuid.UUID | None = ...,
        # Narrow Literal (NOT `str | None`): the concrete PackRecordStore takes
        # `PackState | None`, which structurally conforms to this (a supertype of
        # the seam's param) but NOT to a broad `str | None`. Decoupled (no PackState import).
        state: Literal["installed"] | None = ...,
    ) -> list[Any]: ...


# Page size for the exact tenant-scoped pack lookup; mirrors the
# PackStoreStateInterrogator pagination idiom.
_PACK_LOOKUP_PAGE: int = 200


class ManagedRunChildRunner:
    """Adapts ChildRunContext -> RunRequest -> ManagedRunExecutor.run. Fail-closed
    on a missing managed_run spec or an ambiguous pack identity."""

    def __init__(self, *, executor: _ManagedRunExecutorSeam, pack_store: _PackStoreSeam) -> None:
        self._executor = executor
        self._pack_store = pack_store

    async def run(self, context: ChildRunContext) -> ChildResult:
        spec = context.managed_run
        actor = context.actor  # locals so the guard narrows both to non-None for mypy
        if spec is None or actor is None:
            return ChildResult(
                summary=(
                    "managed_run spec or actor missing (prompt/tools-only child "
                    "unsupported by the managed-run runner this slice)"
                ),
                tokens_used=0,
                wall_time_used_s=0.0,
                ok=False,
            )
        pack_uuid = await self._resolve_pack_uuid(context.tenant_id, spec.pack_id)
        if pack_uuid is None:
            return ChildResult(
                summary=(
                    f"pack identity unresolved for tenant={context.tenant_id} "
                    f"pack_id={spec.pack_id} (zero or multiple installed matches)"
                ),
                tokens_used=0,
                wall_time_used_s=0.0,
                ok=False,
            )
        request = RunRequest(
            tenant_id=context.tenant_id,
            pack_id=spec.pack_id,
            pack_uuid=pack_uuid,
            # P1: caller-provided (PackRecord has no version column)
            pack_version=spec.pack_version,
            argv=spec.argv,
            actor=actor,  # P1: required at executor.py:158; narrowed to Actor by the guard above
            parent_task_id=context.parent_task_id,
            requested_estimated_tokens=context.requested_estimated_tokens,
        )
        started = time.monotonic()
        result = await self._executor.run(request)
        elapsed = time.monotonic() - started
        ok = result.terminal_state == "completed" and result.exit_code == 0
        summary = f"run={result.run_id} state={result.terminal_state} exit={result.exit_code}"
        if result.terminal_state == "suspended":
            summary = "suspended_child_unsupported"
        elif result.terminal_state == "pending_approval":
            # High-risk child pended at sandbox admission; the async child-approval
            # resume loop is a non-goal this slice (spec §4).
            summary = "pending_approval_child_unsupported"
        return ChildResult(summary=summary, tokens_used=0, wall_time_used_s=elapsed, ok=ok)

    async def _resolve_pack_uuid(self, tenant_id: str, pack_id: str) -> uuid.UUID | None:
        """Exact tenant-scoped lookup over installed packs — resolves ONLY the
        pack_uuid (row id). Zero AND multiple matches both fail closed (return
        None) — no caller UUID-threading, no ambiguity. pack_version is NOT
        resolved (PackRecord has no version column); the caller supplies it via
        ManagedRunChildSpec.pack_version. Paginates so a target past the first
        page is still found."""
        matches: list[Any] = []
        cursor: uuid.UUID | None = None
        while True:
            page = await self._pack_store.list_for_tenant(
                tenant_id, limit=_PACK_LOOKUP_PAGE, cursor=cursor, state="installed"
            )
            matches.extend(r for r in page if r.pack_id == pack_id)
            if len(matches) > 1:
                return None  # ambiguous — fail closed early
            if len(page) < _PACK_LOOKUP_PAGE:
                break
            cursor = page[-1].id
        if len(matches) != 1:
            return None
        resolved: uuid.UUID = matches[0].id
        return resolved
