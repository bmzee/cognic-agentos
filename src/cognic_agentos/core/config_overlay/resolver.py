"""ADR-023 resolver — request-time tighten-only resolution, fail-closed (posture R).

An invalid stored overlay (e.g. a value that loosens a ceiling — possible if the
base Setting was later tightened below a previously-accepted overlay) -> RAISE so
the consumer fails closed, PLUS a throttled ``config.tenant_overlay.invalid_at_read``
AUDIT incident (ISO A.9.2). It is NEVER written through the decision-history
mutation path (that records intended set/cleared mutations) and NEVER silently
falls back to base. Absent overlay -> base. No ObservabilityAdapter (audit + log).
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Protocol

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config_overlay.registry import (
    REGISTRY,
    TenantOverlayRejected,
    overridable_field,
    validate_tighten_only,
)

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings

_LOG = logging.getLogger("cognic_agentos.core.config_overlay.resolver")
_ISO_A_9_2 = "ISO42001.A.9.2"
_INVALID_REQUEST_ID_PREFIX = "cfg-ovl-inv-"  # 12 + 32 hex = 44 <= 64
assert len(_INVALID_REQUEST_ID_PREFIX) + 32 <= 64


class _OverlayStore(Protocol):
    # Return type is Mapping[str, object] — NOT dict[str, int | float] — because the
    # stored value comes from an untrusted GovernanceJSON column that could hold a
    # non-coercible value (DB tampering / a since-corrupted row). The resolver
    # validates every stored value at read time rather than trusting the type
    # (per the evidence-boundary-runtime-validation doctrine).
    async def get_many(
        self, tenant_id: str, field_keys: tuple[str, ...]
    ) -> Mapping[str, object]: ...


class _AuditSink(Protocol):
    async def append(self, event: AuditEvent) -> tuple[uuid.UUID, bytes]: ...


class TenantConfigKeyError(Exception):
    """A consumer asked for a non-overridable field (programming error, fail-closed)."""


class TenantConfigOverlayInvalid(Exception):
    def __init__(self, field_key: str, reason: str) -> None:
        super().__init__(f"{field_key}: {reason}")
        self.field_key = field_key
        self.reason = reason


class TenantConfigResolver:
    def __init__(
        self,
        *,
        store: _OverlayStore,
        base: Settings,
        audit: _AuditSink,
        throttle_s: int,
    ) -> None:
        self._store = store
        self._base = base
        self._audit = audit
        self._throttle_s = throttle_s
        self._last_emit: dict[tuple[str, str, str], tuple[float, object]] = {}

    async def effective(self, field_key: str, tenant_id: str) -> int | float:
        return (await self.effective_many((field_key,), tenant_id))[field_key]

    async def effective_many(
        self, field_keys: tuple[str, ...], tenant_id: str
    ) -> dict[str, int | float]:
        for fk in field_keys:
            if fk not in REGISTRY:
                raise TenantConfigKeyError(fk)
        snapshot = await self._store.get_many(tenant_id, field_keys)  # ONE read -> one snapshot
        out: dict[str, int | float] = {}
        for fk in field_keys:
            field = overridable_field(fk)
            base_value = getattr(self._base, fk)
            if fk not in snapshot:
                out[fk] = base_value
                continue
            stored = snapshot[fk]
            try:
                out[fk] = validate_tighten_only(field, base_value=base_value, proposed=stored)
            except TenantOverlayRejected as exc:
                await self._emit_invalid_at_read(tenant_id, fk, base_value, stored, exc.reason)
                raise TenantConfigOverlayInvalid(fk, exc.reason) from exc
        return out

    async def _emit_invalid_at_read(
        self,
        tenant_id: str,
        field_key: str,
        base_value: object,
        stored: object,
        reason: str,
    ) -> None:
        _LOG.warning(  # unthrottled — every refusal logs
            "config.tenant_overlay.invalid_at_read",
            extra={
                "tenant_id": tenant_id,
                "field_key": field_key,
                "reason": reason,
                "base_value": base_value,
                "stored_value": stored,
            },
        )
        key = (tenant_id, field_key, reason)
        now = time.monotonic()
        prev = self._last_emit.get(key)
        if prev is not None and (now - prev[0]) < self._throttle_s and prev[1] == stored:
            return  # audit row throttled per (tenant_id, field_key, reason) + stored value
        # Fail-closed policy: the audit write is best-effort. If the backend fails,
        # log it but do NOT swallow the refusal — the caller still raises
        # TenantConfigOverlayInvalid so downstream consumers hit their closed-enum
        # mapping. The throttle is updated ONLY on a successful write, so a failed
        # write is retried on the next occurrence (never silently suppressed).
        try:
            await self._audit.append(
                AuditEvent(
                    event_type="config.tenant_overlay.invalid_at_read",
                    request_id=f"{_INVALID_REQUEST_ID_PREFIX}{uuid.uuid4().hex}",
                    tenant_id=tenant_id,
                    iso_controls=(_ISO_A_9_2,),
                    payload={
                        "tenant_id": tenant_id,
                        "field_key": field_key,
                        "reason": reason,
                        "base_value": base_value,
                        "stored_value": stored,
                    },
                )
            )
        except Exception:
            _LOG.exception(
                "config.tenant_overlay.invalid_at_read AUDIT WRITE FAILED",
                extra={"tenant_id": tenant_id, "field_key": field_key, "reason": reason},
            )
            return  # do not update throttle → retry the audit write next occurrence
        self._last_emit[key] = (now, stored)
