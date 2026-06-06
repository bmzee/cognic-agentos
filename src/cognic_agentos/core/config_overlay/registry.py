"""ADR-023 — closed, default-deny registry + STRICT tighten-only validator.

Strictness matters: bool is an int subclass and int(2.5) truncates, so coercion must
reject bool and reject fractional values for int fields rather than silently accept them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

from cognic_agentos.core.config import _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS

OverlayDirection = Literal["ceiling", "floor"]

OverlayRefusalReason = Literal[
    "tenant_overlay_field_not_overridable",
    "tenant_overlay_value_not_coercible",
    "tenant_overlay_loosens_ceiling",
    "tenant_overlay_below_base_floor",
    "tenant_overlay_below_kernel_floor",
    "tenant_overlay_ceiling_not_positive",
]


class TenantOverlayRejected(Exception):
    def __init__(self, reason: OverlayRefusalReason) -> None:
        super().__init__(reason)
        self.reason: OverlayRefusalReason = reason


@dataclass(frozen=True, slots=True)
class OverridableField:
    key: str
    direction: OverlayDirection
    value_type: type[int] | type[float]
    kernel_floor: int | float | None


REGISTRY: dict[str, OverridableField] = {
    "sandbox_per_tenant_max_cpu": OverridableField(
        "sandbox_per_tenant_max_cpu", "ceiling", float, None
    ),
    "sandbox_per_tenant_max_memory": OverridableField(
        "sandbox_per_tenant_max_memory", "ceiling", int, None
    ),
    "sandbox_per_tenant_max_walltime": OverridableField(
        "sandbox_per_tenant_max_walltime", "ceiling", float, None
    ),
    "memory_export_retention_seconds": OverridableField(
        "memory_export_retention_seconds",
        "floor",
        int,
        kernel_floor=_MEMORY_EXPORT_RETENTION_FLOOR_SECONDS,
    ),
}


def overridable_field(field_key: str) -> OverridableField:
    field = REGISTRY.get(field_key)
    if field is None:
        raise TenantOverlayRejected("tenant_overlay_field_not_overridable")
    return field


def coerce_value(field: OverridableField, proposed: object) -> int | float:
    if isinstance(proposed, bool):  # bool is an int subclass — never accept
        raise TenantOverlayRejected("tenant_overlay_value_not_coercible")
    try:
        as_float = float(proposed)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise TenantOverlayRejected("tenant_overlay_value_not_coercible") from None
    if not math.isfinite(as_float):  # nan/inf/-inf slip past tighten-only compares + leak int()
        raise TenantOverlayRejected("tenant_overlay_value_not_coercible")
    if field.value_type is int:
        if as_float != int(as_float):  # reject fractional for int fields (no silent truncation)
            raise TenantOverlayRejected("tenant_overlay_value_not_coercible")
        return int(as_float)
    return as_float


def validate_tighten_only(
    field: OverridableField, *, base_value: int | float, proposed: object
) -> int | float:
    value = coerce_value(field, proposed)
    if field.direction == "ceiling":
        if value <= 0:
            raise TenantOverlayRejected("tenant_overlay_ceiling_not_positive")
        if value > base_value:
            raise TenantOverlayRejected("tenant_overlay_loosens_ceiling")
    else:  # floor — check kernel floor FIRST (more fundamental than base)
        if field.kernel_floor is not None and value < field.kernel_floor:
            raise TenantOverlayRejected("tenant_overlay_below_kernel_floor")
        if value < base_value:
            raise TenantOverlayRejected("tenant_overlay_below_base_floor")
    return value
