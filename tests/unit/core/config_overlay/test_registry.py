import typing

import pytest

from cognic_agentos.core.config import _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS, Settings
from cognic_agentos.core.config_overlay.registry import (
    REGISTRY,
    OverlayDirection,
    OverlayRefusalReason,
    TenantOverlayRejected,
    overridable_field,
    validate_tighten_only,
)


def test_registry_has_exactly_four_keys():
    assert set(REGISTRY) == {
        "sandbox_per_tenant_max_cpu",
        "sandbox_per_tenant_max_memory",
        "sandbox_per_tenant_max_walltime",
        "memory_export_retention_seconds",
    }


def test_overlay_direction_closed_enum():
    assert set(typing.get_args(OverlayDirection)) == {"ceiling", "floor"}


def test_refusal_reason_closed_enum_six_values():
    assert set(typing.get_args(OverlayRefusalReason)) == {
        "tenant_overlay_field_not_overridable",
        "tenant_overlay_value_not_coercible",
        "tenant_overlay_loosens_ceiling",
        "tenant_overlay_below_base_floor",
        "tenant_overlay_below_kernel_floor",
        "tenant_overlay_ceiling_not_positive",
    }


def test_unknown_field_rejected():
    with pytest.raises(TenantOverlayRejected) as e:
        overridable_field("require_cosign")
    assert e.value.reason == "tenant_overlay_field_not_overridable"


def test_ceiling_accepts_le_base_rejects_gt():
    f = REGISTRY["sandbox_per_tenant_max_cpu"]  # ceiling, float
    assert validate_tighten_only(f, base_value=4.0, proposed="2.0") == 2.0
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=4.0, proposed="8.0")
    assert e.value.reason == "tenant_overlay_loosens_ceiling"


def test_ceiling_rejects_non_positive():
    f = REGISTRY["sandbox_per_tenant_max_cpu"]
    for bad in ("0", "-1"):
        with pytest.raises(TenantOverlayRejected) as e:
            validate_tighten_only(f, base_value=4.0, proposed=bad)
        assert e.value.reason == "tenant_overlay_ceiling_not_positive"


def test_floor_kernel_floor_checked_BEFORE_base_floor():
    # base == kernel_floor: a sub-floor value reports below_kernel_floor (more fundamental).
    f = REGISTRY["memory_export_retention_seconds"]  # floor, int, kernel_floor=7yr
    base = _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS
    assert validate_tighten_only(f, base_value=base, proposed=str(base + 1)) == base + 1
    with pytest.raises(TenantOverlayRejected) as e:  # below base (raised base) but >= kernel floor
        validate_tighten_only(f, base_value=base + 100, proposed=str(base + 50))
    assert e.value.reason == "tenant_overlay_below_base_floor"
    with pytest.raises(TenantOverlayRejected) as e2:  # below BOTH; kernel floor wins
        validate_tighten_only(f, base_value=base, proposed=str(base - 1))
    assert e2.value.reason == "tenant_overlay_below_kernel_floor"


def test_strict_coercion_rejects_bool():
    f = REGISTRY["sandbox_per_tenant_max_memory"]  # int
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=2048, proposed=True)  # bool is an int subclass — reject
    assert e.value.reason == "tenant_overlay_value_not_coercible"


def test_strict_coercion_rejects_fractional_for_int_field():
    f = REGISTRY["sandbox_per_tenant_max_memory"]  # int — 2.5 must NOT silently truncate to 2
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=2048, proposed=2.5)
    assert e.value.reason == "tenant_overlay_value_not_coercible"


def test_non_coercible_string_rejected():
    f = REGISTRY["sandbox_per_tenant_max_memory"]
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=2048, proposed="not-a-number")
    assert e.value.reason == "tenant_overlay_value_not_coercible"


def test_rejects_non_finite_for_float_field():
    # nan slips past `<=` / `>` comparisons (both False) and would return nan;
    # inf/-inf mis-route to loosens/ceiling_not_positive. All must be non-coercible.
    f = REGISTRY["sandbox_per_tenant_max_cpu"]  # ceiling, float
    for bad in ("nan", "inf", "-inf"):
        with pytest.raises(TenantOverlayRejected) as e:
            validate_tighten_only(f, base_value=4.0, proposed=bad)
        assert e.value.reason == "tenant_overlay_value_not_coercible"


def test_rejects_non_finite_for_int_field():
    # int(float("nan")) -> ValueError, int(float("inf")) -> OverflowError must NOT leak;
    # the finite guard maps them to the closed taxonomy.
    f = REGISTRY["sandbox_per_tenant_max_memory"]  # ceiling, int
    for bad in ("nan", "inf", "-inf"):
        with pytest.raises(TenantOverlayRejected) as e:
            validate_tighten_only(f, base_value=2048, proposed=bad)
        assert e.value.reason == "tenant_overlay_value_not_coercible"


def test_lock_assertion_do_not_configure_invariants_absent_from_registry():
    from cognic_agentos.core.config import _SECRET_VAULT_FIELDS

    locked = {
        "require_cosign",
        "runtime_profile",
        "cosign_path",
        "evidence_pack_signing_key_path",
        *_SECRET_VAULT_FIELDS,
    }
    assert locked.isdisjoint(set(REGISTRY))


def test_every_registry_key_is_a_real_settings_field():
    s = Settings(runtime_profile="dev")
    for key in REGISTRY:
        assert hasattr(s, key)
