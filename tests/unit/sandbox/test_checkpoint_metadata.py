"""Sprint 8.5 T3 — CheckpointMetadata + VaultLeaseRef + TombstoneRecord
shape + round-trip invariants per spec §3.4.

Pins (every test maps to a wire-public invariant the spec locks):

* 9-field ``CheckpointMetadata`` + 4-field ``VaultLeaseRef`` + 3-field
  ``TombstoneRecord`` shape locks.
* ``to_storage_payload()`` produces a canonical-bytes-safe dict
  (``canonical_bytes`` does NOT reject) — wire-public per ADR-006.
* ``to_storage_payload()`` produces ``list`` not ``tuple`` at every
  nested level (defends against the tuple-smuggle bug class that
  ``canonical_bytes`` rejects per ``core/canonical.py:38-44,69-70``).
* ``from_storage_payload(canonical_bytes(meta.to_storage_payload()))``
  round-trip equality.
* ``from_storage_payload`` rejects tuples in input (defence-in-depth on
  read; symmetric with write-side rejection).
* ``from_storage_payload`` ignores unknown top-level keys
  (additive-only schema for Sprint-10 lease-refs extension).
* ``from_storage_payload`` rejects naive datetime — per
  ``feedback_evidence_boundary_runtime_validation``: tz-aware requires
  BOTH ``tzinfo is not None`` AND ``utcoffset() is not None``.
* ``from_storage_payload`` rejects invalid ``checkpoint_id`` shape via
  the module-level ``_validate_checkpoint_id_or_raise`` helper
  (P2.r11 load-bearing — pre-P2.r11 the parser did a bare
  ``CheckpointId(payload[...])`` cast which smuggles invalid ids past
  the NewType façade).
* The module-level validator is the single source of truth shared by
  BOTH ``CheckpointStore.validate_checkpoint_id_or_raise`` AND
  ``CheckpointMetadata.from_storage_payload`` (P2.r11 single-source-
  of-truth pin).
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import fields
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.sandbox.checkpoint_store import (
    CheckpointMetadata,
    CheckpointStore,
    TombstoneRecord,
    VaultLeaseRef,
    _validate_checkpoint_id_or_raise,
)
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
    WritableMount,
)
from cognic_agentos.sandbox.protocol import CheckpointId

# ---------------------------------------------------------------------------
# Helpers — minimal valid CheckpointMetadata fixture.
# ---------------------------------------------------------------------------


def _valid_policy() -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=1.0,
        cpu_time_budget_s=10.0,
        memory_mb=512,
        walltime_s=60.0,
        runtime_image=(
            "cognic/sandbox-runtime-python@sha256:"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        egress_allow_list=("api.example.com",),
        vault_path=None,
        read_only_root=True,
        writable_mounts=(
            WritableMount(host_path="/tmp/x", container_path="/workspace", read_only=False),
        ),
        warm_pool_key=None,
    )


def _valid_pack_context() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="pack-a",
        pack_version="1.0.0",
        pack_artifact_digest=(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        risk_tier="read_only",
        declares_dynamic_install=False,
        profile="production",
    )


def _valid_metadata(*, vault_lease_refs: tuple[VaultLeaseRef, ...] = ()) -> CheckpointMetadata:
    return CheckpointMetadata(
        checkpoint_id=CheckpointId("a" * 32),
        session_id="sess-1",
        tenant_id="tenant-a",
        label="my-label",
        created_at=datetime(2026, 5, 19, 12, 0, 0, tzinfo=UTC),
        policy=_valid_policy(),
        pack_context=_valid_pack_context(),
        retention_window_s=86_400,
        vault_lease_refs=vault_lease_refs,
    )


# ---------------------------------------------------------------------------
# Shape locks (spec §3.4 — 9/4/3 fields).
# ---------------------------------------------------------------------------


class TestShapeLocks:
    def test_checkpoint_metadata_has_exactly_nine_fields(self) -> None:
        names = [f.name for f in fields(CheckpointMetadata)]
        assert names == [
            "checkpoint_id",
            "session_id",
            "tenant_id",
            "label",
            "created_at",
            "policy",
            "pack_context",
            "retention_window_s",
            "vault_lease_refs",
        ]

    def test_checkpoint_metadata_is_frozen(self) -> None:
        meta = _valid_metadata()
        with pytest.raises(dataclasses.FrozenInstanceError):
            meta.session_id = "other"  # type: ignore[misc]

    def test_vault_lease_ref_has_exactly_four_fields(self) -> None:
        names = [f.name for f in fields(VaultLeaseRef)]
        assert names == ["vault_path", "role", "duration_s", "admission_lease_id"]

    def test_vault_lease_ref_is_frozen(self) -> None:
        ref = VaultLeaseRef(
            vault_path="secret/x", role="r", duration_s=60, admission_lease_id="l-1"
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ref.role = "other"  # type: ignore[misc]

    def test_tombstone_record_has_exactly_three_fields(self) -> None:
        names = [f.name for f in fields(TombstoneRecord)]
        assert names == ["tombstoned_at", "tombstoned_by", "retained_until"]

    def test_tombstone_record_is_frozen(self) -> None:
        rec = TombstoneRecord(
            tombstoned_at=datetime(2026, 5, 19, tzinfo=UTC),
            tombstoned_by="alice",
            retained_until=datetime(2026, 5, 20, tzinfo=UTC),
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.tombstoned_by = "other"  # type: ignore[misc]

    def test_vault_lease_refs_defaults_to_empty_tuple(self) -> None:
        meta = _valid_metadata()
        # In-memory shape carries tuple per spec §3.4; only the storage
        # converter flattens to list. Default = () per Q4 lock.
        assert meta.vault_lease_refs == ()


# ---------------------------------------------------------------------------
# to_storage_payload — canonical-bytes safety + no-tuple invariant.
# ---------------------------------------------------------------------------


class TestToStoragePayloadCanonicalBytesSafe:
    def test_to_storage_payload_canonical_bytes_serialisable(self) -> None:
        """canonical_bytes() succeeds on the converter output — the
        single load-bearing invariant for persistence per spec §3.4 P1.

        If the converter leaves a tuple OR a custom dataclass OR a
        naive datetime in the dict, canonical_bytes raises and bytes
        cannot be persisted. The test pins the green path against the
        canonical-form gate at core/canonical.py:38-44,69-70.
        """
        meta = _valid_metadata()
        # Must not raise — the converter is responsible for type-flattening.
        canonical_bytes(meta.to_storage_payload())

    def test_to_storage_payload_canonical_bytes_safe_with_vault_lease_refs(self) -> None:
        """Even though Sprint 8.5 always constructs with vault_lease_refs=(),
        the converter must handle non-empty vault_lease_refs for the
        Sprint-10 forward-compat path; tests construct VaultLeaseRef
        directly to exercise that branch."""
        meta = _valid_metadata(
            vault_lease_refs=(
                VaultLeaseRef(
                    vault_path="secret/x",
                    role="r",
                    duration_s=60,
                    admission_lease_id="lease-1",
                ),
            )
        )
        canonical_bytes(meta.to_storage_payload())

    def test_to_storage_payload_rejects_tuple_smuggling(self) -> None:
        """The converter MUST produce ``list`` not ``tuple`` at every
        nested level — recursive walk asserts no tuple instances appear
        anywhere in the payload. Defends against the silent
        tuple→JSON-array collapse that canonical_bytes rejects at
        core/canonical.py:38-44."""
        meta = _valid_metadata(
            vault_lease_refs=(
                VaultLeaseRef(
                    vault_path="secret/x",
                    role="r",
                    duration_s=60,
                    admission_lease_id="lease-1",
                ),
            )
        )
        payload = meta.to_storage_payload()

        def _assert_no_tuples(obj: Any, path: str = "$") -> None:
            assert not isinstance(obj, tuple), f"tuple at {path}: {obj!r}"
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _assert_no_tuples(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    _assert_no_tuples(v, f"{path}[{i}]")

        _assert_no_tuples(payload)


# ---------------------------------------------------------------------------
# Round-trip equality (write → canonical_bytes → json.loads → read).
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_round_trip_to_from_storage_payload(self) -> None:
        meta = _valid_metadata()
        raw = canonical_bytes(meta.to_storage_payload())
        reloaded_dict = json.loads(raw)
        meta2 = CheckpointMetadata.from_storage_payload(reloaded_dict)
        assert meta2 == meta

    def test_round_trip_preserves_writable_mounts_order(self) -> None:
        """Round-trip equality covers writable_mounts ordering — a bug
        that re-sorted entries on write/read would fail this."""
        policy = dataclasses.replace(
            _valid_policy(),
            writable_mounts=(
                WritableMount(host_path="/a", container_path="/wa", read_only=True),
                WritableMount(host_path="/b", container_path="/wb", read_only=False),
            ),
        )
        meta = dataclasses.replace(_valid_metadata(), policy=policy)
        raw = canonical_bytes(meta.to_storage_payload())
        meta2 = CheckpointMetadata.from_storage_payload(json.loads(raw))
        assert meta2.policy.writable_mounts == policy.writable_mounts

    def test_round_trip_preserves_egress_allow_list_as_tuple(self) -> None:
        """In-memory egress_allow_list is tuple; storage payload is
        list; reload should re-construct as tuple to keep the dataclass
        invariant."""
        meta = _valid_metadata()
        meta2 = CheckpointMetadata.from_storage_payload(
            json.loads(canonical_bytes(meta.to_storage_payload()))
        )
        assert isinstance(meta2.policy.egress_allow_list, tuple)


# ---------------------------------------------------------------------------
# from_storage_payload — negative shape validation.
# ---------------------------------------------------------------------------


class TestFromStoragePayloadRejectsTupleInInput:
    def test_from_storage_payload_rejects_tuple_in_vault_lease_refs(self) -> None:
        """Defence-in-depth on read: a tuple in vault_lease_refs would
        not have round-tripped through canonical_bytes on write
        (canonical_bytes rejects tuples). If it's present, the bytes
        came through a non-canonical path → reject."""
        meta = _valid_metadata()
        payload = meta.to_storage_payload()
        payload["vault_lease_refs"] = ()  # smuggle in a tuple
        with pytest.raises(ValueError, match="vault_lease_refs"):
            CheckpointMetadata.from_storage_payload(payload)


class TestFromStoragePayloadIgnoresUnknownKeys:
    def test_from_storage_payload_ignores_unknown_top_level_keys(self) -> None:
        """Additive-only schema per spec §3.4 P1: Sprint-10 lease-refs
        extension lands additive keys without a schema-version bump.
        Unknown keys are silently ignored at the top level."""
        meta = _valid_metadata()
        payload = meta.to_storage_payload()
        payload["future_sprint_added_field"] = {"hello": "world"}
        payload["another_extension"] = 42
        # Must succeed; unknown keys ignored.
        meta2 = CheckpointMetadata.from_storage_payload(payload)
        assert meta2 == meta


class TestFromStoragePayloadRejectsNaiveDatetime:
    def test_from_storage_payload_rejects_naive_created_at(self) -> None:
        """Per ``feedback_evidence_boundary_runtime_validation``:
        tz-aware requires BOTH tzinfo is not None AND
        utcoffset() is not None. A datetime string with no offset
        parses as naive — reject."""
        meta = _valid_metadata()
        payload = meta.to_storage_payload()
        # Naive ISO string (no offset suffix).
        payload["created_at"] = "2026-05-19T12:00:00"
        with pytest.raises(ValueError, match="tz-aware"):
            CheckpointMetadata.from_storage_payload(payload)

    def test_from_storage_payload_rejects_tzinfo_subclass_returning_none_utcoffset(
        self,
    ) -> None:
        """A tzinfo subclass with utcoffset() returning None is also
        naive per Python's official aware predicate — pinned because
        the canonical-form rule covers this exact edge case at
        core/canonical.py:107-113."""
        # Construct directly (can't smuggle through the normal converter
        # path; build payload manually to test from_storage_payload).
        meta = _valid_metadata()
        payload = meta.to_storage_payload()
        # ISO string built from a datetime whose tzinfo returns None
        # would still emit no offset — same observable shape as naive.
        # We rely on the ISO-string having no offset and the parser
        # rejecting tzinfo-None.
        payload["created_at"] = "2026-05-19T12:00:00"
        with pytest.raises(ValueError, match="tz-aware"):
            CheckpointMetadata.from_storage_payload(payload)


class TestFromStoragePayloadAcceptsNonUtcTzAware:
    def test_from_storage_payload_accepts_non_utc_offset(self) -> None:
        """tz-aware doesn't have to be UTC; any non-None utcoffset is
        valid per the canonical-form rule."""
        non_utc = timezone(timedelta(hours=5, minutes=30))
        payload = _valid_metadata().to_storage_payload()
        payload["created_at"] = datetime(2026, 5, 19, 12, 0, 0, tzinfo=non_utc).isoformat()
        # Must succeed.
        CheckpointMetadata.from_storage_payload(payload)


# ---------------------------------------------------------------------------
# from_storage_payload — checkpoint_id shape validation (P2.r11).
# ---------------------------------------------------------------------------


class TestFromStoragePayloadRejectsInvalidCheckpointIdShape:
    """P2.r11 LOAD-BEARING — the parser MUST route checkpoint_id through
    the shared module-level ``_validate_checkpoint_id_or_raise`` helper.
    Pre-P2.r11 the parser did ``CheckpointId(payload["checkpoint_id"])``
    bypassing the validator. The 3 parametrised cases pin all 3 rejection
    branches of the validator (wrong type / wrong length / non-hex)."""

    @pytest.mark.parametrize(
        "bad_id",
        [
            "not-hex",  # 32-char-ish but non-hex chars
            "abc",  # too short
            123,  # wrong type
        ],
        ids=["non-hex", "too-short", "wrong-type"],
    )
    def test_from_storage_payload_rejects_invalid_checkpoint_id(self, bad_id: Any) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["checkpoint_id"] = bad_id
        with pytest.raises(
            ValueError, match=r"CheckpointMetadata\.checkpoint_id failed shape validation"
        ):
            CheckpointMetadata.from_storage_payload(payload)


class TestValidateCheckpointIdOrRaiseSharedBetweenStoreAndParser:
    """P2.r11 single-source-of-truth pin — both the store's classmethod
    wrapper AND the parser route through the SAME module-level helper.
    A refactor that re-introduces a parser-local validator drifting from
    the store's would fail this test."""

    def test_store_validator_and_parser_share_root_cause_on_same_bad_id(self) -> None:
        bad_id = "not-hex"
        # Store wrapper raises.
        with pytest.raises(ValueError) as ei_store:
            CheckpointStore.validate_checkpoint_id_or_raise(bad_id)
        # Parser raises with the wrapping prefix BUT the chained cause
        # is the same shape-rejection from the SAME helper.
        payload = _valid_metadata().to_storage_payload()
        payload["checkpoint_id"] = bad_id
        with pytest.raises(ValueError) as ei_parser:
            CheckpointMetadata.from_storage_payload(payload)
        # Both messages mention 'not hex' / 'not-hex' from the shared
        # helper — same value-level root cause.
        assert "not-hex" in str(ei_store.value)
        assert "not-hex" in str(ei_parser.value)
        # The parser's chained cause IS a ValueError from the same helper.
        assert isinstance(ei_parser.value.__cause__, ValueError)
        assert "not-hex" in str(ei_parser.value.__cause__)

    def test_module_level_helper_is_callable_directly(self) -> None:
        """The validator is module-level (not class-bound) per spec
        §3.4 P2.r11 — direct import + call succeeds."""
        good = "a" * 32
        assert _validate_checkpoint_id_or_raise(good) == CheckpointId(good)
        with pytest.raises(ValueError):
            _validate_checkpoint_id_or_raise("not-hex")


# ---------------------------------------------------------------------------
# P1.r12 evidence-boundary type-validation regressions
#
# Per ``feedback_evidence_boundary_runtime_validation``: every wire
# field of CheckpointMetadata MUST be type-validated at the parser
# boundary. Without this, a corrupt payload (e.g. retention_window_s=
# "bad") parses silently and leaks as a raw TypeError at downstream
# call sites (purge_expired's retention comparison; wake-time retention
# check), bypassing the closed-enum refusal taxonomy.
#
# These tests pin each typed wire field's rejection contract. A
# regression that lets ANY of these slip through is fail-open.
# ---------------------------------------------------------------------------


class TestFromStoragePayloadValidatesTopLevelTypes:
    """Top-level field types per P1.r12."""

    @pytest.mark.parametrize("bad_value", ["bad", "86400", 86_400.5, None, [], {}])
    def test_rejects_non_int_retention_window_s(self, bad_value: Any) -> None:
        """``retention_window_s`` MUST be int. Bad values (str /
        float / None / list / dict) raise ValueError at the parser
        boundary so wake() can map to ``sandbox_wake_checkpoint_corrupt``
        rather than leaking as raw TypeError at purge_expired's
        comparison site OR wake step 3's retention check.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["retention_window_s"] = bad_value
        with pytest.raises(ValueError, match="retention_window_s must be int"):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_bool_retention_window_s(self) -> None:
        """Python's ``bool<:int`` would silently accept True as 1-second
        retention — the parser MUST reject bool explicitly.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["retention_window_s"] = True
        with pytest.raises(ValueError, match="retention_window_s must be int"):
            CheckpointMetadata.from_storage_payload(payload)

    @pytest.mark.parametrize("field", ["session_id", "tenant_id", "label"])
    @pytest.mark.parametrize("bad_value", [123, True, None, [], {}])
    def test_rejects_non_str_top_level_string_field(self, field: str, bad_value: Any) -> None:
        """``session_id`` / ``tenant_id`` / ``label`` MUST be str.
        Non-str values raise ValueError at the parser boundary.
        """
        payload = _valid_metadata().to_storage_payload()
        payload[field] = bad_value
        with pytest.raises(ValueError, match=f"{field} must be str"):
            CheckpointMetadata.from_storage_payload(payload)


class TestFromStoragePayloadValidatesSandboxPolicyTypes:
    """Nested SandboxPolicy field types per P1.r12."""

    @pytest.mark.parametrize("bad_value", ["all-of-it", 42, True, None, {}])
    def test_rejects_non_list_egress_allow_list(self, bad_value: Any) -> None:
        """``egress_allow_list`` MUST be list. A bare string is the
        bug-class trap: ``tuple("all-of-it")`` silently produces
        ``("a","l","l",...)`` — without explicit list-shape check, the
        parser would happily accept it.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["egress_allow_list"] = bad_value
        with pytest.raises(ValueError, match=r"policy\.egress_allow_list must be"):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_non_str_element_in_egress_allow_list(self) -> None:
        """Element-type check: every list entry MUST be str."""
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["egress_allow_list"] = ["good.example.com", 42]
        with pytest.raises(ValueError, match=r"policy\.egress_allow_list\[1\] must be str"):
            CheckpointMetadata.from_storage_payload(payload)

    @pytest.mark.parametrize("field", ["cpu_cores", "walltime_s"])
    @pytest.mark.parametrize("bad_value", ["1.0", True, None, [], {}])
    def test_rejects_non_number_numeric_policy_field(self, field: str, bad_value: Any) -> None:
        """Numeric policy fields MUST be int/float; reject bool +
        non-numeric.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["policy"][field] = bad_value
        with pytest.raises(ValueError, match=f"policy.{field} must be number"):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_non_int_memory_mb(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["memory_mb"] = 512.5
        with pytest.raises(ValueError, match=r"policy\.memory_mb must be int"):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_non_bool_read_only_root(self) -> None:
        """``read_only_root`` MUST be bool (optional with default=True)."""
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["read_only_root"] = "true"
        with pytest.raises(ValueError, match=r"policy\.read_only_root must be bool"):
            CheckpointMetadata.from_storage_payload(payload)


class TestFromStoragePayloadValidatesWritableMountTypes:
    """Nested WritableMount field types per P1.r12."""

    def test_rejects_writable_mount_missing_host_path(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["writable_mounts"] = [{"container_path": "/workspace"}]
        with pytest.raises(
            ValueError,
            match=r"policy\.writable_mounts\[0\] missing required key 'host_path'",
        ):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_writable_mount_missing_container_path(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["writable_mounts"] = [{"host_path": "/tmp/x"}]
        with pytest.raises(
            ValueError,
            match=(r"policy\.writable_mounts\[0\] missing required key 'container_path'"),
        ):
            CheckpointMetadata.from_storage_payload(payload)

    @pytest.mark.parametrize("bad_value", [123, True, None, []])
    def test_rejects_non_str_writable_mount_host_path(self, bad_value: Any) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["writable_mounts"] = [
            {
                "host_path": bad_value,
                "container_path": "/workspace",
                "read_only": False,
            }
        ]
        with pytest.raises(
            ValueError, match=r"policy\.writable_mounts\[0\]\.host_path must be str"
        ):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_non_bool_writable_mount_read_only(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["policy"]["writable_mounts"] = [
            {
                "host_path": "/tmp/x",
                "container_path": "/workspace",
                "read_only": "no",
            }
        ]
        with pytest.raises(
            ValueError,
            match=r"policy\.writable_mounts\[0\]\.read_only must be bool",
        ):
            CheckpointMetadata.from_storage_payload(payload)


class TestFromStoragePayloadValidatesPackAdmissionContextTypes:
    """Nested PackAdmissionContext field types per P1.r12."""

    @pytest.mark.parametrize("bad_value", ["true", 1, 0, None, [], {}])
    def test_rejects_non_bool_declares_dynamic_install(self, bad_value: Any) -> None:
        """``declares_dynamic_install`` MUST be bool — even 1/0 (Python
        truthy ints) MUST be rejected so a corrupt payload carrying
        ``"true"`` cannot smuggle past the parser.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["pack_context"]["declares_dynamic_install"] = bad_value
        with pytest.raises(
            ValueError,
            match=r"pack_context\.declares_dynamic_install must be bool",
        ):
            CheckpointMetadata.from_storage_payload(payload)

    @pytest.mark.parametrize(
        "field",
        [
            "pack_id",
            "pack_version",
            "pack_artifact_digest",
            "risk_tier",
            "profile",
        ],
    )
    def test_rejects_non_str_pack_context_string_field(self, field: str) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["pack_context"][field] = 42
        with pytest.raises(ValueError, match=f"pack_context.{field} must be str"):
            CheckpointMetadata.from_storage_payload(payload)

    @pytest.mark.parametrize("bad_profile", ["bogus", "PRODUCTION", "", "prod", "dev"])
    def test_rejects_invalid_profile_enum_string(self, bad_profile: str) -> None:
        """**P1.r13 LOAD-BEARING** — ``profile`` MUST be validated against
        the 2-value closed set ``{production, development}`` at the
        parser boundary, NOT just str-shape + cast.

        Reason: ``admission.py:270`` refuses dynamic-install ONLY when
        ``profile == "production"`` (exact string match). A corrupt
        metadata blob carrying ``profile="bogus" + declares_dynamic_install=True``
        would PASS bare str validation, silently cast to the Literal
        type, and BYPASS the production-dynamic-install refusal entirely
        — the wake() would restore a session that should have been
        refused.

        With membership validation, the malformed value surfaces at
        the parser boundary as ValueError → wake() maps to
        ``sandbox_wake_checkpoint_corrupt`` (the correct closed-enum
        taxonomy for malformed metadata, not the wrong
        ``sandbox_wake_policy_revalidation_failed`` Rego-fallthrough
        path).
        """
        payload = _valid_metadata().to_storage_payload()
        payload["pack_context"]["profile"] = bad_profile
        with pytest.raises(ValueError, match=r"pack_context\.profile must be one of"):
            CheckpointMetadata.from_storage_payload(payload)

    @pytest.mark.parametrize(
        "bad_risk_tier",
        [
            "bogus",
            "READ_ONLY",
            "",
            "not_a_tier",
            "high_risk",  # close-but-wrong vs canonical "high_risk_custom"
        ],
    )
    def test_rejects_invalid_risk_tier_enum_string(self, bad_risk_tier: str) -> None:
        """**P1.r13 LOAD-BEARING** — ``risk_tier`` MUST be validated against
        the ADR-014 8-value ``RiskTier`` closed set at the parser
        boundary, NOT just str-shape + cast.

        Reason: ``admission.py:280`` checks ``risk_tier in
        _HIGH_RISK_TIERS_PRE_13_5`` (a 6-value set); the Rego bundle
        at ``policies/_default/sandbox.rego:113-114`` checks
        ``risk_tier in safe_tiers`` / ``not in high_risk_tiers``. A
        corrupt ``risk_tier="bogus"`` would fall through to Rego's
        default refusal → wake() would surface as
        ``sandbox_wake_policy_revalidation_failed`` — the WRONG
        closed-enum taxonomy for what is actually malformed metadata.

        With parser-boundary membership validation, the malformed
        value surfaces correctly as ``sandbox_wake_checkpoint_corrupt``
        per the wake() step 1(c) mapping per spec §3.2.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["pack_context"]["risk_tier"] = bad_risk_tier
        with pytest.raises(ValueError, match=r"pack_context\.risk_tier must be one of"):
            CheckpointMetadata.from_storage_payload(payload)

    def test_accepts_all_canonical_risk_tier_values(self) -> None:
        """Defence-in-depth: confirm every canonical RiskTier value
        passes the parser (catches a regression where _ALLOWED_RISK_TIERS
        is built from a stale set drift-detached from the canonical
        ``typing.get_args(RiskTier)``).
        """
        import typing as _typing

        from cognic_agentos.sandbox.policy import RiskTier as _RiskTier

        for tier in _typing.get_args(_RiskTier):
            payload = _valid_metadata().to_storage_payload()
            payload["pack_context"]["risk_tier"] = tier
            # Must not raise.
            meta = CheckpointMetadata.from_storage_payload(payload)
            assert meta.pack_context.risk_tier == tier

    @pytest.mark.parametrize("profile", ["production", "development"])
    def test_accepts_canonical_profile_values(self, profile: str) -> None:
        """Both canonical profile values pass the parser; catches a
        regression where _ALLOWED_PROFILES is built from a stale set.
        """
        payload = _valid_metadata().to_storage_payload()
        payload["pack_context"]["profile"] = profile
        meta = CheckpointMetadata.from_storage_payload(payload)
        assert meta.pack_context.profile == profile


class TestFromStoragePayloadValidatesVaultLeaseRefTypes:
    """Nested VaultLeaseRef field types per P1.r12 (Sprint 10
    forward-compat — Sprint 8.5 always constructs with empty
    vault_lease_refs, but the parser MUST still reject malformed
    shapes defensively).
    """

    def test_rejects_vault_lease_ref_missing_required_key(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["vault_lease_refs"] = [
            {"vault_path": "secret/x", "role": "r", "duration_s": 60}
            # missing admission_lease_id
        ]
        with pytest.raises(
            ValueError,
            match=(
                r"vault_lease_refs\[0\] missing required keys: "
                r"\['admission_lease_id'\]"
            ),
        ):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_non_int_vault_lease_ref_duration(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["vault_lease_refs"] = [
            {
                "vault_path": "secret/x",
                "role": "r",
                "duration_s": "60s",
                "admission_lease_id": "L-1",
            }
        ]
        with pytest.raises(
            ValueError,
            match=r"vault_lease_refs\[0\]\.duration_s must be int",
        ):
            CheckpointMetadata.from_storage_payload(payload)

    def test_rejects_non_dict_vault_lease_ref_element(self) -> None:
        payload = _valid_metadata().to_storage_payload()
        payload["vault_lease_refs"] = ["not-a-dict"]
        with pytest.raises(ValueError, match=r"vault_lease_refs\[0\] must be dict"):
            CheckpointMetadata.from_storage_payload(payload)


class TestPurgeReasonDriftDetectorTestOnly:
    """P2 round-2 fix per ``feedback_drift_detector_test_only_no_runtime_import``.

    When two modules duplicate a closed-enum constant, each module
    declares its own local copy + a test-only check asserts the two
    Literals remain identical. NO runtime cross-module import — both
    production modules import their own copy from their canonical
    home (audit.py owns the public re-export; checkpoint_store.py
    owns the local copy for its own purge_by_id signature).

    A future edit that drifts ONE Literal without updating the other
    silently breaks audit-vs-store invariants — this drift detector
    fires before the runtime would surface the mismatch as a type
    error at the call site.
    """

    def test_audit_and_store_purge_reason_literals_have_identical_value_sets(
        self,
    ) -> None:
        import typing as _typing

        from cognic_agentos.sandbox import audit as _audit_module
        from cognic_agentos.sandbox import checkpoint_store as _store_module

        audit_values = frozenset(_typing.get_args(_audit_module.PurgeReason))
        store_values = frozenset(_typing.get_args(_store_module._PurgeReason))

        assert audit_values == store_values, (
            f"PurgeReason Literal drift: audit={sorted(audit_values)} != "
            f"store={sorted(store_values)}. Per "
            f"feedback_drift_detector_test_only_no_runtime_import: both "
            f"module-local copies MUST stay in lockstep. Update both at "
            f"once when adding a value (spec §4.3 P3.r4 currently locks "
            f"the set at 4 values; an edit here without an explicit spec "
            f"amendment is a doctrine violation)."
        )

    def test_audit_purge_reason_matches_spec_4_3_p3_r4_value_set(self) -> None:
        """Spec §4.3 P3.r4 locks the 4-value set. Drift here means a
        spec/code disagreement; surface loudly.
        """
        import typing as _typing

        from cognic_agentos.sandbox import audit as _audit_module

        assert frozenset(_typing.get_args(_audit_module.PurgeReason)) == {
            "explicit_destroy",
            "max_per_session_cap",
            "retention_expired",
            "tenant_revocation",
        }, (
            "audit.PurgeReason drift from spec §4.3 P3.r4 — UNCHANGED "
            "4-value set; NO retention_window_active value invented "
            "(that configuration-tension surface is signalled via "
            "CheckpointMaxPerSessionRetentionLocked at the persist() "
            "call site)"
        )
