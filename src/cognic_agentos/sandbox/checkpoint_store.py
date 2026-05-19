"""Sprint 8.5 T3 — CheckpointStore: substantive tenant-isolation +
retention enforcement boundary per spec §3.4 + §4.1 + §4.3.

NEW critical-controls module per ADR-004 §73-93. Owns:

* Wire-public ``CheckpointMetadata`` / ``VaultLeaseRef`` /
  ``TombstoneRecord`` frozen dataclasses (per spec §3.4 — 9 / 4 / 3
  field shape locks).
* ``_validate_checkpoint_id_or_raise`` module-level helper — the
  **single source of truth** for ``CheckpointId`` shape validation
  per spec §3.4 P2.r11. Called by both
  ``CheckpointStore.validate_checkpoint_id_or_raise`` (the staticmethod
  wrapper used at every store entry point) AND
  ``CheckpointMetadata.from_storage_payload`` (the evidence-boundary
  parser). Centralising eliminates parser-vs-store drift; a corrupt
  metadata blob carrying ``checkpoint_id='not-hex'`` raises
  ``ValueError`` at parse time + maps at wake() step 1(c) to
  ``sandbox_wake_checkpoint_corrupt`` rather than smuggling past the
  ``NewType`` façade.
* 2 typed exceptions: ``CheckpointMaxPerSessionRetentionLocked``
  (configuration-tension surface per spec §4.3 P3.r4 — NOT a
  ``SandboxRefusalReason``; persist() raises when the cap would be
  exceeded AND every existing checkpoint is still inside its retention
  window) + ``TombstoneCorruptError`` (P1.r6 fail-closed mapping at
  wake() seam — malformed tombstone sentinel surfaces as
  ``sandbox_wake_session_tombstoned``).
* ``CheckpointStore`` orchestrator with 6 async methods
  (``persist`` / ``load_latest`` / ``purge_expired`` / ``purge_by_id``
  / ``tombstone_session`` / ``load_tombstone``).

Storage layout per spec §4.1 (per-tenant prefix is LOAD-BEARING):
* bucket = ``sandbox-checkpoints``
* key = ``<tenant_id>/<session_id>/<checkpoint_id>.snapshot`` — tar bytes
* key = ``<tenant_id>/<session_id>/<checkpoint_id>.metadata.json`` —
  ``canonical_bytes(meta.to_storage_payload())`` per the §3.4 JSON-
  native converter
* key = ``<tenant_id>/<session_id>/_tombstoned.json`` — tombstone
  sentinel written by ``tombstone_session()``

**Per the Q4 lock** (spec §2.4 amended): this module does NOT extend
``CredentialAdapter``. ``VaultLeaseRef`` ships as forward-compat shape
(always empty in 8.5 — vault-bearing sessions are unreachable via the
existing 8A ``sandbox_credential_adapter_not_configured`` admission-
time refusal). Sprint 10 fills the lease-refs when
``VaultCredentialAdapter`` lands.

**Settings access design choice (Option B per T3 task brief).** This
module reads three Settings fields that have NOT yet landed on the
canonical ``cognic_agentos.core.config.Settings`` model
(``sandbox_checkpoint_retention_s`` / ``sandbox_max_checkpoints_per_session``
/ ``sandbox_reaper_interval_s`` — T10 adds them). The store accepts
any object structurally conforming to the small ``_CheckpointSettings``
``Protocol`` declared below; production code post-T10 passes the real
``Settings`` instance (which will gain the 3 fields then). The
``Protocol`` is module-private (``_``-prefixed) because it is purely an
internal structural contract; ``Settings`` is the public type once T10
lands. Tests pass a stub object that exposes the 3 attributes.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import typing
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.sandbox.audit import sandbox_lifecycle_checkpoint_purged
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.protocol import (
    CheckpointId,
    SandboxLifecycleRefused,
)

if TYPE_CHECKING:
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal constants.
# ---------------------------------------------------------------------------

_BUCKET = "sandbox-checkpoints"
_METADATA_SUFFIX = ".metadata.json"
_SNAPSHOT_SUFFIX = ".snapshot"
_TOMBSTONE_BASENAME = "_tombstoned.json"

_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")

_PurgeReason = Literal[
    "explicit_destroy",
    "max_per_session_cap",
    "retention_expired",
    "tenant_revocation",
]
# Per ``feedback_drift_detector_test_only_no_runtime_import``: the
# canonical 4-value vocabulary lives at ``sandbox/audit.PurgeReason``
# (Sprint 8.5 T2 introduced it there as the wire-public re-export).
# This module declares its own local copy rather than runtime-importing
# from sandbox.audit. A test-only drift detector at
# ``tests/unit/sandbox/test_checkpoint_metadata.py``
# (``TestPurgeReasonDriftDetectorTestOnly``) imports BOTH and asserts
# the two Literals carry the same value-set; that catches a future
# edit that drifts one of the two without coordinated update.


# ---------------------------------------------------------------------------
# Evidence-boundary type-check helpers used by
# ``CheckpointMetadata.from_storage_payload`` (P1.r12 fail-closed parser
# per ``feedback_evidence_boundary_runtime_validation``).
#
# Each helper validates a single JSON-native wire-field type + raises
# ``ValueError`` (NOT ``TypeError`` / ``KeyError``) on mismatch so the
# wake() seam at T6/T7 maps the failure to the closed-enum
# ``sandbox_wake_checkpoint_corrupt`` refusal reason. Without these
# helpers, downstream code paths (purge_expired retention comparison,
# wake-time policy revalidation) hit raw type errors that bypass the
# refusal taxonomy entirely.
#
# Python boolean trap: ``isinstance(True, int)`` is True. Every numeric
# helper rejects ``bool`` BEFORE the int/float check so a stray
# ``retention_window_s=True`` cannot silently coerce to 1-second
# retention.
# ---------------------------------------------------------------------------


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"CheckpointMetadata.{field} must be str (got {type(value).__name__})")
    return value


def _require_str_or_none(value: object, field: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError(
            f"CheckpointMetadata.{field} must be str | None (got {type(value).__name__})"
        )
    return value


def _require_int(value: object, field: str) -> int:
    # Reject bool BEFORE the int check — Python's bool<:int subclass
    # relation would silently accept True as 1, breaking the
    # retention_window_s and memory_mb contracts.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"CheckpointMetadata.{field} must be int (got {type(value).__name__})")
    return value


def _require_number(value: object, field: str) -> float | int:
    """Accept int OR float; reject bool (Python ``bool<:int`` trap)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"CheckpointMetadata.{field} must be number (got {type(value).__name__})")
    return value


def _require_number_or_none(value: object, field: str) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            f"CheckpointMetadata.{field} must be number | None (got {type(value).__name__})"
        )
    return value


def _require_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"CheckpointMetadata.{field} must be bool (got {type(value).__name__})")
    return value


def _require_list_of_str(value: object, field: str) -> list[str]:
    if isinstance(value, tuple):
        raise ValueError(
            f"CheckpointMetadata.{field} must be list (got tuple — would not "
            f"have round-tripped canonical_bytes)"
        )
    if not isinstance(value, list):
        raise ValueError(f"CheckpointMetadata.{field} must be list (got {type(value).__name__})")
    for i, elem in enumerate(value):
        if not isinstance(elem, str):
            raise ValueError(
                f"CheckpointMetadata.{field}[{i}] must be str (got {type(elem).__name__})"
            )
    return value


def _require_in_set(value: object, allowed: frozenset[str], field: str) -> str:
    """Validate that ``value`` is a str AND in the ``allowed`` set.

    Used for closed-enum-string wire fields (``risk_tier`` /
    ``profile``) where the upstream type is a ``Literal[...]`` but the
    parser receives raw JSON strings. Without this membership check, a
    corrupt metadata blob carrying ``profile="bogus"`` would:

      1. Pass the bare ``_require_str`` check.
      2. ``cast()`` to the Literal type at construction time (mypy
         narrows silently; runtime accepts).
      3. Bypass downstream enum-aware checks. E.g.
         ``admission.py:270`` only refuses dynamic-install when
         ``profile == "production"`` — ``profile="bogus"`` is False
         under that comparison, so the production-dynamic-install
         refusal is silently skipped.
      4. The resulting wake() either restores an unsafe session OR
         surfaces a refusal via the WRONG closed-enum value
         (``sandbox_wake_policy_revalidation_failed`` for a Rego
         catch-all, instead of ``sandbox_wake_checkpoint_corrupt``
         which is the taxonomy for malformed metadata).

    Validating membership at the parser boundary closes the bypass
    + lands the correct closed-enum refusal taxonomy.
    """
    if not isinstance(value, str):
        raise ValueError(f"CheckpointMetadata.{field} must be str (got {type(value).__name__})")
    if value not in allowed:
        raise ValueError(
            f"CheckpointMetadata.{field} must be one of {sorted(allowed)} (got {value!r})"
        )
    return value


def _require_list_of_dict(value: object, field: str) -> list[dict[str, Any]]:
    if isinstance(value, tuple):
        raise ValueError(
            f"CheckpointMetadata.{field} must be list (got tuple — would not "
            f"have round-tripped canonical_bytes)"
        )
    if not isinstance(value, list):
        raise ValueError(f"CheckpointMetadata.{field} must be list (got {type(value).__name__})")
    for i, elem in enumerate(value):
        if not isinstance(elem, dict):
            raise ValueError(
                f"CheckpointMetadata.{field}[{i}] must be dict (got {type(elem).__name__})"
            )
    return value


# ---------------------------------------------------------------------------
# Settings structural contract (Option B — see module docstring).
# ---------------------------------------------------------------------------


class _CheckpointSettings(Protocol):
    """Module-private structural contract carrying the 3 Settings fields
    Sprint 8.5 reads.

    Three fields per spec §6:
    * ``sandbox_checkpoint_retention_s``: int — retention floor in
      seconds for the reaper.
    * ``sandbox_max_checkpoints_per_session``: int — per-session cap.
    * ``sandbox_reaper_interval_s``: int — background sweep interval
      (read by the T4 ``CheckpointReaper``; carried here for the same
      Settings contract).

    T10 lands these on the canonical ``Settings`` model; production
    code passes the real ``Settings`` then. The structural ``Protocol``
    pattern means there is no runtime import of an unfinished type.
    """

    sandbox_checkpoint_retention_s: int
    sandbox_max_checkpoints_per_session: int
    sandbox_reaper_interval_s: int


# ---------------------------------------------------------------------------
# CheckpointId validator — module-level single source of truth (P2.r11).
# ---------------------------------------------------------------------------


def _validate_checkpoint_id_or_raise(value: object) -> CheckpointId:
    """**Module-level single source of truth for CheckpointId shape
    validation per spec §3.4 P2.r11.** Called by:

    * ``CheckpointStore.validate_checkpoint_id_or_raise`` (the
      staticmethod wrapper used at every store entry point that
      accepts a ``CheckpointId`` arg).
    * ``CheckpointMetadata.from_storage_payload`` (the evidence-boundary
      parser — rejects corrupt metadata carrying an invalid id BEFORE
      it can smuggle past the ``NewType`` façade).

    Centralising in a module-level helper means there is ONE shape
    contract; both call sites cannot drift. Pre-P2.r11 the parser did
    ``CheckpointId(payload["checkpoint_id"])`` directly, bypassing the
    validator — a corrupt metadata object carrying
    ``checkpoint_id="not-hex"`` would parse successfully + smuggle an
    invalid ``CheckpointId`` into wake()'s pipeline.

    Raises ``ValueError`` (NOT ``TypeError``) on:
    * non-string value;
    * wrong length (must be 32 chars to match ``uuid4().hex``);
    * non-hex characters.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"invalid CheckpointId shape: expected str, got {type(value).__name__} ({value!r})"
        )
    if len(value) != 32:
        raise ValueError(
            f"invalid CheckpointId shape: expected 32-char hex, got len={len(value)} ({value!r})"
        )
    if not _HEX_RE.fullmatch(value):
        raise ValueError(f"invalid CheckpointId shape: not hex ({value!r})")
    return CheckpointId(value)


# ---------------------------------------------------------------------------
# Typed exceptions.
# ---------------------------------------------------------------------------


class CheckpointMaxPerSessionRetentionLocked(Exception):
    """Raised by ``persist()`` when the per-session cap would be
    exceeded AND every existing checkpoint is still inside its
    retention window per spec §4.3 P3.r4.

    NOT a ``SandboxRefusalReason`` — this is a configuration-tension
    surface, NOT a wake-time refusal. Operator response: lower
    ``sandbox_checkpoint_retention_s`` OR raise
    ``sandbox_max_checkpoints_per_session``. Per spec §4.3 P3.r4 the
    typed exception IS the operator-observable signal; persist()
    emits NO ``checkpoint_purged`` chain row + writes NO new
    checkpoint on this branch.
    """

    def __init__(
        self,
        session_id: str,
        tenant_id: str,
        cap: int,
        oldest_retention_remaining_s: int,
    ) -> None:
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.cap = cap
        self.oldest_retention_remaining_s = oldest_retention_remaining_s
        super().__init__(
            f"session {session_id} tenant {tenant_id} at cap {cap}; "
            f"oldest checkpoint has {oldest_retention_remaining_s}s "
            f"retention remaining — lower sandbox_checkpoint_retention_s "
            f"OR raise sandbox_max_checkpoints_per_session"
        )


class TombstoneCorruptError(Exception):
    """Raised by ``load_tombstone()`` when the tombstone sentinel
    exists but is malformed (parse / shape / type error per spec §4.1
    P1.r6 fail-closed correction).

    Wake() (T6/T7 — not in this task) catches and maps to
    ``SandboxLifecycleRefused("sandbox_wake_session_tombstoned")``
    with the original exception message in the refusal's ``detail``
    field. SAME closed-enum value as the well-formed tombstone path —
    operator intent ('destroyed = MUST NOT wake') survives degradation;
    the closed-enum count stays at 21 (the tampering signal lives in
    ``detail``, not in the vocabulary).
    """


# ---------------------------------------------------------------------------
# Wire-public frozen dataclasses (spec §3.4).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VaultLeaseRef:
    """Vault lease reference per spec §3.4 — 4 fields, all required.

    Sprint 8.5 forward-compat shape per Q4 lock (spec §2.4 amended).
    Always empty in 8.5; Sprint 10 fills when ``VaultCredentialAdapter``
    lands. Does NOT carry the lease secret material.
    """

    vault_path: str
    role: str
    duration_s: int
    admission_lease_id: str


@dataclass(frozen=True)
class TombstoneRecord:
    """Parsed tombstone sentinel returned by ``load_tombstone()`` per
    spec §3.4 (P1.r5 tombstone-read fix). 3 fields, all required;
    drift = wire-protocol regression."""

    tombstoned_at: datetime
    tombstoned_by: str
    retained_until: datetime


@dataclass(frozen=True)
class CheckpointMetadata:
    """In-memory representation of a checkpoint metadata record per
    spec §3.4. **9 fields** — drift = wire-protocol regression. Field
    order: all required-without-default fields first;
    ``vault_lease_refs`` (= ``()``) last.

    NOT directly canonical-bytes-safe — ``canonical_bytes()`` rejects
    tuples + custom dataclasses per
    ``core/canonical.py:38-44,69-70``. Persistence + evidence-pack
    export go through the explicit ``to_storage_payload()`` /
    ``from_storage_payload()`` converters.
    """

    checkpoint_id: CheckpointId
    session_id: str
    tenant_id: str
    label: str
    created_at: datetime
    policy: SandboxPolicy
    pack_context: PackAdmissionContext
    retention_window_s: int
    vault_lease_refs: tuple[VaultLeaseRef, ...] = ()

    def to_storage_payload(self) -> dict[str, Any]:
        """Convert to canonical-bytes-safe JSON-native dict per spec §3.4.

        Serialises dataclass + tuple fields to dict + list. The returned
        dict contains ONLY canonical-bytes-allowed types
        (str / int / float / bool / None / list / nested dict /
        iso-string datetime); custom dataclass fields (``policy``,
        ``pack_context``, ``vault_lease_refs[i]``) are recursively
        serialised to nested dicts/lists. ``tuple`` fields
        (``vault_lease_refs``; ``policy.egress_allow_list``;
        ``policy.writable_mounts``) are converted to ``list`` because
        canonical_bytes rejects tuples per the Sprint-2 doctrine.
        """
        return {
            "checkpoint_id": str(self.checkpoint_id),
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "label": self.label,
            "created_at": self.created_at.isoformat(),
            "retention_window_s": self.retention_window_s,
            "policy": {
                "cpu_cores": self.policy.cpu_cores,
                "cpu_time_budget_s": self.policy.cpu_time_budget_s,
                "memory_mb": self.policy.memory_mb,
                "walltime_s": self.policy.walltime_s,
                "runtime_image": self.policy.runtime_image,
                "egress_allow_list": list(self.policy.egress_allow_list),
                "vault_path": self.policy.vault_path,
                "read_only_root": self.policy.read_only_root,
                "writable_mounts": [
                    {
                        "host_path": m.host_path,
                        "container_path": m.container_path,
                        "read_only": m.read_only,
                    }
                    for m in self.policy.writable_mounts
                ],
                "warm_pool_key": self.policy.warm_pool_key,
            },
            "pack_context": {
                "pack_id": self.pack_context.pack_id,
                "pack_version": self.pack_context.pack_version,
                "pack_artifact_digest": self.pack_context.pack_artifact_digest,
                "risk_tier": self.pack_context.risk_tier,
                "declares_dynamic_install": self.pack_context.declares_dynamic_install,
                "profile": self.pack_context.profile,
            },
            "vault_lease_refs": [
                {
                    "vault_path": ref.vault_path,
                    "role": ref.role,
                    "duration_s": ref.duration_s,
                    "admission_lease_id": ref.admission_lease_id,
                }
                for ref in self.vault_lease_refs
            ],
        }

    @classmethod
    def from_storage_payload(cls, payload: dict[str, Any]) -> CheckpointMetadata:
        """Round-trip-load from JSON-native dict per spec §3.4.

        Raises ``ValueError`` (NOT ``TypeError`` / ``KeyError``) on:
        * missing required keys (any of the 9 top-level keys absent
          OR any required nested key absent);
        * wrong-shape values (e.g. ``vault_lease_refs`` is a tuple in
          the payload instead of a list — defence-in-depth against the
          tuple-smuggle attack class that ``canonical_bytes`` rejects
          on write);
        * naive ``created_at`` (``tzinfo is None`` OR
          ``utcoffset() is None``) per
          ``feedback_evidence_boundary_runtime_validation``;
        * invalid ``checkpoint_id`` shape — routed through the
          module-level ``_validate_checkpoint_id_or_raise`` helper
          per spec §3.4 P2.r11 single-source-of-truth invariant.

        Unknown top-level keys are silently ignored (additive-only
        schema; Sprint-10 lease-refs extension lands additive keys
        without a schema-version bump).
        """
        # Deferred import — sandbox/policy is a sibling of this module;
        # an import at module top would still work today but the
        # deferred-inside-classmethod pattern is the established
        # Sprint-8A convention (see sandbox/admission.py) and keeps
        # the canonical converter resilient against future re-org.
        from cognic_agentos.sandbox.policy import (
            PackAdmissionContext,
            RiskTier,
            SandboxPolicy,
            WritableMount,
        )

        if not isinstance(payload, dict):
            raise ValueError(
                f"CheckpointMetadata.from_storage_payload expects dict; "
                f"got {type(payload).__name__}"
            )

        required_top = {
            "checkpoint_id",
            "session_id",
            "tenant_id",
            "label",
            "created_at",
            "retention_window_s",
            "policy",
            "pack_context",
            "vault_lease_refs",
        }
        missing = required_top - set(payload.keys())
        if missing:
            raise ValueError(f"CheckpointMetadata payload missing required keys: {sorted(missing)}")

        # Defence-in-depth tuple-smuggle rejection per spec §3.4 P1.r2:
        # canonical_bytes() rejects tuples on write per
        # canonical.py:38-44,69-70; a tuple HERE means the bytes
        # round-tripped through a non-canonical path (tampering /
        # drift) so reject.
        if isinstance(payload["vault_lease_refs"], tuple):
            raise ValueError(
                "CheckpointMetadata.vault_lease_refs must be list "
                "(got tuple — would not have round-tripped through "
                "canonical_bytes)"
            )

        # Parse + tz-validate created_at per
        # feedback_evidence_boundary_runtime_validation.
        created_raw = payload["created_at"]
        if not isinstance(created_raw, str):
            raise ValueError(
                f"CheckpointMetadata.created_at must be ISO string; got "
                f"{type(created_raw).__name__}"
            )
        try:
            created_at = datetime.fromisoformat(created_raw)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"CheckpointMetadata.created_at not parseable as ISO datetime: {created_raw!r}"
            ) from e
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError(
                f"CheckpointMetadata.created_at must be tz-aware (got "
                f"{created_at!r}); reject naive datetime per "
                f"feedback_evidence_boundary_runtime_validation"
            )

        # Parse nested policy dict.
        policy_dict = payload["policy"]
        if not isinstance(policy_dict, dict):
            raise ValueError(
                f"CheckpointMetadata.policy must be dict (got {type(policy_dict).__name__})"
            )
        required_policy = {
            "cpu_cores",
            "cpu_time_budget_s",
            "memory_mb",
            "walltime_s",
            "runtime_image",
            "egress_allow_list",
            "vault_path",
            "writable_mounts",
        }
        missing_policy = required_policy - set(policy_dict.keys())
        if missing_policy:
            raise ValueError(
                f"CheckpointMetadata.policy missing required keys: {sorted(missing_policy)}"
            )

        # Validate every SandboxPolicy wire field at the type level per
        # P1.r12 evidence-boundary contract. Without this, malformed
        # values (e.g. egress_allow_list="all-of-it") would parse
        # silently and leak as raw TypeError at downstream call sites
        # bypassing the closed-enum refusal taxonomy.
        cpu_cores = _require_number(policy_dict["cpu_cores"], "policy.cpu_cores")
        cpu_time_budget_s = _require_number_or_none(
            policy_dict["cpu_time_budget_s"], "policy.cpu_time_budget_s"
        )
        memory_mb = _require_int(policy_dict["memory_mb"], "policy.memory_mb")
        walltime_s = _require_number(policy_dict["walltime_s"], "policy.walltime_s")
        runtime_image = _require_str(policy_dict["runtime_image"], "policy.runtime_image")
        egress_allow_list_raw = _require_list_of_str(
            policy_dict["egress_allow_list"], "policy.egress_allow_list"
        )
        vault_path = _require_str_or_none(policy_dict["vault_path"], "policy.vault_path")
        writable_mounts_raw = _require_list_of_dict(
            policy_dict["writable_mounts"], "policy.writable_mounts"
        )
        # Optional fields with defaults — validate ONLY if the caller
        # actually supplied them (use sentinel-via-keys not get-with-
        # default so we can tell "absent" from "supplied as None").
        if "read_only_root" in policy_dict:
            read_only_root = _require_bool(policy_dict["read_only_root"], "policy.read_only_root")
        else:
            read_only_root = True
        warm_pool_key = (
            _require_str_or_none(policy_dict["warm_pool_key"], "policy.warm_pool_key")
            if "warm_pool_key" in policy_dict
            else None
        )

        # Validate every WritableMount field at the type level. Earlier
        # impl let missing/wrong fields leak as KeyError/TypeError;
        # P1.r12 requires ValueError so the wake() seam can map.
        writable_mounts_list: list[WritableMount] = []
        for i, m in enumerate(writable_mounts_raw):
            mount_field = f"policy.writable_mounts[{i}]"
            if "host_path" not in m:
                raise ValueError(
                    f"CheckpointMetadata.{mount_field} missing required key 'host_path'"
                )
            if "container_path" not in m:
                raise ValueError(
                    f"CheckpointMetadata.{mount_field} missing required key 'container_path'"
                )
            host_path = _require_str(m["host_path"], f"{mount_field}.host_path")
            container_path = _require_str(m["container_path"], f"{mount_field}.container_path")
            read_only_mount = (
                _require_bool(m["read_only"], f"{mount_field}.read_only")
                if "read_only" in m
                else False
            )
            writable_mounts_list.append(
                WritableMount(
                    host_path=host_path,
                    container_path=container_path,
                    read_only=read_only_mount,
                )
            )
        writable_mounts = tuple(writable_mounts_list)

        policy = SandboxPolicy(
            cpu_cores=cpu_cores,
            cpu_time_budget_s=cpu_time_budget_s,
            memory_mb=memory_mb,
            walltime_s=walltime_s,
            runtime_image=runtime_image,
            egress_allow_list=tuple(egress_allow_list_raw),
            vault_path=vault_path,
            read_only_root=read_only_root,
            writable_mounts=writable_mounts,
            warm_pool_key=warm_pool_key,
        )

        # Parse nested pack_context dict.
        pc_dict = payload["pack_context"]
        if not isinstance(pc_dict, dict):
            raise ValueError(
                f"CheckpointMetadata.pack_context must be dict (got {type(pc_dict).__name__})"
            )
        required_pc = {
            "pack_id",
            "pack_version",
            "pack_artifact_digest",
            "risk_tier",
            "declares_dynamic_install",
            "profile",
        }
        missing_pc = required_pc - set(pc_dict.keys())
        if missing_pc:
            raise ValueError(
                f"CheckpointMetadata.pack_context missing required keys: {sorted(missing_pc)}"
            )
        # Validate every PackAdmissionContext wire field at the type
        # level per P1.r12. ``risk_tier`` + ``profile`` are themselves
        # closed-enum Literals upstream (RiskTier 8 values; profile 2
        # values). The parser MUST validate MEMBERSHIP — NOT just str
        # shape + cast — because downstream consumers do not uniformly
        # gate on enum membership:
        #   - ``admission.py:270`` only refuses dynamic-install when
        #     ``profile == "production"`` (exact-string match). A
        #     corrupt ``profile="bogus"`` would silently bypass the
        #     production-dynamic-install refusal.
        #   - The Rego bundle at ``sandbox.rego:113-114`` checks
        #     ``risk_tier in safe_tiers`` but a bogus risk_tier falls
        #     through to Rego's default refusal which surfaces as
        #     ``sandbox_wake_policy_revalidation_failed`` — the WRONG
        #     closed-enum taxonomy for malformed metadata (the right
        #     one is ``sandbox_wake_checkpoint_corrupt``).
        # Membership validation at the parser closes both bypasses.
        _ALLOWED_RISK_TIERS: frozenset[str] = frozenset(typing.get_args(RiskTier))
        _ALLOWED_PROFILES: frozenset[str] = frozenset({"production", "development"})
        pc_risk_tier_str = _require_in_set(
            pc_dict["risk_tier"], _ALLOWED_RISK_TIERS, "pack_context.risk_tier"
        )
        pc_profile_str = _require_in_set(
            pc_dict["profile"], _ALLOWED_PROFILES, "pack_context.profile"
        )
        pack_context = PackAdmissionContext(
            pack_id=_require_str(pc_dict["pack_id"], "pack_context.pack_id"),
            pack_version=_require_str(pc_dict["pack_version"], "pack_context.pack_version"),
            pack_artifact_digest=_require_str(
                pc_dict["pack_artifact_digest"], "pack_context.pack_artifact_digest"
            ),
            risk_tier=cast(RiskTier, pc_risk_tier_str),
            declares_dynamic_install=_require_bool(
                pc_dict["declares_dynamic_install"], "pack_context.declares_dynamic_install"
            ),
            profile=cast('Literal["production", "development"]', pc_profile_str),
        )

        # Parse vault_lease_refs (always empty in Sprint 8.5 per Q4
        # lock; forward-compat parsing for Sprint 10).
        vlr_list = payload["vault_lease_refs"]
        if not isinstance(vlr_list, list):
            raise ValueError(
                f"CheckpointMetadata.vault_lease_refs must be list (got {type(vlr_list).__name__})"
            )
        # Validate every VaultLeaseRef wire field at the type level per
        # P1.r12. vault_lease_refs is always empty in Sprint 8.5 per Q4
        # lock but the parser MUST still reject malformed shapes
        # defensively (T6/T7 wake-time admit_policy revalidation will
        # refuse vault-bearing wakes via the existing 8A
        # ``sandbox_credential_adapter_not_configured`` refusal; before
        # that even fires, the parser MUST not crash on the metadata
        # blob).
        vault_lease_refs_list: list[VaultLeaseRef] = []
        for i, ref in enumerate(vlr_list):
            ref_field = f"vault_lease_refs[{i}]"
            if not isinstance(ref, dict):
                raise ValueError(
                    f"CheckpointMetadata.{ref_field} must be dict (got {type(ref).__name__})"
                )
            required_ref = {"vault_path", "role", "duration_s", "admission_lease_id"}
            missing_ref = required_ref - set(ref.keys())
            if missing_ref:
                raise ValueError(
                    f"CheckpointMetadata.{ref_field} missing required keys: {sorted(missing_ref)}"
                )
            vault_lease_refs_list.append(
                VaultLeaseRef(
                    vault_path=_require_str(ref["vault_path"], f"{ref_field}.vault_path"),
                    role=_require_str(ref["role"], f"{ref_field}.role"),
                    duration_s=_require_int(ref["duration_s"], f"{ref_field}.duration_s"),
                    admission_lease_id=_require_str(
                        ref["admission_lease_id"], f"{ref_field}.admission_lease_id"
                    ),
                )
            )
        vault_lease_refs = tuple(vault_lease_refs_list)

        # P2.r11 — route checkpoint_id through the shared module-level
        # validator so a corrupt metadata blob carrying
        # ``checkpoint_id='not-hex'`` raises ValueError HERE (mapped at
        # wake() step 1(c) to sandbox_wake_checkpoint_corrupt) rather
        # than smuggling an invalid CheckpointId past the NewType façade.
        try:
            validated_id = _validate_checkpoint_id_or_raise(payload["checkpoint_id"])
        except ValueError as e:
            raise ValueError(
                f"CheckpointMetadata.checkpoint_id failed shape validation: {e}"
            ) from e

        # Top-level wire fields — validate at the type level per P1.r12.
        # Without these, a corrupt payload carrying
        # retention_window_s="bad" would parse silently and later leak
        # as raw TypeError at purge_expired's comparison site OR at
        # wake-time retention check, bypassing the closed-enum refusal
        # taxonomy.
        return cls(
            checkpoint_id=validated_id,
            session_id=_require_str(payload["session_id"], "session_id"),
            tenant_id=_require_str(payload["tenant_id"], "tenant_id"),
            label=_require_str(payload["label"], "label"),
            created_at=created_at,
            policy=policy,
            pack_context=pack_context,
            retention_window_s=_require_int(payload["retention_window_s"], "retention_window_s"),
            vault_lease_refs=vault_lease_refs,
        )


# ---------------------------------------------------------------------------
# CheckpointStore orchestrator.
# ---------------------------------------------------------------------------


class CheckpointStore:
    """Orchestrator per spec §4.1.

    Wraps the Sprint-4 ``ObjectStoreAdapter`` + Sprint-2 ``AuditStore``
    + ``DecisionHistoryStore``. Owns the tenant-isolation + retention
    enforcement boundary.

    Per spec §9: on the durable critical-controls coverage gate from
    T12 (95% line / 90% branch floor).
    """

    def __init__(
        self,
        *,
        object_store: ObjectStoreAdapter,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        settings: _CheckpointSettings,
    ) -> None:
        self._object_store = object_store
        self._audit_store = audit_store
        self._dh_store = decision_history_store
        self._settings = settings

    @staticmethod
    def mint_checkpoint_id() -> CheckpointId:
        """Sole production mint site per spec §3.4 — uuid4 hex
        (32-char lowercase). Tests pin the shape."""
        return CheckpointId(uuid.uuid4().hex)

    @staticmethod
    def validate_checkpoint_id_or_raise(value: object) -> CheckpointId:
        """Thin staticmethod wrapper over the module-level shared
        ``_validate_checkpoint_id_or_raise`` per spec §3.4 P2.r11 —
        single source of truth used by both store entry points AND
        ``CheckpointMetadata.from_storage_payload``."""
        return _validate_checkpoint_id_or_raise(value)

    # ------------------------------------------------------------------
    # persist()
    # ------------------------------------------------------------------

    async def persist(
        self,
        *,
        session_id: str,
        tenant_id: str,
        label: str,
        snapshot_bytes: bytes,
        policy: SandboxPolicy,
        pack_context: PackAdmissionContext,
        vault_lease_refs: tuple[VaultLeaseRef, ...],
    ) -> CheckpointId:
        """Persist a workspace-tar snapshot + sidecar metadata per
        spec §4.1.

        See module docstring for storage layout. Per spec §4.1 P1.r3
        both ``object_store.put()`` calls pass ``retention_seconds=None``
        — retention enforcement lives at the REAPER, NOT the WORM
        lock (the lock would block max-per-session eviction + explicit
        destroy paths against the landed Sprint-4 local driver).

        Enforces ``settings.sandbox_max_checkpoints_per_session`` per
        spec §4.3:
        * If the session has hit the cap AND at least one existing
          checkpoint is OUTSIDE its retention window → purge the
          OLDEST outside-retention checkpoint (emits one
          ``sandbox.lifecycle.checkpoint_purged`` chain row with
          ``purge_reason='max_per_session_cap'``).
        * If the session has hit the cap AND EVERY existing checkpoint
          is INSIDE its retention window → raise
          ``CheckpointMaxPerSessionRetentionLocked`` WITHOUT writing
          the new checkpoint AND WITHOUT emitting any
          ``checkpoint_purged`` chain row. The typed exception IS
          the operator-observable signal per spec §4.3 P3.r4.
        """
        # Mint id + build the in-memory metadata; created_at is
        # tz-aware UTC per feedback_evidence_boundary_runtime_validation.
        new_id = self.mint_checkpoint_id()
        retention_window_s = int(self._settings.sandbox_checkpoint_retention_s)
        created_at = datetime.now(UTC)
        meta = CheckpointMetadata(
            checkpoint_id=new_id,
            session_id=session_id,
            tenant_id=tenant_id,
            label=label,
            created_at=created_at,
            policy=policy,
            pack_context=pack_context,
            retention_window_s=retention_window_s,
            vault_lease_refs=vault_lease_refs,
        )

        # Pre-write — enforce max_per_session_cap. List existing
        # checkpoints under the per-tenant prefix.
        existing = await self._list_session_metadata(tenant_id=tenant_id, session_id=session_id)
        cap = int(self._settings.sandbox_max_checkpoints_per_session)
        if len(existing) >= cap:
            # At/over cap; pick eviction candidate from outside-retention.
            now = datetime.now(UTC)
            outside_retention: list[CheckpointMetadata] = []
            inside_retention: list[CheckpointMetadata] = []
            for m in existing:
                age = (now - m.created_at).total_seconds()
                if age >= m.retention_window_s:
                    outside_retention.append(m)
                else:
                    inside_retention.append(m)

            if not outside_retention:
                # All inside retention → typed exception; NO write;
                # NO chain row per spec §4.3 P3.r4.
                # oldest_retention_remaining_s = min(retention_window_s - age)
                # across the inside-retention set (the smallest
                # remaining = the soonest-to-expire).
                oldest_remaining = min(
                    int(m.retention_window_s - (now - m.created_at).total_seconds())
                    for m in inside_retention
                )
                # Clamp at 0 — a checkpoint at the exact boundary is
                # treated as inside per the >= compare above.
                oldest_remaining = max(0, oldest_remaining)
                raise CheckpointMaxPerSessionRetentionLocked(
                    session_id=session_id,
                    tenant_id=tenant_id,
                    cap=cap,
                    oldest_retention_remaining_s=oldest_remaining,
                )

            # Pick the oldest outside-retention checkpoint
            # (smallest created_at).
            victim = min(outside_retention, key=lambda m: m.created_at)
            await self.purge_by_id(
                session_id=session_id,
                tenant_id=tenant_id,
                checkpoint_id=victim.checkpoint_id,
                purge_reason="max_per_session_cap",
            )

        # Write snapshot + metadata under the per-tenant prefix.
        # retention_seconds=None per spec §4.1 P1.r3 — load-bearing.
        snapshot_key = f"{tenant_id}/{session_id}/{new_id}{_SNAPSHOT_SUFFIX}"
        metadata_key = f"{tenant_id}/{session_id}/{new_id}{_METADATA_SUFFIX}"
        await self._object_store.put(_BUCKET, snapshot_key, snapshot_bytes, retention_seconds=None)
        await self._object_store.put(
            _BUCKET,
            metadata_key,
            canonical_bytes(meta.to_storage_payload()),
            retention_seconds=None,
        )
        return new_id

    # ------------------------------------------------------------------
    # load_latest()
    # ------------------------------------------------------------------

    async def load_latest(
        self,
        *,
        session_id: str,
        tenant_id: str,
    ) -> tuple[CheckpointMetadata, bytes]:
        """Load the most-recent checkpoint for ``(tenant_id,
        session_id)`` per spec §4.1.

        Implementation: lists keys under
        ``<tenant>/<session>/`` via ``ObjectStoreAdapter.list_prefix``;
        filters to ``*.metadata.json`` keys; for each, fetches via
        ``get()`` + ``json.loads()`` +
        ``CheckpointMetadata.from_storage_payload`` (NOT a direct
        dataclass construction — payload bytes round-tripped through
        the canonical-bytes-safe converter); picks the one with the
        latest ``created_at``; fetches the matching ``.snapshot``
        blob.

        Raises ``SandboxLifecycleRefused(
        'sandbox_wake_checkpoint_not_found')`` when no metadata blob
        exists under the prefix — covers both "session was never
        checkpointed" AND "cross-tenant lookup" (the per-tenant prefix
        means tenant-b cannot see tenant-a's keys; defence-in-depth
        past the wake() step 2 tenant-mismatch check).

        ``from_storage_payload()`` raising ``ValueError`` propagates
        OUT of ``load_latest()`` per spec §4.1 P2.r3 — the wake()
        seam catches and maps to ``sandbox_wake_checkpoint_corrupt``;
        store does NOT catch the ValueError itself.
        """
        metas = await self._list_session_metadata(tenant_id=tenant_id, session_id=session_id)
        if not metas:
            raise SandboxLifecycleRefused(
                "sandbox_wake_checkpoint_not_found",
                detail=f"no checkpoints found for {tenant_id}/{session_id}",
            )
        # Pick latest by created_at.
        latest = max(metas, key=lambda m: m.created_at)
        snapshot_key = f"{tenant_id}/{session_id}/{latest.checkpoint_id}{_SNAPSHOT_SUFFIX}"
        snap = await self._object_store.get(_BUCKET, snapshot_key)
        return latest, snap

    # ------------------------------------------------------------------
    # purge_expired()
    # ------------------------------------------------------------------

    async def purge_expired(self) -> int:
        """Reaper-callable per spec §4.3. Walks all checkpoints +
        tombstones via ``list_prefix(bucket='sandbox-checkpoints',
        prefix='')`` — lazy iteration across every tenant prefix.

        Per spec §4.3:

        * Tombstoned session path: if ``_tombstoned.json`` exists,
          read ``retained_until``. If ``now >= retained_until``, purge
          ALL session checkpoints + the tombstone sentinel; emit one
          ``sandbox.lifecycle.checkpoint_purged`` chain row per
          checkpoint with ``purge_reason='explicit_destroy'``.
          Otherwise skip.
        * Non-tombstoned session path: for each
          ``<checkpoint_id>.metadata.json`` blob, read
          ``metadata.created_at`` + ``metadata.retention_window_s``.
          If ``(now - created_at) >= retention_window_s``, purge the
          metadata + snapshot pair with
          ``purge_reason='retention_expired'``. Otherwise skip.

        Returns the count of purged checkpoints (does NOT count the
        tombstone-sentinel deletes — those track the same logical
        session destroy).
        """
        # Walk all keys, partition by session prefix
        # (``<tenant>/<session>/``).
        sessions: dict[tuple[str, str], list[str]] = {}
        async for key in self._object_store.list_prefix(_BUCKET, ""):
            parts = key.split("/")
            if len(parts) < 3:
                # Unexpected shape — skip; production keys are always
                # tenant/session/file.
                continue
            tenant_id, session_id = parts[0], parts[1]
            sessions.setdefault((tenant_id, session_id), []).append(key)

        purged_count = 0
        now = datetime.now(UTC)
        for (tenant_id, session_id), keys in sessions.items():
            # Tombstone branch first per spec §4.3 ordering.
            tomb_key = f"{tenant_id}/{session_id}/{_TOMBSTONE_BASENAME}"
            if tomb_key in keys:
                try:
                    tomb = await self.load_tombstone(session_id=session_id, tenant_id=tenant_id)
                except TombstoneCorruptError:
                    # Corrupt tombstone — fail-closed: skip purge so
                    # operator can manually triage. The tombstone
                    # remains; future sweeps will keep skipping until
                    # the operator fixes the bytes. This is the
                    # symmetric defence to wake()-side P1.r6 fail-closed.
                    logger.warning(
                        "purge_expired: corrupt tombstone at %s — skipping session sweep",
                        tomb_key,
                    )
                    continue
                if tomb is None:
                    # Race — tombstone removed between list + read.
                    continue
                if now < tomb.retained_until:
                    # Inside retention; skip.
                    continue
                # Elapsed — purge every checkpoint + the tombstone.
                # Discover checkpoint ids from metadata keys under the
                # session prefix (do NOT rely on snapshot keys to
                # avoid mismatch when a snapshot was deleted but its
                # sidecar metadata remains for some reason).
                checkpoint_ids: list[str] = []
                for k in keys:
                    if k.endswith(_METADATA_SUFFIX):
                        # Filename = <id>.metadata.json
                        base = k.rsplit("/", 1)[-1]
                        cid = base[: -len(_METADATA_SUFFIX)]
                        checkpoint_ids.append(cid)
                for cid in checkpoint_ids:
                    await self.purge_by_id(
                        session_id=session_id,
                        tenant_id=tenant_id,
                        checkpoint_id=CheckpointId(cid),
                        purge_reason="explicit_destroy",
                    )
                    purged_count += 1
                # Delete the tombstone sentinel itself.
                with contextlib.suppress(FileNotFoundError):
                    await self._object_store.delete(_BUCKET, tomb_key)
                continue

            # Non-tombstoned path — per-metadata retention check.
            for k in keys:
                if not k.endswith(_METADATA_SUFFIX):
                    continue
                try:
                    raw = await self._object_store.get(_BUCKET, k)
                except FileNotFoundError:
                    continue
                try:
                    meta = CheckpointMetadata.from_storage_payload(json.loads(raw))
                except (ValueError, json.JSONDecodeError) as e:
                    logger.warning(
                        "purge_expired: corrupt metadata at %s — skipping: %s",
                        k,
                        e,
                    )
                    continue
                age_s = (now - meta.created_at).total_seconds()
                if age_s < meta.retention_window_s:
                    continue
                await self.purge_by_id(
                    session_id=session_id,
                    tenant_id=tenant_id,
                    checkpoint_id=meta.checkpoint_id,
                    purge_reason="retention_expired",
                )
                purged_count += 1
        return purged_count

    # ------------------------------------------------------------------
    # purge_by_id()
    # ------------------------------------------------------------------

    async def purge_by_id(
        self,
        *,
        session_id: str,
        tenant_id: str,
        checkpoint_id: CheckpointId,
        purge_reason: _PurgeReason,
    ) -> None:
        """Internal-only purge per spec §4.1 (P1.r4 tombstone redesign).

        Called by the reaper (``purge_reason`` ∈
        {``explicit_destroy``, ``retention_expired``,
        ``tenant_revocation``}) + by ``persist()`` for the cap-eviction
        path (``purge_reason='max_per_session_cap'``). NOT called by
        ``destroy()`` directly per the P1.r4 redesign.

        Always succeeds at the storage layer (reaper pre-checks
        retention before calling; no WORM lock per the P1.r3 fix).
        Emits ``sandbox.lifecycle.checkpoint_purged`` via the T2
        helper ``sandbox_lifecycle_checkpoint_purged``.
        """
        # Validate id shape at the entry point per the P2.r11 contract.
        validated_id = _validate_checkpoint_id_or_raise(checkpoint_id)
        snapshot_key = f"{tenant_id}/{session_id}/{validated_id}{_SNAPSHOT_SUFFIX}"
        metadata_key = f"{tenant_id}/{session_id}/{validated_id}{_METADATA_SUFFIX}"
        # Storage-level deletes are idempotent under FileNotFoundError —
        # the metadata or snapshot may have been removed by a prior
        # partial purge, OR the reaper's parallel sweep may have
        # already taken it.
        for k in (snapshot_key, metadata_key):
            with contextlib.suppress(FileNotFoundError):
                await self._object_store.delete(_BUCKET, k)
        # Emit the chain row via the T2 helper.
        await sandbox_lifecycle_checkpoint_purged(
            self._dh_store,
            tenant_id=tenant_id,
            session_id=session_id,
            checkpoint_id=validated_id,
            purge_reason=purge_reason,
        )

    # ------------------------------------------------------------------
    # tombstone_session()
    # ------------------------------------------------------------------

    async def tombstone_session(
        self,
        *,
        session_id: str,
        tenant_id: str,
        tombstoned_by: str,
    ) -> str:
        """Write the tombstone sentinel for a destroyed session per
        spec §4.1 P1.r4.

        Storage layout: key=``<tenant>/<session>/_tombstoned.json``
        carrying ``canonical_bytes`` of ``{tombstoned_at: <iso>,
        tombstoned_by: <actor>, retained_until: <iso>}``.

        Idempotent: a second call on an already-tombstoned session
        returns the existing key WITHOUT overwriting
        ``tombstoned_at``. Prevents destroy()-after-destroy from
        extending retention.

        Uses ``retention_seconds=None`` per spec §4.1 P1.r3 — the
        reaper's retention-floor check applies symmetrically to
        checkpoints AND tombstones; both purged together when
        ``retained_until`` elapses.
        """
        key = f"{tenant_id}/{session_id}/{_TOMBSTONE_BASENAME}"
        # Idempotency probe — if the sentinel already exists, return it
        # unchanged.
        try:
            await self._object_store.get(_BUCKET, key)
            return key
        except FileNotFoundError:
            pass

        now = datetime.now(UTC)
        retained_until = now + timedelta(seconds=int(self._settings.sandbox_checkpoint_retention_s))
        payload = {
            "tombstoned_at": now.isoformat(),
            "tombstoned_by": tombstoned_by,
            "retained_until": retained_until.isoformat(),
        }
        await self._object_store.put(_BUCKET, key, canonical_bytes(payload), retention_seconds=None)
        return key

    # ------------------------------------------------------------------
    # load_tombstone()
    # ------------------------------------------------------------------

    async def load_tombstone(
        self,
        *,
        session_id: str,
        tenant_id: str,
    ) -> TombstoneRecord | None:
        """Read the tombstone sentinel for a session if present per
        spec §4.1 P1.r5 + P1.r6 fail-closed contract.

        Behavior:

        * ``FileNotFoundError`` from ``get()`` → return ``None``
          (genuinely absent; wake() proceeds to ``load_latest()``).
        * Valid sentinel → return ``TombstoneRecord(tombstoned_at,
          tombstoned_by, retained_until)``.
        * Malformed sentinel (parse / shape / type error) → raise
          ``TombstoneCorruptError(original_exc_message)``. **LOAD-
          BEARING P1.r6 fail-closed** — returning ``None`` on malformed
          would be fail-OPEN (wake() would proceed to load_latest()
          and restore a session that operator INTENDED to destroy).
          Wake() (T6/T7) catches and maps to
          ``SandboxLifecycleRefused('sandbox_wake_session_tombstoned')``
          with the original_exc_message in ``detail``.
        """
        key = f"{tenant_id}/{session_id}/{_TOMBSTONE_BASENAME}"
        try:
            raw = await self._object_store.get(_BUCKET, key)
        except FileNotFoundError:
            return None

        # Sentinel bytes exist — parse + validate. Any failure raises
        # TombstoneCorruptError per P1.r6 fail-closed.
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            raise TombstoneCorruptError(
                f"tombstone sentinel at {key} is not valid JSON: {e}"
            ) from e
        if not isinstance(payload, dict):
            raise TombstoneCorruptError(
                f"tombstone sentinel at {key} is not a JSON object (got {type(payload).__name__})"
            )
        required = {"tombstoned_at", "tombstoned_by", "retained_until"}
        missing = required - set(payload.keys())
        if missing:
            raise TombstoneCorruptError(
                f"tombstone sentinel at {key} missing required keys: {sorted(missing)}"
            )
        try:
            tombstoned_at = datetime.fromisoformat(payload["tombstoned_at"])
            retained_until = datetime.fromisoformat(payload["retained_until"])
        except (TypeError, ValueError) as e:
            raise TombstoneCorruptError(
                f"tombstone sentinel at {key} has unparseable datetime: {e}"
            ) from e
        for label, dt in (
            ("tombstoned_at", tombstoned_at),
            ("retained_until", retained_until),
        ):
            if dt.tzinfo is None or dt.utcoffset() is None:
                raise TombstoneCorruptError(
                    f"tombstone sentinel at {key} has naive {label}: {dt!r}"
                )
        tombstoned_by = payload["tombstoned_by"]
        if not isinstance(tombstoned_by, str):
            raise TombstoneCorruptError(
                f"tombstone sentinel at {key} tombstoned_by must be str "
                f"(got {type(tombstoned_by).__name__})"
            )
        return TombstoneRecord(
            tombstoned_at=tombstoned_at,
            tombstoned_by=tombstoned_by,
            retained_until=retained_until,
        )

    # ------------------------------------------------------------------
    # Internal helpers.
    # ------------------------------------------------------------------

    async def _list_session_metadata(
        self,
        *,
        tenant_id: str,
        session_id: str,
    ) -> list[CheckpointMetadata]:
        """List all ``CheckpointMetadata`` instances under the per-tenant
        session prefix. Filters to ``*.metadata.json`` keys; routes
        bytes through ``from_storage_payload`` (raises ``ValueError``
        on corrupt metadata per the P2.r3 contract — wake() seam
        catches + maps).
        """
        prefix = f"{tenant_id}/{session_id}/"
        out: list[CheckpointMetadata] = []
        async for key in self._object_store.list_prefix(_BUCKET, prefix):
            if not key.endswith(_METADATA_SUFFIX):
                continue
            try:
                raw = await self._object_store.get(_BUCKET, key)
            except FileNotFoundError:
                # Race — file removed between list + get.
                continue
            meta = CheckpointMetadata.from_storage_payload(json.loads(raw))
            out.append(meta)
        return out


__all__ = [
    "CheckpointMaxPerSessionRetentionLocked",
    "CheckpointMetadata",
    "CheckpointStore",
    "TombstoneCorruptError",
    "TombstoneRecord",
    "VaultLeaseRef",
    # _validate_checkpoint_id_or_raise is intentionally NOT in __all__
    # — it is a module-private helper consumed by the parser + the
    # staticmethod wrapper; external callers use the staticmethod
    # wrapper. The drift detector at test_checkpoint_metadata.py
    # imports it directly to pin the single-source-of-truth invariant.
]
