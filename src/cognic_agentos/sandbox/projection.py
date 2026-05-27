"""Sprint 10.6 T18 — pure-functional credential projection planner per
ADR-004 §25 + ADR-017 + Sprint 10.6 spec §5.4.

This module is the **wire-public-artifact owner** for the planner half
of the credential-projection contract per Round-7 Gap O doctrinal
positioning. The planner's output shape (``ProjectionPlan`` /
``ProjectionRefused``) IS the wire-protocol-public surface bank-overlay
consumers + SIEM tooling code against — drift here is a wire-protocol
break.

**No I/O. No backend coupling.** The planner is a pure function:

  ``compute_projection_plan(*, lease, manifest_decl)``
    ``-> ProjectionPlan | ProjectionRefused``

- Vault lease ``token`` payloads are validated for field-set parity
  with the manifest's declared ``expected_fields`` AND per-value shape
  (non-string / empty / oversized).
- Ownership (UID/GID) is intentionally NOT a planner input — backend
  executors own ``chgrp`` (Docker) and ``fsGroup`` pinning (K8s) via
  their native API at write time. Mode ``0o440`` IS the planner's
  output; ownership is applied by the executor.
- Substrate preflight (tmpfs / image USER directive / root-workload
  refusal) lives entirely OUTSIDE this planner — the T21 lifecycle
  integration runs preflight BEFORE the planner is ever called per
  spec §5.8 step 2.

Refusals are data-style frozen dataclasses (NOT exceptions) per the
locked Section 2 doctrine. Each ``ProjectionRefused`` carries audit-
useful diagnostics: alphabetised ``extras`` + ``missing`` lists for
field-set mismatches; ``field_name`` + ``actual_type`` for non-string
refusals; ``field_name`` + ``actual_length`` discriminator for
empty/whitespace-only refusals; ``field_name`` + ``actual_size`` +
``cap`` for size-exceeded refusals. Examiners reading the chain row
get full provenance without having to re-derive it from the failed
lease.

**Opaque-path contract** (spec §5.3 + §5.4 + the opaque-path drift
detector at ``tests/unit/sandbox/test_projection.py``): each plan
entry's ``relative_path`` is EXACTLY the field name — never
``logical_name``, never ``vault_path``, never ``lease_id``, never
``tenant_id``. The backend executor concatenates the relative path
with the per-credential opaque dir (Docker) or uses it as the
Secret key (K8s) so semantic names never appear on the host
filesystem.

**Byte-exact preservation contract** (spec §5.3): credential values
round-trip from Vault response → ``content_bytes`` byte-for-byte.
NO trimming, NO trailing newline, NO BOM, NO UTF-8 normalisation.
The only string mutation the planner performs is the
empty-/whitespace-only detection at the field-value-empty refusal
gate; values that pass that gate land in ``content_bytes`` exactly
as Vault returned them.

**Wave-1 closed-enum scope** (spec §5.6):
``ProjectionRefusalReason`` is a wire-equal SUBSET of the 9 T16
``SandboxRefusalReason`` credential-projection values — the 4
planner-emitted values only. The 5 substrate/lifecycle values
(``..._staging_path_not_tmpfs`` + ``..._workload_gid_unknown`` +
``..._image_gid_manifest_mismatch`` +
``..._image_user_directive_non_numeric`` +
``..._root_workload_refused``) are emitted by the T19/T20 per-
backend executors + the T21 lifecycle integration. Drift between
this Literal and the full ``SandboxRefusalReason`` is caught at
module load by the partition-invariant test at
``tests/unit/sandbox/test_projection.py::TestProjectionRefusalReasonDriftDetector``.

**Critical-controls scope:** ``sandbox/projection.py`` is critical-
controls from birth and promotes to the durable per-file coverage
gate at Sprint 10.6 Z1c per spec §5.4 (planner is the wire-public-
artifact owner; the executors consume its output verbatim). Until
the formal gate promotion at Z1c, the strict halt-before-commit
discipline applies per ``[[feedback_strict_review_off_gate]]``.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final, Literal

from cognic_agentos.core.vault import CredentialLease

# ---------------------------------------------------------------------------
# Module-level constants — wire-public per spec §5.1.
# ---------------------------------------------------------------------------

#: Per-credential-field size cap in BYTES (not characters; multi-byte
#: UTF-8 sequences count their encoded byte length). Spec §5.1 locks
#: this at 64 KiB to protect the tmpfs staging area at Docker
#: ``/dev/shm/cognic/`` from runaway-size credential values that
#: could exhaust the host's shared-memory budget. K8s Secrets have
#: their own 1 MiB cap at the kubelet level; this planner-side cap
#: is the inner, stricter bound.
_FIELD_VALUE_SIZE_CAP_BYTES: Final[int] = 64 * 1024


# ---------------------------------------------------------------------------
# Closed-enum closed-vocabulary.
# ---------------------------------------------------------------------------

#: Wire-equal subset of the 9 T16 ``SandboxRefusalReason``
#: credential-projection values. The planner owns these 4 of 9
#: values; the other 5 (``..._staging_path_not_tmpfs`` +
#: ``..._workload_gid_unknown`` + ``..._image_gid_manifest_mismatch``
#: + ``..._image_user_directive_non_numeric`` +
#: ``..._root_workload_refused``) are emitted by the T19/T20 per-
#: backend executors + the T21 lifecycle integration.
#:
#: Drift between this Literal and ``SandboxRefusalReason`` is caught
#: at module load by the partition-invariant test at
#: ``tests/unit/sandbox/test_projection.py::TestProjectionRefusalReasonDriftDetector``.
ProjectionRefusalReason = Literal[
    "sandbox_credential_projection_field_set_mismatch",
    "sandbox_credential_projection_field_value_non_string",
    "sandbox_credential_projection_field_value_empty_string",
    "sandbox_credential_projection_field_value_size_exceeded",
]


# ---------------------------------------------------------------------------
# Frozen wire-public dataclasses.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class CredentialDecl:
    """Per-credential manifest projection — single-credential shape
    extracted from a ``[credentials.<logical_name>]`` block plus the
    surrounding tenant identity.

    Used as the manifest-side input to :func:`compute_projection_plan`.
    The T14 ``cli/validators/credentials.py`` validator has already
    confirmed at build time that:

    - ``logical_name`` matches ``^[a-z][a-z0-9_]*$`` (max 32 chars)
    - ``vault_path`` is well-shaped (no leading/trailing/double slash;
      valid chars; max 512 chars)
    - ``expected_fields`` is a 1-16-entry list of unique snake_case
      identifiers without underscore-prefix (max 32 chars per field
      per spec §5.1)
    - ``ttl_s`` is a positive integer
    - ``purpose_category`` is one of the 8 T12 ``PurposeCategory``
      Wave-1 values
    - ``purpose_description`` is a 1-256-char string

    The planner therefore does NOT re-validate these fields; it
    consumes them as facts.
    """

    logical_name: str
    vault_path: str
    expected_fields: list[str]
    ttl_s: int
    purpose_category: str
    purpose_description: str
    tenant_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectionPlanEntry:
    """One file in the projection plan — corresponds to one
    credential field per spec §5.4.

    ``relative_path`` is EXACTLY the field name (opaque-path drift
    detector pinned). ``content_bytes`` round-trips the Vault
    response value byte-for-byte (no trimming; no trailing newline).
    ``mode`` is always ``0o440`` per spec §5.3 — ownership (chgrp
    to workload GID on Docker; ``fsGroup`` pin on K8s) is the
    executor's responsibility.
    """

    relative_path: str
    content_bytes: bytes
    mode: int


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectionPlan:
    """Successful projection plan for a single credential per spec §5.4.

    ``entries`` are ordered to match ``manifest_decl.expected_fields``
    (manifest declaration order — NOT Vault response iteration order)
    so the lifecycle integration's per-credential audit chain row
    payload (``credentials_projected`` per spec §5.7) sees
    deterministic field ordering across runs.

    All audit-metadata fields are populated by the planner so the
    backend executor + lifecycle integration can emit the
    ``credentials_projected`` chain row without re-deriving the
    surrounding context — single source of truth for the
    examiner-visible provenance.
    """

    entries: tuple[ProjectionPlanEntry, ...]
    logical_name: str
    lease_id: str
    projected_field_count: int
    vault_path: str
    purpose_category: str
    purpose_description: str
    tenant_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectionRefused:
    """Refusal carrier — data-style frozen dataclass per the locked
    Section 2 doctrine ("planner returns data-style refusal NOT
    exceptions"). The lifecycle integration at T21 catches the
    ``ProjectionRefused`` return value AND emits both the
    ``credentials_projection_failed`` chain row AND the upstream
    ``SandboxLifecycleRefused`` exception that propagates to the
    scheduler caller.

    Optional diagnostic fields are populated per ``reason``:

    - ``field_set_mismatch``: ``expected_fields`` + ``actual_fields``
      (alphabetised) + ``extras`` + ``missing`` (also alphabetised
      per spec §5.7's deterministic-audit-diff contract).
    - ``field_value_non_string``: ``field_name`` + ``actual_type``
      (e.g., ``"int"``, ``"NoneType"``).
    - ``field_value_empty_string``: ``field_name`` + ``actual_length``
      (discriminator: 0 = exact empty; N>0 = N whitespace bytes).
    - ``field_value_size_exceeded``: ``field_name`` + ``actual_size``
      + ``cap``.

    ``logical_name`` is ALWAYS populated (the refusal relates to
    exactly one credential per spec §5.4 + spec §5.8 step 3).
    """

    reason: ProjectionRefusalReason
    logical_name: str
    # Optional diagnostic fields — populated per reason.
    #
    # The 4 list-shaped diagnostic fields use ``tuple[str, ...]``
    # (NOT ``list[str]``) per T18 round-1 reviewer fix: ``frozen=True``
    # prevents attribute REASSIGNMENT but does NOT prevent mutation
    # of list CONTENTS. Since ``ProjectionRefused`` instances feed
    # the ``credentials_projection_failed`` audit chain row payload
    # (spec §5.7), any caller mutating ``result.extras`` /
    # ``result.missing`` between planner return + T21 audit emit
    # would silently corrupt the wire-public evidence record.
    # Tuples are immutable at the type level — mutation attempts
    # raise ``AttributeError`` (tuples have no append/extend/etc.).
    # Pinned by ``test_diagnostic_fields_are_immutable_tuples`` +
    # ``test_diagnostic_fields_cannot_be_reassigned``.
    expected_fields: tuple[str, ...] = dataclasses.field(default_factory=tuple)
    actual_fields: tuple[str, ...] = dataclasses.field(default_factory=tuple)
    extras: tuple[str, ...] = dataclasses.field(default_factory=tuple)
    missing: tuple[str, ...] = dataclasses.field(default_factory=tuple)
    field_name: str | None = None
    actual_type: str | None = None
    actual_length: int | None = None
    actual_size: int | None = None
    cap: int | None = None

    def __post_init__(self) -> None:
        """Normalise + validate the 4 list-shaped diagnostic fields per
        the T18 round-2 + round-3 reviewer fixes.

        The planner internally always constructs ``tuple(sorted(...))``
        for the 4 list-shaped diagnostic fields. But ``ProjectionRefused``
        is also a wire-public dataclass exported to bank-overlay
        consumers + future T21 audit-emit code — a caller invoking
        the PUBLIC constructor with
        ``ProjectionRefused(..., extras=["ssl_cert"], missing=["password"])``
        would otherwise persist the mutable list, defeating the
        wire-public-evidence-payload immutability contract pinned in
        ``TestProjectionRefusedImmutability`` at the test file.

        Accepted input types per the T18 round-3 reviewer fix:

        - ``tuple[str, ...]`` — idempotent passthrough (preserves
          object identity; the regression
          ``test_public_constructor_with_already_tuple_input_is_idempotent``
          pins this).
        - ``list[str]`` — normalised to tuple.

        Any other input shape raises ``TypeError``. The round-2 draft
        used ``tuple(value)`` unconditionally which silently expanded
        a string into a char-tuple (``"ssl_cert"`` →
        ``('s', 's', 'l', '_', 'c', 'e', 'r', 't')``) — wire-public
        evidence payloads cannot tolerate that class of input
        coercion. Every item is also validated as ``str``; non-string
        items raise ``TypeError`` rather than silently flowing through
        the audit chain.

        ``object.__setattr__`` is required to bypass ``frozen=True``
        during post-init field normalisation (the standard pattern
        for frozen-dataclass post-init mutation per Python docs; real
        precedent at ``core/vault.py:168`` ``VaultLeaseRequest.__post_init__``
        which also validates inputs in a frozen dataclass).
        """
        for fname in ("expected_fields", "actual_fields", "extras", "missing"):
            value = getattr(self, fname)
            if isinstance(value, tuple):
                normalised: tuple[str, ...] = value
            elif isinstance(value, list):
                normalised = tuple(value)
            else:
                # Defensive — refuse string / dict / arbitrary iterables.
                # The bad shape ``extras="ssl_cert"`` was caught at T18
                # round-3 reviewer review; the unconditional
                # ``tuple(value)`` it would have replaced silently
                # expanded the string to a char tuple.
                raise TypeError(
                    f"ProjectionRefused.{fname} must be tuple[str, ...] "
                    f"or list[str]; got {type(value).__name__!r}."
                )
            for item in normalised:
                if not isinstance(item, str):
                    raise TypeError(
                        f"ProjectionRefused.{fname} entries must be str; "
                        f"got {type(item).__name__!r} ({item!r})"
                    )
            object.__setattr__(self, fname, normalised)


# ---------------------------------------------------------------------------
# Pure-functional planner.
# ---------------------------------------------------------------------------


def compute_projection_plan(
    *,
    lease: CredentialLease,
    manifest_decl: CredentialDecl,
) -> ProjectionPlan | ProjectionRefused:
    """Compute a per-credential projection plan.

    Per spec §5.4: pure function over ``(CredentialLease, CredentialDecl)``;
    no I/O; no backend coupling; no ownership input.

    **Order of operations** (locked):

    1. **Field-set match check** — ``set(actual) == set(expected)``;
       on mismatch → ``ProjectionRefused(field_set_mismatch, ...)``
       with alphabetised ``extras`` + ``missing`` + ``expected_fields``
       + ``actual_fields``. The set check runs BEFORE per-field
       value validation because value validation only matters for
       fields the manifest declared.
    2. **Per-field value validation** — iterate ``expected_fields``
       in manifest declaration order; for each field, in this order:
       (a) non-string check → ``field_value_non_string`` (covers
       ``int`` / ``bool`` / ``list`` / ``dict`` / ``None`` /
       everything that ``isinstance(v, str)`` rejects);
       (b) empty/whitespace-only check → ``field_value_empty_string``
       with ``actual_length`` discriminator;
       (c) byte-size check on the UTF-8-encoded value →
       ``field_value_size_exceeded``. First violation short-circuits;
       no subsequent field is checked.
    3. **Build ``ProjectionPlan``** — one ``ProjectionPlanEntry``
       per field in manifest declaration order; mode ``0o440``;
       ``content_bytes`` byte-exact from the Vault response;
       audit metadata populated from the lease + manifest_decl.

    The planner returns a refusal on the FIRST violation; downstream
    fields are NOT inspected. This matches the lifecycle-integration
    contract at spec §5.8 step 3: one refusal per credential, with
    full diagnostic payload, then revoke-only the failed credential's
    lease + LIFO-unwind already-projected credentials.
    """
    expected_set: set[str] = set(manifest_decl.expected_fields)
    actual_set: set[str] = set(lease.token.keys())

    # Step 1: field-set match.
    if expected_set != actual_set:
        # Construct tuples (NOT lists) so the resulting
        # ``ProjectionRefused`` is truly immutable per T18 round-1
        # reviewer fix; the alphabetised contract from spec §5.7 is
        # preserved by passing ``sorted(...)`` output through
        # ``tuple(...)``.
        extras = tuple(sorted(actual_set - expected_set))
        missing = tuple(sorted(expected_set - actual_set))
        return ProjectionRefused(
            reason="sandbox_credential_projection_field_set_mismatch",
            logical_name=manifest_decl.logical_name,
            expected_fields=tuple(sorted(expected_set)),
            actual_fields=tuple(sorted(actual_set)),
            extras=extras,
            missing=missing,
        )

    # Step 2: per-field value validation in manifest declaration order.
    encoded: list[tuple[str, bytes]] = []
    for field_name in manifest_decl.expected_fields:
        value: Any = lease.token[field_name]

        # 2a — non-string check.
        # ``bool`` is a subclass of int but ALSO not str; this catches
        # bool (and every other non-str type) before any string-
        # specific operation runs.
        if not isinstance(value, str):
            return ProjectionRefused(
                reason="sandbox_credential_projection_field_value_non_string",
                logical_name=manifest_decl.logical_name,
                field_name=field_name,
                actual_type=type(value).__name__,
            )

        # 2b — empty / whitespace-only check.
        # The ``.strip()`` is the ONLY place the planner inspects
        # whitespace; the byte-exactness contract (spec §5.3) is
        # preserved on the happy path because the original ``value``
        # passes through to ``encode("utf-8")`` unchanged.
        #
        # ``actual_length`` is the UTF-8 BYTE count of the value,
        # NOT the character count (spec §193 + §5.7: "N whitespace
        # bytes"). For ASCII whitespace bytes-and-chars are
        # equivalent, but for multi-byte whitespace (e.g.,
        # ideographic space ``　`` = 3 bytes UTF-8) the
        # distinction matters for audit-payload consistency with
        # the ``actual_size`` field on size_exceeded refusals (also
        # bytes). Discriminator: 0 = exact empty; N > 0 = N
        # whitespace bytes.
        if value == "" or value.strip() == "":
            return ProjectionRefused(
                reason="sandbox_credential_projection_field_value_empty_string",
                logical_name=manifest_decl.logical_name,
                field_name=field_name,
                actual_length=len(value.encode("utf-8")),
            )

        # 2c — UTF-8 byte-size cap.
        # Encoding happens here regardless of whether the size check
        # fires — the encoded bytes are reused on the happy path to
        # build ``ProjectionPlanEntry.content_bytes`` below (single
        # encoding pass per field).
        content_bytes = value.encode("utf-8")
        if len(content_bytes) > _FIELD_VALUE_SIZE_CAP_BYTES:
            return ProjectionRefused(
                reason="sandbox_credential_projection_field_value_size_exceeded",
                logical_name=manifest_decl.logical_name,
                field_name=field_name,
                actual_size=len(content_bytes),
                cap=_FIELD_VALUE_SIZE_CAP_BYTES,
            )

        encoded.append((field_name, content_bytes))

    # Step 3: build successful ProjectionPlan.
    entries = tuple(
        ProjectionPlanEntry(
            relative_path=field_name,
            content_bytes=content_bytes,
            mode=0o440,
        )
        for field_name, content_bytes in encoded
    )

    return ProjectionPlan(
        entries=entries,
        logical_name=manifest_decl.logical_name,
        lease_id=lease.lease_id,
        projected_field_count=len(entries),
        vault_path=manifest_decl.vault_path,
        purpose_category=manifest_decl.purpose_category,
        purpose_description=manifest_decl.purpose_description,
        tenant_id=manifest_decl.tenant_id,
    )


__all__ = [
    "CredentialDecl",
    "ProjectionPlan",
    "ProjectionPlanEntry",
    "ProjectionRefusalReason",
    "ProjectionRefused",
    "compute_projection_plan",
]
