"""Sprint 10.6 T18 — pure-functional credential projection planner regressions.

Per ADR-004 §25 + ADR-017 + Sprint 10.6 spec §5.4 (planner contract) +
spec §5.6 (closed-enum subset). The planner is critical-controls from
birth — it owns the planner-emitted half (4 of 9) of the T16 wire-public
``SandboxRefusalReason`` credential-projection refusal vocabulary.

**No I/O. No backend coupling.** The planner is a pure function over
``(CredentialLease, CredentialDecl) → ProjectionPlan | ProjectionRefused``;
ownership (UID/GID), filesystem writes, K8s Secret creation, and
substrate preflight (tmpfs/USER/root) ALL live in the per-backend
executors (T19 Docker + T20 K8s) + the T21 lifecycle integration.

Test scope (locked at task start per user reviewer framing):
  * Happy path — byte-exact UTF-8 content; opaque relative paths;
    mode 0o440; audit metadata.
  * 4 planner-owned refusal reasons (the 5 substrate/lifecycle
    refusals are T19/T21's responsibility).
  * Drift detector pinning ``ProjectionRefusalReason`` ⊆
    ``SandboxRefusalReason`` (wire-equal subset; no independent
    enum per spec §5.6).
  * Opaque-path drift detector — no logical_name, vault_path,
    lease_id, or tenant_id leaks into the planner's relative_path
    output.
"""

from __future__ import annotations

import typing
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseActorRef,
    VaultLeaseRequest,
)
from cognic_agentos.sandbox.projection import (
    _FIELD_VALUE_SIZE_CAP_BYTES,
    CredentialDecl,
    ProjectionPlan,
    ProjectionRefusalReason,
    ProjectionRefused,
    compute_projection_plan,
)
from cognic_agentos.sandbox.protocol import SandboxRefusalReason

# ---------------------------------------------------------------------------
# Test helpers — pure construction; no I/O.
# ---------------------------------------------------------------------------


def _make_lease(token: dict[str, Any]) -> CredentialLease:
    """Construct a ``CredentialLease`` with a fixed canonical Vault
    request + arbitrary token payload.

    The ``token`` parameter is typed as ``dict[str, Any]`` (NOT the
    production ``dict[str, str]``) because negative-path tests
    deliberately exercise non-string values — Python's dataclass
    annotations are not enforced at runtime, so a defensive planner
    must catch the violation.
    """
    minted = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)
    request = VaultLeaseRequest(
        secret_path="database/creds/db-main",
        ttl_s=900,
        tenant_id="tenant-t18-test",
        # Per actual ``VaultLeaseActorRef`` shape at
        # ``core/vault.py:135-146``: field is ``actor_subject``,
        # NOT ``subject``. Plan §639 snippet draft used ``subject``;
        # corrected here + patched in plan at T18 commit time per
        # ``[[feedback_patch_plan_against_doctrine]]``.
        actor_ref=VaultLeaseActorRef(actor_subject="svc-test", actor_type="service"),
        scope_label="t18-test",
    )
    return CredentialLease(
        lease_id="database/creds/db-main/" + uuid4().hex,
        request=request,
        token=token,
        minted_at=minted,
        ttl_s_granted=900,
        expires_at=minted + timedelta(seconds=900),
    )


def _make_decl(
    *,
    expected_fields: list[str] | None = None,
    logical_name: str = "db_main",
    vault_path: str = "database/creds/db-main",
) -> CredentialDecl:
    return CredentialDecl(
        logical_name=logical_name,
        vault_path=vault_path,
        expected_fields=expected_fields
        if expected_fields is not None
        else ["username", "password"],
        ttl_s=900,
        purpose_category="application_database_read",
        purpose_description="Read-only application database access.",
        tenant_id="tenant-t18-test",
    )


# ---------------------------------------------------------------------------
# Drift detector — ProjectionRefusalReason ⊆ SandboxRefusalReason
# (wire-equal subset; no independent enum per spec §5.6).
# ---------------------------------------------------------------------------


class TestProjectionRefusalReasonDriftDetector:
    """Pin that ``ProjectionRefusalReason`` is a wire-equal subset of
    the 9 T16 ``SandboxRefusalReason`` credential-projection values.
    The planner emits only its 4 planner-owned values (field-set
    mismatch + 3 field-value-shape checks); the 5 substrate/
    lifecycle values are emitted by T19 (Docker) / T20 (K8s) /
    T21 (lifecycle integration).
    """

    _PLANNER_OWNED: typing.ClassVar[frozenset[str]] = frozenset(
        {
            "sandbox_credential_projection_field_set_mismatch",
            "sandbox_credential_projection_field_value_non_string",
            "sandbox_credential_projection_field_value_empty_string",
            "sandbox_credential_projection_field_value_size_exceeded",
        }
    )

    def test_count_is_exactly_four(self) -> None:
        """The planner owns exactly 4 of the 9 T16 credential-projection
        refusal values. Drift here means a refusal moved between the
        planner and the executors, breaking the §5.4 doctrine."""
        assert len(typing.get_args(ProjectionRefusalReason)) == 4

    def test_canonical_four_values(self) -> None:
        actual = frozenset(typing.get_args(ProjectionRefusalReason))
        assert actual == self._PLANNER_OWNED

    def test_subset_of_sandbox_refusal_reason(self) -> None:
        """Every ``ProjectionRefusalReason`` value MUST exist in the
        full ``SandboxRefusalReason`` Literal at ``protocol.py``.
        This is the wire-equal-subset doctrine — the planner does
        NOT mint its own refusal vocabulary; it surfaces a 4-value
        subset of the 36-value taxonomy that gets re-raised by T21
        as ``SandboxLifecycleRefused`` at the lifecycle integration
        boundary.
        """
        projection_values = set(typing.get_args(ProjectionRefusalReason))
        sandbox_values = set(typing.get_args(SandboxRefusalReason))
        assert projection_values.issubset(sandbox_values), (
            f"ProjectionRefusalReason values not in SandboxRefusalReason: "
            f"{sorted(projection_values - sandbox_values)}"
        )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_plan_returns_one_entry_per_field(self) -> None:
        lease = _make_lease({"username": "v-tok-uname", "password": "p@ss"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionPlan)
        assert len(result.entries) == 2
        # Mode always 0o440 per spec §5.3
        assert all(entry.mode == 0o440 for entry in result.entries)
        # Relative paths = field names only (workload mounts at
        # /run/credentials/<logical_name>)
        assert {entry.relative_path for entry in result.entries} == {"username", "password"}

    def test_content_is_byte_exact_utf8(self) -> None:
        # Byte-exactness lock per spec §5.3: no .strip(), no trailing
        # newline, no BOM. The credential file IS the value, byte-for-byte.
        lease = _make_lease({"username": "v-tok-uname", "password": "p@ss"})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionPlan)
        by_path = {e.relative_path: e.content_bytes for e in result.entries}
        assert by_path["username"] == b"v-tok-uname"
        assert by_path["password"] == b"p@ss"

    def test_content_preserves_unicode_byte_exact(self) -> None:
        # UTF-8 multi-byte sequence: ñ is 2 bytes (0xc3 0xb1).
        lease = _make_lease({"username": "señor", "password": "naïve"})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionPlan)
        by_path = {e.relative_path: e.content_bytes for e in result.entries}
        assert by_path["username"] == "señor".encode()
        assert by_path["password"] == "naïve".encode()

    def test_content_preserves_internal_whitespace(self) -> None:
        # User guardrail: no trimming except where spec explicitly says
        # whitespace-only → empty-string refusal. Internal whitespace +
        # leading/trailing newline on otherwise non-empty values MUST
        # round-trip byte-exact.
        lease = _make_lease({"username": "  spaces inside  ", "password": "trailing\n"})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionPlan)
        by_path = {e.relative_path: e.content_bytes for e in result.entries}
        assert by_path["username"] == b"  spaces inside  "
        assert by_path["password"] == b"trailing\n"

    def test_plan_carries_audit_metadata(self) -> None:
        lease = _make_lease({"username": "u", "password": "p"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionPlan)
        assert result.logical_name == "db_main"
        assert result.vault_path == "database/creds/db-main"
        assert result.purpose_category == "application_database_read"
        assert result.purpose_description == "Read-only application database access."
        assert result.projected_field_count == 2
        assert result.lease_id == lease.lease_id
        assert result.tenant_id == "tenant-t18-test"

    def test_no_underscore_files_in_plan(self) -> None:
        """Spec §5.3 — NO _metadata.json; drift guard pinned at the planner."""
        lease = _make_lease({"username": "u", "password": "p"})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionPlan)
        assert all(not entry.relative_path.startswith("_") for entry in result.entries), (
            "ProjectionPlan must not contain underscore-prefixed files; _* reserved per spec §5.3"
        )

    def test_entries_preserve_manifest_declaration_order(self) -> None:
        # Manifest-order processing is the spec's lifecycle ordering
        # contract per §5.8 step 3. Tests pin entry order matches
        # ``manifest_decl.expected_fields`` (not Vault's
        # response-key iteration order).
        lease = _make_lease({"password": "p", "username": "u"})  # insertion ≠ manifest order
        decl = _make_decl(expected_fields=["username", "password"])  # manifest order
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionPlan)
        assert [e.relative_path for e in result.entries] == ["username", "password"]


# ---------------------------------------------------------------------------
# Field-set mismatch
# ---------------------------------------------------------------------------


class TestFieldSetMismatch:
    def test_extras_only_refuses(self) -> None:
        lease = _make_lease({"username": "u", "password": "p", "ssl_cert": "cert"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_set_mismatch"
        assert result.logical_name == "db_main"
        # Diagnostic fields are tuples (immutable wire-public evidence
        # per T18 round-1 reviewer fix; spec §5.7).
        assert result.extras == ("ssl_cert",)
        assert result.missing == ()

    def test_missing_only_refuses(self) -> None:
        lease = _make_lease({"username": "u"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_set_mismatch"
        assert result.missing == ("password",)
        assert result.extras == ()

    def test_both_extras_and_missing_refuse(self) -> None:
        lease = _make_lease({"username": "u", "ssl_cert": "cert"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_set_mismatch"
        assert result.missing == ("password",)
        assert result.extras == ("ssl_cert",)

    def test_extras_and_missing_alphabetized_in_payload(self) -> None:
        """Per spec §5.7 — audit payload lists alphabetized for
        deterministic diff. Examiners reading the same refusal across
        runs must see the same byte-shape regardless of dict/set
        iteration order."""
        # Extras: insertion order ≠ alphabetical
        lease = _make_lease({"zeta": "z", "alpha": "a", "beta": "b"})
        # Missing: declaration order ≠ alphabetical
        decl = _make_decl(expected_fields=["delta", "charlie"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        # ``sorted(tuple)`` returns ``list``; wrap the RHS as ``tuple(...)``
        # so the equality comparison succeeds against the tuple-typed
        # diagnostic fields per T18 round-1 reviewer fix.
        assert result.extras == tuple(sorted(result.extras)), (
            f"extras must be alphabetized: {result.extras}"
        )
        assert result.missing == tuple(sorted(result.missing)), (
            f"missing must be alphabetized: {result.missing}"
        )
        assert result.expected_fields == tuple(sorted(result.expected_fields))
        assert result.actual_fields == tuple(sorted(result.actual_fields))


# ---------------------------------------------------------------------------
# Field value non-string
# ---------------------------------------------------------------------------


class TestFieldValueNonString:
    @pytest.mark.parametrize(
        "bad_value,expected_type_name",
        [
            (123, "int"),
            (True, "bool"),
            ([1, 2], "list"),
            ({"k": "v"}, "dict"),
            (None, "NoneType"),
        ],
    )
    def test_non_string_refuses(self, bad_value: Any, expected_type_name: str) -> None:
        lease = _make_lease({"username": "u", "password": bad_value})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_value_non_string"
        assert result.logical_name == "db_main"
        assert result.field_name == "password"
        assert result.actual_type == expected_type_name


# ---------------------------------------------------------------------------
# Field value empty / whitespace-only
# ---------------------------------------------------------------------------


class TestFieldValueEmptyString:
    def test_exact_empty_refuses_with_actual_length_zero(self) -> None:
        lease = _make_lease({"username": "u", "password": ""})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_value_empty_string"
        assert result.logical_name == "db_main"
        assert result.field_name == "password"
        # Discriminator: 0 = exact empty
        assert result.actual_length == 0

    @pytest.mark.parametrize("ws", ["   ", "\n", "\t", " \n\t "])
    def test_whitespace_only_refuses_with_actual_length_matching_input(self, ws: str) -> None:
        lease = _make_lease({"username": "u", "password": ws})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_value_empty_string"
        assert result.field_name == "password"
        # Discriminator: N > 0 = whitespace-only with N UTF-8 BYTES (not chars).
        # For ASCII whitespace, byte count == char count so ``len(ws)`` matches;
        # the multi-byte whitespace regression below pins the byte-vs-char
        # distinction explicitly per T18 round-1 reviewer fix.
        assert result.actual_length == len(ws.encode("utf-8"))
        assert result.actual_length > 0

    def test_multibyte_whitespace_actual_length_is_bytes_not_chars(self) -> None:
        """Per spec §193 + §5.7 — ``actual_length`` is the UTF-8 BYTE
        count of the whitespace-only value, NOT the character count.

        T18 round-1 reviewer found this bug via direct repro: a
        multi-byte whitespace value (``\\u3000`` = ideographic space,
        3 bytes UTF-8 ``\\xe3\\x80\\x80``) reported char-count (1)
        instead of byte-count (3), breaking audit-payload consistency
        with the ``actual_size`` field on size_exceeded refusals
        (also BYTES). Pinned here so a future implementation that
        does ``len(value)`` instead of ``len(value.encode("utf-8"))``
        trips this regression immediately.
        """
        # 　 = ideographic space (U+3000), 1 character, 3 bytes UTF-8.
        lease = _make_lease({"username": "u", "password": "　"})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_value_empty_string"
        # 3 bytes (NOT 1 char) per spec §5.7 audit-payload byte semantics.
        assert result.actual_length == 3, (
            f"expected actual_length=3 (UTF-8 byte count of \\u3000); "
            f"got actual_length={result.actual_length} (likely char count, "
            f"which breaks the spec §5.7 byte-semantics contract)"
        )


# ---------------------------------------------------------------------------
# Field value size cap
# ---------------------------------------------------------------------------


class TestFieldValueSizeExceeded:
    def test_field_above_64KiB_refuses(self) -> None:
        too_big = "x" * (_FIELD_VALUE_SIZE_CAP_BYTES + 1)
        lease = _make_lease({"username": "u", "password": too_big})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_value_size_exceeded"
        assert result.field_name == "password"
        assert result.actual_size == _FIELD_VALUE_SIZE_CAP_BYTES + 1
        assert result.cap == _FIELD_VALUE_SIZE_CAP_BYTES

    def test_field_at_64KiB_passes(self) -> None:
        # At-cap = exactly _FIELD_VALUE_SIZE_CAP_BYTES bytes; the
        # comparison is strict ``>`` (refuse only when above the
        # cap), so the at-cap field projects cleanly.
        at_cap = "x" * _FIELD_VALUE_SIZE_CAP_BYTES
        lease = _make_lease({"username": "u", "password": at_cap})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionPlan)

    def test_multibyte_unicode_counts_bytes_not_characters(self) -> None:
        # Size cap is BYTES not characters. A 32 KiB string of 2-byte
        # ñ chars is 64 KiB on the wire → at-cap (passes); a 32 KiB
        # + 1 char string is 64 KiB + 2 bytes → exceeds (refuses).
        at_cap_chars = "ñ" * (_FIELD_VALUE_SIZE_CAP_BYTES // 2)
        lease = _make_lease({"username": "u", "password": at_cap_chars})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionPlan)

        too_big_chars = "ñ" * (_FIELD_VALUE_SIZE_CAP_BYTES // 2 + 1)
        lease = _make_lease({"username": "u", "password": too_big_chars})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_value_size_exceeded"
        assert result.actual_size == _FIELD_VALUE_SIZE_CAP_BYTES + 2


# ---------------------------------------------------------------------------
# Reserved underscore prefix — defense-in-depth via field-set mismatch
# ---------------------------------------------------------------------------


class TestReservedUnderscorePrefix:
    def test_vault_returns_underscore_prefixed_field_refuses(self) -> None:
        """Spec §5.1 + §5.6 — ``_*`` prefix reserved; runtime
        refuses too.

        ``_metadata`` appearing as a Vault response key is detected
        as a field-set mismatch (``extras``) because the T14
        validator cannot allow ``_``-prefixed entries in
        ``[credentials.<name>].expected_fields`` — so the manifest
        can never declare them. Runtime defense-in-depth picks it
        up here via the existing field-set-mismatch refusal path.
        """
        lease = _make_lease({"username": "u", "password": "p", "_metadata": "leak"})
        result = compute_projection_plan(
            lease=lease, manifest_decl=_make_decl(expected_fields=["username", "password"])
        )
        assert isinstance(result, ProjectionRefused)
        assert result.reason == "sandbox_credential_projection_field_set_mismatch"
        assert "_metadata" in result.extras


# ---------------------------------------------------------------------------
# Opaque-path drift detector — relative_paths are field names only
# ---------------------------------------------------------------------------


class TestOpaquePathDriftDetector:
    """``ProjectionPlan`` entries' ``relative_paths`` must contain
    only the field name; never logical_name, vault_path, lease_id,
    or tenant_id. The planner output is the spec §5.3 opaque-at-
    every-level contract — the backend executor concatenates the
    relative path with the per-credential opaque dir (Docker) or
    uses it as the Secret key (K8s) without leaking semantic names
    onto the host filesystem.
    """

    def test_relative_paths_contain_only_field_names(self) -> None:
        lease = _make_lease({"username": "u", "password": "p"})
        decl = _make_decl(
            expected_fields=["username", "password"],
            logical_name="db_main_with_distinctive_token",
            vault_path="database/creds/distinctive_path",
        )
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionPlan)
        for entry in result.entries:
            # relative_path is EXACTLY the field name; nothing else
            assert entry.relative_path in {"username", "password"}
            # Distinctive substrings must NOT leak into the file name
            assert "distinctive_token" not in entry.relative_path
            assert "distinctive_path" not in entry.relative_path
            assert lease.lease_id not in entry.relative_path
            assert lease.request.tenant_id not in entry.relative_path
            # And neither does the credential's own metadata
            assert "db_main" not in entry.relative_path
            assert "database" not in entry.relative_path


# ---------------------------------------------------------------------------
# ProjectionRefused immutability regression (T18 round-1 reviewer fix)
# ---------------------------------------------------------------------------


class TestProjectionRefusedImmutability:
    """``ProjectionRefused`` is wire-public + feeds the
    ``credentials_projection_failed`` audit chain row payload per
    spec §5.7. ``frozen=True`` blocks attribute REASSIGNMENT but
    does NOT block mutation of list contents — so a caller could
    silently corrupt the wire-public evidence record by calling
    ``result.extras.append("leaked-field")`` between planner return
    + T21 audit emit.

    T18 round-1 reviewer fix: diagnostic fields use ``tuple[str, ...]``
    instead of ``list[str]``. Tuples are immutable at the type level —
    mutation attempts raise ``AttributeError`` (no append/extend/etc.).
    """

    def test_diagnostic_fields_are_immutable_tuples(self) -> None:
        lease = _make_lease({"username": "u", "ssl_cert": "cert"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        # All 4 diagnostic list-shaped fields are ``tuple``, NOT ``list``.
        assert isinstance(result.expected_fields, tuple)
        assert isinstance(result.actual_fields, tuple)
        assert isinstance(result.extras, tuple)
        assert isinstance(result.missing, tuple)
        # And explicitly NOT lists.
        assert not isinstance(result.expected_fields, list)
        assert not isinstance(result.actual_fields, list)
        assert not isinstance(result.extras, list)
        assert not isinstance(result.missing, list)

    def test_diagnostic_fields_cannot_be_mutated(self) -> None:
        lease = _make_lease({"username": "u", "ssl_cert": "cert"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        # Tuples have no append/extend/clear methods — accessing them
        # raises AttributeError. Pinning this prevents a future
        # refactor from re-introducing ``list[str]`` defaults.
        with pytest.raises(AttributeError):
            result.extras.append("leaked-field")  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            result.missing.append("leaked-field")  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            result.expected_fields.extend(["leaked"])  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            result.actual_fields.clear()  # type: ignore[attr-defined]

    def test_dataclass_frozen_blocks_attribute_reassignment(self) -> None:
        import dataclasses

        lease = _make_lease({"username": "u", "ssl_cert": "cert"})
        decl = _make_decl(expected_fields=["username", "password"])
        result = compute_projection_plan(lease=lease, manifest_decl=decl)
        assert isinstance(result, ProjectionRefused)
        # ``frozen=True`` + ``slots=True`` on ``ProjectionRefused`` blocks
        # attribute REASSIGNMENT — combined with the tuple-typed fields,
        # the wire-public evidence payload is immutable at both the
        # attribute-pointer level AND the contents level.
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.extras = ("leaked-field",)  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.logical_name = "other-name"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.reason = "sandbox_credential_projection_field_value_non_string"  # type: ignore[misc]

    def test_public_constructor_normalizes_list_input_to_tuple(self) -> None:
        """T18 round-2 reviewer fix: the planner always constructs
        ``tuple(sorted(...))`` internally, but ``ProjectionRefused`` is
        wire-public — a caller invoking the public constructor with
        list-shaped diagnostic-field arguments would otherwise persist
        the mutable list, defeating the immutability contract.

        ``__post_init__`` normalises list-shaped inputs to tuples via
        ``object.__setattr__`` (required to bypass ``frozen=True``
        during post-init field normalisation; standard Python frozen-
        dataclass post-init pattern).
        """
        # Construct ``ProjectionRefused`` via the public constructor
        # with EXPLICIT list-shaped inputs — these would otherwise
        # land as mutable lists on the instance attributes.
        r = ProjectionRefused(
            reason="sandbox_credential_projection_field_set_mismatch",
            logical_name="db_main",
            expected_fields=["username", "password"],  # type: ignore[arg-type]
            actual_fields=["username", "ssl_cert"],  # type: ignore[arg-type]
            extras=["ssl_cert"],  # type: ignore[arg-type]
            missing=["password"],  # type: ignore[arg-type]
        )
        # ``__post_init__`` normalised all 4 to tuples — instance
        # attributes are tuples regardless of constructor input type.
        assert isinstance(r.expected_fields, tuple)
        assert isinstance(r.actual_fields, tuple)
        assert isinstance(r.extras, tuple)
        assert isinstance(r.missing, tuple)
        assert r.expected_fields == ("username", "password")
        assert r.actual_fields == ("username", "ssl_cert")
        assert r.extras == ("ssl_cert",)
        assert r.missing == ("password",)
        # Mutation now impossible at the contents level — even though
        # the caller passed lists, the instance attributes are tuples
        # and tuples have no append/extend/clear methods.
        with pytest.raises(AttributeError):
            r.extras.append("leaked-field")  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            r.missing.append("leaked-field")  # type: ignore[attr-defined]

    def test_public_constructor_with_already_tuple_input_is_idempotent(self) -> None:
        """``__post_init__`` normalisation must be idempotent — passing
        a tuple to the constructor must NOT re-allocate or re-wrap."""
        original_extras: tuple[str, ...] = ("ssl_cert",)
        r = ProjectionRefused(
            reason="sandbox_credential_projection_field_set_mismatch",
            logical_name="db_main",
            extras=original_extras,
        )
        assert r.extras is original_extras, (
            "tuple input should pass through __post_init__ unchanged (no needless re-allocation)"
        )

    def test_string_input_rejected_with_typeerror(self) -> None:
        """T18 round-3 reviewer fix: a string IS an iterable in Python,
        so an unconditional ``tuple(value)`` normalisation would
        silently expand ``extras="ssl_cert"`` to
        ``('s', 's', 'l', '_', 'c', 'e', 'r', 't')`` — a char-tuple
        that would land on the wire-public audit chain row as garbage.
        Defensive rejection at the constructor boundary refuses this
        class of bad input with a typed/clear ``TypeError``.
        """
        with pytest.raises(TypeError, match="must be tuple"):
            ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name="db_main",
                extras="ssl_cert",  # type: ignore[arg-type]
            )

    def test_non_str_items_rejected_with_typeerror(self) -> None:
        """Every diagnostic-field entry must be a string per spec §5.7.
        Non-string items (int / None / arbitrary) raise ``TypeError``
        at the constructor rather than silently flowing through to
        the audit emit at T21."""
        with pytest.raises(TypeError, match="entries must be str"):
            ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name="db_main",
                extras=[1, 2],  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError, match="entries must be str"):
            ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name="db_main",
                missing=["password", None],  # type: ignore[arg-type]
            )

    def test_dict_input_rejected_with_typeerror(self) -> None:
        """A dict IS an iterable (over keys) in Python — the round-2
        unconditional ``tuple(value)`` would silently produce a tuple
        of dict keys, mis-shaping the audit payload. Refused with a
        typed error at the constructor boundary."""
        with pytest.raises(TypeError, match="must be tuple"):
            ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name="db_main",
                extras={"ssl_cert": "leak"},  # type: ignore[arg-type]
            )

    def test_none_input_rejected_with_typeerror(self) -> None:
        """``None`` is the most common drift mode — a caller skipping
        an optional diagnostic field via ``extras=None`` instead of
        omitting it. Refused at the constructor boundary so the
        ``frozen=True`` + tuple-typed dataclass contract is never
        violated by silent ``None``-passthrough."""
        with pytest.raises(TypeError, match="must be tuple"):
            ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name="db_main",
                extras=None,  # type: ignore[arg-type]
            )
