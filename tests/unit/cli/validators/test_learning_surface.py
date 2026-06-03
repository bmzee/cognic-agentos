"""Sprint 11.5c T2 — [learning_surface] manifest validator regressions.

Tests cover:

  - Absent block is silent (optional field).
  - Non-table leaf ``invalid_shape`` finding.
  - Unknown ``mode`` value → ``mode_invalid``.
  - Unknown / non-string data class → ``data_class_invalid``.
  - Restricted data class declared learnable → ``data_class_restricted_forbidden``.
  - Bare-string ``learnable_data_classes`` → exactly ONE
    ``learnable_data_classes_not_list`` finding (no per-character spam).
  - Well-formed canonical block ([tool.cognic.learning_surface]) → silent.
  - Well-formed alias block ([learning_surface]) → silent.
  - Every finding uses the single closed-enum reason ``learning_surface_violation``
    per ADR-019 §52 (sub-cases ride ``payload["failure_mode"]``).
"""

from __future__ import annotations

from pathlib import Path

from cognic_agentos.cli.validators import learning_surface

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _findings_canonical(block: dict) -> list:  # type: ignore[type-arg]
    """Run validator with the block at the canonical path
    ([tool.cognic.learning_surface])."""
    data = {"pack": {"pack_id": "x"}, "tool": {"cognic": {"learning_surface": block}}}
    return learning_surface.validate(data, Path("."))


def _findings_alias(block: object) -> list:  # type: ignore[type-arg]
    """Run validator with the block at the top-level alias path
    ([learning_surface])."""
    data = {"pack": {"pack_id": "x"}, "learning_surface": block}
    return learning_surface.validate(data, Path("."))


def _violation_modes(fs: list) -> set[str]:  # type: ignore[type-arg]
    return {f.payload.get("failure_mode") for f in fs if f.reason == "learning_surface_violation"}


# ---------------------------------------------------------------------------
# (a) Absent block — no findings
# ---------------------------------------------------------------------------


def test_no_learning_surface_block_is_silent() -> None:
    """A manifest with no [learning_surface] block at either path → empty
    list.  The block is optional; absence means the pack never writes to
    long_term memory as a learning surface."""
    result = learning_surface.validate({"pack": {"pack_id": "x"}}, Path("."))
    assert result == []


# ---------------------------------------------------------------------------
# (b) Non-table (invalid_shape)
# ---------------------------------------------------------------------------


def test_non_table_block_alias_path_refuses_invalid_shape() -> None:
    """[learning_surface] = "yes" (bare string) must surface
    ``invalid_shape``, not be treated as absent.

    This validates the local ``_resolve`` helper correctly returns the
    non-dict leaf as-is (contrast with ``data_governance._resolve_path``
    which returns None for non-dict leaves and would mask this error).
    """
    modes = _violation_modes(_findings_alias("yes"))
    assert "invalid_shape" in modes


def test_non_table_block_canonical_path_refuses_invalid_shape() -> None:
    """[tool.cognic.learning_surface] = 42 (integer) → ``invalid_shape``."""
    data = {"pack": {"pack_id": "x"}, "tool": {"cognic": {"learning_surface": 42}}}
    modes = _violation_modes(learning_surface.validate(data, Path(".")))
    assert "invalid_shape" in modes


# ---------------------------------------------------------------------------
# (c) mode field validation
# ---------------------------------------------------------------------------


def test_unknown_mode_refuses() -> None:
    """An unknown mode value → ``mode_invalid`` finding."""
    modes = _violation_modes(_findings_canonical({"mode": "everything"}))
    assert "mode_invalid" in modes


def test_valid_mode_disabled_is_silent() -> None:
    """``mode="disabled"`` is a valid LearningSurfaceMode → no findings."""
    assert _findings_canonical({"mode": "disabled"}) == []


def test_valid_mode_profile_only_is_silent() -> None:
    """``mode="profile_only"`` is a valid LearningSurfaceMode → no findings."""
    assert _findings_canonical({"mode": "profile_only"}) == []


def test_valid_mode_notes_and_profile_is_silent() -> None:
    """``mode="notes_and_profile"`` is a valid LearningSurfaceMode → no findings."""
    assert _findings_canonical({"mode": "notes_and_profile"}) == []


def test_absent_mode_field_is_silent() -> None:
    """Absent ``mode`` field → no findings (mode is optional)."""
    assert _findings_canonical({}) == []


# ---------------------------------------------------------------------------
# (d) learnable_data_classes — shape guard
# ---------------------------------------------------------------------------


def test_learnable_data_classes_as_string_refuses_not_list_no_per_char_spam() -> None:
    """A bare string ``learnable_data_classes = "public"`` must produce
    EXACTLY ONE ``learnable_data_classes_not_list`` finding and ZERO
    ``data_class_invalid`` findings.

    Without the shape guard, a naive ``for dc in ldc`` would iterate
    per-character, producing 6 spurious ``data_class_invalid`` findings
    for the 6 characters of ``"public"``.
    """
    fs = _findings_canonical({"mode": "profile_only", "learnable_data_classes": "public"})
    modes = _violation_modes(fs)
    assert "learnable_data_classes_not_list" in modes
    assert "data_class_invalid" not in modes


def test_learnable_data_classes_as_integer_refuses_not_list() -> None:
    """``learnable_data_classes = 1`` → ``learnable_data_classes_not_list``."""
    modes = _violation_modes(_findings_canonical({"learnable_data_classes": 1}))
    assert "learnable_data_classes_not_list" in modes


# ---------------------------------------------------------------------------
# (e) learnable_data_classes — member validation
# ---------------------------------------------------------------------------


def test_unknown_data_class_member_refuses() -> None:
    """Unknown string member → ``data_class_invalid``."""
    modes = _violation_modes(
        _findings_canonical({"mode": "profile_only", "learnable_data_classes": ["nope"]})
    )
    assert "data_class_invalid" in modes


def test_non_string_data_class_member_refuses() -> None:
    """Non-string member (integer) → ``data_class_invalid``."""
    modes = _violation_modes(
        _findings_canonical({"mode": "profile_only", "learnable_data_classes": [42]})
    )
    assert "data_class_invalid" in modes


# ---------------------------------------------------------------------------
# (f) Restricted data class bank-safety rule
# ---------------------------------------------------------------------------


def test_customer_pii_declared_learnable_refuses() -> None:
    """``customer_pii`` is in RESTRICTED_DATA_CLASSES → must refuse."""
    modes = _violation_modes(
        _findings_canonical({"mode": "profile_only", "learnable_data_classes": ["customer_pii"]})
    )
    assert "data_class_restricted_forbidden" in modes


def test_payment_data_declared_learnable_refuses() -> None:
    """``payment_data`` is in RESTRICTED_DATA_CLASSES → must refuse."""
    modes = _violation_modes(
        _findings_canonical({"mode": "profile_only", "learnable_data_classes": ["payment_data"]})
    )
    assert "data_class_restricted_forbidden" in modes


def test_credentials_declared_learnable_refuses() -> None:
    """``credentials`` is in RESTRICTED_DATA_CLASSES → must refuse."""
    modes = _violation_modes(
        _findings_canonical({"mode": "profile_only", "learnable_data_classes": ["credentials"]})
    )
    assert "data_class_restricted_forbidden" in modes


def test_regulator_communication_declared_learnable_refuses() -> None:
    """``regulator_communication`` is in RESTRICTED_DATA_CLASSES → must refuse."""
    modes = _violation_modes(
        _findings_canonical(
            {
                "mode": "profile_only",
                "learnable_data_classes": ["regulator_communication"],
            }
        )
    )
    assert "data_class_restricted_forbidden" in modes


def test_restricted_class_refuses_not_data_class_invalid() -> None:
    """A restricted class is a valid DataClass but ALSO restricted.
    The finding must be ``data_class_restricted_forbidden``, not
    ``data_class_invalid`` — the elif branch in the validator guarantees
    they are mutually exclusive."""
    fs = _findings_canonical({"mode": "profile_only", "learnable_data_classes": ["customer_pii"]})
    modes = _violation_modes(fs)
    assert "data_class_restricted_forbidden" in modes
    assert "data_class_invalid" not in modes


# ---------------------------------------------------------------------------
# (g) Well-formed blocks — no findings
# ---------------------------------------------------------------------------


def test_well_formed_canonical_block_is_silent() -> None:
    """Canonical path, valid mode, non-restricted data classes → no findings."""
    fs = _findings_canonical(
        {"mode": "profile_only", "learnable_data_classes": ["internal", "public"]}
    )
    assert fs == []


def test_well_formed_alias_block_is_silent() -> None:
    """[learning_surface] alias path with valid mode → no findings."""
    fs = _findings_alias({"mode": "disabled"})
    assert fs == []


def test_well_formed_notes_and_profile_with_safe_classes() -> None:
    """``notes_and_profile`` mode with non-restricted classes → no findings."""
    fs = _findings_canonical(
        {
            "mode": "notes_and_profile",
            "learnable_data_classes": [
                "public",
                "internal",
                "audit_trail",
                "model_inputs",
                "model_outputs",
            ],
        }
    )
    assert fs == []


# ---------------------------------------------------------------------------
# (h) Closed-enum reason invariant (ADR-019 §52)
# ---------------------------------------------------------------------------


def test_every_finding_uses_the_single_closed_enum_reason() -> None:
    """ADR-019 §52 — exactly one ValidatorReason value
    (``learning_surface_violation``). Sub-cases ride
    ``payload["failure_mode"]``, NOT separate reason values."""
    fs = _findings_canonical({"mode": "bad", "learnable_data_classes": ["customer_pii", "nope"]})
    assert fs and all(f.reason == "learning_surface_violation" for f in fs)


def test_failure_mode_always_present_in_payload() -> None:
    """Every finding must carry ``payload["failure_mode"]`` so CI parsers
    can discriminate sub-cases without parsing the human-readable message."""
    test_cases = [
        _findings_alias("yes"),  # invalid_shape
        _findings_canonical({"mode": "bad"}),  # mode_invalid
        _findings_canonical({"learnable_data_classes": "str"}),  # not_list
        _findings_canonical({"learnable_data_classes": ["nope"]}),  # data_class_invalid
        _findings_canonical({"learnable_data_classes": ["customer_pii"]}),  # restricted_forbidden
    ]
    for findings in test_cases:
        for f in findings:
            assert "failure_mode" in f.payload, (
                f"finding {f.reason!r} is missing payload['failure_mode']: {f.payload!r}"
            )


def test_block_path_always_present_in_payload() -> None:
    """Every finding must carry ``payload["block_path"]`` so CI parsers
    know which path (canonical vs alias) triggered the finding."""
    # trigger via the alias path
    fs = _findings_alias("yes")
    assert fs
    assert all("block_path" in f.payload for f in fs)
    assert all(f.payload["block_path"] == "learning_surface" for f in fs)

    # trigger via the canonical path
    fs2 = _findings_canonical({"mode": "bad"})
    assert fs2
    assert all("block_path" in f.payload for f in fs2)
    assert all(f.payload["block_path"] == "tool.cognic.learning_surface" for f in fs2)
