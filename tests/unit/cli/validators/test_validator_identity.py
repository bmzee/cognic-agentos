"""Sprint-7A T7 — AGNTCY/OASF Wave-1 identity-validator regressions.

Critical-controls module per Doctrine Decision G. Validator contract:

  - Universally mandatory (every pack kind): ``agent_id`` /
    ``display_name`` / ``provider_organization`` / ``provider_url``.
    Each missing OR ``AUTHOR-FILL`` placeholder fires its own
    closed-enum refusal.
  - Agent-pack-only mandatory: ``agent_card_url`` /
    ``agent_card_jws_path``. Tool + skill packs are NOT checked
    against these fields.
  - ``agent_card_jws_path`` resolves: file exists relative to
    ``pack_path``. Path missing AND placeholder both surface as
    ``identity_agent_card_jws_path_missing``; path present but file
    absent surfaces as ``identity_agent_card_jws_path_unresolvable``.
  - Wave-1 optional / Wave-2 mandatory: ``oasf_capability_set``
    absent fires a WARNING-severity finding (NOT refusal); exit
    code stays 0.

AUTHOR-FILL doctrine: T5's scaffold templates ship ``AUTHOR-FILL:``
strings at every author-customizable site. The validator treats
those as missing — so a freshly-scaffolded pack fails ``agentos
validate`` with explicit per-field remediation, the canonical
pack-author iteration loop.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import identity


def _manifest_with_identity(**identity_overrides: Any) -> dict[str, Any]:
    """Build a manifest dict carrying every Wave-1 mandatory identity
    field populated with realistic values, then apply per-test
    overrides (use ``field=None`` to delete a field, or pass a value
    to set it).

    Default kind is ``"tool"``; tests override to ``"agent"`` when
    exercising the agent-pack-only checks.
    """
    base_identity: dict[str, Any] = {
        "agent_id": "did:web:example.com:agents:demo",
        "display_name": "Demo Pack",
        "provider_organization": "Example Org",
        "provider_url": "https://example.com",
        "oasf_capability_set": ["kyc.v1"],
    }
    for k, v in identity_overrides.items():
        if v is None:
            base_identity.pop(k, None)
        else:
            base_identity[k] = v
    return {
        "pack": {"pack_id": "cognic-tool-demo", "kind": "tool"},
        "identity": base_identity,
    }


def _agent_manifest(**identity_overrides: Any) -> dict[str, Any]:
    """Variant of :func:`_manifest_with_identity` that yields an
    agent-kind manifest with the agent-pack-only mandatory fields
    populated by default. Tests use ``field=None`` to delete a
    field."""
    base_identity: dict[str, Any] = {
        "agent_id": "did:web:example.com:agents:demo",
        "display_name": "Demo Agent",
        "provider_organization": "Example Org",
        "provider_url": "https://example.com",
        "agent_card_url": "https://example.com/agents/demo/card.json",
        "agent_card_jws_path": "agent_cards/agent-card.jws",
        "oasf_capability_set": ["dialogue.v1"],
    }
    for k, v in identity_overrides.items():
        if v is None:
            base_identity.pop(k, None)
        else:
            base_identity[k] = v
    return {
        "pack": {"pack_id": "cognic-agent-demo", "kind": "agent"},
        "identity": base_identity,
    }


# ---------------------------------------------------------------------------
# (a) Universally mandatory fields — refusal-severity findings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("agent_id", "identity_agent_id_missing"),
        ("display_name", "identity_display_name_missing"),
        ("provider_organization", "identity_provider_organization_missing"),
        ("provider_url", "identity_provider_url_missing"),
    ],
)
def test_identity_universally_mandatory_field_missing_refuses(
    tmp_path: Path, field: str, reason: str
) -> None:
    """Each universally-mandatory field absent fires its own
    closed-enum refusal. Parametrized over the four fields per the
    plan-of-record."""
    findings = identity.validate(_manifest_with_identity(**{field: None}), tmp_path)
    matching = [f for f in findings if f.reason == reason]
    assert len(matching) == 1, (
        f"expected exactly one {reason!r} finding; "
        f"got {[(f.severity, f.reason) for f in findings]!r}"
    )
    assert matching[0].severity == "refusal"
    assert matching[0].affects_exit_code is True


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("agent_id", "identity_agent_id_missing"),
        ("display_name", "identity_display_name_missing"),
        ("provider_organization", "identity_provider_organization_missing"),
        ("provider_url", "identity_provider_url_missing"),
    ],
)
def test_identity_author_fill_placeholder_treated_as_missing(
    tmp_path: Path, field: str, reason: str
) -> None:
    """A field whose value starts with ``AUTHOR-FILL`` is treated the
    same as missing — pack authors who haven't replaced the scaffold
    placeholder still get the closed-enum remediation."""
    findings = identity.validate(
        _manifest_with_identity(**{field: f"AUTHOR-FILL: replace me ({field})"}), tmp_path
    )
    assert any(f.reason == reason and f.severity == "refusal" for f in findings)


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("agent_id", "identity_agent_id_missing"),
        ("display_name", "identity_display_name_missing"),
        ("provider_organization", "identity_provider_organization_missing"),
        ("provider_url", "identity_provider_url_missing"),
    ],
)
def test_identity_empty_string_treated_as_missing(tmp_path: Path, field: str, reason: str) -> None:
    """Empty strings + whitespace-only strings count as missing."""
    findings = identity.validate(_manifest_with_identity(**{field: "   "}), tmp_path)
    assert any(f.reason == reason and f.severity == "refusal" for f in findings)


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("agent_id", "identity_agent_id_missing"),
        ("display_name", "identity_display_name_missing"),
        ("provider_organization", "identity_provider_organization_missing"),
        ("provider_url", "identity_provider_url_missing"),
    ],
)
def test_identity_non_string_treated_as_missing(tmp_path: Path, field: str, reason: str) -> None:
    """Non-string values (e.g., int / list / dict) count as missing —
    every Wave-1 mandatory field is a string."""
    findings = identity.validate(_manifest_with_identity(**{field: 42}), tmp_path)
    assert any(f.reason == reason and f.severity == "refusal" for f in findings)


# ---------------------------------------------------------------------------
# (b) Agent-pack-only mandatory fields
# ---------------------------------------------------------------------------


def test_identity_tool_pack_skips_agent_card_url_check(tmp_path: Path) -> None:
    """Tool packs (kind="tool") MUST NOT be refused for missing
    ``agent_card_url`` — the field is agent-only."""
    findings = identity.validate(_manifest_with_identity(), tmp_path)
    assert not any(f.reason == "identity_agent_card_url_missing" for f in findings)


def test_identity_skill_pack_skips_agent_card_jws_check(tmp_path: Path) -> None:
    """Skill packs are also not subject to the agent-card checks."""
    manifest = _manifest_with_identity()
    manifest["pack"]["kind"] = "skill"
    findings = identity.validate(manifest, tmp_path)
    assert not any(f.reason == "identity_agent_card_url_missing" for f in findings)
    assert not any(f.reason == "identity_agent_card_jws_path_missing" for f in findings)
    assert not any(f.reason == "identity_agent_card_jws_path_unresolvable" for f in findings)


def test_identity_agent_pack_with_agent_card_url_missing_refuses(tmp_path: Path) -> None:
    """Agent pack missing ``agent_card_url`` fires
    ``identity_agent_card_url_missing``."""
    findings = identity.validate(_agent_manifest(agent_card_url=None), tmp_path)
    assert any(
        f.reason == "identity_agent_card_url_missing" and f.severity == "refusal" for f in findings
    )


def test_identity_agent_pack_with_agent_card_jws_path_missing_refuses(tmp_path: Path) -> None:
    """Agent pack missing ``agent_card_jws_path`` fires
    ``identity_agent_card_jws_path_missing``."""
    findings = identity.validate(_agent_manifest(agent_card_jws_path=None), tmp_path)
    assert any(
        f.reason == "identity_agent_card_jws_path_missing" and f.severity == "refusal"
        for f in findings
    )


def test_identity_agent_pack_with_jws_author_fill_placeholder_refuses(tmp_path: Path) -> None:
    """``AUTHOR-FILL`` placeholder in the JWS path counts as missing
    (NOT as unresolvable)."""
    findings = identity.validate(
        _agent_manifest(agent_card_jws_path="AUTHOR-FILL: pack-relative path"), tmp_path
    )
    assert any(
        f.reason == "identity_agent_card_jws_path_missing" and f.severity == "refusal"
        for f in findings
    )


def test_identity_agent_pack_with_unresolvable_jws_path_refuses(tmp_path: Path) -> None:
    """Path field is present + non-placeholder + pack-relative + path
    is contained in pack root, but the file does not exist →
    ``identity_agent_card_jws_path_unresolvable`` with
    ``failure_mode="file_not_found"`` (R22 P2 #1)."""
    findings = identity.validate(
        _agent_manifest(agent_card_jws_path="agent_cards/missing.jws"),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "identity_agent_card_jws_path_unresolvable"]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].payload["failure_mode"] == "file_not_found"


# ---------------------------------------------------------------------------
# (b.bis) R22 P2 #1 — path containment for agent_card_jws_path
# ---------------------------------------------------------------------------


def test_identity_rejects_absolute_jws_path(tmp_path: Path) -> None:
    """An absolute path (``/etc/hosts``) is rejected as
    ``failure_mode="absolute_path_rejected"`` even if the file
    exists on the host filesystem. Without this check, a malicious
    or malformed manifest could route the Sprint-4 trust-gate
    verifier at files outside the published pack."""
    # /etc/hosts almost certainly exists on the test host, so this
    # arm specifically pins that absolute-path rejection happens
    # BEFORE the file-exists check.
    findings = identity.validate(_agent_manifest(agent_card_jws_path="/etc/hosts"), tmp_path)
    matching = [f for f in findings if f.reason == "identity_agent_card_jws_path_unresolvable"]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].payload["failure_mode"] == "absolute_path_rejected"
    assert matching[0].payload["declared_path"] == "/etc/hosts"


def test_identity_rejects_path_traversal_escape(tmp_path: Path) -> None:
    """A relative path that resolves outside the pack root (via
    ``..``) is rejected as ``failure_mode="path_escape_rejected"``.
    The test creates the target file outside the pack root to
    confirm rejection happens regardless of whether the escaped
    path resolves to an existing file."""
    # Create a file outside the pack root that the escape would
    # otherwise resolve to.
    outside = tmp_path.parent / f"escape-{tmp_path.name}.jws"
    outside.write_text("escaped-content")
    try:
        findings = identity.validate(
            _agent_manifest(agent_card_jws_path=f"../escape-{tmp_path.name}.jws"),
            tmp_path,
        )
    finally:
        outside.unlink(missing_ok=True)

    matching = [f for f in findings if f.reason == "identity_agent_card_jws_path_unresolvable"]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].payload["failure_mode"] == "path_escape_rejected"


def test_identity_rejects_compound_traversal_escape(tmp_path: Path) -> None:
    """Compound ``..`` traversals that climb out of the pack root
    via subdirectory navigation are also rejected."""
    findings = identity.validate(
        _agent_manifest(agent_card_jws_path="agent_cards/../../escape.jws"),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "identity_agent_card_jws_path_unresolvable"]
    assert len(matching) == 1
    assert matching[0].payload["failure_mode"] == "path_escape_rejected"


def test_identity_accepts_normalized_path_inside_pack(tmp_path: Path) -> None:
    """A path with internal ``..`` that NORMALIZES inside the pack
    root is fine — only escapes that resolve outside are rejected.
    Pinning this prevents an over-aggressive containment check from
    rejecting legitimate path strings."""
    nested = tmp_path / "subdir" / "agent-card.jws"
    nested.parent.mkdir()
    nested.write_text("fake-jws")

    findings = identity.validate(
        # ``subdir/../subdir/agent-card.jws`` normalizes to
        # ``subdir/agent-card.jws`` which is inside the pack root.
        _agent_manifest(agent_card_jws_path="subdir/../subdir/agent-card.jws"),
        tmp_path,
    )
    assert not any(f.reason == "identity_agent_card_jws_path_unresolvable" for f in findings)


def test_identity_agent_pack_with_resolvable_jws_path_passes(tmp_path: Path) -> None:
    """Path field is present + the file exists → no
    ``identity_agent_card_jws_path_unresolvable`` finding."""
    jws = tmp_path / "agent_cards" / "agent-card.jws"
    jws.parent.mkdir(parents=True)
    jws.write_text("fake-jws")

    findings = identity.validate(
        _agent_manifest(agent_card_jws_path="agent_cards/agent-card.jws"), tmp_path
    )
    assert not any(f.reason == "identity_agent_card_jws_path_unresolvable" for f in findings)
    assert not any(f.reason == "identity_agent_card_jws_path_missing" for f in findings)


# ---------------------------------------------------------------------------
# (c) Wave-1 optional warning — oasf_capability_set
# ---------------------------------------------------------------------------


def test_identity_oasf_capability_set_missing_emits_warning_not_refusal(
    tmp_path: Path,
) -> None:
    """Wave-1 optional / Wave-2 mandatory: ``oasf_capability_set``
    absent fires WARNING-severity finding, NOT refusal. Exit code
    stays 0 in CI; pack authors see the diagnostic."""
    findings = identity.validate(_manifest_with_identity(oasf_capability_set=None), tmp_path)
    matching = [f for f in findings if f.reason == "identity_oasf_capability_set_missing"]
    assert len(matching) == 1
    assert matching[0].severity == "warning"
    assert matching[0].affects_exit_code is False


def test_identity_oasf_capability_set_present_no_warning(tmp_path: Path) -> None:
    """Capability set declared → no warning."""
    findings = identity.validate(_manifest_with_identity(), tmp_path)
    assert not any(f.reason == "identity_oasf_capability_set_missing" for f in findings)


# ---------------------------------------------------------------------------
# (d) Happy path
# ---------------------------------------------------------------------------


def test_identity_tool_pack_full_pass_returns_empty(tmp_path: Path) -> None:
    """Every Wave-1 mandatory field populated + capability set
    declared → empty list (no findings)."""
    findings = identity.validate(_manifest_with_identity(), tmp_path)
    assert findings == []


def test_identity_agent_pack_full_pass_returns_empty(tmp_path: Path) -> None:
    """Agent pack with every Wave-1 mandatory field populated +
    JWS file resolvable + capability set declared → empty list."""
    jws = tmp_path / "agent_cards" / "agent-card.jws"
    jws.parent.mkdir(parents=True)
    jws.write_text("fake-jws")

    findings = identity.validate(_agent_manifest(), tmp_path)
    assert findings == []


def test_identity_findings_are_validator_finding_instances(tmp_path: Path) -> None:
    """Type-shape pin: every emission is a :class:`ValidatorFinding`
    (not a tuple, not a dict, not a string). Catches a future
    refactor that switches to a different return-type at the seam."""
    findings = identity.validate(_manifest_with_identity(agent_id=None), tmp_path)
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, ValidatorFinding)


# ---------------------------------------------------------------------------
# (e) Multiple-failure aggregation
# ---------------------------------------------------------------------------


def test_identity_returns_one_finding_per_missing_field(tmp_path: Path) -> None:
    """All four universally-mandatory fields missing → four refusals
    (one per field), with reasons matching the closed-enum literal."""
    findings = identity.validate(
        _manifest_with_identity(
            agent_id=None,
            display_name=None,
            provider_organization=None,
            provider_url=None,
        ),
        tmp_path,
    )
    refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
    assert refusal_reasons == {
        "identity_agent_id_missing",
        "identity_display_name_missing",
        "identity_provider_organization_missing",
        "identity_provider_url_missing",
    }


def test_identity_validator_survives_malformed_pack_block(tmp_path: Path) -> None:
    """Defense-in-depth: under normal orchestrator dispatch the T6
    shape gate guarantees ``[pack]`` is a dict, but direct unit-test
    entry points may bypass that. The validator returns ``None`` from
    ``_pack_kind`` (and skips agent-only checks) rather than crashing
    when ``[pack]`` is malformed."""
    findings = identity.validate(
        {
            "pack": "not-a-table",
            "identity": {
                "agent_id": "did:web:example.com:agents:demo",
                "display_name": "Demo",
                "provider_organization": "Org",
                "provider_url": "https://example.com",
                "oasf_capability_set": ["x"],
            },
        },
        tmp_path,
    )
    # Universal-mandatory fields all populated → no refusals; no
    # agent-only checks fire because pack kind cannot be determined.
    assert findings == []


def test_identity_agent_pack_emits_all_agent_card_failures_together(tmp_path: Path) -> None:
    """Agent pack missing both agent_card_url AND agent_card_jws_path
    surfaces both findings (NOT just the first)."""
    findings = identity.validate(
        _agent_manifest(agent_card_url=None, agent_card_jws_path=None), tmp_path
    )
    refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
    assert "identity_agent_card_url_missing" in refusal_reasons
    assert "identity_agent_card_jws_path_missing" in refusal_reasons
