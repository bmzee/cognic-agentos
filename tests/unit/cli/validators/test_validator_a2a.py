"""Sprint-7A T8 — A2A conformance-validator regressions.

The A2A validator's Wave-1 scope is narrow: refuse any manifest that
declares a Wave-2-only field. The closed-enum reason
``a2a_wave2_feature_in_wave1_manifest`` already exists in the T1
ownership map; T8 wires the build-time fire-path that mirrors the
runtime reader's ``_WAVE2_MANIFEST_FIELDS`` filter set in
``protocol.a2a_capability_negotiation``.

Validator-promotion call (Doctrine Decision G):

  - Pure-delegation wrapper around the runtime reader → stays off
    the critical-controls gate.
  - Adds AgentOS-specific build-time refusals (Wave-2 features
    flagged at build time so authors fix manifests before the
    runtime reader silently filters them at registration) → joins
    the gate.

T8's scope (one Wave-2 refusal, mirroring the runtime filter)
borders on pure-delegation but adds a real fire-path the runtime
reader does NOT (the runtime silently filters; the validator
refuses). Final promotion call deferred to T16 closeout per the
plan-of-record; meanwhile T8 halts before commit per the user's
"strict review even off-gate" override.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import a2a
from cognic_agentos.protocol.a2a_capability_negotiation import _WAVE2_MANIFEST_FIELDS


def _agent_manifest_with_a2a(**a2a_overrides: Any) -> dict[str, Any]:
    """Build an agent-kind manifest carrying a Wave-1-clean ``[a2a]``
    block with per-test overrides applied. ``field=None`` deletes."""
    base: dict[str, Any] = {
        "capabilities_supported": ["dialogue.v1"],
        "streaming": False,
        "push_notification_config": False,
        "extended_agent_card": False,
        "artifacts_supported": False,
        "extensions": [],
    }
    for k, v in a2a_overrides.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return {
        "pack": {"pack_id": "cognic-agent-demo", "kind": "agent"},
        "a2a": base,
    }


# ---------------------------------------------------------------------------
# (a) [a2a] block absent / non-dict — nothing to refuse
# ---------------------------------------------------------------------------


def test_a2a_no_block_returns_empty(tmp_path: Path) -> None:
    """Tool packs (and skill packs) ship without an ``[a2a]`` block.
    The validator must NOT refuse them — the block is per-kind."""
    findings = a2a.validate({"pack": {"pack_id": "cognic-tool-x", "kind": "tool"}}, tmp_path)
    assert findings == []


def test_a2a_block_not_a_dict_returns_empty(tmp_path: Path) -> None:
    """Defense-in-depth: under normal orchestrator dispatch the T6
    shape gate guarantees ``[a2a]`` is a dict if present, but direct
    unit-test entry points may bypass that. The validator returns
    ``[]`` rather than crashing on a malformed value."""
    findings = a2a.validate(
        {"pack": {"pack_id": "cognic-agent-x", "kind": "agent"}, "a2a": "not-a-table"},
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (b) Wave-1-clean manifest — no findings
# ---------------------------------------------------------------------------


def test_a2a_wave1_clean_returns_empty(tmp_path: Path) -> None:
    """A manifest with only Wave-1 fields populated produces no
    findings."""
    findings = a2a.validate(_agent_manifest_with_a2a(), tmp_path)
    assert findings == []


def test_a2a_wave1_clean_with_streaming_returns_empty(tmp_path: Path) -> None:
    """``streaming = true`` is a Wave-1 feature; the validator does
    NOT refuse it (T7's identity validator already enforces
    agent_card_url presence for agent packs, so a streaming agent
    pack without a card URL is already caught upstream — no
    duplicate refusal here)."""
    findings = a2a.validate(_agent_manifest_with_a2a(streaming=True), tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (c) Wave-2 feature refusal — push_notification_config + future fields
# ---------------------------------------------------------------------------


def test_a2a_push_notification_config_true_refuses(tmp_path: Path) -> None:
    """``push_notification_config = true`` is a Wave-2 feature; the
    Wave-1 validator refuses with
    ``a2a_wave2_feature_in_wave1_manifest``. Payload carries the
    field name so CI parsers can render targeted remediation."""
    findings = a2a.validate(_agent_manifest_with_a2a(push_notification_config=True), tmp_path)
    matching = [f for f in findings if f.reason == "a2a_wave2_feature_in_wave1_manifest"]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].affects_exit_code is True
    assert matching[0].payload["field"] == "a2a.push_notification_config"


def test_a2a_push_notification_config_false_no_refusal(tmp_path: Path) -> None:
    """``push_notification_config = false`` is the default + does
    NOT trip the refusal (the field's presence is fine; only its
    True-valued declaration is Wave-2)."""
    findings = a2a.validate(_agent_manifest_with_a2a(push_notification_config=False), tmp_path)
    assert findings == []


def test_a2a_push_notification_config_string_true_no_refusal(tmp_path: Path) -> None:
    """Bool-only check (mirrors the runtime reader's ``_bool_or_false``
    semantics): a string ``"true"`` is NOT treated as Wave-2-opt-in.
    The runtime reader silently filters non-bool values to False;
    the build-time validator follows the same posture so manifests
    don't get refused for type mismatches the runtime would tolerate."""
    findings = a2a.validate(_agent_manifest_with_a2a(push_notification_config="true"), tmp_path)
    assert findings == []


@pytest.mark.parametrize("wave2_field", sorted(_WAVE2_MANIFEST_FIELDS))
def test_a2a_validator_iterates_runtime_wave2_field_set(tmp_path: Path, wave2_field: str) -> None:
    """The validator's Wave-2 detection set MUST stay in sync with
    the runtime reader's ``_WAVE2_MANIFEST_FIELDS``. Parametrizing
    here means a future Wave-2 field added to the runtime layer
    automatically gets a build-time refusal — and a regression that
    confirms the wiring."""
    findings = a2a.validate(_agent_manifest_with_a2a(**{wave2_field: True}), tmp_path)
    matching = [f for f in findings if f.reason == "a2a_wave2_feature_in_wave1_manifest"]
    assert len(matching) == 1
    assert matching[0].payload["field"] == f"a2a.{wave2_field}"


# ---------------------------------------------------------------------------
# (d) Type-shape pin
# ---------------------------------------------------------------------------


def test_a2a_validator_returns_validator_finding_instances(tmp_path: Path) -> None:
    """Type-shape pin: every emission is a :class:`ValidatorFinding`."""
    findings = a2a.validate(_agent_manifest_with_a2a(push_notification_config=True), tmp_path)
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, ValidatorFinding)


# ---------------------------------------------------------------------------
# (e) R23 P2 #1 — dual-path validation (top-level [a2a] + [tool.cognic.a2a])
# ---------------------------------------------------------------------------


def test_a2a_validator_refuses_wave2_at_tool_cognic_a2a_path(tmp_path: Path) -> None:
    """A pack-author who follows ``docs/A2A-CONFORMANCE.md`` (which
    uses the runtime-aligned ``[tool.cognic.a2a]`` shape) and sets
    ``push_notification_config = true`` MUST be refused, not
    silently passed. Without this dual-path check, the legacy doc
    layout was a complete bypass of T8's only Wave-2 gate."""
    manifest = {
        "pack": {"pack_id": "cognic-agent-x", "kind": "agent"},
        "tool": {"cognic": {"a2a": {"push_notification_config": True}}},
    }
    findings = a2a.validate(manifest, tmp_path)
    matching = [f for f in findings if f.reason == "a2a_wave2_feature_in_wave1_manifest"]
    assert len(matching) == 1
    assert matching[0].payload["field"] == "tool.cognic.a2a.push_notification_config"


def test_a2a_validator_refuses_wave2_in_both_locations(tmp_path: Path) -> None:
    """If a manifest declares ``[a2a]`` AND ``[tool.cognic.a2a]`` and
    BOTH set the Wave-2 field to true, the validator surfaces both
    refusals (with distinct ``field`` payloads) so authors can fix
    both sites in one pass."""
    manifest = {
        "pack": {"pack_id": "cognic-agent-x", "kind": "agent"},
        "a2a": {"push_notification_config": True},
        "tool": {"cognic": {"a2a": {"push_notification_config": True}}},
    }
    findings = a2a.validate(manifest, tmp_path)
    refusal_paths = {
        f.payload["field"] for f in findings if f.reason == "a2a_wave2_feature_in_wave1_manifest"
    }
    assert refusal_paths == {
        "a2a.push_notification_config",
        "tool.cognic.a2a.push_notification_config",
    }


def test_a2a_validator_handles_partial_tool_cognic_path(tmp_path: Path) -> None:
    """Defensive: a manifest that has ``[tool]`` but NOT
    ``[tool.cognic.a2a]`` must not crash the path walker. Same for
    ``[tool.cognic]`` without ``a2a``."""
    findings = a2a.validate(
        {
            "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
            "tool": {"cognic": {"some_other_block": {}}},
        },
        tmp_path,
    )
    assert findings == []


def test_a2a_validator_handles_non_dict_intermediate(tmp_path: Path) -> None:
    """Defensive: ``[tool]`` set to a scalar (improbable but
    possible from a malformed manifest) does not crash."""
    findings = a2a.validate(
        {
            "pack": {"pack_id": "cognic-agent-x", "kind": "agent"},
            "tool": "not-a-table",
        },
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (f) R23 P2 #2 — scaffolded agent template passes the validator cleanly
# ---------------------------------------------------------------------------


def test_a2a_validator_accepts_scaffolded_agent_template(tmp_path: Path) -> None:
    """Drift detector: the T5 agent-scaffold template's ``[a2a]``
    block fields MUST align with the validator's recognized field
    names. If the scaffold drifts (e.g., uses ``push_notifications``
    instead of ``push_notification_config``), an author flipping that
    field to true would silently pass the validator. R23 P2 #2 caught
    exactly that drift in the original T8 ship.

    This test calls the real T5 scaffolder, parses its produced
    cognic-pack-manifest.toml, runs T8 against it. Wave-1-clean
    template → no findings."""
    import tomllib

    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="agent", pack_name="example", parent_dir=tmp_path)
    manifest_path = pack_root / "cognic-pack-manifest.toml"
    parsed = tomllib.loads(manifest_path.read_text())
    findings = a2a.validate(parsed, pack_root)
    assert findings == [], (
        "T5 agent scaffold's [a2a] block produces refusals from T8; "
        "field-name drift between scaffold + validator. "
        f"Findings: {[(f.reason, f.payload) for f in findings]!r}"
    )


def test_a2a_validator_refuses_scaffolded_agent_when_wave2_flipped(
    tmp_path: Path,
) -> None:
    """The corollary regression: when an author flips the scaffold's
    ``push_notification_config`` to true (the canonical Wave-2 opt-in
    AUTHOR-FILL gesture), the validator MUST refuse. This pins that
    the scaffold's field name + the validator's recognized vocabulary
    align — flipping the documented field actually trips the gate."""
    import tomllib

    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="agent", pack_name="example", parent_dir=tmp_path)
    manifest_path = pack_root / "cognic-pack-manifest.toml"
    text = manifest_path.read_text()
    flipped = text.replace("push_notification_config = false", "push_notification_config = true")
    assert flipped != text, "scaffold did not contain expected push_notification_config field"
    manifest_path.write_text(flipped)

    parsed = tomllib.loads(manifest_path.read_text())
    findings = a2a.validate(parsed, pack_root)
    assert any(
        f.reason == "a2a_wave2_feature_in_wave1_manifest"
        and f.payload.get("field") == "a2a.push_notification_config"
        for f in findings
    )
