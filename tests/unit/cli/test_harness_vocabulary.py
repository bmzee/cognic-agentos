"""Sprint-7B.1 T6a — harness vocabulary regressions.

Doctrine Lock A pin (per
``docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md``):
the harness's supported-kinds frozenset, its kind→entry-point-group
mapping, and the canonical :data:`PackKind` literal MUST stay in
three-way lockstep. Adding a kind anywhere (e.g. a future Wave-2
"workflow" arm) without updating all three trips the drift detector
in this file.

Coverage:

  - :func:`test_supported_kinds_locked_to_pack_kind_literal_and_entry_point_group_keys`
    — three-way drift detector across
    :data:`_HARNESS_SUPPORTED_KINDS`,
    :data:`_KIND_TO_ENTRY_POINT_GROUP` keys, and
    ``typing.get_args(PackKind)``.
  - :func:`test_kind_to_entry_point_group_includes_hook_pointing_at_cognic_hooks`
    — single-source-of-truth assertion that the new ``"hook"`` key
    routes to the ``cognic.hooks`` entry-point group (introduced in
    Sprint-7B.1 T6a alongside the supported-kinds expansion).
  - :func:`test_run_harness_refuses_synthetic_unknown_kind_with_unsupported_pack_kind`
    — defense-in-depth regression that the kind-narrowing gate still
    fires for kinds outside the closed-enum (e.g. a synthetic
    ``"workflow"`` fifth kind). The gate is unreachable through the
    public CLI for kinds that ``cli/sign.py:_VALID_PACK_KINDS``
    refuses up-front, but :func:`run_harness` is also called via
    :mod:`cognic_agentos.cli.app` against unsigned packs (where the
    validate-refusals short-circuit fires first) and via direct
    pack-author integration; the gate is the last line of defense.
"""

from __future__ import annotations

from pathlib import Path
from typing import get_args

from cognic_agentos.cli.test_harness import (
    _HARNESS_SUPPORTED_KINDS,
    _KIND_TO_ENTRY_POINT_GROUP,
    run_harness,
)
from cognic_agentos.packs.lifecycle import PackKind

# ---------------------------------------------------------------------------
# Doctrine Lock A — three-way drift detector
# ---------------------------------------------------------------------------


def test_supported_kinds_locked_to_pack_kind_literal_and_entry_point_group_keys() -> None:
    """Doctrine Lock A — the harness's supported-kinds frozenset, the
    kind→entry-point-group mapping keys, and the canonical
    :data:`PackKind` literal MUST stay in three-way lockstep.

    Drift in ANY of the three trips this assertion. Concrete cases the
    detector catches:

      - adding a kind to :data:`PackKind` without wiring its
        entry-point group → ``_HARNESS_SUPPORTED_KINDS ==
        set(_KIND_TO_ENTRY_POINT_GROUP) != set(get_args(PackKind))``.
      - widening :data:`_HARNESS_SUPPORTED_KINDS` without widening the
        kind→entry-point-group map → ``_HARNESS_SUPPORTED_KINDS !=
        set(_KIND_TO_ENTRY_POINT_GROUP)``.
      - removing an entry from the kind→entry-point-group map without
        narrowing the supported-kinds set → same divergence as above.
    """
    pack_kind_literals = frozenset(get_args(PackKind))
    entry_point_keys = frozenset(_KIND_TO_ENTRY_POINT_GROUP.keys())

    assert entry_point_keys == _HARNESS_SUPPORTED_KINDS, (
        "_HARNESS_SUPPORTED_KINDS / _KIND_TO_ENTRY_POINT_GROUP drift: "
        f"in-supported-only={sorted(_HARNESS_SUPPORTED_KINDS - entry_point_keys)!r}, "
        f"in-mapping-only={sorted(entry_point_keys - _HARNESS_SUPPORTED_KINDS)!r}"
    )
    assert pack_kind_literals == _HARNESS_SUPPORTED_KINDS, (
        "_HARNESS_SUPPORTED_KINDS / PackKind literal drift: "
        f"in-supported-only={sorted(_HARNESS_SUPPORTED_KINDS - pack_kind_literals)!r}, "
        f"in-literal-only={sorted(pack_kind_literals - _HARNESS_SUPPORTED_KINDS)!r}"
    )


def test_kind_to_entry_point_group_includes_hook_pointing_at_cognic_hooks() -> None:
    """Sprint-7B.1 T6a — the new ``"hook"`` key routes to the
    ``cognic.hooks`` entry-point group. Single-sourced here so a
    future migration that renames the group updates one location.

    Pinned alongside the drift detector above so a reviewer who
    catches one bug catches the other: if the hook key were silently
    dropped from the mapping, the drift detector would fire AND this
    test would surface the specific missing routing.
    """
    assert _KIND_TO_ENTRY_POINT_GROUP.get("hook") == "cognic.hooks"


# ---------------------------------------------------------------------------
# Defense-in-depth — unknown-kind refusal preserved
# ---------------------------------------------------------------------------


def _validate_clean_unknown_kind_manifest() -> str:
    """A validate-clean ``kind = "workflow"`` manifest used to drive
    the kind-narrowing gate against a synthetic fifth kind. Mirrors
    the Section-L fixture
    ``test_cli_test_harness.py::_validate_clean_unknown_kind_manifest``
    (Sprint-7B.1 T6a converted that fixture from ``kind="skill"`` to
    ``kind="workflow"`` for the same defense-in-depth reason this
    file exercises).

    Workflow is not a member of :data:`_VALID_PACK_KINDS` at
    ``cli/sign.py:197`` so this manifest can NEVER ship through the
    full author lifecycle (sign refuses it). The harness's
    kind-narrowing gate is the runtime defense-in-depth: a pack that
    somehow bypasses sign + validate (e.g. via direct
    :func:`run_harness` invocation in pack-author integration code)
    MUST still hit the closed-enum refusal here rather than crashing
    in dispatch with a generic AttributeError on a kind the dispatch
    table does not understand.
    """
    return (
        "[pack]\n"
        'pack_id = "cognic-workflow-narrowing"\n'
        "schema_version = 1\n"
        'kind = "workflow"\n'
        "\n"
        "[identity]\n"
        'agent_id = "did:web:example.com:workflows:narrowing"\n'
        'display_name = "Narrowing Workflow"\n'
        'provider_organization = "Sprint-7B.1 T6a fixtures"\n'
        'provider_url = "https://example.com/narrowing"\n'
        'oasf_capability_set = ["test.v1"]\n'
        "\n"
        "[data_governance]\n"
        'data_classes = ["public", "internal"]\n'
        'purpose = "operational_telemetry"\n'
        'retention_policy = "none"\n'
        "\n"
        "[risk_tier]\n"
        'tier = "read_only"\n'
        "\n"
        "[supply_chain]\n"
        "attestation_paths = [\n"
        '    "attestations/cosign.sig",\n'
        '    "attestations/sbom.cdx.json",\n'
        "]\n"
    )


def _write_unknown_kind_pack(pack_path: Path) -> Path:
    """Materialise an on-disk pack directory with the workflow-kind
    manifest + the two attestation placeholder files
    :func:`run_validators` needs to clear the supply-chain
    attestation-paths reachability gate.
    """
    pack_path.mkdir(parents=True, exist_ok=True)
    (pack_path / "cognic-pack-manifest.toml").write_text(_validate_clean_unknown_kind_manifest())
    attestations = pack_path / "attestations"
    attestations.mkdir(parents=True, exist_ok=True)
    (attestations / "cosign.sig").write_bytes(b".")
    (attestations / "sbom.cdx.json").write_bytes(b"{}")
    return pack_path


def test_run_harness_refuses_synthetic_unknown_kind_with_unsupported_pack_kind(
    tmp_path: Path,
) -> None:
    """Regression — the kind-narrowing gate still fires for a fifth
    kind that is not a member of :data:`_HARNESS_SUPPORTED_KINDS`.
    After Sprint-7B.1 T6a widened the supported set from
    ``{"tool"}`` to ``{"tool", "skill", "agent", "hook"}``, the gate
    is no longer the surface that refuses skill / agent / hook packs;
    it is the runtime defense-in-depth for kinds outside the
    closed-enum entirely (e.g. a synthetic ``"workflow"`` future
    Wave-2 kind, or a malicious / typo manifest).

    The synthetic ``"workflow"`` value is deliberately chosen as a
    non-member of :data:`_VALID_PACK_KINDS` at ``cli/sign.py:197``
    AND :data:`PackKind` at ``packs/lifecycle.py:111`` — so this gate
    is reachable only via direct :func:`run_harness` invocation
    against an unsigned pack (the validate-refusals short-circuit
    runs first, but the kind-narrowing gate is the next defense if
    validate is monkeypatched / bypassed in pack-author integration).
    """
    pack_path = _write_unknown_kind_pack(tmp_path / "workflow_pack")
    report = run_harness(pack_path)

    # Validate must be clean for the kind-narrowing gate to surface
    # as the refusal; if validate refuses (e.g. supply-chain shape
    # rejection) the validate-refusals short-circuit fires first and
    # the kind-narrowing gate is never reached.
    refusals = [f for f in report.validate_findings if f.affects_exit_code]
    assert refusals == [], (
        "validate refused the workflow-kind manifest; the kind-narrowing "
        f"gate is unreachable from this fixture: {refusals!r}"
    )

    assert report.overall_status == "fail"
    assert report.pack_kind == "workflow"
    unsupported = next(
        (f for f in report.findings if f.reason == "harness_unsupported_pack_kind"),
        None,
    )
    assert unsupported is not None, (
        "kind-narrowing gate did not fire for a kind outside "
        f"_HARNESS_SUPPORTED_KINDS; findings={report.findings!r}"
    )
    assert unsupported.payload["pack_kind"] == "workflow"
    # The payload's supported_kinds list mirrors the closed-enum
    # surface authors need to widen to add a new kind; pin every
    # known kind so a future shrink (e.g. dropping "hook") trips
    # this assertion.
    assert set(unsupported.payload["supported_kinds"]) == {
        "tool",
        "skill",
        "agent",
        "hook",
    }, unsupported.payload["supported_kinds"]
    assert report.dispatch_results == []
