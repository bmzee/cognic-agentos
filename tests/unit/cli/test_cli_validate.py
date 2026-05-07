"""Sprint-7A T6 — `agentos validate` orchestrator regressions.

The orchestrator is a critical-controls module per Doctrine Decision
G — every commit halts before commit + the module sits at the strict
95% line / 90% branch coverage floor. Tests cover:

  - Manifest-shape refusals: ``manifest_not_found`` /
    ``manifest_unparseable_toml`` are emitted as
    refusal-severity ``ValidatorFinding`` instances BEFORE any
    per-concern validator runs.
  - Validator dispatch: ``run_validators`` calls every per-concern
    validator (identity / a2a / mcp / data_governance / risk_tier /
    supply_chain) exactly once with ``(parsed_dict, pack_path)`` and
    concatenates their returned ``list[ValidatorFinding]`` in
    deterministic order.
  - Severity-aware exit code: warnings render to stderr but DO NOT
    affect exit code; refusals do. A mixed warnings+refusals run
    renders BOTH and exits 1 (any refusal wins).
  - JSON output mode: each finding renders as one JSON line carrying
    ``severity / reason / message / payload``.
  - GH-Actions log format on the default text path (so CI logs
    surface inline annotations at the manifest path).
  - Reason vocabulary check: every emitted reason appears in the
    closed-enum ``ValidatorReason`` literal (drift detector — the
    orchestrator's own emissions stay inside the closed-enum set).
    R20 P3 #1: the drift detector covers all four orchestrator-
    emitted reasons (``manifest_not_found`` /
    ``manifest_unparseable_toml`` /
    ``manifest_missing_pack_id`` /
    ``manifest_missing_required_block``); R19 added the latter two
    when the manifest-shape gate landed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import (
    _VALIDATOR_REASON_OWNERSHIP,
    ValidatorFinding,
    app,
)

if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# Test fixtures: synthesize manifests on disk
# ---------------------------------------------------------------------------

#: Minimum-shape manifest that passes the orchestrator's R19 P2 #1
#: shape gate AND the Wave-1 per-concern validators that have shipped
#: at this commit (T7 identity, T8 a2a, T9 mcp, T10 data_governance).
#: T11-T12 are still stubs — once they ship real refusals, this
#: constant grows to cover their expected clean-pass shape too.
#:
#: Identity block (T7) carries every universally-mandatory field +
#: ``oasf_capability_set`` (so the Wave-1 warning is silenced).
#: data_governance block (T10) populates every closed-enum field
#: with valid values from the canonical _governance_vocab catalogue
#: + a non-restricted data_classes set so the cross-checks pass.
#: Pack kind is ``"tool"`` — agent-pack-only identity checks are
#: skipped, MCP block is empty so T9 doesn't fire on caching/etc.
_MINIMAL_VALID_MANIFEST: str = """\
[pack]
pack_id = "cognic-tool-test"
kind = "tool"

[identity]
agent_id = "did:web:example.com:tools:test"
display_name = "Test Tool"
provider_organization = "Example Org"
provider_url = "https://example.com"
oasf_capability_set = ["test.v1"]

[data_governance]
data_classes = ["public", "internal"]
purpose = "operational_telemetry"
retention_policy = "none"

[risk_tier]
tier = "read_only"

[supply_chain]
"""


def _write_manifest(pack_path: Path, body: str) -> Path:
    pack_path.mkdir(parents=True, exist_ok=True)
    manifest = pack_path / "cognic-pack-manifest.toml"
    manifest.write_text(body)
    return manifest


def _write_manifest_bytes(pack_path: Path, body: bytes) -> Path:
    """Write raw bytes (used for the R19 P2 #2 invalid-UTF-8 arm)."""
    pack_path.mkdir(parents=True, exist_ok=True)
    manifest = pack_path / "cognic-pack-manifest.toml"
    manifest.write_bytes(body)
    return manifest


# ---------------------------------------------------------------------------
# (a) run_validators — pure-function seam used by SDK helpers
# ---------------------------------------------------------------------------


def test_run_validators_returns_manifest_not_found_when_missing(tmp_path: Path) -> None:
    """Pack root with no ``cognic-pack-manifest.toml`` → one refusal-
    severity finding with ``reason="manifest_not_found"``. No
    per-concern validator runs."""
    from cognic_agentos.cli.validate import run_validators

    findings = run_validators(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "refusal"
    assert findings[0].reason == "manifest_not_found"
    assert findings[0].affects_exit_code is True


def test_run_validators_returns_manifest_unparseable_when_bad_toml(tmp_path: Path) -> None:
    """Pack root with a malformed manifest (TOMLDecodeError) → one
    refusal with ``reason="manifest_unparseable_toml"``. Error text
    is in the message + payload carries ``error_type``."""
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(tmp_path, "this is = = = not = valid TOML \x00")
    findings = run_validators(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "refusal"
    assert findings[0].reason == "manifest_unparseable_toml"
    assert "error_type" in findings[0].payload


def test_run_validators_returns_empty_for_valid_minimal_manifest(tmp_path: Path) -> None:
    """Manifest parses cleanly + every per-concern validator (T7-T12
    stubs at this commit) returns ``[]`` → orchestrator returns ``[]``.
    Pack-author exit code on this path is 0."""
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)
    findings = run_validators(tmp_path)
    assert findings == []


def test_run_validators_dispatches_to_every_validator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every per-concern validator (identity / a2a / mcp /
    data_governance / risk_tier / supply_chain) is called exactly
    once with ``(parsed_dict, pack_path)``. Pinning here catches a
    future refactor that drops one of the six dispatch sites."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)

    calls: list[str] = []

    def _make_recorder(name: str) -> Callable[[dict, Path], list[ValidatorFinding]]:  # type: ignore[type-arg]
        def _validate(data: dict, pack_path: Path) -> list[ValidatorFinding]:  # type: ignore[type-arg]
            calls.append(name)
            return []

        return _validate

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", _make_recorder(name))

    run_validators(tmp_path)

    assert calls == [
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ]


def test_run_validators_aggregates_findings_in_dispatch_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings from later validators land AFTER findings from earlier
    validators. Deterministic order matters because pack-author docs
    + CI parsers may rely on positional output."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)

    monkeypatch.setattr(
        validators.identity,
        "validate",
        lambda data, pack: [
            ValidatorFinding(
                severity="refusal",
                reason="identity_agent_id_missing",
                message="from identity",
            )
        ],
    )
    monkeypatch.setattr(
        validators.supply_chain,
        "validate",
        lambda data, pack: [
            ValidatorFinding(
                severity="refusal",
                reason="supply_chain_attestation_path_missing",
                message="from supply_chain",
            )
        ],
    )

    findings = run_validators(tmp_path)
    assert [f.reason for f in findings] == [
        "identity_agent_id_missing",
        "supply_chain_attestation_path_missing",
    ]


# ---------------------------------------------------------------------------
# (a.bis) R19 P2 #1 — manifest-shape gate (pack_id + required blocks)
# ---------------------------------------------------------------------------


def test_run_validators_returns_manifest_missing_pack_id_when_pack_block_absent(
    tmp_path: Path,
) -> None:
    """A manifest with no ``[pack]`` table at all → refusal-severity
    finding ``manifest_missing_pack_id`` with
    ``failure_mode="pack_block_absent"`` in payload."""
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(tmp_path, "[identity]\n[data_governance]\n[risk_tier]\n[supply_chain]\n")
    findings = run_validators(tmp_path)
    assert any(f.reason == "manifest_missing_pack_id" for f in findings)
    pack_id_finding = next(f for f in findings if f.reason == "manifest_missing_pack_id")
    assert pack_id_finding.payload["failure_mode"] == "pack_block_absent"


def test_run_validators_returns_manifest_missing_pack_id_when_pack_id_field_absent(
    tmp_path: Path,
) -> None:
    """``[pack]`` exists but no ``pack_id`` field → same closed-enum
    reason; payload's ``failure_mode`` field distinguishes."""
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(
        tmp_path,
        "[pack]\nschema_version = 1\n[identity]\n[data_governance]\n[risk_tier]\n[supply_chain]\n",
    )
    findings = run_validators(tmp_path)
    pack_id_finding = next(f for f in findings if f.reason == "manifest_missing_pack_id")
    assert pack_id_finding.payload["failure_mode"] == "pack_id_field_absent_or_empty"


def test_run_validators_returns_manifest_missing_pack_id_when_pack_id_empty_string(
    tmp_path: Path,
) -> None:
    """Empty-string ``pack_id`` is rejected (whitespace-only too)."""
    from cognic_agentos.cli.validate import run_validators

    _write_manifest(
        tmp_path,
        '[pack]\npack_id = "   "\n[identity]\n[data_governance]\n[risk_tier]\n[supply_chain]\n',
    )
    findings = run_validators(tmp_path)
    assert any(f.reason == "manifest_missing_pack_id" for f in findings)


@pytest.mark.parametrize(
    "missing_block",
    ["identity", "data_governance", "risk_tier", "supply_chain"],
)
def test_run_validators_returns_manifest_missing_required_block(
    tmp_path: Path, missing_block: str
) -> None:
    """One refusal-severity finding per missing required top-level
    block, with the block name + ``failure_mode="block_absent"`` in
    the payload."""
    from cognic_agentos.cli.validate import run_validators

    blocks = {"identity", "data_governance", "risk_tier", "supply_chain"}
    blocks.discard(missing_block)
    body = '[pack]\npack_id = "cognic-tool-test"\n' + "".join(f"[{b}]\n" for b in sorted(blocks))
    _write_manifest(tmp_path, body)

    findings = run_validators(tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block" and f.payload.get("block") == missing_block
    ]
    assert len(matching) == 1, (
        f"expected exactly one missing-block finding for {missing_block!r}; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )
    assert matching[0].payload["failure_mode"] == "block_absent"


@pytest.mark.parametrize(
    "non_table_block",
    ["identity", "data_governance", "risk_tier", "supply_chain"],
)
def test_run_validators_rejects_non_table_required_block(
    tmp_path: Path, non_table_block: str
) -> None:
    """R20 P2 #1: a required block whose value is a scalar (e.g.,
    ``identity = "x"``) is treated the same as missing — it would
    crash a per-concern validator that expects a TOML sub-table.
    The closed-enum reason is the same as the absent case;
    ``failure_mode="block_not_table"`` distinguishes the two."""
    from cognic_agentos.cli.validate import run_validators

    blocks = {"identity", "data_governance", "risk_tier", "supply_chain"}
    blocks.discard(non_table_block)
    # TOML grammar: top-level key-value pairs MUST appear before any
    # ``[table]`` starts. So the non-table scalar goes at the very
    # top of the manifest, followed by [pack] + the remaining
    # sub-tables.
    body = f'{non_table_block} = "not-a-table"\n[pack]\npack_id = "cognic-tool-test"\n' + "".join(
        f"[{b}]\n" for b in sorted(blocks)
    )
    _write_manifest(tmp_path, body)

    findings = run_validators(tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block"
        and f.payload.get("block") == non_table_block
    ]
    assert len(matching) == 1, (
        f"expected exactly one non-table finding for {non_table_block!r}; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )
    assert matching[0].payload["failure_mode"] == "block_not_table"


def test_run_validators_short_circuits_on_non_table_required_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shape-gate short-circuit also fires when a required block
    is present but not a TOML sub-table — per-concern validators
    MUST NOT be reached with malformed shape. R20 P2 #1."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    called: list[str] = []

    def _record(name: str) -> Callable[[dict, Path], list[ValidatorFinding]]:  # type: ignore[type-arg]
        def _validate(data: dict, pack_path: Path) -> list[ValidatorFinding]:  # type: ignore[type-arg]
            called.append(name)
            return []

        return _validate

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", _record(name))

    _write_manifest(
        tmp_path,
        # Top-level scalar BEFORE [pack] (TOML grammar).
        'identity = "not-a-table"\n'
        '[pack]\npack_id = "cognic-tool-test"\n'
        "[data_governance]\n[risk_tier]\n[supply_chain]\n",
    )
    findings = run_validators(tmp_path)

    assert called == [], "per-concern validators called despite non-table shape failure"
    assert findings, "expected shape-gate refusals"


@pytest.mark.parametrize(
    "block",
    ["identity", "data_governance", "supply_chain"],
)
def test_run_validators_accepts_required_block_at_legacy_path(
    tmp_path: Path, block: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R27 P2 #1: a manifest declaring a required block at the legacy
    ``[tool.cognic.<block>]`` location MUST satisfy the shape gate so
    the per-concern validators (which dual-path-read) get dispatched.
    Without this, the orchestrator short-circuited before the legacy
    compatibility advertised in T7-T10 was reachable.

    ``risk_tier`` is excluded from this parametrize because its legacy
    shape is structurally different — it nests inside
    ``[tool.cognic.runtime]`` as a flat ``risk_tier`` field rather than
    a sub-table. The dedicated regression for that path lives at
    :func:`test_run_validators_accepts_risk_tier_at_legacy_runtime_path`
    below."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    # Stub each per-concern validator so the test isolates the shape
    # gate's behavior (we only care that dispatch happens, not what
    # the per-concern validators say about empty blocks).
    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", lambda data, pack: [])

    blocks = {"identity", "data_governance", "risk_tier", "supply_chain"}
    blocks.discard(block)
    body_lines = ['[pack]\npack_id = "cognic-tool-test"\n']
    body_lines.extend(f"[{b}]\n" for b in sorted(blocks))
    # The block under test goes to the legacy location.
    body_lines.append(f"[tool.cognic.{block}]\n")
    _write_manifest(tmp_path, "".join(body_lines))

    findings = run_validators(tmp_path)
    # NO manifest_missing_required_block for the block at the legacy
    # location.
    block_misses = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block" and f.payload.get("block") == block
    ]
    assert block_misses == [], (
        f"shape gate refused legacy-path [{block}] block when canonical "
        f"top-level was absent: {[(f.reason, f.payload) for f in findings]!r}"
    )


def test_run_validators_accepts_risk_tier_at_legacy_runtime_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T11 doctrine fix: the docs / runtime / fixture-aligned legacy
    shape for risk-tier declaration is ``[tool.cognic.runtime]`` with a
    flat ``risk_tier`` field — NOT ``[tool.cognic.risk_tier].tier``.

    Per ``docs/BUILD_PLAN.md:528``, ``docs/HOW-TO-WRITE-A-PACK.md``,
    the Sprint-7A plan-of-record §"Task 11", and both reference
    fixture packs (``tests/fixtures/cognic_test_{mcp,agent}_pack/``),
    the pack-author-facing legacy shape is::

        [tool.cognic.runtime]
        risk_tier = "read_only"

    A docs-shaped manifest declaring its risk tier this way and NOT
    declaring a top-level ``[risk_tier]`` block MUST satisfy the
    orchestrator's shape gate so the per-concern validator runs."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", lambda data, pack: [])

    _write_manifest(
        tmp_path,
        '[pack]\npack_id = "cognic-tool-test"\n'
        "[identity]\n[data_governance]\n[supply_chain]\n"
        '[tool.cognic.runtime]\nrisk_tier = "read_only"\n',
    )

    findings = run_validators(tmp_path)
    block_misses = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block" and f.payload.get("block") == "risk_tier"
    ]
    assert block_misses == [], (
        "shape gate refused docs-shaped [tool.cognic.runtime] risk_tier "
        f"declaration: {[(f.reason, f.payload) for f in findings]!r}"
    )


@pytest.mark.parametrize(
    "tool_value",
    [
        # [tool] declared as a scalar — short-circuits before reaching
        # the [tool.cognic] check.
        '"not-a-table"',
        # [tool] is a table but [tool.cognic] is a scalar.
        "\n[tool]\ncognic = 42",
        # [tool.cognic] is a table but [tool.cognic.runtime] is a scalar.
        '\n[tool.cognic]\nruntime = "x"',
    ],
)
def test_run_validators_runtime_legacy_path_with_malformed_tool_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool_value: str
) -> None:
    """Defensive guards in the risk_tier-special-case legacy resolver:
    a malformed ``[tool]`` / ``[tool.cognic]`` / ``[tool.cognic.runtime]``
    intermediate cannot rescue a missing top-level ``[risk_tier]``.
    The refusal still surfaces; the resolver returns False before
    reaching the ``risk_tier`` field check."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", lambda data, pack: [])

    if tool_value.startswith('"'):
        body = (
            '[pack]\npack_id = "cognic-tool-test"\n'
            "[identity]\n[data_governance]\n[supply_chain]\n"
            f"tool = {tool_value}\n"
        )
    else:
        body = (
            '[pack]\npack_id = "cognic-tool-test"\n'
            "[identity]\n[data_governance]\n[supply_chain]\n" + tool_value + "\n"
        )
    _write_manifest(tmp_path, body)

    findings = run_validators(tmp_path)
    block_misses = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block" and f.payload.get("block") == "risk_tier"
    ]
    assert len(block_misses) == 1
    assert block_misses[0].payload["failure_mode"] == "block_absent"


def test_run_validators_rejects_runtime_block_without_risk_tier_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``[tool.cognic.runtime]`` only satisfies the risk_tier shape
    gate when the block ACTUALLY carries a ``risk_tier`` field. An
    empty ``[tool.cognic.runtime]`` (or one carrying only unrelated
    runtime config) does not rescue a missing top-level
    ``[risk_tier]`` declaration."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", lambda data, pack: [])

    _write_manifest(
        tmp_path,
        '[pack]\npack_id = "cognic-tool-test"\n'
        "[identity]\n[data_governance]\n[supply_chain]\n"
        '[tool.cognic.runtime]\nsome_other_setting = "x"\n',
    )

    findings = run_validators(tmp_path)
    block_misses = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block" and f.payload.get("block") == "risk_tier"
    ]
    assert len(block_misses) == 1
    assert block_misses[0].payload["failure_mode"] == "block_absent"


def test_run_validators_legacy_path_with_top_level_present_no_double_fire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R27 P2 #1: when BOTH canonical and legacy locations declare
    a required block, the shape gate fires no refusal (the canonical
    path satisfies; the legacy is harmless). Per-concern validators
    handle dual-path semantics themselves."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", lambda data, pack: [])

    _write_manifest(
        tmp_path,
        '[pack]\npack_id = "cognic-tool-test"\n'
        "[identity]\n[data_governance]\n[risk_tier]\n[supply_chain]\n"
        "[tool.cognic.identity]\n[tool.cognic.data_governance]\n",
    )

    findings = run_validators(tmp_path)
    assert not any(f.reason == "manifest_missing_required_block" for f in findings)


def test_run_validators_top_level_non_table_not_rescued_by_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R27 P2 #1 corollary: if top-level is present-but-non-table,
    the legacy path does NOT rescue it — pack-author should fix the
    canonical location. Block_not_table refusal still fires."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", lambda data, pack: [])

    _write_manifest(
        tmp_path,
        # identity declared as a scalar at top-level, then as a table
        # at legacy. The non-table top-level still trips the gate.
        'identity = "not-a-table"\n'
        '[pack]\npack_id = "cognic-tool-test"\n'
        "[data_governance]\n[risk_tier]\n[supply_chain]\n"
        "[tool.cognic.identity]\n",
    )

    findings = run_validators(tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "manifest_missing_required_block" and f.payload.get("block") == "identity"
    ]
    assert len(matching) == 1
    assert matching[0].payload["failure_mode"] == "block_not_table"


def test_run_validators_short_circuits_per_concern_dispatch_on_shape_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the manifest fails the shape gate, the per-concern
    validators MUST NOT be called — they may panic on missing blocks
    they're scoped against. R19 P2 #1 short-circuit doctrine."""
    from cognic_agentos.cli import validators
    from cognic_agentos.cli.validate import run_validators

    called: list[str] = []

    def _record(name: str) -> Callable[[dict, Path], list[ValidatorFinding]]:  # type: ignore[type-arg]
        def _validate(data: dict, pack_path: Path) -> list[ValidatorFinding]:  # type: ignore[type-arg]
            called.append(name)
            return []

        return _validate

    for name in (
        "identity",
        "a2a",
        "mcp",
        "data_governance",
        "risk_tier",
        "supply_chain",
    ):
        monkeypatch.setattr(getattr(validators, name), "validate", _record(name))

    # Empty TOML → shape gate trips on every required block
    _write_manifest(tmp_path, "")
    findings = run_validators(tmp_path)

    assert called == [], "per-concern validators called despite shape-gate refusal"
    assert findings, "expected shape-gate refusals"


# ---------------------------------------------------------------------------
# (a.tris) R19 P2 #2 — invalid UTF-8 surfaces as manifest_unparseable_toml
# ---------------------------------------------------------------------------


def test_run_validators_handles_invalid_utf8_as_manifest_unparseable_toml(
    tmp_path: Path,
) -> None:
    """Non-UTF-8 bytes in the manifest → ``manifest_unparseable_toml``
    refusal carrying ``error_type=UnicodeDecodeError`` in payload.
    Without this, the orchestrator would crash with an uncaught
    ``UnicodeDecodeError`` from ``Path.read_text()``."""
    from cognic_agentos.cli.validate import run_validators

    # \xff is not valid UTF-8.
    _write_manifest_bytes(tmp_path, b"\xff key = 'value'\n")
    findings = run_validators(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "refusal"
    assert findings[0].reason == "manifest_unparseable_toml"
    assert findings[0].payload["error_type"] == "UnicodeDecodeError"


# ---------------------------------------------------------------------------
# (b) format_finding — rendering helper
# ---------------------------------------------------------------------------


def test_format_finding_default_text_for_refusal_uses_gh_actions_error() -> None:
    """The default text format is GH-Actions inline annotation:
    ``::error file=<pack>::<reason>: <message>``. Surfaces refusals
    inline in CI logs at the pack path."""
    from cognic_agentos.cli.validate import format_finding

    f = ValidatorFinding(
        severity="refusal",
        reason="manifest_not_found",
        message="manifest missing at /tmp/pack/cognic-pack-manifest.toml",
    )
    rendered = format_finding(f, json_output=False, pack_path=Path("/tmp/pack"))
    assert rendered.startswith("::error ")
    assert "manifest_not_found" in rendered


def test_format_finding_default_text_for_warning_uses_gh_actions_warning() -> None:
    from cognic_agentos.cli.validate import format_finding

    f = ValidatorFinding(
        severity="warning",
        reason="identity_oasf_capability_set_missing",
        message="optional Wave-1 field absent",
    )
    rendered = format_finding(f, json_output=False, pack_path=Path("/tmp/pack"))
    assert rendered.startswith("::warning ")


def test_format_finding_json_mode_emits_one_line_with_full_shape() -> None:
    """JSON mode outputs one JSON object per finding for CI parsers.
    The shape carries ``severity``, ``reason``, ``message``, and the
    finding's payload."""
    from cognic_agentos.cli.validate import format_finding

    f = ValidatorFinding(
        severity="refusal",
        reason="identity_agent_id_missing",
        message="agent_id is required",
        payload={"field": "identity.agent_id"},
    )
    rendered = format_finding(f, json_output=True, pack_path=Path("/tmp/pack"))
    parsed = json.loads(rendered)
    assert parsed == {
        "severity": "refusal",
        "reason": "identity_agent_id_missing",
        "message": "agent_id is required",
        "payload": {"field": "identity.agent_id"},
    }
    assert "\n" not in rendered, "JSON mode emits one line per finding"


# ---------------------------------------------------------------------------
# (c) Typer command — exit codes + stderr routing
# ---------------------------------------------------------------------------


def test_validate_command_exits_1_on_missing_manifest(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 1, f"expected 1, got {result.exit_code}; stderr={result.stderr!r}"
    assert "manifest_not_found" in result.stderr


def test_validate_command_exits_1_on_unparseable_manifest(tmp_path: Path) -> None:
    _write_manifest(tmp_path, "= = = bad toml \x00")
    runner = CliRunner()
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 1
    assert "manifest_unparseable_toml" in result.stderr


def test_validate_command_exits_0_on_pass(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)
    runner = CliRunner()
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 0, f"expected 0, got {result.exit_code}; stderr={result.stderr!r}"
    # PASS message goes to stdout (NOT stderr) so non-CI runs see it
    # cleanly without redirect tricks.
    assert "PASS" in result.stdout


def test_validate_command_exits_0_on_warning_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3 P2 #3 load-bearing: a warning-severity finding renders to
    stderr (visible diagnostic) BUT does not affect exit code. CI
    parsers see the warning; CI workflow does NOT fail."""
    from cognic_agentos.cli import validators

    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)
    monkeypatch.setattr(
        validators.identity,
        "validate",
        lambda data, pack: [
            ValidatorFinding(
                severity="warning",
                reason="identity_oasf_capability_set_missing",
                message="capability_set missing",
            )
        ],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 0
    assert "identity_oasf_capability_set_missing" in result.stderr
    # Warning still goes to stderr (CI parsers treat both refusals +
    # warnings as diagnostic).
    assert "identity_oasf_capability_set_missing" not in result.stdout


def test_validate_command_exits_1_on_mixed_warnings_and_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any refusal trumps any number of warnings — exit code is 1.
    Both kinds render to stderr in deterministic dispatch order."""
    from cognic_agentos.cli import validators

    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)
    monkeypatch.setattr(
        validators.identity,
        "validate",
        lambda data, pack: [
            ValidatorFinding(
                severity="warning",
                reason="identity_oasf_capability_set_missing",
                message="optional",
            ),
            ValidatorFinding(
                severity="refusal",
                reason="identity_agent_id_missing",
                message="required",
            ),
        ],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 1
    assert "identity_oasf_capability_set_missing" in result.stderr
    assert "identity_agent_id_missing" in result.stderr


def test_validate_command_json_mode_emits_findings_as_json_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``agentos validate --json <pack>`` emits one JSON object per
    finding to stderr — the format CI parsers parse line-by-line."""
    from cognic_agentos.cli import validators

    _write_manifest(tmp_path, _MINIMAL_VALID_MANIFEST)
    monkeypatch.setattr(
        validators.identity,
        "validate",
        lambda data, pack: [
            ValidatorFinding(
                severity="refusal",
                reason="identity_agent_id_missing",
                message="required",
                payload={"field": "identity.agent_id"},
            )
        ],
    )

    runner = CliRunner()
    result = runner.invoke(app, ["validate", "--json", str(tmp_path)])
    assert result.exit_code == 1
    # Each line of stderr that's not the PASS message is a JSON object.
    json_lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert len(json_lines) == 1
    parsed = json.loads(json_lines[0])
    assert parsed["severity"] == "refusal"
    assert parsed["reason"] == "identity_agent_id_missing"
    assert parsed["payload"] == {"field": "identity.agent_id"}


# ---------------------------------------------------------------------------
# (d) Closed-enum drift — every emitted reason appears in ValidatorReason
# ---------------------------------------------------------------------------


#: Closed-enum tuple of every reason the orchestrator itself emits
#: (i.e., reasons whose owning file in ``_VALIDATOR_REASON_OWNERSHIP``
#: is ``validate.py``). R20 P3 #1: extended from the original two
#: (manifest_not_found / manifest_unparseable_toml) to the full four
#: after R19 added the manifest-shape gate's two new emission sites.
_ORCHESTRATOR_EMITTED_REASONS: tuple[str, ...] = (
    "manifest_not_found",
    "manifest_unparseable_toml",
    "manifest_missing_pack_id",
    "manifest_missing_required_block",
)


@pytest.mark.parametrize("reason", _ORCHESTRATOR_EMITTED_REASONS)
def test_orchestrator_emitted_reason_is_in_closed_enum(reason: str) -> None:
    """Every reason the orchestrator emits MUST appear as a key in
    ``_VALIDATOR_REASON_OWNERSHIP`` (the closed-enum drift detector).
    R20 P3 #1: extended after R19 added two new emission sites
    (manifest_missing_pack_id + manifest_missing_required_block); the
    drift detector now covers every active orchestrator emission."""
    assert reason in _VALIDATOR_REASON_OWNERSHIP, (
        f"orchestrator-emitted reason {reason!r} missing from _VALIDATOR_REASON_OWNERSHIP"
    )


def test_orchestrator_emitted_reasons_are_owned_by_validate_py() -> None:
    """Every orchestrator-emitted reason has ``"validate.py"`` as its
    owning file in the ownership map. The per-concern validators own
    the rest."""
    # ``_VALIDATOR_REASON_OWNERSHIP`` is keyed by the closed-enum
    # ``ValidatorReason`` literal. The runtime check on
    # ``reason in _VALIDATOR_REASON_OWNERSHIP`` already verified the
    # string is a valid literal value — cast for mypy strict mode.
    from cognic_agentos.cli import ValidatorReason

    for reason in _ORCHESTRATOR_EMITTED_REASONS:
        typed_reason: ValidatorReason = reason  # type: ignore[assignment]
        assert _VALIDATOR_REASON_OWNERSHIP[typed_reason] == "validate.py", (
            f"orchestrator-emitted reason {reason!r} is owned by "
            f"{_VALIDATOR_REASON_OWNERSHIP[typed_reason]!r}, not validate.py"
        )
