"""Sprint-7A T5 — scaffold-command regressions.

Each ``agentos init-{tool,skill,agent}`` invocation produces a working
pack repo via the bundled Jinja2 templates. The tests cover:

  - CLI wiring: the T4 fail-loud stubs are replaced + ``init-<kind> name``
    exits 0.
  - Tree shape: every file the plan-of-record documents lands at the
    expected path.
  - TOML round-trip: the produced ``pyproject.toml`` + manifest parse
    cleanly via ``tomllib`` (no syntax errors masquerading as
    "scaffolded successfully").
  - Wave-1 manifest blocks: the manifest carries every Wave-1 mandatory
    block per the closed-enum ``ValidatorReason`` literal.
  - AUTHOR-FILL markers: the produced pack ships placeholders that
    ``agentos validate`` (T6) will refuse on explicit remediation —
    NOT generic panics.
  - Scaffold-SDK-contract regression (R5 P2 #2): the generated
    subclass file overrides the right abstract method (Tool's
    ``_invoke`` / Skill's ``execute`` / Agent's ``handle``) and does
    NOT touch the SDK's pinned-final / construction-rejected names
    (``Tool.invoke`` / ``Skill.__init__``). AST shape pin + dynamic
    load + instantiate confirms the SDK base classes accept the
    generated subclass without tripping the runtime override-rejection
    in ``Tool.__init_subclass__`` / ``Skill.__init_subclass__``.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app

if TYPE_CHECKING:
    pass


_KINDS: tuple[str, ...] = ("tool", "skill", "agent")

#: Per-kind expected method override on the generated subclass —
#: pins R5 P2 #2 + Sprint-6 dispatch shape. Tool subclasses override
#: ``_invoke`` (NOT ``invoke``); Skill subclasses override ``execute``;
#: Agent subclasses override ``handle``.
_EXPECTED_METHOD_BY_KIND: dict[str, str] = {
    "tool": "_invoke",
    "skill": "execute",
    "agent": "handle",
}

#: Per-kind names that the generated subclass MUST NOT define directly
#: (they would trip the SDK's ``__init_subclass__`` runtime guards).
_FORBIDDEN_METHODS_BY_KIND: dict[str, tuple[str, ...]] = {
    "tool": ("invoke",),
    "skill": ("__init__",),
    "agent": (),
}


def _scaffold(kind: str, pack_name: str, tmp_path: Path) -> Path:
    """Invoke the scaffold helper directly (bypassing Typer) and
    return the produced pack root. Avoids the CLI wrapper for unit
    tests that don't need to exercise the Typer parsing layer."""
    from cognic_agentos.cli.init import scaffold

    return scaffold(kind=kind, pack_name=pack_name, parent_dir=tmp_path)


# ---------------------------------------------------------------------------
# (a) CLI wiring — fail-loud stubs replaced by working scaffold
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS)
def test_init_command_replaces_stub(kind: str, tmp_path: Path) -> None:
    """Each ``agentos init-<kind> example`` exits 0 (the T4 fail-loud
    stub returned exit 2 with the T5 pointer)."""
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(app, [f"init-{kind}", "example"])
    assert result.exit_code == 0, (
        f"agentos init-{kind} example exited {result.exit_code}; "
        f"expected 0. stdout={result.stdout!r} stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# (b) Tree shape per kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffold_creates_canonical_tree(kind: str, tmp_path: Path) -> None:
    """Every file the plan-of-record documents lands at its expected
    path. Drift between plan + scaffold trips here before pack
    authors hit it."""
    pack_root = _scaffold(kind, "example", tmp_path)
    module_dir = pack_root / "src" / f"cognic_{kind}_example"
    expected_files: list[Path] = [
        pack_root / "pyproject.toml",
        pack_root / "cognic-pack-manifest.toml",
        pack_root / "README.md",
        module_dir / "__init__.py",
        module_dir / f"{kind}.py",
        pack_root / "tests" / f"test_{kind}.py",
        pack_root / "tests" / "conftest.py",
        pack_root / "attestations" / ".gitkeep",
        pack_root / ".github" / "workflows" / "sign-and-publish.yml",
    ]
    if kind == "agent":
        expected_files.append(module_dir / "agent_cards" / ".gitkeep")

    missing = [p for p in expected_files if not p.exists()]
    assert not missing, f"missing scaffold files: {missing}"


def test_tool_scaffold_has_no_agent_cards_dir(tmp_path: Path) -> None:
    """``agent_cards/`` is agent-only; the tool scaffold MUST NOT
    ship it."""
    pack_root = _scaffold("tool", "example", tmp_path)
    assert not (pack_root / "src" / "cognic_tool_example" / "agent_cards").exists()


def test_skill_scaffold_has_no_agent_cards_dir(tmp_path: Path) -> None:
    pack_root = _scaffold("skill", "example", tmp_path)
    assert not (pack_root / "src" / "cognic_skill_example" / "agent_cards").exists()


# ---------------------------------------------------------------------------
# (c) TOML round-trip — pyproject + manifest parse cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffolded_pyproject_parses_via_tomllib(kind: str, tmp_path: Path) -> None:
    pack_root = _scaffold(kind, "example", tmp_path)
    pyproject_text = (pack_root / "pyproject.toml").read_bytes()
    parsed = tomllib.loads(pyproject_text.decode())
    # Must declare the project + the right entry-point group.
    assert parsed["project"]["name"] == f"cognic-{kind}-example"


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffolded_pyproject_declares_entry_point(kind: str, tmp_path: Path) -> None:
    """The produced pack registers under the matching
    ``cognic.{tools,skills,agents}`` entry-point group."""
    pack_root = _scaffold(kind, "example", tmp_path)
    parsed = tomllib.loads((pack_root / "pyproject.toml").read_text())
    group_name = {"tool": "cognic.tools", "skill": "cognic.skills", "agent": "cognic.agents"}[kind]
    entry_points = parsed["project"]["entry-points"][group_name]
    assert "example" in entry_points


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffolded_manifest_parses_via_tomllib(kind: str, tmp_path: Path) -> None:
    pack_root = _scaffold(kind, "example", tmp_path)
    manifest_text = (pack_root / "cognic-pack-manifest.toml").read_bytes()
    parsed = tomllib.loads(manifest_text.decode())
    assert parsed["pack"]["pack_id"] == f"cognic-{kind}-example"


# ---------------------------------------------------------------------------
# (d) Wave-1 mandatory manifest blocks
# ---------------------------------------------------------------------------

#: Closed list of Wave-1 manifest blocks every produced pack ships.
#: Sourced from the closed-enum ``ValidatorReason`` literal in
#: ``cognic_agentos.cli`` — every block name appears as the prefix of
#: at least one validator reason. Pack-author docs reference this set.
_WAVE1_BLOCKS: tuple[str, ...] = (
    "identity",
    "data_governance",
    "risk_tier",
    "supply_chain",
)


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("block", _WAVE1_BLOCKS)
def test_scaffolded_manifest_carries_wave1_block(kind: str, block: str, tmp_path: Path) -> None:
    pack_root = _scaffold(kind, "example", tmp_path)
    parsed = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert block in parsed, f"{kind} manifest missing Wave-1 block {block!r}"


def test_tool_scaffolded_manifest_carries_mcp_block(tmp_path: Path) -> None:
    """Tool packs additionally declare an ``mcp`` block (capabilities
    + caching + elicitation flags)."""
    pack_root = _scaffold("tool", "example", tmp_path)
    parsed = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert "mcp" in parsed


def test_agent_scaffolded_manifest_carries_a2a_block(tmp_path: Path) -> None:
    """Agent packs additionally declare an ``a2a`` block (Wave-1
    capabilities + streaming/push flags)."""
    pack_root = _scaffold("agent", "example", tmp_path)
    parsed = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert "a2a" in parsed


# ---------------------------------------------------------------------------
# (e) AUTHOR-FILL placeholders — T6 has something to refuse on
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffolded_pack_carries_author_fill_markers(kind: str, tmp_path: Path) -> None:
    """The produced manifest ships ``AUTHOR-FILL`` placeholders at every
    author-customizable site so ``agentos validate`` (T6) refuses with
    explicit remediation rather than generic ``missing field`` panics."""
    pack_root = _scaffold(kind, "example", tmp_path)
    manifest_text = (pack_root / "cognic-pack-manifest.toml").read_text()
    # At minimum, identity block has multiple AUTHOR-FILL spots
    # (display_name, provider_organization, provider_url, agent_card_url).
    assert manifest_text.count("AUTHOR-FILL") >= 4, (
        f"manifest carries fewer than 4 AUTHOR-FILL markers: {manifest_text.count('AUTHOR-FILL')}"
    )


# ---------------------------------------------------------------------------
# (f) SDK contract regression — generated subclass shape (R5 P2 #2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffolded_subclass_overrides_correct_abstract_method(kind: str, tmp_path: Path) -> None:
    """AST shape pin: the generated subclass file defines the
    expected abstract-method override + does NOT define any
    SDK-pinned-final / construction-rejected names per kind.
    R5 P2 #2 / R3 P2 #1 / R6 P2 #1 doctrine."""
    pack_root = _scaffold(kind, "example", tmp_path)
    subclass_path = pack_root / "src" / f"cognic_{kind}_example" / f"{kind}.py"
    tree = ast.parse(subclass_path.read_text())

    class_def = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)),
        None,
    )
    assert class_def is not None, f"{kind} scaffold has no class definition"

    method_names = {
        n.name for n in class_def.body if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef)
    }
    expected = _EXPECTED_METHOD_BY_KIND[kind]
    assert expected in method_names, (
        f"{kind} subclass missing expected override {expected!r}; "
        f"defined methods: {sorted(method_names)}"
    )
    for forbidden in _FORBIDDEN_METHODS_BY_KIND[kind]:
        assert forbidden not in method_names, (
            f"{kind} subclass defines forbidden method {forbidden!r} — "
            f"the SDK's __init_subclass__ would refuse this at class-creation time"
        )


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffolded_subclass_imports_and_subclass_check_passes(kind: str, tmp_path: Path) -> None:
    """Dynamic load + class-creation gate. If the generated subclass
    tripped the SDK's ``__init_subclass__`` (e.g., a stale template
    that defined ``invoke`` directly), the import would raise
    ``TypeError`` and pack authors would get a confusing error on
    first ``import``."""
    pack_root = _scaffold(kind, "example", tmp_path)
    subclass_path = pack_root / "src" / f"cognic_{kind}_example" / f"{kind}.py"

    spec = importlib.util.spec_from_file_location(
        f"cognic_{kind}_example_scaffold_{kind}", subclass_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)

    # Module loaded without the SDK rejecting the class shape.


# ---------------------------------------------------------------------------
# (g) Existing-directory refusal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS)
def test_scaffold_refuses_existing_target(kind: str, tmp_path: Path) -> None:
    """Re-invoking ``agentos init-<kind> example`` against an
    already-scaffolded directory refuses (does NOT silently
    overwrite)."""
    from cognic_agentos.cli.init import ScaffoldError

    _scaffold(kind, "example", tmp_path)
    with pytest.raises(ScaffoldError, match="exists"):
        _scaffold(kind, "example", tmp_path)


# ---------------------------------------------------------------------------
# (h) pack_name validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_name",
    ["", "Foo Bar", "../etc", "with.dot", "UPPER", "123start"],
)
def test_scaffold_rejects_invalid_pack_name(bad_name: str, tmp_path: Path) -> None:
    """Pack names MUST be valid lowercase Python identifier fragments
    (letters / digits / underscores; cannot start with digit). Bad
    names raise ``ScaffoldError`` BEFORE any filesystem write."""
    from cognic_agentos.cli.init import ScaffoldError

    with pytest.raises(ScaffoldError):
        _scaffold("tool", bad_name, tmp_path)
    # No partial scaffold left behind on rejection.
    assert list(tmp_path.iterdir()) == []
