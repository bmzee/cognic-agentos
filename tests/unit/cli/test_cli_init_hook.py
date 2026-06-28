"""Sprint-7A2 T3 — `agentos init-hook` scaffold regressions.

Mirrors the Sprint-7A T5 ``test_cli_init.py`` test pattern, narrowed to
``kind="hook"``. Hook packs ship as the 4th first-class pack kind per
Sprint-7A2 plan-of-record Doctrine Lock A; this file covers:

  - CLI wiring: ``agentos init-hook example`` exits 0.
  - Tree shape: every file in the bundled hook template lands at the
    expected path in the produced pack.
  - TOML round-trip: produced ``pyproject.toml`` + manifest parse
    cleanly via ``tomllib``.
  - Hook-specific manifest invariants: ``[hooks]`` block present with
    a ``declarations`` array; NO ``[a2a]`` block; NO ``[mcp]`` block;
    ``[identity]`` does NOT declare ``agent_card_jws_path`` (hook
    packs do not ship a JWS-signed AgentCard).
  - Hook-specific entry-point group: ``[project.entry-points."cognic.hooks"]``.
  - AUTHOR-FILL markers throughout (so ``agentos validate`` refuses
    with explicit remediation messages on the freshly-scaffolded
    pack — covered by Sprint-7A2 T6).
  - Scaffolded subclass overrides ``_invoke`` (NOT ``invoke``); the
    SDK's ``Hook.__init_subclass__`` rejects subclasses that override
    the public final method (mirrors Tool R8 P2 #1).
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app


def _scaffold_hook(pack_name: str, tmp_path: Path) -> Path:
    """Invoke the scaffold helper directly (bypassing Typer) and
    return the produced pack root."""
    from cognic_agentos.cli.init import scaffold

    return scaffold(kind="hook", pack_name=pack_name, parent_dir=tmp_path)


# ---------------------------------------------------------------------------
# (a) CLI wiring
# ---------------------------------------------------------------------------


def test_init_hook_command_exits_zero(tmp_path: Path) -> None:
    """``agentos init-hook example`` exits 0 + produces the pack
    directory in the current working directory."""
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(app, ["init-hook", "example"])
    assert result.exit_code == 0, (
        f"agentos init-hook example exited {result.exit_code}; "
        f"expected 0. stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_init_hook_help_lists_command(tmp_path: Path) -> None:
    """``agentos --help`` lists init-hook alongside the Sprint-7A trio."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    # Strip ANSI SGR escapes for terminal-width determinism (mirrors
    # the T17 R-round-1 ANSI-strip fix in test_cli_verify.py).
    import re as _re

    plain_stdout = _re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert "init-hook" in plain_stdout


# ---------------------------------------------------------------------------
# (b) Tree shape
# ---------------------------------------------------------------------------


def test_scaffold_creates_canonical_tree(tmp_path: Path) -> None:
    """The hook template tree mirrors the skill tree structurally
    (only kind-specific filenames differ: skill.py → hook.py;
    test_skill.py → test_hook.py)."""
    pack_root = _scaffold_hook("example", tmp_path)
    assert pack_root.is_dir()
    expected_files = {
        "cognic-pack-manifest.toml",
        "pyproject.toml",
        "README.md",
        "src/cognic_hook_example/__init__.py",
        "src/cognic_hook_example/hook.py",
        "tests/conftest.py",
        "tests/test_hook.py",
        ".github/workflows/sign-and-publish.yml",
        "attestations/.gitkeep",
    }
    actual_files = {str(p.relative_to(pack_root)) for p in pack_root.rglob("*") if p.is_file()}
    assert actual_files == expected_files, (
        f"unexpected files in hook scaffold: "
        f"extra={actual_files - expected_files}, "
        f"missing={expected_files - actual_files}"
    )


def test_hook_scaffold_has_no_agent_cards_dir(tmp_path: Path) -> None:
    """Hook packs do NOT ship an AgentCard JWS, so the scaffold MUST
    NOT create an ``agent_cards/`` directory (in contrast to agent
    packs which do). The Sprint-7A2 T6 validator refuses
    ``kind="hook"`` packs that declare ``agent_card_jws_path``."""
    pack_root = _scaffold_hook("example", tmp_path)
    assert not (pack_root / "agent_cards").exists()


# ---------------------------------------------------------------------------
# (c) pyproject.toml round-trip + entry-point group
# ---------------------------------------------------------------------------


def test_scaffolded_pyproject_parses_via_tomllib(tmp_path: Path) -> None:
    pack_root = _scaffold_hook("example", tmp_path)
    parsed = tomllib.loads((pack_root / "pyproject.toml").read_text())
    assert parsed["project"]["name"] == "cognic-hook-example"


def test_scaffolded_pyproject_declares_cognic_hooks_entry_point_group(
    tmp_path: Path,
) -> None:
    """The hook pack's pyproject.toml MUST register under the
    ``cognic.hooks`` entry-point group (NOT ``cognic.tools`` /
    ``.skills`` / ``.agents``)."""
    pack_root = _scaffold_hook("example", tmp_path)
    parsed = tomllib.loads((pack_root / "pyproject.toml").read_text())
    entry_points = parsed["project"]["entry-points"]
    assert "cognic.hooks" in entry_points
    assert "cognic.tools" not in entry_points
    assert "cognic.skills" not in entry_points
    assert "cognic.agents" not in entry_points
    # The single entry binds the pack_name → module:class.
    assert entry_points["cognic.hooks"] == {
        "example": "cognic_hook_example.hook:ExampleHook",
    }


# ---------------------------------------------------------------------------
# (d) Manifest round-trip + Wave-1 blocks (hook-specific)
# ---------------------------------------------------------------------------


def test_scaffolded_manifest_parses_via_tomllib(tmp_path: Path) -> None:
    pack_root = _scaffold_hook("example", tmp_path)
    manifest = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert manifest["pack"]["pack_id"] == "cognic-hook-example"
    assert manifest["pack"]["kind"] == "hook"


@pytest.mark.parametrize(
    "block",
    ["pack", "identity", "data_governance", "risk_tier", "hooks", "supply_chain"],
)
def test_scaffolded_manifest_carries_hook_wave1_blocks(block: str, tmp_path: Path) -> None:
    """Wave-1 mandatory blocks for hook packs (per Sprint-7A2 plan-of-
    record Doctrine Lock A): pack / identity / data_governance /
    risk_tier / hooks / supply_chain. Note the new ``hooks`` block
    is hook-pack-specific."""
    pack_root = _scaffold_hook("example", tmp_path)
    manifest = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert block in manifest, f"missing required block [{block}] in hook manifest"


def test_scaffolded_manifest_has_no_a2a_block(tmp_path: Path) -> None:
    """Hook packs do NOT speak A2A; the Sprint-7A2 T6 validator
    refuses ``kind="hook"`` packs that declare an ``[a2a]`` block."""
    pack_root = _scaffold_hook("example", tmp_path)
    manifest = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert "a2a" not in manifest


def test_scaffolded_manifest_has_no_mcp_block(tmp_path: Path) -> None:
    """Hook packs are not MCP-tool-shaped; the Sprint-7A2 T6
    validator refuses ``kind="hook"`` packs that declare an
    ``[mcp]`` block."""
    pack_root = _scaffold_hook("example", tmp_path)
    manifest = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert "mcp" not in manifest


def test_scaffolded_manifest_identity_omits_agent_card_jws_path(
    tmp_path: Path,
) -> None:
    """Hook packs do NOT ship an AgentCard JWS; the manifest's
    ``[identity]`` block MUST NOT declare ``agent_card_jws_path``.
    Sprint-7A2 T6 validator refuses if it's present for
    ``kind="hook"``."""
    pack_root = _scaffold_hook("example", tmp_path)
    manifest = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    assert "agent_card_jws_path" not in manifest["identity"]


def test_scaffolded_manifest_hooks_declarations_is_an_array_of_tables(
    tmp_path: Path,
) -> None:
    """The ``[hooks]`` block carries a ``declarations`` field that's
    a list of tables (TOML array-of-tables); each table declares one
    hook_id + phase + ordering_class + timeout_seconds + fail_policy.
    The scaffold ships exactly one declaration as a starter."""
    pack_root = _scaffold_hook("example", tmp_path)
    manifest = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    declarations = manifest["hooks"]["declarations"]
    assert isinstance(declarations, list)
    assert len(declarations) >= 1
    decl = declarations[0]
    # Five required fields per declaration (Doctrine Lock A).
    assert "hook_id" in decl
    assert "phase" in decl
    assert "ordering_class" in decl
    assert "timeout_seconds" in decl
    assert "fail_policy" in decl
    # fail_policy default is fail_closed per ADR-017.
    assert decl["fail_policy"] == "fail_closed"


# ---------------------------------------------------------------------------
# (e) AUTHOR-FILL markers (so validate refuses with remediation)
# ---------------------------------------------------------------------------


def test_scaffolded_pack_carries_author_fill_markers(tmp_path: Path) -> None:
    """Scaffolded pack ships with AUTHOR-FILL placeholders at every
    author-customizable site so ``agentos validate`` refuses with
    explicit per-field remediation (NOT generic 'missing field'
    panics). Pack authors replace placeholders, re-run validate,
    iterate to green."""
    pack_root = _scaffold_hook("example", tmp_path)
    manifest_text = (pack_root / "cognic-pack-manifest.toml").read_text()
    pyproject_text = (pack_root / "pyproject.toml").read_text()
    hook_source_text = (pack_root / "src" / "cognic_hook_example" / "hook.py").read_text()
    assert "AUTHOR-FILL:" in manifest_text
    assert "AUTHOR-FILL:" in pyproject_text
    assert "AUTHOR-FILL:" in hook_source_text


# ---------------------------------------------------------------------------
# (f) Scaffolded subclass — SDK contract regression
# ---------------------------------------------------------------------------


def test_scaffolded_subclass_overrides_invoke(tmp_path: Path) -> None:
    """Generated subclass overrides ``_invoke`` (NOT ``invoke``); the
    SDK's ``Hook.__init_subclass__`` rejects subclasses that override
    the public final method (mirrors Sprint-7A T2 Tool R8 P2 #1
    doctrine)."""
    pack_root = _scaffold_hook("example", tmp_path)
    source_path = pack_root / "src" / "cognic_hook_example" / "hook.py"
    tree = ast.parse(source_path.read_text())
    class_def = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ExampleHook"
    )
    method_names = {
        node.name
        for node in class_def.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    # Must override _invoke, NOT invoke.
    assert "_invoke" in method_names
    assert "invoke" not in method_names


def test_scaffolded_subclass_loads_and_init_subclass_passes(tmp_path: Path) -> None:
    """Dynamically load the generated subclass module + verify
    class-creation passes the SDK's ``Hook.__init_subclass__``
    runtime guards (no mixin-smuggled ``invoke`` override). The
    subclass's ``_invoke`` is still abstract here (raises
    NotImplementedError); we just confirm class creation works."""
    pack_root = _scaffold_hook("example", tmp_path)
    package_root = pack_root / "src" / "cognic_hook_example"
    # Import dynamically; add the package's parent to sys.path so
    # `cognic_hook_example.hook` resolves.
    package_parent = str(package_root.parent)
    sys.path.insert(0, package_parent)
    try:
        spec = importlib.util.spec_from_file_location(
            "cognic_hook_example.hook",
            package_root / "hook.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Class-creation reached this point → __init_subclass__ passed.
        assert hasattr(module, "ExampleHook")
        from cognic_agentos.sdk.hook import Hook

        assert issubclass(module.ExampleHook, Hook)
    finally:
        sys.path.remove(package_parent)
        # Don't pollute sys.modules across tests.
        sys.modules.pop("cognic_hook_example.hook", None)


# ---------------------------------------------------------------------------
# (g) Negative paths
# ---------------------------------------------------------------------------


def test_scaffold_refuses_existing_target(tmp_path: Path) -> None:
    """Re-scaffolding the same pack name without first deleting the
    target is refused with ``ScaffoldError``."""
    from cognic_agentos.cli.init import ScaffoldError

    _scaffold_hook("example", tmp_path)
    with pytest.raises(ScaffoldError, match="already exists"):
        _scaffold_hook("example", tmp_path)


@pytest.mark.parametrize(
    "bad_name",
    ["", "Has-Dash", "1starts_with_digit", "has space", "has.dot", "../traversal"],
)
def test_scaffold_rejects_invalid_pack_name(bad_name: str, tmp_path: Path) -> None:
    """The pack-name validator rejects non-snake-case + path-traversal
    + shell-metacharacter shapes."""
    from cognic_agentos.cli.init import ScaffoldError

    with pytest.raises(ScaffoldError):
        _scaffold_hook(bad_name, tmp_path)


# ---------------------------------------------------------------------------
# (h) External-pack authoring enablement — kernel dep is git-pinned, not broken
# ---------------------------------------------------------------------------
#
# PR-1: the hook scaffold (like tool/skill/agent) must emit the git-pinned
# cognic-agentos tag form so a clean external hook-pack repo can obtain the
# AgentOS authoring/governance CLI (the kernel is unpublished). Positive +
# negative, mirroring tests/unit/cli/test_cli_init.py section (i).

#: The git-pinned form the hook scaffold must emit. Bump alongside the kernel tag.
_PINNED_KERNEL_DEP = "cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2"


def test_scaffolded_pyproject_git_pins_kernel_dep(tmp_path: Path) -> None:
    """The hook scaffold's cognic-agentos dep uses the git-pinned @v0.0.2
    form (positive) and carries no bare unpinned entry (negative)."""
    pack_root = _scaffold_hook("example", tmp_path)
    deps = tomllib.loads((pack_root / "pyproject.toml").read_text())["project"]["dependencies"]
    assert _PINNED_KERNEL_DEP in deps, (
        f"hook pyproject must git-pin cognic-agentos ({_PINNED_KERNEL_DEP!r}); got {deps!r}"
    )
    assert "cognic-agentos" not in deps, (
        f"hook pyproject must NOT carry a bare unpinned `cognic-agentos` dep; got {deps!r}"
    )


def test_scaffolded_ci_installs_kernel_from_git(tmp_path: Path) -> None:
    """The hook scaffold's CI installs the AgentOS CLI from the git-pinned
    tag (positive) and not via the broken bare install (negative)."""
    pack_root = _scaffold_hook("example", tmp_path)
    ci_text = (pack_root / ".github" / "workflows" / "sign-and-publish.yml").read_text()
    assert f'pip install "{_PINNED_KERNEL_DEP}"' in ci_text, (
        f"hook CI must git-install the kernel; expected "
        f'pip install "{_PINNED_KERNEL_DEP}" in:\n{ci_text}'
    )
    assert "pip install cognic-agentos" not in ci_text, (
        f"hook CI must NOT carry the broken bare `pip install cognic-agentos`:\n{ci_text}"
    )


def test_scaffolded_pyproject_pins_requires_python(tmp_path: Path) -> None:
    """The hook scaffold's ``requires-python`` matches the kernel's actual range
    (``>=3.12,<3.13``). M3-E1 closeout finding: the kernel git-dep requires
    ``<3.13``, so a looser ``>=3.12`` would let an author on Python 3.13 fail to
    install the kernel."""
    pack_root = _scaffold_hook("example", tmp_path)
    requires_python = tomllib.loads((pack_root / "pyproject.toml").read_text())["project"][
        "requires-python"
    ]
    assert requires_python == ">=3.12,<3.13", (
        f'hook pyproject requires-python must match the kernel range ">=3.12,<3.13"; '
        f"got {requires_python!r}"
    )
