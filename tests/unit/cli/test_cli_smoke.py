"""Sprint-7A T4 — `agentos` CLI smoke regressions.

Pins the public command surface that pack-author docs reference:
``agentos --help`` plus every command's own ``--help``. Without these
arms a future Typer reorganisation could drop a command from the
help text (or break a per-command argument declaration) without any
existing test catching it.

The mandatory-console-script regression here ALSO pins the base-deps
choice: if a future maintainer accidentally moves Typer to
``[project.optional-dependencies]``, ``pip install -e .`` of just
the kernel + this test would trip a ``ModuleNotFoundError`` on the
``import typer`` inside ``cli/__init__.py`` and these tests would
all fail collection (the load-bearing R5 P3 #5 invariant).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app

#: Closed-enum list of every public command on the root ``agentos``
#: app. T4 seeds the full surface as fail-loud stubs; T5-T14 each
#: replace a stub body with the real implementation. Adding or
#: removing a command MUST also update this list (drift detector
#: pins this — every name in the list MUST appear in
#: ``agentos --help``).
#:
#: R17 P2 #1: the three scaffold commands ship as top-level
#: hyphenated commands (matching T5's documented ``agentos init-tool
#: example`` surface), NOT as sub-commands of an ``init`` sub-app.
_PUBLIC_COMMAND_NAMES: tuple[str, ...] = (
    "init-tool",
    "init-skill",
    "init-agent",
    "validate",
    "test-harness",
    "sign-blob",
    "sign",
    "verify",
)


def test_root_help_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, (
        f"agentos --help exited {result.exit_code} (stdout: {result.stdout!r})"
    )


def test_root_help_contains_pack_author_title() -> None:
    """The generic title token confirms the help was rendered through
    the AgentOS Typer app, not some other CLI's help."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert "AgentOS pack-author CLI" in result.stdout


@pytest.mark.parametrize(
    "verb",
    ["scaffold", "validate", "test", "sign", "verify"],
)
def test_root_help_lists_five_verb_surface(verb: str) -> None:
    """The five verbs (scaffold / validate / test / sign / verify)
    document the pack-author workflow shape; pinning them here
    catches a future refactor that drops a verb from the help
    description without removing the implementation. R7 P3 #3."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert verb in result.stdout, f"verb {verb!r} missing from agentos --help"


@pytest.mark.parametrize("command_name", _PUBLIC_COMMAND_NAMES)
def test_root_help_lists_every_public_command(command_name: str) -> None:
    """Every public command MUST be listed in the root help. Adding
    a new command without updating ``_PUBLIC_COMMAND_NAMES`` AND
    registering it on the app trips this individually so a future
    Typer reorganisation that hides one command from the help
    surface fails loudly with the offending command's name."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert command_name in result.stdout, f"command {command_name!r} missing from agentos --help"


@pytest.mark.parametrize("command_name", _PUBLIC_COMMAND_NAMES)
def test_command_help_exits_zero(command_name: str) -> None:
    """Every command has a working ``--help``. A missing or malformed
    ``typer.Argument`` / ``typer.Option`` declaration on any command
    would raise on this per-command --help invocation. Pack authors
    who can't read the help text can't use the CLI."""
    runner = CliRunner()
    result = runner.invoke(app, [command_name, "--help"])
    assert result.exit_code == 0, (
        f"agentos {command_name} --help exited {result.exit_code} (stdout: {result.stdout!r})"
    )


# ---------------------------------------------------------------------------
# R16 P2 #1 — natural pack-author invocations parse + reach the stubs
# ---------------------------------------------------------------------------
#
# Without placeholder arguments matching the canonical T6 / T13 / T14
# shapes, the natural Sprint-7A invocations fail in Typer with
# ``Got unexpected extra argument`` or ``No such option`` BEFORE the
# fail-loud stub body runs. These regressions pin that natural pack-
# author commands parse cleanly + reach ``_stub_exit``, which writes
# the Sprint-7A T<N> pointer to stderr and exits 2. When T6 / T13 /
# T14 land + replace the stub bodies, these regressions are replaced
# by real-implementation arms.


# R17 P2 #1 init-{tool,skill,agent} arms originally pinned the
# fail-loud stub behavior (exit 2 + "Sprint-7A T5" pointer). T5
# replaced those stubs with real Jinja2-driven scaffolds, so the
# corresponding working-behavior regressions live in
# ``test_cli_init.py::test_init_command_replaces_stub`` (uses
# ``runner.isolated_filesystem`` to keep scaffold output out of the
# repo root). The init-* arms here would have hit "directory exists"
# refusals as soon as the tests started writing real packs into
# whatever CWD pytest was launched from — better to leave the
# scaffold-behavior coverage exclusively in test_cli_init.py.


# The original R16 P2 #1 ``validate`` arm pinned the T4 fail-loud
# stub (exit 2 + "Sprint-7A T6" pointer). T6 replaced that stub with
# the real orchestrator, so the working-behavior regressions live in
# ``test_cli_validate.py`` (which writes synthesized manifests into
# tmp_path + asserts orchestrator exit codes + stderr shape directly).


def test_test_harness_with_pack_path_reaches_stub_exit_pointer() -> None:
    """``agentos test-harness .`` parses cleanly + exits 2 with the
    T13 pointer in stderr."""
    runner = CliRunner()
    result = runner.invoke(app, ["test-harness", "."])
    assert result.exit_code == 2
    assert "Sprint-7A T13" in result.stderr


def test_sign_blob_with_wheel_path_reaches_stub_exit_pointer() -> None:
    """``agentos sign-blob ./dist/example-0.1.0-py3-none-any.whl``
    parses cleanly + exits 2 with the T14 pointer in stderr."""
    runner = CliRunner()
    result = runner.invoke(app, ["sign-blob", "./dist/example-0.1.0-py3-none-any.whl"])
    assert result.exit_code == 2
    assert "Sprint-7A T14" in result.stderr


def test_sign_with_bundle_flag_and_pack_path_reaches_stub_exit_pointer() -> None:
    """``agentos sign --bundle .`` parses cleanly (the ``--bundle``
    flag is recognized) + exits 2 with the T14 pointer in stderr."""
    runner = CliRunner()
    result = runner.invoke(app, ["sign", "--bundle", "."])
    assert result.exit_code == 2, (
        f"agentos sign --bundle . exited {result.exit_code}; expected 2. stderr: {result.stderr!r}"
    )
    assert "Sprint-7A T14" in result.stderr


def test_verify_with_pack_path_reaches_stub_exit_pointer() -> None:
    """``agentos verify .`` parses cleanly + exits 2 with the T14
    pointer in stderr."""
    runner = CliRunner()
    result = runner.invoke(app, ["verify", "."])
    assert result.exit_code == 2
    assert "Sprint-7A T14" in result.stderr


def test_verify_with_trust_root_option_reaches_stub_exit_pointer() -> None:
    """``agentos verify . --trust-root /tmp/keys``: the ``--trust-root``
    option is recognized + the stub fires."""
    runner = CliRunner()
    result = runner.invoke(app, ["verify", ".", "--trust-root", "/tmp/keys"])
    assert result.exit_code == 2
    assert "Sprint-7A T14" in result.stderr
