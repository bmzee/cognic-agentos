"""Sprint-7A T14 architecture test — banning ``dev_mode_skip_cosign=True``
literal overrides from production code paths.

Per Doctrine Decision F, ``--dev-mode-skip-cosign`` is gated behind a
flag that prints a security warning + the prod settings profile
rejects the flag at startup (``core/config.py:1035`` —
``_validate_dev_mode_skip_cosign_prod_profile_guard``). The runtime
check fires when ``Settings(...)`` is constructed with
``runtime_profile == "prod"`` AND ``dev_mode_skip_cosign == True``.

The runtime guard is necessary but not sufficient: a future commit
could add a literal ``dev_mode_skip_cosign = True`` assignment inside
production code (``cli/sign.py`` / ``cli/verify.py`` /
``cli/__init__.py``) that mutates the field AFTER Settings has
validated, bypassing the guard. This architecture test is the
mechanical static guardrail for that doctrine: walk the AST of every
production module on the sign + verify path and assert that NONE of
them assign ``True`` to a ``dev_mode_skip_cosign`` attribute or
variable.

The CLI Typer wrappers DO accept ``dev_mode_skip_cosign`` as an
explicit parameter / option — that's the legitimate path the user
opts into. What's banned is hardcoded ``= True`` overrides; those
would silently re-enable the dev-skip path even after the prod-
profile guard had fired.

Scope:
  - ``src/cognic_agentos/cli/sign.py`` (T14.A landed; T14.B widens)
  - ``src/cognic_agentos/cli/__init__.py`` (Typer wrapper site)
  - ``src/cognic_agentos/cli/verify.py`` (T14.C lands later)

When T14.B / T14.C add their respective sign-bundle / verify
implementations, this test's module list grows automatically (the
glob pattern ``cli/(sign|verify|__init__).py`` covers the load-bearing
sites). New CLI verbs that don't touch dev_mode_skip_cosign are out
of scope for this scan.

If a future commit trips this test, that commit is adding a hardcoded
dev-mode-skip override to production code — which has no doctrinal
justification. Revert.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_CLI_DIR: Path = _REPO_ROOT / "src" / "cognic_agentos" / "cli"


def _scan_targets() -> list[Path]:
    """Return the production CLI modules in scope for the dev-skip
    static ban. Files that don't exist yet (``verify.py`` lands in
    T14.C) are silently skipped — the test grows naturally as the
    CLI surface ships."""
    candidates = [
        _CLI_DIR / "sign.py",
        _CLI_DIR / "__init__.py",
        _CLI_DIR / "verify.py",
    ]
    return [p for p in candidates if p.is_file()]


def _has_dev_skip_true_literal(tree: ast.AST) -> list[tuple[int, str]]:
    """Walk ``tree`` for any node that assigns ``True`` to a target
    named ``dev_mode_skip_cosign`` (whether on an attribute access
    like ``x.dev_mode_skip_cosign = True`` or a bare name
    ``dev_mode_skip_cosign = True``). Returns a list of
    ``(lineno, source-snippet)`` for every offending node."""
    offenders: list[tuple[int, str]] = []

    def _target_is_dev_skip(target: ast.expr) -> bool:
        if isinstance(target, ast.Attribute) and target.attr == "dev_mode_skip_cosign":
            return True
        return bool(isinstance(target, ast.Name) and target.id == "dev_mode_skip_cosign")

    def _value_is_true_literal(value: ast.expr) -> bool:
        # Python 3.8+ uses ast.Constant for True / False / None.
        return bool(isinstance(value, ast.Constant) and value.value is True)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if _value_is_true_literal(node.value):
                for target in node.targets:
                    if _target_is_dev_skip(target):
                        offenders.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.AnnAssign):
            if (
                node.value is not None
                and _value_is_true_literal(node.value)
                and _target_is_dev_skip(node.target)
            ):
                offenders.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.Call):
            # Catch the kwarg form ``model_copy(update={"dev_mode_skip_cosign": True})``
            # as well — even though that flows through Settings, the
            # guard fires there too. The detection is conservative; if
            # a legitimate use of the kwarg form appears, the test
            # documents the doctrine and the maintainer chooses
            # whether to allow-list or refactor.
            for kw in node.keywords:
                if kw.arg == "dev_mode_skip_cosign" and _value_is_true_literal(kw.value):
                    offenders.append((node.lineno, f"kwarg: {ast.unparse(node)}"))

    return offenders


@pytest.mark.parametrize(
    "target_path",
    _scan_targets(),
    ids=lambda p: p.relative_to(_REPO_ROOT).as_posix(),
)
def test_no_dev_mode_skip_cosign_true_literal_in_production(target_path: Path) -> None:
    """Production CLI module MUST NOT contain a literal
    ``dev_mode_skip_cosign = True`` assignment (whether on an
    attribute access, a bare name, or as a kwarg with constant True).
    The dev-skip flag flows through the user-supplied Typer option
    (``--dev-mode-skip-cosign``) → Settings field → prod-profile
    guard. Any hardcoded ``= True`` site bypasses the guard.

    Doctrine Decision F + AGENTS.md production-grade rule.
    """
    source = target_path.read_text()
    tree = ast.parse(source, filename=str(target_path))
    offenders = _has_dev_skip_true_literal(tree)
    assert offenders == [], (
        f"{target_path.relative_to(_REPO_ROOT)} contains "
        f"{len(offenders)} hardcoded dev_mode_skip_cosign=True site(s) "
        "in production code, bypassing the prod-profile Settings guard "
        "at core/config.py:1035 (_validate_dev_mode_skip_cosign_prod_profile_guard). "
        "Per Doctrine Decision F + AGENTS.md production-grade rule, the "
        "dev-skip flag MUST flow through the user-supplied "
        "--dev-mode-skip-cosign Typer option + Settings validation. "
        f"Offenders:\n" + "\n".join(f"  line {ln}: {src}" for ln, src in offenders)
    )


def test_scan_targets_covers_at_least_one_module() -> None:
    """The scan target list MUST include at least ``cli/sign.py`` +
    ``cli/__init__.py`` once T14.A has landed. Empty target list
    would mean the test is doing no work; pin the floor here."""
    targets = _scan_targets()
    target_names = {p.name for p in targets}
    assert "sign.py" in target_names, (
        "test_cli_sign_no_dev_skip_in_prod expected cli/sign.py to be "
        "in scope after T14.A lands; module not found at "
        f"{_CLI_DIR / 'sign.py'}"
    )
    assert "__init__.py" in target_names, (
        "test_cli_sign_no_dev_skip_in_prod expected cli/__init__.py "
        "to be in scope (Typer wrapper site) after T14.A lands"
    )
