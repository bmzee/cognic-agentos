"""Sprint 10.5b T9 — architectural-arrow guard: scheduler modules MUST
NOT import ``cognic_agentos.core.emergency.*``.

Per plan §1193 + ADR-018: ``core/emergency/quotas.py`` and
``core/emergency/kill_switches.py`` do NOT exist in this workspace
(Sprint 13.5 territory). Sprint 10.5 MUST NOT create them — that's
scope creep into Sprint 13.5. T5 declared the ``QuotaInterrogator``
+ ``KillSwitchInterrogator`` Protocols + fail-loud sentinels in
``core/scheduler/_seams.py`` per
[[feedback_consumer_owned_protocol_for_unlanded_dep]]; Sprint 13.5
will eventually ship the real conformers in ``core/emergency/*`` and
they will be wired by the AgentOS app's DI setup — but the scheduler
modules themselves must NEVER directly import from that namespace.

This AST-walk regression is **wire-protocol-public for the consumer-
owned-Protocol architecture** — drift here would create a hard
dependency cycle the moment ``core/emergency/`` lands (scheduler
imports emergency; emergency might import scheduler types; loop).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SCHEDULER_MODULES = (
    "src/cognic_agentos/core/scheduler/__init__.py",
    "src/cognic_agentos/core/scheduler/_seams.py",
    "src/cognic_agentos/core/scheduler/_types.py",
    "src/cognic_agentos/core/scheduler/engine.py",
    "src/cognic_agentos/core/scheduler/policy.py",
    "src/cognic_agentos/core/scheduler/queue.py",
    "src/cognic_agentos/core/scheduler/storage.py",
)

FORBIDDEN_MODULE_PREFIX = "cognic_agentos.core.emergency"

#: Package path for the scheduler — used to resolve relative imports.
#: Every entry in :data:`SCHEDULER_MODULES` lives under this package.
SCHEDULER_PACKAGE = "cognic_agentos.core.scheduler"


def _resolve_relative_module(
    *,
    current_package: str,
    level: int,
    module: str | None,
) -> str:
    """Resolve a relative ``from X import Y`` into its fully-
    qualified absolute module path.

    Per PEP 328: ``level`` is the number of dots in the relative
    import (1 = ``from .X``; 2 = ``from ..X``; 3 = ``from ...X``).
    ``current_package`` is the importing module's ``__package__``.
    Level=1 means "same package as current_package"; level=2 means
    "parent of current_package"; level=N means climb (N-1) parents.

    So the climb count is ``level - 1``, NOT ``level``. The pre-
    round-1-P2 fix had this off by one and silently mis-resolved
    every relative import.
    """
    if level < 1:
        # Caller should have routed absolute imports (level=0) to
        # node.module directly; raise to surface a logic bug.
        raise ValueError(f"_resolve_relative_module called with level={level} < 1")
    parts = current_package.split(".")
    climb = level - 1
    if climb > len(parts):
        # Invalid relative import (would fail at import time); treat
        # as the highest level we can reach so it still triggers the
        # forbidden-prefix check if intended for /emergency.
        base_parts: list[str] = []
    else:
        base_parts = parts[: len(parts) - climb] if climb > 0 else parts
    base = ".".join(base_parts)
    if module:
        return f"{base}.{module}" if base else module
    return base


def _import_strings(source: str, current_package: str) -> list[str]:
    """Extract every effective fully-qualified module path referenced
    by import statements in ``source``.

    Round-1 P2 reviewer fix — catches 4 forms:
      * Plain ``import cognic_agentos.core.emergency`` (alias.name)
      * ``from cognic_agentos.core.emergency import X`` (node.module)
      * ``from cognic_agentos.core import emergency``
        (node.module + each name appended as ``module.name``;
        treats names as POTENTIAL submodules per a conservative
        false-positive policy — an actual non-submodule name in the
        parent package is fine because no scheduler module currently
        imports anything named ``emergency`` from any parent path)
      * Relative imports like ``from ..emergency import quotas`` or
        ``from .. import emergency`` (resolved to absolute via the
        helper above)
    """
    tree = ast.parse(source)
    paths: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                paths.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                resolved = _resolve_relative_module(
                    current_package=current_package,
                    level=node.level,
                    module=node.module,
                )
            else:
                resolved = node.module or ""
            if resolved:
                paths.append(resolved)
            # Also append "<resolved>.<alias>" for every imported name
            # so the `from parent import submodule` form is caught.
            for alias in node.names:
                if resolved:
                    paths.append(f"{resolved}.{alias.name}")
                else:
                    paths.append(alias.name)
    return paths


def _module_path_to_package(module_path: str) -> str:
    """Convert ``src/cognic_agentos/core/scheduler/X.py`` → the
    importing-package path for resolving relatives. For ``__init__.py``
    the package IS the directory; for other files the package is the
    file's containing directory."""
    p = Path(module_path)
    # Strip ``src/`` prefix
    parts = p.parts
    if parts[0] == "src":
        parts = parts[1:]
    # Drop the file name — for both __init__.py and non-init modules
    # the importing package is the containing directory.
    pkg_parts = parts[:-1]
    return ".".join(pkg_parts)


@pytest.mark.parametrize("module_path", SCHEDULER_MODULES)
def test_scheduler_module_does_not_import_core_emergency(module_path: str) -> None:
    """Every scheduler module MUST be free of any
    ``cognic_agentos.core.emergency.*`` import. The seam Protocols
    in ``core/scheduler/_seams.py`` are the architectural-arrow
    boundary; the real conformers will live in ``core/emergency/``
    at Sprint 13.5 and will be wired through DI, NOT through direct
    imports from scheduler code.

    Round-1 P2 reviewer fix: catches all 4 import forms (plain,
    from-X-import-Y, from-parent-import-submodule, relative)."""
    source = Path(module_path).read_text()
    current_package = _module_path_to_package(module_path)
    imports = _import_strings(source, current_package)
    for imp in imports:
        assert not imp.startswith(FORBIDDEN_MODULE_PREFIX), (
            f"{module_path}: forbidden import resolves to {imp!r}. "
            f"core/emergency/* lives at Sprint 13.5 and must be "
            f"consumed via the QuotaInterrogator + KillSwitchInterrogator "
            f"Protocols declared in core/scheduler/_seams.py (consumer-"
            f"owned-Protocol architecture per "
            f"[[feedback_consumer_owned_protocol_for_unlanded_dep]])."
        )


# --- Self-tests for the AST helper (proves the round-1 P2 fix works) -----


def test_helper_catches_plain_import_form() -> None:
    """``import cognic_agentos.core.emergency``"""
    src = "import cognic_agentos.core.emergency"
    imports = _import_strings(src, SCHEDULER_PACKAGE)
    assert any(i.startswith(FORBIDDEN_MODULE_PREFIX) for i in imports)


def test_helper_catches_from_emergency_import_x_form() -> None:
    """``from cognic_agentos.core.emergency import quotas``"""
    src = "from cognic_agentos.core.emergency import quotas"
    imports = _import_strings(src, SCHEDULER_PACKAGE)
    assert any(i.startswith(FORBIDDEN_MODULE_PREFIX) for i in imports)


def test_helper_catches_from_parent_import_emergency_form() -> None:
    """``from cognic_agentos.core import emergency`` — the parent-
    import-submodule form the pre-round-1-P2 detector missed."""
    src = "from cognic_agentos.core import emergency"
    imports = _import_strings(src, SCHEDULER_PACKAGE)
    assert any(i.startswith(FORBIDDEN_MODULE_PREFIX) for i in imports), (
        f"detector missed the from-parent-import-submodule form. resolved: {imports!r}"
    )


def test_helper_catches_relative_dotdot_emergency_form() -> None:
    """``from ..emergency import quotas`` from a scheduler module
    (level=2 → climbs to cognic_agentos.core → resolves to
    cognic_agentos.core.emergency)."""
    src = "from ..emergency import quotas"
    imports = _import_strings(src, SCHEDULER_PACKAGE)
    assert any(i.startswith(FORBIDDEN_MODULE_PREFIX) for i in imports), (
        f"detector missed the relative ..emergency form. resolved: {imports!r}"
    )


def test_helper_catches_relative_dotdot_import_emergency_form() -> None:
    """``from .. import emergency`` from a scheduler module
    (level=2, module=None → climbs to cognic_agentos.core; each
    alias.name appended as ``cognic_agentos.core.emergency``)."""
    src = "from .. import emergency"
    imports = _import_strings(src, SCHEDULER_PACKAGE)
    assert any(i.startswith(FORBIDDEN_MODULE_PREFIX) for i in imports), (
        f"detector missed the relative `from .. import emergency` form. resolved: {imports!r}"
    )


def test_t9_architectural_arrow_module_set_is_exhaustive() -> None:
    """Drift detector — SCHEDULER_MODULES tuple must enumerate every
    .py file under src/cognic_agentos/core/scheduler/. Adding a new
    scheduler module without adding it to this tuple would silently
    bypass the architectural-arrow guard."""
    scheduler_dir = Path("src/cognic_agentos/core/scheduler")
    on_disk = sorted(p for p in scheduler_dir.glob("*.py") if p.name != "__pycache__")
    listed = sorted(Path(p) for p in SCHEDULER_MODULES)
    assert on_disk == listed, (
        f"Architectural-arrow guard module list out of sync with "
        f"on-disk scheduler modules. Listed: {listed!r}. On disk: {on_disk!r}. "
        f"Add the missing modules to SCHEDULER_MODULES so the no-emergency-"
        f"import regression covers them."
    )
