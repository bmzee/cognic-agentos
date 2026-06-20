"""Sprint 10.5b T11 — architectural-arrow guard: scheduler modules MUST
NOT import ``cognic_agentos.sandbox.*``.

Per plan §1281 + the T11 round-2 P1 atomic-pair fix: sandbox is
consumed via an injected ``SandboxAdapter`` Protocol-conforming
object (atomic ``create`` + ``destroy`` pair), NOT imported. The
``SandboxAdapter`` Protocol + the ``SandboxCreateRefused`` typed
exception both live in ``core/scheduler/_seams.py`` (scheduler-
owned shapes); the AgentOS app's DI binder at startup wraps the
real ``cognic_agentos.sandbox.protocol.SandboxBackend`` into a
structurally-conforming adapter before passing it to
:meth:`SchedulerEngine.mark_running`. Upstream
``SandboxLifecycleRefused`` exceptions are translated to the
scheduler-owned ``SandboxCreateRefused`` at the same binder seam.
Scheduler stays substrate-independent — a sandbox-engine refactor
must NOT require scheduler-side code changes.

The round-1 reviewer found that the prior two-kwarg shape
(``sandbox_create_fn`` + ``sandbox_destroy_fn``) allowed production
miswiring (caller could omit destroy, leaking on storage failure);
the round-2 P1 fix replaced both with the atomic adapter Protocol
+ this AST guard still enforces the no-import-from-sandbox rule
unchanged.

This AST-walk regression mirrors the T9 ``test_architecture_no_emergency_import.py``
pattern + reuses the helpers (resolves relative imports per PEP 328,
catches all 4 import forms including from-parent-import-submodule).

A separate file (rather than extending T9's emergency-only file)
keeps each architectural-arrow guard's purpose clear in the test
output + commit-log search history.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SCHEDULER_MODULES = (
    "src/cognic_agentos/core/scheduler/__init__.py",
    "src/cognic_agentos/core/scheduler/_seams.py",
    "src/cognic_agentos/core/scheduler/_types.py",
    "src/cognic_agentos/core/scheduler/budget_resolver.py",
    "src/cognic_agentos/core/scheduler/engine.py",
    "src/cognic_agentos/core/scheduler/policy.py",
    "src/cognic_agentos/core/scheduler/queue.py",
    "src/cognic_agentos/core/scheduler/storage.py",
)

FORBIDDEN_MODULE_PREFIX = "cognic_agentos.sandbox"

SCHEDULER_PACKAGE = "cognic_agentos.core.scheduler"


def _resolve_relative_module(
    *,
    current_package: str,
    level: int,
    module: str | None,
) -> str:
    """PEP-328 relative-import resolver. Mirrors the helper in
    ``test_architecture_no_emergency_import.py``; kept inline (rather
    than imported across test files) so each guard file is self-
    contained + a future move/rename of the emergency-guard file
    cannot silently break this guard."""
    if level < 1:
        raise ValueError(f"_resolve_relative_module called with level={level} < 1")
    parts = current_package.split(".")
    climb = level - 1
    base_parts = parts[: len(parts) - climb] if climb <= len(parts) else []
    base = ".".join(base_parts) if base_parts else ""
    if module:
        return f"{base}.{module}" if base else module
    return base


def _import_strings(source: str, current_package: str) -> list[str]:
    """Extract every effective fully-qualified module path. Catches
    4 import forms (plain, from-X-import-Y, from-parent-import-
    submodule, relative). Mirrors the T9 emergency-guard helper."""
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
            for alias in node.names:
                if resolved:
                    paths.append(f"{resolved}.{alias.name}")
                else:
                    paths.append(alias.name)
    return paths


def _module_path_to_package(module_path: str) -> str:
    p = Path(module_path)
    parts = p.parts
    if parts[0] == "src":
        parts = parts[1:]
    pkg_parts = parts[:-1]
    return ".".join(pkg_parts)


@pytest.mark.parametrize("module_path", SCHEDULER_MODULES)
def test_scheduler_module_does_not_import_sandbox(module_path: str) -> None:
    """T11 substrate-independence contract — every scheduler module
    MUST be free of any ``cognic_agentos.sandbox.*`` import. The
    sandbox layer is consumed via the ``SandboxAdapter`` Protocol-
    conforming object injected into
    :meth:`SchedulerEngine.mark_running`; the atomic create+destroy
    pair + the scheduler-owned :class:`SandboxCreateRefused` typed
    exception are the bridge surfaces (both live in
    ``core/scheduler/_seams.py``)."""
    source = Path(module_path).read_text()
    current_package = _module_path_to_package(module_path)
    imports = _import_strings(source, current_package)
    for imp in imports:
        assert not imp.startswith(FORBIDDEN_MODULE_PREFIX), (
            f"{module_path}: forbidden import resolves to {imp!r}. "
            f"sandbox is consumed via injected SandboxAdapter Protocol "
            f"object (atomic create+destroy pair) + scheduler-owned "
            f"SandboxCreateRefused exception in core/scheduler/_seams.py "
            f"(plan §1281 + T11 round-2 P1 atomic-pair fix; scheduler-"
            f"as-substrate independence per "
            f"[[feedback_consumer_owned_protocol_for_unlanded_dep]])."
        )


def test_t11_architectural_arrow_module_set_is_exhaustive() -> None:
    """Drift detector — SCHEDULER_MODULES tuple must enumerate every
    .py file under src/cognic_agentos/core/scheduler/. Mirrors the
    T9 emergency-guard exhaustiveness pin."""
    scheduler_dir = Path("src/cognic_agentos/core/scheduler")
    on_disk = sorted(p for p in scheduler_dir.glob("*.py") if p.name != "__pycache__")
    listed = sorted(Path(p) for p in SCHEDULER_MODULES)
    assert on_disk == listed, (
        f"Architectural-arrow guard module list out of sync. "
        f"Listed: {listed!r}. On disk: {on_disk!r}. "
        f"Add the missing modules to SCHEDULER_MODULES."
    )
