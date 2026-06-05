"""Sprint 11.5a T10 — architectural-arrow guard: the governed memory access
path is :class:`MemoryAPI`. No OS module may RUNTIME-import
``cognic_agentos.core.memory.storage``.

Per ADR-019 §7 + the T10 contract: the memory adapter (Postgres / Redis) is
reached ONLY through :class:`MemoryAPI`, which runs every operation through the
:class:`MemoryGate` before touching the backend. A module that imports
``core.memory.storage`` at runtime could construct an adapter and call
``put`` / ``get`` / ``list_*`` directly — bypassing the gate's kill-switch,
sub-agent, consent, DLP, purpose, and cross-subject checks. This guard refuses
the source tree if any module (other than ``storage.py`` itself) performs such a
runtime import.

``TYPE_CHECKING``-guarded imports are EXEMPT: ``api.py`` imports the
``MemoryAdapter`` Protocol under ``if TYPE_CHECKING:`` purely for the injected
constructor annotation — that import never executes at runtime, so it does not
open a bypass. The collector below skips any import nested inside an
``if TYPE_CHECKING:`` block.

Composition-root exemption (Harness-Injection T6 reconciliation):
``harness/runtime.py`` is the ONE OS module allowed to runtime-import
``core.memory.storage``. It is the dependency-injection composition root — its
job is to NAME the concrete ``PostgresMemoryAdapter`` / ``RedisMemoryAdapter``
and inject them INTO ``MemoryAPI`` (which then runs every op through
``MemoryGate``). It constructs adapters; it MUST NOT call ``put`` / ``get`` /
``list_*`` on them directly. The exemption is path-pinned to that one file
(analogous to ``storage.py``'s own self-exemption), and
``test_composition_root_is_the_only_runtime_importer`` asserts no OTHER module
ever joins the allowlist.

AST-walk idiom mirrors ``tests/unit/architecture/test_no_pack_imports.py`` (the
``SRC_ROOT.rglob`` source-tree walk + ``__pycache__`` / ``cli/templates`` skips)
extended with a ``TYPE_CHECKING``-aware import collector.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "cognic_agentos"

#: The single module allowed to define / contain ``core.memory.storage`` symbols
#: — it IS that module. Compared by resolved path so a rename surfaces here.
_STORAGE_MODULE: Path = SRC_ROOT / "core" / "memory" / "storage.py"

#: The composition root — the ONE OS module allowed to RUNTIME-import
#: ``core.memory.storage``. As the dependency-injection composition root,
#: ``build_runtime`` NAMES the concrete Postgres / Redis adapters and injects
#: them into ``MemoryAPI`` (which enforces ``MemoryGate`` on every op); it MUST
#: NOT call storage operations (``put`` / ``get`` / ``list_*``) directly. The
#: exemption is path-pinned (a rename surfaces here) and its NARROWNESS is
#: enforced by ``test_composition_root_is_the_only_runtime_importer``.
_COMPOSITION_ROOT_EXEMPT: Path = SRC_ROOT / "harness" / "runtime.py"

#: Jinja2 scaffold templates carry ``{{ ... }}`` placeholders and are not valid
#: Python until rendered — same carve-out as ``test_no_pack_imports.py``.
_CLI_TEMPLATES_ROOT: Path = SRC_ROOT / "cli" / "templates"

FORBIDDEN_MODULE = "cognic_agentos.core.memory.storage"


def _iter_py_files() -> list[Path]:
    """Every ``.py`` under the OS source tree, EXCEPT ``__pycache__/``,
    ``cli/templates/`` (unrendered Jinja2), and ``storage.py`` itself."""
    return sorted(
        p
        for p in SRC_ROOT.rglob("*.py")
        if "__pycache__" not in p.parts
        and not p.is_relative_to(_CLI_TEMPLATES_ROOT)
        and p.resolve() != _STORAGE_MODULE.resolve()
        and p.resolve() != _COMPOSITION_ROOT_EXEMPT.resolve()
    )


def _is_type_checking_guard(node: ast.If) -> bool:
    """True when ``node`` is an ``if TYPE_CHECKING:`` (or
    ``if typing.TYPE_CHECKING:``) block — imports inside it never execute."""
    test = node.test
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING"
    return False


def _runtime_import_modules(path: Path) -> list[str]:
    """Every fully-qualified module path imported at RUNTIME (imports nested
    inside an ``if TYPE_CHECKING:`` block are skipped). Catches plain
    ``import X``, ``from X import Y``, and ``from X import sub`` forms; relative
    imports inside ``core/memory`` resolve to absolute so ``from .storage import``
    is caught."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    # Collect the id() of every Import / ImportFrom node that sits (at any
    # depth) inside an `if TYPE_CHECKING:` block, so they can be excluded.
    type_checking_import_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_type_checking_guard(node):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Import | ast.ImportFrom):
                    type_checking_import_ids.add(id(inner))

    modules: list[str] = []
    for node in ast.walk(tree):
        if id(node) in type_checking_import_ids:
            continue
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Resolve relative imports to absolute. Only computed when a
                # relative import is present (so the collector also works on
                # off-tree fixture files in the self-test, which use none).
                resolved = _resolve_relative(_module_path_to_package(path), node.level, node.module)
            else:
                resolved = node.module or ""
            if resolved:
                modules.append(resolved)
                modules.extend(f"{resolved}.{alias.name}" for alias in node.names)
    return modules


def _module_path_to_package(path: Path) -> str:
    """``src/cognic_agentos/core/memory/api.py`` -> ``cognic_agentos.core.memory``."""
    rel = path.resolve().relative_to(SRC_ROOT.resolve().parent)
    parts = rel.with_suffix("").parts
    return ".".join(parts[:-1])  # drop the module name, keep the package


def _resolve_relative(current_package: str, level: int, module: str | None) -> str:
    """PEP-328 relative-import resolver (mirrors the scheduler arch guard)."""
    parts = current_package.split(".")
    climb = level - 1
    base_parts = parts[: len(parts) - climb] if climb <= len(parts) else []
    base = ".".join(base_parts) if base_parts else ""
    if module:
        return f"{base}.{module}" if base else module
    return base


@pytest.mark.parametrize("path", _iter_py_files(), ids=lambda p: str(p.relative_to(SRC_ROOT)))
def test_module_does_not_runtime_import_memory_storage(path: Path) -> None:
    """Every OS module (except ``storage.py``) MUST reach the memory adapter
    only through :class:`MemoryAPI` — a runtime import of
    ``cognic_agentos.core.memory.storage`` opens a gate-bypass and is refused.
    ``TYPE_CHECKING``-guarded imports (the ``MemoryAdapter`` Protocol annotation
    in ``api.py``) are exempt."""
    offenders = [
        m
        for m in _runtime_import_modules(path)
        if m == FORBIDDEN_MODULE or m.startswith(FORBIDDEN_MODULE + ".")
    ]
    assert not offenders, (
        f"{path.relative_to(SRC_ROOT)} runtime-imports {offenders!r}. The memory "
        f"adapter is reached ONLY through MemoryAPI (which runs every op through "
        f"MemoryGate first); a runtime import of core.memory.storage bypasses the "
        f"governance gate. Move the import under `if TYPE_CHECKING:` (annotation "
        f"only) or route the access through MemoryAPI."
    )


def test_api_module_type_checking_import_is_exempt() -> None:
    """Positive control: ``api.py`` DOES import the storage Protocol, but only
    under ``TYPE_CHECKING`` — the collector must report ZERO runtime importers
    of it. Guards against the collector silently treating every import as a
    TYPE_CHECKING import (which would make the parametrized guard vacuous)."""
    api_path = SRC_ROOT / "core" / "memory" / "api.py"
    source = api_path.read_text(encoding="utf-8")
    # The raw source DOES reference the storage Protocol import (under guard).
    assert "from cognic_agentos.core.memory.storage import MemoryAdapter" in source
    # But the runtime-import collector excludes it.
    assert FORBIDDEN_MODULE not in _runtime_import_modules(api_path)


def test_collector_detects_a_runtime_import(tmp_path: Path) -> None:
    """Self-test: the runtime-import collector MUST fire on a plain runtime
    import + MUST NOT fire on the same import under ``if TYPE_CHECKING:``.
    Proves the parametrized guard is load-bearing (would fail on a real
    violation) rather than vacuously green."""
    bad = tmp_path / "bad.py"
    bad.write_text(
        "from cognic_agentos.core.memory.storage import PostgresMemoryAdapter\n",
        encoding="utf-8",
    )
    assert FORBIDDEN_MODULE in _runtime_import_modules(bad)

    guarded = tmp_path / "guarded.py"
    guarded.write_text(
        "from __future__ import annotations\n"
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from cognic_agentos.core.memory.storage import PostgresMemoryAdapter\n",
        encoding="utf-8",
    )
    assert FORBIDDEN_MODULE not in _runtime_import_modules(guarded)


def test_composition_root_is_the_only_runtime_importer() -> None:
    """The allowlist is NARROW and the exemption is LOAD-BEARING. Scanning the
    WHOLE source tree (every file the parametrized guard sees PLUS the two
    exempted ones), the ONLY module that runtime-imports ``core.memory.storage``
    is the composition root. ``storage.py`` defines the symbols (it does not
    import itself) and ``api.py``'s import is ``TYPE_CHECKING``-guarded, so
    neither appears here.

    This is the guard against the per-file exemption silently widening the
    bypass surface: a NEW offender anywhere makes the set grow and trips this
    test (the parametrized guard would also catch it — belt and suspenders), and
    if the composition root ever STOPS importing storage the set shrinks,
    flagging a now-stale exemption that should be removed."""
    importers = {
        p.resolve()
        for p in SRC_ROOT.rglob("*.py")
        if "__pycache__" not in p.parts
        and not p.is_relative_to(_CLI_TEMPLATES_ROOT)
        and any(
            m == FORBIDDEN_MODULE or m.startswith(FORBIDDEN_MODULE + ".")
            for m in _runtime_import_modules(p)
        )
    }
    assert importers == {_COMPOSITION_ROOT_EXEMPT.resolve()}, (
        f"Expected ONLY the composition root ({_COMPOSITION_ROOT_EXEMPT.name}) to "
        f"runtime-import {FORBIDDEN_MODULE}; got "
        f"{sorted(str(p.relative_to(SRC_ROOT)) for p in importers)}. A new entry is a "
        f"gate-bypass regression; a missing composition root means the exemption is stale."
    )
