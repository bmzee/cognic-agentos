"""Sprint 6 architecture test — A2A module subprocess/exec import ban.

Per ADR-003 + the Sprint-6 plan-of-record §"Doctrine Decision B" + the
caller-controlled URL threat model: A2A is a **network-only** protocol.
Inbound + outbound A2A traffic flows entirely over HTTPS using
``a2a-sdk`` SDK + ``httpx`` + ``joserfc``. There is NO legitimate
reason for any ``protocol/a2a_*`` module to spawn a subprocess.

(cosign + OPA subprocess invocations live in
``protocol/trust_gate.py`` + ``core/policy/engine.py`` respectively;
those modules are NOT under ``protocol/a2a_*`` and so are out of scope
for this test. A2A's wire-format work happens entirely inside the
Python process.)

This test is the **mechanical guardrail** for the doctrine. It walks
the AST of every Python file matching ``protocol/a2a_*.py`` (top-level
file or nested under a package directory; recursive glob so future
``protocol/a2a_endpoint/helpers.py`` style submodules are caught) and
asserts that NONE of them import or call process-spawn primitives.

If a future commit trips this test, that commit is adding launch code
to A2A — which has no architectural justification. Revert the change.

The 9 banned import / call shapes (mirrors Sprint-5
``test_mcp_stdio_no_subprocess.py`` exactly):

  1. ``import subprocess`` (or ``from subprocess import ...``)
  2. ``import os; os.exec*`` (any of the 8 ``os.exec[lvpe]*`` variants)
  3. ``import os; os.spawn*`` (any of the 8 ``os.spawn[lvpe]*`` variants)
  4. ``import os; os.posix_spawn*`` (both ``posix_spawn`` + ``posix_spawnp``)
  5. ``import os; os.system``
  6. ``import os; os.popen``
  7. ``import asyncio; asyncio.create_subprocess_exec``
  8. ``import asyncio; asyncio.create_subprocess_shell``
  9. ``import multiprocessing; multiprocessing.Process``

Plus the kwarg form: any function call with ``shell=True``.

The test combines with the runtime canary
``tests/unit/protocol/test_a2a_no_caller_controlled_url.py`` (Sprint-6
T14) — even if a future maintainer evades the static check via
``__import__("subprocess")``, the canary trips on the resulting
refusal vector.

Scope difference from Sprint-5 ``test_mcp_stdio_no_subprocess.py``:
this test scans ONLY paths matching ``protocol/a2a_*.py``. There is
no parallel ``*stdio*`` substring scan because A2A has no STDIO
surface — the threat model for A2A is caller-controlled URLs (see
``docs/A2A-CALLER-URL-THREAT-MODEL.md``), not process-spawn injection.
And there is no ``_LAUNCHER_ALLOWLIST`` shape because A2A has no
Sprint-N hand-off contract that would legitimately add a subprocess
launcher to ``protocol/a2a_*`` (cf. Sprint-5's Sprint-8 mcp_stdio
launcher hand-off).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

#: Repo source root — three levels up from this file
#: (``tests/architecture/test_X.py`` → ``tests/`` → ``repo`` → ``src/cognic_agentos/protocol/``).
_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "cognic_agentos" / "protocol"

#: Import-target patterns that indicate process-spawn capability.
#: A ``from foo import bar`` or ``import foo`` whose top-level module
#: is in this set is a direct doctrine violation.
_BANNED_MODULES = frozenset(
    {
        "subprocess",
        "multiprocessing",
    }
)

#: Python's ``os.exec*`` family — direct process replacement (8 variants
#: in Python 3.12). Pinned exactly so a missing primitive fails the
#: completeness self-test below.
_OS_EXEC_VARIANTS: frozenset[str] = frozenset(
    {
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
    }
)

#: Python's ``os.spawn*`` family — fork-and-exec (8 variants in
#: Python 3.12). Pinned exactly.
_OS_SPAWN_VARIANTS: frozenset[str] = frozenset(
    {
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
    }
)

#: Python's ``os.posix_spawn*`` family — POSIX-spawn variants
#: (2 variants in Python 3.12).
_OS_POSIX_SPAWN_VARIANTS: frozenset[str] = frozenset(
    {
        "os.posix_spawn",
        "os.posix_spawnp",
    }
)

#: Shell-style command execution.
_OS_SHELL_EXEC: frozenset[str] = frozenset(
    {
        "os.system",
        "os.popen",
    }
)

#: asyncio subprocess primitives — async equivalents of
#: ``subprocess.Popen`` and ``subprocess.run(..., shell=True)``.
_ASYNCIO_SUBPROCESS: frozenset[str] = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }
)

#: The full banned-call set — union of every category above.
_BANNED_CALLS: frozenset[str] = (
    _OS_EXEC_VARIANTS
    | _OS_SPAWN_VARIANTS
    | _OS_POSIX_SPAWN_VARIANTS
    | _OS_SHELL_EXEC
    | _ASYNCIO_SUBPROCESS
)


def _a2a_modules(src_root: Path | None = None) -> list[Path]:
    """Every Python module under ``protocol/`` whose path matches
    ``a2a_*.py`` (top-level file or nested submodule).

    Collects:

    1. Any path matching ``a2a_*.py`` (top-level file or nested under
       a package directory) — recursive glob so a future
       ``protocol/a2a_endpoint/helpers.py`` style submodule is caught.
    2. **Package ``__init__.py`` files INSIDE any ``a2a_*`` package
       directory** — a package's ``__init__.py`` executes when ANY
       submodule is imported; subprocess imports there would trigger
       before any ``helpers.py`` content. The only ``__init__.py``
       excluded is the root ``protocol/__init__.py`` (the package
       marker that holds the Sprint-5 + Sprint-6 loader API; not an
       A2A surface).

    The ``src_root`` parameter is for testing the collector itself
    (the self-tests below pass a temporary directory to verify
    collection behaviour without depending on the real source tree).
    """
    root = src_root if src_root is not None else _SRC_ROOT
    candidates: set[Path] = set()
    # Layer 1: recursive glob for a2a_*.py (top-level + nested submodules)
    candidates.update(root.rglob("a2a_*.py"))
    # Layer 2: any .py inside a directory whose name starts with 'a2a_'.
    # Catches files like a2a_endpoint/helpers.py that wouldn't match
    # pattern 1 directly. INCLUDES that directory's __init__.py (a
    # package's __init__.py executes on import and could harbor
    # subprocess imports).
    for path in root.rglob("*.py"):
        for part in path.parts:
            if part.startswith("a2a_"):
                candidates.add(path)
                break
    # Exclude only the root protocol/__init__.py (loader API; not
    # A2A surface). Every other __init__.py — including any future
    # protocol/a2a_endpoint/__init__.py — stays in scope.
    root_init = root / "__init__.py"
    candidates.discard(root_init)
    return sorted(candidates)


#: Modules whose names we resolve through aliases + from-imports when
#: scanning calls. Adding to this set extends alias resolution to a new
#: top-level module (e.g., adding "shutil" would resolve
#: ``import shutil as s; s.which(...)`` if shutil ever became banned).
_ALIASED_MODULES_OF_INTEREST: frozenset[str] = frozenset({"os", "asyncio"})


def _build_alias_maps(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    """Walk import nodes once to build two resolution maps.

    Returns ``(module_aliases, from_import_aliases)``:

    - ``module_aliases``: maps the local binding name to the real
      top-level module name. Examples:

      - ``import os`` → ``{"os": "os"}``
      - ``import os as o`` → ``{"o": "os"}``
      - ``import asyncio as aio`` → ``{"aio": "asyncio"}``

      Only modules in :data:`_ALIASED_MODULES_OF_INTEREST` (currently
      ``os`` + ``asyncio``) are tracked — these are the namespaces
      from which banned calls originate. ``subprocess`` /
      ``multiprocessing`` aliases are caught by the banned-import
      scan above, so we don't need to track them here.

    - ``from_import_aliases``: maps the local binding name to the
      fully-qualified target. Examples:

      - ``from os import system`` → ``{"system": "os.system"}``
      - ``from os import system as sys_call`` → ``{"sys_call": "os.system"}``
      - ``from asyncio import create_subprocess_exec as cse`` →
        ``{"cse": "asyncio.create_subprocess_exec"}``

      Only entries whose fully-qualified target matches a banned-call
      prefix are recorded (so unrelated from-imports don't bloat the
      map).

    The two maps together let the call walker resolve every common
    invocation form: ``os.system(...)``, ``o.system(...)`` (aliased
    module), ``system(...)`` (from-imported), ``sys_call(...)``
    (from-imported with rename).
    """
    module_aliases: dict[str, str] = {}
    from_import_aliases: dict[str, str] = {}

    # Pre-compute the set of banned top-level modules from _BANNED_CALLS
    # so we can filter from-imports cheaply (e.g., "os.system" → "os").
    banned_call_top_levels = {call.split(".", 1)[0] for call in _BANNED_CALLS}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _ALIASED_MODULES_OF_INTEREST:
                    bind_name = alias.asname or alias.name
                    module_aliases[bind_name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            if node.module not in banned_call_top_levels:
                continue
            for alias in node.names:
                if alias.name == "*":
                    # Star imports lose name-tracking precision (we
                    # can't tell which bare names entered the local
                    # namespace). They are banned outright by
                    # :func:`_check_imports` for modules in
                    # :data:`_ALIASED_MODULES_OF_INTEREST`, so a module
                    # that reaches this branch has already failed the
                    # architecture test — we just skip the alias-
                    # tracking and let the import-side violation
                    # report the issue.
                    continue
                bind_name = alias.asname or alias.name
                fully_qualified = f"{node.module}.{alias.name}"
                if fully_qualified in _BANNED_CALLS:
                    from_import_aliases[bind_name] = fully_qualified

    return module_aliases, from_import_aliases


def _check_imports(tree: ast.AST, path: Path) -> list[str]:
    """Find any banned import statement.

    Two classes of violation:

    1. **Banned-module imports** — ``import subprocess`` /
       ``import multiprocessing`` (or any submodule thereof), or
       ``from subprocess import …`` / ``from multiprocessing import …``.
       Catches the direct import of process-spawn modules.
    2. **Star imports from call-namespace modules** —
       ``from os import *`` / ``from asyncio import *``. Banned outright:
       a star import from one of these namespaces injects every name
       in the module into the local namespace, including banned bare
       names like ``system`` or ``create_subprocess_exec``. The call
       walker can't track which names came from the star import, so
       banning at the import-statement boundary is the precise fix.
       (``from subprocess import *`` / ``from multiprocessing import *``
       are already caught by the banned-module check above; this rule
       covers ``os`` + ``asyncio`` which are NOT banned modules —
       importing them is fine, but wholesale-importing every name
       is not.)

    Returns a list of human-readable violation strings (one per
    offending statement). Empty list = the module is clean.

    Note: ``os`` and ``asyncio`` are NOT in :data:`_BANNED_MODULES` —
    only ``subprocess`` and ``multiprocessing`` are. Importing ``os``
    is fine; calling ``os.system`` is what's banned. The call walker
    handles that via :func:`_check_calls` + the alias maps.
    """
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                if top_level in _BANNED_MODULES:
                    violations.append(f"{path.name}:{node.lineno} — banned import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top_level = node.module.split(".")[0]
            if top_level in _BANNED_MODULES:
                violations.append(f"{path.name}:{node.lineno} — banned from-import: {node.module}")
                continue
            # Star-import ban for call-namespace modules.
            if node.module in _ALIASED_MODULES_OF_INTEREST:
                for alias in node.names:
                    if alias.name == "*":
                        violations.append(
                            f"{path.name}:{node.lineno} — banned star import: "
                            f"from {node.module} import * "
                            f"(would harbour banned bare names like "
                            f"'system' / 'execvp' / 'create_subprocess_exec' "
                            f"that the call walker cannot track)"
                        )
                        break
    return violations


def _resolve_call_chain(
    func_node: ast.AST,
    module_aliases: dict[str, str],
    from_import_aliases: dict[str, str],
) -> str | None:
    """Resolve a call's function expression to its fully-qualified
    banned-call name, taking aliases + from-imports into account.

    Returns the resolved fully-qualified name (e.g. ``"os.system"``)
    if the call matches a banned form, else None.

    Resolution rules (in order):

    1. **Bare ``Name`` lookup** — ``func_node`` is ``ast.Name(id="x")``.
       If ``x`` is in ``from_import_aliases``, return that mapping
       (e.g., ``from os import system; system()`` resolves to
       ``"os.system"``).
    2. **Attribute chain ending in ``Name``** — ``func_node`` is
       ``ast.Attribute(...).Name(id="m")``. Resolve ``m`` through
       ``module_aliases``, rebuild the chain with the real module
       name, and return that (e.g., ``import os as o; o.system()``
       resolves to ``"os.system"``).
    3. **Otherwise** — return None (caller's chain isn't a simple
       Name-or-Attribute form, e.g., ``foo().bar()``).
    """
    # Rule 1: bare Name (from-import path)
    if isinstance(func_node, ast.Name):
        return from_import_aliases.get(func_node.id)

    # Rule 2: attribute chain ending in Name
    parts: list[str] = []
    cur: ast.AST = func_node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    # cur.id is the leftmost name — resolve through module aliases
    real_module = module_aliases.get(cur.id, cur.id)
    parts.append(real_module)
    return ".".join(reversed(parts))


def _check_calls(tree: ast.AST, path: Path) -> list[str]:
    """Find any ``ast.Call`` whose resolved chain matches a banned
    call (e.g., ``os.execvp(...)``, ``asyncio.create_subprocess_exec(...)``,
    ``o.system(...)`` after ``import os as o``, ``system(...)``
    after ``from os import system``) OR whose ``shell=True`` kwarg
    is set (defensive against future subprocess-shaped calls that
    slip past the import check).

    Returns a list of violation strings.
    """
    module_aliases, from_import_aliases = _build_alias_maps(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = _resolve_call_chain(node.func, module_aliases, from_import_aliases)
        if resolved is not None:
            for banned in _BANNED_CALLS:
                if resolved == banned or resolved.startswith(banned + "."):
                    violations.append(f"{path.name}:{node.lineno} — banned call: {resolved}")
                    break
        # Defensive: shell=True kwarg on any call.
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                violations.append(f"{path.name}:{node.lineno} — shell=True kwarg detected")
    return violations


class TestA2aNoSubprocess:
    """The architectural guardrail. Every ``protocol/a2a_*.py`` module
    MUST NOT import ``subprocess`` / ``multiprocessing`` or call any
    banned process-spawn primitive.

    If this test fails, REVERT the offending edit. A2A is a
    network-only protocol per ADR-003 + the Sprint-6 plan-of-record's
    caller-controlled URL threat model. There is no architectural
    justification for any ``protocol/a2a_*`` module to spawn a
    subprocess.
    """

    @pytest.mark.parametrize(
        "module_path",
        _a2a_modules() or [pytest.param(None, id="no-a2a-modules-yet")],
    )
    def test_no_banned_imports_or_calls(self, module_path: Path | None) -> None:
        """Every A2A module must clear the AST scan. Parametrized arm
        grows from ``[None]`` (T4 — this commit) to 10 modules (after
        T5/T6/T7/T8/T9/T10/T11 land each module — see Sprint-6 plan
        File Structure §"Architecture-sentinel surface").
        """
        if module_path is None:
            pytest.skip(
                "no a2a_* modules exist yet under protocol/; "
                "this arm collects automatically as T5-T11 land each module"
            )
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(module_path))
        violations = _check_imports(tree, module_path) + _check_calls(tree, module_path)
        assert not violations, (
            f"Sprint-6 A2A architecture test failed for "
            f"{module_path.name}:\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\n\nPer ADR-003 + Sprint-6 plan §Doctrine Decision B: "
            "A2A is a network-only protocol. There is NO legitimate "
            "reason for any protocol/a2a_* module to spawn a subprocess. "
            "If you are intentionally adding subprocess code to A2A, "
            "stop and revert — there is no Sprint-N hand-off contract "
            "that legitimises it (cf. Sprint-5 mcp_stdio_launcher's "
            "Sprint-8 hand-off — A2A has no such hand-off because A2A "
            "has no STDIO surface at all)."
        )

    def test_at_least_one_a2a_module_exists(self) -> None:
        """Catches the "test passes vacuously because no a2a_* files
        exist yet" failure mode. Sprint 6 ships 10 a2a_* modules total
        per the architecture-sentinel surface (a2a_endpoint, a2a_authz,
        a2a_agent_cards, a2a_schema, a2a_version, a2a_streaming,
        a2a_artifacts, a2a_capability_negotiation, a2a_cancellation,
        a2a_errors). T16 closeout (this commit) tightens the floor
        from the T4 placeholder ``>= 0`` to ``>= 9`` — leaves room
        for one rename without tripping the test, but trips before
        the parametrized arm above starts vacuously passing on
        accidental module deletion.
        """
        modules = _a2a_modules()
        # T16 floor — Sprint 6 ships 10 a2a_*.py modules; -1 rename buffer.
        assert len(modules) >= 9, (
            f"Only {len(modules)} a2a_*.py modules under "
            f"src/cognic_agentos/protocol/. Sprint 6 ships 10 such "
            f"modules; the collector floor of 9 leaves room for one "
            f"rename without tripping. If two or more were renamed "
            f"or deleted, the parametrized scan above would silently "
            f"shrink — investigate before bumping this floor down."
        )


class TestModuleCollectorSelfTests:
    """Self-tests for :func:`_a2a_modules`. Without these, a regression
    that drops the recursive glob (or the ``a2a_`` prefix scan, or the
    ``__init__.py`` exclusion) could silently mask drift in the main
    contract test above — the parametrized arm would simply collect
    fewer modules and the suite would still go green.

    Each self-test plants a small filesystem layout in ``tmp_path``
    and asserts the collector finds the expected files.
    """

    def test_collector_finds_top_level_a2a_files(self, tmp_path: Path) -> None:
        """Top-level ``protocol/a2a_*.py`` files MUST be picked up. If
        a future maintainer regresses the collector to a non-recursive
        glob that misses something, this self-test fails."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "a2a_endpoint.py").write_text("# stub", encoding="utf-8")
        (fake_root / "a2a_authz.py").write_text("# stub", encoding="utf-8")
        # The root protocol/__init__.py MUST be excluded
        (fake_root / "__init__.py").write_text("", encoding="utf-8")
        # An unrelated file — must NOT be collected
        (fake_root / "plugin_registry.py").write_text("# stub", encoding="utf-8")
        # An MCP file — also must NOT be collected (different test
        # owns the MCP scan)
        (fake_root / "mcp_host.py").write_text("# stub", encoding="utf-8")

        modules = _a2a_modules(src_root=fake_root)
        names = {p.name for p in modules}

        assert {"a2a_endpoint.py", "a2a_authz.py"} <= names
        # The root __init__.py must NOT be collected
        assert (fake_root / "__init__.py") not in modules
        assert "plugin_registry.py" not in names
        # MCP modules are out of scope for this test
        assert "mcp_host.py" not in names

    def test_collector_finds_nested_a2a_submodules(self, tmp_path: Path) -> None:
        """Nested ``protocol/a2a_endpoint/helpers.py`` style submodules
        MUST be picked up. The recursive ``rglob`` + ``a2a_`` directory-
        prefix scan catches them."""
        fake_root = tmp_path / "protocol"
        nested = fake_root / "a2a_endpoint"
        nested.mkdir(parents=True)
        (nested / "helpers.py").write_text("# stub", encoding="utf-8")
        (nested / "validators.py").write_text("# stub", encoding="utf-8")
        # The package's __init__.py MUST be in scope — it executes
        # when any submodule is imported and could harbour subprocess
        # imports of its own
        (nested / "__init__.py").write_text("", encoding="utf-8")

        modules = _a2a_modules(src_root=fake_root)
        names = {p.name for p in modules}

        # Both helpers and validators MUST be in scope (the parent
        # directory a2a_endpoint matches the 'a2a_' directory prefix).
        assert "helpers.py" in names
        assert "validators.py" in names
        # The nested __init__.py IS in scope. Specifically check by
        # full path so we don't false-match the (non-existent here)
        # root __init__.py.
        assert (nested / "__init__.py") in modules

    def test_collector_excludes_only_root_protocol_init(self, tmp_path: Path) -> None:
        """The only ``__init__.py`` excluded from the architecture-test
        scope is the **root** ``protocol/__init__.py`` (Sprint-5 +
        Sprint-6 loader API; not A2A surface). Every other
        ``__init__.py`` under any ``a2a_*`` package directory MUST
        be in scope.

        A future ``protocol/a2a_endpoint/__init__.py`` that imports
        subprocess at package-init time would execute when ANY
        submodule of ``a2a_endpoint`` is imported, and must be
        governed by the architecture test."""
        fake_root = tmp_path / "protocol"
        nested_endpoint = fake_root / "a2a_endpoint"
        nested_streaming = fake_root / "a2a_streaming"
        nested_endpoint.mkdir(parents=True)
        nested_streaming.mkdir(parents=True)
        # The root protocol/__init__.py — explicitly excluded
        (fake_root / "__init__.py").write_text("", encoding="utf-8")
        # Two nested __init__.py files — both MUST be in scope
        (nested_endpoint / "__init__.py").write_text("", encoding="utf-8")
        (nested_streaming / "__init__.py").write_text("", encoding="utf-8")

        modules = _a2a_modules(src_root=fake_root)

        # Root excluded
        assert (fake_root / "__init__.py") not in modules
        # Both nested __init__.py files in scope
        assert (nested_endpoint / "__init__.py") in modules
        assert (nested_streaming / "__init__.py") in modules


class TestBannedSetsConsistency:
    """Light sanity checks on the banned-set definitions themselves.
    These would catch a future copy-paste regression (e.g., dropping
    ``os.system`` from ``_BANNED_CALLS``)."""

    def test_subprocess_is_banned_module(self) -> None:
        assert "subprocess" in _BANNED_MODULES

    def test_multiprocessing_is_banned_module(self) -> None:
        assert "multiprocessing" in _BANNED_MODULES

    def test_os_system_is_banned_call(self) -> None:
        """``os.system`` is the most-direct shell-style command
        execution."""
        assert "os.system" in _BANNED_CALLS

    def test_os_popen_is_banned_call(self) -> None:
        """``os.popen`` opens a pipe to a shell command — same risk
        class as ``os.system``."""
        assert "os.popen" in _BANNED_CALLS

    def test_asyncio_create_subprocess_exec_is_banned_call(self) -> None:
        """The async equivalent of ``subprocess.Popen``."""
        assert "asyncio.create_subprocess_exec" in _BANNED_CALLS

    def test_asyncio_create_subprocess_shell_is_banned_call(self) -> None:
        """The async equivalent of ``subprocess.run(..., shell=True)``."""
        assert "asyncio.create_subprocess_shell" in _BANNED_CALLS

    def test_banned_calls_includes_every_os_exec_variant_exactly(self) -> None:
        """Python's ``os.exec*`` family has exactly 8 variants in
        Python 3.12 (execl, execle, execlp, execlpe, execv, execve,
        execvp, execvpe). Drift detector for missing primitives.
        """
        expected_exec_variants = {
            "os.execl",
            "os.execle",
            "os.execlp",
            "os.execlpe",
            "os.execv",
            "os.execve",
            "os.execvp",
            "os.execvpe",
        }
        os_exec_in_set = {c for c in _BANNED_CALLS if c.startswith("os.exec")}
        missing = expected_exec_variants - os_exec_in_set
        assert not missing, (
            f"_BANNED_CALLS is missing os.exec* variants: {sorted(missing)}. "
            f"Python 3.12 ships exactly 8 exec variants; all must be banned."
        )

    def test_banned_calls_includes_every_os_spawn_variant_exactly(self) -> None:
        """Python's ``os.spawn*`` family has exactly 8 variants in
        Python 3.12."""
        expected_spawn_variants = {
            "os.spawnl",
            "os.spawnle",
            "os.spawnlp",
            "os.spawnlpe",
            "os.spawnv",
            "os.spawnve",
            "os.spawnvp",
            "os.spawnvpe",
        }
        os_spawn_in_set = {c for c in _BANNED_CALLS if c.startswith("os.spawn") and c != "os.spawn"}
        missing = expected_spawn_variants - os_spawn_in_set
        assert not missing, (
            f"_BANNED_CALLS is missing os.spawn* variants: {sorted(missing)}. "
            f"Python 3.12 ships exactly 8 spawn variants; all must be banned."
        )

    def test_banned_calls_includes_both_posix_spawn_variants(self) -> None:
        """``os.posix_spawn`` + ``os.posix_spawnp`` — both must be
        present."""
        expected_posix_spawn = {"os.posix_spawn", "os.posix_spawnp"}
        missing = expected_posix_spawn - _BANNED_CALLS
        assert not missing


class TestAliasAndFromImportResolution:
    """Contract tests for the call walker's alias + from-import
    resolution. Each test feeds a small AST fragment through the same
    ``_check_imports`` + ``_check_calls`` helpers the main contract
    test uses, and asserts the violation is reported.

    Without these tests, the helpers could silently drop alias handling
    and the architecture test would still pass on the parametrized
    arm (which only runs against currently-shipped modules — at T4,
    zero).
    """

    def _scan_source(self, source: str) -> list[str]:
        """Parse a code snippet through the same helpers the main
        contract test uses, and return any violations."""
        tree = ast.parse(source)
        fake_path = Path("test_stub.py")
        return _check_imports(tree, fake_path) + _check_calls(tree, fake_path)

    def test_aliased_os_module_resolves(self) -> None:
        """``import os as o; o.system(...)`` MUST be caught."""
        source = "import os as o\no.system('ls')\n"
        violations = self._scan_source(source)
        assert any("os.system" in v for v in violations), (
            f"Aliased os.system call not caught. Violations: {violations}"
        )

    def test_aliased_asyncio_module_resolves(self) -> None:
        """``import asyncio as aio; aio.create_subprocess_exec(...)``
        MUST be caught."""
        source = "import asyncio as aio\naio.create_subprocess_exec('ls')\n"
        violations = self._scan_source(source)
        assert any("asyncio.create_subprocess_exec" in v for v in violations), (
            f"Aliased asyncio.create_subprocess_exec call not caught. Violations: {violations}"
        )

    def test_from_import_resolves(self) -> None:
        """``from os import system; system(...)`` MUST be caught."""
        source = "from os import system\nsystem('ls')\n"
        violations = self._scan_source(source)
        assert any("os.system" in v for v in violations), (
            f"from-imported system() call not caught. Violations: {violations}"
        )

    def test_from_import_with_rename_resolves(self) -> None:
        """``from os import system as sys_call; sys_call(...)`` MUST
        be caught — the local name is renamed but the resolution still
        maps to ``os.system``."""
        source = "from os import system as sys_call\nsys_call('ls')\n"
        violations = self._scan_source(source)
        assert any("os.system" in v for v in violations), (
            f"Renamed from-import call not caught. Violations: {violations}"
        )

    def test_from_asyncio_import_with_rename_resolves(self) -> None:
        """``from asyncio import create_subprocess_exec as cse;
        cse(...)`` MUST be caught."""
        source = "from asyncio import create_subprocess_exec as cse\ncse('/bin/ls')\n"
        violations = self._scan_source(source)
        assert any("asyncio.create_subprocess_exec" in v for v in violations), (
            f"Renamed asyncio from-import call not caught. Violations: {violations}"
        )

    def test_unaliased_os_call_still_resolves(self) -> None:
        """Sanity: the existing case (``import os; os.system(...)``)
        still resolves correctly through the new helper."""
        source = "import os\nos.system('ls')\n"
        violations = self._scan_source(source)
        assert any("os.system" in v for v in violations), (
            f"Plain os.system call not caught. Violations: {violations}"
        )

    def test_unaliased_asyncio_call_still_resolves(self) -> None:
        """Sanity: ``import asyncio; asyncio.create_subprocess_shell(...)``
        still resolves."""
        source = "import asyncio\nasyncio.create_subprocess_shell('ls')\n"
        violations = self._scan_source(source)
        assert any("asyncio.create_subprocess_shell" in v for v in violations), (
            f"Plain asyncio.create_subprocess_shell call not caught. Violations: {violations}"
        )

    def test_unrelated_from_import_does_not_trigger(self) -> None:
        """Negative control: ``from os import getcwd; getcwd()`` is
        NOT a banned call. The from-import map must not bloat with
        unrelated names."""
        source = "from os import getcwd\ngetcwd()\n"
        violations = self._scan_source(source)
        assert not violations, f"Benign from-import wrongly flagged. Violations: {violations}"

    def test_local_function_with_banned_name_does_not_trigger(self) -> None:
        """Negative control: a local function named ``system`` (not
        imported from ``os``) MUST NOT be flagged."""
        source = "def system(cmd):\n    pass\nsystem('hello')\n"
        violations = self._scan_source(source)
        assert not violations, (
            f"Local function with banned name wrongly flagged. Violations: {violations}"
        )

    def test_subprocess_import_still_caught(self) -> None:
        """The ``_check_imports`` half (banned modules) is unchanged;
        sanity-check that ``import subprocess`` still trips."""
        source = "import subprocess\n"
        violations = self._scan_source(source)
        assert any("subprocess" in v for v in violations)

    def test_from_subprocess_import_still_caught(self) -> None:
        """``from subprocess import run`` still trips the banned-
        modules check."""
        source = "from subprocess import run\n"
        violations = self._scan_source(source)
        assert any("subprocess" in v for v in violations)


class TestStarImportBan:
    """``from os import *`` / ``from asyncio import *`` are banned
    outright.

    A star import injects every name in the source module into the
    local namespace, including banned bare names like ``system``,
    ``execvp``, ``create_subprocess_exec``. The call walker cannot
    track which bare names came from the star import, so the precise
    fix is to ban the star-import statement itself.
    """

    def _scan_source(self, source: str) -> list[str]:
        tree = ast.parse(source)
        fake_path = Path("test_stub.py")
        return _check_imports(tree, fake_path) + _check_calls(tree, fake_path)

    def test_star_import_from_os_banned(self) -> None:
        """``from os import *`` MUST be flagged."""
        source = "from os import *\nsystem('ls')\n"
        violations = self._scan_source(source)
        assert any("banned star import" in v and "os" in v for v in violations), (
            f"from os import * not caught. Violations: {violations}"
        )

    def test_star_import_from_asyncio_banned(self) -> None:
        """``from asyncio import *`` MUST be flagged."""
        source = "from asyncio import *\ncreate_subprocess_exec('/bin/ls')\n"
        violations = self._scan_source(source)
        assert any("banned star import" in v and "asyncio" in v for v in violations), (
            f"from asyncio import * not caught. Violations: {violations}"
        )

    def test_star_import_from_subprocess_caught_by_module_ban(self) -> None:
        """``from subprocess import *`` is caught by the existing
        banned-MODULE check."""
        source = "from subprocess import *\n"
        violations = self._scan_source(source)
        assert any("subprocess" in v for v in violations), (
            f"from subprocess import * not caught. Violations: {violations}"
        )

    def test_star_import_from_unrelated_module_does_not_trigger(self) -> None:
        """Negative control: ``from typing import *`` MUST NOT be
        flagged."""
        source = "from typing import *\n"
        violations = self._scan_source(source)
        assert not violations, (
            f"Star import from unrelated module wrongly flagged. Violations: {violations}"
        )

    def test_star_import_ban_uses_aliased_modules_of_interest_set(self) -> None:
        """The ban keys off :data:`_ALIASED_MODULES_OF_INTEREST` (the
        set tracked by the alias-resolution code). Single source of
        truth for "modules whose call namespace we govern"."""
        assert "os" in _ALIASED_MODULES_OF_INTEREST
        assert "asyncio" in _ALIASED_MODULES_OF_INTEREST
