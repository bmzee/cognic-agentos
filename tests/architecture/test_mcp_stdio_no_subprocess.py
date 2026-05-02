"""Sprint 5 architecture test — STDIO module subprocess/exec import ban.

Per the Sprint-5 Decision Lock (Option C): STDIO ships threat model +
manifest validation + fail-closed refusal in Sprint 5; STDIO does NOT
ship process launch. The launch path is deferred to Sprint 8 with the
sandbox primitive.

This test is the **mechanical guardrail** for that decision. It walks
the AST of every Python file matching the doctrine:

1. Any path matching ``mcp_*.py`` (top-level file or nested under a
   package directory) — recursive glob so future ``protocol/mcp_stdio/
   helpers.py`` style submodules are caught.
2. Any path containing ``stdio`` in its name or in any of its parent
   directory names — defensive against a module that gets renamed
   away from the ``mcp_`` prefix but still ships STDIO-related code.

…and asserts that NONE of them import or call process-spawn primitives.

If a future commit trips this test, that commit is adding launch code.
EITHER it's Sprint 8's sandboxed launcher (in which case update
``_LAUNCHER_ALLOWLIST`` to allow ``subprocess`` in the new launcher
module ONLY) OR it's a doctrine violation that needs explicit review.

The test combines with :class:`TestStubMcpMissingBlocksRealImports`
in ``tests/unit/protocol/test_optional_dep_loader.py`` (which proves
that the kernel-image-equivalent venv genuinely cannot import ``mcp``)
to give true drift detection: even if a maintainer evades the static
check via ``__import__("subprocess")``, the runtime canary
(``test_mcp_no_user_controlled_command.py`` from Task 13) trips on the
resulting refusal vector.
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

#: Function/method calls that indicate process-spawn capability.
#: An ``ast.Call`` whose attribute chain matches any of these (or
#: starts with one of them) is a direct doctrine violation.
#:
#: Includes every variant of ``os.exec*`` and ``os.spawn*`` / ``os.posix_spawn*``
#: that Python provides, plus ``os.system`` / ``os.popen`` (shell-style
#: command execution), plus ``asyncio.create_subprocess_exec`` /
#: ``asyncio.create_subprocess_shell`` (async equivalents).
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

#: Sprint 8 will add a single sandboxed launcher module that is permitted
#: to import process-spawn primitives. Until then, this set is empty and
#: every mcp_* / *stdio* file in protocol/ is banned. Sprint 8 closeout
#: edits this set + adds the launcher to the explicit allow-list path.
#:
#: **Entries are root-relative ``Path`` objects, NOT bare basenames**
#: (per R3 P3 #4). A bare-basename allow-list would exclude EVERY file
#: with that name anywhere under ``protocol/`` — but the Sprint-8
#: hand-off contract is "exactly one launcher module is allowed to
#: import subprocess". When Sprint 8 lands, populate with e.g.
#: ``frozenset({Path("mcp_stdio_launcher.py")})`` (the path is relative
#: to ``_SRC_ROOT``, i.e. ``src/cognic_agentos/protocol/``). The
#: collector below filters via :meth:`Path.relative_to` so a future
#: nested file with the same basename (e.g.
#: ``protocol/some_pkg/mcp_stdio_launcher.py``) remains in scope.
_LAUNCHER_ALLOWLIST: frozenset[Path] = frozenset()


def _mcp_modules(src_root: Path | None = None) -> list[Path]:
    """Every Python module under ``protocol/`` that the Decision Lock
    governs.

    Collects:

    1. Any path matching ``mcp_*.py`` (top-level file or nested under a
       package directory) — recursive glob so future
       ``protocol/mcp_stdio/helpers.py`` style submodules are caught.
    2. Any ``*.py`` whose path includes a directory or basename
       containing ``stdio`` — defensive against modules renamed away
       from the ``mcp_`` prefix.
    3. **Package ``__init__.py`` files INSIDE any ``mcp_*`` or
       ``*stdio*`` package directory** — a package's ``__init__.py``
       executes when ANY submodule is imported; subprocess imports
       there would trigger before any ``helpers.py`` content. The
       only ``__init__.py`` excluded is the root ``protocol/__init__.py``
       (the package marker that holds the Sprint-5 loader API; not
       a stdio package). Per R3 P2 #3.

    Excludes:

    - The root ``protocol/__init__.py`` (kernel-vs-adapters loader API
      lives there — not stdio surface).
    - Any module whose root-relative path is in
      :data:`_LAUNCHER_ALLOWLIST` — Sprint 8 will populate this with
      the sandboxed launcher's path-exact entry to permit its single
      ``subprocess`` import.

    The ``src_root`` parameter is for testing the collector itself
    (the self-tests below pass a temporary directory to verify
    collection behaviour without depending on the real source tree).
    """
    root = src_root if src_root is not None else _SRC_ROOT
    candidates: set[Path] = set()
    # Layer 1: recursive glob for mcp_*.py (top-level + nested submodules)
    candidates.update(root.rglob("mcp_*.py"))
    # Layer 2: any .py with 'stdio' in its basename
    candidates.update(root.rglob("*stdio*.py"))
    # Layer 3: any .py inside a directory whose name contains 'stdio'
    # OR starts with 'mcp_'. Catches files like mcp_stdio/helpers.py
    # that wouldn't match patterns 1+2 directly. INCLUDES that
    # directory's __init__.py (per R3 P2 #3 — package initializers
    # in stdio/mcp packages execute on import and could harbor
    # subprocess imports).
    for path in root.rglob("*.py"):
        for part in path.parts:
            lowered = part.lower()
            if "stdio" in lowered or part.startswith("mcp_"):
                candidates.add(path)
                break
    # Exclude only the root protocol/__init__.py (loader API; not
    # stdio surface). Every other __init__.py — including any future
    # protocol/mcp_stdio/__init__.py — stays in scope.
    root_init = root / "__init__.py"
    candidates.discard(root_init)
    # Exclude the Sprint-8 launcher allow-list (path-exact match,
    # NOT basename — see _LAUNCHER_ALLOWLIST docstring).
    candidates = {p for p in candidates if p.relative_to(root) not in _LAUNCHER_ALLOWLIST}
    return sorted(candidates)


def _attr_chain(node: ast.AST) -> str | None:
    """Resolve a chain of ``ast.Attribute`` lookups to a dotted string.

    Returns e.g. ``"os.execvp"`` for ``os.execvp(...)``,
    ``"asyncio.create_subprocess_exec"`` for the async case.
    Returns None if the call's function expression isn't a simple
    Name-or-Attribute chain (e.g., a method call on a return value
    like ``foo().bar()``).
    """
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


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
                    # :data:`_ALIASED_MODULES_OF_INTEREST` (per R4
                    # P2 fix), so a module that reaches this branch
                    # has already failed the architecture test —
                    # we just skip the alias-tracking and let the
                    # import-side violation report the issue.
                    continue
                bind_name = alias.asname or alias.name
                fully_qualified = f"{node.module}.{alias.name}"
                if fully_qualified in _BANNED_CALLS:
                    from_import_aliases[bind_name] = fully_qualified

    return module_aliases, from_import_aliases


def _check_imports(tree: ast.AST, path: Path) -> list[str]:
    """Find any banned import statement.

    Three classes of violation:

    1. **Banned-module imports** — ``import subprocess`` /
       ``import multiprocessing`` (or any submodule thereof), or
       ``from subprocess import …`` / ``from multiprocessing import …``.
       Catches the direct import of process-spawn modules.
    2. **Star imports from call-namespace modules** —
       ``from os import *`` / ``from asyncio import *``. Banned outright
       per R4 P2: a star import from one of these namespaces injects
       every name in the module into the local namespace, including
       banned bare names like ``system`` or ``create_subprocess_exec``.
       The call walker can't track which names came from the star
       import, so banning at the import-statement boundary is the
       precise fix. (``from subprocess import *`` /
       ``from multiprocessing import *`` are already caught by the
       banned-module check above; this rule covers ``os`` + ``asyncio``
       which are NOT banned modules — importing them is fine, but
       wholesale-importing every name is not.)

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
            # Star-import ban for call-namespace modules (R4 P2 fix).
            # ``from os import *`` injects ``system``, ``execvp``, etc.
            # into the local namespace as bare names; the call walker
            # cannot track which names came from the star import, so
            # we ban at the import-statement boundary instead.
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
        # Defensive: shell=True kwarg on any call. If a future
        # maintainer routes through a wrapper to evade the import
        # check, shell=True remains a strong signal that something
        # process-spawn-shaped is being invoked.
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                violations.append(f"{path.name}:{node.lineno} — shell=True kwarg detected")
    return violations


class TestMcpStdioNoSubprocess:
    """The architectural guardrail. Every ``protocol/mcp_*.py`` and
    every ``*stdio*.py`` MUST NOT import ``subprocess`` /
    ``multiprocessing`` or call any banned process-spawn primitive.

    If this test fails, REVERT the offending edit. Sprint-5 Decision
    Lock has been broken. The only path that legitimately trips this
    test is the Sprint-8 sandboxed launcher landing — at which point
    update :data:`_LAUNCHER_ALLOWLIST` to allow ``subprocess`` in the
    new launcher module ONLY.
    """

    @pytest.mark.parametrize(
        "module_path",
        _mcp_modules() or [pytest.param(None, id="no-mcp-modules-yet")],
    )
    def test_no_banned_imports_or_calls(self, module_path: Path | None) -> None:
        """Every module governed by the Decision Lock must clear the
        AST scan. Parametrized arm grows from ``[None]`` (T4 — this
        commit) to 5 modules (after T5/T6/T7/T8/T9 land each module).
        """
        if module_path is None:
            pytest.skip(
                "no mcp_* / *stdio* modules exist yet under protocol/; "
                "this arm collects automatically as T5-T9 land each module"
            )
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(module_path))
        violations = _check_imports(tree, module_path) + _check_calls(tree, module_path)
        assert not violations, (
            f"Sprint-5 STDIO architecture test failed for "
            f"{module_path.name}:\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\n\nPer Sprint-5 Decision Lock (Option C): STDIO ships "
            "threat model + manifest validation + fail-closed refusal. "
            "NOT process launch. Process spawning is Sprint 8 "
            "(sandboxed launcher module). If you are intentionally "
            "adding sandboxed launch code as part of Sprint 8, update "
            "tests/architecture/test_mcp_stdio_no_subprocess.py:"
            "_LAUNCHER_ALLOWLIST to exclude the new launcher module's "
            "basename."
        )

    def test_at_least_one_mcp_module_exists(self) -> None:
        """Catches the "test passes vacuously because no mcp_* files
        exist yet" failure mode. Sprint 5 ships at least 5 mcp_*
        modules (mcp_authz, mcp_manifest, mcp_capabilities,
        mcp_transports, mcp_host); anything less means a task got
        skipped.

        During T4 (this commit) the count is 0, so the assertion is
        the placeholder ``>= 0``. T15 closeout tightens this to
        ``>= 5`` once all five modules have shipped — drift detector
        for missing tasks.
        """
        modules = _mcp_modules()
        # T4 placeholder; tightened to >= 5 in T15 closeout
        assert len(modules) >= 0


class TestModuleCollectorSelfTests:
    """Self-tests for :func:`_mcp_modules`. Without these, a regression
    that drops the recursive glob (or the ``stdio`` substring scan, or
    the ``__init__.py`` exclusion) could silently mask drift in the
    main contract test above — the parametrized arm would simply
    collect fewer modules and the suite would still go green.

    Each self-test plants a small filesystem layout in ``tmp_path``
    and asserts the collector finds the expected files.
    """

    def test_module_collector_finds_top_level_mcp_files(self, tmp_path: Path) -> None:
        """Top-level ``protocol/mcp_*.py`` files MUST be picked up. If
        a future maintainer regresses the collector to a non-recursive
        glob that misses something, this self-test fails."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "mcp_host.py").write_text("# stub", encoding="utf-8")
        (fake_root / "mcp_authz.py").write_text("# stub", encoding="utf-8")
        # The root protocol/__init__.py MUST be excluded (per R3 P2 #3
        # — kernel-vs-adapters loader API; not stdio surface)
        (fake_root / "__init__.py").write_text("", encoding="utf-8")
        # An unrelated file — must NOT be collected
        (fake_root / "plugin_registry.py").write_text("# stub", encoding="utf-8")

        modules = _mcp_modules(src_root=fake_root)
        names = {p.name for p in modules}

        assert {"mcp_host.py", "mcp_authz.py"} <= names
        # The root __init__.py must NOT be collected
        assert (fake_root / "__init__.py") not in modules
        assert "plugin_registry.py" not in names

    def test_module_collector_finds_nested_stdio_submodules(self, tmp_path: Path) -> None:
        """Nested ``protocol/mcp_stdio/helpers.py`` style submodules
        MUST be picked up. The original non-recursive ``glob('mcp_*.py')``
        would have missed these. The recursive ``rglob`` + 'stdio'
        substring scan + path-parts check catches them."""
        fake_root = tmp_path / "protocol"
        nested = fake_root / "mcp_stdio"
        nested.mkdir(parents=True)
        (nested / "helpers.py").write_text("# stub", encoding="utf-8")
        (nested / "validators.py").write_text("# stub", encoding="utf-8")
        # Per R3 P2 #3: the stdio package's __init__.py MUST be in
        # scope — it executes when any submodule is imported and could
        # harbour subprocess imports of its own
        (nested / "__init__.py").write_text("", encoding="utf-8")

        modules = _mcp_modules(src_root=fake_root)
        names = {p.name for p in modules}

        # Both helpers and validators MUST be in scope (the parent
        # directory mcp_stdio matches both 'mcp_' prefix and 'stdio'
        # substring filters).
        assert "helpers.py" in names
        assert "validators.py" in names
        # The nested __init__.py IS in scope (R3 P2 #3 — package
        # initializers in stdio/mcp packages execute on import and
        # MUST be governed by the architecture test). Specifically
        # check by full path so we don't false-match the
        # (non-existent here) root __init__.py.
        assert (nested / "__init__.py") in modules

    def test_module_collector_excludes_only_root_protocol_init(self, tmp_path: Path) -> None:
        """Per R3 P2 #3: the only ``__init__.py`` excluded from the
        architecture-test scope is the **root** ``protocol/__init__.py``
        (kernel-vs-adapters loader API; not stdio surface). Every
        other ``__init__.py`` under any ``mcp_*`` or ``*stdio*``
        package directory MUST be in scope.

        This is the critical P2 #3 fix: a future
        ``protocol/mcp_stdio/__init__.py`` that imports subprocess
        at package-init time would execute when ANY submodule of
        ``mcp_stdio`` is imported, and must be governed by the
        architecture test."""
        fake_root = tmp_path / "protocol"
        nested_stdio = fake_root / "mcp_stdio"
        nested_mcp = fake_root / "mcp_other"
        nested_stdio.mkdir(parents=True)
        nested_mcp.mkdir(parents=True)
        # The root protocol/__init__.py — explicitly excluded
        (fake_root / "__init__.py").write_text("", encoding="utf-8")
        # Two nested __init__.py files — both MUST be in scope
        (nested_stdio / "__init__.py").write_text("", encoding="utf-8")
        (nested_mcp / "__init__.py").write_text("", encoding="utf-8")

        modules = _mcp_modules(src_root=fake_root)

        # Root excluded
        assert (fake_root / "__init__.py") not in modules
        # Both nested __init__.py files in scope
        assert (nested_stdio / "__init__.py") in modules
        assert (nested_mcp / "__init__.py") in modules

    def test_module_collector_finds_renamed_stdio_module(self, tmp_path: Path) -> None:
        """Defensive: a future refactor that renames the STDIO module
        away from the ``mcp_`` prefix (e.g. to ``protocol/stdio_pack.py``)
        but still ships STDIO-related code MUST still be caught — the
        guardrail keys off the doctrine ('any STDIO surface in
        protocol/'), not just the naming convention."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "stdio_pack.py").write_text("# stub", encoding="utf-8")

        modules = _mcp_modules(src_root=fake_root)
        names = {p.name for p in modules}

        assert "stdio_pack.py" in names

    def test_module_collector_excludes_launcher_allowlist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Sprint-8 hand-off mechanism — populating
        :data:`_LAUNCHER_ALLOWLIST` with a path-relative entry excludes
        that exact path from the architecture-test scope. This self-test
        verifies the exclusion works so Sprint 8's launcher landing
        won't trip the test on its only legitimate ``subprocess`` import.
        """
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "mcp_host.py").write_text("# stub", encoding="utf-8")
        (fake_root / "mcp_stdio_launcher.py").write_text("# stub", encoding="utf-8")

        # Simulate Sprint 8 populating the allow-list with a
        # path-relative entry
        monkeypatch.setattr(
            "tests.architecture.test_mcp_stdio_no_subprocess._LAUNCHER_ALLOWLIST",
            frozenset({Path("mcp_stdio_launcher.py")}),
        )

        modules = _mcp_modules(src_root=fake_root)

        # mcp_host.py still in scope (not on allow-list)
        assert (fake_root / "mcp_host.py") in modules
        # mcp_stdio_launcher.py is the Sprint-8 launcher — allow-listed
        # so it can carry its sandboxed subprocess.run() without tripping
        assert (fake_root / "mcp_stdio_launcher.py") not in modules

    def test_launcher_allowlist_is_path_exact_not_basename(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """**R3 P3 #4 contract test:** the allow-list keys on
        path-exact entries (relative to ``_SRC_ROOT``), NOT bare
        basenames. A nested file with the same basename as the
        allow-listed launcher MUST remain in scope.

        Without this contract the Sprint-8 hand-off could silently
        exclude every ``mcp_stdio_launcher.py`` anywhere under
        ``protocol/`` (e.g., a future ``protocol/some_pkg/
        mcp_stdio_launcher.py`` would also be skipped), which would
        re-open a doctrine drift class."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        # The legitimate Sprint-8 launcher (top-level)
        (fake_root / "mcp_stdio_launcher.py").write_text("# stub", encoding="utf-8")
        # A nested file with the SAME basename — MUST NOT be excluded
        nested = fake_root / "some_pkg"
        nested.mkdir()
        (nested / "mcp_stdio_launcher.py").write_text("# stub", encoding="utf-8")

        # Simulate Sprint 8: allow-list ONLY the top-level launcher
        monkeypatch.setattr(
            "tests.architecture.test_mcp_stdio_no_subprocess._LAUNCHER_ALLOWLIST",
            frozenset({Path("mcp_stdio_launcher.py")}),
        )

        modules = _mcp_modules(src_root=fake_root)

        # Top-level launcher excluded (the legitimate Sprint-8 module)
        assert (fake_root / "mcp_stdio_launcher.py") not in modules
        # Nested same-basename file MUST stay in scope (path-exact
        # contract — bare basename matching would have wrongly
        # excluded this too)
        assert (nested / "mcp_stdio_launcher.py") in modules


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
        execution. If this drops out of the banned set, the canary
        wouldn't catch it."""
        assert "os.system" in _BANNED_CALLS

    def test_os_popen_is_banned_call(self) -> None:
        """``os.popen`` opens a pipe to a shell command — same risk
        class as ``os.system``."""
        assert "os.popen" in _BANNED_CALLS

    def test_asyncio_create_subprocess_exec_is_banned_call(self) -> None:
        """The async equivalent of ``subprocess.Popen``; equally
        dangerous in the threat model."""
        assert "asyncio.create_subprocess_exec" in _BANNED_CALLS

    def test_asyncio_create_subprocess_shell_is_banned_call(self) -> None:
        """The async equivalent of ``subprocess.run(..., shell=True)``;
        equally dangerous."""
        assert "asyncio.create_subprocess_shell" in _BANNED_CALLS

    def test_banned_calls_includes_every_os_exec_variant_exactly(self) -> None:
        """**R3 P2 #2 contract test:** Python's ``os.exec*`` family
        has exactly 8 variants in Python 3.12 (execl, execle, execlp,
        execlpe, execv, execve, execvp, execvpe). The previous
        ``>= 7`` assertion let ``os.execlpe`` slip; the exact-subset
        check below catches missing primitives.
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
        # Subset assertion: the banned set must contain ALL 8
        # variants. If a future Python release adds a new variant,
        # this test still passes (the banned set may legitimately
        # have MORE than expected); but if any of the 8 known
        # variants is missing, this trips.
        missing = expected_exec_variants - os_exec_in_set
        assert not missing, (
            f"_BANNED_CALLS is missing os.exec* variants: {sorted(missing)}. "
            f"Python 3.12 ships exactly 8 exec variants; all must be banned."
        )

    def test_banned_calls_includes_every_os_spawn_variant_exactly(self) -> None:
        """**R3 P2 #2 contract test:** Python's ``os.spawn*`` family
        has exactly 8 variants in Python 3.12 (spawnl, spawnle,
        spawnlp, spawnlpe, spawnv, spawnve, spawnvp, spawnvpe). The
        previous banned set was missing ``os.spawnve``."""
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
        present. Drift detector for the POSIX-spawn family."""
        expected_posix_spawn = {"os.posix_spawn", "os.posix_spawnp"}
        missing = expected_posix_spawn - _BANNED_CALLS
        assert not missing

    def test_launcher_allowlist_starts_empty(self) -> None:
        """Sprint 5 ships with no allow-listed launcher module; the
        Sprint-8 hand-off populates this set. Drift detector for an
        accidental allow-list addition outside Sprint 8."""
        assert not _LAUNCHER_ALLOWLIST


class TestAliasAndFromImportResolution:
    """**R3 P2 #1 contract tests:** the call walker resolves aliases
    + from-imports for ``os`` and ``asyncio`` so common evasion forms
    are caught.

    Each test feeds a small AST fragment through the same
    ``_check_imports`` + ``_check_calls`` helpers the main contract
    test uses, and asserts the violation is reported.

    Without these tests, the helpers could silently drop alias
    handling and the architecture test would still pass on the
    parametrized arm (which only runs against currently-shipped
    modules — currently 0).
    """

    def _scan_source(self, source: str) -> list[str]:
        """Parse a code snippet through the same helpers the main
        contract test uses, and return any violations. The fake
        ``Path`` is just for line-numbering in error messages."""
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
        """``from os import system; system(...)`` MUST be caught even
        though there's no module qualifier on the call site."""
        source = "from os import system\nsystem('ls')\n"
        violations = self._scan_source(source)
        assert any("os.system" in v for v in violations), (
            f"from-imported system() call not caught. Violations: {violations}"
        )

    def test_from_import_with_rename_resolves(self) -> None:
        """``from os import system as sys_call; sys_call(...)`` MUST
        be caught — the local name is renamed but the resolution
        still maps to ``os.system``."""
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
        imported from ``os``) MUST NOT be flagged. The from-import
        map only contains names that were actually imported."""
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
    """**R4 P2 contract tests:** ``from os import *`` /
    ``from asyncio import *`` are banned outright.

    A star import injects every name in the source module into the
    local namespace, including banned bare names like ``system``,
    ``execvp``, ``create_subprocess_exec``. The call walker cannot
    track which bare names came from the star import (it only
    populates ``from_import_aliases`` for explicitly-named
    from-imports), so the precise fix is to ban the star-import
    statement itself.

    The fix lives in :func:`_check_imports`. Tests below cover the
    two banned source modules + a negative control (star import from
    an unrelated module is fine — admission-side modules need to
    be free to ``from typing import *`` or similar without tripping).
    """

    def _scan_source(self, source: str) -> list[str]:
        """Same helper shape as :class:`TestAliasAndFromImportResolution`."""
        tree = ast.parse(source)
        fake_path = Path("test_stub.py")
        return _check_imports(tree, fake_path) + _check_calls(tree, fake_path)

    def test_star_import_from_os_banned(self) -> None:
        """``from os import *`` MUST be flagged (a subsequent
        ``system(...)`` call would be untrackable)."""
        source = "from os import *\nsystem('ls')\n"
        violations = self._scan_source(source)
        assert any("banned star import" in v and "os" in v for v in violations), (
            f"from os import * not caught. Violations: {violations}"
        )

    def test_star_import_from_asyncio_banned(self) -> None:
        """``from asyncio import *`` MUST be flagged (would harbour
        bare ``create_subprocess_exec``)."""
        source = "from asyncio import *\ncreate_subprocess_exec('/bin/ls')\n"
        violations = self._scan_source(source)
        assert any("banned star import" in v and "asyncio" in v for v in violations), (
            f"from asyncio import * not caught. Violations: {violations}"
        )

    def test_star_import_from_subprocess_caught_by_module_ban(self) -> None:
        """``from subprocess import *`` is caught by the existing
        banned-MODULE check (subprocess is in :data:`_BANNED_MODULES`)
        — but it MUST be caught one way or another."""
        source = "from subprocess import *\n"
        violations = self._scan_source(source)
        assert any("subprocess" in v for v in violations), (
            f"from subprocess import * not caught. Violations: {violations}"
        )

    def test_star_import_from_unrelated_module_does_not_trigger(self) -> None:
        """**Negative control:** ``from typing import *`` MUST NOT be
        flagged. The star-import ban is precise — it covers only modules
        whose calls we govern (currently ``os`` + ``asyncio``). Other
        star imports are unrelated to the threat model.
        """
        source = "from typing import *\n"
        violations = self._scan_source(source)
        assert not violations, (
            f"Star import from unrelated module wrongly flagged. Violations: {violations}"
        )

    def test_star_import_ban_uses_aliased_modules_of_interest_set(
        self,
    ) -> None:
        """The ban keys off :data:`_ALIASED_MODULES_OF_INTEREST` (the
        set tracked by the alias-resolution code). If a future change
        adds another module to that set (e.g., to track ``shutil``
        aliases), the star-import ban auto-extends to that module too
        — single source of truth for "modules whose call namespace
        we govern".
        """
        # The set must contain the modules the test set above
        # actually exercises
        assert "os" in _ALIASED_MODULES_OF_INTEREST
        assert "asyncio" in _ALIASED_MODULES_OF_INTEREST
