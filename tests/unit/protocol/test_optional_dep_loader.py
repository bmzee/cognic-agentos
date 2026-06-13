"""Sprint 5 T2 — optional-dep loader API tests.

Per Sprint-5 plan-of-record (1e43792) §T2 step 4 + R3 P1 doctrine:
the `mcp` SDK is an optional dependency that ships in
``[project.optional-dependencies].adapters`` only — kernel image does
NOT install it. The loader API in :mod:`cognic_agentos.protocol`
exposes :func:`is_mcp_available` and :func:`require_mcp` as the
single mechanism by which runtime-side classes (MCPHost,
StreamableHTTPTransport) gate on the SDK at construction time.

This test file pins three load-bearing invariants:

1. **Module-import contract:** every ``protocol/mcp_*.py`` module
   MUST import cleanly even when ``mcp`` SDK is not installed. If a
   future commit adds a module-level ``from mcp import …``, this test
   trips before the kernel image breaks.

2. **Admission stays SDK-free** (R3 P1 doctrine): admission-side
   classes (MCPAuthzClient, validators, extractors) MUST construct
   without the SDK. Currently asserted as a placeholder via
   ``test_module_imports_succeed_without_mcp_sdk``; tightened in
   T5/T6/T8 to assert constructor success on each admission-side
   class as it lands.

3. **Runtime requires SDK**: MCPHost and StreamableHTTPTransport DO
   call ``require_mcp()`` at construction; constructing them on a
   kernel-image-equivalent venv (mocked ``find_spec`` returning None)
   MUST raise :class:`MCPNotAvailableError`. Currently a placeholder;
   tightened in T7/T9 once those classes land.

The placeholder shape is honest scaffolding — it pins the invariants
the contract names and acknowledges which arms will be filled in by
which task. T9 closeout adjusts ``_mcp_modules_to_check`` to include
the full quintet once all five exist.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from collections.abc import Iterator

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol import (
    A2ANotAvailableError,
    MCPNotAvailableError,
    is_a2a_available,
    is_mcp_available,
    require_a2a,
    require_mcp,
)

#: Sprint-5 plan §T2 step 4 enumerates the five mcp_* modules that
#: WILL ship under protocol/. The parametrized test below collects
#: only the modules that currently exist; it tightens automatically
#: as T5/T6/T7/T8/T9 land each module.
_MCP_MODULES_PLANNED = (
    "cognic_agentos.protocol.mcp_authz",
    "cognic_agentos.protocol.mcp_capabilities",
    "cognic_agentos.protocol.mcp_manifest",
    "cognic_agentos.protocol.mcp_transports",
    "cognic_agentos.protocol.mcp_host",
)


def _existing_mcp_modules() -> tuple[str, ...]:
    """Return only the mcp_* modules that have actually shipped.

    During Sprint-5 implementation the count grows from 0 (T2) to 5
    (T9 closeout). The parametrized arms below collect against this
    list so tests pass at every intermediate state without skipped
    arms cluttering the output.
    """
    return tuple(m for m in _MCP_MODULES_PLANNED if importlib.util.find_spec(m) is not None)


#: Sprint-6 plan §T2 step 4 enumerates the protocol/a2a_* modules.
#: Mirrors :data:`_MCP_MODULES_PLANNED` for parity. The parametrized
#: arms below collect against this list so tests pass at every
#: intermediate state without skipped arms cluttering the output.
#:
#: Doctrine boundary (Sprint-6 T2 R3 P1 + R1 P2 + R2 P2 #1 reviewer
#: corrections): admission-side modules (a2a_authz, a2a_agent_cards,
#: a2a_schema, a2a_version, a2a_errors, a2a_capability_negotiation,
#: a2a_cancellation) are SDK-free at the import + construction
#: boundary; runtime-side modules (a2a_endpoint, a2a_streaming,
#: a2a_artifacts) depend on the SDK at runtime. The kernel-image-
#: import contract applies to ALL admission-side modules — they MUST
#: import cleanly without ``a2a-sdk`` installed. The runtime-side
#: modules are tolerated to fail import under ``stub_a2a_missing``
#: (their public classes call ``require_a2a()`` at construction, not
#: at import).
#:
#: T11 small modules (a2a_capability_negotiation, a2a_cancellation)
#: are admission-side: a2a_capability_negotiation reads pack-manifest
#: declarations + returns the canonical capability list, no SDK
#: envelope construction; a2a_cancellation flips task lifecycle state
#: + emits chained audit events using the `A2AErrorCode` Literal from
#: a2a_errors.py (a string-typed wire-code, NOT an SDK type). Both
#: are on the 10-module architecture-sentinel surface but stay outside
#: the SDK boundary.
_A2A_MODULES_PLANNED = (
    # Admission-side (MUST import cleanly without ``a2a-sdk``)
    "cognic_agentos.protocol.a2a_authz",
    "cognic_agentos.protocol.a2a_agent_cards",
    "cognic_agentos.protocol.a2a_schema",
    "cognic_agentos.protocol.a2a_version",
    # Errors module — also admission-side per the Sprint-6 R3 P2 #2
    # reviewer correction (owns the spec wire enum + AgentOS policy
    # enum + their mapping; no SDK consumption)
    "cognic_agentos.protocol.a2a_errors",
    # T11 small modules — admission-side per the Sprint-6 T2 R2 P2 #1
    # reviewer correction (manifest reading + lifecycle-state flips
    # + chained-event emission; no module-level SDK envelope import)
    "cognic_agentos.protocol.a2a_capability_negotiation",
    "cognic_agentos.protocol.a2a_cancellation",
    # Runtime-side (MAY import the SDK at module level — tolerated to
    # fail under stub_a2a_missing because A2AEndpoint /
    # A2AStreamingEmitter / A2AArtifactsManager call require_a2a()
    # at construction, not at import). T9/T10/T11 land these.
    "cognic_agentos.protocol.a2a_endpoint",
    "cognic_agentos.protocol.a2a_streaming",
    "cognic_agentos.protocol.a2a_artifacts",
)


_A2A_ADMISSION_SIDE_MODULES = (
    "cognic_agentos.protocol.a2a_authz",
    "cognic_agentos.protocol.a2a_agent_cards",
    "cognic_agentos.protocol.a2a_schema",
    "cognic_agentos.protocol.a2a_version",
    "cognic_agentos.protocol.a2a_errors",
    # T2 R2 P2 #1: T11 small modules join the admission-side floor
    # because their public surface consumes only the `A2AErrorCode`
    # string-Literal vocabulary from a2a_errors.py + pack-manifest
    # data — no module-level SDK envelope construction.
    "cognic_agentos.protocol.a2a_capability_negotiation",
    "cognic_agentos.protocol.a2a_cancellation",
)


_A2A_RUNTIME_SIDE_MODULES = (
    "cognic_agentos.protocol.a2a_endpoint",
    "cognic_agentos.protocol.a2a_streaming",
    "cognic_agentos.protocol.a2a_artifacts",
)


def _existing_a2a_modules(*, admission_only: bool = False) -> tuple[str, ...]:
    """Return only the a2a_* modules that have actually shipped.

    During Sprint-6 implementation the count grows from 0 (T2) to 10
    (T11 closeout — full architecture-sentinel surface). T2 R2 P2 #1
    reviewer correction extended the planned set from 8 to 10 to
    cover the two T11 small modules (``a2a_capability_negotiation``,
    ``a2a_cancellation``) under the kernel-image-import contract.
    Mirrors :func:`_existing_mcp_modules`.

    ``admission_only=True`` filters to the SDK-free modules only
    (7 of the 10) — used by the kernel-image-import contract test
    which only asserts the import-clean invariant on admission-side
    modules.
    """
    candidates = _A2A_ADMISSION_SIDE_MODULES if admission_only else _A2A_MODULES_PLANNED
    return tuple(m for m in candidates if importlib.util.find_spec(m) is not None)


class _BlockMcpImports:
    """Meta-path finder that hard-blocks any import of ``mcp`` or
    ``mcp.<submodule>`` by raising ``ModuleNotFoundError``.

    Used by :func:`stub_mcp_missing` to simulate a kernel-image install
    where the ``mcp`` SDK is genuinely not importable. Patching only
    :func:`importlib.util.find_spec` is insufficient: a future module-
    level ``from mcp import …`` could still resolve via Python's
    ``sys.modules`` cache or via other meta-path finders, which would
    silently mask drift in CI (where ``uv sync --all-extras`` installs
    ``mcp``) but break the actual kernel image at startup.

    Inserting this finder at index 0 of ``sys.meta_path`` ensures every
    import attempt for ``mcp*`` raises before any other resolver fires.
    """

    def find_spec(
        self,
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> object | None:
        if fullname == "mcp" or fullname.startswith("mcp."):
            raise ModuleNotFoundError(
                f"Test stub blocks import of {fullname!r} "
                f"to simulate a kernel-image install where "
                f"the `mcp` SDK is not present. "
                f"Per Sprint-5 R3 P1 doctrine, the test contract is "
                f"'every protocol/mcp_*.py module imports cleanly "
                f"without the SDK installed' — if you see this error "
                f"during a real test run, a module-level `from mcp "
                f"import …` was added somewhere it shouldn't be."
            )
        return None  # let other meta-path finders handle non-mcp names


@pytest.fixture
def stub_mcp_missing(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Simulate a kernel-image install where the ``mcp`` SDK is genuinely
    NOT importable.

    Three layers (each load-bearing — patching only one is insufficient
    per Sprint-5 R1 P2 #1 review):

    1. **Evict ``mcp.*`` from ``sys.modules``** — if a previous test
       imported ``mcp``, the cached module would be returned by
       subsequent ``import mcp`` calls regardless of ``find_spec`` or
       ``meta_path``.
    2. **Insert ``_BlockMcpImports`` at the head of ``sys.meta_path``**
       — every fresh import attempt for ``mcp*`` hits this finder
       first and raises ``ModuleNotFoundError`` before any other
       resolver fires. This catches module-level ``from mcp import …``
       drift in any ``protocol/mcp_*.py`` module under test.
    3. **Patch ``importlib.util.find_spec``** — :func:`is_mcp_available`
       calls ``find_spec`` directly (NOT ``import``); the patch makes
       it return ``None`` for ``mcp*`` so the loader API reports
       "missing" consistently with the import-blocked state.

    Other modules resolve normally on all three paths.
    """
    import sys

    real_find_spec = importlib.util.find_spec

    # Layer 1: evict cached mcp.* modules
    for cached in list(sys.modules):
        if cached == "mcp" or cached.startswith("mcp."):
            monkeypatch.delitem(sys.modules, cached)

    # Layer 2: insert blocker at head of meta_path
    blocker = _BlockMcpImports()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])

    # Layer 3: patch find_spec for is_mcp_available()
    def _stub(name: str, *args: object, **kwargs: object) -> object | None:
        if name == "mcp" or name.startswith("mcp."):
            return None
        return real_find_spec(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", _stub)
    yield


@pytest.fixture
def stub_mcp_present(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Simulate a default-adapters image install: ``find_spec("mcp")``
    returns a non-None ``ModuleSpec`` sentinel even if ``mcp`` is NOT
    installed in the test venv.

    This makes the loader-API positive-case tests independent of the
    optional-deps install state — the loader contract is "tolerate
    missing mcp" and the unit tests must validate that contract via
    monkeypatching, not by depending on `mcp` being installed (which
    would fail in a kernel-image-equivalent test env where the
    adapters extras are deliberately omitted).

    Other modules resolve normally.
    """
    import importlib.machinery

    real_find_spec = importlib.util.find_spec
    sentinel = importlib.machinery.ModuleSpec("mcp", loader=None)

    def _stub(name: str, *args: object, **kwargs: object) -> object | None:
        if name == "mcp":
            return sentinel
        if name.startswith("mcp."):
            # Submodule lookups also resolve to a fresh spec; loader
            # API only checks the top-level "mcp" so this is mostly
            # for completeness if a future check probes a submodule.
            return importlib.machinery.ModuleSpec(name, loader=None)
        return real_find_spec(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", _stub)
    yield


class TestLoaderApiBasics:
    """Direct contract on :func:`is_mcp_available` + :func:`require_mcp`.

    Both positive and negative cases monkeypatch ``find_spec`` so the
    tests run identically in any venv (kernel-image-equivalent without
    adapters extras OR adapters-installed venv). The "real `import mcp`
    works" check is a separate T2 command verification (see plan-of-
    record §T2 step 3 — ``uv run python -c 'import mcp; ...'``), not a
    unit-test precondition.
    """

    def test_is_mcp_available_returns_true_when_present(self, stub_mcp_present: None) -> None:
        """When ``find_spec("mcp")`` returns a non-None spec, the loader
        reports the SDK as available — used by ``create_prod_app`` to
        wire MCPHost (T9 forward)."""
        assert is_mcp_available() is True

    def test_require_mcp_succeeds_when_present(self, stub_mcp_present: None) -> None:
        """No-op when find_spec returns non-None; raises only on missing."""
        require_mcp()  # raises if it doesn't return cleanly

    def test_require_mcp_raises_when_missing(self, stub_mcp_missing: None) -> None:
        """Per R3 P1 contract: kernel-image venv (no mcp) → loud error
        at construction time, with remediation guidance in the message."""
        with pytest.raises(MCPNotAvailableError) as exc:
            require_mcp()
        # Error message names the optional-deps group so operators see
        # what to install
        assert "adapters" in str(exc.value)
        # Error message names the kernel-vs-default-adapters split
        # explicitly so the misconfiguration cause is immediate
        assert "default-adapters" in str(exc.value).lower()

    def test_is_mcp_available_returns_false_when_missing(self, stub_mcp_missing: None) -> None:
        """The simulated kernel-image install returns False —
        used by ``create_prod_app`` to skip MCPHost wiring with a
        structured warning."""
        assert is_mcp_available() is False


class TestStubMcpMissingBlocksRealImports:
    """Positive control on :func:`stub_mcp_missing` — verify the fixture
    actually blocks ``import mcp`` at the import-system level, not just
    at :func:`importlib.util.find_spec`.

    Without these tests the fixture could silently degrade (e.g., a
    future refactor that drops the meta-path blocker or the sys.modules
    eviction) and the :class:`TestModuleImportsKernelSafe` invariant
    would pass vacuously even when a module-level ``from mcp import …``
    was added.
    """

    def test_import_mcp_fails_under_stub(self, stub_mcp_missing: None) -> None:
        """``import mcp`` MUST raise ``ModuleNotFoundError`` under the
        fixture. The CI venv has ``mcp == 1.27.0`` installed via
        ``adapters`` extras, so without the meta-path blocker this
        import would succeed and silently mask drift."""
        # Use exec() to ensure a fresh import resolution path (avoids
        # any compile-time caching of the import statement)
        with pytest.raises(ModuleNotFoundError) as exc:
            exec("import mcp", {})
        # Error message names the test stub so a real failure is
        # distinguishable from an actual missing-package error
        assert "Test stub blocks import" in str(exc.value)

    def test_from_mcp_import_fails_under_stub(self, stub_mcp_missing: None) -> None:
        """``from mcp import <anything>`` MUST also raise — the blocker
        catches this attribute-style import too. Specifically pins the
        drift class the reviewer named: 'a future module-level
        from mcp import … could still resolve via Python sys.modules
        cache' if the fixture only patched find_spec."""
        with pytest.raises(ModuleNotFoundError) as exc:
            exec("from mcp import ClientSession", {})
        assert "Test stub blocks import" in str(exc.value)

    def test_import_mcp_submodule_fails_under_stub(self, stub_mcp_missing: None) -> None:
        """``import mcp.client`` (or any other ``mcp.<foo>``) MUST also
        raise — the blocker matches both ``mcp`` and ``mcp.*``."""
        with pytest.raises(ModuleNotFoundError) as exc:
            exec("import mcp.client", {})
        assert "Test stub blocks import" in str(exc.value)

    def test_non_mcp_imports_still_work_under_stub(self, stub_mcp_missing: None) -> None:
        """The blocker is precise — only ``mcp*`` is affected. Other
        imports must continue to resolve normally so unrelated test
        infrastructure (httpx, pytest, etc.) keeps working."""
        # Pick a module unrelated to mcp that's known-installed
        exec("import httpx", {})  # raises if blocked


class TestModuleImportsKernelSafe:
    """The hardest invariant — drift-detection at module-import boundary.

    Every ``protocol/mcp_*.py`` module MUST import cleanly even when
    ``mcp`` SDK is not installed. If a future commit adds a module-level
    ``from mcp import …`` (instead of TYPE_CHECKING-only or lazy method-
    body imports), this test trips before the kernel image breaks at
    runtime.

    Combined with :class:`TestStubMcpMissingBlocksRealImports` (which
    pins that the fixture actually blocks imports at the system level,
    not just at :func:`importlib.util.find_spec`), this gives true
    drift detection: the parametrized arm below reloads each
    ``protocol/mcp_*`` module fresh under the import-blocked fixture,
    so any module-level ``from mcp import …`` raises immediately.
    """

    @pytest.mark.parametrize(
        "module_name",
        _existing_mcp_modules() or [pytest.param(None, id="no-mcp-modules-yet")],
    )
    def test_module_imports_succeed_without_mcp_sdk(
        self, module_name: str | None, stub_mcp_missing: None
    ) -> None:
        """Force ``find_spec("mcp")`` to return None, then reload the
        target module fresh. Module-level import MUST succeed; only
        constructor / method calls may raise.

        During T2 (this commit) no ``mcp_*`` modules exist yet, so the
        parametrized arm collects ``[None]`` and we skip cleanly. As
        T5/T6/T7/T8/T9 land each module, the arm count grows.
        """
        if module_name is None:
            pytest.skip(
                "no mcp_* modules exist yet; this arm collects "
                "automatically as T5-T9 land each module"
            )
        # Reload fresh so cached imports don't mask drift
        if module_name in sys.modules:
            del sys.modules[module_name]
        # Module-level import MUST succeed; only construction or
        # method calls may raise MCPNotAvailableError
        importlib.import_module(module_name)

    @pytest.mark.parametrize(
        "module_name",
        _existing_a2a_modules(admission_only=True)
        or [pytest.param(None, id="no-a2a-admission-modules-yet")],
    )
    def test_admission_modules_import_succeed_without_a2a_sdk(
        self, module_name: str | None, stub_a2a_missing: None
    ) -> None:
        """Sprint-6 T2 R1 P2 + R2 P2 #1 reviewer corrections — without
        this test, the ``stub_a2a_missing`` fixture would catch nothing
        because no admission-side a2a_* module is exercised under it.
        As T5/T6/T7/T8/T11 land each admission-side module (a2a_authz,
        a2a_agent_cards, a2a_schema, a2a_version, a2a_errors,
        a2a_capability_negotiation, a2a_cancellation — 7 total per
        the R2 P2 #1 architecture-sentinel surface), the parametrized
        arm count grows and any module-level ``from a2a import …``
        drift trips immediately.

        Per Sprint-6 T2 R3 P1 doctrine: admission-side modules
        construct cleanly without the SDK installed; runtime serving
        (A2AEndpoint, streaming, artifacts) is the surface that
        depends on it. This test pins the admission-side invariant.
        Runtime-side a2a_* modules are NOT covered here — they are
        permitted to import the SDK at module level and have their
        own require_a2a()-on-construction tests.

        During T2 (this commit) no ``a2a_*`` admission modules exist
        yet, so the parametrized arm collects ``[None]`` and we skip
        cleanly. The arm count grows automatically as T5/T6/T7/T8/T11
        land each module.
        """
        if module_name is None:
            pytest.skip(
                "no a2a_* admission-side modules exist yet; this arm "
                "collects automatically as T5/T6/T7/T8/T11 land each module"
            )
        # Reload fresh so cached imports don't mask drift
        if module_name in sys.modules:
            del sys.modules[module_name]
        # Module-level import MUST succeed; only construction or
        # method calls may raise A2ANotAvailableError
        importlib.import_module(module_name)


class TestRuntimeRequiresSDK:
    """Runtime-side classes gate on the SDK at construction time.

    T7 fills the StreamableHTTPTransport arm. T9 adds MCPHost once the
    orchestrator exists.
    """

    def test_streamable_http_transport_construction_requires_sdk(
        self, stub_mcp_missing: None
    ) -> None:
        """Module import succeeds without the SDK, but construction
        fails loudly because StreamableHTTPTransport actually consumes
        the official MCP SDK at runtime."""
        module_name = "cognic_agentos.protocol.mcp_transports"
        if module_name in sys.modules:
            del sys.modules[module_name]

        mcp_transports = importlib.import_module(module_name)

        with pytest.raises(MCPNotAvailableError):
            mcp_transports.StreamableHTTPTransport(
                authz=object(),
                settings=build_settings_without_env_file(),
            )


class TestProtocolOptionalDepsMapShape:
    """The ``_PROTOCOL_OPTIONAL_DEPS`` dict in protocol/__init__.py is
    documentation-only (not consumed by code) but its shape is
    load-bearing: future maintainers reading it to learn the boundary
    MUST see only runtime-side modules, NOT admission-side modules.

    Listing admission-side modules in this dict would be a doctrine
    violation per Sprint-5 R3 P1 (it would mislead future maintainers
    into adding require_mcp() to admission-side constructors).
    """

    def test_dict_excludes_admission_side_modules(self) -> None:
        """``mcp_authz``, ``mcp_capabilities``, ``mcp_manifest`` are
        admission-side and MUST NOT appear in the optional-deps map.
        If a future edit adds them, this test trips immediately."""
        from cognic_agentos.protocol import _PROTOCOL_OPTIONAL_DEPS

        admission_side = {
            "cognic_agentos.protocol.mcp_authz",
            "cognic_agentos.protocol.mcp_capabilities",
            "cognic_agentos.protocol.mcp_manifest",
        }
        leaked = admission_side & _PROTOCOL_OPTIONAL_DEPS.keys()
        assert not leaked, (
            f"Admission-side modules MUST NOT appear in "
            f"_PROTOCOL_OPTIONAL_DEPS — found: {sorted(leaked)}. "
            f"Per Sprint-5 R3 P1 doctrine, only runtime-side classes "
            f"(MCPHost, StreamableHTTPTransport) gate on the SDK."
        )

    def test_dict_includes_runtime_side_modules(self) -> None:
        """Runtime-side modules are present in the map — this is the
        documentation surface that future Sprint-N work uses to discover
        the contract."""
        from cognic_agentos.protocol import _PROTOCOL_OPTIONAL_DEPS

        assert "cognic_agentos.protocol.mcp_transports" in _PROTOCOL_OPTIONAL_DEPS
        assert "cognic_agentos.protocol.mcp_host" in _PROTOCOL_OPTIONAL_DEPS
        # Both runtime modules require exactly {"mcp"}
        for module in (
            "cognic_agentos.protocol.mcp_transports",
            "cognic_agentos.protocol.mcp_host",
        ):
            assert _PROTOCOL_OPTIONAL_DEPS[module] == frozenset({"mcp"})

    def test_dict_excludes_a2a_admission_modules(self) -> None:
        """Sprint-6 T2 R3 P1 + R2 P2 #1 doctrine, mirroring the MCP
        shape: admission-side a2a modules (``a2a_authz``,
        ``a2a_agent_cards``, ``a2a_schema``, ``a2a_version``,
        ``a2a_errors``, ``a2a_capability_negotiation``,
        ``a2a_cancellation`` — 7 total) MUST NOT appear in the
        optional-deps map. Listing them would be a doctrine violation
        — it would mislead future maintainers into adding
        ``require_a2a()`` to admission-side constructors, which would
        then fail on the kernel image where admission is supposed to
        work without the SDK installed."""
        from cognic_agentos.protocol import _PROTOCOL_OPTIONAL_DEPS

        admission_side = set(_A2A_ADMISSION_SIDE_MODULES)
        leaked = admission_side & _PROTOCOL_OPTIONAL_DEPS.keys()
        assert not leaked, (
            f"Admission-side a2a modules MUST NOT appear in "
            f"_PROTOCOL_OPTIONAL_DEPS — found: {sorted(leaked)}. "
            f"Per Sprint-5 R3 P1 + Sprint-6 same doctrine, only "
            f"runtime-side classes (A2AEndpoint, A2AStreamingEmitter, "
            f"A2AArtifactsManager) gate on the SDK at construction."
        )

    def test_dict_includes_a2a_runtime_modules(self) -> None:
        """Runtime-side a2a modules (``a2a_endpoint``, ``a2a_streaming``,
        ``a2a_artifacts``) are present in the map — this is the
        documentation surface that T9-T11 work uses to discover the
        contract. Each maps to exactly ``frozenset({"a2a"})`` because
        ``a2a`` is the import namespace of the ``a2a-sdk`` PyPI
        package (per Sprint-6 plan-of-record Doctrine Decision A —
        NOT ``a2a_sdk``, NOT ``a2a_protocol``, the latter being an
        unrelated 0.1.0 PyPI package)."""
        from cognic_agentos.protocol import _PROTOCOL_OPTIONAL_DEPS

        for module in _A2A_RUNTIME_SIDE_MODULES:
            assert module in _PROTOCOL_OPTIONAL_DEPS, (
                f"Runtime-side a2a module {module!r} MUST appear in "
                f"_PROTOCOL_OPTIONAL_DEPS so future maintainers reading "
                f"the map see the kernel-vs-default-adapters boundary."
            )
            assert _PROTOCOL_OPTIONAL_DEPS[module] == frozenset({"a2a"}), (
                f"Runtime-side a2a module {module!r} MUST require "
                f"exactly frozenset({{'a2a'}}) — the import namespace "
                f"is ``a2a`` per Sprint-6 Doctrine Decision A."
            )


class TestCreateProdAppMcpAvailabilityBranch:
    """Pin the ``create_prod_app`` SDK-availability LOG branch:
    the factory checks :func:`is_mcp_available` once and either logs SDK
    presence or logs a structured ``mcp.host_unavailable_in_image`` warning.

    ``create_prod_app`` itself does NOT construct the host (Sprint 13.8 — the
    long-deferred "Sprint-5 T9" — lands the real ``MCPHost`` construction in the
    ``create_app`` LIFESPAN, after ``build_runtime``). ``create_app`` PRE-SEEDS
    ``app.state.mcp_host = None`` at construction, so after ``create_prod_app()``
    (no lifespan run) the attribute is ``None`` (pre-seed), not unset.

    Without these tests the suite would still pass if the entire
    ``if is_mcp_available()`` block was deleted from ``create_prod_app``.
    The tests exercise both branches via monkeypatch on the
    ``is_mcp_available`` symbol the factory imports, then assert on
    captured log records.
    """

    def test_create_prod_app_logs_sdk_present_when_available(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SDK-available branch: logs ``mcp.sdk_present_at_startup``
        with image=default-adapters; ``app.state.mcp_host`` is the pre-seed
        ``None`` (the lifespan, not create_prod_app, constructs the host)."""
        from cognic_agentos.portal.api import app as app_module

        monkeypatch.setattr(app_module, "is_mcp_available", lambda: True)
        # Capture the app-module logger at INFO level so
        # mcp.sdk_present_at_startup (level=info) is visible
        caplog.set_level("INFO", logger=app_module.__name__)

        app = app_module.create_prod_app()

        # Branch 1: structured info event fired on the SDK-present path
        sdk_present_records = [
            r for r in caplog.records if r.message == "mcp.sdk_present_at_startup"
        ]
        assert len(sdk_present_records) == 1, (
            f"Expected exactly one 'mcp.sdk_present_at_startup' log; "
            f"got {len(sdk_present_records)} records: "
            f"{[r.message for r in caplog.records]}"
        )
        # Image-tag preserved so operators reading logs can confirm
        # which factory fired
        assert getattr(sdk_present_records[0], "image", None) == "default-adapters"

        # Negative-case event MUST NOT have fired
        unavailable_records = [
            r for r in caplog.records if r.message == "mcp.host_unavailable_in_image"
        ]
        assert not unavailable_records

        # Sprint 13.8: app.state.mcp_host is the pre-seed None (create_app pre-
        # seeds it; the lifespan — not create_prod_app — constructs the host).
        assert app.state.mcp_host is None

    def test_create_prod_app_logs_unavailable_when_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SDK-missing branch: logs structured
        ``mcp.host_unavailable_in_image`` warning with remediation;
        ``app.state.mcp_host`` is the pre-seed ``None``."""
        from cognic_agentos.portal.api import app as app_module

        monkeypatch.setattr(app_module, "is_mcp_available", lambda: False)
        caplog.set_level("WARNING", logger=app_module.__name__)

        app = app_module.create_prod_app()

        # Branch 2: structured warning fired on the SDK-missing path
        unavailable_records = [
            r for r in caplog.records if r.message == "mcp.host_unavailable_in_image"
        ]
        assert len(unavailable_records) == 1, (
            f"Expected exactly one 'mcp.host_unavailable_in_image' log; "
            f"got {len(unavailable_records)} records: "
            f"{[r.message for r in caplog.records]}"
        )

        # Remediation message is in the structured payload (operators
        # parsing JSON logs need this for misconfig diagnosis)
        record = unavailable_records[0]
        assert getattr(record, "missing_module", None) == "mcp"
        assert getattr(record, "optional_dep_group", None) == "adapters"
        remediation = getattr(record, "remediation", "")
        assert "adapters" in remediation
        # Names the Sprint-4 cosign+OPA boundary so operators don't
        # confuse this gate with admission failures
        assert "cosign" in remediation
        assert "OPA" in remediation

        # Positive-case event MUST NOT have fired
        sdk_present_records = [
            r for r in caplog.records if r.message == "mcp.sdk_present_at_startup"
        ]
        assert not sdk_present_records

        # Sprint 13.8: app.state.mcp_host is the pre-seed None.
        assert app.state.mcp_host is None

    def test_create_prod_app_preseeds_mcp_host_none_either_branch(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sprint 13.8 (the long-deferred "Sprint-5 T9"): ``create_prod_app``
        itself still does NOT construct ``MCPHost`` — that lands in the
        ``create_app`` LIFESPAN (after ``build_runtime``). ``create_app``
        pre-seeds ``app.state.mcp_host = None`` at construction, so after
        ``create_prod_app()`` (no lifespan run) it MUST be ``None`` (the
        pre-seed) regardless of which SDK branch fires. This pins that
        ``create_prod_app`` stays a startup-log only — it never constructs a
        real host (that would bypass the lifespan's audit/approval wiring)."""
        from cognic_agentos.portal.api import app as app_module

        for available in (True, False):
            monkeypatch.setattr(app_module, "is_mcp_available", lambda v=available: v)
            app = app_module.create_prod_app()
            assert app.state.mcp_host is None, (
                f"app.state.mcp_host should be the pre-seed None after "
                f"create_prod_app (is_mcp_available={available}); construction is "
                f"the lifespan's job"
            )


# ---------------------------------------------------------------------------
# Sprint 6 T2 — A2A SDK presence check + runtime-side guard
# ---------------------------------------------------------------------------


class _BlockA2aImports:
    """Meta-path finder mirroring :class:`_BlockMcpImports` for the
    ``a2a-sdk`` SDK. Hard-blocks any import of ``a2a`` /
    ``a2a.<submodule>`` by raising ``ModuleNotFoundError``.

    Used by :func:`stub_a2a_missing` to simulate a kernel-image
    install where the ``a2a-sdk`` SDK is genuinely not importable
    (the import namespace is ``a2a`` per the Sprint-6 plan-of-record's
    Doctrine Decision A — NOT ``a2a_sdk`` and NOT ``a2a_protocol``,
    the latter being an unrelated 0.1.0 PyPI package).
    """

    def find_spec(
        self,
        fullname: str,
        path: object | None = None,
        target: object | None = None,
    ) -> object | None:
        if fullname == "a2a" or fullname.startswith("a2a."):
            raise ModuleNotFoundError(
                f"Test stub blocks import of {fullname!r} "
                f"to simulate a kernel-image install where "
                f"the `a2a-sdk` SDK is not present. "
                f"Per Sprint-5 R3 P1 + Sprint-6 same doctrine, "
                f"the test contract is 'every protocol/a2a_*.py "
                f"admission-side module imports cleanly without "
                f"the SDK installed' — if you see this error during "
                f"a real test run, a module-level `from a2a import …` "
                f"was added to an admission-side module where it "
                f"shouldn't be (a2a_authz, a2a_agent_cards, a2a_schema, "
                f"a2a_version, a2a_errors, a2a_capability_negotiation, "
                f"a2a_cancellation are SDK-free; only a2a_endpoint, "
                f"a2a_streaming, a2a_artifacts may import the SDK)."
            )
        return None  # let other meta-path finders handle non-a2a names


@pytest.fixture
def stub_a2a_missing(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Simulate a kernel-image install where the ``a2a-sdk`` SDK is
    genuinely NOT importable. Three layers, mirroring
    :func:`stub_mcp_missing`:

    1. **Evict ``a2a.*`` from ``sys.modules``** — if a previous test
       imported ``a2a``, the cached module would be returned by
       subsequent ``import a2a`` calls regardless of ``find_spec`` or
       ``meta_path``.
    2. **Insert ``_BlockA2aImports`` at the head of ``sys.meta_path``**
       — every fresh import attempt for ``a2a*`` hits this finder
       first and raises ``ModuleNotFoundError`` before any other
       resolver fires. This catches module-level ``from a2a import …``
       drift in any ``protocol/a2a_*.py`` admission-side module
       under test.
    3. **Patch ``importlib.util.find_spec``** — :func:`is_a2a_available`
       calls ``find_spec`` directly (NOT ``import``); the patch makes
       it return ``None`` for ``a2a*`` so the loader API reports
       "missing" consistently with the import-blocked state.
    """
    real_find_spec = importlib.util.find_spec

    # Layer 1: evict cached a2a.* modules
    for cached in list(sys.modules):
        if cached == "a2a" or cached.startswith("a2a."):
            monkeypatch.delitem(sys.modules, cached)

    # Layer 2: insert blocker at head of meta_path
    blocker = _BlockA2aImports()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])

    # Layer 3: patch find_spec for is_a2a_available()
    def _stub(name: str, *args: object, **kwargs: object) -> object | None:
        if name == "a2a" or name.startswith("a2a."):
            return None
        return real_find_spec(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", _stub)
    yield


@pytest.fixture
def stub_a2a_present(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Simulate a default-adapters image install: ``find_spec("a2a")``
    returns a non-None ``ModuleSpec`` sentinel even if ``a2a`` is NOT
    installed in the test venv. Mirrors :func:`stub_mcp_present`.
    """
    real_find_spec = importlib.util.find_spec
    sentinel = object()

    def _stub(name: str, *args: object, **kwargs: object) -> object | None:
        if name == "a2a":
            return sentinel  # non-None sentinel
        return real_find_spec(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", _stub)
    yield


class TestA2ASdkPresenceCheck:
    """Direct contract on :func:`is_a2a_available` + :func:`require_a2a`
    + :class:`A2ANotAvailableError`. Mirrors :class:`TestLoaderApiBasics`.

    The "real `import a2a` works" check is a separate T2 command
    verification (the implementation engineer runs ``uv run python -c
    'import a2a; print(a2a.__file__)'`` against the venv after
    ``uv sync --frozen --all-extras``), not a unit-test precondition.
    """

    def test_is_a2a_available_returns_true_when_present(self, stub_a2a_present: None) -> None:
        """Default-adapters image branch: ``find_spec("a2a")`` returns
        non-None, so the loader reports SDK as available — used by
        ``create_prod_app`` to log SDK presence (T2) + by T9+ to wire
        the A2A endpoint route."""
        assert is_a2a_available() is True

    def test_is_a2a_available_returns_false_when_missing(self, stub_a2a_missing: None) -> None:
        """Kernel-image branch: simulated install returns False —
        used by ``create_prod_app`` to skip A2A wiring with a
        structured warning."""
        assert is_a2a_available() is False

    def test_require_a2a_succeeds_when_present(self, stub_a2a_present: None) -> None:
        """No-op when find_spec returns non-None; raises only on missing."""
        require_a2a()  # raises if it doesn't return cleanly

    def test_require_a2a_raises_when_missing(self, stub_a2a_missing: None) -> None:
        """Per Sprint-5 R3 P1 + Sprint-6 same doctrine: kernel-image
        venv (no a2a-sdk) → loud error at construction time, with
        remediation guidance in the message."""
        with pytest.raises(A2ANotAvailableError) as exc:
            require_a2a()
        # Error message names the optional-deps group so operators see
        # what to install
        assert "adapters" in str(exc.value)
        # Error message names the kernel-vs-default-adapters split
        # explicitly so the misconfiguration cause is immediate
        assert "default-adapters" in str(exc.value).lower()
        # Error message names the runtime-only-modules so operators
        # know which classes the error fires on
        assert "A2AEndpoint" in str(exc.value)


class TestA2ANotAvailableErrorIsDistinctFromMcp:
    """Sprint-6 T2 R3 P1 doctrine: A2A and MCP errors are SEPARATE
    closed-enum types so operators can diagnose which SDK is missing
    on a partially-misconfigured image (e.g., MCP installed but A2A
    not)."""

    def test_a2a_error_is_distinct_class_from_mcp_error(self) -> None:
        """Distinct classes — neither inherits from the other.

        The ``is not`` check is statically obvious to mypy (the two
        names resolve to two distinct symbols at import time) but
        the assertion is the load-bearing safety check that catches
        a future refactor that re-exports one as an alias of the
        other — silencing the static-analysis warning is correct.
        """
        assert A2ANotAvailableError is not MCPNotAvailableError  # type: ignore[comparison-overlap]
        assert not issubclass(A2ANotAvailableError, MCPNotAvailableError)
        assert not issubclass(MCPNotAvailableError, A2ANotAvailableError)

    def test_a2a_error_is_runtime_error(self) -> None:
        """Both inherit from RuntimeError so operator-facing
        ``except RuntimeError`` blocks catch both."""
        assert issubclass(A2ANotAvailableError, RuntimeError)


class TestCreateProdAppA2AWiringT2:
    """T2 contract: ``create_prod_app`` logs SDK presence on either
    branch (info on present, warning on missing) but does NOT mount
    any A2A routes. T9 will extend the SDK-available branch to mount
    the receiver; T11 will mount capabilities/cancellation/artifacts.

    R0 P2 reviewer correction (carried forward from the plan): the
    factory MUST NOT promise wiring it doesn't actually do (Sprint-5
    T15 R1 P2 #1 caught the same overclaim with MCPHost). T2's
    contract is the availability log + the ``is_a2a_available()``
    predicate, nothing else.
    """

    def test_create_prod_app_logs_a2a_present_when_available(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SDK-available branch: logs ``a2a.sdk_present_at_startup``
        with image=default-adapters; ``app.state.a2a_endpoint`` not
        set in T2 (T9 will set it via the ``A2AEndpoint`` constructor)."""
        from cognic_agentos.portal.api import app as app_module

        # Pin both presence checks so the MCP branch doesn't pollute
        # the log assertions on the A2A side.
        monkeypatch.setattr(app_module, "is_mcp_available", lambda: True)
        monkeypatch.setattr(app_module, "is_a2a_available", lambda: True)
        caplog.set_level("INFO", logger=app_module.__name__)

        app = app_module.create_prod_app()

        sdk_present_records = [
            r for r in caplog.records if r.message == "a2a.sdk_present_at_startup"
        ]
        assert len(sdk_present_records) == 1, (
            f"Expected exactly one 'a2a.sdk_present_at_startup' log; "
            f"got {len(sdk_present_records)} records: "
            f"{[r.message for r in caplog.records]}"
        )
        assert getattr(sdk_present_records[0], "image", None) == "default-adapters"

        # Negative-case event MUST NOT have fired
        unavailable_records = [
            r for r in caplog.records if r.message == "a2a.endpoint_unavailable_in_image"
        ]
        assert not unavailable_records

        # T2 invariant: app.state.a2a_endpoint is NOT set yet (T9 sets it)
        assert not hasattr(app.state, "a2a_endpoint")

    def test_create_prod_app_logs_a2a_unavailable_when_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SDK-missing branch: logs structured
        ``a2a.endpoint_unavailable_in_image`` warning with
        remediation; ``app.state.a2a_endpoint`` not set."""
        from cognic_agentos.portal.api import app as app_module

        # Pin both presence checks; A2A is False, MCP is True so the
        # mcp warning doesn't show up under the A2A assertions.
        monkeypatch.setattr(app_module, "is_mcp_available", lambda: True)
        monkeypatch.setattr(app_module, "is_a2a_available", lambda: False)
        caplog.set_level("WARNING", logger=app_module.__name__)

        app = app_module.create_prod_app()

        unavailable_records = [
            r for r in caplog.records if r.message == "a2a.endpoint_unavailable_in_image"
        ]
        assert len(unavailable_records) == 1, (
            f"Expected exactly one 'a2a.endpoint_unavailable_in_image' "
            f"log; got {len(unavailable_records)} records: "
            f"{[r.message for r in caplog.records]}"
        )

        # Remediation message in structured payload
        record = unavailable_records[0]
        assert getattr(record, "missing_module", None) == "a2a"
        assert getattr(record, "optional_dep_group", None) == "adapters"
        remediation = getattr(record, "remediation", "")
        assert "adapters" in remediation
        # Names the admission-side modules so operators don't confuse
        # this gate with admission failures (admission works without SDK)
        assert "A2AEndpoint" in remediation

        # Positive-case event MUST NOT have fired
        sdk_present_records = [
            r for r in caplog.records if r.message == "a2a.sdk_present_at_startup"
        ]
        assert not sdk_present_records

        # T2 invariant: app.state.a2a_endpoint is NOT set yet
        assert not hasattr(app.state, "a2a_endpoint")

    def test_create_prod_app_t2_invariant_a2a_endpoint_unset_either_branch(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """T2 contract: scaffolding only — no A2AEndpoint wiring.
        T9 extends the SDK-available branch to construct + attach
        the endpoint. Until then, ``app.state.a2a_endpoint`` MUST
        remain unset regardless of which branch fires.

        R0 P2 reviewer correction pinned this — same shape as the
        Sprint-5 T15 R1 P2 #1 lesson (don't claim wiring you don't
        actually do)."""
        from cognic_agentos.portal.api import app as app_module

        # Hold MCP presence steady so its branch isn't a confounder.
        monkeypatch.setattr(app_module, "is_mcp_available", lambda: True)

        for available in (True, False):
            monkeypatch.setattr(app_module, "is_a2a_available", lambda v=available: v)
            app = app_module.create_prod_app()
            assert not hasattr(app.state, "a2a_endpoint"), (
                f"app.state.a2a_endpoint should not be set in T2 "
                f"(is_a2a_available={available}); A2AEndpoint wiring is T9"
            )
