"""Sprint 10 T10 K8s round-3 reviewer-P2 fix — regression tests for
the dependency-neutral cross-backend credentials helper module.

Pins the dependency-contract claim in
``src/cognic_agentos/sandbox/backends/_shared_credentials.py``:
the module MUST import ONLY from ``cognic_agentos.core.vault`` (for
the 4 Vault exception classes) and
``cognic_agentos.sandbox.protocol`` (for the
``SandboxRefusalReason`` Literal). Adding any backend-specific
import (``aiodocker`` / ``kubernetes_asyncio`` / any other) would
re-introduce the same coupling-bug class that this module was
extracted to fix at T10 K8s round-2 — the original T10 K8s
implementation imported ``_mint_exception_to_refusal_reason``
directly from ``docker_sibling.py`` which loads ``aiodocker`` at
module import, breaking K8s-only deployments without the
``sandbox-docker`` optional extra (per the boundary documented at
``sandbox/__init__.py:99``).

Two regression mechanisms:

1. **AST scan** — read the source AST of
   ``_shared_credentials.py`` and assert ZERO ``import`` /
   ``from … import`` statements reference any backend-specific
   module. Whitelist: ``__future__``, ``cognic_agentos.core.vault``,
   ``cognic_agentos.sandbox.protocol``. Anything else fails the
   test with a structured diagnostic naming the offending import.
   Fast + deterministic — runs in every CI iteration without
   subprocess overhead.

2. **Subprocess blocked-import probe** — spawn ``python -c "..."``
   with ``sys.modules['aiodocker'] = None`` injected, attempt to
   import ``cognic_agentos.sandbox.backends.kubernetes_pod``, and
   assert the import SUCCEEDS. Mirrors the reviewer's verification
   method. Catches transitive coupling regressions even if a future
   refactor introduces the coupling via a path the AST scan does
   not cover (e.g. a runtime import inside a function body, or a
   transitive import through a sibling module).

Both regressions together pin both the FROM-import contract on the
shared module AND the operational outcome (K8s imports clean
without aiodocker). Drift in either fires here with a clear
diagnostic.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# AST regression — _shared_credentials.py imports ONLY from the
# allowlisted dependency-neutral modules.
# ---------------------------------------------------------------------------


_SHARED_CREDENTIALS_SOURCE_PATH = (
    Path(__file__).resolve().parents[4]
    / "src"
    / "cognic_agentos"
    / "sandbox"
    / "backends"
    / "_shared_credentials.py"
)


#: Modules the shared-helper module is allowed to import. Adding to
#: this set should be a deliberate doctrine decision — every
#: addition risks re-coupling the K8s backend to a Docker-only dep.
_ALLOWED_IMPORTS: frozenset[str] = frozenset(
    {
        "__future__",
        "cognic_agentos.core.vault",
        "cognic_agentos.sandbox.protocol",
    }
)


def _collect_module_imports(source_path: Path) -> set[str]:
    """Parse the source file AST and return the set of fully-qualified
    module names that it imports. Covers both ``import X`` /
    ``import X.Y`` and ``from X.Y import …`` shapes.

    Does NOT cover runtime ``importlib.import_module`` / ``__import__``
    calls — those bypass the static-analysis surface. The subprocess
    blocked-import probe below catches the operational outcome
    regardless of how the import was introduced.
    """
    tree = ast.parse(source_path.read_text())
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imports.add(node.module)
    return imports


class TestSharedCredentialsDependencyNeutral:
    def test_shared_credentials_imports_only_allowlisted_modules(self) -> None:
        """The shared-helper module MUST import only from
        ``cognic_agentos.core.vault`` + ``cognic_agentos.sandbox.protocol``
        + ``__future__``. Any backend-specific import (aiodocker /
        kubernetes_asyncio / any other) is the regression that this
        test guards against."""
        assert _SHARED_CREDENTIALS_SOURCE_PATH.exists(), (
            f"_shared_credentials.py expected at "
            f"{_SHARED_CREDENTIALS_SOURCE_PATH} — module-promotion "
            f"regression, was the file removed?"
        )
        imports = _collect_module_imports(_SHARED_CREDENTIALS_SOURCE_PATH)
        forbidden = imports - _ALLOWED_IMPORTS
        assert not forbidden, (
            f"_shared_credentials.py introduced disallowed imports: "
            f"{sorted(forbidden)}. Allowed set: {sorted(_ALLOWED_IMPORTS)}. "
            f"Adding a backend-specific import (aiodocker / "
            f"kubernetes_asyncio / etc.) would re-introduce the T10 K8s "
            f"round-2 coupling-bug class — the shared module exists "
            f"precisely to keep K8s-only deployments without "
            f"sandbox-docker importable. Promote any new imports to "
            f"_ALLOWED_IMPORTS only after a deliberate review."
        )


# ---------------------------------------------------------------------------
# Subprocess blocked-import probe — mirrors the reviewer's
# verification method. Spawns a fresh Python that simulates a
# K8s-only deployment without the sandbox-docker extra (by injecting
# ``sys.modules['aiodocker'] = None``) and asserts that
# kubernetes_pod imports clean.
# ---------------------------------------------------------------------------


_BLOCKED_IMPORT_PROBE = textwrap.dedent("""
    import sys
    import importlib.util

    # Simulate K8s-only deployment without the sandbox-docker extra
    # by blocking the aiodocker import. sys.modules[name] = None
    # forces Python's import machinery to raise ModuleNotFoundError
    # on subsequent imports of that name.
    sys.modules["aiodocker"] = None

    spec = importlib.util.find_spec(
        "cognic_agentos.sandbox.backends.kubernetes_pod"
    )
    if spec is None:
        print("FAIL: kubernetes_pod spec not found")
        sys.exit(2)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except ImportError as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        sys.exit(1)
    print("OK")
""")


class TestSharedCredentialsBlockedImportProbe:
    def test_kubernetes_pod_imports_clean_when_aiodocker_blocked(self) -> None:
        """Mirrors the reviewer's verification at T10 K8s round-2 P1.
        Sub-process so the parent test process's already-loaded
        ``aiodocker`` does not contaminate the probe environment.
        """
        result = subprocess.run(
            [sys.executable, "-c", _BLOCKED_IMPORT_PROBE],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"K8s import failed with aiodocker blocked — "
            f"_shared_credentials.py dependency-neutral contract regressed. "
            f"Stdout: {result.stdout!r}; stderr: {result.stderr!r}. "
            f"Most-likely cause: a recent change re-introduced a "
            f"direct import from docker_sibling (which loads "
            f"aiodocker at module load) in kubernetes_pod.py OR in a "
            f"module kubernetes_pod transitively imports. See the "
            f"T10 K8s round-2 reviewer-P1 history in "
            f"docs/superpowers/plans/2026-05-23-sprint-10-vault-credential-leasing.md "
            f"Round-4 patch-log entry for context."
        )
        assert "OK" in result.stdout, (
            f"K8s import probe completed without raising but did not "
            f"emit the OK marker. Stdout: {result.stdout!r}; "
            f"stderr: {result.stderr!r}."
        )


# ---------------------------------------------------------------------------
# Functional regression — the shared helper still maps the 4 Vault
# exception types correctly. Cross-backend mapping invariant is also
# pinned by the parametrized cross-backend file; this is the
# helper-direct unit test.
# ---------------------------------------------------------------------------


from cognic_agentos.core.vault import (  # noqa: E402 — after blocked-import probe
    VaultAuthDenied,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
)
from cognic_agentos.sandbox.backends._shared_credentials import (  # noqa: E402
    _mint_exception_to_refusal_reason,
)


class TestMintExceptionToRefusalReasonMapping:
    @pytest.mark.parametrize(
        ("exc_factory", "expected_reason"),
        [
            (
                lambda: VaultUnavailable("vault 5xx"),
                "sandbox_credential_mint_failed_vault_unavailable",
            ),
            (
                lambda: VaultPathNotFound("404"),
                "sandbox_credential_mint_failed_secret_path_unknown",
            ),
            (
                lambda: VaultAuthDenied("403"),
                "sandbox_credential_mint_failed_auth_denied",
            ),
            (
                lambda: VaultProtocolError("malformed"),
                # VaultProtocolError collapses to vault_unavailable
                # for closed-enum stability per spec §6.1 / §7.1
                # last row.
                "sandbox_credential_mint_failed_vault_unavailable",
            ),
        ],
    )
    def test_each_vault_exception_maps_to_expected_closed_enum(
        self, exc_factory: object, expected_reason: str
    ) -> None:
        assert _mint_exception_to_refusal_reason(exc_factory()) == expected_reason  # type: ignore[operator]
