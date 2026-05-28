"""Sprint 10.6 — Z3 + Z4 import-contract regression (subprocess-based).

Pins both halves of the fail-loud-when-opted-in import contract per the
Sprint 10.1 ADR-004 §25 amendment Finding #3, for the two Sprint-10.6
live-proof modules:

* Z3 — ``tests/integration/sandbox/test_z3_docker_credential_projection.py``
  (env gate ``COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_INTEGRATION``;
  optional extras ``aiodocker`` + ``hvac``).
* Z4 — ``tests/integration/sandbox/test_z4_k8s_credential_projection.py``
  (env gate ``COGNIC_RUN_K8S_CREDENTIAL_PROJECTION_INTEGRATION``;
  optional extras ``kubernetes_asyncio`` + ``hvac``).

The contract has two halves:

* **Opt-out (env unset)**: a module-level
  ``pytest.skip(..., allow_module_level=True)`` fires BEFORE any optional
  import, gated purely on the env var. The module is silently skipped
  REGARDLESS of whether the optional extras are importable — a strictly
  stronger contract than Sprint 10's Z2 module (which used
  ``pytest.importorskip`` and therefore skipped only *because* the extra
  was missing). The load-bearing property pinned here is the IMPORT
  ORDER: if anyone moved an optional import above the skip gate, the
  opt-out path would raise ``ImportError`` instead of skipping — these
  tests would then flip from the ``CASUAL_SKIP_OK`` (exit 7) marker to
  ``UNEXPECTED_IMPORT_ERROR`` (exit 8) and fail.

* **Opt-in (env set)**: the module-level skip does NOT fire, so execution
  reaches the plain ``import`` statements for the optional extras. A
  missing extra MUST raise ``ImportError`` at module load (NOT silently
  skip via ``pytest.importorskip``) → pytest reports a collection error
  (fail-loud). Opt-in is the "I have the canonical environment
  configured" claim; a broken environment is an error, not a non-issue.

The opt-in tests are named generically (``..._when_optional_extra_missing``)
rather than after a specific package: the contract is "any plain optional
import fails loud", NOT which extra happens to be imported first (import
sorting can reorder them — Z3 currently imports ``aiodocker`` first, Z4
imports ``hvac`` first). Both extras are shimmed so the first optional
import — whichever it is after sorting — raises.

Subprocess isolation is required because the parent test process has
already imported ``hvac`` / ``aiodocker`` / ``kubernetes_asyncio`` (they
ARE installed in this dev env). A ``sys.path`` shim injected at index 0
in the subprocess shadows the real packages with fake-raising stand-ins
WITHOUT contaminating the parent process's module cache. Unlike the Z3/Z4
modules themselves, these regressions need no live Vault / Docker / K8s —
they run in the normal CI suite.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

# Repo root — three parents up from tests/unit/<this file>. Used as the
# subprocess cwd so ``import tests.integration.sandbox....`` resolves
# (mirrors the Sprint-10 Z2 regression at
# tests/unit/test_z2_import_fail_loud_contract.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]

_Z3_MODULE = "tests.integration.sandbox.test_z3_docker_credential_projection"
_Z4_MODULE = "tests.integration.sandbox.test_z4_k8s_credential_projection"
_Z3_ENV_VAR = "COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_INTEGRATION"
_Z4_ENV_VAR = "COGNIC_RUN_K8S_CREDENTIAL_PROJECTION_INTEGRATION"


def _build_shim_dir(tmp_path: Path, module_names: list[str]) -> Path:
    """Create a ``sys.path``-shim directory whose ``<name>/__init__.py``
    raises ``ImportError`` on import, for each module name given.

    The shim is dropped FIRST on the subprocess's ``sys.path`` so it
    takes precedence over the real packages installed at the venv
    site-packages level. Parameterized over ``module_names`` so Z3 can
    shim ``aiodocker`` + ``hvac`` and Z4 can shim ``kubernetes_asyncio``
    + ``hvac`` — both extras shimmed so the FIRST optional import in the
    target module (whichever it is after import sorting) raises.
    """
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    for name in module_names:
        pkg = shim_dir / name
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            f"raise ImportError('Sprint 10.6 regression shim — {name} "
            f"intentionally unimportable to verify the Z3/Z4 fail-loud "
            f"import contract')",
            encoding="utf-8",
        )
    return shim_dir


def _run_opted_in(shim_dir: Path, *, module: str, env_var: str) -> subprocess.CompletedProcess[str]:
    """Spawn a subprocess that imports ``module`` WITH the env gate set +
    the shim active. Exit 7 + ``FAIL_LOUD_OK`` marker means the plain
    optional import raised ``ImportError`` (the desired fail-loud)."""
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(shim_dir)!r})
        try:
            import {module}  # noqa: F401
        except ImportError as e:
            print(f"FAIL_LOUD_OK: {{e}}", flush=True)
            sys.exit(7)
        print("SILENT_SKIP_BUG", flush=True)
        sys.exit(0)
        """
    )
    env = {**os.environ, env_var: "1"}
    return subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=60,
    )


def _run_opted_out(
    shim_dir: Path, *, module: str, env_var: str
) -> subprocess.CompletedProcess[str]:
    """Spawn a subprocess that imports ``module`` WITHOUT the env gate +
    the shim active. Exit 7 + ``CASUAL_SKIP_OK`` means the module-level
    ``pytest.skip`` fired BEFORE the (shimmed) optional imports. Exit 8 +
    ``UNEXPECTED_IMPORT_ERROR`` means an optional import ran before the
    skip gate — the import-ordering regression this test exists to catch."""
    script = textwrap.dedent(
        f"""
        import pytest
        import sys
        sys.path.insert(0, {str(shim_dir)!r})
        try:
            import {module}  # noqa: F401
        except pytest.skip.Exception:
            print("CASUAL_SKIP_OK", flush=True)
            sys.exit(7)
        except ImportError as e:
            print(f"UNEXPECTED_IMPORT_ERROR: {{e}}", flush=True)
            sys.exit(8)
        print("UNEXPECTED_OK", flush=True)
        sys.exit(0)
        """
    )
    env = {**os.environ}
    env.pop(env_var, None)
    return subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=60,
    )


class TestZ3ImportContract:
    """Z3 Docker live-proof module import contract (extras: aiodocker + hvac)."""

    def test_z3_opted_in_fails_loud_when_optional_extra_missing(self, tmp_path: Path) -> None:
        """Opt-in + a shimmed optional extra → the plain optional import
        raises ``ImportError`` at module load (NOT a silent skip).

        Both ``aiodocker`` + ``hvac`` are shimmed so the FIRST optional
        import in the module (whichever it is after import sorting)
        raises — the test does not depend on which extra is imported
        first.
        """
        shim_dir = _build_shim_dir(tmp_path, ["aiodocker", "hvac"])
        result = _run_opted_in(shim_dir, module=_Z3_MODULE, env_var=_Z3_ENV_VAR)
        assert result.returncode == 7, (
            f"Z3 module should fail loud (exit 7) when opted in + an "
            f"optional extra is missing per Sprint-10.1 ADR-004 §25 "
            f"amendment Finding #3; got exit {result.returncode}.\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        assert "FAIL_LOUD_OK" in result.stdout, (
            f"Subprocess did not emit FAIL_LOUD_OK; the Z3 module may have "
            f"used importorskip instead of a plain import in the opted-in "
            f"path. stdout={result.stdout!r}; stderr={result.stderr!r}"
        )

    def test_z3_opted_out_silent_skip_even_when_extras_missing(self, tmp_path: Path) -> None:
        """Opt-out → the module-level ``pytest.skip`` fires BEFORE any
        optional import, so the module skips even with both extras shimmed
        to raise. Exit 8 (``UNEXPECTED_IMPORT_ERROR``) would mean an
        optional import was hoisted above the skip gate — the regression
        this test pins."""
        shim_dir = _build_shim_dir(tmp_path, ["aiodocker", "hvac"])
        result = _run_opted_out(shim_dir, module=_Z3_MODULE, env_var=_Z3_ENV_VAR)
        assert result.returncode == 7, (
            f"Z3 module should silent-skip (exit 7) when NOT opted in, even "
            f"with extras shimmed — the env-gate skip must fire BEFORE the "
            f"optional imports; got exit {result.returncode}.\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        assert "CASUAL_SKIP_OK" in result.stdout, (
            f"Subprocess did not emit CASUAL_SKIP_OK; an optional import may "
            f"have run before the skip gate. stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )


class TestZ4ImportContract:
    """Z4 K8s live-proof module import contract (extras: kubernetes_asyncio + hvac).

    Identical contract shape as Z3; targets the K8s integration module +
    its env gate + the kubernetes_asyncio extra.
    """

    def test_z4_opted_in_fails_loud_when_optional_extra_missing(self, tmp_path: Path) -> None:
        """Opt-in + a shimmed optional extra → the plain optional import
        raises ``ImportError`` at module load (NOT a silent skip).

        Both ``kubernetes_asyncio`` + ``hvac`` are shimmed so the FIRST
        optional import in the module (whichever it is after import
        sorting) raises."""
        shim_dir = _build_shim_dir(tmp_path, ["kubernetes_asyncio", "hvac"])
        result = _run_opted_in(shim_dir, module=_Z4_MODULE, env_var=_Z4_ENV_VAR)
        assert result.returncode == 7, (
            f"Z4 module should fail loud (exit 7) when opted in + an "
            f"optional extra is missing per Sprint-10.1 ADR-004 §25 "
            f"amendment Finding #3; got exit {result.returncode}.\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        assert "FAIL_LOUD_OK" in result.stdout, (
            f"Subprocess did not emit FAIL_LOUD_OK; the Z4 module may have "
            f"used importorskip instead of a plain import in the opted-in "
            f"path. stdout={result.stdout!r}; stderr={result.stderr!r}"
        )

    def test_z4_opted_out_silent_skip_even_when_extras_missing(self, tmp_path: Path) -> None:
        """Opt-out → the module-level ``pytest.skip`` fires BEFORE any
        optional import, so the module skips even with both extras shimmed
        to raise. Exit 8 (``UNEXPECTED_IMPORT_ERROR``) would mean an
        optional import was hoisted above the skip gate."""
        shim_dir = _build_shim_dir(tmp_path, ["kubernetes_asyncio", "hvac"])
        result = _run_opted_out(shim_dir, module=_Z4_MODULE, env_var=_Z4_ENV_VAR)
        assert result.returncode == 7, (
            f"Z4 module should silent-skip (exit 7) when NOT opted in, even "
            f"with extras shimmed — the env-gate skip must fire BEFORE the "
            f"optional imports; got exit {result.returncode}.\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        assert "CASUAL_SKIP_OK" in result.stdout, (
            f"Subprocess did not emit CASUAL_SKIP_OK; an optional import may "
            f"have run before the skip gate. stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
