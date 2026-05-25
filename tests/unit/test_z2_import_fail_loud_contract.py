"""Sprint 10.1 finding #3 — Z2 importorskip fail-loud contract regression.

Pins the spec §10 "opt-in means prove it or fail" contract per the
Sprint-10.1 ADR-004 §25 amendment finding #3 fix. Pre-Sprint-10.1, the
Z2 module at
``tests/integration/sandbox/test_real_vault_credential_lifecycle.py``
called ``pytest.importorskip("hvac")`` + ``pytest.importorskip("aiodocker")``
at module load (lines 140-141), BEFORE the ``pytestmark`` env-gate at
line 163. If an operator opted in via ``COGNIC_RUN_VAULT_INTEGRATION=1``
but the extras were missing, pytest reported "skipped" rather than
failing loud — undercutting the spec §10 contract.

Sprint 10.1 fix: the Z2 module's import preamble flips to a
conditional branch — when ``COGNIC_RUN_VAULT_INTEGRATION=1`` is set,
plain ``import`` (not ``importorskip``) is used so missing extras
raise ``ImportError`` at module load → pytest reports a collection
error (fail-loud). When the env var is unset, the silent-skip path
via ``importorskip`` is preserved for casual local-only
``uv run pytest`` invocations.

Two regressions in this file, mirroring the reviewer's verification
method for Finding 3:

1. **Opted-in + extras missing → fail-loud.** Spawn a subprocess with
   ``COGNIC_RUN_VAULT_INTEGRATION=1`` + a ``sys.path`` shim that makes
   ``hvac`` raise ``ImportError`` on import; attempt to import the Z2
   module; assert the subprocess exits non-zero (ImportError caught
   + reported via the structured ``FAIL_LOUD_OK`` marker).

2. **Not-opted-in + extras missing → silent skip (preserved).** Same
   subprocess shim WITHOUT the env var set; assert the subprocess
   exits with ``pytest.skip.Exception`` (the existing
   ``importorskip`` behaviour, preserved for casual local runs).

Together these pin both halves of the contract: opt-in must produce a
clear ImportError, casual runs must produce the standard pytest skip.

Subprocess isolation is required because the parent test process has
already imported ``hvac`` / ``aiodocker`` (they ARE installed in this
dev env). ``sys.path`` injection via subprocess argv shadows the real
modules with a fake-raising stand-in WITHOUT contaminating the parent
process's module cache.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


def _build_shim_dir(tmp_path: Path) -> Path:
    """Create a sys.path-shim directory whose ``hvac/__init__.py``
    raises ``ImportError`` on import. Used by both regressions below.

    The shim is dropped FIRST on the subprocess's sys.path so it
    takes precedence over the real ``hvac`` package installed at the
    venv site-packages level.
    """
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    fake_hvac = shim_dir / "hvac"
    fake_hvac.mkdir()
    (fake_hvac / "__init__.py").write_text(
        "raise ImportError('Sprint 10.1 finding #3 regression shim — "
        "this hvac module is intentionally unimportable to verify the "
        "Z2 fail-loud contract')",
        encoding="utf-8",
    )
    return shim_dir


def test_z2_module_load_fails_loud_when_opted_in_and_extra_missing(
    tmp_path: Path,
) -> None:
    """Sprint 10.1 finding #3 — opt-in path: when
    ``COGNIC_RUN_VAULT_INTEGRATION=1`` is set + ``hvac`` is
    unimportable, the Z2 module MUST raise ``ImportError`` at module
    load (NOT silently skip via ``pytest.importorskip``).

    Subprocess shim injects a fake ``hvac`` that raises ImportError;
    parent process's already-loaded ``hvac`` is shadowed inside the
    subprocess via ``sys.path.insert(0, ...)``.
    """
    shim_dir = _build_shim_dir(tmp_path)
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(shim_dir)!r})
        try:
            import tests.integration.sandbox.test_real_vault_credential_lifecycle  # noqa: F401
        except ImportError as e:
            print(f"FAIL_LOUD_OK: {{e}}", flush=True)
            sys.exit(7)
        print("SILENT_SKIP_BUG", flush=True)
        sys.exit(0)
        """
    )
    env = {**os.environ, "COGNIC_RUN_VAULT_INTEGRATION": "1"}
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
        timeout=60,
    )
    assert result.returncode == 7, (
        f"Z2 module should fail loud (exit 7) when opted in + extra "
        f"missing per Sprint-10.1 ADR-004 §25 amendment finding #3 "
        f"fix; got exit {result.returncode}.\n"
        f"stdout={result.stdout!r}\n"
        f"stderr={result.stderr!r}"
    )
    assert "FAIL_LOUD_OK" in result.stdout, (
        f"Subprocess did not emit the FAIL_LOUD_OK marker; the Z2 "
        f"module may have used importorskip instead of plain import "
        f"in the opted-in branch. stdout={result.stdout!r}; "
        f"stderr={result.stderr!r}"
    )


def test_z2_module_load_skips_silent_when_not_opted_in_and_extra_missing(
    tmp_path: Path,
) -> None:
    """Sprint 10.1 finding #3 — casual-run path: when
    ``COGNIC_RUN_VAULT_INTEGRATION`` is unset/empty, the importorskip
    silent-skip path MUST still work so casual local-only
    ``uv run pytest`` runs don't break on missing optional extras.
    """
    shim_dir = _build_shim_dir(tmp_path)
    # Need pytest in the subprocess to catch importorskip's
    # ``pytest.skip.Exception`` type.
    script = textwrap.dedent(
        f"""
        import pytest
        import sys
        sys.path.insert(0, {str(shim_dir)!r})
        try:
            import tests.integration.sandbox.test_real_vault_credential_lifecycle  # noqa: F401
        except pytest.skip.Exception:  # importorskip raises this
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
    env.pop("COGNIC_RUN_VAULT_INTEGRATION", None)
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
        timeout=60,
    )
    assert result.returncode == 7, (
        f"Z2 module should silent-skip on casual runs (no env var) "
        f"per spec §10; got exit {result.returncode}.\n"
        f"stdout={result.stdout!r}\n"
        f"stderr={result.stderr!r}"
    )
    assert "CASUAL_SKIP_OK" in result.stdout, (
        f"Subprocess did not emit the CASUAL_SKIP_OK marker; the Z2 "
        f"module may have lost the importorskip fallback in the "
        f"not-opted-in branch. stdout={result.stdout!r}; "
        f"stderr={result.stderr!r}"
    )
