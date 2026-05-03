"""Sprint-5 T6.1 — `protocol.mcp_manifest.extract_pack_manifest` contract tests.

Critical-controls module per AGENTS.md (Plugin trust + supply chain —
manifest extraction is the registry's only read of pack-controlled
TOML at admission, so its deferred-load invariant + missing/malformed
behaviour are load-bearing).

Test classes (per Sprint-5 plan §T6.1):

  TestExtractFromEditableInstall      — happy path on editable install
  TestExtractFromWheelInstall         — happy path on wheel install
  TestExtractMissingManifest          — pack ships no manifest → PackManifestNotFoundError
  TestExtractMalformedManifest        — manifest with invalid TOML → PackManifestMalformedError
  TestExtractDoesNotImportPackage     — deferred-load invariant: __init__.py NEVER executes
  TestExtractAcrossBothInstallModes   — same source → identical manifest dict for editable vs wheel

Most tests use a ``_FakeDistribution`` stub (Sprint-4 pattern in
test_plugin_registry.py) so the unit suite stays fast and doesn't
shell out to ``uv pip install``. The cross-install-mode equivalence
test exercises the contract that ``Distribution.locate_file()`` is
the resolution mechanism and so editable + wheel return the same
file content; we drive that with two stubs whose ``locate_file()``
points at distinct on-disk paths but same bytes.
"""

from __future__ import annotations

import importlib.metadata as _im
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.protocol.mcp_manifest import (
    MCPManifestError,
    PackManifestMalformedError,
    PackManifestNotFoundError,
    extract_pack_manifest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CANONICAL_MANIFEST_BYTES = (
    b"[tool.cognic.identity]\n"
    b'pack_id = "cognic-test-mcp-pack"\n'
    b'pack_version = "0.1.0"\n'
    b"\n"
    b"[tool.cognic.mcp]\n"
    b'transport = "http"\n'
    b'auth = "oauth-prm"\n'
    b'server_url = "https://server.example/mcp"\n'
    b'scopes = ["mcp:tools"]\n'
)


class _FakeDistribution:
    """Stand-in for ``importlib.metadata.Distribution``.

    Real ``Distribution`` objects expose ``locate_file(relative)``
    which returns a filesystem path WITHOUT importing the package.
    The stub mirrors that surface and lets each test direct the
    extractor at a controlled tmp_path location.
    """

    def __init__(self, file_map: dict[str, Path | None]) -> None:
        # Map of relative path within the dist → resolved Path on
        # disk (or None to simulate "file not declared by RECORD").
        self._file_map = file_map

    def locate_file(self, relative: str) -> Path | None:
        return self._file_map.get(relative)


def _patch_distribution(
    monkeypatch: pytest.MonkeyPatch,
    *,
    distribution_name: str,
    file_map: dict[str, Path | None] | None = None,
    raise_not_found: bool = False,
) -> None:
    """Monkeypatch ``importlib.metadata.distribution`` to return a
    ``_FakeDistribution``.

    Importing ``mcp_manifest`` binds ``importlib.metadata.distribution``
    at module load time via the ``import importlib.metadata`` statement;
    we patch the lookup point ``importlib.metadata.distribution`` so the
    extractor's ``importlib.metadata.distribution(...)`` call sees the
    fake.
    """
    if raise_not_found:

        def _raise(_name: str) -> Any:
            raise _im.PackageNotFoundError(distribution_name)

        monkeypatch.setattr(_im, "distribution", _raise)
        return

    fake = _FakeDistribution(file_map or {})

    def _get(name: str) -> _FakeDistribution:
        assert name == distribution_name, (
            f"Test setup error: extractor asked for {name!r} but the fake "
            f"was registered under {distribution_name!r}."
        )
        return fake

    monkeypatch.setattr(_im, "distribution", _get)


# ---------------------------------------------------------------------------
# Happy paths — editable + wheel install modes
# ---------------------------------------------------------------------------


class TestExtractFromEditableInstall:
    """Editable installs (``uv pip install -e``) leave the package
    source on disk at the developer's checkout path; ``locate_file()``
    returns a path under the source tree."""

    def test_returns_parsed_manifest_dict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Simulate an editable install: the manifest file lives at the
        # developer's checkout path under tmp_path.
        manifest_path = tmp_path / "src" / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(_CANONICAL_MANIFEST_BYTES)
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": manifest_path},
        )

        result = extract_pack_manifest(
            distribution_name="cognic-test-mcp-pack",
            package_name="cognic_test_mcp_pack",
        )

        assert result["tool"]["cognic"]["identity"]["pack_id"] == "cognic-test-mcp-pack"
        assert result["tool"]["cognic"]["mcp"]["transport"] == "http"
        assert result["tool"]["cognic"]["mcp"]["auth"] == "oauth-prm"
        assert result["tool"]["cognic"]["mcp"]["scopes"] == ["mcp:tools"]


class TestExtractFromWheelInstall:
    """Wheel installs put the package in site-packages; the manifest
    is at ``<site-packages>/<package>/cognic-pack-manifest.toml``.
    The extractor reads identical content."""

    def test_returns_parsed_manifest_dict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Simulate a wheel install: the manifest is under a fake
        # site-packages directory.
        manifest_path = (
            tmp_path / "site-packages" / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        )
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(_CANONICAL_MANIFEST_BYTES)
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": manifest_path},
        )

        result = extract_pack_manifest(
            distribution_name="cognic-test-mcp-pack",
            package_name="cognic_test_mcp_pack",
        )

        assert result["tool"]["cognic"]["mcp"]["server_url"] == "https://server.example/mcp"


# ---------------------------------------------------------------------------
# Negative paths — missing / malformed
# ---------------------------------------------------------------------------


class TestExtractMissingManifest:
    """A pack that doesn't ship the manifest file MUST surface as a
    closed-typed :class:`PackManifestNotFoundError` from the
    extractor.

    The **registry's reaction** to that exception is a separate
    concern (see ``test_mcp_registration_auth_probe.py``'s
    ``TestAuthProbeManifestMissingProceeds`` — current T6 doctrine
    is that the registry treats the exception as "no MCP intent"
    and proceeds; the closed-enum ``mcp_manifest_missing`` literal
    is reserved for a future explicit MCP-intent path). These
    extractor tests validate ONLY that the exception fires for each
    of the three structural paths below — not what the registry
    chooses to do about it."""

    def test_distribution_not_installed_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``importlib.metadata.distribution`` raises ``PackageNotFoundError``
        for an uninstalled name → the extractor MUST fail closed."""
        _patch_distribution(
            monkeypatch,
            distribution_name="not-installed-pack",
            raise_not_found=True,
        )

        with pytest.raises(PackManifestNotFoundError) as exc:
            extract_pack_manifest(
                distribution_name="not-installed-pack",
                package_name="not_installed_pack",
            )
        assert "not-installed-pack" in str(exc.value)

    def test_locate_file_returns_none_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Distribution exists but RECORD/installed-files does not list
        the manifest path → ``locate_file`` returns ``None``."""
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": None},
        )

        with pytest.raises(PackManifestNotFoundError) as exc:
            extract_pack_manifest(
                distribution_name="cognic-test-mcp-pack",
                package_name="cognic_test_mcp_pack",
            )
        # Operator-relevant: the message names BOTH the distribution
        # and the expected manifest relative path so they can debug
        # which `[tool.hatch.build.targets.wheel.force-include]` line
        # is missing in the pack's pyproject.
        assert "cognic-test-mcp-pack" in str(exc.value)
        assert "cognic-pack-manifest.toml" in str(exc.value)

    def test_locate_file_returns_path_but_file_does_not_exist_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """RECORD claims the file exists but it doesn't on disk
        (corrupted install, partial wheel extraction) → fail closed."""
        nonexistent = tmp_path / "ghost" / "cognic-pack-manifest.toml"
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": nonexistent},
        )

        with pytest.raises(PackManifestNotFoundError):
            extract_pack_manifest(
                distribution_name="cognic-test-mcp-pack",
                package_name="cognic_test_mcp_pack",
            )


class TestExtractMalformedManifest:
    """Invalid TOML → closed-typed error (mapped at the registry
    boundary to ``mcp_manifest_malformed`` refusal)."""

    def test_invalid_toml_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        manifest_path = tmp_path / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(
            "this is not valid TOML = = = oops",
            encoding="utf-8",
        )
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": manifest_path},
        )

        with pytest.raises(PackManifestMalformedError) as exc:
            extract_pack_manifest(
                distribution_name="cognic-test-mcp-pack",
                package_name="cognic_test_mcp_pack",
            )
        assert "cognic-test-mcp-pack" in str(exc.value)

    def test_empty_file_parses_to_empty_dict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An empty manifest is valid TOML (parses to ``{}``). Whether
        that's semantically valid is the capability validator's job —
        T6.1 only worries about extraction. This test pins that
        empty-but-valid TOML does NOT raise here."""
        manifest_path = tmp_path / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(b"")
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": manifest_path},
        )

        result = extract_pack_manifest(
            distribution_name="cognic-test-mcp-pack",
            package_name="cognic_test_mcp_pack",
        )
        assert result == {}


# ---------------------------------------------------------------------------
# Deferred-load invariant — the load-bearing contract
# ---------------------------------------------------------------------------


class TestExtractDoesNotImportPackage:
    """Per Sprint-4 deferred-load doctrine + ADR-002 §"MCP STDIO
    threat model" gate 1: ``extract_pack_manifest`` MUST resolve
    ``cognic-pack-manifest.toml`` via ``Distribution.locate_file()``
    WITHOUT importing the pack package code. If it ever regresses to
    using ``importlib.resources.files()`` (which can trigger
    ``__init__.py`` execution as a side effect), this test catches it.

    Strategy: install a fixture pack whose ``__init__.py`` raises
    ``AssertionError`` on import. Run the extractor against it. If
    the extractor regresses to importing, the assertion fires and
    pytest reports the failure with a pointer at the regression.
    """

    def test_extractor_does_not_trigger_init_py(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Stub-driven invariant test: the fake distribution's
        ``locate_file`` is the only access path. If the extractor
        secretly tried to import the package, it would call
        ``importlib.import_module`` which the stub does NOT implement
        — and the import-poisoned ``__init__.py`` in the on-disk
        fixture would raise. We monkeypatch ``importlib.import_module``
        to fail loudly on any attempt so a regression is caught even
        without the fixture pack actually installed.
        """
        manifest_path = tmp_path / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(_CANONICAL_MANIFEST_BYTES)
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": manifest_path},
        )

        import importlib

        def _raise_on_import(name: str, *args: Any, **kw: Any) -> Any:
            if name.startswith("cognic_test_mcp_pack"):
                raise AssertionError(
                    f"Deferred-load invariant violated: extractor tried to "
                    f"importlib.import_module({name!r}). Use Distribution."
                    f"locate_file() instead."
                )
            return importlib.__import__(name, *args, **kw)

        monkeypatch.setattr(importlib, "import_module", _raise_on_import)

        # Should succeed without triggering the import_module poison.
        result = extract_pack_manifest(
            distribution_name="cognic-test-mcp-pack",
            package_name="cognic_test_mcp_pack",
        )
        assert result["tool"]["cognic"]["identity"]["pack_id"] == "cognic-test-mcp-pack"

    def test_fixture_pack_init_remains_poisoned(self) -> None:
        """Pin that the on-disk fixture pack's ``__init__.py`` is the
        intended import-poisoned variant. If a future refactor
        accidentally makes the fixture importable, the deferred-load
        test above loses its safety net (the extractor could regress
        to using ``importlib.resources.files()`` and the test wouldn't
        notice). This is a metaprogramming guard on the fixture itself.
        """
        fixture_init = (
            Path(__file__).parent.parent.parent
            / "fixtures"
            / "cognic_test_mcp_pack"
            / "cognic_test_mcp_pack"
            / "__init__.py"
        )
        contents = fixture_init.read_text(encoding="utf-8")
        assert "raise AssertionError" in contents, (
            "tests/fixtures/cognic_test_mcp_pack/cognic_test_mcp_pack/__init__.py "
            "must remain import-poisoned (raise AssertionError on import) so the "
            "deferred-load invariant test has a safety net. T12 will move the "
            "poison to a dedicated isolated fixture when the real MCP server "
            "module lands; until then it lives here."
        )


# ---------------------------------------------------------------------------
# Cross-install-mode equivalence
# ---------------------------------------------------------------------------


class TestExtractAcrossBothInstallModes:
    """Same fixture pack source → identical parsed manifest dict
    whether installed editable or as wheel. Sprint 4 doctrine: the
    install-mode shouldn't change registry behaviour."""

    def test_editable_and_wheel_paths_yield_identical_dict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Two locations, identical bytes — simulates editable install
        # at one path and wheel install at another.
        editable_path = (
            tmp_path / "checkout" / "src" / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        )
        wheel_path = (
            tmp_path / "site-packages" / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"
        )
        for p in (editable_path, wheel_path):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(_CANONICAL_MANIFEST_BYTES)

        # First call: editable
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": editable_path},
        )
        editable_result = extract_pack_manifest(
            distribution_name="cognic-test-mcp-pack",
            package_name="cognic_test_mcp_pack",
        )

        # Second call: wheel
        _patch_distribution(
            monkeypatch,
            distribution_name="cognic-test-mcp-pack",
            file_map={"cognic_test_mcp_pack/cognic-pack-manifest.toml": wheel_path},
        )
        wheel_result = extract_pack_manifest(
            distribution_name="cognic-test-mcp-pack",
            package_name="cognic_test_mcp_pack",
        )

        assert editable_result == wheel_result
        assert editable_result["tool"]["cognic"]["identity"]["pack_id"] == ("cognic-test-mcp-pack")


# ---------------------------------------------------------------------------
# Closed exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Both leaf exceptions inherit from ``MCPManifestError`` so a
    single ``except`` at the registry boundary can catch the whole
    extraction surface. The two leaves are MEANINGFULLY DISTINCT
    extractor outcomes; the registry's reaction to each is a
    separate concern (see the module docstring of
    ``protocol.mcp_manifest`` for the extractor-vs-registry
    semantic split). Today's T6 admission contract: the malformed
    leaf maps to closed-enum ``mcp_manifest_malformed`` at the
    registry, while the not-found leaf is treated as "no MCP
    intent" and proceeds — ``mcp_manifest_missing`` is reserved
    for a future explicit MCP-intent path."""

    def test_not_found_inherits_from_base(self) -> None:
        assert issubclass(PackManifestNotFoundError, MCPManifestError)

    def test_malformed_inherits_from_base(self) -> None:
        assert issubclass(PackManifestMalformedError, MCPManifestError)

    def test_base_is_an_exception(self) -> None:
        assert issubclass(MCPManifestError, Exception)


# ---------------------------------------------------------------------------
# Sprint-5 T6 R1 #3 — REAL editable + wheel install proofs
#
# The unit tests above use a ``_FakeDistribution`` stub for speed, but
# the load-bearing T6.1 contract is that the fixture pack's pyproject
# actually packages ``cognic-pack-manifest.toml`` AS PACKAGE DATA AND
# that ``Distribution.locate_file()`` resolves it on a real install
# without importing pack code. The stubs above can pass even if the
# pyproject is mis-configured. The tests below build the fixture as a
# real wheel and then walk it to prove the packaging contract holds.
# ---------------------------------------------------------------------------


class TestRealWheelBuildIncludesManifest:
    """Build the fixture pack as a real wheel + open the resulting
    ``.whl`` ZIP to verify the manifest is included AS PACKAGE DATA.
    This catches the class of bug where someone refactors the fixture
    or the ``[tool.hatch.build.targets.wheel.force-include]`` line
    drops out — the unit tests above would still pass because they
    use a stub Distribution, but a real install would 404 on
    ``Distribution.locate_file()``."""

    def test_built_wheel_contains_manifest_at_canonical_path(self, tmp_path: Path) -> None:
        """Build the wheel via ``uv build``; assert the wheel ZIP
        contains ``cognic_test_mcp_pack/cognic-pack-manifest.toml``."""
        import subprocess
        import zipfile

        repo_root = Path(__file__).resolve().parents[3]
        fixture = repo_root / "tests" / "fixtures" / "cognic_test_mcp_pack"
        # Build into a tmp dir so we don't pollute the fixture's
        # source tree.
        result = subprocess.run(
            [
                "uv",
                "build",
                "--wheel",
                str(fixture),
                "--out-dir",
                str(tmp_path),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0, (
            f"uv build failed:\n  stdout={result.stdout}\n  stderr={result.stderr}"
        )
        # Find the wheel; pattern is e.g.
        # ``cognic_test_mcp_pack-0.1.0-py3-none-any.whl``.
        wheels = sorted(tmp_path.glob("*.whl"))
        assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
        wheel = wheels[0]

        with zipfile.ZipFile(wheel) as zf:
            names = set(zf.namelist())
            manifest_path = "cognic_test_mcp_pack/cognic-pack-manifest.toml"
            assert manifest_path in names, (
                f"wheel does not contain {manifest_path!r}; pyproject's "
                f"[tool.hatch.build.targets.wheel.force-include] is "
                f"misconfigured. Wheel members: {sorted(names)}"
            )
            # Read + parse to make sure the bytes are intact (TOML
            # decoder doesn't crash). The unit tests above pin the
            # contents; this just verifies they survive packaging.
            manifest_bytes = zf.read(manifest_path)
            assert b"[tool.cognic.identity]" in manifest_bytes
            assert b"[tool.cognic.mcp]" in manifest_bytes


class TestRealEditableInstallExtractsManifest:
    """End-to-end proof: install the fixture pack EDITABLE into an
    isolated venv (so we don't pollute the test process) and then
    invoke ``extract_pack_manifest`` against it via a subprocess
    Python in that venv. Proves the full extraction contract —
    pyproject + force-include + Distribution.locate_file() — works
    on a real install.

    Skipped automatically if ``uv`` is not on PATH (CI image
    constraint); marker keeps the test optional in time-pressured
    suites since it shells out twice (venv + install + extract).
    """

    @pytest.mark.skipif(
        __import__("shutil").which("uv") is None,
        reason="uv binary not on PATH — required to create isolated venv + install",
    )
    def test_editable_install_resolves_manifest_via_locate_file(self, tmp_path: Path) -> None:
        """Create venv → editable-install fixture → run extractor in
        a subprocess in the venv → assert the manifest dict came back
        intact. The subprocess Python is the venv's python (not the
        test process's), so ``importlib.metadata.distribution`` walks
        the venv's site-packages, NOT the test process's."""
        import json
        import subprocess

        repo_root = Path(__file__).resolve().parents[3]
        fixture = repo_root / "tests" / "fixtures" / "cognic_test_mcp_pack"
        venv = tmp_path / "venv"

        # Step 1: create a clean isolated venv.
        subprocess.run(
            ["uv", "venv", str(venv)],
            capture_output=True,
            check=True,
            text=True,
        )

        # Step 2: editable-install the fixture pack into that venv.
        # ``--python`` directs uv at the venv's Python.
        venv_python = venv / "bin" / "python"
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(venv_python),
                "-e",
                str(fixture),
            ],
            capture_output=True,
            check=True,
            text=True,
        )

        # Step 3: in that venv's Python, run the extractor end-to-end.
        # The extractor lives in the test repo's source, so we add
        # the test repo's src/ to sys.path BEFORE invoking it. Use
        # JSON for the result so the subprocess boundary is clean.
        src_path = repo_root / "src"
        script = f"""
import json
import sys
sys.path.insert(0, {str(src_path)!r})
from cognic_agentos.protocol.mcp_manifest import extract_pack_manifest
manifest = extract_pack_manifest(
    distribution_name="cognic-test-mcp-pack",
    package_name="cognic_test_mcp_pack",
)
print(json.dumps(manifest))
"""
        result = subprocess.run(
            [str(venv_python), "-c", script],
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0, (
            f"extractor failed in venv subprocess:\n"
            f"  stdout={result.stdout}\n"
            f"  stderr={result.stderr}"
        )
        manifest = json.loads(result.stdout.strip())
        assert manifest["tool"]["cognic"]["identity"]["pack_id"] == ("cognic-test-mcp-pack")
        assert manifest["tool"]["cognic"]["mcp"]["transport"] == "http"
        assert manifest["tool"]["cognic"]["mcp"]["auth"] == "oauth-prm"

        # Defensive: confirm the import-poisoned __init__.py was
        # NOT triggered. If extract_pack_manifest had regressed to
        # using importlib.resources.files(), the venv's import of
        # cognic_test_mcp_pack.__init__ would have raised the
        # AssertionError "MUST NOT be executed by the manifest
        # extractor" — which would have surfaced as a non-zero
        # subprocess return code (caught above).
        assert "MUST NOT be executed" not in result.stderr
