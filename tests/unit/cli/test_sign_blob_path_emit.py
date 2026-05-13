"""Sprint 7B.3 T2 Slice F — ``agentos sign --bundle-root`` regression tests
for the bundle-root-relative ``[supply_chain].blob_path`` emission per
R5 P2 #2 + R6 P2 #4 + R7 P2 #4 contract.

Tests exercise the three new pure-functional helpers introduced in
``cli/sign.py`` so the unit scope stays small (the full
:func:`run_sign_bundle` orchestrator integration is covered by the
existing T14.B end-to-end shim tests; this file pins the new helpers
directly).

Helpers under test:

- :func:`_resolve_bundle_root` — canonicalises both the explicit
  ``--bundle-root`` flag value (when provided) and the implicit default
  (``Path(wheel).parent.resolve()``) via ``Path.resolve()``. Returns
  the canonical absolute :class:`pathlib.Path`.
- :func:`_compute_bundle_root_relative_blob_path` — validates the
  resolved wheel path is a descendant of the resolved bundle root +
  returns the POSIX-style forward-slash relative path via
  :meth:`Path.relative_to` + :meth:`Path.as_posix`. Raises
  :class:`ValueError` when the wheel is outside the root.
- :func:`_write_blob_path_to_manifest` — round-trip-safe TOML mutation
  via stdlib ``tomllib`` (read) + ``tomli_w`` (write). Inserts or
  updates the ``[supply_chain].blob_path`` key; preserves every other
  field in the manifest. Idempotent (running twice with the same value
  produces the same on-disk bytes).

R10 LOCK: signature gate is non-overridable per ADR-012 §110, so the
manifest field MUST be wired automatically — author drift would brick
every approve. Hence the write-back is mandatory rather than an info-
level finding.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

# ===========================================================================
# Section A — _resolve_bundle_root helper
# ===========================================================================


class TestSprint7B3T2SliceFResolveBundleRoot:
    """Bundle-root resolution: default (wheel parent) or explicit flag."""

    def test_default_resolves_to_wheel_parent(self, tmp_path: Path) -> None:
        """No ``--bundle-root`` flag → defaults to ``Path(wheel).parent.resolve()``."""
        from cognic_agentos.cli.sign import _resolve_bundle_root

        wheel = tmp_path / "dist" / "x-1.0.0-py3-none-any.whl"
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b"fake wheel")

        result = _resolve_bundle_root(wheel_path=wheel, bundle_root_override=None)

        assert result == wheel.parent.resolve()

    def test_explicit_override_takes_precedence(self, tmp_path: Path) -> None:
        """Explicit ``--bundle-root`` overrides the default."""
        from cognic_agentos.cli.sign import _resolve_bundle_root

        wheel = tmp_path / "build" / "dist" / "x.whl"
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b"fake wheel")
        bundle_root = tmp_path / "build"

        result = _resolve_bundle_root(wheel_path=wheel, bundle_root_override=bundle_root)

        assert result == bundle_root.resolve()

    def test_canonicalises_via_resolve(self, tmp_path: Path) -> None:
        """Path.resolve() canonicalises symlinks / relative components so the
        relative-to computation operates on a stable absolute path."""
        from cognic_agentos.cli.sign import _resolve_bundle_root

        actual = tmp_path / "real"
        actual.mkdir()
        wheel = actual / "x.whl"
        wheel.write_bytes(b"fake")
        # Provide a non-canonical input (e.g. with redundant /. components).
        non_canonical = tmp_path / "real" / "."

        result = _resolve_bundle_root(wheel_path=wheel, bundle_root_override=non_canonical)

        assert result == actual.resolve()
        assert ".." not in result.parts


# ===========================================================================
# Section B — _compute_bundle_root_relative_blob_path
# ===========================================================================


class TestSprint7B3T2SliceFComputeBundleRootRelativeBlobPath:
    """Bundle-root-relative POSIX blob_path computation + outside-root refusal."""

    def test_wheel_directly_in_bundle_root(self, tmp_path: Path) -> None:
        """Wheel co-located with bundle root → blob_path is just the
        wheel filename."""
        from cognic_agentos.cli.sign import (
            _compute_bundle_root_relative_blob_path,
        )

        bundle_root = tmp_path
        wheel = bundle_root / "example-1.0.0-py3-none-any.whl"
        wheel.write_bytes(b"fake")

        result = _compute_bundle_root_relative_blob_path(
            wheel_path=wheel, bundle_root=bundle_root.resolve()
        )

        assert result == "example-1.0.0-py3-none-any.whl"

    def test_wheel_nested_under_bundle_root(self, tmp_path: Path) -> None:
        """Wheel under a subdirectory of bundle root → POSIX nested
        relative path."""
        from cognic_agentos.cli.sign import (
            _compute_bundle_root_relative_blob_path,
        )

        bundle_root = tmp_path / "pack-bundle"
        wheel = bundle_root / "dist" / "example-1.0.0-py3-none-any.whl"
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b"fake")

        result = _compute_bundle_root_relative_blob_path(
            wheel_path=wheel, bundle_root=bundle_root.resolve()
        )

        # POSIX-style forward slashes for cross-platform manifest portability.
        assert result == "dist/example-1.0.0-py3-none-any.whl"
        # Never windows-style backslashes even on Windows tests (POSIX
        # invariant is wire-protocol-public for the manifest field).
        assert "\\" not in result

    def test_wheel_outside_bundle_root_raises(self, tmp_path: Path) -> None:
        """Wheel NOT a descendant of bundle root → ValueError. The CLI
        translates this into the ``sign_wheel_outside_bundle_root`` SignFinding."""
        from cognic_agentos.cli.sign import (
            _compute_bundle_root_relative_blob_path,
        )

        bundle_root = tmp_path / "inside"
        bundle_root.mkdir()
        outside_wheel = tmp_path / "outside" / "stray.whl"
        outside_wheel.parent.mkdir()
        outside_wheel.write_bytes(b"fake")

        with pytest.raises(ValueError) as exc:
            _compute_bundle_root_relative_blob_path(
                wheel_path=outside_wheel, bundle_root=bundle_root.resolve()
            )
        # Surface the offending paths for operator-facing diagnostics.
        msg = str(exc.value)
        assert "outside" in msg or "not relative" in msg.lower() or "not under" in msg.lower()


# ===========================================================================
# Section C — _write_blob_path_to_manifest (tomllib + tomli_w round-trip)
# ===========================================================================


class TestSprint7B3T2SliceFWriteBlobPathToManifest:
    """Manifest mutation: inserts/updates ``[supply_chain].blob_path``
    via tomllib (read) + tomli_w (write); preserves every other field;
    idempotent on re-run."""

    def test_inserts_blob_path_into_existing_supply_chain_block(self, tmp_path: Path) -> None:
        """Existing ``[supply_chain]`` block with ``attestation_paths`` gains
        a new ``blob_path = "..."`` line; other keys preserved verbatim."""
        from cognic_agentos.cli.sign import _write_blob_path_to_manifest

        manifest = tmp_path / "cognic-pack-manifest.toml"
        manifest.write_text(
            "[pack]\n"
            'name = "example"\n'
            'version = "1.0.0"\n'
            'kind = "tool"\n'
            "\n"
            "[supply_chain]\n"
            'attestation_paths = ["attestations/cosign.sig"]\n'
        )

        _write_blob_path_to_manifest(
            manifest_path=manifest, blob_path="dist/example-1.0.0-py3-none-any.whl"
        )

        # Round-trip through tomllib to confirm the field was inserted
        # AND the existing fields are preserved.
        data: dict[str, Any] = tomllib.loads(manifest.read_text())
        assert data["pack"]["name"] == "example"
        assert data["pack"]["version"] == "1.0.0"
        assert data["pack"]["kind"] == "tool"
        assert data["supply_chain"]["attestation_paths"] == ["attestations/cosign.sig"]
        assert data["supply_chain"]["blob_path"] == "dist/example-1.0.0-py3-none-any.whl"

    def test_creates_supply_chain_block_when_missing(self, tmp_path: Path) -> None:
        """Manifest with no ``[supply_chain]`` block at all → block is
        created + ``blob_path`` inserted."""
        from cognic_agentos.cli.sign import _write_blob_path_to_manifest

        manifest = tmp_path / "cognic-pack-manifest.toml"
        manifest.write_text('[pack]\nname = "minimal"\nversion = "0.1"\nkind = "tool"\n')

        _write_blob_path_to_manifest(manifest_path=manifest, blob_path="minimal.whl")

        data: dict[str, Any] = tomllib.loads(manifest.read_text())
        assert data["pack"]["name"] == "minimal"
        assert data["supply_chain"]["blob_path"] == "minimal.whl"

    def test_idempotent_on_re_run_same_value(self, tmp_path: Path) -> None:
        """Running the writer twice with the same value → same on-disk bytes.
        Pins the no-author-drift invariant: re-signing produces a stable
        manifest."""
        from cognic_agentos.cli.sign import _write_blob_path_to_manifest

        manifest = tmp_path / "cognic-pack-manifest.toml"
        manifest.write_text('[pack]\nname = "x"\nversion = "1"\nkind = "tool"\n')

        _write_blob_path_to_manifest(manifest_path=manifest, blob_path="dist/x-1.whl")
        bytes_after_first = manifest.read_bytes()

        _write_blob_path_to_manifest(manifest_path=manifest, blob_path="dist/x-1.whl")
        bytes_after_second = manifest.read_bytes()

        assert bytes_after_first == bytes_after_second, (
            "Re-running with the same blob_path value must produce "
            "byte-identical manifest output (idempotence invariant)"
        )

    def test_replaces_existing_blob_path_value(self, tmp_path: Path) -> None:
        """Existing ``blob_path`` value → REPLACED with new value
        (re-signing under a different bundle root)."""
        from cognic_agentos.cli.sign import _write_blob_path_to_manifest

        manifest = tmp_path / "cognic-pack-manifest.toml"
        manifest.write_text(
            "[pack]\n"
            'name = "x"\n'
            'version = "1"\n'
            'kind = "tool"\n'
            "\n"
            "[supply_chain]\n"
            'attestation_paths = ["a.sig"]\n'
            'blob_path = "old-value.whl"\n'
        )

        _write_blob_path_to_manifest(manifest_path=manifest, blob_path="new-value.whl")

        data: dict[str, Any] = tomllib.loads(manifest.read_text())
        assert data["supply_chain"]["blob_path"] == "new-value.whl"
        # Other [supply_chain] fields preserved.
        assert data["supply_chain"]["attestation_paths"] == ["a.sig"]


# ===========================================================================
# Section D — Closed-enum ValidatorReason extension (R7 P2 #4)
# ===========================================================================


class TestSprint7B3T2SliceFValidatorReasonExtension:
    """The new ``sign_wheel_outside_bundle_root`` closed-enum value is
    declared in the central ``cli.ValidatorReason`` Literal + mapped to
    sign.py ownership in ``_VALIDATOR_REASON_OWNERSHIP``."""

    def test_sign_wheel_outside_bundle_root_in_validator_reason_literal(
        self,
    ) -> None:
        """The new closed-enum value is reachable via typing.get_args."""
        import typing

        from cognic_agentos.cli import ValidatorReason

        values = typing.get_args(ValidatorReason)
        assert "sign_wheel_outside_bundle_root" in values, (
            f"R7 P2 #4 wheel-outside-bundle-root refusal reason not in "
            f"ValidatorReason Literal; values={values}"
        )

    def test_sign_wheel_outside_bundle_root_owned_by_sign_py(self) -> None:
        """The new reason is mapped to sign.py in the ownership table."""
        from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP

        assert _VALIDATOR_REASON_OWNERSHIP["sign_wheel_outside_bundle_root"] == "sign.py"
