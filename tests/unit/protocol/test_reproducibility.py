"""Sprint 4 T8 — reproducibility manifest digest verifier tests.

Per the user's Sprint-4 scope discipline (T8 reply):

  > For T8, the key guardrail is scope: protocol/reproducibility.py
  > should verify the reproducibility manifest digest only, and keep
  > it informational. No rebuild, no promotion/demotion logic, no
  > critical-controls gate expansion until T15.

So the test surface is narrow:

  * ``TestSigned`` — signed manifest passes (signed=True, both
    digests populated).
  * ``TestUnsigned`` — unsigned manifest returns signed=False
    (NOT a refusal); covers the missing-signature variants.
  * ``TestTampered`` — JSON-envelope signature with a mismatched
    ``manifest_digest`` claim raises ``ManifestTampered``.
  * ``TestNonJsonSignature`` — non-JSON / non-introspectable
    signatures stay signed=True without raising (no claim to
    refute).
  * ``TestExceptionTaxonomy`` — ManifestTampered subclasses
    ReproducibilityError.

Coverage target is the regular ≥80% adapter tier (T15 keeps T8 OFF
the critical-controls gate).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from cognic_agentos.protocol.reproducibility import (
    ManifestTampered,
    ReproducibilityError,
    ReproducibilityResult,
    verify_reproducibility_manifest,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _write_manifest(path: Path, body: bytes = b'{"build_env": "ci"}') -> str:
    """Write manifest bytes; return the SHA-256 hex digest."""
    path.write_bytes(body)
    return hashlib.sha256(body).hexdigest()


def _write_envelope_signature(path: Path, manifest_digest: str | None = None) -> str:
    """Write a JSON-envelope signature that declares a
    ``manifest_digest`` (when supplied) plus a ``signature`` blob.
    Returns the SHA-256 of the file."""
    body: dict[str, object] = {"signature": "base64-bytes-..."}
    if manifest_digest is not None:
        body["manifest_digest"] = manifest_digest
    blob = json.dumps(body).encode("utf-8")
    path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# TestSigned — signed manifest passes.
# ---------------------------------------------------------------------------


class TestSigned:
    def test_signed_manifest_returns_signed_true(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        sig_digest = _write_envelope_signature(signature, manifest_digest=digest)
        result = verify_reproducibility_manifest(manifest, signature)
        assert isinstance(result, ReproducibilityResult)
        assert result.signed is True
        assert result.manifest_digest == digest
        assert result.signature_digest == sig_digest

    def test_signed_manifest_with_sha256_prefix_in_envelope(self, tmp_path: Path) -> None:
        """The envelope can declare ``"sha256:<hex>"`` or bare hex —
        comparison normalises the prefix."""
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        _write_envelope_signature(signature, manifest_digest=f"sha256:{digest}")
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True

    def test_signed_envelope_without_manifest_digest_field_passes(self, tmp_path: Path) -> None:
        """A JSON envelope that doesn't declare a manifest_digest claim
        is still ``signed=True`` — there's nothing to compare against,
        so no tamper detection fires. T10 / Sprint 7B can apply
        full cosign verification when needed."""
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        _write_envelope_signature(signature, manifest_digest=None)
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True
        assert result.manifest_digest == digest

    def test_signed_envelope_with_non_string_manifest_digest_passes(self, tmp_path: Path) -> None:
        """Non-string ``manifest_digest`` value is treated as "no
        introspectable claim" rather than tampered — Sprint 4's scope
        is informational, not strict envelope schema enforcement."""
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(json.dumps({"manifest_digest": 12345}).encode())
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True


# ---------------------------------------------------------------------------
# TestUnsigned — informational, not a refusal.
# ---------------------------------------------------------------------------


class TestUnsigned:
    def test_no_signature_path_returns_signed_false(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        result = verify_reproducibility_manifest(manifest)
        assert result.signed is False
        assert result.manifest_digest == digest
        assert result.signature_digest == ""

    def test_signature_path_does_not_exist_returns_signed_false(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        result = verify_reproducibility_manifest(manifest, tmp_path / "absent.sig")
        assert result.signed is False
        assert result.manifest_digest == digest

    def test_signature_path_is_directory_returns_signed_false(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        sig_dir = tmp_path / "im-a-dir"
        sig_dir.mkdir()
        result = verify_reproducibility_manifest(manifest, sig_dir)
        assert result.signed is False

    def test_empty_signature_file_returns_signed_false(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(b"")
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is False

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses chmod-based unread check")
    def test_unreadable_signature_returns_signed_false_no_raise(self, tmp_path: Path) -> None:
        """Signature file became unreadable between the exists() check
        and the read (race / permission flip). Per scope discipline,
        treat as unsigned — informational, not refusal."""
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(b"some-sig")
        signature.chmod(stat.S_IRUSR & 0)  # 0000 — no read
        try:
            result = verify_reproducibility_manifest(manifest, signature)
            assert result.signed is False
        finally:
            signature.chmod(stat.S_IRWXU)  # restore so tmp teardown works


# ---------------------------------------------------------------------------
# TestTampered — digest-claim mismatch raises hard error.
# ---------------------------------------------------------------------------


class TestTampered:
    def test_envelope_with_mismatched_digest_raises(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        # Envelope claims a digest that doesn't match the actual.
        wrong = hashlib.sha256(b"different-content").hexdigest()
        _write_envelope_signature(signature, manifest_digest=wrong)
        with pytest.raises(ManifestTampered, match="hashes to"):
            verify_reproducibility_manifest(manifest, signature)

    def test_envelope_mismatch_with_sha256_prefix_raises(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        wrong = hashlib.sha256(b"different-content").hexdigest()
        _write_envelope_signature(signature, manifest_digest=f"sha256:{wrong}")
        with pytest.raises(ManifestTampered):
            verify_reproducibility_manifest(manifest, signature)

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n", "   \t\n"])
    def test_envelope_with_blank_manifest_digest_raises(self, tmp_path: Path, blank: str) -> None:
        """R1 reviewer-P2 fix: a JSON envelope that explicitly declares
        ``manifest_digest`` as an empty / whitespace-only string is a
        PRESENT-but-mismatched claim, not "absent". Previously the
        helper returned None on these (truthiness gate), so the
        verifier marked them ``signed=True`` and never raised. Now
        the helper returns the verbatim string and the comparison
        normalises to ``""`` ≠ actual-digest → ``ManifestTampered``."""
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        _write_envelope_signature(signature, manifest_digest=blank)
        with pytest.raises(ManifestTampered, match="hashes to"):
            verify_reproducibility_manifest(manifest, signature)

    def test_envelope_with_sha256_prefix_only_raises(self, tmp_path: Path) -> None:
        """A claim of ``"sha256:"`` (prefix only, no hex) normalises
        to ``""`` and triggers the same mismatch path."""
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        _write_envelope_signature(signature, manifest_digest="sha256:")
        with pytest.raises(ManifestTampered):
            verify_reproducibility_manifest(manifest, signature)

    def test_envelope_with_whitespace_around_prefix_normalises(self, tmp_path: Path) -> None:
        """Counter-test: a legitimate claim with surrounding whitespace
        around the ``sha256:`` prefix DOES normalise to the correct
        digest and verifies cleanly. R1 fix's strip-prefix-strip
        order makes this work."""
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        _write_envelope_signature(signature, manifest_digest=f"  sha256:  {digest}  ")
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True


# ---------------------------------------------------------------------------
# TestNonJsonSignature — opaque blobs stay signed=True (no claim).
# ---------------------------------------------------------------------------


class TestNonJsonSignature:
    def test_binary_detached_signature_stays_signed(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        digest = _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(b"\x00\x01\x02\x03binary-bytes")
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True
        assert result.manifest_digest == digest

    def test_non_utf8_signature_stays_signed(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(b"\xff\xfe\xff")  # invalid UTF-8
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True

    def test_text_non_json_signature_stays_signed(self, tmp_path: Path) -> None:
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(b"-----BEGIN COSIGN SIGNATURE-----\nfake\n")
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True

    def test_json_array_root_signature_stays_signed(self, tmp_path: Path) -> None:
        """JSON arrays / scalars don't carry a manifest_digest field
        → no claim to introspect → not tampered."""
        manifest = tmp_path / "repro.json"
        _write_manifest(manifest)
        signature = tmp_path / "repro.sig"
        signature.write_bytes(b"[1, 2, 3]")
        result = verify_reproducibility_manifest(manifest, signature)
        assert result.signed is True


# ---------------------------------------------------------------------------
# TestManifestNotFound — raw FileNotFoundError per the docstring contract.
# ---------------------------------------------------------------------------


class TestManifestNotFound:
    def test_missing_manifest_raises_file_not_found(self, tmp_path: Path) -> None:
        """T8 docstring contract: raise ``FileNotFoundError`` (NOT
        ManifestTampered) when the manifest itself is absent. T10
        treats that as "no manifest provided" and skips the
        reproducibility flag without refusing — informational."""
        with pytest.raises(FileNotFoundError):
            verify_reproducibility_manifest(tmp_path / "absent.json")


# ---------------------------------------------------------------------------
# TestExceptionTaxonomy — ManifestTampered subclasses ReproducibilityError.
# ---------------------------------------------------------------------------


class TestExceptionTaxonomy:
    def test_manifest_tampered_subclasses_reproducibility_error(self) -> None:
        assert issubclass(ManifestTampered, ReproducibilityError)
