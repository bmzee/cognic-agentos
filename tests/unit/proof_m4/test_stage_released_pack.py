"""stage_released_pack arranges downloaded v0.1.0 assets into the staging tree
the proof image consumes + fail-closes on a digest mismatch (M4 Task 8)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from tests.integration.proof_m4 import stage_released_pack as srp

_EXPECTED_ATTESTATIONS = {
    "cosign.sig",
    "bundle.sigstore",
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
}


def _fake_assets(d: Path, wheel_bytes: bytes, pub_bytes: bytes) -> Path:
    src = d / "downloaded"
    src.mkdir()
    (src / srp.WHEEL).write_bytes(wheel_bytes)
    (src / "cosign.pub").write_bytes(pub_bytes)
    for name in srp.ATTESTATIONS:
        (src / name).write_text("{}")
    return src


def test_arrange_builds_the_exact_image_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel, pub = b"WHEEL", b"PUB"
    monkeypatch.setattr(srp, "EXPECTED_WHEEL_SHA256", hashlib.sha256(wheel).hexdigest())
    monkeypatch.setattr(srp, "EXPECTED_PUB_SHA256", hashlib.sha256(pub).hexdigest())
    src = _fake_assets(tmp_path, wheel, pub)
    dst = tmp_path / "staging"
    srp.arrange(src, dst)
    assert (dst / "wheel" / srp.WHEEL).read_bytes() == wheel
    base = dst / "pack-attestations" / "cognic-tool-oracle-schema" / "0.1.0"
    assert (base / srp.WHEEL).read_bytes() == wheel
    assert {p.name for p in base.iterdir()} == _EXPECTED_ATTESTATIONS | {srp.WHEEL}
    for name in _EXPECTED_ATTESTATIONS:
        assert (base / name).read_text() == "{}"
    assert (dst / "trust-roots" / "_default" / "cosign.pub").read_bytes() == pub
    assert json.loads((dst / "policies" / "plugin_allowlist.json").read_text()) == {
        "_default": ["cognic-tool-oracle-schema"]
    }
    assert (dst / "alembic.ini").exists() and (dst / "alembic.ini").read_bytes()


def test_digest_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _fake_assets(tmp_path, b"WHEEL", b"PUB")
    monkeypatch.setattr(srp, "EXPECTED_WHEEL_SHA256", "deadbeef")
    with pytest.raises(srp.StagingDigestMismatch):
        srp.arrange(src, tmp_path / "staging")


def test_pub_digest_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _fake_assets(tmp_path, b"WHEEL", b"PUB")
    monkeypatch.setattr(srp, "EXPECTED_WHEEL_SHA256", hashlib.sha256(b"WHEEL").hexdigest())
    monkeypatch.setattr(srp, "EXPECTED_PUB_SHA256", "deadbeef")
    with pytest.raises(srp.StagingDigestMismatch):
        srp.arrange(src, tmp_path / "staging")


def test_attestation_list_matches_the_released_bundle_contract() -> None:
    assert set(srp.ATTESTATIONS) == _EXPECTED_ATTESTATIONS


def test_download_retries_transient_gh_release_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    sleeps: list[int] = []

    def fake_run(cmd: list[str], *, check: bool) -> subprocess.CompletedProcess[str]:
        assert check is True
        calls.append(cmd)
        if len(calls) < 3:
            raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("tests.integration.proof_m4.stage_released_pack.subprocess.run", fake_run)
    monkeypatch.setattr(
        "tests.integration.proof_m4.stage_released_pack.time.sleep",
        lambda seconds: sleeps.append(seconds),
    )

    assert srp.download(tmp_path) == tmp_path
    assert len(calls) == 3
    assert sleeps == [3, 3]
