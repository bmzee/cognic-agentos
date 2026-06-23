"""Sprint 9 T3 — evidence-pack signing: identity resolution + fail-loud."""

from __future__ import annotations

from pathlib import Path

import pytest

from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    EvidencePackSigningError,
    SigningIdentity,
    cosign_sign_blob,
    resolve_signing_identity,
)
from tests.support.adapter_fixtures import InMemorySecretAdapter


async def test_resolve_raises_when_key_path_unset() -> None:
    with pytest.raises(EvidencePackSigningError, match="evidence_pack_signing_key_path"):
        await resolve_signing_identity(key_path=None, secret_adapter=None)


async def test_resolve_raises_on_unknown_uri_scheme() -> None:
    with pytest.raises(EvidencePackSigningError, match="scheme"):
        await resolve_signing_identity(key_path="s3://nope/key", secret_adapter=None)


async def test_resolve_vault_uri_requires_secret_adapter() -> None:
    with pytest.raises(EvidencePackSigningError, match="SecretAdapter"):
        await resolve_signing_identity(key_path="vault://secret/evidence-key", secret_adapter=None)


async def test_resolve_pem_path_reads_file_and_records_path_identity(
    tmp_path: Path,
) -> None:
    pem = tmp_path / "evidence-key.pem"
    pem.write_bytes(b"-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----\n")
    identity = await resolve_signing_identity(key_path=str(pem), secret_adapter=None)
    assert identity.identity == str(pem)
    assert identity.pem.startswith(b"-----BEGIN")


async def test_resolve_vault_records_the_uri_not_a_temp_path() -> None:
    # cli/sign.py's Vault contract: the `key` field (here a str).
    adapter = InMemorySecretAdapter()
    await adapter.write("secret/evidence-key", {"key": "-----BEGIN PRIVATE KEY-----\nyyy\n"})
    identity = await resolve_signing_identity(
        key_path="vault://secret/evidence-key", secret_adapter=adapter
    )
    # The auditable identity is the vault:// URI — never a /tmp path.
    assert identity.identity == "vault://secret/evidence-key"
    assert identity.pem.startswith(b"-----BEGIN")


async def test_resolve_vault_accepts_bytes_key_material() -> None:
    adapter = InMemorySecretAdapter()
    await adapter.write("secret/k", {"key": b"-----BEGIN PRIVATE KEY-----\nzzz\n"})
    identity = await resolve_signing_identity(key_path="vault://secret/k", secret_adapter=adapter)
    assert identity.pem == b"-----BEGIN PRIVATE KEY-----\nzzz\n"


async def test_cosign_sign_blob_fails_loud_when_cosign_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cognic_agentos.compliance.iso42001.signing.shutil.which", lambda _: None)
    with pytest.raises(EvidencePackSigningError, match="cosign binary not found"):
        await cosign_sign_blob(b"{}", SigningIdentity(identity="x", pem=b"k"))


def test_validate_cosign_artifacts_rejects_empty_signature() -> None:
    from cognic_agentos.compliance.iso42001.signing import validate_cosign_artifacts

    with pytest.raises(EvidencePackSigningError, match="empty signature"):
        validate_cosign_artifacts(CosignArtifacts(signature=b"", bundle=b"bundle-bytes"))


def test_validate_cosign_artifacts_rejects_empty_bundle() -> None:
    from cognic_agentos.compliance.iso42001.signing import validate_cosign_artifacts

    with pytest.raises(EvidencePackSigningError, match="empty Sigstore bundle"):
        validate_cosign_artifacts(CosignArtifacts(signature=b"sig-bytes", bundle=b""))


async def test_sign_blob_argv_includes_tlog_upload_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Evidence-pack sign-blob is offline on cosign 3.x: --tlog-upload=false
    is present alongside the existing legacy-output compat flags."""
    log_file = tmp_path / "argv.log"
    shim = tmp_path / "cosign"
    shim.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{log_file}"\n'
        # Honour --output-signature / --bundle so cosign_sign_blob's
        # both-outputs-produced guard passes.
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in\n'
        '    --output-signature) printf sig > "$2"; shift 2 ;;\n'
        '    --bundle) printf bundle > "$2"; shift 2 ;;\n'
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "exit 0\n"
    )
    shim.chmod(0o755)
    monkeypatch.setattr(
        "cognic_agentos.compliance.iso42001.signing.shutil.which",
        lambda _: str(shim),
    )
    await cosign_sign_blob(b"{}", SigningIdentity(identity="x", pem=b"-----BEGIN KEY-----\n"))
    recorded = log_file.read_text().strip().splitlines()
    assert "--tlog-upload=false" in recorded
    # Existing compat flags unchanged.
    assert "--use-signing-config=false" in recorded
    assert "--new-bundle-format=false" in recorded
