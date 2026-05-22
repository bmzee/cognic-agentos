"""Sprint 9 T3 — evidence-pack signing: identity resolution + fail-loud."""

from __future__ import annotations

from pathlib import Path

import pytest

from cognic_agentos.compliance.iso42001.signing import (
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


def test_validate_artifacts_rejects_empty_signature() -> None:
    from cognic_agentos.compliance.iso42001.signing import _validate_artifacts

    with pytest.raises(EvidencePackSigningError, match="empty signature"):
        _validate_artifacts(b"", b"bundle-bytes")


def test_validate_artifacts_rejects_empty_bundle() -> None:
    from cognic_agentos.compliance.iso42001.signing import _validate_artifacts

    with pytest.raises(EvidencePackSigningError, match="empty Sigstore bundle"):
        _validate_artifacts(b"sig-bytes", b"")
