"""Evidence-pack manifest signing — Sprint 9 (ADR-006).

cosign sign-blob over the evidence-pack manifest, mirroring the
cli/sign.py discipline (cosign resolved via shutil.which, list-form argv,
asyncio.create_subprocess_exec, .sig + .bundle.sigstore both preserved).
Fail-loud: a missing key OR a missing cosign binary raises
EvidencePackSigningError — there is no best-effort unsigned pack. When
the key is a vault:// URI the signing IDENTITY recorded in the manifest
is the URI, never the temp PEM path written for cosign.

On the critical-controls coverage gate (T10).
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

_VAULT_SCHEME = "vault://"
_COSIGN_TIMEOUT_S = 60.0
#: Field within the Vault secret holding the signing-key material.
#: Matches cli/sign.py's Vault contract — the ``key`` field, str OR bytes.
_VAULT_KEY_FIELD = "key"


class EvidencePackSigningError(RuntimeError):
    """Any evidence-pack signing failure — fail-loud; never a best-effort
    unsigned pack."""


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    """Resolved signing material. ``identity`` is the auditable string
    recorded in the manifest (the vault:// URI or the PEM path); ``pem``
    is the private-key bytes cosign consumes."""

    identity: str
    pem: bytes


@dataclass(frozen=True, slots=True)
class CosignArtifacts:
    """The two cosign sign-blob outputs preserved into the evidence pack."""

    signature: bytes
    bundle: bytes


async def resolve_signing_identity(
    *, key_path: str | None, secret_adapter: SecretAdapter | None
) -> SigningIdentity:
    """Resolve ``Settings.evidence_pack_signing_key_path`` to signing
    material. Fail-loud on every error path."""
    if not key_path:
        raise EvidencePackSigningError(
            "evidence_pack_signing_key_path is unset; an unsigned evidence "
            "pack is forbidden (ADR-006). Configure a vault:// URI or a PEM path."
        )
    if key_path.startswith(_VAULT_SCHEME):
        return await _resolve_vault(key_path, secret_adapter)
    if "://" in key_path:
        raise EvidencePackSigningError(
            f"unsupported signing-key URI scheme in {key_path!r}; "
            "use vault://... or a filesystem PEM path."
        )
    return _resolve_pem_path(key_path)


async def _resolve_vault(key_path: str, secret_adapter: SecretAdapter | None) -> SigningIdentity:
    if secret_adapter is None:
        raise EvidencePackSigningError(
            f"{key_path} requires a SecretAdapter to resolve; none is wired."
        )
    vault_path = key_path[len(_VAULT_SCHEME) :]
    try:
        secret = await secret_adapter.read(vault_path)
    except Exception as exc:  # adapter-specific errors collapse to fail-loud
        raise EvidencePackSigningError(
            f"failed to read evidence-pack signing key from {key_path}: {exc}"
        ) from exc
    raw = secret.get(_VAULT_KEY_FIELD)
    # cli/sign.py's Vault contract: the `key` field is bytes, or str
    # coerced to bytes. Either is accepted; anything else fails loud.
    if isinstance(raw, bytes) and raw:
        pem = raw
    elif isinstance(raw, str) and raw:
        pem = raw.encode("utf-8")
    else:
        raise EvidencePackSigningError(
            f"{key_path} secret has no non-empty {_VAULT_KEY_FIELD!r} field "
            "(expected str or bytes)."
        )
    # Auditable identity = the vault:// URI, NOT any temp path.
    return SigningIdentity(identity=key_path, pem=pem)


def _resolve_pem_path(key_path: str) -> SigningIdentity:
    path = Path(key_path)
    if not path.is_file():
        raise EvidencePackSigningError(
            f"evidence-pack signing key {key_path} is not a readable file."
        )
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise EvidencePackSigningError(
            f"failed to read evidence-pack signing key {key_path}: {exc}"
        ) from exc
    if not pem:
        raise EvidencePackSigningError(f"evidence-pack signing key {key_path} is empty.")
    return SigningIdentity(identity=key_path, pem=pem)


async def cosign_sign_blob(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
    """``cosign sign-blob`` over ``manifest``. Fail-loud if cosign is
    absent, times out, exits non-zero, or fails to produce both outputs.

    argv follows cli/sign.py's list-form subprocess shape, with
    --use-signing-config=false + --new-bundle-format=false so cosign v3
    still writes the separate --output-signature artifact and a bundle
    that `verify-blob --signature --bundle` accepts (the Sprint 9
    evidence-pack wire shape):
      cosign sign-blob --yes --use-signing-config=false --new-bundle-format=false
        --key <key> --output-signature <sig> --bundle <bundle> <blob>
    """
    cosign = shutil.which("cosign")
    if cosign is None:
        raise EvidencePackSigningError(
            "cosign binary not found on PATH; cannot sign the evidence pack "
            "(an unsigned examiner artifact is forbidden, ADR-006)."
        )
    with tempfile.TemporaryDirectory(prefix="cognic-evidence-sign-") as tmp:
        tmp_dir = Path(tmp)
        key_file = tmp_dir / "evidence-key.pem"
        blob_file = tmp_dir / "manifest.json"
        sig_file = tmp_dir / "manifest.json.sig"
        bundle_file = tmp_dir / "manifest.json.bundle.sigstore"
        key_file.write_bytes(identity.pem)
        key_file.chmod(0o600)
        blob_file.write_bytes(manifest)
        proc = await asyncio.create_subprocess_exec(
            cosign,
            "sign-blob",
            "--yes",
            "--use-signing-config=false",
            "--new-bundle-format=false",
            "--key",
            str(key_file),
            "--output-signature",
            str(sig_file),
            "--bundle",
            str(bundle_file),
            str(blob_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_COSIGN_TIMEOUT_S)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise EvidencePackSigningError("cosign sign-blob timed out.") from exc
        if proc.returncode != 0:
            raise EvidencePackSigningError(
                f"cosign sign-blob failed (exit {proc.returncode}): "
                f"{stderr.decode('utf-8', 'replace').strip()}"
            )
        if not sig_file.is_file() or not bundle_file.is_file():
            raise EvidencePackSigningError(
                "cosign sign-blob exited 0 but did not produce both the "
                "signature and the Sigstore bundle."
            )
        signature = sig_file.read_bytes()
        bundle = bundle_file.read_bytes()
        # tempdir (incl. the key file) is removed on context exit.
        artifacts = CosignArtifacts(signature=signature, bundle=bundle)
        validate_cosign_artifacts(artifacts)
        return artifacts


def validate_cosign_artifacts(artifacts: CosignArtifacts) -> None:
    """Reject empty signing outputs — an empty .sig / .bundle.sigstore is
    a structurally-complete but UNVERIFIABLE examiner artifact. cli/sign.py
    treats empty signing outputs as a failure; mirror that, fail-loud
    (cosign can exit 0 yet leave a zero-byte output on some error paths).

    Public so the evidence-pack exporter can re-validate ANY injected
    signer's output — the ``signer`` seam in evidence_pack.py accepts
    test / custom signers, not only cosign_sign_blob's own output."""
    if not artifacts.signature:
        raise EvidencePackSigningError("cosign produced an empty signature.")
    if not artifacts.bundle:
        raise EvidencePackSigningError("cosign produced an empty Sigstore bundle.")
