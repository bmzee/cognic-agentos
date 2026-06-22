"""Model-artefact cosign signature verification — Sprint 9.5 per ADR-013.

Mirrors the ``protocol/trust_gate.py`` cosign discipline exactly: list-form
argv, no shell, frozen 2-key subprocess env, asyncio timeout + SIGKILL +
reap, exit-code-only verdict (stdout/stderr never parsed). CRITICAL
CONTROL.

Consumed by ``models/storage.py`` as the ``proposed -> eval_passed``
precondition — verification runs OUTSIDE the DB transaction (design spec
§2.3). Wave-1 scope: the artefact / bundle / trust-root arguments are
local filesystem paths under a per-tenant guarded root; object-store-
backed fetch is a Wave-2 seam (see plan "planning-time design
decisions" #3). Cosign argv is bundle-only — no ``--signature`` —
pinned by an argv-shape regression in the test.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from shutil import which

from cognic_agentos.core.config import Settings

#: Subprocess env — PATH + HOME only; ``os.environ`` is never passed
#: through. Mirrors ``trust_gate.py:94-100``.
_SUBPROCESS_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}


class ModelSignatureVerificationError(Exception):
    """Raised when cosign verification of a model artefact cannot be
    completed at all (binary missing, launch failure, timeout) —
    fail-closed. Distinct from a clean negative verdict, which returns
    ``False``.
    """


def sigstore_bundle_digest(bundle_path: Path) -> str:
    """SHA-256 hex over the raw bytes of the Sigstore bundle file.

    The pinned ``signature_digest`` byte contract (design spec §2.3) —
    identical to ``protocol/supply_chain.persist_sigstore_bundle``'s
    ``bundle_digest``. Chunked 64 KiB read for large bundles.
    """
    h = hashlib.sha256()
    with open(bundle_path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class ModelTrustGate:
    """Cosign verifier for model artefacts. Resolves the ``cosign``
    binary once at construction (mirrors ``trust_gate.py:280-286``).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        configured = settings.cosign_path or "cosign"
        self._cosign_bin: str | None = which(configured)

    async def verify_model_signature(
        self,
        *,
        signed_artifact_path: Path,
        sigstore_bundle_path: Path,
        tenant_trust_root: Path,
    ) -> bool:
        """Run ``cosign verify-blob`` of the model artefact against the
        per-tenant trust root.

        Returns ``True`` on a clean verify (exit 0), ``False`` on a clean
        negative verdict (exit non-zero). Raises
        :class:`ModelSignatureVerificationError` when verification cannot
        run at all (fail-closed). stdout/stderr are never parsed.
        """
        if self._cosign_bin is None:
            raise ModelSignatureVerificationError(
                "cosign binary not found on PATH; "
                f"Settings.cosign_path={self._settings.cosign_path!r}"
            )
        argv = [
            self._cosign_bin,
            "verify-blob",
            "--key",
            str(tenant_trust_root),
            "--bundle",
            str(sigstore_bundle_path),
            # cosign 3.x offline verify (ADR-013/ADR-016 §6): an offline-signed
            # model has no Rekor tlog entry; ignore the tlog. Bundle-only stays —
            # NO --signature, NO --new-bundle-format=false.
            "--insecure-ignore-tlog",
            str(signed_artifact_path),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_SUBPROCESS_ENV,
            )
        except OSError as exc:
            raise ModelSignatureVerificationError(
                f"failed to launch cosign at {self._cosign_bin!r}: "
                f"errno={exc.errno} class={type(exc).__name__}"
            ) from None
        timeout_s = self._settings.cosign_verify_timeout_s
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise ModelSignatureVerificationError(
                f"cosign verification timed out after {timeout_s}s"
            ) from None
        return proc.returncode == 0


__all__ = [
    "ModelSignatureVerificationError",
    "ModelTrustGate",
    "sigstore_bundle_digest",
]
