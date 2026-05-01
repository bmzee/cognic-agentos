"""Reproducibility manifest digest verifier — informational only.

Per ADR-016 §"Reproducibility commitment" + Sprint-4 plan-of-record T8.
This module is **NOT** a critical-controls module:

  * No rebuild verification (Sprint 7B reviewer flow rebuilds the
    pack from the manifest's declared inputs and compares the
    artifact digest).
  * No promotion / demotion of the pack registration grade.
  * No critical-controls coverage gate expansion (T15 keeps the
    Sprint-2 quartet + Sprint-2.5 triplet + Sprint-3 LLM quintet +
    Sprint-4 protocol/policy quartet at the 95/90 bar; T8 sits at
    the regular ≥80% adapter tier).
  * No cryptographic envelope verification (cosign verify of the
    detached signature is T6's job; if T10 / Sprint 7B needs that
    on the manifest specifically, it calls ``TrustGate.verify_pack_
    signature`` directly with the manifest paths).

What this module DOES in Sprint 4:

  1. Compute SHA-256 of the manifest file → ``manifest_digest``.
  2. If a signature file path is supplied AND the file exists,
     compute SHA-256 of the signature bytes → ``signature_digest``;
     mark ``signed=True``.
  3. If the signature is a JSON envelope that declares a
     ``manifest_digest`` field, AND that field doesn't match the
     actual SHA-256 of the manifest bytes, raise
     ``ManifestTampered``.
  4. Unsigned manifests (no signature path, or path absent, or
     signature unreadable) return ``signed=False`` — informational,
     NOT a refusal. The pack registers without the
     ``reproducible: true`` flag.

T10 / Sprint 7B reviewer flow consume the result and decide
whether to promote the pack with ``reproducible: true``. T8 itself
never refuses registration on reproducibility grounds.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

_LOG = logging.getLogger("cognic_agentos.protocol.reproducibility")


# --- Exception taxonomy -------------------------------------------------


class ReproducibilityError(RuntimeError):
    """Base for T8 manifest-verification failures."""


class ManifestTampered(ReproducibilityError):
    """The signature envelope claims a ``manifest_digest`` that does
    NOT match the actual SHA-256 of the manifest bytes. T10 catches
    this and records the pack with ``reproducible=False`` (and a
    finding); per ADR-016 + the user's Sprint-4 scope discipline,
    reproducibility tampering is informational, NOT a registration
    refusal — the registry exposes the result so operators see the
    discrepancy in the audit trail.
    """


# --- Result type --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReproducibilityResult:
    """Outcome of T8's manifest digest verification.

    ``manifest_digest`` is always populated (SHA-256 hex of the
    manifest bytes). ``signature_digest`` is the SHA-256 hex of the
    signature bytes when ``signed=True``, empty string when
    ``signed=False``. ``signed`` is True iff a signature file was
    supplied AND readable. Unparseable / malformed signatures
    return ``signed=False`` — not tampered, just not signed.

    Sprint 4 contract: this result is informational. The pack
    registers regardless; T10 / Sprint 7B reviewer flow decide
    whether to promote with ``reproducible=True``.
    """

    signed: bool
    manifest_digest: str
    signature_digest: str


# --- Public API ---------------------------------------------------------


def verify_reproducibility_manifest(
    manifest_path: Path,
    signature_path: Path | None = None,
) -> ReproducibilityResult:
    """Compute manifest + signature digests; raise on
    digest-mismatch tampering; otherwise return informational result.

    See module docstring for the Sprint-4 scope discipline (NOT
    critical-controls; no rebuild; no promotion/demotion logic;
    informational result only).

    Raises ``FileNotFoundError`` if the manifest itself doesn't
    exist — T10 treats that as "no manifest provided" and skips
    the reproducibility flag without refusing.

    Raises ``ManifestTampered`` if the signature envelope is a JSON
    object that declares a ``manifest_digest`` field whose value
    doesn't match the actual SHA-256 of the manifest bytes.
    """
    manifest_bytes = manifest_path.read_bytes()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

    if signature_path is None or not signature_path.exists() or not signature_path.is_file():
        return ReproducibilityResult(
            signed=False, manifest_digest=manifest_digest, signature_digest=""
        )

    try:
        signature_bytes = signature_path.read_bytes()
    except OSError as exc:
        # Signature file became unreadable between the exists() check
        # and the read. Per scope discipline, treat as unsigned —
        # informational, not refusal. Log so operators can see the
        # inconsistency.
        _LOG.info(
            "reproducibility: signature unreadable at %s — treating as unsigned: errno=%s class=%s",
            signature_path,
            exc.errno,
            type(exc).__name__,
        )
        return ReproducibilityResult(
            signed=False, manifest_digest=manifest_digest, signature_digest=""
        )

    if not signature_bytes:
        # Empty signature file == no signature.
        return ReproducibilityResult(
            signed=False, manifest_digest=manifest_digest, signature_digest=""
        )

    signature_digest = hashlib.sha256(signature_bytes).hexdigest()

    # If the signature is a JSON envelope that declares a
    # manifest_digest, sanity-check the claim against the actual
    # manifest hash. This is the Sprint-4 tampering signal — full
    # cosign envelope verification (DSSE / Sigstore bundle) is
    # Sprint 7B reviewer-flow territory.
    claimed_digest = _extract_claimed_manifest_digest(signature_bytes)
    if claimed_digest is not None:
        # R1 reviewer-P2 fix: strip first, THEN remove the optional
        # ``sha256:`` prefix, THEN strip again — handles all of
        # ``" sha256:abc "`` / ``"sha256: abc"`` / ``"abc"``. An
        # empty / whitespace-only claim normalises to ``""`` and
        # falls through to the != check below, which raises.
        normalized_claim = claimed_digest.strip().removeprefix("sha256:").strip().lower()
        if normalized_claim != manifest_digest.lower():
            raise ManifestTampered(
                f"signature at {signature_path!s} declares "
                f"manifest_digest={normalized_claim!r} but the manifest at "
                f"{manifest_path!s} hashes to {manifest_digest!r}"
            )

    return ReproducibilityResult(
        signed=True,
        manifest_digest=manifest_digest,
        signature_digest=signature_digest,
    )


def _extract_claimed_manifest_digest(signature_bytes: bytes) -> str | None:
    """Best-effort extraction of a self-declared manifest digest from
    a JSON-shaped signature envelope.

    Returns the declared digest string verbatim (with or without
    ``sha256:`` prefix; possibly empty / whitespace) when the
    signature is a JSON object whose ``manifest_digest`` key is
    present AND string-typed. Returns ``None`` for any other shape —
    binary detached signatures, JSON without the field, or a non-
    string field value (int / list / dict). Non-JSON / non-string-
    field signatures aren't *tampered*, they're just not
    introspectable in Sprint 4; tampering fires only when the
    envelope explicitly declares a string digest claim that we can
    compare against (R1 reviewer-P2 fix: an empty / whitespace-only
    string IS a present-but-mismatched claim, not "absent" — the
    verifier must still compare and refuse).
    """
    try:
        text = signature_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    claimed = parsed.get("manifest_digest")
    if isinstance(claimed, str):
        return claimed
    return None


__all__ = (
    "ManifestTampered",
    "ReproducibilityError",
    "ReproducibilityResult",
    "verify_reproducibility_manifest",
)
