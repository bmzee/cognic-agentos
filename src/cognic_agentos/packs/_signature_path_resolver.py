"""Sprint 7B.3 T9 — signature path resolver (module-private).

Per the plan-of-record §466-489 (R3 P2 #2 + R4 P2 #4 + R6 P2 #4 +
R7 P2 #1). The T9 approve handler's Gate 1 (cosign signature
verification per ADR-016) needs ABSOLUTE filesystem paths for the
``.sig`` file + the signed blob to hand to
:meth:`cognic_agentos.protocol.trust_gate.TrustGate.verify_pack_signature`.
This module is the pure-functional projector that produces them out of
a pack's persisted manifest + the submit-declared bundle root.

**R6 P2 #4 relative-paths + bundle-root contract** (replaces the
rejected R3 filename-derivation + R5 absolute-paths-in-manifest
doctrines):

- ``signature_path`` — the unique entry in the manifest's flat
  ``[supply_chain].attestation_paths`` list whose basename is exactly
  ``cosign.sig`` (NOT a ``*.sig`` glob — the literal filename).
  Manifest-RELATIVE; absolute → refused; ``..`` traversal → refused.
- ``blob_path`` — the explicit ``[supply_chain].blob_path`` manifest
  field (the signed wheel). Manifest-RELATIVE; absolute → refused;
  ``..`` traversal → refused.
- ``signed_artefact_root`` — the absolute bundle directory on the
  approve-time host, submit-declared at the author surface (R8 P2 #4),
  persisted on the submit chain row's ``payload["signed_artefact_root"]``,
  passed in here by the T9 handler. ``None`` → refused.

The resolver concatenates ``signed_artefact_root / <relative>`` for
each path. **Pure-functional — no filesystem I/O.** It does NOT stat
the produced paths; the T9 handler does the ``.exists()`` probe
separately and maps a missing file to ``signature_bundle_path_unreachable``.

**Check precedence** (documented + pinned by the Slice-B precedence
tests): signature-path resolution → blob-path resolution → bundle-root
presence → concatenation. A manifest-declaration failure (the author's
fault) is surfaced ahead of the submit-time bundle-root failure.

**R7 P2 #1.** The 8 failure red-reasons are a SUBSET of the unified
13-value :data:`~cognic_agentos.packs.approval_gates.SignatureRedReason`
Literal — there is NO standalone ``SignaturePathRedReason`` Literal
(it was introduced at R6 and DELETED at R7; implementers MUST NOT
recreate it). :class:`SignaturePathResolution` types ``red_reason`` as
``SignatureRedReason | None`` directly so the T9 handler threads
``resolution.red_reason`` into ``SignatureGateInput.red_reason`` with
no translation table.

Module-private (``_`` prefix): the resolver is implementation detail
of the T9 approve path. Bank overlays do not depend on this surface.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Literal

from cognic_agentos.packs.approval_gates import SignatureRedReason

__all__ = ["SignaturePathResolution", "resolve_signature_paths"]


#: The literal cosign-signature filename produced by ``agentos sign``
#: (``cli/sign.py``). The match is on the path basename, not a glob —
#: a ``*.sig`` entry that is not exactly ``cosign.sig`` does not match.
_COSIGN_SIG_FILENAME: str = "cosign.sig"


@dataclasses.dataclass(frozen=True)
class SignaturePathResolution:
    """Frozen result of :func:`resolve_signature_paths`.

    - ``outcome`` — ``"resolved"`` on the green path; one of the four
      failure-class values otherwise. The failure class names WHICH
      part of the contract was unmet; the precise ``red_reason``
      carries the specific cause.
    - ``signature_path`` / ``blob_path`` — the ABSOLUTE concatenated
      paths on the green path; BOTH ``None`` on every failure path
      (the resolver invents no path — pinned by the Slice-B contract
      test).
    - ``red_reason`` — one of the 8 resolver-side
      :data:`SignatureRedReason` values on a failure path; ``None`` on
      the green path.
    """

    outcome: Literal[
        "resolved",
        "ambiguous",
        "signature_missing",
        "blob_missing",
        "root_missing",
    ]
    signature_path: Path | None
    blob_path: Path | None
    red_reason: SignatureRedReason | None


def _has_traversal(relative: str) -> bool:
    """True iff ``relative`` contains an exact ``..`` path segment.

    Splits on ``/`` and looks for an exact ``..`` segment so a
    legitimate filename like ``..bar`` (leading dots) is NOT
    mis-rejected. Mirrors the same split-and-check idiom the
    ``SubmitDraftRequest.signed_artefact_root`` validator uses.
    """
    return ".." in relative.split("/")


def _signature_failed(
    outcome: Literal["ambiguous", "signature_missing"],
    red_reason: SignatureRedReason,
) -> SignaturePathResolution:
    return SignaturePathResolution(
        outcome=outcome, signature_path=None, blob_path=None, red_reason=red_reason
    )


def _blob_failed(red_reason: SignatureRedReason) -> SignaturePathResolution:
    return SignaturePathResolution(
        outcome="blob_missing",
        signature_path=None,
        blob_path=None,
        red_reason=red_reason,
    )


def _resolve_signature_relative(
    manifest: dict[str, Any],
) -> str | SignaturePathResolution:
    """Project the manifest-relative ``cosign.sig`` path.

    Returns the relative-path ``str`` on success, or a fully-formed
    failure :class:`SignaturePathResolution` when the cosign.sig entry
    is absent / ambiguous / absolute / traversal-unsafe.
    """
    supply_chain = manifest.get("supply_chain")
    attestation_paths = (
        supply_chain.get("attestation_paths") if isinstance(supply_chain, dict) else None
    )
    entries = attestation_paths if isinstance(attestation_paths, list) else []
    matches = [
        entry
        for entry in entries
        if isinstance(entry, str) and Path(entry).name == _COSIGN_SIG_FILENAME
    ]
    if len(matches) == 0:
        return _signature_failed(
            "signature_missing", "signature_cosign_sig_not_in_attestation_paths"
        )
    if len(matches) > 1:
        return _signature_failed("ambiguous", "signature_multiple_cosign_sig_entries_ambiguous")
    candidate = matches[0]
    if candidate.startswith("/"):
        return _signature_failed("signature_missing", "signature_path_must_be_relative")
    if _has_traversal(candidate):
        return _signature_failed("signature_missing", "signature_path_traversal_rejected")
    return candidate


def _resolve_blob_relative(
    manifest: dict[str, Any],
) -> str | SignaturePathResolution:
    """Project the manifest-relative ``blob_path``.

    Returns the relative-path ``str`` on success, or a fully-formed
    failure :class:`SignaturePathResolution`.
    """
    supply_chain = manifest.get("supply_chain")
    blob_path = supply_chain.get("blob_path") if isinstance(supply_chain, dict) else None
    if not isinstance(blob_path, str) or not blob_path:
        return _blob_failed("signature_blob_path_not_declared_in_manifest")
    if blob_path.startswith("/"):
        return _blob_failed("signature_blob_path_must_be_relative")
    if _has_traversal(blob_path):
        return _blob_failed("signature_blob_path_traversal_rejected")
    return blob_path


def resolve_signature_paths(
    manifest: dict[str, Any],
    *,
    signed_artefact_root: Path | None,
) -> SignaturePathResolution:
    """Project the cosign signature + signed-blob ABSOLUTE paths.

    Pure-functional — no filesystem I/O. Resolves the manifest-relative
    ``cosign.sig`` + ``blob_path`` declarations against the
    submit-declared ``signed_artefact_root`` bundle root and returns a
    frozen :class:`SignaturePathResolution`.

    Check precedence (R6 P2 #4 + documented module doctrine):

    1. ``cosign.sig`` attestation entry — absent / ambiguous / absolute
       / ``..``-traversal.
    2. ``[supply_chain].blob_path`` field — absent / non-string /
       absolute / ``..``-traversal.
    3. ``signed_artefact_root`` — ``None``.
    4. concatenate ``signed_artefact_root / <relative>`` → ``resolved``.

    A failure at any step short-circuits with BOTH paths ``None`` and
    the specific :data:`SignatureRedReason`; the T9 handler threads
    that ``red_reason`` straight onto ``SignatureGateInput`` (R7 P2 #1
    — no translation table).
    """
    signature_relative = _resolve_signature_relative(manifest)
    if isinstance(signature_relative, SignaturePathResolution):
        return signature_relative

    blob_relative = _resolve_blob_relative(manifest)
    if isinstance(blob_relative, SignaturePathResolution):
        return blob_relative

    if signed_artefact_root is None:
        return SignaturePathResolution(
            outcome="root_missing",
            signature_path=None,
            blob_path=None,
            red_reason="signature_signed_artefact_root_not_declared_at_submit",
        )

    # Both helpers returned ``str`` relatives — the isinstance guards
    # above are the only way out of the failure paths.
    return SignaturePathResolution(
        outcome="resolved",
        signature_path=signed_artefact_root / signature_relative,
        blob_path=signed_artefact_root / blob_relative,
        red_reason=None,
    )
