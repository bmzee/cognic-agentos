"""protocol/pack_attestation_resolver.py — installed-pack attestation locator.

Critical-controls module per AGENTS.md (Plugin trust + supply chain).
This is a **TRUST-INPUT PRIMITIVE**: it locates an installed pack's
signed attestation artefacts from a deployment-configured root and
returns a :class:`PackAttestations` for the runtime trust gate
(``protocol/trust_gate.py`` + ``protocol/supply_chain.py``) to verify.
A wrong path or a wrong digest here is a wrong trust decision, so the
resolver fails closed on every malformed-input path with a closed-enum
:class:`PackAttestationResolutionError` reason.

Layout contract. For an installed pack the resolver expects a
deployment-provisioned directory tree::

    <pack_attestation_root>/<distribution_name>/<distribution_version>/
        cosign.sig                     (required, non-empty)
        bundle.sigstore                (required, non-empty)
        sbom.cdx.json                  (required, non-empty)
        slsa-provenance.intoto.json    (required, non-empty)
        <single wheel>.whl             (required, exactly one, non-empty)
        intoto-layout.json             (optional)
        vuln-scan.json                 (optional)
        license-audit.json             (optional)

``distribution_name`` and ``distribution_version`` are pack-controlled
metadata captured by ``PluginRegistry.discover()`` from
``importlib.metadata``; a crafted ``../`` segment in either would
escape the configured root, so every resolved artefact path is
canonicalised and asserted to remain under ``pack_attestation_root``
(catching absolute paths, ``..`` traversal, and symlink escape) before
it is trusted.

Deferred-load invariant. The resolver reads ONLY the attestation
directory tree on disk; it NEVER calls ``EntryPoint.load()`` (no pack
code executes here — the trust gate must clear the cosign signature
over the wheel before any pack code runs).

Path-containment doctrine. The canonical containment guard in this
codebase is ``protocol/trust_gate.py::_canonicalise_under_root``
(``os.path.realpath`` + ``Path.relative_to``). That helper is
module-private and carries its own ``PathTraversalError`` taxonomy
(a ``TrustGateError`` subclass); this resolver replicates the EXACT
``realpath`` + ``relative_to`` logic in :func:`_require_under_root`
rather than importing the private symbol, so the resolver stays a
self-contained trust primitive and maps every escape onto its own
closed-enum ``attestation_path_escapes_root`` reason. (The
``mcp_manifest.py`` lines a sibling sprint pointed at are
``_validate_package_name`` — a regex identifier guard, NOT a
path-containment guard.)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from cognic_agentos.protocol.plugin_registry import DiscoveredPack, PackAttestations

__all__ = [
    "AttestationResolutionReason",
    "PackAttestationResolutionError",
    "resolve_pack_attestations",
]

#: Closed-enum refusal vocabulary. IS the consumer-facing wire contract
#: for :attr:`PackAttestationResolutionError.reason`; the boot-builder
#: (a later sprint) maps these onto pack-registration refusals. A
#: drift detector pins the exact six-value set in the test suite.
AttestationResolutionReason = Literal[
    "attestation_distribution_unidentified",
    "attestation_path_escapes_root",
    "attestation_required_artefact_missing",
    "attestation_required_artefact_empty",
    "attestation_wheel_ambiguous",
    "sbom_digest_unsourced",
]

#: The sentinel ``PluginRegistry.discover()`` stamps onto
#: ``distribution_name`` / ``distribution_version`` when the installed
#: distribution metadata could not be resolved (see
#: ``protocol/plugin_registry.py`` discover()). An unidentified
#: distribution cannot have a trustworthy attestation path, so the
#: resolver refuses BEFORE building any path from it.
_UNIDENTIFIED_DISTRIBUTION = "<unknown>"

# --- canonical attestation basenames ------------------------------------

_COSIGN_SIGNATURE_BASENAME = "cosign.sig"
_SIGSTORE_BUNDLE_BASENAME = "bundle.sigstore"
_SBOM_BASENAME = "sbom.cdx.json"
_SLSA_PROVENANCE_BASENAME = "slsa-provenance.intoto.json"
_INTOTO_LAYOUT_BASENAME = "intoto-layout.json"
_VULN_SCAN_BASENAME = "vuln-scan.json"
_LICENSE_AUDIT_BASENAME = "license-audit.json"

#: JSON key path inside ``slsa-provenance.intoto.json`` that carries the
#: cosign-signed SHA-256 of the SBOM bytes. The runtime trust gate
#: (T7-equivalent) verifies the on-disk SBOM content matches this digest.
_SBOM_DIGEST_KEY_PATH = ("predicate", "buildDefinition", "externalParameters", "sbom_digest_sha256")


class PackAttestationResolutionError(Exception):
    """Fail-closed refusal raised by :func:`resolve_pack_attestations`.

    Carries a closed-enum :attr:`reason` (the wire contract) plus an
    optional human-readable ``detail`` for operator logs. ``__slots__``
    keeps the shape tight — the only mutable attribute is ``reason``.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: AttestationResolutionReason, detail: str = "") -> None:
        self.reason: AttestationResolutionReason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _require_under_root(candidate: Path, root: Path) -> None:
    """Assert ``candidate`` canonicalises to a path under ``root``.

    Replicates the EXACT containment logic of
    ``protocol/trust_gate.py::_canonicalise_under_root``: both paths are
    resolved via ``os.path.realpath`` (which follows symlinks and
    resolves ``..``) and the comparison is ``Path.relative_to``. Catches
    absolute paths, relative traversal (``../escape``), and symlink
    escape. Fail-closed: any violation raises
    ``attestation_path_escapes_root``.
    """
    root_canonical = Path(os.path.realpath(str(root)))
    candidate_canonical = Path(os.path.realpath(str(candidate)))
    try:
        candidate_canonical.relative_to(root_canonical)
    except ValueError as exc:
        raise PackAttestationResolutionError(
            "attestation_path_escapes_root",
            f"{candidate} canonicalises to {candidate_canonical}, "
            f"which is not under {root} (canonical {root_canonical})",
        ) from exc


def _require_present_nonempty(base: Path, basename: str, root: Path) -> Path:
    """Resolve a required fixed-name artefact under ``base``; fail closed
    if it is missing or empty.

    Returns the LOGICAL path (``base / basename``) for the caller — the
    realpath is used only for the security containment check, never
    surfaced, so the returned path is stable under symlinked temp roots.
    """
    candidate = base / basename
    _require_under_root(candidate, root)
    if not candidate.is_file():
        raise PackAttestationResolutionError(
            "attestation_required_artefact_missing",
            f"{basename} (expected at {candidate})",
        )
    if candidate.stat().st_size == 0:
        raise PackAttestationResolutionError(
            "attestation_required_artefact_empty",
            f"{basename} (at {candidate})",
        )
    return candidate


def _resolve_single_wheel(base: Path, root: Path) -> Path:
    """Resolve the single signed wheel (``cosign_blob_path``) under
    ``base``; fail closed on zero, multiple, or empty wheels."""
    wheels = sorted(base.glob("*.whl"))
    if len(wheels) == 0:
        raise PackAttestationResolutionError(
            "attestation_required_artefact_missing",
            f"no *.whl signed-blob found under {base}",
        )
    if len(wheels) > 1:
        raise PackAttestationResolutionError(
            "attestation_wheel_ambiguous",
            f"{len(wheels)} wheels under {base}; the signed blob must be unambiguous",
        )
    wheel = wheels[0]
    _require_under_root(wheel, root)
    if wheel.stat().st_size == 0:
        raise PackAttestationResolutionError(
            "attestation_required_artefact_empty",
            f"signed wheel is empty (at {wheel})",
        )
    return wheel


def _resolve_optional(base: Path, basename: str, root: Path) -> Path | None:
    """Resolve an optional grace-period artefact under ``base``.

    Returns the logical path when present (after the containment check)
    and ``None`` when absent. A present-but-escaping optional still
    fails closed via :func:`_require_under_root` — defence-in-depth.
    """
    candidate = base / basename
    if candidate.is_file():
        _require_under_root(candidate, root)
        return candidate
    return None


def _read_sbom_signed_digest(slsa_provenance_path: Path) -> str:
    """Source the cosign-signed SBOM digest from the SLSA provenance JSON.

    Reads ``slsa-provenance.intoto.json`` and navigates
    ``predicate.buildDefinition.externalParameters.sbom_digest_sha256``.
    Fail-closed: a malformed document (missing key / non-object
    intermediate / invalid JSON) OR a non-string digest value maps to
    ``sbom_digest_unsourced``.
    """
    try:
        document = json.loads(slsa_provenance_path.read_text(encoding="utf-8"))
        value = document
        for key in _SBOM_DIGEST_KEY_PATH:
            value = value[key]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PackAttestationResolutionError(
            "sbom_digest_unsourced",
            f"{_SLSA_PROVENANCE_BASENAME} does not carry "
            f"{'.'.join(_SBOM_DIGEST_KEY_PATH)} as a readable value",
        ) from exc
    if not isinstance(value, str):
        raise PackAttestationResolutionError(
            "sbom_digest_unsourced",
            f"{'.'.join(_SBOM_DIGEST_KEY_PATH)} is {type(value).__name__}, expected str",
        )
    return value


def resolve_pack_attestations(
    pack: DiscoveredPack,
    *,
    pack_attestation_root: Path,
    cosign_trust_root: Path,
) -> PackAttestations:
    """Locate an installed pack's signed attestation artefacts.

    Pure — reads NO settings; both roots are supplied by the caller (the
    boot-builder). For
    ``base = pack_attestation_root / distribution_name / distribution_version``:

    (a) refuse an unidentified distribution BEFORE building any path;
    (b) assert ``base`` (and every resolved artefact) stays canonically
        under ``pack_attestation_root`` — catches a crafted ``../`` in
        the pack-controlled distribution metadata;
    (c) the four fixed-name required artefacts must each exist + be
        non-empty;
    (d) the signed wheel (``cosign_blob_path``) is the single ``*.whl``
        under ``base`` — zero / multiple / empty all fail closed;
    (e) the three grace-period artefacts are ``Path`` if present else
        ``None``;
    (f) the required ``sbom_signed_digest`` is sourced from the SLSA
        provenance JSON;
    (g) ``cosign_trust_root`` passes straight through.

    :raises PackAttestationResolutionError: fail-closed on any malformed
        input, with a closed-enum :attr:`reason`.
    """
    record = pack.record
    distribution_name = record.distribution_name
    distribution_version = record.distribution_version

    # (a) Unidentified distribution -> refuse before any path building.
    if distribution_name == _UNIDENTIFIED_DISTRIBUTION:
        raise PackAttestationResolutionError(
            "attestation_distribution_unidentified",
            "distribution metadata could not be resolved at discovery time",
        )

    base = pack_attestation_root / distribution_name / distribution_version

    # (b) Containment guard on the base directory — primary defence
    # against a crafted ``../`` in distribution_name / distribution_version
    # (each artefact below is additionally containment-checked).
    _require_under_root(base, pack_attestation_root)

    # (c) Fixed-name required artefacts (present + non-empty).
    cosign_signature_path = _require_present_nonempty(
        base, _COSIGN_SIGNATURE_BASENAME, pack_attestation_root
    )
    sigstore_bundle_path = _require_present_nonempty(
        base, _SIGSTORE_BUNDLE_BASENAME, pack_attestation_root
    )
    sbom_path = _require_present_nonempty(base, _SBOM_BASENAME, pack_attestation_root)
    slsa_provenance_path = _require_present_nonempty(
        base, _SLSA_PROVENANCE_BASENAME, pack_attestation_root
    )

    # (d) Single signed wheel.
    cosign_blob_path = _resolve_single_wheel(base, pack_attestation_root)

    # (e) Optional grace-period artefacts.
    intoto_layout_path = _resolve_optional(base, _INTOTO_LAYOUT_BASENAME, pack_attestation_root)
    vuln_scan_path = _resolve_optional(base, _VULN_SCAN_BASENAME, pack_attestation_root)
    license_audit_path = _resolve_optional(base, _LICENSE_AUDIT_BASENAME, pack_attestation_root)

    # (f) Source the cosign-signed SBOM digest from the SLSA provenance.
    sbom_signed_digest = _read_sbom_signed_digest(slsa_provenance_path)

    # (g) + (h) Pass the trust root straight through and return.
    return PackAttestations(
        cosign_signature_path=cosign_signature_path,
        cosign_blob_path=cosign_blob_path,
        cosign_trust_root=cosign_trust_root,
        sbom_path=sbom_path,
        sbom_signed_digest=sbom_signed_digest,
        sigstore_bundle_path=sigstore_bundle_path,
        slsa_provenance_path=slsa_provenance_path,
        intoto_layout_path=intoto_layout_path,
        vuln_scan_path=vuln_scan_path,
        license_audit_path=license_audit_path,
    )
