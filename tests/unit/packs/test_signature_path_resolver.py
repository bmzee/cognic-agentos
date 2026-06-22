"""Sprint 7B.3 T9 Slice B — signature path resolver tests.

Per the plan-of-record §466-489 + R3 P2 #2 + R4 P2 #4 + R6 P2 #4 +
R7 P2 #1: ``packs/_signature_path_resolver.py`` is a pure-functional
module-private helper the T9 approve handler uses to project the
cosign signature + signed-blob paths out of a pack's persisted
manifest.

**R6 P2 #4 relative-paths + bundle-root contract.** ``signature_path``
comes from the unique ``cosign.sig`` entry in the manifest's flat
``[supply_chain].attestation_paths`` list (manifest-RELATIVE);
``blob_path`` comes from the explicit ``[supply_chain].blob_path``
field (also manifest-relative). The resolver concatenates each with
the submit-declared ``signed_artefact_root`` bundle root to produce
ABSOLUTE paths for ``TrustGate.verify_pack_signature``. Path-traversal
safe. Pure-functional — no filesystem I/O (the T9 handler does the
existence check separately).

**R7 P2 #1.** The 9 resolver-emitted red-reasons (R7 seeded 8; the
cosign-3.x bridge added the reused ``signature_bundle_path_unreachable``
as the 9th) are all members of the unified
13-value :data:`SignatureRedReason` Literal in ``packs/approval_gates``
— the resolver returns ``SignatureRedReason | None`` directly so the
handler threads ``resolution.red_reason`` into
``SignatureGateInput.red_reason`` with NO translation table.
"""

from __future__ import annotations

import dataclasses
import typing
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.packs._signature_path_resolver import (
    SignaturePathResolution,
    resolve_signature_paths,
)
from cognic_agentos.packs.approval_gates import SignatureRedReason

_ROOT = Path("/var/cognic/bundles/pack-x")

#: The 9 resolver-EMITTED red-reasons, all members of the unified composer
#: ``SignatureRedReason`` Literal (R7 P2 #1 seeded 8; the cosign-3.x bridge
#: added the REUSED ``signature_bundle_path_unreachable`` as the 9th — every
#: bundle-path failure maps to it, introducing NO new wire value).
_RESOLVER_RED_REASONS = (
    "signature_cosign_sig_not_in_attestation_paths",
    "signature_multiple_cosign_sig_entries_ambiguous",
    "signature_blob_path_not_declared_in_manifest",
    "signature_path_must_be_relative",
    "signature_blob_path_must_be_relative",
    "signature_signed_artefact_root_not_declared_at_submit",
    "signature_path_traversal_rejected",
    "signature_blob_path_traversal_rejected",
    "signature_bundle_path_unreachable",
)


def _manifest(
    *,
    attestation_paths: Any = ("cosign.sig", "bundle.sigstore"),
    blob_path: Any = "pack_x-1.0.0-py3-none-any.whl",
    include_supply_chain: bool = True,
    include_blob_path: bool = True,
) -> dict[str, Any]:
    """Build a manifest dict with a tweakable ``[supply_chain]`` block."""
    if not include_supply_chain:
        return {"pack": {"kind": "tool", "version": "1.0.0"}}
    supply_chain: dict[str, Any] = {}
    if attestation_paths is not None:
        supply_chain["attestation_paths"] = (
            list(attestation_paths)
            if isinstance(attestation_paths, (list, tuple))
            else attestation_paths
        )
    if include_blob_path:
        supply_chain["blob_path"] = blob_path
    return {"pack": {"kind": "tool", "version": "1.0.0"}, "supply_chain": supply_chain}


class TestSprint7B3T9SliceBHappyPath:
    """Green path — both relative declarations + a bundle root."""

    def test_resolves_absolute_paths_from_root_plus_relative(self) -> None:
        resolution = resolve_signature_paths(_manifest(), signed_artefact_root=_ROOT)
        assert resolution.outcome == "resolved"
        assert resolution.red_reason is None
        assert resolution.signature_path == _ROOT / "cosign.sig"
        assert resolution.blob_path == _ROOT / "pack_x-1.0.0-py3-none-any.whl"

    def test_cosign_sig_basename_match_works_in_a_subdir(self) -> None:
        # An attestation entry of "sigs/cosign.sig" still resolves —
        # the match is on the basename, not the full relative string.
        manifest = _manifest(attestation_paths=("sigs/cosign.sig", "bundle.sigstore"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "resolved"
        assert resolution.signature_path == _ROOT / "sigs/cosign.sig"

    def test_resolver_does_no_filesystem_io(self) -> None:
        # The bundle root does not exist on disk — the resolver still
        # resolves (it only projects + concatenates; the T9 handler
        # owns the .exists() check).
        nonexistent = Path("/nonexistent/cognic/bundle-root-xyz")
        resolution = resolve_signature_paths(_manifest(), signed_artefact_root=nonexistent)
        assert resolution.outcome == "resolved"
        assert resolution.signature_path == nonexistent / "cosign.sig"


class TestSprint7B3T9SliceBSignatureFailureModes:
    """Failures sourced from the ``cosign.sig`` attestation entry."""

    def test_zero_cosign_sig_entries(self) -> None:
        manifest = _manifest(attestation_paths=("bundle.sigstore", "sbom.spdx.json"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "signature_missing"
        assert resolution.red_reason == "signature_cosign_sig_not_in_attestation_paths"
        assert resolution.signature_path is None
        assert resolution.blob_path is None

    def test_attestation_paths_missing_entirely(self) -> None:
        manifest = _manifest(attestation_paths=None)
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "signature_missing"
        assert resolution.red_reason == "signature_cosign_sig_not_in_attestation_paths"

    def test_supply_chain_block_missing_entirely(self) -> None:
        manifest = _manifest(include_supply_chain=False)
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "signature_missing"
        assert resolution.red_reason == "signature_cosign_sig_not_in_attestation_paths"

    def test_multiple_cosign_sig_entries_ambiguous(self) -> None:
        manifest = _manifest(attestation_paths=("cosign.sig", "sigs/cosign.sig"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "ambiguous"
        assert resolution.red_reason == "signature_multiple_cosign_sig_entries_ambiguous"
        assert resolution.signature_path is None

    def test_absolute_signature_path_rejected(self) -> None:
        manifest = _manifest(attestation_paths=("/abs/cosign.sig", "bundle.sigstore"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "signature_missing"
        assert resolution.red_reason == "signature_path_must_be_relative"

    def test_signature_path_traversal_rejected(self) -> None:
        manifest = _manifest(attestation_paths=("../escape/cosign.sig",))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "signature_missing"
        assert resolution.red_reason == "signature_path_traversal_rejected"


class TestSprint7B3T9SliceBBlobFailureModes:
    """Failures sourced from the ``[supply_chain].blob_path`` field."""

    def test_blob_path_missing_from_manifest(self) -> None:
        manifest = _manifest(include_blob_path=False)
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "blob_missing"
        assert resolution.red_reason == "signature_blob_path_not_declared_in_manifest"
        assert resolution.signature_path is None
        assert resolution.blob_path is None

    def test_blob_path_non_string_treated_as_not_declared(self) -> None:
        manifest = _manifest(blob_path=12345)
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "blob_missing"
        assert resolution.red_reason == "signature_blob_path_not_declared_in_manifest"

    def test_absolute_blob_path_rejected(self) -> None:
        manifest = _manifest(blob_path="/abs/pack.whl")
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "blob_missing"
        assert resolution.red_reason == "signature_blob_path_must_be_relative"

    def test_blob_path_traversal_rejected(self) -> None:
        manifest = _manifest(blob_path="../escape/pack.whl")
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "blob_missing"
        assert resolution.red_reason == "signature_blob_path_traversal_rejected"


class TestSprint7B3T9SliceBRootFailureMode:
    """Failure sourced from a missing submit-declared bundle root."""

    def test_signed_artefact_root_none_rejected(self) -> None:
        resolution = resolve_signature_paths(_manifest(), signed_artefact_root=None)
        assert resolution.outcome == "root_missing"
        assert resolution.red_reason == "signature_signed_artefact_root_not_declared_at_submit"
        assert resolution.signature_path is None
        assert resolution.blob_path is None


class TestSprint7B3T9SliceBPrecedence:
    """The resolver's documented check precedence: signature → blob → bundle → root."""

    def test_signature_failure_takes_precedence_over_blob_failure(self) -> None:
        # Both the cosign.sig entry AND the blob_path field are absent.
        manifest = _manifest(attestation_paths=("bundle.sigstore",), include_blob_path=False)
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.red_reason == "signature_cosign_sig_not_in_attestation_paths"

    def test_blob_failure_takes_precedence_over_root_failure(self) -> None:
        # blob_path absent AND signed_artefact_root None — blob wins.
        manifest = _manifest(include_blob_path=False)
        resolution = resolve_signature_paths(manifest, signed_artefact_root=None)
        assert resolution.red_reason == "signature_blob_path_not_declared_in_manifest"

    def test_bundle_failure_takes_precedence_over_root_failure(self) -> None:
        # cosign.sig + blob_path declared, but bundle.sigstore is absent from
        # attestation_paths AND signed_artefact_root is None — the cosign-3.x
        # bundle check (precedence signature → blob → bundle → root) fires
        # BEFORE the root-missing check, so the reason is bundle-unreachable.
        manifest = _manifest(attestation_paths=("cosign.sig",))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=None)
        assert resolution.red_reason == "signature_bundle_path_unreachable"


class TestSprint7B3T9SliceBContract:
    """Structural + vocabulary contract."""

    def test_resolution_is_frozen(self) -> None:
        resolution = resolve_signature_paths(_manifest(), signed_artefact_root=_ROOT)
        with pytest.raises(dataclasses.FrozenInstanceError):
            resolution.outcome = "ambiguous"  # type: ignore[misc]

    def test_all_nine_resolver_red_reasons_are_members_of_signature_red_reason(
        self,
    ) -> None:
        composer_reasons = set(typing.get_args(SignatureRedReason))
        for reason in _RESOLVER_RED_REASONS:
            assert reason in composer_reasons, (
                f"{reason!r} drifted out of the composer SignatureRedReason Literal"
            )
        # The cosign-3.x bridge added signature_bundle_path_unreachable as the
        # 9th resolver-emitted reason — it must already be in the closed enum
        # (reused, NOT a new wire value).
        assert "signature_bundle_path_unreachable" in _RESOLVER_RED_REASONS
        assert "signature_bundle_path_unreachable" in composer_reasons

    def test_resolver_red_reason_field_is_typed_against_signature_red_reason(
        self,
    ) -> None:
        # The dataclass field's annotation IS SignatureRedReason | None
        # — no standalone SignaturePathRedReason Literal was recreated
        # (R7 P2 #1 — it was DELETED; implementers MUST NOT recreate it).
        hints = typing.get_type_hints(SignaturePathResolution)
        assert hints["red_reason"] == (SignatureRedReason | None)

    @pytest.mark.parametrize(
        ("manifest", "root"),
        [
            (_manifest(attestation_paths=("bundle.sigstore",)), _ROOT),
            (_manifest(attestation_paths=("cosign.sig", "cosign.sig")), _ROOT),
            (_manifest(include_blob_path=False), _ROOT),
            (_manifest(), None),
        ],
    )
    def test_resolver_invents_no_path_on_any_failure(
        self, manifest: dict[str, Any], root: Path | None
    ) -> None:
        resolution = resolve_signature_paths(manifest, signed_artefact_root=root)
        assert resolution.outcome != "resolved"
        assert resolution.signature_path is None
        assert resolution.blob_path is None


class TestSprint7B3T9BundlePathResolution:
    """cosign 3.x bundle-path projection — basename match from
    [supply_chain].attestation_paths (NOT a cosign.sig sibling). Every
    failure maps to the EXISTING signature_bundle_path_unreachable."""

    def test_resolves_bundle_by_basename(self) -> None:
        # _manifest()'s default attestation_paths already carries
        # "bundle.sigstore".
        resolution = resolve_signature_paths(_manifest(), signed_artefact_root=_ROOT)
        assert resolution.outcome == "resolved"
        assert resolution.bundle_path == _ROOT / "bundle.sigstore"

    def test_resolves_bundle_in_custom_dir_by_basename(self) -> None:
        # The NON-SIBLING case: the bundle lives in custom/dir/, not next
        # to cosign.sig. The basename match still resolves it — a
        # sibling-only derivation would wrongly reject this recognised
        # manifest shape (the supply-chain evidence projector accepts it).
        manifest = _manifest(attestation_paths=("cosign.sig", "custom/dir/bundle.sigstore"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "resolved"
        assert resolution.bundle_path == _ROOT / "custom/dir/bundle.sigstore"

    def test_bundle_absent_maps_to_unreachable(self) -> None:
        manifest = _manifest(attestation_paths=("cosign.sig",))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "bundle_missing"
        assert resolution.red_reason == "signature_bundle_path_unreachable"
        assert resolution.bundle_path is None

    def test_multiple_bundle_entries_ambiguous_maps_to_unreachable(self) -> None:
        manifest = _manifest(
            attestation_paths=("cosign.sig", "bundle.sigstore", "x/bundle.sigstore")
        )
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.outcome == "bundle_missing"
        assert resolution.red_reason == "signature_bundle_path_unreachable"
        assert resolution.bundle_path is None

    def test_absolute_bundle_path_maps_to_unreachable(self) -> None:
        manifest = _manifest(attestation_paths=("cosign.sig", "/abs/bundle.sigstore"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.red_reason == "signature_bundle_path_unreachable"
        assert resolution.bundle_path is None

    def test_bundle_path_traversal_maps_to_unreachable(self) -> None:
        manifest = _manifest(attestation_paths=("cosign.sig", "../escape/bundle.sigstore"))
        resolution = resolve_signature_paths(manifest, signed_artefact_root=_ROOT)
        assert resolution.red_reason == "signature_bundle_path_unreachable"
        assert resolution.bundle_path is None

    def test_bundle_reason_introduces_no_new_signature_red_reason_value(self) -> None:
        # signature_bundle_path_unreachable is one of the 5 ORIGINAL
        # gate-1 reasons — already in the Literal; the resolver adds NO
        # new value (the closed SignatureRedReason enum stays frozen).
        assert "signature_bundle_path_unreachable" in set(typing.get_args(SignatureRedReason))
