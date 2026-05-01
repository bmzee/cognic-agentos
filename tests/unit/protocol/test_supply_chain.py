"""Sprint 4 T7 — supply-chain attestation pipeline tests.

≥95% line / ≥90% branch coverage per AGENTS.md critical-controls
discipline (refusal-grade gates).

Test classes:

  * ``TestSBOMMandatoryFloor`` — SBOM missing / file-not-regular /
    SHA-256 mismatch / empty signed digest.
  * ``TestSLSAVerification`` — happy path; predicate-only; missing
    buildType / builder.id; non-dict; malformed JSON; unreadable
    file.
  * ``TestIntotoVerification`` — happy path; missing steps / expires;
    empty steps; malformed JSON; non-dict.
  * ``TestVulnVerification`` — Grype JSON parsing; max_cvss extraction;
    critical_count; known_exploit (kev / known_exploit fields);
    parse-failure tolerance.
  * ``TestLicenseVerification`` — flat license list; per-artifact
    list; ``{"value": "..."}`` entries; allowlist filter; empty
    allowlist means no constraint.
  * ``TestPipelineGrade`` — full grade when all four grace-period
    pass; partial when any missing; partial when threshold breach;
    partial when license disallowed.
  * ``TestPipelineTamperedAlwaysRefuses`` — every "tampered" failure
    raises SBOM/SLSA/IntotoTampered, NEVER downgrades to partial.
  * ``TestExceptionTaxonomy`` — every typed failure subclasses
    SupplyChainError so T10 can catch the base.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.supply_chain import (
    AttestationResult,
    IntotoTampered,
    LicenseResult,
    SBOMMissing,
    SBOMTampered,
    SLSAResult,
    SLSATampered,
    SupplyChainError,
    SupplyChainPipeline,
    VulnResult,
    VulnThresholds,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path: Path) -> Any:
    return build_settings_without_env_file().model_copy(
        update={"local_object_store_root": tmp_path / "obj-store"}
    )


@pytest.fixture
def pipeline(settings: Any) -> SupplyChainPipeline:
    return SupplyChainPipeline(settings=settings)


# --- file-fixture helpers --------------------------------------------------


def _write_sbom(
    path: Path,
    content: bytes = b'{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}',
) -> str:
    """Write SBOM bytes (CycloneDX 1.5 by default — passes the format
    check in ``_verify_sbom``). Returns the hex SHA-256.

    Tests that need a non-CycloneDX or malformed SBOM call
    ``write_bytes`` directly and compute their own digest.
    """
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _write_slsa(path: Path, **overrides: Any) -> Path:
    """Write a valid SLSA v1.0 in-toto Statement; allow per-test
    overrides via dotted path (``buildDefinition.buildType=`` etc).

    The default predicate declares ``slsaLevel=3`` so happy-path
    tests pass the L3+ pipeline gate (R3 reviewer-P2 fix). Tests
    that need a lower level supply ``predicate.slsaLevel=1`` etc
    via overrides.
    """
    statement: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/actions/runner/v1",
                "externalParameters": {
                    "configSource": "git+https://github.com/cognic/cognic-tool-demo@v1.0.0"
                },
            },
            "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
            "slsaLevel": 3,
        },
    }
    # Apply overrides (test helpers; not pretty but small).
    for dotted, value in overrides.items():
        parts = dotted.split(".")
        cursor: Any = statement
        for part in parts[:-1]:
            cursor = cursor[part]
        if value is _DELETE:
            del cursor[parts[-1]]
        else:
            cursor[parts[-1]] = value
    path.write_text(json.dumps(statement))
    return path


_DELETE = object()


def _write_intoto(path: Path, **overrides: Any) -> Path:
    layout: dict[str, Any] = {
        "_type": "https://in-toto.io/Layout/v1",
        "expires": "2027-01-01T00:00:00Z",
        "steps": [
            {"name": "build", "expected_command": ["python", "-m", "build"]},
            {"name": "sign", "expected_command": ["cosign", "sign-blob"]},
        ],
    }
    for dotted, value in overrides.items():
        parts = dotted.split(".")
        cursor: Any = layout
        for part in parts[:-1]:
            cursor = cursor[part]
        if value is _DELETE:
            del cursor[parts[-1]]
        else:
            cursor[parts[-1]] = value
    path.write_text(json.dumps(layout))
    return path


def _write_vuln_scan(path: Path, matches: list[dict[str, Any]] | None = None) -> Path:
    body = {"matches": matches if matches is not None else []}
    path.write_text(json.dumps(body))
    return path


def _write_license_audit(
    path: Path,
    licenses: list[str] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
) -> Path:
    body: dict[str, Any] = {}
    if licenses is not None:
        body["licenses"] = licenses
    if artifacts is not None:
        body["artifacts"] = artifacts
    path.write_text(json.dumps(body))
    return path


def _make_full_pack_attestations(
    tmp_path: Path, *, license_list: list[str] | None = None
) -> dict[str, Any]:
    """Produce a complete clean attestation set for happy-path tests."""
    sbom = tmp_path / "sbom.cdx.json"
    digest = _write_sbom(sbom, b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}')
    slsa = _write_slsa(tmp_path / "slsa.json")
    intoto = _write_intoto(tmp_path / "layout.json")
    vuln = _write_vuln_scan(tmp_path / "vuln.json", matches=[])
    licenses = _write_license_audit(
        tmp_path / "license.json", licenses=license_list or ["MIT", "Apache-2.0"]
    )
    return {
        "sbom_path": sbom,
        "sbom_signed_digest": digest,
        "slsa_provenance_path": slsa,
        "intoto_layout_path": intoto,
        "vuln_scan_path": vuln,
        "license_audit_path": licenses,
    }


# ---------------------------------------------------------------------------
# TestSBOMMandatoryFloor
# ---------------------------------------------------------------------------


class TestSBOMMandatoryFloor:
    def test_missing_sbom_raises_sbom_missing(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        with pytest.raises(SBOMMissing, match="not found"):
            pipeline.verify(
                sbom_path=tmp_path / "absent.json",
                sbom_signed_digest="sha256:" + "a" * 64,
            )

    def test_sbom_path_is_directory_raises_sbom_missing(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        d = tmp_path / "im-a-dir"
        d.mkdir()
        with pytest.raises(SBOMMissing, match="not a regular file"):
            pipeline.verify(sbom_path=d, sbom_signed_digest="sha256:" + "a" * 64)

    def test_sbom_digest_mismatch_raises_sbom_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        sbom.write_bytes(b'{"bomFormat":"CycloneDX"}')
        # Compute digest of a DIFFERENT body.
        wrong = hashlib.sha256(b"not-the-sbom").hexdigest()
        with pytest.raises(SBOMTampered, match="SBOM SHA-256 mismatch"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=wrong)

    def test_sbom_digest_matches_with_sha256_prefix(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Common operator pattern: digest reported as ``sha256:<hex>``."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        # Should not raise.
        pipeline.verify(sbom_path=sbom, sbom_signed_digest=f"sha256:{digest}")

    def test_empty_signed_digest_raises_sbom_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        _write_sbom(sbom)
        with pytest.raises(SBOMTampered, match="must be a non-empty str"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest="")

    def test_whitespace_only_signed_digest_raises_sbom_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        _write_sbom(sbom)
        with pytest.raises(SBOMTampered, match="must be a non-empty str"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest="   ")

    def test_arbitrary_signed_bytes_rejected_as_not_sbom(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R3 reviewer-P2 fix: a digest-only check let arbitrary
        signed bytes (e.g. a wheel itself, an image, random JSON)
        clear the mandatory SBOM floor. ADR-016 says the SBOM proves
        dependency inventory — bytes that don't parse as CycloneDX
        or SPDX 2.3+ are now rejected even when the digest matches."""
        sbom = tmp_path / "sbom.json"
        body = b"this is not an SBOM, just bytes"
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with pytest.raises(SBOMTampered, match="not valid UTF-8 JSON"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_unrelated_json_rejected_as_not_sbom(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """A signed JSON body that lacks ``bomFormat`` or
        ``spdxVersion`` is not an SBOM — refuse."""
        sbom = tmp_path / "sbom.json"
        body = json.dumps({"name": "cognic-tool-demo", "version": "1.0.0"}).encode()
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with pytest.raises(SBOMTampered, match="neither CycloneDX nor SPDX"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_json_array_root_rejected_as_not_sbom(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        body = b"[1, 2, 3]"
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with pytest.raises(SBOMTampered, match="not a JSON object"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_cyclonedx_without_specversion_rejected(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        body = json.dumps({"bomFormat": "CycloneDX"}).encode()
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with pytest.raises(SBOMTampered, match="lacks specVersion"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_spdx_2_3_accepted(self, pipeline: SupplyChainPipeline, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        body = json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}).encode()
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        # Should not raise.
        pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_spdx_2_2_rejected_below_minimum(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        body = json.dumps({"spdxVersion": "SPDX-2.2", "SPDXID": "SPDXRef-DOCUMENT"}).encode()
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with pytest.raises(SBOMTampered, match=r"requires SPDX-2\.3 or later"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_spdx_unparseable_version_rejected(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """SPDX prefix matches but the minor version isn't a parseable
        integer — refuse rather than guess."""
        sbom = tmp_path / "sbom.json"
        body = json.dumps({"spdxVersion": "SPDX-2.banana"}).encode()
        sbom.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        with pytest.raises(SBOMTampered, match="unparseable spdxVersion"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)

    def test_sbom_unreadable_after_exists_check_raises_sbom_missing(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """R4 reviewer-P2 fix: between ``exists()/is_file()`` and the
        single ``read_bytes()`` call, an attacker (or filesystem
        race) could remove / permission-flip the file. The wrapper
        catches OSError and re-raises as ``SBOMMissing`` so T10's
        ``except SupplyChainError`` keeps catching it. Without the
        wrap a raw FileNotFoundError / PermissionError would escape.
        """
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)

        original_read_bytes = Path.read_bytes

        def _race_read(self: Path, *args: Any, **kwargs: Any) -> bytes:
            if self.name == sbom.name:
                raise PermissionError(13, "EACCES — race after exists()")
            return original_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", _race_read)
        with pytest.raises(SBOMMissing, match="became unreadable"):
            pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest)


# ---------------------------------------------------------------------------
# TestSLSAVerification
# ---------------------------------------------------------------------------


class TestSLSAVerification:
    def test_valid_slsa_extracts_fields(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        result = pipeline.verify(**artefacts)
        assert result.slsa is not None
        assert result.slsa.build_type == "https://github.com/actions/runner/v1"
        assert result.slsa.builder_id == "https://github.com/actions/runner"
        assert result.slsa.config_source is not None

    def test_bare_predicate_form_accepted(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """SLSA predicate without the in-toto Statement envelope is
        accepted — the trust gate's cosign verify already covered the
        envelope; T7 just needs the field shape."""
        bare = {
            "buildDefinition": {
                "buildType": "https://example.com/build/v1",
                "externalParameters": {},
            },
            "runDetails": {"builder": {"id": "https://example.com/builder"}},
            "slsaLevel": 3,
        }
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa_path = tmp_path / "slsa.json"
        slsa_path.write_text(json.dumps(bare))
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            slsa_provenance_path=slsa_path,
        )
        assert result.slsa is not None
        assert result.slsa.build_type == "https://example.com/build/v1"
        assert result.slsa.level == 3

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n", "   \t\n"])
    def test_blank_buildType_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path, blank: str
    ) -> None:
        """R7 reviewer-P2 fix: whitespace-only ``buildType`` used to
        pass the truthiness check (``not " "`` is False) and let an
        otherwise-blank Statement verify. Now stripped + required
        non-empty, mirroring the configSource normalisation from R5."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(
            tmp_path / "slsa.json",
            **{"predicate.buildDefinition.buildType": blank},
        )
        with pytest.raises(SLSATampered, match=r"buildDefinition\.buildType"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n", "   \t\n"])
    def test_blank_builder_id_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path, blank: str
    ) -> None:
        """Same R7 reviewer-P2 fix for the runDetails.builder.id field."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(
            tmp_path / "slsa.json",
            **{"predicate.runDetails.builder.id": blank},
        )
        with pytest.raises(SLSATampered, match=r"runDetails\.builder\.id"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_buildType_and_builder_id_with_surrounding_whitespace_stripped(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Legitimate values with surrounding whitespace get trimmed."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(
            tmp_path / "slsa.json",
            **{
                "predicate.buildDefinition.buildType": "  https://example.com/build/v1  ",
                "predicate.runDetails.builder.id": "\t  https://example.com/builder\n",
            },
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            slsa_provenance_path=slsa,
        )
        assert result.slsa is not None
        assert result.slsa.build_type == "https://example.com/build/v1"
        assert result.slsa.builder_id == "https://example.com/builder"

    def test_missing_buildType_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(
            tmp_path / "slsa.json", **{"predicate.buildDefinition.buildType": _DELETE}
        )
        with pytest.raises(SLSATampered, match=r"buildDefinition\.buildType"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_missing_builder_id_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(tmp_path / "slsa.json", **{"predicate.runDetails.builder.id": _DELETE})
        with pytest.raises(SLSATampered, match=r"runDetails\.builder\.id"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_malformed_json_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = tmp_path / "slsa.json"
        slsa.write_text("{not json")
        with pytest.raises(SLSATampered, match="not valid JSON"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_json_array_root_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = tmp_path / "slsa.json"
        slsa.write_text("[1, 2, 3]")
        with pytest.raises(SLSATampered, match="not a JSON object"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    @pytest.mark.parametrize(
        "bad_predicate_type",
        [
            "https://example.com/bogus",
            "https://slsa-typo.dev/",
            # R6 reviewer-P2 fix: same-domain near-miss must be rejected.
            # Without the trailing-slash boundary on the prefix, this
            # value would pass via ``startswith('https://slsa.dev/provenance')``.
            "https://slsa.dev/provenance-not-real/v1",
            # SLSA spec page (without ``/`` boundary the bare prefix
            # would match) — also a near-miss.
            "https://slsa.dev/provenanced/v1",
            123,
            True,
            [1, 2],
        ],
    )
    def test_invalid_predicateType_raises_slsa_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        bad_predicate_type: Any,
    ) -> None:
        """R5 reviewer-P2 fix: a Statement with predicateType present
        but wrong (mismatched URI string OR non-string) MUST raise
        SLSATampered, NOT silently fall through to bare-form
        interpretation. Without this guard a malformed Statement
        with valid top-level buildDefinition + runDetails could pass
        as legitimate provenance.
        """
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = tmp_path / "slsa.json"
        # Compose a Statement whose top-level fields ARE valid (so a
        # bare-form fall-through would otherwise verify) but whose
        # predicateType is invalid.
        slsa.write_text(
            json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": bad_predicate_type,
                    "buildDefinition": {
                        "buildType": "https://example.com/build/v1",
                        "externalParameters": {"configSource": "git+https://example.com@v1"},
                    },
                    "runDetails": {"builder": {"id": "https://example.com/builder"}},
                    "slsaLevel": 3,
                }
            )
        )
        with pytest.raises(SLSATampered, match="invalid predicateType"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_predicate_not_dict_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = tmp_path / "slsa.json"
        slsa.write_text(
            json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "predicate": "i-am-not-a-dict",
                }
            )
        )
        with pytest.raises(SLSATampered, match=r"predicate.*not a JSON object"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_missing_buildDefinition_raises_slsa_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(tmp_path / "slsa.json", **{"predicate.buildDefinition": _DELETE})
        with pytest.raises(SLSATampered, match="missing buildDefinition"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_missing_externalParameters_parsed_but_demotes(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """``externalParameters`` is parsed-as-None at the verifier
        level (not a tampered structural failure), but the pipeline
        demotes to partial because configSource is part of the SLSA
        full-grade requirement (R4 reviewer-P2 fix)."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(
            tmp_path / "slsa.json",
            **{"predicate.buildDefinition.externalParameters": _DELETE},
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            slsa_provenance_path=slsa,
        )
        # Verifier returns a structurally-valid result with
        # config_source=None (no SLSATampered raise).
        assert result.slsa is not None
        assert result.slsa.config_source is None
        # Pipeline demotes: full grade requires configSource.
        assert result.verified["slsa"] is False
        assert any("configSource" in f for f in result.findings)

    @pytest.mark.parametrize("blank_value", ["", "   ", "\t\n"])
    def test_blank_configSource_normalised_to_none_and_demotes(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        blank_value: str,
    ) -> None:
        """R5 reviewer-P2 fix: an empty / whitespace-only
        ``configSource`` is not a usable source reference. The
        verifier strips the value and treats blank-after-strip the
        same as None — pipeline demotes consistently regardless of
        whether the field is absent, blank, or non-string."""
        artefacts = _make_full_pack_attestations(tmp_path)
        _write_slsa(
            artefacts["slsa_provenance_path"],
            **{"predicate.buildDefinition.externalParameters.configSource": blank_value},
        )
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "partial"
        assert result.verified["slsa"] is False
        assert result.slsa is not None
        assert result.slsa.config_source is None
        assert any("configSource" in f for f in result.findings)

    def test_configSource_with_surrounding_whitespace_is_stripped(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """The verifier strips leading/trailing whitespace from
        configSource so a tenant accidentally indenting their
        provenance JSON doesn't lose the field."""
        artefacts = _make_full_pack_attestations(tmp_path)
        _write_slsa(
            artefacts["slsa_provenance_path"],
            **{"predicate.buildDefinition.externalParameters.configSource": "  git+https://x@v1  "},
        )
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.slsa is not None
        assert result.slsa.config_source == "git+https://x@v1"

    def test_missing_configSource_demotes_even_at_l3(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """R4 reviewer-P2 regression: SLSA L3 with all other
        attestations clean MUST still demote to partial when
        configSource is absent — the plan + ADR-016 require all three
        of buildType + builder.id + invocation.configSource for
        full grade. Previously a pack with slsaLevel=3 and no
        configSource earned full."""
        artefacts = _make_full_pack_attestations(tmp_path)
        # Strip externalParameters from the otherwise-full provenance.
        _write_slsa(
            artefacts["slsa_provenance_path"],
            **{"predicate.buildDefinition.externalParameters": _DELETE},
        )
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "partial"
        assert result.verified["slsa"] is False
        assert result.slsa is not None
        assert result.slsa.level == 3
        assert result.slsa.config_source is None
        assert any("configSource" in f for f in result.findings)

    def test_level_l3_full_grade_when_attestation_complete(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """R3 reviewer-P2: SLSA level 3 (or higher) with all other
        attestations clean → full grade. The default fixture asserts
        slsaLevel=3."""
        artefacts = _make_full_pack_attestations(tmp_path)
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "full"
        assert result.slsa is not None
        assert result.slsa.level == 3
        assert result.verified["slsa"] is True

    @pytest.mark.parametrize("level", [1, 2])
    def test_level_below_l3_demotes_to_partial(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        level: int,
    ) -> None:
        """R3 reviewer-P2: per ADR-016, SLSA L1 / L2 falls to
        ``partial`` during the grace period — NOT full, even when
        every other attestation is clean."""
        artefacts = _make_full_pack_attestations(tmp_path)
        # Override the default level=3 in the fixture file.
        _write_slsa(artefacts["slsa_provenance_path"], **{"predicate.slsaLevel": level})
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "partial"
        assert result.verified["slsa"] is False
        assert result.slsa is not None
        assert result.slsa.level == level
        assert any(f"level={level}" in f for f in result.findings)

    def test_level_l4_accepted_at_full_grade(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """L4 (the spec ceiling) is at-or-above L3 → full grade."""
        artefacts = _make_full_pack_attestations(tmp_path)
        _write_slsa(artefacts["slsa_provenance_path"], **{"predicate.slsaLevel": 4})
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "full"
        assert result.slsa is not None
        assert result.slsa.level == 4

    def test_missing_level_demotes_to_partial(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """No ``slsaLevel`` field means the producer never declared a
        level — treated the same as below-L3 for grading. Sprint
        7B/13.5 will introduce builder.id-based level inference."""
        artefacts = _make_full_pack_attestations(tmp_path)
        _write_slsa(artefacts["slsa_provenance_path"], **{"predicate.slsaLevel": _DELETE})
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "partial"
        assert result.verified["slsa"] is False
        assert result.slsa is not None
        assert result.slsa.level is None

    def test_alternate_snake_case_level_field_accepted(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """Some build platforms emit ``slsa_level`` (snake_case) instead
        of ``slsaLevel`` (camelCase). T7 honours both."""
        artefacts = _make_full_pack_attestations(tmp_path)
        # Strip camelCase and add snake_case.
        _write_slsa(
            artefacts["slsa_provenance_path"],
            **{"predicate.slsaLevel": _DELETE, "predicate.slsa_level": 3},
        )
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.slsa is not None
        assert result.slsa.level == 3

    @pytest.mark.parametrize("bad_level", [0, -1, 5, 99])
    def test_level_outside_valid_range_raises_slsa_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        bad_level: int,
    ) -> None:
        """SLSA levels are 1..4. Out-of-range values are tampered."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(tmp_path / "slsa.json", **{"predicate.slsaLevel": bad_level})
        with pytest.raises(SLSATampered, match=r"outside the valid 1\.\.4 range"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_level_bool_rejected_as_slsa_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """``bool`` is a subtype of ``int`` in Python — without an
        explicit guard, ``slsaLevel: true`` would silently coerce to
        1 and let an unattested pack pass."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(tmp_path / "slsa.json", **{"predicate.slsaLevel": True})
        with pytest.raises(SLSATampered, match="bool="):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_level_string_rejected_as_slsa_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(tmp_path / "slsa.json", **{"predicate.slsaLevel": "3"})
        with pytest.raises(SLSATampered, match=r"expected int 1\.\.4"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )


# ---------------------------------------------------------------------------
# TestIntotoVerification
# ---------------------------------------------------------------------------


class TestIntotoVerification:
    def test_valid_layout_passes(self, pipeline: SupplyChainPipeline, tmp_path: Path) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        result = pipeline.verify(**artefacts)
        assert result.verified["intoto"] is True

    def test_missing_steps_raises_intoto_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(tmp_path / "layout.json", **{"steps": _DELETE})
        with pytest.raises(IntotoTampered, match="steps"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_empty_steps_raises_intoto_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(tmp_path / "layout.json", **{"steps": []})
        with pytest.raises(IntotoTampered, match="empty 'steps'"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_missing_expires_raises_intoto_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(tmp_path / "layout.json", **{"expires": _DELETE})
        with pytest.raises(IntotoTampered, match="expires"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    @pytest.mark.parametrize("blank_expires", ["", " ", "\t", "\n", "   \t\n"])
    def test_blank_expires_raises_intoto_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        blank_expires: str,
    ) -> None:
        """R7 reviewer-P2 fix: whitespace-only ``expires`` used to
        pass the truthiness check. Now stripped + required non-empty."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(tmp_path / "layout.json", **{"expires": blank_expires})
        with pytest.raises(IntotoTampered, match="expires"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_non_dict_step_entry_raises_intoto_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """R8 reviewer-P2 fix: in-toto layout is in the hard-refusal
        class — once present, EVERY step entry must be well-formed.
        Previous "at least one well-formed step" tolerance let mixed-
        malformed lists slip through."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(
            tmp_path / "layout.json",
            **{"steps": [123, "string-step", [1, 2], None]},
        )
        with pytest.raises(IntotoTampered, match=r"step\[0\] is not a dict"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_step_dict_without_name_raises_intoto_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """A step dict missing the ``name`` field is malformed —
        reviewer can't tell what was supposed to run."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(
            tmp_path / "layout.json",
            **{
                "steps": [
                    {"expected_command": ["python", "-m", "build"]},
                    {"description": "no name field"},
                ]
            },
        )
        with pytest.raises(IntotoTampered, match=r"step\[0\] missing or blank 'name'"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    @pytest.mark.parametrize("blank_name", ["", " ", "\t", "\n"])
    def test_blank_step_name_raises_intoto_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        blank_name: str,
    ) -> None:
        """Any step with a blank/whitespace-only name is malformed."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(
            tmp_path / "layout.json",
            **{"steps": [{"name": blank_name}]},
        )
        with pytest.raises(IntotoTampered, match=r"step\[0\] missing or blank 'name'"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_mixed_malformed_step_in_otherwise_valid_layout_raises(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """R8 reviewer-P2: this is the test that flipped from "passes"
        to "raises". Even ONE malformed step entry — non-dict, missing
        name, blank name — refuses the whole layout. Tolerance is
        for vuln/license inventory parsing, NOT for the in-toto
        hard-refusal class.
        """
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(
            tmp_path / "layout.json",
            **{
                "steps": [
                    {"name": "build"},  # well-formed first
                    123,  # malformed sibling
                    {"name": "  "},  # blank-name sibling
                    {"name": "sign"},  # well-formed
                ]
            },
        )
        with pytest.raises(IntotoTampered, match=r"step\[1\] is not a dict"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_all_well_formed_steps_pass(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """Counter-test for the all-well-formed shape: every step is a
        dict with a non-empty name → layout verifies cleanly."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(
            tmp_path / "layout.json",
            **{
                "steps": [
                    {"name": "build", "expected_command": ["python", "-m", "build"]},
                    {"name": "sign"},
                    {"name": "  package  "},  # surrounding whitespace OK
                ]
            },
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            intoto_layout_path=layout,
        )
        assert result.verified["intoto"] is True

    def test_malformed_json_raises_intoto_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = tmp_path / "layout.json"
        layout.write_text("{not json")
        with pytest.raises(IntotoTampered, match="not valid JSON"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_json_array_root_raises_intoto_tampered(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = tmp_path / "layout.json"
        layout.write_text("[1, 2, 3]")
        with pytest.raises(IntotoTampered, match="not a JSON object"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    def test_statement_wrapped_layout_accepted(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = tmp_path / "layout.json"
        layout.write_text(
            json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": "https://in-toto.io/Layout/v1",
                    "predicate": {
                        "expires": "2027-01-01T00:00:00Z",
                        "steps": [{"name": "build"}],
                    },
                }
            )
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            intoto_layout_path=layout,
        )
        assert result.verified["intoto"] is True

    def test_predicate_wrapped_but_not_dict_raises(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = tmp_path / "layout.json"
        layout.write_text(
            json.dumps(
                {
                    "predicateType": "https://in-toto.io/Layout/v1",
                    "predicate": "i-am-not-a-dict",
                }
            )
        )
        with pytest.raises(IntotoTampered, match="predicate not a JSON object"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )

    @pytest.mark.parametrize(
        "bad_predicate_type",
        [
            "https://example.com/bogus/v1",  # non-matching URI
            "https://in-toto-typo.io/Layout/v1",  # near-miss domain
            # R6 reviewer-P2 fix: same-domain wrong-path must be
            # rejected. Without the Layout-path boundary on the
            # prefix, ``https://in-toto.io/`` would match
            # ``NotLayout/`` or ``Statement/`` (the envelope shape,
            # not a Layout predicate). Tightening to
            # ``https://in-toto.io/Layout/`` fixes both.
            "https://in-toto.io/NotLayout/v1",
            "https://in-toto.io/Statement/v1",
            "https://in-toto.io/Layout-not-real/v1",
            123,
            True,
            [1, 2],
            {"x": 1},
        ],
    )
    def test_invalid_predicateType_raises_intoto_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        bad_predicate_type: Any,
    ) -> None:
        """R4 reviewer-P2: a non-string ``predicateType`` previously
        raised AttributeError via ``int.startswith(...)``. R5
        reviewer-P2: even after the isinstance guard, present-but-
        invalid predicateType (wrong URI string OR non-string) MUST
        raise ``IntotoTampered`` rather than fall through to bare-
        form. Without the present-vs-absent distinction a malformed
        Statement with valid steps + expires at top level would
        verify cleanly despite a bogus envelope.
        """
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = tmp_path / "layout.json"
        # Compose a layout whose top-level fields ARE valid bare-layout
        # shape (so a fall-through would silently verify) but whose
        # predicateType is invalid.
        layout.write_text(
            json.dumps(
                {
                    "predicateType": bad_predicate_type,
                    "expires": "2027-01-01T00:00:00Z",
                    "steps": [{"name": "build"}],
                }
            )
        )
        with pytest.raises(IntotoTampered, match="invalid predicateType"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )


# ---------------------------------------------------------------------------
# TestVulnThresholdsValidation — refuse misconfigured tenant policy.
# ---------------------------------------------------------------------------


class TestVulnThresholdsValidation:
    """R5 reviewer-P2 fix: VulnThresholds validates at construction so a
    misconfigured tenant policy can never silently disable the gate."""

    def test_default_thresholds_accepted(self) -> None:
        thresholds = VulnThresholds()
        assert thresholds.max_cvss == 7.0
        assert thresholds.allow_known_exploits is False

    def test_typical_overrides_accepted(self) -> None:
        VulnThresholds(max_cvss=0.0, allow_known_exploits=False)
        VulnThresholds(max_cvss=10.0, allow_known_exploits=True)
        VulnThresholds(max_cvss=4)  # int coerces

    def test_max_cvss_nan_rejected(self) -> None:
        """NaN compares False against everything — would silently
        disable the threshold gate."""
        with pytest.raises(ValueError, match="must be finite"):
            VulnThresholds(max_cvss=float("nan"))

    def test_max_cvss_inf_rejected(self) -> None:
        """+inf would admit any finding, -inf reject all — neither
        is a sane policy. Refuse both."""
        with pytest.raises(ValueError, match="must be finite"):
            VulnThresholds(max_cvss=float("inf"))
        with pytest.raises(ValueError, match="must be finite"):
            VulnThresholds(max_cvss=float("-inf"))

    def test_max_cvss_string_rejected(self) -> None:
        with pytest.raises(TypeError, match="must be a real number"):
            VulnThresholds(max_cvss="7.0")  # type: ignore[arg-type]

    def test_max_cvss_bool_rejected(self) -> None:
        """``bool`` is a subtype of ``int`` in Python — reject so a
        config-file True doesn't silently coerce to 1.0 (admitting
        almost everything) or False to 0.0 (rejecting everything)."""
        with pytest.raises(TypeError, match="must be a real number"):
            VulnThresholds(max_cvss=True)

    def test_max_cvss_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"0\.\.10"):
            VulnThresholds(max_cvss=-0.1)

    def test_max_cvss_above_ten_rejected(self) -> None:
        """CVSS scores cap at 10.0 by spec; >10 is a config typo."""
        with pytest.raises(ValueError, match=r"0\.\.10"):
            VulnThresholds(max_cvss=11.0)

    def test_allow_known_exploits_must_be_strict_bool(self) -> None:
        """Truthy non-bool values (1, 'yes', non-empty list) are
        rejected so operator typos can't accidentally admit KEV
        findings."""
        for bad in (1, "yes", [True], {"yes": True}):
            with pytest.raises(ValueError, match="must be bool"):
                VulnThresholds(allow_known_exploits=bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestVulnVerification
# ---------------------------------------------------------------------------


class TestVulnVerification:
    def test_zero_findings_passes_default_threshold(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        result = pipeline.verify(**artefacts)
        assert result.verified["vuln"] is True
        assert result.vuln is not None
        assert result.vuln.total_findings == 0
        assert result.vuln.max_cvss == 0.0

    def test_max_cvss_above_threshold_demotes_to_partial(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {
                    "vulnerability": {
                        "severity": "Critical",
                        "cvss": [{"metrics": {"baseScore": 9.8}}],
                    }
                }
            ],
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            vuln_scan_path=vuln,
            vuln_thresholds=VulnThresholds(max_cvss=7.0),
        )
        assert result.grade == "partial"
        assert result.verified["vuln"] is False
        assert result.vuln is not None
        assert result.vuln.max_cvss == 9.8
        assert result.vuln.critical_count == 1
        assert any("max_cvss" in f for f in result.findings)

    def test_known_exploit_demotes_to_partial_when_disallowed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {
                    "vulnerability": {
                        "severity": "High",
                        "cvss": [{"metrics": {"baseScore": 6.0}}],
                        "kev": True,
                    }
                }
            ],
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            vuln_scan_path=vuln,
            vuln_thresholds=VulnThresholds(max_cvss=7.0, allow_known_exploits=False),
        )
        assert result.verified["vuln"] is False
        assert result.vuln is not None
        assert result.vuln.has_known_exploit is True

    def test_known_exploit_field_alternate_name(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Some Grype versions emit ``known_exploit`` instead of ``kev``."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {
                    "vulnerability": {
                        "severity": "Medium",
                        "cvss": [{"metrics": {"baseScore": 5.0}}],
                        "known_exploit": True,
                    }
                }
            ],
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            vuln_scan_path=vuln,
            vuln_thresholds=VulnThresholds(allow_known_exploits=False),
        )
        assert result.vuln is not None
        assert result.vuln.has_known_exploit is True

    def test_allow_known_exploits_does_not_demote(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {
                    "vulnerability": {
                        "severity": "High",
                        "cvss": [{"metrics": {"baseScore": 6.0}}],
                        "kev": True,
                    }
                }
            ],
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            vuln_scan_path=vuln,
            vuln_thresholds=VulnThresholds(max_cvss=7.0, allow_known_exploits=True),
        )
        assert result.verified["vuln"] is True

    def test_malformed_vuln_json_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R3 reviewer-P2: parse failure on a vuln scan is NOT
        'tampered' (per §3 — only signature failures are tampered),
        but it MUST set ``parse_failed=True`` so the pipeline demotes
        regardless of the threshold. Previously a malformed scan with
        a loose threshold could still earn full grade."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = tmp_path / "vuln.json"
        vuln.write_text("{not json")
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.grade == "partial"
        assert result.verified["vuln"] is False
        assert result.vuln is not None
        assert result.vuln.parse_failed is True
        assert any("unparseable" in f for f in result.findings)

    def test_mix_of_malformed_and_valid_match_entries_passes(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Defensive: non-dict entries inside ``matches`` are skipped
        without breaking the loop, AS LONG AS at least one entry is
        well-formed. The well-formed entry's max_cvss is recorded;
        parse_failed stays False because we DID extract a finding."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                "i-am-a-string",  # type: ignore[list-item]
                {"vulnerability": {"severity": "low", "cvss": "not-a-list"}},
                {"vulnerability": {"cvss": [{"metrics": {"baseScore": 3.0}}]}},
            ],
        )
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.max_cvss == 3.0
        assert result.vuln.parse_failed is False

    def test_all_malformed_inner_entries_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R4 reviewer-P2 fix: a non-empty ``matches`` list with ZERO
        parseable entries is malformed inventory — we tried to
        extract findings and got nothing. Previously this produced
        parse_failed=False, max_cvss=0, and could pass the threshold
        check vacuously. Now sets parse_failed=True so the pipeline
        demotes regardless of threshold.
        """
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {"vulnerability": "not-a-dict"},
                {"vulnerability": ["i-am-an-array-not-a-dict"]},
                {"not-vulnerability-key": "anything"},
                "string-entry",  # type: ignore[list-item]
            ],
        )
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is True
        assert result.verified["vuln"] is False

    def test_all_malformed_vuln_with_loose_threshold_still_demotes(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """R4 reviewer-P2 critical regression: a vuln scan with only
        malformed inner entries + the loosest threshold (max_cvss=10,
        allow_known_exploits=True) MUST still demote to partial.
        Previously this combination earned full grade silently."""
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["vuln_scan_path"].write_text(
            json.dumps({"matches": [{"vulnerability": "garbage"}]})
        )
        result = pipeline.verify(
            **artefacts,
            license_allowlist=("MIT", "Apache-2.0"),
            vuln_thresholds=VulnThresholds(max_cvss=10.0, allow_known_exploits=True),
        )
        assert result.grade == "partial"
        assert result.verified["vuln"] is False

    def test_well_formed_entries_with_missing_baseScore_keep_parse_succeeded(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Entries with ``vulnerability`` dict but cvss/metrics shapes
        that don't carry a ``baseScore`` are still "good" — we tried
        to extract findings, missing keys are not malformed. With
        the new strict score validation (R6 reviewer-P2), only a
        present-but-bad baseScore flips parse_failed; a structurally-
        empty cvss tree does not."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {"vulnerability": {"cvss": ["not-a-dict-cvss"]}},
                {"vulnerability": {"cvss": [{"metrics": "not-a-dict-metrics"}]}},
                {"vulnerability": {"cvss": [{"metrics": {}}]}},  # no baseScore key
            ],
        )
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is False
        assert result.vuln.max_cvss == 0.0
        assert result.vuln.total_findings == 3

    @pytest.mark.parametrize(
        "bad_score",
        [
            "9.8",  # string
            True,  # bool (subtype of int)
            False,
            -1.0,  # below CVSS range
            10.5,  # above CVSS range
            None,
            [9.8],  # list
            {"value": 9.8},  # dict
        ],
    )
    def test_present_but_malformed_baseScore_marks_parse_failed(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        bad_score: Any,
    ) -> None:
        """R6 reviewer-P2 fix: a baseScore that is PRESENT but
        non-numeric / bool / non-finite / out-of-range is malformed
        inventory. Previously these silently coerced (bool → 0.0/1.0)
        or got silently skipped, leaving max_cvss=0 and letting
        loose-threshold tenants pass."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = _write_vuln_scan(
            tmp_path / "vuln.json",
            matches=[
                {"vulnerability": {"cvss": [{"metrics": {"baseScore": bad_score}}]}},
            ],
        )
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is True
        assert result.verified["vuln"] is False

    def test_nan_baseScore_rejected_at_json_parse_step(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R6 reviewer-P2 fix: ``json.loads`` accepts ``NaN`` as a
        Python extension; without ``parse_constant`` it would silently
        coerce to ``float('nan')`` and disable the threshold (NaN > x
        is False for all x). The parse_constant hook rejects NaN /
        Infinity at the JSON-parse step so the entire scan flips
        parse_failed=True."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = tmp_path / "vuln.json"
        # Hand-craft JSON with a NaN literal — Python's json.dumps
        # emits ``NaN`` by default, which is invalid per RFC but
        # accepted by Python's json.loads as an extension.
        vuln.write_text(
            '{"matches": [{"vulnerability": {"cvss": [{"metrics": {"baseScore": NaN}}]}}]}'
        )
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is True

    def test_infinity_baseScore_rejected_at_json_parse_step(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Same parse_constant guard rejects ``Infinity`` and
        ``-Infinity`` JSON literals — both would otherwise survive
        as Python ``float('inf')``."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = tmp_path / "vuln.json"
        vuln.write_text(
            '{"matches": [{"vulnerability": {"cvss": [{"metrics": {"baseScore": Infinity}}]}}]}'
        )
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is True

    def test_malformed_baseScore_with_loose_threshold_still_demotes(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """Critical regression: malformed score + max_cvss=10 +
        allow_known_exploits=True (loosest possible policy) MUST
        still demote. Without R6's score validation a bool-true
        baseScore would coerce to 1.0 < 10.0 and silently pass."""
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["vuln_scan_path"].write_text(
            json.dumps(
                {"matches": [{"vulnerability": {"cvss": [{"metrics": {"baseScore": True}}]}}]}
            )
        )
        result = pipeline.verify(
            **artefacts,
            license_allowlist=("MIT", "Apache-2.0"),
            vuln_thresholds=VulnThresholds(max_cvss=10.0, allow_known_exploits=True),
        )
        assert result.grade == "partial"
        assert result.verified["vuln"] is False

    def test_top_level_matches_not_a_list_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R3 reviewer-P2: Grype JSON whose ``matches`` field is the
        wrong shape (string / dict / null) sets ``parse_failed=True``
        and demotes the grade — this is a schema violation, not a
        zero-findings outcome."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = tmp_path / "vuln.json"
        vuln.write_text(json.dumps({"matches": "not-a-list"}))
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is True
        assert result.verified["vuln"] is False

    def test_top_level_not_a_dict_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        vuln = tmp_path / "vuln.json"
        vuln.write_text("[1, 2, 3]")
        result = pipeline.verify(sbom_path=sbom, sbom_signed_digest=digest, vuln_scan_path=vuln)
        assert result.vuln is not None
        assert result.vuln.parse_failed is True
        assert result.verified["vuln"] is False

    def test_malformed_vuln_with_loose_threshold_still_demotes(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """Critical regression for R3 reviewer-P2: a malformed scan
        with the loosest possible threshold (max_cvss=10.0,
        allow_known_exploits=True) MUST still demote to partial. A
        threshold-only check would have let this pass."""
        artefacts = _make_full_pack_attestations(tmp_path)
        # Replace the clean vuln scan with malformed bytes.
        artefacts["vuln_scan_path"].write_text("{not json")
        result = pipeline.verify(
            **artefacts,
            license_allowlist=("MIT", "Apache-2.0"),
            vuln_thresholds=VulnThresholds(max_cvss=10.0, allow_known_exploits=True),
        )
        assert result.grade == "partial"
        assert result.verified["vuln"] is False


# ---------------------------------------------------------------------------
# TestLicenseVerification
# ---------------------------------------------------------------------------


class TestLicenseVerification:
    def test_flat_license_list_extracted(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = _write_license_audit(tmp_path / "license.json", licenses=["MIT", "Apache-2.0"])
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
        )
        assert result.licenses is not None
        assert "MIT" in result.licenses.licenses
        assert "Apache-2.0" in result.licenses.licenses

    def test_per_artifact_license_list_extracted(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = _write_license_audit(
            tmp_path / "license.json",
            artifacts=[
                {"licenses": ["MIT"]},
                {"licenses": ["Apache-2.0"]},
                {"licenses": [{"value": "BSD-3-Clause"}]},
            ],
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
        )
        assert result.licenses is not None
        assert set(result.licenses.licenses) == {"MIT", "Apache-2.0", "BSD-3-Clause"}

    def test_disallowed_licenses_demote_grade(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = _write_license_audit(tmp_path / "license.json", licenses=["MIT", "AGPL-3.0"])
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
            license_allowlist=("MIT", "Apache-2.0", "BSD-3-Clause"),
        )
        assert result.verified["license"] is False
        assert result.licenses is not None
        assert "AGPL-3.0" in result.licenses.disallowed
        assert any("AGPL-3.0" in f for f in result.findings)

    def test_empty_allowlist_means_no_constraint(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = _write_license_audit(tmp_path / "license.json", licenses=["MIT", "AGPL-3.0"])
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
            # No license_allowlist supplied → no constraint.
        )
        assert result.verified["license"] is True
        assert result.licenses is not None
        assert result.licenses.disallowed == ()

    def test_unparseable_license_audit_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R3 reviewer-P2: a malformed license file MUST set
        ``parse_failed=True`` so the pipeline demotes regardless of
        the allowlist contents. Previously a malformed file returned
        an empty LicenseResult that vacuously passed any allowlist
        check, letting a pack with no real license inventory earn
        full grade."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text("{not json")
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
            license_allowlist=("MIT",),
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is True
        assert result.verified["license"] is False
        assert any("unparseable" in f for f in result.findings)

    def test_top_level_license_json_not_a_dict_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text("[1, 2, 3]")
        result = pipeline.verify(
            sbom_path=sbom, sbom_signed_digest=digest, license_audit_path=audit
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is True
        assert result.verified["license"] is False

    def test_malformed_license_with_empty_allowlist_still_demotes(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """Critical regression for R3 reviewer-P2: a malformed license
        file with NO allowlist (i.e. "no constraint" mode) MUST still
        demote to partial. Previously this case earned full grade
        because the empty allowlist made disallowed=() vacuously."""
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["license_audit_path"].write_text("{not json")
        result = pipeline.verify(**artefacts)  # no license_allowlist
        assert result.grade == "partial"
        assert result.verified["license"] is False

    def test_mix_of_malformed_and_valid_license_entries_passes(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Defensive isinstance branches: non-string flat entries,
        empty/whitespace strings, non-dict artifact entries, non-list
        artifact_licenses, non-string non-dict entries, dict entries
        with missing/non-string ``value`` — all skipped, but parse
        succeeds because well-formed ``MIT`` + ``Apache-2.0`` were
        extracted."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text(
            json.dumps(
                {
                    "licenses": ["MIT", "", "   ", 42, None],
                    "artifacts": [
                        "not-a-dict",
                        {"licenses": "not-a-list"},
                        {"licenses": [123, {"no_value_field": "yes"}, {"value": ""}]},
                        {"licenses": [{"value": "Apache-2.0"}]},
                    ],
                }
            )
        )
        result = pipeline.verify(
            sbom_path=sbom, sbom_signed_digest=digest, license_audit_path=audit
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is False
        # Only the well-formed entries survive: "MIT" + "Apache-2.0".
        assert set(result.licenses.licenses) == {"MIT", "Apache-2.0"}

    def test_all_malformed_license_entries_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R4 reviewer-P2 fix: a license file that lists entries but
        none of them yield a parseable license string is malformed
        inventory. Previously this returned an empty LicenseResult
        that vacuously passed any allowlist check."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text(
            json.dumps(
                {
                    "licenses": [123, None, "", "   ", True],
                    "artifacts": [
                        "not-a-dict",
                        {"licenses": [{"no_value": True}, 42]},
                    ],
                }
            )
        )
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
            license_allowlist=("MIT",),
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is True
        assert result.verified["license"] is False

    def test_audit_without_licenses_or_artifacts_keys_marks_parse_failed(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """R4 reviewer-P2 fix: a JSON object with neither ``licenses``
        nor ``artifacts`` is not shaped like an audit at all. Don't
        let it vacuously pass an allowlist."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text(json.dumps({"random": "object", "not_an_audit": True}))
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
            license_allowlist=("MIT",),
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is True
        assert result.verified["license"] is False

    @pytest.mark.parametrize(
        "audit_payload",
        [
            {"licenses": "MIT"},  # singleton string instead of list
            {"licenses": {"MIT": True}},  # dict instead of list
            {"licenses": None},  # null instead of list
            {"artifacts": "not-a-list"},
            {"artifacts": {"by_name": "..."}},
            {"licenses": ["MIT"], "artifacts": "not-a-list"},  # one valid, one wrong
        ],
    )
    def test_wrong_typed_top_level_field_marks_parse_failed(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        audit_payload: dict[str, Any],
    ) -> None:
        """R5 reviewer-P2 fix: ``licenses`` or ``artifacts`` PRESENT but
        wrong-typed (string / dict / null instead of list) is malformed
        inventory. Previously these silently skipped both extraction
        loops and returned an empty parse_failed=False — letting
        malformed syft output earn ``verified['license']=True``."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text(json.dumps(audit_payload))
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            license_audit_path=audit,
            license_allowlist=("MIT",),
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is True
        assert result.verified["license"] is False

    def test_intentionally_empty_licenses_list_passes(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """A genuinely empty inventory (``{"licenses": []}``) is a
        legitimate statement of "no third-party licenses". It's
        zero attempted entries, not malformed. Stays
        parse_failed=False so a tenant that allows zero licenses
        can still earn full grade."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        audit = tmp_path / "license.json"
        audit.write_text(json.dumps({"licenses": []}))
        result = pipeline.verify(
            sbom_path=sbom, sbom_signed_digest=digest, license_audit_path=audit
        )
        assert result.licenses is not None
        assert result.licenses.parse_failed is False
        assert result.licenses.licenses == ()
        assert result.verified["license"] is True

    def test_all_malformed_license_with_empty_allowlist_still_demotes(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
    ) -> None:
        """R4 reviewer-P2 critical regression: malformed-only inner
        entries + empty allowlist (no constraint) MUST still demote.
        Previously the empty allowlist would vacuously pass the empty
        license set, earning full grade."""
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["license_audit_path"].write_text(json.dumps({"licenses": [123, None, ""]}))
        result = pipeline.verify(**artefacts)  # no license_allowlist
        assert result.grade == "partial"
        assert result.verified["license"] is False


# ---------------------------------------------------------------------------
# TestPipelineGrade
# ---------------------------------------------------------------------------


class TestPipelineGrade:
    def test_full_grade_when_all_four_present_and_clean(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        result = pipeline.verify(
            **artefacts,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert result.grade == "full"
        assert all(result.verified.values())
        assert result.findings == ()

    def test_partial_when_slsa_absent(self, pipeline: SupplyChainPipeline, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            slsa_provenance_path=None,
        )
        assert result.grade == "partial"
        assert result.verified["slsa"] is False
        assert any("slsa" in f for f in result.findings)
        assert result.slsa is None

    def test_partial_when_attestation_path_does_not_exist(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Path supplied but file not on disk — same as not provided."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        result = pipeline.verify(
            sbom_path=sbom,
            sbom_signed_digest=digest,
            slsa_provenance_path=tmp_path / "absent.slsa.json",
            intoto_layout_path=tmp_path / "absent.layout.json",
            vuln_scan_path=tmp_path / "absent.vuln.json",
            license_audit_path=tmp_path / "absent.license.json",
        )
        assert result.grade == "partial"
        assert all(v is False for v in result.verified.values())

    def test_full_grade_returns_isinstance_attestation_result(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        result = pipeline.verify(**artefacts)
        assert isinstance(result, AttestationResult)
        assert isinstance(result.slsa, SLSAResult)
        assert isinstance(result.vuln, VulnResult)
        assert isinstance(result.licenses, LicenseResult)


# ---------------------------------------------------------------------------
# TestPipelineTamperedAlwaysRefuses — the load-bearing hard rule.
# ---------------------------------------------------------------------------


class TestPipelineTamperedAlwaysRefuses:
    """User-locked invariant: every 'tampered' path refuses (raises)
    rather than downgrades to partial. Threshold-breaches and absent
    attestations CAN demote; structural/digest failures on PRESENT
    attestations cannot."""

    def test_sbom_tampered_refuses_even_with_full_other_attestations(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        # Corrupt SBOM but keep digest in callsite — simulates an SBOM
        # whose bytes were swapped after signing.
        artefacts["sbom_path"].write_bytes(b'{"swapped": "after-signing"}')
        with pytest.raises(SBOMTampered):
            pipeline.verify(**artefacts)

    def test_slsa_tampered_refuses_even_with_full_other_attestations(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        # Strip a required field from a present SLSA file.
        artefacts["slsa_provenance_path"].write_text(json.dumps({"predicate": {}}))
        with pytest.raises(SLSATampered):
            pipeline.verify(**artefacts)

    def test_intoto_tampered_refuses_even_with_full_other_attestations(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["intoto_layout_path"].write_text("{not json")
        with pytest.raises(IntotoTampered):
            pipeline.verify(**artefacts)

    def test_vuln_breach_does_not_raise_only_demotes(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        """Counter-test to the hard rule: a vuln threshold breach is
        NOT tampering, just policy. Pipeline returns a partial result;
        no exception."""
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["vuln_scan_path"].write_text(
            json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {
                                "severity": "Critical",
                                "cvss": [{"metrics": {"baseScore": 9.9}}],
                            }
                        }
                    ]
                }
            )
        )
        result = pipeline.verify(**artefacts)
        assert result.grade == "partial"
        assert result.verified["vuln"] is False

    def test_license_disallowed_does_not_raise_only_demotes(
        self, pipeline: SupplyChainPipeline, tmp_path: Path
    ) -> None:
        artefacts = _make_full_pack_attestations(tmp_path)
        artefacts["license_audit_path"].write_text(json.dumps({"licenses": ["AGPL-3.0"]}))
        result = pipeline.verify(**artefacts, license_allowlist=("MIT", "Apache-2.0"))
        assert result.grade == "partial"
        assert result.verified["license"] is False


# ---------------------------------------------------------------------------
# TestExceptionTaxonomy
# ---------------------------------------------------------------------------


class TestExceptionTaxonomy:
    def test_all_typed_failures_subclass_supply_chain_error(self) -> None:
        """T10's ``except SupplyChainError:`` MUST catch each narrower
        failure so it can map them to the matching ``refusal_reason``."""
        for exc in (SBOMMissing, SBOMTampered, SLSATampered, IntotoTampered):
            assert issubclass(exc, SupplyChainError)


# ---------------------------------------------------------------------------
# TestUnreadableFileFallbacks — OSError on read raises tampered (not OSError).
# ---------------------------------------------------------------------------


class TestUnreadableFileFallbacks:
    def test_slsa_path_unreadable_raises_slsa_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If the SLSA file becomes unreadable between ``exists()`` and
        ``read_text()`` (race / permission flip), the pipeline must
        wrap the OSError into SLSATampered rather than letting it
        escape the supply-chain taxonomy."""
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        slsa = _write_slsa(tmp_path / "slsa.json")
        original_read_text = Path.read_text

        def _failing(self: Path, *args: Any, **kwargs: Any) -> str:
            if self.name == slsa.name:
                raise PermissionError(13, "EACCES")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _failing)
        with pytest.raises(SLSATampered, match="unreadable"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                slsa_provenance_path=slsa,
            )

    def test_intoto_path_unreadable_raises_intoto_tampered(
        self,
        pipeline: SupplyChainPipeline,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sbom = tmp_path / "sbom.json"
        digest = _write_sbom(sbom)
        layout = _write_intoto(tmp_path / "layout.json")
        original_read_text = Path.read_text

        def _failing(self: Path, *args: Any, **kwargs: Any) -> str:
            if self.name == layout.name:
                raise PermissionError(13, "EACCES")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _failing)
        with pytest.raises(IntotoTampered, match="unreadable"):
            pipeline.verify(
                sbom_path=sbom,
                sbom_signed_digest=digest,
                intoto_layout_path=layout,
            )
