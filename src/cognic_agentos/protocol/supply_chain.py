"""Supply-chain attestation pipeline — ADR-016 mandatory-floor + grace-period grading.

Critical-controls module per AGENTS.md (full ADR-016 attestation
pipeline — refusal-grade gates). Implements §3 of the Sprint-4 plan-
of-record.

The 8-attestation set per ADR-016 splits into two tiers:

**Mandatory floor (refusal-grade — registration refused if any
missing or tampered):**

  1. cosign signature → verified by ``protocol.trust_gate`` (T6).
  2. SBOM (CycloneDX or SPDX 2.3+) — file SHA-256 pinned to the
     pack's cosign signature. Mismatch ⇒ ``SBOMTampered``.
  3. Sigstore bundle persisted via ``LocalObjectStoreAdapter``
     (T9).

**Grace period (``attestation_grade='partial'`` allowed — pack
registers, tenant policy decides whether to refuse):**

  4. SLSA L3+ provenance — required fields present;
     malformed/missing required field ⇒ ``SLSATampered`` (HARD
     refusal); structurally valid ⇒ pack registers.
  5. in-toto layout — structural required fields present;
     malformed/missing ⇒ ``IntotoTampered`` (HARD refusal).
  6. Vulnerability scan (Grype JSON) — per-tenant ``VulnThresholds``
     applied; threshold breach ⇒ partial grade (NOT hard refusal).
  7. License audit (syft JSON) — disallowed licenses ⇒ partial.

Reproducibility (8th) is informational only and verified
independently by ``protocol.reproducibility`` (T8).

**Tampered-vs-partial discipline (hard rule):** A signature/digest/
structural failure on a *present* attestation is "tampered" and
ALWAYS refuses — never downgrades to partial. Only *absent* (file
not provided) or *threshold-breach* on a present, structurally-
valid attestation degrades grade.

Sprint 4 scope: structural validation + SHA-256 + threshold compare.
Cryptographic in-toto envelope verification (DSSE signatures over the
SLSA / in-toto layout) is deferred to Sprint 7B (the reviewer flow);
in Sprint 4 we trust the cosign signature in T6 covers the bundle
that wraps these attestations. The "tampered" detection here is
structural — malformed JSON, missing required fields, or SBOM hash
mismatch with the cosign-signed digest.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cognic_agentos.core.config import Settings

_LOG = logging.getLogger("cognic_agentos.protocol.supply_chain")

#: SLSA v1.0 in-toto Statement predicateType URI prefix. Spec
#: identifier defined by https://slsa.dev/spec/v1.0/provenance — fixed
#: by external standard, not operational config. R6 reviewer-P2 fix:
#: trailing slash pins the spec-path boundary, so a same-domain near-
#: miss like ``https://slsa.dev/provenance-not-real/v1`` is rejected
#: instead of silently passing.
SLSA_PROVENANCE_PREDICATE_TYPE_PREFIX = "https://slsa.dev/provenance/"

#: in-toto Layout predicateType URI prefix. R6 reviewer-P2 fix:
#: tightened from ``https://in-toto.io/`` to the Layout-specific
#: spec-path boundary, so ``https://in-toto.io/NotLayout/v1`` and
#: ``https://in-toto.io/Statement/v1`` (the envelope, not a Layout
#: predicate) are rejected. The Sprint-4 contract is Layout-specific.
INTOTO_PREDICATE_TYPE_PREFIX = "https://in-toto.io/Layout/"

#: Sentinel for distinguishing "predicateType absent" (bare-form OK)
#: from "predicateType present but invalid" (tampered). Without this,
#: a non-matching string or non-string predicateType would silently
#: fall through to the bare-form branch and a malformed Statement
#: with valid top-level fields could pass as legitimate provenance
#: (R5 reviewer-P2 fix).
_PREDICATE_TYPE_ABSENT: Any = object()


# --- Exception taxonomy -------------------------------------------------


class SupplyChainError(RuntimeError):
    """Base for all supply-chain pipeline failures. T10 catches this
    to refuse pack registration with the matching ``refusal_reason``.
    """


class SBOMMissing(SupplyChainError):
    """SBOM file does not exist at the supplied path. ADR-016
    mandatory floor — registration refused with
    ``refusal_reason='sbom_missing'``."""


class SBOMTampered(SupplyChainError):
    """SBOM file's SHA-256 does NOT match the digest pinned by the
    pack's cosign signature. Hard refusal with
    ``refusal_reason='sbom_tampered'`` — never downgrades to partial."""


class SLSATampered(SupplyChainError):
    """SLSA provenance failed structural validation: malformed JSON,
    wrong predicateType, or missing mandatory field
    (``buildDefinition.buildType`` / ``runDetails.builder.id``).
    Hard refusal with ``refusal_reason='slsa_tampered'``."""


class IntotoTampered(SupplyChainError):
    """in-toto layout failed structural validation: malformed JSON or
    missing required fields (``steps``, ``expires``). Hard refusal
    with ``refusal_reason='intoto_tampered'``."""


# --- Per-attestation result types --------------------------------------


@dataclass(frozen=True, slots=True)
class SLSAResult:
    """Extracted SLSA v1.0 provenance fields (Sprint 4 — structural
    parse only; cryptographic envelope verification is Sprint 7B).

    ``level`` is the declared SLSA build level. SLSA v1.0 doesn't
    fix the field name; we read ``predicate.slsaLevel`` (preferred)
    or ``predicate.slsa_level`` (alternate), expecting an int 1..4.
    Absent → ``None``. T7's pipeline grade decision treats
    ``None`` and ``< 3`` the same way: contributes to ``partial``.
    Sprint 7B / 13.5 will introduce builder.id-based level
    inference via Rego policy.
    """

    build_type: str
    builder_id: str
    config_source: str | None
    level: int | None


@dataclass(frozen=True, slots=True)
class VulnResult:
    """Aggregated vulnerability findings from a Grype JSON scan.

    ``parse_failed`` (R3 reviewer-P2 fix) signals that the scan file
    was unparseable or had the wrong top-level shape. The pipeline
    demotes ``verified['vuln']`` to False on parse failure so a pack
    with a malformed scan can never earn ``full`` grade — missing
    inventory is worse than visible findings.
    """

    total_findings: int
    max_cvss: float
    critical_count: int
    has_known_exploit: bool
    parse_failed: bool = False


@dataclass(frozen=True, slots=True)
class LicenseResult:
    """syft license-audit summary.

    ``parse_failed`` (R3 reviewer-P2 fix) signals an unparseable or
    wrong-shape license file. The pipeline treats parse failure as
    "no license inventory" and demotes ``verified['license']`` to
    False — vacuous-allowlist-passthrough is rejected.
    """

    licenses: tuple[str, ...]
    disallowed: tuple[str, ...]
    parse_failed: bool = False


@dataclass(frozen=True, slots=True)
class VulnThresholds:
    """Per-tenant vulnerability policy. Sprint 4: caller supplies
    explicitly. Sprint 13.5 delegates to the OPA Rego engine
    (``policies/_default/supply_chain.rego``).

    R5 reviewer-P2 fix: validate at construction so a misconfigured
    tenant policy cannot silently disable the gate. Previously
    ``VulnThresholds(max_cvss=float('nan'))`` made every comparison
    return False (NaN is unordered) and ``allow_known_exploits=1``
    was truthy enough to admit known-exploit findings without
    being an actual ``True``.
    """

    max_cvss: float = 7.0
    allow_known_exploits: bool = False

    def __post_init__(self) -> None:
        # ``allow_known_exploits`` MUST be exactly bool. Truthy
        # non-bool values (1, "yes", non-empty list) are rejected so
        # operator typos / config-file drift can't accidentally
        # admit KEV findings.
        if not isinstance(self.allow_known_exploits, bool):
            raise ValueError(
                f"VulnThresholds.allow_known_exploits must be bool; "
                f"got {type(self.allow_known_exploits).__name__}="
                f"{self.allow_known_exploits!r}"
            )
        # ``max_cvss`` MUST be a finite real number in the CVSS
        # 0..10 range. NaN compares False against everything (would
        # disable the threshold); ±inf would either reject all
        # findings or admit them silently. Bool is rejected as a
        # subtype of int. ``int`` IS allowed (and coerced via the
        # comparison).
        if isinstance(self.max_cvss, bool) or not isinstance(self.max_cvss, int | float):
            raise TypeError(
                f"VulnThresholds.max_cvss must be a real number (int or float); "
                f"got {type(self.max_cvss).__name__}={self.max_cvss!r}"
            )
        if not math.isfinite(self.max_cvss):
            raise ValueError(f"VulnThresholds.max_cvss must be finite; got {self.max_cvss!r}")
        if self.max_cvss < 0.0 or self.max_cvss > 10.0:
            raise ValueError(
                f"VulnThresholds.max_cvss must be in 0..10 (CVSS range); got {self.max_cvss}"
            )


@dataclass(frozen=True, slots=True)
class AttestationResult:
    """Outcome of T7's grace-period attestation pipeline.

    ``grade`` is ``'full'`` only when all four grace-period
    attestations passed AND met thresholds; ``'partial'`` if any are
    missing OR present but threshold-breached. Mandatory-floor
    failures (SBOM missing/tampered) raise exceptions and never
    reach this result.
    """

    grade: Literal["full", "partial"]
    verified: dict[str, bool]
    findings: tuple[str, ...]
    slsa: SLSAResult | None
    vuln: VulnResult | None
    licenses: LicenseResult | None


# --- Pipeline ----------------------------------------------------------


class SupplyChainPipeline:
    """ADR-016 attestation pipeline.

    Construction takes ``Settings`` (carried for future extensions; in
    Sprint 4 the pipeline doesn't read settings directly — tenant
    thresholds + allow-lists are passed per-call).
    """

    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings

    def verify(
        self,
        *,
        sbom_path: Path,
        sbom_signed_digest: str,
        slsa_provenance_path: Path | None = None,
        intoto_layout_path: Path | None = None,
        vuln_scan_path: Path | None = None,
        license_audit_path: Path | None = None,
        vuln_thresholds: VulnThresholds | None = None,
        license_allowlist: tuple[str, ...] | None = None,
    ) -> AttestationResult:
        """Run the full attestation pipeline against a pack's
        artefacts.

        Mandatory floor: ``sbom_path`` must exist and its SHA-256
        must match ``sbom_signed_digest`` (the digest the pack's
        cosign signature pinned). Failure raises ``SBOMMissing`` or
        ``SBOMTampered``.

        Grace period: each of slsa / intoto / vuln / license is
        Optional. Missing files → grade demoted to ``partial`` with
        a ``"<name>: not provided"`` finding. Present-but-malformed
        attestations raise ``SLSATampered`` / ``IntotoTampered``
        (hard refusal — NEVER downgrades to partial). Vuln-threshold
        breach + license-disallow contribute to ``partial`` grade
        but do not raise.
        """
        self._verify_sbom(sbom_path, sbom_signed_digest)

        verified: dict[str, bool] = {}
        findings: list[str] = []
        slsa: SLSAResult | None = None
        vuln: VulnResult | None = None
        licenses: LicenseResult | None = None

        # SLSA L3+ provenance. R3 reviewer-P2 fix: structurally valid
        # provenance is necessary but not sufficient — the plan + ADR-016
        # require level >= 3 AND a configSource (source/build-config
        # reference) for full grade; L1/L2/no-level/no-configSource
        # demotes to partial during the grace period.
        if slsa_provenance_path is not None and slsa_provenance_path.exists():
            slsa = self._verify_slsa(slsa_provenance_path)
            slsa_failures: list[str] = []
            if slsa.level is None or slsa.level < 3:
                slsa_failures.append(f"declared level={slsa.level!r} below required L3")
            if slsa.config_source is None:
                # R4 reviewer-P2 fix: the plan calls out
                # invocation.configSource as a required field for full
                # grade. Without it the provenance can't tie the build
                # back to a source/build-config reference, so it cannot
                # earn full even when the level is L3+.
                slsa_failures.append(
                    "missing externalParameters.configSource (build-source reference)"
                )
            if slsa_failures:
                verified["slsa"] = False
                findings.append("slsa: " + "; ".join(slsa_failures))
            else:
                verified["slsa"] = True
        else:
            verified["slsa"] = False
            findings.append("slsa: provenance not provided")

        # in-toto layout.
        if intoto_layout_path is not None and intoto_layout_path.exists():
            self._verify_intoto(intoto_layout_path)
            verified["intoto"] = True
        else:
            verified["intoto"] = False
            findings.append("intoto: layout not provided")

        # Vulnerability scan. R3 reviewer-P2 fix: parseable scan is
        # the precondition for the threshold check; an unparseable
        # file demotes regardless of how loose the threshold is.
        if vuln_scan_path is not None and vuln_scan_path.exists():
            vuln = self._verify_vuln_scan(vuln_scan_path)
            thresholds = vuln_thresholds or VulnThresholds()
            if vuln.parse_failed:
                verified["vuln"] = False
                findings.append("vuln: scan unparseable or wrong shape")
            elif vuln.max_cvss > thresholds.max_cvss:
                verified["vuln"] = False
                findings.append(f"vuln: max_cvss {vuln.max_cvss} > threshold {thresholds.max_cvss}")
            elif vuln.has_known_exploit and not thresholds.allow_known_exploits:
                verified["vuln"] = False
                findings.append("vuln: known-exploit finding present (tenant disallows)")
            else:
                verified["vuln"] = True
        else:
            verified["vuln"] = False
            findings.append("vuln: scan not provided")

        # License audit. R3 reviewer-P2 fix: vacuous-allowlist-passthrough
        # on a malformed file is rejected — parse failure demotes
        # regardless of the allowlist contents.
        if license_audit_path is not None and license_audit_path.exists():
            licenses = self._verify_license_audit(license_audit_path, license_allowlist or ())
            if licenses.parse_failed:
                verified["license"] = False
                findings.append("license: audit unparseable or wrong shape")
            elif licenses.disallowed:
                verified["license"] = False
                findings.append(f"license: disallowed={list(licenses.disallowed)}")
            else:
                verified["license"] = True
        else:
            verified["license"] = False
            findings.append("license: audit not provided")

        grade: Literal["full", "partial"] = "full" if all(verified.values()) else "partial"
        return AttestationResult(
            grade=grade,
            verified=verified,
            findings=tuple(findings),
            slsa=slsa,
            vuln=vuln,
            licenses=licenses,
        )

    # --- mandatory floor ----------------------------------------------

    @staticmethod
    def _verify_sbom(sbom_path: Path, signed_digest: str) -> None:
        """Mandatory-floor check: SBOM file exists, SHA-256 ≡
        cosign-signed digest, AND the bytes parse as a recognised SBOM
        format (CycloneDX or SPDX 2.3+) per ADR-016. R3 reviewer-P2
        fix: a digest-only check let a pack sign arbitrary bytes and
        still clear the floor — the SBOM is supposed to *prove*
        dependency inventory, so its content shape has to match.

        Raises ``SBOMMissing`` (file absent / not regular) or
        ``SBOMTampered`` (digest mismatch / unparseable / wrong shape /
        unsupported SBOM format).
        """
        if not isinstance(signed_digest, str) or not signed_digest.strip():
            raise SBOMTampered(f"sbom_signed_digest must be a non-empty str; got {signed_digest!r}")
        if not sbom_path.exists() or not sbom_path.is_file():
            raise SBOMMissing(f"SBOM not found or not a regular file at {sbom_path!s}")
        # R3 reviewer-P2 fix: read the file ONCE into a single buffer
        # and hash + parse from that buffer. Two separate reads (one
        # for SHA-256, one for the JSON parse) opened a TOCTOU race
        # where an attacker could swap the file between reads, and the
        # resulting OSError would escape the SupplyChainError taxonomy.
        # Wrap the single read so EACCES / ENOENT / ENOEXEC after the
        # exists/is_file check still surface as SBOMMissing instead of
        # bypassing T10's ``except SupplyChainError`` refusal.
        try:
            sbom_bytes = sbom_path.read_bytes()
        except OSError as exc:
            raise SBOMMissing(
                f"SBOM at {sbom_path!s} became unreadable between "
                f"exists() and read: errno={exc.errno} class={type(exc).__name__}"
            ) from None
        actual = hashlib.sha256(sbom_bytes).hexdigest()
        # Allow ``sha256:<hex>`` or bare hex.
        normalized = signed_digest.removeprefix("sha256:").strip()
        if actual.lower() != normalized.lower():
            raise SBOMTampered(
                f"SBOM SHA-256 mismatch at {sbom_path!s}: "
                f"actual_sha256={actual} expected_sha256={normalized}"
            )
        # Format validation. Per ADR-016 the SBOM must be CycloneDX or
        # SPDX 2.3+; otherwise the bytes do not constitute a dependency
        # inventory regardless of who signed them. Parse from the same
        # buffer that was hashed (R3 reviewer-P2 — no second read).
        try:
            data = json.loads(sbom_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SBOMTampered(
                f"SBOM at {sbom_path!s} is not valid UTF-8 JSON: {type(exc).__name__}"
            ) from None
        if not isinstance(data, dict):
            raise SBOMTampered(f"SBOM at {sbom_path!s} top-level is not a JSON object")
        bom_format = data.get("bomFormat")
        spdx_version = data.get("spdxVersion")
        if isinstance(bom_format, str) and bom_format == "CycloneDX":
            spec_version = data.get("specVersion")
            if not isinstance(spec_version, str) or not spec_version.strip():
                raise SBOMTampered(
                    f"SBOM at {sbom_path!s} declares CycloneDX but lacks specVersion"
                )
            return
        if isinstance(spdx_version, str) and spdx_version.startswith("SPDX-2."):
            try:
                minor = int(spdx_version.split("-", 1)[1].split(".")[1])
            except (ValueError, IndexError):
                raise SBOMTampered(
                    f"SBOM at {sbom_path!s} has unparseable spdxVersion={spdx_version!r}"
                ) from None
            if minor < 3:
                raise SBOMTampered(
                    f"SBOM at {sbom_path!s} declares SPDX {spdx_version!r}; "
                    f"ADR-016 requires SPDX-2.3 or later"
                )
            return
        raise SBOMTampered(
            f"SBOM at {sbom_path!s} is neither CycloneDX nor SPDX-2.3+; "
            f"got bomFormat={bom_format!r} spdxVersion={spdx_version!r}"
        )

    # --- grace-period verifiers ---------------------------------------

    @staticmethod
    def _verify_slsa(provenance_path: Path) -> SLSAResult:
        """Parse + structurally validate a SLSA v1.0 provenance
        statement. Required fields per
        https://slsa.dev/spec/v1.0/provenance: ``buildDefinition.
        buildType`` and ``runDetails.builder.id``. Missing or
        malformed → ``SLSATampered``."""
        try:
            raw = provenance_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SLSATampered(
                f"SLSA provenance at {provenance_path!s} unreadable: "
                f"errno={exc.errno} class={type(exc).__name__}"
            ) from None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SLSATampered(
                f"SLSA provenance at {provenance_path!s} is not valid "
                f"JSON: line={exc.lineno} col={exc.colno}"
            ) from None
        if not isinstance(data, dict):
            raise SLSATampered(f"SLSA provenance at {provenance_path!s} is not a JSON object")
        # Support either the in-toto Statement v1 envelope or the
        # bare predicate. R5 reviewer-P2 fix: distinguish "predicateType
        # absent" (bare-form OK) from "predicateType present but
        # invalid" (tampered). Previously a malformed Statement with
        # a wrong / non-string predicateType silently fell through to
        # the bare-form branch and could pass as legitimate provenance
        # if it carried valid top-level buildDefinition/runDetails.
        predicate_type = data.get("predicateType", _PREDICATE_TYPE_ABSENT)
        predicate: Any
        if predicate_type is _PREDICATE_TYPE_ABSENT:
            predicate = data
        elif isinstance(predicate_type, str) and predicate_type.startswith(
            SLSA_PROVENANCE_PREDICATE_TYPE_PREFIX
        ):
            predicate = data.get("predicate")
        else:
            raise SLSATampered(
                f"SLSA provenance at {provenance_path!s} has invalid "
                f"predicateType={predicate_type!r}; expected absent "
                f"(bare predicate) or a string starting with "
                f"{SLSA_PROVENANCE_PREDICATE_TYPE_PREFIX!r}"
            )
        if not isinstance(predicate, dict):
            raise SLSATampered(f"SLSA predicate at {provenance_path!s} is not a JSON object")
        build_definition = predicate.get("buildDefinition")
        run_details = predicate.get("runDetails")
        if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
            raise SLSATampered(
                f"SLSA predicate at {provenance_path!s} missing buildDefinition or runDetails"
            )
        # R7 reviewer-P2 fix: ``buildType`` and ``builder.id`` must
        # be non-empty AFTER strip. Whitespace-only values
        # (``" "``) used to pass the truthiness check and let an
        # otherwise-blank Statement verify as legitimate provenance.
        # Mirrors the configSource normalisation from R5.
        build_type = build_definition.get("buildType")
        if not isinstance(build_type, str) or not build_type.strip():
            raise SLSATampered(
                f"SLSA predicate at {provenance_path!s} missing buildDefinition.buildType"
            )
        build_type = build_type.strip()
        builder = run_details.get("builder")
        builder_id = builder.get("id") if isinstance(builder, dict) else None
        if not isinstance(builder_id, str) or not builder_id.strip():
            raise SLSATampered(
                f"SLSA predicate at {provenance_path!s} missing runDetails.builder.id"
            )
        builder_id = builder_id.strip()
        external_params = build_definition.get("externalParameters")
        config_source: str | None = None
        if isinstance(external_params, dict):
            cs = external_params.get("configSource")
            # R5 reviewer-P2 fix: an empty / whitespace-only
            # configSource is not a usable source reference. Normalise
            # to None so the pipeline's L3+ gate demotes consistently
            # whether the field is absent, blank, or non-string.
            if isinstance(cs, str) and cs.strip():
                config_source = cs.strip()
        # Declared SLSA level. Honor either ``slsaLevel`` (canonical
        # camelCase) or ``slsa_level`` (snake_case alternate seen in
        # some build platforms). Boolean values are explicitly
        # rejected — bool is a subtype of int in Python, but a
        # ``True`` for "level" would silently coerce to 1 and let an
        # unattested pack pass.
        raw_level = predicate.get("slsaLevel")
        if raw_level is None:
            raw_level = predicate.get("slsa_level")
        level: int | None = None
        if isinstance(raw_level, bool):
            raise SLSATampered(
                f"SLSA predicate at {provenance_path!s} declared slsaLevel as "
                f"bool={raw_level!r}; expected int in 1..4"
            )
        if isinstance(raw_level, int):
            if raw_level < 1 or raw_level > 4:
                raise SLSATampered(
                    f"SLSA predicate at {provenance_path!s} declared "
                    f"slsaLevel={raw_level} outside the valid 1..4 range"
                )
            level = raw_level
        elif raw_level is not None:
            raise SLSATampered(
                f"SLSA predicate at {provenance_path!s} declared slsaLevel as "
                f"{type(raw_level).__name__}={raw_level!r}; expected int 1..4"
            )
        return SLSAResult(
            build_type=build_type,
            builder_id=builder_id,
            config_source=config_source,
            level=level,
        )

    @staticmethod
    def _verify_intoto(layout_path: Path) -> None:
        """Parse + structurally validate an in-toto layout. Required
        fields: ``steps`` (non-empty list), ``expires`` (string).
        Missing or malformed → ``IntotoTampered``. Cryptographic
        signature verification is Sprint 7B (reviewer flow).
        """
        try:
            raw = layout_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise IntotoTampered(
                f"in-toto layout at {layout_path!s} unreadable: "
                f"errno={exc.errno} class={type(exc).__name__}"
            ) from None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IntotoTampered(
                f"in-toto layout at {layout_path!s} is not valid JSON: "
                f"line={exc.lineno} col={exc.colno}"
            ) from None
        if not isinstance(data, dict):
            raise IntotoTampered(f"in-toto layout at {layout_path!s} is not a JSON object")
        # Support both bare layout and Statement-wrapped form. R5
        # reviewer-P2 fix: distinguish "predicateType absent"
        # (bare-form OK) from "predicateType present but invalid"
        # (tampered). Previously a malformed Statement with a wrong /
        # non-string predicateType silently fell through to bare-form
        # — a layout with steps + expires at top level would then
        # verify cleanly even though its envelope was bogus.
        predicate_type = data.get("predicateType", _PREDICATE_TYPE_ABSENT)
        layout: Any
        if predicate_type is _PREDICATE_TYPE_ABSENT:
            layout = data
        elif isinstance(predicate_type, str) and predicate_type.startswith(
            INTOTO_PREDICATE_TYPE_PREFIX
        ):
            layout = data.get("predicate")
        else:
            raise IntotoTampered(
                f"in-toto layout at {layout_path!s} has invalid "
                f"predicateType={predicate_type!r}; expected absent "
                f"(bare layout) or a string starting with "
                f"{INTOTO_PREDICATE_TYPE_PREFIX!r}"
            )
        if not isinstance(layout, dict):
            raise IntotoTampered(f"in-toto layout at {layout_path!s} predicate not a JSON object")
        # R7 reviewer-P2 fix: ``steps`` must be a non-empty list AND
        # EVERY step must be a dict with a non-empty stripped ``name``.
        # in-toto is a present-structural attestation in the
        # hard-refusal class (unlike vuln/license inventory parsing
        # which tolerates partial malformation) — once the layout is
        # provided, ANY malformed step entry is tampered. R8
        # reviewer-P2 tightened: previously the gate was "at least
        # one well-formed step", which let mixed-malformed lists like
        # ``[123, {}, {"name": ""}, {"name": "build"}]`` slip
        # through.
        steps = layout.get("steps")
        if not isinstance(steps, list) or len(steps) == 0:
            raise IntotoTampered(f"in-toto layout at {layout_path!s} missing or empty 'steps'")
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise IntotoTampered(
                    f"in-toto layout at {layout_path!s} step[{index}] is not a "
                    f"dict (got {type(step).__name__})"
                )
            name = step.get("name")
            if not isinstance(name, str) or not name.strip():
                raise IntotoTampered(
                    f"in-toto layout at {layout_path!s} step[{index}] missing or blank 'name'"
                )
        expires = layout.get("expires")
        if not isinstance(expires, str) or not expires.strip():
            raise IntotoTampered(f"in-toto layout at {layout_path!s} missing 'expires'")

    @staticmethod
    def _verify_vuln_scan(vuln_path: Path) -> VulnResult:
        """Parse a Grype JSON vulnerability scan. A parse failure
        contributes to partial grade (the threshold check fails) but
        does NOT raise — vulnerabilities-found is not the same as
        cryptographic tamper. Operators see the per-finding count +
        max CVSS in the result.

        Grype JSON shape: ``{"matches": [{"vulnerability": {"severity":
        "...", "cvss": [{"metrics": {"baseScore": 9.8}}]}, ...}]}``.

        Parse / shape failure ⇒ ``parse_failed=True`` (R3 reviewer-P2
        fix). The pipeline treats that as ``verified['vuln']=False``
        regardless of the threshold — a malformed scan can never
        earn full grade.

        ``parse_constant`` (R6 reviewer-P2 fix) rejects JSON-extension
        constants (``NaN`` / ``Infinity`` / ``-Infinity``) at the
        json-parse step. Without this hook ``baseScore: NaN``
        survives as Python's ``float('nan')`` and silently disables
        the threshold gate (NaN compares False against everything).
        """
        raw_data: Any
        try:
            raw_data = json.loads(
                vuln_path.read_text(encoding="utf-8"),
                parse_constant=_reject_non_finite_json_constant,
            )
        except (OSError, json.JSONDecodeError, ValueError):
            return VulnResult(
                total_findings=0,
                max_cvss=0.0,
                critical_count=0,
                has_known_exploit=False,
                parse_failed=True,
            )
        if not isinstance(raw_data, dict):
            return VulnResult(
                total_findings=0,
                max_cvss=0.0,
                critical_count=0,
                has_known_exploit=False,
                parse_failed=True,
            )
        matches = raw_data.get("matches", [])
        if not isinstance(matches, list):
            return VulnResult(
                total_findings=0,
                max_cvss=0.0,
                critical_count=0,
                has_known_exploit=False,
                parse_failed=True,
            )
        max_cvss = 0.0
        critical_count = 0
        has_known_exploit = False
        good_matches = 0
        # R6 reviewer-P2 fix: track present-but-malformed scores
        # (bool, non-finite, out-of-range). Any of these flips
        # parse_failed so a malformed inventory can never silently
        # earn ``verified['vuln']=True`` regardless of how loose the
        # tenant threshold is.
        malformed_score = False
        for match in matches:
            if not isinstance(match, dict):
                continue
            # No default — missing ``vulnerability`` key is malformed
            # inventory, not "empty findings". The ``isinstance`` check
            # below catches both missing-key and non-dict-value cases.
            vuln = match.get("vulnerability")
            if not isinstance(vuln, dict):
                continue
            good_matches += 1
            cvss_list = vuln.get("cvss", [])
            if isinstance(cvss_list, list):
                for cvss in cvss_list:
                    if not isinstance(cvss, dict):
                        continue
                    metrics = cvss.get("metrics", {})
                    if not isinstance(metrics, dict):
                        continue
                    if "baseScore" not in metrics:
                        continue  # missing key is acceptable; we just
                        # have nothing to extract from this cvss entry
                    score = metrics["baseScore"]
                    # Strict score validation: reject bool (subtype of
                    # int — would silently coerce to 0.0 / 1.0),
                    # non-numeric, non-finite (NaN already caught at
                    # json-parse), out-of-range (CVSS spec is 0..10).
                    if (
                        isinstance(score, bool)
                        or not isinstance(score, int | float)
                        or not math.isfinite(score)
                        or score < 0.0
                        or score > 10.0
                    ):
                        malformed_score = True
                        continue
                    max_cvss = max(max_cvss, float(score))
            severity = vuln.get("severity", "")
            if isinstance(severity, str) and severity.lower() == "critical":
                critical_count += 1
            # Grype sometimes ships an `epss` or `kev` annotation;
            # operators map "known exploit" off either field.
            if vuln.get("kev") is True or vuln.get("known_exploit") is True:
                has_known_exploit = True
        # R4 reviewer-P2 fix: a non-empty ``matches`` list with ZERO
        # parseable entries is a malformed inventory — we tried to
        # extract findings and got nothing. ``matches=[]`` (empty) is
        # legitimate (clean scan) and stays parse_failed=False.
        if matches and good_matches == 0:
            return VulnResult(
                total_findings=len(matches),
                max_cvss=0.0,
                critical_count=0,
                has_known_exploit=False,
                parse_failed=True,
            )
        if malformed_score:
            return VulnResult(
                total_findings=len(matches),
                max_cvss=0.0,
                critical_count=0,
                has_known_exploit=False,
                parse_failed=True,
            )
        return VulnResult(
            total_findings=len(matches),
            max_cvss=max_cvss,
            critical_count=critical_count,
            has_known_exploit=has_known_exploit,
        )

    @staticmethod
    def _verify_license_audit(audit_path: Path, allowlist: tuple[str, ...]) -> LicenseResult:
        """Parse a syft license JSON. Two accepted shapes:

          * ``{"licenses": ["MIT", "Apache-2.0", ...]}`` (flat)
          * ``{"artifacts": [{"licenses": [...]}, ...]}`` (per-artifact)

        Returns the unique license set + the subset NOT on the
        tenant allowlist. Empty allowlist means "no constraint" —
        nothing is disallowed.

        Parse / shape failure ⇒ ``parse_failed=True`` (R3 reviewer-P2
        fix). The pipeline treats that as ``verified['license']=False``
        — a malformed audit can't earn full grade by vacuously passing
        an allowlist.
        """
        try:
            data = json.loads(audit_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return LicenseResult(licenses=(), disallowed=(), parse_failed=True)
        if not isinstance(data, dict):
            return LicenseResult(licenses=(), disallowed=(), parse_failed=True)
        # R4 reviewer-P2 fix: a JSON object lacking BOTH ``licenses``
        # and ``artifacts`` is not shaped like an audit at all — refuse
        # to vacuously pass an allowlist check on a file that never
        # claimed to inventory anything.
        if "licenses" not in data and "artifacts" not in data:
            return LicenseResult(licenses=(), disallowed=(), parse_failed=True)
        # R5 reviewer-P2 fix: ``licenses`` or ``artifacts`` present
        # but wrong-typed (string / dict / null instead of list) is
        # malformed inventory — previously these silently skipped
        # both extraction loops and returned an empty parse_failed=False
        # result. Honour the present-but-invalid distinction same as
        # the SLSA / in-toto predicateType handling above.
        if "licenses" in data and not isinstance(data["licenses"], list):
            return LicenseResult(licenses=(), disallowed=(), parse_failed=True)
        if "artifacts" in data and not isinstance(data["artifacts"], list):
            return LicenseResult(licenses=(), disallowed=(), parse_failed=True)
        seen: set[str] = set()
        attempted_entries = 0
        flat = data.get("licenses")
        if isinstance(flat, list):
            for lic in flat:
                attempted_entries += 1
                if isinstance(lic, str) and lic.strip():
                    seen.add(lic.strip())
        artifacts = data.get("artifacts")
        if isinstance(artifacts, list):
            for artifact in artifacts:
                if not isinstance(artifact, dict):
                    continue
                artifact_licenses = artifact.get("licenses")
                if not isinstance(artifact_licenses, list):
                    continue
                for lic in artifact_licenses:
                    attempted_entries += 1
                    # syft sometimes emits {"value": "MIT"} dict
                    # entries instead of bare strings.
                    if isinstance(lic, str) and lic.strip():
                        seen.add(lic.strip())
                    elif isinstance(lic, dict):
                        value = lic.get("value")
                        if isinstance(value, str) and value.strip():
                            seen.add(value.strip())
        # R4 reviewer-P2 fix: tried-but-extracted-nothing ⇒ parse_failed.
        # An audit that lists ANY entries but produces zero parseable
        # licenses is malformed inventory; ``{"licenses": []}``
        # (intentionally empty — zero attempts) stays as a legitimate
        # parse_failed=False outcome.
        if attempted_entries > 0 and not seen:
            return LicenseResult(licenses=(), disallowed=(), parse_failed=True)
        licenses = tuple(sorted(seen))
        if not allowlist:
            disallowed: tuple[str, ...] = ()
        else:
            allowed_set = {a.strip() for a in allowlist}
            disallowed = tuple(lic for lic in licenses if lic not in allowed_set)
        return LicenseResult(licenses=licenses, disallowed=disallowed)


# --- helpers ------------------------------------------------------------


def _reject_non_finite_json_constant(value: str) -> Any:
    """``json.loads`` parse_constant hook — refuses NaN / Infinity /
    -Infinity tokens (Python's JSON-extension constants) at parse
    time. Without this, a malformed scan with ``baseScore: NaN``
    would survive as Python's ``float('nan')`` and silently disable
    threshold comparisons (NaN > x is False for all x). Used by
    ``_verify_vuln_scan``; the exception propagates and is caught by
    the verifier's outer parse-failure handler, flipping
    ``parse_failed=True``.
    """
    raise ValueError(f"non-finite JSON constant rejected: {value!r}")


__all__ = (
    "AttestationResult",
    "IntotoTampered",
    "LicenseResult",
    "SBOMMissing",
    "SBOMTampered",
    "SLSAResult",
    "SLSATampered",
    "SupplyChainError",
    "SupplyChainPipeline",
    "VulnResult",
    "VulnThresholds",
)
