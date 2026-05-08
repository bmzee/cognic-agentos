"""Sprint-7A T1 + T4 — `agentos-cli` Typer app + closed-enum vocabulary.

This module is the public entry point for the `agentos` /
`agentos-cli` console scripts (registered in `pyproject.toml`
`[project.scripts]`) AND the home of the Sprint-7A closed-enum
vocabulary. T1 shipped the literal + the dataclass + the severity
helper; T4 added the Typer app skeleton + the public command surface
as fail-loud stubs. The per-concern validators (T7-T12) and the
sign/verify orchestrators (T14) consume the vocabulary; the
orchestrator at T6 aggregates findings into a single exit-code
calculation; T5-T14 each replace a stub body with the real
implementation.

Closed-enum doctrine (per the Sprint-7A plan-of-record):

  - ``ValidatorReason`` is the single closed-enum literal of every
    refusal + warning the validate command can emit. ~25 values at T1
    seed; grows during T7-T14 (per R6 P3 #5) — every growth point MUST
    update both ``_VALIDATOR_REASON_OWNERSHIP`` (reason → owning
    validator file) and the test-side `_EXPECTED_REFUSAL_REASONS` set
    in `tests/unit/test_config.py::TestSprint7AClosedEnumVocabulary`,
    OR add the new reason to ``_WARNING_REASONS`` if it's a warning.

  - Severity is derived **solely** from ``_WARNING_REASONS`` via
    ``severity_for(reason)``. Everything not in the warning set is a
    refusal by definition (R3 P2 #2 + R4 P2 #1 doctrine). The drift
    detector pins the exhaustive split: ``set(ValidatorReason) -
    _WARNING_REASONS == _EXPECTED_REFUSAL_REASONS``. Adding a literal
    value without explicitly placing it in either set trips the
    drift detector.

  - ``ValidatorFinding`` is the carrier dataclass for refusals +
    warnings. ``affects_exit_code`` is True iff severity == "refusal";
    the orchestrator (T6) computes exit code via
    ``any(f.affects_exit_code for f in findings)``.

Sprint-7A T1 + T4.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Final, Literal

import typer

#: Closed-enum union of every refusal + warning the validate command can
#: emit. T1 seed; grows during T7-T14 per R6 P3 #5. Whenever a new
#: reason lands, both the ownership map below AND the warning frozenset
#: (or the test-side `_EXPECTED_REFUSAL_REASONS` complement) MUST be
#: updated in the same commit.
ValidatorReason = Literal[
    # Manifest shape (T6 orchestrator) — refusals
    "manifest_not_found",
    "manifest_unparseable_toml",
    "manifest_missing_pack_id",
    "manifest_missing_required_block",
    # Identity (T7) — refusals
    "identity_agent_id_missing",
    "identity_display_name_missing",
    "identity_provider_organization_missing",
    "identity_provider_url_missing",
    "identity_agent_card_url_missing",
    "identity_agent_card_jws_path_missing",
    "identity_agent_card_jws_path_unresolvable",
    # Identity (T7) — warning (severity="warning"; exit 0)
    "identity_oasf_capability_set_missing",
    # A2A (T8) — refusal
    "a2a_wave2_feature_in_wave1_manifest",
    # MCP (T9) — refusals
    "mcp_wave2_feature_in_wave1_manifest",
    "mcp_caching_restricted_data_class",
    "mcp_elicitation_form_restricted_data_class",
    # Data governance (T10) — refusals
    "data_governance_contract_missing",
    "data_governance_contract_inconsistent_with_risk_tier",
    "data_governance_contract_inconsistent_with_mcp_caching",
    # Risk tier (T11) — refusal
    "risk_tier_inconsistent_with_data_classes",
    # Supply chain (T12) — refusals
    "supply_chain_attestation_path_missing",
    "supply_chain_attestation_path_unresolvable",
    # Sign (T14 — full Wave-1 bundle generator per Doctrine Decision F
    # + ADR-016; 9 reasons covering missing-tool refusals + signing-key
    # resolution + subprocess-exec failures + JWS-signing failures +
    # template-render failures).
    "sign_cosign_not_installed",
    "sign_syft_not_installed",
    "sign_grype_not_installed",
    "sign_license_auditor_not_installed",
    "sign_signing_key_unavailable",
    "sign_subprocess_failed",
    "sign_agent_card_jws_signing_failed",
    "sign_provenance_template_render_failed",
    "sign_intoto_layout_template_render_failed",
    # Verify (T14 — offline trust gate per ADR-016 Sprint-7A mandate;
    # mirrors the Sprint-4 runtime trust-gate verification path; 7
    # closed-enum reasons covering each of the 6 verification steps
    # plus the trust-root-resolution refusal R7 P2 #2 added).
    "verify_cosign_signature_invalid",
    "verify_sbom_digest_mismatch",
    "verify_provenance_invalid",
    "verify_intoto_layout_invalid",
    "verify_attestation_path_unresolvable",
    "verify_agent_card_jws_invalid",
    "verify_trust_root_path_unresolvable",
]


#: Closed frozenset of warning-severity ``ValidatorReason`` values.
#: Everything not in this set is a refusal by definition. T1 seed:
#: 1 warning (the AGNTCY/OASF Wave-1 optional capability_set field).
#: Growth via the drift-detector test in
#: ``test_config.py::TestSprint7AClosedEnumVocabulary``.
_WARNING_REASONS: Final[frozenset[ValidatorReason]] = frozenset(
    {
        "identity_oasf_capability_set_missing",
    }
)


#: Closed mapping: ``ValidatorReason`` → owning validator-file name.
#: T1 seed; grows during T7-T14 alongside the literal. Every reason
#: lands here exactly once — the file name is the validator that owns
#: emission of that reason. Drift-detector test pins the exhaustive
#: domain (every literal value MUST appear as a key here).
_VALIDATOR_REASON_OWNERSHIP: Final[dict[ValidatorReason, str]] = {
    # Manifest shape — owned by the orchestrator itself (no validator file).
    "manifest_not_found": "validate.py",
    "manifest_unparseable_toml": "validate.py",
    "manifest_missing_pack_id": "validate.py",
    "manifest_missing_required_block": "validate.py",
    # Identity (T7)
    "identity_agent_id_missing": "validators/identity.py",
    "identity_display_name_missing": "validators/identity.py",
    "identity_provider_organization_missing": "validators/identity.py",
    "identity_provider_url_missing": "validators/identity.py",
    "identity_agent_card_url_missing": "validators/identity.py",
    "identity_agent_card_jws_path_missing": "validators/identity.py",
    "identity_agent_card_jws_path_unresolvable": "validators/identity.py",
    "identity_oasf_capability_set_missing": "validators/identity.py",
    # A2A (T8)
    "a2a_wave2_feature_in_wave1_manifest": "validators/a2a.py",
    # MCP (T9)
    "mcp_wave2_feature_in_wave1_manifest": "validators/mcp.py",
    "mcp_caching_restricted_data_class": "validators/mcp.py",
    "mcp_elicitation_form_restricted_data_class": "validators/mcp.py",
    # Data governance (T10)
    "data_governance_contract_missing": "validators/data_governance.py",
    "data_governance_contract_inconsistent_with_risk_tier": "validators/data_governance.py",
    "data_governance_contract_inconsistent_with_mcp_caching": "validators/data_governance.py",
    # Risk tier (T11)
    "risk_tier_inconsistent_with_data_classes": "validators/risk_tier.py",
    # Supply chain (T12)
    "supply_chain_attestation_path_missing": "validators/supply_chain.py",
    "supply_chain_attestation_path_unresolvable": "validators/supply_chain.py",
    # Sign (T14 — full Wave-1 bundle generator per Doctrine Decision F)
    "sign_cosign_not_installed": "sign.py",
    "sign_syft_not_installed": "sign.py",
    "sign_grype_not_installed": "sign.py",
    "sign_license_auditor_not_installed": "sign.py",
    "sign_signing_key_unavailable": "sign.py",
    "sign_subprocess_failed": "sign.py",
    "sign_agent_card_jws_signing_failed": "sign.py",
    "sign_provenance_template_render_failed": "sign.py",
    "sign_intoto_layout_template_render_failed": "sign.py",
    # Verify (T14 — offline trust gate per ADR-016 Sprint-7A mandate)
    "verify_cosign_signature_invalid": "verify.py",
    "verify_sbom_digest_mismatch": "verify.py",
    "verify_provenance_invalid": "verify.py",
    "verify_intoto_layout_invalid": "verify.py",
    "verify_attestation_path_unresolvable": "verify.py",
    "verify_agent_card_jws_invalid": "verify.py",
    "verify_trust_root_path_unresolvable": "verify.py",
}


def severity_for(reason: ValidatorReason) -> Literal["refusal", "warning"]:
    """Return the finding severity for ``reason``.

    Single source-of-truth for severity: a reason is a warning iff it
    appears in ``_WARNING_REASONS``; otherwise it's a refusal. R3 P2 #2
    + R4 P2 #1 doctrine — severity is NOT carried alongside ownership;
    the two axes are independent and pinned independently by drift
    detectors.
    """
    return "warning" if reason in _WARNING_REASONS else "refusal"


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatorFinding:
    """Carrier dataclass for refusals + warnings emitted by per-concern
    validators.

    The orchestrator (T6) aggregates ``list[ValidatorFinding]`` across
    every validator, renders all of them to stderr, and computes exit
    code via ``any(f.affects_exit_code for f in findings)`` so
    warning-severity findings do NOT cause exit 1.

    Per R1 P2 #3 + R3 P2 #2 doctrine: the severity-aware finding model
    keeps the warning channel propagating end-to-end (validator →
    orchestrator → CI parsers) without conflating with refusals.

    **Immutability: shallow only** (R11 P3 #2 reviewer correction —
    the earlier draft claimed "hashable + immutable" which was
    incorrect). ``frozen=True`` + ``slots=True`` block attribute
    reassignment on the finding instance itself, but ``payload`` is a
    plain ``dict[str, Any]`` so callers CAN mutate it via
    ``finding.payload["x"] = "y"``. The orchestrator's render pipeline
    treats findings as logically read-only by convention; deeper
    immutability isn't a load-bearing contract here. Findings are
    NOT hashable — ``hash(finding)`` raises ``TypeError`` because
    ``payload`` is a dict. If the orchestrator ever needs hashable
    findings for deduplication, the caller can map to
    ``(severity, reason, message)`` tuples explicitly.
    """

    severity: Literal["refusal", "warning"]
    reason: ValidatorReason
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def affects_exit_code(self) -> bool:
        """True iff this finding should cause non-zero exit. Refusals
        affect exit code; warnings do not."""
        return self.severity == "refusal"


# ---------------------------------------------------------------------------
# Sprint-7A T4 — Typer app skeleton
# ---------------------------------------------------------------------------
#
# Public command surface (5 verbs covering the pack-author workflow:
# scaffold / validate / test / sign / verify) + the ``init`` sub-app
# that hosts the three scaffold-a-pack subcommands at T5. Every public
# command is registered here at T4 as a fail-loud stub; T5-T14 each
# replace a stub body with the real implementation. Pinning the full
# surface from T4 keeps ``agentos --help`` stable across the sprint.
#
# Stub UX: ``typer.echo(message, err=True) + raise typer.Exit(code=2)``
# is the doctrinal pattern for "command exists but is not yet wired"
# (per AGENTS.md production-grade rule — fail loudly, point at the
# task that lands the real implementation).

app = typer.Typer(
    name="agentos",
    help=(
        "AgentOS pack-author CLI — scaffold, validate, test, sign, "
        "and verify Cognic-compatible plugin packs."
    ),
    no_args_is_help=True,
)


def _stub_exit(message: str) -> None:
    """Common fail-loud stub body. Writes the "not yet wired" pointer
    to stderr (so ``agentos validate ... > /dev/null`` still surfaces
    the message) + exits with code 2 (reserved for "command exists
    but is not implemented yet" — distinct from validate's exit 1
    refusal at T6 + future success exit 0)."""
    typer.echo(message, err=True)
    raise typer.Exit(code=2)


# R16 P2 #1 reviewer correction: the T4 stubs declare placeholder
# arguments + options matching the canonical T5 / T6 / T13 / T14
# surfaces documented in the Sprint-7A plan-of-record so natural
# pack-author invocations (``agentos init-tool foo``,
# ``agentos validate .``, ``agentos sign --bundle .``, etc.) parse
# cleanly + reach the fail-loud ``_stub_exit`` body. The placeholder
# values are intentionally unused — the real argument semantics land
# alongside each command's real implementation at T5 / T6 / T13 / T14.
#
# R17 P2 #1 reviewer correction: the three scaffold commands ship as
# top-level hyphenated commands (``init-tool`` / ``init-skill`` /
# ``init-agent``), NOT as sub-commands of an ``init`` sub-app. This
# matches the T5 plan-of-record's documented surface exactly
# (``agentos init-tool example`` is the canonical T5 invocation).
# An earlier T4 draft wired ``init`` as a sub-app per a stale fragment
# of the T4 example code, but that would have forced T5 to either
# fight the T4 contract or silently shift the documented CLI shape
# to nested commands. Top-level hyphenated stubs is the consistent
# pattern across every other Sprint-7A CLI verb.


def _run_init(kind: str, pack_name: str) -> None:
    """Common init-* command body. Delegates to :func:`scaffold` and
    renders a clean fail-loud message if scaffolding refuses (invalid
    pack name, target exists, etc.) — the exception text comes
    straight from :class:`ScaffoldError`'s remediation copy."""
    from cognic_agentos.cli.init import ScaffoldError, scaffold

    try:
        pack_root = scaffold(kind=kind, pack_name=pack_name, parent_dir=Path.cwd())
    except ScaffoldError as exc:
        typer.echo(f"agentos init-{kind}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"scaffolded {kind} pack at {pack_root}")
    typer.echo(
        "Next steps: edit AUTHOR-FILL placeholders, then run "
        "`agentos validate <pack>` to surface remaining gaps."
    )


@app.command(name="init-tool")
def init_tool(
    pack_name: str = typer.Argument(
        ...,
        help=(
            "Name of the new tool pack. Produces ``cognic-tool-<name>/`` "
            "in the current working directory, scaffolded from the "
            "bundled ``cli/templates/tool/`` Jinja2 templates."
        ),
    ),
) -> None:
    """Scaffold a new tool pack repo from the bundled templates.

    The generated tree includes pyproject.toml + cognic-pack-manifest.toml
    + a ``Tool`` subclass overriding ``_invoke()`` + tests/conftest.py
    wired against ``agentos_sdk.testing``. Pack name MUST be a
    lowercase Python-identifier fragment (a-z, 0-9, _; cannot start
    with a digit).
    """
    _run_init("tool", pack_name)


@app.command(name="init-skill")
def init_skill(
    pack_name: str = typer.Argument(
        ...,
        help=(
            "Name of the new skill pack. Produces ``cognic-skill-<name>/`` "
            "in the current working directory."
        ),
    ),
) -> None:
    """Scaffold a new skill pack repo from the bundled templates.

    Skills compose tools deterministically; the generated subclass
    declares ``declared_tools`` + overrides ``execute()``. The SDK's
    ``Skill.__init_subclass__`` refuses subclasses that define their
    own constructor (R6 P2 #1) — pack-specific init logic goes in
    the ``setup()`` hook the base class calls after the registry
    cross-check.
    """
    _run_init("skill", pack_name)


@app.command(name="init-agent")
def init_agent(
    pack_name: str = typer.Argument(
        ...,
        help=(
            "Name of the new agent pack. Produces ``cognic-agent-<name>/`` "
            "in the current working directory."
        ),
    ),
) -> None:
    """Scaffold a new agent pack repo from the bundled templates.

    The generated tree includes an empty ``agent_cards/`` directory,
    an ``Agent`` subclass overriding ``handle(payload, *, task)``
    matching the shipped Sprint-6 ``A2AEndpoint`` dispatch contract,
    and a ``cognic-pack-manifest.toml`` declaring the agent's A2A
    capabilities.
    """
    _run_init("agent", pack_name)


@app.command()
def validate(
    pack_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the pack directory whose manifest will be validated.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help=(
            "Emit findings as one-JSON-per-line for CI parsers. The JSON "
            "shape carries severity / reason / message / payload."
        ),
    ),
) -> None:
    """Run the manifest validation pipeline against a pack directory.

    Dispatches to every per-concern validator (identity / a2a / mcp /
    data_governance / risk_tier / supply_chain), renders each finding
    to stderr, and exits 1 iff any finding is refusal-severity.
    Warning-severity findings render but do NOT affect exit code
    (R3 P2 #2 doctrine — the warning channel surfaces optional
    Wave-1 fields without failing CI).
    """
    from cognic_agentos.cli.validate import format_finding, run_validators

    findings = run_validators(pack_path)
    for f in findings:
        typer.echo(format_finding(f, json_output=json_output, pack_path=pack_path), err=True)
    if any(f.affects_exit_code for f in findings):
        raise typer.Exit(code=1)
    typer.echo(f"validate: PASS ({pack_path})")


@app.command(name="test-harness")
def test_harness(
    pack_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the pack directory the hybrid harness will exercise.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help=(
            "Emit the conformance report as a single JSON object on "
            "stdout (deterministic-ordered keys) for CI parsers."
        ),
    ),
) -> None:
    """Run the hybrid test harness against a pack repo.

    Per Doctrine Decision C, the harness runs the validate pipeline
    + dispatch dry-run against fixture adapters (no live transports)
    + emits a conformance report covering identity / A2A / MCP /
    data-governance / risk-tier / supply-chain / dispatch outcome.

    Exits 0 when ``HarnessReport.overall_status == "pass"``; 1 when
    the report fails (validate refusals OR dispatch failures).
    """
    from cognic_agentos.cli.test_harness import (
        format_report,
        format_report_finding_annotations,
        format_report_summary,
        run_harness,
    )

    report = run_harness(pack_path)
    if json_output:
        typer.echo(format_report(report, json_output=True))
    else:
        typer.echo(format_report_summary(report))
        for annotation in format_report_finding_annotations(report):
            typer.echo(annotation, err=True)
    if report.overall_status != "pass":
        raise typer.Exit(code=1)


@app.command(name="sign-blob")
def sign_blob(
    wheel_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the wheel to sign with cosign sign-blob.",
    ),
    dev_mode_skip_cosign: bool = typer.Option(
        False,
        "--dev-mode-skip-cosign",
        help=(
            "Skip the real cosign invocation (dev-only; rejected in the "
            "prod settings profile per Doctrine F)."
        ),
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help=(
            "Emit the sign report as a single JSON object on stdout "
            "(deterministic-ordered keys) for CI parsers."
        ),
    ),
) -> None:
    """Cosign sign-blob a single artifact (Wave-1 minimal sign path).

    Lands in Sprint-7A T14.A — narrow cosign sign-blob wrapper.
    Resolves cosign via ``shutil.which`` (or ``settings.cosign_path``),
    wires the signing key from ``settings.signing_key_path``, invokes
    cosign via real ``asyncio.create_subprocess_exec``, and writes
    ``cosign.sig`` + ``bundle.sigstore`` to the wheel's parent
    directory.

    Exits 0 when ``SignReport.overall_status == "pass"``; 1 when the
    report fails (cosign-not-installed / signing-key-unavailable /
    subprocess-failed).
    """
    import asyncio as _asyncio

    from pydantic import ValidationError as _ValidationError

    from cognic_agentos.cli.sign import (
        format_sign_report,
        format_sign_report_finding_annotations,
        format_sign_report_summary,
        run_sign_blob,
    )
    from cognic_agentos.core.config import build_settings_without_env_file

    # Build Settings — Pydantic ValidationError surfaces if the prod-
    # profile guards (config.py:966 signing_key_path-under-fixture-tree;
    # config.py:1035 dev_mode_skip_cosign-in-prod) reject the input.
    # Render the error to stderr before exiting so pack authors see
    # the validator's own remediation message, not a raw traceback.
    try:
        settings = build_settings_without_env_file()
    except _ValidationError as exc:
        typer.echo(f"agentos sign-blob: Settings validation refused: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # Layer the CLI --dev-mode-skip-cosign flag onto Settings + re-
    # validate so prod-profile invocations of the flag fire the same
    # guard even when the env var was unset.
    if dev_mode_skip_cosign and not settings.dev_mode_skip_cosign:
        try:
            mutated = settings.model_dump()
            mutated["dev_mode_skip_cosign"] = True
            settings = type(settings).model_validate(mutated)
        except _ValidationError as exc:
            typer.echo(
                f"agentos sign-blob: --dev-mode-skip-cosign refused by Settings validation: {exc}",
                err=True,
            )
            raise typer.Exit(code=2) from exc

    report = _asyncio.run(
        run_sign_blob(
            wheel_path,
            settings,
            dev_mode_skip_cosign=dev_mode_skip_cosign,
        )
    )
    if json_output:
        typer.echo(format_sign_report(report, json_output=True))
    else:
        typer.echo(format_sign_report_summary(report))
        for annotation in format_sign_report_finding_annotations(report):
            typer.echo(annotation, err=True)
    if report.overall_status != "pass":
        raise typer.Exit(code=1)


@app.command()
def sign(
    pack_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the pack directory to sign.",
    ),
    bundle: bool = typer.Option(
        False,
        "--bundle",
        help=(
            "Generate the full Wave-1 attestation set (cosign + SBOM + "
            "SLSA provenance + in-toto layout + AgentCard JWS) per "
            "Doctrine Decision F. Without --bundle, this command refuses "
            "(use ``agentos sign-blob <wheel>`` for the narrow path)."
        ),
    ),
    dev_mode_skip_cosign: bool = typer.Option(
        False,
        "--dev-mode-skip-cosign",
        help=(
            "Skip the real cosign invocation (dev-only; rejected in the "
            "prod settings profile per Doctrine F)."
        ),
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help=(
            "Emit the sign report as a single JSON object on stdout "
            "(deterministic-ordered keys) for CI parsers."
        ),
    ),
) -> None:
    """Generate the full signed-bundle attestation set for a pack.

    Lands in Sprint-7A T14.B — orchestrates the full Wave-1 recipe:
    cosign + syft SBOM + grype vuln scan + license audit + SLSA
    provenance template + in-toto layout template + AgentCard JWS
    (agent packs only) per Doctrine Decision F + ADR-016. Per-tool
    fail-loud refusal if any external binary is missing; closed-enum
    reasons name the missing tool for CI parsers.

    Exits 0 when ``SignReport.overall_status == "pass"``; 1 when the
    report fails (missing-tool / signing-key-unavailable / subprocess-
    failed / template-render-failed / JWS-signing-failed).

    Without ``--bundle``, the command refuses + points at
    ``agentos sign-blob`` for the narrow cosign-only path.
    """
    import asyncio as _asyncio

    from pydantic import ValidationError as _ValidationError

    from cognic_agentos.cli.sign import (
        format_sign_report,
        format_sign_report_finding_annotations,
        format_sign_report_summary,
        run_sign_bundle,
    )
    from cognic_agentos.core.config import build_settings_without_env_file

    if not bundle:
        typer.echo(
            "agentos sign: --bundle is required for the full Wave-1 "
            "attestation orchestrator. For the narrow cosign-only path "
            "use `agentos sign-blob <wheel>`.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        settings = build_settings_without_env_file()
    except _ValidationError as exc:
        typer.echo(f"agentos sign: Settings validation refused: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if dev_mode_skip_cosign and not settings.dev_mode_skip_cosign:
        try:
            mutated = settings.model_dump()
            mutated["dev_mode_skip_cosign"] = True
            settings = type(settings).model_validate(mutated)
        except _ValidationError as exc:
            typer.echo(
                f"agentos sign: --dev-mode-skip-cosign refused by Settings validation: {exc}",
                err=True,
            )
            raise typer.Exit(code=2) from exc

    # R7 P2 #2 reviewer correction: SecretAdapter construction lives
    # inside the orchestrator (lazy, only for vault:// URIs).
    # Construction failures collapse into a structured
    # ``sign_signing_key_unavailable`` finding routed through the
    # SignReport pipeline — preserves the JSON-output contract for
    # CI parsers in --json mode. Pre-R7 the CLI built the adapter
    # eagerly + exited 2 with a plain stderr string, bypassing
    # JSON output entirely.
    report = _asyncio.run(
        run_sign_bundle(
            pack_path,
            settings,
            dev_mode_skip_cosign=settings.dev_mode_skip_cosign,
        )
    )
    if json_output:
        typer.echo(format_sign_report(report, json_output=True))
    else:
        typer.echo(format_sign_report_summary(report))
        for annotation in format_sign_report_finding_annotations(report):
            typer.echo(annotation, err=True)
    if report.overall_status != "pass":
        raise typer.Exit(code=1)


@app.command()
def verify(
    pack_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to the pack directory whose attestations will be verified.",
    ),
    trust_root: str | None = typer.Option(
        None,
        "--trust-root",
        help=(
            "Trust-root path (or ``vault://...`` URI resolved via the "
            "SecretAdapter) the cosign + JWS verifications run against."
        ),
    ),
) -> None:
    """Offline trust-gate verifier — verify a signed pack's bundle.

    Lands in Sprint-7A T14 — mirrors the runtime
    ``protocol/trust_gate.py`` checks so pack authors can verify
    locally before publishing.
    """
    del pack_path, trust_root  # placeholders until T14
    _stub_exit(
        "agentos verify is not yet wired — lands in Sprint-7A T14 "
        "(offline trust-gate verifier mirroring protocol/trust_gate)."
    )


__all__ = [
    "_VALIDATOR_REASON_OWNERSHIP",
    "_WARNING_REASONS",
    "ValidatorFinding",
    "ValidatorReason",
    "app",
    "severity_for",
]
