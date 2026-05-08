"""Sprint-7A T14 — `agentos sign` orchestrator (CRITICAL CONTROLS).

Doctrine Decision F + ADR-016 — full Wave-1 attestation generator
shipping in three commits per the T14 split:

  - T14.A (this commit): ``agentos sign-blob <wheel-path>`` — narrow
    cosign sign-blob wrapper. Resolves cosign via ``shutil.which``
    (or ``settings.cosign_path``), wires the signing key from
    ``settings.signing_key_path`` (file path; ``vault://`` URIs land
    in T14.B alongside the SecretAdapter wiring), invokes cosign via
    real ``asyncio.create_subprocess_exec``, writes ``cosign.sig`` +
    ``bundle.sigstore`` to the wheel's parent directory.
  - T14.B (follow-up): ``agentos sign --bundle <pack-path>`` — full
    orchestrator (cosign + syft SBOM + grype vuln + license audit +
    SLSA provenance + in-toto layout + AgentCard JWS via joserfc).
  - T14.C (follow-up): ``agentos verify <pack-path>`` — offline
    trust-gate verifier ships in the matching ``cli/verify.py``.

Per Doctrine Decision G this module is on the critical-controls
floor (95% line / 90% branch). Every commit halts before commit per
the explicit halt-before-commit nominee list.

Closed-enum reasons owned by this module (T14 grows the literal
across all three sub-commits):

T14.A (sign-blob) reasons:
  - ``sign_cosign_not_installed`` — ``shutil.which("cosign")`` returns
    None AND ``settings.cosign_path`` is unset / unresolvable.
  - ``sign_signing_key_unavailable`` — ``signing_key_path`` is unset,
    points at a non-existent file, or (T14.B) the ``vault://`` URI
    returns ``None`` from the SecretAdapter.
  - ``sign_subprocess_failed`` — generic catch for cosign exit !=
    0, missing wheel input, or any subprocess-exec OSError. Payload
    carries which tool + the exit code or exception class.

T14.B (sign --bundle) reasons (land in the next commit):
  - ``sign_syft_not_installed`` / ``sign_grype_not_installed`` /
    ``sign_license_auditor_not_installed`` — per-tool ``shutil.which``
    refusals.
  - ``sign_agent_card_jws_signing_failed`` — joserfc exception during
    JWS production.
  - ``sign_provenance_template_render_failed`` /
    ``sign_intoto_layout_template_render_failed`` — template errors.

Production behaviour (Doctrine F):

  - ``shutil.which("<tool>")`` resolves the binary; missing → closed-
    enum refusal naming the missing tool with a remediation pointer.
  - All subprocess invocations use real
    ``asyncio.create_subprocess_exec`` (no ``subprocess.run`` mocking;
    tests use the Sprint-4 cosign-shim pattern extended per-tool).
  - Signing key resolution from the settings layer (file path in
    T14.A; ``vault://`` URI via SecretAdapter in T14.B).
  - ``--dev-mode-skip-cosign`` is gated behind a flag that prints a
    security warning to stderr; the prod profile rejects the flag at
    Settings construction time (``core/config.py:1035``).

Public surface (T14.A):

  - :func:`run_sign_blob` — pure async function, builds + returns the
    :class:`SignReport` without side effects on stdout/stderr/sys.exit.
  - :func:`format_sign_report` — text-mode + JSON renderer; mirrors
    validate's split-stream pattern.

Both entry points are wired by the Typer command in
:mod:`cognic_agentos.cli`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
from pathlib import Path
from typing import Any, Final, Literal

from cognic_agentos.cli import ValidatorReason
from cognic_agentos.core.config import Settings

# ---------------------------------------------------------------------------
# Closed-enum sub-narrow for T14.A
# ---------------------------------------------------------------------------

#: Closed-enum subset of :class:`ValidatorReason` that ``run_sign_blob``
#: emits at the T14.A scope. T14.B (sign --bundle) widens this to include
#: the syft / grype / license-auditor / JWS / template reasons.
_SIGN_BLOB_REASONS: Final[frozenset[str]] = frozenset(
    {
        "sign_cosign_not_installed",
        "sign_signing_key_unavailable",
        "sign_subprocess_failed",
    }
)


# ---------------------------------------------------------------------------
# Carrier dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class SignFinding:
    """Carrier for a closed-enum refusal emitted by the sign
    orchestrator. Mirrors :class:`cognic_agentos.cli.ValidatorFinding`
    but typed against the sign sub-narrow vocabulary so the JSON
    output schema stays single-sourced.
    """

    severity: Literal["refusal", "warning"]
    reason: ValidatorReason
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def affects_exit_code(self) -> bool:
        return self.severity == "refusal"


@dataclasses.dataclass(frozen=True, slots=True)
class SignReport:
    """Sign-orchestrator outcome.

    ``overall_status`` is ``"pass"`` iff ``findings`` carries no
    refusal-severity entries AND the relevant attestation files were
    produced (T14.A: ``cosign.sig`` + ``bundle.sigstore`` next to
    the input wheel; T14.B: the full 7-attestation set).
    """

    operation: Literal["sign-blob", "sign-bundle"]
    target_path: str
    overall_status: Literal["pass", "fail"]
    findings: list[SignFinding]
    artifacts: dict[str, str] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_cosign_path(settings: Settings) -> tuple[str | None, SignFinding | None]:
    """Resolve the cosign binary path. Returns ``(path, None)`` on
    success or ``(None, finding)`` with a closed-enum refusal on
    failure.

    Resolution order:
      1. ``settings.cosign_path`` if set + resolves via ``shutil.which``.
      2. ``shutil.which("cosign")`` against the host's PATH.

    A ``settings.cosign_path`` that points at a non-existent file
    short-circuits to the refusal — pack authors who set the override
    to a typo'd path get the same error as authors with no cosign
    installed. R-doctrine: never silently fall back to PATH when the
    operator explicitly named a path.
    """
    configured = settings.cosign_path
    if configured is not None:
        resolved = shutil.which(configured)
        if resolved is None:
            # Operator-named path doesn't resolve → refusal (no PATH fallback).
            return None, SignFinding(
                severity="refusal",
                reason="sign_cosign_not_installed",
                message=(
                    f"Settings.cosign_path={configured!r} does not resolve "
                    "via shutil.which (the file is missing, not executable, "
                    "or not on PATH). Install cosign in the named location, "
                    "or unset Settings.cosign_path to fall back to the "
                    "host's PATH."
                ),
                payload={"configured_path": configured},
            )
        return resolved, None

    # No override — try the host PATH.
    fallback = shutil.which("cosign")
    if fallback is None:
        return None, SignFinding(
            severity="refusal",
            reason="sign_cosign_not_installed",
            message=(
                "cosign binary not found via shutil.which on the host PATH "
                "AND Settings.cosign_path is unset. Install cosign "
                "(https://docs.sigstore.dev/cosign/installation/) or set "
                "COGNIC_COSIGN_PATH to its absolute path."
            ),
            payload={"configured_path": None},
        )
    return fallback, None


def _resolve_signing_key_path(
    settings: Settings,
) -> tuple[str | None, SignFinding | None]:
    """Resolve the signing key path from ``settings.signing_key_path``.

    T14.A scope: file paths only. ``vault://`` URIs return a refusal
    here; T14.B wires the SecretAdapter and routes URIs through that
    path. The Wave-1 narrow keeps the load-bearing signing-key
    resolution single-sourced.
    """
    configured = settings.signing_key_path
    if configured is None:
        return None, SignFinding(
            severity="refusal",
            reason="sign_signing_key_unavailable",
            message=(
                "Settings.signing_key_path is unset. Set "
                "COGNIC_SIGNING_KEY_PATH to a local PEM path (dev / test "
                "profiles) or a vault:// URI (T14.B — SecretAdapter "
                "resolution lands in the sign --bundle commit)."
            ),
            payload={"configured_path": None},
        )

    if "://" in configured:
        # Vault / kms / other URI shapes — T14.B SecretAdapter wires this.
        return None, SignFinding(
            severity="refusal",
            reason="sign_signing_key_unavailable",
            message=(
                f"Settings.signing_key_path={configured!r} is a URI shape; "
                "URI-based resolution (vault://, kms://, etc.) ships with "
                "T14.B's SecretAdapter wiring. Until T14.B lands, supply a "
                "local PEM file path."
            ),
            payload={"configured_path": configured, "uri_form": True},
        )

    key_path = Path(configured)
    if not key_path.is_file():
        return None, SignFinding(
            severity="refusal",
            reason="sign_signing_key_unavailable",
            message=(
                f"Settings.signing_key_path={configured!r} does not resolve "
                "to a file on disk. Verify the path; for synthetic test-only "
                "keys, see tests/fixtures/cli_sign_target_pack/attestations/"
                "test-signing/."
            ),
            payload={"configured_path": configured},
        )
    return str(key_path), None


async def _exec_cosign_sign_blob(
    cosign_bin: str,
    wheel_path: Path,
    *,
    signing_key_path: str,
    sig_output_path: Path,
    bundle_output_path: Path,
) -> tuple[int, bytes, bytes]:
    """Run ``cosign sign-blob`` via real
    ``asyncio.create_subprocess_exec``. Returns ``(returncode, stdout,
    stderr)``. Per Doctrine F invariant: list-form argv, no shell.

    Argv shape:
      cosign sign-blob --yes --key <key> --output-signature <sig>
        --bundle <bundle> <wheel>
    """
    # R1 P2 #2 reviewer correction — preserve the host process env
    # under cosign and ONLY overlay COSIGN_PASSWORD. An earlier draft
    # passed ``env={"COSIGN_PASSWORD": ""}`` which wiped the entire
    # child environment + broke production cosign flows that depend on
    # HOME (XDG cache + ~/.docker/config.json), PATH (helper-binary
    # resolution), HTTPS_PROXY / NO_PROXY (corporate egress), AWS_*
    # / GOOGLE_APPLICATION_CREDENTIALS / VAULT_ADDR (KMS / Vault
    # signing-key resolution), SIGSTORE_* (Rekor + Fulcio endpoints),
    # and TLS-trust-store overrides. Pinned by the
    # ``test_sign_blob_preserves_host_env_into_cosign_subprocess``
    # regression in test_cli_sign.py.
    cosign_env = {**os.environ, "COSIGN_PASSWORD": ""}
    proc = await asyncio.create_subprocess_exec(
        cosign_bin,
        "sign-blob",
        "--yes",  # skip "are you sure" prompt; required for non-interactive
        "--key",
        signing_key_path,
        "--output-signature",
        str(sig_output_path),
        "--bundle",
        str(bundle_output_path),
        str(wheel_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=cosign_env,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode or 0, stdout, stderr


def _verify_post_exec_artifacts(
    wheel_path: Path,
    *,
    sig_output_path: Path,
    bundle_output_path: Path,
) -> list[SignFinding]:
    """Probe ``sig_output_path`` + ``bundle_output_path`` on disk after
    cosign sign-blob has exited 0. Returns a list of refusals (one per
    missing / empty artifact); empty list means both artifacts landed
    cleanly.

    Per R1 P2 #1 reviewer doctrine: a successful cosign exit does NOT
    by itself prove the artifacts were written. Pack authors who get a
    green ``sign-blob: PASS`` exit MUST be able to trust the report;
    silently advertising non-existent paths would push the failure all
    the way to the runtime trust gate at admission time, far from the
    author's IDE.
    """
    findings: list[SignFinding] = []

    if not sig_output_path.is_file():
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"cosign sign-blob exited 0 but {sig_output_path} was "
                    "not produced. The signing subprocess succeeded "
                    "according to its exit code but failed to write the "
                    "expected --output-signature artifact; pack remains "
                    "unsigned. Common causes: KMS-write permission "
                    "denied silently, signal-on-fork before flush, "
                    "broken cosign shim wiring."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "tool": "cosign",
                    "expected_artifact": str(sig_output_path),
                    "failure_mode": "cosign_sig_output_missing",
                },
            )
        )
    elif sig_output_path.stat().st_size == 0:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"cosign sign-blob exited 0 but {sig_output_path} is "
                    "empty (zero bytes). An empty signature is not a "
                    "valid Sigstore artifact; pack remains unsigned."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "tool": "cosign",
                    "expected_artifact": str(sig_output_path),
                    "failure_mode": "cosign_sig_output_empty",
                },
            )
        )

    if not bundle_output_path.is_file():
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"cosign sign-blob exited 0 but {bundle_output_path} "
                    "was not produced. The signing subprocess succeeded "
                    "according to its exit code but failed to write the "
                    "expected --bundle artifact; the Sigstore bundle "
                    "(needed by the runtime trust gate's verify-blob "
                    "path per ADR-016) is missing."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "tool": "cosign",
                    "expected_artifact": str(bundle_output_path),
                    "failure_mode": "cosign_bundle_output_missing",
                },
            )
        )
    elif bundle_output_path.stat().st_size == 0:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"cosign sign-blob exited 0 but {bundle_output_path} "
                    "is empty (zero bytes). An empty Sigstore bundle is "
                    "not a valid attestation; the runtime trust gate "
                    "would refuse this pack at admission time."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "tool": "cosign",
                    "expected_artifact": str(bundle_output_path),
                    "failure_mode": "cosign_bundle_output_empty",
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public API: run_sign_blob
# ---------------------------------------------------------------------------


async def run_sign_blob(
    wheel_path: Path,
    settings: Settings,
    *,
    dev_mode_skip_cosign: bool = False,
) -> SignReport:
    """Build + return the :class:`SignReport` for ``wheel_path``.

    Pure async function: no stdout / stderr / sys.exit. The Typer
    wrapper renders + computes the exit code; pack-author tests can
    assert against the report directly.

    Pipeline:
      1. ``--dev-mode-skip-cosign`` short-circuit: emit a security
         warning + return a synthetic ``pass`` report. The prod-
         profile guard at ``core/config.py:1035`` already refuses the
         override at Settings construction; reaching this branch
         means dev / test profile.
      2. Resolve cosign via ``_resolve_cosign_path`` → refusal closes
         out the run with ``sign_cosign_not_installed``.
      3. Resolve signing key via ``_resolve_signing_key_path`` →
         refusal closes out with ``sign_signing_key_unavailable``.
      4. Probe the input wheel; missing → ``sign_subprocess_failed``
         with payload identifying the missing input.
      5. Run cosign sign-blob via real
         ``asyncio.create_subprocess_exec``; non-zero exit →
         ``sign_subprocess_failed`` with the captured stderr.
      6. On success, emit a ``pass`` report carrying the produced
         ``cosign.sig`` + ``bundle.sigstore`` paths in
         ``artifacts``.
    """
    findings: list[SignFinding] = []

    if dev_mode_skip_cosign:
        # Security-warning branch. Doctrine F: every dev-skip
        # invocation MUST surface the warning so CI parsers can
        # pattern-match for prod-profile leakage.
        findings.append(
            SignFinding(
                severity="warning",
                reason="sign_subprocess_failed",  # closest closed-enum; payload distinguishes
                message=(
                    "WARNING: --dev-mode-skip-cosign is set; cosign "
                    "sign-blob was NOT invoked. The output cosign.sig + "
                    "bundle.sigstore will NOT be produced. The prod "
                    "settings profile rejects this flag at startup; this "
                    "branch is only reachable from dev / test profiles."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "dev_mode_skip_cosign": True,
                },
            )
        )
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="pass",
            findings=findings,
            artifacts={},
        )

    cosign_bin, cosign_finding = _resolve_cosign_path(settings)
    if cosign_finding is not None:
        findings.append(cosign_finding)
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )
    assert cosign_bin is not None  # narrow for downstream

    key_path, key_finding = _resolve_signing_key_path(settings)
    if key_finding is not None:
        findings.append(key_finding)
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )
    assert key_path is not None

    if not wheel_path.is_file():
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign-blob input wheel {wheel_path} does not resolve "
                    "to a file on disk. Build the wheel (e.g., `python -m "
                    "build --wheel`) before invoking sign-blob."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "failure_mode": "wheel_not_found",
                },
            )
        )
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )

    sig_output_path = wheel_path.parent / "cosign.sig"
    bundle_output_path = wheel_path.parent / "bundle.sigstore"

    try:
        returncode, stdout, stderr = await _exec_cosign_sign_blob(
            cosign_bin,
            wheel_path,
            signing_key_path=key_path,
            sig_output_path=sig_output_path,
            bundle_output_path=bundle_output_path,
        )
    except OSError as exc:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"asyncio.create_subprocess_exec({cosign_bin}) raised "
                    f"{type(exc).__name__}: {exc}. Common causes: shim not "
                    "executable, ENOEXEC on a non-binary file, or kernel "
                    "permission denial."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "tool": "cosign",
                    "error_type": type(exc).__name__,
                    "failure_mode": "subprocess_oserror",
                },
            )
        )
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )

    if returncode != 0:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"cosign sign-blob exited {returncode}; stderr="
                    f"{stderr.decode('utf-8', errors='replace')!r}"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "tool": "cosign",
                    "exit_code": returncode,
                    "stdout": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "failure_mode": "cosign_exit_nonzero",
                },
            )
        )
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )

    # R1 P2 #1 reviewer correction — post-exec artifact verification.
    # Cosign exiting 0 does NOT, by itself, prove the .sig + .bundle
    # files were actually written. A buggy shim or a misconfigured
    # real cosign can exit 0 without producing output (e.g., missing
    # KMS-write permission, write-after-fork crash, signal that
    # cleared the buffer before flush). The orchestrator MUST probe
    # both artifacts on disk + reject empty files; otherwise the
    # report would falsely advertise non-existent ``cosign.sig`` /
    # ``bundle.sigstore`` paths to downstream verify + registry-
    # admission stages.
    #
    # Closed-enum failure_mode values (within the existing
    # ``sign_subprocess_failed`` reason; payload distinguishes):
    #   - ``cosign_sig_output_missing``
    #   - ``cosign_sig_output_empty``
    #   - ``cosign_bundle_output_missing``
    #   - ``cosign_bundle_output_empty``
    artifact_findings = _verify_post_exec_artifacts(
        wheel_path,
        sig_output_path=sig_output_path,
        bundle_output_path=bundle_output_path,
    )
    if artifact_findings:
        findings.extend(artifact_findings)
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )

    return SignReport(
        operation="sign-blob",
        target_path=str(wheel_path),
        overall_status="pass",
        findings=findings,
        artifacts={
            "cosign_sig": str(sig_output_path),
            "bundle_sigstore": str(bundle_output_path),
        },
    )


# ---------------------------------------------------------------------------
# Format helpers — split stdout/stderr (mirrors validate at T6 + harness at T13)
# ---------------------------------------------------------------------------


def format_sign_report_summary(report: SignReport) -> str:
    """Render the sign-orchestrator summary for stdout (text mode).

    Header + per-artifact line. Findings (refusals + warnings) go to
    :func:`format_sign_report_finding_annotations` for stderr-bound
    GH-Actions ``::error`` / ``::warning`` annotations.
    """
    lines: list[str] = []
    label = "PASS" if report.overall_status == "pass" else "FAIL"
    lines.append(f"{report.operation}: {label} ({report.target_path})")
    for name, path in sorted(report.artifacts.items()):
        lines.append(f"  artifact.{name}: {path}")
    return "\n".join(lines)


def format_sign_report_finding_annotations(report: SignReport) -> list[str]:
    """One GH-Actions ``::error`` / ``::warning`` annotation per
    refusal / warning. Mirrors validate's stderr-bound annotation
    pattern (T6) + the harness's T13 pattern."""
    lines: list[str] = []
    for f in report.findings:
        level = "error" if f.severity == "refusal" else "warning"
        lines.append(f"::{level} file={report.target_path}::{f.reason}: {f.message}")
    return lines


def format_sign_report(report: SignReport, *, json_output: bool) -> str:
    """JSON-mode renderer for ``--json`` output. Text mode uses the
    split helpers above so stdout / stderr routing matches validate +
    harness."""
    if json_output:
        return json.dumps(
            {
                "operation": report.operation,
                "target_path": report.target_path,
                "overall_status": report.overall_status,
                "findings": [
                    {
                        "severity": f.severity,
                        "reason": f.reason,
                        "message": f.message,
                        "payload": f.payload,
                    }
                    for f in report.findings
                ],
                "artifacts": report.artifacts,
            },
            sort_keys=True,
        )
    summary = format_sign_report_summary(report)
    annotations = format_sign_report_finding_annotations(report)
    if not annotations:
        return summary
    return "\n".join([summary, *annotations])


__all__ = [
    "SignFinding",
    "SignReport",
    "format_sign_report",
    "format_sign_report_finding_annotations",
    "format_sign_report_summary",
    "run_sign_blob",
]
