"""Sprint-7A T14.C — `agentos verify` orchestrator (CRITICAL CONTROLS).

Doctrine Decision F + ADR-016 — offline trust-gate verifier. Mirrors
the runtime trust-gate (Sprint-4 ``protocol/trust_gate.py``) admission
checks so pack authors can verify locally before publishing.

Shipped surface:

  - **``agentos verify <pack-path>``** — runs every verification step
    a Sprint-4-onward AgentOS deployment would run at admission time:
    cosign verify-blob over the wheel; SBOM digest match against SLSA;
    SLSA + in-toto file shape; attestation file probes; AgentCard JWS
    cryptographic verification (agent packs only); manifest re-
    validation via the full ``run_validators`` pipeline.

The trust root supplied via ``--trust-root <path>`` (or
``vault://...`` URI resolved through the bundled SecretAdapter)
is the single per-pack signer's public PEM. Wave-1 simplification
per Doctrine F: single-signer Wave-1 (multi-signature attestations
are out-of-scope).

Per Doctrine Decision G this module is on the critical-controls
floor (95% line / 90% branch). Halt-before-commit applies.

Closed-enum reasons owned by this module (full T14.C set; pre-
seeded in T1 + drift-detector pinned in
``test_config.py::TestSprint7AClosedEnumVocabulary``):

  - ``verify_trust_root_path_unresolvable`` — neither --trust-root
    flag nor ``Settings.signing_trust_root_path`` set; flag points
    at a non-existent file; ``vault://`` URI returns no payload /
    malformed payload / SecretAdapter raises.
  - ``verify_cosign_signature_invalid`` — cosign verify-blob exits
    non-zero; cosign binary missing entirely (mapped here since
    "tool missing" is indistinguishable from "signature invalid"
    from the user's perspective); cosign subprocess raises OSError.
    Sub-cases distinguished via ``payload.failure_mode``.
  - ``verify_sbom_digest_mismatch`` — recomputed SBOM SHA-256 does
    not match the SLSA-recorded
    ``predicate.buildDefinition.externalParameters.sbom_digest_sha256``.
  - ``verify_provenance_invalid`` — SLSA file unparseable JSON;
    missing required keys; subject digest doesn't match on-disk
    wheel; predicateType is not the SLSA Provenance v1 URI.
  - ``verify_intoto_layout_invalid`` — in-toto layout file
    unparseable JSON; missing _type; empty artifact_paths; _type
    is not the AgentOS Wave-1 layout URI.
  - ``verify_attestation_path_unresolvable`` — any of the 7
    attestation files (cosign.sig, bundle.sigstore, sbom.cdx.json,
    vuln-scan.json, license-audit.json, slsa-provenance.intoto.json,
    intoto-layout.json) missing or empty; the wheel itself missing
    from dist/ also routes here (the wheel IS the signed target).
    Agent packs additionally check the manifest-declared
    agent_card_jws_path.
  - ``verify_agent_card_jws_invalid`` — joserfc detached-payload
    deserialize_compact raises BadSignatureError / DecodeError /
    ValueError on the JWS bytes against the trust-root public PEM.

Production behaviour (Doctrine F):

  - All subprocess invocations use real
    ``asyncio.create_subprocess_exec`` (no ``subprocess.run``
    mocking; tests use the cosign-shim pattern).
  - Trust-root resolution: file path → returned as-is; ``vault://``
    URI → resolved via the bundled SecretAdapter (lazy construction
    so adapter-construction failures collapse into a structured
    ``verify_trust_root_path_unresolvable`` finding routed through
    the VerifyReport pipeline). Resolved PEM bytes are written to
    a tempfile under the orchestrator's try/finally cleanup.
  - SBOM digest verification: recomputed via
    ``hashlib.sha256(sbom_bytes).hexdigest()`` against the
    SLSA-recorded sbom_digest_sha256 — no parse-and-trust path.
  - Manifest re-validation calls
    ``cognic_agentos.cli.validate.run_validators`` directly so
    every refusal that admission-time would catch surfaces
    locally too.

Public surface:

  - :func:`run_verify` — pure async function; builds + returns a
    :class:`VerifyReport` without side effects on stdout / stderr /
    sys.exit.
  - :func:`format_verify_report` — text + JSON renderer mirroring
    sign's split-stream pattern.

The Typer command in :mod:`cognic_agentos.cli` is a thin shell
over ``run_verify`` + ``format_verify_report``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import shutil
import tempfile
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from cognic_agentos.cli import ValidatorReason
from cognic_agentos.cli.sign import (
    _AGENTOS_INTOTO_LAYOUT_TYPE,
    _INTOTO_STATEMENT_TYPE,
    _SLSA_PROVENANCE_PREDICATE_TYPE,
    _VALID_PACK_KINDS,
)
from cognic_agentos.core.config import Settings

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

# ---------------------------------------------------------------------------
# Closed-enum sub-narrow (drift-detector pinned in test_config.py).
# ---------------------------------------------------------------------------

_VERIFY_REASONS: Final[frozenset[str]] = frozenset(
    {
        "verify_cosign_signature_invalid",
        "verify_sbom_digest_mismatch",
        "verify_provenance_invalid",
        "verify_intoto_layout_invalid",
        "verify_attestation_path_unresolvable",
        "verify_agent_card_jws_invalid",
        "verify_trust_root_path_unresolvable",
        "verify_entry_point_load_failed",
    }
)


# ---------------------------------------------------------------------------
# Carrier dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class VerifyFinding:
    """Carrier for a closed-enum refusal emitted by the verify
    orchestrator. Mirrors :class:`cognic_agentos.cli.sign.SignFinding`
    + :class:`cognic_agentos.cli.ValidatorFinding` so the JSON output
    schema stays single-sourced across sign / verify / validate.
    """

    severity: Literal["refusal", "warning"]
    reason: ValidatorReason
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def affects_exit_code(self) -> bool:
        return self.severity == "refusal"


@dataclasses.dataclass(frozen=True, slots=True)
class VerifyReport:
    """Verify-orchestrator outcome. ``overall_status`` is ``"pass"``
    iff ``findings`` carries no refusal-severity entries AND every
    expected attestation was verified.
    """

    operation: Literal["verify"]
    target_path: str
    overall_status: Literal["pass", "fail"]
    findings: list[VerifyFinding]
    artifacts_verified: list[str] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Trust-root resolution
# ---------------------------------------------------------------------------


def _build_secret_adapter(settings: Settings) -> SecretAdapter:
    """Build a :class:`SecretAdapter` from ``settings.secret_driver``
    via the bundled adapter registry — narrow construction mirroring
    ``cli.sign._build_secret_adapter`` (intentionally module-level so
    tests can monkeypatch a per-test in-memory adapter without
    invoking the full bundled registry).
    """
    from cognic_agentos.db.adapters import bundled_registry, load_bundled_adapters
    from cognic_agentos.db.adapters.factory import _secret_args

    load_bundled_adapters()
    secret_cls = bundled_registry.resolve("secret", settings.secret_driver)
    instance: SecretAdapter = secret_cls(*_secret_args(settings))
    return instance


async def _resolve_trust_root(
    *,
    cli_trust_root: str | None,
    settings: Settings,
    secret_adapter: SecretAdapter | None = None,
) -> tuple[str | None, Path | None, VerifyFinding | None]:
    """Resolve the trust-root path from the --trust-root flag (preferred)
    or ``Settings.signing_trust_root_path``. Returns
    ``(trust_root_path_for_cosign, tempfile_to_cleanup, finding)``.

    Vault URIs are read via the SecretAdapter; payload shape is
    ``{"key": <pem-bytes>}`` mirroring the signing-key resolution at
    ``cli.sign._resolve_signing_key_path``.
    """
    configured = cli_trust_root if cli_trust_root is not None else settings.signing_trust_root_path
    if configured is None:
        return (
            None,
            None,
            VerifyFinding(
                severity="refusal",
                reason="verify_trust_root_path_unresolvable",
                message=(
                    "neither --trust-root flag nor "
                    "COGNIC_SIGNING_TRUST_ROOT_PATH env (or "
                    "Settings.signing_trust_root_path) is set. "
                    "Pass --trust-root <path-to-public-pem> or set "
                    "the env var to a vault:// URI."
                ),
                payload={"failure_mode": "trust_root_unset"},
            ),
        )

    if configured.startswith("vault://"):
        if secret_adapter is None:
            try:
                secret_adapter = _build_secret_adapter(settings)
            except Exception as exc:
                return (
                    None,
                    None,
                    VerifyFinding(
                        severity="refusal",
                        reason="verify_trust_root_path_unresolvable",
                        message=(
                            f"Settings.signing_trust_root_path={configured!r} is a "
                            f"vault:// URI but SecretAdapter construction "
                            f"failed: {type(exc).__name__}: {exc}."
                        ),
                        payload={
                            "configured_trust_root": configured,
                            "uri_form": True,
                            "error_type": type(exc).__name__,
                            "failure_mode": "secret_adapter_construction_failed",
                        },
                    ),
                )
        secret_path = configured[len("vault://") :]
        try:
            payload = await secret_adapter.read(secret_path)
        except (KeyError, asyncio.CancelledError):
            return (
                None,
                None,
                VerifyFinding(
                    severity="refusal",
                    reason="verify_trust_root_path_unresolvable",
                    message=(
                        f"SecretAdapter has no trust-root payload at "
                        f"{secret_path!r} (resolved from --trust-root / "
                        f"Settings.signing_trust_root_path={configured!r})."
                    ),
                    payload={
                        "configured_trust_root": configured,
                        "secret_path": secret_path,
                        "uri_form": True,
                        "failure_mode": "secret_path_missing",
                    },
                ),
            )
        except Exception as exc:
            return (
                None,
                None,
                VerifyFinding(
                    severity="refusal",
                    reason="verify_trust_root_path_unresolvable",
                    message=(
                        f"SecretAdapter.read({secret_path!r}) raised {type(exc).__name__}: {exc}"
                    ),
                    payload={
                        "configured_trust_root": configured,
                        "secret_path": secret_path,
                        "error_type": type(exc).__name__,
                        "uri_form": True,
                        "failure_mode": "secret_adapter_read_error",
                    },
                ),
            )
        if not isinstance(payload, dict) or "key" not in payload:
            return (
                None,
                None,
                VerifyFinding(
                    severity="refusal",
                    reason="verify_trust_root_path_unresolvable",
                    message=(
                        f"SecretAdapter trust-root payload at {secret_path!r} "
                        "is not a dict with a 'key' field; expected "
                        "``{'key': '<pem-bytes>'}``."
                    ),
                    payload={
                        "configured_trust_root": configured,
                        "secret_path": secret_path,
                        "uri_form": True,
                        "failure_mode": "secret_payload_malformed",
                    },
                ),
            )
        key_bytes = payload["key"]
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode("utf-8")
        if not isinstance(key_bytes, bytes):
            return (
                None,
                None,
                VerifyFinding(
                    severity="refusal",
                    reason="verify_trust_root_path_unresolvable",
                    message=(
                        f"SecretAdapter trust-root payload at {secret_path!r} "
                        f"carries a 'key' field of type "
                        f"{type(key_bytes).__name__!r} (expected bytes / str)."
                    ),
                    payload={
                        "configured_trust_root": configured,
                        "secret_path": secret_path,
                        "actual_type": type(key_bytes).__name__,
                        "uri_form": True,
                        "failure_mode": "secret_payload_wrong_type",
                    },
                ),
            )
        with tempfile.NamedTemporaryFile(
            prefix="cognic_trust_root_",
            suffix=".pem",
            delete=False,
        ) as tempfile_handle:
            tempfile_handle.write(key_bytes)
        tempfile_path = Path(tempfile_handle.name)
        tempfile_path.chmod(0o600)
        return str(tempfile_path), tempfile_path, None

    # File-path branch.
    trust_path = Path(configured)
    if not trust_path.is_file():
        return (
            None,
            None,
            VerifyFinding(
                severity="refusal",
                reason="verify_trust_root_path_unresolvable",
                message=(
                    f"--trust-root / Settings.signing_trust_root_path="
                    f"{configured!r} does not resolve to a file on disk."
                ),
                payload={
                    "configured_trust_root": configured,
                    "failure_mode": "trust_root_path_missing",
                },
            ),
        )
    return str(trust_path), None, None


# ---------------------------------------------------------------------------
# Manifest read helpers
# ---------------------------------------------------------------------------


def _safe_read_pack_file_bytes(
    pack_path: Path,
    relative_path: str,
    *,
    failure_mode_missing: str,
    failure_mode_escape: str,
    failure_mode_resolve_error: str,
    failure_mode_not_regular_file: str,
) -> tuple[bytes | None, VerifyFinding | None]:
    """Resolve + containment-check a pack-relative file BEFORE reading
    its bytes. R5 P2 #2 reviewer correction: pre-fix verify read root
    metadata files (cognic-pack-manifest.toml, pyproject.toml) through
    ``is_file()`` / ``read_bytes()`` directly — a symlinked file
    pointing outside the pack tree could be parsed before the
    structured-finding refusal could fire. These files drive
    pack_id / kind / version + downstream provenance checks, so they
    MUST use the same resolve + is_relative_to + regular-file guard
    that wheels and attestations already use (R1 P2 #1, R1 P2 #2).

    Closed-enum failure modes (via payload.failure_mode):
      - ``failure_mode_missing`` — file does not exist after resolve.
      - ``failure_mode_resolve_error`` — ``Path.resolve()`` raises
        OSError / RuntimeError on a self-referential symlink chain.
      - ``failure_mode_escape`` — resolved path is outside pack root.
      - ``failure_mode_not_regular_file`` — resolved path exists but
        is not a regular file.

    Returns ``(bytes, None)`` on success or ``(None, finding)`` on
    refusal. All refusals route through the same closed-enum reason
    (``verify_attestation_path_unresolvable``) the existing root-
    metadata helpers use; the caller picks failure-mode strings
    appropriate to the file being read.
    """
    candidate = pack_path / relative_path
    try:
        pack_resolved = pack_path.resolve()
        candidate_resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: could not resolve {relative_path} at "
                f"{candidate}: {type(exc).__name__}: {exc}."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_path": str(candidate),
                "error_type": type(exc).__name__,
                "failure_mode": failure_mode_resolve_error,
            },
        )
    if not candidate_resolved.is_relative_to(pack_resolved):
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: {relative_path} at {candidate} resolves to "
                f"{candidate_resolved}, which is outside the pack root "
                f"{pack_resolved}. Refusing to read root metadata "
                "redirected outside the pack tree (defends against "
                "symlinks routing verify to attacker-controlled "
                "manifest / pyproject content)."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_path": str(candidate),
                "resolved_path": str(candidate_resolved),
                "resolved_pack": str(pack_resolved),
                "failure_mode": failure_mode_escape,
            },
        )
    if not candidate_resolved.exists():
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=f"verify: expected {relative_path} at {candidate} is missing.",
            payload={
                "pack_path": str(pack_path),
                "expected_path": str(candidate),
                "failure_mode": failure_mode_missing,
            },
        )
    if not candidate_resolved.is_file():
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: {relative_path} at {candidate} resolves to "
                f"{candidate_resolved}, which is not a regular file."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_path": str(candidate),
                "resolved_path": str(candidate_resolved),
                "failure_mode": failure_mode_not_regular_file,
            },
        )
    try:
        return candidate_resolved.read_bytes(), None
    except OSError as exc:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: could not read {relative_path} at "
                f"{candidate_resolved}: {type(exc).__name__}: {exc}."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_path": str(candidate),
                "error_type": type(exc).__name__,
                "failure_mode": failure_mode_resolve_error,
            },
        )


def _read_pack_kind_for_verify(
    pack_path: Path,
) -> tuple[str, str, VerifyFinding | None]:
    """Read ``[pack].pack_id`` + ``[pack].kind`` from the manifest.

    R2 P2 #1 reviewer correction: ``[pack].kind`` MUST be a non-empty
    string in the closed enum ``{tool, skill, agent}`` (mirrors sign-
    side ``cli.sign._read_pack_kind_for_bundle``). Pre-fix the helper
    coerced missing/non-string/blank kind to ``""`` and returned any
    other string verbatim — an attacker who flipped a signed agent
    pack's manifest from ``kind = "agent"`` to ``kind = "skill"`` (or
    ``kind = "garbage"`` / ``kind = 42``) could skip the AgentCard
    JWS arm entirely (JWS is gated on ``pack_kind == "agent"``).
    Validators do NOT reliably refuse arbitrary kind values, so the
    refusal MUST land here before any kind-gated step runs. Closed-
    enum vocabulary lives at ``cli.sign._VALID_PACK_KINDS``
    (single-sourced).

    On any IO / parse / shape / closed-enum failure, returns
    ``("", "", verify_attestation_path_unresolvable)``. The full
    validate pipeline (step 10) surfaces additional precise refusal
    reasons; this helper's job is to gate the JWS step + refuse
    obvious manifest-tampering shapes.
    """
    # R5 P2 #2 reviewer correction: use the safe resolve + containment-
    # check reader so a symlinked manifest pointing outside the pack
    # tree fails closed instead of being parsed.
    manifest_path = pack_path / "cognic-pack-manifest.toml"
    raw_bytes, safe_read_finding = _safe_read_pack_file_bytes(
        pack_path,
        "cognic-pack-manifest.toml",
        failure_mode_missing="manifest_not_found",
        failure_mode_escape="manifest_path_escapes_pack",
        failure_mode_resolve_error="manifest_path_resolve_error",
        failure_mode_not_regular_file="manifest_path_not_regular_file",
    )
    if safe_read_finding is not None:
        return "", "", safe_read_finding
    assert raw_bytes is not None
    try:
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: manifest at {manifest_path} could not be "
                    f"parsed as TOML: {type(exc).__name__}"
                ),
                payload={
                    "pack_path": str(pack_path),
                    "error_type": type(exc).__name__,
                    "failure_mode": "manifest_unparseable",
                },
            ),
        )
    pack_block = data.get("pack")
    if not isinstance(pack_block, dict):
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(f"verify: manifest at {manifest_path} missing [pack] block."),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "manifest_missing_pack_block",
                },
            ),
        )
    pack_id = pack_block.get("pack_id", "")
    pack_kind = pack_block.get("kind", "")
    if not isinstance(pack_id, str) or not pack_id.strip():
        pack_id = ""
    pack_id = pack_id.strip()
    # R2 P2 #1 reviewer correction: enforce closed-enum {tool, skill,
    # agent} membership before returning. Refuse any other shape
    # (missing / non-string / empty / whitespace / unknown literal /
    # int / list etc.) so the JWS step's gate cannot be bypassed by
    # tampering with the manifest's [pack].kind value.
    if not isinstance(pack_kind, str) or not pack_kind.strip():
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: manifest at {manifest_path} declares "
                    f"[pack].kind of type {type(pack_kind).__name__!r} "
                    "(or empty / whitespace-only). Required: a non-empty "
                    f"string in {sorted(_VALID_PACK_KINDS)}."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "actual_type": type(pack_kind).__name__,
                    "valid_kinds": sorted(_VALID_PACK_KINDS),
                    "failure_mode": "manifest_invalid_pack_kind_type",
                },
            ),
        )
    pack_kind = pack_kind.strip()
    if pack_kind not in _VALID_PACK_KINDS:
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: manifest at {manifest_path} declares "
                    f"[pack].kind={pack_kind!r}, which is not in the "
                    f"closed enum {sorted(_VALID_PACK_KINDS)}. Refusing "
                    "to verify: manifest tampering (e.g., flipping "
                    "kind=agent to kind=skill to bypass the JWS arm) "
                    "MUST fail closed."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "actual_kind": pack_kind,
                    "valid_kinds": sorted(_VALID_PACK_KINDS),
                    "failure_mode": "manifest_invalid_pack_kind_unknown",
                },
            ),
        )
    return pack_id, pack_kind, None


def _read_agent_card_jws_path_for_verify(
    pack_path: Path,
) -> tuple[Path | None, VerifyFinding | None]:
    """Dual-path lookup of ``[identity].agent_card_jws_path`` mirroring
    ``cli.sign._read_agent_card_jws_path_for_bundle``. Verify needs the
    declared path to know which JWS file to verify against.

    On any failure, returns ``verify_attestation_path_unresolvable`` —
    a manifest that doesn't declare the JWS path is functionally
    indistinguishable from a missing attestation file from verify's
    perspective.
    """
    # R5 P2 #2: use the safe reader. Caller pre-validated the manifest
    # is readable + parseable via _read_pack_kind_for_verify; we
    # nevertheless route through the safe reader to keep the symlink-
    # escape guard at every read site (defense-in-depth).
    manifest_path = pack_path / "cognic-pack-manifest.toml"
    raw_bytes, safe_read_finding = _safe_read_pack_file_bytes(
        pack_path,
        "cognic-pack-manifest.toml",
        failure_mode_missing="manifest_not_found",
        failure_mode_escape="manifest_path_escapes_pack",
        failure_mode_resolve_error="manifest_path_resolve_error",
        failure_mode_not_regular_file="manifest_path_not_regular_file",
    )
    if safe_read_finding is not None:
        return None, safe_read_finding
    assert raw_bytes is not None
    data = tomllib.loads(raw_bytes.decode("utf-8"))

    canonical_identity = data.get("identity")
    identity_block: dict[str, Any] | None = None
    legacy_identity = data.get("tool")
    if isinstance(canonical_identity, dict):
        identity_block = canonical_identity
    elif (
        isinstance(legacy_identity, dict)
        and isinstance(legacy_identity.get("cognic"), dict)
        and isinstance(legacy_identity["cognic"].get("identity"), dict)
    ):
        identity_block = legacy_identity["cognic"]["identity"]
    if identity_block is None:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: agent pack at {manifest_path} declares no "
                "[identity] block (canonical or legacy "
                "[tool.cognic.identity]); cannot determine the "
                "agent_card_jws_path."
            ),
            payload={
                "pack_path": str(pack_path),
                "failure_mode": "manifest_missing_identity_block",
            },
        )
    declared = identity_block.get("agent_card_jws_path")
    if not isinstance(declared, str) or not declared.strip():
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: agent pack at {manifest_path} missing or invalid "
                "[identity].agent_card_jws_path."
            ),
            payload={
                "pack_path": str(pack_path),
                "failure_mode": "manifest_invalid_agent_card_jws_path",
            },
        )
    candidate = pack_path / declared.strip()
    return candidate, None


# ---------------------------------------------------------------------------
# Cosign resolution + invocation
# ---------------------------------------------------------------------------


def _resolve_cosign_path_for_verify(
    settings: Settings,
) -> tuple[str | None, VerifyFinding | None]:
    """Resolve the cosign binary path. Mirrors
    ``cli.sign._resolve_cosign_path`` but maps failures into
    ``verify_cosign_signature_invalid`` (with payload.failure_mode=
    cosign_not_installed) so the verify closed-enum vocabulary stays
    contained.
    """
    configured = settings.cosign_path
    if configured is not None:
        resolved = shutil.which(configured)
        if resolved is None:
            return None, VerifyFinding(
                severity="refusal",
                reason="verify_cosign_signature_invalid",
                message=(
                    f"verify: Settings.cosign_path={configured!r} does not "
                    "resolve via shutil.which (the file is missing, not "
                    "executable, or not on PATH). Install cosign or unset "
                    "Settings.cosign_path."
                ),
                payload={
                    "configured_path": configured,
                    "failure_mode": "cosign_not_installed",
                },
            )
        return resolved, None
    fallback = shutil.which("cosign")
    if fallback is None:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_cosign_signature_invalid",
            message=(
                "verify: cosign binary not found via shutil.which on the "
                "host PATH AND Settings.cosign_path is unset. Install "
                "cosign (https://docs.sigstore.dev/cosign/installation/)."
            ),
            payload={
                "configured_path": None,
                "failure_mode": "cosign_not_installed",
            },
        )
    return fallback, None


async def _exec_cosign_verify_blob(
    cosign_bin: str,
    wheel_path: Path,
    *,
    sig_path: Path,
    bundle_path: Path,
    trust_root_path: str,
    timeout_s: float,
) -> VerifyFinding | None:
    """Run ``cosign verify-blob`` via real
    ``asyncio.create_subprocess_exec`` with an enforced timeout.
    Returns ``None`` on success (cosign exits 0), or a closed-enum
    refusal on any non-zero exit, OSError, or timeout. Per Doctrine
    F invariant: list-form argv, no shell.

    Mirrors ``protocol/trust_gate.py::verify_pack_signature`` —
    including the SIGKILL-on-timeout pattern (R2 P2 #3 reviewer
    correction). Pre-fix this helper awaited ``proc.communicate()``
    directly with no timeout: a hung cosign binary or wrapper would
    leave ``agentos verify`` stuck indefinitely instead of returning
    a closed-enum refusal. The timeout source is
    ``settings.cosign_verify_timeout_s`` (default 30s; same setting
    that gates the runtime trust gate).
    """
    # R13 P2 #2 reviewer correction: use the same minimal-env
    # discipline as the runtime trust gate (``protocol/trust_gate.py``
    # ``_SUBPROCESS_ENV``). Pre-fix verify passed ``{**os.environ,
    # ...}`` which inherited operator + CI shell secrets into the
    # cosign verify-blob subprocess. ``cosign verify-blob`` only
    # needs the public trust root + local sig + bundle paths, all
    # passed argv-explicit; no env credentials are required for
    # verification (signing-side ``cosign sign-blob`` requires
    # COSIGN_PASSWORD for some KMS providers, but verify never
    # decrypts a signing key). Mirror trust_gate's PATH+HOME-only
    # whitelist so accidentally-set CI secrets cannot leak into
    # cosign's subprocess.
    cosign_env: dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/bin",
        "HOME": "/tmp",
    }
    argv = [
        cosign_bin,
        "verify-blob",
        "--key",
        trust_root_path,
        "--signature",
        str(sig_path),
        "--bundle",
        str(bundle_path),
        str(wheel_path),
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=cosign_env,
        )
    except OSError as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_cosign_signature_invalid",
            message=(f"verify: cosign subprocess raised {type(exc).__name__}: {exc}"),
            payload={
                "tool": "cosign",
                "error_type": type(exc).__name__,
                "failure_mode": "cosign_subprocess_error",
            },
        )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except TimeoutError:
        # R2 P2 #3 reviewer correction: SIGKILL the cosign process
        # on timeout (mirrors trust_gate.py's ``proc.kill()``
        # + ``proc.wait()`` reap pattern). On POSIX, ``proc.kill``
        # sends SIGKILL; ``proc.wait`` reaps the zombie so it doesn't
        # leak past the orchestrator's exit.
        proc.kill()
        await proc.wait()
        return VerifyFinding(
            severity="refusal",
            reason="verify_cosign_signature_invalid",
            message=(
                f"verify: cosign verify-blob timed out after "
                f"{timeout_s}s for {wheel_path}; subprocess "
                "SIGKILLed + reaped."
            ),
            payload={
                "tool": "cosign",
                "wheel_path": str(wheel_path),
                "timeout_s": timeout_s,
                "failure_mode": "cosign_subprocess_timeout",
            },
        )
    rc = proc.returncode or 0
    if rc != 0:
        # Per the upstream cosign verify-blob contract: exit code IS
        # the verification signal (R3 reviewer-P1 fix in trust_gate);
        # we never parse stdout for the decision. Stderr SHA-256 +
        # length included for log correlation; raw stderr is NOT
        # surfaced in the payload (privacy + log-injection — cosign
        # stderr can carry attacker-influenced text on hostile blobs).
        return VerifyFinding(
            severity="refusal",
            reason="verify_cosign_signature_invalid",
            message=(
                f"verify: cosign verify-blob exited non-zero "
                f"(returncode={rc}) for {wheel_path}; signature does not "
                "verify against the supplied trust root."
            ),
            payload={
                "tool": "cosign",
                "wheel_path": str(wheel_path),
                "exit_code": rc,
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stderr_len": len(stderr),
                "stdout_len": len(stdout),
                "failure_mode": "cosign_exit_nonzero",
            },
        )
    return None


# ---------------------------------------------------------------------------
# Per-step probes
# ---------------------------------------------------------------------------


def _compute_file_digest_sha256(path: Path) -> str:
    """SHA-256 hex digest of ``path``'s bytes. Mirrors
    ``cli.sign._compute_file_digest_sha256`` for consistency."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _probe_attestation_file(
    path: Path,
    *,
    pack_path: Path,
    failure_mode_missing: str,
    failure_mode_empty: str,
) -> VerifyFinding | None:
    """Check ``path`` exists + is non-empty + resolves under
    ``pack_path``. Returns ``None`` on success or a closed-enum
    refusal.

    R1 P2 #2 reviewer correction: pre-fix this helper used
    ``is_file()`` / ``stat()`` which silently follow symlinks. An
    attacker who controls the pack tree (e.g., via a hostile
    archive) could redirect an attestation path at a file outside
    the pack root → cosign / JSON parsers / digest checks would
    then operate on out-of-pack content while the verify report
    advertises pack-relative paths. Mirrors sign-side
    ``_create_and_validate_output_dir`` + the wheel symlink-escape
    pattern at ``cli.sign._discover_wheel`` (R8 P2 #2 doctrine).

    Closed-enum failure modes (via payload.failure_mode):
      - ``<failure_mode_missing>`` — file does not exist (or its
        parent path is broken).
      - ``<failure_mode_empty>`` — file exists + non-empty check
        fails.
      - ``attestation_path_resolve_error`` — ``Path.resolve()``
        raises OSError / RuntimeError on a self-referential
        symlink chain.
      - ``attestation_path_escapes_pack`` — resolved path is
        outside the resolved pack root.
      - ``attestation_path_not_regular_file`` — resolved path
        exists but is not a regular file (directory / fifo / etc.
        in place of an attestation file).
    """
    try:
        pack_resolved = pack_path.resolve()
        path_resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: could not resolve attestation path "
                f"{path}: {type(exc).__name__}: {exc}. Common cause "
                "is a self-referential symlink in the pack tree."
            ),
            payload={
                "expected_path": str(path),
                "pack_path": str(pack_path),
                "error_type": type(exc).__name__,
                "failure_mode": "attestation_path_resolve_error",
            },
        )
    if not path_resolved.is_relative_to(pack_resolved):
        return VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: attestation at {path} resolves to "
                f"{path_resolved}, which is outside the pack root "
                f"{pack_resolved}. Refusing to verify an attestation "
                "redirected outside the pack tree (defends against "
                "symlinks routing verify to attacker-controlled "
                "files)."
            ),
            payload={
                "expected_path": str(path),
                "resolved_path": str(path_resolved),
                "pack_path": str(pack_path),
                "resolved_pack": str(pack_resolved),
                "failure_mode": "attestation_path_escapes_pack",
            },
        )
    if not path_resolved.exists():
        return VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=f"verify: expected attestation at {path} is missing.",
            payload={
                "expected_path": str(path),
                "resolved_path": str(path_resolved),
                "failure_mode": failure_mode_missing,
            },
        )
    if not path_resolved.is_file():
        return VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: attestation at {path} resolves to "
                f"{path_resolved}, which is not a regular file."
            ),
            payload={
                "expected_path": str(path),
                "resolved_path": str(path_resolved),
                "failure_mode": "attestation_path_not_regular_file",
            },
        )
    if path_resolved.stat().st_size == 0:
        return VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=f"verify: attestation at {path} is empty (zero bytes).",
            payload={
                "expected_path": str(path),
                "resolved_path": str(path_resolved),
                "failure_mode": failure_mode_empty,
            },
        )
    return None


def _read_pyproject_metadata_for_verify(
    pack_path: Path,
) -> tuple[str, str, VerifyFinding | None]:
    """Read ``[project].name`` + ``[project].version`` from
    ``pack_path/pyproject.toml`` for the wheel cross-check (R1 P2
    #1 reviewer correction — verify needs to refuse a stale wheel
    from a different project / version).

    Mirrors ``cli.sign._read_pack_metadata_from_pyproject`` but
    routes failures through ``verify_attestation_path_unresolvable``
    (the closed-enum reason verify reserves for "expected on-disk
    artifact missing or unreadable") with payload.failure_mode for
    sub-distinction. Returns ``("", "", finding)`` on failure.
    """
    # R5 P2 #2 reviewer correction: use the safe resolve + containment-
    # check reader so a symlinked pyproject pointing outside the pack
    # tree fails closed instead of being parsed for project metadata.
    pyproject_path = pack_path / "pyproject.toml"
    raw_bytes, safe_read_finding = _safe_read_pack_file_bytes(
        pack_path,
        "pyproject.toml",
        failure_mode_missing="pyproject_not_found",
        failure_mode_escape="pyproject_path_escapes_pack",
        failure_mode_resolve_error="pyproject_path_resolve_error",
        failure_mode_not_regular_file="pyproject_path_not_regular_file",
    )
    if safe_read_finding is not None:
        return "", "", safe_read_finding
    assert raw_bytes is not None
    try:
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(f"verify: could not parse {pyproject_path}: {type(exc).__name__}: {exc}"),
                payload={
                    "pack_path": str(pack_path),
                    "error_type": type(exc).__name__,
                    "failure_mode": "pyproject_unparseable",
                },
            ),
        )
    project_block = data.get("project")
    if not isinstance(project_block, dict):
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(f"verify: pyproject.toml at {pyproject_path} missing [project] block."),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "pyproject_missing_project_block",
                },
            ),
        )
    name = project_block.get("name")
    version = project_block.get("version")
    if not isinstance(name, str) or not name.strip():
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: pyproject.toml at {pyproject_path} declares "
                    "no [project].name (or the value is empty / not a string)."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "pyproject_missing_project_name",
                },
            ),
        )
    if not isinstance(version, str) or not version.strip():
        return (
            "",
            "",
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: pyproject.toml at {pyproject_path} declares "
                    "no [project].version (or the value is empty / not a string)."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "pyproject_missing_version",
                },
            ),
        )
    return name.strip(), version.strip(), None


def _discover_wheel_for_verify(
    pack_path: Path,
    *,
    expected_project_name: str | None = None,
    expected_version: str | None = None,
) -> tuple[Path | None, VerifyFinding | None]:
    """Discover the single wheel under ``<pack>/dist/*.whl`` + cross-
    check it against the pack's pyproject metadata (R1 P2 #1 reviewer
    correction). Failure routes through ``verify_attestation_path_unresolvable``
    (the wheel IS the signed target — its absence or mismatch means
    there's nothing valid to verify).

    Mirrors sign-side ``cli.sign._discover_wheel`` symlink-escape +
    PEP 427 wheel-name parsing + canonical name/version cross-check
    so a stale wheel from a different project / version cannot pass
    cosign/SLSA digest checks while validate runs against current
    pack metadata.

    Failure modes (closed-enum via payload.failure_mode):
      - ``wheel_not_found`` — dist/ missing or empty.
      - ``multiple_wheels_in_dist`` — ambiguity refusal.
      - ``wheel_symlink_resolve_error`` — ``Path.resolve()`` raises
        on a self-referential symlink chain.
      - ``wheel_symlink_escape`` — resolved wheel is outside the
        resolved pack root.
      - ``wheel_not_regular_file`` — wheel resolves but is not a
        regular file (e.g., a directory at the wheel name).
      - ``wheel_unparseable_filename`` — wheel filename does not
        match PEP 427 ``{name}-{version}-{python}-{abi}-{platform}.whl``.
      - ``wheel_name_mismatch`` — wheel's normalized name does not
        match the pack's pyproject ``[project].name``.
      - ``wheel_version_mismatch`` — wheel's parsed version does not
        match the pack's pyproject ``[project].version``.
    """
    dist_dir = pack_path / "dist"
    if not dist_dir.is_dir():
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(f"verify: expected wheel under {dist_dir}, but dist/ does not exist."),
            payload={
                "pack_path": str(pack_path),
                "expected_dir": str(dist_dir),
                "failure_mode": "wheel_not_found",
            },
        )
    wheels = sorted(dist_dir.glob("*.whl"))
    if not wheels:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: dist/ at {dist_dir} contains no *.whl files. "
                "Run `python -m build --wheel` (or `uv build`) first."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_dir": str(dist_dir),
                "failure_mode": "wheel_not_found",
            },
        )
    if len(wheels) > 1:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: dist/ at {dist_dir} contains "
                f"{len(wheels)} wheels: {[w.name for w in wheels]}. "
                "Refusing to guess which one was signed."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheels_found": [w.name for w in wheels],
                "failure_mode": "multiple_wheels_in_dist",
            },
        )

    wheel = wheels[0]

    # R1 P2 #1 reviewer correction: defense-in-depth against wheel
    # symlinks pointing outside the pack tree. Mirrors sign-side
    # ``_discover_wheel`` R8 P2 #2 protection.
    try:
        pack_resolved = pack_path.resolve()
        wheel_resolved = wheel.resolve()
    except (OSError, RuntimeError) as exc:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: could not resolve wheel path {wheel}: "
                f"{type(exc).__name__}: {exc}. Common cause is a "
                "self-referential symlink in dist/."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "error_type": type(exc).__name__,
                "failure_mode": "wheel_symlink_resolve_error",
            },
        )
    if not wheel_resolved.is_relative_to(pack_resolved):
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: wheel {wheel.name!r} resolves to "
                f"{wheel_resolved}, which is outside the pack root "
                f"{pack_resolved}. Refusing to verify a wheel "
                "redirected outside the pack tree."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "resolved_wheel": str(wheel_resolved),
                "resolved_pack": str(pack_resolved),
                "failure_mode": "wheel_symlink_escape",
            },
        )
    if not wheel_resolved.is_file():
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: wheel {wheel} resolves to {wheel_resolved}, which is not a regular file."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "resolved_wheel": str(wheel_resolved),
                "failure_mode": "wheel_not_regular_file",
            },
        )

    # R1 P2 #1: cross-check wheel filename against pyproject metadata.
    # Defends against the leftover-stale-wheel scenario where the
    # verifier would verify an old wheel while validators run against
    # current pack metadata. Mirrors sign-side R6 P2 #1 doctrine.
    if expected_project_name is None or expected_version is None:
        # Caller didn't supply expected metadata — happens only in
        # tests of the helper in isolation. Production callers
        # ALWAYS pass both (the orchestrator reads pyproject before
        # calling this).
        return wheel, None

    from packaging.utils import (
        InvalidWheelFilename,
        canonicalize_name,
        parse_wheel_filename,
    )
    from packaging.version import InvalidVersion, Version

    try:
        parsed_name, parsed_version, _build_tag, _tags = parse_wheel_filename(wheel.name)
    except (InvalidWheelFilename, InvalidVersion) as exc:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: wheel filename {wheel.name!r} does not match "
                f"PEP 427 shape: {type(exc).__name__}: {exc}."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "error_type": type(exc).__name__,
                "failure_mode": "wheel_unparseable_filename",
            },
        )

    expected_canonical = canonicalize_name(expected_project_name)
    parsed_canonical = canonicalize_name(parsed_name)
    if expected_canonical != parsed_canonical:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: wheel {wheel.name!r} parses as project "
                f"{parsed_canonical!r} but pyproject.toml declares "
                f"{expected_canonical!r}. Refusing to verify a wheel "
                "from a different project."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "wheel_project": parsed_canonical,
                "expected_project": expected_canonical,
                "failure_mode": "wheel_name_mismatch",
            },
        )

    try:
        expected_v = Version(expected_version)
    except InvalidVersion:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: pyproject [project].version={expected_version!r} "
                "is not a valid PEP 440 version."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_version": expected_version,
                "failure_mode": "wheel_version_mismatch",
            },
        )
    if parsed_version != expected_v:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: wheel {wheel.name!r} parses as version "
                f"{parsed_version} but pyproject.toml declares "
                f"{expected_v}. Refusing to verify a stale wheel."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "wheel_version": str(parsed_version),
                "expected_version": str(expected_v),
                "failure_mode": "wheel_version_mismatch",
            },
        )

    # R10 P2 #2 reviewer correction: mirror sign-side raw-filename-
    # version textual-equality gate. Pre-fix verify accepted
    # ``...-1.0.0-...whl`` against pyproject ``1.0`` because Version
    # equality compares ``Version("1.0") == Version("1.0.0")``. Now
    # we require the raw filename version segment to match expected
    # textually (in addition to the Version-equality check above).
    raw_filename_version = wheel.name.split("-")[1] if "-" in wheel.name else ""
    if raw_filename_version != expected_version:
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=(
                f"verify: wheel filename {wheel.name!r} carries "
                f"version segment {raw_filename_version!r} which does "
                f"not match pyproject [project].version="
                f"{expected_version!r} TEXTUALLY (even though both "
                "parse to the same PEP 440 Version). Refusing: "
                "pyproject + wheel filename + wheel METADATA MUST "
                "all use the same spelling so sign + verify operate "
                "on the same string (R10 P2 #2)."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "filename_version_text": raw_filename_version,
                "expected_version_text": expected_version,
                "failure_mode": "wheel_version_mismatch",
            },
        )

    return wheel, None


def _read_signed_wheel_dist_info_metadata(
    wheel_path: Path,
    *,
    expected_project_name: str,
    expected_version: str,
) -> tuple[
    tuple[str, str, str, tuple[tuple[str, str], ...]] | None,
    VerifyFinding | None,
]:
    """Verify-side adapter over :func:`cli._wheel_integrity.read_signed_wheel_dist_info_metadata`.

    R7 P2 #1 reviewer correction: the wheel-content integrity logic
    moved to ``cli._wheel_integrity`` so sign + verify run identical
    checks. This adapter wraps the shared :class:`WheelIntegrityFailure`
    into a :class:`VerifyFinding` with the canonical
    ``verify_attestation_path_unresolvable`` reason. Closed-enum
    ``payload.failure_mode`` values are passed through verbatim.

    R15 follow-up round 1 P2 #1 + P2 #2 reviewer correction: the
    helper now also returns every validated ``(module_path,
    object_path)`` tuple from the same selected dist-info
    entry_points.txt. The caller (step 11 — the FINAL gate of the
    trust pipeline, post R15 follow-up round 2 P2 #1 ordering fix)
    MUST use this tuple directly so the load probe operates on
    exactly the same source that the integrity helper validated, and
    probes each declared cognic entry point — never just the first
    one.
    """
    from cognic_agentos.cli._wheel_integrity import (
        read_signed_wheel_dist_info_metadata as _shared_read,
    )

    quadruple, failure = _shared_read(
        wheel_path,
        expected_project_name=expected_project_name,
        expected_version=expected_version,
    )
    if failure is not None:
        payload = {**failure.payload, "failure_mode": failure.failure_mode}
        return None, VerifyFinding(
            severity="refusal",
            reason="verify_attestation_path_unresolvable",
            message=f"verify: {failure.message}",
            payload=payload,
        )
    return quadruple, None


def _check_sbom_digest_against_slsa(
    *,
    sbom_path: Path,
    slsa_path: Path,
) -> VerifyFinding | None:
    """Recompute on-disk SBOM SHA-256 + compare against SLSA-recorded
    ``predicate.buildDefinition.externalParameters.sbom_digest_sha256``.

    Caller pre-validated both files exist + parse cleanly via the
    earlier probes; this helper assumes the JSON shape fixed by
    sign --bundle's SLSA template (cli/sign.py:_build_slsa_provenance_dict).
    """
    on_disk_digest = _compute_file_digest_sha256(sbom_path)
    try:
        slsa_data = json.loads(slsa_path.read_text())
        recorded = slsa_data["predicate"]["buildDefinition"]["externalParameters"][
            "sbom_digest_sha256"
        ]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # SLSA shape failures route through verify_provenance_invalid
        # (NOT verify_sbom_digest_mismatch) — the SBOM-digest-mismatch
        # reason is reserved for "files exist + parse cleanly + the
        # digests don't match". A SLSA file that can't be read is a
        # provenance-invalid problem, not a digest-mismatch one.
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} missing or has "
                f"unparseable sbom_digest_sha256: "
                f"{type(exc).__name__}: {exc}"
            ),
            payload={
                "slsa_path": str(slsa_path),
                "error_type": type(exc).__name__,
                "failure_mode": "slsa_missing_sbom_digest",
            },
        )
    # R1 P2 #4 reviewer correction: a non-string ``sbom_digest_sha256``
    # (e.g., ``42`` or ``["bytes"]`` if the SLSA template is mutated by
    # an attacker between sign and verify) would otherwise reach the
    # ``recorded[:16]`` slice below and raise TypeError out of the
    # orchestrator. Surface a structured ``verify_provenance_invalid``
    # finding here instead (mirrors the helper's other shape failures
    # under the same closed-enum reason).
    if not isinstance(recorded, str):
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} declares "
                f"sbom_digest_sha256 of type {type(recorded).__name__!r} "
                "(expected a hex SHA-256 string)."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "actual_type": type(recorded).__name__,
                "failure_mode": "slsa_sbom_digest_wrong_type",
            },
        )
    if recorded != on_disk_digest:
        return VerifyFinding(
            severity="refusal",
            reason="verify_sbom_digest_mismatch",
            message=(
                f"verify: SBOM SHA-256 mismatch at {sbom_path}. "
                f"SLSA-recorded={recorded[:16]!r}... on-disk={on_disk_digest[:16]!r}..."
            ),
            payload={
                "sbom_path": str(sbom_path),
                "slsa_path": str(slsa_path),
                "slsa_recorded_digest": recorded,
                "on_disk_digest": on_disk_digest,
                "failure_mode": "sbom_digest_does_not_match_slsa",
            },
        )
    return None


def _check_slsa_provenance_validity(
    *,
    slsa_path: Path,
    wheel_path: Path,
    pack_path: Path,
    expected_pack_id: str,
    expected_pack_version: str,
    expected_pack_kind: str,
) -> VerifyFinding | None:
    """Parse the SLSA provenance file + validate its critical fields:
    ``_type``, ``predicateType``, ``subject[0].name`` matches the
    discovered wheel (R3 P2 #2 reviewer correction; pack-relative
    posix normalization), ``subject[0].digest.sha256`` matches the
    on-disk wheel SHA-256, ``predicate.buildDefinition.externalParameters.pack_id``
    matches the manifest's [pack].pack_id (R2 P2 #2),
    ``predicate.buildDefinition.externalParameters.pack_version`` matches
    pyproject's [project].version (R2 P2 #2), and the SLSA invocationId
    is shaped ``agentos-sign-bundle/{pack_id}@{pack_version}`` (R2 P2 #2).
    Mirrors the in-toto Statement v1 envelope shape
    ``cli.sign._build_slsa_provenance_dict`` produces.

    R2 P2 #2 doctrine: pre-fix verify read pack_id/version but never
    compared SLSA-recorded identity fields back to the live manifest +
    pyproject. A bundle whose provenance named a different pack
    identity / version (e.g., a forged provenance file substituted in
    after sign) would pass cosign + digest checks while routing
    audit-trail evidence to the wrong identity. Verify now refuses
    any provenance whose recorded identity fields disagree with the
    pack's own manifest + pyproject.

    R3 P2 #2 doctrine: pre-fix the helper validated only
    ``subject[0].digest.sha256`` against the discovered wheel. A
    substituted SLSA file could name a different artifact while
    carrying the same digest (a sign of attestation-file forgery).
    Verify now also requires ``subject[0].name`` (after pack-relative
    posix normalization) to match the discovered wheel path; spelling
    differences (sign with relative path, verify with absolute) are
    handled by the same normalization helper used by the in-toto
    layout coverage check.
    """
    try:
        slsa_data = json.loads(slsa_path.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} could not be parsed "
                f"as JSON: {type(exc).__name__}: {exc}"
            ),
            payload={
                "slsa_path": str(slsa_path),
                "error_type": type(exc).__name__,
                "failure_mode": "slsa_unparseable",
            },
        )
    if not isinstance(slsa_data, dict):
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} parsed as "
                f"{type(slsa_data).__name__}, expected JSON object."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "actual_type": type(slsa_data).__name__,
                "failure_mode": "slsa_not_object",
            },
        )
    if slsa_data.get("_type") != _INTOTO_STATEMENT_TYPE:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} has _type="
                f"{slsa_data.get('_type')!r}, expected "
                f"{_INTOTO_STATEMENT_TYPE!r}."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "actual_type": slsa_data.get("_type"),
                "expected_type": _INTOTO_STATEMENT_TYPE,
                "failure_mode": "slsa_wrong_envelope_type",
            },
        )
    if slsa_data.get("predicateType") != _SLSA_PROVENANCE_PREDICATE_TYPE:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} has predicateType="
                f"{slsa_data.get('predicateType')!r}, expected "
                f"{_SLSA_PROVENANCE_PREDICATE_TYPE!r}."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "actual_predicate_type": slsa_data.get("predicateType"),
                "expected_predicate_type": _SLSA_PROVENANCE_PREDICATE_TYPE,
                "failure_mode": "slsa_wrong_predicate_type",
            },
        )
    subject = slsa_data.get("subject")
    if not isinstance(subject, list) or not subject:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(f"verify: SLSA file at {slsa_path} missing or empty subject array."),
            payload={
                "slsa_path": str(slsa_path),
                "failure_mode": "slsa_missing_subject",
            },
        )
    first_subject = subject[0]
    if not isinstance(first_subject, dict):
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(f"verify: SLSA file at {slsa_path} subject[0] is not a JSON object."),
            payload={
                "slsa_path": str(slsa_path),
                "failure_mode": "slsa_subject_not_object",
            },
        )
    digest = first_subject.get("digest") if isinstance(first_subject, dict) else None
    recorded_sha256 = digest.get("sha256") if isinstance(digest, dict) else None
    if not isinstance(recorded_sha256, str):
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} subject[0].digest.sha256 missing or non-string."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "failure_mode": "slsa_subject_digest_missing",
            },
        )
    on_disk_wheel_digest = _compute_file_digest_sha256(wheel_path)
    if recorded_sha256 != on_disk_wheel_digest:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA subject digest mismatch for {wheel_path}. "
                f"Recorded={recorded_sha256[:16]!r}... "
                f"on-disk={on_disk_wheel_digest[:16]!r}..."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "wheel_path": str(wheel_path),
                "slsa_recorded_digest": recorded_sha256,
                "on_disk_digest": on_disk_wheel_digest,
                "failure_mode": "slsa_subject_digest_mismatch",
            },
        )

    # R3 P2 #2 reviewer correction: subject[0].name comparison. Pack-
    # relative posix normalization on both sides handles sign-with-
    # relative / verify-with-absolute spelling differences.
    recorded_name = first_subject.get("name")
    if not isinstance(recorded_name, str):
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(f"verify: SLSA file at {slsa_path} subject[0].name missing or non-string."),
            payload={
                "slsa_path": str(slsa_path),
                "failure_mode": "slsa_subject_name_missing",
            },
        )
    try:
        pack_resolved_for_subject = pack_path.resolve()
    except (OSError, RuntimeError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: could not resolve pack path {pack_path} for "
                f"SLSA subject name comparison: {type(exc).__name__}: {exc}."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "pack_path": str(pack_path),
                "error_type": type(exc).__name__,
                "failure_mode": "slsa_subject_name_pack_path_resolve_error",
            },
        )
    normalized_recorded_name = _normalize_artifact_path(
        recorded_name, pack_resolved=pack_resolved_for_subject
    )
    normalized_wheel_name = _normalize_artifact_path(
        str(wheel_path), pack_resolved=pack_resolved_for_subject
    )
    if normalized_recorded_name != normalized_wheel_name:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA subject[0].name={recorded_name!r} "
                f"(normalized={normalized_recorded_name!r}) does not "
                f"match discovered wheel {wheel_path} "
                f"(normalized={normalized_wheel_name!r}). A substituted "
                "SLSA file naming a different artifact while carrying "
                "a matching digest would otherwise pass."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "wheel_path": str(wheel_path),
                "slsa_recorded_name": recorded_name,
                "slsa_normalized_name": normalized_recorded_name,
                "wheel_normalized_name": normalized_wheel_name,
                "failure_mode": "slsa_subject_name_mismatch",
            },
        )

    # R2 P2 #2 reviewer correction: SLSA externalParameters.pack_id +
    # pack_version + invocationId comparisons. Sign-side at T14.B
    # records all three under a stable shape; verify enforces them.
    predicate = slsa_data.get("predicate")
    build_definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    external_params = (
        build_definition.get("externalParameters") if isinstance(build_definition, dict) else None
    )
    if not isinstance(external_params, dict):
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA file at {slsa_path} missing "
                "predicate.buildDefinition.externalParameters."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "failure_mode": "slsa_missing_external_params",
            },
        )
    slsa_pack_id = external_params.get("pack_id")
    slsa_pack_version = external_params.get("pack_version")
    if slsa_pack_id != expected_pack_id:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA externalParameters.pack_id="
                f"{slsa_pack_id!r} does not match manifest "
                f"[pack].pack_id={expected_pack_id!r}. Refusing: a "
                "bundle's provenance MUST name the same pack identity "
                "as the pack's own manifest."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "slsa_pack_id": slsa_pack_id,
                "expected_pack_id": expected_pack_id,
                "failure_mode": "slsa_pack_id_mismatch",
            },
        )
    if slsa_pack_version != expected_pack_version:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA externalParameters.pack_version="
                f"{slsa_pack_version!r} does not match pyproject "
                f"[project].version={expected_pack_version!r}."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "slsa_pack_version": slsa_pack_version,
                "expected_pack_version": expected_pack_version,
                "failure_mode": "slsa_pack_version_mismatch",
            },
        )
    # R4 P2 #1 reviewer correction: pack_kind comparison. Sign-side
    # at T14.C-R4 records [pack].kind in SLSA externalParameters;
    # verify refuses any provenance whose recorded kind disagrees
    # with the live manifest. This catches the "all-JWS-signals-
    # stripped" kind-flip tamper (attacker flips kind=agent to
    # kind=skill, removes [identity].agent_card_jws_path, deletes
    # the JWS file, removes the layout's .jws entry — all 3 R3
    # signals disabled) by anchoring the original kind in the
    # signed provenance instead.
    slsa_pack_kind = external_params.get("pack_kind")
    if slsa_pack_kind != expected_pack_kind:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA externalParameters.pack_kind="
                f"{slsa_pack_kind!r} does not match manifest "
                f"[pack].kind={expected_pack_kind!r}. Refusing: a "
                "kind-flip tamper that scrubs every JWS-presence "
                "signal would otherwise pass; the signed provenance "
                "preserves the original kind."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "slsa_pack_kind": slsa_pack_kind,
                "expected_pack_kind": expected_pack_kind,
                "failure_mode": "slsa_pack_kind_mismatch",
            },
        )
    # invocationId shape pin: agentos-sign-bundle/{pack_id}@{pack_version}
    run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    metadata = run_details.get("metadata") if isinstance(run_details, dict) else None
    invocation_id = metadata.get("invocationId") if isinstance(metadata, dict) else None
    expected_invocation_id = f"agentos-sign-bundle/{expected_pack_id}@{expected_pack_version}"
    if invocation_id != expected_invocation_id:
        return VerifyFinding(
            severity="refusal",
            reason="verify_provenance_invalid",
            message=(
                f"verify: SLSA runDetails.metadata.invocationId="
                f"{invocation_id!r} does not match expected "
                f"{expected_invocation_id!r} (shape: agentos-sign-bundle/"
                "{pack_id}@{pack_version})."
            ),
            payload={
                "slsa_path": str(slsa_path),
                "slsa_invocation_id": invocation_id,
                "expected_invocation_id": expected_invocation_id,
                "failure_mode": "slsa_invocation_id_mismatch",
            },
        )
    return None


def _normalize_artifact_path(raw: str, *, pack_resolved: Path) -> str:
    """Canonicalize an artifact path string from a layout (or from
    the orchestrator's expected list) to a pack-relative form.

    R2 P3 #1 reviewer correction: pre-fix the layout-coverage
    comparison did raw string equality between sign-side
    ``str(pack_path / 'attestations' / 'sbom.cdx.json')`` and verify-
    side ``str(pack_path / ...)``. If a pack was signed with one
    spelling (e.g., ``.``) and verified with another (absolute,
    symlinked workspace), the same artifact set could fail
    verification. Normalizing to pack-relative posix form removes
    that brittleness.

    R3 P3 #1 reviewer correction: relative layout entries
    (e.g., ``attestations/sbom.cdx.json``) MUST be anchored at the
    resolved pack root before ``Path.resolve()`` runs — otherwise
    Python resolves them against the verifier's process cwd, which
    breaks the common ``cd pack && agentos sign --bundle .`` ->
    ``agentos verify /abs/pack`` flow from elsewhere. Pre-fix,
    layout entries that were already pack-relative would resolve
    against the wrong root + the coverage check would refuse them
    spuriously. Anchoring at ``pack_resolved`` first makes the
    helper cwd-independent.

    Algorithm:
      1. If ``raw`` is a relative path, anchor at ``pack_resolved``
         (R3 P3 #1).
      2. ``Path.resolve()`` to absolute canonical form (follows
         symlinks).
      3. If the resolved path is under ``pack_resolved``, return the
         pack-relative posix path (e.g., ``attestations/sbom.cdx.json``).
      4. Otherwise return the resolved path verbatim — the layout
         coverage check will then refuse it as a missing-expected
         entry (an out-of-pack artifact path is itself a security
         red flag the layout cannot legitimately reference).
      5. On ``Path.resolve()`` failure (self-referential symlink),
         return the input string unchanged so the comparison fails
         loudly via the missing-expected-artifacts check rather than
         tracebacking out.
    """
    raw_path = Path(raw)
    # R3 P3 #1: anchor relative entries at pack_resolved before
    # Python resolves them against process cwd.
    if not raw_path.is_absolute():
        raw_path = pack_resolved / raw_path
    try:
        resolved = raw_path.resolve()
    except (OSError, RuntimeError):
        return raw
    try:
        return resolved.relative_to(pack_resolved).as_posix()
    except ValueError:
        # Resolved is outside the pack root; return the canonical
        # absolute form so the coverage check treats it distinctly
        # from the expected pack-relative entries.
        return resolved.as_posix()


def _check_intoto_layout_validity(
    intoto_path: Path,
    *,
    pack_path: Path,
    expected_artifact_paths: list[str],
    expected_pack_id: str,
    expected_pack_version: str,
    expected_pack_kind: str,
) -> VerifyFinding | None:
    """Parse the in-toto layout file + validate critical fields:
    ``_type`` is the AgentOS Wave-1 layout URI; ``artifact_paths`` is
    a non-empty list; ``artifact_paths`` covers every entry in
    ``expected_artifact_paths`` (R1 P2 #3 reviewer correction);
    ``pack_id`` + ``pack_version`` match manifest + pyproject (R2 P2
    #2 reviewer correction).

    Mirrors the shape ``cli.sign._build_intoto_layout_dict`` produces.
    The expected artifact set is mode-aware (T14.B always produces
    cosign artifacts since dev-skip is forbidden in prod) + kind-aware
    (agent packs add the manifest-declared agent_card_jws_path).
    Path comparison is performed in pack-relative posix form (R2 P3
    #1) so a sign-with-relative / verify-with-absolute spelling
    difference doesn't trip the coverage check spuriously.

    R1 P2 #3 doctrine: pre-fix the helper only required a non-empty
    list — a layout that omits cosign / SBOM / vuln / license / SLSA
    paths or substitutes unrelated artifacts would pass. Verify now
    refuses any layout that fails to cover the expected set produced
    by sign --bundle's mode-aware + kind-aware logic at T14.B.

    R2 P2 #2 doctrine: pre-fix verify ignored the layout's recorded
    pack identity. A layout claiming a different pack_id or
    pack_version (e.g., a forged layout substituted in after sign)
    would pass. Verify now refuses any layout whose recorded
    identity disagrees with the live manifest + pyproject.
    """
    try:
        intoto_data = json.loads(intoto_path.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} could not be "
                f"parsed as JSON: {type(exc).__name__}: {exc}"
            ),
            payload={
                "intoto_path": str(intoto_path),
                "error_type": type(exc).__name__,
                "failure_mode": "intoto_unparseable",
            },
        )
    if not isinstance(intoto_data, dict):
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} parsed as "
                f"{type(intoto_data).__name__}, expected JSON object."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "actual_type": type(intoto_data).__name__,
                "failure_mode": "intoto_not_object",
            },
        )
    if intoto_data.get("_type") != _AGENTOS_INTOTO_LAYOUT_TYPE:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} has _type="
                f"{intoto_data.get('_type')!r}, expected "
                f"{_AGENTOS_INTOTO_LAYOUT_TYPE!r}."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "actual_type": intoto_data.get("_type"),
                "expected_type": _AGENTOS_INTOTO_LAYOUT_TYPE,
                "failure_mode": "intoto_wrong_type",
            },
        )
    artifact_paths = intoto_data.get("artifact_paths")
    if not isinstance(artifact_paths, list) or not artifact_paths:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} has missing or "
                "empty artifact_paths array."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "failure_mode": "intoto_empty_artifact_paths",
            },
        )
    # R1 P2 #3 + R2 P3 #1 reviewer corrections: every expected
    # artifact path MUST appear in the layout's declared set, with
    # pack-relative path normalization so spelling differences (sign
    # with ``.``, verify with absolute) don't fail verification of
    # otherwise-correct bundles.
    try:
        pack_resolved = pack_path.resolve()
    except (OSError, RuntimeError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: could not resolve pack path {pack_path} for "
                f"in-toto layout coverage check: {type(exc).__name__}: {exc}."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "pack_path": str(pack_path),
                "error_type": type(exc).__name__,
                "failure_mode": "intoto_pack_path_resolve_error",
            },
        )
    layout_set = {
        _normalize_artifact_path(p, pack_resolved=pack_resolved)
        for p in artifact_paths
        if isinstance(p, str)
    }
    expected_normalized = [
        _normalize_artifact_path(p, pack_resolved=pack_resolved) for p in expected_artifact_paths
    ]
    missing_expected = [p for p in expected_normalized if p not in layout_set]
    if missing_expected:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} is missing "
                f"{len(missing_expected)} expected artifact(s): "
                f"{missing_expected}. The layout declares "
                f"{len(layout_set)} path(s) but does not cover the "
                "expected mode + kind aware set (pack-relative paths)."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "expected_artifact_paths": expected_normalized,
                "layout_artifact_paths": sorted(layout_set),
                "missing_expected": missing_expected,
                "failure_mode": "intoto_missing_expected_artifacts",
            },
        )
    # R2 P2 #2 reviewer correction: in-toto layout pack_id +
    # pack_version comparisons. Sign-side at T14.B records both
    # under stable shape; verify enforces them.
    layout_pack_id = intoto_data.get("pack_id")
    layout_pack_version = intoto_data.get("pack_version")
    if layout_pack_id != expected_pack_id:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} declares "
                f"pack_id={layout_pack_id!r}, expected "
                f"{expected_pack_id!r} (from manifest [pack].pack_id)."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "layout_pack_id": layout_pack_id,
                "expected_pack_id": expected_pack_id,
                "failure_mode": "intoto_pack_id_mismatch",
            },
        )
    if layout_pack_version != expected_pack_version:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} declares "
                f"pack_version={layout_pack_version!r}, expected "
                f"{expected_pack_version!r} (from pyproject "
                "[project].version)."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "layout_pack_version": layout_pack_version,
                "expected_pack_version": expected_pack_version,
                "failure_mode": "intoto_pack_version_mismatch",
            },
        )
    # R4 P2 #1 reviewer correction: in-toto layout pack_kind must
    # match manifest [pack].kind (same kind-flip tamper defense as
    # SLSA pack_kind comparison).
    layout_pack_kind = intoto_data.get("pack_kind")
    if layout_pack_kind != expected_pack_kind:
        return VerifyFinding(
            severity="refusal",
            reason="verify_intoto_layout_invalid",
            message=(
                f"verify: in-toto layout at {intoto_path} declares "
                f"pack_kind={layout_pack_kind!r}, expected "
                f"{expected_pack_kind!r} (from manifest [pack].kind). "
                "Refusing: a kind-flip tamper that scrubs every JWS-"
                "presence signal would otherwise pass; the signed "
                "layout preserves the original kind."
            ),
            payload={
                "intoto_path": str(intoto_path),
                "layout_pack_kind": layout_pack_kind,
                "expected_pack_kind": expected_pack_kind,
                "failure_mode": "intoto_pack_kind_mismatch",
            },
        )
    return None


def _verify_agent_card_jws(
    *,
    card_path: Path,
    jws_path: Path,
    trust_root_path: str,
) -> VerifyFinding | None:
    """Cryptographically verify the detached JWS at ``jws_path``
    against the on-disk card payload at ``card_path`` using the
    trust-root public PEM at ``trust_root_path``.

    Mirrors ``protocol/trust_gate.verify_jws_blob``'s detached-payload
    verification path. Wave-1 simplification: single-signer Wave-1, no
    kid resolution against a per-tenant keyring (the Vault-keyring
    path is the runtime trust gate's; verify --trust-root is a single
    PEM).
    """
    from joserfc import jws as _jws_module
    from joserfc.errors import BadSignatureError, DecodeError, JoseError
    from joserfc.jwk import RSAKey

    try:
        jws_bytes = jws_path.read_bytes()
        card_payload = card_path.read_bytes()
        public_pem_bytes = Path(trust_root_path).read_bytes()
    except OSError as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_agent_card_jws_invalid",
            message=(
                f"verify: I/O error reading JWS / card / trust-root: {type(exc).__name__}: {exc}"
            ),
            payload={
                "card_path": str(card_path),
                "jws_path": str(jws_path),
                "error_type": type(exc).__name__,
                "failure_mode": "jws_io_error",
            },
        )
    try:
        public_key = RSAKey.import_key(public_pem_bytes)
    except (ValueError, TypeError, JoseError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_agent_card_jws_invalid",
            message=(
                f"verify: trust-root public PEM at {trust_root_path} "
                f"could not be imported as RSA key: {type(exc).__name__}: {exc}"
            ),
            payload={
                "trust_root_path": trust_root_path,
                "error_type": type(exc).__name__,
                "failure_mode": "jws_trust_root_import_error",
            },
        )
    try:
        _jws_module.deserialize_compact(
            jws_bytes,
            public_key,
            payload=card_payload,
        )
    except BadSignatureError as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_agent_card_jws_invalid",
            message=(
                f"verify: JWS cryptographic verification failed for "
                f"{jws_path}: {type(exc).__name__}"
            ),
            payload={
                "jws_path": str(jws_path),
                "card_path": str(card_path),
                "error_type": type(exc).__name__,
                "failure_mode": "jws_bad_signature",
            },
        )
    except (DecodeError, JoseError, ValueError) as exc:
        return VerifyFinding(
            severity="refusal",
            reason="verify_agent_card_jws_invalid",
            message=(
                f"verify: JWS at {jws_path} could not be parsed / "
                f"verified: {type(exc).__name__}: {exc}"
            ),
            payload={
                "jws_path": str(jws_path),
                "error_type": type(exc).__name__,
                "failure_mode": "jws_decode_error",
            },
        )
    return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


_REQUIRED_ATTESTATION_FILES: Final[tuple[tuple[str, str, str], ...]] = (
    # (relative-path-in-attestations/, missing-failure-mode, empty-failure-mode)
    ("cosign.sig", "cosign_sig_missing", "cosign_sig_empty"),
    ("bundle.sigstore", "bundle_sigstore_missing", "bundle_sigstore_empty"),
    ("sbom.cdx.json", "sbom_missing", "sbom_empty"),
    ("vuln-scan.json", "vuln_scan_missing", "vuln_scan_empty"),
    ("license-audit.json", "license_audit_missing", "license_audit_empty"),
    ("slsa-provenance.intoto.json", "slsa_missing", "slsa_empty"),
    ("intoto-layout.json", "intoto_missing", "intoto_empty"),
)


async def run_verify(
    pack_path: Path,
    settings: Settings,
    *,
    trust_root: str | None = None,
    secret_adapter: SecretAdapter | None = None,
) -> VerifyReport:
    """Build + return the :class:`VerifyReport` for the supplied
    pack tree per Doctrine Decision F + ADR-016.

    Pipeline (each per-step refusal short-circuits):
      1. Resolve trust root (file path or vault:// URI).
      2. Read manifest [pack].kind to gate the JWS arm.
      3. Probe every required attestation file exists + non-empty.
      4. Discover wheel + verify it exists.
      5. cosign verify-blob over the wheel using sig + bundle +
         trust root.
      6. SBOM digest match against SLSA-recorded digest.
      7. SLSA provenance validity (envelope type + predicate type +
         subject digest matches on-disk wheel).
      8. in-toto layout validity (_type + artifact_paths).
      9. AgentCard JWS verification (agent packs only).
     10. Manifest re-validation via the full validate pipeline; any
         refusal flows back as a VerifyFinding.

    Trust-root tempfile (when vault://-resolved) is unlinked in the
    finally block.
    """
    findings: list[VerifyFinding] = []
    artifacts_verified: list[str] = []

    # Step 1: trust-root resolution.
    trust_root_path, trust_root_tempfile, trust_root_finding = await _resolve_trust_root(
        cli_trust_root=trust_root,
        settings=settings,
        secret_adapter=secret_adapter,
    )
    if trust_root_finding is not None:
        findings.append(trust_root_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert trust_root_path is not None

    try:
        return await _run_verify_inner(
            pack_path=pack_path,
            settings=settings,
            trust_root_path=trust_root_path,
            findings=findings,
            artifacts_verified=artifacts_verified,
        )
    finally:
        if trust_root_tempfile is not None:
            trust_root_tempfile.unlink(missing_ok=True)


async def _run_verify_inner(
    *,
    pack_path: Path,
    settings: Settings,
    trust_root_path: str,
    findings: list[VerifyFinding],
    artifacts_verified: list[str],
) -> VerifyReport:
    """Inner verify body factored out so the caller can wrap the
    trust-root tempfile cleanup in a single try/finally."""
    # Step 2: manifest pack kind.
    pack_id, pack_kind, manifest_finding = _read_pack_kind_for_verify(pack_path)
    if manifest_finding is not None:
        findings.append(manifest_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    # R2 P2 #2 reviewer correction: pack_id is REQUIRED downstream for
    # SLSA + in-toto identity comparisons. Pre-fix it was read then
    # deleted; the SLSA-recorded ``externalParameters.pack_id`` and
    # in-toto ``pack_id`` could disagree with the manifest without
    # any verifier-side check. Now threaded into the provenance
    # helpers.
    if not pack_id:
        # The closed-enum kind validator above ensures kind is set,
        # but pack_id may still be missing/empty. Validators (step
        # 10) will surface the precise reason; we route this through
        # the same closed-enum reason as the kind-tampering case.
        findings.append(
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: manifest at {pack_path / 'cognic-pack-manifest.toml'} "
                    "missing or invalid [pack].pack_id; provenance "
                    "identity cross-check requires it."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "manifest_invalid_pack_id",
                },
            )
        )
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )

    attestations_dir = pack_path / "attestations"

    # R2 P2 #1 + R3 P2 #1 cross-check (kind-tampering defense):
    # multi-source check that catches an attacker flipping a signed
    # agent pack's [pack].kind to ``"skill"`` or ``"tool"`` to bypass
    # the JWS arm. Closed-enum kind validation alone (``skill`` is a
    # valid value) does not catch this. R3 P2 #1 doctrine: T14.B
    # supports manifest-declared CUSTOM JWS paths
    # (``[identity].agent_card_jws_path = "agent_cards/v2/custom.jws"``),
    # so the R2 default-path check is insufficient — an agent pack
    # using a custom path can be flipped to kind=skill, the default
    # file is absent, expected in-toto omits JWS, validators skip
    # agent-only fields. Defense triangulates THREE signals:
    #   1. Default ``<pack>/agent_cards/agent-card.jws`` exists.
    #   2. Manifest [identity] block (canonical or legacy) declares
    #      ``agent_card_jws_path`` (any custom path).
    #   3. The on-disk in-toto layout's ``artifact_paths`` includes
    #      a ``.jws`` artifact entry.
    # If pack_kind != "agent" but ANY of the three signals fires,
    # refuse with ``agent_card_jws_present_for_non_agent_pack``.
    if pack_kind != "agent":
        jws_signal_paths: list[str] = []

        # Signal 1: default JWS path.
        default_jws_candidate = pack_path / "agent_cards" / "agent-card.jws"
        if default_jws_candidate.is_file():
            jws_signal_paths.append(str(default_jws_candidate))

        # Signal 2: manifest [identity].agent_card_jws_path (dual-path
        # — canonical [identity] OR legacy [tool.cognic.identity]).
        # Read the manifest TOML via the safe resolve + containment-
        # check reader (R5 P2 #2). At this point we don't yet know
        # whether the original kind was agent; we need the raw
        # declared field if any. If the manifest is missing /
        # unreadable / outside the pack tree, the safe reader returns
        # a finding which we silently absorb (Step 3's safe probe will
        # catch the underlying issue with a structured refusal).
        manifest_data: dict[str, Any] = {}
        manifest_raw, _ignored_finding = _safe_read_pack_file_bytes(
            pack_path,
            "cognic-pack-manifest.toml",
            failure_mode_missing="manifest_not_found",
            failure_mode_escape="manifest_path_escapes_pack",
            failure_mode_resolve_error="manifest_path_resolve_error",
            failure_mode_not_regular_file="manifest_path_not_regular_file",
        )
        if manifest_raw is not None:
            try:
                parsed = tomllib.loads(manifest_raw.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError):
                parsed = {}
            if isinstance(parsed, dict):
                manifest_data = parsed
        canonical_identity = (
            manifest_data.get("identity") if isinstance(manifest_data, dict) else None
        )
        identity_block: dict[str, Any] | None = None
        legacy_identity = manifest_data.get("tool") if isinstance(manifest_data, dict) else None
        if isinstance(canonical_identity, dict):
            identity_block = canonical_identity
        elif (
            isinstance(legacy_identity, dict)
            and isinstance(legacy_identity.get("cognic"), dict)
            and isinstance(legacy_identity["cognic"].get("identity"), dict)
        ):
            identity_block = legacy_identity["cognic"]["identity"]
        if identity_block is not None:
            declared = identity_block.get("agent_card_jws_path")
            if isinstance(declared, str) and declared.strip():
                custom_jws_candidate = pack_path / declared.strip()
                if custom_jws_candidate.is_file():
                    jws_signal_paths.append(str(custom_jws_candidate))
                else:
                    # Even if the file isn't on disk, the manifest's
                    # declaration ALONE is a tampering signal — a
                    # non-agent pack should not declare an agent-card
                    # JWS path. (Pre-fix this slipped through when the
                    # custom path was missing.)
                    jws_signal_paths.append(
                        f"[identity].agent_card_jws_path={declared!r} (manifest declaration)"
                    )

        # Signal 3: in-toto layout artifact_paths includes a JWS entry.
        # R4 P2 #2 reviewer correction: resolve + containment-check the
        # layout path BEFORE reading it. Pre-fix this section called
        # ``is_file()`` / ``read_text()`` directly, so a non-agent pack
        # with ``intoto-layout.json`` symlinked outside the pack would
        # be parsed here before Step 3's ``_probe_attestation_file``
        # ran the resolve+is_relative_to guard. That would re-open the
        # out-of-pack-read issue R1 P2 #2 fixed.
        intoto_path_for_kind_check = attestations_dir / "intoto-layout.json"
        try:
            pack_resolved_for_kind = pack_path.resolve()
            intoto_resolved_for_kind = intoto_path_for_kind_check.resolve()
        except (OSError, RuntimeError):
            # Path resolution failed (e.g., self-referential symlink);
            # silently skip Signal 3 — Step 3's safe probe will catch
            # the bad path with a structured refusal.
            pack_resolved_for_kind = None
            intoto_resolved_for_kind = None
        if (
            intoto_resolved_for_kind is not None
            and pack_resolved_for_kind is not None
            and intoto_resolved_for_kind.is_relative_to(pack_resolved_for_kind)
            and intoto_resolved_for_kind.is_file()
        ):
            try:
                intoto_kind_data = json.loads(intoto_resolved_for_kind.read_text())
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                intoto_kind_data = None
            if isinstance(intoto_kind_data, dict):
                layout_paths = intoto_kind_data.get("artifact_paths")
                if isinstance(layout_paths, list):
                    for entry in layout_paths:
                        if isinstance(entry, str) and entry.endswith(".jws"):
                            jws_signal_paths.append(
                                f"intoto-layout.json:artifact_paths entry {entry!r}"
                            )
                            break

        if jws_signal_paths:
            findings.append(
                VerifyFinding(
                    severity="refusal",
                    reason="verify_attestation_path_unresolvable",
                    message=(
                        f"verify: pack manifest declares [pack].kind="
                        f"{pack_kind!r} but at least one AgentCard-JWS "
                        f"signal is present: {jws_signal_paths}. This "
                        "shape only ships from sign --bundle on agent "
                        "packs; the kind value has been tampered with "
                        "to bypass JWS verification. Refusing."
                    ),
                    payload={
                        "pack_path": str(pack_path),
                        "actual_kind": pack_kind,
                        "jws_signals": jws_signal_paths,
                        "failure_mode": "agent_card_jws_present_for_non_agent_pack",
                    },
                )
            )
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )

    # Step 3: probe every required attestation file (R1 P2 #2 — each
    # probe canonicalizes under pack_path so a symlinked attestation
    # file pointing outside the pack tree is refused before cosign /
    # JSON parsers / digest checks can read it).
    for filename, missing_mode, empty_mode in _REQUIRED_ATTESTATION_FILES:
        finding = _probe_attestation_file(
            attestations_dir / filename,
            pack_path=pack_path,
            failure_mode_missing=missing_mode,
            failure_mode_empty=empty_mode,
        )
        if finding is not None:
            findings.append(finding)
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )

    # Agent packs: ensure the JWS file is present + non-empty.
    agent_card_jws_path: Path | None = None
    agent_card_path: Path | None = None
    if pack_kind == "agent":
        agent_card_jws_path, jws_path_finding = _read_agent_card_jws_path_for_verify(pack_path)
        if jws_path_finding is not None:
            findings.append(jws_path_finding)
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )
        assert agent_card_jws_path is not None
        agent_card_path = pack_path / "agent_cards" / "agent-card.json"
        # Probe the JWS file + the card payload it covers (R1 P2 #2
        # canonicalization extends here too).
        jws_probe = _probe_attestation_file(
            agent_card_jws_path,
            pack_path=pack_path,
            failure_mode_missing="agent_card_jws_missing",
            failure_mode_empty="agent_card_jws_empty",
        )
        if jws_probe is not None:
            findings.append(jws_probe)
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )
        card_probe = _probe_attestation_file(
            agent_card_path,
            pack_path=pack_path,
            failure_mode_missing="agent_card_json_missing",
            failure_mode_empty="agent_card_json_empty",
        )
        if card_probe is not None:
            findings.append(card_probe)
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )

    # Step 3b (R1 P2 #1): read pyproject metadata for wheel cross-check.
    project_name, project_version, pyproject_finding = _read_pyproject_metadata_for_verify(
        pack_path
    )
    if pyproject_finding is not None:
        findings.append(pyproject_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )

    # Step 4: discover wheel — cross-checked against pyproject metadata
    # + canonicalized under pack_path (R1 P2 #1).
    wheel_path, wheel_finding = _discover_wheel_for_verify(
        pack_path,
        expected_project_name=project_name,
        expected_version=project_version,
    )
    if wheel_finding is not None:
        findings.append(wheel_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert wheel_path is not None

    # Step 5: cosign verify-blob.
    cosign_bin, cosign_finding = _resolve_cosign_path_for_verify(settings)
    if cosign_finding is not None:
        findings.append(cosign_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert cosign_bin is not None

    sig_path = attestations_dir / "cosign.sig"
    bundle_path = attestations_dir / "bundle.sigstore"
    cosign_verify_finding = await _exec_cosign_verify_blob(
        cosign_bin,
        wheel_path,
        sig_path=sig_path,
        bundle_path=bundle_path,
        trust_root_path=trust_root_path,
        timeout_s=settings.cosign_verify_timeout_s,
    )
    if cosign_verify_finding is not None:
        findings.append(cosign_verify_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts_verified.append(str(sig_path))
    artifacts_verified.append(str(bundle_path))

    # Step 5b (R5 P2 #1 + R6 P2 #1 + R6 P2 #2): wheel-anchored
    # name + version + kind derivation. The wheel is cosign-signed
    # (step 5 just verified it), so its content is integrity-
    # anchored. Read the matched dist-info's METADATA + entry_points
    # to derive integrity-anchored name + version + kind, then cross-
    # check against manifest + pyproject.
    #
    # R5 P2 #1: derive kind from wheel content (not mutable JSON).
    # R6 P2 #1: select dist-info matching wheel filename name+version
    #           + refuse multiple dist-info dirs (spoof-first defense).
    # R6 P2 #2: parse wheel METADATA Name + Version + cross-check
    #           against pyproject (the orchestrator additionally
    #           cross-checks against SLSA + in-toto in steps 7-8).
    wheel_metadata_quadruple, wheel_kind_finding = _read_signed_wheel_dist_info_metadata(
        wheel_path,
        expected_project_name=project_name,
        expected_version=project_version,
    )
    if wheel_kind_finding is not None:
        findings.append(wheel_kind_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert wheel_metadata_quadruple is not None
    (
        wheel_metadata_name,
        wheel_metadata_version,
        derived_pack_kind,
        validated_entry_points,
    ) = wheel_metadata_quadruple
    if derived_pack_kind != pack_kind:
        findings.append(
            VerifyFinding(
                severity="refusal",
                reason="verify_attestation_path_unresolvable",
                message=(
                    f"verify: wheel-derived pack kind={derived_pack_kind!r} "
                    f"does not match manifest [pack].kind={pack_kind!r}. "
                    "The wheel is cosign-signed; its entry-point group is "
                    "the integrity-anchored source of truth for kind. "
                    "Manifest tampering detected — refusing."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "derived_pack_kind": derived_pack_kind,
                    "manifest_pack_kind": pack_kind,
                    "failure_mode": "wheel_kind_disagrees_with_manifest",
                },
            )
        )
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    # Downstream uses ``pack_kind`` (== ``derived_pack_kind`` at this
    # point); rebind to the integrity-anchored value to make the
    # provenance comparisons self-documenting.
    pack_kind = derived_pack_kind
    # R6 P2 #2: rebind project_name + project_version to the wheel-
    # derived (cosign-signed) values so SLSA + in-toto pack_id /
    # pack_version comparisons (steps 7-8) anchor against the wheel
    # content, not the mutable wheel filename. The wheel METADATA
    # Name → manifest [pack].pack_id mapping is canonical name; if
    # the operator's pack_id is differently shaped, this assertion
    # surfaces the inconsistency through the existing SLSA pack_id
    # mismatch path. ``project_name`` was sourced from pyproject;
    # ``wheel_metadata_name`` is the canonicalized form. We keep
    # the canonicalized form for downstream comparisons since the
    # wheel METADATA + filename always agree on canonical form
    # (verified above).
    project_version = wheel_metadata_version
    del wheel_metadata_name  # canonicalized; pyproject form retained
    # in `project_name` for human-readable references in error
    # messages — the digest + identity comparisons all use the
    # canonical project_name normalization downstream.

    # Step 6: SBOM digest match.
    sbom_path = attestations_dir / "sbom.cdx.json"
    slsa_path = attestations_dir / "slsa-provenance.intoto.json"
    sbom_finding = _check_sbom_digest_against_slsa(
        sbom_path=sbom_path,
        slsa_path=slsa_path,
    )
    if sbom_finding is not None:
        findings.append(sbom_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts_verified.append(str(sbom_path))

    # Step 7: SLSA provenance shape + wheel-subject match.
    slsa_finding = _check_slsa_provenance_validity(
        slsa_path=slsa_path,
        wheel_path=wheel_path,
        pack_path=pack_path,
        expected_pack_id=pack_id,
        expected_pack_version=project_version,
        expected_pack_kind=pack_kind,
    )
    if slsa_finding is not None:
        findings.append(slsa_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts_verified.append(str(slsa_path))

    # Step 8: in-toto layout shape + expected-artifact-set check
    # (R1 P2 #3). The expected set is mode + kind aware mirroring
    # ``cli.sign._run_sign_bundle_inner``'s ``intoto_artifact_paths``
    # construction (cosign artifacts always present in prod profile;
    # agent packs add the manifest-declared JWS path).
    intoto_path = attestations_dir / "intoto-layout.json"
    expected_intoto_artifacts: list[str] = [
        str(sbom_path),
        str(attestations_dir / "vuln-scan.json"),
        str(attestations_dir / "license-audit.json"),
        str(slsa_path),
        str(sig_path),
        str(bundle_path),
    ]
    if pack_kind == "agent":
        assert agent_card_jws_path is not None
        expected_intoto_artifacts.append(str(agent_card_jws_path))
    intoto_finding = _check_intoto_layout_validity(
        intoto_path,
        pack_path=pack_path,
        expected_artifact_paths=expected_intoto_artifacts,
        expected_pack_id=pack_id,
        expected_pack_version=project_version,
        expected_pack_kind=pack_kind,
    )
    if intoto_finding is not None:
        findings.append(intoto_finding)
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts_verified.append(str(intoto_path))
    # The remaining two attestation files (vuln-scan + license-audit)
    # were probed at step 3; record them as verified at this point.
    artifacts_verified.append(str(attestations_dir / "vuln-scan.json"))
    artifacts_verified.append(str(attestations_dir / "license-audit.json"))

    # Step 9: AgentCard JWS verification (agent packs only).
    if pack_kind == "agent":
        assert agent_card_jws_path is not None
        assert agent_card_path is not None
        jws_verify_finding = _verify_agent_card_jws(
            card_path=agent_card_path,
            jws_path=agent_card_jws_path,
            trust_root_path=trust_root_path,
        )
        if jws_verify_finding is not None:
            findings.append(jws_verify_finding)
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )
        artifacts_verified.append(str(agent_card_jws_path))

    # Step 10: manifest re-validation via the full validate pipeline.
    # Per ADR-016 + the plan's §"Verification steps" #6: every refusal
    # the runtime trust gate's admission check would surface MUST
    # surface here too. Lazy import avoids a circular import at module
    # load time (cli.validate imports from cli; verify imports from
    # cli.validate but is itself imported by cli).
    from cognic_agentos.cli.validate import run_validators

    validator_findings = run_validators(pack_path)
    for vf in validator_findings:
        if vf.severity == "refusal":
            findings.append(
                VerifyFinding(
                    severity="refusal",
                    reason=vf.reason,
                    message=vf.message,
                    payload=vf.payload,
                )
            )
    if any(f.severity == "refusal" for f in findings):
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
            artifacts_verified=artifacts_verified,
        )

    # Step 11 (R15 follow-up reviewer P2 #1): isolated-subprocess
    # ``EntryPoint.load()`` probe — the FINAL gate, after every non-
    # executing trust check has passed. Pre-fix the probe ran at step
    # 5c (between cosign verify-blob and SBOM digest); a bundle whose
    # wheel signature was valid but whose SBOM / SLSA / in-toto /
    # AgentCard JWS / manifest had been tampered would still get its
    # entry-point code IMPORTED before verify refused it.
    #
    # Post-fix, the load probe runs only after:
    #   - Cosign verify-blob passed (step 5).
    #   - Wheel-anchored integrity passed (step 5b).
    #   - SBOM digest matched SLSA-recorded digest (step 6).
    #   - SLSA provenance shape + wheel-subject matched (step 7).
    #   - In-toto layout shape + expected-artifact-set matched
    #     (step 8).
    #   - AgentCard JWS verified for agent packs (step 9).
    #   - Manifest re-validated via the full validate pipeline
    #     (step 10).
    # — so the probe never executes pack code unless the bundle has
    # cleared every other gate.
    #
    # R15 P2 #1 + P2 #2: probe iterates over the entry-point tuples
    # returned by the wheel-integrity helper — exactly the source the
    # helper validated — instead of re-reading the wheel. Every
    # declared cognic entry point is probed; the first failure routes
    # to refusal.
    from cognic_agentos.cli._load_probe import probe_entry_point_loadability

    if not validated_entry_points:
        # Defense-in-depth fail-closed: ``wheel_empty_cognic_entry_point_group``
        # would have fired upstream; if execution reaches step 11 with
        # an empty entry-point tuple something is structurally wrong.
        findings.append(
            VerifyFinding(
                severity="refusal",
                reason="verify_entry_point_load_failed",
                message=(
                    "verify: wheel-integrity returned no validated entry "
                    "points yet reached step 11 — cannot establish "
                    "loadability. Refusing fail-closed."
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "failure_mode": "load_probe_no_validated_entry_points",
                },
            )
        )
        return VerifyReport(
            operation="verify",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
            artifacts_verified=artifacts_verified,
        )
    for probe_module, probe_object in validated_entry_points:
        load_probe_failure = await probe_entry_point_loadability(
            wheel_path,
            module_path=probe_module,
            object_path=probe_object,
            timeout_s=settings.load_probe_timeout_s,
        )
        if load_probe_failure is not None:
            findings.append(
                VerifyFinding(
                    severity="refusal",
                    reason="verify_entry_point_load_failed",
                    message=f"verify: {load_probe_failure.message}",
                    payload={
                        **load_probe_failure.payload,
                        "failure_mode": load_probe_failure.failure_mode,
                        "entry_point_module": probe_module,
                        "entry_point_object": probe_object,
                    },
                )
            )
            return VerifyReport(
                operation="verify",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
                artifacts_verified=artifacts_verified,
            )

    return VerifyReport(
        operation="verify",
        target_path=str(pack_path),
        overall_status="pass",
        findings=findings,
        artifacts_verified=artifacts_verified,
    )


# ---------------------------------------------------------------------------
# Format helpers — split stdout/stderr (mirrors validate at T6 + sign at T14.B)
# ---------------------------------------------------------------------------


def format_verify_report_summary(report: VerifyReport) -> str:
    """Render the verify summary for stdout (text mode)."""
    lines: list[str] = []
    label = "PASS" if report.overall_status == "pass" else "FAIL"
    lines.append(f"{report.operation}: {label} ({report.target_path})")
    for path in report.artifacts_verified:
        lines.append(f"  verified: {path}")
    return "\n".join(lines)


def format_verify_report_finding_annotations(report: VerifyReport) -> list[str]:
    """One GH-Actions ``::error`` / ``::warning`` annotation per
    refusal / warning. Mirrors validate's stderr-bound annotation
    pattern (T6) + sign's T14.B pattern."""
    lines: list[str] = []
    for f in report.findings:
        level = "error" if f.severity == "refusal" else "warning"
        lines.append(f"::{level} file={report.target_path}::{f.reason}: {f.message}")
    return lines


def format_verify_report(report: VerifyReport, *, json_output: bool) -> str:
    """JSON-mode renderer for ``--json`` output. Text mode uses the
    split helpers above so stdout / stderr routing matches sign +
    validate."""
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
                "artifacts_verified": report.artifacts_verified,
            },
            sort_keys=True,
        )
    summary = format_verify_report_summary(report)
    annotations = format_verify_report_finding_annotations(report)
    if not annotations:
        return summary
    return "\n".join([summary, *annotations])


__all__ = [
    "VerifyFinding",
    "VerifyReport",
    "format_verify_report",
    "format_verify_report_finding_annotations",
    "format_verify_report_summary",
    "run_verify",
]
