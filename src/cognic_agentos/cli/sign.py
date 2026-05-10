"""Sprint-7A T14 — `agentos sign` orchestrator (CRITICAL CONTROLS).

Doctrine Decision F + ADR-016 — full Wave-1 attestation generator.
T14 ships in three commits; this module covers T14.A (sign-blob)
and T14.B (sign --bundle), both shipped here. T14.C (offline
trust-gate verifier) ships separately as ``cli/verify.py``.

Shipped surface in this module:

  - **``agentos sign-blob <wheel-path>``** (T14.A) — narrow cosign
    sign-blob wrapper. Resolves cosign via ``shutil.which`` (or
    ``settings.cosign_path``); wires the signing key from
    ``settings.signing_key_path`` (file path OR ``vault://`` URI
    resolved via the SecretAdapter); invokes cosign via real
    ``asyncio.create_subprocess_exec``; writes ``cosign.sig`` +
    ``bundle.sigstore`` to the wheel's parent directory; verifies
    both artifacts post-exec (R1 P2 #1 doctrine).
  - **``agentos sign --bundle <pack-path>``** (T14.B) — full
    Wave-1 orchestrator producing all 7 attestation files: SBOM
    (syft) + vuln scan (grype) + license audit (pip-licenses) +
    SLSA provenance template + in-toto layout template +
    AgentCard JWS (joserfc, agent packs only) + cosign sign-blob
    over the wheel. Reads pack identity (``[pack].pack_id``,
    ``[pack].kind``, manifest-declared ``[identity].agent_card_jws_path``
    via dual-path lookup per R10 P2 #1) + project metadata
    (``[project].name``, ``[project].version`` from pyproject.toml
    per R6 P2 #1); cross-checks the wheel filename's PEP 427 name
    + version against pyproject metadata; fails closed on multiple
    wheels in dist/. Validates output directories against symlink-
    escape (R8 P2 #3 + R9 P2 #2). Records the auditable signing
    identity (vault URI when applicable, NOT the transient tempfile
    path) in SLSA + in-toto attestations (R6 P2 #3).
  - **``--dev-mode-skip-cosign``** — short-circuits cosign
    resolution + execution entirely in dev / test profiles
    (the prod settings profile rejects the flag at construction
    time per Doctrine F + ``core/config.py:1035``).

Companion T14.C surface (separate module ``cli/verify.py``):
  - **``agentos verify <pack-path>``** — offline trust-gate
    verifier mirroring the Sprint-4 runtime trust-gate
    verification path.

Per Doctrine Decision G this module is on the critical-controls
floor (95% line / 90% branch). Every T14.A/T14.B/T14.C commit
halts before commit per the explicit halt-before-commit nominee
list.

Closed-enum reasons owned by this module (full T14 set; the
shipped T14.A + T14.B paths emit all of these; T14.C's verify
reasons live in the matching ``cli/verify.py``):

  - ``sign_cosign_not_installed`` — ``shutil.which("cosign")`` returns
    None AND ``settings.cosign_path`` is unset / unresolvable.
  - ``sign_syft_not_installed`` / ``sign_grype_not_installed`` /
    ``sign_license_auditor_not_installed`` — per-tool ``shutil.which``
    refusals (sign --bundle path).
  - ``sign_signing_key_unavailable`` — ``signing_key_path`` is unset,
    points at a non-existent file, declares a vault:// URI the
    SecretAdapter can't read (per R2 P2 #2 SecretAdapter wiring),
    OR adapter construction itself raised (per R7 P2 #2 routing
    through the SignReport pipeline).
  - ``sign_subprocess_failed`` — generic catch carrying ``payload.tool``
    + ``payload.failure_mode``. Failure modes include: cosign /
    syft / grype / license_auditor exit-nonzero; OSError from any
    subprocess exec; ``cosign_sig_output_missing`` /
    ``cosign_sig_output_empty`` / ``cosign_bundle_output_missing`` /
    ``cosign_bundle_output_empty`` (R1 P2 #1 + extended to non-cosign
    tools per R2 P2 #1: ``syft_sbom_output_missing/empty`` /
    ``grype_vuln_output_missing/empty`` /
    ``license_audit_output_missing/empty``); ``wheel_not_found`` /
    ``wheel_unparseable_filename`` / ``wheel_name_mismatch`` /
    ``wheel_version_mismatch`` / ``wheel_symlink_escape`` /
    ``wheel_symlink_resolve_error`` / ``wheel_not_regular_file``
    (R5 + R6 + R8 + R9 wheel cross-check + symlink-escape doctrine);
    ``manifest_*`` failure modes for [pack] + [identity] +
    [project] reads; ``attestations_dir_*`` /
    ``agent_cards_dir_*`` (R8 P2 #3 + R9 P2 #2 output-dir
    create+resolve+escape); ``agent_card_jws_path_*`` (R8 P2 #1).
  - ``sign_agent_card_jws_signing_failed`` — joserfc exception during
    JWS production.
  - ``sign_provenance_template_render_failed`` /
    ``sign_intoto_layout_template_render_failed`` — template errors.

Production behaviour (Doctrine F):

  - ``shutil.which("<tool>")`` resolves every external binary;
    missing → closed-enum refusal naming the missing tool with a
    remediation pointer.
  - All subprocess invocations use real
    ``asyncio.create_subprocess_exec`` (no ``subprocess.run`` mocking;
    tests use the Sprint-4 cosign-shim pattern extended per-tool).
  - Signing key resolution from the settings layer: file paths
    return as-is; ``vault://`` URIs route through the bundled
    SecretAdapter (lazy construction inside the orchestrator per
    R7 P2 #2), the resolved PEM bytes are written to a tempfile
    under the orchestrator's try/finally cleanup (R2 P2 #2 +
    R3 P2 #2 type-validation + R6 P2 #2 whitespace-strip).
    SLSA / in-toto / cosign-argv-byproduct record the auditable
    identity (vault URI when applicable), NOT the transient
    tempfile path (R3 P2 #3 + R4 P2 #1 invocation-plan shape).
  - ``--dev-mode-skip-cosign`` is gated behind a flag that prints a
    security warning to stderr; the prod profile rejects the flag at
    Settings construction time (``core/config.py:1035``); the
    sign-bundle orchestrator skips cosign resolution entirely when
    the flag is set (R3 P2 #1) and the in-toto layout omits cosign
    artifacts under dev-skip (R5 P2 #1).

Public surface:

  - :func:`run_sign_blob` — pure async function, builds + returns
    the :class:`SignReport` without side effects on stdout / stderr /
    sys.exit.
  - :func:`run_sign_bundle` — pure async function, full Wave-1
    orchestrator. Same ``SignReport`` shape.
  - :func:`format_sign_report` — text-mode + JSON renderer; mirrors
    validate's split-stream pattern.

Both entry points are wired by Typer commands in
:mod:`cognic_agentos.cli`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import shutil
import tempfile
import tomllib
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from cognic_agentos.cli import ValidatorReason
from cognic_agentos.core.config import Settings

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

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
# Wire-format URI constants (per the architecture
# discipline-test exemption for spec-URI-prefixes — these are external
# standards-body identifiers, not operational endpoints).
# ---------------------------------------------------------------------------

#: in-toto Statement v1 envelope `_type` per the in-toto attestation spec.
_INTOTO_STATEMENT_TYPE: Final[str] = "https://in-toto.io/Statement/v1"

#: SLSA Provenance v1 predicate URI per the SLSA v1.0 spec.
_SLSA_PROVENANCE_PREDICATE_TYPE: Final[str] = "https://slsa.dev/provenance/v1"

#: AgentOS-internal buildType identifier embedded in the SLSA
#: provenance template (per Wave-1 simplification — Doctrine F's
#: out-of-scope notes). Fixed string, not a URL — pack admission
#: doesn't dereference this; it's an opaque label.
_AGENTOS_SIGN_BUNDLE_BUILD_TYPE: Final[str] = "agentos-sprint-7a-sign-bundle/wave-1-simplified"

#: AgentOS-internal in-toto-layout template type identifier (Wave-1
#: simplified — does NOT match the full in-toto layout v1 spec since
#: the Wave-1 simplification omits step + inspection graphs).
_AGENTOS_INTOTO_LAYOUT_TYPE: Final[str] = "in-toto-layout/v1-wave1-simplified"


#: Closed-enum frozenset of valid pack kinds. Per R4 P2 #3 doctrine:
#: ``_read_pack_kind_for_bundle`` rejects manifests whose
#: ``[pack].kind`` is missing / non-string / not in this set.
#: Mirrors the SDK + CLI scaffold types (init-tool / init-skill /
#: init-agent / init-hook + the test-harness's ``_HARNESS_SUPPORTED_KINDS``
#: subset).
#:
#: Sprint-7A2 T9 amendment: ``"hook"`` joins as the 4th first-class
#: pack kind. Hook packs ship the same attestation set as tool +
#: skill packs (no AgentCard JWS); the existing ``pack_kind ==
#: "agent"`` JWS gate handles this without branching. Wheel-integrity
#: kind-derivation (cli/_wheel_integrity.py) is the matching
#: producer-side extension; verify.py imports this same frozenset
#: so the verifier accepts hook packs identically.
_VALID_PACK_KINDS: Final[frozenset[str]] = frozenset({"tool", "skill", "agent", "hook"})


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


def _build_secret_adapter(settings: Settings) -> SecretAdapter:
    """Build a :class:`SecretAdapter` from ``settings.secret_driver``
    via the bundled adapter registry — narrow construction, not the
    full ``build_adapters`` chain.

    Module-level by design so tests can monkeypatch it to inject an
    in-memory adapter (Sprint-1C ``InMemorySecretAdapter``) without
    re-implementing the registry resolution. Per ADR-016 +
    Doctrine F: the production path resolves ``vault://`` URIs
    against this adapter; the dev / test profiles use ``memory``.

    R2 P2 #2 reviewer correction extension: ``build_adapters`` would
    try to resolve relational / vector / embedding / observability /
    object_store drivers too, which fail in the unit-test profile
    where only memory adapters are registered. The narrow lookup
    here resolves ONLY the secret driver, matching the cli/sign.py
    scope.
    """
    from cognic_agentos.db.adapters import bundled_registry, load_bundled_adapters
    from cognic_agentos.db.adapters.factory import _secret_args

    # Bundled adapters register at module import — but the import only
    # fires lazily, so kick the loader to populate the registry. The
    # portal lifespan does this at startup; the CLI does it on first
    # secret-adapter request.
    load_bundled_adapters()
    secret_cls = bundled_registry.resolve("secret", settings.secret_driver)
    instance: SecretAdapter = secret_cls(*_secret_args(settings))
    return instance


async def _resolve_signing_key_path(
    settings: Settings,
    *,
    secret_adapter: SecretAdapter | None = None,
) -> tuple[str | None, str | None, Path | None, SignFinding | None]:
    """Resolve the signing key path from ``settings.signing_key_path``.

    Returns ``(cosign_readable_path, auditable_identity,
    tempfile_to_cleanup, finding)``:
      - ``cosign_readable_path``: filesystem path cosign can read;
        ``None`` on refusal. For ``vault://`` URIs this is a tempfile
        path; for file paths it's the path itself.
      - ``auditable_identity``: the stable identifier recorded in
        SLSA / in-toto attestations + the cosign-argv byproduct
        (per R3 P2 #3 doctrine — vault:// URIs MUST be preserved as
        the auditable identity; recording the transient tempfile
        path leaks local /tmp paths + loses production identity).
        For ``vault://`` URIs this is the URI itself; for file
        paths it's the resolved file path.
      - ``tempfile_to_cleanup``: ``Path`` to a tempfile the
        orchestrator MUST unlink in its finally block when the
        resolution wrote bytes from a Vault payload to disk;
        ``None`` when no tempfile is involved.
      - ``finding``: closed-enum refusal on any failure mode;
        ``None`` on success.

    Per Doctrine F + R2 P2 #2 + R3 P2 #2 + R3 P2 #3 reviewer
    corrections: ``vault://`` URI-shaped paths resolve via the
    SecretAdapter; the resolver validates the payload's ``key``
    field is ``bytes`` (or coerces from ``str``), writes to a
    tempfile cosign can sign-blob against, and returns the URI
    separately as the auditable identity.
    """
    configured = settings.signing_key_path
    if configured is None:
        return (
            None,
            None,
            None,
            SignFinding(
                severity="refusal",
                reason="sign_signing_key_unavailable",
                message=(
                    "Settings.signing_key_path is unset. Set "
                    "COGNIC_SIGNING_KEY_PATH to a local PEM path (dev / test "
                    "profiles) or a vault:// URI (production — resolved via "
                    "the SecretAdapter at sign-time)."
                ),
                payload={"configured_path": None},
            ),
        )

    if configured.startswith("vault://"):
        # Production-path: resolve via SecretAdapter. The vault://
        # prefix maps to a Vault key path the bundled VaultAdapter
        # (or the in-memory test fixture) reads.
        # R7 P2 #2 reviewer correction: lazy construction inside the
        # orchestrator so adapter-construction failures (e.g., the
        # production VaultAdapter requires ``vault_addr`` which isn't
        # set) collapse into a structured ``sign_signing_key_unavailable``
        # finding routed through the SignReport pipeline. Pre-fix the
        # CLI constructed the adapter eagerly + exited 2 with a plain
        # stderr string even in --json mode, bypassing the JSON output
        # contract pack-author CI parsers rely on.
        if secret_adapter is None:
            try:
                secret_adapter = _build_secret_adapter(settings)
            except Exception as exc:
                return (
                    None,
                    None,
                    None,
                    SignFinding(
                        severity="refusal",
                        reason="sign_signing_key_unavailable",
                        message=(
                            f"Settings.signing_key_path={configured!r} is a "
                            f"vault:// URI but SecretAdapter construction "
                            f"failed: {type(exc).__name__}: {exc}. Common "
                            "production cause: VAULT_ADDR (or the matching "
                            "Settings field) is unset. Tests inject the "
                            "InMemorySecretAdapter via monkeypatch on "
                            "``cli.sign._build_secret_adapter``."
                        ),
                        payload={
                            "configured_path": configured,
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
                None,
                SignFinding(
                    severity="refusal",
                    reason="sign_signing_key_unavailable",
                    message=(
                        f"SecretAdapter has no secret at {secret_path!r} "
                        "(resolved from Settings.signing_key_path="
                        f"{configured!r})."
                    ),
                    payload={
                        "configured_path": configured,
                        "secret_path": secret_path,
                        "uri_form": True,
                    },
                ),
            )
        except Exception as exc:
            return (
                None,
                None,
                None,
                SignFinding(
                    severity="refusal",
                    reason="sign_signing_key_unavailable",
                    message=(
                        f"SecretAdapter.read({secret_path!r}) raised {type(exc).__name__}: {exc}"
                    ),
                    payload={
                        "configured_path": configured,
                        "secret_path": secret_path,
                        "error_type": type(exc).__name__,
                        "uri_form": True,
                    },
                ),
            )
        if not isinstance(payload, dict) or "key" not in payload:
            return (
                None,
                None,
                None,
                SignFinding(
                    severity="refusal",
                    reason="sign_signing_key_unavailable",
                    message=(
                        f"SecretAdapter payload at {secret_path!r} is not a "
                        "dict with a 'key' field; expected "
                        "``{'key': '<pem-bytes>'}``."
                    ),
                    payload={
                        "configured_path": configured,
                        "secret_path": secret_path,
                        "uri_form": True,
                    },
                ),
            )
        key_bytes = payload["key"]
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode("utf-8")
        # R3 P2 #2 reviewer correction: after str→bytes coercion, the
        # value MUST be ``bytes``. A misconfigured Vault entry that
        # stored an int / list / nested dict at the ``key`` field
        # would otherwise reach ``tempfile_handle.write(...)`` and
        # raise TypeError out of the orchestrator. Surface a
        # deterministic refusal naming the offending type instead.
        if not isinstance(key_bytes, bytes):
            return (
                None,
                None,
                None,
                SignFinding(
                    severity="refusal",
                    reason="sign_signing_key_unavailable",
                    message=(
                        f"SecretAdapter payload at {secret_path!r} carries a "
                        f"'key' field of type {type(key_bytes).__name__!r} (expected "
                        "bytes or str — the PEM-encoded private key). Re-store "
                        "the secret as a UTF-8 PEM string."
                    ),
                    payload={
                        "configured_path": configured,
                        "secret_path": secret_path,
                        "actual_type": type(key_bytes).__name__,
                        "uri_form": True,
                    },
                ),
            )
        # Write to a tempfile cosign can sign-blob against. Caller's
        # finally block unlinks the path (mode 0600 on the tempfile).
        with tempfile.NamedTemporaryFile(
            prefix="cognic_signing_key_",
            suffix=".pem",
            delete=False,
        ) as tempfile_handle:
            tempfile_handle.write(key_bytes)
        tempfile_path = Path(tempfile_handle.name)
        # Restrict perms — vault-resolved keys must NOT be world-readable.
        tempfile_path.chmod(0o600)
        # R3 P2 #3: cosign reads the tempfile path; SLSA / in-toto /
        # cosign-argv-byproduct record the stable vault URI as the
        # auditable identity.
        return str(tempfile_path), configured, tempfile_path, None

    # File-path branch.
    key_path = Path(configured)
    if not key_path.is_file():
        return (
            None,
            None,
            None,
            SignFinding(
                severity="refusal",
                reason="sign_signing_key_unavailable",
                message=(
                    f"Settings.signing_key_path={configured!r} does not resolve "
                    "to a file on disk. Verify the path; for synthetic test-only "
                    "keys, see tests/fixtures/cli_sign_target_pack/attestations/"
                    "test-signing/."
                ),
                payload={"configured_path": configured},
            ),
        )
    # File-path branch: cosign-readable + auditable identity are the
    # same (the resolved file path).
    resolved = str(key_path)
    return resolved, resolved, None, None


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


# ---------------------------------------------------------------------------
# T14.B helpers — sign --bundle full orchestrator
# ---------------------------------------------------------------------------


def _resolve_tool_path(
    *,
    tool_name: str,
    configured_value: str | None,
    closed_enum_reason: ValidatorReason,
    install_pointer: str,
) -> tuple[str | None, SignFinding | None]:
    """Generic tool-path resolver mirroring ``_resolve_cosign_path``.

    Resolution order:
      1. ``configured_value`` if set + resolves via ``shutil.which``.
      2. ``shutil.which(tool_name)`` against the host PATH.

    A configured-but-unresolvable path short-circuits to the refusal
    (no PATH fallback) — operators who set the override to a typo'd
    path get the same error as operators with no tool installed.
    """
    if configured_value is not None:
        resolved = shutil.which(configured_value)
        if resolved is None:
            return None, SignFinding(
                severity="refusal",
                reason=closed_enum_reason,
                message=(
                    f"Settings.{tool_name}_path={configured_value!r} does not "
                    "resolve via shutil.which (the file is missing, not "
                    "executable, or not on PATH). Install the tool in the "
                    f"named location, or unset Settings.{tool_name}_path to "
                    "fall back to the host's PATH."
                ),
                payload={"configured_path": configured_value, "tool": tool_name},
            )
        return resolved, None
    fallback = shutil.which(tool_name)
    if fallback is None:
        return None, SignFinding(
            severity="refusal",
            reason=closed_enum_reason,
            message=(
                f"{tool_name} binary not found via shutil.which on the host "
                f"PATH AND Settings.{tool_name}_path is unset. {install_pointer}"
            ),
            payload={"configured_path": None, "tool": tool_name},
        )
    return fallback, None


def _resolve_syft_path(settings: Settings) -> tuple[str | None, SignFinding | None]:
    return _resolve_tool_path(
        tool_name="syft",
        configured_value=settings.syft_path,
        closed_enum_reason="sign_syft_not_installed",
        install_pointer=(
            "Install syft (https://github.com/anchore/syft) or set "
            "COGNIC_SYFT_PATH to its absolute path."
        ),
    )


def _resolve_grype_path(settings: Settings) -> tuple[str | None, SignFinding | None]:
    return _resolve_tool_path(
        tool_name="grype",
        configured_value=settings.grype_path,
        closed_enum_reason="sign_grype_not_installed",
        install_pointer=(
            "Install grype (https://github.com/anchore/grype) or set "
            "COGNIC_GRYPE_PATH to its absolute path."
        ),
    )


def _resolve_license_auditor_path(
    settings: Settings,
) -> tuple[str | None, SignFinding | None]:
    return _resolve_tool_path(
        tool_name="pip-licenses",
        configured_value=settings.license_auditor_path,
        closed_enum_reason="sign_license_auditor_not_installed",
        install_pointer=(
            "Install pip-licenses (`pip install pip-licenses`) or set "
            "COGNIC_LICENSE_AUDITOR_PATH to its absolute path."
        ),
    )


def _discover_wheel(
    pack_path: Path,
    *,
    expected_project_name: str | None = None,
    expected_version: str | None = None,
) -> tuple[Path | None, SignFinding | None]:
    """Look for a single ``*.whl`` file under ``pack_path / "dist"``
    that matches the parsed pyproject.toml metadata.

    Returns ``(wheel_path, None)`` on success or ``(None, finding)``
    on any failure mode. Pack authors run ``python -m build --wheel``
    (or equivalent) BEFORE invoking ``agentos sign --bundle``.

    Failure modes (closed-enum via payload.failure_mode):
      - ``wheel_not_found`` — dist/ missing or empty.
      - ``multiple_wheels_in_dist`` (R5 P2 #3) — fail closed when more
        than one wheel is present; pack authors must clean dist/ so
        exactly one wheel remains. The helper does NOT pick a winner
        among multiple candidates; ambiguity is the operator's to
        resolve.
      - ``wheel_unparseable_filename`` (R6 P2 #1) — wheel filename
        doesn't match PEP 427's
        ``{name}-{version}-{python}-{abi}-{platform}.whl`` shape.
      - ``wheel_name_mismatch`` (R6 P2 #1) — wheel's normalized name
        doesn't match ``expected_project_name``.
      - ``wheel_version_mismatch`` (R6 P2 #1) — wheel version doesn't
        match ``expected_version`` (compared as packaging.version
        objects; e.g., ``0.1.0`` != ``2.5.0``).

    Per R6 P2 #1 + R5 P2 #3 doctrine: signing the wrong wheel while
    emitting attestations for the current pyproject metadata is a
    false-provenance failure mode pack admission can't recover from
    downstream — it has to fail at sign time.
    """
    dist_dir = pack_path / "dist"
    if not dist_dir.is_dir():
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle expected a built wheel under "
                f"{dist_dir}, but the dist/ directory does not exist. "
                "Run `python -m build --wheel` (or `uv build`) first."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_dir": str(dist_dir),
                "failure_mode": "wheel_not_found",
            },
        )
    wheels = sorted(dist_dir.glob("*.whl"))
    if not wheels:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle found {dist_dir} but no *.whl files "
                "inside. Run `python -m build --wheel` (or `uv build`) "
                "first."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_dir": str(dist_dir),
                "failure_mode": "wheel_not_found",
            },
        )
    # R5 P2 #3 reviewer correction: fail closed on multiple wheels.
    # Pre-fix the orchestrator picked the lexicographically last
    # wheel — could sign a stale or unrelated artifact while emitting
    # attestations for the current pyproject metadata. Pack authors
    # MUST clean dist/ before sign --bundle (or remove old wheels).
    if len(wheels) > 1:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle found {len(wheels)} wheels under {dist_dir}: "
                f"{[w.name for w in wheels]}. Refusing to guess which one "
                "to sign — clean dist/ (e.g., `rm dist/*.whl` then "
                "`python -m build --wheel`) so exactly one wheel is "
                "present + matches the current pyproject.toml version."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_dir": str(dist_dir),
                "wheels_found": [w.name for w in wheels],
                "failure_mode": "multiple_wheels_in_dist",
            },
        )

    wheel = wheels[0]

    # R8 P2 #2 reviewer correction: defense-in-depth against wheel
    # symlinks pointing outside the pack tree. Pre-fix the
    # orchestrator accepted any wheel-named entry under dist/
    # without checking that its target stays inside the pack;
    # cosign / grype / digest then operated on an external file
    # while the report + provenance presented the pack-local path.
    # Resolve pack_path + wheel candidate; require the resolved
    # wheel under the resolved pack root. Same defensive pattern
    # T13 R31 P2 #1 codified for entry-point loaders + T12 R29 for
    # supply_chain validators.
    try:
        pack_resolved = pack_path.resolve()
        wheel_resolved = wheel.resolve()
    except (OSError, RuntimeError) as exc:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: could not resolve wheel path "
                f"{wheel}: {type(exc).__name__}: {exc}. Common cause "
                "is a self-referential symlink in dist/."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "error_type": type(exc).__name__,
                "failure_mode": "wheel_symlink_resolve_error",
            },
        )
    if not wheel_resolved.is_relative_to(pack_resolved):
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: wheel {wheel.name!r} resolves to "
                f"{wheel_resolved!r} which is outside the pack root "
                f"{pack_resolved!r}. Refusing to sign — would let "
                "an attacker-controlled symlink in dist/ redirect "
                "cosign / grype to an external file."
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
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: wheel {wheel} resolves to {wheel_resolved} "
                "which is not a regular file."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "resolved_wheel": str(wheel_resolved),
                "failure_mode": "wheel_not_regular_file",
            },
        )

    # R6 P2 #1: cross-check the wheel filename against the parsed
    # pyproject metadata. Defends against the leftover-stale-wheel
    # scenario where the orchestrator would sign an old wheel while
    # emitting attestations for the current pyproject version.
    if expected_project_name is None or expected_version is None:
        # Caller didn't supply expected metadata — happens only in
        # tests of the helper in isolation. Production callers
        # ALWAYS pass both.
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
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: wheel filename {wheel.name!r} does not "
                f"match PEP 427 shape: {type(exc).__name__}: {exc}. "
                "Rebuild the wheel with `python -m build --wheel`."
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
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: wheel {wheel.name!r} parses as project "
                f"{parsed_canonical!r} but pyproject.toml declares "
                f"{expected_canonical!r}. Refusing to sign a wheel from a "
                "different project; clean dist/ + rebuild from this pack's "
                "pyproject.toml."
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
        # The pyproject version itself is malformed; the version-
        # reader should have caught this earlier, but defend anyway.
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: pyproject [project].version="
                f"{expected_version!r} is not a valid PEP 440 version."
            ),
            payload={
                "pack_path": str(pack_path),
                "expected_version": expected_version,
                "failure_mode": "wheel_version_mismatch",
            },
        )
    if parsed_version != expected_v:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: wheel {wheel.name!r} parses as version "
                f"{parsed_version} but pyproject.toml declares "
                f"{expected_v}. Refusing to sign a stale wheel; "
                "rebuild with `python -m build --wheel` so the wheel "
                "matches the current pyproject.toml version."
            ),
            payload={
                "pack_path": str(pack_path),
                "wheel_filename": wheel.name,
                "wheel_version": str(parsed_version),
                "expected_version": str(expected_v),
                "failure_mode": "wheel_version_mismatch",
            },
        )

    # R10 P2 #2 reviewer correction: also require the RAW wheel-
    # filename version spelling to match the expected version
    # textually. Pre-fix ``Version(expected) == Version(filename)``
    # (semantic equality) was sufficient — but the reviewer
    # reproduced sign + verify both PASS with pyproject/METADATA/
    # dist-info = ``1.0`` and wheel filename = ``...-1.0.0-...whl``.
    # That contradicts R9's pyproject/filename/METADATA textual-
    # agreement promise + leaves provenance with ``pack_version='1.0'``
    # naming an artifact whose filename says ``1.0.0``. Mirror the
    # textual-equality gate in verify's ``_discover_wheel_for_verify``.
    raw_filename_version = wheel.name.split("-")[1] if "-" in wheel.name else ""
    if raw_filename_version != expected_version:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: wheel filename {wheel.name!r} carries "
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


def _read_pack_kind_for_bundle(
    pack_path: Path,
) -> tuple[str, str, SignFinding | None]:
    """Read ``[pack].pack_id`` + ``[pack].kind`` from the pack
    manifest. Returns ``(pack_id, pack_kind, None)`` on success or
    ``("", "", finding)`` on failure. Sign --bundle uses ``pack_kind``
    to gate the AgentCard JWS step (only fires for ``kind="agent"``)."""
    manifest_path = pack_path / "cognic-pack-manifest.toml"
    if not manifest_path.is_file():
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle expected a manifest at {manifest_path} "
                    "(needed to determine pack kind for the JWS arm)."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "manifest_not_found",
                },
            ),
        )
    try:
        data = tomllib.loads(manifest_path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(f"sign --bundle could not parse {manifest_path}: {type(exc).__name__}"),
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
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=f"sign --bundle: manifest at {manifest_path} missing [pack] block.",
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "manifest_missing_pack_block",
                },
            ),
        )
    # R5 P2 #2 + R6 P2 #2 reviewer corrections: validate
    # ``[pack].pack_id`` with the same closed-enum discipline as
    # ``[pack].kind``. Pre-R5: missing / non-string pack_id silently
    # coerced to "" → SLSA externalParameters.pack_id='' (false
    # provenance). Pre-R6: whitespace-only ``pack_id = "   "`` was
    # accepted because the empty-string check didn't strip first;
    # surrounding whitespace also leaked into invocationId values.
    # Post-fix: strip + reject empty/whitespace-only; record the
    # stripped form downstream.
    if "pack_id" not in pack_block:
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: manifest at {manifest_path} is missing "
                    "[pack].pack_id. Provenance attestations cannot record "
                    "an empty pack_id; remediate by setting [pack].pack_id "
                    "in cognic-pack-manifest.toml."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "manifest_missing_pack_id",
                },
            ),
        )
    raw_pack_id = pack_block["pack_id"]
    if not isinstance(raw_pack_id, str):
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: manifest at {manifest_path} declares "
                    f"[pack].pack_id of type {type(raw_pack_id).__name__!r}; "
                    "expected a string."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "actual_type": type(raw_pack_id).__name__,
                    "failure_mode": "manifest_invalid_pack_id_type",
                },
            ),
        )
    # R6 P2 #2: strip whitespace + reject empty / whitespace-only.
    pack_id_str = raw_pack_id.strip()
    if not pack_id_str:
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: manifest at {manifest_path} declares "
                    f"[pack].pack_id={raw_pack_id!r} which is empty after "
                    "whitespace stripping. Provenance attestations cannot "
                    "record a blank pack_id."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "raw_pack_id": raw_pack_id,
                    "failure_mode": "manifest_missing_pack_id",
                },
            ),
        )

    # R4 P2 #3 reviewer correction: validate ``[pack].kind`` is
    # present, a string, and one of the closed-enum {tool, skill,
    # agent}. Pre-fix: empty / non-string / unknown kinds silently
    # returned "" + skipped JWS, so a malformed agent manifest got
    # a green sign report with NO agent_cards/agent-card.jws —
    # exactly the failure mode pack admission needs the JWS to
    # detect.
    if "kind" not in pack_block or pack_block.get("kind") in ("", None):
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: manifest at {manifest_path} is missing "
                    "[pack].kind. Expected one of {tool, skill, agent, hook}."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "manifest_missing_kind",
                },
            ),
        )
    raw_kind = pack_block["kind"]
    if not isinstance(raw_kind, str):
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: manifest at {manifest_path} declares "
                    f"[pack].kind of type {type(raw_kind).__name__!r}; "
                    "expected a string from {tool, skill, agent, hook}."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "actual_type": type(raw_kind).__name__,
                    "failure_mode": "manifest_invalid_kind_type",
                },
            ),
        )
    if raw_kind not in _VALID_PACK_KINDS:
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: manifest at {manifest_path} declares "
                    f"[pack].kind={raw_kind!r}; expected one of "
                    f"{sorted(_VALID_PACK_KINDS)}."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "kind": raw_kind,
                    "valid_kinds": sorted(_VALID_PACK_KINDS),
                    "failure_mode": "manifest_unknown_kind",
                },
            ),
        )
    return pack_id_str, raw_kind, None


def _read_agent_card_jws_path_for_bundle(
    pack_path: Path,
) -> tuple[Path | None, SignFinding | None]:
    """Read ``[identity].agent_card_jws_path`` from the pack manifest
    + validate it stays under ``pack_path`` (per R8 P2 #1 reviewer
    correction).

    Returns ``(resolved_jws_path, None)`` on success. The path is
    returned as the joined ``pack_path / declared_relative`` form
    (NOT the resolve()'d absolute form) so report/in-toto recording
    matches the pack-relative shape pack authors expect.

    Pre-fix: sign --bundle hardcoded ``agent_cards/agent-card.jws``
    everywhere — JWS output, report artifacts, in-toto layout —
    ignoring whatever the manifest declared. A pack with a custom
    ``agent_card_jws_path`` could ``sign --bundle`` clean while
    leaving the declared path empty + producing attestations
    referencing a path the pack didn't advertise.

    Failure modes (closed-enum via payload.failure_mode):
      - ``manifest_missing_identity_block`` — neither the canonical
        ``[identity]`` nor the legacy ``[tool.cognic.identity]`` is
        declared (R10 P2 #1 dual-path lookup).
      - ``manifest_invalid_identity_block_type`` (R11 P2 #1) —
        canonical ``[identity]`` key is present but the value is
        not a TOML sub-table (e.g., a scalar). Refuses without
        rescuing via the legacy path; mirrors the validator's
        shape-gate ``block_not_table`` semantic.
      - ``manifest_missing_agent_card_jws_path`` (R9 P2 #1 + R10
        P2 #1 enforced across both identity-block paths) — the
        ``agent_card_jws_path`` field is absent from the chosen
        identity block. The field is required for agent packs per
        the AGNTCY/OASF Wave-1 identity contract.
      - ``manifest_invalid_agent_card_jws_path_type`` — declared
        value is not a string (or empty / whitespace-only).
      - ``agent_card_jws_path_escapes_pack`` — declared path
        resolves outside the pack root (absolute path or
        ``..``-traversal).
      - ``agent_card_jws_path_resolve_error`` — ``Path.resolve()``
        raises OSError / RuntimeError (T12 R29 doctrine: collapse
        syscall exceptions into structured findings).
    """
    manifest_path = pack_path / "cognic-pack-manifest.toml"
    # Manifest is already known-readable + parseable here (caller ran
    # _read_pack_kind_for_bundle first); no need to re-handle the
    # IO failure modes.
    data = tomllib.loads(manifest_path.read_bytes().decode("utf-8"))

    # R10 P2 #1 reviewer correction: dual-path the identity block
    # lookup. The validator at ``cli/validators/identity.py`` reads
    # both the canonical ``[identity]`` and the legacy/docs-shaped
    # ``[tool.cognic.identity]`` per the dual-path doctrine. Pre-fix
    # the signer read only the canonical path → a docs-shaped pack
    # validated cleanly + then failed sign --bundle with
    # ``manifest_missing_identity_block``. Mirror the validator's
    # ordering: canonical first, legacy second.
    #
    # R11 P2 #1 reviewer correction: when the canonical key is
    # PRESENT but the wrong type (e.g., ``identity = "not-a-table"``),
    # refuse with a structured finding — do NOT let the legacy path
    # rescue it. The validator's shape gate (T6 R20 P2 #1) treats a
    # present-but-non-table required block as ``block_not_table`` +
    # does not look at the legacy path. The signer mirrors the same
    # semantic so a malformed canonical key isn't silently bypassed.
    canonical_identity = data.get("identity")
    if "identity" in data and not isinstance(canonical_identity, dict):
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: manifest at {manifest_path} declares "
                f"top-level [identity] but the value is of type "
                f"{type(canonical_identity).__name__!r} (expected a TOML "
                "sub-table). The validator's shape gate treats this as a "
                "non-table required block + does NOT let the legacy "
                "[tool.cognic.identity] rescue it; the signer mirrors "
                "that semantic for consistency."
            ),
            payload={
                "pack_path": str(pack_path),
                "actual_type": type(canonical_identity).__name__,
                "failure_mode": "manifest_invalid_identity_block_type",
            },
        )
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
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: agent pack at {manifest_path} declares "
                "no [identity] block (canonical or legacy "
                "[tool.cognic.identity]); cannot determine the "
                "agent_card_jws_path."
            ),
            payload={
                "pack_path": str(pack_path),
                "failure_mode": "manifest_missing_identity_block",
            },
        )
    # R9 P2 #1 reviewer correction: treat the missing field as a
    # structured refusal matching the identity validator's
    # required-field contract. Pre-fix:
    #     identity_block.get("agent_card_jws_path", "agent_cards/agent-card.jws")
    # silently substituted the default + let an agent manifest
    # without the required field sign cleanly. Required-field
    # discipline mirrors AGNTCY/OASF Wave-1 identity contract from
    # the validator at ``cli/validators/identity.py``.
    if "agent_card_jws_path" not in identity_block:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: agent pack at {manifest_path} is missing "
                "[identity].agent_card_jws_path. The field is required "
                "for agent packs (per AGNTCY/OASF Wave-1 identity "
                "contract); add the declared JWS path to the manifest."
            ),
            payload={
                "pack_path": str(pack_path),
                "failure_mode": "manifest_missing_agent_card_jws_path",
            },
        )
    declared = identity_block["agent_card_jws_path"]
    if not isinstance(declared, str) or not declared.strip():
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: agent pack at {manifest_path} declares "
                f"[identity].agent_card_jws_path of type "
                f"{type(declared).__name__!r} (or empty / non-string). "
                "Expected a pack-relative path string."
            ),
            payload={
                "pack_path": str(pack_path),
                "actual_type": type(declared).__name__,
                "failure_mode": "manifest_invalid_agent_card_jws_path_type",
            },
        )
    declared_stripped = declared.strip()
    candidate = pack_path / declared_stripped
    try:
        pack_resolved = pack_path.resolve()
        candidate_resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: could not resolve agent_card_jws_path="
                f"{declared!r} against pack root {pack_path}: "
                f"{type(exc).__name__}: {exc}. Common cause is a "
                "self-referential symlink along the declared path."
            ),
            payload={
                "pack_path": str(pack_path),
                "declared_path": declared_stripped,
                "error_type": type(exc).__name__,
                "failure_mode": "agent_card_jws_path_resolve_error",
            },
        )
    if not candidate_resolved.is_relative_to(pack_resolved):
        return None, SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: agent_card_jws_path={declared!r} "
                f"resolves to {candidate_resolved!r} which is outside "
                f"the pack root {pack_resolved!r}. Refusing to write "
                "the JWS outside the pack tree (defends against "
                "absolute paths and ``..``-traversal)."
            ),
            payload={
                "pack_path": str(pack_path),
                "declared_path": declared_stripped,
                "resolved_path": str(candidate_resolved),
                "failure_mode": "agent_card_jws_path_escapes_pack",
            },
        )
    return candidate, None


def _read_pack_metadata_from_pyproject(
    pack_path: Path,
) -> tuple[str, str, SignFinding | None]:
    """Read ``[project].name`` + ``[project].version`` from the
    pack's ``pyproject.toml`` (per R4 P2 #2 + R6 P2 #1 reviewer
    corrections — sign --bundle MUST record the real version in
    SLSA / in-toto + cross-check the wheel filename against
    ``[project].name`` so a stale wheel from a different project
    can't sneak through).

    Returns ``(project_name, version, None)`` on success or
    ``("", "", finding)`` on failure. Failure modes:
      - pyproject.toml missing → ``failure_mode=pyproject_not_found``
      - unparseable TOML → ``failure_mode=pyproject_unparseable``
      - missing [project] block → ``failure_mode=pyproject_missing_project_block``
      - missing/non-string/blank [project].version →
        ``failure_mode=pyproject_missing_version``
      - missing/non-string/blank [project].name →
        ``failure_mode=pyproject_missing_project_name``
    """
    pyproject_path = pack_path / "pyproject.toml"
    if not pyproject_path.is_file():
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: pyproject.toml not found at {pyproject_path} "
                    "(needed to record the real pack version in SLSA + in-toto "
                    "attestations). Run `python -m build` from a properly-"
                    "scaffolded pack."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "expected_path": str(pyproject_path),
                    "failure_mode": "pyproject_not_found",
                },
            ),
        )
    try:
        data = tomllib.loads(pyproject_path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle could not parse {pyproject_path}: {type(exc).__name__}: {exc}"
                ),
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
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: pyproject.toml at {pyproject_path} missing [project] block."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "pyproject_missing_project_block",
                },
            ),
        )
    name = project_block.get("name")
    if not isinstance(name, str) or not name.strip():
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: pyproject.toml at {pyproject_path} declares "
                    "no [project].name (or the value is empty / not a string). "
                    "Wheel name-match cross-check requires the project name."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "pyproject_missing_project_name",
                },
            ),
        )
    version = project_block.get("version")
    if not isinstance(version, str) or not version.strip():
        return (
            "",
            "",
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: pyproject.toml at {pyproject_path} declares "
                    "no [project].version (or the value is empty / not a "
                    "string). Provenance attestations cannot record a fake "
                    "version; remediate by setting version in pyproject.toml."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "failure_mode": "pyproject_missing_version",
                },
            ),
        )
    return name.strip(), version.strip(), None


async def _exec_tool_with_output_flag(
    tool_bin: str,
    *,
    argv: Iterable[str],
    tool_label: str,
) -> tuple[int, bytes, bytes]:
    """Run ``tool_bin`` via real ``asyncio.create_subprocess_exec``;
    inherit + overlay env (mirrors cosign env preservation).

    Each per-tool wrapper builds the exact argv the tool expects + the
    output flag/path; this generic invoker just runs the subprocess.
    """
    del tool_label  # reserved for future logging hook
    proc = await asyncio.create_subprocess_exec(
        tool_bin,
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ},
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode or 0, stdout, stderr


async def _exec_syft(
    syft_bin: str,
    pack_path: Path,
    *,
    sbom_output_path: Path,
) -> tuple[int, bytes, bytes]:
    """Run ``syft <pack-path> -o cyclonedx-json=<sbom-path>``.

    Wave-1 uses the equals-attached form which writes the CycloneDX
    JSON SBOM directly to ``sbom_output_path``."""
    return await _exec_tool_with_output_flag(
        syft_bin,
        argv=[str(pack_path), "-o", f"cyclonedx-json={sbom_output_path}"],
        tool_label="syft",
    )


async def _exec_grype(
    grype_bin: str,
    wheel_path: Path,
    *,
    vuln_output_path: Path,
) -> tuple[int, bytes, bytes]:
    """Run ``grype <wheel> -o json --file <vuln-path>``."""
    return await _exec_tool_with_output_flag(
        grype_bin,
        argv=[str(wheel_path), "-o", "json", "--file", str(vuln_output_path)],
        tool_label="grype",
    )


async def _exec_license_auditor(
    license_bin: str,
    *,
    license_output_path: Path,
) -> tuple[int, bytes, bytes]:
    """Run ``pip-licenses --with-system --format=json
    --output-file=<license-path>``.

    Wave-1 uses pip-licenses; cyclonedx-py is an alternate auditor
    pack authors can wire via Settings.license_auditor_path. The
    output-file flag form is identical between the two.
    """
    return await _exec_tool_with_output_flag(
        license_bin,
        argv=[
            "--with-system",
            "--format=json",
            f"--output-file={license_output_path}",
        ],
        tool_label="pip-licenses",
    )


def _compute_file_digest_sha256(path: Path) -> str:
    """SHA-256 hex digest of a file's contents. Used by the SLSA
    provenance template to record the SBOM digest the Sigstore
    bundle's verify path can cross-check."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_slsa_provenance_dict(
    *,
    pack_id: str,
    pack_version: str,
    pack_kind: str,
    wheel_path: Path,
    sbom_digest: str,
    signing_identity: str,
    cosign_invocation_plan: dict[str, Any],
) -> dict[str, Any]:
    """Wave-1 simplified SLSA provenance template (per ADR-016
    Wave-1 simplifications + Doctrine F's out-of-scope notes).

    Records the planned cosign invocation + the SBOM digest + the
    signing identity. The schema follows the in-toto Statement-v1
    envelope + the SLSA Provenance v1 predicate; the Wave-1 narrow
    does NOT integrate with the slsa-generator GitHub Actions OIDC
    reusable workflow yet (that lands when the upstream matures per
    ADR-016).

    R4 P2 #1 reviewer correction: the byproduct is named
    ``cosign_invocation_plan`` (not ``cosign_argv``) and structured
    as a dict with an ``executed: bool`` flag. Pre-fix: a literal
    argv list named "argv" implied executed-evidence even when the
    actual exec used a different argv (vault tempfile path) or didn't
    run at all (dev-skip). The new shape preserves the audit trail
    without false execution evidence.

    The function is module-level by design so tests can monkeypatch
    it to raise — pinning the
    ``sign_provenance_template_render_failed`` reason's emit path
    deterministically.
    """
    now = datetime.now(UTC).isoformat()
    return {
        "_type": _INTOTO_STATEMENT_TYPE,
        "predicateType": _SLSA_PROVENANCE_PREDICATE_TYPE,
        "subject": [
            {
                "name": str(wheel_path),
                "digest": {"sha256": _compute_file_digest_sha256(wheel_path)},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": _AGENTOS_SIGN_BUNDLE_BUILD_TYPE,
                "externalParameters": {
                    "pack_id": pack_id,
                    "pack_version": pack_version,
                    # T14.C R4 P2 #1: bind manifest [pack].kind into
                    # SLSA provenance so verify can refuse a kind-flip
                    # tamper that scrubs every JWS-presence signal
                    # (default file, manifest declaration, layout
                    # entry). Without this, an attacker who flips
                    # an agent pack to ``skill`` and removes all JWS
                    # traces would re-derive the expected attestation
                    # set from the tampered kind + pass verify.
                    "pack_kind": pack_kind,
                    "sbom_digest_sha256": sbom_digest,
                    "wave_1_simplification": True,
                },
            },
            "runDetails": {
                "builder": {"id": signing_identity},
                "metadata": {
                    "invocationId": f"agentos-sign-bundle/{pack_id}@{pack_version}",
                    "startedOn": now,
                    "finishedOn": now,
                },
                "byproducts": [
                    {
                        "name": "cosign_invocation_plan",
                        "value": cosign_invocation_plan,
                    }
                ],
            },
        },
    }


def _build_intoto_layout_dict(
    *,
    pack_id: str,
    pack_version: str,
    pack_kind: str,
    signing_identity: str,
    artifact_paths: list[str],
) -> dict[str, Any]:
    """Wave-1 simplified in-toto layout template.

    Lists the artifact set + the signing identity. The full in-toto
    layout v1 spec (with steps + inspections + key thresholds) is
    out-of-scope for Wave-1 per Doctrine F; this template captures
    enough metadata for the runtime trust gate's manifest-shape
    check at admission time.
    """
    now = datetime.now(UTC).isoformat()
    return {
        "_type": _AGENTOS_INTOTO_LAYOUT_TYPE,
        "pack_id": pack_id,
        "pack_version": pack_version,
        # T14.C R4 P2 #1: bind manifest [pack].kind into in-toto
        # layout — same kind-flip tamper defense as SLSA.
        "pack_kind": pack_kind,
        "signing_identity": signing_identity,
        "artifact_paths": artifact_paths,
        "rendered_at": now,
        "wave_1_simplification": True,
        "out_of_scope": [
            "step-graph",
            "inspection-graph",
            "key-thresholds",
            "expiration-date",
        ],
    }


def _render_slsa_provenance_to_disk(
    output_path: Path,
    **kwargs: Any,
) -> SignFinding | None:
    """Render the SLSA provenance dict + write to ``output_path``.
    Wraps any exception during build/write into the closed-enum
    refusal ``sign_provenance_template_render_failed``."""
    try:
        payload = _build_slsa_provenance_dict(**kwargs)
        output_path.write_text(json.dumps(payload, sort_keys=True, indent=2))
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        return SignFinding(
            severity="refusal",
            reason="sign_provenance_template_render_failed",
            message=(
                f"SLSA provenance template render failed for "
                f"{output_path}: {type(exc).__name__}: {exc}"
            ),
            payload={
                "output_path": str(output_path),
                "error_type": type(exc).__name__,
            },
        )
    return None


def _render_intoto_layout_to_disk(
    output_path: Path,
    **kwargs: Any,
) -> SignFinding | None:
    """Render the in-toto layout dict + write to ``output_path``.
    Wraps any exception into ``sign_intoto_layout_template_render_failed``."""
    try:
        payload = _build_intoto_layout_dict(**kwargs)
        output_path.write_text(json.dumps(payload, sort_keys=True, indent=2))
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        return SignFinding(
            severity="refusal",
            reason="sign_intoto_layout_template_render_failed",
            message=(
                f"in-toto layout template render failed for "
                f"{output_path}: {type(exc).__name__}: {exc}"
            ),
            payload={
                "output_path": str(output_path),
                "error_type": type(exc).__name__,
            },
        )
    return None


def _sign_agent_card_jws_bytes(
    card_payload: bytes,
    *,
    private_pem_bytes: bytes,
) -> bytes:
    """Produce a detached compact JWS over ``card_payload`` using the
    RSA private key in ``private_pem_bytes``. Mirrors the Sprint-6
    fixture-pack JWS production pattern + the runtime trust gate's
    ``verify_jws_blob`` detached-payload contract.

    Module-level by design so tests can monkeypatch it to raise —
    pins the ``sign_agent_card_jws_signing_failed`` emit path.
    """
    from joserfc import jws as _jws_module
    from joserfc.jwk import RSAKey

    key = RSAKey.import_key(private_pem_bytes)
    # Detached compact form: header + signature, payload omitted from
    # the wire form (verifier supplies the original payload at verify
    # time). joserfc's `serialize_compact` returns the standard
    # 3-segment form; we strip the middle segment to match Sprint-6's
    # detached-payload contract.
    # joserfc.jws.serialize_compact takes positional args:
    # (protected_header, payload, key). Returns the standard
    # 3-segment compact form.
    standard = _jws_module.serialize_compact(
        {"alg": "RS256"},
        card_payload,
        key,
    )
    parts = standard.split(".")
    if len(parts) != 3:
        raise RuntimeError(f"unexpected JWS shape from joserfc: {len(parts)} segments")
    detached = f"{parts[0]}..{parts[2]}"
    return detached.encode("ascii")


def _sign_agent_card_jws_to_disk(
    pack_path: Path,
    *,
    signing_key_path: str,
    jws_output_path: Path,
) -> SignFinding | None:
    """Sign the AgentCard JSON at ``pack_path/agent_cards/agent-card.json``
    using the RSA private key at ``signing_key_path``; write the
    detached compact JWS to ``jws_output_path`` (per R8 P2 #1 the
    output path comes from the manifest's
    ``[identity].agent_card_jws_path`` field, not a hardcoded
    default).

    The JWS output's parent directory is created if absent (handles
    the manifest-declared-subdirectory case, e.g.,
    ``agent_cards/v2/custom-card.jws``). The parent + the output
    path are NOT re-validated for symlink-escape — the caller
    pre-validates via ``_read_agent_card_jws_path_for_bundle``.

    Wraps any exception into ``sign_agent_card_jws_signing_failed``.
    """
    card_path = pack_path / "agent_cards" / "agent-card.json"
    try:
        card_payload = card_path.read_bytes()
        private_pem = Path(signing_key_path).read_bytes()
        jws_bytes = _sign_agent_card_jws_bytes(
            card_payload,
            private_pem_bytes=private_pem,
        )
        # Ensure the output directory exists (manifest-declared
        # subdirectories like ``agent_cards/v2/...`` may not exist
        # in a fresh pack).
        jws_output_path.parent.mkdir(parents=True, exist_ok=True)
        jws_output_path.write_bytes(jws_bytes)
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return SignFinding(
            severity="refusal",
            reason="sign_agent_card_jws_signing_failed",
            message=(f"AgentCard JWS signing failed for {card_path}: {type(exc).__name__}: {exc}"),
            payload={
                "card_path": str(card_path),
                "jws_output_path": str(jws_output_path),
                "error_type": type(exc).__name__,
            },
        )
    return None


def _exec_subprocess_failed_finding(
    *,
    tool: str,
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    target: str,
) -> SignFinding:
    """Build a ``sign_subprocess_failed`` finding for a tool that
    exited non-zero. Mirrors the cosign exit-nonzero path; payload
    carries which tool + exit code + truncated streams."""
    return SignFinding(
        severity="refusal",
        reason="sign_subprocess_failed",
        message=(
            f"{tool} exited {returncode}; stderr={stderr.decode('utf-8', errors='replace')!r}"
        ),
        payload={
            "tool": tool,
            "target": target,
            "exit_code": returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "failure_mode": f"{tool}_exit_nonzero",
        },
    )


def _verify_tool_output_artifact(
    output_path: Path,
    *,
    tool: str,
    failure_mode_missing: str,
    failure_mode_empty: str,
) -> SignFinding | None:
    """Generic post-exec artifact check (R2 P2 #1 doctrine extended
    to non-cosign tools). After ``<tool>`` exits 0, the orchestrator
    MUST verify the expected output file exists + is non-empty
    BEFORE recording it as an artifact / consuming it as input to a
    downstream step (e.g., the SLSA template reads
    ``_compute_file_digest_sha256(sbom_path)`` which would crash on
    a missing file).

    Returns ``None`` when the artifact is valid; a ``SignFinding``
    with ``payload.failure_mode`` distinguishing missing vs empty
    when invalid.
    """
    if not output_path.is_file():
        return SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"{tool} exited 0 but {output_path} was not produced. "
                "The tool succeeded according to its exit code but "
                "failed to write the expected output artifact; the "
                "downstream pipeline cannot proceed."
            ),
            payload={
                "tool": tool,
                "expected_artifact": str(output_path),
                "failure_mode": failure_mode_missing,
            },
        )
    if output_path.stat().st_size == 0:
        return SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"{tool} exited 0 but {output_path} is empty (zero "
                "bytes). An empty attestation is not a valid output; "
                "pack admission would refuse the bundle."
            ),
            payload={
                "tool": tool,
                "expected_artifact": str(output_path),
                "failure_mode": failure_mode_empty,
            },
        )
    return None


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
    secret_adapter: SecretAdapter | None = None,
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

    # Resolve signing key (file path or vault:// URI). Tempfile
    # cleanup tracked + unlinked in the finally block at function
    # exit per R2 P2 #2 doctrine.
    key_tempfile: Path | None = None
    key_path, _signing_identity, key_tempfile, key_finding = await _resolve_signing_key_path(
        settings,
        secret_adapter=secret_adapter,
    )
    if key_finding is not None:
        findings.append(key_finding)
        return SignReport(
            operation="sign-blob",
            target_path=str(wheel_path),
            overall_status="fail",
            findings=findings,
        )
    assert key_path is not None

    try:
        return await _run_sign_blob_inner(
            wheel_path=wheel_path,
            cosign_bin=cosign_bin,
            key_path=key_path,
            findings=findings,
        )
    finally:
        if key_tempfile is not None:
            key_tempfile.unlink(missing_ok=True)


async def _run_sign_blob_inner(
    *,
    wheel_path: Path,
    cosign_bin: str,
    key_path: str,
    findings: list[SignFinding],
) -> SignReport:
    """Inner sign-blob body factored out so the caller can wrap the
    signing key tempfile cleanup in a single try/finally."""
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
# Public API: run_sign_bundle (T14.B full Wave-1 orchestrator)
# ---------------------------------------------------------------------------


async def run_sign_bundle(
    pack_path: Path,
    settings: Settings,
    *,
    dev_mode_skip_cosign: bool = False,
    secret_adapter: SecretAdapter | None = None,
) -> SignReport:
    """Build + return the :class:`SignReport` for the full Wave-1
    attestation set per Doctrine Decision F + ADR-016.

    Pipeline (ALL via real ``asyncio.create_subprocess_exec`` for
    binaries; module-level helpers for templates + JWS so tests can
    monkeypatch each step deterministically):

      1. Resolve all 4 binaries (cosign / syft / grype / license-
         auditor) up-front. If ANY missing → return refusals (one
         per missing tool) without executing any work; lets pack
         authors fix all install gaps in a single iteration.
      2. Resolve signing key (file path or vault:// URI via
         SecretAdapter per R2 P2 #2 doctrine).
      3. Read manifest [pack].kind to gate the AgentCard JWS step.
      4. Discover the wheel under ``<pack>/dist/*.whl``; missing →
         ``sign_subprocess_failed`` with payload ``failure_mode=
         wheel_not_found``.
      5. Run syft → ``attestations/sbom.cdx.json``.
      6. Run grype → ``attestations/vuln-scan.json``.
      7. Run license-auditor → ``attestations/license-audit.json``.
      8. Render SLSA provenance template → ``attestations/
         slsa-provenance.intoto.json`` (closed-enum reason
         ``sign_provenance_template_render_failed`` on failure).
      9. Render in-toto layout template → ``attestations/
         intoto-layout.json`` (closed-enum reason
         ``sign_intoto_layout_template_render_failed``).
      10. (agent packs only) Sign AgentCard JWS via joserfc →
          ``agent_cards/agent-card.jws``. Detached compact form;
          regenerated JWS verifies against the committed public PEM
          deterministically. Closed-enum reason
          ``sign_agent_card_jws_signing_failed``.
      11. Run cosign sign-blob over the wheel →
          ``attestations/cosign.sig`` + ``attestations/bundle.sigstore``.
      12. Verify post-exec artifacts (R1 P2 #1 doctrine extended to
          the bundle path) — every produced attestation MUST exist
          + be non-empty before the report blesses the run as
          ``pass``.

    Each per-step refusal short-circuits the pipeline + returns a
    failing report; pack authors iterate one issue at a time on
    missing binaries / failed subprocess / template errors / JWS
    failures.
    """
    findings: list[SignFinding] = []

    # Step 1: resolve all 4 tool binaries up-front; accumulate
    # missing-tool refusals.
    #
    # R3 P2 #1 reviewer correction: ``--dev-mode-skip-cosign`` MUST
    # short-circuit cosign resolution entirely. If the operator
    # intends to skip cosign, the missing-cosign refusal at this
    # step would block the whole bundle (the original ignored-flag
    # bug was partial — Settings mutation worked but cosign
    # resolution still ran). Skipping resolution here is safe
    # because step 11 also checks the flag + never invokes cosign.
    cosign_bin: str | None = None
    if not dev_mode_skip_cosign:
        cosign_bin, cosign_finding = _resolve_cosign_path(settings)
        if cosign_finding is not None:
            findings.append(cosign_finding)
    syft_bin, syft_finding = _resolve_syft_path(settings)
    if syft_finding is not None:
        findings.append(syft_finding)
    grype_bin, grype_finding = _resolve_grype_path(settings)
    if grype_finding is not None:
        findings.append(grype_finding)
    license_bin, license_finding = _resolve_license_auditor_path(settings)
    if license_finding is not None:
        findings.append(license_finding)
    if findings:
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert syft_bin is not None
    assert grype_bin is not None
    assert license_bin is not None
    # cosign_bin is None iff dev_mode_skip_cosign — step 11 guards on
    # the flag before reading it.

    # Step 2: signing key (file or vault:// URI per R2 P2 #2 + R3 P2
    # #3 — separate cosign-readable path from auditable identity).
    # Tempfile (when vault://-resolved) is unlinked in the finally
    # block at the end of the orchestrator.
    (
        key_path,
        signing_identity,
        key_tempfile,
        key_finding,
    ) = await _resolve_signing_key_path(
        settings,
        secret_adapter=secret_adapter,
    )
    if key_finding is not None:
        findings.append(key_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert key_path is not None
    assert signing_identity is not None

    try:
        return await _run_sign_bundle_inner(
            pack_path=pack_path,
            cosign_bin=cosign_bin,
            syft_bin=syft_bin,
            grype_bin=grype_bin,
            license_bin=license_bin,
            key_path=key_path,
            signing_identity=signing_identity,
            findings=findings,
            dev_mode_skip_cosign=dev_mode_skip_cosign,
        )
    finally:
        if key_tempfile is not None:
            key_tempfile.unlink(missing_ok=True)


def _create_and_validate_output_dir(
    directory: Path,
    *,
    pack_path: Path,
    directory_label: str,
    create_error_failure_mode: str,
    escape_failure_mode: str,
    resolve_error_failure_mode: str,
) -> SignFinding | None:
    """Create + resolve + validate ``directory`` stays under the
    resolved ``pack_path`` (per R8 P2 #3 + R9 P2 #2 reviewer
    corrections). Returns None on success or a structured
    ``sign_subprocess_failed`` finding when:
      - ``mkdir(exist_ok=True)`` raises ``OSError`` (e.g., a regular
        file already exists at the path → ``FileExistsError``;
        self-referential symlink → ``OSError``) →
        ``create_error_failure_mode``
      - ``Path.resolve()`` raises after creation (symlink loop)
        → ``resolve_error_failure_mode``
      - resolved path is outside the pack root →
        ``escape_failure_mode``

    Used to defend against symlinks / file-in-place at
    ``attestations/`` / ``agent_cards/`` redirecting attestation
    writes outside the pack tree.

    R9 P2 #2 reviewer correction: pre-fix the orchestrator called
    ``directory.mkdir(exist_ok=True)`` BEFORE this helper, so a
    FileExistsError or self-referential symlink raised before the
    structured-finding collapse path could run. This helper now
    owns BOTH mkdir AND resolve+is_relative_to checks.
    """
    try:
        directory.mkdir(exist_ok=True)
    except OSError as exc:
        return SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: could not create {directory_label}/ "
                f"directory at {directory}: {type(exc).__name__}: {exc}. "
                "Common causes: a regular file at that path, a self-"
                "referential symlink, or a permissions issue. Inspect "
                "the pack tree + remove the offending entry."
            ),
            payload={
                "pack_path": str(pack_path),
                "directory": str(directory),
                "error_type": type(exc).__name__,
                "failure_mode": create_error_failure_mode,
            },
        )
    try:
        pack_resolved = pack_path.resolve()
        directory_resolved = directory.resolve()
    except (OSError, RuntimeError) as exc:
        return SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: could not resolve {directory_label}/ "
                f"directory at {directory}: {type(exc).__name__}: {exc}. "
                "Common cause is a self-referential symlink."
            ),
            payload={
                "pack_path": str(pack_path),
                "directory": str(directory),
                "error_type": type(exc).__name__,
                "failure_mode": resolve_error_failure_mode,
            },
        )
    if not directory_resolved.is_relative_to(pack_resolved):
        return SignFinding(
            severity="refusal",
            reason="sign_subprocess_failed",
            message=(
                f"sign --bundle: {directory_label}/ directory at "
                f"{directory} resolves to {directory_resolved} which is "
                f"outside the pack root {pack_resolved}. Refusing to "
                "write attestations outside the pack tree (defends "
                "against symlinks redirecting outputs to attacker-"
                "controlled paths)."
            ),
            payload={
                "pack_path": str(pack_path),
                "directory": str(directory),
                "resolved_directory": str(directory_resolved),
                "resolved_pack": str(pack_resolved),
                "failure_mode": escape_failure_mode,
            },
        )
    return None


async def _run_sign_bundle_inner(
    *,
    pack_path: Path,
    cosign_bin: str | None,
    syft_bin: str,
    grype_bin: str,
    license_bin: str,
    key_path: str,
    signing_identity: str,
    findings: list[SignFinding],
    dev_mode_skip_cosign: bool,
) -> SignReport:
    """Inner sign-bundle body factored out so the caller can wrap the
    signing key tempfile cleanup in a single try/finally (per R2 P2 #2
    doctrine). All steps 3-12 happen here; the outer ``run_sign_bundle``
    handles tool resolution + signing-key resolution + cleanup."""
    # Step 3a: manifest pack id + kind (gates JWS arm; closed-enum
    # validation per R4 P2 #3).
    pack_id, pack_kind, manifest_finding = _read_pack_kind_for_bundle(pack_path)
    if manifest_finding is not None:
        findings.append(manifest_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )

    # Step 3a-output-dirs: create + validate output directories
    # early (R8 P2 #3 + R9 P2 #2). MUST happen BEFORE step 3a-bis
    # (JWS path read) — the JWS path validation otherwise catches
    # a symlinked agent_cards/ with a different closed-enum reason.
    # The helper owns BOTH mkdir AND resolve checks so a
    # FileExistsError or self-referential symlink at the dir path
    # collapses into a structured finding instead of a traceback.
    attestations_dir = pack_path / "attestations"
    early_attest_finding = _create_and_validate_output_dir(
        attestations_dir,
        pack_path=pack_path,
        directory_label="attestations",
        create_error_failure_mode="attestations_dir_create_error",
        escape_failure_mode="attestations_dir_escape",
        resolve_error_failure_mode="attestations_dir_resolve_error",
    )
    if early_attest_finding is not None:
        findings.append(early_attest_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    agent_cards_dir = pack_path / "agent_cards"
    early_cards_finding = _create_and_validate_output_dir(
        agent_cards_dir,
        pack_path=pack_path,
        directory_label="agent_cards",
        create_error_failure_mode="agent_cards_dir_create_error",
        escape_failure_mode="agent_cards_dir_escape",
        resolve_error_failure_mode="agent_cards_dir_resolve_error",
    )
    if early_cards_finding is not None:
        findings.append(early_cards_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )

    # Step 3a-bis: manifest-declared agent_card_jws_path (R8 P2 #1).
    # Only meaningful for agent packs; tool/skill packs have no JWS
    # to sign. Validates the declared path stays under the pack root
    # (defends against ``../`` traversal + absolute paths).
    agent_card_jws_path: Path | None = None
    if pack_kind == "agent":
        agent_card_jws_path, jws_path_finding = _read_agent_card_jws_path_for_bundle(pack_path)
        if jws_path_finding is not None:
            findings.append(jws_path_finding)
            return SignReport(
                operation="sign-bundle",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )

    # Step 3b: pyproject [project].name + [project].version (R4 P2 #2
    # records the REAL pack version in SLSA + in-toto; R6 P2 #1
    # cross-checks the wheel filename against [project].name + version
    # so a stale wheel from a different project / version can't slip
    # past the orchestrator).
    project_name, pack_version, project_finding = _read_pack_metadata_from_pyproject(pack_path)
    if project_finding is not None:
        findings.append(project_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )

    # Step 4: discover wheel — cross-checked against pyproject metadata.
    wheel_path, wheel_finding = _discover_wheel(
        pack_path,
        expected_project_name=project_name,
        expected_version=pack_version,
    )
    if wheel_finding is not None:
        findings.append(wheel_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    assert wheel_path is not None

    # attestations_dir + agent_cards_dir already created + validated
    # in step 3a-output-dirs above (R8 P2 #3 doctrine — early to
    # produce specific closed-enum reasons before any subsequent
    # check might fire on the same symlinked path).

    sbom_path = attestations_dir / "sbom.cdx.json"
    vuln_path = attestations_dir / "vuln-scan.json"
    license_path = attestations_dir / "license-audit.json"
    slsa_path = attestations_dir / "slsa-provenance.intoto.json"
    intoto_path = attestations_dir / "intoto-layout.json"
    sig_path = attestations_dir / "cosign.sig"
    bundle_path = attestations_dir / "bundle.sigstore"

    artifacts: dict[str, str] = {}

    # Step 5: SBOM via syft.
    try:
        rc, stdout, stderr = await _exec_syft(syft_bin, pack_path, sbom_output_path=sbom_path)
    except OSError as exc:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=f"syft subprocess raised {type(exc).__name__}: {exc}",
                payload={"tool": "syft", "error_type": type(exc).__name__},
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    if rc != 0:
        findings.append(
            _exec_subprocess_failed_finding(
                tool="syft", returncode=rc, stdout=stdout, stderr=stderr, target=str(pack_path)
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    syft_artifact_finding = _verify_tool_output_artifact(
        sbom_path,
        tool="syft",
        failure_mode_missing="syft_sbom_output_missing",
        failure_mode_empty="syft_sbom_output_empty",
    )
    if syft_artifact_finding is not None:
        findings.append(syft_artifact_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts["sbom"] = str(sbom_path)

    # Step 6: vuln scan via grype.
    try:
        rc, stdout, stderr = await _exec_grype(grype_bin, wheel_path, vuln_output_path=vuln_path)
    except OSError as exc:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=f"grype subprocess raised {type(exc).__name__}: {exc}",
                payload={"tool": "grype", "error_type": type(exc).__name__},
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    if rc != 0:
        findings.append(
            _exec_subprocess_failed_finding(
                tool="grype", returncode=rc, stdout=stdout, stderr=stderr, target=str(wheel_path)
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    grype_artifact_finding = _verify_tool_output_artifact(
        vuln_path,
        tool="grype",
        failure_mode_missing="grype_vuln_output_missing",
        failure_mode_empty="grype_vuln_output_empty",
    )
    if grype_artifact_finding is not None:
        findings.append(grype_artifact_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts["vuln_scan"] = str(vuln_path)

    # Step 7: license audit.
    try:
        rc, stdout, stderr = await _exec_license_auditor(
            license_bin, license_output_path=license_path
        )
    except OSError as exc:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=f"license-auditor subprocess raised {type(exc).__name__}: {exc}",
                payload={"tool": "license_auditor", "error_type": type(exc).__name__},
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    if rc != 0:
        findings.append(
            _exec_subprocess_failed_finding(
                tool="license_auditor",
                returncode=rc,
                stdout=stdout,
                stderr=stderr,
                target=str(pack_path),
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    license_artifact_finding = _verify_tool_output_artifact(
        license_path,
        tool="license_auditor",
        failure_mode_missing="license_audit_output_missing",
        failure_mode_empty="license_audit_output_empty",
    )
    if license_artifact_finding is not None:
        findings.append(license_artifact_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts["license_audit"] = str(license_path)

    # Step 7b (R7 P2 #1): wheel-content integrity check BEFORE
    # rendering SLSA / in-toto. Mirrors verify-side's R6 P2 #1 +
    # R6 P2 #2 + R7 P2 #2 protections via the shared helper at
    # ``cli._wheel_integrity``. Pre-R7 sign emitted provenance for
    # any wheel whose filename matched pyproject — but a wheel can
    # be renamed without changing the signed bytes, so the wheel's
    # internal METADATA might disagree with the (mutable) wheel
    # filename + pyproject version. That created bundles the new
    # verifier rejects immediately. Sign now refuses up-front.
    from cognic_agentos.cli._wheel_integrity import (
        read_signed_wheel_dist_info_metadata as _shared_wheel_integrity_read,
    )

    _wheel_triple, _wheel_integrity_failure = _shared_wheel_integrity_read(
        wheel_path,
        expected_project_name=project_name,
        expected_version=pack_version,
    )
    if _wheel_integrity_failure is not None:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=f"sign --bundle: {_wheel_integrity_failure.message}",
                payload={
                    **_wheel_integrity_failure.payload,
                    "failure_mode": _wheel_integrity_failure.failure_mode,
                },
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    # R8 P2 #1 reviewer correction: compare the wheel-derived kind
    # against the manifest [pack].kind. Pre-fix sign discarded the
    # triple via ``del _wheel_triple`` + happily emitted AgentCard JWS
    # + agent provenance for a wheel whose entry-point group declared
    # a different kind (e.g., agent manifest + ``[cognic.tools]``
    # wheel). Mirror verify's ``wheel_kind_disagrees_with_manifest``
    # refusal before rendering provenance.
    assert _wheel_triple is not None
    # R15 follow-up round 1 P2 #1/P2 #2: helper now returns a 4-tuple;
    # the validated entry-point list is consumed only by verify
    # step 11 (the FINAL gate of the trust pipeline post R15 follow-up
    # round 2 P2 #1 ordering fix). Sign discards the trailing slot —
    # wheel-integrity-anchored kind + name + version are the sign-side
    # outputs.
    (
        _wheel_metadata_name,
        _wheel_metadata_version,
        _wheel_derived_kind,
        _wheel_validated_entry_points,
    ) = _wheel_triple
    del _wheel_validated_entry_points
    if _wheel_derived_kind != pack_kind:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=(
                    f"sign --bundle: wheel-derived pack kind="
                    f"{_wheel_derived_kind!r} does not match manifest "
                    f"[pack].kind={pack_kind!r}. The wheel's entry-point "
                    "group is the integrity-anchored source of truth for "
                    "kind; refusing to render provenance for a kind-"
                    "mismatched bundle."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "wheel_path": str(wheel_path),
                    "derived_pack_kind": _wheel_derived_kind,
                    "manifest_pack_kind": pack_kind,
                    "failure_mode": "wheel_kind_disagrees_with_manifest",
                },
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    # The wheel's signed METADATA Name + Version + kind all agree
    # with the wheel filename + pyproject + manifest. Sign-side does
    # NOT rebind project_name / pack_version (sign uses them only for
    # reading + provenance authoring; the integrity check above
    # ensures they agree with the signed wheel content).
    del _wheel_metadata_name, _wheel_metadata_version, _wheel_derived_kind

    # Step 8: SLSA provenance template.
    # R3 P2 #3: ``signing_identity`` (vault URI or file path) is
    # recorded in attestations + cosign-argv byproduct. The
    # ``--key`` arg in the byproduct also uses ``signing_identity``,
    # NOT the transient tempfile path that gets unlinked at exit.
    # cosign itself receives ``key_path`` (file path) at exec time;
    # the ATTESTATION records the auditable identity.
    # R4 P2 #1 reviewer correction: the SLSA byproduct is renamed
    # ``cosign_invocation_plan`` (was ``cosign_argv``) + restructured
    # into a dict with an ``executed`` flag. Pre-fix: the byproduct
    # was named "argv" and structured as a literal list, which
    # implied executed-evidence even when (a) cosign actually ran
    # against a tempfile path different from the recorded value
    # (vault path) or (b) cosign didn't run at all (dev-skip).
    # The new shape preserves the audit trail without false
    # execution evidence: ``executed: true`` for non-skip runs,
    # ``executed: false + skip_reason`` for dev-skip.
    sbom_digest = _compute_file_digest_sha256(sbom_path)
    if dev_mode_skip_cosign:
        cosign_invocation_plan: dict[str, Any] = {
            "executed": False,
            "key_identity": signing_identity,
            "skip_reason": "dev_mode_skip_cosign",
        }
    else:
        cosign_invocation_plan = {
            "executed": True,
            "key_identity": signing_identity,
            "wheel_path": str(wheel_path),
            "sig_output_path": str(sig_path),
            "bundle_output_path": str(bundle_path),
        }
    slsa_finding = _render_slsa_provenance_to_disk(
        slsa_path,
        pack_id=pack_id,
        pack_version=pack_version,
        pack_kind=pack_kind,
        wheel_path=wheel_path,
        sbom_digest=sbom_digest,
        signing_identity=signing_identity,
        cosign_invocation_plan=cosign_invocation_plan,
    )
    if slsa_finding is not None:
        findings.append(slsa_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts["slsa_provenance"] = str(slsa_path)

    # Step 9: in-toto layout template.
    # R5 P2 #1 + R7 P2 #1 reviewer corrections: artifact_paths is
    # both mode-aware AND kind-aware:
    #   - dev_mode_skip_cosign omits cosign.sig + bundle.sigstore
    #     (those files are NEVER produced when cosign is skipped)
    #   - kind=="agent" includes agent_cards/agent-card.jws (the
    #     JWS step is step 10, AFTER layout rendering, but the path
    #     is deterministic + the layout describes the EXPECTED
    #     artifact set the runtime trust gate verifies at admission)
    # Pre-R5 fix: layout listed cosign artifacts under dev-skip even
    # when they weren't produced.
    # Pre-R7 fix: layout NEVER listed the JWS even on the agent
    # happy path, leaving the bundle's own artifact-set attestation
    # incomplete.
    intoto_artifact_paths = [
        str(sbom_path),
        str(vuln_path),
        str(license_path),
        str(slsa_path),
    ]
    if not dev_mode_skip_cosign:
        intoto_artifact_paths.extend([str(sig_path), str(bundle_path)])
    if pack_kind == "agent":
        # R8 P2 #1: use the manifest-declared JWS path, not a
        # hardcoded default. agent_card_jws_path is non-None at
        # this point because _read_agent_card_jws_path_for_bundle
        # ran in step 3a-bis for agent kind.
        assert agent_card_jws_path is not None
        intoto_artifact_paths.append(str(agent_card_jws_path))
    intoto_finding = _render_intoto_layout_to_disk(
        intoto_path,
        pack_id=pack_id,
        pack_version=pack_version,
        pack_kind=pack_kind,
        signing_identity=signing_identity,
        artifact_paths=intoto_artifact_paths,
    )
    if intoto_finding is not None:
        findings.append(intoto_finding)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts["intoto_layout"] = str(intoto_path)

    # Step 10: AgentCard JWS (agent packs only).
    # R8 P2 #1: write to the manifest-declared path validated in
    # step 3a-bis.
    if pack_kind == "agent":
        assert agent_card_jws_path is not None
        jws_finding = _sign_agent_card_jws_to_disk(
            pack_path,
            signing_key_path=key_path,
            jws_output_path=agent_card_jws_path,
        )
        if jws_finding is not None:
            findings.append(jws_finding)
            return SignReport(
                operation="sign-bundle",
                target_path=str(pack_path),
                overall_status="fail",
                findings=findings,
            )
        artifacts["agent_card_jws"] = str(agent_card_jws_path)

    # Step 11: cosign sign-blob over the wheel.
    # R2 P2 #3 doctrine — ``--dev-mode-skip-cosign`` honored here:
    # the prod-profile guard at ``core/config.py:1035`` rejects this
    # branch in prod; reaching here means dev / test profile. We
    # emit a security warning + skip the cosign exec + omit cosign
    # output artifacts. The other 6 attestations are still produced;
    # report status remains ``pass`` with the warning.
    if dev_mode_skip_cosign:
        findings.append(
            SignFinding(
                severity="warning",
                reason="sign_subprocess_failed",  # closest closed-enum; payload distinguishes
                message=(
                    "WARNING: --dev-mode-skip-cosign is set; cosign "
                    "sign-blob was NOT invoked. The output cosign.sig + "
                    "bundle.sigstore are NOT in the bundle. The prod "
                    "settings profile rejects this flag at startup; this "
                    "branch is only reachable from dev / test profiles."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "tool": "cosign",
                    "dev_mode_skip_cosign": True,
                    "failure_mode": "dev_mode_skip_cosign",
                },
            )
        )
        # Skip post-exec artifact verification for cosign.
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="pass",
            findings=findings,
            artifacts=artifacts,
        )

    # cosign_bin is non-None at this point because we guarded the
    # dev-skip branch above; mypy needs the assert.
    assert cosign_bin is not None
    try:
        rc, stdout, stderr = await _exec_cosign_sign_blob(
            cosign_bin,
            wheel_path,
            signing_key_path=key_path,
            sig_output_path=sig_path,
            bundle_output_path=bundle_path,
        )
    except OSError as exc:
        findings.append(
            SignFinding(
                severity="refusal",
                reason="sign_subprocess_failed",
                message=f"cosign subprocess raised {type(exc).__name__}: {exc}",
                payload={"tool": "cosign", "error_type": type(exc).__name__},
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    if rc != 0:
        findings.append(
            _exec_subprocess_failed_finding(
                tool="cosign", returncode=rc, stdout=stdout, stderr=stderr, target=str(wheel_path)
            )
        )
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )
    artifacts["cosign_sig"] = str(sig_path)
    artifacts["bundle_sigstore"] = str(bundle_path)

    # Step 12: post-exec artifact verification (R1 P2 #1 doctrine).
    artifact_findings = _verify_post_exec_artifacts(
        wheel_path,
        sig_output_path=sig_path,
        bundle_output_path=bundle_path,
    )
    if artifact_findings:
        findings.extend(artifact_findings)
        return SignReport(
            operation="sign-bundle",
            target_path=str(pack_path),
            overall_status="fail",
            findings=findings,
        )

    return SignReport(
        operation="sign-bundle",
        target_path=str(pack_path),
        overall_status="pass",
        findings=findings,
        artifacts=artifacts,
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
    "run_sign_bundle",
]
