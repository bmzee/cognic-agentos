"""Sprint-7A T7 — AGNTCY/OASF Wave-1 identity validator (CRITICAL CONTROLS).

Per Doctrine Decision G, this module is on the critical-controls
floor (95% line / 90% branch). The identity matrix is wire-protocol-
public — cross-org agent discovery routes off these fields, so a
refusal here protects every downstream consumer from
under-identified packs.

Wave-1 strictness matrix:

  - Universally mandatory (every pack kind): ``agent_id`` /
    ``display_name`` / ``provider_organization`` / ``provider_url``.
    Missing OR ``AUTHOR-FILL`` placeholder OR empty string OR
    non-string → closed-enum refusal per field.
  - Agent-pack-only mandatory: ``agent_card_url`` /
    ``agent_card_jws_path``. Tool + skill packs are NOT checked
    against these (the field is meaningless outside the agent
    discovery surface).
  - ``agent_card_jws_path`` resolves: pack-relative path must point
    at an existing file. Missing-or-placeholder path surfaces as
    ``identity_agent_card_jws_path_missing``; present-but-unresolvable
    surfaces as ``identity_agent_card_jws_path_unresolvable``.
  - Wave-1 optional / Wave-2 mandatory: ``oasf_capability_set``.
    Absent → WARNING-severity finding (NOT refusal). Pack authors
    see the diagnostic; CI exit code stays 0.

Wave-3 reserved fields (e.g., ``verifiable_credentials_path``) are
NOT checked at T7 — there is no closed-enum reason yet, and Wave-3
introduces those reasons alongside the credential-verification
runtime. Adding them at T7 would create closed-enum drift the
T1 ownership-map gate would reject.

AUTHOR-FILL doctrine: T5's scaffold templates ship ``AUTHOR-FILL:``
placeholders at every author-customizable site. This validator
treats those as missing — a freshly-scaffolded pack fails ``agentos
validate`` with explicit per-field remediation, the canonical
pack-author iteration loop the plan-of-record documents.

Dual-path lookup (T11 doctrine-fix follow-up): mirrors the T8/T9/T10
doctrine. Each declared identity path validates independently.

  - Canonical T5 shape: top-level ``[identity]``.
  - Legacy/docs shape: ``[tool.cognic.identity]`` (per
    ``docs/HOW-TO-WRITE-A-PACK.md`` + the existing reference fixture
    packs at ``tests/fixtures/cognic_test_{mcp,agent}_pack/``).

The orchestrator's R27 P2 #1 shape gate accepts either path; without
T7 honouring both, a docs-shaped manifest dispatched here and fired
every field-missing refusal even with a fully-valid legacy block.
Each refusal + warning carries ``payload.block_path`` distinguishing
which path tripped it (``identity`` for canonical;
``tool.cognic.identity`` for legacy) so authors can locate per-path
remediation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding

#: Author-side placeholder prefix the scaffold templates emit. The
#: validator treats values starting with this prefix as missing so
#: pack authors see explicit per-field remediation rather than the
#: validator silently accepting placeholder text.
_AUTHOR_FILL_PREFIX: str = "AUTHOR-FILL"

#: Closed-enum tuple of universally-mandatory identity fields paired
#: with their owning closed-enum reason. Iteration here is the
#: single source of truth for the universal mandatory checks; adding
#: a new field requires updating this list AND the closed-enum
#: ``ValidatorReason`` literal AND the ``_VALIDATOR_REASON_OWNERSHIP``
#: mapping.
_UNIVERSAL_MANDATORY_FIELDS: tuple[tuple[str, str], ...] = (
    ("agent_id", "identity_agent_id_missing"),
    ("display_name", "identity_display_name_missing"),
    ("provider_organization", "identity_provider_organization_missing"),
    ("provider_url", "identity_provider_url_missing"),
)


def _is_missing_or_placeholder(value: Any) -> bool:
    """True iff ``value`` is missing, non-string, empty / whitespace-
    only, or starts with the ``AUTHOR-FILL`` prefix. Any of these
    failure modes counts as a missing field for refusal purposes."""
    if not isinstance(value, str):
        return True
    stripped = value.strip()
    if not stripped:
        return True
    return stripped.startswith(_AUTHOR_FILL_PREFIX)


#: Closed-enum tuple of (block_path, accessor) pairs the validator
#: inspects. Mirrors the T8/T9/T10/T11 dual-path doctrine. Order is
#: (canonical first, legacy second) so deterministic per-path
#: dispatch surfaces canonical-path refusals before legacy-path
#: ones in the orchestrator's aggregated finding list.
_IDENTITY_BLOCK_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("identity", ("identity",)),
    ("tool.cognic.identity", ("tool", "cognic", "identity")),
)


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``data``; return the leaf dict or
    ``None`` on any non-dict intermediate."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def _identity_blocks(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return every declared identity block (canonical + legacy) as
    ``(block_path, block)`` pairs in dispatch order. The
    orchestrator's shape gate (T6 R19 P2 #1 + R27 P2 #1) guarantees
    at least one path is declared by the time this validator runs;
    direct unit-test entry points may pass a manifest with neither
    path, in which case this returns ``[]`` and ``validate`` is a
    no-op (the orchestrator's missing-block refusal owns that
    case)."""
    located: list[tuple[str, dict[str, Any]]] = []
    for prefix, accessor in _IDENTITY_BLOCK_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is not None:
            located.append((prefix, block))
    return located


def _pack_kind(data: dict[str, Any]) -> str | None:
    """Return ``[pack].kind`` as a lowercase string (or ``None`` if
    missing / non-string). Used to gate the agent-pack-only checks."""
    pack_block = data.get("pack")
    if not isinstance(pack_block, dict):
        return None
    kind = pack_block.get("kind")
    return kind if isinstance(kind, str) else None


def _check_jws_path_resolves(
    jws_value: str, pack_path: Path, block_path: str
) -> list[ValidatorFinding]:
    """R22 P2 #1 path-containment gate. Wave-1 doctrine: the
    ``agent_card_jws_path`` field is fed to the Sprint-4 trust-gate
    verifier at admission time and MUST point at a file inside the
    published pack. A malicious or malformed manifest that declared
    an absolute path (``/etc/hosts``) or a traversal
    (``../outside.jws``) could otherwise route the signer/verifier
    at files outside the pack root.

    ``block_path`` distinguishes which manifest path declared the
    JWS field (``identity`` for canonical; ``tool.cognic.identity``
    for legacy) so authors can locate per-path remediation.

    Three failure modes share the closed-enum reason
    ``identity_agent_card_jws_path_unresolvable``; the payload's
    ``failure_mode`` distinguishes them for CI parsers + remediation
    rendering:

      - ``"absolute_path_rejected"`` — path starts with ``/`` (POSIX)
        or has a Windows drive letter; only pack-relative paths are
        accepted.
      - ``"path_escape_rejected"`` — relative path resolves outside
        the pack root (e.g., ``../outside.jws`` or
        ``agent_cards/../../escape.jws``).
      - ``"file_not_found"`` — path is contained inside the pack
        root but the file does not exist.
    """
    candidate = Path(jws_value)
    if candidate.is_absolute():
        return [
            ValidatorFinding(
                severity="refusal",
                reason="identity_agent_card_jws_path_unresolvable",
                message=(
                    f"identity.agent_card_jws_path declares {jws_value!r} "
                    "which is an absolute path; only pack-relative paths "
                    "are accepted. Absolute paths could route the "
                    "Sprint-4 trust-gate verifier at files outside the "
                    "published pack."
                ),
                payload={
                    "block_path": block_path,
                    "field": "identity.agent_card_jws_path",
                    "declared_path": jws_value,
                    "failure_mode": "absolute_path_rejected",
                },
            )
        ]

    pack_root_resolved = pack_path.resolve()
    jws_full_path = (pack_path / jws_value).resolve()
    if not jws_full_path.is_relative_to(pack_root_resolved):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="identity_agent_card_jws_path_unresolvable",
                message=(
                    f"identity.agent_card_jws_path declares {jws_value!r} "
                    f"which resolves to {jws_full_path} — outside the pack "
                    f"root at {pack_root_resolved}. Path traversals are "
                    "rejected to keep the trust-gate verifier scoped to "
                    "files inside the published pack."
                ),
                payload={
                    "block_path": block_path,
                    "field": "identity.agent_card_jws_path",
                    "declared_path": jws_value,
                    "resolved_path": str(jws_full_path),
                    "failure_mode": "path_escape_rejected",
                },
            )
        ]

    if not jws_full_path.is_file():
        return [
            ValidatorFinding(
                severity="refusal",
                reason="identity_agent_card_jws_path_unresolvable",
                message=(
                    f"identity.agent_card_jws_path declares {jws_value!r} "
                    f"but no file exists at {jws_full_path}. The Sprint-4 "
                    "trust-gate verifier reads this file at admission; it "
                    "MUST be present in the published pack."
                ),
                payload={
                    "block_path": block_path,
                    "field": "identity.agent_card_jws_path",
                    "declared_path": jws_value,
                    "resolved_path": str(jws_full_path),
                    "failure_mode": "file_not_found",
                },
            )
        ]

    return []


def _validate_identity_block(
    block: dict[str, Any],
    block_path: str,
    pack_kind: str | None,
    pack_path: Path,
) -> list[ValidatorFinding]:
    """Validate one declared identity block against the AGNTCY/OASF
    Wave-1 strictness matrix. Each refusal + warning carries
    ``payload.block_path = <block_path>`` so authors can locate
    per-path remediation when both shapes are declared."""
    findings: list[ValidatorFinding] = []

    # Universally-mandatory fields — one refusal per missing.
    for field, reason in _UNIVERSAL_MANDATORY_FIELDS:
        if _is_missing_or_placeholder(block.get(field)):
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason=reason,  # type: ignore[arg-type]  # closed-enum literal
                    message=(
                        f"identity.{field} is missing or carries an "
                        f"AUTHOR-FILL placeholder; the AGNTCY/OASF Wave-1 "
                        f"strictness matrix requires this field."
                    ),
                    payload={
                        "block_path": block_path,
                        "field": f"identity.{field}",
                    },
                )
            )

    # Agent-pack-only mandatory fields. Tool + skill packs skip these
    # — agent_card_url and agent_card_jws_path are meaningless outside
    # the agent-discovery surface.
    if pack_kind == "agent":
        if _is_missing_or_placeholder(block.get("agent_card_url")):
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="identity_agent_card_url_missing",
                    message=(
                        "identity.agent_card_url is missing or carries an "
                        "AUTHOR-FILL placeholder; agent packs must declare "
                        "their A2A agent-card endpoint URL."
                    ),
                    payload={
                        "block_path": block_path,
                        "field": "identity.agent_card_url",
                    },
                )
            )

        jws_value = block.get("agent_card_jws_path")
        if _is_missing_or_placeholder(jws_value):
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="identity_agent_card_jws_path_missing",
                    message=(
                        "identity.agent_card_jws_path is missing or carries "
                        "an AUTHOR-FILL placeholder; agent packs must "
                        "declare a pack-relative path to the JWS-signed "
                        "agent card."
                    ),
                    payload={
                        "block_path": block_path,
                        "field": "identity.agent_card_jws_path",
                    },
                )
            )
        else:
            # mypy: _is_missing_or_placeholder returns False only when
            # value is a non-empty string, so jws_value is str here.
            assert isinstance(jws_value, str)
            findings.extend(_check_jws_path_resolves(jws_value, pack_path, block_path))

    # Wave-1 optional / Wave-2 mandatory: oasf_capability_set absent
    # fires a warning-severity finding (does NOT affect exit code).
    if "oasf_capability_set" not in block:
        findings.append(
            ValidatorFinding(
                severity="warning",
                reason="identity_oasf_capability_set_missing",
                message=(
                    "identity.oasf_capability_set is absent; Wave-1 treats "
                    "this as a warning, but Wave-2 will require it for "
                    "AGNTCY/OASF capability discovery. Declare the "
                    "capability set now to avoid a future refusal."
                ),
                payload={
                    "block_path": block_path,
                    "field": "identity.oasf_capability_set",
                },
            )
        )

    return findings


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's identity declaration per the
    AGNTCY/OASF Wave-1 strictness matrix.

    Both the canonical top-level ``[identity]`` and the legacy
    ``[tool.cognic.identity]`` shapes are inspected; each declared
    location validates independently and surfaces its own refusals
    + warnings with ``payload.block_path`` distinguishing the path.

    Returns a list of refusal- + warning-severity findings; empty on
    full pass. The orchestrator concatenates findings across
    validators and computes exit code via
    ``ValidatorFinding.affects_exit_code``.
    """
    located = _identity_blocks(data)
    if not located:
        # Direct unit-test entry without either path declared. The
        # orchestrator's shape gate owns the missing-block refusal
        # for the regular flow.
        return []

    pack_kind = _pack_kind(data)
    findings: list[ValidatorFinding] = []
    for block_path, block in located:
        findings.extend(_validate_identity_block(block, block_path, pack_kind, pack_path))
    return findings


__all__ = ["validate"]
