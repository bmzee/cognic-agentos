"""Sprint 10.6 T19 Phase 1 — pure-functional Docker substrate preflight
per ADR-004 §25 + Sprint 10.6 spec §5.5 + §5.8 step 2.

This module is the **wire-public-artifact owner** for the 5 Docker-
owned ``SandboxRefusalReason`` credential-projection refusal values —
the complement-half of the T18 wire-equal-subset doctrine. T18's
``sandbox/projection.py`` owns the 4 planner-emitted values; this
module owns the 5 substrate/lifecycle-emitted values:

  1. ``sandbox_credential_staging_path_not_tmpfs`` (precedence 1)
  2. ``sandbox_credential_projection_image_user_directive_non_numeric`` (precedence 2)
  3. ``sandbox_credential_projection_workload_gid_unknown`` (precedence 3; dev-escape downgradable)
  4. ``sandbox_credential_projection_root_workload_refused`` (precedence 4; dev-escape downgradable)
  5. ``sandbox_credential_projection_image_gid_manifest_mismatch`` (precedence 5)

**No I/O. No backend coupling.** The preflight is a pure function over
``(expected_workload_gid, image_user_directive, proc_mounts_content,
dev_escape_enabled, profile) → PreflightResult | raises SandboxLifecycleRefused
| raises ValueError``.

The Docker-specific I/O — reading ``/proc/mounts``, inspecting the
image's ``Config.User`` field via ``aiodocker`` — lives at the call
site in ``sandbox/backends/docker_sibling.py`` (T21 lifecycle
integration wires it in). This module operates on already-resolved
data so the test surface is pure-functional + the same preflight
contract can be re-called by T20 K8s with K8s-resolved inputs (K8s
won't pass the ``proc_mounts_content`` kwarg; T20 will likely
introduce a parallel ``verify_k8s_credential_projection_preflight``
calling the same shared private parsers).

**Wave-1 design locks (rounds 0-2 per user reviewer framing):**

- Single public orchestrator (``verify_docker_credential_projection_preflight``)
  + private parsers (``_check_shm_is_tmpfs``, ``_parse_image_user_directive``).
  Mirrors T18's ``compute_projection_plan`` shape; avoids creating
  two semi-public contracts T20 K8s might inherit incorrectly.

- Returns ``PreflightResult`` (T19 round-1 reviewer fix; round-0 returned
  ``None`` which lost the distinction between normal-pass and dev-escape
  downgrade for the T19 Phase 2 executor + T21 audit emit). The result
  carries ``resolved_gid`` + ``file_mode`` (0o440 normal; 0o644 downgrade)
  + ``dir_mode`` (always 0o750) + ``dev_escape_downgrade_reason`` (None
  on the normal path; full wire-public ``SandboxRefusalReason`` value
  on either dev-escape downgrade per T19 round-2 reviewer fix —
  wire-equal-subset pinned by ``TestPreflightDowngradeReasonDriftDetector``).

- Dev-escape (``COGNIC_DEV_ALLOW_PERMISSIVE_CREDENTIAL_PROJECTION=1``)
  downgrades ``sandbox_credential_projection_workload_gid_unknown`` +
  ``sandbox_credential_projection_root_workload_refused`` ONLY; never
  the other 3 refusals. Docker-only. ``profile`` is typed as
  ``RuntimeProfile`` (``Literal["dev", "stage", "prod"]`` from
  ``core/config.py:32``); dev-escape is available ONLY in ``profile="dev"``.
  Combined with any non-``dev`` profile (``stage`` or ``prod``) raises
  ``ValueError`` (programmer/operator misconfig) BEFORE any refusal
  check — never masquerades as a credential refusal per spec §5.5
  fail-loud regression contract. T19 round-1 reviewer fix: the round-0
  guard checked only ``profile == "production"`` which let
  ``profile="prod"`` (the actual Settings vocabulary) AND
  ``profile="stage"`` slip through.

- USER directive parser locked at T19 round-0:
  * ``"UID:GID"`` (both numeric) → ``kind="resolved"``,
    ``gid_numeric=<GID>``. Caller checks against expected_workload_gid.
  * ``"UID"`` (single numeric) → ``kind="uid_only"``,
    ``gid_numeric=None``. GID is ambiguous from a UID-only directive
    — UID==GID is a common Docker convention but NOT guaranteed;
    refusing the ambiguity is the preflight's job. Caller emits
    ``sandbox_credential_projection_workload_gid_unknown``.
  * Name forms (``"root"`` / ``"node"`` / ``"app"``) → ``kind="non_numeric"``.
    Per user round-0 pin: ``"root"`` (the NAME) is non_numeric, NOT
    ``sandbox_credential_projection_root_workload_refused``. The latter
    is reserved for resolved numeric GID 0 (e.g., ``"USER 1000:0"``
    or ``"USER 0:0"``).
  * Mixed numeric/name (``"node:1000"`` / ``"1000:node"``) →
    ``kind="non_numeric"``.
  * Absent (``None`` / ``""`` / whitespace-only) → ``kind="absent"``.
    Caller emits ``sandbox_credential_projection_workload_gid_unknown``.

**Critical-controls scope:** CC from birth (owns wire-public refusal
raise sites; promotes to the durable per-file CC coverage gate at
Z1c per spec §5.4). T19 Phase 1 is the strict-halt-before-commit
discipline per ``[[feedback_strict_review_off_gate]]``.
"""

from __future__ import annotations

import dataclasses
from typing import Final, Literal

from cognic_agentos.core.config import RuntimeProfile
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# ---------------------------------------------------------------------------
# USER directive parser
# ---------------------------------------------------------------------------

#: Kind of the parsed USER directive — closed-enum 4-value Literal.
#:
#:   - ``resolved`` — directive was ``"UID:GID"`` form; ``gid_numeric``
#:     carries the GID half.
#:   - ``uid_only`` — directive was numeric single-part ``"UID"`` form;
#:     ``gid_numeric=None``. Caller emits
#:     ``sandbox_credential_projection_workload_gid_unknown`` because
#:     GID cannot be inferred from UID alone (UID==GID is not a
#:     guaranteed convention).
#:   - ``non_numeric`` — directive contained a name form
#:     (``"root"`` / ``"node"`` / mixed). Caller emits
#:     ``sandbox_credential_projection_image_user_directive_non_numeric``.
#:   - ``absent`` — directive was ``None`` / empty / whitespace-only.
#:     Caller emits ``sandbox_credential_projection_workload_gid_unknown``.
_ParsedUserDirectiveKind = Literal["resolved", "uid_only", "non_numeric", "absent"]


@dataclasses.dataclass(frozen=True, slots=True)
class _ParsedUserDirective:
    """Discriminated-union return type from :func:`_parse_image_user_directive`.

    ``gid_numeric`` is populated iff ``kind == "resolved"``.
    """

    kind: _ParsedUserDirectiveKind
    gid_numeric: int | None = None


def _parse_image_user_directive(directive: str | None) -> _ParsedUserDirective:
    """Parse a Docker image ``Config.User`` directive into a
    discriminated-union result per the T19 round-0 design locks
    (see module docstring).

    Whitespace at the directive level is stripped before parsing;
    inner whitespace renders the directive non_numeric. Negative
    numerics route to non_numeric (semantically invalid as POSIX
    UIDs/GIDs even though syntactically valid integers).
    """
    if directive is None:
        return _ParsedUserDirective(kind="absent")
    stripped = directive.strip()
    if not stripped:
        return _ParsedUserDirective(kind="absent")

    parts = stripped.split(":")

    if len(parts) == 1:
        # Single-part form.
        single = parts[0]
        if not single.isdigit():
            # Name form OR malformed (e.g., "-1", whitespace inside).
            return _ParsedUserDirective(kind="non_numeric")
        # Numeric UID without explicit GID → uid_only (caller emits
        # sandbox_credential_projection_workload_gid_unknown).
        return _ParsedUserDirective(kind="uid_only")

    if len(parts) == 2:
        # ``"UID:GID"`` form.
        uid_part, gid_part = parts[0], parts[1]
        if not (uid_part.isdigit() and gid_part.isdigit()):
            # Mixed or both name forms (``"node:1000"`` / ``"1000:node"``
            # / ``"-1:1000"`` / ``"node:group"``) → non_numeric.
            return _ParsedUserDirective(kind="non_numeric")
        return _ParsedUserDirective(kind="resolved", gid_numeric=int(gid_part))

    # 3+ parts (multiple colons) → malformed → non_numeric.
    return _ParsedUserDirective(kind="non_numeric")


# ---------------------------------------------------------------------------
# /proc/mounts tmpfs check
# ---------------------------------------------------------------------------


def _check_shm_is_tmpfs(proc_mounts_content: str) -> bool:
    """Pure parser for ``/proc/mounts`` content.

    Returns ``True`` iff ``/dev/shm`` appears as a mount point with
    fstype ``tmpfs``. Partial-path matches (``/dev/shm2`` /
    ``/dev/shm/foo``) do NOT count — only the exact mount point
    ``/dev/shm`` qualifies.

    ``/proc/mounts`` format per Linux kernel: each non-empty line is
    space-separated as
    ``<device> <mount_point> <fstype> <opts> <dump> <pass>``. Lines
    with fewer than 3 space-separated tokens are skipped (defensive
    against future kernel format additions; a malformed line MUST
    NOT crash the parser).
    """
    for line in proc_mounts_content.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mount_point = parts[1]
        fstype = parts[2]
        if mount_point == "/dev/shm" and fstype == "tmpfs":
            return True
    return False


# ---------------------------------------------------------------------------
# Public result + orchestrator
# ---------------------------------------------------------------------------

#: Locked closed-enum vocabulary for the dev-escape downgrade reason —
#: the two refusals dev-escape covers per spec §180 + the round-0
#: locked dev-escape matrix. Pinned at the
#: ``PreflightResult.dev_escape_downgrade_reason`` field so the T19
#: Phase 2 executor + the T21 audit-emit seam can both dispatch on
#: which refusal was downgraded.
#:
#: T19 round-2 reviewer fix: values are the FULL wire-public
#: ``SandboxRefusalReason`` strings (not shortened ``"workload_gid_unknown"``
#: / ``"root_workload_refused"`` as round-1 had). This is the
#: wire-equal-subset doctrine that T18's ``ProjectionRefusalReason``
#: pioneered — the result carries the canonical refusal vocabulary
#: directly so:
#:
#:  - T21 audit emit uses the wire vocabulary without translation
#:    (no mapping drift point between preflight + audit chain row)
#:  - Phase 2 executor dispatches on the same closed-enum value
#:    used at the SandboxRefusalReason boundary
#:  - The drift detector at
#:    ``tests/unit/sandbox/test_substrate_preflight.py::TestPreflightDowngradeReasonDriftDetector``
#:    pins this subset of ``SandboxRefusalReason``, same shape as
#:    T18's ``ProjectionRefusalReason`` ⊆ ``SandboxRefusalReason``
#:    drift detector
_PreflightDowngradeReason = Literal[
    "sandbox_credential_projection_workload_gid_unknown",
    "sandbox_credential_projection_root_workload_refused",
]

#: File mode on the normal projection path (spec §5.4 Docker executor:
#: "chmod 0440 on files, 0750 on dirs"). The dev-escape downgrade
#: lowers ONLY the file mode to 0o644 per spec §180; the dir mode
#: stays 0o750 (spec doesn't downgrade it).
_FILE_MODE_NORMAL: Final[int] = 0o440
_FILE_MODE_DEV_ESCAPE_DOWNGRADE: Final[int] = 0o644
_DIR_MODE_NORMAL: Final[int] = 0o750


@dataclasses.dataclass(frozen=True, slots=True)
class PreflightResult:
    """Wire-public-ish result carrier returned by
    :func:`verify_docker_credential_projection_preflight` on success.

    T19 round-1 reviewer-found bug: the round-0 contract returned
    ``None`` for both normal-pass AND dev-escape downgrade paths,
    which meant the Phase 2 Docker executor + the T21 lifecycle
    integration could not distinguish "normal 0o440 + chgrp(gid)
    projection" from "dev-escape 0o644 + structured warning log"
    per spec §180. The fix returns this frozen result carrying:

      - ``resolved_gid``: ``int | None``. Set to the resolved
        numeric GID on the normal path AND on the
        ``sandbox_credential_projection_root_workload_refused``
        downgrade (where the resolved GID IS 0 — the executor will
        ``chgrp(0)`` per the dev-escape's "permissive passthrough"
        contract; the 0o644 file mode makes credentials world-
        readable anyway). ``None`` only on the
        ``sandbox_credential_projection_workload_gid_unknown``
        downgrade where the directive was absent or UID-only (no
        GID to resolve; the executor skips chgrp and relies on the
        0o644 world-readable mode for the dev-only workload).
      - ``file_mode``: ``0o440`` normal; ``0o644`` on either
        dev-escape downgrade path.
      - ``dir_mode``: ``0o750`` ALWAYS — spec §5.4 doesn't downgrade
        the dir mode under dev-escape.
      - ``dev_escape_downgrade_reason``: ``None`` on the normal path;
        ``"sandbox_credential_projection_workload_gid_unknown"`` or
        ``"sandbox_credential_projection_root_workload_refused"``
        on the corresponding downgrade — FULL wire-public
        ``SandboxRefusalReason`` strings (T19 round-2 reviewer fix
        +  round-3 doc-only patch; pinned by
        ``TestPreflightDowngradeReasonDriftDetector`` as a subset
        of ``SandboxRefusalReason``, same shape as T18's
        ``ProjectionRefusalReason`` ⊆ ``SandboxRefusalReason``).
        The T21 lifecycle integration emits a structured warning
        log AND a chain row payload keyed on this field per spec
        §180 ("structured warning log") — wire vocabulary
        directly, no translation layer.

    The shape lets the Phase 2 executor dispatch:

    .. code-block:: python

       result = verify_docker_credential_projection_preflight(...)
       if result.dev_escape_downgrade_reason is not None:
           emit_dev_escape_warning_log(result.dev_escape_downgrade_reason)
       # Apply result.file_mode + result.dir_mode + (chgrp if resolved_gid)
    """

    resolved_gid: int | None
    file_mode: int
    dir_mode: int
    dev_escape_downgrade_reason: _PreflightDowngradeReason | None


_DEV_ESCAPE_NOT_IN_DEV_PROFILE_MESSAGE: Final[str] = (
    "COGNIC_DEV_ALLOW_PERMISSIVE_CREDENTIAL_PROJECTION is only "
    "available in the ``dev`` runtime profile per spec §5.5 + §180. "
    "The dev escape downgrades root-workload + workload-gid-unknown "
    "refusals to permissive passthrough (0o644 + structured warning "
    "log) and is NEVER available in ``stage`` or ``prod`` profiles. "
    "T19 round-1 reviewer fix: the round-0 guard checked only "
    '``profile == "production"`` which let ``profile="prod"`` '
    "(the actual Settings vocabulary at ``core/config.py:32``) slip "
    "through. Operator + programmer misconfig — fail-loud per spec "
    "§180 fail-loud-regression contract."
)


def verify_docker_credential_projection_preflight(
    *,
    expected_workload_gid: int,
    image_user_directive: str | None,
    proc_mounts_content: str,
    dev_escape_enabled: bool = False,
    profile: RuntimeProfile = "prod",
) -> PreflightResult:
    """Run all 5 Docker-substrate preflight checks per spec §5.8 step 2.

    Locked refusal precedence (round-0 reviewer-approved):

      1. ``sandbox_credential_staging_path_not_tmpfs`` — ``/dev/shm``
         not backed by tmpfs (NOT dev-escape-downgradable).
      2. ``sandbox_credential_projection_image_user_directive_non_numeric``
         — image USER is a name form or mixed numeric/name (NOT
         downgradable).
      3. ``sandbox_credential_projection_workload_gid_unknown`` —
         image USER is absent OR UID-only single-numeric (dev-escape
         DOWNGRADABLE in development profile).
      4. ``sandbox_credential_projection_root_workload_refused`` —
         resolved numeric GID is 0 (dev-escape DOWNGRADABLE in
         development profile).
      5. ``sandbox_credential_projection_image_gid_manifest_mismatch``
         — resolved numeric GID != ``expected_workload_gid`` (NOT
         downgradable; manifest-vs-image disagreement is a signed-
         artifact integrity concern).

    First failing check in precedence raises
    ``SandboxLifecycleRefused`` with that closed-enum reason.

    **Profile guard:** ``dev_escape_enabled=True`` combined with any
    non-``dev`` profile (``stage`` or ``prod`` per the ``RuntimeProfile``
    Literal at ``core/config.py:32``) raises ``ValueError`` BEFORE any
    refusal check. The fail-loud-regression contract from spec §180 +
    user-locked rounds 0-1 guardrails: dev-escape misconfig is a
    programmer / operator error, NOT a credential decision; must
    never masquerade as ``sandbox_credential_projection_workload_gid_unknown``
    or ``sandbox_credential_projection_root_workload_refused``. T19
    round-1 reviewer fix: round-0 accepted loose ``profile: str`` +
    checked only ``profile == "production"`` which let
    ``profile="prod"`` (the actual Settings vocabulary) AND
    ``profile="stage"`` slip through; fix tightens to the typed
    Literal + ``profile != "dev"`` check.

    Returns a :class:`PreflightResult` on success — distinguishes
    normal-pass from each of the 2 dev-escape downgrade paths so the
    T19 Phase 2 Docker executor + the T21 lifecycle integration can
    dispatch on ``result.dev_escape_downgrade_reason``.
    """
    # Production guard — fail-loud BEFORE any refusal check.
    # T19 round-1 reviewer fix: profile is now ``RuntimeProfile``
    # (typed Literal ``dev | stage | prod`` from
    # ``core/config.py:32``). Round-0 accepted loose ``str`` +
    # checked only ``profile == "production"`` which let
    # ``profile="prod"`` (the actual Settings vocabulary) AND
    # ``profile="stage"`` slip through. The fix: dev-escape is
    # available ONLY in ``dev``; any non-``dev`` profile with
    # ``dev_escape_enabled=True`` raises ``ValueError``. Typed
    # Literal enforces vocabulary at the call site (mypy strict
    # rejects unknown strings); runtime check provides defence-
    # in-depth at the function boundary.
    if dev_escape_enabled and profile != "dev":
        raise ValueError(_DEV_ESCAPE_NOT_IN_DEV_PROFILE_MESSAGE)

    # Check 1 — staging substrate (precedence 1; never downgradable).
    if not _check_shm_is_tmpfs(proc_mounts_content):
        raise SandboxLifecycleRefused(
            "sandbox_credential_staging_path_not_tmpfs",
            detail=(
                "/dev/shm is not backed by tmpfs per /proc/mounts "
                "parse; credential projection requires a tmpfs-backed "
                "staging area to avoid disk persistence of credential "
                "values per spec §5.4 Docker executor"
            ),
        )

    # Check 2 — image USER directive form (precedence 2; never downgradable).
    parsed = _parse_image_user_directive(image_user_directive)
    if parsed.kind == "non_numeric":
        raise SandboxLifecycleRefused(
            "sandbox_credential_projection_image_user_directive_non_numeric",
            detail=(
                f"image USER directive {image_user_directive!r} is a "
                "name form or mixed numeric/name; only numeric "
                "``UID:GID`` (resolves the workload GID) or numeric "
                "``UID`` (yields "
                "sandbox_credential_projection_workload_gid_unknown) "
                "forms are accepted per spec §5.5"
            ),
        )

    # Check 3 — workload GID resolution (precedence 3; dev-escape downgradable).
    if parsed.kind == "absent" or parsed.kind == "uid_only":
        if dev_escape_enabled:
            # Dev-escape downgrade — passthrough with 0o644 +
            # downgrade-reason signal. The Phase 2 executor + T21
            # lifecycle integration dispatch on
            # ``dev_escape_downgrade_reason`` to (a) skip chgrp
            # (no GID to chgrp to) AND (b) emit a structured
            # warning log per spec §180.
            return PreflightResult(
                resolved_gid=None,
                file_mode=_FILE_MODE_DEV_ESCAPE_DOWNGRADE,
                dir_mode=_DIR_MODE_NORMAL,
                dev_escape_downgrade_reason="sandbox_credential_projection_workload_gid_unknown",
            )
        raise SandboxLifecycleRefused(
            "sandbox_credential_projection_workload_gid_unknown",
            detail=(
                f"cannot resolve workload GID from image USER directive "
                f"{image_user_directive!r}; need numeric ``UID:GID`` form "
                "per spec §5.5 (UID==GID convention is NOT assumed; "
                "set the dev-escape env flag in development profile "
                "if intentional)"
            ),
        )

    # At this point parsed.kind == "resolved" and gid_numeric is set.
    # Type-narrowing assertion mirrors the existing
    # ``compute_projection_plan`` pattern at sandbox/projection.py.
    assert parsed.gid_numeric is not None
    resolved_gid = parsed.gid_numeric

    # Check 4 — root workload refusal (precedence 4; dev-escape downgradable).
    if resolved_gid == 0:
        if dev_escape_enabled:
            # Dev-escape downgrade — passthrough with 0o644 + GID 0
            # + sandbox_credential_projection_root_workload_refused
            # downgrade-reason. The executor
            # WILL chgrp(0) here (the dev-escape's whole point is
            # letting a root-shelled dev image read the credentials);
            # the 0o644 file mode makes credentials world-readable
            # in the sandbox container anyway.
            return PreflightResult(
                resolved_gid=0,
                file_mode=_FILE_MODE_DEV_ESCAPE_DOWNGRADE,
                dir_mode=_DIR_MODE_NORMAL,
                dev_escape_downgrade_reason="sandbox_credential_projection_root_workload_refused",
            )
        raise SandboxLifecycleRefused(
            "sandbox_credential_projection_root_workload_refused",
            detail=(
                f"resolved workload GID is 0 (root) from image USER "
                f"directive {image_user_directive!r}; refused per spec "
                "§5.5 (set the dev-escape env flag in development "
                "profile if intentional)"
            ),
        )

    # Check 5 — manifest vs image GID match (precedence 5; never downgradable).
    if resolved_gid != expected_workload_gid:
        raise SandboxLifecycleRefused(
            "sandbox_credential_projection_image_gid_manifest_mismatch",
            detail=(
                f"image USER directive {image_user_directive!r} resolves "
                f"to GID {resolved_gid}, which does not match the "
                f"manifest's [runtime].expected_workload_gid="
                f"{expected_workload_gid}. The signed pack manifest's "
                "expected_workload_gid is the source of truth; rebuild "
                "the image with the correct USER or correct the "
                "manifest declaration"
            ),
        )

    # Normal happy path — all checks pass.
    return PreflightResult(
        resolved_gid=resolved_gid,
        file_mode=_FILE_MODE_NORMAL,
        dir_mode=_DIR_MODE_NORMAL,
        dev_escape_downgrade_reason=None,
    )


__all__ = [
    "PreflightResult",
    "verify_docker_credential_projection_preflight",
]
