"""Sprint 10.6 T19 Phase 2 — Docker projection executor
(per ADR-004 §25 + Sprint 10.6 spec §5.4 + §5.7 + plan §887-891).

The Docker-backend half of the credential-projection per-backend split
introduced at T18 (planner) + T19 Phase 1 (substrate preflight).

Pipeline contract (caller-driven; this module does NOT orchestrate):

  1. Caller invokes ``derive_session_opaque()`` once per sandbox session.
  2. For each credential in the pack:
       a. Caller invokes ``derive_credential_opaque()``.
       b. Caller runs T19 Phase 1 ``verify_docker_credential_projection_preflight``
          → ``PreflightResult`` (resolved workload GID + file_mode +
          dir_mode + optional dev-escape downgrade signal).
       c. Caller mints Vault lease + builds T18 ``ProjectionPlan``
          (byte-exact content + 0o440 entry modes + audit metadata).
       d. Caller invokes ``execute_projection_plan_docker(...)``.
       e. T21 wires this module's ``host_staging_dir`` output into the
          Docker bind-mount syscall on the runtime container
          (``host_staging_dir → /run/credentials/<logical_name> ro``).
  3. At sandbox teardown (LIFO unwind per spec §5.8 step 5):
     caller invokes ``cleanup_projection_dir(host_staging_dir)`` to
     remove the per-credential staging tree.

The opaque-at-every-level host path layout per spec §5.4 is the
wire-public-artifact contract:

  ``<base>/<session-opaque-16hex>/<credential-opaque-16hex>/<field>``

The host filesystem path NEVER contains ``logical_name`` / ``vault_path``
/ ``lease_id`` / ``tenant_id`` — semantic identifiers stay on
the audit chain row (which lives on encrypted+access-controlled
Postgres), not on the readable host filesystem. This eliminates the
"someone with shell access to the AgentOS host learns which Vault
paths a tenant uses" class of leak.

The container_mount_target IS semantic
(``/run/credentials/<logical_name>``) because the workload reads
credentials by logical name — semantic visibility ends at the
workload's namespace, NOT the host filesystem.

Critical-controls from birth (per spec §5.4); promotes to the
durable per-file CC coverage gate at Z1c.
"""

from __future__ import annotations

import dataclasses
import os
import re
import secrets
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from cognic_agentos.sandbox._preflight import PreflightResult
from cognic_agentos.sandbox.projection import ProjectionPlan

ChownImpl = Callable[..., None]
"""``os.chown``-shaped injection seam.

Production default is ``os.chown``; tests pass a recording lambda so
the suite runs without ``CAP_CHOWN`` (chgrp requires privilege the
test process doesn't have by default).
"""

ProjectionDowngradeReason = Literal[
    "sandbox_credential_projection_workload_gid_unknown",
    "sandbox_credential_projection_root_workload_refused",
]
"""Wire-equal-subset of the T16 ``SandboxRefusalReason`` Literal.

Owns the executor-result vocabulary for the dev-escape downgrade
signal threaded from T19 Phase 1's ``PreflightResult``. Declared
locally per [[feedback_drift_detector_test_only_no_runtime_import]]:
each production module declares its own Literal alias; the test-only
drift detector at ``tests/unit/sandbox/backends/test_docker_credential_projection.py``
asserts equality against ``_preflight._PreflightDowngradeReason`` so
the two stay lockstep without a runtime cross-module import.

The 2-value subset is locked at T19 Phase 1 plan-of-record + spec §180.
Drift either side is wire-protocol regression because T21 will consume
this result for the audit chain row's
``sandbox_credentials_projected_with_downgrade`` structured warning
log.
"""

_OPAQUE_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{16}$")
"""Exact 16-hex grammar for ``session_opaque`` / ``credential_opaque``.

Per spec §5.4: the opaque tokens MUST be 16-hex lowercase strings
(``secrets.token_hex(8)`` output). Defence-in-depth validation at
the executor entry catches programmer-error path-injection attempts
where a caller passes ``"../outside"`` or similar — the spec contract
is opaque-at-every-level + per-session-uniqueness, so any non-hex
token is a contract violation.
"""

_FIELD_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
"""Single-segment safe field-name grammar.

Mirrors the T14 manifest validator's ``credentials.*.fields[].name``
pattern at ``cli/validators/credentials.py``. Even though a
well-formed T18 ``ProjectionPlan`` cannot carry an unsafe
``relative_path`` (the planner reads from the manifest-validated
field set), the executor is a callable boundary that a future
caller could invoke with a hand-rolled ``ProjectionPlan``;
defence-in-depth at this seam rejects ``"../escaped"`` /
``"/etc/passwd"`` / ``"sub/dir/file"`` BEFORE the write syscall.
"""


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectionExecutorResult:
    """Result of one successful Docker projection.

    Carries every field the T21 sandbox lifecycle integration needs:

      - ``host_staging_dir`` — opaque host path; bind-mount source for
        the T21 ``Mount(target=container_mount_target, source=host_staging_dir,
        type='bind', read_only=True)`` syscall. Also the cleanup-helper
        input at sandbox teardown.
      - ``container_mount_target`` — semantic workload-facing path;
        bind-mount target inside the runtime container.
      - ``session_opaque`` / ``credential_opaque`` — opaque tokens for
        the spec §5.7 ``credentials_projected`` chain row payload
        (``backend_resource_name`` mirror).
      - Audit metadata (``logical_name`` / ``vault_path`` / ``tenant_id``
        / ``lease_id`` / ``projected_field_count`` / ``purpose_category``
        / ``purpose_description``) — wire-public per spec §5.7;
        consumed by T21 audit emit.
      - ``dev_escape_downgrade_reason`` — non-None ONLY on dev-escape
        downgrade paths; T21 emits a structured warning log
        (``sandbox_credentials_projected_with_downgrade``) when set.
    """

    logical_name: str
    vault_path: str
    tenant_id: str
    lease_id: str
    projected_field_count: int
    purpose_category: str
    purpose_description: str
    host_staging_dir: str
    container_mount_target: str
    session_opaque: str
    credential_opaque: str
    dev_escape_downgrade_reason: ProjectionDowngradeReason | None


def derive_session_opaque() -> str:
    """Return a fresh per-session 16-hex random opaque token.

    Per spec §5.4: ``secrets.token_hex(8)`` (8 bytes → 16 hex chars).
    Used as the per-session segment in the staging path; cryptographic
    randomness means two concurrent sessions practically never collide
    on the host filesystem.
    """
    return secrets.token_hex(8)


def derive_credential_opaque() -> str:
    """Return a fresh per-credential 16-hex random opaque token.

    Per spec §5.4: ``secrets.token_hex(8)`` (distinct call per
    credential). A multi-credential pack mints one session opaque +
    N credential opaques, nested as
    ``/<session>/<credential-1>/`` … ``/<session>/<credential-N>/``.
    """
    return secrets.token_hex(8)


def derive_staging_paths(
    *,
    base_staging_path: Path,
    session_opaque: str,
    credential_opaque: str,
) -> tuple[Path, Path]:
    """Compute ``(session_dir, credential_dir)`` from opaque tokens.

    Per spec §5.4: ``/<base>/<session-opaque>/<credential-opaque>``.
    Pure-functional — no I/O. The wire-public host-path-layout
    contract; pinned by the opaque-path drift detector.
    """
    session_dir = base_staging_path / session_opaque
    credential_dir = session_dir / credential_opaque
    return session_dir, credential_dir


def execute_projection_plan_docker(
    *,
    plan: ProjectionPlan,
    preflight: PreflightResult,
    session_opaque: str,
    credential_opaque: str,
    base_staging_path: Path,
    chown_impl: ChownImpl = os.chown,
) -> ProjectionExecutorResult:
    """Execute one credential's projection on the Docker backend.

    Side effects (in order):
      1. Validate ``session_opaque`` / ``credential_opaque`` against
         the 16-hex grammar + every ``entry.relative_path`` against
         the single-segment safe-name grammar; raise ``ValueError``
         on any mismatch (defence-in-depth path-escape guard).
      2. Defence-in-depth symlink guards (NEW post review round 2):
         ``base_staging_path`` MUST NOT be a symlink; the
         ``<base>/<session_opaque>`` slot MUST NOT pre-exist as a
         symlink; the ``<base>/<session>/<credential_opaque>`` slot
         MUST NOT pre-exist as a symlink. Each check fires BEFORE
         any ``mkdir`` so a symlink-escape attempt leaves no
         credential_dir trace on the symlink target.
      3. Create ``<base>/<session_opaque>/`` if missing (parents=True).
      4. Post-mkdir TOCTOU re-check on session_dir: refuse if it
         became a symlink between guard #2 and the mkdir.
      5. Create ``<base>/<session_opaque>/<credential_opaque>/`` with
         ``exist_ok=False`` — opaque-token collision raises
         ``FileExistsError`` so a programmer-error reuse (or a
         caller who forgot to call ``cleanup_projection_dir`` first)
         cannot silently merge new fields into a directory with
         stale credential bytes that would survive into the
         bind-mount.
      6. Defence-in-depth resolved-containment check: the resolved
         credential_dir MUST be under the resolved base_staging_path.
      7. Chmod credential_dir to ``preflight.dir_mode`` (0o750).
      8. For each ``ProjectionPlanEntry`` in ``plan.entries``:
         write ``content_bytes`` byte-exact + chmod to
         ``preflight.file_mode`` (0o440 normal; 0o644 dev-escape).
         Per-file resolved-containment check fires BEFORE every
         write_bytes call.
      9. If ``preflight.resolved_gid is not None``: chgrp the credential
         dir + every file to ``resolved_gid`` (UID unchanged via -1).
         When ``resolved_gid is None`` (workload_gid_unknown dev-escape
         downgrade), chgrp is SKIPPED entirely — the 0o644 file mode
         provides world-readability so the unknown-GID workload can
         still read.

    Returns ``ProjectionExecutorResult`` carrying the host path for the
    T21 bind-mount syscall + the full audit metadata for the T21
    ``credentials_projected`` chain row.

    Raises:
      * ``ValueError`` — programmer-error contract violation: bad
        opaque token grammar, bad relative_path grammar,
        symlink-shaped staging path component, or resolved-containment
        escape. NOT a wire-public credential-projection refusal; the
        matching T18 closed-enum refusal path is the T16
        ``SandboxRefusalReason`` Literal which the planner emits.
      * ``FileExistsError`` — opaque-token collision (credential
        staging dir already exists as a real directory). The caller
        is responsible for per-credential opaque token uniqueness;
        reuse semantics require an explicit ``cleanup_projection_dir``
        call first. (Symlink-shaped pre-existing entries surface as
        ``ValueError`` via the guards above, not ``FileExistsError``.)
    """
    if not _OPAQUE_TOKEN_PATTERN.fullmatch(session_opaque):
        raise ValueError(
            f"session_opaque must match {_OPAQUE_TOKEN_PATTERN.pattern!r}; got {session_opaque!r}"
        )
    if not _OPAQUE_TOKEN_PATTERN.fullmatch(credential_opaque):
        raise ValueError(
            f"credential_opaque must match {_OPAQUE_TOKEN_PATTERN.pattern!r}; "
            f"got {credential_opaque!r}"
        )
    for entry in plan.entries:
        if not _FIELD_NAME_PATTERN.fullmatch(entry.relative_path):
            raise ValueError(
                f"entry.relative_path must match "
                f"{_FIELD_NAME_PATTERN.pattern!r}; got {entry.relative_path!r}"
            )

    # Defence-in-depth symlink guard #1: NO component in the
    # ``base_staging_path`` chain — final OR any ancestor — may be a
    # symlink. The reviewer-reproduced bypass class was
    # ``base = tmp/link/cognic`` where ``tmp/link`` is the symlink but
    # the final ``cognic`` component is a real dir: the previous
    # final-component-only check passed, then mkdir/write walked
    # through the symlinked ancestor and landed credential bytes at
    # the symlink target. Walking the FULL chain (``base + parents``)
    # is the correct contract per spec §5.4: credential bytes MUST
    # land on the literal tmpfs path with NO symlink redirection
    # anywhere in the chain.
    #
    # Note re tests: pytest's ``tmp_path`` on macOS already returns
    # ``/private/var/folders/...`` (the resolved form); ``/var`` IS a
    # symlink to ``/private/var`` but pytest pre-resolves so the
    # walked chain contains NO symlink components in test
    # environments. Production deployments use ``/dev/shm/cognic`` on
    # a real Linux tmpfs which also has no symlinked ancestors.
    for _ancestor in (base_staging_path, *base_staging_path.parents):
        if _ancestor.is_symlink():
            raise ValueError(
                f"base_staging_path contains a symlink ancestor (refused "
                f"per spec §5.4 opaque-path / tmpfs-only contract): "
                f"symlink_ancestor={_ancestor!s}; "
                f"base_staging_path={base_staging_path!s}"
            )

    _session_dir, credential_dir = derive_staging_paths(
        base_staging_path=base_staging_path,
        session_opaque=session_opaque,
        credential_opaque=credential_opaque,
    )

    # Defence-in-depth symlink guard #2: a pre-existing
    # ``<base>/<session_opaque>`` symlink redirects every write made
    # under it to the symlink target. Detect + refuse BEFORE
    # ``mkdir(parents=True, exist_ok=True)`` succeeds on the symlink
    # (which silently uses the existing entry).
    if _session_dir.is_symlink():
        raise ValueError(
            f"session_dir is a pre-existing symlink (refused before "
            f"mkdir to avoid leaving a credential_dir trace at the "
            f"symlink target): {_session_dir!s}"
        )

    # Defence-in-depth symlink guard #3: same for credential_dir. The
    # opaque-token grammar + ``exist_ok=False`` P1 #2 fix already
    # protect against accidental collision, but a planted symlink at
    # ``<base>/<session>/<credential_opaque>`` would not be caught by
    # ``mkdir(exist_ok=False)`` — ``mkdir`` raises ``FileExistsError``
    # on symlinks too, but the wire-shape is different (the bytes
    # never land), so refuse explicitly with a symlink-specific
    # message + leave no on-disk trace.
    if credential_dir.is_symlink():
        raise ValueError(f"credential_dir is a pre-existing symlink: {credential_dir!s}")

    # Create parent (base + session) dirs idempotently; the workload
    # never traverses these on the host side (bind-mount runs in the
    # AgentOS process's namespace which has root), so default umask
    # is fine for the parents.
    credential_dir.parent.mkdir(parents=True, exist_ok=True)

    # Symlink guard #2b: the session_dir might have raced into
    # existence as a symlink between guard #2 above and the
    # mkdir(parents=True). Re-check post-mkdir to close the TOCTOU
    # window. If the dir is now a symlink, refuse — but we don't
    # remove it (the session_dir might already hold OTHER credentials'
    # legitimate state from earlier in the same session lifecycle).
    if _session_dir.is_symlink():
        raise ValueError(
            f"session_dir became a symlink after mkdir (TOCTOU race detected): {_session_dir!s}"
        )

    # Per-credential dir created fail-loud on collision so a
    # programmer-error reuse cannot inherit stale credential bytes.
    credential_dir.mkdir(exist_ok=False)
    credential_dir.chmod(preflight.dir_mode)

    # Defence-in-depth resolved-containment check now that the
    # credential_dir + parents exist on disk. Belt-and-suspenders
    # alongside the symlink guards above — the symlink guards already
    # close the symlink-escape class; this check catches any OTHER
    # path-resolution surprise (filesystem oddities, ../ smuggled
    # through future relaxations of the opaque-token grammar, etc).
    _resolved_base = base_staging_path.resolve(strict=False)
    _resolved_cred = credential_dir.resolve(strict=False)
    if not _resolved_cred.is_relative_to(_resolved_base):
        raise ValueError(
            f"credential_dir escapes base_staging_path: "
            f"resolved_credential_dir={_resolved_cred!s}; "
            f"resolved_base={_resolved_base!s}"
        )

    # Write each credential field byte-exact + chmod to the
    # preflight-decided mode. Resolved-containment check fires
    # BEFORE every write so a symlink that races into existence
    # between dir creation and field write cannot redirect bytes.
    for entry in plan.entries:
        file_path = credential_dir / entry.relative_path
        _resolved_file = file_path.resolve(strict=False)
        if not _resolved_file.is_relative_to(_resolved_cred):
            raise ValueError(
                f"entry.relative_path escapes credential_dir: "
                f"resolved_file={_resolved_file!s}; "
                f"resolved_credential_dir={_resolved_cred!s}"
            )
        file_path.write_bytes(entry.content_bytes)
        file_path.chmod(preflight.file_mode)

    # chgrp credential dir + each file to the resolved workload GID.
    # Skipped entirely when resolved_gid is None (the
    # workload_gid_unknown dev-escape downgrade).
    if preflight.resolved_gid is not None:
        chown_impl(str(credential_dir), -1, preflight.resolved_gid)
        for entry in plan.entries:
            chown_impl(
                str(credential_dir / entry.relative_path),
                -1,
                preflight.resolved_gid,
            )

    return ProjectionExecutorResult(
        logical_name=plan.logical_name,
        vault_path=plan.vault_path,
        tenant_id=plan.tenant_id,
        lease_id=plan.lease_id,
        projected_field_count=plan.projected_field_count,
        purpose_category=plan.purpose_category,
        purpose_description=plan.purpose_description,
        host_staging_dir=str(credential_dir),
        container_mount_target=f"/run/credentials/{plan.logical_name}",
        session_opaque=session_opaque,
        credential_opaque=credential_opaque,
        dev_escape_downgrade_reason=preflight.dev_escape_downgrade_reason,
    )


def cleanup_projection_dir(host_staging_dir: Path | str) -> None:
    """Remove the per-credential staging tree.

    Per spec §5.8 step 5 LIFO unwind: projection cleanup runs FIRST
    (before per-credential Vault revoke), in reverse mint order.

    Per spec §214 ``credentials_projection_cleanup_failed`` audit
    contract — the T21 lifecycle integration MUST emit a
    ``cleanup_failed`` chain row when a real cleanup failure occurs
    (partial-state credential bytes remaining on disk). This helper
    therefore distinguishes "already gone" from "failed to remove":

      * ``FileNotFoundError`` — idempotent contract; the dir is
        already gone, return silently. Covers both the "never
        existed" case and the double-cleanup case.
      * Any other exception from ``shutil.rmtree`` (PermissionError,
        OSError EBUSY, OSError ENOTEMPTY race, etc) — PROPAGATES
        to the T21 caller so the lifecycle integration can emit
        ``credentials_projection_cleanup_failed`` with ``partial_state``
        + ``error_class`` per spec §214.
    """
    path = Path(host_staging_dir)
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        # Idempotent: dir was already gone (or never existed).
        return
