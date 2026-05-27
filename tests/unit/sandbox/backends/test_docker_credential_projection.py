"""Sprint 10.6 T19 Phase 2 — Docker projection executor regressions
per ADR-004 §25 + Sprint 10.6 spec §5.4 + §5.7 + plan §887-891.

The executor is the per-backend half that CONSUMES:
  - T18's ``ProjectionPlan`` (planner output: byte-exact UTF-8 content
    + 0o440 mode + audit metadata)
  - T19 Phase 1's ``PreflightResult`` (substrate preflight: resolved
    workload GID + file_mode 0o440/0o644 + dir_mode 0o750 +
    optional dev-escape downgrade signal)

…and writes credential files to the opaque-at-every-level staging
path ``/dev/shm/cognic/<session-opaque>/<credential-opaque>/<field>``
+ chmod + chgrp + returns a ``ProjectionExecutorResult`` carrying the
host path (for the T21 bind-mount call) + container mount target
(``/run/credentials/<logical_name>``) + the full audit metadata for
the T21 ``credentials_projected`` chain row payload per spec §5.7.

**No Docker API calls. No bind-mount.** The bind-mount happens at T21
lifecycle integration (extends ``_start_sandbox_container`` to include
the volume mounts). Phase 2 owns ONLY the filesystem-side prep: dir
creation + file writes + chmod + chgrp + cleanup.

Test scope (locked at task start per user reviewer framing):
  * Pure-functional path derivation helpers — opaque-at-every-level
    drift detector pinned at the wire-public-artifact boundary.
  * Filesystem I/O against ``tmp_path`` (replaces ``/dev/shm/cognic``
    in tests; no privilege needed). Mocked ``os.chown`` for chgrp
    so CI runs without ``CAP_CHOWN``.
  * Happy-path normal projection: 0o440 file + 0o750 dir + chgrp to
    resolved GID + byte-exact UTF-8 content preservation through to
    disk.
  * Dev-escape downgrade variants: 0o644 file mode + GID handling
    matrix (None → skip chgrp; 0 → chgrp(0)).
  * Cleanup helper: idempotent removal; safe on missing dir.
  * Audit metadata return shape: all 9 spec §5.7 ``credentials_projected``
    payload fields present + carries the dev-escape downgrade signal
    for T21 audit emit.

Critical-controls from birth — owns the wire-public host-path layout
contract + the audit metadata wire-public dataclass; promotes to the
durable per-file CC coverage gate at Z1c per spec §5.4.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.sandbox._preflight import PreflightResult
from cognic_agentos.sandbox.backends._docker_executor import (
    cleanup_projection_dir,
    derive_credential_opaque,
    derive_session_opaque,
    derive_staging_paths,
    execute_projection_plan_docker,
)
from cognic_agentos.sandbox.projection import (
    ProjectionPlan,
    ProjectionPlanEntry,
)

# ---------------------------------------------------------------------------
# Test helpers — pure construction of fixtures (no I/O).
# ---------------------------------------------------------------------------


def _make_plan(
    *,
    logical_name: str = "db_main",
    vault_path: str = "database/creds/db-main",
    lease_id: str | None = None,
    fields: dict[str, bytes] | None = None,
) -> ProjectionPlan:
    """Construct a ProjectionPlan from synthetic field bytes."""
    if fields is None:
        fields = {"username": b"v-tok-uname", "password": b"p@ss"}
    if lease_id is None:
        lease_id = f"{vault_path}/lease-{secrets.token_hex(8)}"
    entries = tuple(
        ProjectionPlanEntry(relative_path=name, content_bytes=content, mode=0o440)
        for name, content in fields.items()
    )
    return ProjectionPlan(
        entries=entries,
        logical_name=logical_name,
        lease_id=lease_id,
        projected_field_count=len(entries),
        vault_path=vault_path,
        purpose_category="application_database_read",
        purpose_description="Read-only application database access.",
        tenant_id="tenant-phase2-test",
    )


def _normal_preflight(*, resolved_gid: int = 1000) -> PreflightResult:
    return PreflightResult(
        resolved_gid=resolved_gid,
        file_mode=0o440,
        dir_mode=0o750,
        dev_escape_downgrade_reason=None,
    )


def _dev_escape_workload_gid_unknown_preflight() -> PreflightResult:
    return PreflightResult(
        resolved_gid=None,
        file_mode=0o644,
        dir_mode=0o750,
        dev_escape_downgrade_reason=("sandbox_credential_projection_workload_gid_unknown"),
    )


def _dev_escape_root_workload_refused_preflight() -> PreflightResult:
    return PreflightResult(
        resolved_gid=0,
        file_mode=0o644,
        dir_mode=0o750,
        dev_escape_downgrade_reason=("sandbox_credential_projection_root_workload_refused"),
    )


# ---------------------------------------------------------------------------
# Opaque token derivation
# ---------------------------------------------------------------------------


class TestDeriveSessionOpaque:
    """Per spec §5.4: session-level opaque is 16-hex random.

    Used as the per-session segment in the staging path; uniqueness +
    format pinned here so two concurrent sessions never collide on
    the host filesystem.
    """

    def test_returns_16_hex_string(self) -> None:
        token = derive_session_opaque()
        assert len(token) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", token), f"non-hex: {token!r}"

    def test_two_calls_return_different_values(self) -> None:
        # Cryptographic random — collision probability ~ 2^-64 per pair;
        # not zero in theory but vanishingly small. A test failure here
        # is statistically a real bug, not bad luck.
        assert derive_session_opaque() != derive_session_opaque()


class TestDeriveCredentialOpaque:
    """Per spec §5.4: per-credential opaque is 16-hex random (distinct
    from the session opaque). One per credential per session — so a
    multi-credential pack gets distinct credential-opaque tokens
    nested under the SAME session opaque.
    """

    def test_returns_16_hex_string(self) -> None:
        token = derive_credential_opaque()
        assert len(token) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", token)

    def test_two_calls_return_different_values(self) -> None:
        assert derive_credential_opaque() != derive_credential_opaque()


# ---------------------------------------------------------------------------
# Staging-path derivation — pure-functional; opaque-path drift detector
# ---------------------------------------------------------------------------


class TestDeriveStagingPaths:
    """Pure-functional derivation of ``(session_dir, credential_dir)``
    from the opaque tokens + base staging path.

    Per spec §5.4: ``/dev/shm/cognic/<session-opaque>/<credential-opaque>``.
    Opaque-at-every-level — the host path NEVER contains
    ``logical_name`` / ``vault_path`` / ``lease_id`` / ``tenant_id``.
    """

    def test_returns_session_dir_and_credential_dir(self) -> None:
        session_opaque = "0123456789abcdef"
        credential_opaque = "fedcba9876543210"
        session_dir, credential_dir = derive_staging_paths(
            base_staging_path=Path("/dev/shm/cognic"),
            session_opaque=session_opaque,
            credential_opaque=credential_opaque,
        )
        assert session_dir == Path("/dev/shm/cognic/0123456789abcdef")
        assert credential_dir == Path("/dev/shm/cognic/0123456789abcdef/fedcba9876543210")

    def test_credential_dir_is_under_session_dir(self) -> None:
        session_dir, credential_dir = derive_staging_paths(
            base_staging_path=Path("/dev/shm/cognic"),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
        )
        assert credential_dir.parent == session_dir

    def test_tmp_path_base_works(self, tmp_path: Path) -> None:
        # Test base path override (used by tests + dev-only deployments).
        session_dir, _credential_dir = derive_staging_paths(
            base_staging_path=tmp_path,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
        )
        assert session_dir.parent == tmp_path


class TestOpaquePathDriftDetector:
    """Host staging path NEVER contains ``logical_name`` / ``vault_path``
    / ``lease_id`` / ``tenant_id``. The wire-public-artifact contract.
    Catches a class of "let's just stick the logical_name in the path"
    regressions that would leak semantic names onto the host fs +
    break the spec §5.4 opaque-at-every-level requirement.
    """

    def test_staging_path_does_not_contain_logical_name(self) -> None:
        # Distinctive logical name that would be easy to spot if it
        # leaked into the host path.
        _session_dir, credential_dir = derive_staging_paths(
            base_staging_path=Path("/dev/shm/cognic"),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
        )
        # Even passing the path through str() — no semantic
        # substring should appear.
        path_str = str(credential_dir)
        assert "db_main_with_distinctive_token" not in path_str
        assert "logical_name" not in path_str

    def test_staging_path_does_not_contain_vault_path(self) -> None:
        _session_dir, credential_dir = derive_staging_paths(
            base_staging_path=Path("/dev/shm/cognic"),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
        )
        path_str = str(credential_dir)
        # Vault paths look like "database/creds/db-main"; none of
        # those components should appear.
        assert "database" not in path_str
        assert "creds" not in path_str
        assert "vault" not in path_str

    def test_staging_path_is_only_opaque_tokens_and_cognic_base(self) -> None:
        # Whitelist test: the path MUST be exactly
        # /<base>/<16hex>/<16hex>; anything else is drift.
        session_opaque = secrets.token_hex(8)
        credential_opaque = secrets.token_hex(8)
        _session_dir, credential_dir = derive_staging_paths(
            base_staging_path=Path("/dev/shm/cognic"),
            session_opaque=session_opaque,
            credential_opaque=credential_opaque,
        )
        # 3 components: /, dev, shm, cognic, session_opaque, credential_opaque
        # On POSIX: Path("/dev/shm/cognic").parts == ('/', 'dev', 'shm', 'cognic')
        parts = credential_dir.parts
        # The final 2 parts MUST be the opaque tokens.
        assert parts[-1] == credential_opaque
        assert parts[-2] == session_opaque


# ---------------------------------------------------------------------------
# Execute the plan — happy path (normal mode 0o440 + chgrp)
# ---------------------------------------------------------------------------


class TestExecuteProjectionPlanDockerHappyPath:
    """Normal projection: 0o440 file mode + 0o750 dir mode + chgrp to
    resolved workload GID + byte-exact UTF-8 content preservation
    from the T18 ProjectionPlan to disk."""

    def test_files_are_written_to_credential_opaque_dir(self, tmp_path: Path) -> None:
        plan = _make_plan(
            fields={"username": b"alice", "password": b"hunter2"},
        )
        preflight = _normal_preflight(resolved_gid=1000)
        session_opaque = "a" * 16
        credential_opaque = "b" * 16

        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque=session_opaque,
            credential_opaque=credential_opaque,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        # Files are written under the credential-opaque dir.
        credential_dir = tmp_path / session_opaque / credential_opaque
        assert (credential_dir / "username").read_bytes() == b"alice"
        assert (credential_dir / "password").read_bytes() == b"hunter2"

    def test_files_have_mode_0o440_normal_path(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        preflight = _normal_preflight()
        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        for fname in ("username", "password"):
            file_mode = (credential_dir / fname).stat().st_mode & 0o777
            assert file_mode == 0o440, f"{fname} has mode {oct(file_mode)}; expected 0o440"

    def test_credential_dir_has_mode_0o750(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"x": b"y"})
        preflight = _normal_preflight()
        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        dir_mode = credential_dir.stat().st_mode & 0o777
        assert dir_mode == 0o750, f"dir has mode {oct(dir_mode)}; expected 0o750"

    def test_chgrp_called_on_credential_dir_and_files(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        preflight = _normal_preflight(resolved_gid=1234)
        chown_calls: list[tuple[str, int, int]] = []

        def _record_chown(path: str | bytes | os.PathLike[str], uid: int, gid: int) -> None:
            chown_calls.append((str(path), uid, gid))

        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=_record_chown,
        )
        # chgrp the credential dir + each file. uid=-1 means "don't change uid".
        chowned_paths = {p for p, _uid, _gid in chown_calls}
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        assert str(credential_dir) in chowned_paths
        assert str(credential_dir / "username") in chowned_paths
        assert str(credential_dir / "password") in chowned_paths
        # All chowns target GID 1234 + leave UID unchanged (-1).
        for _path, uid, gid in chown_calls:
            assert gid == 1234
            assert uid == -1


class TestExecuteProjectionPlanDockerByteExactness:
    """Per spec §5.3 byte-exactness contract: T18 planner produces
    byte-exact UTF-8 content; Phase 2 executor MUST round-trip those
    bytes to disk unchanged — no trailing newline, no BOM, no
    re-encoding.
    """

    def test_multibyte_unicode_content_round_trips(self, tmp_path: Path) -> None:
        # 3-byte UTF-8 ñ chars in the credential value.
        plan = _make_plan(fields={"password": "señorita-naïveté".encode()})
        preflight = _normal_preflight()
        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        assert (credential_dir / "password").read_bytes() == ("señorita-naïveté".encode())

    def test_no_trailing_newline_added(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"password": b"no-newline-please"})
        preflight = _normal_preflight()
        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        content = (credential_dir / "password").read_bytes()
        assert content == b"no-newline-please"
        assert not content.endswith(b"\n")

    def test_internal_whitespace_preserved(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"key": b"  internal   whitespace  "})
        preflight = _normal_preflight()
        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        assert (credential_dir / "key").read_bytes() == b"  internal   whitespace  "


# ---------------------------------------------------------------------------
# Dev-escape downgrade variants
# ---------------------------------------------------------------------------


class TestExecuteProjectionPlanDockerDevEscapeDowngrade:
    """Per spec §180 + T19 Phase 1's PreflightResult contract:

      - ``workload_gid_unknown`` downgrade: ``resolved_gid=None`` →
        executor SKIPS chgrp (no GID to chgrp to); file_mode 0o644.
      - ``root_workload_refused`` downgrade: ``resolved_gid=0`` →
        executor chgrp(0) (per dev-escape's "permissive passthrough"
        contract); file_mode 0o644.

    Both downgrade paths set file_mode=0o644 (world-readable) for
    the dev-only workload that couldn't pass the normal preflight.
    """

    def test_workload_gid_unknown_downgrade_uses_0o644_and_skips_chgrp(
        self, tmp_path: Path
    ) -> None:
        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        preflight = _dev_escape_workload_gid_unknown_preflight()
        chown_calls: list[Any] = []

        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *args: chown_calls.append(args),
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        # Files have 0o644 mode (downgrade).
        for fname in ("username", "password"):
            file_mode = (credential_dir / fname).stat().st_mode & 0o777
            assert file_mode == 0o644
        # NO chgrp calls (resolved_gid is None → skip chown entirely).
        assert chown_calls == []

    def test_root_workload_refused_downgrade_uses_0o644_and_chgrp_0(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        preflight = _dev_escape_root_workload_refused_preflight()
        chown_calls: list[tuple[Any, int, int]] = []

        def _record_chown(path: Any, uid: int, gid: int) -> None:
            chown_calls.append((path, uid, gid))

        execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=_record_chown,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        # Files have 0o644 mode (downgrade).
        for fname in ("username", "password"):
            file_mode = (credential_dir / fname).stat().st_mode & 0o777
            assert file_mode == 0o644
        # chgrp(0) called on credential dir + each file.
        chowned_gids = {gid for _path, _uid, gid in chown_calls}
        assert chowned_gids == {0}
        # uid always -1 (no uid change).
        for _path, uid, _gid in chown_calls:
            assert uid == -1


# ---------------------------------------------------------------------------
# Audit metadata return shape — spec §5.7 credentials_projected payload
# ---------------------------------------------------------------------------


class TestProjectionExecutorResultShape:
    """Per spec §5.7 ``credentials_projected`` payload: the
    ``ProjectionExecutorResult`` carries all 9 wire-public payload
    fields the T21 audit emit needs — ``logical_name`` / ``vault_path``
    / ``tenant_id`` / ``lease_id`` / ``projected_field_count`` /
    ``purpose_category`` / ``purpose_description`` / backend resource
    name (the opaque host_staging_dir) / ``sandbox_session_id`` (not
    yet — T21 wires that). Plus the ``dev_escape_downgrade_reason``
    for the dev-escape structured warning log.
    """

    def test_result_carries_all_audit_metadata(self, tmp_path: Path) -> None:
        plan = _make_plan(
            logical_name="db_main",
            vault_path="database/creds/db-main",
            lease_id="database/creds/db-main/lease-abc123",
            fields={"username": b"u", "password": b"p"},
        )
        preflight = _normal_preflight(resolved_gid=1000)
        session_opaque = "0123456789abcdef"
        credential_opaque = "fedcba9876543210"
        result = execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque=session_opaque,
            credential_opaque=credential_opaque,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        # Spec §5.7 audit metadata
        assert result.logical_name == "db_main"
        assert result.vault_path == "database/creds/db-main"
        assert result.tenant_id == "tenant-phase2-test"
        assert result.lease_id == "database/creds/db-main/lease-abc123"
        assert result.projected_field_count == 2
        assert result.purpose_category == "application_database_read"
        assert result.purpose_description == "Read-only application database access."
        # Backend resource name = the opaque host path
        assert result.host_staging_dir == str(tmp_path / session_opaque / credential_opaque)
        # Container mount target = the semantic workload-facing path
        assert result.container_mount_target == "/run/credentials/db_main"
        # No dev-escape downgrade on normal path.
        assert result.dev_escape_downgrade_reason is None
        # Opaque tokens carried for cleanup
        assert result.session_opaque == session_opaque
        assert result.credential_opaque == credential_opaque

    def test_result_carries_dev_escape_downgrade_reason(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"x": b"y"})
        preflight = _dev_escape_workload_gid_unknown_preflight()
        result = execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        assert (
            result.dev_escape_downgrade_reason
            == "sandbox_credential_projection_workload_gid_unknown"
        )

    def test_container_mount_target_is_semantic_logical_name(self, tmp_path: Path) -> None:
        # Per spec §5.4: container_mount_target is the
        # workload-FACING semantic path (logical_name-based), in
        # contrast to the OPAQUE host_staging_dir.
        plan = _make_plan(logical_name="aws_credentials")
        result = execute_projection_plan_docker(
            plan=plan,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        assert result.container_mount_target == "/run/credentials/aws_credentials"


# ---------------------------------------------------------------------------
# Cleanup helper
# ---------------------------------------------------------------------------


class TestCleanupProjectionDir:
    """Per spec §5.8 step 5 (LIFO unwind):
    "Projection cleanup FIRST (remove staging dir / delete K8s Secret)".

    Phase 2's cleanup helper removes the per-credential staging dir.
    Idempotent — calling on an already-cleaned (or never-created) dir
    is safe; no exception.
    """

    def test_removes_credential_dir_and_contents(self, tmp_path: Path) -> None:
        # First project, then cleanup.
        plan = _make_plan(fields={"x": b"y"})
        result = execute_projection_plan_docker(
            plan=plan,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = Path(result.host_staging_dir)
        assert credential_dir.exists()
        cleanup_projection_dir(credential_dir)
        assert not credential_dir.exists()

    def test_idempotent_on_missing_dir(self, tmp_path: Path) -> None:
        # Cleanup on a non-existent dir is safe.
        cleanup_projection_dir(tmp_path / "never-existed")
        # No exception raised.

    def test_idempotent_on_already_cleaned_dir(self, tmp_path: Path) -> None:
        # Cleanup twice on the same dir is safe.
        plan = _make_plan(fields={"x": b"y"})
        result = execute_projection_plan_docker(
            plan=plan,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = Path(result.host_staging_dir)
        cleanup_projection_dir(credential_dir)
        # Second call must not raise.
        cleanup_projection_dir(credential_dir)

    def test_propagates_non_missing_failures(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Per spec design.md:214 — real cleanup failures
        # (PermissionError / EBUSY / ENOTEMPTY race / etc) MUST
        # propagate so the T21 lifecycle integration can emit
        # ``credentials_projection_cleanup_failed`` with the
        # original ``error_class`` for the audit chain row.
        # Pre-fix `ignore_errors=True` swallowed every error and
        # made the audit emission unreachable.
        target_dir = tmp_path / "target"
        target_dir.mkdir()

        def _fake_rmtree(_path: Any) -> None:
            raise PermissionError("simulated permission denied")

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends._docker_executor.shutil.rmtree",
            _fake_rmtree,
        )

        with pytest.raises(PermissionError, match="simulated permission denied"):
            cleanup_projection_dir(target_dir)


# ---------------------------------------------------------------------------
# Defence-in-depth — path-escape guards (P1 review-round fix)
# ---------------------------------------------------------------------------


class TestPathEscapeGuards:
    """Reviewer found that pre-fix the executor wrote credential bytes
    outside ``base_staging_path`` when a caller passed
    ``session_opaque="../outside"`` / ``credential_opaque="../escaped"``
    / ``ProjectionPlanEntry(relative_path="../escaped")`` /
    absolute-path ``relative_path``. The T18 planner consumes the T14
    manifest-validated field set so it cannot ITSELF produce an unsafe
    entry; but the executor IS a callable boundary so defence-in-depth
    validates at this seam too.

    Bare-grammar ValueError raises live here — these are programmer-
    error contract violations, NOT a wire-public credential-projection
    refusal (those live on the T16 ``SandboxRefusalReason`` Literal
    which the planner emits).
    """

    def test_session_opaque_with_path_traversal_raises(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="session_opaque must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="../outside",
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_credential_opaque_with_path_traversal_raises(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="credential_opaque must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="../escaped",
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_session_opaque_with_non_hex_raises(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u"})
        # 16 chars but contains 'g' (not hex)
        with pytest.raises(ValueError, match="session_opaque must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="g" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_session_opaque_with_wrong_length_raises(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u"})
        # 15 hex chars (one short)
        with pytest.raises(ValueError, match="session_opaque must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 15,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_session_opaque_with_uppercase_raises(self, tmp_path: Path) -> None:
        plan = _make_plan(fields={"username": b"u"})
        # Uppercase hex — pattern is lowercase only
        with pytest.raises(ValueError, match="session_opaque must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="A" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_relative_path_with_dotdot_raises(self, tmp_path: Path) -> None:
        # Construct a plan with a malformed relative_path that bypasses
        # the planner's manifest validation. The executor MUST refuse
        # at the boundary — defence-in-depth.
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="../escaped", content_bytes=b"x", mode=0o440),
            ),
            logical_name="db_main",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"entry\.relative_path must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_relative_path_absolute_raises(self, tmp_path: Path) -> None:
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="/etc/passwd", content_bytes=b"x", mode=0o440),
            ),
            logical_name="db_main",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"entry\.relative_path must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_relative_path_with_slash_raises(self, tmp_path: Path) -> None:
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="sub/dir/file", content_bytes=b"x", mode=0o440),
            ),
            logical_name="db_main",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"entry\.relative_path must match"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_no_credential_dir_created_when_validation_raises(self, tmp_path: Path) -> None:
        # Bug-class regression: ValueError MUST fire BEFORE any
        # mkdir/write so a path-escape attempt leaves no trace on disk.
        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="../outside",  # malformed
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )
        # Even the parent path the malformed opaque WOULD have created
        # must not exist on disk.
        assert not (tmp_path / "..").resolve().joinpath("outside").exists()


# ---------------------------------------------------------------------------
# Stale-file collision guard (P1 review-round fix)
# ---------------------------------------------------------------------------


class TestStaleFileCollisionGuard:
    """Reviewer found that pre-fix ``credential_dir.mkdir(exist_ok=True)``
    silently merged a second projection's fields into a directory that
    still held the FIRST projection's bytes — so a credential like
    ``password`` written by the first session would survive into the
    second session's bind-mount alongside the second session's new
    ``api_key``. The fix is fail-loud collision: ``exist_ok=False``
    forces the caller (or test setup, or any future programmer-error
    reuse) to explicitly ``cleanup_projection_dir`` before reuse.
    """

    def test_second_call_with_same_opaque_tokens_raises_file_exists(self, tmp_path: Path) -> None:
        plan_a = _make_plan(fields={"password": b"first-secret"})
        execute_projection_plan_docker(
            plan=plan_a,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        # Second call with SAME opaque tokens must fail-loud rather
        # than silently merge.
        plan_b = _make_plan(fields={"api_key": b"second-secret"})
        with pytest.raises(FileExistsError):
            execute_projection_plan_docker(
                plan=plan_b,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_first_projection_state_survives_second_call_failure(self, tmp_path: Path) -> None:
        # Bug-class regression: pre-fix the stale ``password`` from
        # projection #1 was visible in the bind-mount after projection
        # #2's silent merge. Post-fix the second call MUST fail-loud
        # AND the first projection's state remains untouched.
        plan_a = _make_plan(fields={"password": b"first-secret"})
        execute_projection_plan_docker(
            plan=plan_a,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        # First-projection file is present.
        assert (credential_dir / "password").read_bytes() == b"first-secret"

        plan_b = _make_plan(fields={"api_key": b"second-secret"})
        with pytest.raises(FileExistsError):
            execute_projection_plan_docker(
                plan=plan_b,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )
        # First projection's bytes UNCHANGED; second projection's
        # bytes never written.
        assert (credential_dir / "password").read_bytes() == b"first-secret"
        assert not (credential_dir / "api_key").exists()

    def test_collision_after_cleanup_succeeds(self, tmp_path: Path) -> None:
        # The explicit cleanup-then-reproject path MUST work — the
        # collision guard only fires when the caller forgets cleanup.
        plan_a = _make_plan(fields={"password": b"first-secret"})
        execute_projection_plan_docker(
            plan=plan_a,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        credential_dir = tmp_path / ("a" * 16) / ("b" * 16)
        cleanup_projection_dir(credential_dir)

        plan_b = _make_plan(fields={"api_key": b"second-secret"})
        execute_projection_plan_docker(
            plan=plan_b,
            preflight=_normal_preflight(),
            session_opaque="a" * 16,
            credential_opaque="b" * 16,
            base_staging_path=tmp_path,
            chown_impl=lambda *_: None,
        )
        # Stale first-projection file is GONE; only the second
        # projection's bytes remain.
        assert not (credential_dir / "password").exists()
        assert (credential_dir / "api_key").read_bytes() == b"second-secret"


# ---------------------------------------------------------------------------
# Symlink-shape refusals (P1 review-round 2 fix)
# ---------------------------------------------------------------------------


class TestSymlinkRefusals:
    """Reviewer found that the resolved-containment check follows
    symlinks — when ``base_staging_path`` is a symlink, both the
    "resolved base" AND the "resolved credential_dir" walk through
    the symlink, so the containment check passes and credential
    bytes silently land at the symlink target (outside the literal
    staging base). Same for a pre-existing
    ``<base>/<session_opaque>`` symlink: the executor raised
    ``ValueError`` AFTER mkdir + chmod ran against the symlink target,
    so the path-escape attempt left a trace.

    Fix: ``is_symlink()`` guards on (base_staging_path,
    pre-existing session_dir, pre-existing credential_dir) BEFORE
    any mkdir/chmod/write, plus a post-mkdir TOCTOU re-check on
    session_dir to close the small race window between guard and
    mkdir.

    Spec §5.4 contract: credential bytes MUST land on the LITERAL
    tmpfs path (the deploying operator's chosen staging base), not
    a symlink target on regular disk that the T19 Phase 1 tmpfs
    preflight cannot verify.
    """

    def test_base_staging_path_as_symlink_raises(self, tmp_path: Path) -> None:
        # base_staging_path is a symlink (final component) → refuse.
        # This is a special case of the ancestor-symlink check below —
        # the first iteration of the walk covers the final component.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        base_symlink = tmp_path / "base-symlink"
        base_symlink.symlink_to(elsewhere)

        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="symlink ancestor"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=base_symlink,
                chown_impl=lambda *_: None,
            )

    def test_base_symlink_leaves_no_trace_at_target(self, tmp_path: Path) -> None:
        # Bug-class regression: pre-fix the resolved-containment check
        # passed when base was a symlink because both sides resolved
        # through it, so credential bytes landed at the symlink
        # target (`elsewhere`). Post-fix: refusal MUST fire BEFORE
        # any mkdir on `elsewhere`.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        base_symlink = tmp_path / "base-symlink"
        base_symlink.symlink_to(elsewhere)

        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        with pytest.raises(ValueError):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=base_symlink,
                chown_impl=lambda *_: None,
            )
        # NO credential_dir created at the symlink target.
        assert not (elsewhere / ("a" * 16)).exists()
        # NO credential bytes written at the symlink target.
        assert not (elsewhere / ("a" * 16) / ("b" * 16) / "username").exists()
        assert not (elsewhere / ("a" * 16) / ("b" * 16) / "password").exists()

    def test_session_dir_as_pre_existing_symlink_raises(self, tmp_path: Path) -> None:
        # <base>/<session_opaque> is a pre-existing symlink → refuse.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        session_opaque = "a" * 16
        session_symlink = tmp_path / session_opaque
        session_symlink.symlink_to(elsewhere)

        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="session_dir is a pre-existing symlink"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque=session_opaque,
                credential_opaque="b" * 16,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )

    def test_session_symlink_leaves_no_trace_at_target(self, tmp_path: Path) -> None:
        # Reviewer's specific repro: pre-fix the credential_dir was
        # created + chmodded at the symlink target BEFORE the
        # resolved-containment check fired. Post-fix: refusal MUST
        # fire BEFORE any mkdir on the credential_opaque slot at
        # the symlink target.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        session_opaque = "a" * 16
        credential_opaque = "b" * 16
        (tmp_path / session_opaque).symlink_to(elsewhere)

        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        with pytest.raises(ValueError):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque=session_opaque,
                credential_opaque=credential_opaque,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )
        # NO credential_dir created at the symlink target.
        assert not (elsewhere / credential_opaque).exists()
        # NO credential bytes leaked at the symlink target.
        assert not (elsewhere / credential_opaque / "username").exists()
        assert not (elsewhere / credential_opaque / "password").exists()

    def test_base_staging_path_with_symlink_parent_raises(self, tmp_path: Path) -> None:
        # Reviewer's round-4 P1: an ANCESTOR symlink in the base chain.
        # base_staging_path = tmp_path/link/cognic, where tmp_path/link →
        # tmp_path/outside. The final component (``cognic``) is a REAL
        # dir, but the parent (``link``) is the symlink. Pre-fix the
        # final-component-only ``is_symlink()`` check passed, mkdir +
        # write followed the symlinked parent, and credential bytes
        # landed at the resolved target (tmp_path/outside/cognic/...)
        # outside the literal base chain.
        outside = tmp_path / "outside"
        outside.mkdir()
        real_cognic = outside / "cognic"
        real_cognic.mkdir()
        link = tmp_path / "link"
        link.symlink_to(outside)
        base_with_symlink_parent = link / "cognic"

        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="symlink ancestor"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=base_with_symlink_parent,
                chown_impl=lambda *_: None,
            )

    def test_symlink_ancestor_leaves_no_trace_at_target(self, tmp_path: Path) -> None:
        # Bug-class regression for the ancestor-symlink no-trace
        # contract: pre-fix the credential_dir + chmod + file writes
        # landed at the symlink-resolved target. Post-fix: refusal
        # MUST fire BEFORE any mkdir on the resolved path.
        outside = tmp_path / "outside"
        outside.mkdir()
        real_cognic = outside / "cognic"
        real_cognic.mkdir()
        link = tmp_path / "link"
        link.symlink_to(outside)
        base_with_symlink_parent = link / "cognic"

        plan = _make_plan(fields={"username": b"u", "password": b"p"})
        with pytest.raises(ValueError):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=base_with_symlink_parent,
                chown_impl=lambda *_: None,
            )
        # NO session_dir created at the resolved target.
        assert not (real_cognic / ("a" * 16)).exists()
        # NO credential bytes leaked at the resolved target.
        assert not (real_cognic / ("a" * 16) / ("b" * 16) / "username").exists()
        assert not (real_cognic / ("a" * 16) / ("b" * 16) / "password").exists()

    def test_base_staging_path_with_symlink_grandparent_raises(self, tmp_path: Path) -> None:
        # Deeper-ancestor symlink (grandparent): tmp_path/link →
        # tmp_path/outside; base = tmp_path/link/middle/cognic; both
        # ``link`` (grandparent) is symlink and ``middle`` + ``cognic``
        # are real dirs underneath the symlink target. Walks need to
        # catch this too.
        outside = tmp_path / "outside"
        outside.mkdir()
        real_middle = outside / "middle"
        real_middle.mkdir()
        real_cognic = real_middle / "cognic"
        real_cognic.mkdir()
        link = tmp_path / "link"
        link.symlink_to(outside)
        base_with_symlink_grandparent = link / "middle" / "cognic"

        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="symlink ancestor"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque="a" * 16,
                credential_opaque="b" * 16,
                base_staging_path=base_with_symlink_grandparent,
                chown_impl=lambda *_: None,
            )

    def test_credential_dir_as_pre_existing_symlink_raises(self, tmp_path: Path) -> None:
        # <base>/<session>/<credential_opaque> is a pre-existing symlink
        # → refuse. (Defence-in-depth — the FileExistsError check from
        # P1 #2 fix would also fire here since the symlink IS an
        # existing entry, but the symlink-specific ValueError has a
        # clearer message + leaves no on-disk trace.)
        session_opaque = "a" * 16
        credential_opaque = "b" * 16
        (tmp_path / session_opaque).mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (tmp_path / session_opaque / credential_opaque).symlink_to(elsewhere)

        plan = _make_plan(fields={"username": b"u"})
        with pytest.raises(ValueError, match="credential_dir is a pre-existing symlink"):
            execute_projection_plan_docker(
                plan=plan,
                preflight=_normal_preflight(),
                session_opaque=session_opaque,
                credential_opaque=credential_opaque,
                base_staging_path=tmp_path,
                chown_impl=lambda *_: None,
            )
        # NO credential bytes written at the symlink target.
        assert not (elsewhere / "username").exists()


# ---------------------------------------------------------------------------
# Drift detector — ProjectionDowngradeReason == _PreflightDowngradeReason
# (P2 review-round 2 fix)
# ---------------------------------------------------------------------------


class TestProjectionDowngradeReasonDriftDetector:
    """Per [[feedback_drift_detector_test_only_no_runtime_import]]:
    two production modules each declare their own local Literal alias
    for the wire-public 2-value dev-escape downgrade vocabulary; the
    test-only drift detector here imports from BOTH modules + asserts
    set equality so the production-code architectural arrow stays
    intact (executor does not runtime-import the preflight's
    module-private alias).

    Round-2 P2 fix: pre-fix the ``ProjectionExecutorResult``'s
    ``dev_escape_downgrade_reason`` was typed ``str | None`` which
    widened the vocabulary back to "any string" at the T21
    audit-emit boundary; post-fix it's the locally-declared
    ``ProjectionDowngradeReason`` Literal pinned equal to the
    preflight Literal here.
    """

    def test_projection_downgrade_reason_equals_preflight_downgrade_reason(
        self,
    ) -> None:
        from typing import get_args

        from cognic_agentos.sandbox._preflight import _PreflightDowngradeReason
        from cognic_agentos.sandbox.backends._docker_executor import (
            ProjectionDowngradeReason,
        )

        assert frozenset(get_args(_PreflightDowngradeReason)) == frozenset(
            get_args(ProjectionDowngradeReason)
        )

    def test_projection_downgrade_reason_has_exactly_two_values(self) -> None:
        # Independent count guard for crisp drift diagnosis: if the
        # set count itself drifts (someone adds a third dev-escape
        # downgrade), the equality test above tells us values are
        # in lockstep but not what changed; this test independently
        # pins the cardinality so the failing test names the regression.
        from typing import get_args

        from cognic_agentos.sandbox.backends._docker_executor import (
            ProjectionDowngradeReason,
        )

        assert len(get_args(ProjectionDowngradeReason)) == 2

    def test_projection_downgrade_reason_is_wire_equal_subset_of_sandbox_refusal_reason(
        self,
    ) -> None:
        # The executor's downgrade vocabulary MUST be a strict subset
        # of the T16 SandboxRefusalReason Literal so T21 can map every
        # downgrade reason to a real wire-public closed-enum value
        # without translation.
        from typing import get_args

        from cognic_agentos.sandbox.backends._docker_executor import (
            ProjectionDowngradeReason,
        )
        from cognic_agentos.sandbox.protocol import SandboxRefusalReason

        downgrade_values = frozenset(get_args(ProjectionDowngradeReason))
        sandbox_values = frozenset(get_args(SandboxRefusalReason))
        assert downgrade_values <= sandbox_values, (
            f"ProjectionDowngradeReason values not in SandboxRefusalReason: "
            f"{downgrade_values - sandbox_values}"
        )
