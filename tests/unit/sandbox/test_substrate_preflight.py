"""Sprint 10.6 T19 Phase 1 — pure-functional Docker substrate preflight
regressions per ADR-004 §25 + Sprint 10.6 spec §5.5 + §5.8 step 2.

The preflight is the wire-public-artifact owner for the 5 Docker-owned
``SandboxRefusalReason`` credential-projection values (the
complement-half of the T18 wire-equal-subset doctrine — the planner
owns the OTHER 4 of 9 values):

  1. ``sandbox_credential_staging_path_not_tmpfs`` (precedence 1)
  2. ``sandbox_credential_projection_image_user_directive_non_numeric`` (precedence 2)
  3. ``sandbox_credential_projection_workload_gid_unknown`` (precedence 3; dev-escape downgradable)
  4. ``sandbox_credential_projection_root_workload_refused`` (precedence 4; dev-escape downgradable)
  5. ``sandbox_credential_projection_image_gid_manifest_mismatch`` (precedence 5)

Critical from birth — owns wire-public refusal raise sites; promotes
to the durable per-file CC coverage gate at Z1c per spec §5.4.

Test scope (locked at task start per user reviewer framing):
  * Pure-functional only — no Docker calls; no filesystem reads;
    parser tests use synthetic ``/proc/mounts`` content + synthetic
    image USER directive strings.
  * All 5 refusal values + locked precedence.
  * Dev-escape downgrade matrix (downgrades #3 + #4 only; never
    #1 + #2 + #5).
  * Production guard — ``dev_escape_enabled=True`` +
    ``profile="prod"`` raises ``ValueError`` (programmer /
    operator misconfig) BEFORE any refusal check; never masquerades
    as ``workload_gid_unknown`` or ``root_workload_refused``.
  * USER parser edge cases (numeric / name forms / mixed / empty /
    whitespace / multi-colon).
  * ``/proc/mounts`` tmpfs parser edge cases (partial matches must
    not fire; malformed lines skipped without crash).

User pin (T19 round-0): ``USER root`` → ``image_user_directive_non_numeric``
(NOT ``root_workload_refused``). ``root_workload_refused`` is ONLY for
resolved numeric GID 0 (e.g., ``USER 1000:0`` or ``USER 0:0``).
"""

from __future__ import annotations

import typing

import pytest

from cognic_agentos.sandbox._preflight import (
    _check_shm_is_tmpfs,
    _parse_image_user_directive,
    _PreflightDowngradeReason,
    verify_docker_credential_projection_preflight,
    verify_k8s_credential_projection_preflight,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused, SandboxRefusalReason

# ---------------------------------------------------------------------------
# Drift detector — _PreflightDowngradeReason ⊆ SandboxRefusalReason
# (wire-equal-subset doctrine, same spirit as T18's
# ProjectionRefusalReason ⊆ SandboxRefusalReason pin).
# ---------------------------------------------------------------------------


class TestPreflightDowngradeReasonDriftDetector:
    """Pin that ``_PreflightDowngradeReason`` is a wire-equal subset
    of ``SandboxRefusalReason`` — the 2 dev-escape-downgradable
    Docker-owned refusal values out of the 9 T16
    credential-projection values.

    T19 round-2 reviewer fix: round-1 used shortened strings
    (``"workload_gid_unknown"`` / ``"root_workload_refused"``) as
    the downgrade reason vocabulary, which would have forced T21
    audit emit to either translate to the wire vocabulary OR grow
    a mapping drift point between preflight + chain row payload.
    The fix: full wire-public ``SandboxRefusalReason`` strings
    directly on the result, validated by this subset drift detector
    (same shape as T18's
    ``TestProjectionRefusalReasonDriftDetector``).
    """

    _DOWNGRADABLE_OWNED: typing.ClassVar[frozenset[str]] = frozenset(
        {
            "sandbox_credential_projection_workload_gid_unknown",
            "sandbox_credential_projection_root_workload_refused",
        }
    )

    def test_count_is_exactly_two(self) -> None:
        """Dev-escape downgrades EXACTLY 2 of the 9 credential-
        projection refusal values per spec §180 + the round-0 locked
        dev-escape matrix. Drift here means a refusal moved between
        the downgradable + non-downgradable sets, breaking the
        spec §180 contract."""
        assert len(typing.get_args(_PreflightDowngradeReason)) == 2

    def test_canonical_two_values(self) -> None:
        """The 2 downgradable values are exactly workload_gid_unknown
        + root_workload_refused per spec §180."""
        actual = frozenset(typing.get_args(_PreflightDowngradeReason))
        assert actual == self._DOWNGRADABLE_OWNED

    def test_subset_of_sandbox_refusal_reason(self) -> None:
        """Every ``_PreflightDowngradeReason`` value MUST exist in
        the full ``SandboxRefusalReason`` Literal at
        ``protocol.py``. Same wire-equal-subset doctrine T18's
        ``ProjectionRefusalReason`` pioneered — the preflight does
        NOT mint its own refusal vocabulary; the downgrade reason
        carried on ``PreflightResult`` is the canonical wire
        string T21 audit emit puts on the chain row payload."""
        downgrade_values = set(typing.get_args(_PreflightDowngradeReason))
        sandbox_values = set(typing.get_args(SandboxRefusalReason))
        assert downgrade_values.issubset(sandbox_values), (
            f"_PreflightDowngradeReason values not in "
            f"SandboxRefusalReason: "
            f"{sorted(downgrade_values - sandbox_values)}"
        )


# ---------------------------------------------------------------------------
# USER directive parser — Docker image USER edge cases.
# ---------------------------------------------------------------------------


class TestParseImageUserDirective:
    """Pure parser for Docker image USER directive.

    Per user-locked pin 3 (T19 round-0):
      - Numeric ``UID:GID`` form → resolved with the GID
      - Numeric ``UID`` single-form → uid_only (caller emits
        ``workload_gid_unknown`` since GID can't be inferred from
        UID alone — UID==GID is a common convention but NOT
        guaranteed)
      - Name forms (``root`` / ``node`` / ``app``) → non_numeric
      - Mixed numeric/name (``node:1000`` / ``1000:node``) →
        non_numeric
      - Absent (``None`` / ``""`` / whitespace-only) → absent
    """

    def test_numeric_uid_gid_form_resolves(self) -> None:
        r = _parse_image_user_directive("1000:1000")
        assert r.kind == "resolved"
        assert r.gid_numeric == 1000

    def test_numeric_uid_gid_different_values_resolves(self) -> None:
        # Common pattern: UID = user-specific; GID = shared app group.
        r = _parse_image_user_directive("1000:2000")
        assert r.kind == "resolved"
        assert r.gid_numeric == 2000

    def test_uid_only_returns_uid_only_kind(self) -> None:
        """User pin 3: numeric single-part directive provides UID only;
        GID is ambiguous → caller emits workload_gid_unknown."""
        r = _parse_image_user_directive("1000")
        assert r.kind == "uid_only"
        assert r.gid_numeric is None

    def test_uid_only_zero_returns_uid_only(self) -> None:
        """Edge case: ``USER 0`` is UID=0 but GID unknown. NOT
        root_workload_refused (that's for resolved numeric GID 0)."""
        r = _parse_image_user_directive("0")
        assert r.kind == "uid_only"
        assert r.gid_numeric is None

    def test_uid_zero_gid_zero_resolves_to_zero(self) -> None:
        """``0:0`` resolves to numeric GID=0; caller emits
        root_workload_refused (per spec §5.5)."""
        r = _parse_image_user_directive("0:0")
        assert r.kind == "resolved"
        assert r.gid_numeric == 0

    def test_uid_nonzero_gid_zero_resolves_to_zero(self) -> None:
        """``1000:0`` is a valid form whose GID is root → still emits
        root_workload_refused (the workload's process would run with
        root group access despite a non-root UID)."""
        r = _parse_image_user_directive("1000:0")
        assert r.kind == "resolved"
        assert r.gid_numeric == 0

    def test_root_name_returns_non_numeric(self) -> None:
        """User pin 3 (explicit precedence guardrail): ``USER root`` is
        a NAME form → image_user_directive_non_numeric. NOT
        root_workload_refused (which is reserved for resolved
        numeric GID 0)."""
        r = _parse_image_user_directive("root")
        assert r.kind == "non_numeric"
        assert r.gid_numeric is None

    def test_node_name_returns_non_numeric(self) -> None:
        # Typical Node.js base image USER.
        r = _parse_image_user_directive("node")
        assert r.kind == "non_numeric"

    def test_app_name_returns_non_numeric(self) -> None:
        r = _parse_image_user_directive("app")
        assert r.kind == "non_numeric"

    def test_mixed_name_uid_returns_non_numeric(self) -> None:
        r = _parse_image_user_directive("node:1000")
        assert r.kind == "non_numeric"

    def test_mixed_uid_name_returns_non_numeric(self) -> None:
        r = _parse_image_user_directive("1000:node")
        assert r.kind == "non_numeric"

    def test_multiple_colons_returns_non_numeric(self) -> None:
        """``1000:1000:extra`` is not a valid USER form."""
        r = _parse_image_user_directive("1000:1000:extra")
        assert r.kind == "non_numeric"

    def test_empty_string_returns_absent(self) -> None:
        r = _parse_image_user_directive("")
        assert r.kind == "absent"
        assert r.gid_numeric is None

    def test_whitespace_only_returns_absent(self) -> None:
        r = _parse_image_user_directive("   ")
        assert r.kind == "absent"

    def test_none_returns_absent(self) -> None:
        r = _parse_image_user_directive(None)
        assert r.kind == "absent"

    def test_leading_trailing_whitespace_stripped(self) -> None:
        """Realistic input: ``image.Config.User`` may carry trailing
        whitespace from Dockerfile parsing; strip + treat the inner
        token as the directive."""
        r = _parse_image_user_directive("  1000:1000  ")
        assert r.kind == "resolved"
        assert r.gid_numeric == 1000

    def test_negative_uid_returns_non_numeric(self) -> None:
        """POSIX UIDs are non-negative; ``-1`` is syntactically a
        signed integer but semantically invalid as a USER directive.
        The parser routes it to non_numeric so the executor refuses
        the image rather than emitting a confusing GID-mismatch."""
        r = _parse_image_user_directive("-1:1000")
        assert r.kind == "non_numeric"

    def test_negative_gid_returns_non_numeric(self) -> None:
        r = _parse_image_user_directive("1000:-1")
        assert r.kind == "non_numeric"


# ---------------------------------------------------------------------------
# /proc/mounts tmpfs parser.
# ---------------------------------------------------------------------------


class TestCheckShmIsTmpfs:
    """Pure parser for ``/proc/mounts`` content; refuses partial path
    matches + handles malformed lines gracefully.

    ``/proc/mounts`` format per Linux kernel: each line is space-
    separated as ``<device> <mount_point> <fstype> <opts> <dump>
    <pass>``. The check looks for ``/dev/shm`` as the mount_point
    field with ``tmpfs`` as the fstype field.
    """

    def test_dev_shm_tmpfs_returns_true(self) -> None:
        content = "tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0\n"
        assert _check_shm_is_tmpfs(content) is True

    def test_dev_shm_ext4_returns_false(self) -> None:
        """If /dev/shm is mounted but NOT tmpfs (e.g., bind-mount over
        ext4), the refusal must fire — the credential projection
        contract requires tmpfs to avoid disk persistence."""
        content = "/dev/sda1 /dev/shm ext4 rw 0 0\n"
        assert _check_shm_is_tmpfs(content) is False

    def test_no_dev_shm_returns_false(self) -> None:
        """If /dev/shm doesn't appear in /proc/mounts at all (rare;
        usually means namespace isolation has hidden the mount)."""
        content = "/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n"
        assert _check_shm_is_tmpfs(content) is False

    def test_dev_shm2_partial_match_does_not_count(self) -> None:
        """Partial path match (``/dev/shm2`` etc.) MUST NOT match
        ``/dev/shm``. Catches a class of regex-based parsers that
        would accept ``startswith`` instead of exact-mount-point
        match."""
        content = "tmpfs /dev/shm2 tmpfs rw 0 0\n"
        assert _check_shm_is_tmpfs(content) is False

    def test_dev_shm_subpath_does_not_count(self) -> None:
        """``/dev/shm/foo`` is a path INSIDE /dev/shm, not /dev/shm
        itself. MUST NOT match."""
        content = "tmpfs /dev/shm/foo tmpfs rw 0 0\n"
        assert _check_shm_is_tmpfs(content) is False

    def test_dev_shm_appears_after_other_mounts(self) -> None:
        """The check works regardless of line position in the file."""
        content = (
            "/dev/sda1 / ext4 rw 0 0\n"
            "proc /proc proc rw 0 0\n"
            "tmpfs /dev/shm tmpfs rw 0 0\n"
            "tmpfs /tmp tmpfs rw 0 0\n"
        )
        assert _check_shm_is_tmpfs(content) is True

    def test_empty_input_returns_false(self) -> None:
        assert _check_shm_is_tmpfs("") is False

    def test_malformed_line_skipped(self) -> None:
        """Lines with fewer than 3 space-separated fields are
        skipped, not crashed-on. The parser must be resilient against
        whatever garbage might land in /proc/mounts (e.g., a future
        Linux kernel adds a header line)."""
        content = "garbage\nshort\ntmpfs /dev/shm tmpfs rw 0 0\n"
        assert _check_shm_is_tmpfs(content) is True


# ---------------------------------------------------------------------------
# Public orchestrator — happy path.
# ---------------------------------------------------------------------------


class TestVerifyDockerPreflightHappyPath:
    """Happy-path return shape per T19 round-1 reviewer fix:
    ``PreflightResult`` carries resolved_gid + file_mode 0o440 +
    dir_mode 0o750 + ``dev_escape_downgrade_reason is None`` —
    distinguishable from each of the 2 dev-escape downgrade paths
    so the Phase 2 executor + T21 lifecycle integration can dispatch.
    """

    def test_all_checks_pass_returns_normal_preflight_result(self) -> None:
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=1000,
            image_user_directive="1000:1000",
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
        )
        assert result.resolved_gid == 1000
        assert result.file_mode == 0o440
        assert result.dir_mode == 0o750
        assert result.dev_escape_downgrade_reason is None

    def test_gid_2000_with_manifest_2000_passes(self) -> None:
        # Different GID value (not just 1000) — confirms the check
        # compares against the manifest's expected_workload_gid, not
        # a hardcoded value.
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=2000,
            image_user_directive="1500:2000",
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
        )
        assert result.resolved_gid == 2000
        assert result.file_mode == 0o440
        assert result.dev_escape_downgrade_reason is None


# ---------------------------------------------------------------------------
# Refusal precedence — locked at T19 round-0 per spec §5.8 step 2.
# ---------------------------------------------------------------------------


class TestVerifyDockerPreflightRefusalPrecedence:
    """The 5 Docker-owned refusal values fire in this locked precedence:

      1. tmpfs (precedence 1)
      2. USER directive non-numeric (precedence 2)
      3. workload_gid_unknown (precedence 3)
      4. root_workload_refused (precedence 4)
      5. image_gid_manifest_mismatch (precedence 5)

    Pinned by the multi-failure tests below — if multiple checks
    would fail, the FIRST in precedence fires.
    """

    def test_tmpfs_failure_refuses_first_even_when_user_is_name_form(self) -> None:
        # Both check 1 + check 2 would fail; tmpfs fires first.
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="root",
                proc_mounts_content="/dev/sda1 /dev/shm ext4 rw 0 0\n",
            )
        assert exc_info.value.reason == "sandbox_credential_staging_path_not_tmpfs"

    def test_non_numeric_refuses_before_workload_gid_unknown(self) -> None:
        # Check 2 fires; check 3 (would also fire on absent) is
        # short-circuited.
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="root",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert (
            exc_info.value.reason
            == "sandbox_credential_projection_image_user_directive_non_numeric"
        )

    def test_user_root_name_yields_non_numeric_not_root_refused(self) -> None:
        """User pin 3 explicit guardrail: ``USER root`` (name form)
        MUST yield image_user_directive_non_numeric, NOT
        root_workload_refused. The latter is reserved for resolved
        numeric GID 0."""
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="root",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert (
            exc_info.value.reason
            == "sandbox_credential_projection_image_user_directive_non_numeric"
        )
        # Explicit pin per user pin 3: ``USER root`` must NOT yield
        # root_workload_refused. mypy statically proves this comparison
        # is non-overlapping (the LHS is narrowed to the non_numeric
        # Literal by the equality check above), but the assertion's
        # INTENT is documentation: if a future refactor returns
        # root_workload_refused for the name-form ``root`` directive,
        # the equality check above would change to root_workload_refused
        # + this assertion would fire as a true-positive regression.
        # ``# type: ignore[comparison-overlap]`` lets mypy accept the
        # tautology while preserving the documentation pin.
        assert exc_info.value.reason != "sandbox_credential_projection_root_workload_refused", (  # type: ignore[comparison-overlap]
            "user pin 3: USER root (name form) MUST yield "
            "image_user_directive_non_numeric, NOT root_workload_refused"
        )

    def test_workload_gid_unknown_refuses_when_directive_absent(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive=None,
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_workload_gid_unknown"

    def test_workload_gid_unknown_refuses_when_uid_only(self) -> None:
        """User pin 3: numeric single-part directive yields
        workload_gid_unknown (UID==GID is not assumed)."""
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="1000",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_workload_gid_unknown"

    def test_root_workload_refused_when_resolved_gid_zero(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="1000:0",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_root_workload_refused"

    def test_root_workload_refused_when_both_uid_gid_zero(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="0:0",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_root_workload_refused"

    def test_image_gid_manifest_mismatch(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="2000:2000",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_image_gid_manifest_mismatch"


# ---------------------------------------------------------------------------
# Dev-escape downgrade matrix — covers #3 + #4 only.
# ---------------------------------------------------------------------------


class TestVerifyDockerPreflightDevEscape:
    """Dev-escape env flag (``COGNIC_DEV_ALLOW_PERMISSIVE_CREDENTIAL_PROJECTION=1``)
    per spec §180 + user-locked pin 2 guardrail:

      - DOWNGRADES (no raise; permissive passthrough):
        * workload_gid_unknown (#3)
        * root_workload_refused (#4)

      - NEVER DOWNGRADES (raises despite dev-escape):
        * staging_path_not_tmpfs (#1) — substrate is foundational
        * image_user_directive_non_numeric (#2) — image misconfig is
          a bug; dev-escape doesn't fix it
        * image_gid_manifest_mismatch (#5) — manifest-vs-image
          disagreement is a signed-artifact integrity concern

    Docker-only; never K8s (T20 won't accept this kwarg); never
    production (TestVerifyDockerPreflightProductionGuard below).
    """

    # --- Downgradable: result distinguishes normal-pass from each downgrade ---

    def test_dev_escape_downgrades_absent_user_directive(self) -> None:
        """Absent directive + dev-escape → 0o644 file mode + downgrade
        reason ``workload_gid_unknown`` + ``resolved_gid is None`` (no
        GID to chgrp to; Phase 2 executor skips chgrp on this path).
        T19 round-1 reviewer fix: round-0 returned None, losing the
        distinction between normal-pass and downgrade-passthrough."""
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=1000,
            image_user_directive=None,
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            dev_escape_enabled=True,
            profile="dev",
        )
        assert result.file_mode == 0o644
        assert result.dir_mode == 0o750
        assert result.resolved_gid is None
        assert (
            result.dev_escape_downgrade_reason
            == "sandbox_credential_projection_workload_gid_unknown"
        )

    def test_dev_escape_downgrades_uid_only_workload_gid_unknown(self) -> None:
        """UID-only directive + dev-escape → same downgrade shape as
        absent (the planner cannot resolve a GID from UID-only)."""
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=1000,
            image_user_directive="1000",
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            dev_escape_enabled=True,
            profile="dev",
        )
        assert result.file_mode == 0o644
        assert result.dir_mode == 0o750
        assert result.resolved_gid is None
        assert (
            result.dev_escape_downgrade_reason
            == "sandbox_credential_projection_workload_gid_unknown"
        )

    def test_dev_escape_downgrades_root_workload_refused(self) -> None:
        """``USER 0:0`` + dev-escape → 0o644 + downgrade reason
        ``root_workload_refused`` + ``resolved_gid == 0`` (the executor
        WILL chgrp(0) — the dev-escape's whole point is letting a
        root-shelled dev image read the credentials)."""
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=1000,
            image_user_directive="0:0",
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            dev_escape_enabled=True,
            profile="dev",
        )
        assert result.file_mode == 0o644
        assert result.dir_mode == 0o750
        assert result.resolved_gid == 0
        assert (
            result.dev_escape_downgrade_reason
            == "sandbox_credential_projection_root_workload_refused"
        )

    def test_dev_escape_downgrades_root_workload_refused_uid_nonzero_gid_zero(self) -> None:
        """``USER 1000:0`` + dev-escape → same downgrade shape (the GID
        half is what matters for the chgrp + the root-refusal trigger;
        the UID half is incidental at this preflight)."""
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=1000,
            image_user_directive="1000:0",
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            dev_escape_enabled=True,
            profile="dev",
        )
        assert result.file_mode == 0o644
        assert result.resolved_gid == 0
        assert (
            result.dev_escape_downgrade_reason
            == "sandbox_credential_projection_root_workload_refused"
        )

    # --- NOT downgradable ---

    def test_dev_escape_does_not_downgrade_tmpfs(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="1000:1000",
                proc_mounts_content="/dev/sda1 /dev/shm ext4 rw 0 0\n",
                dev_escape_enabled=True,
                profile="dev",
            )
        assert exc_info.value.reason == "sandbox_credential_staging_path_not_tmpfs"

    def test_dev_escape_does_not_downgrade_non_numeric(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="root",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="dev",
            )
        assert (
            exc_info.value.reason
            == "sandbox_credential_projection_image_user_directive_non_numeric"
        )

    def test_dev_escape_does_not_downgrade_manifest_mismatch(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="2000:2000",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="dev",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_image_gid_manifest_mismatch"


# ---------------------------------------------------------------------------
# Profile guard — dev-escape ONLY available in dev profile.
# ---------------------------------------------------------------------------


class TestVerifyDockerPreflightProfileGuard:
    """Per spec §5.5 + user-locked pin 2 guardrail + T19 round-1
    reviewer fix:

    ``dev_escape_enabled=True`` is available ONLY in the ``dev``
    runtime profile. Any non-``dev`` profile (``stage`` or ``prod``
    per ``RuntimeProfile`` Literal at ``core/config.py:32``) with
    dev-escape raises ``ValueError`` (programmer / operator
    misconfig) BEFORE any refusal check. NEVER masquerades as
    ``workload_gid_unknown`` or ``root_workload_refused``.

    Round-0 bug: round-0 contract accepted loose ``profile: str``
    and checked only ``profile == "production"`` — which let
    ``profile="prod"`` (the actual Settings vocabulary) AND
    ``profile="stage"`` slip through with dev-escape enabled.
    Reviewer reproduced ``profile="prod"`` + ``dev_escape=True``
    + ``USER 0:0`` returning ``NO_RAISE``. The fix:
    ``profile: RuntimeProfile`` typed Literal at the signature
    (mypy strict rejects unknown strings) + runtime check
    ``profile != "dev"`` (defence-in-depth).

    The fail-loud regression is explicit per spec §180 last sentence:
    "Never available in K8s; never available in production profile
    (tested by explicit fail-loud regression)".
    """

    def test_dev_escape_in_production_raises_valueerror(self) -> None:
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="1000:1000",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="prod",
            )

    def test_production_guard_fires_before_tmpfs_check(self) -> None:
        """ValueError fires BEFORE any SandboxLifecycleRefused — even
        when BOTH conditions would fail (tmpfs failure + dev-escape-
        in-prod)."""
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="0:0",
                proc_mounts_content="/dev/sda1 /dev/shm ext4 rw 0 0\n",
                dev_escape_enabled=True,
                profile="prod",
            )

    def test_production_guard_does_not_masquerade_as_workload_gid_unknown(self) -> None:
        """Per user pin 2: production guard MUST NOT masquerade as
        workload_gid_unknown. If a caller naively passes dev_escape
        in production with absent USER directive (which would
        downgrade workload_gid_unknown in dev), the production
        guard MUST fire as ValueError — NOT a downgrade-to-passthrough."""
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive=None,  # would be workload_gid_unknown
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="prod",
            )

    def test_production_guard_does_not_masquerade_as_root_workload_refused(self) -> None:
        """Same pin: dev-escape-in-production MUST NOT masquerade as
        a passthrough for root_workload_refused."""
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="0:0",  # would be root_workload_refused
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="prod",
            )

    def test_production_profile_with_dev_escape_disabled_works_normally(self) -> None:
        """``profile="prod"`` with ``dev_escape_enabled=False``
        is the normal production mode — no ValueError raised; the
        refusal chain runs normally."""
        # No raise == happy path; assert on PreflightResult.
        result = verify_docker_credential_projection_preflight(
            expected_workload_gid=1000,
            image_user_directive="1000:1000",
            proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
            dev_escape_enabled=False,
            profile="prod",
        )
        assert result.dev_escape_downgrade_reason is None
        assert result.file_mode == 0o440

    def test_production_profile_with_dev_escape_disabled_still_refuses_normally(
        self,
    ) -> None:
        """Production profile + dev_escape disabled + invalid input
        → normal SandboxLifecycleRefused (not ValueError; not
        downgrade). Pins that the production-guard doesn't
        interfere with the normal refusal chain."""
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="0:0",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=False,
                profile="prod",
            )
        assert exc_info.value.reason == "sandbox_credential_projection_root_workload_refused"

    # T19 round-1 reviewer-found bug regressions: stage + prod profile
    # must BOTH fail-loud when dev-escape is enabled (NOT just "production"
    # as the round-0 string-typed guard checked). The reviewer's direct
    # repro: ``profile="prod"`` + dev_escape=True + USER 0:0 returned
    # NO_RAISE on round-0 code — these regressions pin the fix.

    def test_stage_profile_with_dev_escape_raises_valueerror(self) -> None:
        """``profile="stage"`` with dev_escape=True MUST raise
        ValueError. Staging is not dev; the dev-escape's permissive
        passthrough must not leak into staging environments per
        the user pin 2 guardrail."""
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="1000:1000",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="stage",
            )

    def test_stage_profile_dev_escape_does_not_masquerade_as_root_refused(self) -> None:
        """``profile="stage"`` + dev_escape=True + USER 0:0 — the
        ValueError MUST fire BEFORE the (would-be) root_workload_refused
        downgrade. Direct repro of the reviewer-found round-0 bug
        class for the stage profile axis."""
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="0:0",  # would be root_workload_refused
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="stage",
            )

    def test_prod_profile_dev_escape_uid_zero_gid_zero_repro_round0_bug(self) -> None:
        """Round-0 bug reproduction (direct quote from reviewer):
        "I reproduced ``profile=\"prod\"`` + dev escape + ``USER 0:0``
        returning ``NO_RAISE``." After the round-1 fix, this exact
        input MUST raise ValueError — NEVER silently downgrade as
        root_workload_refused passthrough."""
        with pytest.raises(ValueError, match="only available in the ``dev``"):
            verify_docker_credential_projection_preflight(
                expected_workload_gid=1000,
                image_user_directive="0:0",
                proc_mounts_content="tmpfs /dev/shm tmpfs rw 0 0\n",
                dev_escape_enabled=True,
                profile="prod",
            )


# ---------------------------------------------------------------------------
# Sprint 10.6 T20 Phase 1 — K8s preflight regressions
# ---------------------------------------------------------------------------


class TestVerifyK8sCredentialProjectionPreflight:
    """Per Sprint 10.6 spec §5.5 K8s row + user-locked T20 entry
    decisions:

      * K8s primary GID source = ``[runtime].expected_workload_gid``
        (pod-level ``fsGroup`` is INJECTED from this value; we don't
        probe an existing pod's fsGroup).
      * NO ``dev_escape_enabled`` / ``profile`` params — Docker-only
        dev escape MUST NOT leak into K8s. The type-system absence
        of these params makes the leak class unrepresentable.
      * 2 refusal paths only (no image USER → no
        ``image_user_directive_non_numeric``; no host tmpfs → no
        ``staging_path_not_tmpfs``; we inject fsGroup → no
        ``image_gid_manifest_mismatch``):
          - ``expected_workload_gid is None`` →
            ``sandbox_credential_projection_workload_gid_unknown``
          - ``expected_workload_gid == 0`` →
            ``sandbox_credential_projection_root_workload_refused``
      * Happy-path returns ``PreflightResult`` with
        ``resolved_gid=expected_workload_gid`` + ``file_mode=0o440``
        + ``dir_mode=0o750`` + ``dev_escape_downgrade_reason=None``
        (the file/dir modes are advisory data carried through to T21;
        K8s ACTUALLY enforces via the Secret's ``defaultMode`` set by
        the executor's pod-spec extension, NOT chmod).
    """

    def test_signature_has_no_dev_escape_enabled_param(self) -> None:
        # The signature itself is the load-bearing leak-prevention
        # contract — if a future refactor accidentally adds the param
        # back, this regression fires. Type-system level prevention
        # of the cross-backend leak class.
        import inspect

        sig = inspect.signature(verify_k8s_credential_projection_preflight)
        param_names = set(sig.parameters.keys())
        assert "dev_escape_enabled" not in param_names, (
            f"verify_k8s_credential_projection_preflight MUST NOT accept "
            f"dev_escape_enabled (Docker-only dev escape leak class); "
            f"got params: {param_names}"
        )

    def test_signature_has_no_profile_param(self) -> None:
        # Parallel guard: ``profile`` param is also Docker-specific
        # (it gates dev-escape against the "dev" runtime profile);
        # K8s preflight has neither.
        import inspect

        sig = inspect.signature(verify_k8s_credential_projection_preflight)
        param_names = set(sig.parameters.keys())
        assert "profile" not in param_names, (
            f"verify_k8s_credential_projection_preflight MUST NOT accept "
            f"profile (Docker-only param for dev-escape profile gating); "
            f"got params: {param_names}"
        )

    def test_signature_accepts_only_expected_workload_gid(self) -> None:
        # Lock the entire signature shape: exactly one
        # keyword-only param ``expected_workload_gid: int | None``.
        import inspect

        sig = inspect.signature(verify_k8s_credential_projection_preflight)
        param_names = list(sig.parameters.keys())
        assert param_names == ["expected_workload_gid"], (
            f"K8s preflight signature drift; expected exactly "
            f"['expected_workload_gid']; got: {param_names}"
        )
        # The param MUST be keyword-only (defence against positional
        # misuse from a future caller).
        param = sig.parameters["expected_workload_gid"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, (
            f"expected_workload_gid must be keyword-only; got {param.kind}"
        )

    def test_none_expected_workload_gid_raises_workload_gid_unknown(self) -> None:
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_k8s_credential_projection_preflight(expected_workload_gid=None)
        assert exc_info.value.reason == "sandbox_credential_projection_workload_gid_unknown"

    def test_zero_expected_workload_gid_raises_root_workload_refused(self) -> None:
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_k8s_credential_projection_preflight(expected_workload_gid=0)
        assert exc_info.value.reason == "sandbox_credential_projection_root_workload_refused"

    def test_valid_gid_returns_preflight_result_with_resolved_gid(self) -> None:
        result = verify_k8s_credential_projection_preflight(expected_workload_gid=1000)
        assert result.resolved_gid == 1000
        assert result.file_mode == 0o440
        assert result.dir_mode == 0o750
        assert result.dev_escape_downgrade_reason is None

    def test_valid_gid_high_value_returns_preflight_result(self) -> None:
        # OpenShift ``MustRunAsRange`` allocates GIDs in 1_000_000_000+.
        # T20 round-4 bumped the validator + preflight cap from 65535
        # to 4_294_967_295 specifically so this happy path is reachable.
        result = verify_k8s_credential_projection_preflight(expected_workload_gid=1000680000)
        assert result.resolved_gid == 1000680000
        assert result.dev_escape_downgrade_reason is None

    def test_gid_at_kernel_max_returns_preflight_result(self) -> None:
        # 2^32 - 1 = 4_294_967_295 — upper edge of the valid range.
        result = verify_k8s_credential_projection_preflight(expected_workload_gid=4_294_967_295)
        assert result.resolved_gid == 4_294_967_295

    def test_negative_gid_raises_value_error(self) -> None:
        # T20 round-4 reviewer P1: pre-fix any int (incl. -1) returned
        # a successful PreflightResult, contradicting the build-time
        # validator's [1, _GID_MAX] range. Defence-in-depth check.
        with pytest.raises(ValueError, match="outside the Linux 32-bit"):
            verify_k8s_credential_projection_preflight(expected_workload_gid=-1)

    def test_gid_above_kernel_max_raises_value_error(self) -> None:
        # 2^32 = 4_294_967_296 — one above the kernel cap.
        with pytest.raises(ValueError, match="outside the Linux 32-bit"):
            verify_k8s_credential_projection_preflight(expected_workload_gid=4_294_967_296)

    def test_out_of_range_gid_takes_value_error_path_not_refusal(self) -> None:
        # Out-of-range is programmer-error (validator should have
        # caught it at build time), NOT a wire-public credential
        # refusal. The exception type discriminates: SandboxLifecycleRefused
        # routes to the audit chain as a wire-public refusal value;
        # ValueError routes to the caller as a contract violation.
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        with pytest.raises(ValueError):
            verify_k8s_credential_projection_preflight(expected_workload_gid=-100)
        try:
            verify_k8s_credential_projection_preflight(expected_workload_gid=-100)
        except SandboxLifecycleRefused:  # pragma: no cover
            pytest.fail("Out-of-range GID must NOT raise SandboxLifecycleRefused")
        except ValueError:
            pass

    def test_true_raises_value_error_not_preflight_result(self) -> None:
        # T20 round-5 reviewer P1 — ``bool`` is a subclass of ``int``
        # in Python, so ``True == 1`` would slip through the int-typed
        # range check as a successful PreflightResult(resolved_gid=True).
        # The validator at credentials.py rejects bools explicitly;
        # the preflight MUST follow the same lockstep contract.
        with pytest.raises(ValueError, match=r"must be int.*not bool"):
            verify_k8s_credential_projection_preflight(expected_workload_gid=True)

    def test_false_raises_value_error_not_root_workload_refused(self) -> None:
        # T20 round-5 reviewer P1 — ``False == 0`` would pre-fix
        # have surfaced as a wire-public
        # ``sandbox_credential_projection_root_workload_refused``
        # refusal. That masquerades a Python-type bug as a real
        # credential refusal at the audit boundary. Fix: type check
        # fires BEFORE the ``== 0`` value check, so False → ValueError
        # (programmer error), NOT SandboxLifecycleRefused.
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        with pytest.raises(ValueError, match=r"must be int.*not bool"):
            verify_k8s_credential_projection_preflight(expected_workload_gid=False)
        # Negative regression: NOT raising the SandboxLifecycleRefused
        # path that the bare ``== 0`` check would have produced.
        try:
            verify_k8s_credential_projection_preflight(expected_workload_gid=False)
        except SandboxLifecycleRefused:  # pragma: no cover
            pytest.fail(
                "False MUST NOT surface as root_workload_refused — "
                "bool type guard must fire BEFORE the == 0 value check"
            )
        except ValueError:
            pass

    def test_bool_type_check_fires_before_value_checks(self) -> None:
        # Bug-class regression: pin that the type check has precedence
        # over the value-based refusal checks. If a future refactor
        # reorders so the ``== 0`` check runs first, False would slip
        # through as root_workload_refused again.
        #
        # AST-walk based regression: docstrings contain the literal
        # text ``expected_workload_gid == 0`` as a contract reference,
        # so a substring-match on the raw source would compare
        # docstring position to code position. AST gives us just the
        # function body statements, in source order.
        import ast
        import inspect

        from cognic_agentos.sandbox._preflight import (
            verify_k8s_credential_projection_preflight as _fn,
        )

        # ``inspect.getsource`` returns the function source with the
        # same indentation it has in the file; top-level functions
        # are at column 0 so ``ast.parse`` accepts it directly.
        tree = ast.parse(inspect.getsource(_fn))
        func = tree.body[0]
        assert isinstance(func, ast.FunctionDef), "expected a FunctionDef"

        # Find lineno of the first statement that contains an
        # ``isinstance(... bool ...)`` call vs the first statement
        # that contains a ``== 0`` comparison. AST stmt order = code
        # execution order.
        bool_lineno: int | None = None
        zero_lineno: int | None = None
        for stmt in func.body:
            for node in ast.walk(stmt):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "isinstance"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Name)
                    and node.args[1].id == "bool"
                    and bool_lineno is None
                ):
                    bool_lineno = stmt.lineno
                if (
                    isinstance(node, ast.Compare)
                    and isinstance(node.left, ast.Name)
                    and node.left.id == "expected_workload_gid"
                    and len(node.ops) == 1
                    and isinstance(node.ops[0], ast.Eq)
                    and len(node.comparators) == 1
                    and isinstance(node.comparators[0], ast.Constant)
                    and node.comparators[0].value == 0
                    and zero_lineno is None
                ):
                    zero_lineno = stmt.lineno

        assert bool_lineno is not None, "bool guard missing from function body"
        assert zero_lineno is not None, "== 0 check missing from function body"
        assert bool_lineno < zero_lineno, (
            f"bool guard MUST appear before == 0 check; "
            f"got bool at line {bool_lineno}, == 0 at line {zero_lineno}"
        )

    def test_dev_escape_env_var_has_no_effect_on_k8s(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # User-locked regression: even if the dev-escape env var is set
        # at process scope, the K8s preflight signature has no
        # acceptance point so the env var cannot trigger a downgrade.
        # Documents the cross-backend non-leak contract at runtime.
        monkeypatch.setenv("COGNIC_DEV_ALLOW_PERMISSIVE_CREDENTIAL_PROJECTION", "1")

        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        # workload_gid_unknown path — env var set, still refuses
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_k8s_credential_projection_preflight(expected_workload_gid=None)
        assert exc_info.value.reason == "sandbox_credential_projection_workload_gid_unknown"

        # root_workload_refused path — env var set, still refuses
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            verify_k8s_credential_projection_preflight(expected_workload_gid=0)
        assert exc_info.value.reason == "sandbox_credential_projection_root_workload_refused"

        # Happy path — env var set, no downgrade in result
        result = verify_k8s_credential_projection_preflight(expected_workload_gid=1000)
        assert result.dev_escape_downgrade_reason is None
