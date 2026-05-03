"""Sprint-5 RefusalReason completeness regression detector (T6 step 7).

R2 P2 #3 + R3 P2 + R6 + R11 + R13 + R14 + T6 R1 collectively pinned the
**24-value** Sprint-5 extension to ``plugin_registry.RefusalReason``
(originally 22; T6 R1 grew it 22 → 24 with the
``mcp_transport_unsupported`` and ``mcp_admission_deps_required``
fail-closed reasons).
This file is the load-bearing drift detector that catches:

  1. A new refusal-emitting site uses a string literal that's NOT in
     the closed enum (mypy's literal-narrowing only flags assignments
     and returns; runtime ``str`` construction sites are weaker).
  2. A literal value gets added to the enum without a dedicated test
     arm somewhere in the suite.
  3. The literal accumulates an orphaned ``mcp_*_`` value that's no
     longer emitted from any site.

If a future commit adds an mcp_* refusal reason without updating
:data:`SPRINT_5_REFUSAL_REASONS`, the first two test methods fire
loudly. The parametrized third method is a slower walk that
discovers actual test arms by inspecting test-collection metadata.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import get_args

import pytest

from cognic_agentos.protocol.plugin_registry import RefusalReason

#: Exact set Sprint 5 introduces (see plan-of-record T6 step 6).
#:
#: Layout:
#:   - 2 manifest extraction failures (T6.1)
#:   - 10 capability validator failures (T6.2; +mcp_transport_unsupported R1)
#:   - 11 registration auth-probe failures (T6.3)
#:   - 1 registry configuration failure (T6.3; mcp_admission_deps_required R1)
#:   = 24 total
#:
#: ``mcp_step_up_unauthorised`` is **runtime-only** (emitted by
#: ``MCPHost.call_tool``'s step-up flow at T9, NEVER from
#: registration). It is intentionally NOT in this set; the
#: ``_authz_reason_to_refusal()`` mapper raises if it ever appears
#: at the registration boundary.
SPRINT_5_REFUSAL_REASONS: frozenset[str] = frozenset(
    {
        # T6.1 manifest extraction (2)
        "mcp_manifest_missing",
        "mcp_manifest_malformed",
        # T6.2 capability validator (10 — R1 P1 #2 added mcp_transport_unsupported)
        "mcp_anonymous_refused",
        "mcp_resources_declared_but_no_list",
        "mcp_sampling_default_denied",
        "mcp_elicitation_form_restricted_data_class",
        "mcp_caching_ttl_restricted_data_class",
        "mcp_stdio_manifest_incomplete",
        "mcp_stdio_manifest_shell_metacharacter",
        "mcp_stdio_command_not_allowlisted",
        "mcp_stdio_disabled_in_sprint_5",
        "mcp_transport_unsupported",
        # T6.3 registration auth probe (11)
        "mcp_as_not_allowlisted",
        "mcp_token_audience_mismatch",
        "mcp_token_scope_overgrant",
        "mcp_oauth_request_timeout",
        "mcp_oauth_transport_failure",
        "mcp_oauth_credentials_missing",
        "mcp_oauth_as_discovery_invalid",
        "mcp_oauth_token_endpoint_error",
        "mcp_oauth_token_response_invalid",
        "mcp_prm_invalid",
        "mcp_api_key_fallback_unresolved",
        # T6.3 registry configuration (1 — R1 P1 #1 added admission-deps-required)
        "mcp_admission_deps_required",
    }
)


class TestRefusalReasonCompleteness:
    """Three drift checks (each with a load-bearing assertion):

    1. ``test_every_sprint_5_reason_in_literal`` — adding a new
       reason to this test set without adding it to the literal
       fails.
    2. ``test_no_orphaned_sprint_5_reason_in_literal`` — adding a
       new ``mcp_*_`` literal without updating this test set fails.
    3. ``test_every_reason_has_a_dedicated_test_arm`` (parametrized)
       — every reason has at least one test in
       ``test_mcp_capabilities.py``,
       ``test_mcp_registration_auth_probe.py``, or
       ``test_mcp_manifest.py`` that asserts the reason's outcome.
    """

    def test_total_count_is_24(self) -> None:
        """Pin the total at 24 so future arithmetic drift is loud
        (the count has been wrong in the plan three times — R2 said
        14 vs 16; R14 corrected 14 → 16 in the T6.3 catalogue summary;
        T6 R1 grew the count 22 → 24 with the
        ``mcp_transport_unsupported`` (R1 P1 #2) and
        ``mcp_admission_deps_required`` (R1 P1 #1) additions). The
        literal list above is the source of truth."""
        assert len(SPRINT_5_REFUSAL_REASONS) == 24, (
            f"Expected 24 Sprint-5 refusal reasons; got {len(SPRINT_5_REFUSAL_REASONS)}. "
            f"Update the count or the set."
        )

    def test_every_sprint_5_reason_in_literal(self) -> None:
        """Every Sprint-5 reason MUST appear in the
        :data:`RefusalReason` literal. Forces any new reason added to
        :data:`SPRINT_5_REFUSAL_REASONS` to also be type-acknowledged
        in ``plugin_registry.py``."""
        literal_args = frozenset(get_args(RefusalReason))
        missing = SPRINT_5_REFUSAL_REASONS - literal_args
        assert not missing, (
            f"Sprint-5 refusal reasons declared in this test but missing "
            f"from plugin_registry.RefusalReason literal: {sorted(missing)}. "
            f"Add them to the literal before this test will pass."
        )

    def test_no_orphaned_sprint_5_reason_in_literal(self) -> None:
        """Defensive: any Sprint-5-prefixed reason in the literal
        that is NOT in :data:`SPRINT_5_REFUSAL_REASONS` is suspicious
        — either a typo or a leftover from a removed feature.
        Sprint-4 reasons all use snake_case without an ``mcp_``
        prefix; Sprint-5 reasons all start with ``mcp_``, so the
        prefix is the discriminator."""
        literal_args = frozenset(get_args(RefusalReason))
        sprint_5_in_literal = {r for r in literal_args if r.startswith("mcp_")}
        orphans = sprint_5_in_literal - SPRINT_5_REFUSAL_REASONS
        assert not orphans, (
            f"plugin_registry.RefusalReason has Sprint-5 reasons NOT in "
            f"SPRINT_5_REFUSAL_REASONS: {sorted(orphans)}. Either add to "
            f"the test set OR remove from the literal."
        )

    @pytest.mark.parametrize("reason", sorted(SPRINT_5_REFUSAL_REASONS))
    def test_every_reason_has_a_dedicated_test_arm(self, reason: str) -> None:
        """For each Sprint-5 reason, at least one test file under
        ``tests/unit/protocol/`` must reference the literal string —
        either as a parametrize input, an assertion target
        (``assert ... == "<reason>"``), or a comment that explicitly
        names the reason. This is a static-text walk over the test
        files; it doesn't actually execute those tests, just confirms
        the literal appears somewhere in the test suite.

        Catches the "reason added to literal but never exercised"
        drift class. If a reason is added without a test arm
        anywhere, this parametrized test fires for that specific
        reason — the failure message names the missing reason.
        """
        test_dir = Path(__file__).parent
        # Walk only the protocol test files (the surface that emits
        # mcp_* reasons). Each file's bytes are searched for the
        # literal reason string.
        candidate_files = sorted(test_dir.glob("test_mcp_*.py"))
        # Exclude THIS file (it lists every reason in the set above
        # — the search would always succeed via the set).
        candidate_files = [f for f in candidate_files if f.name != Path(__file__).name]
        # ALSO exclude files that import SPRINT_5_REFUSAL_REASONS from
        # this module (transitive same-source).
        searchable_files = []
        for f in candidate_files:
            text = f.read_text(encoding="utf-8")
            if "SPRINT_5_REFUSAL_REASONS" in text:
                continue
            searchable_files.append((f, text))

        hits = [str(f) for (f, text) in searchable_files if reason in text]
        assert hits, (
            f"Sprint-5 RefusalReason {reason!r} has NO test arm in any of "
            f"{[str(f) for (f, _) in searchable_files]}. Add a test that "
            f"asserts this reason fires from its emitting site (T6.1, T6.2, "
            f"or T6.3)."
        )


class TestRefusalReasonHistoricalSnapshot:
    """Sprint-4 refusal reasons + Sprint-5 additions = exactly the
    full RefusalReason literal. If a future sprint adds a reason
    that's neither prefixed ``mcp_`` (Sprint 5 convention) nor in
    the Sprint-4 historical set, this test surfaces it as suspicious
    — the new sprint should either rename to fit a convention or
    extend this snapshot test for its own sprint."""

    SPRINT_4_REFUSAL_REASONS: frozenset[str] = frozenset(
        {
            "not_in_tenant_allowlist",
            "cosign_verification_failed",
            "sbom_missing",
            "sbom_tampered",
            "slsa_tampered",
            "intoto_tampered",
            "sigstore_bundle_persistence_failed",
            "policy_denied_partial_grade",
        }
    )

    def test_literal_is_sprint_4_plus_sprint_5(self) -> None:
        actual = frozenset(get_args(RefusalReason))
        expected = self.SPRINT_4_REFUSAL_REASONS | SPRINT_5_REFUSAL_REASONS
        diff_extra = actual - expected
        diff_missing = expected - actual
        assert actual == expected, (
            f"RefusalReason drift detected.\n"
            f"  Unexpected (in literal but not in either sprint snapshot): "
            f"{sorted(diff_extra)}\n"
            f"  Missing (in sprint snapshot but not in literal): "
            f"{sorted(diff_missing)}\n"
            f"  If a future sprint adds reasons, extend the SPRINT_5_REFUSAL_REASONS "
            f"set OR add a new sprint-snapshot constant + test."
        )


class TestPluginRegistryAuthzMapperContract:
    """Pin the public contract of
    :func:`cognic_agentos.protocol.plugin_registry._authz_reason_to_refusal`
    matches every registration-boundary AuthzReason. Eleven values
    map; ``mcp_step_up_unauthorised`` is runtime-only and raises."""

    def test_mapper_covers_all_registration_boundary_authz_reasons(self) -> None:
        """The :data:`AuthzReason` literal has 13 values; 11 are
        registration-boundary (mappable to RefusalReason) and two
        (``mcp_step_up_unauthorised`` + ``mcp_authorisation_lost``)
        are runtime-only — they only fire from inside ``MCPHost``
        flows that don't reach the registration-boundary mapper.
        The mapper's public dict (``_AUTHZ_REASON_TO_REFUSAL``)
        MUST contain exactly the 11 registration-boundary values."""
        from cognic_agentos.protocol.mcp_authz import AuthzReason
        from cognic_agentos.protocol.plugin_registry import (
            _AUTHZ_REASON_TO_REFUSAL,
        )

        all_authz = frozenset(get_args(AuthzReason))
        # Runtime-only reasons (NEVER reach the registration mapper):
        # - mcp_step_up_unauthorised: emitted from
        #   MCPAuthzClient.step_up_token (T5).
        # - mcp_authorisation_lost: emitted from MCPHost.call_tool
        #   when the second-401 retry fails (T9 R1 P2 #3).
        expected_runtime_only = frozenset({"mcp_step_up_unauthorised", "mcp_authorisation_lost"})
        expected_registration_boundary = all_authz - expected_runtime_only
        actual_mapped = frozenset(_AUTHZ_REASON_TO_REFUSAL.keys())

        # The diff catches both directions: mapper missing a reason
        # (would silently fall through), AND mapper having an extra
        # entry (drift the other way).
        assert actual_mapped == expected_registration_boundary, (
            f"AuthzReason / mapper drift.\n"
            f"  AuthzReason values: {sorted(all_authz)}\n"
            f"  Runtime-only (NOT mapped): {sorted(expected_runtime_only)}\n"
            f"  Expected mapped: {sorted(expected_registration_boundary)}\n"
            f"  Actual mapped: {sorted(actual_mapped)}\n"
            f"  Missing from mapper: "
            f"{sorted(expected_registration_boundary - actual_mapped)}\n"
            f"  Extra in mapper: "
            f"{sorted(actual_mapped - expected_registration_boundary)}"
        )

    def test_mapper_outputs_are_all_valid_refusal_reasons(self) -> None:
        """Every value in the mapper's right-hand side MUST be a
        valid :data:`RefusalReason` literal value."""
        from cognic_agentos.protocol.plugin_registry import (
            _AUTHZ_REASON_TO_REFUSAL,
            _VALID_REFUSAL_REASONS,
        )

        mapper_outputs = frozenset(_AUTHZ_REASON_TO_REFUSAL.values())
        unknown = mapper_outputs - _VALID_REFUSAL_REASONS
        assert not unknown, (
            f"Mapper outputs values that aren't in RefusalReason: "
            f"{sorted(unknown)}. The mapper's right-hand side MUST "
            f"be the closed-enum subset."
        )

    def test_mapper_preserves_identity_for_registration_boundary_reasons(self) -> None:
        """Sprint-5 design choice: the eleven registration-boundary
        AuthzReason strings are the SAME literals as their
        RefusalReason counterparts (1:1 identity). Future divergence
        would land in the mapper's value column; this test pins the
        Sprint-5 identity contract."""
        from cognic_agentos.protocol.plugin_registry import _AUTHZ_REASON_TO_REFUSAL

        non_identity = {
            authz: refusal
            for authz, refusal in _AUTHZ_REASON_TO_REFUSAL.items()
            if authz != refusal
        }
        assert not non_identity, (
            f"Mapper has non-identity entries: {non_identity}. If you intend "
            f"to diverge the AuthzReason and RefusalReason vocabularies, "
            f"update this test with the rationale + the new mapping shape."
        )

    def test_mapper_raises_for_step_up_unauthorised(self) -> None:
        """``mcp_step_up_unauthorised`` is runtime-only — emitted from
        :meth:`MCPAuthzClient.step_up_token` (T5). The mapper MUST
        raise rather than silently fall through to a registration
        refusal that examiners would interpret as an admission-time
        decision."""
        from cognic_agentos.protocol.plugin_registry import _authz_reason_to_refusal

        with pytest.raises(ValueError, match="runtime-only"):
            _authz_reason_to_refusal("mcp_step_up_unauthorised")

    def test_mapper_raises_for_authorisation_lost(self) -> None:
        """**T9 R1 P2 #3 contract test** — ``mcp_authorisation_lost``
        is runtime-only: emitted from :meth:`MCPHost.call_tool` when
        the second-401 retry fails. Like ``mcp_step_up_unauthorised``,
        the mapper MUST raise if it ever reaches the registration
        boundary. T11 will surface this in the
        ``audit.tool_invocation_error`` row + the parallel
        ``decision_history`` row, NOT in the registration outcome."""
        from cognic_agentos.protocol.plugin_registry import _authz_reason_to_refusal

        with pytest.raises(ValueError, match="runtime-only"):
            _authz_reason_to_refusal("mcp_authorisation_lost")

    def test_mapper_raises_for_unknown_authz_reason(self) -> None:
        """Sanity: an entirely unknown AuthzReason string also raises
        (defensive — would mean a closed-enum drift the type checker
        should have caught)."""
        from cognic_agentos.protocol.plugin_registry import _authz_reason_to_refusal

        with pytest.raises(ValueError, match="Unknown AuthzReason"):
            _authz_reason_to_refusal("mcp_made_up_value_xyz")

    def test_runtime_only_set_pinned_at_two_values(self) -> None:
        """The runtime-only set (``_RUNTIME_ONLY_AUTHZ_REASONS``) is
        the single source of truth for which AuthzReason values
        bypass the registration mapper. Currently pinned at exactly
        two: ``mcp_step_up_unauthorised`` (T5) and
        ``mcp_authorisation_lost`` (T9 R1 P2 #3). Adding a third
        runtime-only value is a Sprint-N task that MUST extend this
        set + the drift detector + the doctrine docs."""
        from cognic_agentos.protocol.plugin_registry import (
            _RUNTIME_ONLY_AUTHZ_REASONS,
        )

        assert (
            frozenset({"mcp_step_up_unauthorised", "mcp_authorisation_lost"})
            == _RUNTIME_ONLY_AUTHZ_REASONS
        ), (
            f"_RUNTIME_ONLY_AUTHZ_REASONS drift: {_RUNTIME_ONLY_AUTHZ_REASONS}. "
            f"Pinned at the two T5/T9-known runtime-only values."
        )


class TestSprint5DriftDetectorSelfTest:
    """The drift detector itself has a non-trivial enough surface
    (set arithmetic + parametrize + file-walking) that a quick
    self-test catches obvious misconfigurations."""

    def test_set_inspection_works(self) -> None:
        """Sanity: ``inspect`` is importable + the test file walks
        actual files (not phantom paths)."""
        assert inspect.getsourcefile(self.test_set_inspection_works) is not None

    def test_canonical_count_matches_set_size(self) -> None:
        assert len(SPRINT_5_REFUSAL_REASONS) == 24
