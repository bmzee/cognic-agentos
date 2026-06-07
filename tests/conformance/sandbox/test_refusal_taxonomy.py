"""Sprint 8B T8B-a — cross-backend refusal-taxonomy conformance.

Pins that the ``TRIGGERS_BY_REASON`` dispatch at
``tests/conformance/sandbox/refusal_dispatch.py`` REGISTERS a trigger
factory for EVERY value in the wire-public ``SandboxRefusalReason``
Literal at ``src/cognic_agentos/sandbox/protocol.py:34-50``.

Per the user-locked tightening edit A (Sprint 8B preflight,
2026-05-17): T8B-a delivers REGISTRATION coverage of the closed-enum
vocabulary, NOT BEHAVIORAL equivalence between backends. Per-value
behavior coverage lives in:

* ``tests/unit/sandbox/test_admission_pipeline.py`` — 13/15 admission
  pipeline arms (backend-agnostic; both backends invoke admit_policy
  with the same inputs so the same admission refusal arms fire)
* ``tests/unit/sandbox/test_warm_pool.py`` — ``sandbox_warm_pool_drained``
  (raised at ``warm_pool.py:400``; backend-agnostic — SandboxWarmPool
  takes any SandboxBackend)
* per-backend conformance tests (DockerSibling: existing
  ``tests/unit/sandbox/backends/test_docker_sibling_egress_classification.py``
  for ``sandbox_image_digest_not_in_canonical_catalog``; K8s backend
  conformance lands at T8B-b for ``sandbox_backend_unavailable``)

Drift detector — fails when a 16th value lands in
``SandboxRefusalReason`` without a corresponding trigger OR when a
trigger is removed without removing the value. NO claim about
behavioral fan-out across backends.

The drift detector pattern follows ``feedback_drift_detector_test_only_no_runtime_import``
— test-only equality check; no runtime cross-module import bridging
production code. Production modules each own their own copy of any
shared constant; this test imports from BOTH sides and asserts the
sets match.

Design note (plan-amendment): the registry lives at
``refusal_dispatch.py`` (NOT inside ``conftest.py``) because the
existing conformance ``conftest.py`` has
``pytest.importorskip("aiodocker")`` at module top — importing the
registry from conftest would force aiodocker as a dep for the
backend-agnostic membership test. The dispatch helper has zero
backend-specific imports so this test runs in any venv.
"""

from __future__ import annotations

from typing import get_args

from cognic_agentos.sandbox.protocol import SandboxRefusalReason

# This import will FAIL until the registry lands at step 4 — that is
# the failing-test signal step 2 produces per the TDD red phase.
from tests.conformance.sandbox.refusal_dispatch import TRIGGERS_BY_REASON


class TestRefusalTaxonomyRegistrationCoverage:
    """Pin the dispatch-registration completeness invariant.

    Per tightening edit A: this class asserts SET MEMBERSHIP between
    the production Literal and the registry's keyset. It does NOT
    assert that every backend behaviorally raises every value — that
    is a SEPARATE axis covered by the focused suites named in the
    module docstring above.
    """

    def test_triggers_cover_every_refusal_reason_value(self) -> None:
        """Every ``SandboxRefusalReason`` value MUST have a trigger
        registered in ``TRIGGERS_BY_REASON``. Drift detector — fails
        when a 16th value lands in the Literal without adding a
        trigger OR when a trigger is removed without removing the
        value.
        """
        reasons = set(get_args(SandboxRefusalReason))
        registered = set(TRIGGERS_BY_REASON.keys())
        missing = reasons - registered
        extra = registered - reasons
        assert not missing, (
            f"SandboxRefusalReason values without a trigger registered: "
            f"{sorted(missing)}; add a trigger factory to "
            f"TRIGGERS_BY_REASON in refusal_dispatch.py per the "
            f"tightening edit A registration-coverage contract."
        )
        assert not extra, (
            f"TRIGGERS_BY_REASON keys not present in SandboxRefusalReason: "
            f"{sorted(extra)}; remove the orphan triggers OR add the "
            f"values to the production Literal at protocol.py:34-50."
        )

    def test_refusal_reason_count_locked_at_thirty_seven(self) -> None:
        """Crisp value-count guard — separate from the membership
        assertion so drift in size shows a clean diagnostic.

        Sprint 8.5 T1 extended 15 → 21 (6 new wake-time arms per spec
        §3.3). Sprint 10 T7 extended 21 → 22 (kernel-boundary
        cross-tenant guard ``sandbox_credential_request_tenant_mismatch``).
        Sprint 10 T9 extended 22 → 26 (3 ``sandbox_credential_mint_failed_*``
        values with Stage-2 raise sites at T10 backend create(); 1
        ``sandbox_credential_ttl_exceeds_tenant_max`` value that is
        Literal-only per spec §7.3 amendment — no Stage-2 raise site).
        Sprint 10.1 extended 26 → 27 (1 post-mint granted-vs-requested
        TTL refusal ``sandbox_credential_lease_ttl_grant_exceeds_request``
        for the new ``VaultLeaseGrantExceedsRequest`` exception at
        ``core/vault.lease_credential`` per ADR-004 §25 amendment).
        Sprint 10.6 T16 extended 27 → 36 (9 credential-projection
        refusal values per spec §5.1; Literal-only at T16 — Stage-2
        raise sites land at T18 ``sandbox/projection.py`` planner +
        T21 lifecycle integration. The 9 T16 trigger envelopes
        registered in ``refusal_dispatch.py`` are honest no-op
        registration stubs per the registration-coverage doctrine
        documented in this module's docstring; behaviour coverage
        will live at the T18 planner unit suite + T21 cross-backend
        conformance suite when those tasks land later in the sprint).
        ADR-023 (Wave-2) extended 36 → 37 (1 per-tenant config-overlay
        cap-resolution failure ``sandbox_tenant_config_overlay_invalid``
        raised by ``admit_policy`` at Step 5; real refusal, seam-unit-
        proven at ``tests/unit/sandbox/test_admission_overlay.py``).
        If this fails because the count is no longer 37, update the
        constant here AND ensure ``TRIGGERS_BY_REASON`` has a matching
        entry for the new value. NEVER update this guard without also
        updating the dispatch.
        """
        assert len(get_args(SandboxRefusalReason)) == 37
