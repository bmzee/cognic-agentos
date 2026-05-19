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

    def test_refusal_reason_count_locked_at_twenty_one(self) -> None:
        """Crisp value-count guard — separate from the membership
        assertion so drift in size shows a clean diagnostic.

        Sprint 8.5 T1 extended 15 → 21 (6 new wake-time arms per spec
        §3.3). If this fails because the count is no longer 21, update
        the constant here AND ensure ``TRIGGERS_BY_REASON`` has a
        matching entry for the new value. NEVER update this guard
        without also updating the dispatch.
        """
        assert len(get_args(SandboxRefusalReason)) == 21
