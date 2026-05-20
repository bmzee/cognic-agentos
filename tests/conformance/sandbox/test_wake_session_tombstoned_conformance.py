"""Sprint 8.5 T9 (P3.r8) — cross-backend tombstone-first wake conformance.

Pins the LOAD-BEARING tombstone-first wake invariant across BOTH
Wave-1 backends per spec §7.3. ``wake()`` MUST call
``CheckpointStore.load_tombstone()`` BEFORE ``load_latest()`` — a
destroyed session may still have checkpoint bytes on disk (the reaper
purges asynchronously per spec §4.3), so a ``wake()`` that started
with ``load_latest()`` would surface a destroyed session as
restorable. That is the wrong taxonomy and violates operator intent.

Three cases, two backends (``docker_sibling`` + ``kubernetes_pod`` via
the conformance ``backend`` parametrize):

(a) Tombstoned session → ``wake()`` refuses with
    ``sandbox_wake_session_tombstoned``.
(b) Tombstoned session + valid checkpoint metadata still on disk →
    ``wake()`` refuses with ``sandbox_wake_session_tombstoned`` and
    does NOT restore. The test first proves ``load_latest()`` would
    succeed (a restore path genuinely exists), then wraps
    ``load_latest()`` so ANY call to it during ``wake()`` raises. A
    correct tombstone-first ``wake()`` refuses at the
    ``load_tombstone()`` check and never reaches ``load_latest()``; an
    implementation that called ``load_latest()`` first — even one that
    then checks the tombstone before restoring — trips the wrap and
    fails. The "wake refuses + metadata exists" pair alone would NOT
    catch that regression; the wrap is what pins the ordering.
(c) Corrupt ``_tombstoned.json`` + valid checkpoint metadata →
    ``wake()`` refuses with ``sandbox_wake_session_tombstoned`` via the
    ``TombstoneCorruptError`` fail-closed path per P1.r6. A backend
    that returned ``None`` on a malformed tombstone would fail-OPEN and
    restore a session the operator intended to destroy.

The per-backend unit test ``tests/unit/sandbox/test_wake_session_tombstoned.py``
pins the closed-enum + detail-field invariants for ONE backend at a
time; it CANNOT detect a backend-asymmetric skip of the tombstone-first
step. That cross-backend parity is exactly what this conformance test
owns.

Env-gated SYMMETRICALLY: requires BOTH ``COGNIC_RUN_DOCKER_SANDBOX=1``
AND ``COGNIC_RUN_K8S_SANDBOX=1`` — the whole module skips unless both
runtimes are available, so a green run always means both backends were
exercised.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.checkpoint_store import _BUCKET, _TOMBSTONE_BASENAME
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

pytestmark = [
    pytest.mark.asyncio,
    # Once both env gates are set, a per-backend runtime that cannot run
    # FAILS the parity gate instead of skipping — see _backend_unavailable
    # in conftest.py. Without this marker the backend fixture would skip
    # one arm and let the other pass green (a one-backend false-green).
    pytest.mark.require_both_backends,
    pytest.mark.skipif(
        not (
            os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") == "1"
            and os.environ.get("COGNIC_RUN_K8S_SANDBOX") == "1"
        ),
        reason=(
            "cross-backend conformance requires BOTH backend runtimes — "
            "set COGNIC_RUN_DOCKER_SANDBOX=1 AND COGNIC_RUN_K8S_SANDBOX=1. "
            "Symmetric gating is deliberate: a tombstone-first parity test "
            "that ran only one backend would give a false-green result."
        ),
    ),
]


_TENANT = "t-conformance"
_ACTOR = Actor(
    subject="conformance-actor",
    tenant_id=_TENANT,
    scopes=frozenset(),
    actor_type="human",
)
_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.conformance",
    pack_version="v1",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)
_TOMBSTONED_REASON = "sandbox_wake_session_tombstoned"


def _bypass_catalog_trust_gate(backend: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the catalog cosign + SBOM seam so the initial ``create()``
    does not shell out to the real binaries with the fixture trust
    root. Mirrors the catalog-seam bypass at
    ``tests/unit/sandbox/backends/test_docker_sibling_checkpoint.py``.

    ``wake()`` in every tombstone case refuses at step 1 (the
    tombstone check) BEFORE the step-4 ``admit_policy`` revalidation,
    so the cosign seam is never reached on the wake path — but the
    bypass stays active for the whole test so ``create()`` admits.
    """
    monkeypatch.setattr(
        backend._catalog,
        "verify_cosign_or_refuse",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        backend._catalog,
        "verify_sbom_policy_or_refuse",
        AsyncMock(return_value=None),
    )


async def _tombstoned_session(backend: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """create() → checkpoint() → destroy() — the production tombstone
    path.

    ``destroy()`` writes the ``_tombstoned.json`` sentinel only when
    the session ``has_checkpoints`` (per ``docker_sibling.py`` /
    ``kubernetes_pod.py`` destroy bodies), so the explicit
    ``checkpoint()`` call is load-bearing for the setup. After this
    helper returns, the object store carries — under
    ``<tenant>/<session>/`` — BOTH the tombstone sentinel AND the
    checkpoint metadata + snapshot bytes. Returns the destroyed
    session (its ``session_id`` is the wake() input).
    """
    _bypass_catalog_trust_gate(backend, monkeypatch)
    session = await backend.create(
        _POLICY,
        actor=_ACTOR,
        tenant_id=_TENANT,
        pack_context=_PACK_CTX,
        use_warm_pool=False,
    )
    await session.checkpoint("pre-destroy")
    await backend.destroy(session)
    return session


class TestWakeSessionTombstonedConformance:
    """Cross-backend tombstone-first wake parity — 3 cases, each runs
    against ``docker_sibling`` AND ``kubernetes_pod``."""

    async def test_case_a_tombstoned_session_wake_refuses(
        self,
        backend: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(a) A tombstoned session → ``wake()`` refuses fail-closed
        with the ``sandbox_wake_session_tombstoned`` closed-enum
        reason."""
        session = await _tombstoned_session(backend, monkeypatch)

        with pytest.raises(SandboxLifecycleRefused) as excinfo:
            await backend.wake(session.session_id, actor=_ACTOR, tenant_id=_TENANT)
        assert excinfo.value.reason == _TOMBSTONED_REASON

    async def test_case_b_tombstoned_plus_valid_metadata_wake_refuses_not_restore(
        self,
        backend: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(b) Tombstone + valid checkpoint metadata on disk → ``wake()``
        REFUSES, it does NOT restore.

        First proves a restore path genuinely exists by loading the
        checkpoint metadata directly; then wraps ``load_latest()`` so
        any call to it during ``wake()`` raises, and asserts ``wake()``
        still refuses with ``sandbox_wake_session_tombstoned``. A
        backend ``wake()`` that reached ``load_latest()`` at all on a
        tombstoned session trips the wrap — this is the load-bearing
        tombstone-first ordering proof.
        """
        session = await _tombstoned_session(backend, monkeypatch)

        # A restore path genuinely exists — load_latest() succeeds and
        # returns the persisted metadata + snapshot bytes.
        metadata, snapshot = await backend._checkpoint_store.load_latest(
            session_id=session.session_id, tenant_id=_TENANT
        )
        assert metadata.session_id == session.session_id
        assert len(snapshot) > 0

        # Pin the ORDERING contract directly. Wrap load_latest() so ANY
        # call to it during wake() raises. A correct tombstone-first
        # wake() refuses at step 1 (the load_tombstone() check) and
        # NEVER reaches load_latest(); an implementation that called
        # load_latest() FIRST — even one that then checks the tombstone
        # before restoring — trips this AssertionError and fails.
        #
        # The "wake refuses + metadata exists" assertions ABOVE are not
        # enough on their own: a load_latest()-first implementation
        # would satisfy them too. This wrap is what actually catches
        # the load_latest()-before-load_tombstone() regression — the
        # exact regression this conformance case exists for.
        async def _load_latest_must_not_be_called(*_args: object, **_kwargs: object) -> None:
            raise AssertionError(
                "wake() called load_latest() on a tombstoned session — "
                "load_tombstone() MUST run first and refuse before "
                "load_latest() is ever reached (spec §3.2 / §7.1 / §7.2 "
                "tombstone-first ordering)"
            )

        monkeypatch.setattr(
            backend._checkpoint_store,
            "load_latest",
            _load_latest_must_not_be_called,
        )
        with pytest.raises(SandboxLifecycleRefused) as excinfo:
            await backend.wake(session.session_id, actor=_ACTOR, tenant_id=_TENANT)
        assert excinfo.value.reason == _TOMBSTONED_REASON

    async def test_case_c_corrupt_tombstone_plus_valid_metadata_wake_refuses(
        self,
        backend: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(c) Corrupt ``_tombstoned.json`` + valid checkpoint metadata
        → ``wake()`` refuses with ``sandbox_wake_session_tombstoned``
        via the ``TombstoneCorruptError`` fail-closed path per P1.r6.

        A backend that returned ``None`` on a malformed tombstone would
        fail-OPEN — proceed to ``load_latest()`` and restore a session
        the operator intended to destroy.
        """
        session = await _tombstoned_session(backend, monkeypatch)

        # Overwrite the well-formed sentinel with malformed bytes. The
        # key is the spec §4.1 storage-layout contract — imported from
        # checkpoint_store so the test stays pinned to source-of-truth.
        corrupt_key = f"{_TENANT}/{session.session_id}/{_TOMBSTONE_BASENAME}"
        await backend._checkpoint_store._object_store.put(
            _BUCKET,
            corrupt_key,
            b"{ this is not valid tombstone json",
            retention_seconds=None,
        )

        with pytest.raises(SandboxLifecycleRefused) as excinfo:
            await backend.wake(session.session_id, actor=_ACTOR, tenant_id=_TENANT)
        # Same closed-enum reason as a well-formed tombstone — operator
        # destroy() intent survives sentinel corruption.
        assert excinfo.value.reason == _TOMBSTONED_REASON
        # The corrupt-exception message is surfaced in detail for
        # incident-response traceability per the P1.r6 contract.
        assert "corrupt" in excinfo.value.detail
