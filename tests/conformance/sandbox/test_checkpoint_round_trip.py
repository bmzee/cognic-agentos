"""Sprint 8.5 T9 — cross-backend checkpoint round-trip conformance.

Pins workspace-tar semantics across BOTH Wave-1 backends per spec
§7.3. Drift in tar-encoding semantics (gzip level, file-mode
preservation, symlink handling) surfaces here as a conformance
failure rather than a silent backend-asymmetric divergence.

The single test body runs against ``docker_sibling`` AND
``kubernetes_pod`` via the conformance ``backend`` fixture (conftest
``params=["docker_sibling", "kubernetes_pod"]``). The per-backend unit
round-trip tests — ``tests/unit/sandbox/backends/test_docker_sibling_checkpoint.py``
and ``tests/unit/sandbox/backends/test_kubernetes_pod_checkpoint.py``
— prove each backend in isolation; THIS test proves the two behave
identically. Future Wave-2 backends (gVisor / Firecracker per
ADR-004 §27) MUST also pass it to clear the cross-backend
wire-public parity gate.

Env-gated SYMMETRICALLY: requires BOTH ``COGNIC_RUN_DOCKER_SANDBOX=1``
AND ``COGNIC_RUN_K8S_SANDBOX=1`` plus the canonical Sprint-8A image
catalog. The symmetric gate is deliberate — a parity test that ran
only one backend would give a false-green parity result, so the
whole module skips unless both runtimes are available.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy

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
            "Symmetric gating is deliberate: a parity test that ran only "
            "one backend would give a false-green parity result."
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
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.conformance",
    pack_version="v1",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


@pytest.fixture
def policy(fixture_runtime_image: str) -> SandboxPolicy:
    """Conformance ``SandboxPolicy`` — ``runtime_image`` flows from the
    conftest fixture (runtime fixture ref in fixture mode, canonical
    placeholder otherwise). All other fields unchanged from the
    pre-#477 ``_POLICY`` constant."""
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image=fixture_runtime_image,
        egress_allow_list=(),
        vault_path=None,
    )


def _bypass_catalog_trust_gate(backend: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the catalog cosign + SBOM seam so admission does not shell
    out to the real binaries with the fixture trust root.

    The conformance ``backend`` fixture builds a REAL
    ``CanonicalImageCatalog``, but the conftest trust root is a fixture
    file — NOT a real cosign public key. The canonical-image preflight
    only proves the images are present in the runtime, not that they
    verify against this fixture key. Mirrors the catalog-seam bypass at
    ``tests/unit/sandbox/backends/test_docker_sibling_checkpoint.py`` +
    ``test_kubernetes_pod_checkpoint.py``. The patch stays active for
    the whole test body so it covers BOTH the initial ``create()`` and
    the ``admit_policy`` revalidation inside ``wake()``.
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


async def test_checkpoint_round_trip_preserves_workspace_state(
    backend: Any,
    monkeypatch: pytest.MonkeyPatch,
    policy: SandboxPolicy,
) -> None:
    """checkpoint() → suspend() → wake() → exec() round-trips the
    /workspace contents. The SAME assertion runs against both Wave-1
    backends via the conftest ``backend`` parametrize.

    Per spec §7.3: a workspace-tar encoding divergence between the two
    backends (gzip level / file mode / symlink handling) surfaces as a
    failure of this test on exactly one of the two parametrized arms.
    """
    _bypass_catalog_trust_gate(backend, monkeypatch)

    session = await backend.create(
        policy,
        actor=_ACTOR,
        tenant_id=_TENANT,
        pack_context=_PACK_CTX,
        use_warm_pool=False,
    )
    woken = None
    try:
        # 1. Populate /workspace with three artifacts that each exercise
        #    a distinct dimension of the workspace-tar encoding contract
        #    per spec §7.3:
        #      * marker.txt — a regular file (content preservation),
        #      * exec.sh    — mode 0755 (file-mode-bit preservation),
        #      * link.txt   — a relative symlink (symlink NOT
        #                     dereferenced into a copy).
        #    A backend whose tar encoding drops mode bits or follows
        #    symlinks passes the content check but fails step 5.
        setup = await session.exec(
            [
                "sh",
                "-c",
                "echo conformance-marker > /workspace/marker.txt && "
                "printf '#!/bin/sh\\necho hi\\n' > /workspace/exec.sh && "
                "chmod 0755 /workspace/exec.sh && "
                "ln -s marker.txt /workspace/link.txt",
            ]
        )
        assert setup.exit_code == 0

        # 2. Explicit checkpoint() — exercises the checkpoint() Protocol
        #    method's workspace-tar path directly (suspend() also takes
        #    a final checkpoint, but pinning checkpoint() on its own is
        #    the §7.3 workspace-tar parity contract).
        await session.checkpoint("round-trip")

        # 3. Suspend — takes the final checkpoint + tears down the
        #    backend resource (container / Pod).
        await session.suspend()

        # 4. Wake by session_id — restores into a fresh backend
        #    resource with the ORIGINAL session_id.
        woken = await backend.wake(session.session_id, actor=_ACTOR, tenant_id=_TENANT)
        assert woken.session_id == session.session_id

        # 5. Verify all three artifacts survived the round-trip. The
        #    combined probe emits one token per dimension so a single
        #    failed dimension (content / mode bit / symlink) is
        #    individually diagnosable.
        result = await woken.exec(
            [
                "sh",
                "-c",
                'printf "MARKER=%s\\n" "$(cat /workspace/marker.txt)"; '
                "test -x /workspace/exec.sh "
                '&& printf "EXEC_BIT=ok\\n" || printf "EXEC_BIT=LOST\\n"; '
                "test -L /workspace/link.txt "
                '&& printf "SYMLINK=%s\\n" "$(readlink /workspace/link.txt)" '
                '|| printf "SYMLINK=LOST\\n"',
            ]
        )
        assert result.exit_code == 0
        # Regular-file content preserved.
        assert b"MARKER=conformance-marker" in result.stdout
        # Mode 0755 preserved — the executable bit survived tar encoding.
        assert b"EXEC_BIT=ok" in result.stdout
        # Symlink preserved as a symlink (target intact, NOT dereferenced
        # into a regular-file copy).
        assert b"SYMLINK=marker.txt" in result.stdout
    finally:
        # Best-effort teardown of the live (woken) resource. Suppressed
        # so a teardown error never masks a real assertion failure.
        if woken is not None:
            with contextlib.suppress(Exception):
                await backend.destroy(woken)
        with contextlib.suppress(Exception):
            await backend.destroy(session)
