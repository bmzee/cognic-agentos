"""Sprint 9.5 Z2 — real-cosign proof of the Wave-1 model trust path.

**Two-layer proof** per the user-locked Z2 reviewer bar:

  **Layer 1 — direct trust gate.** Real cosign ``generate-key-pair``
    → real ``cosign sign-blob --bundle`` → :meth:`ModelTrustGate.verify_model_signature`
    returns ``True`` end-to-end with the actual cosign binary at the
    target version. This is the foundational trust proof; if Layer 1
    fails the bundle-only cosign verify-blob shape is broken at the
    target cosign version (see plan Step 3 FAIL branch — amendments
    to spec/trust.py would land in the same closeout commit).

  **Layer 2 — route + storage end-to-end.** The same bundle digest
    threaded through the FastAPI route surface:
    ``POST /api/v1/models`` (register) → ``POST /…/promote``
    (target_state=eval_passed). The route's
    ``_verify_record_signature`` recomputes the bundle digest per the
    B4 R2 P1 evidence-integrity invariant, the real cosign subprocess
    passes, storage's ``promote_eval_passed`` precondition accepts
    ``signature_verified=True``, and the chain row stamps the
    verified digest.

**Env-gated** on ``COGNIC_RUN_COSIGN_INTEGRATION=1``. Default
``pytest`` invocations skip the entire module (no SKIP noise unless
opted-in). When the env var IS set, the fixture **fails LOUD** if
``cosign`` is missing from PATH — the opt-in env-var is the "I have
cosign" contract; missing cosign at that point is a broken environment,
NOT a non-issue (no silent skip, no pretend-success).

**Per the user-locked Z2 invariants:**

  - Private key lives in ``tmp_path`` (mktemp), NEVER in the fixture
    dir; wiped after signing.
  - Byte-coupling per
    ``[[feedback_test_fixture_byte_coupling_for_crypto_claims]]``:
    the Layer-2 payload's ``signature_digest`` IS
    :func:`sigstore_bundle_digest` of the real bundle bytes — NOT a
    placeholder.
  - Selective-add guard per the plan's Step 4 bash check (also in
    ``.gitignore`` at the package level): ``*.key`` / ``*.pem``
    refused at commit time.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.models.storage import ModelRecordStore
from cognic_agentos.models.trust import ModelTrustGate, sigstore_bundle_digest
from cognic_agentos.portal.api.models import build_models_router
from cognic_agentos.portal.rbac.actor import Actor

# Module-level env-gate. Default ``pytest`` invocations skip; opting
# in requires the env var. Skip message names the env var explicitly
# so operators reading "SKIPPED [N]" output know how to opt in.
pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_COSIGN_INTEGRATION") != "1",
    reason=(
        "real-cosign Z2 proof; opt in via COGNIC_RUN_COSIGN_INTEGRATION=1 "
        "(requires cosign on PATH at the target version — fails loud if missing)"
    ),
)


class _StubBinder:
    """Test-only binder returning a fixed Actor per the SYNC
    ``ActorBinder.bind`` Protocol contract."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


@pytest.fixture(scope="module")
def real_cosign_keypair_and_bundle(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Any]:
    """Mint a real cosign keypair + sign a real bundle.

    Layout — everything in tmp_path; the private key is wiped after
    signing. Module-scoped so the keypair-generation + sign cost is
    amortised across both Layer-1 and Layer-2 tests.

    **Fail-loud contract**: if ``cosign`` is missing from PATH when
    the env-gate is opted in, the fixture raises ``AssertionError``
    with a clear message — pytest reports ERROR (not SKIP), per the
    user-locked Z2 invariant.
    """
    cosign = shutil.which("cosign")
    assert cosign is not None, (
        "cosign binary not found on PATH; opt-in env "
        "COGNIC_RUN_COSIGN_INTEGRATION=1 implies cosign is available — "
        "this fixture fails LOUD rather than silently skipping the proof."
    )

    tmp = tmp_path_factory.mktemp("z2_real_cosign")

    # Keypair in tmp_path/keys — never in the fixture dir.
    keys_dir = tmp / "keys"
    keys_dir.mkdir()
    _subprocess_env = {
        "COSIGN_PASSWORD": "",
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp),
    }
    subprocess.run(
        [cosign, "generate-key-pair"],
        cwd=keys_dir,
        env=_subprocess_env,
        check=True,
        capture_output=True,
    )
    private_key = keys_dir / "cosign.key"
    public_key = keys_dir / "cosign.pub"
    assert private_key.exists(), "cosign generate-key-pair did not write cosign.key"
    assert public_key.exists(), "cosign generate-key-pair did not write cosign.pub"

    # Per-tenant artefact tree mirroring the production layout:
    # <root>/<tenant_id>/{trust-root.pub, artefact.bin, bundle.sigstore}
    artifact_root = tmp / "artifacts"
    tenant_dir = artifact_root / "tenant-acme"
    tenant_dir.mkdir(parents=True)

    # Copy ONLY the public key as the tenant trust root.
    trust_root = tenant_dir / "trust-root.pub"
    trust_root.write_bytes(public_key.read_bytes())

    # Write a real small artefact.
    artefact = tenant_dir / "artefact.bin"
    artefact.write_text("Sprint 9.5 Z2 real-cosign proof — model artefact bytes\n")

    # Sign with --bundle output.
    bundle = tenant_dir / "bundle.sigstore"
    subprocess.run(
        [
            cosign,
            "sign-blob",
            "--key",
            str(private_key),
            "--bundle",
            str(bundle),
            "--yes",
            str(artefact),
        ],
        env=_subprocess_env,
        check=True,
        capture_output=True,
    )
    assert bundle.exists(), "cosign sign-blob did not write the bundle"

    # **Wipe the private key.** From here on the test surface uses
    # only the public trust root + the signed bundle + the artefact.
    private_key.unlink()
    assert not private_key.exists(), "private key wipe failed"
    # Defence-in-depth — confirm NO key file landed in the tenant dir.
    for path in tenant_dir.rglob("*"):
        assert not path.name.endswith((".key", ".pem")), (
            f"private key/cert leaked into the tenant dir: {path}"
        )

    # Compute the bundle digest for byte-coupled Layer-2 payload.
    bundle_digest = sigstore_bundle_digest(bundle)

    return {
        "tmp": tmp,
        "artifact_root": artifact_root,
        "tenant_dir": tenant_dir,
        "trust_root": trust_root,
        "artefact": artefact,
        "bundle": bundle,
        "bundle_digest": bundle_digest,
        "cosign_path": cosign,
    }


# ──────────────────────────────────────────────────────────────────────
# Layer 1 — direct trust gate proof
# ──────────────────────────────────────────────────────────────────────


async def test_layer1_direct_trust_gate_verifies_real_bundle(
    real_cosign_keypair_and_bundle: dict[str, Any],
) -> None:
    """**Layer 1** — real cosign keypair → real signed bundle →
    :meth:`ModelTrustGate.verify_model_signature` returns ``True``.

    This is the foundational proof: the bundle-only ``cosign verify-blob``
    argv shape ``--key TR --bundle B A`` (no ``--signature`` flag)
    DOES work at the target cosign version. If this assertion fires
    False/raises, the spec/trust.py needs amendment (signature_ref +
    --signature back to argv) per the plan's Step 3 FAIL branch.
    """
    settings = Settings(cosign_path=real_cosign_keypair_and_bundle["cosign_path"])
    gate = ModelTrustGate(settings)
    verified = await gate.verify_model_signature(
        signed_artifact_path=real_cosign_keypair_and_bundle["artefact"],
        sigstore_bundle_path=real_cosign_keypair_and_bundle["bundle"],
        tenant_trust_root=real_cosign_keypair_and_bundle["trust_root"],
    )
    assert verified is True, (
        "real cosign rejected bundle-only verify-blob — Wave-1 model "
        "trust path needs --signature back; see spec §2.3 + plan "
        "decision #3 + plan Step 3 FAIL branch for the same-commit "
        "amendment list."
    )


# ──────────────────────────────────────────────────────────────────────
# Layer 2 — route + storage end-to-end
# ──────────────────────────────────────────────────────────────────────


async def test_layer2_route_and_storage_end_to_end(
    real_cosign_keypair_and_bundle: dict[str, Any],
    tmp_path: Path,
) -> None:
    """**Layer 2** — the same bundle digest threaded through the
    FastAPI route + storage pipeline. The route's
    ``_verify_record_signature`` recomputes the bundle digest per the
    B4 R2 P1 evidence-integrity invariant; real cosign passes;
    storage's ``promote_eval_passed`` precondition accepts
    ``signature_verified=True``.

    Byte-coupling per
    ``[[feedback_test_fixture_byte_coupling_for_crypto_claims]]`` —
    the payload's ``signature_digest`` IS
    :func:`sigstore_bundle_digest` of the real bundle bytes, NOT a
    placeholder. If the route's recompute-then-compare check drifts
    from the storage's ``signature_digest`` field, this assertion
    fires.
    """
    # Per-test sqlite engine + ModelRecordStore + chain heads seed.
    db = tmp_path / "z2_layer2.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    try:
        store = ModelRecordStore(engine)
        settings = Settings(
            cosign_path=real_cosign_keypair_and_bundle["cosign_path"],
            model_artifact_root=str(real_cosign_keypair_and_bundle["artifact_root"]),
        )
        trust_gate = ModelTrustGate(settings)
        actor = Actor(
            subject="z2-actor",
            tenant_id="tenant-acme",
            scopes=frozenset({"model.register", "model.promote.eval_passed", "model.audit.read"}),
            actor_type="human",
        )
        app = FastAPI()
        app.state.model_registry_store = store
        app.state.actor_binder = _StubBinder(actor)
        app.include_router(
            build_models_router(store=store, trust_gate=trust_gate, settings=settings)
        )

        payload = {
            "model_id": "z2-real-cosign-model",
            "base_model": "qwen3-8b-instruct",
            "version": "1.0.0",
            "kind": "foundation",
            "signature_digest": real_cosign_keypair_and_bundle["bundle_digest"],
            "signed_artifact_ref": "artefact.bin",
            "sigstore_bundle_ref": "bundle.sigstore",
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 1. Register — record stamped with the real bundle digest.
            register_response = await client.post("/api/v1/models", json=payload)
            assert register_response.status_code == 200, register_response.text
            register_body = register_response.json()
            assert register_body["lifecycle_state"] == "proposed"
            assert register_body["signature_digest"] == payload["signature_digest"]

            # 2. Promote eval_passed — real cosign runs OUTSIDE
            # transaction; bundle-digest recompute + cosign verify
            # both pass; storage's TOCTOU re-check matches; transition
            # commits.
            promote_response = await client.post(
                f"/api/v1/models/{payload['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
            assert promote_response.status_code == 200, (
                f"promote_eval_passed refused; real cosign failed end-to-end "
                f"through the route layer. body={promote_response.text!r}"
            )
            promote_body = promote_response.json()
            assert promote_body["lifecycle_state"] == "eval_passed"
            # Digest preserved through the transition (immutable
            # across the lifecycle per A6.0 payload contract).
            assert promote_body["signature_digest"] == payload["signature_digest"]

            # 3. Audit endpoint sanity: both chain rows (proposed +
            # eval_passed) carry the verified digest, proving the
            # evidence chain is intact through real cosign.
            audit_response = await client.get(f"/api/v1/models/{payload['model_id']}/audit")
            assert audit_response.status_code == 200, audit_response.text
            audit_events = audit_response.json()
            assert [e["decision_type"] for e in audit_events] == [
                "model.lifecycle.proposed",
                "model.lifecycle.eval_passed",
            ]
            for event in audit_events:
                assert event["payload"]["signature_digest"] == payload["signature_digest"], (
                    f"chain row {event['decision_type']!r} signature_digest "
                    f"diverged from the verified bundle digest — broken "
                    f"evidence integrity"
                )
    finally:
        await engine.dispose()
