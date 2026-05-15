"""Sprint 7B.3 T9 — shared fixtures + stubs for the approve-endpoint tests.

NOT a test module — the ``_`` prefix means pytest does not collect it. It
houses the :class:`~cognic_agentos.packs.storage.PackRecordStore` seeding
helpers + the :class:`~cognic_agentos.protocol.trust_gate.TrustGate` /
:class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`
stubs shared by the four T9 approve-endpoint test files:

- ``test_review_approve_5_gate.py`` — 5-gate composition + green/412 paths.
- ``test_review_approve_override.py`` — the ADR-012 §107 override path.
- ``test_review_routes_trust_gate_wiring.py`` — factory-signature wiring.
- ``test_app_factory_trust_gate_wiring.py`` — ``create_app`` wiring.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from sqlalchemy import select, update
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.trust_gate import CosignVerificationResult

# ---------------------------------------------------------------------------
# Chain-row direct-read helper.
#
# The SQLite ``engine`` + ``store`` pytest fixtures the T9 approve-endpoint
# test files use live in ``conftest.py`` (not here) — importing a fixture
# into a test module + naming a test parameter the same triggers ruff F811.
# ---------------------------------------------------------------------------


async def read_chain_rows(engine: AsyncEngine, *, event_type: str | None = None) -> list[Row[Any]]:
    """Read ``decision_history`` rows DIRECTLY (record_id + event_type +
    payload), sequence-ordered.

    :meth:`PackRecordStore.load_lifecycle_history` only surfaces the
    ``pack.lifecycle.%`` slice — the ``pack.approval_override`` event
    (``decision_type == "pack.approval_override"``) needs a direct read.
    Mirrors ``test_storage_override_event.py``'s direct-read helper.
    """
    async with engine.connect() as conn:
        stmt = select(
            _decision_history.c.record_id,
            _decision_history.c.event_type,
            _decision_history.c.payload,
        ).order_by(_decision_history.c.sequence)
        if event_type is not None:
            stmt = stmt.where(_decision_history.c.event_type == event_type)
        result = await conn.execute(stmt)
        return list(result.all())


# The reviewer-acknowledgement panel keys (mirror ReviewerAcknowledgement).
_ACK_KEYS = (
    "data_governance_acknowledged",
    "risk_tier_acknowledged",
    "supply_chain_acknowledged",
    "conformance_acknowledged",
)


# ---------------------------------------------------------------------------
# Actor + binder + create_app helpers.
# ---------------------------------------------------------------------------


class StubBinder:
    """Test-only :class:`ActorBinder` returning a configured actor."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def make_actor(
    *,
    subject: str = "alice@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"pack.review.approve"}),
    actor_type: str = "human",
) -> Actor:
    """Build a fixture :class:`Actor`. Defaults to the reviewer ``alice``
    with ``pack.review.approve``; pass ``scopes`` with
    ``pack.override.approval_gate`` added for the override-path tests."""
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


def build_app(
    *,
    actor: Actor,
    store: PackRecordStore,
    trust_gate: Any = None,
    trust_root_resolver: Any = None,
) -> FastAPI:
    """Build a portal app via :func:`create_app` with the given binder +
    store + (optional) trust-gate verifier + trust-root resolver."""
    return create_app(
        actor_binder=StubBinder(actor),
        pack_record_store=store,
        trust_gate=trust_gate,
        trust_root_resolver=trust_root_resolver,
    )


# ---------------------------------------------------------------------------
# TrustGate + TrustRootResolver stubs.
# ---------------------------------------------------------------------------


class StubTrustGate:
    """Test-only :class:`TrustGate` stand-in.

    Default: ``verify_pack_signature`` succeeds with a synthetic
    ``CosignVerificationResult``. Pass ``raises=<exc>`` to make it raise
    a chosen exception (``CosignVerificationFailed`` /
    ``CosignNotInstalledError`` / ``PathTraversalError`` / ``ValueError``)
    so the approve handler's 4-class except set can be exercised.
    """

    def __init__(
        self,
        *,
        raises: Exception | None = None,
        signature_digest: str = "sig-digest-deadbeefcafe",
    ) -> None:
        self._raises = raises
        self._signature_digest = signature_digest
        self.calls: list[dict[str, Any]] = []

    async def verify_pack_signature(
        self,
        *,
        pack_id: str,
        version: str,
        signature_path: Path,
        blob_path: Path,
        trust_root: Path,
        tenant_id: str | None = None,
        request_id: str = "system",
    ) -> CosignVerificationResult:
        self.calls.append(
            {
                "pack_id": pack_id,
                "version": version,
                "signature_path": signature_path,
                "blob_path": blob_path,
                "trust_root": trust_root,
                "tenant_id": tenant_id,
                "request_id": request_id,
            }
        )
        if self._raises is not None:
            raise self._raises
        return CosignVerificationResult(
            verified=True,
            pack_id=pack_id,
            version=version,
            signature_digest=self._signature_digest,
        )


class StubTrustRootResolver:
    """Test-only :class:`TrustRootResolver` stand-in.

    Default: resolves to a fixed :class:`~pathlib.Path`. Pass
    ``raises=NotImplementedError(...)`` to exercise the kernel-default
    fail-loud path (→ ``signature_trust_root_not_configured``).
    """

    def __init__(
        self,
        *,
        raises: Exception | None = None,
        trust_root: Path | None = None,
    ) -> None:
        self._raises = raises
        self._trust_root = trust_root or Path("/var/cognic/trust-roots/t1")
        self.calls: list[str] = []

    async def resolve_trust_root(self, *, tenant_id: str) -> Path:
        self.calls.append(tenant_id)
        if self._raises is not None:
            raise self._raises
        return self._trust_root


# ---------------------------------------------------------------------------
# Manifest + request-body builders.
# ---------------------------------------------------------------------------


def default_manifest(
    *,
    kind: str = "tool",
    version: str = "1.0.0",
    attestation_paths: list[str] | None = None,
    blob_path: str = "pack_x-1.0.0-py3-none-any.whl",
    include_supply_chain: bool = True,
) -> dict[str, Any]:
    """Build a persisted-manifest dict with a tool ``[pack]`` block + a
    well-formed ``[supply_chain]`` block (relative cosign.sig + blob)."""
    manifest: dict[str, Any] = {"pack": {"kind": kind, "version": version}}
    if include_supply_chain:
        manifest["supply_chain"] = {
            "attestation_paths": (
                attestation_paths
                if attestation_paths is not None
                else ["cosign.sig", "bundle.sigstore"]
            ),
            "blob_path": blob_path,
        }
    return manifest


def approve_body(
    *,
    ack_all: bool = True,
    override_reason: str | None = None,
    **ack_overrides: bool,
) -> dict[str, Any]:
    """Build a ``POST /approve`` JSON body. ``ack_all`` sets every panel
    ack True; ``ack_overrides`` flips individual panels; ``override_reason``
    is the optional categorised :data:`ApprovalOverrideReason`."""
    acknowledgement = {key: ack_all for key in _ACK_KEYS}
    acknowledgement.update(ack_overrides)
    body: dict[str, Any] = {"acknowledgement": acknowledgement}
    if override_reason is not None:
        body["override_reason"] = override_reason
    return body


# ---------------------------------------------------------------------------
# Pack seeding.
# ---------------------------------------------------------------------------


def make_bundle(
    tmp_path: Path,
    *,
    blob_filename: str = "pack_x-1.0.0-py3-none-any.whl",
    write_sig: bool = True,
    write_blob: bool = True,
) -> Path:
    """Create a signed-bundle directory under ``tmp_path`` with a
    ``cosign.sig`` + the signed wheel; return the absolute bundle root.

    ``write_sig`` / ``write_blob`` can be False to leave one file
    missing on disk (exercises ``signature_bundle_path_unreachable``).
    """
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    if write_sig:
        (bundle / "cosign.sig").write_bytes(b"-----BEGIN SIGNATURE-----\n")
    if write_blob:
        (bundle / blob_filename).write_bytes(b"PK\x03\x04 fake wheel bytes")
    return bundle


def _draft_record(*, tenant_id: str, created_by: str, kind: str) -> PackRecord:
    now = datetime.now(UTC)
    return PackRecord(
        id=uuid.uuid4(),
        kind=kind,  # type: ignore[arg-type]
        pack_id=f"cognic-{kind}-{uuid.uuid4().hex[:8]}",
        display_name="Seed Pack",
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by=created_by,
        last_actor=created_by,
        created_at=now,
        updated_at=now,
    )


async def seed_draft_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    kind: str = "tool",
) -> PackRecord:
    """Seed a pack left in ``draft`` (no submit chain row) — exercises
    the approve handler's ``pack_not_yet_submitted`` 409."""
    record = _draft_record(tenant_id=tenant_id, created_by=created_by, kind=kind)
    await store.save_draft(record)
    return record


async def seed_submitted_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    kind: str = "tool",
    manifest: dict[str, Any] | None = None,
    conformance: dict[str, Any] | None = None,
    signed_artefact_root: str | None = None,
) -> PackRecord:
    """Seed a pack into ``submitted`` (submitted but NOT claimed) with a
    populated submit chain row — exercises the R15 P2 #3
    ``approve_transition_refused`` path (approve on a pack that is not
    in ``under_review`` → ``LifecycleTransitionRefused``)."""
    record = _draft_record(tenant_id=tenant_id, created_by=created_by, kind=kind)
    await store.save_draft(record)
    submit_kwargs: dict[str, Any] = {
        "payload_manifest": manifest if manifest is not None else default_manifest(kind=kind),
    }
    if signed_artefact_root is not None:
        submit_kwargs["signed_artefact_root"] = signed_artefact_root
    if conformance is not None:
        submit_kwargs["payload_conformance"] = conformance
    await store.transition(
        pack_id=record.id,
        transition="submit",
        actor_id=created_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"submit-seed-{record.id.hex[:8]}",
        **submit_kwargs,
    )
    return record.model_copy(update={"state": "submitted"})


async def _inject_submit_evidence(
    store: PackRecordStore,
    pack_id: uuid.UUID,
    *,
    evaluation: dict[str, Any] | None,
    adversarial: dict[str, Any] | None,
) -> None:
    """Test-only — splice ``evaluation`` / ``adversarial`` keys into the
    submit chain row's payload via a direct ``UPDATE``.

    The submit ``transition()`` has NO kwarg for gate-2/3 evidence (per
    Reviewer Flag #3 (c) production never writes ``payload["evaluation"]``
    / ``payload["adversarial"]`` in Sprint 7B.3) — but the approve
    handler's all-green green path is only exercisable when all 5 gates
    resolve green, which requires those keys to be present. The approve
    read path (``find_latest_submit_row`` + ``payload`` reads) does NOT
    verify the chain hash, so a direct payload mutation is sufficient
    for the test and stays a clearly-separated test-only path.
    """
    engine = store._engine  # test-only direct chain read/write
    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                select(_decision_history.c.record_id, _decision_history.c.payload).where(
                    _decision_history.c.event_type == "pack.lifecycle.submitted"
                )
            )
        ).all()
        for row in rows:
            payload = dict(row.payload or {})
            if payload.get("pack_id") != str(pack_id):
                continue
            if evaluation is not None:
                payload["evaluation"] = evaluation
            if adversarial is not None:
                payload["adversarial"] = adversarial
            await conn.execute(
                update(_decision_history)
                .where(_decision_history.c.record_id == row.record_id)
                .values(payload=payload)
            )


async def seed_under_review_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    claimed_by: str = "carol@bank.example",
    kind: str = "tool",
    manifest: dict[str, Any] | None = None,
    conformance: dict[str, Any] | None = None,
    evaluation: dict[str, Any] | None = None,
    adversarial: dict[str, Any] | None = None,
    signed_artefact_root: str | None = None,
    persist_manifest: bool = True,
) -> PackRecord:
    """Seed a pack into ``under_review`` with a populated submit chain row.

    ``draft → save_draft → submit → claim``. The submit transition
    threads ``payload_manifest`` / ``signed_artefact_root`` /
    ``payload_conformance`` so the approve handler's
    :func:`find_latest_submit_row` walk surfaces the evidence. The
    reviewer (``alice``) is a third actor distinct from ``created_by``
    + ``claimed_by`` so the role-separation guard ADMITS.

    ``persist_manifest=False`` seeds a submit row with NO
    ``payload["manifest"]`` (exercises ``manifest_evidence_not_persisted``).

    ``evaluation`` / ``adversarial`` (test-only) are spliced into the
    submit chain row's payload via :func:`_inject_submit_evidence` AFTER
    the submit transition. Production never writes these keys in Sprint
    7B.3 (Reviewer Flag #3 (c)), so gates 2-3 default to
    ``evidence_not_attached``; the seeding kwargs exist purely so the
    all-green green path is exercisable in the regression suite.
    """
    record = _draft_record(tenant_id=tenant_id, created_by=created_by, kind=kind)
    await store.save_draft(record)

    submit_kwargs: dict[str, Any] = {}
    if persist_manifest:
        submit_kwargs["payload_manifest"] = (
            manifest if manifest is not None else default_manifest(kind=kind)
        )
    if signed_artefact_root is not None:
        submit_kwargs["signed_artefact_root"] = signed_artefact_root
    if conformance is not None:
        submit_kwargs["payload_conformance"] = conformance
    await store.transition(
        pack_id=record.id,
        transition="submit",
        actor_id=created_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"submit-seed-{record.id.hex[:8]}",
        **submit_kwargs,
    )
    if evaluation is not None or adversarial is not None:
        await _inject_submit_evidence(
            store, record.id, evaluation=evaluation, adversarial=adversarial
        )
    await store.transition(
        pack_id=record.id,
        transition="claim",
        actor_id=claimed_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"claim-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "under_review"})


__all__ = [
    "StubBinder",
    "StubTrustGate",
    "StubTrustRootResolver",
    "approve_body",
    "build_app",
    "default_manifest",
    "make_actor",
    "make_bundle",
    "read_chain_rows",
    "seed_draft_pack",
    "seed_submitted_pack",
    "seed_under_review_pack",
]
