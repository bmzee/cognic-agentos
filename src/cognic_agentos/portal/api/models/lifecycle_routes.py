"""Sprint 9.5 B4 — register / promote / retire route module.

CRITICAL CONTROL. Owns:

* The cosign **path-containment resolver** —
  :func:`_resolve_under_tenant_root`. Rejects 5 attack classes per the
  user-locked B4 reviewer bar: absolute paths, ``..``-traversal
  segments, URI schemes, symlink escapes (post-resolve), wrong-tenant
  symlink crossings, and missing-or-non-file targets. Both
  ``signed_artifact_ref`` AND ``sigstore_bundle_ref`` flow through the
  same helper.
* Body-aware authz for ``POST /promote`` — the required scope is
  ``model.promote.<target_state>`` resolved from the request body at
  handler time (NOT a fixed factory-time :func:`RequireScope` arg),
  because the scope depends on the body's ``target_state``. The
  ``HumanActor`` gate fires (only) when ``target_state == "serving"``.
* State-aware human gate at ``POST /retire`` — fires (only) when the
  CURRENT ``lifecycle_state == "serving"`` (retiring an already-
  serving model is a customer-facing action; retiring an earlier-
  state model is mechanical cleanup).
* Cosign verification OUTSIDE any DB transaction (design spec §2.3) —
  ``_verify_record_signature`` runs the subprocess pre-lock; the
  storage-layer ``promote_eval_passed`` precondition then re-checks
  the same refs under the row lock via the ``expected_*`` kwargs
  (TOCTOU defence per A4 R1 P1).

Standing-offer §30 invariant: ``from __future__ import annotations``
is **INTENTIONALLY OMITTED**. FastAPI's ``inspect.signature()`` /
``typing.get_type_hints()`` must resolve
``Annotated[..., Depends(<closure-local>)]`` against the closure-local
dependency instances (``_require_register`` / ``_require_retire`` /
``_require_tenant_ownership`` are local-scope inside
:func:`build_model_lifecycle_routes`, NOT module globals); PEP 563
string-deferral would surface as 422 ``Unprocessable Entity`` at
request time. Pinned via the route tests at
``tests/unit/portal/api/models/test_lifecycle_routes.py``.
"""

import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException

from cognic_agentos.core.config import Settings
from cognic_agentos.models.registry import ModelLifecycleRefused
from cognic_agentos.models.storage import (
    ModelNotFound,
    ModelRecord,
    ModelRecordStore,
)
from cognic_agentos.models.trust import (
    ModelSignatureVerificationError,
    ModelTrustGate,
    sigstore_bundle_digest,
)
from cognic_agentos.portal.api.models.dto import (
    ModelResponse,
    PromoteModelRequest,
    RegisterModelRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope, bind_actor
from cognic_agentos.portal.rbac.model_tenant_isolation import (
    RequireModelTenantOwnership,
)

_LOG = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Request-id minters — per-verb prefixes, decision_history column cap.
# ──────────────────────────────────────────────────────────────────────


#: 13-char per-verb prefix + uuid4().hex (32) = 45 chars, comfortably
#: under the decision_history.request_id String(64) column cap. Module-
#: foot assertion pins the invariant against drift.
_MODEL_REGISTER_REQUEST_ID_PREFIX: Final[str] = "mdl-register-"
_MODEL_PROMOTE_REQUEST_ID_PREFIX: Final[str] = "mdl-promote--"
_MODEL_RETIRE_REQUEST_ID_PREFIX: Final[str] = "mdl-retire---"
_REQUEST_ID_MAX_LEN: Final[int] = 64


def _mint_request_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


# ──────────────────────────────────────────────────────────────────────
# Cosign path-containment resolver (CC — user-locked B4 pin #2).
# ──────────────────────────────────────────────────────────────────────


def _resolve_under_tenant_root(
    *,
    relative_ref: str,
    tenant_id: str,
    root: Path,
) -> Path:
    """Resolve ``<root>/<tenant_id>/<relative_ref>`` with tight
    containment guards. Raises :class:`ValueError` on every guard
    failure, with a documented closed-set ``args[0]`` reason string.

    Documented guard reasons (the closed set pinned at
    ``test_lifecycle_routes.py::TestPathContainmentDirectHelper::test_guard_branches_have_distinct_reasons``):

    **Tenant-id guards (B4 R1 P2 — defence-in-depth against malformed
    tenant identifiers reaching the resolver):**

    - ``tenant_id_invalid`` — tenant_id is empty, ``.`` / ``..``,
      contains path separators (``/`` or ``\\``), or starts with
      ``.`` (hidden-file convention; could mask a directory). Without
      this guard a malformed tenant_id like ``..`` lets the resolved
      ``tenant_root`` land outside ``root`` BEFORE the containment
      check runs.
    - ``tenant_root_escapes_root`` — post-resolve check on the tenant
      subtree itself. A symlinked tenant directory (e.g.
      ``<root>/tenant-acme`` -> ``/etc``) trips this guard BEFORE
      candidate resolution proceeds; otherwise the helper would trust
      ``/etc`` as the containment boundary for ALL subsequent
      relative_ref resolves.

    **Relative-ref guards:**

    - ``absolute_path`` — empty string OR starts with ``/``.
    - ``uri_scheme`` — contains ``://`` or starts with ``//`` (e.g.
      ``s3://`` / ``http://`` / ``file://``). Wave-1 is filesystem-
      only; object-store-backed fetch is a Wave-2 seam (ADR-009).
    - ``traversal_segment`` — any path part is ``..`` or empty.
      Refused at the syntax check BEFORE ``Path.resolve()`` — defence-
      in-depth even if the resolved path would coincidentally land
      back inside the tenant root.
    - ``escapes_tenant_root`` — post-resolve check on the candidate.
      ``Path.resolve()`` follows symlinks; any candidate whose
      resolved canonical path is NOT under the tenant root (symlink-
      out, cross-tenant redirection) trips this guard.
    - ``missing_or_not_file`` — the resolved path either does not
      exist or is not a regular file (e.g. a directory).

    Argument shape — keyword-only because positional misuse on a
    path-containment helper is the exact bug class this module exists
    to prevent.
    """
    # Tenant-id validation FIRST — a malformed tenant_id would
    # otherwise let ``(root / tenant_id).resolve()`` land anywhere on
    # the filesystem and become the trusted containment root.
    if (
        not tenant_id
        or tenant_id in (".", "..")
        or "/" in tenant_id
        or "\\" in tenant_id
        or tenant_id.startswith(".")
    ):
        raise ValueError("tenant_id_invalid")
    # Relative-ref shape gates.
    if not relative_ref or relative_ref.startswith("/"):
        raise ValueError("absolute_path")
    if "://" in relative_ref or relative_ref.startswith("//"):
        raise ValueError("uri_scheme")
    parts = Path(relative_ref).parts
    if any(p in ("..", "") for p in parts):
        raise ValueError("traversal_segment")
    # Resolve the artifact root explicitly + the tenant subtree
    # strictly; then verify two invariants on the tenant subtree:
    #
    #   (1) ``tenant_root`` is contained within the resolved
    #       artifact root — catches symlinked tenant directories
    #       that point OUTSIDE root entirely.
    #   (2) ``tenant_root.name == tenant_id`` — catches symlinked
    #       tenant directories that point to a SIBLING under root
    #       (wrong-tenant crossing at the directory level). Without
    #       this check, ``<root>/tenant-acme`` symlinked to
    #       ``<root>/tenant-other`` would let a caller with
    #       tenant-acme credentials read tenant-other's files
    #       (the resolved tenant_root IS under root, so invariant
    #       (1) alone would not catch it).
    #
    # Both invariants raise the same closed-enum
    # ``tenant_root_escapes_root`` reason — operator-discipline
    # invariant is "tenant directories are real directories, never
    # symlinks", regardless of where the symlink points.
    resolved_root = root.resolve(strict=True)
    tenant_root = (root / tenant_id).resolve(strict=True)
    try:
        tenant_root.relative_to(resolved_root)
    except ValueError:
        raise ValueError("tenant_root_escapes_root") from None
    if tenant_root.name != tenant_id:
        raise ValueError("tenant_root_escapes_root")
    candidate = (tenant_root / relative_ref).resolve(strict=False)
    try:
        candidate.relative_to(tenant_root)
    except ValueError:
        raise ValueError("escapes_tenant_root") from None
    if not candidate.exists() or not candidate.is_file():
        raise ValueError("missing_or_not_file")
    return candidate


async def _verify_record_signature(
    record: ModelRecord,
    *,
    settings: Settings,
    trust_gate: ModelTrustGate,
) -> bool:
    """Resolve the artefact / bundle / trust-root refs under the
    per-tenant root, **verify the bundle bytes match the claimed
    ``signature_digest``**, then run the cosign verify.

    The bundle-digest cross-check (B4 R1 P1) is the load-bearing
    evidence-integrity guard. The chain row carries
    ``signature_digest`` as part of the immutable evidence snapshot
    (per A6.0 + [[feedback_chain_payload_is_evidence_snapshot]]); the
    spec defines that field as SHA-256 over the bundle bytes
    (mirrors ``protocol/supply_chain.persist_sigstore_bundle``'s
    ``bundle_digest``; helper :func:`sigstore_bundle_digest` shipped
    at A2). Without this re-computation, a client could register
    with a stale or fabricated digest, cosign verify-blob would
    still pass against the actual bundle, and the chain row would
    claim a digest examiners cannot reproduce by hashing the bundle
    bytes themselves.

    Returns ``True`` on a clean verify pipeline; ``False`` on any of:

    - ``record.signed_artifact_ref`` / ``record.sigstore_bundle_ref``
      / ``record.signature_digest`` is ``None`` (a registered model
      lacking any of the three cannot be promoted to eval_passed —
      fail-closed).
    - The path-containment resolver raises ``ValueError`` (bad ref /
      bad tenant_id / containment escape) or ``OSError`` (missing
      tenant subtree).
    - The recomputed ``sigstore_bundle_digest(bundle)`` does not
      match ``record.signature_digest`` (B4 R1 P1 evidence-integrity
      pin — chain claim must equal recomputable fact).
    - Bundle file read raises ``OSError`` (path resolved fine but
      bytes unreadable mid-verify).
    - The cosign subprocess returns a clean negative verdict (exit
      non-zero) — :meth:`ModelTrustGate.verify_model_signature`
      returns ``False``.
    - :class:`ModelSignatureVerificationError` — cosign cannot run
      at all (binary missing, launch failure, timeout). Fail-closed;
      the storage gate's
      ``model_promote_signature_verification_failed`` refusal carries
      the same closed-enum reason regardless of root cause.

    The route handler maps ``False`` to a 409 with the same reason
    as storage's gate — single wire-public closed enum on the
    verify-failure surface (callers cannot tell digest-mismatch from
    bad-cosign from missing-binary — that distinction is internal
    log only, per the B2 wire-body-collapse doctrine extended to
    signature failure modes).
    """
    if (
        record.signed_artifact_ref is None
        or record.sigstore_bundle_ref is None
        or record.signature_digest is None
    ):
        return False
    root = Path(settings.model_artifact_root)
    try:
        artefact = _resolve_under_tenant_root(
            relative_ref=record.signed_artifact_ref,
            tenant_id=record.tenant_id,
            root=root,
        )
        bundle = _resolve_under_tenant_root(
            relative_ref=record.sigstore_bundle_ref,
            tenant_id=record.tenant_id,
            root=root,
        )
        trust_root = _resolve_under_tenant_root(
            relative_ref="trust-root.pub",
            tenant_id=record.tenant_id,
            root=root,
        )
    except (ValueError, OSError):
        return False
    # B4 R1 P1 — verify the bundle's actual SHA-256 matches the
    # claim BEFORE running cosign. A mismatch means the chain
    # row's signature_digest would name a hash examiners cannot
    # reproduce by hashing the bundle bytes themselves — broken
    # evidence integrity regardless of cosign's verdict.
    try:
        computed_digest = sigstore_bundle_digest(bundle)
    except OSError:
        return False
    if computed_digest != record.signature_digest:
        _LOG.warning(
            "portal.models.signature_digest_mismatch",
            extra={
                "reason": "signature_digest_mismatch",
                "model_id": record.model_id,
                "tenant_id": record.tenant_id,
                # Never log the actual digest values — would leak
                # the claim shape to log readers. Operators reading
                # the structured log + the chain row separately have
                # the diagnostic context they need.
            },
        )
        return False
    try:
        return await trust_gate.verify_model_signature(
            signed_artifact_path=artefact,
            sigstore_bundle_path=bundle,
            tenant_trust_root=trust_root,
        )
    except ModelSignatureVerificationError:
        return False


# ──────────────────────────────────────────────────────────────────────
# Route factory + 3 handlers.
# ──────────────────────────────────────────────────────────────────────


def build_model_lifecycle_routes(
    *,
    store: ModelRecordStore,
    trust_gate: ModelTrustGate,
    settings: Settings,
) -> APIRouter:
    """Build the model-registry lifecycle router (register / promote /
    retire). Mounted by ``build_models_router`` (B5) under the parent
    ``/api/v1/models`` prefix.

    The factory captures ``store`` / ``trust_gate`` / ``settings`` in
    the closure so handlers do not re-resolve them from
    ``request.app.state`` — eager wiring keeps the dependency injection
    simple + sub-dep cache effective.
    """
    router = APIRouter()

    # Closure-local dependency instances — referenced via
    # ``Annotated[..., Depends(<local>)]`` inside the handlers below.
    # ``from __future__ import annotations`` is intentionally omitted
    # at the module top so FastAPI's signature inspection resolves
    # these names eagerly (not via PEP 563 string-deferred lookup
    # against globals only).
    _require_register = RequireScope("model.register")
    _require_retire = RequireScope("model.retire")
    _require_tenant_ownership = RequireModelTenantOwnership(model_id_param="model_id")

    # ──────────────────────────────────────────────────────────────────
    # POST /  — register (genesis)
    # ──────────────────────────────────────────────────────────────────

    @router.post(
        "",
        summary="Register a new model (genesis: state=proposed)",
        response_model=ModelResponse,
    )
    async def register_model(
        body: RegisterModelRequest,
        actor: Annotated[Actor, Depends(_require_register)],
    ) -> ModelResponse:
        now = datetime.now(UTC)
        record = ModelRecord(
            id=uuid.uuid4(),
            model_id=body.model_id,
            # tenant_id MUST come from the actor, NEVER the body — pin
            # the server-side assignment so a client cannot register a
            # model into another tenant by spoofing the body. Sibling
            # to the DTO-level absence pin at
            # ``test_dto.py::TestRegisterModelRequest::test_tenant_id_absent``.
            tenant_id=actor.tenant_id,
            base_model=body.base_model,
            version=body.version,
            kind=body.kind,
            recipe_hash=body.recipe_hash,
            training_data_fingerprint=body.training_data_fingerprint,
            eval_results_ref=None,
            adversarial_pass_rate=None,
            signature_digest=body.signature_digest,
            signed_artifact_ref=body.signed_artifact_ref,
            sigstore_bundle_ref=body.sigstore_bundle_ref,
            serving_endpoint=body.serving_endpoint,
            # lifecycle_state forced to genesis — mirrors the
            # storage-side A3 R1 P1 initial-state gate
            # ``model_register_initial_state_not_proposed``.
            lifecycle_state="proposed",
            last_actor=actor.subject,
            created_at=now,
            updated_at=now,
        )
        try:
            await store.register(
                record,
                request_id=_mint_request_id(_MODEL_REGISTER_REQUEST_ID_PREFIX),
                actor_id=actor.subject,
                actor_type=actor.actor_type,
            )
        except ModelLifecycleRefused as exc:
            _LOG.warning(
                "portal.models.register_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "model_id": body.model_id,
                    "http_status": 409,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None
        loaded = await store.load_by_model_id(body.model_id)
        # Defensive — should never fire because register() succeeded
        # atomically. Treat as a 500 if it does (kernel-level race).
        if loaded is None:
            raise HTTPException(  # pragma: no cover
                status_code=500, detail={"reason": "register_load_back_failed"}
            )
        return ModelResponse.model_validate(loaded)

    # ──────────────────────────────────────────────────────────────────
    # POST /{model_id}/promote  — body-aware scope + serving human gate
    # ──────────────────────────────────────────────────────────────────

    @router.post(
        "/{model_id}/promote",
        summary=(
            "Promote (body-aware scope: model.promote.<target_state>; "
            "HumanActor gate when target_state=='serving')"
        ),
        response_model=ModelResponse,
    )
    async def promote_model(
        body: PromoteModelRequest,
        record: Annotated[ModelRecord, Depends(_require_tenant_ownership)],
        actor: Annotated[Actor, Depends(bind_actor)],
    ) -> ModelResponse:
        # 1. Body-aware scope resolution. The required scope depends on
        #    body.target_state, so we cannot use a factory-time
        #    RequireScope(...) dep — the check happens here in-handler.
        required_scope = f"model.promote.{body.target_state}"
        if required_scope not in actor.scopes:
            _LOG.warning(
                "portal.models.promote_refused",
                extra={
                    "reason": "scope_not_held",
                    "required_scope": required_scope,
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "http_status": 403,
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "scope_not_held",
                    "required_scope": required_scope,
                    "actor_subject": actor.subject,
                },
            )

        # 2. Body-aware HumanActor gate — promote → serving requires a
        #    human actor; service actors holding the right scope are
        #    refused HERE, BEFORE the storage transition fires.
        #    User-locked B4 pin #1: state MUST NOT advance on this
        #    refusal path.
        if body.target_state == "serving" and actor.actor_type != "human":
            _LOG.warning(
                "portal.models.promote_refused",
                extra={
                    "reason": "actor_type_must_be_human",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "http_status": 403,
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "actor_type_must_be_human",
                    "actor_subject": actor.subject,
                },
            )

        # 3. Cosign verification OUTSIDE the DB transaction (design
        #    spec §2.3) — only for promote_eval_passed. The route
        #    threads the verified refs/digest as expected_* kwargs so
        #    the locked precondition re-checks byte-identical (A4 R1
        #    P1 TOCTOU guard).
        transition = f"promote_{body.target_state}"
        signature_verified: bool | None = None
        if body.target_state == "eval_passed":
            signature_verified = await _verify_record_signature(
                record, settings=settings, trust_gate=trust_gate
            )

        # 4. Storage transition. Refusal mapping mirrors the B2 wire-
        #    body contract: ModelNotFound → 404 model_not_found
        #    (race window); ModelLifecycleRefused → 409 + closed-enum
        #    reason.
        try:
            await store.transition(
                row_id=record.id,
                transition=transition,  # type: ignore[arg-type]
                actor_id=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_MODEL_PROMOTE_REQUEST_ID_PREFIX),
                signature_verified=signature_verified,
                eval_results_ref=body.eval_results_ref,
                adversarial_pass_rate=body.adversarial_pass_rate,
                expected_signed_artifact_ref=(
                    record.signed_artifact_ref if body.target_state == "eval_passed" else None
                ),
                expected_sigstore_bundle_ref=(
                    record.sigstore_bundle_ref if body.target_state == "eval_passed" else None
                ),
                expected_signature_digest=(
                    record.signature_digest if body.target_state == "eval_passed" else None
                ),
            )
        except ModelNotFound:
            # Race: model deleted between the tenant guard's
            # ownership-load and the transition. Should be vanishingly
            # rare; treated as 404 with the canonical wire shape.
            _LOG.warning(
                "portal.models.promote_refused",
                extra={
                    "reason": "model_not_found",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "http_status": 404,
                },
            )
            raise HTTPException(status_code=404, detail={"reason": "model_not_found"}) from None
        except ModelLifecycleRefused as exc:
            _LOG.warning(
                "portal.models.promote_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "from_state": record.lifecycle_state,
                    "target_state": body.target_state,
                    "http_status": 409,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None

        updated = await store.load(record.id)
        if updated is None:
            raise HTTPException(  # pragma: no cover
                status_code=500,
                detail={"reason": "promote_load_back_failed"},
            )
        return ModelResponse.model_validate(updated)

    # ──────────────────────────────────────────────────────────────────
    # POST /{model_id}/retire  — state-aware human gate
    # ──────────────────────────────────────────────────────────────────

    @router.post(
        "/{model_id}/retire",
        summary=("Retire (HumanActor gate when current lifecycle_state == 'serving')"),
        response_model=ModelResponse,
    )
    async def retire_model(
        record: Annotated[ModelRecord, Depends(_require_tenant_ownership)],
        actor: Annotated[Actor, Depends(_require_retire)],
    ) -> ModelResponse:
        # State-aware human gate. Retiring a serving model is a
        # customer-facing action (revoking inference availability);
        # retiring an earlier-state model is mechanical cleanup.
        if record.lifecycle_state == "serving" and actor.actor_type != "human":
            _LOG.warning(
                "portal.models.retire_refused",
                extra={
                    "reason": "actor_type_must_be_human",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "http_status": 403,
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "actor_type_must_be_human",
                    "actor_subject": actor.subject,
                },
            )

        try:
            await store.transition(
                row_id=record.id,
                transition="retire",
                actor_id=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_MODEL_RETIRE_REQUEST_ID_PREFIX),
            )
        except ModelNotFound:
            _LOG.warning(
                "portal.models.retire_refused",
                extra={
                    "reason": "model_not_found",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "http_status": 404,
                },
            )
            raise HTTPException(status_code=404, detail={"reason": "model_not_found"}) from None
        except ModelLifecycleRefused as exc:
            _LOG.warning(
                "portal.models.retire_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": record.model_id,
                    "from_state": record.lifecycle_state,
                    "http_status": 409,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None

        updated = await store.load(record.id)
        if updated is None:
            raise HTTPException(  # pragma: no cover
                status_code=500,
                detail={"reason": "retire_load_back_failed"},
            )
        return ModelResponse.model_validate(updated)

    return router


# ──────────────────────────────────────────────────────────────────────
# Module-foot build-time request-id length invariant.
# ──────────────────────────────────────────────────────────────────────


for _prefix in (
    _MODEL_REGISTER_REQUEST_ID_PREFIX,
    _MODEL_PROMOTE_REQUEST_ID_PREFIX,
    _MODEL_RETIRE_REQUEST_ID_PREFIX,
):
    assert len(_prefix) + 32 <= _REQUEST_ID_MAX_LEN, (
        f"request_id prefix {_prefix!r} would overflow "
        f"decision_history.request_id column cap "
        f"({len(_prefix)} + 32 > {_REQUEST_ID_MAX_LEN})"
    )
del _prefix


__all__ = [
    "build_model_lifecycle_routes",
]
