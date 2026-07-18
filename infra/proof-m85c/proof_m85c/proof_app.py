"""PROOF-ONLY app factory for the M8.5-C live proof (ADR-028 / Cognic Harness v1).

This is the M8.5 proof factory with ONE structural change, and it is the change
the whole milestone turns on:

**THE HEADER BINDER IS GONE.** The M8.5-A/B proof bound identity from an
``X-Proof-Role`` request header — a client-supplied string trusted as an
identity. Design spec §4 rules that out for M8.5-C in the strongest terms it
has: *"No fallback: no actor headers, no shared-secret user impersonation, no
'accept unverified claims in proof mode.' The ``X-Proof-Role`` binder is absent
from the M8.5-C proof entirely."* It is not disabled, not gated, not left in for
a fallback path — it is deleted, and Bar F structurally scans the production
bundle and this proof flow to prove no actor-header path exists anywhere.

Every one of the eight proof identities now arrives the same way a real bank
user would: a REAL Keycloak login (Authorization Code + PKCE) mints a REAL
access token, and :class:`ReferenceOidcBinder` (``overlay_reference/binder.py``)
verifies it locally — signature, issuer, exact audience, authorized party, time
claims, tenant shape, and a closed scope vocabulary — before the kernel sees an
:class:`Actor`. ``actor_type="human"`` is derived from the realm's LOCKED GRANT
PROFILE (no client-credentials grant, no direct-access grant — Bar B proves both
attempts fail), never from a caller-supplied claim.

The reference binder is a WORKED EXAMPLE of a bank overlay, injected here via
``create_app(actor_binder=...)``. It is not shipped in the kernel package and it
does not claim HP-2 (per-bank issuer / claim mapping / assurance level) is
closed — that stays open, and the README says so.

Everything else carries forward from the M8.5 proof factory unchanged:

**A. Eager-injection wiring (the two-engine note).** The packs router, the
configure router, and — new in M8.5-C — the APPROVALS router all mount at
``create_app`` BODY time from kwargs whose stores need a LIVE engine, but
``create_app`` only builds its own adapter engine in the LIFESPAN. So this
factory builds an EAGER :class:`~sqlalchemy.ext.asyncio.AsyncEngine` and passes
the stores it backs as ``create_app(...)`` kwargs. The lifespan still builds the
runtime / MCP host / sandbox backend / skill executor / agent loop / boot
registry on its OWN engine against the SAME Postgres. **Two engines on one DB is
acceptable for a PROOF-ONLY factory** — production would inject ONE engine via a
real bank-overlay deploy.

This matters for approvals specifically, so it is worth being explicit: the
approval request that ``MCPHost.call_tool`` MINTS is written through the
lifespan runtime's engine, while the grant/deny the approvals ROUTER performs
goes through this factory's eager engine. They are two SQLAlchemy engines over
ONE Postgres, so they see the same rows — the four-eyes ledger in Bar D is
coherent because Postgres, not because the two halves share an object.

**B. The approvals surface.** ``create_app(approval_store=...,
approval_assignment_store=..., approval_engine=...)`` mounts
``/api/v1/approvals`` — the surface the harness's approvals screen reads and
acts on, and the surface HP-4 (paginated queue + actor-bound grant replay)
extended. The engine is built with the SYNC :class:`OPAEngine` constructor: the
async ``OPAEngine.create()`` differs only by emitting one ``policy.bundle_loaded``
chain row, which the lifespan's ``build_runtime`` emits anyway from its own
engine — so nothing is lost and the factory stays synchronous, as uvicorn's
``--factory`` entry point requires.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from fastapi import FastAPI

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.portal.rbac.actor import ActorBinder

PROOF_TENANT: Final = "proof-m85c"
#: The FOREIGN tenant (analyst.zara). Present so the read + approval surfaces can
#: prove tenant isolation is the storage WHERE clause, not the scope set.
PROOF_FOREIGN_TENANT: Final = "proof-foreign"

#: Operator env (never image-baked). The issuer is the ONE hostname every caller
#: resolves — in-cluster by the namespace search domain, on the host by an
#: /etc/hosts entry — so one exact `iss` string holds for every token.
_ISSUER_ENV: Final = "COGNIC_PROOF_M85C_OIDC_ISSUER"
#: The per-run proof CA. The binder's discovery + JWKS fetches verify against it;
#: `verify=False` appears nowhere on the human-identity path.
_CA_BUNDLE_ENV: Final = "COGNIC_PROOF_M85C_OIDC_CA_BUNDLE"

#: The kernel pod may boot before Keycloak finishes importing the realm. Fetching
#: discovery + JWKS is a STARTUP concern (never a request-path one), so a bounded
#: retry here turns a benign ordering race into a readable wait instead of a
#: crash-loop. Exhausting it FAILS THE BOOT — there is deliberately no
#: "start without a binder and bind later" path, because that path is exactly the
#: unverified-claims fallback §4 forbids.
_BINDER_BUILD_DEADLINE_S: Final = 300.0
_BINDER_BUILD_INTERVAL_S: Final = 5.0


def _build_actor_binder() -> ActorBinder:
    """Build the reference OIDC binder against the pinned Keycloak realm.

    Fail-loud on missing configuration: a proof kernel that cannot verify tokens
    must not serve. There is no unauthenticated mode, no header mode, and no
    "trust the claims" mode to fall back to.
    """
    from overlay_reference.binder import build_reference_binder

    issuer = os.environ.get(_ISSUER_ENV, "")
    ca_bundle = os.environ.get(_CA_BUNDLE_ENV, "")
    if not issuer:
        raise RuntimeError(
            f"proof-m85c: {_ISSUER_ENV} is unset. The reference OIDC binder is the ONLY "
            "identity path in this proof (spec §4: no actor headers, no fallback), so the "
            "kernel cannot serve without it."
        )
    if not ca_bundle or not Path(ca_bundle).is_file():
        raise RuntimeError(
            f"proof-m85c: {_CA_BUNDLE_ENV}={ca_bundle!r} does not name a readable CA bundle. "
            "The binder verifies Keycloak's TLS against the per-run proof CA; it will not "
            "fall back to an unverified connection."
        )

    deadline = time.monotonic() + _BINDER_BUILD_DEADLINE_S
    last_error: Exception | None = None
    while True:
        try:
            return build_reference_binder(issuer=issuer, verify=ca_bundle)
        except Exception as exc:  # discovery/JWKS not up yet, or genuinely misconfigured
            last_error = exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"proof-m85c: could not build the reference OIDC binder against {issuer} "
                    f"within {_BINDER_BUILD_DEADLINE_S:.0f}s: {exc}"
                ) from last_error
            time.sleep(_BINDER_BUILD_INTERVAL_S)


def create_proof_app() -> FastAPI:
    """Build the PROOF-ONLY app for the M8.5-C live proof.

    Deferred imports keep this module importable (factory-not-called) WITHOUT a
    live engine — every fallible / engine-touching construction happens INSIDE
    the factory body. The factory:

    1. builds an EAGER :class:`~sqlalchemy.ext.asyncio.AsyncEngine` from
       ``settings.database_url`` (the SAME DB the lifespan's adapter engine uses);
    2. builds the operator stores + the runtime-config materializer on it;
    3. builds a real :class:`TrustGate` + the proof-only staged trust-root
       resolver, so the approve 5-gate's SIGNATURE gate cosign-verifies the
       RELEASED, SIGNED packs against a REAL trust root (never stubbed);
    4. builds the ADR-014 approval + assignment stores and assignment-aware
       engine so ``/api/v1/approvals`` mounts;
    5. builds the REFERENCE OIDC BINDER — the only identity path;
    6. calls ``create_app(...)`` with all of the above.

    The plugin registry is NOT eagerly built — the lifespan's boot
    trust-registration populates ``app.state.plugin_registry`` and the install
    gate reads it per request. The SAME lifespan builds the managed sandbox
    runtime, the skill executor, the MCP host (whose approval seam mints the
    high-risk request Bar D drives), and the governed agent loop.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.core.approval.assignments import ApprovalAssignmentStore
    from cognic_agentos.core.approval.engine import ApprovalEngine
    from cognic_agentos.core.approval.policy import ApprovalPolicy
    from cognic_agentos.core.approval.storage import ApprovalRequestStore
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.config import get_settings
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.core.mcp_config.materializer import RuntimeConfigMaterializer
    from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigStore
    from cognic_agentos.core.mcp_config.storage import (
        MCPInternalHostAllowlistStore,
        MCPServerUrlOverrideStore,
    )
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.db.adapters import bundled_registry
    from cognic_agentos.db.adapters.vault_adapter import VaultAdapter
    from cognic_agentos.harness.runtime import _KeyErrorToNoneVaultReader
    from cognic_agentos.packs.storage import PackRecordStore
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.protocol.trust_gate import TrustGate

    settings = get_settings()

    # (1) EAGER engine — the SAME DB URL the lifespan adapter engine uses.
    if not settings.database_url:
        raise RuntimeError(
            "proof-m85c: settings.database_url is unset; the eager operator-store "
            "engine cannot be built. Set COGNIC_DATABASE_URL (the proof Helm "
            "overlay + migrate Job supply it)."
        )
    eager_engine = create_async_engine(settings.database_url)

    audit_store = AuditStore(eager_engine)
    decision_history_store = DecisionHistoryStore(eager_engine)

    # (2) Operator stores + the materializer (SOLE writer of the derived carve-out
    # rows; validates the Vault OAuth/AS refs by reference at install time).
    pack_store = PackRecordStore(eager_engine)
    config_store = PackRuntimeConfigStore(eager_engine)
    override_store = MCPServerUrlOverrideStore(eager_engine)
    allowlist_store = MCPInternalHostAllowlistStore(eager_engine)
    vault_reader = _KeyErrorToNoneVaultReader(
        VaultAdapter(
            addr=settings.vault_addr,
            token=settings.vault_token,
            namespace=settings.vault_namespace,
        )
    )
    materializer = RuntimeConfigMaterializer(
        override_store=override_store,
        allowlist_store=allowlist_store,
        config_store=config_store,
        vault_reader=vault_reader,
    )

    # (3) Real TrustGate + the proof-only staged trust-root resolver. The approve
    # 5-gate's SIGNATURE gate is GENUINELY exercised — it cosign-verifies the
    # released, signed pack against the staged `_default` root baked into the
    # image. The override scope can waive the other four gates; it cannot
    # manufacture a green signature (ADR-012 §110 — signature is non-overridable).
    trust_gate = TrustGate(settings=settings, audit_store=audit_store)
    trust_root_resolver = ProofStagedTrustRootResolver(settings=settings)

    # (4) ADR-014 approval store + engine -> the /api/v1/approvals router mounts.
    # The SYNC OPAEngine constructor is used deliberately (see the module
    # docstring): it loads + hashes the tools.rego bundle and resolves the OPA
    # binary exactly as the async factory does, differing only by the one
    # `policy.bundle_loaded` chain row the lifespan already emits. tools.rego is
    # the REAL tier->flow classifier, so the probe pack's declared
    # `high_risk_custom` tier routes to the genuine ADR-014 four-eyes flow — the
    # proof does not hand-wire the flow it claims to be testing.
    approval_store = ApprovalRequestStore(decision_history_store)
    approval_assignment_store = ApprovalAssignmentStore(decision_history_store)
    approval_engine = ApprovalEngine(
        policy=ApprovalPolicy(
            opa_engine=OPAEngine(
                bundle_path=settings.tools_policy_bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path=settings.opa_path,
                eval_timeout_s=settings.opa_eval_timeout_s,
            )
        ),
        store=approval_store,
        assignments=approval_assignment_store,
        settings=settings,
        clock=lambda: datetime.now(UTC),
    )

    # (5) The ONLY identity path. Built at startup, outside the request path.
    actor_binder = _build_actor_binder()

    # (6) Mount everything.
    app = create_app(
        settings,
        adapter_registry=bundled_registry,
        actor_binder=actor_binder,
        pack_record_store=pack_store,
        runtime_config_store=config_store,
        runtime_config_materializer=materializer,
        trust_gate=trust_gate,
        trust_root_resolver=trust_root_resolver,
        approval_store=approval_store,
        approval_assignment_store=approval_assignment_store,
        approval_engine=approval_engine,
    )
    return app


class ProofStagedTrustRootResolver:
    """PROOF-ONLY :class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`
    — resolves EVERY tenant to the single staged
    ``<trust_root_prefix>/_default/cosign.pub`` trust root baked into the proof
    image.

    This is the SAME ``_default`` cosign trust root the kernel's boot
    trust-registration uses for tools-kind packs, so the approve 5-gate's
    signature gate cosign-verifies the released, signed pack against a REAL trust
    root. The HOOK / SKILL / AGENT packs' DIFFERENT signer keys are staged
    per-pack under ``trust-roots/{hook,skill,agent}-packs/<pack_id>/cosign.pub``
    and consumed by the kernel's boot loop (``registry_boot``), NOT by this
    resolver — none of those packs ever enters the approve flow.

    Production injects a real per-tenant Vault-backed resolver
    (``secret/cognic/<tenant>/trust-root`` per ADR-012 §134); the kernel default
    is fail-loud. This proof-only resolver returns a real staged path so the
    signature gate is GENUINELY exercised (NOT stubbed).
    """

    def __init__(self, *, settings: Settings) -> None:
        self._default_root: Path = Path(settings.trust_root_prefix) / "_default" / "cosign.pub"

    async def resolve_trust_root(self, *, tenant_id: str) -> Path:
        return self._default_root
