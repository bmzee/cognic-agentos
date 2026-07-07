"""PROOF-ONLY multi-actor app factory + header-driven binder for Proof M8.

NOT kernel product behavior. Production requires a real bank-overlay
:class:`ActorBinder` (OIDC / mTLS-backed) AND a proper eager-injection deploy
that threads the operator stores + the materializer + the trust gate. This
module is the M8 mirror of ``infra/proof-m6/proof_m6/proof_app.py`` — the
SAME shape (the two crux decisions below carry forward unchanged) with the M8
tenant + role identities and the TWO M8 deltas:

* **Two ANALYST actors** — ``analyst.amir`` + ``analyst.sara`` — each carrying
  ONLY the ``agent.ask`` scope (``portal/rbac/scopes.py::AgentRBACScope``).
  The six bars ride these two identities: the kernel-side entitlement matrix
  (migration-0014 ``entitlements`` rows, seeded by ``kernel-seed.sql``) keys
  on EXACTLY these ``Actor.subject`` strings — amir is entitled to
  ``retail_analytics + financials``, sara to ``cards_analytics +
  retail_analytics`` — and the A10 dispatch chokepoint reads the subject off
  the bound Actor (never the request body), so the m:n split the bars assert
  is enforced kernel-side per request identity.
* The ``mcp`` role drops M6's ``skill.invoke`` (no M8 bar invokes an
  executable skill — all four staged skills are instruction-mode) and keeps
  the two governed MCP scopes for the SETUP warm-up ``list_tools`` probe.

**Deliberately NO agent-specific logic here.** The M8 delta is entirely
kernel-side: the ``create_app`` LIFESPAN constructs the managed sandbox
runtime + the skill executor (the M6 posture, unchanged — the hosted_skills
surface Step 0 asserts), then the governed agent loop
(``harness/agent_host.build_agent_loop`` -> ``app.state.agent_loop`` +
``app.state.hosted_agents``) over the boot-trusted registry + the MCP host +
the LLM gateway + the governed memory factory, reading the query-context
SIGNING key from the runtime Secret mount
(``COGNIC_AGENT_QUERY_CONTEXT_SIGNING_KEY_PATH``).

Two crux decisions (see the M4 Task-8 plan §"Key Decisions"):

**A. Eager-injection wiring (the two-engine note).** The packs router (author +
review + operator + inspection + evidence) and the configure router BOTH mount
at ``create_app`` BODY time from kwargs whose stores need a LIVE engine — but
``create_app`` only builds its own adapter engine in the LIFESPAN. So
:func:`create_proof_app` builds an EAGER :class:`~sqlalchemy.ext.asyncio.AsyncEngine`
from ``settings`` + the operator stores + the materializer + a real
:class:`~cognic_agentos.protocol.trust_gate.TrustGate` + a proof-only
:class:`ProofStagedTrustRootResolver`, and passes them as ``create_app(...)``
kwargs so the two routers mount. The lifespan still builds the runtime / MCP
host / sandbox backend / skill executor / agent loop / boot registry on its
OWN engine (the SAME Postgres via the same ``COGNIC_*`` DB URL). **Two engines
on one DB is acceptable for a PROOF-ONLY factory** — production would inject
ONE engine via a real bank-overlay deploy.

**B. Multi-actor binder (header-driven).** :class:`MultiActorProofBinder` reads
the ``X-Proof-Role`` request header and returns a DISTINCT :class:`Actor` per
role — ``author`` / ``reviewer`` / ``operator`` / ``mcp`` / ``amir`` /
``sara``. The ``reviewer`` subject is deliberately DIFFERENT from the
``author`` subject so role-separation passes; ``operator`` carries
``actor_type="human"`` for the allow-list + configure human-actor gates; the
``reviewer`` carries ``pack.override.approval_gate`` so the happy-path 5-gate
approve can override the four non-signature gates (the signature gate stays
genuinely REAL — cosign-verified against the released, signed pack).
Test-header trust is UNACCEPTABLE in production — this binder is PROOF-ONLY.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

from fastapi import FastAPI, Request

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import (
    AgentRBACScope,
    MCPRBACScope,
    PackRBACScope,
)

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings

PROOF_TENANT: Final = "proof-m8"

#: The proof role header. The multi-actor binder reads this to pick which role
#: :class:`Actor` to return. PROOF-ONLY — production binders resolve identity
#: from a real auth primitive (OIDC bearer / mTLS cert), never a client header.
PROOF_ROLE_HEADER: Final = "X-Proof-Role"

# ---------------------------------------------------------------------------
# Per-role scope sets. Precise element types (vs a bare ``Final``) so strict
# mypy accepts the standalone constants at the ``Actor(scopes=...)`` call
# sites: a bare ``Final`` infers ``frozenset[str]`` which is NOT assignable to
# the typed ``Actor.scopes`` union field; ``frozenset`` is covariant, so a
# typed ``frozenset[PackRBACScope]`` / ``frozenset[MCPRBACScope]`` /
# ``frozenset[AgentRBACScope]`` IS assignable to the wider scope-union field.
# Same repo idiom as ``MCP_SCOPES`` / ``AGENT_SCOPES`` (scopes.py).
# ---------------------------------------------------------------------------

#: Author role — creates + submits the draft (``pack.submit`` admits
#: CREATE/UPDATE/SUBMIT per the same-tenant author-collaboration policy).
_AUTHOR_SCOPES: Final[frozenset[PackRBACScope]] = frozenset({"pack.submit"})

#: Reviewer role — claims + approves (+ can reject). DISTINCT subject from the
#: author so the role-separation guard passes. Also holds
#: ``pack.override.approval_gate`` because the happy-path approve overrides the
#: four NON-signature gates (evaluation / adversarial / owasp / reviewer-ack)
#: via the override path — and the override scope is checked on the SAME actor
#: that hits the reviewer-scoped ``/approve`` endpoint. The SIGNATURE gate
#: stays genuinely REAL (non-overridable per ADR-012 §110 — cosign-verified
#: against the released, signed v0.3.0 pack), so the override cannot
#: manufacture a green signature. PROOF-ONLY (a real reviewer would attach
#: genuine evaluation / adversarial evidence).
_REVIEWER_SCOPES: Final[frozenset[PackRBACScope]] = frozenset(
    {
        "pack.review.claim",
        "pack.review.approve",
        "pack.review.reject",
        "pack.override.approval_gate",
    }
)

#: Operator role — the lifecycle-operator scopes
#: (allow_list + configure + install + disable + revoke + uninstall).
#: ``actor_type="human"`` so the ``RequireHumanActor`` gate on allow-list +
#: configure passes. ``pack.audit.read`` lets the operator read the pack audit
#: chain (the bar evidence assertions read the DB directly, but the scope keeps
#: the operator a plausible examiner too).
_OPERATOR_SCOPES: Final[frozenset[PackRBACScope]] = frozenset(
    {
        "pack.allow_list",
        "pack.configure",
        "pack.install",
        "pack.disable",
        "pack.revoke",
        "pack.uninstall",
        "pack.audit.read",
    }
)

#: MCP caller role — the SETUP warm-up probe only (``GET
#: /api/v1/mcp/servers/{id}/tools`` warms the per-tenant OAuth token +
#: list_tools cache so a carve-out failure surfaces as a clear MCP error, not
#: an opaque agent 502). NO ``skill.invoke`` (the M6 -> M8 delta: no M8 bar
#: invokes an executable skill). ``actor_type="service"`` (machine principal).
_MCP_SCOPES: Final[frozenset[MCPRBACScope]] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})

#: Analyst roles — the M8 bars' asking identities. ONLY ``agent.ask``: an
#: analyst can drive the governed loop and nothing else (no pack lifecycle, no
#: raw MCP invoke). The kernel-side entitlement matrix keys on the SUBJECT
#: strings below; the two Actors differ ONLY by subject (m:n proven on
#: identity, not on scope shape).
_ANALYST_SCOPES: Final[frozenset[AgentRBACScope]] = frozenset({"agent.ask"})


def _author_actor() -> Actor:
    return Actor(
        subject="proof-m8-author",
        tenant_id=PROOF_TENANT,
        scopes=_AUTHOR_SCOPES,
        actor_type="human",
    )


def _reviewer_actor() -> Actor:
    # Subject DIFFERS from the author (role-separation: a reviewer may not
    # review their own pack — RequireDifferentActorThanCreator).
    return Actor(
        subject="proof-m8-reviewer",
        tenant_id=PROOF_TENANT,
        scopes=_REVIEWER_SCOPES,
        actor_type="human",
    )


def _operator_actor() -> Actor:
    return Actor(
        subject="proof-m8-operator",
        tenant_id=PROOF_TENANT,
        scopes=_OPERATOR_SCOPES,
        actor_type="human",
    )


def _mcp_actor() -> Actor:
    return Actor(
        subject="proof-m8-mcp",
        tenant_id=PROOF_TENANT,
        scopes=_MCP_SCOPES,
        actor_type="service",
    )


def _amir_actor() -> Actor:
    # The multi-scope analyst: entitled (kernel-side, seeded) to
    # retail_analytics + financials; NEVER cards_analytics / atm_recon.
    return Actor(
        subject="analyst.amir",
        tenant_id=PROOF_TENANT,
        scopes=_ANALYST_SCOPES,
        actor_type="human",
    )


def _sara_actor() -> Actor:
    # The shared-scope analyst: entitled (kernel-side, seeded) to
    # cards_analytics + retail_analytics (retail shared with amir — the m:n
    # second direction); NEVER financials / atm_recon.
    return Actor(
        subject="analyst.sara",
        tenant_id=PROOF_TENANT,
        scopes=_ANALYST_SCOPES,
        actor_type="human",
    )


class UnknownProofRole(Exception):
    """Raised by :meth:`MultiActorProofBinder.bind` when the ``X-Proof-Role``
    header is absent or names an unknown role — the request cannot be bound to
    a proof actor. Fail-loud (NOT a silent default) so a mis-headed proof step
    surfaces immediately instead of running under the wrong identity (an
    entitlement bar asserted under the wrong analyst would be a false
    result)."""


class MultiActorProofBinder:
    """Header-driven multi-actor binder. PROOF-ONLY.

    Reads the ``X-Proof-Role`` header and returns the matching role
    :class:`Actor`. The 6 roles cover the full operator lifecycle plus the
    governed MCP warm-up plus the two analyst identities the six M8 bars
    drive:

    - ``author``   — ``pack.submit`` (create + submit the draft);
    - ``reviewer`` — ``pack.review.{claim,approve,reject}`` +
      ``pack.override.approval_gate``, DISTINCT subject from the author;
    - ``operator`` — the 6 operator scopes + ``pack.audit.read``,
      ``actor_type="human"`` (allow-list / configure human-actor gates);
    - ``mcp``      — ``mcp.tool.{list,invoke}`` (the SETUP warm-up probe);
    - ``amir``     — ``agent.ask`` as ``analyst.amir`` (retail + fin scopes);
    - ``sara``     — ``agent.ask`` as ``analyst.sara`` (cards + retail).

    An absent / unknown role raises :class:`UnknownProofRole` (fail-loud).
    This binder is PROOF-ONLY: production resolves identity from a real auth
    primitive, NEVER a client-supplied header.
    """

    #: Role -> zero-arg Actor factory. Exactly 6 entries.
    _FACTORIES: Final = {
        "author": _author_actor,
        "reviewer": _reviewer_actor,
        "operator": _operator_actor,
        "mcp": _mcp_actor,
        "amir": _amir_actor,
        "sara": _sara_actor,
    }

    def bind(self, *, request: Request | None) -> Actor:  # matches the kernel ActorBinder Protocol
        role = None if request is None else request.headers.get(PROOF_ROLE_HEADER)
        factory = self._FACTORIES.get(role) if role is not None else None
        if factory is None:
            raise UnknownProofRole(
                f"proof-m8: no proof actor for {PROOF_ROLE_HEADER}={role!r}; "
                f"expected one of {sorted(self._FACTORIES)}"
            )
        return factory()

    @classmethod
    def role_actors(cls) -> dict[str, Actor]:
        """All 6 role actors (for the structural pins). PROOF-ONLY."""
        return {role: factory() for role, factory in cls._FACTORIES.items()}


def create_proof_app() -> FastAPI:
    """Build the PROOF-ONLY multi-actor app for the M8 governed-agent-loop proof.

    **Eager-injection wiring (Key Decision A).** Deferred imports keep this
    module importable (factory-not-called) WITHOUT a live engine — every
    fallible / engine-touching construction happens INSIDE the factory body
    (mirrors ``proof_m6.proof_app``). The factory:

    1. builds an EAGER :class:`~sqlalchemy.ext.asyncio.AsyncEngine` from
       ``settings.database_url`` (the SAME DB URL the lifespan's adapter engine
       would use — two engines, one Postgres; PROOF-ONLY);
    2. builds the operator stores on that eager engine
       (:class:`PackRecordStore` + :class:`PackRuntimeConfigStore` +
       :class:`MCPServerUrlOverrideStore` + :class:`MCPInternalHostAllowlistStore`)
       + a :class:`RuntimeConfigMaterializer` whose ``vault_reader`` is the
       KeyError->None shim around a real :class:`VaultAdapter`
       (validate-refs-by-reference at install time);
    3. builds a real :class:`TrustGate` + a proof-only
       :class:`ProofStagedTrustRootResolver` so the approve 5-gate's signature
       gate resolves GENUINELY (cosign-verifies the released, signed
       ``v0.3.0`` pack against the staged ``_default`` trust root);
    4. calls ``create_app(adapter_registry=bundled_registry, ...)`` with those
       instances so the packs router (incl. the approve 5-gate) + the configure
       router mount at BODY time, and sets the multi-actor binder.

    The plugin registry is NOT eagerly built — it is REQUEST-time: the
    lifespan's boot trust-registration populates ``app.state.plugin_registry``
    and install gate 2 reads it per-request. The SAME lifespan builds the M6
    managed sandbox runtime + skill executor (unchanged posture — the
    hosted_skills surface) AND the M8 governed agent loop
    (``build_agent_loop`` -> ``app.state.agent_loop`` +
    ``app.state.hosted_agents``) — no agent-specific wiring lives in this
    factory. The lifespan builds its OWN runtime (its own engine, same DB);
    its ``app.state.runtime_config_store`` / ``runtime_config_materializer``
    overwrite (create_app.app.py) is harmless — the BODY-mounted operator
    routes closed over the EAGER instances at mount time.

    Production uses a real bank-overlay binder + a proper single-engine
    eager-injection deploy; this factory is PROOF-ONLY.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.config import get_settings
    from cognic_agentos.core.mcp_config.materializer import RuntimeConfigMaterializer
    from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigStore
    from cognic_agentos.core.mcp_config.storage import (
        MCPInternalHostAllowlistStore,
        MCPServerUrlOverrideStore,
    )
    from cognic_agentos.db.adapters import bundled_registry
    from cognic_agentos.db.adapters.vault_adapter import VaultAdapter
    from cognic_agentos.harness.runtime import _KeyErrorToNoneVaultReader
    from cognic_agentos.packs.storage import PackRecordStore
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.protocol.trust_gate import TrustGate

    settings = get_settings()

    # (1) EAGER engine — the SAME DB URL the lifespan adapter engine uses. Two
    # engines on one Postgres (PROOF-ONLY): this one backs the BODY-mounted
    # operator API routes; the lifespan engine backs the boot trust-registration.
    if not settings.database_url:
        raise RuntimeError(
            "proof-m8: settings.database_url is unset; the eager operator-store "
            "engine cannot be built. Set COGNIC_DATABASE_URL (the proof Helm "
            "overlay + migrate Job supply it)."
        )
    eager_engine = create_async_engine(settings.database_url)

    # (2) Operator stores on the eager engine + the materializer (SOLE writer of
    # the derived carve-out rows; validates the Vault OAuth/AS refs by reference).
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

    # (3) Real TrustGate + proof-only staged trust-root resolver so the approve
    # 5-gate's SIGNATURE gate resolves GENUINELY (the released v0.3.0 pack is
    # cosign-signed; the staged attestations + trust root are baked into the
    # image at /opt/cognic by Dockerfile.agentos-proof). TrustGate needs an
    # AuditStore (cosign-verify emits an audit event) — build one on the eager
    # engine; the same signature_root_path / trust_root_prefix env the boot
    # trust-registration uses applies.
    trust_gate = TrustGate(settings=settings, audit_store=AuditStore(eager_engine))
    trust_root_resolver = ProofStagedTrustRootResolver(settings=settings)

    # (4) Mount the packs + configure routers via the create_app kwargs; the
    # lifespan builds the boot registry (request-time gate 2) + the sandbox
    # runtime + the skill executor + the MCP host + the agent loop on its own
    # engine.
    app = create_app(
        settings,
        adapter_registry=bundled_registry,
        actor_binder=MultiActorProofBinder(),
        pack_record_store=pack_store,
        runtime_config_store=config_store,
        runtime_config_materializer=materializer,
        trust_gate=trust_gate,
        trust_root_resolver=trust_root_resolver,
    )
    return app


class ProofStagedTrustRootResolver:
    """PROOF-ONLY :class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`
    — resolves EVERY tenant to the single staged
    ``<trust_root_prefix>/_default/cosign.pub`` trust root baked into the proof
    image (``COPY proof-m8-staging/trust-roots/
    /opt/cognic/trust-roots/`` + ``COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots``).

    This is the SAME ``_default`` cosign trust root the kernel's boot
    trust-registration uses for tools-kind packs (the released ORACLE pack's
    ``cosign.pub``), so the approve 5-gate's signature gate cosign-verifies
    the released, signed ``v0.3.0`` pack against a REAL trust root. The HOOK /
    four SKILL / AGENT packs' DIFFERENT signer keys are staged per-pack at
    ``trust-roots/hook-packs/<pack_id>/cosign.pub``,
    ``trust-roots/skill-packs/<pack_id>/cosign.pub`` and
    ``trust-roots/agent-packs/<pack_id>/cosign.pub`` (+ the dual-root
    ``agent-card.pub``) and consumed by the kernel's boot loop
    (``registry_boot``), NOT by this resolver — none of those packs ever
    enters the approve flow (trust-register + registry-admit + hosting only).
    Production injects a real per-tenant Vault-backed resolver
    (``secret/cognic/<tenant>/trust-root`` per ADR-012 §134); the kernel
    default is fail-loud. This proof-only resolver returns a real staged path
    so the signature gate is GENUINELY exercised (NOT stubbed).
    """

    def __init__(self, *, settings: Settings) -> None:
        # ``settings.trust_root_prefix`` is the operator-approved root prefix the
        # TrustGate canonicalises the trust root under; boot registration uses
        # the same locked convention: ``_default/cosign.pub``.
        self._default_root: Path = Path(settings.trust_root_prefix) / "_default" / "cosign.pub"

    async def resolve_trust_root(self, *, tenant_id: str) -> Path:
        # Every proof tenant resolves to the single staged _default root.
        return self._default_root
