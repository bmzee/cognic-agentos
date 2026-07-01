"""PROOF-ONLY multi-actor app factory + header-driven binder for Proof M4.

NOT kernel product behavior. Production requires a real bank-overlay
:class:`ActorBinder` (OIDC / mTLS-backed) AND a proper eager-injection deploy
that threads the operator stores + the materializer + the trust gate. This
module ships BOTH proof-only pieces so the deployed **operator-grade pack
install flow** (`submit -> review -> approve -> allow-list -> configure ->
install`, then `disable` / `revoke`) can be driven end-to-end against a real
kernel.

Two crux decisions (see the M4 Task-8 plan §"Key Decisions"):

**A. Eager-injection wiring (the two-engine note).** The packs router (author +
review + operator + inspection + evidence) and the configure router BOTH mount
at ``create_app`` BODY time from kwargs whose stores need a LIVE engine — but
``create_app`` only builds its own adapter engine in the LIFESPAN. So
:func:`create_proof_app` builds an EAGER :class:`~sqlalchemy.ext.asyncio.AsyncEngine`
from ``settings`` + the operator stores + the materializer + a real
:class:`~cognic_agentos.protocol.trust_gate.TrustGate` + a proof-only
:class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`, and
passes them as ``create_app(...)`` kwargs so the two routers mount. The lifespan
still builds the runtime / MCP host / boot registry on its OWN engine (the SAME
Postgres via the same ``COGNIC_*`` DB URL). **Two engines on one DB is
acceptable for a PROOF-ONLY factory** — the eager engine backs the operator API
routes (create/submit/claim/approve/allow-list/configure/install/disable/revoke),
while the lifespan engine backs the boot trust-registration that install gate 2
reads from ``app.state.plugin_registry`` at request time (ADR-026 D6). Production
would inject ONE engine via a real bank-overlay deploy.

**B. Multi-actor binder (header-driven).** :class:`MultiActorProofBinder` reads
the ``X-Proof-Role`` request header and returns a DISTINCT :class:`Actor` per
role — ``author`` / ``reviewer`` / ``operator`` / ``mcp`` — each with its own
subject, scope set, tenant, and actor_type. The ``reviewer`` subject is
deliberately DIFFERENT from the ``author`` subject so
:class:`~cognic_agentos.portal.rbac.role_separation.RequireDifferentActorThanCreator`
passes (a reviewer may not review their own pack). ``operator`` carries
``actor_type="human"`` so :class:`~cognic_agentos.portal.rbac.human_actor.RequireHumanActor`
on the allow-list + configure surfaces passes. The ``reviewer`` carries
``pack.override.approval_gate`` so the happy-path 5-gate approve can override the
four non-signature gates (the signature gate stays genuinely REAL —
cosign-verified against the released, signed pack). Test-header trust is
UNACCEPTABLE in production — this binder is PROOF-ONLY.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

from fastapi import FastAPI, Request

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import (
    MCPRBACScope,
    PackRBACScope,
)

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings

PROOF_TENANT: Final = "proof-m4"

#: The proof role header. The multi-actor binder reads this to pick which role
#: :class:`Actor` to return. PROOF-ONLY — production binders resolve identity
#: from a real auth primitive (OIDC bearer / mTLS cert), never a client header.
PROOF_ROLE_HEADER: Final = "X-Proof-Role"

# ---------------------------------------------------------------------------
# Per-role scope sets. Precise element types (vs a bare ``Final``) so strict
# mypy accepts the standalone constants at the ``Actor(scopes=...)`` call sites:
# a bare ``Final`` infers ``frozenset[str]`` which is NOT assignable to the
# typed ``Actor.scopes`` union field; ``frozenset`` is covariant, so a typed
# ``frozenset[PackRBACScope]`` / ``frozenset[MCPRBACScope]`` IS assignable to
# the wider scope-union field. Same repo idiom as ``MCP_SCOPES`` (scopes.py).
# ---------------------------------------------------------------------------

#: Author role — creates + submits the draft (``pack.submit`` admits
#: CREATE/UPDATE/SUBMIT per the same-tenant author-collaboration policy).
_AUTHOR_SCOPES: Final[frozenset[PackRBACScope]] = frozenset({"pack.submit"})

#: Reviewer role — claims + approves (+ can reject). DISTINCT subject from the
#: author so the role-separation guard passes. Also holds
#: ``pack.override.approval_gate`` because the happy-path approve overrides the
#: four NON-signature gates (evaluation / adversarial / owasp / reviewer-ack)
#: via the override path — and the override scope is checked on the SAME actor
#: that hits the reviewer-scoped ``/approve`` endpoint (``"pack.override.approval_gate"
#: in actor.scopes``). The SIGNATURE gate stays genuinely REAL (non-overridable
#: per ADR-012 §110 — cosign-verified against the released, signed pack), so the
#: override cannot manufacture a green signature; it only skips the four gates
#: whose evidence this proof does not attach. PROOF-ONLY (a real reviewer would
#: attach genuine evaluation / adversarial evidence).
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
#: chain (the materialization-evidence assertions read the DB directly, but the
#: scope keeps the operator a plausible examiner too). The override scope lives
#: on the REVIEWER role (the actor that hits ``/approve``), NOT here.
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

#: MCP caller role — drives the governed MCP invoke route (list + call).
#: ``actor_type="service"`` (a machine principal), mirroring the proof-1b-2c
#: fixed-actor binder.
_MCP_SCOPES: Final[frozenset[MCPRBACScope]] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})


def _author_actor() -> Actor:
    return Actor(
        subject="proof-m4-author",
        tenant_id=PROOF_TENANT,
        scopes=_AUTHOR_SCOPES,
        actor_type="human",
    )


def _reviewer_actor() -> Actor:
    # Subject DIFFERS from the author (role-separation: a reviewer may not
    # review their own pack — RequireDifferentActorThanCreator).
    return Actor(
        subject="proof-m4-reviewer",
        tenant_id=PROOF_TENANT,
        scopes=_REVIEWER_SCOPES,
        actor_type="human",
    )


def _operator_actor() -> Actor:
    return Actor(
        subject="proof-m4-operator",
        tenant_id=PROOF_TENANT,
        scopes=_OPERATOR_SCOPES,
        actor_type="human",
    )


def _mcp_actor() -> Actor:
    return Actor(
        subject="proof-m4-mcp",
        tenant_id=PROOF_TENANT,
        scopes=_MCP_SCOPES,
        actor_type="service",
    )


class UnknownProofRole(Exception):
    """Raised by :meth:`MultiActorProofBinder.bind` when the ``X-Proof-Role``
    header is absent or names an unknown role — the request cannot be bound to a
    proof actor. Fail-loud (NOT a silent default) so a mis-headed proof step
    surfaces immediately instead of running under the wrong identity."""


class MultiActorProofBinder:
    """Header-driven multi-actor binder. PROOF-ONLY.

    Reads the ``X-Proof-Role`` header and returns the matching role
    :class:`Actor`. The 4 roles cover the full operator lifecycle:

    - ``author``   — ``pack.submit`` (create + submit the draft);
    - ``reviewer`` — ``pack.review.{claim,approve,reject}``, DISTINCT subject
      from the author (role-separation);
    - ``operator`` — the 6 operator scopes + ``pack.audit.read``,
      ``actor_type="human"`` (allow-list / configure human-actor gates). The
      5-gate override scope lives on ``reviewer`` because ``/approve`` is the
      reviewer-scoped endpoint;
    - ``mcp``      — ``mcp.tool.{list,invoke}``, ``actor_type="service"`` (the
      governed MCP invoke route).

    An absent / unknown role raises :class:`UnknownProofRole` (fail-loud). This
    binder is PROOF-ONLY: production resolves identity from a real auth primitive,
    NEVER a client-supplied header.
    """

    #: Role -> zero-arg Actor factory. Exactly 4 entries.
    _FACTORIES: Final = {
        "author": _author_actor,
        "reviewer": _reviewer_actor,
        "operator": _operator_actor,
        "mcp": _mcp_actor,
    }

    def bind(self, *, request: Request | None) -> Actor:  # matches the kernel ActorBinder Protocol
        role = None if request is None else request.headers.get(PROOF_ROLE_HEADER)
        factory = self._FACTORIES.get(role) if role is not None else None
        if factory is None:
            raise UnknownProofRole(
                f"proof-m4: no proof actor for {PROOF_ROLE_HEADER}={role!r}; "
                f"expected one of {sorted(self._FACTORIES)}"
            )
        return factory()

    @classmethod
    def role_actors(cls) -> dict[str, Actor]:
        """All 4 role actors (for the structural pins). PROOF-ONLY."""
        return {role: factory() for role, factory in cls._FACTORIES.items()}


def create_proof_app() -> FastAPI:
    """Build the PROOF-ONLY multi-actor operator-install app.

    **Eager-injection wiring (Key Decision A).** Deferred imports keep this
    module importable (factory-not-called) WITHOUT a live engine — every
    fallible / engine-touching construction happens INSIDE the factory body
    (mirrors ``proof_1b_2c.proof_app``). The factory:

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
       gate resolves GENUINELY (cosign-verifies the released, signed pack against
       the staged ``/opt/cognic/trust-roots/_default`` root);
    4. calls ``create_app(adapter_registry=bundled_registry, ...)`` with those
       instances so the packs router (incl. the approve 5-gate) + the configure
       router mount at BODY time, and sets ``app.state.actor_binder`` to the
       multi-actor binder.

    The plugin registry is NOT eagerly built — it is REQUEST-time (Task 7): the
    lifespan's boot trust-registration populates ``app.state.plugin_registry``
    and install gate 2 reads it per-request. The lifespan builds its OWN runtime
    (its own engine, same DB); its ``app.state.runtime_config_store`` /
    ``runtime_config_materializer`` overwrite (create_app.app.py) is harmless —
    the BODY-mounted operator routes closed over the EAGER instances at mount
    time.

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
            "proof-m4: settings.database_url is unset; the eager operator-store "
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
    # 5-gate's SIGNATURE gate resolves GENUINELY (the released pack is
    # cosign-signed; the staged attestations + trust root are baked into the
    # image at /opt/cognic by Dockerfile.agentos-proof). TrustGate needs an
    # AuditStore (cosign-verify emits an audit event) — build one on the eager
    # engine; the same signature_root_path / trust_root_prefix env the boot
    # trust-registration uses applies.
    trust_gate = TrustGate(settings=settings, audit_store=AuditStore(eager_engine))
    trust_root_resolver = ProofStagedTrustRootResolver(settings=settings)

    # (4) Mount the packs + configure routers via the create_app kwargs; the
    # lifespan builds the boot registry (request-time gate 2) on its own engine.
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
    image (``COPY proof-m4-staging/trust-roots/
    /opt/cognic/trust-roots/`` + ``COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots``).

    This is the SAME ``_default`` cosign trust root the kernel's boot
    trust-registration uses (the released pack's ``cosign.pub``), so the approve
    5-gate's signature gate cosign-verifies the released, signed pack against a
    REAL trust root. Production injects a real per-tenant Vault-backed resolver
    (``secret/cognic/<tenant>/trust-root`` per ADR-012 §134); the kernel default
    is fail-loud. This proof-only resolver returns a real staged path so the
    signature gate is GENUINELY exercised (NOT stubbed).
    """

    def __init__(self, *, settings: Settings) -> None:
        # ``settings.trust_root_prefix`` is the operator-approved root prefix the
        # TrustGate canonicalises the trust root under; boot registration uses
        # the same locked convention: ``_default/cosign.pub``.
        self._default_root: Path = Path(settings.trust_root_prefix) / "_default" / "cosign.pub"

    async def resolve_trust_root(self, *, tenant_id: str) -> Path:
        # Every proof tenant resolves to the single staged _default root.
        return self._default_root
