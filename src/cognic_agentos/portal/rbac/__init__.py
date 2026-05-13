"""Portal RBAC primitives.

Layer classification: **portal surface** (governance gate sub-layer).

Sprint 7B.2 ships the access-control primitives for the bank-pack lifecycle
portal API per ADR-012 + BUILD_PLAN §622-625:

- :mod:`.scopes` — closed-enum ``PackRBACScope`` + role-group frozensets
  (wire-protocol contract carried in every 403 ``scope_not_held`` body).
- :mod:`.actor` — frozen :class:`Actor` model + pluggable
  :class:`ActorBinder` Protocol + fail-loud :class:`KernelDefaultActorBinder`
  per ADR-008 production-grade-rule (kernel does not assume an auth backend).
- :mod:`.enforcement` — :class:`RequireScope` FastAPI dependency +
  closed-enum :data:`RBACDenialReason` (structured-HTTP denial only in 7B.2;
  hash-chain emission deferred to Sprint 7B.4 per plan Round 5 P3 #5).
- :mod:`.tenant_isolation` — :class:`RequireTenantOwnership` dependency
  factory + closed-enum :data:`TenantIsolationFailure` (404 not 403 —
  info-leak prevention symmetry).
- :mod:`.human_actor` — :class:`RequireHumanActor` dependency (admits
  ``actor.actor_type == "human"``, refuses ``service``).

AGENTS.md "RBAC (``portal/rbac/``)" stop rule — all five modules are
critical controls; closed-enum vocabularies are wire-protocol contracts.
"""
