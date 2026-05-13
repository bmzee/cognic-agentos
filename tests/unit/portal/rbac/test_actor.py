"""Sprint 7B.2 T2 — Actor + ActorBinder Protocol + ActorType + kernel-default fail-loud.

Pins:

- :data:`Actor` is an immutable Pydantic v2 model (``frozen=True``).
- :data:`ActorType` is a 2-value closed-enum Literal (``"human"`` / ``"service"``)
  per plan Round 1 P3 #8.
- :attr:`Actor.actor_type` carries the type discriminator that drives
  :class:`RequireHumanActor` (operator-surface human-only gate).
- :class:`ActorBinder` is a Protocol — kernel ships only the protocol + a
  fail-loud default per ADR-008 production-grade-rule; bank overlays inject
  a real binder via ``create_app(actor_binder=...)``.
- :class:`KernelDefaultActorBinder.bind` raises :class:`NotImplementedError`
  citing ADR-008 — distinct from :class:`ActorBinderUnauthenticated` which a
  real binder raises on per-request auth failure (plan Round 3 P2 #2 emit
  path for the :data:`RBACDenialReason` value ``actor_unauthenticated``).
- :class:`ActorBinderUnauthenticated` is its own exception class (NOT a
  subclass of ``NotImplementedError``) so :class:`RequireScope` can dispatch
  on class to distinguish kernel-misconfig (500) from per-request auth
  failure (403).
"""

from __future__ import annotations

from typing import get_args

import pydantic
import pytest

from cognic_agentos.portal.rbac.actor import (
    Actor,
    ActorBinder,
    ActorBinderUnauthenticated,
    ActorType,
    KernelDefaultActorBinder,
)


def test_actor_type_literal_frozen_at_2_values() -> None:
    """Plan Round 1 P3 #8 — exactly 2 actor-type values."""
    assert set(get_args(ActorType)) == {"human", "service"}


def test_actor_is_frozen_and_carries_actor_type() -> None:
    actor = Actor(
        subject="alice@bank.example",
        tenant_id="t1",
        scopes=frozenset({"pack.submit"}),
        actor_type="human",
    )
    assert actor.actor_type == "human"
    assert actor.subject == "alice@bank.example"
    assert actor.tenant_id == "t1"
    assert actor.scopes == frozenset({"pack.submit"})
    # frozen=True: mutation must raise (Pydantic v2 raises ValidationError).
    with pytest.raises(pydantic.ValidationError):
        actor.subject = "bob@bank.example"


def test_actor_rejects_invalid_actor_type() -> None:
    """Closed-enum stability — out-of-vocab actor_type refused at construction."""
    with pytest.raises(pydantic.ValidationError):
        Actor(
            subject="x",
            tenant_id="t1",
            scopes=frozenset(),
            actor_type="robot",  # type: ignore[arg-type]
        )


def test_actor_accepts_service_actor_type() -> None:
    """Closed-enum admits both human + service; partition is mutually exhaustive."""
    actor = Actor(
        subject="svc-account-1",
        tenant_id="t1",
        scopes=frozenset({"pack.invocation.read"}),
        actor_type="service",
    )
    assert actor.actor_type == "service"


def test_actor_extra_fields_forbidden() -> None:
    """Wire-shape pin — unknown fields refused so a bank-overlay binder
    cannot smuggle extra claims through the Actor model without an
    explicit kernel update."""
    with pytest.raises(pydantic.ValidationError):
        Actor(  # type: ignore[call-arg]
            subject="x",
            tenant_id="t1",
            scopes=frozenset(),
            actor_type="human",
            roles=["author"],  # unknown field
        )


def test_kernel_default_binder_fails_loud() -> None:
    """Production-grade-rule — kernel ships a fail-loud default, NOT a
    silent identity fallback. The ``NotImplementedError`` cites ADR-008
    so an examiner can trace the missing-overlay misconfig back to the
    authoring-platform contract."""
    binder: ActorBinder = KernelDefaultActorBinder()
    with pytest.raises(NotImplementedError) as exc:
        binder.bind(request=None)  # type: ignore[arg-type]
    assert "ADR-008" in str(exc.value)


def test_actor_binder_unauthenticated_is_distinct_from_not_implemented() -> None:
    """Plan Round 3 P2 #2 — :class:`ActorBinderUnauthenticated` is a
    distinct exception class so :class:`RequireScope` can dispatch on
    class to distinguish kernel-misconfig (500) from per-request auth
    failure (403). Must NOT subclass :class:`NotImplementedError`."""
    assert not issubclass(ActorBinderUnauthenticated, NotImplementedError)
    exc = ActorBinderUnauthenticated("missing bearer token")
    assert isinstance(exc, Exception)


def test_actor_binder_protocol_runtime_check() -> None:
    """The kernel-default binder must satisfy :class:`ActorBinder`. We rely
    on structural matching (Protocol) rather than ``isinstance`` here
    because :class:`ActorBinder` is not declared ``@runtime_checkable``
    — but assigning to an :class:`ActorBinder`-annotated variable proves
    the shape matches at the type-checker level."""
    binder: ActorBinder = KernelDefaultActorBinder()
    # Smoke-call to ensure ``.bind(request=...)`` is the wire-shape.
    with pytest.raises(NotImplementedError):
        binder.bind(request=None)  # type: ignore[arg-type]
