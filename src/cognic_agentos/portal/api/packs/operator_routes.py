"""Sprint 7B.2 T6 — operator surface endpoints (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md``
§"Task 6: Operator surface endpoints" — ships the 5 operator-surface
endpoints behind ``/api/v1/packs``:

- ``POST   /{pack_id}/allow-list`` — gated by ``pack.allow_list`` +
  tenant + :func:`RequireHumanActor` per Round 1 P3 #8;
  transition ``approved → allow_listed``.
- ``POST   /{pack_id}/install`` — gated by ``pack.install`` + tenant;
  transition ``allow_listed → installed``.
- ``POST   /{pack_id}/disable`` — gated by ``pack.disable`` + tenant;
  transition ``installed → disabled``.
- ``POST   /{pack_id}/revoke`` — gated by ``pack.revoke`` + tenant;
  multi-from transition ``installed/disabled → revoked``.
- ``DELETE /{pack_id}/install`` — gated by ``pack.uninstall`` + tenant;
  multi-from transition ``disabled/revoked → uninstalled`` (the
  uninstall verb shares the ``/install`` path with method=DELETE
  per the plan endpoint table).

**T6 deliverable (post-slice-4) — all 5 operator handlers are real
implementations**. The bones-first slicing pattern (slice 1 — route
table + 501 stubs; slices 2-4 — per-verb handler bodies) landed
incrementally within the same T6 commit; in the final shape there are
no 501 stubs left in this module. Each handler shares the same
delegate-to-storage pattern: try ``store.transition(...)`` → catch
:class:`PackNotFound` → 404 + ``portal.packs.<verb>_refused`` log →
catch :class:`LifecycleTransitionRefused` → 409 + closed-enum reason
+ ``portal.packs.<verb>_refused`` log → green path returns the
re-loaded :class:`PackResponse`. The allow-list handler additionally
emits the green-path ``portal.packs.allow_list`` log carrying
``actor_type`` per R24 watchpoint (d) examiner-traceability surface.

**R24 Path B + B2 actor_type carry-forward**: every handler threads
``actor_type=actor.actor_type`` into ``store.transition(...)``.
The amended :meth:`PackRecordStore.transition` (``packs/storage.py``)
persists the actor_type as a top-level ``payload["actor_type"]`` key
conditionally (key omitted entirely when the kwarg is ``None``, so
existing call sites + every pre-T6 chain row stay byte-shape
compatible). This single payload-key surface gives examiners the
human-actor evidence on the allow-list audit row without requiring
log correlation across surfaces.

**Standing-offer §30 — module-header invariant**: ``from __future__
import annotations`` is INTENTIONALLY OMITTED here (same as
``portal/rbac/role_separation.py``, ``portal/api/packs/author_routes.py``,
``portal/api/packs/review_routes.py``). PEP 563 string-deferred
annotations would prevent FastAPI's ``inspect.signature()`` /
``typing.get_type_hints()`` from resolving
``Annotated[..., Depends(<local-var>)]`` annotations on the inner
endpoint handlers (the shared dependency instances like
``_require_pack_allow_list`` are LOCAL variables inside
:func:`build_operator_routes`, NOT module globals). A regression that
adds the future-import would make FastAPI silently fall back to
treating handler parameters as query params — exactly the bug
R15 P2 #1 pinned for ``role_separation.py``, then again caught
mid-cycle in T5 slice 2a when ``review_routes.py`` shipped with the
future-import. Pinned by an AST self-test + per-verb invocation tests
in ``tests/unit/portal/api/packs/test_operator_routes.py`` per
``feedback_security_regression_hardening.md``.

**Plan Round 18 P2 #4 + Round 19 P3 #3 — request_id minters**: T6
declares 5 new request-id prefix constants (one per verb) at module
scope. All 5 cross-import :func:`_mint_request_id` from
``author_routes.py:98`` as a single source of truth for the minter.
Per-prefix lengths are 13 chars each (NOT uniform with T4/T5's 12
chars per Plan Round 19 P3 #3 — false-uniformity coupling was
explicitly rejected); the invariant is ``len(prefix) + 32 <= 64``
pinned by the module-foot build-time ``assert`` so any future drift
that overflows the ``decision_history.request_id`` String(64) column
cap refuses module load at import.
"""

import logging
from collections.abc import Iterator
from typing import Annotated, Final, Literal, Protocol, get_args, runtime_checkable

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.mcp_config.materializer import MaterializeRejected, MaterializeResult
from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigRecord
from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused, validate_transition
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.author_routes import _mint_request_id
from cognic_agentos.portal.api.packs.dto import PackResponse
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor
from cognic_agentos.portal.rbac.tenant_isolation import RequireTenantOwnership
from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# M4 (ADR-026 D1/D6) — consumer-owned dependency Protocols
# ---------------------------------------------------------------------------
#
# The operator install/disable/revoke handlers gain the M4 runtime-config
# materialization saga. The TWO body-time collaborators (the materializer + the
# runtime-config record store) are declared here as narrow consumer-owned
# Protocols per ``[[feedback_consumer_owned_protocol_for_unlanded_dep]]`` so this
# module ships BEFORE the Task-7 composition root wires the real instances. When
# BOTH are ``None`` (the pre-Task-7 wiring — e.g. the current
# ``build_packs_router(store=...)`` call site + the existing test suite) the
# handlers fall back to the pre-M4 plain ``store.transition`` delegate path;
# the saga runs ONLY when BOTH are wired (all-2-or-none — partial is a
# ValueError at construction).
#
# The plugin registry is DELIBERATELY NOT a body-time collaborator: it is
# populated in the ``create_app`` LIFESPAN (boot-time trust-registration), while
# the operator router is mounted at ``create_app`` BODY time — so closing over a
# body-time registry object would see an empty/None registry. Install gate 2
# instead reads ``request.app.state.plugin_registry`` at REQUEST time (ADR-026
# D6, Task-7 option B). A ``None`` registry (boot-registration failed / not yet
# populated) refuses fail-closed ``install_plugin_registry_unavailable`` (503);
# a populated registry that does not carry the pack refuses
# ``install_pack_not_registered`` (409).


@runtime_checkable
class _MaterializerLike(Protocol):
    """Structural view of
    :class:`~cognic_agentos.core.mcp_config.materializer.RuntimeConfigMaterializer`
    (only the two entry-points the saga calls). ``materialize`` validates BOTH
    required Vault refs read-only BEFORE any derived write (raising
    :class:`MaterializeRejected` on the first failure — zero rows written), then
    reconciles the tenant allow-list FIRST and the pack-scoped override LAST.
    ``retract`` clears the override then reconciles the allow-list to the union
    EXCLUDING this pack."""

    async def materialize(
        self,
        *,
        record: PackRuntimeConfigRecord,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> MaterializeResult: ...

    async def retract(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None: ...


@runtime_checkable
class _ConfigStoreLike(Protocol):
    """Structural view of
    :class:`~cognic_agentos.core.mcp_config.runtime_config.PackRuntimeConfigStore`
    (the two methods the saga consumes). ``get`` is tenant-scoped (cross-tenant
    reads as absent); ``set_activation_status`` updates ONLY the activation
    status (does NOT bump generation)."""

    async def get(self, *, tenant_id: str, pack_id: str) -> PackRuntimeConfigRecord | None: ...

    async def set_activation_status(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        status: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None: ...


@runtime_checkable
class _RegisteredPackReader(Protocol):
    """Structural view of the boot-time trust surface
    (:meth:`~cognic_agentos.protocol.plugin_registry.PluginRegistry.iter_registered_pack_candidates`)
    — yields REGISTERED (trusted) packs only. Gate 2 matches the pack's
    ``pack_id`` (distribution-name string) against
    :attr:`RegisteredPackCandidate.distribution_name`."""

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]: ...


# ---------------------------------------------------------------------------
# M4 (ADR-026 D1/D6) — route-owned closed-enum refusal vocabulary
# ---------------------------------------------------------------------------

#: Closed-enum refusal reasons the M4 saga surfaces (distinct from the
#: pre-existing ``pack_not_found`` + the ``LifecycleRefusalReason`` values that
#: pass through unchanged). 8 install reasons + 4 disable/revoke analogues.
#: The count is pinned via ``typing.get_args`` (NOT regex — comment tokens
#: inside ``Literal[...]`` would over-count per
#: ``[[feedback_count_enum_values_via_ast_not_regex]]``).
InstallRefusalReason = Literal[
    # Gate refusals (read-only pre-checks — refuse BEFORE any write).
    "install_plugin_registry_unavailable",  # gate 2 — app.state.plugin_registry None (503 infra)
    "install_pack_not_registered",  # gate 2 — registry present, pack not boot-registered/trusted
    "install_runtime_config_missing",  # gate 3 — no desired runtime-config record
    "install_runtime_config_incomplete",  # gate 3 — a required Vault ref is None
    "install_runtime_config_vault_ref_unresolved",  # gate 4 — MaterializeRejected
    # Saga write failures (post-gate; each drives compensation).
    "install_materialize_failed",  # A — a store mutator failed mid-materialize
    "install_activation_failed",  # C — the set-active write failed
    "install_transition_failed",  # B — a non-lifecycle transition error
    "install_compensation_failed",  # a compensation step ITSELF raised (fail loud)
    # disable / revoke analogues.
    "disable_runtime_config_missing",
    "disable_transition_failed",  # generic (non-lifecycle) disable transition error
    "disable_compensation_failed",
    "disable_status_write_failed",  # phase B — disabled + retracted; status write failed
    "revoke_runtime_config_missing",
    "revoke_transition_failed",  # generic (non-lifecycle) revoke transition error
    "revoke_compensation_failed",
    "revoke_status_write_failed",  # phase B — revoked + retracted; status write failed
]

#: Count-guard the test pins via ``typing.get_args`` (metadata, NOT the gate).
_INSTALL_REFUSAL_REASON_COUNT: Final[int] = len(get_args(InstallRefusalReason))


# ---------------------------------------------------------------------------
# Plan Round 18 P2 #4 + Round 19 P3 #3 — request-id prefix constants
# ---------------------------------------------------------------------------

#: Allow-list verb prefix. 13 chars + uuid4().hex (32) = 45 chars; under
#: the 64-char ``decision_history.request_id`` String column cap.
_PACK_ALLOW_LIST_REQUEST_ID_PREFIX: Final[str] = "pack-alowlst-"

#: Install verb prefix. 13 chars + uuid4().hex (32) = 45 chars.
_PACK_INSTALL_REQUEST_ID_PREFIX: Final[str] = "pack-install-"

#: Disable verb prefix. 13 chars + uuid4().hex (32) = 45 chars.
_PACK_DISABLE_REQUEST_ID_PREFIX: Final[str] = "pack-disable-"

#: Revoke verb prefix. 13 chars + uuid4().hex (32) = 45 chars. Double-
#: dash prefix-uniqueness against ``pack-revoke`` substring matches
#: (mirrors T5's ``pack-claim--`` doubling at ``review_routes.py:81``).
_PACK_REVOKE_REQUEST_ID_PREFIX: Final[str] = "pack-revoke--"

#: Uninstall verb prefix. 13 chars + uuid4().hex (32) = 45 chars.
_PACK_UNINSTALL_REQUEST_ID_PREFIX: Final[str] = "pack-uninstal"

#: M4 saga sub-write prefixes (materialize / activation-status / retract legs).
#: Each is 13 chars + uuid4().hex (32) = 45 chars, under the 64-char cap. The
#: derived carve-out mutators mint their OWN request_ids downstream from the
#: value the materializer threads; these prefix the config-store activation
#: write + the materializer/retract call request_id.
_PACK_MATERIALIZE_REQUEST_ID_PREFIX: Final[str] = "pack-mtrlize-"
_PACK_ACTIVATION_REQUEST_ID_PREFIX: Final[str] = "pack-activat-"
_PACK_RETRACT_REQUEST_ID_PREFIX: Final[str] = "pack-retract-"


#: Plan Round 18 P2 #4 — request_id bounded-length invariant: every
#: prefix + uuid4().hex (32) must fit under the 64-char
#: ``decision_history.request_id`` column cap. Module-foot assert below
#: pins this at import time.
_REQUEST_ID_MAX_LEN: Final[int] = 64


#: Shared ``pack_not_found`` reason for race translation (slice 2-4
#: use; declared here for cross-slice stability). Same string as
#: :data:`cognic_agentos.portal.rbac.tenant_isolation.TenantIsolationFailure`'s
#: ``pack_not_found`` value so the wire-protocol-public 404 body is
#: identical across review + author + operator surfaces.
_PACK_NOT_FOUND_REASON: Final[str] = "pack_not_found"


def build_operator_routes(
    *,
    store: PackRecordStore,
    materializer: _MaterializerLike | None = None,
    config_store: _ConfigStoreLike | None = None,
) -> APIRouter:
    """Build the operator-surface sub-router.

    **M4 (ADR-026 D1/D6) — the runtime-config materialization saga.** The TWO
    body-time keyword-only collaborators (``materializer`` / ``config_store``)
    are the M4 install/disable/revoke saga dependencies, wired ALL-2-or-NONE:

    - **both wired** (the Task-7 composition root) → the install/disable/revoke
      handlers run the M4 saga;
    - **both absent** (default ``None``) → the handlers fall back to the pre-M4
      plain ``store.transition`` delegate, so this factory stays
      backward-compatible with the pre-Task-7 call site
      (``build_packs_router(store=...)`` → ``build_operator_routes(store=store)``);
    - **partial (exactly one present)** → :class:`ValueError` at construction. A
      partial wiring is a mis-configuration that would SILENTLY bypass the M4
      install materialization gates on a critical route — so it fails fast at
      construction rather than soft-downgrading.

    The **plugin registry is NOT a body-time collaborator** (ADR-026 D6, Task-7
    option B). It is populated in the ``create_app`` LIFESPAN (boot-time
    trust-registration) while this router mounts at ``create_app`` BODY time, so
    install gate 2 reads ``request.app.state.plugin_registry`` at REQUEST time
    instead of closing over a (would-be empty) body-time object.

    ``allow_list`` + ``uninstall`` are UNCHANGED regardless.

    The ``store`` argument is captured in this factory so each endpoint
    closes over a single :class:`PackRecordStore` instance per app
    lifespan (mirrors :func:`build_author_routes` at
    ``portal/api/packs/author_routes.py`` + :func:`build_review_routes`
    at ``portal/api/packs/review_routes.py:104``).

    The returned router does NOT carry a prefix —
    :func:`build_packs_router` mounts it under the parent
    ``/api/v1/packs`` prefix so each endpoint's full path is
    ``/api/v1/packs/{pack_id}/<verb>``.

    **Shared dependency instances** — built once per router-factory
    invocation (mirrors T5 R14 P2 #3 — same ``_require_tenant_ownership``
    instance shared across all 5 endpoints so FastAPI's per-request
    callable-identity sub-dependency cache deduplicates the
    :class:`PackRecord` load → ONE ``store.load`` call on the happy
    path).

    **Handler bodies (post-slice-4 final shape)**: each of the 5
    endpoints delegates to :meth:`PackRecordStore.transition` with the
    verb-specific transition name, threading ``actor_type=actor.actor_type``
    per the R24 Path B + B2 actor-type-in-payload contract. Refusal
    paths share a 3-arm pattern: :class:`PackNotFound` → 404
    ``pack_not_found`` + ``portal.packs.<verb>_refused`` log;
    :class:`LifecycleTransitionRefused` → 409 + closed-enum reason +
    ``portal.packs.<verb>_refused`` log; green path returns the
    re-loaded :class:`PackResponse`. The allow-list handler
    additionally emits the green-path ``portal.packs.allow_list`` log
    carrying ``actor_type`` (the watchpoint (d) examiner-traceability
    structured-log surface, dual to the chain-row payload key).
    """
    router = APIRouter()

    # Shared dependency instances — one per scope + one tenant-ownership
    # + one human-actor (allow-list only).
    _require_pack_allow_list = RequireScope("pack.allow_list")
    _require_pack_install = RequireScope("pack.install")
    _require_pack_disable = RequireScope("pack.disable")
    _require_pack_revoke = RequireScope("pack.revoke")
    _require_pack_uninstall = RequireScope("pack.uninstall")
    _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")
    _require_human_actor = RequireHumanActor()

    #: M4 saga is active ONLY when BOTH body-time collaborators are wired (Task-7
    #: composition root). PARTIAL wiring (exactly one) is a mis-configuration —
    #: FAIL FAST at construction rather than silently downgrading the hardened
    #: install route to the pre-M4 path (which would bypass the M4 gates). The
    #: all-absent path keeps the pre-M4 plain delegate the existing suite runs.
    #: The plugin registry is a REQUEST-time gate (read from app.state), NOT a
    #: body-time dep — so it is intentionally excluded from this all-2-or-none.
    _m4_deps_present = sum(dep is not None for dep in (materializer, config_store))
    if _m4_deps_present not in (0, 2):
        raise ValueError(
            "build_operator_routes: the M4 body-time saga collaborators "
            "(materializer, config_store) must be BOTH wired or BOTH absent; a "
            f"partial wiring ({_m4_deps_present}/2 present) would silently bypass "
            "the M4 install materialization gates. Wire both (Task-7 composition "
            "root) or neither (pre-M4 backward-compat). The plugin registry is NOT "
            "a body-time dep — install gate 2 reads it from app.state at request "
            "time."
        )
    _m4_enabled = _m4_deps_present == 2

    async def _plain_transition(
        *,
        actor: Actor,
        record: PackRecord,
        transition: str,
        prefix: str,
        refused_event: str,
    ) -> PackResponse:
        """The pre-M4 delegate-to-storage handler (shared by allow_list +
        uninstall always, and by install/disable/revoke on the None path):
        ``store.transition`` → 404 ``PackNotFound`` / 409
        ``LifecycleTransitionRefused`` + ``<refused_event>`` log; green →
        re-loaded :class:`PackResponse`."""
        try:
            await store.transition(
                pack_id=record.id,
                transition=transition,  # type: ignore[arg-type]
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(prefix),
                actor_type=actor.actor_type,
            )
        except PackNotFound:
            _LOG.warning(
                refused_event,
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON}
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                refused_event,
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None

        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence in depth
            raise HTTPException(status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON})
        return PackResponse.model_validate(updated)

    def _refuse_install(
        *, actor: Actor, record: PackRecord, reason: str, status: int = 409
    ) -> HTTPException:
        """Install refusal — ``status`` (default 409) + ``portal.packs.install_refused``
        log. The gate refusals (gates 1-3, read-only pre-checks) keep the 409
        default; the transition-first B step maps its own statuses
        (404 :class:`PackNotFound` / 409 :class:`LifecycleTransitionRefused` /
        502 generic ``install_transition_failed``) via the ``status`` argument."""
        _LOG.warning(
            "portal.packs.install_refused",
            extra={
                "reason": reason,
                "actor_subject": actor.subject,
                "pack_id": str(record.id),
                "from_state": record.state,
            },
        )
        return HTTPException(status_code=status, detail={"reason": reason})

    def _log_compensation_failed(
        *, event: str, record: PackRecord, primary: BaseException, secondary: BaseException
    ) -> HTTPException:
        """A compensation step ITSELF raised — fail loud with a 500 + a
        ``<event>`` log carrying pack_id + BOTH error strings (the operator
        must intervene: the derived state may be inconsistent)."""
        _LOG.error(
            event,
            extra={
                "pack_id": str(record.id),
                "primary_error": str(primary),
                "compensation_error": str(secondary),
            },
        )
        reason = (
            "install_compensation_failed"
            if event.endswith("install_compensation_failed")
            else event.rsplit(".", 1)[-1]
        )
        return HTTPException(status_code=500, detail={"reason": reason})

    async def _install_compensate_to_disabled(
        *,
        actor: Actor,
        record: PackRecord,
        cfg_pack_id: str,
        tenant: str,
        primary: Exception,
    ) -> None:
        """Compensate a POST-transition install failure (A materialize or C
        set-active) FORWARD to a fail-closed ``disabled`` end state — never
        revert to ``allow_listed`` (there is no un-install transition; Task 5's
        ``disabled → installed`` re-enable makes the pack recoverable).

        Three steps, all inside ONE ``try``:
        1. :meth:`materializer.retract` — un-expose / clean any partial derived
           rows so ``mcp_authz`` refuses the pack via its carve-out-absent path.
        2. ``store.transition("disable", ...)`` — record ``installed → disabled``
           so the lifecycle matches the un-exposed reality (fail-closed).
        3. ``config_store.set_activation_status(status="disabled", ...)`` — mark
           the desired record disabled.

        Fresh request-ids are minted from the existing prefixes. If ANY of the
        three raises, the compensation ITSELF failed — re-raise a fail-loud 500
        ``install_compensation_failed`` chained from ``primary`` so the operator
        knows the derived/lifecycle state may be inconsistent."""
        assert materializer is not None and config_store is not None
        try:
            await materializer.retract(
                tenant_id=tenant,
                pack_id=cfg_pack_id,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_PACK_RETRACT_REQUEST_ID_PREFIX),
            )
            await store.transition(
                pack_id=record.id,
                transition="disable",
                actor_id=actor.subject,
                tenant_id=tenant,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_DISABLE_REQUEST_ID_PREFIX),
                actor_type=actor.actor_type,
            )
            await config_store.set_activation_status(
                tenant_id=tenant,
                pack_id=cfg_pack_id,
                status="disabled",
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_PACK_ACTIVATION_REQUEST_ID_PREFIX),
            )
        except Exception as comp_exc:
            raise _log_compensation_failed(
                event="portal.packs.install_compensation_failed",
                record=record,
                primary=primary,
                secondary=comp_exc,
            ) from primary

    async def _run_install_saga(
        *, actor: Actor, record: PackRecord, registry: _RegisteredPackReader | None
    ) -> PackResponse:
        """The M4 install saga — TRANSITION-FIRST (record governance BEFORE
        exposure); order is load-bearing for the fail-CLOSED invariant.

        ``cfg_pack_id = str(record.id)`` (the UUID string — the config-store +
        materializer key, matching Task-3's ``configure`` write);
        ``dist_name = record.pack_id`` (the distribution-name string — the
        registry gate key). ``registry`` is read by the install HANDLER from
        ``request.app.state.plugin_registry`` at request time (ADR-026 D6 option
        B) and threaded here — a ``None`` registry refuses fail-closed 503
        ``install_plugin_registry_unavailable`` (gate 2, infra); a populated
        registry that does not carry ``dist_name`` refuses 409
        ``install_pack_not_registered`` (gate 2, trust).

        Gates 1-3 are read-only pre-checks (refuse before any write). Then the
        write order is **B transition-to-``installed`` FIRST → A materialize
        (expose) → C set-config-active LAST**. ``materialize`` writes the derived
        override + allow-list rows that ``mcp_authz`` reads for callability, so
        exposing BEFORE recording ``installed`` would leave a crash-window where
        the pack is callable-but-not-installed (fail-OPEN). Transition-first
        inverts that: the lifecycle records ``installed`` before the pack is
        exposed, so a crash leaves it ``installed``-but-NOT-callable
        (fail-CLOSED), never the reverse.

        Compensation: B is first, so a B failure needs NO compensation (nothing
        was written before it). Any POST-transition failure (A or C) compensates
        FORWARD to a fail-closed ``disabled`` state via
        :func:`_install_compensate_to_disabled` — never revert to
        ``allow_listed`` (there is no un-install transition; Task 5's
        ``disabled → installed`` re-enable makes it recoverable).
        """
        assert materializer is not None and config_store is not None
        cfg_pack_id = str(record.id)
        dist_name = record.pack_id
        tenant = actor.tenant_id

        # -- Gate 1 — lifecycle dry-run (read-only) --------------------------
        gate1_reason = validate_transition(
            from_state=record.state,
            to_state="installed",
            kind=record.kind,
            transition="install",
        )
        if gate1_reason is not None:
            raise _refuse_install(actor=actor, record=record, reason=gate1_reason)

        # -- Gate 2 — boot-registered / trusted (read-only) ------------------
        # The registry is read at REQUEST time from ``app.state.plugin_registry``
        # (populated by the lifespan's boot trust-registration). A ``None``
        # registry is an infra/config failure (boot-registration failed OR the
        # SDK-gated boot did not run) — refuse fail-CLOSED 503, DISTINCT from the
        # 409 "registry present but this pack is not trust-registered" refusal so
        # operators get a clean infra-vs-trust diagnosis.
        if registry is None:
            raise _refuse_install(
                actor=actor,
                record=record,
                reason="install_plugin_registry_unavailable",
                status=503,
            )
        if not any(
            c.distribution_name == dist_name for c in registry.iter_registered_pack_candidates()
        ):
            raise _refuse_install(actor=actor, record=record, reason="install_pack_not_registered")

        # -- Gate 3 — runtime-config exists + complete (read-only) -----------
        cfg = await config_store.get(tenant_id=tenant, pack_id=cfg_pack_id)
        if cfg is None:
            raise _refuse_install(
                actor=actor, record=record, reason="install_runtime_config_missing"
            )
        if cfg.oauth_credential_ref is None or cfg.as_allowlist_ref is None:
            raise _refuse_install(
                actor=actor, record=record, reason="install_runtime_config_incomplete"
            )

        # -- B — transition to ``installed`` FIRST (record governance) -------
        # NO writes happened before this, so a B failure needs NO compensation.
        try:
            await store.transition(
                pack_id=record.id,
                transition="install",
                actor_id=actor.subject,
                tenant_id=tenant,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_INSTALL_REQUEST_ID_PREFIX),
                actor_type=actor.actor_type,
            )
        except PackNotFound:
            raise _refuse_install(
                actor=actor, record=record, reason=_PACK_NOT_FOUND_REASON, status=404
            ) from None
        except LifecycleTransitionRefused as exc:
            # The race case — gate 1 passed but the state changed under a
            # concurrent op.
            raise _refuse_install(
                actor=actor, record=record, reason=exc.reason, status=409
            ) from None
        except Exception as exc:
            raise _refuse_install(
                actor=actor, record=record, reason="install_transition_failed", status=502
            ) from exc

        # -- A — materialize (EXPOSE; the pack is now ``installed``) ----------
        # ANY failure here must compensate FORWARD to ``disabled`` (fail-closed).
        try:
            await materializer.materialize(
                record=cfg,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_PACK_MATERIALIZE_REQUEST_ID_PREFIX),
            )
        except MaterializeRejected as exc:
            await _install_compensate_to_disabled(
                actor=actor,
                record=record,
                cfg_pack_id=cfg_pack_id,
                tenant=tenant,
                primary=exc,
            )
            _LOG.warning(
                "portal.packs.install_refused",
                extra={
                    "reason": "install_runtime_config_vault_ref_unresolved",
                    "materialize_reason": exc.reason,
                    "detail": exc.detail,
                    "actor_subject": actor.subject,
                    "pack_id": cfg_pack_id,
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": "install_runtime_config_vault_ref_unresolved"},
            ) from None
        except Exception as exc:
            await _install_compensate_to_disabled(
                actor=actor,
                record=record,
                cfg_pack_id=cfg_pack_id,
                tenant=tenant,
                primary=exc,
            )
            _LOG.warning(
                "portal.packs.install_refused",
                extra={
                    "reason": "install_materialize_failed",
                    "actor_subject": actor.subject,
                    "pack_id": cfg_pack_id,
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=502, detail={"reason": "install_materialize_failed"}
            ) from exc

        # -- C — set config active (LAST, after derived rows exist) ----------
        try:
            await config_store.set_activation_status(
                tenant_id=tenant,
                pack_id=cfg_pack_id,
                status="active",
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_PACK_ACTIVATION_REQUEST_ID_PREFIX),
            )
        except Exception as exc:
            await _install_compensate_to_disabled(
                actor=actor,
                record=record,
                cfg_pack_id=cfg_pack_id,
                tenant=tenant,
                primary=exc,
            )
            _LOG.warning(
                "portal.packs.install_refused",
                extra={
                    "reason": "install_activation_failed",
                    "actor_subject": actor.subject,
                    "pack_id": cfg_pack_id,
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=502, detail={"reason": "install_activation_failed"}
            ) from exc

        # -- Green — the chain rows ARE the audit; re-load + return -----------
        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence in depth
            raise HTTPException(status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON})
        return PackResponse.model_validate(updated)

    async def _run_unexpose_saga(
        *,
        actor: Actor,
        record: PackRecord,
        transition: str,
        target_state: str,
        target_status: str,
        missing_reason: str,
        transition_failed_reason: str,
        compensation_reason: str,
        status_write_failed_reason: str,
        refused_event: str,
    ) -> PackResponse:
        """The M4 disable/revoke saga (retract-FIRST safety, then govern).

        1. **Gate 1 (lifecycle dry-run, read-only)** — refuse a deterministic
           illegal transition (e.g. re-revoke on an already-revoked pack, or a
           disable from a non-installed state) with the lifecycle reason 409
           BEFORE any retract. This keeps a terminal pack from being re-exposed
           by the step-4 compensation (which re-materializes on a genuine
           transient failure); a deterministic refusal must never reach that
           path.
        2. ``config_store.get`` — a disabled/revoked pack with no config is a
           bug; refuse fail-closed 409 ``<verb>_runtime_config_missing``.
        3. **Retract FIRST** (un-expose) — removes the pack's derived rows so
           ``mcp_authz`` refuses the pack immediately via its carve-out-absent
           path. If retract raises → 500 ``<verb>_compensation_failed`` (fail
           loud; nothing else attempted).
        4. **Phase A — ``store.transition``** (lifecycle). A transition is
           atomic: on failure the state has NOT changed, so **re-materialize**
           (compensation) to restore the pack's callable projection rather than
           leaving it silently half-disabled. If the re-materialize raises → 500
           ``<verb>_compensation_failed``. Then re-raise the transition error
           mapped (404 / 409 / 502).
        5. **Phase B — ``config_store.set_activation_status``** (the lifecycle
           has ALREADY changed). A failure here MUST NOT re-materialize — that
           would re-expose the pack while the lifecycle already says
           disabled/revoked (fail-OPEN, the same class as the install-ordering
           bug). Leave the derived rows retracted (fail-CLOSED / not callable)
           and fail loud 500 ``<verb>_status_write_failed`` so the operator
           reconciles the now-stale desired-config ``activation_status`` marker.
        """
        assert materializer is not None and config_store is not None
        cfg_pack_id = str(record.id)
        tenant = actor.tenant_id

        # -- Gate 1 — lifecycle dry-run (read-only; refuse before any write) --
        gate1_reason = validate_transition(
            from_state=record.state,
            to_state=target_state,  # type: ignore[arg-type]
            kind=record.kind,
            transition=transition,  # type: ignore[arg-type]
        )
        if gate1_reason is not None:
            _LOG.warning(
                refused_event,
                extra={
                    "reason": gate1_reason,
                    "actor_subject": actor.subject,
                    "pack_id": cfg_pack_id,
                    "from_state": record.state,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": gate1_reason})

        cfg = await config_store.get(tenant_id=tenant, pack_id=cfg_pack_id)
        if cfg is None:
            _LOG.warning(
                refused_event,
                extra={
                    "reason": missing_reason,
                    "actor_subject": actor.subject,
                    "pack_id": cfg_pack_id,
                    "from_state": record.state,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": missing_reason})

        # -- Retract FIRST (un-expose) ---------------------------------------
        try:
            await materializer.retract(
                tenant_id=tenant,
                pack_id=cfg_pack_id,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_PACK_RETRACT_REQUEST_ID_PREFIX),
            )
        except Exception as exc:
            _LOG.error(
                refused_event.replace("_refused", "_compensation_failed"),
                extra={
                    "pack_id": cfg_pack_id,
                    "primary_error": "retract",
                    "compensation_error": str(exc),
                },
            )
            raise HTTPException(status_code=500, detail={"reason": compensation_reason}) from exc

        # -- Phase A — lifecycle transition ----------------------------------
        # A transition is atomic: if it FAILS the state has NOT changed, so
        # re-materialize to restore the pack's prior callable projection (the
        # retract un-exposed it, but the disable/revoke did not take effect).
        try:
            await store.transition(
                pack_id=record.id,
                transition=transition,  # type: ignore[arg-type]
                actor_id=actor.subject,
                tenant_id=tenant,
                evidence_pointer=None,
                request_id=_mint_request_id(
                    _PACK_DISABLE_REQUEST_ID_PREFIX
                    if transition == "disable"
                    else _PACK_REVOKE_REQUEST_ID_PREFIX
                ),
                actor_type=actor.actor_type,
            )
        except Exception as exc:
            # Re-materialize compensation — the state did NOT change, so restore
            # the callable projection rather than leaving the pack half-disabled.
            try:
                await materializer.materialize(
                    record=cfg,
                    actor_subject=actor.subject,
                    actor_type=actor.actor_type,
                    request_id=_mint_request_id(_PACK_MATERIALIZE_REQUEST_ID_PREFIX),
                )
            except Exception as comp_exc:
                _LOG.error(
                    refused_event.replace("_refused", "_compensation_failed"),
                    extra={
                        "pack_id": cfg_pack_id,
                        "primary_error": str(exc),
                        "compensation_error": str(comp_exc),
                    },
                )
                raise HTTPException(
                    status_code=500, detail={"reason": compensation_reason}
                ) from exc
            # Re-raise the transition error mapped by exception class.
            if isinstance(exc, PackNotFound):
                _LOG.warning(
                    refused_event,
                    extra={
                        "reason": _PACK_NOT_FOUND_REASON,
                        "actor_subject": actor.subject,
                        "pack_id": cfg_pack_id,
                        "from_state": record.state,
                    },
                )
                raise HTTPException(
                    status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON}
                ) from None
            if isinstance(exc, LifecycleTransitionRefused):
                _LOG.warning(
                    refused_event,
                    extra={
                        "reason": exc.reason,
                        "actor_subject": actor.subject,
                        "pack_id": cfg_pack_id,
                        "from_state": record.state,
                    },
                )
                raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None
            _LOG.warning(
                refused_event,
                extra={
                    "reason": transition_failed_reason,
                    "actor_subject": actor.subject,
                    "pack_id": cfg_pack_id,
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=502, detail={"reason": transition_failed_reason}
            ) from exc

        # -- Phase B — set config activation-status (state ALREADY changed) --
        # The lifecycle transition COMMITTED (state is now the target). A failure
        # here MUST NOT re-materialize — that would re-expose the pack while the
        # lifecycle already says disabled/revoked (fail-OPEN, the same class as the
        # install-ordering bug). Leave the derived rows retracted (fail-CLOSED / not
        # callable) and fail loud so the operator reconciles the now-stale desired-
        # config ``activation_status`` marker.
        try:
            await config_store.set_activation_status(
                tenant_id=tenant,
                pack_id=cfg_pack_id,
                status=target_status,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint_request_id(_PACK_ACTIVATION_REQUEST_ID_PREFIX),
            )
        except Exception as exc:
            _LOG.error(
                refused_event.replace("_refused", "_status_write_failed"),
                extra={
                    "pack_id": cfg_pack_id,
                    "note": (
                        "lifecycle transitioned + derived rows retracted (fail-closed); "
                        "desired-config activation_status NOT updated — operator must reconcile"
                    ),
                    "error": str(exc),
                },
            )
            raise HTTPException(
                status_code=500, detail={"reason": status_write_failed_reason}
            ) from exc

        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence in depth
            raise HTTPException(status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON})
        return PackResponse.model_validate(updated)

    @router.post(
        "/{pack_id}/allow-list",
        summary="Allow-list a pack for this tenant (transition: approved → allow_listed)",
    )
    async def allow_list(
        actor: Annotated[Actor, Depends(_require_pack_allow_list)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        _human: Annotated[Actor, Depends(_require_human_actor)],
    ) -> PackResponse:
        """Transition ``approved → allow_listed`` via
        ``store.transition("allow_list", ...)``.

        Dependency chain (resolution order):
        1. :class:`RequireScope("pack.allow_list")` — 403 ``scope_not_held``
           for missing scope; emits ``portal.rbac.denied`` sibling log.
        2. :class:`RequireTenantOwnership` — 404 ``tenant_id_mismatch`` /
           ``pack_not_found`` for cross-tenant; returns the
           :class:`PackRecord`.
        3. :class:`RequireHumanActor` — 403 ``actor_type_must_be_human``
           for service-token actors; emits
           ``portal.rbac.human_actor_required`` sibling log per
           ``portal/rbac/human_actor.py:69``. Plan R1 P3 #8 — AGENTS.md
           "Human-only decisions" ↔ "Per-tenant allow-list changes"
           doctrine pin. The ``_human`` parameter binding the dependency
           result is unused inside the body but the FastAPI
           :class:`Depends` declaration is what registers the guard;
           dropping it would silently disable the human-actor refusal.

        Handler-body refusals:
        - :class:`PackNotFound` race (Plan R18 P2 #4) — concurrent
          delete between tenant-isolation preload + ``transition()``
          SELECT FOR UPDATE → 404 ``pack_not_found``.
        - :class:`LifecycleTransitionRefused` — state-machine refusal
          (e.g. allow-list on draft pack) → 409 + closed-enum reason
          from :data:`LifecycleRefusalReason` (e.g.
          ``lifecycle_transition_allow_list_not_approved`` per
          ``packs/lifecycle.py:526``).

        Structured-log contract (Plan R19 P2 #2 mutually-exclusive):
        - Green: EXACTLY ONE ``portal.packs.allow_list`` record
          carrying ``actor_type`` + ``actor_subject`` + ``pack_id`` —
          watchpoint (d) examiner-traceability surface.
        - Refused (state-machine OR :class:`PackNotFound` race):
          EXACTLY ONE ``portal.packs.allow_list_refused`` record
          carrying ``reason`` + ``actor_subject`` + ``pack_id`` +
          ``from_state``.
        - Dep-chain refusal (RBAC / tenant / human-actor): ZERO
          ``portal.packs.allow_list*`` records — sibling-guard logs
          carry the refusal in their own logger namespace
          (``portal.rbac.denied`` / ``portal.rbac.tenant_isolation`` /
          ``portal.rbac.human_actor_required``).
        """
        try:
            await store.transition(
                pack_id=record.id,
                transition="allow_list",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_ALLOW_LIST_REQUEST_ID_PREFIX),
                # R24 P2 Path B + B2: persist actor.actor_type as a
                # flat payload key for examiner-traceability per
                # watchpoint (d). The RequireHumanActor dep upstream
                # guarantees ``actor.actor_type == "human"`` at this
                # point; passing through means the chain row carries
                # that guarantee on-record (no log correlation
                # required). Storage stores verbatim; the closed-enum
                # ``human|service`` discriminator lives at the rbac
                # boundary.
                actor_type=actor.actor_type,
            )
        except PackNotFound:
            # R18 P2 #4 — race translation; refused-event log fires
            # (mutually-exclusive with the green-path allow_list log).
            _LOG.warning(
                "portal.packs.allow_list_refused",
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                "portal.packs.allow_list_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        # Green-path: emit the watchpoint (d) examiner-traceability
        # log carrying ``actor_type`` (proves the RequireHumanActor
        # guard upstream had ``actor.actor_type == "human"``). The
        # chain row's ``actor_id`` carries the human's subject; the
        # log's ``actor_type`` field carries the human-actor
        # invariant — together they pin the cross-row + cross-log
        # evidence the examiner needs per AGENTS.md "Human-only
        # decisions" doctrine.
        _LOG.warning(
            "portal.packs.allow_list",
            extra={
                "actor_subject": actor.subject,
                "actor_type": actor.actor_type,
                "pack_id": str(record.id),
            },
        )

        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence in depth
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return PackResponse.model_validate(updated)

    @router.post(
        "/{pack_id}/install",
        summary="Install an allow-listed pack (transition: allow_listed → installed)",
    )
    async def install(
        request: Request,
        actor: Annotated[Actor, Depends(_require_pack_install)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Transition ``allow_listed → installed`` via
        ``store.transition("install", ...)``.

        Dependency chain (resolution order — symmetric with disable):
        1. :class:`RequireScope("pack.install")` — 403 ``scope_not_held``
           for missing scope; emits ``portal.rbac.denied`` sibling log.
        2. :class:`RequireTenantOwnership` — 404 ``tenant_id_mismatch`` /
           ``pack_not_found`` for cross-tenant; returns the
           :class:`PackRecord`. No :class:`RequireHumanActor` — install
           is open to service actors per AGENTS.md (the human-only rule
           applies specifically to allow-list per Plan R1 P3 #8).

        Handler-body refusals:
        - :class:`PackNotFound` race (Plan watchpoint (h)) → 404
          ``pack_not_found`` + ``portal.packs.install_refused`` log.
        - :class:`LifecycleTransitionRefused` — state-machine refusal
          (e.g. install on draft pack) → 409 + closed-enum reason
          (``lifecycle_transition_invalid_state_pair`` from the
          legal-pair table; per-transition install-specific reason
          would surface here too if lifecycle added one).

        R24 carry-forward (Path B + B2): ``actor_type=actor.actor_type``
        threaded into ``transition()`` so the chain row's
        ``payload["actor_type"]`` records the actor type for examiner
        parity with the allow-list audit row.

        Mutually-exclusive log contract (Plan R19 P2 #2): green path
        emits NO operator-vocab log (the lifecycle chain row IS the
        audit surface for install); refused path emits EXACTLY ONE
        ``portal.packs.install_refused``.

        **M4 (ADR-026 D1/D6) — the materialization saga.** When the
        materializer + config_store are both wired (Task-7 composition
        root) this handler runs the install saga (gates 1-3 read-only
        pre-checks → transition-to-``installed`` FIRST → materialize
        (expose) → set-config-active LAST, recording governance BEFORE
        exposure so a crash is fail-CLOSED; a post-transition failure
        compensates FORWARD to ``disabled``) via :func:`_run_install_saga`.
        Gate 2's plugin registry is read HERE from
        ``request.app.state.plugin_registry`` at request time (ADR-026 D6
        option B — the lifespan populates it AFTER this router mounts). On
        the pre-Task-7 both-None path it falls back to the pre-M4 plain
        ``store.transition`` delegate.
        """
        if _m4_enabled:
            # Gate 2 reads the boot-registered registry at REQUEST time: the
            # lifespan populates ``app.state.plugin_registry`` AFTER this router
            # mounts at body time. ``getattr`` (not attribute access) so a
            # mis-wired app missing the attr refuses fail-closed via the saga's
            # ``None`` gate (503 ``install_plugin_registry_unavailable``) rather
            # than raising a bare ``AttributeError``.
            registry = getattr(request.app.state, "plugin_registry", None)
            return await _run_install_saga(actor=actor, record=record, registry=registry)
        return await _plain_transition(
            actor=actor,
            record=record,
            transition="install",
            prefix=_PACK_INSTALL_REQUEST_ID_PREFIX,
            refused_event="portal.packs.install_refused",
        )

    @router.post(
        "/{pack_id}/disable",
        summary="Disable an installed pack (transition: installed → disabled)",
    )
    async def disable(
        actor: Annotated[Actor, Depends(_require_pack_disable)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Transition ``installed → disabled`` via
        ``store.transition("disable", ...)``.

        Dependency chain symmetric with install (RBAC + tenant; no
        human-actor sub-dependency).

        State-machine refusals at this verb surface
        ``lifecycle_transition_disable_not_installed`` (per-transition
        closed-enum reason from ``packs/lifecycle.py``) when the pack
        is not in ``installed`` state. Per-transition specificity
        differentiates disable-on-non-installed from generic
        ``lifecycle_transition_invalid_state_pair`` (the legal-pair-
        table fallback) — the per-transition reason takes precedence
        per ``packs/lifecycle.py:validate_transition``'s ordered
        check chain.

        R24 carry-forward: threads ``actor_type=actor.actor_type``
        into transition() — disable chain rows record the operator's
        actor_type for examiner parity.

        **M4 (ADR-026 D6) — retract-FIRST un-expose saga.** When the M4
        collaborators are wired this handler retracts the pack's derived
        rows FIRST (un-expose → immediately refused by ``mcp_authz``),
        then transitions + marks the config ``disabled``. A post-retract
        **transition** failure (state unchanged) re-materializes
        (compensation) so the pack is left callable rather than silently
        half-disabled; a **status-write** failure AFTER the transition
        committed does NOT re-materialize — it leaves the pack fail-closed
        (retracted / not callable, lifecycle ``disabled``) and fails loud
        (via :func:`_run_unexpose_saga`). On the None path it falls back to
        the pre-M4 plain delegate.
        """
        if _m4_enabled:
            return await _run_unexpose_saga(
                actor=actor,
                record=record,
                transition="disable",
                target_state="disabled",
                target_status="disabled",
                missing_reason="disable_runtime_config_missing",
                transition_failed_reason="disable_transition_failed",
                compensation_reason="disable_compensation_failed",
                status_write_failed_reason="disable_status_write_failed",
                refused_event="portal.packs.disable_refused",
            )
        return await _plain_transition(
            actor=actor,
            record=record,
            transition="disable",
            prefix=_PACK_DISABLE_REQUEST_ID_PREFIX,
            refused_event="portal.packs.disable_refused",
        )

    @router.post(
        "/{pack_id}/revoke",
        summary="Revoke an installed/disabled pack (multi-from: installed/disabled → revoked)",
    )
    async def revoke(
        actor: Annotated[Actor, Depends(_require_pack_revoke)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Transition (``installed`` OR ``disabled``) → ``revoked`` via
        ``store.transition("revoke", ...)``.

        **Multi-from-state contract** per ``packs/lifecycle.py:224-228``:
        ``revoke`` accepts EITHER ``installed`` OR ``disabled`` as the
        from-state. The legal-pair table at
        ``_VALID_TRANSITIONS["revoke"]`` enforces this — the handler
        does not branch on from-state itself; storage's
        ``validate_transition`` handles the closed-set membership check.

        Idempotency: re-revoke on an already-revoked pack surfaces the
        per-transition closed-enum reason
        ``lifecycle_transition_revoke_already_revoked`` (per
        ``packs/lifecycle.py:183``) — distinct from the generic
        ``lifecycle_transition_invalid_state_pair`` legal-pair fallback;
        the per-transition reason takes precedence in
        ``validate_transition``'s ordered check chain.

        R24 carry-forward: threads ``actor_type=actor.actor_type`` into
        transition() — revoke chain rows record the operator's
        actor_type for examiner parity.

        **M4 (ADR-026 D6) — retract-FIRST un-expose saga.** Symmetric
        with disable (multi-from ``installed | disabled → revoked``): the
        M4 path retracts the derived rows FIRST, then transitions + marks
        the config ``revoked``. A post-retract **transition** failure
        (state unchanged) re-materializes (compensation); a **status-write**
        failure AFTER the transition committed does NOT re-materialize —
        it leaves the pack fail-closed (retracted, lifecycle ``revoked``)
        and fails loud. Idempotency (re-revoke on an already-revoked pack)
        is caught by the saga's gate-1 dry-run BEFORE any retract, so a
        terminal pack is NOT re-exposed by the compensation path. On the
        None path it falls back to the pre-M4 plain delegate.
        """
        if _m4_enabled:
            return await _run_unexpose_saga(
                actor=actor,
                record=record,
                transition="revoke",
                target_state="revoked",
                target_status="revoked",
                missing_reason="revoke_runtime_config_missing",
                transition_failed_reason="revoke_transition_failed",
                compensation_reason="revoke_compensation_failed",
                status_write_failed_reason="revoke_status_write_failed",
                refused_event="portal.packs.revoke_refused",
            )
        return await _plain_transition(
            actor=actor,
            record=record,
            transition="revoke",
            prefix=_PACK_REVOKE_REQUEST_ID_PREFIX,
            refused_event="portal.packs.revoke_refused",
        )

    @router.delete(
        "/{pack_id}/install",
        summary="Uninstall a disabled/revoked pack (multi-from: disabled/revoked → uninstalled)",
    )
    async def uninstall(
        actor: Annotated[Actor, Depends(_require_pack_uninstall)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackResponse:
        """Transition (``disabled`` OR ``revoked``) → ``uninstalled`` via
        ``store.transition("uninstall", ...)``.

        **Multi-from-state contract** per ``packs/lifecycle.py:230-234``:
        ``uninstall`` accepts EITHER ``disabled`` OR ``revoked`` as the
        from-state.

        State-machine refusal at this verb: from-state outside
        ``{disabled, revoked}`` (e.g. ``installed``) surfaces the
        per-transition closed-enum reason
        ``lifecycle_transition_uninstall_not_revoked_or_disabled`` per
        ``packs/lifecycle.py:184`` — distinct from
        ``lifecycle_transition_terminal_state`` (which fires when
        from-state is ``uninstalled``; that's a genuine terminal-state
        refusal, not a not-revoked-or-disabled refusal).

        DELETE method on the ``/install`` path per the plan endpoint
        table — the uninstall verb shares the install path with
        method=DELETE; pinned by
        ``test_install_path_carries_both_post_and_delete`` (slice 1).

        R24 carry-forward: threads ``actor_type=actor.actor_type`` into
        transition() — uninstall chain rows record the operator's
        actor_type for examiner parity.
        """
        try:
            await store.transition(
                pack_id=record.id,
                transition="uninstall",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_UNINSTALL_REQUEST_ID_PREFIX),
                actor_type=actor.actor_type,
            )
        except PackNotFound:
            _LOG.warning(
                "portal.packs.uninstall_refused",
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                "portal.packs.uninstall_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence in depth
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return PackResponse.model_validate(updated)

    return router


# Build-time invariant: every operator request-id prefix MUST fit under
# the ``decision_history.request_id`` String(64) column cap. uuid4().hex
# is exactly 32 chars; the cap is 64; the prefix budget is therefore 32
# chars. All 5 in-tree prefixes are 13 chars — well under the budget.
# Any future prefix that pushes the total over the cap is a wire-
# protocol bug; this assert refuses module load to surface it at import.
# Mirrors ``author_routes.py:770-775``.
for _prefix in (
    _PACK_ALLOW_LIST_REQUEST_ID_PREFIX,
    _PACK_INSTALL_REQUEST_ID_PREFIX,
    _PACK_DISABLE_REQUEST_ID_PREFIX,
    _PACK_REVOKE_REQUEST_ID_PREFIX,
    _PACK_UNINSTALL_REQUEST_ID_PREFIX,
    _PACK_MATERIALIZE_REQUEST_ID_PREFIX,
    _PACK_ACTIVATION_REQUEST_ID_PREFIX,
    _PACK_RETRACT_REQUEST_ID_PREFIX,
):
    assert len(_prefix) + 32 <= _REQUEST_ID_MAX_LEN, (
        f"request_id prefix {_prefix!r} ({len(_prefix)} chars) + uuid4().hex (32 chars) "
        f"= {len(_prefix) + 32} > {_REQUEST_ID_MAX_LEN}; "
        "would overflow decision_history.request_id column cap"
    )
del _prefix
