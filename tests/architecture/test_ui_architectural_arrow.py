"""Sprint 7B.4 T13 — UI event-stream architectural-arrow regressions.

6 AST-walk invariants per spec §6 + plan §5110-5196. Each invariant
mechanically pins a doctrine constraint that mypy / runtime tests
cannot enforce (because the constraint is structural / negative —
"this module MUST NOT import X" / "this function MUST pass kwarg Y").

  1. ``protocol/ui_events.py`` doesn't import FastAPI / Starlette /
     sse-starlette / portal — the protocol module is portal-free so
     bank-overlay packs can import the event types without dragging
     FastAPI into the import graph.

  2. ``protocol/elicitation_adapter.py`` doesn't import portal /
     fastapi / mcp_host — the adapter Protocol stays narrow + bank-
     pluggable; the runtime contract is duck-typed (T7 forward
     watchpoint), so the Protocol module has zero coupling to the
     portal/protocol-runtime layers.

  3. ``portal/api/ui/elicitation_gate.py`` doesn't raise
     ``HTTPException`` + doesn't import ``mcp_host`` — the gate is
     pure-functional; HTTP mapping lives in ``action_routes.py``
     (which is FastAPI-coupled by design).

  4. ``portal/api/ui/action_routes.py`` doesn't import ``mcp_host``
     OR ``DecisionHistoryStore`` — the append seam is centralised
     through the broker; routes never construct ``DecisionRecord``
     instances or call ``DecisionHistoryStore.append`` directly.

  5. FastAPI route modules MUST NOT carry
     ``from __future__ import annotations`` — PEP 563 string-deferred
     annotations break FastAPI's ``inspect.signature()`` resolution
     on ``Annotated[..., Depends(closure-local)]`` (standing-offer
     invariant; same as ``operator_routes.py`` / ``inspection_routes.py``).
     Pure helper modules (``dto.py`` / ``elicitation_gate.py``) are
     exempt — they're imported as data, not route-resolved.

  6. Every per-type projector in ``_DECISION_HISTORY_TYPED_PROJECTORS``
     passes ``event_id=_chain_derived_event_id(...)`` to its event
     class constructor (NOT the default factory) — the deterministic
     event_id is the load-bearing cursor seam for SSE-resume.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


def _imports_of(path: Path) -> set[str]:
    """Return every fully-qualified module name imported by ``path``.

    Covers both ``from X.Y import Z`` (returns ``"X.Y"``) and
    ``import X.Y`` (returns ``"X.Y"``).

    Note: returns MODULE names only. Use :func:`_imported_symbol_pairs`
    if you need the imported SYMBOLS (the right-hand side of
    ``from X import Y``) — symbol-level invariants (e.g. "does this
    module import DecisionHistoryStore?") CANNOT be answered by
    splitting the module name on ``.`` and taking the last segment;
    that yields the module's basename, NOT the imported symbol."""
    tree = ast.parse(path.read_text())
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                out.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
    return out


def _imported_symbol_pairs(path: Path) -> set[tuple[str, str]]:
    """Return ``(source_module, imported_name)`` for every
    ``from M import N`` site in ``path``.

    Symbol-level analog of :func:`_imports_of`. Used by invariants
    that need to detect "does this module import a specific symbol"
    — e.g. ``DecisionHistoryStore`` could be imported FROM either
    ``cognic_agentos.core.decision_history`` (the canonical module
    path) OR a re-export site, and either is a violation. The
    ``alias.name`` is the IMPORTED name as written at the import
    site (the symbol's name in the source module, NOT the local
    ``as``-alias)."""
    tree = ast.parse(path.read_text())
    out: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                out.add((mod, alias.name))
    return out


def _has_future_annotations(path: Path) -> bool:
    """True iff ``path`` contains an ACTUAL ``from __future__ import
    annotations`` statement (NOT a docstring mention).

    AST-based detection — substring matching would false-positive on
    the docstrings every route module carries explaining WHY the
    import is omitted ("`from __future__ import annotations` is
    DELIBERATELY OMITTED …")."""
    tree = ast.parse(path.read_text())
    for node in ast.iter_child_nodes(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
        ):
            return True
    return False


def _derived_per_type_projector_names() -> frozenset[str]:
    """Return the set of per-type projector function NAMES, derived
    from the LIVE production dispatcher table — NOT a hand-maintained
    constant.

    R4 P1 #2 fix: the earlier ``_PER_TYPE_PROJECTORS`` frozenset was
    static; adding a 6th projector to the source + registering it in
    ``_DECISION_HISTORY_TYPED_PROJECTORS`` without updating the
    frozenset would silently bypass the event_id-explicit invariant.
    Deriving from the live dict + the rbac-prefix projector ensures
    every routable per-type projector is covered automatically.

    Returns the union of:
      - ``fn.__name__`` for every value in ``_DECISION_HISTORY_TYPED_PROJECTORS``
      - ``_project_policy_rbac_denied.__name__`` (the rbac.* prefix
        projector — routed by ``_project_typed_decision_history``'s
        prefix-match branch, NOT by the dict; would be invisible to
        a dict-only walk)
      - ``_project_subagent_recursion_capped.__name__`` (Sprint 11b T9 —
        the depth-cap projector routed by the scoped ``escalation.opened``
        conditional branch, NOT the dict; same shape as the rbac add)
    """
    from cognic_agentos.protocol.ui_events import (
        _DECISION_HISTORY_TYPED_PROJECTORS,
        _project_policy_rbac_denied,
        _project_subagent_recursion_capped,
    )

    names = {fn.__name__ for fn in _DECISION_HISTORY_TYPED_PROJECTORS.values()}
    names.add(_project_policy_rbac_denied.__name__)
    names.add(_project_subagent_recursion_capped.__name__)
    return frozenset(names)


class TestUIArchitecturalArrowInvariants:
    """6 invariants per Sprint 7B.4 spec §6. Each fires as an AST-level
    assertion; production code that drifts from the invariant fails
    the test deterministically."""

    def test_invariant_1_protocol_ui_events_no_portal_or_fastapi(self) -> None:
        imports = _imports_of(Path("src/cognic_agentos/protocol/ui_events.py"))
        for forbidden in ("fastapi", "starlette", "sse_starlette"):
            assert not any(i.startswith(forbidden) for i in imports), (
                f"protocol/ui_events.py imports {forbidden} — protocol "
                "module must stay portal-free + FastAPI-free so packs "
                "can import event types without the FastAPI graph."
            )
        assert not any(i.startswith("cognic_agentos.portal") for i in imports), (
            "protocol/ui_events.py imports cognic_agentos.portal — "
            "protocol is upstream of portal; reversing the arrow breaks "
            "the layer rule."
        )

    def test_invariant_2_protocol_elicitation_adapter_clean(self) -> None:
        imports = _imports_of(Path("src/cognic_agentos/protocol/elicitation_adapter.py"))
        for forbidden in (
            "fastapi",
            "starlette",
            "sse_starlette",
            "cognic_agentos.portal",
            "cognic_agentos.protocol.mcp_host",
        ):
            assert not any(i.startswith(forbidden) for i in imports), (
                f"protocol/elicitation_adapter.py imports {forbidden} — "
                "the adapter Protocol must stay narrow + bank-pluggable."
            )

    def test_invariant_3_elicitation_gate_no_httpexception_no_mcp_host(
        self,
    ) -> None:
        gate_path = Path("src/cognic_agentos/portal/api/ui/elicitation_gate.py")
        imports = _imports_of(gate_path)
        gate_src = gate_path.read_text()
        # Pure-functional gate — HTTP mapping (HTTPException raising)
        # happens in action_routes.py at the call site, NOT in the gate.
        # Even an unused `from fastapi import HTTPException` would
        # violate the layer contract; check for any mention of the
        # identifier in source.
        assert "HTTPException" not in gate_src, (
            "elicitation_gate.py must not reference HTTPException; the "
            "gate is pure-functional + returns a GateOutcome dataclass. "
            "HTTP mapping lives in action_routes.py at the call site."
        )
        assert not any(i.startswith("cognic_agentos.protocol.mcp_host") for i in imports), (
            "elicitation_gate.py imports mcp_host — the gate is the UI "
            "elicitation boundary, NOT the MCP host."
        )

    def test_invariant_4_action_routes_no_mcp_host_no_decision_history_store(
        self,
    ) -> None:
        action_routes_path = Path("src/cognic_agentos/portal/api/ui/action_routes.py")
        imports = _imports_of(action_routes_path)
        assert not any(i.startswith("cognic_agentos.protocol.mcp_host") for i in imports), (
            "action_routes.py imports mcp_host — wrong protocol surface."
        )
        # Append seam centralisation: action_routes MUST NEVER touch
        # the DH append surface in ANY import shape. All chain writes
        # go through broker.append_frontend_action_{submitted,accepted,rejected}.
        #
        # Three bypass classes the invariant must block:
        #
        #   (a) ``from cognic_agentos.core.decision_history import
        #        DecisionHistoryStore`` (symbol-direct from canonical
        #        module path).
        #   (b) ``from cognic_agentos.core import decision_history``
        #        followed by ``decision_history.DecisionHistoryStore``
        #        attribute access (submodule-import shape).
        #   (c) ``import cognic_agentos.core.decision_history [as dh]``
        #        followed by ``dh.DecisionHistoryStore`` attribute
        #        access (bare-import shape).
        #
        # R5 P1 #1 fix: the earlier symbol-pair-only check caught (a)
        # but missed (b) + (c) — both shapes import the MODULE rather
        # than the symbol, so a `name in {"DecisionHistoryStore", ...}`
        # check returned False. New strategy: forbid the MODULE
        # ``cognic_agentos.core.decision_history`` under all three
        # import shapes; once the module cannot be referenced, no
        # symbol from it can be accessed.
        forbidden_module = "cognic_agentos.core.decision_history"
        symbol_pairs = _imported_symbol_pairs(action_routes_path)
        # Shape (a): from <forbidden_module> import X
        # Shape (b): from cognic_agentos.core import decision_history
        violators_from = [
            f"from {mod} import {name}"
            for mod, name in symbol_pairs
            if mod == forbidden_module
            or (mod == "cognic_agentos.core" and name == "decision_history")
        ]
        # Shape (c): bare ``import cognic_agentos.core.decision_history``.
        # Note ``_imports_of`` returns the module name for BOTH
        # ``ast.Import`` aliases and ``ast.ImportFrom.module`` — exact
        # match (not startswith) so adjacent modules aren't over-matched.
        violators_import = [f"import {i}" for i in imports if i == forbidden_module]
        violators = sorted(set(violators_from + violators_import))
        assert not violators, (
            f"action_routes.py imports the DH append seam: {violators}. "
            "Even module-level imports enable downstream attribute "
            "access (``dh.DecisionHistoryStore`` / "
            "``decision_history.DecisionRecord``) that bypasses the "
            "broker centralisation. All chain writes MUST go through "
            "UIEventBroker.append_frontend_action_{submitted,accepted,rejected}."
        )

    @pytest.mark.parametrize(
        "route_module",
        [
            "src/cognic_agentos/portal/api/ui/action_routes.py",
            "src/cognic_agentos/portal/api/ui/stream_routes.py",
            "src/cognic_agentos/portal/api/ui/well_known_routes.py",
            "src/cognic_agentos/portal/api/ui/router.py",
        ],
    )
    def test_invariant_5_no_future_annotations_in_fastapi_route_modules(
        self, route_module: str
    ) -> None:
        """Per P1 #1 fix in spec §6 — invariant applies ONLY to
        FastAPI route modules. ``dto.py`` + ``elicitation_gate.py``
        are pure helpers (NOT route-resolved by FastAPI's signature
        introspection) and are exempt; they MAY carry
        ``from __future__ import annotations``."""
        assert not _has_future_annotations(Path(route_module)), (
            f"{route_module} carries 'from __future__ import annotations' — "
            "PEP 563 string-deferred annotations break FastAPI's "
            "inspect.signature()/typing.get_type_hints() resolution on "
            "Annotated[..., Depends(closure-local)] route deps. "
            "Standing-offer invariant (same as operator_routes.py / "
            "inspection_routes.py)."
        )

    def test_invariant_6_every_per_type_projector_passes_chain_derived_event_id(
        self,
    ) -> None:
        """Every per-type projector routed by the LIVE
        ``_DECISION_HISTORY_TYPED_PROJECTORS`` dispatcher table (plus
        the ``_project_policy_rbac_denied`` rbac-prefix projector)
        MUST pass ``event_id=_chain_derived_event_id(...)`` as an
        explicit keyword to its event-class constructor — NOT the
        Pydantic default factory ``_new_event_id`` (which mints a
        fresh ULID disconnected from the chain row's sequence /
        ordinal), NOT a literal value, NOT some other helper.

        The deterministic event_id is the load-bearing cursor seam
        for SSE Last-Event-ID resume: a projector that lets Pydantic
        generate a random event_id would break reconnect semantics
        silently.

        R4 P1 #2 fix: derives the projector set from the live
        production dispatcher dict + the rbac-prefix projector —
        adding a 6th per-type projector is covered automatically
        without updating any constant in this test.

        R4 P1 #3 fix: verifies the ``event_id=`` keyword VALUE is
        a Call to ``_chain_derived_event_id`` (NOT just that an
        ``event_id=`` keyword exists). Also pins the canonical
        ``chain_id="decision_history"`` + ``ordinal=0`` arguments
        — drift on either breaks the SSE cursor decoder."""
        expected_projectors = _derived_per_type_projector_names()
        src = Path("src/cognic_agentos/protocol/ui_events.py").read_text()
        tree = ast.parse(src)

        # 1) Collect every per-type projector function found in the
        # source AND scan its `return EventClass(...)` Call for the
        # event_id=_chain_derived_event_id(...) shape.
        found_projectors: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name not in expected_projectors:
                continue
            found_projectors.add(node.name)

            returns_call = next(
                (
                    n
                    for n in ast.walk(node)
                    if isinstance(n, ast.Return) and isinstance(n.value, ast.Call)
                ),
                None,
            )
            assert returns_call is not None, (
                f"{node.name}: expected a `return EventClass(...)` Call; "
                "did the projector signature change?"
            )
            call = returns_call.value
            assert isinstance(call, ast.Call)

            # event_id= MUST exist AND its value MUST be a Call to
            # _chain_derived_event_id (Name(id=) check covers the
            # local-import case; if the import becomes qualified
            # like `ui_events._chain_derived_event_id(...)` the
            # check would need an Attribute branch — not yet needed).
            event_id_kw = next((kw for kw in call.keywords if kw.arg == "event_id"), None)
            assert event_id_kw is not None, (
                f"{node.name}: event-class constructor MUST receive an "
                "explicit event_id= keyword — Pydantic's default factory "
                "_new_event_id would mint a random ULID disconnected from "
                "the chain row's sequence/ordinal, breaking SSE "
                "Last-Event-ID resume."
            )
            val = event_id_kw.value
            assert (
                isinstance(val, ast.Call)
                and isinstance(val.func, ast.Name)
                and val.func.id == "_chain_derived_event_id"
            ), (
                f"{node.name}: event_id= MUST be a Call to "
                f"_chain_derived_event_id(...) (got {ast.dump(val)[:200]}). "
                "Literal values, _new_event_id(), or other helpers all "
                "break the deterministic cursor invariant."
            )

            # Pin the canonical chain_id + ordinal args (drift in either
            # breaks the SSE cursor decoder + Last-Event-ID resume).
            _chain_derived_kwargs = {kw.arg: kw.value for kw in val.keywords}
            chain_id_val = _chain_derived_kwargs.get("chain_id")
            chain_id_dump = ast.dump(chain_id_val) if chain_id_val is not None else "MISSING"
            assert (
                isinstance(chain_id_val, ast.Constant) and chain_id_val.value == "decision_history"
            ), (
                f"{node.name}: _chain_derived_event_id(...) MUST pass "
                f'chain_id="decision_history" (got {chain_id_dump}). '
                "All typed projectors fire on the decision-history "
                "chain; the audit-event chain is Wave-2 and uses a "
                "different chain_disc byte."
            )
            ordinal_val = _chain_derived_kwargs.get("ordinal")
            assert isinstance(ordinal_val, ast.Constant) and ordinal_val.value == 0, (
                f"{node.name}: _chain_derived_event_id(...) MUST pass "
                f"ordinal=0 (got {ast.dump(ordinal_val) if ordinal_val else 'MISSING'}). "
                "Per-type projectors emit the ORDINAL-0 typed event; "
                "ordinal=1 is reserved for the decision_audit mirror "
                "built by _build_decision_audit_for_dh_snapshot."
            )

        # 2) Bidirectional drift sentinel between the source's
        # ``_project_<family>_<type>`` function DEFINITIONS and the
        # dispatcher-derived expected set. Walks ALL ``_project_*``
        # functions in source (excluding the dispatcher itself), then
        # asserts source-defs == dispatcher-derived. Catches BOTH:
        #
        #   (a) source ADDED a per-type projector that's NOT in the
        #       dispatcher dict (likely a wiring bug — the new
        #       projector would never be called).
        #   (b) source DROPPED a per-type projector that's STILL in
        #       the dispatcher dict (would ImportError at runtime,
        #       but this fires at test time).
        #   (c) dispatcher dict DROPPED an entry whose per-type
        #       projector function still EXISTS in source as dead
        #       code (R4 P1 #2 follow-up — the earlier sentinel
        #       missed this case because the source-walk filter was
        #       ``if node.name not in expected_projectors``, which
        #       hid the now-orphan def).
        source_per_type_projectors = frozenset(
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name.startswith("_project_")
            # Exclude the dispatcher (returns the result of calling
            # another projector — not a per-type projector itself).
            and node.name != "_project_typed_decision_history"
        )
        assert source_per_type_projectors == expected_projectors, (
            "Per-type projector set drift between source + production "
            "dispatcher. Source-defined ``_project_<family>_<type>`` "
            f"functions: {sorted(source_per_type_projectors)}. "
            "Expected (derived from live _DECISION_HISTORY_TYPED_PROJECTORS "
            f"+ _project_policy_rbac_denied rbac-prefix): "
            f"{sorted(expected_projectors)}. Symmetric difference: "
            f"{sorted(source_per_type_projectors ^ expected_projectors)}."
        )

    def test_invariant_6b_per_type_projector_event_id_matches_recomputed_chain_derived(
        self,
    ) -> None:
        """R5 P1 #2: cross-validate ``family=`` + ``type_=`` arguments
        to ``_chain_derived_event_id(...)`` by RUNTIME re-projection.

        The AST-level invariant 6 pins ``chain_id="decision_history"``
        + ``ordinal=0`` as Constants but allows ANY ``family=`` /
        ``type_=`` values — a projector could return
        ``FrontendActionAccepted(type="accepted")`` while encoding
        the cursor with ``type_="submitted"``, producing a mismatched
        ``type_hash`` that breaks Last-Event-ID replay (the boundary
        type_hash drift detector in ``stream_routes._validate_cursor_tenant``
        would fire 500 ``cursor_projection_drift_detected`` on
        reconnect — silent under unit tests, observable only at
        client reconnect time).

        Cross-validation: for each dispatcher-routed per-type
        projector, call it with a synthetic snapshot, then
        recompute ``_chain_derived_event_id(chain_id="decision_history",
        sequence=snapshot.sequence, ordinal=0, family=event.family,
        type_=event.type)`` from the PROJECTED event's family/type +
        assert the recomputed event_id matches the projected
        event.event_id. A mismatch proves the projector encoded
        wrong family/type into its cursor."""
        import uuid as _uuid
        from datetime import UTC, datetime

        from cognic_agentos.core.decision_history import AppendedDecisionSnapshot
        from cognic_agentos.protocol.ui_events import (
            _DECISION_HISTORY_TYPED_PROJECTORS,
            _chain_derived_event_id,
            _project_typed_decision_history,
        )

        def _snapshot(decision_type: str) -> AppendedDecisionSnapshot:
            return AppendedDecisionSnapshot(
                record_id=_uuid.uuid4(),
                chain_id="decision_history",
                sequence=42,
                new_hash=b"\x00" * 32,
                created_at=datetime.now(UTC),
                decision_type=decision_type,
                request_id="portal-req-test",
                payload={
                    "request_id": "portal-req-test",
                    "actor_subject": "u1",
                    "tenant_id": "t1",
                    "action_class": "approve",
                    "client_correlation_id": None,
                    "payload_digest": "sha256:test",
                },
                tenant_id="t1",
            )

        # Drive every dispatcher-registered decision_type. Plus one
        # rbac.* decision_type to exercise the prefix-match branch
        # (which routes to _project_policy_rbac_denied).
        decision_types_to_check: list[str] = [
            *sorted(_DECISION_HISTORY_TYPED_PROJECTORS.keys()),
            "rbac.scope_not_held",  # routes via _project_policy_rbac_denied
        ]
        for decision_type in decision_types_to_check:
            snapshot = _snapshot(decision_type)
            event = _project_typed_decision_history(snapshot)
            assert event is not None, (
                f"_project_typed_decision_history returned None for "
                f"decision_type={decision_type!r}; dispatch table or "
                "rbac.* prefix routing has drifted."
            )
            # Cross-recompute the cursor using the PROJECTED event's
            # OWN family/type. If the projector encoded wrong values
            # into _chain_derived_event_id(..., family=..., type_=...),
            # the recomputed event_id will NOT equal event.event_id.
            recomputed = _chain_derived_event_id(
                chain_id="decision_history",
                sequence=snapshot.sequence,
                ordinal=0,
                family=event.family,  # type: ignore[attr-defined]
                type_=event.type,  # type: ignore[attr-defined]
            )
            assert event.event_id == recomputed, (
                f"per-type projector for decision_type={decision_type!r} "
                f"emitted event.event_id={event.event_id!r} but recomputed "
                f"from event.family={event.family!r}/event.type={event.type!r} "  # type: ignore[attr-defined]
                f"yields {recomputed!r}. The projector passed the wrong "
                "family= / type_= arguments to _chain_derived_event_id; "
                "the boundary type_hash drift detector at "
                "stream_routes._validate_cursor_tenant would fire "
                "500 cursor_projection_drift_detected on Last-Event-ID "
                "reconnect."
            )
