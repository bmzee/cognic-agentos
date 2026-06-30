"""Per-file coverage gate for critical-controls modules.

Reads ``coverage.json`` (produced by ``pytest --cov-report=json``)
and asserts that EACH listed file independently meets the coverage
threshold. Replaces the combined ``--cov-fail-under=95`` shape that
masks an under-covered file behind a well-covered sibling in the
same target set.

Usage:

    uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json
    uv run python tools/check_critical_coverage.py

Exits 0 if every critical file meets its line + branch thresholds,
1 otherwise. Prints a per-file summary so CI logs are scannable.

Per AGENTS.md amendment in PR #5: ``core/audit.py``,
``core/decision_history.py``, ``core/chain_verifier.py``, and
``core/canonical.py`` are the four critical-controls modules of
Sprint 2. Each one carries ``95%+ line + ≥90% branch`` per the plan;
this script enforces that as a CI gate. Sprint 2.5 added the SLA /
escalation / guardrails triplet at the same floor. Sprint 3 T11
extends the gate to the LLM-gateway-shape quintet (gateway, policy,
preflight, ledger, concurrency) at the same single strict floor —
all five sit on the cloud-policy / provider-honesty path that
ADR-007's authoritativeness contract depends on, and the rate-limit
primitive is small and stable enough to ride the strict gate without
churn. Sprint 4 T15 extends the gate further with the plugin-trust /
supply-chain / policy quartet — ``protocol/plugin_registry.py`` (the
admission orchestrator), ``protocol/trust_gate.py`` (cosign
subprocess gate per ADR-002), ``protocol/supply_chain.py`` (SLSA +
in-toto + SBOM + vuln + license + Sigstore-bundle persister per
ADR-016), and ``core/policy/engine.py`` (the OPA Rego decision
engine per ADR-015). All four are explicitly named on the AGENTS.md
critical-controls list and ride the same single strict floor; gate
size grows from 12 modules to 16.

Sprint 5 T14 extends the gate with the MCP-host quintet —
``protocol/mcp_authz.py`` (OAuth/PRM admission-side authz client per
ADR-002), ``protocol/mcp_capabilities.py`` (signed-manifest capability
validator + STDIO four-gate enforcement), ``protocol/mcp_manifest.py``
(deferred-load signed-manifest extractor), ``protocol/mcp_transports.py``
(Streamable HTTP transport + STDIO non-launching refusal stub per the
Sprint-5 Decision Lock), and ``protocol/mcp_host.py`` (admission-to-
invocation orchestrator + ADR-014 transitional gate + audit /
decision-history correlation). All five sit on the MCP-host critical-
path that ADR-002 (MCP plugin protocol amendment April 2026) and the
April-2026 OX-Security disclosures' threat model depend on, and ride
the same strict 95% line / 90% branch floor; gate size grows from 16
modules to 21.

Sprint 7A T16 extends the gate with the **authoring SDK + CLI**
nonet — nine modules that together form the build-time half of the
trust gate (mirrors the runtime trust gate's protocol/* modules
already on the floor):

  * ``cli/validate.py`` — orchestrator that coordinates the six
    per-concern validators + the shape gate; the build-time
    counterpart to the runtime ``protocol/plugin_registry.py`` per
    Doctrine Decision G.
  * ``cli/validators/identity.py`` — AGNTCY/OASF Wave-1 strictness
    on the [identity] block. Wire-protocol-public for cross-org
    agent discovery.
  * ``cli/validators/a2a.py`` — Wave-2 capability-feature refusal
    on the [a2a] block (T8/R28 promotion call deferred to T16; on
    review the validator owns refusal paths the runtime reader does
    NOT — runtime silently filters, validator refuses → policy, not
    delegation; promoted at T16).
  * ``cli/validators/data_governance.py`` — ADR-017 contract
    validation on the [data_governance] block. Runtime DLP
    enforcement reads the same closed-enum vocabulary.
  * ``cli/validators/supply_chain.py`` — ADR-016 attestation-paths
    declaration validator. Feeds the runtime trust gate.
  * ``cli/sign.py`` — full-bundle generator: cosign sign-blob +
    syft SBOM + grype vuln scan + license audit + AgentCard JWS +
    SLSA provenance + in-toto layout + 7-attestation persister.
    Security-critical signing path.
  * ``cli/verify.py`` — offline trust gate per ADR-016 Sprint-7A
    mandate (R2 P2 #5). 11-step orchestrator mirroring the
    Sprint-4 runtime trust-gate verification path. R15 follow-up
    round 2 P2 #1 moved the load probe to step 11 (FINAL gate)
    so pack code never executes until every non-executing trust
    check has passed.
  * ``cli/_load_probe.py`` — isolated-subprocess EntryPoint.load()
    probe. R15 follow-up round 2 P2 #2 hardened the result channel
    (fd inheritance + per-invocation success token + token-write
    only after ep.load() returns + parent enforces token match).
    Step 11 of the verify trust pipeline.
  * ``cli/_wheel_integrity.py`` — wheel identity + dist-info +
    METADATA + entry-point shape validator. Helper threads the
    validated (module, object) tuples to verify so the load probe
    operates on the same source the helper validated (R15
    follow-up round 1 P2 #1 fix).

All nine ride the same single strict 95% line / 90% branch floor.
Off-gate per Doctrine Decision G's pure-delegation rule:
``cli/validators/mcp.py`` (narrow caching/elicitation refusals
delegating to cross-checks) and ``cli/validators/risk_tier.py``
(closed-enum check + vocabulary delegation). Gate size grows from
28 modules to 37.

Sprint 6 T15 extends the gate with the A2A endpoint septet —
``protocol/a2a_authz.py`` (per-tenant pinned-token validator),
``protocol/a2a_agent_cards.py`` (three-pass Agent Card validator +
JWS verifier; T14 added the 7th profile gate
``agent_card_profile_wave2_auth_required`` for cards declaring
mtlsSecurityScheme — 11-value AgentCardValidationReason),
``protocol/a2a_endpoint.py`` (inbound receiver + task lifecycle
state machine + cross-agent chain linkage),
``protocol/a2a_schema.py`` (pinned A2A 1.0 wire-format types),
``protocol/a2a_version.py`` (A2A-Version 6-case header negotiation —
R0/R2 promoted from non-critical because version negotiation IS
wire-protocol surface per AGENTS.md §"Wire-protocol contracts"),
``protocol/a2a_errors.py`` (spec wire ``A2AErrorCode`` 14 values +
AgentOS ``A2APolicyRefusalReason`` 11 values + their mapping; R3
promoted from non-critical because the mapping IS wire-protocol
contract), and ``protocol/ui_events.py`` (Wave-1 typed event
taxonomy + emit-hook layer per ADR-020 — public event schema, MUST
remain backward-compatible across versions). All seven ride the
same strict 95% line / 90% branch floor; gate size grows from 21
modules to 28.

Sprint 7A2 T12 extends the gate with the **hook-pack runtime + author
quartet** — four modules that together form the runtime + build-time
trust path for ADR-017 hook packs (the 4th first-class pack kind
alongside tool / skill / agent):

  * ``packs/hooks/registry.py`` — admission gate; fail-closed on
    duplicate-ID / stale-digest / cross-pack-conflict; per-pack
    selector tracking. Sprint-7A2 T6.
  * ``packs/hooks/dispatcher.py`` — runtime decision engine; closed-
    enum ``HookDecision`` (pass / redact / mask / refuse); per-pack
    selector semantics + budget-before-lookup precedence; payload-
    never-logged AST regression at
    ``tests/architecture/test_hook_payload_never_logged.py``. Sprint-7A2 T7.
  * ``packs/hooks/dlp_integration.py`` — DLPGuard adapter wrapping
    ``dispatch_for_pack`` with ``dlp_pre`` / ``dlp_post`` phase
    semantics. Closed-enum 3-value ``DLPRefusalReason``
    (``dlp_hook_id_unresolved`` / ``dlp_dispatcher_failed`` /
    ``dlp_dispatcher_refused``); ADR-017 line 97 enforcement
    boundary. T8 commit explicitly tagged ``(CRITICAL CONTROLS)``;
    the refusal-payload-contract-divergence and delegate-first-
    preserves-precedence doctrine memories were both born from T8
    R1 P2 fixes on this module. T12 reconcile decision lifted
    ``dlp_integration.py`` from off-list (provisional Doctrine Lock F
    written before T7+T8 landed) to on-gate; promoted under
    Doctrine Decision G's "non-trivial allow/deny logic" rule (the
    same rule that promoted ``cli/validators/a2a.py`` at Sprint-7A
    T16). Sprint-7A2 T8.
  * ``cli/validators/hooks.py`` — manifest validator + cross-
    reference resolver against ADR-017 declarations. Sprint-7A2 T5.

``sdk/hook.py`` stays off the gate per Doctrine E (public-API
stability halt-before-commit covers it; coverage-gate would be
cargo-cult). Existing critical-controls modules touched by this
sprint (``cli/validate.py``, ``cli/sign.py``, ``cli/verify.py``,
``cli/_wheel_integrity.py``, ``cli/validators/data_governance.py``)
carry forward their existing pinning. All four hook modules ride
the same single strict 95% line / 90% branch floor; gate size grows
from 37 modules to 41.

Sprint 7B.1 T7 extends the gate with the **Bank pack lifecycle**
pair — two modules that together form the ADR-012 lifecycle-state-
machine + storage critical path:

  * ``packs/lifecycle.py`` — pure-functional state machine.
    Closed-enum **14-value** ``LifecycleRefusalReason`` at
    lines 175-190 (13 values finalised at T2 from the plan-of-record's
    provisional ±1 count as the transition table was enumerated; +1
    at Sprint 7B.2 T9 for the locked manifest-digest precondition
    refusal — storage-only-emit, race-condition fix per plan
    §1179-1181).
    ``_VALID_TRANSITIONS`` legal-pair table at :210 (11 transitions
    / 14 legal pairs; Sprint 7B.2 T4 extended from 10/13 by adding
    ``cancel_draft`` per ADR-012 §59). ``validate_transition(*, from_state,
    to_state, kind, transition)`` pure validator at :421 — four
    keyword-only args. ``iso_controls_for(transition)`` at :366
    returns the canonical ISO 42001 control tuple from the
    3-value ``_KNOWN_ISO_CONTROL_CODES`` set ({``A.5.31``,
    ``A.5.32``, ``A.6.2.4``}) feeding chain-row emission.
    ``LifecycleTransitionRefused(reason)`` at :332 carries ONLY
    the closed-enum reason. Doctrine Lock C — the closed-enum
    vocabulary IS the consumer-API wire-protocol contract carried
    by ``LifecycleTransitionRefused.reason``. **Two-tier consumer
    split**: T3 storage (``packs/storage.py:129-130``) is the SOLE
    DIRECT caller of ``iso_controls_for(...)`` +
    ``validate_transition(...)``; the Sprint 7B.2 portal pack-API
    handlers (T4 author / T5 review / T6 operator / T7 inspection)
    consume the ``LifecycleTransitionRefused.reason`` closed-enum
    SURFACED by storage's re-raise (typed-exception catch around
    ``store.transition(...)`` call sites in each handler body).
    ``transition()`` derives the canonical ISO control tuple via
    ``iso_controls_for(transition)`` at :761 BEFORE the precondition
    closure — pure-functional helper, no I/O — then runs
    ``validate_transition(...)`` at :810-815 INSIDE the closure
    under the row-locked view; the precondition raises
    ``LifecycleTransitionRefused`` at :817 (validate-refusal path)
    or at :806-808 (Sprint 7B.2 T9 storage-only-emit digest-mismatch
    path — see below), ``engine.begin()`` at
    ``core/decision_history.py:482`` rolls back the transaction on
    every exception path, and the exception propagates up through
    ``append_with_precondition`` and ``transition()`` to the portal
    handler — neither storage layer catches it. Chain audit events themselves use the
    ``pack.lifecycle.<target_state>`` namespace (keyed by target
    state, not by ``.refused`` — refusals roll back BEFORE any
    chain row is written). Sprint-7B.1 T2.
  * ``packs/storage.py`` — Postgres-backed ``PackRecordStore`` at
    :385; the ``DecisionHistoryStore.append_with_precondition``
    consumer that drives every lifecycle transition through the
    Sprint-2.5 T2 atomic primitive. ``transition()`` at :622
    first runs the preflight transition-name guard at :742-743
    (out-of-vocabulary transitions raise
    ``LifecycleTransitionRefused("lifecycle_transition_name_unknown")``
    BEFORE any helper invocation or DB work; mirrors the
    asymmetric-runtime-guard fix at ``packs/lifecycle.py:416-417``);
    on the green path resolves ``target_state`` at :745 and
    derives the canonical ISO 42001 control tuple via
    ``iso_controls_for(transition)`` at :761 BEFORE the closure
    (pure-functional, no I/O), then enters the row-locked
    precondition closure at :763 (``SELECT ... FOR UPDATE`` on
    the ``packs`` row at :778-783 projecting
    ``state, kind, manifest_digest`` under the chain-head ``FOR
    UPDATE`` lock — Sprint 7B.2 T9 extended the column set from
    ``state, kind`` to add ``manifest_digest`` so the locked
    precondition can cross-check the row's digest against the
    caller's ``expected_manifest_digest`` kwarg) →
    **Sprint 7B.2 T9 storage-only-emit digest cross-check at
    :806-808**: when ``expected_manifest_digest is not None`` AND
    the row-locked ``manifest_digest`` does NOT match, the
    precondition raises
    ``LifecycleTransitionRefused("lifecycle_transition_manifest_digest_changed_during_submit")``
    BEFORE the state-machine validator runs (race-condition fix
    per plan §1179-1181; storage-only-emit because
    ``validate_transition`` has no access to the persisted digest
    column) → ``validate_transition(...)`` at :810-815 under the
    locked view (raises ``LifecycleTransitionRefused(reason)`` at
    :817 on the state-machine refusal path) → ``UPDATE packs SET
    state, last_actor, updated_at`` at :824-832 (three columns;
    no ``version_counter`` field — atomicity comes from the
    chain-head + row lock pair). OUTSIDE the closure:
    ``_build_record`` at :835 mints a ``DecisionRecord`` with
    ``decision_type = f"pack.lifecycle.{target_state}"`` at :866
    and the pre-derived ``canonical_iso_controls`` value (no fresh
    ``iso_controls_for`` call from ``_build_record``). **Sprint 7B.2
    T6 slice-2 (R24 P2 Path B + B2 user-authorized CC-ADJ) added
    the optional keyword-only ``actor_type: str | None = None``
    kwarg at :631; when non-None it is persisted as a top-level
    ``payload["actor_type"]`` key conditionally at :854-855 so
    existing call sites + every pre-T6 chain row stay byte-shape
    compatible (additive-only schema; storage stays a thin string
    passthrough — the ``human | service`` closed-enum lives at the
    rbac boundary).** **Sprint 7B.2 T9 added three further
    optional keyword-only kwargs to ``transition()`` at :632-634
    — ``payload_conformance: dict[str, Any] | None``,
    ``expected_manifest_digest: bytes | None``, and
    ``evidence_attachments: dict[str, Any] | None``; the first +
    third land as conditional ``payload["conformance"]`` /
    ``payload["evidence_attachments"]`` keys at :861-864 via the
    same ``_build_record`` shape pattern as the T6
    ``payload["actor_type"]`` insert (omitted kwargs add NO empty
    keys); the second feeds the storage-only-emit digest cross-
    check above. Storage stays a thin passthrough — vocabulary /
    shape validation lives at the portal route boundary, not
    storage.** ``append_with_precondition`` at :874 commits
    chain row + state-cache UPDATE + chain-head UPDATE atomically.
    Two-class refusal taxonomy: ``PackNotFound`` at :272 for
    missing-pack lookups; ``PackRecordRefused`` at :299-356
    carrying the 4-value ``PackRecordRefusalReason`` Literal at
    :291 (genesis-state guard + 3 update_draft API-contract
    refusals — Sprint 7B.2 T4 bumped 1 → 4 when ``update_draft()``
    landed; ``update_draft()`` itself at :449 mirrors
    ``save_draft()``'s genesis-state pattern at :402 — atomic
    ``UPDATE … WHERE state='draft'``, no chain row); transition-
    table refusals raise ``LifecycleTransitionRefused`` from the
    precondition at :817 so the engine's transactional rollback
    fires (no chain row, no state-cache mutation, no orphan
    INSERT). **Sprint 7B.2 T7 CC-ADJ extension (Slice 1 — pure
    read; no Doctrine Lock D touch)**: NEW ``list_for_tenant(...)``
    at :933 + module-private ``_build_list_for_tenant_stmt(...)``
    at :1073 — the AUTHORITATIVE tenant-scoped read seam for the
    T7 inspection-list endpoint (the only inspection endpoint
    without a ``{pack_id}`` path-param, so server-side WHERE clause
    ``tenant_id == :tenant_id`` IS the tenant boundary). REQUIRED
    positional-or-keyword ``tenant_id`` BEFORE the ``*`` separator
    (NOT optional like ``list_by_status``'s tenant kwarg); the
    Slice-1 SQL-shape regression imports the SAME builder + asserts
    on the compiled output (shared-builder pattern eliminates the
    vacuous-proof bug class). Doctrine Lock D. Sprint-7B.1 T3.

Both modules ride the same single strict 95% line / 90% branch
floor. Off-gate per Doctrine F gate-counting rule: the Alembic
migration version file at
``src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py``
— DDL is doctrine-critical but not coverage-tracked by convention
(migrations are run-once executable schema, not behavioural code).
Gate size grows from 41 modules to 43.

Sprint 7B.2 T6 extends the gate with the **operator-surface route
module** — one module that owns the 5 ADR-012 §68-73 operator
lifecycle endpoints behind ``/api/v1/packs``:

  * ``portal/api/packs/operator_routes.py`` — 5 endpoints
    (POST ``/{pack_id}/allow-list`` + POST ``/{pack_id}/install`` +
    POST ``/{pack_id}/disable`` + POST ``/{pack_id}/revoke`` + DELETE
    ``/{pack_id}/install`` for uninstall). The allow-list endpoint
    is the **single user-authorized site for the AGENTS.md
    "Human-only decisions / Per-tenant allow-list changes" doctrine
    enforcement** — wired with :func:`RequireHumanActor` so a
    service-token actor holding ``pack.allow_list`` scope is refused
    at the dep chain (closed-enum
    ``HumanActorDenialReason("actor_type_must_be_human")``) before
    the handler body runs. The module also owns the watchpoint (d)
    examiner-traceability surface for the allow-list audit row: the
    green-path ``portal.packs.allow_list`` structured log carries
    ``actor_type`` AND the chain row's ``payload["actor_type"]``
    records the same value via R24 Path B + B2 (the storage CC-ADJ
    threaded through ``actor_type=actor.actor_type`` on every call
    to :meth:`PackRecordStore.transition`). All 5 handlers share a
    delegate-to-storage 3-arm refusal pattern: :class:`PackNotFound`
    → 404 ``pack_not_found`` + ``portal.packs.<verb>_refused`` log;
    :class:`LifecycleTransitionRefused` → 409 + closed-enum reason
    + ``portal.packs.<verb>_refused`` log; green path returns the
    re-loaded :class:`PackResponse`. Per R19 P2 #2 mutually-
    exclusive log contract: RBAC / tenant / human-actor dep-chain
    refusals emit their OWN sibling-guard logs (zero operator-vocab
    log); handler-body refusals (state-machine OR PackNotFound
    race) emit EXACTLY ONE ``portal.packs.<verb>_refused``. The
    R27-hardened race contract pins this on the
    :class:`PackNotFound` axis for every verb (caplog asserts
    reason / actor_subject / pack_id / from_state on the refused
    log; threat-model-revert verified load-bearing). Multi-from-
    state pairs (revoke installed/disabled → revoked; uninstall
    disabled/revoked → uninstalled) are pinned explicitly per leg.
    The module also owns the per-verb request-id minter prefixes
    (``_PACK_{ALLOW_LIST,INSTALL,DISABLE,REVOKE,UNINSTALL}_REQUEST_ID_PREFIX``
    at module scope; 13 chars each; the module-foot build-time
    ``assert`` pins the ``len(prefix) + 32 (uuid4().hex) <= 64``
    invariant against the ``decision_history.request_id`` String(64)
    column cap). Standing-offer §30 module-header invariant: ``from
    __future__ import annotations`` is INTENTIONALLY OMITTED — PEP
    563 string-deferred annotations would break FastAPI's
    ``inspect.signature()`` / ``typing.get_type_hints()`` resolution
    on ``Annotated[..., Depends(<closure-local>)]`` annotations
    (the shared dependency instances are local-scope inside
    :func:`build_operator_routes`, NOT module globals); pinned by
    AST self-test + per-verb invocation tests at
    ``tests/unit/portal/api/packs/test_operator_routes.py`` per
    ``feedback_security_regression_hardening.md`` (threat-model-
    revert verified at slice-1 + slice-2 + slice-4 boundaries).
    Sprint-7B.2 T6.

T6 scope note: this commit adds ``operator_routes.py`` to the
durable per-file critical-controls coverage gate because it owns
the AGENTS.md "Human-only decisions" enforcement boundary
(:func:`RequireHumanActor` sub-dependency on allow-list) + the
R24 actor_type chain-payload provenance surface — both
wire-protocol-public surfaces. Whether the sibling pack-router
modules already classified CC at commit time
(``portal/api/packs/author_routes.py`` per T4,
``portal/api/packs/review_routes.py`` per T5,
``portal/api/packs/router.py`` per T3) should ALSO be added to
this durable per-file gate is a separate doctrinal decision —
T6 deliberately does NOT change their on-gate status either way;
the CC tag carried by their respective landing commits stays as-is
until explicitly reviewed. Off-gate per public-API-stability rule:
``packs/storage.py``'s ``actor_type`` kwarg shape change (R24) is
doctrine-critical but is covered transitively via the existing
``packs/storage.py`` gate entry + 3 dedicated R24 backward-compat
tests at ``tests/unit/packs/test_storage.py``.

The module rides the same single strict 95% line / 90% branch
floor as the rest of the critical-controls gate. Gate size grows
from 43 modules to 44.

Sprint 7B.2 T8 extends the gate with the **OWASP conformance check
matrix** pair (ADR-012 §119 + BUILD_PLAN §628) — both modules form
the wire-protocol-public reviewer-evidence surface that T9 attaches
to the chain payload's ``payload.conformance`` and 7B.3 reviewers
consume:

  * ``packs/conformance/checks.py`` — closed-enum 10-value
    :data:`OWASPCheckCategory` Literal + the 3-value
    :data:`ConformanceCheckStatus` + :data:`ConformanceOverallStatus`
    Literals + the frozen :class:`ConformanceCheckResult` +
    :class:`ConformanceReport` (4-field order:
    ``overall_status, results, summary, errored_categories``)
    dataclasses. Wire-protocol-public per ADR-006 — drift in the
    Literal vocabulary or the dataclass field order breaks evidence-
    pack export readers.
  * ``packs/conformance/owasp_agentic.py`` — 10 deterministic
    manifest-shape check bodies (``check_tool_misuse``,
    ``check_goal_hijacking``, ``check_identity_abuse``,
    ``check_prompt_injected_skills``, ``check_dependency_poisoning``,
    ``check_secret_exfiltration``, ``check_unsafe_filesystem``,
    ``check_unsafe_network``, ``check_supply_chain_integrity``,
    ``check_skills_top_10``), the :data:`_APPLICABILITY` matrix
    (per-pack-kind 10x4 declarative gate; examiner-readable from the
    static table without running the suite), the
    :data:`_CHECK_REGISTRY` ordered tuple (1:1 with the Literal), and
    the :func:`run_owasp_conformance` dispatcher. The dispatcher
    consults :data:`_APPLICABILITY` BEFORE invoking each check body —
    on a known kind not in the applicability set the runner
    synthesises a ``not_applicable`` result with a
    ``manifest.pack.kind:`` field-path prefix WITHOUT calling the
    body. Bodies are wrapped in ``try / except Exception`` so a
    checker raising synthesises a ``not_applicable`` result with the
    user-locked exact format ``"manifest: <category> checker raised
    <ExcType>: <message>"`` AND appends the category to
    :class:`ConformanceReport.errored_categories`. Overall-status
    precedence: **yellow > red > green** — yellow takes precedence
    over red because a checker exception means the suite is
    incomplete and the red/green verdict is not trustworthy.

Per-check enum is preserved at 3 values (``pass`` / ``fail`` /
``not_applicable``); ``yellow`` lives ONLY on the composite report.
Findings are ``list[str]`` with stable field-path prefixes
(``manifest.<path>: <reason>``). Checks are deterministic +
manifest-shape only: no filesystem reads, no network calls, no
dependency downloads, no digest recomputation (the CLI validators
at ``cli/validators/identity.py`` etc. own the file-system-
touching checks at build/admission time; conformance runtime
duplicates only the small manifest-shape subset and never reaches
back into CLI plumbing).

The ``__init__.py`` re-exports only (no behaviour) and is
off-gate per Doctrine F. A cross-set drift guard at
``test_owasp_applicability.py::TestCategorySetCohesion`` pins
that :data:`OWASPCheckCategory`, :data:`_CHECK_REGISTRY`, and
:data:`_APPLICABILITY` all carry the same 10-element category set
in registry-iteration order — drift in any one of the three is the
most-likely future regression class.

Both modules ride the same single strict 95% line / 90% branch
floor as the rest of the critical-controls gate. Gate size grows
from 44 modules to 46.

Sprint 7B.2 T9 Slice 4 promotes the **chain-payload serialization
adapter** to the durable gate (plan §1062-1252; gate 46 → 47):

  * ``packs/conformance/runner.py`` —
    :func:`run_owasp_conformance_for_chain_payload(manifest) ->
    dict[str, Any]` is the WIRE-SHAPE boundary between the
    :func:`run_owasp_conformance` check matrix and the chain row's
    ``payload["conformance"]`` key.  Delegates to the T8 dispatcher
    for the check matrix, then converts the returned
    :class:`ConformanceReport` via :func:`dataclasses.asdict` and
    EXPLICITLY converts ``errored_categories`` from tuple to list.
    The tuple → list conversion is load-bearing: Python's
    :func:`dataclasses.asdict` PRESERVES tuple-typed fields, but the
    Sprint-2 canonical-form at
    :func:`cognic_agentos.core.canonical.canonical_bytes` REJECTS
    tuples in chain payloads (to prevent the silent list/tuple
    ambiguity bug class).  Without the explicit conversion the
    chain insert at every T9 submit would fail with a TypeError on
    the canonical-form gate.  The 4-key top-level shape
    (``overall_status, results, summary, errored_categories``) is
    wire-protocol-public per ADR-006 — T9 chain payload consumers +
    7B.3 reviewer evidence panels read this exact dict shape.

T9 promotes runner.py — NOT pure re-export glue — because it owns
the chain-payload serialization contract (including the canonical-
form-required tuple/list conversion).  Drift in either the 4-key
top-level shape or the tuple → list invariant breaks chain-payload
byte-stability + canonical-form acceptance + 7B.3 reviewer
consumer schemas.  Pinned by
``tests/unit/packs/conformance/test_runner.py``'s 9-test wire-
shape suite.

Rides the same single strict 95% line / 90% branch floor.  Gate
size grows from 46 modules to 47.

----------------------------------------------------------------------
Sprint 7B.2 T12 — Portal RBAC + portal pack API promotions (gate 47 → 55).
----------------------------------------------------------------------

T12 completes the plan §1304-1314 critical-controls floor uplift for
Sprint 7B.2.  The plan claimed a 12-module bump (43 → 55) but 4 of
those modules were promoted incrementally during T6 / T8 / T9 as
each landed its own halt-before-commit critical-controls review
(``operator_routes.py`` at T6; ``conformance/checks.py`` +
``conformance/owasp_agentic.py`` at T8; ``conformance/runner.py`` at
T9 Slice 4).  T12 promotes the remaining 8:

  * Portal RBAC primitives (6 modules) — closed-enum vocabularies
    are wire-protocol-public per ADR-012 §40 + ADR-008:
    - ``portal/rbac/scopes.py`` — 13-value ``PackRBACScope`` Literal
      (12 BUILD_PLAN §622-625 lifecycle scopes + the Sprint-7B.3-T8
      ADR-012 §107-110 override scope ``pack.override.approval_gate``)
      + 4 role-group frozensets plus ``OVERRIDE_SCOPES`` whose 5-way
      union equals ``PACK_LIFECYCLE_SCOPES`` (partition invariant).
    - ``portal/rbac/actor.py`` — frozen ``Actor`` Pydantic model +
      2-value ``ActorType`` Literal.  Identity boundary at the
      portal admission seam + production-grade fail-loud default
      (unconfigured actor providers raise ``NotImplementedError``).
    - ``portal/rbac/enforcement.py`` — ``RequireScope`` factory +
      3-value ``RBACDenialReason``
      (``actor_unauthenticated`` / ``scope_not_held`` /
      ``actor_binder_not_configured``).
    - ``portal/rbac/tenant_isolation.py`` —
      ``RequireTenantOwnership`` factory + 4-value
      ``TenantIsolationFailure``.  Cross-tenant 404 doctrine: pack
      belonging to tenant A is INVISIBLE to tenant B (404 not 403
      so a probe cannot enumerate cross-tenant pack-IDs).
    - ``portal/rbac/human_actor.py`` — ``RequireHumanActor`` +
      1-value ``HumanActorDenialReason``.  Single user-authorized
      site for the AGENTS.md "Per-tenant allow-list changes"
      Human-only-decisions doctrine — wired as a sub-dependency on
      the allow-list endpoint at ``operator_routes.py``.
    - ``portal/rbac/role_separation.py`` —
      ``RequireDifferentActorThanCreator`` factory + 1-value
      ``RoleSeparationFailure``.  ADR-012 §17 cross-role
      separation: the actor who created a pack MUST NOT review it.

  * Portal pack API route modules (2) — wire-protocol-public author
    + review surfaces:
    - ``portal/api/packs/author_routes.py`` — owns the T9 Slice 2
      route-owned 4-way refusal union via
      ``AuthorRequestRefusalReason = Literal["manifest_digest_mismatch"]``
      + auto-runs OWASP conformance + threads
      ``expected_manifest_digest`` to close the TOCTOU window
      per plan §1179-1181.
    - ``portal/api/packs/review_routes.py`` — owns claim / approve /
      reject / evidence-read endpoints + the T9 Slice 3 dual-surface
      emission contract (rejection reason + comments land on BOTH
      the structured log AND the chain row's
      ``payload["evidence_attachments"]``).

Off-floor rationale for the modules T12 deliberately does NOT
promote (each carrying its own doctrinal carve-out documented at
the call site):

  * ``portal/api/packs/inspection_routes.py`` (T7) — pure-read
    endpoints; no ``store.transition()`` calls; no chain-row
    writes; no Human-only-decisions enforcement boundary.  The
    R32 doctrine kept it off the durable gate because the CC risk
    for its tenant-isolation boundary is fully covered by
    ``packs/storage.py``'s ``list_for_tenant`` method already on
    the gate from T7 Slice 1.
  * ``portal/api/packs/router.py`` (T3) — sub-router scaffolding
    file.  No decision logic; no closed-enum vocabulary; no
    refusal taxonomy.  Carrier file only.
  * ``cli/conformance.py`` (T10) + ``cli/test_harness.py`` (T11
    extension) — authoring/dev-only public CLI commands per
    Sprint-7A T13 R4 P3 #5 doctrine ("public command, NOT
    test-only path, off-floor because every gate it surfaces is
    enforced upstream by the on-floor matrix at
    ``packs/conformance/owasp_agentic.py``").  Both delegate to
    the on-floor matrix for the actual decision logic; the CLI
    modules carry only manifest-parse + dispatch + render +
    exit-code translation glue.

Rides the same single strict 95% line / 90% branch floor.  Gate
size grows from 47 modules to 55 (+8).  All promoted modules
verified at line=100%/branch=100% in the T11 + R45 + R46 fresh
coverage.json baseline.

----------------------------------------------------------------------
Sprint 7B.3 — Reviewer evidence panels + 5-gate composer (gate 55 → 60).
----------------------------------------------------------------------

Sprint 7B.3 ships the 4 reviewer evidence panels + the pure-functional
5-gate approval composer per ADR-012 §41 + §107-119.  Unlike the
Sprint 7B.2 T12 batch promotion, every 7B.3 critical-controls module
was promoted to the durable gate *by its own landing commit* (the
per-task-promotion pattern) — the entries already appear in
``_CRITICAL_FILES`` below with their per-task inline rationale.  This
section records the batch for the docstring audit trail; T11 itself
adds NO new ``_CRITICAL_FILES`` entry.

  * ``packs/evidence/data_governance.py`` (T3) — ADR-017 data-
    governance evidence panel projector + the wire-protocol-public
    ``DataGovernanceDiffFlag`` closed-enum.
  * ``packs/evidence/risk_tier.py`` (T4) — ADR-014 risk-tier evidence
    panel + the ``ApprovalFlowKind`` closed-enum + the 1:1
    ``_RISK_TIER_TO_APPROVAL_FLOW`` mapping table.
  * ``packs/evidence/supply_chain.py`` (T5) — ADR-016 supply-chain
    evidence panel + the ``AttestationKind`` closed-enum + the
    7-year sigstore-bundle retention-floor math.
  * ``packs/evidence/conformance_matrix.py`` (T6) — ADR-002 + ADR-003
    protocol-conformance evidence panel + the ``MatrixComparisonFlag``
    closed-enum + the R9 kind-applicability matrix + the persisted-
    OWASP-verdict reconstruction.
  * ``packs/approval_gates.py`` (T7) — ADR-012 §41 five-gate approval
    composer; the pure-functional ``compose_approval_gates`` decides
    the ``under_review → approved`` transition + owns 10 wire-
    protocol-public closed-enum Literals + the T8 override path.

Off-floor rationale for the 7B.3 route + scaffolding modules that
deliberately do NOT promote (each carrying its own doctrinal carve-out
documented at the call site):

  * ``portal/api/packs/evidence_routes.py`` (T3-T6 panel handlers +
    the T10 audit-emission seam) — same R32 doctrine as
    ``inspection_routes.py``: the module owns no Human-only-decisions
    enforcement boundary and no actor_type chain-payload provenance
    surface.  The T10 ``pack.evidence_read.<panel>`` audit events are
    emitted through ``packs/storage.py``'s
    ``append_evidence_read_event`` method, which is ALREADY on the
    durable gate — the CC risk is covered upstream.  (Plan Round-19
    user decision, 2026-05-15, superseding the R3 P2 #3 on-gate
    projection.)
  * ``portal/api/packs/router.py`` — sub-router scaffolding.  The
    7B.3 wiring extension (threading ``trust_gate`` /
    ``trust_root_resolver`` through to the new
    ``build_evidence_routes`` include) adds no decision logic, no
    closed-enum vocabulary, and no refusal taxonomy.  Carrier file
    only — consistent with the Sprint 7B.2 T3 carve-out.

Rides the same single strict 95% line / 90% branch floor.  Gate size
grows from 55 modules to 60 (+5).  The count is pinned by the T11
self-test at ``tests/unit/tools/test_check_critical_coverage.py``.

----------------------------------------------------------------------
Sprint 7B.4 — UI event-stream endpoints (gate 60 → 63).
----------------------------------------------------------------------

Sprint 7B.4 ships the ADR-020 UI event-stream surface — typed-event
broker (T4 extension to ``protocol/ui_events.py``), 5-step
elicitation gate (T8 ``elicitation_gate.py``), 3 SSE GET endpoints
+ Last-Event-ID + reconnect (T10 ``stream_routes.py``), POST /actions
discriminated-union dispatch + RequireUIAction (T11
``action_routes.py``), .well-known schema publication (T12), full
``create_app`` wiring (T12 portal/api/app.py CC-ADJ extension).  3
modules promoted to the durable gate at T13:

  * ``portal/api/ui/action_routes.py`` (T11) — wire-protocol-public
    POST /api/v1/ui/actions + RequireUIAction FastAPI dep + 6-class
    discriminated-union dispatch + submit_elicitation gate routing
    + frontend_action.{submitted,accepted,rejected} chain emit via
    the broker centralisation seam.  The 10-value
    ``ActionRejectionReason`` Literal (defined in
    ``portal/api/ui/dto.py``; mirrored in ``elicitation_gate.py``)
    is the wire vocabulary every refusal body carries; closed-enum
    drift is wire-break.

  * ``portal/api/ui/stream_routes.py`` (T10) — reconnect-safe SSE
    transport.  Owns the 4-value ``CursorRefusalReason`` Literal
    (``cursor_malformed`` / ``cursor_chain_unsupported`` /
    ``cursor_not_found`` / ``cursor_projection_drift_detected`` —
    ``cursor_tenant_mismatch`` deliberately NOT in the enum per the
    cross-tenant-invisible doctrine; cross-tenant cursors emit
    ``pack_not_found`` instead).  Cross-tenant 404 invisibility +
    type_hash drift detection (pre-stream, in
    ``_validate_cursor_tenant``) + boundary-row dedup are all
    load-bearing security properties pinned by TM-revert tests.

  * ``portal/api/ui/elicitation_gate.py`` (T8) — substantive policy
    boundary for submit_elicitation.  5-step refusal contract
    (adapter wired? → ctx lookup → mode parity → restricted-data-
    class → Rego eval) + 10-value ``ActionRejectionReason`` Literal
    carrier (parallel definition with ``portal/api/ui/dto.py``;
    lockstep pinned by the test-only drift detector at
    ``tests/unit/portal/api/ui/test_dto_action.py
    ::TestActionRejectionReasonCrossModuleEquality``).  Pure-async
    + returns ``GateOutcome``; HTTP mapping is in
    ``action_routes.py`` at the call site, NOT here.

Off-floor rationale for the 7B.4 modules that deliberately do NOT
promote (each carrying its own doctrinal carve-out):

  * ``portal/api/ui/dto.py`` (T9) — pure type-only DTOs + closed-enum
    Literals + Pydantic v2 discriminated unions.  No runtime logic;
    drift in the wire types is caught at Pydantic parse time +
    static type checks.  Same precedent as ``portal/api/packs/dto.py``.

  * ``portal/api/ui/router.py`` (T12) — composition factory.  Threads
    closure-captured deps into ``build_stream_routes(...)`` +
    ``build_action_routes(...)``.  Carrier file with no decision
    logic, no closed-enum vocabulary, no refusal taxonomy.

  * ``portal/api/ui/well_known_routes.py`` (T12) — schema publication.
    Builds the snapshot-pinned JSON Schema bundle via
    ``pydantic.TypeAdapter(union).json_schema()`` over the 11 Wave-1
    family discriminated unions; the snapshot-drift regression at
    ``tests/unit/portal/api/ui/test_well_known_routes.py
    ::TestSchemaSnapshotPinned`` is the load-bearing pin.  No
    decision logic.

  * ``protocol/elicitation_adapter.py`` (Sprint-7B.4 T7-foundation)
    — narrow ``@runtime_checkable`` Protocol + frozen dataclasses
    (``ElicitationContext`` / ``ElicitationResult``) + the
    ``ElicitationBackendError`` exception class.  Bank overlays
    implement this Protocol; AgentOS ships only the
    ``KernelDefaultElicitationAdapter`` fail-loud scaffold.  Off-floor
    because the module is pure type-contract + exception class —
    every meaningful invariant (Protocol method shape, dataclass
    field set, exception identity) is enforced at the call site
    (``portal/api/ui/elicitation_gate.py`` is on the floor + covers
    the runtime contract) or via type-shape regressions
    (``tests/unit/protocol/test_ui_events_dh_replay_snapshot.py``
    precedent applies to any future shape pin needed here).  Coverage
    on a pure-Protocol module would measure runtime-import + class-
    decoration lines only — no decision logic to gate.

  * ``portal/api/ui/__init__.py`` — package marker.

Rides the same single strict 95% line / 90% branch floor.  Gate size
grows from 60 modules to 63 (+3).  The count is pinned by the T13
self-test at ``tests/unit/tools/test_check_critical_coverage.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

#: Critical files + their thresholds. Each entry: (path, line_floor,
#: branch_floor) — both as ratios in [0, 1]. Path is relative to the
#: repo root (matches the keys coverage.json emits).
_CRITICAL_FILES: tuple[tuple[str, float, float], ...] = (
    # Sprint 2 critical-controls quartet — chain-of-custody substrate.
    ("src/cognic_agentos/core/audit.py", 0.95, 0.90),
    ("src/cognic_agentos/core/canonical.py", 0.95, 0.90),
    ("src/cognic_agentos/core/chain_verifier.py", 0.95, 0.90),
    ("src/cognic_agentos/core/decision_history.py", 0.95, 0.90),
    # Sprint 2.5 critical-controls triplet — operational primitives
    # consuming the Sprint-2 substrate. All three named in AGENTS.md
    # critical-controls list; all three carry the same per-file
    # floors as Sprint 2 (95% line / 90% branch).
    ("src/cognic_agentos/core/sla.py", 0.95, 0.90),
    ("src/cognic_agentos/core/escalation.py", 0.95, 0.90),
    ("src/cognic_agentos/core/guardrails.py", 0.95, 0.90),
    # Sprint 3 T11 — LLM-gateway-shape critical-controls quintet.
    # ``llm/gateway.py`` is explicitly named on the AGENTS.md
    # critical-controls list (cloud-policy enforcer + provider-
    # honesty ledger feed). The other four are co-load-bearing for
    # the same surface and ride the same single strict floor:
    #   * ``policy.py`` is the cloud-policy decision engine the
    #     gateway delegates to — fail-closed denials on provenance
    #     gaps (ADR-007) live here.
    #   * ``preflight.py`` owns LiteLLM-alias → ResolvedUpstream
    #     resolution + the four-state provenance + the api_base-
    #     aware classifier; mis-classifications here become silent
    #     cloud-policy holes.
    #   * ``ledger.py`` is the authoritative writer for
    #     ``/effective-routing`` (ADR-007 §"two layers"); the
    #     "no successful return without persisted ledger row"
    #     contract is enforced here.
    #   * ``concurrency.py`` is the per-profile rate-limiter; small
    #     (~50 stmts) and stable, kept at the strict floor for
    #     consistency rather than carrying an operational tier.
    ("src/cognic_agentos/llm/gateway.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/policy.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/preflight.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/ledger.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/concurrency.py", 0.95, 0.90),
    # Sprint 4 T15 — plugin-trust / supply-chain / policy quartet.
    # All four are explicitly named on the AGENTS.md critical-controls
    # list (per the Sprint-4 ADR-002 / ADR-015 / ADR-016 amendments)
    # and ride the same single strict 95% line / 90% branch floor as
    # the Sprint-2/2.5/3 modules above:
    #   * ``plugin_registry.py`` is the admission orchestrator that
    #     calls every other verifier in sequence and emits the closed-
    #     enum ``RefusalReason`` on any deny path (fail-closed).
    #   * ``trust_gate.py`` is the cosign subprocess gate; the eight
    #     §2 secure-subprocess invariants live here (no shell, list-
    #     form argv, version+regex pinned, timeout, output ignored
    #     for parsing, etc.).
    #   * ``supply_chain.py`` verifies SBOM + SLSA L3+ + in-toto +
    #     vuln + license, then atomically persists the Sigstore bundle
    #     under 7-year retention per ADR-016 §"Retention".
    #   * ``core/policy/engine.py`` is the OPA Rego decision engine;
    #     fail-closed on every engine error path (ADR-015 §"Default-
    #     deny posture").
    ("src/cognic_agentos/protocol/plugin_registry.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/trust_gate.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/supply_chain.py", 0.95, 0.90),
    ("src/cognic_agentos/core/policy/engine.py", 0.95, 0.90),
    # Sprint 5 T14 — MCP-host critical-controls quintet. The Sprint-5
    # plan-of-record nominates these five modules as the MCP-host
    # critical-controls floor; T14 lands them in this gate. T15 is the
    # corresponding AGENTS.md doctrine update that mirrors this gate
    # under a new "Protocol — MCP host (Sprint 5)" section. (Pre-T15,
    # AGENTS.md only names ``protocol/mcp_authz.py`` under "Protocol
    # authorization"; T15 expands that list to match this gate so the
    # gate config + doctrine document stay in sync.) All five ride the
    # same single strict 95% line / 90% branch floor as Sprint-2/2.5/
    # 3/4 modules:
    #   * ``mcp_authz.py`` is the admission-side OAuth/PRM authz
    #     client — RFC 8707 resource indicator + AS allow-list +
    #     Token cache with refresh + audit / decision-history feed
    #     per the Sprint-5 plan's auth-probe contract.
    #   * ``mcp_capabilities.py`` is the signed-manifest capability
    #     validator. Sprint-5 closed-enum 12-value vocabulary (10
    #     original + ``mcp_http_manifest_shape_invalid`` from T15 R1
    #     P2 #6 + ``mcp_tool_data_classes_shape_invalid`` from T15
    #     R2 P2) + STDIO four-gate enforcement + Decision Lock
    #     umbrella; fail-closed on every pack-controlled-TOML
    #     defect path (HTTP-family ``server_url`` / ``scopes`` shape,
    #     tool ``data_classes`` shape, malformed transport, missing
    #     auth surface, restricted-data-class on form / TTL gates).
    #   * ``mcp_manifest.py`` is the deferred-load signed-manifest
    #     extractor. Resolves ``cognic-pack-manifest.toml`` via
    #     ``Distribution.locate_file()`` WITHOUT importing pack
    #     code per ADR-002 §gate 1; the deferred-load invariant.
    #   * ``mcp_transports.py`` carries the two protocol-side transport
    #     classes: the Streamable HTTP transport (canonical MCP SDK
    #     ``streamablehttp_client`` wiring + ``open_session`` /
    #     ``send`` / ``close_session`` lifecycle + transport
    #     ``event_hook`` contract for emitting transport events). Hook-
    #     failure semantics are PER EVENT and intentionally non-
    #     uniform: only ``send_error`` emission is safe-swallowed (via
    #     ``_emit_send_error_safe``) so a broken audit hook can't mask
    #     the underlying ``mcp_call_tool_timeout`` /
    #     ``mcp_transport_send_failed`` taxonomies; the
    #     ``session_open`` event is fail-closed (hook exceptions
    #     re-raise after the AsyncExitStack is closed); ``session_close``
    #     hook failures are best-effort and may propagate to the
    #     host's close path. Plus the STDIO non-launching refusal stub
    #     per the Sprint-5 Decision Lock (three transport methods, all
    #     NotImplementedError; no ``register`` method, no audit-event
    #     emission). Pagination, per-tenant caching, descriptor
    #     handling, and cursor opacity are NOT transport
    #     responsibilities — they live on the host.
    #   * ``mcp_host.py`` is the admission-to-invocation orchestrator
    #     and owns: ADR-014 transitional high-risk-tier gate;
    #     audit-chain + decision-history correlation via
    #     ``_emit_call_evidence``; ``_DispatchContext`` for split
    #     acquired-vs-dispatched token state; ``mcp_orchestrator_error``
    #     closed-enum catch-all; per-tenant ``list_tools`` cache (key
    #     tuple ``(tenant_id, server_id, manifest_scopes)`` for
    #     cross-tenant isolation);
    #     bounded pagination with cap + cycle detection via opaque
    #     SHA-256 cursor fingerprints; deep-copy of returned tool
    #     descriptors so callers can't mutate cache entries.
    ("src/cognic_agentos/protocol/mcp_authz.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/mcp_capabilities.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/mcp_manifest.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/mcp_transports.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/mcp_host.py", 0.95, 0.90),
    # PR-1 Slice 2 (ADR-002 trust-register-then-defer) — the discovery_status axis owns the
    # wire-visible ``DiscoveryStatus`` enum (surfaced on /system/plugins) + the AuthzReason ->
    # discovery_status mapper; critical-control-adjacent (small, pure, heavily tested).
    ("src/cognic_agentos/protocol/discovery_status.py", 0.95, 0.90),
    # Sprint 6 T15 — A2A endpoint septet (R2 P2 #4 reviewer correction
    # expanded the original quintet with ``a2a_version.py`` — version
    # negotiation IS wire-protocol surface per AGENTS.md
    # §"Wire-protocol contracts"; R3 P2 #2 reviewer correction added
    # ``a2a_errors.py`` — the spec wire error enum + AgentOS policy-
    # refusal enum + their mapping all live there, and drift in any of
    # those is wire-protocol-public). The Sprint-6 plan-of-record
    # nominates these **seven** modules as the A2A critical-controls
    # floor; T15 lands them in this gate. T16 is the corresponding
    # AGENTS.md doctrine update that mirrors this gate under a new
    # "Protocol — A2A endpoint (Sprint 6)" section. All seven ride the
    # same single strict 95% line / 90% branch floor as
    # Sprint-2/2.5/3/4/5 modules:
    #   * ``a2a_authz.py`` is the per-tenant pinned-token validator —
    #     closed-enum 8-value A2AAuthzReason; Vault-read exception
    #     mapping per Sprint-5 T15 R1 P2 #2 doctrine.
    #   * ``a2a_agent_cards.py`` is the three-pass Agent Card validator
    #     + JWS verifier. Pass 1 upstream A2A 1.0 schema; Pass 2
    #     AgentOS bank-grade profile (T14 added the 7th profile gate
    #     ``agent_card_profile_wave2_auth_required`` for cards
    #     declaring mtlsSecurityScheme — 11-value
    #     AgentCardValidationReason). JWS rides Sprint-4 trust root.
    #     Identity-routing critical: a forged card routes outbound
    #     traffic to attacker-controlled endpoints.
    #   * ``a2a_endpoint.py`` is the inbound receiver + task lifecycle
    #     state machine + cross-agent chain linkage. Anonymous-refusal
    #     gate + Wave-2-refusal gate live here. Single-writer for the
    #     TaskState transitions.
    #   * ``a2a_schema.py`` is the pinned A2A 1.0 wire-format types.
    #     Wire-format drift = wire-protocol break; the schema-drift CI
    #     gate (test_a2a_schema_drift.py) catches upstream movement
    #     before it reaches us. Pinned digest constants + the upstream
    #     URL constants live here.
    #   * ``a2a_version.py`` is the A2A-Version 6-case header
    #     negotiation matrix. Wire-protocol gate every inbound A2A
    #     call passes through; closed-enum A2AVersionOutcome carries
    #     the per-case behaviour. Module is small + pure-functional but
    #     the doctrinal surface is wire-protocol-public (R0 P2 #4 +
    #     R2 P2 #4 reviewer corrections promoted from non-critical).
    #   * ``a2a_errors.py`` owns the spec wire ``A2AErrorCode`` literal
    #     (14 spec-defined codes) + the AgentOS ``A2APolicyRefusalReason``
    #     literal (11 policy reasons) + ``_POLICY_REASON_TO_SPEC_CODE``
    #     mapping (drives the error-response builder; what remote
    #     callers actually see). Drift in any of these is wire-protocol-
    #     public; promoted from non-critical at R3 P2 #2.
    #   * ``ui_events.py`` is the Wave-1 typed event taxonomy + emit-
    #     hook layer per ADR-020. Public event schema; MUST remain
    #     backward-compatible across versions. Per ADR-020 stop rule
    #     on the AGENTS.md critical-controls list.
    ("src/cognic_agentos/protocol/a2a_authz.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_agent_cards.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_endpoint.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_schema.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_version.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_errors.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/ui_events.py", 0.95, 0.90),
    # Sprint 7A T16 — authoring SDK + CLI nonet. Build-time half of
    # the trust gate; mirrors the runtime trust gate's protocol/*
    # modules above. See module docstring for per-module rationale.
    # T8 (a2a.py) promotion call deferred at landing → resolved at
    # T16 closeout: validator owns refusal paths the runtime reader
    # does not (runtime filters silently, validator refuses), so it
    # qualifies as policy under Doctrine Decision G's "non-trivial
    # allow/deny logic" rule and joins the gate.
    # Off-gate per the pure-delegation rule: cli/validators/mcp.py
    # (narrow caching/elicitation refusals) + cli/validators/risk_tier.py
    # (closed-enum + vocabulary delegation).
    ("src/cognic_agentos/cli/validate.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/validators/identity.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/validators/a2a.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/validators/data_governance.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/validators/supply_chain.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/sign.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/verify.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/_load_probe.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/_wheel_integrity.py", 0.95, 0.90),
    # Sprint 7A2 T12 — hook-pack runtime + author quartet. ADR-017
    # 4th-pack-kind enforcement path; see module docstring for per-
    # module rationale + the T12 reconcile decision that lifted
    # dlp_integration.py from off-list to on-gate. All four ride the
    # same single strict 95% line / 90% branch floor.
    ("src/cognic_agentos/packs/hooks/registry.py", 0.95, 0.90),
    ("src/cognic_agentos/packs/hooks/dispatcher.py", 0.95, 0.90),
    ("src/cognic_agentos/packs/hooks/dlp_integration.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/validators/hooks.py", 0.95, 0.90),
    # Sprint 7B.1 T7 — Bank pack lifecycle (state machine + storage)
    # pair. Both modules form the ADR-012 lifecycle-state-machine +
    # storage critical path; see module docstring above for per-module
    # rationale. ``packs/lifecycle.py`` is the pure-functional state
    # machine (closed-enum ``LifecycleRefusalReason`` +
    # ``_VALID_TRANSITIONS`` table + ``validate_transition`` pure
    # validator + ``iso_controls_for`` ISO 42001 control mapping).
    # ``packs/storage.py`` is the row-locked ``append_with_precondition``
    # consumer (atomic chain-insert + state-cache UPDATE + chain-head
    # UPDATE in a single transaction). Off-gate per Doctrine F
    # gate-counting rule: the Alembic migration version file
    # (``src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py``)
    # — doctrine-critical DDL but not coverage-tracked by convention.
    # Both ride the same single strict 95% line / 90% branch floor.
    ("src/cognic_agentos/packs/lifecycle.py", 0.95, 0.90),
    ("src/cognic_agentos/packs/storage.py", 0.95, 0.90),
    # Sprint 7B.2 T6 — operator-surface route module. The 5 ADR-012
    # §68-73 operator endpoints (allow-list + install + disable +
    # revoke + uninstall) live here; the allow-list endpoint is the
    # single user-authorized site for the AGENTS.md "Human-only
    # decisions / Per-tenant allow-list changes" doctrine enforcement
    # (RequireHumanActor sub-dependency). Owns the watchpoint (d)
    # examiner-traceability surface for the allow-list audit row via
    # the R24 Path B + B2 actor_type carry-forward through every
    # transition() call. R27-hardened mutually-exclusive race
    # contract: every verb's PackNotFound race path emits EXACTLY
    # ONE ``portal.packs.<verb>_refused`` log with reason +
    # actor_subject + pack_id + from_state (caplog asserted;
    # threat-model-revert verified load-bearing at slices 2 + 3 + 4).
    # Standing-offer §30 module-header invariant pinned by AST self-
    # test + per-verb invocation tests per
    # ``feedback_security_regression_hardening.md``. Rides the same
    # single strict 95% line / 90% branch floor.
    ("src/cognic_agentos/portal/api/packs/operator_routes.py", 0.95, 0.90),
    # Sprint 7B.2 T8 — OWASP conformance check matrix pair (ADR-012
    # §119 + BUILD_PLAN §628). Both modules form the wire-protocol-
    # public reviewer-evidence surface that T9 attaches to the chain
    # payload's ``payload.conformance`` and 7B.3 reviewers consume:
    #   * ``packs/conformance/checks.py`` owns the closed-enum 10-
    #     value ``OWASPCheckCategory`` Literal + the 3-value
    #     ``ConformanceCheckStatus`` + ``ConformanceOverallStatus``
    #     Literals + the frozen ``ConformanceCheckResult`` +
    #     ``ConformanceReport(overall_status, results, summary,
    #     errored_categories)`` dataclasses. Field order is wire-
    #     protocol-public per ADR-006 — drift breaks evidence-pack
    #     export readers.
    #   * ``packs/conformance/owasp_agentic.py`` owns the 10
    #     deterministic manifest-shape check bodies, the
    #     ``_APPLICABILITY`` matrix (per-pack-kind 10x4 declarative
    #     gate), the ``_CHECK_REGISTRY`` ordered tuple (1:1 with the
    #     Literal), and the ``run_owasp_conformance`` dispatcher
    #     (applicability gate + exception-wrapping + yellow-precedence
    #     overall-status derivation + ``(N errored)`` summary suffix).
    #     Yellow takes precedence over red because a checker exception
    #     means the suite is incomplete and the red/green verdict is
    #     not trustworthy. The ``__init__.py`` re-exports only; off-
    #     gate per Doctrine F.
    # Both ride the same single strict 95% line / 90% branch floor.
    ("src/cognic_agentos/packs/conformance/checks.py", 0.95, 0.90),
    ("src/cognic_agentos/packs/conformance/owasp_agentic.py", 0.95, 0.90),
    # Sprint 7B.2 T9 Slice 4 — chain-payload serialization adapter
    # (plan §1062-1252).  Thin wire-shape boundary between the T8
    # check matrix + the T9 chain row's ``payload["conformance"]``.
    # Owns the load-bearing ``errored_categories`` tuple → list
    # conversion + the 4-key wire-shape contract — NOT pure re-
    # export glue.  Pinned by ``test_runner.py``'s 9-test suite.
    ("src/cognic_agentos/packs/conformance/runner.py", 0.95, 0.90),
    # Sprint 7B.2 T12 doctrine — Portal RBAC modules (6) + portal
    # pack API author/review route modules (2). The plan-of-record at
    # §1298 claimed a 12-module floor uplift; 4 of the 12 were
    # promoted incrementally during T6 (operator_routes), T8 (checks
    # + owasp_agentic), and T9 (runner) as each landed its own
    # halt-before-commit critical-controls review. T12 promotes the
    # remaining 8. Gate count goes 47 → 55. Plan §1304-1310 lists
    # all 12; the 4 already-promoted entries above carry the same
    # rationale + ride the same single strict 95% line / 90% branch
    # floor. The 8 T12 promotions are:
    #
    #   * RBAC primitives (6):
    #     - ``portal/rbac/scopes.py`` — closed-enum 13-value
    #       ``PackRBACScope`` Literal IS the wire-protocol contract
    #       for every 403 RBAC denial in the portal pack API; the
    #       5-group frozenset partition (4 role groups +
    #       ``OVERRIDE_SCOPES``) pins which groups perform which
    #       lifecycle actions. Sprint 7B.3 T8 added the 13th value,
    #       the ADR-012 §107-110 override scope.
    #     - ``portal/rbac/actor.py`` — frozen ``Actor`` Pydantic
    #       model + closed-enum 2-value ``ActorType`` Literal +
    #       production-grade fail-loud default. The identity
    #       boundary at the portal admission seam.
    #     - ``portal/rbac/enforcement.py`` — ``RequireScope``
    #       dependency factory + closed-enum 3-value
    #       ``RBACDenialReason``. The 403 wire-protocol surface.
    #     - ``portal/rbac/tenant_isolation.py`` — closed-enum
    #       4-value ``TenantIsolationFailure`` (Round 1 P2 #3
    #       seeded 3 values; T2 R1 P2 #1 added
    #       ``pack_store_not_configured``). Cross-tenant 404
    #       doctrine — a pack belonging to tenant A is INVISIBLE
    #       to tenant B; 404 (NOT 403) so a probe cannot enumerate
    #       cross-tenant pack-IDs.
    #     - ``portal/rbac/human_actor.py`` — ``RequireHumanActor``
    #       dependency + closed-enum 1-value
    #       ``HumanActorDenialReason("actor_type_must_be_human")``.
    #       The single user-authorized site for the AGENTS.md
    #       "Per-tenant allow-list changes" Human-only-decisions
    #       doctrine — wired as a sub-dependency on the allow-list
    #       endpoint at ``operator_routes.py`` BEFORE the handler
    #       body runs.
    #     - ``portal/rbac/role_separation.py`` —
    #       ``RequireDifferentActorThanCreator`` factory +
    #       closed-enum 1-value ``RoleSeparationFailure``. ADR-012
    #       §17 cross-role separation: the actor who created a
    #       pack MUST NOT also review it.
    #   * Portal pack API route modules (2):
    #     - ``portal/api/packs/author_routes.py`` — wire-protocol-
    #       public author surface. The T9 Slice 2 extension adds
    #       a route-owned 4-way refusal union via the
    #       ``AuthorRequestRefusalReason = Literal["manifest_digest_mismatch"]``
    #       closed-enum (distinct from ``AuthorRefusalReason``
    #       409s + ``TenantIsolationFailure`` 404/500s +
    #       ``RBACDenialReason`` 403/500s) + auto-runs OWASP
    #       conformance + threads ``expected_manifest_digest`` to
    #       close the TOCTOU window.
    #     - ``portal/api/packs/review_routes.py`` — wire-protocol-
    #       public review surface (5 endpoints: claim / approve /
    #       reject / approve fail-loud per P2 #1 + 4-axis matrix
    #       per Round 11 P3 #6 / evidence read / queue list). T9
    #       Slice 3 extension threads ``evidence_attachments`` into
    #       the chain row's ``payload["evidence_attachments"]`` for
    #       the dual-surface emission contract (structured log +
    #       chain payload).
    #
    # NOT on this T12 promotion set:
    #   * ``portal/api/packs/inspection_routes.py`` (T7) — pure-read
    #     inspection endpoints. R32 doctrine kept it OFF the durable
    #     gate because it owns neither the Human-only-decisions
    #     enforcement boundary nor the R24 actor_type chain-payload
    #     provenance surface; the CC risk for its tenant-isolation
    #     boundary is covered by ``packs/storage.py``'s
    #     ``list_for_tenant`` already being on the gate from T7
    #     Slice 1.
    #   * ``portal/api/packs/router.py`` (T3) — sub-router
    #     scaffolding. Carrier file with no decision logic.
    #   * ``cli/conformance.py`` (T10) + ``cli/test_harness.py``
    #     (T11 extension) — authoring/dev-only public CLI commands
    #     per Sprint-7A T13 R4 P3 #5 doctrine; off-floor because
    #     every gate they surface is enforced upstream by the
    #     on-floor matrix at ``packs/conformance/owasp_agentic.py``.
    #
    # All 8 ride the same single strict 95% line / 90% branch floor.
    ("src/cognic_agentos/portal/rbac/scopes.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/rbac/actor.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/rbac/enforcement.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/rbac/tenant_isolation.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/rbac/human_actor.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/rbac/role_separation.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/packs/author_routes.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/packs/review_routes.py", 0.95, 0.90),
    # Sprint 7B.3 T3 — pack data-governance evidence panel.
    # AGENTS.md L54 + L167 explicit stop rule: "Pack data-governance
    # contracts (``packs/evidence/data_governance.py``, runtime DLP
    # enforcement)". The module owns the wire-protocol-public 7-value
    # ``DataGovernanceDiffFlag`` closed-enum vocabulary + the pure-
    # functional projector that the 5-gate composer (T7) reads in
    # addition to the route handler — drift in the vocab OR the
    # projector field-set is wire-protocol-public regression.
    #
    # NOT on this T3 promotion set:
    #   * ``portal/api/packs/evidence_routes.py`` (T3) — route module
    #     orchestrating the projector. Mirrors the T7 inspection_routes
    #     decision (R32 doctrine): route module that doesn't own a
    #     Human-only-decisions enforcement boundary or actor_type
    #     chain-payload provenance surface stays OFF the durable gate;
    #     CC risk covered by the projector being on the gate + the
    #     route-owned ``EvidencePanelRefusalReason`` 3-value vocab
    #     pinned by the disjointness drift detectors in
    #     ``test_evidence_routes_structure.py``.
    ("src/cognic_agentos/packs/evidence/data_governance.py", 0.95, 0.90),
    # Sprint 7B.3 T4 — risk-tier evidence panel.
    # ADR-014 §24-37 — risk-tier vocabulary IS the runtime tool-
    # approval contract. The module owns the wire-protocol-public
    # 7-value ``ApprovalFlowKind`` closed-enum + the 1:1
    # ``_RISK_TIER_TO_APPROVAL_FLOW`` mapping table that the 5-gate
    # composer (T7) consumes alongside the panel route handler.
    # Drift in the Literal OR the mapping table is wire-protocol-
    # public regression. Mirrors the T3 data-governance projector
    # promotion (wire-protocol-public vocab + cross-layer consumer).
    #
    # Same R32 carry-over as T3: ``portal/api/packs/evidence_routes.py``
    # stays OFF the durable gate — the T4 risk-tier handler does not
    # own a Human-only-decisions enforcement boundary or actor_type
    # chain-payload provenance surface; CC risk covered by the
    # projector being on the gate + the existing T3 disjointness
    # drift detectors covering the shared ``EvidencePanelRefusalReason``
    # vocab in ``test_evidence_routes_structure.py``.
    ("src/cognic_agentos/packs/evidence/risk_tier.py", 0.95, 0.90),
    # Sprint 7B.3 T5 — supply-chain evidence panel.
    # ADR-016 §23-33 (attestation kinds) + §70-72 (7-year sigstore-
    # bundle retention) — the module owns the wire-protocol-public
    # 7-value ``AttestationKind`` closed-enum that the 5-gate composer
    # (T7) consumes for Gate 1 (signature) evidence lookup alongside
    # the panel route handler. The projector ALSO encodes the truth
    # table for retention-floor computation per the regulator
    # boundary; drift in EITHER the Literal OR the retention math is
    # wire-protocol-public regression.
    #
    # Same R32 carry-over as T3 + T4: ``portal/api/packs/evidence_routes.py``
    # stays OFF the durable gate — the T5 supply-chain handler does
    # not own a Human-only-decisions enforcement boundary or
    # actor_type chain-payload provenance surface; CC risk covered by
    # the projector being on the gate + the existing T3/T4 disjointness
    # drift detectors covering the shared ``EvidencePanelRefusalReason``
    # vocab in ``test_evidence_routes_structure.py``. The companion
    # storage seam ``PackRecordStore.load_latest_submit_created_at``
    # ships on ``packs/storage.py`` which is ALREADY on the durable
    # gate; no separate gate-bump for the new method.
    ("src/cognic_agentos/packs/evidence/supply_chain.py", 0.95, 0.90),
    # Sprint 7B.3 T6 — conformance-matrix evidence panel.
    # ADR-002 (MCP capability conformance) + ADR-003 (A2A feature
    # conformance) + the AGNTCY/OASF Wave-2 identity posture — the
    # module owns the wire-protocol-public 6-value ``MatrixComparisonFlag``
    # closed-enum that reviewers see in ``flagged_mismatches`` AND the
    # R9 kind-applicability matrix (which protocol matrices apply to
    # tool / skill / agent / hook packs). The projector ALSO defensively
    # reconstructs the persisted ``payload["conformance"]`` OWASP verdict
    # into the panel-local ``OwaspVerdictData`` shape; drift in EITHER
    # the Literal OR the kind-applicability sets OR the verdict-
    # reconstruction shape is wire-protocol-public regression.
    #
    # Same R32 carry-over as T3 + T4 + T5: ``portal/api/packs/evidence_routes.py``
    # stays OFF the durable gate — the T6 conformance handler does not
    # own a Human-only-decisions enforcement boundary or an actor_type
    # chain-payload provenance surface; CC risk is covered by the
    # projector being on the gate + the shared ``EvidencePanelRefusalReason``
    # disjointness drift detectors in ``test_evidence_routes_structure.py``.
    # The static-shipped ``conformance_matrix.json`` is generated by the
    # off-floor ``tools/generate_conformance_matrix_json.py`` build-time
    # script (tools/ scripts are not coverage-tracked per Doctrine F);
    # the JSON shape is pinned against the source Markdown by the
    # build-time drift detector at
    # ``tests/unit/tools/test_generate_conformance_matrix_json.py``.
    ("src/cognic_agentos/packs/evidence/conformance_matrix.py", 0.95, 0.90),
    # Sprint 7B.3 T7 — ADR-012 §41 five-gate approval composer.
    # ``packs/approval_gates.py`` is the substantive enforcement boundary
    # for the ``under_review → approved`` lifecycle transition: the
    # pure-functional ``compose_approval_gates`` decides whether a
    # plugin pack clears the 5 orthogonal gates (signature / evaluation
    # / adversarial / owasp_conformance / reviewer_acknowledgement). The
    # module owns 10 wire-protocol-public closed-enum Literals — the T7
    # composer's 9 (5 per-gate red-reason vocabularies + the consolidated
    # 22-value ``ApprovalGateRedReason`` union + ``ApprovalGateName`` +
    # ``ApprovalGateOutcome`` + the binary ``SignatureGateOutcome`` which
    # makes the illegal ``evidence_not_attached`` signature state
    # unrepresentable per ADR-012 §110) plus the T8 override path's
    # ``OverrideRefusalReason`` (4-value — the 412 refusal body's
    # override-path branch) — that render into the 412
    # ``ApproveRefusalResponse`` body, the ``_NON_OVERRIDABLE_GATES``
    # ADR-012 §110 policy constant (cosign signature is the single
    # non-overridable gate), the gate-5 derivation logic (the one gate
    # the composer itself decides), and the T8 override seam
    # (``evaluate_override_decision`` + the canonical-safe
    # ``composition_snapshot`` serialiser). Drift in any Literal, the
    # policy set, the derivation, or the override helper is wire-
    # protocol-public / governance-doctrine regression. On the durable
    # gate per the Sprint-7B.3 per-task precedent (T3-T6 each added their
    # own CC module); promoted here at T7 rather than deferred to T11.
    # Pure-functional (no I/O); the route handler at
    # ``portal/api/packs/review_routes.py`` (T9) owns the wiring +
    # pre-computes gates 1-4.
    ("src/cognic_agentos/packs/approval_gates.py", 0.95, 0.90),
    # cosign 3.x legacy-compat bridge (Task 3) — ``_signature_path_resolver``
    # gains the approval-gate ``bundle.sigstore`` projection (basename match
    # from ``[supply_chain].attestation_paths``, custom-dir-safe) feeding the
    # 5-gate signature gate's new required ``--bundle`` argument. The
    # resolver is a supply-chain trust-input projector: a bug here lets a
    # missing/unresolved bundle reach the runtime trust gate. Every
    # bundle-path failure maps to the EXISTING ``signature_bundle_path_
    # unreachable`` — no new ``SignatureRedReason`` value. Promoted to the
    # durable gate here per the tightening-edit-B discipline.
    ("src/cognic_agentos/packs/_signature_path_resolver.py", 0.95, 0.90),
    # ------------------------------------------------------------------
    # Sprint 7B.4 T13 — UI event-stream durable critical-controls
    # modules (gate 60 → 63).
    # ------------------------------------------------------------------
    # ``portal/api/ui/action_routes.py`` (T11) — wire-protocol-public
    # POST /api/v1/ui/actions surface.  ``RequireUIAction(broker)``
    # closure-factory dep parses body via Annotated[ActionRequest,
    # Body(...)] discriminated union + binds actor via
    # Depends(_bind_actor) + maps body.action_class →
    # ``ui.action.<class>`` required scope + emits
    # ``policy.rbac_denied`` via the shared ``_emit_denial_or_500``
    # helper (fail-closed 500 ``rbac_denial_emit_failed`` on broker
    # exception).  ``_STUB_REASONS`` 5-class deferred-stub map is
    # wire-protocol-public (the 3 ``action_backend_deferred_*``
    # closed-enum reasons land on every stub-path response body +
    # the rejected chain row's payload).  submit_elicitation path
    # routes through ``evaluate_elicitation_submission`` (T8 gate);
    # green path calls ``adapter.handle_submission``; backend
    # exception translates to ``elicitation_backend_failed``
    # (distinct from gate refusals so examiners can tell "backend
    # rejected" apart from "gate refused" without re-running the
    # gate).  Deterministic ``submitted_event_id`` +
    # ``resolution_event_id`` cursors via the broker's
    # ``_chain_derived_event_id`` projection — pinned by
    # ``test_action_routes.py
    # ::TestActionResponseEventIdCursorsMatchSSE``.  T7 forward
    # watchpoint honored: no isinstance check against the
    # ``@runtime_checkable`` ``ElicitationAdapter`` Protocol;
    # duck-typed at the call site.
    ("src/cognic_agentos/portal/api/ui/action_routes.py", 0.95, 0.90),
    # ``portal/api/ui/stream_routes.py`` (T10) — reconnect-safe SSE
    # transport.  3 SSE GET endpoints (``/runs/{run_id}/events``,
    # ``/tenants/{tenant_id}/events``, ``/events/since/{event_id}``)
    # gated by ``ui.run_stream`` / ``ui.tenant_stream`` RBAC.  Closure-
    # captures broker + settings + decision_history_store at
    # ``build_stream_routes`` call time (T10 plan-vs-reality drift
    # #1 resolution — ``create_app`` populates
    # ``app.state.decision_history_store`` but NOT
    # ``app.state.settings``).  Owns the 4-value ``CursorRefusalReason``
    # Literal (``cursor_malformed`` / ``cursor_chain_unsupported``
    # / ``cursor_not_found`` / ``cursor_projection_drift_detected``);
    # ``cursor_tenant_mismatch`` deliberately NOT in the enum per
    # the cross-tenant-invisible doctrine (cross-tenant cursors
    # emit ``pack_not_found`` so a probe cannot enumerate tenant
    # boundaries by response shape).  Type_hash drift detection in
    # ``_validate_cursor_tenant`` runs PRE-STREAM (NOT in the
    # generator) so the 500 actually reaches the client — raising
    # HTTPException after http.response.start would leave the
    # client with a broken stream.  Last-Event-ID header WINS over
    # URL cursor; malformed header fails closed with 422
    # ``cursor_malformed`` (no silent fall-back) — TM-revert pinned.
    # Boundary-row dedup + heartbeat cadence + send_timeout half-
    # open cleanup are all wire-protocol-public properties pinned
    # by the T10 test suite.
    ("src/cognic_agentos/portal/api/ui/stream_routes.py", 0.95, 0.90),
    # ``portal/api/ui/elicitation_gate.py`` (T8) — substantive
    # policy boundary for the submit_elicitation surface.  Pure-async
    # ``evaluate_elicitation_submission(*, request, actor, adapter,
    # rego_engine) -> GateOutcome``; 5-step refusal contract
    # mapped to a 10-value ``ActionRejectionReason`` Literal (6
    # gate-emitted + 4 handler-emitted reasons; lockstep with
    # ``portal/api/ui/dto.py``'s parallel Literal via the test-only
    # drift detector at
    # ``tests/unit/portal/api/ui/test_dto_action.py
    # ::TestActionRejectionReasonCrossModuleEquality``).  Step 1
    # adapter-wired check + Step 2 ctx resolution + Step 3 mode
    # parity (BOTH directions) + Step 4 form-mode + restricted-data-
    # class refusal (``_RESTRICTED_DATA_CLASSES`` = 3-value frozenset
    # mirroring ``protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES``
    # via test-only three-way lockstep — NO runtime cross-module
    # import per the user-locked drift-detector doctrine) + Step 5
    # Rego eval at ``data.cognic.ui.elicitation_submit.allow`` with
    # fail-closed mapping for OPA-unavailable / bundle-error /
    # decision-false.  The route handler at ``action_routes.py``
    # owns the HTTP mapping; the gate stays pure-functional.
    ("src/cognic_agentos/portal/api/ui/elicitation_gate.py", 0.95, 0.90),
    # ------------------------------------------------------------------
    # Sprint 8A T12 — Sandbox primitive durable critical-controls
    # modules (gate 63 → 70).
    # ------------------------------------------------------------------
    # Per the Sprint-8A design spec §17 "Critical-controls scope"
    # (``docs/superpowers/specs/2026-05-16-sprint-8a-sandbox-primitive-design.md``)
    # the entire ``sandbox/`` tree is a stop-rule isolation boundary;
    # the 7 modules promoted here are the substantive enforcement
    # surfaces of the sandbox admission + lifecycle + egress + warm-pool
    # critical path. All ride the same single strict 95% line / 90%
    # branch floor as Sprint-2/2.5/3/4/5/6/7A/7A2/7B.1-4 modules.
    #
    # Floor arithmetic: Sprint 8A lands BEFORE Sprint 10.5 in BUILD_PLAN
    # phase order (Phase 3 sequence: 8 → 8.5 → 9 → 9.5 → 10 → 10.5 → 11).
    # Post-7B.4 floor is 63; Sprint 8A adds 7 modules → 70. When
    # Sprint 10.5 subsequently lands its scheduler modules the floor
    # extends further.
    #
    #   * ``sandbox/protocol.py`` — ``SandboxBackend`` + ``SandboxSession``
    #     Protocols + ``PackAdmissionContext`` + ``SandboxPolicy`` +
    #     ``SandboxBackendHealth`` + ``SandboxRefusalReason``
    #     (wire-protocol-public closed-enum) + ``SandboxPolicyViolationReason``
    #     (wire-protocol-public closed-enum, 6-value at T10c R1 P1.2) +
    #     ``SandboxLifecycleEvent`` (8-value event family discriminator
    #     per ADR-006 amendment). Backend-conformance contract: every
    #     backend (DockerSibling Wave-1, KubernetesPod Sprint 8B, gVisor/
    #     Firecracker Wave-2) MUST structurally conform. Drift in any
    #     Protocol method or closed-enum is wire-protocol-public
    #     regression that breaks every downstream backend + caller.
    #   * ``sandbox/policy.py`` — ``SandboxPolicy`` frozen dataclass
    #     (``@dataclass(frozen=True)`` at ``policy.py:133`` — NOT a
    #     Pydantic model) + pure synchronous ``validate_policy_shape()``
    #     (Stage-1 admission glue); ``_validate_egress_host`` RFC 1123
    #     hostname + HTTP/HTTPS scheme guard feeding
    #     ``sandbox_policy_egress_host_invalid`` (``policy.py:277,282``)
    #     + ``sandbox_policy_egress_protocol_not_http``
    #     (``policy.py:267``) refusals — both values live on the wire-
    #     public ``SandboxRefusalReason`` Literal at
    #     ``protocol.py:45-46``. Stage-1 is the cheap shape gate that
    #     runs BEFORE async Stage-2 admission; a bug here lets malformed
    #     policies reach the catalog + cosign + Rego layers.
    #   * ``sandbox/admission.py`` — async ``admit_policy()``; Stage-2
    #     admission pipeline (catalog + cosign + SBOM + Rego + credential
    #     adapter + high-risk-tier gate). The substantive trust-gate-
    #     equivalent decision point shared across all backends. Declares
    #     the ``CatalogProtocol`` + ``CredentialAdapter`` Protocols
    #     inline per the ``feedback_consumer_owned_protocol_for_unlanded_dep``
    #     resolution; ``KernelDefaultCredentialAdapter`` sentinel raises
    #     ``NotImplementedError`` pointing at Sprint 10 per the
    #     production-grade rule. Step 6 captures the catalog membership
    #     bools (canonical-set + tenant-allow-list) as locals BEFORE
    #     Step 9 threads them into the Rego input dict; pinned by 2 T11
    #     regression tests so a future refactor can't disconnect the
    #     Stage-2 catalog check from the Rego rule-4 decision point.
    #   * ``sandbox/catalog.py`` — ``CanonicalImageCatalog`` + cosign
    #     subprocess verification + real syft SBOM verification + per-
    #     tenant allow-list. Spec round-1 P1 promotion — a bug here
    #     lets untrusted images run; not "thin wiring". Mirrors the
    #     ``protocol/trust_gate.py`` cosign subprocess invariants
    #     (no shell, list-form argv, version-pinned, timeout, output
    #     ignored for parsing).
    #   * ``sandbox/proxy.py`` — egress proxy config rendering + allow-
    #     list enforcement + per-request audit-log shaping. Spec round-1
    #     P1 promotion — the single egress enforcement point; a bug
    #     here lets forbidden outbound traffic through; not "thin
    #     wiring". Owns the wire-protocol-public ``ProxyAccessRecord``
    #     6-field frozen dataclass at ``protocol.py:140-188``
    #     (``host`` / ``method`` / ``timestamp`` / ``policy_id`` /
    #     ``outcome`` / ``refusal_reason``) materialised via
    #     ``proxy_log_to_chain_payload`` at ``proxy.py:238`` into
    #     ``payload["proxy_log"]`` on ``sandbox.lifecycle.exec_completed``
    #     (``audit.py:53``) AND on ``sandbox.policy.violated``
    #     (``audit.py:56``) per the T10c R2 ADR-006 amendment.
    #     Evidence-boundary helpers validate runtime semantics per
    #     ``feedback_evidence_boundary_runtime_validation`` (T7 R1-R5
    #     fixes: tz-aware audit timestamps via ``utcoffset() is not
    #     None`` at ``proxy.py:320``; joint invariants across closed-
    #     enum + payload key set — ``outcome='allowed'`` requires no
    #     ``refusal_reason`` + ``outcome='refused'`` requires one; per
    #     ``proxy.py:342-357``; unknown-Literal refusals;
    #     ``# type: ignore`` smuggling guard).
    #   * ``sandbox/warm_pool.py`` — bounded pool + drain semantics +
    #     audit emission + ``use_warm_pool=False`` replenishment
    #     contract. The latency-target enforcement surface (≤500ms P95
    #     sandbox session create per spec §16 exit criterion). Pool-key
    #     derivation at ``_derive_pool_key`` (``warm_pool.py:164``) keys
    #     by ``tenant_id + policy + 5 PackAdmissionContext admission
    #     fields`` — ``tenant_id`` is part of the key per the T9 R1
    #     P1 reviewer fix (``warm_pool.py:174``) which closed the
    #     cross-tenant pool-reuse bug class (admission contexts from
    #     different tenants that happen to look identical MUST NOT
    #     share a warm session); pinned by
    #     ``tests/unit/sandbox/test_warm_pool.py::
    #     test_checkout_under_different_tenant_id_returns_none``
    #     (``test_warm_pool.py:641``).
    #     Capacity-before-eviction + wall-time-vs-idle-time + list/
    #     tuple ambiguity at ``canonical_bytes`` input — all three
    #     closed by T9 R1-R3 fixes per
    #     ``feedback_evidence_boundary_runtime_validation``.
    #   * ``sandbox/backends/docker_sibling.py`` —
    #     ``DockerSiblingSandboxBackend``. The actual Wave-1 backend-
    #     specific enforcement surface: dual-container internal-network
    #     topology (runtime container + egress-proxy sidecar, both on
    #     a sandbox-private bridge with ``--network none`` on the
    #     runtime side per ``feedback_sandbox_network_isolation_precision``);
    #     cgroup integration for CPU/memory caps; OOM-killer enforcement
    #     for ``memory_cap_exceeded``; AgentOS-side walltime timer for
    #     ``walltime_cap_exceeded``. The ``Wave-1 DinD`` doctrinal-
    #     vs-implementation gap per ``feedback_precise_security_terminology``
    #     resolved at T10a: backend name is ``DockerSiblingSandboxBackend``
    #     (not ``DindBackend``); ADR-004 amendment ships the clarifying
    #     "Wave-1 DinD = sibling-pattern" language alongside Sprint 8A.
    #     Architecture-discipline test (URL-literal / port-int guards
    #     at ``tests/unit/architecture/``) catches f-string URL drift —
    #     concrete loss case at T10c per
    #     ``feedback_full_gate_pre_commit``.
    #
    # OFF the durable gate per spec §17 + Doctrine F (with explicit
    # carve-out rationale; same precedent as ``packs/conformance/__init__.py``
    # + ``portal/api/packs/router.py``):
    #
    #   * ``sandbox/audit.py`` — thin chain-row converter for the
    #     8 sandbox lifecycle event taxonomies. The substantive
    #     audit-chain invariants (hash-chain integrity, canonical-form
    #     determinism, ISO 42001 control tagging) are enforced upstream
    #     by the on-gate ``core/audit.py`` + ``core/decision_history.py``
    #     + ``core/canonical.py``. Bugs in audit.py's event-payload-
    #     rendering surface through the 8-event taxonomy unit test +
    #     the integration tests of ``backends/docker_sibling.py``. CC
    #     risk covered upstream; promoting here would measure runtime-
    #     import + delegation lines only.
    #
    # NOTE — ``sandbox/credentials.py`` was an off-gate Sprint 8A
    # carve-out (re-export shim covering the canonical home at
    # ``sandbox/admission.py``) but moved ON the gate at Sprint 10 Z1
    # alongside the real ``VaultCredentialAdapter`` implementation,
    # executing the long-standing "Sprint 10's real adapter goes ON
    # the gate when it lands" promise. The Z1 promotion entry lives
    # below in the Sprint 10 Z1 section; the matching test-suite pin
    # is ``test_sprint_10_modules_present_with_standard_floors`` +
    # the removal from ``_SPRINT_8A_OFF_GATE_MODULES`` at
    # ``tests/unit/tools/test_check_critical_coverage.py``.
    ("src/cognic_agentos/sandbox/protocol.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/policy.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/admission.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/catalog.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/proxy.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/warm_pool.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/backends/docker_sibling.py", 0.95, 0.90),
    #
    # Sprint 8B T8B-d — Sandbox primitive (Wave-1 K8s/OpenShift backend)
    # gate promotion (+1 module → 71 total). Lands the second Wave-1
    # SandboxBackend per ADR-004 amendment + project_openshift_deployment_target.
    # Same 95%/90% floor as the Sprint 8A backends; promoted at T8B-d
    # via the user-locked tightening edit B from Sprint 8B preflight
    # (2026-05-17): `tools/check_critical_coverage.py` against fresh
    # coverage.json runs IN THE SAME COMMIT as this `_CRITICAL_FILES`
    # extension — NOT just the `_EXPECTED_ENTRY_COUNT` bump in the
    # count-guard self-test. Per
    # `feedback_verify_promotion_meets_floor_at_promotion_time`
    # (born from the Sprint 8A T12 verification gap where the gate
    # was promoted having only verified the count-guard, NOT the
    # actual floor — and post-T13 the gate found 2/7 promoted modules
    # below threshold). The count guard pins gate METADATA; the gate
    # tool itself pins actual coverage. Orthogonal axes; T8B-d
    # commits BOTH.
    #
    # ON the durable gate (+1):
    #
    #   * ``sandbox/backends/kubernetes_pod.py`` —
    #     ``KubernetesPodSandboxBackend``. The Wave-1 K8s/OpenShift
    #     bank-production backend. Conforms to the same SandboxBackend
    #     Protocol (``protocol.py:254``) as DockerSibling; reuses the
    #     backend-agnostic 9-step ``admit_policy`` Stage-2 pipeline +
    #     canonical image catalog + 8-event audit taxonomy + sandbox.rego
    #     bundle. K8s-specific surface: per-Pod NetworkPolicy (deny-all
    #     egress except proxy sidecar via shared Pod localhost per
    #     ``feedback_sandbox_network_isolation_precision``); OpenShift-
    #     compatible pod SecurityContext (no ``--privileged``; omits
    #     ``runAsUser`` for namespace-allocated MustRunAsRange compat;
    #     capabilities.drop=[ALL]; readOnlyRootFilesystem); cgroup-via-
    #     exec cpu-budget monitor (NOT metrics-server; chosen at T8B-c
    #     Step 1 verification for sub-second granularity + no cluster
    #     prereq); OOMKilled detection via
    #     ``ContainerStatus.last_state.terminated.reason == "OOMKilled"``
    #     (kubelet-authoritative; not exit 137 alone). Proxy-log fail-
    #     closed contract preserved (T10c R1 P1.2 wire-protocol-public
    #     per ``SandboxPolicyViolationReason.egress_audit_unreadable``).
    #     The cross-backend drift detector at
    #     ``tests/unit/sandbox/backends/test_exec_classification_cross_backend_drift.py``
    #     pins behavioural lockstep with docker_sibling's
    #     ``_classify_exec_failure`` without coupling production code
    #     per ``feedback_drift_detector_test_only_no_runtime_import``.
    #     User-found P1 at orchestrator's trust-but-verify gate (T8B-c
    #     commit ``7943491``): ``backend_factory.get_backend`` documented
    #     ``kwargs["settings"] = settings`` injection but did not deliver
    #     until the post-subagent P1 fix landed — refines the
    #     trust-but-verify doctrine ("test fixture papers over production
    #     gap" is a distinct subagent failure mode beyond the
    #     "re-gate-ladder after auto-fix" one).
    #
    # OFF the durable gate per Doctrine F (with explicit carve-out
    # rationale; same precedent as Sprint 8A's ``sandbox/audit.py``;
    # the Sprint-8A ``sandbox/credentials.py`` carve-out was promoted
    # at Sprint 10 Z1 alongside the real ``VaultCredentialAdapter``,
    # so it no longer applies as an off-gate precedent):
    #
    #   * ``sandbox/backend_factory.py`` — pure selection seam (130 LoC).
    #     The wire-protocol-public contract IS the
    #     ``Settings.sandbox_backend`` Literal arm set + the
    #     ``COGNIC_SANDBOX_BACKEND`` env-var override per ADR-004 §32.
    #     Drift between the Literal arms + the factory's accepted set
    #     is pinned by
    #     ``tests/unit/sandbox/test_backend_factory.py::TestBackendFactoryEnumerateCoverage``;
    #     the settings-injection contract is pinned by
    #     ``TestBackendFactoryRoutesByLiteral`` (3 tests post-P1-fix,
    #     TM-revert verified). The substantive enforcement lives in
    #     the chosen backend's own ``create()`` / ``exec()`` /
    #     ``destroy()`` / ``health()`` methods (both backends ON the
    #     gate). Promoting the factory would measure routing-glue
    #     coverage where the test surface already drift-detects the
    #     wire contract; off-gate per the same Sprint-7A T17 R4 P3 #5
    #     doctrine that kept ``cli/conformance.py`` off-gate when the
    #     dispatched matrix is already CC.
    #   * ``sandbox/backends/_shared_exec.py`` — pure-functional helper
    #     (101 LoC: ``_classify_exec_failure`` + ``_ProxyLogReadFailure``).
    #     Consumer-owned by ``kubernetes_pod`` per
    #     ``feedback_consumer_owned_protocol_for_unlanded_dep``;
    #     docker_sibling keeps its inline copies UNCHANGED per the
    #     sandbox isolation-boundary stop-rule. Behavioural lockstep
    #     across both backends pinned by the test-only drift detector
    #     at ``test_exec_classification_cross_backend_drift.py``. CC
    #     risk covered by the on-gate ``kubernetes_pod.py`` consumer
    #     surface + the on-gate ``docker_sibling.py`` consumer
    #     surface; promoting here would double-count the same enforcement.
    ("src/cognic_agentos/sandbox/backends/kubernetes_pod.py", 0.95, 0.90),
    #
    # ------------------------------------------------------------------
    # Sprint 8.5 T12 — resumable-session-API gate promotion (+2 → 73).
    # ------------------------------------------------------------------
    # Per spec §9 the 2 modules below are promoted to the durable gate
    # at the standard 95% line / 90% branch floor. The user-locked
    # tightening edit B (``feedback_verify_promotion_meets_floor_at_
    # promotion_time``) ran ``tools/check_critical_coverage.py`` against
    # a FRESH full-suite ``coverage.json`` IN THE SAME COMMIT as this
    # ``_CRITICAL_FILES`` extension — NOT just the count-guard bump. The
    # 2026-05-20 promotion run found BOTH modules below floor on fresh
    # data (``checkpoint_store.py`` 89.90% line / 85.48% branch;
    # ``local_object_store_adapter.py`` 92.58% line); the SAME commit
    # lands the focused negative-path repair
    # (``test_checkpoint_store_coverage.py`` +
    # ``test_local_object_store_adapter_coverage.py``) bringing both to
    # 99%+ line / 99%+ branch. The repair ALSO surfaced + fixed a real
    # taxonomy gap in the promoted adapter: Python 3.12 ``Path.resolve()``
    # raises ``RuntimeError`` (not ``OSError``) on a symlink loop, so the
    # adapter's four ``except OSError`` resolve-guards did not catch
    # loops — fixed to ``except (OSError, RuntimeError)`` in this commit.
    #
    #   * ``sandbox/checkpoint_store.py`` — the substantive tenant-
    #     isolation + retention enforcement boundary of the Sprint-8.5
    #     resumable-session API. Owns the ``CheckpointStore`` orchestrator
    #     (persist / load_latest / tombstone_session / load_tombstone /
    #     purge_expired / purge_by_id), the ``CheckpointMetadata`` /
    #     ``VaultLeaseRef`` / ``TombstoneRecord`` frozen wire-public
    #     dataclasses, and the ``TombstoneCorruptError`` /
    #     ``CheckpointMaxPerSessionRetentionLocked`` typed exceptions.
    #     ON the gate because: checkpoint bytes are keyed by
    #     ``<tenant_id>/<session_id>/`` — the per-tenant prefix IS the
    #     cross-tenant isolation boundary; ``from_storage_payload`` is
    #     the wake-time evidence parser (a malformed-blob branch that
    #     raised a raw ``TypeError`` instead of ``ValueError`` would
    #     surface the WRONG wake-time closed-enum refusal taxonomy);
    #     ``load_tombstone`` raising ``TombstoneCorruptError`` on a
    #     tampered sentinel (P1.r6 fail-closed) is what stops a
    #     destroyed session from looking restorable; retention-window
    #     enforcement at ``purge_expired`` is the regulator-erasure
    #     surface.
    #   * ``db/adapters/local_object_store_adapter.py`` — Sprint-4 driver
    #     promoted because Sprint 8.5's ``list_prefix()`` Protocol
    #     extension (spec §3.5) makes it a RUNTIME checkpoint tenant-
    #     isolation enforcement surface: ``CheckpointStore.load_latest()``
    #     + ``purge_expired()`` walk per-tenant ``<tenant>/<session>/``
    #     prefixes via ``list_prefix``, and the driver's dual root-safety
    #     check (every resolved dir + file must canonicalise under BOTH
    #     ``self._root`` AND the prefix subtree) is what stops a tenant-a
    #     symlink pointing at tenant-b's checkpoints from leaking into
    #     tenant-a's listing. A ``..`` traversal OR a cross-prefix
    #     symlink leak here bypasses the tenant-isolation invariant.
    #     Promoted alongside ``checkpoint_store.py`` because Sprint 8.5
    #     adds the new substantive enforcement surface — NOT because 8.5
    #     is the first runtime consumer (the driver already backs
    #     ``protocol/supply_chain.py`` Sigstore bundles + plugin-registry
    #     admission fixtures per P3.r6).
    #
    # OFF the durable gate per spec §4.2 + Doctrine F (with explicit
    # carve-out rationale; same precedent as Sprint 8A's
    # ``sandbox/audit.py`` + Sprint 8B's ``sandbox/backend_factory.py``):
    #
    #   * ``sandbox/reaper.py`` — ``CheckpointReaper``: a thin asyncio
    #     loop (``run_once`` / ``run_forever``) wrapping the on-gate
    #     ``CheckpointStore.purge_expired()``. NOT-CC per spec §4.2 — the
    #     substantive retention-floor enforcement lives in
    #     ``checkpoint_store.py`` (which IS on the gate); the reaper
    #     carries only schedule + loop + exception-survival glue. Pinned
    #     by ``tests/unit/sandbox/test_reaper.py``. Promoting it would
    #     measure loop-glue coverage where the enforcement is already
    #     gated — same Doctrine F precedent as ``sandbox/audit.py``.
    ("src/cognic_agentos/sandbox/checkpoint_store.py", 0.95, 0.90),
    ("src/cognic_agentos/db/adapters/local_object_store_adapter.py", 0.95, 0.90),
    # Sprint 9 T10 — ISO 42001 control-mapping evidence layer (ADR-006):
    # the registry, the domain-separated Merkle tree, cosign signing,
    # and the evidence-pack exporter — they define examiner-facing
    # evidence format, control mapping, integrity proof, and signing.
    ("src/cognic_agentos/compliance/iso42001/controls.py", 0.95, 0.90),
    ("src/cognic_agentos/compliance/iso42001/merkle.py", 0.95, 0.90),
    ("src/cognic_agentos/compliance/iso42001/signing.py", 0.95, 0.90),
    ("src/cognic_agentos/compliance/iso42001/evidence_pack.py", 0.95, 0.90),
    #
    # ------------------------------------------------------------------
    # Sprint 9.5 Z1 — Model Registry primitive durable critical-controls
    # modules (gate 77 → 81).
    # ------------------------------------------------------------------
    # Per ADR-013 + the Sprint-9.5 spec §10 Z1 closeout, the 4 modules
    # below are promoted to the durable gate at the standard 95% line /
    # 90% branch floor. The user-locked tightening edit B per
    # ``feedback_verify_promotion_meets_floor_at_promotion_time`` ran
    # ``tools/check_critical_coverage.py`` against a FRESH full-suite
    # ``coverage.json`` IN THE SAME COMMIT as this ``_CRITICAL_FILES``
    # extension — NOT just the count-guard ``_EXPECTED_ENTRY_COUNT``
    # bump in the self-test. The 2026-05-23 promotion run found 3/4
    # modules at 100% line / 100% branch on fresh data AND
    # ``portal/api/models/lifecycle_routes.py`` BELOW floor at 91.08%
    # line (4 branches missing: 3 ``_verify_record_signature`` early-
    # returns + 2 ``ModelNotFound`` race paths + the
    # ``retire_model`` ``ModelLifecycleRefused`` catch); the SAME
    # commit lands the focused negative-path repair
    # (``TestVerifyRecordSignatureEarlyReturns`` 3 tests +
    # ``TestPromoteRetireRacePaths`` 2 tests +
    # ``TestRetireLifecycleRefused`` 1 test = 6 floor-pin tests
    # appended to ``tests/unit/portal/api/models/test_lifecycle_routes.py``)
    # bringing lifecycle_routes.py to 100% line / 100% branch.
    #
    # The 4 modules promoted form the Model Registry primitive's
    # substantive enforcement surface per ADR-013 + AGENTS.md
    # "Model registry lifecycle transitions" stop rule:
    #
    #   * ``models/registry.py`` — pure-functional ``ModelRecord``
    #     lifecycle state machine. Owns the closed-enum 12-value
    #     ``ModelLifecycleRefusalReason`` Literal (the wire-protocol
    #     contract for every 409 lifecycle refusal body) + the
    #     6-value ``ModelLifecycleState`` + 4-value ``ModelKind`` +
    #     5-value ``ModelTransition`` Literals + the 5-value
    #     ``MODEL_LIFECYCLE_ISO_CONTROLS`` tuple stamped on every
    #     ``model.lifecycle.*`` chain row. ``validate_transition(*,
    #     from_state, to_state, transition)`` is the pure-functional
    #     state-machine validator at ``registry.py:116``;
    #     ``ModelLifecycleRefused(reason)`` carries ONLY the
    #     closed-enum reason — no transition field on the exception.
    #     Drift in any of the 4 Literals or the validate_transition
    #     refusal precedence (state-vocab → re-retire-idempotency →
    #     terminal-state-guard → generic-legal-pair) is
    #     wire-protocol-public regression.
    #   * ``models/storage.py`` — Postgres + Oracle ``ModelRecordStore``
    #     at ``storage.py:206``; the
    #     ``DecisionHistoryStore.append_with_precondition`` consumer
    #     that drives every model-lifecycle transition through the
    #     Sprint-2.5 atomic primitive. Owns the ``register()`` genesis
    #     path (INSERT ``proposed`` + append ``model.lifecycle.proposed``
    #     chain row atomically); the ``transition()`` promote/retire
    #     path with the A4 R1 P1 TOCTOU re-check + the 12-value refusal
    #     vocabulary; the A6.0 ``_lifecycle_payload`` immutable
    #     evidence snapshot helper (17 fields covering the per-spec
    #     §4.1 + §4.2 control-tag evidence binding); the
    #     ``load_by_model_id`` / ``list_for_tenant(tenant_id, *,
    #     limit, cursor, state)`` / ``load_lifecycle_history`` read
    #     methods (A5). The B4 R2 P1 ``signature_digest`` recompute-
    #     before-cosign evidence-integrity contract depends on this
    #     module storing the digest faithfully; the B5 ``?state=``
    #     filter contract depends on ``list_for_tenant``'s ``state``
    #     kwarg being honest. Tenant-isolation enforcement boundary:
    #     the ``WHERE tenant_id == :tenant_id`` clause in
    #     ``list_for_tenant`` IS the cross-tenant boundary (no
    #     application-side filter; defence-in-depth at the storage
    #     layer).
    #   * ``models/trust.py`` — cosign artefact verification gate per
    #     ADR-013. ``ModelTrustGate.verify_model_signature(*,
    #     signed_artifact_path, sigstore_bundle_path,
    #     tenant_trust_root)`` mirrors the ``protocol/trust_gate.py``
    #     cosign subprocess discipline exactly (list-form argv, no
    #     shell, frozen 2-key subprocess env at module-scope
    #     ``_SUBPROCESS_ENV`` = ``{"PATH": "/usr/local/bin:/usr/bin",
    #     "HOME": "/tmp"}``, asyncio timeout + SIGKILL + reap,
    #     exit-code-only verdict — stdout/stderr never parsed).
    #     Module-level ``sigstore_bundle_digest(path) -> str`` helper
    #     (SHA-256 hex over the raw bundle bytes, chunked 64 KiB)
    #     — the B4 R2 P1 evidence-integrity invariant for
    #     ``record.signature_digest == sha256(bundle_bytes)`` runs
    #     here. The 3-arg bundle-only argv shape (cosign verify-blob
    #     --key <trust> --bundle <bundle> <artefact>; no
    #     --signature flag) is pinned by the A2 R1 argv-shape
    #     regression — Sigstore bundles carry the signature inside
    #     the bundle, NOT as a separate --signature payload.
    #   * ``portal/api/models/lifecycle_routes.py`` — register /
    #     promote / retire route module (B4). CC at the route layer:
    #     owns the cosign path-containment helper
    #     ``_resolve_under_tenant_root`` (rejects 7 documented attack
    #     classes: tenant_id_invalid + tenant_root_escapes_root +
    #     absolute_path + uri_scheme + traversal_segment +
    #     escapes_tenant_root + missing_or_not_file — per the B4 R2
    #     P2 #2 tenant-id + tenant-root containment fix); the cosign-
    #     OUTSIDE-transaction helper ``_verify_record_signature`` with
    #     the B4 R2 P1 ``sigstore_bundle_digest`` recompute-before-
    #     cosign evidence-integrity check; the body-aware promote
    #     scope resolution (``model.promote.<target_state>``) +
    #     HumanActor gate for ``target_state=="serving"``; the state-
    #     aware HumanActor gate at ``/retire`` (only fires when
    #     current ``lifecycle_state == "serving"``). All three
    #     handlers thread the closed-enum refusal reasons from
    #     storage's state machine onto the 409 wire body per the B2
    #     R1 wire-body-collapse contract; the ``ModelNotFound`` race
    #     paths surface as 404 ``model_not_found``. Standing-offer
    #     §30 invariant: ``from __future__ import annotations`` is
    #     INTENTIONALLY OMITTED so FastAPI's ``inspect.signature()``
    #     can resolve ``Annotated[..., Depends(<closure-local>)]``
    #     against closure-local dependency instances (``_require_retire``
    #     + ``_require_tenant_ownership`` live inside
    #     ``build_model_lifecycle_routes``; the bare-POST register
    #     endpoint moves to ``register_model_lifecycle_register(parent,
    #     *, store)`` per the B5 lifecycle-routes split — see
    #     ``feedback_bare_prefix_endpoints_register_on_parent``).
    #
    # OFF the durable gate per Doctrine F (with explicit carve-out
    # rationale; same precedent as Sprint 8A's ``sandbox/audit.py`` +
    # Sprint 8B's ``sandbox/backend_factory.py`` + Sprint 8.5's
    # ``sandbox/reaper.py``):
    #
    #   * ``portal/api/models/inspection_routes.py`` (B5) — pure-read
    #     list / detail / audit endpoints; no ``store.transition()``
    #     calls; no Human-only-decisions enforcement boundary; no
    #     cosign verification. Same R32 doctrine as the pack
    #     ``inspection_routes.py``: pure-read inspection module owns
    #     no chain-row write and no Human-only-decisions enforcement
    #     boundary; CC risk for the tenant-isolation surface is
    #     covered by ``models/storage.py``'s ``list_for_tenant`` +
    #     ``load_by_model_id`` being on the gate (the WHERE clause
    #     IS the boundary).
    #   * ``portal/api/models/router.py`` (B5) — composition glue
    #     (``build_models_router`` factory that mounts the bare-POST
    #     register + bare-GET list directly on the parent router +
    #     includes the ``{model_id}``-keyed lifecycle + inspection
    #     sub-routers). No decision logic; no closed-enum vocabulary;
    #     no refusal taxonomy. Same Doctrine F precedent as
    #     ``portal/api/packs/router.py``.
    #   * ``portal/api/models/dto.py`` (B3) — pure type-only DTOs
    #     (``ModelBaseModel`` frozen + ``extra="forbid"`` base +
    #     ``RegisterModelRequest`` + ``PromoteModelRequest`` +
    #     ``ModelResponse`` + ``ModelLifecycleEventResponse`` +
    #     ``ModelDetailResponse`` + the 4-value ``PromoteTargetState``
    #     Literal). Same precedent as ``portal/api/packs/dto.py`` +
    #     ``portal/api/ui/dto.py`` — DTO type contracts are caught at
    #     Pydantic parse time + static type checks; coverage on a
    #     pure-DTO module would measure runtime-import + class-
    #     decoration lines only.
    #   * ``portal/rbac/model_tenant_isolation.py`` (B2) — although
    #     this module owns the wire-public ``ModelTenantIsolationFailure``
    #     (4 internal) + ``ModelTenantIsolationWireReason`` (3
    #     wire-public) closed-enum vocabulary AND the user-locked B2
    #     wire-body-collapse doctrine (cross-tenant → ``model_not_found``
    #     at the wire), it is NOT in the AGENTS.md model-registry
    #     stop-rule list. The CC risk is fully covered by the
    #     11-test ``TestModelTenantIsolationVocabulary`` +
    #     ``TestWireShapeParityPin`` + the integration tests at
    #     ``test_lifecycle_routes.py`` (which already exercise the
    #     wire-body collapse via the on-gate lifecycle_routes.py
    #     handler). Same Doctrine F precedent as the pack
    #     ``portal/rbac/tenant_isolation.py`` (which IS on the gate
    #     via T12 promotion alongside the other 5 portal/rbac/
    #     primitives) — but B2 ships a NEW module under portal/rbac/
    #     and the user-locked invariant + the test surface together
    #     pin the wire-body-collapse contract without needing
    #     promotion.  Promotion-equity decision: same Doctrine F
    #     pattern as the Sprint-7B.2 split between the on-gate pack
    #     ``tenant_isolation.py`` and the off-gate
    #     ``portal/api/packs/router.py`` — the model module's
    #     stronger wire-collapse behaviour is pinned by its own
    #     ``TestModelTenantIsolationVocabulary`` (4-test) +
    #     ``TestWireShapeParityPin`` (1-test) suite, leaving the
    #     route-layer integration as the cross-coverage anchor.
    ("src/cognic_agentos/models/registry.py", 0.95, 0.90),
    ("src/cognic_agentos/models/storage.py", 0.95, 0.90),
    ("src/cognic_agentos/models/trust.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/models/lifecycle_routes.py", 0.95, 0.90),
    # Sprint 10 Z1 — Vault credential-leasing critical-controls
    # quartet. All 4 ride the same single strict 95% line / 90%
    # branch floor as the modules above:
    #
    #   * ``core/vault.py`` (T4) — dynamic credential leasing
    #     primitive. ``core/`` stop-rule per AGENTS.md L48; owns
    #     the wire-public 4-value Vault exception taxonomy
    #     (``VaultUnavailable`` / ``VaultPathNotFound`` /
    #     ``VaultAuthDenied`` / ``VaultProtocolError``) that
    #     drives the sandbox-side closed-enum collapse.
    #
    #   * ``core/_vault_transport.py`` (T2) — shared hvac
    #     transport (read/write/lease/revoke + retry + auth
    #     state). Carries auth/retry/connection management for
    #     Vault; ``core/`` stop-rule by automatic rule.
    #
    #   * ``sandbox/credentials.py`` (T6) — real
    #     ``VaultCredentialAdapter`` implementing the
    #     ``CredentialAdapter`` Protocol's ``mint_lease`` +
    #     ``revoke_lease`` extension. Executes the AGENTS.md
    #     L188 off-gate → on-gate promotion promise that was
    #     reserved at Sprint 8A.
    #
    #   * ``sandbox/backends/_shared_credentials.py`` (T10 K8s
    #     round-2 Gap I) — dependency-neutral cross-backend
    #     Vault exception → ``SandboxRefusalReason`` closed-
    #     enum mapping table. Wire-protocol-public artifact
    #     owner per Round-7 Gap O — Docker + K8s MUST agree on
    #     the mapping (drift = wire-protocol regression where
    #     the same Vault exception surfaces as different refusal
    #     reasons to bank-overlay consumers). Doctrinal fit is
    #     wire-public-artifact owner (like ``core/canonical.py``,
    #     ON-gate), NOT consumer-owned helper (like
    #     ``sandbox/backends/_shared_exec.py``, OFF-gate per
    #     Doctrine F). The Doctrine F framing does NOT apply
    #     because ``_shared_credentials.py`` is genuinely
    #     cross-backend infrastructure — both backends import
    #     symmetrically from a neutral location, not one-
    #     backend-owns-and-extracts.
    ("src/cognic_agentos/core/vault.py", 0.95, 0.90),
    ("src/cognic_agentos/core/_vault_transport.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/credentials.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/backends/_shared_credentials.py", 0.95, 0.90),
    # --- Sprint 10.5a Z1a — runtime scheduler primitive (ADR-022) -----
    # core/ stop-rule per AGENTS.md. Promoted to the durable critical-
    # controls coverage gate at the standard 95% line / 90% branch
    # floor per the user-locked tightening edit B per
    # [[feedback_verify_promotion_meets_floor_at_promotion_time]] —
    # gate runs against fresh ``--cov-branch coverage.json`` in this
    # same Z1a commit. Z1a focused-coverage repair (+11 tests: 9
    # in test_queue.py — constructor validation x4, max_depth
    # property x1, remove-not-found x2, retry-after-on-empty x2;
    # +2 in test_engine.py — reap_expired skip-no-TTL, _read_state
    # SchedulerTaskNotFound) brought engine.py 99.08%/94.74%,
    # queue.py 100%/100%, storage.py 100%/100% — all above floor.
    #
    # Module rationale:
    #   * ``core/scheduler/engine.py`` — public seam orchestrating
    #     storage + queue + concurrency caps + 4 consumer-owned seam
    #     Protocols (Quota / KillSwitch / ParentBudget / PackState) +
    #     policy_evaluator callable. Owns the 7-method public surface
    #     (submit / mark_running / complete / fail / cancel / preempt
    #     / reap_expired); owns the `SchedulerPromotionRefused` typed
    #     exception with 2-value closed-enum reason (`caps_saturated`
    #     / `not_at_queue_head`); owns the `parent_task_id` fail-loud
    #     pre-T10 guard; owns the durable-first promotion ordering
    #     contract (storage.transition succeeds BEFORE in-memory
    #     bookkeeping mutates per round-7 reviewer P2).
    #   * ``core/scheduler/queue.py`` — `BoundedQueue` (FIFO + bounded
    #     depth + dynamic wall-clock aging via injectable clock seam
    #     + `peek` for round-7 FIFO-head probe) + `ConcurrencyCaps`
    #     frozen dataclass. The bounded-invariant runtime guards here
    #     are wire-protocol-public for the SchedulerEngine consumer +
    #     the Settings-layer mirror at `core/config.py` (T6).
    #   * ``core/scheduler/storage.py`` — Postgres-backed
    #     `SchedulerStorage`; `DecisionHistoryStore.append_with_precondition`
    #     consumer driving `submit()` (genesis) + `transition()`
    #     (state-machine) + `record_admission_refused()` (audit-only,
    #     no scheduler_tasks row). Owns the `_LockedTaskSnapshot` full
    #     evidence-snapshot threading from row-locked SELECT FOR
    #     UPDATE to chain payload per
    #     [[feedback_chain_payload_is_evidence_snapshot]]; owns the
    #     `_VALID_REFUSAL_REASONS` runtime closed-enum guard on the
    #     `scheduler.admission_refused` chain row.
    ("src/cognic_agentos/core/scheduler/engine.py", 0.95, 0.90),
    ("src/cognic_agentos/core/scheduler/queue.py", 0.95, 0.90),
    ("src/cognic_agentos/core/scheduler/storage.py", 0.95, 0.90),
    # --- Sprint 10.5b Z1b — SchedulerPolicy Rego eval glue (ADR-022) ---
    # core/ stop-rule per AGENTS.md L48. Promoted at Sprint-10.5b Z1b
    # alongside the AGENTS.md stop-rule entry for
    # `policies/_default/scheduler.rego`. Gate runs against fresh
    # `--cov-branch coverage.json` in this same Z1b commit per
    # [[feedback_verify_promotion_meets_floor_at_promotion_time]].
    # Z1b focused-coverage repair (+10 tests in
    # `TestSchedulerPolicyFetchRefusalReasonErrorPaths` +
    # `TestSchedulerPolicyEvaluateDenyPathRefusalReasonFailClosed`)
    # brought policy.py from 73% to 100% line / 100% branch on the
    # `_fetch_refusal_reason` subprocess error paths (timeout /
    # FileNotFoundError / non-zero exit / malformed JSON / non-dict
    # JSON / empty result / unexpected shape / non-string value) +
    # the deny-path fetch-failure fail-closed envelope.
    #
    # Module rationale:
    #   * ``core/scheduler/policy.py`` — `SchedulerPolicy` Rego eval
    #     glue + `PolicyDecision` canonical home. Owns the wire-
    #     protocol-public 8-key spec §4.8 input projection
    #     (`_build_rego_input`), the deny-path string-fetch helper
    #     (`_fetch_refusal_reason`) bridging from
    #     `data.cognic.scheduler.admit.refusal_reason` to
    #     `PolicyDecision.policy_reason`, the plan §1179 allow-path
    #     suppression contract (allow=True ⇒ policy_reason=None),
    #     and the fail-closed envelope mapping
    #     `OpaNotInstalledError` / `RegoEvaluationError` to
    #     `PolicyDecision(allow=False, policy_reason="opa_unavailable")`.
    #     Subprocess invariants (PATH + HOME=/tmp; list-form argv;
    #     finite timeout) lockstep-pinned with `core/policy/engine.py`
    #     OPAEngine via a test-only drift detector.
    ("src/cognic_agentos/core/scheduler/policy.py", 0.95, 0.90),
    #
    # ------------------------------------------------------------------
    # Sprint 10.6 Z1c — workload credential projection planner (ADR-004
    # §25 amendment; closes Sprint 10.1 deferred Finding #1). Gate
    # 89 → 90.
    # ------------------------------------------------------------------
    # ``sandbox/`` is a stop-rule isolation boundary (AGENTS.md "Stop
    # rules" — the "Sandbox or sub-agent enforcement boundaries" rule;
    # section-relative ref avoids line-number drift), so the projection
    # planner rides the same durable per-file coverage
    # gate as the other promoted sandbox modules. Promoted at Sprint-10.6
    # Z1c per the spec §5.4 planner/executor split. The gate runs against
    # a FRESH full-suite ``--cov-branch coverage.json`` IN THE SAME
    # COMMIT as this ``_CRITICAL_FILES`` extension — NOT just the
    # count-guard ``_EXPECTED_ENTRY_COUNT`` bump — per
    # ``feedback_verify_promotion_meets_floor_at_promotion_time``. The
    # 2026-05-28 promotion run found the module at 100% line / 100%
    # branch on fresh data (``tests/unit/sandbox/test_projection.py``,
    # 39 tests), so no same-commit negative-path repair was required.
    #
    # Module rationale:
    #   * ``sandbox/projection.py`` — the per-credential pure-functional
    #     planner ``compute_projection_plan(*, lease, manifest_decl)``
    #     per spec §5.4 (NO ``resolved_workload_gid`` input — the backend
    #     executors own chgrp (Docker) / fsGroup (K8s)). Owns the
    #     ``CredentialDecl`` manifest-declaration dataclass + the
    #     ``ProjectionPlan`` / ``ProjectionRefused`` result types + the
    #     field-set-mismatch + field-value (non-string / empty / size)
    #     refusal axes whose closed-enum reasons are the wire-equal
    #     subset of ``SandboxRefusalReason`` carried on the
    #     ``credentials_projection_failed`` chain row per spec §5.7. A
    #     bug here lets malformed credential material reach the backend
    #     executor (Docker bind-mount / K8s Secret) — the substantive
    #     credential-projection gate, not thin wiring.
    #
    # NOTE on the live proofs: this Z1c commit is a COVERAGE-GATE
    # promotion only. The Z3 (Docker) + Z4 (K8s) live integration proofs
    # at ``tests/integration/sandbox/test_z{3,4}_*_credential_projection.py``
    # are env-gated + remain DEFERRED to the operator's pre-merge audit
    # (no live Vault / Docker / K8s in CI). The "sprint cannot close
    # until Z3 + Z4 pass" gate is a closeout / PR-merge concern, NOT a
    # claim made by this coverage promotion.
    ("src/cognic_agentos/sandbox/projection.py", 0.95, 0.90),
    #
    # ------------------------------------------------------------------
    # Sprint 11 Z1a — sub-agent primitive (ADR-005) 11a. Gate 90 → 94.
    # ------------------------------------------------------------------
    # ``subagent/`` is a stop-rule isolation boundary (AGENTS.md "Stop
    # rules" — the "Sandbox or sub-agent enforcement boundaries" rule;
    # section-relative ref avoids line-number drift), so the four
    # substantive 11a modules ride the same durable per-file coverage
    # gate. Promoted at Sprint-11 Z1a per the plan. The gate runs against
    # a FRESH full-suite ``--cov-branch coverage.json`` IN THE SAME
    # COMMIT as this ``_CRITICAL_FILES`` extension — NOT just the
    # count-guard ``_EXPECTED_ENTRY_COUNT`` bump — per
    # ``feedback_verify_promotion_meets_floor_at_promotion_time``. The
    # 2026-05-30 promotion run found all four at/above floor on fresh
    # data (``_types`` / ``policy`` / ``audit`` 100% line / 100% branch;
    # ``audit_verifier`` 96.67% line / 100% branch), so no same-commit
    # negative-path repair was required.
    #
    # Module rationale:
    #   * ``subagent/_types.py`` — wire-public closed-enum vocabulary
    #     (``SubAgentRefusalReason`` / ``SubAgentAuditEvent``) + typed
    #     refusal exceptions + ``SUBAGENT_ISO_CONTROLS``; drift is a
    #     wire-protocol regression.
    #   * ``subagent/policy.py`` — pure privilege-de-escalation (tool
    #     allow-list subset) + recursion-depth cap + budget narrowing per
    #     ADR-005; a bug here lets a child escalate beyond the parent or
    #     exceed the depth/budget cap.
    #   * ``subagent/audit.py`` — the four ADR-005 ``subagent.*`` chain
    #     emitters + payload-only parent-record linkage; a bug here
    #     breaks the cross-agent audit chain.
    #   * ``subagent/audit_verifier.py`` — cross-row linkage verifier
    #     (event-type filter + tenant-column parity + causal ordering,
    #     first-break semantics); a bug here lets a forged parent-child
    #     link verify clean.
    #
    # ``subagent/__init__.py`` stays OFF the gate per Doctrine F
    # (re-export marker; no decision logic).
    ("src/cognic_agentos/subagent/_types.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/policy.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/audit.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/audit_verifier.py", 0.95, 0.90),
    #
    # ------------------------------------------------------------------
    # Sprint 11b Z1b — sub-agent integration (ADR-005) 11b. Gate 94 → 97.
    # ------------------------------------------------------------------
    # ``subagent/`` is a stop-rule isolation boundary (AGENTS.md "Stop
    # rules" — the "Sandbox or sub-agent enforcement boundaries" rule), so
    # the three substantive 11b modules ride the same durable per-file
    # coverage gate. Promoted at Sprint-11b Z1b per the plan. The gate runs
    # against a FRESH full-suite ``--cov-branch coverage.json`` IN THE SAME
    # COMMIT as this ``_CRITICAL_FILES`` extension — NOT just the count-guard
    # ``_EXPECTED_ENTRY_COUNT`` bump — per
    # ``feedback_verify_promotion_meets_floor_at_promotion_time``.
    #
    # Module rationale:
    #   * ``subagent/spawn.py`` — the T6 scheduler-mediated spawn
    #     orchestrator; threads every spawn through the real SchedulerEngine
    #     (submit → mark_running → complete/preempt/fail) with no leaked
    #     rows/reservations on any admission outcome (refused / queued-cancel
    #     / over-budget-preempt / not-ok-fail / ok-complete). The substantive
    #     enforcement surface; a bug here breaks privilege de-escalation,
    #     budget narrowing, or the scheduler task lifecycle.
    #   * ``subagent/conformers.py`` — the T5 real DI conformers
    #     (``LocalParentBudgetResolver`` fail-loud on an unknown parent;
    #     ``PackStoreStateInterrogator`` matching the LOGICAL ``pack_id`` via
    #     paginated ``list_for_tenant(state="installed")`` — NOT
    #     ``store.load`` which keys by row id); a bug here mis-resolves
    #     pack-installed state or parent budget.
    #   * ``subagent/_facade.py`` — the T7 ``SubAgent`` facade + the T8
    #     module-level ``spawn_subagent`` seam; the privilege-de-escalation
    #     public boundary that constructs the spawner from ``settings`` +
    #     delegates. Thin, but on the floor because it is the public seam.
    #
    # ``subagent/__init__.py`` stays OFF the gate per Doctrine F (re-export
    # marker). ``subagent/_types.py`` + ``subagent/policy.py`` are already on
    # the gate from 11a Z1a (extended by 11b T4.5/T5, NOT re-added);
    # ``subagent/audit.py``/``audit_verifier.py`` likewise unchanged by 11b.
    ("src/cognic_agentos/subagent/spawn.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/conformers.py", 0.95, 0.90),
    ("src/cognic_agentos/subagent/_facade.py", 0.95, 0.90),
    # ──────────────────────────────────────────────────────────────────
    # Sprint 11.5a Z1a — governed memory substrate (ADR-019). 6 modules
    # promoted at the standard 95/90 floor:
    #   * ``core/memory/tiers.py`` — wire-public ``MemoryRefusalReason`` +
    #     the ``SubjectRef`` unscoped-refusal invariant.
    #   * ``core/memory/gate.py`` — the per-write / per-recall / per-enumerate
    #     enforcement boundary (ordered refusal precedence IS the contract).
    #   * ``core/memory/api.py`` — the single Layer-C governed access path.
    #   * ``core/memory/storage.py`` — ``MemoryAdapter`` contract + Postgres +
    #     Redis(scratch) impls; tenant- AND agent-scoped reads.
    #   * ``core/memory/consent.py`` — restricted-class consent gate.
    #   * ``core/dlp/scanner.py`` — the checksum/regex/gazetteer DLP seed.
    # OFF-gate per Doctrine F: ``core/memory/__init__.py`` (re-export),
    # ``_context.py`` / ``_seams.py`` (pure DTOs / consumer-owned seam).
    # ``vector.py`` / ``episodes.py`` were recall-feature modules off-gate at
    # 11.5a but are PROMOTED at 11.5c Z1c (see the 11.5c block below — T7 wired
    # substantive recall enforcement into them). ``portal/rbac/scopes.py`` +
    # ``actor.py`` + ``enforcement.py`` are ALREADY on the gate (T12 only
    # widened their scope unions; NOT re-added here).
    ("src/cognic_agentos/core/memory/tiers.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/gate.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/api.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/storage.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/consent.py", 0.95, 0.90),
    ("src/cognic_agentos/core/dlp/scanner.py", 0.95, 0.90),
    # ──────────────────────────────────────────────────────────────────
    # Sprint 11.5b Z1b — memory regulator-core (ADR-019). 4 modules
    # promoted at the standard 95/90 floor:
    #   * ``core/emergency/kill_switches.py`` — the real Redis
    #     ``memory.write_freeze`` kill-switch; fail-closed parse (non-bool
    #     ``frozen`` / missing custody / malformed → frozen + cache-poisoned).
    #   * ``core/memory/forget.py`` — the erasure entry point (tombstone /
    #     regulator-erasure custody validation); value-never-in-chain.
    #   * ``core/memory/redact.py`` — the tombstone-then-insert redaction op.
    #   * ``core/memory/_routing.py`` — the scratch→Postgres fallback composite
    #     (unavailable-only fallback; collision-free hashed scratch key;
    #     fail-closed envelope parse).
    # OFF-gate per Doctrine F: ``core/memory/reaper.py`` (thin asyncio loop;
    # the substantive retention-floor enforcement is the on-gate
    # ``adapter.purge_expired`` it delegates to — Sprint 8.5 ``sandbox/
    # reaper.py`` precedent).
    ("src/cognic_agentos/core/emergency/kill_switches.py", 0.95, 0.90),
    # Sprint 13.6b (ADR-018) — the QuotaEngine token meter (decomposed atomic
    # Redis counters; would_admit / release_reservation / record_actuals /
    # check_gateway_admit). The substantive admission-control enforcement
    # boundary; a bug here lets runaway-spend through or wedges the queue.
    ("src/cognic_agentos/core/emergency/quotas.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/forget.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/redact.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/_routing.py", 0.95, 0.90),
    # ──────────────────────────────────────────────────────────────────
    # Sprint 11.5c Z1c — agent-memory governance SURFACES (ADR-019). 5
    # modules promoted at the standard 95/90 floor:
    #   * ``core/memory/export.py`` — NEW; serialize + fail-closed persist
    #     (``MemoryExportPersistenceFailed``) + metadata-only ``memory.export``
    #     emit; value-never-in-chain; durable-tier filter; caller-supplied
    #     bucket + retention.
    #   * ``core/memory/episodes.py`` — the threshold>0.0 vector path: refusal
    #     on missing/blank query, authz-INTERSECTION with the governed long_term
    #     set (an ungoverned vector hit is dropped), score filter.
    #   * ``core/memory/vector.py`` — ``ensure_collection`` + the
    #     ``_is_indexable`` restricted-class exclusion rule (single source).
    #   * ``cli/validators/learning_surface.py`` — NEW; the
    #     ``[learning_surface]`` manifest-block validator (non-trivial
    #     allow/deny logic; on-gate per the Sprint-7A validator precedent).
    #   * ``portal/api/memory/routes.py`` — NEW; the ``/api/v1/memory`` surface
    #     — owns the Human-only-decisions boundary (``RequireHumanActor`` on
    #     regulator_erasure + export) + required-selector validation.
    # NOTE: ``vector.py`` + ``episodes.py`` were DELIBERATELY off-gate at 11.5a
    # (recall-feature modules with no enforcement); Sprint 11.5c T7 wired
    # substantive governance into them (the vector-path authz-intersection, the
    # ``memory_vector_recall_unavailable`` refusal, the index-on-write
    # restricted-class policy), so they are PROMOTED here.
    # OFF-gate per Doctrine F: ``portal/api/memory/__init__.py`` (re-export) +
    # ``portal/api/memory/dto.py`` (pure Pydantic DTOs — parse + static types
    # catch drift; same precedent as ``portal/api/packs/dto.py`` +
    # ``portal/api/ui/dto.py``). ``core/memory/_context.py`` (DTOs) +
    # ``core/config.py`` (settings) remain off-gate, unchanged.
    ("src/cognic_agentos/core/memory/export.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/episodes.py", 0.95, 0.90),
    ("src/cognic_agentos/core/memory/vector.py", 0.95, 0.90),
    ("src/cognic_agentos/cli/validators/learning_surface.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/memory/routes.py", 0.95, 0.90),
    # Eval slice (ADR-010 LLM-as-judge), eval-judge T6. The judge primitive IS the
    # single governed LLM-judge decision surface (parse fail-closed; it never
    # fabricates a verdict), so it rides the per-file floor. The route + DTOs stay
    # off-gate (R32 precedent — route enforcement covered by its own tests);
    # ``llm/gateway.py`` (already on-gate) was NOT modified by the slice.
    ("src/cognic_agentos/evaluation/judge.py", 0.95, 0.90),
    # ADR-023 (Wave-2) per-tenant config-overlay — the 4 substantive CC modules
    # (T1/T3/T4/T6 each landed under its own halt-before-commit critical-controls
    # review). All ride the standard 95% line / 90% branch floor:
    #   * registry.py — strict tighten-only validator + closed OverlayRefusalReason
    #     (the default-deny gate; a bug here silently widens a tenant cap/floor).
    #   * storage.py — in-closure atomic upsert/delete via append_with_precondition
    #     (config.tenant_overlay.{set,cleared} chain rows; the audit-write seam).
    #   * resolver.py — fail-closed request-time resolution + invalid_at_read audit
    #     (the consumer-facing decision point; corrupt overlay must fail closed).
    #   * portal/api/config_overlay/routes.py — operator-administered, human-only
    #     mutation endpoint; owns the AGENTS.md Human-only-decisions enforcement
    #     boundary (RequireHumanActor on PUT/DELETE), the same criterion that put
    #     packs/operator_routes.py on the gate. ``core/config.py`` (global Settings)
    #     stays OFF-gate.
    ("src/cognic_agentos/core/config_overlay/registry.py", 0.95, 0.90),
    ("src/cognic_agentos/core/config_overlay/storage.py", 0.95, 0.90),
    ("src/cognic_agentos/core/config_overlay/resolver.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/config_overlay/routes.py", 0.95, 0.90),
    # Sprint 12 (ADR-010 amendment) evaluation harness — 4 CC modules, each
    # landed under its own halt-before-commit critical-controls review:
    #   * corpus.py   — strict fail-closed corpus contract + loader (a bug here
    #     lets malformed corpora through into execution).
    #   * scorers.py  — evaluator/pass-fail logic (the gradable-quality boundary).
    #   * runner.py   — run orchestration + per-case error isolation.
    #   * storage.py  — atomic eval evidence + tenant boundary + value-free chain.
    # target.py / types.py + the portal route/DTO stay OFF-gate (R32 precedent).
    ("src/cognic_agentos/evaluation/corpus.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/scorers.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/runner.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/storage.py", 0.95, 0.90),
    # Sprint 13a (ADR-010) live replay — eval-run replay orchestration + diff;
    # the pass/fail-drift classification + the persist/diff/chain flow. route/DTO off-gate (R32).
    ("src/cognic_agentos/evaluation/replay.py", 0.95, 0.90),
    # Sprint 13b (ADR-011) adversarial testing — pure deterministic mutation engine +
    # the expand/run/verdict/persist/evidence orchestrator. corpus/scorers/runner/storage
    # extensions ride their existing gate entries; types/route/DTO/CLI off-gate (R32).
    ("src/cognic_agentos/evaluation/adversarial/mutator.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/adversarial/runner.py", 0.95, 0.90),
    # Sprint 13c (ADR-011) adversarial promotion gate — the submit-time evidence
    # producer (resolve candidate/baseline → verify → baseline regression via 13a's
    # compute_replay_diff → map the payload["adversarial"] snapshot). storage/
    # approval_gates/review_routes extensions ride their existing gate entries;
    # route/DTO off-gate (R32).
    ("src/cognic_agentos/evaluation/adversarial/evidence.py", 0.95, 0.90),
    # Sprint 13.5a (ADR-014/015) runtime approval engine core — the non-blocking
    # human-checkpoint primitive. engine.py: classify / create_request / check /
    # verify_grant_for_action (replay-binding gate) / grant / grant_second / deny;
    # engine-boundary human-only guard + RBAC scope-per-tier + 4-eyes distinctness
    # + lazy authoritative expiry. storage.py: decision-history-backed
    # approval_requests + the 5 value-free approval.* chain events via
    # append_with_precondition (Doctrine Lock D). policy.py: tools.rego tier->flow
    # classifier over the existing OPAEngine (fail-closed require_4_eyes). _types.py
    # stays OFF-gate (pure closed-enum + frozen-dataclass + validate_transition;
    # drift pinned by tests/unit/core/approval/test_types.py count guards).
    ("src/cognic_agentos/core/approval/engine.py", 0.95, 0.90),
    ("src/cognic_agentos/core/approval/storage.py", 0.95, 0.90),
    ("src/cognic_agentos/core/approval/policy.py", 0.95, 0.90),
    # Sprint 14A-A (ADR-022 + ADR-004) — the managed-run executor: the first
    # EXERCISED managed-run authority. Loads + validates the trusted pack record
    # (four fail-closed pre-submit checks), admits through the scheduler, owns
    # the sandbox session directly (create/exec/destroy, Fork A), routes the
    # failure semantics (non-zero exit -> complete; create/exec exception ->
    # scheduler.fail + finally-guarded teardown), and emits value-free run.*
    # evidence (separate stdout/stderr sha256 + byte counts; never raw output).
    # CC because a bug here lets an unvalidated pack reach sandbox-context
    # construction or mis-routes the create/exec failure semantics. SDK-free +
    # portal-runtime-free + packs-free (AST-fenced at
    # tests/unit/architecture/test_run_no_sdk_import.py). Pack access via the
    # PackRecordLoader seam (conformer in harness/sandbox.py).
    ("src/cognic_agentos/core/run/executor.py", 0.95, 0.90),
    # Sprint 14A-A3a (ADR-022 + ADR-004) — the durable run-record store: the
    # run-lifecycle tenant-isolation + chain-atomicity boundary (mirrors
    # core/scheduler/storage.py + packs/storage.py). RunRecordStore drives every
    # run-state transition through DecisionHistoryStore.append_with_precondition
    # (atomic chain row + state-cache UPDATE under one transaction, Doctrine Lock
    # D). CC because the SELECT ... FOR UPDATE tenant-scoped row lock + the
    # reserved-payload-key guard + the closed-enum transition gate are the
    # run-substrate's correctness boundary that A3b resume builds on. Store-only /
    # dormant in A3a (no production caller). core/run/_types.py (RunState +
    # validate_transition) stays OFF-gate (pure types, drift-pinned) per the
    # core/scheduler/_types.py precedent.
    ("src/cognic_agentos/core/run/storage.py", 0.95, 0.90),
    # Parent budget resolver seam (2026-06-19; ADR-005 + ADR-022) — the
    # scheduler-backed parent-budget-inheritance authority that resolves the
    # Sprint-13.7 Fork-E `_NullParentBudgetResolver` deferral. Wired into
    # build_runtime, so a parent_task_id-bearing scheduler submit narrows the
    # child budget (min(child_quota, parent_granted)) instead of raising
    # NotImplementedError. CC because the tenant-scoped snapshot read + the
    # terminal-state refusal + the fail-loud ParentTaskBudgetUnavailable
    # propagation (NO quota reservation / NO admission_refused row / NO
    # task-row insert) are the budget-inheritance policy boundary. Gate
    # 131 -> 132. The gate runs against a FRESH full-suite --cov-branch
    # coverage.json IN THE SAME COMMIT as this _CRITICAL_FILES extension
    # (NOT just the _EXPECTED_ENTRY_COUNT bump) per
    # feedback_verify_promotion_meets_floor_at_promotion_time; the promotion
    # run found the module at 100% line / 100% branch on fresh data
    # (tests/unit/core/scheduler/test_budget_resolver.py). The off-gate
    # _seams.py (Protocol + ParentTaskBudgetUnavailable) stays OFF per the
    # core/scheduler/_seams.py precedent.
    ("src/cognic_agentos/core/scheduler/budget_resolver.py", 0.95, 0.90),
    # Live sub-agent dispatch (2026-06-20; ADR-005 + ADR-022) — the default
    # ChildRunner: a child sub-agent runs as a governed managed run. CC because
    # fail-closed (missing managed_run / actor), the exact tenant-scoped pack
    # identity resolution (zero/multiple installed matches both fail closed), and
    # the RunResult -> ChildResult mapping (incl. the suspended /
    # pending_approval special-case summaries) are the live-dispatch enforcement
    # surface. Gate 132 -> 133. The gate runs against a FRESH full-suite
    # --cov-branch coverage.json IN THE SAME COMMIT as this _CRITICAL_FILES
    # extension (NOT just the _EXPECTED_ENTRY_COUNT bump) per
    # feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/subagent/managed_run_runner.py", 0.95, 0.90),
    # Startup discovery/trust-registration — Sprint 2 (ADR-002 + ADR-016) — the
    # pack-attestation resolver: a TRUST-INPUT PRIMITIVE that locates an installed
    # pack's signed attestation artefacts (cosign sig / sigstore bundle / SBOM /
    # SLSA provenance / single signed wheel + 3 grace-period optionals) from a
    # deployment-configured root and returns a PackAttestations for the runtime
    # trust gate (protocol/trust_gate.py + protocol/supply_chain.py) to verify.
    # CC because a wrong path or a wrong sourced SBOM digest is a wrong trust
    # decision: every resolved artefact path is canonicalised (realpath +
    # relative_to, replicating trust_gate._canonicalise_under_root) and asserted
    # under pack_attestation_root so a crafted ../ in the pack-controlled
    # distribution metadata cannot escape; required artefacts must exist + be
    # non-empty; the single-wheel rule fails closed on zero/multiple/empty; the
    # SBOM digest is sourced fail-closed from the SLSA provenance JSON. NEVER calls
    # EntryPoint.load() (no pack code executes in the resolver). Gate 133 -> 134.
    # The gate runs against a FRESH full-suite --cov-branch coverage.json IN THE
    # SAME COMMIT as this _CRITICAL_FILES extension (NOT just the
    # _EXPECTED_ENTRY_COUNT bump) per
    # feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/protocol/pack_attestation_resolver.py", 0.95, 0.90),
    # PR-2b-1 (ADR-002 amendment) — the operator MCP server_url override + the
    # per-tenant exact-IP internal-host allow-list, both decision-history-audited
    # (mirrors core/config_overlay/storage.py). CC because a bug here lets a
    # malformed override URL or a metadata/loopback IP into the trust path the
    # Task-2 guard carve-out reads: validate_override_url enforces the http://-IP-
    # literal grammar (no DNS-reintroduction on the SDK leg), validate_allowlist_ip
    # + the shared ip_passes_internal_floor floor enforce exact-IP-only / no-
    # metadata at set-time AND feed the read-time guard, and each mutator threads
    # actor_type onto the chain-payload evidence snapshot. Grammar is enforced
    # INSIDE the precondition so a refusal rolls back the chain + state row
    # atomically. Gate 136 -> 137. The gate runs against a FRESH full-suite
    # --cov-branch coverage.json IN THE SAME COMMIT as this _CRITICAL_FILES
    # extension (NOT just the _EXPECTED_ENTRY_COUNT bump) per
    # feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/core/mcp_config/storage.py", 0.95, 0.90),
    # PR-2b-1 Task 6 (ADR-002 amendment) — the operator MCP override + per-tenant
    # internal-host allow-list write/read endpoints. CC because this route module
    # OWNS the AGENTS.md "Human-only decisions / Per-tenant ... changes"
    # enforcement boundary: every write (override PUT/DELETE, allow-list
    # add/remove) wires RequireHumanActor as a sub-dependency so a service-token
    # actor holding the write scope is refused 403 at the dep chain BEFORE the
    # handler body — exactly the boundary that put packs/operator_routes.py on the
    # gate. It also owns the closed-enum MCPConfigRejected -> 422 mapping (every
    # refusal surface needs a negative-path test) + the actor_type chain-payload
    # provenance threading + the mutually-exclusive accepted/refused/sibling-gate
    # log contract. The route NEVER writes the DB directly — every mutation goes
    # through the audited store mutators (set_override / clear_override / add_ip /
    # remove_ip). Gate 137 -> 138. The gate runs against a FRESH full-suite
    # --cov-branch coverage.json IN THE SAME COMMIT as this _CRITICAL_FILES
    # extension (NOT just the _EXPECTED_ENTRY_COUNT bump) per
    # feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/portal/api/mcp_config/routes.py", 0.95, 0.90),
    # M4 Task 1 — the runtime-config record store (ADR-026). The authoritative
    # DESIRED runtime-config state per (tenant, pack); a governance-path
    # append_with_precondition store the materializer (M4 Task 4) projects into the
    # derived MCP carve-out tables on install + retracts on disable/revoke. Owns the
    # closed-enum RuntimeConfigRefusalReason (incl. the active + terminal-revoked
    # reconfigure refusals) + the DB CheckConstraint on activation_status. Joins the
    # sibling core/mcp_config/storage.py + portal/api/mcp_config/routes.py above.
    # Gate 138 -> 139. Verified against a FRESH full-suite --cov-branch coverage.json
    # IN THE SAME COMMIT (NOT just the _EXPECTED_ENTRY_COUNT bump) per
    # feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/core/mcp_config/runtime_config.py", 0.95, 0.90),
)


def main() -> int:
    coverage_json = Path("coverage.json")
    if not coverage_json.exists():
        print(
            "::error::coverage.json not found in CWD. "
            "Run `uv run pytest --cov=cognic_agentos --cov-branch "
            "--cov-report=json` first."
        )
        return 1

    try:
        data = json.loads(coverage_json.read_text())
    except json.JSONDecodeError as exc:
        print(f"::error::failed to parse coverage.json: {exc}")
        return 1

    files = data.get("files", {})
    fail = False

    print("Per-file critical-controls coverage gate")
    print("=" * 72)

    for path, line_floor, branch_floor in _CRITICAL_FILES:
        entry = files.get(path)
        if entry is None:
            print(
                f"[FAIL] {path}: no coverage data — module not exercised "
                f"by the suite (or coverage.json was generated for a "
                f"different scope)"
            )
            print(f"::error file={path}::no coverage data for critical-controls module")
            fail = True
            continue

        summary = entry["summary"]
        # ``percent_covered`` is reported as a percentage, not a ratio.
        line_rate = summary["percent_covered"] / 100.0

        # Branch coverage is reported only when ``--cov-branch`` is
        # passed at run time. Calculate from the underlying counts so
        # this works on every coverage.py version.
        branches_covered = summary.get("covered_branches")
        branches_total = summary.get("num_branches")
        if branches_total is None or branches_total == 0:
            # No branches in this file → branch coverage is trivially 100%.
            branch_rate = 1.0
        else:
            branch_rate = branches_covered / branches_total

        ok_line = line_rate >= line_floor
        ok_branch = branch_rate >= branch_floor
        marker = "PASS" if (ok_line and ok_branch) else "FAIL"
        print(
            f"[{marker}] {path}: "
            f"line={line_rate:.2%} (floor {line_floor:.0%}) "
            f"branch={branch_rate:.2%} (floor {branch_floor:.0%})"
        )

        if not ok_line:
            print(
                f"::error file={path}::line coverage {line_rate:.2%} below floor {line_floor:.0%}"
            )
            fail = True
        if not ok_branch:
            print(
                f"::error file={path}::branch coverage {branch_rate:.2%} "
                f"below floor {branch_floor:.0%}"
            )
            fail = True

    print("=" * 72)
    if fail:
        print("Per-file critical-controls coverage gate: FAILED")
        return 1

    print("Per-file critical-controls coverage gate: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
