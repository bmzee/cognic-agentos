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
    Closed-enum **13-value** ``LifecycleRefusalReason`` at
    lines 160-174 (finalised at T2 from the plan-of-record's
    provisional ±1 count as the transition table was enumerated).
    ``_VALID_TRANSITIONS`` legal-pair table at :191 (10 transitions
    / 13 legal pairs). ``validate_transition(*, from_state,
    to_state, kind, transition)`` pure validator at :393 — four
    keyword-only args. ``iso_controls_for(transition)`` at :338
    returns the canonical ISO 42001 control tuple from the
    3-value ``_KNOWN_ISO_CONTROL_CODES`` set ({``A.5.31``,
    ``A.5.32``, ``A.6.2.4``}) feeding chain-row emission.
    ``LifecycleTransitionRefused(reason)`` at :304 carries ONLY
    the closed-enum reason. Doctrine Lock C — the closed-enum
    vocabulary IS the consumer-API wire-protocol contract carried
    by ``LifecycleTransitionRefused.reason``. The only in-tree
    consumer today is T3 storage (``packs/storage.py:108`` imports
    the contract; ``transition()`` derives the canonical ISO
    control tuple via ``iso_controls_for(transition)`` at :456
    BEFORE the precondition closure — pure-functional helper, no
    I/O — then runs ``validate_transition(...)`` at :480-485
    INSIDE the closure under the row-locked view; the precondition
    raises ``LifecycleTransitionRefused`` at :487, ``engine.begin()``
    at ``core/decision_history.py:482`` rolls back the transaction
    on the exception path, and the exception propagates up
    through ``append_with_precondition`` and ``transition()`` to
    the caller — neither storage layer catches it); Sprint 7B.2
    portal handlers are the planned next consumer. Chain audit events themselves use the
    ``pack.lifecycle.<target_state>`` namespace (keyed by target
    state, not by ``.refused`` — refusals roll back BEFORE any
    chain row is written). Sprint-7B.1 T2.
  * ``packs/storage.py`` — Postgres-backed ``PackRecordStore`` at
    :296; the ``DecisionHistoryStore.append_with_precondition``
    consumer that drives every lifecycle transition through the
    Sprint-2.5 T2 atomic primitive. ``transition()`` at :360
    first runs the preflight transition-name guard at :437-438
    (out-of-vocabulary transitions raise
    ``LifecycleTransitionRefused("lifecycle_transition_name_unknown")``
    BEFORE any helper invocation or DB work; mirrors the
    asymmetric-runtime-guard fix at ``packs/lifecycle.py:388-389``);
    on the green path resolves ``target_state`` at :440 and
    derives the canonical ISO 42001 control tuple via
    ``iso_controls_for(transition)`` at :456 BEFORE the closure
    (pure-functional, no I/O), then enters the row-locked
    precondition closure at :458 (``SELECT ... FOR UPDATE`` on
    the ``packs`` row at :467-473 under the chain-head ``FOR
    UPDATE`` lock) → ``validate_transition(...)`` at :480-485
    under the locked view → ``UPDATE packs SET state, last_actor,
    updated_at`` at :494-502 (three columns; no ``version_counter``
    field — atomicity comes from the chain-head + row lock pair).
    OUTSIDE the closure: ``_build_record`` at :505 mints a
    ``DecisionRecord`` with
    ``decision_type = f"pack.lifecycle.{target_state}"`` at :508
    and the pre-derived ``canonical_iso_controls`` value (no fresh
    ``iso_controls_for`` call from ``_build_record``).
    ``append_with_precondition`` at :524 commits chain row +
    state-cache UPDATE + chain-head UPDATE atomically. Two-class
    refusal taxonomy: ``PackNotFound`` at :219 for missing-pack
    lookups; ``PackRecordRefused`` at :238-265 carrying the
    1-value ``PackRecordRefusalReason`` Literal at :235 (only for
    the ``save_draft`` API-contract genesis-state guard);
    transition-table refusals raise ``LifecycleTransitionRefused``
    from the precondition at :487 so the engine's transactional
    rollback fires (no chain row, no state-cache mutation, no
    orphan INSERT). Doctrine Lock D. Sprint-7B.1 T3.

Both modules ride the same single strict 95% line / 90% branch
floor. Off-gate per Doctrine F gate-counting rule: the Alembic
migration version file at
``src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py``
— DDL is doctrine-critical but not coverage-tracked by convention
(migrations are run-once executable schema, not behavioural code).
Gate size grows from 41 modules to 43.
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
