# Cognic — Enterprise Development Plan
## Brick-by-Brick Build Sequence · v1.2 · April 2026

> ⚠️ **LEGACY CONTEXT FOR THIS REPO. BUILD_PLAN.md WINS ON CONFLICT.** This is the parent `bmzee/cognic` monorepo's brick sequence — useful for product/business context. Sprint-level execution in this repo follows [`docs/BUILD_PLAN.md`](../BUILD_PLAN.md). Where this doc references `src/cognic/`, in-repo agents/tools/skills, AI Governance Agent as a product agent, mock data in runtime paths, or bundled portal UI, the translations in [`ARCHITECTURE.md §8`](ARCHITECTURE.md) and the [`PROJECT_PLAN.md §2`](../PROJECT_PLAN.md) translation rule apply.

> **Governing document:** Cognic Master Strategy v5.0 (STRATEGY FROZEN)
> **Companion documents:** AgentOps Implementation Guide, Future Roadmap (Year 2+)
> **Rule:** Strategy principles are immutable. This plan implements them. Implementation ADRs extend details without changing principles.

---

## Part 1 — Engineering Standards (Non-Negotiable)

### 1.1 Repository Structure

```
cognic/
├── pyproject.toml                    # uv project config, single source of truth
├── .python-version                   # Python 3.12+
├── docker-compose.yml                # Dev environment
├── docker-compose.prod.yml           # Production overlay
├── Makefile                          # make dev, make test, make lint, make build
├── Dockerfile                        # Multi-stage build for cognic:latest image
├── .github/workflows/
│   ├── ci.yml                        # Lint → Type-check → Unit → Integration → Build
│   ├── cd-staging.yml                # Auto-deploy to staging on staging branch push
│   └── cd-production.yml             # Manual-approval deploy to production on main merge
│
├── src/cognic/
│   ├── core/                         # AgentOS core runtime
│   │   ├── three_pool.py             # Pool classification enforcer
│   │   ├── harness.py                # Planner → Executor → Checker state machine
│   │   ├── sprint_contract.py        # Sprint contract schema + enforcer
│   │   ├── context_reset.py          # 90-minute context reset + handoff
│   │   ├── decision_history.py       # CognicDecisionRecord + store
│   │   ├── audit.py                  # Tamper-evident audit engine
│   │   ├── guardrails.py             # Input/output guardrails runtime
│   │   ├── escalation.py             # Escalation bus
│   │   ├── auto_degradation.py       # Circuit breaker on accuracy drop
│   │   ├── citation.py               # Inline citation engine + verifier
│   │   ├── consent_ledger.py         # Consent record store + enforcement
│   │   └── config.py                 # Environment configs, threshold loading
│   │
│   ├── db/                           # Database abstraction
│   │   ├── engine.py                 # SQLAlchemy engine factory
│   │   ├── models.py                 # ORM models
│   │   ├── vector_store.py           # VectorStoreAdapter
│   │   └── migrations/               # Alembic migrations
│   │
│   ├── ingestion/                    # Data ingestion layer
│   │   ├── kafka_consumer.py         # Kafka consumer (conditional)
│   │   ├── webhook.py                # REST webhook endpoints
│   │   ├── db_poller.py              # Database polling with CDC
│   │   ├── file_drop.py              # File-based ingestion
│   │   └── event_bus.py              # Unified internal event format
│   │
│   ├── retrieval/                    # Hybrid retrieval pipeline
│   │   ├── dense.py                  # pgvector dense search
│   │   ├── bm25.py                   # PostgreSQL full-text / BM25
│   │   ├── reranker.py               # Cross-encoder reranker client
│   │   ├── orchestrator.py           # Hybrid merge + metadata filter + rerank
│   │   └── citation_verifier.py      # Citation accuracy validation
│   │
│   ├── llm/                          # LLM gateway
│   │   ├── gateway.py                # LiteLLM routing + cost tracking
│   │   ├── model_registry.py         # MLflow alias resolution
│   │   └── serving.py                # vLLM/SGLang deployment configs
│   │
│   ├── observability/                # AgentOps observability
│   │   ├── langfuse_client.py        # Langfuse tracing wrapper
│   │   ├── trace_context.py          # workflow_trace_id propagation
│   │   ├── cost_tracker.py           # Per-session cost aggregation
│   │   ├── scorers.py                # Custom Langfuse scorers
│   │   └── temporal_interceptor.py   # Temporal trace context serialization
│   │
│   ├── tools/                        # Layer A — atomic tools (no LLM)
│   │   ├── registry.py               # Tool registry + discovery
│   │   ├── cbs/                      # CBS read/write tools
│   │   ├── calculations/             # calc_cet1, calc_dscr, etc.
│   │   ├── documents/                # PDF extraction, SWIFT parsing
│   │   ├── search/                   # search_circulars, etc.
│   │   ├── external/                 # Sanctions screening, CIB lookup
│   │   ├── notifications/            # send_alert, log_audit
│   │   ├── intelligence/             # extract_spending, extract_travel
│   │   └── ml_models/                # ML model tool wrappers
│   │
│   ├── skills/                       # Layer B — deterministic workflows (no LLM)
│   │   ├── circular_ingestion.py
│   │   ├── kyc_expiry_check.py
│   │   ├── customer_intelligence.py
│   │   ├── nostro_reconciliation.py
│   │   ├── payment_validation.py
│   │   ├── str_package_assembly.py
│   │   ├── framl_correlation.py
│   │   ├── typology_screening.py
│   │   └── capital_adequacy.py
│   │
│   ├── agents/                       # Layer C — LLM-powered agents
│   │   ├── base_agent.py             # Pydantic AI base with Langfuse tracing
│   │   ├── policy_qa/
│   │   │   ├── agent.py
│   │   │   ├── config.yaml
│   │   │   └── prompts/
│   │   ├── regulatory_intel/
│   │   ├── rm_copilot/
│   │   ├── compliance_checker/
│   │   ├── ai_governance/
│   │   ├── aml_investigation/
│   │   ├── credit_proposal/
│   │   └── shariah_compliance/
│   │
│   ├── portal/                       # Bank portal
│   │   ├── api/                      # FastAPI backend
│   │   └── ui/                       # React frontend
│   │
│   └── deployment/
│       ├── kubernetes/
│       ├── zarf/
│       └── thresholds/               # Environment-specific AgentOps thresholds
│           ├── development.yaml
│           ├── pilot.yaml
│           ├── uat.yaml
│           └── production.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── eval/                         # Governed evaluation datasets
│       ├── policy_qa_100.json        # Versioned, owned by compliance advisor
│       ├── reg_intel_20.json
│       └── README.md                 # Dataset governance metadata
│
├── docs/
│   ├── adrs/                         # Architectural Decision Records
│   ├── brick-completion/             # Per-brick completion evidence
│   └── incidents/                    # RCA documents for SEV-1/2/3 incidents
│
└── scripts/
    ├── mock_data_generator.py
    ├── sbp_circular_fetcher.py
    └── check_critical_coverage.py    # Enforces per-file coverage on critical modules
```

### 1.2 Code Quality Gates (Enforced by CI)

Every pull request must pass ALL of these before merge:

```yaml
# .github/workflows/ci.yml — no exceptions, no "we'll fix it later"
steps:
  - name: Lint
    run: uv run ruff check src/ tests/
  - name: Type Check
    run: uv run mypy src/cognic/ --strict
  - name: Unit Tests (global floor)
    run: uv run pytest tests/unit/ -v --cov=src/cognic --cov-fail-under=80
  - name: Critical Module Coverage (95%+ enforced per file)
    run: |
      uv run pytest tests/unit/ -v \
        --cov=src/cognic/core/decision_history.py \
        --cov=src/cognic/core/audit.py \
        --cov=src/cognic/core/guardrails.py \
        --cov=src/cognic/core/consent_ledger.py \
        --cov=src/cognic/core/auto_degradation.py \
        --cov=src/cognic/core/escalation.py \
        --cov=src/cognic/observability/temporal_interceptor.py \
        --cov=src/cognic/retrieval/citation_verifier.py \
        --cov-report=json:coverage-critical.json
      python scripts/check_critical_coverage.py coverage-critical.json 95 \
        src/cognic/core/decision_history.py \
        src/cognic/core/audit.py \
        src/cognic/core/guardrails.py \
        src/cognic/core/consent_ledger.py \
        src/cognic/core/auto_degradation.py \
        src/cognic/core/escalation.py \
        src/cognic/observability/temporal_interceptor.py \
        src/cognic/retrieval/citation_verifier.py
  - name: Integration Tests
    run: docker compose up -d && uv run pytest tests/integration/ -v
  - name: Build Container Image
    run: docker build -t cognic:latest .
  - name: Security (full pipeline — see Part 8 for details)
    run: |
      uv run bandit -r src/cognic/ -ll
      uv run pip-audit
      gitleaks detect --source . --verbose
      trivy image cognic:latest --severity HIGH,CRITICAL --exit-code 1
      trivy config src/cognic/deployment/kubernetes/ --exit-code 1
      hadolint Dockerfile
  - name: SBOM
    run: syft cognic:latest -o spdx-json > sbom.json
```

**Non-negotiable rules:**
- No PR merges without passing CI. No exceptions.
- Tiered test coverage enforced:
    - **95%+ coverage (critical control modules, enforced per file via `scripts/check_critical_coverage.py`):** decision_history.py, audit.py, guardrails.py, consent_ledger.py, auto_degradation.py, temporal_interceptor.py, citation_verifier.py, escalation.py. These modules also require negative-path testing (what happens when inputs are malformed, thresholds are breached, hashes don't match, consent is revoked mid-operation).
    - **80% coverage (global floor):** all other modules. Every brick adds tests for its components.
- Type hints on every function signature. `mypy --strict` enforced.
- No raw SQL without ADR + tests + parameterisation + review. Default path is SQLAlchemy ORM for all queries. Exceptions permitted for: pgvector search tuning, BM25/full-text queries, bulk ingestion, audit reporting, and performance-critical paths — but each exception requires an ADR documenting why ORM is insufficient, must use parameterised queries (never string interpolation), must have dedicated tests, and must be approved in PR review.
- No hardcoded secrets. All secrets via Vault.
- No hardcoded model checkpoint names. All via LiteLLM alias → MLflow registry.
- Every LLM call traced to Langfuse. No silent LLM calls.
- Every tool/skill/agent has a docstring explaining its pool classification and why.

### 1.3 Git Workflow

```
feature branches → staging (integration) → main (production-ready)

feature/brick-XX-description
  └── PR → staging (1 approval + CI pass + brick tests green)
staging
  └── cd-staging.yml auto-deploys to staging environment on push
  └── PR → main (2 approvals + all tests + gate checklist signed)
main
  └── cd-production.yml deploys to production with manual approval gate
```

**Environment promotion:** staging branch = staging environment. main branch = production-ready. Feature branches never deploy anywhere. This is a linear promotion chain — no shortcuts.

**Commit format:** `feat(brick-01): add PostgreSQL + pgvector to docker-compose`

**Every PR must include:** brick number link, updated tests, updated docstrings, AgentOps checklist items addressed.

### 1.4 ADR Process

Every non-trivial technical decision gets an ADR to prevent "why did we do it this way?" conversations later.

```markdown
# ADR-XXX: [Title]
Status: Proposed / Accepted / Superseded
Date: YYYY-MM-DD
Context: What problem are we solving?
Decision: What did we decide?
Alternatives: What else did we evaluate?
Consequences: What are the trade-offs?
Strategy alignment: Which v5.0 principle does this implement?
```

**Triggers:** any deviation from v5.0 defaults, any tech substitution, any new dependency, any threshold definition, any data model decision.

### 1.5 Brick Completion Protocol

Brick completion has two distinct states to avoid circularity between brick sign-off and phase gates:

**State 1 — READY FOR GATE** (required before phase gate review):

```
BRICK READINESS CHECKLIST — Brick [XX]: [Name]
─────────────────────────────────────────────────
□ Code implemented and merged to staging
□ Unit tests written and passing (≥80% coverage for new code; 95%+ for critical modules)
□ Integration tests written and passing
□ Type hints complete, mypy clean
□ Docstrings on all public functions
□ ADR written for any non-trivial decisions
□ AgentOps items addressed:
  □ Every LLM call traced to Langfuse
  □ Every tool/skill call appears as child span
  □ Guardrails tested and firing
  □ Cost-per-session metric populating (if applicable)
  □ Decision history records written (if applicable)
  □ Audit engine captures trace (if applicable)
□ Brick-specific gate criteria met (from v5.0 Appendix A/B)
□ Evidence document filed in docs/brick-completion/brick-XX.md
□ PR approved by 1 reviewer for feature → staging promotion
→ Brick is now READY FOR GATE. Phase gate review can proceed.
```

**State 2 — RELEASED TO MAIN** (after phase gate passes):

```
□ Phase gate passed with this brick included
□ Promotion PR approved by 2 reviewers for staging → main
□ PR promoted from staging to main
□ Evidence document updated with gate pass reference
→ Brick is now RELEASED.
```

**Why two states:** Phase gates require all bricks in the phase to be Ready for Gate. But merging to main requires the phase gate to have passed. Without this split, a brick cannot be "complete" until merged to main, but main promotion depends on completed bricks — a circularity that jams delivery.

---

## Part 2 — Sprint Plan (12-Week MVP)

### Sprint Cadence

| Element | Rule |
|---------|------|
| Sprint length | 1 week |
| Planning | Monday 9am (30 min) |
| Standup | Daily 9:30am (15 min) |
| Review + demo | Friday 3pm (1 hour — demo working software) |
| Retro | Friday 4pm (30 min) |
| Gate review | End of each phase (Weeks 2, 4, 6, 10, 12) |

**Gate rule:** No release-critical implementation proceeds to the next phase until the current phase gate passes. Incomplete bricks carry forward but predecessor bricks must function together.

**Approved parallel prep (allowed before gate passes):** ADR drafting, evaluation dataset preparation, mock data shaping, Wave 2 design notes, documentation, and non-code planning for upcoming bricks. This prep work does not bypass the gate — it reduces dead time while gate review is in progress. No code for the next phase's bricks is written until the current gate passes.

### Staffing Assumptions

This 12-week timeline assumes AI-assisted implementation with senior human review. Specifically:

| Role | Commitment | Responsibilities |
|------|-----------|-----------------|
| CTO / Platform Lead | Full-time | Architecture decisions, infrastructure bricks, database/ingestion/deployment, gate sign-off |
| AI Engineering Lead | Full-time | Agent implementation, retrieval pipeline, LLM integration, prompt engineering, evaluation |
| Compliance Advisor | Part-time (10-15 hrs/week) | Evaluation dataset validation, accuracy review, regulatory positioning, SBP sandbox prep |
| Claude Code | Implementation engine | Scaffolding, test generation, boilerplate, documentation drafts, refactoring under human review |

**What this means practically:** Claude Code writes most of the initial code. Humans own architecture decisions, critical control module design, gate reviews, accuracy evaluation, and release authority. The 12-week timeline is achievable with this model because the majority of implementation volume (boilerplate, tests, documentation, integration glue) is AI-assisted, while the minority of high-judgment work (guardrails design, retrieval tuning, prompt engineering, compliance review) remains human-led.

**If Claude Code is not used:** This timeline should be extended to 18-24 weeks with a minimum team of 3-4 full-time engineers plus a part-time compliance advisor.

---

### ═══════════════════════════════════════════════════════
### PHASE 1: FOUNDATION (Weeks 1-2) — Bricks 1-9
### ═══════════════════════════════════════════════════════

**Goal:** Every infrastructure dependency running, observable, tested. BaseAgent skeleton with workforce identity and decision options schemas defined. No domain agent logic yet — that starts in Phase 2.

#### WEEK 1 — Infrastructure Bootstrap

**Sprint goal:** All containers healthy, DB abstraction proven, Langfuse live, LLM gateway routing.

```
DAY 1 (Monday):
  Morning:
    □ Project init: uv init, pyproject.toml, ruff/mypy config
    □ GitHub repo created, CI pipeline skeleton (empty tests pass)
    □ Docker Compose file: PostgreSQL 16 + pgvector extension
  Afternoon:
    □ Docker Compose continued: Redis 7, RabbitMQ 3.13, HashiCorp Vault
    □ BRICK 1 TESTS: PG CRUD, Redis SET/GET, RabbitMQ pub/sub, Vault r/w
    → Deliverable: docker compose up → all services healthy + integration tests passing

DAY 2 (Tuesday):
  Morning:
    □ BRICK 2: Langfuse Docker deployment with PostgreSQL backend
    □ Create test trace manually, verify dashboard renders
  Afternoon:
    □ Configure Langfuse dashboard views per AgentOps guide:
      - agent_accuracy_7d, agent_cost_per_session, agent_latency_p50_p95
      - guardrail_activation_rate, escalation_rate, correction_rate
    → Deliverable: Langfuse dashboard live with metric views configured

DAY 3 (Wednesday):
  Morning:
    □ BRICK 5 (start): SQLAlchemy engine factory
    □ PostgreSQL dialect default, test with SQLite for fast unit tests
    □ Dialect switching: verify Oracle/MSSQL connection string patterns work
  Afternoon:
    □ BRICK 5 continued: VectorStoreAdapter interface definition
    □ PgVectorStore implementation: index(), search(), delete()
    □ TESTS: index 100 vectors, search returns correct top-3, cosine similarity verified
    → Deliverable: ORM + vector store working, dialect switching tested

DAY 4 (Thursday):
  Morning:
    □ BRICK 5 continued: Alembic migration setup
    □ Create initial migration: decision_history, audit_log, consent_ledger tables
    □ TEST: alembic upgrade head → tables created, alembic downgrade → tables dropped
  Afternoon:
    □ BRICK 3: LiteLLM gateway deployment
    □ Configuration: route to Ollama (dev), vLLM (staging), SGLang (prod)
    □ TEST: curl to LiteLLM with cognic-tier1-dev alias → response received
    → Deliverable: LiteLLM routing to Ollama verified

DAY 5 (Friday):
  Morning:
    □ BRICK 4: Ollama installed with Tier 1 dev model
    □ LiteLLM → Ollama integration verified end-to-end
    □ Cost callback: LiteLLM sends cost metadata to Langfuse
  Afternoon:
    □ TEST: Full chain: HTTP request → LiteLLM → Ollama → response → Langfuse trace with cost
    □ Sprint review: demo all infrastructure running
    → Deliverable: Full LLM chain working, cost tracked in Langfuse
```

**WEEK 1 GATE:**
```
□ docker compose up → 6 services healthy (PG, pgvector, Redis, RabbitMQ, Vault, Langfuse)
□ SQLAlchemy CRUD verified, dialect switching tested
□ VectorStoreAdapter: 100 vectors indexed, top-3 search correct
□ Alembic migrations: up/down clean
□ Langfuse: dashboard accessible, test trace + cost visible
□ LiteLLM: routes to Ollama, cost tracked
□ Vault: secret read/write, zero hardcoded secrets
□ CI: lint + typecheck + unit + integration all green
□ All code has type hints + docstrings
□ Bricks 1-5 completion checklists signed
```

#### WEEK 2 — AgentOS Skeleton

**Sprint goal:** Tool registry, three-pool enforcement, data ingestion, BaseAgent all working.

```
DAY 1 (Monday):
  Morning:
    □ BRICK 6: Tool registry — register(), discover(), call() methods
    □ Pydantic model schemas for tool input/output definitions
  Afternoon:
    □ Register 5 dummy tools (calc_dscr, search_circulars mock, etc.)
    □ TESTS: register → discover → call → response → Langfuse tool span
    → Deliverable: Tool registry working with Langfuse tracing

DAY 2 (Tuesday):
  Morning:
    □ BRICK 7: Three-pool enforcement runtime validator
    □ Decorator/validator that checks: tools have no LLM imports,
      skills have no LLM imports, agents must use harness
  Afternoon:
    □ TESTS:
      - test_tool_rejects_llm_import: tool with LLM call → rejected
      - test_skill_rejects_llm_import: skill with LLM call → rejected
      - test_agent_requires_harness: agent without harness → rejected
      - test_valid_tool_accepted: clean tool → accepted
    → Deliverable: Three-pool enforcement passing all validation tests

DAY 3 (Wednesday):
  Morning:
    □ BRICK 8 (start): REST webhook endpoint (FastAPI)
    □ POST /ingest/webhook → validates payload → normalises to internal event
    □ Authentication: mTLS or API key + HMAC
    □ Idempotency: event_id in header, deduplicate via Redis SET with 72h TTL
  Afternoon:
    □ BRICK 8 continued: DB poller skeleton
    □ Polls test table on schedule, emits normalised events
    □ Deduplicates by (table, row_id, updated_at) tuple
    □ File-based ingestion: file drop → SHA256 verify → normalise
    □ Deduplicates by (filename, hash, size) tuple
    → Deliverable: Two ingestion modes producing same internal event format

DAY 4 (Thursday):
  Morning:
    □ BRICK 8 continued: Unified event bus
    □ All ingestion modes produce identical CognicEvent schema with schema_version field
    □ Poison message handling: events failing 3x validation → dead-letter queue + alert
    □ Partial failure: batch of N events processed individually, failures quarantined
    □ TESTS: webhook event == poller event == file event (same schema)
    □ TESTS: malformed event → DLQ after 3 retries. Duplicate event → deduplicated silently.
  Afternoon:
    □ BRICK 9 (start): BaseAgent with Pydantic AI
    □ Structured I/O with Pydantic models, model-agnostic via LiteLLM
    □ Retry logic on schema violation
    □ AgentIdentityRecord schema defined (Part 5A.1) — employee ID, department, reporting line, authority level
    □ DecisionOptionsResponse schema defined (Part 5A.4) — 2-3 ranked options with evidence and dissenting_considerations
    → Deliverable: Event bus unified, BaseAgent skeleton with workforce identity + decision options schemas

DAY 5 (Friday):
  Morning:
    □ BRICK 9 continued: Auto-trace to Langfuse on every call
    □ Agent identity (workforce registry ID) included in Langfuse trace metadata
    □ Tool binding: agent calls registered tools, tool spans visible
  Afternoon:
    □ INTEGRATION TEST: webhook event → tool registry → BaseAgent → Langfuse trace
    □ Sprint review: demo tool registry + three-pool + webhook + BaseAgent
    → Deliverable: Full skeleton chain working
```

**WEEK 2 GATE:**
```
□ Tool registry: register/discover/call/log for 5+ tools
□ Three-pool: tests prove no LLM in tools/skills, agents use harness
□ Data ingestion: webhook + poller + file drop → same event format
□ BaseAgent: structured output via LiteLLM → Ollama, Langfuse traced
□ AgentIdentityRecord and DecisionOptionsResponse schemas defined and tested
□ Agent workforce ID present in Langfuse trace metadata
□ All Brick 1-9 checklists signed
```

**═══ PHASE 1 GATE REVIEW (End of Week 2) ═══**
CTO + AI Lead jointly review all 9 brick completion docs.
Integration test: webhook → tool registry → BaseAgent → Langfuse (full chain).
No proceeding to Phase 2 until gate passes.

---

### ═══════════════════════════════════════════════════════
### PHASE 2: AGENT INFRASTRUCTURE (Weeks 3-4) — Bricks 10-20
### ═══════════════════════════════════════════════════════

**Goal:** Full governed harness cycle working end-to-end.

#### WEEK 3 — Harness + Core Governance

```
DAY 1 (Monday):
  □ BRICK 10: LangGraph harness — planner → executor → checker state machine
  □ workflow_trace_id: every graph execution gets UUID, propagated to all child spans
  □ TEST: graph cycles through states, parent-child traces visible in Langfuse

DAY 2 (Tuesday):
  □ BRICK 10 continued: checkpointing for crash recovery
  □ TEST: agent crash mid-execution → resume from checkpoint → completes correctly
  □ BRICK 11: Sprint contract enforcer
  □ TEST: vague task rejected, missing tools rejected, valid contract accepted

DAY 3 (Wednesday):
  □ BRICK 12: Compliance checker agent — skeptical evaluator
  □ Three-dimension evaluation: regulatory, factual, quality
  □ TEST: bad output rejected, good output approved, threshold breach → hard escalate
  □ BRICK 13: Context reset manager — 90-min timer + handoff artifact
  □ TEST: timer fires, handoff written, session continues

DAY 4 (Thursday):
  □ BRICK 14: Decision history store — CognicDecisionRecord, append-only, signed
  □ Include workforce identity fields: agent_department, agent_authority_level, reports_to
  □ Include decision option tracking: options_presented, agent_recommended, human_selected, followed_recommendation
  □ TEST: record created, signed with hash, indexed, queryable by agent/date/outcome
  □ TEST: workforce identity fields populated and queryable
  □ BRICK 15: Audit engine — full I/O logging, hash chain, tamper-evident
  □ TEST: audit trail written, hash chain verified, query interface works

DAY 5 (Friday):
  □ BRICK 16: Guardrails runtime
  □ Input: prompt injection detection, PII redaction (6 PK patterns), data freshness
  □ Output: decision authority check, regulatory language block, citation presence
  □ TESTS: CNIC redacted, IBAN redacted, injection blocked, stale data flagged
  □ INTEGRATION: full harness cycle with guardrails
  □ → plan → guard_input → execute → guard_output → check → log
```

#### WEEK 4 — Escalation + Monitoring + Citations + AI Gov

```
DAY 1 (Monday):
  □ BRICK 17: Escalation bus — Redis queue, HITL gate blocks until approval
  □ TEST: escalation created → queued → HITL blocks → approval → continues
  □ BRICK 18 (start): Langfuse integration — auto-trace decorators

DAY 2 (Tuesday):
  □ BRICK 18 continued: custom scorer registration, LLM-as-a-Judge pipeline
  □ sbp_circular_scorer registered, prompt versioning working
  □ TEST: judge evaluates sample output, score recorded in Langfuse

DAY 3 (Wednesday):
  □ BRICK 19: Auto-degradation monitor — rolling 7-day accuracy, circuit breaker
  □ Environment thresholds loaded from development.yaml/pilot.yaml/production.yaml
  □ TEST: accuracy drops below floor → agent degrades → alert → audit logged

DAY 4 (Thursday):
  □ BRICK 20: Inline citation engine — SBP reference format, source traceability
  □ Citation verifier: cross-references claim vs source, flags unsupported
  □ TEST: cited claim passes, uncited claim flagged, wrong citation flagged
  □ AI Governance Agent scaffold: reads Langfuse traces, logs governance events

DAY 5 (Friday):
  □ FULL INTEGRATION TEST:
    agent → guard_input → plan → execute → guard_output → check → cite → verify
    → escalate_if_needed → audit → decision_history → Langfuse trace with full hierarchy
  □ Sprint review: demo complete governed agent cycle
```

**═══ PHASE 2 GATE REVIEW (End of Week 4) ═══**
```
□ LangGraph harness: plan → execute → check with crash recovery
□ Sprint contracts enforced, compliance checker three-dimension evaluation
□ Decision history: append-only, signed, queryable
□ Audit engine: tamper-evident, hash-chained
□ Guardrails: PII redaction (6 PK patterns), injection, freshness
□ Escalation: HITL gate blocks until approval
□ Auto-degradation: circuit breaker fires, env-specific thresholds
□ Citation engine: source traceability, verifier flags bad citations
□ AI Gov Agent: running, monitoring traces
□ Langfuse: full trace hierarchy with workflow_trace_id
□ AgentOps: cost tracking, all dashboard metrics populating
□ All Brick 10-20 checklists signed, ≥80% coverage, 0 mypy errors
```

---

### ═══════════════════════════════════════════════════════
### PHASE 3: KNOWLEDGE LAYER (Weeks 5-6) — Bricks 21-30
### ═══════════════════════════════════════════════════════

**Goal:** SBP knowledge base with hybrid retrieval returning correct results.

#### WEEK 5 — Ingest + Index + Hybrid Retrieval

```
DAY 1: BRICK 21 — SBP circular fetcher (500+ circulars downloaded with metadata)
       BRICK 22 — PDF/HTML extractor (10 samples spot-checked for correctness)

DAY 2: BRICK 23 — Document embedder (semantic chunking, pgvector via VectorStoreAdapter)
       BRICK 24 — BM25 keyword index (PostgreSQL tsvector + metadata columns)
       TEST: keyword search for "BPRD Circular No. 04 of 2023" returns exact match

DAY 3: BRICK 25 — Reranker model deployment (cross-encoder endpoint)
       TEST: reranker scores candidate pairs correctly
       URDU BENCHMARK: 10 Urdu test queries evaluated, results documented

DAY 4: BRICK 26 — Hybrid retrieval orchestrator
       Merges dense + BM25, applies metadata filters, feeds reranker
       TEST: hybrid_search returns better results than either index alone

DAY 5: BRICK 27 — Citation verifier (cross-references cited circular vs KB)
       BRICK 28 — Circular ingestion skill (fetch → extract → chunk → embed → index both)
       TEST: new circular ingested → both indexes updated → searchable immediately
```

#### WEEK 6 — Search Tools + PolicyQA Start

```
DAY 1: BRICK 29 — Search tools suite (all via hybrid orchestrator)
       search_circulars, search_credit_policy, search_shariah_standards
       All registered in tool registry

DAY 2: BRICK 30 — Banking knowledge base assembly
       2K-3K chunks in both dense + BM25
       QUALITY GATE: 50 test searches return correct top-3
       URDU GATE: 20 Urdu queries benchmarked, results documented

DAY 3: Synthesise generic Pakistan credit policy + ingest
       BRICK 31 (start) — PolicyQA agent: executor prompt, tool binding, sprint contract

DAY 4: BRICK 31 continued: compliance checker integration, correction capture
       Agent answers first 20 test questions with citations

DAY 5: BRICK 31 continued: citation verifier integrated, full harness cycle
       PolicyQA answers 20 questions with verified citations through full governed pipeline
```

**═══ PHASE 3 GATE REVIEW (End of Week 6) ═══**
```
□ 500+ circulars fetched, extracted, chunked, indexed in dense + BM25
□ Reranker deployed, hybrid retrieval returning better results than single-index
□ Citation verifier flagging unsupported citations
□ 50 test searches: correct top-3 results
□ 20 Urdu queries: benchmarked with results documented
□ PolicyQA: answers 20 questions with verified citations
□ Full harness: retrieve → generate → check → cite → verify → log
□ Governed eval dataset: policy_qa_100.json created, owner assigned
□ All Brick 21-30 checklists signed
```

---

### ═══════════════════════════════════════════════════════
### PHASE 4: WAVE 1 AGENTS + PORTAL (Weeks 7-10) — Bricks 31-39 + Reviewer Lite
### ═══════════════════════════════════════════════════════

**Goal:** Three agents + AI Gov working. Portal demo-ready.

#### WEEK 7 — PolicyQA Accuracy Push

```
DAY 1-2: BRICK 32 — PolicyQA accuracy scorer
         100 ground-truth questions, Langfuse LLM-as-a-Judge pipeline
         Eval dataset: versioned, owned by compliance advisor

DAY 3-4: Prompt engineering iteration
         Fix top failure categories from eval
         Adjust retrieval: chunk sizes, reranker weights, metadata filters
         Track prompt versions in Langfuse

DAY 5:   Accuracy checkpoint: target >75%
         Failure case analysis documented
```

#### WEEK 8 — Regulatory Intelligence Agent

```
DAY 1: BRICK 33 — RegIntel agent (SBP website polling, circular ingestion)
DAY 2: Impact assessment: affected units, deadlines, actions for 5 test circulars
DAY 3: BRICK 34 — RegIntel accuracy scorer (20 assessments, compliance advisor review)
       Eval dataset: versioned, owned by compliance advisor
DAY 4: Jurisdiction-aware prompts (PK active, UAE/KSA config placeholders)
DAY 5: Prompt tuning for both PolicyQA and RegIntel, failure analysis
```

#### WEEK 9 — RM Copilot + AI Governance

```
DAY 1: BRICK 35 — RM Copilot Phase 1: mock client profile schema + generator
DAY 2: Pre-meeting brief template + KB integration
DAY 3: Generate 10 briefs, qualitative review by team (no accuracy gate)
DAY 4: BRICK 36 — AI Governance Agent: full implementation
       Weekly governance report from Langfuse traces
       Quarterly performance review template (Part 5A.6) integrated
       Authority compliance monitoring: blocks out-of-scope actions, logs violations
       KPI tracking: accuracy, correction rate, cost, latency, escalation discipline per agent
DAY 5: BRICK 37 — SBP examination evidence package (audit-ready PDF)
```

#### WEEK 10 — Integration + Portal + Reviewer Lite

```
DAY 1: BRICK 38 — Bank portal API (FastAPI): query endpoints, auth, rate limiting
       AI workforce registry API: agent identity records, org relationships, KPI summaries
       Executive decision board API (Wave 1 primitive: data endpoint only, full UI in Wave 2)
DAY 2: WebSocket for real-time agent status
DAY 3: BRICK 39 — Bank portal UI (React)
       Wave 1 scope:
         □ Query + governance dashboard + audit viewer
         □ Basic workforce identity view: agent list with ID, department, state, current accuracy
         □ Adoption dashboard (usage patterns, time savings)
       Wave 2 hardening (not in Wave 1 scope unless capacity allows):
         □ Full org-chart visualisation with reporting lines
         □ Detailed agent profile pages with authority, KPI history, evaluation records
         □ Executive decision board: pending decisions, option selection, decision log
DAY 4: Reviewer Lite (Wave 1 version of Reviewer Workbench):
       Human review is central to trust — even Wave 1 must have a named review surface.
       Acceptance criteria for Reviewer Lite:
         □ Case list: shows all agent outputs pending human review (State 1 = 100% review)
         □ Evidence view: click any output → see full Langfuse trace + cited sources
         □ Approve/Correct/Reject buttons with reason code dropdown
         □ Correction text field: human writes what the correct answer should have been
         □ Corrections flow to decision history store with reason codes
         □ SLA indicator: time since output generated (visual urgency)
       This is NOT the full Reviewer Workbench (Brick 61, Wave 2). This is the minimum
       review surface that makes State 1 (100% human review) operationally workable.
       Full workbench (diff view, case queue prioritisation, examiner export) comes in Wave 2.
DAY 5: Full integration: all agents through portal + Reviewer Lite
       Auto-degradation monitor: all metrics flowing to governance dashboard
```

**═══ PHASE 4 GATE REVIEW (End of Week 10) ═══**
```
□ PolicyQA: answers with cited, verified SBP references
□ RegIntel: detects circulars, produces impact assessments
□ RM Copilot Phase 1: realistic briefs from mock profiles
□ AI Gov: monitors all agents, weekly governance report
□ SBP evidence package: audit-ready PDF
□ Portal: query + governance + audit working
□ Portal: basic workforce identity view shows agent list with ID, department, state, accuracy
□ Workforce registry API: identity records queryable
□ Reviewer Lite: case list + evidence view + approve/correct/reject + reason codes
□ Reviewer Lite: corrections flowing to decision history with reason codes
□ Auto-degradation: metrics flowing, circuit breaker tested
□ Non-functional spot-check: PolicyQA p95 latency verified, portal API <200ms
□ All Brick 31-39 checklists signed + Reviewer Lite acceptance criteria met
□ Both eval datasets versioned and owned
```

---

### ═══════════════════════════════════════════════════════
### PHASE 5: DEMO READINESS (Weeks 11-12) — Bricks 40-43
### ═══════════════════════════════════════════════════════

**Goal:** PolicyQA >85%. Complete demo package. Adoption kit.

#### WEEK 11 — Accuracy Push

```
DAY 1: Full accuracy evaluation: 100 questions PolicyQA, 20 circulars RegIntel
DAY 2: Fix top failure categories (prompt tuning)
DAY 3: Fix retrieval failures (hybrid tuning)
DAY 4: Model tier evaluation if accuracy insufficient (test alternatives, document in ADR)
DAY 5: RM Copilot: qualitative review by full team
       GATE: PolicyQA >80%, RegIntel >75%, RM Copilot reviewed
```

#### WEEK 12 — Demo Polish

```
DAY 1: BRICK 40 — 50 mock Pakistani banking profiles (12-month tx history)
DAY 2: BRICK 41 — Adoption Kit (50+ prompts, training materials, 30-day onboarding)
       Agent performance review template (quarterly format from Part 5A.6)
       AI workforce onboarding guide for bank HR/governance teams
DAY 3: BRICK 42 — Demo script (10 questions + live Q&A, CCO/CTO pitch deck)
DAY 4: BRICK 43 — Accuracy report (publishable metrics, AI gov sample)
DAY 5: FINAL GATE REVIEW + demo rehearsal
```

**═══ PHASE 5 FINAL GATE — DEMO READY ═══**
```
FUNCTIONAL:
□ PolicyQA: >85% on 100-question governed eval dataset
□ RegIntel: >82% on 20-circular governed eval dataset
□ RM Copilot Phase 1: team sign-off on brief quality
□ AI Governance report: sample generated
□ SBP evidence package: audit-ready sample
□ Mock data: 50 profiles with Pakistani banking data
□ Adoption kit: prompts + training + onboarding ready
□ Demo: 10 questions + live Q&A, runs without intervention
□ Accuracy report: publishable for bank meetings
□ Portal: query + governance + audit through UI
□ Reviewer Lite: case list + evidence + approve/correct/reject functional
□ Workforce primitives: AgentIdentityRecord schema, DecisionOptionsResponse schema,
  workforce fields in decision history, basic identity view in portal, performance review template in adoption kit

NON-FUNCTIONAL (verified with evidence):
□ PolicyQA p95 latency <5 seconds
□ Portal API p95 <200ms
□ Hybrid retrieval p95 <500ms
□ Data ingestion: webhook handles 100 events/second sustained
□ Database backup/restore tested and timed
□ RTO <4 hours documented in runbook
□ Agent cost per session documented and within budget
□ Langfuse trace retention configured for ≥12 months

SECURITY:
□ CI security pipeline: bandit + pip-audit + gitleaks + trivy + hadolint all passing
□ SBOM generated for current build
□ Container image scanned, zero critical/high findings
□ No hardcoded secrets (Vault verified)
□ Dependency pins verified in uv.lock

OPERATIONAL:
□ Incident severity model documented
□ On-call rotation defined (even if team of 2)
□ Rollback protocol documented and tested (Docker Compose image/tag rollback for MVP environment)
□ Note: Argo CD one-command rollback is a Wave 2 production gate requirement, not a Week 12 MVP requirement
□ Ingestion DLQ monitored, dead-letter alert configured
□ ALL 43 brick completion checklists signed and filed
□ Zero known P1 bugs. All P2 bugs documented with timeline.
□ CI: all green, tiered coverage met, 0 mypy errors, 0 security findings
```

**═══ DO NOT APPROACH ANY BANK BEFORE THIS GATE IS PASSED ═══**

---

## Part 3 — Wave 2 Planning Framework (Months 5-12)

Detailed sprint plans created during Weeks 10-12 of Wave 1. Same cadence, same gates, same protocol.

### Wave 2 Pre-Planning (Begin Week 10)

| Task | When | Output |
|------|------|--------|
| CBS adapter architecture ADR | Week 10 | ADR: CBS abstraction design |
| T24 API sandbox access negotiated | Week 10-11 | API credentials |
| Temporal deployment ADR | Week 10 | ADR: Temporal config + trace interceptor |
| Enterprise control plane ADR | Week 11 | ADR: Argo CD + SPIFFE + OPA |
| Wave 2 sprint plan | Week 12 | Detailed plan for Bricks 44-63 |

### Wave 2 Brick Risk Register

| Brick | Risk | Mitigation |
|-------|------|-----------|
| 44-45 | T24 API docs poor quality | Mock adapter first, budget 2x time |
| 46 | Bank doesn't run Kafka | Use DB polling (Brick 8) — already built |
| 48 | ⚠️ Temporal breaks traces | Temporal Interceptor (AgentOps guide) — test explicitly |
| 58-59 | ML training data unavailable | Generic models on mock data, per-bank calibration at onboarding |
| 62 | Bank security review delays | Start security questionnaire at Week 10, not at deployment |
| 63 | Urdu OCR accuracy insufficient | PaddleOCR + LLM fallback, benchmark before committing |

### Wave 3-4 and Platform

Follow identical planning pattern — ADRs created during preceding wave, detailed sprints planned 2 weeks before start. Key advance items:

| Item | Advance Action | When |
|------|---------------|------|
| FRAML (Brick 75) | Requires AML + Fraud agents both live | Plan during Wave 2 Month 10 |
| Typology Registry (Brick 76) | Compliance advisor defines 8 typologies | Start research during Wave 2 |
| Federated Learning (Brick 77) | Requires 3+ banks | Earliest Month 18 |
| Digital Session Telemetry (Brick 78) | Conditional — assess bank digital maturity | Only for mature banks |

---

## Part 4 — Risk Mitigation Matrix

| Risk | Probability | Impact | Detection | Mitigation |
|------|-------------|--------|-----------|-----------|
| Brick dependency breaks | Medium | High | CI integration test failures | Explicit dependencies documented per brick |
| Accuracy gate not met Week 12 | Medium | High | Langfuse accuracy tracking | Built-in tuning weeks (7, 11). Model tier eval as fallback. Extend assisted phase — never ship below gate |
| Engineer leaves mid-build | Medium | High | Single-person dependency in standup | Every brick has completion doc + tests + ADRs. Code reviewable by second person |
| LLM model degrades after update | Medium | Medium | Model eval pipeline | Governed eval datasets. Shadow deployment before promotion |
| CBS integration harder than expected | High | Medium | CBS adapter ADR flags early | Mock adapter first. 2x time budget for real adapter |
| Temporal breaks trace context | High | Medium | Disconnected traces in Langfuse | ⚠️ Temporal Interceptor. Test explicitly with 5-min sleep workflow |
| Scope creep during demos | High | Medium | Feature request not in roadmap | v5.0 FROZEN. No new agents without ADR + strategy review |
| Security vulnerability | Low | High | CI: bandit + pip-audit | Every PR scanned. Zero-tolerance for critical/high findings |
| Bank procurement delays | High | High | Sales pipeline tracking | Free pilot + sandbox. Warm relationships from Month 1 via compliance advisor |
| Team burnout on 12-week sprint | Medium | Medium | Retro feedback | Friday retros. Sustainable pace. No weekend work as default |

---

## Part 5 — Weekly Quality Dashboard

Track from Week 1. Review every Friday at sprint review.

| Metric | Target | Tool | Alert Threshold |
|--------|--------|------|----------------|
| Test coverage (global) | ≥80% | pytest-cov | <75% = P1 |
| Test coverage (critical modules) | ≥95% | pytest-cov | <90% = P1 |
| Type safety | 0 errors | mypy --strict | Any error = PR blocked |
| Lint violations | 0 | ruff | Any violation = PR blocked |
| Security findings | 0 critical/high | bandit + pip-audit + trivy + gitleaks | Any finding = PR blocked |
| Brick completion rate | 3-4/week | Checklists | <2/week = escalate |
| PolicyQA accuracy | >85% by W12 | Langfuse eval | <70% at W8 = escalate |
| RegIntel accuracy | >82% by W12 | Langfuse eval | <65% at W9 = escalate |
| Agent cost/session | Trending down | Langfuse + LiteLLM | Spike >2x = investigate |
| CI build time | <10 min | GitHub Actions | >15 min = optimise |
| Integration test pass | 100% | pytest | Any failure = PR blocked |
| Open P1 bugs | 0 at gates | GitHub Issues | Any at gate = blocks |

---

## Part 6 — Non-Functional Acceptance Criteria

For enterprise banking software, functional correctness is not enough. Every phase gate must also verify non-functional readiness against these numerical targets.

### 6.1 Latency

| Agent/Operation | p95 Target | p99 Target | Measurement |
|----------------|-----------|-----------|-------------|
| PolicyQA (single query) | <5 seconds | <8 seconds | Langfuse trace duration |
| RegIntel (impact assessment) | <15 seconds | <25 seconds | Langfuse trace duration |
| RM Copilot (brief generation) | <20 seconds | <30 seconds | Langfuse trace duration |
| Hybrid retrieval (search) | <500ms | <1 second | Langfuse span duration |
| Tool call (deterministic) | <100ms | <200ms | Langfuse span duration |
| Portal API response | <200ms | <500ms | FastAPI middleware timing |

**Rule:** Latency targets are measured under realistic load (concurrent users = expected pilot load). Not tested on empty system with single user.

### 6.2 Throughput and Capacity

| Component | Target | Measurement |
|-----------|--------|-------------|
| Data ingestion (webhook) | >100 events/second sustained | Load test with k6 or locust |
| Data ingestion (DB poller) | Full customer table scan <30 min for 50K customers | Timed test with mock data |
| Data ingestion (file drop) | 1000-record CSV processed <60 seconds | Timed test |
| RabbitMQ queue backlog | <1000 messages sustained (alert at 5000) | RabbitMQ management console |
| Concurrent agent sessions | ≥10 simultaneous (pilot scale) | Load test |

### 6.3 Data and Storage

| Concern | Target | Validation |
|---------|--------|-----------|
| Database growth projection | <10GB/month at pilot scale (1 bank, 3 agents) | Measured after Week 10 mock data load |
| Decision history retention | Unlimited (append-only, never purged) | Schema design review |
| Langfuse trace retention | ≥12 months in production | Langfuse retention config |
| Knowledge base index size | <5GB for 3000 chunks (dense + BM25) | Measured after Brick 30 |
| Backup/restore time | Full PG backup <15 min, restore <30 min at pilot scale | Tested with `pg_dump`/`pg_restore` |
| RTO (Recovery Time Objective) | <4 hours for full platform recovery | Documented in runbook, tested quarterly |
| RPO (Recovery Point Objective) | <1 hour (WAL-based continuous backup) | PostgreSQL WAL archiving configured |

### 6.4 Audit and Compliance

| Concern | Target | Validation |
|---------|--------|-----------|
| Audit export generation | Full agent audit trail export <5 min for 30-day window | Timed test |
| SBP evidence package PDF | Generated <2 min | Timed test at Brick 37 |
| Decision history query | Any date/agent/outcome query returns <3 seconds | Indexed query test |
| Consent ledger query | Customer consent status lookup <100ms | Indexed query test |

### 6.5 Cost

| Concern | Target | Measurement |
|---------|--------|-------------|
| Agent cost per session (Tier 1) | <PKR 5 per query (pilot) | Langfuse cost tracking |
| Daily platform compute cost | <PKR 5,000/day at pilot (1 bank, dev GPU) | Infrastructure monitoring |
| Cost budget per environment | Dev: unlimited. Pilot: PKR 150K/month. Production: per bank SLA | Monthly review |

**Gate integration:** Phase 2 and Phase 4 gate reviews include non-functional spot-checks. Phase 5 (final gate) requires ALL non-functional targets verified with evidence.

---

## Part 7 — Incident Operations

Production alerts (auto-degradation, escalations, guardrail breaches) require operational response — not just architectural awareness.

### 7.1 Severity Model

| Severity | Definition | Example | Response SLA |
|----------|-----------|---------|-------------|
| SEV-1 (Critical) | Agent producing harmful/wrong output in production. Data integrity breach. Security incident. | PolicyQA citing wrong SBP circular leading to compliance violation | Acknowledge <15 min. Mitigate <1 hour. Resolve <4 hours. |
| SEV-2 (High) | Agent degraded or offline in production. Accuracy below gate. HITL gate unresponsive. | Auto-degradation triggered. Reviewer Workbench down. | Acknowledge <30 min. Mitigate <2 hours. Resolve <8 hours. |
| SEV-3 (Medium) | Performance degradation. Non-critical feature broken. Cost spike. | Latency >2x normal. Langfuse dashboard unavailable. | Acknowledge <2 hours. Resolve <24 hours. |
| SEV-4 (Low) | Cosmetic issue. Non-blocking bug. Minor UX problem. | Portal UI alignment issue. Dashboard chart rendering glitch. | Resolve in next sprint. |

### 7.2 On-Call and Authority

| Role | Responsibility | Authority |
|------|---------------|-----------|
| **Primary on-call (rotating weekly)** | Monitors alerts, acknowledges SEV-1/2, initiates response | Can rollback agent to previous version. Can disable agent. Cannot change thresholds. |
| **CTO** | Escalation point for SEV-1. Owns platform rollback authority. | Can rollback entire platform. Can change thresholds. Can override auto-degradation. |
| **AI Engineering Lead** | Owns agent accuracy investigation. Root cause analysis. | Can modify prompts. Can trigger model re-evaluation. Can adjust retrieval config. |
| **Compliance Advisor** | Consulted on any SEV-1 involving regulatory output. Approves agent re-promotion after degradation. | Can block agent re-promotion. Cannot modify code. |

### 7.3 Rollback Protocol

```
SEV-1/2 Detected:
  1. On-call acknowledges in Slack/PagerDuty within SLA
  2. Immediate action: disable affected agent (auto-degradation may already have done this)
  3. Verify: is the issue agent-level (prompt/retrieval) or platform-level (infra)?
  4. Agent issue → rollback to previous prompt version in Langfuse, re-run eval dataset
  5. Platform issue → rollback to previous deployment (MVP: Docker Compose image/tag rollback; Production: Argo CD one-command)
  6. Verify rollback successful: eval dataset passes, traces clean, no more bad outputs
  7. Notify bank stakeholder (for production incidents)
  8. RCA document due within 48 hours (filed in docs/incidents/)
  9. Re-promotion requires accuracy gate re-pass + compliance advisor sign-off
```

### 7.4 Communication

| Audience | Channel | When |
|----------|---------|------|
| Engineering team | Slack #cognic-incidents | All SEV-1/2/3 |
| CTO | Phone + Slack | All SEV-1, SEV-2 if unresolved in 2 hours |
| Bank stakeholder | Email from CEO/Domain Lead | SEV-1 in production, within 2 hours of detection |
| Compliance Advisor | Slack + call | Any SEV-1 involving regulatory output |

### 7.5 Post-Incident

- **RCA deadline:** 48 hours after resolution for SEV-1/2. 1 week for SEV-3.
- **RCA format:** What happened → Why → What we did → What we'll change → ADR if systemic
- **Blameless:** RCAs focus on systems, not individuals. No punitive action from incident investigation.
- **RCA review:** Discussed at next weekly AgentOps review (per AgentOps guide ownership cadence)

---

## Part 8 — Security Pipeline (Enterprise-Grade)

Bandit and pip-audit are necessary but not sufficient for banking software. The full security pipeline:

### 8.1 CI Security Controls

```yaml
# Extended CI security pipeline — every PR, no exceptions
steps:
  # Code-level security
  - name: Static Analysis
    run: uv run bandit -r src/cognic/ -ll
  - name: Dependency Audit
    run: uv run pip-audit

  # Secrets scanning (prevent credentials in code)
  - name: Secrets Scan
    run: gitleaks detect --source . --verbose
    # Blocks PR if any secret pattern detected in code or history

  # Container security
  - name: Container Image Scan
    run: trivy image cognic:latest --severity HIGH,CRITICAL --exit-code 1
    # Scans built container for OS-level and library vulnerabilities

  # SBOM generation (Software Bill of Materials)
  - name: Generate SBOM
    run: syft cognic:latest -o spdx-json > sbom.json
    # Required by bank procurement for supply-chain transparency

  # Infrastructure-as-Code scanning
  - name: K8s Manifest Scan
    run: trivy config src/cognic/deployment/kubernetes/ --exit-code 1
    # Catches insecure K8s configs (privileged containers, missing limits, etc.)

  # Dockerfile best practices
  - name: Dockerfile Lint
    run: hadolint Dockerfile
```

### 8.2 Dependency Management

- **Pinning policy:** All dependencies pinned to exact versions in `uv.lock`. No floating ranges in production.
- **Update cadence:** Dependency updates reviewed weekly. Security patches applied within 48 hours of disclosure.
- **Approval:** New dependencies require ADR documenting: licence compatibility (must be Apache 2.0/MIT/BSD compatible), maintenance status, security track record.

### 8.3 Artifact Integrity

- **Container image signing:** Images signed with cosign before push to registry. Bank deployment verifies signature.
- **Model weight integrity:** SHA256 checksum for every model artefact in Zarf package. Verified on deployment.
- **SBOM archived:** Every release includes SBOM. Bank procurement can audit full dependency chain.

---

## Part 9 — Ingestion Reliability Controls

The Data Ingestion Layer (Brick 8) must handle real-world operational failures, not just happy-path events.

### 9.1 Controls Per Ingestion Mode

| Control | Webhook | DB Poller | File Drop | Kafka |
|---------|---------|-----------|-----------|-------|
| **Idempotency keys** | Required — deduplicate by event_id in request header | Deduplicate by (table, row_id, updated_at) tuple | Deduplicate by (filename, SHA256, size) tuple | Deduplicate by (topic, partition, offset) |
| **Replay handling** | Webhook replay accepted if idempotency key not seen in last 72 hours | Poller re-reads from last confirmed checkpoint on restart | File re-drop accepted if content hash differs from last processed | Consumer replays from committed offset on restart |
| **Duplicate detection** | Redis SET with TTL (72h) on event_id | PostgreSQL upsert on natural key | Hash-based dedup table | Kafka offset management + dedup window |
| **Poison message quarantine** | Events failing 3x validation → dead-letter queue + alert | Rows failing extraction → quarantine table + alert | Files failing verification → quarantine directory + alert | Messages failing 3x → DLQ topic + alert |
| **Partial failure recovery** | Batch of N events: process individually, quarantine failures, continue rest | Batch of N rows: same pattern | Per-record within file: same pattern | Per-message within batch: same pattern |

### 9.2 Schema Evolution

- **Schema versioning:** Every event carries a `schema_version` field. Ingestion layer routes to version-specific deserialiser.
- **Backward compatibility:** New schema versions must accept old event formats (add fields with defaults, never remove or rename).
- **Forward compatibility:** Old schema handlers gracefully ignore unknown fields.
- **Breaking changes:** Require ADR + coordinated migration plan with bank. Never silently deployed.

### 9.3 Observability

- Dead-letter queue depth tracked as dashboard metric (alert if >0)
- Ingestion throughput per mode tracked (events/second)
- Ingestion latency per mode tracked (time from event receipt to internal processing)
- Schema version distribution tracked (detect old-schema stragglers)

---

## Part 10 — Document Ecosystem

| Document | Purpose | Status |
|----------|---------|--------|
| Cognic Master Strategy v5.0 | Architecture, principles, governance, Digital Workforce | FROZEN |
| Cognic AgentOps Implementation Guide | Build-time operational discipline | Active during build |
| Cognic Future Roadmap (Year 2+) | Growth levers for Month 12+ | Reference |
| **This Development Plan** | Sprint-level execution plan | Active — governs daily work |
| ADR Pack | Implementation decisions | Created during build |
| Brick Completion Docs | Per-brick evidence | Created per brick |
| Evaluation Datasets | Governed accuracy benchmarks | Created during build, versioned |

---

*Document version 1.2 · April 2026*
*Governing strategy: Cognic Master Strategy v5.0 (FROZEN)*
*This plan implements the strategy. It does not change it.*
*ADRs extend implementation details. Strategy principles are immutable.*

*Changes from v1.1 → v1.2 (v5.0 cascade + consistency patch):*
*— Governing strategy updated from v4.4 to v5.0.*
*— Brick 9: AgentIdentityRecord + DecisionOptionsResponse schemas. Workforce ID in Langfuse traces.*
*— Brick 14: CognicDecisionRecord extended with workforce identity and decision option tracking fields.*
*— Brick 36: Quarterly performance reviews, authority compliance monitoring, per-agent KPI tracking.*
*— Brick 38: Workforce registry API + executive decision board data endpoint.*
*— Brick 39: Split Wave 1 scope (basic identity view) vs Wave 2 hardening (org chart, profiles, decision board UI).*
*— Brick 41: Performance review template + AI workforce onboarding guide.*
*— Gates: Week 2, Phase 4, and Final gates updated with workforce primitives verification.*
*— CI: added dedicated critical-module coverage step enforcing 95%+ per file (was policy-only, now enforced).*
*— CI: added explicit Docker build step before trivy/syft. Dockerfile added to repo tree.*
*— Brick completion: split into "Ready for Gate" and "Released to Main" — resolves gate/merge circularity.*
*— Week 12 rollback: changed from Argo CD (Wave 2) to Docker Compose image/tag rollback (MVP-appropriate).*
*— Phase-gate rule: softened to allow approved parallel prep. No next-phase code before gate passes.*
*— Staffing assumptions: CTO + AI Lead full-time, Compliance Advisor part-time, Claude Code as implementation engine. 18-24 weeks without Claude Code.*
*— Phase 1 description: reworded to match actual Week 2 scope (BaseAgent + schemas, not "no agent code").*
*— Incident rollback protocol: made environment-aware (MVP: Compose; Production: Argo CD).*
*— CI coverage precision: critical-module coverage now enforced per file via `coverage-critical.json` + `scripts/check_critical_coverage.py`, not just as a combined threshold.*
*— Reviewer approvals aligned: feature → staging requires 1 reviewer; staging → main requires 2 reviewers. Brick readiness/release checklists now match Git workflow.*
*— Repo tree completed: `docs/incidents/` and `scripts/check_critical_coverage.py` added for operational/documentation consistency.*

*Changes from v1.0 → v1.1:*
*— Git workflow: fixed CD contradiction. Staging deploys from staging branch, production from main. Linear promotion chain documented.*
*— Raw SQL: absolute ban softened. Exceptions permitted with ADR + tests + parameterisation + review.*
*— Test coverage: tiered. 95%+ for critical control modules (audit, guardrails, consent, degradation, escalation). 80% global floor.*
*— Non-functional criteria: Part 6 added with numerical gates for latency, throughput, storage, backup/restore, RTO/RPO, audit performance, cost budgets.*
*— Incident operations: Part 7 added with severity model (SEV-1 to SEV-4), on-call ownership, response SLAs, rollback protocol, communication runbooks, 48-hour RCA deadline.*
*— Security pipeline: Part 8 added. Extended beyond bandit/pip-audit to include gitleaks (secrets), trivy (containers + K8s), syft (SBOM), hadolint (Dockerfile), cosign (image signing), dependency pinning policy.*
*— Ingestion reliability: Part 9 added. Idempotency keys, replay handling, duplicate detection, poison-message quarantine, partial-failure recovery, schema versioning, DLQ monitoring per ingestion mode.*
*— Reviewer Lite: added to Week 10 with explicit acceptance criteria (case list, evidence view, approve/correct/reject, reason codes, SLA indicator). Wave 1 must have a named review surface.*
*— Phase 4 gate: Reviewer Lite + non-functional spot-checks added.*
*— Final gate: expanded to 4 categories (functional, non-functional, security, operational) with specific evidence requirements.*
