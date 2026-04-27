# Cognic — AgentOps Implementation Guide
## Reference Document for Engineering Team · March 2026

> ⚠️ **LEGACY CONTEXT FOR THIS REPO. BUILD_PLAN.md WINS ON CONFLICT.** This guide describes AgentOps practices in the parent `bmzee/cognic` monorepo and references in-repo agents, in-repo tools, and AI Governance Agent as a product agent. In Cognic AgentOS (this repo), agents/tools/skills are external plugin packs; AI Governance is split into deterministic platform monitor + separate LLM-driven reporting pack (see [`ARCHITECTURE.md §8`](ARCHITECTURE.md)). Sprint-level execution follows [`BUILD_PLAN.md`](../BUILD_PLAN.md).

> **Purpose:** This document defines how AgentOps practices are implemented within AgentOS during the build sequence. It is NOT a strategy document — the Cognic Master Strategy v5.0 is frozen and contains all architectural decisions. This guide maps AgentOps disciplines to existing v5.0 components and specifies implementation details to address during relevant bricks.
>
> **Rule:** No brick is complete unless its AgentOps checklist items are addressed.

---

## What AgentOps Means for Cognic

AgentOps is the operational discipline for lifecycle management of AI agents — development, testing, monitoring, feedback, and governance. It extends DevOps and MLOps principles to agentic systems where behavior is non-deterministic and requires continuous observability.

Cognic does not need a separate AgentOps product or platform. AgentOS already contains every AgentOps ingredient. This guide ensures nothing is skipped during implementation.

**One-line summary for CTO conversations:**
> "AgentOS includes an AgentOps operating layer for lifecycle management of agents, skills, retrieval systems, and ML tools across instrumentation, evaluation, feedback, governance, and runtime operations."

---

## AgentOps Capability Map — What Exists in v5.0

| AgentOps Discipline | v5.0 Component | Brick(s) | Status |
|---|---|---|---|
| **Instrumentation** | OpenTelemetry semantic conventions | Brick 2, 18 | Architecture defined, implement during build |
| **Tracing** | Langfuse self-hosted (per-agent traces) | Brick 2, 18 | Architecture defined |
| **Metrics** | Langfuse for LLM metrics. Prometheus/Grafana for platform infra metrics (deploy when needed, not mandatory in Week 1) | Brick 2 | Architecture defined |
| **LLM Evaluation** | Langfuse LLM-as-a-Judge, governed eval datasets | Brick 32, 34, 60 | Architecture defined |
| **ML Model Governance** | MLflow Model Registry, drift monitoring, bias review | Brick 58, 60 | Architecture defined (Section 5.4D) |
| **Accuracy Monitoring** | Auto-degradation monitor (rolling 7-day accuracy) | Brick 19 | Architecture defined |
| **Feedback Capture** | Decision history store (CognicDecisionRecord) | Brick 14 | Architecture defined |
| **Human Review (Wave 1)** | Reviewer Lite — case list, evidence view, approve/correct/reject, reason codes, SLA indicator | Brick 39b, Week 10 | Planned in build (Week 10) |
| **Human Review (Wave 2)** | Full Reviewer Workbench — case queue, diff view, examiner export, prioritisation | Brick 61 | Architecture defined (Wave 2) |
| **Guardrails** | Input/output guardrails runtime, PII redaction | Brick 16 | Architecture defined |
| **Compliance Checking** | Compliance checker agent (skeptical evaluator) | Brick 12 | Architecture defined |
| **Agent Governance** | AI Governance Agent (monitors all agents) | Brick 36 | Architecture defined |
| **Audit Trail** | Audit engine (tamper-evident, examiner-accessible) | Brick 15 | Architecture defined |
| **Model Promotion** | MLflow aliases, shadow deployment, quarterly eval | Brick 60 | Architecture defined |
| **Enterprise Control Plane** | Argo CD, SPIFFE/SPIRE, OPA Gatekeeper | Brick 62 | Architecture defined (Wave 2) |
| **Cost Tracking** | Langfuse token counts + LiteLLM cost metadata | Brick 2, 18 | Planned in build (Week 1 cost callback, Week 3-4 dashboard) |
| **Cross-Agent Trace Correlation** | LangGraph checkpointing + Langfuse parent-child | Brick 10, 18 | Planned in build (Week 3 workflow_trace_id) |
| **Agent Lifecycle Versioning** | MLflow for models, but agent configs not versioned as unit | Brick 60 | Deferred — address at Month 12+ |

---

## Implementation Details — Address During Build

### During Brick 2 (Langfuse Self-Hosted) — Week 1

**Configure from day one:**
- Enable per-trace cost tracking: Langfuse captures token counts automatically, but configure LiteLLM's cost callback to attach USD/PKR cost metadata to every trace
- Set up trace hierarchy: define `workflow_trace_id` as a top-level trace attribute so every agent/skill/tool call within a workflow links to a single parent trace
- Create dashboard views: agent accuracy trend, cost per agent per day, latency percentiles, guardrail activation rate, escalation frequency
- These are Langfuse configuration items, not new code

**Langfuse dashboard metrics to configure:**

```
# Core AgentOps metrics — configure in Langfuse dashboard
agent_accuracy_7d:        rolling 7-day accuracy per agent (feeds auto-degradation)
agent_cost_per_session:   total token cost (USD/PKR) per agent invocation
agent_latency_p50_p95:    response time percentiles per agent
guardrail_activation_rate: % of calls where input/output guardrails fired
escalation_rate:          % of calls escalated to human
correction_rate:          % of human-reviewed outputs where human corrected
checker_rejection_rate:   % of executor outputs rejected by compliance checker
tool_call_frequency:      which tools/skills each agent calls most often
model_tier_distribution:  % of calls routed to Tier 1 vs Tier 2 vs Tier 3

# Digital Workforce metrics (v5.0) — configure alongside core metrics
recommendation_follow_rate: % of decisions where human chose agent's recommended option
authority_compliance_rate:  % of agent actions within defined authority scope (Part 5A.3)
# Note: recommendation_follow_rate becomes meaningful only once DecisionOptionsResponse
# workflows and human option-selection are live (Executive Decision Board, Wave 2 hardening).
# authority_compliance_rate becomes meaningful once authority levels are configured per agent.
# Configure both dashboards from day one; expect meaningful data from Wave 2 onward.
```

**Agent identity in trace metadata (v5.0):**
- Every Langfuse trace must include the agent's workforce registry ID (`COG-AI-001`) as a top-level metadata field
- This is defined by `AgentIdentityRecord` (strategy Part 5A.1) and implemented in Brick 9 (BaseAgent)
- Configure Langfuse to index `agent_workforce_id` so traces are filterable by agent identity
- This enables the quarterly performance review (Part 5A.6) to pull KPI data per agent identity, not just per agent class

### During Brick 10 (LangGraph Harness) — Week 3

**Implement cross-agent trace correlation:**
- Every LangGraph graph execution gets a unique `workflow_trace_id`
- Pass this ID through all agent/skill/tool calls within the workflow
- Langfuse parent-child trace linking: the graph is the parent trace, each node (agent/skill/tool) is a child span
- This enables "show full trace" in the Reviewer Workbench — a compliance officer clicks one button and sees every step from data ingestion to SAR draft

```python
# Example: workflow_trace_id propagation
import uuid
from langfuse import Langfuse

langfuse = Langfuse()

# Top-level workflow trace
workflow_trace = langfuse.trace(
    name="aml_investigation_workflow",
    id=str(uuid.uuid4()),
    metadata={"workflow_type": "aml_investigation", "customer_id": customer_id}
)

# Each agent/skill/tool call becomes a child span
policy_span = workflow_trace.span(name="search_circulars")
intel_span = workflow_trace.span(name="customer_intelligence_assembly")
aml_span = workflow_trace.span(name="aml_investigation_agent")
framl_span = workflow_trace.span(name="framl_signal_correlation")
```

### During Brick 18 (Langfuse Integration Layer) — Week 3-4

**Complete the AgentOps observability layer:**
- Auto-trace every Pydantic AI agent call (Langfuse decorator)
- Register custom scorers (SBP circular scorer, Shariah compliance scorer, etc.)
- Configure LLM-as-a-Judge evaluation pipeline
- Enable prompt versioning for A/B testing
- Wire cost tracking from LiteLLM into Langfuse trace metadata
- Verify that every agent, skill, and tool call appears in the trace hierarchy

### During Brick 19 (Auto-Degradation Monitor) — Week 3-4

**Implement the automated circuit breaker:**
- Query Langfuse for rolling 7-day accuracy per agent
- If accuracy drops below configured floor → degrade agent state automatically
- Alert compliance officer + Cognic engineering
- Log degradation event in audit trail
- This is the AgentOps "monitoring → feedback → governance" loop in action

### ⚠️ CRITICAL: During Brick 48 (Temporal Deployment) — Wave 2

**The Temporal Trap — trace context will break if you miss this.**

Temporal workflows run asynchronously, cross process boundaries, and can sleep for hours or days (e.g., the overnight KYC batch, STR 7-day approval wait). When Temporal suspends and resumes a workflow, standard Python context variables — which OpenTelemetry and Langfuse rely on for trace propagation — are lost. The `workflow_trace_id` you carefully wired in Brick 10 will silently fragment into disconnected, orphaned spans the moment a workflow hits a Temporal boundary.

**The fix: Temporal Interceptors for trace context serialization.**

You must implement custom Temporal Interceptors that serialize the Langfuse/OpenTelemetry trace context into Temporal workflow headers on suspension, and deserialize them on resumption. This is not optional — without it, your entire Wave 2+ trace hierarchy is broken.

```python
# Temporal Interceptor for Langfuse trace context propagation
from temporalio.worker import Interceptor
from temporalio.workflow import WorkflowInboundInterceptor, WorkflowOutboundInterceptor
from temporalio.activity import ActivityInboundInterceptor
import json

class LangfuseTraceInterceptor(Interceptor):
    """
    Serializes Langfuse trace context (workflow_trace_id, parent_span_id)
    into Temporal workflow/activity headers so trace hierarchy survives
    Temporal's suspend/resume boundaries.
    """

    def intercept_activity(self, next):
        return LangfuseActivityInbound(next)

    def workflow_interceptor_class(self, input):
        return LangfuseWorkflowInbound


class LangfuseActivityInbound(ActivityInboundInterceptor):
    async def execute_activity(self, input):
        # Deserialize trace context from Temporal headers
        trace_context = json.loads(
            input.headers.get("langfuse_trace_context", "{}")
        )
        workflow_trace_id = trace_context.get("workflow_trace_id")
        parent_span_id = trace_context.get("parent_span_id")

        # Restore Langfuse trace context before activity execution
        # (actual Langfuse API calls depend on your wrapper implementation)
        with langfuse_context(workflow_trace_id, parent_span_id):
            return await super().execute_activity(input)


# Register interceptor when creating Temporal worker
worker = Worker(
    client=temporal_client,
    task_queue="cognic-workflows",
    workflows=[KYCExpiryWorkflow, STRApprovalWorkflow],
    activities=[...],
    interceptors=[LangfuseTraceInterceptor()],  # <-- DO NOT FORGET THIS
)
```

**Test this explicitly:** Run a workflow that sleeps for 5 minutes, resumes, and completes. Verify in Langfuse that the entire workflow appears as one continuous trace with correct parent-child span hierarchy — not as two disconnected traces. If the spans are disconnected, the interceptor is not working.

**Release rule (non-negotiable):** No Wave 2+ Temporal workflow may be promoted to production unless trace continuity is verified across sleep/resume boundaries, activity boundaries, and retry/restart paths. This is audit-critical — a compliance officer must be able to click "show full trace" on any Temporal workflow and see the complete chain. Broken traces are a release blocker, not a known issue.

**Affected workflows in Wave 2+:**
- `kyc_expiry_check_skill` — overnight batch, runs for hours
- `str_package_assembly_skill` → STR approval wait (up to 7 working days)
- `customer_intelligence_assembly_skill` — overnight batch across full customer base
- `capital_adequacy_daily_skill` — daily batch
- Any future Temporal workflow that spans multiple execution windows

### During Brick 58 (ML Model Tool Infrastructure) — Wave 2

**Extend AgentOps monitoring to ML tools:**
- MLflow Model Registry tracks model versions, aliases, promotion status
- Configure drift monitoring (PSI for input features, accuracy on holdout data)
- Champion-challenger shadow testing before any model promotion
- Bias review results stored alongside model version in MLflow
- Auto-rollback if production model accuracy drops below floor
- All ML model governance requirements from Section 5.4D implemented here

### During Brick 60 (Model Evaluation Pipeline) — Wave 2

**Governed evaluation datasets:**
- Every evaluation dataset versioned in MLflow alongside the model it evaluates
- Dataset owner documented (compliance advisor for regulatory agents, model scientist for ML tools)
- Changes to evaluation data require same approval as changes to model code
- Evaluation results logged per-run with dataset version used
- No model promotion without documented evaluation results on current dataset version

---

## Agent Lifecycle States — Reference

```
Agent Lifecycle (AgentOps view):

  DEVELOPMENT
    └── Engineer builds agent with Pydantic AI + LangGraph
        Sprint contract defined, tools/skills allowlisted
        Langfuse tracing enabled from first test

  EVALUATION (State 0 — Pre-Pilot)
    └── Agent runs against governed evaluation dataset
        Must pass accuracy gate before any bank exposure
        All traces logged, cost tracked, latency measured

  PILOT (State 1 — Assisted, 100% Human Review)
    └── Agent outputs reviewed by compliance officer before delivery
        Every decision logged in decision history store
        Corrections captured with reason codes
        Auto-degradation monitor active

  PRODUCTION (State 2 — Assisted, Sampled Review)
    └── Sampling-based human review (configurable %)
        Rolling 7-day accuracy tracked
        If accuracy < floor → auto-degrade to State 1
        Cost-per-session trending visible in dashboard

  AUTONOMOUS (State 3 — Automated, Exception Review)
    └── Human reviews only flagged/escalated outputs
        Full audit trail maintained
        AI Governance Agent monitors continuously
        Quarterly model evaluation against challengers

  RETIREMENT (when agent version is superseded)
    └── Decision history preserved (never deleted)
        Evaluation datasets preserved with version tag
        Model registry entry marked deprecated
        New version's traces link to predecessor for continuity
        Old agent config archived, not deleted
```

---

## Pre-Brick AgentOps Checklist

Before marking any brick as complete, verify the applicable items below. Not every item applies to every brick — infrastructure bricks (1-8) will have fewer applicable items than agent bricks (31-36). Check what applies, skip what doesn't, but never skip an applicable item.

```
Always applicable:
□ Audit engine captures complete trace for examiner access (if brick touches auditable paths)

If the brick introduces or modifies any LLM path:
□ Every LLM call traced to Langfuse with full input/output/cost
□ Every tool/skill call appears as a child span in the workflow trace
□ Cost-per-session metric populating in dashboard

If the brick introduces or modifies agent behavior:
□ Guardrails tested and firing correctly (input + output)
□ Accuracy scorer configured with governed evaluation dataset
□ Escalation triggers tested with edge cases
□ Decision history records written for every agent output
□ Auto-degradation threshold configured and tested

If the brick introduces or modifies ML model tool behavior:
□ Drift monitoring, bias review, rollback criteria documented
```

---

## AgentOps Ownership Cadence

AgentOps dashboards and governance actions need clear owners and a regular review rhythm. Without this, dashboards become decoration and degradation alerts become noise.

**Weekly AgentOps Review (30 minutes):**

| Attendee | Role |
|----------|------|
| CTO / AI Engineering Lead | Owns platform health, reviews cost trends and latency |
| AI Engineering Lead | Owns agent accuracy, reviews drift alerts and trace anomalies |
| Compliance Advisor | Reviews accuracy gate status, validates evaluation dataset relevance |
| Model Scientist (Wave 2+) | Reviews ML model drift, champion-challenger results, bias metrics |

**Agenda:**
1. Agent accuracy dashboard — any agent trending toward degradation floor?
2. Cost-per-session trends — any unexpected spike? Model tier routing efficient?
3. Guardrail activation rate — rising rate may indicate prompt drift or adversarial inputs
4. Escalation/correction rate — rising corrections signal model or retrieval degradation
5. Open degradation events — any agents currently in degraded state? Root cause status?
6. ML model drift alerts (Wave 2+) — any models approaching PSI threshold?

**Decision authority:**

| Decision | Who Approves |
|----------|-------------|
| Agent degradation (auto-triggered) | Automatic — AI Governance Agent. CTO reviews within 24 hours |
| Agent promotion (State 1 → State 2 → State 3) | CTO + Compliance Advisor jointly |
| Model promotion (challenger → champion) | Model Scientist + Compliance Advisor. CTO notified |
| Model rollback (auto-triggered) | Automatic — MLflow. Model Scientist investigates within 48 hours |
| Evaluation dataset changes | Dataset owner (compliance advisor or model scientist) + one peer reviewer |
| Guardrail threshold changes | CTO + Compliance Advisor. Logged in audit trail |
| Agent retirement (v1 → v2 transition) | CTO. Decision history + eval datasets preserved per lifecycle guide |

**Quarterly AgentOps Review (2 hours):**

| Attendee | Role |
|----------|------|
| CEO / Domain Lead | Strategic alignment — are the right agents being prioritised? |
| CTO | Platform health, technical debt, scaling needs |
| Compliance Advisor | Regulatory alignment, SBP examination readiness |
| Model Scientist | Model evaluation results, challenger model assessment |

**Agenda:**
1. Quarterly model evaluation results — any challenger beating current champion by >3%?
2. Decision history analysis — what are agents getting wrong? Patterns in corrections?
3. Evaluation dataset health — still representative? Need new edge cases?
4. Cost trajectory — sustainable at current pricing? Tier routing optimised?
5. Roadmap alignment — which Wave 2/3 agents are next? AgentOps readiness for each?
6. **Agent performance reviews (v5.0)** — generate formal quarterly review per agent using the template in strategy Part 5A.6. Review KPIs (accuracy, correction rate, recommendation follow-rate, cost, latency, escalation discipline, compliance adherence, citation accuracy). Determine state promotion eligibility. Record evaluation in decision history alongside agent outputs.

---

## Environment-Specific Thresholds

Pilot, UAT, and production environments have different operational requirements. Applying production-grade degradation thresholds to a pilot environment will trigger false alerts constantly. Applying pilot-grade thresholds to production will miss real issues.

**Threshold configuration must be environment-specific:**

```yaml
# src/cognic/deployment/thresholds/development.yaml
environment: development
accuracy_degradation_floor: 0.60    # lenient — agents are being tuned
cost_alert_threshold_pkr: null       # no cost alerts in dev
latency_alert_p95_ms: null           # no latency alerts in dev
guardrail_activation_alert: false    # expect frequent guardrail triggers during testing
auto_degrade_enabled: false          # manual degradation only in dev

# src/cognic/deployment/thresholds/pilot.yaml
environment: pilot
accuracy_degradation_floor: 0.80    # tighter than dev, looser than prod
cost_alert_threshold_pkr: 50000     # alert if daily agent cost exceeds PKR 50K
latency_alert_p95_ms: 15000         # 15 seconds — acceptable for pilot
guardrail_activation_alert: true    # monitor but don't page
auto_degrade_enabled: true          # auto-degrade active, but floor is lower
escalation_alert_rate_threshold: 0.40  # alert if >40% of outputs escalate

# src/cognic/deployment/thresholds/uat.yaml
environment: uat
accuracy_degradation_floor: 0.85    # matches production accuracy gate
cost_alert_threshold_pkr: 30000     # tighter cost monitoring
latency_alert_p95_ms: 10000         # 10 seconds
guardrail_activation_alert: true
auto_degrade_enabled: true
escalation_alert_rate_threshold: 0.30

# src/cognic/deployment/thresholds/production.yaml
environment: production
accuracy_degradation_floor: 0.90    # strict — this is the State 2 floor
cost_alert_threshold_pkr: 20000     # alert if daily agent cost exceeds PKR 20K
latency_alert_p95_ms: 5000          # 5 seconds max for production queries
guardrail_activation_alert: true    # page on-call if activation rate spikes
auto_degrade_enabled: true          # mandatory in production
escalation_alert_rate_threshold: 0.20  # alert if >20% of outputs escalate
ml_drift_psi_threshold: 0.20       # Population Stability Index for ML tools
bias_review_block_deploy: true      # cannot deploy ML model without bias review
```

**Rules:**
- Every agent/ML tool config specifies which threshold file it uses based on deployment environment
- Production thresholds are the strictest — no exceptions
- Pilot thresholds are intentionally looser to allow tuning without constant alerts
- UAT mirrors production thresholds to catch issues before go-live
- Development has minimal alerting — engineers need room to experiment
- Threshold values are reviewed quarterly during the AgentOps quarterly review
- Changes to production thresholds require CTO + Compliance Advisor approval

---

## What This Guide Does NOT Do

- Does NOT change the v5.0 master strategy (frozen)
- Does NOT add new bricks, agents, skills, or tools
- Does NOT introduce new architectural components
- Does NOT define new commercial products
- DOES ensure that existing v5.0 components are implemented with full AgentOps discipline
- DOES provide implementation-level detail that ADRs can reference

---

*Filed: March 2026 · Updated April 2026 (v5.0 cascade)*
*Owner: CTO / AI Engineering Lead*
*Reference during: Brick 2, 10, 18, 19, 32, 34, 58, 60, 61, 62 build*
*This document supports the Cognic Master Strategy v5.0 without modifying it.*

*v5.0 update: added agent workforce ID (`agent_workforce_id`) as required Langfuse trace metadata field, added `recommendation_follow_rate` and `authority_compliance_rate` to dashboard metrics with timing note, added formal agent performance review (Part 5A.6) to quarterly review agenda. Synchronisation patch: Reviewer Lite added to capability map (Wave 1 / Brick 39b), Prometheus/Grafana wording softened to match EDP, threshold paths aligned to `src/cognic/deployment/thresholds/`, pre-brick checklist conditionalized, Gap statuses updated to Planned where EDP now covers them, Temporal release rule strengthened to non-negotiable gate.*
