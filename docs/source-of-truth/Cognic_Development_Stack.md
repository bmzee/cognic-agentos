# Cognic — Development Stack Reference
## Canonical build-time stack for Claude Code and engineering team · April 2026
## Last refreshed: post-Brick-10 (2026-04-05)

> ⚠️ **STATUS IN THIS REPO (cognic-agentos): HISTORICAL REFERENCE ONLY.**
>
> This document was authored against the parent `bmzee/cognic` monorepo and assumes a `src/cognic/` layout with the portal UI, Layer C agents, tools, and skills bundled inside the same package. **Cognic AgentOS uses `src/cognic_agentos/` and ships AgentOS only** — UI, agents, tools, and skills are separate artefacts/plugin packs.
>
> Where this doc and the AgentOS-specific docs (PROJECT_PLAN.md, ARCHITECTURE.md, BUILD_PLAN.md, the ADRs) disagree, **the AgentOS docs win** per the translation rule in PROJECT_PLAN.md §2.
>
> Specifically reinterpret:
> - "Source layout: `src/cognic/`" → `src/cognic_agentos/` for this repo
> - "portal/ui/" inside this repo → external `cognic-portal-ui` artefact
> - "agents/" inside this repo → external `cognic-agent-<name>` plugin packs
> - "tools/" / "skills/" inside this repo → external `cognic-tool-*` / `cognic-skill-*` plugin packs

> **Purpose:** This file centralizes the development stack assumptions already implied across the approved Cognic document set. It is a convenience reference for Claude Code and engineers. If any conflict arises, the source-of-truth order is: **Master Strategy v5.0 → EDP v1.2 → AgentOps Guide → Future Roadmap → AgentOS-repo docs (PROJECT_PLAN, ARCHITECTURE, ADRs, BUILD_PLAN)**.

---

## 1. Core Development Standards

- **Python version:** 3.12 or 3.13
- **Python version file:** `.python-version`
- **Package / environment manager:** `uv`
- **Project metadata:** `pyproject.toml`
- **Source layout:** `src/cognic/`
- **Dependency lock file:** `uv.lock`
- **Primary OS/runtime assumption for development:** Linux-compatible containerized workflow

### Repo bootstrap expectation
- `uv init`
- `pyproject.toml` as the single source of truth
- strict typing and linting from day one
- Docker-based local environment from day one

---

## 2. Backend and API Stack

- **Primary backend framework:** FastAPI 0.135.x
- **API style:** REST-first, typed request/response schemas
- **Data validation:** Pydantic / PydanticAI schemas
- **Agent runtime base:** PydanticAI
- **Agent orchestration:** LangGraph 1.1.x
- **Durable long-running workflows (Wave 2+):** Temporal

### Key backend design rules
- typed schemas everywhere
- deterministic logic stays in tools/skills, not prompts
- no silent LLM calls
- every externally meaningful action is auditable

---

## 3. Frontend Stack

- **Frontend framework:** React 19.x
- **Portal location:** `src/cognic/portal/ui/`
- **Portal backend:** FastAPI under `src/cognic/portal/api/`

### Wave 1 portal scope
- query UI
- governance dashboard
- audit viewer
- basic workforce identity view
- Reviewer Lite surface

### Wave 2 portal hardening
- org chart
- detailed agent profile pages
- executive decision board
- richer workforce views

---

## 4. Data and Storage Stack

- **Primary relational database:** PostgreSQL 16
- **Vector extension:** `pgvector`
- **ORM:** SQLAlchemy 2.1
- **Migrations:** Alembic 1.18.x
- **Cache / ephemeral state:** Redis 8.x
- **Messaging / queue:** RabbitMQ 4.2.x
- **Secrets management:** HashiCorp Vault 1.21.x

### Database rules
- default path = SQLAlchemy ORM
- raw SQL allowed only with ADR + tests + parameterization + review
- pgvector used for dense retrieval
- PostgreSQL full-text / BM25 used for keyword search

---

## 5. LLM and Inference Stack

- **LLM gateway:** LiteLLM (>=1.83.0)
- **Local/dev inference:** Ollama
- **Staging / production inference:** vLLM and/or SGLang
- **Model routing:** alias-based through LiteLLM
- **Model governance:** MLflow Model Registry aliases and promotion logic

### LLM rules
- no hardcoded checkpoint names in app logic
- route by approved aliases only
- every LLM call must be traced
- structured outputs preferred where possible

---

## 6. Retrieval and Knowledge Stack

- **Dense retrieval:** pgvector
- **Keyword retrieval:** PostgreSQL full-text / BM25
- **Reranker:** cross-encoder reranker service/client
- **Hybrid retrieval orchestration:** dense + BM25 + metadata filters + rerank
- **Citation verification:** required for governed knowledge outputs

### Retrieval rules
- hybrid retrieval is the default for knowledge agents
- citation verifier must validate claims against sources
- metadata filtering is part of retrieval, not prompt-only logic
- Urdu benchmark coverage is required where applicable

---

## 7. Observability, AgentOps, and Governance Stack

- **Tracing / evals / prompt management:** Langfuse (self-hosted)
- **Trace correlation:** workflow-level `workflow_trace_id`
- **Platform metrics:** Prometheus/Grafana when needed for infra-level telemetry
- **Model governance:** MLflow
- **Audit engine:** in-house, tamper-evident
- **Decision history:** in-house append-only store
- **Guardrails:** in-house runtime
- **AI Governance Agent:** in-house monitoring/governance layer

### Required observability outcomes
- full LLM traces
- tool/skill/agent child spans
- cost per session
- accuracy trend
- escalation rate
- correction rate
- checker rejection rate
- workforce identity in trace metadata where applicable

---

## 8. CI/CD and Quality Tooling

### Quality tools
- **Linting:** Ruff
- **Type checking:** mypy (`--strict`)
- **Unit/integration testing:** pytest
- **Coverage:** pytest-cov
- **Static security scan:** Bandit
- **Dependency audit:** pip-audit
- **Secrets scan:** gitleaks
- **Container scan:** Trivy
- **Kubernetes/IaC scan:** Trivy config
- **Dockerfile linting:** hadolint
- **SBOM generation:** Syft
- **Image signing:** Cosign

### Coverage rules
- **Global floor:** 80%
- **Critical control modules:** 95%+
- **Critical coverage enforcement helper:** `coverage-critical.json` + `scripts/check_critical_coverage.py`

### Branching and promotion
- `feature/*` → `staging` → `main`
- staging auto-deploys to staging environment
- production promotion requires approvals and gate pass

---

## 9. Container and Environment Stack

- **Containerization:** Docker
- **Local orchestration:** Docker Compose
- **Production/container platform direction:** Kubernetes / OpenShift-compatible deployment model
- **Air-gapped / packaged deployment path:** Zarf (planned in deployment layout)
- **GitOps / enterprise control plane (Wave 2):** Argo CD + SPIFFE/SPIRE + OPA Gatekeeper

### Environment tiers
- development
- pilot
- UAT
- production

### Threshold configuration path
- `src/cognic/deployment/thresholds/`

---

## 10. Document and File Processing Stack

### Wave 1 / default approach
- PDF extraction via deterministic tools
- OCR-first document processing where needed
- LLM used for correction/synthesis, not blind end-to-end trust

### Wave 2 / evaluation track
- Spreadsheet Intelligence toolkit
- active VLM benchmark track for Urdu/mixed-layout banking documents

### Current document intelligence posture
- keep OCR + LLM as the production default until benchmark evidence justifies VLM migration
- VLM migration requires benchmark pass, not model hype

---

## 11. Digital Workforce Stack Implications

The stack must support the Digital Workforce model defined in strategy v5.0.

### Required primitives
- `AgentIdentityRecord`
- `DecisionOptionsResponse`
- workforce ID in traces
- workforce fields in decision history
- authority level awareness
- KPI tracking support
- Reviewer Lite / later Reviewer Workbench support

### Development implication
Any code touching:
- `base_agent.py`
- `decision_history.py`
- `guardrails.py`
- portal workforce surfaces
must preserve Digital Workforce semantics.

---

## 12. Approved Source-of-Truth Order

If Claude or engineers see conflicting information, follow this order:

1. **Cognic Master Strategy v5.0**
2. **Cognic Enterprise Development Plan v1.2**
3. **Cognic AgentOps Implementation Guide**
4. **Cognic Future Roadmap**
5. local brick files, rules, and skills

This file is a convenience reference, not the governing authority.

---

## 13. Quick Stack Summary for Claude Code

```text
Python 3.12/3.13 via uv
FastAPI 0.135.x backend
React 19.x frontend
PostgreSQL 16 + pgvector
SQLAlchemy 2.1 + Alembic 1.18.x
Redis 8.x
RabbitMQ 4.2.x
Vault 1.21.x
LiteLLM >=1.83.0 gateway
Ollama (dev)
vLLM / SGLang (staging/prod)
Langfuse self-hosted v3
LangGraph 1.1.x orchestration
Temporal in Wave 2+
MLflow model governance
Docker / Compose
Ruff + mypy + pytest + Bandit + pip-audit + gitleaks + Trivy + hadolint + Syft + Cosign
```

---

## 14. Stack Refresh Notes (post-Brick-10)

### Documentation-only changes (no code impact)
These version targets are updated in this reference file. The running code
may still pin lower versions in `pyproject.toml` or `docker-compose.yml` and
will be upgraded in a future compatibility-testing brick.

- Python 3.13 listed as acceptable target alongside 3.12
- FastAPI 0.135.x, SQLAlchemy 2.1, Alembic 1.18.x — version labels added
- LangGraph 1.1.x — version label added
- LiteLLM >=1.83.0 — version label added
- React 19.x — version label added (no frontend code yet)

### Changes requiring later compatibility testing
These components have a **major version bump** from what is currently deployed
in `docker-compose.yml`. Upgrade and test in a dedicated infrastructure brick
before production use.

| Component | Currently deployed | Target | Action needed |
|---|---|---|---|
| Redis | 7-alpine | 8.x | Upgrade Docker image, re-run integration tests |
| RabbitMQ | 3.13-management-alpine | 4.2.x | Upgrade Docker image, re-run pub/sub tests |
| Vault | 1.17 | 1.21.x | Upgrade Docker image, re-run secret read/write tests |

---

*Filed: April 2026*
*Last refreshed: 2026-04-05 post-Brick-10*
*Use: repo reference for Claude Code + engineering onboarding*
*Status: convenience file derived from approved Cognic document set*
