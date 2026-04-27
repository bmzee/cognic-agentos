# Cognic — Future Roadmap
## Updated April 2026 (v5.0 sync) · Near-Term Wave 2 Expansion + Growth Levers

> ⚠️ **LEGACY CONTEXT FOR THIS REPO. BUILD_PLAN.md + ROADMAP.md WIN ON CONFLICT.** This is the parent monorepo's product roadmap. Engineering execution in this repo follows [`docs/ROADMAP.md`](../ROADMAP.md) (phase-level) + [`docs/BUILD_PLAN.md`](../BUILD_PLAN.md) (sprint-level).

> **Purpose:** This document captures planned expansion items beyond the 12-week MVP. It is split into two sections: **Near-Term Wave 2 Expansion** (Month 5-12, planned implementation) and **Growth Levers** (Year 2+, conditional on prerequisites). Items absorbed into v5.0 strategy or EDP v1.2 are noted at the end.

---

## Section A — Near-Term Wave 2 Expansion (Month 5-12)

These items are planned for implementation during Wave 2. They have defined scope, clear prerequisites, and integration points with the existing architecture.

### A1. Regulatory Control Map (Month 6-8)

Visual overlay in the bank portal mapping the bank's internal controls against SBP/FMU/AAOIFI requirements in a graph view. Shows gaps, coverage, and compliance status at a glance. Powered by RegIntel and PolicyQA output data.

This is a frontend reporting view, not a new agent or skill. The data already exists from PolicyQA and RegIntel outputs. Lowest-risk expansion item — consider pulling forward if demo impact justifies it.

**Prerequisite:** PolicyQA and RegIntel in production with sufficient circular coverage.

### A2. Digital Workforce Full Experience (Month 5-8)

v5.0 defines the Digital Workforce framework. Wave 1 implements primitives (schemas, data models, basic portal view). Wave 2 hardens the full experience:

| Component | Wave 1 Primitive | Wave 2 Hardening |
|-----------|-----------------|-----------------|
| Agent identity | AgentIdentityRecord schema, workforce ID in traces | Full org-chart visualisation with reporting lines |
| Decision options | DecisionOptionsResponse schema, checker validation | Executive Decision Board: pending decisions, option selection, decision log |
| KPI tracking | Langfuse metrics, basic dashboards | Detailed agent profile pages with KPI history, evaluation records |
| Performance reviews | Template in Adoption Kit, data collection | Auto-generated quarterly reviews from AI Governance Agent |
| Authority matrix | Authority level field, compliance monitoring | Configurable authority scopes per bank with governance UI |

**Prerequisite:** Wave 1 completed with workforce primitives verified at Phase 5 gate.

### A3. Spreadsheet Intelligence Toolkit (Month 6-8)

Layer A tools for Excel/CSV parsing, summary statistics, anomaly detection, period comparison, pivot/aggregation, schema validation. Layer B skill orchestrates the pipeline. Domain agents receive structured output and produce `DecisionOptionsResponse` grounded in bank data.

Why Wave 2: Wave 1 agents work with SBP circulars and mock data. Spreadsheet analysis becomes relevant when real bank data flows through CBS adapters (Brick 44-47).

**Effort (enterprise-grade, not prototype):** Core parsing tools: 1-2 weeks (must handle formula cells, merged ranges, multi-sheet workbooks, malformed files, encoding edge cases). Skill orchestration + lineage tracking (cell/range/sheet provenance for audit): 1 week. Agent integration + prompt tuning: 3-5 days. Testing against messy real bank spreadsheets (not clean samples): 1 week. Permissions and auditability layer (who uploaded what, what was extracted, consent checks): 3-5 days. **Realistic total: 4-6 weeks**, not days. The concept is simple; enterprise-grade reliability against real banking files is not.

### A4. VLM Document Understanding — Active Benchmark Track (Month 8-10)

**Latest intelligence (April 2026):** Qwen3-VL now supports 32 languages (up from 10 in Qwen2-VL), runs on Ollama (already in Cognic's dev stack), and offers dense variants from 2B to 32B suitable for sovereign deployment. Document parsing outputs structured HTML/JSON with per-element bounding boxes. A dedicated OCR model (qwen-vl-ocr) is available for high-precision text extraction with coordinate output. The 7B dense variant fits Tier 1 hardware constraints.

**What changed since v4.4:** This was previously a passive "evaluate when models mature" item. Qwen3-VL's 32-language OCR expansion, Ollama compatibility, and structured document parsing make it a viable evaluation candidate now — not a distant future possibility. However, no published benchmarks exist for Urdu banking documents. Character-level accuracy is strong on tested languages but unverified for Nastaliq script. Latency remains a concern — Qwen3-VL is accurate but slower than specialised OCR pipelines on enterprise workloads.

**Wave 2 action plan (active, not watchlist):**

1. **Build Urdu banking benchmark dataset** during Wave 2 from real documents (with bank permission). Target: 200+ documents across LCs, property papers, CNICs, financial statements, court orders, mixed Urdu/English forms.
2. **Benchmark Qwen3-VL-7B** against current Brick 63 baseline (PaddleOCR + LLM post-correction) on this dataset.
3. **Evaluation criteria:** (a) Urdu character accuracy >95%, (b) table extraction >90%, (c) mixed Urdu/English layout detection >90%, (d) latency p95 <10s per page on Tier 1 hardware.
4. **Go/no-go decision at Month 10:** If benchmarks met → migrate Brick 63 to VLM with OCR as fallback. If not met → retain current pipeline, re-evaluate with next model generation.
5. **Also evaluate:** Mistral OCR (strong layout understanding, fastest latency) and DeepSeek-OCR (speed-optimised but weaker accuracy) as alternative candidates.

**Ownership:**
- **Benchmark dataset:** AI Engineering Lead builds dataset with bank compliance advisor sourcing documents (requires bank permission and data handling agreement)
- **Benchmark execution:** AI Engineering Lead runs evaluation, documents results in ADR
- **Go/no-go decision:** CTO + AI Engineering Lead jointly, with compliance advisor reviewing any accuracy trade-offs on regulated document types (CNICs, court orders, SBP circulars)
- **This is an AI-engineering-owned workstream**, not a general product initiative

### A5. ISO 42001 — Year 1 Readiness Program (Start Month 6)

**Latest intelligence (April 2026):** ISO 42001 is now mainstream and certifiable. Microsoft 365 Copilot, Google Cloud, and Miro are certified. BSI is the first UKAS-accredited certification body. ISO/IEC 42006:2025 (requirements for certification bodies) has been published. Integrated ISO 27001 + ISO 42001 implementation reduces total effort by 35-45% versus sequential standalone engagements. The EU AI Act (fully applicable August 2026) explicitly encourages ISO 42001 alignment.

**This is a Year 1 readiness program, not just a future certification milestone:**

**Month 6-12 (lightweight readiness — not a certification project):**

Keep this deliberately lean. Wave 2 engineering is the priority — the readiness program runs alongside it, not in competition with it. Specifically:

- Map existing Cognic controls to ISO 42001 Annex A control objectives (AI Governance Agent, accuracy gates, decision history, audit engine, guardrails, consent ledger, auto-degradation, evaluation datasets, AgentOps cadence, Digital Workforce identity framework) — this is a document, not a project
- Identify gaps between current implementation and certification requirements — a spreadsheet, not a workstream
- Begin evidence structure: decide where AI impact assessments, risk treatment plans, and AI system inventory will live in the repo — folder structure and templates, not heavy documentation
- Engage a pre-assessment consultant (BSI or DNV) for a 1-2 day gap analysis — not a multi-month engagement

The goal at Month 12 is: "we know exactly what gaps remain and have a plan to close them during the ISO 27001 + 42001 integrated audit." Not: "we've spent 6 months on compliance paperwork while Wave 2 slipped."

**Month 12-18 (ISO 27001 certification):**
- Formal ISO 27001 audit and certification
- Establishes the management system framework that ISO 42001 extends

**Month 18-24 (ISO 42001 certification):**
- Integrated audit leveraging shared management system (35-45% effort reduction)
- Formal ISO 42001 certification

**Immediate sales use (now):** "Architecture designed for ISO 42001 compliance from Day 1. Readiness program begins at Month 6. Certification planned for Month 18-24." Most Pakistani IT companies don't know ISO 42001 exists. Microsoft and Google are certified — Cognic is designing for it before first deployment.

### A6. SBP Regulatory Sandbox — Second Cohort Preparation

**Workstream type: Business/regulatory — not engineering backlog.** This is owned by the CEO/Domain Lead, not the engineering team. It does not compete with Wave 2 delivery for engineering capacity. Engineering's only contribution is providing accuracy evidence and demo materials from the Wave 1 gate.

**Latest intelligence (April 2026):** SBP announced first cohort shortlist in January 2026 — 6 firms across Open Banking (Neem, Digi Khata, Swich Retail), Remote Merchant Onboarding (Bank of Punjab), and Inward Remittances (Barq Fintech, Taptap Send + UBL). First cohort tests for up to 6 months. The sandbox framework explicitly mentions "RegTech solutions" and "AI-based credit scoring" as potential future themes.

**Cognic action:**
- Monitor SBP announcements for second cohort theme announcement (expected H2 2026)
- If themes include AI/RegTech/compliance technology: submit application within 2 weeks
- Prepare application materials during Wave 2 (Month 6-8) — don't wait for announcement
- Lead with Digital Workforce positioning: "We manage AI the way banks manage employees — with identity, reporting lines, KPIs, and performance reviews"
- Include PolicyQA + RegIntel accuracy evidence from Wave 1 demo gate

---

## Section B — Growth Levers (Year 2+)

These items require significant prerequisites and are not planned for immediate implementation.

### B1. Outcome-Based Pricing + ROI Engine (Month 12-18)

"Cognic ROI Simulator" dashboard. Pricing tranche with 20% tied to measured outcomes.

**Prerequisite:** 6+ months live production data at 1+ bank.

### B2. Constrained Configuration UI (Month 18+)

Visual configuration for bank compliance teams. Constrained, audited, role-gated.

**Prerequisite:** 3+ banks live, compliance teams using Reviewer Workbench.

### B3. Confidential Computing Deployment Option

Optional confidential compute (Intel TDX / NVIDIA Confidential GPUs / AMD SEV-SNP). "Sovereign-plus" narrative.

**Effort:** Small but non-zero — requires deployment configuration changes, attestation verification setup, key management integration, and validation testing. Budget 1-2 weeks as best case; actual effort depends on target infrastructure, attestation flow complexity, and bank security documentation requirements. Could extend to 3-4 weeks for a bank with strict security review processes.

**Prerequisite:** Tier 1 bank or MENA CTO explicitly requesting it.

### B4. Patent Filings (After Bricks 75-77)

Provisional patents on typology screening, FRAML correlation, federated learning, Customer Intelligence privacy framework. Budget: ~PKR 200-500K per filing.

### B5. Connector Marketplace + Partner Program (Month 12-18)

SI partner program for certified CBS connectors. Kills "integration risk" objection.

**Prerequisite:** First 2-3 CBS connectors proven in production.

### B6. Big4 Co-Selling Alliance (Month 12-18)

Formal co-sell with PwC/EY/KPMG/Deloitte Pakistan/MENA practices.

**Prerequisite:** Working product at 1+ bank + SBP sandbox participation.

### B7. Agent Lifecycle Versioning (Month 12+) — HIGH-PRIORITY FUTURE CONTROL ITEM

Agent configuration (model + prompt + tools + guardrails + eval dataset) versioned as a managed unit. v5.0 AgentIdentityRecord provides the identity anchor.

**Why high-priority:** This becomes a real control problem faster than it appears. Once you have v1 and v2 of an agent, multiple prompt revisions, evolving guardrails, and evaluation dataset updates, the lack of configuration-as-a-unit versioning creates audit gaps. Which version of PolicyQA produced this decision record? Which guardrails were active? Which eval dataset validated it?

**Watch trigger:** Begin active planning the moment any agent enters its second major version in production. Do not wait for Month 12 if this happens earlier.

### B8. AI-Directed Workflow Prioritisation (Month 18+)

Supervisory authority level: agents route tasks to humans under governed scope. Task routing only — not HR authority.

**Prerequisite:** 2+ banks live, governance committee approval, Temporal deployed.

### B9. MENA Usage-Based Pricing (Month 24+)

Per-transaction or consumption-based pricing for Gulf banks. Separate from Pakistan annual licence model.

---

## Summary Table

| Item | Section | Impact | Effort | Timing | Status |
|------|---------|--------|--------|--------|--------|
| Regulatory Control Map | A1 | Medium | Low | Month 6-8 | **Wave 2 planned** |
| Digital Workforce hardening | A2 | High | Medium | Month 5-8 | **Wave 2 planned** |
| Spreadsheet Intelligence | A3 | Medium | Medium (4-6 wks) | Month 6-8 | **Wave 2 planned** |
| VLM benchmark track | A4 | Medium | Medium | Month 8-10 | **Wave 2 active eval** |
| ISO 42001 readiness | A5 | High | Medium | Month 6 start | **Year 1 program** |
| SBP sandbox prep | A6 | High | Low | Ongoing | **Active monitoring** |
| ROI Engine | B1 | Very High | Medium | Month 12-18 | Growth lever |
| Configuration UI | B2 | High | High | Month 18+ | Growth lever |
| Confidential Computing | B3 | Medium | Small-Med (best case) | When required | Growth lever |
| Patent Filings | B4 | High | Low | After Bricks 75-77 | Growth lever |
| Connector Marketplace | B5 | High | Medium | Month 12-18 | Growth lever |
| Big4 Co-Selling | B6 | Very High | Low | Month 12-18 | Growth lever |
| Agent lifecycle versioning | B7 | Medium | Medium | Month 12+ | **High-priority control** |
| AI-directed workflow | B8 | High | High | Month 18+ | Growth lever |
| MENA pricing | B9 | Medium | Low | Month 24+ | Growth lever |

**Items absorbed into active build (no longer in roadmap):**

| Item | Absorbed Into |
|------|-------------|
| AgentOps terminology | v5.0 strategy |
| AgentOps cost tracking | EDP v1.2 Week 1 |
| AgentOps trace correlation | EDP v1.2 Week 3 |

---

*Filed: March 2026 · Restructured April 2026*
*Review: Month 12 or when 2+ banks live, whichever comes first*
*Governs: Cognic Master Strategy v5.0*
*Section A feeds into Wave 2 sprint planning. Section B reviewed when prerequisites are met.*
