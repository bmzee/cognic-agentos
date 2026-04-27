# Cognic — Master Strategy Document
## Version 5.0 · April 2026 · Digital Workforce Architecture

> ⚠️ **LEGACY CONTEXT FOR THIS REPO. BUILD_PLAN.md WINS ON CONFLICT.**
>
> This document was written against the parent `bmzee/cognic` monorepo and assumes Layer C agents, tools, skills, AI Governance Agent, and portal UI all live inside the same package as the kernel. **Cognic AgentOS (this repo) ships the kernel only**; agents/tools/skills/UI are external plugin packs / artefacts.
>
> Per [`PROJECT_PLAN.md §2`](../PROJECT_PLAN.md) translation rule: when this document conflicts with `PROJECT_PLAN.md`, `BUILD_PLAN.md`, or any ADR in `docs/adrs/`, **the AgentOS-repo doc wins**. The most-frequently-cited translations live in [`ARCHITECTURE.md §8`](ARCHITECTURE.md): AI Governance Agent → deterministic platform monitor + separate LLM-driven reporting pack; Vector default → Qdrant bundled with pgvector as plugin pack; `src/cognic/` → `src/cognic_agentos/`; UI → separate artefact.
>
> Treat this document as **product strategy + investor briefing**, not engineering execution. Engineers should read PROJECT_PLAN → BUILD_PLAN → ADRs first.

> **Purpose:** This is the single source of truth before a line of code is written.
> Every architectural decision, technology choice, and product boundary is locked here.
> Engineers read this first. Investors read this first. The PRD is derived from this.
>
> **Build approach:** Built from scratch. Reference codebases inform design decisions.
> They do not own our architecture or IP.

---

## Part 1 — The Company

### 1.1 What We Are Building

Cognic is a banking intelligence company for South Asia and MENA. We build domain-specific AI agents — each deployed as a governed digital worker within a bank's organisational structure, each a foundational brick toward a single destination: a **Bank Intelligence Platform** that gives bank leadership a complete, real-time picture of their institution and handles routine decisions autonomously across every domain.

Every Cognic agent has an identity, a department, a reporting line, defined authority, measurable KPIs, and a formal performance evaluation — just like any employee. The difference: agents are traceable, auditable, and governable at a level no human workforce can match.

### 1.2 What We Are Not Building

- A generic AI chatbot or copilot
- A cloud-first SaaS product
- A system that replaces bank staff — agents augment capacity as digital colleagues, not headcount substitutes
- An AI with HR-style authority over humans — agents route tasks and prioritise work under human supervisory governance
- A product that sends bank data to any external API
- A CEO Agent (externally — that framing kills sales)
- A product competing with core banking systems (Temenos, Finacle, FLEXCUBE)

### 1.3 The Destination — Bank Intelligence Platform

The ultimate product answers questions no human can answer in real time:

> *"If PKR depreciates 8% this week, which of our 847 corporate clients breach their DSCR covenants, what is our total exposure, and what is the recommended remediation sequence?"*

> *"Across all RMs, which relationships show early stress signals not yet flagged?"*

> *"We have three facility renewals expiring, two AML investigations pending SARs, and LCR approaching the regulatory buffer. What is today's priority sequence?"*

This is not a chatbot. It is an intelligence layer that continuously maintains a real-time model of the bank across all five domains — compliance, operations, revenue, risk, and treasury — and reasons across them simultaneously.

### 1.4 The Honest Timeline

| Milestone | Realistic Date | What Enables It |
|-----------|---------------|-----------------|
| Wave 1 live (first client) | Month 4–6 | Demo on mock data → pilot |
| Wave 2 live (CBS connected) | Month 9–12 | Wave 1 accuracy gate met |
| Wave 3 live (AML/credit) | Month 15–18 | 6+ months decision history |
| Seed raise | Month 18–24 | 3+ banks · PKR 150M+ ARR |
| Bank Intelligence Platform | Month 36+ | 10K+ decisions · 3+ banks · fine-tuned model |

**30-month platform target is optimistic.** Decision history accumulation is the constraint, not technology. 36+ months is realistic.

---

## Part 2 — Market and Positioning

### 2.1 Why Pakistan First

Pakistan has 33 commercial banks, 6 Islamic banks, and 12 microfinance banks. SBP regulatory intensity is increasing — circulars arrive weekly, prudential regulation is tightening, AI governance guidelines are at "advanced stage of finalization" per SBP's Financial Stability Review 2024. Banks are under examination pressure with inadequate intelligence tooling.

Pakistan-specific constraints that Western vendors cannot solve:

- SBP circular format and cross-referencing structure (still PDF/HTML, no XBRL)
- FMU STR format and filing workflow
- NADRA integration for e-KYC
- RAAST/RTGS/IBFT/PRISM+ (ISO 20022) payment rails
- Urdu document handling (230M+ speakers, still a low-resource language in LLMs)
- EFS/LTFF/TERF government refinancing scheme complexity
- 20%+ Islamic banking assets requiring Shariah screening (Meezan Bank alone holds 35% Islamic market share)

**Critical market fact:** No Pakistani IT company offers a proprietary, standalone AI/ML banking compliance product. NdcTech (now merged into Systems Limited) implements Temenos's AI — they do not build their own. This is the single most important competitive gap in our target market.

### 2.2 SBP Regulatory Environment — Our Window

**SBP AI Governance Guidelines:** At "advanced stage of finalization" but NOT yet issued as a binding circular. SBP surveyed 55 regulated entities — approximately half have deployed or are developing AI, primarily for fraud detection, virtual assistants, and credit risk. Guidelines will mandate transparency, accountability, bias mitigation, and human oversight. Cognic's AI Governance Agent and audit engine are designed to meet these requirements before they become mandatory.

**SBP Regulatory Sandbox:** First cohort launched August 2025, six entities shortlisted January 2026 (themes: open banking, inward remittances, remote merchant onboarding). Future cohorts expected — SBP has signaled intent to expand to RegTech and AI-based credit scoring. **Action:** Apply to second cohort when announced, targeting AI compliance automation.

**Pakistan Data Protection:** No enacted comprehensive data protection law. Personal Data Protection Bill 2023 approved by Cabinet but stuck in Parliament. Draft includes right not to be subject to solely automated decisions (affects AI credit scoring) and cross-border data transfer restrictions. Design for GDPR-equivalent compliance now — it costs nothing extra and future-proofs the architecture.

**SBP BPRD Circular No. 04 of 2023:** Already mandates "Intelligent Algorithm-based Customer Transaction Behavior Profiling" — explicitly requiring AI/ML-based fraud monitoring at all banks. This is our demand creation circular.

**National AI Policy 2025:** Approved July 30, 2025. Establishes National AI Fund (30% of R&D Fund via Ignite), proposes AI Regulatory Directorate. Creates institutional support for AI adoption in regulated sectors.

### 2.3 MENA Expansion Logic

| Market | Entry Timing | Primary Differentiator | Key Regulatory Driver |
|--------|-------------|----------------------|----------------------|
| UAE | Month 24+ | Islamic finance depth · CBUAE compliance · AMLSCU integration | CBUAE Federal Decree-Law No. 6/2025 — compliance deadline Sep 16, 2026. 52% of DIFC firms already using AI |
| KSA | Month 30+ | Full Islamic banking · SAMA framework · SAFIU STR format | 2026 designated "Year of AI." $9.1B AI funding in 2025. HUMAIN building 500MW AI data centres |
| Bangladesh | Month 30+ | Bangladesh Bank similarity to SBP · remittance corridors | Similar regulatory framework to Pakistan |
| Egypt | Month 36+ | CBE framework · scale | Largest MENA banking market by population |

**The jurisdiction config pattern** means writing one Pakistan profile in Month 1 means UAE and KSA profiles take days to add later. Build parameterised from day one.

### 2.4 Three Non-Negotiable Differentiators

**Sovereign deployment first.** For Pakistan and most MENA banks, the winning posture is self-hosted by default — on-premises where required, private cloud where acceptable, hybrid where needed. The moat is not "cloud never." The moat is data sovereignty, approval velocity, deployment flexibility, and zero dependency on external APIs for sensitive workloads. Validated by JPMorgan (200K employees on LLM Suite), BNY Mellon (DGX SuperPOD on-prem), and HSBC (Mistral AI self-hosted models).

**Accuracy-first discipline.** Every agent has defined accuracy gates. No agent enters production until it meets its threshold. No commercial pressure ever moves an agent forward prematurely. This is the commitment that earns regulatory trust.

**Banking domain depth.** We understand SWIFT field formats, nostro/vostro mechanics, SBP circular taxonomy, FMU STR requirements, FATF regional typologies, Urdu document handling, and AAOIFI Shariah standards. Generic AI companies do not. This domain knowledge is the moat that stops large vendors from parachuting in overnight.

**The durable edge is combined, not singular.** Competitors are catching up on deployment flexibility. Our defensible position is: sovereign deployment + CBS-agnostic integration + Pakistan/SBP/FMU depth + Urdu/bilingual handling + Islamic finance intelligence + governed agent runtime.

### 2.5 Competitive Positioning — Refined March 2026

| Competitor | Their Capability | Their Gap | Our Win |
|-----------|-----------------|----------|---------|
| Unit21 ($92M raised) | Strong alert operations, investigations, and case workflow maturity | US-first, limited Pakistan/MENA regulatory depth, no SBP/FMU/Urdu specialisation | Sovereign deployment, Pakistan-native compliance intelligence |
| Hawk AI ($56M Series C) | Mature AML/fraud platform, Riyadh presence, SaaS or private-cloud deployment | No Pakistan office, no SBP/FMU circular intelligence, no Urdu layer | Pakistan-first, regulatory-intelligence-led, broader bank-intelligence roadmap |
| Mozn (150+ clients, Riyadh) | FOCAL AML platform, Arabic name matching, strong GCC footprint | Saudi/GCC focused, no Pakistan presence, no Urdu, no SBP integration | Pakistan + GCC coverage, Urdu + Islamic + conventional depth |
| ComplyAdvantage ($167M, $824M valuation) | Strong data/intelligence network, SaaS-native financial-crime platform | Cloud/SaaS-led, limited sovereign deployment posture, no South Asian regulatory specialization | Self-hosted by default, FMU/SBP-native workflows |
| NdcTech / Systems Limited | Premier Temenos implementation partner, deep bank relationships | Implements vendor AI; does not own a proprietary bank-wide agent platform | Purpose-built AI agents, AgentOS, CBS-agnostic roadmap |
| Temenos AI (3000+ institutions) | Strong installed base, GenAI tools, flexible deployment incl. on-prem/cloud/SaaS | Best fit in Temenos estates, global/generic layer rather than Pakistan-first regulatory intelligence | CBS-agnostic, Pakistan/MENA-specific, phased and modular |
| Oracle Banking AI / FLEXCUBE AI | Pre-built banking agents, broad Oracle ecosystem, expanding private/on-prem options | Best fit in Oracle estates, generic global platform, limited SBP/FMU/Urdu specialization | Sovereign deployment + local regulation + multilingual + bank-intelligence positioning |
| Daeson Technologies (Riyadh) | Shariah AI Compliance Co-Pilot for GCC | Early stage, GCC-only, narrower product scope | Pakistan + GCC coverage, broader compliance and operations roadmap |
| Building internally | Full control, internal knowledge, internal politics alignment | 18+ months, difficult talent mix, no cross-bank learning | 8 weeks to first value, domain-native patterns, decision-history moat |

**Important correction:** our moat is not deployment mode alone. It is sovereign deployment **plus** local regulation, language coverage, Islamic finance depth, CBS abstraction, human-governed automation, and a bank-wide AgentOS foundation.

**Estimated competitive window:** approximately 18–24 months before global RegTech or GCC players localise aggressively for Pakistan. This is an estimate based on current competitor posture, not a guaranteed timeline. Move now.

---

## Part 3 — Architecture (Non-Negotiable Decisions)

### 3.1 The Three-Pool Architecture

This is the most important engineering decision in Cognic. Every capability must be placed in exactly one pool. Misclassifying a skill as an agent is a cost, latency, reliability, and governance failure.

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER C — AGENT POOL                                       │
│  Goal-driven · LLM-powered · uses tools and skills         │
│  Only where judgment, synthesis, or ambiguity is needed    │
├─────────────────────────────────────────────────────────────┤
│  LAYER B — SKILL / WORKFLOW POOL                            │
│  Multi-step deterministic logic · Temporal workflows       │
│  No LLM · reusable · composable · auditable                │
├─────────────────────────────────────────────────────────────┤
│  LAYER A — TOOL POOL                                        │
│  Atomic capabilities · No LLM · Pure I/O functions         │
│  Millisecond latency · 0 tokens · 100% deterministic       │
└─────────────────────────────────────────────────────────────┘
```

**The classification decision rule — run in order, stop at first match:**

1. Fetch data / call an external system / run a formula → **Tool**
2. Sequence tools in a fixed deterministic order → **Skill**
3. Requires judgment / synthesis / resolving ambiguity → **Agent**
4. Unsure? → Make it a Skill. Upgrade to Agent only when proven insufficient.
5. Reached Step 3 because prompting an LLM is easier than writing code? → Go back to Step 2.

**The cost argument (not theoretical):**

```
KYC expiry check on 50,000 customers:

  As Agent:  50,000 calls × 2,000 tokens = 100M tokens
             4–6 hours GPU time · non-deterministic
             Cannot be audited as "the calculation is correct"

  As Skill:  get_all_customers → filter WHERE expiry < NOW()+30d
             → create_task → send_alert
             Runtime: 4 seconds · 0 tokens · 100% reproducible
             Every step logged deterministically · passes SBP audit
```

The Skill version is 1,000× cheaper, 1,000× faster, and passes a regulatory audit. The Agent version fails all three.

### 3.2 Tiered Model Strategy

The open-source model landscape moves too fast to hard-code checkpoint names as architecture. The strategy locks the **policy**, not the exact checkpoint. Model choice is a runtime config via LiteLLM and is re-evaluated on a fixed benchmark cadence.

**Model policy, not model lock-in:**
1. Assign the smallest model that can pass the agent's accuracy gate.
2. Benchmark quarterly against the latest open models.
3. Run a 2-week shadow deployment before promoting any new model.
4. Prefer permissive licences, strong multilingual performance, and self-hosted serving compatibility.
5. Keep a family-first preference, not a checkpoint-first commitment.

**Primary model family posture:** Qwen-family first, because it combines strong multilingual capability (119 languages including Urdu and Arabic), open weights (Apache 2.0), strong agentic/reasoning momentum, and a practical self-hosted path. As of March 2026, the current benchmark reference point is the **Qwen3.5 family**. Earlier Qwen3 checkpoints remain valid where already validated, lighter, or easier to operate. DeepSeek distills, selected Llama variants, and other open models remain benchmark challengers — not ideological exclusions.

**Application code references model aliases, not checkpoint names.** The model registry resolves aliases to the current approved checkpoint.

**Tier 1 — SLM Fleet (7–14B parameters): The Workhorse**

Purpose: High-volume, RAG-heavy tasks where the knowledge base does the heavy lifting and the model synthesizes, formats, and cites. Used for Wave 1 agents (PolicyQA, RegIntel) and deterministic-adjacent agents.

Primary benchmark candidates: Qwen-family Tier 1 checkpoints (current reference: Qwen3.5-class small models; prior validated: Qwen3-8B/14B class). Challenger candidates: other multilingual 7B–14B checkpoints that beat Qwen on the bank's benchmark set.

Hardware: Single RTX 4090 (24GB) or single A100 40GB. No enterprise GPU procurement required for development or pilot.

Why this matters: A Pakistani Tier-3 bank does not need to procure A100 GPUs to run PolicyQA. A single consumer-grade GPU handles the workload. This transforms the TCO pitch from "you need $200K in GPUs" to "you need one server."

**Tier 2 — Mid-Range Reasoning (30–70B parameters): The Analyst**

Purpose: Tasks requiring genuine multi-step reasoning — credit proposal structuring, AML investigation narrative, complex regulatory interpretation. Used for Wave 2-3 agents.

Primary benchmark candidates: Qwen-family sparse or mid-range checkpoints (current reference: Qwen3.5-35B-A3B / comparable Qwen3-30B-A3B class). Challenger candidates: DeepSeek distills, selected Llama or other open 30B–70B models that win on domain benchmarks.

Hardware: 1-2x A100 80GB or 1x H100.

**Tier 3 — Frontier Reasoning (100B+ parameters): The Director**

Purpose: Cross-domain synthesis, complex ambiguity resolution, fine-tuning base for domain adaptation. Used for L1 Domain Agents and L0 Orchestrator in Month 18+.

Primary benchmark candidates: Top-end Qwen-family checkpoints (current reference: Qwen3.5 frontier class; previously validated Qwen3-235B-A22B class). Challenger candidates: DeepSeek R1-class or future frontier open models that materially outperform on bank benchmarks.

Hardware: Multi-GPU deployment. Plan by tier and SLA, not by one model marketing number. Assume 2–8 H100-class GPUs depending on checkpoint, quantization, concurrency, and context window.

**Critical MoE discipline:** MoE reduces active compute per token but does NOT eliminate the memory burden of loading expert weights. Size planning must be based on actual deployment artefacts, quantization, KV cache, concurrency, and target latency — not on "active parameters" alone.

**Hardware planning reference table — illustrative benchmark references only, not approved long-term commitments:**

| Model Class | Total/Active Params | FP16 VRAM | INT4 VRAM | Minimum Hardware |
|-------------|-------------------|-----------|-----------|-----------------|
| Tier 1 dense (e.g. Qwen3-8B) | 8B/8B | ~16GB | ~4GB | 1x RTX 4060 Ti |
| Tier 2 MoE (e.g. Qwen3-30B-A3B) | 30.5B/3.3B | ~61GB | ~15GB | 1x A100 80GB |
| Tier 2 dense (e.g. R1-Distill-32B) | 32B/32B | ~64GB | ~16GB | 1x H100 |
| Tier 3 MoE (e.g. Qwen3-235B-A22B) | 235B/22B | ~470GB | ~120GB | 8x H100 |

*These checkpoints reflect the March 2026 landscape and are examples of each tier's resource profile. Actual deployed models are determined by the quarterly benchmark evaluation process and resolved through MLflow Model Registry aliases. Do not cite this table as a hardware procurement commitment.*

### 3.3 Complete Tool / Skill / Agent Classification for Cognic

#### Layer A — Tool Pool (atomic, no LLM)

**CBS Read Tools**
```
get_account(account_id) → Account
get_facility(facility_id) → Facility
get_transactions(account_id, from_date, to_date) → [Transaction]
get_customer(customer_id) → Customer
get_collateral(facility_id) → [Collateral]
get_kyc_status(customer_id) → KYCStatus
```

**CBS Write Tools**
```
create_task(customer_id, task_type, due_date) → Task
flag_account(account_id, flag_type, reason) → FlagResult
update_facility_status(facility_id, status) → UpdateResult
create_watchlist_entry(customer_id, reason) → WatchlistEntry
```

**Calculation Tools** (pure functions, deterministic)
```
calc_cet1(balance_sheet_data) → CET1Result
calc_lcr(hqla, net_outflows) → LCRResult
calc_nsfr(asf, rsf) → NSFRResult
calc_ecl(loan_data, pd, lgd, ead, scenario_weights) → ECLResult
calc_var(positions, method, confidence, horizon) → VaRResult
calc_dscr(net_operating_income, debt_service) → DSCRResult
calc_clv(customer_data, churn_prob, margin) → CLVScore
```

**Document Tools**
```
extract_pdf(url) → DocumentText
parse_swift_message(raw_message) → SWIFTMessage
extract_lc_fields(document) → LCFields
fetch_sbp_circular(circular_id) → CircularDocument
```

**Vector Search Tools**
```
search_circulars(query, top_k) → [CircularChunk]
search_credit_policy(query, top_k) → [PolicyChunk]
search_shariah_standards(query, top_k) → [ShariahChunk]
embed_document(text) → Vector
```

**External API Tools**
```
screen_sanctions(name, dob, nationality) → ScreeningResult
cib_lookup(cnic, ntn) → CIBReport
swift_message_query(reference) → SWIFTStatus
raast_validate(iban, amount) → ValidationResult
fmu_submit_str(str_draft, human_auth_token) → SubmissionResult  # HITL gate
```

**Notification and Audit Tools**
```
send_alert(recipient_id, alert_type, context) → AlertResult
create_escalation(agent_id, reason, context) → EscalationResult
log_audit(record: CognicDecisionRecord) → AuditEntry
vault_get(secret_name) → SecretValue
check_role(user_id, permission) → bool
```

**Customer Intelligence Extraction Tools** (deterministic data extraction, no LLM)
```
extract_spending_pattern(account_id, period) → SpendingProfile
    # Sources: POS transactions, debit card, mobile app
    # Output: merchant-category breakdown (clothing, food, medical, travel, etc.),
    #         monthly trends, top merchants, average ticket size by category

extract_travel_pattern(account_id, period) → TravelProfile
    # Sources: ATM withdrawals (location), POS (merchant city),
    #         mobile app geolocation (if consented), cross-city transfers
    # Output: home city, travel frequency, destinations, domestic vs international

extract_digital_behavior(account_id, period) → DigitalProfile
    # Sources: mobile app sessions, website activity, login patterns,
    #         feature usage, channel preferences
    # Output: digital engagement score, preferred channels, session frequency

extract_family_structure(customer_id) → FamilyProfile
    # Sources: joint accounts, beneficiary records, CNIC-linked accounts,
    #         insurance nominees, school fee payments (merchant category),
    #         medical payments (merchant category)
    # Output: estimated household size, dependents, education stage indicators
    # NOTE: ALL inferences derived from customer's OWN transaction data.
    #       No external surveillance. Each inference tagged with confidence
    #       level and source data reference. Privacy guardrails apply.
```

**ML Model Tools** (trained offline via MLflow, served as inference endpoints, no LLM)

Trained ML models are Layer A tools. Once trained, `score_X(features) → Result` is no different from `calc_dscr(income, debt) → DSCRResult`. Structured input, structured output, deterministic for same input, millisecond latency. The training pipeline is offline infrastructure (MLflow). The inference endpoint is just another tool.

```
score_customer_persona(enriched_profile) → PersonaClassification
    # Supervised classifier trained on bank's labeled persona data
    # Input: merged customer intelligence profile features
    # Output: persona label + confidence + feature importance

score_gift_recommendation(persona, preferences, budget_tier) → GiftRecommendation
    # Supervised model trained on past successful gift-persona matches
    # Input: persona classification + spending preferences + WAD bracket

score_credit_risk(applicant_features) → CreditRiskScore
    # SME/retail credit scoring model
    # Input: financial ratios, bureau data, behavioral features

predict_churn(customer_features) → ChurnProbability
    # Churn prediction model — feeds RM Copilot alerts
    # Input: engagement trends, balance trends, competitor signals

score_fraud_risk(transaction_features) → FraudRiskScore
    # Real-time transaction fraud scoring
    # Input: transaction amount, velocity, merchant, device, geolocation

classify_transaction_typology(transaction_pattern) → TypologyMatch
    # Maps transaction patterns to known FATF/Pakistan-specific typologies
    # Input: transaction sequence features
    # Output: matched typology ID + confidence + indicator list

predict_next_best_action(customer_360, context) → NBARecommendation
    # Cross-sell / next-best-action propensity model
    # Input: full customer intelligence profile + current context
```

#### Layer B — Skill / Workflow Pool (Temporal workflows, no LLM)

```
kyc_expiry_check_skill(threshold_days=30)
  get_all_customers → filter_expiring
  → create_task → send_alert → log_audit

circular_ingestion_skill(rss_source)
  poll_rss → download_pdf → extract_pdf
  → embed_document → index → log_audit

nostro_reconciliation_skill(date, account_id)
  fetch_mirror_position → fetch_nostro_statement
  → match_entries → flag_breaks → create_tasks

basel_ratio_skill(date)
  get_balance_sheet → calc_cet1 → calc_lcr
  → calc_nsfr → compare_minimums → generate_report

payment_validation_skill(payment_instruction)
  validate_fields → check_limits → screen_sanctions
  → score_fraud_risk → return_decision

customer_intelligence_assembly_skill(customer_id)
  get_customer → get_facilities → get_transactions
  → get_kyc_status → get_collateral
  → extract_spending_pattern → extract_travel_pattern
  → extract_digital_behavior → extract_family_structure
  → merge_all_profiles → score_customer_persona
  → validate_data_completeness → store_enriched_profile
  → log_audit

  Output: CognicCustomerIntelligenceProfile
      ├── banking_profile (accounts, facilities, exposure, KYC)
      ├── spending_profile (merchant-category breakdown)
      ├── travel_profile (movement patterns from ATM/POS)
      ├── digital_profile (app/web channel behavior)
      ├── family_profile (household structure — inferred, tagged)
      ├── persona (ML-classified label + confidence)
      ├── data_completeness_score (% of fields populated)
      ├── inference_disclosure (which data sources fed each inference)
      └── last_updated timestamp

  NOTE: Runs as Temporal overnight batch (full base) or on-demand
  per customer (RM pre-meeting trigger). Data completeness varies
  by bank — banks without mobile app or POS data produce partial
  profiles. The skill handles graceful degradation.

sanctions_batch_screen_skill()
  get_new_onboarded_customers → screen_sanctions_each
  → flag_hits → create_tasks → log_audit

fatca_indicia_scan_skill()
  get_all_customers → check_us_person_indicia
  → check_foreign_tax_resident_indicia
  → classify → generate_report

swift_standard_repair_skill(rejection_id)
  get_rejection → classify_error_type
  → apply_known_fix → resubmit → log_audit
  # Escalates to AML Investigation Agent if non-standard

capital_adequacy_daily_skill(date)
  get_balance_sheet → calc_cet1 → calc_lcr → calc_nsfr
  → compare_sbp_minimums → flag_breaches → send_alert

str_package_assembly_skill(alert_id)
  get_transaction_detail → get_customer_profile
  → get_investigation_notes → assemble_fmu_format
  # Returns draft only — submission always requires human

framl_signal_correlation_skill(customer_id, period)
  get_fraud_agent_outputs(customer_id) → get_aml_agent_outputs(customer_id)
  → cross_reference_alerts → match_shared_entities_and_networks
  → flag_correlated_signals → create_unified_case_view → log_audit
  # Layer B deterministic: pattern matching across two output sets.
  # Criminals use the same networks for fraud and money laundering.
  # This skill surfaces correlations that siloed teams miss.
  # Does NOT require LLM — it's set intersection and network matching.
  # Wave 3, runs after both AML and Fraud agents produce outputs.

typology_screening_skill(transaction_batch, jurisdiction)
  load_typology_registry(jurisdiction) → extract_transaction_features
  → classify_transaction_typology(features)  # ML Model Tool
  → flag_matches_above_threshold → enrich_with_typology_context
  → route_to_aml_agent_if_match → log_audit
  # Runs known criminal blueprints against transaction patterns.
  # Pakistan-specific typologies: hawala/hundi, textile TBML,
  # EFS/LTFF scheme abuse, PKR 2.5M structuring across 1LINK/RAAST.
  # FATF reference attached to every flagged pattern.
  # Wave 3, feeds into AML Investigation Agent's SAR narrative.
```

#### Layer C — Agent Pool (LLM-powered, use tools and skills, judgment required)

```
RegulatoryIntelAgent (Tier 1 model)
  Uses: circular_ingestion_skill (output)
  Does: interprets regulatory impact · maps to business units
        drafts action items · flags deadline-driven compliance tasks
  Does NOT: ingest the circular (that's the skill)

PolicyQAAgent (Tier 1 model)
  Uses: search_circulars · search_credit_policy · search_shariah_standards
  Does: answers policy questions with citations
        confirms which SBP circular governs a situation
        identifies conflicting policy provisions

AMLInvestigationAgent (Tier 2-3 model)
  Uses: customer_intelligence_assembly_skill · sanctions_batch_screen_skill
        str_package_assembly_skill (for draft) · framl_signal_correlation_skill
        typology_screening_skill · classify_transaction_typology (ML tool)
  Does: reasons on transaction patterns · assesses suspicion
        drafts SAR narrative with typology reference and FATF citation
        incorporates FRAML correlated signals from fraud domain
        recommends case outcome
  Does NOT: submit SAR (hard HITL gate · FMU requires human)

RMCopilotAgent (Tier 2 model)
  Uses: customer_intelligence_assembly_skill · search_circulars (tool)
        score_customer_persona (ML tool) · predict_churn (ML tool)
        score_gift_recommendation (ML tool) · predict_next_best_action (ML tool)
  Does: synthesises pre-meeting brief with customer intelligence profile
        identifies cross-sell signals from NBA model
        spots early stress/churn indicators
        suggests personalized gift/offer from recommendation model
        provides policy context for products under discussion
  Does NOT: assemble the intelligence profile (that's the skill)

CreditProposalAgent (Tier 2 model)
  Uses: customer_intelligence_assembly_skill · calc_dscr · calc_ecl
        score_credit_risk (ML tool)
  Does: structures credit narrative · articulates risk rationale
        incorporates ML credit score with feature explanation
        drafts facility recommendation with conditions
  Does NOT: make the credit decision (human credit officer does)

ComplianceCheckerAgent (Tier 1 model)
  Uses: search_circulars · vector search tools
  Does: adversarial review of any other agent output
        default presumption: the output contains an error
  Does NOT: approve outputs (only recommends)

ShariahComplianceAgent (Tier 2 model)
  Uses: search_shariah_standards · get_facility (tool)
  Does: screens transactions/products against AAOIFI standards
        identifies potential Shariah violations for scholar review
        drafts preliminary Shariah audit opinion
  Does NOT: issue Shariah rulings (scholar required)

CorrespondentBankingAgent (Tier 2 model)
  Uses: customer_intelligence tools · get_transactions
  Does: monitors health of correspondent relationships
        flags deteriorating corridors · assesses de-risking risk
        tracks AML typology alerts per corridor

AIGovernanceAgent (Tier 1 model)
  Uses: log_audit (tool) · all Langfuse scorer tools
  Does: monitors all other agents for accuracy drift
        generates board-level AI risk report
        produces SBP examination evidence package
        flags agents approaching accuracy floor
  This agent governs the agents. Built into AgentOS core.

BankIntelligenceOrchestrator (L0 — built last, Tier 3 model)
  Uses: all domain agent outputs
  Does: cross-domain synthesis · priority sequencing
        surfaces cross-domain signals · routes complex queries
  Does NOT: replace any human decision-maker
```

### 3.4 Agent Hierarchy — Build Order

```
L0  BankIntelligenceOrchestrator          ← Built last (Tier 3 model)
      ↓
L1  Domain Agents (5 domains)
    ComplianceDomainAgent
    OperationsDomainAgent
    RevenueDomainAgent
    RiskDomainAgent
    TreasuryDomainAgent                   ← Built third (Tier 2-3 model)
      ↓
L2  Director Agents (per domain)
    AMLDirectorAgent · KYCDirectorAgent
    PaymentsDirectorAgent · etc.          ← Built second (Tier 2 model)
      ↓
L3  Specialist Agents (actual work)
    PolicyQAAgent · RegulatoryIntelAgent
    AMLInvestigationAgent · RMCopilotAgent
    CreditProposalAgent · etc.            ← Built first (Tier 1-2 model)
```

**Absolute rule:** L3 specialists before L2 directors before L1 domain agents before L0 orchestrator. Never reverse this. The temptation to build the orchestrator first and fill in agents later is what causes every complex AI system to fail.

### 3.5 The Multi-Agent Harness

Every agent in Layer C runs inside the same harness. No exceptions.

```
PLANNER → EXECUTOR → COMPLIANCE CHECKER
    ↑__________________________|
         correction → decision history store
```

**Sprint contracts** — negotiated before any execution begins:

```python
@dataclass
class SprintContract:
    task_description:      str           # precise, not vague
    success_criteria:      list[str]     # specific and testable
    hard_stop_conditions:  list[str]     # if any true → stop immediately
    escalation_triggers:   list[str]     # conditions requiring human
    max_execution_seconds: int           # prevents runaway agents
    confidence_threshold:  float         # below this → escalate
    tools_permitted:       list[str]     # explicit allowlist
    skills_permitted:      list[str]     # explicit allowlist
```

**Context resets** — fire every 90 minutes for long-running agents. Before reset, a structured handoff artifact is written:

```python
@dataclass
class HandoffArtifact:
    agent_id:           str
    session_id:         UUID
    reset_timestamp:    datetime
    work_completed:     list[str]     # what was done
    work_remaining:     list[str]     # what remains
    decisions_made:     list[dict]    # key choices and rationale
    open_questions:     list[str]     # unresolved items
    evidence_gathered:  dict          # key facts found
    next_action:        str           # first thing next session does
```

**The compliance checker** — the most important agent in the system:

Its system prompt begins: *"Your job is to find problems. Assume the executor has made at least one error. Your default position is rejection, not approval. Approval requires evidence. Rejection requires only doubt."*

It evaluates three dimensions for every output:
- Regulatory compliance — does this contradict any SBP/SECP regulation?
- Factual accuracy — can every claim be traced to a source in context?
- Decision quality — is this the right recommendation given the full context?

Hard escalation triggers override everything — regardless of checker score:
- Any amount above defined threshold
- Any compliance deadline within 7 days
- Any regulatory penalty language in the output
- Model confidence below minimum threshold
- Any data older than 24 hours used for a time-sensitive decision

### 3.6 The Guardrails Layer

This layer runs on every agent input and output before the compliance checker. It is the first line of defence.

**Input guardrails (on every agent input):**
```
check_prompt_injection(text) → block if detected
check_pii_exposure(text) → redact CNIC/IBAN/phone before sending to LLM
validate_data_freshness(context) → flag if data >24h for time-sensitive tasks
check_input_schema(input) → reject malformed inputs before LLM call
```

**Output guardrails (on every agent output):**
```
check_decision_authority(output, agent_id) → flag if PKR amount exceeds threshold
check_regulatory_language(output) → block forbidden phrases:
    "guaranteed profit" · "approved by SBP" · "definitely halal"
    "no documentation needed" · "guaranteed returns"
check_citation_presence(output) → warn if claim has no source citation
check_escalation_required(output) → force HITL if hard threshold breached
```

**PII redaction patterns for Pakistan:**
```python
PK_PII_PATTERNS = {
    r"\b\d{13}\b":                    "[CNIC]",
    r"PK\d{2}[A-Z]{4}\d{16}":       "[IBAN_PK]",
    r"\b\d{11}\b":                    "[PHONE_PK]",
    r"\b\d{7,8}\b":                   "[ACCOUNT_PK]",
    r"\b[A-Z]{2}\d{7}\b":            "[PASSPORT]",
    r"\b\d{7}-\d-\d\b":             "[NTN]",
}
```

### 3.7 Escalation Trigger Discipline

**Before writing any agent, define its escalation triggers in config.** These are numeric thresholds, not LLM judgments. The compliance checker enforces them programmatically.

Template for every new agent:

```yaml
# agents/aml_investigation/config.yaml
agent_name: AMLInvestigationAgent
layer: C
skill_dependencies:
  - customer_intelligence_assembly_skill
  - sanctions_batch_screen_skill

escalation_triggers:
  - trigger: customer_is_pep
    action: escalate_immediately
    reasoning: "PEP cases always require MLRO review"

  - trigger: transaction_amount_pkr > 2500000
    action: escalate
    reasoning: "SBP CTR threshold"

  - trigger: confidence_score < 0.72
    action: escalate
    reasoning: "Below minimum confidence for case recommendation"

  - trigger: previous_str_exists
    action: flag_to_director
    reasoning: "Prior reporting history changes risk profile"

hard_stops:
  - condition: customer_is_sanctioned
    action: freeze_and_escalate_immediately

hitl_gates:
  - gate: str_submission
    approver: senior_compliance_officer
    mandatory: true
    sla_hours: 168  # 7 working days per SBP requirement
```

---

## Part 4 — Technology Stack

### 4.1 Definitive Stack

Every core technology has a default, a rationale, and an escape hatch. Defaults are strong; hard lock-in is avoided where the market is moving too fast.

| Layer | Technology | Rationale | Do Not Substitute |
|-------|-----------|-----------|------------------|
| Agent framework | **Pydantic AI** (v1+) | Type-safe structured outputs, runtime validation, retry on schema violations, model-agnostic provider support | Ad-hoc prompt spaghetti |
| Agent orchestration | **LangGraph** (34.5M monthly downloads) | Durable graph orchestration, conditional routing, checkpointing, human-in-the-loop, time-travel debugging | Custom orchestration without persistence |
| Framework integration | **Pydantic AI + LangGraph combined** | Pydantic AI defines WHAT agents do; LangGraph defines HOW they interact | Either alone for the whole system |
| Workflow engine | **Temporal** | Durable execution for overnight, long-running, and approval-heavy workflows. Used by OpenAI Codex and Replit Agent 3 | Celery for bank-critical durable workflows |
| LLM serving — primary | **vLLM** (PagedAttention) | Broadest model/hardware support, <4% KV cache waste, largest community, production default | TGI as primary (maintenance mode Dec 2025) |
| LLM serving — high-throughput | **SGLang** (RadixAttention) | 29% higher throughput than vLLM on H100, 5x faster for agentic workflows, powers xAI Grok 3 | Single-serving-runtime absolutism |
| Inference platform (Wave 2/3+) | **KServe** (optional, recommended at multi-team scale) | Standardised self-hosted inference control plane for larger multi-model deployments | Hand-built per-model deployment snowflakes |
| LLM model policy | **Qwen-family-first, quarterly benchmark cadence** | Strong multilingual/open-weight path, selection remains benchmark-driven. See Section 3.2 | Hard-coding checkpoint names as architecture |
| LLM routing | **LiteLLM** | Model-agnostic routing, uniform APIs across self-hosted and external providers | Direct SDK coupling in agent code |
| Retrieval stack | **Hybrid: pgvector dense + BM25 keyword + reranker + citation verifier** | Banking accuracy depends heavily on retrieval quality, not just generation. See Section 4.2A | Dense-vector-only RAG |
| Database | **PostgreSQL 16 + pgvector** | Single DB for structured data + vector search | Prematurely splitting storage layers |
| Decision history | **PostgreSQL (append-only)** | Audit trail · correction capture · moat | Any opaque external store |
| Model registry & promotion | **MLflow Model Registry** | Model versioning, lineage, promotion control, aliases, deployment governance | Ad-hoc spreadsheet/model-folder governance |
| Observability | **Langfuse + OpenTelemetry + Prometheus/Grafana** | Langfuse for LLM traces/evals (self-hosted); OpenTelemetry as common telemetry standard; Prometheus/Grafana for platform metrics | SaaS-only observability in bank production |
| Cache | **Redis 7** | Session state · escalation queue · rate limiting | Memcached |
| Message queue | **RabbitMQ** | Agent-to-agent async · priority queues · dead-letter handling | Kafka for internal control plane (overkill) |
| API | **FastAPI** | Agent interfaces · bank portal backend · async | Flask, Django |
| Secrets | **HashiCorp Vault** | Zero hardcoded credentials · dynamic secrets | Environment variables |
| GitOps deployment (Wave 2+) | **Argo CD** | Declarative, bank-grade Kubernetes delivery, drift detection | Manual kubectl-based production ops |
| Workload identity (Wave 2+) | **SPIFFE/SPIRE** (or bank-approved equivalent) | Cryptographic workload identity for zero-trust internal service auth | Long-lived shared service credentials |
| Policy as code (Wave 2+) | **OPA Gatekeeper or Kyverno** | Enforce deployment, security, and runtime guardrails centrally | Tribal-knowledge policy enforcement |
| Metrics standard | **OpenTelemetry semantic conventions** | Common telemetry vocabulary across platform and agent runtime | Vendor-specific telemetry silos |
| Package manager | **uv** | 100x faster than pip · modern standard | pip, Poetry |
| Containers | **Docker + Kubernetes** | On-prem deployment · bank infrastructure | Cloud-managed assumptions |
| Air-gapped packaging | **Zarf** | Packages Helm charts + containers + model weights into single transportable archives | Manual image transfer |
| Data ingestion | **Kafka consumer + REST webhook + DB polling + file drop** | Conditional — deploy Kafka only for banks that run it. Tier 2-3 Pakistani banks use DB polling/REST first | Single ingestion mode |
| Internal messaging | **RabbitMQ** (retained) | Internal control plane, priority routing, dead-letter handling | Kafka for every internal interaction |
| ORM | **SQLAlchemy with dialect abstraction** | PostgreSQL default, Oracle/SQL Server accommodation when mandated | Raw SQL, single-dialect code |
| Vector search | **VectorStoreAdapter** with pgvector default | Enables Qdrant/Milvus/Oracle AI Vector Search swap without rewriting agents | Locking to one vector store forever |
| Banking standards | **BIAN alignment** | Enterprise banking credibility in CTO meetings | None |

**Note on enterprise control plane (Argo CD, SPIFFE, OPA):** These are essential for passing a bank's production security review but are NOT Week 1 infrastructure. Deploy before first bank production installation (Month 4-5), not during the 12-week build sequence. Engineers build agents first; ops hardens for production second.

### 4.2 Why Pydantic AI + LangGraph (Not Either/Or)

**Pydantic AI owns agent definition:** tool registration, structured output schemas, input/output validation, model-agnostic LLM calls, retry logic on schema violations.

**LangGraph owns agent orchestration:** state machine routing (planner → executor → checker → human approval), conditional branching, checkpointing for crash recovery, time-travel debugging, human-in-the-loop gates.

Each Pydantic AI agent is a node in a LangGraph graph. The graph manages the flow between agents. Pydantic AI manages what happens inside each node.

**Observability rule:** OpenTelemetry is the common telemetry substrate. Langfuse is the human-facing LLM observability and evaluation layer in production. Internal R&D may use other tools, but bank production converges into a single on-prem observability plane rather than fragmenting traces across multiple SaaS products.

### 4.2A Hybrid Retrieval — Retrieval Quality Is a Product Surface

For banking policy, compliance, and audit workflows, most early "LLM accuracy" failures are actually **retrieval failures** disguised as reasoning failures. Dense-vector-only RAG is insufficient for circulars, regulations, policy manuals, bilingual documents, and citation-heavy workflows. Retrieval is a first-class system, not an implementation detail.

**Every production RAG agent must use:**
1. Dense retrieval (pgvector via VectorStoreAdapter)
2. Keyword/BM25 retrieval (PostgreSQL full-text search or Elasticsearch)
3. Metadata filters (jurisdiction, date, regulation type, bank policy source)
4. Reranking (cross-encoder reranker model)
5. Citation verification before response delivery

**Default benchmark candidates:**
- Embeddings: Qwen embedding family and BGE-M3 class models
- Rerankers: Qwen reranker family or equivalent cross-encoder rerankers
- Query processing: query rewriting + hybrid recall + strict citation attachment

**Pakistan-specific rule:** Urdu and bilingual documents are benchmarked separately. Never assume multilingual performance on English benchmarks transfers cleanly to Urdu-heavy compliance corpora.

**BM25 upgrade path:** PostgreSQL full-text search is the default BM25 implementation. It is sufficient for Wave 1-2 corpus sizes (2,000-10,000 chunks) and avoids adding another infrastructure dependency. Upgrade to Elasticsearch or OpenSearch only if: (a) corpus size exceeds 50,000+ chunks across multiple banks, (b) multilingual ranking quality on Urdu requires language-specific analysers not available in PostgreSQL, or (c) operational needs demand a dedicated search cluster with independent scaling. This decision is evaluated during Wave 2 deployment, not assumed upfront.

### 4.2B Enterprise Control Plane — Required Before First Bank Production (Wave 2)

A bank-grade AI platform needs more than agents, models, and RAG. It needs a control plane. This is NOT Week 1 infrastructure — it is deployed before the first bank production installation (Month 4-5).

**Minimum enterprise control-plane capabilities:**
- GitOps deployment control via Argo CD (declarative, drift-detected K8s delivery)
- Workload identity for service-to-service trust (SPIFFE/SPIRE or bank-approved equivalent)
- Policy-as-code for cluster/runtime restrictions (OPA Gatekeeper or Kyverno)
- Deployment promotion controls tied to MLflow Model Registry status
- Environment parity across dev / test / prod
- Data lineage and traceability for regulated outputs

Without this layer, the system may work technically but will fail architecture review, security review, or production governance at any serious bank.

### 4.2C Reviewer Workbench — Product Requirement from Wave 2

Competitors in AML/compliance win deals partly because their compliance officer workflow UX is polished. Cognic needs a dedicated reviewer workbench from Wave 2 onward. This is where trust is operationalised.

**The workbench must provide:**
- Case queue and prioritisation (by agent, severity, SLA deadline)
- Inline evidence and source traceability (click-through to original SBP circular paragraph)
- Diff view between agent draft and human correction
- Escalation / approval / rejection actions with reason codes
- SLA tracking (e.g., 7-day FMU STR deadline countdown)
- Decision-history capture by correction reason code (DATA_ERROR/POLICY_GAP/EDGE_CASE/FORMAT/THRESHOLD/JUDGEMENT)
- Audit export for SBP examiners (PDF, filterable by agent, date range, outcome)

### 4.3 Development vs Production LLM Strategy

```python
# Same agent code — only endpoint and model alias change

# Development (no GPU, no cost)
agent = Agent('ollama:cognic-tier1-dev',
    base_url='http://localhost:11434/v1')

# Production Tier 1 (bank's single GPU server)
agent = Agent('openai:cognic-tier1-current',
    base_url='http://vllm-server:8000/v1')

# Production Tier 2 (bank's GPU cluster)
agent = Agent('openai:cognic-tier2-current',
    base_url='http://vllm-server:8000/v1')

# Production Tier 3 (bank's multi-GPU cluster)
agent = Agent('openai:cognic-tier3-current',
    base_url='http://sglang-server:30000/v1')

# Challenger / shadow deployment
agent = Agent('openai:cognic-tier2-shadow',
    base_url='http://shadow-serving:8000/v1')

# Fallback if bank policy allows external API access (rare)
agent = Agent('anthropic:claude-sonnet-4-5')
```

**Important discipline:** application code references model aliases (e.g., `cognic-tier1-current`), not raw checkpoint names (e.g., `qwen3-8b`). The MLflow Model Registry resolves the alias to the current approved checkpoint. When a new model is promoted after shadow testing, only the registry entry changes — zero agent code changes.

### 4.4 Temporal — When to Deploy

**Do not deploy Temporal in Wave 1.** Simple agents like PolicyQA and RegIntel do not need durable workflow execution.

Design the abstraction layer to support Temporal from day one, but deploy it only when Wave 2 agents require it. KYC Monitor running overnight — that needs Temporal. Policy Q&A answering a synchronous query — that does not.

```python
# Day 1: abstraction that works without Temporal
class WorkflowRunner:
    async def run(self, skill_name, params):
        # Week 1-8: direct async call
        return await self.skill_registry[skill_name](**params)

# Month 5 when Wave 2 arrives: swap to Temporal
class WorkflowRunner:
    async def run(self, skill_name, params):
        # Now uses Temporal for durability
        handle = await self.temporal_client.start_workflow(
            skill_name, params, id=uuid4()
        )
        return await handle.result()
```

### 4.5 Hardware Requirements — Tiered

| Environment | GPU | Models Served | Use |
|------------|-----|---------------|-----|
| Development | None — Ollama CPU | Tier 1 dev alias | Demo, testing, agent development |
| Minimal pilot | 1x RTX 4090 (24GB) or 1x A100 40GB | Tier 1 family models | Wave 1: PolicyQA + RegIntel + RM Copilot Phase 1 |
| Wave 2 production | 1-2x A100 80GB | Tier 2 family + Tier 1 fleet | Wave 2 agents + CBS integration |
| Wave 3 production | 2-4x A100 80GB or 2x H100 | Tier 3 family + Tier 1/2 fleet | All domain agents |
| Full platform | 4-8x H100-class GPUs | All tiers concurrent | Bank Intelligence Platform |

**Planning rule:** procure for the validated tier, concurrency, and latency target — not for a single checkpoint name.

**Pakistan GPU access reality:** Data Vault Pakistan (with Telenor) is the only AI-enabled data centre with NVIDIA approval for 3000+ GPUs. Partnership or hosted-private-cluster options may be needed for some banks. In MENA, GPU access is abundant (HUMAIN building 500MW AI facilities with NVIDIA).

### 4.6 Air-Gapped Deployment Architecture

Some Pakistani and MENA banks require fully air-gapped environments:

- **Zarf** packages entire Helm charts + container images + model weights into single transportable archives
- **Harbor/Nexus** runs as air-gapped container registry inside bank network
- Model weights pre-downloaded and included in Zarf package
- SBP circular ingestion via manual USB transfer pathway with cryptographic verification
- Langfuse observability runs entirely on-prem with no external data transmission
- All PyPI/npm dependencies pre-bundled

### 4.7 Certification Pathway

Priority order: **ISO 27001** (foundational, required by most bank procurement). **ISO/IEC 42001:2023** (AI Management System — first certifiable AI standard, increasingly required). **NIST AI RMF** (operational AI risk discipline). **PCI DSS** (when processing payment data in Wave 2+).

### 4.8 Data Ingestion Layer — Consuming Bank Data

Banks will NOT adapt their infrastructure to push data in our preferred format. We must consume from whatever they have. The Data Ingestion Layer supports four modes:

**Mode 1 — Kafka Consumer (primary for banks with streaming infrastructure)**
Many Pakistani banks doing real-time fraud monitoring or transaction streaming already run Kafka. When Cognic needs real-time transactions for AML monitoring, fraud detection, or payment validation in Waves 2-3, the bank will say "we stream transactions to Kafka topics — just consume from there." Cognic deploys a Kafka consumer group that subscribes to bank-defined topics (transactions, account events, KYC updates, circular notifications). Schema registry integration (Avro/Protobuf) for typed deserialization. Consumer offset management for exactly-once processing guarantees.

**Mode 2 — REST API Webhook (for banks pushing events via HTTP)**
Bank systems call Cognic's FastAPI webhook endpoints with event payloads. Authentication via mTLS or API key + HMAC. Idempotency keys prevent duplicate processing.

**Mode 3 — Database Polling (for banks where we read directly from CBS)**
Scheduled polling of CBS views/tables via CBS adapter layer. Change Data Capture (CDC) where available (Oracle GoldenGate, PostgreSQL logical replication). Configurable polling intervals per data type.

**Mode 4 — File-Based Ingestion (for air-gapped environments)**
Batch CSV/XML/JSON file drops via secure file share or USB transfer. Cryptographic verification of file integrity. Manual trigger or scheduled processing. SBP circular ingestion uses this mode in air-gapped banks.

**Mode 5 — Digital Session Telemetry (Wave 3+, for digitally mature banks)**
Ingests device fingerprint data, IP/geolocation signals, login anomaly events, VPN detection flags, and session behavioral patterns from the bank's digital channels (mobile app, internet banking, API gateway). NOT required for Pakistani Tier 2-3 banks in Wave 1-2 — most lack this telemetry infrastructure. Deploy for Tier 1 Pakistani banks (HBL, MCB) and MENA banks (Emirates NBD, ADCB, Al Rajhi) where digital-first customer bases generate rich session data. Feeds into Fraud Detection Agent and FRAML Signal Correlation Skill.

**Critical design principle:** Kafka is for the external data plane (bank → Cognic). RabbitMQ stays for the internal control plane (agent → agent). These are different concerns. Kafka handles high-throughput, durable, ordered event streams from bank systems. RabbitMQ handles lightweight, priority-routed, dead-letter-capable agent-to-agent messages. Mixing them creates unnecessary complexity.

### 4.9 Database Abstraction Strategy

**AgentOS's own database (decision history, audit, knowledge base) defaults to PostgreSQL.** It runs inside our containerized environment, isolated from the bank's infrastructure. We control this.

**Why not offer Oracle as default:** PostgreSQL is open-source (no licence cost per bank), has pgvector for vector search in the same instance, and our Docker/K8s deployment controls the environment. Adding Oracle as AgentOS default doubles development surface, adds licence costs, and introduces a dependency we don't control.

**When Oracle matters:** Some Tier-1 bank CIOs mandate that nothing on their network runs outside their approved technology list. For these banks (expect this at HBL, NBP-scale), AgentOS data layer uses SQLAlchemy with dialect abstraction. PostgreSQL is default; Oracle is an accommodation option activated by deployment config, not code change.

```python
# SQLAlchemy dialect abstraction — same code, different DB
from sqlalchemy import create_engine

# Default (PostgreSQL)
engine = create_engine("postgresql+psycopg2://user:pass@localhost/cognic")

# Oracle accommodation (Tier-1 bank mandate)
engine = create_engine("oracle+oracledb://user:pass@localhost/cognic")

# SQL Server accommodation (some Finacle deployments)
engine = create_engine("mssql+pyodbc://user:pass@localhost/cognic")
```

**Vector search abstraction:** pgvector is default. If a bank mandates Oracle-only, Oracle AI Vector Search (23ai) is the swap. If a bank already runs Qdrant/Milvus, we plug into their existing infrastructure via VectorStoreAdapter interface.

```python
class VectorStoreAdapter(ABC):
    @abstractmethod
    async def index(self, chunks: list[DocumentChunk]) -> None: ...
    
    @abstractmethod
    async def search(self, query: str, top_k: int) -> list[SearchResult]: ...

class PgVectorStore(VectorStoreAdapter): ...    # Default
class QdrantStore(VectorStoreAdapter): ...      # If bank runs Qdrant
class OracleAIVectorStore(VectorStoreAdapter): ... # If bank mandates Oracle
```

**CBS adapter layer is where Oracle/SQL Server support is mandatory from Day 1.** When we connect to a bank's core banking system, we read from whatever they run — Oracle for FLEXCUBE banks, SQL Server for some Finacle deployments, Temenos's own data layer for T24. The CBS adapter tools (get_account, get_facility, etc.) abstract this completely.

---

## Part 4A — Lessons from Leading Banks (What We Were Missing)

Deep analysis of JPMorgan Chase ($18B tech budget, 200K+ employees on LLM Suite, 600+ AI use cases delivering $1.5-2B annual value), HSBC (Mistral AI self-hosted partnership), BNY Mellon (Eliza platform, 99% workforce adoption), and DBS Bank (PURE framework) reveals six capabilities Cognic's strategy was missing.

### Lesson 1: The Data Flywheel (from JPMorgan's JADE)

JPMorgan's JADE data ecosystem makes all enterprise data "AI-ready" — structured and unstructured, real-time and historical, internal and external. Every 8 weeks, LLM Suite is updated with connections to more databases and applications. This creates a compounding advantage: more data → better AI → more adoption → more data.

**What Cognic was missing:** No explicit data normalisation/preparation layer. Our knowledge base covers SBP circulars but doesn't address how to make a bank's OWN data (transaction history, client records, internal policies, committee minutes) AI-ready.

**What we add:** A "Bank Data Readiness" engagement phase (pre-Wave 2) where we inventory, profile, and connect the bank's key data sources to AgentOS. This becomes a moat — once we've mapped their data, switching cost is enormous. Add a `DataReadinessEngine` to AgentOS that profiles data quality, identifies gaps, and generates a remediation plan for each bank.

### Lesson 2: Prompt Library and Adoption Program (from JPMorgan's "AI Made Easy")

JPMorgan ran 30,000+ "AI Made Easy" training sessions in Q1 alone. They provide visual dashboards showing adoption metrics (not tracking individuals — tracking tool/capability usage), weekly town halls, and a curated prompt library. BNY Mellon achieved 80% training completion across the firm before Eliza rollout. Santander is mandating AI training for ALL employees starting 2026.

**What Cognic was missing:** Zero adoption/change management strategy. We assumed banks would adopt our agents because they're good. JPMorgan proves that adoption requires a deliberate program — marketing, training, metrics, and executive sponsorship.

**What we add:** Every bank deployment includes a "Cognic Adoption Kit" — pre-built prompt library for compliance officers (50+ banking-specific prompts), adoption dashboard showing team usage patterns and time savings, "Cognic Made Easy" training session materials (2-hour workshop for compliance teams), and a dedicated "first 30 days" onboarding program. This is not optional. It is part of the implementation engagement.

### Lesson 3: Inline Citations with Source Traceability (from BNY Mellon's Eliza)

BNY Mellon's Eliza provides inline citations to original sources for every claim, specifically to mitigate hallucination risk in a financial context. Every AI-generated statement links back to the specific document, paragraph, and date that supports it.

**What Cognic was missing:** PolicyQA "answers with citations" but the strategy didn't specify the citation format or traceability chain.

**What we add:** Every PolicyQA response includes: the specific SBP circular reference (BPRD/IH/DMMD number + date), the exact section and paragraph cited, a confidence score for each claim, and a "verify" link that shows the original source chunk. The compliance checker validates citation accuracy as part of its three-dimension evaluation. This is a regulatory trust requirement, not a nice-to-have.

### Lesson 4: Automated Kill Switch (from DBS Bank's PURE Framework)

DBS Bank operates under the "PURE" framework — all AI systems must be Purposeful, Unsurprising, Respectful, and Easy to explain. For high-risk applications, DBS implements real-time metrics with defined performance limits. If any metric is breached, automated kill switches activate, immediately stopping the agent and routing all requests to human handlers.

**What Cognic was missing:** Accuracy gates are manual evaluation checkpoints. No automated, real-time kill switch mechanism.

**What we add:** Every agent in production has an automated accuracy monitor (powered by the AI Governance Agent). If rolling 7-day accuracy drops below the State 2 floor (e.g., <90% for PolicyQA), the system automatically: degrades the agent from State 3 (automated) to State 2 (assisted — human reviews all outputs), sends an alert to the compliance officer and Cognic engineering, and logs the degradation event in the audit trail. This is an automated circuit breaker, not a manual review. Add `AutoDegradationMonitor` to AgentOS core.

### Lesson 5: Federated Learning for Cross-Bank Intelligence (from Banking Circle + Lucinity)

Cognic's strategy mentions "cross-bank learning" and "anonymised pattern sharing" but doesn't specify the mechanism. Banking Circle adopted Flower's federated learning platform to train AML models across regions without moving data across borders. Lucinity holds patents in federated learning and PII encryption for compliance intelligence. Several major banks are planning federated learning pilots by 2026.

**What Cognic was missing:** The cross-bank learning mechanism was vague. "Anonymised hash" is insufficient — you need a privacy-preserving training framework.

**What we add:** Cross-bank learning uses federated learning (Flower framework, MIT license). Each bank's Cognic instance trains locally on its own correction data. Model weight updates (not raw data) are aggregated centrally. No bank's raw data ever leaves their infrastructure. This is architecturally aligned with the on-prem-first principle. Add `FederatedLearningCoordinator` to AgentOS (Wave 3+, when 3+ banks are live).

### Lesson 6: Model-Agnostic Architecture with Regular Model Rotation (from JPMorgan's LLM Suite)

JPMorgan's LLM Suite is an "abstraction layer" that swaps models from OpenAI, Anthropic, and others. Every 8 weeks, the platform is updated with new model capabilities. Derek Waldron explicitly designed this because "different models will be good for different things, and we don't want to architect ourselves around one particular model."

**What Cognic was missing:** LiteLLM provides model-agnostic routing, but the strategy didn't include a cadence for model evaluation or an A/B testing framework.

**What we add:** Quarterly Model Evaluation Cadence — every 3 months, run the accuracy gate test suite against the latest open-source challengers. If a newer model beats the current approved model by >3% on any agent's benchmark set, run a 2-week shadow deployment before promotion. Application code references model aliases (e.g., `cognic-tier1-current`) resolved by MLflow Model Registry — not raw checkpoint names. When a model is promoted, only the registry entry changes; zero agent code changes. Add `ModelEvaluationPipeline` and `ModelPromotionPolicy` to AgentOS.

---

## Part 5 — AgentOS Platform

### 5.1 What AgentOS Is

AgentOS is the infrastructure layer sold to every bank. It is not an agent. It is what agents run on. Every bank pays a platform licence before any agent module licence.

```
AgentOS Components:
├── Three-pool runtime (enforces Tool/Skill/Agent boundaries architecturally)
├── Harness runtime (planner-executor-checker, sprint contracts, context resets)
├── Sovereign LLM gateway (vLLM + SGLang + LiteLLM, model-agnostic, tiered)
├── ML model serving layer (MLflow-registered models served as Layer A tools)
├── Hybrid retrieval layer (dense + BM25 keyword + reranker + citation verifier)
├── Decision history store (append-only PostgreSQL, cryptographically signed)
├── Banking knowledge base (SBP circulars, PRs, schemes, FATF, AAOIFI)
├── Typology registry (Pakistan-specific + FATF criminal pattern blueprints)
├── Customer intelligence assembly (enriched profiles from CBS + CRM + digital channels)
├── Customer intelligence privacy framework (inference disclosure, confidence tagging, audit)
├── Data adapter layer (T24, Finacle, Misys, Oracle FLEXCUBE, CRM systems — CBS-agnostic)
├── Data ingestion layer (Kafka, REST webhook, DB polling, file drop, digital session telemetry)
├── Database abstraction (SQLAlchemy — PostgreSQL default, Oracle/SQL Server swap)
├── Vector search abstraction (pgvector default, Qdrant/Oracle AI Vector Search swap)
├── Guardrails runtime (input/output guardrails, PII redaction, PK patterns)
├── Compliance checker runtime (skeptical evaluator, configurable per agent)
├── Human escalation bus (Temporal signals + Redis queue + bank portal)
├── Reviewer workbench (case queue, evidence pane, approval/reject/diff, SLA tracking)
├── Auto-degradation monitor (automated kill switch — circuit breaker on accuracy drop)
├── Audit engine (every LLM call logged, signed, examiner-accessible)
├── Langfuse observability (self-hosted, tracing, evals, prompt management)
├── OpenTelemetry telemetry plane (shared traces, metrics, logs)
├── Model registry and promotion flow (MLflow — versioning, aliases, shadow deployments)
├── Model evaluation pipeline (quarterly model rotation, A/B shadow deployment)
├── AI governance agent (monitors all other agents — non-optional)
├── FRAML signal correlation (cross-references fraud + AML outputs per customer)
├── Federated learning coordinator (cross-bank model improvement, Wave 3+)
├── Bank data readiness engine (data profiling, quality assessment, gap analysis)
├── Adoption kit (prompt library, training materials, usage dashboards)
├── AI workforce registry (agent identity, org graph, authority matrix, KPI definitions)
├── Performance evaluation engine (quarterly agent reviews, KPI trending, promotion readiness)
├── Executive decision board (2-3 option rendering, human decision capture, decision audit trail)
├── Enterprise control plane (Argo CD GitOps + workload identity + policy-as-code, Wave 2+)
├── Consent ledger (tracks customer opt-in/opt-out for behavioral profiling, location data)
└── Jurisdiction compliance config (SBP/SECP/FMU/CBUAE/SAMA pluggable)
```

### 5.2 Jurisdiction Config — Built for MENA from Day One

```python
class ComplianceConfig(BaseModel):
    jurisdiction:               str    # PK, UAE, KSA, UK
    currency:                   str    # PKR, AED, SAR, GBP
    currency_symbol:            str    # ₨, د.إ, ﷼, £
    primary_regulator:          str    # SBP, CBUAE, SAMA
    prudential_regulator:       str    # SBP, CBUAE, SAMA
    aml_reporting_authority:    str    # FMU, AMLSCU, SAFIU
    central_bank:               str    # SBP, CBUAE, SAMA
    capital_framework:          str    # Basel_III
    data_protection_law:        str    # PDPA_Draft, PDPL
    aml_framework:              str    # AML/CFT_Regs_2020
    domestic_payment_schemes:   list[str]  # RAAST, RTGS, IBFT
    international_scheme:       str    # SWIFT
    str_filing_days:            int    # 7 (SBP), 30 (UK)
    ctr_threshold_local:        Decimal  # PKR 2,500,000
    breach_notification_hours:  int    # 72
    shariah_mode:               bool   # True for Islamic banks
    human_approval_required:    list[str]  # STR, HIGH_VALUE_TX

# Pakistan (primary market)
PK_CONFIG = ComplianceConfig(
    jurisdiction="PK", currency="PKR", currency_symbol="₨",
    primary_regulator="SBP", aml_reporting_authority="FMU",
    domestic_payment_schemes=["RAAST", "RTGS", "IBFT", "1LINK"],
    str_filing_days=7, ctr_threshold_local=Decimal("2500000"),
    shariah_mode=False,
    human_approval_required=["STR", "HIGH_VALUE_TX", "NEW_PRODUCT_APPROVAL"]
)

# UAE (first expansion)
UAE_CONFIG = ComplianceConfig(
    jurisdiction="UAE", currency="AED", currency_symbol="د.إ",
    primary_regulator="CBUAE", aml_reporting_authority="AMLSCU",
    domestic_payment_schemes=["UAEFTS", "IPP", "FAWRI"],
    ctr_threshold_local=Decimal("40000"),
    shariah_mode=False,
)
```

### 5.3 The Decision History Store — The Moat

This is the most valuable database in the company. It must be append-only, cryptographically signed, queryable, and anonymised (bank_id hashed before any cross-bank use).

```python
@dataclass
class CognicDecisionRecord:
    # Identity and tracing
    record_id:              UUID
    timestamp:              datetime
    agent_id:               str          # COG-AI-001 (workforce registry ID)
    agent_name:             str
    agent_department:       str          # From workforce registry
    agent_authority_level:  str          # Advisory / Operational / Supervisory
    reports_to:             str          # Human or agent supervisor ID
    bank_id:                str          # anonymised hash
    jurisdiction:           str
    trace_id:               str          # Langfuse trace ID
    model_name:             str
    model_version:          str

    # What the agent saw and did
    input_context:          dict
    reasoning_steps:        list[str]
    tools_called:           list[str]
    skills_invoked:         list[str]
    output:                 dict
    confidence_score:       float

    # Guardrail results
    guardrail_flags:        list[str]
    guardrail_actions:      list[str]

    # Langfuse scorer results
    domain_scorer_results:  dict

    # Human review (populated after review)
    human_action:           str | None   # APPROVE/CORRECT/PARTIAL/ESCALATE
    human_correction:       dict | None
    correction_reason:      str | None   # DATA_ERROR/POLICY_GAP/EDGE_CASE/FORMAT/THRESHOLD/JUDGEMENT
    correction_detail:      str | None
    outcome:                str | None   # CORRECT/INCORRECT/UNKNOWN (hindsight)

    # Decision options (populated when agent uses DecisionOptionsResponse)
    options_presented:      int | None   # 2 or 3
    agent_recommended:      int | None   # Which option the agent recommended
    human_selected:         int | None   # Which option the human chose
    followed_recommendation: bool | None # Did human follow agent's recommendation?

    # Classification
    domain:                 str          # COMPLIANCE/OPERATIONS/REVENUE/RISK/TREASURY
    agent_layer:            str          # L3/L2/L1/L0
    ceo_agent_relevant:     bool
    cross_bank_shareable:   bool

    # Computed signature
    record_signature:       str          # cryptographic hash of all fields above
```

**Three uses of this store, in order of maturity:**
1. Prompt improvement — corrections become better few-shot examples (immediate)
2. Threshold calibration — correction patterns tune confidence cutoffs (Month 6+)
3. Fine-tuning — domain-adapted model after 1,000+ corrections per agent (Month 18+)

### 5.4 The Banking Knowledge Base

Built before the first client demo. Every agent draws from this.

| Component | Source | Status |
|-----------|--------|--------|
| SBP circular archive (2010–present) | sbp.org.pk | Public, fetch and embed |
| SBP Prudential Regulations | sbp.org.pk | Public |
| SBP scheme docs (EFS, LTFF, TERF, REER) | sbp.org.pk | Public |
| SBP Digital Banking Framework | sbp.org.pk | Public |
| FMU STR/SAR format and guidelines | fmu.gov.pk | Public |
| FATF 40 Recommendations | fatf-gafi.org | Public |
| FATF South Asia regional typologies | APG | Public |
| AAOIFI Shariah standards | aaoifi.com | Licensed or manual |
| SECP regulations (banking groups) | secp.gov.pk | Public |
| Synthesised generic Pakistan credit policy | — | Build internally |
| **Pakistan Typology Registry** | FATF + APG + FMU + internal | **Build internally — moat** |

Total embedded documents at launch: ~2,000–3,000 chunks across all sources.

**5.4A The Typology Registry — Competitive Moat**

No global RegTech vendor has a Pakistan-specific typology registry. This is a structured knowledge base (not free text) where each entry includes:

```yaml
typology_id: PK-TBML-001
name: "Textile Export Over/Under-Invoicing"
fatf_reference: "FATF Trade-Based ML Guidance, 2006 (updated 2020)"
apg_reference: "APG South Asia Typology Report, Section 4.2"
pakistan_specific: true
description: "Manipulation of textile export invoices to move value cross-border"
indicators:
  - invoice_value_deviation > 25% from market benchmark for HS code
  - same buyer/seller pair with alternating over/under invoicing
  - EFS/LTFF refinancing claimed on manipulated invoice values
  - rapid settlement followed by immediate outward remittance
detection_layer: "Skill (classify_transaction_typology ML tool) + Agent (AML Investigation)"
regulatory_consequence: "FMU STR required · SBP examination priority"
```

**Pakistan-specific typologies to build at launch:**
1. Textile/rice export over/under-invoicing (TBML)
2. Hawala/hundi layering alongside formal banking channels
3. PKR 2.5M CTR structuring across multiple 1LINK/RAAST accounts
4. EFS/LTFF/TERF refinancing scheme abuse
5. Circular trading through commodity exchanges
6. Shell company layering through nominee CNIC accounts
7. Cross-border remittance corridor manipulation (UAE/UK/US)
8. Digital wallet fragmentation (Easypaisa/JazzCash → bank account layering)

Each typology feeds the `classify_transaction_typology` ML Model Tool and the AML Investigation Agent's SAR narrative. When the agent drafts a SAR, it cites the specific typology ID and FATF reference — this is what SBP examiners want to see.

### 5.4B Customer Intelligence Privacy Framework

The Customer Intelligence Assembly Skill infers personal attributes (family structure, lifestyle preferences, travel patterns) from transaction data. Every inference must be:

- **Derived from the customer's OWN transaction data only** — school fee payments at merchant category 8211 imply school-age dependents. We do not access school enrollment records, social media, or third-party data.
- **Tagged with inference type** — STATED (customer-provided), VERIFIED (NADRA/CNIC confirmed), INFERRED (derived from transaction patterns). Every field carries its tag.
- **Assigned a confidence score** — high (multiple corroborating signals), medium (single strong signal), low (weak/ambiguous signal).
- **Logged with source data references** — every inference links to the specific transactions, accounts, or events that produced it via `ProfileInferenceDisclosure`.
- **Subject to all existing PII guardrails** — CNIC, IBAN, phone redaction before LLM processing. Inference data is equally sensitive.
- **Auditable** — a customer, bank compliance officer, or SBP examiner can ask "how did you determine this customer has two school-age dependents?" and receive a traceable answer.
- **Compliant with Pakistan's draft PDPA** — right not to be subject to solely automated decisions. The enriched profile feeds agents that make RECOMMENDATIONS, not automated decisions. Human review remains in the loop.

```python
@dataclass
class ProfileInferenceDisclosure:
    field_name:         str       # e.g., "estimated_dependents"
    inferred_value:     Any       # e.g., 2
    inference_type:     str       # STATED / VERIFIED / INFERRED
    confidence:         str       # HIGH / MEDIUM / LOW
    source_data:        list[str] # ["POS:merchant_cat_8211:12_transactions",
                                  #  "standing_order:school_name_partial:monthly"]
    inference_logic:    str       # human-readable explanation
    timestamp:          datetime
```

### 5.4C Customer Intelligence — Permitted and Prohibited Uses

The Customer Intelligence Assembly Skill produces rich behavioral profiles. Without explicit use boundaries, this capability becomes a liability — reputationally, regulatorily, and legally. This policy governs what agents and bank users MAY and MAY NOT do with enriched profiles.

**Permitted Uses:**
- RM pre-meeting preparation (relationship context, product suitability assessment)
- Portfolio-level analytics (aggregated across customer segments, not individual targeting)
- AML/KYC investigation context (behavioral patterns relevant to suspicion assessment). AML/KYC investigative use of behavioral context must remain purpose-limited to the specific investigation and role-restricted to authorised compliance officers — enriched profile data accessed for an investigation must not be repurposed for marketing, cross-sell, or relationship management without separate authorisation
- Credit risk assessment inputs (with human credit officer review — never sole basis for adverse action)
- Cross-sell/NBA recommendations presented to RM for human judgment (not auto-executed)
- Churn prediction alerts to RM (for proactive relationship management, not punitive action)
- Gift/offer recommendation as suggestion to RM (human selects final gift, not system)

**Prohibited Uses:**
- **Automated adverse action** — no credit denial, account closure, limit reduction, or fee increase based solely on inferred attributes without human review and separate approval
- **Discriminatory pricing** — inferred lifestyle, family structure, travel patterns, or spending categories must NEVER be used to set differential pricing for the same product
- **Customer-facing disclosure of inferred private information** — an RM must not say "we know you have two children at Lahore Grammar School" based on merchant-category inference. Inferences inform the RM's preparation, not their conversation script
- **Geolocation-based inference without explicit consent** — any inference derived from ATM/POS location, mobile app geolocation, or IP address requires that the bank has obtained explicit consent for location data processing, logged in the Consent Ledger. If consent is absent, location-derived fields are suppressed from the profile
- **Silent profiling without opt-out** — the bank must provide account holders a mechanism to opt out of behavioral profiling. Opt-out is recorded in the Consent Ledger and enforced at profile assembly time; the skill checks ledger status before running extraction tools. Opt-out suppresses the enriched profile; basic banking profile (accounts, facilities, KYC) remains unaffected

**The Consent Ledger** is a named AgentOS platform component, not just a policy requirement. It is an append-only PostgreSQL table that records:

```python
@dataclass
class ConsentRecord:
    customer_id:      str
    consent_type:     str       # BEHAVIORAL_PROFILING / LOCATION_DATA / DIGITAL_SESSION
    status:           str       # GRANTED / REVOKED
    granted_at:       datetime | None
    revoked_at:       datetime | None
    channel:          str       # BRANCH / MOBILE_APP / INTERNET_BANKING / WRITTEN
    bank_reference:   str       # bank's internal consent form reference
    cognic_enforced:  bool      # True = Cognic suppresses fields if revoked
```

The Customer Intelligence Assembly Skill queries the Consent Ledger before executing extraction tools. If `LOCATION_DATA` consent is `REVOKED`, `extract_travel_pattern` is skipped. If `BEHAVIORAL_PROFILING` consent is `REVOKED`, the entire enriched profile is suppressed and only the basic banking profile is produced. This is architectural enforcement, not policy-only.
- **Sale or transfer of enriched profiles** — inferred customer intelligence is the bank's data, processed by Cognic under engagement contract. It must never be sold, shared with third parties, or used outside the contracted bank relationship
- **Training Cognic's cross-bank models on identifiable profile data** — federated learning uses model weights only, never raw profile data. This prohibition is architectural (Brick 76 design) and contractual

**Enforcement:** The AI Governance Agent audits agent tool calls and flags any use pattern that matches a prohibited category. The Reviewer Workbench logs every profile access by user ID. Quarterly compliance review includes profile usage audit.

### 5.4D ML Model Tool Governance — Equal Discipline to LLM Agents

Trained ML models (Layer A tools) require the same governance discipline as LLM-powered agents. A credit scoring model with demographic bias or a fraud scoring model with concept drift is as dangerous as a hallucinating LLM — arguably more so because it operates at higher volume with less human review per decision.

**Every ML Model Tool in production must comply with:**

**Drift monitoring (mandatory):**
- Input distribution monitoring — alert if feature distributions shift beyond defined thresholds (population stability index > 0.2)
- Output distribution monitoring — alert if prediction score distributions change significantly
- Performance monitoring — track accuracy/precision/recall on labeled holdout data
- AutoDegradationMonitor applies to ML tools, not just LLM agents: if drift exceeds threshold, model reverts to previous version automatically

**Champion-challenger testing (mandatory before any model promotion):**
- New model version runs in shadow mode alongside current champion
- Minimum 2-week shadow period with statistical comparison
- Promotion requires documented approval in MLflow Model Registry (not automatic)
- Human sign-off required — model scientist + compliance reviewer

**Feature lineage (mandatory):**
- Every model documents which data sources feed which features
- Changes to upstream data sources trigger model revalidation
- Feature store (if deployed) maintains versioned feature definitions

**Bias review (mandatory before first deployment, annual thereafter):**
- Protected attributes analysis: gender, age, geography, religion (inferred or stated)
- Disparate impact assessment for credit scoring and pricing-adjacent models
- Review documented and retained in audit trail
- SBP AI Governance Guidelines will likely mandate this — build the practice now

**Retraining approval workflow:**
- Retraining triggered by drift alerts or scheduled cadence (quarterly minimum)
- Retrained model must pass accuracy gate on current test set before promotion
- Retraining data reviewed for quality and bias before use
- MLflow tracks training data version, hyperparameters, and evaluation metrics

**Rollback criteria:**
- If production model accuracy drops below defined threshold (per-tool, documented in config)
- Automatic rollback to previous registered version in MLflow
- Alert to model scientist + compliance + bank stakeholder
- Rollback event logged in audit trail with root cause analysis required within 48 hours

**Evaluation datasets as governed assets (mandatory):**

Every RAG agent and every ML Model Tool must have a versioned, owned evaluation dataset. This is not optional instrumentation — it is the artefact that makes accuracy gates, shadow testing, and model promotion possible. Without it, governance is theatre.

- **Versioned** — every evaluation dataset is stored with a version tag in MLflow (for ML tools) or Langfuse (for RAG agents). Changes to evaluation data require the same approval as changes to model code
- **Owned** — every dataset has a named owner (compliance advisor for regulatory agents, model scientist for ML tools). The owner approves additions, removals, and corrections
- **Separated** — training data, validation data, and holdout evaluation data are strictly separated. Evaluation data is never used for training or fine-tuning
- **Representative** — evaluation sets must cover edge cases, Urdu/bilingual inputs (where applicable), jurisdiction-specific scenarios, and adversarial examples. A 100-question PolicyQA eval set that only covers English circulars from 2024 is not representative
- **Auditable** — evaluation results (accuracy, precision, recall, failure cases) are logged per-run with the dataset version used. SBP examiners or auditors can request "show me the evaluation results for PolicyQA version X on dataset version Y"

```yaml
# Example: ML Model Tool governance config
model_name: score_credit_risk
model_type: supervised_classifier
registry: mlflow
current_version: v3.2.1
accuracy_floor: 0.82  # AUC-ROC minimum
drift_threshold_psi: 0.2  # Population Stability Index
shadow_period_days: 14
bias_review_cadence: annual
retraining_cadence: quarterly
rollback_target: v3.1.0  # previous approved version
eval_dataset_version: eval-credit-v2.3  # versioned, owned, auditable
eval_dataset_owner: model_scientist_lead
required_approvers:
  - model_scientist
  - compliance_reviewer
```

### 5.5 Custom Langfuse Scorers — Pakistan-Specific

```python
def sbp_circular_scorer(output, context):
    """Does output cite actual SBP circular references in correct format?"""
    # Check: BPRD/IH/DMMD circular number + date present
    # Check: cited regulation matches claim made

def shariah_compliance_scorer(output, context):
    """Does Islamic finance output reference correct AAOIFI standards?"""
    # Check: AAOIFI standard number cited
    # Check: Arabic term used correctly (Murabaha vs Musharakah)
    # Check: Scholar review flagged where required

def fmu_str_scorer(output, context):
    """Does STR draft contain all FMU-required fields?"""
    # Check: all 12 mandatory FMU STR fields present
    # Check: threshold amount stated correctly
    # Check: suspicious activity narrative present

def sbp_policy_qa_scorer(output, context):
    """For Policy Q&A — does answer contain verifiable citation?"""
    # Check: circular or regulation cited
    # Check: claim matches source content (cross-reference against KB)
    # Check: no fabricated regulatory references
```

---

## Part 5A — Digital Workforce Operating Model

Cognic agents are not background processes. They are digital workers — identifiable, accountable, governed, and performance-evaluated members of a bank's operational structure. This section defines how agents exist within a bank's organisation, how they interact with human colleagues, and how their performance is measured.

This is not a cosmetic framing layer. The identity framework, authority matrix, decision output model, and KPI structure defined here must be designed into the agent registry, decision history store, audit engine, portal, and governance agent from Brick 9 onward. Retrofitting these concepts after deployment is materially more expensive than designing for them now.

### 5A.1 AI Workforce Registry

Every Cognic agent deployed at a bank receives a formal identity record in the AI Workforce Registry. This record exists alongside the bank's HR system — not inside it, but mapped to it.

```python
class AgentIdentityRecord(BaseModel):
    # Core identity
    agent_id:               str        # COG-AI-001
    display_name:           str        # "Regulatory Policy Advisor"
    functional_title:       str        # "Senior Compliance Analyst — Regulatory Policy"
    department:             str        # "Compliance"
    division:               str        # "Regulatory Affairs" (optional — bank-dependent)
    deployment_date:        date       # First production deployment
    current_lifecycle_state: str       # Development | Pilot | Production | Autonomous | Retired

    # Organisational position
    reports_to:             str        # Human employee ID or another agent_id
    direct_reports:         list[str]  # Human employee IDs or agent_ids receiving prioritised work
    authority_level:        str        # Advisory | Operational | Supervisory (see 5A.3)
    authority_scope:        str        # Free-text scope definition per bank agreement

    # Technical linkage
    agent_class:            str        # "policy_qa" — maps to src/cognic/agents/
    model_tier:             str        # Tier 1 / Tier 2 / Tier 3
    sprint_contract_ref:    str        # Reference to active sprint contract
    tool_allowlist:         list[str]  # Tools this agent is permitted to call
    skill_allowlist:        list[str]  # Skills this agent is permitted to invoke

    # Performance
    kpi_profile_ref:        str        # Reference to KPI definition (see 5A.6)
    last_evaluation_date:   date | None
    last_evaluation_result: str | None # Exceeds / Meets / Below / Probation

    # Governance
    accuracy_gate_current:  float      # Current rolling accuracy
    accuracy_gate_target:   float      # Required for current state
    governance_owner:       str        # Human compliance officer responsible
    consent_scope:          str        # What customer data this agent may access
```

**Registry rules:**
- Every agent in production must have an identity record. No anonymous agents.
- Identity records are created during agent deployment and updated on state transitions, evaluations, and retirement.
- Identity records are queryable from the portal, the AI Governance Agent, and the audit engine.
- Identity records are included in SBP examination evidence packages.
- When an agent is retired, the record is preserved (never deleted) with a retirement date and reason.

### 5A.2 Organisational Graph and Reporting Lines

Agents exist within a bank's organisational structure. The reporting relationship between agents and humans takes two forms:

**Agent reporting to human (default for Wave 1-2):**

The agent produces output. A human supervisor reviews, approves, corrects, or rejects the output. The agent's performance is evaluated by the human supervisor. This is the standard compliance-reviewed model that banks and regulators already understand.

```
Chief Compliance Officer (human)
├── Senior Compliance Analyst — Regulatory Policy (COG-AI-001, PolicyQA)
├── Regulatory Intelligence Analyst (COG-AI-002, RegIntel)
├── AML Investigation Specialist (COG-AI-003, AML Agent)
└── Human compliance officers (3-5 FTEs)
```

**Human receiving AI-directed workflow (Wave 3+, requires explicit bank agreement):**

The agent analyses data, prioritises work items, and routes tasks to human workers. The human workers execute the tasks. A human supervisor governs the overall workflow and approves the agent's prioritisation logic.

**Critical distinction:** "human receiving AI-directed workflow" means operational task routing and priority management — not HR authority. The agent cannot hire, fire, promote, discipline, or evaluate human employees. The agent cannot override a human's professional judgment on a specific case. The agent cannot set compensation or working conditions. The agent routes work, suggests priorities, flags deadlines, and escalates overdue items. A human supervisor always governs the agent's authority to do this.

This distinction matters commercially (banks will buy task routing, they won't buy "AI bosses"), politically (board members and unions have opinions), and regulatorily (SBP will not accept autonomous HR-style authority over banking staff).

```
# Wave 3+ org model — task routing only, human-governed
Head of AML (human supervisor — governs agent's routing authority)
├── AML Investigation Specialist (COG-AI-003, AML Agent)
│   ├── Routes: prioritised case queue to investigators
│   ├── Routes: deadline alerts to investigators
│   ├── Routes: escalation flags to Head of AML
│   └── CANNOT: override investigator's case judgment
├── AML Investigator 1 (human — receives prioritised work from agent)
├── AML Investigator 2 (human — receives prioritised work from agent)
└── AML Investigator 3 (human — receives prioritised work from agent)
```

**Reporting line rules:**
- Wave 1-2: all agents report to a human supervisor. No exceptions.
- Wave 3+: agents may route work to humans only under a documented authority scope approved by the bank's governance committee.
- The organisational graph is configurable per bank — Cognic does not impose a fixed structure.
- Reporting lines are visible in the portal and included in governance reports.

### 5A.3 Authority Matrix

Each agent operates within a defined authority level. The authority level constrains what the agent can do and what requires human approval.

| Authority Level | What the Agent Can Do | What Requires Human Approval | Typical Wave |
|----------------|----------------------|------------------------------|-------------|
| **Advisory** | Analyse data, produce reports, answer questions, cite sources, flag risks. All outputs reviewed by a human before delivery. | Everything — agent produces, human decides. | Wave 1 |
| **Operational** | Execute defined workflows autonomously within guardrails. Route tasks. Generate alerts. Produce compliance packages. | Threshold changes. New workflow definitions. Changes to routing rules. Any action with external regulatory impact. | Wave 2-3 |
| **Supervisory** | Prioritise work queues. Set task deadlines. Monitor human task completion. Escalate overdue items to human supervisors. | Authority scope definition. Escalation policies. Any action that affects human employment terms. | Wave 3+ |

**Authority rules:**
- Authority level is defined per agent in the identity record.
- Authority level can only be increased through a formal governance review involving the bank's compliance officer and Cognic's AI Engineering Lead.
- Authority level increases require evidence of sustained accuracy above the relevant gate for at least 30 days.
- Authority level can be decreased instantly by any human with governance authority (CCO, CTO, or designated compliance officer).
- Authority level is logged in the audit trail. Every change is timestamped, attributed, and justified.
- The AI Governance Agent monitors authority level compliance — if an agent acts outside its authority scope, the action is blocked and escalated.

### 5A.4 Decision Options Model — The 2-3 Option Rule

Cognic agents do not make decisions. They present options. For every substantive decision surface, agents produce 2-3 ranked options with evidence, trade-offs, and a recommendation. The human executive selects.

```python
class DecisionOption(BaseModel):
    option_id:            int           # 1, 2, or 3
    title:                str           # Short label
    recommendation:       str           # What this option means
    supporting_evidence:  list[CitedSource]  # Cited references
    risk_assessment:      str           # What could go wrong
    trade_offs:           str           # What you gain vs what you lose
    confidence_score:     float         # 0.0 to 1.0
    estimated_impact:     str           # Business impact assessment

class DecisionOptionsResponse(BaseModel):
    context_summary:          str       # Situation overview
    options:                  list[DecisionOption]  # 2-3 options, ranked
    agent_recommendation:     int       # Which option the agent prefers
    recommendation_reasoning: str       # Why the agent prefers this option
    dissenting_considerations: str      # What the agent might be wrong about
    decision_deadline:        datetime | None  # If time-sensitive
    escalation_note:          str | None       # If any option triggers escalation
```

**Decision model rules:**
- Every decision-support agent must use the `DecisionOptionsResponse` schema as its primary output format.
- The compliance checker validates that options are presented (not a single directive), that evidence is cited, and that trade-offs are explicit.
- The decision history store records which option the human selected, with timestamp and reasoning.
- Agents that produce informational output (e.g., PolicyQA answering a factual question) may use a simpler response schema — the options model applies to recommendation and decision surfaces.
- The `dissenting_considerations` field is mandatory. Agents must articulate what they might be wrong about. This builds trust and demonstrates the system's awareness of its own limitations.

### 5A.5 Executive Decision Board

The Executive Decision Board is a portal surface where human executives see pending decisions from their reporting agents, select options, and track decision history.

```
Executive Decision Board — CCO View
─────────────────────────────────────
┌─ Pending Decisions (3)
│
│  1. [URGENT] PolicyQA — Circular BPRD-04-2026 Impact
│     3 options presented · Agent recommends: Option 2
│     Deadline: 48 hours · Filed: 2 hours ago
│
│  2. RegIntel — New AML Guideline Compliance Gap
│     2 options presented · Agent recommends: Option 1
│     No deadline · Filed: 1 day ago
│
│  3. AML Agent — Unusual Transaction Pattern (Account 4412-XXX)
│     3 options presented · Agent recommends: Option 3 (escalate to FMU)
│     Deadline: 24 hours · Filed: 6 hours ago
│
├─ Recent Decisions (last 30 days)
│  17 decisions made · 14 followed agent recommendation · 3 overridden
│
└─ Decision Quality
   Agent recommendation accuracy: 82% (based on outcome tracking)
```

**Board rules:**
- Every human with reporting agents sees their pending decisions in priority order.
- Decisions have optional deadlines. Overdue decisions are escalated.
- Decision history tracks whether the human followed the agent's recommendation or overrode it, and what the outcome was (when verifiable).
- The board feeds into the agent's KPI evaluation — recommendation follow-rate and outcome accuracy are measurable signals.

### 5A.6 KPI Framework and Performance Evaluation

Every agent has a defined KPI profile. KPIs are measured continuously and evaluated formally on a quarterly and annual basis.

**Standard KPI dimensions (apply to all agents):**

| KPI | Measurement | Source | Target |
|-----|-------------|--------|--------|
| Accuracy | Rolling accuracy on governed evaluation dataset | Langfuse eval pipeline | Per-agent gate (see Part 6) |
| Response quality | Human correction rate — % of outputs corrected by reviewers | Decision history store | <10% at production state |
| Recommendation follow-rate | % of decisions where human chose agent's recommended option | Executive decision board | >75% sustained (indicates trust) |
| Cost efficiency | Cost per session in PKR/USD | Langfuse + LiteLLM cost tracking | Below budget per environment |
| Latency | p95 response time | Langfuse trace duration | Per-agent NFR target |
| Availability | % uptime during business hours | Infrastructure monitoring | >99.5% |
| Escalation discipline | % of edge cases correctly escalated vs handled incorrectly | Decision history + reviewer corrections | >90% correct escalation |
| Compliance adherence | % of outputs passing compliance checker without modification | Compliance checker logs | >95% |
| Citation accuracy | % of cited sources verified as correct by citation verifier | Citation verifier logs | >98% |

**Agent-specific KPIs (examples):**

| Agent | Additional KPI | Target |
|-------|---------------|--------|
| PolicyQA | SBP circular coverage — % of active circulars in knowledge base | >95% |
| RegIntel | New circular detection lag — time from SBP publication to agent awareness | <24 hours |
| RM Copilot | Brief usefulness — RM edit rate on generated briefs | <15% edit rate |
| AML Investigation | SAR package completeness — % of SAR drafts requiring <2 revisions | >80% |

**Performance evaluation cadence:**

| Review | Frequency | Reviewer | Output |
|--------|-----------|----------|--------|
| Weekly operational review | Weekly | AI Engineering Lead + Compliance Advisor | Dashboard review, anomaly investigation |
| Quarterly performance review | Quarterly | CTO + Compliance Advisor + Governance Owner | Formal performance report, state promotion consideration |
| Annual performance evaluation | Annual | CEO + CTO + Compliance Advisor | Formal evaluation record, KPI target adjustment, authority level review |

**Quarterly performance report format:**

```
Agent Performance Review — Q1 2027
───────────────────────────────────
Agent ID:        COG-AI-001
Display Name:    Regulatory Policy Advisor
Department:      Compliance
Reports To:      Chief Compliance Officer
Authority Level: Advisory
Current State:   State 2 — Assisted Production

KPI Summary:
  Accuracy:                91.2% (target: 85%) ✅ EXCEEDS
  Correction rate:          4.3% (target: <10%) ✅ EXCEEDS
  Recommendation follow:   84% (target: >75%) ✅ EXCEEDS
  Cost/session:            PKR 3.2 (target: <5) ✅ MEETS
  Latency p95:             4.1s (target: <5s)  ✅ MEETS
  Availability:            99.7% (target: 99.5%) ✅ MEETS
  Escalation discipline:   93% (target: >90%)  ✅ MEETS
  Compliance adherence:    97% (target: >95%)  ✅ MEETS
  Citation accuracy:       99.1% (target: >98%) ✅ MEETS

Overall Rating: EXCEEDS EXPECTATIONS

State Promotion Eligible: YES — recommend evaluation for State 3
Authority Level Review: No change recommended this quarter
KPI Target Adjustment: Raise accuracy target to 90% for next quarter

Signed: _________________________ (Governance Owner)
Date:   _________________________
```

**Evaluation rules:**
- Performance reviews are stored in the decision history alongside agent outputs — part of the audit trail.
- State promotions require sustained KPI achievement for 30+ days plus governance owner sign-off.
- An agent receiving "Below Expectations" for two consecutive quarters triggers a mandatory review of its model configuration, retrieval pipeline, and prompt templates.
- An agent receiving "Probation" is downgraded to State 1 (100% human review) until performance recovers.
- Annual evaluations may adjust KPI targets upward (never downward without ADR justification).

### 5A.7 Spreadsheet Intelligence Layer

Banking executives live in spreadsheets. Agents must be able to consume, analyse, and reason over tabular data.

The Spreadsheet Intelligence Layer is a set of Layer A tools (deterministic, no LLM) that parse, extract, and summarise tabular data from Excel, CSV, and structured file formats. Agents use these tools to ground their reasoning in actual bank data.

```python
# Layer A tools — deterministic, no LLM
class SpreadsheetIntelligenceTools:
    """
    All tools in this class are Layer A (atomic, deterministic).
    They parse and compute. They do not interpret or recommend.
    Interpretation is the agent's job (Layer C).
    """

    def parse_excel(file: UploadedFile) -> StructuredTable:
        """Parse Excel/CSV into typed columnar data with metadata."""

    def compute_summary_statistics(table: StructuredTable, columns: list[str]) -> SummaryStats:
        """Mean, median, std, min, max, quartiles, null counts per column."""

    def detect_anomalies(table: StructuredTable, column: str, method: str) -> list[AnomalyRecord]:
        """Statistical anomaly detection (IQR, z-score). No ML, no LLM."""

    def compute_period_comparison(table: StructuredTable, period_col: str, value_col: str) -> PeriodComparison:
        """YoY, QoQ, MoM comparison with growth rates."""

    def pivot_and_aggregate(table: StructuredTable, group_by: list[str], agg: dict) -> StructuredTable:
        """Group-by aggregation with configurable functions."""

    def validate_against_schema(table: StructuredTable, expected_schema: TableSchema) -> ValidationResult:
        """Check column types, ranges, nullability against expected schema."""
```

**Where this fits in the architecture:**
- Layer A tools: `parse_excel`, `compute_summary_statistics`, `detect_anomalies`, `pivot_and_aggregate`, etc.
- Layer B skill: `spreadsheet_analysis_skill` — orchestrates parse → validate → summarise → anomaly detect → structure for agent consumption.
- Layer C agent: the domain agent (RM Copilot, Credit Proposal, etc.) receives the structured analysis and produces its `DecisionOptionsResponse` grounded in the data.

**Build timing:** Wave 2 (Month 6-8). Requires file ingestion (Brick 8 already supports file drop) and CBS adapter layer (Brick 44-47). The tools themselves are 3-5 days of implementation. The skill orchestration is 1-2 days. Agent integration is prompt configuration.

### 5A.8 Regulatory Positioning — The Language That Matters

The way Cognic describes the Digital Workforce model to regulators, bank boards, and compliance committees determines whether the product is welcomed or blocked.

**Use this language:**
- "AI-assisted decision support with full human oversight"
- "Digital workforce members operating under defined authority scopes"
- "Every AI action is traced, auditable, and revocable"
- "Human executives make the final decision — AI presents ranked options with evidence"
- "Performance-evaluated AI agents with formal governance reviews"
- "Task routing and workflow prioritisation under human supervisory authority"

**Never use this language:**
- "AI making decisions" — agents present options, humans decide
- "AI managing humans" — agents route tasks, human supervisors govern
- "Autonomous AI" — even State 3 agents have escalation paths and audit trails
- "AI replacing employees" — agents augment capacity, not headcount
- "AI boss" — agents prioritise workflows under human authority

**SBP-specific framing:**
SBP's current regulatory posture (as of early 2026) emphasises technology risk management, operational resilience, and management accountability. The Digital Workforce model aligns by ensuring: every AI agent has a human governance owner, every AI output is auditable, every AI authority scope is documented, every AI performance metric is reviewed by a human compliance officer, and every AI can be degraded or disabled instantly by human authority.

When Cognic applies for the SBP regulatory sandbox (second cohort), the Digital Workforce framework becomes a differentiator: "We don't just deploy AI — we manage AI the way you'd manage any employee, with identity, reporting lines, KPIs, and performance reviews."

---

## Part 6 — Accuracy-First Protocol

This section governs every engineering, product, and commercial decision. It is not a policy document. It is the operating system of the company.

### 6.1 Agent States

| State | Description | Who Sees Output | Entry | Exit |
|-------|-------------|-----------------|-------|------|
| 0 — Development | Mock data, no real users | Engineering team | Default | >80% on synthetic ground truth |
| 1 — Assisted pilot | Every output human-reviewed | Compliance officer reviews 100% | State 0 passed | >85% sustained 14 days |
| 2 — Assisted production | 20% random sample + all flags | Compliance reviews sample + flags | State 1 passed | >92% sustained 30 days |
| 3 — Automated | Escalations and anomalies only | Compliance reviews escalations | State 2 passed | Monthly audit; auto-rollback if <90% for 7 days |

### 6.2 Accuracy Gates by Agent

| Agent | State 0→1 | State 1→2 | State 2→3 | Measurement Method |
|-------|-----------|-----------|-----------|-------------------|
| Policy Q&A | 85% | 95% | 98% | 100 sampled queries vs SBP circular ground truth |
| Reg Intelligence | 82% | 90% | 95% | Compliance officer reviews impact assessments |
| KYC Monitor | 95% | 99% | 100% | Date math — verifiable, no excuse for error |
| AML Investigation | 78% | 88% | 92% | Senior compliance officer case review |
| SWIFT Repair | 80% | 92% | 95% | Resubmission success rate |
| Nostro Recon | 85% | 95% | 99% | Matching correctness on closed-period data |
| RM Copilot | 75% | 85% | 92% | RM edit rate on generated briefs |
| Credit Proposal | 72% | 85% | 90% | Credit officer modification rate |
| Shariah Compliance | 85% | 94% | 97% | Shariah scholar review of flagged items |
| Capital Adequacy | 99% | 100% | 100% | Math — must be deterministic for regulatory use |

### 6.3 The Pre-Coding Checklist

Before writing any agent, the following must be defined in writing:

```yaml
agent_name: [Name]
layer: [A/B/C]
model_tier: [1/2/3]
description: [One precise sentence]

input_specification:
  - what: [exactly what data the agent receives]
  - source: [which tool or skill provides it]

output_specification:
  - format: [exact schema, Pydantic model]
  - what_it_is_not: [what the agent must not decide]

success_metric:
  - definition: [specific, measurable, unambiguous]
  - measurement: [who measures, how many samples, what period]

failure_conditions:
  - [what constitutes an incorrect output]
  - [what constitutes a dangerous output]

escalation_triggers:
  - [numeric thresholds — no LLM judgment involved]

hard_stops:
  - [conditions that abort agent immediately]

hitl_gates:
  - gate: [what requires human approval]
  - approver: [who specifically]
  - sla: [hours]
  - mandatory: [true/false]

accuracy_gates:
  - state_0_to_1: [threshold %]
  - state_1_to_2: [threshold %]
  - state_2_to_3: [threshold %]

skills_used: [list]
tools_used: [list]
cross_agent_data_flows:
  - provides_to: [agent] [data type]
  - receives_from: [agent] [data type]

decision_history_capture:
  - correction_reasons: [DATA_ERROR/POLICY_GAP/EDGE_CASE/FORMAT/THRESHOLD/JUDGEMENT]
  - ceo_agent_relevant: [true/false]
```

This document is reviewed by the compliance advisor before any code is written. This is the engineering contract.

### 6.4 The Absolute Commercial Rule

**No commercial pressure ever moves an agent forward through accuracy gates.**

When a bank pushes for automation before the gate is met:

*"Our standard is non-negotiable. It protects you as much as it protects us. We have N days remaining in the evaluation window. We will meet the threshold. If we do not, we extend the assisted phase. We do not compromise accuracy for schedule."*

Holding this line is what earns the trust that allows gate 3 agents to be given consequential authority in year 3.

---

## Part 7 — Deployment Waves

### Wave 1 — Establish Trust (Months 1–6)

**Purpose:** Get inside the bank. Start the decision history clock. Prove we deliver exactly what we promise.

**What deploys (client-facing agents):**
- PolicyQA Agent (Tier 1 SLM) — RAG over SBP/SECP knowledge base, instant verifiable answers
- Regulatory Intelligence Agent (Tier 1 SLM) — monitors circulars, produces impact assessments
- RM Copilot Agent Phase 1 (Tier 1 SLM, demo-capability) — pre-meeting briefs on mock client profiles and knowledge base only. No CBS data in Phase 1. This is a capabilities preview that opens the second buyer persona (Head of Retail Banking) and showcases Wave 2 revenue value. It is NOT a production tool until CBS is connected in Wave 2.

**What AgentOS deploys automatically (platform component, not a billable agent):**
- AI Governance Agent — monitors all three client-facing agents, generates weekly governance report, produces SBP examination evidence package

**What we deliberately do not do in Wave 1:**
- No CBS integration (RM Copilot Phase 1 runs on mock profiles and knowledge base only)
- No write operations of any kind
- No autonomous actions
- No Tier 2/3 models required
- No Wave 2 agents regardless of client pressure

**Hardware required at bank:** Single server with 1x RTX 4090 or A100 40GB. Total hardware cost under PKR 3M.

**Success gate that unlocks Wave 2:** PolicyQA accuracy >95% sustained 30 days, measured on 100 sampled queries against SBP circular ground truth, reviewed by bank compliance officer. RM Copilot Phase 1 does not have a Wave 1 accuracy gate — it operates on mock data as a demo capability. Its accuracy gate begins in Wave 2 when CBS data is connected.

**Revenue:** PKR 2-3M pilot (discounted) · PKR 5-8M first full year

### Wave 2 — Operational Efficiency (Months 5–12)

**First CBS integration:** Read-only connectors to T24 or Finacle. Built once, reused for all banks on same platform.

**What deploys:**
- KYC Expiry Monitor (primarily a Skill — deterministic workflow)
- RM Copilot Phase 2 (Tier 2 model) — CBS-connected pre-meeting briefs with real client data, portfolio alerts, cross-sell signals, policy Q&A
- SWIFT Repair Assistant — diagnoses rejections, suggests fixes (80% as Skill, 20% as Agent)
- Nostro Reconciliation (Skill — deterministic matching, flags breaks)
- Payment Validation Skill — RAAST/IBFT/PRISM+ instruction validation
- Shariah Compliance Agent (Tier 2 model) — for Islamic banking clients
- Capital Adequacy Daily Skill — deterministic Basel III ratio calculation

**Note:** KYC Monitor, Nostro, Capital Adequacy are primarily Skills. The LLM is invoked only for edge cases requiring judgment. Do not implement these as agents.

**Temporal deployed here** — KYC overnight batch needs durable execution.

**Hardware upgrade:** Add 1-2x A100 80GB for Tier 2 model serving.

### Wave 3 — Revenue and Risk Intelligence (Months 10–18)

**Prerequisite:** 6+ months of decision history from at least one bank.

**What deploys:**
- AML Investigation Agent (Tier 2-3 model) — requires calibrated decision history
- Fraud Detection — BEC NLP + transaction anomaly
- Credit Proposal Agent (Tier 2 model) — full narrative with risk rationale
- Cross-Sell Signal Engine (NBA) — CLV + propensity + timing
- Portfolio Stress Monitoring
- Capital Adequacy Monitor expansion (daily Basel III ratios with trend analysis)
- FATCA/AEOI/CRS Detection Skill
- Correspondent Banking Monitor
- Regulatory Reporting Drafter

**Cross-bank learning activates.** Correction data from Bank 1 improves Bank 2's starting accuracy. Fine-tuning pipeline runs for first time (if >1,000 labeled decisions available).

### Wave 4 — Selective Automation (Months 16–24)

**What graduates to automated:**
- KYC expiry → auto-creates tasks without human initiation
- Nostro reconciliation → auto-matches breaks below defined threshold
- SWIFT standard repair → auto-resolves known rejection patterns
- Capital adequacy → auto-populates SBP return for compliance review

**What stays assisted permanently:**
- AML case closure (SBP requires human MLO sign-off)
- SAR/STR submission (legal liability — FMU requires human authorisation)
- Credit decisions above defined thresholds
- Any customer-facing decision

### Bank Intelligence Platform — Month 36+

**Three conditions that must all be met simultaneously:**
1. At least one accurate agent in each of the five domains
2. Minimum 10,000 labeled decisions from at least 3 banks
3. Fine-tuned model trained on domain-specific correction data

The platform is not rebuilt. It is the integration layer that connects domain agents already in production and routes cross-domain queries to the right combination. The orchestrator emerges from the ecosystem — it is not a separate build.

---

## Part 8 — Banking Domain Coverage

### 8.1 Full Domain Map with Wave Assignment

| Domain | Agent / Skill | Type | Wave | Model Tier |
|--------|--------------|------|------|------------|
| **Compliance** | Policy Q&A | Agent | 1 | Tier 1 |
| | Regulatory Intelligence | Agent | 1 | Tier 1 |
| | KYC Expiry Monitor | Skill | 2 | N/A (no LLM) |
| | Sanctions Batch Screen | Skill | 2 | N/A |
| | Shariah Compliance | Agent | 2 | Tier 2 |
| | AML Investigation | Agent | 3 | Tier 2-3 |
| | SAR Package Assembly | Skill | 3 | N/A |
| | FATCA/AEOI/CRS Scan | Skill | 3 | N/A |
| | Typology Screening | Skill + ML Tool | 3 | N/A (ML tool) |
| **Operations** | Payment Validation | Skill | 2 | N/A |
| | SWIFT Repair | Skill + Agent | 2 | Tier 1-2 |
| | Nostro Reconciliation | Skill | 2 | N/A |
| | Trade Finance / LC Check | Agent | 3 | Tier 2 |
| | Correspondent Banking Monitor | Agent | 3 | Tier 2 |
| | Circular Ingestion | Skill | 1 | N/A |
| **Revenue** | RM Copilot Phase 1 (demo-capability) | Agent | 1 | Tier 1 |
| | RM Copilot Phase 2 (CBS-connected) | Agent | 2 | Tier 2 |
| | Customer Intelligence Assembly | Skill + ML Tools | 2 | N/A (ML tools) |
| | Credit Proposal | Agent | 3 | Tier 2 |
| | Cross-Sell / NBA Engine | Agent + ML Tool | 3 | Tier 2 |
| | SME Credit Scoring | Skill + ML Tool | 3 | Tier 2 |
| | Gift/Offer Recommendation | ML Tool | 2+ | N/A (ML tool) |
| | Churn Prediction | ML Tool | 2+ | N/A (ML tool) |
| **Risk** | Portfolio Stress Monitor | Agent | 3 | Tier 2 |
| | Covenant Watch | Skill | 3 | N/A |
| | Fraud Detection | Agent + ML Tool | 3 | Tier 2 |
| | Model Risk Monitor | Agent | 3 | Tier 2 |
| **Treasury** | Capital Adequacy Daily | Skill | 2 | N/A |
| | Basel Ratio Calculation | Skill | 2 | N/A |
| | Regulatory Reporting Drafter | Agent | 3 | Tier 2 |
| | Liquidity Monitoring | Skill | 3 | N/A |
| **Cross-cutting** | AI Governance Agent | Agent | AgentOS core | Tier 1 |
| | Compliance Checker | Agent | AgentOS core | Tier 1 |
| | FRAML Signal Correlation | Skill | 3 | N/A (deterministic) |
| | Bank Intelligence Orchestrator | Agent | L0, built last | Tier 3 |

### 8.2 Pakistan-Exclusive Differentiators

These are agents/skills no Western vendor builds because they don't understand the market:

| Agent / Skill | Pakistan-Specific Reason |
|--------------|-------------------------|
| SBP Circular Intelligence | SBP circular taxonomy, BPRD/IH/DMMD format, cross-reference structure unique |
| FMU STR Compliance | FMU-specific format, 7-working-day deadline, PKR threshold (₨2.5M) |
| EFS/LTFF/TERF Scheme Advisor | Pakistan refinancing schemes — MENA banks use these for corporate clients |
| Remittance Corridor Monitor | $30B+ annual inflows · de-risking pressure on UAE/UK/US corridors |
| NADRA e-KYC Integration | CNIC verification unique to Pakistan identity infrastructure |
| SRB/FBR Tax Compliance | SRB Sindh, FBR federal — dual tax authority unique to Pakistan |
| Urdu Document Intelligence | Bilingual KYC, property docs, court orders — no Western model handles Urdu reliably |
| Islamic Banking Shariah Screen | Pakistan 20%+ Islamic assets · AAOIFI standard · local Shariah board requirements |

---

## Part 9 — Go-to-Market

### 9.1 The Build-First Rule

Do not approach any bank before the PolicyQA agent achieves >85% accuracy on 100 test questions drawn from real SBP circulars, running on realistic mock data.

**Mock data requirements before any bank meeting:**
- 50 realistic Pakistani commercial banking client profiles (textile exporters, pharmaceutical distributors, rice mills, construction companies, commodity traders)
- 12 months of realistic transaction history per client with seasonal patterns embedded
- Cross-sell signals hidden in the data for the RM Copilot to surface
- Early stress indicators embedded for the portfolio monitoring agent to find
- Real SBP circulars from sbp.org.pk (publicly available)
- Synthesised generic Pakistan credit policy

**The demo script:** *"Everything you see runs on realistic Pakistani banking mock data. The SBP knowledge base is real — those are actual SBP circulars, fetched from sbp.org.pk. When we connect to your T24, only the data source changes. The agents, the accuracy, and the governance framework are identical."*

### 9.2 SBP Regulatory Sandbox Strategy

**Action:** Apply to SBP's second regulatory sandbox cohort when announced (expected H1 2026). Proposed theme: AI-powered compliance automation for SBP circular monitoring and regulatory reporting.

**Benefits:** Regulatory legitimacy that no demo replicates. Structured path to bank access. Six months of controlled live testing with SBP oversight. Credibility multiplier for commercial sales.

**Parallel action:** Apply to SECP sandbox (year-round applications, 4+ cohorts completed) for AI/ML-themed solutions including AML/KYC.

### 9.3 The Phased Engagement Model

```
Pre-phase: Regulatory sandbox participation (if accepted) — 6 months

Discovery (Week 0)
  No product. No demo.
  One meeting: understand their specific pain.
  Output: Which 3 problems cost them the most time and risk?

Demo (Week 1-2)
  Product demo on mock data.
  The PolicyQA agent answers 10 SBP circular questions live.
  They ask the 11th question on the spot — we answer it correctly.

Pilot (Weeks 3-10)
  Phase 1 Compliance Intelligence: PKR 2-3M discounted
  PolicyQA + Reg Intel on knowledge base only.
  No CBS connection. No write operations.
  Deliver what we promised. Nothing more.

Phase 2 (Weeks 11-22)
  Trigger: Phase 1 accuracy gate met (>95%, 30 days).
  Add CBS read-only + RM Copilot + KYC Monitor.
  Price: Full Wave 2 module stack.

Phase 3 (Weeks 23-40)
  Trigger: Phase 2 adoption >70% of target user base.
  Add AML triage + Credit proposals + Risk monitoring.

Full platform
  Trigger: Accuracy gates met · 10,000+ decisions
```

### 9.4 The Pitch — One Honest Sentence

> *"We build banking agents that go live in 8 weeks, earn 95% accuracy before touching anything autonomously, and get smarter with every correction — across every bank we serve."*

**The Digital Workforce pitch (for CXO-level conversations):**

> *"We deploy AI employees into your bank — each with an identity, a department, a reporting line, measurable KPIs, and a performance review. Unlike human employees, every decision they make is traced, auditable, and instantly revocable. They present options; your executives decide."*

### 9.5 Target Client Sequence

| Order | Target | Tier | Rationale |
|-------|--------|------|-----------|
| 1 | Faysal Bank / JS Bank / Bank Alfalah | 2-3 | Faster procurement · relationship-driven · compliance pilot proof case |
| 1A | Allied Bank (ABL) — dual track | 1 | **Track 1 (Month 3-4):** Compliance intelligence to CCO (PolicyQA + RegIntel). **Track 1.5 (Month 6-8):** Customer Intelligence Assembly to CDO/Head of Retail — ABL already has CRM personas, debit card spend data, and semi-automated profiling. Cognic operationalizes and scales it. **Track 2 (Month 9-12):** RM Copilot Phase 2 with enriched profiles + gift/NBA recommendation ML models. ABL becomes the reference case for "Cognic turns your data into intelligence your RMs actually use." |
| 2 | Second mid-tier | 2-3 | Second case study · refine CBS adapter |
| 3 | NBP or similar | 1-2 | Government bank · different dynamics |
| 4 | HBL or MCB | 1 | Tier-1 entry after 2-3 case studies |
| 5+ | UAE (ADCB, Emirates NBD) | 1-2 | MENA entry · new jurisdiction config |

### 9.6 Pricing

**Product A — AgentOS Platform Licence (annual)**

| Bank Tier | Assets (PKR) | Annual Licence |
|-----------|-------------|----------------|
| Tier 3 | 50–200B | PKR 5–8M |
| Tier 2 | 200–500B | PKR 10–18M |
| Tier 1 | 500B+ | PKR 25–40M |

**Product B — Domain Agent Modules (annual, on top of platform)**

| Module | Annual Fee |
|--------|-----------|
| Compliance Intelligence (PolicyQA + RegIntel) | PKR 3M |
| RM Copilot | PKR 5M |
| KYC + AML Suite | PKR 6M |
| Payments Intelligence | PKR 4M |
| Capital Adequacy Monitor | PKR 4M |
| Islamic Finance Module | PKR 4M |
| Risk Intelligence Suite | PKR 7M |

**Product C — Implementation + Managed Service**
- One-time: PKR 3–8M per engagement
- Monthly managed: PKR 500K–2M

**Anchor client pricing strategy:** First 2-3 banks receive 50% platform licence discount in Year 1, converting to full pricing in Year 2 contingent on demonstrated ROI.

**Revenue trajectory (conservative):**

| Month | Banks | ARR |
|-------|-------|-----|
| 12 | 1-2 | PKR 15-25M |
| 18 | 3-4 | PKR 50-75M |
| 24 | 6-8 | PKR 120-180M |
| 30 | 10+ + MENA | PKR 250M+ |

---

## Part 10 — Team

### 10.1 Founding Four Roles

**CEO / Domain Lead** — Banking domain credibility that creates peer-level conversation with a bank CCO, CRO, or CTO. Handles all bank relationships, sales, and regulatory positioning. Technical knowledge is a bonus. Domain trust is mandatory.

**CTO / Platform Engineer** — Owns AgentOS. Deep expertise in vLLM/SGLang serving, Pydantic AI + LangGraph orchestration, Temporal, and on-prem Kubernetes. Must understand MoE model serving, INT4 quantization trade-offs, and air-gapped deployment. Has read and understood AWS's "Agentic AI in Financial Services" paper. Cannot be someone who builds demos — must be someone who builds production systems with audit trails.

**AI Engineering Lead** — Builds the domain agents. Expert in Pydantic AI prompt design, RAG pipelines, Langfuse integration, decision history capture, and guardrail implementation. Works with compliance advisor to ensure every agent's evaluation rubric is grounded in actual banking requirements.

**Compliance / Banking Advisor (part-time, equity)** — Former SBP examiner, banking compliance head, or banking lawyer. Does not write code. Reviews every agent's pre-coding checklist before implementation. Attends every bank pitch. Provides the credibility that no amount of technical capability substitutes. Equity compensated.

---

## Part 11 — Risk Register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| Bank sales cycle 12+ months | High | High | Free pilot · sandbox participation · anchor client early |
| LLM accuracy insufficient for banking | Medium | Critical | Tiered model strategy — use smallest model that meets gate. Accuracy gates prevent deployment |
| SBP AI regulation unfavourable | Low | High | BIAN alignment · audit trails · AI governance agent. Proactive SBP engagement |
| Competitor with deeper pockets enters Pakistan | Medium | Medium | Domain depth + on-prem + decision history moat = 3 years to replicate. 18-24 month window |
| CBS integration complexity (T24 versioning) | High | Medium | Mock adapter first · budget 2x time for first CBS · T24 Transact vs legacy R-series differences |
| Pakistan GPU access constraints | Medium | High | Data Vault Pakistan partnership · SLM-first architecture reduces requirements |
| Model landscape shifts (new frontier model) | High | Low | LiteLLM abstraction · model selection is runtime config · re-evaluate every 3-6 months |
| 40% agentic AI project cancellation rate | High (industry) | Medium | Our accuracy gates + AI governance = projects don't get cancelled |
| Team lacks banking depth | Medium | High | Compliance advisor covers · domain knowledge encoded in KB |
| Air-gapped deployment complexity | Medium | Medium | Zarf packaging · pre-bundled dependencies · tested playbook |
| Pakistan data protection law passes | Medium | Low | Architecture already designed for GDPR-equivalent compliance |
| Decision history slower than planned | Medium | Medium | Synthetic augmentation · start capture day 1 |
| Hardware cost at bank | Medium | Medium | SLM-first reduces from $200K to $5K for Wave 1 · present TCO analysis |

---

## Part 12 — What We Deliberately Excluded

| Excluded | Reason |
|----------|--------|
| "CEO Agent" external branding | Signals leadership replacement · kills sales before first meeting |
| Locked model choices in strategy doc | Landscape moves too fast. Model selection is a runtime config via LiteLLM |
| MLflow as primary LLM observability | Undecided on GenAI focus. Langfuse is purpose-built, self-hostable |
| TGI as LLM serving engine | Entered maintenance mode December 2025 |
| AutoGen/AG2 for agent framework | Effectively abandoned — teams advised to migrate |
| 30-month platform timeline | Optimistic · corrected to 36+ months |
| Temporal in Wave 1 | Premature complexity · design abstraction · deploy in Wave 2 |
| 35+ agent roadmap for year 1 | Scope creep · 8-10 agents done exceptionally > 35 done poorly |
| Cloud deployment default | Entire differentiation is on-prem · offering cloud dilutes the message |
| C-suite "digital twins" framing | Replacement framing · wrong for incumbent banking market |
| Full autonomy as selling point | Technology not ready · not legal · not sellable to regulated banks |
| Forking any existing codebase | Clean IP · clean architecture · no inherited technical debt |
| GPU procurement as bank prerequisite | SLM-first means Wave 1 runs on single consumer GPU |

---

## Part 13 — The Five PRD Questions (ANSWERED)

### 1. Official company and product name

Recommendation: **"Cognic"** works as both company and product name. Legal entity: Cognic Technologies (Private) Limited, registered in Pakistan. Product branding: "Cognic AgentOS" for the platform, "Cognic [Domain]" for modules (Cognic Compliance, Cognic Risk, etc.). The name is not taken in Pakistan's SECP registry (verify before filing). Alternative if unavailable: "RegMind" or "CompliMind" — keep the "Mind" suffix for brand consistency.

### 2. Primary user persona

**Name:** Sana Malik. **Title:** Head of Compliance / Chief Compliance Officer. **Bank:** JS Bank (Tier 2-3, ~PKR 150B assets, 350+ branches). **Experience:** 14 years in banking compliance, formerly at NBP and SBP examination department.

**Her day:** Arrives at 8am to 3-4 new SBP circulars from the previous week. Spends 2 hours determining which circulars affect which business units. Fields 15+ internal queries daily ("does this transaction comply with circular BPRD/xxx?"). Manages a team of 8 compliance officers reviewing KYC exceptions, AML alerts, and SAR filings. Prepares quarterly SBP examination evidence packages.

**Measured on:** Zero regulatory penalties, examination findings closure rate, SAR filing timeliness (<7 working days), KYC portfolio health (% current vs expired).

**Keeps her up at night:** Missing a critical SBP circular deadline, FMU rejecting a SAR for incomplete data, examination finding she can't explain.

**What she tells her boss after our demo:** *"This answered SBP circular questions in 30 seconds that take my team 2 hours. And it cited the exact circular reference. We need this before the next SBP examination."*

### 3. V1 scope — exactly 3 agents

**Agent 1: PolicyQA Agent.** Knowledge base: SBP circulars (2010-present), SBP Prudential Regulations, SECP banking group regulations. Target bank tier: All tiers — universal compliance need. Accuracy threshold: >85% on 100 ground-truth questions before first demo. >95% before production.

**Agent 2: Regulatory Intelligence Agent.** Knowledge base: SBP website monitoring (sbp.org.pk scrape), circular ingestion skill output. Target bank tier: All tiers. Accuracy threshold: >82% on impact assessment correctness for 20 test circulars.

**Agent 3: RM Copilot Agent Phase 1 (demo-capability).** Knowledge base: Mock client profiles (generated internally), SBP circulars (via search_circulars tool). Target bank tier: Tier 2–3 (relationship banking is primary revenue driver). Wave 1 version runs on mock client profiles — no CBS required. This is a capabilities preview that opens the second buyer persona (Head of Retail Banking) and showcases Wave 2 revenue value. It does NOT have an accuracy gate in Wave 1 — it is reviewed qualitatively by the team for realism and usefulness. Its production accuracy gate (>75% measured by RM edit rate) begins in Wave 2 when CBS data is connected.

> **Note on AI Governance Agent:** The AI Governance Agent is an AgentOS core component — built into the platform, always running, non-optional. It is not one of the three client-facing V1 agents. It monitors PolicyQA, RegIntel, and RM Copilot from day one, generates weekly governance reports, and produces SBP examination evidence packages. It is a platform differentiator, not a standalone product. It is covered under the AgentOS platform licence, not a separate module.

### 4. Direct competitors and differentiation

**Competitor 1:** NdcTech / Systems Limited — They implement Temenos; we build purpose-built AI agents that are CBS-agnostic and work alongside any core banking system.

**Competitor 2:** Internal bank IT teams — They take 18+ months and lack domain AI expertise; we deliver first value in 8 weeks with pre-built agents and accumulated decision history.

**Competitor 3:** Hawk AI (if they enter Pakistan via Riyadh) — They are cloud-dependent and don't understand SBP/FMU regulatory structure; we are on-prem native with Pakistan regulatory intelligence built in.

### 5. Month 12 success in numbers

- **ARR:** PKR 15-25M (1-2 banks, discounted pilot + first full-year conversions)
- **Live banks:** 2 (1 paying pilot, 1 in pilot stage)
- **PolicyQA accuracy:** >95% sustained 30+ days
- **RegIntel accuracy:** >90% on impact assessments
- **Labeled decisions in history store:** 2,000+
- **SBP regulatory sandbox:** Application submitted (if second cohort announced)

---

## Appendix A — 12-Week Build Sequence

| Week | What Gets Built | Gate Before Moving Forward |
|------|----------------|--------------------------|
| 1 | Project structure · pyproject.toml (uv) · Docker Compose · PostgreSQL + pgvector · Redis · RabbitMQ · HashiCorp Vault · Langfuse self-hosted · SQLAlchemy abstraction layer | All containers healthy · CRUD verified · Langfuse dashboard accessible · ORM dialect switching tested |
| 2 | AgentOS skeleton: LiteLLM gateway · vLLM local (Tier 1 dev model via Ollama) · BaseAgent with Pydantic AI · Tool registry · Three-pool enforcement scaffold · Data ingestion layer (REST webhook + DB polling) | Simple agent responds · tool registry works · LiteLLM routes correctly · webhook endpoint accepts test events |
| 3 | LangGraph integration: planner-executor-checker graph · sprint contract enforcement · human-in-the-loop gates · Langfuse tracing | Full harness cycle: plan → execute → check → log. Traces visible in Langfuse |
| 4 | Decision history store schema · Audit engine · Guardrails layer (input + output) · PII redaction for Pakistan patterns · AI Governance Agent (platform infra — monitors everything from this point forward) | Audit records written · guardrails fire · PII redacted correctly · AI Gov agent running and logging |
| 5 | SBP knowledge base: fetch all circulars · embed with embedding model · index in both pgvector (dense) AND PostgreSQL full-text (BM25) · Circular ingestion Skill · deploy reranker model | 500+ circulars indexed in both dense + BM25 · hybrid search returns correct top-3 results · Urdu queries benchmarked separately |
| 6 | Hybrid Retrieval Orchestrator + Citation Verifier · PolicyQA Agent: executor prompt · compliance checker · correction capture · sprint contract · Langfuse eval pipeline | Agent answers 20 test questions with cited SBP references verified by Citation Verifier · checker runs · corrections captured |
| 7 | PolicyQA accuracy evaluation: 100 ground-truth questions · sbp_policy_qa_scorer · Langfuse LLM-as-a-Judge experiments | >75% accuracy (below gate but directionally correct) |
| 8 | Regulatory Intelligence Agent: SBP website polling · circular ingestion Skill · impact assessment · jurisdiction-aware prompts | Agent correctly identifies affected units for 5 test circulars |
| 9 | RM Copilot Phase 1 (demo-capability): mock client profile generator · pre-meeting brief template · knowledge base integration · brief generation on mock data | Agent generates 10 realistic pre-meeting briefs from mock profiles · briefs include policy context from SBP KB |
| 10 | Full agent suite integration: PolicyQA + RegIntel + RM Copilot Phase 1 + AI Governance (platform) · bank portal UI (FastAPI + React) · demo script · auto-degradation monitor | End-to-end demo runs on mock data without intervention · governance dashboard shows all agent metrics |
| 11 | Accuracy evaluation: 100 questions PolicyQA · 20 circulars RegIntel · tune prompts and retrieval · evaluate model tiers. RM Copilot Phase 1 reviewed qualitatively (no accuracy gate — demo-only) | PolicyQA >80% · RegIntel >75% · RM Copilot briefs reviewed by team for realism |
| 12 | Demo polish · 50 mock client profiles · pitch materials · accuracy report · SBP sandbox application draft · Cognic Adoption Kit (prompt library + training materials) | PolicyQA >85% on 100 questions — minimum to approach any bank |

**Do not approach any bank before Week 12 gate is passed.**

---

## Appendix B — Brick-by-Brick Development Roadmap

This roadmap defines the exact sequence of development artefacts. Each brick depends on the bricks below it. Build bottom-up, never top-down.

### Foundation Layer (Weeks 1-2) — Build Once, Used By Everything

```
Brick 1:  Container Infrastructure
          Docker Compose: PostgreSQL 16 + pgvector, Redis 7, RabbitMQ, HashiCorp Vault
          All containers healthy, CRUD verified, network connectivity confirmed

Brick 2:  Langfuse Self-Hosted
          Docker deployment, PostgreSQL backend, dashboard accessible
          Observability from day 1 — every subsequent brick logs to Langfuse

Brick 3:  LiteLLM Gateway
          Model-agnostic routing, OpenAI-compatible API
          Routes to Ollama (dev), vLLM (staging), SGLang (production)

Brick 4:  vLLM / Ollama Local
          Tier 1 dev model running via Ollama for development (CPU, no GPU)
          vLLM config ready for GPU deployment when available

Brick 5:  Database Abstraction Layer (NEW)
          SQLAlchemy ORM with dialect abstraction
          PostgreSQL default, Oracle/SQL Server swap via deployment config
          VectorStoreAdapter interface: pgvector default, Qdrant/Oracle AI Vector Search pluggable
          All queries ORM-based — no raw SQL anywhere

Brick 6:  Tool Registry
          Register, discover, call any Layer A tool
          Type-safe tool definitions using Pydantic models
          Tool call logging to Langfuse

Brick 7:  Three-Pool Enforcement
          Architectural guardrail — rejects misclassified capabilities
          Runtime validation: tools have no LLM calls, skills have no LLM calls,
          agents must use harness

Brick 8:  Data Ingestion Layer (NEW)
          Kafka consumer (confluent-kafka-python) with schema registry support
          REST webhook endpoints (FastAPI) with mTLS/HMAC auth
          Database polling engine with CDC support
          File-based ingestion with cryptographic verification
          Unified event bus: all modes normalise to same internal event format
```

### Agent Infrastructure Layer (Weeks 2-4) — The Harness

```
Brick 9:  BaseAgent (Pydantic AI)
          Structured I/O with Pydantic models, model-agnostic via LiteLLM
          Tool binding, retry logic on schema violations
          Auto-trace to Langfuse on every call
          AgentIdentityRecord schema defined (Part 5A.1)
          DecisionOptionsResponse schema defined (Part 5A.4)
          Every BaseAgent instance carries its workforce registry ID in trace metadata

Brick 10: LangGraph Harness
          Planner → Executor → Checker state machine with LangGraph
          Conditional routing, checkpointing for crash recovery
          Time-travel debugging enabled

Brick 11: Sprint Contract Enforcer
          Validates task/success/hard-stop before any execution begins
          Rejects vague tasks, enforces tool/skill allowlists
          Max execution time enforcement

Brick 12: Compliance Checker Agent
          Skeptical evaluator, default-reject posture
          Three-dimension evaluation: regulatory, factual, quality
          Hard escalation trigger enforcement (numeric, not LLM-based)

Brick 13: Context Reset Manager
          90-minute timer for long-running agents
          Structured handoff artifact generation
          Seamless session continuation after reset

Brick 14: Decision History Store
          Append-only PostgreSQL table with CognicDecisionRecord schema
          Cryptographic signing of every record (via SQLAlchemy ORM — DB-agnostic)
          Indexes for correction analysis, fine-tuning queries

Brick 15: Audit Engine
          Every LLM call logged with full input/output/trace
          Examiner-accessible query interface
          Tamper-evident logging with hash chains

Brick 16: Guardrails Runtime
          Input: prompt injection detection, PII redaction, data freshness
          Output: decision authority check, regulatory language block,
          citation presence, escalation enforcement
          Pakistan PII patterns (CNIC, IBAN_PK, NTN, etc.)

Brick 17: Escalation Bus
          Redis queue for urgent escalations
          Temporal signal integration (abstracted for Wave 1 without Temporal)
          Bank portal notification endpoint
          HITL gate: blocks agent execution until human approval received

Brick 18: Langfuse Integration Layer
          Auto-trace every Pydantic AI agent call
          Custom scorer registration (SBP circular scorer, etc.)
          LLM-as-a-Judge evaluation pipeline
          Prompt versioning and A/B testing support

Brick 19: Auto-Degradation Monitor (NEW — from DBS PURE framework lesson)
          Real-time accuracy tracking via Langfuse traces
          Rolling 7-day accuracy window per agent
          Automated circuit breaker: if accuracy < State floor, degrade to assisted mode
          Alert to compliance officer + Cognic engineering
          Audit trail of all degradation events

Brick 20: Inline Citation Engine (NEW — from BNY Mellon Eliza lesson)
          Every agent output includes source traceability
          SBP circular reference (BPRD/IH/DMMD number + date + section + paragraph)
          Confidence score per claim
          "Verify" link showing original source chunk
          Compliance checker validates citation accuracy
```

### Knowledge Layer (Weeks 4-6) — The Brain

```
Brick 21: SBP Circular Fetcher (Tool)
          Downloads from sbp.org.pk — all BPRD, IH, DMMD circulars
          Handles PDF and HTML formats
          Stores raw files with metadata (date, type, reference number)

Brick 22: PDF/HTML Extractor (Tool)
          Extracts text from SBP circular formats
          Preserves section structure, table data, cross-references
          Handles Urdu text in bilingual documents

Brick 23: Document Embedder (Tool)
          Embedding model (Qwen embedding family or BGE-M3 class) via vLLM/Ollama
          Chunks documents at semantic boundaries (not fixed-size)
          Stores vectors via VectorStoreAdapter (pgvector default)

Brick 24: BM25 Keyword Index (NEW — hybrid retrieval)
          PostgreSQL full-text search index over all ingested documents
          tsvector columns with jurisdiction/date/regulation-type metadata filters
          Complementary to dense vector search — catches exact regulatory references
          that embedding similarity misses (e.g., "BPRD Circular No. 04 of 2023")

Brick 25: Reranker Model Deployment (NEW — hybrid retrieval)
          Cross-encoder reranker (Qwen reranker family or BGE-reranker class)
          Runs as separate lightweight inference endpoint via vLLM
          Takes top-K candidates from dense + BM25 recall and re-scores
          Urdu/bilingual documents benchmarked separately from English

Brick 26: Hybrid Retrieval Orchestrator (NEW — hybrid retrieval)
          Merges dense vector results + BM25 keyword results
          Applies metadata filters (jurisdiction, date, regulation type, source)
          Feeds merged candidates to reranker for final scoring
          Returns ranked results with source traceability metadata

Brick 27: Citation Verifier (NEW — hybrid retrieval)
          Validates that every agent claim maps to a specific source chunk
          Cross-references cited SBP circular number + section against knowledge base
          Flags unsupported claims before response delivery
          Integrated into compliance checker flow

Brick 28: Circular Ingestion Skill
          Orchestrates: fetch → extract → chunk → embed → index (both dense + BM25) → log_audit
          Deterministic workflow — no LLM involved
          Designed for Temporal migration in Wave 2

Brick 29: Search Tools Suite
          search_circulars(query, top_k) — hybrid retrieval over SBP circulars
          search_credit_policy(query, top_k) — hybrid retrieval over credit policy
          search_shariah_standards(query, top_k) — hybrid retrieval over AAOIFI
          All tools route through Hybrid Retrieval Orchestrator (Brick 26)

Brick 30: Banking Knowledge Base Assembly
          2,000-3,000 chunks across all sources indexed in both dense + BM25
          Quality gate: 50 test searches return correct top-3 results
          Separate Urdu/bilingual benchmark: 20 test queries in Urdu
```

### Wave 1 Agents (Weeks 6-10) — First Value

```
Brick 31: PolicyQA Agent
          Pydantic AI agent using hybrid retrieval search tools
          Answers policy questions with inline SBP circular citations (via Citation Verifier)
          Runs through full harness: plan → execute → check → log
          Every query becomes a decision history record

Brick 32: PolicyQA Accuracy Scorer
          100 ground-truth questions with verified answers
          Langfuse LLM-as-a-Judge evaluation pipeline
          Automated accuracy tracking over time
          Evaluation dataset is a governed asset: versioned, owned by compliance
          advisor, changes require approval (see Section 5.4D)

Brick 33: Regulatory Intelligence Agent
          Monitors SBP website for new circulars
          Produces impact assessment: affected business units, deadlines, actions
          Jurisdiction-aware prompts (Pakistan first, UAE/KSA config ready)

Brick 34: RegIntel Accuracy Scorer
          20 circular impact assessments evaluated by compliance advisor
          Evaluation dataset is a governed asset: versioned, owned by compliance
          advisor, changes require approval (see Section 5.4D)

Brick 35: RM Copilot Phase 1 (demo-capability)
          Pydantic AI agent with search_circulars tool + mock client profiles
          Generates pre-meeting briefs: client summary, policy context, talking points
          Runs on mock data only — no CBS connection
          Demonstrates Wave 2 revenue value to bank CTO/Head of Retail
          No accuracy gate in Wave 1 — qualitative review only

Brick 36: AI Governance Agent
          Monitors PolicyQA + RegIntel accuracy from Langfuse traces
          Generates weekly governance report (accuracy trends, drift detection)
          Triggers auto-degradation monitor (Brick 19) when thresholds breached
          Generates quarterly agent performance reviews (Part 5A.6)
          Monitors authority level compliance — blocks out-of-scope actions
          Built into AgentOS core — non-optional

Brick 37: SBP Examination Evidence Package Generator
          Produces audit-ready PDF: agent decisions, accuracy metrics,
          guardrail activations, escalation history, human override log
```

### Presentation Layer (Weeks 10-12) — Demo Ready

```
Brick 38: Bank Portal API (FastAPI)
          Agent query endpoints, authentication, rate limiting
          Governance dashboard API, audit viewer API
          AI workforce registry API (identity records, org graph, KPIs)
          Executive decision board API (pending decisions, option selection, decision history)
          WebSocket for real-time agent status

Brick 39: Bank Portal UI (React)
          Query interface: ask SBP circular questions, see cited answers
          Governance dashboard: accuracy charts, agent health, drift alerts
          Audit viewer: decision history browser, correction interface
          AI workforce view: org chart, agent profiles, authority levels, KPI summaries
          Executive decision board: pending decisions, option selection, decision log
          Adoption dashboard: team usage patterns, time savings metrics (NEW)

Brick 40: Mock Data Generator
          50 Pakistani commercial banking client profiles
          Textile exporters, pharma, rice mills, construction, commodity traders
          12 months realistic transaction history with seasonal patterns
          Cross-sell signals and early stress indicators embedded

Brick 41: Cognic Adoption Kit (NEW — from JPMorgan "AI Made Easy" lesson)
          50+ banking-specific prompt library for compliance officers
          "Cognic Made Easy" training session materials (2-hour workshop)
          First 30 days onboarding program with daily tips
          Agent performance review template (quarterly, Part 5A.6)
          AI workforce onboarding guide for bank HR/governance teams
          Adoption metrics dashboard template
          This is NOT optional — it ships with every bank deployment

Brick 42: Demo Script & Materials
          End-to-end demo flow: 10 pre-selected questions + live Q&A
          Pitch deck for CCO/CTO audience
          TCO comparison: Cognic vs manual compliance team

Brick 43: Accuracy Report
          Publishable accuracy metrics for bank meetings
          PolicyQA >85% verified, RegIntel >82% verified
          AI Governance report sample
          Gate: This is the minimum to approach any bank
```

### Wave 2 Bricks (Months 5-12) — CBS Integration

```
Brick 44: CBS Adapter Abstraction Layer
          Interface definition for T24/Finacle/FLEXCUBE
          Read-only in Wave 2, write operations gated for Wave 3+
          Version-aware: T24 Transact vs legacy R-series handled
          Oracle/SQL Server/PostgreSQL CBS backends supported natively

Brick 45: T24 Read Adapter
          get_account, get_facility, get_transactions, get_customer,
          get_collateral, get_kyc_status — all via T24 API
          Connection pooling, error handling, circuit breaker

Brick 46: Kafka Consumer Deployment (CONDITIONAL — bank-infrastructure-dependent)
          Deploy only when bank already runs Kafka streaming infrastructure.
          Most Pakistani Tier 2-3 banks (JS Bank, Faysal Bank, Bank Alfalah) do NOT run Kafka.
          For these banks: use DB polling (Brick 8) or REST webhooks as primary integration.
          For Tier 1 banks (HBL, MCB, UBL) that may run Kafka: deploy this brick.
          Connect to bank's Kafka topics for real-time transaction events.
          Schema registry integration for typed deserialization.
          Consumer group management, exactly-once processing.
          Feeds transaction data to AML, fraud, and payment validation agents.
          Default Wave 2 integration path: DB polling → REST webhook → Kafka (in order of bank readiness).

Brick 47: Bank Data Readiness Engine (NEW — from JPMorgan JADE lesson)
          Inventory bank's data sources (CBS, data warehouse, file shares)
          Profile data quality (completeness, freshness, consistency)
          Generate gap analysis report and remediation plan
          This engagement phase creates switching-cost moat

Brick 48: Temporal Deployment
          Durable execution for overnight batch workflows
          Worker fleet configuration for bank infrastructure
          Integration with LangGraph harness (Temporal underneath)

Brick 49-57: Wave 2 Skills and Agents
          KYC Expiry Check Skill, Customer Intelligence Assembly Skill (replaces Client 360),
          RM Copilot Phase 2 (Tier 2, CBS-connected), SWIFT Repair Skill + Agent,
          Nostro Reconciliation Skill, Payment Validation Skill,
          Shariah Compliance Agent (Tier 2), Capital Adequacy Daily Skill,
          Basel Ratio Skill

Brick 58: ML Model Tool Infrastructure (NEW)
          MLflow Model Registry deployed (versioning, aliases, promotion)
          Model serving endpoint (BentoML or KServe for traditional ML models)
          Training pipeline template (feature store → train → evaluate → register)
          First ML tools: score_customer_persona, predict_churn
          score_gift_recommendation: generic model trained on mock Pakistani
          retail data at launch. Per-bank calibration using bank-provided
          persona labels during Wave 2 onboarding engagement.

Brick 59: Customer Intelligence Extraction Tools (NEW — ABL-driven)
          extract_spending_pattern (POS/debit card/mobile app data)
          extract_travel_pattern (ATM location/POS merchant city)
          extract_digital_behavior (app/web session data)
          extract_family_structure (transaction-inferred, privacy-tagged)
          ProfileInferenceDisclosure for every inferred field

Brick 60: Model Evaluation Pipeline
          Quarterly accuracy gate test suite against latest open-source models
          Shadow deployment framework (new model runs parallel, not served)
          Langfuse A/B experiment comparison
          If new model beats current by >3%, initiate 2-week shadow test
          All evaluations run against versioned, governed evaluation datasets
          (see Section 5.4D). No model promotion without documented eval results.

Brick 61: Reviewer Workbench
          Case queue with priority by agent, severity, SLA deadline
          Inline evidence pane with click-through to original source
          Diff view between agent draft and human correction
          Escalation / approval / rejection with reason codes
          SLA tracking, decision-history capture, examiner PDF export

Brick 62: Enterprise Control Plane (deploy before first bank production)
          Argo CD for GitOps, SPIFFE/SPIRE for workload identity,
          OPA Gatekeeper/Kyverno for policy-as-code
          Deployment promotion tied to MLflow Model Registry status
          NOT part of 12-week build — deployed Month 4-5

Brick 63: Document Intelligence Engine (NEW — Wave 2, Urdu differentiation surface)
          OCR pipeline: PaddleOCR (Urdu + English + Arabic) or Tesseract 5 with Urdu traineddata
          Layout analysis for scanned documents (property papers, KYC packs, trade docs)
          Table extraction from scanned regulatory documents and financial statements
          Mixed Urdu/English document handling with language detection per text block
          Post-OCR correction using Tier 1 LLM for Urdu text normalisation
          Input sources: scanned SBP circulars (older archives), CNIC copies, utility bills,
          property valuation reports, LC/trade documents, court orders, Shariah board rulings
          This is where "we handle Urdu" becomes a concrete, testable, benchmarked capability
          — not a marketing claim. Urdu OCR accuracy benchmarked separately.
          GOVERNANCE: OCR-extracted content carries a per-field confidence score.
          Below-threshold extractions (configurable, default <85% character confidence)
          are flagged for human verification before any downstream agent uses them.
          OCR output must NEVER directly drive adverse decisions (credit denial,
          account closure, AML escalation) without human review of the source document.
          This keeps the governance pattern consistent across structured data, ML,
          LLM, and OCR-derived content.
```

### Wave 3 Bricks (Months 10-18) — Revenue & Risk

```
Brick 64-74: Wave 3 Skills and Agents
          AML Investigation Agent (Tier 2-3), STR Package Assembly Skill,
          Fraud Detection Agent (with score_fraud_risk ML tool),
          Credit Proposal Agent (Tier 2, with score_credit_risk ML tool),
          Cross-Sell Signal Engine (with predict_next_best_action ML tool),
          Portfolio Stress Monitor,
          FATCA/AEOI/CRS Detection Skill, Correspondent Banking Monitor,
          Regulatory Reporting Drafter (Tier 2),
          Fine-tuning Pipeline (LoRA on domain correction data),
          Cross-bank Learning Engine (federated learning — see Brick 77)

Brick 75: FRAML Signal Correlation Skill (NEW)
          Cross-references fraud agent outputs + AML agent outputs per customer
          Deterministic set intersection and network matching (Layer B, no LLM)
          Surfaces correlated signals that siloed compliance/fraud teams miss
          Creates unified case view for Reviewer Workbench
          CROSS-FUNCTIONAL ACCESS GOVERNANCE:
          Banks maintain separate fraud and AML teams with distinct mandates.
          Merging signals into a shared view requires explicit role-based visibility:
          - AML compliance officers: see full AML + correlated fraud signals
          - Fraud investigators: see full fraud + correlated AML signals
          - RMs: see NO fraud/AML investigation detail — only a flag that
            says "active investigation, do not onboard/extend" (no case specifics)
          - Compliance director / MLRO: sees everything (full FRAML view)
          - AI Governance / audit: sees metadata and correlation logs, not case content
          Role-based access enforced by check_role tool at Reviewer Workbench level.
          Configured per bank during deployment — not hardcoded.
          Banks will ask about this in security review. Have the answer ready.

Brick 76: Typology Registry + Screening Skill (NEW — competitive moat)
          Pakistan-specific typology registry (8 typologies at launch)
          classify_transaction_typology ML Model Tool
          Typology screening skill runs known criminal blueprints against patterns
          AML agent cites typology ID and FATF reference in SAR narrative
          SBP examiners can see which typologies are being monitored

Brick 77: Federated Learning Coordinator
          Flower framework (MIT license) integration
          Each bank trains locally on correction data
          Model weight aggregation without raw data transfer
          Privacy-preserving cross-bank intelligence
          Activated when 3+ banks are live

Brick 78: Digital Session Telemetry Adapter (Wave 3+, CONDITIONAL)
          Mode 5 ingestion for digitally mature banks only
          Device fingerprint, IP/geolocation, login anomaly, VPN detection
          Feeds Fraud Detection Agent and FRAML Correlation Skill
          Deploy for Tier 1 Pakistani banks and MENA expansion banks
```

### Wave 4 Bricks (Months 16-24) — Automation & Scale

```
Brick 79-83: Automation Graduation
          Automation Graduation Framework (rules for assisted → automated),
          KYC Auto-Task Creator, SWIFT Auto-Resolver,
          Nostro Auto-Matcher, Capital Adequacy Auto-Populate
```

### Platform Bricks (Month 24+) — Intelligence Layer

```
Brick 84-89: Bank Intelligence Platform
          Domain Agent Framework (L1 for each of 5 domains),
          Cross-Domain Query Router,
          Bank Intelligence Orchestrator (L0, Tier 3 model),
          Jurisdiction Config: UAE (CBUAE/AMLSCU),
          Jurisdiction Config: KSA (SAMA/SAFIU),
          MENA CBS Adapters
```

**Total: 89 bricks across 5 waves over 36+ months.**

The first 43 bricks (Weeks 1-12) are the MVP. Everything before Brick 31 is infrastructure. **Brick 31 (PolicyQA Agent) is the first moment of customer-visible value.** Brick 43 (Accuracy Report) is the gate to approaching any bank.

**Strategic sequencing note:** Customer intelligence (Bricks 49-59) is a Wave 2 expansion capability. Wave 1 deploys compliance intelligence only. No customer profiling tools, ML model tools, or behavioral extraction capabilities are built or marketed before compliance accuracy gates are met. Compliance earns trust; customer intelligence expands value.

---

## Appendix C — Cross-Agent Data Flow Map

Define before coding. Every agent's input must come from a tool or skill. No agent calls another agent's internal logic directly.

```
circular_ingestion_skill
  └── produces: indexed circular chunks in pgvector + BM25 index
      consumed by: PolicyQAAgent (via hybrid retrieval search tools)
                   RegulatoryIntelAgent (reads ingestion output)

customer_intelligence_assembly_skill (replaces client_360_assembly_skill)
  └── produces: CognicCustomerIntelligenceProfile
      (banking + spending + travel + digital + family + persona)
      consumed by: RMCopilotAgent (pre-meeting briefs with full intelligence)
                   CreditProposalAgent (enriched risk context)
                   AMLInvestigationAgent (behavioral context for investigation)
                   score_gift_recommendation ML tool (input features)
                   predict_churn ML tool (input features)
                   predict_next_best_action ML tool (input features)

kyc_expiry_check_skill
  └── produces: [ExpiringCustomer] list + tasks created
      consumed by: KYCDirectorAgent (for portfolio view)
                   ComplianceDomainAgent (for monitoring)

basel_ratio_skill
  └── produces: CapitalRatioReport (CET1, LCR, NSFR)
      consumed by: CapitalAdequacyMonitorAgent
                   BankIntelligenceOrchestrator (treasury domain view)

calc_ecl (tool) + calc_pd (tool) + score_credit_risk (ML tool)
  └── produces: ECLResult, PDEstimate, CreditRiskScore
      consumed by: CreditProposalAgent
                   PortfolioStressMonitor

str_package_assembly_skill
  └── produces: FMUSTRDraft (structured, not submitted)
      consumed by: AMLInvestigationAgent (adds narrative + typology citation)
      HITL gate: submission always requires human authorisation token

typology_screening_skill
  └── produces: [TypologyMatch] with FATF reference + indicator list
      consumed by: AMLInvestigationAgent (cites in SAR narrative)
                   FRAML signal correlation skill (cross-references with fraud)

framl_signal_correlation_skill
  └── produces: unified case view correlating fraud + AML signals
      consumed by: Reviewer Workbench (unified case display)
                   AMLDirectorAgent (for portfolio-level FRAML risk view)
```

---

*Document version 4.4 · March 2026 · STRATEGY FROZEN*
*Status: Strategy locked. Principles, architecture, and governance decisions are final. Implementation ADRs (Architectural Decision Records) may extend details, add bank-specific accommodations, and capture discovery findings without changing the principles defined here. No new strategy rewrites — build.*

*Final polish (v4.4 freeze):*
*— Consent Ledger added as named AgentOS platform component with ConsentRecord schema. Customer Intelligence Assembly Skill enforces consent status architecturally — not policy-only.*
*— Evaluation datasets defined as first-class governed assets. Every RAG agent and ML Model Tool must have versioned, owned, separated, representative, auditable evaluation data. Added to ML governance section and YAML config.*
*— Hardware planning reference table explicitly labelled as illustrative benchmark references with disclaimer against procurement commitment.*
*— Document Intelligence Engine (Brick 63) governance added: OCR-extracted content carries per-field confidence scores, below-threshold extractions flagged for human verification, OCR output never directly drives adverse decisions.*
*— FRAML cross-functional access boundaries defined (Brick 75): role-based visibility for AML officers, fraud investigators, RMs, MLRO, and audit. Configured per bank. Enforced by check_role tool at Reviewer Workbench level.*

*Prior changes: See v4.4 patch notes and v4.3 changelog for full v3.0→v4.4 history.*

---

*v5.0 changelog (April 2026):*

*— NEW: Part 5A — Digital Workforce Operating Model (8 sections)*
*— 5A.1: AI Workforce Registry with AgentIdentityRecord schema (employee ID, department, reporting line, authority level, KPI profile, governance owner)*
*— 5A.2: Organisational Graph — agent-to-human and human-receiving-AI-workflow models with clear distinction: task routing ≠ HR authority*
*— 5A.3: Authority Matrix — Advisory / Operational / Supervisory levels with promotion, demotion, and audit rules*
*— 5A.4: Decision Options Model — DecisionOptionsResponse schema enforcing 2-3 ranked options with evidence, trade-offs, and mandatory dissenting_considerations*
*— 5A.5: Executive Decision Board — portal surface for pending decisions, option selection, decision quality tracking*
*— 5A.6: KPI Framework and Performance Evaluation — 9 standard KPIs, agent-specific KPIs, quarterly review format, annual evaluation, probation rules*
*— 5A.7: Spreadsheet Intelligence Layer — Layer A tools for Excel/CSV parsing, anomaly detection, period comparison*
*— 5A.8: Regulatory Positioning — approved vs prohibited language for SBP, bank boards, and compliance committees*
*— UPDATED: Part 1.1 — company description now reflects digital workforce positioning*
*— UPDATED: Part 1.2 — "What We Are Not Building" clarified: agents augment capacity, not headcount; task routing, not HR authority*
*— UPDATED: Part 5.1 — AgentOS component tree expanded with AI workforce registry, performance evaluation engine, executive decision board*
*— UPDATED: Part 5.3 — CognicDecisionRecord extended with agent_department, agent_authority_level, reports_to, and decision option tracking fields (options_presented, agent_recommended, human_selected, followed_recommendation)*
*— UPDATED: Brick 9 — AgentIdentityRecord and DecisionOptionsResponse schemas added as requirements*
*— UPDATED: Brick 36 — AI Governance Agent now generates quarterly performance reviews and monitors authority compliance*
*— UPDATED: Brick 38 — Bank Portal API now includes workforce registry API and executive decision board API*
*— UPDATED: Brick 39 — Bank Portal UI now includes org chart view, agent profiles, and executive decision board*
*— UPDATED: Brick 41 — Adoption Kit now includes agent performance review template and AI workforce onboarding guide*
*— UPDATED: Part 9.4 — Digital Workforce pitch added for CXO conversations*
*— No bricks added or removed. No timeline changes. No infrastructure changes. The Digital Workforce is a framework layer on existing AgentOS components.*

*Next actions:*
*1. Update Enterprise Development Plan v1.1 → v1.2 to reflect v5.0 schema requirements in affected bricks*
*2. Update Claude Code brick pack to include workforce identity requirements in Bricks 9, 36, 38, 39, 41*
*3. ADR pack — document implementation decisions as they arise*
*4. Brick 1–12 delivery plan — begin with `docker compose up`*
*5. First benchmark/evaluation datasets — PolicyQA 100-question ground truth, RegIntel 20-circular impact assessment set*
