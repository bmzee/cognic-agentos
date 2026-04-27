# ADR-013 — Model Lifecycle & Fine-Tuning Boundary

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Banks deploying AgentOS have a real, near-term need: customise the underlying language and embedding models on their own data — internal regulatory corpora, PII-redacted customer interactions, bank-specific terminology, persona-aligned tone. Sovereign self-hosted-first posture (per Cognic Master Strategy v5.0) is hollow if the bank can only run *somebody else's* model.

Three deployment realities make this concrete:

1. **Foundation models commoditise.** The premium banks pay for is governance + customisation, not the base model. Year-on-year, fine-tuned variants of open weights (Qwen3, Llama 3, Mistral) match or beat proprietary cloud models on bank-specific tasks at a fraction of the inference cost — when banks own the fine-tuning loop.
2. **Regulatory data residency forbids sending bank data to commercial fine-tuning APIs.** Banks must run the fine-tuning workflow inside their own boundary or via a vendor with explicit single-tenant guarantees.
3. **The fine-tuning ecosystem is mature.** Axolotl, HuggingFace transformers + PEFT, Unsloth, LLaMA-Factory cover QLoRA / LoRA / full fine-tune / DPO / RLHF in production. Karpathy's nanochat is brilliant teaching code but not production fine-tuning infrastructure.

The architectural question is not "should AgentOS support fine-tuning" — banks will demand it — but **where the fine-tuning workflow lives** relative to the AgentOS runtime boundary.

## Decision

Split the responsibility cleanly along the runtime / batch boundary:

### What AgentOS owns (this repo, Wave 1)

A **Model Registry primitive** — a metadata + audit layer for the lifecycle of every model AgentOS routes a request through. AgentOS does not train models, does not store weights, does not orchestrate GPU jobs. It tracks:

| Field | Purpose |
|---|---|
| `model_id` | Stable identity (e.g. `cognic-tier1-bank-acme-v3`) |
| `base_model` | The foundation model the fine-tune started from (e.g. `qwen3-8b-instruct`) |
| `version` | Semver |
| `kind` | `foundation` / `fine_tune` / `adapter` (LoRA/QLoRA artefact attached to a base) / `embedding` |
| `recipe_hash` | SHA256 of the fine-tuning config + hyperparameters (reproducibility) |
| `training_data_fingerprint` | SHA256 of the training corpus manifest (no raw data — just the manifest) |
| `eval_results_ref` | Pointer to the ADR-010 eval harness run that validated this model |
| `signature_digest` | cosign signature of the model artefact (matches the trust gate from ADR-002) |
| `serving_endpoint` | Where the model is loaded — vLLM/SGLang URL, or the LiteLLM alias that fronts it |
| `lifecycle_state` | `proposed` → `eval_passed` → `tenant_approved` → `serving` → `deprecated` → `retired` |
| `iso_42001_evidence` | Tagged events for A.8.5 (development), A.7.4 (impact), A.6.2.6 (responsibilities), A.7.6 (risk), A.10.2 (transparency) |

Portal API endpoints (added in Sprint 9.5):
```
POST   /api/v1/models                  register a new model
GET    /api/v1/models                  list, filter by tenant + state
GET    /api/v1/models/{id}             detail incl. lifecycle history
POST   /api/v1/models/{id}/promote     transition to next lifecycle state (RBAC-gated)
POST   /api/v1/models/{id}/retire      stop routing to this model on this tenant
GET    /api/v1/models/{id}/audit       hash-chained audit events for this model
GET    /api/v1/models/{id}/usage?from  per-tenant invocation counts derived from decision_history
```

Provider-honesty endpoint (per ADR-007) extended: every recent-call entry now includes the registered `model_id`, not just the LiteLLM alias. Banks see exactly which fine-tune handled which case.

Decision-history events tagged with `model_id` so examiners can prove **which model version handled which case** at any point in time. Model promotions hash-chain into `decision_history` — the model lifecycle becomes part of the tamper-evident audit trail.

### What AgentOS does NOT own

Fine-tuning workflows themselves. AgentOS does not embed Axolotl, HuggingFace PEFT, Unsloth, or any training framework. It does not vendor `nanochat` as a production dependency. Training is **batch GPU work** — different infrastructure, different lifecycle, different audit shape from runtime inference.

### What lives in **Cognic Forge** (separate Wave 2 repo)

A separate Cognic product, repository, and lifecycle for the actual fine-tuning workflow:

- **Recipes**: Axolotl-driven config templates for QLoRA / LoRA / full fine-tune, plus DPO/RLHF templates for Wave 3
- **Data pipeline**: PII filter (with banks' own DLP rules), license tracker, dedup, curriculum sequencing
- **Compute orchestration**: Slurm / Kubernetes-with-GPU-operator job submission; AgentOS does not assume any specific scheduler
- **Eval-during-training**: integrates with ADR-010 eval harness — every checkpoint runs the bank's eval corpus; Forge attaches eval results to the model record at registry-publish time
- **Signing pipeline**: produces cosign-signed model artefacts that satisfy the AgentOS trust gate (ADR-002)
- **Registry publish hook**: when a fine-tune completes + passes eval thresholds, Forge calls `POST /api/v1/models` on the bank's AgentOS instance to register the new model

Forge is **bank-installable, bank-extensible** — same plugin discipline as agent / tool / skill packs (per ADR-002). Banks who want to write their own fine-tuning workflow ship their own pack; Forge is the Cognic-published reference implementation.

### Position of Karpathy's nanochat

**Teaching artefact, not production dependency.** Specifically:

- A `examples/nanochat-walkthrough/` directory in the future Forge repo demonstrates the full pipeline for engineers who want to understand what's happening under the hood. Banner: "this is teaching code — for production fine-tuning use the Axolotl recipes."
- Useful for: developer onboarding, demos that don't require GPU clusters, weekend hacks, architectural micro-experiments (Karpathy himself uses nanochat for autoresearch architecture sweeps)
- NOT useful for: production fine-tuning of foundation models (no QLoRA, no multi-node, no PII filtering, no compliance audit chain)

### Supported fine-tuning frameworks (none vendored, all bank-pluggable)

| Framework | When to use |
|---|---|
| **Axolotl** | Default recipe driver — handles QLoRA / LoRA / full FT / DPO with declarative YAML configs. Production-grade, multi-node, mature. |
| **HuggingFace transformers + PEFT** | Direct Python control when bank engineers need custom training loops |
| **Unsloth** | Faster QLoRA on small clusters; useful for rapid iteration on smaller models |
| **LLaMA-Factory** | Alternative to Axolotl with strong multi-language tooling |
| **TRL** (HuggingFace) | RLHF / DPO / RLAIF post-training (Wave 3) |

Forge can ship reference recipes for all of these; banks pick what their cluster supports. AgentOS doesn't care — it sees the registered artefact, not the framework that produced it.

### ISO 42001 control mapping (extends ADR-006)

| Control | Cognic hook |
|---|---|
| A.6.2.6 — Roles and responsibilities | Model registry's `lifecycle_state` transitions are RBAC-gated; promotion requires explicit reviewer + operator scopes |
| A.7.4 — AI system impact assessment | Model record includes `eval_results_ref` linking to ADR-010 eval-pack output |
| A.7.6 — AI system risk evaluation | Adversarial-test pass-rate (per ADR-011) attached to model record before `tenant_approved` |
| A.8.2 — Data quality for AI systems | `training_data_fingerprint` plus PII-filter audit log (Forge-side) |
| A.8.5 — AI system development | Full model record — recipe hash, base model, training config — exported in evidence packs |
| A.10.2 — Stakeholder transparency | Provider-honesty endpoint surfaces fine-tune lineage so operators see exactly what's serving |

## Consequences

### Positive
- **Banks own their model lifecycle** without forking AgentOS or managing GPU work inside the runtime
- **Provenance is examinable** — every audit-record case has a `model_id` linking to a fully-versioned, signed model record
- **Procurement story closes** — "yes, you can fine-tune; here's the signed-artefact + audit-chain integration"
- **Framework-agnostic** — banks pick Axolotl / HF / Unsloth based on their existing competence, not Cognic's vendoring
- **Forge is independently deployable** — banks who don't fine-tune install just AgentOS; banks who do install Forge separately
- **ISO 42001 model-lifecycle controls satisfied** in the registry, not bolted on later

### Negative
- **Two products to maintain** (AgentOS + Forge). Forge needs its own roadmap, ADRs, build plan in its own repo. Wave 2 work.
- **Cross-product API contract** — Forge → AgentOS registry-publish hook needs versioning + breaking-change discipline
- **Model artefact storage** — models are GB-scale; AgentOS uses ObjectStoreAdapter (per ADR-009 — Sprint 8) for the artefacts. Registry stores metadata + pointer; artefact sits in S3 / Azure Blob / on-prem object store
- **Multi-tenant complications** — a model fine-tuned for tenant A is registered under tenant A's scope; cross-tenant model sharing requires explicit operator action with audit
- **GPU cost transparency** — Forge surfaces training spend; AgentOS surfaces inference spend; banks need a consolidated view (Wave 3 dashboard)

### Neutral
- The Model Registry primitive ships **bundled in AgentOS** (not a plugin pack), same logic as audit/decision_history/eval — every bank deployment needs it
- Forge ships in its own repo when Wave 2 begins; today it's a documented future-product, not a vapourware shim

## Implementation phases

| Sprint / Phase | Work |
|---|---|
| **Sprint 9.5** (new — between Sprint 9 ISO 42001 + Sprint 10 Vault leasing) | Model Registry primitive: tables, API endpoints, RBAC scopes, ISO 42001 tagged audit events, decision_history linkage, provider-honesty extension. ~2 work-units. |
| **Wave 2 — Cognic Forge repo** (separate repo, post Phases 1-4) | Axolotl-driven fine-tuning workflow + PII filter + license tracker + signing pipeline + registry-publish hook. Separate roadmap, ADRs, build plan. |
| **Wave 3** | DPO / RLHF / RLAIF post-training; cross-tenant federated training (privacy-preserving); model-cost reconciliation dashboard. |

## References
- ADR-001 (OS-only platform — Forge is a separate product, not embedded)
- ADR-002 (MCP plugin protocol — Forge artefacts go through the same cosign trust gate)
- ADR-006 (ISO 42001 control mapping — model-lifecycle control extensions)
- ADR-007 (provider-honesty — extended with `model_id` per call)
- ADR-009 (pluggable adapters — ObjectStoreAdapter stores model artefacts)
- ADR-010 (evaluation harness — `eval_results_ref` attached to every model record)
- ADR-011 (adversarial testing — pass-rate gates `tenant_approved` transition)
- [Karpathy nanochat — teaching code, not production](https://github.com/karpathy/nanochat)
- [Axolotl — production fine-tuning framework](https://github.com/OpenAccess-AI-Collective/axolotl)
- [HuggingFace PEFT](https://github.com/huggingface/peft)
- [Unsloth](https://github.com/unslothai/unsloth)
- [LLaMA-Factory](https://github.com/hiyouga/LLaMA-Factory)
