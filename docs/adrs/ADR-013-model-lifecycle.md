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
| `signature_digest` | **SHA-256 over the raw Sigstore bundle bytes** (NOT cosign signature bytes; NOT the cosign verdict). Computed by `sigstore_bundle_digest(bundle_path)` in `models/trust.py`. The route's `_verify_record_signature` recomputes this BEFORE invoking cosign and refuses on mismatch — wrapper verdict and claim truthfulness are orthogonal (per ADR §"Bundle-digest evidence-integrity gate" + `feedback_recompute_derived_facts_not_just_wrapper`). Pairs with `signed_artifact_ref` + `sigstore_bundle_ref` (file refs) and the per-tenant trust root at `<root>/<tenant>/trust-root.pub` to anchor the same trust gate as packs from ADR-002. |
| `serving_endpoint` | Where the model is loaded — vLLM/SGLang URL, or the LiteLLM alias that fronts it |
| `lifecycle_state` | `proposed` → `eval_passed` → `tenant_approved` → `serving` → `deprecated` → `retired` |
| `iso_42001_evidence` | Tagged events for A.6.2.6 (responsibilities), A.7.4 (impact), A.8.2 (data quality — Sprint 9.5 §4.2), A.8.5 (development), A.10.2 (transparency). **A.7.6 deferred to Sprint 13** — Sprint 9.5 stores reviewer-attested risk evidence (`adversarial_pass_rate` on the `tenant_approved` chain row) but machine-verified ADR-011 evaluation requires the eval-run resolver + adversarial corpus loader that land later. |

Portal API endpoints — Sprint 9.5a implements 6 lifecycle endpoints (PR/merge pending):
```
POST   /api/v1/models                       register a new model (genesis: state=proposed)
GET    /api/v1/models?state=<state>         list, scoped to actor.tenant_id, optional state filter (B5)
GET    /api/v1/models/{id}                  detail incl. lifecycle history
POST   /api/v1/models/{id}/promote          body-aware (model.promote.<target_state>) + HumanActor on serving
POST   /api/v1/models/{id}/retire           state-aware HumanActor gate when current state == "serving"
GET    /api/v1/models/{id}/audit            hash-chained audit events oldest-first, exact-match on payload.model_id
```

The 7th endpoint **`GET /api/v1/models/{id}/usage`** is **deferred to
Sprint 9.5b** (Block C) per the cut-line decision at the close of B5 —
the usage aggregate depends on `gateway_call_ledger.model_id` linkage
which itself depends on the LLM gateway writing the column on every
call, and the gateway is a separate cloud-policy stop-rule risk
cluster that deserves its own review/PR surface.

**RBAC scopes (8 values per Sprint 9.5 B1):** `model.register`,
`model.promote.eval_passed`, `model.promote.tenant_approved`,
`model.promote.serving`, **`model.promote.deprecated` (+1 vs the original
BUILD_PLAN enumeration)**, `model.retire`, `model.audit.read`,
`model.usage.read`. The four `model.promote.<target_state>` scopes are
resolved body-aware at the `/promote` handler from `body.target_state`.

Provider-honesty endpoint (per ADR-007) extension — **deferred to
Sprint 9.5b**: `/effective-routing` extension to surface `model_id`
next to the LiteLLM alias requires the `gateway_call_ledger.model_id`
column write at the LLM gateway, which is the Block C scope.

Decision-history events tagged with `model_id` — Sprint 9.5a ships
this on the `model.lifecycle.*` chain rows (the lifecycle subject IS
the `model_id`). The **per-call** `decision_history.payload["model_id"]`
linkage on EVERY LLM call is deferred to Sprint 9.5b at the gateway
layer (separate from the lifecycle chain).

**Chain-payload contract (Sprint 9.5 A6.0):** Every `model.lifecycle.*`
chain row's `payload` carries 17 keys covering the per-control evidence
binding documented in the ISO 42001 mapping table below. Per the
tag-coverage-vs-evidence-coverage doctrine (§"Tag coverage vs evidence
coverage" amendment below), control claims on chain rows MUST be backed
by supporting facts in the same `payload` — the mutable `models` table
column is a join key, not evidence.

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

**Sprint 9.5 amendment (2026-05-23):** Five (not six) controls tagged on
every `model.lifecycle.*` chain row. A.7.6 dropped at spec §4.2 because
shape-valid `adversarial_pass_rate` storage is NOT a machine-verified
AI-risk evaluation; machine-verified ADR-011 risk evaluation is deferred
to Sprint 13 (when the eval-run resolver + adversarial corpus loader
land). A.7.6 remains in `compliance/iso42001/controls.py` as `deferred`
with the rewritten reason: "model lifecycle stores reviewer-attested
risk evidence in Sprint 9.5; machine-verified ADR-011 risk evaluation
deferred to Sprint 13."

| Control | Cognic hook (Sprint 9.5 evidence binding) |
|---|---|
| A.6.2.6 — Roles and responsibilities | Model registry's `lifecycle_state` transitions are RBAC-gated; promotion requires explicit reviewer + operator scopes. **Evidence on chain row**: `from_state` + `to_state` + `last_actor` + `actor_type`. |
| A.7.4 — AI system impact assessment | Model record includes `eval_results_ref` linking to ADR-010 eval-pack output. **Evidence on chain row**: `eval_results_ref` populated at `promote_tenant_approved`. |
| ~~A.7.6 — AI system risk evaluation~~ | **Deferred to Sprint 13** — `adversarial_pass_rate` IS stored on the chain row at `tenant_approved` (reviewer-attested), but machine verification requires the ADR-011 corpus loader + ≥0.99 threshold enforcement that lands later. |
| A.8.2 — Data quality for AI systems | `training_data_fingerprint` plus PII-filter audit log (Forge-side). **Evidence on chain row**: `training_data_fingerprint` (set at register, immutable through lifecycle). |
| A.8.5 — AI system development | Full model record — recipe hash, base model, training config — exported in evidence packs. **Evidence on chain row**: `recipe_hash` + `base_model` + `version` (set at register, immutable). |
| A.10.2 — Stakeholder transparency | **Sprint 9.5a evidence (implemented on `feat/sprint-9.5-model-registry`; PR/merge pending):** the `model.lifecycle.*` chain payload itself — `version` (lineage) + `serving_endpoint` (when set) + the oldest-first event sequence (proposed → eval_passed → tenant_approved → serving → deprecated/retired) surfaces at `GET /api/v1/models/{id}/audit`. **Sprint 9.5b follow-up (deferred):** the `/api/v1/system/effective-routing` provider-honesty endpoint extension to surface `model_id` next to the LiteLLM alias on every recent call — depends on the Block-C `gateway_call_ledger.model_id` write at the LLM gateway. The 9.5a chain-payload evidence is the load-bearing A.10.2 surface today; the 9.5b extension widens reach to per-call routing data. |

### Tag coverage vs evidence coverage (doctrinal amendment, Sprint 9.5 A6.0)

**A control's `iso_controls` tag is not evidence on its own.** The supporting
facts that an examiner needs to verify the claim MUST live in the
hash-chained `payload` dict, not in a mutable table column the chain row
knows the key to. A claim backed only by a side-channel-readable column
(`models.signature_digest`, `models.recipe_hash`, …) is **tag coverage**,
not **evidence coverage**: the examiner reading just the immutable chain
has no way to verify the claim without trusting the mutable column at
audit time, which defeats the integrity purpose of the chain.

The A6.0 fix that landed at Sprint 9.5 extends `_lifecycle_payload` from 6
keys to 17 — every supporting fact per the §4.1 + §4.2 mapping rows above
is now on the chain row at every transition. Cross-cutting requirement
for any future control flip from `deferred` to `implemented`: before
promotion, audit the payload-builder helper for the supporting fields the
claim depends on, and either extend the payload OR keep the control
deferred with an honest reason. The runtime check at `audit_coverage(...)`
in `compliance/iso42001/controls.py` enforces the tag side; the
chain-payload integrity is owned by the storage layer's `_lifecycle_payload`
+ `transition()` post-update overlay (per `feedback_chain_payload_is_evidence_snapshot`).

### Bundle-digest evidence-integrity gate (Sprint 9.5 B4 R2 P1)

The route layer's `_verify_record_signature` MUST recompute
`sigstore_bundle_digest(bundle)` and compare it to `record.signature_digest`
BEFORE invoking cosign. cosign exit-0 on a valid (artefact, bundle, key)
triple does NOT verify that `record.signature_digest` equals
`sha256(bundle_bytes)` — those are orthogonal facts. Without this
recompute-then-compare check, a client could register with a fabricated
`signature_digest` claim, cosign verifies successfully against the real
bundle, and the chain row records a digest examiners cannot reproduce by
hashing the bundle bytes themselves (broken evidence integrity regardless
of the wrapper's verdict). Pinned by
`tests/unit/portal/api/models/test_lifecycle_routes.py::test_promote_eval_passed_refused_on_digest_mismatch`
with cosign stub set to `cosign_exit_zero=True` (proves the gate fires
BEFORE the wrapper). Per `feedback_recompute_derived_facts_not_just_wrapper`.

### Wave-1 bundle-only cosign verify-blob argv shape

The Sprint 9.5 Z2 real-cosign two-layer proof at
`tests/integration/models/test_real_cosign_proof.py` (env-gated on
`COGNIC_RUN_COSIGN_INTEGRATION=1`) verifies that the bundle-only
`cosign verify-blob --key <trust> --bundle <bundle> <artefact>` shape
(NO `--signature` flag) works end-to-end at the target cosign version
against a real Sigstore bundle. Layer 1 hits `ModelTrustGate.verify_model_signature`
directly; Layer 2 threads the same bundle digest through the route +
storage pipeline (register → promote_eval_passed). Both passed at
sprint close. The argv-shape regression at
`tests/unit/models/test_trust.py::test_argv_excludes_signature_flag_and_pins_bundle_only_shape`
is the canonical pin; the integration test is the durable evidence
across cosign upgrades.

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

| Sprint / Phase | Work | Status |
|---|---|---|
| **Sprint 9.5a** (on `feat/sprint-9.5-model-registry`; PR/merge pending) | Model Registry primitive — domain (registry / storage / trust / chain payload / ISO 42001 mapping flips) + portal (RBAC widening / tenant isolation / DTOs / 6 lifecycle endpoints / create_app mount) + close (critical-controls gate 77→81 + real-cosign two-layer proof env-gated + doc reconciliation). All A6.0 + B2 R1 + B4 R2 + B5 R2 R-round findings landed in-cycle. | **Implemented; PR/merge pending** |
| **Sprint 9.5b** (DEFERRED — separate PR) | Block C: `Settings.llm_model_id_map` config; `llm/gateway.py` writes `gateway_call_ledger.model_id` on every LLM call (CC — touches the cloud-policy stop rule); `/api/v1/models/{id}/usage` aggregate endpoint; `/api/v1/system/effective-routing` extension showing `model_id` next to LiteLLM alias. **Touches a different risk cluster** (`core/config.py`, `llm/gateway.py`, ledger linkage) and deserves its own review/PR surface; not bundled with the model-registry domain commits. | **Deferred — explicit follow-up** |
| **Wave 2 — Cognic Forge repo** (separate repo, post Phases 1-4) | Axolotl-driven fine-tuning workflow + PII filter + license tracker + signing pipeline + registry-publish hook. Separate roadmap, ADRs, build plan. |  |
| **Wave 3** | DPO / RLHF / RLAIF post-training; cross-tenant federated training (privacy-preserving); model-cost reconciliation dashboard. |  |

## References
- ADR-001 (OS-only platform — Forge is a separate product, not embedded)
- ADR-002 (MCP plugin protocol — Forge artefacts go through the same cosign trust gate)
- ADR-006 (ISO 42001 control mapping — model-lifecycle control extensions)
- Sprint 9.5 design spec: `docs/superpowers/specs/2026-05-22-sprint-9.5-model-registry-design.md`
- Sprint 9.5 implementation plan: `docs/superpowers/plans/2026-05-22-sprint-9.5-model-registry.md` (carries R-round reconciliation history for A6 / A6.0 / B1 / B2 / B3 / B4 / B5 / Z1 / Z2 / Z3 + the deferred-to-9.5b Block-C cut)
- Critical-controls gate floor: `tools/check_critical_coverage.py` — Z1 promoted 4 modules to the durable per-file gate (77→81): `models/registry.py`, `models/storage.py`, `models/trust.py`, `portal/api/models/lifecycle_routes.py`
- Real-cosign two-layer proof: `tests/integration/models/test_real_cosign_proof.py` (env-gated on `COGNIC_RUN_COSIGN_INTEGRATION=1`; Z2)
- ADR-007 (provider-honesty — extended with `model_id` per call)
- ADR-009 (pluggable adapters — ObjectStoreAdapter stores model artefacts)
- ADR-010 (evaluation harness — `eval_results_ref` attached to every model record)
- ADR-011 (adversarial testing — pass-rate gates `tenant_approved` transition)
- [Karpathy nanochat — teaching code, not production](https://github.com/karpathy/nanochat)
- [Axolotl — production fine-tuning framework](https://github.com/OpenAccess-AI-Collective/axolotl)
- [HuggingFace PEFT](https://github.com/huggingface/peft)
- [Unsloth](https://github.com/unslothai/unsloth)
- [LLaMA-Factory](https://github.com/hiyouga/LLaMA-Factory)
