# Inference Backends — Operator Guide

> **Status:** Sprint 1D operator reference. Companion to
> [`ADR-009`](adrs/ADR-009-pluggable-infrastructure-adapters.md) §"LLM serving"
> + [`infra/litellm/config.yaml`](../infra/litellm/config.yaml).

Cognic AgentOS speaks LLM inference through LiteLLM tier aliases
(`cognic-tier1-*` / `cognic-tier2-*`); the alias resolves to one of the
backends below. Embedding inference goes through one of the bundled
`EmbeddingAdapter` implementations. This guide helps operators choose
the right backend per deployment.

## TL;DR

| Use case | Inference (chat) | Embedding | Notes |
|---|---|---|---|
| **Local dev / laptop** | Ollama (`cognic-tier{1,2}-dev`) | Ollama (`embed_driver=ollama`) | Single-process; no GPU required; fits a Mac M-series. |
| **Single-GPU staging** | vLLM (`cognic-tier{1,2}-vllm`) | OpenAI-compat (`embed_driver=openai_compat`, `provider_label=vllm`) | One GPU per node; vLLM is the simplest production stack. |
| **Multi-GPU production** | SGLang (`cognic-tier{1,2}-sglang`) | OpenAI-compat (`provider_label=sglang`) | SGLang is throughput-optimised on long-context workloads. |
| **Cloud-only deployment** | LiteLLM cloud aliases | OpenAI-compat (`provider_label=openai`/`azure_oai`/`bedrock`) | Requires `ALLOW_EXTERNAL_LLM=true` cloud-policy override (per ADR-007 provider-honesty). |

## Decision matrix

### Picking inference

| Criterion | Ollama | vLLM | SGLang | Cloud |
|---|---|---|---|---|
| GPU required | No | Yes | Yes | No (network out) |
| Throughput | Low | High | Highest | Variable |
| Long-context (>32K) | Slow | Good | Best | Provider-dependent |
| Streaming | Yes | Yes | Yes | Yes |
| Self-hosted / sovereign | Yes | Yes | Yes | **No** |
| Cognic dev parity | Strongest | Strong | Strong | Drift risk |
| Cost | $0 (HW only) | $0 (HW only) | $0 (HW only) | Per-token billing |

### Picking embedding

| Criterion | Ollama | OpenAI-compat (vLLM) | OpenAI-compat (cloud) |
|---|---|---|---|
| GPU required | No | Yes | No |
| Throughput | Low | High | High |
| Audit `provider_label` | `ollama` | `vllm` | `openai`, `azure_oai`, `bedrock`, `cohere` |
| Multilingual coverage | Good (Qwen3-Embedding) | Model-dependent | Provider-dependent |
| Self-hosted | Yes | Yes | **No** |

## Deployment topologies

### Dev (Ollama, no GPU)

`infra/dev/docker-compose.yml` brings up the default 7-service stack;
Ollama itself runs on the host (`COGNIC_EMBEDDING_BASE_URL=http://localhost:11434`).
Set `COGNIC_EMBED_DRIVER=ollama` and `COGNIC_TIER1_MODEL=cognic-tier1-dev`.
Best for laptop work, demos, and CI runners without GPU.

### Single-GPU staging (vLLM)

Activate the vLLM compose overlay:

```bash
docker compose -f infra/dev/docker-compose.yml \
               -f infra/dev/docker-compose.vllm.yml up -d
```

Set:

```bash
COGNIC_TIER1_MODEL=cognic-tier1-vllm
VLLM_BASE_URL=http://vllm:8000
COGNIC_TIER1_VLLM_MODEL=Qwen/Qwen3-8B-Instruct  # or whatever fits the GPU

COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=http://vllm:8000
COGNIC_EMBEDDING_MODEL=BAAI/bge-large-en-v1.5
COGNIC_EMBEDDING_DIMENSIONS=1024
COGNIC_EMBED_PROVIDER_LABEL=vllm
# COGNIC_EMBEDDING_API_KEY=                  # vLLM defaults to no auth
```

### Multi-GPU production (SGLang)

SGLang is preferred when throughput per GPU matters (e.g. Tier-1 banks
running >100K agent invocations / day). Topology mirrors vLLM but with
SGLang's runtime + a model-shard configuration matching the cluster's
GPU count.

```bash
COGNIC_TIER1_MODEL=cognic-tier1-sglang
SGLANG_BASE_URL=http://sglang.internal:30000
COGNIC_TIER1_SGLANG_MODEL=Qwen/Qwen3-32B-Instruct

COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=http://sglang-embed.internal:30000
COGNIC_EMBEDDING_DIMENSIONS=1024
COGNIC_EMBED_PROVIDER_LABEL=sglang
```

### Cloud (OpenAI / Azure / Bedrock)

Requires the cloud-policy override per ADR-007 (`ALLOW_EXTERNAL_LLM=true`).
The provider-honesty endpoint will surface the active backend; banks
reviewing routing reality see `provider_label=openai|azure_oai|bedrock`
in the audit trail (Sprint 2 wires the actual emission; Sprint 1D
stores the label on the adapter).

```bash
# Example: OpenAI cloud
COGNIC_TIER1_MODEL=cognic-tier1-cloud-openai
COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=https://api.openai.com
COGNIC_EMBEDDING_MODEL=text-embedding-3-large
COGNIC_EMBEDDING_DIMENSIONS=3072
COGNIC_EMBED_PROVIDER_LABEL=openai
COGNIC_EMBEDDING_API_KEY=sk-...               # via Vault in prod
COGNIC_EMBEDDING_API_KEY_HEADER=Authorization # default; sends Bearer
```

```bash
# Example: Azure OpenAI fronted by an OpenAI-compat proxy
COGNIC_EMBED_DRIVER=openai_compat
COGNIC_EMBEDDING_BASE_URL=https://your-azure-proxy.example
COGNIC_EMBEDDING_MODEL=text-embedding-3-large
COGNIC_EMBEDDING_DIMENSIONS=3072
COGNIC_EMBED_PROVIDER_LABEL=azure_oai
COGNIC_EMBEDDING_API_KEY=<azure-key>
COGNIC_EMBEDDING_API_KEY_HEADER=api-key       # raw header, no Bearer prefix
COGNIC_EMBEDDING_EXTRA_HEADERS={"api-version": "2024-02-15-preview"}
```

> **Direct Azure-OpenAI URL shape** (`/openai/deployments/<name>/embeddings?api-version=...`)
> requires a separate Azure-specific adapter — deferred. Sprint 1D
> supports Azure only when fronted by an OpenAI-compat proxy (the shape
> above).

## Audit + governance notes

- **Provider honesty (per ADR-007).** The OpenAI-compat embedding
  adapter exposes `provider_label` so audit emissions can record which
  backend actually served each call. Sprint 1D wires storage; Sprint 2
  emits the label from `core/audit` alongside the existing decision-
  history hash chain.
- **Self-hosted-first.** Bank-grade deployments default to vLLM/SGLang;
  cloud is opt-in per tenant. The cloud-policy gate is enforced in the
  LLM gateway (Sprint 3); ALLOW_EXTERNAL_LLM=false forbids cloud
  routing entirely.
- **Tier promotion.** Tier 1 = primary inference; Tier 2 = fallback
  (cheaper/smaller model when Tier 1 is unavailable or budget-capped).
  Both tiers can independently target Ollama/vLLM/SGLang/cloud.

## Embedding response validation

`OpenAICompatEmbeddingAdapter` validates upstream responses on every
embed:

- **Response count** must equal request count. Out-of-spec providers
  that drop or duplicate rows would otherwise silently mis-align
  retrieval upserts; the adapter raises `ValueError` instead.
- **Per-row dimensionality** must match `COGNIC_EMBEDDING_DIMENSIONS`.
  A wrong-dim response is almost always operator misconfiguration
  (the deployed model emits a different dim than declared) — fail
  loudly so the index doesn't get poisoned with garbage rows.
- **Per-row type** must be a list. A non-list embedding row signals
  a malformed provider response; raised as `ValueError`.

## References

- [ADR-009 §"LLM serving"](adrs/ADR-009-pluggable-infrastructure-adapters.md) — adapter contract + LiteLLM tier-alias scheme
- [ADR-007 — Provider honesty](adrs/ADR-007-provider-honesty.md) — cloud-policy + audit surface
- [`infra/litellm/config.yaml`](../infra/litellm/config.yaml) — concrete tier-alias definitions
- [`infra/dev/docker-compose.vllm.yml`](../infra/dev/docker-compose.vllm.yml) — single-GPU vLLM overlay
- vLLM docs: https://docs.vllm.ai
- SGLang docs: https://github.com/sgl-project/sglang
- Dynatrace Metric Ingest API: https://docs.dynatrace.com/docs/shortlink/api-metrics-v2-post-datapoints (required scopes: `metrics.read` + `metrics.ingest`)
