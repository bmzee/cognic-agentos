# ADR-009 — Pluggable Infrastructure Adapters

## Status
**APPROVED for implementation** on 2026-04-26. Foundational for Sprint 1.

## Context

AgentOS depends on six external infrastructure systems:

| Concern | Cognic default | Examples a bank may already own + refuse to change |
|---|---|---|
| RDBMS | Postgres | Oracle, MS SQL Server, MySQL/MariaDB, IBM Db2 |
| Vector DB | Qdrant | Chroma, Weaviate, Milvus, pgvector, Pinecone (cloud), OpenSearch k-NN |
| Secrets manager | HashiCorp Vault | AWS Secrets Manager, Azure Key Vault, CyberArk, GCP Secret Manager |
| Embedding provider | Ollama (local Qwen3-Embedding 8B) | OpenAI / Cohere / AWS Bedrock / Azure OpenAI |
| Object storage | S3 / MinIO | Azure Blob, GCS, on-prem NetApp/Dell EMC, IBM COS |
| Observability stack | Langfuse + OpenTelemetry | Splunk, Datadog, New Relic, Dynatrace |

Pakistani and global banks have *legacy* infrastructure investments. A bank that runs Oracle for everything will not migrate to Postgres just to deploy Cognic. A bank using AWS Secrets Manager won't stand up Vault for one application. A bank with Splunk doesn't want a second logging stack.

If AgentOS hardcodes Postgres + Qdrant + Vault, it's deployable to a narrow subset of banks. We need a clean abstraction so banks pick their backends via config, and bank-specific adapters install as plugin packs (per ADR-002 pattern).

The parent cognic monorepo already half-implements this: `cognic.db.vector_store.QdrantStore` and `cognic.db.ticket_store.SQLAlchemyTicketStore` are concrete classes used directly. There's no protocol layer; adding a new vector backend means editing OS code. AgentOS does this properly from day 1.

## Decision

### Adapter protocols (the contracts)

Six `Protocol` (PEP 544) interfaces in `cognic_agentos.db.adapters.protocols`:

| Protocol | Methods (sketch) |
|---|---|
| `RelationalAdapter` | `connect()`, `session()`, `run_migrations(dir)`, `close()`, `health_check()` |
| `VectorAdapter` | `ensure_collection(name, dim, metric)`, `upsert(items)`, `search(vector, k, filter)`, `delete(ids)`, `health_check()` |
| `SecretAdapter` | `read(path)`, `write(path, value)`, `lease(path, ttl_s)`, `revoke(lease_id)`, `health_check()` |
| `EmbeddingAdapter` | `embed(texts) -> list[list[float]]`, `dimensions`, `health_check()` |
| `ObjectStoreAdapter` | `put(bucket, key, body)`, `get(bucket, key)`, `delete(bucket, key)`, `presign(bucket, key, ttl_s)`, `health_check()` |
| `ObservabilityAdapter` | `emit_trace(...)`, `emit_metric(...)`, `flush()`, `health_check()` |

(LLM provider routing already lives behind LiteLLM gateway — same pattern, different layer.)

### Bundled adapters (ship with AgentOS — both dev-friendly and enterprise-grade options in the box)

Ship in `cognic_agentos.db.adapters.{name}.py`:

**Relational (RDBMS):**
- `postgres_adapter.py` — RelationalAdapter via SQLAlchemy + asyncpg (default for dev + many bank deployments)
- `oracle_adapter.py` — RelationalAdapter via SQLAlchemy + python-oracledb (most-common enterprise bank choice)

**Vector:**
- `qdrant_adapter.py` — VectorAdapter via qdrant-client (default; production-proven; self-hostable)

> **Translation note vs Master Strategy v5.0 §4 line 725.** Master Strategy lists "VectorStoreAdapter with pgvector default." This ADR (AgentOS-repo, supersedes per PROJECT_PLAN §2 translation rule) re-evaluates that default as **Qdrant** for three reasons: (1) Qdrant is purpose-built for vector workloads at scale (Master Strategy was written before Qdrant's enterprise adoption matured); (2) banks already running Postgres rarely have it sized for vector workloads — adding pgvector creates an operational coupling that's hard to undo; (3) Qdrant scales independently from the relational store, which matters once a bank's RAG corpus exceeds a few million chunks. **pgvector remains supported** as a separate plugin pack (`cognic-vector-pgvector`, listed under "Alternative adapters" below) for banks that genuinely have only Postgres. Master Strategy intent — "Enables Qdrant/Milvus/Oracle AI Vector Search swap without rewriting agents" — is preserved exactly: the swap is config-only.

**Secrets:**
- `vault_adapter.py` — SecretAdapter via hvac (HashiCorp Vault, default)

**Embedding (LLM serving — Ollama is dev only; vLLM / SGLang are enterprise-grade for production GPU clusters):**
- `ollama_adapter.py` — EmbeddingAdapter (Ollama HTTP). **Dev-friendly, not enterprise-grade** — single-process binary, no horizontal scaling, no batching optimisations.
- `openai_compat_adapter.py` — EmbeddingAdapter against any OpenAI-compatible `/v1/embeddings` endpoint. Works with **vLLM**, **SGLang**, OpenAI, Azure OpenAI, Cohere, AWS Bedrock (via OpenAI-compatible endpoint). The adapter records a `provider_label` (e.g. `vllm`, `sglang`) on every audit emission so banks see exactly which backend handled the embedding.

**Object storage:**
- `s3_adapter.py` — ObjectStoreAdapter (boto3 / MinIO-compatible) — added Sprint 8 alongside evidence-pack export

**Observability:**
- `langfuse_otel_adapter.py` — ObservabilityAdapter combining Langfuse + OpenTelemetry (default — Langfuse for LLM-trace UI, OTel for distributed tracing). The adapter speaks the Langfuse v2/v3-compatible HTTP shape (`/api/public/health` + `/api/public/ingestion`); the bundled dev compose pins `langfuse/langfuse:2` (single-container, Postgres-only). Banks that need v3 features (Clickhouse-backed traces, S3 blob storage) ship a v3-compatible compose overlay alongside the dev stack — see Sprint 1C plan note. Sprint 2/3 wires the full Langfuse SDK trace lifecycle alongside `core/decision_history` + the LLM gateway.
- `dynatrace_adapter.py` — ObservabilityAdapter for Dynatrace tenants. Two integration paths supported: (a) OTLP export to Dynatrace's ingest endpoint (no Dynatrace SDK needed; uses native OTel pipe), (b) Dynatrace Metric Ingest API for custom Cognic governance metrics with Dynatrace-specific dimensions. Authentication via `DYNATRACE_API_TOKEN` Vault path.

### LLM serving — LiteLLM gateway handles routing (no separate "LLM adapter")

Chat completion is routed through LiteLLM (already in the architecture). Sprint 1 ships LiteLLM config presets for **all three serving backends**:

| Backend | LiteLLM alias | Suitability |
|---|---|---|
| **Ollama** | `cognic-tier1-dev` / `cognic-tier2-dev` | Dev / laptop only |
| **vLLM** | `cognic-tier1-vllm` / `cognic-tier2-vllm` | **Production GPU clusters — Berkeley research, mature** |
| **SGLang** | `cognic-tier1-sglang` / `cognic-tier2-sglang` | **Production GPU clusters — LMSYS, faster on long-context workloads** |

Banks set `COGNIC_TIER1_MODEL=cognic-tier1-vllm` (or `-sglang`) in production. LiteLLM forwards to the bank's vLLM/SGLang inference endpoint. No code change in AgentOS.

### Alternative adapters (separate plugin packs — covered by ADR-002 plugin protocol)

Beyond the bundled set above, these install as plugin packs:

```
cognic-db-mssql:0.1.0           (RelationalAdapter for MS SQL Server)
cognic-db-mysql:0.1.0           (RelationalAdapter for MySQL/MariaDB)
cognic-vector-chroma:0.1.0      (VectorAdapter for Chroma)
cognic-vector-weaviate:0.1.0    (VectorAdapter for Weaviate)
cognic-vector-pgvector:0.1.0    (VectorAdapter for pgvector — when bank only has Postgres)
cognic-vector-milvus:0.1.0      (VectorAdapter for Milvus)
cognic-secrets-aws:0.1.0        (SecretAdapter for AWS Secrets Manager)
cognic-secrets-azure:0.1.0      (SecretAdapter for Azure Key Vault)
cognic-secrets-cyberark:0.1.0   (SecretAdapter for CyberArk Conjur)
cognic-storage-azure:0.1.0      (ObjectStoreAdapter for Azure Blob)
cognic-storage-gcs:0.1.0        (ObjectStoreAdapter for GCS)
cognic-obs-splunk:0.1.0         (ObservabilityAdapter for Splunk)
cognic-obs-datadog:0.1.0        (ObservabilityAdapter for Datadog)
cognic-obs-newrelic:0.1.0       (ObservabilityAdapter for New Relic)
```

Discovery via Python entry points (per ADR-002):
```toml
# in cognic-vector-chroma/pyproject.toml
[project.entry-points."cognic.adapters.vector"]
chroma = "cognic_vector_chroma:ChromaAdapter"
```

### Configuration

Per-bank `.env` selects the driver per concern:
```bash
COGNIC_DB_DRIVER=postgres            # postgres (bundled) | oracle (bundled) | mssql | mysql
COGNIC_VECTOR_DRIVER=qdrant           # qdrant (bundled) | chroma | weaviate | pgvector | milvus
COGNIC_SECRET_DRIVER=vault            # vault (bundled) | aws | azure | cyberark
COGNIC_EMBED_DRIVER=ollama            # ollama (bundled, dev only) | openai_compat (bundled — vLLM / SGLang / OpenAI / Azure-OAI / Bedrock)
COGNIC_EMBED_PROVIDER_LABEL=ollama    # audit label when embed_driver=openai_compat: vllm | sglang | openai | azure_oai | bedrock | cohere
COGNIC_STORAGE_DRIVER=s3              # s3 (bundled, Sprint 8) | azure | gcs
COGNIC_OBS_DRIVER=langfuse_otel       # langfuse_otel (bundled) | dynatrace (bundled) | splunk | datadog | newrelic

# LLM serving (LiteLLM tier alias):
COGNIC_TIER1_MODEL=cognic-tier1-dev   # dev (Ollama) | vllm | sglang | cloud_openai | cloud_anthropic
COGNIC_TIER2_MODEL=cognic-tier2-dev   # same options
```

At startup, `cognic_agentos.db.adapters.factory.build_adapters(settings)` reads the drivers, looks them up in the registry (bundled or plugin), constructs each adapter, and returns a typed `Adapters` container. **Fails fast** if a configured driver isn't installed — clear error message.

### Configuration source for adapter-specific settings

Bundled adapters read their config from the same `core/config.py` settings:
- `database_url` (Postgres) → `postgresql+asyncpg://...`
- `qdrant_url` → `http://...`
- `vault_addr` → `https://...`

Plugin-packaged adapters declare their own settings group via Pydantic Settings:
```python
class ChromaAdapterSettings(BaseSettings):
    chroma_host: str
    chroma_port: int = 8000
    chroma_collection: str
    model_config = SettingsConfigDict(env_prefix="COGNIC_CHROMA_")
```

Banks set `COGNIC_CHROMA_HOST=...` etc. in `.env`. Plugin pack documentation lists required env vars.

### Trust boundary

Adapter packs go through the same trust gate as tool/skill/agent packs:
- cosign signature verification
- Per-tenant allow-list
- Audit-logged registration with adapter identity (name + version + signature digest)

Banks know exactly which adapter is in use and can audit the source.

### Migration policy

- **RDBMS migrations**: Alembic, but the adapter exposes `run_migrations(dir)`. Postgres migrations live in `db/migrations/postgres/`; Oracle pack provides its own migrations in `db/migrations/oracle/` (or generated from Alembic with the right dialect).
- **Vector collection setup**: each `VectorAdapter` implements `ensure_collection(name, dim, metric)` idempotently. AgentOS calls this at startup for each declared collection.

## Consequences

### Positive
- **Bank-agnostic deployment** — same AgentOS image runs on Postgres+Qdrant or Oracle+Chroma+CyberArk
- **No fork pressure** — banks never edit OS source to change backends
- **Clean test boundary** — `MemoryAdapter` implementations enable fast unit tests without docker-compose
- **Future-proof** — new vector DBs / secrets managers / observability stacks become one-pack additions
- **Procurement story** — bank legal audits the adapter pack once, then never has to look at OS internals
- **Vendor lock-out resilience** — if Qdrant gets acquired and licensing changes, banks swap drivers without disruption

### Negative
- **More abstraction up front** — Sprint 1 adds ~1 work-unit for the protocol definitions + factory
- **Adapter parity testing** — each adapter pack must pass a conformance test suite Cognic publishes; otherwise behavior drifts between drivers
- **Documentation burden** — every protocol method needs precise contract docs so adapter authors don't guess
- **Some features may not generalise cleanly** — e.g. Postgres-specific JSONB queries, Oracle-specific PL/SQL features. The `RelationalAdapter` interface is SQLAlchemy-based which papers over much of this, but advanced features may need driver-specific extensions

### Neutral
- LLM gateway already follows this pattern via LiteLLM — adapter pattern at this layer mirrors it for infrastructure
- Workflow engine (Temporal) is **not** abstracted — there are very few alternatives and the activity model is tightly coupled. If a bank ever demands a different workflow engine, that's a future ADR
- Message queue (Redis) is **not** abstracted in Wave 1 — used only for caching and rate-limiting; banks accept Redis or we bundle it. Future ADR if a bank refuses

## Implementation phases

| Sprint | Adapter work |
|---|---|
| **Sprint 1** | Protocol definitions + Postgres + Qdrant + Vault + Ollama + Langfuse_OTel adapters (all bundled). Adapter factory in `db/adapters/factory.py`. `MemoryAdapter` reference implementations for tests. |
| **Sprint 4** | Adapter packs go through plugin trust gate (per ADR-002). Conformance test suite published. |
| **Sprint 8** | S3/MinIO ObjectStoreAdapter (for evidence packs). |
| **Phase 5+** | First alternative adapter pack POC: `cognic-vector-chroma`. Validates the pack-author experience. |

## References
- ADR-001 (OS-only platform) — defines what's bundled vs pack
- ADR-002 (MCP plugin protocol) — same trust + discovery model applies to adapter packs
- ADR-007 (provider-honesty) — same audited-runtime-reality discipline applies to which adapters are in use
- Parent cognic `cognic.db.vector_store.QdrantStore` / `cognic.db.ticket_store.SQLAlchemyTicketStore` — existing concrete adapters; serve as starting point for Postgres + Qdrant default implementations
