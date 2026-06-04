# Pre-GA Configurability / Hard-Code Audit — Charter

> **Date:** 2026-06-03
> **Status:** Charter (methodology spec) — pending review; **no execution yet**
> **Workstream:** Pre-GA Configurability Audit — #1 of the "deployable at a client without bespoke code surgery" sequence (#1 audit → #2 harness injection → #3 Sprint 11.5d recall hardening)
> **Boundary:** This document is the audit **charter only**. It fixes doctrine, taxonomy, sweep scope, the do-not-configure set, finding format, and fix-wave structure. It contains **no findings and no fixes**. The sweep that produces findings is a distinct downstream phase (preference: parallel fan-out), gated on this charter's approval.

---

## 1. Purpose

Cognic AgentOS is built as a production-grade system that a bank "deploys once and runs forever" (AGENTS.md). For GA, a client must be able to stand up AgentOS in their environment — their hosts, their Vault, their Postgres/Oracle, their tenants, their model endpoints — **without editing source**. Any deployment difference that today requires a code edit is a GA blocker.

This audit classifies every deployment-variable value in the kernel into a small, unambiguous taxonomy so that, in priority order, we can:

1. promote values trapped in code to **deployment configuration**;
2. identify values that must become **per-tenant overlays**;
3. explicitly protect the values that must **stay hard-pinned** because they are governance, protocol, or evidence controls — making those configurable would be a security regression, not a feature.

The charter deliberately keeps those three concerns separate, because conflating them is the failure mode that produces both deployment friction (config trapped in code) and governance holes (invariants exposed as config).

This is a **doctrine + methodology** deliverable. It produces the map's *legend and survey plan*, not the map.

---

## 2. Doctrine anchor

AgentOS already states a configuration doctrine; this charter **extends** rather than replaces it.

- `core/config.py` module docstring + `docs/BUILD_PLAN.md` (Phase-1 production-grade principles): *operational values (host, port, profile, timeouts, log levels, …) load from environment variables via the central `Settings` object; environment-specific values do not live in source elsewhere. Declared defaults, route names, protocol identifiers, and package metadata are **not** "hardcoding" and are allowed.*
- The kernel config surface is already strongly centralized: one `Settings(BaseSettings)` (`COGNIC_` env prefix, ≈129 fields), profile-aware (`dev` / `stage` / `prod`; prod flips defaults closed), with bounded validators (`ge` / `le` / `gt`) and prod-profile startup guards.
- A calibration sweep confirms config is **largely** centralized — but not entirely. *Most* `os.environ` reads outside `core/config.py` are subprocess-env *hardening* (PATH + HOME only, deliberately *not* passing the parent env) and ARE out of scope. **Several are real config seams that read the host environment directly and ARE in scope to classify:** LiteLLM `${VAR}` / `${VAR:-default}` substitution (`src/cognic_agentos/llm/preflight.py:_substitute_env`, `:155–176`); deliberate full-host-env inheritance for the cosign + supply-chain tool subprocesses (`src/cognic_agentos/cli/sign.py:582,1505` — preserves HOME / PATH / HTTPS_PROXY / AWS_* / VAULT_ADDR / SIGSTORE_* for KMS / Vault / registry auth); and the egress-proxy PID1 entrypoint that builds its whole config from `os.environ` (`infra/sandbox/egress-proxy/entrypoint.py:374`). The sweep treats these as known seams to classify; **only PATH+HOME-only hardening sites are excluded** (§4 exclusions).

The audit is therefore **not** a hardcoding cleanup. It is a pre-GA classification of the deployment-variable surface, extending the existing "operational values from env" doctrine to the full disposition set in §3 — including the two cases the current doctrine does not name explicitly: **per-tenant variation** and **must-not-be-configurable invariants**.

---

## 3. Classification taxonomy

Every finding carries exactly **one primary disposition** (categories 1–7). Two refinements keep that rule clean where a single value resists one tag:

- **Separable halves → two findings.** When a value has two genuinely separable halves (e.g. a Rego bundle's configurable *path* and its pinned *content*), the sweep records **two findings**, one per half — never one finding with two primary dispositions.
- **Forward-looking re-classification → secondary tag.** When a value is one disposition *today* but a candidate to become another *later* (e.g. a global setting that should become a tenant overlay once the mechanism exists), the primary disposition is what it is today, with an explicit **secondary tag** (e.g. `tenant-overlay-candidate`).

For the two "configurable" dispositions, the finding also records **scope** (global vs per-tenant) in its *proposed home* field. A separate **ownership marker** (§3.8) applies orthogonally when the value belongs to a bank-overlay repo rather than this kernel.

| # | Disposition | Configurable? | Proposed home |
|---|---|---|---|
| 1 | `deployment setting` | yes — global, per-instance | a `Settings` env field |
| 2 | `tenant overlay` | yes — per-tenant | a per-tenant override mechanism (mostly absent today — §9) |
| 3 | `safe default` | yes, low priority | a `Settings` env field (already fine as shipped) |
| 4 | `security floor` | bounded — tighten only | a `Settings` env field + a one-directional / prod guard |
| 5 | `ADR/protocol invariant` | **no** | leave pinned (do-not-configure set — §5) |
| 6 | `test fixture` | out of scope | leave (test/demo paths only) |
| 7 | `secret material` | **resolved, not set** | secret adapter (Vault) or tenant-scoped secret reference |

**1. `deployment setting`** — a global, per-instance operational value a real client deployment must be able to set. *e.g.* `qdrant_url`, `database_url`, `otel_exporter_endpoint`, `host` / `port`, `embedding_base_url`, `model_artifact_root`.

**2. `tenant overlay`** — a value that must vary per tenant within one deployment. *Most of the mechanism to express this does not exist today* (see §9). *e.g.* per-tenant model policy, per-tenant memory retention window, per-tenant egress / provider allow-lists, per-tenant sub-agent recursion cap.

**3. `safe default`** — operationally fine as shipped; an operator *may* override, but a typical client never needs to. *e.g.* `llm_timeout_s`, `opa_eval_timeout_s`, cache TTLs, queue sizes, `provider_honesty_ledger_window_minutes`.

**4. `security floor`** — bounded-configurable: may be tightened, never loosened past the kernel floor. The override exists but is one-directional, and prod often guards the loosening direction at startup. *e.g.* `memory_export_retention_seconds` (≥ 7-year floor), `require_cosign` (override exists; `False` in prod is a critical-controls violation), `dev_mode_skip_cosign` (prod rejects `True` at config-load).

**5. `ADR/protocol invariant`** — must **not** be configurable. Loosening is a governance break or a wire-protocol break. This is the do-not-configure set (§5). *e.g.* canonical-form bytes, closed-enum refusal vocabularies, default-deny Rego *content*, pinned protocol versions, audit / evidence-pack schemas.

**6. `test fixture`** — test/demo-only hardcode; out of scope for promotion. *e.g.* synthetic keys under `examples/` + `tests/fixtures/`, dev credentials in `infra/dev/docker-compose*.yml`.

**7. `secret material`** — must resolve through the secret adapter (Vault) or a tenant-scoped secret reference; **never** a plain config value or source default in prod. "Configurable" is the wrong mental model: a secret is *resolved*, not *set*. The sweep flags any secret currently settable via plain env without Vault-path resolution and/or a prod-profile guard. *e.g.* `vault_token`, `litellm_master_key`, `langfuse_secret_key`, `embedding_api_key`, `dynatrace_api_token`.

### 3.8 Ownership marker: `bank-overlay artifact`

Orthogonal to disposition. Some deployment-variable values are bank-specific by design and live in **separate bank-overlay repos**, not in this kernel (AGENTS.md "Lives elsewhere": themes, OIDC client config, custom CBS adapters, bank-specific Rego overlays). For these, the audit's only in-repo concern is the **kernel seam**: is there a present, overlay-ready injection point, or is the value wrongly baked into the kernel?

**Rule: audit the seam, not the artifact.** A `bank-overlay artifact` finding records whether the kernel seam is `present` / `absent` / `needs-work`; it never proposes moving the bank-specific value into this repo. This keeps the audit honest with the OS/pack boundary — *AgentOS provides the seam; bank overlays live elsewhere.* The canonical example is the OIDC → `Actor` identity binding: the seam is `portal/rbac/actor.py` (the actor-binder, which fails loud with `NotImplementedError` until an overlay wires it); the bank's OIDC client config is the artifact and stays out of this repo.

---

## 4. Sweep scope & targets

Each subsystem below is a sweep unit (one agent per unit under the preferred parallel fan-out). For each, the agent reads the production source **plus** the relevant `Settings` fields, `.env.example`, Rego bundles, and `infra/` manifests, and classifies every deployment-variable value it finds.

| Subsystem | Paths (repo-relative, exact) | Expected dispositions |
|---|---|---|
| Central config | `src/cognic_agentos/core/config.py` (≈129 fields) + `.env.example` (drift cross-check) | all 7 — this is the disposition baseline |
| Memory / DLP | `src/cognic_agentos/core/memory/`, `src/cognic_agentos/core/dlp/`, `src/cognic_agentos/portal/api/memory/`, `src/cognic_agentos/cli/validators/learning_surface.py` | floors (retention), invariants (refusal vocab), overlays (per-tenant retention), deployment (qdrant collection) |
| LLM gateway | `src/cognic_agentos/llm/gateway.py`, `src/cognic_agentos/llm/preflight.py` (incl. the `${VAR}` env-substitution seam, `:155–176`) | deployment (endpoints, aliases), secret (master key), safe default (timeouts), overlay (provider allow-list) |
| Vector / retrieval | `src/cognic_agentos/db/adapters/qdrant_adapter.py`, `src/cognic_agentos/core/memory/{vector,episodes}.py`, `src/cognic_agentos/retrieval/` | deployment (url, collection, dims), safe default (thresholds) |
| Model lifecycle | `src/cognic_agentos/models/`, `src/cognic_agentos/portal/api/models/` | deployment (`model_artifact_root`), invariant (lifecycle state machine, refusal vocab) |
| Plugin / supply-chain | `src/cognic_agentos/protocol/{plugin_registry,trust_gate,supply_chain}.py`, `src/cognic_agentos/packs/`, `src/cognic_agentos/cli/sign.py`, `src/cognic_agentos/cli/verify.py` (host-env inheritance seam, `sign.py:582,1505`) | deployment (binary paths cosign/syft/grype/opa; inherited host env), floor (`require_cosign`), invariant (attestation schema) |
| RBAC / OIDC | `src/cognic_agentos/portal/rbac/` | invariant (closed-enum scopes), bank-overlay artifact (actor-binder seam) |
| Object store | `src/cognic_agentos/db/adapters/local_object_store_adapter.py`, `*_root` Settings fields | deployment (roots), floor (path-containment) |
| Emergency controls | `src/cognic_agentos/core/emergency/kill_switches.py`, `src/cognic_agentos/core/emergency/quotas.py` | floor (propagation budget, fail-closed), overlay (per-tenant quotas) |
| Scheduler | `src/cognic_agentos/core/scheduler/` | deployment / safe default (caps, queue depth, SLAs), invariant (closed-enum outcomes) |
| Sandbox | `src/cognic_agentos/sandbox/` + `infra/sandbox/egress-proxy/entrypoint.py` (env-config seam, `:374`) | deployment (egress-proxy URL/port), floor (canonical image catalog), invariant (admission refusal vocab) |
| Protocol (MCP / A2A) | `src/cognic_agentos/protocol/` | invariant (version pins, wire schemas), deployment (Vault path templates), safe default (timeouts) |
| Rego bundles | `policies/_default/*.rego` (7 bundles + `plugin_allowlist.json`) | deployment (bundle **path**) **vs** invariant (default bundle **content**) — see note |
| Observability | `src/cognic_agentos/observability/` + otel / langfuse / dynatrace Settings fields | deployment (endpoints), secret (tokens/keys) |
| Compliance / evidence | `src/cognic_agentos/compliance/` | invariant (evidence-pack schema, ISO control mapping) |
| Deployment manifests | `infra/agentos/Dockerfile`, `infra/dev/docker-compose*.yml` (×3), `infra/sandbox/{runtime-python,egress-proxy}/Dockerfile` | deployment (image tags, pinned binary versions), test fixture (dev creds) |

**Rego path-vs-content nuance.** A Rego *bundle path* (`mcp_sampling_policy_bundle`, `supply_chain_policy_bundle`, …) is a `deployment setting` — an operator may point it at a Vault-mounted overlay. The *default bundle content* shipped in `policies/_default/` is an `ADR/protocol invariant` — banks may **tighten** via overlay, but loosening a kernel default requires a coordinated kernel + ADR amendment (per the AGENTS.md policy-bundle stop-rules). Per the §3 two-findings rule, a Rego bundle yields **two findings** — one for the path, one for the content.

**`.env.example` cross-check.** The audit treats `.env.example` as a config-surface artifact: every operator-tunable `Settings` field should have a documented entry, and every entry should map to a real field. Drift in either direction is a finding (a `safe default` / Wave-3 item, unless it hides a P0).

**Explicit exclusions.** `tests/`, `examples/`, `dist/`, `docs/` (referenced only, never swept as targets). Subprocess-env hardening sites (PATH+HOME-only env construction) are **not** config-scatter and are out of scope.

---

## 5. The do-not-configure set

These classes are `ADR/protocol invariant` (category 5). The sweep uses this list **both** as a reference (a value matching the set → tag `ADR/protocol invariant`, leave alone) **and** as an active checklist (§6, D2): verify none is *currently* exposed as configurable without a guard.

- **Canonical-form bytes** — `core/canonical.py` (`canonical_bytes`, `hash_record`, `_json_default`, `ZERO_HASH`); the evidence-pack wire format.
- **Closed-enum refusal vocabularies** — every wire-public `*RefusalReason` / `*Reason` Literal (memory, sandbox, scheduler, lifecycle, RBAC, A2A error codes, …). Drift breaks downstream consumers.
- **Default-deny Rego content** — the shipped default decisions across the 7 bundles under `policies/_default/`: `sampling.rego`, `supply_chain.rego`, `elicitation.rego`, `sandbox.rego` (admission), `scheduler.rego` (admission), `memory.rego`, `memory_purpose_matrix.rego`. Bundle *path* is configurable; default *content* is pinned.
- **Pinned protocol versions** — `a2a_pinned_spec_version`, MCP capability/version pins, the A2A schema-drift digests.
- **Audit / evidence-pack schemas** — `audit_event` + `decision_history` canonical shapes, ISO 42001 control mappings, evidence-pack export format.
- **Retention floors** — the *floor* values themselves (e.g. the 7-year memory-export / Sigstore-bundle floor). The configured window may exceed the floor; the floor may not be lowered.
- **Fail-closed posture** — kill-switch fail-closed default, default-deny gates, prod profile flipping security defaults closed.

This list is a *class* list, not an exhaustive file list; the sweep expands it to concrete sites and reports any that are wrongly configurable.

---

## 6. Audit methodology

1. **Both directions (D2).** Every sweep agent reports in *both* directions:
   - **(i) trapped value** — a deployment/overlay/secret value baked into code or a non-overridable constant → propose its config / overlay / Vault home;
   - **(ii) leaked invariant** — an `ADR/protocol invariant` *already* exposed as configurable without a guard → flag as a governance hole.
2. **Read, don't mutate.** The sweep produces the findings inventory only. No value is changed; no `Settings` field is added. Fixes are Wave 1–3 (§8), each with its own plan.
3. **One primary disposition per finding** (§3). Ambiguity is resolved by the §3 definitions and the §Appendix-A calibration examples. A value with two genuinely separable halves (e.g. a Rego bundle: configurable path + pinned content) is split into **two findings**, one per half; a "X today, Y-candidate later" value carries a single primary disposition plus a secondary tag (e.g. `tenant-overlay-candidate`) — never two primary dispositions on one row.
4. **Seam-not-artifact for bank overlays.** A `bank-overlay artifact` value (§3.8) yields a finding about the *seam state*, never a proposal to move the artifact in-repo.
5. **Fan-out vs inline** is decided at execution time (preference: parallel fan-out, one agent per §4 subsystem, results merged into a single inventory). The methodology is identical either way.

---

## 7. Finding output format & severity

Each finding is one row in the downstream inventory:

| Field | Meaning |
|---|---|
| `id` | stable finding id (`CFG-<subsystem>-NNN`) |
| `category` | one of the 7 dispositions (§3) |
| `ownership` | `kernel` or `bank-overlay artifact` (§3.8) |
| `subsystem` | sweep unit (§4) |
| `location` | `file:line` (or manifest path) |
| `current` | current value / default / constant |
| `deploy_scenario` | the client deployment difference it blocks (or "—" for invariants) |
| `disposition` | proposed action: config home / overlay / leave-pinned / move-to-vault / fix-guard |
| `scope` | for configurable dispositions: `global` or `per-tenant` |
| `severity` | `P0` / `P1` / `P2` |
| `tests_required` | the regression(s) a fix must add |
| `notes` | direction (trapped vs leaked), secondary tags (e.g. `tenant-overlay-candidate`), cross-refs, caveats |

**Severity rubric:**

- **P0** — a real client deployment **cannot run** without editing source (trapped deployment setting or secret), **or** an invariant is leaked as loosenable config in prod with no guard. Wave 1.
- **P1** — needs per-tenant variation with no mechanism today (overlay candidate). Wave 2.
- **P2** — polish: documentation, `.env.example` drift, cosmetic safe-default tidy. Wave 3.

---

## 8. Fix-wave structure

- **Wave 1 — P0 deployment blockers.** Promote module-baked deployment settings to `Settings`; close any `secret material` leaks (secret settable via plain env in prod without a Vault-path / prod guard); fix any leaked-invariant governance hole. Each fix is real, swappable, deployable (production-grade rule) with a regression.
- **Wave 2 — tenant overlays.** Address `tenant overlay` (P1) candidates. **Depends on the overlay-mechanism spec (§9)** — Wave 2 cannot land before the mechanism exists.
- **Wave 3 — polish.** `safe default` documentation, `.env.example` ↔ `Settings` drift reconciliation, cosmetic tidy.

Waves are independent deliverables. Each gets its own implementation plan + TDD execution; the charter does not pre-commit their contents beyond the priority ordering.

---

## 9. Tenant-overlay mechanism — tag-and-defer (D1)

The charter **does not design** the per-tenant overlay mechanism. Today the only per-tenant config surfaces are Vault path templates (`secret/cognic/{tenant}/…`) and `plugin_allowlist.json` (`{tenant_id: […]}`); there is **no general per-tenant `Settings`-overlay mechanism**.

The audit's job is to:

1. **identify overlay candidates** (`tenant overlay`, P1 findings), and
2. **name the structural gap** as a single explicit finding: *"AgentOS has no general per-tenant configuration-overlay mechanism."*

Designing that mechanism is a **downstream sub-project with its own spec**, informed by the candidate set the sweep produces (the shape of the mechanism should follow the real list of things that need overlaying, not be guessed up front). Wave 2 depends on it.

---

## 10. Non-goals

- **No findings or fixes** in this document — it is the charter only.
- **No overlay-mechanism design** (deferred per §9).
- **No bank-overlay artifacts authored here** (they live in overlay repos; we audit only the kernel seam).
- **No changes to any do-not-configure invariant** (§5).
- **Not** a security audit, performance audit, or dependency audit — configurability only. (A leaked-invariant finding is in scope because it *is* a configurability question; deeper exploitation analysis is not.)

---

## 11. Execution handoff

On charter approval → review → commit, the next phase is:

1. **Execute the sweep** — preferred: parallel fan-out, one agent per §4 subsystem; results merged into a single findings inventory (§7 format), written to a separate `docs/superpowers/specs/` (or `docs/`) inventory doc. Inline execution is the fallback; the methodology is identical.
2. **Triage + rank** the inventory by severity (§7 rubric).
3. **Per-wave plans** — each fix wave (§8) gets its own implementation plan + TDD execution.

This charter is a **methodology spec**. The standard brainstorm → writing-plans → TDD rail applies to the fix **waves**, not to the charter itself; the immediate next artifact after this charter is the **findings inventory**, not code.

---

## Appendix A — taxonomy calibration examples

*These are **not** audit findings.* They illustrate how a handful of representative, real kernel values classify under §3, so sweep agents apply the taxonomy consistently. (Line numbers reference `src/cognic_agentos/core/config.py` at charter-write time and are indicative, not pinned.)

| Value | Disposition | Why |
|---|---|---|
| `host` / `port` (`:100–101`) | `deployment setting` (global) | every deploy binds differently |
| `qdrant_url` (`:300`) | `deployment setting` (global) | per-deploy vector endpoint |
| `qdrant_collection="cognic_default"` (`:304`) | `deployment setting` (global) | a client wants their own collection namespace |
| `embedding_model="qwen3-embedding:8b"` (`:358`) | `deployment setting` (global) | model identifier varies per deploy / provider |
| `model_artifact_root="/var/lib/cognic/model-artifacts"` (`:627`) | `deployment setting` (global, install-time path) | host filesystem layout varies |
| `llm_timeout_s=30.0` (`:522`) | `safe default` | fine as shipped; rarely tuned |
| `subagent_max_recursion_depth=3` (`:125`) | `deployment setting` (global); secondary tag `tenant-overlay-candidate` | global today; docstring defers per-tenant override to policy/approval (13.5) |
| `memory_export_retention_seconds` (≥ 7yr floor) | `security floor` | configurable up, never below the floor |
| `require_cosign=True` (`:607`) | `security floor` | `False`-in-prod is a CC violation; the sweep verifies the prod-loosening guard exists (D2 direction ii) |
| `dev_mode_skip_cosign` (`:708`) | `security floor` (guarded) | prod rejects `True` at config-load — the guard pattern a floor should follow |
| `vault_token` (`:317`) | `secret material` | must resolve via Vault/secret adapter, not plain env in prod |
| `litellm_master_key` (`:493`) | `secret material` | same |
| `a2a_pinned_spec_version="1.0"` (`:982`) | `ADR/protocol invariant` | wire-protocol pin; bump is a reviewed drift-gated change, never config |
| `mcp_sampling_policy_bundle` (`:895`) | **two findings** — (a) bundle *path* = `deployment setting`; (b) default bundle *content* = `ADR/protocol invariant` | operator may point at an overlay bundle; the shipped default-deny content is pinned |
| OIDC client config (seam at `portal/rbac/actor.py`) | `bank-overlay artifact` | artifact lives in a bank-overlay repo; audit only confirms the actor-binder seam is overlay-ready |
