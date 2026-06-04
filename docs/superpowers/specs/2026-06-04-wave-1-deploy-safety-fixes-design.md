# Wave-1 Deploy-Safety Fixes — Design Spec

> **Date:** 2026-06-04
> **Status:** Design spec — pending review; **no code yet**
> **Workstream:** Wave 1 of the Pre-GA Configurability Audit (fix-wave mapping in `docs/superpowers/specs/2026-06-03-pre-ga-configurability-audit-findings-inventory.md`).
> **Posture:** This is **critical-controls code** — `core/config.py` validators, secret resolution, `sandbox/backend_factory.py`, the approval-gate path. Implementation runs under `core-controls-engineer` + `/critical-module-mode` + halt-before-commit per the AGENTS.md stop-rules.
> **Findings addressed:** CFG-config-01/02/03/05/06/07/08/09/10/11/12/13/14, CFG-sandbox-launch, CFG-portal-adversarial.

---

## 1. Goal & scope

Close the deploy-safety findings so a bank can stand up AgentOS in `prod` **without silently misconfiguring or insecurely exposing it**. Add only the config surface needed; the §9 per-tenant overlay mechanism stays out (Wave 2, its own spec).

**In scope:**
- Secret resolution doctrine: `vault_token` (bootstrap) + 4 service secrets + 2 deprecated inert `_vault_path` fields.
- `require_cosign=False` forbidden in prod.
- Unsafe prod defaults: `embedding_model`/`embedding_dimensions`, `tier1_alias`/`tier2_alias`, sandbox canonical images, `model_artifact_root` (profile-aware).
- `CFG-sandbox-launch`: backend image-launch threading.
- `CFG-portal-adversarial`: tighten-only adversarial pass-rate floor.

**Out of scope (named deferrals):** the §9 per-tenant overlay mechanism (Wave 2); K8s/AppRole Vault auth (follow-up — retires `vault_token`); the P2 tail (Wave 3 — `.env.example` drift, timeouts, HNSW, etc.); the 3 unbuilt AGENTS.md critical-controls modules (`auto_degradation`, `citation`, `retrieval/citation_verifier`).

---

## 2. Architecture — the guard / resolver split

Two distinct mechanisms, deliberately separated so the deploy-safety check has no async/adapter dependency and the kernel-clean arrow is preserved:

- **Guard** — *synchronous*, lives in `core/config.py` `model_validator`(s), fires at **config-load** (fail-loud-at-startup). It inspects only the **string shape** of a field (is it `None` / plain / a `vault://` URI; is it the shipped dev default) + `runtime_profile`. It does **not** import or call `SecretAdapter` (config.py:51 forbids `core/` → `db.adapters`). Raises `ValidationError` with a stable reason-prefix (the existing config convention — see §3.7).
- **Resolver** — *asynchronous*, lives at the **adapter / app-wiring layer** where `SecretAdapter` is available, runs **once at component construction / startup** (never per-call). For a field holding `vault://…`: strip the prefix → `await secret_adapter.read(path)` → extract the agreed dict field → hand the value to the consumer. Models the proven `cli/sign._build_secret_adapter` + `InMemorySecretAdapter` test pattern.

**Why the split:** the guard delivers the bank-grade fail-loud with zero Vault dependency at Settings-load; the resolver does the real fetch lazily where async + the adapter exist. It also keeps `core/config.py` free of any `db.adapters` import.

**Profile doctrine.** `dev` is the only profile with relaxed ergonomics; **strict profiles = {`stage`, `prod`}** follow the secure rules. Every *new* Wave-1 guard below fires in **strict profiles** — a bank's pre-prod/stage must not run dev-style plain secrets or dev/personal defaults. The pre-existing `dev_mode_skip_cosign` guard (config.py:1169, prod-only) is **unchanged**. (Two exceptions, called out where they occur: the `vault_token` bootstrap guard §3.5 fires in *any* profile that uses `vault://`; the `model_artifact_root` resolver §5.4 is a path default, not a security guard, so it follows the object-store prod-vs-rest split.)

---

## 3. Secret resolution (CFG-config-10/11/12/13/14 + `vault_token`)

### 3.1 Pattern A — canonical for all 4 service secrets
`litellm_master_key`, `langfuse_secret_key`, `embedding_api_key`, `dynatrace_api_token` — each value field may be:
- `None` → no secret needed (e.g. local no-auth vLLM/SGLang); always allowed.
- a **plain value** → allowed **only in `dev`** (strict profiles `stage`/`prod` reject it).
- a **`vault://secret/path` URI** → allowed in any profile; **required** for a non-`None` secret in `stage`/`prod`; resolved at construction via `SecretAdapter.read`.

### 3.2 Guard (sync, config-load)
A `core/config.py` `model_validator(mode="after")`: for each of the 4 service-secret fields, when `runtime_profile` is a **strict profile (`stage`/`prod`)** and the value **is not `None` and does not start with `vault://`** → `ValidationError` with the reason-prefix `secret_plain_value_forbidden_in_strict_profile` (message names the field + points at the `vault://` form). `None` and `vault://…` pass; **only `dev` plain values pass.**

### 3.3 Resolver (async, construction-time)
A shared helper at the adapter layer — proposed `src/cognic_agentos/db/adapters/secret_resolution.py`:
```
async def resolve_secret_field(
    value: str | None, *, secret_adapter: SecretAdapter, field_name: str,
) -> str | None
```
- `None` → `None`; non-`vault://` → return as-is (dev path); `vault://path` → `await secret_adapter.read(path)` → extract the `"key"` field (see §3.6) → return.
- **Call sites:** `db/adapters/factory.py` resolves `embedding_api_key` / `langfuse_secret_key` / `dynatrace_api_token` before passing them to their adapter constructors; the LLM-gateway wiring resolves `litellm_master_key` **once at gateway construction** and passes the resolved value in (today `llm/gateway.py:333` reads it per-call — that read changes to the pre-resolved value so we don't hit Vault on every LLM call).
- Resolution failure (e.g. `vault://` set but Vault unreachable) fails loud with a structured error — mirrors `cli/sign.py`'s `sign_signing_key_unavailable` shape.

### 3.4 Deprecated inert `_vault_path` fields — **fail-loud in prod**
`embedding_api_key_vault_path`, `dynatrace_api_token_vault_path` are declared-but-unconsumed today; left as-is they read as a secure prod path while delivering no protection. A `core/config.py` guard:
- **strict profile (`stage`/`prod`)** + either field set → `ValidationError` (reason-prefix `vault_path_field_deprecated_use_vault_uri`) instructing the operator to use `embedding_api_key="vault://…"` / `dynatrace_api_token="vault://…"`.
- `dev` + set → a one-line deprecation warning (logged) — no resolution behavior.
- They are **never** honored as an alternate resolution path (the resolver ignores them entirely).

### 3.5 `vault_token` — the bootstrap exception
- May **not** be a `vault://` URI (chicken-and-egg — it is how static-token auth reaches Vault).
- **Plain value allowed** in all profiles (it is the bootstrap credential), exempt from §3.2.
- **Required whenever any service secret uses `vault://` — in ANY profile:** if any of the 4 service-secret fields starts with `vault://` and (`vault_addr` unset **or** `vault_token` unset) → `ValidationError` (reason-prefix `vault_bootstrap_unset_for_secret_resolution`). Profile-independent by design: declaring a `vault://` value implies the bootstrap is needed, so this fails loud at config-load rather than at resolve-time (closes the `dev`-with-`vault://`-but-no-bootstrap gap the review flagged).
- Documented as **platform-secret-injected** (K8s secret mount / projected file), **not** a committed `.env` value (doc note, not enforceable in-process).
- **K8s/AppRole auth is the named follow-up** that retires `vault_token`; explicitly deferred.

### 3.6 Vault dict-key convention
`SecretAdapter.read(path)` returns `dict[str, Any]`, so the resolver must pick which key holds the secret. **LOCKED: the resolver reads the dict field `"key"`** for all 4 service secrets — reusing the existing `_VAULT_KEY_FIELD = "key"` precedent (`compliance/iso42001/signing.py:30`) so the codebase has **one** convention across signing keys + service secrets (no new vocabulary). The expected Vault secret shape is `{"key": "<secret>"}`, documented in `.env.example` + the resolver docstring. A read result missing the `"key"` field → the `secret_field_resolution_failed` failure (§3.3 / §3.7).

### 3.7 Validation-reason convention
The reason tokens above (`secret_plain_value_forbidden_in_strict_profile`, `vault_path_field_deprecated_use_vault_uri`, `vault_bootstrap_unset_for_secret_resolution`, and the resolver-side `secret_field_resolution_failed`) are **NOT a formal closed-enum Literal**. They follow the existing `core/config.py` convention: a **stable reason-prefix in the raised `ValueError` message** (e.g. `signing_key_path_under_test_fixture_tree_in_prod:` at config.py:1161), **pinned by Settings tests** (both rejected and allowed shapes, per the R10 P2 #2 precedent). No new Literal vocabulary or drift-test home is introduced; promoting these to a true enum is a deliberate future decision, out of Wave-1 scope. (The §4 `require_cosign_false_forbidden_in_strict_profile` + the §5 unsafe-default reasons follow the same convention.)

---

## 4. `require_cosign` prod guard (CFG-config-01)

The sole charter-strict leaked invariant. Add a `core/config.py` `model_validator(mode="after")`: `runtime_profile` is a **strict profile (`stage`/`prod`)** and `require_cosign is False` → `ValidationError` (reason-prefix `require_cosign_false_forbidden_in_strict_profile`). Implement beside the existing `dev_mode_skip_cosign` guard (config.py:1169-1174) — but note that guard stays **prod-only (unchanged)**; only the **new** `require_cosign` guard adopts the strict-profile rule. `require_cosign` stays `True` by default; `dev` may set `False`.

---

## 5. Unsafe prod defaults

Per-field disposition (decided here, not guessed):

### 5.1 `embedding_model` / `embedding_dimensions` (CFG-config-02/03)
Keep the dev-friendly default; a guard rejects the **shipped dev default** in strict profiles so stage/prod can't silently run a dev model. `core/config.py` `model_validator`: **strict profile** + `embedding_model == _DEV_DEFAULT_EMBEDDING_MODEL` (the constant `"qwen3-embedding:8b"`) → `ValidationError` (reason-prefix `embedding_model_dev_default_in_strict_profile`, "set a production embedding model"). `embedding_dimensions` is coupled (model-specific vector width) — the operator who sets a prod model must set matching dimensions; document the coupling in the field description and the error message (no automatic dimension inference). Only `dev` keeps the convenient default.

### 5.2 `tier1_alias` / `tier2_alias` (CFG-config-05/06)
Adversarial verification showed these are **inert under the `self_hosted` default** (`policy_mode="self_hosted"` + `allow_external_llm=False`), so guard **only when they're actually live**: `core/config.py` `model_validator`: **strict profile** + (`allow_external_llm is True` **or** `policy_mode != "self_hosted"`) + (`tier1_alias` or `tier2_alias` still equals its `*-dev` shipped default) → `ValidationError` (reason-prefix `tier_alias_dev_default_with_external_llm`). Under the self-hosted default the guard does not fire (no false positive).

### 5.3 Sandbox canonical images (CFG-config-08/09)
Defaults point at a **personal `ghcr.io/bmzee` namespace** a bank cannot pull or re-sign. Two parts:
- **Guard:** `core/config.py` `model_validator`: **strict profile** + either `sandbox_canonical_runtime_python_image` / `sandbox_canonical_egress_proxy_image` still equals its `ghcr.io/bmzee/...` shipped default → `ValidationError` (reason-prefix `sandbox_canonical_image_personal_default_in_strict_profile`, "set your registry + matching trust root"). The same `ghcr.io/bmzee` ref is also hardcoded as a backend fallback at `docker_sibling.py:202` / `kubernetes_pod.py:260`; those fallbacks are addressed by §6 (threading) — once threaded, the guard on the Settings field is the single enforcement point.
- **Follow-up note (not Wave 1):** publishing the canonical images to a real official namespace (so the *default* is usable) needs a published `cognic/...` registry + signing — a release/infra task, recorded but deferred.

### 5.4 `model_artifact_root` (CFG-config-07) — profile-aware resolver, **not** fail-loud
`/var/lib/cognic/model-artifacts` is an acceptable Linux service default in prod (peer of `local_object_store_root`'s `/var/lib/cognic-agentos/object-store`); the real defect is it's an **unconditional literal** with no dev divergence (local runs write to `/var/lib`). This is a **path-default resolver, not a security guard**, so it follows the object-store prod-vs-rest split, **not** the strict-profile rule. **Decision (mirrors `_resolve_local_object_store_root`, config.py:1177):**
- **Field type:** `model_artifact_root: str | None` (was `str`), default `None`. Kept `str`-family (not `Path | None` like `local_object_store_root`) because the **sole consumer** wraps it — `lifecycle_routes.py` does `Path(settings.model_artifact_root)`. **RECONCILED 2026-06-04 (decision A):** because the field is now `str | None`, that `Path(...)` needs a 1-line type-narrow (`assert artifact_root is not None`) — `Path(None)` is a mypy error — so the consumer IS lightly touched (a defensive type guard, not a behavior change; the resolver always fills a non-`None` `str`). The earlier "leaves that caller unchanged" was wrong; the narrow is a CC-reviewed change landed in the T4 commit.
- Add a `model_validator(mode="after")`: if `None` → `prod` resolves to `"/var/lib/cognic/model-artifacts"`, **dev + stage** resolve to a `$TMPDIR`-derived path (new `_default_model_artifact_root()` helper mirroring `_default_object_store_root()`, config.py:1682). The resolver fills a **`str`**; after validation the field is always a non-`None` `str`.
- Operator override (env / kwarg) always wins (non-`None` at validator entry) — a real stage env that wants `/var/lib` sets it explicitly.
- **Not** a fail-loud — prod (and stage-with-override) get a sane writable default; dev stops polluting `/var/lib`.

---

## 6. `CFG-sandbox-launch` — backend image-launch threading (P1)

`sandbox/backend_factory.py:100-110` injects the `sandbox_canonical_*` Settings into the `CanonicalImageCatalog` (trust gate) **only**; it does not pass `egress_proxy_image` into the backend constructor, so the backend launches the hardcoded `_CANONICAL_EGRESS_PROXY_IMAGE` (`ghcr.io/bmzee/...`, `docker_sibling.py:202` / `kubernetes_pod.py:260`) regardless of the override → catalog says "trust the bank image", backend launches the bmzee image → catalog/launch mismatch (sandbox create fails the membership/cosign gate, or launches the wrong image).

**Fix:** in `backend_factory.get_backend`, thread the image Settings into the backend constructor:
- pass `egress_proxy_image=settings.sandbox_canonical_egress_proxy_image` to both `DockerSiblingSandboxBackend` / `KubernetesPodSandboxBackend`.
- **verify + fix the runtime-python image path** the same way (the grep showed `_CANONICAL_EGRESS_PROXY_IMAGE` clearly; confirm whether a `runtime_python_image` constructor arg + `_CANONICAL_RUNTIME_PYTHON_IMAGE` fallback exists and thread it too — implementation must read the backend constructors at `docker_sibling.py:956` / `kubernetes_pod.py:977` and close every image-launch path that ignores Settings).
- **Invariant the test pins:** for any operator override, the catalog's canonical set and the backend's launched image are the **same** ref (no mismatch).

This is a `sandbox/` isolation-boundary change — backend_factory is off-the-CC-gate but the backends are on it; halt-before-commit applies.

---

## 7. `CFG-portal-adversarial` — tighten-only pass-rate floor (P1)

The ADR-011 adversarial-corpus pass-rate floor is baked at the gate-enforcement site: `_ADVERSARIAL_PASS_RATE_THRESHOLD: Final[float] = 0.99` at `portal/api/packs/review_routes.py:140` (the `0.99` in `packs/approval_gates.py:313` is only a docstring). No Settings home → a bank can't tighten its adversarial floor.

**Fix:**
- New `core/config.py` field `adversarial_pass_rate_floor: float = Field(default=0.99, ge=0.99, le=1.0)` — **tighten-only**: `ge=0.99` forbids loosening below the kernel floor; the operator may raise it (e.g. `0.999`).
- The threshold lives in the **module-level** helper `_build_adversarial_gate_input` (`review_routes.py:221`, comparison at `:263`); `build_review_routes` (`:478`) already captures `settings` (used elsewhere in the module, e.g. `settings.signature_root_path` at `:432`). **Fix: parameterize the helper** — `_build_adversarial_gate_input(raw, *, pass_rate_floor: float)` — and have the route handler (closure-captured `settings`) pass `settings.adversarial_pass_rate_floor`. **Not** an ad-hoc `get_settings()` read; **not** left module-global.
- Keep the kernel-floor value documented as the ADR-011 minimum; `.env.example` entry.

---

## 8. Files touched (critical-controls)

| file | change |
|---|---|
| `src/cognic_agentos/core/config.py` | new fields (`adversarial_pass_rate_floor`); model_validator guards (§3.2/3.4/3.5, §4, §5.1/5.2/5.3); `model_artifact_root` default→None + profile resolver (§5.4) + `_default_model_artifact_root()` helper; new reason-prefix strings + dev-default constants |
| `src/cognic_agentos/db/adapters/secret_resolution.py` *(new)* | `resolve_secret_field(...)` async resolver (§3.3) |
| `src/cognic_agentos/db/adapters/factory.py` | resolve `embedding_api_key` / `langfuse_secret_key` / `dynatrace_api_token` via the resolver before adapter construction |
| `src/cognic_agentos/llm/gateway.py` (+ its wiring) | resolve `litellm_master_key` once at construction; `:333` uses the resolved value, not a per-call Settings read |
| `src/cognic_agentos/sandbox/backend_factory.py` | thread `egress_proxy_image` (+ runtime-python image) into the backend constructor (§6) |
| `src/cognic_agentos/portal/api/packs/review_routes.py` | read `settings.adversarial_pass_rate_floor` (§7) |
| `.env.example` | document the `vault://` secret convention + `adversarial_pass_rate_floor`; remove/deprecate the 2 `_vault_path` example entries |

---

## 9. Testing strategy (TDD, per fix)

- **Secret guard (× each of the 4 fields):** `stage`/`prod` + plain → `ValidationError(secret_plain_value_forbidden_in_strict_profile)`; `stage`/`prod` + `vault://` → OK; `stage`/`prod` + `None` → OK; **`dev` + plain → OK**.
- **Resolver:** `vault://path` → reads via an injected `InMemorySecretAdapter`, extracts the **`"key"`** field; missing `"key"` → `secret_field_resolution_failed`; `None`→`None`; plain→identity; Vault-unreachable→structured failure.
- **Deprecated fields:** `stage`/`prod` + `*_vault_path` set → `ValidationError(vault_path_field_deprecated_use_vault_uri)`; `dev` + set → warning, no resolution.
- **`vault_token` bootstrap:** **any profile** + a service secret is `vault://` + no `vault_token`/`vault_addr` → `ValidationError(vault_bootstrap_unset_for_secret_resolution)`; plain `vault_token` → OK (exempt, any profile).
- **`require_cosign`:** `stage`/`prod` + `False` → `ValidationError`; `dev` + `False` → OK; default `True` → OK.
- **Unsafe defaults:** `stage`/`prod` + `embedding_model` dev default → fail; `dev` + dev default → OK; explicit → OK. Tier aliases: `stage`/`prod` + `self_hosted` + dev alias → OK (no false positive); `stage`/`prod` + `allow_external_llm=True` + dev alias → fail. Sandbox images: `stage`/`prod` + bmzee default → fail; + custom → OK.
- **`model_artifact_root`:** `prod` + unset → `/var/lib/cognic/model-artifacts`; **`dev`/`stage` + unset → `$TMPDIR`-derived**; explicit override → wins (× profiles); field type `str | None`, always a non-`None` `str` post-validation.
- **`CFG-sandbox-launch`:** the factory passes the configured image into the backend constructor; a regression asserts catalog ref == launched ref for an overridden image (both backends).
- **`CFG-portal-adversarial`:** `adversarial_pass_rate_floor` rejects `<0.99` at Settings load (`ge`); `review_routes` reads the Settings value at the gate; a finding below the configured floor refuses.

Coverage: `core/config.py` is a critical-controls module — negative-path tests required for every new guard; the verify-floor-at-promotion-time rule applies if any module crosses the CC gate.

---

## 10. Open questions / risks (resolve at plan or implementation)

1. **Gateway resolution wiring (§3.3):** confirm where the LLM gateway is constructed in app-wiring so `litellm_master_key` resolves once there; if the gateway is constructed without a `SecretAdapter` in scope, the wiring passes the pre-resolved value in (preferred) rather than handing the gateway an adapter.
2. **Runtime-python image (§6):** confirm whether the runtime-python image has the same un-threaded-launch issue as the egress-proxy image, and close it identically.
3. **Sandbox-image "official namespace" follow-up (§5.3):** the fail-loud guard is Wave 1; publishing usable official-namespace defaults is a deferred release/infra task.

---

## 11. Non-goals

- §9 per-tenant overlay mechanism (Wave 2 — its own spec; gates the ≈10 overlay candidates).
- K8s/AppRole Vault auth (follow-up — retires `vault_token`).
- The P2 polish tail (Wave 3).
- The 3 unbuilt AGENTS.md critical-controls modules.
- No change to any do-not-configure invariant (canonical form, closed-enum vocab, default-deny Rego content, evidence schemas) — verified intact by the audit.
