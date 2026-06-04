# Wave-1 Deploy-Safety Fixes — Closeout (2026-06-04)

**Branch:** `feat/wave-1-deploy-safety` · **Workstream #1** of the deployable-without-code-surgery sequence (Pre-GA Configurability Audit → Wave-1 fixes → … ).

**Goal met:** a bank can now stand up AgentOS in `stage`/`prod` without silently
misconfiguring or insecurely exposing it — dev-shaped defaults, plaintext
secrets, and unresolvable `vault://` URIs fail loud at config-load; the
egress-proxy launch + adversarial pass-rate floor are now operator-configurable.

Source spec: `docs/superpowers/specs/2026-06-04-wave-1-deploy-safety-fixes-design.md`.
Plan-of-record: `docs/superpowers/plans/2026-06-04-wave-1-deploy-safety-fixes.md`.

## The 8 commits (T1–T8)

| Task | Commit | What |
|---|---|---|
| T1 | `832b585` | `core/config.py` strict-profile guards G1–G8 + blast-radius test remediation |
| T2 | `7509b4e` | `vault://` secret resolver (`db/adapters/secret_resolution.py`) + `build_adapters_async` factory seam |
| T3 | `e15a2b0` | `LLMGateway` `litellm_master_key` resolution seam (read-once-at-construction + fail-loud) |
| T4 | `ffae007` | `model_artifact_root` profile-aware resolver (`str \| None` + consumer narrow) |
| T5 | `0342d22` | thread egress-proxy image into the sandbox backend constructor (CFG-sandbox-launch) |
| T6 | `6cda946` | `adversarial_pass_rate_floor` tighten-only Settings field (CFG-portal-adversarial) |
| T7 | `98da044` | reconcile `.env.example` with the Wave-1 config surface |
| T8 | (this doc) | Z-gate: full suite + critical-coverage + closeout |

## Strict-profile doctrine

`dev` is the only relaxed profile; **strict profiles = {`stage`, `prod`}**. Every
Wave-1 guard fires in strict profiles (a bank's pre-prod must not run dev/plain
defaults). Two profile-independent exceptions: the `vault_token` bootstrap guard
(G3) + the `vault_token` shape guard (G8) fire in *any* profile that uses
`vault://`. `model_artifact_root` (T4) is a path-default resolver (prod-vs-rest
split), not a security guard.

## Fail-loud reason-prefixes (all test-pinned, all TM-revert-verified)

`ValueError` reason-prefixes (T1 `core/config.py::_validate_wave1_deploy_safety_guards`):

- G1 `secret_plain_value_forbidden_in_strict_profile`
- G2 `vault_path_field_deprecated_use_vault_uri`
- G3 `vault_bootstrap_unset_for_secret_resolution`
- G4 `require_cosign_false_forbidden_in_strict_profile`
- G5 `embedding_model_dev_default_in_strict_profile`
- G6 `tier_alias_dev_default_with_external_llm`
- G7 `sandbox_canonical_image_personal_default_in_strict_profile`
- G8 `vault_token_vault_uri_forbidden`

`RuntimeError` reason-prefixes:

- T2 resolver: `secret_field_resolution_failed` (Vault unreachable / non-dict / missing `"key"` / empty-or-non-str)
- T2 factory preflight: `build_adapters_sync_unresolved_vault_secret`
- T3 gateway: `litellm_master_key_unresolved_vault_uri`

Pydantic field constraints: `adversarial_pass_rate_floor` (`ge=0.99, le=1.0` —
tighten-only); `model_artifact_root` is `str | None` resolved per profile.

### TM-revert ledger (load-bearing proofs)

- **G1–G8 (T1):** each guard neutralized in isolation → its matching negative test FAILED → restored. (Verified at T1 + the G8 follow-up.)
- **T5 egress thread:** neutralized the `kwargs["egress_proxy_image"]` thread → both backend arms' tests FAILED, surfacing the exact `ghcr.io/bmzee` default vs configured `ghcr.io/cognic` mismatch → restored.
- **T6 handler hop:** dropped `pass_rate_floor=adversarial_pass_rate_floor` at the approve handler → the end-to-end gate-3 test's strict half went green (helper default) → FAILED → restored.

## The secret-resolution model (the four service secrets)

`litellm_master_key` / `langfuse_secret_key` / `embedding_api_key` /
`dynatrace_api_token` accept `None` / plaintext (DEV ONLY) / `vault://secret/<path>`.
In strict profiles plaintext is refused (G1); a `vault://` value is resolved
**once at construction** by reading the Vault secret's `"key"` dict field
(`{"key": "<secret>"}`, matching `compliance/iso42001/signing.py:_VAULT_KEY_FIELD`).
The 3 adapter secrets resolve via `build_adapters_async` (T2); the gateway's
`litellm_master_key` via the `LLMGateway(litellm_master_key=…)` constructor seam (T3).
`vault_token` is the bootstrap credential — required when any secret is `vault://`,
may not itself be `vault://` (G8), and is platform-secret-injected in prod (a
real/prod token is NEVER committed; dev examples may use a throwaway placeholder
like `dev-only-root`).

## Gate evidence (Z-gate, fresh `--cov-branch coverage.json`)

- **Full unit suite:** 9351 passed, 23 skipped (the 23 are standing env-gated K8s live-cluster tests).
- **Full-tree:** `ruff check .` ✅ · `ruff format --check .` ✅ (735 files) · `mypy src tests` ✅ (719 files).
- **Per-file critical-controls coverage gate: passed.** The 3 touched on-gate modules:
  - `llm/gateway.py` (T3) — line 99.12% / branch 100.00%
  - `portal/api/packs/review_routes.py` (T6) — line 100.00% / branch 100.00%
  - `portal/api/models/lifecycle_routes.py` (T4) — line 100.00% / branch 100.00%
- **Off-gate touched modules** (no promotion this wave — deliberate): `core/config.py` (settings layer, off-gate per the gate's own note), `db/adapters/secret_resolution.py` (new module), `db/adapters/factory.py`, `portal/api/app.py`, `portal/api/packs/router.py`, `sandbox/backend_factory.py` (Doctrine F selection seam). New module `secret_resolution.py` was NOT auto-promoted; flag for a future deliberate gate decision if it becomes an enforcement surface.

## Do-not-configure posture — UNCHANGED

No security floor was made loosenable; the Wave-1 work only **adds** floors or
**tightens**:

- `require_cosign` gained a strict-profile guard (G4) — it can no longer be
  silently `False` in stage/prod (the sole leaked invariant the audit found).
- `adversarial_pass_rate_floor` is **tighten-only** (`ge=0.99`) — banks may raise
  the bar, never drop below the kernel floor.
- Sandbox egress-proxy launch is now operator-configurable AND
  catalog/launch-consistent (T5) — no loosening; the canonical-image trust gate
  is unchanged.
- The hash-chain canonical form, evidence-pack format, RBAC, kill-switches,
  policy bundles, and protocol wire-formats were untouched.

## Open follow-ups (recorded, out of Wave-1 scope)

1. **Live secret resolution wiring (workstream #2 — Harness Injection).** T2's
   `build_adapters_async` is wired into the app lifespan; T3's gateway ships the
   **seam** only (`LLMGateway` has no live app construction site yet — it is
   test-constructed). Live `vault://` resolution for the gateway lands when the
   gateway is harness-wired.
2. **K8s / AppRole Vault auth.** Wave-1 uses static-token (`vault_token`) auth
   only; K8s ServiceAccount / AppRole flows that retire the static bootstrap
   token are deferred (named follow-up in spec §3.5).
3. **Official-namespace canonical image publish.** The canonical sandbox images
   still default to `ghcr.io/bmzee/...`; publishing them to an official
   `cognic/...` registry (so the *default* is usable in prod without an override)
   is a release/infra task. G7 + T5 ensure a bank that doesn't override fails
   loud rather than silently launching the personal-registry image.
4. **Runtime-python sandbox image** — verified at the T5 scope-lock to be
   admission/catalog-driven (no backend constructor arg); no divergence found, so
   no `runtime_python_image` constructor seam was invented. No follow-up.

## NOT Wave-1 (next workstreams, per the audit)

- **Per-tenant config-overlay mechanism** (charter §9 — the structural headline;
  ~10 P1 tenant-overlay candidates depend on it; gates Wave 2). Earns its own spec.
- **AGENTS.md doc reconciliation:** 3 critical-controls modules listed but not
  yet built (`core/auto_degradation.py`, `core/citation.py`,
  `retrieval/citation_verifier.py`).
- **Broad `.env.example` drift** (~45 fields beyond the Wave-1-touched set) — Wave-3.

## READY FOR GATE

All 8 tasks complete; full suite + full-tree lint/type + critical-coverage gate
all green. The branch (spec + plan + T1–T8) is ready to push + open as one
Wave-1 PR on the human's tokens.
