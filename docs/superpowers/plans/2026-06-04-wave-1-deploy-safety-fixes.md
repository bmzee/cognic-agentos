# Wave-1 Deploy-Safety Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Every task is critical-controls** (core/config.py validators, secret resolution, sandbox backend, portal gate) → run under `core-controls-engineer` + `/critical-module-mode` + **halt-before-commit**.

**Goal:** Close the Wave-1 deploy-safety findings from the Pre-GA Configurability Audit so a bank can stand up AgentOS in `stage`/`prod` without silently misconfiguring or insecurely exposing it.

**Architecture:** A sync **guard** in `core/config.py` (string-shape + profile only, fail-loud at config-load, no `db.adapters` import) + an async **resolver** at the adapter/wiring layer (`SecretAdapter.read(path)["key"]`, once at construction). Plus four bounded fixes (model-artifact path resolver, sandbox image threading, tighten-only pass-rate floor, `.env.example`).

**Tech stack:** Python 3.12, Pydantic-Settings, `uv run` for everything, pytest, ruff, mypy.

**Source spec:** `docs/superpowers/specs/2026-06-04-wave-1-deploy-safety-fixes-design.md`
**Branch:** `feat/wave-1-deploy-safety` (exists; spec committed `7efa8f7`). Do NOT create or switch branches.

---

## Global review pins (apply to EVERY task)

1. **No `core/config.py` → `db.adapters` import.** The guard is sync, string-shape only. An AST/import test pins it (T1 step).
2. **`"key"` Vault dict field everywhere** — the resolver reads `read(path)["key"]`; tests assert `{"key": "<secret>"}` shape; a missing `"key"` → `secret_field_resolution_failed`.
3. **`stage`/`prod` strict-profile tests** — every guard test parametrizes over `("stage", "prod")` for fail + `"dev"` for pass. Use `_STRICT_PROFILES = frozenset({"stage", "prod"})`.
4. **No per-call Vault reads** — `litellm_master_key` + the 3 adapter secrets resolve **once at construction**; a test pins that the per-call path reads a pre-resolved value, not the Settings field.
5. **TM-revert-ready negative test for every guard** — for each guard, the negative test must FAIL if the guard is deleted (verify by temporarily reverting the guard, confirming RED, restoring; document in the commit message per `feedback_security_regression_hardening`).
6. **Reason-prefix convention** — guard `ValueError` messages start with a stable reason-prefix (e.g. `secret_plain_value_forbidden_in_strict_profile:`); NOT a Literal enum (§3.7). Pin both rejected + allowed shapes in tests.
7. **Gate ladder** — `uv run` for all Python; `ruff check . && ruff format --check . && mypy src tests` full-tree at HALT; `pytest` narrow at HALT, **full at COMMIT**. No parallel `uv run` background.

## Shared constants (define in `core/config.py`, module scope)

```python
_STRICT_PROFILES: Final[frozenset[str]] = frozenset({"stage", "prod"})
_DEV_DEFAULT_EMBEDDING_MODEL: Final[str] = "qwen3-embedding:8b"
_DEV_DEFAULT_TIER1_ALIAS: Final[str] = "cognic-tier1-dev"
_DEV_DEFAULT_TIER2_ALIAS: Final[str] = "cognic-tier2-dev"
# personal-registry MARKER rule (NOT exact-default comparison): the guard rejects any
# sandbox image whose ref CONTAINS this personal namespace (substring test) — so a bank's
# own registry passes and any ghcr.io/bmzee image fails, however it was spelled.
_PERSONAL_REGISTRY_MARKER: Final[str] = "ghcr.io/bmzee/"
_SECRET_VAULT_FIELDS: Final[tuple[str, ...]] = (
    "litellm_master_key", "langfuse_secret_key", "embedding_api_key", "dynatrace_api_token",
)
```

---

## Task 1: `core/config.py` strict-profile guards + reason-prefix tests

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (add the shared constants + the model_validators; add the `adversarial_pass_rate_floor` field is T6 — not here)
- Test: `tests/unit/core/test_config_wave1_guards.py` (new)

Guards in this task (all in `core/config.py` `model_validator(mode="after")`, fail-loud at config-load):
- **G1 secret-plain** — for each of `_SECRET_VAULT_FIELDS`: `runtime_profile in _STRICT_PROFILES` and value is not `None` and not `startswith("vault://")` → `ValueError("secret_plain_value_forbidden_in_strict_profile: <field> …")`.
- **G2 deprecated `_vault_path`** — `embedding_api_key_vault_path` / `dynatrace_api_token_vault_path`: strict profile + set → `ValueError("vault_path_field_deprecated_use_vault_uri: …")`; `dev` + set → `logging.getLogger(...).warning(...)` (no raise).
- **G3 vault_token bootstrap (ANY profile)** — if any `_SECRET_VAULT_FIELDS` value `startswith("vault://")` and (`vault_addr is None` or `vault_token is None`) → `ValueError("vault_bootstrap_unset_for_secret_resolution: …")`.
- **G4 require_cosign** — strict profile + `require_cosign is False` → `ValueError("require_cosign_false_forbidden_in_strict_profile: …")`. (Implement beside the existing `dev_mode_skip_cosign` guard at config.py:1169-1174; that guard stays prod-only, unchanged.)
- **G5 embedding_model** — strict profile + `embedding_model == _DEV_DEFAULT_EMBEDDING_MODEL` → `ValueError("embedding_model_dev_default_in_strict_profile: …")`.
- **G6 tier aliases** — strict profile + (`allow_external_llm is True` or `policy_mode != "self_hosted"`) + (`tier1_alias == _DEV_DEFAULT_TIER1_ALIAS` or `tier2_alias == _DEV_DEFAULT_TIER2_ALIAS`) → `ValueError("tier_alias_dev_default_with_external_llm: …")`.
- **G7 sandbox images** — strict profile + (`_PERSONAL_REGISTRY_MARKER in sandbox_canonical_runtime_python_image` or `… in sandbox_canonical_egress_proxy_image`) → `ValueError("sandbox_canonical_image_personal_default_in_strict_profile: …")`.

- [ ] **Step 1: Write failing tests (RED)** — `tests/unit/core/test_config_wave1_guards.py`. Use the `Settings(...)` constructor with explicit kwargs (tests build Settings directly, suppressing `.env`). One representative per guard shown; write the full parametrized set.

```python
import pytest
from pydantic import ValidationError
from cognic_agentos.core.config import Settings

STRICT = ("stage", "prod")
_PIN = "@sha256:" + "a" * 64   # any valid digest-pin (satisfies the digest-pin validator)

def _base(**kw):
    # Sets EVERY other strict-profile guard to a PASSING value so only the field
    # under test (via **kw) trips its guard. Bootstrap present (G3), prod embedding
    # model (G5), non-personal digest-pinned sandbox images (G7); tier aliases stay
    # inert under the self_hosted default (G6). Each test overrides the one field it targets.
    base = {
        "vault_addr": "http://vault:8200",
        "vault_token": "boot",
        "embedding_model": "prod-embed-model",
        "sandbox_canonical_runtime_python_image": "ghcr.io/acme/runtime" + _PIN,
        "sandbox_canonical_egress_proxy_image": "ghcr.io/acme/proxy" + _PIN,
    }
    base.update(kw)
    return base

@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("field", ["litellm_master_key", "langfuse_secret_key",
                                   "embedding_api_key", "dynatrace_api_token"])
def test_g1_plain_secret_forbidden_in_strict_profile(profile, field):
    with pytest.raises(ValidationError, match="secret_plain_value_forbidden_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(**{field: "plaintext-secret"}))

@pytest.mark.parametrize("field", ["litellm_master_key", "langfuse_secret_key",
                                   "embedding_api_key", "dynatrace_api_token"])
def test_g1_vault_uri_ok_in_prod(field):
    s = Settings(runtime_profile="prod", **_base(**{field: "vault://secret/cognic/x"}))
    assert getattr(s, field) == "vault://secret/cognic/x"

@pytest.mark.parametrize("field", ["litellm_master_key", "langfuse_secret_key",
                                   "embedding_api_key", "dynatrace_api_token"])
def test_g1_plain_secret_ok_in_dev(field):
    s = Settings(runtime_profile="dev", **{field: "plaintext-secret"})  # dev: no other guard fires
    assert getattr(s, field) == "plaintext-secret"

@pytest.mark.parametrize("profile", STRICT)
def test_g2_deprecated_vault_path_forbidden(profile):
    with pytest.raises(ValidationError, match="vault_path_field_deprecated_use_vault_uri"):
        Settings(runtime_profile=profile, **_base(embedding_api_key_vault_path="secret/x"))

def test_g2_deprecated_vault_path_warns_in_dev(caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        Settings(runtime_profile="dev", embedding_api_key_vault_path="secret/x")  # dev: warn, no raise
    assert any(("vault_path" in r.message.lower()) or ("deprecat" in r.message.lower())
               for r in caplog.records), "dev _vault_path warning must be emitted"

@pytest.mark.parametrize("profile", ("dev", "stage", "prod"))
def test_g3_vault_bootstrap_required_any_profile(profile):
    # vault:// used but NO vault_addr/vault_token -> fail in ANY profile. Don't use _base
    # (it provides the bootstrap); satisfy G5/G7 inline so only G3 fires.
    with pytest.raises(ValidationError, match="vault_bootstrap_unset_for_secret_resolution"):
        Settings(runtime_profile=profile, embedding_model="prod-embed-model",
                 sandbox_canonical_runtime_python_image="ghcr.io/acme/r" + _PIN,
                 sandbox_canonical_egress_proxy_image="ghcr.io/acme/p" + _PIN,
                 litellm_master_key="vault://secret/x")

@pytest.mark.parametrize("profile", STRICT)
def test_g4_require_cosign_false_forbidden(profile):
    with pytest.raises(ValidationError, match="require_cosign_false_forbidden_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(require_cosign=False))

def test_g4_require_cosign_false_ok_in_dev():
    assert Settings(runtime_profile="dev", require_cosign=False).require_cosign is False

@pytest.mark.parametrize("profile", STRICT)
def test_g5_embedding_model_dev_default_forbidden(profile):
    # override _base's prod model back to the dev default to trip G5
    with pytest.raises(ValidationError, match="embedding_model_dev_default_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(embedding_model="qwen3-embedding:8b"))

@pytest.mark.parametrize("profile", STRICT)
def test_g6_tier_alias_guard_fires_when_not_self_hosted(profile):
    # non-self_hosted policy + dev tier alias (the default) -> G6 fires
    with pytest.raises(ValidationError, match="tier_alias_dev_default_with_external_llm"):
        Settings(runtime_profile=profile, **_base(policy_mode="cloud_openai"))

@pytest.mark.parametrize("profile", STRICT)
def test_g6_tier_alias_inert_under_self_hosted(profile):
    # self_hosted default + dev tier alias -> NO false positive
    s = Settings(runtime_profile=profile, **_base())
    assert s.tier1_alias == "cognic-tier1-dev"

@pytest.mark.parametrize("profile", STRICT)
def test_g7_sandbox_personal_image_default_forbidden(profile):
    # override _base's non-personal image with the shipped bmzee default to trip G7
    with pytest.raises(ValidationError, match="sandbox_canonical_image_personal_default_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(
            sandbox_canonical_egress_proxy_image="ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy" + _PIN))
```

Plus an import-purity test:
```python
def test_config_does_not_import_db_adapters():
    import ast, pathlib
    src = pathlib.Path("src/cognic_agentos/core/config.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        for m in mods:
            assert "db.adapters" not in m, f"config.py must not import db.adapters (found {m})"
```

- [ ] **Step 2: Run → verify RED.** `uv run pytest tests/unit/core/test_config_wave1_guards.py -q` → fails (guards not implemented; some tests may currently pass because the constructor succeeds — those are the ones the guard must start rejecting).
- [ ] **Step 3: Implement the guards.** Add the shared constants (module scope) + one `@model_validator(mode="after")` per guard group (or a single consolidated validator — author's call, but keep each reason testable). Each raises `ValueError("<reason-prefix>: <human message>")`. Reuse the existing prod-guard validator block (config.py:1099 / :1169) for proximity where natural; G4 goes beside `dev_mode_skip_cosign`. **Do not import `db.adapters`.**
- [ ] **Step 4: Run → verify GREEN.** `uv run pytest tests/unit/core/test_config_wave1_guards.py -q` → all pass.
- [ ] **Step 5: TM-revert verification.** For G1–G7, temporarily delete the guard, run the matching negative test, confirm it FAILS, restore. Record in the commit message.
- [ ] **Step 6: HALT for review.** `ruff check . && ruff format --check . && mypy src tests`; narrow pytest. Halt-before-commit (critical-controls).

---

## Task 2: Secret resolver + adapter-factory resolution (3 adapter secrets)

**Files:**
- Create: `src/cognic_agentos/db/adapters/secret_resolution.py`
- Modify: `src/cognic_agentos/db/adapters/factory.py` (add the async resolution seam)
- Test: `tests/unit/db/adapters/test_secret_resolution.py` (new) + a factory wiring test

- [ ] **Step 1: Write failing resolver tests (RED)** — `tests/unit/db/adapters/test_secret_resolution.py`.

```python
import pytest
from cognic_agentos.db.adapters.secret_resolution import resolve_secret_field, SecretFieldResolutionError

class _StubAdapter:
    def __init__(self, mapping): self._m = mapping
    async def read(self, path): return self._m[path]   # raises KeyError if absent

@pytest.mark.asyncio
async def test_none_passthrough():
    assert await resolve_secret_field(None, secret_adapter=_StubAdapter({}), field_name="x") is None

@pytest.mark.asyncio
async def test_plain_identity():
    assert await resolve_secret_field("plain", secret_adapter=_StubAdapter({}), field_name="x") == "plain"

@pytest.mark.asyncio
async def test_vault_uri_reads_key_field():
    a = _StubAdapter({"secret/cognic/litellm": {"key": "resolved-master-key"}})
    out = await resolve_secret_field("vault://secret/cognic/litellm", secret_adapter=a, field_name="litellm_master_key")
    assert out == "resolved-master-key"

@pytest.mark.asyncio
async def test_missing_key_field_fails_loud():
    a = _StubAdapter({"secret/x": {"not_key": "v"}})
    with pytest.raises(SecretFieldResolutionError, match="secret_field_resolution_failed"):
        await resolve_secret_field("vault://secret/x", secret_adapter=a, field_name="x")

@pytest.mark.asyncio
async def test_vault_unreachable_fails_loud():
    class _Boom:
        async def read(self, path): raise RuntimeError("vault down")
    with pytest.raises(SecretFieldResolutionError, match="secret_field_resolution_failed"):
        await resolve_secret_field("vault://secret/x", secret_adapter=_Boom(), field_name="x")

@pytest.mark.asyncio
async def test_non_dict_payload_fails_loud():
    class _BadShape:
        async def read(self, path): return "not-a-dict"
    with pytest.raises(SecretFieldResolutionError, match="not a dict"):
        await resolve_secret_field("vault://secret/x", secret_adapter=_BadShape(), field_name="x")

@pytest.mark.asyncio
async def test_empty_string_key_fails_loud():
    a = _StubAdapter({"secret/x": {"key": ""}})
    with pytest.raises(SecretFieldResolutionError, match="non-empty str"):
        await resolve_secret_field("vault://secret/x", secret_adapter=a, field_name="x")

@pytest.mark.asyncio
async def test_non_str_key_value_fails_loud():
    a = _StubAdapter({"secret/x": {"key": 12345}})
    with pytest.raises(SecretFieldResolutionError, match="non-empty str"):
        await resolve_secret_field("vault://secret/x", secret_adapter=a, field_name="x")
```

- [ ] **Step 2: Run → RED.** `uv run pytest tests/unit/db/adapters/test_secret_resolution.py -q`.
- [ ] **Step 3: Implement the resolver** — `db/adapters/secret_resolution.py`:

```python
"""Async resolution of a config secret field that may carry a ``vault://`` URI."""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

_VAULT_PREFIX = "vault://"
_SECRET_VALUE_KEY = "key"   # matches compliance/iso42001/signing.py:_VAULT_KEY_FIELD

class SecretFieldResolutionError(RuntimeError):
    """Raised (reason-prefix ``secret_field_resolution_failed``) when a ``vault://`` field
    cannot be resolved (Vault unreachable, path missing, or no ``"key"`` field)."""

def _fail(field_name, path, why):
    raise SecretFieldResolutionError(
        f"secret_field_resolution_failed: {field_name} (path={path!r}): {why}"
    )

async def resolve_secret_field(value, *, secret_adapter, field_name):
    if value is None:
        return None
    if not value.startswith(_VAULT_PREFIX):
        return value
    path = value[len(_VAULT_PREFIX):]
    try:
        payload = await secret_adapter.read(path)
    except Exception as exc:  # noqa: BLE001 — fail-loud, wrap into the closed reason
        raise SecretFieldResolutionError(
            f"secret_field_resolution_failed: {field_name} (path={path!r}): "
            f"read failed: {type(exc).__name__}: {exc}"
        ) from exc
    # Fail-loud on every malformed-payload shape (a bank secret must be a real string).
    if not isinstance(payload, dict):
        _fail(field_name, path, f"Vault payload is not a dict (got {type(payload).__name__})")
    if _SECRET_VALUE_KEY not in payload:
        _fail(field_name, path, f"Vault secret missing the {_SECRET_VALUE_KEY!r} field")
    resolved = payload[_SECRET_VALUE_KEY]
    if not isinstance(resolved, str) or not resolved:
        _fail(field_name, path,
              f"{_SECRET_VALUE_KEY!r} must be a non-empty str (got {type(resolved).__name__})")
    return resolved
```

- [ ] **Step 4: Run → GREEN** (resolver unit tests).
- [ ] **Step 5: Add `build_adapters_async`; keep `build_adapters` SYNC (LOCKED).** Do **not** make `build_adapters` async — it is a sync public API called at `portal/api/app.py:523` + many tests; making it async = broad sync-call churn. Add `async def build_adapters_async(settings, *, registry=bundled_registry) -> Adapters` in `factory.py` that: (1) builds the secret adapter from the original `settings` (needs `vault_addr`/`vault_token`, present per G3); (2) resolves the 3 service secrets via `resolve_secret_field(...)` once; (3) builds a resolved Settings via `settings.model_copy(update={"embedding_api_key": …, "langfuse_secret_key": …, "dynatrace_api_token": …})` — **`model_copy` does NOT re-run validators**, so the resolved plain values do not re-trip the secret guard; (4) `return build_adapters(resolved_settings, registry=registry)`. Then change `portal/api/app.py:523` from `build_adapters(settings, ...)` to `await build_adapters_async(settings, ...)`. The sync `_embedding_args`/`_observability_args` stay **UNCHANGED** (no `await`); all other sync callers/tests keep working — **except** `build_adapters` gains one fail-loud preflight (Step 5b).
- [ ] **Step 5b: Sync `build_adapters` fail-loud preflight (RED→GREEN).** Config now PERMITS `vault://` service secrets, so a *direct sync* `build_adapters` caller could otherwise leak an unresolved `vault://` value to an adapter as an API key. At the top of `build_adapters`, for each of the 3 ADAPTER secrets `embedding_api_key` / `langfuse_secret_key` / `dynatrace_api_token`: if the value `startswith("vault://")` → raise `RuntimeError("build_adapters_sync_unresolved_vault_secret: <field> is a vault:// URI; call build_adapters_async (sync build_adapters cannot resolve secrets)")`. (NOT `litellm_master_key` — the factory doesn't consume it; that's the gateway's, T3.) Test: `build_adapters(Settings(..., embedding_api_key="vault://x", + bootstrap))` raises that reason-prefix; `build_adapters_async` with the same value SUCCEEDS — it resolves BEFORE delegating, so the delegated `build_adapters(resolved_settings)` sees a plain value and passes the preflight.
- [ ] **Step 6: Write the factory wiring test (RED→GREEN).** Given `embedding_api_key="vault://secret/emb"` + an injected `InMemorySecretAdapter` holding `{"secret/emb": {"key": "resolved"}}`, the constructed embedding adapter receives `"resolved"` (not the `vault://` URI). Assert on the embedding adapter's captured key.
- [ ] **Step 7: HALT** (gate ladder + halt-before-commit).

---

## Task 3: LLM gateway `litellm_master_key` resolution seam

**Reality (verified):** `LLMGateway` (gateway.py:214, keyword-only `__init__`) has **no live app-wiring construction site** — it is constructed only in tests today (consistent with the harness-injection-deferred state). So Wave-1 ships the **seam**, not live resolution wiring; the actual resolve-from-Vault lands when the gateway is harness-wired (workstream #2). LOCKED approach: a pre-resolved constructor param (NOT a hunt for an absent construction site).

**Files:**
- Modify: `src/cognic_agentos/llm/gateway.py`
- Test: `tests/unit/llm/test_gateway_secret_resolution.py` (new)

- [ ] **Step 1: Write failing test (RED).** Construct `LLMGateway(..., litellm_master_key="resolved-key")` (with the existing required kwargs); assert the per-call `Authorization` header uses `"resolved-key"`. Then monkeypatch `settings.litellm_master_key` to a *different* value AFTER construction and assert the call STILL uses `"resolved-key"` → proves the master key is read **once at construction**, never per-call. **PLUS a fail-loud test:** `LLMGateway(settings=Settings(runtime_profile="dev", vault_addr="http://v", vault_token="b", litellm_master_key="vault://secret/x"), ...)` with NO `litellm_master_key=` param → raises `RuntimeError` matching `litellm_master_key_unresolved_vault_uri` (must never store/send `Bearer vault://...`).
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement (constructor-param seam + fail-loud fallback).** Add an optional keyword param `litellm_master_key: str | None = None` to `LLMGateway.__init__` (gateway.py:214). In `__init__`: **fail loud if the fallback would send a `vault://` URI** — if `litellm_master_key is None` AND `settings.litellm_master_key` starts with `"vault://"` → raise `RuntimeError("litellm_master_key_unresolved_vault_uri: settings.litellm_master_key is a vault:// URI but no resolved value was passed; the harness must resolve it and pass litellm_master_key=")`. Otherwise `self._litellm_master_key = litellm_master_key if litellm_master_key is not None else settings.litellm_master_key` — read **once at construction**. Change `gateway.py:333` to use `self._litellm_master_key` (never `self._settings.litellm_master_key`). **Pin: no per-call read; never send `Bearer vault://…`.** Document in the `__init__` docstring that a future harness resolves via `resolve_secret_field(...)` and passes the result as `litellm_master_key=`; cross-ref the deferred harness wiring. (No live app-wiring change in this task — there is none to change.)
- [ ] **Step 4: GREEN; Step 5: HALT** (gate ladder + halt-before-commit).

---

## Task 4: `model_artifact_root` profile-aware resolver

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (field type → `str | None`, default `None`; `_default_model_artifact_root()` helper; `model_validator`)
- Test: `tests/unit/core/test_config_model_artifact_root.py` (new)

- [ ] **Step 1: Write failing tests (RED).**
```python
import os, pytest
from cognic_agentos.core.config import Settings

def test_prod_unset_resolves_var_lib():
    s = Settings(runtime_profile="prod", vault_addr="http://v:8200", vault_token="b",
                 embedding_model="prod-model")
    assert s.model_artifact_root == "/var/lib/cognic/model-artifacts"
    assert isinstance(s.model_artifact_root, str)

@pytest.mark.parametrize("profile", ("dev", "stage"))
def test_dev_stage_unset_resolves_tmpdir(profile, monkeypatch):
    monkeypatch.setenv("TMPDIR", "/tmp/x")
    kw = {} if profile == "dev" else {"vault_addr": "http://v:8200", "vault_token": "b", "embedding_model": "m"}
    s = Settings(runtime_profile=profile, **kw)
    assert s.model_artifact_root.startswith("/tmp/x")

def test_explicit_override_wins():
    s = Settings(runtime_profile="prod", model_artifact_root="/srv/models",
                 vault_addr="http://v:8200", vault_token="b", embedding_model="m")
    assert s.model_artifact_root == "/srv/models"
```
- [ ] **Step 2: RED.** `uv run pytest tests/unit/core/test_config_model_artifact_root.py -q`.
- [ ] **Step 3: Implement.** Change the field to `model_artifact_root: str | None = Field(default=None, ...)`; add `_default_model_artifact_root()` (mirror `_default_object_store_root()`, config.py:1682 — `$TMPDIR`-derived str, else `/var/lib/cognic/model-artifacts`); add a `model_validator(mode="after")` (mirror `_resolve_local_object_store_root`, config.py:1177): if `None` → prod `"/var/lib/cognic/model-artifacts"`, dev/stage → `_default_model_artifact_root()`. Resolver fills a **str**. The sole consumer `lifecycle_routes.py:278` (`Path(settings.model_artifact_root)`) is unaffected.
- [ ] **Step 4: GREEN; Step 5: HALT.**

---

## Task 5: Sandbox image threading (both backends + runtime-python verify)

**Files:**
- Modify: `src/cognic_agentos/sandbox/backend_factory.py`
- Test: `tests/unit/sandbox/test_backend_factory_image_threading.py` (new)

- [ ] **Step 1: Read + confirm (scope-lock the runtime-python path).** The live backend constructors expose **`egress_proxy_image` ONLY** (`docker_sibling.py:956` / `kubernetes_pod.py:977`) — there is NO `runtime_python_image` constructor arg. So Wave-1 threads **only** `egress_proxy_image`. For the runtime-python image: **verify** (read the backend `create()` / admission flow) that it is **catalog/admission-driven** (the runtime image to launch comes from pack admission, validated against the catalog) and NOT a separate hardcoded constructor fallback. **Do NOT invent a `runtime_python_image` constructor seam** — only raise a finding (and stop for review) if that read produces evidence of an actual un-threaded runtime-launch path. Scope-creep guard.
- [ ] **Step 2: Write failing test (RED).** Build the backend via `backend_factory.get_backend(settings)` with `sandbox_canonical_egress_proxy_image` overridden to a non-bmzee ref; assert the constructed backend's launched image (`backend._egress_proxy_image`, docker_sibling.py:987 / kubernetes_pod.py:1010) equals the overridden Settings value (and equals the catalog's canonical ref → no mismatch). (Mock the backend extra-import so the test runs without docker/k8s libs — follow the existing `test_backend_factory.py` skip/mocking pattern.) No runtime-python assertion (catalog-driven per Step 1).
- [ ] **Step 3: Implement.** In `backend_factory.get_backend`, pass `egress_proxy_image=settings.sandbox_canonical_egress_proxy_image` into the backend constructor `**kwargs`, alongside the existing `settings` + `image_catalog` injection (backend_factory.py:85/:100). **No `runtime_python_image` kwarg** (no such constructor arg exists). **Invariant the test pins:** catalog canonical egress-proxy ref == backend launched egress-proxy ref for any override.
- [ ] **Step 4: GREEN.** **Step 5: HALT** — this is a `sandbox/` isolation boundary; backends are on the CC gate; halt-before-commit.

---

## Task 6: `adversarial_pass_rate_floor` Settings field + `review_routes` parameterization

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (new field); `src/cognic_agentos/portal/api/packs/review_routes.py` (parameterize the helper + update the caller)
- Test: `tests/unit/core/test_config_adversarial_floor.py` + `tests/unit/portal/api/packs/test_review_routes_floor.py`

- [ ] **Step 1: Write failing tests (RED).**
```python
# config field
import pytest
from pydantic import ValidationError
from cognic_agentos.core.config import Settings

def test_floor_default_and_tighten_only():
    assert Settings(runtime_profile="dev").adversarial_pass_rate_floor == 0.99
    assert Settings(runtime_profile="dev", adversarial_pass_rate_floor=0.999).adversarial_pass_rate_floor == 0.999

def test_floor_rejects_below_kernel_floor():
    with pytest.raises(ValidationError):
        Settings(runtime_profile="dev", adversarial_pass_rate_floor=0.95)  # ge=0.99
```
For `review_routes`: a test that `_build_adversarial_gate_input(raw, pass_rate_floor=0.999)` builds the gate input using the passed floor (a pass_rate of 0.995 fails against 0.999 but passes against 0.99) — proving the threshold is parameterized, not the module constant.
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.** Add `adversarial_pass_rate_floor: float = Field(default=0.99, ge=0.99, le=1.0, description=...)` to `core/config.py`. In `review_routes.py`: change `_build_adversarial_gate_input(raw: Any)` (:221) → `_build_adversarial_gate_input(raw: Any, *, pass_rate_floor: float)`; replace the `_ADVERSARIAL_PASS_RATE_THRESHOLD` comparison (:263) with `pass_rate_floor`; remove or keep `_ADVERSARIAL_PASS_RATE_THRESHOLD` as the documented kernel-floor constant only. Update the caller at `:826` to pass `pass_rate_floor=settings.adversarial_pass_rate_floor` (`settings` is captured by `build_review_routes` :478). **Not** `get_settings()`.
- [ ] **Step 4: GREEN; Step 5: HALT.**

---

## Task 7: `.env.example` reconciliation (Wave-1 fields only)

**Files:** Modify: `.env.example`

- [ ] **Step 1.** Add/adjust entries for the Wave-1-touched fields ONLY (the broad ~45-field drift is Wave-3, NOT here):
  - the 4 service secrets: document `…=vault://secret/cognic/<...>` (prod) with the `{"key": "<secret>"}` Vault shape; show the `dev` plain form as dev-only.
  - **remove** the `COGNIC_EMBEDDING_API_KEY_VAULT_PATH` / `COGNIC_DYNATRACE_API_TOKEN_VAULT_PATH` example lines (deprecated; fail-loud in strict profiles).
  - `COGNIC_VAULT_TOKEN` — note it's the bootstrap, platform-secret-injected, never a committed value.
  - `COGNIC_ADVERSARIAL_PASS_RATE_FLOOR` (default 0.99, tighten-only).
  - `COGNIC_MODEL_ARTIFACT_ROOT` — note the profile-aware default (unset → prod `/var/lib`, dev/stage `$TMPDIR`).
- [ ] **Step 2.** No test (config-surface doc). Whitespace check via `git add -N .env.example && git diff --check`. **HALT.**

---

## Task 8 (Z gate): full suite + critical-coverage + closeout

**Files:** Create: `docs/closeouts/2026-06-04-wave-1-deploy-safety.md`

- [ ] **Step 1: Full suite.** `uv run pytest -q` — all green (record counts).
- [ ] **Step 2: Full-tree lint/type.** `ruff check . && ruff format --check . && uv run mypy src tests`.
- [ ] **Step 3: Critical-coverage check.** Determine whether `core/config.py` (and any other touched module) is on the durable CC gate (`tools/check_critical_coverage.py::_CRITICAL_FILES`). If **yes**, run `tools/check_critical_coverage.py` against a **fresh** `--cov-branch coverage.json` (per `feedback_verify_promotion_meets_floor_at_promotion_time`) and confirm the new guard/validator code keeps it ≥ 95% line / 90% branch; land any focused negative-path coverage repair in the SAME task. If a new module (`db/adapters/secret_resolution.py`) warrants gate promotion, that's a deliberate decision — flag it, don't auto-promote.
- [ ] **Step 4: Closeout doc** — summarize the 7 fixes, the guard reason-prefixes (now test-pinned), the TM-revert evidence, the open follow-ups (K8s/AppRole auth; official-namespace image publish; runtime-python image if it diverged), and confirm no do-not-configure invariant changed.
- [ ] **Step 5: HALT — READY FOR GATE.** This is the point to (on the human's tokens) push the branch + open the Wave-1 PR (spec + plan + code as one unit).

---

## Self-review notes
- Every guard has a strict-profile (stage+prod) negative test + a dev-pass test + TM-revert (pin 5).
- Resolver locked to `"key"` (pin 2); no per-call Vault read (pins 4, T3 step 2).
- `core/config.py` import-purity test (pin 1, T1).
- `model_artifact_root` typed `str | None`, consumer unaffected (T4).
- Reason-prefixes are `ValueError` substrings pinned by tests, not a Literal enum (pin 6).
- Task order is dependency-safe: T2's resolver is imported by T3; T1/T4/T6 touch config.py independently; T5 is isolated; T8 gates everything.

## Execution handoff
Use **superpowers:subagent-driven-development** — fresh subagent per task, two-stage review (spec-compliance then code-quality), halt-before-commit per task under `/critical-module-mode`. Do NOT push/PR until T8 READY FOR GATE + explicit human tokens.
