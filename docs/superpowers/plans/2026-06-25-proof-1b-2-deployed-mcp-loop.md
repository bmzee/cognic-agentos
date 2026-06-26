# Proof 1b-2 — Deployed Governed MCP Invocation Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This is a DEPLOYED-PROOF plan — most tasks build infra/images/manifests; only T1–T3 carry unit tests, and the proof RUN itself (T9) is gated behind `COGNIC_RUN_PROOF_1B2=1` and is operator-run, never in PR CI.**

**Goal:** In a `kind` cluster, prove a deployed AgentOS kernel performs the full governed MCP invocation path — `discovery_status=auth_ready` + real `list_tools`/`call_tool` — against an in-cluster MCP tool Service reachable only through the PR-2b-1 override + exact-IP allow-list, with the OAuth legs reaching an emulated-external (public-shaped) AS.

**Architecture:** Extend the Proof 1b-1 deploy harness (on branch `feat/pack-loop-proof-1b @ 2125b22`) into a new `infra/proof-1b-2/` tree. Deploy the default-adapters AgentOS image (prod profile) via a thin proof-only `create_proof_app` factory that wires a fixed-Actor binder; deploy a private-ClusterIP MCP tool Service (from `examples/cognic-tool-search`) and an emulated-external AS (from `tests/integration/pack_loop/_local_as.py`) at a genuine-global `externalIP` (kube-proxy-intercepted, no real egress). Seed the override/allow-list rows in Postgres and the OAuth/AS-allowlist secrets in Vault (KV v1). A single runner drives Bar 1 (carve-out checkpoint) then Bar 2 (full loop).

**Tech Stack:** kind, Helm, kubectl, Docker, Postgres 16, Vault 1.18 (dev, KV v1), Python 3.12, `mcp==1.27.0` (FastMCP), Starlette/uvicorn, hvac.

## Global Constraints

- **Source spec:** `docs/superpowers/specs/2026-06-25-proof-1b-2-deployed-mcp-loop-design.md` (every requirement below traces to it).
- **The kernel is NOT modified.** No file under `src/cognic_agentos/` changes. The only repo-code edits are to the two test/example fixtures (`examples/cognic-tool-search/.../server.py`, `tests/integration/pack_loop/_local_as.py`) and NEW proof-only files under `infra/proof-1b-2/` + `tests/integration/proof_1b_2/`.
- **Proof-only fixed-actor binder (Option A, user-locked):** lives in the proof harness/image, NOT the kernel. Fixed tenant `proof-1b-2`; scopes EXACTLY `{"mcp.tool.list", "mcp.tool.invoke"}`; `actor_type="service"`. It calls the normal `create_app(...)` and only sets `app.state.actor_binder` — it does NOT fork runtime behavior. **The plan + the proof README must record: production still requires a real bank-overlay actor binder; this binder is proof-only.**
- **The single effective MCP URL** = `http://10.96.0.50:8765/mcp` — byte-identical across: the override row `server_url_override`, the MCP server's `COGNIC_PROOF_SERVER_URL` (→ PRM `resource_server_url` + token `resource`), the AgentOS-sent RFC-8707 `resource`, and the AS-echoed token `aud`. `10.96.0.50` is a **static private ClusterIP** (within the default service CIDR `10.96.0.0/12`; `is_private=True`, passes `ip_passes_internal_floor`).
- **The AS issuer** = `http://192.88.99.9:9000` — byte-identical across: the MCP server's `COGNIC_PROOF_AS_ISSUER` (→ PRM `authorization_servers`), the Vault `mcp-as-allowlist` `servers[0]`, the Vault path segment `as_host` = `192.88.99.9_9000`, and the AS's `_AS_ISSUER` (→ `token_endpoint` + `issuer`). `192.88.99.9` is RFC7526 deprecated 6to4-relay-anycast: `is_global=True` (guard allows the OAuth legs) yet special-purpose (kube-proxy-intercepted, **no real external egress**).
- **MCP Service stays a private ClusterIP** — reachable only via the override + allow-list carve-out; never a guard-allowed address. **OAuth legs stay hard-public-only** — no carve-out added; PR-2b-0 intact.
- **Vault is KV v1** at `secret/` — the bundled adapter does a raw `transport.read(path)` and the Settings templates have no `/data/` segment; the proof's Vault init disables the dev `secret/` (KV v2 default) and re-enables it `-version=1`.
- **Bar 1 is a checkpoint, Bar 2 is completion.** If Bar 2 cannot be stood up, record a design/product finding in `docs/VALIDATION-RESULTS.md` — never redefine the proof downward.
- **Findings F1 (no guard-allowed documentation range) + F2 (CGNAT `is_private=False`)** are recorded in `docs/VALIDATION-RESULTS.md` regardless of outcome.
- Run all Python via `uv run`. Branch: `feat/proof-1b-2-deployed-mcp-loop`. Never stage the 3 protected docs or `infra/proof-1b/` staging.
- **T4–T6 are AUTHOR-ONLY (user-locked decision):** the three image Dockerfiles (T4 MCP server, T5 AS, T6 proof AgentOS) are AUTHORED + pinned by a structural pytest (`tests/unit/proof_1b_2/test_proof_images.py`, extended per image); the actual `docker build` is **DEFERRED to the T9 operator run** (which rebuilds the wheel + builds every image — a broken Dockerfile is caught there). No Docker/kind authority is spent during the T1–T8 authoring slices; only T9 (env-gated `COGNIC_RUN_PROOF_1B2=1`, explicit operator authorization) runs Docker/kind.

---

## File Structure

**Fixture edits (existing files, env-driven so defaults stay backward-compatible):**
- `examples/cognic-tool-search/src/cognic_tool_search/server.py` — `_HOST` + `_SERVER_URL` become env-driven (defaults unchanged).
- `tests/integration/pack_loop/_local_as.py` — `_AS_ISSUER` + `run_local_as` host become env-driven; add a `__main__`.

**NEW proof-only Python (test tree — importable by tests + baked into images):**
- `tests/integration/proof_1b_2/__init__.py`
- `tests/integration/proof_1b_2/proof_app.py` — `ProofActorBinder` + `create_proof_app()` factory.
- `tests/unit/proof_1b_2/test_proof_app.py` — unit tests for the binder + factory.

**NEW proof harness (`infra/proof-1b-2/`):**
- `Dockerfile.agentos-proof` — bakes `create_proof_app` + the trust-staging onto the default-adapters base.
- `Dockerfile.mcp-server` — the MCP tool Service image.
- `Dockerfile.as` — the emulated-external AS image.
- `manifests/mcp-server.yaml` — Deployment + Service (static `clusterIP: 10.96.0.50`).
- `manifests/auth-server.yaml` — Deployment + Service (`externalIPs: [192.88.99.9]`).
- `proof-1b-2-values.yaml` — Helm values (proof image, prod profile, migrations off).
- `migrate-job.yaml` — copied/adapted from the 1b-1 harness.
- `seed-db.sh` — seeds the override + allow-list rows in Postgres.
- `seed-vault.sh` — converts `secret/` to KV v1 + seeds the OAuth + AS-allowlist secrets.
- `run-proof-1b-2.sh` — the operator-run end-to-end runner (Bar 1 then Bar 2).
- `README.md` — records the proof-only-binder caveat + the run instructions.

**Reused verbatim from `feat/pack-loop-proof-1b @ 2125b22`** (copy into `infra/proof-1b-2/` or `git checkout` the paths): `tests/integration/proof_1b/stage_trust_inputs.py` (trust staging), the backend pre-pull loop, and the `Dockerfile.proof1b` bake pattern.

---

### Task 1: MCP server fixture — env-driven host + URL

**Files:**
- Modify: `examples/cognic-tool-search/src/cognic_tool_search/server.py` (lines 21, 23)
- Test: `examples/cognic-tool-search/tests/test_server_env.py` (NEW)

**Interfaces:**
- Produces: the server binds `COGNIC_PROOF_HOST` (default `127.0.0.1`) and advertises `COGNIC_PROOF_SERVER_URL` (default `http://127.0.0.1:8765/mcp`) as both the PRM `resource_server_url` and the token `resource`.

- [ ] **Step 1: Write the failing test**
```python
# examples/cognic-tool-search/tests/test_server_env.py
import importlib
def test_server_url_is_env_driven(monkeypatch):
    monkeypatch.setenv("COGNIC_PROOF_SERVER_URL", "http://10.96.0.50:8765/mcp")
    monkeypatch.setenv("COGNIC_PROOF_HOST", "0.0.0.0")
    import cognic_tool_search.server as s
    importlib.reload(s)
    assert s._SERVER_URL == "http://10.96.0.50:8765/mcp"
    assert s._HOST == "0.0.0.0"
def test_defaults_unchanged(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_SERVER_URL", raising=False)
    monkeypatch.delenv("COGNIC_PROOF_HOST", raising=False)
    import cognic_tool_search.server as s
    importlib.reload(s)
    assert s._SERVER_URL == "http://127.0.0.1:8765/mcp"
    assert s._HOST == "127.0.0.1"
```

- [ ] **Step 2: Run it, verify it fails** — `uv run pytest examples/cognic-tool-search/tests/test_server_env.py -v` (run from the REPO ROOT — `cd examples/cognic-tool-search && uv run …` spins a separate nested `.venv` with the wrong pytest and no `cognic_tool_search` synced; the example pack has no `[tool.pytest.ini_options]`, so the repo-root env applies. NOTE for T4/T9: the `uv build --wheel` commands DO `cd examples/cognic-tool-search` on purpose — that builds the example's own wheel, which is correct.) → FAIL (constants are literals, env ignored).

- [ ] **Step 3: Implement** — `server.py` imports `os` ONLY inside `if __name__ == "__main__"` (L71), so FIRST add a top-level `import os` (with the other top-level imports, after the `from __future__` line), THEN change lines 21 + 23:
```python
import os  # NEW top-level import — currently `os` is imported only inside __main__ (L71)
# ...
_HOST = os.environ.get("COGNIC_PROOF_HOST", "127.0.0.1")          # L21
_SERVER_URL = os.environ.get("COGNIC_PROOF_SERVER_URL", "http://127.0.0.1:8765/mcp")  # L23
```
(The `__main__` block's local `import os` at L71 is now redundant — leave it or delete it, harmless; `as_issuer` is already env-driven via `COGNIC_PROOF_AS_ISSUER` at L73 — no change.)

- [ ] **Step 4: Run it, verify it passes** — same command → 2 passed.

- [ ] **Step 5: Commit** — `git add examples/cognic-tool-search/src/cognic_tool_search/server.py examples/cognic-tool-search/tests/test_server_env.py && git commit -m "feat(proof-1b-2): env-drive the cognic-tool-search server host + URL"`

---

### Task 2: AS fixture — env-driven issuer + bind + `__main__`

**Files:**
- Modify: `tests/integration/pack_loop/_local_as.py` (lines 28, 66; add `__main__`)
- Test: `tests/unit/proof_1b_2/test_local_as_env.py` (NEW) + `tests/unit/proof_1b_2/__init__.py` (NEW, empty)

**Interfaces:**
- Produces: `_AS_ISSUER` reads `COGNIC_PROOF_AS_ISSUER` (default `http://127.0.0.1:9000`); `run_local_as` binds `COGNIC_PROOF_AS_HOST` (default `127.0.0.1`); `python -m tests.integration.pack_loop._local_as` runs the AS on `COGNIC_PROOF_AS_PORT` (default `9000`).

- [ ] **Step 1: Write the failing test**
```python
# tests/unit/proof_1b_2/test_local_as_env.py
import importlib
def test_as_issuer_env_driven(monkeypatch):
    monkeypatch.setenv("COGNIC_PROOF_AS_ISSUER", "http://192.88.99.9:9000")
    import tests.integration.pack_loop._local_as as m
    importlib.reload(m)
    assert m._AS_ISSUER == "http://192.88.99.9:9000"
def test_as_issuer_default(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_AS_ISSUER", raising=False)
    import tests.integration.pack_loop._local_as as m
    importlib.reload(m)
    assert m._AS_ISSUER == "http://127.0.0.1:9000"
```

- [ ] **Step 2: Run it, verify it fails** — `uv run pytest tests/unit/proof_1b_2/test_local_as_env.py -v` → FAIL.

- [ ] **Step 3: Implement** — line 28 + line 66 + a `__main__` at end:
```python
_AS_ISSUER = os.environ.get("COGNIC_PROOF_AS_ISSUER", "http://127.0.0.1:9000")  # L28 (add `import os` at top if absent)
# ... run_local_as: host=os.environ.get("COGNIC_PROOF_AS_HOST", "127.0.0.1")  # was "127.0.0.1" at L66
if __name__ == "__main__":  # NEW
    run_local_as(port=int(os.environ.get("COGNIC_PROOF_AS_PORT", "9000")))
```

- [ ] **Step 4: Run it, verify it passes** — same command → 2 passed.

- [ ] **Step 5: Commit** — `git add tests/integration/pack_loop/_local_as.py tests/unit/proof_1b_2/ && git commit -m "feat(proof-1b-2): env-drive the local AS issuer/host + add __main__"`

---

### Task 3: Proof-only ActorBinder + `create_proof_app`

**Files:**
- Create: `tests/integration/proof_1b_2/__init__.py` (empty), `tests/integration/proof_1b_2/proof_app.py`
- Test: `tests/unit/proof_1b_2/test_proof_app.py` (NEW)

**Interfaces:**
- Consumes: `cognic_agentos.portal.api.app.create_app`, `cognic_agentos.portal.rbac.actor.{Actor, ActorBinder}`.
- Produces: `ProofActorBinder` (sync `bind(*, request) -> Actor` returning the fixed proof Actor) + `create_proof_app() -> FastAPI` (calls `create_app(adapter_registry=bundled)` then sets `app.state.actor_binder`).

- [ ] **Step 1: Write the failing test**
```python
# tests/unit/proof_1b_2/test_proof_app.py
from tests.integration.proof_1b_2.proof_app import ProofActorBinder, PROOF_TENANT, PROOF_SCOPES
def test_binder_yields_fixed_proof_actor():
    actor = ProofActorBinder().bind(request=None)
    assert actor.tenant_id == PROOF_TENANT == "proof-1b-2"
    assert set(actor.scopes) == PROOF_SCOPES == {"mcp.tool.list", "mcp.tool.invoke"}
    assert actor.actor_type == "service"
def test_scopes_are_exactly_the_two_mcp_tool_scopes():
    # guardrail: no broader grant leaks in
    assert ProofActorBinder().bind(request=None).scopes == frozenset({"mcp.tool.list", "mcp.tool.invoke"})
```

- [ ] **Step 2: Run it, verify it fails** — `uv run pytest tests/unit/proof_1b_2/test_proof_app.py -v` → FAIL (module missing).

- [ ] **Step 3: Implement** `tests/integration/proof_1b_2/proof_app.py`:
```python
"""PROOF-ONLY app factory + fixed-actor binder for Proof 1b-2.

NOT kernel product behavior. Production requires a real bank-overlay ActorBinder
(OIDC/mTLS-backed). This binder yields ONE fixed Actor scoped to the proof tenant
and exactly the two MCP tool scopes, so the deployed governed MCP invoke route
(/api/v1/mcp/...) can be driven end-to-end. It does NOT fork runtime behavior —
it calls the normal create_app() and only sets app.state.actor_binder.
"""
from __future__ import annotations
from typing import Final
from fastapi import FastAPI, Request
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import MCPRBACScope

PROOF_TENANT: Final = "proof-1b-2"
# Typed element (NOT a bare `Final`, which infers frozenset[str] and is rejected by
# strict mypy at the Actor(scopes=...) call site — frozenset is covariant so
# frozenset[MCPRBACScope] IS assignable to Actor.scopes). Same idiom as MCP_SCOPES.
PROOF_SCOPES: Final[frozenset[MCPRBACScope]] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})

class ProofActorBinder:
    """Yields a single fixed proof Actor for every request. PROOF-ONLY."""
    def bind(self, *, request: Request | None) -> Actor:  # matches the kernel ActorBinder Protocol
        return Actor(subject="proof-1b-2-operator", tenant_id=PROOF_TENANT,
                     scopes=PROOF_SCOPES, actor_type="service")

def create_proof_app() -> FastAPI:
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.db.adapters import bundled_registry  # same import path create_prod_app uses (app.py:51)
    app = create_app(adapter_registry=bundled_registry)
    app.state.actor_binder = ProofActorBinder()
    return app
```
(Verify `bundled_registry` is the exact symbol `create_prod_app` uses at `portal/api/app.py:1773`; if it is constructed inline there, replicate that one line here rather than importing a non-existent name.)

- [ ] **Step 4: Run it, verify it passes** — same command → 2 passed. Also `uv run python -c "from tests.integration.proof_1b_2.proof_app import create_proof_app"` imports clean (factory not called — avoids needing a live engine).

- [ ] **Step 5: Commit** — `git add tests/integration/proof_1b_2/ tests/unit/proof_1b_2/test_proof_app.py && git commit -m "feat(proof-1b-2): proof-only fixed-actor binder + create_proof_app factory"`

---

### Task 4: MCP tool Service image

**Files:** Create `infra/proof-1b-2/Dockerfile.mcp-server` + `tests/unit/proof_1b_2/test_proof_images.py` (the author-time structural test)

- [ ] **Step 1: Write the Dockerfile**
```dockerfile
# infra/proof-1b-2/Dockerfile.mcp-server — PROOF-ONLY in-cluster MCP tool Service
FROM python:3.12-slim
RUN pip install --no-cache-dir "mcp==1.27.0" "uvicorn[standard]>=0.35"
# the prebuilt wheel ships in-tree; build context = repo root
COPY examples/cognic-tool-search/dist/cognic_tool_search-0.1.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir --no-deps /tmp/cognic_tool_search-0.1.0-py3-none-any.whl
EXPOSE 8765
CMD ["python", "-m", "cognic_tool_search.server"]
```
(If `dist/*.whl` is stale vs the Task-1 edits, rebuild first: `cd examples/cognic-tool-search && uv build --wheel`. The Task-1 edits ARE in the wheel only after a rebuild — the runner T9 rebuilds the wheel before this image.)

- [ ] **Step 2: Structural verification (AUTHOR-ONLY — `docker build` DEFERRED to T9 per the Global-Constraints T4–T6 author-only decision).** Add `tests/unit/proof_1b_2/test_proof_images.py` reading the Dockerfile as text + asserting the load-bearing invariants: the `examples/cognic-tool-search/dist/` wheel COPY path + the exact `.whl` filename, the exact `CMD ["python", "-m", "cognic_tool_search.server"]`, and the `mcp==1.27.0` + `uvicorn` pip install. `uv run pytest tests/unit/proof_1b_2/test_proof_images.py -v` → passes. (T9's runner runs the real `docker build` — a broken Dockerfile is caught there.)

- [ ] **Step 3: Commit** — `git add infra/proof-1b-2/Dockerfile.mcp-server tests/unit/proof_1b_2/test_proof_images.py && git commit -m "feat(proof-1b-2): T4 — MCP tool Service image Dockerfile (author-only) + structural test"`

---

### Task 5: Emulated-external AS image (vendored `_local_as.py`)

**Files:** Create `infra/proof-1b-2/Dockerfile.as` + extend `tests/unit/proof_1b_2/test_proof_images.py` (the author-time structural test, from T4)

- [ ] **Step 1: Write the Dockerfile** (vendor the single AS file; it has no installable distribution):
```dockerfile
# infra/proof-1b-2/Dockerfile.as — PROOF-ONLY emulated-external OAuth AS
FROM python:3.12-slim
RUN pip install --no-cache-dir "uvicorn[standard]>=0.35" "starlette>=0.40" "python-multipart>=0.0.9"
# python-multipart: the AS /token endpoint reads `await request.form()`; Starlette form parsing requires it
# (without it Bar 2 fails at the token POST). Vendor exactly the one AS fixture file. Build context =
# infra/proof-1b-2/ (NOT repo root): the runner copies _local_as.py into this context first, because
# .dockerignore excludes tests/ from every repo-root context. So the COPY source is context-relative.
COPY _local_as.py /app/_local_as.py
WORKDIR /app
EXPOSE 9000
CMD ["python", "_local_as.py"]
```
(The Task-2 `__main__` makes `python _local_as.py` run the AS, env-driven by `COGNIC_PROOF_AS_ISSUER` / `COGNIC_PROOF_AS_HOST` / `COGNIC_PROOF_AS_PORT`.) **Build context = `infra/proof-1b-2/`, NOT repo root** — `.dockerignore` excludes `tests/` from every repo-root build context (prod images ship no test code), so a repo-root `COPY tests/integration/pack_loop/_local_as.py` is filtered out + the build fails. The T9 runner `cp`s `tests/integration/pack_loop/_local_as.py` into `infra/proof-1b-2/` before `docker build`, mirroring how it copies the staging in for `Dockerfile.agentos-proof`. *(This vendor-into-context approach is the fix for the BAR 0 defect the live attempt-1 run caught — see `docs/VALIDATION-RESULTS.md`.)*

- [ ] **Step 2: Structural verification (AUTHOR-ONLY — `docker build` DEFERRED to T9 per the Global-Constraints T4–T6 author-only decision).** Extend `tests/unit/proof_1b_2/test_proof_images.py` with the AS-image invariants: the context-relative `COPY _local_as.py` vendor line (and that it does NOT reference the repo-root `tests/` path — `.dockerignore` excludes it), the exact `CMD ["python", "_local_as.py"]` (the T2 `__main__` path), and the `uvicorn` + `starlette` + `python-multipart` (form-parse dep) pip install. Also add a `.dockerignore`-aware regression guard (`test_no_proof_dockerfile_copies_from_excluded_dir`) that fails if any proof Dockerfile built with the repo-root context COPYs from a `.dockerignore`-excluded directory (the BAR 0 class). `uv run pytest tests/unit/proof_1b_2/test_proof_images.py -v` → passes. (T9's runner runs the real `docker build`.)

- [ ] **Step 3: Commit** — `git add infra/proof-1b-2/Dockerfile.as tests/unit/proof_1b_2/test_proof_images.py && git commit -m "feat(proof-1b-2): T5 — emulated-external AS image Dockerfile (author-only) + structural test"`

---

### Task 6: Proof AgentOS image (bakes `create_proof_app` + trust staging)

**Files:** Create `infra/proof-1b-2/Dockerfile.agentos-proof` + extend `tests/unit/proof_1b_2/test_proof_images.py` (the author-time structural test). Reuse the 1b-1 staging via `infra/proof-1b/proof1b-staging` (or re-run `stage_trust_inputs.py`).

- [ ] **Step 1: Write the Dockerfile** (mirrors `Dockerfile.proof1b`; adds the proof_app module):
```dockerfile
ARG BASE_IMAGE=cognic-agentos:proof1b2-base
FROM ${BASE_IMAGE}
USER root
# trust staging (same as 1b-1): wheel install + attestations + trust roots + alembic.ini
COPY proof1b-staging/wheel/ /tmp/wheel/
RUN /opt/venv/bin/python -m ensurepip --upgrade \
 && /opt/venv/bin/python -m pip install --no-deps --no-cache-dir /tmp/wheel/*.whl && rm -rf /tmp/wheel
COPY proof1b-staging/pack-attestations/ /opt/cognic/pack-attestations/
COPY proof1b-staging/trust-roots/ /opt/cognic/trust-roots/
COPY proof1b-staging/policies/ /opt/cognic/policies/
COPY proof1b-staging/alembic.ini /app/alembic.ini
# proof-only app factory (vendored into the image so uvicorn can import it)
COPY proof_1b_2/ /app/proof_1b_2/
RUN chmod -R a+rX /opt/cognic /app/alembic.ini /app/proof_1b_2
ENV COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations \
    COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots \
    COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json
# /app/proof_1b_2 is vendored (COPY, not pip-installed), so /app must be importable.
# The default-adapters base sets no PYTHONPATH and runs uvicorn as a console script
# (sys.path[0] = /opt/venv/bin, NOT the /app WORKDIR), so make /app explicit rather
# than relying on uvicorn's --app-dir cwd default.
ENV PYTHONPATH=/app
USER cognic
# override the default CMD to the PROOF app factory (the only kernel-facing change, and it is image-level)
CMD ["sh","-c","exec uvicorn proof_1b_2.proof_app:create_proof_app --factory --host 0.0.0.0 --port 8000"]
```
Build context = `infra/proof-1b-2/` after the runner copies `proof1b-staging/` (from `infra/proof-1b/`) and `proof_1b_2/` (from `tests/integration/proof_1b_2/`) into it. **`proof_1b_2.proof_app` import path (RESOLVED at author time):** the COPY places it at `/app/proof_1b_2/`. The `default-adapters` base (`infra/agentos/Dockerfile`) sets `WORKDIR /app` but **no `PYTHONPATH`**, and `cognic_agentos` is importable only because `uv sync --no-editable` installs it into the venv site-packages (NOT via `/app`). uvicorn runs as a console script, so `sys.path[0] = /opt/venv/bin` (not `/app`); whether `/app` lands on `sys.path` would otherwise rely on uvicorn's `--app-dir` cwd default. Since the base does NOT *clearly* put `/app` on `sys.path`, this Dockerfile sets **`ENV PYTHONPATH=/app`** explicitly (sanctioned addition) so the vendored `proof_1b_2` import is deterministic; the structural test pins it.

- [ ] **Step 2: Structural verification (AUTHOR-ONLY — `docker build` DEFERRED to T9 per the Global-Constraints T4–T6 author-only decision).** Extend `tests/unit/proof_1b_2/test_proof_images.py` with the agentos-proof-image invariants: the `ARG BASE_IMAGE=cognic-agentos:proof1b2-base`, the staging COPYs (`proof1b-staging/wheel/`, `pack-attestations/`, `trust-roots/`, `policies/`, `alembic.ini`), the `COPY proof_1b_2/ /app/proof_1b_2/` vendor, the proof-factory `CMD … uvicorn proof_1b_2.proof_app:create_proof_app --factory …`, and (if added per the import-path note below) `ENV PYTHONPATH=/app`. `uv run pytest tests/unit/proof_1b_2/test_proof_images.py -v` → passes. (T9's runner runs the real `docker build` with build context = `infra/proof-1b-2/` after copying the staging + proof_1b_2 in.)

- [ ] **Step 3: Commit** — `git add infra/proof-1b-2/Dockerfile.agentos-proof tests/unit/proof_1b_2/test_proof_images.py && git commit -m "feat(proof-1b-2): T6 — proof AgentOS image (author-only) bakes create_proof_app + trust staging + structural test"`

---

### Task 7: kind manifests — private MCP ClusterIP + public-shaped AS externalIP

**Files:** Create `infra/proof-1b-2/manifests/mcp-server.yaml`, `infra/proof-1b-2/manifests/auth-server.yaml` + `tests/unit/proof_1b_2/test_proof_manifests.py` (the author-time structural test)

- [ ] **Step 1: MCP server manifest** (static private ClusterIP `10.96.0.50`):
```yaml
# infra/proof-1b-2/manifests/mcp-server.yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: proof-mcp, labels: { app: proof-mcp } }
spec:
  replicas: 1
  selector: { matchLabels: { app: proof-mcp } }
  template:
    metadata: { labels: { app: proof-mcp } }
    spec:
      containers:
      - name: mcp
        image: cognic-proof-mcp:1b2
        imagePullPolicy: IfNotPresent
        ports: [{ containerPort: 8765 }]
        env:
        - { name: COGNIC_PROOF_HOST, value: "0.0.0.0" }
        - { name: COGNIC_PROOF_SERVER_URL, value: "http://10.96.0.50:8765/mcp" }
        - { name: COGNIC_PROOF_AS_ISSUER, value: "http://192.88.99.9:9000" }
---
apiVersion: v1
kind: Service
metadata: { name: proof-mcp }
spec:
  clusterIP: 10.96.0.50      # static, private, knowable up front (override + allow-list seed this exact IP)
  selector: { app: proof-mcp }
  ports: [{ port: 8765, targetPort: 8765 }]
```

- [ ] **Step 2: AS manifest** (genuine-global `externalIP`, kube-proxy-intercepted):
```yaml
# infra/proof-1b-2/manifests/auth-server.yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: proof-as, labels: { app: proof-as } }
spec:
  replicas: 1
  selector: { matchLabels: { app: proof-as } }
  template:
    metadata: { labels: { app: proof-as } }
    spec:
      containers:
      - name: as
        image: cognic-proof-as:1b2
        imagePullPolicy: IfNotPresent
        ports: [{ containerPort: 9000 }]
        env:
        - { name: COGNIC_PROOF_AS_HOST, value: "0.0.0.0" }
        - { name: COGNIC_PROOF_AS_ISSUER, value: "http://192.88.99.9:9000" }
        - { name: COGNIC_PROOF_AS_PORT, value: "9000" }
---
apiVersion: v1
kind: Service
metadata: { name: proof-as }
spec:
  externalIPs: ["192.88.99.9"]   # genuine-global (RFC7526), guard-allowed, kube-proxy-intercepted (NO real egress)
  selector: { app: proof-as }
  ports: [{ port: 9000, targetPort: 9000 }]
```

- [ ] **Step 3: Offline validation (NO Docker/kind/live cluster).** (a) Add `tests/unit/proof_1b_2/test_proof_manifests.py` parsing both manifests via `yaml.safe_load_all` + asserting the load-bearing invariants: the MCP Service `clusterIP == "10.96.0.50"` (static private), the AS Service `externalIPs == ["192.88.99.9"]`, and the single-URL/AS-issuer invariant (`COGNIC_PROOF_SERVER_URL == "http://10.96.0.50:8765/mcp"` on the MCP container; `COGNIC_PROOF_AS_ISSUER == "http://192.88.99.9:9000"` on BOTH the MCP + AS containers). `uv run pytest tests/unit/proof_1b_2/test_proof_manifests.py -v` → passes. (b) If `which kubeconform` finds it, also run `kubeconform -strict infra/proof-1b-2/manifests/*.yaml`; if not, skip + note (the structural pytest is the reliable offline gate). Do NOT use `kubectl --dry-run` if it would contact a cluster.

- [ ] **Step 4: Commit** — `git add infra/proof-1b-2/manifests/ tests/unit/proof_1b_2/test_proof_manifests.py && git commit -m "feat(proof-1b-2): T7 — kind manifests (private MCP ClusterIP + public-shaped AS externalIP) + structural test"`

---

### Task 8: Seed scripts — Postgres rows + Vault (KV v1) secrets

**Files:** Create `infra/proof-1b-2/seed-db.sh`, `infra/proof-1b-2/seed-vault.sh` + `tests/unit/proof_1b_2/test_proof_seeds.py` (the author-time structural test)

- [ ] **Step 1: DB seed** (`seed-db.sh`) — runs `psql` inside the Postgres pod (Service `postgres:5432`, `cognic/cognic/cognic`):
```bash
#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proof1b2}"; T="proof-1b-2"; URL="http://10.96.0.50:8765/mcp"; IP="10.96.0.50"
kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -v ON_ERROR_STOP=1 -c "
INSERT INTO mcp_server_url_override (id, tenant_id, pack_id, server_url_override, set_by_actor, set_at, last_request_id)
VALUES (gen_random_uuid(), '$T', 'cognic-tool-search', '$URL', 'proof-1b-2-seed', now(), 'proof-seed-0001')
ON CONFLICT (tenant_id, pack_id) DO UPDATE SET server_url_override = EXCLUDED.server_url_override;
INSERT INTO mcp_internal_host_allowlist (id, tenant_id, ip, set_by_actor, set_at, last_request_id)
VALUES (gen_random_uuid(), '$T', '$IP', 'proof-1b-2-seed', now(), 'proof-seed-0001')
ON CONFLICT (tenant_id, ip) DO NOTHING;"
```
(`gen_random_uuid()` = pg13+; the allow-list `ip` is already canonical `str(ip)` for `10.96.0.50`. A separate `unseed-allowlist.sh` deletes ONLY the allow-list row for the Bar 1 delta — see T9.)

- [ ] **Step 2: Vault seed** (`seed-vault.sh`) — convert `secret/` to KV v1, then put the two secrets (Vault dev token from values):
```bash
#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proof1b2}"; T="proof-1b-2"; ASHOST="192.88.99.9_9000"; AS="http://192.88.99.9:9000"
VX() { kubectl -n "$NS" exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=smoke-root-token vault "$@"; }  # == the reused backends.yaml Vault VAULT_DEV_ROOT_TOKEN_ID
VX secrets disable secret || true
VX secrets enable -version=1 -path=secret kv
# mcp-as-allowlist.servers MUST be a JSON LIST — _load_as_allowlist (mcp_authz.py:1439) expects a list.
# `vault kv put key=value` stores a STRING; use Vault's reliable @file JSON form (a bare `-` may be parsed
# as a data arg, not stdin). Write the JSON to a temp file INSIDE the vault pod, then feed it via @file:
echo "{\"servers\":[\"$AS\"]}" | kubectl -n "$NS" exec -i deploy/vault -- sh -c 'cat > /tmp/as-allowlist.json'
VX kv put "secret/cognic/$T/mcp-as-allowlist" @/tmp/as-allowlist.json
# readback assertion: servers must come back as a JSON ARRAY (KV v1 -> data.servers)
VX kv get -format=json "secret/cognic/$T/mcp-as-allowlist" | python3 -c 'import json,sys; s=json.load(sys.stdin)["data"]["servers"]; assert isinstance(s,list), f"servers not a list: {type(s).__name__}"; print("as-allowlist OK:", s)'
VX kv put "secret/cognic/$T/mcp-oauth/$ASHOST" client_id=proof-client client_secret=proof-secret auth_method=client_secret_post
```
**Verify at execution:** the @file put + readback assertion above pin the `servers` JSON-list shape that `_load_as_allowlist` (`mcp_authz.py:1439`) requires. The implementer additionally confirms the bundled `SecretAdapter` raw `read("secret/cognic/...")` resolves under KV v1 (the templates carry no `/data/` segment) — either a one-line `kubectl exec` read through the kernel's Vault path, or the readback assertion above standing as the proof.

- [ ] **Step 3: Offline verification (NO kubectl/Vault/Docker/kind — the scripts RUN only at T9).** (a) `bash -n infra/proof-1b-2/seed-db.sh infra/proof-1b-2/seed-vault.sh` (syntax) → exit 0; `shellcheck` if available. (b) Add `tests/unit/proof_1b_2/test_proof_seeds.py` reading both scripts as text + asserting the invariant values: `T="proof-1b-2"`, the override `URL="http://10.96.0.50:8765/mcp"`, the allow-list `IP="10.96.0.50"`, `AS="http://192.88.99.9:9000"`, `ASHOST="192.88.99.9_9000"`; the table names (`mcp_server_url_override`, `mcp_internal_host_allowlist`); the Vault KV-v1 enable (`secrets enable -version=1 -path=secret kv`); and the `servers` JSON-LIST via the `@/tmp/as-allowlist.json` @file form (asserting `servers=` inline is NOT used). `uv run pytest tests/unit/proof_1b_2/test_proof_seeds.py -v` → passes.

- [ ] **Step 4: Commit** — `git add infra/proof-1b-2/seed-db.sh infra/proof-1b-2/seed-vault.sh tests/unit/proof_1b_2/test_proof_seeds.py && git commit -m "feat(proof-1b-2): T8 — Postgres + Vault(KV v1) seed scripts (author-only) + structural test"`

---

### Task 9: Helm values, migrate job, and the end-to-end runner (Bar 1 → Bar 2)

**Files:** Create `infra/proof-1b-2/proof-1b-2-values.yaml`, `infra/proof-1b-2/migrate-job.yaml` (copy from 1b-1), `infra/proof-1b-2/run-proof-1b-2.sh`, `infra/proof-1b-2/README.md` + `tests/unit/proof_1b_2/test_proof_runner.py` (the author-time structural test). **Also copy `tests/integration/proof_1b/{__init__.py, stage_trust_inputs.py}` from `feat/pack-loop-proof-1b`** (the runner Step 3 staging dep; its `tests.integration.pack_loop._authoring` dependency is already on this branch — `git show` the 2 files, do NOT checkout the branch). Without it the operator run dies `ModuleNotFoundError` before the image build.

- [ ] **Step 1: Values** — `git show feat/pack-loop-proof-1b:infra/proof-1b/proof-1b-values.yaml > infra/proof-1b-2/proof-1b-2-values.yaml` (the file is branch-only; `infra/proof-1b/` on THIS branch holds only untracked staging — mirror the `git show` Step 2 uses for the migrate job). Then set `image.tag: "proof1b2"`, keep `runtimeProfile: prod`, `migrations.enabled: false`, `secrets.vaultToken: "smoke-root-token"` (== the reused backends.yaml Vault `VAULT_DEV_ROOT_TOKEN_ID`), `podSecurityContext: {runAsUser: 10001, fsGroup: 10001}`. The proof image's CMD already points to `create_proof_app` (T6).

- [ ] **Step 2: Migrate job** — `git show feat/pack-loop-proof-1b:infra/proof-1b/migrate-job.yaml > infra/proof-1b-2/migrate-job.yaml` (non-hook, `envFrom` the config map, `__AGENTOS_IMAGE__` sed slot).

- [ ] **Step 3: Runner** (`run-proof-1b-2.sh`, env-gated `COGNIC_RUN_PROOF_1B2=1`, exits 0 if unset). Sequence (extends `run-proof-1b-1.sh` verbatim where possible):
  1. Preflight tools; `CLUSTER`/`NS=cognic-proof1b2`.
  2. **Rebuild the pack wheel** (`cd examples/cognic-tool-search && uv build --wheel`) so the Task-1 edits are in it.
  3. `uv run python -m tests.integration.proof_1b.stage_trust_inputs infra/proof-1b/proof1b-staging` (trust staging).
  4. Build: base (`--target default-adapters` → `cognic-agentos:proof1b2-base`); copy `infra/proof-1b/proof1b-staging` + `tests/integration/proof_1b_2` into `infra/proof-1b-2/`; build `Dockerfile.agentos-proof` → `cognic-agentos:proof1b2` (context `infra/proof-1b-2`); build `Dockerfile.mcp-server` → `cognic-proof-mcp:1b2` (context repo root — copies from `examples/`, not `.dockerignore`-excluded); copy `tests/integration/pack_loop/_local_as.py` into `infra/proof-1b-2/` + build `Dockerfile.as` → `cognic-proof-as:1b2` (**context `infra/proof-1b-2`, NOT repo root** — `.dockerignore` excludes `tests/` from the repo-root context, so the AS fixture is vendored into the proof context; `cleanup()` removes the transient copy).
  5. `kind create cluster`; `kind load docker-image` all 3 proof images + pre-pulled backends.
  6. `kubectl create ns`; apply `backends.yaml`; wait available.
  7. **Vault init/seed** (`seed-vault.sh`) — must run after Vault is up, before AgentOS reads it.
  8. `helm install rel infra/charts/agentos -n NS -f infra/proof-1b-2/proof-1b-2-values.yaml`.
  9. Migrate job (sed image, apply, wait complete); `kubectl apply -f manifests/mcp-server.yaml -f manifests/auth-server.yaml`; wait the MCP + AS deploys ready.
  10. **DB seed** (`seed-db.sh`) — after migrations created the tables.
  11. `kubectl rollout restart deploy/rel-agentos`; wait ready; `port-forward svc/rel-agentos 8000:8000`.
  - **BAR 1 (checkpoint) — pinned cold-cache sequence.** MCPHost caches BOTH the OAuth token and the list_tools result per tenant, so the allow-list-removed delta is only observable on a COLD pod (a rollout restart):
    1. (allow-list seeded) `curl -sf http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-search/tools` → 200; assert via `kubectl -n NS logs deploy/rel-agentos` that `audit.mcp_allowlist_permitted` fired for a resource leg (`server_url`/`prm_metadata`), host `10.96.0.50`. [Bar 1 positive]
    2. delete the allow-list row, restart to a cold pod, fresh probe MUST refuse:
       `kubectl -n NS exec deploy/postgres -- psql -U cognic -d cognic -c "DELETE FROM mcp_internal_host_allowlist WHERE tenant_id='proof-1b-2' AND ip='10.96.0.50';"`
       `kubectl -n NS rollout restart deploy/rel-agentos && kubectl -n NS rollout status deploy/rel-agentos --timeout=300s`
       `kubectl -n NS wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=300s`; re-establish `port-forward`;
       fresh `curl .../tools` MUST refuse — discovery records `mcp_discovery_url_refused` / `refused_component=host_address` (assert via response body + logs). [Bar 1 delta — the carve-out is load-bearing]
    3. re-run `seed-db.sh` (re-insert the allow-list row) → `kubectl -n NS rollout restart deploy/rel-agentos` → `rollout status` + `wait ready` → re-establish `port-forward` (cold pod, allow-list present — clean state for Bar 2). **Print `BAR 1 PASS` (checkpoint, not done).**
  - **BAR 2 (completion):** `curl -sf -X GET http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-search/tools` → 200 with the tool set (drives the governed path: override → carve-out → OAuth legs → token → invoke). Then `curl -sf -X POST .../tools/call -d '{"tool_name":"search_policy_docs","arguments":{"query":"policy"}}'` → 200 with a real result. Then `curl -sf "http://127.0.0.1:8000/api/v1/system/plugins?tenant_id=proof-1b-2"` and a `python3` heredoc asserting the `cognic-tool-search` row has `discovery_status == "auth_ready"`. **Print `PROOF 1b-2 (BAR 2) PASS`.**
  - On Bar 2 failure: capture logs + `discovery_status` + the authz reason, write the finding to `docs/VALIDATION-RESULTS.md`, exit non-zero — do NOT downgrade.
  - `trap cleanup EXIT` deletes the cluster.

- [ ] **Step 4: README + findings** — `infra/proof-1b-2/README.md` records the proof-only-binder caveat ("production requires a real bank-overlay ActorBinder") + the run command. Add F1/F2 + the Bar 1/Bar 2 result to `docs/VALIDATION-RESULTS.md` (done at RUN time, not now).

- [ ] **Step 5: Offline verification + commit (NO COGNIC_RUN_PROOF_1B2=1 / Docker / kind / Helm / kubectl — the runner RUNS only when the operator sets the gate).** (a) `bash -n infra/proof-1b-2/run-proof-1b-2.sh` (syntax) → exit 0. (b) Add `tests/unit/proof_1b_2/test_proof_runner.py` reading the runner + values + README as text + asserting: the runner is env-gated on `COGNIC_RUN_PROOF_1B2` AND exits 0 when unset; it CALLS `seed-db.sh` + `seed-vault.sh` (uses the T8 scripts) AND does NOT re-`INSERT INTO mcp_server_url_override` inline (the override seed isn't drift-prone-duplicated; the Bar 1 `DELETE FROM mcp_internal_host_allowlist` delta + the `10.96.0.50` audit assertion are the runner's own negative-test logic, legitimately present); it prints `BAR 1 PASS` (checkpoint) AND `PROOF 1b-2 (BAR 2) PASS` (completion) as DISTINCT markers; it has `trap cleanup EXIT`; the values pin `image.tag: "proof1b2"` + `runtimeProfile: prod` + `migrations.enabled: false`; the README carries the proof-only-binder caveat (`bank-overlay ActorBinder`); AND the runner's Step 3 staging module `tests.integration.proof_1b.stage_trust_inputs` exists + imports (`importlib.import_module` + `hasattr(mod, "stage")`) so the operator run can't die with `ModuleNotFoundError` before the proof starts. `uv run pytest tests/unit/proof_1b_2/test_proof_runner.py -v` → passes. **DO NOT run the runner.** (c) `git add infra/proof-1b-2/{proof-1b-2-values.yaml,migrate-job.yaml,run-proof-1b-2.sh,README.md} tests/integration/proof_1b/{__init__.py,stage_trust_inputs.py} tests/unit/proof_1b_2/test_proof_runner.py && git commit -m "feat(proof-1b-2): T9 — values + migrate job + end-to-end runner (Bar 1 checkpoint + Bar 2 completion) + staging-module copy + structural test"`

---

### Task 10 (optional): env-gated kind CI job

**Files:** Modify `.github/workflows/python.yml`

- [ ] **Step 1: Add the `proof-1b-2` job** mirroring `kind-smoke` (`.github/workflows/python.yml:651`) — `runs-on: ubuntu-latest`, `if: ${{ vars.COGNIC_RUN_PROOF_1B2 == '1' || github.event_name == 'workflow_dispatch' }}` (**never default-on**), `steps:` = checkout (`actions/checkout@v6`) + `helm/kind-action@v1` (`install_only: true`) + the runner step. **The runner step MUST set the env gate** — `run: COGNIC_RUN_PROOF_1B2=1 bash infra/proof-1b-2/run-proof-1b-2.sh` (the runner self-gates on the ENV var `COGNIC_RUN_PROOF_1B2` + exits 0 if unset per `run-proof-1b-2.sh:23-26`, so a bare `bash …` would silently SKIP the proof even when the job runs — a fix vs the original bare-`bash` plan text; the GitHub `vars.` gates the JOB, the ENV enables the RUNNER). Add the tool setup the runner's preflight (`run-proof-1b-2.sh:112`) requires — `uv` (the runner's Step 2 is `uv build`) + `cosign` + `syft` + `grype` (docker/curl/python3 are preinstalled; kind-action gives kind+helm+kubectl); mirror the existing CI install actions/versions — cosign pins to the Dockerfile's exact version+SHA; **syft/grype have NO in-repo pin → pin via the fetched release-tarball SHA256 + `sha256sum -c` (SHAs computed from the linux_amd64 bytes + cross-checked against anchore's published `checksums.txt`), NOT a piped remote installer from a mutable branch**. `timeout-minutes: 40` (4 image builds + kind + Bar 1/Bar 2, heavier than the 25-min smoke).

- [ ] **Step 2: Structural test** — add `tests/unit/proof_1b_2/test_proof_ci_job.py` parsing `.github/workflows/python.yml` (`yaml.safe_load`) + asserting: the `proof-1b-2` job exists under `jobs`; its `if` references BOTH `vars.COGNIC_RUN_PROOF_1B2` AND `workflow_dispatch` (the never-default-on gate); a step's `run` sets `COGNIC_RUN_PROOF_1B2=1` AND references `infra/proof-1b-2/run-proof-1b-2.sh`; the job uses `helm/kind-action`; the syft/grype install is version+SHA256-pinned (`SYFT_VERSION`/`SYFT_SHA256`/`GRYPE_VERSION`/`GRYPE_SHA256` + `sha256sum -c`) with NO `install.sh` / `curl | sh` supply-chain anti-pattern. `uv run pytest tests/unit/proof_1b_2/test_proof_ci_job.py -v` → passes. Verify the YAML parses; `actionlint` if available.

- [ ] **Step 3: Commit** — `git add .github/workflows/python.yml tests/unit/proof_1b_2/test_proof_ci_job.py docs/superpowers/plans/2026-06-25-proof-1b-2-deployed-mcp-loop.md && git commit -m "chore(proof-1b-2): T10 — env-gated kind CI job (never default-on) + structural test"`

---

## Self-Review (run against the spec)

**Spec coverage:** Bar 1 checkpoint → T9 Bar 1 block (permit event + allow-list-removed delta). Bar 2 completion → T9 Bar 2 block (auth_ready + list_tools/call_tool). Topology (default-adapters prod, private MCP ClusterIP, public-shaped AS externalIP) → T6/T7. G1 direct DB seed → T8. G2 tiny images → T4/T5. Single-effective-URL invariant → Global Constraints + T7 env + T8 seed (all `http://10.96.0.50:8765/mcp`). No real egress → T7 externalIP + Global Constraints. OAuth-legs-public → unchanged kernel. F1/F2 findings → T9 Step 4. Proof-only binder + prod-needs-overlay note → T3 + Global Constraints + T9 README. Builds on 1b-1 harness → T6/T9 reuse `stage_trust_inputs` + `Dockerfile.proof1b` pattern + `migrate-job.yaml`.

**Placeholder scan:** the two deliberate VERIFY-AT-EXECUTION items (T6 `PYTHONPATH=/app` for the `proof_1b_2` import; T8 Vault `servers` JSON-list read shape) are flagged as explicit verification steps with the exact check, not hand-waves — acceptable because they depend on runtime behavior the implementer confirms in-task.

**Type/name consistency:** `PROOF_TENANT="proof-1b-2"`, scopes `{"mcp.tool.list","mcp.tool.invoke"}`, MCP URL `http://10.96.0.50:8765/mcp`, AS issuer `http://192.88.99.9:9000`, `as_host` `192.88.99.9_9000`, image tags `cognic-agentos:proof1b2` / `cognic-proof-mcp:1b2` / `cognic-proof-as:1b2` — used identically across T3/T6/T7/T8/T9.
