# Proof 1a — Real-App In-Process Pack-Governance Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the real authoring trust pipeline produces artifacts the real runtime trust pipeline accepts, end-to-end in-process.

**Architecture:** A real in-tree MCP server pack (`examples/cognic-tool-search/`, kept out of the OS wheel by `packages = ["src/cognic_agentos"]`) is built into a wheel, signed with the real `agentos sign` toolchain, and its attestations are provisioned into the runtime attestation root. An env-gated integration harness boots the **real composition root** (`build_adapters_async → build_runtime → build_and_populate_registry → build_mcp_host`) over a minimal adapter pool (sqlite + local_fs + in-memory secret/vector/embedding/observability; **no Redis, no scheduler**), with `require_cosign=True` so the trust gate verifies the real signature, then drives a `read_only` tool call through the production `POST /api/v1/mcp/servers/{server_id}/tools/call` route and asserts the decision-history chain + evidence export.

**Tech Stack:** Python 3.12, uv, pytest-asyncio, the `mcp` SDK 1.27.0 (FastMCP), FastAPI/Starlette, cosign/syft/grype toolchain (operator), env-gated integration test.

---

## Locked decisions (baked into this plan)

1. **`require_cosign=True`** in the harness `Settings`. The dev default is `False`, which makes `TrustGate.verify_pack_signature` return a synthetic `cosign-skipped:require_cosign=false` digest — hollowing out the exact seam this proof exists to test. The harness sets `require_cosign=True` so registration verifies the **real** cosign signature. cosign is already in the operator toolchain for `agentos sign`.
2. **One manifest, both block families.** The pack ships ONE `cognic-pack-manifest.toml` carrying BOTH the build-time top-level blocks (`[pack]`, `[identity]`, `[data_governance]`, `[risk_tier]`, `[supply_chain]`) AND the runtime nested `[tool.cognic.mcp]` block. The CLI (`validate`/`sign`/`verify`) reads the top-level blocks from the manifest at the path passed on the command line; the runtime reads the **same** manifest as package data inside the installed wheel via `Distribution.locate_file`. `pyproject.toml` `force-include`s that manifest into the wheel at `cognic_tool_search/cognic-pack-manifest.toml`. Record the "two consumers, one manifest" finding in `VALIDATION-RESULTS.md`.

## Two findings this proof is built to surface (expected, not failures)

- **Wheel co-location gap (Task 6).** `agentos sign` writes the 7 attestations into `<pack>/attestations/` but signs the wheel **in place** in `<pack>/dist/` — it never co-locates them. The resolver expects all 8 artifacts under `<root>/<dist>/<version>/`. The provisioning copy (no renames) is the author↔runtime bridge the proof validates. Record it.
- **`[tool.cognic.mcp]`-on-tool-pack validate tolerance (Task 3, UNVERIFIED).** Whether `agentos validate` accepts a `[tool.cognic.mcp]` block on a tool-kind manifest is not yet confirmed. Task 3 RUNS `agentos validate` and treats a refusal as a real finding to record + resolve, not a test bug.

## Flagged in-task verifications (grounding left these for the implementer to confirm against the code)

- **Exact in-memory adapter class names** for the relational / secret / vector / embedding / observability stubs. Grounding points at `tests/support/adapter_fixtures.py` (`InMemoryRelationalAdapter`, sqlite+aiosqlite + auto `create_all`) and the `tests/conftest.py` `memory_registry` fixture as the template — **Task 7 Step 1 confirms the actual class names + how the harness registers them** before wiring. Do not assume; read those two files first.
- **`AdapterRegistry` / `build_adapters_async` construction surface** — Task 7 reads `db/adapters/factory.py` + `tests/conftest.py` for the exact registry-construction call shape.
- **`MCPAdmissionDeps` construction** for `build_and_populate_registry(mcp_admission=...)` — Task 7 mirrors the lifespan in `portal/api/app.py` (the slice-2 startup-discovery wiring) for the exact kwargs (`settings`, `vault_client`, `opa_engine=None`, `make_authz_client_for_probe`).
- **`Actor` construction + `actor_binder`** shape for the route — Task 7 reads `portal/rbac/actor.py` + the `create_app(actor_binder=...)` seam for the exact `Actor(subject, tenant_id, scopes=frozenset({...}), actor_type=...)` fields.

---

## Shared test-server fixtures (avoid port/lifecycle flakes)

The pack's FastMCP server binds `127.0.0.1:8765` (pinned by the manifest `server_url`) and the local AS binds `127.0.0.1:9000`. Tasks 4, 5, and 7 all need them live. Do **not** spawn a fresh daemon thread per test on those fixed ports — running the pack-loop tests as a group would collide on the bound port and leak un-torn-down servers. Create `tests/integration/pack_loop/conftest.py` with **session-scoped, managed** fixtures that start each server once and shut it down at session end. Tasks 4, 5, and 7 consume these fixtures as test-function arguments (`pack_server` / `local_as`) — the committed tests never launch their own per-test threads:

```python
# tests/integration/pack_loop/conftest.py
"""Session-scoped managed servers for the Proof 1a pack-loop tests.

The pack server (127.0.0.1:8765) and local AS (127.0.0.1:9000) bind FIXED ports
(the manifest pins server_url), so they must start ONCE per session with real
teardown — not a daemon thread per test (which collides + leaks)."""
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import pytest
import uvicorn
from starlette.types import ASGIApp

_AS_ISSUER = "http://127.0.0.1:9000"


def _wait_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.25)
            if s.connect_ex((host, port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"never came up on {host}:{port}")


def _serve(app: ASGIApp, host: str, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_port(host, port)
    return server, thread


@pytest.fixture(scope="session")
def local_as() -> Iterator[str]:
    # _local_as.py lands in Task 5; resolve it dynamically so this Task-4 conftest
    # type-checks under strict mypy (a static import errors import-not-found while
    # the module is absent; a `# type: ignore` would become an unused-ignore error
    # under warn_unused_ignores once Task 5 creates the file).
    import importlib

    build_app = importlib.import_module("tests.integration.pack_loop._local_as").build_app

    server, thread = _serve(build_app(), "127.0.0.1", 9000)
    try:
        yield _AS_ISSUER
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def pack_server() -> Iterator[str]:
    # NOTE: independent of `local_as` — the PRM document only ADVERTISES the AS
    # issuer (a string); the server does not call the AS to serve PRM. So Task 4
    # (PRM shape) needs only `pack_server`; Task 5/7 (token acquisition) request
    # BOTH `pack_server` and `local_as`. Keeping pack_server decoupled means it
    # does not import _local_as.py (created later, in Task 5).
    from cognic_tool_search.server import build_server

    mcp = build_server(as_issuer=_AS_ISSUER)
    # FastMCP.streamable_http_app() returns the Starlette ASGI app (serves /mcp + auto-PRM).
    server, thread = _serve(mcp.streamable_http_app(), "127.0.0.1", 8765)
    try:
        yield "http://127.0.0.1:8765/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
```

> **In-task verification:** confirm `FastMCP.streamable_http_app()` is the ASGI-app accessor in mcp 1.27.0 and that uvicorn-serving it preserves the auto-PRM routes (the grounding confirmed FastMCP exposes `streamable_http_app()`; if instead FastMCP must own its own `run()` loop, fall back to a **managed subprocess** — `subprocess.Popen([sys.executable, "-m", "cognic_tool_search.server"], env={**os.environ, "COGNIC_PROOF_AS_ISSUER": local_as})` with `.terminate()` + `.wait(5)` teardown — never a bare daemon thread with no teardown). Tasks 4/5/7 take `pack_server` / `local_as` as fixture args rather than launching their own threads.

---

## Task 1: Pack scaffold + discovery

**Files:**
- Create: `examples/cognic-tool-search/pyproject.toml`
- Create: `examples/cognic-tool-search/src/cognic_tool_search/__init__.py`
- Create: `examples/cognic-tool-search/README.md`
- Test: `tests/integration/pack_loop/__init__.py`, `tests/integration/pack_loop/test_pack_discovery.py`

- [ ] **Step 1: Write the failing discovery test**

```python
# tests/integration/pack_loop/test_pack_discovery.py
"""Proof 1a Task 1 — the example pack is discoverable as a cognic.tools entry point.

Env-gated: requires the pack to be pip-installed into the venv (its distribution
metadata is read by PluginRegistry.discover()). Skips when not installed so the
default unit run stays green; the proof harness installs it.
"""
import datetime as dt
import importlib.util
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.protocol.plugin_registry import PluginRegistry

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None,
    reason="cognic-tool-search not installed; run `uv pip install -e examples/cognic-tool-search`",
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'pack_loop_discovery.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=dt.datetime.now(dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def registry(engine: AsyncEngine) -> PluginRegistry:
    return PluginRegistry(audit_store=AuditStore(engine))


def test_discover_finds_cognic_tool_search(registry: PluginRegistry) -> None:
    records = [p.record for p in registry.discover()]
    matches = [r for r in records if r.distribution_name == "cognic-tool-search"]
    assert len(matches) == 1, f"expected exactly one cognic-tool-search record, got {matches}"
    rec = matches[0]
    assert rec.kind == "tools"
    assert rec.name == "search_policy_docs"
    assert rec.entry_point_value == "cognic_tool_search:SERVER_DESCRIPTOR"
    assert rec.distribution_version == "0.1.0"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/integration/pack_loop/test_pack_discovery.py -v`
Expected: SKIPPED (the package is not installed yet) — confirm the skip reason names the install command. (After Step 4 installs it, this becomes a real PASS in Step 5.)

- [ ] **Step 3: Create the pack `pyproject.toml`**

```toml
# examples/cognic-tool-search/pyproject.toml
[build-system]
requires = ["hatchling>=1.27"]
build-backend = "hatchling.build"

[project]
name = "cognic-tool-search"
version = "0.1.0"
description = "Proof 1a — minimal real MCP tool pack: deterministic policy-doc search over a bundled corpus."
requires-python = ">=3.12"
dependencies = ["mcp==1.27.0", "uvicorn[standard]>=0.35"]

# PluginRegistry.discover() walks this entry-point group. The runtime MCP path
# never EntryPoint.load()s this object (the tool runs behind HTTP); it exists so
# discover() sees the distribution and `agentos verify`'s load-probe resolves.
[project.entry-points."cognic.tools"]
search_policy_docs = "cognic_tool_search:SERVER_DESCRIPTOR"

[tool.hatch.build.targets.wheel]
packages = ["src/cognic_tool_search"]

# NOTE: the LOCK-2 force-include of the root cognic-pack-manifest.toml is added in
# Task 3 (once that manifest exists) — adding it here would make this Task-1
# editable install reference a file that does not exist yet and can break the
# build before the discovery test runs. The corpus (src/cognic_tool_search/corpus/
# *.json) is INSIDE the package tree, so hatchling auto-includes it via the
# `packages` setting above — no force-include needed for it.
```

- [ ] **Step 4: Create the package `__init__.py` (SERVER_DESCRIPTOR marker) + README, then install editable**

```python
# examples/cognic-tool-search/src/cognic_tool_search/__init__.py
"""cognic-tool-search — Proof 1a example MCP tool pack.

SERVER_DESCRIPTOR is the importable entry-point object PluginRegistry.discover()
resolves the distribution from. The runtime MCP invocation path runs the tool
behind a real HTTP server (see server.py) and NEVER EntryPoint.load()s this
object; it exists only for discovery + the optional `agentos verify` load-probe.
Do NOT import-poison this module — `agentos verify`'s load-probe must succeed.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _ServerDescriptor:
    """Inert marker. The real server lives in cognic_tool_search.server."""

    pack_id: str = "cognic-tool-search"
    tool_name: str = "search_policy_docs"


SERVER_DESCRIPTOR = _ServerDescriptor()
```

```markdown
<!-- examples/cognic-tool-search/README.md -->
# cognic-tool-search (Proof 1a example pack)

A minimal **real** MCP tool pack used by the Proof 1a end-to-end pack-governance
loop (`tests/integration/pack_loop/`). It exposes one deterministic tool,
`search_policy_docs(query)`, over a small bundled static corpus — no network, no
LLM — so the proof fails only on AgentOS integration, never on a provider.

This pack lives in-tree but is **not** part of the AgentOS wheel
(`packages = ["src/cognic_agentos"]`); it is built into its own wheel, signed
with `agentos sign`, and installed as an external pack. See
`docs/superpowers/specs/2026-06-21-pack-loop-proof-1a-design.md`.
```

Run: `uv pip install -e examples/cognic-tool-search`
Expected: `Successfully installed cognic-tool-search-0.1.0`.

- [ ] **Step 5: Run the discovery test to verify it passes**

Run: `uv run pytest tests/integration/pack_loop/test_pack_discovery.py -v`
Expected: PASS (1 passed) — `discover()` now yields the `cognic-tool-search` record.

- [ ] **Step 6: Commit**

```bash
git add examples/cognic-tool-search/pyproject.toml \
        examples/cognic-tool-search/src/cognic_tool_search/__init__.py \
        examples/cognic-tool-search/README.md \
        tests/integration/pack_loop/__init__.py \
        tests/integration/pack_loop/test_pack_discovery.py
git commit -m "feat(proof): cognic-tool-search pack scaffold + discovery (Proof 1a Task 1)"
```

---

## Task 2: Bundled corpus + deterministic search

**Files:**
- Create: `examples/cognic-tool-search/src/cognic_tool_search/corpus/policy_docs.json`
- Create: `examples/cognic-tool-search/src/cognic_tool_search/corpus_loader.py`
- Test: `tests/integration/pack_loop/test_corpus_search.py`

- [ ] **Step 1: Write the failing search test**

```python
# tests/integration/pack_loop/test_corpus_search.py
"""Proof 1a Task 2 — deterministic substring/keyword search over the bundled corpus."""
import importlib.util

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None,
    reason="cognic-tool-search not installed; run `uv pip install -e examples/cognic-tool-search`",
)


def test_search_is_deterministic_and_matches_keyword() -> None:
    from cognic_tool_search.corpus_loader import load_corpus, search

    corpus = load_corpus()
    assert len(corpus) >= 3  # a small static set

    hits = search(corpus, "retention")
    # deterministic: same input → identical ordered output
    assert hits == search(corpus, "retention")
    assert hits, "expected at least one doc mentioning 'retention'"
    assert all({"doc_id", "title", "snippet"} <= set(h) for h in hits)
    assert any("retention" in h["snippet"].lower() for h in hits)


def test_search_empty_query_returns_empty() -> None:
    from cognic_tool_search.corpus_loader import load_corpus, search

    assert search(load_corpus(), "   ") == []


def test_search_no_match_returns_empty() -> None:
    from cognic_tool_search.corpus_loader import load_corpus, search

    assert search(load_corpus(), "zzz-no-such-term-zzz") == []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/integration/pack_loop/test_corpus_search.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cognic_tool_search.corpus_loader'` (the package is installed editable from Task 1, but the module does not exist yet).

- [ ] **Step 3: Create the corpus + loader**

```json
// examples/cognic-tool-search/src/cognic_tool_search/corpus/policy_docs.json
[
  {
    "doc_id": "policy-001",
    "title": "Data retention policy",
    "body": "Customer transaction records are retained for seven years to satisfy the regulator retention floor. Scratch working data is purged at session end."
  },
  {
    "doc_id": "policy-002",
    "title": "Access control policy",
    "body": "Privileged actions require four-eyes approval. Read-only access to public policy documents is granted to all authenticated staff."
  },
  {
    "doc_id": "policy-003",
    "title": "Incident response policy",
    "body": "Severity-one incidents are escalated within fifteen minutes. Kill switches fail closed and propagate within thirty seconds."
  }
]
```

```python
# examples/cognic-tool-search/src/cognic_tool_search/corpus_loader.py
"""Deterministic in-memory search over the bundled static policy-doc corpus.

No network, no LLM (a tool pack must not embed an LLM — three-pool rule). The
corpus ships as package data; load_corpus() reads it via importlib.resources so
it resolves the same way inside an installed wheel.
"""
from __future__ import annotations

import json
from importlib import resources
from typing import Any

_SNIPPET_LEN = 160


def load_corpus() -> list[dict[str, Any]]:
    raw = resources.files("cognic_tool_search").joinpath("corpus/policy_docs.json").read_text(
        encoding="utf-8"
    )
    docs: list[dict[str, Any]] = json.loads(raw)
    return docs


def search(corpus: list[dict[str, Any]], query: str) -> list[dict[str, str]]:
    """Case-insensitive substring match over title+body. Deterministic: preserves
    corpus order; returns a stable {doc_id, title, snippet} shape."""
    q = query.strip().lower()
    if not q:
        return []
    hits: list[dict[str, str]] = []
    for doc in corpus:
        haystack = f"{doc['title']} {doc['body']}".lower()
        if q in haystack:
            body = doc["body"]
            idx = body.lower().find(q)
            start = max(0, idx - 20) if idx >= 0 else 0
            snippet = body[start : start + _SNIPPET_LEN]
            hits.append({"doc_id": doc["doc_id"], "title": doc["title"], "snippet": snippet})
    return hits
```

- [ ] **Step 4: Run the search tests to verify they pass**

Run: `uv run pytest tests/integration/pack_loop/test_corpus_search.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Reinstall (so the new package-data corpus is packaged) and commit**

Run: `uv pip install -e examples/cognic-tool-search`
Expected: reinstalled cleanly.

```bash
git add examples/cognic-tool-search/src/cognic_tool_search/corpus/policy_docs.json \
        examples/cognic-tool-search/src/cognic_tool_search/corpus_loader.py \
        tests/integration/pack_loop/test_corpus_search.py
git commit -m "feat(proof): bundled corpus + deterministic search (Proof 1a Task 2)"
```

---

## Task 3: The one manifest (both block families) + `agentos validate`

**Files:**
- Create: `examples/cognic-tool-search/cognic-pack-manifest.toml`
- Test: `tests/integration/pack_loop/test_manifest_validate.py`

- [ ] **Step 1: Write the failing validate test**

```python
# tests/integration/pack_loop/test_manifest_validate.py
"""Proof 1a Task 3 — the single manifest is accepted by `agentos validate`.

This is the LOCK-2 "two consumers, one manifest" check. UNVERIFIED until run:
whether `agentos validate` tolerates a [tool.cognic.mcp] block on a tool-kind
manifest. A refusal here is a real finding to record in VALIDATION-RESULTS.md
and resolve (e.g. relocate the runtime block), NOT a test bug.
"""
import importlib.util
from pathlib import Path

import pytest

_PACK = Path(__file__).resolve().parents[3] / "examples" / "cognic-tool-search"


def test_manifest_exists_with_both_block_families() -> None:
    import tomllib

    manifest = (_PACK / "cognic-pack-manifest.toml").read_bytes()
    data = tomllib.loads(manifest.decode("utf-8"))
    # build-time top-level blocks
    assert data["pack"]["pack_id"] == "cognic-tool-search"
    assert data["pack"]["kind"] == "tool"
    assert {"agent_id", "display_name", "provider_organization", "provider_url"} <= set(
        data["identity"]
    )
    assert data["risk_tier"]["tier"] == "read_only"
    assert "data_classes" in data["data_governance"]
    assert "attestation_paths" in data["supply_chain"]
    # runtime nested block
    mcp = data["tool"]["cognic"]["mcp"]
    assert mcp["transport"] == "streamable-http"
    assert mcp["auth"] == "oauth-prm"
    assert mcp["server_url"] == "http://127.0.0.1:8765/mcp"
    assert mcp["scopes"] == ["mcp:tools"]


# LOCK-2 GUARD: the shape test above only parses the ROOT manifest. This second
# test pins the RUNTIME extraction (force-include → package data → extract_pack_manifest),
# so the force-include cannot silently regress while the shape test still passes.
@pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None,
    reason="cognic-tool-search not installed; run `uv pip install -e examples/cognic-tool-search`",
)
def test_runtime_extracts_mcp_block_from_installed_package() -> None:
    from cognic_agentos.protocol.mcp_manifest import extract_pack_manifest

    manifest = extract_pack_manifest(
        distribution_name="cognic-tool-search", package_name="cognic_tool_search"
    )
    mcp = manifest["tool"]["cognic"]["mcp"]
    assert mcp["transport"] == "streamable-http"
    assert mcp["auth"] == "oauth-prm"
    assert mcp["server_url"] == "http://127.0.0.1:8765/mcp"
    assert mcp["scopes"] == ["mcp:tools"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/integration/pack_loop/test_manifest_validate.py -v`
Expected: FAIL with `FileNotFoundError` (the manifest does not exist yet).

- [ ] **Step 3: Create the single manifest (both block families)**

```toml
# examples/cognic-tool-search/cognic-pack-manifest.toml
# Proof 1a — ONE manifest, BOTH consumers (LOCK 2):
#  - the CLI (validate/sign/verify) reads the top-level blocks below;
#  - the runtime (registry + MCP host) reads [tool.cognic.mcp] as package data.
# pyproject.toml force-includes this file into the wheel at
# cognic_tool_search/cognic-pack-manifest.toml.

[pack]
pack_id = "cognic-tool-search"
schema_version = 1
kind = "tool"

[identity]
# Universally mandatory Wave-1 fields (cli/validators/identity.py:11). The
# agent-card fields are agent-pack-only and intentionally omitted for a tool pack.
agent_id = "did:web:cognic.example:tools:cognic-tool-search"
display_name = "Cognic Policy-Doc Search"
provider_organization = "Cognic Proof Harness"
provider_url = "https://cognic.example"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = []

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = [
    "attestations/cosign.sig",
    "attestations/sbom.cdx.json",
]

[tool.cognic.mcp]
# Runtime-consumed block (harness/mcp_host.py + protocol/mcp_capabilities.py).
# The key is `scopes`, NOT `required_scopes`.
transport = "streamable-http"
auth = "oauth-prm"
server_url = "http://127.0.0.1:8765/mcp"
scopes = ["mcp:tools"]
resources_supported = false
prompts_supported = false
sampling_supported = false
conformance_version = "1.0"
```

- [ ] **Step 4: Run the manifest-shape test to verify it passes**

Run: `uv run pytest tests/integration/pack_loop/test_manifest_validate.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: RUN `agentos validate` and record the result (LOCK 2 / finding)**

Run: `uv run agentos validate examples/cognic-tool-search`
Expected (LANDED 2026-06-22): pre-sign, validate exits **1** — but ONLY on the missing-attestation-file arm (`supply_chain_attestation_path_unresolvable` for `attestations/cosign.sig` + `sbom.cdx.json`, which `agentos sign` produces in Task 6) + a non-gating `identity_oasf_capability_set_missing` warning. The `[tool.cognic.mcp]` block itself is **TOLERATED** (no block-related refusal): `cli/validators/mcp.py` only refuses on restricted-data-class inconsistencies (caching / elicitation_form on `customer_pii`/`payment_action`/etc.), so for this `data_classes=["public"]` pack the block is structurally tolerated and the runtime is the real consumer. Confirm by temporarily creating non-empty placeholder attestation files → validate then exits **0** / `validate: PASS` → delete them. Full validate PASS is deferred to Task 6's real signing. **If validate REFUSES with a `[tool.cognic.mcp]`-block-related reason** on a tool pack: STOP — that would be the real finding. Record the exact refusal reason in `VALIDATION-RESULTS.md` (Task 9) and resolve per the validator's contract — re-read `cli/validate.py` + the per-concern validator that fired, adjust the offending top-level value minimally, and **never weaken the runtime `[tool.cognic.mcp]` block** (the runtime needs it verbatim).

Note: a *pre-sign* `agentos validate` will refuse on missing `supply_chain.attestation_paths` files — that is expected (the files are produced by `sign` in Task 6) and is NOT the finding. Run this readiness check knowing the attestation-file-existence arm will flag until Task 6; the block-shape acceptance is what Step 5 is checking. To isolate block-shape from attestation-existence, the implementer may temporarily create empty `attestations/cosign.sig` + `attestations/sbom.cdx.json` placeholders for this readiness check, then delete them before Task 6 signs for real.

- [ ] **Step 6: Add the LOCK-2 force-include to `pyproject.toml` (the manifest now exists) + reinstall**

The Task-1 `pyproject.toml` intentionally omitted the force-include (the manifest did not exist yet). Now that `cognic-pack-manifest.toml` exists, add the stanza so the runtime reads the SAME manifest as package data inside the wheel (`extract_pack_manifest` → `Distribution.locate_file`). Append to `examples/cognic-tool-search/pyproject.toml`:

```toml
# LOCK 2: ship the SAME manifest the CLI reads (the root file) as package data
# inside the wheel, so the runtime extract_pack_manifest(Distribution.locate_file)
# finds it at cognic_tool_search/cognic-pack-manifest.toml. (The corpus is inside
# the package tree, so hatchling auto-includes it — no force-include needed.)
[tool.hatch.build.targets.wheel.force-include]
"cognic-pack-manifest.toml" = "cognic_tool_search/cognic-pack-manifest.toml"
```

Run: `uv pip install -e examples/cognic-tool-search`
Expected: reinstalled cleanly (no "file not found" for the force-included manifest, since it now exists).

- [ ] **Step 7: Commit**

```bash
git add examples/cognic-tool-search/cognic-pack-manifest.toml \
        examples/cognic-tool-search/pyproject.toml \
        tests/integration/pack_loop/test_manifest_validate.py
git commit -m "feat(proof): single dual-consumer pack manifest + force-include + validate check (Proof 1a Task 3)"
```

---

## Task 4: FastMCP server + LocalTokenVerifier + auto-PRM

**Files:**
- Create: `examples/cognic-tool-search/src/cognic_tool_search/server.py`
- Create: `tests/integration/pack_loop/conftest.py` (the session-scoped managed `pack_server` / `local_as` fixtures — verbatim the "Shared test-server fixtures" section above; created here because Task 4 is the first task whose test consumes a fixture)
- Test: `tests/integration/pack_loop/test_server_prm.py`

- [ ] **Step 1: Write the failing server/PRM integration test (consumes the `pack_server` fixture)**

```python
# tests/integration/pack_loop/test_server_prm.py
"""Proof 1a Task 4 — the pack's FastMCP server serves /mcp and auto-publishes PRM.

Uses the session-scoped, managed `pack_server` fixture (conftest.py) — NOT a
per-test daemon thread — so the fixed port 8765 is bound once and torn down at
session end (no port/lifecycle flakes when the pack-loop tests run as a group).
"""
import importlib.util

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None or importlib.util.find_spec("mcp") is None,
    reason="cognic-tool-search and the mcp SDK must be installed",
)


def test_server_publishes_prm_with_authorization_server(pack_server: str) -> None:
    # pack_server has started the FastMCP server + waited for port 8765.
    # PRM is auto-served at the RFC 9728 well-known path for resource path /mcp.
    resp = httpx.get("http://127.0.0.1:8765/.well-known/oauth-protected-resource/mcp", timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    # The SDK builds PRM `authorization_servers` from AuthSettings.issuer_url, an
    # `AnyHttpUrl`. pydantic normalizes a host-only URL to canonical RFC-3986 form
    # WITH a trailing slash, so the real served value is "http://127.0.0.1:9000/".
    # (Carry-forward: Task 5's AS allow-list secret must seed the SLASH form to
    # match this exact-string membership check.)
    assert body["authorization_servers"] == ["http://127.0.0.1:9000/"]

    # The /mcp endpoint requires auth (401 with no bearer) — the runtime PRM probe relies on this.
    unauth = httpx.get("http://127.0.0.1:8765/mcp", timeout=5)
    assert unauth.status_code == 401
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/integration/pack_loop/test_server_prm.py -v`
Expected: FAIL — the `pack_server` fixture errors because `conftest.py` and/or `cognic_tool_search.server.build_server` do not exist yet (the fixture imports `build_server`). Once Step 3 creates both, this becomes a PASS in Step 4.

- [ ] **Step 3: Implement the FastMCP server (1.27.0 API)**

```python
# examples/cognic-tool-search/src/cognic_tool_search/server.py
"""Streamable-HTTP MCP server for cognic-tool-search (mcp SDK 1.27.0 FastMCP).

Resource-server-only OAuth mode: passing `auth` + `token_verifier` (and no
auth_server_provider) makes FastMCP auto-publish Protected Resource Metadata at
/.well-known/oauth-protected-resource/mcp and wrap /mcp with bearer auth. The
LocalTokenVerifier accepts tokens minted by the Proof 1a local authorization
server; it binds the resource (audience) to server_url and the granted scope to
a subset of {mcp:tools}.
"""
from __future__ import annotations

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from cognic_tool_search.corpus_loader import load_corpus, search

_HOST = "127.0.0.1"
_PORT = 8765
_SERVER_URL = "http://127.0.0.1:8765/mcp"
_REQUIRED_SCOPES = ["mcp:tools"]


class LocalTokenVerifier(TokenVerifier):
    """Accepts any non-empty bearer token from the trusted local AS and binds it
    to this resource + the required scopes. The Proof 1a harness is the only
    caller; the AS allow-list + OAuth client creds are enforced upstream by the
    AgentOS MCPAuthzClient before a token ever reaches here."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(
            token=token,
            client_id="cognic-tool-search-proof",
            scopes=list(_REQUIRED_SCOPES),
            expires_at=None,
            resource=_SERVER_URL,
        )


def build_server(*, as_issuer: str) -> FastMCP:
    mcp = FastMCP(
        "cognic-tool-search",
        host=_HOST,
        port=_PORT,
        streamable_http_path="/mcp",
        json_response=False,
        stateless_http=False,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(as_issuer),
            resource_server_url=AnyHttpUrl(_SERVER_URL),
            required_scopes=list(_REQUIRED_SCOPES),
        ),
        token_verifier=LocalTokenVerifier(),
    )

    _corpus = load_corpus()

    @mcp.tool(name="search_policy_docs", description="Search the bundled static policy-doc corpus.")
    def search_policy_docs(query: str) -> list[dict[str, str]]:
        return search(_corpus, query)

    return mcp


if __name__ == "__main__":
    import os

    build_server(as_issuer=os.environ.get("COGNIC_PROOF_AS_ISSUER", "http://127.0.0.1:9000")).run(
        transport="streamable-http"
    )
```

- [ ] **Step 4: Create `tests/integration/pack_loop/conftest.py` (the shared managed fixtures)**

Create `conftest.py` with the `_AS_ISSUER` constant + `_wait_port` / `_serve` helpers + the session-scoped `local_as` and (decoupled) `pack_server` fixtures **exactly as shown in the "Shared test-server fixtures" section above**. The `local_as` fixture lazily imports `tests.integration.pack_loop._local_as` (created in Task 5) inside the fixture body — so it is harmless here (Task 4's test requests only `pack_server`, which imports `cognic_tool_search.server` created in Step 3). Do not request `local_as` until Task 5.

- [ ] **Step 5: Run the server/PRM test to verify it passes**

Run: `uv run pytest tests/integration/pack_loop/test_server_prm.py -v`
Expected: PASS (1 passed) — the `pack_server` fixture starts the server once and the PRM well-known path returns 200. If the PRM well-known path differs in the installed `mcp` 1.27.0 build, read the SDK's `mcp/server/fastmcp/server.py` PRM wiring and adjust the asserted path — the well-known path is SDK-owned.

- [ ] **Step 6: Commit**

```bash
git add examples/cognic-tool-search/src/cognic_tool_search/server.py \
        tests/integration/pack_loop/conftest.py \
        tests/integration/pack_loop/test_server_prm.py
git commit -m "feat(proof): FastMCP streamable-http server + token verifier + PRM + shared server fixtures (Proof 1a Task 4)"
```

---

## Task 5: Local authorization server + `acquire_token` end-to-end

**Files:**
- Create: `tests/integration/pack_loop/_local_as.py`
- Test: `tests/integration/pack_loop/test_acquire_token.py`

- [ ] **Step 1: Write the failing acquire_token end-to-end test**

```python
# tests/integration/pack_loop/test_acquire_token.py
"""Proof 1a Task 5 — MCPAuthzClient.acquire_token succeeds against the live local
AS + the live pack server + a seeded in-memory secret adapter.

This is the trickiest harness piece: it exercises the REAL runtime OAuth/PRM path
(PRM discovery -> per-tenant AS allow-list -> token request -> resource binding).
"""
import importlib.util

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None or importlib.util.find_spec("mcp") is None,
    reason="cognic-tool-search and the mcp SDK must be installed",
)

_TENANT = "proof_tenant"
_AS_ISSUER = "http://127.0.0.1:9000"
_AS_HOST_KEY = "127.0.0.1_9000"
_SERVER_URL = "http://127.0.0.1:8765/mcp"


class _SeededSecretAdapter:
    """Minimal SecretAdapter: only async read(path)->dict is exercised by authz."""

    def __init__(self, secrets: dict[str, dict]) -> None:
        self._secrets = secrets

    async def read(self, path: str) -> dict:
        return self._secrets[path]


@pytest.mark.asyncio
async def test_acquire_token_succeeds_end_to_end(pack_server: str, local_as: str) -> None:
    # The `pack_server` (127.0.0.1:8765) and `local_as` (127.0.0.1:9000) fixtures
    # (conftest.py) have started both servers once + waited for their ports — no
    # per-test thread launch (managed teardown at session end).
    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.protocol.mcp_authz import MCPAuthzClient

    # seeded secret adapter: AS allow-list + OAuth client creds (per-tenant)
    secret = _SeededSecretAdapter(
        {
            f"secret/cognic/{_TENANT}/mcp-as-allowlist": {"servers": [_AS_ISSUER]},
            f"secret/cognic/{_TENANT}/mcp-oauth/{_AS_HOST_KEY}": {
                "client_id": "cognic-mcp-proof",
                "client_secret": "proof-secret",
                "auth_method": "client_secret_post",
            },
        }
    )

    settings = build_settings_without_env_file()  # runtime_profile defaults to "dev"
    assert settings.runtime_profile == "dev"  # loopback SSRF guard is off in dev

    async with httpx.AsyncClient() as http_client:
        authz = MCPAuthzClient(
            settings=settings,
            vault_client=secret,
            http_client=http_client,
            audit_store=_NullAuditStore(),
            decision_history_store=_NullDecisionHistoryStore(),
        )
        token = await authz.acquire_token(
            server_url=_SERVER_URL,
            manifest_scopes=("mcp:tools",),
            request_id="proof-rid",
            tenant_id=_TENANT,
        )

    assert token.value
    assert token.resource_indicator == _SERVER_URL
    assert set(token.scopes) <= {"mcp:tools"}
```

> **In-task verification (Step 1):** the `audit_store` / `decision_history_store` are constructor-required but unused on the `acquire_token` success path. Confirm whether the harness can pass lightweight nulls or must construct the real in-memory stores. If real stores are required, replace `_NullAuditStore()` / `_NullDecisionHistoryStore()` with the in-memory relational-backed `AuditStore(engine)` / `DecisionHistoryStore(engine)` built in Task 7 Step 2 (read `core/audit.py` + `core/decision_history.py` constructors). Define the nulls at the top of this test module if the path truly never touches them, else import the real ones.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/integration/pack_loop/test_acquire_token.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tests.integration.pack_loop._local_as'`.

- [ ] **Step 3: Implement the local authorization server**

```python
# tests/integration/pack_loop/_local_as.py
"""A tiny localhost OAuth2 client-credentials authorization server for Proof 1a.

Serves exactly what MCPAuthzClient needs:
  - GET /.well-known/oauth-authorization-server -> {"token_endpoint": ".../token"}
  - POST /token (grant_type=client_credentials) -> {"access_token","expires_in","scope"}

The access token is a simple JWT (3-part header.payload.signature) whose payload
carries `aud = <resource>` — the RFC 8707 `resource` form parameter, which is the
MCP `server_url`. The runtime DECODES it and exercises audience validation
(`aud == server_url`), matching spec §5. The signature part is decorative: AgentOS
does NOT verify the AS signature here (the AS is trusted via the per-tenant
allow-list); it validates the `aud` claim. The granted scope echoes the requested
scope so it is a subset of the manifest scopes (no overgrant).
"""
from __future__ import annotations

import base64
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

_AS_ISSUER = "http://127.0.0.1:9000"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


async def _metadata(_request: Request) -> JSONResponse:
    return JSONResponse({"token_endpoint": f"{_AS_ISSUER}/token", "issuer": _AS_ISSUER})


async def _token(request: Request) -> JSONResponse:
    form = await request.form()
    requested_scope = str(form.get("scope", "mcp:tools"))
    resource = str(form.get("resource", ""))  # RFC 8707 resource indicator == server_url
    # A simple JWT so the runtime decodes the payload and validates aud == server_url
    # (spec §5 audience check). header.payload.signature; signature is decorative.
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    payload = _b64url(json.dumps({"aud": resource, "scope": requested_scope}).encode("utf-8"))
    access_token = f"{header}.{payload}.sig"
    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600, "scope": requested_scope}
    )


def build_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/.well-known/oauth-authorization-server", _metadata, methods=["GET"]),
            Route("/token", _token, methods=["POST"]),
        ]
    )


def run_local_as(*, port: int = 9000) -> None:
    uvicorn.run(build_app(), host="127.0.0.1", port=port, log_level="warning")
```

- [ ] **Step 4: Run the acquire_token test to verify it passes**

Run: `uv run pytest tests/integration/pack_loop/test_acquire_token.py -v`
Expected: PASS (1 passed). If it fails on an `AuthzReason`, map the reason to the grounded contract: `mcp_as_not_allowlisted` → the allow-list secret key/string mismatch; `mcp_oauth_credentials_missing` → the `<as_host>` `:`→`_` key shape; `mcp_oauth_as_discovery_invalid` → the AS metadata shape; `mcp_token_scope_overgrant` → the granted scope is not ⊆ manifest scopes. Fix the harness (not the runtime).

- [ ] **Step 5: Commit**

```bash
git add tests/integration/pack_loop/_local_as.py \
        tests/integration/pack_loop/test_acquire_token.py
git commit -m "feat(proof): local AS + acquire_token end-to-end (Proof 1a Task 5)"
```

---

## Task 6: Authoring pipeline + attestation provisioning

**Files:**
- Create: `tests/integration/pack_loop/_authoring.py`
- Test: `tests/integration/pack_loop/test_authoring_provision.py`

- [ ] **Step 1: Write the failing provisioning test**

```python
# tests/integration/pack_loop/test_authoring_provision.py
"""Proof 1a Task 6 — real `agentos sign` output, provisioned into the resolver's
expected layout, is accepted by resolve_pack_attestations.

The author->runtime bridge: sign writes 7 files to <pack>/attestations/ and signs
the wheel IN PLACE in <pack>/dist/; the resolver wants all 8 co-located under
<root>/<dist>/<version>/. The provisioning copy (no renames) is the bridge.

Env-gated: requires the cosign/syft/grype toolchain. Fail-loud (not skip) when
COGNIC_RUN_PACK_LOOP_PROOF is set but the toolchain is missing.
"""
import os
import shutil
from pathlib import Path

import pytest

_PROOF = os.environ.get("COGNIC_RUN_PACK_LOOP_PROOF") == "1"
pytestmark = pytest.mark.skipif(not _PROOF, reason="set COGNIC_RUN_PACK_LOOP_PROOF=1 to run the proof")

_REQUIRED_BINS = ("cosign", "syft", "grype")


def _require_toolchain() -> None:
    missing = [b for b in _REQUIRED_BINS if shutil.which(b) is None]
    if missing:
        raise AssertionError(
            f"COGNIC_RUN_PACK_LOOP_PROOF=1 but missing toolchain: {missing}. "
            "Install cosign/syft/grype or unset the env to skip."
        )


def test_real_sign_output_provisions_into_resolver_layout(
    tmp_path: Path, registry: PluginRegistry
) -> None:
    _require_toolchain()
    from cognic_agentos.protocol.pack_attestation_resolver import resolve_pack_attestations
    from cognic_agentos.protocol.plugin_registry import PluginRegistry

    from tests.integration.pack_loop._authoring import (
        build_sign_verify,
        provision_attestation_tree,
        write_cosign_pub,
    )

    pack = Path(__file__).resolve().parents[3] / "examples" / "cognic-tool-search"
    trust_root = tmp_path / "trust-roots"
    att_root = tmp_path / "attestations"

    artifacts = build_sign_verify(pack, key_dir=tmp_path / "keys")
    write_cosign_pub(trust_root, artifacts.cosign_pub)
    base = provision_attestation_tree(att_root, artifacts)

    # The resolver accepts the assembled tree against a discovered pack record.
    # Reuse/mirror Task 1's seeded sqlite AuditStore fixture; PluginRegistry
    # requires audit_store= even though discover() itself never writes audit rows.
    pack_obj = next(
        p for p in registry.discover() if p.record.distribution_name == "cognic-tool-search"
    )
    att = resolve_pack_attestations(
        pack_obj, pack_attestation_root=att_root, cosign_trust_root=trust_root / "_default" / "cosign.pub"
    )
    assert att.cosign_signature_path == base / "cosign.sig"
    assert att.cosign_blob_path.suffix == ".whl"
    assert att.cosign_blob_path.parent == base
    assert len(att.sbom_signed_digest) == 64
```

- [ ] **Step 2: Run it to verify it fails**

Run: `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_authoring_provision.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tests.integration.pack_loop._authoring'` (or, if the toolchain is absent, an explicit `AssertionError` naming the missing binaries — that fail-loud is itself correct behavior).

- [ ] **Step 3: Implement the authoring + provisioning helpers**

```python
# tests/integration/pack_loop/_authoring.py
"""Build -> sign -> validate -> verify the example pack, then provision the
attestation tree into the resolver's expected <root>/<dist>/<version>/ layout.

`agentos sign --bundle` writes 7 attestations into <pack>/attestations/ and signs
the wheel in place in <pack>/dist/. The resolver expects all 8 artifacts
co-located under <root>/<dist_name>/<dist_version>/. provision_attestation_tree
performs that copy (no renames) — the author->runtime bridge Proof 1a validates.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_DIST_NAME = "cognic-tool-search"
_DIST_VERSION = "0.1.0"
_ATTESTATION_FILES = (
    "cosign.sig",
    "bundle.sigstore",
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
)


@dataclass(frozen=True)
class Artifacts:
    wheel: Path
    attestations_dir: Path
    cosign_pub: Path


def _run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise AssertionError(f"{' '.join(cmd)} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}")


def build_sign_verify(pack: Path, *, key_dir: Path) -> Artifacts:
    key_dir.mkdir(parents=True, exist_ok=True)
    # 1. cosign keypair. COSIGN_PASSWORD="" -> unattended (empty passphrase).
    cosign_env = {**os.environ, "COSIGN_PASSWORD": ""}
    _run(["cosign", "generate-key-pair"], cwd=key_dir, env=cosign_env)
    cosign_pub = key_dir / "cosign.pub"
    cosign_key = key_dir / "cosign.key"

    # 2. build the wheel into <pack>/dist/
    dist = pack / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    _run([sys.executable, "-m", "build", "--wheel"], cwd=pack)
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"

    # 3. sign --bundle (real cosign + syft + grype + license + SLSA + in-toto).
    #    `agentos sign` has NO --key flag; it resolves the signing key from
    #    settings.signing_key_path == env COGNIC_SIGNING_KEY_PATH (cli/sign.py:362,372).
    #    cosign sign-blob reads the (encrypted) key, so COSIGN_PASSWORD must be set too.
    sign_env = {**os.environ, "COGNIC_SIGNING_KEY_PATH": str(cosign_key), "COSIGN_PASSWORD": ""}
    _run(["uv", "run", "agentos", "sign", "--bundle", str(pack)], env=sign_env)

    # 4. validate against the now-populated attestation tree, then verify.
    #    `agentos verify` needs the trust root: --trust-root <cosign.pub> (preferred)
    #    or env COGNIC_SIGNING_TRUST_ROOT_PATH (cli/verify.py:203,213). The trust root
    #    is the cosign PUBLIC key; the signing key above is the PRIVATE key.
    _run(["uv", "run", "agentos", "validate", str(pack)])
    _run(["uv", "run", "agentos", "verify", "--trust-root", str(cosign_pub), str(pack)])

    return Artifacts(wheel=wheels[0], attestations_dir=pack / "attestations", cosign_pub=cosign_pub)


def write_cosign_pub(trust_root: Path, cosign_pub: Path) -> Path:
    dest = trust_root / "_default" / "cosign.pub"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(cosign_pub.read_bytes())
    return dest


def provision_attestation_tree(att_root: Path, artifacts: Artifacts) -> Path:
    """Assemble <att_root>/<dist>/<version>/ with the 7 attestations + the wheel.
    No renames — the names already match the resolver exactly. THIS is the
    co-location bridge sign itself never performs (the recorded finding)."""
    base = att_root / _DIST_NAME / _DIST_VERSION
    base.mkdir(parents=True, exist_ok=True)
    for name in _ATTESTATION_FILES:
        src = artifacts.attestations_dir / name
        if src.exists():  # 4 required always present; 3 optional may or may not be
            shutil.copy2(src, base / name)
    shutil.copy2(artifacts.wheel, base / artifacts.wheel.name)
    return base
```

> **In-task verification (Step 3):** the signing-key mechanism is RESOLVED — `agentos sign` has no `--key` flag; it reads the key from `COGNIC_SIGNING_KEY_PATH` (the env set above), and `agentos verify` takes `--trust-root <cosign.pub>` (both confirmed against `cli/sign.py:362,372` + `cli/verify.py:203,213`). The one thing to confirm before running: that `agentos sign --bundle` takes the pack dir **positionally** as written (run `uv run agentos sign --help` once; adjust the `_run([...])` argv only if the positional/flag shape differs). `COSIGN_PASSWORD=""` is set in the subprocess env for unattended keygen + sign. The goal is real signatures; do not stub.

- [ ] **Step 4: Run the provisioning test to verify it passes**

Run: `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_authoring_provision.py -v`
Expected: PASS (1 passed) — real `agentos sign` output drops into the resolver layout after the co-location copy. (If `agentos validate` refuses the `[tool.cognic.mcp]` block here, that is the Task 3 finding surfacing — record + resolve.)

- [ ] **Step 5: Commit**

```bash
git add tests/integration/pack_loop/_authoring.py \
        tests/integration/pack_loop/test_authoring_provision.py
git commit -m "feat(proof): real sign + attestation provisioning into resolver layout (Proof 1a Task 6)"
```

---

## Task 7: In-process harness — the full loop

**Files:**
- Create: `tests/integration/pack_loop/test_proof_1a_inprocess.py`
- (Read for wiring: `tests/support/adapter_fixtures.py`, `tests/conftest.py`, `db/adapters/factory.py`, `harness/runtime.py`, `harness/registry_boot.py`, `harness/mcp_host.py`, `portal/api/app.py`, `portal/api/mcp/routes.py`, `portal/rbac/actor.py`)

- [ ] **Step 1: Confirm the in-memory adapter wiring (read-only — no code yet)**

Read `tests/support/adapter_fixtures.py` and `tests/conftest.py` (the `memory_registry` fixture). Confirm the exact class names + registration calls for: relational (`InMemoryRelationalAdapter`, sqlite+aiosqlite + auto `create_all`), secret, vector, embedding, observability. Confirm how an `AdapterRegistry` is constructed and how `build_adapters_async(settings, registry)` consumes it. Confirm the `MCPAdmissionDeps` construction by reading the startup-discovery lifespan in `portal/api/app.py`. Record the confirmed names inline in the test you write in Step 3. (No commit — this is a read step.)

- [ ] **Step 2: Write the full-loop harness test (registration + route call_tool + chain verify)**

```python
# tests/integration/pack_loop/test_proof_1a_inprocess.py
"""Proof 1a — the real-app in-process pack-governance loop.

Green IFF the real authoring trust pipeline produces artifacts the real runtime
trust pipeline accepts: real signed pack -> provisioned attestations -> startup
trust-registration (require_cosign=True) -> MCP host resolves it -> route tool
call succeeds -> decision-history chain verifies -> evidence pack exports.

Env-gated COGNIC_RUN_PACK_LOOP_PROOF=1; fail-loud (not skip) when set but the
toolchain is missing (mirrors tests/integration/models/test_real_cosign_proof.py).
"""
import os
import shutil
from pathlib import Path

import httpx
import pytest

_PROOF = os.environ.get("COGNIC_RUN_PACK_LOOP_PROOF") == "1"
pytestmark = pytest.mark.skipif(not _PROOF, reason="set COGNIC_RUN_PACK_LOOP_PROOF=1 to run the proof")

_TENANT = "proof_tenant"
_AS_ISSUER = "http://127.0.0.1:9000"
_AS_HOST_KEY = "127.0.0.1_9000"
_SERVER_URL = "http://127.0.0.1:8765/mcp"


def _require_toolchain() -> None:
    missing = [b for b in ("cosign", "syft", "grype") if shutil.which(b) is None]
    if missing:
        raise AssertionError(f"COGNIC_RUN_PACK_LOOP_PROOF=1 but missing toolchain: {missing}.")


@pytest.mark.asyncio
async def test_proof_1a_full_loop(pack_server: str, local_as: str, tmp_path: Path) -> None:
    # The `pack_server` (127.0.0.1:8765) + `local_as` (127.0.0.1:9000) fixtures
    # (conftest.py) start both servers once with managed teardown — no per-test
    # thread launch (no port/lifecycle flake when the pack-loop tests run together).
    _require_toolchain()
    # Read-step (Task 7 Step 1) confirmed names are used below.
    from tests.integration.pack_loop._authoring import (
        build_sign_verify,
        provision_attestation_tree,
        write_cosign_pub,
    )

    pack = Path(__file__).resolve().parents[3] / "examples" / "cognic-tool-search"
    trust_root = tmp_path / "trust-roots"
    att_root = tmp_path / "attestations"

    # ---- authoring + provisioning (Task 6 helpers) ----
    artifacts = build_sign_verify(pack, key_dir=tmp_path / "keys")
    write_cosign_pub(trust_root, artifacts.cosign_pub)
    provision_attestation_tree(att_root, artifacts)

    # ---- allow-list file listing THIS pack's distribution name ----
    allowlist = tmp_path / "plugin_allowlist.json"
    allowlist.write_text('{"_default": ["cognic-tool-search"]}', encoding="utf-8")

    # ---- Settings: require_cosign=True (LOCK 1), dev profile, the tmp trust/att roots ----
    # (construct via the project's Settings builder; set fields per the grounded recipe)
    settings = _build_proof_settings(
        trust_root_prefix=trust_root,
        pack_attestation_root_path=att_root,
        plugin_allowlist_path=allowlist,
        evidence_signing_key=tmp_path / "evidence-signing.pem",
    )
    assert settings.runtime_profile == "dev"
    assert settings.require_cosign is True

    # ---- minimal adapter pool + the REAL composition root ----
    adapters = await _open_minimal_adapters(settings, secret_seed=_secret_seed())
    runtime = _build_runtime(settings, adapters)
    registry = await _populate_registry(settings, runtime, adapters)

    # ASSERTION 2 (core seam): the pack registered WITHOUT a fail-soft skip.
    registered = [r for r in registry.iter_registered_pack_candidates()]
    assert any(getattr(r, "package_name", None) == "cognic_tool_search" or
               "cognic-tool-search" in str(r) for r in registered), \
        f"cognic-tool-search not registered (fail-soft skip = the real attestation pipeline REJECTED real sign output): {registered}"

    # ---- build the app with the MCP host + an actor binder, drive the route ----
    app = _build_app(settings, runtime, registry, adapters)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # ASSERTION 3: list_tools shows search_policy_docs
        lst = await client.get(f"/api/v1/mcp/servers/{_server_id()}/tools", headers=_actor_headers())
        assert lst.status_code == 200, lst.text
        assert any(t["name"] == "search_policy_docs" for t in lst.json()["tools"])

        # ASSERTION 4: call_tool returns the deterministic result
        call = await client.post(
            f"/api/v1/mcp/servers/{_server_id()}/tools/call",
            headers=_actor_headers(),
            json={"tool_name": "search_policy_docs", "arguments": {"query": "retention"}},
        )
        assert call.status_code == 200, call.text
        assert "retention" in str(call.json()).lower()

    # ASSERTION 5: a decision-history row exists for the invocation + the chain verifies
    await _assert_invocation_audited_and_chain_valid(runtime, tenant_id=_TENANT)
```

> **In-task verification (Step 2):** the helper names prefixed `_` above (`_build_proof_settings`, `_open_minimal_adapters`, `_build_runtime`, `_populate_registry`, `_build_app`, `_actor_headers`, `_server_id`, `_secret_seed`, `_assert_invocation_audited_and_chain_valid`) are to be implemented in this same test module per the Step 1 confirmed wiring. Implement each as a thin wrapper over the real composition-root calls (`build_adapters_async`, `build_runtime`, `build_and_populate_registry`, `build_mcp_host`, `create_app(actor_binder=...)`). The `iter_registered_pack_candidates()` assertion shape + the `_server_id()` derivation (the registry's server-id for the pack) must be confirmed against `protocol/plugin_registry.py` + `portal/api/mcp/routes.py`; adjust the assertion to the real registered-candidate API. The `CallToolRequest` body shape (`tool_name` in body, arguments dict) is per `portal/api/mcp/dto.py` — confirm field names.

- [ ] **Step 3: Implement the helper wrappers in the test module**

Implement the `_`-prefixed helpers using the Step 1 confirmed adapter class names + the real composition-root functions. Each helper is a thin, real call (no mocks): `_open_minimal_adapters` builds an `AdapterRegistry` with the in-memory relational/secret/vector/embedding/observability adapters + `local_fs` object store, seeds the secret adapter with the two OAuth keys, and calls `build_adapters_async` + `open_all`; `_populate_registry` calls `build_and_populate_registry(...)` with the real `SupplyChainPipeline(settings)` + `MCPAdmissionDeps`; `_build_app` calls `create_app(...)` threading the registry + host + an `actor_binder` returning an `Actor(subject="proof", tenant_id=_TENANT, scopes=frozenset({"mcp.tool.invoke", "mcp.tool.list", "compliance.evidence_pack.read"}), actor_type="service")`.

- [ ] **Step 4: Run the full-loop harness to verify it passes**

Run: `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_proof_1a_inprocess.py -v`
Expected: PASS (1 passed) — assertions 2–5 green. A fail-soft skip at assertion 2 = the real attestation pipeline rejected real sign output (the seam finding); diagnose against the resolver/trust-gate reason and record.

- [ ] **Step 5: Typecheck + commit**

Run: `uv run mypy src tests`
Expected: no new errors in the touched scope.

```bash
git add tests/integration/pack_loop/test_proof_1a_inprocess.py
git commit -m "feat(proof): in-process full-loop harness — registration + route call + chain verify (Proof 1a Task 7)"
```

---

## Task 8: Evidence-pack export + re-verify

**Files:**
- Modify: `tests/integration/pack_loop/test_proof_1a_inprocess.py` (add the evidence-export assertion — PASS criterion 6)

- [ ] **Step 1: Add the failing evidence-export assertion**

Append to `test_proof_1a_full_loop` (after assertion 5):

```python
    # ASSERTION 6: an evidence pack exports + its tarball is well-formed (tamper-evident
    # shape). NOTE: there is NO verify_evidence_pack() — re-verification is tarball
    # inspection. export_evidence_pack REQUIRES tenant_id / period_start / period_end /
    # signing_key_path (evidence_pack.py:131-137) plus engine / secret_adapter.
    import datetime as _dt
    import io
    import tarfile

    from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack

    now = _dt.datetime.now(_dt.timezone.utc)
    tar_bytes = await export_evidence_pack(
        engine=adapters.relational.engine,
        secret_adapter=adapters.secret,
        tenant_id=_TENANT,
        period_start=now - _dt.timedelta(hours=1),
        period_end=now + _dt.timedelta(hours=1),
        signing_key_path=settings.evidence_pack_signing_key_path,
    )
    assert tar_bytes, "evidence pack export returned no bytes"
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        members = tar.getnames()
    # The pack must contain the hash-chained decision-history JSONL + a signature.
    assert any(m.endswith(".jsonl") for m in members), f"no JSONL in evidence pack: {members}"
    assert any(m.endswith(".sig") or "sig" in m.lower() for m in members), \
        f"no signature member in evidence pack: {members}"
```

> **In-task verification (Step 1):** `verify_evidence_pack` does NOT exist — re-verification is tarball inspection. Read `tests/unit/compliance/iso42001/test_evidence_pack.py` for the EXACT member names + any chain-verification helper used (e.g. `core/chain_verifier.py`), and assert against those exact names rather than the `endswith`/substring heuristics above. `export_evidence_pack` requires `tenant_id` / `period_start` / `period_end` / `signing_key_path` (`evidence_pack.py:131-137`) + `engine` / `secret_adapter`; it shells `cosign sign-blob`, so cosign on PATH + the signing-key PEM are required (already in `_require_toolchain` + `_build_proof_settings`'s `evidence_pack_signing_key_path`). Alternative production-surface path: drive `GET {api_prefix}/compliance/evidence-pack?from=...&to=...` via the bound-actor client (the actor carries `compliance.evidence_pack.read`) — `evidence_pack_routes.py:24` (query params `from`/`to`; tenant from the actor). Either is acceptable; the direct call is simpler given the client block has already closed by this point in the test.

- [ ] **Step 2: Run the full harness to verify assertion 6 passes**

Run: `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_proof_1a_inprocess.py -v`
Expected: PASS (1 passed) with all 6 assertions green.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/pack_loop/test_proof_1a_inprocess.py
git commit -m "feat(proof): evidence-pack export + re-verify assertion (Proof 1a Task 8)"
```

---

## Task 9: VALIDATION-RESULTS.md (the deliverable)

**Files:**
- Create: `docs/VALIDATION-RESULTS.md`

- [ ] **Step 1: Write the operator-fillable results template**

```markdown
<!-- docs/VALIDATION-RESULTS.md -->
# AgentOS — Validation Results

**Proof 1a — real-app in-process pack-governance loop.**

> Proof 1a proves the pack-governance loop in the real composition root. Proof 1b
> proves the same signed pack in a kind/Helm deployed instance. 1a proves the loop
> **logic**; it does NOT claim "bank-deployed."

## Run metadata
- **AgentOS commit:** `<git rev-parse HEAD>`
- **Pack:** `cognic-tool-search` 0.1.0 (`examples/cognic-tool-search/`)
- **Date / operator:** `<fill>`
- **Toolchain:** cosign `<ver>`, syft `<ver>`, grype `<ver>`
- **Command:** `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_proof_1a_inprocess.py -v`

## Artifact digests
- wheel `cognic_tool_search-0.1.0-*.whl` sha256: `<fill>`
- `cosign.sig` sha256: `<fill>`
- `sbom.cdx.json` sha256: `<fill>`
- SLSA `sbom_digest_sha256`: `<fill>`

## The 6 PASS assertions
1. [ ] `agentos verify` exits 0 on the signed pack.
2. [ ] `build_and_populate_registry` registers `cognic-tool-search` WITHOUT a fail-soft skip (the core seam: real runtime trust pipeline accepted real `agentos sign` output, with `require_cosign=True`).
3. [ ] `list_tools` reports `search_policy_docs`.
4. [ ] `call_tool("search_policy_docs", {"query": "retention"})` via `POST /api/v1/mcp/servers/{id}/tools/call` returns the deterministic result.
5. [ ] A decision-history/audit row exists for the invocation with pack identity + signature digest; the hash chain verifies.
6. [ ] An evidence pack exports and re-verifies (tamper-evident).

**Green ⇔ the real authoring trust pipeline produces artifacts the real runtime trust pipeline accepts.**

## Findings recorded by this proof
- **Two consumers, one manifest (LOCK 2):** the CLI reads the top-level blocks from the on-disk manifest; the runtime reads the SAME manifest as package data inside the wheel (`force-include`). Result: `<accepted / refused — exact reason>`.
- **Wheel co-location provisioning:** `agentos sign` writes attestations to `<pack>/attestations/` and signs the wheel in place in `<pack>/dist/`; the resolver requires all 8 under `<root>/<dist>/<version>/`. A provisioning copy (no renames) bridges them. Result: `<bridged cleanly / renames required — detail>`.
- **`[tool.cognic.mcp]`-on-tool-pack validate tolerance:** `<agentos validate accepted / refused — exact reason + resolution>`.
- **Other deltas:** `<fill any author↔runtime mismatch surfaced>`.

## Honesty boundary
- "Done/✅" here means the loop ran green in the real composition root in-process. It does NOT mean deployed-and-proven on a cluster — that is **Proof 1b** (kind/Helm, same signed pack).
```

- [ ] **Step 2: Commit**

```bash
git add docs/VALIDATION-RESULTS.md
git commit -m "docs(proof): VALIDATION-RESULTS.md template for Proof 1a (Task 9)"
```

---

## Final verification (after all tasks)

- [ ] Run the env-gated proof end-to-end: `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/ -v` — all green (or the toolchain-missing fail-loud if run without the binaries).
- [ ] Run the default (non-proof) suite touching the new files: `uv run pytest tests/integration/pack_loop/ -v` — the env-gated proof tests SKIP; the unit-level tests (discovery, corpus, manifest-shape, server/PRM) PASS where their packages are installed.
- [ ] `uv run mypy src tests` — clean for the touched scope.
- [ ] Confirm `examples/cognic-tool-search/` is NOT in the OS wheel: `uv build` then inspect — `packages = ["src/cognic_agentos"]` excludes it.
- [ ] Fill `docs/VALIDATION-RESULTS.md` with the real operator run + record every finding.
- [ ] Then use **superpowers:finishing-a-development-branch**.

## Self-review notes (controller, pre-handoff)

- **Spec coverage:** §3 pack → Tasks 1–4; §4 authoring (sign-before-validate) → Task 6; §5 OAuth/PRM → Tasks 4–5; §6 harness/footprint → Task 7; §7 the 6 PASS criteria → Tasks 6 (verify), 7 (2–5), 8 (6); §8 VALIDATION-RESULTS → Task 9; §9 (b) fallback → recorded in Task 9 findings; §10 risks → the two surfaced findings (Tasks 3, 6). Covered.
- **Name consistency:** `SERVER_DESCRIPTOR`, `search_policy_docs`, `server_url = http://127.0.0.1:8765/mcp`, `_AS_ISSUER = http://127.0.0.1:9000`, `_AS_HOST_KEY = 127.0.0.1_9000`, distribution `cognic-tool-search` / package `cognic_tool_search`, `scopes` (never `required_scopes`) — consistent across tasks.
- **Flagged unknowns** (deliberate in-task verifications, not placeholders): the `[tool.cognic.mcp]`-on-tool-pack validate tolerance (Task 3 Step 5); exact in-memory adapter class names + registry construction (Task 7 Step 1); the `agentos sign --bundle` positional / `agentos verify --trust-root` shape (Task 6 — argv now resolved to `COGNIC_SIGNING_KEY_PATH` env + `--trust-root <pub>`; confirm the `--bundle` positional via `agentos sign --help`); `iter_registered_pack_candidates` / `_server_id` / `CallToolRequest` body shape (Task 7 Step 2); evidence-pack tarball member names (Task 8 Step 1). Each is a read-the-real-code step inside its task with the fallback behavior named.
