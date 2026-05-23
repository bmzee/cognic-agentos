# Sprint 10 — Vault credential leasing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the real `VaultCredentialAdapter` per ADR-004 §25/§68/§102 (replaces the Sprint-8A fail-loud `KernelDefaultCredentialAdapter` sentinel) so sandboxes can mint short-TTL credentials at create + revoke at destroy. Closes the Vault-credential-leasing gap in the Phase-3 sandbox arc; Sprint 10.5 (scheduler) is the remaining Phase-3 dependency.

**Architecture:** A new `core/vault.py` carrying the high-level `lease_credential` / `revoke_credential` API + the `CredentialLease` / `VaultLeaseRequest` / `VaultLeaseActorRef` frozen dataclasses; a new `core/_vault_transport.py` carrying a shared `hvac.Client` + asyncio.to_thread façade consumed by BOTH the existing Sprint-1C `db/adapters/vault_adapter.py` AND the new `core/vault.py`; a real `VaultCredentialAdapter` in `sandbox/credentials.py` (currently a re-export shim); a Rego rule 6 in `policies/_default/sandbox.rego` enforcing per-tenant max credential TTL; 3 new `SandboxLifecycleEvent` values (`lease_minted` / `lease_revoked` / `lease_revoke_failed`); 4 new `SandboxRefusalReason` values (3 mint failures + 1 TTL cap).

**Tech Stack:** Python 3.12, hvac (HashiCorp Vault SDK; sync, wrapped in `asyncio.to_thread`), SQLAlchemy 2.0 async (Postgres + Oracle dual-dialect — not exercised by Sprint 10 directly but the adapter refactor must stay backward-compat), FastAPI, Pydantic v2, pytest + pytest-asyncio, `uv` for all commands, real `vault` server (for the env-gated Z2 integration proof).

---

## How to use this plan

- **Source spec:** `docs/superpowers/specs/2026-05-23-sprint-10-vault-credential-leasing-design.md` (committed `4ac96fa`). Section references below (`spec §N`) point there.
- **Single block.** Sprint 10 is a single linear arc (no Block A/B/C split). 12 tasks T2-Z3 (T1 = spec commit, already done at `4ac96fa`). If the sprint overruns ~2 work-units, the natural cut-line is at T6 (real `VaultCredentialAdapter` shipped; sandbox-side threading deferred) — but the BUILD_PLAN §10 budget should not require a split.
- **Stop-rule discipline.** Tasks touching `core/`, `sandbox/admission.py`, `sandbox/credentials.py`, `sandbox/backends/`, `db/adapters/vault_adapter.py`, or `policies/_default/sandbox.rego` are **critical-controls**: implement under `core-controls-engineer` + `/critical-module-mode`, and the commit step is **HALT-BEFORE-COMMIT** — present the diff for human critical-controls review; commit only after explicit approval. These tasks are tagged **[CC — HALT]**.
- **NO edits** to `core/audit.py`, `core/decision_history.py`, `core/canonical.py`, `core/chain_verifier.py`, or `compliance/iso42001/*`. Sprint 10 is a consumer of `SandboxLifecycleEvent` audit emission via the existing patterns; it does not modify the audit infrastructure itself.
- **Commands:** every command is `uv run …`. The gate ladder at commit time: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests` (full-tree) + the task's pytest scope; the full suite runs only at the explicit commit token per the gate-ladder doctrine.
- **Branch:** all work on `feat/sprint-10-vault-credential-leasing` (already created from `main@985264f`; the spec is committed there at `4ac96fa`).

### Planning-time design decisions (flag for the human before execution)

1. **Shared transport API surface — domain-shaped, NOT HTTP-shaped.** Spec §3.5 declares the `VaultTransport` API as `read/write/lease/revoke/health_check` (matching hvac's domain methods). The earlier brainstorm flirted with HTTP-shaped (`get/post/delete`); rejected because both consumers (Sprint-1C adapter + Sprint-10 `core/vault.py`) need the same domain operations and pushing HTTP-shape semantics to consumers would defeat the "one Vault discipline" goal.

2. **VaultAdapter refactor accepts `transport=None` for backward-compat.** Sprint-1C's `VaultAdapter.__init__(addr, token, namespace)` has any number of out-of-tree consumers (bank overlays, plugin packs). Sprint 10's refactor adds an **optional** `transport: VaultTransport | None = None` kwarg; default None lazily mints a transport internally. No existing caller breaks.

3. **VaultLeaseActorRef is in `core/vault.py`, NOT a new module.** Spec §3.1 declares the projection inline in `core/vault.py`. The projection IS NOT extracted into `core/_lease_audit.py` or similar — it's tightly coupled to `VaultLeaseRequest` and there's no other consumer.

4. **`requires_credentials=()` default everywhere.** Spec §4.1 `admit_policy()` extension uses `requires_credentials: list[VaultLeaseRequest] = ()` (empty tuple default). Every existing test that calls `admit_policy()` without the kwarg STAYS GREEN — zero regression on the Sprint-8A admission surface. Pin this with a backward-compat test in T7.

5. **NO `sandbox/session.py` module created.** Per spec §1 BUILD_PLAN doc-drift flag: BUILD_PLAN §10 names `sandbox/session.py` but no such module exists in the live tree. Sprint 10's "sandbox session integration" lands as:
   - Protocol extension on `SandboxBackend.create()` (in `sandbox/protocol.py`)
   - Implementation in `sandbox/backends/docker_sibling.py` + `sandbox/backends/kubernetes_pod.py`
   - NO new `sandbox/session.py` module

   The BUILD_PLAN line gets patched in Z3.

6. **Real-Vault Z2 proof — env-gated.** Z2 runs against a real `vault` binary + a test Vault server (HashiCorp `vault server -dev` is acceptable for dev/CI; bank deployments use prod Vault). Opt-in via `COGNIC_RUN_VAULT_INTEGRATION=1`. Fail-loud on missing `vault` binary OR unreachable server. Mirrors the Sprint 9.5 Z2 real-cosign proof pattern. The Z2 proof confirms (a) static-token auth works at the target Vault version; (b) `database/creds/<role>` returns the expected `{username, password}` shape; (c) revoke against a real lease succeeds + auto-expiry works as the safety net.

7. **CC gate promotion at Z1 — fresh coverage verification per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`.** All 3 promoted modules (`core/vault.py` + `core/_vault_transport.py` + `sandbox/credentials.py`) must reach 95/90 line/branch floor on fresh `coverage.json` from a full-suite `--cov-branch` run IN THE SAME Z1 commit; focused negative-path repair lands in the same commit if any module is below floor.

---

## File structure

### Created (NEW; ~6 files)

```
src/cognic_agentos/core/vault.py                              (T4 — CC)
src/cognic_agentos/core/_vault_transport.py                   (T2 — CC)
tests/unit/core/test_vault.py                                 (T4)
tests/unit/core/test_vault_transport.py                       (T2)
tests/unit/sandbox/test_credentials.py                        (T6)
tests/unit/sandbox/test_admit_credentials.py                  (T7)
tests/unit/sandbox/test_credential_lifecycle.py               (T10)
tests/unit/policies/test_sandbox_rego_credentials.py          (T8)
tests/unit/sandbox/test_lease_dataclass_landscape.py          (T4)
tests/integration/sandbox/test_real_vault_credential_lifecycle.py  (Z2 — env-gated)
```

### Modified (existing; ~9 files)

```
src/cognic_agentos/db/adapters/vault_adapter.py                (T3 — CC)
src/cognic_agentos/sandbox/credentials.py                     (T6 — CC, off-gate → on-gate)
src/cognic_agentos/sandbox/admission.py                       (T5 + T7 — CC)
src/cognic_agentos/sandbox/protocol.py                        (T9 — closed-enum extensions)
src/cognic_agentos/sandbox/audit.py                           (T9 — new payloads; NOT-CC per Doctrine F)
src/cognic_agentos/sandbox/backends/docker_sibling.py         (T10 — CC)
src/cognic_agentos/sandbox/backends/kubernetes_pod.py         (T10 — CC)
src/cognic_agentos/core/config.py                             (T2 + T4 + T8 — CC by core/ stop-rule)
policies/_default/sandbox.rego                                (T8 — stop-rule policy bundle)

tests/unit/db/test_vault_adapter.py                           (T3 — refactor-impact tests)
tests/unit/test_config.py                                     (T2 + T4 + T8 — new settings tests)
tests/unit/sandbox/test_admission_pipeline.py                 (T7 — backward-compat regression)
tests/unit/sandbox/test_audit.py                              (T9 — new payload tests)
tests/unit/sandbox/backends/test_docker_sibling_lifecycle.py  (T10 — create/destroy threading)
tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py  (T10 — create/destroy threading)
tests/unit/tools/test_check_critical_coverage.py              (Z1 — bump _EXPECTED_ENTRY_COUNT 81 → 84)

docs/BUILD_PLAN.md                                            (Z3 — patch §10 stale sandbox/session.py name + reflect +3 CC promotion)
docs/adrs/ADR-004-sandbox-primitive.md                        (Z3 — mark §25 + §68 + §102 Sprint 10 deferred-then-landed)
AGENTS.md                                                     (Z3 — mark sandbox/credentials.py promotion executed; add core/vault.py + core/_vault_transport.py to CC list)
tools/check_critical_coverage.py                              (Z1 — +3 entries; bump _EXPECTED_ENTRY_COUNT 81 → 84)
```

### Untouched (DO NOT MODIFY)

```
src/cognic_agentos/core/audit.py                              (audit infrastructure; consumer-only)
src/cognic_agentos/core/decision_history.py                   (audit infrastructure)
src/cognic_agentos/core/canonical.py                          (audit infrastructure)
src/cognic_agentos/core/chain_verifier.py                     (audit infrastructure)
src/cognic_agentos/compliance/iso42001/*                      (compliance scoring)
src/cognic_agentos/sandbox/checkpoint_store.py                (Sprint-8.5 VaultLeaseRef — DISTINCT dataclass per spec Q1; do NOT consolidate)
```

---

## Tasks

### Task T2: `core/_vault_transport.py` — shared hvac transport  [CC — HALT]

**Files:**
- Create: `src/cognic_agentos/core/_vault_transport.py`
- Create: `tests/unit/core/test_vault_transport.py`
- Modify: `src/cognic_agentos/core/config.py` (add `vault_http_timeout_s`, `vault_http_max_retries`)

- [ ] **Step 1: Write the failing test for VaultTransport construction + read**

Create `tests/unit/core/test_vault_transport.py`:

```python
"""Sprint 10 T2 — core/_vault_transport.py shared hvac transport."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings


def _settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        vault_addr="http://vault.test:8200",
        vault_token="test-token",
        vault_namespace=None,
        vault_http_timeout_s=10.0,
        vault_http_max_retries=3,
        **overrides,
    )  # type: ignore[call-arg]


def test_vault_transport_constructs_with_required_fields() -> None:
    """Bar T2 #1 — construct VaultTransport with addr + token + namespace + timeout + retries."""
    settings = _settings()
    transport = VaultTransport(
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
        vault_namespace=settings.vault_namespace,
        timeout_s=settings.vault_http_timeout_s,
        max_retries=settings.vault_http_max_retries,
    )
    assert transport is not None


async def test_vault_transport_read_delegates_to_hvac() -> None:
    """Bar T2 #2 — read(path) calls hvac.Client.secrets.kv.v2.read_secret_version
    via asyncio.to_thread, returns the secret payload."""
    settings = _settings()
    transport = VaultTransport(
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
        vault_namespace=settings.vault_namespace,
        timeout_s=settings.vault_http_timeout_s,
        max_retries=settings.vault_http_max_retries,
    )
    fake_response = {"data": {"data": {"key": "value"}}}
    with patch.object(transport, "_client", create=True) as mock_client:
        mock_client.read.return_value = fake_response
        result = await transport.read("secret/data/test")
    assert result == fake_response
```

- [ ] **Step 2: Run — verify failure (module missing)**

`uv run pytest tests/unit/core/test_vault_transport.py -q`
Expected: ImportError on `cognic_agentos.core._vault_transport`.

- [ ] **Step 3: Implement `core/_vault_transport.py`**

Create `src/cognic_agentos/core/_vault_transport.py`:

```python
"""Sprint 10 §2.1 — shared low-level Vault transport.

INTERNAL — not part of any documented public surface. Both
``db/adapters/vault_adapter.py::VaultAdapter`` AND
``core/vault.py::lease_credential`` consume this for one Vault
transport discipline (one shared ``hvac.Client``, one static-token
auth context, one retry policy, one asyncio.to_thread façade).

Wave-1 static-token authentication only — ``vault_token`` is
operator-pre-provided; no AppRole / Kubernetes / JWT-OIDC auth
flows (future work).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import hvac

from cognic_agentos.db.adapters.protocols import AdapterHealth

_LOG = logging.getLogger(__name__)


class VaultTransport:
    """Shared hvac.Client wrapper. See module docstring."""

    def __init__(
        self,
        *,
        vault_addr: str,
        vault_token: str | None,
        vault_namespace: str | None,
        timeout_s: float,
        max_retries: int,
    ) -> None:
        if not vault_addr:
            raise ValueError("VaultTransport requires vault_addr; got empty/None")
        self._addr = vault_addr.rstrip("/")
        self._token = vault_token
        self._namespace = vault_namespace
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._client: hvac.Client | None = None

    def _ensure_client(self) -> hvac.Client:
        if self._client is None:
            self._client = hvac.Client(
                url=self._addr,
                token=self._token,
                namespace=self._namespace,
                timeout=self._timeout_s,
            )
        return self._client

    async def read(self, path: str) -> dict[str, Any]:
        def _read() -> dict[str, Any]:
            return self._ensure_client().read(path)
        return await asyncio.to_thread(_read)

    async def write(self, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        def _write() -> dict[str, Any] | None:
            return self._ensure_client().write(path, **body)
        return await asyncio.to_thread(_write)

    async def lease(self, path: str, ttl_s: int) -> dict[str, Any]:
        """Mint a dynamic-secret lease at ``path`` with the requested TTL.
        Returns the raw hvac response (caller normalises shape)."""
        def _lease() -> dict[str, Any]:
            return self._ensure_client().write(
                path, **{"ttl": f"{ttl_s}s"}
            )
        return await asyncio.to_thread(_lease)

    async def revoke(self, lease_id: str) -> None:
        def _revoke() -> None:
            self._ensure_client().sys.revoke_lease(lease_id)
        await asyncio.to_thread(_revoke)

    async def health_check(self) -> AdapterHealth:
        def _health() -> bool:
            try:
                return self._ensure_client().sys.is_initialized()
            except Exception:
                return False
        ok = await asyncio.to_thread(_health)
        return AdapterHealth(status="ok" if ok else "unreachable")
```

Add settings to `src/cognic_agentos/core/config.py` (inside the LLM-adjacent settings block or appropriate Vault section):

```python
vault_http_timeout_s: float = Field(
    default=10.0,
    gt=0.0,
    le=60.0,
    description="Sprint 10 — per-request timeout for VaultTransport calls (seconds).",
)
vault_http_max_retries: int = Field(
    default=3,
    ge=0,
    le=10,
    description="Sprint 10 — bounded exponential-backoff retry count for transient Vault failures.",
)
```

- [ ] **Step 4: Run — verify pass**

`uv run pytest tests/unit/core/test_vault_transport.py tests/unit/test_config.py -q -k "vault_http"`
Expected: GREEN on both files.

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — core/ stop-rule review**

`core/_vault_transport.py` is in `core/` per AGENTS.md L48; halt-before-commit applies. Present the diff; map watchpoints (Wave-1 static-token only; NO refresh_token; hvac wrapped via asyncio.to_thread; timeout + retries bounded settings). Commit only after approval:

```bash
git add src/cognic_agentos/core/_vault_transport.py \
        src/cognic_agentos/core/config.py \
        tests/unit/core/test_vault_transport.py \
        tests/unit/test_config.py
git commit -m "feat(sprint-10): core/_vault_transport.py shared hvac transport (T2)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T3: `db/adapters/vault_adapter.py` refactor to consume shared transport  [CC — HALT]

**Files:**
- Modify: `src/cognic_agentos/db/adapters/vault_adapter.py`
- Modify: `tests/unit/db/test_vault_adapter.py` (refactor-impact + backward-compat tests)

- [ ] **Step 1: Write the failing test for transport injection + backward-compat**

Append to `tests/unit/db/test_vault_adapter.py`:

```python
def test_vault_adapter_accepts_transport_kwarg() -> None:
    """T3 — VaultAdapter.__init__ accepts an optional transport= kwarg."""
    from cognic_agentos.core._vault_transport import VaultTransport
    from cognic_agentos.db.adapters.vault_adapter import VaultAdapter

    transport = VaultTransport(
        vault_addr="http://vault.test:8200",
        vault_token="t",
        vault_namespace=None,
        timeout_s=10.0,
        max_retries=3,
    )
    adapter = VaultAdapter(
        addr="http://vault.test:8200",
        token="t",
        namespace=None,
        transport=transport,
    )
    assert adapter._transport is transport  # type: ignore[attr-defined]


def test_vault_adapter_backward_compat_no_transport_kwarg() -> None:
    """T3 — old 3-arg construction still works (lazily mints transport)."""
    from cognic_agentos.db.adapters.vault_adapter import VaultAdapter

    adapter = VaultAdapter(
        addr="http://vault.test:8200",
        token="t",
        namespace=None,
    )
    # Internal transport lazily minted on first call; constructor stays
    # side-effect-free per the Sprint-1C contract.
    assert adapter is not None


def test_shared_transport_actually_shared() -> None:
    """T3 — two VaultAdapter instances built with the SAME VaultTransport
    see the same underlying hvac.Client (proves the shared transport is
    genuinely shared, not just structurally typed)."""
    from cognic_agentos.core._vault_transport import VaultTransport
    from cognic_agentos.db.adapters.vault_adapter import VaultAdapter

    transport = VaultTransport(
        vault_addr="http://vault.test:8200",
        vault_token="t",
        vault_namespace=None,
        timeout_s=10.0,
        max_retries=3,
    )
    a1 = VaultAdapter(addr="x", token="t", namespace=None, transport=transport)
    a2 = VaultAdapter(addr="x", token="t", namespace=None, transport=transport)
    assert a1._transport is a2._transport  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run — verify failure**

`uv run pytest tests/unit/db/test_vault_adapter.py -q -k "transport or backward_compat or shared"`
Expected: FAIL.

- [ ] **Step 3: Refactor `db/adapters/vault_adapter.py`**

Update `VaultAdapter.__init__` to accept the optional `transport` kwarg + delegate all hvac calls through it. Sketch:

```python
class VaultAdapter:
    driver = "vault"

    def __init__(
        self,
        addr: str | None,
        token: str | None,
        namespace: str | None,
        *,
        transport: "VaultTransport | None" = None,  # NEW Sprint 10 T3
    ) -> None:
        # ... existing validation ...
        self._addr = addr.rstrip("/")
        self._token = token
        self._namespace = namespace
        self._transport = transport  # may be None; lazily built

    def _ensure_transport(self) -> "VaultTransport":
        if self._transport is None:
            # Lazy default — preserves Sprint-1C side-effect-free constructor
            from cognic_agentos.core._vault_transport import VaultTransport
            self._transport = VaultTransport(
                vault_addr=self._addr,
                vault_token=self._token,
                vault_namespace=self._namespace,
                timeout_s=10.0,        # adapter-side default; not Settings-driven
                max_retries=3,
            )
        return self._transport

    async def read(self, path: str) -> dict[str, Any]:
        return await self._ensure_transport().read(path)

    async def write(self, path: str, value: dict[str, Any]) -> None:
        await self._ensure_transport().write(path, value)

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        raw = await self._ensure_transport().lease(path, ttl_s)
        return SecretLease(
            lease_id=raw["lease_id"],
            ttl_s=raw.get("lease_duration", ttl_s),
            value=raw.get("data", {}),
        )

    async def revoke(self, lease_id: str) -> None:
        await self._ensure_transport().revoke(lease_id)

    async def health_check(self) -> AdapterHealth:
        return await self._ensure_transport().health_check()
```

Delete the lazy `_ensure_client` + the inline `hvac.Client` construction — they live in the transport now.

- [ ] **Step 4: Run — verify pass + no regression**

`uv run pytest tests/unit/db/ tests/unit/core/test_vault_transport.py -q`
Expected: GREEN; the existing test_vault_adapter.py tests still pass (backward-compat preserved).

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — db/adapters/ CC review**

`db/adapters/vault_adapter.py` is ON the gate (Sprint 1C). Present the diff; map watchpoints (~50-80 LoC delta; public API unchanged; backward-compat for 3-arg constructor; shared transport pin via the `_transport is _transport` regression). Commit only after approval:

```bash
git add src/cognic_agentos/db/adapters/vault_adapter.py \
        tests/unit/db/test_vault_adapter.py
git commit -m "refactor(sprint-10): VaultAdapter delegates to shared VaultTransport (T3)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T4: `core/vault.py` — VaultLeaseActorRef + VaultLeaseRequest + CredentialLease + lease_credential + revoke_credential  [CC — HALT]

**Files:**
- Create: `src/cognic_agentos/core/vault.py`
- Create: `tests/unit/core/test_vault.py`
- Create: `tests/unit/sandbox/test_lease_dataclass_landscape.py`

- [ ] **Step 1: Write failing tests for the dataclasses + the lease/revoke API**

Create `tests/unit/core/test_vault.py`:

```python
"""Sprint 10 T4 — core/vault.py public API + exception mapping."""

from __future__ import annotations

import datetime as _dt
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseActorRef,
    VaultLeaseRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
    lease_credential,
    revoke_credential,
)


def _actor_ref() -> VaultLeaseActorRef:
    return VaultLeaseActorRef(actor_subject="test-user", actor_type="human")


def _request() -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path="database/creds/payment-readonly",
        ttl_s=900,
        tenant_id="tenant-acme",
        actor_ref=_actor_ref(),
        scope_label="payment-readonly-test",
    )


def test_vault_lease_actor_ref_frozen() -> None:
    """T4 #1 — VaultLeaseActorRef is frozen + slots."""
    ref = _actor_ref()
    with pytest.raises(Exception):  # noqa: BLE001 — frozen-dataclass attribute set
        ref.actor_subject = "other"  # type: ignore[misc]


def test_vault_lease_request_frozen_with_actor_ref() -> None:
    """T4 #2 — VaultLeaseRequest carries actor_ref (NOT actor); architectural arrow preserved."""
    req = _request()
    assert req.actor_ref.actor_subject == "test-user"
    assert req.actor_ref.actor_type == "human"


def test_vault_lease_request_validates_traversal_in_secret_path() -> None:
    """T4 #3 — VaultLeaseRequest rejects path traversal at construction."""
    with pytest.raises(ValueError, match="secret_path"):
        VaultLeaseRequest(
            secret_path="database/creds/../etc/passwd",
            ttl_s=900,
            tenant_id="tenant-acme",
            actor_ref=_actor_ref(),
            scope_label="bad",
        )


async def test_lease_credential_returns_credential_lease(monkeypatch) -> None:
    """T4 #4 — happy path: transport.lease returns vault response; lease_credential
    composes CredentialLease."""
    transport = AsyncMock(spec=VaultTransport)
    transport.lease.return_value = {
        "lease_id": "lease-abc-123",
        "lease_duration": 900,
        "data": {"username": "u", "password": "p"},
    }
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    lease = await lease_credential(_request(), transport=transport, settings=settings)
    assert isinstance(lease, CredentialLease)
    assert lease.lease_id == "lease-abc-123"
    assert lease.token == {"username": "u", "password": "p"}
    assert lease.ttl_s_granted == 900
    assert lease.minted_at.tzinfo is not None  # UTC-aware per Sprint-2 R3


@pytest.mark.parametrize(
    "exc_type,error,expected_mapped_exc",
    [
        ("Forbidden", "permission denied", VaultAuthDenied),
        ("InvalidPath", "path not found", VaultPathNotFound),
        ("InvalidRequest", "5xx error", VaultUnavailable),
    ],
)
async def test_lease_credential_maps_hvac_exceptions(
    exc_type: str, error: str, expected_mapped_exc: type[Exception]
) -> None:
    """T4 #5 — closed-enum-aligned exception mapping per spec §7.1."""
    import hvac.exceptions

    transport = AsyncMock(spec=VaultTransport)
    raised = getattr(hvac.exceptions, exc_type)(error)
    transport.lease.side_effect = raised
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    with pytest.raises(expected_mapped_exc):
        await lease_credential(_request(), transport=transport, settings=settings)
```

Create `tests/unit/sandbox/test_lease_dataclass_landscape.py`:

```python
"""Sprint 10 T4 — pin the three-lease-dataclass landscape per spec §2.3."""

from __future__ import annotations


def test_three_distinct_lease_dataclasses_exist() -> None:
    """The three lease-shaped dataclasses MUST stay distinct types
    (per spec §2.3 design call Q1 = B1)."""
    from cognic_agentos.core.vault import CredentialLease
    from cognic_agentos.db.adapters.protocols import SecretLease
    from cognic_agentos.sandbox.checkpoint_store import VaultLeaseRef

    assert CredentialLease is not SecretLease
    assert CredentialLease is not VaultLeaseRef
    assert SecretLease is not VaultLeaseRef
```

- [ ] **Step 2: Run — verify failure**

`uv run pytest tests/unit/core/test_vault.py tests/unit/sandbox/test_lease_dataclass_landscape.py -q`
Expected: ImportError on `cognic_agentos.core.vault`.

- [ ] **Step 3: Implement `src/cognic_agentos/core/vault.py`**

Per spec §3.1 + §3.2 + §3.3 + §7.1. Include the closed-enum exception types `VaultUnavailable`, `VaultPathNotFound`, `VaultAuthDenied`, `VaultProtocolError`; the `VaultLeaseActorRef` + `VaultLeaseRequest` + `CredentialLease` frozen dataclasses; and the `lease_credential` + `revoke_credential` async functions with explicit hvac exception mapping.

Key shape (per spec):

```python
@dataclass(frozen=True, slots=True)
class VaultLeaseActorRef:
    actor_subject: str
    actor_type: Literal["human", "service"]


@dataclass(frozen=True, slots=True)
class VaultLeaseRequest:
    secret_path: str
    ttl_s: int
    tenant_id: str
    actor_ref: VaultLeaseActorRef
    scope_label: str

    def __post_init__(self) -> None:
        # Validation: non-empty path, no traversal, ttl_s > 0, scope_label ≤ 64.
        if not self.secret_path or ".." in Path(self.secret_path).parts:
            raise ValueError(f"secret_path invalid: {self.secret_path!r}")
        # ... rest of validation
```

- [ ] **Step 4: Run — verify pass**

`uv run pytest tests/unit/core/test_vault.py tests/unit/sandbox/test_lease_dataclass_landscape.py -q`
Expected: GREEN.

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — core/ stop-rule review**

`core/vault.py` is in `core/`; halt-before-commit applies. Present the diff; map watchpoints (VaultLeaseActorRef is core-owned projection, NOT importing portal/rbac/Actor — architectural arrow check; three-dataclass landscape pinned by test; 4 exception classes mapping hvac errors to closed-enum-aligned types per spec §7.1; token never persisted on chain rows). Commit only after approval:

```bash
git add src/cognic_agentos/core/vault.py \
        tests/unit/core/test_vault.py \
        tests/unit/sandbox/test_lease_dataclass_landscape.py
git commit -m "feat(sprint-10): core/vault.py VaultLeaseRequest + CredentialLease + lease/revoke API (T4)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T5: `CredentialAdapter` Protocol extension  [CC — HALT]

**Files:**
- Modify: `src/cognic_agentos/sandbox/admission.py` (extend `CredentialAdapter` Protocol; extend `KernelDefaultCredentialAdapter` with fail-loud `mint_lease` / `revoke_lease`)
- Modify: `tests/unit/sandbox/test_credential_adapter_stub.py` (extend fail-loud assertions)

- [ ] **Step 1: Write failing tests for the Protocol extension**

Append to `tests/unit/sandbox/test_credential_adapter_stub.py`:

```python
async def test_kernel_default_mint_lease_raises_not_implemented() -> None:
    """T5 — KernelDefaultCredentialAdapter.mint_lease MUST fail loud per
    ADR-004 §102 (Sprint 10 ships the real VaultCredentialAdapter)."""
    from cognic_agentos.core.vault import VaultLeaseActorRef, VaultLeaseRequest
    from cognic_agentos.sandbox.admission import KernelDefaultCredentialAdapter

    sentinel = KernelDefaultCredentialAdapter()
    request = VaultLeaseRequest(
        secret_path="database/creds/x",
        ttl_s=900,
        tenant_id="t",
        actor_ref=VaultLeaseActorRef(actor_subject="u", actor_type="human"),
        scope_label="s",
    )
    with pytest.raises(NotImplementedError, match="Sprint 10"):
        await sentinel.mint_lease(request)


async def test_kernel_default_revoke_lease_raises_not_implemented() -> None:
    """T5 — KernelDefaultCredentialAdapter.revoke_lease MUST fail loud."""
    from cognic_agentos.sandbox.admission import KernelDefaultCredentialAdapter

    sentinel = KernelDefaultCredentialAdapter()
    with pytest.raises(NotImplementedError, match="Sprint 10"):
        await sentinel.revoke_lease("any-lease-id")
```

- [ ] **Step 2: Run — verify failure**

`uv run pytest tests/unit/sandbox/test_credential_adapter_stub.py -q`
Expected: FAIL — methods don't exist on sentinel.

- [ ] **Step 3: Extend `CredentialAdapter` Protocol + sentinel**

In `src/cognic_agentos/sandbox/admission.py`:

```python
@runtime_checkable
class CredentialAdapter(Protocol):
    async def fetch_secret(self, path: str) -> str | None: ...

    # Sprint 10 T5 — Protocol extension per ADR-004 §102 Q4 LOCK.
    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease: ...
    async def revoke_lease(self, lease_id: str) -> None: ...


class KernelDefaultCredentialAdapter:
    """... existing docstring ..."""

    async def fetch_secret(self, path: str) -> str | None:
        raise NotImplementedError(
            "KernelDefaultCredentialAdapter is the Sprint-8A fail-loud sentinel. "
            "Wire a real CredentialAdapter (Sprint 10 VaultCredentialAdapter) "
            "in create_app() before any pack declares vault_path."
        )

    # Sprint 10 T5 — fail-loud sentinel methods for the Protocol extension.
    async def mint_lease(self, request: "VaultLeaseRequest") -> "CredentialLease":
        raise NotImplementedError(
            "KernelDefaultCredentialAdapter is the Sprint-8A fail-loud sentinel "
            "for the Protocol; Sprint 10 ships the real VaultCredentialAdapter "
            "in sandbox/credentials.py. Wire it in create_app() before any "
            "pack/sandbox declares requires_credentials."
        )

    async def revoke_lease(self, lease_id: str) -> None:
        raise NotImplementedError(
            "KernelDefaultCredentialAdapter is the Sprint-8A fail-loud sentinel "
            "for the Protocol; Sprint 10 ships the real VaultCredentialAdapter "
            "in sandbox/credentials.py. Wire it in create_app() before any "
            "pack/sandbox declares requires_credentials."
        )
```

- [ ] **Step 4: Run — verify pass + sentinel-check regression still works**

`uv run pytest tests/unit/sandbox/test_credential_adapter_stub.py tests/unit/sandbox/test_admission_pipeline.py -q`
Expected: GREEN.

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — sandbox/admission.py CC review**

`sandbox/admission.py` is ON the gate. Present the diff; map watchpoints (Protocol extension is structural — backward-compat for real adapters; sentinel fails LOUD on both new methods; the isinstance check in admit_policy still correctly distinguishes sentinel from real adapter). Commit only after approval:

```bash
git add src/cognic_agentos/sandbox/admission.py \
        tests/unit/sandbox/test_credential_adapter_stub.py
git commit -m "feat(sprint-10): CredentialAdapter Protocol +mint_lease/+revoke_lease; fail-loud sentinel (T5)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T6: `sandbox/credentials.py` real `VaultCredentialAdapter`  [CC — HALT; off-gate → on-gate promotion target]

**Files:**
- Modify: `src/cognic_agentos/sandbox/credentials.py` (replace re-export shim with real adapter)
- Create: `tests/unit/sandbox/test_credentials.py`

- [ ] **Step 1: Write failing tests for the real adapter**

Create `tests/unit/sandbox/test_credentials.py`:

```python
"""Sprint 10 T6 — sandbox/credentials.py real VaultCredentialAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseActorRef,
    VaultLeaseRequest,
)
from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)
from cognic_agentos.sandbox.credentials import VaultCredentialAdapter


def _request() -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path="database/creds/x",
        ttl_s=900,
        tenant_id="t",
        actor_ref=VaultLeaseActorRef(actor_subject="u", actor_type="human"),
        scope_label="s",
    )


def test_vault_credential_adapter_structurally_conforms_to_protocol() -> None:
    """T6 — real adapter structurally implements the extended Protocol."""
    transport = AsyncMock(spec=VaultTransport)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    adapter = VaultCredentialAdapter(transport=transport, settings=settings)
    assert isinstance(adapter, CredentialAdapter)


def test_vault_credential_adapter_distinct_from_sentinel() -> None:
    """T6 — real adapter is NOT the sentinel; isinstance check in
    admit_policy still distinguishes them."""
    transport = AsyncMock(spec=VaultTransport)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    adapter = VaultCredentialAdapter(transport=transport, settings=settings)
    assert not isinstance(adapter, KernelDefaultCredentialAdapter)


async def test_mint_lease_delegates_to_lease_credential() -> None:
    """T6 — VaultCredentialAdapter.mint_lease is a thin wrapper over
    core.vault.lease_credential."""
    from datetime import UTC, datetime, timedelta

    transport = AsyncMock(spec=VaultTransport)
    transport.lease.return_value = {
        "lease_id": "L-1",
        "lease_duration": 900,
        "data": {"k": "v"},
    }
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    adapter = VaultCredentialAdapter(transport=transport, settings=settings)
    lease = await adapter.mint_lease(_request())
    assert isinstance(lease, CredentialLease)
    assert lease.lease_id == "L-1"


async def test_revoke_lease_delegates_to_revoke_credential() -> None:
    """T6 — VaultCredentialAdapter.revoke_lease delegates to
    core.vault.revoke_credential."""
    transport = AsyncMock(spec=VaultTransport)
    transport.revoke.return_value = None
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    adapter = VaultCredentialAdapter(transport=transport, settings=settings)
    await adapter.revoke_lease("lease-id")
    transport.revoke.assert_awaited_once_with("lease-id")
```

- [ ] **Step 2: Run — verify failure**

`uv run pytest tests/unit/sandbox/test_credentials.py -q`
Expected: ImportError on `VaultCredentialAdapter` (the shim doesn't export it).

- [ ] **Step 3: Implement `src/cognic_agentos/sandbox/credentials.py`**

Replace the shim contents with the real adapter while preserving the re-exports:

```python
"""Sprint 10 T6 — VaultCredentialAdapter.

PROMOTED from off-gate re-export shim (Sprint 8A) to ON the durable
critical-controls gate per AGENTS.md L188's explicit promise.

Implements the extended CredentialAdapter Protocol declared in
sandbox/admission.py. The real adapter delegates to core.vault for the
substantive lease/revoke logic; this module wires the Protocol surface
+ dependency injection (transport + settings).

The Sprint-8A re-exports (CredentialAdapter, KernelDefaultCredentialAdapter)
are PRESERVED — every consumer that imports from this path stays
backward-compat.
"""

from __future__ import annotations

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseRequest,
    lease_credential,
    revoke_credential,
)
from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)


class VaultCredentialAdapter:
    """Real CredentialAdapter implementation per ADR-004 §102 Q4 LOCK.

    Sprint 10 ships this as the replacement for the Sprint-8A fail-loud
    KernelDefaultCredentialAdapter sentinel. Banks wire this in
    create_app() with a configured VaultTransport.
    """

    def __init__(self, *, transport: VaultTransport, settings: Settings) -> None:
        self._transport = transport
        self._settings = settings

    async def fetch_secret(self, path: str) -> str | None:
        # Read a secret KV value (e.g. for trust-root paths).
        # Returns the raw secret-value string if present; None if 404.
        try:
            response = await self._transport.read(path)
        except Exception:
            return None
        data = response.get("data") if isinstance(response, dict) else None
        if isinstance(data, dict) and "value" in data:
            return str(data["value"])
        return None

    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        return await lease_credential(
            request,
            transport=self._transport,
            settings=self._settings,
        )

    async def revoke_lease(self, lease_id: str) -> None:
        await revoke_credential(lease_id, transport=self._transport)


__all__ = [
    "CredentialAdapter",
    "KernelDefaultCredentialAdapter",
    "VaultCredentialAdapter",
]
```

- [ ] **Step 4: Run — verify pass**

`uv run pytest tests/unit/sandbox/test_credentials.py tests/unit/sandbox/test_credential_adapter_stub.py -q`
Expected: GREEN.

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — sandbox/credentials.py CC review**

This module is **PROMOTED off-gate → on-gate** at the Z1 commit; this T6 commit lands the production code that will be promoted. Present the diff; map watchpoints (re-exports preserved → no breaking change for Sprint-8A imports; isinstance discrimination between real adapter + sentinel still works; structural Protocol conformance pinned by test). Commit only after approval:

```bash
git add src/cognic_agentos/sandbox/credentials.py \
        tests/unit/sandbox/test_credentials.py
git commit -m "feat(sprint-10): real VaultCredentialAdapter implementing extended Protocol (T6)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T7: `admit_policy()` signature + Rego input + Actor→VaultLeaseActorRef projection  [CC — HALT]

**Files:**
- Modify: `src/cognic_agentos/sandbox/admission.py` (extend `admit_policy()`)
- Create: `tests/unit/sandbox/test_admit_credentials.py`
- Modify: `tests/unit/sandbox/test_admission_pipeline.py` (backward-compat regression for default `requires_credentials=()`)

- [ ] **Step 1: Write failing tests for the admission threading**

Create `tests/unit/sandbox/test_admit_credentials.py`:

```python
"""Sprint 10 T7 — admit_policy() requires_credentials threading + Rego input."""

from __future__ import annotations

import pytest

from cognic_agentos.core.vault import VaultLeaseActorRef, VaultLeaseRequest
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.admission import (
    KernelDefaultCredentialAdapter,
    admit_policy,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused


# ... fixtures for catalog, rego_engine, settings, policy, pack_context ...


async def test_admit_policy_default_kwarg_backward_compat(
    valid_policy,
    valid_pack_context,
    catalog,
    rego_engine,
    settings,
) -> None:
    """T7 — admit_policy() with default requires_credentials=() stays
    backward-compat for Sprint-8A callers (zero-impact at the call site)."""
    actor = Actor(subject="u", tenant_id="t", scopes=frozenset(), actor_type="human")
    real_adapter = SomeNonSentinelAdapter()  # any non-sentinel
    # Should NOT raise:
    await admit_policy(
        valid_policy,
        tenant_id="t",
        actor=actor,
        pack_context=valid_pack_context,
        catalog=catalog,
        credential_adapter=real_adapter,
        rego_engine=rego_engine,
        settings=settings,
        # NO requires_credentials kwarg — default ()
    )


async def test_admit_policy_refuses_when_credentials_requested_with_sentinel_adapter(
    valid_policy,
    valid_pack_context,
    catalog,
    rego_engine,
    settings,
) -> None:
    """T7 — when requires_credentials is non-empty AND the wired adapter
    is the fail-loud sentinel, admit_policy refuses with the existing
    sandbox_credential_adapter_not_configured reason."""
    actor = Actor(subject="u", tenant_id="t", scopes=frozenset(), actor_type="human")
    sentinel = KernelDefaultCredentialAdapter()
    request = VaultLeaseRequest(
        secret_path="database/creds/x",
        ttl_s=900,
        tenant_id="t",
        actor_ref=VaultLeaseActorRef(actor_subject="u", actor_type="human"),
        scope_label="s",
    )
    with pytest.raises(SandboxLifecycleRefused) as excinfo:
        await admit_policy(
            valid_policy,
            tenant_id="t",
            actor=actor,
            pack_context=valid_pack_context,
            catalog=catalog,
            credential_adapter=sentinel,
            rego_engine=rego_engine,
            settings=settings,
            requires_credentials=[request],
        )
    assert excinfo.value.reason == "sandbox_credential_adapter_not_configured"


async def test_admit_policy_threads_requires_credentials_into_rego_input(
    valid_policy,
    valid_pack_context,
    catalog,
    real_credential_adapter,
    captured_rego_inputs,  # fixture that captures the rego_engine.evaluate input dict
    settings,
) -> None:
    """T7 — the Rego input dict gains a top-level requires_credentials key
    with per-request {secret_path, ttl_s, scope_label} shape (NOT including
    actor/tenant — those are top-level for cross-tenant matching)."""
    actor = Actor(subject="u", tenant_id="t", scopes=frozenset(), actor_type="human")
    request = VaultLeaseRequest(
        secret_path="database/creds/x",
        ttl_s=900,
        tenant_id="t",
        actor_ref=VaultLeaseActorRef(actor_subject="u", actor_type="human"),
        scope_label="s",
    )
    await admit_policy(
        valid_policy,
        tenant_id="t",
        actor=actor,
        pack_context=valid_pack_context,
        catalog=catalog,
        credential_adapter=real_credential_adapter,
        rego_engine=captured_rego_inputs.engine,
        settings=settings,
        requires_credentials=[request],
    )
    rego_input = captured_rego_inputs.last_input
    assert "requires_credentials" in rego_input
    assert rego_input["requires_credentials"] == [
        {
            "secret_path": "database/creds/x",
            "ttl_s": 900,
            "scope_label": "s",
        }
    ]


async def test_admit_policy_refuses_cross_tenant_request_at_construction() -> None:
    """T7 — VaultLeaseRequest with tenant_id != actor.tenant_id is refused
    at the call site (the admit_policy boundary owns this check;
    VaultLeaseRequest itself cannot per the architectural-arrow contract)."""
    actor = Actor(subject="u", tenant_id="tenant-acme", scopes=frozenset(), actor_type="human")
    bad_request = VaultLeaseRequest(
        secret_path="database/creds/x",
        ttl_s=900,
        tenant_id="tenant-OTHER",  # CROSS-TENANT
        actor_ref=VaultLeaseActorRef(actor_subject="u", actor_type="human"),
        scope_label="s",
    )
    # Implementation: admit_policy raises SandboxLifecycleRefused with reason
    # sandbox_credential_request_tenant_mismatch (NEW reason — included in T9).
    # OR raise ValueError pre-admission. Decide at implementation time.
    # (Spec leaves this open; pick one path + pin the test.)
```

- [ ] **Step 2: Run — verify failure**

`uv run pytest tests/unit/sandbox/test_admit_credentials.py -q`
Expected: FAIL.

- [ ] **Step 3: Extend `admit_policy()`**

In `src/cognic_agentos/sandbox/admission.py`:

```python
async def admit_policy(
    policy: SandboxPolicy,
    *,
    tenant_id: str,
    actor: Actor,
    pack_context: PackAdmissionContext,
    catalog: CatalogProtocol,
    credential_adapter: CredentialAdapter,
    rego_engine: OPAEngine,
    settings: Settings,
    requires_credentials: list[VaultLeaseRequest] = (),  # NEW Sprint 10
) -> None:
    # ... existing Stage-1 + Stage-2 logic ...

    # NEW Sprint 10 — Step Nx: if requires_credentials is non-empty,
    # validate consistency + refuse if sentinel adapter wired.
    if requires_credentials:
        # Cross-tenant check at the kernel boundary (the request itself
        # cannot enforce this per the architectural-arrow contract).
        for req in requires_credentials:
            if req.tenant_id != actor.tenant_id:
                raise SandboxLifecycleRefused(
                    reason="sandbox_credential_request_tenant_mismatch",
                    detail=f"tenant_id={req.tenant_id} != actor.tenant_id={actor.tenant_id}",
                )

        # Sentinel adapter check — fail-closed if any lease is requested.
        if isinstance(credential_adapter, KernelDefaultCredentialAdapter):
            raise SandboxLifecycleRefused(
                reason="sandbox_credential_adapter_not_configured",
                detail="requires_credentials is non-empty but the wired adapter is the Sprint-8A fail-loud sentinel",
            )

    # ... existing Stage-2 rego eval — thread requires_credentials into input dict ...
    rego_input = {
        # ... existing fields ...
        "requires_credentials": [
            {
                "secret_path": req.secret_path,
                "ttl_s": req.ttl_s,
                "scope_label": req.scope_label,
            }
            for req in requires_credentials
        ],
    }
    # ... evaluate rego ...
```

NOTE: `sandbox_credential_request_tenant_mismatch` is the 5th Sprint-10 `SandboxRefusalReason` value enumerated in spec §6.1 (21 → 26 net). T7 implements the kernel-boundary check that raises it; T9 extends the `SandboxRefusalReason` Literal to include it alongside the other 4 Sprint-10 values.

- [ ] **Step 4: Run — verify pass**

`uv run pytest tests/unit/sandbox/test_admit_credentials.py tests/unit/sandbox/test_admission_pipeline.py -q`
Expected: GREEN; backward-compat tests still pass.

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — sandbox/admission.py CC review**

`sandbox/admission.py` is ON the gate. Present the diff; map watchpoints (default `()` kwarg backward-compat; cross-tenant check at the kernel boundary; sentinel-adapter refusal preserves Sprint-8A reason; Rego input dict gains top-level `requires_credentials` key; NEW `sandbox_credential_request_tenant_mismatch` reason flagged for T9 inclusion). Commit only after approval:

```bash
git add src/cognic_agentos/sandbox/admission.py \
        tests/unit/sandbox/test_admit_credentials.py \
        tests/unit/sandbox/test_admission_pipeline.py
git commit -m "feat(sprint-10): admit_policy threads requires_credentials + Rego input (T7)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T8: `policies/_default/sandbox.rego` rule 6 + TTL cap  [CC — HALT; stop-rule policy bundle]

**Files:**
- Modify: `policies/_default/sandbox.rego` (add rule 6)
- Create: `tests/unit/policies/test_sandbox_rego_credentials.py`
- Modify: `src/cognic_agentos/core/config.py` (add `sandbox_kernel_default_max_credential_ttl_s`)

- [ ] **Step 1: Write failing tests for the TTL cap rule**

Create `tests/unit/policies/test_sandbox_rego_credentials.py`:

```python
"""Sprint 10 T8 — sandbox.rego rule 6 — per-tenant max credential TTL."""

from __future__ import annotations

import pytest

from cognic_agentos.core.opa import OPAEngine  # or wherever Rego eval lives
from cognic_agentos.core.config import Settings


def _input_with_credential_ttl(ttl_s: int, tenant_overlay_max: int | None = None) -> dict:
    """Build a Rego input dict with one credential request."""
    return {
        "policy": {...},  # minimal valid policy shape
        "tenant": {
            "overlay": {"max_credential_ttl_s": tenant_overlay_max} if tenant_overlay_max else {},
        },
        "kernel_default": {"max_credential_ttl_s": 900},
        "requires_credentials": [{
            "secret_path": "database/creds/x",
            "ttl_s": ttl_s,
            "scope_label": "s",
        }],
        # ... other required input fields per existing sandbox.rego shape ...
    }


def test_rule_6_admits_when_ttl_under_kernel_default() -> None:
    """T8 #1 — credential request with ttl_s ≤ kernel default cap → admit."""
    engine = OPAEngine.load("policies/_default/sandbox.rego")
    result = engine.evaluate("data.cognic.sandbox.admit", _input_with_credential_ttl(600))
    assert result["allow"] is True
    assert "sandbox_credential_ttl_exceeds_tenant_max" not in result.get("deny", [])


def test_rule_6_refuses_when_ttl_exceeds_kernel_default() -> None:
    """T8 #2 — credential request with ttl_s > kernel default cap → deny."""
    engine = OPAEngine.load("policies/_default/sandbox.rego")
    result = engine.evaluate("data.cognic.sandbox.admit", _input_with_credential_ttl(7200))
    assert result["allow"] is False
    assert "sandbox_credential_ttl_exceeds_tenant_max" in result.get("deny", [])


def test_rule_6_respects_tenant_overlay() -> None:
    """T8 #3 — tenant overlay raises the cap above kernel default."""
    engine = OPAEngine.load("policies/_default/sandbox.rego")
    result = engine.evaluate(
        "data.cognic.sandbox.admit",
        _input_with_credential_ttl(1800, tenant_overlay_max=3600),
    )
    assert result["allow"] is True


def test_rule_6_pure_rego_type_check_defense() -> None:
    """T8 #4 — Sprint-8A T11 R2-R3 defense-in-depth: rule 6 is PURE Rego;
    malformed type at the input slot is REFUSED (NOT NPE'd)."""
    engine = OPAEngine.load("policies/_default/sandbox.rego")
    bad_input = _input_with_credential_ttl(600)
    bad_input["requires_credentials"][0]["ttl_s"] = "not-an-int"  # malformed shape
    result = engine.evaluate("data.cognic.sandbox.admit", bad_input)
    assert result["allow"] is False
```

- [ ] **Step 2: Run — verify failure**

`uv run pytest tests/unit/policies/test_sandbox_rego_credentials.py -q`
Expected: FAIL.

- [ ] **Step 3: Add rule 6 to `policies/_default/sandbox.rego`**

Per spec §5.1:

```rego
# Rule 6 (Sprint 10) — per-tenant max credential TTL cap.
# Wave-1 flat cap: every requires_credentials entry's ttl_s must
# be <= the tenant's configured max_credential_ttl_s.

deny[reason] {
    some i
    cred := input.requires_credentials[i]
    is_number(cred.ttl_s)                          # defense-in-depth type check
    cred.ttl_s > tenant_max_credential_ttl_s
    reason := "sandbox_credential_ttl_exceeds_tenant_max"
}

# Defense-in-depth: malformed type at the ttl_s slot also denies.
deny[reason] {
    some i
    cred := input.requires_credentials[i]
    not is_number(cred.ttl_s)
    reason := "sandbox_credential_ttl_exceeds_tenant_max"  # collapsed for closed-enum stability
}

tenant_max_credential_ttl_s := ttl {
    ttl := input.tenant.overlay.max_credential_ttl_s
} else := ttl {
    ttl := input.kernel_default.max_credential_ttl_s
}
```

Add to `src/cognic_agentos/core/config.py`:

```python
sandbox_kernel_default_max_credential_ttl_s: int = Field(
    default=900,
    ge=60,
    le=86400,
    description="Sprint 10 — kernel default per-tenant max credential lease TTL (seconds). Bank overlays may raise via Rego tenant.overlay.max_credential_ttl_s. Wave-1 flat cap; per-secret-class caps are future work.",
)
```

- [ ] **Step 4: Run — verify pass**

`uv run pytest tests/unit/policies/test_sandbox_rego_credentials.py tests/unit/test_config.py -q`
Expected: GREEN.

- [ ] **Step 5: Gate ladder**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: clean.

- [ ] **Step 6: HALT-BEFORE-COMMIT — sandbox.rego stop-rule review**

`policies/_default/sandbox.rego` is a stop-rule policy bundle per AGENTS.md L150. Present the diff; map watchpoints (rule 6 is PURE Rego per the Sprint-8A T11 R2-R3 contract; defense-in-depth type check catches malformed input; closed-enum reason `sandbox_credential_ttl_exceeds_tenant_max` added; kernel default = 900s, bank overlays raise; loosening the kernel default requires coordinated kernel + ADR amendment per existing precedent). Commit only after approval:

```bash
git add policies/_default/sandbox.rego \
        src/cognic_agentos/core/config.py \
        tests/unit/policies/test_sandbox_rego_credentials.py \
        tests/unit/test_config.py
git commit -m "feat(sprint-10): sandbox.rego rule 6 — per-tenant max credential TTL cap (T8)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T9: closed-enum extensions — `SandboxRefusalReason` 21 → 26; `SandboxLifecycleEvent` 12 → 15

**Files:**
- Modify: `src/cognic_agentos/sandbox/protocol.py` (closed-enum extensions)
- Modify: `src/cognic_agentos/sandbox/audit.py` (3 new lifecycle event payloads — NOT-CC per Doctrine F)
- Modify: `tests/unit/sandbox/test_audit.py` (3 new payload-shape tests)

NOTE: spec §6.1 enumerates **5 new Sprint-10 refusal values** (21 → 26 net): 3 mint-failure values per §7.1, 1 Rego TTL-cap value per §5.1, 1 kernel-boundary cross-tenant value per §4.1. T9 extends the `SandboxRefusalReason` Literal to include all 5; the count assertion below pins `len(actual) == 26`.

- [ ] **Step 1: Write failing tests for the closed-enum extensions**

Append to `tests/unit/sandbox/test_audit.py`:

```python
def test_sandbox_refusal_reason_includes_sprint_10_values() -> None:
    """T9 — 5 new Sprint 10 refusal values added."""
    from typing import get_args
    from cognic_agentos.sandbox.protocol import SandboxRefusalReason

    sprint_10_values = {
        "sandbox_credential_mint_failed_vault_unavailable",
        "sandbox_credential_mint_failed_secret_path_unknown",
        "sandbox_credential_mint_failed_auth_denied",
        "sandbox_credential_ttl_exceeds_tenant_max",
        "sandbox_credential_request_tenant_mismatch",
    }
    actual = set(get_args(SandboxRefusalReason))
    assert sprint_10_values.issubset(actual)
    assert len(actual) == 26


def test_sandbox_lifecycle_event_includes_sprint_10_values() -> None:
    """T9 — 3 new Sprint 10 lifecycle event values added."""
    from typing import get_args
    from cognic_agentos.sandbox.protocol import SandboxLifecycleEvent

    sprint_10_values = {
        "sandbox.lifecycle.lease_minted",
        "sandbox.lifecycle.lease_revoked",
        "sandbox.lifecycle.lease_revoke_failed",
    }
    actual = set(get_args(SandboxLifecycleEvent))
    assert sprint_10_values.issubset(actual)
    assert len(actual) == 15


def test_lease_minted_payload_carries_audit_evidence(...):
    """T9 — sandbox.lifecycle.lease_minted chain row carries all 9 evidence
    fields per spec §6.2 (lease_id + request.secret_path + scope_label +
    tenant_id + actor_ref.actor_subject + actor_ref.actor_type + ttl_s +
    ttl_s_granted + minted_at + expires_at)."""
    # ... full payload-shape assertion ...


def test_lease_revoke_failed_payload_carries_vault_error_and_auto_expiry(...):
    """T9 — sandbox.lifecycle.lease_revoke_failed payload carries
    vault_error + auto_expiry_at IN ADDITION to the standard fields."""
    # ... assertion ...
```

- [ ] **Step 2: Extend `SandboxRefusalReason` + `SandboxLifecycleEvent`**

In `src/cognic_agentos/sandbox/protocol.py`:

```python
SandboxRefusalReason = Literal[
    # ... existing 21 values ...
    # Sprint 10 — 5 new values:
    "sandbox_credential_mint_failed_vault_unavailable",
    "sandbox_credential_mint_failed_secret_path_unknown",
    "sandbox_credential_mint_failed_auth_denied",
    "sandbox_credential_ttl_exceeds_tenant_max",
    "sandbox_credential_request_tenant_mismatch",
]

SandboxLifecycleEvent = Literal[
    # ... existing 12 values ...
    # Sprint 10 — 3 new lifecycle events:
    "sandbox.lifecycle.lease_minted",
    "sandbox.lifecycle.lease_revoked",
    "sandbox.lifecycle.lease_revoke_failed",
]
```

In `src/cognic_agentos/sandbox/audit.py`: add 3 payload converters for the new events per spec §6.2 (must include `request.actor_ref.actor_subject` + `request.actor_ref.actor_type` + the standard 7 other fields).

- [ ] **Step 3: Run — verify pass**

`uv run pytest tests/unit/sandbox/test_audit.py -q`
Expected: GREEN.

- [ ] **Step 4: Gate ladder + HALT-BEFORE-COMMIT — sandbox/protocol.py review**

`sandbox/protocol.py` is the wire-public closed-enum surface for the sandbox primitive. Present the diff; map watchpoints (5 new refusal values not 4 — T7 introduced the cross-tenant guard; 3 new lifecycle event values; payload conversions include the actor_ref projection NOT the full Actor; token contents NEVER persisted). Commit only after approval:

```bash
git add src/cognic_agentos/sandbox/protocol.py \
        src/cognic_agentos/sandbox/audit.py \
        tests/unit/sandbox/test_audit.py
git commit -m "feat(sprint-10): closed-enum extensions — SandboxRefusalReason 26 + SandboxLifecycleEvent 15 (T9)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task T10: Backend-side `create()` + `destroy()` threading  [CC — HALT × 2 (one per backend)]

**Files:**
- Modify: `src/cognic_agentos/sandbox/protocol.py` (extend `SandboxBackend.create()` Protocol signature)
- Modify: `src/cognic_agentos/sandbox/backends/docker_sibling.py` (mint at create, revoke at destroy)
- Modify: `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` (same)
- Modify: `tests/unit/sandbox/backends/test_docker_sibling_lifecycle.py` (lifecycle tests)
- Modify: `tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py` (lifecycle tests)
- Create: `tests/unit/sandbox/test_credential_lifecycle.py` (cross-backend abstract tests)

This task is **TWO halt-before-commit cycles** — one per backend — because each backend is independently CC.

Implementation pattern per spec §4.2 + §4.3 — mint post-admission with try/except mapping; revoke fail-soft with structured audit emission.

- [ ] **Step 1: Extend Protocol + Step 2-4: per-backend implementation + Step 5: cross-backend lifecycle pin**

(See spec §4.2 + §4.3 for the full pseudocode. Each backend test asserts: mint happens after admission, before exec; destroy revokes leases (best-effort) + emits structured events; fail-soft on Vault unavailability during revoke.)

- [ ] **Step 6 (Docker): HALT-BEFORE-COMMIT — docker_sibling.py CC review**

Halt. Commit:
```bash
git add src/cognic_agentos/sandbox/protocol.py \
        src/cognic_agentos/sandbox/backends/docker_sibling.py \
        tests/unit/sandbox/backends/test_docker_sibling_lifecycle.py \
        tests/unit/sandbox/test_credential_lifecycle.py
git commit -m "feat(sprint-10): DockerSibling backend create/destroy threads credential lifecycle (T10 Docker)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

- [ ] **Step 7 (K8s): HALT-BEFORE-COMMIT — kubernetes_pod.py CC review**

Halt. Commit:
```bash
git add src/cognic_agentos/sandbox/backends/kubernetes_pod.py \
        tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py
git commit -m "feat(sprint-10): KubernetesPod backend create/destroy threads credential lifecycle (T10 K8s)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task Z1: CC gate promotion (+3 → 84) + fresh coverage verification  [CC — HALT]

**Files:**
- Modify: `tools/check_critical_coverage.py` (+3 entries; bump `_EXPECTED_ENTRY_COUNT` 81 → 84)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (bump count + per-module presence tests)

- [ ] **Step 1: Run fresh coverage on full suite + branch coverage**

```bash
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q
```

Capture `coverage.json`. Verify ALL 3 new CC candidates (`core/vault.py` + `core/_vault_transport.py` + `sandbox/credentials.py`) at ≥95% line / ≥90% branch.

- [ ] **Step 2: Add the 3 entries + bump count**

In `tools/check_critical_coverage.py`:

```python
_CRITICAL_FILES = (
    # ... existing 81 entries ...
    ("src/cognic_agentos/core/vault.py", 0.95, 0.90),
    ("src/cognic_agentos/core/_vault_transport.py", 0.95, 0.90),
    ("src/cognic_agentos/sandbox/credentials.py", 0.95, 0.90),
)
```

In `tests/unit/tools/test_check_critical_coverage.py`: bump `_EXPECTED_ENTRY_COUNT` 81 → 84; add per-module-presence tests for the 3 new entries.

- [ ] **Step 3: Run gate against fresh coverage in the SAME commit**

```bash
uv run python tools/check_critical_coverage.py
```

Expected: 84/84 PASS. If ANY module is below floor, focused negative-path repair in this SAME commit (per the Sprint 9.5 Z1 precedent).

- [ ] **Step 4: HALT-BEFORE-COMMIT — Z1 promotion review**

Per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`. Present:
- Fresh `coverage.json` excerpt for the 3 promoted modules
- `check_critical_coverage.py` output showing 84/84 PASS
- Any focused negative-path test additions

Commit only after approval:

```bash
git add tools/check_critical_coverage.py \
        tests/unit/tools/test_check_critical_coverage.py
git commit -m "feat(sprint-10): CC gate promotion +3 (81 → 84) — Z1

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task Z2: Real-Vault integration proof gate (env-gated)  [CC — HALT]

**Files:**
- Create: `tests/integration/sandbox/test_real_vault_credential_lifecycle.py`

Mirror Sprint 9.5 Z2 real-cosign two-layer proof:
- Layer 1: direct `lease_credential` + `revoke_credential` round-trip against a real `vault` binary on PATH (or test Vault server URL via `COGNIC_VAULT_TEST_ADDR`)
- Layer 2: full sandbox `create()` + `destroy()` with `requires_credentials` against real Vault → assert lease minted at create, revoked at destroy, audit events emitted

Env-gated on `COGNIC_RUN_VAULT_INTEGRATION=1`. Fail-loud on missing `vault` binary OR unreachable server (no silent skip).

- [ ] **Step 1: Implement test file (~150-200 LoC)**

Pattern from `tests/integration/models/test_real_cosign_proof.py`. Skip when env var not set; raise loud diagnostic when env var set but `vault` binary missing.

- [ ] **Step 2: Local proof run** (developer machine + dev Vault server)

```bash
COGNIC_RUN_VAULT_INTEGRATION=1 \
COGNIC_VAULT_TEST_ADDR=http://localhost:8200 \
COGNIC_VAULT_TEST_TOKEN=root \
uv run pytest tests/integration/sandbox/test_real_vault_credential_lifecycle.py -v
```

Expected: BOTH layers pass against real Vault. Document the run in the closeout note.

- [ ] **Step 3: HALT-BEFORE-COMMIT — Z2 proof commit**

Commit:
```bash
git add tests/integration/sandbox/test_real_vault_credential_lifecycle.py
git commit -m "chore(sprint-10): Z2 — real-Vault two-layer integration proof (env-gated on COGNIC_RUN_VAULT_INTEGRATION)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task Z3: Doc reconciliation — BUILD_PLAN §10 + ADR-004 + AGENTS.md  [HUMAN-AUTHORED EDITS — HALT]

**Files:**
- Modify: `docs/BUILD_PLAN.md` §10
- Modify: `docs/adrs/ADR-004-sandbox-primitive.md` §25 + §68 + §102
- Modify: `AGENTS.md` (L48 critical-controls list + L188 sandbox/credentials.py promotion mark)

- [ ] **Step 1: BUILD_PLAN §10 patches**

- Patch the stale `sandbox/session.py` name — Sprint 10 lands as `SandboxBackend.create()` per-backend, not a new module
- Reflect the +3 CC promotion (81 → 84)
- Mark Sprint 10 as MERGED once PR lands

- [ ] **Step 2: ADR-004 patches**

- §25 + §68 + §102 mark "Sprint 10 shipped the real `VaultCredentialAdapter` + the `mint_lease`/`revoke_lease` Protocol extension"
- Note the new 5 refusal values + 3 lifecycle event values
- Phase 3 still NOT closed (Sprint 10.5 scheduler remains)

- [ ] **Step 3: AGENTS.md patches**

- L48 critical-controls list: add `core/vault.py` + `core/_vault_transport.py`
- L188: mark the `sandbox/credentials.py` off-gate → on-gate promotion as EXECUTED at Sprint 10 Z1

- [ ] **Step 4: HALT-BEFORE-COMMIT — doc-reconciliation review**

Present every diff. Commit only after approval:
```bash
git add docs/BUILD_PLAN.md docs/adrs/ADR-004-sandbox-primitive.md AGENTS.md
git commit -m "docs(sprint-10): reconcile BUILD_PLAN §10 + ADR-004 + AGENTS.md (Z3)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Self-Review (writing-plans skill step)

**Spec coverage** — every spec section maps to ≥1 task:

| Spec § | Task(s) |
|---|---|
| §1 context/scope | T1 (already done @ 4ac96fa) |
| §2.1 three-module Vault landscape | T2 (transport) + T4 (core/vault) + T3 (adapter refactor) |
| §2.2 refactor scope on db/adapters/vault_adapter.py | T3 |
| §2.3 three-lease-dataclass landscape | T4 (test_lease_dataclass_landscape.py) |
| §3.1 VaultLeaseActorRef + VaultLeaseRequest | T4 |
| §3.2 CredentialLease | T4 |
| §3.3 core/vault.py public API | T4 |
| §3.4 token shape passthrough | T4 |
| §3.5 VaultTransport | T2 |
| §4.1 admit_policy signature extension | T7 |
| §4.2 mint at create() post-admission | T10 |
| §4.3 revoke at destroy() fail-soft | T10 |
| §4.4 CredentialAdapter Protocol extension | T5 |
| §5 sandbox.rego rule 6 | T8 |
| §6.1 SandboxRefusalReason 21 → 26 (5 new values: 3 mint failures + 1 TTL cap + 1 cross-tenant) | T9 (Literal extension) + T7 (cross-tenant check at kernel boundary) |
| §6.2 SandboxLifecycleEvent 12 → 15 | T9 |
| §6.3 SandboxPolicyViolationReason unchanged | (no task) |
| §7.1 mint-failure taxonomy | T4 (exception classes) + T10 (handler-side mapping) |
| §7.2 revoke-failure fail-soft | T10 |
| §7.3 decision matrix | T7 + T10 |
| §8.1 modules touched | (whole plan) |
| §8.2 new settings | T2 + T8 |
| §8.3 CC promotion ritual | Z1 |
| §8.4 real-Vault Z2 proof | Z2 |
| §9 test surface | each task has its tests |
| §10 out-of-scope | (no code) |
| §11 Phase-3 partial closure | Z3 (BUILD_PLAN note) |

**Placeholder scan** — no "TBD" / "TODO" / "fill in details" markers. Every code step has a code block. T10 sketches the backend integration at high level — the implementer follows spec §4.2 + §4.3 for the precise sequence.

**Type consistency**:
- `lease_credential(request, *, transport, settings)` — same signature at every reference (T4 + T10 + Z2)
- `revoke_credential(lease_id, *, transport)` — same at every reference
- `VaultLeaseRequest(secret_path, ttl_s, tenant_id, actor_ref, scope_label)` — 5-field order matches §3.1
- `CredentialLease(lease_id, request, token, minted_at, ttl_s_granted, expires_at)` — matches §3.2
- `VaultLeaseActorRef(actor_subject, actor_type)` — 2-field; `actor_type: Literal["human", "service"]` matches portal/rbac/actor's contract

**Cross-task dependency ordering**: T2 → T3 (adapter refactor depends on transport) → T4 (core/vault depends on transport) → T5 (Protocol extension is independent of T4 BUT T6 needs both) → T6 (depends on T4 + T5) → T7 (depends on T5; needs VaultLeaseRequest from T4) → T8 (independent Rego work) → T9 (depends on T7 for the cross-tenant refusal value) → T10 (depends on T6 + T7 + T9). Z1 (depends on all preceding). Z2 (depends on T6 + T10). Z3 (depends on Z1 + Z2). No cycles.

**Flagged for execution-time clarification:**
1. **T8 token-shape test fixture detail** — the spec leaves the test-fixture Vault HTTP response shape to the implementer. Pin against the actual hvac response shape at T8 implementation time.
2. **T10 backend-side implementation symmetry** — Docker + K8s land in TWO separate halt-before-commit commits (one per backend) for clean bisection per the Sprint 8B precedent.

---

**END OF PLAN.** Ready for plan-of-record commit + execution start at T2.
