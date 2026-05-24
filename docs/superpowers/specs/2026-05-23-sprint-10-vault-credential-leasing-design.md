# Sprint 10 — Vault credential leasing: design

**Status:** brainstorm output (2026-05-23). Authored on `main@985264f` after PR #35 (9.5a) + PR #36 (9.5b) + PR #37 (7B.4 latency hardening) all merged. Awaiting user review before plan derivation.

**ADR lineage:** ADR-004 §25 + §68 + §102 (sandbox primitive — Vault leasing deferred to Sprint 10); ADR-009 (pluggable infrastructure adapters — Vault); ADR-015 (policy-as-code — TTL cap is policy, not config); cross-cuts ADR-022 (Sprint 10.5 scheduler wraps `sandbox.create()` so admission + mint flow under scheduler admission later).

**BUILD_PLAN scope:** §10 — `core/vault.py` + `sandbox/session.py` integration + per-tenant max TTL policy. 2 work-units, Phase 3.

**BUILD_PLAN doc-drift flag (§1.1):** BUILD_PLAN §10 names `sandbox/session.py` as the integration surface, but **no such module exists** in the live tree. Sprint 8A landed the session machinery split across `sandbox/protocol.py` (declares `SandboxBackend.create()` Protocol + `SandboxSession` Protocol) + the per-backend implementations (`sandbox/backends/docker_sibling.py` + `sandbox/backends/kubernetes_pod.py`). Sprint 10's "sandbox session integration" therefore lands as:
- An EXTENSION to the `SandboxBackend.create()` Protocol method (new `requires_credentials` kwarg)
- EXTENSIONS to both backend implementations (mint at create, revoke at destroy)
- NO new `sandbox/session.py` module is created.

This BUILD_PLAN line is doc drift from the original ADR-004 sketch; per the established `[[feedback_patch_plan_against_doctrine]]` discipline this gets fixed in the Sprint 10 Z3 doc-reconciliation commit (see Appendix B).

**Pre-locked design calls (brainstorm 2026-05-23):**

| Axis | User-locked default |
|---|---|
| A — Vault adapter scope | NEW `core/vault.py` distinct from `db/adapters/vault_adapter.py`. Persistent secret fetch vs short-TTL credential leasing are different contracts. |
| B — lease/token semantics | `CredentialLease` (NEW dataclass) is durable; `token` is ephemeral credential material handed to the sandbox. `VaultLeaseRequest` carries `secret_path + ttl_s + tenant_id + actor_ref + scope_label`; the `actor_ref` field is a core-owned `VaultLeaseActorRef` projection (`actor_subject + actor_type`) to keep `core/vault.py` independent of `portal/rbac/Actor` per the architectural-arrow contract (see §3.1). |
| C — sandbox seam | Separate `requires_credentials: list[VaultLeaseRequest]` kwarg threaded through `create()`/`admit_policy()`, NOT stuffed into `SandboxPolicy`. |
| D — TTL cap policy | Rego-driven in `policies/_default/sandbox.rego`. Settings only carry static adapter/bootstrap config. Flat per-tenant cap in Wave 1 (no per-class). |
| E — revoke-on-destroy | Fail-soft operationally (don't block cleanup), fail-loud in evidence (emit `sandbox.lifecycle.lease_revoke_failed`). Single attempt. Vault-side TTL is the operational safety net. |
| F — mint timing | Mint at sandbox `create()` AFTER admission allows + BEFORE exec. Admission stays a pure policy decision; create performs the Vault side-effect. |
| G — CC promotion | Single Z-style promotion at sprint close. **THREE modules: `core/vault.py` (new) + `core/_vault_transport.py` (new) + `sandbox/credentials.py` (promoted off-gate → on-gate per AGENTS.md L188's explicit promise).** Both new `core/` modules are automatically CC by the `core/` stop-rule (AGENTS.md L48). Net **81 → 84**. The brainstorm-Round-1 count of "+2 → 83" missed `_vault_transport.py`; corrected here. |
| Q1 — lease-shape relationship to Sprint-8.5 | **B1 — Distinct types.** `core/vault.py::CredentialLease` is a NEW dataclass; Sprint-8.5's `sandbox/checkpoint_store.py::VaultLeaseRef` stays untouched and checkpoint-specific. Semantics differ wide enough (long-lived/singular checkpoint-key vs short-lived/plural/revoked-on-destroy operation-credentials) that sharing would muddy both contracts. |
| Q2 — Vault transport sharing | **H1 — Shared underlying transport.** Extract `core/_vault_transport.py` (NEW) carrying the shared `hvac.Client` + static-token auth context + retry mechanics (wraps hvac's sync calls via `asyncio.to_thread`). Two public adapter surfaces consume it: `db/adapters/vault_adapter.py` (existing; persistent secret fetch) + `core/vault.py` (NEW; dynamic credential leasing). One Vault transport discipline; two distinct domain APIs. |

---

## 1. Context & scope

Sprint 10 closes the Vault-credential-leasing gap in the Phase-3 sandbox arc by replacing the Sprint-8A fail-loud `KernelDefaultCredentialAdapter` sentinel with a real `VaultCredentialAdapter` (Phase 3 itself closes only after Sprint 10.5's scheduler primitive lands — see §11). The sentinel currently refuses fail-closed at `sandbox/admission.py` whenever any pack declares `vault_path:` in its policy; this means **no production pack today can use Vault-backed credentials** without each tenant manually wiring a custom adapter. Sprint 10 lands the canonical implementation so the sentinel becomes unreachable in normal operation (it stays as the kernel-default for safety; banks wire `VaultCredentialAdapter` explicitly at create_app time).

The sandbox-side API extension is small (one new kwarg on `create()` + admission threading) but the cross-cut is significant: a new `core/` module, a Protocol extension on `CredentialAdapter` per the Sprint-8.5 ADR-004 §Q4 LOCK, a Rego rule for TTL caps, three closed-enum extensions (refusal reasons, lifecycle events), and the standard CC-gate promotion ritual.

**Cross-references:**
- ADR-004 §25 + §68: "Sprint 10 ships the real `VaultCredentialAdapter`"
- ADR-004 §102: "fail-loud Vault-lease path NOW; NO `CredentialAdapter` extension in Sprint 8.5. … Sprint 10 ships the real `VaultCredentialAdapter` + `mint_lease`/`revoke_lease` Protocol extension"
- ADR-009: pluggable adapter layer where the underlying Vault driver lives
- ADR-022: Sprint 10.5 wraps `sandbox.create()` in `SchedulerEngine.submit()` AFTER Sprint 10; the `requires_credentials` kwarg flows through unchanged
- AGENTS.md L188 + L216: `sandbox/credentials.py` is currently off-gate per Doctrine F; "Sprint 10's real `VaultCredentialAdapter` goes ON the gate when it lands"

**Not in scope (deferred or out-of-band):**
- Per-class per-tenant TTL caps (e.g. DB credentials 1h, payment-API 5min) — flat cap only in Wave 1; per-class future-work if banks demand
- Retry-on-revoke-failure / pending-revocation queue — fail-soft single-attempt only
- Vault auth methods beyond static token (Wave-1 only consumes `Settings.vault_token` — an operator-pre-minted token). AppRole, Kubernetes ServiceAccount, and JWT/OIDC auth flows are future work; would require new Settings (role_id, secret_id, JWT path, etc.) + transport-level auth-state management
- Dynamic-secret backend coverage beyond DB + cloud-credentials — token shape stays `dict[str, str]` passthrough (see §3.4)
- Lease renewal (`renew(lease_id, ttl_s)`) — Wave-1 leases are short-lived and one-shot; renewal is a Wave-2 feature if needed
- Scheduler-time admission (sandbox.create wrapped in SchedulerEngine.submit) — that's Sprint 10.5's concern; Sprint 10 ships a scheduler-free `requires_credentials` shape that Sprint 10.5 will consume

---

## 2. Architecture — module landscape

### 2.1 Three-module Vault landscape

```
┌────────────────────────────────────────────────────────────────────┐
│ db/adapters/vault_adapter.py   (existing; Sprint 1C)               │
│   Public API: SecretAdapter Protocol                               │
│     read(path) / write(path, value) / lease(path, ttl_s)           │
│     revoke(lease_id) / health_check()                              │
│   Purpose: persistent secret fetch + low-level lease primitive     │
│   Lease dataclass: SecretLease (existing)                          │
│ ───────────────────────────────────────────────────────────────────│
│ core/vault.py                  (NEW; Sprint 10)                    │
│   Public API:                                                      │
│     lease_credential(request: VaultLeaseRequest)                   │
│       -> CredentialLease                                           │
│     revoke_credential(lease_id: str) -> None                       │
│   Purpose: high-level dynamic credential leasing for sandboxes;    │
│            tenant/actor context; per-operation lifecycle;          │
│            integrates with admission Rego + audit                  │
│   Lease dataclass: CredentialLease (NEW)                           │
│ ───────────────────────────────────────────────────────────────────│
│ core/_vault_transport.py            (NEW; Sprint 10; shared transport)  │
│   Public API: VaultTransport (shared hvac.Client + static-token   │
│     auth + retry; async façade via asyncio.to_thread)              │
│     read(path) / write(path, body) / lease(path, ttl_s)            │
│     revoke(lease_id) / health_check()                              │
│   Purpose: ONE shared hvac.Client; ONE static-token auth context;  │
│            ONE retry discipline; async-friendly via to_thread.     │
│            Consumed by both adapter surfaces above.                │
└────────────────────────────────────────────────────────────────────┘
```

**Architectural arrow:** `core/_vault_transport.py` ← (consumed by) `db/adapters/vault_adapter.py` AND `core/vault.py`. Both consumers are **public adapter surfaces**; neither imports the other. The shared transport eliminates duplicate HTTP/auth/retry logic without collapsing two distinct domain APIs into one blob.

**Module placement rationale:**
- `core/_vault_transport.py` (NOT `db/adapters/_vault_transport.py`) because both `core/` and `db/adapters/` consume it; placing it under `core/` keeps the architectural arrow clean (db/adapters can import from core, but not vice versa per ADR-009).
- Underscore prefix signals INTERNAL — not part of any documented public surface. Banks wire `VaultAdapter` or `VaultCredentialAdapter`, not `VaultTransport`.
- `core/vault.py` (NOT `core/credential_leasing.py` or similar) because the BUILD_PLAN names it `core/vault.py`; sticking to the documented name avoids drift.

### 2.2 Refactor scope on existing `db/adapters/vault_adapter.py`

**Correction from brainstorm wording:** Sprint 1C's `VaultAdapter` uses `hvac` (the official HashiCorp Vault Python SDK — synchronous), wrapping each blocking call in `asyncio.to_thread` to keep the FastAPI event loop cooperative. There is NO httpx client in the existing adapter today; the brainstorm phrasing implied otherwise. The shared-transport design is therefore **wrapping hvac**, NOT extracting httpx.

```
Sprint 1C (today):  VaultAdapter   ─[creates lazily]─→ hvac.Client
                    (sync calls wrapped in asyncio.to_thread per method)

Sprint 10 (this):   VaultAdapter   ─→ VaultTransport ─[wraps]─→ hvac.Client
                    core.vault     ─→ VaultTransport ─[same]──→ hvac.Client
                    (one shared hvac.Client per (vault_addr, token, namespace)
                    triple; same to_thread discipline at each consumer call)
```

- **Before (Sprint 1C):** `VaultAdapter.__init__(addr, token, namespace)` stores connection params; `_ensure_client()` lazily mints an `hvac.Client`; `read/write/lease/revoke/health_check` each wrap a sync hvac call in `asyncio.to_thread`. No shared client across adapter instances.
- **After (Sprint 10):** `VaultAdapter.__init__(addr, token, namespace, *, transport: VaultTransport | None = None)` accepts an optional pre-built `VaultTransport`; defaults to lazily building one internally if None (backward-compat for any out-of-tree consumer that constructs `VaultAdapter(addr, token, namespace)`). Methods delegate hvac calls to `self._transport.<verb>(...)`. The transport owns the lone `hvac.Client` instance + the static-token auth context + retry logic.

**This refactor is bounded** (~50-80 LoC delta in `vault_adapter.py`; the public API stays identical). It is a precondition for `core/vault.py` to share the same hvac client + retry discipline. Pin with a test that two `VaultAdapter` instances built with the same shared `VaultTransport` see the same underlying `hvac.Client` instance + static token state (proves the shared transport is genuinely shared, not just structurally typed).

**Why NOT replace hvac with httpx:** hvac is the standard SDK; covers every Vault backend + every auth method; rewriting against raw httpx would invalidate Sprint-1C's adapter and add maintenance burden for zero functional gain. The shared transport keeps hvac as the underlying client + adds the cross-cutting concerns (token caching, retry, asyncio-friendly façade) that BOTH consumers need.

### 2.3 Three-lease-dataclass landscape (explicit to avoid future conflation)

Sprint 10 introduces a THIRD lease-shaped frozen dataclass into the codebase. This is **intentional** — each represents a different lease lifecycle:

| Dataclass | Module | Sprint | Lifetime | Cardinality | Purpose |
|---|---|---|---|---|---|
| `SecretLease` | `db/adapters/vault_adapter.py` | 1C | seconds-to-hours | per-call | low-level Vault lease primitive (kernel-secrets adapter return shape) |
| `VaultLeaseRef` | `sandbox/checkpoint_store.py` | 8.5 | days-to-weeks | 1 per session | checkpoint-encryption-key lease metadata (wire-public; persisted) |
| **`CredentialLease`** | **`core/vault.py`** | **10 (NEW)** | **seconds-to-hours** | **N per session** | **per-operation sandbox credential lease** |

Pin the three-dataclass landscape via a test (`test_lease_dataclass_landscape_documented.py`) that imports all three by name + asserts they're distinct types — catches a future refactor that accidentally consolidates them.

---

## 3. API contracts

### 3.1 `VaultLeaseActorRef` + `VaultLeaseRequest` (NEW, frozen, Sprint 10)

**Architectural arrow:** `core/vault.py` is a KERNEL layer; `portal/rbac/actor.py::Actor` is a PORTAL-layer type. Per the AGENTS.md / ADR architectural-arrow contract, `core/` MUST NOT import from `portal/`. Sprint 10 declares a tiny core-owned projection — `VaultLeaseActorRef` — that carries ONLY the audit-context fields the kernel needs. The Actor → VaultLeaseActorRef projection happens at the request-construction boundary (in `sandbox/admission.py` or whoever assembles the `VaultLeaseRequest` from a `requires_credentials` declaration on a sandbox call).

```python
@dataclass(frozen=True, slots=True)
class VaultLeaseActorRef:
    """Sprint 10 §3.1 — core-owned audit-context projection of the
    portal-layer ``Actor``. ``core/vault.py`` MUST NOT import from
    ``portal/rbac/actor.py``; the projection lives here in
    ``core/vault.py`` and the call site maps Actor → VaultLeaseActorRef
    at the kernel boundary.

    Two fields carry exactly the audit context examiners need; no
    scopes or other portal-only structure.
    """
    actor_subject: str
    actor_type: Literal["human", "service"]


@dataclass(frozen=True, slots=True)
class VaultLeaseRequest:
    """Operator-facing description of a credential lease to mint.

    Sprint 10 §3.1. Wire-public — banks consume this from pack
    manifests + sandbox.create() callers.

    Fields:
        secret_path: Vault path the credential is leased from
                     (e.g. "database/creds/payment-readonly").
                     The path's TENANT prefix is NOT enforced here —
                     that's a Rego concern (sandbox.rego enforces
                     per-tenant path patterns).
        ttl_s:       requested lease TTL in seconds. The Rego cap
                     applies; Vault may cap further at its own
                     backend-side maximum.
        tenant_id:   audit-context — which tenant requested this
                     lease. The request constructor enforces that
                     this matches the originating Actor.tenant_id
                     (caller-side validation; see below).
        actor_ref:   audit-context — core-owned projection of the
                     originating ``Actor`` (subject + type only).
                     Threaded into the chain-row payload so
                     examiners can trace lease lineage. NOT a full
                     Actor — keeps ``core/vault.py`` independent of
                     ``portal/rbac/``.
        scope_label: short operator-friendly label for evidence
                     (e.g. "payment-write-2026Q2"). NOT a Vault
                     role; informational only. Bounded to 64 chars.
    """
    secret_path: str
    ttl_s: int
    tenant_id: str
    actor_ref: VaultLeaseActorRef
    scope_label: str
```

Validation: pre-construction Pydantic shape check (path is non-empty + non-traversal + matches `^[a-z0-9_/\-]+$`); `ttl_s > 0`; `scope_label` length ≤ 64. The `tenant_id` ↔ originating-Actor-tenant_id consistency check happens at the **call site** in `sandbox/admission.py` (which has both the request shape AND the originating Actor in scope); core-side `VaultLeaseRequest` cannot enforce it without re-introducing the architectural-arrow violation.

### 3.2 `CredentialLease` (NEW, frozen, Sprint 10)

```python
@dataclass(frozen=True, slots=True)
class CredentialLease:
    """Sprint 10 §3.2. The handle returned by ``lease_credential()``.

    Distinct from Sprint-1C's ``SecretLease`` (low-level Vault HTTP
    response shape) and Sprint-8.5's ``VaultLeaseRef`` (checkpoint-
    encryption-key lease, persisted on checkpoint blobs).

    Wire-public — consumed by sandbox session-init code, audit-event
    emitters, and the revoke path.

    Fields:
        lease_id:        Vault-side identifier; revoke key.
        request:         the originating ``VaultLeaseRequest`` (kept
                         for audit + revoke routing). The token IS
                         NOT here — see ``token`` below.
        token:           ephemeral credential material handed to the
                         sandbox process. ``dict[str, str]`` for
                         per-backend flexibility (DB credentials
                         expose ``{"username", "password"}``; cloud
                         expose ``{"access_key", "secret_key",
                         "session_token"}``). The dict is NEVER
                         persisted; admission audit chain MUST omit
                         it (only ``lease_id`` + ``request`` land on
                         the chain row).
        minted_at:       UTC-aware datetime; Sprint-2 R3 contract.
        ttl_s_granted:   actual TTL granted by Vault (may be less
                         than ``request.ttl_s`` if a backend-side
                         cap intervened); examiners read the granted
                         TTL, not the requested.
        expires_at:      ``minted_at + ttl_s_granted``; derived
                         convenience for sandbox-side timer logic.
                         Vault is authoritative; this is a hint.
    """
    lease_id: str
    request: VaultLeaseRequest
    token: dict[str, str]
    minted_at: datetime
    ttl_s_granted: int
    expires_at: datetime
```

### 3.3 `core/vault.py` public API

```python
async def lease_credential(
    request: VaultLeaseRequest,
    *,
    transport: VaultTransport,
    settings: Settings,
) -> CredentialLease:
    """Mint a short-TTL dynamic credential from Vault.

    Raises:
        VaultUnavailable — network failure or Vault returned 5xx;
            caller maps to ``sandbox_credential_mint_failed_vault_unavailable``
        VaultPathNotFound — Vault returned 404 on the secret_path;
            caller maps to ``sandbox_credential_mint_failed_secret_path_unknown``
        VaultAuthDenied — Vault returned 403 on the secret_path;
            caller maps to ``sandbox_credential_mint_failed_auth_denied``
        VaultProtocolError — Vault returned a malformed response
            shape; caller surfaces with extra detail (rare; treat
            as ``sandbox_credential_mint_failed_vault_unavailable``
            for closed-enum stability)
    """

async def revoke_credential(
    lease_id: str,
    *,
    transport: VaultTransport,
) -> None:
    """Revoke an active lease. Fail-soft per §7.2 — raises on Vault
    error but the caller's destroy() path swallows the exception
    and emits ``sandbox.lifecycle.lease_revoke_failed``. The lease
    will still auto-expire at its TTL deadline as the operational
    safety net."""
```

### 3.4 Token shape — `dict[str, str]` passthrough

Vault's dynamic-secret backends return heterogeneous response shapes:

| Backend | Response shape |
|---|---|
| `database/creds/<role>` | `{"username": ..., "password": ...}` |
| `aws/creds/<role>` | `{"access_key": ..., "secret_key": ..., "session_token": ...}` |
| `gcp/key/<role>` | `{"key_algorithm": ..., "private_key_data": ...}` |
| `pki/issue/<role>` | `{"certificate": ..., "private_key": ..., "ca_chain": ...}` |
| `kv-v2` (static, NOT dynamic) | arbitrary user-defined keys |

Sprint 10 surfaces the token as `dict[str, str]` passthrough — we don't try to normalize across backends because the consuming sandbox process needs the backend-specific shape anyway. Banks wire their pack code to read the keys they need; the kernel doesn't enforce a schema.

**Pin:** test that `token` is `dict[str, str]` (NOT typed/tagged); examiners audit by `lease_id` + `request.secret_path` + `request.scope_label`, NOT by token contents.

### 3.5 `VaultTransport` — shared transport

```python
class VaultTransport:
    """Sprint 10 §2.1 — shared low-level Vault HTTP transport.

    INTERNAL — not part of any documented public surface. Both
    ``db/adapters/vault_adapter.py::VaultAdapter`` AND
    ``core/vault.py::lease_credential`` consume this for one
    Vault transport discipline (one shared hvac.Client across both
    consumers, asyncio.to_thread façade for the sync hvac calls, one
    retry policy, one static-token auth context).

    Methods are domain-shaped (read/write/lease/revoke) — each
    delegates to the corresponding hvac call wrapped in
    asyncio.to_thread. NO refresh_token() in Wave 1: static-token
    auth is configured at construction via Settings.vault_token + ...
    and the hvac.Client holds it for its lifetime. AppRole / K8s
    refresh flows are future work (§10).
    """

    def __init__(
        self,
        *,
        vault_addr: str,
        vault_token: str | None,
        vault_namespace: str | None,
        timeout_s: float,
        max_retries: int,
    ) -> None: ...

    async def read(self, path: str) -> dict[str, Any]: ...
    async def write(self, path: str, body: dict[str, Any]) -> dict[str, Any]: ...
    async def lease(self, path: str, ttl_s: int) -> dict[str, Any]: ...
    async def revoke(self, lease_id: str) -> None: ...
    async def health_check(self) -> AdapterHealth: ...
```

Concrete implementation wraps a shared `hvac.Client` (matches existing Sprint 1C pattern at `db/adapters/vault_adapter.py`); each method invokes the sync hvac call via `asyncio.to_thread` to keep the event loop cooperative. **Wave-1 static-token authentication only** — `Settings.vault_addr` + `Settings.vault_token` + `Settings.vault_namespace` are operator-pre-provided; no AppRole or Kubernetes ServiceAccount auth flows (those would need additional Settings + transport-level auth-state management; deferred per §10). Bounded exponential backoff on transient hvac exceptions (mirrors `protocol/mcp_authz.py` retry pattern); per-request timeout from `Settings.vault_http_timeout_s` (NEW; see §8.2).

---

## 4. Sandbox integration

### 4.1 `admit_policy()` signature extension

Current Sprint-8A signature:
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
) -> None:
```

Sprint 10 extension:
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
    requires_credentials: list[VaultLeaseRequest] = (),  # NEW
) -> None:
```

Default `()` keeps existing callers backward-compat (zero impact on Sprint-8A and earlier admission paths).

**Pre-Rego validation step (NEW): kernel-boundary cross-tenant check.** When `requires_credentials` is non-empty, `admit_policy` first validates that every `VaultLeaseRequest.tenant_id` matches the originating `Actor.tenant_id`. The `VaultLeaseRequest` itself CANNOT enforce this — per §3.1's architectural-arrow contract the request carries only the projected `VaultLeaseActorRef` (`actor_subject` + `actor_type`), not the full Actor with its tenant_id. The check therefore lives at the `sandbox/admission.py` kernel boundary, where both the request shape AND the originating Actor are in scope:

```python
if requires_credentials:
    for req in requires_credentials:
        if req.tenant_id != actor.tenant_id:
            raise SandboxLifecycleRefused(
                reason="sandbox_credential_request_tenant_mismatch",
                detail=f"tenant_id={req.tenant_id} != actor.tenant_id={actor.tenant_id}",
            )
    # Then: sentinel-adapter check (existing Sprint-8A reason), Rego eval below, etc.
```

This refusal is **NOT** a mint failure (§7.1) — it fires BEFORE any Vault round-trip; the categorical fit is admission-time request-validation alongside the Rego cap rule (§5.1). Pinned by `test_admit_credentials.py::test_admit_policy_refuses_cross_tenant_request` (see §9.1).

The Rego input dict gains a new top-level key:
```python
rego_input = {
    "policy": ...,
    "tenant": ...,
    "actor": ...,
    "pack": ...,
    "runtime_image_in_canonical_set": ...,  # Sprint 8A T11 R1
    "runtime_image_in_tenant_allow_list": ...,  # Sprint 8A T11 R1
    "requires_credentials": [  # NEW — Sprint 10
        {
            "secret_path": req.secret_path,
            "ttl_s": req.ttl_s,
            "scope_label": req.scope_label,
        }
        for req in requires_credentials
    ],
}
```

Note: `tenant_id` + `actor` are stripped from each entry in the Rego input — they're top-level for cross-tenant + actor matching, and per-request inclusion would be redundant + leak audit data into the Rego eval surface.

### 4.2 Mint at `create()` post-admission

Pseudocode for the sandbox create path (per backend; both `DockerSibling` and `KubernetesPod` follow the same shape):

```python
async def create(self, *, policy, tenant_id, actor, pack_context,
                  requires_credentials: list[VaultLeaseRequest] = ()):
    # Step 1 — Admission (Stage-2 trust-gate-equivalent decision)
    await admit_policy(
        policy=policy,
        tenant_id=tenant_id,
        actor=actor,
        pack_context=pack_context,
        catalog=self._catalog,
        credential_adapter=self._credential_adapter,
        rego_engine=self._rego_engine,
        settings=self._settings,
        requires_credentials=requires_credentials,  # NEW
    )

    # Step 2 — Mint leases (post-admission; pre-exec)  [NEW Sprint 10]
    minted_leases: list[CredentialLease] = []
    try:
        for request in requires_credentials:
            lease = await lease_credential(
                request,
                transport=self._vault_transport,
                settings=self._settings,
            )
            minted_leases.append(lease)
            # ``SandboxLifecycleEvent`` is a Literal[...] (typing string
            # union) not an Enum — emit takes the literal string value.
            await self._audit.emit("sandbox.lifecycle.lease_minted", lease)
    except (VaultUnavailable, VaultPathNotFound, VaultAuthDenied) as exc:
        # Revoke any leases already minted in this attempt (best-effort)
        for already_minted in minted_leases:
            try:
                await revoke_credential(already_minted.lease_id,
                                        transport=self._vault_transport)
            except Exception:
                # Vault TTL is the safety net; emit but don't block
                await self._audit.emit(
                    "sandbox.lifecycle.lease_revoke_failed",
                    already_minted,
                )
        # Surface as closed-enum sandbox refusal
        raise SandboxLifecycleRefused(
            reason=_map_mint_exception(exc),
            detail=str(exc),
        )

    # Step 3 — Continue with sandbox creation, threading tokens into container env
    session = await self._backend_create(policy, minted_leases)
    return session
```

### 4.3 Revoke at `destroy()` — fail-soft

```python
async def destroy(self, session):
    # ... existing destroy logic ...

    # Sprint 10 — revoke all active leases for this session, fail-soft
    for lease in session.active_leases:
        try:
            await revoke_credential(lease.lease_id,
                                     transport=self._vault_transport)
            # SandboxLifecycleEvent is a Literal[...] string union, not an Enum
            await self._audit.emit("sandbox.lifecycle.lease_revoked", lease)
        except Exception as exc:
            # Don't block cleanup. Vault TTL is the operational safety
            # net — even if our revoke fails, the lease auto-expires at
            # ``lease.expires_at``. Emit structured evidence so the
            # examiner trail captures the failure.
            await self._audit.emit(
                "sandbox.lifecycle.lease_revoke_failed",
                lease,
                detail={
                    "vault_error": str(exc),
                    "auto_expiry_at": lease.expires_at.isoformat(),
                    "lease_id": lease.lease_id,
                    "secret_path": lease.request.secret_path,
                    "scope_label": lease.request.scope_label,
                },
            )
            # Continue cleanup. Do NOT raise.

    # ... existing destroy continuation ...
```

### 4.4 `CredentialAdapter` Protocol extension

Sprint-8A's Protocol shape:
```python
@runtime_checkable
class CredentialAdapter(Protocol):
    async def fetch_secret(self, path: str) -> str | None: ...
```

Sprint 10 extension (per ADR-004 §102 Q4 LOCK):
```python
@runtime_checkable
class CredentialAdapter(Protocol):
    async def fetch_secret(self, path: str) -> str | None: ...
    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease: ...  # NEW
    async def revoke_lease(self, lease_id: str) -> None: ...                       # NEW
```

The concrete `VaultCredentialAdapter` implements all 3 methods; `mint_lease` + `revoke_lease` delegate to `core/vault.py`'s top-level `lease_credential` + `revoke_credential` functions (the Protocol method is a thin instance-bound wrapper for type safety + dependency injection).

The Sprint-8A `KernelDefaultCredentialAdapter` sentinel must ALSO extend with stub implementations of `mint_lease` + `revoke_lease` that raise `NotImplementedError` pointing at Sprint 10 (production-grade rule — fail loud). The existing `isinstance(credential_adapter, KernelDefaultCredentialAdapter)` check in `admit_policy` continues to refuse policies that declare `vault_path:`; the new `requires_credentials` kwarg gets a NEW refusal: if `requires_credentials` is non-empty AND the adapter is the sentinel, refuse at admission with the existing `sandbox_credential_adapter_not_configured` reason (no new refusal value needed — extends the existing one's semantic).

---

## 5. Policy — `sandbox.rego` TTL cap rule

### 5.1 New Rego rule at `policies/_default/sandbox.rego`

Adds a 6th admission rule (Sprint-8A T11 shipped 5). The existing bundle is pure allow-conjunction with `default allow := false`; rule 6 follows the same pattern so it actually refuses (a standalone `deny[reason]` set in this bundle would be inert — nothing in `OPAEngine.evaluate`'s `Decision(allow, rule_matched, reasoning, decision_data)` return surfaces a `deny` set to Python, and the existing `allow if { … }` does not gate on `count(deny) == 0`):

```rego
# Rule 6 (Sprint 10) — per-tenant max credential TTL cap.
# Wave-1 flat cap: every requires_credentials entry's ttl_s must
# be <= the tenant's configured max_credential_ttl_s. Positive
# helper joined to the `allow if` conjunction; matches the
# Sprint-8A T11 R2-R3 pure-Rego defence-in-depth contract
# (is_number type guard + numeric comparison both inside the
# helper so malformed shapes refuse fail-closed without NPE).
#
# 2-arm pattern mirrors the existing `_credential_precondition_satisfied`
# helper at sandbox.rego:137-144:
#   (i) absent  — pre-T7 input shape entirely (Sprint-8A admission
#                 paths that never opt into dynamic-lease declarations);
#   (ii) present — every entry's ttl_s passes the cap (`every` over
#                  an empty list also holds, so T7-compatible callers
#                  passing the default empty list also pass via arm
#                  (ii); admission.py threads `requires_credentials: []`
#                  on the no-kwarg path).
# Arm (i) is load-bearing: without it the helper would be undefined
# on pre-T7-shape input (Rego's `every x in undefined { … }` is
# undefined, not vacuously true), which would refuse every existing
# Sprint-8A admission path the moment rule 6 joins the `allow if`
# conjunction.

_credential_ttl_within_tenant_max if {
    not input.requires_credentials
}

_credential_ttl_within_tenant_max if {
    every cred in input.requires_credentials {
        is_number(cred.ttl_s)
        cred.ttl_s <= tenant_max_credential_ttl_s
    }
}

tenant_max_credential_ttl_s := ttl if {
    # Tenant overlay first, kernel default fallback.
    ttl := input.tenant.overlay.max_credential_ttl_s
} else := ttl if {
    ttl := input.kernel_default.max_credential_ttl_s
}
```

The existing `allow if { … }` conjunction extends with `_credential_ttl_within_tenant_max` so the cap participates in the admit decision. The 2-arm pattern correctly handles all three shapes: absent key (Sprint-8A backward-compat), empty list (T7 callers with no dynamic-lease declarations), and non-empty list (Sprint 10 dynamic-lease admission).

Closed-enum impact: ONE new refusal value `sandbox_credential_ttl_exceeds_tenant_max` is RESERVED here for Sprint 10 T9, where it lifts into the `SandboxRefusalReason` Literal. T9 does NOT wire a matching Stage-2 mapping — `OPAEngine.Decision` carries only `allow` + the decision-point-derived generic `reasoning`, with no per-rule-name channel that could distinguish "rule 6 fired vs rule 5 fired" — so the cap continues to surface at runtime via the existing Stage-2 mapping `not decision.allow → SandboxLifecycleRefused("sandbox_policy_rego_denied", …)` at `admission.py:601-603`. Rego-reason surfacing through `OPAEngine.Decision` is **deferred to a future task** (a follow-up sprint adds either a per-rule deny-set or a `decision_data`-carried rule_name channel + the Stage-2 dispatch wiring; T9's bare Literal lift gives that future task a stable closed-enum target without imposing wire-protocol-public engine work in Sprint 10). For T8 the cap is enforced — a TTL-exceeded request returns `decision.allow=false` and surfaces through the existing generic arm. The bisection invariant holds because T8 adds NO Python `SandboxRefusalReason` Literal entry for the new string AND NO Python raise / mapping site — every mention outside the Rego bundle (this spec, the plan, the rule comment block, two test docstrings, one Protocol module docstring) is explanatory documentation pointing forward to T9, not an executable reference.

### 5.2 Kernel default + tenant overlay

The kernel default `max_credential_ttl_s = 900` (15 minutes) is owned by **`Settings.sandbox_kernel_default_max_credential_ttl_s: int = 900`** (NEW, `core/config.py`) per the conservative-Wave-1-default doctrine. Bank overlays raise it (e.g. CRC bank overlay sets `tenant.overlay.max_credential_ttl_s = 3600` for their long-running batch jobs).

`sandbox/admission.py` Step 9 threads the Settings value into the Rego input dict as **`input.kernel_default.max_credential_ttl_s`** (mirrors how the existing `tenant_max.{cpu_cores, memory_mb, walltime_s}` flat caps are threaded from their Settings counterparts at `admission.py:539-543`). `policies/_default/sandbox.rego` itself ships NO TTL constant — the bundle reads the value from the input dict and falls back from `input.tenant.overlay.max_credential_ttl_s` to `input.kernel_default.max_credential_ttl_s` via the `else` branch shown in §5.1. Wave-1 omits the `tenant.overlay` key entirely from the admission.py input dict; the Rego `else` branch handles absent-overlay deployments. Bank-overlay plumbing for `tenant.overlay.max_credential_ttl_s` (per-tenant raise) is a future-sprint hook (out of scope for Sprint 10).

### 5.3 Wire-protocol-public — sandbox.rego is a stop-rule policy bundle

Per AGENTS.md L48 + L150, `policies/_default/sandbox.rego` is a stop-rule. The new rule + new refusal value MUST be reviewed under critical-controls discipline; the existing Sprint-8A T11 R2-R3 defence-in-depth contract (PURE Rego guard with type checks) applies to the new rule too. Bank overlays may TIGHTEN the cap (lower TTL ceiling); LOOSENING the kernel default requires a coordinated kernel + ADR amendment.

---

## 6. Audit & closed-enum extensions

### 6.1 `SandboxRefusalReason` — 21 → 26 (+5)

**Five new closed-enum refusal values land at Sprint 10:**

- **3 Vault-round-trip mint failures** at `create()` post-admission (per §7.1 — Vault unavailable / secret_path 404 / auth 403)
- **1 admission-time Rego cap refusal** for the per-tenant max TTL rule (per §5.1 — `sandbox_credential_ttl_exceeds_tenant_max`)
- **1 kernel-boundary request-validation refusal** for the tenant_id ↔ Actor.tenant_id consistency check (`sandbox_credential_request_tenant_mismatch`; see §4.1 + §3.1). This validation is owned by the request-meets-actor boundary in `sandbox/admission.py` — `VaultLeaseRequest` itself cannot enforce the consistency without re-introducing the architectural-arrow violation (per §3.1 the request only carries the projected `VaultLeaseActorRef`, not the full `Actor`).

| Existing (21) | Sprint 10 additions |
|---|---|
| Sprint 8A (15 values; unchanged) | `sandbox_credential_mint_failed_vault_unavailable` — Vault 5xx or network failure (§7.1) |
| Sprint 8.5 (6 wake-time values; unchanged) | `sandbox_credential_mint_failed_secret_path_unknown` — Vault 404 on secret_path (§7.1) |
| | `sandbox_credential_mint_failed_auth_denied` — Vault 403 on secret_path (§7.1) |
| | `sandbox_credential_ttl_exceeds_tenant_max` — Rego rule 6 admission-time refusal (§5.1). **Literal value reserved on `SandboxRefusalReason` at T9; no T9/T10 Stage-2 raise site** — the cap continues to surface at runtime as `sandbox_policy_rego_denied` until Rego-reason surfacing through `OPAEngine.Decision` lands (deferred to a future task per §7.3 amendment) |
| | `sandbox_credential_request_tenant_mismatch` — kernel-boundary validation: `VaultLeaseRequest.tenant_id != Actor.tenant_id` (§4.1; owned by `sandbox/admission.py` since the projected `VaultLeaseActorRef` doesn't carry full Actor) |

**Total: 21 → 26** (+5).

### 6.2 `SandboxLifecycleEvent` — 12 → 15 (+3)

| Existing (12) | Sprint 10 additions |
|---|---|
| Sprint 8A (8 lifecycle + 0 warm-pool synth) | `sandbox.lifecycle.lease_minted` — emitted per minted lease in `create()` |
| Sprint 8.5 (4 checkpoint values; unchanged) | `sandbox.lifecycle.lease_revoked` — emitted per successful revoke in `destroy()` |
| | `sandbox.lifecycle.lease_revoke_failed` — emitted per failed revoke (fail-soft) |

Each event's chain-row payload carries:
- `lease_id` (always)
- `request.secret_path` (always)
- `request.scope_label` (always)
- `request.tenant_id` (always)
- `request.actor_ref.actor_subject` (always — core-owned projection per §3.1)
- `request.actor_ref.actor_type` (always — `"human"` or `"service"`; carries the human-vs-service axis examiners need without leaking full portal/rbac/Actor into the kernel chain)
- `request.ttl_s` (always — requested TTL)
- `lease.ttl_s_granted` (lease_minted + lease_revoked + lease_revoke_failed; the Vault-granted TTL)
- `lease.minted_at` ISO string (always)
- `lease.expires_at` ISO string (always)
- `vault_error` (lease_revoke_failed ONLY — the Vault HTTP error string)
- `auto_expiry_at` ISO string (lease_revoke_failed ONLY — same as `expires_at` but surfaced separately for the examiner's "this lease should auto-expire" claim)

**Token contents NEVER appear on the chain row.** Examiners trace by `lease_id` + `secret_path` + `scope_label`.

ISO 42001 tags: per ADR-006 §A.6.2.5 (sandbox lifecycle events), all 3 new values join the existing 12 under the `A.6.2.5` tag. The audit-event taxonomy test at `tests/unit/sandbox/test_audit_event_taxonomy.py` extends to cover the new 3.

### 6.3 `SandboxPolicyViolationReason` — UNCHANGED at 6

No new policy-violation reasons; mint/revoke failures are admission-time (refusal) or destroy-time (fail-soft evidence), not runtime policy violations.

---

## 7. Failure-mode taxonomy

### 7.1 Mint failures at `create()` (admission has passed; Vault round-trip fails)

Three failure modes, each mapped to a distinct closed-enum refusal:

| Vault response | Exception | `SandboxRefusalReason` |
|---|---|---|
| 5xx, connection refused, timeout, DNS failure | `VaultUnavailable` | `sandbox_credential_mint_failed_vault_unavailable` |
| 404 on secret_path | `VaultPathNotFound` | `sandbox_credential_mint_failed_secret_path_unknown` |
| 403 on secret_path (auth method denied) | `VaultAuthDenied` | `sandbox_credential_mint_failed_auth_denied` |
| Anything else (malformed response, unexpected 2xx without lease_id, etc.) | `VaultProtocolError` | `sandbox_credential_mint_failed_vault_unavailable` (collapse for closed-enum stability; `detail` field carries specifics) |

**On any mint failure mid-batch:** revoke leases already minted in the same `create()` attempt (best-effort); refuse the sandbox creation with the first-encountered refusal reason. No partial sandboxes.

### 7.2 Revoke failures at `destroy()` (sandbox is being torn down; Vault round-trip fails)

**Fail-soft policy:**
- Single revoke attempt per lease
- On failure: emit `sandbox.lifecycle.lease_revoke_failed` with structured detail (Vault error string + `auto_expiry_at`)
- Continue destroy() — do NOT raise, do NOT block cleanup
- Vault-side TTL is the operational safety net: even if our revoke fails, the lease auto-expires at its `expires_at` deadline

**Why fail-soft:**
- Blocking destroy() on Vault unavailability is a worse outcome (orphaned sandboxes consume backend resources; bank operators have to manually destroy them)
- The lease's own TTL is its OWN backstop — there's no scenario where a revoke-failed lease lives past its TTL deadline (Vault enforces TTL server-side)
- Banks have audit evidence for every revoke failure (the `sandbox.lifecycle.lease_revoke_failed` event); SOC operations can retry out-of-band if they want a tighter window than the lease's TTL

**Why NOT add retry loop:**
- A bounded retry loop adds latency to destroy() without changing the worst-case outcome (eventually we give up + emit the failed-revoke event anyway)
- The retry budget would have to be small (we can't block destroy() for minutes); a 3-retry exponential-backoff at 100ms-300ms-900ms adds 1.3s to destroy() in the worst case, which is significant for short-lived sandboxes
- Future Wave 2 feature if banks demand it; not Wave 1

### 7.3 Decision matrix

| Stage | Failure | Outcome |
|---|---|---|
| Admission — kernel-boundary check | `VaultLeaseRequest.tenant_id != Actor.tenant_id` (cross-tenant request) | `SandboxLifecycleRefused(sandbox_credential_request_tenant_mismatch)` — pre-Rego, pre-Vault; pure request-shape validation at the kernel boundary (§4.1) |
| Admission — Rego rule 6 | TTL cap exceeded | `SandboxLifecycleRefused(sandbox_policy_rego_denied)` — pure policy decision, NO Vault touched (§5.1). The Rego bundle's rule 6 fires + denies, but `OPAEngine.Decision` exposes only `allow` (no per-rule-name channel), so admission.py's single generic arm at `admission.py:601-603` is the only Stage-2 mapping today. The closed-enum value `sandbox_credential_ttl_exceeds_tenant_max` is reserved on the `SandboxRefusalReason` Literal at T9 but is NOT raised by any Stage-2 caller. **Rego-reason surfacing deferred to a future task** (the follow-up adds either a per-rule deny-set carried via `decision_data` or a `rule_name` channel on `Decision`, plus the admission.py dispatch wiring that translates per-rule denies to specific `SandboxRefusalReason` values). |
| Create — mint | First lease fails (Vault unavailable) | `SandboxLifecycleRefused(sandbox_credential_mint_failed_vault_unavailable)` — no leases minted, no cleanup needed |
| Create — mint | Nth lease fails (after N-1 minted) | Revoke N-1 already-minted leases (best-effort) → `SandboxLifecycleRefused(...)` for the failed Nth |
| Create — mint | Any backend failure post-mint (image pull, network setup, etc.) | Revoke ALL minted leases (best-effort) → propagate the backend error |
| Destroy — revoke | Any single lease revoke fails | Emit `sandbox.lifecycle.lease_revoke_failed` + continue destroy() |

---

## 8. Critical-controls gate & module promotions

### 8.1 Modules touched

| Module | Pre-Sprint-10 state | Sprint-10 touch | CC state post-Sprint-10 |
|---|---|---|---|
| `core/vault.py` | NOT EXIST | NEW (§3.3 + §2.1) | ON the gate from day 1 by `core/` stop-rule (AGENTS.md L48) |
| `core/_vault_transport.py` | NOT EXIST | NEW (§2.1 + §3.5) | **ON the gate from day 1 by `core/` stop-rule — carries auth/retry/connection management for Vault; CC by automatic rule** |
| `sandbox/credentials.py` | OFF gate (re-export shim, Doctrine F carve-out) | EXTEND with real `VaultCredentialAdapter` | PROMOTED to ON the gate per AGENTS.md L188's explicit promise |
| `sandbox/admission.py` | ON the gate (Sprint 8A) | EXTEND `admit_policy()` signature + Rego input + Protocol | Stays ON the gate; floor-pin during touching commit |
| `db/adapters/vault_adapter.py` | ON the gate (Sprint 1C) | REFACTOR to consume shared transport; public API unchanged | Stays ON the gate; floor-pin during touching commit |
| `core/config.py` | ON the gate (via `core/` stop-rule) | EXTEND with 2-3 Sprint 10 settings | Stays ON the gate |
| `policies/_default/sandbox.rego` | Stop-rule policy bundle | EXTEND with rule 6 + closed-enum reason | Stop-rule; AGENTS.md L150 stop-rule entry update |
| `sandbox/protocol.py` | (Sprint 8.5 + Sprint 10 T7) `SandboxRefusalReason` 22-value (T7 already shipped `sandbox_credential_request_tenant_mismatch`) | EXTEND to 26-value (+4 at T9; see §6.1 for the enumeration) | n/a — typing module |
| `sandbox/audit.py` | OFF gate per Doctrine F | EXTEND with 3 new lifecycle event payloads | Stays OFF gate (Doctrine F still applies; CC-adjacent extension) |
| `sandbox/backends/docker_sibling.py` + `kubernetes_pod.py` | ON the gate (Sprint 8B) | EXTEND `create()` with `requires_credentials` mint + `destroy()` with revoke | Stay ON the gate; floor-pin during touching commit |

**Z-style promotion at sprint close: +3 modules (81 → 84)** — `core/vault.py` + `core/_vault_transport.py` + `sandbox/credentials.py`. Brainstorm Round 1's "+2 → 83" undercount missed `_vault_transport.py`'s automatic CC inclusion by `core/` stop-rule.

### 8.2 New settings in `core/config.py` (Sprint 10)

```python
vault_http_timeout_s: float = Field(default=10.0, gt=0.0, le=60.0, ...)
vault_http_max_retries: int = Field(default=3, ge=0, le=10, ...)
sandbox_kernel_default_max_credential_ttl_s: int = Field(default=900, ge=60, le=86400, ...)
# (vault_addr, vault_token, vault_namespace — already exist from Sprint 1C)
```

Bounded settings (positive, ≤cap); pin via `test_config.py` extension (mirror Sprint 9.5 C1 pattern).

### 8.3 CC promotion ritual at sprint close (Z1)

Per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`:
- Run `tools/check_critical_coverage.py` against fresh `coverage.json` (full suite, `--cov-branch`) in the SAME commit as the `_CRITICAL_FILES` extension
- **All 3 new modules** (`core/vault.py` + `core/_vault_transport.py` + `sandbox/credentials.py`) must reach 95/90 line/branch floors BEFORE the gate-count bump lands
- If any is below floor: focused negative-path repair in the SAME commit (per Sprint 9.5 Z1 precedent at lifecycle_routes.py 91.08% repair)
- Gate count bump: `_EXPECTED_ENTRY_COUNT` **81 → 84** + **3 new `_CRITICAL_FILES` tuple entries** with the 0.95 / 0.90 floors

### 8.4 Real-Vault integration test (Z2-style)

Mirror Sprint 9.5 Z2's real-cosign two-layer proof pattern:
- Env-gated on `COGNIC_RUN_VAULT_INTEGRATION=1`
- Layer 1: direct `lease_credential` + `revoke_credential` round-trip against a real `vault` binary on PATH (or a test Vault server URL)
- Layer 2: full sandbox `create()` + `destroy()` with `requires_credentials` against a real Vault → assert lease minted at create, revoked at destroy, lease metadata visible in audit events
- Fail-loud on missing `vault` binary or Vault server (no silent skip; mirrors `feedback_canonical_artifact_not_oss_substitute`)

---

## 9. Test surface

### 9.1 New test files (NEW Sprint 10)

| File | Surface | Test count target |
|---|---|---|
| `tests/unit/core/test_vault.py` | `core/vault.py::lease_credential` + `revoke_credential` happy + 3 mint-failure mappings + 1 revoke-error mapping | 6-8 |
| `tests/unit/core/test_vault_transport.py` | `core/_vault_transport.py` transport — retry behavior + auth refresh + bounded backoff + 5xx/404/403 mapping | 6-10 |
| `tests/unit/sandbox/test_credentials.py` | NEW — `sandbox/credentials.py::VaultCredentialAdapter` implementing extended `CredentialAdapter` Protocol; sentinel-vs-real adapter discrimination at admit_policy; isinstance check still works | 5-8 |
| `tests/unit/sandbox/test_admit_credentials.py` | `admit_policy()` extension — `requires_credentials` threaded into Rego input dict; 4 refusal pathways (Rego TTL-cap + 3 mint-failures); cross-tenant request refused at construction | 8-10 |
| `tests/unit/sandbox/test_credential_lifecycle.py` | Lifecycle: mint at create (post-admission), revoke at destroy, fail-soft revoke emits structured event + continues cleanup; 3 new SandboxLifecycleEvent payloads | 6-8 |
| `tests/unit/policies/test_sandbox_rego_credentials.py` | Rule 6 — TTL cap; tenant overlay + kernel default; type-check defense-in-depth (Sprint 8A T11 R2-R3 pattern); refusal value matches the new SandboxRefusalReason value | 6-8 |
| `tests/unit/sandbox/test_lease_dataclass_landscape.py` | Three-dataclass landscape pin (SecretLease + VaultLeaseRef + CredentialLease are distinct types) | 2-3 |
| `tests/integration/sandbox/test_real_vault_credential_lifecycle.py` | Env-gated real Vault round-trip (§8.4) | 2-3 (env-gated) |

**Test count target: ~40-55 new unit + 2-3 integration.**

### 9.2 Extensions to existing tests

| File | Extension |
|---|---|
| `tests/unit/test_config.py` | 3-4 tests for new Sprint 10 settings (defaults + bounds + env-var input + invalid-value refusal) |
| `tests/unit/sandbox/test_admission_pipeline.py` | Backward-compat: existing tests pass with default `requires_credentials=()` (zero impact) |
| `tests/unit/sandbox/test_audit_event_taxonomy.py` | 3 new payload-shape tests for the new lifecycle events |
| `tests/unit/db/test_vault_adapter.py` | Refactor-impact tests: `VaultAdapter` delegates hvac calls to the shared `VaultTransport`; backward-compat for `__init__(addr, token, namespace)` 3-arg shape (no `transport=` kwarg required for existing callers; defaults to lazily building one). |
| `tests/unit/sandbox/backends/test_docker_sibling_lifecycle.py` | NEW backend-side test: `create(requires_credentials=[...])` mints + injects tokens into container env; destroy revokes |
| `tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py` | Same as above for K8s backend |

### 9.3 BUILD_PLAN-named tests (3 from §10)

- `test_vault_lease.py` — landed under `tests/unit/core/test_vault.py` per §9.1
- `test_sandbox_credential_lifecycle.py` — landed at the named path under §9.1
- `test_credential_ttl_cap.py` — folded into `test_sandbox_rego_credentials.py` per §9.1 (TTL cap is Rego-driven; that's where the test belongs)

---

## 10. Out of scope

Explicitly deferred to future sprints or out-of-band tooling:

- **Per-class per-tenant TTL caps** (e.g. DB credentials 1h, payment-API 5min). Wave 1 flat cap only. Future-work if banks demand.
- **Retry-on-revoke-failure / pending-revocation queue.** Fail-soft single-attempt only. Vault TTL is the safety net.
- **Lease renewal** (`renew(lease_id, ttl_s)`). Wave-1 leases are short-lived one-shots; renewal is Wave 2 if needed.
- **Per-backend token normalization.** `token: dict[str, str]` passthrough; banks read the keys they need (DB has `username`/`password`; AWS has `access_key`/`secret_key`/`session_token`; etc.). No kernel-side schema enforcement.
- **Vault auth methods beyond static token.** Sprint-1C and Sprint 10 both consume the operator-pre-minted `Settings.vault_token` only — there are no AppRole / Kubernetes ServiceAccount / JWT-OIDC auth settings in `core/config.py` today. Adding those flows needs (a) new `Settings.vault_approle_role_id` / `vault_approle_secret_id` / `vault_k8s_role` / `vault_k8s_jwt_path` settings, (b) transport-level periodic-refresh logic (the dynamic-auth flows return a renewable token; static doesn't), (c) consideration of credential storage / rotation. Future work after Sprint 10 ships static-token Wave 1.
- **Scheduler-time admission.** ADR-022 Sprint 10.5 wraps `sandbox.create()` in `SchedulerEngine.submit()`; the `requires_credentials` shape Sprint 10 ships flows through unchanged. No Sprint-10 scheduler hooks.
- **Cognic Forge (model-leasing).** ADR-013 §"Wave 2" sets Forge as a separate repo; this sprint does NOT extend `core/vault.py` to model-artifact leasing.

---

## 11. Phase-3 partial closure (Sprint 10 = sandbox-credentials sub-arc only)

Sprint 10 does NOT close Phase 3 — it closes the **Vault-credential-leasing sub-arc** within Phase 3. Phase 3 itself does not close until Sprint 10.5 lands.

- **What Sprint 10 closes:** the sandbox-credentials gap explicitly deferred by Sprint-8A (per ADR-004 §25 + §68 + §102). The real `VaultCredentialAdapter` lands; sandboxes can mint short-TTL credentials at create + revoke at destroy. The fail-loud `KernelDefaultCredentialAdapter` sentinel stays as the kernel default for safety but becomes unreachable in normal operation once banks wire `VaultCredentialAdapter` at `create_app` time.
- **What still blocks Phase-3 exit:** **Sprint 10.5** (Runtime scheduler / work queue per ADR-022, 3 work-units, BUILD_PLAN §10.5). Phase 3 itself does NOT close until the scheduler primitive lands. Per BUILD_PLAN §10.5 "Phase 3 exit": *"AgentOS provides bank-grade isolation + audit-evidence-export ready for examiner + model lifecycle registry that closes the 'which fine-tuned model handled which case' procurement gap, **plus the ADR-022 runtime scheduler substrate that manages work admission, priority, cancellation, backpressure, and quota refusal before sub-agents arrive.**"* The bolded clause is the Sprint 10.5 dependency that Sprint 10 does NOT discharge.
- **Sprint-10.5 forward-compat:** Sprint 10.5 wraps `sandbox.create()` in `SchedulerEngine.submit()` per the existing forward-compat hook noted in ADR-004 §69; the `requires_credentials` kwarg Sprint 10 ships flows through unchanged into `SchedulerEngine.submit(..., requires_credentials=...)` later. The Sprint 10 API shape is designed to be Sprint-10.5-ready (the kwarg surface name + position do not change at the scheduler-wrap boundary).

---

## Appendix A — open spec-time questions (for Round 2 brainstorm if needed)

None identified — the 7 axes (A-G) + 2 Q1+Q2 design calls + the 6 sub-edges in §1-§8 all closed during the brainstorm. The spec is self-contained for plan derivation.

If the user identifies open edges during review (e.g., "actually I want per-class TTL caps in Wave 1" or "I'd rather we did fail-loud revoke + retry"), Round 2 brainstorm will reopen the affected axes and re-derive the spec sections.

## Appendix B — plan-derivation guidance (for the writing-plans skill)

Suggested task arc (8-10 tasks; 2 work-units total):

1. **T1 — Spec commit** (this file + spec self-review per writing-plans skill)
2. **T2 — `core/_vault_transport.py` shared transport** (wraps `hvac.Client` + auth/retry/connection management; no consumers yet; can land independently). CC by `core/` stop-rule.
3. **T3 — `db/adapters/vault_adapter.py` refactor to consume shared transport** (public API unchanged; optional `transport=` kwarg added; floor-pin during commit). CC stays.
4. **T4 — `core/vault.py` `VaultLeaseActorRef` + `VaultLeaseRequest` + `CredentialLease` + `lease_credential` + `revoke_credential`** (depends on T2). CC by `core/` stop-rule.
5. **T5 — `CredentialAdapter` Protocol extension** (sandbox/admission.py; `mint_lease` + `revoke_lease`; `KernelDefaultCredentialAdapter` stub extension fail-loud).
6. **T6 — `sandbox/credentials.py` real `VaultCredentialAdapter`** (depends on T4 + T5; the off-gate-to-on-gate promotion target).
7. **T7 — `admit_policy()` signature + Rego input extension** (CC stop-rule; depends on T5; threads `requires_credentials` + the Actor → `VaultLeaseActorRef` projection at the call site).
8. **T8 — `policies/_default/sandbox.rego` rule 6 + TTL cap** (stop-rule; depends on T7).
9. **T9 — `sandbox/protocol.py` closed-enum extensions** (`SandboxRefusalReason` 21 → 26, `SandboxLifecycleEvent` 12 → 15) + `sandbox/audit.py` lifecycle event payloads (depends on T7+T8).
10. **T10 — Backend-side create/destroy threading** (Docker + K8s — `SandboxBackend.create()` per-backend; mint at create post-admission, revoke fail-soft at destroy; depends on T6+T7+T9). **NOT a new `sandbox/session.py` module** — the BUILD_PLAN §10 name is stale; Sprint 8A landed the session machinery via `sandbox/protocol.py::SandboxBackend.create()` + per-backend implementations.
11. **Z1 — CC gate promotion (+3 → 84) + fresh coverage verification** (depends on all preceding tasks; promotes `core/vault.py` + `core/_vault_transport.py` + `sandbox/credentials.py`).
12. **Z2 — Real-Vault integration proof (env-gated)** (depends on T6+T10).
13. **Z3 — Doc reconciliation:**
    - BUILD_PLAN §10 (correct the stale `sandbox/session.py` name; reflect the 3-module CC promotion)
    - ADR-004 §25/§68/§102 (note Sprint 10 has landed the `VaultCredentialAdapter` + `mint_lease`/`revoke_lease` Protocol extension)
    - AGENTS.md L188 (mark the `sandbox/credentials.py` promotion as executed)
    - AGENTS.md L48 critical-controls list (add `core/vault.py` + `core/_vault_transport.py` if not already implicit via the `core/` stop-rule)

Estimate: T2-T10 are ~1.5 work-units; Z1-Z3 are ~0.5 work-units. Total fits the BUILD_PLAN §10 2-work-unit budget.

Each CC task (T2 + T3 + T4 + T5 + T6 + T7 + T8 + T9 + T10 + Z1) gets halt-before-commit per the existing session pattern. T2 + T4 are `core/` modules — CC by `core/` stop-rule by automatic rule; halt-before-commit applies.

---

**END OF SPEC.** Ready for user review. On approval, proceed to `docs/superpowers/plans/2026-05-23-sprint-10-vault-credential-leasing.md` per the writing-plans skill arc.
