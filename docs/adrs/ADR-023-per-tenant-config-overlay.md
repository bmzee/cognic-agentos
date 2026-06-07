# ADR-023 — Per-Tenant Configuration Overlay (Wave-2)

## Status

**PROPOSED** — DRAFT 2026-06-07. Human acceptance pending (ADR acceptance is a
Human-only decision per `AGENTS.md` §"Human-only decisions"; this document is
**not** self-accepted). The implementation landed under the spec
`docs/superpowers/specs/2026-06-06-per-tenant-config-overlay-design.md` + plan
`docs/superpowers/plans/2026-06-06-per-tenant-config-overlay.md` (12 TDD tasks)
on branch `feat/per-tenant-config-overlay`, but the doctrine remains PROPOSED
until a human approves it.

## Context

AgentOS ships a single global `Settings` object (`core/config.py`) that pins
kernel-wide caps and floors — sandbox per-tenant CPU/memory/walltime maxima
(ADR-004), the memory-export retention floor (ADR-019), and many others. A bank
deployment runs many tenants against one kernel, and the pre-GA configurability
audit (`docs/superpowers/specs/2026-06-04` workstream) found there was **no
per-tenant overlay**: a regulator that mandates a 10-year memory-export
retention for tenant A, or an operator that wants to cap tenant B's sandboxes
more tightly than the kernel default, had no governed surface to express it.
Every cap was global-or-nothing.

The naïve fix — a free-form per-tenant key/value config store — is dangerous in
a governance kernel:

- A tenant (or a compromised tenant-admin token) could **loosen** a security
  invariant: raise their own sandbox cap, lower their retention floor below the
  regulator minimum, or flip a kernel safety flag (`require_cosign`,
  egress allow-lists, kill-switch posture).
- An open key space means every future `Settings` field silently becomes
  per-tenant-overridable with no review — the opposite of default-deny.
- Per-tenant config drift with no audit trail is unexaminable; an examiner
  cannot reconstruct "what cap was in force for tenant A on date D".

What was needed is a **narrow, default-deny, tighten-only, audited** overlay: a
closed registry of explicitly-overridable fields, where a per-tenant value may
only make that tenant's own limit **stricter** than the kernel/operator base,
administered by a **human operator** (not tenant self-service), with every
mutation and every read-time rejection on the hash-chained evidence record.

## Decision

Ship a per-tenant configuration overlay as a kernel primitive under
`core/config_overlay/`, plus an operator-administered portal surface and two
proven consumers (sandbox admission caps + memory-export retention floor).

### Module layout

```
core/config_overlay/registry.py        # closed default-deny field registry + tighten-only validator
core/config_overlay/storage.py         # Postgres-backed in-closure atomic store + chain events
core/config_overlay/resolver.py        # fail-closed request-time resolution + invalid_at_read audit
portal/api/config_overlay/routes.py    # operator-administered, human-only PUT/DELETE/GET
db/migrations/versions/...0007_tenant_config_overlay.py
```

### 1. Closed registry + default-deny + tighten-only (the core invariant)

`registry.REGISTRY` is a closed `dict[str, OverridableField]`. A field is
overridable **only if it appears in the registry** — any other key is refused
(`tenant_overlay_field_not_overridable`). This is default-deny: the global
`Settings` surface is NOT per-tenant-overridable by default; promoting a field
requires a deliberate registry edit (and review).

Each `OverridableField` declares a **direction**:

- `ceiling` — the overlay value must be `> 0` and `<= base_value` (the tenant
  may only **lower** their cap). Used by the sandbox maxima.
- `floor` — the overlay value must be `>= kernel_floor` (a non-loosenable
  kernel minimum) **and** `>= base_value` (the tenant may only **raise** their
  floor). Used by the memory-export retention floor.

Wave-1 registry (4 fields): `sandbox_per_tenant_max_cpu` (ceiling, float),
`sandbox_per_tenant_max_memory` (ceiling, int), `sandbox_per_tenant_max_walltime`
(ceiling, float), `memory_export_retention_seconds` (floor, int, kernel-locked
at the 7-year ADR-019 minimum).

`validate_tighten_only(field, *, base_value, proposed)` is the single
pure-functional gate. Coercion is **strict**: `bool` is never accepted as a
number (it is an `int` subclass); non-finite floats (`nan`/`inf`/`-inf`) are
refused; an `int`-typed field rejects a fractional value rather than truncating
("no silent fractional int coercion"). The closed `OverlayRefusalReason` (6
values) is the wire-protocol contract: `tenant_overlay_field_not_overridable`,
`tenant_overlay_value_not_coercible`, `tenant_overlay_ceiling_not_positive`,
`tenant_overlay_loosens_ceiling`, `tenant_overlay_below_kernel_floor`,
`tenant_overlay_below_base_floor`. For a floor field the kernel-floor check runs
**before** the base check (the kernel minimum is the more fundamental refusal).

### 2. Storage — in-closure atomic mutation + chain evidence (ADR-006/009)

`TenantConfigOverlayStore` (Postgres-backed, migration `0007`) drives every
mutation through `DecisionHistoryStore.append_with_precondition`: the
overlay-row upsert/delete and the hash-chained evidence row commit in **one
transaction** with a row + chain-head `FOR UPDATE` lock (the
`packs/storage.py` / `models/storage.py` pattern). It emits two wire-public
chain events, each tagged ISO `A.6.2.5` (Operational responsibilities):

- `config.tenant_overlay.set` — payload carries `tenant_id`, `field_key`,
  `direction`, `base_value`, `overlay_value`, `previous_overlay_value`,
  `actor_subject`, `actor_type` (the chain payload is the evidence snapshot — an
  examiner reads the cap-change history from the chain alone).
- `config.tenant_overlay.cleared` — symmetric, carries the prior value.

A refusal rolls the transaction back (no chain row, no orphan overlay row).

### 3. Resolver — fail-closed request-time resolution (posture R) + A.9.2

`TenantConfigResolver.effective(field_key, tenant_id)` /
`effective_many(field_keys, tenant_id)` is the consumer-facing decision point.
One store read per call (a single snapshot — never per-field reads, to close the
concurrent-mutation interleaving window). Resolution:

- No stored overlay → return the base `Settings` value.
- A valid (still-tightening) stored overlay → return it.
- An **invalid** stored overlay → **fail closed** (posture R): raise
  `TenantConfigOverlayInvalid` AND emit a throttled
  `config.tenant_overlay.invalid_at_read` AUDIT incident. It never silently
  falls back to the base value. An overlay can become invalid after the fact —
  e.g. the operator later tightens the kernel base **below** a
  previously-accepted overlay, or a row is corrupted — and a governance kernel
  must refuse rather than serve a stale, now-loosening value.

The `invalid_at_read` incident is tagged ISO **A.9.2** (System and operational
logging) and written through the **audit** store (`AuditStore.append`), NOT the
decision-history mutation path — it records an operational anomaly, not an
intended state transition. It carries a minted request-id (`AuditEvent` requires
one) and is **throttled** per `(tenant_id, field_key, reason)` + stored value:
the runtime refusal itself is never throttled (every consumer call fails
closed), only the audit row is rate-limited to avoid a hot-path log storm; the
throttle entry updates only on a **successful** audit write, so a failed write is
retried on the next occurrence. If the audit write itself fails, the audit
exception is logged and swallowed; the typed overlay refusal
(`TenantConfigOverlayInvalid`) still propagates so downstream consumers hit their
closed-enum mapping.

### 4. Operator-administered, human-only portal surface (ADR-008/012 §40)

`portal/api/config_overlay/routes.py` exposes three endpoints under `/api/v1`:

- `PUT  /tenants/{tenant_id}/config-overlay/{field_key}` — set an overlay.
- `DELETE /tenants/{tenant_id}/config-overlay/{field_key}` — clear it.
- `GET  /tenants/{tenant_id}/config-overlay` — list a tenant's overlays.

The model is **operator-administered**, not tenant self-service: an operator
sets configuration *for* a tenant. Consequently there is **no
`RequireTenantOwnership`** gate — a cross-tenant operator holding the scope is
allowed (the scope IS the boundary). The PUT/DELETE mutation surface is
additionally **human-only** (`RequireHumanActor`) per the `AGENTS.md`
"Per-tenant ... changes" Human-only-decisions rule — a service-token actor
holding the write scope is refused at the dependency chain before the handler
runs. GET is read-only and permits service actors.

The wire-public `ConfigOverlayRBACScope` (2 values, namespace-disjoint from
every other scope family): `config.tenant_overlay.write` (PUT/DELETE, human-only)
and `config.tenant_overlay.read` (GET). The request DTO is `StrictInt |
StrictFloat` — JSON `true`/`false` and string `"2"` are refused at the request
boundary so a non-numeric value can never reach the registry pre-coerced (the
registry bool-guard is the second line of defence; the DTO is the first). The
path `field_key` is registry-gated (`overridable_field`) **before**
`getattr(settings, field_key)` runs, so a caller cannot name an arbitrary
`Settings` attribute via the URL.

### 5. Proven consumers

- **Sandbox admission caps (ADR-004).** `admit_policy(..., resolver:
  TenantConfigResolver | None = None)` resolves the three sandbox caps **once**
  and feeds the same effective values into both the Step-5 Python tenant-max
  check **and** the Step-9 Rego `tenant_max` input (single source — the two
  layers can never disagree). A corrupt overlay fails closed with the new
  `SandboxRefusalReason` value `sandbox_tenant_config_overlay_invalid`. The
  resolver is **optional** and the sandbox path is **seam-only**: there is no
  Runtime-owned sandbox backend, so no production caller threads a resolver yet;
  when `None`, admission uses the base settings caps (byte-equivalent to
  pre-ADR-023). This keeps the "no Runtime→sandbox overlay path" claim honest.

- **Memory-export retention floor (ADR-019).** `MemoryAPI(..., resolver:
  TenantConfigResolver | None = None)`; `export()` resolves
  `memory_export_retention_seconds` via the resolver when wired (a tenant may
  raise the floor above the base), else uses the base setting. The resolved
  value is accepted only if it is a real `int` (bool rejected; a fractional
  float fails closed — no silent truncation). A corrupt overlay fails closed
  with the new `MemoryRefusalReason` value
  `memory_export_tenant_config_overlay_invalid`. Memory **is** production-wired:
  the composition root threads a real resolver into the `MemoryAPI` factory.

### 6. Composition root + ISO mapping

`harness/build_runtime` builds the store + resolver **unconditionally** (the
overlay surface is independent of memory/cache) and before the leak-prone HTTP
client (both are pure constructors), threads the resolver into the `MemoryAPI`
factory, and exposes `config_overlay_store` / `config_overlay_resolver` on the
`Runtime`. `create_app` mounts the overlay router via a 3-state gate (both
deps → mount + `app.state.config_overlay_router_mounted`; partial → fail-loud
warning; neither → no mount), mirroring the packs router. The sandbox resolver
is deliberately **not** wired into any sandbox create path (seam-only).

ISO 42001 mapping (ADR-006): `config.tenant_overlay.{set,cleared}` are added to
the **A.6.2.5** (Operational responsibilities) control's intended hooks. The
resolver's `config.tenant_overlay.invalid_at_read` is tagged **A.9.2** and is
covered by that control's existing `audit.append` surface hook.

### 7. Critical-controls

`core/config_overlay/{registry,storage,resolver}.py` +
`portal/api/config_overlay/routes.py` are on the durable per-file
critical-controls coverage gate (95% line / 90% branch); the gate count moved
113 → 117. `core/config.py` (global Settings) stays off-gate — it is not
overlay-specific. `core/config_overlay/*` and the portal route module are
`core/`-and-RBAC stop-rule surfaces (Human-only-decisions enforcement boundary).

## Consequences

**Positive**

- A bank can express per-tenant regulatory tightening (longer retention, tighter
  sandbox caps) through one governed, audited surface — no code change.
- Default-deny + tighten-only makes per-tenant config **safe**: a tenant can
  never loosen a kernel security invariant, only constrain themselves further.
- Every mutation is hash-chained (A.6.2.5) and every read-time rejection is an
  audited incident (A.9.2); an examiner can reconstruct the cap history.
- Fail-closed posture R means a corrupted/stale overlay refuses rather than
  silently serving a now-loosening value.

**Negative / costs**

- A new closed registry is one more thing to review when promoting a field to
  per-tenant-overridable (by design — the friction is the safety).
- Two resolver instances may exist in production (one in the `MemoryAPI`
  factory, one passed to `create_app` for the router) reading the same engine;
  their per-instance audit-throttle caches are independent (acceptable — the
  throttle only rate-limits the A.9.2 log, never the refusal).
- The sandbox consumer is seam-only until a Runtime-owned sandbox backend
  exists; per-tenant sandbox-cap tightening is unit-proven but not yet on a
  production Runtime→sandbox path.

## Alternatives considered

- **Free-form per-tenant key/value config** — rejected: an open key space lets a
  tenant loosen security invariants and silently makes every `Settings` field
  overridable with no review. The closed registry is the whole point.
- **Per-tenant Rego policy bundles (ADR-015)** — rejected for Wave-1: heavier,
  and the tighten-only numeric-cap problem is a registry + comparator problem,
  not a policy-evaluation problem. A future field whose override is genuinely
  policy-shaped can still route through Rego.
- **Tenant self-service overlay endpoint** — rejected: per-tenant config change
  is a Human-only decision (`AGENTS.md`); the operator-administered + human-only
  model is the governance-correct shape.
- **Required resolver on the consumers** — rejected (locked to optional + base
  fallback): a required resolver would force a sandbox backend-constructor
  cascade before any Runtime→sandbox overlay path exists, blurring the
  seam-only scope and overclaiming production wiring.

## Deferred (Wave-2+)

- Additional registry fields (more sandbox/memory/gateway caps) as banks request
  them — each a deliberate registry edit + review.
- A production Runtime→sandbox overlay path (the sandbox consumer is seam-only
  today); when a Runtime-owned backend lands, thread the exposed resolver into
  its create path.
- Policy-shaped overrides via Rego for fields that are not simple numeric
  ceilings/floors.
- Operator UI for the overlay surface (Studio, deferred per ADR-008/021).

## References

- Spec: `docs/superpowers/specs/2026-06-06-per-tenant-config-overlay-design.md`
- Plan: `docs/superpowers/plans/2026-06-06-per-tenant-config-overlay.md`
- ADR-004 (sandbox primitive — per-tenant caps), ADR-019 (agent memory
  governance — export retention), ADR-006 (ISO 42001 control mapping +
  hash-chain canonical form), ADR-009 (pluggable persistence), ADR-008 (authoring
  platform — operator surface), ADR-012 §40 (portal RBAC + Human-only model).
