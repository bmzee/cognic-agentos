# ADR-026 — Operator-Grade Pack Install: Lifecycle-Governed Runtime Configuration (Desired/Derived State)

## Status
**APPROVED for M4 implementation** on 2026-06-30. Targets milestone **M4** (production-grade milestone checklist, B-track pack ecosystem). Full design: `docs/superpowers/specs/2026-06-30-m4-operator-pack-install-flow-design.md`. Amends **ADR-012** (lifecycle extension — see the "M4 amendment" section there).

## Context

ADR-012 shipped the bank pack lifecycle (`draft → … → approved → allow_listed → installed → disabled → revoked → uninstalled`) as an RBAC-gated, audit-chained portal API. M2 (Proof 1b-2, PR #103) and M3 (Proof 2, PR #110) proved a deployed pack callable through the governed MCP path. But a read-only scouting pass (2026-06-30) established that the lifecycle DB state is **decoupled from actual callability**:

- The `install` endpoint only flips a DB row — **no** trust / registry / MCP side effect.
- Real callability is gated elsewhere: **boot-time** registration (`harness/registry_boot.py` → `protocol/plugin_registry.register_with_full_attestation_check`: cosign + the `_default` JSON allow-list; baked image tree + pod restart), and **runtime** `protocol/mcp_authz.py` (the MCP server-url override + per-tenant internal-host allow-list carve-outs from PR-2b-1/2b-2).
- The override + internal-host-allowlist operator endpoints (`portal/api/mcp_config/`) exist but are **not mounted** in the deployed app (the stores aren't threaded into `create_app`); the per-tenant Vault OAuth creds + AS allow-list have **no operator API** at all. So the deployed proofs (1b-2, 1b-2c) **seed these directly via SQL / Vault**, bypassing the operator path.
- There is **no runtime install API**; registering a pack is boot-only.

M4's goal is to make the governance controls *matter*: a pack becomes callable **only** through the governed operator path, and `disable` / `revoke` make a previously-callable pack refused. The architectural question is how to reconcile the lifecycle DB state machine with the registration/callability mechanism **without abandoning the immutable-runtime-image posture proven in M3**.

## Decision

Make the **pack lifecycle state govern runtime callability** through a **desired / derived runtime-configuration provisioning model**. Pack *code* registration stays boot-time + cosign-trusted (no live code-load). The lifecycle owns a first-class runtime-config record (authoritative *desired* state) that a **materializer** projects into the existing MCP carve-outs (*derived* state). `mcp_authz` — a critical control — is **not changed**.

The eight positions (full detail in the M4 design spec §3):

1. **No runtime code-load (Approach A).** Pack code stays boot-registered + cosign-trusted (immutable image). Live code registration is explicitly out of scope — a possible future milestone, not M4.
2. **A first-class runtime-config record** per `(tenant, pack)` is the provisioning abstraction — not raw carve-out rows — so future install outputs extend the record, not the lifecycle state machine.
3. **Desired vs derived state.** The record is authoritative *desired* state; the override + internal-host-allowlist rows are *derived* projections. This makes install idempotent, disable/revoke clean, and a future reconcile loop possible.
4. **`configure` is a dedicated lifecycle step** (new endpoint + a new `pack.configure` scope, human-actor-gated) writing the record, required *before* install — separating "operator configured X" from "operator activated X" as distinct audit events.
5. **OAuth by reference.** The record *references* operator-pre-provisioned Vault material (OAuth creds + AS allow-list); `install` *validates* presence/shape but writes no secrets. M4 adds no secret-write API.
6. **Remove-derived for `disable` + `revoke`.** Both retract the derived rows; the pack goes refused through the unchanged `mcp_authz` carve-out-absent path (the live-proven Bar 1 mechanism). They differ only in whether the desired record survives (disable: retained → re-installable; revoke: terminal). **`mcp_authz` is not modified.**
7. **The materializer is the sole writer** of the derived MCP carve-out tables. The existing standalone override / allow-list *write* endpoints are superseded (left unmounted) to avoid two write paths / two sources of truth.
8. **The materializer is idempotent, transactional / recoverable, and retry-safe**, and audits **both** the lifecycle transition and the materialization result. Vault-reference validation (read-only) runs *before* the derived-row transaction commits, so a missing/misshaped reference refuses install before any derived row is written.

**Lifecycle extension (amends ADR-012):** `install` gains a `disabled → installed` re-enable transition (the existing table had only `allow_listed → installed`). `configure` while the record is `active` is **refused** in M4 — a live config change is `disable → configure → install` — so the model never produces desired/derived drift without a reconcile loop (deferred).

**Callability invariant:** a pack is callable iff **(boot-registered + cosign-trusted)** AND **(lifecycle `installed` + materialized carve-outs present)** AND **(Vault OAuth/AS material present)**. The `install` boot-registration check is the explicit reconciliation point between the boot code-trust layer and the per-tenant operator activation layer.

## Consequences

### Positive
- The lifecycle becomes the **real governance + provisioning layer** — install / disable / revoke actually change callability, audited end-to-end.
- **`mcp_authz` (a critical control) is untouched** — callability changes reuse the live-proven refusal path; no new runtime authorization condition in the most sensitive code.
- **Single source of truth** — the desired record is authoritative; the derived rows are recomputable; partial materialization is detectable / recoverable.
- Preserves the **immutable-runtime-image** posture proven in M3 — no dynamic code loading into a running pod.
- **Secrets stay in Vault / operator custody** — OAuth-by-reference avoids a new secret-write surface.
- Enables a **future reconcile loop** without re-architecting (the desired/derived split is the foundation).

### Negative
- A new lifecycle step (`configure`) + a new RBAC scope + a new store / table / migration + a materializer — real scope, and a **critical-controls** change to the lifecycle path (the ADR-012 amendment).
- **Reconfigure-while-active is refused** in M4 (a deliberate constraint) — a live config change requires `disable → configure → install`. Acceptable until a reconcile loop exists.
- **No continuous reconcile loop** in M4 — drift between desired + derived is *prevented* by the active-config refusal, not *detected/corrected* automatically.

### Neutral
- The OAuth Vault material remains operator-provisioned out-of-band (a documented migration step); only the override + internal-host-allowlist rows are materialized by the operator path.
- The deployed proof remains kind (not AKS — that bar is M15/M24).
- Pack code provenance stays a build/boot concern (cosign at boot); per-tenant activation + config is the governed operator concern — an honest separation, not a regression.

## Implementation

Lands under milestone M4 on a `feat/m4-…` branch, subagent-driven per-task with critical-controls scrutiny on the lifecycle / RBAC / materializer changes (per AGENTS.md `core-controls-engineer` + `/critical-module-mode`). Task breakdown in the M4 implementation plan (`docs/superpowers/plans/2026-06-30-m4-…`). The deployed proof extends the proof-1b-2c harness with a multi-actor binder and drives the real operator API (no direct override / allow-list seeding); recorded in `docs/VALIDATION-RESULTS.md`.

## References
- M4 design spec: `docs/superpowers/specs/2026-06-30-m4-operator-pack-install-flow-design.md`
- ADR-012 (bank pack lifecycle — amended by M4; the lifecycle this governs)
- ADR-002 (MCP plugin protocol — the override / allow-list / OAuth runtime config this provisions)
- ADR-023 (per-tenant config overlay — related per-tenant configuration)
- PR #103 (Proof 1b-2) + PR #110 (Proof 2 / M3) — the deployed proofs whose direct seeding M4 replaces
