# Sprint 9 — ISO 42001 control mapping — design spec

**Date:** 2026-05-21
**Status:** approved
**Subsystem:** compliance evidence (`compliance/iso42001/`) + portal surface + governance-hook tagging
**Relevant ADRs / plan:** ADR-006 (ISO/IEC 42001 control mapping), `docs/BUILD_PLAN.md` §752

---

## 1. Problem statement

Cognic AgentOS implements the mechanisms ISO/IEC 42001 requires (audit, decision
history, escalation, citation verification, …) but does not yet expose them as an
**examiner-ready evidence pack** tagged with the ISO 42001 Annex A control IDs an
auditor traces. ADR-006 calls for a `compliance/iso42001/` module: a control registry,
governance-hook control tagging, and a signed, tamper-evident evidence-pack export.

## 2. Scope

**In scope (Sprint 9, ~2 work-units):**
- New `compliance/iso42001/` package — control registry, domain-separated Merkle helper,
  evidence-pack exporter, evidence-pack signing.
- Two examiner portal endpoints under a new `portal/api/compliance/` route package.
- Two new RBAC scopes for those endpoints.
- Control-tagging **gap-fill** so each of the 8 ADR-006 controls has ≥1 hook emitting it.

**Already in place — not re-touched:** the `iso_controls: tuple[str, ...]` field on
`AuditEvent` / `DecisionRecord`, the `iso_controls` DB columns, and `append`
persistence. The BUILD_PLAN deliverable "`core/audit.py` extension — `append(event,
iso_controls=())`" is already done; Sprint 9 does **not** modify `core/audit.py` or
`core/decision_history.py`.

**Out of scope:** AIUC-1 mapping (ADR-006 Wave 2); control-area sub-filtering on the
export API; retrofitting *every* governance hook (ADR-006's long-term aspiration — see
§9); a new event store (the trace explorer reads existing tables).

## 3. Module structure — `src/cognic_agentos/compliance/iso42001/`

| File | Responsibility |
|---|---|
| `__init__.py` | Package marker + public re-exports. |
| `controls.py` | Control registry — the 8 ADR-006 controls, canonical IDs, intended-hook map, coverage-audit helper. Source of truth. |
| `merkle.py` | Domain-separated Merkle tree over chain-row hashes. Pure-functional; no `core/canonical.py` dependency. |
| `signing.py` | Evidence-pack manifest signing — resolve the signing key, `cosign sign-blob`, fail-loud. |
| `evidence_pack.py` | `export_evidence_pack(...)` orchestrator — query rows → Merkle tree → per-control coverage → manifest → sign → tarball. |

`portal/api/compliance/` (route package — see §8): `evidence_pack_routes.py`,
`trace_routes.py`, `router.py`.

## 4. Control registry — `controls.py`

A frozen registry of the **8 ADR-006 Wave-1 controls**: `A.6.2.5`, `A.6.2.6`, `A.7.4`,
`A.7.6`, `A.8.2`, `A.8.5`, `A.9.2`, `A.10.2`.

**Canonical control-ID form (locked).** The registry's canonical ID — the value emitted
into `iso_controls` and stored on chain rows — is the **`ISO42001.`-prefixed** form,
e.g. `ISO42001.A.6.2.5`. The codebase today emits a mix (`A.7.4` raw *and*
`ISO42001.A.7.4` prefixed); Sprint 9 pins `ISO42001.A.x.y` as canonical. A separate
`display` field carries the bare `A.x.y` for human-facing surfaces. The registry
exposes a closed-enum `Literal` of the 8 canonical IDs.

Each registry entry: `control_id` (canonical), `display`, `title`, and
`intended_hooks` — the Cognic hook(s) from ADR-006's table that should tag this control.

The registry provides a coverage-audit helper used by the test suite to assert **8/8
controls each have ≥1 hook emitting the canonical ID**. The registry is *read* by the
evidence-pack exporter to build the per-control coverage section; it is **never**
imported by `core/` (dependency arrow: `compliance/` → `core/`, never the reverse).

## 5. Merkle helper — `merkle.py`

Builds the evidence pack's integrity proof (Q1 locked).

- **Leaves = existing canonical chain hashes.** Each leaf is an in-scope row's
  already-computed canonical hash-chain hash — the `hash` column of `_audit_event` /
  `_decision_history` (raw 32-byte SHA-256; `prev_hash` is the predecessor link, `hash`
  is this row's hash). No row re-canonicalisation; `core/canonical.py` is untouched and
  not imported.
- **Domain separation.** RFC-6962-style distinct prefixes — leaf hash =
  `SHA-256(0x00 ‖ row_hash)`, internal node = `SHA-256(0x01 ‖ left ‖ right)` — so
  leaf and internal hashes are unambiguous. The exact prefix bytes are pinned here and
  live only in `merkle.py`, never in `core/canonical.py`.
- **Deterministic leaf ordering (wire-public — pinned here).** Leaves are ordered by
  `(source_chain, sequence)`. `source_chain` is a fixed identifier per source table,
  ordered **`audit_event` before `decision_history`**. `sequence` is the table's
  `sequence` column — `BigInteger`, `nullable=False`, `unique=True`, present on both
  `_audit_event` and `_decision_history` — the monotonic chain ordinal. No filesystem-
  or query-order dependence; no deferral to the plan.
- **Odd-node handling.** RFC-6962 style — a lone rightmost node is promoted unchanged to
  the next level. Pinned for determinism.
- Supports per-leaf **inclusion proofs** (enables future selective disclosure; not
  surfaced on the Sprint-9 API).

Pure-functional, fully unit-testable in isolation.

## 6. Evidence-pack export — `evidence_pack.py` + `signing.py`

### 6.1 API

`export_evidence_pack(*, engine, tenant_id, period_start, period_end,
signing_key_path, secret_adapter) -> bytes` — returns the tarball bytes. `engine` is an
`AsyncEngine` (§7); `signing_key_path` + `secret_adapter` drive signing (§6.3).

### 6.2 Tarball contents

Mirrors the `cli/sign.py` signing discipline — the Sigstore bundle is preserved, not
dropped:

| Member | Content |
|---|---|
| `manifest.json` | The signed blob — see §6.4. |
| `manifest.json.sig` | `cosign sign-blob` signature over `manifest.json`. |
| `manifest.json.bundle.sigstore` | The cosign Sigstore bundle (mirrors `cli/sign.py`'s `bundle.sigstore`). |
| `decision_history.jsonl` | In-scope `_decision_history` rows — see §6.2.1 row shape. |
| `audit_event.jsonl` | In-scope `_audit_event` rows — see §6.2.1 row shape. |

### 6.2.1 Evidence-row JSONL shape (wire-public)

Each `*.jsonl` line is one table row as a JSON object carrying every column of the
source table. Encoding is pinned (examiner-facing wire format):
- `prev_hash` and `hash` — the chain-hash columns — are **lowercase hex strings**.
  The field names match the DB columns exactly (`prev_hash`, `hash`); no rename layer.
- `created_at` — ISO-8601 UTC string.
- `iso_controls` — JSON array of canonical control-ID strings.
- `payload` — the JSON object as stored.
- `record_id` / `sequence` / `tenant_id` / `event_type` / `request_id` / `trace_id` /
  `span_id` etc. — as-is.

The Merkle leaf for a row is the **raw 32 bytes** of that row's `hash` value (the hex
string in the JSONL decoded back to bytes).

### 6.3 Signing (Q2 locked)

A new `Settings.evidence_pack_signing_key_path: str | None` — **distinct** from
`Settings.signing_key_path` (which is pack-publisher identity for `agentos sign
--bundle`; evidence-pack signing is the AgentOS *instance* trust role). Accepted forms:
- `vault://secret/path/...` — production-preferred; resolved through the `SecretAdapter`.
- `/secure/.../evidence-pack-key.pem` — filesystem PEM; operator escape hatch, same
  strict validation posture as existing signing code.

**Fail-loud (locked).** A missing key *or* a missing `cosign` binary → `export_evidence_pack`
**raises**. There is no best-effort unsigned pack — an unsigned examiner artifact is
forbidden.

**Stable signing identity (locked).** When the key is resolved from Vault, the manifest
records the `vault://...` URI as the signing identity — not the temporary PEM path
written to disk for the `cosign` invocation. Mirrors `cli/sign.py`; avoids leaking
`/tmp` paths while preserving the auditable identity.

### 6.4 `manifest.json` schema (wire-public — stop-rule surface)

`schema_version`, `agentos_version`, `tenant_id`, `period_start`, `period_end`,
`generated_at`, `merkle_algorithm` (the domain-separated SHA-256 scheme identifier),
`merkle_root` (hex), `decision_history_row_count`, `audit_event_row_count`,
`signing_identity`, and `per_control_coverage` — the registry-driven section: each of
the 8 controls → row count tagged + the hooks observed.

### 6.5 Examiner verification path

`cosign verify-blob --key <pub> --signature manifest.json.sig manifest.json` (or via the
Sigstore bundle) → recompute the Merkle root from the bundled `*.jsonl` rows using the
`merkle.py` scheme (leaves = each row's `hash` bytes, ordered per §5) → check it equals
`manifest.json`'s `merkle_root` → optionally re-walk each row's canonical hash via the
existing `chain_verifier` to confirm each `hash` (Merkle leaf) is genuine.

## 7. Read seam — `engine: AsyncEngine` read model

The exporter and trace reader need read access to `_decision_history` + `_audit_event`.
Locked design:

- They accept an explicit `engine: AsyncEngine` parameter — **no dependency on private
  store attributes** (`store._engine`) and **no new methods on the `AuditStore` /
  `DecisionHistoryStore` critical-controls classes**.
- They read the **exported Table objects** `_audit_event` (from `core/audit.py`,
  in `__all__`) and `_decision_history` (from `core/decision_history.py`, in `__all__`)
  — the schema definitions, legitimately importable; this is *not* a private-attr reach.
- **Production wiring — a request-time FastAPI dependency.** `app.state.adapters` is
  populated by `create_app`'s lifespan *after* `open_all()` — i.e. after the compliance
  router has already been mounted — so the route package **cannot** closure-capture the
  engine at mount time. Instead `portal/api/compliance/` defines a request-time
  dependency `_require_relational_engine(request) -> AsyncEngine` that reads
  `request.app.state.adapters.relational.engine` per request and **fails loud**
  (HTTP 503) when `app.state.adapters` is `None` (adapters not built / not configured)
  or the engine is otherwise unavailable. The resolved `AsyncEngine` is passed into
  `export_evidence_pack` / the trace reader. `adapters.relational.engine` is the
  `RelationalAdapter.engine` accessor added by #489.
- **Tests** pass an in-memory `AsyncEngine` directly to the `export_evidence_pack` /
  trace-reader functions, bypassing the route dependency.

This keeps `core/audit.py` and `core/decision_history.py` source unmodified while
introducing no fresh private-attribute coupling.

## 8. Portal endpoints + RBAC

### 8.1 Route package

Per current repo style (`portal/api/packs/`, `portal/api/ui/`) — **not** inline in
`app.py` (the BUILD_PLAN names `app.py`; that predates the route-package convention):

- `portal/api/compliance/evidence_pack_routes.py` — `build_evidence_pack_routes(...)`.
- `portal/api/compliance/trace_routes.py` — `build_trace_routes(...)`.
- `portal/api/compliance/router.py` — composition factory.
- `app.py` only **mounts** the composed compliance router.

### 8.2 Endpoints

- `GET /api/v1/compliance/evidence-pack?from=&to=&scope=` — `scope` = `tenant_id`; one
  pack = one tenant + period. Returns the signed tarball. Gated by
  `compliance.evidence_pack.read` + a `RequireTenantOwnership`-style guard
  (`actor.tenant_id == scope`).
- `GET /api/v1/traces/{trace_id}` — chain-walked run timeline from `_decision_history` +
  `_audit_event` (ordered parent/child links; examiner-visible provenance preserved).
  Gated by `compliance.trace.read`; rows filtered by `actor.tenant_id`. A `trace_id`
  that exists only in another tenant returns **empty / 404**, never a forbidden-with-hint
  (cross-tenant-invisible doctrine, matching `portal/rbac/tenant_isolation.py`). Not a
  new event store — a read-only walk of existing rows.

### 8.3 RBAC scopes

Two new scopes — bulk disclosure and targeted forensic lookup are distinct examiner
powers, kept as separate atoms so bank overlays can grant them independently:
`compliance.evidence_pack.read` and `compliance.trace.read`.

`portal/rbac/scopes.py` is a wire-protocol-public RBAC stop-rule module. Pinned design:
- A new closed-enum `ComplianceRBACScope = Literal["compliance.evidence_pack.read",
  "compliance.trace.read"]` family, mirroring the existing `PackRBACScope` /
  `UIRBACScope` family pattern.
- A new `EXAMINER_COMPLIANCE_SCOPES: frozenset[ComplianceRBACScope]` holding both
  values. Bank-overlay examiner-role binders grant `EXAMINER_SCOPES |
  EXAMINER_COMPLIANCE_SCOPES` — the kernel ships the scope atoms + the documented
  grouping; it cannot force an overlay's role mapping.
- **`Actor.scopes` widening (required).** `portal/rbac/actor.py` currently types
  `Actor.scopes` as `frozenset[PackRBACScope | UIRBACScope]`. Sprint 9 widens it to
  `frozenset[PackRBACScope | UIRBACScope | ComplianceRBACScope]` so an examiner `Actor`
  can carry the compliance scopes — exactly mirroring the Sprint-7B.4 widening that
  added `UIRBACScope`. `portal/rbac/actor.py` is listed in §13 files-touched.
- The `scopes.py` + `actor.py` changes get explicit RBAC stop-rule review.

## 9. Control-tagging gap-fill

One Sprint-9 task audits the 8 ADR-006 controls against current emission sites and wires
`iso_controls=(...)` **explicitly at the call site** where a control has no hook —
**no** auto-lookup / default injection in `AuditStore` / `DecisionHistoryStore` (that
would invert the `compliance/` → `core/` dependency arrow). Existing emitters of an
ADR-006 control that use the raw `A.x.y` form are reconciled to the canonical
`ISO42001.A.x.y` form. Existing tags for **non-ADR-006** codes (e.g. `packs/lifecycle.py`'s
`A.5.31` / `A.5.32`) are left untouched — out of the Wave-1 8.

The registry's coverage-audit test proves **8/8** controls each have ≥1 hook emitting
the canonical ID. ADR-006's "every governance hook tags" remains the long-term
aspiration the registry enables incrementally, not a Sprint-9 retrofit.

## 10. Critical-controls / stop-rule treatment

- **Evidence-pack format is an AGENTS.md stop rule** ("changes how examiners audit").
  The tarball layout (§6.2), `manifest.json` schema (§6.4), and Merkle byte-framing
  (§5) are wire-public and get explicit human review at spec time and on the format.
- **All four new runtime compliance modules go on the critical-controls coverage gate**
  (95% line / 90% branch) at sprint close — `controls.py`, `merkle.py`, `signing.py`,
  `evidence_pack.py` — they define examiner-facing evidence format, control mapping,
  integrity proof, and signing. Gate count **73 → 77**; verified against fresh
  `coverage.json` at promotion time per `feedback_verify_promotion_meets_floor_at_promotion_time`.
- `portal/rbac/scopes.py` change is an RBAC stop-rule touch (§8.3) — reviewed.
- `core/audit.py`, `core/decision_history.py`, `core/canonical.py` — **not modified**
  (by design — §3 dependency arrow, §5 read seam, §7 no store-method additions).
- The tagging gap-fill (§9) makes one-line `iso_controls=` additions at emission sites
  in `core/` and elsewhere — small, explicit, reviewable; no contract changes.

## 11. Testing

Per BUILD_PLAN §764 plus module-level coverage for the gate:
- `test_control_mapping.py` — every ADR-006 control has ≥1 hook emitting its canonical
  ID (registry coverage-audit helper); 8/8.
- `test_evidence_pack.py` — generate a pack; validate the Merkle root; validate the
  cosign signature + Sigstore bundle.
- `test_evidence_pack_completeness.py` — the pack contains every in-scope audit + decision
  row in the window.
- `test_trace_explorer.py` — the trace timeline walks parent/child chain links in order,
  preserves examiner-visible provenance, and **never returns cross-tenant rows**.
- `merkle.py` unit tests — determinism, domain separation, odd-node handling, inclusion
  proofs.
- Signing fail-loud tests — missing key / missing `cosign` binary → `export_evidence_pack`
  raises.
- RBAC / tenant-isolation tests on both endpoints — scope enforcement + cross-tenant 404.

## 12. Acceptance criteria

- **AC1** — `compliance/iso42001/controls.py` registry holds the 8 ADR-006 controls with
  canonical `ISO42001.A.x.y` IDs; coverage-audit helper present.
- **AC2** — `merkle.py` builds a domain-separated Merkle tree over chain-row hashes with
  deterministic ordering; unit tests green.
- **AC3** — `export_evidence_pack` produces a tarball with `manifest.json` +
  `manifest.json.sig` + `manifest.json.bundle.sigstore` + the evidence `*.jsonl`;
  fail-loud on missing key/binary.
- **AC4** — generated pack passes external verification: `cosign verify-blob` of the
  manifest + independent Merkle-root recomputation.
- **AC5** — `GET /api/v1/compliance/evidence-pack` + `GET /api/v1/traces/{trace_id}` live
  under `portal/api/compliance/`, gated by the two new scopes + tenant isolation;
  cross-tenant requests get 404/empty.
- **AC6** — 8/8 ADR-006 controls each have ≥1 hook emitting the canonical ID
  (`test_control_mapping.py`).
- **AC7** — a trace timeline reconstructs a run from `_decision_history` without UI
  event-stream state.
- **AC8** — the 4 compliance modules pass the 95/90 critical-controls gate; gate 73 → 77.
- **AC9** — full gate ladder green (`ruff`, `ruff format`, `mypy src tests`, full
  `pytest`, critical-controls coverage gate).

## 13. Files touched

**Created:** `src/cognic_agentos/compliance/__init__.py`,
`compliance/iso42001/{__init__,controls,merkle,signing,evidence_pack}.py`,
`portal/api/compliance/{__init__,evidence_pack_routes,trace_routes,router}.py`; the test
modules in §11.

**Modified:** `core/config.py` (`evidence_pack_signing_key_path` setting);
`portal/rbac/scopes.py` (`ComplianceRBACScope` family + `EXAMINER_COMPLIANCE_SCOPES`);
`portal/rbac/actor.py` (`Actor.scopes` widened to include `ComplianceRBACScope`);
`portal/api/app.py` (mount the compliance router); emission sites identified by the §9
gap-fill audit; `tools/check_critical_coverage.py` (gate 73 → 77); `docs/BUILD_PLAN.md`
§752 (status at sprint close).

## 14. BUILD_PLAN reconciliation notes

Two BUILD_PLAN §752 drifts, resolved in this spec:
1. "`core/audit.py` extension — `append(event, iso_controls=())`" — already done; the
   `iso_controls` field/columns/persistence exist. Sprint 9 does not re-do it.
2. "`portal/api/app.py` — `GET …`" — the route-package convention postdates that line;
   Sprint 9 ships a `portal/api/compliance/` package and `app.py` only mounts it.

## 15. Out of scope / deferred

AIUC-1 mapping (ADR-006 Wave 2); evidence-pack control-area sub-filtering; full
"every-hook" tagging retrofit; selective-disclosure API surface (the `merkle.py`
inclusion-proof capability exists but is not exposed on the Sprint-9 API).
