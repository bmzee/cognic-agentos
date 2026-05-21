# ADR-006 — ISO/IEC 42001 Control Mapping

## Status

**Amended on 2026-05-18** (this revision) — Sprint 8.5 T1 amendment shipped alongside the resumable-session-API design spec. Extends the A.6.2.5 (Operational responsibilities) row from 8 → **12 sandbox lifecycle events** (adds `sandbox.lifecycle.checkpointed` / `.suspended` / `.woken` / `.checkpoint_purged` per Sprint 8.5 spec §3.3) AND extends the `SandboxRefusalReason` taxonomy from 15 → **21 values** (adds 6 wake-time refusal arms per spec §3.3: `sandbox_wake_checkpoint_not_found` / `_corrupt` / `_retention_expired` / `_session_tombstoned` / `_tenant_mismatch` / `_policy_revalidation_failed`). Also documents the Sprint-8.5 destroy() payload extension (2 new conditional payload keys `retained_until` + `tombstone_object_key` per spec §5.1 — presence is the wire-public marker that retention is in effect). Chain verifier walks the suspend → wake transition via explicit payload keys (`suspend_event_id` + `restored_from_checkpoint_id`) per spec §5.2 — no `decision_history` schema migration. Tombstoning is a STORAGE artifact, NOT a new lifecycle event.

**Amended on 2026-05-16** — Sprint 8A T1 amendment. Added the original 8 sandbox lifecycle events + `SandboxRefusalReason` 15 values + `SandboxPolicyViolationReason` 6 values (extended from 5 → 6 at Sprint 8A T10c R1 P1.2 with the addition of `egress_audit_unreadable` for fail-closed proxy_log readback) as the wire-protocol-public refusal taxonomies tagged under A.6.2.5.

**APPROVED for implementation** on 2026-04-26.

## Context

ISO/IEC 42001:2023 is the global AI Management System standard. As of April 2026 it's the de facto compliance gold standard — voluntary but adopted across financial services for governance maturity assessments. Banks adopting Cognic AgentOS will need to demonstrate conformance to ISO 42001 controls during examiner audits and (increasingly) for ISO 42001 certification.

Today Cognic AgentOS implements the **mechanisms** ISO 42001 requires (audit, decision history, citation verification, escalation, etc.) but doesn't tag its evidence with the control IDs an auditor needs to trace.

The complementary **AIUC-1** framework is agent-specific — focuses on autonomous action explainability, reversibility, accountability. Cognic should map to both.

## Decision

Add a `compliance/iso42001/` module containing:

1. **Control registry** (`controls.py`) — every applicable ISO 42001 Annex A control mapped to one or more Cognic governance hooks. Single source of truth.
2. **Evidence emission** — every governance hook (audit, decision_history.append, escalation.transition, citation_verifier.verify, etc.) accepts an optional `iso_controls: tuple[str, ...]` argument and tags the emitted record. Hooks lookup default control IDs from the registry; explicit values override.
3. **Evidence pack export** — `compliance.iso42001.export_evidence_pack(period, scope)` produces an examiner-ready bundle: per-control coverage, raw evidence rows, hash-chain integrity proof, signed manifest.

### Initial control coverage (Wave 1)

| Control area | Cognic hook |
|---|---|
| A.6.2.5 — Operational responsibilities | `escalation.transition`, `rbac.check_scope`, **12 sandbox lifecycle events** (2026-05-16 amendment per Sprint 8A spec §4.3 — extended to 12 at Sprint 8.5 T1 per spec §3.3): `sandbox.lifecycle.created`, `sandbox.lifecycle.exec_completed`, `sandbox.lifecycle.destroyed` (Sprint 8.5 amendment: carries 2 new conditional payload keys `retained_until` + `tombstone_object_key` when the destroyed session had persisted checkpoints — presence is the wire-public marker that retention is in effect per spec §5.1), `sandbox.lifecycle.refused` (carries `SandboxRefusalReason` **21-value** closed-enum — extended from 15 at Sprint 8.5 T1 with 6 new wake-time arms: `sandbox_wake_checkpoint_not_found` / `sandbox_wake_checkpoint_corrupt` / `sandbox_wake_checkpoint_retention_expired` / `sandbox_wake_session_tombstoned` / `sandbox_wake_tenant_mismatch` / `sandbox_wake_policy_revalidation_failed`), `sandbox.policy.violated` (carries `SandboxPolicyViolationReason` 6-value closed-enum — amended to 6 at Sprint 8A T10c R1 P1.2 with `egress_audit_unreadable`; egress-reason rows additionally carry `payload.proxy_log: list[ProxyAccessRecord]` per spec §10.3 examiner-readable evidence requirement), `sandbox.warm_pool.precreated`, `sandbox.warm_pool.checked_out`, `sandbox.warm_pool.drained`, **Sprint 8.5 T1 — 4 new events** (per spec §3.3): `sandbox.lifecycle.checkpointed` (workspace-tar snapshot persisted; payload carries `checkpoint_id` + `label` + `policy_digest`), `sandbox.lifecycle.suspended` (final checkpoint taken; container/Pod released; payload carries `final_checkpoint_id` as the linkage target for the chain-verifier walk per spec §5.2), `sandbox.lifecycle.woken` (session restored from checkpoint with ORIGINAL session_id; payload carries `suspend_event_id` + `restored_from_checkpoint_id` for the chain-verifier walk via explicit payload keys — no `decision_history` schema migration needed), `sandbox.lifecycle.checkpoint_purged` (reaper emits one chain row per purge; payload carries `purge_reason` 4-value closed-enum: `explicit_destroy` / `max_per_session_cap` / `retention_expired` / `tenant_revocation`). Tombstoning is a STORAGE artifact NOT a lifecycle event — destroy() reuses the extended `sandbox.lifecycle.destroyed` event with conditional payload keys per the spec §5.1 P1.r4 redesign |
| A.6.2.6 — Roles and responsibilities | `rbac.role_scopes` |
| A.7.4 — AI system impact assessment | `decision_history.append` (with `impact: high`) |
| A.7.6 — AI system risk evaluation | `auto_degradation.evaluate`, `compliance_checker.score` |
| A.8.2 — Data quality for AI systems | `citation_verifier.verify`, `bm25.index_freshness` |
| A.8.5 — AI system development | `gateway.completion` (model + alias + provider tagged) |
| A.9.2 — System and operational logging | `audit.append`, `chain_verifier.walk` |
| A.10.2 — Stakeholder transparency | `decision_history.export_for_subject` |

This list is initial; full coverage map lives in `controls.py` and is the source of truth.

### AIUC-1 mapping

Add `compliance/aiuc1/` once the framework's machine-readable schema stabilises (currently in active development). For now, AIUC-1 conformance is documented narratively; mechanical mapping is Wave 2.

### Tamper-evident evidence chain

Evidence-pack export includes a Merkle root over the evidence rows in scope, signed by the AgentOS instance's identity key. Examiners verify the bundle independently. This satisfies ISO 42001's audit-trail integrity requirement.

## Consequences

### Positive
- **Examiner-ready exports** — banks generate evidence packs without manual decision-history traversal
- **Compliance certification ready** — when a bank pursues ISO 42001 certification, the control mapping accelerates the auditor's review
- **Future-proof against regulator framework changes** — hooks are decoupled from specific control IDs; new framework (e.g. EU AI Act high-risk) plugs in via the same registry pattern
- **Tamper-evident** — Merkle proof over evidence rows is verifiable independently

### Negative
- **Maintenance burden** — control registry must be updated when ISO releases revisions
- **Initial population effort** — manually mapping ~50 controls to ~20 hooks is one-time setup
- **Per-pack burden** — agent / tool packs need to declare which controls they touch (mitigated by harness defaults)

### Neutral
- AIUC-1 mapping is deferred to Wave 2 pending schema stability — narrative conformance documentation in the meantime

## Implementation phases
1. **Phase 3.1**: `controls.py` with initial 8-control mapping above
2. **Phase 3.2**: governance hooks accept `iso_controls` argument + emit tagged events
3. **Phase 3.3**: `export_evidence_pack(period, scope)` with Merkle root + signed manifest
4. **Phase 3.4**: integration test — generate a 7-day pack, validate against an external auditor's checklist
5. **Phase 4.x**: AIUC-1 mapping when schema stabilises

## References
- [ISO/IEC 42001:2023 — AI Management Systems](https://www.iso.org/standard/42001)
- [ISO 42001 — 2026 Gold Standard, Insight Assurance](https://insightassurance.com/insights/blog/iso-iec-42001-the-2026-gold-standard-for-ai-governance-and-trust/)
- [AI Governance & ISO 42001 FAQs — Cloud Security Alliance, Feb 2026](https://cloudsecurityalliance.org/blog/2026/02/17/ai-governance-and-iso-42001-faqs-what-organizations-need-to-know-in-2026)
- [Microsoft compliance — ISO 42001](https://learn.microsoft.com/en-us/compliance/regulatory/offering-iso-42001)
