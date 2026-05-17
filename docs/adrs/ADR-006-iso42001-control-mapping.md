# ADR-006 — ISO/IEC 42001 Control Mapping

## Status

**Amended on 2026-05-16** (this revision) — minor amendment shipped alongside the Sprint 8A T1 design spec. Adds the 8 sandbox lifecycle events from Sprint 8A's audit taxonomy to the A.6.2.5 (Operational responsibilities) row of the Initial control coverage table; introduces 2 new sandbox closed-enum vocabularies (`SandboxRefusalReason` 15 values + `SandboxPolicyViolationReason` 6 values — extended from 5 → 6 at Sprint 8A T10c R1 P1.2 with the addition of `egress_audit_unreadable` for fail-closed proxy_log readback) as the wire-protocol-public refusal taxonomies tagged under A.6.2.5.

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
| A.6.2.5 — Operational responsibilities | `escalation.transition`, `rbac.check_scope`, **8 sandbox lifecycle events** (2026-05-16 amendment per Sprint 8A spec §4.3): `sandbox.lifecycle.created`, `sandbox.lifecycle.exec_completed`, `sandbox.lifecycle.destroyed`, `sandbox.lifecycle.refused` (carries `SandboxRefusalReason` 15-value closed-enum), `sandbox.policy.violated` (carries `SandboxPolicyViolationReason` 6-value closed-enum — amended to 6 at Sprint 8A T10c R1 P1.2 with `egress_audit_unreadable`; egress-reason rows additionally carry `payload.proxy_log: list[ProxyAccessRecord]` per spec §10.3 examiner-readable evidence requirement), `sandbox.warm_pool.precreated`, `sandbox.warm_pool.checked_out`, `sandbox.warm_pool.drained` |
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
