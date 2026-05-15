"""Sprint 7B.3 — pack reviewer evidence-panel projectors (CRITICAL CONTROLS).

This sub-package houses the four pure-functional evidence-panel
projectors that compose the reviewer-facing evidence surface per
ADR-012 §41 + the 5-gate composer:

- :mod:`data_governance` (T3) — ADR-017 manifest projection +
  optional tenant-policy diff. **CC stop rule** per AGENTS.md L54
  (`Pack data-governance contracts`) + L156.
- :mod:`risk_tier` (T4) — ADR-014 risk-tier projection.
- :mod:`supply_chain` (T5) — ADR-016 attestation roll-up.
- :mod:`conformance` (T6) — kind-aware OWASP-matrix re-projection
  from the persisted ``payload["conformance"]`` chain row.

The portal pack-API consumes these projectors via the four
``GET /api/v1/packs/{pack_id}/evidence/<panel>`` endpoints in
:mod:`cognic_agentos.portal.api.packs.evidence_routes`. The
architectural arrow is ``portal → packs/evidence`` — projectors do
NOT import from portal.

Per ADR-012 §41 + R10 LOCK Flag #2, the 5-gate composer (T7) reads
the same projector outputs to compute the gate-level verdict; the
reviewer sees the same evidence the composer scored against, so the
approve decision is fully auditable. The 7B.3 closeout (T13) flips
BUILD_PLAN §602 to record this layer.
"""

from __future__ import annotations

__all__: list[str] = []
