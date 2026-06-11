"""Sprint 13.5a (ADR-014/015) — runtime approval engine core (``core/`` stop-rule).

Non-blocking approval decision primitive: classify a tool's risk tier to an
approval flow (``tools.rego``), create + persist a value-free approval request,
and check / grant / deny it with engine-boundary human-only enforcement, 4-eyes
distinctness, lazy authoritative expiry, and a replay-binding gate. Designed as
the generic Sprint-14 human-checkpoint primitive. No portal API and no consumer
seam cutover here (Sprint 13.5b); no quota / kill-switch (Sprint 13.6).
"""
