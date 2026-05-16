"""Sprint 7B.4 — UI route + gate package.

Owns the portal-side UI surface per ADR-020:

  - :mod:`.elicitation_gate` (T8) — async 5-step gate for the
    POST /api/v1/ui/actions `submit_elicitation` class.
  - :mod:`.dto` (T9, future) — Pydantic typed action-request DTOs.
  - :mod:`.action_routes` (T11, future) — POST /actions handler.
  - :mod:`.stream_routes` (T10, future) — 3 SSE GET endpoints.
  - :mod:`.well_known_routes` (T12, future) — well-known schema publication.
"""
