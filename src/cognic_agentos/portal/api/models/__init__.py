"""Cognic AgentOS portal model-registry API surface — Sprint 9.5.

This package will host the model-registry route handlers (B4 +
B5) + DTOs (B3) under ``/api/v1/models``. The :mod:`dto` module
ships at B3; the route modules at B4 (lifecycle: register / promote
/ retire) and B5 (inspection: list / detail / audit + router +
``app.py`` mount).
"""
