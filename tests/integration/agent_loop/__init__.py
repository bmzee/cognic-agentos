"""Kernel conformance suite for the governed agent loop (ADR-027).

Each module carries its own PROVEN / SUBSTITUTED / NOT-YET-PROVEN statement.
Every PROVEN bullet must be backed by an assertion in that module — a claim
that cannot be pinned by a test belongs in SUBSTITUTED or must be deleted.

* :mod:`~tests.integration.agent_loop.test_kernel_conformance` — pack-load
  wiring: the real manifest/``AGENT.md`` extractors and the
  ``agent_host._build_agent_records`` admission walk.
* :mod:`~tests.integration.agent_loop.test_loop_composition` — the real
  ``harness.agent_host.build_agent_loop`` entry point, its 3-state dependency
  discipline, and the identity of the collaborators it composes.
* :mod:`~tests.integration.agent_loop.test_dispatch_conformance` — the governed
  dispatch pipeline: assignment and entitlement gates, the Rego policy gate,
  refusal feedback, and digest-only dispatch evidence.

Read the module scope statement before citing any of it as evidence.
"""
