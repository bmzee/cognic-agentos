"""Kernel conformance suite for the governed agent loop (ADR-027).

TODAY THIS PACKAGE PROVES PACK-LOAD WIRING ONLY — the manifest/``AGENT.md``
extractors and the ``agent_host._build_agent_records`` admission walk. It does
NOT yet prove agent-loop wiring: ``build_agent_loop``, the assignment and
entitlement stores, the Rego dispatch gate, refusal feedback, and dispatch
evidence are all still unexercised.

Read the scope statement in
:mod:`tests.integration.agent_loop.test_kernel_conformance` before citing this
package as evidence of anything.
"""
