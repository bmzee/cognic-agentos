"""Kernel conformance suite for the governed agent loop (ADR-027).

Proves the loop's WIRING — not its unit logic — against a synthetic agent pack,
so a failure here is unambiguously a KERNEL defect rather than a pack defect.
See :mod:`tests.integration.agent_loop.test_kernel_conformance`.
"""
