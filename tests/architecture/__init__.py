"""Architecture tests — doctrine-level invariants enforced via AST walks
or other static checks.

Distinct from unit tests under ``tests/unit/`` because architecture tests
assert on the shape of the codebase itself (e.g., "module X never imports
module Y"), not on runtime behaviour. They typically run quickly (no I/O,
no fixtures) and catch class-of-bug rather than instance-of-bug
regressions.

Sprint 5 lands the first member: ``test_mcp_stdio_no_subprocess.py`` per
the Sprint-5 Decision Lock guardrail #2 — banning ``subprocess`` /
``os.exec*`` / ``os.spawn*`` / ``os.posix_spawn*`` / ``os.system`` /
``os.popen`` / ``asyncio.create_subprocess_*`` / ``multiprocessing.Process``
imports + calls in any ``protocol/mcp_*.py`` or ``*stdio*.py`` module.
"""
