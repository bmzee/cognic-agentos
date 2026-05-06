"""Sprint-6 test fixture pack — IMPORT-POISONED (intentionally permanent).

This module's import is deliberately a hard error so the registry's
admission pipeline gets a load-bearing test of the deferred-load
invariant per ADR-002 §gate 1: the registry MUST resolve
``cognic-pack-manifest.toml`` AND ``agent_cards/test_agent.{json,jws}``
via ``Distribution.locate_file()`` WITHOUT importing the package code.
If any future regression triggers ``__init__.py`` execution as a side
effect, importing this package raises the AssertionError below —
which pytest surfaces as a clear test failure pointing at the
regression.

Mirrors the Sprint-5 ``cognic_test_mcp_pack`` import-poisoning pattern
verbatim. T13 inherits the SAME scope decision: the unit lane uses a
mocked HTTP transport for the receiver smoke. A real runnable A2A 1.0
server (live tenant token round-trip, signed Agent Card published at
the spec well-known path, real sockets) belongs to a future
integration lane (Sprint 13.5 / pre-go-live), not the unit suite.

Do NOT "fix" this fixture by adding a server module — the lack of one
is intentional.
"""

raise AssertionError(
    "cognic_test_agent_pack.__init__ MUST NOT be executed by the "
    "admission pipeline. The deferred-load invariant requires "
    "Distribution.locate_file() to resolve cognic-pack-manifest.toml + "
    "agent_cards/test_agent.{json,jws} WITHOUT importing the package. "
    "If this assertion fires, the admission pipeline regressed."
)
