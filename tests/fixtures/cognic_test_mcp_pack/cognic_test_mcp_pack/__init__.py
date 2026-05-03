"""Sprint-5 test fixture pack — IMPORT-POISONED (intentionally permanent).

This module's import is deliberately a hard error so the
mcp_manifest extractor's deferred-load invariant gets a load-bearing
test. Per ADR-002 §"MCP STDIO threat model" gate 1 + Sprint-4
discover→register→load doctrine: the registry MUST resolve
``cognic-pack-manifest.toml`` via ``Distribution.locate_file()``
WITHOUT importing the package code. If the extractor ever regresses
to using ``importlib.resources.files()`` or any other primitive that
triggers ``__init__.py`` execution as a side effect, importing this
package will raise the AssertionError below — which pytest surfaces
as a clear test failure pointing at the regression.

The import-poisoning is the *intended* steady state for this fixture
in the Sprint-5 unit lane and **does not move**:

- T6 (manifest extractor) needs the package to be unimportable so the
  deferred-load invariant is testable.
- T12 (fixture pack admission + MCPHost orchestrator smoke) exercises
  the registry + orchestrator against a **mocked HTTP transport**;
  there is no runnable server module here and none is required for
  the unit lane.

A real runnable MCP server (live OAuth AS, PRM publication, real
sockets) belongs to a future integration lane (Sprint 13.5 /
pre-go-live), not the unit suite. Do not "fix" this fixture by adding
a server module — the lack of one is intentional.
"""

raise AssertionError(
    "cognic_test_mcp_pack.__init__ MUST NOT be executed by the manifest "
    "extractor. The deferred-load invariant requires Distribution.locate_file() "
    "to resolve cognic-pack-manifest.toml WITHOUT importing the package. If "
    "this assertion fires, the extractor regressed."
)
