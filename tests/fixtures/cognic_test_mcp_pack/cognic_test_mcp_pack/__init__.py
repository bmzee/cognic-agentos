"""Sprint-5 test fixture pack — IMPORT-POISONED.

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

T12 will replace this fixture with a richer pack that includes a real
MCP server module; the import-poisoning will move at that point to a
dedicated isolated fixture so T12's server module can be importable
when test code DELIBERATELY calls ``PluginRegistry.load(...)``.
"""

raise AssertionError(
    "cognic_test_mcp_pack.__init__ MUST NOT be executed by the manifest "
    "extractor. The deferred-load invariant requires Distribution.locate_file() "
    "to resolve cognic-pack-manifest.toml WITHOUT importing the package. If "
    "this assertion fires, the extractor regressed."
)
