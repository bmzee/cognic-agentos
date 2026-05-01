"""Sprint-4 test fixture pack.

Installed via ``uv pip install -e tests/fixtures/cognic_test_pack/``
to exercise the plugin-registry discover → verify → register flow
end-to-end. Not a real Cognic plugin pack — the runtime path's
deferred-load contract means this module is NEVER imported during
T10 admission; only the explicit ``PluginRegistry.load(kind, name)``
call site triggers the import.
"""
