"""Sprint 7B.4 T8 — direct-OPA integration tests for the
policies/_default/*.rego bundles.

Tests in this package use `@pytest.mark.opa_required` (a skipif on
`shutil.which("opa") is None`) so the suite stays green on systems
without the OPA binary installed. CI runs OPA-bearing lanes by
ensuring the binary is on PATH; local dev skips by default.
"""
