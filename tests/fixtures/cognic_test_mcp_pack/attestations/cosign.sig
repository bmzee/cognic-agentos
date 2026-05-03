cognic-test-mcp-pack-fixture-cosign-signature-placeholder
this file is intentionally non-cryptographic for Sprint-5 unit tests
the @pytest.mark.cosign_real integration path regenerates this with
build_test_attestations.sh --regenerate before running real cosign
verify-blob against it. Per the T6 trust gate's contract the file
contents are opaque bytes — only the SHA-256 of the file is reported
back to the registry as signature_digest.
