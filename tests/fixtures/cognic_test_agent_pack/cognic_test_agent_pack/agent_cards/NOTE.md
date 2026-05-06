# Test agent card fixture material (generated at fixture-author time)

Used by Sprint-6 T13's `test_a2a_fixture_pack_admission.py` to
exercise the `A2AAgentCardVerifier` (T7) against real RS256 JWS
bytes.

Files:
  - `test_agent.json` — minimal A2A 1.0 AgentCard JSON. Round-trips
    cleanly through `google.protobuf.json_format.Parse(card_bytes,
    a2a.types.a2a_pb2.AgentCard())`. SDK profile fields used:
    `provider.organization`, `securitySchemes`, `securityRequirements`,
    `supportedInterfaces`, `signatures`.
  - `test_agent.jws` — RS256 plain detached compact JWS
    (`<header>..<signature>` with empty middle segment), signed
    over the verbatim bytes of `test_agent.json`. The protected
    header carries `alg` + `kid` only — this is the standard
    joserfc/PyJWT detached convention (the signing input is
    `b64url(header) + "." + b64url(payload)`), **not** RFC 7797
    unencoded-payload mode (which would also set `b64: false` +
    `crit: ["b64"]`). `kid = "test-agent-pack-fixture-key-v1"`.
  - `test_agent.pub.pem` — RSA public key PEM. The smoke test mocks
    the `SecretAdapter` to return this PEM at
    `secret/cognic/<tenant>/a2a-jws-trust-root`.

The corresponding RSA private key was generated once at
fixture-author time and discarded after producing the JWS — it is
**NOT committed**. The fixture is round-trippable verbatim:
`joserfc.jws.deserialize_compact(jws, pub_key, algorithms=["RS256"],
payload=card_bytes)` verifies the detached signature against the
card bytes, exactly as the trust gate runtime path
(`TrustGate.verify_jws_blob`) and `A2AAgentCardVerifier.validate_card`
do. Tampering the payload bytes causes `BadSignatureError` (the
verifier MUST NOT accept the signature against any other payload
— pinned by the tampered-payload regression in
`test_a2a_fixture_pack_admission.py`).

If a future card-shape change lands (e.g. a new mandatory profile
field), regenerate by re-running the inline script in T13's commit
diff (the script is preserved in the commit message footer).
