# A2A 1.0 Conformance Fixtures

Curated valid + invalid A2A 1.0 messages that
`tests/unit/protocol/test_a2a_spec_conformance.py` walks. Per
Sprint-6 T13:

- `valid/*.json` — messages that the corresponding Sprint-6
  validators MUST accept (T6 protobuf parse / T8 version negotiator
  / T11 capability reader, etc.).
- `invalid/*.json` — messages with sibling `*_expected.json`
  declaring the spec error code that MUST surface (`A2AErrorCode`
  literal value + optional `policy_reason` from
  `A2APolicyRefusalReason`).

The fixtures are JSON-RPC-2.0-shaped envelopes per A2A 1.0 §"Method
catalog" + protobuf-JSON encodings of `StreamResponse` per T10's
shipped contract. The test runner does NOT call the full HTTP
endpoint — it dispatches each fixture against the appropriate
validator inline (validators have no I/O) so the conformance set
runs in milliseconds and forms a regression net against future
spec edits.

The `*_expected.json` schema:

```json
{
  "spec_code": "<one of A2AErrorCode>",
  "policy_reason": "<optional, one of A2APolicyRefusalReason>",
  "validator": "<which Sprint-6 validator surfaces it>",
  "wave2_feature": "<optional sub-tag for wave2_feature_refused>",
  "rationale": "<one-line why this fixture trips this code>"
}
```
