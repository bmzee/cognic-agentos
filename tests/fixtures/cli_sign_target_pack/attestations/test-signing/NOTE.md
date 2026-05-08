# Test-only signing keypair — Sprint-7A T14 fixture

**This keypair is test-only, synthetic, and committed deliberately.**
Do NOT reuse outside the T14 sign/verify test slice or the T15 lifecycle
test (when the same pattern lands for the agent reference pack).

## What it is

- `test_signing_key.private.pem` — RSA-2048 private key in PKCS8 PEM.
- `test_signing_key.public.pem` — matching RSA public key in
  SubjectPublicKeyInfo PEM.

## Why both PEMs are committed

T14's JWS-signing arm needs the *private* PEM to deterministically
regenerate the AgentCard JWS in-process. T14's verify happy-path arm
needs the *public* PEM as the trust root the regenerated JWS verifies
against. Without the private side committed, the lifecycle test would
either be non-deterministic or require live signing infrastructure.

Per R9 P2 #1, this extends the Sprint-6 fixture-pack public-PEM
pattern to the private side, with two protections:

1. The `prod` settings profile rejects any `signing_key_path` pointing
   inside `tests/fixtures/` or `examples/` at startup
   (`core/config.py::_validate_signing_key_path_prod_profile_guard`).
2. The `test_signing_key` naming + this NOTE alongside both PEMs make
   the test-only intent unmissable.

## How it was generated (audit trail)

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
public_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
```

Re-run the snippet only if the key needs rotating (e.g., a future
audit determines the test material should be refreshed); commit the
new pair via the same `.gitignore` exception lines.
