"""Sprint 6 T6 — A2A schema-drift CI gate.

Pulls the upstream A2A 1.0 protobuf source at the pinned canonical
URL and compares its SHA-256 against the digest pinned in
``protocol/a2a_schema.py``. Mismatch → build fails; a deliberate
review + version-bump pass is required (per Sprint-6 Decision Lock
#1 — silent upgrades forbidden).

**Env-gated** per Sprint-6 Doctrine Decision C: this file's tests
only run when ``COGNIC_RUN_A2A_UPSTREAM=1`` is set. CI sets it on
the dedicated ``a2a-spec-drift`` lane (see
``.github/workflows/python.yml``); local dev skips the file by
default to avoid a network round-trip on every test run. Mirrors
the Sprint-4 ``cosign_real`` env-gate pattern.

**Capture-time divergence from the plan-of-record (T6 R0 capture):**
the plan's draft included two upstream artifacts (protobuf source +
JSON-schema bundle) and a parity check. Reality at T6 capture time:
the spec authors publish only the protobuf source at a canonical URL
(``raw.githubusercontent.com/a2aproject/A2A/v1.0.0/specification/a2a.proto``);
the ``specification/json/`` directory contains only a README pointing
back at the protobuf source. T6 ships the protobuf-digest gate only;
the JSON-schema artifact + parity check land when (or if) the spec
authors publish a canonical JSON-schema bundle.

When upstream ``v1.0.0`` actually moves (rare — the v-tag is
spec-author-controlled), this test fails with a clear error message
+ the upstream digest in the assertion text so reviewers can decide
whether to bump the pin OR reject the spec change. Persistent
upstream outage (DNS, GitHub down) raises an HTTP error from
``httpx``; CI's lane timeout (10 minutes) bounds the retry window.
"""

from __future__ import annotations

import hashlib
import os

import httpx
import pytest

from cognic_agentos.protocol.a2a_schema import (
    _PINNED_PROTOBUF_DIGEST,
    _UPSTREAM_PROTOBUF_URL,
)

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("COGNIC_RUN_A2A_UPSTREAM") != "1",
        reason=(
            "live A2A upstream schema check; opt in via "
            "COGNIC_RUN_A2A_UPSTREAM=1 (CI sets this on the "
            "a2a-spec-drift lane; local dev skips to save the "
            "network round-trip on every test run)"
        ),
    ),
    pytest.mark.a2a_upstream,
]


async def test_pinned_protobuf_digest_matches_upstream() -> None:
    """The pinned protobuf-source digest in
    ``protocol/a2a_schema.py`` MUST match the SHA-256 of the bytes
    upstream is publishing right now.

    If upstream moves, the build fails and a Sprint-N reviewer +
    version-bump pass is required. Per Sprint-6 Decision Lock #1,
    silent upgrades are forbidden — every spec change MUST be
    reviewed against the Wave-1/2/3 conformance matrix in
    ``docs/A2A-CONFORMANCE.md``.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(_UPSTREAM_PROTOBUF_URL)
        resp.raise_for_status()
        upstream_digest = hashlib.sha256(resp.content).hexdigest()

    assert upstream_digest == _PINNED_PROTOBUF_DIGEST, (
        f"\n"
        f"A2A 1.0 protobuf source has drifted from pin.\n"
        f"  Pinned:   {_PINNED_PROTOBUF_DIGEST}\n"
        f"  Upstream: {upstream_digest}\n"
        f"  URL:      {_UPSTREAM_PROTOBUF_URL}\n"
        f"\n"
        f"Action: review the upstream change against the Wave-1/2/3\n"
        f"matrix in docs/A2A-CONFORMANCE.md. If the change is accepted,\n"
        f"bump the pin in protocol/a2a_schema.py with an explicit\n"
        f"changelog entry. Silent upgrades are forbidden per Sprint-6\n"
        f"Decision Lock #1."
    )
