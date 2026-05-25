"""Sprint 10 T10 K8s reviewer-P1 fix — cross-backend credential helpers.

Dependency-neutral home for cross-backend pure-functional credential
helpers that BOTH ``docker_sibling`` AND ``kubernetes_pod`` need.

Owns ``_mint_exception_to_refusal_reason`` — the 5-value
``core.vault`` exception taxonomy → 4-value ``sandbox_credential_*``
``SandboxRefusalReason`` closed-enum mapping per Sprint-10 spec §7.1
+ Sprint-10.1 amendment per ADR-004 §25 (3 hvac-mapped values map to
``sandbox_credential_mint_failed_*`` + the 5th
``VaultLeaseGrantExceedsRequest`` value maps to its own
``sandbox_credential_lease_ttl_grant_exceeds_request`` value).

**Why this module exists** (Sprint 10 T10 K8s round-2 reviewer P1
fix, 2026-05-24): the first iteration of T10 K8s imported
``_mint_exception_to_refusal_reason`` directly from
``docker_sibling`` per the user-scope "Reuse Docker's
``_mint_exception_to_refusal_reason``; no duplicate mapping table".
That import coupled K8s deployments to the ``sandbox-docker``
optional extra at import time (``docker_sibling.py`` imports
``aiodocker`` at module load), breaking the optional-extra boundary
documented at ``sandbox/__init__.py``: K8s-only deployments
explicitly do NOT install ``sandbox-docker``. The fix promotes the
helper out of ``docker_sibling.py`` into this dependency-neutral
shared module — both backends import from here. Mirrors the
precedent set by ``_shared_exec.py`` (consumer-owned helpers
extracted when a second backend needed them).

**Dependency contract**: this module imports ONLY from
``cognic_agentos.core.vault`` (for the 5 Vault exception classes
post-Sprint-10.1: ``VaultUnavailable`` / ``VaultPathNotFound`` /
``VaultAuthDenied`` / ``VaultProtocolError`` /
``VaultLeaseGrantExceedsRequest``) and
``cognic_agentos.sandbox.protocol`` (for the
``SandboxRefusalReason`` Literal). Adding a backend-specific
import (aiodocker / kubernetes_asyncio / any other) would
re-introduce the same coupling bug class — pinned by the test-only
AST scan at ``tests/unit/sandbox/backends/test_shared_credentials.py``
that confirms zero backend-specific imports + asserts the K8s
blocked-import probe still succeeds.

Promote additional cross-backend credential helpers HERE as future
Sprint-10.x tasks land (e.g. revoke-side closed-enum mappings, lease
refresh helpers, etc.). Do NOT inline-duplicate the helpers in
either backend — drift between Docker + K8s on credential
closed-enum mappings is wire-protocol-public regression.
"""

from __future__ import annotations

from cognic_agentos.core.vault import (
    VaultAuthDenied,
    VaultLeaseGrantExceedsRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
)
from cognic_agentos.sandbox.protocol import SandboxRefusalReason


def _mint_exception_to_refusal_reason(
    exc: (
        VaultUnavailable
        | VaultPathNotFound
        | VaultAuthDenied
        | VaultProtocolError
        | VaultLeaseGrantExceedsRequest
    ),
) -> SandboxRefusalReason:
    """Sprint 10 T10 + Sprint 10.1 amendment — collapse the 5-value
    ``core.vault`` exception taxonomy onto the ``sandbox_credential_*``
    closed-enum vocabulary per spec §7.1.

    ``VaultProtocolError`` collapses to ``vault_unavailable`` for
    closed-enum stability per spec §6.1 / §7.1 last row — the
    ``detail`` field on the raised ``SandboxLifecycleRefused`` carries
    the malformed-response specifics so operators can correlate the
    protocol-error pattern in Langfuse / Dynatrace without expanding
    the wire-public closed-enum surface.

    Sprint 10.1: 5th arm added for :class:`VaultLeaseGrantExceedsRequest`
    → ``sandbox_credential_lease_ttl_grant_exceeds_request``. The
    granted-vs-requested TTL enforcement at
    :func:`cognic_agentos.core.vault.lease_credential` raises this
    exception (with best-effort revoke before raise per Finding A of
    the 2026-05-24 plan-review round 1); the sandbox boundary maps it
    to the new wire-public closed-enum value. Backend except-tuples in
    ``docker_sibling.py`` + ``kubernetes_pod.py`` extended in the SAME
    commit per Finding B so no intermediate state leaves the new
    exception escaping uncaught.

    Pure-functional + dependency-neutral — both Docker + K8s import
    this from the shared module so the mapping table lives at ONE
    site (cross-backend invariant: drift between Docker + K8s on this
    mapping is wire-protocol-public regression).
    """
    if isinstance(exc, VaultUnavailable):
        return "sandbox_credential_mint_failed_vault_unavailable"
    if isinstance(exc, VaultPathNotFound):
        return "sandbox_credential_mint_failed_secret_path_unknown"
    if isinstance(exc, VaultAuthDenied):
        return "sandbox_credential_mint_failed_auth_denied"
    if isinstance(exc, VaultProtocolError):
        return "sandbox_credential_mint_failed_vault_unavailable"
    if isinstance(exc, VaultLeaseGrantExceedsRequest):
        return "sandbox_credential_lease_ttl_grant_exceeds_request"
    # Static-typing safety net: the parameter type union exhausts the
    # 5-value taxonomy; this arm is unreachable at runtime but keeps
    # mypy happy on the function's return-type contract.
    raise AssertionError(  # pragma: no cover
        f"_mint_exception_to_refusal_reason: unexpected exception type "
        f"{type(exc).__name__}; expected one of VaultUnavailable / "
        f"VaultPathNotFound / VaultAuthDenied / VaultProtocolError / "
        f"VaultLeaseGrantExceedsRequest"
    )


__all__ = ["_mint_exception_to_refusal_reason"]
