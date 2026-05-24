"""Sprint 10 T6 — VaultCredentialAdapter.

PROMOTED from off-gate re-export shim (Sprint 8A) to ON the durable
per-file critical-controls coverage gate at the Sprint-10 close commit
per spec §17. T6 lands the production code that will be promoted.

Implements the post-T5 :class:`CredentialAdapter` Protocol declared in
:mod:`cognic_agentos.sandbox.admission`. This module is a thin
delegation layer:

* :meth:`VaultCredentialAdapter.mint_lease` delegates to
  :func:`cognic_agentos.core.vault.lease_credential`.
* :meth:`VaultCredentialAdapter.revoke_lease` delegates to
  :func:`cognic_agentos.core.vault.revoke_credential`.
* :meth:`VaultCredentialAdapter.fetch_secret` reads via
  :meth:`VaultTransport.read` and extracts the Wave-1 single-value
  convention.

USER-LOCKED CORRECTION #1 (Round-0 review): ``fetch_secret`` does
NOT swallow transport exceptions. The :class:`CredentialAdapter`
Protocol docstring at ``sandbox/admission.py:119`` says "Implementations
MUST surface auth / network failures as exceptions (NOT silent None)".
The plan-of-record's Step 3 sketch had a ``try / except Exception:
return None`` catch-all that contradicted the Protocol contract; this
module ships the corrected behaviour:

* ``transport.read(path) is None`` → ``fetch_secret`` returns None
  (not-found-style absence per the Protocol's "or None if not found").
* Any transport-raised exception PROPAGATES unchanged.
* Shape-mismatch (response present but doesn't fit the Wave-1
  single-value convention) raises :class:`VaultProtocolError` —
  surfacing the malformed response rather than silently masking it
  as a not-found absence.

USER-LOCKED CORRECTION #2 (Round-0 review): ``mint_lease`` /
``revoke_lease`` PRESERVE the T4 4-value exception taxonomy
(:class:`VaultUnavailable` / :class:`VaultPathNotFound` /
:class:`VaultAuthDenied` / :class:`VaultProtocolError`). The
sandbox-closed-enum collapse to
``sandbox_credential_mint_failed_*`` belongs at the
create / admission boundary that raises
:class:`SandboxLifecycleRefused` (Sprint 10 T7+), NOT inside this
thin adapter. The runtime code (i.e. non-docstring source — imports,
raises, and string literals at code positions) intentionally contains
ZERO references to ``SandboxRefusalReason`` / ``SandboxLifecycleRefused``
/ ``sandbox_credential_mint_failed_`` — pinned by the AST-walk
regression at
``tests/unit/sandbox/test_credentials.py::TestNoClosedEnumMappingCreepInT6``,
which deliberately exempts docstring positions so this intent-
documentation prose (which necessarily names the closed-enum types)
does not trip the detector.

The Sprint-8A re-exports (:class:`CredentialAdapter`,
:class:`KernelDefaultCredentialAdapter`) are PRESERVED so every
consumer that imports from this path stays backward-compat.
"""

from __future__ import annotations

from typing import Any

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseRequest,
    VaultProtocolError,
    lease_credential,
    revoke_credential,
)
from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)


class VaultCredentialAdapter:
    """Real CredentialAdapter implementation per ADR-004 §102 Q4 LOCK.

    Sprint 10 ships this as the production replacement for the
    Sprint-8A fail-loud :class:`KernelDefaultCredentialAdapter`
    sentinel. Banks wire this in ``create_app()`` with a configured
    :class:`VaultTransport`.

    Thin delegation layer — the substantive lease/revoke logic +
    exception taxonomy live in :mod:`cognic_agentos.core.vault`.
    """

    def __init__(self, *, transport: VaultTransport, settings: Settings) -> None:
        self._transport = transport
        self._settings = settings

    async def fetch_secret(self, path: str) -> str | None:
        """Read a single-value secret at ``path``.

        Per the :class:`CredentialAdapter` Protocol contract at
        ``sandbox/admission.py:119``:

        * Returns ``None`` ONLY when ``transport.read(path)`` returns
          ``None`` (Vault 404 / not-found-style absence).
        * Auth / network failures from the transport PROPAGATE as
          exceptions (NO silent None — user-locked correction #1).
        * Shape-mismatch (response present but doesn't fit the
          Wave-1 single-value convention) raises
          :class:`VaultProtocolError` — surfacing the malformed
          response rather than silently masking it as a not-found
          absence.

        Wave-1 single-value convention: the secret is stored at the
        path with its value under a top-level ``"value"`` key.

        * KV v1: ``response = {"data": {"value": "<v>"}}``
        * KV v2: ``response = {"data": {"data": {"value": "<v>"}}}``

        Multi-field secrets MUST use :meth:`mint_lease` instead —
        ``fetch_secret`` is the Sprint-8A single-value static-secret
        path retained for backward compatibility with operator-supplied
        custom adapters.
        """
        # NO try/except — exceptions PROPAGATE per Protocol contract.
        # User-locked correction #1: silent-None substitution on
        # transport exceptions is forbidden; the plan-of-record's
        # Step 3 catch-all violated this and was rejected at Round-0.
        response = await self._transport.read(path)
        if response is None:
            # The ONLY None-returning path: genuine not-found absence
            # per the Protocol docstring's "or None if not found" clause.
            return None

        # Extract data; normalise KV v2 nesting (mirrors the existing
        # VaultAdapter normalisation at db/adapters/vault_adapter.py:90-95
        # so the caller sees uniform shape regardless of deployed KV
        # mount version).
        data: Any = response.get("data", {})
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
            data = data["data"]

        if not isinstance(data, dict):
            # Shape mismatch — transport returned response but data
            # field is not a dict. Surface as VaultProtocolError to
            # stay consistent with the T4 taxonomy class for
            # malformed-response cases (lease_credential uses
            # VaultProtocolError for the same defensive arm).
            raise VaultProtocolError(
                f"fetch_secret({path!r}): Vault response.data is not a "
                f"dict; got {type(data).__name__}"
            )

        if "value" not in data:
            # Shape mismatch — secret IS present but does NOT have
            # the Wave-1 single-value ``value`` key. User-locked
            # correction #1: "return None ONLY for transport.read(path)
            # is None / not-found-style absence" — a present-but-
            # multi-field secret is NOT not-found absence, so silent
            # None is wrong. Raise so the caller knows to use the
            # lease API.
            raise VaultProtocolError(
                f"fetch_secret({path!r}): Vault response present but "
                f"missing Wave-1 single-value 'value' key; got keys "
                f"{sorted(data.keys())}. Multi-field secrets MUST use "
                f"mint_lease / revoke_lease."
            )

        return str(data["value"])

    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        """Mint a dynamic credential lease for the given request.

        Delegates to :func:`cognic_agentos.core.vault.lease_credential`
        and returns the resulting :class:`CredentialLease` unchanged.

        USER-LOCKED CORRECTION #2 (Round-0 review): the 4-value
        ``core.vault`` exception taxonomy (:class:`VaultUnavailable` /
        :class:`VaultPathNotFound` / :class:`VaultAuthDenied` /
        :class:`VaultProtocolError`) PROPAGATES unchanged. The
        sandbox-closed-enum collapse to
        ``sandbox_credential_mint_failed_*`` belongs at the
        create / admission boundary (Sprint 10 T7+), NOT here.
        """
        return await lease_credential(
            request,
            transport=self._transport,
            settings=self._settings,
        )

    async def revoke_lease(self, lease_id: str) -> None:
        """Revoke a previously-minted lease by Vault lease ID.

        Delegates to :func:`cognic_agentos.core.vault.revoke_credential`.

        USER-LOCKED CORRECTION #2: exception taxonomy preserved (see
        :meth:`mint_lease` docstring).
        """
        await revoke_credential(lease_id, transport=self._transport)


__all__ = [
    "CredentialAdapter",
    "KernelDefaultCredentialAdapter",
    "VaultCredentialAdapter",
]
