"""Sprint 10 T6 — sandbox/credentials.py real VaultCredentialAdapter.

CRITICAL CONTROL — sandbox/credentials.py is PROMOTED from off-gate
re-export shim (Sprint 8A) to ON the durable per-file critical-controls
coverage gate at the Sprint-10 close commit per spec §17. T6 lands the
production code that will be promoted.

Tests pin the two user-locked T6 corrections (Round-0):

1. ``fetch_secret`` does NOT swallow transport exceptions.
   The CredentialAdapter Protocol docstring at
   ``sandbox/admission.py:119`` says "Implementations MUST surface
   auth / network failures as exceptions (NOT silent None)". The
   plan-of-record's Step 3 sketch had a ``try / except Exception:
   return None`` catch-all that contradicted the Protocol contract;
   T6 ships the corrected behaviour:
   * ``transport.read(path) is None`` → ``fetch_secret`` returns None
     (not-found-style absence per the Protocol's "or None if not
     found" clause).
   * Any transport-raised exception PROPAGATES unchanged.
   * Shape-mismatch (response present but doesn't fit the Wave-1
     single-value convention) raises VaultProtocolError — surfacing
     the malformed response rather than silently masking it as a
     not-found absence.

2. ``mint_lease`` / ``revoke_lease`` PRESERVE the T4 4-value
   exception taxonomy (``VaultUnavailable`` / ``VaultPathNotFound`` /
   ``VaultAuthDenied`` / ``VaultProtocolError``). The sandbox
   closed-enum collapse to ``sandbox_credential_mint_failed_*``
   belongs at the create / admission boundary that raises
   ``SandboxLifecycleRefused`` (Sprint 10 T7+), NOT inside this thin
   adapter. T6 is a delegation layer; the runtime code (i.e.
   non-docstring source — imports, raises, and string literals at
   code positions) MUST contain ZERO references to
   ``SandboxRefusalReason`` / ``SandboxLifecycleRefused`` /
   ``sandbox_credential_mint_failed_`` per the user-locked correction
   — pinned by the AST-walk regression at
   ``TestNoClosedEnumMappingCreepInT6``, which deliberately exempts
   docstring positions so intent-documentation prose (this one,
   plus the production module's own docstring) does not trip the
   detector.

Plus the standard T6 watchpoints (user-stated Round-0):
* re-exports preserved (CredentialAdapter, KernelDefaultCredentialAdapter
  still importable from sandbox.credentials);
* VaultCredentialAdapter is NOT the sentinel (isinstance check);
* structural Protocol conformance pinned.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import hvac
import hvac.exceptions
import pytest

import cognic_agentos
from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseActorRef,
    VaultLeaseRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
)
from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)
from cognic_agentos.sandbox.credentials import VaultCredentialAdapter


def _request() -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path="database/creds/payment-readonly",
        ttl_s=900,
        tenant_id="t-1",
        actor_ref=VaultLeaseActorRef(actor_subject="u-1", actor_type="human"),
        scope_label="payment-readonly-test",
    )


def _settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def _mock_transport(
    *,
    read_return: object = None,
    read_side_effect: object = None,
    lease_return: object = None,
    lease_side_effect: object = None,
    revoke_side_effect: object = None,
) -> MagicMock:
    transport = MagicMock(spec=VaultTransport)
    if read_side_effect is not None:
        transport.read = AsyncMock(side_effect=read_side_effect)
    else:
        transport.read = AsyncMock(return_value=read_return)
    if lease_side_effect is not None:
        transport.lease = AsyncMock(side_effect=lease_side_effect)
    else:
        transport.lease = AsyncMock(return_value=lease_return)
    if revoke_side_effect is not None:
        transport.revoke = AsyncMock(side_effect=revoke_side_effect)
    else:
        transport.revoke = AsyncMock(return_value=None)
    return transport


def _happy_lease_payload() -> dict[str, object]:
    return {
        "lease_id": "database/creds/payment-readonly/lease-abc-123",
        "lease_duration": 900,
        "data": {"username": "u-001", "password": "p-001"},
    }


# ──────────────────────────────────────────────────────────────────────
# 1. Re-export preservation + Protocol conformance + sentinel distinction.
# ──────────────────────────────────────────────────────────────────────


class TestReExportsAndConformance:
    def test_re_exports_credential_adapter(self) -> None:
        """T6 watchpoint #1 — re-export preserved. The Sprint-8A
        ``CredentialAdapter`` Protocol re-export from
        ``sandbox.credentials`` MUST survive T6's shim replacement
        so every consumer that imports from this path stays
        backward-compat."""
        from cognic_agentos.sandbox.admission import (
            CredentialAdapter as AdmissionCA,
        )
        from cognic_agentos.sandbox.credentials import (
            CredentialAdapter as CredentialsCA,
        )

        assert AdmissionCA is CredentialsCA, (
            "T6 MUST preserve the CredentialAdapter re-export from "
            "sandbox.credentials; T8-era TestReExportEquivalence pins "
            "object identity across both paths"
        )

    def test_re_exports_kernel_default_credential_adapter(self) -> None:
        """T6 watchpoint #1 — re-export preserved for the sentinel."""
        from cognic_agentos.sandbox.admission import (
            KernelDefaultCredentialAdapter as AdmissionKDCA,
        )
        from cognic_agentos.sandbox.credentials import (
            KernelDefaultCredentialAdapter as CredentialsKDCA,
        )

        assert AdmissionKDCA is CredentialsKDCA

    def test_vault_credential_adapter_structurally_conforms_to_protocol(
        self,
    ) -> None:
        """T6 watchpoint #3 — structural Protocol conformance pinned.
        VaultCredentialAdapter implements all 3 post-T5 Protocol
        methods (fetch_secret + mint_lease + revoke_lease), so it
        satisfies the @runtime_checkable isinstance gate."""
        adapter = VaultCredentialAdapter(transport=_mock_transport(), settings=_settings())
        assert isinstance(adapter, CredentialAdapter)

    def test_vault_credential_adapter_is_not_the_sentinel(self) -> None:
        """T6 watchpoint #2 — real adapter is NOT the sentinel. The
        isinstance(KernelDefaultCredentialAdapter) check that
        admit_policy uses at admission.py:258 + admission.py:384 to
        gate per-policy ``vault_path``/``requires_credentials`` must
        continue to distinguish sentinel from real adapter."""
        adapter = VaultCredentialAdapter(transport=_mock_transport(), settings=_settings())
        assert not isinstance(adapter, KernelDefaultCredentialAdapter)

    def test_vault_credential_adapter_in_credentials_module_all(self) -> None:
        """T6 — VaultCredentialAdapter MUST be in
        ``sandbox.credentials.__all__`` so star-imports + IDE
        autocomplete + ``pydoc`` see the canonical export. Catches
        a regression that adds the class but forgets to export it."""
        from cognic_agentos.sandbox import credentials as creds_module

        assert "VaultCredentialAdapter" in creds_module.__all__
        # Plus the Sprint-8A re-exports must still be in __all__.
        assert "CredentialAdapter" in creds_module.__all__
        assert "KernelDefaultCredentialAdapter" in creds_module.__all__


# ──────────────────────────────────────────────────────────────────────
# 2. fetch_secret — user correction #1: NO catch-all; exceptions PROPAGATE.
# ──────────────────────────────────────────────────────────────────────


class TestFetchSecretContractDoesNotSwallow:
    """User correction #1 (Round-0): the plan sketch's
    ``try / except Exception: return None`` catch-all in
    ``fetch_secret`` contradicts the CredentialAdapter Protocol
    docstring at admission.py:119. T6 implements the corrected
    behaviour: exceptions propagate; None ONLY for not-found."""

    async def test_fetch_secret_returns_none_for_transport_read_returns_none(
        self,
    ) -> None:
        """T6 — Protocol contract: ``None`` is the not-found absence
        signal. ``transport.read(path) is None`` (Vault 404) → fetch_secret
        returns None per the Protocol docstring's "or None if not found"
        clause. THIS is the only None-returning path."""
        transport = _mock_transport(read_return=None)
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        result = await adapter.fetch_secret("secret/foo")
        assert result is None

    async def test_fetch_secret_propagates_vault_down_exception(self) -> None:
        """T6 USER-LOCKED CORRECTION #1 PIN — transport exceptions
        PROPAGATE unchanged. ``hvac.exceptions.VaultDown`` on the
        underlying ``transport.read`` must bubble up to the caller,
        NOT be silently swallowed into None. The Protocol docstring
        at admission.py:119 explicitly forbids the silent-None
        substitution; the plan-of-record sketch's ``try / except
        Exception: return None`` violated this contract."""
        transport = _mock_transport(read_side_effect=hvac.exceptions.VaultDown("503"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(hvac.exceptions.VaultDown):
            await adapter.fetch_secret("secret/foo")

    async def test_fetch_secret_propagates_forbidden_exception(self) -> None:
        """T6 USER-LOCKED CORRECTION #1 PIN — auth failures propagate.
        ``hvac.exceptions.Forbidden`` (Vault 403) on transport.read
        bubbles up so the caller can audit. Silent None on auth-deny
        would let a misconfigured tenant silently appear as a
        not-found secret instead of a permissions issue."""
        transport = _mock_transport(read_side_effect=hvac.exceptions.Forbidden("403"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(hvac.exceptions.Forbidden):
            await adapter.fetch_secret("secret/foo")

    async def test_fetch_secret_propagates_connection_error(self) -> None:
        """T6 USER-LOCKED CORRECTION #1 PIN — network failures
        propagate. ConnectionError (TCP / DNS) bubbles up — silent
        None would mask a network outage as a missing secret."""
        transport = _mock_transport(read_side_effect=ConnectionError("DNS"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(ConnectionError):
            await adapter.fetch_secret("secret/foo")

    async def test_fetch_secret_propagates_invalid_path(self) -> None:
        """T6 USER-LOCKED CORRECTION #1 PIN — even hvac's 'InvalidPath'
        (which the transport surfaces as an exception on some Vault
        configurations) propagates rather than being collapsed to
        None. The Protocol contract is strict: the caller decides
        whether InvalidPath should be treated as not-found or
        misconfiguration."""
        transport = _mock_transport(read_side_effect=hvac.exceptions.InvalidPath("404"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(hvac.exceptions.InvalidPath):
            await adapter.fetch_secret("secret/foo")


# ──────────────────────────────────────────────────────────────────────
# 3. fetch_secret — happy paths + shape-mismatch raise.
# ──────────────────────────────────────────────────────────────────────


class TestFetchSecretHappyPathAndShapeContract:
    async def test_fetch_secret_returns_value_for_kv_v1_shape(self) -> None:
        """T6 — Vault KV v1 returns ``{"data": {"value": "<v>"}}``.
        Wave-1 single-value convention: the secret is stored under
        a top-level ``value`` key inside ``data``. fetch_secret
        returns the str."""
        transport = _mock_transport(read_return={"data": {"value": "secret-v1"}})
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        result = await adapter.fetch_secret("secret/foo")
        assert result == "secret-v1"

    async def test_fetch_secret_returns_value_for_kv_v2_nested_shape(self) -> None:
        """T6 — Vault KV v2 returns
        ``{"data": {"data": {"value": "<v>"}}}``. The adapter
        normalises the KV-v2 nesting (mirrors the existing
        ``VaultAdapter`` normalisation at db/adapters/vault_adapter.py
        :90-95) so the caller sees a uniform ``str | None`` regardless
        of the deployed KV mount version."""
        transport = _mock_transport(read_return={"data": {"data": {"value": "secret-v2"}}})
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        result = await adapter.fetch_secret("secret/foo")
        assert result == "secret-v2"

    async def test_fetch_secret_raises_for_missing_value_key(self) -> None:
        """T6 — shape mismatch: secret IS present but does NOT have
        the Wave-1 single-value ``value`` key. The user-locked
        correction #1 wording is "return None ONLY for
        transport.read(path) is None / not-found-style absence" —
        a present-but-multi-field secret is NOT not-found absence,
        so silent None is wrong. Raise VaultProtocolError so the
        caller knows to use the lease API for multi-field secrets."""
        transport = _mock_transport(read_return={"data": {"username": "u", "password": "p"}})
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultProtocolError, match="value"):
            await adapter.fetch_secret("secret/foo")

    async def test_fetch_secret_raises_for_non_dict_data(self) -> None:
        """T6 — shape mismatch: transport returned response but its
        ``data`` field is not a dict. Defensive against future Vault
        shape drift; consistent with T4's
        ``VaultProtocolError`` for non-dict-data responses in
        lease_credential."""
        transport = _mock_transport(read_return={"data": ["wrong", "shape"]})
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultProtocolError, match="dict"):
            await adapter.fetch_secret("secret/foo")


# ──────────────────────────────────────────────────────────────────────
# 4. mint_lease — delegates to lease_credential; PRESERVES taxonomy.
# ──────────────────────────────────────────────────────────────────────


class TestMintLeasePreservesTaxonomy:
    """User correction #2 (Round-0) + Sprint-10.1 amendment per ADR-004
    §25: no closed-enum collapse in T6. mint_lease delegates to
    core.vault.lease_credential; the ``core.vault`` exception taxonomy
    propagates UNCHANGED — ``mint_lease`` can surface the full 5-value
    taxonomy post-Sprint-10.1 (VaultUnavailable / VaultPathNotFound /
    VaultAuthDenied / VaultProtocolError / VaultLeaseGrantExceedsRequest
    — the 5th is raised by ``core.vault.lease_credential`` when the
    post-mint TTL gate fires, with best-effort ``transport.revoke``
    before the raise); ``revoke_lease`` remains scoped to the
    hvac/transport-error 4-value subset (VaultUnavailable /
    VaultPathNotFound / VaultAuthDenied / VaultProtocolError) because
    revoke has no granted-vs-requested concept. The sandbox-closed-enum
    collapse to ``sandbox_credential_*`` belongs at the admission
    boundary (T7+ + the Sprint-10.1 backend except-tuple extension
    4 → 5 to also catch ``VaultLeaseGrantExceedsRequest``), NOT here."""

    async def test_mint_lease_returns_credential_lease_on_happy_path(self) -> None:
        """T6 — mint_lease delegates to core.vault.lease_credential
        and returns the resulting ``CredentialLease`` unchanged."""
        transport = _mock_transport(lease_return=_happy_lease_payload())
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        lease = await adapter.mint_lease(_request())
        assert isinstance(lease, CredentialLease)
        assert lease.lease_id == "database/creds/payment-readonly/lease-abc-123"
        assert lease.token == {"username": "u-001", "password": "p-001"}

    async def test_mint_lease_calls_transport_lease_via_core_vault(self) -> None:
        """T6 — mint_lease wires through core.vault.lease_credential
        which calls ``transport.lease(secret_path, ttl_s)``. Pinning
        the contract pathway end-to-end so a future refactor that
        accidentally bypasses core.vault is caught."""
        transport = _mock_transport(lease_return=_happy_lease_payload())
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        await adapter.mint_lease(_request())
        transport.lease.assert_awaited_once_with("database/creds/payment-readonly", 900)

    async def test_mint_lease_preserves_vault_unavailable(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — VaultUnavailable from
        core.vault.lease_credential PROPAGATES unchanged. Adapter
        MUST NOT collapse to a SandboxLifecycleRefused or any other
        sandbox-closed-enum reason — that's T7+ admission-boundary
        work."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.VaultDown("503"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultUnavailable):
            await adapter.mint_lease(_request())

    async def test_mint_lease_preserves_vault_path_not_found(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — VaultPathNotFound
        propagates unchanged."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.InvalidPath("404"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultPathNotFound):
            await adapter.mint_lease(_request())

    async def test_mint_lease_preserves_vault_auth_denied(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — VaultAuthDenied
        propagates unchanged."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.Forbidden("403"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultAuthDenied):
            await adapter.mint_lease(_request())

    async def test_mint_lease_preserves_vault_protocol_error(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — VaultProtocolError
        (synthesised by core.vault for malformed Vault responses)
        propagates unchanged."""
        transport = _mock_transport(lease_return=None)  # malformed: no body
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultProtocolError):
            await adapter.mint_lease(_request())


# ──────────────────────────────────────────────────────────────────────
# 5. revoke_lease — delegates to revoke_credential; PRESERVES taxonomy.
# ──────────────────────────────────────────────────────────────────────


class TestRevokeLeasePreservesTaxonomy:
    async def test_revoke_lease_delegates_to_transport_revoke(self) -> None:
        """T6 — revoke_lease delegates to core.vault.revoke_credential
        which calls ``transport.revoke(lease_id)``."""
        transport = _mock_transport()
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        await adapter.revoke_lease("lease-abc")
        transport.revoke.assert_awaited_once_with("lease-abc")

    async def test_revoke_lease_preserves_vault_unavailable(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — VaultUnavailable
        propagates on revoke path."""
        transport = _mock_transport(revoke_side_effect=hvac.exceptions.VaultDown("503"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultUnavailable):
            await adapter.revoke_lease("lease-abc")

    async def test_revoke_lease_preserves_vault_path_not_found(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — VaultPathNotFound
        propagates on revoke (e.g., lease_id no longer valid)."""
        transport = _mock_transport(revoke_side_effect=hvac.exceptions.InvalidPath("lease gone"))
        adapter = VaultCredentialAdapter(transport=transport, settings=_settings())
        with pytest.raises(VaultPathNotFound):
            await adapter.revoke_lease("lease-abc")


# ──────────────────────────────────────────────────────────────────────
# 6. No closed-enum mapping creep — AST source-grep regression.
# ──────────────────────────────────────────────────────────────────────


class TestNoClosedEnumMappingCreepInT6:
    """User watchpoint #5 (Round-0): T6 ships a thin delegation
    adapter. The sandbox-closed-enum collapse to
    ``sandbox_credential_mint_failed_*`` belongs at the
    create / admission boundary (T7+ admission.py) — NOT inside
    VaultCredentialAdapter.

    AST-walk regression (not bare grep) so the production module's
    docstring is free to NAME the closed-enum types in its
    intent-documentation prose without tripping the regression. We
    catch the actual creep PATTERNS: import statements + raise
    statements that would produce a real collapse.

    Test-only drift detector per
    ``[[feedback_drift_detector_test_only_no_runtime_import]]`` —
    parses the production module source from disk; no runtime
    cross-module imports involved."""

    def _module(self) -> ast.Module:
        root = Path(cognic_agentos.__file__).resolve().parent
        src = (root / "sandbox" / "credentials.py").read_text(encoding="utf-8")
        return ast.parse(src)

    def test_no_import_of_sandbox_refusal_reason_or_lifecycle_refused(
        self,
    ) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — source MUST NOT
        import SandboxRefusalReason or SandboxLifecycleRefused.
        Catches the most-likely creep pattern: pulling the
        closed-enum / refusal-exception into the adapter's
        namespace as a prelude to mapping."""
        module = self._module()
        forbidden = {"SandboxRefusalReason", "SandboxLifecycleRefused"}
        offenders: list[str] = []
        for node in ast.walk(module):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in forbidden:
                        offenders.append(f"from {node.module} import {alias.name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in forbidden:
                        offenders.append(f"import {alias.name}")
        assert not offenders, (
            "VaultCredentialAdapter MUST NOT import the sandbox closed-enum / "
            "refusal exception (Round-0 user-locked correction #2). The "
            "collapse to sandbox_credential_mint_failed_* belongs at the "
            "admission boundary (T7+). Found imports: " + ", ".join(offenders)
        )

    def test_no_raise_of_sandbox_lifecycle_refused(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — source MUST NOT
        contain a ``raise SandboxLifecycleRefused(...)`` statement.
        Catches the actual collapse pattern at the raise site
        (where the closed-enum reason would actually be supplied)."""
        module = self._module()
        offenders: list[int] = []
        for node in ast.walk(module):
            if isinstance(node, ast.Raise) and node.exc is not None:
                exc = node.exc
                # ``raise X(...)`` — exc is a Call whose func is a Name.
                # ``raise X`` (bare) — exc is a Name directly.
                if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                    if exc.func.id == "SandboxLifecycleRefused":
                        offenders.append(node.lineno)
                elif isinstance(exc, ast.Name) and exc.id == "SandboxLifecycleRefused":
                    offenders.append(node.lineno)
        assert not offenders, (
            "VaultCredentialAdapter MUST NOT raise SandboxLifecycleRefused "
            "(Round-0 user-locked correction #2 — preserve the T4 4-value "
            "core.vault taxonomy; admission boundary does the collapse). "
            f"Found raise sites at lines: {offenders}"
        )

    def test_no_sandbox_credential_mint_failed_literal_in_code(self) -> None:
        """T6 USER-LOCKED CORRECTION #2 PIN — source MUST NOT
        contain a ``sandbox_credential_mint_failed_*`` string
        literal in CODE (constant nodes used as values), as
        distinct from docstrings (constant nodes used as the first
        statement of a module / class / function body, which the
        AST tracks as ``ast.Expr(value=ast.Constant(value=<str>))``
        at the head of a body).

        The docstring exemption is intentional: the production
        module's docstring documents the closed-enum names to
        explain the intent (no collapse here). The regression
        catches the actual creep pattern: passing the literal as
        a kwarg / argument inside ``mint_lease`` / ``revoke_lease``
        / ``fetch_secret`` (e.g., ``reason="sandbox_credential_mint_failed_..."``)."""
        module = self._module()

        # Collect every Constant node that IS a docstring (first
        # Expr-statement of a body). Set-based exclusion so we can
        # walk the AST once and skip those exact node IDs.
        docstring_node_ids: set[int] = set()
        for parent in ast.walk(module):
            body = getattr(parent, "body", None)
            if (
                isinstance(body, list)
                and body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstring_node_ids.add(id(body[0].value))

        offenders: list[int] = []
        for node in ast.walk(module):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "sandbox_credential_mint_failed_" in node.value
                and id(node) not in docstring_node_ids
            ):
                offenders.append(node.lineno)
        assert not offenders, (
            "VaultCredentialAdapter source MUST NOT contain any "
            "sandbox_credential_mint_failed_* string literal in CODE "
            "(docstrings exempt — they document the no-collapse intent). "
            f"Found code-literal occurrences at lines: {offenders}. "
            "That collapse belongs at the admission boundary (T7+)."
        )
