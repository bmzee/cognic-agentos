"""Sprint 10.6 T21 slice 2 — pair-invariant guard for the
``(requires_credentials, credential_decls)`` paired inputs to
``SandboxBackend.create()``.

Per the user-locked T21 entry decisions (locks 1 + 4):

  * Both inputs paired by index in manifest declaration order.
  * If one is non-empty, BOTH must be non-empty (no silent
    ``zip()`` truncation — a caller passing only credentials but
    no decls would otherwise produce sandboxes with leases that
    have no projection, OR vice versa).
  * Lengths must match exactly.
  * Per-index ``VaultLeaseRequest.secret_path == CredentialDecl.vault_path``
    — the Vault-side path the lease was minted from MUST equal the
    manifest-side path the planner uses for byte projection.

Failures here are programmer-error contract violations (the
calling layer should have already coupled lease requests to decls
via the manifest projection), NOT wire-public credential refusals.
``ValueError`` raise per the T19/T20 boundary-guard pattern.

Critical-controls from birth — owns the wire-public pair-invariant
contract; promotes to the durable per-file CC coverage gate
alongside the other T21 modules.
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.vault import VaultLeaseActorRef, VaultLeaseRequest
from cognic_agentos.sandbox._credentials_pair import (
    verify_credentials_pair_invariants,
)
from cognic_agentos.sandbox.projection import CredentialDecl


def _make_request(
    *, secret_path: str = "database/creds/db-main", tenant_id: str = "tenant-1"
) -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=300,
        tenant_id=tenant_id,
        actor_ref=VaultLeaseActorRef(actor_subject="user-1", actor_type="human"),
        scope_label="test",
    )


def _make_decl(
    *,
    logical_name: str = "db_main",
    vault_path: str = "database/creds/db-main",
    tenant_id: str = "tenant-1",
) -> CredentialDecl:
    return CredentialDecl(
        logical_name=logical_name,
        vault_path=vault_path,
        expected_fields=["password", "username"],
        ttl_s=300,
        purpose_category="application_database_read",
        purpose_description="Read-only application database access.",
        tenant_id=tenant_id,
    )


class TestBothEmptyAllowed:
    """The credentials-less sandbox path MUST stay reachable: the
    pre-T21 ``requires_credentials=()`` default surface is preserved.
    No exception when BOTH are empty.
    """

    def test_both_empty_returns_none(self) -> None:
        # Function is None-returning by contract (pure validation;
        # raise-or-return-None per the T19/T20 boundary-guard pattern).
        # The mere absence of an exception is the success signal.
        verify_credentials_pair_invariants(
            requires_credentials=(),
            credential_decls=(),
        )

    def test_both_empty_lists_also_allowed(self) -> None:
        # Sequence != Tuple — accept both empty list + empty tuple.
        verify_credentials_pair_invariants(
            requires_credentials=[],
            credential_decls=[],
        )


class TestOneSideEmptyRaises:
    """Reviewer-locked invariant #1: if one Sequence is non-empty,
    BOTH must be non-empty. A silent ``zip()`` truncation would
    otherwise let a caller mint leases that never project (decls
    empty) OR build planner state with no leases (decls non-empty).
    """

    def test_requires_credentials_non_empty_decls_empty_raises(self) -> None:
        with pytest.raises(ValueError, match=r"both must be non-empty"):
            verify_credentials_pair_invariants(
                requires_credentials=(_make_request(),),
                credential_decls=(),
            )

    def test_decls_non_empty_requires_credentials_empty_raises(self) -> None:
        with pytest.raises(ValueError, match=r"both must be non-empty"):
            verify_credentials_pair_invariants(
                requires_credentials=(),
                credential_decls=(_make_decl(),),
            )


class TestLengthMismatchRaises:
    """Reviewer-locked invariant #2: lengths MUST match exactly. A
    silent ``zip()`` truncation would otherwise lose the trailing
    elements of the longer Sequence."""

    def test_two_requests_one_decl_raises(self) -> None:
        with pytest.raises(ValueError, match=r"length mismatch"):
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(secret_path="database/creds/db-main"),
                    _make_request(secret_path="aws/creds/payments"),
                ),
                credential_decls=(_make_decl(),),
            )

    def test_one_request_two_decls_raises(self) -> None:
        with pytest.raises(ValueError, match=r"length mismatch"):
            verify_credentials_pair_invariants(
                requires_credentials=(_make_request(),),
                credential_decls=(
                    _make_decl(logical_name="db_main"),
                    _make_decl(logical_name="aws_credentials"),
                ),
            )

    def test_length_mismatch_message_carries_both_lengths(self) -> None:
        # Operator-readable error — message MUST name both lengths so
        # the offending caller can immediately see which side was off.
        with pytest.raises(ValueError) as exc_info:
            verify_credentials_pair_invariants(
                requires_credentials=(_make_request(), _make_request()),
                credential_decls=(_make_decl(),),
            )
        assert "2" in str(exc_info.value)
        assert "1" in str(exc_info.value)


class TestVaultPathMismatchRaises:
    """Reviewer-locked invariant #3: per-index
    ``request.secret_path == decl.vault_path``. The lease was minted
    from the Vault path; the planner uses that path for byte
    projection. A mismatch silently projects from a different Vault
    path than the lease was minted on — a class of credential-leak
    bug that the runtime preflight cannot catch.

    Note: ``VaultLeaseRequest.secret_path`` is the field name; user's
    lock #1 referred to it as ``vault_path`` descriptively. Same
    string value.
    """

    def test_single_pair_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match=r"vault_path mismatch at index 0"):
            verify_credentials_pair_invariants(
                requires_credentials=(_make_request(secret_path="database/creds/db-main"),),
                credential_decls=(_make_decl(vault_path="aws/creds/payments"),),
            )

    def test_second_pair_mismatch_raises(self) -> None:
        # First pair matches; second pair mismatches. Index 1 named
        # in the error.
        with pytest.raises(ValueError, match=r"vault_path mismatch at index 1"):
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(secret_path="database/creds/db-main"),
                    _make_request(secret_path="aws/creds/payments"),
                ),
                credential_decls=(
                    _make_decl(
                        logical_name="db_main",
                        vault_path="database/creds/db-main",
                    ),
                    _make_decl(
                        logical_name="aws_credentials",
                        vault_path="database/creds/wrong-engine",
                    ),
                ),
            )

    def test_error_message_carries_both_paths(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            verify_credentials_pair_invariants(
                requires_credentials=(_make_request(secret_path="database/creds/db-main"),),
                credential_decls=(_make_decl(vault_path="aws/creds/payments"),),
            )
        msg = str(exc_info.value)
        assert "database/creds/db-main" in msg
        assert "aws/creds/payments" in msg


class TestHappyPath:
    """Both inputs equal length + per-index secret_path matches. No
    raise; the pair is admissible for the T21 mint-then-project loop.
    """

    def test_single_pair_match_returns_none(self) -> None:
        # Mere absence of an exception is the success signal.
        verify_credentials_pair_invariants(
            requires_credentials=(_make_request(secret_path="database/creds/db-main"),),
            credential_decls=(_make_decl(vault_path="database/creds/db-main"),),
        )

    def test_three_pair_match_returns_none(self) -> None:
        verify_credentials_pair_invariants(
            requires_credentials=(
                _make_request(secret_path="database/creds/db-main"),
                _make_request(secret_path="aws/creds/payments"),
                _make_request(secret_path="pki/sign/external-api"),
            ),
            credential_decls=(
                _make_decl(
                    logical_name="db_main",
                    vault_path="database/creds/db-main",
                ),
                _make_decl(
                    logical_name="aws_credentials",
                    vault_path="aws/creds/payments",
                ),
                _make_decl(
                    logical_name="pki_signer",
                    vault_path="pki/sign/external-api",
                ),
            ),
        )

    def test_list_inputs_also_accepted(self) -> None:
        # Sequence — list + tuple should both work.
        verify_credentials_pair_invariants(
            requires_credentials=[_make_request(secret_path="database/creds/db-main")],
            credential_decls=[_make_decl(vault_path="database/creds/db-main")],
        )


class TestTenantIdMismatchRaises:
    """Round-1 P1 reviewer-locked invariant #4: per-index
    ``request.tenant_id == decl.tenant_id``. The lease-side
    tenant identity (used by the T21 audit emit helpers to derive
    ``DecisionRecord.tenant_id``) MUST equal the planner-side tenant
    identity (used by the executor + ``credentials_projected``
    payload via ``decl.tenant_id``).

    Reviewer-reproduced bug: pre-fix the guard accepted
    ``request.tenant_id == "tenant-a"`` paired with
    ``decl.tenant_id == "tenant-b"`` as long as ``secret_path ==
    vault_path``. The lifecycle integration would then split the
    per-credential evidence across two tenants — bank-grade
    contract violation.
    """

    def test_single_pair_tenant_mismatch_raises(self) -> None:
        # Reviewer's exact repro: same path, different tenant.
        with pytest.raises(ValueError, match=r"tenant_id mismatch at index 0"):
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(
                        secret_path="database/creds/db-main",
                        tenant_id="tenant-a",
                    ),
                ),
                credential_decls=(
                    _make_decl(
                        vault_path="database/creds/db-main",
                        tenant_id="tenant-b",
                    ),
                ),
            )

    def test_second_pair_tenant_mismatch_raises(self) -> None:
        # First pair matches; second pair mismatches. Index 1 named
        # in the error.
        with pytest.raises(ValueError, match=r"tenant_id mismatch at index 1"):
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(
                        secret_path="database/creds/db-main",
                        tenant_id="tenant-a",
                    ),
                    _make_request(
                        secret_path="aws/creds/payments",
                        tenant_id="tenant-a",
                    ),
                ),
                credential_decls=(
                    _make_decl(
                        logical_name="db_main",
                        vault_path="database/creds/db-main",
                        tenant_id="tenant-a",
                    ),
                    _make_decl(
                        logical_name="aws_credentials",
                        vault_path="aws/creds/payments",
                        tenant_id="tenant-b",
                    ),
                ),
            )

    def test_error_message_carries_both_tenants(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(
                        secret_path="database/creds/db-main",
                        tenant_id="tenant-acme-prod",
                    ),
                ),
                credential_decls=(
                    _make_decl(
                        vault_path="database/creds/db-main",
                        tenant_id="tenant-acme-dev",
                    ),
                ),
            )
        msg = str(exc_info.value)
        assert "tenant-acme-prod" in msg
        assert "tenant-acme-dev" in msg

    def test_vault_path_mismatch_takes_precedence_over_tenant_mismatch(self) -> None:
        # Both path AND tenant mismatch on the same pair — path
        # mismatch is the more severe leak class (projecting from the
        # wrong Vault path), so it MUST surface first.
        with pytest.raises(ValueError, match=r"vault_path mismatch at index 0"):
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(
                        secret_path="database/creds/db-main",
                        tenant_id="tenant-a",
                    ),
                ),
                credential_decls=(
                    _make_decl(
                        vault_path="aws/creds/payments",
                        tenant_id="tenant-b",
                    ),
                ),
            )


class TestCredentialDeclPublicSurface:
    """Per the T20 round-1 P3 doctrine (Literal aliases + helpers
    promoted to ``sandbox/__init__.py`` for consistency with
    ``PurgeReason`` / ``sandbox_lifecycle_lease_*``): ``CredentialDecl``
    is caller-facing for ``SandboxBackend.create()``'s
    ``credential_decls`` kwarg, so it MUST be importable from the
    package root + listed in ``__all__``.

    T18 originally left it in ``sandbox.projection`` only since
    nothing outside the planner used it; T21 makes it a public type.
    """

    def test_credential_decl_importable_from_package_root(self) -> None:
        from cognic_agentos.sandbox import CredentialDecl as PublicDecl
        from cognic_agentos.sandbox.projection import CredentialDecl as CanonicalDecl

        # Same canonical object — protects against a future divergent
        # re-export (a wrapper dataclass with the same name).
        assert PublicDecl is CanonicalDecl

    def test_credential_decl_in_sandbox_all_set(self) -> None:
        from cognic_agentos import sandbox as sandbox_pkg

        assert "CredentialDecl" in sandbox_pkg.__all__


class TestEvaluationOrder:
    """Pin the 4-step evaluation order:
    one-side-empty → length-mismatch → vault_path-mismatch →
    tenant_id-mismatch. A future refactor that reorders the checks
    could surface vault_path errors when the lengths obviously
    mismatch, OR length errors when one side is empty, OR
    tenant_id errors when paths mismatch (each less informative
    than the canonical message for the same root cause).

    The path-before-tenant precedence at the per-index level is
    pinned separately by
    ``TestTenantIdMismatchRaises.test_vault_path_mismatch_takes_precedence_over_tenant_mismatch``.
    """

    def test_one_empty_takes_precedence_over_length(self) -> None:
        # Empty + 2 decls — both invariants violated; the empty-side
        # message MUST be the one surfaced.
        with pytest.raises(ValueError, match=r"both must be non-empty"):
            verify_credentials_pair_invariants(
                requires_credentials=(),
                credential_decls=(_make_decl(), _make_decl()),
            )

    def test_length_mismatch_takes_precedence_over_path_mismatch(self) -> None:
        # 2 requests + 1 decl — length mismatch wins. The first pair's
        # paths might also mismatch but length error is the right
        # surface here.
        with pytest.raises(ValueError, match=r"length mismatch"):
            verify_credentials_pair_invariants(
                requires_credentials=(
                    _make_request(secret_path="database/creds/db-main"),
                    _make_request(secret_path="aws/creds/payments"),
                ),
                credential_decls=(_make_decl(vault_path="totally/different/path"),),
            )
