"""Sprint 10.6 T21 slice 2 — pair-invariant guard for
``(requires_credentials, credential_decls)`` per the user-locked
T21 entry decisions (locks 1 + 4).

Wave-1 ``SandboxBackend.create()`` accepts TWO Sequences keyed by
manifest declaration order:

  * ``requires_credentials: Sequence[VaultLeaseRequest]`` — used by
    the mint loop (one ``mint_lease`` call per request).
  * ``credential_decls: Sequence[CredentialDecl]`` — used by the
    T18 ``compute_projection_plan`` (one plan per decl).

This module pins three fail-loud invariants the lifecycle
integration relies on:

  1. **Both-empty or both-non-empty** — silent ``zip()`` truncation
     would otherwise let a caller pass leases that never project
     (decls empty) OR build planner state with no leases (decls
     non-empty).
  2. **Length match** — silent ``zip()`` would drop trailing
     elements of the longer Sequence.
  3. **Per-index ``request.secret_path == decl.vault_path``** —
     the Vault-side path the lease was minted from MUST equal the
     manifest-side path the planner uses for byte projection. A
     mismatch silently projects from a different Vault path than
     the lease was minted on (credential-leak bug class the
     runtime preflight cannot catch).
  4. **Per-index ``request.tenant_id == decl.tenant_id``** —
     the lease-side tenant identity (used by the T21 audit emit
     helpers to derive ``DecisionRecord.tenant_id``) MUST equal
     the planner-side tenant identity (used by the executor +
     ``credentials_projected`` payload via ``decl.tenant_id``).
     A mismatch silently splits the per-credential evidence
     across two tenants (round-1 P1 reviewer find).

All four failures raise ``ValueError`` — programmer-error contract
violations, NOT wire-public credential refusals (same exception-type
discriminator as the T19/T20 boundary-grammar guards). The calling
layer should pair the inputs via the manifest projection; reaching
this guard with a mismatch means an upstream binding bug.

Evaluation order (pinned by tests):
  one-side-empty → length-mismatch → vault_path-mismatch → tenant_id-mismatch
"""

from __future__ import annotations

from collections.abc import Sequence

from cognic_agentos.core.vault import VaultLeaseRequest
from cognic_agentos.sandbox.projection import CredentialDecl


def verify_credentials_pair_invariants(
    *,
    requires_credentials: Sequence[VaultLeaseRequest],
    credential_decls: Sequence[CredentialDecl],
) -> None:
    """Raise ``ValueError`` on any pair-invariant violation.

    Called from ``SandboxBackend.create()`` BEFORE the substrate
    preflight + mint loop per spec §5.8 step 1 (the pair-shape
    check is admission-time, not lifecycle-time).

    Raises:
      * ``ValueError`` (with message starting with ``"both must be
        non-empty"``) — exactly one of the inputs is empty.
      * ``ValueError`` (with ``"length mismatch"``) — both
        non-empty but lengths differ.
      * ``ValueError`` (with ``"vault_path mismatch at index N"``)
        — per-index ``request.secret_path != decl.vault_path``.
      * ``ValueError`` (with ``"tenant_id mismatch at index N"``)
        — per-index ``request.tenant_id != decl.tenant_id``
        (round-1 P1 reviewer-locked invariant — closes the
        split-evidence bug class where lease-side and planner-side
        ship different tenants).
    """
    n_requests = len(requires_credentials)
    n_decls = len(credential_decls)

    # Invariant 1: both-empty or both-non-empty.
    if (n_requests == 0) != (n_decls == 0):
        raise ValueError(
            f"requires_credentials and credential_decls: both must be non-empty "
            f"OR both empty; got len(requires_credentials)={n_requests}, "
            f"len(credential_decls)={n_decls}"
        )

    # Invariant 2: length match (only reachable when both non-empty
    # OR both empty; the empty/empty case has n_requests==n_decls==0
    # so the inequality is False and we skip directly to the loop
    # which iterates zero times).
    if n_requests != n_decls:
        raise ValueError(
            f"requires_credentials and credential_decls: length mismatch; "
            f"got len(requires_credentials)={n_requests}, "
            f"len(credential_decls)={n_decls}"
        )

    # Invariants 3 + 4: per-index vault_path + tenant_id equality.
    # vault_path-mismatch takes precedence over tenant_id-mismatch
    # (path-mismatch is a more severe leak class — projecting from
    # the wrong Vault path — so reporting it first matches what the
    # operator most needs to see). Pinned by
    # ``test_vault_path_mismatch_takes_precedence_over_tenant_mismatch``.
    for i, (request, decl) in enumerate(zip(requires_credentials, credential_decls, strict=True)):
        if request.secret_path != decl.vault_path:
            raise ValueError(
                f"requires_credentials and credential_decls: vault_path "
                f"mismatch at index {i}; "
                f"request.secret_path={request.secret_path!r} != "
                f"decl.vault_path={decl.vault_path!r}"
            )
        if request.tenant_id != decl.tenant_id:
            raise ValueError(
                f"requires_credentials and credential_decls: tenant_id "
                f"mismatch at index {i}; "
                f"request.tenant_id={request.tenant_id!r} != "
                f"decl.tenant_id={decl.tenant_id!r}"
            )
