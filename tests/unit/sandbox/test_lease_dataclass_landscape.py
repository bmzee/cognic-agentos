"""Sprint 10 T4 — three-lease-dataclass landscape pin (spec §2.3).

The Sprint 10 design INTRODUCES a third lease-shaped frozen dataclass:

* ``SecretLease`` (``db/adapters/protocols.py``, Sprint 1C) —
  seconds-to-hours / per-call / low-level Vault lease primitive.
* ``VaultLeaseRef`` (``sandbox/checkpoint_store.py``, Sprint 8.5) —
  days-to-weeks / 1 per session / checkpoint-encryption-key meta.
* ``CredentialLease`` (``core/vault.py``, Sprint 10 NEW) —
  seconds-to-hours / N per session / per-operation sandbox creds.

Per the user-locked Q1 = B1 design call (R0 brainstorm): the three
distinct types ARE intentional — collapsing them would muddy
contracts with very different lifecycles (long-lived/singular
checkpoint-key vs short-lived/plural/revoked-on-destroy
operation-credentials vs the kernel-secrets low-level primitive).

This test pins the three-dataclass landscape so a future refactor
that accidentally consolidates them is caught at import time —
without this guard, a well-intentioned dedup PR could quietly
collapse ``CredentialLease`` into ``SecretLease`` (they look
similar) and silently change the sandbox-credential-lease wire
contract.
"""

from __future__ import annotations

import dataclasses


def test_three_distinct_lease_dataclass_types() -> None:
    """T4 — the three lease-shaped dataclasses MUST stay distinct
    types per spec §2.3 design call Q1 = B1.

    Implementation note: the three references are widened to
    ``type[object]`` before the ``is not`` comparisons so mypy
    cannot statically narrow them to the three concrete types and
    flag the comparison as non-overlapping ([comparison-overlap]).
    The runtime check stays the same — a future refactor that
    aliases ``CredentialLease = SecretLease`` flips the
    ``is not`` chain to False and trips the test."""
    from cognic_agentos.core.vault import CredentialLease
    from cognic_agentos.db.adapters.protocols import SecretLease
    from cognic_agentos.sandbox.checkpoint_store import VaultLeaseRef

    credential_lease: type[object] = CredentialLease
    secret_lease: type[object] = SecretLease
    vault_lease_ref: type[object] = VaultLeaseRef

    assert credential_lease is not secret_lease
    assert credential_lease is not vault_lease_ref
    assert secret_lease is not vault_lease_ref


def test_secret_lease_shape() -> None:
    """T4 — Sprint-1C SecretLease carries the documented 3-field
    shape (lease_id + ttl_s + value). Pin against accidental field
    drift that would change the Sprint-1C kernel-secrets adapter
    wire contract."""
    from cognic_agentos.db.adapters.protocols import SecretLease

    field_names = {f.name for f in dataclasses.fields(SecretLease)}
    assert field_names == {"lease_id", "ttl_s", "value"}, (
        f"SecretLease field set drift: got {sorted(field_names)}"
    )


def test_vault_lease_ref_shape() -> None:
    """T4 — Sprint-8.5 VaultLeaseRef carries the documented 4-field
    shape (vault_path + role + duration_s + admission_lease_id) per
    its frozen-class docstring."""
    from cognic_agentos.sandbox.checkpoint_store import VaultLeaseRef

    field_names = {f.name for f in dataclasses.fields(VaultLeaseRef)}
    assert field_names == {
        "vault_path",
        "role",
        "duration_s",
        "admission_lease_id",
    }, f"VaultLeaseRef field set drift: got {sorted(field_names)}"


def test_credential_lease_shape() -> None:
    """T4 — Sprint-10 CredentialLease carries the documented 6-field
    shape per spec §3.2."""
    from cognic_agentos.core.vault import CredentialLease

    field_names = {f.name for f in dataclasses.fields(CredentialLease)}
    assert field_names == {
        "lease_id",
        "request",
        "token",
        "minted_at",
        "ttl_s_granted",
        "expires_at",
    }, f"CredentialLease field set drift: got {sorted(field_names)}"
