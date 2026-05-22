"""Sprint 9 T2 — domain-separated Merkle tree."""

from __future__ import annotations

import hashlib

import pytest

from cognic_agentos.compliance.iso42001.merkle import (
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)

_A = b"\x11" * 32
_B = b"\x22" * 32
_C = b"\x33" * 32


def _leaf(h: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + h).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_empty_tree_root_is_sha256_of_empty() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_root_is_the_domain_separated_leaf() -> None:
    assert merkle_root([_A]) == _leaf(_A)


def test_two_leaf_root_is_node_of_two_leaves() -> None:
    assert merkle_root([_A, _B]) == _node(_leaf(_A), _leaf(_B))


def test_odd_leaf_promotes_lone_node_unchanged() -> None:
    # RFC-6962 style: the lone third leaf is promoted unchanged.
    expected = _node(_node(_leaf(_A), _leaf(_B)), _leaf(_C))
    assert merkle_root([_A, _B, _C]) == expected


def test_root_is_deterministic_and_order_sensitive() -> None:
    assert merkle_root([_A, _B]) == merkle_root([_A, _B])
    assert merkle_root([_A, _B]) != merkle_root([_B, _A])


def test_leaf_and_node_domains_are_separated() -> None:
    # A leaf hash must never collide with an internal node hash.
    assert _leaf(_A) != hashlib.sha256(b"\x01" + _A).digest()


@pytest.mark.parametrize("idx", [0, 1, 2, 3])
def test_inclusion_proof_round_trips(idx: int) -> None:
    leaves = [_A, _B, _C, b"\x44" * 32]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, idx)
    assert verify_inclusion(leaves[idx], idx, proof, root) is True


def test_inclusion_proof_rejects_wrong_leaf() -> None:
    leaves = [_A, _B]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    assert verify_inclusion(_C, 0, proof, root) is False


def test_inclusion_proof_rejects_wrong_index() -> None:
    # Correct leaf, correct proof for position 2 — but the verifier is
    # told the leaf sits at position 0. The proof's L/R/P side sequence
    # encodes position 2; verify_inclusion MUST bind `index` and reject.
    leaves = [_A, _B, _C, b"\x44" * 32]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 2)
    assert verify_inclusion(_C, 0, proof, root) is False


@pytest.mark.parametrize("idx", [0, 1, 2])
def test_inclusion_proof_round_trips_odd_tree(idx: int) -> None:
    # A 3-leaf tree forces a lone-promotion level — exercises the "P"
    # proof element and index reconstruction across a skipped node.
    leaves = [_A, _B, _C]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, idx)
    assert verify_inclusion(leaves[idx], idx, proof, root) is True
