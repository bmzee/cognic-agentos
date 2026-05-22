"""Sprint 9 T10 — merkle.py negative-path coverage top-up.

The T2 suite covers root computation + inclusion-proof round-trips; this
file tops up the two fail-closed branches — a malformed proof side and
an out-of-range leaf index — for the T10 critical-controls gate.
"""

from __future__ import annotations

import pytest

from cognic_agentos.compliance.iso42001.merkle import (
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)


def test_verify_inclusion_rejects_malformed_side() -> None:
    """A proof entry with an unknown side value fails closed (False).

    The root here is the VALID single-leaf root for ``leaf`` — that makes
    the test load-bearing: an implementation that merely *ignored* the
    unknown ``"Z"`` side (instead of failing closed) would fold nothing
    into ``acc``, leave it equal to that root, reconstruct index 0, and
    wrongly return True. Against an empty-tree root the test would pass
    either way and prove nothing.
    """
    leaf = b"\x11" * 32
    proof = [(b"\x22" * 32, "Z")]  # "Z" is neither L, R, nor P
    root = merkle_root([leaf])  # the valid single-leaf root for `leaf`
    assert verify_inclusion(leaf, 0, proof, root) is False


def test_inclusion_proof_raises_on_out_of_range_index() -> None:
    with pytest.raises(IndexError, match="out of range"):
        inclusion_proof([b"\x11" * 32], 5)
