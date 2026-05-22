"""Domain-separated Merkle tree over evidence-pack chain hashes — Sprint 9 (ADR-006).

WIRE-PUBLIC — examiners recompute the root independently. RFC-6962-style
domain separation: leaf hash = SHA-256(0x00 || row_hash); internal node =
SHA-256(0x01 || left || right). A lone rightmost node is promoted
unchanged. The empty tree's root is SHA-256(b"").

Defined entirely here — never in ``core/canonical.py`` (the canonical
hash-chain framing is a separate, untouched stop-rule module).
"""

from __future__ import annotations

import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(row_hash: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + row_hash).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def merkle_root(row_hashes: list[bytes]) -> bytes:
    """Root over ``row_hashes`` (each a raw chain-row hash), in given order."""
    if not row_hashes:
        return hashlib.sha256(b"").digest()
    level = [_leaf_hash(h) for h in row_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promote lone node unchanged
        level = nxt
    return level[0]


def inclusion_proof(row_hashes: list[bytes], index: int) -> list[tuple[bytes, str]]:
    """Sibling-path proof for leaf ``index``: one ``(sibling, side)`` entry
    per tree level. ``side`` is ``"L"`` (sibling on the left of the proven
    node), ``"R"`` (sibling on the right), or ``"P"`` (the proven node was
    the lone odd-one-out and was promoted unchanged — there is no sibling,
    so the entry's hash is ``b""``). Emitting an entry at *every* level —
    including lone-promotion levels — makes the side sequence an
    unambiguous encoding of ``index``, which ``verify_inclusion`` binds."""
    if not 0 <= index < len(row_hashes):
        raise IndexError(f"leaf index {index} out of range for {len(row_hashes)} leaves")
    level = [_leaf_hash(h) for h in row_hashes]
    proof: list[tuple[bytes, str]] = []
    pos = index
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        if pos % 2 == 1:
            proof.append((level[pos - 1], "L"))
        elif pos + 1 < len(level):
            proof.append((level[pos + 1], "R"))
        else:
            proof.append((b"", "P"))  # lone promoted node — no sibling
        pos //= 2
        level = nxt
    return proof


def verify_inclusion(
    row_hash: bytes, index: int, proof: list[tuple[bytes, str]], root: bytes
) -> bool:
    """True iff ``row_hash`` is the leaf at position ``index`` under
    ``root``. Binds all three: the proof's ``L``/``R``/``P`` sides are both
    folded into ``root`` AND reconstruct ``index`` — a proof generated for
    a different position fails the index check even when its sibling
    hashes are otherwise valid. A malformed side fails closed."""
    acc = _leaf_hash(row_hash)
    reconstructed = 0
    for bit, (sibling, side) in enumerate(proof):
        if side == "L":
            acc = _node_hash(sibling, acc)
            reconstructed |= 1 << bit
        elif side == "R":
            acc = _node_hash(acc, sibling)
        elif side == "P":
            pass  # lone promotion — acc unchanged, this index bit is 0
        else:
            return False  # malformed proof — fail closed
    return acc == root and reconstructed == index
