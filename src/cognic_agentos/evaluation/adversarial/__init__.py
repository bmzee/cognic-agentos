"""ADR-011 Sprint-13b adversarial testing package.

Re-exports the canonical corpus-owned adversarial vocabulary for ergonomics; the
single source of truth (and the loader's fail-closed contract) stays in
``evaluation/corpus.py``.
"""

from __future__ import annotations

from cognic_agentos.evaluation.corpus import (
    _DEFERRED_CATEGORIES,
    _RUNNABLE_CATEGORIES,
    AdversarialBlock,
    AttackCategory,
    MutationStrategy,
)

__all__ = [
    "_DEFERRED_CATEGORIES",
    "_RUNNABLE_CATEGORIES",
    "AdversarialBlock",
    "AttackCategory",
    "MutationStrategy",
]
