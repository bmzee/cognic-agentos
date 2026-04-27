"""Adapter package — protocols + (Task 5) registry / factory.

Sprint 1C T3 ships only the typed contracts in :mod:`protocols`. The
:func:`load_bundled_adapters`, :class:`AdapterRegistry`, and
:func:`build_adapters` re-exports land in T5 once the registry + factory
modules exist.
"""

from cognic_agentos.db.adapters import protocols

__all__ = ["protocols"]
