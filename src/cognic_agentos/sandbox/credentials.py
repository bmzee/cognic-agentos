"""Sprint 8A T8 — credentials.py re-export shim.

The canonical home of ``CredentialAdapter`` Protocol +
``KernelDefaultCredentialAdapter`` sentinel is
:mod:`cognic_agentos.sandbox.admission` (T5 commit ``4967ce8`` per the
``feedback_consumer_owned_protocol_for_unlanded_dep`` resolution rule —
T5 declared the dependency Protocols + sentinel inline in admission.py
so the critical-controls module could ship independently runnable;
T8 was scheduled to own the canonical home but the user-preferred
resolution at T5 R0 was a re-export shim, NOT a canonical-home shift).

This module is a thin re-export shim that exposes the same names at the
``cognic_agentos.sandbox.credentials`` import path. Sprint 10's
``VaultCredentialAdapter`` will replace ``KernelDefaultCredentialAdapter``
in this module without rewriting any consumer that imports from
``sandbox.credentials``.

NOT on the durable critical-controls coverage gate per spec §17
R32-doctrine carve-out — re-export shim with zero new logic. The CC risk
is covered by ``sandbox/admission.py`` already being on the gate.
Sprint 10's real ``VaultCredentialAdapter`` goes on the gate when it
lands.

Per spec §8 + ADR-004 §"Credential-scoped" + ADR-009 (pluggable adapter
layer where the real Vault implementation lives).
"""

from __future__ import annotations

from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)

__all__ = [
    "CredentialAdapter",
    "KernelDefaultCredentialAdapter",
]
