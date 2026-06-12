"""Sprint 13.5c3 — the single memory value-digest definition (ADR-019 + ADR-014).

Extracted from ``core/memory/storage.py`` at 13.5c3 T3.5 so BOTH the storage
layer (the ``memory.write`` chain row's ``redacted_value_digest``) and the
write gate (the approval binding's ``value_digest`` field per the c3 spec
§3.3 F4 lock) share ONE digest definition WITHOUT the gate runtime-importing
``core.memory.storage`` — the Layer-C gate-bypass architecture fence at
``tests/unit/architecture/test_memory_layer_c_no_direct_storage.py`` pins
that ONLY the composition root imports the storage module.
"""

from __future__ import annotations

import hashlib

from cognic_agentos.core.canonical import canonical_bytes


def _value_digest(value: object) -> str:
    """SHA-256 of the canonical JSON bytes of ``value``.

    This is the ONLY representation of a memory value that may enter the
    hash chain — the raw value lives solely in the ``memory_records.value``
    column (default-deny long-term, regulator-erasure pathway per ADR-019).
    Uses ``core/canonical.canonical_bytes`` so the digest is stable across
    Python versions + platforms."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()
