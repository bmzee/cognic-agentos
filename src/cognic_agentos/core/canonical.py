"""Canonical form + hash function — single source of truth for the
audit_event / decision_history hash chain.

**Critical-controls module.** Per AGENTS.md amendment landed in PR #5:
every edit requires human review. Canonical form is the wire-format
for evidence-pack export per ADR-006; any change is a wire-protocol
change that breaks past evidence verification. Changes require:

1. An explicit `schema_version` bump in the audit_event +
   decision_history migrations (Sprint 2 ships at version 1).
2. Updated goldens in tests/unit/core/test_canonical.py pinned to the
   new canonical bytes.
3. A documented canonical-form decision in
   docs/superpowers/plans/<sprint-N>-... or an ADR amendment.

Reimplementing canonicalization elsewhere (in core/audit, core/
decision_history, core/chain_verifier, or any future consumer) is a
doctrine violation: different bytes for the same logical record means
a silent chain break.

Canonical form rules (Sprint 2, schema_version=1):

- JSON output with **sorted dict keys**; no whitespace; preserved
  Unicode (`ensure_ascii=False`).
- **Dict keys must be strings.** Non-string keys (int, float, bool,
  None, UUID, ...) are rejected with ``ValueError``. Python's
  ``json.dumps`` would otherwise silently coerce them: ``{1: "x"}``
  and ``{"1": "x"}`` produce identical canonical bytes, which means
  payload structure could be altered without breaking the chain.
- Datetimes → ISO 8601 with explicit timezone offset (UTC datetimes
  serialize as ``2026-04-28T10:30:45+00:00``, not ``Z``). **Naive
  datetimes are rejected with ``ValueError``** — ambiguous chain
  material is a doctrine violation. The awareness check uses
  ``o.tzinfo is not None and o.utcoffset() is not None``; a
  ``tzinfo`` subclass that returns ``None`` from ``utcoffset()``
  is also rejected, because ``isoformat()`` would still emit no
  offset.
- **Tuples are rejected with ``TypeError``.** Python's
  ``json.dumps`` silently converts tuples to JSON arrays, which
  means ``{'x': (1, 2)}`` and ``{'x': [1, 2]}`` produce identical
  canonical bytes — different Python structures, same hash. For
  evidence canonicalization that's a chain integrity hole. Convert
  tuples to lists explicitly at the call site (the audit + decision
  envelopes already do this for ``iso_controls`` etc.).
- UUIDs → 36-char hex-with-dashes (lowercase) via ``str(uuid)``.
- bytes / bytearray → standard base64 (RFC 4648 §4) ASCII string.
- Decimal → ``str(value)`` so precision is preserved verbatim.
  **Non-finite Decimals (``Decimal('NaN')`` / ``Decimal('Infinity')``)
  are rejected with ``ValueError``**, mirroring the float rule. JSON
  syntax permits ``"NaN"`` as a string, but emitting it weakens the
  non-finite-value discipline that the governance chain depends on
  for finance-grade reproducibility.
- Enum → ``.value``. **Only string-valued enums are accepted**; an
  enum with a tuple, dict, list, int, or other non-string value
  raises ``TypeError``. ``Enum.value`` is returned to ``json.dumps``
  AFTER the pre-walk, so non-string values would bypass the
  unsafe-value rules (e.g. ``TupleEnum.X = (1, 2)`` would silently
  collapse to a JSON array). Sprint-2 governance enums
  (``CognicAction`` / ``ComplianceVerdict`` / ``FieldStatus``) are
  all ``StrEnum``; this rule formalises that contract.
- Floating-point ``NaN`` / ``Infinity`` → ``ValueError`` anywhere
  in the structure, including dict keys. Three-layer defence:
    1. Pre-walk in ``_reject_unsafe_values`` rejects NaN / Infinity
       in dict keys + values + lists + tuples.
    2. ``json.dumps(allow_nan=False)`` raises if anything still
       leaks through.
    3. Defensive branch in ``_json_default`` (dead code in normal
       flow; documents the rule).
- Custom types with no rule above → ``TypeError``. Allow-list shape
  by design — random objects cannot silently slip into the chain.

Hash framing: ``sha256(prev_hash || canonical_bytes)``. ``prev_hash``
must be exactly 32 bytes; genesis is 32 zero bytes (``ZERO_HASH``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

#: Genesis prev_hash — 32 zero bytes.
ZERO_HASH: bytes = bytes(32)


def _json_default(o: Any) -> Any:
    """Per-type JSON serialization rule. Allow-list by design.

    The float branch is documentation rather than a hot path:
    ``_reject_unsafe_values`` runs before ``json.dumps`` and raises
    on any NaN/Inf in the object tree, so non-finite floats never
    reach this callback. ``json.dumps(allow_nan=False)`` is the
    second defence layer.
    """

    if isinstance(o, datetime):
        # Naive datetimes (and datetimes with a tzinfo subclass that
        # returns None from utcoffset()) yield an ambiguous ISO 8601
        # string with no offset — ``2026-04-28T10:30:45``. That's
        # chain material an examiner cannot reproduce deterministically.
        # Python's official "aware" predicate is ``tzinfo is not None
        # AND utcoffset() is not None``; mirror it here.
        if o.tzinfo is None or o.utcoffset() is None:
            raise ValueError(
                f"naive datetime not allowed in canonical form "
                f"(must have tzinfo AND a non-None utcoffset()): {o!r}"
            )
        return o.isoformat()
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, bytes | bytearray):
        return base64.b64encode(bytes(o)).decode("ascii")
    if isinstance(o, Decimal):
        # Non-finite Decimals (NaN / Infinity / -Infinity) would
        # serialize as the string "NaN" / "Infinity" via str(o).
        # Reject for parity with the float NaN/Infinity rule —
        # finance-grade governance does not emit these values.
        if not o.is_finite():
            raise ValueError(f"non-finite Decimal not allowed in canonical form: {o!r}")
        return str(o)
    if isinstance(o, Enum):
        # Enum.value is returned to json.dumps AFTER the pre-walk in
        # _reject_unsafe_values, which means a non-string enum value
        # bypasses the safety rules entirely. Restrict Enum support
        # to string-valued enums; Sprint-2 governance enums are all
        # StrEnum, so this rule formalises that contract.
        if not isinstance(o.value, str):
            raise TypeError(
                f"only string-valued Enum members are allowed in canonical "
                f"form (Enum.value bypasses the safety walker): "
                f"{type(o).__name__}.{o.name} has "
                f"{type(o.value).__name__} value {o.value!r}"
            )
        return o.value
    if isinstance(o, float) and not math.isfinite(o):
        raise ValueError(f"non-finite float not allowed in canonical form: {o!r}")
    raise TypeError(
        f"canonical_bytes cannot serialize {type(o).__name__}; "
        f"add an explicit rule before passing this type into the chain"
    )


def _reject_unsafe_values(obj: Any) -> None:
    """Walk ``obj`` and raise on:

    1. Non-string dict keys. Python's ``json.dumps`` silently coerces
       int/float/bool/None keys to their string repr, which means
       ``{1: "x"}`` and ``{"1": "x"}`` produce identical canonical
       bytes. For evidence canonicalization, two different payload
       structures yielding the same hash is a chain integrity hole.
    2. Tuples (anywhere). ``json.dumps`` silently converts tuples to
       JSON arrays, so ``{'x': (1, 2)}`` and ``{'x': [1, 2]}`` produce
       identical canonical bytes — same hash from different Python
       structures. Reject tuples at the canonical_bytes boundary;
       call sites convert ``tuple[T, ...]`` fields to ``list(...)``
       explicitly (audit + decision envelopes already do this).
    3. Non-finite floats (NaN, Infinity) anywhere in the structure,
       including dict keys, dict values, and list elements.

    Walks dicts (keys + values) + lists. Tuples raise. Per-type
    serialization rules (datetime tzinfo, Decimal precision, ...)
    live in ``_json_default``.
    """

    # ``isinstance(obj, tuple)`` must come before ``list`` because
    # ``namedtuple`` is a subclass of tuple but not list.
    # Important: bool is a subclass of int, but tuple is not a subclass
    # of list (they're sibling sequence types), so the order matters
    # only for catch-tuples-before-treating-them-as-lists.
    if isinstance(obj, tuple):
        raise TypeError(
            f"tuple not allowed in canonical form (would silently "
            f"serialize as a JSON array, colliding with list inputs); "
            f"convert to list explicitly at the call site: {obj!r}"
        )
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError(f"non-finite float not allowed in canonical form: {obj!r}")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(
                    f"non-string dict key not allowed in canonical form: "
                    f"{k!r} ({type(k).__name__}); JSON key coercion would "
                    f"otherwise let payload structure change without "
                    f"breaking the chain"
                )
            # Keys established as strings; walk values for nested
            # dicts / lists / tuples / non-finite floats.
            _reject_unsafe_values(v)
        return
    if isinstance(obj, list):
        for v in obj:
            _reject_unsafe_values(v)


def canonical_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical UTF-8 JSON bytes.

    Deterministic across Python versions and platforms (verified by
    hard-coded golden hashes in tests/unit/core/test_canonical.py).
    Three-layer defence against NaN/Infinity sneaking into the chain:
    pre-walk → ``allow_nan=False`` → defensive ``_json_default``
    branch.
    """

    _reject_unsafe_values(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def hash_record(canonical: bytes, prev_hash: bytes) -> bytes:
    """Compute ``sha256(prev_hash || canonical)``.

    ``prev_hash`` MUST be exactly 32 bytes. Genesis is ``ZERO_HASH``.
    Returns the 32-byte digest.
    """

    if len(prev_hash) != 32:
        raise ValueError(f"prev_hash must be exactly 32 bytes, got {len(prev_hash)}")
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(canonical)
    return h.digest()
