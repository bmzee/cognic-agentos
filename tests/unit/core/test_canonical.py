"""Canonical form + hash function — single source of truth for the
audit_event / decision_history hash chain.

Tests are deliberately exhaustive: any change to canonical-form rules is
a wire-protocol change for evidence-pack export per ADR-006. A change
that breaks any of these tests requires:

1. An explicit `schema_version` bump in the audit_event +
   decision_history migrations.
2. Per-AGENTS.md stop-rule amendment landed in PR #5: human review on
   every edit.
3. Updated goldens with the new canonical bytes pinned.
"""

from __future__ import annotations

import hashlib
import math
import uuid
from datetime import UTC, datetime, tzinfo
from decimal import Decimal
from enum import Enum, StrEnum
from zoneinfo import ZoneInfo

import pytest

from cognic_agentos.core.canonical import (
    ZERO_HASH,
    canonical_bytes,
    hash_record,
)


class TestCanonicalDeterminism:
    """Order-independence + whitespace-stripping rules — the
    cross-platform reproducibility guarantee."""

    def test_dict_key_order_independent(self) -> None:
        a = canonical_bytes({"a": 1, "b": 2, "c": 3})
        b = canonical_bytes({"c": 3, "b": 2, "a": 1})
        assert a == b

    def test_nested_dict_key_order_independent(self) -> None:
        a = canonical_bytes({"x": {"a": 1, "b": 2}})
        b = canonical_bytes({"x": {"b": 2, "a": 1}})
        assert a == b

    def test_list_order_preserved(self) -> None:
        # Lists are ordered; flipping changes canonical bytes (and thus the hash).
        a = canonical_bytes({"items": [1, 2, 3]})
        b = canonical_bytes({"items": [3, 2, 1]})
        assert a != b

    def test_no_whitespace(self) -> None:
        out = canonical_bytes({"a": 1, "b": "x"})
        assert b" " not in out
        assert b"\n" not in out
        assert b"\t" not in out

    def test_unicode_preserved(self) -> None:
        out = canonical_bytes({"name": "Zürich"})
        # ensure_ascii=False → multibyte chars land as UTF-8 bytes verbatim.
        assert "Zürich".encode() in out


class TestCanonicalTypes:
    """Per-type serialization rules. Each is a wire-format pin."""

    def test_datetime_iso8601_with_offset(self) -> None:
        dt = datetime(2026, 4, 28, 10, 30, 45, tzinfo=UTC)
        out = canonical_bytes({"ts": dt})
        # UTC datetimes serialize with explicit +00:00 — predictable across
        # Python versions and platforms.
        assert b'"ts":"2026-04-28T10:30:45+00:00"' in out

    def test_uuid_hex_with_dashes_lowercase(self) -> None:
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        out = canonical_bytes({"id": u})
        assert b'"id":"12345678-1234-5678-1234-567812345678"' in out

    def test_bytes_base64(self) -> None:
        out = canonical_bytes({"b": b"\x00\x01\x02\x03"})
        # base64 of \x00\x01\x02\x03 == "AAECAw==".
        assert b'"b":"AAECAw=="' in out

    def test_bytearray_base64(self) -> None:
        out = canonical_bytes({"b": bytearray(b"\x00\x01\x02\x03")})
        assert b'"b":"AAECAw=="' in out

    def test_decimal_string(self) -> None:
        # Decimal serializes as str so precision is preserved verbatim;
        # round-tripping a Decimal through float would lose 19.99 → 19.989...
        out = canonical_bytes({"price": Decimal("19.99")})
        assert b'"price":"19.99"' in out

    def test_decimal_nan_rejected(self) -> None:
        # Round-4 hardening: Decimal('NaN') would otherwise serialize
        # as the JSON string "NaN" via str(o), which is valid JSON but
        # weakens the non-finite-value discipline in a finance-grade
        # governance chain.
        with pytest.raises(ValueError, match="non-finite Decimal"):
            canonical_bytes({"x": Decimal("NaN")})

    def test_decimal_infinity_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-finite Decimal"):
            canonical_bytes({"x": Decimal("Infinity")})

    def test_decimal_negative_infinity_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-finite Decimal"):
            canonical_bytes({"x": Decimal("-Infinity")})

    def test_nan_rejected_top_level(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonical_bytes({"x": math.nan})

    def test_inf_rejected_top_level(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonical_bytes({"x": math.inf})

    def test_nan_rejected_nested(self) -> None:
        # Defends the chain against NaN sneaking through nested structures.
        with pytest.raises(ValueError, match="non-finite"):
            canonical_bytes({"outer": {"inner": math.nan}})

    def test_inf_rejected_in_list(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonical_bytes({"vec": [1.0, 2.0, math.inf]})

    def test_unsupported_type_raises_typeerror(self) -> None:
        # Object with no JSON-default rule → TypeError. Tests the
        # "explicit allow-list" property — random custom types cannot
        # silently slip into the canonical envelope.
        class Custom:
            pass

        with pytest.raises(TypeError, match="cannot serialize"):
            canonical_bytes({"x": Custom()})

    def test_enum_value_serialized(self) -> None:
        # The Enum branch is part of the wire-format contract; pin it
        # with an explicit test rather than relying on transitive
        # coverage from envelope tests.
        class Verdict(StrEnum):
            APPROVED = "approved"
            DENIED = "denied"

        out = canonical_bytes({"v": Verdict.APPROVED})
        assert out == b'{"v":"approved"}'

    def test_tuple_valued_enum_rejected(self) -> None:
        # Round-4 hardening: Enum.value is returned to json.dumps
        # AFTER the pre-walk, so a tuple-valued enum would silently
        # collapse to a JSON array — same chain integrity hole the
        # tuple rule blocks for normal tuples.
        class TupleEnum(Enum):
            X = (1, 2)

        with pytest.raises(TypeError, match="string-valued Enum"):
            canonical_bytes({"x": TupleEnum.X})

    def test_dict_valued_enum_rejected(self) -> None:
        # Same hole, dict-valued. The non-string-key rule would not
        # protect against this because the dict is delivered to
        # json.dumps via _json_default, after the pre-walk.
        class DictEnum(Enum):
            X = {1: "x"}  # noqa: RUF012  -- Enum member, not a mutable class default

        with pytest.raises(TypeError, match="string-valued Enum"):
            canonical_bytes({"x": DictEnum.X})

    def test_int_valued_enum_rejected(self) -> None:
        # Sprint-2 governance enums are all StrEnum (CognicAction,
        # ComplianceVerdict, FieldStatus). Non-string values are
        # rejected to formalise that contract — relaxing it later
        # would require an ADR amendment.
        class IntFlag(Enum):
            X = 42

        with pytest.raises(TypeError, match="string-valued Enum"):
            canonical_bytes({"x": IntFlag.X})

    def test_naive_datetime_rejected(self) -> None:
        # Naive datetimes (no tzinfo) yield an ambiguous ISO 8601
        # string with no offset — chain material an examiner cannot
        # reproduce deterministically. Reject loudly.
        with pytest.raises(ValueError, match="naive datetime"):
            canonical_bytes({"ts": datetime(2026, 4, 28, 10, 30, 45)})

    def test_datetime_with_tzinfo_returning_none_offset_rejected(self) -> None:
        # Python's official "aware" predicate is ``tzinfo is not None
        # AND utcoffset() is not None``. A tzinfo subclass that returns
        # None from utcoffset() satisfies the first half but not the
        # second; isoformat() would emit no offset, producing the same
        # ambiguous chain material as a naive datetime.
        class LyingTz(tzinfo):
            def utcoffset(self, dt: datetime | None) -> None:
                return None

            def dst(self, dt: datetime | None) -> None:
                return None

            def tzname(self, dt: datetime | None) -> str:
                return "lies"

        dt = datetime(2026, 4, 28, 10, 30, 45, tzinfo=LyingTz())
        with pytest.raises(ValueError, match="naive datetime"):
            canonical_bytes({"ts": dt})

    def test_non_utc_aware_datetime_serializes_with_offset(self) -> None:
        # Aware datetimes in any timezone are accepted; the canonical
        # form preserves the offset verbatim. Round-tripping requires
        # operators to keep the original tzinfo — there is no implicit
        # UTC normalization.
        dt = datetime(2026, 4, 28, 10, 30, 45, tzinfo=ZoneInfo("Europe/Zurich"))
        out = canonical_bytes({"ts": dt})
        # Europe/Zurich in late April is CEST = UTC+02:00.
        assert b'"ts":"2026-04-28T10:30:45+02:00"' in out


class TestCanonicalDictKeyDiscipline:
    """Round-2-amendment-strict dict-key rules. JSON key coercion in
    Python's stdlib silently turns int/float/bool/None keys into
    strings, which means {1: "a"} and {"1": "a"} produce identical
    canonical bytes. For evidence canonicalization that's a chain
    integrity hole — payload structure can change without the chain
    detecting it. Reject non-string keys at the canonical_bytes
    boundary."""

    def test_int_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-string dict key"):
            canonical_bytes({1: "a"})

    def test_bool_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-string dict key"):
            canonical_bytes({True: "a"})

    def test_none_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-string dict key"):
            canonical_bytes({None: "a"})

    def test_uuid_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-string dict key"):
            canonical_bytes({uuid.UUID(int=0): "a"})

    def test_nan_key_rejected(self) -> None:
        # The reviewer's P1 reproducer: previously serialized as
        # b'{"NaN":"x"}' — a documented contract violation. Now
        # rejected by the non-string-key rule (nan is a float, not a
        # string). The non-finite-float rule is also a backstop.
        with pytest.raises(ValueError, match=r"non-string dict key|non-finite"):
            canonical_bytes({math.nan: "x"})

    def test_inf_key_rejected(self) -> None:
        # Same as above for +infinity.
        with pytest.raises(ValueError, match=r"non-string dict key|non-finite"):
            canonical_bytes({math.inf: "x"})

    def test_neg_inf_key_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"non-string dict key|non-finite"):
            canonical_bytes({-math.inf: "x"})

    def test_nested_dict_int_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-string dict key"):
            canonical_bytes({"outer": {1: "x"}})

    def test_dict_in_list_int_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-string dict key"):
            canonical_bytes({"items": [{"ok": 1}, {2: "bad"}]})


class TestCanonicalTupleRejection:
    """Round-3 amendment: tuples reject with TypeError. Python's
    json.dumps silently converts tuples to JSON arrays, which means
    ``{'x': (1, 2)}`` and ``{'x': [1, 2]}`` produce identical canonical
    bytes — same hash from different Python structures. Reject at the
    canonical_bytes boundary; call sites convert tuples to lists
    explicitly (audit + decision envelopes already do this for
    iso_controls etc.)."""

    def test_top_level_tuple_value_rejected(self) -> None:
        with pytest.raises(TypeError, match="tuple not allowed"):
            canonical_bytes({"x": (1, 2)})

    def test_top_level_tuple_alone_rejected(self) -> None:
        with pytest.raises(TypeError, match="tuple not allowed"):
            canonical_bytes((1, 2))

    def test_nested_tuple_in_list_rejected(self) -> None:
        with pytest.raises(TypeError, match="tuple not allowed"):
            canonical_bytes({"x": [1, (2, 3)]})

    def test_nested_tuple_in_dict_rejected(self) -> None:
        with pytest.raises(TypeError, match="tuple not allowed"):
            canonical_bytes({"outer": {"inner": (1, 2)}})

    def test_namedtuple_rejected(self) -> None:
        # NamedTuples are subclasses of tuple — same JSON-array
        # collision risk. Reject for the same reason.
        from collections import namedtuple

        Point = namedtuple("Point", ["x", "y"])
        with pytest.raises(TypeError, match="tuple not allowed"):
            canonical_bytes({"p": Point(1, 2)})

    def test_list_with_same_values_still_works(self) -> None:
        # Sanity check the rejection isn't over-broad: lists containing
        # the same values as the rejected tuples still serialize.
        out = canonical_bytes({"x": [1, 2]})
        assert out == b'{"x":[1,2]}'


class TestHashRecord:
    """Hash framing: sha256(prev_hash || canonical_bytes)."""

    def test_zero_hash_is_32_bytes(self) -> None:
        assert bytes(32) == ZERO_HASH
        assert len(ZERO_HASH) == 32

    def test_hash_is_32_bytes(self) -> None:
        h = hash_record(b'{"k":"v"}', ZERO_HASH)
        assert len(h) == 32

    def test_hash_is_deterministic(self) -> None:
        h1 = hash_record(b'{"k":"v"}', ZERO_HASH)
        h2 = hash_record(b'{"k":"v"}', ZERO_HASH)
        assert h1 == h2

    def test_different_canonical_produces_different_hash(self) -> None:
        h1 = hash_record(b'{"k":"v"}', ZERO_HASH)
        h2 = hash_record(b'{"k":"w"}', ZERO_HASH)
        assert h1 != h2

    def test_different_prev_produces_different_hash(self) -> None:
        h1 = hash_record(b'{"k":"v"}', ZERO_HASH)
        h2 = hash_record(b'{"k":"v"}', bytes([1] * 32))
        assert h1 != h2

    def test_invalid_prev_hash_length_rejected(self) -> None:
        # 31, 33, 0 — all wrong; only 32 bytes is valid.
        with pytest.raises(ValueError, match="32 bytes"):
            hash_record(b'{"k":"v"}', bytes(31))
        with pytest.raises(ValueError, match="32 bytes"):
            hash_record(b'{"k":"v"}', bytes(33))
        with pytest.raises(ValueError, match="32 bytes"):
            hash_record(b'{"k":"v"}', b"")


class TestGoldenHashes:
    """Hard-coded canonical-bytes + hash goldens for the Sprint-2 envelope.

    ANY change to these assertions means canonical-form rules changed. A
    change requires:

      1. An explicit `schema_version` bump in audit_event +
         decision_history migrations (Sprint 2 ships at version 1).
      2. Updated goldens pinned to the new canonical bytes.
      3. Per AGENTS.md stop rule: human review on the change.

    Goldens are computed once and pinned forever (well, until v2)."""

    def test_canonical_bytes_golden_simple(self) -> None:
        # {"a":1,"b":"x"} — two keys, sorted, no whitespace, UTF-8.
        assert canonical_bytes({"a": 1, "b": "x"}) == b'{"a":1,"b":"x"}'

    def test_canonical_bytes_golden_full_envelope(self) -> None:
        # The exact envelope shape Sprint 2 audit will produce. The expected
        # bytes are the alphabetically-sorted JSON form. Frozen 2026-04-28.
        envelope = {
            "schema_version": 1,
            "chain_id": "audit_event",
            "record_id": "12345678-1234-5678-1234-567812345678",
            "sequence": 1,
            "tenant_id": None,
            "created_at": datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC),
            "event_type": "tool_invocation",
            "request_id": "r-1",
            "trace_id": None,
            "span_id": None,
            "langfuse_trace_id": None,
            "provider_label": None,
            "iso_controls": [],
            "payload": {"tool": "echo"},
        }
        canonical = canonical_bytes(envelope)
        expected = (
            b'{"chain_id":"audit_event","created_at":"2026-04-28T12:00:00+00:00",'
            b'"event_type":"tool_invocation","iso_controls":[],'
            b'"langfuse_trace_id":null,"payload":{"tool":"echo"},'
            b'"provider_label":null,"record_id":"12345678-1234-5678-1234-567812345678",'
            b'"request_id":"r-1","schema_version":1,"sequence":1,"span_id":null,'
            b'"tenant_id":null,"trace_id":null}'
        )
        assert canonical == expected

        # Genesis hash for this exact canonical form.
        h = hash_record(canonical, ZERO_HASH)
        assert h.hex() == hashlib.sha256(ZERO_HASH + expected).hexdigest()
