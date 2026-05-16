"""Sprint 7B.4 T3 — cursor encoder + decoder regressions for the
16-byte chain-derived event_id payload (chain_disc + sequence +
ordinal + type_hash) per ADR-020 + the design spec §4.3.

protocol/ui_events.py is on the AGENTS.md critical-controls list +
stop-rule surface; these regressions defend the cursor-encode/decode
boundary against drift (wire-protocol-public — any change breaks
SSE-resume cursor compatibility across released versions).
"""

from __future__ import annotations

import hashlib

import pytest

from cognic_agentos.protocol.ui_events import (
    ChainCursor,
    CursorChainUnsupported,
    CursorMalformed,
    _chain_derived_event_id,
    _decode_chain_cursor,
)


class TestChainDerivedEventIdRoundtrip:
    """Round-trip + determinism regressions for the cursor encoder/decoder."""

    def test_encode_decode_typed_event(self) -> None:
        event_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=12345,
            ordinal=0,
            family="policy",
            type_="rbac_denied",
        )
        # Wire-format-public: `evt_` prefix + 26-char Crockford-base32 ULID.
        assert event_id.startswith("evt_")
        assert len(event_id) == 30  # "evt_" + 26

        cursor = _decode_chain_cursor(event_id)
        assert isinstance(cursor, ChainCursor)
        assert cursor.chain_id == "decision_history"
        assert cursor.sequence == 12345
        assert cursor.ordinal == 0
        # type_hash = first 6 bytes of sha256("<family>.<type_>") per the
        # locked payload layout.
        assert cursor.type_hash == hashlib.sha256(b"policy.rbac_denied").digest()[:6]

    def test_encode_is_deterministic(self) -> None:
        """Determinism is load-bearing: the broker resolves event_id by
        re-encoding the persisted (sequence, ordinal, family, type)
        tuple; if encoding were nondeterministic the captured event_id
        would diverge from the SSE-fanout event_id."""
        a = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=1,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        )
        b = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=1,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        )
        assert a == b

    def test_different_sequences_yield_different_ids(self) -> None:
        a = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=1,
            ordinal=0,
            family="policy",
            type_="rbac_denied",
        )
        b = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=2,
            ordinal=0,
            family="policy",
            type_="rbac_denied",
        )
        assert a != b

    def test_different_ordinals_yield_different_ids(self) -> None:
        """Ordinal-axis discrimination: typed projector (ordinal 0) vs
        decision_audit mirror (ordinal 1) on the SAME chain row MUST
        produce different cursors so SSE Last-Event-ID resume is unambiguous."""
        a = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=1,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        )
        b = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=1,
            ordinal=1,
            family="decision_audit",
            type_="event_appended",
        )
        assert a != b

    def test_different_families_yield_different_ids(self) -> None:
        """Defence-in-depth — same (sequence, ordinal) under two different
        family.type tuples MUST still diverge through the type_hash bytes
        even though the chain_disc + seq + ordinal prefix is identical."""
        a = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=42,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        )
        b = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=42,
            ordinal=0,
            family="policy",
            type_="rbac_denied",
        )
        assert a != b


class TestCursorRefusals:
    """Negative-path regressions — every malformed input MUST refuse
    with a closed-enum exception type (no silent fallback per the
    production-grade rule)."""

    def test_malformed_prefix_refused(self) -> None:
        with pytest.raises(CursorMalformed):
            _decode_chain_cursor("notanevt_0123456789ABCDEFGHIJK")

    def test_wrong_length_refused(self) -> None:
        # "evt_" prefix but too short.
        with pytest.raises(CursorMalformed):
            _decode_chain_cursor("evt_TOOSHORT")

    def test_base32_decode_failure_refused(self) -> None:
        # 30 chars total, "evt_" prefix, but the 26-char body contains
        # characters outside the Crockford base32 alphabet.
        with pytest.raises(CursorMalformed):
            _decode_chain_cursor("evt_!!!!!!!!!!!!!!!!!!!!!!!!!!")

    def test_audit_chain_disc_unsupported_wave_1(self) -> None:
        """chain_disc=0x02 is reserved for Wave-2 audit-event SSE. A
        cursor minted with chain_id='audit_event' must decode-refuse
        in Wave-1 with CursorChainUnsupported, NOT a silent fallback
        to decision_history."""
        bogus = _chain_derived_event_id(
            chain_id="audit_event",
            sequence=1,
            ordinal=0,
            family="tool_call",
            type_="approved",
        )
        with pytest.raises(CursorChainUnsupported):
            _decode_chain_cursor(bogus)

    def test_unknown_chain_disc_refused_fail_closed(self) -> None:
        """A chain_disc byte OUTSIDE the {0x01, 0x02} reverse map (e.g. 0x03)
        MUST refuse fail-closed with CursorChainUnsupported. The encoder
        rejects unknown ChainId at the `_CHAIN_DISCRIMINATOR_BYTES[...]`
        lookup, so this branch is reachable only by a forged cursor
        constructed at the byte level — we use ULID.from_bytes directly to
        bypass the encoder and pin the decoder's unknown-byte rejection.

        Threat model: an attacker (or a future code path that adds new
        chain types without updating the reverse map) sending a cursor
        with an unrecognized chain_disc MUST NOT silently fall through to
        the `chain_disc != 0x01` branch — distinct refusal vocabularies
        let operators / reviewers tell "unknown chain type" apart from
        "known but Wave-2-reserved" at incident-response time."""
        from ulid import ULID

        # Construct a 16-byte payload with chain_disc=0x03 (not in either
        # forward or reverse map) directly at the byte level.
        forged = bytes([0x03]) + (1).to_bytes(8, "big") + bytes([0]) + b"\x00" * 6
        assert len(forged) == 16
        forged_event_id = f"evt_{ULID.from_bytes(forged)}"
        with pytest.raises(CursorChainUnsupported, match="not in Wave-1 supported set"):
            _decode_chain_cursor(forged_event_id)
