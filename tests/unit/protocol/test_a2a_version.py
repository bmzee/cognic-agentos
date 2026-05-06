# ruff: noqa: RUF001
# T8 R2 P2 #1 fixture-shape exception: this test file uses
# intentionally-ambiguous non-ASCII digit glyphs (Arabic-Indic,
# fullwidth, mathematical, Devanagari) as inbound A2A-Version
# header fixtures to verify the parser's ASCII-only digit-class
# enforcement. RUF001 fires on these literals as "ambiguous
# character" warnings — the file-level disable accepts them
# because they're the test surface itself. The implementation
# module (protocol/a2a_version.py) carries no such literals.
"""Sprint 6 T8 — protocol/a2a_version.py contract tests.

Pin the 6-case A2A-Version header negotiation matrix per
ADR-003 §"Version negotiation" + A2A-CONFORMANCE.md §"Versioning"
+ Sprint-6 plan-of-record's Doctrine Decision F (a2a_version is
on the critical-controls floor; version negotiation is wire-
protocol-public per AGENTS.md §"Wire-protocol contracts").

The 6 closed-enum :data:`A2AVersionOutcome` values map 1:1 to the
6 spec-mandated header shapes:

  1. ``A2A-Version: 1.0`` → ``accepted``
  2. Header absent → ``absent_rejected`` (per spec, absent ⇒ ``0.3``;
     AgentOS doesn't speak 0.3 + Decision Lock #1 forbids silent
     upgrade)
  3. ``A2A-Version: 0.x`` → ``legacy_rejected``
  4. ``A2A-Version: 1.<higher minor>`` → ``higher_minor_degraded``
     (processed with feature-degradation warning at the caller)
  5. ``A2A-Version: 2.x`` (or any other unknown major) →
     ``unsupported_rejected``
  6. Header malformed → ``malformed_rejected``

Pure-functional module — no I/O, no SDK, no Settings. ``A2AEndpoint``
(T9) calls into this and surfaces the response header +
spec-defined error code.
"""

from __future__ import annotations

import dataclasses
from typing import get_args

import pytest

from cognic_agentos.protocol import A2AVersionOutcome
from cognic_agentos.protocol.a2a_version import (
    PINNED_VERSION,
    negotiate_inbound_version,
    outbound_version_header,
)

# =============================================================================
# 6-case spec matrix — one class per outcome
# =============================================================================


class TestAccepted:
    """Case 1: ``A2A-Version: 1.0`` (matches pinned version)."""

    def test_exact_pinned_version_accepted(self) -> None:
        decision = negotiate_inbound_version(a2a_version_header="1.0")
        assert decision.outcome == "accepted"
        assert decision.parsed_major == 1
        assert decision.parsed_minor == 0
        assert decision.response_header_value == "1.0"

    def test_whitespace_around_version_tolerated(self) -> None:
        """Spec-permitted leading/trailing whitespace per HTTP header
        conventions; the regex tolerates it."""
        decision = negotiate_inbound_version(a2a_version_header="  1.0  ")
        assert decision.outcome == "accepted"


class TestAbsentRejected:
    """Case 2: header absent → rejected with ``Supported-A2A-Versions:
    1.0`` response header. Per A2A 1.0 spec, an absent header is
    interpreted as version ``0.3``; AgentOS doesn't speak 0.3, so
    we refuse rather than silently upgrade (Sprint-6 Decision
    Lock #1)."""

    def test_none_header_rejected(self) -> None:
        decision = negotiate_inbound_version(a2a_version_header=None)
        assert decision.outcome == "absent_rejected"
        assert decision.parsed_major is None
        assert decision.parsed_minor is None
        # The response header MUST advertise our pinned version so
        # callers know what to retry with.
        assert decision.response_header_value == "1.0"


class TestLegacyRejected:
    """Case 3: ``A2A-Version: 0.x`` (any 0.x legacy version) →
    rejected with ``Supported-A2A-Versions: 1.0``."""

    @pytest.mark.parametrize(
        "header,expected_minor",
        [
            ("0.0", 0),
            ("0.1", 1),
            ("0.2", 2),
            ("0.3", 3),  # the spec's "absent ⇒ 0.3" mapping; explicit form is also rejected
            ("0.99", 99),
        ],
    )
    def test_legacy_version_rejected(self, header: str, expected_minor: int) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "legacy_rejected"
        assert decision.parsed_major == 0
        assert decision.parsed_minor == expected_minor
        assert decision.response_header_value == "1.0"


class TestHigherMinorDegraded:
    """Case 4: ``A2A-Version: 1.<higher minor>`` (same major, newer
    minor) → accepted with feature-degradation warning. AgentOS
    processes the call but the caller may use features only in the
    higher minor — the caller (``A2AEndpoint``) surfaces the
    warning."""

    @pytest.mark.parametrize(
        "header,expected_minor",
        [
            ("1.1", 1),
            ("1.2", 2),
            ("1.10", 10),
            ("1.99", 99),
        ],
    )
    def test_higher_minor_accepted_with_degradation(self, header: str, expected_minor: int) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "higher_minor_degraded"
        assert decision.parsed_major == 1
        assert decision.parsed_minor == expected_minor

    def test_lower_minor_NOT_higher_minor(self) -> None:
        """Defensive: ``1.0`` vs default-pinned ``1.0`` is a same-
        major exact-match (case 1), NOT a higher-minor case. The
        pinned-minor parameter MUST be respected."""
        decision = negotiate_inbound_version(
            a2a_version_header="1.0",
            pinned_major=1,
            pinned_minor=2,  # operator pinned to 1.2
        )
        # Caller's "1.0" is LOWER than pinned 1.2 → unsupported,
        # NOT higher-minor.
        assert decision.outcome == "unsupported_rejected"


class TestUnsupportedRejected:
    """Case 5: any unknown major (``2.x``, ``3.x``, etc.) → rejected
    with ``Supported-A2A-Versions: 1.0``."""

    @pytest.mark.parametrize(
        "header,expected_major",
        [
            ("2.0", 2),
            ("2.1", 2),
            ("3.0", 3),
            ("99.0", 99),
            ("10.5", 10),
        ],
    )
    def test_future_major_rejected(self, header: str, expected_major: int) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "unsupported_rejected"
        assert decision.parsed_major == expected_major
        assert decision.response_header_value == "1.0"


class TestMalformedRejected:
    """Case 6: header malformed → rejected with spec-defined parse
    error. Catches every shape that doesn't match
    ``\\d+\\.\\d+`` (with optional whitespace)."""

    @pytest.mark.parametrize(
        "header",
        [
            "",  # empty
            "1",  # single segment, no dot
            "1.0.0",  # three segments
            "1.0-rc",  # build metadata
            "1.0+1",  # PEP-440 local version
            "v1.0",  # leading 'v'
            "1.0a",  # alpha suffix
            "abc",  # non-numeric
            ".",  # bare dot
            "1.",  # missing minor
            ".0",  # missing major
            "1..0",  # double dot
            "1.0\n2.0",  # newline injection (multi-line header)
            "1,0",  # comma instead of dot
            "1 0",  # space instead of dot
            "-1.0",  # negative major (regex \\d+ rejects '-')
            "1.-0",  # negative minor (regex rejects)
            "1.0.0.0",  # four segments
        ],
    )
    def test_malformed_header_rejected(self, header: str) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "malformed_rejected"
        assert decision.parsed_major is None
        assert decision.parsed_minor is None
        assert decision.response_header_value == "1.0"


class TestStrictHttpOwsPadding:
    """**T8 R1 P2 #1 contract tests:** the regex's optional padding
    MUST be HTTP OWS (RFC 7230 §3.2.3 — SP or HTAB only). The
    earlier ``\\s*`` pattern matched all Unicode whitespace,
    accepting CR / LF / form-feed / non-breaking-space etc. For an
    HTTP wire-protocol gate, that's a header-injection bypass —
    a value like ``\\n1.0`` would parse as accepted but the raw
    LF could leak into downstream HTTP rendering surfaces.
    """

    @pytest.mark.parametrize(
        "header",
        [
            "\n1.0",  # leading LF
            "1.0\n",  # trailing LF
            "\r1.0",  # leading CR
            "1.0\r",  # trailing CR
            "\r\n1.0",  # CRLF before
            "1.0\r\n",  # CRLF after
            "\f1.0",  # form-feed
            "1.0\v",  # vertical-tab
            " 1.0",
            " 1.0",
        ],
    )
    def test_non_http_ows_padding_rejected_as_malformed(self, header: str) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "malformed_rejected"
        assert decision.parsed_major is None

    @pytest.mark.parametrize(
        "header",
        [
            " 1.0",  # leading SP
            "1.0 ",  # trailing SP
            "\t1.0",  # leading HTAB
            "1.0\t",  # trailing HTAB
            "  \t1.0\t  ",  # mixed SP + HTAB
        ],
    )
    def test_http_ows_padding_accepted(self, header: str) -> None:
        """Negative control: legitimate HTTP OWS padding (SP / HTAB)
        is still tolerated."""
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "accepted"


class TestOversizedSegments:
    """**T8 R1 P2 #2 contract tests:** the regex caps each segment
    at 10 digits so the int() conversion never approaches
    Python's 4300-digit str-to-int DoS-mitigation limit (PEP 657).
    Without this cap, an attacker-controlled header like
    ``1.<5000 digits>`` would match the regex and then raise raw
    ``ValueError`` from ``int()`` — escaping the closed-enum /
    audit path entirely.
    """

    @pytest.mark.parametrize(
        "header,description",
        [
            ("1." + "9" * 11, "minor of 11 digits"),
            ("9" * 11 + ".0", "major of 11 digits"),
            ("9" * 100 + ".0", "major of 100 digits"),
            ("1." + "9" * 5000, "minor of 5000 digits (would trip Py3.11+ int-conversion limit)"),
            ("9" * 5000 + ".0", "major of 5000 digits"),
        ],
    )
    def test_oversized_segment_rejected_as_malformed(self, header: str, description: str) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "malformed_rejected", (
            f"oversized segment ({description}) escaped closed-enum"
        )
        assert decision.parsed_major is None
        assert decision.parsed_minor is None

    def test_max_allowed_segment_length_accepted(self) -> None:
        """Negative control: the maximum permitted segment length
        (10 digits) is still accepted. The regex bound is exactly
        ``[1-9][0-9]{0,9}``; ``9999999999`` (10 9s) is the boundary."""
        # Pin to a specific 10-digit minor so we land in
        # higher_minor_degraded (same major as default 1, minor
        # higher than 0).
        decision = negotiate_inbound_version(a2a_version_header="1.9999999999")
        assert decision.outcome == "higher_minor_degraded"
        assert decision.parsed_minor == 9999999999


class TestNonAsciiDigitsRejected:
    """**T8 R2 P2 #1 contract tests:** Python's ``\\d`` is
    Unicode-aware (matches Arabic-Indic, fullwidth, mathematical
    digit classes), and ``int()`` accepts those forms. For an
    HTTP wire-protocol version gate, accepted syntax MUST be
    ASCII-only. The regex's switch from ``\\d`` to ``[0-9]``
    closes this — non-ASCII digit shapes fall through to
    ``malformed_rejected``.
    """

    @pytest.mark.parametrize(
        "header,description",
        [
            # Literal non-ASCII glyphs are used here as the test
            # surface — these ARE the inbound header bytes the
            # parser must reject. The file-level RUF001 disable
            # at the top of this module accepts the resulting
            # ambiguous-character lints (the only place
            # ambiguous-digit glyphs land in the repo).
            # Mathematical digits use ``\U0001d7d9`` /
            # ``\U0001d7d8`` escapes because the codepoints fall
            # outside the BMP and the literal glyphs render
            # inconsistently across editor / terminal stacks; the
            # other digit families render reliably so they appear
            # as literal glyphs for readability of the description
            # column.
            ("١.٠", "Arabic-Indic 1.0 (U+0660 / U+0661)"),
            ("١٢.٠", "Arabic-Indic 12.0"),
            ("１.０", "Fullwidth 1.0 (U+FF10 / U+FF11)"),
            ("\U0001d7d9.\U0001d7d8", "Mathematical 1.0 (U+1D7D8 / U+1D7D9)"),
            ("१.०", "Devanagari 1.0 (U+0966 / U+0967)"),
            ("۱.۰", "Extended Arabic-Indic 1.0"),
            # Mixed ASCII + non-ASCII forms — also rejected.
            ("1.٠", "ASCII major + Arabic-Indic minor"),
            ("١.0", "Arabic-Indic major + ASCII minor"),
        ],
    )
    def test_non_ascii_digit_rejected_as_malformed(self, header: str, description: str) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "malformed_rejected", (
            f"non-ASCII digit shape ({description}) escaped "
            f"closed-enum and parsed as a valid version"
        )
        assert decision.parsed_major is None
        assert decision.parsed_minor is None


class TestLeadingZerosRejected:
    """**T8 R2 P2 #2 contract tests:** the canonical wire form is
    ``A2A-Version: 1.0`` exactly. Lexical aliases (``01.0``,
    ``1.00``, ``001.000``) parse to the same integer pair via
    ``int()`` but a downstream proxy / middleware that compares
    the raw header string against ``"1.0"`` would behave
    differently from the int-parsed gate. Reject lexical aliases
    at parse time — each segment must be ``(0|[1-9][0-9]{0,9})``
    (a bare ``0`` OR a string with no leading zero).
    """

    @pytest.mark.parametrize(
        "header,description",
        [
            ("01.0", "leading zero on major"),
            ("1.00", "trailing zero on minor"),
            ("001.000", "leading zeros on both segments"),
            ("01.01", "leading zero on both segments"),
            ("1.01", "leading zero on minor"),
            ("00.0", "two zeros on major"),
            ("1.0001", "multiple leading zeros on minor"),
        ],
    )
    def test_leading_zero_alias_rejected_as_malformed(self, header: str, description: str) -> None:
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == "malformed_rejected", (
            f"leading-zero alias ({description}) accepted as canonical "
            f"version — wire-protocol contract weakened"
        )
        assert decision.parsed_major is None
        assert decision.parsed_minor is None

    @pytest.mark.parametrize(
        "header,expected_major,expected_minor,expected_outcome",
        [
            # Canonical bare-zero forms are still accepted (the
            # regex's ``(0|[1-9][0-9]{0,9})`` branch admits a
            # bare ``0``).
            ("0.0", 0, 0, "legacy_rejected"),
            ("0.1", 0, 1, "legacy_rejected"),
            ("1.0", 1, 0, "accepted"),
            ("10.0", 10, 0, "unsupported_rejected"),
            ("1.10", 1, 10, "higher_minor_degraded"),
        ],
    )
    def test_canonical_decimal_forms_accepted(
        self,
        header: str,
        expected_major: int,
        expected_minor: int,
        expected_outcome: A2AVersionOutcome,
    ) -> None:
        """Negative control: canonical decimal forms (no leading
        zeros, but bare ``0`` allowed) parse correctly into the
        existing 6-case matrix."""
        decision = negotiate_inbound_version(a2a_version_header=header)
        assert decision.outcome == expected_outcome
        assert decision.parsed_major == expected_major
        assert decision.parsed_minor == expected_minor


# =============================================================================
# Configurable pin — pinned_major/pinned_minor parameters honour
# Settings.a2a_pinned_spec_version overrides
# =============================================================================


class TestConfigurablePin:
    """The ``pinned_major`` / ``pinned_minor`` parameters let
    operators (via Settings.a2a_pinned_spec_version) bump the pin
    without source edits. Default is (1, 0) per A2A 1.0; bumping to
    1.1 once the spec releases would change the matrix shape (1.1
    becomes accepted; 1.0 becomes lower-minor unsupported)."""

    def test_pin_to_1_2_accepts_1_2_exact(self) -> None:
        decision = negotiate_inbound_version(
            a2a_version_header="1.2",
            pinned_major=1,
            pinned_minor=2,
        )
        assert decision.outcome == "accepted"

    def test_pin_to_1_2_treats_1_3_as_higher_minor(self) -> None:
        decision = negotiate_inbound_version(
            a2a_version_header="1.3",
            pinned_major=1,
            pinned_minor=2,
        )
        assert decision.outcome == "higher_minor_degraded"

    def test_response_header_reflects_pin(self) -> None:
        decision = negotiate_inbound_version(
            a2a_version_header="2.0",
            pinned_major=1,
            pinned_minor=2,
        )
        assert decision.response_header_value == "1.2"


# =============================================================================
# Outbound header
# =============================================================================


class TestOutboundVersionHeader:
    def test_outbound_returns_pinned_version(self) -> None:
        """Every outbound A2A call carries ``A2A-Version: 1.0``.
        Bumping the pinned version is a deliberate reviewed change
        per Sprint-6 Decision Lock #1."""
        assert outbound_version_header() == "1.0"
        assert outbound_version_header() == PINNED_VERSION


# =============================================================================
# Closed-enum drift detector — pin the 6-value outcome literal so a
# future edit that adds/drops a value must update both the source
# module + this test surface.
# =============================================================================


class TestClosedEnumOutcomesExhaustive:
    def test_outcome_set_matches_protocol_literal(self) -> None:
        expected = {
            "accepted",
            "absent_rejected",
            "legacy_rejected",
            "higher_minor_degraded",
            "unsupported_rejected",
            "malformed_rejected",
        }
        actual = set(get_args(A2AVersionOutcome))
        assert actual == expected, (
            f"A2AVersionOutcome literal drift: extra={actual - expected}, "
            f"missing={expected - actual}"
        )

    def test_outcome_count_is_six(self) -> None:
        """Pin the count explicitly per Sprint-6 plan-of-record's
        T1 R1 P3 reviewer correction (the literal was originally
        drafted as 5 values; T1 R1 P3 corrected it to 6, the count
        ADR-003 + A2A-CONFORMANCE.md actually require)."""
        assert len(get_args(A2AVersionOutcome)) == 6


# =============================================================================
# Decision dataclass — frozen+slotted shape
# =============================================================================


class TestDecisionDataclass:
    def test_decision_is_frozen(self) -> None:
        """Frozen dataclass: callers cannot mutate the decision
        after the parser returns it. Defensive against a downstream
        caller (e.g. middleware) altering ``outcome`` between the
        parser and the response emission."""
        decision = negotiate_inbound_version(a2a_version_header="1.0")
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.outcome = "malformed_rejected"  # type: ignore[misc]

    def test_decision_repr_includes_outcome(self) -> None:
        """Operator-readable repr — outcome + parsed values land in
        debug log surfaces unchanged."""
        decision = negotiate_inbound_version(a2a_version_header="2.0")
        rendered = repr(decision)
        assert "unsupported_rejected" in rendered
        assert "parsed_major=2" in rendered
