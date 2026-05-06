"""protocol/a2a_version.py — A2A-Version HTTP header negotiation.

Critical-controls module per AGENTS.md (Sprint-6 amendment +
§"Wire-protocol contracts" stop rule). Per Sprint-6 plan-of-record
§Doctrine Decision F + R0 P2 #4 reviewer correction:
``a2a_version.py`` is on the critical-controls floor because the
6-case header-negotiation matrix is the wire-protocol gate every
inbound A2A call passes through.

Per ADR-003 §"Version negotiation" + ``docs/A2A-CONFORMANCE.md``
§"Versioning". This module is **pure-functional**:

- No I/O, no SDK, no Settings-construction-time work.
- Imports cleanly without ``a2a-sdk`` (admission-side per Sprint-5
  R3 P1 doctrine — ``A2AEndpoint`` (T9) is the SDK-consuming
  caller; this module is what the endpoint asks before deciding
  whether to refuse the request).
- The 6 closed-enum :class:`A2AVersionOutcome` values are the
  exhaustive matrix:

  1. ``A2A-Version: 1.0`` (matches pinned) → ``accepted``.
  2. Header absent → ``absent_rejected`` (per spec, absent ⇒
     ``0.3`` interpretation; AgentOS doesn't speak 0.3 + Decision
     Lock #1 forbids silent upgrade).
  3. ``A2A-Version: 0.x`` → ``legacy_rejected``.
  4. ``A2A-Version: 1.<higher minor>`` → ``higher_minor_degraded``
     (caller surfaces a feature-degradation warning).
  5. ``A2A-Version: 2.x`` (or any other unknown major / lower
     minor than pinned) → ``unsupported_rejected``.
  6. Header malformed → ``malformed_rejected`` (spec-defined
     parse error).

Every refusal carries a ``Supported-A2A-Versions: <pin>`` response
header so callers know what to retry with. The caller
(``A2AEndpoint``, T9) maps the closed-enum outcome onto the
spec-conformant HTTP error code (typically a JSON-RPC
``invalid_request`` envelope with ``data.policy_reason``
identifying the version-negotiation failure).
"""

from __future__ import annotations

import dataclasses
import re
from typing import Final

from cognic_agentos.protocol import A2AVersionOutcome

#: Pinned A2A spec version. Kept here as a Final string so callers
#: that don't want to pull Settings (e.g. test fixtures, the
#: outbound-header helper below) can import it directly. Production
#: A2AEndpoint passes ``Settings.a2a_pinned_spec_version`` parsed
#: into (pinned_major, pinned_minor) at the negotiate boundary.
PINNED_VERSION: Final[str] = "1.0"

#: Header pattern: HTTP OWS-only whitespace (SP / HTAB) +
#: bounded-length canonical-decimal segments separated by a dot
#: + HTTP OWS-only whitespace. Four reviewer corrections folded
#: in:
#:
#: - **OWS-only whitespace** (T8 R1 P2 #1). The earlier ``\s*``
#:   pattern matched all Unicode whitespace (CR / LF / form-feed /
#:   non-breaking-space / Unicode line-separator etc.). For an
#:   HTTP wire-protocol gate, optional padding MUST be the HTTP
#:   OWS production from RFC 7230 §3.2.3 — exactly SP (``0x20``)
#:   or HTAB (``0x09``). Tightening to ``[ \t]*`` rejects
#:   ``\n1.0`` / ``1.0\r`` / similar header-injection shapes
#:   that bypass downstream sanitisation.
#:
#: - **Bounded segment length** (T8 R1 P2 #2). The earlier
#:   ``\d+`` accepted segment strings of arbitrary length.
#:   Python 3.11+ bounds string-to-int conversion at 4300 digits
#:   by default (PEP 657 / DoS mitigation), so
#:   ``int("1.<5000 digits>")`` would raise raw ``ValueError``
#:   from ``int()`` — an attacker-controlled inbound header
#:   escaping the closed-enum / audit path. The 10-digit cap
#:   covers every reasonable semver-style major/minor (10**10 - 1
#:   = ~10 billion is well beyond any practical version-number
#:   scale).
#:
#: - **ASCII-only digits** (T8 R2 P2 #1). Python's ``\d`` is
#:   Unicode-aware: it matches Arabic-Indic digits (U+0660-9),
#:   fullwidth digits (U+FF10-9), mathematical digits
#:   (U+1D7D8-D7E1), Devanagari digits (U+0966-F), etc. — and
#:   ``int()`` accepts those digit classes. For an HTTP wire-
#:   protocol version gate, accepted version syntax MUST be
#:   ASCII-only. Using ``[0-9]`` (NOT ``\d``) makes the digit
#:   class explicit; non-ASCII digit shapes fall through to
#:   ``malformed_rejected`` rather than parsing as accepted.
#:
#: - **Canonical decimal form, no leading zeros** (T8 R2 P2 #2).
#:   The earlier ``\d{1,10}`` accepted ``01.0``, ``1.00``,
#:   ``001.000`` — all aliases of the canonical pinned ``1.0``.
#:   For a wire-protocol gate, lexical aliases weaken the
#:   contract (a future proxy or middleware that compares the
#:   raw header string against ``"1.0"`` would behave
#:   differently from the int-parsed gate). Tightening each
#:   segment to ``(0|[1-9][0-9]{0,9})`` accepts only canonical
#:   decimal: a bare ``0`` OR a string with no leading zero, up
#:   to 10 digits.
_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[ \t]*(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})[ \t]*$"
)


@dataclasses.dataclass(frozen=True, slots=True)
class A2AVersionDecision:
    """Outcome of parsing an inbound ``A2A-Version`` header.

    Frozen + slotted so the decision cannot be mutated between the
    parser and the HTTP-response emission (defensive against a
    downstream middleware altering ``outcome`` after the gate).

    Fields:

    - ``outcome`` — closed-enum :data:`A2AVersionOutcome` value.
    - ``parsed_major`` / ``parsed_minor`` — integer pair from a
      successful regex match; both ``None`` on absent / malformed.
    - ``response_header_value`` — the ``Supported-A2A-Versions``
      response header value the caller must emit on refusal
      (always the pinned version; empty on accept paths but the
      caller typically still emits it for cache hygiene).
    """

    outcome: A2AVersionOutcome
    parsed_major: int | None
    parsed_minor: int | None
    response_header_value: str


def negotiate_inbound_version(
    *,
    a2a_version_header: str | None,
    pinned_major: int = 1,
    pinned_minor: int = 0,
) -> A2AVersionDecision:
    """Parse + classify an inbound ``A2A-Version`` header value.

    Returns an :class:`A2AVersionDecision` that the caller
    (``A2AEndpoint``, T9) consumes to either:

    - Proceed with handling the request (``accepted`` /
      ``higher_minor_degraded``); the latter logs a feature-
      degradation warning if the request used a feature only
      defined in the higher minor.
    - Refuse with a 400-class HTTP response carrying the spec-
      defined error code + a ``Supported-A2A-Versions:
      <decision.response_header_value>`` response header.

    The 6 closed-enum outcomes are spec-mandated (see module
    docstring). Pure-functional — no I/O, no audit emission, no
    Settings construction. The caller emits audit + decision-
    history rows after this function returns.
    """
    response_header = f"{pinned_major}.{pinned_minor}"

    # Case 2: header absent. Per A2A 1.0 spec the absent-header
    # case is interpreted as version 0.3; AgentOS doesn't bundle
    # a 0.3 implementation, so refuse rather than silently upgrade.
    if a2a_version_header is None:
        return A2AVersionDecision(
            outcome="absent_rejected",
            parsed_major=None,
            parsed_minor=None,
            response_header_value=response_header,
        )

    # Case 6: regex fail-through covers every malformed shape —
    # empty string, single segment ("1"), three+ segments
    # ("1.0.0"), build-metadata suffixes ("1.0-rc"), non-numeric
    # ("v1.0", "abc"), comma-separated, newline injection, etc.
    match = _VERSION_PATTERN.fullmatch(a2a_version_header)
    if match is None:
        return A2AVersionDecision(
            outcome="malformed_rejected",
            parsed_major=None,
            parsed_minor=None,
            response_header_value=response_header,
        )

    # Defensive: the regex caps each segment at 10 digits so the
    # int() conversion stays well under Python's 4300-digit
    # str-to-int limit (PEP 657). If a future regex edit relaxes
    # the bound without re-checking int-conversion safety, this
    # ValueError catch routes the failure to malformed_rejected
    # rather than letting raw ValueError escape the closed-enum
    # path. T8 R1 P2 #2 reviewer correction safety-net.
    try:
        major = int(match.group(1))
        minor = int(match.group(2))
    except ValueError:  # pragma: no cover  (regex bound makes this unreachable)
        return A2AVersionDecision(
            outcome="malformed_rejected",
            parsed_major=None,
            parsed_minor=None,
            response_header_value=response_header,
        )

    # Case 3: legacy 0.x — refused per A2A-CONFORMANCE.md table.
    if major == 0:
        return A2AVersionDecision(
            outcome="legacy_rejected",
            parsed_major=major,
            parsed_minor=minor,
            response_header_value=response_header,
        )

    # Case 1: exact match of the pinned major + minor.
    if major == pinned_major and minor == pinned_minor:
        return A2AVersionDecision(
            outcome="accepted",
            parsed_major=major,
            parsed_minor=minor,
            response_header_value=response_header,
        )

    # Case 4: same-major + higher-minor → accepted with feature-
    # degradation warning (caller emits the warning on the
    # response side).
    if major == pinned_major and minor > pinned_minor:
        return A2AVersionDecision(
            outcome="higher_minor_degraded",
            parsed_major=major,
            parsed_minor=minor,
            response_header_value=response_header,
        )

    # Case 5: any other version — future major (2.x+), past major
    # (when we eventually pin to 2.x and a 1.x request arrives),
    # or same-major-but-lower-minor than pinned. All map to
    # ``unsupported_rejected``.
    return A2AVersionDecision(
        outcome="unsupported_rejected",
        parsed_major=major,
        parsed_minor=minor,
        response_header_value=response_header,
    )


def outbound_version_header() -> str:
    """The ``A2A-Version`` value AgentOS includes on every outbound
    A2A call.

    Always the pinned version; bumping is a deliberate reviewed
    change tied to the schema-drift CI gate (T6) per Sprint-6
    Decision Lock #1 — silent upstream upgrades are forbidden.
    """
    return PINNED_VERSION


__all__ = (
    "PINNED_VERSION",
    "A2AVersionDecision",
    "negotiate_inbound_version",
    "outbound_version_header",
)
