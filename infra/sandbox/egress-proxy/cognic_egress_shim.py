"""Canonical egress-proxy PID1 shim — tinyproxy Filter renderer + host validator.

This module is IMAGE CONTENT: it runs INSIDE the cognic egress-proxy Docker
container as part of the entrypoint, not inside the AgentOS Python package. It
therefore uses ONLY the Python standard library and MUST NOT import from
``cognic_agentos`` (the package is not present in the proxy image).

tinyproxy runs with ``FilterDefaultDeny Yes`` (whitelist mode). The Filter file
is a list of regexes, one per line, each an anchored exact-match for an allowed
hostname. An EMPTY filter file therefore means DENY ALL egress — which is the
fail-closed posture this renderer falls back to on any malformed input.

Security note: ``re.escape`` alone is NOT sufficient to keep the
one-pattern-per-line invariant. ``re.escape("a\\nb")`` preserves the literal
newline, which would split one host into two filter lines and could widen
access. The real control is :func:`_is_valid_host`, which rejects any host
containing control characters or whitespace (among other RFC-1123 violations);
``re.escape`` is defense-in-depth on regex metacharacters only.
"""

from __future__ import annotations

import json
import re

# RFC-1123 label: 1-63 chars, alphanumeric start/end, hyphens allowed in the
# middle only. No underscore, no leading/trailing hyphen, no empty label.
# End-anchor is ``\Z`` (absolute end), NOT ``$``: in Python ``$`` also matches
# just before a trailing newline, so ``$`` would let a host ending in ``\n``
# validate and inject a literal newline into the one-pattern-per-line Filter
# file. ``\Z`` closes that hole — do NOT "simplify" back to ``$``.
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\Z")

# RFC-1123 total hostname length cap.
_MAX_HOST_LEN = 253

# RFC-1123 label length cap.
_MAX_LABEL_LEN = 63


def _is_valid_host(h: str) -> bool:
    """Return True iff ``h`` is a syntactically valid RFC-1123 hostname.

    Rejects (returns False for): empty string; total length > 253; any empty
    label (e.g. ``a..b``); any label > 63 chars; any label with a
    leading/trailing hyphen; underscores; schemes (``://``); paths (``/``);
    wildcards (``*``); whitespace; and control characters — because none of
    those match the per-label regex. The whitespace/control-char reject is the
    load-bearing control that stops a newline-embedded host from breaking the
    one-pattern-per-line Filter invariant.
    """
    if not h or len(h) > _MAX_HOST_LEN:
        return False
    labels = h.split(".")
    for label in labels:
        if len(label) > _MAX_LABEL_LEN:
            return False
        if _LABEL_RE.match(label) is None:
            return False
    return True


def render_filter_file(allow_list_json: str) -> str:
    """Render a tinyproxy Filter file from a JSON array of allowed hostnames.

    Fail-closed contract: returns ``""`` (an empty filter ⇒ deny-all under
    ``FilterDefaultDeny Yes``) on ANY malformed input — invalid JSON, a
    non-list top level, a non-string element, or a single host that fails
    :func:`_is_valid_host`. One bad entry poisons the whole list: a tampered
    ``ALLOW_LIST`` must never widen access by silently dropping the bad entry
    and keeping the good ones.

    On valid input, renders one anchored exact-match regex per host
    (``^`` + ``re.escape(host)`` + ``$``), de-duplicated preserving first-seen
    order, joined by newlines.
    """
    try:
        parsed = json.loads(allow_list_json)
    except (json.JSONDecodeError, ValueError):
        # Invalid JSON ⇒ deny-all. Never raise into an allow-all posture.
        return ""

    if not isinstance(parsed, list):
        # Non-list top level (object, string, number, …) ⇒ deny-all.
        return ""

    lines: list[str] = []
    seen: set[str] = set()
    for element in parsed:
        if not isinstance(element, str) or not _is_valid_host(element):
            # One bad entry poisons the whole list ⇒ deny-all.
            return ""
        if element in seen:
            continue
        seen.add(element)
        lines.append(f"^{re.escape(element)}$")

    return "\n".join(lines)


class ShimStartupError(Exception):
    """Raised when the shim cannot start safely (e.g. SESSION_ID absent/empty).

    The entrypoint treats this as refuse-startup — the proxy must NOT run and
    emit audit records it cannot correlate to a session.
    """


def resolve_policy_id(env: dict[str, str]) -> str:
    """Resolve the ProxyAccessRecord ``policy_id`` from the launch env.

    ``policy_id = SESSION_ID`` (the per-session id the backend passes). Raises
    :class:`ShimStartupError` if ``SESSION_ID`` is absent or empty — fail-closed:
    never emit audit records with a missing/uncorrelatable policy_id.
    """
    session_id = env.get("SESSION_ID")
    if not session_id:  # None or "" -> refuse startup
        raise ShimStartupError(
            "SESSION_ID env var is required (policy_id = SESSION_ID); refusing "
            "to start rather than emit audit records with no session correlation."
        )
    return session_id
