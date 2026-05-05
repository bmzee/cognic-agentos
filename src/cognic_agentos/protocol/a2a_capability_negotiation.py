"""protocol/a2a_capability_negotiation.py — A2A capability discovery.

Backs ``GET /api/v1/a2a/capabilities``. Reads pack manifests'
declarations under the canonical FLAT ``[tool.cognic.a2a]`` block
(per ``docs/A2A-CONFORMANCE.md`` §"What pack authors must declare"
+ ``docs/BUILD_PLAN.md``) and returns the Wave-1-filtered
:class:`A2ACapabilities` response.

Per ADR-003 + A2A-CONFORMANCE.md + Sprint-6 plan-of-record T11:

  - **Declared-capability reader; never invent capabilities.** The
    returned subset is always ⊆ what the manifest declared.
    Operators looking at ``GET /api/v1/a2a/capabilities`` see only
    what the agent's pack manifest has explicitly opted into.

  - **Empty if absent.** No declaration → empty
    :class:`A2ACapabilities` (all-false flags / empty
    capabilities_supported / empty extensions). The wire response
    is honest about that.

  - **Wave-2 filtered.** ``push_notification_config = true`` in
    the manifest is forced to false per Decision Lock #2; the
    dropped declaration is surfaced via
    :attr:`A2ACapabilities.deferred_wave2_features` so operators
    see what was silently filtered (no silent "we ignored your
    capability declaration").

  - **Strict bool typing (T11 R1 P2 #2).** Boolean fields require
    the actual ``bool`` Python type — non-bool values (strings,
    dicts, lists, ``None``) are treated as ``False`` regardless
    of truthiness. Otherwise a manifest declaring
    ``streaming = "false"`` (string) would promote to ``True`` via
    ``bool("false")``, advertising support the manifest didn't
    validly declare. Fail-closed against TOML schema violations.

Canonical manifest schema (T11 R1 P2 #1 reviewer correction —
**FLAT** under ``[tool.cognic.a2a]``, NOT nested under
``[tool.cognic.a2a.capabilities]``)::

    [tool.cognic.a2a]
    spec_version = "1.0"
    agent_card_url = "..."
    agent_card_jws_path = "..."
    capabilities_supported = ["regulatory_qa", "citation_grounded"]
    streaming = true
    push_notification_config = false   # opt-in for Wave-2 (filtered)
    artifacts_supported = true
    auth_scheme = "bearer"

Field mapping into :class:`A2ACapabilities`:

    Manifest field                  → A2ACapabilities field
    ------------------------------- → ------------------------------
    capabilities_supported          → capabilities_supported (tuple)
    streaming                       → streaming (bool)
    push_notification_config        → push_notifications (filtered)
    artifacts_supported             → artifacts_supported (bool)
    extended_agent_card             → extended_agent_card (bool)
    extensions                      → extensions (tuple)

``capabilities_supported`` is the Cognic semantic capability list
(routing/discovery tags like ``"regulatory_qa"``); the bool flags
mirror the A2A 1.0 ``AgentCapabilities`` proto fields. The
``GET /api/v1/a2a/capabilities`` response carries both axes.

NOT critical-controls — manifest-side declarations are pack-author
authority, the reader just exposes them safely (filtered to Wave-1
+ defensively typed).
"""

from __future__ import annotations

import dataclasses
from typing import Any

#: Wave-2 manifest-field names that are forced to false regardless
#: of declaration. Per Decision Lock #2: ``push_notification_config``
#: is the only AgentCapabilities Wave-2 flag in the canonical Sprint-6
#: manifest schema (multimodal payloads + task resumption are
#: wire-side gates per T9, not capability-flag declarations).
#: Allowing ``push_notification_config = true`` to be advertised
#: would lie to remote callers about what the endpoint will accept.
_WAVE2_MANIFEST_FIELDS: frozenset[str] = frozenset({"push_notification_config"})


def _bool_or_false(value: Any) -> bool:
    """Strict bool typing per T11 R1 P2 #2. Returns ``value`` only
    if it is the actual ``bool`` type; otherwise ``False``.

    ``bool(other_value)`` would silently promote truthy non-bool
    shapes — e.g. ``bool("false")`` is ``True`` because the string
    is non-empty, ``bool([0])`` is ``True``, ``bool({"x": 0})`` is
    ``True``. For a wire-protocol-public capabilities response,
    fail-closed treatment of malformed flags is the only safe
    default — pack authors who want a flag enabled MUST declare an
    actual TOML boolean (``true``/``false``).
    """
    return value if isinstance(value, bool) else False


def _string_tuple(value: Any) -> tuple[str, ...]:
    """List-of-strings reader. Returns the tuple of string entries
    if ``value`` is a list; non-string entries are silently dropped
    (defence against TOML schema violations). Non-list input
    → empty tuple."""
    if not isinstance(value, list):
        return ()
    return tuple(entry for entry in value if isinstance(entry, str))


@dataclasses.dataclass(frozen=True, slots=True)
class A2ACapabilities:
    """Wave-1 capability subset returned by the negotiation
    endpoint.

    Carries both axes the canonical manifest declares:

      - **Cognic semantic capabilities** (``capabilities_supported``)
        — routing/discovery tags pack authors declare for their
        agent's domain (e.g. ``"regulatory_qa"``,
        ``"citation_grounded"``). Free-form strings; the endpoint
        does not validate them against any closed enum.

      - **A2A 1.0 ``AgentCapabilities`` proto flags**:
        ``streaming`` / ``push_notifications`` /
        ``extended_agent_card`` / ``artifacts_supported`` /
        ``extensions``. Boolean flags mirror the protobuf field
        names; ``push_notification_config`` in the manifest maps
        onto ``push_notifications`` (Wave-2, forced False).

      - **AgentOS-side audit surface** (``deferred_wave2_features``)
        — Wave-2 manifest declarations the reader filtered out so
        operators see what was silently dropped. Sorted tuple.

    Frozen + slotted so the wire response can't be mutated between
    the read and the HTTP serialization at egress.
    """

    capabilities_supported: tuple[str, ...] = ()
    streaming: bool = False
    push_notifications: bool = False
    extended_agent_card: bool = False
    artifacts_supported: bool = False
    extensions: tuple[str, ...] = ()
    deferred_wave2_features: tuple[str, ...] = ()


def read_pack_capabilities(manifest: dict[str, Any]) -> A2ACapabilities:
    """Read the FLAT ``[tool.cognic.a2a]`` block from a parsed pack
    manifest dict and return the Wave-1-filtered
    :class:`A2ACapabilities` response.

    Parameters
    ----------
    manifest
        Parsed pyproject.toml-shaped dict. Navigates safely through
        ``tool.cognic.a2a``; returns empty :class:`A2ACapabilities`
        if any layer is missing or the section is malformed
        (fail-closed).

    Returns
    -------
    Wave-1-filtered :class:`A2ACapabilities`. ``deferred_wave2_features``
    lists the Wave-2 manifest field names the pack tried to opt
    in to (manifest declared the actual bool ``True``) but the
    reader filtered out per Decision Lock #2.
    """
    section = manifest.get("tool", {}).get("cognic", {}).get("a2a", {})
    if not isinstance(section, dict):
        return A2ACapabilities()

    # Wave-1 flags: strict bool typing per T11 R1 P2 #2.
    streaming = _bool_or_false(section.get("streaming"))
    extended_agent_card = _bool_or_false(section.get("extended_agent_card"))
    artifacts_supported = _bool_or_false(section.get("artifacts_supported"))

    # Cognic semantic capabilities + URN-shaped extensions list.
    capabilities_supported = _string_tuple(section.get("capabilities_supported"))
    extensions = _string_tuple(section.get("extensions"))

    # Wave-2 fields: forced to false; track manifest declarations
    # that were filtered so operators see what was dropped.
    deferred: list[str] = []
    for field in _WAVE2_MANIFEST_FIELDS:
        if _bool_or_false(section.get(field)):
            deferred.append(field)

    return A2ACapabilities(
        capabilities_supported=capabilities_supported,
        streaming=streaming,
        push_notifications=False,  # always False in Wave-1
        extended_agent_card=extended_agent_card,
        artifacts_supported=artifacts_supported,
        extensions=extensions,
        deferred_wave2_features=tuple(sorted(deferred)),
    )


__all__ = (
    "A2ACapabilities",
    "read_pack_capabilities",
)
