"""Sprint-7A T2 — `agentos_sdk.Tool` base class for MCP tool implementations.

Subclass + register under the ``cognic.tools`` entry-point group in
``pyproject.toml``. The SDK's testing fixtures + the runtime MCP host both
consume this contract. Per Doctrine Decision E: every commit touching this
surface halts before commit (semver-stability concern, NOT critical-controls
security gate).

Template-method pattern (R2 P2 #4 + R3 P2 #1 + R8 P2 #1):

  - Public ``invoke()`` is ``@typing.final`` + enforced at runtime via
    ``__init_subclass__`` (R3 P2 #1) + the MRO walk catches mixin smuggling
    (R8 P2 #1). Subclasses MUST override ``_invoke`` instead of ``invoke``.
  - ``invoke()`` validates kwargs against ``input_schema`` BEFORE delegating
    to ``_invoke``; validates the returned dict against ``output_schema``
    AFTER. Value-validation failures raise ``ToolInputSchemaError`` /
    ``ToolOutputSchemaError``. If the pack's declared schema is itself
    invalid JSON-Schema (e.g. unknown ``type`` keyword), the wrapper
    raises ``ToolSchemaDeclarationError`` instead — all three are
    subclasses of ``ToolError``, so the runtime MCP host's single
    ``except ToolError`` catch refuses the call deterministically and
    raw ``jsonschema`` exceptions never escape the SDK boundary.

The base class deliberately does NOT emit audit events (R4 P2 #2) — audit
emission belongs to the runtime MCP host (Sprint 5
``mcp_host._emit_call_evidence``) which has the AuditStore +
DecisionHistoryStore + tenant context the bare Tool instance does not.
"""

from __future__ import annotations

import abc
import typing
from typing import Any, ClassVar, final

import jsonschema


class ToolError(Exception):
    """Base class for all SDK Tool errors. The runtime MCP host
    catches this single class to refuse a tool invocation; both
    schema-validation subclasses below are reachable via that catch."""


class ToolInputSchemaError(ToolError):
    """Kwargs passed to ``invoke()`` failed JSON-Schema validation
    against ``input_schema`` BEFORE ``_invoke`` was called."""


class ToolOutputSchemaError(ToolError):
    """The dict returned from ``_invoke`` failed JSON-Schema
    validation against ``output_schema`` AFTER ``_invoke`` returned."""


class ToolSchemaDeclarationError(ToolError):
    """The pack's declared ``input_schema`` or ``output_schema`` is
    not itself a valid JSON-Schema document (draft 2020-12).

    Raised at ``invoke()`` time when ``jsonschema`` rejects the
    schema before it can validate any value against it. This is a
    pack-author bug, not a runtime data error — but the runtime MCP
    host's ``ToolError`` catch still reaches it so a malformed pack
    is refused deterministically instead of leaking a raw
    ``jsonschema.SchemaError`` past the SDK boundary.
    """


def _validate_against_schema(
    value: Any, schema: dict[str, Any], *, kind: typing.Literal["input", "output"]
) -> None:
    """Raise ``ToolInputSchemaError`` / ``ToolOutputSchemaError`` if
    ``value`` does not match ``schema`` per draft 2020-12 JSON-Schema.
    Raise ``ToolSchemaDeclarationError`` if ``schema`` is itself
    invalid — every error path stays inside the ``ToolError``
    hierarchy so the runtime MCP host's single ``except ToolError``
    catches it.
    """
    try:
        jsonschema.validate(instance=value, schema=schema)
    except jsonschema.SchemaError as exc:
        # Pack-declared schema is invalid; nothing was actually
        # validated against. Wrapping into a deterministic SDK
        # exception keeps the runtime catch surface tight.
        raise ToolSchemaDeclarationError(
            f"{kind}_schema is not a valid JSON-Schema document: {exc.message}"
        ) from exc
    except jsonschema.ValidationError as exc:
        if kind == "input":
            raise ToolInputSchemaError(f"input failed schema validation: {exc.message}") from exc
        raise ToolOutputSchemaError(f"output failed schema validation: {exc.message}") from exc


class Tool(abc.ABC):
    """Base class for ``cognic.tools`` entry-point implementations.

    Subclasses declare ``name`` + ``input_schema`` + ``output_schema``
    as ClassVar fields, override ``_invoke`` for the actual work, and
    let the SDK's template-method validation seam handle input/output
    schema checks.

    Schema validation is enforced by the SDK base — pack authors
    CANNOT skip it by forgetting (the seam is enforced via
    ``__init_subclass__`` + ``@typing.final`` together).
    """

    name: ClassVar[str]
    input_schema: ClassVar[dict[str, Any]]
    output_schema: ClassVar[dict[str, Any]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """R3 P2 #1 + R8 P2 #1 — runtime enforcement of the
        validation seam.

        ``typing.final`` is mypy-only; Python runtime allows a
        subclass to override ``invoke`` despite the decorator.
        Without this guard, a pack author who shadows ``invoke``
        bypasses the SDK's input/output schema validation.

        R8 P2 #1: walk ``cls.__mro__`` and refuse any ancestor
        (other than ``Tool`` itself and ``object``) that defines
        ``invoke`` directly. This catches mixin smuggling that the
        simpler ``cls.__dict__`` check missed (e.g.,
        ``class Bypass: async def invoke(...): ...; class Sub(Bypass, Tool): pass``).

        Subclasses MUST override ``_invoke`` instead.
        """
        super().__init_subclass__(**kwargs)
        for ancestor in cls.__mro__:
            if ancestor is Tool or ancestor is object:
                continue
            if "invoke" in ancestor.__dict__:
                raise TypeError(
                    f"{cls.__qualname__} resolves Tool.invoke() to a non-base "
                    f"override defined in {ancestor.__qualname__} (in MRO before "
                    "Tool). The Tool template-method contract pins ``invoke`` as "
                    "final; the only allowed owner is the SDK's Tool base. "
                    "Either remove the override from "
                    f"{ancestor.__qualname__} or refactor it to override "
                    "_invoke instead so the SDK's input/output schema "
                    "validation seam cannot be bypassed via mixin smuggling."
                )

    @final
    async def invoke(self, **kwargs: Any) -> dict[str, Any]:
        """Public entry point. Validates ``kwargs`` against
        ``input_schema`` BEFORE delegating to ``_invoke``; validates
        the returned dict against ``output_schema`` AFTER. Subclasses
        MUST NOT override this method (pinned via ``@typing.final``
        for mypy + ``__init_subclass__`` for runtime).

        Raises ``ToolInputSchemaError`` if kwargs fail input
        validation; ``ToolOutputSchemaError`` if the subclass's
        return value fails output validation.
        """
        _validate_against_schema(dict(kwargs), self.input_schema, kind="input")
        result = await self._invoke(**kwargs)
        _validate_against_schema(result, self.output_schema, kind="output")
        return result

    @abc.abstractmethod
    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:
        """Subclass-specific behaviour. The base class has already
        validated ``kwargs`` against ``input_schema`` by the time
        this is called; the base will validate the return value
        against ``output_schema`` afterwards. Subclasses focus on
        the actual work, not the validation discipline."""
        raise NotImplementedError


__all__ = [
    "Tool",
    "ToolError",
    "ToolInputSchemaError",
    "ToolOutputSchemaError",
    "ToolSchemaDeclarationError",
]
