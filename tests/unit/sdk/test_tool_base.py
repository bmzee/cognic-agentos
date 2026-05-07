# mypy: disable-error-code="misc,override,unused-ignore,arg-type,assignment,truthy-bool"
# ruff: noqa: RUF012
# ^ test fixture subclasses declare `input_schema = {...}` / `output_schema = {...}`
#   directly to mirror the public Tool-author pattern. The base class types these
#   as ClassVar[dict[str, Any]]; the test classes are throwaway, so the RUF012
#   "Consider annotating with typing.ClassVar" hint just adds noise here.
"""Sprint-7A T2 — `agentos_sdk.Tool` base-class contract tests.

The Tool base class is the **public API** every MCP tool pack subclasses.
Per Doctrine Decision E, every commit touching this surface halts before
commit (semver-stability concern, NOT critical-controls security gate).

Test arms (per the plan T2 Step 1):

  (a) Abstract method enforcement on `_invoke`.
  (b) ClassVar declaration (name + input_schema + output_schema).
  (c) Public `invoke()` validates kwargs against `input_schema`
      BEFORE delegating to `_invoke`.
  (d) Public `invoke()` validates the returned dict against
      `output_schema` AFTER `_invoke` returns.
  (e) Schema-validation-failure exception types are deterministic
      (`ToolInputSchemaError` + `ToolOutputSchemaError`, both subclasses
      of `ToolError`).
  (f) **Runtime override-rejection** (R3 P2 #1) — defining a subclass
      with its own `invoke` method raises `TypeError` at class-creation
      time via `__init_subclass__`.
  (g) **Mixin-bypass rejection** (R8 P2 #1) — defining a class hierarchy
      `class Bypass: async def invoke(...): ...; class Sub(Bypass, Tool):
      pass` raises at `Sub`'s class-creation time. The MRO walk catches
      mixin smuggling that the simpler `cls.__dict__` check missed.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# (a) Abstract method enforcement on `_invoke`
# ---------------------------------------------------------------------------


def test_tool_invoke_is_abstract() -> None:
    """Instantiating a subclass that doesn't override `_invoke`
    raises TypeError per the abc.ABC contract."""
    from cognic_agentos.sdk.tool import Tool

    class IncompleteTool(Tool):
        name = "incomplete"
        input_schema: dict = {}  # type: ignore[type-arg]
        output_schema: dict = {}  # type: ignore[type-arg]

    with pytest.raises(TypeError, match="abstract"):
        IncompleteTool()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# (b) ClassVar declarations
# ---------------------------------------------------------------------------


def test_tool_classvar_name_is_required() -> None:
    """The Tool base declares `name` as a ClassVar[str]; subclasses
    must set it for the SDK + runtime MCP host to identify the tool."""
    from cognic_agentos.sdk.tool import Tool

    # Tool's __annotations__ should declare `name` as a ClassVar-typed field.
    assert "name" in Tool.__annotations__


def test_tool_classvar_input_schema_is_required() -> None:
    from cognic_agentos.sdk.tool import Tool

    assert "input_schema" in Tool.__annotations__


def test_tool_classvar_output_schema_is_required() -> None:
    from cognic_agentos.sdk.tool import Tool

    assert "output_schema" in Tool.__annotations__


# ---------------------------------------------------------------------------
# (c) Public invoke() validates kwargs against input_schema BEFORE _invoke
# ---------------------------------------------------------------------------


async def test_invoke_validates_input_schema_before_delegating() -> None:
    """Bad kwargs (missing required field per JSON-Schema) raise
    `ToolInputSchemaError` BEFORE `_invoke` is called. Pinned by a
    flag the subclass sets in its `_invoke` — the flag MUST stay
    False on input-validation failure."""
    from cognic_agentos.sdk.tool import Tool, ToolInputSchemaError

    class GoodTool(Tool):
        name = "echo"
        input_schema = {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        }
        output_schema = {
            "type": "object",
            "properties": {"echo": {"type": "string"}},
            "required": ["echo"],
        }
        invoked: bool = False

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            type(self).invoked = True
            return {"echo": str(kwargs.get("text"))}

    t = GoodTool()
    # Missing required field "text" → ToolInputSchemaError before _invoke.
    with pytest.raises(ToolInputSchemaError):
        await t.invoke()
    assert GoodTool.invoked is False, "_invoke ran despite input-validation failure"


async def test_invoke_passes_kwargs_to_underscore_invoke_on_success() -> None:
    """Happy path: `invoke(text='hi')` succeeds, `_invoke` receives
    `text='hi'`, output validates."""
    from cognic_agentos.sdk.tool import Tool

    class EchoTool(Tool):
        name = "echo"
        input_schema = {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        }
        output_schema = {
            "type": "object",
            "properties": {"echo": {"type": "string"}},
            "required": ["echo"],
        }

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {"echo": str(kwargs["text"])}

    t = EchoTool()
    result = await t.invoke(text="hi")
    assert result == {"echo": "hi"}


# ---------------------------------------------------------------------------
# (d) Public invoke() validates output_schema AFTER _invoke
# ---------------------------------------------------------------------------


async def test_invoke_validates_output_schema_after_underscore_invoke() -> None:
    """Subclass returns a dict that doesn't match `output_schema` →
    `ToolOutputSchemaError` AFTER `_invoke` ran."""
    from cognic_agentos.sdk.tool import Tool, ToolOutputSchemaError

    class WrongOutputTool(Tool):
        name = "wrong"
        input_schema = {"type": "object"}
        output_schema = {
            "type": "object",
            "properties": {"echo": {"type": "string"}},
            "required": ["echo"],
        }

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {"unexpected_field": "value"}  # missing required `echo`

    t = WrongOutputTool()
    with pytest.raises(ToolOutputSchemaError):
        await t.invoke()


# ---------------------------------------------------------------------------
# (e) Deterministic exception types
# ---------------------------------------------------------------------------


def test_tool_input_schema_error_subclasses_tool_error() -> None:
    """The runtime MCP host catches `ToolError`; both schema-error
    subclasses MUST be reachable via that single catch."""
    from cognic_agentos.sdk.tool import ToolError, ToolInputSchemaError

    assert issubclass(ToolInputSchemaError, ToolError)


def test_tool_output_schema_error_subclasses_tool_error() -> None:
    from cognic_agentos.sdk.tool import ToolError, ToolOutputSchemaError

    assert issubclass(ToolOutputSchemaError, ToolError)


def test_tool_schema_declaration_error_subclasses_tool_error() -> None:
    """R12 P2 #1 follow-up — ``jsonschema.SchemaError`` (raised when
    the pack's declared schema is itself invalid, not when a value
    fails validation) MUST be wrapped into a ``ToolError`` subclass
    so the runtime MCP host's single ``except ToolError`` catch
    refuses a malformed pack deterministically instead of leaking
    a raw ``jsonschema`` exception."""
    from cognic_agentos.sdk.tool import ToolError, ToolSchemaDeclarationError

    assert issubclass(ToolSchemaDeclarationError, ToolError)


async def test_invoke_with_malformed_input_schema_raises_declaration_error() -> None:
    """A pack that declares an invalid ``input_schema`` (here:
    ``{"type": "not_a_real_type"}`` — JSON-Schema rejects unknown
    type keywords) raises ``ToolSchemaDeclarationError`` at
    ``invoke()`` time, BEFORE ``_invoke`` runs. The runtime MCP
    host's single ``except ToolError`` catches it; the raw
    ``jsonschema.SchemaError`` never escapes the SDK boundary."""
    from cognic_agentos.sdk.tool import Tool, ToolSchemaDeclarationError

    class MalformedInputTool(Tool):
        name = "malformed_input"
        # "not_a_real_type" is not a valid JSON-Schema "type" value;
        # jsonschema's metaschema rejects this BEFORE any value can
        # be validated against it.
        input_schema = {"type": "not_a_real_type"}
        output_schema = {"type": "object"}
        invoked: bool = False

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            type(self).invoked = True
            return {}

    t = MalformedInputTool()
    with pytest.raises(ToolSchemaDeclarationError, match="input_schema"):
        await t.invoke()
    assert MalformedInputTool.invoked is False, (
        "_invoke ran despite malformed-schema declaration failure"
    )


async def test_invoke_with_malformed_output_schema_raises_declaration_error() -> None:
    """The corollary on the output side: ``output_schema`` is
    invalid JSON-Schema, ``_invoke`` runs and returns a dict, but
    the SDK's post-invoke validation rejects the malformed schema
    itself with ``ToolSchemaDeclarationError`` rather than leaking
    ``jsonschema.SchemaError``."""
    from cognic_agentos.sdk.tool import Tool, ToolSchemaDeclarationError

    class MalformedOutputTool(Tool):
        name = "malformed_output"
        input_schema = {"type": "object"}
        # Same malformed-metaschema pattern on the output side.
        output_schema = {"type": "not_a_real_type"}

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {"echo": "ok"}

    t = MalformedOutputTool()
    with pytest.raises(ToolSchemaDeclarationError, match="output_schema"):
        await t.invoke()


# ---------------------------------------------------------------------------
# (f) Runtime override-rejection on invoke (R3 P2 #1)
# ---------------------------------------------------------------------------


def test_subclass_overriding_invoke_raises_at_class_creation() -> None:
    """R3 P2 #1: defining a subclass that overrides `invoke` directly
    raises `TypeError` at class-creation time via `__init_subclass__`.
    `@typing.final` is mypy-only; the runtime guard closes the actual
    bypass surface."""
    from cognic_agentos.sdk.tool import Tool

    with pytest.raises(TypeError, match="invoke"):

        class BadTool(Tool):
            name = "bad"
            input_schema: dict = {}  # type: ignore[type-arg]
            output_schema: dict = {}  # type: ignore[type-arg]

            async def invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
                return {}

            async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
                return {}


def test_subclass_overriding_only_underscore_invoke_succeeds() -> None:
    """The corollary: subclasses that override `_invoke` but NOT
    `invoke` succeed cleanly. This is the intended Tool-author
    pattern."""
    from cognic_agentos.sdk.tool import Tool

    class GoodTool(Tool):
        name = "good"
        input_schema: dict = {}  # type: ignore[type-arg]
        output_schema: dict = {}  # type: ignore[type-arg]

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {}

    GoodTool()  # No exception.


# ---------------------------------------------------------------------------
# (g) Mixin-bypass rejection (R8 P2 #1)
# ---------------------------------------------------------------------------


def test_mixin_smuggled_invoke_raises_at_class_creation() -> None:
    """R8 P2 #1: `class Bypass: async def invoke(...): ...; class Sub(Bypass, Tool): pass`
    must raise at `Sub`'s class-creation time. The MRO walk catches
    the mixin's `invoke` even though `Sub.__dict__` is empty."""
    from cognic_agentos.sdk.tool import Tool

    class Bypass:
        async def invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg]
            return {"smuggled": "yes"}

    with pytest.raises(TypeError, match="Bypass"):

        class Sub(Bypass, Tool):
            name = "sub"
            input_schema: dict = {}  # type: ignore[type-arg]
            output_schema: dict = {}  # type: ignore[type-arg]

            async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
                return {}


def test_mixin_bypass_via_multi_level_inheritance_raises() -> None:
    """R8 P2 #1 multi-level: `class Mid(Tool): _invoke; class Bypass:
    invoke; class Sub(Bypass, Mid): pass` ALSO raises (the MRO walk
    inspects every ancestor, not just `cls.__bases__`)."""
    from cognic_agentos.sdk.tool import Tool

    class Mid(Tool):
        name = "mid"
        input_schema: dict = {}  # type: ignore[type-arg]
        output_schema: dict = {}  # type: ignore[type-arg]

        async def _invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {}

    class Bypass:
        async def invoke(self, **kwargs: object) -> dict:  # type: ignore[type-arg]
            return {"smuggled": "yes"}

    with pytest.raises(TypeError, match="Bypass"):

        class Sub(Bypass, Mid):
            pass
