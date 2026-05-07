"""{{ class_name }} — AUTHOR-FILL: short description of what this tool does.

The pack-author contract:

  - Override ``_invoke`` (NOT ``invoke``). The SDK's ``Tool.invoke`` is
    ``@final`` + the SDK's ``Tool.__init_subclass__`` rejects subclasses
    that override it directly (R3 P2 #1 + R8 P2 #1 doctrine).
  - Declare ``input_schema`` + ``output_schema`` as ClassVars. The SDK
    validates kwargs against ``input_schema`` BEFORE delegating to
    ``_invoke`` and validates the returned dict against
    ``output_schema`` AFTER.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.sdk.tool import Tool


class {{ class_name }}(Tool):
    """AUTHOR-FILL: docstring describing what this tool does."""

    name: ClassVar[str] = "{{ pack_name }}"

    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            # AUTHOR-FILL: declare your input fields here.
        },
        "required": [],
        "additionalProperties": False,
    }

    output_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            # AUTHOR-FILL: declare your output fields here.
        },
        "required": [],
        "additionalProperties": False,
    }

    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:
        """AUTHOR-FILL: implement the tool body.

        The SDK has already validated ``kwargs`` against
        ``input_schema`` by the time this is called; the SDK will
        validate the return value against ``output_schema`` after.
        """
        raise NotImplementedError(
            "AUTHOR-FILL: implement {{ class_name }}._invoke"
        )
