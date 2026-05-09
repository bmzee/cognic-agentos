"""Sprint-7A T15 reference tool — inert echo.

The implementation deliberately mirrors the smallest valid ``Tool``
subclass: a single string-typed input ``message``, a single string-
typed output ``echo``. Pack authors copying this directory get a
working pipeline they can verify end-to-end before substituting real
tool behavior.

Per Doctrine D (plan §59), the pack ships **inert** behavior —
``_invoke`` returns ``{"echo": message}`` verbatim. NOT a model for
production tools.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.sdk.tool import Tool


class ExampleMinimalTool(Tool):
    """Inert echo tool — Wave-1 reference implementation."""

    name: ClassVar[str] = "example_minimal"
    input_schema: ClassVar[dict[str, Any]] = {
        # ``required: []`` so ``agentos test-harness``'s empty-args
        # dispatch dry-run succeeds (mirrors the T13 harness fixture
        # pattern). Pack authors substituting real tool behavior
        # tighten ``required`` as appropriate.
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": [],
        "additionalProperties": False,
    }
    output_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {"echo": {"type": "string"}},
        "required": ["echo"],
        "additionalProperties": False,
    }

    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:
        return {"echo": str(kwargs.get("message", ""))}
