"""Sprint-7A T15 reference skill — inert deterministic composition.

Declares ``example_minimal`` as the only required tool; the skill's
``execute`` invokes that tool via the bound ``ToolRegistry`` and
returns the tool's output verbatim. Lets pack authors copy a working
``Skill`` subclass that already cross-checks its declared tools at
instantiation.

Per Doctrine D (plan §59), the pack is **inert** — the composition
just round-trips the input string through the tool's echo. NOT a
model for production skill orchestration.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.sdk.skill import Skill


class ExampleMinimalSkill(Skill):
    """Inert deterministic skill — Wave-1 reference implementation."""

    name: ClassVar[str] = "example_minimal"
    declared_tools: ClassVar[tuple[str, ...]] = ("example_minimal",)

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        echo_tool = self._tools.get("example_minimal")
        result = await echo_tool.invoke(message=str(kwargs.get("message", "")))
        return {"composed": result}
