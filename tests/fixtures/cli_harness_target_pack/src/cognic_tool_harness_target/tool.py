"""Sprint-7A T13 fixture tool — minimal-but-valid synthetic Tool subclass.

Used by ``tests/unit/cli/test_cli_test_harness.py`` to exercise the
``agentos test-harness`` dispatch dry-run. Inert by design: ``_invoke``
echoes its kwargs back so the harness's input-then-output schema
validation seam (the SDK's :class:`Tool.invoke` template) round-trips
cleanly.

The class is loaded by the harness via
``importlib.util.spec_from_file_location`` against the fixture pack's
``src/cognic_tool_harness_target/tool.py`` filepath; the harness does
NOT pip-install the fixture pack. Pack-author packs in production
SHOULD ship as installable distributions whose entry-points get
discovered via :func:`importlib.metadata.entry_points` — the
filepath-loader path is a Wave-1 simplification for fixtures.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.sdk.tool import Tool


class HarnessTargetTool(Tool):
    """Inert echo tool used by the T13 harness dispatch dry-run."""

    name: ClassVar[str] = "harness_target"

    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "message": {"type": "string"},
        },
        "required": [],
        "additionalProperties": False,
    }

    output_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "echo": {"type": "string"},
        },
        "required": ["echo"],
        "additionalProperties": False,
    }

    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:
        """Echo the supplied ``message`` (or empty string) back as
        ``echo``. The harness's dispatch dry-run invokes this with no
        kwargs, so the empty-string default is what the conformance
        report records as the dispatched result."""
        return {"echo": str(kwargs.get("message", ""))}
