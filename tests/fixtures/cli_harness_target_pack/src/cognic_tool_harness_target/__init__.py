"""Sprint-7A T13 fixture pack package init.

The ``cognic_tool_harness_target`` package is the importable Python
module surface the T13 harness loads via
``importlib.util.spec_from_file_location`` against the fixture pack's
``src/`` tree. Only the ``HarnessTargetTool`` class is re-exported;
every other contract on the pack lives in ``tool.py``.
"""

from __future__ import annotations

from cognic_tool_harness_target.tool import HarnessTargetTool

__all__ = ["HarnessTargetTool"]
