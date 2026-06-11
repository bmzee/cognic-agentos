from __future__ import annotations

from pathlib import Path

from cognic_agentos.core.config import build_settings_without_env_file


def test_tools_policy_bundle_default() -> None:
    s = build_settings_without_env_file()
    assert s.tools_policy_bundle == Path("policies/_default/tools.rego")
