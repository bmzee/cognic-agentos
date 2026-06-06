from __future__ import annotations

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.portal.api.app import create_app


def test_eval_judge_route_mounted() -> None:
    app = create_app(build_settings_without_env_file())
    assert any(getattr(r, "path", "") == "/api/v1/eval/judge" for r in app.routes)
