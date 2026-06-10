from __future__ import annotations

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.portal.api.app import create_app


def test_adversarial_route_mounted() -> None:
    app = create_app(build_settings_without_env_file())
    paths = {r.path for r in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/eval/adversarial-run" in paths
