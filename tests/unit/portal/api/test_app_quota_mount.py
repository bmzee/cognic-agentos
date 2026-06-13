"""Sprint 13.6b T6 (ADR-018) — quota router mount in create_app.

Single-dep mount: quota_engine present → mount build_quota_routes + set
app.state.quota_router_mounted = True; absent → no mount (opt-in operator
surface, the emergency injection-seam posture).
"""

from __future__ import annotations

from typing import Any

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.emergency.quotas import QuotaEngine
from cognic_agentos.portal.api.app import create_app

_QUOTAS_PATH = "/api/v1/emergency/quotas"


class _FakeRedis:
    async def get(self, key: str) -> Any:
        return None

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        return None

    async def incrby(self, key: str, amount: int) -> int:
        return amount

    async def decrby(self, key: str, amount: int) -> int:
        return -amount

    async def getdel(self, key: str) -> Any:
        return None

    async def expire(self, key: str, seconds: int) -> Any:
        return None


def _engine() -> QuotaEngine:
    return QuotaEngine(redis_client=_FakeRedis(), settings=build_settings_without_env_file())


def _paths(app: object) -> set[str]:
    return {getattr(r, "path", "") for r in app.routes}  # type: ignore[attr-defined]


def test_quota_router_mounted_when_engine_present() -> None:
    app = create_app(build_settings_without_env_file(), quota_engine=_engine())
    assert app.state.quota_router_mounted is True
    assert _QUOTAS_PATH in _paths(app)


def test_quota_router_not_mounted_without_engine() -> None:
    app = create_app(build_settings_without_env_file())
    assert app.state.quota_router_mounted is False
    assert _QUOTAS_PATH not in _paths(app)
