"""Wave-1 T4 — ``model_artifact_root`` profile-aware resolver.

The field is ``str | None`` (default ``None``); the
``_resolve_model_artifact_root`` model_validator fills it per ``runtime_profile``
at construction: prod → ``/var/lib/cognic/model-artifacts``, dev / stage →
``$TMPDIR``-derived. These tests pin that resolution for all three profiles + the
explicit-override path, and that the sole consumer's ``Path(...)`` pattern still
receives a non-None str after the type change.
"""

from pathlib import Path
from typing import Any, Literal

import pytest

from cognic_agentos.core.config import Settings

# A strict-profile (stage/prod) Settings must satisfy T1's G5 (non-dev
# embedding_model) + G7 (non-personal digest-pinned sandbox images) to
# construct. These tests assert model_artifact_root RESOLUTION on top of a valid
# strict Settings, so they supply those compliant fields inline (the field under
# test is model_artifact_root, not those).
_PIN = "@sha256:" + "0" * 64
_RP_IMG = "ghcr.io/cognic-test/sandbox-runtime-python" + _PIN
_EP_IMG = "ghcr.io/cognic-test/sandbox-egress-proxy" + _PIN


def _strict_kw(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "embedding_model": "prod-embed-model",
        "sandbox_canonical_runtime_python_image": _RP_IMG,
        "sandbox_canonical_egress_proxy_image": _EP_IMG,
    }
    base.update(extra)
    return base


def test_prod_unset_resolves_var_lib() -> None:
    s = Settings(runtime_profile="prod", **_strict_kw())
    assert s.model_artifact_root == "/var/lib/cognic/model-artifacts"
    assert isinstance(s.model_artifact_root, str)


@pytest.mark.parametrize("profile", ("dev", "stage"))
def test_dev_stage_unset_resolves_tmpdir(
    profile: Literal["dev", "stage"], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TMPDIR", "/tmp/cognic-t4")
    kw = {} if profile == "dev" else _strict_kw()
    s = Settings(runtime_profile=profile, **kw)
    assert s.model_artifact_root is not None  # resolver filled it
    assert s.model_artifact_root.startswith("/tmp/cognic-t4")
    assert isinstance(s.model_artifact_root, str)


def test_explicit_override_wins_in_every_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    # The resolver only fills when unset — an explicit value is never clobbered.
    monkeypatch.setenv("TMPDIR", "/tmp/cognic-t4")
    s_prod = Settings(runtime_profile="prod", model_artifact_root="/srv/models", **_strict_kw())
    assert s_prod.model_artifact_root == "/srv/models"
    s_dev = Settings(runtime_profile="dev", model_artifact_root="/srv/models")
    assert s_dev.model_artifact_root == "/srv/models"  # NOT clobbered by $TMPDIR


def test_lifecycle_consumer_receives_path_string() -> None:
    """The sole consumer (``portal/api/models/lifecycle_routes.py``) does
    ``Path(settings.model_artifact_root)`` after a non-None narrow. Prove that a
    resolver-FILLED (unset) value narrows to a non-None str and wraps in ``Path``
    cleanly — mirroring the exact T4 consumer narrow."""
    s = Settings(runtime_profile="prod", **_strict_kw())  # unset → resolver fills
    artifact_root = s.model_artifact_root
    assert artifact_root is not None
    root = Path(artifact_root)
    assert isinstance(root, Path)
    assert str(root) == "/var/lib/cognic/model-artifacts"
