"""Test-only factory for a *valid* strict-profile (stage/prod) ``Settings``.

Wave-1 deploy-safety (T1) added config-load guards that fail loud when a
``stage`` / ``prod`` ``Settings`` is built from dev-shaped defaults:
``embedding_model`` left at the dev default (G5), ``ghcr.io/bmzee`` sandbox
images (G7), or dev tier aliases while external-LLM / non-``self_hosted`` is
configured (G6). Many pre-existing tests construct
``Settings(runtime_profile="prod")`` purely to exercise some *unrelated* prod
behaviour (otel, readyz, metrics, log format, gateway routing). Those tests
need a prod ``Settings`` that PASSES the new guards — this factory supplies
exactly the minimal deploy-safe overrides a real strict deployment would set.

Honest scope — use this ONLY for tests that need "a valid strict-profile
Settings object". Do NOT use it in tests whose purpose is to assert config
*defaults* or to exercise a guard's *failure* path (e.g.
``tests/unit/core/test_config_wave1_guards.py`` or the prod-default
assertions in ``tests/unit/test_config.py``) — those must build ``Settings``
directly so the field-under-test keeps its dev default and the guard can fire.

Lives under ``tests/support/`` per the AGENTS.md test-fixture-placement rule
(test-only; never importable by production code).
"""

from __future__ import annotations

from typing import Any

from cognic_agentos.core.config import RuntimeProfile, Settings

# Non-dev, digest-pinned, non-personal-registry images — satisfy G5/G7 AND the
# field-level digest-pin validator (``<ref>@sha256:<64-lowercase-hex>``). The
# digest is a syntactically-valid 64-hex placeholder; these refs are never
# pulled in unit tests.
_VALID_DIGEST = "@sha256:" + ("0" * 64)
_RUNTIME_PYTHON_IMAGE = "ghcr.io/cognic-test/sandbox-runtime-python" + _VALID_DIGEST
_EGRESS_PROXY_IMAGE = "ghcr.io/cognic-test/sandbox-egress-proxy" + _VALID_DIGEST


def prod_settings(*, profile: RuntimeProfile = "prod", **overrides: Any) -> Settings:
    """Return a ``Settings`` in a strict profile (default ``prod``) that PASSES
    every Wave-1 deploy-safety guard.

    Supplies the minimal deploy-safe overrides a real strict deployment would
    set: a non-dev ``embedding_model``, non-personal digest-pinned sandbox
    images, and non-dev tier aliases (so a caller may flip
    ``allow_external_llm=True`` / a cloud ``policy_mode`` without tripping G6).
    ``.env`` is suppressed (``_env_file=None``) for determinism — matching the
    careful existing pattern in ``test_reaper`` / ``test_config``.

    Bootstrap (``vault_addr`` / ``vault_token``) is NOT set by default: none of
    the strict-Settings tests set a ``vault://`` secret, so G3 stays silent.
    Pass them via ``**overrides`` if a test needs G3 satisfied.

    Any explicit ``**overrides`` win, so a test can still target a specific
    field. ``profile`` may be ``"stage"`` for stage-profile coverage.
    """
    fields: dict[str, Any] = {
        "runtime_profile": profile,
        "embedding_model": "cognic-test-embedding-model",
        "sandbox_canonical_runtime_python_image": _RUNTIME_PYTHON_IMAGE,
        "sandbox_canonical_egress_proxy_image": _EGRESS_PROXY_IMAGE,
        "tier1_alias": "cognic-tier1-prod",
        "tier2_alias": "cognic-tier2-prod",
    }
    fields.update(overrides)
    return Settings(_env_file=None, **fields)  # type: ignore[call-arg]
