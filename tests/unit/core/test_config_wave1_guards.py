from typing import Any

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings

STRICT = ("stage", "prod")
_PIN = "@sha256:" + "a" * 64  # valid digest-pin (satisfies the digest-pin field-validator)


def prod_compliant_settings_kwargs(**kw: Any) -> dict[str, Any]:
    """Strict-profile (``prod``) Settings kwargs that PASS every G1-G8 guard.

    Sets EVERY strict-profile guard to a passing value so only the field a caller
    overrides (via ``**kw``) can trip a guard: bootstrap present (G3), prod
    embedding model (G5), non-personal digest-pinned sandbox images (G7); tier
    aliases stay inert under the ``self_hosted`` default (G6); ``runtime_profile``
    is ``prod`` so STRICT guards are active. The dict is typed ``dict[str, Any]``
    (mirroring tests/unit/core/test_vault_transport.py ``_settings``) so
    ``Settings(**kwargs)`` matches every field overload — a str-valued dict would
    not satisfy bool / int / Path fields under strict mypy.

    Reused by tests/unit/core/test_config_cache_guards.py (Harness Injection T4)
    to exercise the cache guards (G9/G10) against a baseline that clears G1-G8.
    """
    base: dict[str, Any] = {
        "runtime_profile": "prod",
        "vault_addr": "http://vault:8200",
        "vault_token": "boot",
        "embedding_model": "prod-embed-model",
        "sandbox_canonical_runtime_python_image": "ghcr.io/acme/runtime" + _PIN,
        "sandbox_canonical_egress_proxy_image": "ghcr.io/acme/proxy" + _PIN,
    }
    base.update(kw)
    return base


def _base(**kw: Any) -> dict[str, Any]:
    # Strict-profile-compliant kwargs MINUS ``runtime_profile`` — the existing
    # G1-G8 tests pass ``runtime_profile=profile`` separately (parametrized over
    # ("stage", "prod")), so this helper must not pin the profile itself. Single
    # source of truth: derive from ``prod_compliant_settings_kwargs`` and drop the
    # profile key, then apply the per-test override.
    base = prod_compliant_settings_kwargs()
    base.pop("runtime_profile")
    base.update(kw)
    return base


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize(
    "field",
    ["litellm_master_key", "langfuse_secret_key", "embedding_api_key", "dynatrace_api_token"],
)
def test_g1_plain_secret_forbidden_in_strict_profile(profile, field):
    with pytest.raises(ValidationError, match="secret_plain_value_forbidden_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(**{field: "plaintext-secret"}))


@pytest.mark.parametrize(
    "field",
    ["litellm_master_key", "langfuse_secret_key", "embedding_api_key", "dynatrace_api_token"],
)
def test_g1_vault_uri_ok_in_prod(field):
    s = Settings(runtime_profile="prod", **_base(**{field: "vault://secret/cognic/x"}))
    assert getattr(s, field) == "vault://secret/cognic/x"


@pytest.mark.parametrize(
    "field",
    ["litellm_master_key", "langfuse_secret_key", "embedding_api_key", "dynatrace_api_token"],
)
def test_g1_plain_secret_ok_in_dev(field):
    overrides: dict[str, Any] = {field: "plaintext-secret"}
    s = Settings(runtime_profile="dev", **overrides)  # dev: no other guard fires
    assert getattr(s, field) == "plaintext-secret"


@pytest.mark.parametrize("profile", STRICT)
def test_g2_deprecated_vault_path_forbidden(profile):
    with pytest.raises(ValidationError, match="vault_path_field_deprecated_use_vault_uri"):
        Settings(runtime_profile=profile, **_base(embedding_api_key_vault_path="secret/x"))


def test_g2_deprecated_vault_path_warns_in_dev(caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        Settings(
            runtime_profile="dev", embedding_api_key_vault_path="secret/x"
        )  # dev: warn, no raise
    assert any(
        ("vault_path" in r.message.lower()) or ("deprecat" in r.message.lower())
        for r in caplog.records
    ), "dev _vault_path warning must be emitted"


@pytest.mark.parametrize("profile", ("dev", "stage", "prod"))
def test_g3_vault_bootstrap_required_any_profile(profile):
    # vault:// used but NO vault_addr/vault_token -> fail in ANY profile. Don't use _base
    # (it provides the bootstrap); satisfy G5/G7 inline so only G3 fires.
    with pytest.raises(ValidationError, match="vault_bootstrap_unset_for_secret_resolution"):
        Settings(
            runtime_profile=profile,
            embedding_model="prod-embed-model",
            sandbox_canonical_runtime_python_image="ghcr.io/acme/r" + _PIN,
            sandbox_canonical_egress_proxy_image="ghcr.io/acme/p" + _PIN,
            litellm_master_key="vault://secret/x",
        )


@pytest.mark.parametrize("profile", STRICT)
def test_g4_require_cosign_false_forbidden(profile):
    with pytest.raises(ValidationError, match="require_cosign_false_forbidden_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(require_cosign=False))


def test_g4_require_cosign_false_ok_in_dev():
    assert Settings(runtime_profile="dev", require_cosign=False).require_cosign is False


@pytest.mark.parametrize("profile", STRICT)
def test_g5_embedding_model_dev_default_forbidden(profile):
    with pytest.raises(ValidationError, match="embedding_model_dev_default_in_strict_profile"):
        Settings(runtime_profile=profile, **_base(embedding_model="qwen3-embedding:8b"))


@pytest.mark.parametrize("profile", STRICT)
def test_g6_tier_alias_guard_fires_when_not_self_hosted(profile):
    with pytest.raises(ValidationError, match="tier_alias_dev_default_with_external_llm"):
        Settings(runtime_profile=profile, **_base(policy_mode="cloud_openai"))


@pytest.mark.parametrize("profile", STRICT)
def test_g6_tier_alias_inert_under_self_hosted(profile):
    s = Settings(runtime_profile=profile, **_base())
    assert s.tier1_alias == "cognic-tier1-dev"


@pytest.mark.parametrize("profile", STRICT)
def test_g7_sandbox_personal_image_default_forbidden(profile):
    with pytest.raises(
        ValidationError, match="sandbox_canonical_image_personal_default_in_strict_profile"
    ):
        Settings(
            runtime_profile=profile,
            **_base(
                sandbox_canonical_egress_proxy_image="ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy"
                + _PIN
            ),
        )


@pytest.mark.parametrize("profile", ("dev", "stage", "prod"))
def test_g8_vault_token_vault_uri_forbidden_any_profile(profile):
    # vault_token is the bootstrap credential — it can NEVER itself be a vault://
    # reference (chicken-and-egg, spec §3.5). Forbidden in EVERY profile. For strict
    # profiles _base supplies compliant embedding_model + images so ONLY G8 fires;
    # in dev no other guard applies.
    overrides: dict[str, Any] = {"vault_token": "vault://secret/bootstrap"}
    kw = overrides if profile == "dev" else _base(**overrides)
    with pytest.raises(ValidationError, match="vault_token_vault_uri_forbidden"):
        Settings(runtime_profile=profile, **kw)


@pytest.mark.parametrize("profile", ("dev", "stage", "prod"))
def test_g8_vault_token_plain_ok_any_profile(profile):
    # A plain (non-vault://) bootstrap token is allowed in EVERY profile — only the
    # vault:// shape is forbidden (vault_token is exempt from the G1 plaintext rule).
    overrides: dict[str, Any] = {"vault_token": "plain-bootstrap-token"}
    kw = overrides if profile == "dev" else _base(**overrides)
    s = Settings(runtime_profile=profile, **kw)
    assert s.vault_token == "plain-bootstrap-token"


def test_config_does_not_import_db_adapters():
    import ast
    import pathlib

    src = pathlib.Path("src/cognic_agentos/core/config.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        for m in mods:
            assert "db.adapters" not in m, f"config.py must not import db.adapters (found {m})"
