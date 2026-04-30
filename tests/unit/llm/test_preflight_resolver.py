"""Sprint 3 T6 — PreflightResolver + classification helpers.

Critical-controls module per AGENTS.md (``llm/preflight.py`` is on
the cloud-policy enforcer + provider-honesty ledger feed list, since
incorrect alias-to-upstream resolution silently bypasses the
enforcer per Round-3 reviewer-P1#2).

Tests cover:

- ``PreflightResolver.from_yaml`` parses ``model_list`` + stores RAW
  templates (Round-3 reviewer-P1#3: lazy ``${VAR}`` substitution).
- ``resolve(alias)`` returns ``ResolvedUpstream`` with api_base-aware
  ``external`` classification (Round-2 reviewer-P1#2: vLLM/SGLang
  serving ``model: openai/X`` against a private api_base classify
  as self-hosted).
- ``reverse_lookup(model_string)`` returns ALL matching aliases as a
  tuple (Round-3 reviewer-P1: gateway disambiguates ambiguity).
- ``UnknownAliasError`` on unknown alias.
- Classification primitives (``_is_external``, ``_is_private_host``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from cognic_agentos.llm.preflight import (
    SELF_HOSTED_MODEL_PREFIXES,
    PreflightResolver,
    ResolvedUpstream,
    UnknownAliasError,
    _is_external,
    _is_private_host,
)


def _make_config(model_list: list[dict[str, Any]]) -> str:
    return yaml.safe_dump(
        {
            "model_list": model_list,
            "litellm_settings": {},
            "general_settings": {},
        }
    )


def _write_yaml(tmp_path: Path, model_list: list[dict[str, Any]]) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(_make_config(model_list))
    return cfg


# ---------------------------------------------------------------------------
# TestPreflightResolverFromYaml — parse + store templates.
# ---------------------------------------------------------------------------


class TestPreflightResolverFromYaml:
    def test_resolves_dev_alias_to_ollama_upstream(self, tmp_path: Path) -> None:
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "cognic-tier1-dev",
                    "litellm_params": {
                        "model": "ollama/qwen3:8b",
                        "api_base": "http://ollama:11434",
                    },
                },
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        resolved = resolver.resolve("cognic-tier1-dev")
        assert resolved.model_string == "ollama/qwen3:8b"
        assert resolved.api_base == "http://ollama:11434"
        assert resolved.external is False
        assert resolved.provenance == "resolved"
        assert resolved.alias == "cognic-tier1-dev"

    def test_unknown_alias_fails_loudly(self, tmp_path: Path) -> None:
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "cognic-tier1-dev",
                    "litellm_params": {"model": "ollama/qwen3:8b"},
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        with pytest.raises(UnknownAliasError, match="not declared in"):
            resolver.resolve("cognic-tier1-cloud-openai")

    def test_known_aliases_returns_all_declared(self, tmp_path: Path) -> None:
        cfg = _write_yaml(
            tmp_path,
            [
                {"model_name": "alias-a", "litellm_params": {"model": "ollama/x"}},
                {"model_name": "alias-b", "litellm_params": {"model": "ollama/y"}},
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert set(resolver.known_aliases) == {"alias-a", "alias-b"}

    def test_skips_entries_missing_model_name(self, tmp_path: Path) -> None:
        """Defensive: a YAML entry without model_name is ignored, not
        raised on. Operator-friendly behaviour for partially-edited
        configs."""
        cfg = _write_yaml(
            tmp_path,
            [
                {"model_name": "good", "litellm_params": {"model": "ollama/x"}},
                {"litellm_params": {"model": "ollama/orphan"}},  # no model_name
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.known_aliases == ("good",)

    def test_skips_entries_missing_model_template(self, tmp_path: Path) -> None:
        cfg = _write_yaml(
            tmp_path,
            [
                {"model_name": "good", "litellm_params": {"model": "ollama/x"}},
                {"model_name": "orphan", "litellm_params": {}},  # no model
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.known_aliases == ("good",)

    def test_handles_empty_model_list(self, tmp_path: Path) -> None:
        cfg = tmp_path / "empty.yaml"
        cfg.write_text(yaml.safe_dump({"model_list": []}))
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.known_aliases == ()

    def test_handles_missing_model_list_key(self, tmp_path: Path) -> None:
        cfg = tmp_path / "no-list.yaml"
        cfg.write_text(yaml.safe_dump({"litellm_settings": {}}))
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.known_aliases == ()


# ---------------------------------------------------------------------------
# TestEnvVarSubstitution — Round-3 reviewer-P1#3 lazy substitution.
# ---------------------------------------------------------------------------


class TestEnvVarSubstitution:
    def test_substitutes_env_vars_at_resolve_time(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LiteLLM uses ``${VAR_NAME}`` substitution. The resolver
        must do the same so the parsed upstream matches what LiteLLM
        dispatches.

        Round-3 reviewer-P1#3: substitution is **lazy** — happens on
        ``resolve(alias)``, not at ``from_yaml`` load time."""
        monkeypatch.setenv("COGNIC_TIER1_VLLM_MODEL", "Qwen3-8B-Instruct")
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "cognic-tier1-vllm",
                    "litellm_params": {
                        "model": "openai/${COGNIC_TIER1_VLLM_MODEL}",
                        "api_base": "http://vllm:8000/v1",
                    },
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        resolved = resolver.resolve("cognic-tier1-vllm")
        assert resolved.model_string == "openai/Qwen3-8B-Instruct"
        assert resolved.api_base == "http://vllm:8000/v1"
        # Round-2 reviewer-P1#2: api_base on private hostname → self-hosted
        # despite the openai/ model prefix.
        assert resolved.external is False

    def test_lazy_substitution_does_not_require_unused_aliases(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Round-3 reviewer-P1#3 load-bearing test: real
        ``infra/litellm/config.yaml`` declares vLLM/SGLang aliases
        whose env vars are normally unset in dev. A naive eager-
        substitution ``from_yaml()`` would fail at import time. The
        lazy resolver must construct fine and only fail when the
        operator tries to ``resolve`` an alias whose vars are
        missing."""
        monkeypatch.delenv("COGNIC_TIER1_VLLM_MODEL", raising=False)
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "cognic-tier1-dev",
                    "litellm_params": {
                        "model": "ollama/qwen3:8b",
                        "api_base": "http://ollama:11434",
                    },
                },
                {
                    "model_name": "cognic-tier1-vllm",
                    "litellm_params": {
                        "model": "openai/${COGNIC_TIER1_VLLM_MODEL}",
                        "api_base": "http://vllm:8000/v1",
                    },
                },
            ],
        )
        # MUST NOT raise — the vllm var is unset but we're not using that alias.
        resolver = PreflightResolver.from_yaml(cfg)
        # Dev alias works:
        assert resolver.resolve("cognic-tier1-dev").model_string == "ollama/qwen3:8b"
        # The vllm alias fails ONLY when actually selected:
        with pytest.raises(ValueError, match="COGNIC_TIER1_VLLM_MODEL"):
            resolver.resolve("cognic-tier1-vllm")

    def test_default_value_syntax(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """LiteLLM's ``${VAR:-default}`` form: use ``default`` when
        ``VAR`` is unset. Matches LiteLLM's own substitution shape."""
        monkeypatch.delenv("UNSET_VAR", raising=False)
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "with-default",
                    "litellm_params": {
                        "model": "ollama/${UNSET_VAR:-fallback-model}",
                        "api_base": "http://ollama:11434",
                    },
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        resolved = resolver.resolve("with-default")
        assert resolved.model_string == "ollama/fallback-model"

    def test_round_trip_against_real_compose_config_dev_env_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reads the real ``infra/litellm/config.yaml``. Sets ONLY the
        dev/Ollama env. Round-3 reviewer-P1#3 pin: production
        vLLM/SGLang aliases must not require their env vars to be set
        just to load the resolver — only to resolve them."""
        # Clear all the production env vars to prove the dev path stands alone.
        for var in (
            "COGNIC_TIER1_VLLM_MODEL",
            "COGNIC_TIER2_VLLM_MODEL",
            "COGNIC_TIER1_SGLANG_MODEL",
            "COGNIC_TIER2_SGLANG_MODEL",
            "VLLM_BASE_URL",
            "VLLM_API_KEY",
            "SGLANG_BASE_URL",
            "SGLANG_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        repo_root = Path(__file__).resolve().parents[3]
        resolver = PreflightResolver.from_yaml(repo_root / "infra/litellm/config.yaml")
        # Dev aliases resolve cleanly:
        assert resolver.resolve("cognic-tier1-dev").model_string.startswith("ollama/")
        assert resolver.resolve("cognic-tier2-dev").model_string.startswith("ollama/")
        # Production aliases are KNOWN but not RESOLVED — calling resolve raises.
        assert "cognic-tier1-vllm" in resolver.known_aliases
        with pytest.raises(ValueError):
            resolver.resolve("cognic-tier1-vllm")

    def test_no_substitution_for_static_strings(self, tmp_path: Path) -> None:
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "static",
                    "litellm_params": {"model": "ollama/no-vars-here"},
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.resolve("static").model_string == "ollama/no-vars-here"


# ---------------------------------------------------------------------------
# TestApiBaseAwareClassification — Round-2 reviewer-P1#2 load-bearing.
# ---------------------------------------------------------------------------


class TestApiBaseAwareClassification:
    def test_classifies_openai_compat_self_hosted_as_self_hosted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Round-2 reviewer-P1#2 load-bearing test.

        ``model: openai/X`` + ``api_base: http://vllm:8000/v1`` is the
        production self-hosted vLLM shape. The api_base-aware
        classifier must mark this as self-hosted, NOT external."""
        monkeypatch.setenv("COGNIC_TIER1_VLLM_MODEL", "Qwen3-8B-Instruct")
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "cognic-tier1-vllm",
                    "litellm_params": {
                        "model": "openai/${COGNIC_TIER1_VLLM_MODEL}",
                        "api_base": "http://vllm:8000/v1",
                    },
                },
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {
                        "model": "openai/gpt-4o",
                        # No api_base — pure cloud shape.
                    },
                },
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        vllm = resolver.resolve("cognic-tier1-vllm")
        cloud = resolver.resolve("cognic-tier1-cloud-openai")
        assert vllm.external is False, "vLLM with private api_base must classify as self-hosted"
        assert cloud.external is True, "openai/* without api_base must classify as external"

    def test_known_cloud_host_in_api_base_classifies_external(self, tmp_path: Path) -> None:
        """An api_base pointing at a known cloud host (e.g.
        api.openai.com, *.openai.azure.com) classifies as external
        regardless of model prefix."""
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "azure-via-api-base",
                    "litellm_params": {
                        # Operator misconfigured: thought adding
                        # api_base would somehow make Azure self-hosted.
                        # api_base host is on the cloud allow-list →
                        # external.
                        "model": "openai/gpt-4o",
                        "api_base": "https://my-deploy.openai.azure.com/",
                    },
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.resolve("azure-via-api-base").external is True

    def test_unknown_api_base_host_fails_closed_external(self, tmp_path: Path) -> None:
        """Defensive: an api_base pointing at an unrecognised host
        (not on the cloud allow-list, not private) is treated as
        external. Operator must explicitly add new self-hosted hosts
        to the SELF_HOSTED list — no silent allow."""
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "unknown-host",
                    "litellm_params": {
                        "model": "openai/x",
                        "api_base": "https://random-public-host.example.com/v1",
                    },
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.resolve("unknown-host").external is True

    def test_no_api_base_with_self_hosted_prefix_is_self_hosted(self, tmp_path: Path) -> None:
        """Without api_base, classification falls back to the model
        prefix. ``ollama/`` etc. are on the self-hosted whitelist."""
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "no-api-base-self-hosted",
                    "litellm_params": {"model": "ollama/qwen3:8b"},
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.resolve("no-api-base-self-hosted").external is False

    def test_no_api_base_with_unknown_prefix_fails_closed_external(self, tmp_path: Path) -> None:
        """Without api_base AND without a recognised self-hosted
        prefix → fail-closed external. New self-hosted runtimes
        require an explicit prefix-list addition."""
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "weird-no-api-base",
                    "litellm_params": {"model": "weirdvendor/secret-model"},
                }
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.resolve("weird-no-api-base").external is True


# ---------------------------------------------------------------------------
# TestIsPrivateHost — RFC1918 / loopback / *.local / single-label DNS.
# ---------------------------------------------------------------------------


class TestIsPrivateHost:
    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "vllm",  # single-label container DNS
            "ollama",
            "litellm",
            "service.local",
            "host.internal",
            "name.svc",
            "x.svc.cluster.local",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
        ],
    )
    def test_private_hosts_recognised(self, host: str) -> None:
        assert _is_private_host(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            "api.openai.com",
            "example.com",
            "8.8.8.8",
            "1.1.1.1",
        ],
    )
    def test_public_hosts_not_recognised_as_private(self, host: str) -> None:
        assert _is_private_host(host) is False

    def test_empty_host_is_not_private(self) -> None:
        """Defensive: empty hostname (urlparse on a bad api_base
        returns empty) must not classify as private — fall through to
        external in the caller."""
        assert _is_private_host("") is False


# ---------------------------------------------------------------------------
# TestIsExternal — combined classification function.
# ---------------------------------------------------------------------------


class TestIsExternal:
    def test_api_base_known_cloud_is_external(self) -> None:
        assert _is_external("openai/x", "https://api.openai.com/v1") is True

    def test_api_base_private_host_is_self_hosted(self) -> None:
        assert _is_external("openai/x", "http://vllm:8000/v1") is False

    def test_api_base_unrecognised_fails_closed_external(self) -> None:
        assert _is_external("openai/x", "https://unknown.example.com") is True

    def test_no_api_base_self_hosted_prefix(self) -> None:
        assert _is_external("ollama/x", None) is False

    def test_no_api_base_unknown_prefix_fails_closed(self) -> None:
        assert _is_external("weirdvendor/x", None) is True

    def test_unparseable_api_base_falls_through_to_fail_closed(self) -> None:
        """An ``api_base`` urlparse cannot extract a hostname from
        (e.g. a bare path) treats hostname as empty — which is
        neither a known cloud host nor a private host — so the
        function falls through to fail-closed external. Covers the
        defensive empty-host branches in ``_is_known_cloud_host`` +
        ``_is_private_host``."""
        # urlparse("/no-scheme-no-host").hostname is None.
        assert _is_external("openai/x", "/no-scheme-no-host") is True


# ---------------------------------------------------------------------------
# TestReverseLookup — Round-3 reviewer-P1 + Round-3 collision.
# ---------------------------------------------------------------------------


class TestReverseLookup:
    def test_reverse_lookup_returns_all_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Round-3 reviewer-P1: ``reverse_lookup`` returns ALL aliases
        whose resolved ``model_string`` matches. The gateway
        disambiguates."""
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "cognic-tier1-dev",
                    "litellm_params": {
                        "model": "ollama/qwen3:8b",
                        "api_base": "http://ollama:11434",
                    },
                },
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {"model": "openai/gpt-5.4"},
                },
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        matches = resolver.reverse_lookup("openai/gpt-5.4")
        assert len(matches) == 1
        assert matches[0].alias == "cognic-tier1-cloud-openai"
        assert matches[0].external is True
        # Empty tuple on no match — caller fail-closes.
        assert resolver.reverse_lookup("anthropic/claude-3-5-sonnet") == ()

    def test_reverse_lookup_returns_all_matches_on_collision(self, tmp_path: Path) -> None:
        """Round-3 reviewer-P1 load-bearing test: two aliases share
        the same model_string but differ in api_base/classification —
        exactly the OpenAI-compat self-hosted vs cloud OpenAI shape
        this plan supports. ``reverse_lookup`` must return ALL
        matches so the gateway can detect the ambiguity and
        fail-closed."""
        cfg = _write_yaml(
            tmp_path,
            [
                # Self-hosted vLLM serving openai/gpt-4o.
                {
                    "model_name": "cognic-tier1-vllm-gpt4o-shape",
                    "litellm_params": {
                        "model": "openai/gpt-4o",
                        "api_base": "http://vllm:8000/v1",
                    },
                },
                # Real cloud OpenAI gpt-4o.
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {"model": "openai/gpt-4o"},
                },
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        matches = resolver.reverse_lookup("openai/gpt-4o")
        assert len(matches) == 2, "both aliases share the model_string and must both surface"
        externals = {m.external for m in matches}
        assert externals == {True, False}, (
            "matches must reflect the api_base-aware classification disagreement"
        )

    def test_reverse_lookup_skips_unresolvable_aliases(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If an alias's env var is unset, ``reverse_lookup`` must
        skip it rather than raise — otherwise an unrelated production
        alias would block reverse-lookup of the dev path."""
        monkeypatch.delenv("UNSET_PRODUCTION_VAR", raising=False)
        cfg = _write_yaml(
            tmp_path,
            [
                {
                    "model_name": "production",
                    "litellm_params": {
                        "model": "openai/${UNSET_PRODUCTION_VAR}",
                    },
                },
                {
                    "model_name": "dev",
                    "litellm_params": {"model": "ollama/qwen3:8b"},
                },
            ],
        )
        resolver = PreflightResolver.from_yaml(cfg)
        # reverse_lookup of the dev alias works despite production
        # being unresolvable.
        matches = resolver.reverse_lookup("ollama/qwen3:8b")
        assert len(matches) == 1
        assert matches[0].alias == "dev"


# ---------------------------------------------------------------------------
# TestSelfHostedPrefixes — vocabulary pin.
# ---------------------------------------------------------------------------


class TestSelfHostedPrefixes:
    def test_vocabulary_includes_known_runtimes(self) -> None:
        # Pin the prefix vocabulary so an accidental edit (or future
        # plugin pack adding a prefix) requires explicit test update.
        # Per Decision-Locking §1: ollama, vllm, sglang, openai-compat,
        # local — anything else is fail-closed external.
        assert set(SELF_HOSTED_MODEL_PREFIXES) == {
            "ollama/",
            "vllm/",
            "sglang/",
            "openai-compat/",
            "local/",
        }


# ---------------------------------------------------------------------------
# TestResolvedUpstreamReusedFromT3 — confirm T3's dataclass still works.
# ---------------------------------------------------------------------------


class TestResolvedUpstreamReusedFromT3:
    """T3 shipped the dataclass; T6 extends preflight.py with the
    resolver but should not break the dataclass shape. Smoke-check
    that import paths still work."""

    def test_can_construct_directly(self) -> None:
        r = ResolvedUpstream(
            alias="x",
            model_string="ollama/y",
            api_base="http://ollama:11434",
            external=False,
        )
        assert r.provenance == "resolved"

    def test_provider_helper(self) -> None:
        r = ResolvedUpstream(alias="x", model_string="openai/gpt-4o", api_base=None, external=True)
        assert r.provider() == "openai"


# ---------------------------------------------------------------------------
# TestRealLiteLLMConfigYaml — Sprint 3 T10.
#
# Pins the contract that ``infra/litellm/config.yaml`` declares the
# Sprint 3 cloud aliases and that they classify correctly through
# the api_base-aware classifier.
#
# Round-10 reviewer-P2 correction: ``PreflightResolver`` substitutes
# env vars only in ``model`` and ``api_base``; the YAML's ``api_key``
# field is not read by the resolver at all. So cloud aliases
# ``resolve()`` successfully even with ``OPENAI_API_KEY`` /
# ``ANTHROPIC_API_KEY`` unset — that's load-bearing for the T10
# denial-path-exerciseability goal: a dev/test environment without
# cloud credentials can still resolve the cloud alias, classify it
# external, and have the gateway's pre-call cloud-policy enforcer
# deny the call BEFORE any LiteLLM dispatch attempts to use the
# (absent) credential. The ``cloud_alias_resolves_then_denies``
# regression below pins that path.
# ---------------------------------------------------------------------------


_REAL_CONFIG = Path(__file__).parents[3] / "infra" / "litellm" / "config.yaml"

_CLOUD_OPENAI_ALIASES = (
    ("cognic-tier1-cloud-openai", "openai/gpt-4o"),
    ("cognic-tier2-cloud-openai", "openai/gpt-4o-mini"),
)
_CLOUD_ANTHROPIC_ALIASES = (
    ("cognic-tier1-cloud-anthropic", "anthropic/claude-3-5-sonnet-20241022"),
    ("cognic-tier2-cloud-anthropic", "anthropic/claude-3-5-haiku-20241022"),
)


class TestRealLiteLLMConfigYaml:
    def test_real_config_parses_with_cloud_keys_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Round-3 reviewer-P1#3 lazy-substitution contract: a dev
        environment with no cloud credentials and no vLLM / SGLang
        env vars must construct the resolver fine. ``from_yaml``
        stores raw templates; substitution happens only at
        ``resolve()`` time and only for the ``model`` + ``api_base``
        fields the resolver consumes."""
        for var in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "VLLM_API_KEY",
            "SGLANG_API_KEY",
            "VLLM_BASE_URL",
            "SGLANG_BASE_URL",
            "COGNIC_TIER1_VLLM_MODEL",
            "COGNIC_TIER2_VLLM_MODEL",
            "COGNIC_TIER1_SGLANG_MODEL",
            "COGNIC_TIER2_SGLANG_MODEL",
            "COGNIC_TIER1_CLOUD_OPENAI_MODEL",
            "COGNIC_TIER2_CLOUD_OPENAI_MODEL",
            "COGNIC_TIER1_CLOUD_ANTHROPIC_MODEL",
            "COGNIC_TIER2_CLOUD_ANTHROPIC_MODEL",
        ):
            monkeypatch.delenv(var, raising=False)
        resolver = PreflightResolver.from_yaml(_REAL_CONFIG)
        # Dev ollama aliases construct + resolve fine — they have a
        # default api_base and no required env-var.
        assert resolver.resolve("cognic-tier1-dev").external is False

    def test_real_config_declares_all_sprint_3_cloud_aliases(self) -> None:
        """Lock the alias-name contract. A rename or removal of any
        Sprint-3 cloud alias breaks the operator-facing surface
        documented in .env.example + the BUILD_PLAN."""
        resolver = PreflightResolver.from_yaml(_REAL_CONFIG)
        declared = set(resolver.known_aliases)
        expected = {
            "cognic-tier1-cloud-openai",
            "cognic-tier2-cloud-openai",
            "cognic-tier1-cloud-anthropic",
            "cognic-tier2-cloud-anthropic",
        }
        assert expected.issubset(declared), f"missing Sprint 3 cloud aliases: {expected - declared}"

    @pytest.mark.parametrize(
        ("alias", "expected_model"),
        _CLOUD_OPENAI_ALIASES + _CLOUD_ANTHROPIC_ALIASES,
    )
    def test_cloud_alias_resolves_to_external_with_default_model(
        self,
        alias: str,
        expected_model: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Cloud aliases:
        * resolve to external=True (no api_base set; classifier sees
          the cloud provider prefix unguarded by a private host),
        * carry api_base=None (Round-2 reviewer-P1#2: api_base is
          dispositive — its absence on a cloud alias is what makes
          the classification external),
        * substitute the documented default model when the per-tier
          override env var is unset.

        Round-10 reviewer-P2: ``api_key`` is NOT read by the
        resolver, so the cloud-credential env vars are intentionally
        NOT set here. Resolution succeeds without them; the gateway's
        pre-call enforcer is what gates the actual dispatch.
        """
        for var in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "COGNIC_TIER1_CLOUD_OPENAI_MODEL",
            "COGNIC_TIER2_CLOUD_OPENAI_MODEL",
            "COGNIC_TIER1_CLOUD_ANTHROPIC_MODEL",
            "COGNIC_TIER2_CLOUD_ANTHROPIC_MODEL",
        ):
            monkeypatch.delenv(var, raising=False)
        resolver = PreflightResolver.from_yaml(_REAL_CONFIG)
        resolved = resolver.resolve(alias)
        assert resolved.external is True
        assert resolved.api_base is None
        assert resolved.model_string == expected_model
        assert resolved.provenance == "resolved"

    @pytest.mark.parametrize(
        "alias",
        [
            "cognic-tier1-cloud-openai",
            "cognic-tier2-cloud-openai",
            "cognic-tier1-cloud-anthropic",
            "cognic-tier2-cloud-anthropic",
        ],
    )
    def test_cloud_alias_resolves_then_denies_under_default_policy(
        self, alias: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Round-10 reviewer-P2 — pin the actual T10 denial-path
        story end-to-end: with NO cloud credentials in the env, the
        resolver still resolves each cloud alias to an external
        ResolvedUpstream, and the default-secure cloud-policy
        enforcer denies BEFORE dispatch ever attempts to use the
        absent credential. This is the realistic dev/test posture
        the cloud aliases were added for; it also documents that
        ``api_key`` is not part of the resolver's substitution
        surface.
        """
        from cognic_agentos.core.config import Settings
        from cognic_agentos.llm.policy import enforce_cloud_policy

        for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        resolver = PreflightResolver.from_yaml(_REAL_CONFIG)
        resolved = resolver.resolve(alias)
        assert resolved.external is True, "cloud alias must classify external"

        # Default-secure settings: external denied.
        decision = enforce_cloud_policy(
            resolved=resolved,
            settings=Settings(
                allow_external_llm=False,
                policy_mode="self_hosted",
                allowed_providers=[],
            ),
            post_response=False,
        )
        assert decision.allowed is False
        assert "allow_external_llm=False" in decision.reason

    def test_cloud_openai_model_override_substitutes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Operator override flows through ``${VAR:-default}``.

        Round-10 reviewer-P2: ``api_key`` env vars are NOT required
        for resolution; deleted explicitly to make that contract
        visible in the test."""
        for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("COGNIC_TIER1_CLOUD_OPENAI_MODEL", "gpt-5.4")
        resolver = PreflightResolver.from_yaml(_REAL_CONFIG)
        assert resolver.resolve("cognic-tier1-cloud-openai").model_string == "openai/gpt-5.4"
