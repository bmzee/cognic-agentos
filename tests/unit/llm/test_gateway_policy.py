"""Sprint 3 T3 — cloud-policy enforcer.

Critical-controls module per AGENTS.md (``llm/policy.py`` —
cloud-policy enforcer). Coverage gate: ≥95% line / ≥90% branch
per-file.

Plan provenance: Decision-Locking §1 (api_base-aware classification)
+ §2 (decision tree priority), §5 (audit emission shape). Round
findings reflected in test names where load-bearing.
"""

from __future__ import annotations

import dataclasses

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.llm.policy import (
    CloudPolicyViolationError,
    GuardrailViolationError,
    enforce_cloud_policy,
)
from cognic_agentos.llm.preflight import ResolvedUpstream

# ---------------------------------------------------------------------------
# ResolvedUpstream factories — match the plan's T3 sample shape exactly.
# ---------------------------------------------------------------------------


def _ollama() -> ResolvedUpstream:
    return ResolvedUpstream(
        alias="cognic-tier1-dev",
        model_string="ollama/qwen3:8b",
        api_base="http://ollama:11434",
        external=False,
    )


def _vllm_self_hosted() -> ResolvedUpstream:
    """vLLM serving OpenAI-compat HTTP shape on a private host. The
    Round-2 reviewer-P1#2 case: model_string is ``openai/X`` BUT
    api_base is private, so external=False."""
    return ResolvedUpstream(
        alias="cognic-tier1-vllm",
        model_string="openai/Qwen3-8B-Instruct",
        api_base="http://vllm:8000/v1",
        external=False,
    )


def _openai_cloud() -> ResolvedUpstream:
    return ResolvedUpstream(
        alias="cognic-tier1-cloud-openai",
        model_string="openai/gpt-5.4",
        api_base=None,
        external=True,
    )


def _bedrock_cloud() -> ResolvedUpstream:
    return ResolvedUpstream(
        alias="cognic-tier1-cloud-bedrock",
        model_string="bedrock/anthropic.claude-3-5-sonnet",
        api_base=None,
        external=True,
    )


def _unresolved_external(cause: str = "model_not_in_yaml") -> ResolvedUpstream:
    """Round-5 + Round-6 reviewer-P1: the post-dispatch fail-closed
    upstream the gateway builds when reverse_lookup returns zero
    matches OR the LiteLLM response has no/empty/non-string ``model``
    field. Provenance gap: enforce_cloud_policy must DENY
    unconditionally regardless of settings."""
    del cause  # cause is in the audit-event payload, not on ResolvedUpstream
    return ResolvedUpstream(
        alias="cognic-tier1-cloud-openai",
        model_string="openai/gpt-7",  # not declared anywhere in YAML
        api_base=None,
        external=True,
        provenance="unresolved",
    )


def _ambiguous_external() -> ResolvedUpstream:
    """Round-3+4 reviewer-P1: mixed-classification YAML collision —
    same model_string maps to a private vLLM AND a cloud-OpenAI alias.
    Gateway builds the fail-closed object with provenance="ambiguous"."""
    return ResolvedUpstream(
        alias="cognic-tier1-cloud-openai",
        model_string="openai/gpt-4o",
        api_base=None,
        external=True,
        provenance="ambiguous",
    )


# ---------------------------------------------------------------------------
# TestEnforceCloudPolicy — the decision-tree matrix.
# ---------------------------------------------------------------------------


class TestEnforceCloudPolicy:
    """Plan T3 happy + denial paths, expanded with Round-4+5+6
    provenance-gap regressions."""

    def test_self_hosted_ollama_passes(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_ollama(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.allowed is True
        assert "self-hosted" in decision.reason

    def test_self_hosted_vllm_passes_even_with_openai_model_prefix(
        self, settings_self_hosted: Settings
    ) -> None:
        """Round-2 reviewer-P1#2: vLLM with private api_base must pass,
        even though model_string is ``openai/X``. Without this, the
        production self-hosted vLLM/SGLang shape is rejected by
        default."""
        decision = enforce_cloud_policy(
            resolved=_vllm_self_hosted(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.allowed is True
        assert "self-hosted" in decision.reason

    def test_external_with_flag_off_denies(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.allowed is False
        assert "allow_external_llm=False" in decision.reason

    def test_external_with_flag_on_but_provider_not_allowlisted_denies(
        self, settings_cloud_anthropic_only: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_cloud_anthropic_only,
            post_response=False,
        )
        assert decision.allowed is False
        assert "openai" in decision.reason

    def test_external_with_flag_on_and_provider_allowlisted_passes(
        self, settings_cloud_openai_allowed: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_cloud_openai_allowed,
            post_response=False,
        )
        assert decision.allowed is True
        assert "external upstream allowed" in decision.reason

    def test_external_to_external_drift_denied_post_response(
        self, settings_cloud_openai_allowed: Settings
    ) -> None:
        """Round-2 reviewer-P1#1: openai allow-listed but actual is
        bedrock. Both classify as external; without the post-response
        recheck the call would silently succeed against an unsanctioned
        provider."""
        decision = enforce_cloud_policy(
            resolved=_bedrock_cloud(),
            settings=settings_cloud_openai_allowed,
            post_response=True,
        )
        assert decision.allowed is False
        assert "bedrock" in decision.reason

    def test_mode_self_hosted_with_flag_on_still_denies_external(
        self, settings_self_hosted_mode_with_flag_on: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted_mode_with_flag_on,
            post_response=False,
        )
        assert decision.allowed is False
        assert "self_hosted" in decision.reason

    # --- Sprint 3 enforcer scope (T10 reviewer-P2) ------------------------
    # The Sprint 3 enforcer does NOT bind ``policy_mode=cloud_*`` sub-
    # modes to provider families: the only provider gate is
    # ``allowed_providers``. A ``cloud_anthropic`` mode + an ``openai``
    # entry on the allow-list will permit an OpenAI upstream. Tightening
    # this is on the Sprint 13.5 OPA-Rego roadmap; until then the docs
    # in ``infra/litellm/config.yaml`` and ``.env.example`` describe the
    # *actual* enforcement surface, and this test pins the gap so any
    # future runtime-strengthening commit fails here and prompts a
    # doc/test update at the same time.

    def test_policy_mode_does_not_bind_provider_family(self) -> None:
        """``cloud_anthropic`` mode + ``openai`` on the allow-list
        currently ALLOWS an OpenAI cloud upstream. Documents the gap."""
        mismatched = Settings(
            allow_external_llm=True,
            policy_mode="cloud_anthropic",  # operator says "anthropic only"
            allowed_providers=["openai"],  # ...but allow-list says openai
        )
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=mismatched,
            post_response=False,
        )
        assert decision.allowed is True, (
            "Sprint 3 enforcer treats policy_mode!=self_hosted uniformly; "
            "if this assertion now fails, the runtime has been strengthened "
            "to bind policy_mode to provider families — update the docs in "
            "infra/litellm/config.yaml + .env.example to match."
        )

    # --- Provenance-gap deny (Rounds 4+5+6 reviewer-P1) -------------------

    def test_unresolved_provenance_denies_unconditionally_default_settings(
        self, settings_self_hosted: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_unresolved_external(),
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.allowed is False
        assert "provenance gap" in decision.reason
        assert "unresolved" in decision.reason

    def test_unresolved_provenance_denies_under_permissive_allow_list(
        self, settings_cloud_openai_allowed: Settings
    ) -> None:
        """Round-5 + Round-6 reviewer-P1: even with openai allow-listed
        + flag on, an unresolved upstream must deny. Provenance gap
        overrides every other gate per Decision-Locking §2 step 1."""
        decision = enforce_cloud_policy(
            resolved=_unresolved_external(),
            settings=settings_cloud_openai_allowed,
            post_response=True,
        )
        assert decision.allowed is False
        assert "provenance gap" in decision.reason

    def test_unresolved_provenance_denies_under_max_permissive_settings(
        self, settings_cloud_mixed: Settings
    ) -> None:
        """Round-4+5+6: even ``cloud_mixed`` mode + every cloud provider
        on the allow-list cannot make a provenance-gap call pass."""
        decision = enforce_cloud_policy(
            resolved=_unresolved_external(),
            settings=settings_cloud_mixed,
            post_response=True,
        )
        assert decision.allowed is False

    def test_ambiguous_provenance_denies_unconditionally_default_settings(
        self, settings_self_hosted: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_ambiguous_external(),
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.allowed is False
        assert "provenance gap" in decision.reason
        assert "ambiguous" in decision.reason

    def test_ambiguous_provenance_denies_under_permissive_allow_list(
        self, settings_cloud_openai_allowed: Settings
    ) -> None:
        """Round-3+4 reviewer-P1: openai allow-listed BUT YAML has both
        a private-vLLM and a cloud-openai alias for the same
        model_string. Gateway flagged ambiguous; policy must deny."""
        decision = enforce_cloud_policy(
            resolved=_ambiguous_external(),
            settings=settings_cloud_openai_allowed,
            post_response=True,
        )
        assert decision.allowed is False
        assert "provenance gap" in decision.reason

    def test_ambiguous_provenance_denies_under_max_permissive_settings(
        self, settings_cloud_mixed: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_ambiguous_external(),
            settings=settings_cloud_mixed,
            post_response=True,
        )
        assert decision.allowed is False

    # --- Provenance-gap deny precedes external check ---------------------

    def test_provenance_gap_denies_even_when_resolved_self_hosted(
        self, settings_self_hosted: Settings
    ) -> None:
        """An unresolved/ambiguous ResolvedUpstream that classified as
        self-hosted (impossible-but-defensible-test) still denies. The
        provenance check is the first gate."""
        weird_self_hosted_unresolved = ResolvedUpstream(
            alias="cognic-tier1-dev",
            model_string="ollama/unknown-tag",
            api_base="http://ollama:11434",
            external=False,  # api_base says private
            provenance="unresolved",
        )
        decision = enforce_cloud_policy(
            resolved=weird_self_hosted_unresolved,
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.allowed is False
        assert "provenance gap" in decision.reason


# ---------------------------------------------------------------------------
# TestPolicyDecisionAuditPayload — privacy + shape contract per §5.
# ---------------------------------------------------------------------------


class TestPolicyDecisionAuditPayload:
    """Audit payload is the wire-format reviewer-emit format. Every key
    is examiner-visible; PII / prompt content must NEVER appear."""

    def test_payload_carries_all_resolved_fields(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.audit_payload["alias"] == "cognic-tier1-cloud-openai"
        assert decision.audit_payload["model_string"] == "openai/gpt-5.4"
        assert decision.audit_payload["api_base"] is None
        assert decision.audit_payload["external"] is True
        assert decision.audit_payload["provenance"] == "resolved"

    def test_payload_carries_all_settings_fields(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.audit_payload["policy_mode"] == "self_hosted"
        assert decision.audit_payload["allow_external_llm"] is False
        assert decision.audit_payload["allowed_providers"] == []

    def test_payload_carries_post_response_flag_false(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.audit_payload["post_response"] is False

    def test_payload_carries_post_response_flag_true(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.audit_payload["post_response"] is True

    def test_payload_carries_reason(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert "reason" in decision.audit_payload

    def test_payload_omits_prompt_content(self, settings_self_hosted: Settings) -> None:
        """Decision-Locking §5: NO prompt content / messages / PII in
        the payload — alias + model + api_base + reason only."""
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        assert "prompt" not in decision.audit_payload
        assert "messages" not in decision.audit_payload
        assert "content" not in decision.audit_payload

    def test_payload_provenance_propagates_for_unresolved(
        self, settings_self_hosted: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_unresolved_external(),
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.audit_payload["provenance"] == "unresolved"

    def test_payload_provenance_propagates_for_ambiguous(
        self, settings_self_hosted: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_ambiguous_external(),
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.audit_payload["provenance"] == "ambiguous"

    def test_payload_allowed_providers_is_a_fresh_list_not_a_settings_alias(
        self,
        settings_cloud_openai_allowed: Settings,
    ) -> None:
        """The payload eventually goes through the canonical-form
        round-trip in ``AuditStore.append`` — must be a real list, not
        a settings alias that could mutate later."""
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_cloud_openai_allowed,
            post_response=False,
        )
        assert decision.audit_payload["allowed_providers"] == ["openai"]
        assert isinstance(decision.audit_payload["allowed_providers"], list)


class TestPolicyDecision:
    """Frozen-slotted dataclass invariants."""

    def test_decision_is_frozen(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.allowed = True  # type: ignore[misc]

    def test_decision_carries_resolved_object(self, settings_self_hosted: Settings) -> None:
        resolved = _openai_cloud()
        decision = enforce_cloud_policy(
            resolved=resolved,
            settings=settings_self_hosted,
            post_response=False,
        )
        assert decision.resolved is resolved

    def test_decision_carries_post_response_flag(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=True,
        )
        assert decision.post_response is True


# ---------------------------------------------------------------------------
# TestCloudPolicyViolationError + TestGuardrailViolationError.
# ---------------------------------------------------------------------------


class TestCloudPolicyViolationError:
    def test_carries_decision(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        err = CloudPolicyViolationError.from_decision(decision)
        assert err.decision is decision

    def test_message_includes_upstream(self, settings_self_hosted: Settings) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        err = CloudPolicyViolationError.from_decision(decision)
        assert "openai/gpt-5.4" in str(err)

    def test_message_includes_post_response_suffix_when_true(
        self, settings_self_hosted: Settings
    ) -> None:
        """The post-response recheck path appends a suffix so log
        readers can distinguish pre-dispatch denials from post-response
        denials at a glance."""
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=True,
        )
        err = CloudPolicyViolationError.from_decision(decision)
        assert "post-response recheck" in str(err)

    def test_message_omits_post_response_suffix_when_false(
        self, settings_self_hosted: Settings
    ) -> None:
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        err = CloudPolicyViolationError.from_decision(decision)
        assert "post-response recheck" not in str(err)

    def test_subclasses_runtime_error(self) -> None:
        """Generic runtime-error catchers still trip — important for
        request-path callers that wrap the gateway in a 500-handler."""
        assert issubclass(CloudPolicyViolationError, RuntimeError)

    def test_constructor_accepts_explicit_message(self, settings_self_hosted: Settings) -> None:
        """Direct construction (vs ``from_decision``) is supported for
        tests + future custom callers."""
        decision = enforce_cloud_policy(
            resolved=_openai_cloud(),
            settings=settings_self_hosted,
            post_response=False,
        )
        err = CloudPolicyViolationError("custom message", decision)
        assert str(err) == "custom message"
        assert err.decision is decision


class TestGuardrailViolationError:
    def test_input_direction_message(self) -> None:
        err = GuardrailViolationError("input", "regex_pii")
        assert err.direction == "input"
        assert err.trip_summary == "regex_pii"
        assert "guardrail.input trip" in str(err)
        assert "regex_pii" in str(err)

    def test_output_direction_message(self) -> None:
        err = GuardrailViolationError("output", "injection")
        assert err.direction == "output"
        assert "guardrail.output trip" in str(err)

    def test_subclasses_runtime_error(self) -> None:
        assert issubclass(GuardrailViolationError, RuntimeError)


# ---------------------------------------------------------------------------
# TestResolvedUpstream — dataclass shape + provider() helper.
# ---------------------------------------------------------------------------


class TestResolvedUpstream:
    """T3 ships only the dataclass; T6 adds the YAML parser. Tests
    here pin the shape T3 + T6 + T8/T9 all consume."""

    def test_default_provenance_is_resolved(self) -> None:
        r = ResolvedUpstream(
            alias="cognic-tier1-dev",
            model_string="ollama/qwen3:8b",
            api_base="http://ollama:11434",
            external=False,
        )
        assert r.provenance == "resolved"

    def test_provenance_unresolved_accepted(self) -> None:
        r = ResolvedUpstream(
            alias="cognic-tier1-dev",
            model_string="openai/gpt-7",
            api_base=None,
            external=True,
            provenance="unresolved",
        )
        assert r.provenance == "unresolved"

    def test_provenance_ambiguous_accepted(self) -> None:
        r = ResolvedUpstream(
            alias="cognic-tier1-dev",
            model_string="openai/gpt-4o",
            api_base=None,
            external=True,
            provenance="ambiguous",
        )
        assert r.provenance == "ambiguous"

    def test_provider_extracts_head_with_slash(self) -> None:
        r = ResolvedUpstream(alias="x", model_string="openai/gpt-5.4", api_base=None, external=True)
        assert r.provider() == "openai"

    def test_provider_returns_none_on_empty_model_string(self) -> None:
        r = ResolvedUpstream(alias="x", model_string="", api_base=None, external=True)
        assert r.provider() is None

    def test_provider_returns_none_when_string_starts_with_slash(self) -> None:
        """Defensive — fail-closed posture: a malformed model_string
        that starts with ``/`` has no provider; return None so the
        allowed_providers check denies it."""
        r = ResolvedUpstream(alias="x", model_string="/foo", api_base=None, external=True)
        assert r.provider() is None

    def test_provider_returns_full_string_when_no_slash(self) -> None:
        """A model_string with no slash returns the whole string as
        provider. Combined with the allowed_providers check, this
        denies unknown shapes by default."""
        r = ResolvedUpstream(alias="x", model_string="custom-model", api_base=None, external=True)
        assert r.provider() == "custom-model"

    def test_dataclass_is_frozen(self) -> None:
        r = ResolvedUpstream(alias="x", model_string="ollama/x", api_base=None, external=False)
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.alias = "y"  # type: ignore[misc]
