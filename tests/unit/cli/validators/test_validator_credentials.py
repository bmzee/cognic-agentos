"""Sprint 10.6 T14 — credentials manifest validator regressions.

Per-concern validator for ``[credentials.<logical_name>]`` pack-manifest
blocks declared per ADR-004 §25 + ADR-017 + Sprint 10.6 spec §5.1. One
positive + one negative test per closed-enum refusal reason (~45 tests
including the corrected duplicate-detection design).

Test file naming matches the existing codebase convention
(``test_validator_<name>.py``) sitting under ``tests/unit/cli/validators/``;
the Sprint 10.6 plan-of-record §127 + §132 used ``test_credentials.py``
which was a one-off naming; patched to the canonical convention in the
same T14 commit per ``[[feedback_patch_plan_against_doctrine]]``.

Corrected duplicate-detection design (vs the original plan §216-223):
the plan's ``test_duplicate_logical_name_across_blocks_refuses`` was
broken because the sample input ``{"db_main": decl, "db_main ": decl}``
(trailing space on the second key) trips
``credentials_logical_name_invalid_grammar`` FIRST (trailing space is
not lowercase snake_case), so the duplicate check never gets to compare
the two strings. The fix:

- ``credentials_logical_name_duplicate`` is UNREACHABLE from a single
  Python dict input (dict keys are unique by language invariant; TOML
  parsers reject duplicate section headers at parse time).
- The validator's internal helper ``_detect_duplicate_names`` IS the
  surface that fires the refusal — called from ``validate()`` with
  ``list(credentials.items())`` (no-op for dict input; future-proofs
  the Sprint 10.6+ T15 orchestrator-merge path that produces a
  list-of-pairs from composed base + overlay manifest sources).
- Two narrow tests pin the contract: precedence (grammar refusal
  takes precedence; the duplicate refusal is never collateral on a
  trailing-space key) + helper-direct (the helper fires when called
  with a synthetic list-of-pairs duplicate, demonstrating the closed-
  enum value is genuinely wired even though dict input cannot reach
  it).
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli.validators.credentials import _detect_duplicate_names, validate

# Baseline valid pack manifest with one [credentials.db_main] block.
# Tests override single fields to exercise each refusal mode.
_BASELINE: dict[str, Any] = {
    "pack": {"name": "test-pack", "version": "0.1.0"},
    "runtime": {"expected_workload_gid": 1000},
    "risk_tier": {"tier": "internal_write"},
    "credentials": {
        "db_main": {
            "vault_path": "database/creds/db-main",
            "expected_fields": ["username", "password"],
            "ttl_s": 900,
            "purpose_category": "application_database_read",
            "purpose_description": "Read-only database access.",
        },
    },
}


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Recursive merge; overrides win at every nesting level."""
    result = copy.deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _assert_refuses_with(
    reason: str, overrides: dict[str, Any], *, pack_path: Path = Path(".")
) -> None:
    findings = validate(_deep_merge(_BASELINE, overrides), pack_path)
    refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
    assert reason in refusal_reasons, (
        f"Expected refusal reason {reason!r} in findings; got {refusal_reasons!r}"
    )


def _assert_passes(overrides: dict[str, Any], *, pack_path: Path = Path(".")) -> None:
    findings = validate(_deep_merge(_BASELINE, overrides), pack_path)
    refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
    assert refusal_reasons == set(), f"Expected zero refusals; got {refusal_reasons!r}"


# ---------------------------------------------------------------------------
# Logical-name grammar
# ---------------------------------------------------------------------------


class TestLogicalNameGrammar:
    def test_valid_lowercase_snake_case_passes(self) -> None:
        decl = _BASELINE["credentials"]["db_main"]
        _assert_passes({"credentials": {"db_main_v2": decl, "db_main": None}})

    def test_uppercase_refuses_with_logical_name_invalid_grammar(self) -> None:
        decl = _BASELINE["credentials"]["db_main"]
        _assert_refuses_with(
            "credentials_logical_name_invalid_grammar",
            {"credentials": {"DB_Main": decl, "db_main": None}},
        )

    def test_starting_with_digit_refuses(self) -> None:
        decl = _BASELINE["credentials"]["db_main"]
        _assert_refuses_with(
            "credentials_logical_name_invalid_grammar",
            {"credentials": {"1bad": decl, "db_main": None}},
        )

    def test_exceeds_32_chars_refuses(self) -> None:
        too_long = "a" * 33
        decl = _BASELINE["credentials"]["db_main"]
        _assert_refuses_with(
            "credentials_logical_name_invalid_grammar",
            {"credentials": {too_long: decl, "db_main": None}},
        )


# ---------------------------------------------------------------------------
# Logical-name duplicate detection (corrected design — see module docstring)
# ---------------------------------------------------------------------------


class TestLogicalNameDuplicateDetection:
    """The ``credentials_logical_name_duplicate`` closed-enum value is
    wire-protocol-public + drift-detector-pinned (per T13) but is
    UNREACHABLE from a single canonical dict input — Python dict keys
    are unique by language invariant.

    Reachable future site: T15+ orchestrator overlay merge that
    produces a list-of-pairs shape from composed base + overlay
    manifest sources. The validator's internal helper
    ``_detect_duplicate_names`` IS the surface that catches them.
    """

    def test_grammar_refusal_takes_precedence_over_duplicate_detection(self) -> None:
        # When the validator encounters a near-duplicate logical name
        # that fails grammar (e.g., trailing space, which the test
        # constructs via a TOML-parser-allowable quoted-key shape that
        # Python preserves as a dict key with trailing whitespace),
        # the grammar refusal fires; the bad name is dropped from
        # further per-block checks for that name + the duplicate
        # detector never compares it against the canonical key.
        decl = _BASELINE["credentials"]["db_main"]
        findings = validate(
            _deep_merge(_BASELINE, {"credentials": {"db_main ": decl}}),
            Path("."),
        )
        refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
        assert "credentials_logical_name_invalid_grammar" in refusal_reasons
        assert "credentials_logical_name_duplicate" not in refusal_reasons, (
            "duplicate-detection refusal must NOT fire on a near-duplicate "
            "where one key fails grammar — that key never participates in "
            "the duplicate check after being refused on grammar grounds"
        )

    def test_helper_fires_on_synthetic_list_of_pairs_duplicates(self) -> None:
        # Direct call to ``_detect_duplicate_names`` with a synthetic
        # list-of-pairs input demonstrates the closed-enum value is
        # genuinely wired + reachable from the future T15+ orchestrator
        # merge path. Dict input cannot construct this case (key
        # uniqueness is a Python invariant), but a composed-input
        # shape from upstream overlay merging can.
        decl = _BASELINE["credentials"]["db_main"]
        findings = _detect_duplicate_names([("db_main", decl), ("db_main", decl)])
        reasons = {f.reason for f in findings}
        assert "credentials_logical_name_duplicate" in reasons

    def test_helper_does_not_filter_grammar_on_malformed_duplicates(self) -> None:
        # T14b reviewer-found doc-drift: the helper's contract is
        # exact-string compare without grammar pre-filtering. A
        # synthetic list-of-pairs with TWO copies of a malformed
        # name will fire ``credentials_logical_name_duplicate``
        # from the helper. End-to-end ``validate()`` would ALSO fire
        # ``credentials_logical_name_invalid_grammar`` from its
        # per-block grammar loop — but the helper itself emits
        # only the duplicate refusal. This test pins the
        # no-grammar-filtering contract so future callers
        # consuming the helper directly know what to expect.
        decl = _BASELINE["credentials"]["db_main"]
        findings = _detect_duplicate_names([("DB_Main", decl), ("DB_Main", decl)])
        reasons = {f.reason for f in findings}
        assert "credentials_logical_name_duplicate" in reasons, (
            "helper must fire duplicate refusal on exact-string-equal "
            "malformed names — no grammar pre-filtering at the helper layer"
        )
        # The helper does NOT independently emit the grammar refusal;
        # that's the per-block grammar check's job at the validate()
        # level. Pin the helper's narrow scope:
        assert "credentials_logical_name_invalid_grammar" not in reasons, (
            "helper must NOT emit grammar refusals — its scope is "
            "duplicate detection only; grammar is the per-block check's "
            "responsibility"
        )


# ---------------------------------------------------------------------------
# vault_path
# ---------------------------------------------------------------------------


class TestVaultPathGrammar:
    def test_valid_database_creds_role_passes(self) -> None:
        _assert_passes({"credentials": {"db_main": {"vault_path": "database/creds/db-main"}}})

    def test_empty_refuses_with_empty(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_empty",
            {"credentials": {"db_main": {"vault_path": ""}}},
        )

    def test_leading_slash_refuses_with_invalid_shape(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_invalid_shape",
            {"credentials": {"db_main": {"vault_path": "/database/creds/db-main"}}},
        )

    def test_trailing_slash_refuses_with_invalid_shape(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_invalid_shape",
            {"credentials": {"db_main": {"vault_path": "database/creds/db-main/"}}},
        )

    def test_double_slash_refuses_with_invalid_shape(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_invalid_shape",
            {"credentials": {"db_main": {"vault_path": "database//creds/db-main"}}},
        )

    def test_no_separator_refuses_with_invalid_shape(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_invalid_shape",
            {"credentials": {"db_main": {"vault_path": "database-creds-db-main"}}},
        )

    def test_contains_dot_refuses_with_invalid_chars(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_invalid_chars",
            {"credentials": {"db_main": {"vault_path": "database/creds/db.main"}}},
        )

    def test_exceeds_512_chars_refuses(self) -> None:
        too_long = "database/creds/" + ("a" * 512)
        _assert_refuses_with(
            "credentials_vault_path_exceeds_length",
            {"credentials": {"db_main": {"vault_path": too_long}}},
        )

    def test_duplicate_across_blocks_refuses(self) -> None:
        same_path_decl = {
            **_BASELINE["credentials"]["db_main"],
            "vault_path": "database/creds/shared",
        }
        _assert_refuses_with(
            "credentials_vault_path_duplicate_across_blocks",
            {
                "credentials": {
                    "db_main": {**same_path_decl},
                    "db_audit": {**same_path_decl},
                }
            },
        )

    def test_case_sensitive_preservation(self) -> None:
        # Mixed case allowed; validator does NOT lowercase the path
        _assert_passes({"credentials": {"db_main": {"vault_path": "database/Creds/DB-Main"}}})

    def test_invalid_chars_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_invalid_chars",
            {"credentials": {"db_main": {"vault_path": "database/creds/role!"}}},
        )


# ---------------------------------------------------------------------------
# expected_fields
# ---------------------------------------------------------------------------


class TestExpectedFieldsGrammar:
    def test_valid_two_fields_passes(self) -> None:
        _assert_passes({"credentials": {"db_main": {"expected_fields": ["username", "password"]}}})

    def test_empty_list_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_expected_fields_empty",
            {"credentials": {"db_main": {"expected_fields": []}}},
        )

    def test_seventeen_fields_refuses_with_count_exceeds(self) -> None:
        _assert_refuses_with(
            "credentials_expected_fields_count_exceeds_maximum",
            {"credentials": {"db_main": {"expected_fields": [f"field{i}" for i in range(17)]}}},
        )

    def test_duplicates_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_expected_fields_contains_duplicates",
            {"credentials": {"db_main": {"expected_fields": ["username", "username"]}}},
        )

    def test_underscore_prefix_refuses_with_reserved(self) -> None:
        # Precedence locked: reserved-underscore-prefix fires BEFORE
        # the general invalid-grammar refusal, so authors get an
        # actionable error pointing at the reserved-prefix rule
        # rather than a generic "name doesn't match snake_case".
        _assert_refuses_with(
            "credentials_expected_fields_reserved_underscore_prefix",
            {"credentials": {"db_main": {"expected_fields": ["username", "_password"]}}},
        )

    def test_uppercase_field_name_refuses_with_invalid_grammar(self) -> None:
        _assert_refuses_with(
            "credentials_expected_fields_field_name_invalid_grammar",
            {"credentials": {"db_main": {"expected_fields": ["Username", "password"]}}},
        )

    def test_invalid_chars_refuses_with_invalid_grammar(self) -> None:
        _assert_refuses_with(
            "credentials_expected_fields_field_name_invalid_grammar",
            {"credentials": {"db_main": {"expected_fields": ["user-name", "password"]}}},
        )

    def test_field_name_exceeding_32_chars_refuses(self) -> None:
        # Spec §5.1: each ``expected_fields`` entry matches
        # ``^[a-z][a-z0-9_]{0,31}$`` (max 32 chars total). The T14b
        # reviewer-found drift was that the earlier draft used
        # ``^[a-z][a-z0-9_]*$`` (no length cap) which let 33+-char
        # names pass. This regression pins the corrected regex.
        too_long_field = "a" * 33  # 33 lowercase 'a's — fails length cap
        _assert_refuses_with(
            "credentials_expected_fields_field_name_invalid_grammar",
            {"credentials": {"db_main": {"expected_fields": [too_long_field, "password"]}}},
        )


# ---------------------------------------------------------------------------
# ttl_s
# ---------------------------------------------------------------------------


class TestTtlSInvalid:
    def test_negative_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_ttl_s_invalid",
            {"credentials": {"db_main": {"ttl_s": -1}}},
        )

    def test_zero_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_ttl_s_invalid",
            {"credentials": {"db_main": {"ttl_s": 0}}},
        )

    def test_positive_passes(self) -> None:
        _assert_passes({"credentials": {"db_main": {"ttl_s": 600}}})


# ---------------------------------------------------------------------------
# purpose_category
# ---------------------------------------------------------------------------


class TestPurposeCategoryGrammar:
    def test_valid_value_passes(self) -> None:
        _assert_passes(
            {"credentials": {"db_main": {"purpose_category": "external_api_authentication"}}}
        )

    def test_invalid_value_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_purpose_category_invalid_value",
            {"credentials": {"db_main": {"purpose_category": "made_up_category"}}},
        )


# ---------------------------------------------------------------------------
# purpose_description
# ---------------------------------------------------------------------------


class TestPurposeDescriptionShape:
    def test_valid_short_string_passes(self) -> None:
        _assert_passes({"credentials": {"db_main": {"purpose_description": "Brief purpose."}}})

    def test_empty_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_purpose_description_invalid_shape",
            {"credentials": {"db_main": {"purpose_description": ""}}},
        )

    def test_exceeds_256_chars_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_purpose_description_invalid_shape",
            {"credentials": {"db_main": {"purpose_description": "x" * 257}}},
        )


# ---------------------------------------------------------------------------
# pack-wide cap
# ---------------------------------------------------------------------------


class TestPackWideCaps:
    def test_seventeen_credentials_refuses_with_count_exceeds_maximum(self) -> None:
        big = {f"db_{i}": _BASELINE["credentials"]["db_main"] for i in range(17)}
        _assert_refuses_with("credentials_count_exceeds_maximum", {"credentials": big})


# ---------------------------------------------------------------------------
# unknown_field
# ---------------------------------------------------------------------------


class TestUnknownField:
    def test_unknown_field_in_credential_block_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_unknown_field",
            {"credentials": {"db_main": {"made_up_field": "x"}}},
        )


# ---------------------------------------------------------------------------
# Required-field enforcement (T14b reviewer fix per spec §5.1)
# ---------------------------------------------------------------------------


class TestRequiredFields:
    """Spec §5.1 marks all 5 ``[credentials.<name>]`` block fields as
    required (``vault_path``, ``expected_fields``, ``ttl_s``,
    ``purpose_category``, ``purpose_description``). The pre-T14b
    draft only ran per-field validators when the field key was
    present in ``decl``, which silently admitted empty-block + any-
    missing-field manifests. Fixed at T14b by calling each per-field
    validator unconditionally via ``decl.get("xxx")`` — absent
    fields forward ``None`` which each validator maps to the
    closest closed-enum refusal for its field.

    These regressions pin the required-field contract so a future
    refactor that re-introduces the ``in`` check is caught
    immediately. Without this contract, T15's wiring into
    ``cli/validate.py`` would admit malformed signed manifests
    that lack required credential fields.
    """

    def test_empty_dict_block_emits_all_5_required_field_refusals(self) -> None:
        manifest: dict[str, Any] = {
            "pack": {"name": "test-pack", "version": "0.1.0"},
            "runtime": {"expected_workload_gid": 1000},
            "risk_tier": {"tier": "internal_write"},
            "credentials": {"db_main": {}},
        }
        findings = validate(manifest, Path("."))
        refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
        assert "credentials_vault_path_empty" in refusal_reasons
        assert "credentials_expected_fields_empty" in refusal_reasons
        assert "credentials_ttl_s_invalid" in refusal_reasons
        assert "credentials_purpose_category_invalid_value" in refusal_reasons
        assert "credentials_purpose_description_invalid_shape" in refusal_reasons

    def test_missing_vault_path_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_vault_path_empty",
            {"credentials": {"db_main": {"vault_path": None}}},
        )

    def test_missing_expected_fields_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_expected_fields_empty",
            {"credentials": {"db_main": {"expected_fields": None}}},
        )

    def test_missing_ttl_s_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_ttl_s_invalid",
            {"credentials": {"db_main": {"ttl_s": None}}},
        )

    def test_missing_purpose_category_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_purpose_category_invalid_value",
            {"credentials": {"db_main": {"purpose_category": None}}},
        )

    def test_missing_purpose_description_refuses(self) -> None:
        _assert_refuses_with(
            "credentials_purpose_description_invalid_shape",
            {"credentials": {"db_main": {"purpose_description": None}}},
        )

    def test_non_dict_block_emits_shape_refusal_and_all_5_missing_fields(self) -> None:
        # T14b round-2 reviewer fix: non-dict block (e.g.,
        # ``{"db_main": "not-a-dict"}``) used to slip through with
        # zero refusals because ``_validate_credential_block`` had
        # an early ``if not isinstance(decl, dict): return findings``
        # short-circuit. Once T15 wires this validator into
        # ``cli/validate.py``, that would admit malformed signed
        # manifests with scalar credential declarations. The fix
        # emits ONE ``credentials_unknown_field`` refusal carrying
        # ``failure_mode="non_table"`` to flag the block-shape
        # issue, then continues as if the block were empty so the
        # 5 required-field-missing refusals also fire.
        manifest: dict[str, Any] = {
            "pack": {"name": "test-pack", "version": "0.1.0"},
            "runtime": {"expected_workload_gid": 1000},
            "risk_tier": {"tier": "internal_write"},
            "credentials": {"db_main": "not-a-dict"},
        }
        findings = validate(manifest, Path("."))
        refusal_reasons = {f.reason for f in findings if f.severity == "refusal"}
        # Block-shape signal fires
        assert "credentials_unknown_field" in refusal_reasons
        # All 5 required-field-missing signals also fire
        assert "credentials_vault_path_empty" in refusal_reasons
        assert "credentials_expected_fields_empty" in refusal_reasons
        assert "credentials_ttl_s_invalid" in refusal_reasons
        assert "credentials_purpose_category_invalid_value" in refusal_reasons
        assert "credentials_purpose_description_invalid_shape" in refusal_reasons
        # The block-shape refusal carries the failure_mode discriminator
        non_table_findings = [
            f
            for f in findings
            if f.reason == "credentials_unknown_field"
            and f.payload.get("failure_mode") == "non_table"
        ]
        assert len(non_table_findings) == 1, (
            "exactly one credentials_unknown_field refusal with "
            "failure_mode='non_table' must fire on a non-dict block"
        )
        assert non_table_findings[0].payload.get("block_type") == "str", (
            "the non_table refusal must carry the actual block type"
        )

    def test_non_dict_block_with_list_value_fires_same_shape_refusal(self) -> None:
        # Defensive coverage of a second non-dict shape (list value);
        # ensures the non-dict guard is type-generic, not string-only.
        manifest: dict[str, Any] = {
            "pack": {"name": "test-pack", "version": "0.1.0"},
            "runtime": {"expected_workload_gid": 1000},
            "risk_tier": {"tier": "internal_write"},
            "credentials": {"db_main": ["not", "a", "dict"]},
        }
        findings = validate(manifest, Path("."))
        non_table_findings = [
            f
            for f in findings
            if f.reason == "credentials_unknown_field"
            and f.payload.get("failure_mode") == "non_table"
        ]
        assert len(non_table_findings) == 1
        assert non_table_findings[0].payload.get("block_type") == "list"


# ---------------------------------------------------------------------------
# Risk-tier cross-validation (per spec §5.1 + Sprint 10.5 ADR-014 amendment)
# ---------------------------------------------------------------------------


class TestRiskTierCrossValidator:
    """Per spec §5.1: pre-Sprint-13.5, credential-bearing packs may
    not declare any of the 6 high-risk tiers.

    Refusal is the credentials-validator-owned counterpart to the
    Rego-bundle refusal at ``scheduler.rego`` /
    ``sandbox.rego``::``*_high_risk_tier_refused_pre_13_5`` per ADR-014
    Sprint 10.5 amendment. Build-time refusal catches the same
    contract violation BEFORE the pack ships.
    """

    @pytest.mark.parametrize(
        "tier",
        [
            "customer_data_read",
            "customer_data_write",
            "payment_action",
            "regulator_communication",
            "cross_tenant",
            "high_risk_custom",
        ],
    )
    def test_high_risk_tier_with_credentials_refuses_pre_13_5(self, tier: str) -> None:
        _assert_refuses_with(
            "credentials_risk_tier_not_permitted_pre_13_5",
            {"risk_tier": {"tier": tier}},
        )

    def test_missing_risk_tier_suppresses_credentials_risk_check(self) -> None:
        # Per user guidance: when the upstream risk-tier validator's
        # missing-risk-tier finding fires, the credentials validator
        # MUST suppress its own risk-tier check (which would otherwise
        # produce a misleading false positive against the absent tier).
        manifest = _deep_merge(_BASELINE, {})
        del manifest["risk_tier"]
        findings = validate(manifest, Path("."))
        credentials_risk_reasons = {
            f.reason for f in findings if f.reason == "credentials_risk_tier_not_permitted_pre_13_5"
        }
        assert credentials_risk_reasons == set(), (
            "credentials validator must suppress its risk-tier check when "
            "the upstream [risk_tier] block is absent"
        )


# ---------------------------------------------------------------------------
# expected_workload_gid cross-validation
# ---------------------------------------------------------------------------


class TestExpectedWorkloadGid:
    def test_credential_pack_without_gid_refuses(self) -> None:
        # [credentials.*] present + [runtime].expected_workload_gid absent
        manifest = _deep_merge(_BASELINE, {})
        del manifest["runtime"]
        findings = validate(manifest, Path("."))
        reasons = {f.reason for f in findings if f.severity == "refusal"}
        assert "runtime_expected_workload_gid_required_for_credential_pack" in reasons

    def test_gid_zero_refuses(self) -> None:
        _assert_refuses_with(
            "runtime_expected_workload_gid_invalid_range",
            {"runtime": {"expected_workload_gid": 0}},
        )

    def test_gid_above_65535_refuses(self) -> None:
        _assert_refuses_with(
            "runtime_expected_workload_gid_invalid_range",
            {"runtime": {"expected_workload_gid": 65536}},
        )

    def test_gid_negative_refuses(self) -> None:
        _assert_refuses_with(
            "runtime_expected_workload_gid_invalid_range",
            {"runtime": {"expected_workload_gid": -1}},
        )

    def test_gid_without_credentials_refuses(self) -> None:
        # Per spec §5.1 strict-block tie-in: expected_workload_gid
        # is only valid when at least one [credentials.*] block
        # exists. Manifest with runtime block but no credentials
        # block → refuse.
        manifest = _deep_merge(_BASELINE, {})
        del manifest["credentials"]
        findings = validate(manifest, Path("."))
        reasons = {f.reason for f in findings if f.severity == "refusal"}
        assert "runtime_expected_workload_gid_without_credentials" in reasons


# ---------------------------------------------------------------------------
# Cross-validator non-emission (per user guidance: "Direct validator
# should not emit unrelated orchestrator/risk-tier findings")
# ---------------------------------------------------------------------------


class TestValidatorScopeIsolation:
    def test_validator_does_not_emit_orchestrator_reasons(self) -> None:
        # T6 orchestrator-owned reasons (manifest_not_found / unparseable /
        # missing_pack_id / missing_required_block) MUST NOT come from
        # this validator regardless of input shape.
        findings = validate(_BASELINE, Path("."))
        orchestrator_reasons = {f.reason for f in findings if f.reason.startswith("manifest_")}
        assert orchestrator_reasons == set()

    def test_validator_does_not_emit_risk_tier_validator_reasons(self) -> None:
        # T11 risk-tier-validator-owned reason (risk_tier_inconsistent_with_data_classes)
        # MUST NOT come from this validator either — credentials validator
        # owns ONLY the credentials-specific refusals.
        findings = validate(_BASELINE, Path("."))
        risk_tier_reasons = {
            f.reason for f in findings if f.reason == "risk_tier_inconsistent_with_data_classes"
        }
        assert risk_tier_reasons == set()
