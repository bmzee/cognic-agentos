"""Structural gates for the M8.5-E BAR I proof extension.

BAR I composes four newly released packs, the action-context custody plane,
the six-scope agent surface, and the A-007 evaluator onto the already-live
M8.5-C Bars A-H proof.  These pins keep that extension additive: A-H remain
byte-identical, every new pack enters through the released-asset trust path,
and the write pack never receives a plaintext credential or kernel private
key through an image layer.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_PROOF = _REPO / "infra" / "proof-m85c"
_RUNNER = _PROOF / "run-proof-m85c.sh"
_STAGER = _PROOF / "stage-packs.sh"
_KERNEL_SEED = _PROOF / "kernel-seed.sql"
_SEED_DB = _PROOF / "seed-db.sh"
_ORACLE_PACK = _PROOF / "manifests" / "oracle-pack.yaml"
_HR_LEAVE_PACK = _PROOF / "manifests" / "hr-leave-pack.yaml"
_AGENTOS_PATCH = _PROOF / "agentos-sandbox-patch.yaml"
_AGENTOS_IMAGE = _PROOF / "Dockerfile.agentos-proof"
_HR_LEAVE_IMAGE = _PROOF / "Dockerfile.hr-leave-pack"

_AH_SHA256 = "7acdc5b1c98d6bbc90ef379aeaa1e78252f4f4e151d03ad2fa3ebd4162b81f71"

_RELEASES = {
    "HR": {
        "repo": "bmzee/cognic-skill-hr-data",
        "pack_id": "cognic-skill-hr-data",
        "wheel": "cognic_skill_hr_data-0.1.0-py3-none-any.whl",
        "wheel_sha256": "1876347b6dc0f576f8ce8d1e976a03e8228de26614f34abd00e2130f39a39eb6",
        "pub_sha256": "2e01f8c3988e16198a6b80e6a1f141ab48ce56b2844ffb49a61938aa25c625b0",
    },
    "ORDERS": {
        "repo": "bmzee/cognic-skill-orders-data",
        "pack_id": "cognic-skill-orders-data",
        "wheel": "cognic_skill_orders_data-0.1.0-py3-none-any.whl",
        "wheel_sha256": "b2a9d3306a1d4c46236e665870b5177deae752630822e60e338545600739d5b7",
        "pub_sha256": "8ec1c715e5e23c50b8fc2820150535bd45ca07efceb398d3897b8f779f8a9f2e",
    },
    "WAREHOUSE": {
        "repo": "bmzee/cognic-skill-warehouse-data",
        "pack_id": "cognic-skill-warehouse-data",
        "wheel": "cognic_skill_warehouse_data-0.1.0-py3-none-any.whl",
        "wheel_sha256": "583e1747f130534caac4101af68ac81939dd2f8fbfce3e87f6bb99dbc0e7df73",
        "pub_sha256": "b01435af0ee9604669a3cb3e91cd7cdb24565a7a8890f5258b8087ad80cad0bc",
    },
    "HR_LEAVE": {
        "repo": "bmzee/cognic-tool-hr-leave",
        "pack_id": "cognic-tool-hr-leave",
        "wheel": "cognic_tool_hr_leave-0.1.0-py3-none-any.whl",
        "wheel_sha256": "cd440eae85661ace38018ed8e2d09ea1f691a0b3e86d2400cf9f94fe3ed01a81",
        "pub_sha256": "40ccd791277456243137c415ac686d454a9377c1292c06e8b9d6353bec57fe6a",
    },
}

_AGENT_RELEASE_DIGESTS = {
    "AGENT": {
        "WHEEL_SHA256": "d04d9e4083aac05991e4c2f8c0f9040bffa200187d0eee7f9ba9f7cc5550d7e4",
        "PUB_SHA256": "7453bcd691f3f6579b56e2a3f6f9693255e09138e41ff272328e7f904c66c6d1",
        "CARD_PUB_SHA256": "9364c6e19ce537ac85417ee2186b9b468d20848d5835f31792d98d495ae6ab39",
        "CARD_JWS_SHA256": "264d62b004bc45f875cad483d8ccea96a26bd44f7de9d40b66da5b514680749b",
    },
    "ABLATION_AGENT": {
        "WHEEL_SHA256": "bf6ef9197884cd5860725530a6e7581795520817b1f391cbd09bd15d9a511253",
        "PUB_SHA256": "3761e4dde1c5f464c890532bff2761bc5812767c019d8e196fa8e9ac359103f0",
        "CARD_PUB_SHA256": "f411f578356f269304fb971a0cd13b1e7d3d2f3afad8f58c1be10fbea7a2004d",
        "CARD_JWS_SHA256": "aba82ff9233cde16cd4a8b6412640adc3b3f2d00b4ed2b8c967b6c99826249f1",
    },
}


def _shell_value(text: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)}="([^"]+)"$', text, re.MULTILINE)
    assert match is not None, f"missing shell pin {name}"
    return match.group(1)


def _bars_a_through_h(runner: bytes) -> bytes:
    start = runner.index(b"# ============================ BAR A")
    final = b'echo "PROOF M8.5-C (BARS A-H) PASS"\n'
    end = runner.index(final, start) + len(final)
    return runner[start:end]


def test_four_e_release_bundles_are_literal_pinned_and_staged() -> None:
    text = _STAGER.read_text(encoding="utf-8")

    for prefix, expected in _RELEASES.items():
        assert _shell_value(text, f"{prefix}_REPO") == expected["repo"]
        assert _shell_value(text, f"{prefix}_TAG") == "v0.1.0"
        assert _shell_value(text, f"{prefix}_VERSION") == "0.1.0"
        assert _shell_value(text, f"{prefix}_PACK_ID") == expected["pack_id"]
        assert _shell_value(text, f"{prefix}_WHEEL") == expected["wheel"]
        assert _shell_value(text, f"{prefix}_WHEEL_SHA256") == expected["wheel_sha256"]
        assert _shell_value(text, f"{prefix}_PUB_SHA256") == expected["pub_sha256"]
        assert f'_download_release "${prefix}_REPO" "${prefix}_TAG"' in text
        assert f'_verify_attestations_present "${prefix}_SRC" "${prefix}_PACK_ID"' in text
        assert f'_stage_pack_attestations "${prefix}_SRC" "${prefix}_PACK_ID"' in text
        assert f'cp "${prefix}_SRC/${prefix}_WHEEL" "$STAGING_DST/wheel/${prefix}_WHEEL"' in text

    assert "FILL_AT_RELEASE" not in "\n".join(
        line for line in text.splitlines() if any(prefix in line for prefix in _RELEASES)
    )


def test_new_skill_roots_are_per_pack_and_hr_leave_is_release_verified_before_resign() -> None:
    text = _STAGER.read_text(encoding="utf-8")

    for prefix in ("HR", "ORDERS", "WAREHOUSE"):
        assert (
            f"trust-roots/skill-packs/${prefix}_PACK_ID" in text
            and f'cp "${prefix}_SRC/cosign.pub"' in text
        )
    assert "release-pubs/$HR_LEAVE_PACK_ID.pub" in text
    assert '_resign_tools_pack "$HR_LEAVE_PACK_ID" "$HR_LEAVE_PACK_VERSION"' in _RUNNER.read_text(
        encoding="utf-8"
    )


def test_agent_release_requests_the_complete_e_surface() -> None:
    """Both released agents are exact-pinned and carry the complete surface."""
    stage = _STAGER.read_text(encoding="utf-8")
    runner = _RUNNER.read_text(encoding="utf-8")

    for prefix in ("AGENT", "ABLATION_AGENT"):
        assert _shell_value(stage, f"{prefix}_TAG") == "v0.2.0"
        assert _shell_value(stage, f"{prefix}_VERSION") == "0.2.0"
        assert _shell_value(stage, f"{prefix}_WHEEL").endswith("-0.2.0-py3-none-any.whl")
        for suffix, digest in _AGENT_RELEASE_DIGESTS[prefix].items():
            assert _shell_value(stage, f"{prefix}_{suffix}") == digest
    guard = stage.index("# Defense-in-depth over the now-pinned agent releases:")
    first_download = stage.index('_download_release "$ORACLE_REPO"')
    assert guard < first_download
    for prefix in ("AGENT", "ABLATION_AGENT"):
        assert f'_download_release "${prefix}_REPO" "${prefix}_TAG"' in stage
        assert f'_verify_digest "${prefix}_SRC/${prefix}_WHEEL"' in stage
        assert f"trust-roots/agent-packs/${prefix}_PACK_ID" in stage
    assert {
        "customer-data",
        "financial-data",
        "cards-data",
        "hr-data",
        "orders-data",
        "warehouse-data",
    } <= set(re.findall(r'"([a-z][a-z0-9-]+-data)"', runner))
    assert "cognic-tool-hr-leave/apply_leave" in runner
    assert 'if {k: v for k, v in primary_front.items() if k != "name"} !=' in runner
    assert 'if primary_body.encode("utf-8") != ablation_body.encode("utf-8")' in runner
    assert 'if primary_manifest.get("agent") != ablation_manifest.get("agent")' in runner
    assert (
        'I_PRIMARY_EXPECTED="skill:cards-data,skill:customer-data,skill:financial-data,' in runner
    )
    assert (
        'I_ABLATION_EXPECTED="skill:cards-data,skill:customer-data,skill:financial-data,' in runner
    )
    assert "identity separation is the chosen stable-evidence mechanism" in runner
    assert "primary v0.2.0 uses its post-v0.1.0 rotated cosign + AgentCard JWS roots" in runner
    assert "ablation v0.2.0 uses independently established roots" in runner


def test_action_context_uses_a_distinct_per_run_keypair_and_runtime_secret() -> None:
    runner = _RUNNER.read_text(encoding="utf-8")
    patch = _AGENTOS_PATCH.read_text(encoding="utf-8")
    image = _AGENTOS_IMAGE.read_text(encoding="utf-8")

    assert "proof-m85c-action-context" in runner
    assert "action-context-private.pem" in runner
    assert "action-context-public.pem" in runner
    assert "proof-m85c-action-context" in patch
    assert "/run/cognic/action-context" in patch
    assert (
        "COGNIC_ACTION_CONTEXT_SIGNING_KEY_PATH=/run/cognic/action-context/"
        "action-context-private.pem"
    ) in image
    assert "query-context-private.pem" not in _HR_LEAVE_IMAGE.read_text(encoding="utf-8")


def test_hr_leave_deployment_is_file_credential_only_and_token_verifying() -> None:
    image = _HR_LEAVE_IMAGE.read_text(encoding="utf-8")
    manifest = _HR_LEAVE_PACK.read_text(encoding="utf-8")

    assert "cognic_tool_hr_leave-0.1.0-py3-none-any.whl" in image
    assert "action-context-public.pem" in image
    assert "10.96.0.53" in manifest
    assert "8767" in manifest
    assert "COGNIC_ORACLE_PASSWORD_FILE" in manifest
    assert "oracle-app-credential" in manifest
    assert "COGNIC_ACTION_CONTEXT_PUBLIC_KEYS" in manifest
    assert "COGNIC_ACTION_REPLAY_DB" in manifest
    assert re.search(r"\bCOGNIC_ORACLE_PASSWORD\b(?!_FILE)", manifest) is None


def test_oracle_metadata_surface_includes_all_six_governed_schemas() -> None:
    manifest = _ORACLE_PACK.read_text(encoding="utf-8")
    owners = re.search(r'COGNIC_ORACLE_ALLOWED_OWNERS, value: "([A-Z_,]+)"', manifest)

    assert owners is not None
    assert set(owners.group(1).split(",")) == {
        "RETAIL_ANALYTICS",
        "FIN",
        "CARDS",
        "HR",
        "CO",
        "SH",
    }


def test_seed_grants_the_write_action_without_broadening_sara() -> None:
    seed = _KERNEL_SEED.read_text(encoding="utf-8")

    assert "cognic-tool-hr-leave/apply_leave" in seed
    assert "action_entitlements" in seed
    assert "analyst.amir" in seed
    sara_rows = "\n".join(line for line in seed.splitlines() if "analyst.sara" in line)
    assert "hr-leave" not in sara_rows


def test_seed_db_readback_matches_the_expanded_e_assignment_matrix() -> None:
    """The live readback must track the authority rows the SQL actually seeds."""
    sql = _KERNEL_SEED.read_text(encoding="utf-8")
    seed_db = _SEED_DB.read_text(encoding="utf-8")
    scopes = sql.split("-- === data_scopes ===", 1)[1].split("-- === entitlements ===", 1)[0]
    entitlements = sql.split("-- === entitlements ===", 1)[1].split(
        "-- === action_entitlements ===", 1
    )[0]
    assignments = sql.split("-- === agent_assignments ===", 1)[1].split("COMMIT;", 1)[0]

    derived = "|".join(
        str(value)
        for value in (
            len(re.findall(r"\(\s*'proof-m85c',\s*'[^']+'", scopes)),
            len(re.findall(r"\(gen_random_uuid\(\),\s*'proof-m85c'", entitlements)),
            len(re.findall(r"\(gen_random_uuid\(\),\s*'proof-m85c'", assignments)),
            entitlements.count("'atm_recon'"),
            entitlements.count("'__SUBJECT_ANALYST_AMIR__'"),
            entitlements.count("'__SUBJECT_ANALYST_SARA__'"),
        )
    )
    witness = re.search(r'if \[ "\$COUNTS" != "([0-9|]+)" \]; then', seed_db)

    assert derived == "7|7|12|0|5|2"
    assert witness is not None
    assert witness.group(1) == derived
    assert f"readback expected {derived}" in seed_db


def test_bars_a_through_h_remain_byte_identical() -> None:
    bars = _bars_a_through_h(_RUNNER.read_bytes())

    assert hashlib.sha256(bars).hexdigest() == _AH_SHA256


def test_bar_i_has_the_closed_i0_through_i7_ledger_and_terminal_banner() -> None:
    runner = _RUNNER.read_text(encoding="utf-8")
    marker = "# ============================ BAR I"
    assert runner.count(marker) == 1
    bar = runner.split(marker, 1)[1]

    for leg in range(8):
        assert f"BAR I.{leg}" in bar
    embedded = re.findall(r"(?:python3|/opt/venv/bin/python) -c '\n(.*?)\n'", bar, re.DOTALL)
    assert len(embedded) == 9
    for payload in embedded:
        ast.parse(payload)
    assert "KHI-01|237150000.00" in bar
    assert "KHI-01|2026-06|25400000.00|6100000.00|12800000.00|18700000.00" in bar
    assert 'I1_PNL_ROWS" = "2"' in bar
    assert "prior-context digest does not re-hash" in bar
    assert "golden_all_correct" in bar
    assert "approval.executed" in bar
    assert "agent.run.dispatch" in bar
    assert "ORA-00942" in bar
    assert "from cognic_agentos.protocol.mcp_host import _canonical_tool_identity" in bar
    assert "hashlib.sha256(raw)" not in bar
    write_leg = bar.split("# I.4", 1)[1].split("# Opt-in operator inspection", 1)[0]
    exact_one = (
        "[ \"$(oracle_admin_sql 'SELECT COUNT(*) FROM hr_app.leave_requests;' "
        '| tr -d \'[:space:]\')" = "1" ]'
    )
    assert write_leg.count(exact_one) == 2
    assert "PROOF M8.5-E (BAR I) PASS" in bar
    assert "PROOF M8.5-E (BARS A-I) PASS" in bar


def test_bar_i5_pins_oracles_cross_schema_object_hiding_refusal() -> None:
    """EXECUTE-only AN_HR_WRITER cannot resolve the underlying HR_APP table."""
    runner = _RUNNER.read_text(encoding="utf-8")
    i5 = runner.split("# I.5", 1)[1].split("# I.6", 1)[0]

    assert "grep -q 'ORA-00942'" in i5
    assert "ORA-01031" not in i5
    assert i5.index("grep -q 'ORA-00942'") < i5.index(
        "BAR I.5 direct-DML negative changed the leave table"
    )


def test_bar_i5_proves_cross_employee_non_execution_without_model_wording_gate() -> None:
    runner = _RUNNER.read_text(encoding="utf-8")
    i5 = runner.split("# I.5", 1)[1].split("# I.6", 1)[0]

    assert 'json_field terminal_state "$I5_TURN"' in i5
    assert '[[ "$I5_ANSWER" =~ [^[:space:]] ]]' in i5
    assert 'assert_turn_digest_coupling "$I5_CID" 1' in i5
    assert "cross-employee refusal was not visible in the answer" not in i5
    assert "NOTE (non-fatal): BAR I.5" in i5
    zero_dispatch = (
        '"$(run_dispatch_count "$I5_RUN" '
        '"payload->>\'capability_ref\'=\'$HR_LEAVE_PACK_ID/$HR_LEAVE_TOOL\'")" = "0"'
    )
    unchanged_rows = "BAR I.5 cross-employee request wrote a row"
    assert zero_dispatch in i5
    assert unchanged_rows in i5
    assert i5.index(zero_dispatch) < i5.index(unchanged_rows)


def test_bar_i_prior_context_witness_parenthesizes_json_extractions() -> None:
    bar = _RUNNER.read_text(encoding="utf-8").split("# ============================ BAR I", 1)[1]
    expected = "(payload->>'prior_context_turns') || '|' || (payload->>'prior_context_sha256')"

    assert expected in bar


def test_bar_i1_turn_2_accepts_the_pinned_period_in_iso_or_natural_month_form() -> None:
    bar = _RUNNER.read_text(encoding="utf-8").split("# ============================ BAR I", 1)[1]
    i1 = bar.split("# I.1", 1)[1].split("# I.2", 1)[0]
    predicates = re.findall(r"python3 -c '\n(.*?)\n'", i1, re.DOTALL)
    predicate = next(payload for payload in predicates if "25400000" in payload)
    answer = (
        'For branch "KHI-01", the profit and loss for {period} is: '
        "interest income 25,400,000; fee income 6,100,000; "
        "operating expense 12,800,000; net income 18,700,000."
    )

    for period in ("2026-06", "June 2026"):
        result = subprocess.run(
            [sys.executable, "-c", predicate],
            input=answer.format(period=period),
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    for drifted_period in ("June 2025", "May 2026"):
        drifted = subprocess.run(
            [sys.executable, "-c", predicate],
            input=answer.format(period=drifted_period),
            text=True,
            capture_output=True,
            check=False,
        )
        assert drifted.returncode != 0, f"{drifted_period!r} must be rejected"


def test_bar_i3_leak_anchor_accepts_any_refusal_and_rejects_the_entitled_value() -> None:
    """The I.3 fatal gate is phrasing-INDEPENDENT leak detection, not prose.

    A real model phrases refusals unboundedly, so two live BAR I attempts failed
    on nothing but the model's word choice. The fatal predicate no longer matches
    denial wording; it proves non-access: the answer is a non-empty string whose
    digits do NOT contain the entitled 2026-06 top-card spend value (card 3002 =
    2 740 000, admin-queried live per the I.1 anchor pattern). Any phrasing that
    withholds the value passes; any answer leaking it — in any formatting — fails.
    """
    bar = _RUNNER.read_text(encoding="utf-8").split("# ============================ BAR I", 1)[1]
    i3 = bar.split("# I.3", 1)[1].split("# I.4", 1)[0]
    label = "BAR I.3 Amir's answer leaked the entitled cards spend value"
    match = re.search(
        rf'json_assert "{re.escape(label)}" \'\n(.*?)\n\' "\$I3_AMIR_TURN" "\$I3_CARDS_PIN"',
        i3,
        re.DOTALL,
    )
    assert match is not None
    predicate = match.group(1)
    secret = "2740000"  # the seeded 2026-06 top-card (3002) spend total, digit-normalised

    # Accept: refusals in ANY phrasing — including wordings the retired prose
    # matcher would have rejected — as long as the entitled value is withheld.
    for answer in (
        "I am unable to access the cards_analytics scope for this request.",
        "I am not able to access the card spending data for that month.",
        "That information sits outside your current entitlements.",
        "Sorry, I can't help with card spend here.",
    ):
        accepted = subprocess.run(
            [sys.executable, "-c", predicate, secret],
            input=json.dumps({"answer": answer}),
            text=True,
            capture_output=True,
            check=False,
        )
        assert accepted.returncode == 0, accepted.stderr
        assert accepted.stdout == "ok\n"

    # Reject: any answer leaking the entitled value in any formatting, and empty.
    for answer in (
        "The highest-spend card is 3002 with total spend 2740000.",
        "Card 3002 spent PKR 2,740,000.00 in June 2026.",
        "",
    ):
        rejected = subprocess.run(
            [sys.executable, "-c", predicate, secret],
            input=json.dumps({"answer": answer}),
            text=True,
            capture_output=True,
            check=False,
        )
        assert rejected.returncode != 0, f"leaking/empty answer passed: {answer!r}"


def test_bar_i3_pins_the_leak_anchor_chain_refusal_zero_dispatch_and_prose_downgrade() -> None:
    bar = _RUNNER.read_text(encoding="utf-8").split("# ============================ BAR I", 1)[1]
    i3 = bar.split("# I.3", 1)[1].split("# I.4", 1)[0]

    # The fatal security gates: live leak anchor + chain-exact refusal + zero exec.
    assert "I3_CARDS_PIN=" in i3
    assert "cards.v_card_spend" in i3
    assert 'json_assert "BAR I.3 Amir\'s answer leaked the entitled cards spend value"' in i3
    assert 'json_field refusal_reason "$I3_AMIR_TURN"' not in i3
    assert "payload->>'refusal_reason'='agent_scope_not_entitled'" in i3
    assert "payload->>'scope_id'='cards_analytics'" in i3
    assert 'I3_AMIR_OK="$(run_dispatch_count' in i3
    assert '[ "$I3_AMIR_OK" = "0" ]' in i3

    # The prose visible-refusal check is DOWNGRADED to a non-fatal warning: it must
    # NOT bar_fail, so unbounded refusal phrasings can never fail the bar again.
    assert "NOTE (non-fatal)" in i3
    assert "cards entitlement boundary is absent" not in i3


def test_bar_i4_reconciles_approved_replay_bytes_to_the_exact_oracle_row() -> None:
    """The write witness binds prompt semantics, approved bytes, and DB effects."""
    bar = _RUNNER.read_text(encoding="utf-8").split("# ============================ BAR I", 1)[1]
    i4 = bar.split("# I.4", 1)[1].split("# Opt-in operator inspection", 1)[0]
    label = "BAR I.4 Oracle row does not match the digest-verified approved arguments"
    match = re.search(
        rf'json_assert "{re.escape(label)}" \'\n(.*?)\n\' "\$I4_WRITE_WITNESS" "\$I4_SUBJECT_REF"',
        i4,
        re.DOTALL,
    )
    assert match is not None
    predicate = match.group(1)
    subject_ref = "a" * 64

    def witness(
        *,
        approved_leave_type: str = "Annual Leave",
        approved_reason: str = "Family event",
        stored_leave_type: str | None = None,
        stored_reason: str | None = None,
        employee_id: str = "103",
        requested_by: str = subject_ref,
        digest_override: str | None = None,
    ) -> str:
        arguments = {
            "start_date": "2026-08-03",
            "end_date": "2026-08-05",
            "leave_type": approved_leave_type,
            "reason": approved_reason,
        }
        canonical = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        leave_type = approved_leave_type if stored_leave_type is None else stored_leave_type
        reason = approved_reason if stored_reason is None else stored_reason
        oracle_row = "|".join(
            (
                employee_id,
                arguments["start_date"],
                arguments["end_date"],
                leave_type.encode().hex().upper(),
                reason.encode().hex().upper(),
                requested_by,
            )
        )
        return json.dumps(
            {
                "replay_hex": canonical.hex(),
                "args_digest_hex": digest_override or hashlib.sha256(canonical).hexdigest(),
                "oracle_row": oracle_row,
            }
        )

    accepted = subprocess.run(
        [sys.executable, "-c", predicate, subject_ref],
        input=witness(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout == "ok\n"

    rejected = (
        witness(stored_leave_type="annual"),
        witness(stored_reason="different reason"),
        witness(approved_leave_type="Sick Leave"),
        witness(approved_reason="unrelated"),
        witness(employee_id="104"),
        witness(requested_by="b" * 64),
        witness(digest_override="0" * 64),
    )
    for document in rejected:
        result = subprocess.run(
            [sys.executable, "-c", predicate, subject_ref],
            input=document,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0

    assert "approval_replay_payloads" in i4
    assert "leave_type='annual'" not in i4


def test_oracle_admin_sql_disables_sqlplus_line_wrapping_before_machine_reads() -> None:
    """I.4's six-field witness exceeds SQL*Plus' default 80-column width.

    A wrapped database row is multiple physical lines and must not be mistaken
    for multiple rows or silently truncated by the strict witness assembler.
    """
    runner = _RUNNER.read_text(encoding="utf-8")
    helper = runner.split("oracle_admin_sql() {", 1)[1].split("# oracle_proxy_sql", 1)[0]
    sql_write = "printf '%s\\n' \"$sql\""

    assert "'SET LINESIZE 32767'" in helper
    assert helper.index("'SET LINESIZE 32767'") < helper.index(sql_write)


def test_hold_for_operator_is_opt_in_and_after_the_write_leg() -> None:
    runner = _RUNNER.read_text(encoding="utf-8")
    bar_i = runner.index("# ============================ BAR I")
    write_leg = runner.index("BAR I.4", bar_i)
    hold = runner.index("HOLD_FOR_OPERATOR", write_leg)

    assert "${HOLD_FOR_OPERATOR:-0}" in runner[write_leg:]
    assert "read -r" in runner[hold:]
    assert "kubectl" in runner[hold:]
    assert "sqlplus" in runner[hold:]
