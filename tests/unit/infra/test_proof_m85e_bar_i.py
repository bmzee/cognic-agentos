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
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_PROOF = _REPO / "infra" / "proof-m85c"
_RUNNER = _PROOF / "run-proof-m85c.sh"
_STAGER = _PROOF / "stage-packs.sh"
_KERNEL_SEED = _PROOF / "kernel-seed.sql"
_ORACLE_PACK = _PROOF / "manifests" / "oracle-pack.yaml"
_HR_LEAVE_PACK = _PROOF / "manifests" / "hr-leave-pack.yaml"
_AGENTOS_PATCH = _PROOF / "agentos-sandbox-patch.yaml"
_AGENTOS_IMAGE = _PROOF / "Dockerfile.agentos-proof"
_HR_LEAVE_IMAGE = _PROOF / "Dockerfile.hr-leave-pack"

_AH_SHA256 = "7fbdc030da19391b8e836bd00f9dacb2d6cac61e9195e229e342223222017f7e"

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
    """Both unreleased agents are complete and fail before any network access."""
    stage = _STAGER.read_text(encoding="utf-8")
    runner = _RUNNER.read_text(encoding="utf-8")

    for prefix in ("AGENT", "ABLATION_AGENT"):
        assert _shell_value(stage, f"{prefix}_TAG") == "v0.2.0"
        assert _shell_value(stage, f"{prefix}_VERSION") == "0.2.0"
        assert _shell_value(stage, f"{prefix}_WHEEL").endswith("-0.2.0-py3-none-any.whl")
        for suffix in (
            "WHEEL_SHA256",
            "PUB_SHA256",
            "CARD_PUB_SHA256",
            "CARD_JWS_SHA256",
        ):
            assert _shell_value(stage, f"{prefix}_{suffix}") == "FILL_AT_RELEASE"
    guard = stage.index("# The agent releases do not exist at authoring time.")
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
    assert len(embedded) == 8
    for payload in embedded:
        ast.parse(payload)
    assert "KHI-01|237150000.00" in bar
    assert "KHI-01|2026-06|25400000.00|6100000.00|12800000.00|18700000.00" in bar
    assert 'I1_PNL_ROWS" = "2"' in bar
    assert "prior-context digest does not re-hash" in bar
    assert "golden_all_correct" in bar
    assert "approval.executed" in bar
    assert "agent.run.dispatch" in bar
    assert "ORA-01031" in bar
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


def test_hold_for_operator_is_opt_in_and_after_the_write_leg() -> None:
    runner = _RUNNER.read_text(encoding="utf-8")
    bar_i = runner.index("# ============================ BAR I")
    write_leg = runner.index("BAR I.4", bar_i)
    hold = runner.index("HOLD_FOR_OPERATOR", write_leg)

    assert "${HOLD_FOR_OPERATOR:-0}" in runner[write_leg:]
    assert "read -r" in runner[hold:]
    assert "kubectl" in runner[hold:]
    assert "sqlplus" in runner[hold:]
