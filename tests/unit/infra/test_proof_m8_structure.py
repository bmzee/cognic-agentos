"""Structural pins for the ``infra/proof-m8/`` scaffolding + seeds (M8 Task C1).

Mirrors ``tests/unit/infra/test_proof_m6_structure.py`` for the M8 governed-
agent-loop proof tree. C1 ships the scaffolding + seeds ONLY (the six-bar
runner ``run-proof-m8.sh`` is Task C2 and extends this suite); the pins here:

* the SIX Part-B releases staged + sha256-pinned fail-closed (maintainer-
  locked C1 pin table) PLUS the reused M5 hook release (the oracle v0.3.0
  wheel's baked manifest declares ``dlp_pre_hooks`` — without the hook pack
  every governed tool call fail-closes at the DLP gate and BAR 1 could never
  pass; same pins byte-identical to proof-m6);
* the dual-root agent shape (M8 finding #4 custody split): ``cosign.pub`` +
  ``agent-card.pub`` staged under ``agent-packs/cognic-agent-bank-analyst/``,
  with ``agent-card.jws`` + ``agent-card.json`` staged for standalone
  verification — the JWS trust root is NEVER ``cosign.pub``;
* the kernel image builds from the PINNED M8 anchor
  ``b910108ab705f9b6b8359ba61b5214d3ae8c5e66``;
* the four seeded scopes (``retail_analytics`` / ``financials`` /
  ``cards_analytics`` / ``atm_recon``), the maintainer entitlement matrix
  (amir -> retail+fin; sara -> cards+retail; atm_recon entitled to NOBODY),
  and agent assignments = EXACTLY the requested set (three skills + the
  oracle tool; atm-recon NEVER assigned — the standing BAR-2 negative);
* the governed views match the released skills' SKILL.md contracts, the
  proxy users ride ``GRANT CONNECT THROUGH``, and the per-identity grant
  matrix carries BOTH negatives (no ATM-view grant to any analyst identity;
  ``AN_ATM_RECON`` never provisioned — the BAR-4b DB backstop);
* key custody: the query-context PRIVATE key is a runtime-mount reference
  only — never tracked, never COPY'd into a layer; no bypass flags anywhere.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROOF_DIR = _REPO_ROOT / "infra" / "proof-m8"

DOCKER_AGENTOS = (_PROOF_DIR / "Dockerfile.agentos-proof").read_text()
DOCKER_ORACLE = (_PROOF_DIR / "Dockerfile.oracle-pack").read_text()
STAGE = (_PROOF_DIR / "stage-packs.sh").read_text()
KERNEL_SEED = (_PROOF_DIR / "kernel-seed.sql").read_text()
ORACLE_SEED = (_PROOF_DIR / "oracle-seed" / "seed_schema.sql").read_text()
README = (_PROOF_DIR / "README.md").read_text()
VALUES_RAW = (_PROOF_DIR / "proof-m8-values.yaml").read_text()
VALUES = yaml.safe_load(VALUES_RAW)

_ALL_TEXTS = {
    "Dockerfile.agentos-proof": DOCKER_AGENTOS,
    "Dockerfile.oracle-pack": DOCKER_ORACLE,
    "stage-packs.sh": STAGE,
    "kernel-seed.sql": KERNEL_SEED,
    "oracle-seed/seed_schema.sql": ORACLE_SEED,
    "README.md": README,
    "proof-m8-values.yaml": VALUES_RAW,
}


def _assert_all(text: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        assert needle in text, f"missing: {needle!r}"


# ---------------------------------------------------------------------------
# The maintainer-locked C1 release pins (the six Part-B releases). A mismatch
# in stage-packs.sh means the staging site no longer fail-closes on the
# released bytes. The hook pins are byte-identical to proof-m6 (same reused
# M5 release).
# ---------------------------------------------------------------------------

_PINS: dict[str, str] = {
    "ORACLE_WHEEL_SHA256": "a520e4374408513033d589e68cfff2011cbc129575de82147a40427ee3e4a4ed",
    "ORACLE_PUB_SHA256": "43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78",
    "CUSTOMER_WHEEL_SHA256": "253e1d83f9e2507cf65abf7993795fa42dc86bd1f60f7545ad805dd85c99d41c",
    "CUSTOMER_PUB_SHA256": "2ac85879bf0bc8bb01fac6547210c0ae1b391af789614785cd02240486dbe499",
    "FINANCIAL_WHEEL_SHA256": "15b26a81911b0704965aaf5b4287c0a26feb01a0107e89d9cbc0b420eb416567",
    "FINANCIAL_PUB_SHA256": "dc3a1f0f0477b3ceb2699d8654a01432214abe034834a394424b7b124913e34d",
    "CARDS_WHEEL_SHA256": "a4b6f4c3ad330a116be47a59eec16fcb1f1b93904d41361c8e607bcfca5f154b",
    "CARDS_PUB_SHA256": "99307c338f8922937e9bed3dcbcd014621eadc4980b8d78acc1a89fe7ff001e6",
    "ATMRECON_WHEEL_SHA256": "f53e290ad61b614ec4ba55f9c7d7e86f0e7e7b6870595492d5251092dd35c7ad",
    "ATMRECON_PUB_SHA256": "e1b0c58aa95a355bb418a5ef7b847dc7702145babd280e6db521137f46fe0c59",
    "AGENT_WHEEL_SHA256": "77be5140a11e25970b28e13be9df9d33d4cf7f16ee267d27061e09fa96bcdec9",
    "AGENT_PUB_SHA256": "532fe8e2181008be86a06c19c3552aedd901a74fd9da3f405ab8e119e783929e",
    "AGENT_CARD_PUB_SHA256": "c691d31693459a52226d7190b07dd07e1fdb21a1abdf0324a9225c7c2558d214",
    "AGENT_CARD_JWS_SHA256": "71207eaf5956d08a0b9bc1381bce75113478295c5b968c18b600dc16efb0e13a",
    # The reused M5 hook release (byte-identical to the proof-m6 pins).
    "HOOK_WHEEL_SHA256": "1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432",
    "HOOK_PUB_SHA256": "e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49",
}

_KERNEL_ANCHOR = "b910108ab705f9b6b8359ba61b5214d3ae8c5e66"

_GOVERNED_VIEWS = (
    "retail_analytics.v_customer_deposits",
    "retail_analytics.v_customer_profile",
    "fin.v_gl_balances",
    "fin.v_branch_pnl",
    "cards.v_card_accounts",
    "cards.v_card_spend",
    "cards.v_atm_settlements",
    "cards.v_atm_disputes",
)


# ---------------------------------------------------------------------------
# File set + permissions
# ---------------------------------------------------------------------------


def test_proof_dir_carries_the_c1_file_set() -> None:
    expected = {
        "Dockerfile.agentos-proof",
        "Dockerfile.oracle-pack",
        "README.md",
        "kernel-seed.sql",
        "proof-m8-values.yaml",
        "stage-packs.sh",
        "oracle-seed",
    }
    assert {p.name for p in _PROOF_DIR.iterdir()} >= expected
    assert (_PROOF_DIR / "oracle-seed" / "seed_schema.sql").is_file()


def test_stage_packs_is_executable() -> None:
    mode = (_PROOF_DIR / "stage-packs.sh").stat().st_mode
    assert mode & stat.S_IXUSR, "stage-packs.sh must be executable"


# ---------------------------------------------------------------------------
# Release pins (six Part-B releases + the reused hook dependency)
# ---------------------------------------------------------------------------


def test_stage_packs_pins_every_release_digest_verbatim() -> None:
    for var, digest in _PINS.items():
        assert f'{var}="{digest}"' in STAGE, f"stage-packs.sh missing pin {var}={digest}"


def test_stage_packs_names_the_six_part_b_releases_plus_the_hook_dependency() -> None:
    _assert_all(
        STAGE,
        (
            'ORACLE_REPO="bmzee/cognic-tool-oracle-schema"',
            'ORACLE_TAG="v0.3.0"',
            'CUSTOMER_REPO="bmzee/cognic-skill-customer-data"',
            'FINANCIAL_REPO="bmzee/cognic-skill-financial-data"',
            'CARDS_REPO="bmzee/cognic-skill-cards-data"',
            'ATMRECON_REPO="bmzee/cognic-skill-atm-recon"',
            'AGENT_REPO="bmzee/cognic-agent-bank-analyst"',
            'HOOK_REPO="bmzee/cognic-hook-schema-guard"',
        ),
    )
    # Released assets only — the stager never rebuilds a pack from source.
    assert "gh release download" in STAGE
    assert "uv build" not in STAGE


def test_stage_packs_fails_closed_on_digest_mismatch() -> None:
    _assert_all(
        STAGE,
        (
            "_verify_digest",
            "sha256 mismatch",
            "set -euo pipefail",
        ),
    )


def test_stage_packs_verifies_the_dual_root_agent_assets() -> None:
    _assert_all(
        STAGE,
        (
            '_verify_digest "$AGENT_SRC/agent-card.pub" "$AGENT_CARD_PUB_SHA256"',
            '_verify_digest "$AGENT_SRC/agent-card.jws" "$AGENT_CARD_JWS_SHA256"',
            "agent-card.json",  # staged fail-loud + stage-time digest record
            "staged-digests.sha256",
        ),
    )


# ---------------------------------------------------------------------------
# Trust-root staging layout (seven distinct signers; agent dual root)
# ---------------------------------------------------------------------------


def test_trust_root_layout_covers_all_packs_including_the_agent_dual_root() -> None:
    _assert_all(
        STAGE,
        (
            'trust-roots/_default"',
            'trust-roots/hook-packs/$HOOK_PACK_ID"',
            'trust-roots/skill-packs/$CUSTOMER_PACK_ID"',
            'trust-roots/skill-packs/$FINANCIAL_PACK_ID"',
            'trust-roots/skill-packs/$CARDS_PACK_ID"',
            'trust-roots/skill-packs/$ATMRECON_PACK_ID"',
            'trust-roots/agent-packs/$AGENT_PACK_ID"',
            "agent-packs/$AGENT_PACK_ID/agent-card.pub",
        ),
    )


def test_allowlist_admits_all_seven_packs() -> None:
    # Seven ids under _default: the six Part-B packs + the hook dependency.
    # rindex: the WRITE site (the printf), not the staging-tree comment.
    marker = STAGE[
        STAGE.rindex("plugin_allowlist.json") - 400 : STAGE.rindex("plugin_allowlist.json")
    ]
    for var in (
        "$ORACLE_PACK_ID",
        "$HOOK_PACK_ID",
        "$CUSTOMER_PACK_ID",
        "$FINANCIAL_PACK_ID",
        "$CARDS_PACK_ID",
        "$ATMRECON_PACK_ID",
        "$AGENT_PACK_ID",
    ):
        assert var in marker, f"allow-list printf missing {var}"


# ---------------------------------------------------------------------------
# Kernel image (anchor + key custody)
# ---------------------------------------------------------------------------


def test_kernel_image_builds_from_the_pinned_m8_anchor() -> None:
    assert f"ARG KERNEL_ANCHOR={_KERNEL_ANCHOR}" in DOCKER_AGENTOS


def test_kernel_image_stages_trust_roots_and_agent_cards() -> None:
    _assert_all(
        DOCKER_AGENTOS,
        (
            "COPY proof-m8-staging/trust-roots/ /opt/cognic/trust-roots/",
            "COPY proof-m8-staging/agent-cards/ /opt/cognic/agent-cards/",
            "COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots",
        ),
    )


def test_query_context_private_key_is_a_runtime_mount_never_a_layer() -> None:
    # The public half is staged; the PRIVATE key rides a runtime mount.
    assert "COPY proof-m8-staging/query-context/ /opt/cognic/query-context/" in DOCKER_AGENTOS
    assert "/run/cognic/query-context" in DOCKER_AGENTOS
    # No COPY line may reference private key material.
    for line in DOCKER_AGENTOS.splitlines():
        if line.strip().startswith("COPY"):
            assert "private" not in line.lower(), f"private key COPY'd into a layer: {line!r}"


def test_no_tracked_private_key_material_anywhere_in_the_proof_tree() -> None:
    pem_header = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
    for path in _PROOF_DIR.rglob("*"):
        if path.is_file():
            assert not pem_header.search(path.read_text(errors="ignore")), (
                f"private key material tracked in {path}"
            )


def test_oracle_pack_image_wires_the_query_context_public_keys() -> None:
    _assert_all(
        DOCKER_ORACLE,
        (
            "COGNIC_QUERY_CONTEXT_PUBLIC_KEYS",
            "cognic_tool_oracle_schema-0.3.0-py3-none-any.whl",
        ),
    )


# ---------------------------------------------------------------------------
# Oracle seed — governed views, proxy users, the grant matrix + its negatives
# ---------------------------------------------------------------------------


def test_oracle_seed_creates_every_governed_view() -> None:
    for view in _GOVERNED_VIEWS:
        assert f"CREATE VIEW {view} AS" in ORACLE_SEED, f"missing governed view {view}"


def test_oracle_seed_view_columns_match_the_skill_md_contracts() -> None:
    # Spot-pin the cards contract (the finding-#2 pack) column-for-column;
    # the sibling views carry the same inline SKILL.md cross-ref comments.
    for col in ("card_id", "customer_id", "product", "status", "open_date", "credit_limit"):
        assert col in ORACLE_SEED
    for col in ("spend_month", "merchant_category", "txn_count", "spend_amount"):
        assert col in ORACLE_SEED


def test_oracle_seed_provisions_proxy_users_with_connect_through() -> None:
    _assert_all(
        ORACLE_SEED,
        (
            "CREATE USER an_amir NO AUTHENTICATION",
            "CREATE USER an_sara NO AUTHENTICATION",
            "ALTER USER an_amir GRANT CONNECT THROUGH cognic",
            "ALTER USER an_sara GRANT CONNECT THROUGH cognic",
        ),
    )


def test_oracle_seed_grant_matrix_matches_the_entitlements() -> None:
    _assert_all(
        ORACLE_SEED,
        (
            "GRANT SELECT ON retail_analytics.v_customer_deposits TO an_amir;",
            "GRANT SELECT ON retail_analytics.v_customer_profile TO an_amir;",
            "GRANT SELECT ON fin.v_gl_balances TO an_amir;",
            "GRANT SELECT ON fin.v_branch_pnl TO an_amir;",
            "GRANT SELECT ON cards.v_card_accounts TO an_sara;",
            "GRANT SELECT ON cards.v_card_spend TO an_sara;",
            "GRANT SELECT ON retail_analytics.v_customer_deposits TO an_sara;",
            "GRANT SELECT ON retail_analytics.v_customer_profile TO an_sara;",
        ),
    )


def test_oracle_seed_negative_no_atm_grants_and_no_atm_identity() -> None:
    # BAR-4b DB backstop: the ATM views are granted to NOBODY, amir never
    # sees cards/fin-outside-his-scopes, and the atm_recon proxy identity is
    # never even provisioned.
    assert not re.search(r"GRANT\s+SELECT\s+ON\s+cards\.v_atm_\w+\s+TO", ORACLE_SEED, re.I), (
        "no analyst identity may hold a grant on the ATM views"
    )
    assert not re.search(
        r"GRANT\s+SELECT\s+ON\s+cards\.v_card_\w+\s+TO\s+an_amir", ORACLE_SEED, re.I
    )
    assert not re.search(r"CREATE\s+USER\s+an_atm_recon", ORACLE_SEED, re.I), (
        "AN_ATM_RECON must NOT be provisioned (fail-closed at the session layer)"
    )


def test_oracle_seed_has_a_deterministic_top10_fixture() -> None:
    _assert_all(ORACLE_SEED, ("top-10-depositors", "12 depositors"))


# ---------------------------------------------------------------------------
# Kernel seed — scopes, entitlements, assignments + the negatives
# ---------------------------------------------------------------------------


def test_kernel_seed_seeds_exactly_the_four_scopes() -> None:
    for scope, objects in (
        (
            "retail_analytics",
            '["RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS", "RETAIL_ANALYTICS.V_CUSTOMER_PROFILE"]',
        ),
        ("financials", '["FIN.V_GL_BALANCES", "FIN.V_BRANCH_PNL"]'),
        ("cards_analytics", '["CARDS.V_CARD_ACCOUNTS", "CARDS.V_CARD_SPEND"]'),
        ("atm_recon", '["CARDS.V_ATM_SETTLEMENTS", "CARDS.V_ATM_DISPUTES"]'),
    ):
        assert f"'{scope}'" in KERNEL_SEED, f"scope {scope} missing"
        assert objects in KERNEL_SEED, f"objects list for {scope} missing"


def test_kernel_seed_entitlement_matrix_is_the_maintainer_matrix() -> None:
    _assert_all(
        KERNEL_SEED,
        (
            "'analyst.amir', 'retail_analytics'",
            "'analyst.amir', 'financials'",
            "'analyst.sara', 'cards_analytics'",
            "'analyst.sara', 'retail_analytics'",
        ),
    )
    # The negative: atm_recon is a seeded scope but entitled to NOBODY.
    assert not re.search(r"analyst\.\w+',\s*'atm_recon'", KERNEL_SEED), (
        "no subject may be entitled to atm_recon"
    )


def test_kernel_seed_assignments_are_exactly_the_requested_set() -> None:
    _assert_all(
        KERNEL_SEED,
        (
            "'bank-analyst', 'skill', 'customer-data'",
            "'bank-analyst', 'skill', 'financial-data'",
            "'bank-analyst', 'skill', 'cards-data'",
            "'bank-analyst', 'tool', 'cognic-tool-oracle-schema/run_readonly_query'",
        ),
    )
    # The BAR-2 negative: the atm-recon skill is NEVER assigned.
    assert "'skill', 'atm-recon'" not in KERNEL_SEED
    # Exactly four assignment rows (three skills + one tool).
    assert KERNEL_SEED.count("'bank-analyst',") == 4


def test_kernel_seed_is_idempotent_and_tenant_scoped() -> None:
    _assert_all(
        KERNEL_SEED,
        (
            "'proof-m8'",
            "ON CONFLICT (tenant_id, scope_id) DO NOTHING",
            "ON CONFLICT ON CONSTRAINT uq_entitlements_tenant_subject_scope DO NOTHING",
            "ON CONFLICT ON CONSTRAINT uq_agent_assignments_tenant_agent_kind_ref DO NOTHING",
        ),
    )


# ---------------------------------------------------------------------------
# No bypass flags; README carries the six bars + custody notes
# ---------------------------------------------------------------------------


def test_no_bypass_flags_anywhere_in_the_proof_tree() -> None:
    # Comment lines may NAME the flags to document the no-bypass posture
    # (e.g. the values file's "NO bypass flags anywhere: no
    # dev_mode_skip_cosign" note); only NON-comment occurrences are
    # forbidden — an actual assignment/flag would live on a live line.
    for name, text in _ALL_TEXTS.items():
        live_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        live = "\n".join(live_lines)
        for forbidden in (
            "dev_mode_skip_cosign",
            "COGNIC_DEV_MODE_SKIP_COSIGN",
            "COGNIC_USE_LOCAL_FIXTURE",
        ):
            assert forbidden not in live, f"bypass flag {forbidden} live in {name}"


def test_values_parse_and_wire_the_cloud_alias_without_bypass() -> None:
    assert VALUES is not None
    assert "COGNIC_TIER1" in VALUES_RAW  # the cloud model alias env wiring
    assert "runtime_profile" not in VALUES_RAW or "dev" not in str(
        VALUES.get("runtime_profile", "")
    )


def test_readme_carries_all_six_bars_and_key_custody() -> None:
    _assert_all(
        README,
        (
            "BAR 1",
            "BAR 2",
            "BAR 3",
            "BAR 4",
            "BAR 4b",
            "BAR 5",
            "PROOF M8 (BAR 1) PASS",
            "custody",
        ),
    )
