"""Structural pin — the M4 operator-install end-to-end runner (Task 8)."""

from pathlib import Path

R = Path("infra/proof-m4/run-proof-m4.sh").read_text()
README = Path("infra/proof-m4/README.md").read_text()
GITIGNORE = Path(".gitignore").read_text()


def _assert_all(text: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        assert needle in text, f"missing: {needle!r}"


def test_env_gated_and_skip_clean():
    _assert_all(
        R,
        (
            'if [[ "${COGNIC_RUN_PROOF_M4:-}" != "1" ]]; then',
            "skipped: set COGNIC_RUN_PROOF_M4=1",
            "exit 0",
            'CLUSTER="${KIND_CLUSTER:-cognic-proofm4}"',
            'NS="cognic-proofm4"',
            'PROOF_DIR="infra/proof-m4"',
            'TENANT="proof-m4"',
            'PACK_ID="cognic-tool-oracle-schema"',
        ),
    )


def test_transient_build_context_copies_are_cleaned_and_ignored():
    _assert_all(
        R,
        (
            'STAGING_DST="$PROOF_DIR/proof-m4-staging"',
            'PROOF_APP_DST="$PROOF_DIR/proof_m4"',
            'rm -rf "$STAGING_DST" "$PROOF_APP_DST" "$PROOF_DIR/_local_as.py"',
        ),
    )
    _assert_all(
        GITIGNORE,
        (
            "infra/proof-m4/proof-m4-staging/",
            "infra/proof-m4/proof_m4/",
            "infra/proof-m4/_local_as.py",
        ),
    )


def test_uses_released_staging_not_local_build():
    _assert_all(
        R,
        (
            "tests.integration.proof_m4.stage_released_pack",
            '"$STAGING_DST"',
            "download, not build",
        ),
    )
    assert "uv build" not in R  # released artifact only


def test_builds_the_expected_images_from_the_expected_contexts():
    _assert_all(
        R,
        (
            "for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh",
            'BASE_IMAGE="cognic-agentos:proof1b2-base"',
            'IMAGE="cognic-agentos:proofm4"',
            'MCP_IMAGE="cognic-proof-oracle-pack:m4"',
            'AS_IMAGE="cognic-proof-as:m4"',
            "docker build -f infra/agentos/Dockerfile --target default-adapters",
            'cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"',
            'docker build -f "$PROOF_DIR/Dockerfile.agentos-proof"',
            'docker build -f "$PROOF_DIR/Dockerfile.oracle-pack" -t "$MCP_IMAGE" "$PROOF_DIR"',
            'cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"',
            'docker build -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"',
        ),
    )


def test_backends_start_and_wait_before_xe_with_diagnostics():
    backends_wait = R.index(
        'kubectl -n "$NS" wait --for=condition=available --timeout=300s '
        "deploy -l 'app notin (oracle-xe)'"
    )
    seed_cm = R.index('kubectl -n "$NS" create configmap oracle-xe-seed')
    xe_apply = R.index('kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"')
    assert backends_wait < seed_cm, "backends-wait must precede the oracle-xe-seed ConfigMap"
    assert backends_wait < xe_apply, "backends-wait must precede the oracle-xe.yaml apply"
    _assert_all(
        R,
        (
            "|| backends_fail",
            "backends_fail() {",
            "pod -l app=oracle-xe --timeout=1200s",
            "xe_fail",
            "docs/VALIDATION-RESULTS.md",
        ),
    )
    assert "--timeout=600s" not in R


def test_seeds_through_scripts_and_no_inline_or_seeded_derived_rows():
    _assert_all(
        R,
        (
            'NS="$NS" bash "$PROOF_DIR/seed-vault.sh"',
            'NS="$NS" bash "$PROOF_DIR/seed-db.sh"',
            'helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m4-values.yaml"',
            'sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml"',
            'kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" '
            '-f "$PROOF_DIR/manifests/auth-server.yaml"',
        ),
    )
    # THE M4 HEADLINE: the runner NEVER inlines the derived-row INSERTs (install
    # materializes them; seed-db.sh is a no-op guard).
    assert "INSERT INTO mcp_server_url_override" not in R
    assert "INSERT INTO mcp_internal_host_allowlist" not in R


def test_bar1_drives_the_full_operator_api_sequence_multi_actor():
    """The governed lifecycle via the REAL operator API, multi-actor via
    X-Proof-Role: submit -> claim -> approve -> allow-list -> configure -> install."""
    _assert_all(
        R,
        (
            "X-Proof-Role: $role",
            # create draft (author)
            "api author POST /api/v1/packs/drafts",
            # submit (author) — manifest + signed_artefact_root; digest via kernel canonical_bytes
            'api author POST "/api/v1/packs/drafts/$PACK_UUID/submit"',
            "from cognic_agentos.core.canonical import canonical_bytes",
            "signed_artefact_root",
            # claim (reviewer) — distinct subject -> role-separation
            'api reviewer POST "/api/v1/packs/$PACK_UUID/claim"',
            # approve (reviewer) — signature REAL-green, 4 gates overridden
            'api reviewer POST "/api/v1/packs/$PACK_UUID/approve"',
            '"override_reason": "prerelease_validation"',
            # allow-list (operator, human-actor)
            'api operator POST "/api/v1/packs/$PACK_UUID/allow-list"',
            # configure (operator) — the desired runtime-config record
            'api operator PUT "/api/v1/packs/$PACK_UUID/runtime-config"',
            '"oauth_credential_ref"',
            '"as_allowlist_ref"',
            # install (operator) — materializes
            'api operator POST "/api/v1/packs/$PACK_UUID/install"',
        ),
    )


def test_bar1_asserts_materialization_auth_ready_and_call_tool():
    _assert_all(
        R,
        (
            # materialization evidence: decision_history mcp.override.set + mcp.allowlist.add
            "SELECT decision_type FROM decision_history WHERE decision_type IN "
            "('mcp.override.set','mcp.allowlist.add')",
            "mcp.override.set",
            "mcp.allowlist.add",
            "materialized by install (not seeded)",
            # discovery_status=auth_ready (cold pod) + call_tool
            'DS="$(discovery_status)"',
            '[ "$DS" = "auth_ready" ]',
            "/api/v1/mcp/servers/$PACK_ID/tools/call",
            '"tool_name":"describe_table"',
            '"owner":"COGNIC"',
            '"table":"EMPLOYEES"',
            "FULL_NAME",
            "PROOF M4 (BAR 1) PASS",
        ),
    )


def test_bar2_negatives_assert_closed_enum_install_refusal_reasons():
    _assert_all(
        R,
        (
            # gate 1 — not approved/allow-listed
            '_assert_install_refused "$NEG1" 409 "lifecycle_transition_invalid_state_pair"',
            # gate 3 — not configured
            '_assert_install_refused "$NEG2" 409 "install_runtime_config_missing"',
            # gate 4 — Vault OAuth ref absent
            '_assert_install_refused "$NEG3" 409 "install_runtime_config_vault_ref_unresolved"',
            "DOES-NOT-EXIST",
            # approve refused on signature-red (signature non-overridable)
            "/opt/cognic/pack-attestations/NO-SUCH-PACK/9.9.9",
            '[ "$HTTP_CODE" = "412" ] || bar_fail "BAR 2.4 approve expected 412 on signature-red',
            "signature stays REAL, non-overridable",
            "PROOF M4 (BAR 2) PASS",
        ),
    )


def test_bar3_disable_refused_reinstall_restored_revoke_terminal():
    _assert_all(
        R,
        (
            'api operator POST "/api/v1/packs/$PACK_UUID/disable"',
            '[ "$DS" = "refused" ] || bar_fail "BAR 3.1',
            # re-install (disabled->installed re-enable)
            "disabled->installed re-enable",
            '[ "$DS" = "auth_ready" ] || bar_fail "BAR 3.2',
            # revoke -> refused + terminal (install-after-revoke 409)
            'api operator POST "/api/v1/packs/$PACK_UUID/revoke"',
            "install-after-revoke expected 409 terminal",
            "PROOF M4 (BAR 3) PASS",
            "PROOF M4 (ALL BARS) PASS",
        ),
    )


def test_readme_documents_the_operator_boundary_and_proof_only_wiring():
    _assert_all(
        README,
        (
            "RELEASED, signed",
            "COGNIC_RUN_PROOF_M4=1",
            "materializer **materializes**",
            "seed-db.sh` is a **no-op guard**",
            "MultiActorProofBinder",
            "X-Proof-Role",
            "role-separation",
            "two-engine note",
            "REAL signature gate",
            "non-overridable",
            "PROOF M4 (BAR 1) PASS",
            "PROOF M4 (BAR 2) PASS",
            "PROOF M4 (BAR 3) PASS",
            "must NOT be shipped as kernel behavior",
        ),
    )
