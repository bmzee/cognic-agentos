"""Structural pin — the M3-E2c end-to-end runner (Task 10)."""

from pathlib import Path

R = Path("infra/proof-1b-2c/run-proof-1b-2c.sh").read_text()
README = Path("infra/proof-1b-2c/README.md").read_text()
GITIGNORE = Path(".gitignore").read_text()


def _assert_all(text: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        assert needle in text


def test_env_gated_and_skip_clean():
    _assert_all(
        R,
        (
            'if [[ "${COGNIC_RUN_PROOF_1B2C:-}" != "1" ]]; then',
            "skipped: set COGNIC_RUN_PROOF_1B2C=1",
            "exit 0",
            'CLUSTER="${KIND_CLUSTER:-cognic-proof1b2c}"',
            'NS="cognic-proof1b2c"',
            'PROOF_DIR="infra/proof-1b-2c"',
        ),
    )


def test_transient_build_context_copies_are_cleaned_and_ignored():
    _assert_all(
        R,
        (
            'STAGING_DST="$PROOF_DIR/proof1b2c-staging"',
            'PROOF_APP_DST="$PROOF_DIR/proof_1b_2c"',
            'rm -rf "$STAGING_DST" "$PROOF_APP_DST" "$PROOF_DIR/_local_as.py"',
        ),
    )
    _assert_all(
        GITIGNORE,
        (
            "infra/proof-1b-2c/proof1b2c-staging/",
            "infra/proof-1b-2c/proof_1b_2c/",
            "infra/proof-1b-2c/_local_as.py",
        ),
    )


def test_uses_released_staging_not_local_build():
    _assert_all(
        R,
        (
            "tests.integration.proof_1b_2c.stage_released_pack",
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
            'IMAGE="cognic-agentos:proof1b2c"',
            'MCP_IMAGE="cognic-proof-oracle-pack:1b2c"',
            'AS_IMAGE="cognic-proof-as:1b2c"',
            "docker build -f infra/agentos/Dockerfile --target default-adapters",
            'cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"',
            'docker build -f "$PROOF_DIR/Dockerfile.agentos-proof"',
            'docker build -f "$PROOF_DIR/Dockerfile.oracle-pack" -t "$MCP_IMAGE" "$PROOF_DIR"',
            'cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"',
            'docker build -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"',
        ),
    )


def test_creates_seed_configmap_from_single_source_file():
    _assert_all(
        R,
        (
            "create configmap oracle-xe-seed",
            '--from-file=seed_schema.sql="$PROOF_DIR/oracle-seed/seed_schema.sql"',
            "--dry-run=client -o yaml | kubectl apply",
        ),
    )


def test_brings_up_and_waits_for_xe():
    _assert_all(
        R,
        (
            'printf \'%s\\n\' "gvenzl/oracle-xe:21-slim" "busybox:1.36"',
            'apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"',
            "deploy -l 'app notin (oracle-xe)'",
            "pod -l app=oracle-xe --timeout=1200s",
            "xe_fail",
            "Oracle XE readiness FAILURE",
            "describe pod -l app=oracle-xe",
            "logs -l app=oracle-xe --tail=120",
            "docs/VALIDATION-RESULTS.md",
        ),
    )
    assert "--timeout=600s" not in R


def test_backends_start_and_wait_before_xe_with_diagnostics():
    # Sequenced startup (attempt-4 finding): the backends-Available wait must come
    # BEFORE the XE seed ConfigMap + the XE apply — overlap starved the backends.
    backends_wait = R.index(
        'kubectl -n "$NS" wait --for=condition=available --timeout=300s '
        "deploy -l 'app notin (oracle-xe)'"
    )
    seed_cm = R.index('kubectl -n "$NS" create configmap oracle-xe-seed')
    xe_apply = R.index('kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"')
    assert backends_wait < seed_cm, "backends-wait must precede the oracle-xe-seed ConfigMap"
    assert backends_wait < xe_apply, "backends-wait must precede the oracle-xe.yaml apply"
    # backends_fail wired to the backend wait + its diagnostic surface (attempt-4 diagnosability).
    _assert_all(
        R,
        (
            "|| backends_fail",
            "backends_fail() {",
            "backends readiness FAILURE",
            "get deploy,pods -o wide",
            "describe deploy -l 'app notin (oracle-xe)'",
            "describe pod -l 'app notin (oracle-xe)'",
            "docs/VALIDATION-RESULTS.md",
        ),
    )


def test_seeds_through_scripts_not_inline_override_inserts():
    _assert_all(
        R,
        (
            'NS="$NS" bash "$PROOF_DIR/seed-vault.sh"',
            'NS="$NS" bash "$PROOF_DIR/seed-db.sh"',
            'helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-1b-2c-values.yaml"',
            'sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml"',
            'kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" '
            '-f "$PROOF_DIR/manifests/auth-server.yaml"',
        ),
    )
    assert "INSERT INTO mcp_server_url_override" not in R


def test_bar1_allowlist_removed_delta_is_the_must_have_negative():
    _assert_all(
        R,
        (
            "/api/v1/mcp/servers/cognic-tool-oracle-schema/tools",
            "audit.mcp_allowlist_permitted",
            "SELECT payload::text FROM audit_event",
            "10.96.0.51",
            "DELETE FROM mcp_internal_host_allowlist",
            "tenant_id='proof-1b-2c'",
            "ip='10.96.0.51'",
            "/tmp/proof1b2c-refuse-body",
            "mcp_discovery_url_refused",
            "/api/v1/system/plugins?tenant_id=proof-1b-2c",
            'ds == "refused"',
            "BAR 1 PASS",
        ),
    )


def test_bar2_calls_describe_table_and_asserts_auth_ready():
    _assert_all(
        R,
        (
            "/api/v1/mcp/servers/cognic-tool-oracle-schema/tools/call",
            '"tool_name":"describe_table"',
            '"owner":"COGNIC"',
            '"table":"EMPLOYEES"',
            "FULL_NAME",
            'ds == "auth_ready"',
            "PROOF 1b-2c (BAR 2) PASS",
        ),
    )


def test_optional_verifier_negative_is_env_gated():
    _assert_all(
        R,
        (
            'if [[ "${COGNIC_PROOF_VERIFIER_NEGATIVE:-}" == "1" ]]; then',
            "COGNIC_OAUTH_AUDIENCE=http://10.96.0.99:8765/mcp",
            "expected call_tool to FAIL on aud mismatch",
            "COGNIC_OAUTH_AUDIENCE=http://10.96.0.51:8765/mcp",
        ),
    )


def test_readme_documents_the_operator_boundary_and_proof_only_binder():
    _assert_all(
        README,
        (
            "RELEASED, signed",
            "COGNIC_RUN_PROOF_1B2C=1",
            "Optional verifier negative",
            "Proof-only fixed-actor binder",
            "Production still requires a real",
            "BAR 1 PASS",
            "PROOF 1b-2c (BAR 2) PASS",
        ),
    )
