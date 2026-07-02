"""Structural pins for the ``infra/proof-m5/`` scaffolding + runner (M5 Tasks 9-10).

Mirrors the proof-m4 structural tests (``tests/unit/proof_m4/test_values.py`` +
``test_seeds.py`` + ``test_runner.py``) for the M5 tree, plus the M5-specific
pins:

* the proof-m5 dir carries the expected file set — INCLUDING the Task-10
  ``run-proof-m5.sh`` 3-bar DLP runner (executable, env-gated on
  ``COGNIC_RUN_PROOF_M5=1``, no default-on CI job);
* the oracle Dockerfile / staging reference the ``v0.2.0`` DLP-governed
  re-release (never the M3/M4 ``0.1.0`` oracle wheel);
* the kernel-image Dockerfile stages the hook-pack wheel (baked into the kernel
  venv — trust-register + registry-admit only, spec §6 decision B) and keeps the
  M4 site-packages chmod fix;
* the recorded release-asset sha256 digests (both wheels + both cosign.pub keys)
  are pinned fail-closed at the staging site (``stage-packs.sh``);
* the two-key trust-root layout: ``_default`` carries the ORACLE key (the LOCKED
  boot convention + the approve signature-gate root); the HOOK key is staged
  per-pack under the same prefix;
* the runner drives the three DLP bars against the single deployed ``v0.2.0``
  tool with the ARGUMENT as the only variable (``EMPLOYEES`` permitted /
  ``__FORBIDDEN__`` policy-refused 403 ``dlp_pre_refused`` /
  ``__EXPLODE__`` fail-closed 409 ``dlp_pre_failed``), asserts the refusal
  fired BEFORE the tool (``audit.tool_invocation`` count unchanged), and pins
  the DIGEST-ONLY evidence invariant (the sentinel literal in NO chain row;
  ``dlp_policy_input_digest`` is the correlator);
* the proof app (``tests/integration/proof_m5/proof_app.py``) is the M5 mirror
  of the M4 multi-actor factory the ``Dockerfile.agentos-proof`` CMD boots
  (``proof_m5.proof_app:create_proof_app``).
"""

from __future__ import annotations

import stat
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROOF_DIR = _REPO_ROOT / "infra" / "proof-m5"
_PROOF_APP_DIR = _REPO_ROOT / "tests" / "integration" / "proof_m5"

DOCKER_AGENTOS = (_PROOF_DIR / "Dockerfile.agentos-proof").read_text()
DOCKER_ORACLE = (_PROOF_DIR / "Dockerfile.oracle-pack").read_text()
DOCKER_AS = (_PROOF_DIR / "Dockerfile.as").read_text()
STAGE = (_PROOF_DIR / "stage-packs.sh").read_text()
SEED_DB = (_PROOF_DIR / "seed-db.sh").read_text()
SEED_VAULT = (_PROOF_DIR / "seed-vault.sh").read_text()
README = (_PROOF_DIR / "README.md").read_text()
VALUES = yaml.safe_load((_PROOF_DIR / "proof-m5-values.yaml").read_text())
MIGRATE_RAW = (_PROOF_DIR / "migrate-job.yaml").read_text()
MIGRATE = yaml.safe_load(MIGRATE_RAW)
RUNNER = (_PROOF_DIR / "run-proof-m5.sh").read_text()
PROOF_APP = (_PROOF_APP_DIR / "proof_app.py").read_text()


def _assert_all(text: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        assert needle in text, f"missing: {needle!r}"


# The pinned release-asset digests (M5 Task 9). These are the sha256 of the
# RELEASED artifacts; a mismatch in stage-packs.sh means the staging site no
# longer fail-closes on the released bytes.
_ORACLE_WHEEL_SHA256 = "2961ce5d4aaf97425ab5851670f65e76c64164a5922b99d6f0e982a634be0439"
_ORACLE_PUB_SHA256 = "43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78"
_HOOK_WHEEL_SHA256 = "1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432"
_HOOK_PUB_SHA256 = "e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49"

_ORACLE_WHEEL = "cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"
_HOOK_WHEEL = "cognic_hook_schema_guard-0.1.0-py3-none-any.whl"


# ---------------------------------------------------------------------------
# file set
# ---------------------------------------------------------------------------


def test_proof_dir_carries_the_expected_file_set() -> None:
    required = {
        "Dockerfile.agentos-proof",
        "Dockerfile.as",
        "Dockerfile.oracle-pack",
        "README.md",
        "manifests",
        "migrate-job.yaml",
        "oracle-seed",
        "proof-m5-values.yaml",
        "run-proof-m5.sh",
        "seed-db.sh",
        "seed-vault.sh",
        "stage-packs.sh",
    }
    actual = {p.name for p in _PROOF_DIR.iterdir()}
    missing = required - actual
    assert not missing, f"proof-m5 scaffolding files missing: {sorted(missing)}"
    assert {p.name for p in (_PROOF_DIR / "manifests").iterdir()} == {
        "auth-server.yaml",
        "oracle-pack.yaml",
        "oracle-xe.yaml",
    }
    assert (_PROOF_DIR / "oracle-seed" / "seed_schema.sql").read_text().strip()


def test_runner_exists_executable_and_no_m4_runner_copied() -> None:
    # Task 10 landed run-proof-m5.sh (flipping the Task-9 "no runner yet" pin);
    # run-proof-m4.sh must never be copied here.
    runner = _PROOF_DIR / "run-proof-m5.sh"
    assert runner.exists()
    assert runner.stat().st_mode & stat.S_IXUSR, "run-proof-m5.sh not executable"
    assert not (_PROOF_DIR / "run-proof-m4.sh").exists()


# ---------------------------------------------------------------------------
# released-asset staging (stage-packs.sh) — versions + fail-closed digests
# ---------------------------------------------------------------------------


def test_stage_packs_pins_the_released_versions() -> None:
    assert 'ORACLE_TAG="v0.2.0"' in STAGE
    assert f'ORACLE_WHEEL="{_ORACLE_WHEEL}"' in STAGE
    assert 'HOOK_TAG="v0.1.0"' in STAGE
    assert f'HOOK_WHEEL="{_HOOK_WHEEL}"' in STAGE
    # released assets only: downloaded via gh, never built from pack source
    assert "gh release download" in STAGE
    assert 'ORACLE_REPO="bmzee/cognic-tool-oracle-schema"' in STAGE
    assert 'HOOK_REPO="bmzee/cognic-hook-schema-guard"' in STAGE
    # the M3/M4 oracle wheel must never sneak back in
    assert "cognic_tool_oracle_schema-0.1.0" not in STAGE


def test_stage_packs_pins_all_four_release_digests_fail_closed() -> None:
    assert f'ORACLE_WHEEL_SHA256="{_ORACLE_WHEEL_SHA256}"' in STAGE
    assert f'ORACLE_PUB_SHA256="{_ORACLE_PUB_SHA256}"' in STAGE
    assert f'HOOK_WHEEL_SHA256="{_HOOK_WHEEL_SHA256}"' in STAGE
    assert f'HOOK_PUB_SHA256="{_HOOK_PUB_SHA256}"' in STAGE
    # each pinned digest is actually verified (not just declared)
    assert '_verify_digest "$ORACLE_SRC/$ORACLE_WHEEL" "$ORACLE_WHEEL_SHA256"' in STAGE
    assert '_verify_digest "$ORACLE_SRC/cosign.pub" "$ORACLE_PUB_SHA256"' in STAGE
    assert '_verify_digest "$HOOK_SRC/$HOOK_WHEEL" "$HOOK_WHEEL_SHA256"' in STAGE
    assert '_verify_digest "$HOOK_SRC/cosign.pub" "$HOOK_PUB_SHA256"' in STAGE
    # and a mismatch dies (fail-closed) rather than warning
    assert "sha256 mismatch" in STAGE
    assert "die " in STAGE


def test_stage_packs_arranges_the_per_pack_attestation_trees() -> None:
    # resolve_pack_attestations walks <root>/<distribution_name>/<version>/.
    assert '_stage_pack_attestations "$ORACLE_SRC" "$ORACLE_PACK_ID" "$ORACLE_VERSION"' in STAGE
    assert '_stage_pack_attestations "$HOOK_SRC" "$HOOK_PACK_ID" "$HOOK_VERSION"' in STAGE
    assert 'ORACLE_VERSION="0.2.0"' in STAGE
    assert 'HOOK_VERSION="0.1.0"' in STAGE
    # the 7-attestation released-bundle contract (M3/M4 shape)
    for name in (
        "cosign.sig",
        "bundle.sigstore",
        "sbom.cdx.json",
        "slsa-provenance.intoto.json",
        "intoto-layout.json",
        "vuln-scan.json",
        "license-audit.json",
    ):
        assert f'"{name}"' in STAGE, f"attestation basename {name} not staged"


def test_stage_packs_two_key_trust_root_layout() -> None:
    # _default = the ORACLE key (LOCKED boot convention + approve signature root);
    # the HOOK key is staged per-pack under the same prefix (different signer).
    assert 'cp "$ORACLE_SRC/cosign.pub" "$STAGING_DST/trust-roots/_default/cosign.pub"' in STAGE
    assert (
        'cp "$HOOK_SRC/cosign.pub" '
        '"$STAGING_DST/trust-roots/hook-packs/$HOOK_PACK_ID/cosign.pub"' in STAGE
    )


def test_stage_packs_allowlists_both_packs_for_the_default_tenant() -> None:
    assert 'printf \'{"_default": ["%s", "%s"]}\\n\' "$ORACLE_PACK_ID" "$HOOK_PACK_ID"' in STAGE
    assert 'ORACLE_PACK_ID="cognic-tool-oracle-schema"' in STAGE
    assert 'HOOK_PACK_ID="cognic-hook-schema-guard"' in STAGE


# ---------------------------------------------------------------------------
# kernel image (Dockerfile.agentos-proof)
# ---------------------------------------------------------------------------


def test_kernel_dockerfile_stages_both_wheels_and_the_trust_tree() -> None:
    # stage-packs.sh puts BOTH wheels in proof-m5-staging/wheel/; the kernel image
    # pip-installs the whole dir, so the hook pack's cognic.hooks entry points are
    # boot-discoverable (iter_registered_pack_candidates sees it once registered).
    assert "COPY proof-m5-staging/wheel/ /tmp/wheel/" in DOCKER_AGENTOS
    assert "pip install --no-deps --no-cache-dir /tmp/wheel/*.whl" in DOCKER_AGENTOS
    assert 'cp "$HOOK_SRC/$HOOK_WHEEL" "$STAGING_DST/wheel/$HOOK_WHEEL"' in STAGE
    assert 'cp "$ORACLE_SRC/$ORACLE_WHEEL" "$STAGING_DST/wheel/$ORACLE_WHEEL"' in STAGE
    assert "COPY proof-m5-staging/pack-attestations/ /opt/cognic/pack-attestations/" in (
        DOCKER_AGENTOS
    )
    assert "COPY proof-m5-staging/trust-roots/ /opt/cognic/trust-roots/" in DOCKER_AGENTOS
    assert "COPY proof-m5-staging/policies/ /opt/cognic/policies/" in DOCKER_AGENTOS
    assert "COPY proof-m5-staging/alembic.ini /app/alembic.ini" in DOCKER_AGENTOS


def test_kernel_dockerfile_keeps_the_m4_source_overlay_and_chmod_fix() -> None:
    # the live proof must exercise THIS branch's DLP wiring (source overlay), and
    # the M4 site-packages chmod fix must cover the overlaid package.
    assert "rm -rf /opt/venv/lib/python3.12/site-packages/cognic_agentos" in DOCKER_AGENTOS
    assert (
        "COPY cognic_agentos/ /opt/venv/lib/python3.12/site-packages/cognic_agentos/"
        in DOCKER_AGENTOS
    )
    assert (
        "chmod -R a+rX /opt/cognic /app/alembic.ini /app/proof_m5 "
        "/opt/venv/lib/python3.12/site-packages/cognic_agentos" in DOCKER_AGENTOS
    )
    # trust env: attestation root + signature root + trust-root prefix + allow-list
    assert "COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations" in DOCKER_AGENTOS
    assert "COGNIC_SIGNATURE_ROOT_PATH=/opt/cognic/pack-attestations" in DOCKER_AGENTOS
    assert "COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots" in DOCKER_AGENTOS
    assert (
        "COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json" in DOCKER_AGENTOS
    )


def test_kernel_dockerfile_boots_the_m5_proof_app() -> None:
    assert "COPY proof_m5/ /app/proof_m5/" in DOCKER_AGENTOS
    assert "uvicorn proof_m5.proof_app:create_proof_app --factory" in DOCKER_AGENTOS
    assert "proof_m4" not in DOCKER_AGENTOS


# ---------------------------------------------------------------------------
# oracle-pack image (v0.2.0, never 0.1.0)
# ---------------------------------------------------------------------------


def test_oracle_dockerfile_stages_the_v020_release_wheel() -> None:
    assert f"COPY proof-m5-staging/wheel/{_ORACLE_WHEEL} /tmp/" in DOCKER_ORACLE
    assert f"pip install --no-cache-dir --no-deps /tmp/{_ORACLE_WHEEL}" in DOCKER_ORACLE
    # the M3/M4 0.1.0 oracle WHEEL must never be staged/installed (prose may
    # legitimately mention v0.1.0 when describing the release delta)
    assert "cognic_tool_oracle_schema-0.1.0" not in DOCKER_ORACLE
    assert 'CMD ["python", "-m", "cognic_tool_oracle_schema.server"]' in DOCKER_ORACLE


def test_as_dockerfile_vendors_the_single_fixture() -> None:
    assert "COPY _local_as.py /app/_local_as.py" in DOCKER_AS
    assert 'CMD ["python", "_local_as.py"]' in DOCKER_AS


# ---------------------------------------------------------------------------
# values + migrate job (mirrors tests/unit/proof_m4/test_values.py)
# ---------------------------------------------------------------------------


def test_values_prod_profile_migrations_off_proof_tag() -> None:
    assert VALUES["image"]["repository"] == "cognic-agentos"
    assert VALUES["image"]["tag"] == "proofm5"
    assert VALUES["image"]["pullPolicy"] == "IfNotPresent"
    assert VALUES["runtimeProfile"] == "prod"
    assert VALUES["migrations"]["enabled"] is False
    assert VALUES["cache"]["enabled"] is False
    assert VALUES["podSecurityContext"] == {"runAsUser": 10001, "fsGroup": 10001}


def test_values_vault_token_matches_seed_vault() -> None:
    assert VALUES["secrets"]["create"] is True
    assert VALUES["secrets"]["vaultToken"] == "smoke-root-token"
    assert "VAULT_TOKEN=smoke-root-token" in SEED_VAULT


def test_migrate_job_is_non_hook_with_image_slot() -> None:
    assert "__AGENTOS_IMAGE__" in MIGRATE_RAW
    assert MIGRATE["kind"] == "Job"
    assert "annotations" not in MIGRATE["metadata"]  # NOT a helm hook (Gap 3)
    pod = MIGRATE["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert pod["securityContext"] == {"runAsNonRoot": True, "runAsUser": 10001}
    assert "exec alembic upgrade head" in container["args"][0]
    assert container["envFrom"][0]["configMapRef"]["name"] == "rel-agentos-config"


# ---------------------------------------------------------------------------
# seeds (mirrors tests/unit/proof_m4/test_seeds.py, m5 identities)
# ---------------------------------------------------------------------------


def test_db_seed_stays_a_no_op_guard() -> None:
    assert "INSERT INTO mcp_server_url_override" not in SEED_DB
    assert "INSERT INTO mcp_internal_host_allowlist" not in SEED_DB
    assert 'T="proof-m5"' in SEED_DB
    assert 'NS="${NS:-cognic-proofm5}"' in SEED_DB
    assert "no-op" in SEED_DB
    assert "SOLE" in SEED_DB
    # the hook pack takes NO lifecycle/DB path at all (trust-register only)
    assert "trust-register" in SEED_DB


def test_vault_seed_targets_the_m5_tenant_by_reference() -> None:
    assert 'NS="${NS:-cognic-proofm5}"' in SEED_VAULT
    assert 'T="proof-m5"' in SEED_VAULT
    assert 'ASHOST="192.88.99.9_9000"' in SEED_VAULT
    assert 'AS="http://192.88.99.9:9000"' in SEED_VAULT
    # trailing-slash allow-list entry (FastMCP AnyHttpUrl normalisation)
    assert 'echo "{\\"servers\\":[\\"${AS}/\\"]}"' in SEED_VAULT
    assert '"secret/cognic/$T/mcp-as-allowlist"' in SEED_VAULT
    assert '"secret/cognic/$T/mcp-oauth/$ASHOST"' in SEED_VAULT
    assert "BY REFERENCE" in SEED_VAULT
    # `servers=` would store a STRING in Vault; the kernel expects a JSON list.
    assert "servers=" not in SEED_VAULT


def test_scripts_are_executable() -> None:
    for name in ("stage-packs.sh", "seed-db.sh", "seed-vault.sh"):
        assert (_PROOF_DIR / name).stat().st_mode & stat.S_IXUSR, f"{name} not executable"


# ---------------------------------------------------------------------------
# manifests
# ---------------------------------------------------------------------------


def test_manifests_use_m5_image_tags_and_keep_the_single_effective_url() -> None:
    oracle_pack = (_PROOF_DIR / "manifests" / "oracle-pack.yaml").read_text()
    auth_server = (_PROOF_DIR / "manifests" / "auth-server.yaml").read_text()
    oracle_xe = (_PROOF_DIR / "manifests" / "oracle-xe.yaml").read_text()
    assert "image: cognic-proof-oracle-pack:m5" in oracle_pack
    assert "image: cognic-proof-as:m5" in auth_server
    assert ":m4" not in oracle_pack and ":m4" not in auth_server
    # single-effective-URL invariant (unchanged from M4/1b-2c)
    assert "clusterIP: 10.96.0.51" in oracle_pack
    assert oracle_pack.count("http://10.96.0.51:8765/mcp") == 2  # server_url == audience
    assert 'externalIPs: ["192.88.99.9"]' in auth_server
    assert 'COGNIC_PROOF_AS_SIGNING_MODE, value: "rs256"' in auth_server
    assert "gvenzl/oracle-xe:21-slim" in oracle_xe
    assert "configMap: { name: oracle-xe-seed }" in oracle_xe


# ---------------------------------------------------------------------------
# README — the three DLP bars + the trust-register-vs-operator-install split
# ---------------------------------------------------------------------------


def test_readme_states_the_three_dlp_bars() -> None:
    # BAR 1 — permitted arg -> hook allows -> tool executes -> 200 / FULL_NAME
    assert "BAR 1" in README
    assert "table=EMPLOYEES" in README
    assert "FULL_NAME" in README
    # BAR 2 — forbidden arg -> 403 dlp_pre_refused, before the tool, digest-only
    assert "BAR 2" in README
    assert "__FORBIDDEN__" in README
    assert "dlp_pre_refused" in README
    assert "403" in README
    assert "policy_reason=forbidden_schema_arg" in README
    assert "digest-only" in README
    # BAR 3 — explode arg -> 409 dlp_pre_failed (fail-closed, never a bypass)
    assert "BAR 3" in README
    assert "__EXPLODE__" in README
    assert "dlp_pre_failed" in README
    assert "409" in README


def test_readme_states_the_trust_register_vs_operator_install_split() -> None:
    assert "operator-installed via the M4 flow" in README
    assert "trust-register + registry-admit ONLY" in README
    assert "never" in README.lower()
    # the two-key trust staging is documented (different signers, one prefix)
    assert "trust-roots/_default/cosign.pub" in README
    assert "trust-roots/hook-packs/cognic-hook-schema-guard/cosign.pub" in README
    assert "different cosign keys" in README
    # released-assets-only + digest pinning are stated
    assert "released assets only" in README.lower()
    assert "sha256" in README.lower()
    # the runner is documented (Task 10 shipped it; see the runner pins below)
    assert "run-proof-m5.sh" in README
    assert "Task 10" in README


# ---------------------------------------------------------------------------
# runner (Task 10) — env gate, identities, staging, lifecycle, hook preflight
# ---------------------------------------------------------------------------


def test_runner_env_gated_and_skip_clean() -> None:
    _assert_all(
        RUNNER,
        (
            'if [[ "${COGNIC_RUN_PROOF_M5:-}" != "1" ]]; then',
            "skipped: set COGNIC_RUN_PROOF_M5=1",
            "exit 0",
            'CLUSTER="${KIND_CLUSTER:-cognic-proofm5}"',
            'NS="cognic-proofm5"',
            'PROOF_DIR="infra/proof-m5"',
            'AGENTOS_SRC_SRC="src/cognic_agentos"',
            'AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"',
            'TENANT="proof-m5"',
            'PACK_ID="cognic-tool-oracle-schema"',
            'HOOK_PACK_ID="cognic-hook-schema-guard"',
            'PACK_WHEEL="cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"',
        ),
    )
    # the M3/M4 oracle wheel must never sneak back in
    assert "cognic_tool_oracle_schema-0.1.0" not in RUNNER


def test_runner_stages_via_stage_packs_sh_not_the_m4_python_stager() -> None:
    # M5 delta vs proof-m4: the staging contract is the proof-owned shell script
    # (both released packs, sha256-pinned), never the m4 python module and never
    # a source build.
    _assert_all(
        RUNNER,
        (
            'STAGING_DST="$PROOF_DIR/proof-m5-staging"',
            'bash "$PROOF_DIR/stage-packs.sh" "$STAGING_DST"',
            "download, not build",
        ),
    )
    assert "stage_released_pack" not in RUNNER  # the m4 python stager
    assert "uv build" not in RUNNER  # released artifacts only


def test_runner_builds_m5_images_and_cleans_the_transient_copies() -> None:
    _assert_all(
        RUNNER,
        (
            "for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh",
            'BASE_IMAGE="cognic-agentos:proof1b2-base"',
            'IMAGE="cognic-agentos:proofm5"',
            'MCP_IMAGE="cognic-proof-oracle-pack:m5"',
            'AS_IMAGE="cognic-proof-as:m5"',
            "docker_build_with_retry -f infra/agentos/Dockerfile --target default-adapters",
            'PROOF_APP_SRC="tests/integration/proof_m5"',
            'PROOF_APP_DST="$PROOF_DIR/proof_m5"',
            'cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"',
            'cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.oracle-pack" '
            '-t "$MCP_IMAGE" "$PROOF_DIR"',
            'cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"',
            # cleanup trap removes ALL FOUR transient build-context copies
            'rm -rf "$STAGING_DST" "$PROOF_APP_DST" "$AGENTOS_SRC_DST" "$PROOF_DIR/_local_as.py"',
        ),
    )


def test_runner_seeds_through_scripts_and_never_inlines_derived_rows() -> None:
    _assert_all(
        RUNNER,
        (
            'NS="$NS" bash "$PROOF_DIR/seed-vault.sh"',
            'NS="$NS" bash "$PROOF_DIR/seed-db.sh"',
            'helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m5-values.yaml"',
            'sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml"',
            'kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" '
            '-f "$PROOF_DIR/manifests/auth-server.yaml"',
        ),
    )
    # inherited M4 governance property: install MATERIALIZES the derived rows;
    # the runner NEVER inlines the INSERTs.
    assert "INSERT INTO mcp_server_url_override" not in RUNNER
    assert "INSERT INTO mcp_internal_host_allowlist" not in RUNNER


def test_runner_drives_the_m4_operator_lifecycle_for_the_v020_tool() -> None:
    """The tool pack is operator-installed EXACTLY as proven in M4 (multi-actor
    via X-Proof-Role); the manifest describes the v0.2.0 release incl. its
    [data_governance].dlp_pre_hooks binding."""
    _assert_all(
        RUNNER,
        (
            "X-Proof-Role: $role",
            "api author POST /api/v1/packs/drafts",
            'api author POST "/api/v1/packs/drafts/$PACK_UUID/submit"',
            "from cognic_agentos.core.canonical import canonical_bytes",
            "signed_artefact_root",
            'api reviewer POST "/api/v1/packs/$PACK_UUID/claim"',
            'api reviewer POST "/api/v1/packs/$PACK_UUID/approve"',
            '"override_reason": "prerelease_validation"',
            'api operator POST "/api/v1/packs/$PACK_UUID/allow-list"',
            'api operator PUT "/api/v1/packs/$PACK_UUID/runtime-config"',
            '"oauth_credential_ref"',
            '"as_allowlist_ref"',
            'api operator POST "/api/v1/packs/$PACK_UUID/install"',
            # the submitted manifest is the v0.2.0 DLP-governed release shape
            '"version": "0.2.0"',
            '"dlp_pre_hooks": ["refuse_forbidden_schema_arg", "explode_schema_guard"]',
            'SIGNED_ARTEFACT_ROOT="/opt/cognic/pack-attestations/$PACK_ID/0.2.0"',
            # materialization evidence (M4-inherited): events + derived rows
            "mcp.override.set",
            "mcp.allowlist.add",
            "override|$TENANT|$PACK_ID|http://10.96.0.51:8765/mcp",
            "allowlist|$TENANT|10.96.0.51|proof-m5-operator",
        ),
    )


def test_runner_asserts_hook_pack_registry_admission_before_the_bars() -> None:
    """The hook pack is trust-register + registry-admit ONLY (spec §6 decision B):
    the runner probes GET /system/plugins for its registered candidate row
    (status=registered, kind=hooks) AND greps the boot logs clean of hook-admission
    / DLP-guard construction failures — before the lifecycle AND again on the cold
    pod that serves the bars."""
    _assert_all(
        RUNNER,
        (
            "assert_hook_pack_registered() {",
            "/api/v1/system/plugins?tenant_id=$TENANT",
            'if row.get("status") != "registered" or row.get("kind") != "hooks":',
            "dlp_guard_construction_failed",
            "hook_pack_trust_root_invalid",
            'assert_hook_pack_registered "hook-pack preflight (first boot)"',
            'assert_hook_pack_registered "BAR 1 preflight (hook pack on the serving pod)"',
        ),
    )
    # the hook pack must NEVER enter the operator lifecycle (no draft/install
    # call carries the hook pack id)
    assert '"pack_id": "cognic-hook-schema-guard"' not in RUNNER


# ---------------------------------------------------------------------------
# runner (Task 10) — the three DLP bars (argument is the only variable)
# ---------------------------------------------------------------------------


def test_runner_bar1_permitted_arg_executes_the_tool() -> None:
    _assert_all(
        RUNNER,
        (
            "/api/v1/mcp/servers/$PACK_ID/tools",
            "/api/v1/mcp/servers/$PACK_ID/tools/call",
            '\'{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}\'',
            'grep -qF "FULL_NAME" <<<"$CALL1_RESP"',
            '[ "$DS" = "auth_ready" ] || bar_fail "BAR 1',
            # the success evidence row is the BAR 2/3 contrast baseline
            '[ "$TOOL_INVOCATIONS_AFTER_BAR1" -ge 1 ]',
            "PROOF M5 (BAR 1) PASS",
        ),
    )


def test_runner_bar2_forbidden_arg_refused_before_the_tool_digest_only() -> None:
    _assert_all(
        RUNNER,
        (
            '\'{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"__FORBIDDEN__"}}\'',
            '[ "$HTTP_CODE" = "403" ] || bar_fail "BAR 2 expected HTTP 403 dlp_pre_refused',
            '[ "$BAR2_REASON" = "dlp_pre_refused" ]',
            '[ "$BAR2_POLICY_REASON" = "forbidden_schema_arg" ]',
            # (a) refused BEFORE the tool: the success-row count is UNCHANGED
            "SELECT count(*) FROM audit_event WHERE event_type='audit.tool_invocation';",
            'TOOL_INVOCATIONS_BEFORE_BAR2="$(tool_invocation_count)"',
            '[ "$TOOL_INVOCATIONS_AFTER_BAR2" = "$TOOL_INVOCATIONS_BEFORE_BAR2" ]',
            # ...and the refusal row is the DLP one, attributed to the refusing hook
            "event_type='audit.tool_invocation_refused'",
            'reason == "dlp_pre_refused"',
            'hook == "refuse_forbidden_schema_arg"',
            # (b) digest-only: sha256 correlator present, plaintext literal ABSENT
            "dlp_policy_input_digest",
            're.fullmatch(r"[0-9a-f]{64}", digest)',
            "evidence_rows_containing_literal '__FORBIDDEN__'",
            '[ "$FORBIDDEN_LITERAL_ROWS" = "0" ]',
            "PROOF M5 (BAR 2) PASS",
        ),
    )
    # strpos, NOT LIKE — '_' is a LIKE single-char wildcard and the sentinel is
    # underscore-heavy ('%__FORBIDDEN__%' would over/under-match).
    assert "strpos(payload::text, '$literal') > 0" in RUNNER
    assert "LIKE '%__FORBIDDEN__%'" not in RUNNER


def test_runner_bar3_explode_arg_fails_closed() -> None:
    _assert_all(
        RUNNER,
        (
            '\'{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"__EXPLODE__"}}\'',
            '[ "$HTTP_CODE" = "409" ] || bar_fail "BAR 3 expected HTTP 409 dlp_pre_failed',
            '[ "$BAR3_REASON" = "dlp_pre_failed" ]',
            '[ "$TOOL_INVOCATIONS_AFTER_BAR3" = "$TOOL_INVOCATIONS_BEFORE_BAR3" ]',
            'reason == "dlp_pre_failed"',
            'hook == "explode_schema_guard"',
            "evidence_rows_containing_literal '__EXPLODE__'",
            '[ "$EXPLODE_LITERAL_ROWS" = "0" ]',
            "PROOF M5 (BAR 3) PASS",
            "PROOF M5 (ALL BARS) PASS",
        ),
    )


def test_runner_bar_failures_capture_to_validation_results() -> None:
    # the proof is NEVER redefined downward: any bar failure captures diagnostics
    # (incl. the audit.tool_invocation* evidence tail + hook/DLP log markers) to
    # docs/VALIDATION-RESULTS.md and exits non-zero.
    _assert_all(
        RUNNER,
        (
            "bar_fail() {",
            "docs/VALIDATION-RESULTS.md",
            "## Proof M5 — FAILURE",
            "audit.tool_invocation%",
            "exit 1",
        ),
    )


def test_runner_api_command_substitution_reloads_http_code() -> None:
    _assert_all(
        RUNNER,
        (
            'HTTP_CODE_FILE="/tmp/proofm5-code"',
            "load_http_code() {",
        ),
    )
    captures = RUNNER.count('="$(api ')
    # Every command-substitution capture runs api in a subshell, so the HTTP_CODE
    # assignment inside api does not propagate. Each capture must reload from the
    # status file before checking HTTP_CODE.
    assert captures == RUNNER.count("load_http_code # after api command substitution")


# ---------------------------------------------------------------------------
# proof app (Task 10) — the M5 multi-actor factory the kernel image CMD boots
# ---------------------------------------------------------------------------


def test_proof_app_package_exists_with_create_proof_app() -> None:
    # Dockerfile.agentos-proof CMD boots proof_m5.proof_app:create_proof_app from
    # the vendored proof_m5/ package — both files must exist.
    assert (_PROOF_APP_DIR / "__init__.py").exists()
    assert (_PROOF_APP_DIR / "proof_app.py").exists()
    assert "def create_proof_app() -> FastAPI:" in PROOF_APP


def test_proof_app_is_the_m5_multi_actor_mirror() -> None:
    _assert_all(
        PROOF_APP,
        (
            'PROOF_TENANT: Final = "proof-m5"',
            'PROOF_ROLE_HEADER: Final = "X-Proof-Role"',
            "class MultiActorProofBinder:",
            # the four role subjects (reviewer DIFFERS from author: role-separation;
            # the operator subject is the derived allow-list row's set_by_actor the
            # runner asserts)
            'subject="proof-m5-author"',
            'subject="proof-m5-reviewer"',
            'subject="proof-m5-operator"',
            'subject="proof-m5-mcp"',
            # the mcp role holds the governed invoke scopes the three bars ride
            '"mcp.tool.list"',
            '"mcp.tool.invoke"',
            # the reviewer holds the override scope (signature stays REAL)
            '"pack.override.approval_gate"',
            # the operator holds the human-actor-gated lifecycle scopes
            '"pack.allow_list"',
            '"pack.configure"',
            '"pack.install"',
            # eager-injection wiring (Key Decision A carried from M4)
            "create_async_engine",
            "RuntimeConfigMaterializer",
            "class ProofStagedTrustRootResolver:",
        ),
    )
    # no M4 identity leakage: the m5 app must never mint proof-m4-* subjects
    # (module-path references to proof_m4 in prose are fine).
    assert "proof-m4-" not in PROOF_APP
