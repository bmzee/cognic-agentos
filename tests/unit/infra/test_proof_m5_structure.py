"""Structural pins for the ``infra/proof-m5/`` scaffolding (M5 Task 9).

Mirrors the proof-m4 structural tests (``tests/unit/proof_m4/test_values.py`` +
``test_seeds.py``) for the M5 tree, plus the Task-9 specific pins:

* the proof-m5 dir carries the expected file set — and NO ``run-proof-m5.sh``
  yet (the runner is the Task-10 deliverable; Task 10 updates this pin when it
  lands);
* the oracle Dockerfile / staging reference the ``v0.2.0`` DLP-governed
  re-release (never the M3/M4 ``0.1.0`` oracle wheel);
* the kernel-image Dockerfile stages the hook-pack wheel (baked into the kernel
  venv — trust-register + registry-admit only, spec §6 decision B) and keeps the
  M4 site-packages chmod fix;
* the recorded release-asset sha256 digests (both wheels + both cosign.pub keys)
  are pinned fail-closed at the staging site (``stage-packs.sh``);
* the two-key trust-root layout: ``_default`` carries the ORACLE key (the LOCKED
  boot convention + the approve signature-gate root); the HOOK key is staged
  per-pack under the same prefix.
"""

from __future__ import annotations

import stat
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROOF_DIR = _REPO_ROOT / "infra" / "proof-m5"

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


def test_no_runner_yet_and_no_m4_runner_copied() -> None:
    # Task 10 owns run-proof-m5.sh; run-proof-m4.sh must never be copied here.
    # (Task 10: replace the first assertion with runner pins when the runner lands.)
    assert not (_PROOF_DIR / "run-proof-m5.sh").exists()
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
    # the runner is Task 10 (not shipped in this scaffolding)
    assert "run-proof-m5.sh" in README
    assert "Task 10" in README
