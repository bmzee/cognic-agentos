"""Structural pins for the ``infra/proof-m6/`` scaffolding + runner (M6 Tasks C1-C3).

Mirrors ``tests/unit/infra/test_proof_m5_structure.py`` for the M6 governed-
agent-skill proof tree, plus the M6-specific pins:

* the proof-m6 dir carries the expected file set — INCLUDING the Task-C1
  ``Dockerfile.skill-runtime`` (the immutable sandbox runtime image baking the
  released skill wheel + the in-sandbox skill-runner) and the Task-C3
  ``run-proof-m6.sh`` 3-bar runner (executable, env-gated on
  ``COGNIC_RUN_PROOF_M6=1``, no default-on CI job);
* the staging site pins ALL SIX release-asset sha256 digests fail-closed
  (three packs x wheel + cosign.pub: oracle ``v0.2.0`` + hook ``v0.1.0``
  [both reused verbatim from M5] + skill ``v0.1.0`` [the M6 release]);
* the THREE-key trust-root layout: ``_default`` carries the ORACLE key (the
  LOCKED boot convention + the approve signature-gate root); the HOOK key is
  per-pack at ``hook-packs/<pack_id>/cosign.pub`` (M5); the SKILL key is
  per-pack at ``skill-packs/cognic-skill-schema-summary/cosign.pub``
  (``harness/registry_boot._SKILL_PACK_TRUST_ROOT_SUBDIR = "skill-packs"``);
* the skill-runtime image stages the released ``0.1.0`` skill wheel
  (``--no-deps``), overlays THIS branch's kernel source (so the sandbox-side
  ``sdk.skill_transport`` is byte-identical to the kernel-side broker), proves
  the runner import chain at BUILD time, and honors the sandbox runtime-image
  contracts (USER 65534:65534 + keep-alive CMD + writable ``/workspace``) —
  the exec entrypoint is ``python -m cognic_agentos.sdk.skill_runner``;
* the runner drives the THREE governed-skill bars against the single deployed
  skill (``schema-summary``) with the ARGUMENT as the only variable:
  BAR 1 ``owner=COGNIC`` -> 200 completed + the two declared tools' governed
  ``audit.tool_invocation`` rows + a ``skill.invoked`` decision row;
  BAR 2 ``mode=forbidden`` -> 403 ``skill_tool_not_declared`` refused BEFORE
  ``MCPHost.call_tool`` (zero ``get_constraints`` evidence rows);
  BAR 3 ``mode=exfil`` -> the direct outbound call blocked (``--network
  none``), fail-closed 502 ``skill_runtime_error``, never a success;
* no proof-only bypass: the sandbox admission gate runs REAL (the runner
  re-homes + cosign-signs the runtime images under a proof canonical key in a
  local TLS registry — the documented bank re-home flow), and the M4/M5
  operator-install lifecycle + the M5 hook-pack DLP posture carry forward
  unchanged.
"""

from __future__ import annotations

import stat
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROOF_DIR = _REPO_ROOT / "infra" / "proof-m6"
_PROOF_APP_DIR = _PROOF_DIR / "proof_m6"

DOCKER_AGENTOS = (_PROOF_DIR / "Dockerfile.agentos-proof").read_text()
DOCKER_ORACLE = (_PROOF_DIR / "Dockerfile.oracle-pack").read_text()
DOCKER_AS = (_PROOF_DIR / "Dockerfile.as").read_text()
DOCKER_SKILL_RUNTIME = (_PROOF_DIR / "Dockerfile.skill-runtime").read_text()
STAGE = (_PROOF_DIR / "stage-packs.sh").read_text()
SEED_DB = (_PROOF_DIR / "seed-db.sh").read_text()
SEED_VAULT = (_PROOF_DIR / "seed-vault.sh").read_text()
README = (_PROOF_DIR / "README.md").read_text()
VALUES = yaml.safe_load((_PROOF_DIR / "proof-m6-values.yaml").read_text())
MIGRATE_RAW = (_PROOF_DIR / "migrate-job.yaml").read_text()
MIGRATE = yaml.safe_load(MIGRATE_RAW)
KIND_CONFIG_RAW = (_PROOF_DIR / "kind-config.yaml").read_text()
KIND_CONFIG = yaml.safe_load(KIND_CONFIG_RAW)
SANDBOX_PATCH_RAW = (_PROOF_DIR / "agentos-sandbox-patch.yaml").read_text()
SANDBOX_PATCH = yaml.safe_load(SANDBOX_PATCH_RAW)
RUNNER = (_PROOF_DIR / "run-proof-m6.sh").read_text()
PROOF_APP = (_PROOF_APP_DIR / "proof_app.py").read_text()


def _assert_all(text: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        assert needle in text, f"missing: {needle!r}"


# The pinned release-asset digests. Oracle + hook are byte-identical to the M5
# pins (same releases); the skill pins are the controller-recorded v0.1.0
# release assets (bmzee/cognic-skill-schema-summary — wheel + trust root). A
# mismatch in stage-packs.sh means the staging site no longer fail-closes on
# the released bytes.
_ORACLE_WHEEL_SHA256 = "2961ce5d4aaf97425ab5851670f65e76c64164a5922b99d6f0e982a634be0439"
_ORACLE_PUB_SHA256 = "43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78"
_HOOK_WHEEL_SHA256 = "1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432"
_HOOK_PUB_SHA256 = "e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49"
_SKILL_WHEEL_SHA256 = "d747b5e7ea5ccce23649281d93623bd1fd6316867e63f22e329d423dd07118aa"
_SKILL_PUB_SHA256 = "6e29b37dd3f31b68ad0eac569a53786e1ada43eeb75db63647dda8e52dff1a12"

_ORACLE_WHEEL = "cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"
_HOOK_WHEEL = "cognic_hook_schema_guard-0.1.0-py3-none-any.whl"
_SKILL_WHEEL = "cognic_skill_schema_summary-0.1.0-py3-none-any.whl"


# ---------------------------------------------------------------------------
# file set
# ---------------------------------------------------------------------------


def test_proof_dir_carries_the_expected_file_set() -> None:
    required = {
        "Dockerfile.agentos-proof",
        "Dockerfile.as",
        "Dockerfile.oracle-pack",
        "Dockerfile.skill-runtime",
        "README.md",
        "agentos-sandbox-patch.yaml",
        "kind-config.yaml",
        "manifests",
        "migrate-job.yaml",
        "oracle-seed",
        "proof-m6-values.yaml",
        "proof_m6",
        "run-proof-m6.sh",
        "seed-db.sh",
        "seed-vault.sh",
        "stage-packs.sh",
    }
    actual = {p.name for p in _PROOF_DIR.iterdir()}
    missing = required - actual
    assert not missing, f"proof-m6 scaffolding files missing: {sorted(missing)}"
    assert {p.name for p in (_PROOF_DIR / "manifests").iterdir()} == {
        "auth-server.yaml",
        "oracle-pack.yaml",
        "oracle-xe.yaml",
        "redis.yaml",
    }
    assert (_PROOF_DIR / "oracle-seed" / "seed_schema.sql").read_text().strip()


def test_runner_exists_executable_and_no_m5_runner_copied() -> None:
    runner = _PROOF_DIR / "run-proof-m6.sh"
    assert runner.exists()
    assert runner.stat().st_mode & stat.S_IXUSR, "run-proof-m6.sh not executable"
    assert not (_PROOF_DIR / "run-proof-m5.sh").exists()


# ---------------------------------------------------------------------------
# released-asset staging (stage-packs.sh) — versions + fail-closed digests
# ---------------------------------------------------------------------------


def test_stage_packs_pins_the_released_versions() -> None:
    assert 'ORACLE_TAG="v0.2.0"' in STAGE
    assert f'ORACLE_WHEEL="{_ORACLE_WHEEL}"' in STAGE
    assert 'HOOK_TAG="v0.1.0"' in STAGE
    assert f'HOOK_WHEEL="{_HOOK_WHEEL}"' in STAGE
    assert 'SKILL_TAG="v0.1.0"' in STAGE
    assert f'SKILL_WHEEL="{_SKILL_WHEEL}"' in STAGE
    # released assets only: downloaded via gh, never built from pack source
    assert "gh release download" in STAGE
    assert 'ORACLE_REPO="bmzee/cognic-tool-oracle-schema"' in STAGE
    assert 'HOOK_REPO="bmzee/cognic-hook-schema-guard"' in STAGE
    assert 'SKILL_REPO="bmzee/cognic-skill-schema-summary"' in STAGE
    # the M3/M4 oracle wheel must never sneak back in
    assert "cognic_tool_oracle_schema-0.1.0" not in STAGE


def test_stage_packs_pins_all_six_release_digests_fail_closed() -> None:
    assert f'ORACLE_WHEEL_SHA256="{_ORACLE_WHEEL_SHA256}"' in STAGE
    assert f'ORACLE_PUB_SHA256="{_ORACLE_PUB_SHA256}"' in STAGE
    assert f'HOOK_WHEEL_SHA256="{_HOOK_WHEEL_SHA256}"' in STAGE
    assert f'HOOK_PUB_SHA256="{_HOOK_PUB_SHA256}"' in STAGE
    assert f'SKILL_WHEEL_SHA256="{_SKILL_WHEEL_SHA256}"' in STAGE
    assert f'SKILL_PUB_SHA256="{_SKILL_PUB_SHA256}"' in STAGE
    # each pinned digest is actually verified (not just declared)
    assert '_verify_digest "$ORACLE_SRC/$ORACLE_WHEEL" "$ORACLE_WHEEL_SHA256"' in STAGE
    assert '_verify_digest "$ORACLE_SRC/cosign.pub" "$ORACLE_PUB_SHA256"' in STAGE
    assert '_verify_digest "$HOOK_SRC/$HOOK_WHEEL" "$HOOK_WHEEL_SHA256"' in STAGE
    assert '_verify_digest "$HOOK_SRC/cosign.pub" "$HOOK_PUB_SHA256"' in STAGE
    assert '_verify_digest "$SKILL_SRC/$SKILL_WHEEL" "$SKILL_WHEEL_SHA256"' in STAGE
    assert '_verify_digest "$SKILL_SRC/cosign.pub" "$SKILL_PUB_SHA256"' in STAGE
    # and a mismatch dies (fail-closed) rather than warning
    assert "sha256 mismatch" in STAGE
    assert "die " in STAGE


def test_stage_packs_arranges_the_per_pack_attestation_trees() -> None:
    assert '_stage_pack_attestations "$ORACLE_SRC" "$ORACLE_PACK_ID" "$ORACLE_VERSION"' in STAGE
    assert '_stage_pack_attestations "$HOOK_SRC" "$HOOK_PACK_ID" "$HOOK_VERSION"' in STAGE
    assert '_stage_pack_attestations "$SKILL_SRC" "$SKILL_PACK_ID" "$SKILL_VERSION"' in STAGE
    assert 'ORACLE_VERSION="0.2.0"' in STAGE
    assert 'HOOK_VERSION="0.1.0"' in STAGE
    assert 'SKILL_VERSION="0.1.0"' in STAGE
    # the 7-attestation released-bundle contract (M3/M4/M5 shape)
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


def test_stage_packs_three_key_trust_root_layout() -> None:
    # _default = the ORACLE key (LOCKED boot convention + approve signature
    # root); the HOOK + SKILL keys are staged per-pack under the same prefix
    # (three DIFFERENT signers, one COGNIC_TRUST_ROOT_PREFIX). The skill
    # subdir is the kernel's LOCKED _SKILL_PACK_TRUST_ROOT_SUBDIR
    # ("skill-packs", harness/registry_boot.py).
    assert 'cp "$ORACLE_SRC/cosign.pub" "$STAGING_DST/trust-roots/_default/cosign.pub"' in STAGE
    assert (
        'cp "$HOOK_SRC/cosign.pub" '
        '"$STAGING_DST/trust-roots/hook-packs/$HOOK_PACK_ID/cosign.pub"' in STAGE
    )
    assert (
        'cp "$SKILL_SRC/cosign.pub" '
        '"$STAGING_DST/trust-roots/skill-packs/$SKILL_PACK_ID/cosign.pub"' in STAGE
    )
    assert 'SKILL_PACK_ID="cognic-skill-schema-summary"' in STAGE
    # the resolved skill trust-root path the kernel boot loop reads
    assert "trust-roots/skill-packs/cognic-skill-schema-summary/cosign.pub" in (
        STAGE.replace("$SKILL_PACK_ID", "cognic-skill-schema-summary")
    )


def test_stage_packs_allowlists_all_three_packs_for_the_default_tenant() -> None:
    assert (
        'printf \'{"_default": ["%s", "%s", "%s"]}\\n\' '
        '"$ORACLE_PACK_ID" "$HOOK_PACK_ID" "$SKILL_PACK_ID"' in STAGE
    )
    assert 'ORACLE_PACK_ID="cognic-tool-oracle-schema"' in STAGE
    assert 'HOOK_PACK_ID="cognic-hook-schema-guard"' in STAGE


def test_stage_packs_stages_all_three_wheels_for_the_kernel_venv() -> None:
    # ALL THREE wheels land in wheel/ — the kernel image pip-installs the dir so
    # the oracle (cognic.tools+mcp), hook (cognic.hooks), and skill
    # (cognic.skills) entry points are ALL boot-discoverable; the oracle wheel
    # additionally feeds Dockerfile.oracle-pack and the skill wheel additionally
    # feeds Dockerfile.skill-runtime.
    assert 'cp "$ORACLE_SRC/$ORACLE_WHEEL" "$STAGING_DST/wheel/$ORACLE_WHEEL"' in STAGE
    assert 'cp "$HOOK_SRC/$HOOK_WHEEL" "$STAGING_DST/wheel/$HOOK_WHEEL"' in STAGE
    assert 'cp "$SKILL_SRC/$SKILL_WHEEL" "$STAGING_DST/wheel/$SKILL_WHEEL"' in STAGE


# ---------------------------------------------------------------------------
# skill-runtime image (Task C1) — the sandbox side of the governed skill
# ---------------------------------------------------------------------------


def test_skill_runtime_dockerfile_stages_the_released_skill_wheel() -> None:
    assert f"COPY proof-m6-staging/wheel/{_SKILL_WHEEL} /tmp/wheel/" in DOCKER_SKILL_RUNTIME
    assert f"pip install --no-deps --no-cache-dir /tmp/wheel/{_SKILL_WHEEL}" in DOCKER_SKILL_RUNTIME
    # released skill wheel only — never another version
    assert "cognic_skill_schema_summary-0.2.0" not in DOCKER_SKILL_RUNTIME


def test_skill_runtime_dockerfile_bakes_the_branch_sdk_and_proves_the_import() -> None:
    # The in-sandbox runner + wire transport MUST be byte-identical to the
    # kernel-side broker's (same branch source overlay both images), and the
    # import chain is proven AT BUILD TIME (a missing dep fails the build, not
    # BAR 1 mid-proof).
    assert "rm -rf /opt/venv/lib/python3.12/site-packages/cognic_agentos" in DOCKER_SKILL_RUNTIME
    assert (
        "COPY cognic_agentos/ /opt/venv/lib/python3.12/site-packages/cognic_agentos/"
        in DOCKER_SKILL_RUNTIME
    )
    assert (
        'RUN /opt/venv/bin/python -c "import cognic_agentos.sdk.skill_runner'
        in DOCKER_SKILL_RUNTIME
    )
    assert "cognic_skill_schema_summary.skill" in DOCKER_SKILL_RUNTIME


def test_skill_runtime_dockerfile_honors_the_sandbox_runtime_contracts() -> None:
    # The exec-driven sandbox model (infra/sandbox/runtime-python/Dockerfile):
    # keep-alive CMD holds the container open; the executor session.exec's the
    # runner (`env K=V ... python -m cognic_agentos.sdk.skill_runner`); the
    # backend forces User=65534:65534 so the image USER matches; /workspace is
    # the writable anonymous volume under ReadonlyRootfs.
    assert 'CMD ["sleep", "infinity"]' in DOCKER_SKILL_RUNTIME
    assert "USER 65534:65534" in DOCKER_SKILL_RUNTIME
    assert "mkdir -p /workspace && chmod 0777 /workspace" in DOCKER_SKILL_RUNTIME
    assert 'VOLUME ["/workspace"]' in DOCKER_SKILL_RUNTIME
    # the exec entrypoint contract is documented on the image itself
    assert "python -m cognic_agentos.sdk.skill_runner" in DOCKER_SKILL_RUNTIME
    # NO baked secrets / credentials — the sandbox runs with
    # requires_credentials=() and --network none
    assert "COGNIC_VAULT" not in DOCKER_SKILL_RUNTIME
    assert "SECRET" not in DOCKER_SKILL_RUNTIME.upper().replace("NO SECRETS", "")


# ---------------------------------------------------------------------------
# kernel image (Dockerfile.agentos-proof)
# ---------------------------------------------------------------------------


def test_kernel_dockerfile_stages_all_wheels_and_the_trust_tree() -> None:
    assert "COPY proof-m6-staging/wheel/ /tmp/wheel/" in DOCKER_AGENTOS
    assert "pip install --no-deps --no-cache-dir /tmp/wheel/*.whl" in DOCKER_AGENTOS
    assert "COPY proof-m6-staging/pack-attestations/ /opt/cognic/pack-attestations/" in (
        DOCKER_AGENTOS
    )
    assert "COPY proof-m6-staging/trust-roots/ /opt/cognic/trust-roots/" in DOCKER_AGENTOS
    assert "COPY proof-m6-staging/policies/ /opt/cognic/policies/" in DOCKER_AGENTOS
    assert "COPY proof-m6-staging/alembic.ini /app/alembic.ini" in DOCKER_AGENTOS


def test_kernel_dockerfile_adds_the_m6_sandbox_runtime_layers() -> None:
    # M6 deltas over the M5 kernel image:
    #   * aiodocker — is_sandbox_available() requires it (the sandbox-docker
    #     extra is NOT in the default-adapters base);
    #   * the proof canonical-image trust material (the runner-generated proof
    #     canonical cosign PUBLIC key + the local TLS registry CA) so the REAL
    #     sandbox admission gate (catalog cosign verify) runs un-bypassed;
    #   * SSL_CERT_FILE is a BUNDLE (system CAs + the registry CA) so public
    #     TLS keeps verifying.
    assert "aiodocker" in DOCKER_AGENTOS
    assert "COPY proof-m6-staging/canonical-trust/ /opt/cognic/canonical-trust/" in DOCKER_AGENTOS
    assert (
        "COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH=/opt/cognic/canonical-trust/cosign.pub"
        in DOCKER_AGENTOS
    )
    assert "SSL_CERT_FILE=/opt/cognic/canonical-trust/ca-bundle.pem" in DOCKER_AGENTOS
    assert "ca-certificates.crt" in DOCKER_AGENTOS  # bundle = system CAs + registry CA


def test_kernel_dockerfile_keeps_the_m4_source_overlay_and_chmod_fix() -> None:
    assert "rm -rf /opt/venv/lib/python3.12/site-packages/cognic_agentos" in DOCKER_AGENTOS
    assert (
        "COPY cognic_agentos/ /opt/venv/lib/python3.12/site-packages/cognic_agentos/"
        in DOCKER_AGENTOS
    )
    assert (
        "chmod -R a+rX /opt/cognic /app/alembic.ini /app/proof_m6 "
        "/opt/venv/lib/python3.12/site-packages/cognic_agentos" in DOCKER_AGENTOS
    )
    assert "COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations" in DOCKER_AGENTOS
    assert "COGNIC_SIGNATURE_ROOT_PATH=/opt/cognic/pack-attestations" in DOCKER_AGENTOS
    assert "COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots" in DOCKER_AGENTOS
    assert (
        "COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json" in DOCKER_AGENTOS
    )


def test_kernel_dockerfile_boots_the_m6_proof_app() -> None:
    assert "COPY proof_m6/ /app/proof_m6/" in DOCKER_AGENTOS
    assert "uvicorn proof_m6.proof_app:create_proof_app --factory" in DOCKER_AGENTOS
    assert "proof_m5" not in DOCKER_AGENTOS


# ---------------------------------------------------------------------------
# oracle-pack image (v0.2.0, never 0.1.0) + AS image
# ---------------------------------------------------------------------------


def test_oracle_dockerfile_stages_the_v020_release_wheel() -> None:
    assert f"COPY proof-m6-staging/wheel/{_ORACLE_WHEEL} /tmp/" in DOCKER_ORACLE
    assert f"pip install --no-cache-dir --no-deps /tmp/{_ORACLE_WHEEL}" in DOCKER_ORACLE
    assert "cognic_tool_oracle_schema-0.1.0" not in DOCKER_ORACLE
    assert 'CMD ["python", "-m", "cognic_tool_oracle_schema.server"]' in DOCKER_ORACLE


def test_as_dockerfile_vendors_the_single_fixture() -> None:
    assert "COPY _local_as.py /app/_local_as.py" in DOCKER_AS
    assert 'CMD ["python", "_local_as.py"]' in DOCKER_AS


# ---------------------------------------------------------------------------
# values + migrate job + kind config + sandbox patch
# ---------------------------------------------------------------------------


def test_values_prod_profile_migrations_off_proof_tag() -> None:
    assert VALUES["image"]["repository"] == "cognic-agentos"
    assert VALUES["image"]["tag"] == "proofm6"
    assert VALUES["image"]["pullPolicy"] == "IfNotPresent"
    assert VALUES["runtimeProfile"] == "prod"
    assert VALUES["migrations"]["enabled"] is False


def test_values_enable_the_m6_sandbox_and_scheduler_planes() -> None:
    # M6 deltas vs the M5 overlay: the scheduler needs the Redis control plane
    # (cache.enabled=true — runtime.scheduler is None otherwise, and the
    # lifespan then never constructs the sandbox backend / skill executor);
    # sandbox.runtimeEnabled=true opens the managed sandbox runtime. The
    # digest-pinned canonical image refs are computed at RUN time (build ->
    # push -> sign) and injected via `helm --set` — the static overlay MUST NOT
    # carry a personal-registry (G7) or placeholder ref the boot would trust.
    assert VALUES["cache"]["enabled"] is True
    assert VALUES["cache"]["url"] == "redis://redis:6379/0"
    assert VALUES["sandbox"]["runtimeEnabled"] is True
    assert "canonicalRuntimeImage" not in VALUES["sandbox"]  # runner --set only
    assert "canonicalEgressProxyImage" not in VALUES["sandbox"]  # runner --set only
    # single-uid broker<->sandbox contract: the kernel pod runs as the SAME uid
    # the backend forces on the sandbox workload (65534), so the broker's 0700
    # socket dir + 0600 socket (spec 5.4 #1/#2) stay connectable by the intended
    # client and NOTHING else.
    assert VALUES["podSecurityContext"] == {"runAsUser": 65534, "fsGroup": 65534}


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


def test_kind_config_mounts_the_docker_sock_and_the_broker_share() -> None:
    # Docker-sibling in kind: the kernel pod needs (a) the HOST docker socket
    # (sibling containers are created on the host daemon) and (b) a broker
    # socket dir that resolves to the SAME absolute path in the pod AND on the
    # docker host (the sibling bind-mounts it), VM-local (never a macOS share —
    # unix sockets do not cross the Docker Desktop file share).
    assert KIND_CONFIG["kind"] == "Cluster"
    mounts = KIND_CONFIG["nodes"][0]["extraMounts"]
    pairs = {(m["hostPath"], m["containerPath"]) for m in mounts}
    assert ("/var/run/docker.sock", "/var/run/docker.sock") in pairs
    assert (
        "/var/lib/cognic-proof-m6-broker",
        "/var/lib/cognic-proof-m6-broker",
    ) in pairs


def test_sandbox_patch_threads_tmpdir_docker_sock_and_broker_share() -> None:
    spec = SANDBOX_PATCH["spec"]["template"]["spec"]
    container = next(c for c in spec["containers"] if c["name"] == "agentos")
    env = {e["name"]: e.get("value") for e in container["env"]}
    # the broker (core/skill/broker.py) creates its per-invocation 0700 dir
    # under tempfile.gettempdir() — TMPDIR points it at the host-shared path
    assert env["TMPDIR"] == "/var/lib/cognic-proof-m6-broker"
    mount_pairs = {(m["name"], m["mountPath"]) for m in container["volumeMounts"]}
    assert ("docker-sock", "/var/run/docker.sock") in mount_pairs
    assert ("broker-share", "/var/lib/cognic-proof-m6-broker") in mount_pairs
    volumes = {v["name"]: v for v in spec["volumes"]}
    assert volumes["docker-sock"]["hostPath"]["path"] == "/var/run/docker.sock"
    assert volumes["broker-share"]["hostPath"] == {
        "path": "/var/lib/cognic-proof-m6-broker",
        "type": "DirectoryOrCreate",
    }
    # the root-owned hostPath dir must be writable by the pod uid (65534)
    init = next(c for c in spec["initContainers"] if c["name"] == "broker-share-perms")
    assert init["securityContext"] == {"runAsUser": 0, "runAsNonRoot": False}
    assert "chmod 1777 /var/lib/cognic-proof-m6-broker" in " ".join(init["command"])


# ---------------------------------------------------------------------------
# seeds (m6 identities; contracts inherited from m4/m5)
# ---------------------------------------------------------------------------


def test_db_seed_stays_a_no_op_guard() -> None:
    assert "INSERT INTO mcp_server_url_override" not in SEED_DB
    assert "INSERT INTO mcp_internal_host_allowlist" not in SEED_DB
    assert 'T="proof-m6"' in SEED_DB
    assert 'NS="${NS:-cognic-proofm6}"' in SEED_DB
    assert "no-op" in SEED_DB
    assert "SOLE" in SEED_DB
    # neither the hook pack nor the skill pack takes ANY lifecycle/DB path
    # (both are trust-register + registry-admit only)
    assert "trust-register" in SEED_DB


def test_vault_seed_targets_the_m6_tenant_by_reference() -> None:
    assert 'NS="${NS:-cognic-proofm6}"' in SEED_VAULT
    assert 'T="proof-m6"' in SEED_VAULT
    assert 'ASHOST="192.88.99.9_9000"' in SEED_VAULT
    assert 'AS="http://192.88.99.9:9000"' in SEED_VAULT
    assert 'echo "{\\"servers\\":[\\"${AS}/\\"]}"' in SEED_VAULT
    assert '"secret/cognic/$T/mcp-as-allowlist"' in SEED_VAULT
    assert '"secret/cognic/$T/mcp-oauth/$ASHOST"' in SEED_VAULT
    assert "BY REFERENCE" in SEED_VAULT
    assert "servers=" not in SEED_VAULT


def test_scripts_are_executable() -> None:
    for name in ("stage-packs.sh", "seed-db.sh", "seed-vault.sh"):
        assert (_PROOF_DIR / name).stat().st_mode & stat.S_IXUSR, f"{name} not executable"


# ---------------------------------------------------------------------------
# manifests
# ---------------------------------------------------------------------------


def test_manifests_use_m6_image_tags_and_keep_the_single_effective_url() -> None:
    oracle_pack = (_PROOF_DIR / "manifests" / "oracle-pack.yaml").read_text()
    auth_server = (_PROOF_DIR / "manifests" / "auth-server.yaml").read_text()
    oracle_xe = (_PROOF_DIR / "manifests" / "oracle-xe.yaml").read_text()
    assert "image: cognic-proof-oracle-pack:m6" in oracle_pack
    assert "image: cognic-proof-as:m6" in auth_server
    assert ":m5" not in oracle_pack and ":m5" not in auth_server
    # single-effective-URL invariant (unchanged from M4/M5/1b-2c)
    assert "clusterIP: 10.96.0.51" in oracle_pack
    assert oracle_pack.count("http://10.96.0.51:8765/mcp") == 2  # server_url == audience
    assert 'externalIPs: ["192.88.99.9"]' in auth_server
    assert 'COGNIC_PROOF_AS_SIGNING_MODE, value: "rs256"' in auth_server
    assert "gvenzl/oracle-xe:21-slim" in oracle_xe
    assert "configMap: { name: oracle-xe-seed }" in oracle_xe


def test_redis_manifest_backs_the_scheduler_control_plane() -> None:
    redis = yaml.safe_load_all((_PROOF_DIR / "manifests" / "redis.yaml").read_text())
    docs = list(redis)
    kinds = {d["kind"] for d in docs}
    assert kinds == {"Deployment", "Service"}
    deploy = next(d for d in docs if d["kind"] == "Deployment")
    assert deploy["metadata"]["name"] == "redis"
    image = deploy["spec"]["template"]["spec"]["containers"][0]["image"]
    assert image.startswith("redis:")
    svc = next(d for d in docs if d["kind"] == "Service")
    assert svc["spec"]["ports"][0]["port"] == 6379


# ---------------------------------------------------------------------------
# README — the three governed-skill bars + the skill-vs-tool split
# ---------------------------------------------------------------------------


def test_readme_states_the_three_governed_skill_bars() -> None:
    # BAR 1 — composition works (200 + fixed shape + dual-layer evidence)
    assert "BAR 1" in README
    assert "schema-summary" in README
    assert "list_tables" in README
    assert "describe_table" in README
    assert "skill.invoked" in README
    assert "audit.tool_invocation" in README
    # BAR 2 — undeclared tool refused by the broker BEFORE MCPHost.call_tool
    assert "BAR 2" in README
    assert "mode=forbidden" in README
    assert "skill_tool_not_declared" in README
    assert "403" in README
    assert "get_constraints" in README
    # BAR 3 — isolation holds (mandatory; never weakened)
    assert "BAR 3" in README
    assert "mode=exfil" in README
    assert "--network none" in README
    assert "skill_runtime_error" in README
    assert "502" in README
    assert "MANDATORY" in README


def test_readme_states_the_skill_vs_tool_split_and_trust_staging() -> None:
    # the SKILL.md package is HOSTED (validated, trust-registered, read-only);
    # ONLY the signed executable action runs — sandboxed + broker-mediated
    assert "SKILL.md" in README
    assert "hosted" in README.lower()
    assert "never executed" in README.lower() or "never runs" in README.lower()
    assert "broker" in README.lower()
    # three-key trust staging is documented (three signers, one prefix)
    assert "trust-roots/_default/cosign.pub" in README
    assert "trust-roots/hook-packs/cognic-hook-schema-guard/cosign.pub" in README
    assert "trust-roots/skill-packs/cognic-skill-schema-summary/cosign.pub" in README
    # released-assets-only + digest pinning are stated
    assert "released assets only" in README.lower()
    assert "sha256" in README.lower()
    # the REAL sandbox admission gate runs (re-home + re-sign, no bypass)
    assert "re-home" in README.lower()
    assert "canonical" in README.lower()
    assert "run-proof-m6.sh" in README


# ---------------------------------------------------------------------------
# runner (Task C3) — env gate, identities, staging, sign/re-home, lifecycle
# ---------------------------------------------------------------------------


def test_runner_env_gated_and_skip_clean() -> None:
    _assert_all(
        RUNNER,
        (
            'if [[ "${COGNIC_RUN_PROOF_M6:-}" != "1" ]]; then',
            "skipped: set COGNIC_RUN_PROOF_M6=1",
            "exit 0",
            'CLUSTER="${KIND_CLUSTER:-cognic-proofm6}"',
            'NS="cognic-proofm6"',
            'PROOF_DIR="infra/proof-m6"',
            'AGENTOS_SRC_SRC="src/cognic_agentos"',
            'AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"',
            'TENANT="proof-m6"',
            'PACK_ID="cognic-tool-oracle-schema"',
            'HOOK_PACK_ID="cognic-hook-schema-guard"',
            'SKILL_PACK_ID="cognic-skill-schema-summary"',
            'SKILL_ID="schema-summary"',
            'PACK_WHEEL="cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"',
        ),
    )
    assert "cognic_tool_oracle_schema-0.1.0" not in RUNNER


def test_runner_stages_via_stage_packs_sh_never_a_source_build() -> None:
    _assert_all(
        RUNNER,
        (
            'STAGING_DST="$PROOF_DIR/proof-m6-staging"',
            'bash "$PROOF_DIR/stage-packs.sh" "$STAGING_DST"',
            "download, not build",
        ),
    )
    assert "stage_released_pack" not in RUNNER
    assert "uv build" not in RUNNER  # released pack artifacts only


def test_runner_builds_m6_images_and_cleans_the_transient_copies() -> None:
    _assert_all(
        RUNNER,
        (
            "for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh openssl",
            'BASE_IMAGE="cognic-agentos:proof1b2-base"',
            'IMAGE="cognic-agentos:proofm6"',
            'MCP_IMAGE="cognic-proof-oracle-pack:m6"',
            'AS_IMAGE="cognic-proof-as:m6"',
            'SKILL_RUNTIME_LOCAL_TAG="cognic-proof-skill-runtime:m6"',
            "docker_build_with_retry -f infra/agentos/Dockerfile --target default-adapters",
            'PROOF_APP_SRC="$PROOF_DIR/proof_m6"',
            'cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.skill-runtime"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.oracle-pack" '
            '-t "$MCP_IMAGE" "$PROOF_DIR"',
            'cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"',
            'docker_build_with_retry -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"',
            'rm -rf "$STAGING_DST" "$AGENTOS_SRC_DST" "$PROOF_DIR/_local_as.py"',
        ),
    )


def test_runner_rehomes_and_signs_the_sandbox_images_no_bypass() -> None:
    """The sandbox admission gate (catalog membership + cosign verify against
    the canonical trust root) runs REAL: the runner mints a proof canonical
    cosign keypair, pushes the skill-runtime + egress-proxy images to a local
    TLS registry on the kind docker network, signs BOTH under the proof
    canonical key, and threads the digest-pinned refs + the trust root into
    the deploy — the documented bank re-home flow, never a fixture flag."""
    _assert_all(
        RUNNER,
        (
            "cosign generate-key-pair",
            "COSIGN_PASSWORD=",
            'REGISTRY_NAME="cognic-proof-m6-registry"',
            "registry:2",
            "REGISTRY_HTTP_TLS_CERTIFICATE",
            "openssl req",
            "subjectAltName",
            "/etc/docker/certs.d",
            "cosign sign --key",
            "RepoDigests",
            "sandbox-egress-proxy",
            # the digest-pinned refs are injected at install time (G7: the
            # static overlay must never carry a personal-registry ref)
            '--set sandbox.canonicalRuntimeImage="$SKILL_RUNTIME_REF"',
            '--set sandbox.canonicalEgressProxyImage="$EGRESS_PROXY_REF"',
        ),
    )
    # no fixture/bypass flags — the REAL admission pipeline decides
    assert "COGNIC_USE_LOCAL_FIXTURE" not in RUNNER
    assert "--allow-insecure-registry" not in RUNNER


def test_runner_provisions_kind_with_the_sandbox_topology() -> None:
    _assert_all(
        RUNNER,
        (
            'kind create cluster --name "$CLUSTER" --config "$PROOF_DIR/kind-config.yaml"',
            'kubectl -n "$NS" patch deploy/rel-agentos --patch-file '
            '"$PROOF_DIR/agentos-sandbox-patch.yaml"',
            'kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/redis.yaml"',
        ),
    )


def test_runner_seeds_through_scripts_and_never_inlines_derived_rows() -> None:
    _assert_all(
        RUNNER,
        (
            'NS="$NS" bash "$PROOF_DIR/seed-vault.sh"',
            'NS="$NS" bash "$PROOF_DIR/seed-db.sh"',
            'helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m6-values.yaml"',
            'sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml"',
            'kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" '
            '-f "$PROOF_DIR/manifests/auth-server.yaml"',
        ),
    )
    assert "INSERT INTO mcp_server_url_override" not in RUNNER
    assert "INSERT INTO mcp_internal_host_allowlist" not in RUNNER


def test_runner_drives_the_m4_operator_lifecycle_for_the_v020_tool() -> None:
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
            '"version": "0.2.0"',
            '"dlp_pre_hooks": ["refuse_forbidden_schema_arg", "explode_schema_guard"]',
            'SIGNED_ARTEFACT_ROOT="/opt/cognic/pack-attestations/$PACK_ID/0.2.0"',
            "mcp.override.set",
            "mcp.allowlist.add",
            "override|$TENANT|$PACK_ID|http://10.96.0.51:8765/mcp",
            "allowlist|$TENANT|10.96.0.51|proof-m6-operator",
        ),
    )
    # neither the hook pack nor the skill pack ever enters the operator
    # lifecycle (both trust-register + registry-admit only)
    assert '"pack_id": "cognic-hook-schema-guard"' not in RUNNER
    assert '"pack_id": "cognic-skill-schema-summary"' not in RUNNER


def test_runner_asserts_skill_and_hook_registry_admission_before_the_bars() -> None:
    """The skill pack is trust-registered + HOSTED at boot: the runner probes
    GET /system/plugins for the registered candidate row (status=registered,
    kind=skills — the cosign gate against the per-pack skill-packs/ trust root
    + the tenant allow-list passed) AND for the hosted_skills ingestion row
    (SKILL.md validated; declared_tools cross-checked), before the bars."""
    _assert_all(
        RUNNER,
        (
            "assert_skill_pack_hosted() {",
            'if row.get("status") != "registered" or row.get("kind") != "skills":',
            '"hosted_skills"',
            'hosted.get("skill_id")',
            "assert_hook_pack_registered() {",
            'if row.get("status") != "registered" or row.get("kind") != "hooks":',
            "dlp_guard_construction_failed",
            'assert_skill_pack_hosted "skill-pack preflight (first boot)"',
            'assert_skill_pack_hosted "BAR 1 preflight (skill pack on the serving pod)"',
            "skill.executor_construction_failed",
            "sandbox.runtime_construction_failed",
        ),
    )


# ---------------------------------------------------------------------------
# runner (Task C3) — the three governed-skill bars
# ---------------------------------------------------------------------------


def test_runner_bar1_composition_works_with_dual_layer_evidence() -> None:
    _assert_all(
        RUNNER,
        (
            '"/api/v1/skills/$SKILL_ID/invoke"',
            '\'{"arguments":{"owner":"COGNIC"}}\'',
            '[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1',
            '"completed"',
            # fixed-shape summary over the seeded schema (2 tables; EMPLOYEES
            # carries FULL_NAME)
            "DEPARTMENTS",
            "EMPLOYEES",
            "FULL_NAME",
            '"table_count"',
            # execution-layer evidence: the two DECLARED tools' governed rows
            "tool_invocation_count_for",
            "payload->>'tool_name'",
            "event_type='audit.tool_invocation'",
            # instruction-layer evidence: ONE digest-only skill.invoked row
            "latest_skill_invoked_payload",
            "event_type='skill.invoked'",
            "arguments_sha256",
            "PROOF M6 (BAR 1) PASS",
        ),
    )


def test_runner_bar2_undeclared_tool_refused_before_call_tool() -> None:
    _assert_all(
        RUNNER,
        (
            '\'{"arguments":{"owner":"COGNIC","mode":"forbidden"}}\'',
            '[ "$HTTP_CODE" = "403" ] || bar_fail "BAR 2 expected HTTP 403 skill_tool_not_declared',
            '"skill_tool_not_declared"',
            # the broker refused BEFORE MCPHost.call_tool: the oracle
            # get_constraints tool has ZERO evidence rows of ANY event type,
            # and the success-row count is UNCHANGED
            "get_constraints",
            'TOOL_INVOCATIONS_BEFORE_BAR2="$(tool_invocation_count)"',
            '[ "$TOOL_INVOCATIONS_AFTER_BAR2" = "$TOOL_INVOCATIONS_BEFORE_BAR2" ]',
            '[ "$GET_CONSTRAINTS_ROWS" = "0" ]',
            '"refused"',
            "PROOF M6 (BAR 2) PASS",
        ),
    )


def test_runner_bar3_isolation_holds_fail_closed() -> None:
    _assert_all(
        RUNNER,
        (
            '\'{"arguments":{"owner":"COGNIC","mode":"exfil"}}\'',
            '[ "$HTTP_CODE" = "502" ] || bar_fail "BAR 3 expected HTTP 502 skill_runtime_error',
            '"skill_runtime_error"',
            '"failed"',
            '[ "$TOOL_INVOCATIONS_AFTER_BAR3" = "$TOOL_INVOCATIONS_BEFORE_BAR3" ]',
            # the exfil probe NEVER succeeds and NO success marker leaks into
            # the response or the evidence chains
            "unexpectedly_succeeded",
            '[ "$EXFIL_MARKER_ROWS" = "0" ]',
            "PROOF M6 (BAR 3) PASS",
            "PROOF M6 (ALL BARS) PASS",
        ),
    )
    # BAR 3 is MANDATORY and never redefined downward
    assert "never redefine" in RUNNER.lower() or "NEVER redefined" in RUNNER


def test_runner_bar_failures_capture_to_validation_results() -> None:
    _assert_all(
        RUNNER,
        (
            "bar_fail() {",
            "docs/VALIDATION-RESULTS.md",
            "## Proof M6 — FAILURE",
            "audit.tool_invocation%",
            "skill.invoked",
            "exit 1",
        ),
    )


def test_runner_api_command_substitution_reloads_http_code() -> None:
    _assert_all(
        RUNNER,
        (
            'HTTP_CODE_FILE="/tmp/proofm6-code"',
            "load_http_code() {",
        ),
    )
    captures = RUNNER.count('="$(api ')
    assert captures == RUNNER.count("load_http_code # after api command substitution")


# ---------------------------------------------------------------------------
# proof app — the M6 multi-actor factory the kernel image CMD boots
# ---------------------------------------------------------------------------


def test_proof_app_package_exists_with_create_proof_app() -> None:
    assert (_PROOF_APP_DIR / "__init__.py").exists()
    assert (_PROOF_APP_DIR / "proof_app.py").exists()
    assert "def create_proof_app() -> FastAPI:" in PROOF_APP


def test_proof_app_is_the_m6_multi_actor_mirror_with_skill_invoke() -> None:
    _assert_all(
        PROOF_APP,
        (
            'PROOF_TENANT: Final = "proof-m6"',
            'PROOF_ROLE_HEADER: Final = "X-Proof-Role"',
            "class MultiActorProofBinder:",
            'subject="proof-m6-author"',
            'subject="proof-m6-reviewer"',
            'subject="proof-m6-operator"',
            'subject="proof-m6-mcp"',
            # the mcp role drives the governed MCP surface AND the skill invoke
            '"mcp.tool.list"',
            '"mcp.tool.invoke"',
            '"skill.invoke"',
            '"pack.override.approval_gate"',
            '"pack.allow_list"',
            '"pack.configure"',
            '"pack.install"',
            "create_async_engine",
            "RuntimeConfigMaterializer",
            "class ProofStagedTrustRootResolver:",
        ),
    )
    # no M5 identity leakage
    assert "proof-m5-" not in PROOF_APP


def test_gitignore_covers_the_m6_transient_build_context_paths() -> None:
    """The runner's trap removes its transient build-context paths, but an
    INTERRUPTED live run must never leave stageable noise — the M3/M4/M5
    defensive-.gitignore precedent. infra/proof-m6/proof_m6/ is deliberately
    NOT ignored: unlike m4/m5's copied-in variants it is tracked source (the
    in-context proof app helper)."""
    gitignore = (_REPO_ROOT / ".gitignore").read_text()
    # Actual ignore ENTRIES only (comment lines may legitimately mention the
    # tracked proof_m6/ path when documenting why it is NOT listed).
    entries = [
        line.strip()
        for line in gitignore.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    for entry in (
        "infra/proof-m6/proof-m6-staging/",
        "infra/proof-m6/cognic_agentos/",
        "infra/proof-m6/_local_as.py",
    ):
        assert entry in entries, f".gitignore missing the M6 transient entry {entry!r}"
    assert "infra/proof-m6/proof_m6/" not in entries, (
        "infra/proof-m6/proof_m6/ is TRACKED SOURCE and must not be gitignored"
    )
