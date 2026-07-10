"""Structural pins for the ``infra/proof-m85/`` tree (M8.5 Sprint C2).

Mirrors ``tests/unit/infra/test_proof_m8_structure.py`` for the M8.5
conversational-slice proof tree (ADR-028 vertical-slice gate, BARs 1-3).
The deployment carries the proven proof-m8 bring-up byte-for-byte (same seven
release pins, same trust-root layout, same M4 operator lifecycle, same seed
matrix); the pins here cover BOTH the carried surfaces AND the M8.5 deltas:

* the SEVEN release digests staged + sha256-pinned fail-closed (byte-identical
  to the proof-m8 pins — the conversation substrate adds no pack);
* the kernel image builds from the ``main @ 235daede`` M8.5 anchor;
* the analyst roles carry ONLY the four ``conversation.*`` scopes and NO
  ``agent.ask`` (maintainer ruling 2026-07-10) — verified on the IMPORTED
  proof app's real ``Actor`` objects, not on string grep;
* the runner sets ``COGNIC_CONVERSATION_CLAIM_TTL_S=600`` (recon finding R1:
  the executor's claim-TTL-exceeds-wall-clock construction guard would
  otherwise fail-soft the whole conversation block into 503s);
* every evidence query is tenant-scoped (``tenant_id='proof-m85'`` — ruling
  2026-07-10; ``conversation_turns`` reads ride the JOIN to
  ``conversations.tenant_id``);
* BAR 1's prior-context recompute is BYTE-COUPLED to the kernel loop's
  framing (``user:<question>\\nassistant:<answer>`` — the extracted runner
  heredoc is EXECUTED against the same samples as the loop's own encoding
  expression over real ``PriorTurn`` values);
* BAR 2 probes ALL FIVE forged history fields and requires an
  ``extra_forbidden`` error naming the field (status alone insufficient);
* BAR 3 proves EXACTLY ONE entitlement row existed, was deleted (readback 0),
  and was restored (readback 1), with a FRESH turn-2 question (ruling R3);
* the R4 plan deviation (no pytest twin of the bash bars) and the R6 OTEL
  posture (inherited diagnostics; no bar depends on spans) are recorded in
  the README;
* key custody: the query-context PRIVATE key is a runtime-mount reference
  only; no private-key material and no bypass flags anywhere in the tree.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROOF_DIR = _REPO_ROOT / "infra" / "proof-m85"

DOCKER_AGENTOS = (_PROOF_DIR / "Dockerfile.agentos-proof").read_text()
DOCKER_ORACLE = (_PROOF_DIR / "Dockerfile.oracle-pack").read_text()
DOCKER_AS = (_PROOF_DIR / "Dockerfile.as").read_text()
STAGE = (_PROOF_DIR / "stage-packs.sh").read_text()
KERNEL_SEED = (_PROOF_DIR / "kernel-seed.sql").read_text()
ORACLE_SEED = (_PROOF_DIR / "oracle-seed" / "seed_schema.sql").read_text()
README = (_PROOF_DIR / "README.md").read_text()
VALUES_RAW = (_PROOF_DIR / "proof-m85-values.yaml").read_text()
VALUES = yaml.safe_load(VALUES_RAW)
RUNNER = (_PROOF_DIR / "run-proof-m85.sh").read_text()
SEED_DB = (_PROOF_DIR / "seed-db.sh").read_text()
SEED_VAULT = (_PROOF_DIR / "seed-vault.sh").read_text()
MIGRATE_RAW = (_PROOF_DIR / "migrate-job.yaml").read_text()
KIND_CONFIG_RAW = (_PROOF_DIR / "kind-config.yaml").read_text()
SANDBOX_PATCH_RAW = (_PROOF_DIR / "agentos-sandbox-patch.yaml").read_text()
PROOF_APP = (_PROOF_DIR / "proof_m85" / "proof_app.py").read_text()
PROOF_APP_INIT = (_PROOF_DIR / "proof_m85" / "__init__.py").read_text()
MANIFEST_ORACLE_XE = (_PROOF_DIR / "manifests" / "oracle-xe.yaml").read_text()
MANIFEST_ORACLE_PACK = (_PROOF_DIR / "manifests" / "oracle-pack.yaml").read_text()
MANIFEST_AS = (_PROOF_DIR / "manifests" / "auth-server.yaml").read_text()
MANIFEST_REDIS = (_PROOF_DIR / "manifests" / "redis.yaml").read_text()
MANIFEST_OTEL = (_PROOF_DIR / "manifests" / "otel-collector.yaml").read_text()

_ALL_TEXTS = {
    "Dockerfile.agentos-proof": DOCKER_AGENTOS,
    "Dockerfile.oracle-pack": DOCKER_ORACLE,
    "Dockerfile.as": DOCKER_AS,
    "stage-packs.sh": STAGE,
    "kernel-seed.sql": KERNEL_SEED,
    "oracle-seed/seed_schema.sql": ORACLE_SEED,
    "README.md": README,
    "proof-m85-values.yaml": VALUES_RAW,
    "run-proof-m85.sh": RUNNER,
    "seed-db.sh": SEED_DB,
    "seed-vault.sh": SEED_VAULT,
    "migrate-job.yaml": MIGRATE_RAW,
    "kind-config.yaml": KIND_CONFIG_RAW,
    "agentos-sandbox-patch.yaml": SANDBOX_PATCH_RAW,
    "proof_m85/__init__.py": PROOF_APP_INIT,
    "proof_m85/proof_app.py": PROOF_APP,
    "manifests/oracle-xe.yaml": MANIFEST_ORACLE_XE,
    "manifests/oracle-pack.yaml": MANIFEST_ORACLE_PACK,
    "manifests/auth-server.yaml": MANIFEST_AS,
    "manifests/redis.yaml": MANIFEST_REDIS,
    "manifests/otel-collector.yaml": MANIFEST_OTEL,
}


def _assert_all(text: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        assert needle in text, f"missing: {needle!r}"


# ---------------------------------------------------------------------------
# The maintainer-locked release pins — BYTE-IDENTICAL to the proof-m8 pins
# (tests/unit/infra/test_proof_m8_structure.py): the M8.5 slice stages the
# SAME seven releases; the conversation substrate adds no pack. A mismatch in
# stage-packs.sh means the staging site no longer fail-closes on the released
# bytes (pins are never silently re-pointed).
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
    "HOOK_WHEEL_SHA256": "1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432",
    "HOOK_PUB_SHA256": "e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49",
}

#: main @ the M8.5 A/B/C1 squash-merge (PR #126).

#: Ruling 2026-07-10: BAR 2 probes ALL FIVE forged history fields, in order.
_BAR2_FIELDS = ("messages", "history", "prior_context", "context", "transcript")

#: The four conversation scopes the analyst roles carry (and nothing else).
_CONVERSATION_SCOPES = frozenset(
    {
        "conversation.create",
        "conversation.read",
        "conversation.post_turn",
        "conversation.close",
    }
)


def _load_proof_app_module() -> ModuleType:
    """Import the PROOF-ONLY app module by path (it lives under infra/, not
    the package tree). Module-level code only builds constants; the fallible
    engine-touching work is deferred into create_proof_app().

    Bytecode writing is suppressed for the exec so the loader can never leave
    a ``__pycache__`` residue inside the proof tree (maintainer finding,
    2026-07-10)."""
    spec = importlib.util.spec_from_file_location(
        "proof_m85_proof_app_under_test", _PROOF_DIR / "proof_m85" / "proof_app.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    prior = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    return module


# ---------------------------------------------------------------------------
# File set + permissions
# ---------------------------------------------------------------------------


def test_proof_dir_carries_the_full_file_set() -> None:
    expected = {
        "Dockerfile.agentos-proof",
        "Dockerfile.as",
        "Dockerfile.oracle-pack",
        "README.md",
        "agentos-sandbox-patch.yaml",
        "kernel-seed.sql",
        "kind-config.yaml",
        "manifests/auth-server.yaml",
        "manifests/oracle-pack.yaml",
        "manifests/oracle-xe.yaml",
        "manifests/otel-collector.yaml",
        "manifests/redis.yaml",
        "migrate-job.yaml",
        "oracle-seed/seed_schema.sql",
        "proof-m85-values.yaml",
        "proof_m85/__init__.py",
        "proof_m85/proof_app.py",
        "run-proof-m85.sh",
        "seed-db.sh",
        "seed-vault.sh",
        "stage-packs.sh",
    }
    actual = {
        str(p.relative_to(_PROOF_DIR))
        for p in _PROOF_DIR.rglob("*")
        if p.is_file() and "proof-m85-staging" not in p.parts and "__pycache__" not in p.parts
    }
    assert actual == expected, f"unexpected/missing: {sorted(actual ^ expected)}"


def test_scripts_are_executable() -> None:
    for name in ("run-proof-m85.sh", "seed-db.sh", "seed-vault.sh", "stage-packs.sh"):
        mode = (_PROOF_DIR / name).stat().st_mode
        assert mode & 0o100, f"{name} lost its owner-execute bit"


def test_no_stale_m8_identifiers_anywhere() -> None:
    """The sweep must be complete: no EXECUTABLE m8 identifier survives (env
    vars, cluster/namespace/image names, the module path). Lineage PROSE
    references to proof-m8 (docs, "mirrors ..." comments) are deliberate and
    allowed — the m85 identifiers all continue with "5", so a negative
    lookahead catches exactly the stale ones."""
    stale = (
        r"proofm8(?!5)",  # cluster/ns/image/tmp-file names
        r"proof_m8(?!5)",  # the python package/module path
        r"COGNIC_PROOF_M8_",  # env-var family (M85_ does not match)
        r"COGNIC_RUN_PROOF_M8=",  # the proof gate (M85= does not match)
    )
    for name, text in _ALL_TEXTS.items():
        for pattern in stale:
            match = re.search(pattern, text)
            assert match is None, f"{name}: stale m8 identifier {match.group(0)!r}"


# ---------------------------------------------------------------------------
# Staging: the seven release pins, fail-closed verification, trust-root layout
# ---------------------------------------------------------------------------


def test_stage_packs_pins_every_release_digest_verbatim() -> None:
    for var, digest in _PINS.items():
        assert f'{var}="{digest}"' in STAGE, f"stage-packs.sh pin drift: {var}"


def test_stage_packs_fails_closed_on_digest_mismatch() -> None:
    _assert_all(STAGE, ("_verify_digest", "die ", "sha256"))
    assert "die() { echo" in STAGE


def test_trust_root_layout_covers_all_packs_including_the_agent_dual_root() -> None:
    _assert_all(
        STAGE,
        (
            "trust-roots/_default/cosign.pub",
            "trust-roots/hook-packs/$HOOK_PACK_ID",
            "trust-roots/skill-packs/$CUSTOMER_PACK_ID",
            "trust-roots/skill-packs/$FINANCIAL_PACK_ID",
            "trust-roots/skill-packs/$CARDS_PACK_ID",
            "trust-roots/skill-packs/$ATMRECON_PACK_ID",
            "trust-roots/agent-packs/$AGENT_PACK_ID",
            "agent-card.pub",
            "agent-card.jws",
        ),
    )


# ---------------------------------------------------------------------------
# Kernel image: anchor, custody, overlays
# ---------------------------------------------------------------------------


def test_kernel_image_provenance_is_computed_verified_and_clean_tree() -> None:
    """finding 2 (2026-07-10): the hardcoded anchor claimed main@235daede
    while the runner overlaid THIS branch's changed kernel source — false
    provenance. The ARG now has NO default (a stale sha cannot resurface);
    the runner computes the revision from a CLEAN kernel-source tree, passes
    it as the build arg, and reads the label back off the built artifact."""
    assert "ARG KERNEL_GIT_SHA\n" in DOCKER_AGENTOS
    assert "ARG KERNEL_GIT_SHA=" not in DOCKER_AGENTOS, "the anchor ARG must carry NO default"
    assert "io.cognic.proof.kernel-anchor=$KERNEL_GIT_SHA" in DOCKER_AGENTOS
    assert 'io.cognic.proof.milestone="m8.5-conversational-slice"' in DOCKER_AGENTOS
    assert "235daede" not in DOCKER_AGENTOS.replace("main@235daede", ""), (
        "a hardcoded kernel sha resurfaced in the Dockerfile"
    )
    _assert_all(
        RUNNER,
        (
            'KERNEL_GIT_SHA="$(git rev-parse HEAD)"',
            "KERNEL_TREE_DIRTY=",
            "kernel source tree is DIRTY",
            '--build-arg KERNEL_GIT_SHA="$KERNEL_GIT_SHA"',
            "docker inspect -f '{{ index .Config.Labels \"io.cognic.proof.kernel-anchor\" }}'",
            '[ "$LABEL_SHA" = "$KERNEL_GIT_SHA" ]',
        ),
    )
    # The clean-tree guard + revision resolution run BEFORE the source copy.
    assert RUNNER.index("git rev-parse HEAD") < RUNNER.index('cp -r "$AGENTOS_SRC_SRC"')


def test_query_context_private_key_is_a_runtime_mount_never_a_layer() -> None:
    # The PUBLIC half is baked; the PRIVATE PEM only ever appears as a /run/
    # mount reference. No COPY of a private key into any layer.
    assert "COPY proof-m85-staging/query-context/" in DOCKER_AGENTOS
    assert "/run/cognic/query-context" in DOCKER_AGENTOS
    for line in DOCKER_AGENTOS.splitlines():
        if line.strip().startswith("COPY"):
            assert "private" not in line.lower(), f"private key COPY'd: {line}"


def test_no_tracked_private_key_material_anywhere_in_the_proof_tree() -> None:
    for name, text in _ALL_TEXTS.items():
        assert "BEGIN PRIVATE KEY" not in text, name
        assert "BEGIN RSA PRIVATE KEY" not in text, name
        assert "BEGIN OPENSSH PRIVATE KEY" not in text, name


def test_no_bypass_flags_anywhere_in_the_proof_tree() -> None:
    # Comment lines may NAME the flags to document the no-bypass posture
    # (the values header's "no dev_mode_skip_cosign" note); only NON-comment
    # occurrences are forbidden — a live assignment would sit on a live line.
    for name, text in _ALL_TEXTS.items():
        live = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for flag in (
            "dev_mode_skip_cosign",
            "COGNIC_DEV_MODE_SKIP_COSIGN",
            "COGNIC_USE_LOCAL_FIXTURE",
        ):
            assert flag not in live, f"{name}: bypass flag {flag!r} on a live line"


# ---------------------------------------------------------------------------
# Seeds: the maintainer matrix (byte-carried from proof-m8, m85 tenant)
# ---------------------------------------------------------------------------


def test_kernel_seed_seeds_exactly_the_four_scopes_for_the_m85_tenant() -> None:
    for scope in ("retail_analytics", "financials", "cards_analytics", "atm_recon"):
        assert f"('proof-m85', '{scope}'" in KERNEL_SEED, scope
    assert "'proof-m8'," not in KERNEL_SEED  # the tenant is proof-m85 everywhere


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
    assert "'analyst.amir', 'cards_analytics'" not in KERNEL_SEED
    assert (
        "'atm_recon', now()"
        not in KERNEL_SEED.split("=== agent_assignments ===")[0].split("=== entitlements ===")[-1]
    ), "atm_recon must be entitled to NOBODY"


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
    assert "'skill', 'atm-recon'" not in KERNEL_SEED


def test_kernel_seed_is_idempotent() -> None:
    assert KERNEL_SEED.count("ON CONFLICT") >= 3


def test_seed_db_applies_kernel_seed_with_readback() -> None:
    _assert_all(SEED_DB, ("kernel-seed.sql", "4|4|4|0", 'T="proof-m85"'))


# ---------------------------------------------------------------------------
# Values: cloud alias, key custody, OTEL posture, prod profile
# ---------------------------------------------------------------------------


def test_values_parse_and_wire_the_cloud_alias_without_bypass() -> None:
    assert VALUES["image"]["tag"] == "proofm85"
    assert VALUES["runtimeProfile"] == "prod"
    assert VALUES["migrations"] == {"enabled": False}
    litellm_config = yaml.safe_load(VALUES["litellm"]["config"])
    models = {m["model_name"]: m["litellm_params"] for m in litellm_config["model_list"]}
    tier1 = models["cognic-tier1-proof-m85"]
    assert tier1["model"] == "openai/gpt-4o"
    assert tier1["api_key"] == "os.environ/COGNIC_PROOF_M85_TIER1_API_KEY"
    litellm_live = "\n".join(
        line
        for line in VALUES["litellm"]["config"].splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "master_key" not in litellm_live  # finding #7: comment-only mention
    assert "general_settings" not in litellm_config


def test_values_otel_is_inherited_diagnostics_not_a_bar_surface() -> None:
    # Ruling R6: the exporter wiring carries forward drift-free, but NO M8.5
    # bar depends on spans — and the values say so.
    assert VALUES["otel"]["exporter"]["endpoint"] == "http://otel-collector:4317"
    assert "INHERITED DIAGNOSTICS ONLY" in VALUES_RAW
    assert "NO M8.5 bar" in VALUES_RAW


def test_runner_never_asserts_on_otel_spans() -> None:
    assert "assert_workforce_span" not in RUNNER
    assert "llm.gateway.agent_workforce_id" not in RUNNER


def test_kernel_litellm_master_key_is_vault_referenced_not_plaintext() -> None:
    assert "COGNIC_LITELLM_MASTER_KEY=vault://secret/cognic/proof-m85/litellm" in RUNNER


# ---------------------------------------------------------------------------
# Runner: gates, env, custody, lifecycle, cleanup
# ---------------------------------------------------------------------------


def test_runner_env_gated_and_provider_key_gated() -> None:
    _assert_all(
        RUNNER,
        (
            'if [[ "${COGNIC_RUN_PROOF_M85:-}" != "1" ]]; then',
            "exit 0",
            'if [[ -z "${COGNIC_PROOF_M85_TIER1_API_KEY:-}" ]]; then',
            "exit 1",
        ),
    )


def _extract_key_probe_block() -> str:
    """The complete provider-key probe block, anchored: from the column-0
    provider-switch ``if`` to its column-0 ``fi`` (the nested RC ``if``/``fi``
    and the ``case`` are indented, so the anchor cannot close early)."""
    match = re.search(
        r'^if \[\[ "\$\{COGNIC_PROOF_M85_ALLOWED_PROVIDERS:-openai\}" == "openai" \]\]; then\n'
        r"(.*?)^fi$",
        RUNNER,
        re.DOTALL | re.MULTILINE,
    )
    assert match is not None, "the provider-key probe block is missing from the runner"
    return match.group(0)


def test_runner_probes_key_validity_before_any_cluster_work() -> None:
    """Live run-2 finding (2026-07-10): a rotated key 401'd only at BAR 1,
    ~25 minutes into a fully-green bring-up. The runner must probe the key
    against the ZERO-SPEND GET /v1/models endpoint at the gate — refusing
    BEFORE any cluster work — and must SKIP (not false-fail) on a provider
    swap. The probe must sit before the config block (CLUSTER=...)."""
    gate_region = RUNNER.split('CLUSTER="${KIND_CLUSTER:-cognic-proofm85}"')[0]
    probe = _extract_key_probe_block()
    assert probe in gate_region, "the probe block must precede the config block"
    _assert_all(
        probe,
        (
            "https://api.openai.com/v1/models",
            "provider-key preflight SKIPPED (provider swap",
            "refusing",
            "BEFORE any cluster work",
        ),
    )
    # No completion endpoint at the gate: the probe must stay zero-spend.
    assert "chat/completions" not in gate_region


def test_key_probe_is_bounded_by_connect_and_total_timeouts() -> None:
    """Review finding #1 (2026-07-10): without --connect-timeout/--max-time,
    "fails in seconds" is not guaranteed — a hung TCP connect could stall the
    gate indefinitely. Mutation-tested: removing --max-time goes RED."""
    probe = _extract_key_probe_block()
    _assert_all(probe, ("--connect-timeout 5", "--max-time 15"))


def test_key_probe_feeds_the_bearer_header_via_stdin_never_argv() -> None:
    """Review finding #3 (2026-07-10): a bearer in curl argv is visible to
    every local process via `ps`. The header must ride stdin (-H @-)."""
    probe = _extract_key_probe_block()
    _assert_all(
        probe,
        (
            "printf 'Authorization: Bearer %s\\n' \"$COGNIC_PROOF_M85_TIER1_API_KEY\"",
            "-H @-",
        ),
    )
    # The argv-borne form must be gone from the ENTIRE runner: no curl line
    # may carry the bearer as an argument.
    for lineno, line in enumerate(RUNNER.splitlines(), start=1):
        if "curl" in line and "Authorization" in line:
            raise AssertionError(f"line {lineno}: bearer header on a curl argv line")


def test_key_probe_diagnoses_transport_auth_and_unexpected_separately() -> None:
    """Review finding #2 (2026-07-10): `|| true` collapsed transport failure,
    DNS failure, timeout, and HTTP refusal into one false "rotate the key"
    diagnosis. The four outcomes must be handled separately: curl nonzero ->
    unreachable/UNDETERMINED; 401/403 -> key REFUSED; 200 -> pass; other ->
    unexpected/UNDETERMINED."""
    probe = _extract_key_probe_block()
    assert "|| true" not in probe, "the probe must not swallow curl's exit status"
    _assert_all(
        probe,
        (
            "KEY_PROBE_RC=$?",
            '[[ "$KEY_PROBE_RC" -ne 0 ]]',
            "could not REACH",
            "transport/DNS/timeout; key validity UNDETERMINED",
            "do NOT rotate the key on this signal",
            'case "$KEY_PROBE_CODE" in',
            "200)",
            "401|403)",
            "REFUSED by api.openai.com",
            "Rotate/re-export the key and re-run",
            "*)",
            "unexpected provider response",
            "do NOT assume a bad key",
        ),
    )
    # Each non-200 arm and the transport arm must fail loud.
    assert probe.count("exit 1") >= 3


def test_runner_sets_the_conversation_claim_ttl_above_the_wall_clock() -> None:
    """Recon finding R1 (ruled 2026-07-10): without this line the executor's
    claim_ttl_s > agent_run_wall_clock_s construction guard fails, the
    lifespan fail-softs the WHOLE conversation block, and every
    /api/v1/conversations route 503s."""
    ttl = re.search(r"COGNIC_CONVERSATION_CLAIM_TTL_S=(\d+)", RUNNER)
    wall = re.search(r"COGNIC_AGENT_RUN_WALL_CLOCK_S=(\d+)", RUNNER)
    assert ttl is not None, "the runner does not set COGNIC_CONVERSATION_CLAIM_TTL_S"
    assert wall is not None, "the runner does not set COGNIC_AGENT_RUN_WALL_CLOCK_S"
    assert int(ttl.group(1)) > int(wall.group(1)), (
        f"claim TTL {ttl.group(1)} must EXCEED the run wall clock {wall.group(1)}"
    )
    assert int(ttl.group(1)) == 600


def test_runner_stages_the_provider_key_as_a_secret_only() -> None:
    assert "proof-m85-provider-key" in RUNNER
    # The key reaches ONLY the litellm pod via secretKeyRef — never a values
    # literal, never an image bake.
    assert "COGNIC_PROOF_M85_TIER1_API_KEY" not in DOCKER_AGENTOS
    assert "secretKeyRef" in RUNNER


def test_runner_stages_via_stage_packs_sh_never_a_source_build() -> None:
    assert "stage-packs.sh" in RUNNER
    assert "pip wheel" not in RUNNER
    assert "python -m build" not in RUNNER


def test_runner_cleanup_trap_tears_everything_down() -> None:
    _assert_all(RUNNER, ("trap cleanup EXIT", "kind delete cluster", "cleanup() {"))


def test_runner_drives_the_m4_operator_lifecycle_for_the_tool() -> None:
    _assert_all(
        RUNNER,
        (
            "SETUP 5 — allow-list",
            "/approve",
            "/allow-list",
            "/runtime-config",
            "/install",
            "mcp.override.set",
            "mcp.allowlist.add",
        ),
    )


def test_runner_step0_asserts_registered_and_hosted_surfaces() -> None:
    _assert_all(
        RUNNER,
        (
            "assert_m8_surfaces",
            "assert_hook_pack_registered",
            "hosted_skills",
            "hosted_agents",
        ),
    )


def test_runner_bar_failures_capture_and_exit_non_zero() -> None:
    """The complete bar_fail body is extracted with an anchored regex (the
    function opens at column 0 and closes with a column-0 ``}``); its OWN
    ``exit 1`` must be the last statement. Mutation-tested 2026-07-10: the
    earlier global-fallback assertion could not fail when bar_fail's exit was
    removed."""
    match = re.search(r"^bar_fail\(\) \{\n(.*?)^\}$", RUNNER, re.DOTALL | re.MULTILINE)
    assert match is not None, "bar_fail() is missing from the runner"
    body = match.group(1)
    _assert_all(
        body,
        (
            "docs/VALIDATION-RESULTS.md",
            "## Proof M8.5 slice — FAILURE",
            "conversation.%",
        ),
    )
    statements = [ln.strip() for ln in body.splitlines() if ln.strip()]
    assert statements[-1] == "exit 1", (
        "bar_fail must END with its own `exit 1` — a captured failure that "
        f"returns 0 redefines every bar downward (last statement: {statements[-1]!r})"
    )


# ---------------------------------------------------------------------------
# Load-bearing SQL: the fail-capturing PSQL helper + the run-3 findings
# ---------------------------------------------------------------------------


def _extract_function(name: str) -> str:
    """A column-0 ``<name>() {`` ... column-0 ``}`` block, verbatim."""
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", RUNNER, re.DOTALL | re.MULTILINE)
    assert match is not None, f"{name}() is missing from the runner"
    return match.group(0)


def test_no_unparenthesized_json_extraction_concatenation() -> None:
    """Live run-3 finding (2026-07-10): PostgreSQL gives ``->>`` and ``||``
    EQUAL precedence (left-associative), so ``payload->>'a' || '|' ||
    payload->>'b'`` parses as ``((payload->>'a' || '|') || payload) ->> 'b'``
    -> ``operator does not exist: text ->> unknown``. Every extraction that
    feeds a concatenation must be parenthesized. Mutation-tested: reverting
    the BAR-1 query to the unparenthesized form goes RED."""
    hazard = re.search(r"->>'[a-z_]+' \|\|", RUNNER)
    assert hazard is None, (
        f"unparenthesized JSON extraction feeding ||: {hazard.group(0)!r} — "
        "wrap the extraction: (payload->>'field') || ..."
    )
    # The corrected BAR-1 query, pinned verbatim.
    assert (
        "(payload->>'prior_context_turns') || '|' || (payload->>'prior_context_sha256')" in RUNNER
    )


def test_psql_routes_failures_through_bar_fail_with_the_sql_error() -> None:
    """Live run-3 finding: a raw psql error inside a command substitution
    aborted the runner under ``set -e`` with NO failure capture. The PSQL
    helper must capture rc + stderr itself and route nonzero through
    bar_fail, preserving the psql error text."""
    psql_fn = _extract_function("PSQL")
    _assert_all(
        psql_fn,
        (
            "set +e",
            "rc=$?",
            "set -e",
            '[ "$rc" -ne 0 ]',
            'bar_fail "load-bearing SQL failed',
            # Review finding 2026-07-10: the stderr capture must live under
            # the per-run PRIVATE $QC_TMP (0700, trap-removed) — a
            # predictable shared /tmp path is a symlink/truncation hazard
            # and leaks residue. Pre-mint calls refuse loud.
            'err_file="$QC_TMP/psql-err"',
            "PSQL called before QC_TMP was minted",
        ),
    )
    assert "/tmp/proofm85-psql-err" not in RUNNER


def test_load_bearing_sql_cannot_bypass_the_fail_capturing_helper() -> None:
    """Direct ``psql -U cognic`` is permitted ONLY as the PSQL definition and
    inside bar_fail's tolerant diagnostics. Everything load-bearing —
    including SETUP-8's materialization reads (converted after run-3) — must
    ride the helper."""
    psql_fn = _extract_function("PSQL")
    bar_fail_fn = _extract_function("bar_fail")
    # Each permitted body must occur EXACTLY once before removal (review
    # hardening 2026-07-10): a duplicated complete function body would
    # otherwise be silently removed by replace() and escape the scan.
    assert RUNNER.count(psql_fn) == 1, "PSQL() body duplicated in the runner"
    assert RUNNER.count(bar_fail_fn) == 1, "bar_fail() body duplicated in the runner"
    remainder = RUNNER.replace(psql_fn, "", 1).replace(bar_fail_fn, "", 1)
    # Occurrence-counting (review finding 2026-07-10): the earlier line-set
    # membership check let a COPIED identical psql line outside the permitted
    # functions pass. With both permitted bodies removed, ZERO direct psql
    # may remain anywhere.
    assert "psql -U cognic" not in remainder, "direct psql outside PSQL()/bar_fail(): " + next(
        ln.strip()[:120] for ln in remainder.splitlines() if "psql -U cognic" in ln
    )
    _assert_all(RUNNER, ('MAT="$(PSQL ', 'DERIVED_ROWS="$(PSQL '))


def test_psql_failure_produces_the_m85_capture_and_a_nonzero_exit(tmp_path: Path) -> None:
    """BEHAVIORAL: the extracted PSQL + bar_fail run VERBATIM in a sandbox
    with a stubbed failing kubectl. A forced SQL error must (1) append the
    '## Proof M8.5 slice — FAILURE' capture carrying the psql error text,
    (2) never reach the statement after the failing substitution, and
    (3) exit the script nonzero (set -e on the failed assignment)."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "kubectl").write_text(
        "#!/usr/bin/env bash\n"
        'echo "ERROR:  operator does not exist: text ->> unknown" >&2\n'
        "exit 1\n"
    )
    (stub_dir / "kubectl").chmod(0o755)
    (tmp_path / "docs").mkdir()
    qc_tmp = tmp_path / "qc-tmp"
    qc_tmp.mkdir(mode=0o700)

    script = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "NS=test-ns\n"
        "TENANT=proof-m85\n"
        "BASE_URL=http://127.0.0.1:1\n"
        "HTTP_CODE=000\n"
        f'QC_TMP="{qc_tmp}"\n'
        'die() { echo "FAIL: $*" >&2; exit 1; }\n'
        + _extract_function("bar_fail")
        + "\n"
        + _extract_function("PSQL")
        + "\n"
        'X="$(PSQL "SELECT broken")"\n'
        'echo "UNREACHABLE"\n'
    )
    (tmp_path / "harness.sh").write_text(script)

    import os

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env['PATH']}"
    result = subprocess.run(
        ["bash", "harness.sh"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, "a failed load-bearing PSQL must exit the runner nonzero"
    assert "UNREACHABLE" not in result.stdout
    capture = (tmp_path / "docs" / "VALIDATION-RESULTS.md").read_text()
    _assert_all(
        capture,
        (
            "## Proof M8.5 slice — FAILURE",
            "load-bearing SQL failed",
            "operator does not exist: text ->> unknown",
            "SELECT broken",
        ),
    )
    # The forced error's stderr capture landed under the sandboxed QC_TMP.
    assert (qc_tmp / "psql-err").exists()
    # No ambient-host-state assertion (review hardening 2026-07-10: a
    # developer's leftover residue from the OLD runner must not fail this
    # suite). Instead, prove at the CODE level that the executed harness —
    # the extracted PSQL + bar_fail included — writes nothing outside
    # tmp_path: the old absolute path is gone from the runner, and no write
    # redirect targets /tmp anywhere in the script (all writes are relative
    # to the tmp_path cwd or $QC_TMP-rooted).
    assert "/tmp/proofm85-psql-err" not in RUNNER
    assert not re.search(r">>?\s*/tmp/", script), (
        "the harness script carries a write redirect into shared /tmp"
    )


# ---------------------------------------------------------------------------
# The conversation surface: analysts ride conversation.* ONLY (no agent.ask)
# ---------------------------------------------------------------------------


def test_runner_exercises_only_the_conversation_surface() -> None:
    """No ask() helper, no /api/v1/agents call anywhere — the analyst roles
    hold no agent.ask, so a stray single-shot ask would 403 (ruling
    2026-07-10)."""
    assert "/api/v1/agents/" not in RUNNER
    assert "\nask() {" not in RUNNER
    _assert_all(RUNNER, ("conv_create() {", "conv_turn() {", "conv_get() {"))
    _assert_all(RUNNER, ("/api/v1/conversations",))


def test_proof_app_analysts_carry_the_four_conversation_scopes_only() -> None:
    """Imported-module pin (not string grep): the two analyst Actors carry
    EXACTLY the four conversation.* scopes; the other roles are unchanged."""
    module = _load_proof_app_module()
    actors = module.MultiActorProofBinder.role_actors()
    assert set(actors) == {"author", "reviewer", "operator", "mcp", "amir", "sara", "foreign"}
    for analyst in ("amir", "sara"):
        assert actors[analyst].scopes == _CONVERSATION_SCOPES, analyst
        assert "agent.ask" not in actors[analyst].scopes
        assert actors[analyst].tenant_id == "proof-m85"
        assert actors[analyst].actor_type == "human"
    assert actors["amir"].subject == "analyst.amir"
    assert actors["sara"].subject == "analyst.sara"
    assert actors["mcp"].scopes == frozenset({"mcp.tool.list", "mcp.tool.invoke"})
    assert actors["operator"].actor_type == "human"
    assert actors["reviewer"].subject != actors["author"].subject


def test_proof_app_source_never_grants_agent_ask() -> None:
    assert '"agent.ask"' not in PROOF_APP
    assert "ConversationRBACScope" in PROOF_APP


# ---------------------------------------------------------------------------
# Tenant scoping: EVERY evidence query carries tenant_id='proof-m85'
# ---------------------------------------------------------------------------


#: Every tenant-carrying table the runner may query. gateway_call_ledger,
#: memory_records, decision_history, audit_event and the mcp carve-out tables
#: all carry the column; conversation_turns does not (its reads JOIN
#: conversations — pinned separately below).
_GOVERNED_TABLES = (
    "decision_history",
    "audit_event",
    "entitlements",
    "conversations",
    "conversation_turns",
    "gateway_call_ledger",
    "memory_records",
    "mcp_server_url_override",
    "mcp_internal_host_allowlist",
    "data_scopes",
    "agent_assignments",
)


def test_every_evidence_query_is_tenant_scoped() -> None:
    """Ruling 2026-07-10 (broadened after review finding #2: the first scanner
    only examined ``PSQL "`` helper calls and missed the direct
    ``kubectl ... psql -c`` queries — SETUP 8's materialization asserts ran
    across ALL tenants). EVERY line of SQL touching a governed table — helper
    or direct — must carry one tenant predicate PER ``FROM`` (the SETUP-8
    UNION ALL line needs two); the entitlement-restore INSERT carries the
    tenant as a VALUES literal."""
    offenders = []
    for lineno, line in enumerate(RUNNER.splitlines(), start=1):
        froms = sum(len(re.findall(rf"FROM {table}\b", line)) for table in _GOVERNED_TABLES)
        inserts = len(re.findall(r"INSERT INTO entitlements\b", line))
        if froms + inserts == 0:
            continue
        predicates = line.count("tenant_id='$TENANT'")
        if inserts and "'$TENANT'" in line:
            predicates += inserts
        if predicates < froms + inserts:
            offenders.append(
                f"{lineno}: needs {froms + inserts} tenant predicate(s), "
                f"has {predicates}: {line.strip()[:160]}"
            )
    assert not offenders, "SQL touching governed tables without tenant scoping:\n" + "\n".join(
        offenders
    )


def test_conversation_turns_reads_ride_the_tenant_join() -> None:
    # conversation_turns has no tenant column; the plaintext reader must JOIN
    # conversations and scope on c.tenant_id.
    for lineno, line in enumerate(RUNNER.splitlines(), start=1):
        if "FROM conversation_turns" in line:
            assert "JOIN conversations" in line and "c.tenant_id='$TENANT'" in line, (
                f"line {lineno} reads conversation_turns without the tenant JOIN"
            )


# ---------------------------------------------------------------------------
# BAR 1: multi-turn e2e — mechanical pins
# ---------------------------------------------------------------------------


def test_runner_bar1_creates_a_conversation_and_two_turns() -> None:
    _assert_all(
        RUNNER,
        (
            "BAR 1 — governed multi-turn e2e",
            'BAR1_CREATE_RESP="$(conv_create amir)"',
            '[ "$HTTP_CODE" = "201" ]',
            "conversation.created",
            "Of those, what is the second-largest customer's total balance?",
            'json_field seq "$BAR1_T1_RESP")" = "1"',
            'json_field seq "$BAR1_T2_RESP")" = "2"',
            "PROOF M8.5 SLICE (BAR 1) PASS",
        ),
    )


def test_runner_bar1_turn2_question_contains_no_entity_name() -> None:
    match = re.search(r'BAR1_T2_Q="([^"]+)"', RUNNER)
    assert match is not None
    for name in ("Ayesha", "Bilal", "Chandni", "Khan", "Sheikh", "Malik"):
        assert name not in match.group(1), f"turn-2 question leaks the entity {name!r}"


def test_runner_bar1_pins_prior_context_mechanically() -> None:
    _assert_all(
        RUNNER,
        (
            "prior_context_turns' FROM decision_history",
            '[ "$BAR1_T2_PCT" = "2" ]',
            # The parenthesized (run-3 precedence-fix) combined read.
            "(payload->>'prior_context_turns') || '|' || (payload->>'prior_context_sha256')"
            " FROM decision_history WHERE event_type='agent.run.started'",
            '[ "$BAR1_T2_PCSHA" = "$RECOMPUTED_PCSHA" ]',
        ),
    )
    # Turn 1 must have run with an EMPTY prior context.
    assert "prior_context_turns != 0" in RUNNER


def test_runner_bar1_two_lineages_and_digest_coupling() -> None:
    """Run-5 ruling (2026-07-10): the chain join is TWO lineages. Context
    lineage: seq=2 -> BAR1_RUN2 -> started/completed. Dispatch lineage:
    seq=1 -> BAR1_RUN1 -> started/completed -> >=1 ok retail
    run_readonly_query dispatch (the three-hop join rides the turn that DID
    dispatch)."""
    _assert_all(
        RUNNER,
        (
            # context lineage (turn 2)
            'HOP1_T2_RUN="$(conv_turn_run_id "$BAR1_CID" 2)"',
            '[ "$HOP1_T2_RUN" = "$BAR1_RUN2" ]',
            'run_event_count "$BAR1_RUN2" agent.run.completed',
            'run_event_count "$BAR1_RUN2" agent.run.started',
            # dispatch lineage (turn 1)
            'HOP1_T1_RUN="$(conv_turn_run_id "$BAR1_CID" 1)"',
            '[ "$HOP1_T1_RUN" = "$BAR1_RUN1" ]',
            'run_event_count "$BAR1_RUN1" agent.run.completed',
            'run_event_count "$BAR1_RUN1" agent.run.started',
            'HOP3_DISPATCH="$(run_dispatch_count "$BAR1_RUN1"',
            '[ "$HOP3_DISPATCH" -ge 1 ]',
            # digest coupling + dual identity (both runs + the conversation)
            'assert_turn_digest_coupling "$BAR1_CID" 1',
            'assert_turn_digest_coupling "$BAR1_CID" 2',
            'run_dual_identity_violations "$BAR1_RUN1" analyst.amir',
            'run_dual_identity_violations "$BAR1_RUN2" analyst.amir',
            'conv_dual_identity_violations "$BAR1_CID" analyst.amir',
        ),
    )
    # The dispatch-lineage hop retains the STRONGER predicate: a successful
    # retail-scoped run_readonly_query with a well-formed args digest.
    hop3_line = next(ln for ln in RUNNER.splitlines() if 'HOP3_DISPATCH="$(' in ln)
    _assert_all(
        hop3_line,
        (
            '"$BAR1_RUN1"',
            "payload->>'outcome'='ok'",
            "run_readonly_query",
            "payload->>'scope_id'='retail_analytics'",
            "args_sha256",
        ),
    )


def test_runner_bar1_never_constrains_the_turn2_dispatch_count() -> None:
    """Run-5 live finding: turn 2 answered ENTIRELY from the replayed
    context with ZERO dispatches (steps_used=1) — correct, desirable
    behaviour that the old hop-3 pin wrongly failed. BAR 1 must never
    query, let alone constrain, the turn-2 run's dispatch count: 0 means
    context reuse; >=1 means legitimate re-verification; neither fails."""
    assert 'run_dispatch_count "$BAR1_RUN2"' not in RUNNER, (
        "BAR 1 re-grew a turn-2 dispatch-count constraint — the run-5 "
        "false invariant (a model-behaviour assumption in a mechanical pin)"
    )
    # And the ruling is documented where the pins live.
    _assert_all(RUNNER, ("DELIBERATELY UNCONSTRAINED",))


def test_bar1_prior_context_recompute_is_byte_coupled_to_the_loop_framing() -> None:
    """Execute the runner's ACTUAL recompute heredoc against tricky samples
    and require byte-equality with the kernel loop's own encoding expression
    over real PriorTurn values (loop.py: '\\n'.join(f'{t.role}:{t.content}')).
    Newlines and quotes inside the plaintext are the drift-prone cases the
    base64 transport exists for."""
    from cognic_agentos.core.agent._types import PriorTurn

    match = re.search(
        r'RECOMPUTED_PCSHA="\$\(python3 - "\$T1_Q_B64" "\$T1_A_B64" <<\'PY\'\n(.*?)\nPY\n',
        RUNNER,
        re.DOTALL,
    )
    assert match is not None, "the BAR-1 recompute heredoc is missing from the runner"
    heredoc = match.group(1)

    question = 'What is 1+1?\nAnd "why"? — naïve ünïcode'
    answer = 'It is 2.\n\nBecause — "arithmetic" saïd so.'
    prior = (
        PriorTurn(role="user", content=question),
        PriorTurn(role="assistant", content=answer),
    )
    loop_encoded = "\n".join(f"{t.role}:{t.content}" for t in prior).encode("utf-8")
    expected = hashlib.sha256(loop_encoded).hexdigest()

    result = subprocess.run(
        [
            sys.executable,
            "-",
            base64.b64encode(question.encode()).decode(),
            base64.b64encode(answer.encode()).decode(),
        ],
        input=heredoc,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == expected, (
        "the runner's recompute framing drifted from the loop's user:<q>\\nassistant:<a> encoding"
    )


def test_kernel_loop_still_uses_the_pinned_framing_expression() -> None:
    """The other half of the byte-coupling: if loop.py changes its encoding,
    this pin fails and the runner recompute must move in lockstep."""
    loop_src = (_REPO_ROOT / "src" / "cognic_agentos" / "core" / "agent" / "loop.py").read_text()
    assert '"\\n".join(f"{t.role}:{t.content}" for t in prior_context)' in loop_src


# ---------------------------------------------------------------------------
# BAR 2: record integrity — five fields, extra_forbidden, zero-loop
# ---------------------------------------------------------------------------


def test_runner_bar2_probes_all_five_forged_fields() -> None:
    assert f"for field in {' '.join(_BAR2_FIELDS)}; do" in RUNNER


def test_runner_bar2_requires_extra_forbidden_naming_the_field() -> None:
    """Status alone is insufficient (ruling 2026-07-10): the 422 body must
    carry a Pydantic extra_forbidden error whose loc names the field."""
    _assert_all(
        RUNNER,
        (
            '[ "$HTTP_CODE" = "422" ]',
            'e.get("type") == "extra_forbidden"',
            'field in [str(part) for part in e.get("loc", [])]',
        ),
    )


def test_runner_bar2_zero_loop_pin() -> None:
    _assert_all(
        RUNNER,
        (
            "AGENT_ROWS_BEFORE_BAR2",
            "AGENT_ROWS_AFTER_BAR2",
            '[ "$AGENT_ROWS_AFTER_BAR2" = "$AGENT_ROWS_BEFORE_BAR2" ]',
            'TURN_ROWS_AFTER_BAR2" = "$TURN_ROWS_BEFORE_BAR2"',
            "PROOF M8.5 SLICE (BAR 2) PASS",
        ),
    )


def test_bar2_forged_body_shape_is_realistic() -> None:
    """The probe body must be a REAL forged-history attempt: a list of
    role/content messages riding the forged field alongside a valid
    user_message."""
    assert (
        '{"user_message": "q", sys.argv[1]: [{"role": "user", "content": "forged history"}]}'
        in RUNNER
    )


def test_the_wire_dto_still_forbids_extras() -> None:
    """The kernel half of BAR 2: PostTurnRequest must still be
    extra="forbid" with exactly one field, or the five 422s become vacuous."""
    dto_src = (
        _REPO_ROOT / "src" / "cognic_agentos" / "portal" / "api" / "conversations" / "dto.py"
    ).read_text()
    assert 'extra="forbid"' in dto_src
    for field in _BAR2_FIELDS:
        assert f"{field}:" not in dto_src, f"PostTurnRequest grew a {field!r} field"


# ---------------------------------------------------------------------------
# BAR 3: mid-conversation revocation — exactly-one, delete, restore, fresh Q
# ---------------------------------------------------------------------------


def test_runner_bar3_proves_exactly_one_entitlement_deleted_and_restored() -> None:
    _assert_all(
        RUNNER,
        (
            'ENT_BEFORE="$(entitlement_count analyst.amir financials)"',
            '[ "$ENT_BEFORE" = "1" ]',
            "entitlement_delete analyst.amir financials",
            '[ "$ENT_AFTER_DELETE" = "0" ]',
            "entitlement_restore analyst.amir financials",
            '[ "$ENT_AFTER_RESTORE" = "1" ]',
            "PROOF M8.5 SLICE (BAR 3) PASS",
        ),
    )


def test_runner_bar3_load_bearing_pins_are_chain_rows() -> None:
    _assert_all(
        RUNNER,
        (
            "payload->>'refusal_reason'='agent_scope_not_entitled'"
            " AND payload->>'scope_id'='financials'",
            '[ "$BAR3_REFUSED" -ge 1 ]',
            '[ "$BAR3_FIN_OK_T2" = "0" ]',
        ),
    )
    # HTTP stays 200 — the bar asserts chain rows, never an error status.
    bar3 = RUNNER.split("BAR 3 — mid-conversation revocation")[1]
    assert '[ "$HTTP_CODE" = "200" ]' in bar3


def test_runner_bar3_turn2_is_a_fresh_question_not_the_turn1_question() -> None:
    """Ruling R3: re-asking the turn-1 question could be answered from the
    replayed transcript without dispatching — turn 2 must need FRESH data."""
    bar3 = RUNNER.split("BAR 3 — mid-conversation revocation")[1]
    turns = re.findall(r'conv_turn amir "\$BAR3_CID" "([^"]+)"', bar3)
    assert len(turns) == 2, "BAR 3 must drive exactly two turns"
    assert turns[0] != turns[1]
    assert "general-ledger" in turns[0]
    assert "profit-and-loss" in turns[1]


def test_runner_bar3_uses_financials_never_bar1s_retail() -> None:
    # Bounded at the M8.5-B marker: the read section AFTER the bars re-reads
    # BAR 1's retail dispatches legitimately; BAR 3 itself must not.
    bar3 = RUNNER.split("BAR 3 — mid-conversation revocation")[1].split("M8.5-B (READ APIS)")[0]
    assert "retail_analytics" not in bar3, "BAR 3 must not touch BAR 1's scope"


# ---------------------------------------------------------------------------
# Migrate job + manifests + README posture
# ---------------------------------------------------------------------------


def test_migrate_job_is_non_hook_with_image_slot_and_head_0016() -> None:
    assert "helm.sh/hook" not in MIGRATE_RAW
    _assert_all(MIGRATE_RAW, ("__AGENTOS_IMAGE__", "alembic upgrade head", "rev 0016"))
    assert "rev 0015" not in MIGRATE_RAW, "the schema-head claim went stale again (finding 2)"


def test_runner_reads_back_the_0016_schema_shape_after_migrate() -> None:
    """finding 2 (2026-07-10): the proof previously CLAIMED head 0015 with no
    readback. The M8.5-B read APIs hard-require the 0016 correlation column +
    the two query indexes, so the runner proves the DEPLOYED shape live."""
    _assert_all(
        RUNNER,
        (
            "SELECT version_num FROM alembic_version;",
            '[ "$SCHEMA_REV" = "0016" ]',
            "column_name='turn_completed_request_id'",
            "ix_decision_history_tenant_event_sequence",
            "ix_conversations_tenant_creator_created",
            '[ "$SHAPE_0016" = "1|2" ]',
        ),
    )
    assert "rev 0015" not in RUNNER, "a stale 0015 schema claim survives in the runner"


def test_manifests_use_m85_image_tags_and_keep_the_single_effective_url() -> None:
    assert "cognic-proof-oracle-pack:m85" in MANIFEST_ORACLE_PACK
    assert "10.96.0.51" in MANIFEST_ORACLE_PACK
    assert "cognic-proof-as:m85" in MANIFEST_AS


def test_sandbox_patch_mounts_the_query_context_secret_read_only() -> None:
    patch = yaml.safe_load(SANDBOX_PATCH_RAW)
    raw = SANDBOX_PATCH_RAW
    assert "proof-m85-query-context" in raw
    assert "/run/cognic/query-context" in raw
    assert patch is not None


def test_readme_carries_the_three_bars_and_the_honesty_boundary() -> None:
    _assert_all(
        README,
        (
            "BAR 1 (governed multi-turn e2e)",
            "BAR 2 (record integrity",
            "BAR 3 (mid-conversation revocation",
            "VERTICAL-SLICE GATE, not the M8.5 production proof",
            "BARs 4\u20137",  # the en dash the README uses
            "Honesty boundary",
            "PROOF M8.5 SLICE (BARS 1-3) PASS",
            "user:<question>\\nassistant:<answer>",
            "`extra_forbidden`",
            "COGNIC_CONVERSATION_CLAIM_TTL_S=600",
            "depends on spans",
            "no M8.5 bar",
        ),
    )


def test_readme_records_the_r4_plan_deviation() -> None:
    _assert_all(
        README,
        (
            "test_conversation_e2e.py",
            "deliberately\n   NOT authored",
            "run-proof-m85.sh",
            "test_proof_m85_structure.py",
        ),
    )


def test_readme_never_overclaims_production() -> None:
    assert "production-proven" in README  # only inside the do-NOT-read-as quote
    assert 'Do not read a\npass as "conversational agent production-proven."' in README


# ---------------------------------------------------------------------------
# json_field regression (carried from the m8 run-12 false-failure finding)
# ---------------------------------------------------------------------------


def test_json_field_reads_a_top_level_field_argument_order_pinned() -> None:
    match = re.search(r"json_field\(\) \{\n(.*?)\n\}", RUNNER, re.DOTALL)
    assert match is not None
    body = match.group(1)
    assert '"$1" "$2"' in body, "json_field must pass (field, json) in order"
    one_liner = re.search(r"python3 -c '([^']+)'", body)
    assert one_liner is not None
    sample = json.dumps({"terminal_state": "completed", "answer": "x"})
    result = subprocess.run(
        [sys.executable, "-c", one_liner.group(1), "terminal_state", sample],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "completed"


# ---------------------------------------------------------------------------
# M8.5-B (READ APIS): the deterministic read-surface section
# ---------------------------------------------------------------------------

_M85B_MARKER = "# ================================ M8.5-B (READ APIS) "


def _m85b_section() -> str:
    parts = RUNNER.split(_M85B_MARKER)
    assert len(parts) == 2, "the M8.5-B (READ APIS) section marker must appear exactly once"
    return parts[1]


def test_runner_m85b_section_follows_the_bars_and_owns_the_final_pass_line() -> None:
    """The M8.5-A marker semantics stay untouched: BARS 1-3 PASS still prints
    BEFORE the M8.5-B section, and the runner's LAST act is the M8.5-B PASS."""
    before, _ = RUNNER.split(_M85B_MARKER)
    assert 'echo "PROOF M8.5 SLICE (BARS 1-3) PASS"' in before
    lines = [ln for ln in RUNNER.splitlines() if ln.strip()]
    assert lines[-1] == 'echo "PROOF M8.5-B (READ APIS) PASS"'
    section = _m85b_section()
    steps = ("1 ", "1b ", "1c ", "2 ", "2b ", "3 ", "3b ", "4 ", "5 ", "6 ")
    for step in steps:
        assert f"M8.5-B READ {step}" in section, f"missing M8.5-B READ {step.strip()}"


def test_runner_m85b_is_read_only_and_deterministic() -> None:
    """The whole point of the section: it reads what BARs 1-3 already wrote.
    ZERO new model calls (no conv_turn), zero record creation, zero
    entitlement mutation, zero SQL, zero pod rolls after the marker."""
    section = _m85b_section()
    for forbidden in (
        "conv_turn ",
        "conv_create ",
        "entitlement_delete",
        "entitlement_restore",
        "PSQL ",
        'PSQL "',
        "roll_and_wait",
    ):
        assert forbidden not in section, f"M8.5-B section must be read-only; found {forbidden!r}"
    # Every HTTP call in the section is a GET.
    for m in re.finditer(r"api (\w+) (\w+) ", section):
        assert m.group(2) == "GET", f"non-GET call in the M8.5-B section: {m.group(0)!r}"


def test_json_assert_is_fail_capturing_and_unique() -> None:
    """json_assert mirrors the PSQL run-3 discipline: rc captured under
    set +e, ANY nonzero exit OR non-ok output routes through bar_fail with
    the captured detail — a raised predicate inside a bare command
    substitution would abort under set -e with no capture."""
    fn = _extract_function("json_assert")
    assert RUNNER.count(fn) == 1, "json_assert() body duplicated in the runner"
    _assert_all(
        fn,
        (
            "set +e",
            "rc=$?",
            "set -e",
            'out="$(python3 -c "$src" "$@" 2>&1)"',
            '[ "$rc" -ne 0 ] || [ "$out" != "ok" ]',
            'bar_fail "$label (rc=$rc): ${out:-<no output>}"',
        ),
    )
    # Every predicate body in the runner ends by printing the ok sentinel.
    assert RUNNER.count('json_assert "M8.5-B') == RUNNER.count('json_assert "')
    section = _m85b_section()
    assert section.count('json_assert "') == section.count('print("ok")')


def test_json_assert_failure_produces_the_capture_and_a_nonzero_exit(tmp_path: Path) -> None:
    """BEHAVIORAL (mirrors the PSQL sandbox test): the extracted json_assert +
    bar_fail run VERBATIM. A failing predicate must (1) append the FAILURE
    capture carrying the assertion detail, (2) never reach the next statement,
    (3) exit nonzero. A passing predicate must continue."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "kubectl").write_text("#!/usr/bin/env bash\nexit 0\n")
    (stub_dir / "kubectl").chmod(0o755)
    (tmp_path / "docs").mkdir()
    qc_tmp = tmp_path / "qc-tmp"
    qc_tmp.mkdir(mode=0o700)

    preamble = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "NS=test-ns\n"
        "TENANT=proof-m85\n"
        "BASE_URL=http://127.0.0.1:1\n"
        "HTTP_CODE=000\n"
        f'QC_TMP="{qc_tmp}"\n'
        'die() { echo "FAIL: $*" >&2; exit 1; }\n'
        + _extract_function("bar_fail")
        + "\n"
        + _extract_function("json_assert")
        + "\n"
    )
    ok_predicate = 'import json, sys\nassert json.loads(sys.argv[1])["x"] == 1\nprint("ok")\n'
    bad_predicate = (
        'import json, sys\nassert json.loads(sys.argv[1])["x"] == 2, "x-must-be-two"\nprint("ok")\n'
    )
    import os

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env['PATH']}"

    green = preamble + (
        f'json_assert "green predicate" \'{ok_predicate}\' \'{{"x": 1}}\'\necho "REACHED"\n'
    )
    (tmp_path / "green.sh").write_text(green)
    result = subprocess.run(
        ["bash", "green.sh"], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "REACHED" in result.stdout

    red = preamble + (
        f'json_assert "red predicate" \'{bad_predicate}\' \'{{"x": 1}}\'\necho "UNREACHABLE"\n'
    )
    (tmp_path / "red.sh").write_text(red)
    result = subprocess.run(
        ["bash", "red.sh"], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    assert result.returncode != 0, "a failing json_assert predicate must exit the runner nonzero"
    assert "UNREACHABLE" not in result.stdout
    capture = (tmp_path / "docs" / "VALIDATION-RESULTS.md").read_text()
    _assert_all(capture, ("## Proof M8.5 slice — FAILURE", "red predicate", "x-must-be-two"))


def test_runner_m85b_list_pins_thread_both_bar_conversations() -> None:
    section = _m85b_section()
    _assert_all(
        section,
        (
            '"$B_LIST_RESP" "$BAR1_CID" "$BAR3_CID" "$AGENT_ID"',
            'assert row["turn_count"] == 2',
            "/api/v1/conversations?limit=1",
            'assert page2["next_cursor"] is None',
            "assert not set(ids1) & set(ids2)",
        ),
    )


def test_runner_m85b_probes_malformed_wrong_version_and_filter_mismatch_cursors() -> None:
    section = _m85b_section()
    _assert_all(
        section,
        (
            "cursor=@@not-base64url@@",
            'json.dumps({"v": 999})',
            "&state=closed",
        ),
    )
    # Each probe asserts 422 + the closed-enum cursor_invalid reason.
    assert section.count('"$HTTP_CODE" = "422"') >= 3
    assert section.count('== "cursor_invalid"') == 3


def test_runner_m85b_transcript_pins_the_ruled_precision_locks() -> None:
    """Live-transcript precision locks (2026-07-10): non-null user_message +
    answer, null erased_at, positive token attribution, the frozen watermark
    on BOTH pages, and the plaintext prefix pin against the BAR-1 question."""
    section = _m85b_section()
    _assert_all(
        section,
        (
            'assert isinstance(t["user_message"], str) and t["user_message"]',
            'assert isinstance(t["answer"], str) and t["answer"]',
            'assert t["erased_at"] is None',
            'assert t["prompt_tokens"] > 0 and t["completion_tokens"] > 0',
            '"Who are the top 3 customers"',
            'assert page1["watermark"] == 2 and page2["watermark"] == 2',
            'assert [t["seq"] for t in page1["turns"]] == [1]',
            'assert [t["seq"] for t in page2["turns"]] == [2]',
        ),
    )


def test_runner_m85b_chain_pins_four_blocks_window_and_retail_dispatch() -> None:
    section = _m85b_section()
    _assert_all(
        section,
        (
            'assert set(doc) == {"turn_completed", "started", "terminal", "dispatches"}',
            'assert st["sequence"] < tm["sequence"] < tc["sequence"]',
            'assert all(st["sequence"] < d["sequence"] < tm["sequence"] for d in dispatches)',
            'd["scope_id"] == "retail_analytics"',
            'assert st["prior_context_turns"] == 0',
            # finding 1 (2026-07-10): the kernel records len(prior_context)
            # — PriorTurn MESSAGES, two per replayed turn — the same
            # semantic BAR 1 pins live. An ==1 here guaranteed a
            # post-spend live failure.
            'assert st["prior_context_turns"] == 2',
            'assert tm["answer_sha256"] == tc["answer_sha256"]',
            # finding 7: the started<->hop1 question-digest coupling + true
            # 64-HEX digests (length alone accepted any 64-char string).
            'assert st["question_sha256"] == tc["question_sha256"]',
            'hex64 = re.compile(r"[0-9a-f]{64}")',
            'assert all(hex64.fullmatch(d["args_sha256"]) for d in dispatches)',
        ),
    )
    assert 'assert st["prior_context_turns"] == 1' not in _m85b_section(), (
        "the run-guaranteed-to-fail ==1 message-count confusion resurfaced (finding 1)"
    )


def test_runner_m85b_turn2_dispatch_count_stays_unconstrained() -> None:
    """The run-5 ruling carried into the read surface: the turn-2 chain pin is
    SHAPE (an array inside the run window), never a count constraint."""
    section = _m85b_section()
    read3b = section.split("==> M8.5-B READ 3b")[1].split("==> M8.5-B READ 4")[0]
    assert "isinstance(dispatches, list)" in read3b
    assert "len(dispatches) >= 1" not in read3b, (
        "READ 3b re-grew a turn-2 dispatch-count constraint — the run-5 false invariant"
    )
    assert "UNCONSTRAINED" in read3b
    # The turn-1 chain (READ 3) DOES require >=1 — the two predicates differ
    # deliberately (turn 1 must have dispatched; turn 2 may have reused context).
    read3 = section.split("==> M8.5-B READ 3 ")[1].split("==> M8.5-B READ 3b")[0]
    assert "len(dispatches) >= 1" in read3


def test_runner_m85b_six_way_byte_identical_404() -> None:
    """unknown-id / cross-actor (sara) / cross-tenant (foreign) x transcript +
    chain: all 404 AND the bodies compare byte-for-byte against the genuine
    unknown-id body. The owner-visible absent turn stays DISTINCT
    (turn_not_found) — the two-level 404 semantic."""
    section = _m85b_section()
    _assert_all(
        section,
        (
            'api sara GET "/api/v1/conversations/$BAR1_CID/transcript"',
            'api foreign GET "/api/v1/conversations/$BAR1_CID/transcript"',
            'api sara GET "/api/v1/conversations/$BAR1_CID/turns/1/chain"',
            'api foreign GET "/api/v1/conversations/$BAR1_CID/turns/1/chain"',
            '[ "$B_404_T_SARA" = "$B_404_T_UNKNOWN" ]',
            '[ "$B_404_T_FOREIGN" = "$B_404_T_UNKNOWN" ]',
            '[ "$B_404_C_SARA" = "$B_404_C_UNKNOWN" ]',
            '[ "$B_404_C_FOREIGN" = "$B_404_C_UNKNOWN" ]',
            '== "conversation_not_found"',
            "turns/99/chain",
            '== "turn_not_found"',
        ),
    )
    assert section.count('"$HTTP_CODE" = "404"') == 7  # six-way + the owner-visible turn probe


def test_runner_m85b_isolation_lists_read_empty() -> None:
    section = _m85b_section()
    _assert_all(
        section,
        (
            'api sara GET "/api/v1/conversations"',
            'api foreign GET "/api/v1/conversations"',
        ),
    )
    assert section.count('assert doc["items"] == [] and doc["next_cursor"] is None, doc') == 2


def test_runner_m85b_access_log_pins() -> None:
    """The access-trail predicate: ok list/transcript/chain records with
    identifiers (incl. the foreign reader's trail — an EMPTY read still logs),
    and ZERO transcript plaintext in any access line. The kubectl|grep runs
    fail-captured (set +e / rc routed through bar_fail) and its artifacts live
    under the private $QC_TMP, never shared /tmp."""
    section = _m85b_section()
    _assert_all(
        section,
        (
            'grep -F "portal.conversations."',
            '"$QC_TMP/conv-access-lines"',
            '"$QC_TMP/conv-access-err"',
            "B_ACCESS_RC=$?",
            '"top 3 customers"',
            '"general-ledger balance"',
            'r.get("tenant_id") == "proof-foreign"',
            'r.get("actor_subject") == "analyst.zara"',
            'r.get("outcome") == "ok"',
            # finding 7: the scan bans EVERY live transcript plaintext
            # fragment (questions AND answers), derived from the READ-2
            # response persisted under the private $QC_TMP — two static
            # question fragments proved almost nothing.
            '"$QC_TMP/conv-transcript.json"',
            "for frag in text.splitlines():",
            "if len(frag) >= 16:",
            'assert fragments, "the live transcript carried no scannable plaintext fragments"',
            "fragment redacted",
        ),
    )
    assert not re.search(r">>?\s*/tmp/", section), "the M8.5-B section writes into shared /tmp"


def test_proof_app_foreign_role_is_the_cross_tenant_reader() -> None:
    """Imported-module pin: the 7th role binds analyst.zara in tenant
    proof-foreign with EXACTLY the four conversation.* scopes — tenant
    isolation is the storage WHERE clause, not the scope set, so the foreign
    reader must be fully scoped."""
    module = _load_proof_app_module()
    actors = module.MultiActorProofBinder.role_actors()
    foreign = actors["foreign"]
    assert foreign.subject == "analyst.zara"
    assert foreign.tenant_id == "proof-foreign"
    assert foreign.tenant_id != module.PROOF_TENANT
    assert foreign.scopes == _CONVERSATION_SCOPES
    assert "agent.ask" not in foreign.scopes
    assert foreign.actor_type == "human"
