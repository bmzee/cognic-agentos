"""Structural gate (author-time): the Proof 1b-2 runner + Helm values + README
pin the load-bearing end-to-end-proof invariants OFFLINE — without a ``kind``
cluster, ``docker``, ``helm``, ``kubectl``, or running the proof (the runner RUNS
only at the operator-run T9 stage, gated behind ``COGNIC_RUN_PROOF_1B2=1``).

Per the Proof 1b-2 plan (Task 9), ``infra/proof-1b-2/`` ships:

* ``run-proof-1b-2.sh`` — the operator-run end-to-end runner. It is env-gated on
  ``COGNIC_RUN_PROOF_1B2`` and exits ``0`` cleanly when the gate is unset (inert in
  any non-operator context). It drives Bar 1 (the carve-out checkpoint) then Bar 2
  (the full governed loop), and deletes the cluster on exit (``trap cleanup EXIT``).
* ``proof-1b-2-values.yaml`` — the Helm overlay pinning the proof image
  (``cognic-agentos:proof1b2``), the ``prod`` runtime profile, and migrations OFF.
* ``README.md`` — records the proof-only-binder caveat (production still needs a
  real bank-overlay ``ActorBinder``) + the run command.

**Seed-drift contract (HARD BAR #4).** The runner CALLS the Task-8 seed scripts
(``seed-db.sh`` / ``seed-vault.sh``) — it MUST NOT re-inline the override/allow-list
SEED INSERTs (the override seed contract lives in ``seed-db.sh`` alone). The runner
DOES legitimately contain the Bar 1 ``DELETE FROM mcp_internal_host_allowlist`` delta
+ the ``10.96.0.50`` audit-log assertion — that is the runner's own negative-test
logic, NOT seeding. These tests therefore assert the override INSERT is absent but
DO NOT assert the absence of ``10.96.0.50`` / ``mcp_internal_host_allowlist`` (both
are expected in the Bar 1 block).

All tests read the three files as text only — they never invoke ``bash`` / ``docker``
/ ``kubectl`` / a cluster / the runner.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROOF_DIR = _REPO_ROOT / "infra" / "proof-1b-2"
_RUNNER = _PROOF_DIR / "run-proof-1b-2.sh"
_VALUES = _PROOF_DIR / "proof-1b-2-values.yaml"
_README = _PROOF_DIR / "README.md"

# The env gate that makes the operator-run proof inert by default — byte-identical
# to the guard the runner ships (mirrors the 1b-1 ``COGNIC_RUN_PROOF_1B`` gate).
_GATE_GUARD = 'if [[ "${COGNIC_RUN_PROOF_1B2:-}" != "1" ]]; then'

# The two DISTINCT outcome markers — Bar 1 is a CHECKPOINT, Bar 2 is COMPLETION.
_BAR1_MARKER = "BAR 1 PASS"
_BAR2_MARKER = "PROOF 1b-2 (BAR 2) PASS"


def _runner_text() -> str:
    return _RUNNER.read_text()


def _values_text() -> str:
    return _VALUES.read_text()


def _readme_text() -> str:
    return _README.read_text()


# --- existence + strict bash ----------------------------------------------------


def test_runner_artifacts_exist() -> None:
    assert _RUNNER.is_file(), f"Proof 1b-2 runner not found at {_RUNNER}"
    assert _VALUES.is_file(), f"Proof 1b-2 values not found at {_VALUES}"
    assert _README.is_file(), f"Proof 1b-2 README not found at {_README}"


def test_runner_is_strict_bash() -> None:
    # `set -euo pipefail` is load-bearing: a failed build/seed/probe step MUST abort
    # the runner (and fire the cleanup trap), not silently continue past a Bar.
    text = _runner_text()
    assert text.startswith("#!/usr/bin/env bash"), "runner must start with the bash shebang"
    assert "set -euo pipefail" in text, "runner must `set -euo pipefail`"


# --- env gate + clean early exit ------------------------------------------------


def test_runner_is_env_gated_on_proof_1b2() -> None:
    # The runner is operator-only — it gates on COGNIC_RUN_PROOF_1B2 so it never
    # builds images / spins kind in a non-operator context.
    text = _runner_text()
    assert "COGNIC_RUN_PROOF_1B2" in text, "runner must reference COGNIC_RUN_PROOF_1B2"
    assert _GATE_GUARD in text, "runner must carry the COGNIC_RUN_PROOF_1B2 != 1 gate guard"


def test_runner_exits_zero_cleanly_when_gate_unset() -> None:
    # The user's emphasis: with the gate UNSET the runner must exit 0 cleanly. Prove
    # the clean `exit 0` lives INSIDE the gate guard block (between the guard `then`
    # and its closing `fi`), so an unset gate short-circuits before any side effect.
    text = _runner_text()
    start = text.index(_GATE_GUARD)
    end = text.index("\nfi", start)
    guard_block = text[start:end]
    assert "exit 0" in guard_block, (
        "the gate guard block must `exit 0` when COGNIC_RUN_PROOF_1B2 is unset"
    )


# --- seed scripts CALLED, override INSERT NOT inlined ---------------------------


def test_runner_calls_both_seed_scripts() -> None:
    # The runner CALLS the Task-8 seed scripts for the seeding (single source of
    # truth) rather than duplicating their logic.
    text = _runner_text()
    assert "seed-db.sh" in text, "runner must call seed-db.sh (not inline the DB seed)"
    assert "seed-vault.sh" in text, "runner must call seed-vault.sh (not inline the Vault seed)"


def test_runner_does_not_inline_the_override_insert() -> None:
    # The override SEED INSERT must live ONLY in seed-db.sh — re-inlining it in the
    # runner is the drift class HARD BAR #4 forbids. (The Bar 1 DELETE + the
    # 10.96.0.50 audit assertion are the runner's own negative-test logic and ARE
    # expected — they are deliberately NOT asserted-absent here.)
    assert "INSERT INTO mcp_server_url_override" not in _runner_text(), (
        "the override seed INSERT must not be inlined in the runner — it lives in seed-db.sh"
    )


def test_runner_contains_the_bar1_negative_test_logic() -> None:
    # Positive guardrail: the Bar 1 allow-list-removed delta IS the runner's own
    # logic. The DELETE + the 10.96.0.50 audit_event-table assertion legitimately appear
    # here (a negative test, NOT seeding) — pin their presence so a refactor can't quietly
    # drop the load-bearing carve-out check.
    text = _runner_text()
    assert "DELETE FROM mcp_internal_host_allowlist" in text, (
        "Bar 1 must DELETE the allow-list row to prove the carve-out is load-bearing"
    )
    assert "10.96.0.50" in text, "Bar 1 must assert the permit/refusal against host 10.96.0.50"


def test_bar1_evidence_reads_db_and_api_surfaces_not_stdout() -> None:
    # The permit (audit.mcp_allowlist_permitted) is a DD-2 audit-store event persisted to the
    # audit_event table — NOT a stdout log (AuditStore.append never logs the event); the refusal
    # reason lands in the HTTP response BODY and discovery_status=refused on /system/plugins. The
    # runner must read THOSE surfaces — the earlier `kubectl logs | grep` could never find the
    # audit event, which is what failed the live run (Proof 1b-2 attempt-5 finding).
    text = _runner_text()
    assert "audit_event" in text, (
        "Bar 1.1 must query the audit_event table for the permit (the event is not on pod stdout)"
    )
    assert "proof1b2-refuse-body" in text, (
        "Bar 1.2 must assert mcp_discovery_url_refused in the captured HTTP response body"
    )
    assert 'ds == "refused"' in text, (
        "Bar 1.2 must assert discovery_status=refused via /system/plugins (Bar 2's evidence model)"
    )


# --- distinct Bar markers + cleanup trap ----------------------------------------


def test_runner_prints_distinct_bar1_checkpoint_and_bar2_completion_markers() -> None:
    # Bar 1 is a CHECKPOINT (not the final pass); Bar 2 is COMPLETION. The two
    # markers must be DISTINCT so an operator can tell the checkpoint from the
    # completion in the run output.
    text = _runner_text()
    assert _BAR1_MARKER in text, f"runner must print the Bar 1 checkpoint marker {_BAR1_MARKER!r}"
    assert _BAR2_MARKER in text, f"runner must print the Bar 2 completion marker {_BAR2_MARKER!r}"
    assert _BAR1_MARKER != _BAR2_MARKER, "the two Bar markers must be distinct strings"


def test_runner_traps_cleanup_on_exit() -> None:
    # The runner deletes the kind cluster on exit so a failed proof leaves no
    # dangling cluster — `trap cleanup EXIT` is the only delete path.
    assert "trap cleanup EXIT" in _runner_text(), "runner must `trap cleanup EXIT`"


# --- Helm values pins -----------------------------------------------------------


def test_values_pin_proof_image_prod_profile_and_migrations_off() -> None:
    # The overlay deltas vs the base chart: the proof image tag, the prod runtime
    # profile, and migrations OFF (the proof runs a non-hook migration Job — Gap 3).
    data = yaml.safe_load(_values_text())
    assert data["image"]["tag"] == "proof1b2", "values must pin image.tag: proof1b2"
    assert data["runtimeProfile"] == "prod", "values must keep runtimeProfile: prod"
    assert data["migrations"]["enabled"] is False, "values must pin migrations.enabled: false"


# --- README caveat + run command ------------------------------------------------


def test_readme_records_proof_only_binder_caveat() -> None:
    # The deployed image runs a PROOF-ONLY fixed-actor binder; production still needs
    # a real bank-overlay ActorBinder. The caveat must be recorded so the proof is
    # never mistaken for a production identity path.
    assert "bank-overlay ActorBinder" in _readme_text(), (
        "README must record the proof-only-binder caveat (production needs a real "
        "bank-overlay ActorBinder)"
    )


def test_readme_records_the_run_command() -> None:
    assert "COGNIC_RUN_PROOF_1B2=1 bash infra/proof-1b-2/run-proof-1b-2.sh" in _readme_text(), (
        "README must record the operator run command"
    )


# --- Step 3 staging module exists + imports (regression for the runner's Step 3) -


def test_runner_references_the_staging_module() -> None:
    # The runner's Step 3 stages the trust inputs by invoking this module by path
    # (`python -m tests.integration.proof_1b.stage_trust_inputs`). Pin the
    # runner<->module linkage so a rename on either side surfaces here.
    assert "tests.integration.proof_1b.stage_trust_inputs" in _runner_text(), (
        "runner Step 3 must invoke `python -m tests.integration.proof_1b.stage_trust_inputs`"
    )


def test_staging_module_imports() -> None:
    # The runner's Step 3 runs the staging module BEFORE the image build. It MUST
    # exist + import on THIS branch (copied from feat/pack-loop-proof-1b; its
    # tests.integration.pack_loop._authoring dependency is already present here) —
    # else the operator run dies with ModuleNotFoundError before the proof starts.
    # import_module fails loud if the module is missing; `stage` is the entry point
    # the `python -m` invocation drives.
    import importlib

    mod = importlib.import_module("tests.integration.proof_1b.stage_trust_inputs")
    assert hasattr(mod, "stage"), "stage_trust_inputs must expose the stage() entry point"
