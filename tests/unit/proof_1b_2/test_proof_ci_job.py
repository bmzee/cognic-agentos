"""Structural gate (author-time): the Proof 1b-2 CI job in
``.github/workflows/python.yml`` pins the load-bearing CI-wiring invariants
OFFLINE — without GitHub Actions, a ``kind`` cluster, ``docker``, or running the
proof (the job RUNS only when an operator opts in; see below).

Per the Proof 1b-2 plan (Task 10), the workflow ships an OPTIONAL ``proof-1b-2``
job that runs the operator end-to-end runner
(``infra/proof-1b-2/run-proof-1b-2.sh``) in a ``kind`` cluster. The job is
**NEVER default-on** — it executes ONLY when the repo var
``COGNIC_RUN_PROOF_1B2 == '1'`` OR on a manual ``workflow_dispatch``; it builds
four images + spins kind + a live Vault/Postgres, far too heavy for every PR.

**Two-gate contract (HARD BAR #3).** There are TWO independent gates and BOTH are
required:

* the GitHub ``vars.COGNIC_RUN_PROOF_1B2`` (the job ``if``) gates whether the JOB
  runs at all, and
* the ENV ``COGNIC_RUN_PROOF_1B2=1`` set inside the runner step enables the
  RUNNER (the runner self-gates on that ENV var and exits ``0`` cleanly when it is
  unset — ``run-proof-1b-2.sh:23-26``).

A bare ``bash run-proof-1b-2.sh`` would run the job but the runner would silently
``exit 0`` (skip the proof), so the runner step MUST set the ENV gate.

All tests parse the workflow YAML as data only — they never invoke GitHub
Actions / ``bash`` / ``docker`` / a cluster / the runner. (Heads-up: GitHub's
``on:`` key parses as Python ``True`` under ``yaml.safe_load`` because YAML 1.1
treats ``on`` as a boolean — these tests read ``jobs`` only, so it never bites.)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "python.yml"

# The job key the Proof 1b-2 plan (Task 10) adds to the workflow.
_JOB = "proof-1b-2"

# The runner the job invokes (the operator end-to-end proof — Bar 1 + Bar 2).
_RUNNER_PATH = "infra/proof-1b-2/run-proof-1b-2.sh"

# The ENV gate the runner step MUST set (enables the RUNNER; distinct from the
# GitHub `vars.` gate that gates the JOB).
_ENV_GATE = "COGNIC_RUN_PROOF_1B2=1"


def _workflow() -> Any:
    return yaml.safe_load(_WORKFLOW.read_text())


def _proof_job() -> Any:
    jobs = _workflow()["jobs"]
    assert _JOB in jobs, f"the {_JOB!r} job must exist under `jobs` in {_WORKFLOW}"
    return jobs[_JOB]


def _step_runs(job: Any) -> list[str]:
    # `run` values are strings (single-line or block-scalar multi-line) — the
    # ones we care about for the env-gate + runner-path assertions.
    return [step["run"] for step in job["steps"] if "run" in step]


def _step_uses(job: Any) -> list[str]:
    # `uses` values name the actions the job depends on (checkout, kind-action,
    # setup-uv, …).
    return [step["uses"] for step in job["steps"] if "uses" in step]


# --- the workflow parses + the job exists ---------------------------------------


def test_workflow_yaml_parses_and_has_jobs() -> None:
    doc = _workflow()
    assert isinstance(doc, dict), "the workflow must parse to a mapping"
    assert isinstance(doc.get("jobs"), dict), "the workflow must carry a `jobs` mapping"


def test_proof_1b2_job_exists() -> None:
    # The Task-10 job must be present under `jobs`.
    assert _JOB in _workflow()["jobs"], f"the {_JOB!r} job must exist under `jobs`"


# --- NEVER default-on: BOTH gate clauses present (the user's #1 emphasis) --------


def test_proof_1b2_job_is_never_default_on() -> None:
    # The job `if` is the JOB gate. It MUST reference BOTH the repo var
    # (`vars.COGNIC_RUN_PROOF_1B2`) AND a manual `workflow_dispatch` — and nothing
    # else may make it run. The presence of the `if` at all is what keeps the job
    # off every normal PR/push; pin both clauses so a refactor can't quietly drop
    # the var gate (which would make it default-on for dispatch) or the dispatch
    # clause (which would make it unrunnable by hand).
    job = _proof_job()
    assert "if" in job, f"the {_JOB!r} job MUST carry an `if` gate (never default-on)"
    gate = job["if"]
    assert isinstance(gate, str), "the job `if` must be a string expression"
    assert "vars.COGNIC_RUN_PROOF_1B2" in gate, (
        "the job `if` must gate on the repo var `vars.COGNIC_RUN_PROOF_1B2`"
    )
    assert "workflow_dispatch" in gate, (
        "the job `if` must allow a manual `workflow_dispatch` trigger"
    )


# --- the runner step sets the ENV gate AND runs the runner (HARD BAR #3) ---------


def test_proof_1b2_runner_step_sets_env_gate_and_runs_the_runner() -> None:
    # SOME step's `run` must set the ENV gate (COGNIC_RUN_PROOF_1B2=1 — enables the
    # RUNNER, which self-gates + exits 0 if unset) AND invoke the runner script in
    # the SAME command. A bare `bash run-proof-1b-2.sh` (env unset) would run the
    # job but silently skip the proof — the two must ride one `run` string.
    runs = _step_runs(_proof_job())
    assert any(_ENV_GATE in run and _RUNNER_PATH in run for run in runs), (
        f"a step `run` must set {_ENV_GATE!r} AND invoke {_RUNNER_PATH!r} in one command "
        f"(runner self-gates on the ENV var — run-proof-1b-2.sh:23-26)"
    )


# --- the job uses helm/kind-action (kind + helm + kubectl) -----------------------


def test_proof_1b2_uses_kind_action() -> None:
    # The runner preflight requires kind/helm/kubectl on PATH
    # (run-proof-1b-2.sh:112); `helm/kind-action` provides them (mirrors the
    # `kind-smoke` job).
    uses = _step_uses(_proof_job())
    assert any(action.startswith("helm/kind-action") for action in uses), (
        "the job must use `helm/kind-action` to provide kind + helm + kubectl"
    )


# --- the job is a plain ubuntu runner, mirroring kind-smoke ----------------------


def test_proof_1b2_runs_on_ubuntu_latest() -> None:
    assert _proof_job().get("runs-on") == "ubuntu-latest", (
        f"the {_JOB!r} job must run on ubuntu-latest (mirrors the kind-smoke job)"
    )


# --- syft/grype are version + sha256 pinned (no `curl | sh`) — supply-chain ------

# The pinned syft/grype versions + checksums. Computed from the linux_amd64 release
# tarballs AND cross-checked against anchore's published checksums.txt (both agreed).
# A version bump MUST re-fetch the matching SHA — the version + checksum ride together.
_SYFT_VERSION = "1.45.1"
_SYFT_SHA256 = "20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716"
_GRYPE_VERSION = "0.114.0"
_GRYPE_SHA256 = "edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343"


def test_syft_grype_are_version_and_sha256_pinned() -> None:
    # syft/grype install via PINNED release tarballs + `sha256sum -c` verification
    # (the cosign shape). Pin the exact version + checksum vars so a silent bump
    # (which invalidates the checksum) is caught here.
    runs = "\n".join(_step_runs(_proof_job()))
    for token in (
        f"SYFT_VERSION={_SYFT_VERSION}",
        f"SYFT_SHA256={_SYFT_SHA256}",
        f"GRYPE_VERSION={_GRYPE_VERSION}",
        f"GRYPE_SHA256={_GRYPE_SHA256}",
    ):
        assert token in runs, f"the syft/grype install must pin {token!r}"
    assert "sha256sum -c" in runs, (
        "the syft/grype install must verify the download via `sha256sum -c` before install"
    )


def test_no_curl_pipe_sh_supply_chain_antipattern() -> None:
    # HARD supply-chain guard: NO `curl … | sh` from a mutable install script
    # (e.g. raw.githubusercontent.com/anchore/.../main/install.sh — it can change
    # after review) anywhere in the proof-1b-2 job. Pinned tarball + checksum is the
    # only acceptable install shape (mirrors cosign).
    runs = "\n".join(_step_runs(_proof_job()))
    assert "install.sh" not in runs, (
        "no `install.sh` — install scripts from a mutable branch are forbidden (pin the tarball)"
    )
    # `| sh` as a COMMAND (curl … | sh), NOT the legit `| sha256sum` — the `\b` after
    # `sh` excludes `sha256sum` (sh->a is mid-word, no boundary).
    assert not re.search(r"\|\s*sh\b", runs), (
        "no `curl | sh` pattern — pin the release tarball + verify sha256 instead"
    )
