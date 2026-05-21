# #477 live-proof evidence — sandbox checkpoint/suspend/wake

> **Task #477 status: LIVE PROOF RECORDED — eligible to close.**
>
> This file now contains a real, witnessed, passing run of the acceptance
> command in the **Recorded runs** section below. The run proves the live
> backend mechanics against the minimal two-image fixture set; it is still not
> a canonical-image publication, cosign, or SBOM supply-chain proof.

## Completion rule (LOCKED)

Per the #477 design spec
(`docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md` §10):

- **#477 stays OPEN** until this file records a passing acceptance run.
- **Opportunistic-run clause.** Any reachable leg may be probed during
  implementation, but a passing-live-proof claim is accepted **only** when the
  run output is recorded here. No completion claim is made off an unrecorded or
  un-witnessed run.
- **No fabricated output.** Paste only the verbatim `pytest` output from a run
  you actually executed and witnessed. Do not pre-fill a Run record block, do
  not copy illustrative output from the runbook, do not mark an acceptance
  criterion `PASS` without the corresponding witnessed output present below.

## How to produce a run

Follow `docs/runbooks/477-live-sandbox-proof.md` end to end. Then copy the
**Run record template** below into the **Recorded runs** section, fill every
field from the actual run, and update the status line at the top of this file
if the run passes all of AC1–AC5.

---

## Recorded runs

### Run record — `2026-05-21`

**Operator:** Codex, user-authorized local run on bmz Mac

**Deployment target:** OpenShift Local / CRC

**Tool versions:**

| Tool | Command | Version |
|---|---|---|
| Host Docker | `docker --version` / `docker info --format ...` | Docker version 28.5.1, build e180ab8; Server Version: 28.5.1; CPUs: 16; Memory: 33864519680 |
| CRC / OpenShift Local | `crc version` / `crc status` | CRC version: 2.57.0+ae41f6; OpenShift version: 4.20.5; MicroShift version: 4.20.0; CRC VM: Running; OpenShift: Running (v4.20.5); RAM Usage: 8.077GB of 33.59GB; Disk Usage: 70.85GB of 128.2GB |
| OpenShift / Kubernetes server | `oc version` | Kubernetes Version: v1.33.5 |
| `oc` client | `oc version` | Client Version: 4.20.5; Kustomize Version: v5.6.0 |
| Active OpenShift user | `oc whoami` | developer |

**OpenShift SCC checks** (runbook step 1g — proves the acceptance run used the
regular CRC developer user, not kubeadmin/anyuid):

| Check | Expected | Actual |
|---|---|---|
| `oc auth can-i use scc/restricted-v2` | `yes` | `yes` |
| `oc auth can-i use scc/anyuid` | `no` | `no` |

**Fixture image refs exercised** (the post-push RepoDigests captured per runbook
step 3 — full `repository@sha256:<64 hex>` form):

| Env var | Captured ref |
|---|---|
| `COGNIC_FIXTURE_RUNTIME_IMAGE_REF` | `default-route-openshift-image-registry.apps-crc.testing/cognic-sandbox/cognic-sandbox-runtime-fixture@sha256:6e4a241d164a400563fa847049624dec1086f8c821cb7ced412b51d8222ac32f` |
| `COGNIC_FIXTURE_PROXY_IMAGE_REF` | `default-route-openshift-image-registry.apps-crc.testing/cognic-sandbox/cognic-sandbox-egress-proxy-fixture@sha256:c9cff4efbb94fc5fc8c306802714b938a8e2aa5ab27000dfe1df2a2cde7743d3` |

**Acceptance command** (the single symmetric invocation — runbook step 5; both
backend env vars set, run NOT split per backend):

```bash
COGNIC_RUN_DOCKER_SANDBOX=1 \
COGNIC_RUN_K8S_SANDBOX=1 \
COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1 \
COGNIC_FIXTURE_RUNTIME_IMAGE_REF='default-route-openshift-image-registry.apps-crc.testing/cognic-sandbox/cognic-sandbox-runtime-fixture@sha256:6e4a241d164a400563fa847049624dec1086f8c821cb7ced412b51d8222ac32f' \
COGNIC_FIXTURE_PROXY_IMAGE_REF='default-route-openshift-image-registry.apps-crc.testing/cognic-sandbox/cognic-sandbox-egress-proxy-fixture@sha256:c9cff4efbb94fc5fc8c306802714b938a8e2aa5ab27000dfe1df2a2cde7743d3' \
uv run pytest tests/conformance/sandbox/test_checkpoint_round_trip.py \
  tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py -v
```

**`pytest` output** (verbatim):

```text
============================= test session starts ==============================
platform darwin -- Python 3.12.8, pytest-9.0.3, pluggy-1.6.0 -- /Users/bmz/development/cognic-agentos/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /Users/bmz/development/cognic-agentos
configfile: pyproject.toml
plugins: cov-7.1.0, asyncio-1.3.0, respx-0.23.1, anyio-4.13.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 8 items

tests/conformance/sandbox/test_checkpoint_round_trip.py::test_checkpoint_round_trip_preserves_workspace_state[docker_sibling] PASSED [ 12%]
tests/conformance/sandbox/test_checkpoint_round_trip.py::test_checkpoint_round_trip_preserves_workspace_state[kubernetes_pod] PASSED [ 25%]
tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py::TestWakeSessionTombstonedConformance::test_case_a_tombstoned_session_wake_refuses[docker_sibling] PASSED [ 37%]
tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py::TestWakeSessionTombstonedConformance::test_case_a_tombstoned_session_wake_refuses[kubernetes_pod] PASSED [ 50%]
tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py::TestWakeSessionTombstonedConformance::test_case_b_tombstoned_plus_valid_metadata_wake_refuses_not_restore[docker_sibling] PASSED [ 62%]
tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py::TestWakeSessionTombstonedConformance::test_case_b_tombstoned_plus_valid_metadata_wake_refuses_not_restore[kubernetes_pod] PASSED [ 75%]
tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py::TestWakeSessionTombstonedConformance::test_case_c_corrupt_tombstone_plus_valid_metadata_wake_refuses[docker_sibling] PASSED [ 87%]
tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py::TestWakeSessionTombstonedConformance::test_case_c_corrupt_tombstone_plus_valid_metadata_wake_refuses[kubernetes_pod] PASSED [100%]

============================== 8 passed in 20.35s ==============================
```

**Acceptance criteria** (marked against the witnessed output pasted above):

| AC | Criterion | Result |
|---|---|---|
| AC1 | `test_checkpoint_round_trip.py` — `docker_sibling` arm passes live (Docker daemon + fixture images) | PASS |
| AC2 | `test_checkpoint_round_trip.py` — `kubernetes_pod` arm passes live (CRC/OpenShift + fixture images) | PASS |
| AC3 | `test_wake_session_tombstoned_conformance.py` — passes on **both** backend arms (tombstone-first wake refusal proven live) | PASS |
| AC4 | symlink + executable-bit preservation verified through the `/workspace` workspace-tar round-trip | PASS |
| AC5 | results for AC1–AC4 recorded in this file | PASS |

**Notes / anomalies:** The run used the CRC `developer` user, not `kubeadmin`,
so the K8s arm exercised restricted-v2 (`yes`) and not anyuid (`no`). The
fixture images are digest-pinned route refs from CRC's exposed registry. This
is a fixture-image runtime-mechanics proof only; it does not prove the Sprint
14 canonical image catalog, signing, or SBOM publication path.

---

## Run record template

> Copy everything between the rules below into the **Recorded runs** section and
> fill it in. Leave a field blank only if it genuinely does not apply, and say
> why.

---

### Run record — `<YYYY-MM-DD>`

**Operator:** `<name>`

**Deployment target:** `<OpenShift Local / CRC | remote OpenShift | plain K8s or kind>`

> If the target is plain Docker-Desktop Kubernetes or `kind`, this leg is
> **non-authoritative** for #477 (the restricted-v2 SCC + `MustRunAsRange` paths
> are not exercised — see runbook "Deployment targets"). State that explicitly
> here and treat AC2/AC3 as **not** satisfied by this run.

**Tool versions:**

| Tool | Command | Version |
|---|---|---|
| Host Docker | `docker --version` | `<fill>` |
| CRC / OpenShift Local | `crc version` | `<fill>` |
| OpenShift cluster | `crc status` / `oc version` | `<fill>` |
| `oc` client | `oc version` | `<fill>` |
| Active OpenShift user | `oc whoami` | `<developer>` |

**OpenShift SCC checks** (runbook step 1g — proves the acceptance run used the
regular CRC developer user, not kubeadmin/anyuid):

| Check | Expected | Actual |
|---|---|---|
| `oc auth can-i use scc/restricted-v2` | `yes` | `<fill>` |
| `oc auth can-i use scc/anyuid` | `no` | `<fill>` |

**Fixture image refs exercised** (the post-push RepoDigests captured per runbook
step 3 — full `repository@sha256:<64 hex>` form):

| Env var | Captured ref |
|---|---|
| `COGNIC_FIXTURE_RUNTIME_IMAGE_REF` | `<fill>` |
| `COGNIC_FIXTURE_PROXY_IMAGE_REF` | `<fill>` |

**Acceptance command** (the single symmetric invocation — runbook step 5; both
backend env vars set, run NOT split per backend):

```
uv run pytest tests/conformance/sandbox/test_checkpoint_round_trip.py \
  tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py -v
```

**`pytest` output** (paste the verbatim output of the run above — including the
final summary line; do not edit or abbreviate):

```text
<paste the actual pytest output here>
```

**Acceptance criteria** (mark `PASS` / `FAIL` only against the witnessed output
pasted above):

| AC | Criterion | Result |
|---|---|---|
| AC1 | `test_checkpoint_round_trip.py` — `docker_sibling` arm passes live (Docker daemon + fixture images) | `<PASS / FAIL>` |
| AC2 | `test_checkpoint_round_trip.py` — `kubernetes_pod` arm passes live (CRC/OpenShift + fixture images) | `<PASS / FAIL>` |
| AC3 | `test_wake_session_tombstoned_conformance.py` — passes on **both** backend arms (tombstone-first wake refusal proven live) | `<PASS / FAIL>` |
| AC4 | symlink + executable-bit preservation verified through the `/workspace` workspace-tar round-trip | `<PASS / FAIL>` |
| AC5 | results for AC1–AC4 recorded in this file | `<PASS / FAIL>` |

**Notes / anomalies:** `<anything that affects how this run should be read — a
non-authoritative target, a retried step, a flake, etc. — or "none">`

---
