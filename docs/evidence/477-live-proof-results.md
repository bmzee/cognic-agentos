# #477 live-proof evidence — sandbox checkpoint/suspend/wake

> **Task #477 status: OPEN.**
>
> This file is a **template**. It contains **no** results. Task #477 remains
> OPEN until a real, witnessed, passing run of the acceptance command is
> recorded in a Run record block below. Merging the #477 PR delivers the
> *artifacts* (fixture images, the `egress_proxy_image` seam,
> `_FixtureOnlySandboxCatalog`, the conftest wiring, the runbook) — it does
> **not** close #477. The recorded live evidence closes it.

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

_No witnessed run recorded yet — #477 remains OPEN._

<!-- Append one filled Run record block here per witnessed run. -->

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
| OpenShift cluster | `oc get clusterversion version -o jsonpath='{.status.desired.version}'` | `<fill>` |
| `oc` client | `oc version --client` | `<fill>` |

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
