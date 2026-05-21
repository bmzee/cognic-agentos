# Runbook — #477 live sandbox checkpoint/suspend/wake proof

**Audience:** an operator running the env-gated sandbox conformance suite against a
live Docker daemon **and** a live OpenShift cluster, to produce the recorded
evidence that closes task #477.

**Status of #477:** the implementation artifacts (fixture images, the
`egress_proxy_image` seam, `_FixtureOnlySandboxCatalog`, conftest wiring) are
merged. Task #477 nonetheless stays **OPEN** until a passing run of the
acceptance command in step 5 is recorded in
`docs/evidence/477-live-proof-results.md`. This runbook is the procedure that
produces that evidence. See the #477 design spec
`docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md` (§9, §10)
for the contract.

## What this run proves — and what it does not

**Proves (acceptance criteria AC1–AC4):** that `DockerSiblingSandboxBackend` and
`KubernetesPodSandboxBackend` correctly checkpoint → suspend → wake a sandbox
session — workspace tar round-trip with symlink + executable-bit preservation,
and tombstone-first wake refusal — against **real, runnable, registry-backed
container images** on both backends.

**Does NOT prove:** supply-chain admission of the *canonical* cognic sandbox
images (cosign signature verification, SBOM policy on the canonical catalog).
The fixture images are minimal throwaway images; `_FixtureOnlySandboxCatalog`
no-op-passes cosign/SBOM verification for exactly the two fixture digests. That
is by design — supply-chain admission of the canonical set has its own dedicated
tests and is Sprint 14 deploy-kit scope. This run proves **runtime mechanics**,
not supply-chain trust.

---

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| **Docker Desktop** running | The `docker_sibling` backend talks to the host Docker daemon via `aiodocker`. Confirm `docker info` succeeds. Docker Desktop's own bundled Kubernetes is **not** used and may be left disabled. |
| **CRC (OpenShift Local)** installed | The `kubernetes_pod` backend's authoritative target. Install per <https://crc.dev>. `crc version` should report a recent release. |
| **`oc` CLI** on `PATH` | Bundled with CRC — `eval "$(crc oc-env)"` puts it on `PATH`. |
| **`uv`** | The repo's Python runner. All `pytest` invocations below use `uv run`. |
| **Local resources** | CRC defaults to 4 vCPU / ~9 GiB RAM / 35 GiB disk; the sandbox Pods plus the egress-proxy sidecars need headroom. Recommend **≥6 vCPU and ≥12 GiB RAM** allocated to CRC (`crc config set cpus 6`, `crc config set memory 12288`) and a few GiB free for the host Docker daemon's fixture containers. |
| **A registry reachable by BOTH host Docker and the cluster** | This runbook uses **CRC's internal image registry**, exposed via its default route. The host Docker daemon pushes/pulls through the route; the cluster pulls internally. See step 3 for the alternate (remote registry). |

A plain `docker build` produces a tag and an image ID but **no repository
digest**. AgentOS sandbox admission is digest-axis: `SandboxPolicy.runtime_image`
and the egress-proxy image must both be **digest-pinned OCI refs**
(`repository[:tag]@sha256:<64 lowercase hex>`). A digest-pinned ref only exists
once an image has been **pushed to a registry**. That is why steps 2–3 build,
push, and then capture the post-push `RepoDigest` — and why a registry reachable
by both runtimes is mandatory.

---

## 1. Start CRC and expose its internal registry

```bash
# 1a. Start the cluster.
crc start
eval "$(crc oc-env)"                       # put `oc` on PATH for this shell

# 1b. Log in as kubeadmin (crc prints the credentials; `crc console
#     --credentials` reprints them).
oc login -u kubeadmin https://api.crc.testing:6443

# 1c. Expose the internal image registry on its default route.
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --type=merge -p '{"spec":{"defaultRoute":true}}'

# 1d. Capture the route host and log the host Docker daemon into it.
REGISTRY_ROUTE="$(oc get route default-route -n openshift-image-registry \
  -o jsonpath='{.spec.host}')"
echo "registry route: ${REGISTRY_ROUTE}"
oc registry login --registry="${REGISTRY_ROUTE}" --insecure=true

# 1e. Create the namespace the sandbox backend launches Pods into,
#     then grant CRC's regular `developer` user admin in that namespace.
#     The cluster-admin kubeadmin user is used only for setup. The
#     acceptance run itself switches to `developer` so the Pods are
#     admitted by restricted-v2, not the kubeadmin-only anyuid SCC.
#     The conformance conftest defaults COGNIC_K8S_SANDBOX_NAMESPACE
#     to `cognic-sandbox`.
oc get project cognic-sandbox >/dev/null 2>&1 || oc new-project cognic-sandbox
oc adm policy add-role-to-user admin developer -n cognic-sandbox

# 1f. Give the cluster pull access to the registry ROUTE. The fixture
#     refs captured in step 3 are route-host refs — T5 feeds the SAME
#     ref into both the host Docker preflight and the K8s Pod image
#     field, and the host Docker daemon can only reach the registry
#     through the route (it cannot resolve the in-cluster registry
#     service DNS). From the kubelet's perspective the route host is an
#     authenticated external registry: same-project pull rights cover
#     the in-cluster `image-registry...svc:5000` path, NOT the route.
#     So the sandbox Pods need an explicit pull secret for the route,
#     or they ImagePullBackOff before reaching checkpoint/suspend/wake.
#
#     The `--dry-run=client -o yaml | oc apply -f -` form is idempotent:
#     re-run this step verbatim to refresh an expired `oc whoami -t`
#     token (a plain `oc create secret` would fail `AlreadyExists` and
#     leave the stale token in place).
oc create secret docker-registry crc-fixture-pull \
  --docker-server="${REGISTRY_ROUTE}" \
  --docker-username="$(oc whoami)" \
  --docker-password="$(oc whoami -t)" \
  -n cognic-sandbox \
  --dry-run=client -o yaml | oc apply -f -
oc secrets link default crc-fixture-pull --for=pull -n cognic-sandbox

# Verify the link — `crc-fixture-pull` MUST appear in the default
# ServiceAccount's pull secrets before the acceptance run.
oc get serviceaccount default -n cognic-sandbox \
  -o jsonpath='{.imagePullSecrets[*].name}'; echo

# 1g. Switch kubeconfig to the regular CRC developer user for the
#     actual proof run. This is load-bearing: if pytest runs as
#     kubeadmin, OpenShift selects the anyuid SCC, which is not the
#     restricted-v2 posture #477 is meant to prove.
oc login -u developer -p developer https://api.crc.testing:6443
oc project cognic-sandbox
oc auth can-i use scc/restricted-v2
oc auth can-i use scc/anyuid
```

`oc login` writes `~/.kube/config`; the conformance conftest's `kubernetes_pod`
arm loads that default kubeconfig (it tries in-cluster config first, then falls
back to the default kubeconfig). No `KUBECONFIG` export is required if the final
step-1g `oc login` targeted the default config.

The step-1g SCC checks must print `yes` for `restricted-v2` and `no` for
`anyuid`. Record those two lines in the evidence file. A proof run as
`kubeadmin` is not authoritative for #477 because it does not exercise the
restricted-v2 SCC path.

> **TLS note.** CRC's registry route uses a cluster-signed certificate. If
> `docker push` (step 3) fails certificate verification, either add
> `${REGISTRY_ROUTE}` to Docker Desktop → Settings → Docker Engine
> `insecure-registries` and restart Docker, or trust the CRC ingress CA on the
> host. `oc registry login --insecure=true` only covers the login step, not the
> subsequent `docker push`.

---

## 2. Build the two fixture images

The fixture Dockerfiles live in `tests/fixtures/sandbox/`. They take no build
arguments and contain no `COPY` directives, so the build context is irrelevant —
the directory itself is used below.

```bash
RUNTIME_REPO="${REGISTRY_ROUTE}/cognic-sandbox/cognic-sandbox-runtime-fixture"
PROXY_REPO="${REGISTRY_ROUTE}/cognic-sandbox/cognic-sandbox-egress-proxy-fixture"

docker build \
  -f tests/fixtures/sandbox/runtime-fixture.Dockerfile \
  -t "${RUNTIME_REPO}:v1" \
  tests/fixtures/sandbox/

docker build \
  -f tests/fixtures/sandbox/egress-proxy-fixture.Dockerfile \
  -t "${PROXY_REPO}:v1" \
  tests/fixtures/sandbox/
```

The `:v1` tag is a convenience handle for the push only. The fixture **ref** the
test layer consumes is the digest-pinned form captured in step 3 — the tag is
never used as the test input.

---

## 3. Push the images and capture digest-pinned refs

```bash
docker push "${RUNTIME_REPO}:v1"
docker push "${PROXY_REPO}:v1"

# Capture the post-push RepoDigest — the digest-pinned, registry-backed
# ref. This is `repository@sha256:<digest>` (untagged RepoDigest form,
# which is valid input). Do NOT use the `:v1` tag or the image ID.
RUNTIME_REF="$(docker inspect --format '{{index .RepoDigests 0}}' "${RUNTIME_REPO}:v1")"
PROXY_REF="$(docker inspect --format '{{index .RepoDigests 0}}' "${PROXY_REPO}:v1")"

echo "COGNIC_FIXTURE_RUNTIME_IMAGE_REF = ${RUNTIME_REF}"
echo "COGNIC_FIXTURE_PROXY_IMAGE_REF   = ${PROXY_REF}"
```

Each captured ref **must** be `repository[:tag]@sha256:<64 lowercase hex>`. If a
ref is a bare tag, an image ID, or anything without an `@sha256:` digest of
exactly 64 lowercase hex characters, the conformance conftest's
`resolve_fixture_refs()` **fails fast** with a `RuntimeError` pointing back at
this runbook — there is no silent skip and no placeholder fallback. Re-run the
capture if a ref looks wrong; do not hand-edit it.

> **Alternate capture.** `docker buildx build --push --metadata-file out.json`
> writes `containerimage.digest`; combine it with the repository name to form
> the same `repository@sha256:<digest>` ref. `skopeo inspect
> docker://${RUNTIME_REPO}:v1` also reports the digest. Any method that yields
> the genuine post-push repository digest is acceptable.

**Cluster pull.** The captured refs are **route-host** refs
(`${REGISTRY_ROUTE}/cognic-sandbox/...@sha256:...`) — T5 feeds the *same* ref
into both the host Docker preflight and the K8s Pod image field, and the host
Docker daemon can only reach the registry through the route. From the kubelet's
perspective the route host is an authenticated external registry, so the
`cognic-sandbox` Pods pull it via the **`crc-fixture-pull` secret linked in step
1f** — same-project pull rights cover the in-cluster registry *service* path,
not the route. Confirm step 1f's verification line listed `crc-fixture-pull`
before running the acceptance command; without it the K8s arm fails
`ImagePullBackOff` before reaching checkpoint/suspend/wake.

---

## 4. Export the test environment

Export **all five** variables in the **same shell** that will run the acceptance
command:

```bash
export COGNIC_RUN_DOCKER_SANDBOX=1
export COGNIC_RUN_K8S_SANDBOX=1
export COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1
export COGNIC_FIXTURE_RUNTIME_IMAGE_REF="${RUNTIME_REF}"
export COGNIC_FIXTURE_PROXY_IMAGE_REF="${PROXY_REF}"
```

| Variable | Purpose |
|---|---|
| `COGNIC_RUN_DOCKER_SANDBOX=1` | Un-gates the `docker_sibling` conformance arm. |
| `COGNIC_RUN_K8S_SANDBOX=1` | Un-gates the `kubernetes_pod` conformance arm. |
| `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1` | Switches the conftest to fixture mode (`_FixtureOnlySandboxCatalog` + the two fixture refs). |
| `COGNIC_FIXTURE_RUNTIME_IMAGE_REF` | The runtime fixture ref captured in step 3 — flows into `SandboxPolicy.runtime_image`. |
| `COGNIC_FIXTURE_PROXY_IMAGE_REF` | The egress-proxy fixture ref captured in step 3 — flows into each backend's `egress_proxy_image` constructor kwarg. |

Optional: `COGNIC_K8S_SANDBOX_NAMESPACE` overrides the Pod namespace (default
`cognic-sandbox` — the project created in step 1e). Leave it unset to use the
default.

All three `COGNIC_*FIXTURE*` variables are **test-only** — read solely by the
sandbox test conftests, never by any `src/` module. An architecture
import-regression test (`tests/unit/architecture/test_fixture_path_not_in_src.py`)
enforces that boundary.

---

## 5. Acceptance run — single symmetric invocation

Run the two conformance modules in **one** invocation:

```bash
uv run pytest tests/conformance/sandbox/test_checkpoint_round_trip.py \
  tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py -v
```

**DO NOT split this into a Docker-only run and a K8s-only run.** Both modules
carry a module-level `skipif` that requires **both** `COGNIC_RUN_DOCKER_SANDBOX`
and `COGNIC_RUN_K8S_SANDBOX`, and the wake module is additionally marked
`require_both_backends`. A run with only one backend env var set would **skip
the entire module** — a parity test that ran a single backend would false-green
(a tombstone-first ordering regression on one backend would go unnoticed while
the other arm passes). The symmetric gate is deliberate. The per-runtime
*preparation* (steps 1–4) may be staged across sessions; the acceptance *run*
may not be split.

Each module is parametrized over both backend arms (`docker_sibling`,
`kubernetes_pod`). With both env gates set, a backend that cannot actually run
**fails** the run rather than skipping it.

**Expected shape of a passing run** (illustrative — record the *actual* output
in the evidence file, see step 6):

```
test_checkpoint_round_trip.py::test_checkpoint_round_trip_preserves_workspace_state[docker_sibling] PASSED
test_checkpoint_round_trip.py::test_checkpoint_round_trip_preserves_workspace_state[kubernetes_pod] PASSED
test_wake_session_tombstoned_conformance.py::...::test_case_a_tombstoned_session_wake_refuses[docker_sibling] PASSED
test_wake_session_tombstoned_conformance.py::...::test_case_a_tombstoned_session_wake_refuses[kubernetes_pod] PASSED
test_wake_session_tombstoned_conformance.py::...::test_case_b_tombstoned_plus_valid_metadata_wake_refuses_not_restore[docker_sibling] PASSED
test_wake_session_tombstoned_conformance.py::...::test_case_b_tombstoned_plus_valid_metadata_wake_refuses_not_restore[kubernetes_pod] PASSED
test_wake_session_tombstoned_conformance.py::...::test_case_c_corrupt_tombstone_plus_valid_metadata_wake_refuses[docker_sibling] PASSED
test_wake_session_tombstoned_conformance.py::...::test_case_c_corrupt_tombstone_plus_valid_metadata_wake_refuses[kubernetes_pod] PASSED
```

That is 8 passed (1 checkpoint test + 3 wake cases, each × 2 backend arms),
0 skipped, 0 failed.

**Run only the two modules named above — do not target the whole
`tests/conformance/sandbox/` directory in fixture mode.** #477 fixture-wired
exactly those two conformance modules. `test_backend_conformance.py` is *not*
parameterized: it still builds its `SandboxPolicy` with the placeholder
canonical runtime image, which `_FixtureOnlySandboxCatalog` does not allowlist,
so it would fail at catalog admission under
`COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`. The full conformance directory is a
valid target only on the default (canonical-image) path, never in fixture mode.

---

## 6. Record the results

Copy the **actual** `pytest` output, the two captured fixture refs, and the tool
versions into `docs/evidence/477-live-proof-results.md`, filling one run block
per the template there. Task #477 closes only when a passing run is recorded in
that file — merging the #477 PR delivers the artifacts, the recorded evidence
closes the task. **Do not** record a run that was not actually executed and
witnessed; do not paste this runbook's illustrative output as if it were a real
result.

---

## Deployment targets — authoritative vs non-authoritative

| Target | Status for #477 proof |
|---|---|
| **OpenShift Local / CRC** | **Primary, authoritative.** Exercises the restricted-v2 SCC, namespace-allocated non-root UID ranges (`MustRunAsRange`), `readOnlyRootFilesystem`, the writable `emptyDir` mounts, the per-Pod `NetworkPolicy`, and the image-pull-into-cluster paths that `KubernetesPodSandboxBackend` actually targets. |
| **Remote OpenShift cluster** | **Alternate, authoritative** — if the operator configures image pull from a registry reachable by the cluster. Replace step 1's CRC-internal-registry path with the remote cluster's registry (and its pull credentials / `imagePullSecret`); steps 2–6 are unchanged. The cluster must be genuine OpenShift for the SCC paths to be exercised. |
| **Plain Kubernetes — Docker Desktop Kubernetes, `kind`, vanilla upstream k8s** | **NOT accepted as full #477 proof.** These are plain Kubernetes, not OpenShift: the restricted-v2 SCC + `MustRunAsRange` UID-allocation paths the backend targets are not present, so a green run on them does not prove the production posture. If a run is performed on plain K8s/`kind` for convenience, the evidence file entry **MUST explicitly mark that leg as non-authoritative / weaker** — it does not satisfy AC2/AC3 on its own. |

---

## Troubleshooting

- **`resolve_fixture_refs()` raises `RuntimeError` ("… not a valid digest-pinned
  OCI ref")** — a fixture ref is a bare tag or image ID. Re-run the step-3
  capture; the ref must be `repository@sha256:<64 lowercase hex>`.
- **`resolve_fixture_refs()` raises `RuntimeError` ("… is unset")** —
  `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1` but a ref var is missing. Re-export
  all five variables (step 4) in the shell that runs `pytest`.
- **Whole conformance module skips** — one of `COGNIC_RUN_DOCKER_SANDBOX` /
  `COGNIC_RUN_K8S_SANDBOX` is unset. Both are mandatory (step 4); the gate is
  symmetric by design.
- **`docker push` fails TLS verification** — add `${REGISTRY_ROUTE}` to Docker
  Desktop's `insecure-registries` and restart Docker, or trust the CRC ingress
  CA (see the TLS note in step 1).
- **K8s arm fails with `ImagePullBackOff`** — the `cognic-sandbox` default
  ServiceAccount has no pull secret for the registry route, or its `oc whoami
  -t` token has expired. Re-run step 1f verbatim — its `oc apply` form refreshes
  the stored token in place — and confirm the verification line lists
  `crc-fixture-pull`.
- **CRC out of resources** — increase the CRC allocation (`crc config set cpus`
  / `crc config set memory`, then `crc stop && crc start`).
