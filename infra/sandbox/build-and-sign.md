# T30 — Canonical Sandbox Image Build / Sign / Push (Operator Runbook)

**Status:** operator-executed. Engineering authored this runbook; an operator
with the canonical signing key + registry credentials runs it. Signing-key
custody and registry push are **Human-only decisions** (plugin-trust-root
territory per `AGENTS.md`) — they are not, and must not be, automated by the
agent.

## 1. Purpose

Build, attest, sign, and publish the two Wave-1 canonical sandbox images so the
runtime catalog's admission accepts them and canonical Z3/Z4 can close:

| Image | Dockerfile | Role |
|---|---|---|
| `cognic/sandbox-runtime-python` | `infra/sandbox/runtime-python/Dockerfile` (T8) | workload runtime container |
| `cognic/sandbox-egress-proxy`   | `infra/sandbox/egress-proxy/Dockerfile` (T7)   | egress proxy sidecar (tinyproxy + shim) |

The other two catalog images (`sandbox-runtime-shell`, `sandbox-runtime-data`)
are **out of scope** for T30 (deferred); only the two above are built here.

The local `:dev` images from the T7/T8 smoke builds are **NOT** the canonical
artifacts — the canonical artifacts are the signed, pushed, digest-pinned images
this runbook produces (per `[[feedback_canonical_artifact_not_oss_substitute]]`).

## 2. Prerequisites

- **cosign `v3.0.6`** — MUST match the platform-pinned version (the agentos
  image installs cosign v3.0.6; the catalog shells out to bare `cosign` on
  PATH). The verify argv contract below was empirically verified at this version
  (T8.6). A different cosign major version may change the verify contract —
  re-verify Step 5 before trusting it.
- **syft**, **grype** (SBOM + vuln scan; `[[feedback_verify_dep_availability_at_implementation]]`).
- **docker** (Z3 / build) and/or `oc` + the OpenShift internal registry (Z4).
- **The canonical AgentOS cosign signing keypair.** The operator holds the
  private key; its **public half becomes the canonical trust root**
  (`CANONICAL_TRUST_ROOT` below). Generate once, store the private key in the
  operator's secret store — NEVER in the repo or CI logs.

## 3. The admission contract these images MUST satisfy

`sandbox/admission.py` admits a sandbox image through a 9-step pipeline. The two
steps the published images must clear (both empirically verified during T30):

- **Step 7 — cosign verification (runs for canonical AND tenant images).** The
  catalog runs **exactly**:

  ```
  cosign verify --key <CANONICAL_TRUST_ROOT> <full_ref@sha256:...>
  ```

  Key-based, **no keyless flags** (T8.6 removed `--certificate-identity-regexp`,
  which cosign v3 rejects alongside `--key`). So you MUST sign key-based (Step 5)
  with the private key whose public half is `CANONICAL_TRUST_ROOT`. cosign v3
  verifies the transparency-log claim **offline** from the signing bundle — no
  public Rekor reachability is required at admission time.

- **Step 8 — SBOM license-deny policy: SKIPPED for canonical images** (T8.5 /
  ADR-016 2026-05-29 amendment). The tenant/default permissive-allow-only
  license policy does NOT gate canonical platform images, so the GPL/LGPL base
  packages (glibc, coreutils) and the GPL-2.0 egress proxy (tinyproxy) are
  fine. The SBOM is still **generated + retained** (Step 4.2) as ADR-016
  evidence — it is simply not used as an admission deny-gate for canonical
  images. (Tenant-allow-listed per-pack images keep the full license gate.)

## 4. Per-image procedure (run for BOTH images)

Set `IMG` to one image at a time and repeat. Example values shown; the operator
substitutes the real repository + key path + registry.

```bash
# --- operator-provided inputs (examples) ---
COSIGN_PRIVATE_KEY=/secure/cognic-canonical-cosign.key   # operator secret store
CANONICAL_TRUST_ROOT=/secure/cognic-canonical-cosign.pub  # the public half
REPO=cognic                                               # registry/namespace

IMG=sandbox-runtime-python   # then repeat with: sandbox-egress-proxy
DOCKERFILE_DIR=infra/sandbox/runtime-python   # then: infra/sandbox/egress-proxy
LOCAL_TAG="${REPO}/${IMG}:v1"
```

### 4.1 Build

```bash
docker build -t "${LOCAL_TAG}" "${DOCKERFILE_DIR}"
```

### 4.2 SBOM (retained evidence — ADR-016)

```bash
syft "${LOCAL_TAG}" -o spdx-json > "${IMG}.sbom.spdx.json"
```

Retain `${IMG}.sbom.spdx.json` in the 7-year attestation store. It is evidence,
NOT a canonical admission deny-gate (§3, Step 8).

### 4.3 Vulnerability baseline

```bash
grype "${LOCAL_TAG}" -o json > "${IMG}.grype.json"
```

Record the baseline. Banks gate on CVE thresholds via Rego (ADR-016 / ADR-015),
not in this runbook.

### 4.4 Push + capture the digest

**Z3 (Docker dev/CI surface):** make the image available to the Linux Docker
host the Z3 proof runs on (load or push to that host's registry), then capture
the digest:

```bash
docker push "${LOCAL_TAG}"   # to the Z3 host's registry
FULL_REF=$(docker inspect "${LOCAL_TAG}" --format '{{index .RepoDigests 0}}')
echo "${IMG} -> ${FULL_REF}"
```

**Z4 (OpenShift / CRC):** push to the cluster-internal registry + create the
image stream, then capture the registry digest:

```bash
oc create imagestream "${IMG}" -n cognic-sandbox   # once per image
docker tag "${LOCAL_TAG}" "image-registry.openshift-image-registry.svc:5000/cognic-sandbox/${IMG}:v1"
docker push "image-registry.openshift-image-registry.svc:5000/cognic-sandbox/${IMG}:v1"
# capture the registry-reported @sha256: digest for FULL_REF
```

### 4.5 Sign (key-based — the §3 Step-7 contract)

```bash
cosign sign --key "${COSIGN_PRIVATE_KEY}" --yes "${FULL_REF}"
```

Use `--allow-insecure-registry` ONLY for an HTTP test registry; production
registries are HTTPS and must not need it (the catalog's verify argv omits it).

## 5. Outputs (consumed by downstream tasks — record these)

| Output | Example | Consumed by |
|---|---|---|
| `RUNTIME_PYTHON_REF` | `cognic/sandbox-runtime-python:v1@sha256:<…>` | T10 `sandbox_canonical_runtime_python_image`; T11 catalog `canonical_refs` |
| `EGRESS_PROXY_REF` | `cognic/sandbox-egress-proxy:v1@sha256:<…>` | T10 `sandbox_canonical_egress_proxy_image`; **T12** `_CANONICAL_EGRESS_PROXY_IMAGE` swap in BOTH backends (`docker_sibling.py` + `kubernetes_pod.py`, replacing the `"d"*64` placeholder); T11 `canonical_refs` |
| `CANONICAL_TRUST_ROOT` (public key path) | `/secure/cognic-canonical-cosign.pub` | T10 `sandbox_canonical_image_trust_root_path`; T10b catalog `canonical_trust_root` |
| `COGNIC_Z3_EXPECTED_WORKLOAD_GID` / `COGNIC_Z4_EXPECTED_WORKLOAD_GID` | `65534` | Z3/Z4 substrate preflight (matches the runtime-python image `USER 65534:65534`, T8) |

## 6. Verify catalog admission before declaring done

Two complementary checks (both should pass before T14 closes canonical Z3/Z4):

1. **Cosign image-verify proof** (the T8.6 opt-in live proof, generalized to the
   real signed image): confirms `cosign verify --key <CANONICAL_TRUST_ROOT>
   <FULL_REF>` exits 0 at the platform cosign version. See
   `tests/integration/sandbox/test_real_cosign_image_verify.py` for the pattern
   (it drives the REAL catalog `_run_cosign_verify`).
2. **Real-catalog admission proof** (T14 Step 2b): constructs the real
   `CanonicalImageCatalog` via `get_backend(settings)` (T11) — NOT a MagicMock —
   and drives `create()` end-to-end against the signed images so `is_canonical`
   + `verify_cosign_or_refuse` (step 7) actually run + pass, and step 8 is
   correctly skipped for the canonical images. This is the test that proves
   T10–T12 + T8.5 + T8.6 together.

A cosign-verify failure here means the signing key ↔ `CANONICAL_TRUST_ROOT`
pairing is wrong, the cosign version drifted, or the image was not signed —
fix and re-run before proceeding.

## 7. Security / custody notes

- **Signing-key custody + rotation are Human-only decisions** (plugin-trust-root
  per `AGENTS.md`). The private key never enters the repo, CI logs, or the
  agent's reach.
- **No mocks / no placeholder substitution.** The canonical images are real
  signed artifacts. The env-gated proofs have a two-state contract: with the
  opt-in env var **unset** they skip by design (no proof requested); once
  **opted in**, missing artifacts / cosign / docker / registry **fail loud**
  with `AssertionError` (a broken environment is an error, never a silent skip
  or a pretend-success). Never silently swap an OSS image
  (`[[feedback_canonical_artifact_not_oss_substitute]]`).
- **cosign v3 transparency log.** Key-based `cosign sign` attaches an
  offline-verifiable bundle; verify succeeded **offline** in the T8.6 empirical
  proof (no public Rekor reachability needed at admission). Air-gapped banks
  should retain the signing bundle with the image; a private Rekor is optional.

## 8. What this unblocks

`T10 → T11 → T12` (Settings + catalog wiring + the egress-proxy constant swap)
consume the §5 outputs; `T13` (egress-enforcement proof) and `T14` (canonical
Z3/Z4 + the real-catalog admission proof) run against the pushed signed images.
Phase 3 + Sprint 10.6 close **only** after canonical Z3/Z4 are green, the
operator audit completes, and explicit human authorization is given.
