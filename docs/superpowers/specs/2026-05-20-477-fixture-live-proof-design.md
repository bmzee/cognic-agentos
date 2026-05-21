# #477 — Sandbox fixture-image path for live `checkpoint`/`suspend`/`wake` proof — Design Spec

**Date:** 2026-05-20
**Status:** APPROVED (brainstorm 2026-05-20; 5 design-call questions Q1-Q5 + 4 review rounds resolved — see §13; user-approved 2026-05-20; live-proof amendment recorded 2026-05-21).
**Scope:** A minimal **test-only** fixture-image path — plus one narrowly-scoped production-code egress-proxy-image seam and live-proof-discovered KubernetesPod hardening fixes — that unblocks the env-gated cross-backend sandbox conformance suite so `checkpoint → suspend → wake` can be proven against a live Docker daemon and a live OpenShift/CRC cluster. Closes the operational-proof gap tracked as task **#477** (carried open by the Sprint 8.5 closeout + PR #30).
**Brainstorming source:** session of 2026-05-20; 5 design-call questions answered inline (see §13).

---

## 1. Goal & scope boundary

The Sprint 8.5 resumable-session API (`checkpoint()` / `suspend()` / `wake()`) shipped with mocked-unit critical-controls coverage but **was never exercised against a live container runtime** — the cross-backend conformance suite is env-gated (`COGNIC_RUN_DOCKER_SANDBOX` / `COGNIC_RUN_K8S_SANDBOX`) and SKIPS in CI because the canonical sandbox images do not exist yet (a Sprint 14 deploy-kit deliverable). #477 closes that gap with a minimal test-only fixture image set.

**#477 proves** — runtime mechanics on both Wave-1 backends (`DockerSibling` + `KubernetesPod`):
- container create + exec
- `/workspace` snapshot on `checkpoint()`/`suspend()` and restore on `wake()`
- symlink + executable-bit preservation through the workspace-tar round-trip
- tombstone-first wake refusal (a destroyed session is not wakeable)
- the dual-container egress topology (runtime container + egress-proxy sidecar)

**#477 does NOT prove** — and the spec, runbook, and evidence file all state this explicitly:
- supply-chain admission *as a production claim* — i.e. that the real canonical images are signed/published
- canonical-image publication / signing / cataloging
Those keep their existing dedicated tests and remain Sprint 14 deploy-kit scope.

**Acceptance wording (LOCKED).** Every artifact #477 produces — spec, runbook, evidence file, the eventual PR/closeout — describes the result as:

> "Live backend mechanics (`checkpoint`/`suspend`/`wake`) proven against a minimal two-image test fixture set."

and **never** as "canonical image family proven" or "sandbox runtime images production-ready."

## 2. What #477 ships / does NOT ship

**Ships:**
- 2 test-only fixture Dockerfiles (§4).
- **Exactly one narrowly-scoped production-code seam** — an optional egress-proxy-image constructor kwarg on both backends, production default unchanged (§5).
- **Live-proof-discovered KubernetesPod fixes** — bounded Pod-readiness wait before `create()` returns, deterministic-name delete wait before wake recreates a Pod, and OpenShift-safe K8s tar restore flags. These were not planned scope; the CRC acceptance run surfaced them as pre-existing backend bugs that blocked the proof (§13 "Live proof amendment").
- 3 test-only env vars — the fixture-mode flag `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES` plus the 2 digest-ref vars `COGNIC_FIXTURE_RUNTIME_IMAGE_REF` / `COGNIC_FIXTURE_PROXY_IMAGE_REF` (§6, §4.3).
- 1 test-only catalog double `_FixtureOnlySandboxCatalog` (§7).
- Conftest wiring in the existing conformance sandbox conftest plus policy parameterization in the 2 conformance test files (§8).
- 1 CRC runbook doc (§9).
- 1 evidence-results file + completion rule (§10).
- Tests: the seam tests (§5), an architecture import-regression test (§7), and the live-proof conformance runs (§11).

**Does NOT ship** (out of scope — see §12):
- Any production supply-chain/catalog change. In particular `sandbox/catalog.py` (`CanonicalImageCatalog`, a critical-controls module) is **untouched**, and no catalog gating is added, removed, or bypassed in production.
- cosign/SBOM/supply-chain proof of the real canonical images.
- The 3 canonical runtime variants (`sandbox-runtime-python` / `-shell` / `-data`).
- `COGNIC_USE_LOCAL_FIXTURE_PROXY` production wiring (Sprint 14).
- Task #489 (production reaper wiring) — a separate follow-up.

## 3. Branch topology

#477 ships on a new branch `feat/sprint-8.5-477-fixture-live-proof` **stacked off the PR #30 tip** (`2f0a074` on `feat/sprint-8.5-resumable-session-api`). It opens as its own stacked PR with base `feat/sprint-8.5-resumable-session-api`; when PR #30 merges to `main`, the #477 PR re-targets `main` — the repo's established stacked-PR pattern (Sprint 7B.1 → 7B.2). This keeps PR #30's review surface clean while letting #477 ride the same release-gate decision: #477 is a **merge-blocker for the operational-proof claim**, not for keeping PR #30 open for review.

## 4. The 2 fixture images

Both Dockerfiles live test-only under `tests/fixtures/sandbox/`. Each carries a header comment: `# TEST FIXTURE — not a canonical/production sandbox image. See docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md`. Image tags use a `-fixture` suffix so they can never be confused with the `cognic/sandbox-runtime-*` / `cognic/sandbox-egress-proxy` canonical namespace.

### 4.1 `cognic-sandbox-runtime-fixture`

- **Base:** `debian:bookworm-slim`. Chosen for GNU `tar` — alpine/busybox `tar` has known symlink and xattr edge-case behaviour that would muddy the symlink + exec-bit preservation proof (AC4). GNU tar gives deterministic, well-understood preservation semantics.
- **Must support:**
  - running shell commands via the backend exec path (Docker `exec` + the K8s v4-channel `exec` with the `head -c N | tar xzf - --strip-components=1 --no-overwrite-dir -C /workspace` restore pipeline).
  - read/write access to `/workspace`.
  - `tar czf - -C /workspace .` on checkpoint and `head -c N | tar xzf - --strip-components=1 --no-overwrite-dir -C /workspace` on K8s restore, preserving symlinks and executable bits without rewriting the OpenShift `emptyDir` mount-root metadata.
- **Contains:** a shell (`bash`), GNU `coreutils`, GNU `tar`. Nothing else — it is a runtime *fixture*, not a real runtime image.
- **Image user:** declares `USER 65534:65534`. DockerSibling also sets `User=65534:65534` at container create, but Kubernetes `runAsNonRoot=True` validates the image default before start; an unspecified/root image user is refused before the live proof reaches `exec()`.
- **Supplied to the backend** via `SandboxPolicy.runtime_image` (`policy.py:166`) — the runtime image is caller-supplied through the policy/admission context, so the test simply constructs the policy with the runtime fixture's full OCI ref. No production-code seam is needed for the runtime image.

### 4.2 `cognic-sandbox-egress-proxy-fixture`

The T7 review found the K8s backend's most fragile surface is the proxy-log read; the fixture proxy contract must be crisp.

- **Must:**
  - create the proxy access-log file at `/var/log/cognic-proxy/access.jsonl` and keep it present + readable for the lifetime of the sidecar.
  - keep the sidecar process **alive** for the duration of every `exec()` so the backend's proxy-log read (`_read_proxy_log_from_sidecar` / `_read_proxy_log_from_sidecar_k8s`) succeeds. A dead sidecar or an absent file is the failure mode that surfaces `egress_audit_unreadable` (`SandboxPolicyViolationReason`) — the fixture must not trigger it.
  - not block green-path `exec()`.
- **Log shape — explicitly confirmed acceptable as empty.** The backend parser `_parse_proxy_log_jsonl` (`sandbox/backends/docker_sibling.py:303`) iterates `raw.splitlines()`, silently skips blank lines, and returns an empty tuple `()` on empty input. An **empty, readable, append-only `access.jsonl`** is therefore a fully valid green-path result — it yields zero `ProxyAccessRecord`s, which is correct when the workload made no egress requests. The fixture proxy **does NOT need to emit real access records.** It needs only: file present + readable + sidecar alive. The distinction is load-bearing — `egress_audit_unreadable` fires on an *unreadable* log (sidecar gone / `cat` non-zero), never on an *empty* one.
- **Contains:** a minimal long-lived process (e.g. a shell loop or a tiny script) that creates the log file and stays alive. Not a real filtering/forwarding proxy.
- **Image user:** declares `USER 65534:65534` for the same Kubernetes `runAsNonRoot=True` validation reason as the runtime fixture.
- **Supplied to the backend** via the §5 seam — the proxy image is AgentOS-owned backend-internal infrastructure, not caller-supplied, so it requires a production-code injection point (see §5).

### 4.3 Image production + digest materialization

AgentOS admission is **digest-axis**: `SandboxPolicy.runtime_image` must be a **digest-pinned OCI ref** — `repository[:tag]@sha256:<64-hex>`, where the tag is *optional* (`policy.py` `_validate_image_ref` Stage-1 regex validates repository + optional tag + a mandatory `@sha256:` digest; the gate is *not* bypassed by `_FixtureOnlySandboxCatalog`). The §5 proxy seam value must likewise be a digest-pinned OCI ref (the K8s proxy gate at `kubernetes_pod.py:831` does `.rsplit("@", 1)` to extract the digest). A plain local `docker build` yields a tag + image ID but **no repository digest** — a digest-pinned OCI ref is not resolvable until the image has been pushed to a registry, and both backends then try to *launch* exactly that ref. So the fixture refs must be materialized as real, runnable, registry-backed digest-pinned OCI refs (`repository@sha256:<digest>` — the untagged RepoDigest form is the typical output and is valid).

**Mechanism:**
1. Build the 2 fixture images (§4.1, §4.2).
2. Push both to a **single registry reachable by both the local Docker daemon and CRC**. Documented primary choice: **CRC's internal image registry exposed via its default route** — CRC pulls internally; the host Docker daemon pushes + pulls via the route after `oc registry login`. (A standalone local registry is a possible alternate, but CRC reaching a host-local registry needs extra insecure-registry network config — the runbook documents the CRC-internal-registry path as primary and owns the exact, tested command sequence.)
3. **Capture the post-push `RepoDigest`** for each image — e.g. `docker buildx build --push --metadata-file` (`containerimage.digest`), `docker inspect --format '{{index .RepoDigests 0}}'` after the push, or `skopeo inspect`. The captured `name@sha256:<digest>` strings are the fixture refs — pullable by both the host Docker daemon and CRC.
4. The 2 captured refs are surfaced to the test layer via **two test-only image-ref environment variables** — `COGNIC_FIXTURE_RUNTIME_IMAGE_REF` and `COGNIC_FIXTURE_PROXY_IMAGE_REF`. The conftest reads them when `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`; if the flag is set but a ref var is missing or not `@sha256:`-shaped, the conftest **fails fast** with a message pointing at the runbook — no silent skip, no placeholder fallback.
5. `_FixtureOnlySandboxCatalog` (§7) derives its two allowlisted `sha256:` digests from those two captured refs; the conftest threads the runtime ref into the policy fixture (§8) and the proxy ref into the §5 `egress_proxy_image` kwarg.

The two ref env vars are **test-only** (read only by the conftest, never by `src/`) — the same boundary as the §6 flag; the §7 architecture import-regression test covers them too. The runbook (§9) is the artifact that nails the exact build/push/capture commands, and the §10 evidence rule means it is validated by a real run before #477 closes.

## 5. Egress-proxy image injection seam — the one production-code change

#477's "test-only" boundary cannot cover the proxy image because both backends select it from production code, and the value there today is a placeholder digest the backends cannot actually launch:

- `DockerSiblingSandboxBackend._start_proxy_sidecar` computes `proxy_image` as a **function-body local** — `"cognic/sandbox-egress-proxy:v1@sha256:" + "d"*64` (`docker_sibling.py:1767`). Not monkeypatchable without replacing the whole method.
- `KubernetesPodSandboxBackend` uses the module constant `_CANONICAL_EGRESS_PROXY_IMAGE` (`kubernetes_pod.py:196`), same placeholder digest.

Without a seam, an env-gated fixture run would still try to launch the non-existent canonical proxy and the dual-container topology could not be proven. #477 therefore adds **exactly one** narrowly-scoped production-code seam.

**Seam contract:**
- Add an optional keyword-only constructor parameter `egress_proxy_image: str | None = None` to **both** `DockerSiblingSandboxBackend` and `KubernetesPodSandboxBackend`.
- Store as a private attribute `self._egress_proxy_image`, resolved at construction with **explicit `None`-check semantics**: `self._egress_proxy_image = <canonical default> if egress_proxy_image is None else egress_proxy_image`. **Not** `egress_proxy_image or <default>` — truthiness would silently convert an empty string `""` to the canonical default and mask a broken fixture injection (a live run would then launch the non-existent placeholder canonical proxy instead of failing clearly). The constructor additionally guards: a *provided* `egress_proxy_image` must be a non-empty `str` — an empty/blank value raises at construction (fail-fast), it does not fall back to the default. When the kwarg is omitted (`None`) the resolved value is byte-identical to today's hardcoded canonical string.
- **Docker selection site** — `DockerSiblingSandboxBackend._start_proxy_sidecar` is a backend *method*; its function-local `proxy_image` (`docker_sibling.py:1767`) is replaced by a read of `self._egress_proxy_image`.
- **K8s selection site** — `_build_pod_spec` (`kubernetes_pod.py:384`) is a **standalone module-level function** (exported in `__all__`), not a backend method, so it cannot read `self.`. The seam therefore adds an `egress_proxy_image` **parameter** to `_build_pod_spec(...)`; the parameter replaces the hardcoded `_CANONICAL_EGRESS_PROXY_IMAGE` at the sidecar-container `"image"` field (`:528`); and **every production call site** of `_build_pod_spec` (`:847`, `:1499`) passes `self._egress_proxy_image`. The K8s proxy-image catalog-gate digest extraction (`kubernetes_pod.py:831` — `_CANONICAL_EGRESS_PROXY_IMAGE.rsplit("@", 1)`) is likewise re-pointed at `self._egress_proxy_image`, so the injected proxy image's digest goes through the gate. The module constant `_CANONICAL_EGRESS_PROXY_IMAGE` stays as the constructor default source. `_build_pod_spec`'s pure-helper tests (`test_kubernetes_pod_pure_helpers.py`) are updated for both the default and the injected `egress_proxy_image` value.
- The injected value flows through the **identical path** the canonical default uses today, **including each backend's existing proxy-image catalog verification** — verified for both backends: Docker's `_start_proxy_sidecar` (`docker_sibling.py:1754-1775`, T10c R1 P1.1, pinned by `TestProxyImageGoesThroughCatalogVerification`) and the K8s proxy-image digest gate at `kubernetes_pod.py:831`. #477 adds, removes, and bypasses **no** catalog gating.
- **No `Settings` field. No environment-variable injection path.** The constructor kwarg is the *only* way to inject — and only test code passes it. Production callers (incl. `backend_factory.get_backend`) omit it and get the canonical default.
- `CanonicalImageCatalog` is **not** touched.

**Critical-controls note.** `docker_sibling.py` and `kubernetes_pod.py` are both on the durable critical-controls coverage gate. The seam is a **CC change** — its commit gets halt-before-commit + careful review; the production default path must remain byte-identical; the new lines must keep both modules ≥95% line / ≥90% branch.

**Seam tests (→ AC8-AC12):**
- default constructor (kwarg omitted / `None`) → both backends use the canonical proxy image string; `_build_pod_spec`'s pure-helper test covers the default.
- injected proxy image → used by Docker `_start_proxy_sidecar` and threaded through `_build_pod_spec` into the K8s Pod spec; `_build_pod_spec`'s pure-helper test covers the injected value.
- injected proxy image → still routed through `is_canonical` + `verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse` (the existing proxy catalog gate, both backends).
- empty/blank `egress_proxy_image` → raises at construction (fail-fast); it does NOT silently fall back to the canonical default.
- no injection path exists through `Settings` or environment variables — only the constructor kwarg.

## 6. Test-only env flag — `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES`

- A test-only env flag, `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`, plus the two test-only image-ref env vars from §4.3 (`COGNIC_FIXTURE_RUNTIME_IMAGE_REF`, `COGNIC_FIXTURE_PROXY_IMAGE_REF`) — all three read **only** in the two sandbox test conftests (§8). None is a `Settings` field; none is **read by any `src/` module** — including by the §5 seam, which is driven purely by its constructor kwarg (the conftest passes the captured proxy ref into that kwarg; production never does).
- **Unset (default — and the state on every CI run):** the conformance + backend test suites behave exactly as today (env-gated SKIPs, or canonical refs).
- **Set to `1`:** the conftests build the fixture-mode backend — runtime fixture ref via `SandboxPolicy.runtime_image`, proxy fixture ref via the §5 `egress_proxy_image` kwarg, and `_FixtureOnlySandboxCatalog` as the catalog.
- Because all three env vars live only in test code, they are **unreachable from production code** — there is no "production refusal" branch to write (a production-refusal branch would require `src/` to know the flag exists; it does not). The architecture import-regression test (§7) enforces this: if any `src/` module ever imports or references the flag, either of the two §4.3 ref env vars, or the fixture catalog, that test fails.

## 7. `_FixtureOnlySandboxCatalog`

A `CatalogProtocol`-conformant test double, defined in `tests/conformance/sandbox/` (test code only).

- **The Protocol surface (`admission.py:63`) is 4 digest-axis methods**, each keyed on `image_digest: str` (`sha256:<64-hex>`), not on full OCI refs:
  - `is_canonical(image_digest) -> bool`
  - `is_tenant_allow_listed(image_digest, tenant_id) -> bool`
  - `verify_cosign_or_refuse(image_digest, *, tenant_id) -> None` — async; raises `SandboxLifecycleRefused` on failure (does not return bool)
  - `verify_sbom_policy_or_refuse(image_digest, *, tenant_id) -> None` — async; same raise contract
- **Ref-vs-digest split.** The two **full fixture image refs** (`name@sha256:<digest>` for the runtime fixture and the proxy fixture) are the post-push RepoDigests materialized per §4.3 and supplied via the two §4.3 env vars. `_FixtureOnlySandboxCatalog` **derives the two `sha256:<digest>` values** from those refs at construction and allowlists exactly those two digests for the admission calls.
- **Behaviour:** `is_canonical(d)` returns `True` iff `d` is one of the two allowlisted fixture digests, else `False`. `verify_cosign_or_refuse` / `verify_sbom_policy_or_refuse` no-op-pass (return `None`) for those two digests and raise `SandboxLifecycleRefused` with the matching closed-enum reason for anything else. `is_tenant_allow_listed` returns `False` (the fixtures pass via the canonical path, not the per-tenant escape hatch). It implements **all four** Protocol methods exactly, so it is structurally substitutable wherever `CatalogProtocol` is consumed.
- **Both fixture digests are allowlisted — runtime AND proxy.** Because the §5 seam keeps the proxy image flowing through the same catalog gate as the runtime image, the fixture catalog must accept both, or the proxy sidecar's `is_canonical`/cosign/SBOM check would refuse the fixture proxy.
- **Docstring (mandatory text):** states it is TEST-ONLY, active only under `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`, allowlists exactly the two named fixture digests, and **"no-op-passes cosign/SBOM verification for those two digests — this is NOT a supply-chain proof; supply-chain admission has its own dedicated tests; see #477 spec §1."**
- **Boundary enforcement:** an architecture import-regression test (alongside the existing `tests/unit/architecture/` guards) asserts that **no `src/` module** imports or references `_FixtureOnlySandboxCatalog` or `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES`. This is the concrete mechanism behind the "unreachable from production code" guarantee in §6.

## 8. Test wiring — conftests + the 2 conformance test files

#477 modifies **three existing test files** (none are created):
- `tests/conformance/sandbox/conftest.py` — the cross-backend conformance fixtures + the `_CANONICAL_SPRINT_8A_IMAGES` preflight.
- `tests/conformance/sandbox/test_checkpoint_round_trip.py` — hardcodes a module-level `_POLICY` (`:66`) whose `runtime_image` is the placeholder canonical ref `cognic/sandbox-runtime-python:v1@sha256:a*64`.
- `tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py` — same: a module-level `_POLICY` (`:87`) with the placeholder canonical `runtime_image`.

(Review round 6 — scope correction: an earlier draft of §8 also listed `tests/unit/sandbox/backends/conftest.py`. That conftest serves the env-gated *unit* backend tests, not the conformance suite — and #477's live proof is the conformance suite only, §9-§11. The unit backend tests stay canonical-only, so #477 does not touch that conftest. §11 AC-set + §9 runbook are unaffected.)

**Conftest changes** — when `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`, the conformance conftest (0) reads + validates the two §4.3 ref env vars (`COGNIC_FIXTURE_RUNTIME_IMAGE_REF`, `COGNIC_FIXTURE_PROXY_IMAGE_REF`) — fail-fast if either is absent or not `@sha256:`-shaped; (a) swaps the canonical-image preflight to inspect the 2 fixture refs instead of the 4 canonical refs; (b) constructs the env-gated backend with `_FixtureOnlySandboxCatalog` (built from the 2 refs); (c) passes the proxy fixture ref via the §5 `egress_proxy_image` constructor kwarg; and (d) exposes a `runtime_image` (or whole-`policy`) **pytest fixture** that yields the runtime fixture ref. When the flag is unset, behaviour is unchanged.

**Conformance test-file changes (required — P1, review round 3).** The 2 conformance test files' module-level `_POLICY` constants hardcode the runtime image, so a conftest-only change cannot reach them — the tests would still call `backend.create(_POLICY, …)` with the nonexistent `a*64` canonical runtime, and #477's accepted proof (AC1-AC4) would never actually exercise the fixture image. #477 therefore **parameterizes the runtime image in both conformance test files**: the `runtime_image` is sourced from the conftest fixture in (d) rather than baked into a module constant. Flag unset → the fixture yields the canonical placeholder (today's behaviour — the module skips in CI anyway via the §9 symmetric env-gate); flag set → the runtime fixture ref. This is a test-file change, in scope. The production `SandboxPolicy` type remains untouched; the later live-proof amendment (§13) documents the additional KubernetesPod backend fixes discovered only by the CRC run.

## 9. CRC runbook

A new doc, `docs/runbooks/477-live-sandbox-proof.md`, gives the step-by-step live-proof procedure:
1. **Prereqs** — Docker Desktop running; CRC (OpenShift Local) installed.
2. **Start CRC + its registry** — `crc start`; `oc login`; expose CRC's internal image registry via its default route; `oc registry login` so the host Docker daemon can push + pull through the route.
3. **Build the 2 fixture images** — `docker build` against the §4 Dockerfiles (one runtime fixture, one egress-proxy fixture).
4. **Push + capture digests** — push both fixture images to the CRC-internal-registry route; capture each image's post-push `RepoDigest` per §4.3 step 3. The two resulting `<route>/name@sha256:<digest>` strings are the fixture refs — pullable by both the host Docker daemon (via the route) and CRC.
5. **Export the test env** — `COGNIC_RUN_DOCKER_SANDBOX=1` + `COGNIC_RUN_K8S_SANDBOX=1` + `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1` + `COGNIC_FIXTURE_RUNTIME_IMAGE_REF=<captured runtime ref>` + `COGNIC_FIXTURE_PROXY_IMAGE_REF=<captured proxy ref>`.
6. **Acceptance run — single invocation; DO NOT split per backend.** Both T9 conformance modules carry a module-level `skipif` requiring **BOTH** backend env vars (the wake module also `pytest.mark.require_both_backends`) — symmetric gating, because a tombstone-first parity test that ran only one backend would false-green. A run with only one backend env var would **skip the whole module**. With step 5's env exported, run exactly the two #477 fixture-wired modules (`test_checkpoint_round_trip.py` + `test_wake_session_tombstoned_conformance.py`) **once** — the single run exercises both the `docker_sibling` and `kubernetes_pod` arms. The per-runtime preparation (steps 2-4) may be staged; the acceptance run may not be split.
7. **Exact `pytest` invocation** for the acceptance run, with expected pass output for both backend arms.

**#477's live proof is the conformance suite only.** The env-gated *backend checkpoint* tests (`tests/unit/sandbox/backends/test_docker_sibling_checkpoint.py`, `test_kubernetes_pod_checkpoint.py`) are deliberately NOT in scope — see §12 + §8 for why a conftest-only fixture wiring cannot reach their bespoke `_POLICY` / mock-catalog fixtures, and §13 review-round-2 for the decision.

- **Primary documented target: OpenShift Local / CRC.** It exercises the SCC behaviour, non-root UID allocation, `readOnlyRootFilesystem`, emptyDir writable mounts, NetworkPolicy, and image-pull-into-cluster paths the `KubernetesPodSandboxBackend` actually implements. Cluster-admin setup is allowed, but the acceptance run must use CRC's regular `developer` user (or an equivalent non-anyuid user) so OpenShift selects restricted-v2 rather than kubeadmin's anyuid SCC.
- **Alternate supported target:** a remote OpenShift cluster, if the operator configures image pull from a reachable registry. The runbook documents this as an alternate with the extra registry/credentials steps.
- **Not accepted as full #477 proof:** plain Docker Desktop Kubernetes or `kind`. They are plain K8s, not OpenShift — the restricted-v2 SCC + `MustRunAsRange` paths the backend targets would not be exercised. If a run uses one of these, the evidence file MUST mark that leg explicitly weaker / non-authoritative.

## 10. Evidence file + completion rule

A new file, `docs/evidence/477-live-proof-results.md`, was committed as part of #477 as a **template with placeholders** (no fabricated results). The 2026-05-21 live proof appended a witnessed passing run to that file. It captures, per run:
- date, operator, CRC version, OpenShift version, Docker version
- the two captured fixture image refs (post-push RepoDigests per §4.3) actually exercised
- the `pytest` output for the single symmetric acceptance run (§9 step 6) — both backend arms of the checkpoint round-trip + the tombstone-first wake
- pass/fail against each acceptance criterion in §11

**Completion rule (LOCKED).** Task **#477 stays OPEN** until `docs/evidence/477-live-proof-results.md` records a passing run. Merging the #477 PR delivers the *artifacts*; it does not by itself close #477 — the recorded live evidence does.

**Opportunistic-run clause (LOCKED).** During implementation the agent MAY probe `docker` / `oc` / `crc` reachability and run any reachable leg. But a passing-live-proof claim is accepted **only** when the run output is recorded in the evidence file. No completion claim is made off an unrecorded or un-witnessed run.

## 11. Acceptance criteria

- **AC1** — in the single symmetric conformance run (§9 step 6 — the acceptance run), `test_checkpoint_round_trip.py`'s `docker_sibling` arm passes against a live Docker daemon using the fixture images.
- **AC2** — in that same run, `test_checkpoint_round_trip.py`'s `kubernetes_pod` arm passes against a live CRC/OpenShift cluster using the fixture images.
- **AC3** — in that same run, `test_wake_session_tombstoned_conformance.py` passes on both backend arms (tombstone-first wake refusal proven live).
- **AC4** — symlink + executable-bit preservation is verified through the `/workspace` workspace-tar round-trip.
- **AC5** — results for AC1-AC4 are recorded in `docs/evidence/477-live-proof-results.md`.
- **AC6** — the architecture import-regression test passes: no `src/` module references the fixture flag or `_FixtureOnlySandboxCatalog`.
- **AC7** — the full non-env-gated suite + `tools/check_critical_coverage.py` stay green; the §5 seam keeps `docker_sibling.py` + `kubernetes_pod.py` ≥95% line / ≥90% branch (the 73-module gate count is unchanged — #477 promotes no module).
- **AC8** — default constructor (no `egress_proxy_image` kwarg) → both backends use the canonical proxy image string.
- **AC9** — injected `egress_proxy_image` → used by Docker `_start_proxy_sidecar` and the K8s Pod spec.
- **AC10** — the injected proxy image still flows through `is_canonical` + `verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse` (the existing proxy catalog gate is preserved).
- **AC11** — no proxy-image injection path exists through `Settings` or environment variables — only the constructor kwarg.
- **AC12** — an empty/blank `egress_proxy_image` raises at construction (fail-fast); it does not silently fall back to the canonical default.

All criteria are worded as fixture-image proof. None claims canonical-image production readiness. #477's live-proof acceptance (AC1-AC4) is the **conformance suite**; the env-gated backend checkpoint tests are out of scope (§12).

## 12. Out of scope

- **Any production supply-chain/catalog change.** In particular `sandbox/catalog.py` / `CanonicalImageCatalog` (critical-controls) is untouched, and no catalog gating is added, removed, or bypassed in production. The 2026-05-21 live proof did add KubernetesPod backend hardening in `src/` because CRC exposed pre-existing readiness, deletion, and restore bugs that blocked AC1-AC5; those fixes are recorded in §13 and are no longer out of scope.
- **Supply-chain admission proof of the real canonical images** — cosign signature verification, SBOM policy on the canonical set. Covered by existing catalog/admission tests; not re-proven here.
- **Canonical-image publication / signing / cataloging** — Sprint 14 deploy kit.
- **The 3 canonical runtime variants** (`sandbox-runtime-python` / `-shell` / `-data`) — #477 ships a single runtime fixture.
- **`COGNIC_USE_LOCAL_FIXTURE_PROXY` production wiring** — Sprint 14.
- **Task #489** (production `CheckpointReaper` wiring into `create_prod_app`) — a separate follow-up; #477 does not touch it.
- **The env-gated backend checkpoint tests** (`tests/unit/sandbox/backends/test_docker_sibling_checkpoint.py`, `test_kubernetes_pod_checkpoint.py`) — they define their own bespoke `_POLICY` (placeholder canonical runtime refs) and their own monkeypatched / `MagicMock` catalog fixtures, which a conftest-only fixture wiring (§8) does not reach. #477 does NOT rewrite those tests to consume the fixture refs — that would widen the surface for no added live-proof value, since the conformance suite already covers the cross-backend round-trip + tombstone proof (AC1-AC4). Those tests remain in their pre-#477 state (live-runnable only once canonical images exist — Sprint 14).

## 13. Design decisions log

**Brainstorm 2026-05-20 (Q1-Q5):**
- **Q1 — test-only fixture path.** #477 does NOT pull Sprint 14 catalog/cosign/canonical-publication scope forward. Production `CanonicalImageCatalog` (a CC module) is untouched.
- **Q2 — minimal 2-image fixture set.** One runtime fixture + one egress-proxy fixture. The 3 canonical runtime variants are Sprint 14 territory.
- **Q3 — `_FixtureOnlySandboxCatalog` test double.** Fixture admission lives in a test-only catalog double, not in production code. No local cosign signing of fixtures.
- **Q4 — CRC as the documented target.** Primary runbook target OpenShift Local / CRC; alternate remote OpenShift; plain Docker-Desktop-K8s / `kind` not accepted as full proof.
- **Q5 — execution split A.** The agent authors all codebase artifacts + runbook + evidence template; the live proof is a runbook the operator executes; #477 stays open until live results are recorded. Optional opportunistic probing/running allowed, but no completion claim without recorded live evidence.

**Review round 1 (2026-05-20) — P1/P2/P3 closed:**
- **P1 (blocker) — egress-proxy image is selected in production code, so a pure test-only path cannot run the fixture proxy.** Verified: Docker's proxy image is a function-body local (`docker_sibling.py:1767`, not monkeypatchable), K8s's is a module constant (`kubernetes_pod.py:196`); both are placeholder digests the backends cannot launch. **Resolution: Option 1 — narrow backend image seam (§5).** An optional `egress_proxy_image` constructor kwarg on both backends, default = canonical image, production default-path byte-identical. Not Sprint-14 supply-chain scope; it is runtime configurability for tests. The "no `src/` change" boundary is revised to "exactly one narrow `src/` seam." Monkeypatching was rejected (Docker's function-local would force replacing the whole proxy-start method — a fidelity downgrade); downgrading the proof was rejected (loses the T7 proxy-log/sidecar risk surface).
- **P2 — fixture catalog spec mixed image refs with the digest-axis Protocol.** Verified: `CatalogProtocol` (`admission.py:63`) is 4 digest-axis methods (`is_canonical`, `is_tenant_allow_listed`, `verify_cosign_or_refuse`, `verify_sbom_policy_or_refuse`). §7 rewritten: the runbook/preflight owns the two full fixture refs; `_FixtureOnlySandboxCatalog` derives + allowlists their two `sha256:` digests and implements all four methods exactly. Both fixture digests (runtime + proxy) are allowlisted, because §5 keeps the proxy image flowing through the catalog gate.
- **P3 — spec status said APPROVED before review was complete.** Changed to DRAFT; flips to APPROVED only on explicit user sign-off.

**Review round 2 (2026-05-20) — execution-shape gaps closed:**
- **P2 — K8s proxy seam did not match the pure-helper shape.** Verified: `_build_pod_spec` (`kubernetes_pod.py:384`) is a standalone module-level function (exported in `__all__`), not a backend method — it cannot read `self._egress_proxy_image`. §5 rewritten: the seam adds an `egress_proxy_image` *parameter* to `_build_pod_spec(...)`, threaded from `self._egress_proxy_image` at every production call site (`:847`, `:1499`); the param replaces the hardcoded constant at the sidecar `"image"` field (`:528`); the K8s proxy catalog-gate digest extraction (`:831`) is re-pointed at it; `_build_pod_spec`'s pure-helper tests are updated for default + injected values. The Docker side stays an attribute read (`_start_proxy_sidecar` is a method).
- **P2 — backend-test live runs not covered by the conftest-only fixture plan.** Verified: `test_docker_sibling_checkpoint.py:66` + `test_kubernetes_pod_checkpoint.py:81` define their own `_POLICY` (placeholder `a*64` runtime refs) + their own monkeypatched / `MagicMock` catalogs; the §8 conftest-only wiring does not reach them. **Resolution: narrow #477's live proof to the conformance suite only.** §9 runbook drops "+ backend tests"; §11 states AC1-AC4 acceptance is the conformance suite; §12 adds the backend checkpoint tests as explicit out-of-scope. The conformance suite is purpose-built (T9) for the cross-backend round-trip + tombstone proof, so this loses no proof value; rewriting the backend tests' bespoke fixtures would be surface for no gain.
- **P3 — constructor seam used truthiness, not `None`-check.** §5 changed from `egress_proxy_image or <default>` to `<default> if egress_proxy_image is None else egress_proxy_image`, plus a fail-fast constructor guard that a provided value is a non-empty `str` (empty/blank raises — it does not silently default to the placeholder canonical proxy). New AC12 + seam test pin it.

**Review round 3 (2026-05-20) — conformance-run execution blockers closed:**
- **P1 — conformance tests still owned placeholder runtime policies.** Verified: `test_checkpoint_round_trip.py:66` + `test_wake_session_tombstoned_conformance.py:87` each define a module-level `_POLICY` with `runtime_image="cognic/sandbox-runtime-python:v1@sha256:a*64"` — a conftest-only change cannot reach them, so #477's accepted proof would call `backend.create()` with the nonexistent canonical runtime. §8 rewritten: #477 modifies **four** test files (the 2 conftests + the 2 conformance test files); the conformance files' `_POLICY` runtime image is parameterized to flow from a conftest fixture (canonical placeholder when the flag is unset, runtime fixture ref when set).
- **P2 — runbook split symmetrically-gated tests.** Verified: both T9 conformance modules carry `skipif(not (DOCKER==1 and K8S==1))`; the wake module also `require_both_backends`. The round-2 runbook described separate Docker-only and CRC-only legs — each would skip the whole module. §9 restructured: the per-runtime *preparation* steps are separate, but the **acceptance run is a single invocation** with both backend env vars + the fixture flag exported together. AC1-AC3 reworded as arms of that one symmetric run.
- **P3 — self-review acceptance-criteria count drift.** The self-review said "11 acceptance criteria" after AC12 was added in round 2. Corrected to 12.

**Review round 4 (2026-05-20) — digest-materialization gap closed:**
- **P1 — fixture refs are digest-pinned but the runbook did not materialize runnable digests.** Verified against the existing constraints: `policy.py` `_validate_image_ref` mandates an `@sha256:<64-hex>` suffix on `runtime_image` (Stage-1 shape gate, not bypassed by the catalog double), and the K8s proxy gate at `kubernetes_pod.py:831` does `.rsplit("@", 1)` — yet a plain local `docker build` produces no repository digest. New **§4.3** added: build → push to a single registry reachable by both the host Docker daemon and CRC (documented primary: CRC's internal registry via its default route) → capture the post-push `RepoDigest` for each image → surface the two captured refs through two test-only env vars (`COGNIC_FIXTURE_RUNTIME_IMAGE_REF` / `COGNIC_FIXTURE_PROXY_IMAGE_REF`) the conftest reads + fail-fast-validates. §6 broadened to the flag + 2 ref vars; §8 conftest step (0) reads/validates them; §9 runbook restructured to build → push → capture → export → single run; §10 evidence file now records the captured refs. Without this, AC1/AC2 would fail before exercising `checkpoint`/`suspend`/`wake`.

**Live proof amendment (2026-05-21) — CRC run surfaced pre-existing KubernetesPod bugs:**
- **Fixture image default user.** OpenShift refused the original fixture images before `exec()` because the Pod security context had `runAsNonRoot=True` and the images had no non-root default user. Resolution: both fixture Dockerfiles declare `USER 65534:65534`; the runbook also requires the acceptance run to use CRC's regular `developer` user so Pods exercise restricted-v2 rather than kubeadmin's anyuid SCC.
- **Cold create readiness race.** `KubernetesPodSandboxBackend.create()` returned immediately after Pod creation, so the conformance test's first `session.exec()` could race kubelet startup and fail as a pods/exec websocket HTTP 500. Resolution: `create()` now waits for Pod readiness before returning, with bounded timeout + teardown on failure.
- **Suspend→wake deterministic-name deletion race.** `suspend()` deletes `sb-<session_id>`, but Kubernetes deletion is asynchronous; immediate wake could recreate the same deterministic Pod name before deletion completed and fail with `409 AlreadyExists`. Resolution: `_delete_pod_if_exists()` deletes with zero grace and waits until the apiserver reports 404, with a bounded timeout.
- **OpenShift emptyDir restore metadata.** The checkpoint archive contains the `./` directory entry; restoring as an arbitrary restricted-v2 UID could not chmod/utime the `/workspace` emptyDir mount root. `--no-overwrite-dir` alone was insufficient because GNU tar still tried to chmod `.`. Resolution: K8s restore uses `head -c N | tar xzf - --strip-components=1 --no-overwrite-dir -C /workspace`, which strips the leading `./` component and restores contents without rewriting mount-root metadata.
- **Evidence.** The witnessed symmetric acceptance run on Docker + CRC passed 8/8 and is recorded in `docs/evidence/477-live-proof-results.md` with fixture digests, tool versions, and SCC posture (`restricted-v2=yes`, `anyuid=no`).

## Self-review notes

- **Placeholder scan:** No TBDs. Image base (`debian:bookworm-slim`), the env-var name, the seam kwarg name, the catalog-double name, file paths, and 12 acceptance criteria (AC1-AC12) are all concrete.
- **Internal consistency:** §1 scope (runtime mechanics, not supply chain) is consistent with §7 (catalog double no-op-passes cosign/SBOM for 2 digests) and §12 (supply-chain out of scope). §2 now distinguishes the originally-planned egress-proxy-image seam from the live-proof-discovered KubernetesPod hardening fixes recorded in §13. §5's "injected image still flows through the catalog gate" is consistent with §7's "both fixture digests allowlisted" and AC10. The §6 "unreachable from production code" claim is consistent with §5 (seam driven only by constructor kwarg, no Settings/env path) and §7's import-regression test (AC6 + AC11). §8's three-file modification set (1 conformance conftest + 2 conformance test files) is consistent with §9's single-symmetric-run acceptance and with AC1-AC3 being arms of that one run.
- **Scope check:** Focused effort — test fixtures + conftest wiring + docs + one narrow production seam, plus bounded KubernetesPod live-proof fixes discovered by the actual CRC acceptance run. The live-proof fixes are not supply-chain or catalog scope; they are backend-mechanics defects the proof was designed to expose.
- **Ambiguity check:** The egress-proxy fixture's required behaviour (the T7 failure surface) is resolved explicitly in §4.2 against `_parse_proxy_log_jsonl`. The seam's production-default-preservation is explicit in §5 (byte-identical default path). "Live proof" is unambiguously scoped to fixture images in §1 / §11 / the acceptance-wording lock. The digest-axis/local-build mismatch is resolved in §4.3 (build → push → capture RepoDigest → 2 test-only ref env vars), consistent with §6 (3 test-only env vars), §8 conftest step (0), and the §9 build/push/capture/export runbook order.
