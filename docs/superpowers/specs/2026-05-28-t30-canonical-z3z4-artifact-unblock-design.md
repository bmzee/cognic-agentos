# T30 — Canonical Z3/Z4 Production Artifact Unblock (Design)

**Status:** DRAFT — design-only. No Dockerfiles, no shim code, no backend edits in this document. Implementation follows in a separate plan (`writing-plans`) after this spec is reviewed.

**Date:** 2026-05-28
**Owner branch (future):** `feat/sprint-t30-canonical-image-unblock` (not yet cut)
**Relationship to Sprint 10.6:** 10.6 is code-complete + fixture-proven + locally green at `4428bf0` but its canonical Z3/Z4 gates are OPEN. **10.6 stays on HOLD: no merge / PR / CLOSED / Phase-3-CLOSED until canonical Z3/Z4 pass *after* T30 lands.**

---

## 1. Context & problem statement

Sprint 8A introduced the canonical 4-image sandbox catalog and the AgentOS code that *expects and verifies* those images — `CanonicalImageCatalog` (`sandbox/catalog.py`), cosign/SBOM admission, and the Docker/K8s backends that launch a runtime container + an egress-proxy sidecar. The **production image artifacts were never built**. The repo today ships only:

- `infra/agentos/Dockerfile` (AgentOS itself),
- two **test fixtures**: `tests/fixtures/sandbox/{runtime,egress-proxy}-fixture.Dockerfile`.

Three concrete consequences, all verified at HEAD `4428bf0`:

1. **The egress-proxy fixture is a no-op.** Its own header: *"It does NOT filter or forward traffic. It only: (a) creates a present + readable `/var/log/cognic-proxy/access.jsonl`, and (b) stays alive."* (`tests/fixtures/sandbox/egress-proxy-fixture.Dockerfile`). It is a liveness/log-presence stub, not an enforcer.
2. **The canonical proxy ref is a placeholder digest.** `_CANONICAL_EGRESS_PROXY_IMAGE = "cognic/sandbox-egress-proxy:v1@sha256:" + "d"*64` in **both** backends (`sandbox/backends/docker_sibling.py:186`, `sandbox/backends/kubernetes_pod.py:254`). Digest-*shaped* (passes `_validate_image_ref`) but points at no real image.
3. **`CanonicalImageCatalog` is constructed only in test code.** No production wiring exists (no `Settings` field for canonical refs; nothing in `backend_factory.py`/app builds a real catalog). Confirmed: `grep` finds `CanonicalImageCatalog(` only under `tests/`.

**The good news — the AgentOS side of the proxy contract is fully built.** The backends already render the proxy's env, point the workload's proxy variables at it, read its log, and materialise the audit chain. T30 does **not** invent an interface; it builds an image that **conforms to the existing one** (§4). This is the central design constraint.

This is not a Sprint 10.6 credential-projection bug. It is a deferred **artifact-delivery** gap from the sandbox-platform line (Sprint 8A / Sprint 14 deployment-kit territory), pulled forward now because honest "fully ready for production use" cannot be claimed while canonical Z3/Z4 are unprovable.

---

## 2. Goals / Non-goals

### Goals (the locks)
- **G1.** Production Dockerfile + build for `cognic/sandbox-runtime-python`.
- **G2.** Production Dockerfile + build for `cognic/sandbox-egress-proxy` with **real egress enforcement**.
- **G3.** Proxy engine: **tinyproxy inside the canonical signed AgentOS image** (Approach A). OSS is permitted *inside* the canonical image; what is forbidden is substituting an arbitrary OSS image at runtime and calling it canonical (`[[feedback_canonical_artifact_not_oss_substitute]]`).
- **G4.** Shim = **PID1 entrypoint**: renders **anchored exact-host** filters from `ALLOW_LIST`, starts tinyproxy, normalizes tinyproxy's log into the `ProxyAccessRecord` JSONL schema (§4.3).
- **G5. Security pin:** **never** `FilterURLs`; use the default **domain `Filter` + `FilterDefaultDeny Yes`** (§5). HTTPS port via `ConnectPort`.
- **G6. Empirical proof:** a **denied HTTPS `CONNECT` must fail in a live test**, not by doc inference (§7). Allowed/denied for both HTTP and HTTPS, malformed allow-list fail-closed, `access.jsonl` schema conformance, Docker + K8s smoke.
- **G7.** Production catalog wiring: a `Settings` surface for canonical refs of **both images** (runtime-python + egress-proxy) + real `CanonicalImageCatalog` construction outside tests. (The proxy *selector* stays a constant per N2; its *digest* must still be a catalog member — §7.1.)
- **G8.** Replace the placeholder proxy digest in both backend constants with the real signed digest.
- **G9.** Build / SBOM / scan / sign / push the two images such that the catalog's existing cosign+SBOM admission accepts them; then **rerun canonical Z3/Z4 and close only when green**.

### Non-goals (deferred)
- **N1.** `cognic/sandbox-runtime-shell`, `cognic/sandbox-runtime-data` — no proof exercises them (YAGNI). → Sprint 14 deployment-kit catalog completion.
- **N2.** `Settings`-driven **proxy** ref injection — the proxy ref stays a hardcoded constant in the two backends (made real). Deploy-configurable proxy refs → Sprint 14.
- **N3.** Multi-arch beyond `amd64` (Wave-1 target is the CRC/OpenShift + Linux Docker amd64 surface). → revisit if a bank target needs arm64.
- **N4.** Any code/Dockerfile in *this* document — design-only.
- **N5.** `TrustRootResolver` integration into `CanonicalImageCatalog` — the async per-tenant resolver (`protocol/trust_root_resolver.py`) is **not** wired here. T30 uses a single `canonical_trust_root` for the AgentOS-signed canonical images (§7.1.1); the resolver becomes relevant only when tenant-specific image allow-lists exist. → future work.

---

## 3. Scope: two artifacts

| Artifact | Purpose | Launched by | Consumed contract |
|---|---|---|---|
| `cognic/sandbox-runtime-python` | the workload container Z3/Z4 exec into | both backends (runtime container) | catalog admission; numeric `USER`/GID; read-only root + writable `/workspace` |
| `cognic/sandbox-egress-proxy` | the egress sidecar that enforces the allow-list | both backends (proxy sidecar) | the §4 proxy contract (env in, JSONL out) + catalog admission (digest ∈ `canonical_refs`) |

---

## 4. The existing contract the egress-proxy image MUST conform to

This is fixed by code already on the critical-controls gate. The image is the *only* missing piece; it adapts to these, it does not change them. (Changing any of these is a wire-protocol change to on-gate modules and is out of T30 scope.)

### 4.1 Network
- Proxy **listens on `_PROXY_PORT = 3128`**, scheme `http` (`docker_sibling.py:160,168`; `kubernetes_pod.py:225,234`). The workload's `HTTP_PROXY`/`HTTPS_PROXY` point at it — **K8s:** `http://localhost:3128` in the shared Pod netns (`kubernetes_pod.py:23`); **Docker:** the runtime container is attached **only** to the sandbox-internal bridge (`HostConfig.NetworkMode = <internal net>`, `docker_sibling.py:638`) — **not** `--network none` — and reaches the proxy via the Docker-DNS alias `egress-proxy:3128` on that bridge. The internal bridge has no external route; the proxy sidecar is the sole egress path. (Note: AGENTS.md + `[[feedback_sandbox_network_isolation_precision]]` phrase this as the runtime being "`--network none`"; the code at `docker_sibling.py:638` uses an internal bridge with no external route — that is the accurate description. Reconciling the AGENTS.md/memory wording is a separate doc-drift fix, out of T30 scope.)
- HTTPS travels as `CONNECT host:443` through the proxy (no MITM / no TLS termination).

### 4.2 Env input (set by the backend → proxy container)
- **`ALLOW_LIST`** — a **JSON array of hostnames** (`sandbox/proxy.py:153` → `json.dumps(list(self.allow_list))`; doc at `proxy.py:127`). Hostnames are scheme-stripped (`proxy.py:214`). Source of truth is `SandboxPolicy.egress_allow_list: tuple[str, ...]` (`sandbox/policy.py:167`), each entry RFC-1123 + HTTP/HTTPS-only validated by `_validate_egress_host` (`policy.py:245`).
- **`SESSION_ID`** — the per-session id. `EgressProxyConfig.to_env()` returns **exactly** `ALLOW_LIST` + `SESSION_ID` (`sandbox/proxy.py:142-155`), and `ProxyAccessRecord.policy_id` is documented as "the per-session policy identifier the sidecar received via env" (`protocol.py:466-468`). Therefore **`policy_id = SESSION_ID`** — this is fixed by the existing contract, not a plan-time choice. Adding a dedicated `policy_id` env key would be a change to `to_env()` and is out of T30 scope.

### 4.3 Log output (the shim MUST emit) — authoritative schema
- **Path:** `/var/log/cognic-proxy/access.jsonl` (`_PROXY_LOG_PATH`, both backends).
- **Format:** JSONL — one JSON object per line — parsed by `_parse_proxy_log_jsonl` (`docker_sibling.py:372`). Required keys: `host`, `method`, `timestamp`, `policy_id`, `outcome`; optional `refusal_reason`.
- **`ProxyAccessRecord`** (`protocol.py:449-497`), 6 fields:
  - `host: str` — exact requested host the proxy saw.
  - `method: str` — `GET`/`POST`/`CONNECT`/…
  - `timestamp: datetime` — **timezone-aware ISO 8601** (`tzinfo is not None` AND `utcoffset() is not None`).
  - `policy_id: str` — per-session id from env.
  - `outcome: ProxyAccessOutcome` — closed set **`"allowed"` | `"refused"`** (`sandbox/proxy.py`).
  - `refusal_reason: str | None` — `None` when allowed; when refused, one of the **Wave-1 `ProxyAccessRefusalReason`** values: **`"not_in_allow_list"` | `"non_http_connect_target"`** (`sandbox/proxy.py`).
- **Downstream mapping** (`_classify_egress_refusal`, `docker_sibling.py:413`): `not_in_allow_list → egress_host_not_allow_listed`; `non_http_connect_target → egress_protocol_not_http` (`SandboxPolicyViolationReason`).
- **Always-present + empty-valid invariant:** the file MUST exist for the sidecar's lifetime (empty → parser returns `()`); a missing file / dead sidecar / unreadable log surfaces as `egress_audit_unreadable`. It must be created at **runtime** (the backend mounts a fresh dir — Docker anonymous VOLUME / K8s `emptyDir` — over `/var/log/cognic-proxy`, shadowing any build-time file).

> Implication: the shim emits records whose `outcome`/`refusal_reason` come from a closed vocabulary that the on-gate parser + classifier already depend on. Mapping tinyproxy's native behaviour into exactly these two refusal values is the core risk (§8).

---

## 5. Design — `cognic/sandbox-egress-proxy`

### 5.1 Base
- Minimal, **non-root**, digest-pinned base (candidate: `debian:bookworm-slim` to match the fixture's proven `/workspace`/VOLUME behaviour, or an even smaller distro if tinyproxy packages cleanly). **Base digest + tinyproxy version to be pinned at plan time** (`[[feedback_verify_dep_availability_at_implementation]]`).

### 5.2 tinyproxy configuration (security-pinned)
- **`FilterDefaultDeny Yes`** — default-deny whitelist.
- Default **domain `Filter`** (NOT `FilterURLs`). Rationale: the destination host in a `CONNECT` line is plaintext, so domain filtering gates HTTPS; `FilterURLs` only filters plaintext-HTTP URLs and is HTTPS-blind (tinyproxy docs). **`FilterURLs` is forbidden in this image.**
- **`ConnectPort 443`** (+ `8443` if a workload needs it) — restricts the HTTPS tunnel to expected ports; everything else denied.
- `LogFile` to a path the shim tails; `LogLevel` chosen for deterministic allow/deny lines (§8).

### 5.3 The AgentOS shim (PID1 entrypoint)
Responsibilities, in order:
1. Read `ALLOW_LIST` (JSON array of hostnames) + the session/policy-id env.
2. **Fail-closed validation:** empty/absent/invalid-JSON `ALLOW_LIST` ⇒ render an **empty allow-list under `FilterDefaultDeny Yes`** (deny-all), never allow-all. Malformed input must not widen access.
3. **Render the tinyproxy `Filter` file with anchored exact-host patterns** — each hostname escaped + anchored (`^api\.example\.com$`), never a bare substring. (tinyproxy `Filter` entries are regexes; `api.example.com` unanchored also matches `api.example.com.attacker.com`.) This is security-critical.
4. Render `tinyproxy.conf` (port 3128, `FilterDefaultDeny Yes`, `Filter <file>`, `ConnectPort 443`, `LogFile`).
5. Ensure `/var/log/cognic-proxy/access.jsonl` exists (empty-valid) **at runtime** (after the mount is in place).
6. Start tinyproxy.
7. **Normalize** tinyproxy log events → the §4.3 JSONL schema (`policy_id` from env; `outcome` ∈ {allowed, refused}; `refusal_reason` ∈ {not_in_allow_list, non_http_connect_target} | null), appending to `access.jsonl`.
8. Stay alive for the sidecar lifetime; propagate signals so the container stops cleanly.

### 5.4 Security pins (summary)
- Anchored exact-host filter rendering (§5.3.3).
- Domain `Filter` + `FilterDefaultDeny Yes`; **never `FilterURLs`** (§5.2).
- Fail-closed on malformed `ALLOW_LIST` (§5.3.2).
- Non-root; `ConnectPort` restricts HTTPS port; no inbound listener beyond 3128 on the sandbox-internal network.

---

## 6. Design — `cognic/sandbox-runtime-python`

- Digest-pinned Python base; **immutable** — no dynamic `apt-get`/`pip` at create-time (`[[feedback_immutable_runtime_images_no_dynamic_install]]`).
- **Numeric `USER`/GID** so the Docker-sibling preflight's numeric-`USER` parse + GID-axis checks resolve (Z3); the same GID is what `COGNIC_Z3_EXPECTED_WORKLOAD_GID` must match. (K8s/Z4 is GID-axis-only via `fsGroup`; no image-`USER` match required.)
- **Read-only root + writable `/workspace`** via a VOLUME (mirrors the fixture's proven behaviour under `ReadonlyRootfs=True`).
- Minimal, audit-friendly toolset (the binary set must be SBOM-capturable per ADR-006).

---

## 7. Catalog wiring + supply chain + constant swap

### 7.1 Production catalog wiring (G7)
- Add a `Settings` surface (`core/config.py`) for the canonical image refs — **both `sandbox-runtime-python` AND `sandbox-egress-proxy`** — as full OCI refs incl. `@sha256:` (the catalog stores full refs, not bare digests, and keeps a digest→full-ref reverse-map for cosign/syft, `catalog.py:232,267`).
- Construct a real `CanonicalImageCatalog` **outside tests** (app/`backend_factory` wiring) from those Settings, so production admission uses a real catalog rather than a test-only one.
- **The proxy digest MUST be a catalog member.** Both backends extract the proxy digest and gate launch on `self._catalog.is_canonical(proxy_image_digest)`, refusing with `sandbox_image_digest_not_in_canonical_catalog` if absent (`docker_sibling.py:2718-2719`, `kubernetes_pod.py:1076-1077`). Excluding the proxy from `canonical_refs` would make canonical Z3/Z4 fail at launch.
- **Two references, one digest (N2 clarified):** the proxy image has two references that must agree — the *launch selector* (`_CANONICAL_EGRESS_PROXY_IMAGE` hardcoded constant, §7.3; not Settings-injected per N2) and the *admission membership* (`canonical_refs` entry, this section). Both MUST carry the **same** real signed digest or `is_canonical` refuses. N2 defers only making the *selector* a Setting; it does **not** exclude the proxy from the catalog.

#### 7.1.1 Canonical-image trust root (a scoped `catalog.py` critical-controls change)

Cosign verification needs a trust root, but `CanonicalImageCatalog.tenant_trust_roots` is a **static** per-tenant `dict[str, Path]` (`catalog.py:233`), while production per-tenant roots come from the **async** `TrustRootResolver` (`protocol/trust_root_resolver.py:50` — Vault-backed `secret/cognic/<tenant>/trust-root`, with a fail-loud `KernelDefaultTrustRootResolver`). And the two canonical images are **AgentOS-signed platform artifacts**, so they want a **single canonical trust root, not a per-tenant one**. `trust_gate.py:512` only canonicalizes an already-supplied path — it resolves nothing. Resolution (Option 1, user-confirmed 2026-05-28):

- Add `canonical_trust_root: Path | None = None` to `CanonicalImageCatalog` (**backward-compatible**).
- `verify_cosign_or_refuse` uses `canonical_trust_root` when `image_digest in self._canonical_digests` (the catalog already maintains that set); tenant-allow-listed images keep using `tenant_trust_roots[tenant_id]`.
- T30 factory wiring: `canonical_refs={runtime-python, egress-proxy}`, `canonical_trust_root=settings.sandbox_canonical_image_trust_root_path`, `tenant_trust_roots={}`, `tenant_allow_lists={}`.
- **`TrustRootResolver` integration stays out of scope** (future work for tenant-specific image allow-lists; not needed while `tenant_allow_lists={}`).

This is a critical-controls edit to `catalog.py` (halt-before-commit); it does **not** change the per-tenant pack-verification path. Two tests pin it: (a) canonical-image verification does NOT fail on "no tenant trust root configured" when `canonical_trust_root` is present; (b) a tenant-allow-listed image still requires `tenant_trust_roots[tenant_id]`.

### 7.2 Supply chain (G9)
- For each image: build → digest-pin → **SBOM (syft)** → **vuln scan (grype)** → **sign (`cosign sign` on the OCI ref)** → push. This is the **image** variant of the supply-chain tooling that `cli/sign.py` uses for pack bundles (`cosign sign-blob`); image signing is a distinct invocation and must produce signatures + SBOM that the **catalog's existing cosign + syft admission verification accepts** (`sandbox/catalog.py`).
- Registry targets: Z3 needs the images locally on a **Linux Docker** host; Z4 needs them **cluster-pullable** (CRC internal registry `image-registry.openshift-image-registry.svc:5000`). **amd64** Wave-1.

### 7.3 Constant swap (G8) — critical-controls change
- Replace `_CANONICAL_EGRESS_PROXY_IMAGE` (the `"…@sha256:" + "d"*64` placeholder) with the **real signed digest** in **both** `sandbox/backends/docker_sibling.py:186` and `sandbox/backends/kubernetes_pod.py:254`. These are critical-controls modules → **halt-before-commit**, full gate ladder.
- **Consistency invariant:** this constant (the launch selector) and the `canonical_refs` catalog entry (§7.1, the admission gate) MUST carry the **same** digest. Drift between them fails `is_canonical(proxy_image_digest)` at launch — a plan-time check should assert they agree.

---

## 8. RISK — log normalization (ship / no-ship criterion)

**Risk:** tinyproxy emits a **native text log**, but `_parse_proxy_log_jsonl` requires JSONL in the exact `ProxyAccessRecord` shape with a **closed `outcome`/`refusal_reason` vocabulary**. The shim must derive, per request, whether it was **allowed** vs **refused**, and on refusal, **which** of `not_in_allow_list` vs `non_http_connect_target` applies. If tinyproxy's native log cannot reliably and unambiguously distinguish these (e.g. it logs a filter denial and a CONNECT-port denial indistinguishably, or its log format is not stable across the pinned version), the shim cannot populate authoritative records.

**Mitigation path (decide at plan/spike time, before committing to tinyproxy-log-tailing):**
1. **Spike tinyproxy log determinism first.** Confirm, on the pinned version, that filter-denied (`not_in_allow_list`) and CONNECT-port-denied (`non_http_connect_target`) requests produce distinguishable, stable log lines, and that allowed requests are distinguishable from both. If yes → tail + map.
2. **If log-tailing is not reliable → shim-authoritative records.** The shim front-loads the allow/deny *decision* (it already renders the allow-list, so it knows the policy) and emits the authoritative `ProxyAccessRecord` itself, using tinyproxy purely as the forwarding engine for *allowed* traffic. This keeps the audit record authoritative even if tinyproxy's log is lossy. (Heavier; changes where the decision is recorded; only taken if step 1 fails.)

**Ship/no-ship:** T30 does **not** ship a canonical proxy whose `access.jsonl` outcomes/refusal-reasons are guessed from an unstable log. Either the log format is proven stable for the mapping (path 1), or the shim emits authoritative records (path 2). A proxy that can't produce trustworthy `egress_host_not_allow_listed` / `egress_protocol_not_http` evidence is a no-ship.

---

## 9. Testing & success criteria

### 9.1 Egress-enforcement proof (NEW — the projection proofs do not cover this)
The credential-projection proofs (Z3/Z4) exercise *projection*, not egress filtering. T30 adds a dedicated enforcement proof:
- **Allowed HTTP host** → forwarded; `access.jsonl` record `outcome="allowed"`.
- **Allowed HTTPS host** (`CONNECT`) → forwarded; `outcome="allowed"`, `method="CONNECT"`.
- **Denied HTTP host** → blocked; `outcome="refused"`, `refusal_reason="not_in_allow_list"`.
- **Denied HTTPS host (`CONNECT`)** → **blocked in a live test** (G6 — empirical, not by doc inference); `outcome="refused"`, `refusal_reason="not_in_allow_list"`.
- **CONNECT to a non-allowed port** → `refusal_reason="non_http_connect_target"`.
- **Malformed `ALLOW_LIST`** → fail-closed (deny all).
- **`access.jsonl` schema** → every line parses via `_parse_proxy_log_jsonl` into a valid `ProxyAccessRecord`; timestamps tz-aware; closed-set values only.
- **Docker + K8s smoke** → the image comes up, binds 3128, presents a readable log, on both surfaces.

### 9.2 Canonical Z3/Z4 (the close)
- With the two real signed images pullable + the constant swapped + the catalog wired, **rerun the four canonical Z3/Z4 targets** (the same env-gated tests, with the audit env exported per the project-state checklist). **Close canonical only when green.**

---

## 10. 10.6 hold (reaffirmed)
Sprint 10.6 stays on HOLD until canonical Z3/Z4 pass *after* T30. No push / PR / merge / CLOSED / Phase-3-CLOSED without explicit per-action authorization (`push` / `pr` / `merge`). T30's own landing (image build/sign + constant swap + catalog wiring + enforcement proof) is itself reviewed + gated the same way.

---

## 11. To-pin at plan time (open items, not blockers)
- tinyproxy version + base-image digest(s) (verify package availability — `[[feedback_verify_dep_availability_at_implementation]]`).
- Registry mechanics for Z3 (local Linux Docker load) vs Z4 (CRC internal registry push + image stream).
- Outcome of the §8 log-determinism spike (path 1 vs path 2).
- Exact `cosign sign` / `syft` / `grype` invocations that satisfy `sandbox/catalog.py` admission.

---

## 12. Citations
- **tinyproxy config semantics** — `FilterDefaultDeny` (whitelist), default domain `Filter`, `FilterURLs` (HTTP-only / HTTPS-blind), `ConnectPort` (HTTPS port gate): tinyproxy docs at `github.com/tinyproxy/tinyproxy.github.io`, via context7. **Version to be pinned at plan time.**
- **Code contract** (HEAD `4428bf0`): `ProxyAccessRecord` `protocol.py:449-497`; parser `_parse_proxy_log_jsonl` `docker_sibling.py:372`; classifier `_classify_egress_refusal` `docker_sibling.py:413`; `EgressProxyConfig.to_env()` (exactly `ALLOW_LIST` + `SESSION_ID`) `proxy.py:142-155`; constants `_PROXY_{SCHEME,PORT,LOG_PATH}` `docker_sibling.py:160,168,177` + `kubernetes_pod.py:225,234,266`; Docker runtime `HostConfig.NetworkMode = <internal net>` `docker_sibling.py:638`; proxy launch gate `is_canonical(proxy_image_digest)` `docker_sibling.py:2718-2719` + `kubernetes_pod.py:1076-1077`; placeholder `_CANONICAL_EGRESS_PROXY_IMAGE` `docker_sibling.py:186` + `kubernetes_pod.py:254`; catalog full-ref store + digest→ref reverse-map `catalog.py:232,267`; `SandboxPolicy.egress_allow_list` `policy.py:167`; `_validate_egress_host` `policy.py:245`; `CanonicalImageCatalog` trust-root ctor arg `catalog.py:233` + no-trust-root cosign failure `catalog.py:368-372`; `TrustRootResolver` Protocol + fail-loud `KernelDefaultTrustRootResolver` `protocol/trust_root_resolver.py:50,73`; fixture `tests/fixtures/sandbox/egress-proxy-fixture.Dockerfile`.
