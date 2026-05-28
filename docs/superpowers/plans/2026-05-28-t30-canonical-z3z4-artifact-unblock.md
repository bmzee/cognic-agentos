# T30 — Canonical Z3/Z4 Production Artifact Unblock — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, sign, and catalog the two canonical sandbox images Z3/Z4 actually launch (`cognic/sandbox-runtime-python` + `cognic/sandbox-egress-proxy`), with the egress proxy *really enforcing* the allow-list, so canonical Z3/Z4 can pass and Sprint 10.6 can close honestly.

**Architecture:** A tinyproxy-based egress-proxy image with a Python shim (PID1) that renders anchored exact-host filters from `ALLOW_LIST`, runs tinyproxy, and emits the `ProxyAccessRecord` JSONL the backend already parses. A minimal non-root runtime-python image. Production catalog wiring (Settings → `CanonicalImageCatalog` in the backend factory). The proxy digest is hardcoded in both backend constants **and** added to `canonical_refs` (same digest). No backend redesign — the image conforms to the existing `sandbox/proxy.py` + `_parse_proxy_log_jsonl` contract (spec §4).

**Tech Stack:** tinyproxy (version pinned at Task 1), Python 3.12 shim, Docker (Z3 / build), OpenShift/CRC (Z4), cosign + syft + grype (supply chain, mirroring `cli/sign.py` for the *image* variant), pytest/ruff/mypy + `uv`.

**Spec:** `docs/superpowers/specs/2026-05-28-t30-canonical-z3z4-artifact-unblock-design.md` (approved). Read it first.

**Sequencing DAG (read before starting):** `T1 (spike)` → `T2–T8 (shim + Dockerfiles)` → `T9 (build/sign/push ⇒ real digests)` → `T10 / T10b / T11–T12 (Settings + catalog canonical_trust_root + factory wiring + constant swap, consume the digests)` → `T13–T14 (proofs)` → `T15 (closeout)`. **T12 + T14 are gated on T9's real digest. T5's variant is gated on T1's spike outcome. T11 depends on T10b (the `canonical_trust_root` param).**

**Critical-controls note:** T12 edits `sandbox/backends/{docker_sibling,kubernetes_pod}.py` and T10b edits `sandbox/catalog.py` (all on the CC gate); T10/T11 edit `core/config.py` + the factory. All of T10–T12 (incl. T10b) are **halt-before-commit**, full gate ladder, per `[[feedback_strict_review_off_gate]]`. The shim (T2–T7) is image content, not on the CC gate, but its anchored-regex + fail-closed logic is security-critical and gets negative-path tests.

**HOLD:** Sprint 10.6 stays on HOLD; nothing merges / no CLOSED markers until canonical Z3/Z4 pass after T30, each with explicit `push`/`pr`/`merge` tokens.

---

## Phase 0 — Spike (decision gate)

### Task 1: tinyproxy log-determinism spike → choose the shim's record-emission path

**Files:**
- Create: `docs/superpowers/spikes/2026-05-28-t30-tinyproxy-log-determinism.md` (findings + decision)
- Scratch (not committed): a throwaway tinyproxy container + reference `tinyproxy.conf`

**Why:** Per spec §8, the shim must emit `outcome ∈ {allowed, refused}` + `refusal_reason ∈ {not_in_allow_list, non_http_connect_target}`. Whether the shim can derive those by **tailing tinyproxy's log** (path 1) or must become an **in-path decision shim** (path 2) is the architecture-deciding question. This is a ship/no-ship gate.

- [ ] **Step 1: Pin a tinyproxy version + base image.** Verify availability in the chosen base distro's package repo (`[[feedback_verify_dep_availability_at_implementation]]`). Record exact `name=version` + base digest in the findings doc.
- [ ] **Step 2: Stand up deterministic local upstreams + a throwaway tinyproxy.** Run two controlled local services on the sandbox-internal Docker network — an HTTP echo and a TLS-terminating echo (for `CONNECT`) — reachable via explicit network aliases `allowed.test` + `denied.test` (NO public / `example.com` dependency; the proof must be hermetic). Configure tinyproxy with `FilterDefaultDeny Yes`, a domain `Filter` containing `^allowed\.test$`, `ConnectPort 443`, `LogFile`, `LogLevel Connect` (and also test `Info`).
- [ ] **Step 3: Drive the four cases** through it and capture the raw log lines for each:
  1. allowed host, HTTP GET → expect forwarded;
  2. allowed host, HTTPS `CONNECT :443` → expect forwarded;
  3. denied host, HTTP + HTTPS `CONNECT` → expect filter denial (`not_in_allow_list`);
  4. allowed host, `CONNECT :22` (non-443) → expect ConnectPort denial (`non_http_connect_target`).
- [ ] **Step 4: Decide.** In the findings doc, record whether the native log lines reliably + stably distinguish all four outcomes:
  - **Path 1 (log-tail):** if yes — document the exact line→outcome/`refusal_reason` mapping. T5 = T5a.
  - **Path 2 (in-path decision shim):** if no — the shim becomes the proxy decision point (it knows the allow-list; it emits the authoritative record and forwards allowed traffic via tinyproxy as upstream). T5 = T5b. **This is the heavier path; only taken if Step 4 fails.**
- [ ] **Step 5: Commit** `docs(t30): tinyproxy log-determinism spike findings + path decision`.

**Decision criterion (explicit):** Path 1 requires that, on the pinned version, (a) allowed vs refused is unambiguous, and (b) `not_in_allow_list` vs `non_http_connect_target` is distinguishable. If either fails → Path 2.

---

## Phase 1 — egress-proxy shim (TDD) + image

Shim lives at `infra/sandbox/egress-proxy/cognic_egress_shim.py` (pure-logic functions) + `infra/sandbox/egress-proxy/entrypoint.py` (PID1 wrapper). Tests at `tests/unit/sandbox/egress_proxy/` with a `conftest.py` that inserts the shim dir on `sys.path` (Step 1 of Task 2 establishes this; mirror the closest existing infra-test pattern, else the sys.path insert is the documented approach).

### Task 2: allow-list parser + anchored exact-host filter renderer

**Files:**
- Create: `infra/sandbox/egress-proxy/cognic_egress_shim.py`
- Create: `tests/unit/sandbox/egress_proxy/conftest.py` (sys.path insert)
- Create: `tests/unit/sandbox/egress_proxy/test_filter_render.py`

- [ ] **Step 1: Write failing tests** for `render_filter_file(allow_list_json: str) -> str`:

```python
def test_anchored_exact_host():
    out = render_filter_file('["api.example.com"]')
    assert out.splitlines() == [r"^api\.example\.com$"]

def test_dots_escaped_not_wildcard():
    # an unanchored/unescaped pattern would also match api.example.com.attacker.com
    out = render_filter_file('["api.example.com"]')
    assert r"\." in out and out.startswith("^") and out.rstrip().endswith("$")

def test_empty_list_renders_empty_filter_deny_all():
    assert render_filter_file("[]") == ""  # with FilterDefaultDeny Yes ⇒ deny all

def test_malformed_json_fails_closed():
    # not valid JSON ⇒ deny-all (empty filter), never raise-into-allow-all
    assert render_filter_file("not json") == ""

def test_non_list_fails_closed():
    assert render_filter_file('{"host":"x"}') == ""

def test_dedup_preserves_first_order():
    out = render_filter_file('["a.com","a.com","b.com"]')
    assert out.splitlines() == [r"^a\.com$", r"^b\.com$"]

# Per-entry RFC-1123 validation — ANY malformed entry ⇒ deny-all (fail-closed),
# because this renders line-oriented regex config from tamper-capable env input.
@pytest.mark.parametrize("bad", [
    '[""]',                          # empty host
    '["https://api.example.com"]',   # scheme
    '["api.example.com/path"]',      # path
    '["*.example.com"]',             # wildcard
    '["api.example.com\\n^evil$"]',  # newline → config-line injection
    '["api\\t.com"]',                # control char
    '["a..b.com"]',                  # empty RFC-1123 label
    '["-lead.com"]',                 # label cannot start with hyphen
    '["UPPER_under.com"]',           # underscore not RFC-1123
    '[123]',                         # non-string element
    '["ok.com","*.bad"]',            # one bad entry poisons the whole list
])
def test_malformed_entry_denies_all(bad):
    assert render_filter_file(bad) == ""
```

- [ ] **Step 2: Run, fail** — `uv run pytest tests/unit/sandbox/egress_proxy/test_filter_render.py -v`.
- [ ] **Step 3: Implement** `render_filter_file` + a private `_is_valid_host(h: str) -> bool`: parse JSON; if not a `list` → `""`. For each element — if not a `str`, or `_is_valid_host` fails → return `""` (deny-all; a tampered entry must not widen access). `_is_valid_host` enforces RFC-1123: non-empty, total ≤253, each dot-separated label 1–63 chars matching `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`, and **no** scheme / `/` / `*` / whitespace / control chars. Only then `re.escape(host)` wrapped `^…$`; dedup preserving order. **`re.escape` alone is insufficient** — it does not stop a newline in the input from breaking the one-pattern-per-line Filter invariant (`re.escape("a\nb")` keeps the literal newline), so the explicit `_is_valid_host` reject is the security control, not `re.escape`.
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Gate ladder at HALT** (`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`; focused pytest).
- [ ] **Step 6: Commit** `feat(t30): egress-proxy shim — anchored exact-host filter renderer (fail-closed)`.

### Task 3: SESSION_ID handling — fail-closed if absent (watchpoint 1)

**Files:** Modify `infra/sandbox/egress-proxy/cognic_egress_shim.py`; Create `tests/unit/sandbox/egress_proxy/test_session_id.py`

- [ ] **Step 1: Write failing tests** for `resolve_policy_id(env: dict) -> str`:

```python
import pytest

def test_session_id_becomes_policy_id():
    assert resolve_policy_id({"SESSION_ID": "abc123"}) == "abc123"

def test_missing_session_id_raises():
    with pytest.raises(ShimStartupError):
        resolve_policy_id({})

def test_empty_session_id_raises():
    with pytest.raises(ShimStartupError):
        resolve_policy_id({"SESSION_ID": ""})
```

- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** `resolve_policy_id` + a `ShimStartupError`. Absent/empty `SESSION_ID` ⇒ raise (the entrypoint, Task 6, treats this as **refuse-startup** — never emit uncorrelatable records, per the spec's `policy_id = SESSION_ID` contract).
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Gate ladder at HALT.**
- [ ] **Step 6: Commit** `feat(t30): egress-proxy shim — fail-closed on missing/empty SESSION_ID`.

### Task 4: tinyproxy.conf renderer

**Files:** Modify shim; Create `tests/unit/sandbox/egress_proxy/test_conf_render.py`

- [ ] **Step 1: Write failing tests** for `render_tinyproxy_conf(*, filter_path, log_path, port=3128) -> str` asserting the rendered conf contains exactly: `Port 3128`, `FilterDefaultDeny Yes`, `Filter "<filter_path>"`, **no** `FilterURLs` line (security pin — assert `"FilterURLs" not in conf`), `ConnectPort 443`, `LogFile "<log_path>"`.
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** the renderer.
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Gate ladder at HALT.**
- [ ] **Step 6: Commit** `feat(t30): egress-proxy shim — tinyproxy.conf renderer (FilterDefaultDeny, no FilterURLs, ConnectPort)`.

### Task 5: access.jsonl record emitter (ProxyAccessRecord schema) — **path-dependent on Task 1**

**Files:** Modify shim; Create `tests/unit/sandbox/egress_proxy/test_record_emit.py`

Implement the variant chosen by Task 1.

**Task 5a (Path 1 — log-tail mapper):**
- [ ] **Step 1: Write failing tests** for `tinyproxy_line_to_record(line, *, policy_id) -> dict | None` using the **real captured log lines from Task 1** as fixtures. Assert each maps to a dict with keys `host`, `method`, `timestamp` (tz-aware ISO 8601), `policy_id`, `outcome ∈ {"allowed","refused"}`, `refusal_reason ∈ {None,"not_in_allow_list","non_http_connect_target"}`. Non-access lines (startup/notice) → `None`.
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** the mapper using the Task-1 mapping table; tz-aware timestamps (UTC with offset).
- [ ] **Step 4: Run, pass.**

**Task 5b (Path 2 — in-path decision emitter, only if Task 1 chose it):**
- [ ] **Step 1: Write failing tests** for `decide_and_record(host, method, *, allow_list, policy_id) -> dict` asserting the same 6-field schema, with the shim making the allow/deny decision from `allow_list` (anchored match) + `ConnectPort` semantics.
- [ ] **Step 2–4:** red/green as above.

Common:
- [ ] **Step 5: Schema-conformance test** — round-trip every emitted record through the backend parser: `from cognic_agentos.sandbox.backends.docker_sibling import _parse_proxy_log_jsonl` and assert it yields a valid `ProxyAccessRecord` (this pins the image to the on-gate contract).
- [ ] **Step 6: Gate ladder at HALT.**
- [ ] **Step 7: Commit** `feat(t30): egress-proxy shim — access.jsonl emitter conforming to ProxyAccessRecord (path <1a|2b>)`.

### Task 6: shim PID1 entrypoint

**Files:** Create `infra/sandbox/egress-proxy/entrypoint.py`; Create `tests/unit/sandbox/egress_proxy/test_entrypoint.py` (unit-test the orchestration via injected fakes — no real tinyproxy in unit tests)

- [ ] **Step 1: Write failing test** for an `Entrypoint` orchestrator (DI: subprocess launcher + clock injected) asserting order: resolve `policy_id` (refuse-startup if missing) → render filter file + conf → **ensure `/var/log/cognic-proxy/access.jsonl` exists at runtime** (empty-valid) → start tinyproxy → run the emit loop. Assert refuse-startup short-circuits before launching tinyproxy.
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** the entrypoint (thin; pure logic already in `cognic_egress_shim`). Propagate SIGTERM/SIGINT to tinyproxy for clean stop.
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Gate ladder at HALT.**
- [ ] **Step 6: Commit** `feat(t30): egress-proxy shim — PID1 entrypoint orchestration`.

### Task 7: egress-proxy Dockerfile

**Files:** Create `infra/sandbox/egress-proxy/Dockerfile`

- [ ] **Step 1:** Author the Dockerfile: pinned base (from Task 1), install pinned tinyproxy + Python, `COPY` the shim, `USER` non-root numeric, `VOLUME ["/var/log/cognic-proxy"]`, `EXPOSE 3128`, `ENTRYPOINT ["python","/opt/cognic/entrypoint.py"]`. Immutable — no build-time network installs beyond the pinned package step (`[[feedback_immutable_runtime_images_no_dynamic_install]]`).
- [ ] **Step 2: Build locally** (Linux Docker): `docker build -t cognic/sandbox-egress-proxy:dev infra/sandbox/egress-proxy`.
- [ ] **Step 3: Smoke** — run with `ALLOW_LIST='["example.com"]' SESSION_ID=test`, confirm it binds 3128, creates `/var/log/cognic-proxy/access.jsonl`, and refuses startup with `SESSION_ID` unset.
- [ ] **Step 4: Commit** `feat(t30): egress-proxy production Dockerfile (tinyproxy + shim, non-root)`.

---

## Phase 2 — runtime-python image

### Task 8: runtime-python Dockerfile

**Files:** Create `infra/sandbox/runtime-python/Dockerfile`

- [ ] **Step 1:** Author: pinned Python base; numeric `USER`/GID (record the GID — it's what `COGNIC_Z3_EXPECTED_WORKLOAD_GID` must match for Z3); read-only-root-compatible writable `/workspace` via `VOLUME` (mirror `tests/fixtures/sandbox/runtime-fixture.Dockerfile`'s proven approach); minimal SBOM-capturable toolset; no dynamic install at create time.
- [ ] **Step 2: Build + smoke** — `docker build`; run a trivial `exec` to confirm `/workspace` is writable under read-only root and the numeric USER resolves.
- [ ] **Step 3: Commit** `feat(t30): runtime-python production Dockerfile (non-root numeric USER, writable /workspace)`.

---

## Phase 3 — build / sign / push (produces the real digests)

### Task 9: build + SBOM + scan + sign + push both images

**Files:** Create `infra/sandbox/build-and-sign.md` (runbook) + optionally `infra/sandbox/build-and-sign.sh` (operator script)

**Note:** This is the **image** supply-chain variant — `cosign sign` on the OCI ref (distinct from `cli/sign.py`'s `cosign sign-blob` pack-bundle path). Signatures + SBOM must satisfy the catalog's existing admission (`verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse`, `catalog.py`).

- [ ] **Step 1:** For each image: build → `syft <image> -o spdx-json` (SBOM) → `grype <image>` (scan; record baseline) → `cosign sign <image>` → push. Z3: load into the **Linux Docker** host. Z4: push to the **CRC internal registry** (`image-registry.openshift-image-registry.svc:5000/cognic-sandbox/...`) + create the image stream.
- [ ] **Step 2: Capture the resolved `@sha256:` digests** for both images (this is the output other tasks consume). Record in the runbook.
- [ ] **Step 3: Verify catalog admission accepts them** — a focused check that `verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse` pass against the signed images (env-gated live check).
- [ ] **Step 4: Commit** `chore(t30): image build+sign+push runbook + captured canonical digests`.

---

## Phase 4 — catalog wiring + constant swap (consumes the digests)

### Task 10: Settings surface for canonical refs (both images) + canonical trust root

**Files:** Modify `src/cognic_agentos/core/config.py`; Modify `tests/unit/test_config.py`

- [ ] **Step 1: Write failing tests** asserting `Settings` exposes three fields: `sandbox_canonical_runtime_python_image: str` + `sandbox_canonical_egress_proxy_image: str` (full OCI refs incl. `@sha256:`, env-overridable `COGNIC_SANDBOX_CANONICAL_*`, validator rejecting refs without `@sha256:`) **and** `sandbox_canonical_image_trust_root_path: Path` (the AgentOS canonical cosign trust root used to verify canonical-image signatures; env-overridable).
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** the three `Field(...)` settings (mirror `core/config.py:79-113`) + the `@sha256:` validator on the two image refs.
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Full gate ladder at HALT** (CC-adjacent — `core/config.py`).
- [ ] **Step 6: Commit** `feat(t30): Settings for canonical sandbox image refs + canonical image trust root (CRITICAL CONTROLS)`.

### Task 10b: `catalog.py` — `canonical_trust_root` (CRITICAL CONTROLS)

**Files:** Modify `src/cognic_agentos/sandbox/catalog.py`; Modify `tests/unit/sandbox/test_image_catalog.py`

Per spec §7.1.1 (user-confirmed Option 1). Canonical images are AgentOS-signed platform artifacts → a single canonical trust root, NOT the per-tenant `TrustRootResolver` (which stays out of scope, N5).

- [ ] **Step 1: Write failing tests:**
  - **(a)** Construct `CanonicalImageCatalog(canonical_refs={<digest>}, tenant_trust_roots={}, tenant_allow_lists={}, canonical_trust_root=<path>)`; assert `verify_cosign_or_refuse(<canonical digest>, tenant_id="t-anything")` does **NOT** return the "no trust root configured" failure (it proceeds to use `canonical_trust_root` — mock the cosign subprocess seam, as the existing catalog tests do).
  - **(b)** Regression: a **tenant-allow-listed** (non-canonical) digest with `canonical_trust_root` set but no `tenant_trust_roots[tenant_id]` entry STILL returns "no trust root configured" — canonical root must not leak into the tenant-image path.
  - **(c)** Backward-compat: omitting `canonical_trust_root` (default `None`) preserves today's behavior exactly (canonical digest with no canonical root + no tenant root ⇒ "no trust root configured").
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** — add `canonical_trust_root: Path | None = None` to `__init__` (store it); in `verify_cosign_or_refuse`, when `image_digest in self._canonical_digests` and `self._canonical_trust_root is not None`, use it; else fall back to `self._tenant_trust_roots.get(tenant_id)` (unchanged path). No other behavior change.
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Full gate ladder at HALT** — **`catalog.py` is critical-controls; halt-before-commit** per `[[feedback_strict_review_off_gate]]`; map (a)/(b)/(c) to their pinning tests in the HALT summary; confirm the per-tenant pack-verification path is unchanged.
- [ ] **Step 6: Commit** `feat(t30): catalog canonical_trust_root for AgentOS-signed canonical images (CRITICAL CONTROLS)`.

### Task 11: real `CanonicalImageCatalog` construction in the backend factory

**Files:** Modify `src/cognic_agentos/sandbox/backend_factory.py`; Modify `tests/unit/sandbox/test_backend_factory.py`

Per spec §7.1.1 — Option 1. T30 uses `tenant_allow_lists={}` (only the two kernel-canonical images), so the catalog needs `canonical_refs` + `canonical_trust_root` (from T10b/T10); `tenant_trust_roots={}`. No `TrustRootResolver` (N5).

- [ ] **Step 1: Write failing tests** asserting `get_backend(settings)` constructs a `CanonicalImageCatalog` where: (a) `canonical_refs` includes **both** `settings.sandbox_canonical_runtime_python_image` + `…_egress_proxy_image`; (b) `canonical_trust_root == settings.sandbox_canonical_image_trust_root_path`; (c) `tenant_trust_roots == {}` and `tenant_allow_lists == {}`; and the catalog is injected as the backend's `image_catalog`. Add an assertion that the constructed catalog's `verify_cosign_or_refuse(<canonical digest>, tenant_id="t-x")` does NOT short-circuit on "no trust root configured" (cosign seam mocked) — proving the canonical-root wiring end-to-end through the factory.
- [ ] **Step 2: Factory-authoritative contract test.** Assert the factory **overwrites** any caller-supplied `image_catalog` in `kwargs` (mirroring how it already overwrites `settings`), so a caller cannot bypass production wiring. Migrate the existing `_docker_kwargs`/`_k8s_kwargs` helpers (`tests/unit/sandbox/test_backend_factory.py:49`) that pass a `MagicMock` `image_catalog`: tests that need a fake catalog now patch the construction seam (`monkeypatch.setattr` on the catalog builder), not inject via kwargs.
- [ ] **Step 3: Run, fail.**
- [ ] **Step 4: Implement** — factory builds `canonical_refs` from the two image Settings + `canonical_trust_root=settings.sandbox_canonical_image_trust_root_path` + `tenant_trust_roots={}` + `tenant_allow_lists={}`; constructs the catalog; sets `kwargs["image_catalog"]` **authoritatively** (overwrite, like `kwargs["settings"]`); passes to the backend (both arms).
- [ ] **Step 5: Run, pass.**
- [ ] **Step 6: Full gate ladder at HALT** (CC-adjacent; the authoritative-injection is a factory **contract change** — call it out + map to the overwrite test).
- [ ] **Step 7: Commit** `feat(t30): factory builds + authoritatively injects production canonical catalog (canonical_trust_root; image_catalog overwrite) (CRITICAL CONTROLS)`.

### Task 12: constant swap + consistency assertion

**Files:** Modify `src/cognic_agentos/sandbox/backends/docker_sibling.py:186`; Modify `src/cognic_agentos/sandbox/backends/kubernetes_pod.py:254`; Modify a test pinning the constant↔catalog agreement

- [ ] **Step 1: Write failing test** asserting (a) `_CANONICAL_EGRESS_PROXY_IMAGE` equals the real signed proxy ref from Task 9 (no `"d"*64` placeholder), and (b) the constant's digest equals `settings.sandbox_canonical_egress_proxy_image`'s digest (the spec's consistency invariant — launch selector == catalog member).
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement** — replace the placeholder in both backends with the real digest (from Task 9).
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Full gate ladder at HALT** — **critical-controls; halt-before-commit per `[[feedback_strict_review_off_gate]]`**; map the consistency invariant to its pinning test in the HALT summary.
- [ ] **Step 6: Commit** `feat(t30): replace placeholder canonical egress-proxy digest in both backends (CRITICAL CONTROLS)`.

---

## Phase 5 — proofs

### Task 13: egress-enforcement proof (the empirical denied-HTTPS-CONNECT live test)

**Files:** Create `tests/integration/sandbox/test_egress_enforcement.py` (env-gated, opt-in like Z3/Z4)

- [ ] **Step 1: Write the proof** (env-gated `COGNIC_RUN_EGRESS_ENFORCEMENT_PROOF=1`, fail-loud-when-opted-in per the Finding-#3 import contract). **Hermetic upstreams (no public deps):** stand up controlled local services on the sandbox-internal network — an HTTP echo + a TLS-terminating echo — bound to explicit host aliases `allowed.test` (in the allow-list) + `denied.test` (not). All cases target these aliases; the test owns the DNS/alias mapping (Docker network aliases for Z3; a sidecar/Service alias for the K8s smoke leg). Cases, each asserting the `access.jsonl` record too:
  - allowed HTTP host → forwarded; record `outcome="allowed"`.
  - allowed HTTPS host (`CONNECT`) → forwarded; `outcome="allowed"`, `method="CONNECT"`.
  - **denied HTTPS host (`CONNECT`) → BLOCKED live** (G6 — empirical, not inference); `outcome="refused"`, `refusal_reason="not_in_allow_list"`.
  - denied HTTP host → blocked; `not_in_allow_list`.
  - `CONNECT` to non-allowed port → `non_http_connect_target`.
  - malformed `ALLOW_LIST` → fail-closed (deny all).
  - schema: every record parses via `_parse_proxy_log_jsonl`.
- [ ] **Step 2: Run live** on the Linux Docker surface (and the K8s surface for the smoke leg). Green required.
- [ ] **Step 3: Commit** `test(t30): egress-enforcement proof (allow/deny HTTP+HTTPS, empirical denied-CONNECT, fail-closed)`.

### Task 14: rerun canonical Z3/Z4 → close when green

- [ ] **Step 1:** Export the canonical audit env (per the project-state checklist: `COGNIC_VAULT_TEST_*`, `COGNIC_Z{3,4}_RUNTIME_IMAGE`=real signed runtime, `COGNIC_Z{3,4}_EXPECTED_WORKLOAD_GID`, the `COGNIC_RUN_{DOCKER,K8S}_CREDENTIAL_PROJECTION_INTEGRATION=1` opt-ins; fixture vars unset).
- [ ] **Step 2: Run the four canonical targets** (Z3 happy/negative on Linux Docker; Z4 happy/LIFO on CRC). Green required.
- [ ] **Step 2b: Real-catalog admission proof (closes the MagicMock gap).** The existing Z3/Z4 helpers stub `image_catalog` with `MagicMock` (`test_z3_docker_credential_projection.py:476`, `test_z4_k8s_credential_projection.py:548`; `is_canonical → True`, `verify_*_or_refuse → None`), so the four canonical targets do **not** exercise the production catalog — they would stay green even if T10–T12 wiring were broken. Add an env-gated test (one Docker leg + one K8s leg) that constructs the **real** `CanonicalImageCatalog` via `get_backend(settings)` (T11) — NOT a MagicMock — and drives `create()` end-to-end against the signed images, so `is_canonical` + `verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse` actually run + pass — with `settings.sandbox_canonical_image_trust_root_path` pointing at the real AgentOS cosign trust root, so canonical cosign verification routes through the `canonical_trust_root` path (T10b), NOT a per-tenant root. This is the test that proves T10–T12 (incl. T10b). The MagicMock Z3/Z4 stay as projection-mechanics coverage (orthogonal).
- [ ] **Step 3:** Record manual-proof timestamps. Canonical Z3/Z4 close **only** when both the four targets AND the real-catalog admission proof are green.

---

## Phase 6 — closeout

### Task 15: T30 closeout + HOLD

- [ ] **Step 1:** Full gate ladder at current HEAD (ruff/format/mypy + `pytest -q --cov-branch --cov-report=json:coverage.json` + `tools/check_critical_coverage.py` — the gate must stay green; T12 touched CC modules).
- [ ] **Step 2: Closeout report:** images built+signed+pushed (digests); placeholder removed; catalog wired; egress-enforcement proof green; canonical Z3/Z4 green (timestamps); the §8 path taken.
- [ ] **Step 3: HOLD** for explicit authorization — then 10.6 + T30 merge, each token-gated (`push`/`pr`/`merge`); Phase 3 + sprint CLOSED markers only at merge.

---

## Out of scope (deferred — do NOT do here)
- `sandbox-runtime-shell`, `sandbox-runtime-data` (Sprint 14).
- Settings-injected **proxy** *selector* (N2 — proxy selector stays the constant; only the runtime refs + catalog membership are Settings-driven here).
- The AGENTS.md `--network none` doc-drift correction (separate stop-rule doc edit, under separate authorization).

## Self-review
- **Spec coverage:** §5 proxy → T1–T7; §6 runtime → T8; §7.1 catalog → T10–T11; §7.2 supply chain → T9; §7.3 constant swap → T12; §8 risk → T1 (gate) + T5 (path); §9 tests → T13–T14; §10 hold → T15. ✓
- **Watchpoints:** SESSION_ID fail-closed → T3 + T6; §8 spike load-bearing + path-2 fallback → T1 + T5b; AGENTS.md drift kept separate → Out-of-scope. ✓
- **Types/paths:** `_parse_proxy_log_jsonl` (`docker_sibling.py:372`) used as the schema oracle in T5; constants at `docker_sibling.py:186`/`kubernetes_pod.py:254`; factory `get_backend(settings, /, **kwargs)`; backend ctor kwarg `image_catalog` (the catalog instance the factory injects); planned catalog ctor param `canonical_trust_root` (alongside `canonical_refs` / `tenant_trust_roots` / `tenant_allow_lists`). ✓
- **Digest DAG:** T9 produces digests; T10/T12 consume them; T12's consistency test pins constant==catalog. ✓
- **Review round 1 fixes:** catalog needs `tenant_trust_roots` + `tenant_allow_lists`, not just `canonical_refs` (the *derivation* mechanism was then corrected in round 2 — see below); canonical Z3/Z4 stub the catalog with MagicMock so the rerun alone doesn't prove the wiring → real-catalog admission proof T14 Step 2b; shim allow-list fail-closes on any malformed RFC-1123 entry (not just bad JSON) → T2 strengthened; live proofs use hermetic local `allowed.test`/`denied.test` upstreams, no public deps → T1 Step 2 + T13 Step 1. ✓
- **Review round 2 fixes:** the trust-root derivation was un-implementable (`trust_root_prefix` resolves nothing; real surface is the async per-tenant `TrustRootResolver`). Resolved via Option 1 (user-confirmed): a `canonical_trust_root` on the catalog for AgentOS-signed canonical images → new CC task T10b (`catalog.py`) + the `sandbox_canonical_image_trust_root_path` Setting (T10) + factory wiring (T11); `TrustRootResolver` kept out of scope (spec N5). Factory is authoritative for `image_catalog` (overwrite, mirroring `settings`), not `setdefault` → T11 Step 2 + test migration off kwargs-injection. Spec amended at §7.1.1. ✓
