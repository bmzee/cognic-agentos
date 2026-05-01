# Sprint 4 — Plugin Registry + Trust Gate + Supply-Chain Attestations + Policy-Engine Seed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** AgentOS discovers installed plugin packs via Python entry points, verifies the full Wave-1 supply-chain attestation set per ADR-016 (cosign signature + SLSA + in-toto + SBOM + vuln scan + license audit + Sigstore bundle), persists Sigstore bundles for 7-year offline re-verification, enforces per-tenant allow-list, and exposes the registry through the operator-facing `/api/v1/system/plugins` endpoint. Decisions about partial-grade tolerance go through a Rego policy bundle evaluated by the new Sprint-4-seed policy engine. Lands all five new critical-controls modules (`protocol/plugin_registry`, `protocol/trust_gate`, `protocol/supply_chain`, `core/policy/engine`, plus the production filesystem `db/adapters/local_object_store_adapter` — the first real `ObjectStoreAdapter` implementation per AGENTS.md production-grade rule; Sprint 8 adds an S3 driver alongside, both drivers conform to the same Protocol).

**Architecture:** A pack-registration pipeline composed of four layered checks, each emitting hash-chained `audit_event` and `decision_history` rows into the Sprint 2 substrate:

```
discover (entry-point walk)
   │
   ▼
trust_gate (cosign verify against per-tenant trust root + allow-list)
   │
   ▼
supply_chain (SLSA + in-toto + SBOM + vuln + license verifiers
              → mandatory-floor vs grace-period grade decision)
   │
   ▼
policy.engine (Rego query against tenant supply_chain.rego bundle
              → final allow / deny / refuse-on-partial decision;
              emits decision_history rows)
   │
   ▼
sigstore-bundle persister (atomic write to LocalObjectStoreAdapter
              under attestations/<pack_id>/<version>/bundle.sigstore
              with retention metadata)
   │
   ▼
registry.register(pack, attestation_grade)  →  GET /api/v1/system/plugins
```

Pack-registration outcomes are flat: `registered` or `refused_at_registration` plus `attestation_grade: full | partial` + `refusal_reason`. The full ADR-012 lifecycle (`submitted → under_review → approved → allow_listed → installed → revoked → uninstalled`) is **deferred to Sprint 7B**.

**Tech Stack:** Python 3.12, `importlib.metadata.entry_points` (pack discovery), `subprocess` with `shell=False` + explicit list-form argv (cosign + opa shell-out — secure invocation per ADR-016 §"What this is NOT" and the April 2026 MCP supply-chain disclosures), Pydantic Settings (additive fields), SQLAlchemy 2.0 async (no new tables — emissions go through the existing Sprint-2 `audit_event` + `decision_history` chain), FastAPI (one new GET endpoint), the Sprint 2 substrate (`AuditStore`, `core/canonical`), the Sprint 2.5 substrate (`SLATimer`, `decision_history.append_with_precondition[T]`), filesystem (`LocalObjectStoreAdapter` filesystem-backed atomic writes via `os.fsync` + `os.rename`).

---

## Doctrine adherence — locked-before-code decisions

Sprint 4 sits atop a dense ADR set (ADR-002 plugin protocol, ADR-009 adapter protocols, ADR-012 pack lifecycle, ADR-015 policy-as-code, ADR-016 supply-chain controls). These eight decision-locks resolve doctrine conflicts that surfaced in pre-plan brainstorm review and prevent rebuild churn during implementation.

### §1 Pack discovery contract

`PluginRegistry.discover()` walks `importlib.metadata.entry_points(group="cognic.tools")` + `cognic.skills` + `cognic.agents`. Each entry point's `EntryPoint.load()` is **deferred to `PluginRegistry.load(kind, name)`**, NOT eagerly called at discovery time. Eager loading would import every pack at AgentOS startup; that defeats sandboxing + delays kernel readiness + lets a malicious pack execute `import`-time code before trust verification runs.

Discovery captures the entry-point metadata (group / name / module path / attribute) only. The trust gate runs on the *metadata* (cosign signature digest of the distribution wheel/sdist that contains the entry point); the actual `load()` happens after registration succeeds AND only when an explicit caller asks.

**Sprint 4 registration trigger surface — startup-only, no portal endpoint** (P3-C clarification): registration runs once at AgentOS lifespan startup; there is no human-initiated registration endpoint in Sprint 4. The auth surface is the file-backed per-tenant allow-list (§6) — no RBAC scope checks, no portal POST. ADR-012's full lifecycle (`pack.submit` / `pack.review.approve` / `pack.allow_list` / `pack.install` / `pack.revoke`) is Sprint 7B; Sprint 4 deliberately ships none of those scopes. The `/api/v1/system/plugins` endpoint (T11) is read-only.

**AGNTCY/OASF identity-field validation deferred to Sprint 7A** (P3-A clarification): ADR-002 §"Wave 1 identity-field strictness" mandates that pack manifests declare specific identity fields (`agent_id` URN, `display_name`, `provider_organization` + `provider_url`, `agent_card_url`, `agent_card_jws_path` for agent packs). Sprint 4 does NOT validate these fields at registration; that surface lands in Sprint 7A `agentos validate` (pack-author-side) + Sprint 7B reviewer-flow (registry-side). Sprint 4's trust gate consumes the cosign signature over the wheel — that's the only manifest-level check in scope.

### §2 Cosign verification — secure subprocess invariants

The trust gate shells out to cosign. Per ADR-016 §"What this is NOT" + the April-2026 MCP supply-chain disclosures, **no pack-controlled string ever flows into argv**. Locked invariants:

1. **Argv is list-form only.** `subprocess.run([COSIGN_BIN, "verify", ...], shell=False, ...)` — `shell=False` is explicit + tested. A regression that switches to `shell=True` or to a string command line trips the negative-path test in T6.
2. **`COSIGN_BIN` is resolved at module-import time** via `shutil.which(settings.cognic_cosign_path or "cosign")` and frozen into a module-level constant. If `cognic_require_cosign=true` (default) and `which` returns `None`, the trust gate raises `CosignNotInstalledError` at the FIRST call (not at import — kernel-image boot must not fail when only running tests that don't touch the trust gate).
3. **Pack identity / version / signature blob path are validated against a strict regex BEFORE being passed.** Pack name: `^[a-z0-9][a-z0-9_-]{0,127}$`. Version: `^[0-9A-Za-z.+_-]{1,64}$` (PEP 440 superset). Signature blob path: must canonicalise via `os.path.realpath()` to a path under the operator-approved `cognic_signature_root_path` prefix; any traversal attempt rejects.
4. **Per-tenant trust root path** read from settings (file-backed in Sprint 4; Vault swap → Sprint 10). The path is canonicalised + asserted to live under `cognic_trust_root_prefix`; rejects path-traversal attempts.
5. **No environment variables passed through.** Subprocess uses an explicit minimal `env` dict: `{"PATH": "/usr/local/bin:/usr/bin", "HOME": "/tmp"}` only. No `os.environ` passthrough.
6. **Strict timeout** (default 30s, configurable via `cognic_cosign_verify_timeout_s`); on timeout the subprocess is `SIGKILL`-terminated; the timeout itself emits `audit_event(trust_gate.cosign_timeout)` chained into `audit_event` substrate.
7. **Output parsed via cosign's JSON mode (`--output json`)**. Never via shell pipe / regex on free-form stderr. Parse failure → fail-closed refusal.
8. **Negative-path tests cover every input vector.** T6 ships unit tests for: shell metacharacters in pack name (`;`, `|`, `` ` ``, `$`, `&`, newline, backslash, quotes, glob chars); path traversal in signature path (`../`, `/etc/passwd`, symlink targets outside the prefix); over-long inputs (>128 char pack name, >64 char version); valid-looking inputs that fail cosign at the JSON-parse step (truncated output, malformed JSON, JSON that lacks the `verified` field).

### §3 Supply-chain attestation pipeline — mandatory floor vs grace period

Per ADR-016 §"Implementation phases" + Sprint 4's plan-PR shape, attestation verification is a two-tier decision over **7 attestations that grade the pack**, plus a separate 8th informational attestation (reproducibility) verified independently in T8.

**ADR-016's full attestation set is 8 entries** (cosign signature + SBOM + Sigstore bundle + SLSA + in-toto + vuln scan + license audit + reproducibility manifest). Sprint 4's grade decision (full / partial / refused) consults the **first 7**; reproducibility is **opt-in informational** per ADR-016 §"Reproducibility commitment" — verified separately in T8, surfaces as a `reproducible: bool` flag on the registry record, never participates in the refusal decision unless a tenant Rego policy explicitly requires it (deferred to Sprint 13.5 OPA-Rego per ADR-015).

The 7 attestations participating in the grade decision split into two tiers:

**Mandatory floor (refusal-grade — registration refused if any of these are missing):**

1. **cosign signature** verified by `protocol/trust_gate.py` (§2 above).
2. **SBOM** (CycloneDX or SPDX 2.3+); SBOM digest pinned to the pack signature (the SBOM file's SHA-256 must match a digest that was itself signed by the cosign signature).
3. **Sigstore bundle** persisted via `LocalObjectStoreAdapter.put(bucket="cognic-attestations", key=f"attestations/{pack_id}/{version}/bundle.sigstore", body=...)` with **retention metadata = 7 years** enforced at adapter level (T4 contract).

**Grace-period (`attestation_grade: partial` allowed — pack registers, tenant policy decides whether to refuse):**

4. **SLSA L3+ provenance** (`buildType`, `builder.id`, `invocation.configSource` validated). L1/L2 provenance falls back to partial; tampered (signature-fail) provenance is a hard refusal regardless of grade.
5. **in-toto layout** (build steps performed by declared parties in declared order). Mismatched layout → partial; tampered → refusal.
6. **Vulnerability scan** (Trivy/Grype JSON output consumed). Per-tenant Rego policy decides max-CVSS / max-EPSS / known-exploit thresholds.
7. **License audit** (per-tenant allow-list of OSI/SPDX identifiers). Disallowed-copyleft fails for closed-deployment tenants.

**`attestation_grade` is a separate field on the registry record** — `full` if all 7 verifiers pass; `partial` if any of (4)-(7) fails or is missing AND tenant Rego policy permits. The Rego policy in `policies/_default/supply_chain.rego` is the final arbiter on whether `partial` is acceptable for a given (pack, tenant) pair.

Round-locked: tampered attestations (cryptographic signature failure on SLSA / in-toto / SBOM digest) are NEVER grace-able — they're a hard refusal class. The grace period covers *missing* attestations, not *forged* ones.

### §4 `LocalObjectStoreAdapter` contract — production filesystem storage

**`LocalObjectStoreAdapter` is production filesystem storage, not a mock or test adapter.** Per AGENTS.md "Production-grade implementation rule" (real integrations in the runtime path; mocks confined to clearly separated test paths) + Q1 of pre-plan brainstorm, this Sprint ships the FIRST real `ObjectStoreAdapter` implementation. Banks deploying AgentOS on a single host or on shared filesystem-backed storage (NFS, EFS, Azure Files, GlusterFS, on-prem mounts) run this driver in production indefinitely; Sprint 8 adds an S3 driver as an *alternative* `cognic_object_store_driver` choice, not a replacement. Both drivers conform to the same `ObjectStoreAdapter` Protocol; deployments choose per-tenant. Locked contract:

1. **Filesystem-backed.** Root path from `cognic_local_object_store_root` setting; default `${COGNIC_DATA_DIR:-/var/lib/cognic-agentos}/object-store`. Bucket = first path segment; key = remaining path.
2. **Atomic write via `os.rename`.** `put(bucket, key, body)` writes to `<root>/<bucket>/.tmp/<uuid4>.tmp`, fsyncs, then renames into `<root>/<bucket>/<key>`. Crash-safe on POSIX; partial files never visible. Concurrent writes to the same key resolve last-writer-wins (acceptable for Sigstore-bundle re-uploads of the same pack version — content is identical).
3. **Path-traversal safe.** All `bucket` + `key` arguments validated by regex (`^[a-z0-9][a-z0-9._/-]{0,255}$`); resolved path must canonicalise via `os.path.realpath()` to remain under the configured root. Rejects `..`, absolute paths, NUL bytes, symlinks pointing outside root.
4. **Retention metadata enforced at adapter level.** `put(...)` accepts an optional `retention_seconds` keyword (default `None` = no retention policy). When set, the adapter writes a sidecar `<key>.retention` file containing `{"created_at": "<ISO8601>", "retain_until": "<ISO8601>", "retention_seconds": <int>}`. `delete(bucket, key)` rejects with `RetentionWindowActiveError` if the sidecar's `retain_until` has not passed. T4 unit tests cover (a) deletion within window refused, (b) deletion after window allowed, (c) sidecar tamper (manual edit) → fail-closed-on-read.
5. **`presign(bucket, key, ttl_s)` raises `NotImplementedError`** with message `"presign requires non-local ObjectStoreAdapter driver — local_fs deployments do not support signed-URL semantics"` (P2-B reviewer-fix). The `presign` API exists in the Protocol for S3 swap symmetry, but a `file://`-scheme degenerate URL would silently mislead callers expecting external-HTTP-accessible URLs (e.g. Sprint 7B reviewer dashboard fetching attestation bundles cross-host). Fail-loud is mandatory: any caller that needs presigned-URL access must select an `ObjectStoreAdapter` driver that actually implements signed-URL semantics (S3 / MinIO via Sprint 8). The unit tests in T4 explicitly assert `NotImplementedError` is raised.
6. **`get(bucket, key)` reads body bytes directly.** No decompression, no automatic content-type interpretation; opaque bytes round-trip exactly as written.
7. **`health_check()` returns** `AdapterHealth(status="ok", driver="local_fs", latency_ms=<root-stat-time>)` when the configured root is writable; `unreachable` if the root is missing or unwritable.
8. **Deterministic read-back round-trip** is the load-bearing T4 test: `put(b, k, body); body == get(b, k)` for arbitrary bytes including null bytes, high-bit characters, and 10-MiB Sigstore-bundle-shaped payloads.

This adapter satisfies the Sprint 8-S3 swap point without leaking filesystem-specific details into the caller. Sprint 8 implements `S3ObjectStoreAdapter` against the same Protocol; the only change at the Sigstore-bundle persister is the registered driver name.

### §5 `core/policy/engine.py` Rego evaluator seed — minimal Sprint 4 scope

Per ADR-015 §"Sprint 4 (seed)", Sprint 4 ships the smallest evaluator that can answer `policies/_default/supply_chain.rego`:

1. **Engine type:** OPA Go binary subprocess invocation (Q3 lock — WASM revisited post-Sprint-13.5). Binary pinned in `infra/agentos/Dockerfile` (`default-adapters` target only — the kernel image does NOT carry the OPA binary; calling `policy.engine.evaluate()` from a kernel-only deployment fail-closes with `OpaNotInstalledError`).
2. **API:** `async def evaluate(decision_point: str, input: dict) -> Decision`. `Decision` is a frozen+slotted dataclass: `(allow: bool, rule_matched: str | None, reasoning: str, decision_data: dict[str, Any] | None)`. Q8 lock — `decision_data` carries Sprint-specific outcome data (e.g. `{"attestation_grade": "full"}`).

   **Async deviation from ADR-015 §"Engine integration"** (P2-D reviewer-fix). ADR-015 specs `Sync API: engine.evaluate(decision, input) -> Decision`. The plan deliberately deviates: Sprint 2's `AuditStore.append` + Sprint 2.5's `decision_history.append_with_precondition` substrates are async; emitting `policy.decision_evaluated` synchronously inside `evaluate()` would require either `asyncio.to_thread` (defeats the async substrate's chain-head FOR UPDATE serialisation) or fire-and-forget (breaks ADR-007-style "no successful return without persisted evidence" discipline). Async `evaluate()` aligns with the Sprint 2 substrate's locking model. ADR-015's "Sync API" wording predates the Sprint-2 async substrate decision; the deviation is doctrine-aware, not accidental.
3. **Bundle loading:** load-from-disk only at startup. NO hot-reload (Sprint 13.5 adds it). Bundle path = `cognic_supply_chain_policy_bundle`; default `policies/_default/supply_chain.rego`. Missing bundle file → fail-closed `RegoBundleNotFoundError` at engine construction.
4. **Bundle compilation:** at engine construction, the evaluator runs `opa eval --partial --data <bundle-path>` once to validate the bundle syntactically. Syntax error → fail-closed `RegoBundleInvalidError` with the OPA error message embedded. No runtime bundle reload.
5. **Per-call invocation:** for each `evaluate()` call, the evaluator runs `opa eval --data <bundle-path> --input <input-as-json> --format json "<decision-point-query>"` with a strict 5-second timeout. Subprocess shape mirrors §2 — list-form argv, `shell=False`, explicit minimal env, JSON output parse, fail-closed on non-zero exit / parse failure / timeout.
6. **Audit emission contract** (Q7 lock — first `decision_history` emissions in the project):
   - `policy.bundle_loaded` — emitted ONCE per engine-construction in Sprint 4 (no hot-reload). Hash-chained into `decision_history`. Payload: `{"bundle_path": "<path>", "bundle_sha256": "<hash>", "loaded_at": "<ISO8601>"}`. NO bundle source content in payload (just the path + hash). **Cardinality future-proofing** (P3-E): when Sprint 13.5 adds hot-reload, this emission becomes per-reload (one row per bundle-load attempt — both successful and failed). The Sprint-4 schema/payload shape is forward-compatible — no payload-shape change is needed when the cardinality flips, only the call-site frequency.
   - `policy.decision_evaluated` — emitted on every `evaluate()` call. Hash-chained into `decision_history`. Payload: `{"decision_point": "<str>", "input_fingerprint": "<sha256>", "rule_matched": "<str|null>", "outcome": "allow|deny", "bundle_sha256": "<hash>"}`. **`input_fingerprint` is `sha256(canonical_bytes(input))` per Sprint 2 substrate** — never the input itself (input may carry pack manifest content + tenant identifiers; fingerprint is the auditable index).
7. **No pack-controlled string flows into the OPA argv.** Decision-point query strings are compile-time constants; `input` is JSON-serialised via the Sprint-2 canonical-form path (deterministic). The full §2 secure-subprocess invariant set applies.

### §6 Per-tenant allow-list source — file-backed in Sprint 4

Per Q6 lock + ADR-002 trust contract:

- Allow-list path = `cognic_plugin_allowlist_path` (settings field). Default: `policies/_default/plugin_allowlist.json`.
- Format: `{"<tenant_id>": ["<pack_name>", ...]}`. JSON, version-controlled, cosign-signed in production.
- Loaded once at registry construction (`PluginRegistry.from_paths(...)`); refresh requires AgentOS restart in Sprint 4.
- Vault swap → Sprint 10; the file-path setting becomes a Vault path setting then. No API surface change.
- A pack registered without an allow-list match is **refused at registration** with `refusal_reason="not_in_tenant_allowlist"` and emits `audit_event(plugin.registration_refused)` chained into `audit_event` substrate.

### §7 First `decision_history` emissions — critical-controls discipline

Sprint 3 explicitly deferred `decision_history` emission to Sprint 9.5 (waiting for `model_id` per ADR-013). Sprint 4's `policy.bundle_loaded` + `policy.decision_evaluated` emissions are the FIRST `decision_history` rows in the project. They are `impact: high` per ISO 42001 control A.7.4 mapping (admission decisions on plugin packs that affect what the OS will execute).

Implications:
- Every commit touching either emission halts-before-commit per AGENTS.md critical-controls discipline.
- Both emissions use `decision_history.append_with_precondition[T]` (Sprint 2.5 atomic-validator primitive — there's no precondition logic for these specific events, so the precondition is an async no-op + identity record_builder, mirroring the existing `decision_history.append()` wrapper).
- Negative-path tests pin: malformed payload → emission rejection at canonical-form boundary; concurrent emissions serialise via FOR UPDATE on `governance_chain_heads`; tamper-evidence walks clean via `ChainVerifier(engine, "decision_history")`.
- The audit + decision-history shape is the Sprint-4 evidence surface. Examiners reviewing pack admissions reconstruct the chain of (`policy.bundle_loaded` → `policy.decision_evaluated` × N → `plugin.registration_succeeded` / `plugin.registration_refused`) per pack.

### §8 Critical-controls coverage gate extension

Per AGENTS.md critical-controls list + Sprint 4 plan exit criterion, `tools/check_critical_coverage.py` extends to enforce ≥95% line / ≥90% branch on:

- `protocol/plugin_registry.py` (entry-point discovery — pack-trust attack surface)
- `protocol/trust_gate.py` (cosign verification — argv-construction critical control)
- `protocol/supply_chain.py` (full ADR-016 attestation pipeline — refusal-grade gates)
- `core/policy/engine.py` (Rego decision engine — admission-control substrate)

Plus the `LocalObjectStoreAdapter` per Q1 — but at the existing **adapter coverage tier** (≥80% line per the Sprint-1C convention; not the strict 95/90 because adapter implementations are evidence-quality work, not chain-of-custody work).

After T15, the gate enforces **16 modules** (the Sprint 2 quartet + Sprint 2.5 triplet + Sprint 3 LLM quintet + Sprint 4 protocol/policy quartet). The single-tier gate convention from Sprint 3 holds.

Reproducibility manifest verification (`protocol/reproducibility.py`) is **not** added to the gate — the module is a thin manifest-digest verifier in Sprint 4 (rebuild verification is Sprint 7B reviewer territory). Coverage discipline is per-file ≥80% via the global rollup, no per-file gate.

---

## File Structure

### Created (~22)

**`src/cognic_agentos/protocol/`** (new package):
- `__init__.py` — package marker
- `plugin_registry.py` — `PluginRegistry`, `PluginRecord`, `PluginKind` Literal, `discover()`, `register(record, attestation_grade)`, `load(kind, name)`, `known_packs()`, `RegistrationRefused` exception, `refusal_reason` enum vocabulary
- `trust_gate.py` — `verify_pack_signature(pack_id, version, signature_path, trust_root, *, settings) -> CosignVerificationResult`, `CosignVerificationResult` dataclass, `CosignNotInstalledError`, `CosignVerificationFailed`, `_validate_pack_id`, `_validate_version`, `_validate_signature_path`, `_canonicalise_under_root`, secure-subprocess wrapper
- `supply_chain.py` — `verify_attestation_set(pack_id, version, attestation_dir, *, settings) -> AttestationResult`; `AttestationResult` (`grade: Literal["full", "partial"]`, `verified: dict[str, bool]`, `findings: list[str]`); per-attestation verifiers (`_verify_sbom`, `_verify_slsa`, `_verify_intoto`, `_verify_vulnerability_scan`, `_verify_license_audit`); the mandatory-floor check
- `reproducibility.py` — `verify_reproducibility_manifest(manifest_path, signature_path, *, settings) -> bool`. Sprint 4 verifies the manifest's digest is signed; rebuild itself is Sprint 7B.

**`src/cognic_agentos/core/policy/`** (new package):
- `__init__.py` — package marker
- `engine.py` — `OPAEngine`, `Decision` dataclass, `evaluate(decision_point, input)`, `OpaNotInstalledError`, `RegoBundleNotFoundError`, `RegoBundleInvalidError`, `RegoEvaluationError`; `_audit_emit_bundle_loaded`, `_audit_emit_decision_evaluated`

**`src/cognic_agentos/db/adapters/`**:
- `local_object_store_adapter.py` — `LocalObjectStoreAdapter` filesystem impl conforming to `ObjectStoreAdapter` Protocol; atomic-write, path-traversal-safe, retention-metadata-enforced

**`policies/_default/`** (new directory at repo root):
- `supply_chain.rego` — Sprint 4's only bundle. Default rules: full grade always allowed; partial grade allowed unless tenant policy `require_full = true`. Rego version 1.x.
- `plugin_allowlist.json` — file-backed per-tenant allow-list (Vault swap → Sprint 10)

**`tests/fixtures/`** (new directory):
- `__init__.py`
- `cognic_test_pack/` — installable test pack with full attestation set:
  - `pyproject.toml` (declares `cognic.tools` entry point)
  - `cognic_test_pack/__init__.py` (the importable module)
  - `cognic_test_pack/tool.py` (a stub Tool class)
  - `attestations/cosign.sig` (pre-baked signed blob — see T12 for generation)
  - `attestations/sbom.cdx.json` (CycloneDX SBOM)
  - `attestations/slsa-provenance.intoto.jsonl`
  - `attestations/intoto-layout.json`
  - `attestations/vuln-scan.json` (Grype JSON output, no findings)
  - `attestations/license-audit.json` (allow-listed licenses only)
  - `attestations/bundle.sigstore` (cosign attest --bundle output)

- `tests/unit/protocol/__init__.py`
- 4 unit test modules (T5/T6/T7/T8 below)

- `tests/unit/core/policy/__init__.py`
- 1 unit test module (T2/T3)

- `tests/unit/db/adapters/test_local_object_store_adapter.py` (T4)

- `tests/unit/portal/api/test_plugins_endpoint.py` (T11)

### Modified (~7)

- `pyproject.toml` — no entry-point group declarations needed (groups materialise from installed packs); `[project.optional-dependencies].adapters` extended with the OPA Go binary install hook (vendored — see T13). `dev` extra unchanged.
- `src/cognic_agentos/core/config.py` — Sprint 4 settings group:
  - `cognic_plugin_allowlist_path: Path` (default: `Path("policies/_default/plugin_allowlist.json")`)
  - `cognic_require_cosign: bool = True`
  - `cognic_cosign_path: str | None = None` (None → `shutil.which("cosign")`)
  - `cognic_cosign_verify_timeout_s: float = 30.0` (gt=0)
  - `cognic_supply_chain_policy_bundle: Path` (default: `Path("policies/_default/supply_chain.rego")`)
  - `cognic_opa_path: str | None = None` (None → `shutil.which("opa")`)
  - `cognic_opa_eval_timeout_s: float = 5.0` (gt=0)
  - `cognic_local_object_store_root: Path` (default: derived from `runtime_profile`; `/var/lib/cognic-agentos/object-store` for prod, `${tmpdir}/object-store` for dev)
  - `cognic_signature_root_path: Path` (default: `Path("attestations")` — relative to the configured pack-distribution root)
  - `cognic_trust_root_prefix: Path` (default: `Path("trust-roots")`)
- `src/cognic_agentos/db/adapters/factory.py` — `build_adapters` extends to construct `LocalObjectStoreAdapter` when `cognic_object_store_driver=local`; default driver becomes `local` (was `None`); `S3ObjectStoreAdapter` when Sprint 8 lands flips the default.
- `src/cognic_agentos/db/adapters/registry.py` — registers `local_fs` driver name → `LocalObjectStoreAdapter`.
- `src/cognic_agentos/portal/api/system_routes.py` — adds `GET /api/v1/system/plugins` route + `_plugin_record_dict` helper. Reads `request.app.state.plugin_registry` (set by lifespan).
- `src/cognic_agentos/portal/api/app.py` — extends `create_app` with optional `plugin_registry: PluginRegistry | None` kwarg; lifespan attaches to `app.state.plugin_registry`. Mirrors the Sprint-3 `gateway_ledger` injection pattern.
- `infra/agentos/Dockerfile` — `default-adapters` target installs cosign (pinned SHA256) + OPA Go binary (pinned SHA256). Kernel target stays unchanged. Image-budget regression check confirms kernel stays ≤120 MiB; default-adapters stays ≤220 MiB (current 177 MiB → +cosign 80 + opa 50 = +130 MiB headroom available; expected new size ~190 MiB, well under budget).
- `tools/check_critical_coverage.py` — adds the Sprint 4 quartet at `(0.95, 0.90)` floors.
- `.env.example` — Sprint 4 settings section with operator-facing knobs.
- `docs/HOW-TO-WRITE-A-PACK.md` — new doc with pack-author-facing attestation-requirements section.

---

## Tasks

### Task 0: Confirm clean working tree, branch from main

**Files:** none

- [ ] **Step 1: Confirm clean working tree on `main`**

```bash
git status   # expect "nothing to commit, working tree clean"
git rev-parse HEAD   # confirm we're at 89300de or later
```

Expected: `## main`, no untracked / modified files.

- [ ] **Step 2: Halt for user authorization to branch**

Sprint 4 plan-PR merge is a separate per-action authorization. Wait for explicit `branch + start T1` token before proceeding to Step 3.

- [ ] **Step 3: After authorization, create branch**

```bash
git checkout -b feat/sprint-4-plugin-registry-trust-gate
```

- [ ] **Step 4: No commit yet** — branch creation is itself the checkpoint; T1 is the first commit.

---

### Task 1: Settings extension

**Files:**
- Modify: `src/cognic_agentos/core/config.py:386` (extend Sprint-3 LLM section with Sprint-4 Plugin/Policy section)
- Modify: `.env.example` (operator-facing knobs)
- Test: `tests/unit/test_config.py` (add Sprint-4 settings tests to existing module)

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_config.py — append to existing class TestSettings
class TestSprint4PluginPolicySettings:
    def test_sprint_4_defaults_match_secure_posture(self) -> None:
        s = Settings(runtime_profile="prod")
        # Cosign required by default — fail-closed posture
        assert s.cognic_require_cosign is True
        assert s.cognic_cosign_path is None  # derived via shutil.which at use-time
        assert s.cognic_cosign_verify_timeout_s == 30.0
        # File-backed allow-list defaults
        assert s.cognic_plugin_allowlist_path == Path("policies/_default/plugin_allowlist.json")
        # Rego seed bundle
        assert s.cognic_supply_chain_policy_bundle == Path(
            "policies/_default/supply_chain.rego"
        )
        # OPA defaults
        assert s.cognic_opa_path is None
        assert s.cognic_opa_eval_timeout_s == 5.0

    def test_cosign_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError, match="greater than 0"):
            Settings(runtime_profile="prod", cognic_cosign_verify_timeout_s=0)
        with pytest.raises(ValidationError):
            Settings(runtime_profile="prod", cognic_cosign_verify_timeout_s=-1)

    def test_opa_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError, match="greater than 0"):
            Settings(runtime_profile="prod", cognic_opa_eval_timeout_s=0)

    def test_local_object_store_root_dev_vs_prod(self, monkeypatch, tmp_path) -> None:
        """Dev profile derives root from tmpdir; prod uses /var/lib path."""
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        dev = Settings(runtime_profile="dev")
        prod = Settings(runtime_profile="prod")
        assert tmp_path in dev.cognic_local_object_store_root.parents
        assert prod.cognic_local_object_store_root == Path(
            "/var/lib/cognic-agentos/object-store"
        )
```

- [ ] **Step 2: Run tests → fail**

```bash
uv run pytest tests/unit/test_config.py::TestSprint4PluginPolicySettings -v
```

Expected: AttributeError on `s.cognic_require_cosign` (settings don't exist yet).

- [ ] **Step 3: Implement the settings extension**

```python
# core/config.py — append after the Sprint 3 LLM gateway block

# --- Sprint 4 — Plugin registry + trust gate + policy seed (per ADRs 002, 015, 016) ---
cognic_plugin_allowlist_path: Path = Field(
    default=Path("policies/_default/plugin_allowlist.json"),
    description=(
        "Per-tenant plugin allow-list path. JSON: {tenant_id: [pack_name, ...]}. "
        "File-backed in Sprint 4; Vault swap → Sprint 10."
    ),
)
cognic_require_cosign: bool = Field(
    default=True,
    description=(
        "Master fail-closed flag for the plugin trust gate. Default true: pack "
        "registration refuses if cosign cannot verify the signature. "
        "Setting false in production is a critical-controls violation."
    ),
)
cognic_cosign_path: str | None = Field(
    default=None,
    description=(
        "Override path to the cosign binary. None → shutil.which('cosign') at "
        "first use. Production: pinned in default-adapters Dockerfile target."
    ),
)
cognic_cosign_verify_timeout_s: float = Field(
    default=30.0,
    gt=0.0,
    description=(
        "Per-call cosign-verify timeout in seconds. Strict: SIGKILL on timeout; "
        "timeout itself emits a chained audit event."
    ),
)
cognic_supply_chain_policy_bundle: Path = Field(
    default=Path("policies/_default/supply_chain.rego"),
    description=(
        "Rego bundle path consulted by the Sprint-4 policy engine seed for "
        "supply-chain admission decisions (allow / deny / partial-grade tolerance)."
    ),
)
cognic_opa_path: str | None = Field(
    default=None,
    description=(
        "Override path to the OPA Go binary. None → shutil.which('opa') at "
        "engine construction. Production: pinned in default-adapters Dockerfile target."
    ),
)
cognic_opa_eval_timeout_s: float = Field(
    default=5.0,
    gt=0.0,
    description=(
        "Per-evaluate OPA timeout in seconds. Strict: SIGKILL on timeout; "
        "fail-closed on parse / non-zero exit."
    ),
)
cognic_local_object_store_root: Path = Field(
    default_factory=lambda: _default_object_store_root(),
    description=(
        "Root directory for the LocalObjectStoreAdapter. Dev profile derives "
        "from $TMPDIR; prod default is /var/lib/cognic-agentos/object-store."
    ),
)
cognic_signature_root_path: Path = Field(
    default=Path("attestations"),
    description=(
        "Root prefix under which all pack signature paths must canonicalise. "
        "Path-traversal attempts are refused at the trust-gate boundary."
    ),
)
cognic_trust_root_prefix: Path = Field(
    default=Path("trust-roots"),
    description=(
        "Root prefix under which all per-tenant cosign trust-root paths must "
        "canonicalise. Path-traversal attempts are refused."
    ),
)
```

Plus the helper:

```python
def _default_object_store_root() -> Path:
    """Profile-aware default for cognic_local_object_store_root."""
    import os
    if (tmp := os.environ.get("TMPDIR")) is not None:
        return Path(tmp) / "cognic-agentos-object-store"
    return Path("/var/lib/cognic-agentos/object-store")
```

- [ ] **Step 4: Update `.env.example`**

Append a new section after the Sprint-3 LLM block:

```
# ----- Sprint 4 — Plugin registry + trust gate + policy seed (per ADRs 002 / 015 / 016) -----
# Per-tenant plugin allow-list. File path in Sprint 4; Vault swap → Sprint 10.
# COGNIC_PLUGIN_ALLOWLIST_PATH=policies/_default/plugin_allowlist.json
#
# Trust gate (cosign).
# COGNIC_REQUIRE_COSIGN=true                     # default; setting false in prod is a critical-controls violation
# COGNIC_COSIGN_PATH=                            # leave unset to use shutil.which('cosign'); prod pins via Dockerfile
# COGNIC_COSIGN_VERIFY_TIMEOUT_S=30.0            # SIGKILL on timeout; timeout emits chained audit event
#
# Policy engine seed (per ADR-015 Sprint 4 phase).
# COGNIC_SUPPLY_CHAIN_POLICY_BUNDLE=policies/_default/supply_chain.rego
# COGNIC_OPA_PATH=                               # leave unset to use shutil.which('opa'); prod pins via Dockerfile
# COGNIC_OPA_EVAL_TIMEOUT_S=5.0
#
# LocalObjectStoreAdapter (per Sprint 4 — first real ObjectStoreAdapter impl per ADR-009 + ADR-016).
# Sprint 8 adds the S3 driver alongside; this filesystem path stays the dev/test default.
# COGNIC_LOCAL_OBJECT_STORE_ROOT=                # leave unset to derive from $TMPDIR (dev) or /var/lib/cognic-agentos/object-store (prod)
#
# Path-traversal prevention prefixes (boundary-asserted at trust-gate).
# COGNIC_SIGNATURE_ROOT_PATH=attestations
# COGNIC_TRUST_ROOT_PREFIX=trust-roots
```

- [ ] **Step 5: Run tests → pass**

```bash
uv run pytest tests/unit/test_config.py::TestSprint4PluginPolicySettings -v
```

Expected: 4 passed.

- [ ] **Step 6: Wide sweep + halt-before-commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests && uv run pytest -q
```

All clean. Halt-before-commit summary; await explicit `commit` per AGENTS.md per-action rule.

- [ ] **Step 7: Commit**

```bash
git add src/cognic_agentos/core/config.py tests/unit/test_config.py .env.example
git commit -m "feat(sprint-4): add plugin registry / trust gate / policy seed settings (T1)"
```

---

### Task 2: `core/policy/engine.py` Rego evaluator seed (failing test first)

**Files:**
- Create: `src/cognic_agentos/core/policy/__init__.py`
- Create: `src/cognic_agentos/core/policy/engine.py`
- Test: `tests/unit/core/policy/__init__.py`
- Test: `tests/unit/core/policy/test_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/policy/test_engine.py
"""Sprint 4 T2 — OPAEngine load-from-disk + Decision shape contract.

Tests cover:
- Engine construction loads the bundle, computes its sha256, refuses on
  missing or syntactically-invalid bundle.
- Decision dataclass shape (frozen, slotted, decision_data slot present).
- evaluate() shells out to OPA via secure subprocess (list-form argv,
  shell=False, timeout); parses JSON output; fails closed on non-zero
  exit / parse failure / timeout.
- Audit emissions: policy.bundle_loaded once at construction;
  policy.decision_evaluated per evaluate() call.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from unittest.mock import patch

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.policy.engine import (
    Decision,
    OPAEngine,
    OpaNotInstalledError,
    RegoBundleInvalidError,
    RegoBundleNotFoundError,
)


def _write_valid_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "supply_chain.rego"
    bundle.write_text(
        """\
package cognic.supply_chain

default allow = false

allow if {
    input.attestation_grade == "full"
}
"""
    )
    return bundle


class TestOPAEngineConstruction:
    def test_missing_bundle_fails_closed(self, tmp_path: Path, audit_store: AuditStore) -> None:
        with pytest.raises(RegoBundleNotFoundError, match="bundle not found"):
            OPAEngine(bundle_path=tmp_path / "missing.rego", audit_store=audit_store)

    def test_invalid_bundle_fails_closed(
        self, tmp_path: Path, audit_store: AuditStore
    ) -> None:
        bundle = tmp_path / "bad.rego"
        bundle.write_text("this is not valid rego")
        with pytest.raises(RegoBundleInvalidError, match="syntax"):
            OPAEngine(bundle_path=bundle, audit_store=audit_store)

    async def test_valid_bundle_emits_bundle_loaded(
        self, tmp_path: Path, audit_store: AuditStore, gateway_engine
    ) -> None:
        bundle = _write_valid_bundle(tmp_path)
        engine = OPAEngine(bundle_path=bundle, audit_store=audit_store)
        # Construction emitted policy.bundle_loaded
        async with gateway_engine.connect() as conn:
            from cognic_agentos.core.decision_history import _decision_history
            from sqlalchemy import select
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        assert any(r.event_type == "policy.bundle_loaded" for r in rows)
        assert engine.bundle_sha256.startswith(("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"))


class TestDecisionShape:
    def test_decision_is_frozen_slotted(self) -> None:
        d = Decision(allow=True, rule_matched="allow", reasoning="full grade", decision_data={"attestation_grade": "full"})
        assert dataclasses.is_dataclass(Decision)
        with pytest.raises(dataclasses.FrozenInstanceError):
            d.allow = False  # type: ignore[misc]

    def test_decision_data_can_be_none(self) -> None:
        d = Decision(allow=False, rule_matched=None, reasoning="default deny", decision_data=None)
        assert d.decision_data is None


class TestEvaluate:
    async def test_full_grade_input_allows(
        self, tmp_path: Path, audit_store: AuditStore
    ) -> None:
        bundle = _write_valid_bundle(tmp_path)
        engine = OPAEngine(bundle_path=bundle, audit_store=audit_store)
        decision = await engine.evaluate(
            decision_point="data.cognic.supply_chain.allow",
            input={"attestation_grade": "full"},
        )
        assert decision.allow is True

    async def test_partial_grade_input_denies(
        self, tmp_path: Path, audit_store: AuditStore
    ) -> None:
        bundle = _write_valid_bundle(tmp_path)
        engine = OPAEngine(bundle_path=bundle, audit_store=audit_store)
        decision = await engine.evaluate(
            decision_point="data.cognic.supply_chain.allow",
            input={"attestation_grade": "partial"},
        )
        assert decision.allow is False

    async def test_missing_opa_binary_fails_closed(
        self, tmp_path: Path, audit_store: AuditStore, monkeypatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        bundle = _write_valid_bundle(tmp_path)
        with pytest.raises(OpaNotInstalledError, match="opa not found"):
            engine = OPAEngine(bundle_path=bundle, audit_store=audit_store, opa_path=None)
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )

    async def test_subprocess_argv_is_list_form_no_shell(
        self, tmp_path: Path, audit_store: AuditStore
    ) -> None:
        """Critical: shell=False and argv is list. Regression test
        against accidentally enabling shell=True."""
        bundle = _write_valid_bundle(tmp_path)
        engine = OPAEngine(bundle_path=bundle, audit_store=audit_store)
        captured = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["shell"] = kwargs.get("shell")
            from subprocess import CompletedProcess
            return CompletedProcess(argv, 0, stdout='{"result":[{"expressions":[{"value":true}]}]}', stderr="")

        with patch("subprocess.run", side_effect=_fake_run):
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )
        assert isinstance(captured["argv"], list)
        assert captured["shell"] is False
        assert captured["argv"][0].endswith("opa")
```

- [ ] **Step 2: Run test → fail**

Expected: `ImportError` on `cognic_agentos.core.policy.engine`.

- [ ] **Step 3: Implement the engine**

```python
# src/cognic_agentos/core/policy/__init__.py
"""Sprint 4 minimal Rego evaluator seed (per ADR-015 Sprint-4 phase).

Sprint 13.5 extends this with hot-reload, decision-trail API, and the
remaining default bundles.
"""
from cognic_agentos.core.policy.engine import (
    Decision,
    OPAEngine,
    OpaNotInstalledError,
    RegoBundleInvalidError,
    RegoBundleNotFoundError,
    RegoEvaluationError,
)

__all__ = (
    "Decision",
    "OPAEngine",
    "OpaNotInstalledError",
    "RegoBundleInvalidError",
    "RegoBundleNotFoundError",
    "RegoEvaluationError",
)
```

```python
# src/cognic_agentos/core/policy/engine.py
"""Minimal Rego evaluator seed (Sprint 4, per ADR-015).

Layer: **platform primitive** (critical control per AGENTS.md —
admission-control substrate; ≥95% line / ≥90% branch coverage gate).

Sprint 4 ships the smallest evaluator that can answer
``policies/_default/supply_chain.rego``. Sprint 13.5 extends to
hot-reload + decision-trail + rest of default bundles.

Secure subprocess invariants per Sprint-4 §2 + §5 (locked):
- list-form argv only; shell=False
- explicit minimal env (no os.environ passthrough)
- strict timeout (default 5s); SIGKILL on timeout; fail-closed on
  non-zero exit / JSON parse failure
- bundle path must canonicalise under operator-approved prefix
- decision-point query strings are compile-time constants only
"""

from __future__ import annotations

import dataclasses as _dataclasses
import datetime as _dt
import hashlib
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

_LOG = logging.getLogger("cognic_agentos.core.policy.engine")


class OpaNotInstalledError(RuntimeError):
    """Raised when the OPA Go binary cannot be located."""


class RegoBundleNotFoundError(FileNotFoundError):
    """Raised when the configured bundle path does not exist."""


class RegoBundleInvalidError(ValueError):
    """Raised when the bundle fails OPA syntax validation at construction."""


class RegoEvaluationError(RuntimeError):
    """Raised when OPA returns non-zero exit, malformed JSON, or times out."""


@_dataclasses.dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of one ``OPAEngine.evaluate()`` call.

    Per Sprint-4 §5/§8 (Q8 lock): ``decision_data`` carries Sprint-
    specific structured outcomes (e.g. ``{"attestation_grade": "full"}``).
    Downstream callers consume ``decision_data`` for rich outcomes
    rather than overloading ``rule_matched`` / ``reasoning``.
    """

    allow: bool
    rule_matched: str | None
    reasoning: str
    decision_data: dict[str, Any] | None


# ... (full implementation continues — load-from-disk constructor with
# bundle_sha256 fingerprint + OPA syntax check + policy.bundle_loaded
# decision_history emission; evaluate() with secure-subprocess shape
# + policy.decision_evaluated emission per call.)
```

The full implementation of `OPAEngine.__init__`, `_validate_bundle_syntax`, `_compute_bundle_sha256`, `evaluate`, `_emit_bundle_loaded`, `_emit_decision_evaluated`, `_run_opa`, `_parse_decision`, and the `_resolve_opa_path` helper continues — each method is < 30 lines, all together fit in one ~250-line module. Implementation guidance below; engineer reads §5 + §7 of this plan + the failing tests above to construct the methods.

Key implementation notes:
- Constructor signature: `OPAEngine(*, bundle_path: Path, audit_store: AuditStore, decision_history_store: DecisionHistoryStore, opa_path: str | None = None, eval_timeout_s: float = 5.0)`.
- `_validate_bundle_syntax`: `subprocess.run([opa_bin, "fmt", "--diff", str(bundle_path)], shell=False, capture_output=True, text=True, env={"PATH": "/usr/local/bin:/usr/bin"}, timeout=30.0)`. Non-zero exit → `RegoBundleInvalidError(stderr)`.
- `_compute_bundle_sha256`: `hashlib.sha256(bundle_path.read_bytes()).hexdigest()`.
- `_emit_bundle_loaded` (sync after loading): writes a `decision_history` row via `DecisionHistoryStore.append()` with `event_type="policy.bundle_loaded"`, payload `{bundle_path, bundle_sha256, loaded_at}`.
- `evaluate`: runs `opa eval --data <bundle> --input <stdin> --format json "<query>"` with input piped via stdin; parses JSON; emits `policy.decision_evaluated` with `input_fingerprint=sha256(canonical_bytes(input)).hexdigest()`.

- [ ] **Step 4: Run tests → pass**

```bash
uv run pytest tests/unit/core/policy/ -v
```

Expected: all pass.

- [ ] **Step 5: Wide sweep + halt-before-commit**

This is critical-controls work (Q7 — first `decision_history` emissions in the project). Halt-before-commit MUST happen.

- [ ] **Step 6: Commit**

```bash
git add src/cognic_agentos/core/policy/ tests/unit/core/policy/
git commit -m "feat(sprint-4): policy engine seed with Rego evaluator (T2)"
```

---

### Task 3: `policies/_default/supply_chain.rego` + `plugin_allowlist.json`

**Files:**
- Create: `policies/_default/supply_chain.rego`
- Create: `policies/_default/plugin_allowlist.json`
- Test: extends `tests/unit/core/policy/test_engine.py`

- [ ] **Step 1: Write the failing tests**

```python
# Append to tests/unit/core/policy/test_engine.py
class TestDefaultSupplyChainBundle:
    """Round-trip the actual policies/_default/supply_chain.rego bundle."""

    async def test_full_grade_pack_allowed_by_default(
        self, audit_store: AuditStore
    ) -> None:
        engine = OPAEngine(
            bundle_path=Path("policies/_default/supply_chain.rego"),
            audit_store=audit_store,
        )
        decision = await engine.evaluate(
            decision_point="data.cognic.supply_chain.allow",
            input={
                "attestation_grade": "full",
                "tenant_policy": {},
            },
        )
        assert decision.allow is True

    async def test_partial_grade_pack_allowed_when_tenant_permits(
        self, audit_store: AuditStore
    ) -> None:
        engine = OPAEngine(
            bundle_path=Path("policies/_default/supply_chain.rego"),
            audit_store=audit_store,
        )
        decision = await engine.evaluate(
            decision_point="data.cognic.supply_chain.allow",
            input={
                "attestation_grade": "partial",
                "tenant_policy": {"require_full": False},
            },
        )
        assert decision.allow is True

    async def test_partial_grade_pack_denied_when_tenant_requires_full(
        self, audit_store: AuditStore
    ) -> None:
        engine = OPAEngine(
            bundle_path=Path("policies/_default/supply_chain.rego"),
            audit_store=audit_store,
        )
        decision = await engine.evaluate(
            decision_point="data.cognic.supply_chain.allow",
            input={
                "attestation_grade": "partial",
                "tenant_policy": {"require_full": True},
            },
        )
        assert decision.allow is False
```

- [ ] **Step 2: Run tests → fail**

Expected: `RegoBundleNotFoundError` (file doesn't exist yet).

- [ ] **Step 3: Implement the bundle**

```rego
# policies/_default/supply_chain.rego
package cognic.supply_chain

# Default-deny posture per ADR-007 / ADR-016 fail-closed conventions.
default allow = false

# Full-grade packs always allowed (mandatory floor cleared + grace-period
# gates also cleared).
allow if {
    input.attestation_grade == "full"
}

# Partial-grade packs allowed UNLESS the tenant policy requires full grade.
# Per ADR-016 §"Implementation phases" Wave 1 grace period.
allow if {
    input.attestation_grade == "partial"
    not input.tenant_policy.require_full
}

# Reasoning surfaces in Decision.reasoning so operator UIs can show
# WHY a pack was admitted or refused.
reasoning := "full attestation grade; mandatory floor + grace-period gates cleared" if {
    input.attestation_grade == "full"
}

reasoning := "partial attestation grade allowed under Wave-1 default tenant policy" if {
    input.attestation_grade == "partial"
    not input.tenant_policy.require_full
}

reasoning := "partial attestation grade refused: tenant requires full grade" if {
    input.attestation_grade == "partial"
    input.tenant_policy.require_full
}
```

- [ ] **Step 4: Implement the allow-list**

```json
{
    "_default": [
        "cognic_test_pack"
    ]
}
```

(Production deployments overwrite this file or swap to Vault per Sprint 10.)

- [ ] **Step 5: Run tests → pass**

```bash
uv run pytest tests/unit/core/policy/test_engine.py::TestDefaultSupplyChainBundle -v
```

- [ ] **Step 6: Halt-before-commit + commit**

```bash
git add policies/_default/
git commit -m "feat(sprint-4): default supply-chain Rego bundle + tenant allow-list (T3)"
```

---

### Task 4: `LocalObjectStoreAdapter` — production filesystem ObjectStoreAdapter

**Production-grade scope:** This is the FIRST real `ObjectStoreAdapter` implementation. Per AGENTS.md "Production-grade implementation rule" the adapter ships as production code on the main runtime path — not a mock, not a test stub, not a placeholder for Sprint 8. Filesystem-backed deployments (single-host AgentOS, NFS/EFS-mounted clusters, on-prem shared mounts) run this driver in production indefinitely. Sprint 8 adds S3 as an *alternative* driver choice; both drivers conform to the same `ObjectStoreAdapter` Protocol and are selected via `cognic_object_store_driver`.

**Files:**
- Create: `src/cognic_agentos/db/adapters/local_object_store_adapter.py`
- Modify: `src/cognic_agentos/db/adapters/registry.py` (register `local_fs` driver)
- Modify: `src/cognic_agentos/db/adapters/factory.py` (default driver = `local_fs` when none configured)
- Test: `tests/unit/db/adapters/test_local_object_store_adapter.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/db/adapters/test_local_object_store_adapter.py
"""Sprint 4 T4 — LocalObjectStoreAdapter contract.

Per Sprint-4 §4: filesystem-backed ObjectStoreAdapter, atomic writes,
path-traversal safe, retention metadata enforced. This is the FIRST
real ObjectStoreAdapter implementation; Sprint 8 adds the S3 driver
alongside without changing the Protocol.
"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path

import pytest

from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
    PathTraversalError,
    RetentionWindowActiveError,
)
from cognic_agentos.db.adapters.protocols import AdapterHealth


class TestLocalObjectStoreAdapterRoundTrip:
    async def test_put_then_get_round_trips_arbitrary_bytes(
        self, tmp_path: Path
    ) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        body = bytes(range(256))  # all byte values
        await adapter.put("test", "key1", body)
        assert await adapter.get("test", "key1") == body

    async def test_put_then_get_round_trips_large_payload(
        self, tmp_path: Path
    ) -> None:
        """Sigstore bundles are typically 5-10 MB. Adapter must round-trip."""
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        body = os.urandom(10 * 1024 * 1024)  # 10 MiB
        await adapter.put("attestations", "pkg/v1/bundle.sigstore", body)
        assert await adapter.get("attestations", "pkg/v1/bundle.sigstore") == body


class TestLocalObjectStoreAdapterAtomicity:
    async def test_concurrent_writes_resolve_last_writer_wins(
        self, tmp_path: Path
    ) -> None:
        """Atomic rename means the file at the key is always either
        a complete previous body or a complete new body — never partial."""
        import asyncio
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await asyncio.gather(
            adapter.put("test", "k", b"a" * 1024),
            adapter.put("test", "k", b"b" * 1024),
            adapter.put("test", "k", b"c" * 1024),
        )
        body = await adapter.get("test", "k")
        # One of them won — body is one homogeneous block of 1024 bytes
        assert len(body) == 1024
        assert body in (b"a" * 1024, b"b" * 1024, b"c" * 1024)

    async def test_no_partial_files_visible(self, tmp_path: Path) -> None:
        """The .tmp staging directory is excluded from listings; only
        complete writes appear under <bucket>/<key>."""
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("test", "k", b"complete")
        # No .tmp file leaked into the visible namespace
        bucket_dir = tmp_path / "test"
        leaked = list(bucket_dir.glob("*.tmp"))
        assert leaked == [], f"partial files leaked: {leaked}"


class TestLocalObjectStoreAdapterPathSafety:
    async def test_traversal_in_key_rejected(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        for bad_key in ("../escape", "/etc/passwd", "valid/../escape", "..", "\x00null"):
            with pytest.raises(PathTraversalError):
                await adapter.put("test", bad_key, b"x")

    async def test_traversal_in_bucket_rejected(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        for bad_bucket in ("../escape", "/etc", ".", "..", "test/sub"):
            with pytest.raises(PathTraversalError):
                await adapter.put(bad_bucket, "k", b"x")

    async def test_symlink_target_outside_root_rejected(
        self, tmp_path: Path
    ) -> None:
        """Even if a symlink is planted under root pointing outside,
        canonicalisation rejects."""
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        bucket_dir = tmp_path / "test"
        bucket_dir.mkdir(parents=True)
        outside = tmp_path.parent / "outside_target.txt"
        outside.write_text("steal me")
        try:
            (bucket_dir / "evil").symlink_to(outside)
            with pytest.raises(PathTraversalError):
                await adapter.get("test", "evil")
        finally:
            outside.unlink(missing_ok=True)


class TestLocalObjectStoreAdapterRetention:
    async def test_delete_within_retention_window_refused(
        self, tmp_path: Path
    ) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put(
            "test", "k", b"keep-me", retention_seconds=3600  # 1 hour
        )
        with pytest.raises(RetentionWindowActiveError):
            await adapter.delete("test", "k")

    async def test_delete_after_retention_window_allowed(
        self, tmp_path: Path
    ) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        # Past-dated retention: write the sidecar manually with retain_until
        # in the past
        await adapter.put("test", "k", b"old", retention_seconds=1)
        # Manually edit sidecar to place retain_until in the past
        sidecar = tmp_path / "test" / "k.retention"
        import json as _json
        meta = _json.loads(sidecar.read_text())
        meta["retain_until"] = "2020-01-01T00:00:00+00:00"
        sidecar.write_text(_json.dumps(meta))
        await adapter.delete("test", "k")  # MUST succeed
        assert not (tmp_path / "test" / "k").exists()

    async def test_no_retention_means_immediate_delete_ok(
        self, tmp_path: Path
    ) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("test", "k", b"transient")
        await adapter.delete("test", "k")
        assert not (tmp_path / "test" / "k").exists()

    async def test_seven_year_retention_records_correct_metadata(
        self, tmp_path: Path
    ) -> None:
        """ADR-016 minimum 7-year retention for Sigstore bundles.
        Sprint 4 enforces this at the adapter via retention_seconds."""
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put(
            "attestations",
            "pkg/v1/bundle.sigstore",
            b"bundle",
            retention_seconds=7 * 365 * 24 * 3600,  # 7 years
        )
        sidecar = tmp_path / "attestations" / "pkg/v1/bundle.sigstore.retention"
        import json as _json
        meta = _json.loads(sidecar.read_text())
        assert meta["retention_seconds"] == 7 * 365 * 24 * 3600
        retain_until = _dt.datetime.fromisoformat(meta["retain_until"])
        created_at = _dt.datetime.fromisoformat(meta["created_at"])
        assert (retain_until - created_at).total_seconds() == 7 * 365 * 24 * 3600


class TestLocalObjectStoreAdapterPresign:
    async def test_presign_raises_not_implemented(self, tmp_path: Path) -> None:
        """P2-B reviewer-fix: presign() on the local driver MUST fail
        loudly. A degenerate file:// URL would silently mislead
        callers (e.g. Sprint 7B reviewer dashboard) expecting external-
        HTTP-accessible URLs. Cross-host attestation-bundle access
        requires a non-local ObjectStoreAdapter driver."""
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("test", "k", b"x")
        with pytest.raises(
            NotImplementedError,
            match="presign requires non-local ObjectStoreAdapter driver",
        ):
            await adapter.presign("test", "k", ttl_s=60)


class TestLocalObjectStoreAdapterHealth:
    async def test_health_reports_ok_when_writable(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        h = await adapter.health_check()
        assert h.status == "ok"
        assert h.driver == "local_fs"

    async def test_health_reports_unreachable_when_root_missing(
        self, tmp_path: Path
    ) -> None:
        bad_root = tmp_path / "nonexistent"
        adapter = LocalObjectStoreAdapter(root=bad_root)
        h = await adapter.health_check()
        assert h.status == "unreachable"
```

- [ ] **Step 2: Run tests → fail**

Expected: `ImportError` on `cognic_agentos.db.adapters.local_object_store_adapter`.

- [ ] **Step 3: Implement the adapter**

Full implementation guidance:
- Module docstring describing the contract per Sprint-4 §4.
- Constructor: `__init__(self, *, root: Path) -> None`. Stores resolved root via `root.resolve()`.
- `put(bucket, key, body, *, retention_seconds=None)`: validates bucket+key via regex; computes target = `root / bucket / key`; canonicalises `target.parent.resolve()` and asserts `is_relative_to(self._root)`; creates `<root>/<bucket>/.tmp/` if missing; writes body to `<tmp_dir>/<uuid4>.tmp`; `os.fsync(fd)`; `os.rename(tmp, target)`. If `retention_seconds` is set, writes `<target>.retention` sidecar with `{created_at, retain_until, retention_seconds}` (ISO8601 + UTC).
- `get(bucket, key)`: validates; reads bytes; canonicalisation check on resolved target rejects symlinks pointing outside root.
- `delete(bucket, key)`: validates; checks sidecar; if `retain_until > now()` raises `RetentionWindowActiveError`; else removes file + sidecar.
- `presign(bucket, key, ttl_s)`: raises `NotImplementedError("presign requires non-local ObjectStoreAdapter driver — local_fs deployments do not support signed-URL semantics")`. P2-B fail-loud per §4 item 5 — never returns a degenerate `file://` URL that would mislead callers expecting external-HTTP access.
- `health_check()`: writes a temp probe file under `root / .health_probe`, deletes it, measures latency. On any IOError → `unreachable`.
- Validation regex: `_VALID_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]*$")`; bucket = single segment; key may contain `/` separators between segments.

- [ ] **Step 4: Wire up registry + factory**

`db/adapters/registry.py`: register `("object_store", "local_fs"): LocalObjectStoreAdapter`.

`db/adapters/factory.py`: `build_adapters` constructs `LocalObjectStoreAdapter(root=settings.cognic_local_object_store_root)` when `settings.cognic_object_store_driver == "local_fs"` (new default).

- [ ] **Step 5: Run tests → pass**

```bash
uv run pytest tests/unit/db/adapters/test_local_object_store_adapter.py -v
```

Expected: all pass.

- [ ] **Step 6: Halt-before-commit + commit**

```bash
git add src/cognic_agentos/db/adapters/local_object_store_adapter.py \
        src/cognic_agentos/db/adapters/registry.py \
        src/cognic_agentos/db/adapters/factory.py \
        tests/unit/db/adapters/test_local_object_store_adapter.py
git commit -m "feat(sprint-4): production filesystem ObjectStoreAdapter (T4)"
```

---

### Task 5: `protocol/plugin_registry.py` discovery + register API

**Files:**
- Create: `src/cognic_agentos/protocol/__init__.py`
- Create: `src/cognic_agentos/protocol/plugin_registry.py`
- Test: `tests/unit/protocol/__init__.py`
- Test: `tests/unit/protocol/test_plugin_registry.py`

- [ ] **Step 1: Write the failing test**

Tests cover: `discover()` walks all three entry-point groups; deferred `load()` (no eager import at discover time); `register(record, attestation_grade)` records the pack and emits `audit_event(plugin.registration_succeeded)`; `register` with a `refusal_reason` records the refused state and emits `audit_event(plugin.registration_refused)`; `known_packs()` returns flat list; `load(kind, name)` raises `RegistrationRefused` when the pack was refused; concurrent register calls serialise via the chain-head primitive.

**P2-K reviewer-fix — explicit no-eager-`EntryPoint.load()` test** pinning the §1 dynamic invariant. The existing `tests/unit/architecture/test_no_pack_imports.py` covers static-import-tree discipline (no `cognic_*` pack-namespace imports in the source tree); this new test pins the dynamic invariant that `discover()` itself doesn't trigger `EntryPoint.load()`. Without this test, a regression that adds `entry_point.load()` inside `discover()` would silently re-introduce eager pack import at startup — the supply-chain attack surface ADR-002 §"MCP STDIO threat model" warns against. Test shape:

```python
# tests/unit/protocol/test_plugin_registry.py — new test in TestDiscovery class
def test_discover_does_not_eager_import_pack_modules(
    monkeypatch, tmp_path
) -> None:
    """P2-K reviewer-fix — pin the §1 deferred-load invariant.

    A pack's __init__.py executing during discover() would defeat the
    trust gate's pre-import verification. This test installs a
    fixture pack whose __init__.py sets a sentinel module-level flag
    and asserts the flag stays False after discover() returns. The
    flag only flips when register() → load() is called explicitly.
    """
    # Arrange: install a fixture pack with a sentinel-flipping __init__.py
    # via a tmp-path entry-point shim.
    import importlib.metadata

    sentinel = {"imported": False}

    class _FakeEntryPoint:
        name = "test_tool"
        group = "cognic.tools"
        value = "fake_pack:Tool"

        def load(self):
            sentinel["imported"] = True
            class Tool: ...
            return Tool

    def _fake_entry_points(*, group: str):
        if group == "cognic.tools":
            return [_FakeEntryPoint()]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", _fake_entry_points)

    registry = PluginRegistry()

    # Act: discover() must walk metadata only.
    discovered = registry.discover()

    # Assert: the sentinel did NOT flip — load() was not called.
    assert len(discovered) == 1
    assert sentinel["imported"] is False, (
        "discover() eager-imported a pack — §1 deferred-load invariant "
        "violated. The trust gate's pre-import verification depends on "
        "discover() walking metadata only."
    )

    # Sanity: explicit load DOES flip the sentinel.
    registry.load("tools", "test_tool")
    assert sentinel["imported"] is True
```

- [ ] **Step 2-7:** TDD: red → implement → green → halt → commit. Single commit:

```bash
git commit -m "feat(sprint-4): plugin registry with deferred-load discovery (T5)"
```

---

### Task 6: `protocol/trust_gate.py` cosign verification + secure-subprocess invariants

**Files:**
- Create: `src/cognic_agentos/protocol/trust_gate.py`
- Test: `tests/unit/protocol/test_trust_gate.py`

The most security-critical task in Sprint 4. Per §2 of this plan.

- [ ] **Step 1: Write the failing tests** — full negative-path coverage

```python
# Excerpts; full test file covers ~25 negative-path tests + 3 positive-path tests

class TestTrustGateInputValidation:
    def test_pack_id_with_shell_metacharacter_rejected(self) -> None:
        for bad in (
            "pack;ls", "pack|cat", "pack`whoami`", "pack$(id)",
            "pack&", "pack\nrm -rf", "pack\\test", "pack'", 'pack"',
            "pack*", "pack?", "pack<", "pack>",
        ):
            with pytest.raises(ValueError, match="invalid pack_id"):
                _validate_pack_id(bad)

    def test_pack_id_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            _validate_pack_id("a" * 129)

    def test_version_with_invalid_chars_rejected(self) -> None:
        for bad in ("v1; ls", "1.0\nrm", "1.0$(whoami)", "1.0`id`", "1.0|cat"):
            with pytest.raises(ValueError, match="invalid version"):
                _validate_version(bad)

    def test_signature_path_traversal_rejected(self, tmp_path: Path) -> None:
        adapter_root = tmp_path / "attestations"
        adapter_root.mkdir()
        for bad_path in (
            "../etc/passwd",
            "/etc/passwd",
            f"{adapter_root}/../escape",
            "valid/../../escape",
        ):
            with pytest.raises(PathTraversalError):
                _canonicalise_under_root(Path(bad_path), adapter_root)


class TestTrustGateSubprocessShape:
    def test_argv_is_list_form_no_shell(self, ...): ...
    def test_env_is_minimal_no_environ_passthrough(self, ...): ...
    def test_strict_timeout_kills_process(self, ...): ...
    def test_timeout_emits_audit_event(self, ...): ...
    def test_json_output_parsed_strict(self, ...): ...
    def test_non_zero_exit_fails_closed(self, ...): ...
    def test_malformed_json_fails_closed(self, ...): ...


class TestTrustGateHappyPath:
    def test_valid_signature_returns_verification_result(
        self, cosign_shim
    ) -> None:
        result = verify_pack_signature(
            pack_id="cognic_test_pack",
            version="0.1.0",
            signature_path=Path("attestations/cognic_test_pack/0.1.0/cosign.sig"),
            trust_root=Path("trust-roots/_default/trust-root.pem"),
            settings=test_settings,
        )
        assert result.verified is True
        assert result.signature_digest is not None
```

- [ ] **Step 2-7:** Standard TDD shape; halt-before-commit per AGENTS.md (this is critical-controls work). Single commit:

```bash
git commit -m "feat(sprint-4): cosign trust gate with secure-subprocess invariants (T6)"
```

---

### Task 7: `protocol/supply_chain.py` attestation pipeline

**Files:**
- Create: `src/cognic_agentos/protocol/supply_chain.py`
- Test: `tests/unit/protocol/test_supply_chain.py`

Implements the §3 mandatory-floor / grace-period decision tree. Verifiers per attestation type:

- `_verify_sbom(sbom_path, signature_digest) -> bool` — parses CycloneDX or SPDX 2.3+; verifies SBOM file SHA-256 matches a digest signed by the pack's cosign signature.
- `_verify_slsa(provenance_path) -> SLSAResult` — parses the in-toto-style SLSA provenance; checks `buildType`, `builder.id`, `invocation.configSource`; returns level (1-3+) + tampered flag. Tampered → hard refusal regardless of grade.
- `_verify_intoto(layout_path, links_dir) -> bool` — verifies in-toto layout signatures + step adjacency.
- `_verify_vulnerability_scan(vuln_path, tenant_thresholds) -> VulnResult` — consumes Trivy/Grype JSON; per-tenant Rego policy delegated.
- `_verify_license_audit(license_path, tenant_allowlist) -> LicenseResult` — consumes syft license JSON; per-tenant allow-list match.

Returns `AttestationResult(grade: Literal["full", "partial"], verified: dict[str, bool], findings: list[str])`. Mandatory-floor failures (cosign / SBOM / Sigstore-bundle-persisted) ARE NOT in this module — they belong to T6 + T9 — but the decision logic for combining (cosign + SBOM cleared elsewhere) with the four grace-period gates lives here.

- [ ] Standard TDD; halt-before-commit; commit:

```bash
git commit -m "feat(sprint-4): supply-chain attestation pipeline per ADR-016 (T7)"
```

---

### Task 8: `protocol/reproducibility.py` manifest digest verifier

**Files:**
- Create: `src/cognic_agentos/protocol/reproducibility.py`
- Test: `tests/unit/protocol/test_reproducibility.py`

Per ADR-016 §"Reproducibility commitment": Sprint 4 verifies the manifest's digest is signed but does NOT re-build the pack. Rebuild is Sprint 7B.

API: `verify_reproducibility_manifest(manifest_path: Path, signature_path: Path, trust_root: Path) -> ReproducibilityResult`. Result includes `signed: bool`, `manifest_digest: str`, `signature_digest: str`. If `signed` is False, the pack registers without `reproducible: true` flag (informational, not refusal).

Tests pin: signed manifest passes; unsigned manifest returns `signed=False` (NOT a refusal); tampered manifest (digest mismatch) raises hard error.

- [ ] Standard TDD; commit:

```bash
git commit -m "feat(sprint-4): reproducibility manifest digest verifier (T8)"
```

---

### Task 9: Sigstore bundle persister wired through `LocalObjectStoreAdapter`

**Files:**
- Extends: `src/cognic_agentos/protocol/supply_chain.py` with `persist_sigstore_bundle(...)` helper
- Test: `tests/unit/protocol/test_sigstore_persistence.py`

Atomic write via the T4 adapter:

```python
async def persist_sigstore_bundle(
    *,
    pack_id: str,
    version: str,
    bundle_bytes: bytes,
    object_store: ObjectStoreAdapter,
) -> None:
    """Persist Sigstore bundle for 7-year offline re-verification.

    Per ADR-016 §"Retention + offline re-verification" + Sprint-4 §4
    LocalObjectStoreAdapter contract: retention is 7 years (≥ longest
    expected regulator window).
    """
    _validate_pack_id(pack_id)
    _validate_version(version)
    key = f"attestations/{pack_id}/{version}/bundle.sigstore"
    await object_store.put(
        bucket="cognic-attestations",
        key=key,
        body=bundle_bytes,
        retention_seconds=7 * 365 * 24 * 3600,  # 7 years
    )
```

Tests:
- Round-trip: persist → read back → exact bytes.
- Retention metadata sidecar contains `retain_until` 7 years out.
- Pack-id with shell metacharacter rejected before adapter is touched.
- Concurrent persists for same (pack_id, version) resolve last-writer-wins.

- [ ] Standard TDD; commit:

```bash
git commit -m "feat(sprint-4): Sigstore bundle persister with 7y retention (T9)"
```

---

### Task 10: Registry assembly — discover → trust → supply-chain → policy → register

**Files:**
- Extends: `src/cognic_agentos/protocol/plugin_registry.py` with `register_with_full_attestation_check(entry_point, *, trust_gate, supply_chain, policy_engine, object_store, audit_store)`
- Test: `tests/unit/protocol/test_registry_integration.py`

The integration step. Ties T5 + T6 + T7 + T9 + T2 together:

```python
async def register_with_full_attestation_check(
    self,
    entry_point: EntryPoint,
    *,
    trust_gate,
    supply_chain,
    policy_engine,
    object_store,
    audit_store,
    tenant_id: str = "_default",
) -> RegistrationOutcome:
    """One end-to-end pack registration.

    Order:
    1. Resolve attestation directory from entry-point metadata.
    2. Cosign verify (T6) — refusal-grade gate; missing signature → refused.
    3. SBOM verify (T7 helper) — refusal-grade gate; missing SBOM → refused.
    4. Persist Sigstore bundle (T9) — refusal-grade gate; failure → refused.
    5. Run remaining grace-period verifiers (SLSA / in-toto / vuln /
       license, T7) — produces grade=full|partial.
    6. Run policy engine on (grade, tenant_policy) — final allow/deny (T2).
    7. Update registry record with attestation_grade + refusal_reason.
    8. Emit audit_event(plugin.registration_succeeded |
       plugin.registration_refused).
    9. Return RegistrationOutcome.
    """
```

This is the load-bearing integration test surface. T10 alone has ~12 tests covering each refusal class:
- cosign-missing → refused at step 2
- SBOM-missing → refused at step 3
- bundle-persist-fails → refused at step 4
- SLSA-tampered → refused at step 5 (tampered ≠ grace)
- license-disallowed-with-require-full → refused at step 6
- everything-passes-full-grade → registered, grade=full
- everything-passes-but-SLSA-L2 → registered, grade=partial (default tenant)
- same-as-above-with-tenant-require-full → refused at step 6

**P3-J — BUILD_PLAN exit criterion startup log.** BUILD_PLAN Sprint 4 exit criterion: "AgentOS startup logs `Discovered N packs (M registered, K rejected)` plus per-pack attestation outcomes." T10 owns this — at the end of the lifespan-startup pack-registration loop, the registry emits a single `INFO`-level structured log line summarising the registration outcomes:

```python
# Excerpt from app.py lifespan integration in T10
discovered = registry.discover()
registered, refused = 0, 0
for entry_point in discovered:
    outcome = await registry.register_with_full_attestation_check(entry_point, ...)
    if outcome.status == "registered":
        registered += 1
    else:
        refused += 1
        # Per-pack refusal already audit-logged at the audit_event level;
        # this is the operator-visible startup log line.
        logger.warning(
            "pack registration refused",
            extra={"pack_id": outcome.pack_id, "reason": outcome.refusal_reason},
        )

logger.info(
    "plugin discovery complete",
    extra={
        "discovered": len(discovered),
        "registered": registered,
        "refused": refused,
        "by_grade": {"full": ..., "partial": ...},
    },
)
```

The startup log is a regression-testable contract — T10's integration test asserts the exact `extra` shape so portal operators can scrape it deterministically.

- [ ] Standard TDD; halt-before-commit (critical-controls); commit:

```bash
git commit -m "feat(sprint-4): registry integration — full pack admission pipeline (T10)"
```

---

### Task 11: `GET /api/v1/system/plugins` endpoint

**Files:**
- Modify: `src/cognic_agentos/portal/api/system_routes.py` (add the endpoint + `_plugin_record_dict` helper)
- Modify: `src/cognic_agentos/portal/api/app.py` (extend `create_app` with `plugin_registry` kwarg + lifespan attach)
- Test: `tests/unit/portal/api/test_plugins_endpoint.py`

Mirrors the Sprint-3 `gateway_ledger` injection pattern. Response shape:

```json
{
    "plugins": [
        {
            "kind": "tools",
            "name": "search_circulars",
            "version": "0.1.0",
            "status": "registered",
            "attestation_grade": "full",
            "signature_digest": "sha256:...",
            "registered_at": "2026-05-01T...",
            "refusal_reason": null
        },
        {
            "kind": "tools",
            "name": "kyc_lookup",
            "version": "0.2.0",
            "status": "refused_at_registration",
            "attestation_grade": null,
            "signature_digest": null,
            "registered_at": null,
            "refusal_reason": "cosign verification failed"
        }
    ],
    "summary": {
        "total_discovered": 2,
        "registered": 1,
        "refused_at_registration": 1,
        "by_grade": {"full": 1, "partial": 0}
    }
}
```

Tests pin: empty registry → 200 with empty list; mixed registered/refused → counts correct; status field uses operator-vocabulary (`registered` / `refused_at_registration`, not internal lifecycle states); response shape is stable.

- [ ] Standard TDD; commit:

```bash
git commit -m "feat(sprint-4): /api/v1/system/plugins endpoint (T11)"
```

---

### Task 12: `tests/fixtures/cognic_test_pack/` — installable test pack with full attestations

**Files:**
- Create: `tests/fixtures/__init__.py`
- Create: `tests/fixtures/cognic_test_pack/pyproject.toml`
- Create: `tests/fixtures/cognic_test_pack/cognic_test_pack/__init__.py`
- Create: `tests/fixtures/cognic_test_pack/cognic_test_pack/tool.py`
- Create: `tests/fixtures/cognic_test_pack/attestations/cosign.sig`
- Create: `tests/fixtures/cognic_test_pack/attestations/sbom.cdx.json`
- Create: `tests/fixtures/cognic_test_pack/attestations/slsa-provenance.intoto.jsonl`
- Create: `tests/fixtures/cognic_test_pack/attestations/intoto-layout.json`
- Create: `tests/fixtures/cognic_test_pack/attestations/vuln-scan.json` (no findings)
- Create: `tests/fixtures/cognic_test_pack/attestations/license-audit.json` (allow-listed only)
- Create: `tests/fixtures/cognic_test_pack/attestations/bundle.sigstore`
- Create: `tests/fixtures/_signing_kit/build_test_attestations.sh` (idempotent regeneration script)

Test pack is installable via `uv pip install -e tests/fixtures/cognic_test_pack/`.

The cosign signature blob is **ephemerally generated at test fixture setup** by the build script when run with `--regenerate` (CI runs without regeneration; local dev regenerates as needed). For unit tests that don't need a real signature, the cosign subprocess is shimmed (Q4 lock) to return canned JSON.

For the env-gated `@pytest.mark.cosign_real` integration path: requires cosign binary + Sigstore.dev access; runs against the actually-signed pack with a real cosign verify call.

- [ ] Standard implementation; commit:

```bash
git commit -m "test(sprint-4): cognic_test_pack fixture with full attestation set (T12)"
```

---

### Task 13: Dockerfile updates — pin cosign + OPA in default-adapters image

**Files:**
- Modify: `infra/agentos/Dockerfile` (default-adapters target)
- Modify: `.github/workflows/python.yml` (image-budget regression check still passes)

Adds to the `default-adapters` Dockerfile stage:

```dockerfile
# Sprint 4: cosign + OPA Go binary for the trust gate + policy engine.
# Kernel image deliberately does NOT carry these — registration runs in
# the default-adapters runtime profile.
ARG COSIGN_VERSION=2.4.0
ARG COSIGN_SHA256=...  # pinned at PR-author time
ARG OPA_VERSION=0.68.0
ARG OPA_SHA256=...     # pinned at PR-author time

RUN curl -sSL -o /tmp/cosign \
    https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64 \
 && echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c - \
 && install -m 0755 /tmp/cosign /usr/local/bin/cosign \
 && rm /tmp/cosign

RUN curl -sSL -o /tmp/opa \
    https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static \
 && echo "${OPA_SHA256}  /tmp/opa" | sha256sum -c - \
 && install -m 0755 /tmp/opa /usr/local/bin/opa \
 && rm /tmp/opa
```

Image-budget verification:
- Kernel target stays unchanged at ~101 MiB / 120 MiB budget.
- Default-adapters target grows from ~177 MiB → ~190 MiB (cosign 80 MiB + OPA 50 MiB binaries; some overlap with existing layers); well under 220 MiB budget.

- [ ] Verify the build locally; commit:

```bash
git commit -m "chore(sprint-4): pin cosign + OPA in default-adapters image (T13)"
```

---

### Task 14: `docs/HOW-TO-WRITE-A-PACK.md` — attestation requirements section

**Files:**
- Create: `docs/HOW-TO-WRITE-A-PACK.md`

Contents:
- Pack manifest structure (mirror ADR-002 manifest shape)
- AGNTCY/OASF identity fields (mandatory vs optional in Wave 1)
- Sprint 4 attestation requirements (mandatory floor + grace-period; pointer to ADR-016 for the full rationale)
- `agentos sign --bundle` reference (Sprint 7A SDK extension)
- Local verification recipe (`agentos verify <pack-path>` — Sprint 7A)
- Where to look in the AgentOS source (`src/cognic_agentos/protocol/`) for the verification path

- [ ] Author + commit:

```bash
git commit -m "docs(sprint-4): pack-author attestation requirements (T14)"
```

---

### Task 15: Critical-controls coverage gate extension

**Files:**
- Modify: `tools/check_critical_coverage.py`

Add the Sprint 4 quartet:

```python
("src/cognic_agentos/protocol/plugin_registry.py", 0.95, 0.90),
("src/cognic_agentos/protocol/trust_gate.py", 0.95, 0.90),
("src/cognic_agentos/protocol/supply_chain.py", 0.95, 0.90),
("src/cognic_agentos/core/policy/engine.py", 0.95, 0.90),
```

Updated docstring footer pins Sprint 4 in the gate scope.

- [ ] Run the gate; verify all 16 modules pass; commit:

```bash
git commit -m "chore(sprint-4): extend critical-controls gate to plugin/policy quartet (T15)"
```

---

### Task 16: Closeout note + BUILD_PLAN refresh

**Files:**
- Create: `docs/closeouts/2026-05-XX-sprint-4-plugin-registry-trust-gate.md` (date filled at commit time)
- Modify: `docs/BUILD_PLAN.md` — flip Sprint 4 status to `**CLOSED**`

Closeout structure mirrors Sprint 3:
- Header (parent SHA, base SHA, branch state)
- What ships (5 critical-controls modules + LocalObjectStoreAdapter + 1 endpoint + 4 default Rego/JSON bundles + Dockerfile pins + gate extension)
- CI matrix
- Doctrine adherence
- Test + coverage state (16-module gate table)
- Plan-review findings closed (round-by-round)
- ADR-016 / ADR-015 / ADR-002 Validation table (delivered / partial / carryover map)
- Doctrine amendments accepted in Sprint 4
- Carryover for Sprint 5+ (must include the following Wave-2 items — P3-G + P3-H reviewer-fixes):
  - **Annual integrity sweep job** (P3-G — ADR-016 §"Retention + offline re-verification") — a scheduled job that picks 1% of registered packs at random + re-verifies their persisted Sigstore bundles + alerts on bundle-verification failure. Wave 2 / out of Sprint 4 scope. Requires Sprint 5+ scheduling primitive.
  - **Vuln-drift alerting** (P3-H — ADR-016 §"Negative") — emit `pack.vuln_drift` audit event when a registered pack's deps gain a new CVE that exceeds tenant policy threshold post-registration. Wave 2; consumes Sprint 4's persisted SBOM + the future scheduled scan substrate.
- Out-of-scope items
- Next sprint pointer (Sprint 5 — MCP host)

BUILD_PLAN refresh: Sprint 4 deliverables list expanded to surface load-bearing artifacts (LocalObjectStoreAdapter, dockerfile binaries, gate extension); status line flipped to CLOSED; commit count + suite delta filled in.

- [ ] Author + commit:

```bash
git commit -m "docs(sprint-4): closeout note + BUILD_PLAN refresh (T16)"
```

---

## Self-Review

After authoring the 16 tasks above, the plan was reviewed against:

**Spec coverage check:**
- All Sprint 4 BUILD_PLAN deliverables mapped to tasks: plugin_registry → T5; trust_gate → T6; supply_chain → T7; reproducibility → T8; policy/engine → T2; supply_chain.rego + allowlist.json → T3; LocalObjectStoreAdapter → T4 (replaces ADR-009 Sprint-8 deferral per Q1 lock); /system/plugins endpoint → T11; cognic_test_pack fixture → T12; HOW-TO-WRITE-A-PACK doc → T14; coverage-gate extension → T15. Settings extension (T1) covers all eight Sprint-4 settings.

**Placeholder scan:** searched the plan for "TBD", "TODO", "implement later", "fill in details", "Add appropriate ...". The two implementation-section paragraphs marked "Implementation guidance" (T2, T4) explicitly defer FULL CODE to the engineer because the tests themselves pin the contract — that's TDD, not a placeholder. T6 says "Standard TDD shape" — same shape as T5; safe abbreviation.

**Type consistency:** every type referenced in later tasks defined in earlier ones. `Decision` defined in T2; `RegistrationOutcome` defined in T5 + reused in T10; `AttestationResult` defined in T7; `PathTraversalError` / `RetentionWindowActiveError` defined in T4; `CosignVerificationResult` defined in T6.

**Cross-task dependencies:** T2 lands the policy-engine seed before T3 (which defines the bundle the engine will consult). T4 lands the LocalObjectStoreAdapter before T9 (which uses it). T5 lands the registry before T6/T7 (which it integrates). T10 is the integration step that requires T2 + T6 + T7 + T9 + T4 to all be done.

**Halt-before-commit discipline:** every task touching a critical-controls module (T2, T5, T6, T7, T10) explicitly mentions halt-before-commit. T1 (settings) and T11 (endpoint) are not critical-controls but still halt per the per-action rule.

---

## Execution Handoff

Plan complete. The plan-of-record itself needs:
1. Local commit on a chore branch
2. Push + open chore PR (separate authorisation)
3. Reviewer rounds against the doctrine
4. Plan-PR merge

Only after the plan-PR merges does Sprint 4 implementation start, beginning at T0 → T1.

Two execution options for the implementation phase:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using the executing-plans sub-skill, batch execution with checkpoints for review.

But this decision waits until after the plan-PR is merged, mirroring Sprint 3's flow.
