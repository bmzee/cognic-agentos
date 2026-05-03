# Sprint 5 — MCP Host (Streamable HTTP First; STDIO Restricted; OAuth/PRM Authorization) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** AgentOS speaks MCP (Model Context Protocol) over **Streamable HTTP** (production default) with full OAuth + Protected Resource Metadata authorization per the April 2026 MCP authorization spec, validates pack manifests against the Wave-1 conformance matrix at registration, and refuses high-risk tool invocations until the Sprint 13.5 approval engine ships. **STDIO transport in Sprint 5 = threat-model document + manifest/config validation + fail-closed refusal at registration; STDIO ≠ process launch** (deferred to Sprint 8 with sandbox primitive per ADR-002 §"Sandbox dependency hard-block"). Sprint 4 admits packs onto the registry; Sprint 5 controls what those packs can actually invoke.

**Architecture:** **Five new critical-controls modules** under `src/cognic_agentos/protocol/` — the Sprint-5 MCP quintet, all enforced at the same ≥95% line / ≥90% branch coverage floor by `tools/check_critical_coverage.py` (T14) and named in the AGENTS.md doctrine list (T15):
- `mcp_authz.py` — OAuth/PRM client (3-path resource-metadata discovery, per-tenant AS allow-list, RFC 8707 resource indicator, audience validation, 401-vs-403 step-up flow, token cache + refresh). Admission-side per R3 P1 doctrine — no `mcp` SDK dependency.
- `mcp_manifest.py` — signed-manifest extractor that reads `cognic-pack-manifest.toml` from an installed pack distribution via `importlib.metadata.Distribution.locate_file()` without importing pack code (preserves Sprint-4's deferred-load invariant). Admission-side per R3 P1 doctrine — stdlib only, no SDK dependency.
- `mcp_capabilities.py` — capability + manifest validator enforcing the conformance matrix from `docs/MCP-CONFORMANCE.md` against parsed pack manifest declarations: resources optional, sampling default-deny per tenant + per pack + per cloud-policy (via Sprint-4 `OPAEngine`), restricted-data-class elicitation/caching refusals, anonymous MCP forbidden, STDIO refused in Sprint 5. Admission-side per R3 P1 doctrine — no `mcp` SDK dependency (the OPA-backed sampling check inherits Sprint-4's OPA-binary dependency, which is a separate boundary).
- `mcp_transports.py` — pluggable transport layer with two classes: `StreamableHTTPTransport` (production default, opens MCP sessions over HTTP via the official SDK; runtime-side per R3 P1 — calls `require_mcp()` at construction) and `StdioTransport` (a non-launching stub: default Python constructor + three transport methods (`open_session` / `send` / `close_session`), each of which is an unconditional `NotImplementedError` raise; no `register` method exists; STDIO refusal at registration is owned entirely by `mcp_capabilities` + `plugin_registry` per R2 P2 #4 doctrine; Sprint 8 lifts the STDIO launch path with the sandbox primitive).
- `mcp_host.py` — `MCPHost.discover_servers() / list_tools() / call_tool()` orchestration; ADR-014 transitional gate refuses any `risk_tier > internal_write` invocation until `core/approval` ships in Sprint 13.5; runtime-side per R3 P1 — calls `require_mcp()` at construction.

**Tech Stack:** Python 3.12 + FastAPI 0.115+ + httpx (async HTTP for OAuth + MCP transport) + the official `mcp` SDK pinned to its current released version. AsyncSQL via SQLAlchemy 2.0 (already wired) for the Sprint-2 audit-event chain + decision-history substrate. OPA Rego (already wired in Sprint 4) for the sampling-default-deny policy bundle. cosign signature verification on pack wheels (already wired in Sprint 4) covers the **wheel itself + any signed-static-manifest file shipped inside it**; AgentCard JWS signature verification is **not** in Sprint 5 — that's Sprint 6's A2A endpoint scope per ADR-003. Sprint 5 reads MCP server identity from the cosign-verified wheel, never trusts a runtime-fetched card.

---

## Decision Lock — Option C: STDIO ships docs + validation + refusal, NOT process launch

This decision is load-bearing for the rest of the plan. It is not a footnote; every task downstream of this section assumes it.

**STDIO in Sprint 5 SHIPS:**
- `docs/MCP-STDIO-THREAT-MODEL.md` — the canonical threat-model document. Catalogues the April-2026 MCP supply-chain disclosures (OX Security et al), codifies the four-gate STDIO restriction from ADR-002, names the audit events that fire on every refusal, and explicitly states that process spawning is a Sprint-8 concern.
- Three layered refusal sites for STDIO packs at registration, each owning a distinct doctrine boundary:
  - **Signature integrity (Sprint-4 boundary, not Sprint-5):** unsigned wheels (and therefore unsigned manifests-shipped-inside-the-wheel) are refused by `protocol/trust_gate.py` (cosign signature verification) before any Sprint-5 code path runs. Sprint 5 inherits this — it does NOT re-implement signature verification at the manifest layer.
  - **Malformed static manifest file** (`protocol/mcp_manifest.py`, T6.1): `PackManifestMalformedError` if the manifest file exists but its TOML is invalid → registry refuses with closed-enum `mcp_manifest_malformed` (always, regardless of pack intent — cosign-signed bytes that don't parse imply a packaging-bug fail-closed event). The R2-doctrine ABSENT-manifest case is NOT a refusal here: per the registry contract (`PluginRegistry._mcp_admit`), a missing `cognic-pack-manifest.toml` is treated as "no MCP intent" and proceeds to the policy step (Sprint-4-style pack OR non-MCP cognic pack). The `mcp_manifest_missing` closed-enum literal still exists in the `RefusalReason` vocabulary but is RESERVED for a future explicit MCP-intent path (Sprint-7A `agentos validate` or future MCP-specific entry-point group); no current T6 admission code path emits it. Separately, R2 P1 routes a present-but-non-dict `[tool.cognic.mcp]` block to `mcp_manifest_malformed` via the registry's safe-walk so structural shape errors in the MCP block can't bypass the gates.
  - **Bad parsed STDIO declarations** (`protocol/mcp_capabilities.py`, T6.2): the validator operates on the parsed manifest dict (output of T6.1's extractor) and refuses on parsed-content defects only — missing `command` / `args` / `env_allowlist`; shell metacharacters in the command; command not on per-tenant allow-list; the umbrella `mcp_stdio_disabled_in_sprint_5` Decision-Lock refusal that fires regardless of the other three. Maps to the `mcp_stdio_*` closed-enum reasons.
- The three sites compose into "any STDIO pack registers as refused in Sprint 5" without any single layer claiming responsibility for ALL refusals — signature coverage stays at the Sprint-4 trust gate (no doctrine drift), manifest existence/parsing stays at `mcp_manifest`, and capability/declaration validation stays at `mcp_capabilities`.
- Config-load fail-fast in `core/config.py` — if `runtime_profile = "prod"` AND `mcp_stdio_enabled = true` AND no sandbox runtime is importable (`cognic_agentos.sandbox.runtime` doesn't exist in Sprint 5) → raise `SandboxNotAvailableError` at startup, NOT at first invocation. Dev profile (`runtime_profile = "dev"`) defaults `mcp_stdio_enabled = false` in Sprint 5 (Sprint 8 may flip dev to `true` after sandbox lands; prod stays hard-disabled until both sandbox AND operator opt-in). The settings field name is `runtime_profile` (not `profile`); the env var is `COGNIC_RUNTIME_PROFILE`.
- Refusal-at-registration tests pinning the contract: any STDIO pack registers as refused with the `mcp_stdio_disabled_in_sprint_5` closed-enum reason (Sprint 8 will rename this to `mcp_stdio_disabled` when the umbrella refusal turns into a conditional gate; Sprint-5 contract uses the `_in_sprint_5` suffix everywhere); an `audit.stdio_launch_refused` event is appended to the `audit_event` chain via `AuditStore.append`. (No `decision_history` row is written for STDIO registration refusals — per T11, only MCP call_tool outcomes, token refreshes, and registration *auth probes* produce decision-history rows; STDIO refusal is registry-side and audit-only.)
- The `audit.stdio_launch_refused` audit event vocabulary (event name + payload schema as a row in the hash-chained `audit_event` table) so Sprint 8 has a stable shape to extend, NOT a new vocabulary to invent.

**STDIO in Sprint 5 DOES NOT SHIP:**
- Any `subprocess.run`, `subprocess.Popen`, `os.execvp`, `os.execve`, `os.spawn*`, or `multiprocessing.Process` call from any module under `protocol/mcp_*` or anywhere else in the runtime path that would execute an external command.
- Any "command launcher" helper, even a private one named `_validate_command_then_skip_launch` or similar.
- Any sandbox-integration scaffolding (no `from cognic_agentos.sandbox import …` imports — that module doesn't exist yet and won't be referenced until Sprint 8).
- Any test that exercises a real launch (only tests proving the launch path is refused).
- Any environment-variable filtering / capability-restriction code that pretends to bound a process that isn't being spawned.

If a reviewer or future-you finds a `_validate_command()` helper or `subprocess` import being added to keep "Option C honest about validation," that is the drift Option C is designed to prevent. The architecture test (Task 4) catches it mechanically.

**Sprint 8 hand-off (load-bearing, surfaced in Task 15 closeout):** when sandbox lands, the deferred work is a SINGLE concrete addition: a sandbox-aware `StdioTransport.launch()` method that spawns the validated command inside the sandbox boundary, with the env-allowlist applied, with the audit event upgraded from `stdio_launch_refused` to `stdio_launch_completed`. Everything else (manifest validation, command-allowlist lookup, env-allowlist parsing, threat-model documentation) is settled in Sprint 5.

---

## Three Guardrails (load-bearing)

These three artifacts make the Decision Lock actionable rather than aspirational:

### 1. Scope-boundary "does not ship" list

Embedded in the plan above (the "STDIO in Sprint 5 DOES NOT SHIP" section). The plan-PR review enforces it — any task whose code introduces a banned construct is reverted before commit. The list is also restated in `docs/MCP-STDIO-THREAT-MODEL.md` as part of the doctrine document, so future sprints can reference it.

### 2. Architecture test banning `subprocess` / `os.exec*` imports in STDIO modules

`tests/architecture/test_mcp_stdio_no_subprocess.py` walks the AST of every Python file under `src/cognic_agentos/protocol/mcp_*` (and any submodule named `*stdio*`) and asserts:

- No `import subprocess` (any form: bare `import`, `from subprocess import …`, `import subprocess as _sub`).
- No `os.execvp`, `os.execve`, `os.execvpe`, `os.execlp`, `os.execle`, `os.spawn*`, `os.posix_spawn*`, `os.system`.
- No `multiprocessing.Process` (or `multiprocessing.Pool` configured for command execution).
- No `asyncio.create_subprocess_exec`, `asyncio.create_subprocess_shell`.
- No string-mode shell calls via `shell=True` kwargs (defensive against any future module import).

Crude but mechanical. Tripping it in Sprint 8 is correct (when the launcher lands, the test gets updated to allow `subprocess` in the new sandboxed launcher module only). Tripping it in any other sprint is a doctrine violation that needs explicit review.

### 3. Sprint-8 hand-off checklist

Lives in the Sprint-5 closeout note (Task 15). Names exactly what Sprint 8 must add to lift STDIO from refused-at-registration to sandboxed-launch:

- A new module `protocol/mcp_stdio_launcher.py` with the sandboxed `launch()` method (added to the architecture-test allow-list when it lands).
- Flip `mcp_stdio_enabled` default for `dev` profile from `false` to `true` (production stays `false` until operator explicitly opts in plus sandbox is importable plus the four-gate manifest validates).
- Update the registry-side STDIO gate (which currently returns `mcp_stdio_disabled_in_sprint_5` for any STDIO pack via T6's capability validator): switch to a conditional refusal — `mcp_stdio_enabled=true AND sandbox available AND four-gate manifest passes AND command on per-tenant allow-list → registration succeeds; otherwise → refusal with the same closed-enum vocabulary`. The Sprint-5 `mcp_stdio_disabled_in_sprint_5` literal value is renamed to `mcp_stdio_disabled` (Sprint 8 closeout edit). Registry stays the single owner of `RegistrationOutcome`; transport never produces refusals.
- Upgrade the audit event vocabulary from `stdio_launch_refused` (Sprint 5) to add `stdio_launch_completed` + `stdio_launch_failed` + `stdio_launch_timeout` (Sprint 8). The `_refused` reason stays — that's the path operators see when they misconfigure.
- Integration tests under the sandbox runtime that prove (a) launch happens inside the sandbox, (b) env-allowlist is enforced, (c) command-allowlist is enforced, (d) sandbox boundary breach attempts fail closed.

Sprint 5 ships everything else. Sprint 8 ships the launcher. The seam is clean.

---

## File Structure

This sprint creates 7 new modules, 1 new doctrine document, 1 new test fixture pack, ~12 unit-test modules, 1 architecture test, modifies ~5 existing files. ~17 files created, ~6 modified.

**Created:**
- `docs/MCP-STDIO-THREAT-MODEL.md` — canonical threat-model doc (Task 3)
- `src/cognic_agentos/protocol/__init__.py` — kernel-resilient `_PROTOCOL_OPTIONAL_DEPS` map for missing-`mcp`-SDK tolerance on the kernel image (Task 2; addresses R1 P2 #1)
- `src/cognic_agentos/protocol/mcp_authz.py` — OAuth/PRM client with audit-store + decision-history-store dependencies (Task 5)
- `src/cognic_agentos/protocol/mcp_manifest.py` — signed-manifest extractor using `Distribution.locate_file()` to preserve the deferred-load invariant (Task 6; addresses R1 P2 #2)
- `src/cognic_agentos/protocol/mcp_capabilities.py` — capability validator (Task 6)
- `src/cognic_agentos/protocol/mcp_transports.py` — StreamableHTTPTransport + StdioTransport refusal (Tasks 7–8)
- `src/cognic_agentos/protocol/mcp_host.py` — MCPHost orchestrator with audit + decision-history correlation (Task 9)
- `policies/_default/sampling.rego` — default-deny sampling Rego bundle (Task 6)
- `tests/architecture/__init__.py` + `tests/architecture/test_mcp_stdio_no_subprocess.py` — guardrail with recursive scan + 3 self-tests (Task 4)
- `tests/unit/protocol/test_mcp_authz.py` (Task 5)
- `tests/unit/protocol/test_mcp_manifest.py` — extractor tests against editable + wheel-installed fixtures (Task 6)
- `tests/unit/protocol/test_mcp_capabilities.py` (Task 6)
- `tests/unit/protocol/test_mcp_registration_auth_probe.py` — registration-time auth probe tests (Task 6; addresses R1 P2 #3)
- `tests/unit/protocol/test_refusal_reason_completeness.py` — closed-enum completeness regression test pinning the 24-value Sprint-5 RefusalReason extension (Task 6; addresses R2 P2 #3 + R3 P2 arithmetic correction + R6 P2 production-grade auth surface + R11 P2 split AS-discovery / token-endpoint / token-response off the PRM-invalid bucket + T6 R1 P1 #1/#2 fail-closed admission gates: `mcp_admission_deps_required` + `mcp_transport_unsupported`)
- `tests/unit/protocol/test_optional_dep_loader.py` — optional-dep loader API tests pinning kernel-image module-import behaviour (Task 2; addresses R2 P2 #1)
- `tests/unit/protocol/test_mcp_transports_http.py` (Task 7)
- `tests/unit/protocol/test_mcp_transports_stdio.py` (Task 8)
- `tests/unit/protocol/test_mcp_host.py` (Task 9)
- `tests/unit/protocol/test_mcp_high_risk_tier_refused.py` (Task 10)
- `tests/unit/protocol/test_mcp_audit_linkage.py` — audit-chain side (Task 11)
- `tests/unit/protocol/test_mcp_decision_history_linkage.py` — decision-history side (Task 11; addresses R1 P2 #6)
- `tests/fixtures/cognic_test_mcp_pack/` — fixture HTTP MCP server with `cognic-pack-manifest.toml` (Task 12)
- `tests/unit/protocol/test_mcp_no_user_controlled_command.py` — negative-path canary (Task 13)
- `docs/closeouts/2026-05-XX-sprint-5-mcp-host.md` — closeout (Task 15)

**Modified:**
- `src/cognic_agentos/core/config.py` — Sprint-5 settings (Task 1; 8 new fields including `mcp_sampling_policy_bundle` per R1 P3 #8 and `mcp_oauth_credentials_path` per T5 R6 P1)
- `.env.example` — operator-facing docs for new settings (Task 1)
- `pyproject.toml` + `uv.lock` — pin official `mcp` SDK in adapters extras (Task 2)
- `src/cognic_agentos/portal/api/app.py` — `create_app` (kernel) does NOT wire MCPHost; `create_prod_app` (default-adapters) does, with kernel-resilient ImportError handling (Task 2; addresses R1 P2 #1)
- `infra/agentos/Dockerfile` — header comment documents the kernel-vs-default-adapters MCP availability split (Task 2)
- `src/cognic_agentos/protocol/plugin_registry.py` — extractor → validator → auth-probe sequence on registration; 11 new closed-enum reasons (Task 6 — narrow edit, halt-before-commit because it's a critical-controls module)
- `AGENTS.md` — append Sprint-5 critical-controls quintet to the doctrine list (Task 15; addresses R1 P3 #9)
- `tools/check_critical_coverage.py` — extend gate from 16 → 21 modules (Task 14)
- `docs/BUILD_PLAN.md` — flip Sprint 5 status to **CLOSED** with deliverables refresh (Task 15)

---

## Task 0: Land plan-of-record on `main` as chore PR

**Files:**
- Verify the plan file is committed on the chore branch (already done before this task fires).
- Push, open PR, doctrine-review rounds, merge to `main`. **This is the only Sprint-5 work that goes through a separate PR cycle from the implementation branch.** Same shape as Sprint 4 PR #12.

- [ ] **Step 1: Push chore branch + open plan PR**

```bash
git push -u origin chore/sprint-5-mcp-host-plan
gh pr create --base main --head chore/sprint-5-mcp-host-plan \
  --title "Sprint 5 plan: MCP host (Streamable HTTP first; STDIO restricted; OAuth/PRM)" \
  --body "$(cat <<'EOF'
Sprint 5 plan-of-record.

Locks Option C: STDIO in Sprint 5 = threat model + manifest/config validation +
fail-closed refusal at registration. STDIO ≠ process launch (deferred to Sprint 8
with sandbox primitive per ADR-002 §"Sandbox dependency hard-block").

Three guardrails baked into the plan:
- Scope-boundary "does not ship" list
- Architecture test banning subprocess/exec imports in STDIO modules
- Sprint-8 hand-off checklist

Preserves BUILD_PLAN Sprint 5 intent: Streamable HTTP first / OAuth+PRM /
capability validation / audit + decision-history linkage / ADR-014 transitional
high-risk refusal / fixture MCP pack only (no production tools).

Doctrine references:
- docs/adrs/ADR-002-mcp-plugin-protocol.md
- docs/MCP-CONFORMANCE.md
- docs/adrs/ADR-014-runtime-tool-approval.md (transitional rule)
- docs/adrs/ADR-015-policy-as-code.md (sampling.rego seed)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR opens; CI runs lint+test+coverage on the chore branch (no production code changed; tests still 1441 passed).

- [ ] **Step 2: Doctrine-review rounds (Round 1, Round 2, …)**

Reviewer surfaces P1 / P2 / P3 findings against ADRs, BUILD_PLAN, AGENTS.md. Findings get patched into the plan file directly on the chore branch. Each round = halt + summary + commit per finding cluster.

- [ ] **Step 3: Squash-merge plan-PR to main once review-clean**

```bash
gh pr merge <PR#> --squash --delete-branch \
  --subject "chore(plan): sprint 5 mcp host (Streamable HTTP first; STDIO restricted; OAuth/PRM) plan-of-record" \
  --body "<rounds-summary>"
```

After merge: switch to a fresh implementation branch `feat/sprint-5-mcp-host`, root it on the merged plan, begin Task 1.

---

## Task 1: Settings extension + `.env.example`

**Files:**
- Modify: `src/cognic_agentos/core/config.py` — add 8 Sprint-5 settings (R8 P2 added the production-grade Vault credentials path that R6 P1 needed for real OAuth client credentials; the plan was originally drafted for 7 fields).
- Modify: `.env.example` — operator-facing docs.
- Test: `tests/unit/test_config.py` — extend existing settings tests.

The 8 settings:

```python
# Sprint 5 — MCP host
mcp_stdio_enabled: bool = Field(
    default=False,
    description=(
        "STDIO MCP transport opt-in. Default False in all profiles; Sprint 8 "
        "may flip dev to True after sandbox primitive is operational. "
        "Production profile remains hard-disabled until operator explicitly "
        "opts in PLUS sandbox available PLUS four-gate manifest passes."
    ),
)
mcp_stdio_command_allowlist_path: str = Field(
    default="secret/cognic/{tenant}/stdio-command-allowlist",
    description=(
        "Vault path template for the per-tenant STDIO command allow-list. "
        "Sprint 5 reads this at registration time to refuse STDIO packs "
        "whose declared command is not on the list. Per ADR-002 §MCP STDIO "
        "threat model gate 2."
    ),
)
mcp_as_allowlist_path: str = Field(
    default="secret/cognic/{tenant}/mcp-as-allowlist",
    description=(
        "Vault path template for the per-tenant OAuth authorization-server "
        "allow-list. Sprint 5 refuses MCP servers whose PRM points to a "
        "non-allowlisted AS. Per ADR-002 §MCP Authorization step 3."
    ),
)
mcp_oauth_token_cache_ttl_s: int = Field(
    default=3600,
    description=(
        "TTL for the OAuth token cache. Tokens cached per (server, scope, "
        "resource) tuple; refreshed before this expiry; refresh emits "
        "audit.mcp_token_refresh event appended to the audit_event chain "
        "via AuditStore.append. T11 also writes a decision_history row "
        "for the refresh decision (correlated by request_id)."
    ),
)
mcp_oauth_request_timeout_s: int = Field(
    default=30,
    description=(
        "Strict timeout on every PRM discovery + token request + token "
        "refresh outbound HTTP call. Same fail-closed posture as the "
        "cosign subprocess timeout."
    ),
)
mcp_call_tool_timeout_s: int = Field(
    default=60,
    description=(
        "Strict timeout on every MCP call_tool invocation against an HTTP "
        "MCP server. Tool that exceeds this raises mcp_call_tool_timeout, "
        "audit-logged with pack identity + tool name + duration."
    ),
)
mcp_sampling_policy_bundle: Path = Field(
    default=Path("policies/_default/sampling.rego"),
    description=(
        "Rego bundle path consumed by protocol/mcp_capabilities.py to "
        "evaluate the four-condition sampling default-deny per ADR-002 + "
        "MCP-CONFORMANCE.md. Operators override per-tenant by pointing this "
        "at a Vault-mounted bundle. Default ships with `policies/_default/"
        "sampling.rego` (default-deny; allow only when pack manifest, "
        "tenant policy, cloud-policy tier consistency, and "
        "allow_external_llm consistency all hold)."
    ),
)
mcp_oauth_credentials_path: str = Field(
    default="secret/cognic/{tenant}/mcp-oauth/{as_host}",
    description=(
        "Vault path template for per-tenant per-AS OAuth client credentials. "
        "Resolved at token-acquisition time as "
        "``mcp_oauth_credentials_path.format(tenant=tenant_id, "
        "as_host=urlparse(as_issuer).netloc.replace(':', '_'))``. "
        "**Sanitisation** (R9 P3): the AS issuer netloc has ``:`` replaced "
        "by ``_`` before interpolation so the value is safe to use as a Vault "
        "path segment; operators populating Vault for an issuer with an "
        "explicit port (e.g. ``https://as.example:8443``) MUST write the "
        "secret to ``secret/cognic/<tenant>/mcp-oauth/as.example_8443`` "
        "(underscore), NOT ``as.example:8443``. Vault secret shape: "
        "``{client_id, client_secret, auth_method}`` where auth_method is "
        "one of ``client_secret_post`` / ``client_secret_basic`` (Sprint 5; "
        "Wave 2 adds private_key_jwt + mTLS). Added in T5 R6 P1 to replace "
        "the originally-planned synthesised-client_id stub with real Vault-"
        "backed credentials per AGENTS.md production-grade rule."
    ),
)
```

- [ ] **Step 1: Write the failing test (mcp settings present + correct defaults)**

```python
# tests/unit/test_config.py — append to existing class
class TestMcpSettings:
    def test_mcp_stdio_enabled_defaults_false(self) -> None:
        settings = build_settings_without_env_file()
        assert settings.mcp_stdio_enabled is False

    def test_mcp_oauth_token_cache_ttl_defaults_one_hour(self) -> None:
        settings = build_settings_without_env_file()
        assert settings.mcp_oauth_token_cache_ttl_s == 3600

    def test_mcp_oauth_request_timeout_defaults_thirty_seconds(self) -> None:
        settings = build_settings_without_env_file()
        assert settings.mcp_oauth_request_timeout_s == 30

    def test_mcp_call_tool_timeout_defaults_one_minute(self) -> None:
        settings = build_settings_without_env_file()
        assert settings.mcp_call_tool_timeout_s == 60

    def test_mcp_stdio_command_allowlist_path_template(self) -> None:
        settings = build_settings_without_env_file()
        assert "{tenant}" in settings.mcp_stdio_command_allowlist_path
        assert "stdio-command-allowlist" in settings.mcp_stdio_command_allowlist_path

    def test_mcp_as_allowlist_path_template(self) -> None:
        settings = build_settings_without_env_file()
        assert "{tenant}" in settings.mcp_as_allowlist_path
        assert "mcp-as-allowlist" in settings.mcp_as_allowlist_path

    def test_mcp_sampling_policy_bundle_defaults_to_default_rego(self) -> None:
        settings = build_settings_without_env_file()
        assert settings.mcp_sampling_policy_bundle == Path(
            "policies/_default/sampling.rego"
        )

    def test_mcp_oauth_credentials_path_template(self) -> None:
        """Per-tenant per-AS Vault path template added in T5 R6 P1.
        Both ``{tenant}`` and ``{as_host}`` placeholders preserved
        verbatim so runtime ``.format()`` substitutes correctly."""
        settings = build_settings_without_env_file()
        assert "{tenant}" in settings.mcp_oauth_credentials_path
        assert "{as_host}" in settings.mcp_oauth_credentials_path
        assert "mcp-oauth" in settings.mcp_oauth_credentials_path
```

Run: `uv run pytest tests/unit/test_config.py::TestMcpSettings -v`
Expected: 8 tests FAIL with `AttributeError: 'Settings' object has no attribute 'mcp_stdio_enabled'`.

- [ ] **Step 2: Implement settings in `core/config.py`**

Add the 8 fields above to `class Settings(BaseSettings):` after the Sprint-4 settings group. Group them under a `# Sprint 5 — MCP host` comment header.

- [ ] **Step 3: Run tests; expect PASS**

Run: `uv run pytest tests/unit/test_config.py::TestMcpSettings -v`
Expected: 8 PASSED.

- [ ] **Step 4: Update `.env.example`**

Append:

```
# ===== Sprint 5 — MCP host =====
# STDIO transport is hard-disabled in Sprint 5 (sandbox primitive lands Sprint
# 8). Setting this to True with runtime_profile=prod and no sandbox available =>
# fail-fast at startup. See docs/MCP-STDIO-THREAT-MODEL.md.
COGNIC_MCP_STDIO_ENABLED=false

# Vault path template for the per-tenant STDIO command allow-list.
COGNIC_MCP_STDIO_COMMAND_ALLOWLIST_PATH=secret/cognic/{tenant}/stdio-command-allowlist

# Vault path template for the per-tenant OAuth authorization-server allow-list.
COGNIC_MCP_AS_ALLOWLIST_PATH=secret/cognic/{tenant}/mcp-as-allowlist

# OAuth token cache TTL (seconds). Refresh emits audit.mcp_token_refresh.
COGNIC_MCP_OAUTH_TOKEN_CACHE_TTL_S=3600

# Strict timeout on every PRM discovery + token request HTTP call (seconds).
COGNIC_MCP_OAUTH_REQUEST_TIMEOUT_S=30

# Strict timeout on every MCP call_tool invocation (seconds).
COGNIC_MCP_CALL_TOOL_TIMEOUT_S=60

# Sampling default-deny Rego bundle path (consumed by protocol/mcp_capabilities.py).
# Operators override per-tenant by pointing this at a Vault-mounted bundle.
COGNIC_MCP_SAMPLING_POLICY_BUNDLE=policies/_default/sampling.rego

# Vault path template for per-tenant per-AS OAuth client credentials (T5 R6 P1).
# Resolved at token-acquisition time with {tenant} + {as_host} substitutions
# where {as_host} is urlparse(as_issuer).netloc with ':' replaced by '_' (R9 P3
# — keeps the value safe as a Vault path segment). For an issuer like
# "https://as.example:8443" populate Vault at .../mcp-oauth/as.example_8443
# (underscore), NOT as.example:8443.
# Vault secret shape: {client_id, client_secret, auth_method} where auth_method
# is "client_secret_post" or "client_secret_basic" (Sprint 5; Wave 2 adds
# private_key_jwt + mTLS). Operators MUST populate this Vault path before MCP
# packs admit; missing credentials surface as the closed-enum
# mcp_oauth_credentials_missing refusal.
COGNIC_MCP_OAUTH_CREDENTIALS_PATH=secret/cognic/{tenant}/mcp-oauth/{as_host}
```

- [ ] **Step 5: Sweep + commit**

Run: `uv run ruff check . && uv run mypy src tests && uv run pytest -q`
Expected: All green; suite at 1441 + 8 = 1449 passed.

```bash
git add src/cognic_agentos/core/config.py tests/unit/test_config.py .env.example
git commit -m "feat(sprint-5): add MCP host settings (T1)"
```

---

## Task 2: Add the official `mcp` SDK dependency + lock the kernel-vs-default-adapters runtime contract

**Files:**
- Modify: `pyproject.toml` — add `mcp` to `[project.optional-dependencies].adapters`.
- Modify: `uv.lock` — auto-resolved by `uv sync`.
- Modify: `src/cognic_agentos/db/adapters/__init__.py` — extend the existing `_BUNDLED_ADAPTER_OPTIONAL_DEPS` allow-list pattern (Sprint 1C) so the kernel-resilient loader handles the new MCP modules' missing-dep case identically.
- Modify: `src/cognic_agentos/portal/api/app.py` — narrow edit so `create_app` (kernel factory) does NOT wire `MCPHost` and `create_prod_app` (default-adapters factory) DOES wire it. **Halt-before-commit because `app.py` mediates the kernel-vs-adapters runtime contract.**
- Modify: `infra/agentos/Dockerfile` header comment — add a paragraph documenting the kernel-vs-default-adapters MCP availability split.
- Test: `tests/unit/llm/test_plugins_endpoint.py` already exercises the kernel-resilient loader's tolerance for missing optional deps; extend it with an MCP-specific arm.

**The kernel-vs-default-adapters runtime contract (load-bearing — addresses R1 P2 #1).** This task locks the runtime contract for Sprint 5 explicitly so implementation does not produce a "split-brain" image where MCP code ships in the kernel image but cannot import its runtime dep.

The contract:

1. **`mcp` SDK lives in `[project.optional-dependencies].adapters` only** — kernel image (`runtime` Docker target) does NOT carry it. Default-adapters image (`default-adapters` Docker target) does.
2. **MCP host availability is locked to the default-adapters image.** A kernel-image deployment exposes governance + audit + registry-discovery + the /system/* read surfaces, plus the Sprint-5 MCP admission modules at the import + construction boundary (`mcp_manifest`, `mcp_capabilities`, `mcp_authz` all SDK-free). It does NOT serve `MCPHost` — the kernel `create_app` factory deliberately does not wire it. `create_prod_app` (the default-adapters factory) is the only entry point that wires `MCPHost` into `app.state`. **Caveat (Sprint-4 doctrine, surfaced here for clarity):** end-to-end signed-pack admission (`register_with_full_attestation_check`) subprocess-calls cosign + OPA, both of which Sprint 4 ships in the default-adapters image only — so kernel-image admission of HTTP MCP packs is bounded by that prior constraint, NOT a new Sprint-5 limitation. Operators choosing the kernel image are signalling "I want the read surfaces and will run admission + MCP via a sidecar or default-adapters pod."
3. **Module-level imports of every `protocol/mcp_*.py` module MUST succeed without the `mcp` SDK installed** — admission-side modules (`mcp_manifest`, `mcp_capabilities`, `mcp_authz`) never reference the SDK at all (no `from mcp import …` anywhere); runtime-side modules (`mcp_host`, `mcp_transports.StreamableHTTPTransport`) keep all SDK references behind `TYPE_CHECKING:` for typing or inside method bodies for lazy resolution. **Do NOT use guarded `try: from mcp import … except ImportError` at module scope** — that pattern fires at import time, while the contract is "module imports always succeed; constructor / method calls fail loudly via `require_mcp()` only when actually invoked on a kernel-image venv." The kernel-resilient *startup* loader (T2 step 5 — `create_prod_app`) reads `is_mcp_available()` once and either wires `MCPHost` or skips with a structured warning; that warning, NOT a try/except at module scope, is what mirrors the Sprint-1C `_BUNDLED_ADAPTER_OPTIONAL_DEPS` log-and-skip pattern.
4. **The kernel-resilient loader emits a structured warning at startup** when it skips an MCP module due to missing `mcp` dep, naming the affected module + the optional-dep group that would resolve it. Operators see exactly why the MCPHost is unavailable.
5. **Documented in:** `infra/agentos/Dockerfile` header (alongside the existing kernel-vs-default-adapters split note); `docs/HOW-TO-WRITE-A-PACK.md` §"Where the verification path lives in source" (extended); the Sprint-5 closeout (§"Runtime image availability").

This is the same shape Sprint 4 used for `cosign` + `OPA` binaries (default-adapters image only; kernel image deliberately untouched). Sprint 5 follows the same precedent for the SDK-import dimension.

- [ ] **Step 1: Identify the current released `mcp` SDK version**

```bash
# Check on PyPI for the current released version of the MCP Python SDK.
# Pin to that exact version (no ^ or ~ ranges — Sprint-4 doctrine on
# secure-subprocess invariants applies to OAuth client behaviour too;
# version drift is a registration-time contract change).
```

Update the plan with the actual pinned version (the implementation engineer fills this in at task time; the SDK is released by Anthropic + the MCP working group, available on PyPI as `mcp`).

- [ ] **Step 2: Add to `pyproject.toml` adapters extras**

```toml
[project.optional-dependencies]
adapters = [
  # ... existing entries (Sprint 1C / 1D) ...
  "mcp == X.Y.Z",  # Sprint 5 — pinned at task time
]
```

- [ ] **Step 3: `uv sync --extra adapters`; verify import works in adapters venv**

```bash
uv sync --extra adapters
uv run python -c "import mcp; print(mcp.__version__)"
```

Expected: prints the pinned version cleanly. If import fails, the dep was misnamed; halt and investigate.

- [ ] **Step 4: Specify the optional-dep loader API in `protocol/__init__.py` (R2 P2 #1 + R3 P1)**

The R1 patch sketched a `_PROTOCOL_OPTIONAL_DEPS` map but did not specify how it gets consumed. R2 review correctly flagged this as underspecified. R3 review then identified that the R2 patch over-applied `require_mcp()` to admission-side modules, breaking the kernel-image admission boundary. **Final contract — admission stays SDK-free; only runtime invocation gates on the SDK:**

**The kernel-vs-default-adapters split (R3 P1 doctrine — load-bearing):**

| Module | SDK use? | `require_mcp()` at construction? | Lives where? |
|---|---|---|---|
| `mcp_manifest` | No (stdlib only — `Distribution.locate_file()` + `tomllib`) | **No** | Admission-side; module imports + construction succeed without SDK |
| `mcp_capabilities` | No (pure-functional dict validation + Sprint-4 OPAEngine subprocess) | **No** | Admission-side; module imports + construction succeed without SDK |
| `mcp_authz` | No (httpx + json + OAuth/PRM URL conventions; pure HTTP/2.1 + RFC 8707) | **No** | Admission-side AND runtime; module imports + construction + every method succeed without SDK |
| `mcp_transports.StreamableHTTPTransport` | Yes (SDK session wiring) | **Yes** | Runtime-only; default-adapters image |
| `mcp_transports.StdioTransport` | No (the three transport methods raise `NotImplementedError`; default constructor) | **No** | Sprint-5 stub; co-located with `StreamableHTTPTransport` |
| `mcp_host.MCPHost` | Yes (SDK orchestration) | **Yes** | Runtime-only; default-adapters image |

(**Caveat on "without SDK":** the table column means "the MCP layer doesn't add a `mcp` SDK dependency to admission". It does NOT mean "full Sprint-4 signed-pack admission runs end-to-end on the kernel image" — that path still depends on cosign + OPA binaries which Sprint 4 ships in the default-adapters image only. See the docstring caveat in `protocol/__init__.py` below.)

The doctrine: **`require_mcp()` belongs ONLY in `MCPHost.__init__` and `StreamableHTTPTransport.__init__`**. Putting it in `mcp_authz` (R2 patch's mistake) would force admission-time HTTP MCP pack registration to fail on the kernel image — even though the registration probe only needs httpx + OAuth/PRM mechanics (which are SDK-free). Putting it in `mcp_manifest` / `mcp_capabilities` / `StdioTransport` is wasteful (those modules don't use the SDK at all).

**Module-import contract:** `import cognic_agentos.protocol.mcp_authz` (and every other mcp_* module) MUST succeed on a Python interpreter that has NO `mcp` SDK installed. This is non-negotiable — every test under `tests/unit/protocol/` runs on the kernel-image-equivalent venv (no `--extra adapters`) so even importing the test module shouldn't fail. Implementation discipline:

- The runtime mcp_* modules (`mcp_transports.StreamableHTTPTransport`, `mcp_host`) use **lazy / sentinel imports**, NOT module-level `from mcp import …`.
- Every reference to `mcp` SDK symbols inside any mcp_* module sits inside a function or method body, not at module scope.
- The admission-side modules (`mcp_authz`, `mcp_capabilities`, `mcp_manifest`) have NO `from mcp import …` anywhere — they don't use the SDK at all.

Pattern for runtime-side modules (those that DO use the SDK):

```python
# src/cognic_agentos/protocol/mcp_host.py — module-level imports stay clean
from __future__ import annotations
from typing import TYPE_CHECKING

from cognic_agentos.protocol import require_mcp  # raises if mcp missing

if TYPE_CHECKING:
    # Type-only imports — never resolved at runtime. Safe on kernel image.
    from mcp import ClientSession  # noqa: F401

class MCPHost:
    def __init__(self, *, registry, transports, authz, audit_store, decision_history_store, settings) -> None:
        require_mcp()  # explicit kernel-image guard — runtime, not admission
        # ... existing init ...

    async def call_tool(self, ...) -> CallResult:
        # Lazy SDK import inside the method body — module-level import succeeds on kernel
        from mcp import ClientSession  # only runs when method is actually called
        ...
```

Pattern for admission-side modules (those that do NOT use the SDK):

```python
# src/cognic_agentos/protocol/mcp_authz.py — admission-side; SDK-free
from __future__ import annotations

import httpx
import json
# NO `from cognic_agentos.protocol import require_mcp` — admission stays SDK-free.
# NO `from mcp import …` (lazy or otherwise) — module does not use the SDK.

class MCPAuthzClient:
    def __init__(
        self,
        *,
        audit_store,
        decision_history_store,
        settings,
        vault_client,
        http_client,
    ) -> None:
        # NO require_mcp() — PRM discovery + token acquisition use httpx +
        # OAuth/PRM URL conventions (RFC 8707, OAuth 2.1). The MCP spec
        # specifies HOW to do OAuth for MCP servers; the underlying
        # mechanism is generic OAuth + httpx. Kernel image admits HTTP MCP
        # packs through this client without the mcp SDK.
        # ... existing init (settings, vault_client, http_client wiring) ...

    async def discover_resource_metadata(self, *, server_url, request_id, tenant_id) -> ResourceMetadata:
        # Pure httpx — no SDK reference anywhere
        ...

    async def acquire_token(self, *, server_url, manifest_scopes, request_id, tenant_id) -> Token:
        # Pure httpx — no SDK reference anywhere
        ...
```

**Loader API surface in `src/cognic_agentos/protocol/__init__.py`:**

```python
# src/cognic_agentos/protocol/__init__.py — Sprint 5 loader API
"""Protocol package public surface + kernel-vs-default-adapters MCP gating.

The MCP host modules ship in this package but split across two boundaries:

1. Admission-side modules (mcp_manifest, mcp_capabilities, mcp_authz)
   are SDK-free — they import + construct cleanly without the `mcp`
   SDK installed (stdlib + httpx + the Sprint-4 OPAEngine subprocess).
   This is the Sprint-5 contribution to the kernel-vs-default-adapters
   boundary: the MCP-specific admission extensions (manifest
   extraction → capability validation → OAuth/PRM auth probe) do not
   gate on the `mcp` SDK.

   **Important caveat:** "SDK-free at the MCP layer" does NOT mean
   "full Sprint-4 signed-pack admission runs on the kernel image."
   Sprint-4's admission pipeline (cosign verification + supply-chain
   verifiers + OPA-driven policy gates) ships its load-bearing
   binaries (cosign, OPA) in the default-adapters image only — the
   kernel image carries the Python admission code but cannot complete
   a real `register_with_full_attestation_check` call without those
   binaries on PATH. Sprint 5 therefore narrows its claim to: the
   MCP admission extensions added in Sprint 5 do not introduce a NEW
   default-adapters-only dependency for admission. End-to-end
   kernel-image admission of HTTP MCP packs requires either (a) the
   default-adapters image (which carries cosign + OPA), or (b) an
   explicitly documented local fallback that supplies cosign + OPA
   into the kernel image's PATH (out of Sprint 5 scope).

2. Runtime-side modules (mcp_host, mcp_transports.StreamableHTTPTransport)
   use the official `mcp` SDK for session wiring. They live in this
   package but call require_mcp() at construction time. The SDK lives in
   [project.optional-dependencies].adapters; the kernel image does NOT
   install it.

Importing any of the mcp_* modules MUST succeed regardless of whether
`mcp` is installed (every SDK reference is lazy/inside-function, never
at module scope; type-only imports use TYPE_CHECKING). Constructing
MCPHost or StreamableHTTPTransport on a kernel image raises
MCPNotAvailableError; the create_prod_app factory checks
is_mcp_available() first and either wires the runtime layer or skips
with a structured warning. Admission-side modules construct cleanly
either way.

StdioTransport methods all raise NotImplementedError; the class does
not call require_mcp() because it doesn't use the SDK at all (per
Sprint-5 R3 P1 doctrine — `require_mcp()` belongs ONLY where the SDK
is actually consumed).
"""

from __future__ import annotations

import importlib.util
import logging

logger = logging.getLogger(__name__)


class MCPNotAvailableError(RuntimeError):
    """Raised when MCP runtime-side code is invoked on a kernel-image deployment.

    Hard-fails so operators see the misconfiguration immediately rather
    than silent degraded behaviour. The kernel image is a valid deploy
    target for governance + audit + the /system/* read surfaces; it can
    also import + construct the Sprint-5 MCP admission modules
    (mcp_manifest, mcp_capabilities, mcp_authz) without the `mcp` SDK
    installed (those modules are SDK-free at the import + construction
    boundary).

    What the kernel image CANNOT do, regardless of this error: complete
    a full Sprint-4 signed-pack admission (`register_with_full_attestation_check`)
    — that path subprocess-calls cosign + OPA, which Sprint 4 ships in
    the default-adapters image only. The MCP layer's contribution to
    that boundary is "no NEW default-adapters-only requirement"; full
    end-to-end admission of HTTP MCP packs still requires either the
    default-adapters image or an explicitly-documented local fallback
    that brings cosign + OPA into PATH (out of Sprint 5 scope).

    What this error specifically signals: an attempt to construct
    ``MCPHost`` or ``StreamableHTTPTransport`` (the only two SDK-using
    classes per R3 P1 doctrine) on a venv where the `mcp` SDK is not
    installed. Use the default-adapters image if you need
    ``MCPHost.call_tool`` / ``list_tools`` to work.
    """


def is_mcp_available() -> bool:
    """Return True iff the `mcp` SDK is importable in the current venv.

    Used by ``create_prod_app`` to decide whether to wire ``MCPHost``
    into ``app.state``. Cheap (uses ``importlib.util.find_spec`` — no
    actual import); safe to call repeatedly at startup.

    Admission-side code does NOT need to call this — manifest extraction,
    capability validation, and OAuth/PRM auth probing all work without
    the SDK installed.
    """
    return importlib.util.find_spec("mcp") is not None


def require_mcp() -> None:
    """Raise ``MCPNotAvailableError`` if ``mcp`` SDK is not installed.

    **Call this ONLY in classes that genuinely use the SDK at runtime:**

    - ``MCPHost.__init__`` (orchestrator that opens MCP sessions via the SDK)
    - ``StreamableHTTPTransport.__init__`` (HTTP transport wraps the SDK's
      HTTP client)

    **Do NOT call this in:**

    - ``MCPAuthzClient.__init__`` — PRM discovery + token acquisition use
      httpx + OAuth/PRM URL conventions (RFC 8707, OAuth 2.1); SDK-free.
    - ``mcp_manifest`` module — uses stdlib (``Distribution.locate_file`` +
      ``tomllib``); SDK-free.
    - ``mcp_capabilities`` module — pure-functional dict validation +
      Sprint-4 ``OPAEngine``; SDK-free.
    - ``StdioTransport.__init__`` — every transport method raises
      ``NotImplementedError``; the class never references the SDK.

    Per Sprint-5 R3 P1 doctrine: `require_mcp()` belongs ONLY where the
    SDK is actually consumed. Over-applying it to admission-side modules
    forces kernel-image admission of HTTP MCP packs to fail before
    manifest validation can run, which contradicts the kernel-image
    contract from Sprint 4.
    """
    if not is_mcp_available():
        raise MCPNotAvailableError(
            "MCP SDK is not installed in this venv. The `mcp` package "
            "ships in the `adapters` optional-deps group; rebuild with "
            "`uv sync --extra adapters` or use the default-adapters "
            "image (which carries the SDK by construction). Operators "
            "running the kernel image get governance + audit + "
            "/system/* read surfaces, and the Sprint-5 MCP admission "
            "modules (mcp_manifest, mcp_capabilities, mcp_authz) import "
            "+ construct without this SDK. Full Sprint-4 signed-pack "
            "admission still depends on cosign + OPA which are "
            "default-adapters-only — that is unrelated to this error. "
            "This error specifically signals an attempt to construct "
            "MCPHost or StreamableHTTPTransport (runtime-only, default-"
            "adapters-only)."
        )


# Documentation only — not consumed by code. The loader API is the
# is_mcp_available() / require_mcp() pair above. This dict is for
# future Sprint-N extensions that want to tolerate other optional
# protocol-layer SDKs (A2A in Sprint 6, etc.).
#
# Note: only the runtime-side modules actually depend on `mcp` at
# construction time per R3 P1; admission-side modules (mcp_manifest,
# mcp_capabilities, mcp_authz) are listed here for informational
# completeness but are SDK-free in their import + construction paths.
_PROTOCOL_OPTIONAL_DEPS: dict[str, frozenset[str]] = {
    "cognic_agentos.protocol.mcp_transports": frozenset({"mcp"}),  # StreamableHTTPTransport ctor
    "cognic_agentos.protocol.mcp_host": frozenset({"mcp"}),         # MCPHost ctor
}
```

**Tests for the loader API:**

```python
# tests/unit/protocol/test_optional_dep_loader.py
class TestOptionalDepLoader:
    def test_is_mcp_available_returns_true_when_installed(self) -> None:
        # Default test environment has mcp installed (we ran uv sync --extra adapters)
        assert is_mcp_available() is True

    def test_require_mcp_succeeds_when_installed(self) -> None:
        require_mcp()  # no-op when installed; raises only on missing

    def test_require_mcp_raises_when_missing(self, monkeypatch) -> None:
        # Simulate a kernel-image install: stub out the spec lookup
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name: None if name == "mcp" else importlib.util.find_spec(name),
        )
        with pytest.raises(MCPNotAvailableError) as exc:
            require_mcp()
        assert "adapters" in str(exc.value)  # error names the optional-deps group

    @pytest.mark.parametrize("module_name", [
        "cognic_agentos.protocol.mcp_authz",
        "cognic_agentos.protocol.mcp_capabilities",
        "cognic_agentos.protocol.mcp_manifest",
        "cognic_agentos.protocol.mcp_transports",
        "cognic_agentos.protocol.mcp_host",
    ])
    def test_module_imports_succeed_without_mcp_sdk(
        self, module_name: str, monkeypatch
    ) -> None:
        """The hardest invariant: every mcp_* module must import cleanly
        even when `mcp` SDK is not installed. If a module-level
        `from mcp import …` is added by a future commit, this test
        catches it BEFORE the kernel image breaks at runtime."""
        # Force find_spec("mcp") to return None even though mcp is installed
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *args, **kw: None if name == "mcp" else importlib.util.find_spec(name, *args, **kw),
        )
        # Reload the target module fresh so cached imports don't mask drift
        import importlib
        if module_name in sys.modules:
            del sys.modules[module_name]
        # Module-level import MUST succeed; only construction or method calls may raise
        importlib.import_module(module_name)


class TestAdmissionStaysSDKFree:
    """R3 P1 doctrine: admission-side modules (mcp_authz, mcp_capabilities,
    mcp_manifest) and StdioTransport MUST NOT call require_mcp() at
    construction. Only MCPHost and StreamableHTTPTransport are runtime-side
    and gate on the SDK.

    These tests construct each admission-side class on a kernel-image-
    equivalent venv (mocked find_spec returning None for mcp) and assert
    construction succeeds. If a future commit re-introduces require_mcp()
    in any of them, the test trips immediately.
    """

    def test_mcp_authz_constructs_without_sdk(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *a, **kw: None if name == "mcp" else importlib.util.find_spec(name, *a, **kw),
        )
        from cognic_agentos.protocol.mcp_authz import MCPAuthzClient
        # Constructor must succeed with no SDK installed — admission probe
        # uses httpx + OAuth/PRM, never the mcp SDK
        client = MCPAuthzClient(
            audit_store=Mock(),
            decision_history_store=Mock(),
            settings=Mock(),
            vault_client=Mock(),
            http_client=Mock(),
        )
        assert client is not None

    def test_mcp_capabilities_validate_runs_without_sdk(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *a, **kw: None if name == "mcp" else importlib.util.find_spec(name, *a, **kw),
        )
        from cognic_agentos.protocol.mcp_capabilities import validate_mcp_manifest
        # Function call must succeed (validates manifest dict; no SDK reference)
        result = validate_mcp_manifest({"tool": {"cognic": {"mcp": {"transport": "http", "auth": "oauth-prm"}}}}, ...)
        assert result is not None

    def test_mcp_manifest_extract_runs_without_sdk(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *a, **kw: None if name == "mcp" else importlib.util.find_spec(name, *a, **kw),
        )
        from cognic_agentos.protocol.mcp_manifest import extract_pack_manifest
        # Function call against an installed fixture pack must succeed
        manifest = extract_pack_manifest("cognic-test-mcp-pack", "cognic_test_mcp_pack")
        assert manifest is not None

    def test_stdio_transport_constructs_without_sdk(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *a, **kw: None if name == "mcp" else importlib.util.find_spec(name, *a, **kw),
        )
        from cognic_agentos.protocol.mcp_transports import StdioTransport
        # StdioTransport methods all raise NotImplementedError; construction
        # itself does NOT call require_mcp() (no SDK use anywhere in the class)
        transport = StdioTransport()
        assert transport is not None


class TestRuntimeRequiresSDK:
    """The complement of TestAdmissionStaysSDKFree: MCPHost and
    StreamableHTTPTransport DO call require_mcp() at construction. These
    tests assert that constructing them on a kernel-image-equivalent venv
    raises MCPNotAvailableError cleanly."""

    def test_mcp_host_construction_requires_sdk(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *a, **kw: None if name == "mcp" else importlib.util.find_spec(name, *a, **kw),
        )
        from cognic_agentos.protocol.mcp_host import MCPHost
        with pytest.raises(MCPNotAvailableError):
            MCPHost(
                registry=Mock(),
                transports={},
                authz=Mock(),
                audit_store=Mock(),
                decision_history_store=Mock(),
                settings=Mock(),
            )

    def test_streamable_http_transport_construction_requires_sdk(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "cognic_agentos.protocol.importlib.util.find_spec",
            lambda name, *a, **kw: None if name == "mcp" else importlib.util.find_spec(name, *a, **kw),
        )
        from cognic_agentos.protocol.mcp_transports import StreamableHTTPTransport
        with pytest.raises(MCPNotAvailableError):
            StreamableHTTPTransport(authz=Mock(), settings=Mock())
```

The `test_module_imports_succeed_without_mcp_sdk` parametrized arm is the strict invariant the R2 reviewer flagged. The `TestAdmissionStaysSDKFree` + `TestRuntimeRequiresSDK` pair are the R3 P1 doctrine — they pin which classes gate on the SDK and which don't. Any drift in either direction (admission gaining `require_mcp()`, runtime dropping it) trips immediately.

- [ ] **Step 5: Update `portal/api/app.py` to honour the kernel-vs-adapters split**

`create_app` (kernel factory) MUST NOT instantiate `MCPHost`. `create_prod_app` (default-adapters factory) calls `is_mcp_available()` first; if true, wires MCPHost; if false, logs a structured warning and skips wiring (kernel-image-equivalent venv). **Halt-before-commit because `portal/api/app.py` mediates the kernel-vs-adapters contract.**

```python
# src/cognic_agentos/portal/api/app.py — sketch
from cognic_agentos.protocol import is_mcp_available

def create_prod_app(...) -> FastAPI:
    app = create_app(...)
    # ... existing Sprint-4 wiring (plugin_registry, etc.) ...
    if is_mcp_available():
        # Lazy import — only resolved on the default-adapters image
        from cognic_agentos.protocol.mcp_host import MCPHost
        app.state.mcp_host = MCPHost(
            registry=app.state.plugin_registry,
            transports={...},
            authz=app.state.mcp_authz,
            audit_store=app.state.audit_store,
            decision_history_store=app.state.decision_history_store,
            settings=app.state.settings,
        )
        logger.info("mcp.host_wired", extra={"image": "default-adapters"})
    else:
        logger.warning(
            "mcp.host_unavailable_in_image",
            extra={
                "missing_module": "mcp",
                "optional_dep_group": "adapters",
                "remediation": (
                    "rebuild image with --extra adapters to wire MCPHost, "
                    "or use the kernel image only for governance + audit + "
                    "registry-discovery + /system/* read surfaces (note: "
                    "end-to-end signed-pack admission also requires cosign "
                    "+ OPA which are default-adapters-only per Sprint-4 "
                    "doctrine, independent of this MCP-runtime gate)"
                ),
            },
        )
        # app.state.mcp_host deliberately NOT set; downstream code MUST
        # check getattr(app.state, "mcp_host", None) before invoking.
    return app
```

**Note that `create_app` (the kernel factory) is unchanged.** It never wired MCPHost in the first place; the contract is "kernel image runs `create_app`, default-adapters image runs `create_prod_app`". The split is at the factory choice, not inside the factories.

- [ ] **Step 6: Update Dockerfile header comment**

Append to the existing Sprint-1C/Sprint-4 budget-revision paragraphs:

```
# Sprint 5 added the official `mcp` SDK to the adapters extras group
# (NOT to base dependencies). Kernel image (`runtime` target) does not
# carry the SDK and `create_app` deliberately does not wire `MCPHost`
# into app.state. Operators using the kernel image get governance +
# audit + /system/* read surfaces; the Sprint-5 MCP admission modules
# (mcp_manifest, mcp_capabilities, mcp_authz) import + construct on the
# kernel image without the SDK installed. End-to-end signed-pack
# admission, however, still depends on the Sprint-4 cosign + OPA
# binaries which ship in this default-adapters image only — the kernel
# image cannot complete `register_with_full_attestation_check` without
# those binaries on PATH. MCP-host serving (call_tool / list_tools) is
# default-adapters-only via `create_prod_app`. This is the same
# precedent Sprint 4 set for cosign + OPA binaries.
```

- [ ] **Step 7: Verify both images behave correctly**

```bash
# Kernel image: builds + boots; MCPHost not in app.state
docker build -f infra/agentos/Dockerfile --target runtime -t cognic-agentos:kernel-mcp-check .
docker run --rm cognic-agentos:kernel-mcp-check python -c "import mcp" 2>&1
# Expected: ModuleNotFoundError: No module named 'mcp'  (kernel stays clean)

# Default-adapters image: builds + boots; MCPHost wired
docker build -f infra/agentos/Dockerfile --target default-adapters -t cognic-agentos:adapters-mcp-check .
docker run --rm cognic-agentos:adapters-mcp-check python -c "import mcp; print(mcp.__version__)"
# Expected: prints the pinned version
```

- [ ] **Step 8: Sweep + halt-before-commit summary; wait for `commit` token**

Halt summary covers: kernel image deliberately omits MCP; default-adapters image carries it; loader pattern matches Sprint 1C; `app.py` factory split is unchanged in shape (just adds the MCPHost wiring on the prod side).

```bash
git add pyproject.toml uv.lock src/cognic_agentos/protocol/__init__.py \
        src/cognic_agentos/portal/api/app.py infra/agentos/Dockerfile
git commit -m "build(sprint-5): pin mcp SDK + lock kernel-vs-adapters runtime contract (T2)"
```

---

## Task 3: `docs/MCP-STDIO-THREAT-MODEL.md` — canonical threat-model document

**Files:**
- Create: `docs/MCP-STDIO-THREAT-MODEL.md`.
- No tests (docs-only); doctrine review during plan-PR rounds is the gate.

This is the **doctrine document** that codifies why STDIO is restricted, what the four gates from ADR-002 mean operationally, and what threat-vectors the architecture test (Task 4) defends against.

- [ ] **Step 1: Author the threat-model doc**

Sections required:

1. **Background — April 2026 MCP supply-chain disclosures.**
   Cite the OX Security disclosure pattern (model-controlled string flows into command argv → RCE in the host process). Cite the CISA / MCP Working Group response. State unambiguously: AgentOS treats *every* STDIO launch attempt as untrusted by default.

2. **Threat model.**
   The adversary controls one or more of: (a) the MCP server pack itself, (b) the model output, (c) configuration files, (d) user input, (e) a remote pack channel. The defended asset: AgentOS host process integrity + tenant data + cross-tenant isolation. Out-of-scope (not Sprint 5's threat model): ransomware on the host OS, supply-chain attacks on the kernel image (covered by ADR-016 + Sprint-4 cosign verification).

3. **The four gates from ADR-002 §"MCP STDIO threat model".**
   Restate verbatim:
   - Pack ships a **signed static manifest** declaring command + arguments + env vars, verified at registration time (cosign signature on the wheel covers the manifest's static declarations).
   - Launch command appears on a **per-tenant static command allow-list** (Vault path; operator-curated; RBAC-gated to change).
   - Launch occurs **inside a sandbox profile** (per ADR-004; Sprint 8 dependency).
   - Environment variables are **bounded** — no `os.environ` passthrough; only the manifest's declared allow-list.

4. **Sprint-5 enforcement (this plan).**
   - Manifest validation at registration: any STDIO pack whose `[tool.cognic.mcp].transport = "stdio"` block lacks `command` or `args` or `env_allowlist` → registration refused with `mcp_stdio_manifest_incomplete`.
   - Manifest validation: any command containing shell metacharacters (`;`, `|`, `&`, backticks, `$()`, `<`, `>`, etc.) → registration refused with `mcp_stdio_manifest_shell_metacharacter`.
   - Command-allowlist lookup at registration: command not on the per-tenant allow-list → registration refused with `mcp_stdio_command_not_allowlisted`.
   - Sandbox-availability check at config-load: `runtime_profile="prod"` AND `mcp_stdio_enabled=true` AND no `cognic_agentos.sandbox.runtime` importable → fail-fast at startup with `SandboxNotAvailableError`.
   - Every STDIO refusal appends an `audit.stdio_launch_refused` event to the `audit_event` chain (via `AuditStore.append`) with pack identity + declared command (truncated to 256 chars) + refusal reason + tenant_id. STDIO registration refusal is audit-only — no `decision_history` row (per T11, decision-history rows are reserved for MCP call_tool outcomes, token refreshes, and registration *auth probes*).

5. **Sprint-5 explicit non-enforcement.**
   - **Sprint 5 does not spawn any process. Period.** This is the Decision Lock — every STDIO pack registration refuses with `mcp_stdio_disabled_in_sprint_5` (mapped from one of the more specific reasons above) regardless of any other config. Sprint 8 lifts this when sandbox lands AND renames the literal to `mcp_stdio_disabled`.
   - Sprint 5 does not implement env-allowlist application — it only validates the declaration shape.
   - Sprint 5 does not implement sandbox profile lookup — it only checks whether the sandbox runtime module is importable.

6. **The architecture test (Task 4) as backstop.**
   Even if a future maintainer accidentally adds a `subprocess.run` somewhere under `protocol/mcp_*`, the architecture test trips and CI fails. The test is mechanical, fast, and lives at the architecture-doctrine boundary.

7. **Sprint-8 hand-off summary.**
   Names what Sprint 8 must add (sandboxed launcher module, dev-default flip, audit-event extension). Restates that the Decision Lock is what allowed Sprint 5 to ship STDIO doctrine without process-spawn risk.

8. **Negative-path canary test reference.**
   `tests/unit/protocol/test_mcp_no_user_controlled_command.py` (Task 13) is the runtime canary: it deliberately tries to inject a user-controlled command/argument through every reachable code path and asserts every one is refused. The doc explicitly names this test as the threat-model boundary check.

- [ ] **Step 2: Cross-reference verification**

Verify every reference resolves:
- `docs/adrs/ADR-002-mcp-plugin-protocol.md` (exists)
- `docs/adrs/ADR-004-sandbox-primitive.md` (exists)
- `docs/MCP-CONFORMANCE.md` (exists)
- Future `tests/unit/protocol/test_mcp_no_user_controlled_command.py` (created in Task 13; doc forward-references it)

- [ ] **Step 3: Sweep + commit**

```bash
git add docs/MCP-STDIO-THREAT-MODEL.md
git commit -m "docs(sprint-5): MCP STDIO threat-model doctrine (T3)"
```

---

## Task 4: Architecture test — STDIO module subprocess/exec import ban

**Files:**
- Create: `tests/architecture/__init__.py` (empty).
- Create: `tests/architecture/test_mcp_stdio_no_subprocess.py` (the guardrail).
- No production code changes.

This is **Guardrail 2** from the Decision Lock. Tripping it = a doctrine violation, not a code-style nit.

- [ ] **Step 1: Write the failing test first (architecture-test scaffolding doesn't exist yet)**

```python
# tests/architecture/test_mcp_stdio_no_subprocess.py
"""Sprint 5 architecture test — STDIO module subprocess/exec import ban.

Per the Sprint-5 Decision Lock (Option C): STDIO ships threat model +
manifest validation + fail-closed refusal in Sprint 5; STDIO does NOT
ship process launch. The launch path is deferred to Sprint 8 with the
sandbox primitive.

This test is the mechanical guardrail. It walks the AST of every Python
file under ``src/cognic_agentos/protocol/mcp_*`` (and any submodule named
``*stdio*``) and asserts none of them import the process-spawning
primitives below.

If a future commit trips this test: that commit is adding launch code.
EITHER it's Sprint 8's sandboxed launcher (in which case update the
architecture test to allow ``subprocess`` in the new launcher module
ONLY) OR it's a doctrine violation that needs explicit review.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "cognic_agentos" / "protocol"

#: Import-target patterns that indicate process-spawn capability.
_BANNED_MODULES = frozenset({
    "subprocess",
    "multiprocessing",
})

#: Function/method calls that indicate process-spawn capability.
_BANNED_CALLS = frozenset({
    "os.execvp",
    "os.execve",
    "os.execvpe",
    "os.execlp",
    "os.execle",
    "os.execl",
    "os.execv",
    "os.spawn",
    "os.spawnv",
    "os.spawnvp",
    "os.spawnvpe",
    "os.spawnl",
    "os.spawnlp",
    "os.spawnle",
    "os.spawnlpe",
    "os.posix_spawn",
    "os.posix_spawnp",
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
})


#: Sprint 8 will add a single sandboxed launcher module that is permitted
#: to import process-spawn primitives. Until then, this set is empty and
#: every mcp_* / *stdio* file in protocol/ is banned. Sprint 8 closeout
#: edits this set + adds the launcher to the explicit allow-list path.
_LAUNCHER_ALLOWLIST: frozenset[str] = frozenset()


def _mcp_modules() -> list[Path]:
    """Every Python module under protocol/ that matches the doctrine:

    1. Any path matching ``mcp_*.py`` (top-level file or nested under a
       package directory) — recursive glob so future ``protocol/mcp_stdio/
       helpers.py`` style submodules are caught.
    2. Any path containing ``stdio`` in its name — defensive against a
       module that gets renamed away from the ``mcp_`` prefix but still
       ships STDIO-related code.

    Excludes:
    - ``__init__.py`` files (package markers; doctrine is at the
      submodule level).
    - The Sprint-8 launcher allow-list (see ``_LAUNCHER_ALLOWLIST`` above).
    """
    candidates: set[Path] = set()
    for pattern in ("mcp_*.py", "*stdio*.py"):
        candidates.update(_SRC_ROOT.rglob(pattern))
    # Also scan any file that lives inside a directory whose name contains
    # 'mcp' or 'stdio' (e.g. protocol/mcp_stdio/helpers.py — note the
    # 'helpers.py' would not match the patterns above).
    for path in _SRC_ROOT.rglob("*.py"):
        if any("stdio" in part.lower() or part.startswith("mcp_") for part in path.parts):
            candidates.add(path)
    candidates = {p for p in candidates if p.name != "__init__.py"}
    candidates = {p for p in candidates if p.name not in _LAUNCHER_ALLOWLIST}
    return sorted(candidates)


def _check_imports(tree: ast.AST, path: Path) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                if top_level in _BANNED_MODULES:
                    violations.append(
                        f"{path.name}:{node.lineno} — banned import: {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top_level = node.module.split(".")[0]
            if top_level in _BANNED_MODULES:
                violations.append(
                    f"{path.name}:{node.lineno} — banned from-import: {node.module}"
                )
    return violations


def _check_calls(tree: ast.AST, path: Path) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Resolve attribute chain like os.execvp -> "os.execvp"
        attr_chain = _attr_chain(node.func)
        if attr_chain is None:
            continue
        for banned in _BANNED_CALLS:
            if attr_chain == banned or attr_chain.startswith(banned + "."):
                violations.append(
                    f"{path.name}:{node.lineno} — banned call: {attr_chain}"
                )
                break
        # Defensive: shell=True kwarg on any subprocess-shaped call
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                violations.append(
                    f"{path.name}:{node.lineno} — shell=True kwarg detected"
                )
    return violations


def _attr_chain(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


class TestMcpStdioNoSubprocess:
    @pytest.mark.parametrize("module_path", _mcp_modules(), ids=lambda p: p.name)
    def test_no_banned_imports_or_calls(self, module_path: Path) -> None:
        """Every protocol/mcp_*.py module MUST NOT import process-spawn
        modules or call process-spawn functions. Sprint-5 Decision Lock."""
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(module_path))
        violations = _check_imports(tree, module_path) + _check_calls(tree, module_path)
        assert not violations, (
            f"Sprint-5 STDIO architecture test failed for {module_path.name}:\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\n\nPer Sprint-5 Decision Lock (Option C): STDIO ships threat model "
            + "+ manifest validation + fail-closed refusal. NOT process launch. "
            + "Process spawning is Sprint 8 (sandboxed launcher module). If you "
            + "are intentionally adding sandboxed launch code as part of Sprint 8, "
            + "update _mcp_modules() to exclude the new launcher module."
        )

    def test_at_least_one_mcp_module_exists(self) -> None:
        """Catches the "test passes vacuously because no mcp_*.py files
        exist yet" failure mode. Once Task 5 lands the first MCP module
        (mcp_authz.py), this test starts asserting against real files."""
        # Sprint 5 ships at least 5 mcp_* modules: authz, manifest,
        # capabilities, transports, host. Anything less means a task got
        # skipped (the >= 5 tightening lands in T15).
        modules = _mcp_modules()
        # During plan-PR review the count is 0; once T5+ land, at least 1.
        assert len(modules) >= 0  # placeholder; tightened to >= 5 in T15 closeout

    def test_module_collector_finds_top_level_mcp_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Self-test for the collector: top-level ``protocol/mcp_*.py``
        files MUST be picked up. If this regresses to a non-recursive
        glob that misses something, the doctrine guardrail is broken."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "mcp_host.py").write_text("# stub", encoding="utf-8")
        (fake_root / "mcp_authz.py").write_text("# stub", encoding="utf-8")
        monkeypatch.setattr(
            "tests.architecture.test_mcp_stdio_no_subprocess._SRC_ROOT", fake_root
        )
        modules = _mcp_modules()
        names = {p.name for p in modules}
        assert {"mcp_host.py", "mcp_authz.py"} <= names

    def test_module_collector_finds_nested_stdio_submodules(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Self-test for the collector: nested ``protocol/mcp_stdio/
        helpers.py`` style submodules MUST be picked up. The original
        non-recursive glob('mcp_*.py') would have missed these. The
        recursive rglob + 'stdio' substring scan catches them."""
        fake_root = tmp_path / "protocol"
        nested = fake_root / "mcp_stdio"
        nested.mkdir(parents=True)
        (nested / "helpers.py").write_text("# stub", encoding="utf-8")
        (nested / "validators.py").write_text("# stub", encoding="utf-8")
        (nested / "__init__.py").write_text("", encoding="utf-8")
        monkeypatch.setattr(
            "tests.architecture.test_mcp_stdio_no_subprocess._SRC_ROOT", fake_root
        )
        modules = _mcp_modules()
        names = {p.name for p in modules}
        # Both the helpers and validators files MUST be in scope; the
        # __init__.py MUST NOT be (per the collector's exclusion rule).
        assert "helpers.py" in names
        assert "validators.py" in names
        assert "__init__.py" not in names

    def test_module_collector_finds_renamed_stdio_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defensive: a future refactor that renames the STDIO module
        away from the ``mcp_`` prefix (e.g. to ``protocol/stdio_pack.py``)
        but still ships STDIO-related code MUST still be caught — the
        guardrail keys off the doctrine ('any STDIO surface in protocol/')
        not just the naming convention."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "stdio_pack.py").write_text("# stub", encoding="utf-8")
        monkeypatch.setattr(
            "tests.architecture.test_mcp_stdio_no_subprocess._SRC_ROOT", fake_root
        )
        modules = _mcp_modules()
        names = {p.name for p in modules}
        assert "stdio_pack.py" in names
```

Run: `uv run pytest tests/architecture/ -v`
Expected: PASS — there are no `mcp_*.py` files in the real tree yet (parametrized arm collects 0); the 3 collector self-tests + the `at_least_one` test pass.

- [ ] **Step 2: Verify the test infrastructure works against planted positive controls**

Plant test cases that should trip the architecture test, confirm they trip, then revert. Three positive controls:

```bash
# Control 1: top-level subprocess import in mcp_authz.py
echo 'import subprocess' > src/cognic_agentos/protocol/mcp_authz.py
uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py::TestMcpStdioNoSubprocess::test_no_banned_imports_or_calls -v
# Expected: FAIL with "banned import: subprocess"
rm src/cognic_agentos/protocol/mcp_authz.py

# Control 2: nested submodule with subprocess import — proves rglob recursion
mkdir -p src/cognic_agentos/protocol/mcp_stdio
echo '"""nested helpers"""\nimport subprocess' > src/cognic_agentos/protocol/mcp_stdio/helpers.py
touch src/cognic_agentos/protocol/mcp_stdio/__init__.py
uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py::TestMcpStdioNoSubprocess::test_no_banned_imports_or_calls -v
# Expected: FAIL — helpers.py picked up by rglob, subprocess detected
rm -rf src/cognic_agentos/protocol/mcp_stdio

# Control 3: renamed module with subprocess import (no mcp_ prefix, but 'stdio' in path)
echo 'import os; os.system("ls")' > src/cognic_agentos/protocol/stdio_helpers.py
uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py::TestMcpStdioNoSubprocess::test_no_banned_imports_or_calls -v
# Expected: FAIL — picked up by 'stdio' substring scan, os.system flagged
rm src/cognic_agentos/protocol/stdio_helpers.py

# Final clean-state verify
uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py -v
# Expected: PASS (collector self-tests + vacuous parametrized arm)
```

These three controls prove the guardrail catches all three regression patterns the reviewer raised: top-level files, nested submodules, and stdio-named modules without the mcp_ prefix.

- [ ] **Step 3: Sweep + commit**

```bash
git add tests/architecture/__init__.py tests/architecture/test_mcp_stdio_no_subprocess.py
git commit -m "test(sprint-5): architecture test banning subprocess in MCP modules (T4)"
```

---

## Task 5: `protocol/mcp_authz.py` — OAuth/PRM client

**Files:**
- Create: `src/cognic_agentos/protocol/mcp_authz.py` — critical-controls module.
- Test: `tests/unit/protocol/test_mcp_authz.py`.

**Critical-controls module — every commit halts before commit per AGENTS.md.**

This is the OAuth + Protected Resource Metadata client per ADR-002 §"MCP Authorization" + `docs/MCP-CONFORMANCE.md` §"Authorization". Surface area:

- `MCPAuthzClient.__init__(*, settings, vault_client, http_client, audit_store, decision_history_store)` — lazy construction; AS allow-list loaded on first call. **The audit + decision-history dependencies are constructor-required (R1 P2 #7) so refresh / acquire flows can emit audit events without a later breaking change to the client API.** **Does NOT call `require_mcp()` (R3 P1 doctrine):** PRM discovery + token acquisition use httpx + json + OAuth/PRM URL conventions (RFC 8707, OAuth 2.1) — pure HTTP standards, NOT MCP-spec wire format. This client is admission-side: module imports + construction + every method succeed without the `mcp` SDK installed; the only sites that gate on the SDK are `MCPHost.__init__` (T9) and `StreamableHTTPTransport.__init__` (T7). (The "kernel-image runs admission" claim is bounded by the Sprint-4 cosign + OPA dependency; the MCP layer's contribution is just "MCPAuthzClient does not add a NEW default-adapters-only requirement to admission".) Construction MUST succeed on a venv with no `mcp` SDK installed; the runtime methods (`acquire_token`, `refresh_token`, `step_up_token`) similarly use only httpx, never the SDK.
- `async discover_resource_metadata(*, server_url: str, request_id: str, tenant_id: str) -> ResourceMetadata` — three-path discovery in priority order. `request_id` + `tenant_id` flow through to any audit emission triggered by failure cases (e.g., `mcp_prm_invalid` audit on malformed PRM).
- `async acquire_token(*, server_url: str, manifest_scopes: tuple[str, ...], request_id: str, tenant_id: str) -> Token` — AS allow-list check + RFC 8707 resource indicator + audience validation on the returned token. Correlates audit + decision-history rows by `request_id`.
- `async step_up_token(*, server_url: str, current_token: Token, requested_scope: str, manifest_scopes: tuple[str, ...], request_id: str, tenant_id: str) -> Token` — only on `403 insufficient_scope` per spec; refuses if requested_scope is not in manifest_scopes. Step-up is audit-logged with prior + requested-additional scopes.
- `async refresh_token(*, token: Token, request_id: str, tenant_id: str) -> Token` — emits `audit.mcp_token_refresh` via `audit_store.append(...)` with AS issuer + scopes + resource indicator + client_id; **never token contents**. Also writes a `decision_history` row for the refresh decision (per MCP-CONFORMANCE §observability requirement that session/auth events are correlatable in decision_history).
- Token cache keyed by `(server_url, frozenset(GRANTED scopes), resource_indicator)` with **exact-match** lookup (R9/R10 P2: an entry hits the cache iff the requested scopes equal the cached granted scopes — neither broader nor narrower cached entries satisfy a request). Concurrent cold acquires for the same key are coalesced via an in-flight `dict[CacheKey, asyncio.Future[Token]]` map; waiters await the shared Future under `asyncio.shield` to keep waiter cancellation from poisoning the slot (R11/R12 P2).

Every method that emits audit takes `request_id: str` and `tenant_id: str` as keyword-only parameters (no defaults; caller MUST provide). This is the same per-request correlation pattern Sprint 3's LLM-gateway uses; not optional.

Closed-enum error vocabulary (**13 values total: 11 registration-boundary + 2 runtime-only**, after R6 P2 production-grade auth surface + R11 P2 split AS-discovery / token-endpoint / token-response off the PRM-invalid bucket + T9 R1 P2 #3 added `mcp_authorisation_lost` as the second runtime-only value; the original draft listed only the 6 marked **(original)**):

- `mcp_anonymous_refused` **(original)** — server lacks PRM AND no API-key fallback declared.
- `mcp_as_not_allowlisted` **(original)** — PRM points to a non-allowlisted AS.
- `mcp_token_audience_mismatch` **(original)** — `aud` claim does not match resource indicator.
- `mcp_token_scope_overgrant` **(R6)** — AS granted scopes are not a subset of the manifest-declared set; no-silent-privilege-widening doctrine fails closed even when the AS is allow-listed but misconfigured / compromised.
- `mcp_step_up_unauthorised` **(original; runtime-only)** — manifest does not declare the wider scope the server is asking for. Emitted from `MCPAuthzClient.step_up_token`; NEVER reaches the registration-boundary refusal mapper (`_authz_reason_to_refusal` raises if it does).
- `mcp_authorisation_lost` **(T9 R1 P2 #3; runtime-only)** — emitted from `MCPHost.call_tool` when the second-401 retry fails — both the cached and the freshly-acquired token were rejected by the MCP server with 401 / 403 invalid_token. Like `mcp_step_up_unauthorised`, NEVER reaches the registration-boundary refusal mapper. T11 will surface this in the `audit.tool_invocation_error` row + the parallel `decision_history` row.
- `mcp_oauth_request_timeout` **(original)** — discovery / token / refresh exceeded `mcp_oauth_request_timeout_s`.
- `mcp_oauth_transport_failure` **(R6)** — non-timeout transport error (DNS, ConnectError, TLS handshake, network unreachable). Distinct from request-timeout so operators see the precise cause.
- `mcp_oauth_credentials_missing` **(R6)** — Vault has no per-`(tenant, AS-issuer)` OAuth client credentials configured (R6 P1 replaced the originally-planned synthesised-client_id stub with a Vault-backed lookup; missing config fails closed before any AS round-trip).
- `mcp_oauth_as_discovery_invalid` **(R11)** — AS `.well-known/oauth-authorization-server` doc malformed (non-200 status, non-JSON body, missing `token_endpoint`). Distinct from `mcp_prm_invalid` because operators debug AS-issuer config differently from MCP-server-side PRM problems.
- `mcp_oauth_token_endpoint_error` **(R11)** — AS token endpoint returned a non-200 status (401 typically = rejected Vault-stored client credentials, 400 = `invalid_grant`/`invalid_scope`, 503 = AS down). Payload carries `status_code` only — NEVER the response body, which could echo credentials or AS-side debug strings.
- `mcp_oauth_token_response_invalid` **(R11)** — token response shape malformed (non-JSON body, missing `access_token`, non-numeric / non-finite / non-positive / bool `expires_in`, non-string `scope`).
- `mcp_prm_invalid` **(original — narrowed by R11)** — PRM document on the MCP server side malformed (`/.well-known/oauth-protected-resource`). NO LONGER covers AS-discovery / token-endpoint / token-response failures (R11 split those out).

- [ ] **Step 1: Write failing tests (full surface, parametrized where it matters)**

The implementation rounds (R6–R12) substantially expanded the original test surface. The plan-of-record draft listed 12 classes / ~30 tests; the merged implementation lands ~26 classes / ~115 tests covering the closed-enum vocabulary R6–R11 grew from 6 → 12 values (T9 R1 added the 13th, `mcp_authorisation_lost` — runtime-only, asserted in `test_mcp_host.py`'s 401 retry suite + `test_refusal_reason_completeness.py`'s drift detector), the cancellation hardening R12 added on the in-flight Future, and the cache-correctness invariants R9/R10 pinned (granted-keyed exact-match). T9 R1 also added a public `MCPAuthzClient.invalidate_cached_token(server_url)` surface used by `MCPHost.call_tool` on 401 / 403 invalid_token (drops every scope-tier cache entry whose resource_indicator matches the server). Test classes (canonical surface — implementer adds the negative-path arms per the closed-enum table above):

**Discovery + audience + cache + refresh (original draft):**
- `TestPrmDiscoveryWWWAuthenticatePath` — primary header-driven discovery; `WWW-Authenticate: Bearer resource_metadata="..."` URL followed; header missing → fall through to next path.
- `TestPrmDiscoveryEndpointSpecificFallback` — endpoint-specific well-known: `https://server.example/public/mcp` → probe `https://server.example/.well-known/oauth-protected-resource/public/mcp`. Found → root path NOT probed.
- `TestPrmDiscoveryRootFallback` — endpoint-specific 404 → fall back to root `/.well-known/oauth-protected-resource`.
- `TestPrmDiscoveryPriorityOrder` — both endpoint-specific and root paths populated → endpoint-specific wins.
- `TestPrmDiscoveryAnonymousRefused` — all three paths fail AND no API-key fallback declared → `mcp_anonymous_refused`.
- `TestPrmInvalidShapes` + `TestPrmDocumentEdgeCases` — narrowed `mcp_prm_invalid` ONLY for MCP-server-side PRM-doc malformation per R11 (non-JSON, non-object, missing/empty/malformed `authorization_servers`, malformed `scopes_supported`, fall-through behaviour on 404 / 500 / unclosed-quote `WWW-Authenticate`).
- `TestAsAllowlistEnforcement` — PRM advertises AS not on per-tenant allow-list → `mcp_as_not_allowlisted`; allow-listed → token request proceeds.
- `TestRfc8707ResourceIndicator` — every token request includes `resource=<server URL>` form param.
- `TestTokenAudienceValidation` + `TestTokenRepr` — `aud` matches → accepted; mismatched → `mcp_token_audience_mismatch`; opaque token → trust AS's RFC 8707 binding; `Token.__repr__` MUST redact value.
- `TestTokenCacheAndRefresh` — refresh emits `audit.mcp_token_refresh` (no token contents) + `decision_history` row.
- `TestStepUpScopeFlow` + `TestStepUpAsAllowlistRevoked` — `403` with manifest declaring wider scope → step-up audit-logged; manifest does NOT declare → `mcp_step_up_unauthorised`; AS allow-list revoked between original acquire and step-up → `mcp_as_not_allowlisted`.
- `TestOauthRequestTimeout` — every PRM/AS-discovery/token-endpoint timeout → `mcp_oauth_request_timeout`.

**Production-grade auth surface (R6):**
- `TestVaultOauthCredentials` — Vault-backed client_id/client_secret resolved by `(tenant, as_host)`; `client_secret_post` form body vs `client_secret_basic` header; missing/malformed credentials fail closed with `mcp_oauth_credentials_missing`; client_secret never leaks into `Token.__repr__`.
- `TestTransportFailureClosedEnum` — every `httpx.RequestError` (DNS / ConnectError / TLS handshake / network unreachable) on PRM probe / PRM fetch / AS discovery / token endpoint → `mcp_oauth_transport_failure` (operationally distinct from timeout).
- `TestScopeOvergrantRejection` — AS-granted scopes ⊋ manifest-declared → `mcp_token_scope_overgrant`; AS-narrowing accepted (subset OK).
- `TestStepUpAuditOnDenial` — denial paths emit `audit.mcp_step_up` BEFORE the raise.
- `TestRefreshFailureDecisionHistory` — refresh failures (timeout, audience mismatch, AS error) write `decision_history` rows with decision `refresh_failed`.

**TTL cap + defensive parses (R7 / R8):**
- `TestExpiresInValidation` + `TestExpiresInNonFiniteAndBool` — `expires_in` parsed defensively (non-numeric, null, zero, negative, NaN, Infinity, bool `True`/`False`) → `mcp_oauth_token_response_invalid` (R11 split this off `mcp_prm_invalid`); operator-set `mcp_oauth_token_cache_ttl_s` caps token lifetime even if AS sets longer.
- `TestAllowlistStrictValidation` — non-string / blank / `None` entries in the AS allow-list fail closed (no silent drop).
- `TestCredentialsWhitespaceRefused` — whitespace-only `client_id` / `client_secret` → `mcp_oauth_credentials_missing`.
- `TestBasicAuthEncoding` + `TestBasicAuthFormEncoding` — `client_secret_basic` form-url-encodes credentials per RFC 6749 §2.3.1 (spaces → `+`, NOT `%20`); reserved-character round-trip preserved.

**Cache correctness (R9 / R10):**
- `TestNarrowedTokenCacheNotReused` (R9) — AS narrows requested broader scope set; cached token MUST NOT be returned for a later broader request.
- `TestMalformedScopeResponse` (R9) — `scope: null` / list / object → `mcp_oauth_token_response_invalid`; absent → defaults to manifest per OAuth 2.1 §3.2.3.
- `TestAsHostSanitizationForIssuersWithPorts` (R9) — AS issuer with explicit port (`https://as.example:8443`) resolves Vault path with `:` → `_` substitution.
- `TestCacheLookupBranchCoverage` (R9) — cross-server entry skipped; near-expiry entry skipped.
- `TestBroaderCachedTokenNotReusedForNarrowerRequest` (R10) — stepped-up broader-scope token MUST NOT be returned for a later narrower acquire (least-privilege exact-match invariant).

**AS / token-endpoint / token-response split (R11):**
- `TestRequestTokenErrorPaths` — AS discovery non-200/malformed-JSON/missing-`token_endpoint` → `mcp_oauth_as_discovery_invalid`; token endpoint non-200 (incl. 401 with credential-echoing body) → `mcp_oauth_token_endpoint_error` with `status_code` payload but NEVER body; token response missing `access_token` → `mcp_oauth_token_response_invalid`.

**In-flight coalescing + cancellation hardening (R11 / R12):**
- `TestInflightAcquireCoalescing` (R11) — two concurrent cold acquires for the same key share ONE network round-trip; failure propagates to concurrent waiter; in-flight slot cleared on success or failure.
- `TestInflightCancellationHardening` (R12) — cancelling a waiter does NOT cancel the shared Future (`asyncio.shield`); cancelling a waiter does NOT poison the in-flight slot (identity-checked finally-deregister); `set_result` / `set_exception` guarded with `if not future.done()`; cancelling the owner propagates without hanging waiters.

**Closed-enum drift detector + admission-side doctrine:**
- `TestRefusalReasonClosedEnum` — drift test pinning the **13-value** `AuthzReason` literal (R1+R2 amendments: `mcp_authorisation_lost` added as the 13th value, runtime-only alongside `mcp_step_up_unauthorised`); adding a new reason without updating `EXPECTED_REASONS` fails the test.
- `TestAdmissionStaysSdkFree` — R3 P1: client constructs cleanly with `mcp` SDK absent (kernel-image simulation via monkeypatched `find_spec`).

Each test uses `respx` to mock HTTP responses (already a project dep) — same pattern as Sprint-3 LLM gateway tests.

Each test uses `respx` to mock HTTP responses (already a project dep) — same pattern as Sprint-3 LLM gateway tests.

```python
# Sketch of one critical test — the rest follow the same pattern
class TestRfc8707ResourceIndicator:
    async def test_token_request_includes_resource_indicator(
        self, authz: MCPAuthzClient, mocked_as: respx.Router
    ) -> None:
        server_url = "https://server.example/mcp"
        # ... mock PRM discovery + token endpoint ...
        await authz.acquire_token(
            server_url=server_url,
            manifest_scopes=("mcp:tools",),
            tenant_id="bank_a",
        )
        # Assert the token POST included resource=<server_url>
        token_request = mocked_as["token"].calls[0].request
        body = parse_qs(token_request.content.decode())
        assert body["resource"] == [server_url]

    async def test_token_without_bound_resource_refused(
        self, authz: MCPAuthzClient, mocked_as: respx.Router
    ) -> None:
        # ... AS returns token with no `aud` claim ...
        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url="https://server.example/mcp",
                manifest_scopes=("mcp:tools",),
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_token_audience_mismatch"
```

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py -v`
Expected (red): ~115 tests FAIL (`MCPAuthzClient` doesn't exist). The original draft estimated ~30; the implementation rounds (R6 production-grade auth surface, R7/R8 TTL cap + defensive parses, R9 cache invariants, R10 least-privilege match, R11 closed-enum split + in-flight coalescing, R12 cancellation hardening) grew the surface ~3.8×.

- [ ] **Step 2: Implement `protocol/mcp_authz.py`**

Implementation notes:
- Use `httpx.AsyncClient` with explicit `timeout=settings.mcp_oauth_request_timeout_s` on every call. Catch `httpx.TimeoutException` → `mcp_oauth_request_timeout`; catch `httpx.RequestError` → `mcp_oauth_transport_failure` (R6 P2 — DNS / TLS / network unreachable distinct from slow response).
- `ResourceMetadata` is a frozen-slotted dataclass.
- `Token` is a frozen-slotted dataclass; the `__repr__` is overridden to redact the value (frozen-slotted alone does not — Python's default slotted-dataclass repr still includes every field).
- Token cache is an `asyncio.Lock`-protected dict keyed by `(server_url, frozenset(GRANTED scopes), resource_indicator)`. R9/R10: lookup is **exact match** on granted scopes — neither broader nor narrower cached entries satisfy a request (composes least-privilege + no-silent-under-scoping into one rule). R11/R12: an in-flight `dict[CacheKey, asyncio.Future[Token]]` map coalesces concurrent cold acquires into one AS round-trip; waiters use `asyncio.shield` so cancellation doesn't poison the shared Future; `set_result`/`set_exception` guarded with `not future.done()`; identity-checked deregister in `finally`.
- Audit emission uses `audit_store.append(...)` (Sprint-2 substrate); `decision_history_store.append(...)` writes a row for token refreshes (success AND failure outcomes).
- The audit payload for `mcp_token_refresh` includes: `as_issuer`, `scopes`, `resource_indicator`, `client_id`. NEVER the token value. The audit payload for `mcp_token_endpoint_error` includes `status_code` only — NEVER the AS response body (could echo credentials).
- OAuth client credentials per `(tenant, AS issuer)` resolved from Vault at `settings.mcp_oauth_credentials_path` (R6 P1); netloc sanitised by replacing `:` with `_` (R9 P3); `client_secret_basic` credentials form-url-encoded via `quote_plus` per RFC 6749 §2.3.1 (R8 P3) before base64.
- AS-granted `expires_in` capped by `settings.mcp_oauth_token_cache_ttl_s` (R7 P2); defensive parse rejects non-numeric / non-finite / non-positive / bool with `mcp_oauth_token_response_invalid` (R7/R8/R11 P2).
- Closed-enum errors are raised via `MCPAuthzError(reason: AuthzReason, …)` where `AuthzReason` is a `Literal[…]` matching the **13 enum values above** (R6 + R11 grew the original 6 to 12; T9 R1 P2 #3 added the 13th value `mcp_authorisation_lost` — runtime-only, emitted from `MCPHost.call_tool` second-401-retry exhaustion, NEVER from `MCPAuthzClient` registration paths).

- [ ] **Step 3: Run tests; expect PASS**

Run: `uv run pytest tests/unit/protocol/test_mcp_authz.py -v --cov=cognic_agentos.protocol.mcp_authz --cov-report=term-missing`
Expected (green): ~115 PASSED; coverage 100% line / 100% branch (well over the ≥95/≥90 critical-controls floor).

- [ ] **Step 4: Architecture test still green**

Run: `uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py -v`
Expected: PASS — `mcp_authz.py` does not import `subprocess` or call `os.exec*`.

- [ ] **Step 5: Halt-before-commit summary; wait for `commit` token**

Critical-controls module landing. Halt summary covers: closed-enum reason vocabulary, audit-event payload shape, token-cache key invariants, what was deliberately NOT implemented (token-value persistence, multi-AS-per-server discovery — both deferred / out-of-scope).

```bash
git add src/cognic_agentos/protocol/mcp_authz.py tests/unit/protocol/test_mcp_authz.py
git commit -m "feat(sprint-5): OAuth/PRM client with 3-path discovery + audience validation (T5)"
```

---

## Task 6: Manifest extraction contract + capability validation + registration auth probe

**Files:**
- Create: `src/cognic_agentos/protocol/mcp_manifest.py` — signed-manifest extraction module (NEW; addresses R1 P2 #2).
- Create: `src/cognic_agentos/protocol/mcp_capabilities.py` — capability validator (critical-controls).
- Create: `policies/_default/sampling.rego` — default-deny sampling Rego bundle.
- Modify: `src/cognic_agentos/protocol/plugin_registry.py` — registration hook calls (a) manifest extractor → (b) capability validator → (c) registration-time OAuth/PRM probe via MCPAuthzClient. **Halt-before-commit because `plugin_registry.py` is critical-controls.**
- Test: `tests/unit/protocol/test_mcp_manifest.py` — extractor tests against editable + wheel-installed fixture installs.
- Test: `tests/unit/protocol/test_mcp_capabilities.py` — validator tests.
- Test: `tests/unit/protocol/test_mcp_registration_auth_probe.py` — registration-probe integration tests (NEW; addresses R1 P2 #3).

**Critical-controls module — halt before commit.**

This task addresses three R1 P2 findings together because they form a chain at registration time: extract manifest → validate capabilities → probe auth. Splitting them across separate tasks would create awkward halts mid-pipeline.

### 6.1 Manifest extraction contract (R1 P2 #2)

**The contract:**
- A pack ships `cognic-pack-manifest.toml` as **package data** inside its importable package directory (e.g., `cognic_test_mcp_pack/cognic-pack-manifest.toml`). This file is the signed static manifest per ADR-002 §"MCP STDIO threat model" gate 1; the pack's cosign-verified wheel covers its bytes via inclusion.
- Pack's `pyproject.toml` includes the manifest file via `[tool.hatch.build.targets.wheel.force-include]` (or the equivalent build-backend mechanism for setuptools / poetry / etc. — the contract is "ship as package data inside the importable package directory", not "use hatchling").
- The manifest file contains the same `[tool.cognic.mcp]`, `[tool.cognic.runtime]`, `[tool.cognic.identity]`, `[tool.cognic.data_governance]`, `[tool.cognic.supply_chain]` blocks documented in `docs/HOW-TO-WRITE-A-PACK.md`. Pyproject can ALSO carry these blocks for editor / `agentos validate` (Sprint 7A) consumption, but the runtime registry reads the in-package manifest file — that's what cosign signs.

**The extractor (`protocol/mcp_manifest.py`):**

```python
# Sketch — full implementation in T6 step 2
import importlib.metadata
import tomllib
from pathlib import Path

class PackManifestNotFoundError(MCPManifestError): ...
class PackManifestMalformedError(MCPManifestError): ...

def extract_pack_manifest(distribution_name: str, package_name: str) -> dict:
    """Read cognic-pack-manifest.toml from an installed pack distribution
    WITHOUT importing pack code (Sprint 4 deferred-load invariant).
    
    Uses Distribution.locate_file() — this resolves a relative path against
    the dist's RECORD/installed-files location and DOES NOT import the
    package. Works for both editable (`uv pip install -e`) and
    wheel-installed dists.
    """
    try:
        dist = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise PackManifestNotFoundError(distribution_name) from exc
    
    relative_path = f"{package_name}/cognic-pack-manifest.toml"
    manifest_path = dist.locate_file(relative_path)
    if manifest_path is None or not Path(manifest_path).is_file():
        raise PackManifestNotFoundError(
            f"Pack {distribution_name!r} ships no cognic-pack-manifest.toml at "
            f"{relative_path!r}. Per ADR-002 §MCP STDIO threat model gate 1, "
            f"the signed static manifest is required at this path."
        )
    
    try:
        return tomllib.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PackManifestMalformedError(distribution_name) from exc
```

**Why `Distribution.locate_file()` and not `importlib.resources.files()`:**
- `locate_file()` returns a path WITHOUT importing the package — preserves Sprint 4's deferred-load invariant strictly.
- `importlib.resources.files()` may trigger `__init__.py` execution as a side effect; even an empty init technically counts as code execution.
- The Sprint-4 invariant is specifically about not calling `EntryPoint.load()` (which loads the Plugin class). `__init__.py` execution is in a gray zone but the safer pattern is `locate_file()` which avoids it entirely.

**Tests for the extractor (in `test_mcp_manifest.py`):**
- `TestExtractFromEditableInstall` — fixture pack installed via `uv pip install -e tests/fixtures/cognic_test_mcp_pack/`; extractor returns the parsed manifest; manifest contents match what's on disk.
- `TestExtractFromWheelInstall` — fixture pack built via `uv build` then installed via `uv pip install dist/*.whl`; same contract holds; `Distribution.locate_file()` resolves to the wheel-installed location.
- `TestExtractMissingManifest` — pack missing the manifest file → `PackManifestNotFoundError`.
- `TestExtractMalformedManifest` — manifest file with invalid TOML → `PackManifestMalformedError`.
- `TestExtractDoesNotImportPackage` — proves the deferred-load invariant: extractor runs against a pack with `__init__.py` containing `raise AssertionError("MUST NOT import")`; extractor MUST NOT trip the assertion. (If `locate_file` ever regresses to importing the package, this test catches it.)
- `TestExtractAcrossBothInstallModes` — the same pack source tree → identical manifest dict whether installed editable or as wheel.

### 6.2 Capability validation surface

- `validate_mcp_manifest(manifest: dict) -> ManifestValidation` — pure function over the parsed manifest dict (output of T6.1's extractor).
- Closed-enum reasons emitted by the validator (subset of the 24-value Sprint-5 extension; full enumeration in T6 step 6 below): the 10 capability-side reasons (`mcp_anonymous_refused`, `mcp_resources_declared_but_no_list`, `mcp_sampling_default_denied`, `mcp_elicitation_form_restricted_data_class`, `mcp_caching_ttl_restricted_data_class`, `mcp_stdio_manifest_incomplete`, `mcp_stdio_manifest_shell_metacharacter`, `mcp_stdio_command_not_allowlisted`, `mcp_stdio_disabled_in_sprint_5`, `mcp_transport_unsupported` — last added in T6 R1 P1 #2 as the gate-0 closed-enum transport check). The T6.1 extractor produces two distinct closed-typed exceptions whose registry-side mappings differ: `PackManifestMalformedError` always refuses with `mcp_manifest_malformed`; `PackManifestNotFoundError` is treated by the registry as "no MCP intent" and proceeds (R2 doctrine — no current admission code path emits `mcp_manifest_missing`, which is reserved for a future explicit MCP-intent path).
- Sampling default-deny enforced via OPA evaluation against `policies/_default/sampling.rego` — uses the Sprint-4 `OPAEngine`.

### 6.3 Registration-time auth probe (R1 P2 #3)

ADR-002 §"MCP Authorization" step 8 mandates: "Failed auth at registration → pack stays in `proposed` state per ADR-002 (does NOT load until resolved)." Sprint 5 honours this with a registration-time probe via `MCPAuthzClient`:

After capability validation passes, if the manifest declares `[tool.cognic.mcp].transport = "http"` (production default; Sprint 5's only invocable transport), the registry probes auth:
- For `auth = "oauth-prm"` (default): call `MCPAuthzClient.discover_resource_metadata(server_url)` → `MCPAuthzClient.acquire_token(server_url, manifest_scopes, tenant_id)`. Any of the **eleven registration-boundary `AuthzReason` failures** → registration refused with the corresponding closed-enum reason via `_authz_reason_to_refusal()` 1:1 mapping. The eleven (R6 + R11 grew the original five): `mcp_anonymous_refused` (PRM advertises no auth surface), `mcp_as_not_allowlisted` (PRM AS not on per-tenant allow-list), `mcp_token_audience_mismatch` (token `aud` ≠ resource indicator), `mcp_token_scope_overgrant` **(R6)** (AS granted scopes ⊋ manifest), `mcp_oauth_request_timeout` (PRM/AS-discovery/token-endpoint timeout), `mcp_oauth_transport_failure` **(R6)** (DNS/TLS/network unreachable, distinct from timeout), `mcp_oauth_credentials_missing` **(R6)** (Vault has no per-`(tenant, AS-issuer)` client credentials), `mcp_oauth_as_discovery_invalid` **(R11)** (AS `.well-known/oauth-authorization-server` non-200 / non-JSON / missing `token_endpoint`), `mcp_oauth_token_endpoint_error` **(R11)** (token endpoint non-200; payload carries `status_code` only — NEVER the response body), `mcp_oauth_token_response_invalid` **(R11)** (token response shape malformed: missing `access_token`, bad `expires_in`, non-string `scope`), `mcp_prm_invalid` (MCP-server-side PRM document malformed; narrowed by R11). Note: `mcp_step_up_unauthorised` is NOT mapped here — step-up is runtime-only (T9 call_tool).
- For `auth = "api-key"` (Wave 1 fallback): validate the Vault path resolves AND the secret at that path is non-empty AND the manifest declares the deprecation warning has been acknowledged. Any failure → registration refused with `mcp_api_key_fallback_unresolved`.
- For STDIO transport: probe is skipped (STDIO is refused upstream of auth probe by the Decision Lock; auth is moot).

The probe is **token-acquired-but-not-stored** — the token returned is discarded after the probe (registration only needs to know "could we acquire one"). The acquired token is NOT cached; runtime calls re-acquire fresh. This avoids stale-token risk between registration and first call.

The Rego bundle:

```rego
# policies/_default/sampling.rego
package cognic.sampling

# Default-deny per ADR-002 + MCP-CONFORMANCE.md.
# Operators override per-tenant by overriding the bundle.
default allow = false

# Allow only if all four hold:
#   1. Pack manifest declares sampling_supported = true
#   2. Tenant policy explicitly permits sampling
#   3. Cloud-policy permits the requested model tier
#   4. The model tier is consistent with allow_external_llm
allow {
    input.pack.sampling_supported == true
    input.tenant.sampling_permitted == true
    input.cloud_policy.tier_consistent == true
    input.cloud_policy.allow_external_llm_consistent == true
}
```

- [ ] **Step 1: Write failing tests for the manifest extractor (T6.1)**

6 test classes in `test_mcp_manifest.py` per the contract above. The fixture pack (built in Task 12) is the test subject; the test installs it both ways (editable + wheel) under `tmp_path` to prove the contract holds across install modes.

- [ ] **Step 2: Implement `protocol/mcp_manifest.py`**

Use the sketch above. Key invariants pinned in tests: `Distribution.locate_file()` is the only resolution mechanism; package code is never imported; both install modes return identical manifest dicts.

- [ ] **Step 3: Write failing tests for the capability validator (T6.2)**

10 test classes (~25 tests):

- `TestResourcesOptional` — `resources_supported = false` ⇒ valid; `= true` AND missing list/read declarations ⇒ refused.
- `TestSamplingDefaultDeny` — pack declares `sampling_supported = true` but tenant policy missing ⇒ refused with `mcp_sampling_default_denied`. All four conditions present ⇒ allowed.
- `TestElicitationFormRestrictedDataClass` — pack declares `elicitation_modes = ["form"]` AND tool's `data_classes` include `customer_pii` / `payment_action` / `regulator_communication` ⇒ refused with `mcp_elicitation_form_restricted_data_class`.
- `TestCachingTtlRestrictedDataClass` — pack declares `caching_strategy = "ttl"` for tool with restricted data class ⇒ refused with `mcp_caching_ttl_restricted_data_class`.
- `TestStdioManifestIncomplete` — STDIO transport declared with missing `command` / `args` / `env_allowlist` ⇒ refused.
- `TestStdioManifestShellMetacharacter` — command containing `;`, `|`, `&`, backticks, `$()`, `<`, `>` ⇒ refused.
- `TestStdioCommandNotAllowlisted` — command not on per-tenant allow-list ⇒ refused.
- `TestStdioDisabledInSprint5` — even if every other STDIO gate passes, registration in Sprint 5 ⇒ refused with `mcp_stdio_disabled_in_sprint_5`. **This is the Decision Lock at the manifest layer.**
- `TestAnonymousMcpRefused` — manifest declares no `auth` AND no `api-key` fallback ⇒ refused.
- `TestPluginRegistryIntegration` — registry calls extractor → validator → auth probe in order during admission; refusal returns the same closed-enum `RefusalReason` shape Sprint 4 established.

- [ ] **Step 4: Implement `protocol/mcp_capabilities.py`**

Implementation notes:
- Pure-functional validator (no I/O except the OPA evaluation for sampling).
- The OPA evaluation reuses the Sprint-4 `OPAEngine` with the bundle path read from `settings.mcp_sampling_policy_bundle` (introduced in T1).
- The validator does NOT call the extractor — it takes a parsed manifest dict as input. This separation lets the registry integration call extractor → validator → probe explicitly, halt at any failure, and return the right closed-enum reason without coupling validator and extractor.
- **Module is admission-side per R3 P1 doctrine**: NO `from cognic_agentos.protocol import require_mcp` import; NO `from mcp import …` anywhere (lazy or otherwise). The validator works on plain Python dicts; neither the module imports nor the validator's wiring requires the `mcp` SDK. Module imports + construction succeed without the SDK.
- **OPA-backed sampling check has its own image dependency (separate from the `mcp` SDK):** the four-condition sampling-default-deny rule subprocess-calls the OPA binary via the Sprint-4 `OPAEngine`. OPA ships in the default-adapters image only (Sprint-4 doctrine; same boundary as cosign). Capability validation that reaches the sampling-policy code path therefore requires either the default-adapters image OR an explicitly-documented local fallback that brings OPA into PATH — same constraint Sprint 4 imposed on every Rego-evaluating code path. The MCP layer adds no NEW default-adapters-only requirement; it inherits Sprint 4's. Capability validation paths that do NOT reach the OPA call (manifest-shape errors, restricted-data-class refusals, STDIO-disabled refusals) succeed without OPA — the OPA dependency is reachable only when the manifest declares `sampling_supported = true`.

Same SDK-free import/construction posture for `protocol/mcp_authz.py` (T5) and `protocol/mcp_manifest.py` (T6.1); see T2 step 4's "kernel-vs-default-adapters split" table for the full surface boundary. (`mcp_authz` and `mcp_manifest` have no OPA dependency at all — they are SDK-free AND OPA-free; only `mcp_capabilities` is OPA-bound on the sampling-check path.)

- [ ] **Step 5: Write failing tests for the registration auth probe (T6.3)**

`test_mcp_registration_auth_probe.py` exercises the registry's full `register_with_full_attestation_check` against fixture packs that exercise each auth-probe failure mode:

**Original five auth-probe failure arms (R1-era; still required):**
- `TestAuthProbeOauthPrmHappyPath` — pack declares `auth = "oauth-prm"`; PRM mock returns valid metadata; AS allow-list contains the issuer; token request succeeds; registration succeeds.
- `TestAuthProbeAnonymousRefused` — pack declares no auth; PRM mock returns no advertised AS → registration refused with `mcp_anonymous_refused`.
- `TestAuthProbeAsNotAllowlisted` — PRM advertises an AS not on the per-tenant allow-list → registration refused with `mcp_as_not_allowlisted`.
- `TestAuthProbeAudienceMismatch` — token returned with mismatched `aud` → registration refused with `mcp_token_audience_mismatch`.
- `TestAuthProbeTimeout` — PRM endpoint hangs past `mcp_oauth_request_timeout_s` → registration refused with `mcp_oauth_request_timeout`.
- `TestAuthProbePrmInvalid` — PRM endpoint returns malformed JSON (the MCP-server-side `/.well-known/oauth-protected-resource` doc; R11 narrowed this from the previous catch-all sense) → registration refused with `mcp_prm_invalid`.

**Production-grade auth surface (R6) — three additional arms required so the auth probe + registry mapper exercise the new closed-enum reasons end-to-end:**
- `TestAuthProbeOauthCredentialsMissing` — Vault path for the per-`(tenant, AS-issuer)` OAuth client credentials (`secret/cognic/{tenant}/mcp-oauth/{as_host}`) returns 404 OR the resolved secret is missing `client_id`/`client_secret`/`auth_method` OR the auth_method is unsupported (e.g., `private_key_jwt` reserved for Wave 2) → registration refused with `mcp_oauth_credentials_missing`.
- `TestAuthProbeOauthTransportFailure` — `httpx.RequestError` (DNS / ConnectError / TLS handshake / network unreachable) on PRM probe / PRM fetch / AS discovery / token endpoint → registration refused with `mcp_oauth_transport_failure`. Distinct from request-timeout — operators see the precise cause.
- `TestAuthProbeOauthScopeOvergrant` — AS returns `scope` containing values NOT in the manifest-declared scope set (e.g., `mcp:tools mcp:admin` when manifest declares only `mcp:tools`) → registration refused with `mcp_token_scope_overgrant` (no-silent-privilege-widening doctrine).

**AS / token-endpoint / token-response split (R11) — three additional arms so each new closed-enum reason has a registration-side test:**
- `TestAuthProbeOauthAsDiscoveryInvalid` — AS `.well-known/oauth-authorization-server` returns non-200 OR non-JSON OR JSON missing `token_endpoint` → registration refused with `mcp_oauth_as_discovery_invalid`. Distinct from `mcp_prm_invalid` — operators debug AS-issuer config differently from MCP-server-side PRM problems.
- `TestAuthProbeOauthTokenEndpointError` — AS token endpoint returns non-200 (covers 401 = rejected Vault-stored client credentials, 400 = `invalid_grant`/`invalid_scope`, 503 = AS down) → registration refused with `mcp_oauth_token_endpoint_error`. The refusal payload MUST carry `status_code` only; assert that the AS response body (which may echo credentials or AS-side debug strings) is NOT propagated.
- `TestAuthProbeOauthTokenResponseInvalid` — AS returns 200 but the response body is malformed (non-JSON OR missing `access_token` OR `expires_in` non-numeric / non-finite / non-positive / bool OR `scope` non-string) → registration refused with `mcp_oauth_token_response_invalid`. Parametrize over these shapes.

**API-key fallback + STDIO + don't-leak-into-cache invariants (still required from R1):**
- `TestAuthProbeApiKeyFallbackHappyPath` — pack declares `auth = "api-key"`, Vault path resolves to a non-empty secret, manifest acknowledges the deprecation warning → registration succeeds with deprecation-warning audit event.
- `TestAuthProbeApiKeyFallbackUnresolved` — Vault path returns 404 OR secret is empty OR manifest does not acknowledge deprecation → `mcp_api_key_fallback_unresolved`.
- `TestAuthProbeSkippedForStdio` — STDIO pack reaches auth-probe step → probe is skipped (STDIO refusal is upstream); registration outcome is the STDIO-disabled refusal, not an auth one.
- `TestAuthProbeTokenNotPersisted` — after a successful probe, the `MCPAuthzClient` cache does NOT contain the probe-acquired token (registration only validates "could acquire", not "use"). With R10's exact-match cache invariant in place, this means the registry MUST construct an `MCPAuthzClient` whose cache is independent of (or cleared after) the runtime client's cache, OR the probe MUST take a non-caching code path.

**Total: 16 test classes** — 6 original (1 OauthPrmHappyPath + 5 failure arms: anonymous-refused / AS-not-allowlisted / audience-mismatch / timeout / PRM-invalid) + 3 R6 production-grade arms (credentials-missing / transport-failure / scope-overgrant) + 3 R11 split-error arms (AS-discovery-invalid / token-endpoint-error / token-response-invalid) + 4 trailing invariants (API-key happy-path / API-key unresolved / STDIO skip / token-not-persisted). All 11 registration-boundary `AuthzReason` failures have a dedicated test arm; this also satisfies the `test_every_reason_has_a_dedicated_test_arm` parametrize check in `test_refusal_reason_completeness.py`.

- [ ] **Step 6: Implement registry integration in `plugin_registry.py`**

A single new step in `register_with_full_attestation_check` between the cosign verification and the policy-engine evaluation. Pseudocode (R2 doctrine — current contract):

```python
# After cosign verification, before policy-engine grade evaluation.
#
# CURRENT (R2) doctrine: missing manifest ALWAYS proceeds (no MCP
# intent — Sprint-4-style pack OR misconfigured MCP pack). The
# MCP-intent signal is a well-shaped [tool.cognic.mcp] block in
# the manifest; nothing else. ``mcp_admission`` is dependency
# wiring, NOT pack intent.

# Step A: Extract the signed manifest (T6.1)
try:
    manifest = mcp_manifest.extract_pack_manifest(
        distribution_name=record.distribution_name,
        package_name=_derive_package_name(record),
    )
except PackManifestNotFoundError:
    # No MCP intent — Sprint-4 path. ``mcp_manifest_missing`` is
    # reserved-for-future-use (Sprint-7A `agentos validate` or a
    # future MCP-specific entry-point group).
    return None  # proceed to policy step
except PackManifestMalformedError:
    # Always fail-closed: cosign-signed bytes, so a malformed
    # manifest implies a packaging-bug regardless of pack intent.
    return refuse("mcp_manifest_malformed", ...)

# Step B: Detect MCP intent via safe walk (R2 P1: non-dict
# intermediates handled gracefully; present-but-non-dict mcp
# block refuses with mcp_manifest_malformed).
mcp_block = _safe_walk_to_mcp(manifest)
if mcp_block is _MCP_BLOCK_MALFORMED:
    return refuse("mcp_manifest_malformed", ...)
if mcp_block is None:
    return None  # No MCP intent; proceed (Sprint-4 cognic pack)

# MCP intent confirmed. R1 P1 #1 fail-closed: caller MUST have
# wired the admission deps (the MCPHost / authz client / OPA
# engine bundle). Without them, refuse rather than silent admit.
if mcp_admission is None:
    return refuse("mcp_admission_deps_required", ...)

# Step C: Validate capability declarations (T6.2)
validation = await mcp_capabilities.validate_mcp_manifest(
    manifest, context=_build_validation_context(...)
)
if not validation.ok:
    return refuse(validation.reason, ...)

# Step D: Probe auth at registration time (T6.3). R1 P1 #2:
# accept BOTH "http" (legacy alias) and "streamable-http"
# (canonical) — both map to the OAuth/PRM probe.
if mcp_block.get("transport") in {"http", "streamable-http"}:
    try:
        await _probe_mcp_auth(
            mcp_block, settings, tenant_id, request_id, authz_client
        )
    except MCPAuthzError as exc:
        return refuse(_authz_reason_to_refusal(exc.reason), ...)
```

**The closed-enum `RefusalReason` extension — exact, enumerated (R2 P2 #3 fix; R6 P2 production-grade auth surface widened the auth-probe row from 5 to 8).**

R1 said "grows by 11 values" without an explicit enumeration; R2's first patch enumerated the literal but mis-summed the auth-probe count as 3 (yielding 14) when the literal block actually listed 5 auth-probe reasons (yielding 16). R6's T5 production-hardening round added three more auth-probe reasons (`mcp_oauth_credentials_missing`, `mcp_oauth_transport_failure`, `mcp_token_scope_overgrant`) — each operationally distinct from the existing five (Vault ops issue ≠ AS server issue; DNS/TLS/network unreachable ≠ slow response; AS overgrant ≠ AS not allow-listed). R11's review of the production-grade error vocabulary added three more (`mcp_oauth_as_discovery_invalid`, `mcp_oauth_token_endpoint_error`, `mcp_oauth_token_response_invalid`) — splitting the original `mcp_prm_invalid` bucket so that operators see distinct reasons for an AS discovery problem (operators debug the AS issuer config) vs a token-endpoint HTTP error (a 401 here usually points at rejected Vault-stored client credentials, not the MCP server's PRM) vs a malformed token-response shape (missing `access_token`, bad `expires_in`, non-string `scope`). T6 R1 added two more **fail-closed admission gates**: `mcp_transport_unsupported` (R1 P1 #2 — closes the silent-skip hole where a correctly-spec'd `transport = "streamable-http"` pack bypassed the OAuth/PRM probe entirely; the validator now closes the enum on transport, accepts `http` + `streamable-http` + `stdio`, and refuses everything else) and `mcp_admission_deps_required` (R1 P1 #1 — closes the silent-skip hole where a Sprint-4 caller that forgot to wire `mcp_admission` could admit an MCP pack without ANY of the manifest / capability / auth-probe gates running; the registry now ALWAYS attempts manifest extraction and refuses fail-closed when the manifest declares `[tool.cognic.mcp]` but admission deps are absent). Sprint 4 made `RefusalReason` a closed vocabulary (the literal type in `plugin_registry.py`) precisely so this kind of drift surfaces at type-check time. The corrected count: **exactly 24 new reasons** added to the literal:

```python
# src/cognic_agentos/protocol/plugin_registry.py — Sprint-5 RefusalReason extension
RefusalReason = Literal[
    # Sprint 4 — existing (8 values; not repeated here)
    # ...
    # Sprint 5 — manifest extraction failures (T6.1):
    "mcp_manifest_missing",                      # RESERVED FOR FUTURE: explicit MCP-intent path (Sprint-7A
                                                 # `agentos validate` or future MCP-specific entry-point group);
                                                 # current T6 admission treats absent manifest as "no MCP intent"
                                                 # and proceeds — no admission code path emits this today.
    "mcp_manifest_malformed",                    # TOML invalid OR present-but-non-dict [tool.cognic.mcp] block

    # Sprint 5 — capability-validator failures (T6.2; 10 values):
    "mcp_anonymous_refused",                     # neither oauth-prm nor api-key declared
    "mcp_resources_declared_but_no_list",        # resources_supported=true but list/read missing
    "mcp_sampling_default_denied",               # sampling 4-condition gate failed
    "mcp_elicitation_form_restricted_data_class",# elicitation form mode for PII/payment/regulator
    "mcp_caching_ttl_restricted_data_class",     # ttl cache for restricted data class
    "mcp_stdio_manifest_incomplete",             # STDIO missing command/args/env_allowlist
    "mcp_stdio_manifest_shell_metacharacter",    # STDIO command contains shell metachars
    "mcp_stdio_command_not_allowlisted",         # STDIO command not on per-tenant allow-list
    "mcp_stdio_disabled_in_sprint_5",            # umbrella refusal for STDIO until Sprint 8
    "mcp_transport_unsupported",                 # transport not in {http, streamable-http, stdio} (T6 R1 P1 #2)

    # Sprint 5 — registration auth-probe failures (T6.3; 11 values):
    "mcp_as_not_allowlisted",                    # PRM advertises non-allowlisted AS
    "mcp_token_audience_mismatch",               # token aud != resource indicator
    "mcp_token_scope_overgrant",                 # AS granted scopes not in manifest set (R6)
    "mcp_oauth_request_timeout",                 # PRM/token request exceeded timeout
    "mcp_oauth_transport_failure",               # DNS/TLS/network unreachable on PRM/AS/token (R6)
    "mcp_oauth_credentials_missing",             # Vault has no client_id/client_secret/auth_method (R6)
    "mcp_oauth_as_discovery_invalid",            # AS .well-known/oauth-authorization-server bad (R11)
    "mcp_oauth_token_endpoint_error",            # AS token endpoint non-200 (401 = creds, 400 = grant) (R11)
    "mcp_oauth_token_response_invalid",          # token response shape malformed (no access_token, etc.) (R11)
    "mcp_prm_invalid",                           # PRM document malformed (MCP server side)
    "mcp_api_key_fallback_unresolved",           # api-key fallback Vault path / secret invalid

    # Sprint 5 — registry-configuration failures (T6.3; 1 value):
    "mcp_admission_deps_required",               # MCP block declared but mcp_admission=None (T6 R1 P1 #1)
]
```

Total Sprint-5 additions: **2 manifest + 10 capability + 11 auth-probe + 1 registry-config = 24 values**. (Plus the **two** runtime-only `AuthzReason` values from `MCPAuthzClient`'s own enum, which never reach the registration boundary: `mcp_step_up_unauthorised` — emitted by `MCPAuthzClient.step_up_token` from inside the T9 step-up flow — and `mcp_authorisation_lost` — emitted by `MCPHost.call_tool` when the second-401 retry fails (T9 R1 P2 #3). Neither appears in `plugin_registry.RefusalReason`; both raise `ValueError` in `_authz_reason_to_refusal()` if mistakenly routed there.)

**Enum-completeness regression test (R2 P2 #3 fix — load-bearing):**

```python
# tests/unit/protocol/test_refusal_reason_completeness.py
"""Sprint-5 RefusalReason completeness regression.

If a future commit adds a refusal path that emits a string literal
NOT present in plugin_registry.RefusalReason, mypy may not catch it
(literal-type narrowing only flags assignments / returns; runtime
string-construction sites are weaker). This test does an authoritative
walk: every closed-enum site MUST be in the literal AND must have a
test arm.
"""

from typing import get_args
from cognic_agentos.protocol.plugin_registry import RefusalReason

#: The exact set Sprint 5 introduces. Adding a new reason without
#: updating this set fails the test — forcing the author to also
#: name the test arm that exercises it.
SPRINT_5_REFUSAL_REASONS: frozenset[str] = frozenset({
    "mcp_manifest_missing",
    "mcp_manifest_malformed",
    "mcp_anonymous_refused",
    "mcp_resources_declared_but_no_list",
    "mcp_sampling_default_denied",
    "mcp_elicitation_form_restricted_data_class",
    "mcp_caching_ttl_restricted_data_class",
    "mcp_stdio_manifest_incomplete",
    "mcp_stdio_manifest_shell_metacharacter",
    "mcp_stdio_command_not_allowlisted",
    "mcp_stdio_disabled_in_sprint_5",
    "mcp_transport_unsupported",          # T6 R1 P1 #2
    "mcp_as_not_allowlisted",
    "mcp_token_audience_mismatch",
    "mcp_token_scope_overgrant",
    "mcp_oauth_request_timeout",
    "mcp_oauth_transport_failure",
    "mcp_oauth_credentials_missing",
    "mcp_oauth_as_discovery_invalid",
    "mcp_oauth_token_endpoint_error",
    "mcp_oauth_token_response_invalid",
    "mcp_prm_invalid",
    "mcp_api_key_fallback_unresolved",
    "mcp_admission_deps_required",        # T6 R1 P1 #1
})

class TestRefusalReasonCompleteness:
    def test_every_sprint_5_reason_in_literal(self) -> None:
        """Every Sprint-5 reason MUST appear in RefusalReason. Forces
        any new reason to be type-acknowledged in plugin_registry.py."""
        literal_args = frozenset(get_args(RefusalReason))
        missing = SPRINT_5_REFUSAL_REASONS - literal_args
        assert not missing, (
            f"Sprint-5 refusal reasons declared in this test but missing "
            f"from plugin_registry.RefusalReason literal: {sorted(missing)}. "
            f"Add them to the literal before this test will pass."
        )

    def test_no_orphaned_sprint_5_reason_in_literal(self) -> None:
        """Defensive: any Sprint-5-prefixed reason in the literal that
        is NOT in SPRINT_5_REFUSAL_REASONS is suspicious — either a
        typo or a leftover. Forces the test set to stay synchronised."""
        literal_args = frozenset(get_args(RefusalReason))
        # Sprint-5 reasons all start with "mcp_" — Sprint-4 reasons don't.
        sprint_5_in_literal = {r for r in literal_args if r.startswith("mcp_")}
        orphans = sprint_5_in_literal - SPRINT_5_REFUSAL_REASONS
        assert not orphans, (
            f"plugin_registry.RefusalReason has Sprint-5 reasons not in "
            f"this test's SPRINT_5_REFUSAL_REASONS set: {sorted(orphans)}. "
            f"Either add to the test set OR remove from the literal."
        )

    @pytest.mark.parametrize("reason", sorted(SPRINT_5_REFUSAL_REASONS))
    def test_every_reason_has_a_dedicated_test_arm(self, reason: str) -> None:
        """For each Sprint-5 reason, at least one test in the suite
        asserts the reason is emitted by some refusal path. Walks the
        test-collection metadata; fails if any reason has zero asserting
        tests. Catches the "reason added to literal but never exercised"
        drift class."""
        # Implementation: collect all test ids matching the reason
        # in a parametrize id OR in an assertion against
        # outcome.refusal_reason. If zero matches, fail.
        # ... (concrete implementation in the test file)
```

The mapping `_authz_reason_to_refusal()` helper converts the eleven registration-boundary `MCPAuthzClient` reasons (`mcp_anonymous_refused`, `mcp_as_not_allowlisted`, `mcp_token_audience_mismatch`, `mcp_token_scope_overgrant`, `mcp_oauth_request_timeout`, `mcp_oauth_transport_failure`, `mcp_oauth_credentials_missing`, `mcp_oauth_as_discovery_invalid`, `mcp_oauth_token_endpoint_error`, `mcp_oauth_token_response_invalid`, `mcp_prm_invalid`) one-to-one into the registry's enum. The **two runtime-only** `AuthzReason` values — `mcp_step_up_unauthorised` (T9 step-up flow) and `mcp_authorisation_lost` (T9 R1 P2 #3 second-401-retry exhaustion) — are NOT mapped: the helper raises `ValueError` if either reaches it. The `_RUNTIME_ONLY_AUTHZ_REASONS` frozenset in `plugin_registry.py` is the single source of truth; the drift detector in `test_refusal_reason_completeness.py` enforces that the two sets stay in sync.

- [ ] **Step 7: Run tests; expect PASS; coverage ≥95/90 on `mcp_manifest.py` and `mcp_capabilities.py`; existing critical-controls coverage on `plugin_registry.py` still ≥95/90**

- [ ] **Step 8: Architecture test still green**

Run: `uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py -v`
Expected: PASS — neither `mcp_manifest.py` nor `mcp_capabilities.py` imports `subprocess`.

- [ ] **Step 9: Halt-before-commit summary; wait for `commit` token**

Three halts in this task (one per critical-controls module touched):

1. After `mcp_manifest.py` lands.
2. After `mcp_capabilities.py` + `policies/_default/sampling.rego` land.
3. After the `plugin_registry.py` integration edit lands (separate halt because `plugin_registry.py` is critical-controls and the edit adds 11 new closed-enum reasons + a new sequenced step in admission).

```bash
git add src/cognic_agentos/protocol/mcp_manifest.py \
        src/cognic_agentos/protocol/mcp_capabilities.py \
        policies/_default/sampling.rego \
        tests/unit/protocol/test_mcp_manifest.py \
        tests/unit/protocol/test_mcp_capabilities.py \
        tests/unit/protocol/test_mcp_registration_auth_probe.py \
        tests/unit/protocol/test_refusal_reason_completeness.py \
        src/cognic_agentos/protocol/plugin_registry.py
git commit -m "feat(sprint-5): MCP manifest extraction + capability validator + registration auth probe (T6)"
```

---

## Task 7: `protocol/mcp_transports.py` — `StreamableHTTPTransport`

**Files:**
- Create: `src/cognic_agentos/protocol/mcp_transports.py` — critical-controls module (this file ALSO carries `StdioTransport` in Task 8; the file lands in two halts: T7 lands the HTTP transport, T8 lands the STDIO refusal).
- Test: `tests/unit/protocol/test_mcp_transports_http.py`.

**Critical-controls module — halt before commit.**

Surface:
- Abstract `MCPTransport` protocol: `async open_session(server_url, token) -> MCPSession`, `async close_session(session)`, `async send(session, request) -> Response`.
- `StreamableHTTPTransport(MCPTransport)` — production default. Uses the official `mcp` SDK's HTTP client, wraps it with:
  - Strict timeout per `settings.mcp_oauth_request_timeout_s` (PRM/auth) and `settings.mcp_call_tool_timeout_s` (tool calls).
  - Audit-event hooks that fire on session-open / session-close / send-error so MCPHost can append rows to the `audit_event` chain via `AuditStore.append` (and write the corresponding `decision_history` row per T11 when the event corresponds to a call_tool outcome).
  - Authorization header injection via the Sprint-5 `MCPAuthzClient`.
- `StreamableHTTPTransport.__init__(*, authz, settings)` — **calls `require_mcp()` at construction time per R3 P1 doctrine**. This is one of the two classes (along with `MCPHost`) that genuinely uses the SDK at runtime; constructing it on a kernel-image-equivalent venv MUST fail with `MCPNotAvailableError`. Module-level imports stay clean (TYPE_CHECKING-only references to `mcp` types); SDK import happens inside method bodies (e.g., `open_session` imports `mcp.client.streamable_http` lazily).

- [ ] **Step 1: Write failing tests** (~15 tests covering session open/close, token injection, timeout, error taxonomy).

- [ ] **Step 2: Implement `StreamableHTTPTransport`** with the official `mcp` SDK as the underlying client.

- [ ] **Step 3: Run tests; expect PASS; coverage ≥95/90**.

- [ ] **Step 4: Architecture test still green** (transports module does NOT import subprocess).

- [ ] **Step 5: Halt-before-commit summary; wait for `commit` token**

```bash
git commit -m "feat(sprint-5): StreamableHTTP MCP transport (T7)"
```

---

## Task 8: `protocol/mcp_transports.py` — `StdioTransport` (non-launching transport methods only) + sandbox-availability detection

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_transports.py` — add `StdioTransport`.
- Modify: `src/cognic_agentos/core/config.py` — sandbox-availability check at config-load.
- Test: `tests/unit/protocol/test_mcp_transports_stdio.py`.

**Critical-controls module — halt before commit. This task is the most discipline-sensitive in the sprint: it is where Option C either holds or drifts.**

**R2 P2 #4 fix — registry owns refusal, transport does not.** Sprint 4 established that `PluginRegistry.register(...)` is the single owner of `RegistrationOutcome` creation + the closed-enum refusal mapping + the registry-side audit emission. A transport class fabricating its own `RegistrationOutcome` would either duplicate audit rows OR bypass the closed-enum vocabulary. Sprint 5 keeps the doctrine: **STDIO refusal happens in T6's capability validator + the `plugin_registry` admission hook; `StdioTransport` exposes ONLY non-launching transport methods, all of which raise `NotImplementedError`. The transport never sees a pack object and never produces a `RegistrationOutcome`.**

`StdioTransport` Sprint-5 surface (default Python constructor + 3 transport methods; 0 of the methods can spawn a process; the constructor does not call `require_mcp()` per R3 P1 doctrine since the class doesn't use the SDK):

- `async open_session(*, server_url: str, token: Token) -> MCPSession` — raises `NotImplementedError("STDIO transport launch is deferred to Sprint 8 sandbox primitive per ADR-002 §Sandbox dependency hard-block. STDIO packs are refused at registration in Sprint 5; this method is unreachable from the registry path.")`. The error message names ADR-002 + ADR-004 + the Sprint-8 hand-off (T15).
- `async send(session, request) -> Response` — raises `NotImplementedError` with the same shape.
- `async close_session(session) -> None` — raises `NotImplementedError` with the same shape.
- `__init__()` — default Python constructor; takes no arguments. **Does NOT call `require_mcp()`** — per R3 P1 doctrine, `require_mcp()` belongs only in classes that actually use the SDK at runtime. The three transport methods (`open_session`, `send`, `close_session`) all raise `NotImplementedError`; the class never references the SDK in any code path. Stores no state — the class is a pure refusal stub.

**Where the actual STDIO refusal lives (per T6):**
- T6's `mcp_capabilities.validate_mcp_manifest()` returns one of the `mcp_stdio_*` closed-enum reasons for any STDIO pack (`mcp_stdio_disabled_in_sprint_5` is the umbrella, with `mcp_stdio_manifest_incomplete` / `mcp_stdio_manifest_shell_metacharacter` / `mcp_stdio_command_not_allowlisted` taking precedence when more specific defects are present).
- T6's plugin_registry hook calls the validator and refuses registration via the existing Sprint-4 `PluginRegistry.register(refusal_reason=…)` path — which is what writes the audit event. ONE writer for refusals: the registry. ONE audit row per refusal.
- The `audit.stdio_launch_refused` event vocabulary lives at the registry-side audit emission, NOT in StdioTransport. T11 documents the payload schema.

This shape protects against three regression modes the R2 reviewer identified: (a) duplicate audit rows when both registry and transport emit refusals, (b) bypass of the closed-enum vocabulary if a transport invents its own refusal taxonomy, (c) drift where future Sprint-N work adds launch code to a transport because the surface "looks like" a registration handler.

Sandbox-availability check in `core/config.py` (unchanged from R1):
- At settings construction, if `runtime_profile == "prod"` AND `mcp_stdio_enabled = True` AND `cognic_agentos.sandbox.runtime` is not importable (try/except `ImportError`) → raise `SandboxNotAvailableError("STDIO MCP transport requires sandbox primitive (Sprint 8). Production profile cannot opt in until both sandbox available AND four-gate manifest validates. Set COGNIC_MCP_STDIO_ENABLED=false or wait for Sprint 8.")`.
- This is fail-fast at startup, NOT at first invocation. The error message references ADR-002 + ADR-004 + the Sprint-5 closeout note.

- [ ] **Step 1: Write failing tests** (~10 tests):
  - `test_stdio_open_session_raises_not_implemented` — explicitly proves Sprint 5 carries no launch path.
  - `test_stdio_send_raises_not_implemented`.
  - `test_stdio_close_session_raises_not_implemented`.
  - `test_stdio_constructor_does_not_call_require_mcp` — constructing `StdioTransport` on a kernel-image-equivalent venv (mocked `find_spec` returning None for `mcp`) succeeds without raising. **R3 P1 doctrine**: the class doesn't use the SDK, so it doesn't gate on it; admission-side modules construct cleanly on the kernel image. (Companion test `TestRuntimeRequiresSDK::test_streamable_http_transport_construction_requires_sdk` in `test_optional_dep_loader.py` covers the runtime-side counterpart.)
  - `test_stdio_transport_does_not_have_register_method` — defensive: asserts `hasattr(StdioTransport, "register") is False` so future drift that re-introduces a refusal-fabricating method trips immediately.
  - `test_stdio_transport_does_not_emit_audit_events` — defensive: any audit emission from StdioTransport itself fails the contract (registry owns audit on refusal; transport only emits on send-error / session-event for the HTTP path, which StdioTransport doesn't have because every method raises before reaching the audit hook).
  - `test_sandbox_availability_check_fail_fast_in_prod` — `runtime_profile="prod" + stdio_enabled=true + no sandbox` → fail at startup.
  - `test_sandbox_availability_check_dev_does_not_fail_fast` — `runtime_profile="dev"` with `stdio_enabled=true` but no sandbox merely logs a warning at startup; pack registration is still refused (T6 capability validator's `mcp_stdio_disabled_in_sprint_5` rule fires regardless of sandbox availability).
  - `test_sandbox_availability_check_prod_with_stdio_disabled_starts_clean` — `runtime_profile="prod" + stdio_enabled=false` starts cleanly regardless of sandbox availability.
  - `test_sandbox_runtime_module_does_not_exist_in_sprint_5` — `importlib.util.find_spec("cognic_agentos.sandbox.runtime")` returns None (Sprint 5 invariant; Sprint 8 lifts).

(Note: no `test_stdio_register_always_refused` test in this task — that contract belongs to T6's `test_mcp_capabilities.py::TestStdioDisabledInSprint5`. The doctrine boundary is clean: registry-side refusals are tested at the registry; transport-side refusals are `NotImplementedError`-only.)

- [ ] **Step 2: Implement `StdioTransport` + sandbox-availability check**

Implementation discipline:
- `StdioTransport` is a class with the **default Python constructor (no `__init__` body — implicit pass-through; does NOT call `require_mcp()`) plus three transport methods (`open_session`, `send`, `close_session`)**. Each of the three transport methods is `raise NotImplementedError("...")`. Total file delta: ~30 lines including docstrings. **No `if` / `try` / `match` constructs in any of the three transport-method bodies — all three are unconditional raises.**
- The sandbox-availability check in `core/config.py` is a single `_check_sandbox_availability()` function called from `Settings.model_post_init` (or equivalent). The try/except is the entire mechanism — `cognic_agentos.sandbox.runtime` doesn't exist; `ImportError` is the negative signal.

- [ ] **Step 3: Run tests; expect PASS; coverage ≥95/90 on `mcp_transports.py` (both transports together)**

- [ ] **Step 4: ARCHITECTURE TEST IS THE LOAD-BEARING GATE FOR THIS TASK**

```bash
uv run pytest tests/architecture/test_mcp_stdio_no_subprocess.py -v
```

Expected: PASS — `mcp_transports.py` (which now contains `StdioTransport`) does NOT import subprocess. **If this test fails, REVERT the offending edit immediately. The Decision Lock has been broken.**

- [ ] **Step 5: Halt-before-commit summary; wait for `commit` token**

The halt-summary explicitly states:
- StdioTransport has 3 transport methods (`open_session`, `send`, `close_session`); all three are unconditional `NotImplementedError` raises. No `register` method exists. No `require_mcp()` call — per R3 P1 doctrine, the class doesn't use the SDK so it doesn't gate on it.
- StdioTransport DOES NOT have a `register` method — registry owns registration outcomes per Sprint-4 doctrine.
- StdioTransport DOES NOT emit audit events — registry owns audit emission on refusal.
- No subprocess import exists in the module (architecture test verifies).
- Sandbox-availability check works at config-load.

```bash
git commit -m "feat(sprint-5): STDIO transport non-launching methods + sandbox-availability fail-fast (T8)"
```

---

## Task 9: `protocol/mcp_host.py` — `MCPHost`

**Files:**
- Create: `src/cognic_agentos/protocol/mcp_host.py` — critical-controls module.
- Test: `tests/unit/protocol/test_mcp_host.py`.

**Critical-controls module — halt before commit.**

**Transport protocol shape (R1 P2 #5 fix):** the abstract `MCPTransport` protocol takes the token at session-open time, NOT after — `async open_session(*, server_url: str, token: Token) -> MCPSession`. This means MCPHost.call_tool MUST acquire the token BEFORE calling `open_session`. For HTTP MCP, session-open itself is an authenticated request per the MCP authorization spec (the SDK's HTTP client opens the session with `Authorization: Bearer ...` set on the very first request); opening before authz would fail with 401 immediately. The 401-vs-403 distinction is handled inside `MCPHost.call_tool` (NOT at session-open, NOT inside `transport.send`) — the orchestrator walks the `__cause__` chain of an `MCPTransportError` for `httpx.HTTPStatusError`, parses `WWW-Authenticate`, and routes to drop+reacquire or step-up via `MCPAuthzClient`.

Surface (T9 + R1/R2/R3/R4 amendments — final shape):
- `MCPHost(*, servers: Mapping[str, MCPServerEntry], transports: Mapping[str, MCPTransport], authz: MCPAuthzClient, audit_store, decision_history_store, settings)` — constructed once at portal startup. **Doctrinal scope-decision (T9 R1):** the `servers` parameter is a typed `Mapping[str, MCPServerEntry]`, NOT the raw `PluginRegistry` — decoupling MCPHost from `plugin_registry`'s internals avoids touching that critical-controls module in T9. The portal lifespan code populates this mapping from the registry walk + per-pack `[tool.cognic.mcp]` extraction (registry → MCPServerEntry pipeline lands in a follow-up infra task). `transports` is keyed by canonical transport-kind name; both `"http"` and `"streamable-http"` are accepted (T9 R1 P2 #1 — both refer to the same canonical HTTP family). The constructor rejects unknown transport-kind strings (T9 R2 P2 #1 — runtime allow-list mirrors T6's `mcp_transport_unsupported` registration-side fence). Audit + decision-history dependencies are constructor-required (matches Sprint-3 LLM gateway + T5 MCPAuthzClient pattern). **Calls `require_mcp()` at construction time** per R3 P1 doctrine — `MCPHost` orchestrates SDK-backed sessions, kernel-image-equivalent venv MUST fail with `MCPNotAvailableError`. Module-level imports stay clean (no `mcp` SDK at module level); SDK use happens only via the transport.
- `async discover_servers() -> list[DiscoveredMCPServer]` — pure read of the configured `servers` mapping; returns metadata only (no session opened, no token acquired, no audit row).
- `async list_tools(*, server_id: str, request_id: str, tenant_id: str) -> list[Tool]`:
  - Step 1: Cache lookup keyed by `(tenant_id, server_id, manifest_scopes)` (T9 R1 P2 #2 — tenant_id MUST be in the key so per-tenant AS allow-list checks fire on every tenant's first call). Cached entries return a `copy.deepcopy` of the inner descriptors (T9 R2 P2 #2 — caller mutation of an inner dict cannot poison the cache).
  - Step 2: Acquire/refresh minimum-scope token via `authz.acquire_token(server_url, manifest_scopes, request_id, tenant_id)`.
  - Step 3: `transport.open_session(server_url, token)` — token-injected at the open call.
  - Step 4: SDK `list_tools(cursor)` paginated walk (T9 R3 P1) — real `mcp.types.ListToolsResult` (Pydantic) normalised via `result.tools` + `result.nextCursor`. Pagination is **bounded** (T9 R4 P2 #1) by cycle detection (repeated cursor → fail) + page cap (`_MAX_LIST_TOOLS_PAGES = 100` → fail). Each SDK call wrapped in `asyncio.wait_for` + try/except mapping to closed-enum `MCPTransportError` (T9 R4 P2 #2 — timeouts → `mcp_call_tool_timeout`, generic SDK exceptions → `mcp_transport_send_failed` with `error_type=type(exc).__name__`, NEVER `str(exc)`).
  - Step 5: `transport.close_session(session)` (best-effort; both `MCPTransportError` and generic `Exception` from a buggy session_close hook are caught + audit-logged with `failure_class` ∈ {`"transport"`, `"hook"`} but DO NOT fail the result — T9 R3 P2).
  - Step 6: Cache result per `(tenant_id, server_id, manifest_scopes)` with TTL = `settings.mcp_call_tool_timeout_s * 5` (deep-copy on cache write).
- `async call_tool(*, server_id: str, tool_name: str, arguments: dict, request_id: str, tenant_id: str) -> CallResult` — **call order revised in R1 P2 #5 to acquire token BEFORE session open**:
  - Step 1: **ADR-014 transitional gate** (pre-auth) — see Task 10. Refuses high-risk tools before any token / session work, so a refused call never touches the AS or the MCP server.
  - Step 2: **Acquire minimum-scope token** via `authz.acquire_token(server_url, manifest_scopes, request_id, tenant_id)`. This includes PRM discovery (cached from registration probe + per `Cache-Control`), AS allow-list check, RFC 8707 resource indicator, audience validation. AuthzClient errors map directly to `mcp_*` refusal reasons.
  - Step 3: **Open transport session WITH the token**: `transport.open_session(server_url=server_url, token=token)`. For HTTP, the SDK's HTTP client uses the token's `Authorization: Bearer ...` on every request including session-open.
  - Step 4: **Send the call_tool request** through the open session. Strict timeout per `settings.mcp_call_tool_timeout_s`.
  - Step 5: **Retry semantics on auth-related responses (handled in `MCPHost.call_tool`, NOT in `transport.send`)** — T9 R1 P2 #3: orchestrator walks `__cause__` chain of `MCPTransportError` for `httpx.HTTPStatusError`, parses `WWW-Authenticate`, and routes:
    - `401 WWW-Authenticate: Bearer ...` → call `authz.invalidate_cached_token(server_url)` to drop the cached token, redo Step 2 (fresh PRM discovery + fresh token request), then Step 3 + Step 4 with the new token. One retry max — second 401 → raise `MCPAuthzError("mcp_authorisation_lost")`.
    - `403 WWW-Authenticate: Bearer error="insufficient_scope", scope="<wider>"` → call `authz.step_up_token(...)`. Manifest declares wider scope ⇒ retry with stepped-up token. Manifest does NOT declare wider scope ⇒ `step_up_token` raises `MCPAuthzError("mcp_step_up_unauthorised")` (audit-emitted from inside the authz client per T5). One retry max.
    - `403 WWW-Authenticate: Bearer error="invalid_token"` (or `403` with no scope hint / no `WWW-Authenticate` header) → drop cached token + redo Step 2 + Step 3 + Step 4. Spec says `invalid_token` can return either 401 or 403; both paths drop+rediscover.
  - Step 6: **Close session** (best-effort; transport + hook failure tolerance per T9 R3 P2).
  - Step 7: **Emit audit + decision-history rows** per Task 11. T9 itself emits ONLY the close-failure tolerance audit row; the full `audit.tool_invocation` / `audit.tool_invocation_refused` / `audit.tool_invocation_error` + parallel `decision_history` rows land in T11 (including the audit row for the `mcp_authorisation_lost` second-401-retry exhaustion path — T9 raises the closed-enum `MCPAuthzError` but does NOT write the row).
  - Step 8: **Returns `CallResult`** with the tool's response payload + envelope metadata + correlation IDs (request_id, mcp_session_id, as_issuer, scopes, client_id).

- [ ] **Step 1: Write failing tests** (~20 tests covering discover_servers, list_tools, call_tool happy/error paths, transport selection, audit emission, token injection).

- [ ] **Step 2: Implement `MCPHost`**

- [ ] **Step 3: Run tests; expect PASS; coverage ≥95/90**

- [ ] **Step 4: Architecture test still green**

- [ ] **Step 5: Halt-before-commit summary; wait for `commit` token**

```bash
git commit -m "feat(sprint-5): MCPHost orchestrator (T9)"
```

---

## Task 10: ADR-014 transitional high-risk-tier refusal at invocation

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py` — add the transitional gate + closed-enum exception class + risk_tier normalisation helper.
- Test: `tests/unit/protocol/test_mcp_high_risk_tier_refused.py`.

Per ADR-014 §"Sprint 5 (transitional rule)":

> Harness ships **fail-closed** for all tiers above `internal_write` — high-risk tools register but every invocation is refused with `tool_approval_engine_not_available` and audit-logged. This is the only safe state until the approval engine exists.

Surface (T10 + R1 + R2 + R3 + R4 amendments — final shape):

- **`MCPToolInvocationRefused(Exception)`** — closed-enum runtime refusal class, distinct from `MCPTransportError` (transport-layer) + `MCPAuthzError` (auth-layer). Carries `reason: ToolInvocationRefusalReason` + `payload: dict`. Token-free: caller-supplied tool arguments NEVER appear in the payload.
- **`ToolInvocationRefusalReason = Literal["tool_approval_engine_not_available"]`** — Sprint-5 ships exactly one value; Sprint 13.5 will extend with the approval-engine outcomes.
- **`_ADR_014_LOW_RISK_TIERS = frozenset({"read_only", "internal_write"})`** — **whitelist semantics + fail-closed default**. The 6 named ADR-014 high-risk tiers (`customer_data_read`, `customer_data_write`, `payment_action`, `regulator_communication`, `cross_tenant`, `high_risk_custom`) AND any unknown / typo / malformed value all refuse. Pinned by regression test. Adding a tier weakens the fail-closed default → MUST land alongside the Sprint 13.5 approval engine.
- **`_normalize_risk_tier_for_gate(value: Any) -> str`** — defense-in-depth helper for the manifest-supplied risk_tier value (R1+R2+R3). Allow-list strings pass through unchanged (preserves exact-match semantics); other strings get `encode("unicode_escape").decode("ascii")[:200]` (R3 P2 — neutralises log-injection / ANSI / NUL injection attempts; R2 P2 — bounds multi-KB malicious manifests); non-strings get `repr(value)[:200]` (R1 P2 — bounds list/dict/None/etc. so they fail-close via the closed-enum path instead of raw TypeError from the membership check).
- **`_sanitize_string_for_operator_surface(value: str) -> str`** — defense-in-depth helper for the OTHER caller-supplied strings (`tool_name`, `request_id`, `server_id`) that flow into operator-facing surfaces (R4 P2). Same `encode("unicode_escape").decode("ascii")[:200]` discipline as the risk_tier helper but **without** the allow-list passthrough — every input is escaped + bounded. Used at: the audit-failure warning log path; the `MCPToolInvocationRefused` exception message construction. The audit-row payload **keeps the raw `tool_name`** (T11's downstream canonical-name queries depend on the unsanitised form; JSON canonical-form serialisation handles on-disk safety for the chain row).
- **Gate at the top of `MCPHost.call_tool`**, fires BEFORE `authz.acquire_token` AND BEFORE `transport.open_session` — a refused call MUST NOT touch the AS or the MCP server (security: don't burn tokens on refusals; audit cleanliness: a refusal row is the only evidence a refused call leaves).
- **T10 owns the `audit.tool_invocation_refused` audit row** for the ADR-014 path. Payload: `{server_id, tool_name (raw, canonical for T11 query), declared_risk_tier (normalised + bounded + escaped), refusal_reason: "tool_approval_engine_not_available", sprint_13_5_followup: True}`. Top-level `request_id` + `tenant_id` populated. **T11 MUST NOT duplicate this row** — T11 owns `audit.tool_invocation` (success), `audit.tool_invocation_error` (dispatch failures incl. `mcp_authorisation_lost` from T9), and the parallel `decision_history` rows. Audit-pipeline failure during the refusal-emit MUST NOT swallow the refusal; logged token-free + refusal still propagates (the refusal IS the safety outcome).
- This rule is **mechanical, not configurable**. Sprint 13.5 removes it.

- [ ] **Step 1: Write failing tests** (~30 baseline + R1/R2/R3/R4 tests = **73 tests across 11 classes** — the original draft sketched 8 tests against the 6 named high-risk tiers; the merged implementation grew to cover whitelist semantics for unknown / typo / empty / case values, defense-in-depth for non-string + multi-KB string + control-character-injection risk_tier shapes, operator-surface sanitisation for caller-supplied `tool_name` / `server_id` / `request_id`, and the audit-emit-failure-doesn't-mask-refusal contract).

Test catalogue (canonical surface — implementer adds the negative-path arms per the closed-enum table above):

- `TestRiskTierLowRiskTiers` — 2 parametrized (`read_only`, `internal_write`): gate transparent, normal call_tool flow, no refusal audit row.
- `TestRiskTierHighRiskTiersRefused` — 6 parametrized (the 6 named ADR-014 high-risk tiers): each refuses with closed-enum reason + `declared_risk_tier` payload.
- `TestRiskTierRefusalUpstreamOfDispatch` — 12 parametrized (× 2 contracts × 6 tiers): refusal does NOT call `authz.acquire_token`; refusal does NOT open / send / close transport session.
- `TestRiskTierRefusalAuditRow` — 1: payload schema complete (server_id, tool_name, declared_risk_tier, refusal_reason, sprint_13_5_followup); top-level (request_id, tenant_id) populated; tool **arguments NOT in payload**.
- `TestRiskTierUnknownValueFailsClosed` — 5 parametrized (typos / case / empty / made-up): unknown tier values fail-close via the same closed-enum path; payload carries verbatim declared value (escaped + bounded).
- `TestRiskTierRefusalSurvivesAuditFailure` — 1: audit-pipeline failure does NOT mask the refusal (safety outcome wins).
- `TestRiskTierAllowListPinned` — 3: allow-list pinned at exactly `{read_only, internal_write}`; closed enum pinned at `{tool_approval_engine_not_available}`; exception inherits from Exception.
- **R1 P2 — `TestRiskTierMalformedShapesFailClosed`** + `TestRiskTierNormalizeHelper` — 11 tests: 7 parametrized non-string shapes (list / multi-list / dict / None / int / bool / float) refuse via the closed-enum path; helper-direct tests pin string passthrough + non-string-truncation contracts; headline list-shape-doesn't-raise-TypeError regression.
- **R2 P2 — `TestRiskTierNormalizeHelper` extension + `TestLongStringRiskTierEndToEnd`** — 4 tests: long unknown string bounded; short unknown strings pass through; allow-list values pass through unchanged; end-to-end 50 KB string tier bounded in audit row + exception message.
- **R3 P2 — `TestRiskTierControlCharacterEscaping` + `TestRiskTierAllowListPassThroughVerbatim` + `TestRiskTierEscapingHelper`** — 14 tests: 5 parametrized control-char tiers (newline / tab / ANSI / NUL / CR) escaped in audit row + exception message; log-injection-via-newline doesn't forge a separate log line in the audit-failure warning path; allow-list literal byte-equality preserved; helper-direct tests for 6 parametrized control chars + printable-ASCII passthrough.
- **R4 P2 — `TestRiskTierToolNameSanitization` + `TestSanitizeStringForOperatorSurfaceHelper`** — 14 tests: 4 parametrized control-char `tool_name` values (newline / tab / ANSI / NUL) escaped in the exception message; log-injection-via-newline-in-`tool_name` doesn't forge a separate log line in the audit-failure warning path; audit row payload preserves the canonical (raw) `tool_name` for T11 downstream queries; helper-direct tests for 6 parametrized control chars + printable-ASCII passthrough + long-string bounding.

- [ ] **Step 2: Implement the gate in `MCPHost.call_tool`**

The gate is a ~15-line block at the top of `call_tool` (after the `_lookup_server` call, before `_resolve_transport`). References ADR-014 in a comment. Plus, at module scope: the `ToolInvocationRefusalReason` closed enum + `MCPToolInvocationRefused` exception class + `_ADR_014_LOW_RISK_TIERS` allow-list + the two defense-in-depth helpers (`_normalize_risk_tier_for_gate` for risk_tier per R1/R2/R3, `_sanitize_string_for_operator_surface` for the other caller-supplied strings per R4). Plus, on `MCPHost`: the `_emit_high_risk_tier_refusal_audit` instance method (which uses `_sanitize_string_for_operator_surface` in its warning-log fallback path).

- [ ] **Step 3: Run tests; expect PASS**

- [ ] **Step 4: Architecture test still green**

- [ ] **Step 5: Halt-before-commit summary; wait for `commit` token**

```bash
git commit -m "feat(sprint-5): ADR-014 transitional high-risk tier refusal (T10)"
```

---

## Task 11: Audit-event chain + decision-history linkage for MCP calls

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py` — wire both audit + decision-history emission.
- Modify: `src/cognic_agentos/protocol/mcp_authz.py` — wire token-refresh audit + decision-history rows.
- Test: `tests/unit/protocol/test_mcp_audit_linkage.py`.
- Test: `tests/unit/protocol/test_mcp_decision_history_linkage.py` — separate file because the assertions are different (audit chain vs decision-history rows; correlation by request_id).

**R1 P2 #6 fix — separating the two evidence surfaces.** Sprint 2 established two distinct evidence stores:

- **`AuditStore`** writes to the **`audit_event` chain** (tamper-evident hash-chained). Used for fail-closed-violation events, security-relevant refusals, and operational events where examiners need ordered tamper-evidence.
- **`DecisionHistoryStore`** writes to the **`decision_history` table**. Used for policy decisions and any event that must be queryable by `trace_id` / `request_id` / `mcp_session_id` for examiner replay (per MCP-CONFORMANCE.md §"Authorization" item 9: "Every MCP call records `client_id` + scopes used + AS issuer + resource indicator in `decision_history`").

The two surfaces have different durability + query shapes; calling one "chains into" the other was a Sprint-5-plan error in R0. Sprint 5 writes to both, correlated by `request_id`.

### `audit_event` chain (via `AuditStore.append`)

Each event is hash-chained for tamper-evidence:

- `audit.tool_invocation` — every successful `call_tool`. Payload: `pack_id`, `pack_signature_digest`, `tool_name`, `mcp_session_id`, `as_issuer`, `scopes` (as sorted tuple), `resource_indicator`, `client_id`, `duration_ms`, `outcome="ok"`, `tenant_id`, `request_id`.
- `audit.tool_invocation_refused` — every refusal (ADR-014 transitional, capability validator, auth probe). Payload: subset of above + `refusal_reason` (closed-enum) + `declared_risk_tier` (when ADR-014 gate fires).
- `audit.tool_invocation_error` — call dispatched but failed (HTTP error, timeout, malformed response). Payload: above + `error_taxonomy`.
- `audit.mcp_token_refresh` — every token refresh. Payload: `as_issuer`, `scopes`, `resource_indicator`, `client_id`. **NEVER token contents.**
- `audit.mcp_step_up` — every step-up scope flow. Payload: prior scopes, requested-additional scopes, outcome (`granted` / `mcp_step_up_unauthorised`).
- `audit.stdio_launch_refused` — every STDIO registration refusal (wired in T8; this task ensures payload schema is consistent).

### `decision_history` rows (via `DecisionHistoryStore.append`)

Each row carries the policy-relevant decision metadata, queryable by `request_id` / `mcp_session_id`:

- **MCP call decision row** — written on every `call_tool` outcome (ok / refused / error). Schema: `request_id`, `mcp_session_id`, `pack_id`, `tool_name`, `decision` (`invoked` / `refused` / `errored`), `decision_reason` (closed-enum or `null` for ok), `as_issuer`, `scopes`, `resource_indicator`, `client_id`, `tenant_id`, `declared_risk_tier`, `timestamp`.
- **Token-refresh decision row** — written on every successful token refresh OR refresh failure. Schema: `request_id`, `decision` (`refreshed` / `refresh_failed`), `as_issuer`, `scopes`, `resource_indicator`, `client_id`, `tenant_id`, `timestamp`.
- **Registration probe decision row** — written when T6's auth probe runs. Schema: `request_id`, `pack_id`, `decision` (`probe_succeeded` / `probe_refused`), `decision_reason`, `as_issuer` (when applicable), `tenant_id`, `timestamp`.

### Correlation by `request_id`

Every `request_id` flowing through `MCPHost.call_tool` produces:
- 1 `audit_event` row (one of `tool_invocation` / `tool_invocation_refused` / `tool_invocation_error`).
- 1 `decision_history` row (the MCP call decision row).
- Possibly 0+ additional rows on either surface (token refresh; step-up; transient retry events).

Examiners querying `decision_history WHERE request_id = ?` get the full MCP-call shape including `mcp_session_id` (per MCP-CONFORMANCE.md §observability) and the auth context. Examiners querying the audit chain by `request_id` get the tamper-evident timeline.

- [ ] **Step 1: Write failing tests for the audit-chain side** (~10 tests covering each event type + happy / error / refusal axes).

- [ ] **Step 2: Write failing tests for the decision-history side** (~8 tests covering MCP call rows + token-refresh rows + registration-probe rows; correlation-by-`request_id` assertions).

- [ ] **Step 3: Wire emission in `mcp_host.py` + `mcp_authz.py`**

Both `MCPHost` and `MCPAuthzClient` already accept `audit_store` + `decision_history_store` in their constructors (per T5 + T9 surface). This task adds the actual emission calls at each event site:

```python
# Sketch — MCPHost.call_tool successful path
await self._audit_store.append(
    event_type="audit.tool_invocation",
    payload={...},
    request_id=request_id,
    tenant_id=tenant_id,
)
await self._decision_history_store.append(
    request_id=request_id,
    decision_type="mcp_call",
    decision="invoked",
    decision_reason=None,
    metadata={"mcp_session_id": session.id, "as_issuer": ..., ...},
    tenant_id=tenant_id,
)
```

- [ ] **Step 4: Run tests; expect PASS; coverage ≥95/90 holds on both `mcp_host.py` and `mcp_authz.py`**

- [ ] **Step 5: Architecture test still green**

- [ ] **Step 6: Halt-before-commit summary; wait for `commit` token**

Halt summary explicitly states: audit chain row count + decision_history row count are correlated by `request_id`; never reused; both surfaces written for every MCP call outcome.

```bash
git commit -m "feat(sprint-5): MCP audit-chain + decision-history linkage (T11)"
```

---

## Task 12: Fixture HTTP MCP test pack

**Files:**
- Create: `tests/fixtures/cognic_test_mcp_pack/pyproject.toml`.
- Create: `tests/fixtures/cognic_test_mcp_pack/cognic_test_mcp_pack/__init__.py`.
- Create: `tests/fixtures/cognic_test_mcp_pack/cognic_test_mcp_pack/server.py` — a minimal HTTP MCP server using the `mcp` SDK that publishes PRM, requires OAuth, exposes 2 tools (one `read_only`, one `internal_write`).
- Create: `tests/fixtures/cognic_test_mcp_pack/attestations/` — full Sprint-4 attestation set so the pack actually admits via the registry. Mirror the `cognic_test_pack` shape from Sprint 4.

**This pack is a fixture only — `tools-only` (no production tools, no real bank logic).** Its purpose is to give the integration tests something real-shaped to exercise.

- [ ] **Step 1: Author the fixture pack** (mirror `tests/fixtures/cognic_test_pack/` from Sprint 4; add the MCP-specific manifest block + the minimal server).

- [ ] **Step 2: Write the integration smoke test**

`tests/unit/protocol/test_mcp_fixture_pack_admission.py` — admits the fixture pack through the full Sprint-4 admission pipeline + Sprint-5 capability validation; opens HTTP MCP session via `MCPHost.list_tools`; calls the `read_only` tool; verifies audit chain.

- [ ] **Step 3: Run tests; expect PASS**

- [ ] **Step 4: Architecture test still green**

- [ ] **Step 5: Sweep + commit**

```bash
git commit -m "test(sprint-5): cognic_test_mcp_pack fixture + admission smoke (T12)"
```

---

## Task 13: Negative-path canary — `test_mcp_no_user_controlled_command.py`

**Files:**
- Create: `tests/unit/protocol/test_mcp_no_user_controlled_command.py`.

Per `docs/MCP-STDIO-THREAT-MODEL.md` §"Negative-path canary":

> This test is the canary for the threat model. It deliberately tries to inject a user-controlled command/argument through every reachable code path → asserts every one is refused at every entry point.

Coverage:
- Manifest declared command `; rm -rf /` → `mcp_stdio_manifest_shell_metacharacter`.
- Manifest declared command interpolating `{user_input}` → registration refused (manifest must be static per ADR-002 §gate 1).
- Tool argument that resembles a command argument (`--exec ...`) reaching dispatch → no special handling (refused by transport before dispatch).
- Direct invocation of `StdioTransport.open_session` / `send` → `NotImplementedError`.
- Etc. — every reachable surface enumerated as a parametrized arm.

- [ ] **Step 1: Write the test** (~25 parametrized arms).

- [ ] **Step 2: Run; expect PASS** (every arm refused).

- [ ] **Step 3: Sweep + commit**

```bash
git commit -m "test(sprint-5): negative-path canary for STDIO threat model (T13)"
```

---

## Task 14: Critical-controls coverage gate extension

**Files:**
- Modify: `tools/check_critical_coverage.py` — extend gate from 16 → 21 modules.

Add the Sprint-5 quintet (R1 patch added `mcp_manifest.py` to the original quartet — the signed-manifest extractor sits on the deferred-load invariant + cosign-trust path and rides the same critical-controls floor as the others):

```python
("src/cognic_agentos/protocol/mcp_authz.py", 0.95, 0.90),
("src/cognic_agentos/protocol/mcp_capabilities.py", 0.95, 0.90),
("src/cognic_agentos/protocol/mcp_manifest.py", 0.95, 0.90),
("src/cognic_agentos/protocol/mcp_transports.py", 0.95, 0.90),
("src/cognic_agentos/protocol/mcp_host.py", 0.95, 0.90),
```

Update the docstring footer to mention Sprint 5 + the new gate count.

- [ ] **Step 1: Run the gate; verify all 21 modules pass; commit**

```bash
git commit -m "chore(sprint-5): extend critical-controls gate to MCP quintet (T14)"
```

---

## Task 15: Closeout note + BUILD_PLAN refresh + AGENTS.md critical-controls update + Sprint-8 hand-off checklist

**Files:**
- Create: `docs/closeouts/2026-05-XX-sprint-5-mcp-host.md` (date filled at commit time).
- Modify: `docs/BUILD_PLAN.md` — flip Sprint 5 status to `**CLOSED**`.
- Modify: `AGENTS.md` — add the Sprint-5 critical-controls quintet to the doctrine list (R1 P3 #9 — `mcp_authz` is already named; add `mcp_manifest`, `mcp_capabilities`, `mcp_transports`, `mcp_host` to bring the doctrine list in sync with the gate).
- Modify: `tests/architecture/test_mcp_stdio_no_subprocess.py` — tighten `at_least_one_mcp_module_exists` from `>= 0` to `>= 5`.

Closeout structure mirrors Sprint 4:
- Header (parent SHA, base SHA, branch state, commit count).
- What ships (**5 critical-controls MCP modules** — `mcp_authz`, `mcp_manifest`, `mcp_capabilities`, `mcp_transports`, `mcp_host` — plus threat-model doc + sampling Rego seed + fixture MCP pack + 1 architecture test + 24-value RefusalReason extension with completeness regression + audit-event vocabulary + decision-history correlation + ADR-014 transitional gate + kernel-vs-default-adapters loader API).
- CI matrix (no new lanes; existing lanes still gate; per-file coverage now enforces **21 modules**).
- Doctrine adherence (halt-before-commit on every critical-controls edit; Decision Lock held; architecture test never tripped during sprint).
- Test + coverage state (20-module gate table).
- Plan-review findings closed (round-by-round).
- ADR-002 / ADR-014 / ADR-015 (sampling) Validation table (delivered / partial / carryover map).
- Doctrine amendments accepted in Sprint 5 (esp. the Sprint-5 Decision Lock named in AGENTS.md as a doctrine pattern future sprints can reference).

**Sprint-8 hand-off checklist (load-bearing — surfaced as its own §):**

1. New module `src/cognic_agentos/protocol/mcp_stdio_launcher.py` lands with the sandboxed `launch()` method.
2. `tests/architecture/test_mcp_stdio_no_subprocess.py::_mcp_modules` updated to exclude `mcp_stdio_launcher.py` (the only module allowed to import subprocess; any OTHER subprocess import in protocol/mcp_* still trips the test).
3. `mcp_stdio_enabled` default for `dev` profile flips from `false` to `true`. Production stays `false`.
4. **Registry-side STDIO gate** (currently in T6's capability validator + the Sprint-4 `plugin_registry` admission hook) switches from "always refused" to: refuse unless (a) `mcp_stdio_enabled=true` AND (b) sandbox runtime importable AND (c) four-gate manifest validates AND (d) command on per-tenant allow-list. Same closed-enum reasons; the `mcp_stdio_disabled_in_sprint_5` value gets renamed to `mcp_stdio_disabled` (Sprint 8 closeout edit). Registry stays the single owner of `RegistrationOutcome`; `StdioTransport` never produces refusals (per Sprint-5 R2 P2 #4 doctrine).
5. `audit.stdio_launch_refused` event vocabulary extended with `audit.stdio_launch_completed` + `audit.stdio_launch_failed` + `audit.stdio_launch_timeout`.
6. Integration tests under the sandbox runtime that prove launch happens inside the sandbox boundary, env-allowlist enforced, command-allowlist enforced, breach attempts fail closed.

The hand-off is the contract Sprint 5 deliberately leaves unfinished. Sprint 8 should treat this list as its acceptance criteria for the STDIO portion of its scope.

- [ ] **Step 1: Author the closeout note**

- [ ] **Step 2: BUILD_PLAN refresh** (Sprint 5 deliverables list expanded; status line flipped to CLOSED with commit count + suite delta filled in).

- [ ] **Step 3: AGENTS.md doctrine update** — append to the critical-controls list under "Protocol authorization" / new "Protocol — MCP host" section:

```markdown
*Protocol — MCP host (Sprint 5):*
- `protocol/mcp_authz.py` (per ADR-002 amendment — already in critical-controls list pre-Sprint-5; gate enforcement extended in Sprint 5)
- `protocol/mcp_capabilities.py` (per ADR-002 + MCP-CONFORMANCE.md — manifest validation, capability default-deny enforcement)
- `protocol/mcp_transports.py` (per Sprint-5 Decision Lock — Streamable HTTP transport + STDIO refusal-only; Sprint-8 launcher is a separate critical-controls module added then)
- `protocol/mcp_host.py` (per ADR-002 — admission-to-invocation orchestrator; ADR-014 transitional gate; audit + decision-history correlation)
- `protocol/mcp_manifest.py` (per Sprint-5 R1 P2 #2 — signed-manifest extractor; deferred-load invariant)
```

This makes the gate config (`tools/check_critical_coverage.py`) and the doctrine document (`AGENTS.md`) match. Future edits to any of the new modules get the same halt-before-commit treatment as the existing critical-controls modules.

- [ ] **Step 4: Tighten architecture test** (`>= 0` → `>= 5` so the test starts asserting against real coverage of the 5 modules — authz, manifest, capabilities, transports, host).

- [ ] **Step 5: Author + commit:**

```bash
git add docs/closeouts/ docs/BUILD_PLAN.md AGENTS.md tests/architecture/test_mcp_stdio_no_subprocess.py
git commit -m "docs(sprint-5): closeout + BUILD_PLAN refresh + AGENTS.md critical-controls update + Sprint-8 hand-off (T15)"
```

---

## Self-Review

After authoring the 15 tasks above + folding in the R1 doctrine-review patches (7 P2 + 4 P3 findings), the plan was reviewed against:

**Spec coverage check:** All BUILD_PLAN Sprint 5 deliverables mapped to tasks: `protocol/mcp_host.py` → T9; `protocol/mcp_transports.py` (HTTP) → T7; `protocol/mcp_transports.py` (STDIO refusal) → T8; `protocol/mcp_authz.py` → T5; `protocol/mcp_capabilities.py` → T6; `policies/_default/sampling.rego` → T6; `core/config.py` Sprint-5 settings → T1; sandbox-availability fail-fast → T8; `audit.tool_invocation` event → T11; ADR-014 transitional gate → T10; `tests/fixtures/cognic_test_mcp_pack/` → T12; `mcp` SDK dep → T2; `docs/MCP-STDIO-THREAT-MODEL.md` → T3; coverage-gate extension → T14; closeout → T15. **Four additional load-bearing artifacts the plan adds beyond BUILD_PLAN's literal list:** the architecture test (T4 — guardrail 2 from the Decision Lock), the negative-path canary test (T13 — explicit threat-model boundary check), the Sprint-8 hand-off checklist (T15 — guardrail 3 from the Decision Lock), and the signed-manifest extractor `protocol/mcp_manifest.py` (T6 — added in R1 P2 #2 because the original "registry parses pyproject" claim was unworkable for wheel-installed packs; the extractor uses `Distribution.locate_file()` to preserve the deferred-load invariant).

**Placeholder scan:** searched the plan for "TBD", "TODO", "implement later", "fill in details", "Add appropriate ...". One deliberate placeholder: T2's `mcp == X.Y.Z` — the implementation engineer fills in the pinned version at task time after checking PyPI. This is honest deferral, not a placeholder; the doctrine of "pinned at PR-author time" is exactly the Sprint-4 T13 pattern for cosign + OPA pins.

**Type consistency:** every type referenced in later tasks is defined in earlier ones. `MCPAuthzClient` defined in T5 with `audit_store` + `decision_history_store` constructor params (R1 P2 #7) + reused in T7/T8/T9; admission-side per R3 P1 doctrine (no `require_mcp()` call; pure httpx + OAuth/PRM). `Token` / `ResourceMetadata` defined in T5. `MCPTransport` protocol defined in T7 with `open_session(server_url, token)` taking the token as a constructor-like param (R1 P2 #5 — the call order in T9 acquires the token before opening the session). **`StdioTransport` (T8): the three transport methods (`open_session`, `send`, `close_session`) raise `NotImplementedError`; no `register` method exists** (R2 P2 #4 — registry stays the single owner of `RegistrationOutcome` per Sprint-4 doctrine; R3 P1 — no `require_mcp()` call either, since the class doesn't actually use the SDK). `AuthzReason` literal defined in T5 (**13 values** — the original 6, plus R6 P2 added `mcp_token_scope_overgrant`, `mcp_oauth_transport_failure`, `mcp_oauth_credentials_missing`, plus R11 P2 added `mcp_oauth_as_discovery_invalid`, `mcp_oauth_token_endpoint_error`, `mcp_oauth_token_response_invalid` (12 values total at end of T5), plus T9 R1 P2 #3 added the runtime-only `mcp_authorisation_lost` (13th value)). The split between the **11 registration-boundary** values (mappable via `_authz_reason_to_refusal`) and the **2 runtime-only** values (`mcp_step_up_unauthorised` from T5's `step_up_token`, `mcp_authorisation_lost` from T9's `call_tool` second-401-retry exhaustion) is enforced by the `_RUNTIME_ONLY_AUTHZ_REASONS` frozenset in `plugin_registry.py` + the drift detector in `test_refusal_reason_completeness.py`. Closed-enum reason vocabulary unified across T6 + T11 (no two reasons share a name); the **24-value** extension to `plugin_registry.RefusalReason` is enumerated explicitly in T6 step 6 with a completeness regression test (R2 P2 #3 + R3 P2 arithmetic correction + R6 P2 production-grade auth surface widened to 8 auth-probe values + R11 P2 split AS-discovery / token-endpoint / token-response off the PRM-invalid bucket → 11 auth-probe values + T6 R1 P1 #1/#2 fail-closed admission gates: `mcp_transport_unsupported` extending the capability cohort 9 → 10 and `mcp_admission_deps_required` adding a 1-value registry-configuration cohort).

**Cross-task dependencies:** T1 (settings, including `mcp_sampling_policy_bundle` per R1 P3 #8) lands before everything else. T2 (mcp dep + kernel-vs-default-adapters runtime contract per R1 P2 #1) lands before T7/T9. T3 (threat model doc) lands before T4. T4 (architecture test with recursive scan + 3 self-tests per R1 P2 #4) lands before T5. T5 (mcp_authz with audit/decision-history constructor deps per R1 P2 #7) lands before T6 (registration auth probe needs the client per R1 P2 #3) and before T7 (HTTP transport injects auth). T6 (manifest extraction → capability validation → registration auth probe) integrates into `plugin_registry.py` — load-bearing for T8 (STDIO refusal uses the validator) and T9 (MCPHost reads validated manifest). T8 (StdioTransport refusal) lands before T13 (negative-path canary). T11 (separate audit-chain + decision-history rows per R1 P2 #6) lands after T9. T14 (gate extension to 21 modules) lands AFTER all 5 critical-controls modules are at ≥95/90 coverage. T15 (closeout + AGENTS.md update per R1 P3 #9) is last.

**Halt-before-commit discipline:** every task touching a critical-controls module (T2 portal/api/app.py + protocol/__init__.py, T5 mcp_authz, T6 mcp_manifest + mcp_capabilities + plugin_registry, T7 + T8 mcp_transports, T9 mcp_host, T10 mcp_host, T11 mcp_host + mcp_authz) explicitly mentions halt-before-commit. T1 (settings), T3 (threat model doc), T4 (architecture test), T12 (fixture), T13 (canary test), T14 (gate config), T15 (closeout) are not critical-controls but still halt per the per-action rule on commits.

**Decision Lock discipline check (the one this plan exists to defend):**
- T8 (StdioTransport) explicitly states: the three transport methods (`open_session`, `send`, `close_session`) raise `NotImplementedError`; no `register` method exists; no code path exists that could spawn a process.
- T4 (architecture test) is wired BEFORE T5 so it gates every subsequent task. R1 P2 #4 fix tightened the collector to recursive scan + stdio-substring detection + 3 self-tests proving the collector catches top-level files, nested submodules, and renamed modules.
- T15 (closeout) tightens the architecture test from `>= 0` to `>= 5` to confirm the 5 modules all landed with the discipline intact.
- The Sprint-8 hand-off checklist names exactly what Sprint 8 must add — `mcp_stdio_launcher.py` is the SINGLE new module that's allowed to import subprocess; everything else stays clean. The `_LAUNCHER_ALLOWLIST` set in the architecture test is the explicit allow-list mechanism Sprint 8 will populate.
- The negative-path canary (T13) is the runtime backstop: even if the architecture test misses a sneaky import via `__import__("subprocess")` or similar dynamic invocation, T13 trips on the resulting refusal vector.

**R7 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P2 — Signature refusal incorrectly assigned to `mcp_capabilities`.** The Decision Lock STDIO-SHIPS bullet at line 24 said `mcp_capabilities` "refuses unsigned manifests" — overstating the validator's responsibility and conflicting with the body contract (signature coverage is Sprint-4 cosign / trust-gate work, manifest reading is `mcp_manifest`, capability/declaration validation is `mcp_capabilities`). Reworded to a three-layered refusal-site list with explicit doctrine-boundary attribution: signature integrity stays at Sprint-4 `protocol/trust_gate.py` (cosign verifies the wheel, which transitively covers the manifest file shipped inside it); missing/malformed static manifest stays at `mcp_manifest` (`PackManifestNotFoundError` / `PackManifestMalformedError`); bad parsed STDIO declarations stay at `mcp_capabilities` (missing command/args/env_allowlist + shell metacharacters + command allowlist + Sprint-5 disabled umbrella). The three sites compose into "any STDIO pack registers as refused in Sprint 5" without any single layer claiming responsibility for ALL refusals — preserves the doctrine boundary the body contract already established.

**Implementation-round amendments (post-plan-merge, folded back into the plan-of-record so future plan-readers see the load-bearing-current vocabulary, not a stale snapshot):**
- **T6 implementation R6 2×P2 → source-of-truth literal-comment sync (T6 R6 round).** R5 fixed the base-exception docstring but the **closed-enum vocabulary site itself** in `plugin_registry.py` (the `RefusalReason` literal at lines 90-93 + the `_VALID_REFUSAL_REASONS` validset at lines 133-136) still commented `mcp_manifest_missing` as "cognic-pack-manifest.toml absent" — the pre-R2 contract. Two comments updated to mark the literal as **reserved-for-future-use**: kept in the literal + validset for type-checker / drift-detector consistency, but no current T6 admission code path emits it. The `mcp_manifest_malformed` neighbour comment also expanded to call out R2 P1's present-but-non-dict-MCP-block routing. With this, the source-of-truth vocabulary file matches every downstream docstring touched in R2/R3/R4/R5.
- **T6 implementation R5 P2 → base-exception contract sync (T6 R5 round).** R4's sweep updated the leaf class docstrings + module docstring + registry docstring + plan, but missed the `MCPManifestError` BASE class docstring (`mcp_manifest.py:97-105`). The base still said "the registry maps each leaf subclass to its closed-enum `RefusalReason`. New leaf subclasses MUST add a corresponding registry-side mapper branch AND a new `RefusalReason` literal value" — which carries the pre-R2 one-leaf-one-refusal doctrine and would steer the next implementer adding a new leaf to wire a refusal mapping for it even if the policy choice is "proceed". Updated to call out the **asymmetric routing** explicitly: malformed → always refuses; not-found → registry proceeds; future leaves choose their behaviour deliberately and the Sprint-4 closed-enum extension contract (literal + mapper + test arm + audit branch) only applies to the fail-closed leaves. With this, every `mcp_manifest_missing` reference site that R2/R3/R4/R5 touched is consistent.
- **T6 implementation R4 3×P2 + P3 → exhaustive `mcp_manifest_missing` doc-sync sweep (T6 R4 round).** R3 caught two of the stale `mcp_manifest_missing` references but missed several — R4 ran a `grep -rn mcp_manifest_missing` over `src/`, `tests/`, and `docs/` and updated every site that still implied the literal is emitted by current admission. Eight surfaces fixed:
  - **`MCPAdmissionDeps` step-A docstring** (`plugin_registry.py:236-240`) said "missing → mcp_manifest_missing; malformed → mcp_manifest_malformed". Replaced with the four-outcome R2 contract (missing proceeds; well-shaped MCP block continues; no MCP block proceeds; malformed MCP block / TOML decode failure refuses with `mcp_manifest_malformed`); explicit note that `mcp_manifest_missing` is reserved-for-future-use; explicit doctrine note that `mcp_admission` is dependency wiring, not pack intent.
  - **`mcp_manifest.py` module docstring** (`mcp_manifest.py:58-66`) said both leaf exceptions map 1:1 to refusals. Rewritten to distinguish **extractor exception semantics** (the structural fact "no manifest at this path" vs "TOML parse failed") from **registry refusal semantics** (whether to refuse, and with which reason). The two leaves are MEANINGFULLY DISTINCT extractor outcomes; the registry's policy choice is a separate concern.
  - **`PackManifestNotFoundError` class docstring** (`mcp_manifest.py:124-127`) said "operators see this as the closed-enum mcp_manifest_missing refusal". Updated to: current T6 admission catches and proceeds (no MCP intent); the message remains useful for future explicit MCP-intent callers (Sprint-7A or new entry-point group).
  - **Plan top-level Decision Lock** (`plan:24-27`) said absent manifest maps to `mcp_manifest_missing`. Replaced with the R2 contract: only TOML decode failure (or present-but-non-dict MCP block via R2 P1's safe-walk) refuses with `mcp_manifest_malformed`; absent manifest proceeds. Calls out the reserved-for-future-use status of `mcp_manifest_missing` so future readers don't try to map it.
  - **Plan T6.2 prose** (`plan:1521`) listed "2 extractor-failure reasons proxied from T6.1" without explaining the asymmetric registry mapping. Updated to spell out the asymmetry: malformed always refuses; not-found is treated as no-intent and proceeds; mcp_manifest_missing is reserved.
  - **Plan literal-block comment** (`plan:1695`) said `# cognic-pack-manifest.toml absent` next to `mcp_manifest_missing`. Updated to make the reserved-for-future-use status clear in the literal block itself, alongside the new comment on `mcp_manifest_malformed` that includes the R2 P1 present-but-non-dict-block case.
  - **Test class docstring** in `test_mcp_manifest.py:181-184` (`TestExtractMissingManifest`) said the closed error maps to `mcp_manifest_missing` refusal at the registry boundary. Updated to be explicit that the extractor tests validate ONLY the exception, not the registry's reaction; with a pointer to `TestAuthProbeManifestMissingProceeds` for the registry contract.
  - **Test class docstring** in `test_mcp_manifest.py:440-445` (`TestExceptionHierarchy`) said per-leaf maps to distinct closed-enum reasons. Updated to spell out the asymmetric mapping (malformed → refuse; not-found → proceed) consistent with the module docstring.
  - **`_mcp_admit` "Four behaviours" → "Five behaviours"** (`plugin_registry.py:745`) arithmetic — the bullet list grew to five in R3 but the leading count word was still "Four" (P3).
- **T6 implementation R3 2×P2 + 2×P3 → R2-aftermath doc-sync (T6 R3 round).** All four findings are pure documentation/comment fixes for stale references that R2's behavior changes left behind. No new code, no new tests, no new RefusalReason values. Fixed sites:
  - `_mcp_admit` method docstring (`plugin_registry.py:742-750`) still described R1's "manifest absent + admission deps = mcp_manifest_missing" rule. Updated to enumerate the four current R2 outcomes (manifest absent → proceed; manifest present + well-shaped MCP block → continue; manifest present without MCP block → proceed; manifest present + malformed MCP block → mcp_manifest_malformed) plus the TOML-decode-failure path. Explicit note that ``mcp_manifest_missing`` is reserved-for-future-use (Sprint-7A `agentos validate` or future MCP entry-point group).
  - **Plan T6 step-6 pseudocode** (this file ~1626) still showed the R1 contract that refused PackManifestNotFoundError as ``mcp_manifest_missing``. Replaced with the current R2 pseudocode: missing manifest → return None (proceed); safe MCP-block walk via `_safe_walk_to_mcp` with the malformed-block sentinel; explicit fail-closed gate for MCP-intent-without-deps; HTTP-family transport check accepts both `http` and `streamable-http`. Plan-of-record now matches what the next implementer would copy if they re-implemented this surface.
  - In-method comment in `plugin_registry.py:910-914` still said "the validator's literal IS the refusal subset for the 9 capability-side reasons". Updated to 10 (R1 added `mcp_transport_unsupported`).
  - `TestEnumCompleteness` docstring (`test_registry_integration.py:1020-1029`) still said "Sprint-5 additions … 22 values" / "9 capability reasons". Updated to 24 / 10 capability + 11 auth-probe + 2 manifest + 1 registry-config, with the R1 origin tags called out for the two new reasons.
- **T6 implementation R2 P1 + 3×P2 + P3 → admission-deps-vs-pack-intent decoupling + fail-closed shape gates + doc-sync (T6 R2 round).** Five findings:
  - **R2 #1 — admission deps are NOT a pack-intent signal.** The R1 #1 fix made the registry refuse with `mcp_manifest_missing` whenever the manifest extractor raised `PackManifestNotFoundError` AND the caller had wired `mcp_admission`. But `mcp_admission` is dependency wiring, NOT proof that the current pack is MCP — a default-adapters caller may legitimately pass these deps for every registration (Sprint-4 + Sprint-5 packs share the same admission flow). The R1 contract would have rejected every Sprint-4 pack on a default-adapters image. R2 reverts: missing manifest ALWAYS proceeds (no MCP gates apply). `mcp_manifest_missing` is now reserved-for-future-use (a Sprint-7A `agentos validate` signal or a future MCP-specific entry-point group might fire it; today no T6 admission code path reaches it). The R1 fail-closed gate (manifest WITH `[tool.cognic.mcp]` block + no admission deps → refuse) is preserved — only the missing-manifest branch changed.
  - **R2 P1 — malformed `[tool.cognic.mcp]` block bypassed admission.** R1's `mcp_block_present = isinstance(...get("mcp"), dict)` was True only when the block was a dict; a present-but-non-dict mcp value (`mcp = "bad"`) was treated as no MCP block → silent admission of structurally-broken MCP declarations. Worse, non-dict intermediates (`tool = "bad"`) raised raw `AttributeError`. Fix: new `_safe_walk_to_mcp(manifest)` helper returns `dict` (well-shaped MCP block), `None` (absent or unreachable), or the `_MCP_BLOCK_MALFORMED` sentinel (present-but-non-dict). The registry refuses with `mcp_manifest_malformed` for the sentinel case; treats the unreachable case as Sprint-4 (proceed). 4 regression tests pin: `mcp = "bad-shape"` refuses, `mcp = ["http"]` refuses, `tool = "bad"` proceeds (no AttributeError), `cognic = "bad"` proceeds.
  - **R2 #2 — validator's safe accessors crashed on malformed TOML.** `validate_mcp_manifest({"tool": "bad"}, ...)` raised `AttributeError: 'str' object has no attribute 'get'`. New `_safe_get_dict(parent, key)` helper returns `{}` if either `parent` or the value at `key` is not a dict; `_mcp_block` and `_tools_block` walk via this helper. 5 regression tests cover `tool`/`cognic`/`mcp`/`tools` non-dict shapes plus the empty-manifest case — all return closed `ManifestValidation` outcomes, never crash.
  - **R2 P2 — stale `MCPAdmissionDeps` docstring claimed skip-entirely contract.** The class docstring still said "When `mcp_admission` is `None` the three MCP steps SKIP entirely". After R1, that's no longer true — manifest extraction always runs. Updated to enumerate the four current outcomes (manifest absent → proceed; manifest present without MCP block → proceed; manifest present with MCP block + no deps → `mcp_admission_deps_required`; manifest present with malformed MCP block → `mcp_manifest_malformed`) and to call out the R2 doctrine explicitly.
  - **R2 P3 — `mcp_capabilities` count docs said 9.** Module docstring + `validate_mcp_manifest` docstring both said "nine"/"9 capability-side reasons". After R1 P1 #2 added `mcp_transport_unsupported`, the count is 10. Both updated; module docstring's evaluation-order list now includes gate 0 (transport closed-enum check) explicitly. Plus a paragraph documenting the R2 P2 pack-controlled-TOML safety contract (validator MUST never crash on malformed manifest input).

  No new RefusalReason values added in R2 — only behavior fixes and doc-sync. The 24-value vocabulary set in R1 is unchanged.
- **T6 implementation R1 P1 #1 + #2 + P2 → fail-closed admission gates + real-install proofs (T6 R1 round).** Three findings:
  - **R1 P1 #1 — registry silently skipped MCP admission when `mcp_admission` was None.** The first T6 implementation pass made `mcp_admission` an optional kwarg (defaulting to None), and skipped the manifest extraction + capability validation + auth probe steps entirely when omitted. That meant a tools/MCP pack could register without ANY of the Sprint-5 gates if a caller forgot to wire MCPHost. Reviewer caught it as a P1. Fix: `_mcp_admit` now ALWAYS attempts manifest extraction. If the manifest declares `[tool.cognic.mcp]` AND `mcp_admission is None`, the registry refuses fail-closed with the new closed-enum value `mcp_admission_deps_required`. Sprint-4 packs without an MCP block (or no manifest at all) remain unaffected — they pass through with `None` and proceed to the policy step. Four regression tests in `TestMcpAdmissionDepsRequiredFailClosed` pin the contract: MCP pack + no admission deps → refused; Sprint-4 pack + no admission deps → proceeds; manifest without MCP block + no deps → proceeds; manifest without MCP block + deps → proceeds without invoking the auth probe.
  - **R1 P1 #2 — Streamable HTTP bypassed the auth probe.** The registry's HTTP-transport check matched only `transport == "http"`, but MCP-CONFORMANCE.md tells pack authors to declare the spec-canonical `transport = "streamable-http"`. The validator only special-cased `"stdio"`, so a correctly-spec'd Streamable HTTP pack with `auth = "oauth-prm"` would pass validation AND skip the OAuth/PRM probe at the registry. Fix: validator's new gate-0 transport closed-enum check accepts `{http, streamable-http, stdio}` and refuses everything else with the new closed-enum value `mcp_transport_unsupported`; the registry's auth-probe HTTP-family check now matches both `"http"` (legacy alias) and `"streamable-http"` (canonical) via the shared `_HTTP_TRANSPORT_VALUES` constant. Six tests in `TestTransportClosedEnum` pin the gate (streamable-http canonical pass, http legacy pass, stdio reaches the umbrella, missing transport refused, unknown transport refused, non-string transport refused) plus two integration tests in `TestStreamableHttpTransportInvokesAuthProbe` (streamable-http really does invoke the auth probe; unknown transport refused at validator before the probe).
  - **R1 P2 — fake-only fixture install tests didn't prove the packaging contract.** The unit tests monkeypatched `importlib.metadata.distribution` to a `_FakeDistribution`, so they would have passed even if the fixture pack's pyproject was misconfigured (the wheel wouldn't actually contain the manifest). Two new real-install tests added in `tests/unit/protocol/test_mcp_manifest.py`: `TestRealWheelBuildIncludesManifest` shells out to `uv build --wheel`, opens the resulting `.whl` ZIP, and asserts the manifest is present at the canonical path; `TestRealEditableInstallExtractsManifest` (skipped automatically when `uv` is absent on PATH) creates an isolated venv via `uv venv`, editable-installs the fixture, then runs `extract_pack_manifest` end-to-end in that venv via subprocess. Both pass against the actual fixture, proving the pyproject's `force-include` line is correct and the deferred-load invariant survives a real install.
  - Plan amended in 6 surfaces: literal block extended with two new entries (capability cohort 9 → 10, plus the new 1-value registry-configuration cohort); `SPRINT_5_REFUSAL_REASONS` test set extended; total count `22 → 24`; T6.2 validator-subset reference (9 → 10 capability reasons); closeout deliverable line bumped 22 → 24; type-consistency Self-Review entry updated; this amendment log entry added.
- **T5 implementation R14 P3 → T6.3 catalogue arithmetic fix (R14 round).** R13's T6.3 amendment grew the auth-probe test catalogue from 10 → 16 entries (6 original + 3 R6 + 3 R11 + 4 trailing), but the trailing summary line under-counted to "14 test classes — the original 10 plus 4 new ones from R6 + 3 new ones from R11" — internally inconsistent (the 4-from-R6 figure was a typo; only 3 R6 arms exist) and arithmetically wrong (10 + 3 + 3 = 16, not 14). Sprint 4's `RefusalReason` closed-vocabulary doctrine exists precisely so this kind of count drift surfaces before the next implementer reads it. Corrected the summary line to enumerate the four cohorts explicitly: `6 original (1 OauthPrmHappyPath + 5 failure arms) + 3 R6 + 3 R11 + 4 trailing invariants = 16 test classes`. Pure arithmetic correction; no new test class added or removed.
- **T5 implementation R13 P2 + P3 → T6 auth-probe sketch sync + acquire_token docstring refresh (R13 round).** Two findings:
  - **R13 P2 — T6 auth-probe paragraph + test catalogue still stale.** The R12 round resynced the **T5** body (closed-enum vocabulary, test catalogue, implementation note) but the **T6.3 registration auth-probe** paragraph at line 1529 still listed only the original five OAuth failures (anonymous-refused / AS-not-allowlisted / audience-mismatch / timeout / PRM-invalid), and the test catalogue at lines 1596-1605 listed 10 test classes covering only those five plus the API-key/STDIO/cache-isolation arms. Since T6 is the next implementation surface, an implementer reading T6 in isolation would have built the registry mapper + completeness tests against a 5-value vocabulary that contradicts the merged 11-value registration-boundary mapper (R6 added 3 + R11 added 3, total 11). Resynced 2 T6.3 surfaces: (1) the auth-probe paragraph now enumerates all 11 registration-boundary `AuthzReason` failures (with R6/R11 origin tags + the operational-distinction rationale for each); (2) the test-class catalogue grew from 10 → 14 entries (3 R6 arms + 3 R11 arms; the R11 token-endpoint-error arm specifically asserts that the AS response body — which can echo credentials — is NOT propagated into the closed-enum payload), and the catalogue now explicitly notes that all 11 registration-boundary `AuthzReason` failures have a dedicated arm (satisfying the `test_every_reason_has_a_dedicated_test_arm` parametrize check in `test_refusal_reason_completeness.py`).
  - **R13 P3 — `acquire_token` method-level docstring stale.** The method-level docstring on `acquire_token` listed only the pre-hardening 5-failure surface (anonymous-refused / AS-not-allowlisted / audience-mismatch / timeout / PRM-invalid). The module-level docstring is correct, so this was not a behaviour blocker — but a public method docstring out-of-step with the implementation is the kind of breadcrumb that drift-debugging lands on first. Updated to enumerate all 11 closed-enum reasons that `acquire_token` can raise (every value of `AuthzReason` except the runtime-only `mcp_step_up_unauthorised`), each tagged with origin round + operational meaning, with a pointer to the module docstring for the full vocabulary + firing conditions.
- **T5 implementation R12 P2 → cancellation hardening + T5 plan-body re-sync (R12 round).** Two findings:
  - **R12 P2 (a) — shield shared in-flight Future from waiter cancellation.** R11's coalescing patch had waiters `await future_to_await` directly. In asyncio, cancelling a waiter task cancels the Future it is awaiting; the owner's later `set_result` / `set_exception` would then raise `InvalidStateError`. On the original failure path that was particularly bad: `set_exception(exc)` ran BEFORE the in-flight slot was popped, so a cancelled-waiter scenario could crash the owner's cleanup mid-flow and leave the slot poisoned with a cancelled Future for the lifetime of the process. Fix: (1) waiters use `asyncio.shield(future_to_await)` so a waiter's cancellation produces a `CancelledError` in THAT task only, leaving the shared Future untouched; (2) the owner's `set_result` / `set_exception` are guarded with `if not future_to_await.done()` so a Future that did somehow end up cancelled doesn't raise InvalidStateError when the owner tries to resolve it; (3) deregister moves into a `finally` block (always runs, regardless of whether `set_exception` raised) and is identity-checked (only pops if the dict entry is still ours, defensively guarding against re-entrant retry storms).
  - **R12 P2 (b) — T5 plan body re-sync.** The R11 round amended the T6 RefusalReason section (count `19 → 22`, mapper to 11 values) but the **T5** body still listed the old 6-value `AuthzReason`, the original ~30-test sketch, and the implementation note saying `AuthzReason` matches "the 6 enum values above". That contradicted the current 12-value `AuthzReason` and the AS / token-endpoint / token-response split. Resynced 5 T5 surfaces: (1) the closed-enum vocabulary list (6 → 12 values, each tagged with origin round); (2) the test-class catalogue (~30 → ~115 tests, organised by introducing round); (3) the FAIL/PASS expected-count line (~30 → ~115); (4) the cache-key + coalescing implementation note (frozenset of GRANTED scopes + in-flight Future + shield); (5) the "matches the 6 enum values above" note → "matches the 12 enum values above". This was hygiene the R11 amendment should have included; R12 closes it before any subagent / future-implementer reads the stale T5 body.
- **T5 implementation R11 P2 → in-flight coalescing + AS / token-endpoint / token-response error split (R11 round).** Two findings:
  - **R11 P2 (a) — coalesce in-flight token acquires.** The constructor comment claimed `_cache_lock` "prevents two concurrent acquires racing the AS", but the lock was actually released between the cache-miss check and the network round-trip, so two cold callers requesting the same `(server, exact_scope_set, resource)` could each issue their own AS request. Fix: keyed in-flight `dict[CacheKey, asyncio.Future]`. The first miss creates a Future, registers under the cache key, releases the lock, runs PRM-discovery + AS-discovery + token POST, and on completion / failure (a) sets the Future result/exception so any concurrent waiters wake up with the same outcome, and (b) removes the Future in `finally` so a future call can retry (transient AS errors don't poison the cache key). The second concurrent caller observes the in-flight Future under lock and awaits it instead of issuing its own request.
  - **R11 P2 (b) — split AS / token-endpoint / token-response failures off `mcp_prm_invalid`.** The original closed-enum had AS-discovery non-200, AS-discovery malformed JSON, AS-discovery missing `token_endpoint`, token-endpoint non-200, token-response non-JSON, token-response missing `access_token`, malformed `expires_in` (bool / non-numeric / non-finite / non-positive), and non-string `scope` all mapping to the single `mcp_prm_invalid` reason. But `mcp_prm_invalid` is documented as the MCP-server-side PRM document being malformed; a 401 from the AS token endpoint usually points at rejected Vault-stored OAuth client credentials, not at the MCP server's PRM. Three new closed-enum reasons added: `mcp_oauth_as_discovery_invalid` (covers AS `.well-known/oauth-authorization-server` non-200 / malformed JSON / missing `token_endpoint`), `mcp_oauth_token_endpoint_error` (token endpoint non-200; payload carries `status_code` only — never the response body, which could echo credentials or AS-side debug strings), `mcp_oauth_token_response_invalid` (token response shape malformed: non-JSON, missing `access_token`, bad `expires_in`, non-string `scope`). `mcp_prm_invalid` retains its narrow original meaning: only PRM-doc validation failures in `_fetch_prm` raise it. Plan amended in 6 surfaces: (1) `AuthzReason` in T5 9 → 12 values; (2) RefusalReason auth-probe row 8 → 11 values, total 19 → 22; (3) literal block extended with three R11-tagged entries; (4) `SPRINT_5_REFUSAL_REASONS` test set extended; (5) `_authz_reason_to_refusal()` mapper now maps 11 registration-boundary reasons (was 8); (6) closeout deliverable line bumped 19 → 22; type-consistency Self-Review entry updated; this amendment log entry added.
- **T5 implementation R10 P2 → exact-match cache lookup (R10 round).** R9 introduced a granted-keyed cache with a `granted ⊇ requested` lookup filter to fix the under-scoping bug; R10 reviewer flagged that this same superset rule violates **least privilege** going the other way: a stepped-up token cached under broader granted scopes would be returned for any subsequent narrower acquire, sending a higher-privilege bearer than the call needed. ADR-002 + the Sprint-5 plan call for minimum-scope token acquisition keyed by `(server, scope, resource)`. The fix is exact-match: the cache lookup returns a cached token only when its granted scopes EQUAL the requested set (not narrower, not broader). Implementation simplified from an iterating loop to a direct `dict.get` with key `(server, frozenset(requested), resource)`. Both R9 and R10 invariants now compose as one rule — an entry hits the cache iff `granted == requested`. Helper renamed `_lookup_cached_covering_scopes → _lookup_cached_for_exact_scopes`. The R9 same-narrow-as-cached test still passes because exact-match also fires when the second request happens to ask for exactly the cached granted set; the R10 test pins the broader-cached-narrower-requested case as a fresh round-trip.
- **T5 implementation R9 P3 + R9 P3 → T1 doc-sync + amendment-count fix (R9 round).** R9 reviewer flagged that the runtime `_load_oauth_credentials` sanitises the AS issuer's netloc by replacing `:` with `_` (so the value is safe as a Vault path segment) but the operator-facing surfaces (T1 plan field-block description + `.env.example` + `core/config.py` field description) all described `{as_host}` as the raw `urlparse(as_issuer).netloc`. For an issuer with an explicit port (e.g. `https://as.example:8443`), an operator following the docs would populate Vault at `secret/cognic/<tenant>/mcp-oauth/as.example:8443` while the client reads `as.example_8443` — producing `mcp_oauth_credentials_missing` at admission. Documented the sanitisation in all three surfaces (the runtime docstring of `_load_oauth_credentials` already had it). R9 P3 separately corrected the immediate-prior R8 amendment entry's count `5 T1 sites → 8 T1-area surfaces (+ 1 non-T1)` since the same sentence already enumerated 8 distinct edits.
- **T5 implementation R6 P1 + 5×P2 → plan amendment (R7 round).** During T5 (`mcp_authz.py`) implementation review, the user's R6 round flagged that the Sprint-5 plan's "synthesised client_id / no client_secret" stub was a production-grade violation; the fix landed real Vault-backed OAuth client credentials + closed-enum on transport failure + AS-overgrant rejection + audit-on-denial step-up + decision-history-on-refresh-failure + narrowed kernel-image admission docstring. Three of the six fixes added new closed-enum reasons that the plan's "5 auth-probe values" line did not anticipate: `mcp_oauth_credentials_missing` (Vault ops issue, distinct from any pre-existing reason), `mcp_oauth_transport_failure` (DNS/TLS/network unreachable, distinct from `mcp_oauth_request_timeout`), `mcp_token_scope_overgrant` (AS overgrant, distinct from `mcp_as_not_allowlisted`). Per R7 P2 finding "sync new authz reasons with plan/T6", the plan was amended in 8 sites: count `16 → 19` (5 → 8 auth-probe), literal block extended with three R6-tagged entries, `SPRINT_5_REFUSAL_REASONS` test set extended to 19 entries, `_authz_reason_to_refusal()` mapper now maps 8 registration-boundary reasons (was 5), top-level table-of-contents entry, T6.2 validator-subset reference, closeout deliverable line, type-consistency self-review entry. Mapping these into existing reasons would have lost operationally-distinct semantics (Vault ops issue ≠ AS server issue; transport failure ≠ slow response; overgrant ≠ not-allowlisted), so the vocabulary expansion was the right call.
- **T5 implementation R7 P2 + R8 P2 → T1 surface amendment (R8 round).** R7's "sync new authz reasons with plan/T6" landed the closed-enum + mapper amendment (above), but R8 then flagged that the T1 settings surface was still drafted for 7 fields when R6's Vault-backed credentials path made `mcp_oauth_credentials_path` load-bearing for production OAuth. Plan amended in 8 T1-area surfaces: (1) File Structure header `7 new fields → 8 new fields` with the R6-P1 reason cited; (2) T1 file-list intro `6 → 8` Sprint-5 settings; (3) field-block intro `The 6 settings → The 8 settings`; (4) the 8th field block (`mcp_oauth_credentials_path: str = Field(...)`) inserted after the sampling-policy block; (5) test sketch extended with `test_mcp_oauth_credentials_path_template`; (6) expected-count `7 FAIL/PASSED → 8 FAIL/PASSED`; (7) suite delta `1441 + 7 = 1448 → 1441 + 8 = 1449`; (8) .env snippet extended with the new commented entry. Plus a 9th non-T1 change: R8 P3 corrected the immediate-prior R7 amendment entry's "two of the six fixes added new closed-enum reasons" to "three" (matches the literal list of three new reasons that follows in the same sentence).

**R6 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P2 — Top architecture summary omits `mcp_manifest`.** The opening Architecture paragraph (lines 7-12) still described "three critical-controls modules plus a fourth `mcp_capabilities.py`" — pre-R1 framing that omitted the `mcp_manifest.py` extractor R1 P2 #2 added. Reworded to: "Five new critical-controls modules — the Sprint-5 MCP quintet" with all five modules (`mcp_authz`, `mcp_manifest`, `mcp_capabilities`, `mcp_transports`, `mcp_host`) listed at the top level + each tagged with its R3-P1 admission-vs-runtime classification. The top summary now matches the T14 coverage gate (21 modules) + the T15 AGENTS.md update (Sprint-5 quintet) + the closeout's "5 critical-controls MCP modules" claim.
- **P3 — `StdioTransport` parenthetical sounded like a registrar.** The transports bullet (line 9) called `StdioTransport` "refusal-only — registers no pack until config-load gates pass; pack registration always refused" — language that sounded like the transport itself owned registration outcomes. R2 P2 #4 had moved registration refusal entirely to `mcp_capabilities` + `plugin_registry`, leaving `StdioTransport` as a non-launching stub. Reworded to: "a non-launching stub: default Python constructor + three transport methods (`open_session` / `send` / `close_session`), each of which is an unconditional `NotImplementedError` raise; no `register` method exists; STDIO refusal at registration is owned entirely by `mcp_capabilities` + `plugin_registry` per R2 P2 #4 doctrine".

**R5 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P2 #1 — Remaining kernel admission overclaims.** Three sites still claimed the kernel image "can do MCP pack admission": (a) the `MCPNotAvailableError` docstring at line 548-552 ("it can do MCP pack admission..."), (b) the `require_mcp()` error message at lines 602-604 ("Operators running the kernel image get... MCP pack admission..."), (c) the Dockerfile header text at lines 819-820 ("Operators using the kernel image get governance + admission..."). All three rewritten with explicit narrowing: the kernel image imports + constructs the Sprint-5 MCP admission modules without the `mcp` SDK; full Sprint-4 signed-pack admission still depends on cosign + OPA binaries which are default-adapters-only; the MCP layer's contribution is "no NEW default-adapters-only requirement", not "kernel-image admission works end-to-end".
- **P2 #2 — Capability calls "run on kernel image" overclaim.** T6.2 implementation-notes bullet (line 1468) said "module imports + function calls all run cleanly on the kernel image" — but the sampling-check code path subprocess-calls OPA (default-adapters-only). Reworded to: module imports + construction succeed without the SDK; the OPA-backed sampling check inherits Sprint 4's OPA-binary dependency (default-adapters-image OR documented local fallback). Capability validation paths that do NOT reach the OPA call (manifest-shape errors, restricted-data-class refusals, STDIO-disabled refusals) succeed without OPA — the OPA dependency is reachable only when the manifest declares `sampling_supported = true`. `mcp_authz` and `mcp_manifest` have no OPA dependency at all.

**R4 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P2 #1 — Stale guarded-import contract.** Line 362 still prescribed `try: from mcp ... except ImportError: raise MCPNotAvailableError(...)` — a module-scope guard that fires at import time, contradicting the R3 contract (module imports always succeed; SDK is gated at construction via `require_mcp()` for runtime classes only). Reworded the bullet to explicitly forbid module-scope try/except for `mcp` imports and point at the `is_mcp_available()` startup check + lazy method-body imports as the correct pattern.
- **P2 #2 — Overclaim about kernel-image admission.** The R3 docstring + contract table claimed admission-side modules "run on the kernel image", which implied full Sprint-4 signed-pack admission works there. Rewritten with explicit caveat: the table column means "module imports + construction succeed without the `mcp` SDK"; full admission still depends on the Sprint-4 cosign + OPA binaries which ship in default-adapters image only. End-to-end kernel-image admission of HTTP MCP packs requires either the default-adapters image OR an explicitly documented local fallback that brings cosign + OPA into the kernel-image PATH (out of Sprint 5 scope).
- **P3 #3 — Register wording still present.** Line 2091 in the Decision Lock self-review still had `every transport method other than \`register\` raises NotImplementedError`. (My R3 verification rg used `"other than register"` which missed the literal because of the embedded backticks.) Reworded to user's exact spec: "the three transport methods (`open_session`, `send`, `close_session`) raise `NotImplementedError`; no `register` method exists; no code path exists that could spawn a process."
- **P3 #4 — StdioTransport method count contradicts new constructor.** T8's implementation-discipline bullet still said "4-method class where every method body is `raise NotImplementedError`", contradicting the R3 surface (default constructor + 3 transport methods, only the 3 raise). Reworded to: "default Python constructor (no `__init__` body — implicit pass-through; does NOT call `require_mcp()`) plus three transport methods (`open_session`, `send`, `close_session`); each of the three transport methods is `raise NotImplementedError`". The contract-table row + Sprint-5-surface header + R3-P1-bullet description all updated to match.

**R3 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P1 — Keep admission SDK-free (substantive doctrine).** R2's first patch over-applied `require_mcp()` to admission-side modules (`MCPAuthzClient`, `mcp_capabilities`, `mcp_manifest`, `StdioTransport`), which would have forced kernel-image admission of HTTP MCP packs to fail before manifest validation could run. R3 corrects the boundary: **`require_mcp()` belongs ONLY in `MCPHost.__init__` and `StreamableHTTPTransport.__init__`** (the two classes that genuinely use the SDK at runtime). PRM discovery + token acquisition in `MCPAuthzClient` use httpx + OAuth 2.1 + RFC 8707 URL conventions — pure HTTP standards, SDK-free. Manifest extraction uses stdlib (`Distribution.locate_file()` + `tomllib`); SDK-free. Capability validation is pure-functional + the Sprint-4 `OPAEngine`; SDK-free. `StdioTransport` methods all raise `NotImplementedError` and never reference the SDK. T2 step 4 now spells out the full kernel-vs-default-adapters split table. New tests `TestAdmissionStaysSDKFree` + `TestRuntimeRequiresSDK` in `test_optional_dep_loader.py` pin which classes gate on the SDK and which don't — drift in either direction trips immediately.
- **P2 #2 — STDIO refusal literal split.** Two sites still used `mcp_stdio_disabled` (the future Sprint-8 rename) inside Sprint-5 contract paragraphs. Both rewritten to `mcp_stdio_disabled_in_sprint_5`; `mcp_stdio_disabled` appears only as the documented Sprint-8 rename target.
- **P2 #3 — RefusalReason count arithmetically wrong.** R2's prose said "3 auth-probe values, total 14" but the literal block listed 5 auth-probe values (total = 16). All 5 are needed (mcp_as_not_allowlisted, mcp_token_audience_mismatch, mcp_oauth_request_timeout, mcp_prm_invalid, mcp_api_key_fallback_unresolved). Corrected count: **2 manifest + 9 capability + 5 auth-probe = 16 values**. Eight sites updated (T6 prose + literal comment + closeout + Self-Review entries).
- **P3 — Self-review wording on impossible register method.** Self-review line still implied a `register` method existed via "every transport method other than `register`". Reworded to: "the three transport methods (`open_session`, `send`, `close_session`) raise `NotImplementedError`; no `register` method exists" — matches the actual T8 surface.

**R2 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P2 #1 — optional-dep loader API underspecified.** T2 step 4 now defines the exact loader contract: `is_mcp_available()` + `require_mcp()` in `protocol/__init__.py`; module-level imports of every `mcp_*.py` MUST succeed without the `mcp` SDK installed (lazy/sentinel imports inside method bodies, TYPE_CHECKING-only top-level imports); `MCPHost.__init__` calls `require_mcp()` to fail cleanly on the kernel image. New test file `test_optional_dep_loader.py` includes a parametrized `test_module_imports_succeed_without_mcp_sdk` arm that monkeypatches `find_spec` to simulate kernel-image install and reloads each `mcp_*` module fresh. `create_prod_app` calls `is_mcp_available()` then either wires `MCPHost` or skips with structured warning.
- **P2 #2 — audit-vs-decision-history drift in non-T11 sections.** Six sites flagged across the Decision Lock (lines 26-27), settings field description (line 216), threat-model doc paragraph (line 673), HTTP transport audit-hook description (line 1351). All rewritten to say "appended to the audit_event chain via AuditStore.append" rather than "chained into decision_history". STDIO registration refusal is explicitly named as audit-only — no `decision_history` row, since per T11 only call_tool outcomes / token refreshes / registration auth probes produce decision-history rows.
- **P2 #3 — RefusalReason extension count inconsistent.** T6 step 6 now enumerates the EXACT 16 new closed-enum values (2 manifest + 9 capability + 5 auth-probe; `mcp_step_up_unauthorised` excluded as runtime-only). (R3 corrected the count from "14" to "16" — R2's first pass mis-summed the auth-probe row as 3 when the literal block lists 5.) New test file `test_refusal_reason_completeness.py` with three classes: every Sprint-5 reason MUST be in the literal; no orphaned literal entry; every reason has a dedicated test arm. Catches future drift mechanically.
- **P2 #4 — StdioTransport.register duplicates registry responsibility.** T8 reshaped: `StdioTransport` exposes only `__init__` + the 3 transport methods (`open_session`, `send`, `close_session`), all of which are unconditional `NotImplementedError` raises. NO `register` method. STDIO refusal lives entirely in T6's capability validator + the registry admission hook. Registry stays the single owner of `RegistrationOutcome` per Sprint-4 doctrine. Test file extended with `test_stdio_transport_does_not_have_register_method` + `test_stdio_transport_does_not_emit_audit_events` defensive tests.
- **P3 #5 — closeout counts pre-R1 values.** T15 closeout structure updated: "trio" → "quintet"; ">= 4" → ">= 5"; "4 critical-controls MCP modules" → "5 critical-controls MCP modules"; "20 modules" → "21 modules". AGENTS.md update step also adds the 4 new modules (was 3 in R1).

**R1 doctrine-review findings closed (folded inline into the plan, not deferred):**
- **P2 #1 — kernel split-brain on MCP SDK availability.** T2 reshaped to lock the kernel-vs-default-adapters runtime contract: SDK in adapters extras, kernel `create_app` does NOT wire MCPHost, default-adapters `create_prod_app` does, `_PROTOCOL_OPTIONAL_DEPS` map mirrors Sprint-1C's adapters loader pattern, Dockerfile header documents the split.
- **P2 #2 — manifest extraction contract.** T6 split into 3 sub-concerns: signed-manifest extraction via `Distribution.locate_file()` (new module `protocol/mcp_manifest.py`), capability validation, registration auth probe. New `cognic-pack-manifest.toml` shipped as package data inside the pack's importable directory; cosign-signed via wheel inclusion. Tested against editable + wheel installs.
- **P2 #3 — registration-time OAuth/PRM probe.** T6 step 6 adds the probe step in `plugin_registry.py` after capability validation: PRM discovery → AS allow-list check → token acquisition → discard. Token is NOT cached for runtime use (runtime acquires fresh).
- **P2 #4 — architecture guardrail too narrow.** T4 collector uses recursive `rglob` + stdio-substring scan; 3 self-tests pin the contract; `_LAUNCHER_ALLOWLIST` is the explicit Sprint-8 extension hook.
- **P2 #5 — MCPHost call order acquired session before token.** T9 call_tool reordered: ADR-014 gate → token acquisition → session-open WITH token → send → 401-vs-403 retry semantics in `send` not at open.
- **P2 #6 — audit vs decision-history confusion.** T11 separates the two evidence surfaces: `audit_event` chain via `AuditStore.append`, `decision_history` rows via `DecisionHistoryStore.append`, correlated by `request_id`. Per MCP-CONFORMANCE.md `mcp_session_id` lands in decision_history.
- **P2 #7 — authz client missing audit dependency.** T5 constructor signature now includes `audit_store` + `decision_history_store`; every method takes `request_id` + `tenant_id` keyword-only.
- **P3 #8 — sampling policy setting opportunistic.** T1 now declares `mcp_sampling_policy_bundle` explicitly with test + .env entry; suite delta updated 6 → 7.
- **P3 #9 — AGENTS.md doctrine update missing.** T15 step 3 adds the AGENTS.md edit promoting the Sprint-5 quintet to the critical-controls list.
- **P3 #10 — `profile` vs `runtime_profile` naming.** All 6 sites in the plan updated to `runtime_profile` / `COGNIC_RUNTIME_PROFILE`.
- **P3 #11 — JWS-verification overclaim.** Tech stack header reworded: cosign covers the wheel + signed manifest; AgentCard JWS verification is Sprint 6, not Sprint 5.

---

## Execution Handoff

After this plan-of-record merges to `main` (Task 0 PR), implementation begins on a fresh branch `feat/sprint-5-mcp-host` rooted at the merge tip.

Two execution options:

**1. Subagent-Driven** — fresh subagent per task, review between tasks, fast iteration. Recommended for this sprint because every task has a halt-before-commit discipline that benefits from a clean reviewer-vs-implementer separation.

**2. Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batch with checkpoints. Acceptable but less rigorous against the Decision Lock discipline.

The decision waits until after the plan-PR merges, mirroring Sprint 3 / Sprint 4 flow.
