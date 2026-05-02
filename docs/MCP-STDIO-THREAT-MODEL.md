# MCP STDIO Threat Model

**Status:** Authoritative reference for why STDIO is a restricted MCP transport in Cognic AgentOS, what the four gates from [ADR-002 §"MCP STDIO threat model"](adrs/ADR-002-mcp-plugin-protocol.md) mean operationally, and what Sprint 5 enforces vs. what it deliberately does NOT enforce.

This document complements [`ADR-002`](adrs/ADR-002-mcp-plugin-protocol.md) (MCP plugin protocol) and [`ADR-004`](adrs/ADR-004-sandbox-primitive.md) (sandbox primitive — Sprint 8 dependency). Pack authors and bank operators read this to know why STDIO is hard-disabled in Sprint 5; reviewers (Sprint 7B) consult it when evaluating any pack that declares `[tool.cognic.mcp].transport = "stdio"`.

## 1. Background — April 2026 MCP supply-chain disclosures

In April 2026, **OX Security published a series of vulnerability disclosures** for MCP host implementations across the ecosystem. **Cloud Security Alliance later published a research note analyzing the systemic risk** the disclosures surfaced and corroborating OX Security's findings. The disclosures share a common pattern:

> A model-controlled string (or a string from a remote pack manifest, a user input, or a configuration file) flows into the host process's command-launch path for an MCP STDIO server. Because the launch is `subprocess.Popen` with shell-style argument construction or insufficient argv quoting, a crafted input becomes **remote code execution** in the host process — the AgentOS process, in our case.

**AgentOS's response** (codified in [ADR-002](adrs/ADR-002-mcp-plugin-protocol.md) §"MCP STDIO threat model" amendment, April 2026) treats **every STDIO launch as untrusted by default** until the host can prove four things at registration time: (a) the launch command is statically declared in a signed manifest, (b) the command is on an operator-curated allow-list, (c) the launch happens inside a sandbox, (d) environment variables are bounded to a manifest-declared allow-list. The four-gate model is the doctrine ADR-002 adopts — it is the AgentOS response, not a recommendation we are quoting from a third party. The OX Security disclosures (corroborated by Cloud Security Alliance's subsequent systemic-risk analysis) motivated the response; the gates themselves are AgentOS's prescription.

## 2. Threat model

### Adversary capability

The adversary controls **at least one** of:

- **The MCP server pack itself** — a malicious pack distributed via the cognic plugin channel, signed under a trusted-but-compromised key, whose manifest declares a hostile command.
- **The model output** — string content the LLM produces that flows through the agent into MCP tool dispatch.
- **A configuration file** — operator-readable config (`.env`, Vault entries) that an attacker has tampered with via a separate vector.
- **User input** — string content the operator (or end user) provides through a UI / API.
- **A remote pack channel** — the MCP server is fetched from a remote registry whose contents an attacker can substitute.

### Defended asset

- **AgentOS host process integrity** — the bank-deployed process running the kernel + (optionally) default-adapters image.
- **Tenant data isolation** — bank-specific data (customer PII, payment authority, regulator communications) inside the AgentOS process.
- **Cross-tenant isolation** — preventing one tenant's pack from escalating into another tenant's data path on the same AgentOS deployment.

### Out-of-scope

- **Ransomware on the host OS** outside the AgentOS process (covered by the bank's host-OS security perimeter, not this threat model).
- **Supply-chain attacks on the kernel image itself** — covered by [ADR-016](adrs/ADR-016-supply-chain-controls.md) + Sprint-4 cosign verification of the AgentOS distribution.
- **MCP Streamable HTTP transport** — that's the production default per ADR-002, with its own threat model in §"MCP Authorization" (OAuth/PRM, RFC 8707, audience validation). This document is STDIO-specific.
- **Process spawning under the sandbox primitive** — Sprint 8 lifts this restriction; until then, the threat model assumes "no STDIO process is ever spawned in production".

## 3. The four gates from ADR-002 §"MCP STDIO threat model"

Restated verbatim from ADR-002 (the doctrine source-of-truth):

> AgentOS therefore enforces:
>
> 1. **Streamable HTTP MCP is the production default.** Production deployments treat STDIO as opt-in only.
> 2. **STDIO is allowed only when ALL of the following are true:**
>    - Pack ships a **signed static manifest** declaring its launch command + arguments + env vars
>    - The launch command is on a **per-tenant static command allow-list** (operator-curated, RBAC-gated to change)
>    - The launch happens inside a **sandbox profile** (per ADR-004) with bounded filesystem, bounded egress, bounded resource caps
>    - **Bounded environment variables** — no `os.environ` passthrough; only the explicit allow-list from the manifest
>    - **Audit event emitted for every launch** — pack identity, command, arguments, sandbox-id, outcome — chained into `decision_history`
> 3. **No user-, model-, or remote-pack-controlled command or argument may reach process execution.** The host validates the manifest against the allow-list at registration, then ignores any subsequent attempt to override.
> 4. **Any STDIO launch failing any of (1)-(3) is refused at registration.** No silent fallback to permissive behavior.

**Reading guide for the quote above:** the bullet "**Audit event emitted for every launch** — chained into `decision_history`" describes **launch-time** behaviour (Sprint 8 onward, when a sandboxed launcher actually spawns a process). It does NOT describe Sprint-5 STDIO **registration-refusal** behaviour. Per Sprint-5 T11 doctrine, registration refusals are written **only** to the `audit_event` chain via `AuditStore.append`; they do **not** produce `decision_history` rows (decision-history rows are reserved for `call_tool` outcomes, OAuth token refreshes, and registration-time auth probes). §4.4 below gives the precise Sprint-5 audit schema. When Sprint 8 lands the launcher, the launch-time audit (with its sandbox-id + outcome payload) is what populates the `decision_history` correlation per ADR-002 — that contract is forward-looking from Sprint-5's perspective, not active in this sprint.

## 4. Sprint-5 enforcement (this sprint)

Sprint 5 enforces every gate that does NOT require process spawning. Concretely:

### 4.1 Manifest validation at registration (T6 capability validator)

Per the [Sprint-5 plan §T6.2](superpowers/plans/2026-05-02-sprint-5-mcp-host.md): `protocol/mcp_capabilities.py:validate_mcp_manifest()` operates on the parsed `[tool.cognic.mcp]` block (extracted by `protocol/mcp_manifest.py` from the pack's signed `cognic-pack-manifest.toml`) and refuses on any of the reasons below. **Precedence order**: the more specific defects fire first; the umbrella `mcp_stdio_disabled_in_sprint_5` only fires when an otherwise-valid STDIO declaration would still not be launchable in Sprint 5. Tests assert against the *most specific* applicable reason — getting the wrong reason past CI is a contract violation, not a near-miss.

1. **`mcp_stdio_manifest_incomplete`** — STDIO declaration missing `command` / `args` / `env_allowlist`. Manifest must be fully static; partial declarations are a registration-time defect. (Fires before any of the lower-precedence reasons below.)
2. **`mcp_stdio_manifest_shell_metacharacter`** — command string contains any of `;`, `|`, `&`, backticks, `$()`, `<`, `>`, redirection operators. Even with sandboxing, shell metacharacters in argv are a smell that the manifest was generated from non-static input. (Fires before allow-list lookup so an unsafe command is rejected before the lookup runs.)
3. **`mcp_stdio_command_not_allowlisted`** — declared command is not on the per-tenant Vault-stored allow-list at `secret/cognic/{tenant}/stdio-command-allowlist`. RBAC-gated to change per ADR-002 gate 2. (Fires before the umbrella so operators see the precise allow-list miss, not the umbrella.)
4. **`mcp_stdio_disabled_in_sprint_5`** — the **umbrella refusal**. Fires only when every more-specific check above passes (manifest complete, no shell metacharacters, command on the allow-list) but the sandbox primitive (Sprint 8) is still absent. **This is the Sprint-5 Decision Lock at the manifest layer**: an otherwise-valid STDIO declaration cannot launch in Sprint 5 regardless of any other config.

### 4.2 Config-load fail-fast (T8 sandbox-availability check)

In `core/config.py`, at settings construction:

- If `runtime_profile == "prod"` AND `mcp_stdio_enabled == True` AND `cognic_agentos.sandbox.runtime` is not importable (it doesn't exist in Sprint 5) → raise `SandboxNotAvailableError` at startup.
- This is **fail-fast at startup**, not at first invocation. Operators who misconfigure see the error immediately rather than discovering it weeks later when an STDIO pack registers.
- Dev profile (`runtime_profile == "dev"`) merely logs a warning if `mcp_stdio_enabled == True` without sandbox; pack registration still refuses (the manifest-validator gate above fires regardless).

### 4.3 Signature integrity (Sprint-4 boundary, inherited)

Unsigned wheels — and therefore unsigned manifests-shipped-inside-the-wheel — are refused by `protocol/trust_gate.py` (cosign signature verification) before any Sprint-5 code path runs. Sprint 5 does NOT re-implement signature verification at the manifest layer; it inherits the Sprint-4 cosign trust gate.

### 4.4 Audit emission

Every STDIO refusal appends an `audit.stdio_launch_refused` event to the `audit_event` chain via `AuditStore.append`. Payload (per [Sprint-5 plan §T11](superpowers/plans/2026-05-02-sprint-5-mcp-host.md)):

- `pack_id` (signed distribution identity)
- `pack_signature_digest`
- declared command (truncated to 256 chars; defensive against payload bloat)
- `refusal_reason` (one of the closed-enum `mcp_stdio_*` values)
- `tenant_id`
- `request_id` (correlator)

**STDIO registration refusal is audit-only** — no `decision_history` row is written for STDIO refusals. Per Sprint-5 T11, decision-history rows are reserved for MCP `call_tool` outcomes, OAuth token refreshes, and registration *auth probes* (the OAuth/PRM probe Sprint 5's `mcp_authz` performs at registration). STDIO refusal happens upstream of the auth probe — auth is moot when the manifest itself fails validation.

## 5. Sprint-5 explicit non-enforcement

These are the gates Sprint 5 deliberately does NOT enforce — Sprint 8 lifts each one:

- **Sprint 5 does not spawn any process. Period.** Every STDIO pack registration refuses. The Decision Lock from the [Sprint-5 plan-of-record](superpowers/plans/2026-05-02-sprint-5-mcp-host.md) §"Decision Lock — Option C" is what allows this doctrine to ship without process-spawn risk.
- **Sprint 5 does not implement env-allowlist application.** It only validates the declaration shape. Sprint 8 will apply the allow-list when the launcher spawns the process.
- **Sprint 5 does not implement sandbox-profile lookup.** The config-load check above only verifies whether the sandbox runtime module is importable. Sprint 8 wires sandbox-profile resolution + boundary enforcement.
- **Sprint 5 does not run a sandboxed launcher.** `protocol/mcp_transports.StdioTransport` exposes only three transport methods (`open_session` / `send` / `close_session`), each of which is an unconditional `NotImplementedError` raise. No `register` method exists; registration refusal is owned entirely by the registry + capability validator.

## 6. The architecture test as backstop

Even if a future maintainer accidentally adds a `subprocess.run` (or `os.exec*`, `os.spawn*`, `os.posix_spawn*`, `os.system`, `os.popen`, `asyncio.create_subprocess_exec`, `asyncio.create_subprocess_shell`, `multiprocessing.Process`, or `shell=True` kwarg) somewhere under `protocol/mcp_*` or any module whose path contains `stdio`, the architecture test at `tests/architecture/test_mcp_stdio_no_subprocess.py` (Task 4) trips and CI fails.

The test walks the AST of every matching module recursively (covering top-level files, nested submodules under any future `protocol/mcp_stdio/` package, and renamed modules where the `mcp_` prefix has been dropped but `stdio` survives in the path). Three self-tests pin the collector contract: top-level, nested-submodule, and renamed-module detection.

The test is mechanical, fast (~200ms), and lives at the architecture-doctrine boundary — it expresses "Sprint 5 STDIO ships no launch path" as code, not as a docstring promise. Tripping it in Sprint 8 is correct (when the launcher lands at `protocol/mcp_stdio_launcher.py`, the test's `_LAUNCHER_ALLOWLIST` set gets updated to allow `subprocess` in the new launcher module ONLY). Tripping it in any other sprint is a doctrine violation that needs explicit review.

## 7. Sprint-8 hand-off

When the sandbox primitive (per ADR-004) lands in Sprint 8, the deferred work is a single concrete addition:

1. **New module** `src/cognic_agentos/protocol/mcp_stdio_launcher.py` — the sandboxed `launch()` method that spawns the validated command inside the sandbox boundary, with the env-allowlist applied.
2. **Architecture-test allow-list** updated to exclude `mcp_stdio_launcher.py` from the subprocess-import ban (the only module allowed to import process-spawn primitives).
3. **`mcp_stdio_enabled` default for `dev` profile** flipped from `false` to `true`. Production stays `false` until operator explicitly opts in PLUS sandbox available PLUS four-gate manifest validates.
4. **Registry-side STDIO gate** in `protocol/mcp_capabilities.py` switches from "always refused" to: refuse unless (a) `mcp_stdio_enabled=true` AND (b) sandbox runtime importable AND (c) four-gate manifest validates AND (d) command on per-tenant allow-list. Same closed-enum reasons; the `mcp_stdio_disabled_in_sprint_5` literal value gets renamed to `mcp_stdio_disabled` (Sprint-8 closeout edit).
5. **Audit event vocabulary extended** with `audit.stdio_launch_completed` + `audit.stdio_launch_failed` + `audit.stdio_launch_timeout` alongside the existing `audit.stdio_launch_refused`. Sprint-5 payload schema is the stable foundation; Sprint 8 adds peer event types, doesn't redesign.
6. **Integration tests under the sandbox runtime** that prove launch happens inside the sandbox boundary, env-allowlist enforced, command-allowlist enforced, breach attempts fail closed.

The Decision Lock from Sprint 5 is what allowed this hand-off contract to be clean. Sprint 8's job is to add the launcher; everything else (manifest validation, command-allowlist lookup, env-allowlist parsing, threat-model documentation) is settled here.

## 8. Negative-path canary test reference

`tests/unit/protocol/test_mcp_no_user_controlled_command.py` (Sprint-5 Task 13) is the runtime canary for this threat model. It deliberately attempts to inject a user-controlled command or argument through every reachable code path and asserts every one is refused at every entry point. Specifically:

- Manifest declared command containing `; rm -rf /` → refused with `mcp_stdio_manifest_shell_metacharacter`.
- Manifest declared command interpolating `{user_input}` → refused at registration (the manifest must be statically declared per ADR-002 gate 1; runtime substitution is a doctrine violation).
- Tool argument that resembles a command-line argument (`--exec ...`) reaching dispatch → no special handling; refused upstream by the transport before dispatch can fire.
- Direct invocation of `StdioTransport.open_session` / `send` / `close_session` → `NotImplementedError`. No code path exists that could spawn a process.
- Plus ~20 additional parametrized arms enumerating every reachable surface from the threat model above.

This test is the runtime backstop that complements the architecture test (Task 4): even if a future maintainer somehow evades the static-import check (e.g., via `__import__("subprocess")` or `exec()` of a string-built import), the canary test trips on the resulting refusal vector — the manifest validator + transport-method `NotImplementedError` shapes hold regardless of how the caller constructed the request.

If the canary test fails, the threat model is breached. CI fails the build; the offending change is reverted before merge.

## Cross-reference

- [`ADR-002`](adrs/ADR-002-mcp-plugin-protocol.md) — MCP plugin protocol; STDIO four-gate doctrine source-of-truth
- [`ADR-004`](adrs/ADR-004-sandbox-primitive.md) — sandbox primitive (Sprint-8 dependency for the launcher)
- [`ADR-016`](adrs/ADR-016-supply-chain-controls.md) — supply-chain controls (cosign verification of the wheel that ships the manifest)
- [`docs/MCP-CONFORMANCE.md`](MCP-CONFORMANCE.md) — capability matrix Sprint 5 enforces (resources optional, sampling default-deny, restricted-data-class refusals)
- [`docs/superpowers/plans/2026-05-02-sprint-5-mcp-host.md`](superpowers/plans/2026-05-02-sprint-5-mcp-host.md) — Sprint-5 plan-of-record (Decision Lock + three guardrails)
- `tests/architecture/test_mcp_stdio_no_subprocess.py` (Sprint-5 Task 4) — architecture-test backstop
- `tests/unit/protocol/test_mcp_no_user_controlled_command.py` (Sprint-5 Task 13) — runtime canary
