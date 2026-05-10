# Sprint 7A2 — Hook Packs + Runtime Hook Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add **hooks as a first-class plugin pack kind** alongside tools / skills / agents. Sprint-7A2 lands the SDK + CLI authoring surface for hook packs, the runtime hook registry + dispatcher, and the ADR-017 DLP pre/post wiring — so Sprint-7B's bank-pack lifecycle API can model `tool | skill | agent | hook` from day one without a kind-schema migration.

**Architecture.** Hook packs are deterministic governance extensions (NOT Layer C agent behavior). They ship through the same signed-pack pipeline as tools / skills / agents (cosign + 7-attestation bundle + JWS-not-required since hooks have no AgentCard); they expose a closed-phase taxonomy (Wave-1: `dlp_pre` + `dlp_post`); they run inside the runtime via a verified registry + a deterministic dispatcher with explicit ordering, timeout, failure policy, and audit linkage.

**Tech stack.** Python 3.12; `typer` (CLI scaffolder extension); `joserfc` (already pinned for AgentCard JWS — hook packs don't ship JWS but may share the trust-root machinery); existing `protocol.plugin_registry` admission path extended; existing `core.audit` chain consumed for hook decision evidence.

**Planning-format note.** This plan follows the repo's Sprint-7A plan-of-record style (paragraph-per-task with doctrine locks at the top, ADR amendment slate, and reviewer-strict halt-before-commit annotations) rather than the strict 2-5 minute checkbox-step format from the `superpowers:writing-plans` skill. The choice is intentional: Sprint-7A shipped successfully under this style, and Sprint-7A2 should remain consistent with shipped repo precedent. **Implementation agents must still decompose each task into micro-steps during execution** — the paragraph format describes the contract; the executing agent (subagent-driven-development per task) breaks it down into Red → Verify-Red → Green → Verify-Green → Refactor → Commit cycles.

---

## Doctrine Locks (locked before any code)

These seven items are locked at plan-of-record; reviewer rounds may amend them but no implementation begins until each is settled.

### Doctrine Lock A — Hook pack kind + manifest shape

**Decision.** `kind = "hook"` joins `tool / skill / agent` as the **4th first-class pack kind**. The pack manifest layout mirrors the Sprint-7A canonical block layout plus one new top-level `[hooks]` block:

```toml
[pack]
pack_id = "cognic-hook-example-dlp-precheck"
schema_version = 1
kind = "hook"

[identity]
agent_id = "did:web:example.com:hooks:dlp_precheck"
display_name = "Example DLP Precheck Hook"
provider_organization = "..."
provider_url = "..."
agent_card_url = "..."          # hook packs reuse the identity surface but
                                # do NOT ship an AgentCard JWS (no
                                # `agent_card_jws_path` field). ADR-008
                                # amendment captures this.
oasf_capability_set = ["hook.dlp.v1"]

# Hook packs do NOT declare [a2a] (they're not A2A-speaking) and do
# NOT declare [mcp] (they're not MCP-tool-shaped); the validator
# explicitly forbids these blocks for kind="hook" so no caller
# falsely assumes runtime A2A/MCP wiring.

[data_governance]
data_classes = ["public"]       # hook packs that themselves touch governed
                                # data MUST declare it; the dispatcher
                                # cross-checks the calling pack's contract.
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = []          # hook packs are normally egress-free.

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = [
    "attestations/cosign.sig",
    "attestations/bundle.sigstore",
    "attestations/sbom.cdx.json",
    "attestations/vuln-scan.json",
    "attestations/license-audit.json",
    "attestations/slsa-provenance.intoto.json",
    "attestations/intoto-layout.json",
]

[hooks]
# Each entry binds a stable hook_id to a phase. Hook IDs are the
# binding surface ADR-017's [data_governance].dlp_pre_hooks /
# dlp_post_hooks reference. T11 cross-checks every hook_id named in
# any pack's [data_governance].dlp_*_hooks resolves to a registered
# hook in the verified hook registry.
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"   # closed-enum; controls dispatcher order
timeout_seconds = 5.0                # hook-pack-author-declared upper bound
fail_policy = "fail_closed"          # closed-enum; "fail_closed" is Wave-1
                                     # default for data-governance phases.
                                     # "fail_open" is REFUSED by validator
                                     # for any phase where ADR-017 mandates
                                     # fail-closed.
```

**Rationale.**
- Single top-level `[hooks].declarations` array (TOML array-of-tables) — mirrors the Sprint-7A canonical top-level block shape; dual-path lookup also accepts legacy `[tool.cognic.hooks]` per R23 doctrine.
- `hook_id` is the binding surface. Multiple hooks per pack are allowed (one entry-point under `[project.entry-points."cognic.hooks"]` per declared `hook_id`).
- `phase` is closed-enum (`dlp_pre` / `dlp_post` Wave-1). Future phases (memory pre/post per ADR-019; escalation pre per ADR-014; egress pre per ADR-017's egress allow-list) land in follow-up sprints.
- `ordering_class` is closed-enum; the dispatcher's deterministic order resolves first by phase, then by `ordering_rank` ascending (the rank table at `cli/_governance_vocab.HOOK_ORDERING_RANK` — every `HookOrderingClass` maps to an integer rank), with ties broken by `hook_id` alphabetic. Pack authors don't write absolute integer priorities; they pick a class, and the rank table makes the position deterministic regardless of class-name spelling.
- `timeout_seconds` is pack-author-declared but a Settings-side ceiling (`Settings.hook_max_timeout_s`, default 30s) caps it.
- `fail_policy` is closed-enum (`fail_closed` default). `fail_open` requires the calling pack's `[data_governance]` to declare an explicit `fail_open_exception` phase + reason — refused at validate time otherwise.

### Doctrine Lock B — `cognic.hooks` entry-point contract

**Decision.** Pack authors declare hooks via `[project.entry-points."cognic.hooks"]` with **one entry per declared `hook_id`**:

```toml
[project.entry-points."cognic.hooks"]
redact_pii_in_input = "cognic_hook_example_dlp_precheck.hook:RedactPiiHook"
```

The validator cross-checks every entry-point key matches exactly one `[hooks].declarations[].hook_id` (and vice versa). The wheel-integrity helper `_wheel_integrity.py` already validates the entry-point shape; the kind-derivation table needs `cognic.hooks → "hook"` added.

### Doctrine Lock C — Hook SDK base API

**Decision.** New module `src/cognic_agentos/sdk/hook.py` with:

```python
class HookPhase(Literal):
    """Closed-enum hook phase. Wave-1 narrow."""
    # "dlp_pre" | "dlp_post" — only.

@dataclass(frozen=True, slots=True)
class HookContext:
    hook_id: str
    phase: HookPhase
    pack_id: str            # the calling pack — NOT the hook pack
    tenant_id: str
    request_id: str
    trace_id: str | None
    parent_trace_id: str | None
    manifest_data_classes: tuple[str, ...]
    manifest_purpose: str
    # Payload contents are NOT carried on context — the dispatcher
    # passes them as a separate argument to _invoke() so context can
    # be safely logged without payload material leaking to audit.

@dataclass(frozen=True, slots=True)
class HookResult:
    decision: Literal["pass", "redact", "mask", "refuse"]
    redacted_payload: bytes | None  # populated for "redact" / "mask"
    policy_reason: str | None        # closed-enum literal; required for
                                     # "refuse"; otherwise None
    audit_metadata: dict[str, Any]   # token-free; safe to persist

class Hook(abc.ABC):
    """Base class for cognic.hooks entry-point implementations.

    Subclasses declare hook_id + phase as ClassVar fields, override
    _invoke(context, payload) for the actual work. Public `invoke()`
    is @final + __init_subclass__-guarded (mirrors Tool / Skill
    pattern); subclasses cannot bypass the SDK validation seam via
    mixin smuggling.
    """
    hook_id: ClassVar[str]
    phase: ClassVar[HookPhase]

    @final
    async def invoke(
        self, context: HookContext, payload: bytes
    ) -> HookResult:
        # SDK base: validates context shape + payload non-None +
        # delegates to _invoke + validates HookResult shape on return
        # before passing back to the dispatcher.
        ...

    @abc.abstractmethod
    async def _invoke(
        self, context: HookContext, payload: bytes
    ) -> HookResult:
        raise NotImplementedError
```

The `Hook` base is **public API**, under Doctrine E halt-before-commit (broader than the critical-controls floor — public-API stability matters separately from the gate).

### Doctrine Lock D — Runtime hook registry/dispatcher boundary

**Decision.** Two new modules under `src/cognic_agentos/packs/hooks/`:

- **`registry.py`** — `HookRegistry` admission gate. Only verified hook packs register (consume the existing Sprint-4 `protocol/plugin_registry.py` admission orchestrator's verified-pack list). Indexed by `(phase, hook_id)`; duplicate hook IDs across packs refuse fail-closed; stale digests (post-pack-revoke) refuse fail-closed. The registry is **single-writer at admission**; no runtime mutation after the registration path completes.
- **`dispatcher.py`** — `HookDispatcher` deterministic phase dispatcher. Single-writer for the dispatch loop. For each (phase, ordered hook list), invokes hooks in deterministic order (`ordering_rank` ascending per `cli/_governance_vocab.HOOK_ORDERING_RANK`, ties broken by `hook_id` alphabetic), enforces per-hook timeout via `asyncio.wait_for` + SIGKILL/cancellation, applies failure policy (fail_closed default), emits audit + decision-history rows for every hook decision, and short-circuits the dispatch chain on the first `decision="refuse"`.

**Boundary**: registry owns admission; dispatcher owns runtime decision. The two never share mutable state — the dispatcher reads an immutable snapshot of `(phase, hook_id) → HookEntry` at dispatch entry. A self-registering hook (e.g., a hook that calls back into the registry during `_invoke`) cannot extend the dispatcher's iteration target — the snapshot is taken once per dispatch call.

### Doctrine Lock E — ADR-017 DLP pre/post hook failure policy

**Decision.** Five closed-enum failure modes, all routed through `payload.failure_mode` on `dispatch_hook_failed` audit/decision-history rows:

| Failure mode | Trigger | Outcome |
|---|---|---|
| `hook_timeout` | `asyncio.wait_for` exceeded `min(manifest.timeout_seconds, Settings.hook_max_timeout_s)` | fail-closed; emit audit + decision-history; refuse the calling-pack invocation (HTTP 503 / refusal envelope). |
| `hook_exception` | `Hook._invoke()` raised any unhandled exception (caught at dispatcher; subclasses NEVER see the parent's catch logic) | fail-closed; same. |
| `hook_malformed_result` | `Hook.invoke()` returned a non-`HookResult` shape OR a `HookResult` with internally-inconsistent fields (e.g., `decision="redact"` with `redacted_payload=None`) | fail-closed; same. |
| `hook_policy_refused` | Hook returned `HookResult(decision="refuse", policy_reason=<closed-enum>)` legitimately | fail-closed; emit audit; refuse the calling-pack invocation with the hook's `policy_reason` propagated to the refusal envelope. |
| `hook_payload_unscannable` | Payload exceeded a depth/size budget the dispatcher imposes BEFORE the hook runs (mirrors A2A wave2 classifier doctrine) | fail-closed without ever invoking the hook; emit audit. |

**ADR-017 line 97 amendment**: change `cognic_agentos.dlp.DLPHook` → `cognic_agentos.sdk.hook.Hook` (broaden from DLP-only to a generic Hook surface). This is a doctrine amendment captured at T13 (closeout) alongside the AGENTS.md update; Sprint-7A2 carries the amendment note in the closeout doc.

**Payload-contents-never-logged invariant**: the `payload` argument is opaque bytes; the dispatcher computes `hashlib.sha256(payload).hexdigest()` for the audit row's `policy_input_digest` field but NEVER includes the payload bytes themselves in any audit / decision-history / log line. Pinned by an AST-walk regression in `tests/architecture/test_hook_payload_never_logged.py`.

### Doctrine Lock F — Critical-controls promotion list (T12 final call)

**Provisional list (T12 closeout decision):**

| Module | On-gate? | Rationale |
|---|---|---|
| `packs/hooks/registry.py` | **on** | Admission gate; fail-closed on duplicate-ID / stale-digest / cross-pack-conflict; security-critical. |
| `packs/hooks/dispatcher.py` | **on** | Runtime decision engine; fail-closed default; ADR-017 enforcement boundary. |
| `cli/validators/hooks.py` | **on** | Manifest validator + cross-reference resolver against ADR-017 declarations. |
| `sdk/hook.py` | **off (Doctrine E)** | Public API surface — halt-before-commit per Doctrine E covers it; coverage-gate would be cargo-cult here. |
| `cli/init.py` (existing module, hook scaffolder added) | off | scaffolding; output is what matters, gated by `test_cli_init_hook.py`. |
| `cli/sign.py` / `cli/verify.py` (existing) | already on | extended to accept `kind = "hook"`; the existing critical-controls pinning carries forward. |
| `cli/_wheel_integrity.py` (existing) | already on | extended kind-derivation table for `cognic.hooks → "hook"`; existing pinning carries forward. |

Final list lands at T12 closeout. Gate size: **37 → 40 modules** (+3 new: registry, dispatcher, hooks validator).

### Doctrine Lock G — Validate / sign / verify acceptance criteria

**Validate (`cli/validate.py` orchestrator + new `cli/validators/hooks.py`):**
- Accepts `kind = "hook"` packs.
- New `[hooks].declarations` block validator (T6 of this sprint):
  - Required fields per declaration: `hook_id` (string, snake_case), `phase` (closed-enum), `ordering_class` (closed-enum), `timeout_seconds` (positive float ≤ `Settings.hook_max_timeout_s`), `fail_policy` (closed-enum).
  - Refuses: missing fields, duplicate hook_ids within the manifest, unknown phase, unknown ordering_class, timeout above ceiling, fail_open with no `fail_open_exception` declaration, mismatch between manifest declarations + pyproject `[project.entry-points."cognic.hooks"]` keys.
- Cross-references existing validators:
  - `cli/validators/data_governance.py` — when a non-hook pack declares `[data_governance].dlp_pre_hooks` or `dlp_post_hooks`, those hook_ids MUST be declarable across the verified hook-pack ecosystem (validate-time check is shape-only since cross-pack resolution is runtime; runtime registry resolution is the gate).
  - `cli/validators/identity.py` — hook packs do NOT declare `agent_card_jws_path`; the existing identity validator's agent-pack rule already only requires `agent_card_jws_path` for `kind = "agent"`.
- Refuses `[a2a]` and `[mcp]` blocks for `kind = "hook"` packs.

**Sign (`cli/sign.py` existing):**
- No changes required to the orchestrator; `cli/_wheel_integrity.py` accepts any `cognic.*` entry-point group.
- One narrow change to `_wheel_integrity.py`: kind-derivation table at line ~456 adds `"hook": "cognic.hooks"`.
- Hook packs do NOT JWS-sign an AgentCard (no `agent_cards/` dir in committed state); the JWS-signing path in `sign --bundle` is already conditioned on `kind = "agent"` (T14.B doctrine) so this works without modification.

**Verify (`cli/verify.py` existing):**
- Same kind-derivation table change inherited from `_wheel_integrity.py`.
- Step 9 (AgentCard JWS verification) is already conditioned on `kind = "agent"` — hook packs skip step 9 cleanly.
- Step 11 (load probe) runs against `cognic.hooks` entry-points exactly as it does for `cognic.tools` / `cognic.skills` / `cognic.agents`. The probe verifies the `Hook` subclass loads cleanly + the entry-point class is importable.

**Reference pack** (T11): `examples/cognic-hook-example-minimal/` — inert reference pack with a single `dlp_pre` hook that returns `HookResult(decision="pass", ...)` for all inputs. Static-only-committed-state per Sprint-7A T15 doctrine; lifecycle test at `tests/unit/cli/test_reference_packs_full_lifecycle_green.py` extended with a 4th lifecycle arm for hook packs (PASS at every gate; the harness narrowing means `agentos test-harness` either supports hooks or refuses with `harness_unsupported_pack_kind` — Wave-1 we narrow to refusal mirroring skill+agent at T13/R31; Sprint-7B's harness expansion adds hook dispatch dry-runs).

---

## ADR amendments needed (locked at T13 closeout)

These are explicit doctrine amendments Sprint-7A2 must land. Each is tracked as a checklist item; each has a corresponding sub-item under **T13: Closeout** below so the amendments are physically applied at the closeout commit. **Do not amend any ADR before T13** — surfaced at plan-of-record so reviewers see the slate up front.

- [ ] **A1 — ADR-008 amendment: `hook` joins the pack-kind enumeration.** Currently ADR-008 enumerates only `tools / skills / agents` (line 8); `init-tool / init-skill / init-agent` only (line 32); SDK modules `agentos_sdk.tool / .skill / .agent` only (lines 42-46). Sprint-7A2 amends:
  - line 8: `tools / skills / agents / hooks`.
  - line 32: add `agentos init-hook my-hook`.
  - lines 42-46: add `agentos_sdk.hook` (Hook base class + HookContext + HookResult + HookPhase closed-enum).
  - The amendment is non-substantive (additive); reflects that ADR-008 was written before the hook taxonomy firmed up.

- [ ] **A2 — ADR-017 line 97 amendment: hook adapter base class path.** Currently reads "Hook is a separate adapter `cognic_agentos.dlp.DLPHook`". Sprint-7A2 broadens from DLP-only to a generic phase taxonomy (`dlp_pre` / `dlp_post` Wave-1; future phases for memory governance / escalation / egress in follow-up sprints). Amend to: "Hook is a separate adapter `cognic_agentos.sdk.hook.Hook`; the DLP pre/post phases are two of the closed-enum hook phases supported in Wave-1." Add a one-sentence Sprint-7A2 amendment note explaining the broadening.

- [ ] **A3 — ADR-017 line 125 amendment: hook pack naming convention.** Currently reads "Cognic ships baseline DLP hooks (PII redaction, account masking); banks plug in their own DLP via the plugin registry as `cognic-dlp-<name>` packs." Sprint-7A2 amends the naming to follow the kind, not the phase: pack name is `cognic-hook-<name>` generically (e.g., `cognic-hook-redact-pii`, `cognic-hook-mask-accounts`). The legacy `cognic-dlp-<name>` form is **accepted at runtime** (no breaking change for already-published DLP packs) but **not promoted in scaffolders or documentation** going forward — `agentos init-hook` produces `cognic-hook-<name>`-shaped packs only. Amendment note explicit on the back-compat path so a future reviewer can audit.

- [ ] **A4 — ADR-017 new subsection: "DLP hook failure policy".** Currently ADR-017's Runtime enforcement subsection (lines 94-101) describes the pre/post hook flow but does not enumerate failure modes. Sprint-7A2 adds a new subsection "DLP hook failure policy" documenting the 5 closed-enum failure modes from Doctrine Lock E (`hook_timeout` / `hook_exception` / `hook_malformed_result` / `hook_policy_refused` / `hook_payload_unscannable`) + the fail-closed-by-default rule + the `fail_open_exception` declaration carve-out + the payload-contents-never-logged invariant.

**Sequencing decision.** All four amendments land in **the T13 closeout commit** (alongside the BUILD_PLAN status flip + AGENTS.md amendment), NOT as a separate ADR-amendment-first PR. Rationale: the amendments are descriptive (codifying what Sprint-7A2 actually shipped), not prescriptive (locking new design before code). Sprint-7A used the same pattern at T17 (AGENTS.md "Authoring — SDK + CLI (Sprint 7A)" subsection landed in the closeout). If reviewer prefers an amendment-first PR, surface at T1 review and the slate moves to a pre-T1 PR.

---

## File Structure

**Created (~14 files):**

- `src/cognic_agentos/sdk/hook.py` — `Hook` + `HookContext` + `HookResult` + `HookPhase` (T2).
- `src/cognic_agentos/cli/templates/hook/` — Jinja2 scaffold tree (manifest + pyproject + inert source + tests + README) (T4).
- `src/cognic_agentos/cli/validators/hooks.py` — `[hooks]` block validator (T6).
- `src/cognic_agentos/packs/__init__.py` — new package (T7).
- `src/cognic_agentos/packs/hooks/__init__.py` — hook-package init (T7).
- `src/cognic_agentos/packs/hooks/registry.py` — `HookRegistry` (T7).
- `src/cognic_agentos/packs/hooks/dispatcher.py` — `HookDispatcher` (T8).
- `examples/cognic-hook-example-minimal/` — inert reference pack (T11): manifest + pyproject + `src/cognic_hook_example_minimal/{__init__.py, hook.py}` + README. Static-only-committed-state.
- `tests/architecture/test_hook_payload_never_logged.py` — AST-walk regression (T9).
- `tests/unit/sdk/test_hook_base.py` — Hook base class (T2).
- `tests/unit/cli/validators/test_validator_hooks.py` — manifest validator (T6).
- `tests/unit/packs/hooks/test_hook_registry.py` — registry (T7).
- `tests/unit/packs/hooks/test_hook_dispatcher.py` — dispatcher (T8).
- `tests/unit/cli/test_cli_init_hook.py` — scaffolder (T4).

**Modified (~10 files):**

- `src/cognic_agentos/cli/__init__.py` — `init-hook` subcommand registration; `ValidatorReason` literal + ownership map extended.
- `src/cognic_agentos/cli/_governance_vocab.py` — `HookPhase` + `HookOrderingClass` + `HookFailPolicy` closed enums.
- `src/cognic_agentos/cli/_wheel_integrity.py` — kind-derivation table: `cognic.hooks → "hook"`.
- `src/cognic_agentos/cli/init.py` — `agentos init-hook <name>` scaffolder.
- `src/cognic_agentos/cli/validate.py` — orchestrator dispatch to `validators/hooks.py`.
- `src/cognic_agentos/cli/validators/data_governance.py` — `dlp_pre_hooks` / `dlp_post_hooks` shape validation (string-array of hook_ids; cross-pack resolution is runtime).
- `src/cognic_agentos/core/config.py` — `Settings.hook_max_timeout_s` (default 30.0; gt=0).
- `src/cognic_agentos/sdk/__init__.py` — re-export `Hook` / `HookContext` / `HookResult` / `HookPhase`.
- `tests/unit/cli/test_reference_packs_full_lifecycle_green.py` — 4th lifecycle arm for the hook reference pack.
- `tools/check_critical_coverage.py` — gate +3 modules (registry, dispatcher, hooks validator) (T12).
- `docs/HOW-TO-WRITE-A-PACK.md` — Section 0 quickstart extended with `init-hook`; new Section 8 covering hook authoring + ADR-017 DLP wiring.
- `docs/SDK-REFERENCE.md` — new Section 8 for `Hook` base class + `HookContext` / `HookResult`.
- `docs/PACK-MANIFEST-SPEC.md` — new `[hooks]` section.
- `docs/BUILD_PLAN.md` — Sprint-7A2 status flip to CLOSED at T13.
- `AGENTS.md` — new "Authoring — Hook packs (Sprint 7A2)" critical-controls subsection at T13.

---

## Task arc (13 tasks)

### Task 1: Settings + closed-enum vocabulary scaffolding

- Create: `src/cognic_agentos/cli/_governance_vocab.py` extensions — `HookPhase` (`"dlp_pre" | "dlp_post"`), `HookOrderingClass` (closed-enum, ~5-8 values across the Wave-1 phases), `HookFailPolicy` (`"fail_closed" | "fail_open"`).
- Modify: `src/cognic_agentos/core/config.py` — add `hook_max_timeout_s: float = Field(default=30.0, gt=0.0)`.
- Modify: `src/cognic_agentos/cli/__init__.py` — extend `ValidatorReason` literal with `hook_*` reasons (~10-12 values) + ownership map.
- Test: `tests/unit/test_config.py` — drift detector seeds new closed-enum values.

**Halt-before-commit:** No (vocab scaffolding; off-floor).

### Task 2: SDK base — `sdk/hook.py`

- Create: `src/cognic_agentos/sdk/hook.py` per Doctrine Lock C.
- Modify: `src/cognic_agentos/sdk/__init__.py` — re-exports.
- Test: `tests/unit/sdk/test_hook_base.py` — base class invariants (template-method seam, `__init_subclass__` mixin guard, `HookContext` / `HookResult` frozen+slotted, validation on input/output shapes).

**Halt-before-commit:** Yes (Doctrine E — public API surface).

### Task 3: CLI entry point — `init-hook` scaffolder

- Modify: `src/cognic_agentos/cli/init.py` — `init-hook` subcommand.
- Create: `src/cognic_agentos/cli/templates/hook/` — manifest + pyproject + inert source + tests/conftest.py + tests/test_hook.py + README + `.github/workflows/sign-and-publish.yml` (mirrors tool/skill/agent template tree).
- Test: `tests/unit/cli/test_cli_init_hook.py` — scaffold produces a static-only valid hook pack tree.

**Halt-before-commit:** No (scaffolding; off-floor).

### Task 4: Validate orchestrator + manifest support

- Modify: `src/cognic_agentos/cli/validate.py` — orchestrator dispatch to `validators/hooks.py` for `kind = "hook"` packs; refuse `[a2a]` + `[mcp]` blocks for hook packs.
- Modify: `src/cognic_agentos/cli/validators/identity.py` — explicit hook-pack-kind handling (no `agent_card_jws_path` required; mirrors tool / skill behavior).

**Halt-before-commit:** Yes (cli/validate.py is on the critical-controls floor).

### Task 5: `cli/validators/hooks.py` — manifest validator (CRITICAL CONTROLS)

- Create: `src/cognic_agentos/cli/validators/hooks.py` per Doctrine Lock G acceptance criteria.
- Test: `tests/unit/cli/validators/test_validator_hooks.py` — refusal arms for every closed-enum reason; happy-path arm; dual-path lookup arm.

**Halt-before-commit:** Yes (CRITICAL CONTROLS — joins the gate at T12).

### Task 6: Hook registry — `packs/hooks/registry.py` (CRITICAL CONTROLS)

- Create: `src/cognic_agentos/packs/__init__.py`, `packs/hooks/__init__.py`, `packs/hooks/registry.py`.
- Wire admission via existing `protocol/plugin_registry.py`'s verified-pack list.
- Test: `tests/unit/packs/hooks/test_hook_registry.py` — verified-only registration; duplicate hook_ids across packs refuse fail-closed; stale-digest refusals; cross-pack conflict resolution.

**Halt-before-commit:** Yes (CRITICAL CONTROLS).

### Task 7: Hook dispatcher — `packs/hooks/dispatcher.py` (CRITICAL CONTROLS)

- Create: `src/cognic_agentos/packs/hooks/dispatcher.py` per Doctrine Lock D + E.
- Test: `tests/unit/packs/hooks/test_hook_dispatcher.py` — deterministic ordering; per-hook timeout; failure policy fail-closed default; audit emission; tuple-snapshot at dispatch entry; short-circuit on first refuse.
- Test: `tests/architecture/test_hook_payload_never_logged.py` — AST-walk regression that no hook code path logs payload bytes.

**Halt-before-commit:** Yes (CRITICAL CONTROLS).

### Task 8: ADR-017 runtime DLP wiring

- Wire the dispatcher into the calling-pack invocation path: `protocol/plugin_registry` (or the appropriate runtime hot path) calls `HookDispatcher.dispatch(phase="dlp_pre", ...)` before pack code sees governed input + `HookDispatcher.dispatch(phase="dlp_post", ...)` before governed output leaves AgentOS.
- The exact hot-path integration site is identified at the start of T8 (likely `protocol/plugin_registry.invoke_tool` or analogous; specific module locked at T8 review).
- Test: `tests/unit/packs/hooks/test_dlp_hook_integration.py` — pre-hooks run before governed input reaches pack code; post-hooks run before output leaves; payload contents never logged; refusal short-circuits the call.

**Halt-before-commit:** Yes (touches runtime hot path).

### Task 9: Sign / verify support — wheel-integrity kind-derivation extension

- Modify: `src/cognic_agentos/cli/_wheel_integrity.py` — kind-derivation table extended with `cognic.hooks → "hook"`.
- Modify: `src/cognic_agentos/cli/sign.py` — confirm hook-pack code path (no JWS for hooks; existing kind-conditional already handles this).
- Modify: `src/cognic_agentos/cli/verify.py` — same; verify Step 9 already conditioned on agent kind.
- Test: `tests/unit/cli/test_cli_sign.py` extended with a hook-pack-fixture arm.
- Test: `tests/unit/cli/test_cli_verify.py` extended with a hook-pack-fixture arm.

**Halt-before-commit:** Yes (touches `_wheel_integrity.py` + `sign.py` + `verify.py` — all on critical-controls floor).

### Task 10: ADR-017 validator cross-reference for `dlp_pre_hooks` / `dlp_post_hooks`

- Modify: `src/cognic_agentos/cli/validators/data_governance.py` — shape-validate `dlp_pre_hooks` + `dlp_post_hooks` as string arrays of snake_case hook_ids. Cross-pack resolution remains a runtime registry concern.
- Test: `tests/unit/cli/validators/test_validator_data_governance.py` extended with hook-id-shape arms.

**Halt-before-commit:** Yes (`data_governance.py` is on the critical-controls floor).

### Task 11: Reference hook pack `examples/cognic-hook-example-minimal/`

- Create: full inert pack (manifest + pyproject + inert source + README + (no agent_cards/, no test-signing/ keypair since hooks don't ship JWS)).
- Modify: `tests/unit/cli/test_reference_packs_full_lifecycle_green.py` — 4th arm for hook packs. Per-kind matrix decision (hooks PASS or refuse at harness?): Wave-1 narrow — `harness_unsupported_pack_kind` (mirrors skill + agent at T13/R31; harness expansion lands in Sprint-7B alongside skill+agent).
- Static-only-committed-state per Sprint-7A T15 doctrine.

**Halt-before-commit:** No (off-floor reference pack).

### Task 12: Critical-controls coverage gate extension + 4 docs

- Modify: `tools/check_critical_coverage.py` — gate +3 modules (`packs/hooks/registry.py`, `packs/hooks/dispatcher.py`, `cli/validators/hooks.py`); gate size **37 → 40**.
- Coverage probe: candidate-module-narrowed `--cov` per the modified-B doctrine from Sprint-7A T16.
- Modify: `docs/HOW-TO-WRITE-A-PACK.md` — Section 0 extended with `init-hook`; new Section 8 hook authoring.
- Modify: `docs/SDK-REFERENCE.md` — new Section 8 `Hook` API.
- Modify: `docs/PACK-MANIFEST-SPEC.md` — new `[hooks]` section + cross-reference from `[data_governance]`.
- Create: `docs/operator-runbooks/hook-pack-failure-policy.md` — operator runbook for the 5 closed-enum failure modes.

**Halt-before-commit:** Yes (gate config is executable single-source-of-truth for the per-file coverage floor).

### Task 13: Closeout

- [ ] Create: `docs/closeouts/2026-05-XX-sprint-7a2-hook-packs-runtime.md` (date filled at commit time).
- [ ] Modify: `docs/BUILD_PLAN.md` — Sprint-7A2 status flip to CLOSED.
- [ ] Modify: `AGENTS.md` — new "Authoring — Hook packs (Sprint 7A2)" critical-controls subsection listing the 3 promoted modules (registry, dispatcher, hooks validator).
- [ ] **A1**: amend `docs/adrs/ADR-008-authoring-platform.md` — kind enumeration line 8 (`tools / skills / agents / hooks`); add `agentos init-hook` line 32; add `agentos_sdk.hook` lines 42-46. Per the "ADR amendments needed" section above.
- [ ] **A2**: amend `docs/adrs/ADR-017-data-governance-contracts.md` line 97 — `cognic_agentos.dlp.DLPHook` → `cognic_agentos.sdk.hook.Hook`; add Sprint-7A2 amendment note.
- [ ] **A3**: amend `docs/adrs/ADR-017-data-governance-contracts.md` line 125 — `cognic-dlp-<name>` → `cognic-hook-<name>` (with explicit back-compat note for legacy `cognic-dlp-*` runtime acceptance).
- [ ] **A4**: amend `docs/adrs/ADR-017-data-governance-contracts.md` — add new "DLP hook failure policy" subsection codifying the 5 closed-enum failure modes + fail-closed-by-default rule + payload-contents-never-logged invariant.

**Halt-before-commit:** Yes (AGENTS.md + ADRs are doctrine documents).

---

## Self-Review

After writing the complete plan, looked at the BUILD_PLAN deliverables / tests / exit criteria with fresh eyes:

**Spec coverage:**
- ✅ All 7 BUILD_PLAN deliverables (lines 565-580) map to tasks T2-T11.
- ✅ All 8 BUILD_PLAN test files (lines 583-591) map to tasks T2-T11.
- ✅ All 5 BUILD_PLAN exit criteria (lines 594-598) are pinned by tests in T11 (reference-pack lifecycle), T6 (validator), T7 (registry), T8 (dispatcher), T8 (DLP integration).

**Spec gaps surfaced:**
- BUILD_PLAN doesn't explicitly enumerate the 5 closed-enum failure modes — Doctrine Lock E pins them.
- BUILD_PLAN says hook packs "do not ship a production DLP recogniser" but doesn't lock the manifest's `[hooks]` block shape — Doctrine Lock A pins it.
- BUILD_PLAN doesn't enumerate which modules are critical-controls — Doctrine Lock F pins them.

**Doctrine touchpoints flagged for explicit halt-before-commit at T13:**
- ADR-008, ADR-017 line 97, ADR-017 line 125, ADR-017 new "DLP hook failure policy" subsection.
- AGENTS.md "Authoring — Hook packs (Sprint 7A2)" subsection.
- BUILD_PLAN.md Sprint-7A2 status flip.

**Critical-controls coverage gate floor + promotion rule (Doctrine Decision G, inherited from Sprint-7A T16):**
- 3 hook modules promote at T12: `packs/hooks/registry.py`, `packs/hooks/dispatcher.py`, `cli/validators/hooks.py`.
- `sdk/hook.py` stays off the floor per Doctrine E (public-API stability halt-before-commit covers it).
- `cli/init.py` extension stays off (scaffolding).
- Existing critical-controls modules touched (`cli/validate.py`, `cli/sign.py`, `cli/verify.py`, `cli/_wheel_integrity.py`, `cli/validators/data_governance.py`) carry forward their existing pinning.

**Halt-before-commit map (per-task):**

| Task | Halt? | Why |
|---|---|---|
| T1 | No | Vocab scaffolding |
| T2 | Yes | Doctrine E — public SDK API |
| T3 | No | Scaffolding |
| T4 | Yes | `cli/validate.py` is on the floor |
| T5 | Yes | CRITICAL CONTROLS — `validators/hooks.py` joins the gate |
| T6 | Yes | CRITICAL CONTROLS — `packs/hooks/registry.py` |
| T7 | Yes | CRITICAL CONTROLS — `packs/hooks/dispatcher.py` |
| T8 | Yes | Touches runtime hot path |
| T9 | Yes | Touches `_wheel_integrity.py` + `sign.py` + `verify.py` |
| T10 | Yes | `data_governance.py` is on the floor |
| T11 | No | Reference pack |
| T12 | Yes | Gate config |
| T13 | Yes | AGENTS.md + ADRs |

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-05-09-sprint-7a2-hook-packs-runtime.md`.

**Next:** halt for plan review against doctrine. Specifically requesting confirmation of:

1. **The 7 doctrine locks A-G** — any adjustments before T1 begins?
2. **The ADR amendment slate** (ADR-008 + ADR-017 line 97 + ADR-017 line 125 + ADR-017 new failure-policy subsection) — agreed to land at T13 closeout, OR should an ADR-amendment-first PR land separately before any code?
3. **Critical-controls promotion list** (3 modules: registry / dispatcher / hooks validator; `sdk/hook.py` off-floor per Doctrine E) — adjust?
4. **Harness-narrow decision for hook packs** (Wave-1: refuse with `harness_unsupported_pack_kind` mirroring skill + agent; Sprint-7B grows the dispatch table) — agreed?
5. **Failure policy closed-enum** (5 sub-cases under `dispatch_hook_failed`: timeout / exception / malformed_result / policy_refused / payload_unscannable) — complete?

No code begins until each lock is confirmed.
