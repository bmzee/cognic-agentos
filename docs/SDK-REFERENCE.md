# Cognic AgentOS SDK reference

Python API surface for pack authors. Covers the four base classes
(`Tool`, `Skill`, `Agent`, `Hook`), the `ToolRegistry` protocol skills
consume, and the testing + compliance helpers under
`cognic_agentos.sdk.testing`.

This doc is the API contract; for the *workflow* (scaffold → build
wheel → sign → validate → harness → verify per the static-only/
sign-before-validate doctrine) read
`docs/HOW-TO-WRITE-A-PACK.md`. For the manifest schema read
`docs/PACK-MANIFEST-SPEC.md`.

**Audience.** Pack authors; integrators of the SDK into IDE tooling
or CI runners.

**Stability.** Public SDK surface — backward-compatible across
Sprint-7A onward per ADR-008. Breaking changes require an ADR
amendment + a migration release note.

---

## 1. Importing

```python
from cognic_agentos.sdk.tool import Tool
from cognic_agentos.sdk.skill import Skill, SkillUnregisteredToolError
from cognic_agentos.sdk.agent import Agent
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult
from cognic_agentos.sdk.registry import ToolRegistry
```

The SDK ships with `cognic-agentos`. Pack distributions declare the
SDK as a dependency in `[project].dependencies = ["cognic-agentos"]`.

---

## 2. `cognic_agentos.sdk.tool.Tool`

Base class for `cognic.tools` entry-point implementations. Subclasses
declare `name` + `input_schema` + `output_schema` as `ClassVar`
fields, override `_invoke()` for the actual work, and let the SDK's
template-method validation seam handle input/output schema checks.

### 2.1 Required ClassVars

```python
class MyTool(Tool):
    name: ClassVar[str] = "my_tool"  # matches the pyproject entry-point alias
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": [],
        "additionalProperties": False,
    }
    output_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {"echo": {"type": "string"}},
        "required": ["echo"],
        "additionalProperties": False,
    }
```

### 2.2 Required override

```python
async def _invoke(self, **kwargs: Any) -> dict[str, Any]:
    return {"echo": str(kwargs.get("message", ""))}
```

The SDK base validates `kwargs` against `input_schema` BEFORE calling
`_invoke`; validates the returned dict against `output_schema` AFTER.
Subclasses focus on the work; the validation discipline cannot be
bypassed.

### 2.3 The `invoke()` template method (DO NOT OVERRIDE)

The public entry point is `Tool.invoke(**kwargs)`. It is `@final`
(mypy) AND guarded at runtime via `__init_subclass__` walking
`cls.__mro__`. Any class that defines `invoke` directly in a
non-base ancestor raises `TypeError` at class-creation time —
catches mixin-smuggling that would otherwise bypass the schema
validation.

Override `_invoke` instead.

### 2.4 Errors

- `ToolInputSchemaError` — `kwargs` failed `input_schema` validation.
- `ToolOutputSchemaError` — `_invoke`'s return value failed
  `output_schema` validation.
- `ToolSchemaDeclarationError` — `input_schema` or `output_schema`
  isn't a valid JSON Schema fragment.

---

## 3. `cognic_agentos.sdk.skill.Skill`

Base class for `cognic.skills` entry-point implementations. Skills
COMPOSE one or more tools; they receive a `ToolRegistry` at
instantiation and resolve their declared tools via
`self._tools.get(name)`.

### 3.1 Required ClassVars

```python
class MySkill(Skill):
    name: ClassVar[str] = "my_skill"
    declared_tools: ClassVar[tuple[str, ...]] = ("upstream_tool_a", "upstream_tool_b")
```

`declared_tools` is the cross-check the SDK enforces at
instantiation time: if any name is missing from the supplied
`ToolRegistry`, `__init__` raises
`SkillUnregisteredToolError` BEFORE any `execute()` call. This is the
T2 Step-1 instantiation-time regression.

### 3.2 Required override

```python
async def execute(self, **kwargs: Any) -> dict[str, Any]:
    upstream = self._tools.get("upstream_tool_a")
    result_a = await upstream.invoke(message=kwargs.get("input", ""))
    return {"composed": result_a}
```

`self._tools` is bound by the SDK base before `setup()` (the
optional override-or-no-op hook) runs.

### 3.3 The `__init__` template method (DO NOT OVERRIDE)

`Skill.__init__(*, tools)` is `@final` AND guarded at runtime via
`__init_subclass__`. Override `setup()` for pack-specific
construction logic so the `declared_tools` cross-check seam cannot
be bypassed via mixin smuggling.

### 3.4 Errors

- `SkillUnregisteredToolError` — `declared_tools` references a name
  not in the supplied `ToolRegistry`.
- `SkillError` — base class for any SDK-raised skill error.

---

## 4. `cognic_agentos.sdk.agent.Agent`

Base class for `cognic.agents` entry-point implementations. Agents
receive Wave-1 A2A 1.0 task envelopes via `handle()`.

### 4.1 Required ClassVars

```python
from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities

class MyAgent(Agent):
    name: ClassVar[str] = "my_agent"
    declared_capabilities: ClassVar[A2ACapabilities] = A2ACapabilities(
        capabilities_supported=("my_capability_v1",),
        streaming=False,
        push_notifications=False,
        extended_agent_card=False,
        artifacts_supported=False,
        extensions=(),
        deferred_wave2_features=(),
    )
```

`declared_capabilities` is the Wave-1 capability subset the agent
exposes; the runtime A2A endpoint reads it for capability
negotiation.

### 4.2 Required override

```python
async def handle(
    self,
    payload: bytes,
    *,
    task: TaskRecord,
) -> dict[str, Any]:
    # `payload` is the raw inbound JSON-RPC 2.0 envelope bytes.
    # The endpoint has already validated authn + Wave-2-feature
    # refusal + version-negotiated by the time this is called.
    # `task` carries task_id / target_agent / parent_trace_id /
    # child_trace_id for cross-agent chain linkage.
    return {"text": "ok"}
```

### 4.3 What's intentionally NOT in the SDK

- **No `__init__` template** on `Agent`. Agents are constructed by
  the runtime endpoint, not by the SDK.
- **No automatic schema validation** on `handle()`'s return. A2A 1.0
  spec validates the wire envelope at the endpoint boundary; the
  agent's response is wrapped into a `StreamResponse` envelope by
  the endpoint's lifecycle machinery.

---

## 5. `cognic_agentos.sdk.registry.ToolRegistry`

PEP-544 protocol describing the registry shape skills consume.

```python
class ToolRegistry(Protocol):
    def get(self, name: str) -> Tool:
        """Return the registered Tool by pack_id; raise KeyError if not registered."""
        ...

    def list_tools(self) -> list[str]:
        """Return the pack_ids of every registered tool."""
        ...
```

The runtime supplies an implementation backed by the discovered
plugin registry. Pack-author tests can use the
`cognic_agentos.sdk.testing.fixture_tool_registry` **pytest fixture**
(see Section 6) for fixture-only adapters; declaring it as a test
argument auto-loads the calling pack's `cognic.tools` entry-points.

---

## 6. `cognic_agentos.sdk.testing` — pytest fixtures

The testing helpers are **pytest fixtures**, not standalone callables.
Pack-author tests inject them via the fixture argument convention.

```python
# In your pack's conftest.py (one-time setup):
pytest_plugins = ("cognic_agentos.sdk.testing",)
```

Then write tests that take the fixtures as arguments:

```python
def test_my_skill_composes_tools(fixture_tool_registry, fixture_settings) -> None:
    skill = MySkill(tools=fixture_tool_registry)
    # fixture_settings is a Settings instance pointed at memory adapters
    ...
```

### 6.1 `fixture_tool_registry`

```python
@pytest.fixture
def fixture_tool_registry() -> ToolRegistry: ...
```

Returns a `ToolRegistry`-conformant object pre-populated with the
**calling pack's discovered `cognic.tools` entry-points**. Auto-loads
via `importlib.metadata.entry_points()` — no `tools` argument is
accepted. In the cognic-agentos dev environment the discovered list
is empty (tools live in pack repos); in a pack's test environment
the pack's installed entry-points populate the registry.

### 6.2 `fixture_settings`

```python
@pytest.fixture
def fixture_settings(tmp_path: Path) -> Settings: ...
```

Returns a `Settings` instance with every adapter driver collapsed to
`"memory"` (`db_driver`, `vector_driver`, `secret_driver`,
`embed_driver`, `obs_driver` — all `"memory"`) and
`local_object_store_root = tmp_path`. Pack tests exercise governance
+ lifespan + `/readyz` paths without standing up Postgres / Qdrant /
Vault / Ollama / Langfuse. The `tmp_path` parameter is injected by
pytest; pack tests just declare the fixture as a function argument.

If you need to override a specific Settings field on top of the
memory-adapter defaults, use `fixture_settings.model_copy(update={...})`
inside the test:

```python
def test_with_custom_signing_key(fixture_settings, tmp_path) -> None:
    settings = fixture_settings.model_copy(
        update={"signing_key_path": tmp_path / "signing.pem"},
    )
    ...
```

### 6.3 What's intentionally NOT here

- **No transport interception.** The Wave-1 narrow contract (T13/R33
  P2 #1) explicitly does NOT install `httpx.MockTransport`, sandbox
  filesystem / network access, or scope environment variables. Pack
  `_invoke()` code runs against the unmodified host runtime; pack
  authors who need transport-level isolation wire it themselves via
  pytest's `monkeypatch` + `httpx.MockTransport` (or analogous) in
  their own fixtures.

---

## 7. `cognic_agentos.sdk.compliance` — ISO 42001 control declaration

```python
from cognic_agentos.sdk.compliance import (
    ControlDeclaration,
    declare_iso_42001_controls,
    declared_iso_42001_controls,
)
```

Wave-1 surface for declaring ISO 42001 control implementations
the pack ships. Pack authors call `declare_iso_42001_controls(...)`
at module-import time with one or more `ControlDeclaration` instances;
the runtime evidence-pack exporter reads back via
`declared_iso_42001_controls()` to assemble the per-pack control
matrix.

### 7.1 `ControlDeclaration`

Frozen dataclass with control identifier, evidence pointers, and
implementation rationale. See the `cognic_agentos.sdk.compliance`
module docstring for the field-level contract; the dataclass is
public API and stable across Sprint-7A onward.

### 7.2 `declare_iso_42001_controls(*controls)`

Variadic registration helper. Each call **appends** the supplied
`ControlDeclaration` instances to the module-level registry; repeated
calls accumulate. Pack authors typically declare every control in a
single batch at module-import time, but splitting across modules is
allowed and registration order follows pack-import order in the host
process. The current Wave-1 implementation does NOT de-duplicate by
control identifier and does NOT validate against conflicting evidence
pointers — pack authors are responsible for emitting each control
declaration once. Idempotency + conflict-detection are tracked for
a follow-up sprint alongside the runtime auto-attestation API.

### 7.3 `declared_iso_42001_controls()`

Returns the tuple of `ControlDeclaration` instances the pack has
registered. Used by the evidence-pack exporter; pack code does NOT
typically read this directly.

**Why declaration vs emit.** Wave-1 ships the declaration shape so
operators can audit each pack's claimed control coverage at install
time; per-event emission into the audit chain (the emit path) lands
in a follow-up sprint alongside the runtime auto-attestation API.

---

## 8. `cognic_agentos.sdk.hook.Hook` (Sprint-7A2)

Base class for `cognic.hooks` entry-point implementations — the 4th
first-class pack kind alongside `Tool` / `Skill` / `Agent`. Hooks
are deterministic governance extensions (PII redaction / account
masking / output egress checks / etc.) that DLP-aware tool /
skill / agent packs reference via
`[data_governance].dlp_pre_hooks` / `dlp_post_hooks` (per ADR-017).
Subclasses declare `hook_id` + `phase` as `ClassVar` fields,
override `_invoke()` for the actual work, and let the SDK's
template-method validation seam handle context / payload / result
shape checks.

### 8.1 Required ClassVars

```python
from typing import ClassVar
from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


class RedactPIIHook(Hook):
    hook_id: ClassVar[str] = "redact_pii_in_input"
    phase: ClassVar[HookPhase] = "dlp_pre"
```

`hook_id` matches the manifest's `[hooks].declarations[].hook_id`
+ the calling pack's `[data_governance].dlp_pre_hooks` /
`dlp_post_hooks` reference. `phase` is the closed-enum from
`cognic_agentos.cli._governance_vocab.HookPhase` (Wave-1:
`"dlp_pre"` / `"dlp_post"`).

### 8.2 Required override

```python
async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
    if self._matches_pii(payload):
        return HookResult(
            decision="redact",
            redacted_payload=self._redact(payload),
            policy_reason=None,
        )
    return HookResult(decision="pass", redacted_payload=None, policy_reason=None)
```

The SDK base validates `context` + `payload` BEFORE calling
`_invoke`, validates the returned `HookResult` AFTER. Subclasses
focus on the policy decision; the validation discipline cannot be
bypassed.

### 8.3 The `invoke()` template method (DO NOT OVERRIDE)

The dispatcher entry point is `Hook.invoke(context, payload)`. It
is `@final` (mypy) AND guarded at runtime via `__init_subclass__`
walking `cls.__mro__`. Any class that defines `invoke` directly in
a non-base ancestor raises `TypeError` at class-creation time —
catches mixin-smuggling that would otherwise bypass the validation
seam.

Override `_invoke` instead.

### 8.4 `HookContext`

Frozen + slotted dataclass passed to every `_invoke()` call. Carries
hook + invocation IDs + closed-enum policy metadata + manifest
snapshots the hook may key its decision off:

| Field | Type | Notes |
|---|---|---|
| `hook_id` | `str` | The `hook_id` this invocation targets. |
| `phase` | `HookPhase` | Closed-enum (`"dlp_pre"` / `"dlp_post"`). |
| `pack_id` | `str` | The CALLING pack's `[pack].pack_id` (NOT the hook pack's). |
| `tenant_id` | `str` | Per-tenant binding for tenant-specific policy. |
| `request_id` | `str` | Stable request identifier for audit-chain correlation. |
| `trace_id` | `str \| None` | Distributed-trace identifier (None outside a traced request). |
| `parent_trace_id` | `str \| None` | Parent-trace identifier for cross-agent chain linkage (None at top of chain). |
| `manifest_data_classes` | `tuple[str, ...]` | The CALLING pack's declared `[data_governance].data_classes`, snapshot at admission time. |
| `manifest_purpose` | `str` | The CALLING pack's declared `[data_governance].purpose`. |

Critical invariant: `HookContext` does NOT carry the payload bytes.
The dispatcher passes payload separately to `_invoke()` so the
context is safely loggable. The AST-walk regression at
`tests/architecture/test_hook_payload_never_logged.py` (Sprint-7A2
T7) pins the payload-never-logged invariant; hooks MUST NOT log /
store / exfiltrate the `payload` argument.

### 8.5 `HookResult`

Frozen + slotted dataclass returned to the dispatcher.

| Field | Type | Notes |
|---|---|---|
| `decision` | `HookDecision` | Closed-enum: `"pass"` / `"redact"` / `"mask"` / `"refuse"`. |
| `redacted_payload` | `bytes \| None` | For `redact` / `mask`: the modified payload bytes. MUST be None for `pass` / `refuse`. |
| `policy_reason` | `str \| None` | For `refuse`: closed-enum policy reason from the calling pack's vocabulary; propagates to the `hook_policy_refused` audit row + caller refusal envelope. MUST be None for `pass` / `redact` / `mask`; MUST be a non-empty string for `refuse`. |
| `audit_metadata` | `dict[str, Any]` | Token-free metadata the dispatcher attaches to the audit row. Hooks MUST NOT include payload bytes here. |

Decision-↔-fields invariant enforced by `Hook.invoke()` AFTER
`_invoke` returns; violations raise `HookResultShapeError` (subclass
of `HookContractError` → in the `HookError` hierarchy → caught by
the dispatcher's single refusal-surface catch).

### 8.6 Errors

- `HookError` — base class for any SDK-raised hook error.
- `HookContractError` — base for contract-shape violations (caught by
  the dispatcher as a single refusal-surface).
- `HookContextError` — `context` argument was None / wrong type.
- `HookPayloadError` — `payload` argument was None / non-`bytes`.
- `HookResultShapeError` — `_invoke` returned a non-`HookResult`, OR
  a `HookResult` whose fields violate the decision-↔-fields
  invariant.

Pack-author-raised exceptions (anything NOT in the `HookError`
hierarchy) route to the closed-enum `hook_exception` dispatcher
failure mode; the dispatcher catches them at the single try/except
boundary and emits the failure-mode audit row. See
`docs/operator-runbooks/hook-pack-failure-policy.md` for the full
5-failure-mode operator runbook.

### 8.7 What's intentionally NOT here

- **No tool / skill registry passed to hooks.** Hooks key decisions
  off the payload + the `HookContext` snapshot only — they do NOT
  invoke other hooks / tools / skills via the SDK. The dispatcher
  enforces ordering + concurrency via the closed-enum
  `ordering_class` taxonomy declared in the manifest.
- **No automatic schema validation.** Hooks operate on raw
  `payload: bytes`; pack authors implement payload-shape parsing
  inline. The dispatcher's payload budget (per-pack + per-hook
  ceiling) is the only payload-side gate the SDK enforces.

---

## 9. Stability + versioning

- The four base classes (`Tool`, `Skill`, `Agent`, `Hook`), the
  `ToolRegistry` protocol, and the testing helpers are **public
  API**. Backward-compatible across Sprint-7A and forward per
  ADR-008.
- Breaking changes require an ADR amendment + a migration release
  note + a deprecation period.
- Closed-enum vocabularies referenced by the SDK (e.g., the
  `RiskTier` literal) live at `cognic_agentos.cli._governance_vocab`
  and ARE wire-protocol-public — they appear in pack manifests and
  are validated by the build-time + runtime trust gates.

For the schema of the manifest the SDK consumes, see
`docs/PACK-MANIFEST-SPEC.md`.
