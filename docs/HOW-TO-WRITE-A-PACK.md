# How to write a Cognic AgentOS plugin pack

This doc tells you how to build a plugin pack that AgentOS will register
at startup. It is the pack-author counterpart to ADR-002 (plugin
protocol), ADR-008 (authoring platform), ADR-016 (supply-chain
controls), and ADR-017 (data-governance contracts) — read those when
you need the *why*; this doc tells you the *what* in checklist form.

**Audience.** Engineers writing a tool, skill, agent, or hook pack
that will ship as its own distribution and install on top of
AgentOS via `uv pip install` (or whatever the operator's pack
channel is).

**Sprint-7A author surface (Wave 1, current).** The recommended way to
build a pack is the `agentos` CLI (Sprint-7A T4 + T5 + T6 + T13 + T14).
Skip down to **Section 0 (Sprint-7A quickstart)** for the
`init → build wheel → sign --bundle → validate → test-harness → verify`
workflow against the Wave-1 toolchain. The order is sign-before-validate
because `agentos validate` checks every declared
`supply_chain.attestation_paths` file is present on disk — `sign --bundle`
is what populates them. The deeper sections of this doc (1–7) describe
the full plumbing the CLI automates and remain the canonical reference
for operators and pack-author edge cases.

**Wave 1 scope.** This doc reflects Sprint 4 / Wave 1 plumbing + the
Sprint-7A SDK + CLI author surface that lands on top. Items marked as
**Wave 2** or **Sprint 7A+** describe the eventual contract; the
**Wave 1 escape hatch** subsection under each tells you what to do
*today* before that tooling lands.

The canonical worked examples for the Sprint-7A author flow are the
four reference packs at
`examples/cognic-{tool,skill,agent,hook}-example-minimal/` (the hook
pack lands in Sprint-7A2). When this doc and a reference pack
disagree, the pack is right (CI re-verifies all four on every build
via `tests/unit/cli/test_reference_packs_full_lifecycle_green.py`)
and this doc is wrong; please open an issue. The Sprint-4 fixture
pack at `tests/fixtures/cognic_test_pack/` remains the canonical
example for the runtime trust-gate plumbing covered in
Sections 4 + 7.

---

## 0. Sprint-7A quickstart — `agentos` CLI

**Install.** The `agentos` console script ships with `cognic-agentos`.

```
uv pip install cognic-agentos
agentos --help
```

**Four pack kinds, four scaffolders.** Pick the kind matching your
pack's role (Section 1 covers the difference; Sprint-7A2 added
`hook` as the 4th first-class kind for ADR-017 deterministic
governance extensions):

```
agentos init-tool  my-pack    # cognic.tools  entry-point group
agentos init-skill my-pack    # cognic.skills entry-point group
agentos init-agent my-pack    # cognic.agents entry-point group
agentos init-hook  my-pack    # cognic.hooks  entry-point group  (Sprint-7A2)
```

Each scaffolder writes a complete pack tree (manifest + pyproject +
inert source + README) with `AUTHOR-FILL:` placeholders the validator
refuses on. Replace every placeholder with a real value before
proceeding. Hook packs do NOT ship an `agent_cards/` directory — the
JWS arm in `cli/sign.py` + `cli/verify.py` is gated on
`pack_kind == "agent"`. Section 8 covers the hook-specific manifest
shape + the runtime DLP enforcement boundary.

**Canonical workflow order: `init → build wheel → sign --bundle →
validate → test-harness → verify`.** The `agentos validate` step
checks `supply_chain.attestation_paths` for non-empty + every declared
file present on disk; the seven attestation files are produced by
`sign --bundle`, so the realistic flow runs sign FIRST and then
validates against the populated tree. Running `agentos validate` on a
fresh checkout (before any sign) WILL refuse — that's the expected
shape, not a bug; it's a useful pre-sign **readiness check** for
catching block-shape errors before you spend wall-clock time on the
sign pipeline.

**Build the wheel.**

```
python -m build --wheel    # or `uv build`
```

**Sign + bundle.** Run the four supply-chain binaries (cosign / syft /
grype / pip-licenses) + emit the SLSA + in-toto attestations + (agent
packs) sign the AgentCard JWS:

```
agentos sign --bundle .
```

This populates `attestations/` with the seven files the runtime trust
gate verifies. For agent packs, `agent_cards/agent-card.jws` is also
written.

**Validate (now passes).**

```
agentos validate .
```

The orchestrator runs six per-concern validators (identity, a2a, mcp,
data_governance, risk_tier, supply_chain) plus a shape gate against
the canonical [pack] / [identity] / [a2a] / [mcp] / [data_governance]
/ [risk_tier] / [supply_chain] block layout (the legacy
`[tool.cognic.*]` shape is also accepted via dual-path lookup).

**Optional pre-sign readiness check.** If you want to catch
block-shape / closed-enum / AUTHOR-FILL errors before running the
sign pipeline, you CAN run `agentos validate .` before sign — but
expect a refusal on `supply_chain.attestation_paths` because the
attestation files do not exist yet. That refusal is informational;
proceed with the sign step and re-validate after.

**Optional: `agentos test-harness`.** Sprint-7B.1 T6a + T6b
delivered the harness's per-kind dry-run dispatch for all four
supported kinds (`tool` / `skill` / `agent` / `hook`); kinds
outside that set are refused with `harness_unsupported_pack_kind`
at the kind-narrowing gate. Each kind dispatches through its
PUBLIC SDK seam (never the private `_invoke` paths) against the
**unmodified host runtime** so the SDK's validation seams fire
end-to-end before publish:

- `tool` — `await tool.invoke()` against the Tool input/output
  schema-validation seam.
- `skill` — `Skill(tools=<no-op-registry>) + await skill.execute()`
  against the R5 P2 #3 cross-check seam (the no-op registry is
  derived from your skill's `declared_tools` ClassVar so
  multi-tool skills get an exactly-matching registry).
- `agent` — `await agent.handle(payload=b"", task=<synthetic
  TaskRecord>)` against the Agent abstract method seam.
- `hook` — `await hook.invoke(context, payload)` against the
  public seam at `sdk/hook.py:347` (NOT the abstract `_invoke` at
  `:373`). The harness runs all three SDK validation phases
  (pre-`_invoke` context + pre-`_invoke` payload + post-`_invoke`
  result-shape) and strips the raw `redacted_payload` bytes from
  the conformance report per ADR-017 + Doctrine Lock E.

```
agentos test-harness .
```

**Wave-1 narrow contract.** The harness does NOT install
`httpx.MockTransport`, inject `agentos_sdk.testing.fixture_settings`,
scope environment variables, or sandbox filesystem / network access.
Tool `_invoke()` code runs against real httpx / hvac / sqlalchemy /
Langfuse clients if your pack constructs them. If your tool performs
live network or filesystem actions at import time or `_invoke()`
time, those actions WILL fire during `agentos test-harness`. Pack
authors who need fixture-adapter isolation wire it themselves in
their pack test suite via `agentos_sdk.testing.fixture_settings` /
`agentos_sdk.testing.fixture_audit_capture` — the harness is a
pre-publish sanity gate (validate pipeline + `Tool.invoke` dispatch
+ conformance report), NOT a sandbox.

**Verify offline.** Optional dry-run of the runtime trust gate against
the freshly signed bundle. Same 11-step pipeline the runtime
plugin-registry runs at admission time, plus the load probe (Step 11):

```
agentos verify .
```

**Reference packs.** Four minimal-but-valid packs at
`examples/cognic-{tool,skill,agent,hook}-example-minimal/` demonstrate
the full lifecycle for each kind (the hook pack lands in
Sprint-7A2 T11). They are inert by design (no production behavior)
but every committed artifact passes every gate; copy a reference
pack, substitute real behavior, and the surrounding manifest +
pyproject + lifecycle is already valid. The agent example ships an
explicit test-only RSA-2048 keypair under
`attestations/test-signing/` (with a NOTE.md spelling out the
test-only doctrine + the `prod`-profile rejection guard); hook
packs reuse the same keypair only via the lifecycle-test fixture and
ship neither an `agent_cards/` directory nor a test-signing keypair
of their own.

**The detailed plumbing.** Sections 1–7 below describe the manifest
shapes, the seven attestation files, and the runtime trust gate that
sits beneath the CLI. The CLI automates most of it; read the deeper
sections when you need to debug a refusal or override a step.

---

## 1. Anatomy of a pack

A pack is **a Python distribution** that declares one or more entry
points under the `cognic.tools`, `cognic.skills`, or `cognic.agents`
group. AgentOS's `protocol/plugin_registry.py` walks
`importlib.metadata.entry_points()` for those three groups at startup
and registers what it finds.

Minimum file layout:

```
your_pack/
├── pyproject.toml                  # distribution metadata + entry point
├── your_pack/                      # importable package
│   ├── __init__.py
│   └── tool.py                     # contains the Plugin class
└── attestations/                   # supply-chain attestation set
    ├── sbom.cdx.json
    ├── slsa-provenance.intoto.json
    ├── intoto-layout.json
    ├── vuln-scan.json
    ├── license-audit.json
    ├── cosign.sig
    └── bundle.sigstore
```

The seven attestation files are what the trust gate verifies; section 4
covers them.

---

## 2. The `pyproject.toml` manifest

### 2.1 Distribution metadata + entry point

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "your-pack"                  # the SIGNED distribution identity (kebab-case)
version = "0.1.0"
description = "What this pack does, in one line."
requires-python = ">=3.11"

[project.entry-points."cognic.tools"]
your_pack = "your_pack.tool:Plugin" # entry-point alias (snake-case) → import target
```

**Critical rule (T10):** the **distribution name** (`name = "your-pack"`)
is what cosign signs and what AgentOS keys allow-list lookups against.
The **entry-point alias** (the LHS of the entry-point line) is just a
human-friendly name — it can differ from the distribution name. The
fixture pack deliberately uses `cognic-test-pack` as the distribution
and `cognic_test_pack` as the entry-point alias to force pack authors
to confront this distinction; if your two values match by accident, your
allow-list edit will still work, but if you ever introduce a divergence
later you will get a `not_in_tenant_allowlist` refusal at startup that
looks mysterious. Pick one early.

### 2.2 Identity block — `[tool.cognic.identity]` (per ADR-002 §AGNTCY/OASF)

```toml
[tool.cognic.identity]
agent_id = "urn:cognic:agent:your_pack:0.1.0"
display_name = "Your Pack"
provider_organization = "Your Org"
provider_url = "https://your.org"
agent_card_url = "https://packs.your.org/agent_cards/your_pack.json"  # agents only
agent_card_jws_path = "agent_cards/your_pack.jws"                     # agents only
oasf_capability_set = ["your", "capabilities"]                        # Wave 1 optional
verifiable_credentials_path = "credentials/your_pack.vc.jsonld"       # Wave 1 optional
```

**Wave 1 mandatory vs optional** (see ADR-002 §"Wave 1 identity-field
strictness"):

| Field | Wave 1 |
|---|---|
| `agent_id` (URN form) | Mandatory |
| `display_name` | Mandatory |
| `provider_organization` + `provider_url` | Mandatory (both) |
| `agent_card_url` | Mandatory for agent packs; tool/skill packs omit |
| `agent_card_jws_path` | Mandatory for agent packs; tool/skill packs omit |
| `oasf_capability_set` | Optional (warning if absent); Wave 2 mandatory |
| `verifiable_credentials_path` | Optional/reserved; Wave 3 flips mandatory |

### 2.3 Conformance + governance blocks (per ADR-002 / ADR-017)

The full `agentos validate` (Sprint 7A) checks five additional blocks:
`[tool.cognic.mcp]`, `[tool.cognic.a2a]` (agents only),
`[tool.cognic.data_governance]`, `[tool.cognic.runtime]`, and
`[tool.cognic.supply_chain]`. The exact field set per block is documented
in ADR-002 §"AGNTCY/OASF-compatible manifest fields" + ADR-017 + the
plan section in `docs/BUILD_PLAN.md` lines 515–520. Sprint 7A formalises
the validator; until then, the registry verifies the
`[tool.cognic.supply_chain]` block (section 4 below) and treats the rest
as documentation.

---

## 3. The `Plugin` class

Whatever the entry point points to — `your_pack.tool:Plugin` in the
example — must be importable. AgentOS does **NOT** import it during pack
admission (the §1 deferred-load invariant); it imports only when the
runtime explicitly calls `PluginRegistry.load(kind, name)`. This means
your `Plugin` class can have heavy dependencies and they will not be
loaded until first use:

```python
# your_pack/tool.py
class Plugin:
    name: str = "your_pack"
    version: str = "0.1.0"
    # Tool-specific contract per ADR-002 / ADR-014; see the
    # cognic-tool-* reference packs for tool-shaped Plugins,
    # cognic-skill-* for skill-shaped, cognic-agent-* for agents.
```

If your `Plugin.__init__` raises during admission, you have a bug — the
admission path doesn't call it. If it raises on first `load()` call, the
runtime surfaces that as a load failure, *not* a registration refusal.

---

## 4. Attestation requirements (per ADR-016)

Every pack version registered in AgentOS carries a **supply-chain
attestation set** that the trust gate verifies before the pack admits.
Wave 1 splits the set into a mandatory floor (refuses registration if
any are missing) and a grace-period tier (registers with
`attestation_grade: partial`; tenants can require `full` via policy).

### 4.1 Mandatory floor (Wave 1 — registration refused if missing)

| File | What it proves | How to generate |
|---|---|---|
| `attestations/cosign.sig` | Identity of the publisher | `cosign sign-blob --bundle bundle.sigstore --output-signature cosign.sig <wheel>` |
| `attestations/sbom.cdx.json` | Full transitive dependency inventory (CycloneDX 1.5) | `syft <wheel> -o cyclonedx-json > sbom.cdx.json` |
| `attestations/bundle.sigstore` | Combined cosign + Rekor entry, offline re-verifiable | `cosign sign-blob --bundle bundle.sigstore <wheel>` |

The trust gate refuses any pack missing one of these three regardless of
tenant policy.

### 4.2 Grace-period tier (Wave 1 — `attestation_grade: partial` if missing)

| File | What it proves | How to generate |
|---|---|---|
| `attestations/slsa-provenance.intoto.json` | SLSA L3+ provenance | `slsa-github-generator` workflow OR equivalent |
| `attestations/intoto-layout.json` | Build steps performed in declared order by declared parties | `in-toto-attest` with your build step list |
| `attestations/vuln-scan.json` | CVE scan against your transitive deps | `grype <wheel> -o json > vuln-scan.json` |
| `attestations/license-audit.json` | Transitive license list | `syft <wheel> -o syft-text \| your license-classifier > license-audit.json`, or Cognic's reference shape: `{"licenses": [...], "artifacts": [...]}` |

Tenants that set `require_full: true` in their policy bundle (per ADR-015)
will refuse `partial` packs. If your bank-tenant has set this — and most
production tenants will — you must ship all four grace-period files too.

### 4.3 Manifest declaration

In your `pyproject.toml`, point the registry at the files:

```toml
[tool.cognic.supply_chain]
slsa_level = 3                              # the level your provenance attests
provenance_url = "attestations/slsa-provenance.intoto.json"
sbom_path = "attestations/sbom.cdx.json"
vuln_scan_report = "attestations/vuln-scan.json"
license_audit_report = "attestations/license-audit.json"
reproducibility_manifest = "uv.lock"        # or package-lock.json / Cargo.lock / etc.
sigstore_bundle_path = "attestations/bundle.sigstore"
```

### 4.4 Wave 1 escape hatch — generating the bundle by hand

`agentos sign --bundle` (Sprint 7A) will eventually wrap all of this in
a single command. Until that ships, the reference recipe is:

```bash
# 1. Build the wheel
uv build

# 2. SBOM (mandatory)
syft "dist/your_pack-0.1.0-py3-none-any.whl" \
  -o cyclonedx-json > attestations/sbom.cdx.json

# 3. cosign sign-blob with bundle (mandatory — produces cosign.sig + bundle.sigstore)
COSIGN_EXPERIMENTAL=1 cosign sign-blob \
  --output-signature attestations/cosign.sig \
  --bundle attestations/bundle.sigstore \
  --yes \
  "dist/your_pack-0.1.0-py3-none-any.whl"

# 4. SLSA provenance (grace-period — strongly recommended)
#    Easiest path: slsa-github-generator workflow on GitHub Actions.
#    Manual path: see https://slsa.dev/provenance/v1

# 5. in-toto layout (grace-period)
#    in-toto-attest --in-toto-layout layout.toml ... > attestations/intoto-layout.json

# 6. Vuln scan (grace-period)
grype "dist/your_pack-0.1.0-py3-none-any.whl" -o json > attestations/vuln-scan.json

# 7. License audit (grace-period) — Cognic shape:
#    {"licenses": ["MIT", "Apache-2.0"], "artifacts": [...]}
#    Generate from `syft -o syft-text` and classify; or use a CI helper.
```

The fixture pack at `tests/fixtures/_signing_kit/build_test_attestations.sh`
has a working reference: in `--regenerate` mode it does the cosign step
end-to-end with an ephemeral keypair. Do not ship to production with an
ephemeral keypair; use your bank-tenant's Vault-stored signing key.

---

## 5. Local verification before submission

`agentos verify <pack-path>` (Sprint 7A) will run the same checks the
trust gate runs at registration time, locally, before you submit to
the bank-pack lifecycle. Until that ships, the Wave 1 recipe is to run
the unit-test smoke against your pack:

1. Install your pack: `uv pip install -e path/to/your_pack/`
2. Run AgentOS's plugin registry test suite, scoped to admission:
   `uv run pytest tests/unit/protocol/test_fixture_pack_admission.py -v`
3. Adapt that test (it's ~290 LoC, well-commented) to point at your
   pack's `DiscoveredPack` + `PackAttestations` instead of the fixture's,
   then run again. If it admits at `attestation_grade: full`, the bank
   reviewer will too.

---

## 6. Where the verification path lives in the AgentOS source

When something fails and the message isn't enough, the verification path
is short and well-named:

| File | Role |
|---|---|
| `src/cognic_agentos/protocol/plugin_registry.py` | Entry-point discovery + `register_with_full_attestation_check()` (the integration method that calls each verifier in order) |
| `src/cognic_agentos/protocol/trust_gate.py` | cosign signature verification (subprocess shell-out to the pinned cosign binary) |
| `src/cognic_agentos/protocol/supply_chain.py` | SBOM format + SLSA L3+ + in-toto + vuln + license + Sigstore bundle persister (7-year retention per ADR-016) |
| `src/cognic_agentos/protocol/reproducibility.py` | Reproducibility-manifest digest verification (informational in Wave 1) |
| `policies/_default/supply_chain.rego` | Default Rego policy that maps an admitted pack's attestation grade onto an admit/deny decision |
| `policies/_default/plugin_allowlist.json` | Default per-tenant allow-list (keyed off **distribution name**, not entry-point alias) |

Closed-enum refusal reasons (the `RefusalReason` literal in
`plugin_registry.py`) are the eight values the trust gate / supply chain
emits. If your pack is refused, the audit event records exactly one of
those values; pair it with the file table above to trace the cause.

---

## 7. Cross-reference

- **ADR-002** — plugin protocol, manifest shape, AGNTCY/OASF identity, MCP STDIO threat model
- **ADR-012** — bank-pack lifecycle (`proposed → under_review → approved → allow_listed → installed`)
- **ADR-014** — runtime tool approval / risk tiers (`[tool.cognic.runtime]` block)
- **ADR-015** — policy-as-code Rego bundles (where tenants set thresholds)
- **ADR-016** — supply-chain controls (the *why* behind section 4)
- **ADR-017** — data-governance contracts (`[tool.cognic.data_governance]` block)
- **`docs/MCP-CONFORMANCE.md`** — what MCP features Wave 1 supports/restricts
- **`docs/A2A-CONFORMANCE.md`** — what A2A features agent packs declare
- **`tests/fixtures/cognic_test_pack/`** — worked example (this is the canonical reference)

---

## 8. Hook packs (Sprint-7A2 / ADR-017)

Hook packs are the 4th first-class pack kind alongside tool / skill /
agent. They ship deterministic governance extensions (PII redaction /
account masking / output egress checks / etc.) registered under the
`cognic.hooks` entry-point group; DLP-aware tool / skill / agent packs
reference them via `[data_governance].dlp_pre_hooks` /
`dlp_post_hooks` (PACK-MANIFEST-SPEC.md §5). The runtime DLP adapter
at `packs/hooks/dlp_integration.py` (T8 critical-controls module)
wraps the hook dispatcher with `dlp_pre` / `dlp_post` phase
semantics + a closed-enum 3-value `DLPRefusalReason` taxonomy.

**Why hook packs vs. shipping DLP code inside the calling pack?**
Separation of duty. A regulator-friendly pack ecosystem keeps the
DLP recogniser code in dedicated hook packs that can be audited +
cosigned + version-pinned independently of the consuming
tool / skill / agent. Banks ship their own `cognic-hook-redact-<bank>`
packs without forking every DLP-aware tool pack.

### 8.1 Scaffold + sign + validate + verify

Hook packs ride the same lifecycle as every other kind:

```
agentos init-hook  redact-pii-pan
cd cognic-hook-redact-pii-pan
# fill the AUTHOR-FILL placeholders in cognic-pack-manifest.toml + pyproject.toml
python -m build --wheel
agentos sign --bundle .       # produces 7 attestations under attestations/
agentos validate .            # passes once attestations exist on disk
agentos test-harness .        # green path post Sprint-7B.1 T6b — Hook.invoke(context, payload) seam
agentos verify .              # offline trust-gate dry run; 11-step pipeline
```

Two doctrine differences vs tool / skill / agent packs:

1. **No AgentCard JWS.** Hook packs do NOT ship an `agent_cards/`
   directory. The JWS arm in `cli/sign.py` + `cli/verify.py` is
   gated on `pack_kind == "agent"`; sign skips JWS generation +
   verify skips Step 9 (JWS verification) for hook packs. The
   validator does NOT enforce the JWS gate — ownership lives
   sign-side + verify-side.
2. **Harness dispatch via the public `Hook.invoke` seam.** Sprint-
   7B.1 T6b wired hook-pack dispatch dry-run via
   `Hook.invoke(context, payload)` at `sdk/hook.py:347` (NOT the
   abstract `_invoke` at `sdk/hook.py:373`) so the SDK's three
   validation phases (`_validate_hook_context` /
   `_validate_hook_payload` / `_validate_hook_result`) fire
   against your hook subclass end-to-end. The harness's
   conformance report strips raw `redacted_payload` bytes per
   ADR-017 + Doctrine Lock E (the AST-walk regression at
   `tests/architecture/test_hook_payload_never_logged.py` is
   extended to the harness layer in T6b's
   `test_hook_dispatch_report_never_carries_redacted_payload_bytes`).
   Sign + verify remain kind-agnostic so the full lifecycle runs
   end-to-end through the supply-chain + trust-gate path.

### 8.2 Manifest shape — `[hooks]` block

Every `kind = "hook"` pack ships a `[hooks]` block declaring the
hooks the pack registers. Each declaration matches a
`[project.entry-points."cognic.hooks"]` key in the same pack's
`pyproject.toml`. Full schema at PACK-MANIFEST-SPEC.md §8;
minimal example:

```toml
[pack]
pack_id = "cognic-hook-redact-pii-pan"
schema_version = 1
kind = "hook"

[identity]
agent_id = "did:web:example.com:hooks:redact_pii_pan"
display_name = "Redact PII PAN"
provider_organization = "Example Bank"
provider_url = "https://example.com/packs"
agent_card_url = "https://example.com/packs/hooks/redact_pii_pan/card.json"
oasf_capability_set = ["dlp.pii.v1"]

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = []

[risk_tier]
tier = "read_only"

[hooks]
[[hooks.declarations]]
hook_id = "redact_pii_pan"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"

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
```

`fail_policy = "fail_closed"` is the only accepted Wave-1 value per
ADR-017 + Doctrine Lock E. The validator refuses every
`fail_open` declaration with closed-enum `hook_fail_policy_invalid`
(failure_mode `fail_open_without_exception`) — the matching
exception-declaration shape (a per-`HookDeclaration` runtime
carve-out, NOT a `[data_governance]` field) is reserved for a
follow-up sprint and not yet wired up. Use `fail_closed` until
that lands. See the operator runbook at
`docs/operator-runbooks/hook-pack-failure-policy.md` for the
audit-trail contract + the 5 dispatcher failure modes.

### 8.3 The `Hook` subclass

```python
# cognic_hook_redact_pii_pan/hook.py
from typing import ClassVar

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


class RedactPIIPANHook(Hook):
    hook_id: ClassVar[str] = "redact_pii_pan"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        # Inspect payload (BUT DO NOT log / store / exfiltrate it —
        # the AST-walk regression at
        # tests/architecture/test_hook_payload_never_logged.py pins
        # the payload-never-logged invariant).
        if self._contains_pan(payload):
            return HookResult(
                decision="redact",
                redacted_payload=self._redact(payload),
                policy_reason=None,
            )
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)
```

The SDK's template-method seam validates `context` + `payload`
BEFORE `_invoke` runs and validates the returned `HookResult`
AFTER. `Hook.invoke()` is `@final` (mypy + runtime guarded) — pack
authors override `_invoke` only.

For the full SDK contract (`HookContext` field surface, `HookResult`
decision-↔-fields invariant, exception hierarchy, `HookContractError`
sub-classes, dispatcher failure modes) see SDK-REFERENCE.md §8.

### 8.4 Reference pack

`examples/cognic-hook-example-minimal/` is the canonical worked
example. It is inert by design (`_invoke()` returns `decision="pass"`
unconditionally without touching the payload); every committed
artifact passes every gate. The lifecycle gate at
`tests/unit/cli/test_reference_packs_full_lifecycle_green.py::test_reference_hook_pack_full_lifecycle_green`
re-verifies it on every build.
