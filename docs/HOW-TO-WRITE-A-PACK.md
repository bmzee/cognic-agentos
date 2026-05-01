# How to write a Cognic AgentOS plugin pack

This doc tells you how to build a plugin pack that AgentOS will register
at startup. It is the pack-author counterpart to ADR-002 (plugin
protocol), ADR-016 (supply-chain controls), and ADR-017 (data-governance
contracts) — read those when you need the *why*; this doc tells you the
*what* in checklist form.

**Audience.** Engineers writing a tool, skill, or agent pack that will
ship as its own distribution and install on top of AgentOS via
`uv pip install` (or whatever the operator's pack channel is).

**Wave 1 scope.** This doc reflects Sprint 4 / Wave 1. Items marked as
**Wave 2** or **Sprint 7A+** describe the eventual contract; the
**Wave 1 escape hatch** subsection under each tells you what to do
*today* before that tooling lands.

The canonical worked example is the in-tree fixture pack at
`tests/fixtures/cognic_test_pack/` — a complete, installable pack with
a full attestation set. When this doc and that fixture disagree, the
fixture is right (CI re-verifies it on every build) and this doc is
wrong; please open an issue.

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
