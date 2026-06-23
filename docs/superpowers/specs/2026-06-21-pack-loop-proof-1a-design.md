# Proof 1a — Real-App In-Process Pack-Governance Loop — Design Spec

**Date:** 2026-06-21
**Status:** Design — approved with the MCP-auth correction (2026-06-21)
**Epic:** First real-pack end-to-end proof. Sequence: **Proof 1a** (this spec) → Proof 1b (kind/Helm deploy) → Proof 2 (separate repo + independent pack CI).
**Relates to:** ADR-001 (OS-only), ADR-002 (MCP plugin protocol), ADR-012 (pack lifecycle), ADR-016 (supply chain); the MCP/A2A startup-discovery slice (PR #92); the `docs/PROJECT_STATUS.md` headline gap.

---

## 1. Problem — the seam this proves

The AgentOS kernel is built and unit-tested, but the full deployable loop — *deploy → install a real signed pack → an agent does one governed task → audit trail* — has never run end-to-end with a **real** pack. In particular, the startup-discovery slice (PR #92) unit-proved the **runtime** trust pipeline against **hand-built** attestations. The seam between the **authoring** output and the **runtime** trust-registration **input** has never been exercised:

```
agentos validate/sign/verify output
  → pack_attestation_resolver expected layout
  → register_with_full_attestation_check
  → MCP runtime catalog
  → tool call
  → audit / decision-history / evidence
```

**Green ⇔ the real authoring trust pipeline produces artifacts the real runtime trust pipeline accepts.**

## 2. Scope + honesty boundary

**In scope (this spec):** Proof 1a — the loop above, run against the **real composition root in-process**, with a **real** `agentos validate/sign/verify` pipeline and **real** attestation-root + trust-root handoff.

**Sequenced (separate slices, not this spec):**
- **Proof 1b** — the *same signed pack* on a kind/Helm-deployed instance (boot-time registration via image-bake or mounted volume + pod restart — there is no runtime install API). This is the rung that starts closing the `PROJECT_STATUS.md` headline gap.
- **Proof 2** — extract `cognic-tool-search` to its own repo with independent pack CI.

**Honesty boundary (must appear verbatim in `VALIDATION-RESULTS.md`):**
> Proof 1a proves the pack-governance loop in the real composition root. Proof 1b proves the same signed pack in a kind/Helm deployed instance.

1a proves the loop **logic**; it does **not** claim "bank-deployed."

**Explicitly out of scope for 1a:** the approval/4-eyes seam (the tool is `read_only` and auto-runs through the gate; approval is already proven by the Sprint 14A approval integration tests); real web/network retrieval; multi-tool packs; deployment.

## 3. The pack — `examples/cognic-tool-search/`

In-tree but a real external-to-OS artifact: built into a wheel, signed, and installed *as if* external. It cannot leak into the OS image — `pyproject.toml` ships only `packages = ["src/cognic_agentos"]`, and `tests/unit/architecture/test_no_pack_imports.py` forbids the OS importing a pack.

Components:
- **`cognic-pack-manifest.toml`**
  - `[pack]` — `pack_id`, `schema_version = 1`, `kind = "tool"`. There is **no** `name`/`version` field here; the distribution name + version come from the wheel/`pyproject.toml` metadata (and drive the runtime attestation-root path, §4).
  - `[identity]` — the **universally** mandatory Wave-1 fields are `agent_id`, `display_name`, `provider_organization`, `provider_url`. The agent-card fields (`agent_card_url`, `agent_card_jws_path`) are **agent-pack-only** — the identity validator (`cli/validators/identity.py`) does **not** refuse a tool pack for omitting them (the scaffold ships them as inert `AUTHOR-FILL` placeholders).
  - `[risk_tier]` — `tier = "read_only"`.
  - `[data_governance]` — minimal: a benign data class, `purpose`, `retention_policy = "none"`, an egress allow-list consistent with `read_only`.
  - `[supply_chain]` — `attestation_paths` for the signed bundle.
  - **`[tool.cognic.mcp]`** — the **runtime-consumed** block (NOT the older `[mcp]` shape): `transport = "streamable-http"`, **`auth = "oauth-prm"`**, `scopes = ["mcp:tools"]` (the runtime-consumed key is `scopes`, not `required_scopes`), `resources_supported = false`, `prompts_supported = false`, `sampling_supported = false`, `conformance_version`.
- **MCP server module** — a real Streamable-HTTP MCP server exposing one tool, `search_policy_docs(query: str)`. It advertises **Protected Resource Metadata (PRM)** pointing at the local test authorization server (§5).
- **Bundled corpus** — a handful of static policy documents shipped as package data; `search_policy_docs` does a deterministic substring/keyword match over them. No network, no provider — so the proof fails only on AgentOS integration.
- **`pyproject.toml`** — builds a wheel; registers the `cognic.tools` entry point so `discover()` finds it; includes the corpus as package data.

The existing `examples/cognic-tool-example-minimal/` is scaffolding only (older `[mcp]` shape) — useful as a starting template but not sufficient for this proof.

## 4. Authoring trust pipeline (full real, operator-run)

**Canonical order — sign *before* validate.** `agentos validate` checks `supply_chain.attestation_paths` exist, and those files are produced by `sign --bundle`; a pre-sign validate refuses by design (`docs/HOW-TO-WRITE-A-PACK.md:73`).

1. **Build the wheel** — `python -m build --wheel` (or `uv build`).
2. `agentos sign --bundle examples/cognic-tool-search/` → real cosign sign-blob + syft SBOM + grype vuln scan + license audit + SLSA provenance + in-toto layout → the attestation bundle.
3. `agentos validate examples/cognic-tool-search/` → clean against the now-populated attestation tree. (A *pre-sign* `validate` is an optional **readiness** check for block-shape errors — it refuses on missing attestations by design and is **not** a pass criterion.)
4. `agentos verify examples/cognic-tool-search/` → exits 0.
5. A **real cosign keypair**; its public key is copied to `<trust_root_prefix>/_default/cosign.pub` (the locked runtime cosign trust anchor).
6. The wheel + attestations are copied to `pack_attestation_root_path/<distribution_name>/<distribution_version>/` — the directory the runtime resolver derives from the **discovered** distribution metadata (not a manifest version field).

The runtime resolver (`protocol/pack_attestation_resolver.py`) expects, under that directory: `cosign.sig`, `bundle.sigstore`, `sbom.cdx.json`, `slsa-provenance.intoto.json`, and a single `*.whl` (the cosign blob); the SBOM digest is sourced from the SLSA provenance at `predicate.buildDefinition.externalParameters.sbom_digest_sha256`. **The proof checks `agentos sign`'s actual output against this expected layout — a mismatch is the headline expected finding (§10).**

## 5. Runtime auth path (the corrected design)

**Grounding (verified):** `MCPHost.list_tools` / `call_tool` *always* call `MCPAuthzClient.acquire_token(server_url, manifest_scopes, request_id, tenant_id)` before opening the transport session (`protocol/mcp_host.py:840`). The `api-key` fallback is validated at admission/registration in `plugin_registry.py` — it is **not** the runtime invocation path. Therefore 1a uses **OAuth/PRM** for the runtime call.

The env-gated proof stands up a **tiny local OAuth/PRM test server**:
- The pack's MCP server advertises **PRM** → advertises the local authorization server (AS).
- A **test secret adapter** (not a full Vault deployment) holds the per-tenant **AS allow-list** and the OAuth client credentials.
- The AS **token endpoint** returns a JWT with `aud = server_url`, `scope = "mcp:tools"` (a subset of the manifest `scopes` — no over-grant), and a valid `expires_in`.
- The harness runs in **`runtime_profile = "dev"`**, so `mcp_authz`'s loopback/private/link-local/reserved discovery-URL rejection (strict `stage`/`prod` profiles only — `protocol/mcp_authz.py:1007`) does not fire for the localhost AS/PRM URLs.

This exercises the **real** `acquire_token` path end-to-end: PRM discovery → AS allow-list check → token fetch → audience validation → scope-subset enforcement.

## 6. The proof harness — `tests/integration/pack_loop/test_proof_1a_inprocess.py`

- **Env-gate:** skips unless `COGNIC_RUN_PACK_LOOP_PROOF=1`. When set, **fail loud** (not skip) if the toolchain (cosign/syft/grype) is missing — mirrors `tests/integration/models/test_real_cosign_proof.py`.
- **Backend footprint:** real **Postgres** (compose) for decision-history so the hash chain is genuinely persisted and verifiable; real **local_fs** object-store for attestations/evidence; a **test secret adapter** for the AS allow-list + OAuth credentials. **No** Redis / scheduler / sandbox (a `read_only` MCP invoke is host → transport → pack server; it touches none of them). **No** full Vault deployment.
- **Steps:**
  1. (operator pre-step / fixture) build the wheel, run `agentos sign`, place wheel + attestations + cosign pub (§4).
  2. pip-install the wheel into the env (so the `cognic.tools` entry point is discoverable).
  3. configure `Settings` — `pack_attestation_root_path`, `trust_root_prefix`, `runtime_profile = "dev"`.
  4. launch the pack's MCP server subprocess (Streamable HTTP + PRM) and the local AS.
  5. boot the **real composition root** → `build_and_populate_registry` → `discover()` → `resolve_pack_attestations` → `register_with_full_attestation_check` → populated registry → `build_mcp_host(registry)`.
  6. drive a real tool call via the production route `POST /api/v1/mcp/servers/{server_id}/tools/call`, with a bound `Actor` holding the `mcp.tool.invoke` scope (proves the production surface, not just the host object).
  7. assert the PASS criteria (§7).

## 7. PASS criteria (green-iff)

1. `agentos verify` exits 0 on the signed pack.
2. `build_and_populate_registry` registers `cognic-tool-search` **without** a fail-soft skip — i.e. the real runtime attestation pipeline *accepted* real `agentos sign` output (**the core seam assertion**).
3. `list_tools` reports `search_policy_docs` in the catalog.
4. `call_tool("search_policy_docs", {query})` via the route returns the deterministic expected result.
5. A decision-history / audit row exists for the invocation carrying pack identity + signature digest; the hash chain verifies.
6. An evidence pack exports and re-verifies (tamper-evident).

**Green ⇔ the real authoring trust pipeline produces artifacts the real runtime trust pipeline accepts.**

## 8. Deliverable — `docs/VALIDATION-RESULTS.md`

The operator's recorded run: the exact commands, their outputs, the six green assertions, artifact digests (wheel / cosign signature / SBOM), and the AgentOS commit under test. This is the artifact the `PROJECT_STATUS.md` headline gap points at; a green 1a flips that headline from "never run end-to-end" to "loop proven in the real composition root; deployment proof = 1b."

## 9. Fallback (b) — diagnostic only

If a hard blocker stops the full pipeline (e.g. a signing binary is unavailable in the lane), the **(b)** path — real cosign signature + minimal-valid hand-built SBOM/SLSA/bundle that satisfy the runtime's shape + digest checks — is permitted **only** as a diagnostic, recorded explicitly in `VALIDATION-RESULTS.md` as *"diagnostic fallback, not the proof."* It still verifies a real signature but does not exercise the real signing pipeline, so it does not satisfy the green-iff in §7.

## 10. Risks / expected findings

- **The seam (headline, by design):** `agentos sign`'s emitted filenames/shapes may not match the resolver's expected layout — most sharply, whether `sign` writes the SLSA `predicate.buildDefinition.externalParameters.sbom_digest_sha256` field the resolver reads, and the exact `cosign.sig` / `bundle.sigstore` / `sbom.cdx.json` / `slsa-provenance.intoto.json` names. A mismatch turns 1a red and surfaces a real author↔runtime gap to fix — which is the point of running it.
- **The auth flow:** the local OAuth/PRM test server (PRM discovery shape, AS allow-list wiring, JWT `aud`/`scope`/`expires_in`) is the most intricate harness piece.
- **Backend footprint creep:** the real composition root may pull in adapters beyond the curated set; if so, the footprint in §6 expands — to be confirmed when writing the plan (verify against `build_runtime` / `create_prod_app`).

## 11. Open items to resolve at plan time (verify against real code)

- Exact `agentos sign` output filenames vs the resolver's expected names (do not pre-assume they match — the proof exists to check).
- The minimal real-auth wiring for `acquire_token` against the local AS (the precise PRM document shape + the test secret-adapter AS-allow-list key).
- Whether the in-process composition-root boot needs any adapter beyond Postgres + local_fs + test secret adapter for a `read_only` MCP invoke path.
- The MCP-server SDK specifics for advertising PRM on a Streamable-HTTP server.

---

*Sequenced follow-ons after a green 1a: Proof 1b (kind/Helm, same signed pack — the deployment proof), then Proof 2 (separate repo + pack CI).*
