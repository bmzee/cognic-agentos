# M3-E2 — FastMCP tool-pack authoring path + `cognic-tool-oracle-schema` (design)

**Date:** 2026-06-28
**Status:** APPROVED (design) — ready for implementation planning (`writing-plans`)
**Milestone:** M3 / Proof 2 in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md`. This spec covers M3-E2; the M3 checkbox flips only when M3-E2c (the deployed proof) runs green against the released artifact.
**Builds on:** M3-E1 (git-pinned authoring enablement; merged #106/#107 @ `4f27950`, tag `v0.0.1`). Reuses the proven Proof 1b-2 kind topology (`infra/proof-1b/`).

---

## 1. Goal

Make AgentOS's official tool-pack authoring path (`agentos init-tool`) emit the **real FastMCP MCP-server shape** that production tool packs use, then create the first external product pack — **`cognic-tool-oracle-schema`** (read-only Oracle schema metadata) — *through that path*. The pack does double duty: a useful product pack **and** proof that the documented/scaffolded authoring story matches the real product path.

M3 is not "can we hand-build one external repo." It proves the production-grade pack-development path end to end: scaffold → external repo → independent CI/sign/verify/release → install/prove through a deployed AgentOS. If the official scaffold still emitted the old SDK-`Tool`-subclass while the real pack uses FastMCP, the proof would have a credibility gap.

## 2. Architecture — one combined spec, three phases

| Phase | Where | Deliverable |
|---|---|---|
| **M3-E2a** | `cognic-agentos` (this repo) | Realign `init-tool` scaffold + `sdk/testing.py` to the FastMCP pattern. Merge, then cut tag `v0.0.2`. |
| **M3-E2b** | new external repo `cognic-tool-oracle-schema` | First external product pack, **generated from the realigned scaffold @ `v0.0.2`**: six read-only Oracle schema-metadata tools, real JWT/JWKS auth, independent CI/sign/verify/release, local integration tests. |
| **M3-E2c** | deployed proof (criteria here; detailed kind deploy-plan is a separate follow-on) | Install the **released, signed** pack into a deployed AgentOS, prove the governed loop against an in-cluster seeded Oracle. |

**Ordering is load-bearing:** M3-E2a merges first → `v0.0.2` is cut → M3-E2b is generated from `v0.0.2` → M3-E2c deploys the released M3-E2b artifact.

## 3. The proven FastMCP pattern (grounding)

The pack shape is taken from the proven example `examples/cognic-tool-search/` (Proof 1a/1b), not the current `init-tool` scaffold. Verified in-tree:

- `pyproject.toml` — runtime `dependencies = ["mcp==1.27.0", "uvicorn[standard]>=0.35"]` (**no `cognic-agentos` runtime dep**); `[project.entry-points."cognic.tools"]` → `<name> = "<module>:SERVER_DESCRIPTOR"`; `[tool.hatch.build.targets.wheel.force-include]` ships the root `cognic-pack-manifest.toml` into the wheel as package data.
- `src/<module>/__init__.py` — an inert `@dataclass(frozen=True) _ServerDescriptor` + `SERVER_DESCRIPTOR = _ServerDescriptor()`. The runtime MCP path **never** `EntryPoint.load()`s this object (the tool runs behind HTTP); it exists only so `PluginRegistry.discover()` sees the distribution and `agentos verify`'s load-probe resolves. Must not be import-poisoned.
- `src/<module>/server.py` — `build_server(*, as_issuer) -> FastMCP(...)` with env-driven host/port/`server_url`, `AuthSettings(...)` (resource-server OAuth-PRM), a `token_verifier`, `@mcp.tool(...)` functions; `__main__` runs `.run(transport="streamable-http")`.
- `cognic-pack-manifest.toml` — `[pack]` / `[identity]` / `[data_governance]` / `[risk_tier]` / `[supply_chain]` / `[tool.cognic.mcp]` (the runtime block; key is `scopes`, with `server_url`, `auth = "oauth-prm"`, `transport = "streamable-http"`, `conformance_version`).
- `attestations/` — the 7-file signed bundle produced by `agentos sign --bundle`.

The kernel driver for Oracle is `oracledb` thin-mode async via SQLAlchemy `oracle+oracledb` (`src/cognic_agentos/db/adapters/oracle_adapter.py`; `oracledb>=2.5` in the kernel `pyproject.toml`). The kernel's Oracle test substrate is `infra/dev/docker-compose.oracle.yml` (`gvenzl/oracle-xe:21-slim`, `XEPDB1`, env-gated `COGNIC_RUN_ORACLE_INTEGRATION=1` + `pytest -m oracle`).

---

## 4. Phase M3-E2a — authoring-path realignment (in `cognic-agentos`)

Lands first, on its own PR. The **shape** change (FastMCP server + inert descriptor + manifest `[tool.cognic.mcp]` + kernel-pin-moved-to-dev-extras) is the **`tool` scaffold only**. The `skill` / `agent` / `hook` templates keep their current shape — they are not MCP servers and legitimately import the SDK at runtime (skill = no-LLM `Skill.execute()`, agent = LLM worker, hook = DLP governance extension), so their kernel pin stays a runtime dep. But because `v0.0.2` is the next authoring release, **all four scaffolds' kernel pins (CI step + pyproject) are bumped `@v0.0.1` → `@v0.0.2`** for release consistency — a generated skill/agent/hook pack must not still install the superseded `v0.0.1`.

### 4.1 `init-tool` scaffold → FastMCP shape

Replace the current SDK-`Tool`-subclass scaffold (`src/cognic_agentos/cli/templates/tool/src/__module__/tool.py`) with the FastMCP shape. The realigned `tool` template emits:

- `src/__module__/__init__.py` — an inert frozen `_ServerDescriptor` + `SERVER_DESCRIPTOR` instance carrying an explicit **import-free** marker `cognic_pack_kind = "mcp_server"` (so the kernel can recognise it without the pack importing the kernel — see §4.2). Mirrors the example's `__init__.py`.
- `src/__module__/server.py` — `build_server(*, as_issuer) -> FastMCP(...)` with a trivial sample `@mcp.tool ping() -> str`, env-driven host/url, `AuthSettings` + `token_verifier`, and a `__main__` that runs `streamable-http`. The sample tool means a freshly-scaffolded pack **runs** immediately; per scaffold doctrine the fresh pack still carries AUTHOR-FILL placeholders, so `agentos validate` surfaces explicit remediation rather than a fake clean pass (placeholder hygiene — see §4.3).
- `pyproject.toml`:
  - runtime `dependencies = ["mcp==1.27.0", "uvicorn[standard]>=0.35"]` — **no kernel runtime dep** (baseline matches the proven example; bump at plan time if a newer `mcp` is validated);
  - entry-point `<pack_name> = "<module_name>:SERVER_DESCRIPTOR"`;
  - `[tool.hatch.build.targets.wheel.force-include]` of `cognic-pack-manifest.toml`;
  - **the kernel git-pin moves out of runtime `dependencies` into `[project.optional-dependencies] dev`** (alongside pytest), pinned to **`cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2`** so a `uv pip install -e '.[dev]'` gives the author the `agentos` CLI for local validate/sign/verify;
  - keep `requires-python = ">=3.12,<3.13"` (parity with the kernel authoring window + CI's Python 3.12; avoids the M3-E1 Python-3.13 install fragility).
- `cognic-pack-manifest.toml` — gains the `[tool.cognic.mcp]` block (`transport` / `auth = "oauth-prm"` / `server_url` / `scopes` / `conformance_version`).
- `.github/workflows/sign-and-publish.yml` — unchanged in shape; the explicit `pip install "cognic-agentos @ git+...@v0.0.2"` CI step is bumped to `v0.0.2`.

### 4.2 `sdk/testing.py:_load_entry_point_tools` — three-way classification

Today (`src/cognic_agentos/sdk/testing.py:128-140`) the helper does `cls = entry.load(); instance = cls()` for **every** `cognic.tools` entry, which crashes on a FastMCP pack's inert `SERVER_DESCRIPTOR` (`TypeError: '_ServerDescriptor' object is not callable`). Replace with an explicit three-way classification that never silently drops a broken entry:

1. **SDK `Tool` subclass** (`isinstance(obj, type) and issubclass(obj, Tool)`) → instantiate `obj()` and register (legacy in-process SDK-`Tool` packs).
2. **Recognised inert MCP-server descriptor** → skip intentionally **with a testable trace** (a record on a module logger, caplog-assertable — not a silent drop). FastMCP packs contribute nothing to the in-process registry by design (they run behind HTTP).
3. **Anything else** → **raise** a clear error so a broken/weird entry point is visible (this is a developer testing helper; surprises should fail loudly).

Recognition of (2) is **import-free** (preserving the pack's no-kernel-runtime-dep property) — keyed on the `cognic_pack_kind == "mcp_server"` marker the realigned scaffold emits. **Constraint:** recognition must stay compatible with the already-signed `examples/cognic-tool-search` descriptor **without re-signing it**; the exact predicate (marker check, with a back-compat arm for the example's existing `_ServerDescriptor` shape if the marker would force a re-sign) is pinned at plan time.

This is a semver-sensitive SDK surface (`sdk/testing.py` carries the Doctrine-E halt-before-commit — banks build pack test suites against this contract). The change is backward-compatible (legacy `Tool` packs still discovered); the commit halts before commit.

### 4.3 Scaffold tests

Fresh scaffolds carry AUTHOR-FILL placeholders by doctrine — a fresh pack does **not** `validate` clean; `validate` surfaces explicit remediation pointing at the unfilled fields. So `tests/unit/cli/test_cli_init*.py` assert:
- **Structural FastMCP shape** of the generated `tool` pack: entry-point → `:SERVER_DESCRIPTOR`; `server.py` builds a `FastMCP`; manifest has `[tool.cognic.mcp]`; **no kernel runtime dep**; kernel git-pin present in `[project.optional-dependencies] dev` pinned to `@v0.0.2`; `requires-python == ">=3.12,<3.13"`.
- **Placeholder hygiene** — `agentos validate` on the *fresh* scaffold refuses with explicit AUTHOR-FILL remediation findings (not a fake clean pass).
- **Filled fixture validates clean** (the hard proof the shape is valid once authored) — a fixture with the placeholders replaced by real values passes `agentos validate` (`validate` needs no supply-chain binaries).
- **All four scaffold pins** — the M3-E1 per-kind git-pin tests (tool/skill/agent/hook) assert `@v0.0.2`.

Full `sign` / `verify` stays env-gated/operator (mirrors the M3-E1 `verify.sh` posture — `sign --bundle` shells out to cosign/syft/grype/pip-licenses, absent from CI). A `sdk/testing.py` regression proves the three-way classification: a `Tool` subclass instantiates; a marker-bearing descriptor is skipped with a caplog trace; an unrecognised object raises.

### 4.4 Post-merge tag

After M3-E2a merges to green `main`, cut an annotated tag **`v0.0.2`** from that commit (the M3-E1 pattern — the scaffolds reference the forward tag, which is cut after the enabling PR lands green). `v0.0.2` is the first tag that contains the realigned FastMCP scaffold; M3-E2b is generated from it.

> **Why a new tag (the credibility correction):** `v0.0.1` was the M3-E1 authoring-consumption tag and does **not** contain the realigned scaffold. Generating `cognic-tool-oracle-schema` from `v0.0.1` would claim to dogfood the new authoring path while the public tag still points at the old SDK-`Tool`-subclass scaffold. Tiny version number, big credibility issue.

---

## 5. Phase M3-E2b — `cognic-tool-oracle-schema` (external repo)

### 5.1 Repo

- New, separate repo: `github.com/bmzee/cognic-tool-oracle-schema` (never inside `cognic-agentos`). Version `0.1.0`.
- **Generated via `agentos init-tool` from the kernel @ `v0.0.2`**, then filled with the real tools. Pins `cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2` for dev/CI authoring (in `[project.optional-dependencies] dev`), and records the **resolved kernel commit SHA** in the proof evidence (tag for readability, SHA for integrity).
- Independent CI / sign / verify / release.

### 5.2 The six tools

All tools are fixed, parameterised `SELECT`s against Oracle **data-dictionary views** — never application tables, never user-supplied SQL, never rows, never DML/DDL. Each returns a bounded envelope `{ items | columns: [...], truncated: bool }` (no opaque cursor in v1).

| Tool | Inputs | Source views | Returns (per item) |
|---|---|---|---|
| `list_schemas` | — | `SELECT DISTINCT owner FROM ALL_TABLES` | `owner` (schemas with visible tables, allow-list filtered) |
| `list_tables` | `owner` | `ALL_TABLES` (+ `ALL_TAB_COMMENTS`) | `owner`, `table_name`, `comments` |
| `describe_table` | `owner`, `table` | `ALL_TAB_COLUMNS` (+ `ALL_COL_COMMENTS`) | `column_name`, `data_type`, `nullable`, `data_default`, `comments` |
| `find_columns` | `name_pattern`, `owner?` | `ALL_TAB_COLUMNS` (bound `LIKE`) | `owner`, `table_name`, `column_name`, `data_type` |
| `list_relationships` | `owner`, `table?` | `ALL_CONSTRAINTS` (type `R`) + `ALL_CONS_COLUMNS` | FK edge: `constraint_name`, child `(owner, table, columns)`, parent `(owner, table, columns)` |
| `get_constraints` | `owner`, `table` | `ALL_CONSTRAINTS` (+ `ALL_CONS_COLUMNS`) | `constraint_name`, `type` (P/U/C/R), `columns`, details |

`list_schemas` deliberately uses `SELECT DISTINCT owner FROM ALL_TABLES`, **not `ALL_USERS`**: "schema" means "schema with table visibility granted to the metadata account," not "every user the account can see."

### 5.3 Safety boundary

Verbatim in the pack README + spec:

> **This is a schema-metadata tool, not a database query tool. It never executes user-supplied SQL, never queries application tables, never returns application rows, and never performs DML/DDL.**

Operator-facing notes:
- The Oracle DSN is **deployment config** (`COGNIC_ORACLE_DSN`), **not** a manifest egress entry. The connection is TCP 1521 from the pack's own deployment; `egress_allow_list` governs sandboxed-tool HTTP egress via the AgentOS proxy, and an external MCP server is not AgentOS-sandboxed.
- The tool returns **metadata only**; no row data, no arbitrary SQL, no persistence.
- If table/column **names** themselves are sensitive for a given bank, the operator scopes visibility with `COGNIC_ORACLE_ALLOWED_OWNERS` and DB grants.

Mechanism: every query is a hand-written string with bind variables; tool arguments bind as **values** (`WHERE owner = :owner AND table_name = :t`, or `LIKE :pat`), never concatenated into SQL text. No passthrough/query tool exists.

### 5.4 Connection model

- `oracledb` thin-mode async via SQLAlchemy `oracle+oracledb` (no Oracle Instant Client). Health probe `SELECT 1 FROM dual`.
- The DB account is **read-only** — granted only catalog `SELECT` (e.g. `SELECT_CATALOG_ROLE`). This is the hard backend boundary; even a hypothetical bug cannot read application rows or write.
- Env:
  - `COGNIC_ORACLE_DSN`, `COGNIC_ORACLE_USER`, `COGNIC_ORACLE_PASSWORD`
  - `COGNIC_ORACLE_ALLOWED_OWNERS` — optional operator-visible product boundary; when set, every tool additionally refuses owners not in the list. Unset = "trust the DB grant" (useful for dev/test). Layered control: DB grant = hard backend boundary; allow-list = operator-visible product boundary.
  - `COGNIC_ORACLE_MAX_ROWS` — output cap (default `200`, hard max `1000`). Applied to every tool whose output can grow; `find_columns('%')` across a bank schema must not be a foot-gun.

### 5.5 Auth — real JWT/JWKS verifier

The pack is an OAuth-PRM resource server (`auth = "oauth-prm"` in the manifest; FastMCP `AuthSettings` + a `token_verifier`). For a production-grade pack the verifier validates the bearer itself (defense-in-depth — a private ClusterIP can still be reached by other in-cluster workloads if NetworkPolicy is imperfect; the server must not rely only on "AgentOS was supposed to call me"). v1 validates:

- issuer = `COGNIC_OAUTH_ISSUER`
- JWKS signature
- expiry / not-before
- audience / resource = this server's resource URL
- required scope = `oracle_schema.read`

Env: `COGNIC_OAUTH_ISSUER`, `COGNIC_OAUTH_AUDIENCE` (or derive from the server URL / `COGNIC_MCP_SERVER_URL`), `COGNIC_REQUIRED_SCOPES=oracle_schema.read`, and the **guarded dev mode**:

- `COGNIC_AUTH_MODE=jwt` (default) — the real verifier above.
- `COGNIC_AUTH_MODE=dev_insecure` — the proof-parity accept-and-bind verifier for local tests; **permitted only when `COGNIC_ENV=dev`**, else the server **fails closed at startup**. Named `dev_insecure` (not `dev`) so it can never read like a normal deployment mode.

Runtime JWT/JWKS library (rec `joserfc`, matching the kernel's JWS choice; whether the `mcp` SDK ships a JWKS verifier vs we write a small `TokenVerifier` is confirmed at plan time, along with the exact pin).

### 5.6 Manifest

```toml
[pack]
pack_id = "cognic-tool-oracle-schema"
schema_version = 1
kind = "tool"

[identity]
agent_id = "did:web:cognic.example:tools:cognic-tool-oracle-schema"
display_name = "Cognic Oracle Schema Metadata"
provider_organization = "<AUTHOR-FILL>"
provider_url = "<AUTHOR-FILL>"

[data_governance]
data_classes = ["internal"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = []

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = ["attestations/cosign.sig", "attestations/sbom.cdx.json"]

[tool.cognic.mcp]
transport = "streamable-http"
auth = "oauth-prm"
server_url = "<override-pinned ClusterIP at deploy>"
scopes = ["oracle_schema.read"]
resources_supported = false
prompts_supported = false
sampling_supported = false
conformance_version = "1.0"
```

**Governance values are validator-clean (grounded in `cli/_governance_vocab.py`):** `read_only` is a low-authority tier, and the validators refuse `read_only` + any *restricted* class (`customer_pii` / `payment_data` / `credentials` / `regulator_communication`). Schema **structure** metadata (names/types/constraints — never rows) is correctly classed `internal`, which is non-restricted and carries no minimum-tier requirement, so `read_only` + `internal` is consistent. `purpose = "operational_telemetry"` is the honest classification (internal operational metadata tooling; the tool handles no customer data). `retention_policy = "none"` — the tool persists nothing.

### 5.7 CI / sign / verify / release

`sign-and-publish.yml` (from the realigned scaffold): checkout → setup-python 3.12 → `pip install "cognic-agentos @ git+...@v0.0.2"` → `agentos validate .` → `agentos sign --bundle .` → `agentos verify .` → publish. A tag cuts the signed release; the resolved kernel SHA is recorded in the proof evidence.

### 5.8 Local tests

- **Unit** (always run, no DB): assert each tool's SQL/bind shape against a fake cursor — the query text uses the expected data-dictionary view, arguments bind as values (no concatenation), the allow-list filter is applied, and output respects `COGNIC_ORACLE_MAX_ROWS` (`truncated` set correctly at the boundary).
- **Integration** (env-gated `COGNIC_RUN_ORACLE_INTEGRATION=1`, `pytest -m oracle`): against `gvenzl/oracle-xe:21-slim` (`XEPDB1`), copying the kernel's `infra/dev/docker-compose.oracle.yml` pattern, seeded with a tiny schema — ≥2 tables, a foreign key, a PK + a unique + a check constraint, and varied column types — so all six tools return real metadata. Fails loud (not skip) when opted in but the DB is unreachable.

---

## 6. Phase M3-E2c — deployed Proof-2 acceptance bar

This spec defines the acceptance criteria and topology reference; the **detailed kind deploy-plan is a separate follow-on** (as Proof 1b-2 had its own deploy design + plan).

Reuse/extend the proven Proof 1b-2 kind topology (`infra/proof-1b/`):
- swap the example MCP server for the `cognic-tool-oracle-schema` server;
- add an in-cluster `gvenzl/oracle-xe:21-slim` (`XEPDB1`) seeded with the §5.8 test schema;
- keep the operator `server_url` override + the per-(tenant, IP) internal-host allow-list pointing the (tenant, pack) at the private ClusterIP.

**Acceptance (all must hold against the released, signed artifact — not a local editable):**
1. The released, signed pack is operator-installed.
2. Boot-time trust registration succeeds.
3. Discovery reaches `discovery_status = auth_ready`.
4. A real `call_tool(describe_table, ...)` returns the seeded table's metadata over the override-pinned ClusterIP.

**The M3 checkbox in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` flips only when this runs green.**

---

## 7. Cross-cutting

- **Production-grade rule:** real `oracledb` integration in the runtime path; real JWT/JWKS verification (no "trust the caller"); mocks/fixtures only under test paths. No mock/synthetic behaviour in the main runtime path.
- **Doctrine / process:** `sdk/testing.py` change halts before commit (Doctrine-E semver surface). Scaffold templates are data, not CC code. M3-E2b is a separate repo (the OS/pack boundary). Per-action authorization applies to every remote-affecting step (merge / tag / push / release).
- **Honest posture:** `auth_ready` means PRM-discovery + token-acquire succeeded — not "healthy." The deployed proof (M3-E2c) is the live operational bar; local verification is not live operational proof.

## 8. Out of scope / deferred (decided)

- `skill` / `agent` / `hook` scaffold **shape** realignment — M3-E2a changes the `tool` shape only; the other three keep their shape (they import the SDK at runtime) and receive only the `@v0.0.2` pin bump.
- Cursor-based pagination of tool results (v1 uses `limit` + `truncated`; cursor is a v1.1 convention if needed — the MCP host imposes cursor semantics only on the `tools/list` catalogue, not on `tools/call` results: `protocol/mcp_host.py:873-1079`).
- Exact JWT/JWKS library pin + whether the `mcp` SDK ships a JWKS verifier (plan-time).
- Exact `_load_entry_point_tools` descriptor-recognition predicate, constrained by "must not re-sign the `cognic-tool-search` example" (plan-time).
- The detailed M3-E2c kind deploy-plan (separate follow-on).

## 9. Acceptance criteria (this spec)

- **M3-E2a:** realigned `tool` scaffold emits the FastMCP shape (no kernel runtime dep; `@v0.0.2` pin in `dev` extras + CI); all four scaffolds' kernel pins bumped to `@v0.0.2`; `_load_entry_point_tools` three-way classification with a testable skip trace and a fail-loud unknown arm; scaffold tests prove structural shape + placeholder hygiene (fresh scaffold surfaces AUTHOR-FILL remediation) + a filled fixture validates clean; `sdk/testing.py` regression green; full local gate; halt-before-commit. Tag `v0.0.2` cut after merge.
- **M3-E2b:** `cognic-tool-oracle-schema` generated from `v0.0.2`, six tools over data-dictionary views with the §5.3 boundary, the §5.4 connection model, the §5.5 real JWT/JWKS verifier + guarded `dev_insecure`, the §5.6 manifest; `agentos validate/sign/verify` green; unit + env-gated integration tests green; signed release tagged with the kernel SHA recorded.
- **M3-E2c:** the §6 acceptance run green against the released artifact (deploy-plan follow-on); M3 checkbox flips.
