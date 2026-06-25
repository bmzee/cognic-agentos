# PR-2b-1 — operator `server_url` override + per-tenant exact-IP internal-host allow-list — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Let an operator point a `(tenant, pack)` at a real in-cluster MCP Service — a private host the strict-profile SSRF guard refuses today — via an audited per-`(tenant,pack)` `http://`-IP-literal `server_url` override + a per-tenant default-deny **exact-IP (ClusterIP) allow-list**, without weakening the guard. Code/security-control PR only; the **deployed Proof 1b-2 is PR-2b-2** (separate).

**Architecture:** Two new decision-history-audited Postgres/Oracle stores (mirroring `config_overlay`), a guard carve-out on the three MCP-resource legs (HTTP-only, exact-IP, full-resolved-set) that returns the pinned IP, a kernel-owned resolve-and-pin for the `prm_metadata` hostname fetch, resolve-per-use override observation on `MCPHost`, a new RBAC family, and operator write/read endpoints behind the HumanActor boundary.

**Tech Stack:** Python, SQLAlchemy + Alembic, FastAPI, pytest. Threat-model source of truth: the merged spec `docs/superpowers/specs/2026-06-25-pr2b-mcp-internal-host-override-allowlist-design.md` (§6, §7, §7a, §8, §9, §10).

## Global Constraints

- **CC modules** (durable 95% line / 90% branch gate, negative-path tests mandatory, **halt-before-commit on every commit**, `core-controls-engineer` discipline): NEW `core/mcp_config/storage.py` (promote at closeout), `protocol/mcp_authz.py`, `protocol/mcp_host.py`, `portal/rbac/scopes.py` (+ `portal/rbac/actor.py` + `portal/rbac/enforcement.py`), NEW `portal/api/mcp_config/routes.py` (promoted at Task 6 per the user's on-gate-by-default guardrail — it OWNS the `RequireHumanActor` write boundary + the closed-enum `MCPConfigRejected`→422 mapping, the `packs/operator_routes.py` precedent; 100/100 at promotion). Off-gate: `core/mcp_config/__init__.py`, the migration, `harness/runtime.py`, `harness/mcp_host.py`, `portal/api/app.py`.
- **`core/` stop-rule:** the new `core/mcp_config/*` + the migration are `core/`-class changes (governance/persistence).
- **Ratified design decisions (do not re-litigate):**
  - **DD-1** — the guard loads the per-tenant allow-list from the **new DB store** (NOT Vault); inject the store into `MCPAuthzClient`.
  - **DD-2** — the **`audit.mcp_allowlist_permitted`** evidence event (one spelling everywhere — the `AuditEvent.event_type`, matching the existing `audit.*` convention) carries `tenant_id`, `leg`, resolved/pinned IP, `request_id`, and the host — **NO `pack_id` thread** through the authz stack (pack is correlated via the MCPHost call path + request evidence). The merged spec §9 is patched to match (drops `pack`).
  - **DD-3** — a **new RBAC family** `mcp.override.{read,write}` + `mcp.allowlist.{read,write}`, kept disjoint from `mcp.tool.*`, with explicit value-disjointness + `mcp.`-prefix pins.
  - **DD-4** — both stores live in a new **CC** `core/mcp_config/storage.py`.
  - **DD-5** — **one** migration `0012` creates both tables (chains off the current head `0011`).
- **Security invariants:**
  - The carve-out applies to the **three resource legs only** (`server_url`, `prm_metadata`, `well_known_prm`) — never `as_metadata`/`token_endpoint`.
  - Internal legs are **HTTP-only** (an internal `https://` is refused at the guard AND at override set-time).
  - The match is on **every resolved IP** ∈ the exact-IP allow-list (a host resolving to any non-allow-listed IP — including a mix of public + private — is refused; AS-9 operator-mis-list is an audited residual, not prevented).
  - **No DNS-reintroduction (spec §8):** the override is an **`http://`-IP-literal** (the MCP-SDK `server_url`/`well_known_prm` legs connect to the literal IP — no DNS, no rebinding); the kernel-owned `prm_metadata` hostname fetch uses **resolve-and-pin** (connect to the guard-validated IP, Host preserved).
  - **Fail-closed:** allow-list store unreachable → empty allow-list → default-deny; override store unreachable → manifest `server_url` (signed).
- **Both writes are Human-only** (`RequireHumanActor`, threading `actor_type=human` onto the chain row); reads are service-permitted.
- **Storage tests run against the Alembic-MIGRATED DB**, not `create_all` (per the migration-only-constraint discipline), and drive **cross-tenant negatives**.
- TDD throughout; commit trailer required; the deployed Proof 1b-2 is explicitly out of scope.

## File Structure

- **Create** `src/cognic_agentos/core/mcp_config/__init__.py` (re-exports) + `src/cognic_agentos/core/mcp_config/storage.py` (**CC**) — `MCPServerUrlOverrideStore` + `MCPInternalHostAllowlistStore` + row DTOs + closed-enum refusals + the `http://`-IP-literal override validator + the exact-IP allow-list validator.
- **Create** `src/cognic_agentos/db/migrations/versions/20260625_0012_mcp_override_and_allowlist.py` — both tables (revision `"0012"`, down_revision `"0011"`).
- **Modify** `src/cognic_agentos/protocol/mcp_authz.py` (**CC**) — thread `tenant_id`/`request_id` into `_refuse_non_public_discovery_url` (now `-> str | None`, returning the pinned IP) + `_fetch_prm`; inject `internal_host_allowlist_store`; the carve-out + the `audit.mcp_allowlist_permitted` event + the `prm_metadata` resolve-and-pin.
- **Modify** `src/cognic_agentos/protocol/mcp_host.py` (**CC**) — `override_store` seam + resolve-per-use at the `server_url` read sites, incl. the **`list_tools` cache key**.
- **Modify** `src/cognic_agentos/portal/rbac/scopes.py` + `actor.py` + `enforcement.py` (**CC**) — the new family + union widenings.
- **Create** `src/cognic_agentos/portal/api/mcp_config/__init__.py` + `routes.py` — operator override + allow-list write/read endpoints.
- **Modify** `src/cognic_agentos/harness/runtime.py` + `src/cognic_agentos/harness/mcp_host.py` + `src/cognic_agentos/portal/api/app.py` — construct + thread the stores; mount the routers.
- **Modify** `docs/adrs/ADR-002-mcp-plugin-protocol.md` — the PR-2b-1 amendment; **and the spec §9** (`audit.mcp_allowlist_permitted`, drop `pack`).
- **Tests** under `tests/unit/core/mcp_config/`, `tests/unit/protocol/`, `tests/unit/portal/rbac/`, `tests/unit/portal/api/mcp_config/`, `tests/unit/db/`.

Patterns to mirror (exact, from grounding): store + `append_with_precondition` → `core/config_overlay/storage.py:40-233` (incl. `actor_type` threading); migration → `db/migrations/versions/20260606_0007_tenant_config_overlay.py` (head `0011` at `20260615_0011_runs.py:20-21`); guard → `protocol/mcp_authz.py:1043-1106` (legs `:200-214`, the `_PRM_DISCOVERY_PATH_TO_LEG` map `:210-214`, call sites `:505`/`:1147`, `_fetch_prm` `:1133` called from `discover_resource_metadata` `:543,:549,:555`, loader shape `:1216-1294`, audit sinks `self._audit`/`self._dh` from `__init__:449-465`); resolve-per-use → `protocol/mcp_host.py:760` + the `server_url` reads `:874,:889,:1684,:1721,:1762,:1769,:1795,:1812` + the `list_tools` cache `:850-865`, seam mirrors `discovery_status_recorder` `:673`; routes → `portal/api/config_overlay/routes.py` (whole module); RBAC → `portal/rbac/scopes.py:344-414` + the pin `tests/unit/portal/rbac/test_mcp_scopes.py:36-54`; mount → `portal/api/app.py:1271-1310`.

---

### Task 1 — the two stores + the migration

**Files:** Create `core/mcp_config/__init__.py`, `core/mcp_config/storage.py`; create `db/migrations/versions/20260625_0012_mcp_override_and_allowlist.py`. Test: `tests/unit/core/mcp_config/test_storage.py`, `tests/unit/db/test_migration_20260625_0012.py`.

**Interfaces (Produces):**
- `MCPServerUrlOverrideStore(engine)`: `async set_override(*, tenant_id, pack_id, server_url, actor_subject, actor_type, request_id)`, `async clear_override(*, tenant_id, pack_id, actor_subject, actor_type, request_id)`, `async get(*, tenant_id, pack_id) -> str | None`.
- `MCPInternalHostAllowlistStore(engine)`: `async add_ip(*, tenant_id, ip, actor_subject, actor_type, request_id)`, `async remove_ip(*, tenant_id, ip, actor_subject, actor_type, request_id)`, `async get_allowlist(*, tenant_id) -> frozenset[str]`, `async list_for_tenant(tenant_id) -> list[AllowlistEntryRow]`.
- Closed-enum `MCPConfigRefusalReason` Literal — **override** (`http://`-IP-literal grammar, spec §8): `override_url_not_string`, `override_url_malformed`, `override_url_not_http` (scheme must be `http` — internal HTTPS rejected), `override_url_host_not_ip_literal` (host must be an IP literal — hostnames rejected so no DNS is reintroduced on the SDK leg), `override_url_host_not_internal` (a public/non-private host IP — PR-2b-1 is internal-only, public-server repointing deferred); **allow-list** (exact-IP, spec §7/AS-4): `allowlist_ip_not_string`, `allowlist_ip_malformed` (FQDN, `*.svc.cluster.local`, garbage), `allowlist_ip_not_exact` (CIDR/range/prefix), `allowlist_ip_hard_blocked` (metadata/loopback/link-local/multicast/unspecified — never listable). Carried by `MCPConfigRejected(reason)`.
- Pure validators `validate_override_url(s)` + `validate_allowlist_ip(s)` (both `-> None`, raise `MCPConfigRejected`), plus the **shared floor predicate** `ip_passes_internal_floor(ip) -> bool` (True ONLY for a private internal IP — **requires `ip.is_private`** so a public IP like `8.8.8.8` is rejected, PR-2b-1 is internal-only; False for any non-private IP AND for loopback / link-local / multicast / unspecified / reserved + the canonical IMDS IPv6 ULA `fd00:ec2::254` via a module-level `_METADATA_IPS` set) — consumed by `validate_allowlist_ip` (set-time) **and** the Task 2 guard (read-time, defense-in-depth against a corrupted allow-list). **Note (impl deviation, T1):** the IMDS IPv4 `169.254.169.254` is deliberately NOT a `_METADATA_IPS` literal — it is already caught by the `is_link_local` clause (169.254.0.0/16), and the `test_no_env_specific_values_in_source` architecture guard forbids bare-IPv4 literals outside `core/config.py`; the tests assert both IMDS IPs are blocked.

- [ ] **Step 1: failing migration shape test** — `tests/unit/db/test_migration_20260625_0012.py`: assert the migration module has `revision == "0012"`, `down_revision == "0011"`, and that against a freshly Alembic-migrated SQLite/Postgres test DB the tables `mcp_server_url_override` + `mcp_internal_host_allowlist` exist with the unique constraints `uq_mcp_server_url_override_tenant_pack` and `uq_mcp_internal_host_allowlist_tenant_ip`. (Use the existing migrated-DB fixture pattern from `tests/unit/db/test_migration_20260615_0011.py`.)

- [ ] **Step 2: run → FAIL** (`uv run pytest tests/unit/db/test_migration_20260625_0012.py -v`) — module not found.

- [ ] **Step 3: write the migration** (mirror `20260606_0007`, two tables; `_TS = sa.TIMESTAMP(timezone=True)`):
```python
"""mcp server_url override + internal-host allow-list (PR-2b-1)."""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

_TS = sa.TIMESTAMP(timezone=True)

def upgrade() -> None:
    op.create_table(
        "mcp_server_url_override",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("server_url_override", sa.String(length=2048), nullable=False),
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", _TS, nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "pack_id", name="uq_mcp_server_url_override_tenant_pack"),
    )
    op.create_index("ix_mcp_server_url_override_tenant_id", "mcp_server_url_override", ["tenant_id"])
    op.create_table(
        "mcp_internal_host_allowlist",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),  # v4/v6 literal
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", _TS, nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "ip", name="uq_mcp_internal_host_allowlist_tenant_ip"),
    )
    op.create_index("ix_mcp_internal_host_allowlist_tenant_id", "mcp_internal_host_allowlist", ["tenant_id"])

def downgrade() -> None:
    op.drop_index("ix_mcp_internal_host_allowlist_tenant_id", table_name="mcp_internal_host_allowlist")
    op.drop_table("mcp_internal_host_allowlist")
    op.drop_index("ix_mcp_server_url_override_tenant_id", table_name="mcp_server_url_override")
    op.drop_table("mcp_server_url_override")
```
Run → PASS.

- [ ] **Step 4: failing store tests** — `tests/unit/core/mcp_config/test_storage.py` (against the migrated DB; mirror `tests/unit/core/config_overlay/` if present, else the migrated-DB fixture):
  - (a) `set_override` then `get` returns the URL; `clear_override` then `get` returns `None`; a second `(tenant,pack)` is isolated; a **different tenant** reading the same pack gets `None`.
  - (b) `add_ip` then `get_allowlist` contains the IP; `remove_ip` drops it; cross-tenant isolation.
  - (c) **override grammar:** `validate_override_url("http://10.42.0.7:8080/mcp")` accepted; `validate_override_url("https://10.42.0.7")` raises `override_url_not_http`; `validate_override_url("http://svc.ns.svc.cluster.local")` raises `override_url_host_not_ip_literal`; `validate_override_url("http://8.8.8.8")` raises `override_url_host_not_internal`; `validate_override_url("ftp://x")` raises `override_url_not_http`; `validate_override_url("not a url")` raises `override_url_malformed`; `validate_override_url(123)` raises `override_url_not_string`.
  - (d) **allow-list grammar:** `validate_allowlist_ip("10.42.0.7")` accepted; `"10.0.0.0/8"` → `allowlist_ip_not_exact`; `"169.254.169.254"`/`"127.0.0.1"`/`"::1"`/`"224.0.0.1"`/`"0.0.0.0"` → `allowlist_ip_hard_blocked`; `"*.svc.cluster.local"`/`"my-host"` → `allowlist_ip_malformed`.
  - (e) **chain-row evidence (exact key set):** `set_override` emits a `mcp.override.set` decision-history row carrying `tenant_id`/`pack_id`/`actor_id`/**`actor_type`** (= `"human"` in the test)/new + previous value; `add_ip` emits `mcp.allowlist.add` carrying `tenant_id`/`ip`/`actor_id`/**`actor_type`** (chain-payload-is-evidence-snapshot — assert the exact payload key set incl. `actor_type`).

- [ ] **Step 5: implement `core/mcp_config/storage.py`** — mirror `config_overlay/storage.py:40-233` exactly: two `sa.Table`s on `core.audit._metadata`, frozen row DTOs, `self._dh = DecisionHistoryStore(engine)`, and `set_*`/`clear_*`/`add_*`/`remove_*` each running a `_precondition` that `SELECT ... .with_for_update()` the current state row, captures `previous`, validates (`validate_override_url`/`validate_allowlist_ip` — grammar enforced **before** storage), upserts/deletes the non-chain row in-closure, and a `_build` returning `DecisionRecord(decision_type="mcp.override.set"|"mcp.override.cleared"|"mcp.allowlist.add"|"mcp.allowlist.remove", request_id=…, tenant_id=…, actor_id=actor_subject, iso_controls=("ISO42001.A.5.31","ISO42001.A.6.2.4"), payload={…, "actor_type": actor_type})`, then `await self._dh.append_with_precondition(...)`. `validate_override_url`: `urlparse`, reject non-str, reject `scheme != "http"` (`override_url_not_http`), reject host that isn't `ipaddress.ip_address`-parseable (`override_url_host_not_ip_literal`), reject `not ip_passes_internal_floor(host_ip)` (`override_url_host_not_internal` — a public/non-internal host IP), reject malformed. `validate_allowlist_ip`: reject non-str, reject prefix forms (`/` present → not-exact), `ipaddress.ip_address` parse (else malformed), then `if not ip_passes_internal_floor(ip): raise … allowlist_ip_hard_blocked`. `ip_passes_internal_floor(ip)` returns `ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved) and str(ip) not in _METADATA_IPS` (the leading **`ip.is_private` is load-bearing** — PR-2b-1 is internal-only, so a public IP is rejected at set-time AND at the Task-2 guard) — **module-level, exported** so `mcp_authz` can import it (the `core/mcp_config → mcp_authz` arrow already exists via the store injection). `get`/`get_allowlist` are plain tenant-scoped SELECTs. Run → PASS.

- [ ] **Step 6: promote `core/mcp_config/storage.py` to the durable CC gate** — add it to `tools/check_critical_coverage.py` `_CRITICAL_FILES` + bump the count-guard. Run the full-suite gate on fresh data (`uv run pytest --cov --cov-report=json -q` then `uv run python tools/check_critical_coverage.py`) and confirm the new module is ≥ 95% line / 90% branch (the verify-promotion-at-promotion-time rule — the module is CC from this task and must not sit ungated across intermediate commits). The Step-4 negative-path tests carry the branch coverage.

- [ ] **Step 7: commit** (exact-path stage the 3 new files + the 2 test files + the gate manifest).

---

### Task 2 — the guard carve-out + the `audit.mcp_allowlist_permitted` event (CC)

**Files:** Modify `protocol/mcp_authz.py`. Test: `tests/unit/protocol/test_mcp_authz.py` (or a focused `test_mcp_authz_allowlist.py`).

**Interfaces:** Consumes `MCPInternalHostAllowlistStore.get_allowlist` + `ip_passes_internal_floor` (Task 1). Produces: `_refuse_non_public_discovery_url(self, url, *, leg, tenant_id, request_id) -> str | None` (signature widened; **returns the pinned validated IP** for an allow-listed internal carve-out, `None` for a public host, raises for a refusal) + a private `_RESOURCE_LEGS = frozenset({"server_url","prm_metadata","well_known_prm"})`; `MCPAuthzClient.__init__` gains `internal_host_allowlist_store` (optional). Task 3 consumes the returned pinned IP.

- [ ] **Step 1: failing tests** (`authz_strict` + `respx` shape from PR-2a/2b-0; `monkeypatch` `_resolve_host_addresses` so an internal host resolves to a private IP):
  - **carve-out hit:** strict profile, `server_url` resolves to `10.42.0.7`, the tenant's allow-list (a stub store) contains `10.42.0.7`, scheme `http` → the guard returns `"10.42.0.7"` (no raise); a stub `audit_store` records exactly one `audit.mcp_allowlist_permitted` event carrying `tenant_id`/`request_id` as top-level `AuditEvent` fields + payload `{leg:"server_url", host, resolved_ips:["10.42.0.7"]}` (no `pack_id`) — per the Step-3 `_emit_allowlist_permitted` pseudocode + the `audit.*` convention.
  - **carve-out miss (not listed):** allow-list empty / different IP → raises `mcp_discovery_url_refused` (`refused_component="host_address"`), **no** permit event.
  - **internal HTTPS refused:** `https://10.42.0.7/` with `10.42.0.7` allow-listed → still raises (HTTP-only).
  - **OAuth leg never carved out:** `as_metadata`/`token_endpoint` resolving to an allow-listed internal IP → still raises (leg ∉ `_RESOURCE_LEGS`), no permit event.
  - **multi-IP all-or-nothing:** host resolves to `[10.42.0.7, 10.42.0.9]`, only `…7` listed → refused. Mixed public+private (`[10.42.0.7, 8.8.8.8]`, only `…7` listed) → refused.
  - **fail-closed:** allow-list store raises / returns empty → default-deny (refuse), no permit event.
  - **guard-time floor (defense-in-depth, spec §7 line 114):** the stub store returns an allow-list *containing* a metadata/loopback IP (`169.254.169.254` / `127.0.0.1`) and `_resolve_host_addresses` resolves to it → the guard **still refuses** (the floor catches a corrupted/buggy allow-list entry that bypassed set-time validation), no permit event.
  - **public host unaffected:** a public IP returns `None` (no allow-list consult, no permit event) and proceeds.

- [ ] **Step 2: run → FAIL.**

- [ ] **Step 3: implement.** (a) Widen `__init__` with `internal_host_allowlist_store: MCPInternalHostAllowlistStore | None = None` → `self._internal_host_allowlist_store`. (b) Add `_RESOURCE_LEGS`. (c) Widen the signature to `... -> str | None`. (d) Replace the per-iteration raise loop with a resolve-once-then-decide body:
```python
        resolved = [ip for a in addresses if (ip := _maybe_ip(a)) is not None]
        non_public = [ip for ip in resolved if (ip.is_private or ip.is_loopback or ip.is_link_local
                                                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)]
        if not non_public:
            return None  # all-public host: no carve-out, no pin
        if leg in _RESOURCE_LEGS and parsed.scheme == "http" and self._internal_host_allowlist_store is not None:
            allowlist = await self._load_internal_host_allowlist(tenant_id)  # fail-closed -> frozenset()
            if allowlist and all(str(ip) in allowlist and ip_passes_internal_floor(ip) for ip in resolved):
                await self._emit_allowlist_permitted(
                    tenant_id=tenant_id, leg=leg, request_id=request_id,
                    host=host, resolved_ips=[str(ip) for ip in resolved],
                )
                return str(resolved[0])  # pinned validated IP — Task 3's _fetch_prm connects here
        raise MCPAuthzError("mcp_discovery_url_refused", "discovery URL host resolves to a non-public address",
                            refused_component="host_address", leg=leg)
```
(e) `_load_internal_host_allowlist(tenant_id)` — wraps `self._internal_host_allowlist_store.get_allowlist(tenant_id=tenant_id)` in a fail-closed `try/except (asyncio.CancelledError raise; Exception -> return frozenset())`. (f) `_emit_allowlist_permitted(...)` → `await self._audit.append(AuditEvent(event_type="audit.mcp_allowlist_permitted", request_id=request_id, tenant_id=tenant_id, payload={"leg":leg,"host":host,"resolved_ips":resolved_ips}))` (no `pack_id` — DD-2). (g) Thread `tenant_id`/`request_id` into the **3 resource-leg call sites**: `server_url` at `:505` (already has both via `discover_resource_metadata`); `_fetch_prm` — add `tenant_id`/`request_id` params and pass at its 3 callers (`:543,:549,:555`). The 2 OAuth call sites (`:1423,:1465`) pass their `tenant_id`/`request_id` but are excluded by `leg ∉ _RESOURCE_LEGS`. All existing guard callers ignore the new return value (back-compatible). Run → PASS + full `test_mcp_authz.py` (update existing guard-test call sites for the widened signature).

- [ ] **Step 4: drift-pin** — an AST/structural test that the carve-out branch is gated on `leg in _RESOURCE_LEGS` AND `parsed.scheme == "http"` (so a refactor can't drop the leg/scheme gate). Run → PASS.

- [ ] **Step 5: commit.**

---

### Task 3 — `prm_metadata` resolve-and-pin (CC)

**Files:** Modify `protocol/mcp_authz.py` (`_fetch_prm`). Test: `tests/unit/protocol/test_mcp_authz.py`.

**Interfaces:** Consumes the pinned IP that `_refuse_non_public_discovery_url` returns (Task 2: `-> str | None`). Produces: `_fetch_prm` connects to the pinned IP (HTTP-only, original `Host` preserved) when the guard returns one — closing the TOCTOU rebinding window (spec §8 line 136, test §11 line 174). `server_url`/`well_known_prm` are IP-literal (override grammar / IP-derived) so their resolve-to-self pin is trivial; `prm_metadata` (from `WWW-Authenticate`, may be a hostname) is the one leg that needs the kernel pin.

- [ ] **Step 1: failing tests** (rebinding, spec line 174): monkeypatch `_resolve_host_addresses` for the PRM host to return the allow-listed `10.42.0.7` on the guard's resolution, then a DIFFERENT non-allow-listed `10.42.0.99` on any later call; allow-list stub contains `10.42.0.7`; `respx` routes `http://10.42.0.7/...`.
  - (a) the PRM fetch connects to `http://10.42.0.7/...` (the pinned IP) with header `Host: <original-host>` — proving the pin (respx asserts the request URL host is `10.42.0.7`).
  - (b) `_resolve_host_addresses` for that host is called **exactly once** (resolve-once).
  - (c) a PRM host resolving only to a non-allow-listed IP → refused at the guard, **no fetch**.
  - (d) a **public** PRM host (guard returns `None`) → fetched at the original URL, no rewrite.
  - (e) a pinned host with a **non-default port** (`http://svc:8443/...` → `10.42.0.7`) → the GET targets `http://10.42.0.7:8443/...` with `Host: svc:8443`, and the original `timeout` is passed through.
  - (f) an **IPv6** pinned IP (private `fd00::7`) → the GET netloc is bracketed (`http://[fd00::7]:80/...`).

- [ ] **Step 2: run → FAIL.**

- [ ] **Step 3: implement.** `_fetch_prm` already calls the guard before its GET (Task 2 threaded `tenant_id`/`request_id`). Capture the return and pin:
```python
        pinned_ip = await self._refuse_non_public_discovery_url(
            url, leg=leg, tenant_id=tenant_id, request_id=request_id,
        )
        if pinned_ip is not None:
            parsed = urlparse(url)
            port = parsed.port or 80
            netloc_ip = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip  # bracket IPv6
            # Rebind `url` (NOT a separate `pinned_url`) so the GET's first positional
            # arg stays `url` — the security AST detector
            # test_real_mcp_authz_has_no_unguarded_fetches requires the fetch's first
            # arg to be ast.dump-identical to the `url` guard's. (Option A — detector untouched.)
            url = urlunparse(parsed._replace(netloc=f"{netloc_ip}:{port}"))
            host_header = parsed.hostname or ""           # original authority, userinfo stripped
            if parsed.port is not None:
                host_header = f"{host_header}:{parsed.port}"
            resp = await self._http.get(url, headers={"Host": host_header}, timeout=timeout)
        else:
            resp = await self._http.get(url, timeout=timeout)
```
Keeps `timeout=timeout` (fail-closed/latency semantics unchanged), brackets IPv6 pinned literals in the netloc, and carries the original authority (incl. a non-default port) as `Host`; HTTP-only so no SNI/cert concern (spec §8). Run → PASS + full `test_mcp_authz.py`.

- [ ] **Step 4: drift-pin** — a structural test that `_fetch_prm` issues its GET against the guard-returned pinned IP (not a re-resolved address) whenever the guard returns a non-`None` IP. Run → PASS.

- [ ] **Step 5: commit.**

---

### Task 4 — resolve-per-use override on `MCPHost` (CC)

**Files:** Modify `protocol/mcp_host.py`. Test: `tests/unit/protocol/test_mcp_host.py`.

**Interfaces:** Consumes `MCPServerUrlOverrideStore.get` (Task 1). Produces: `MCPHost.__init__` gains `override_store: MCPServerUrlOverrideStore | None = None`; an async `_effective_server_url(*, tenant_id, server_id, manifest_url) -> str`; the `list_tools` cache key includes the effective URL.

- [ ] **Step 1: failing tests** — (a) with an override-store stub returning an override URL for `(tenant, server_id)`, `list_tools`/`call_tool` open the session + acquire the token against the **override** URL, not the manifest URL; (b) stub returns `None` → manifest `entry.server_url`; (c) a **post-construction** override change is observed on the next call (resolve-per-use); (d) store unreachable (stub raises) → fall back to the manifest URL (fail-safe to the signed value); **(e) stale-cache negative** — prime `list_tools` cache against override-A, change the stub to override-B, assert `list_tools` re-fetches against B (the cache does NOT return the A-computed list).

- [ ] **Step 2: run → FAIL.**

- [ ] **Step 3: implement.** Add `override_store` to `__init__` (mirror the optional `discovery_status_recorder` seam `:673`/`:772`) → `self._override_store`. Add:
```python
    async def _effective_server_url(self, *, tenant_id: str, server_id: str, manifest_url: str) -> str:
        if self._override_store is None:
            return manifest_url
        try:
            override = await self._override_store.get(tenant_id=tenant_id, pack_id=server_id)
        except Exception:
            return manifest_url  # fail-safe to the signed manifest value
        return override or manifest_url
```
In `list_tools`: compute `effective_url = await self._effective_server_url(...)` **before** the cache lookup (`:850-865`) and **include `effective_url` in the cache key** (`(tenant_id, server_id, manifest_scopes, effective_url)`) so a changed override is a cache miss → re-fetch (this is the P1 stale-cache fix — the prior "cache key unaffected" assumption was wrong). In `_call_tool_inner`: compute `effective_url` once at the top and use it at every read site (`:1684,:1721,:1762,:1769,:1795,:1812`). Replace the raw `entry.server_url` reads at `:874,:889` (list_tools) accordingly. Run → PASS + full `test_mcp_host.py`.

- [ ] **Step 4: commit.**

---

### Task 5 — the RBAC family (CC)

**Files:** Modify `portal/rbac/scopes.py`, `actor.py`, `enforcement.py`. Test: `tests/unit/portal/rbac/test_mcp_internal_access_scopes.py`.

- [ ] **Step 1: failing tests** — a new `test_mcp_internal_access_scopes.py`: (a) `set(get_args(MCPInternalAccessRBACScope)) == {"mcp.override.read","mcp.override.write","mcp.allowlist.read","mcp.allowlist.write"}`; (b) **all four start with `mcp.`**; (c) **value-disjoint from every other family** incl. `MCPRBACScope` (`mcp.tool.*`) — iterate all families' `get_args`; (d) the new family is in `Actor.scopes`' union and `RequireScope`'s union (a constructed `Actor(scopes=frozenset({"mcp.allowlist.write"}))` validates; `RequireScope("mcp.allowlist.write")` constructs). Also extend `tests/unit/portal/rbac/test_mcp_scopes.py`'s `others` loop to include the new family (so the `mcp.tool.*` disjointness stays covered against it).

- [ ] **Step 2: run → FAIL.**

- [ ] **Step 3: implement.** In `scopes.py` (mirror `ConfigOverlayRBACScope:401-414`):
```python
MCPInternalAccessRBACScope = Literal[
    "mcp.override.read", "mcp.override.write",
    "mcp.allowlist.read", "mcp.allowlist.write",
]
MCP_INTERNAL_ACCESS_SCOPES: frozenset[MCPInternalAccessRBACScope] = frozenset({
    "mcp.override.read", "mcp.override.write", "mcp.allowlist.read", "mcp.allowlist.write",
})
```
Add to `actor.py` import (`:37-52`) + the `Actor.scopes` union (`:142-156`), and `enforcement.py` import (`:40-54`) + the `RequireScope` union (`:250-263`). Run → PASS.

- [ ] **Step 4: commit.**

---

### Task 6 — operator write/read endpoints

**Files:** Create `portal/api/mcp_config/__init__.py` + `routes.py`. Test: `tests/unit/portal/api/mcp_config/test_routes.py`.

**Interfaces:** `build_mcp_override_routes(*, store: MCPServerUrlOverrideStore) -> APIRouter` + `build_mcp_allowlist_routes(*, store: MCPInternalHostAllowlistStore) -> APIRouter`. Endpoints under `/api/v1`: PUT/DELETE/GET `/tenants/{tenant_id}/mcp-overrides/{pack_id}` (write Human-only); PUT(add)/DELETE(remove)/GET `/tenants/{tenant_id}/mcp-allowlist[/{ip}]` (write Human-only).

- [ ] **Step 1: failing tests** (mirror `config_overlay` route tests): (a) override PUT by a human actor with `mcp.override.write` → 200 + `store.set_override` called with `actor_type="human"`; (b) override PUT by a **service** actor → 403, exactly one `portal.rbac.human_actor_required` log + ZERO `portal.mcp_config.*` logs (the mutually-exclusive contract); (c) override GET with `mcp.override.read` by a service actor → 200; (d) allow-list add with a malformed/broad/metadata IP → 422 carrying the closed-enum `MCPConfigRefusalReason`; (e) override PUT with `https://`-or-hostname body → 422 (`override_url_not_http`/`override_url_host_not_ip_literal`); (f) allow-list add Human-only enforced; (g) the **future-import-omitted** invariant test (`assert "from __future__ import annotations" not in source`).

- [ ] **Step 2: run → FAIL.**

- [ ] **Step 3: implement** — mirror `config_overlay/routes.py` exactly (module **omits** `from __future__ import annotations`; closure-local `_write = RequireScope("mcp.override.write")`, `_read = RequireScope("mcp.override.read")`, `_human = RequireHumanActor()` for the override factory; the parallel `mcp.allowlist.*` set for the allow-list factory). Handlers thread `actor_subject=actor.subject`, `actor_type=actor.actor_type`, `request_id=_mint(prefix)` into the store; catch `MCPConfigRejected` → `HTTPException(422, {"reason": exc.reason})` + a `portal.mcp_config.<verb>_refused` warning log; request-id prefixes with the `assert len(prefix)+32<=64` module-foot guard. Run → PASS.

- [ ] **Step 4: commit.**

---

### Task 7 — wiring + ADR-002 + spec §9 sync + closeout

**Files:** Modify `harness/runtime.py`, `harness/mcp_host.py`, `portal/api/app.py`, `docs/adrs/ADR-002-mcp-plugin-protocol.md`, the spec. Test: a wiring/integration test + the closeout gate.

- [ ] **Step 1: wiring (with a failing wiring test first).** `harness/runtime.py`: construct `mcp_override_store = MCPServerUrlOverrideStore(engine)` + `mcp_internal_host_allowlist_store = MCPInternalHostAllowlistStore(engine)` next to `overlay_store` (`:109`); hold both on `Runtime` (`:56-59`, `:385`). `harness/mcp_host.py::build_mcp_host` — thread `runtime.mcp_override_store` into `MCPHost(override_store=…)` and `runtime.mcp_internal_host_allowlist_store` into the `MCPAuthzClient(internal_host_allowlist_store=…)` it assembles. `portal/api/app.py` — add `mcp_override_store`/`mcp_internal_host_allowlist_store` `create_app` kwargs + two 3-state mount blocks (mirror `:1271-1310`) mounting `build_mcp_override_routes`/`build_mcp_allowlist_routes` at `prefix="/api/v1"`, each with an `app.state.<name>_router_mounted` flag. A wiring test asserts the host's `MCPAuthzClient` has the allow-list store and the host has the override store when built via `build_runtime`/`build_mcp_host`.

- [ ] **Step 2: ADR-002 amendment + spec §9 sync** — ADR-002 `## per-tenant internal-host allow-list + operator server_url override (PR-2b-1, 2026-06-25)`: the two audited stores, the `http://`-IP-literal override grammar + exact-IP allow-list grammar (+ hard-block set, AS-9 ownership residual), the three-resource-leg HTTP-only carve-out returning the pinned IP, the `prm_metadata` resolve-and-pin, resolve-per-use (incl. the cache-key fix), the new RBAC family + HumanActor boundary, the `audit.mcp_allowlist_permitted` event (no `pack_id`, DD-2), fail-closed semantics; name the deferred deployed **Proof 1b-2 = PR-2b-2**. **Spec §9** line ~146: change the event to `audit.mcp_allowlist_permitted` and **drop `pack`** from its payload (already patched in this plan's prep; verify it landed).

- [ ] **Step 3: closeout gate** (CC discipline — fresh full-suite data, the verify-promotion rule):
```bash
uv run pytest --cov --cov-report=json -q            # full suite (2 pre-existing sdk/testing fails expected)
uv run python tools/check_critical_coverage.py      # mcp_config/storage.py, mcp_authz.py, mcp_host.py, scopes.py >= 95/90
uv run mypy src tests && uv run ruff check . && uv run ruff format --check .
```
`core/mcp_config/storage.py` is **already on the gate** (promoted in Task 1); this closeout **re-verifies** the full CC gate (all PR-2b-1 CC modules + the existing set) on fresh full-suite data.

- [ ] **Step 4: commit.**

---

## Self-review

- **Spec coverage:** override store + `http://`-IP-literal grammar (§6/§8, T1) · exact-IP allow-list store + AS-4 grammar (§7, T1) · guard carve-out 3-resource-legs + HTTP-only + full-resolved-set + **guard-time hard-block floor** + `audit.mcp_allowlist_permitted` (§7/§7a/§9, T2 per DD-2) · `prm_metadata` resolve-and-pin + rebinding test (§8 line 136 / §11 line 174, T3) · resolve-per-use + stale-cache fix (§6/OD-12, T4) · RBAC family + HumanActor + `actor_type=human` audit (§9 line 145, T1/T5/T6) · fail-closed (§10, T2/T4) · AS-9 residual + hard-block (T1 + ADR). Proof 1b-2 **out of scope (PR-2b-2)**.
- **Placeholder scan:** none — each task has the new code or an exact "mirror file:line + these specifics."
- **Type/name consistency:** `internal_host_allowlist_store` / `override_store` seam names consistent across `mcp_authz`/`mcp_host`/`harness`; guard return `str | None` consumed by `_fetch_prm` (T3); `MCPConfigRefusalReason` (9 values: 5 override + 4 allow-list) reused by the routes; `actor_type` threaded store→route; `MCPInternalAccessRBACScope` 4 values consistent across scopes/actor/enforcement/tests; one event spelling `audit.mcp_allowlist_permitted` (plan + spec + ADR + tests).

## Execution handoff

Subagent-driven (fresh subagent per task + two-stage review), one commit token per task per the established cadence. **T1 → T7** in order (T2 depends on T1's allow-list store; T3 depends on T2's pinned-IP return; T4 depends on T1's override store; T6 depends on T1's stores + T5's scopes; T7 wires all). The deployed **Proof 1b-2 is PR-2b-2** — a separate plan after this merges.
