# M3-E2b — `cognic-tool-oracle-schema` external pack (implementation plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first external Cognic AgentOS product pack — `cognic-tool-oracle-schema`, a FastMCP MCP-server exposing six `read_only` Oracle schema-metadata tools — generated from `agentos init-tool @ v0.0.2`, with a real JWT/JWKS verifier, its own CI/sign/verify/release, and a recorded provenance to the AgentOS authoring tag.

**Architecture:** A standalone repo (NOT inside cognic-agentos), no kernel runtime dependency. A FastMCP Streamable-HTTP server registers six tools that each run a fixed, parameterised `SELECT` against Oracle data-dictionary views via `oracledb` (thin-mode async pool). Auth is OAuth-PRM resource-server mode with a `PyJWT`/JWKS verifier (fail-closed; `dev_insecure` only under `COGNIC_ENV=dev`). The kernel `agentos` CLI is used author/CI-time only (validate/sign/verify) via the `@v0.0.2` git pin.

**Tech Stack:** Python 3.12; `mcp==1.27.0` (FastMCP) + `uvicorn[standard]>=0.35`; `oracledb>=2.5` (thin-mode async); `PyJWT[crypto]>=2.10,<3`; dev: `cognic-agentos @ git+…@v0.0.2`, `pytest>=8`, `pytest-asyncio>=1`. Integration substrate: `gvenzl/oracle-xe:21-slim` (`XEPDB1`).

**Design source of truth:** `docs/superpowers/specs/2026-06-28-m3-e2-oracle-schema-tool-pack-design.md` (#108) — this plan does NOT re-decide design; it builds it. **This plan FILE lives in cognic-agentos** (`docs/superpowers/plans/`); the BUILD happens in the new external repo `/Users/bmz/development/cognic-tool-oracle-schema`.

## Global Constraints

- **New separate repo:** `bmzee/cognic-tool-oracle-schema` (public), local path `/Users/bmz/development/cognic-tool-oracle-schema`. NEVER inside cognic-agentos.
- **No kernel runtime dep.** Kernel pin (`cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2`) lives in `[project.optional-dependencies] dev` only.
- **Safety boundary (verbatim from #108, goes in README + module docstrings):** *"This is a schema-metadata tool, not a database query tool. It never executes user-supplied SQL, never queries application tables, never returns application rows, and never performs DML/DDL."* Every query is a fixed string with **bind variables**; tool args bind as values, never concatenated. No passthrough tool.
- **Governance manifest (from #108):** `[risk_tier] tier="read_only"`; `[data_governance] data_classes=["internal"], purpose="operational_telemetry", retention_policy="none", egress_allow_list=[]`; `[tool.cognic.mcp] auth="oauth-prm", transport="streamable-http", scopes=["oracle_schema.read"]`.
- **Env (from #108):** `COGNIC_ORACLE_DSN` / `COGNIC_ORACLE_USER` / `COGNIC_ORACLE_PASSWORD` / `COGNIC_ORACLE_ALLOWED_OWNERS` (unset = trust DB grant) / `COGNIC_ORACLE_MAX_ROWS` (default 200, hard max 1000); `COGNIC_OAUTH_ISSUER` / `COGNIC_OAUTH_JWKS_URI` / `COGNIC_OAUTH_AUDIENCE` (or derive from server URL) / `COGNIC_REQUIRED_SCOPES=oracle_schema.read`; `COGNIC_AUTH_MODE` (`jwt` default; `dev_insecure` only when `COGNIC_ENV=dev`, else fail-closed at startup).
- **Output bounding:** every enumerating tool returns `{items|columns: [...], truncated: bool}`; the Oracle cursor fetches `MAX_ROWS+1` rows via `fetchmany()` to detect truncation; no opaque cursor in v1.
- **Read-only DB account:** the connecting Oracle user is granted only catalog `SELECT` (e.g. `SELECT_CATALOG_ROLE`). Documented as an operator precondition.
- **TDD, frequent commits** in the external repo. **Per-action authorization** for every remote-affecting step (repo create, push, release, tag) — restate + token-gate each.
- **Record provenance:** the resolved AgentOS tag `v0.0.2` = commit `1baed46` (`git rev-list -n1 v0.0.2`) recorded in the pack's `docs/VALIDATION-RESULTS.md` (source of truth) + a `README.md` pointer line.

---

## File Structure (the external repo)

```
cognic-tool-oracle-schema/
  pyproject.toml                  # deps, entry-point → SERVER_DESCRIPTOR, force-include manifest
  cognic-pack-manifest.toml       # [pack]/[identity]/[data_governance]/[risk_tier]/[supply_chain]/[tool.cognic.mcp]
  README.md                       # usage, safety boundary, dev-run, provenance pointer
  .github/workflows/sign-and-publish.yml  # from scaffold, @v0.0.2
  docker-compose.oracle.yml       # gvenzl/oracle-xe:21-slim for integration tests
  src/cognic_tool_oracle_schema/
    __init__.py                   # SERVER_DESCRIPTOR (from scaffold)
    config.py                     # env config + fail-closed validation
    oracle.py                     # async pool + bounded fetch helper + owner-allowlist guard
    tools.py                      # the 6 schema-metadata tool functions (SQL + bind + map)
    auth.py                       # JwtTokenVerifier (PyJWKClient) + _select_token_verifier (dev_insecure guard)
    server.py                     # build_server: register the 6 tools + the verifier
    py.typed
  tests/
    conftest.py
    test_config.py                # env parse + fail-closed
    test_oracle.py                # bounded fetch + allowlist guard (fake cursor)
    test_tools.py                 # per-tool SQL/bind/allowlist/bounds (fake cursor, no DB)
    test_auth.py                  # verifier accept/reject + dev_insecure guard
    test_server.py                # build_server registers 6 tools; auth wired
    fixtures/seed_schema.sql      # tiny schema for integration
    integration/test_oracle_integration.py  # env-gated, real XE
  docs/VALIDATION-RESULTS.md      # provenance: authored against cognic-agentos v0.0.2 (1baed46) + sign/verify proof
  attestations/                   # generated by `agentos sign --bundle` at release
```

---

## Task 1: Repo genesis — generate from `init-tool @ v0.0.2`, fill logistics

**Files:** the whole scaffold (generated) + `pyproject.toml` + `cognic-pack-manifest.toml` edits.

**Interfaces:** Produces the repo skeleton with the FastMCP shape (`SERVER_DESCRIPTOR`, `server.py`), distribution name `cognic-tool-oracle-schema`, module `cognic_tool_oracle_schema`, the locked deps, and the governance manifest.

- [ ] **Step 1: Install the kernel CLI @ v0.0.2 in a clean 3.12 venv** (author-time tool):
```bash
cd /Users/bmz/development
uv venv --python 3.12 /tmp/agentos-v002 && \
  uv pip install --python /tmp/agentos-v002/bin/python "cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2"
```
- [ ] **Step 2: Generate the scaffold.** `init-tool` pack-names are `[a-z][a-z0-9_]*` (no hyphen), so use `oracle_schema`:
```bash
cd /Users/bmz/development
/tmp/agentos-v002/bin/agentos init-tool oracle_schema
# → creates ./cognic-tool-oracle_schema/ with module src/cognic_tool_oracle_schema/
```
- [ ] **Step 3: Rename the distribution to the hyphenated repo name** (keep the underscore module — standard Python dist/module split):
```bash
cd /Users/bmz/development
mv cognic-tool-oracle_schema cognic-tool-oracle-schema
cd cognic-tool-oracle-schema && git init
```
Edit `pyproject.toml` `name = "cognic-tool-oracle_schema"` → `"cognic-tool-oracle-schema"`. Edit `cognic-pack-manifest.toml` `[pack] pack_id` → `"cognic-tool-oracle-schema"`. The module dir, entry-point (`cognic_tool_oracle_schema:SERVER_DESCRIPTOR`), and force-include path stay underscore.
- [ ] **Step 4: Fill the locked deps in `pyproject.toml`** — runtime `dependencies = ["mcp==1.27.0", "uvicorn[standard]>=0.35", "oracledb>=2.5", "PyJWT[crypto]>=2.10,<3"]`; `[project.optional-dependencies] dev = ["pytest>=8", "pytest-asyncio>=1", "cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.2"]`; keep `requires-python = ">=3.12,<3.13"`.
- [ ] **Step 5: Fill the manifest governance** (`cognic-pack-manifest.toml`) — `[identity]` concrete values: `agent_id = "did:web:github.com:bmzee:cognic-tool-oracle-schema"`, `display_name = "Cognic Oracle Schema"`, `provider_organization = "Cognic"`, `provider_url = "https://github.com/bmzee/cognic-tool-oracle-schema"`; `[data_governance] data_classes = ["internal"]`, `purpose = "operational_telemetry"`, `retention_policy = "none"`, `egress_allow_list = []`; `[risk_tier] tier = "read_only"`; `[tool.cognic.mcp] auth = "oauth-prm"`, `transport = "streamable-http"`, `server_url = "http://127.0.0.1:8765/mcp"` (deploy-overridden), `scopes = ["oracle_schema.read"]`.
- [ ] **Step 6: Verify scaffold integrity** — `cd /Users/bmz/development/cognic-tool-oracle-schema`; `uv venv --python 3.12 .venv && uv pip install -e '.[dev]'`; `python -c "import ast,sys; ast.parse(open('src/cognic_tool_oracle_schema/server.py').read())"`. (Do NOT commit yet; repo creation is a later token-gated step.)

---

## Task 2: `config.py` — env config + fail-closed validation

**Files:** Create `src/cognic_tool_oracle_schema/config.py`; Test `tests/test_config.py`.

**Interfaces:** Produces `@dataclass(frozen=True) Config` + `Config.from_env() -> Config`. Consumed by `oracle.py`, `auth.py`, `server.py`.

- [ ] **Step 1: Failing test** (`tests/test_config.py`):
```python
import pytest
from cognic_tool_oracle_schema.config import Config, ConfigError


def test_from_env_parses_oracle_and_auth(monkeypatch):
    for k, v in {
        "COGNIC_ORACLE_DSN": "localhost:1521/XEPDB1",
        "COGNIC_ORACLE_USER": "ro_user",
        "COGNIC_ORACLE_PASSWORD": "pw",
        "COGNIC_ORACLE_ALLOWED_OWNERS": "HR, SALES",
        "COGNIC_ORACLE_MAX_ROWS": "50",
        "COGNIC_OAUTH_ISSUER": "https://as.example/",
        "COGNIC_OAUTH_JWKS_URI": "https://as.example/.well-known/jwks.json",
        "COGNIC_OAUTH_AUDIENCE": "http://127.0.0.1:8765/mcp",
        "COGNIC_REQUIRED_SCOPES": "oracle_schema.read",
        "COGNIC_AUTH_MODE": "jwt",
    }.items():
        monkeypatch.setenv(k, v)
    cfg = Config.from_env()
    assert cfg.allowed_owners == frozenset({"HR", "SALES"})
    assert cfg.max_rows == 50
    assert cfg.required_scopes == frozenset({"oracle_schema.read"})


def test_max_rows_clamped_to_hard_cap(monkeypatch):
    _set_min_oracle_env(monkeypatch); monkeypatch.setenv("COGNIC_ORACLE_MAX_ROWS", "99999")
    assert Config.from_env().max_rows == 1000


def test_jwt_mode_requires_oauth_fields(monkeypatch):
    _set_min_oracle_env(monkeypatch); monkeypatch.setenv("COGNIC_AUTH_MODE", "jwt")
    monkeypatch.delenv("COGNIC_OAUTH_ISSUER", raising=False)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_dev_insecure_only_in_dev_env(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure"); monkeypatch.delenv("COGNIC_ENV", raising=False)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_required_scopes_cannot_be_empty(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    monkeypatch.setenv("COGNIC_REQUIRED_SCOPES", " , ")
    with pytest.raises(ConfigError):
        Config.from_env()
```
(`_set_min_oracle_env` sets DSN/USER/PASSWORD — define it at top of the test.)

- [ ] **Step 2: Run → fail** (`ConfigError`/`Config` undefined). `uv run pytest tests/test_config.py -v`.
- [ ] **Step 3: Implement** `config.py`:
```python
from __future__ import annotations

import os
from dataclasses import dataclass

_HARD_MAX_ROWS = 1000
_DEFAULT_MAX_ROWS = 200


class ConfigError(RuntimeError):
    """Raised at startup when required env is missing or dev_insecure is misused (fail-closed)."""


@dataclass(frozen=True)
class Config:
    oracle_dsn: str
    oracle_user: str
    oracle_password: str
    allowed_owners: frozenset[str]          # empty = trust the DB grant
    max_rows: int
    pool_max: int
    auth_mode: str                           # "jwt" | "dev_insecure"
    oauth_issuer: str | None
    oauth_jwks_uri: str | None
    oauth_audience: str | None
    required_scopes: frozenset[str]

    @staticmethod
    def from_env() -> "Config":
        def _req(k: str) -> str:
            v = os.environ.get(k)
            if not v:
                raise ConfigError(f"missing required env {k}")
            return v

        auth_mode = os.environ.get("COGNIC_AUTH_MODE", "jwt")
        if auth_mode == "dev_insecure" and os.environ.get("COGNIC_ENV") != "dev":
            raise ConfigError("COGNIC_AUTH_MODE=dev_insecure requires COGNIC_ENV=dev")
        if auth_mode not in ("jwt", "dev_insecure"):
            raise ConfigError(f"invalid COGNIC_AUTH_MODE {auth_mode!r}")

        owners_raw = os.environ.get("COGNIC_ORACLE_ALLOWED_OWNERS", "")
        allowed = frozenset(o.strip().upper() for o in owners_raw.split(",") if o.strip())

        try:
            max_rows = int(os.environ.get("COGNIC_ORACLE_MAX_ROWS", str(_DEFAULT_MAX_ROWS)))
        except ValueError as exc:
            raise ConfigError("COGNIC_ORACLE_MAX_ROWS must be an integer") from exc
        max_rows = max(1, min(max_rows, _HARD_MAX_ROWS))

        issuer = os.environ.get("COGNIC_OAUTH_ISSUER")
        jwks = os.environ.get("COGNIC_OAUTH_JWKS_URI")
        audience = os.environ.get("COGNIC_OAUTH_AUDIENCE")
        if auth_mode == "jwt" and not (issuer and jwks and audience):
            raise ConfigError(
                "COGNIC_AUTH_MODE=jwt requires COGNIC_OAUTH_ISSUER, "
                "COGNIC_OAUTH_JWKS_URI, COGNIC_OAUTH_AUDIENCE"
            )
        scopes = frozenset(
            s.strip() for s in os.environ.get("COGNIC_REQUIRED_SCOPES", "oracle_schema.read").split(",") if s.strip()
        )
        if not scopes:
            raise ConfigError("COGNIC_REQUIRED_SCOPES must contain at least one scope")
        return Config(
            oracle_dsn=_req("COGNIC_ORACLE_DSN"),
            oracle_user=_req("COGNIC_ORACLE_USER"),
            oracle_password=_req("COGNIC_ORACLE_PASSWORD"),
            allowed_owners=allowed, max_rows=max_rows,
            pool_max=int(os.environ.get("COGNIC_ORACLE_POOL_MAX", "4")),
            auth_mode=auth_mode, oauth_issuer=issuer, oauth_jwks_uri=jwks,
            oauth_audience=audience, required_scopes=scopes,
        )
```
- [ ] **Step 4: Run → pass. Commit** (external repo): `feat: env config with fail-closed validation`.

---

## Task 3: `oracle.py` — async pool + bounded fetch + owner-allowlist guard

**Files:** Create `src/cognic_tool_oracle_schema/oracle.py`; Test `tests/test_oracle.py`.

**Interfaces:** Produces `init_pool(cfg)`, `close_pool()`, `async fetch(sql, binds, *, limit) -> tuple[list[tuple], bool]`, and `guard_owner(owner, cfg) -> str` (raises `OwnerNotAllowed` when an allow-list is set + owner not in it; upper-cases). Consumed by `tools.py`.

- [ ] **Step 1: Failing test** (fake cursor, no DB):
```python
import pytest
from cognic_tool_oracle_schema import oracle
from cognic_tool_oracle_schema.config import Config


def _cfg(**kw): ...  # minimal Config with allowed_owners/max_rows overridable


def test_guard_owner_allows_when_no_allowlist():
    assert oracle.guard_owner("hr", _cfg(allowed_owners=frozenset())) == "HR"


def test_guard_owner_refuses_outside_allowlist():
    with pytest.raises(oracle.OwnerNotAllowed):
        oracle.guard_owner("SECRET", _cfg(allowed_owners=frozenset({"HR"})))


@pytest.mark.asyncio
async def test_fetch_sets_truncated_when_over_limit(monkeypatch):
    # fake pool/cursor returning limit+1 rows; assert truncated True + rows trimmed to limit
    rows = await oracle.fetch("select 1 from dual", {}, limit=2, _pool=_FakePool([("a",), ("b",), ("c",)]))
    assert rows == ([("a",), ("b",)], True)
```
(Inject a fake pool via a test seam — the real `fetch` reads the module pool; the test passes a `_pool=` override param.)

- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** `oracle.py`:
```python
from __future__ import annotations

import oracledb
from .config import Config

_pool: "oracledb.AsyncConnectionPool | None" = None


class OwnerNotAllowed(ValueError):
    """Owner not in COGNIC_ORACLE_ALLOWED_OWNERS (operator-visible product boundary)."""


def init_pool(cfg: Config) -> None:
    global _pool
    _pool = oracledb.create_pool_async(
        user=cfg.oracle_user, password=cfg.oracle_password, dsn=cfg.oracle_dsn,
        min=1, max=cfg.pool_max, increment=1,
    )


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def guard_owner(owner: str, cfg: Config) -> str:
    """Upper-case + (when an allow-list is configured) refuse owners not in it.
    Empty allow-list = trust the DB grant. The DB read-only grant is the hard
    boundary; this is the operator-visible product boundary."""
    norm = owner.strip().upper()
    if cfg.allowed_owners and norm not in cfg.allowed_owners:
        raise OwnerNotAllowed(f"owner {norm!r} not in COGNIC_ORACLE_ALLOWED_OWNERS")
    return norm


async def fetch(sql: str, binds: dict, *, limit: int, _pool=None) -> tuple[list[tuple], bool]:
    """Run a bounded read-only SELECT. Fetches limit+1 rows from the cursor to
    detect truncation; returns (rows[:limit], truncated)."""
    pool = _pool if _pool is not None else _require_pool()
    async with pool.acquire() as conn:
        with conn.cursor() as cur:
            await cur.execute(sql, binds)
            fetched = await cur.fetchmany(limit + 1)
    return fetched[:limit], len(fetched) > limit


def _require_pool():
    if _pool is None:
        raise RuntimeError("oracle pool not initialised; call init_pool(cfg) at startup")
    return _pool
```
(The `_FakePool` in the test implements `acquire()` as an async context manager yielding a fake connection whose `cursor()` returns a fake cursor with async `execute`/`fetchmany`.)
- [ ] **Step 4: Run → pass. Commit:** `feat: async oracle pool, bounded fetch, owner-allowlist guard`.

---

## Task 4: `tools.py` — the six schema-metadata tools

**Files:** Create `src/cognic_tool_oracle_schema/tools.py`; Test `tests/test_tools.py`.

**Interfaces:** Produces six async functions, each `(*, cfg, **args) -> dict` returning `{items|columns: [...], truncated: bool}`. All SQL is fixed with bind variables (`:owner`, `:tname`, `:pat` and generated `:owner_N` allow-list binds); owner args pass through `guard_owner`. Consumed by `server.py`.

The SQL (Oracle data-dictionary; result bounding is enforced by `oracle.fetch(...).fetchmany(limit + 1)`, not by a fragile row-limit clause):

```python
from __future__ import annotations

from .config import Config
from .oracle import fetch, guard_owner

_LIST_SCHEMAS = (
    "SELECT DISTINCT owner FROM all_tables "
    "WHERE {owner_filter} ORDER BY owner"
)
_LIST_TABLES = (
    "SELECT t.table_name, c.comments FROM all_tables t "
    "LEFT JOIN all_tab_comments c ON c.owner = t.owner AND c.table_name = t.table_name "
    "WHERE t.owner = :owner ORDER BY t.table_name"
)
_DESCRIBE_TABLE = (
    "SELECT col.column_name, col.data_type, col.nullable, col.data_default, cc.comments "
    "FROM all_tab_columns col "
    "LEFT JOIN all_col_comments cc ON cc.owner = col.owner "
    "AND cc.table_name = col.table_name AND cc.column_name = col.column_name "
    "WHERE col.owner = :owner AND col.table_name = :tname "
    "ORDER BY col.column_id"
)
_FIND_COLUMNS = (
    "SELECT owner, table_name, column_name, data_type FROM all_tab_columns "
    "WHERE column_name LIKE :pat AND {owner_filter} "
    "ORDER BY owner, table_name, column_name"
)
_LIST_RELATIONSHIPS = (
    "SELECT c.constraint_name, c.owner AS child_owner, c.table_name AS child_table, "
    "cc.column_name AS child_column, rc.owner AS parent_owner, rc.table_name AS parent_table, "
    "rcc.column_name AS parent_column "
    "FROM all_constraints c "
    "JOIN all_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name "
    "JOIN all_constraints rc ON rc.owner = c.r_owner AND rc.constraint_name = c.r_constraint_name "
    "JOIN all_cons_columns rcc ON rcc.owner = rc.owner AND rcc.constraint_name = rc.constraint_name "
    "AND rcc.position = cc.position "
    "WHERE c.constraint_type = 'R' AND c.owner = :owner {table_filter} "
    "ORDER BY c.constraint_name, cc.position"
)
_GET_CONSTRAINTS = (
    "SELECT c.constraint_name, c.constraint_type, cc.column_name, c.search_condition, "
    "c.r_owner, c.r_constraint_name "
    "FROM all_constraints c "
    "LEFT JOIN all_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name "
    "WHERE c.owner = :owner AND c.table_name = :tname "
    "ORDER BY c.constraint_name, cc.position"
)
```

Each function maps rows → dicts and wraps `{..., "truncated": truncated}`. `list_schemas` applies the configured owner allow-list even though it has no owner argument; `find_columns(owner=None)` also filters to the configured allow-list when present; `find_columns(owner="...")` uses `guard_owner`. Build the owner predicates with bind variables only:
```python
def _owner_predicate(column: str, cfg: Config, *, owner: str | None = None) -> tuple[str, dict[str, str]]:
    if owner is not None:
        return f"{column} = :owner", {"owner": guard_owner(owner, cfg)}
    if not cfg.allowed_owners:
        return "1 = 1", {}
    binds = {f"owner_{i}": value for i, value in enumerate(sorted(cfg.allowed_owners))}
    placeholders = ", ".join(f":{key}" for key in binds)
    return f"{column} IN ({placeholders})", binds
```
`list_relationships` builds `{table_filter}` as `AND c.table_name = :tname` only when `table` is supplied. Example body (the others follow the same shape):
```python
async def describe_table(*, cfg: Config, owner: str, table: str) -> dict:
    rows, truncated = await fetch(
        _DESCRIBE_TABLE,
        {"owner": guard_owner(owner, cfg), "tname": table.strip().upper()},
        limit=cfg.max_rows,
    )
    columns = [
        {"column_name": r[0], "data_type": r[1], "nullable": r[2] == "Y",
         "data_default": (r[3].strip() if r[3] else None), "comments": r[4]}
        for r in rows
    ]
    return {"columns": columns, "truncated": truncated}
```

- [ ] **Step 1: Failing tests** (`tests/test_tools.py`, fake-cursor; assert per tool: (a) the SQL uses the right `all_*` view, (b) args bind as values [no f-string concat], (c) owner args run through `guard_owner` → `OwnerNotAllowed` when outside the allow-list, (d) `list_schemas` and ownerless `find_columns` still constrain results to `COGNIC_ORACLE_ALLOWED_OWNERS` via generated binds, (e) `truncated` honours `max_rows`). Capture the executed SQL+binds via a fake `fetch` (monkeypatch `tools.fetch`).
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** all six functions per the SQL above.
- [ ] **Step 4: Run → pass. Commit:** `feat: six read-only Oracle schema-metadata tools`.

---

## Task 5: `auth.py` — PyJWT/JWKS verifier + fail-closed selection

**Files:** Create `src/cognic_tool_oracle_schema/auth.py`; Test `tests/test_auth.py`.

**Interfaces:** Produces `JwtTokenVerifier(TokenVerifier)` (async `verify_token`), a `DevTokenVerifier` (dev-only), and `select_token_verifier(cfg) -> TokenVerifier`. Consumed by `server.py`.

- [ ] **Step 1: Failing tests** — (a) `select_token_verifier` returns `JwtTokenVerifier` in `jwt` mode, `DevTokenVerifier` in `dev_insecure` (cfg already enforces `COGNIC_ENV=dev`); (b) `JwtTokenVerifier.verify_token` returns `None` for an unverifiable token (monkeypatch `_verify_sync` to raise) and an `AccessToken` with the required scope for a valid one (monkeypatch `_verify_sync` to return claims incl. `scope`); (c) a valid token missing the required scope → `None`.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** `auth.py`:
```python
from __future__ import annotations

import asyncio

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import Config


class DevTokenVerifier(TokenVerifier):
    """DEV-ONLY (reachable only via COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev,
    enforced in Config.from_env). Accepts any non-empty bearer."""

    def __init__(self, cfg: Config) -> None:
        self._scopes = list(cfg.required_scopes)
        self._aud = cfg.oauth_audience or ""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(token=token, client_id="dev", scopes=self._scopes,
                           expires_at=None, resource=self._aud)


class JwtTokenVerifier(TokenVerifier):
    """Resource-server verifier: validates RS256 signature against the AS JWKS,
    plus audience / issuer / exp / required scope."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._jwks = PyJWKClient(cfg.oauth_jwks_uri)  # type: ignore[arg-type]  # jwt-mode guarantees non-None

    def _verify_sync(self, token: str) -> dict:
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token, signing_key.key, algorithms=["RS256"],
            audience=self._cfg.oauth_audience, issuer=self._cfg.oauth_issuer,
            options={"require": ["exp", "iat"]},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        try:
            claims = await asyncio.to_thread(self._verify_sync, token)
        except Exception:
            return None  # FastMCP treats None as unauthorized (fail-closed)
        granted = _scopes_from_claims(claims)
        if not self._cfg.required_scopes.issubset(granted):
            return None
        return AccessToken(
            token=token, client_id=str(claims.get("azp") or claims.get("client_id") or "unknown"),
            scopes=sorted(granted), expires_at=claims.get("exp"),
            resource=self._cfg.oauth_audience,
        )


def _scopes_from_claims(claims: dict) -> set[str]:
    raw = claims.get("scope") or claims.get("scp") or ""
    return set(raw.split()) if isinstance(raw, str) else set(raw)


def select_token_verifier(cfg: Config) -> TokenVerifier:
    return DevTokenVerifier(cfg) if cfg.auth_mode == "dev_insecure" else JwtTokenVerifier(cfg)
```
- [ ] **Step 4: Run → pass. Commit:** `feat: PyJWT/JWKS resource-server verifier with dev_insecure guard`.

---

## Task 6: `server.py` — wire the FastMCP server

**Files:** Modify `src/cognic_tool_oracle_schema/server.py` (replace the scaffold's `ping`); Test `tests/test_server.py`.

**Interfaces:** Produces `build_server(*, as_issuer) -> FastMCP` registering the six tools + the selected verifier; lifespan calls `oracle.init_pool(cfg)`/`close_pool()`.

- [ ] **Step 1: Failing test** — `build_server` returns a `FastMCP` whose registered tool names are exactly `{list_schemas, list_tables, describe_table, find_columns, list_relationships, get_constraints}`; with `COGNIC_AUTH_MODE=jwt` + missing oauth env, building fails closed (Config raises). (Inspect FastMCP's registered tools via its public tool registry; confirm the exact accessor at build time.)
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** — `Config.from_env()`; `FastMCP(..., auth=AuthSettings(...), token_verifier=select_token_verifier(cfg))`; register each tool with `@mcp.tool(name=..., description=...)` delegating to `tools.<fn>(cfg=cfg, **args)`; wire `oracle.init_pool(cfg)` at startup + `close_pool()` at shutdown (FastMCP lifespan). Keep the env-driven host/url + `__main__` runner from the scaffold.
- [ ] **Step 4: Run → pass. Commit:** `feat: wire FastMCP server with the six tools + verifier + oracle pool lifespan`.

---

## Task 7: Integration substrate — gvenzl XE + seed schema + env-gated tests

**Files:** Create `docker-compose.oracle.yml`, `tests/fixtures/seed_schema.sql`, `tests/integration/test_oracle_integration.py`, `tests/integration/conftest.py`.

- [ ] **Step 1:** `docker-compose.oracle.yml` — `gvenzl/oracle-xe:21-slim`, `XEPDB1`, `APP_USER`/`APP_USER_PASSWORD`, healthcheck (copy the kernel's `infra/dev/docker-compose.oracle.yml` pattern).
- [ ] **Step 2:** `seed_schema.sql` — ≥2 tables with a FK, a PK + a UNIQUE + a CHECK constraint, varied column types + a table/column comment (so all six tools return real metadata). Grant the read-only test user `SELECT_CATALOG_ROLE` (or catalog SELECT).
- [ ] **Step 3:** `tests/integration/test_oracle_integration.py` — env-gated `@pytest.mark.skipif(os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION") != "1")`; `pytest -m oracle`; `init_pool` against XE; assert each of the six tools returns the seeded metadata (e.g. `describe_table` returns the seeded columns; `list_relationships` returns the FK edge; `get_constraints` returns PK/UK/CK/FK). Fail loud (not skip) when opted-in but DB unreachable.
- [ ] **Step 4: Run** (env-gated; operator runs with XE up). Unit suite stays green without DB. **Commit:** `test: gvenzl XE integration substrate + seeded six-tool checks`.

---

## Task 8: CI, README, provenance record

**Files:** `.github/workflows/sign-and-publish.yml` (from scaffold — confirm `@v0.0.2`), `README.md`, `docs/VALIDATION-RESULTS.md`.

- [ ] **Step 1:** Confirm the scaffold CI git-installs `cognic-agentos @ …@v0.0.2` → `agentos validate .` → `agentos sign --bundle .` → `agentos verify .`. Add a `pytest` (unit) step + the `oracle integration` job (gated, brings up the compose) mirroring the kernel's lanes.
- [ ] **Step 2:** `README.md` — overview, the **verbatim safety-boundary statement**, the operator notes (DSN is deployment config not manifest egress; metadata only; no rows/SQL/persistence; scope sensitive names via `COGNIC_ORACLE_ALLOWED_OWNERS` + DB grants), the env table, the dev-run (`COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev python -m cognic_tool_oracle_schema.server`), and a **provenance pointer line** → `docs/VALIDATION-RESULTS.md`.
- [ ] **Step 3:** `docs/VALIDATION-RESULTS.md` — "Authored against **cognic-agentos `v0.0.2`** = commit `1baed46` (`git rev-list -n1 v0.0.2`)." Leave a `sign/verify proof` section to fill at release (Task 9).
- [ ] **Step 4: Commit:** `docs: CI lanes, README (safety boundary + provenance), VALIDATION-RESULTS`.

---

## Task 9: Local gate, repo creation, first push, release proof

- [ ] **Step 1: Full local gate** — `uv run pytest` (unit; integration env-gated), `uv run ruff check` / `ruff format --check` (adopt ruff config from the kernel's style), `uv run mypy src tests`. Green.
- [ ] **Step 2: `agentos validate .`** (via the `.[dev]` kernel CLI) → clean. **HALT** — report; request the **repo-creation token** (remote-affecting).
- [ ] **Step 3 (token-gated):** `gh repo create bmzee/cognic-tool-oracle-schema --public --source=. --remote=origin` (restate first). Push `main`.
- [ ] **Step 4: Release proof (token-gated)** — `agentos sign --bundle .` (cosign/syft/grype/pip-licenses; operator host) → `agentos verify .` → green; record the proof + the resolved SHA in `docs/VALIDATION-RESULTS.md`; tag the pack `v0.1.0`. If a required supply-chain binary is absent, record `BLOCKED tooling_absent:<bin>`, install/provide the missing tool, and rerun; unlike M3-E1's enablement smoke, M3-E2b is not complete until sign + verify both pass.
- [ ] **Step 5:** Confirm CI green on the pushed repo.

**M3-E2c handoff:** once `cognic-tool-oracle-schema` is released + signed, M3-E2c is its own deploy design+plan (reuse the Proof 1b-2 kind topology + an in-cluster seeded `gvenzl/oracle-xe:21-slim`; install the released signed pack; discovery `auth_ready`; real `call_tool(describe_table)`). That run flips the M3 checkbox.

---

## Self-Review

**Spec coverage (#108):** six tools §5.2 (Task 4) · safety boundary §5.3 (README + module docstrings + bind-only SQL, Tasks 4/8) · connection model §5.4 (Tasks 2/3) · real JWT/JWKS verifier + `dev_insecure` §5.5 (Tasks 2/5) · manifest §5.6 (Task 1) · CI/release §5.7 (Tasks 8/9) · local tests §5.8 (Tasks 4/7) · provenance/SHA (Tasks 8/9). M3-E2c §6 is the deferred deploy-plan (handoff noted).

**Placeholder scan:** generated scaffold placeholders are filled with concrete values in Task 1; no plan placeholders or scaffold placeholder tokens remain. Two build-time confirmations are flagged inline (FastMCP's registered-tool accessor in Task 6; whether `mcp` ships a built-in verifier — we ship our own regardless).

**Type/name consistency:** distribution `cognic-tool-oracle-schema` / module `cognic_tool_oracle_schema` / entry-point `cognic_tool_oracle_schema:SERVER_DESCRIPTOR` consistent (Task 1). `Config` fields consumed by `oracle`/`auth`/`tools`/`server` match Task 2's definition. The six tool names are identical across Tasks 4/6/7. `fetch(...)→(rows, truncated)` + `guard_owner(...)→str`/`OwnerNotAllowed` consistent across Tasks 3/4.

**Risks:** (1) Oracle async cursor API (`execute` + `fetchmany`) is pinned by fake-cursor unit tests and the XE integration test. (2) `PyJWKClient.get_signing_key_from_jwt` is sync + network — wrapped in `asyncio.to_thread`; PyJWKClient caches keys. (3) the dist-name/module split rename (Task 1) — pinned by `agentos validate` + the import in tests. (4) read-only DB grant is an operator precondition (documented), not enforced by the pack.

## Execution Handoff

Plan complete. Recommended: **subagent-driven** (fresh subagent per task, two-stage review), with the remote-affecting steps (Task 9 repo-create / push / release / tag) token-gated and restated. Tasks 1–8 are local to the new repo; the repo only goes remote at Task 9.
