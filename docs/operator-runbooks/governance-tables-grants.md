# Operator Runbook — Governance-Table GRANTs

> **Audience:** bank database operators rolling out Cognic AgentOS for the first time, or rotating credentials.
>
> **When:** apply this runbook **before** the AgentOS runtime container connects to the database with non-superuser credentials. The runbook is the production-grade canary for the BUILD_PLAN "Append-only governance tables" principle.
>
> **What it does:** grants the runtime DB role exactly the privileges it needs on `audit_event`, `decision_history`, and `governance_chain_heads` — and nothing more. UPDATE / DELETE on the evidence tables are reserved for a separate `agentos_evidence_admin` role used by Phase 3.3 evidence-pack export + retention enforcement.
>
> **Why not in the Alembic migration:** schema management (DDL) and role management (admin) are separate concerns. Banks have account-management policies that conflict with migration-driven role/grant churn. Mixing them invites silent privilege drift across deployments. The migration ships pure DDL; this runbook ships dialect-specific GRANT shapes.

## Step 1 — Confirm the migration ran

```bash
COGNIC_DATABASE_URL='<your superuser DSN>' uv run alembic current
# Expected output: a single line ending in `0001 (head)` or similar.
```

If the migration hasn't run, apply it first:

```bash
COGNIC_DATABASE_URL='<your superuser DSN>' uv run alembic upgrade head
```

The migration must run **as a superuser / table-owner** so it can issue `CREATE TABLE`. The runtime role is created later (this runbook).

## Step 2 — Create the runtime + admin roles

Pick names that match your bank's account-management policy. The names below are placeholders.

### Postgres

```sql
-- Runtime: AgentOS application connections.
CREATE ROLE agentos_runtime LOGIN PASSWORD '<random secret>';

-- Evidence admin: retention-enforcement / examiner-export tooling
-- (Phase 3.3). Out-of-scope for Sprint 2 but provisioned now so the
-- DELETE privilege is never silently held by the runtime role.
CREATE ROLE agentos_evidence_admin LOGIN PASSWORD '<random secret>';
```

### Oracle

```sql
-- Runtime.
CREATE USER agentos_runtime IDENTIFIED BY "<random secret>";
GRANT CREATE SESSION TO agentos_runtime;

-- Evidence admin.
CREATE USER agentos_evidence_admin IDENTIFIED BY "<random secret>";
GRANT CREATE SESSION TO agentos_evidence_admin;
```

Rotate both passwords through your secrets management system before the runtime container reads them.

## Step 3 — Apply the GRANTs

Substitute `:runtime_role` with `agentos_runtime` (or your chosen name) and `:admin_role` with `agentos_evidence_admin`.

### Postgres

```sql
-- Runtime: append-only on the evidence tables.
GRANT INSERT, SELECT ON audit_event       TO agentos_runtime;
GRANT INSERT, SELECT ON decision_history  TO agentos_runtime;

-- Runtime: chain-head row gets INSERT/SELECT/UPDATE because the append
-- transaction must lock + advance the latest_sequence + latest_hash.
-- The chain head IS the only legitimately-mutated state in the
-- governance tier.
GRANT INSERT, SELECT, UPDATE ON governance_chain_heads TO agentos_runtime;

-- Evidence admin: DELETE privilege for retention enforcement only.
-- NOT granted to the runtime role.
GRANT SELECT, DELETE ON audit_event       TO agentos_evidence_admin;
GRANT SELECT, DELETE ON decision_history  TO agentos_evidence_admin;
```

### Oracle

```sql
-- GRANTs themselves are identical to Postgres in shape. Sprint-2 table
-- names avoid Oracle reserved words entirely (audit_event, not audit),
-- so no quoted identifiers are needed.
--
-- Run as the schema owner (the user who ran `alembic upgrade head`):
GRANT INSERT, SELECT ON audit_event       TO agentos_runtime;
GRANT INSERT, SELECT ON decision_history  TO agentos_runtime;
GRANT INSERT, SELECT, UPDATE ON governance_chain_heads TO agentos_runtime;

GRANT SELECT, DELETE ON audit_event       TO agentos_evidence_admin;
GRANT SELECT, DELETE ON decision_history  TO agentos_evidence_admin;
```

## Step 3.5 (Oracle only) — Resolve unqualified table names

Oracle resolves unqualified table references against the **connecting user's own schema first**. AgentOS uses unqualified table names in its SQLAlchemy Table objects (`audit_event`, `decision_history`, `governance_chain_heads`) — production code does NOT prefix the schema owner. So unless the runtime user can resolve those names to the owner's tables, every `INSERT` raises `ORA-00942: table or view does not exist`.

Pick **one** of the two options below. The verification test in Step 4 fails identically either way if the resolution is misconfigured, so either path is provably correct.

### Option A — Private synonyms (recommended)

Create per-user synonyms pointing at the schema owner's tables. Persistent; one-time setup; no per-connection runtime cost.

Pick **one of the two privilege paths** below. Oracle does NOT let the schema owner create synonyms in another user's namespace just because they own the source tables — synonym creation is governed by `CREATE SYNONYM` (own schema) or `CREATE ANY SYNONYM` (any schema).

#### Path A.1 — DBA / user with `CREATE ANY SYNONYM`

A user holding `CREATE ANY SYNONYM` (typically a DBA, or a designated provisioning role) can create the synonyms directly inside the runtime / admin schemas:

```sql
-- Run as a user with CREATE ANY SYNONYM:
CREATE OR REPLACE SYNONYM agentos_runtime.audit_event             FOR <schema_owner>.audit_event;
CREATE OR REPLACE SYNONYM agentos_runtime.decision_history        FOR <schema_owner>.decision_history;
CREATE OR REPLACE SYNONYM agentos_runtime.governance_chain_heads  FOR <schema_owner>.governance_chain_heads;

-- agentos_evidence_admin only needs the two evidence tables (no
-- chain_heads — that table holds the runtime's chain-state and the
-- admin role does not append to it).
CREATE OR REPLACE SYNONYM agentos_evidence_admin.audit_event       FOR <schema_owner>.audit_event;
CREATE OR REPLACE SYNONYM agentos_evidence_admin.decision_history  FOR <schema_owner>.decision_history;
```

#### Path A.2 — each user creates synonyms in its own schema

If your bank's policy forbids `CREATE ANY SYNONYM`, grant each non-owner user `CREATE SYNONYM` on its own schema, then have each user create its synonyms after connecting:

```sql
-- Schema owner (or a DBA with GRANT) issues CREATE SYNONYM grants:
GRANT CREATE SYNONYM TO agentos_runtime;
GRANT CREATE SYNONYM TO agentos_evidence_admin;

-- Connect AS agentos_runtime, then run (no schema-prefix on the
-- synonym; the FOR clause carries the owner reference):
CREATE OR REPLACE SYNONYM audit_event             FOR <schema_owner>.audit_event;
CREATE OR REPLACE SYNONYM decision_history        FOR <schema_owner>.decision_history;
CREATE OR REPLACE SYNONYM governance_chain_heads  FOR <schema_owner>.governance_chain_heads;

-- Connect AS agentos_evidence_admin, then run:
CREATE OR REPLACE SYNONYM audit_event       FOR <schema_owner>.audit_event;
CREATE OR REPLACE SYNONYM decision_history  FOR <schema_owner>.decision_history;
```

Path A.2 is the lower-privilege option — `CREATE SYNONYM` is bounded to the user's own schema.

### Option B — Per-session `CURRENT_SCHEMA`

If your bank's account-management policy forbids synonyms entirely, set `CURRENT_SCHEMA` on every runtime connection. The runtime user must already hold the privileges granted in Step 3 (which is unaffected by `CURRENT_SCHEMA` — privileges are evaluated against the actual underlying tables).

```sql
ALTER SESSION SET CURRENT_SCHEMA = <schema_owner>
```

This needs to run on every fresh connection from the pool. The bank deployment's `cognic-agentos-overlay` registers a SQLAlchemy `connect` event listener on the runtime AsyncEngine — pseudocode:

```python
# Pseudocode — wire this into the bank-overlay code that constructs
# the runtime engine. AgentOS does not ship a first-class hook for
# this in Sprint 2; Phase 4 RBAC will introduce one.
from sqlalchemy import event

engine = <bank-overlay-built AsyncEngine>          # the AgentOS runtime engine
schema_owner = "<schema_owner>"                    # value from operator config

@event.listens_for(engine.sync_engine, "connect")
def _set_current_schema(dbapi_conn, _record):
    with dbapi_conn.cursor() as cur:
        cur.execute(f"ALTER SESSION SET CURRENT_SCHEMA = {schema_owner}")
```

The actual wiring is the bank overlay's responsibility; this snippet is documentation of the contract, not copy-pasteable code.

### Why no `current_schema` URL parameter?

`oracledb` driver accepts a `current_schema` connection-string param, but Oracle's native SQL "current_schema" semantics differ subtly from `ALTER SESSION SET CURRENT_SCHEMA` — particularly around object-resolution caching. Use one of the two options above, not URL params.

## Step 4 — Verify the runtime role is append-only

The integration test `tests/integration/db/test_runtime_role_is_append_only.py` (lands in Sprint 2 Task 12.5 of the plan) is the production-grade canary that this runbook was applied:

```bash
# Postgres:
COGNIC_RUN_POSTGRES_INTEGRATION=1 \
COGNIC_RUNTIME_DATABASE_URL_POSTGRES_TEST='postgresql+asyncpg://agentos_runtime:<secret>@host:5432/cognic' \
  uv run pytest -m postgres -v -k test_runtime_role

# Oracle:
COGNIC_RUN_ORACLE_INTEGRATION=1 \
COGNIC_RUNTIME_DATABASE_URL_ORACLE_TEST='oracle+oracledb://agentos_runtime:<secret>@host:1521/?service_name=XEPDB1' \
  uv run pytest -m oracle -v -k test_runtime_role
```

The test asserts:

- `UPDATE audit_event` and `DELETE FROM audit_event` raise the dialect's permission-denied error for the runtime role (PG: `permission denied`; Oracle: `ORA-01031`).
- Same for `decision_history`.
- `INSERT INTO audit_event` + `UPDATE governance_chain_heads` succeed via the production `AuditStore.append()` flow — proves all three positive privileges work together (catches partial-GRANT misconfigurations where INSERT on audit_event works but UPDATE on chain_heads is missing).

If the test passes against your runtime DSN, the runbook has been applied correctly.

## Step 5 — Wire the runtime container

Update the AgentOS runtime container's `COGNIC_DATABASE_URL` to use the **runtime role** (not superuser), then roll out the new runtime image. Without this step, the runtime is using superuser credentials and the chain is INSERT-only by code discipline only — explicitly **NOT acceptable** for `COGNIC_RUNTIME_PROFILE=prod` (per the BUILD_PLAN production-grade rule landed in PR #5).

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Runtime container reports 503 on every audit emission | Runtime role missing INSERT on `audit_event` | Re-run Step 3 GRANTs for that table |
| `/readyz` reports `db: ok` but no audit rows landing | Runtime role has SELECT but not INSERT | Re-run Step 3 GRANTs |
| Audit emit fails with "tuple index out of range" / chain-head update silently rolls back | Runtime role missing UPDATE on `governance_chain_heads` | Re-run Step 3 GRANTs (the UPDATE clause specifically) |
| **(Oracle)** `ORA-00942: table or view does not exist` | Step 3.5 not applied — runtime role can't resolve unqualified table names to the owner's schema | Apply Option A (synonyms) or Option B (`CURRENT_SCHEMA`) |
| `test_runtime_role_is_append_only.py` says runtime role CAN UPDATE evidence tables | Runtime role is a superuser, or Step 3 was never run | Roll back to Step 1 and verify which DSN the test is hitting |

## References

- `BUILD_PLAN.md` §"Append-only governance tables" — the production-grade principle this runbook enforces.
- `AGENTS.md` Stop rule for `core/canonical.py` — the wire-format discipline this runbook complements.
- `docs/superpowers/plans/2026-04-28-sprint-2-governance-primitives.md` — Round-3 amendment moving GRANTs out of the migration into this runbook.
- ADR-006 §"Tamper-evident evidence chain" — Phase-3 evidence-pack export + Merkle-root signing (Sprint 2 enforces append-only via DB grants; Phase 3 adds cryptographic tamper-evidence for examiner replay).
