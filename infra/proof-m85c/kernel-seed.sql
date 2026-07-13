-- proof-m85c — kernel-side seed: the migration-0014 rows (Postgres).
--
-- Applied by run-proof-m85c.sh AFTER the alembic migration Job has brought
-- the schema to HEAD (rev 0016; the seeded authority tables below —
-- data_scopes / entitlements / agent_assignments — ORIGINATE from rev 0014,
-- and the 0015/0016 conversation tables need no seed). These rows are PROOF-SIDE
-- SEED per the 0014 migration docstring ("scope/entitlement/assignment ROWS are proof-side seed (spec §6),
-- never kernel migration data").
--
-- Shapes (single source of truth: db/migrations/versions/
-- 20260705_0014_agent_entitlements.py + core/entitlements/store.py +
-- core/agent/assignments.py):
--   data_scopes(tenant_id, scope_id, schema_name, objects JSON, proxy_db_identity, created_at)
--     — composite PK (tenant_id, scope_id); objects = the JSON list of
--       SCHEMA-QUALIFIED governed-view names (the tool's arm-5 allow-set
--       normalizes referenced objects to their dotted upper form, so the
--       seeded names are the exact match targets).
--   entitlements(id, tenant_id, subject, scope_id, created_at)
--     — uq (tenant_id, subject, scope_id).
--   agent_assignments(id, tenant_id, agent_id, capability_kind, capability_ref, created_at)
--     — uq (tenant_id, agent_id, capability_kind, capability_ref);
--       capability_kind CHECK-pinned to ('skill', 'tool'). Every ref MUST be
--       inside the agent pack's REQUESTED set (core/agent/assignments.py
--       ingestion invariant: a grant beyond the requested set refuses
--       agent_grant_not_requested at load, fail-closed).
--
-- Tenant: proof-m85c (the proof-m6 tenant convention). Idempotent: every INSERT
-- is ON CONFLICT DO NOTHING against its uniqueness contract, so re-running
-- the seed (pod restart, runner retry) never duplicates or errors.
--
-- The maintainer-locked matrix this file encodes:
--   scopes        retail_analytics + financials + cards_analytics + atm_recon
--   entitlements  analyst.amir -> retail_analytics + financials
--                 analyst.sara -> cards_analytics + retail_analytics
--                 (atm_recon is seeded as a scope but entitled to NOBODY)
--   assignments   agent bank-analyst = EXACTLY the requested set:
--                 skills customer-data + financial-data + cards-data,
--                 tool cognic-tool-oracle-schema/run_readonly_query
--                 (the atm-recon skill is NEVER assigned — the BAR-2 negative)
--
-- SUBJECT PLACEHOLDERS (M8.5-C): entitlements are keyed by the BOUND
-- Actor.subject — the ISSUER-QUALIFIED stable Keycloak sub,
-- <issuer>#<uuid5>, NEVER the mutable preferred_username (a reassigned
-- username must not inherit the old holder's entitlements or replay their
-- approval grants; see overlay_reference/binder.py step 9). The
-- __SUBJECT_<NAME>__ tokens below are rendered by seed-db.sh from the
-- generator-emitted realm-subjects.env (KC_SUB_<NAME>=<issuer>#<uuid>,
-- keycloak/gen_realm.py property 4) BEFORE this file reaches psql;
-- seed-db.sh dies if any placeholder survives the pass. The uuid5 subjects
-- are deterministic across runs, so the ON CONFLICT idempotency contract
-- still holds across pod restarts and runner retries.
--
-- Proxy identities (scope-level per ADR-027 §c — the dispatcher stamps
-- resolved_scope.proxy_db_identity into the query-context token):
--   retail_analytics -> AN_AMIR     financials -> AN_AMIR
--   cards_analytics  -> AN_SARA     atm_recon  -> AN_ATM_RECON
-- AN_ATM_RECON is DELIBERATELY NOT provisioned in Oracle (see
-- oracle-seed/seed_schema.sql §5): the scope exists, no subject is entitled
-- to it, and its DB identity cannot even open a session — fail-closed at
-- every layer.

BEGIN;

-- === data_scopes ===

INSERT INTO data_scopes (tenant_id, scope_id, schema_name, objects, proxy_db_identity, created_at)
VALUES
  ('proof-m85c', 'retail_analytics', 'RETAIL_ANALYTICS',
   '["RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS", "RETAIL_ANALYTICS.V_CUSTOMER_PROFILE"]'::json,
   'AN_AMIR', now()),
  ('proof-m85c', 'financials', 'FIN',
   '["FIN.V_GL_BALANCES", "FIN.V_BRANCH_PNL"]'::json,
   'AN_AMIR', now()),
  ('proof-m85c', 'cards_analytics', 'CARDS',
   '["CARDS.V_CARD_ACCOUNTS", "CARDS.V_CARD_SPEND"]'::json,
   'AN_SARA', now()),
  ('proof-m85c', 'atm_recon', 'CARDS',
   '["CARDS.V_ATM_SETTLEMENTS", "CARDS.V_ATM_DISPUTES"]'::json,
   'AN_ATM_RECON', now())
ON CONFLICT (tenant_id, scope_id) DO NOTHING;

-- === entitlements ===
-- analyst.amir (__SUBJECT_ANALYST_AMIR__): retail_analytics + financials
-- (multi-scope leg).
-- analyst.sara (__SUBJECT_ANALYST_SARA__): cards_analytics + retail_analytics
-- (the shared-scope leg — m:n proven both directions: one subject with many
-- scopes AND one scope with many subjects). NO subject is entitled to the
-- fourth seeded scope. The placeholders render to the issuer-qualified stable
-- sub each analyst's token binds (see the SUBJECT PLACEHOLDERS note above).

INSERT INTO entitlements (id, tenant_id, subject, scope_id, created_at)
VALUES
  (gen_random_uuid(), 'proof-m85c', '__SUBJECT_ANALYST_AMIR__', 'retail_analytics', now()),
  (gen_random_uuid(), 'proof-m85c', '__SUBJECT_ANALYST_AMIR__', 'financials', now()),
  (gen_random_uuid(), 'proof-m85c', '__SUBJECT_ANALYST_SARA__', 'cards_analytics', now()),
  (gen_random_uuid(), 'proof-m85c', '__SUBJECT_ANALYST_SARA__', 'retail_analytics', now())
ON CONFLICT ON CONSTRAINT uq_entitlements_tenant_subject_scope DO NOTHING;

-- === agent_assignments ===
-- EXACTLY the agent pack's requested set (cognic-agent-bank-analyst
-- manifest [agent]: requested_skills = customer-data + financial-data +
-- cards-data; requested_tools = cognic-tool-oracle-schema/run_readonly_query).
-- Granting ANYTHING beyond this set would refuse the WHOLE grant load at
-- boot (agent_grant_not_requested, no partial set). The fourth skill is
-- NEVER granted here — the standing BAR-2 negative.

INSERT INTO agent_assignments (id, tenant_id, agent_id, capability_kind, capability_ref, created_at)
VALUES
  (gen_random_uuid(), 'proof-m85c', 'bank-analyst', 'skill', 'customer-data', now()),
  (gen_random_uuid(), 'proof-m85c', 'bank-analyst', 'skill', 'financial-data', now()),
  (gen_random_uuid(), 'proof-m85c', 'bank-analyst', 'skill', 'cards-data', now()),
  (gen_random_uuid(), 'proof-m85c', 'bank-analyst', 'tool', 'cognic-tool-oracle-schema/run_readonly_query', now())
ON CONFLICT ON CONSTRAINT uq_agent_assignments_tenant_agent_kind_ref DO NOTHING;

COMMIT;
