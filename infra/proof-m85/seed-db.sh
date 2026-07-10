#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proofm85}"; T="proof-m85"
PROOF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# M8.5-slice kernel-side DB seed (the M8 matrix verbatim) — TWO contracts in one place (drift-prevention: the
# runner NEVER inlines seed SQL):
#
# 1. KEPT FROM M4/M5/M6 (ADR-026 D2/D3/D7): NO derived MCP carve-out rows.
#    The runner drives the REAL operator API (submit -> claim -> approve ->
#    allow-list -> configure -> install) for cognic-tool-oracle-schema@v0.3.0,
#    and the `install` handler's materializer projects the DESIRED
#    runtime-config record INTO the derived tables (mcp_server_url_override +
#    mcp_internal_host_allowlist). The materializer is the SOLE writer of
#    those rows; seeding them here would bypass the governance path.
#
# 2. CARRIED FROM M8 (ADR-027): apply kernel-seed.sql — the 0014-origin
#    data_scopes / entitlements / agent_assignments ROWS (proof-side seed per
#    the migration docstring; never kernel migration data). Idempotent
#    (ON CONFLICT DO NOTHING) + tenant-scoped to proof-m85. Applied AFTER the
#    migration Job brought the schema to HEAD (rev 0015 — the M8.5
#    conversation tables it adds need NO seed); readback-asserted here so a
#    silent partial apply can never reach the bars.
#
# Neither the HOOK pack nor the four INSTRUCTION SKILL packs nor the AGENT
# pack needs ANY other DB seeding: all five are trust-register + registry-
# admit (+ hosting/ingestion) only — no lifecycle rows, no runtime-config
# record, no carve-out rows. The agent's AUTHORITY rows are exactly the 0014
# seed above (assignments = the requested set; the atm-recon skill is NEVER
# assigned — the standing BAR-2 negative).
PSQL() { kubectl -n "$NS" exec -i deploy/postgres -- psql -U cognic -d cognic -v ON_ERROR_STOP=1 "$@"; }

echo "seed-db.sh (M8.5 slice): applying kernel-seed.sql (0014 rows; tenant=$T, ns=$NS)"
PSQL < "$PROOF_DIR/kernel-seed.sql"

# Readback assertion — the exact maintainer matrix (4 scopes / 4 entitlements /
# 4 assignments) landed for the proof tenant; atm_recon entitled to NOBODY.
COUNTS="$(PSQL -tA <<SQL
SELECT (SELECT count(*) FROM data_scopes WHERE tenant_id = '$T')
    || '|' || (SELECT count(*) FROM entitlements WHERE tenant_id = '$T')
    || '|' || (SELECT count(*) FROM agent_assignments WHERE tenant_id = '$T')
    || '|' || (SELECT count(*) FROM entitlements WHERE tenant_id = '$T' AND scope_id = 'atm_recon');
SQL
)"
if [ "$COUNTS" != "4|4|4|0" ]; then
  echo "FAIL: seed-db.sh (M8.5 slice) readback expected 4|4|4|0 (scopes|entitlements|assignments|atm_recon-entitlements), got: $COUNTS" >&2
  exit 1
fi
echo "seed-db.sh (M8.5 slice): 0014 rows verified (4 scopes, 4 entitlements, 4 assignments, atm_recon entitled to NOBODY)"
