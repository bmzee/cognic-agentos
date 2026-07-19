#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proofm85c}"; T="proof-m85c"
PROOF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# M8.5-slice kernel-side DB seed (the M8 matrix, entitlement subjects rendered
# per M8.5-C) — THREE contracts in one place (drift-prevention: the
# runner NEVER inlines seed SQL):
#
# 1. KEPT FROM M4/M5/M6 (ADR-026 D2/D3/D7): NO derived MCP carve-out rows.
#    The runner drives the REAL operator API (submit -> claim -> approve ->
#    allow-list -> configure -> install) for cognic-tool-oracle-schema@v0.5.1,
#    and the `install` handler's materializer projects the DESIRED
#    runtime-config record INTO the derived tables (mcp_server_url_override +
#    mcp_internal_host_allowlist). The materializer is the SOLE writer of
#    those rows; seeding them here would bypass the governance path.
#
# 2. CARRIED FROM M8 (ADR-027): apply kernel-seed.sql — the 0014-origin
#    data_scopes / entitlements / agent_assignments ROWS (proof-side seed per
#    the migration docstring; never kernel migration data). Idempotent
#    (ON CONFLICT DO NOTHING) + tenant-scoped to proof-m85c. Applied AFTER the
#    migration Job brought the schema to HEAD (rev 0016 — the M8.5
#    conversation tables + read-model shape it adds need NO seed);
#    readback-asserted here so a
#    silent partial apply can never reach the bars.
#
# Neither the HOOK pack nor the four INSTRUCTION SKILL packs nor the AGENT
# pack needs ANY other DB seeding: all five are trust-register + registry-
# admit (+ hosting/ingestion) only — no lifecycle rows, no runtime-config
# record, no carve-out rows. The agent's AUTHORITY rows are exactly the 0014
# seed above (assignments = the requested set; the atm-recon skill is NEVER
# assigned — the standing BAR-2 negative).
#
# 3. NEW AT M8.5-C: entitlements are keyed by the BOUND Actor.subject — the
#    ISSUER-QUALIFIED stable Keycloak sub (<issuer>#<uuid5>), NEVER the mutable
#    preferred_username (a reassigned username must not inherit the old
#    holder's entitlements). kernel-seed.sql therefore carries
#    __SUBJECT_<NAME>__ placeholders which this script renders from the
#    generator-emitted realm-subjects.env (KC_SUB_<NAME>=<subject> lines;
#    keycloak/gen_realm.py property 4) whose path the runner exports as
#    COGNIC_PROOF_M85C_REALM_SUBJECTS. Fail-loud twice: no env/file -> die;
#    any placeholder surviving the render -> die (a literal __SUBJECT_*__
#    seeded as a subject would make every entitlement check fail confusingly).
PSQL() { kubectl -n "$NS" exec -i deploy/postgres -- psql -U cognic -d cognic -v ON_ERROR_STOP=1 "$@"; }

SUBJECTS_ENV="${COGNIC_PROOF_M85C_REALM_SUBJECTS:-}"
if [ -z "$SUBJECTS_ENV" ]; then
  echo "FAIL: COGNIC_PROOF_M85C_REALM_SUBJECTS is unset — export the path to the per-run" >&2
  echo "      realm-subjects.env (keycloak/gen_realm.py writes it next to realm-credentials.env)." >&2
  echo "      Entitlements are keyed by the BOUND subject (<issuer>#<sub>), so the seed" >&2
  echo "      cannot be rendered without it." >&2
  exit 1
fi
if [ ! -f "$SUBJECTS_ENV" ]; then
  echo "FAIL: COGNIC_PROOF_M85C_REALM_SUBJECTS points at '$SUBJECTS_ENV' which is not a file." >&2
  exit 1
fi

# Render every __SUBJECT_<NAME>__ placeholder from the KC_SUB_<NAME> lines.
# Bash ${var//pattern/replacement} substitution is LITERAL — no sed
# metacharacter hazards from the '/', ':' and '#' inside the issuer-qualified
# subject values.
SEED_SQL="$(cat "$PROOF_DIR/kernel-seed.sql")"
while IFS='=' read -r var value; do
  case "$var" in
    KC_SUB_*)
      placeholder="__SUBJECT_${var#KC_SUB_}__"
      SEED_SQL="${SEED_SQL//$placeholder/$value}"
      ;;
  esac
done < "$SUBJECTS_ENV"

LEFTOVER="$(grep -o '__SUBJECT_[A-Za-z0-9_]*__' <<<"$SEED_SQL" | sort -u || true)"
if [ -n "$LEFTOVER" ]; then
  echo "FAIL: unsubstituted subject placeholder(s) in kernel-seed.sql after rendering:" >&2
  echo "$LEFTOVER" >&2
  echo "      realm-subjects.env at '$SUBJECTS_ENV' must carry a KC_SUB_<NAME> line per placeholder." >&2
  exit 1
fi
# Belt-and-braces: ANY surviving __SUBJECT_ text on a NON-comment line is fatal
# too — this catches a malformed placeholder the shape-check above cannot name
# (SQL comment lines are excluded: the seed's own docs may mention the token
# convention, and rendered comments carry no authority).
STRAY="$(grep -v '^[[:space:]]*--' <<<"$SEED_SQL" | grep -c '__SUBJECT_' || true)"
if [ "$STRAY" != "0" ]; then
  echo "FAIL: $STRAY non-comment line(s) still carry __SUBJECT_ text after rendering — a" >&2
  echo "      malformed placeholder would seed a literal string as the subject. Fix" >&2
  echo "      kernel-seed.sql to use the __SUBJECT_<UPPERCASE_NAME>__ convention." >&2
  exit 1
fi

# Subjects are NOT secrets (they ride in every token) — print the two entitled
# ones for the run log so an entitlement mismatch is diagnosable. NEVER print
# the credentials file (realm-credentials.env stays private; never read here).
AMIR_SUB="$(grep '^KC_SUB_ANALYST_AMIR=' "$SUBJECTS_ENV" | cut -d= -f2- || true)"
SARA_SUB="$(grep '^KC_SUB_ANALYST_SARA=' "$SUBJECTS_ENV" | cut -d= -f2- || true)"
if [ -z "$AMIR_SUB" ] || [ -z "$SARA_SUB" ]; then
  echo "FAIL: realm-subjects.env at '$SUBJECTS_ENV' lacks KC_SUB_ANALYST_AMIR / KC_SUB_ANALYST_SARA." >&2
  exit 1
fi

echo "seed-db.sh (M8.5 slice): applying kernel-seed.sql (0014 rows; tenant=$T, ns=$NS)"
echo "  entitled subjects: analyst.amir -> $AMIR_SUB"
echo "                     analyst.sara -> $SARA_SUB"
PSQL <<<"$SEED_SQL"

# Readback assertion — the exact maintainer matrix (4 scopes / 4 entitlements /
# 4 assignments) landed for the proof tenant; atm_recon entitled to NOBODY; and
# the entitlement rows are keyed by the RENDERED bound subjects (2 each), so a
# wrong-but-substituted subject (e.g. a stale realm-subjects.env) also dies here
# instead of surfacing 30 minutes later as an inexplicable empty scope set.
COUNTS="$(PSQL -tA <<SQL
SELECT (SELECT count(*) FROM data_scopes WHERE tenant_id = '$T')
    || '|' || (SELECT count(*) FROM entitlements WHERE tenant_id = '$T')
    || '|' || (SELECT count(*) FROM agent_assignments WHERE tenant_id = '$T')
    || '|' || (SELECT count(*) FROM entitlements WHERE tenant_id = '$T' AND scope_id = 'atm_recon')
    || '|' || (SELECT count(*) FROM entitlements WHERE tenant_id = '$T' AND subject = '$AMIR_SUB')
    || '|' || (SELECT count(*) FROM entitlements WHERE tenant_id = '$T' AND subject = '$SARA_SUB');
SQL
)"
if [ "$COUNTS" != "4|4|4|0|2|2" ]; then
  echo "FAIL: seed-db.sh (M8.5 slice) readback expected 4|4|4|0|2|2 (scopes|entitlements|assignments|atm_recon-entitlements|amir-subject|sara-subject), got: $COUNTS" >&2
  exit 1
fi
echo "seed-db.sh (M8.5 slice): 0014 rows verified (4 scopes, 4 entitlements keyed by bound subjects, 4 assignments, atm_recon entitled to NOBODY)"
