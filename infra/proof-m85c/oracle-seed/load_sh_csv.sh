#!/usr/bin/env bash
# Populate the six SH CSV-backed tables that SQLcl's LOAD command owns upstream.
set -euo pipefail

WORK_DIR="${1:-/tmp/cognic-oracle-sh-23.3}"
CSV_ARCHIVE="${2:-/tmp/oracle-samples-23.3-sh-csv.tar.gz}"
SQLPLUS="/opt/oracle/product/26ai/dbhomeFree/bin/sqlplus"
SQLLDR="/opt/oracle/product/26ai/dbhomeFree/bin/sqlldr"
CREDENTIAL_PARFILE=""
EXPECTED_COUNTS=(
  "sales:918843"
  "customers:55500"
  "times:1826"
  "costs:82112"
  "promotions:503"
  "supplementary_demographics:4500"
)

die() { echo "SH CSV load refused: $*" >&2; exit 1; }
cleanup_credential_parfile() {
  [ -z "$CREDENTIAL_PARFILE" ] || rm -f "$CREDENTIAL_PARFILE"
}
trap cleanup_credential_parfile EXIT

[ -x "$SQLPLUS" ] || die "sqlplus is absent from the pinned Oracle image"
[ -x "$SQLLDR" ] || die "sqlldr is absent from the pinned Oracle image"
[ -s "$CSV_ARCHIVE" ] || die "CSV archive is absent or empty"
[ -n "${ORACLE_PASSWORD:-}" ] || die "Oracle administrator credential is absent"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
tar -xzf "$CSV_ARCHIVE" -C "$WORK_DIR"
CSV_DIR="$WORK_DIR/sales_history"
for table in sales customers times costs promotions supplementary_demographics; do
  [ -s "$CSV_DIR/$table.csv" ] || die "verified archive is missing $table.csv"
  chmod 0644 "$CSV_DIR/$table.csv"
done

pre_counts="$($SQLPLUS -s / as sysdba <<'SQL' | tr -d '[:space:]'
SET HEADING OFF FEEDBACK OFF PAGESIZE 0 VERIFY OFF ECHO OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = FREEPDB1;
SELECT (SELECT COUNT(*) FROM sh.sales) || '|' ||
       (SELECT COUNT(*) FROM sh.customers) || '|' ||
       (SELECT COUNT(*) FROM sh.times) || '|' ||
       (SELECT COUNT(*) FROM sh.costs) || '|' ||
       (SELECT COUNT(*) FROM sh.promotions) || '|' ||
       (SELECT COUNT(*) FROM sh.supplementary_demographics)
  FROM dual;
EXIT
SQL
)"
[ "$pre_counts" = "0|0|0|0|0|0" ] \
  || die "CSV-backed SH tables were not empty before the one-time load"

write_control() {
  local table="$1" mode="$2" table_upper fields control
  table_upper="$(printf '%s' "$table" | tr '[:lower:]' '[:upper:]')"
  control="$WORK_DIR/$table.ctl"
  fields="$($SQLPLUS -s / as sysdba <<SQL
SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 32767 VERIFY OFF ECHO OFF TRIMSPOOL ON
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = FREEPDB1;
SELECT CASE
         WHEN data_type NOT IN ('NUMBER', 'DATE', 'CHAR', 'VARCHAR2', 'NCHAR', 'NVARCHAR2')
           THEN '__UNSUPPORTED__:' || column_name || ':' || data_type
         ELSE '  ' || column_name ||
              CASE
                WHEN data_type = 'DATE' THEN ' DATE "YYYY-MM-DD"'
                WHEN data_type IN ('CHAR', 'VARCHAR2', 'NCHAR', 'NVARCHAR2') THEN ' CHAR(4000)'
                ELSE ''
              END ||
              CASE WHEN column_id < MAX(column_id) OVER () THEN ',' ELSE '' END
       END
  FROM all_tab_columns
 WHERE owner = 'SH'
   AND table_name = '$table_upper'
 ORDER BY column_id;
EXIT
SQL
)" || die "could not derive SQL*Loader fields for $table"
  [ -n "$(printf '%s' "$fields" | tr -d '[:space:]')" ] \
    || die "no live columns found for sh.$table"
  if grep -q '__UNSUPPORTED__' <<<"$fields"; then
    die "unsupported live column type while generating the $table control"
  fi

  if [ "$mode" = "direct" ]; then
    printf '%s\n' 'OPTIONS (SKIP=1, DIRECT=TRUE)' > "$control"
  elif [ "$mode" = "conventional" ]; then
    printf '%s\n' 'OPTIONS (SKIP=1, ROWS=5000, BINDSIZE=20000000, READSIZE=20000000)' > "$control"
  else
    die "unknown SQL*Loader mode for $table"
  fi
  cat >> "$control" <<EOF
LOAD DATA
INFILE '$CSV_DIR/$table.csv'
INTO TABLE sh.$table
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
TRAILING NULLCOLS
(
$fields
)
EOF
}

load_table() {
  local table="$1" mode="$2"
  local bad="$WORK_DIR/$table.bad" log="$WORK_DIR/$table.log"
  write_control "$table" "$mode"
  rm -f "$bad" "$log" "$WORK_DIR/$table.discard"
  [ -d /dev/shm ] || die "the in-memory credential directory is absent"
  CREDENTIAL_PARFILE="$(umask 077 && mktemp /dev/shm/cognic-sh-sqlldr.XXXXXX.par)" \
    || die "could not create the in-memory SQL*Loader parameter file"
  printf '%s\n' \
    "USERID='sys/${ORACLE_PASSWORD}@//localhost:1521/FREEPDB1 AS SYSDBA'" \
    "CONTROL=$WORK_DIR/$table.ctl" \
    "LOG=$log" \
    "BAD=$bad" \
    "DISCARD=$WORK_DIR/$table.discard" > "$CREDENTIAL_PARFILE"
  if ! "$SQLLDR" parfile="$CREDENTIAL_PARFILE"; then
    [ ! -f "$log" ] || tail -n 40 "$log" >&2
    die "sqlldr failed for sh.$table"
  fi
  rm -f "$CREDENTIAL_PARFILE"
  CREDENTIAL_PARFILE=""
  [ ! -e "$bad" ] || die "sqlldr emitted a .bad file for sh.$table"
}

# Parents first. FK-bearing customers/costs/sales use the proven conventional
# path; DIRECT=TRUE is retained only for the three live-proven compatible tables.
load_table customers conventional
load_table promotions direct
load_table times direct
load_table supplementary_demographics direct
load_table costs conventional
load_table sales conventional

post_counts="$($SQLPLUS -s / as sysdba <<'SQL' | tr -d '[:space:]'
SET HEADING OFF FEEDBACK OFF PAGESIZE 0 VERIFY OFF ECHO OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE
ALTER SESSION SET CONTAINER = FREEPDB1;
SELECT 'sales:' || (SELECT COUNT(*) FROM sh.sales) || '|' ||
       'customers:' || (SELECT COUNT(*) FROM sh.customers) || '|' ||
       'times:' || (SELECT COUNT(*) FROM sh.times) || '|' ||
       'costs:' || (SELECT COUNT(*) FROM sh.costs) || '|' ||
       'promotions:' || (SELECT COUNT(*) FROM sh.promotions) || '|' ||
       'supplementary_demographics:' ||
         (SELECT COUNT(*) FROM sh.supplementary_demographics)
  FROM dual;
EXIT
SQL
)"
expected_counts="$(IFS='|'; echo "${EXPECTED_COUNTS[*]}")"
[ "$post_counts" = "$expected_counts" ] \
  || die "SH row-count gate failed (expected $expected_counts, observed $post_counts)"
echo "SH CSV load PASS: $post_counts"
