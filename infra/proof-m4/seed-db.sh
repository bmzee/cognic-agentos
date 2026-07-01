#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proofm4}"; T="proof-m4"
# M4 DELTA (ADR-026 D2/D3/D7 + Task 8): this script is a NO-OP. It DELIBERATELY
# does not seed the derived MCP carve-out rows (the pack-scoped server_url override
# + the per-tenant exact-IP internal-host allow-list).
#
# In proof-1b-2c those derived rows were seeded directly here. Under M4 they are
# MATERIALIZED by the governed operator path — the runner drives the REAL operator
# API (submit -> claim -> approve -> allow-list -> configure -> install), and the
# `install` handler's materializer projects the DESIRED runtime-config record
# (written by `configure`) INTO those derived tables. The materializer is the SOLE
# writer of the carve-out rows (ADR-026 D7); seeding them here would bypass the very
# governance path this proof exists to prove.
#
# The script is retained (a no-op) so the runner's call site + the seed contract
# stay in ONE place (drift-prevention — the runner NEVER inlines derived-row SQL).
# Any FUTURE non-override DB setup the proof needs would live here.
#
# The "no derived-row seeding" invariant is pinned by the structural test over BOTH
# this script AND the runner (tests/unit/proof_m4/test_seeds.py +
# tests/unit/proof_m4/test_runner.py assert the derived-row INSERT strings are
# absent from both). If a future edit re-introduces that SQL, the whole point of M4
# (install materializes the derived rows) is broken — and the structural gate fails.
echo "seed-db.sh (M4): no-op — the override + allow-list rows are materialized by \`install\` (tenant=$T, ns=$NS)"
