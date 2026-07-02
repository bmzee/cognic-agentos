#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proofm5}"; T="proof-m5"
# KEPT FROM M4 (ADR-026 D2/D3/D7): this script is a NO-OP. It DELIBERATELY
# does not seed the derived MCP carve-out rows (the pack-scoped server_url override
# + the per-tenant exact-IP internal-host allowlist).
#
# M5 reuses the M4 governed operator path unchanged for the TOOL pack — the runner
# drives the REAL operator API (submit -> claim -> approve -> allow-list ->
# configure -> install) for cognic-tool-oracle-schema@v0.2.0, and the `install`
# handler's materializer projects the DESIRED runtime-config record (written by
# `configure`) INTO those derived tables. The materializer is the SOLE writer of
# the carve-out rows (ADR-026 D7); seeding them here would bypass the governance
# path the M4 proof established and the M5 proof builds on.
#
# The HOOK pack (cognic-hook-schema-guard) needs NO DB seeding either: it is
# trust-register + registry-admit only (spec §6 decision B) — no lifecycle rows,
# no runtime-config record, no carve-out rows. Its admission evidence is the boot
# trust-registration audit chain, not seeded state.
#
# The script is retained (a no-op) so the runner's call site + the seed contract
# stay in ONE place (drift-prevention — the runner NEVER inlines derived-row SQL).
# Any FUTURE non-override DB setup the proof needs would live here.
#
# The "no derived-row seeding" invariant is pinned by the structural test over
# this script (tests/unit/infra/test_proof_m5_structure.py asserts the derived-row
# INSERT strings are absent); run-proof-m5.sh (Task 10) gets the matching runner
# pin when it lands. If a future edit re-introduces that SQL, the M4 governance
# property M5 inherits (install materializes the derived rows) is broken — and
# the structural gate fails.
echo "seed-db.sh (M5): no-op — the override + allow-list rows are materialized by \`install\` (tenant=$T, ns=$NS)"
